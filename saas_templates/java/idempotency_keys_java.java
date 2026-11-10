import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * Idempotency keys (spec docs/specs/idempotency_keys.md, draft-ietf-httpapi-idempotency-key-header-07).
 *
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-07/08/10/11 amendments): records gain the status 'uncertain'.
 * An operation that throws OperationFailedException did nothing, so its key is freed; ANY other error leaves the key
 * 'uncertain' (a retry gets 409 outcome_unknown and does not run) until an operator calls release() or resolve().
 * Only 'completed' records expire; an 'in_progress' record past expires_at (a crashed process) counts as uncertain
 * and is never replaced. release() and resolve() are each one conditional write, so of two concurrent calls exactly
 * one returns true. Touches: the injected store (memory or SQL); no network, no money itself.
 */
public final class IdempotencyKeys {
    private IdempotencyKeys() {}

    /**
     * The operation's way of saying "I definitely did nothing" (a validation error, a provider decline): the key is
     * freed and a retry runs the operation (IDEM-08). Any other exception leaves the key uncertain (IDEM-10).
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public static class OperationFailedException extends RuntimeException {
        public OperationFailedException(String message) {
            super(message);
        }

        public OperationFailedException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Storage for idempotency records. Every write is conditional, so concurrent callers cannot both win.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: markUncertain, release, resolve and listUncertain added; tryClaim
     * replaces only an expired COMPLETED record; purgeExpired deletes only expired completed records.
     */
    public interface Store {
        /** Inserts record if no row exists, or replaces a 'completed' row whose expires_at <= now. True if claimed. */
        boolean tryClaim(IdempotencyRecord record, long now);
        IdempotencyRecord get(String scope, String idemKey);
        /** 'in_progress' (same createdAt) -> 'completed' with the response. */
        void complete(String scope, String idemKey, long createdAt, int responseStatus, String responseBody);
        /** Deletes the row if still 'in_progress' with that createdAt (OperationFailedException path). */
        void delete(String scope, String idemKey, long createdAt);
        /** 'in_progress' (same createdAt) -> 'uncertain' (any other error). */
        void markUncertain(String scope, String idemKey, long createdAt);
        /** One conditional delete of an uncertain row (status 'uncertain', or 'in_progress' with expires_at <= now). */
        boolean release(String scope, String idemKey, long now);
        /** One conditional update of an uncertain row to 'completed' with the response and expires_at = newExpiresAt. */
        boolean resolve(String scope, String idemKey, int responseStatus, String responseBody, long now, long newExpiresAt);
        /** Uncertain rows (as above), oldest created_at first, ties in insertion order, at most limit. */
        List<IdempotencyRecord> listUncertain(int limit, long now);
        /** Deletes 'completed' rows with expires_at <= now; uncertain and in_progress rows are kept. */
        int purgeExpired(long now);
    }

    /** True when a record counts as uncertain at now: status 'uncertain', or 'in_progress' past expires_at. */
    static boolean isUncertain(IdempotencyRecord r, long now) {
        return "uncertain".equals(r.status()) || ("in_progress".equals(r.status()) && r.expiresAt() <= now);
    }

    /**
     * In-memory Store (insertion-ordered, synchronized). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: uncertain
     * records, release/resolve/listUncertain, and expiry for completed records only. Touches: memory only.
     */
    public static final class InMemoryStore implements Store {
        private final Map<Key, IdempotencyRecord> rows = new LinkedHashMap<>();

        private record Key(String scope, String idemKey) {}

        @Override
        public synchronized boolean tryClaim(IdempotencyRecord record, long now) {
            Key key = new Key(record.scope(), record.idemKey());
            IdempotencyRecord existing = rows.get(key);
            if (existing == null || ("completed".equals(existing.status()) && existing.expiresAt() <= now)) {
                rows.remove(key);
                rows.put(key, record);
                return true;
            }
            return false;
        }

        @Override
        public synchronized void markUncertain(String scope, String idemKey, long createdAt) {
            Key key = new Key(scope, idemKey);
            IdempotencyRecord e = rows.get(key);
            if (e != null && "in_progress".equals(e.status()) && e.createdAt() == createdAt) {
                rows.put(key, new IdempotencyRecord(scope, idemKey, e.requestFingerprint(), "uncertain",
                        null, null, e.createdAt(), e.expiresAt()));
            }
        }

        @Override
        public synchronized boolean release(String scope, String idemKey, long now) {
            Key key = new Key(scope, idemKey);
            IdempotencyRecord e = rows.get(key);
            if (e == null || !isUncertain(e, now)) {
                return false;
            }
            rows.remove(key);
            return true;
        }

        @Override
        public synchronized boolean resolve(String scope, String idemKey, int responseStatus, String responseBody, long now, long newExpiresAt) {
            Key key = new Key(scope, idemKey);
            IdempotencyRecord e = rows.get(key);
            if (e == null || !isUncertain(e, now)) {
                return false;
            }
            rows.put(key, new IdempotencyRecord(scope, idemKey, e.requestFingerprint(), "completed",
                    responseStatus, responseBody, e.createdAt(), newExpiresAt));
            return true;
        }

        @Override
        public synchronized List<IdempotencyRecord> listUncertain(int limit, long now) {
            List<IdempotencyRecord> out = new ArrayList<>();
            for (IdempotencyRecord r : rows.values()) {
                if (isUncertain(r, now)) out.add(r);
            }
            out.sort((a, b) -> Long.compare(a.createdAt(), b.createdAt()));   // stable: ties keep insertion order
            return out.size() > limit ? new ArrayList<>(out.subList(0, Math.max(0, limit))) : out;
        }

        @Override
        public synchronized IdempotencyRecord get(String scope, String idemKey) {
            return rows.get(new Key(scope, idemKey));
        }

        @Override
        public synchronized void complete(String scope, String idemKey, long createdAt, int responseStatus, String responseBody) {
            Key key = new Key(scope, idemKey);
            IdempotencyRecord existing = rows.get(key);
            if (existing != null && "in_progress".equals(existing.status()) && existing.createdAt() == createdAt) {
                rows.put(key, new IdempotencyRecord(
                    scope, idemKey, existing.requestFingerprint(), "completed",
                    responseStatus, responseBody, createdAt, existing.expiresAt()
                ));
            }
        }

        @Override
        public synchronized void delete(String scope, String idemKey, long createdAt) {
            Key key = new Key(scope, idemKey);
            IdempotencyRecord existing = rows.get(key);
            if (existing != null && "in_progress".equals(existing.status()) && existing.createdAt() == createdAt) {
                rows.remove(key);
            }
        }

        @Override
        public synchronized int purgeExpired(long now) {
            int count = 0;
            Iterator<Map.Entry<Key, IdempotencyRecord>> it = rows.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<Key, IdempotencyRecord> entry = it.next();
                if ("completed".equals(entry.getValue().status()) && entry.getValue().expiresAt() <= now) {
                    it.remove();
                    count++;
                }
            }
            return count;
        }
    }

    public static final class SqlStore implements Store {
        private final Connection conn;

        public SqlStore(Connection conn) {
            this.conn = conn;
        }

        public void migrate() {
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("CREATE TABLE IF NOT EXISTS idempotency_records (scope TEXT NOT NULL, idem_key TEXT NOT NULL, request_fingerprint TEXT NOT NULL, status TEXT NOT NULL CHECK (status IN ('in_progress', 'completed', 'uncertain')), response_status INTEGER NULL, response_body TEXT NULL, created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL, PRIMARY KEY (scope, idem_key))");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_idempotency_records_expires_at ON idempotency_records (expires_at)");
            } catch (SQLException e) {
                throw new IdempotencyError("STORE_ERROR", 500, e.getMessage());
            }
        }

        @Override
        public synchronized boolean tryClaim(IdempotencyRecord record, long now) {
            String sql = "INSERT INTO idempotency_records (scope, idem_key, request_fingerprint, status, response_status, response_body, created_at, expires_at) VALUES (?, ?, ?, 'in_progress', NULL, NULL, ?, ?) ON CONFLICT (scope, idem_key) DO UPDATE SET request_fingerprint = excluded.request_fingerprint, status = 'in_progress', response_status = NULL, response_body = NULL, created_at = excluded.created_at, expires_at = excluded.expires_at WHERE idempotency_records.status = 'completed' AND idempotency_records.expires_at <= ?";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, record.scope());
                pstmt.setString(2, record.idemKey());
                pstmt.setString(3, record.requestFingerprint());
                pstmt.setLong(4, record.createdAt());
                pstmt.setLong(5, record.expiresAt());
                pstmt.setLong(6, now);
                int affected = pstmt.executeUpdate();
                return affected == 1;
            } catch (SQLException e) {
                throw new IdempotencyError("STORE_ERROR", 500, e.getMessage());
            }
        }

        @Override
        public synchronized IdempotencyRecord get(String scope, String idemKey) {
            String sql = "SELECT scope, idem_key, request_fingerprint, status, response_status, response_body, created_at, expires_at FROM idempotency_records WHERE scope = ? AND idem_key = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, scope);
                pstmt.setString(2, idemKey);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) {
                        String rScope = rs.getString(1);
                        String rIdemKey = rs.getString(2);
                        String rFp = rs.getString(3);
                        String rStatus = rs.getString(4);
                        int rRespStatusVal = rs.getInt(5);
                        Integer rRespStatus = rs.wasNull() ? null : rRespStatusVal;
                        String rRespBody = rs.getString(6);
                        long rCreatedAt = rs.getLong(7);
                        long rExpiresAt = rs.getLong(8);
                        return new IdempotencyRecord(rScope, rIdemKey, rFp, rStatus, rRespStatus, rRespBody, rCreatedAt, rExpiresAt);
                    }
                    return null;
                }
            } catch (SQLException e) {
                throw new IdempotencyError("STORE_ERROR", 500, e.getMessage());
            }
        }

        @Override
        public synchronized void complete(String scope, String idemKey, long createdAt, int responseStatus, String responseBody) {
            String sql = "UPDATE idempotency_records SET status = 'completed', response_status = ?, response_body = ? WHERE scope = ? AND idem_key = ? AND created_at = ? AND status = 'in_progress'";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setInt(1, responseStatus);
                pstmt.setString(2, responseBody);
                pstmt.setString(3, scope);
                pstmt.setString(4, idemKey);
                pstmt.setLong(5, createdAt);
                pstmt.executeUpdate();
            } catch (SQLException e) {
                throw new IdempotencyError("STORE_ERROR", 500, e.getMessage());
            }
        }

        @Override
        public synchronized void delete(String scope, String idemKey, long createdAt) {
            String sql = "DELETE FROM idempotency_records WHERE scope = ? AND idem_key = ? AND created_at = ? AND status = 'in_progress'";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, scope);
                pstmt.setString(2, idemKey);
                pstmt.setLong(3, createdAt);
                pstmt.executeUpdate();
            } catch (SQLException e) {
                throw new IdempotencyError("STORE_ERROR", 500, e.getMessage());
            }
        }

        /** See Store. One conditional UPDATE. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database. */
        @Override
        public synchronized void markUncertain(String scope, String idemKey, long createdAt) {
            String sql = "UPDATE idempotency_records SET status = 'uncertain' WHERE scope = ? AND idem_key = ? AND created_at = ? AND status = 'in_progress'";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, scope);
                pstmt.setString(2, idemKey);
                pstmt.setLong(3, createdAt);
                pstmt.executeUpdate();
            } catch (SQLException e) {
                throw new IdempotencyError("STORE_ERROR", 500, e.getMessage());
            }
        }

        private static final String UNCERTAIN = "(status = 'uncertain' OR (status = 'in_progress' AND expires_at <= ?))";

        /** See Store. One conditional DELETE. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database. */
        @Override
        public synchronized boolean release(String scope, String idemKey, long now) {
            String sql = "DELETE FROM idempotency_records WHERE scope = ? AND idem_key = ? AND " + UNCERTAIN;
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, scope);
                pstmt.setString(2, idemKey);
                pstmt.setLong(3, now);
                return pstmt.executeUpdate() == 1;
            } catch (SQLException e) {
                throw new IdempotencyError("STORE_ERROR", 500, e.getMessage());
            }
        }

        /** See Store. One conditional UPDATE. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database. */
        @Override
        public synchronized boolean resolve(String scope, String idemKey, int responseStatus, String responseBody, long now, long newExpiresAt) {
            String sql = "UPDATE idempotency_records SET status = 'completed', response_status = ?, response_body = ?, expires_at = ? WHERE scope = ? AND idem_key = ? AND " + UNCERTAIN;
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setInt(1, responseStatus);
                pstmt.setString(2, responseBody);
                pstmt.setLong(3, newExpiresAt);
                pstmt.setString(4, scope);
                pstmt.setString(5, idemKey);
                pstmt.setLong(6, now);
                return pstmt.executeUpdate() == 1;
            } catch (SQLException e) {
                throw new IdempotencyError("STORE_ERROR", 500, e.getMessage());
            }
        }

        /** See Store. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the database. */
        @Override
        public synchronized List<IdempotencyRecord> listUncertain(int limit, long now) {
            String sql = "SELECT scope, idem_key, request_fingerprint, status, response_status, response_body, created_at, expires_at FROM idempotency_records WHERE " + UNCERTAIN + " ORDER BY created_at, rowid LIMIT ?";
            List<IdempotencyRecord> out = new ArrayList<>();
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setLong(1, now);
                pstmt.setInt(2, Math.max(0, limit));
                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        int st = rs.getInt(5);
                        Integer rst = rs.wasNull() ? null : st;
                        out.add(new IdempotencyRecord(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                                rst, rs.getString(6), rs.getLong(7), rs.getLong(8)));
                    }
                }
                return out;
            } catch (SQLException e) {
                throw new IdempotencyError("STORE_ERROR", 500, e.getMessage());
            }
        }

        /** Deletes expired COMPLETED rows only (uncertain rows wait for release/resolve). Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        @Override
        public synchronized int purgeExpired(long now) {
            String sql = "DELETE FROM idempotency_records WHERE status = 'completed' AND expires_at <= ?";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setLong(1, now);
                return pstmt.executeUpdate();
            } catch (SQLException e) {
                throw new IdempotencyError("STORE_ERROR", 500, e.getMessage());
            }
        }
    }

    public record IdempotencyRecord(
        String scope,
        String idemKey,
        String requestFingerprint,
        String status,
        Integer responseStatus,
        String responseBody,
        long createdAt,
        long expiresAt
    ) {}

    public record HttpResponse(int status, String contentType, String body) {}

    public record OperationResult(int status, String body) {}

    public static final class IdempotencyError extends RuntimeException {
        public final String code;
        public final int status;

        public IdempotencyError(String code, int status, String message) {
            super(message);
            this.code = code;
            this.status = status;
        }
    }

    public static final class IdempotencyOptions {
        public LongSupplier clock = null;
        public long ttlSeconds = 86400;
        public Set<String> requiredMethods = Set.of("POST", "PATCH");
    }

    public static final class IdempotencyService {
        private final Store store;
        private final LongSupplier clock;
        private final long ttlSeconds;
        private final Set<String> requiredMethods;

        private static final String PROBLEM_KEY_MISSING = "{\"type\":\"https://developer.example.com/problems/idempotency-key-missing\",\"title\":\"Idempotency-Key is missing\",\"detail\":\"This operation requires an Idempotency-Key request header.\"}";
        private static final String PROBLEM_KEY_INVALID = "{\"type\":\"https://developer.example.com/problems/idempotency-key-invalid\",\"title\":\"Idempotency-Key is invalid\",\"detail\":\"An Idempotency-Key must be 1 to 255 printable ASCII characters.\"}";
        private static final String PROBLEM_KEY_REUSED = "{\"type\":\"https://developer.example.com/problems/idempotency-key-reused\",\"title\":\"Idempotency-Key is already used\",\"detail\":\"This Idempotency-Key was already used with a different request payload.\"}";
        private static final String PROBLEM_OUTCOME_UNKNOWN = "{\"type\":\"https://developer.example.com/problems/outcome_unknown\",\"title\":\"The outcome of the first request is unknown\",\"detail\":\"The first request with this Idempotency-Key failed in a way that may have taken effect. It will not be run again until it is reconciled.\"}";
        private static final String PROBLEM_REQUEST_IN_PROGRESS = "{\"type\":\"https://developer.example.com/problems/idempotency-request-outstanding\",\"title\":\"A request is outstanding for this Idempotency-Key\",\"detail\":\"A request with the same Idempotency-Key is still being processed. Retry later.\"}";

        public IdempotencyService(Store store, IdempotencyOptions options) {
            if (store == null) {
                throw new IllegalArgumentException("Store cannot be null");
            }
            this.store = store;
            IdempotencyOptions opts = options != null ? options : new IdempotencyOptions();
            if (opts.ttlSeconds < 1) {
                throw new IdempotencyError("INVALID_OPTIONS", 500, "ttl_seconds must be >= 1");
            }
            this.ttlSeconds = opts.ttlSeconds;
            this.clock = opts.clock != null ? opts.clock : () -> java.time.Instant.now().getEpochSecond();
            
            Set<String> methods = new HashSet<>();
            if (opts.requiredMethods != null) {
                for (String m : opts.requiredMethods) {
                    methods.add(asciiUpper(m));
                }
            }
            this.requiredMethods = Collections.unmodifiableSet(methods);
        }

        /**
         * Runs operation at most once per (scope, key). Order: missing/invalid key 400; different fingerprint 422;
         * uncertain (or in_progress past expires_at) 409 outcome_unknown; in_progress 409; completed -> stored
         * response. In: scope (the authenticated client id), key, method, path, body, operation. Out: HttpResponse;
         * errors are application/problem+json. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: outcome_unknown and
         * expiry of completed records only (IDEM-07/10). Touches: the store, whatever the operation touches.
         */
        public HttpResponse handle(String scope, String idempotencyKey, String method, String path, String body, Supplier<OperationResult> operation) {
            String m = asciiUpper(method != null ? method : "");
            String p = path != null ? path : "";
            String b = body != null ? body : "";

            if (!requiredMethods.contains(m)) {
                OperationResult r = operation.get();
                checkResult(r);
                return new HttpResponse(r.status(), "application/json", r.body());
            }

            if (scope == null || scope.isEmpty()) {
                throw new IdempotencyError("SCOPE_REQUIRED", 500, "scope is required");
            }

            if (idempotencyKey == null || idempotencyKey.isEmpty()) {
                return new HttpResponse(400, "application/problem+json", PROBLEM_KEY_MISSING);
            }

            if (!validKey(idempotencyKey)) {
                return new HttpResponse(400, "application/problem+json", PROBLEM_KEY_INVALID);
            }

            String fp = computeFingerprint(m, p, b);
            long now = clock.getAsLong();

            IdempotencyRecord rec = new IdempotencyRecord(
                scope, idempotencyKey, fp, "in_progress", null, null, now, now + ttlSeconds
            );

            for (int attempt = 0; attempt < 2; attempt++) {
                if (store.tryClaim(rec, now)) {
                    return runClaimed(rec, operation);
                }
                IdempotencyRecord ex = store.get(scope, idempotencyKey);
                if (ex == null || ("completed".equals(ex.status()) && ex.expiresAt() <= now)) {
                    continue;
                }
                if (!java.security.MessageDigest.isEqual(ex.requestFingerprint().getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        fp.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
                    return new HttpResponse(422, "application/problem+json", PROBLEM_KEY_REUSED);
                }
                if (isUncertain(ex, now)) {
                    return new HttpResponse(409, "application/problem+json", PROBLEM_OUTCOME_UNKNOWN);
                }
                if ("in_progress".equals(ex.status())) {
                    return new HttpResponse(409, "application/problem+json", PROBLEM_REQUEST_IN_PROGRESS);
                }
                return new HttpResponse(ex.responseStatus(), "application/json", ex.responseBody());
            }

            return new HttpResponse(409, "application/problem+json", PROBLEM_REQUEST_IN_PROGRESS);
        }

        /**
         * Runs the claimed operation. OperationFailedException -> the key is deleted (a retry runs again, IDEM-08);
         * any other Throwable, or a result that cannot be stored as valid, -> the key becomes 'uncertain' (IDEM-10);
         * both re-throw. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: every error used to delete the key,
         * so a timeout after a provider charge let the retry charge twice. Touches: the store.
         */
        private HttpResponse runClaimed(IdempotencyRecord rec, Supplier<OperationResult> operation) {
            OperationResult r;
            try {
                r = operation.get();
            } catch (OperationFailedException failed) {
                store.delete(rec.scope(), rec.idemKey(), rec.createdAt());
                throw failed;
            } catch (Throwable t) {
                markUncertainQuietly(rec);
                throw t;
            }

            try {
                checkResult(r);
            } catch (RuntimeException invalid) {
                markUncertainQuietly(rec);
                throw invalid;
            }
            store.complete(rec.scope(), rec.idemKey(), rec.createdAt(), r.status(), r.body());
            return new HttpResponse(r.status(), "application/json", r.body());
        }

        /** markUncertain without masking the operation's own error if the store is down (the row then stays in_progress, which also blocks a re-run). */
        private void markUncertainQuietly(IdempotencyRecord rec) {
            try {
                store.markUncertain(rec.scope(), rec.idemKey(), rec.createdAt());
            } catch (RuntimeException storeDown) {
                // The record stays 'in_progress'; once past expires_at it is treated as uncertain all the same.
            }
        }

        /**
         * Operator / reconciliation only, never an API route: frees an uncertain key once reconciliation shows the
         * first attempt did nothing. In: the stored record's scope and key. Out: true if this call released it; false
         * (nothing changed) for a key that is not uncertain. One conditional write. 2026-11-10,
         * session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-10/11). Touches: the store.
         */
        public boolean release(String scope, String idempotencyKey) {
            return store.release(scope, idempotencyKey, clock.getAsLong());
        }

        /**
         * Operator / reconciliation only: stores the outcome reconciliation found for an uncertain key as 'completed'
         * with expires_at = now + 24h, so a retry gets it. In: scope, key, status (100-599), body. Out: true if this
         * call resolved it; false for a key that is not uncertain. One conditional write. 2026-11-10,
         * session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-11). Touches: the store.
         */
        public boolean resolve(String scope, String idempotencyKey, int status, String body) {
            checkResult(new OperationResult(status, body));
            long now = clock.getAsLong();
            return store.resolve(scope, idempotencyKey, status, body, now, now + 86400);
        }

        /**
         * Operator / reconciliation only: the uncertain keys, oldest first. In: limit. Out: [{scope, idem_key,
         * created_at}]. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the store.
         */
        public List<Map<String, Object>> listUncertain(int limit) {
            List<Map<String, Object>> out = new ArrayList<>();
            for (IdempotencyRecord r : store.listUncertain(limit, clock.getAsLong())) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("scope", r.scope());
                m.put("idem_key", r.idemKey());
                m.put("created_at", r.createdAt());
                out.add(m);
            }
            return out;
        }

        public boolean isRequired(String method, String path) {
            return requiredMethods.contains(asciiUpper(method));
        }

        public int purgeExpired() {
            return store.purgeExpired(clock.getAsLong());
        }

        private static boolean validKey(String k) {
            if (k == null || k.isEmpty() || k.length() > 255) {
                return false;
            }
            for (int i = 0; i < k.length(); i++) {
                char c = k.charAt(i);
                if (c < 0x20 || c > 0x7E) {
                    return false;
                }
            }
            return true;
        }

        private static void checkResult(OperationResult r) {
            if (r == null || r.body() == null || r.status() < 100 || r.status() > 599) {
                throw new IdempotencyError("INVALID_OPERATION_RESULT", 500, "Invalid operation result");
            }
        }
    }

    public static String asciiUpper(String s) {
        if (s == null) return "";
        char[] chars = s.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            if (chars[i] >= 'a' && chars[i] <= 'z') {
                chars[i] = (char) (chars[i] - 32);
            }
        }
        return new String(chars);
    }

    public static String computeFingerprint(String method, String path, String body) {
        String m = asciiUpper(method != null ? method : "");
        String p = path != null ? path : "";
        String b = body != null ? body : "";
        String input = m + " " + p + "\n" + b;
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(hash);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
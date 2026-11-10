package com.saas.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

import java.security.SecureRandom;
import java.sql.*;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Immutable audit event log with replay, and erasable personal data (spec docs/specs/audit_logging.md).
 *
 * <p>The log keeps EVENTS only. Everything that leads back to a person lives beside it, so it can be erased without
 * rewriting an event:
 * <ul>
 *   <li>{@code audit_log}: append-only events (UPDATE and DELETE refused). For an entry with a data subject,
 *       resource_id, old_value, new_value and why_chain_id are NULL here.</li>
 *   <li>{@code audit_personal}: per entry, an 'actor' row {actor_id, ip, user_agent, request_id} and/or a 'subject' row
 *       {resource_id, old_value, new_value, why_chain_id}, each under the person's random subject_ref.</li>
 *   <li>{@code audit_subjects}: subject_ref (random 128 bits, never derived from the id) to user_id.</li>
 * </ul>
 * {@link #eraseSubject} and {@link #applyRetention} delete personal and subject rows only; audit_log rows stay. Reads are
 * for admins only (403 otherwise) and show {@code personal_erased: true} once an entry's personal rows are gone.
 *
 * <p>Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-08/09/10 amendments after review on PR 19 and an
 * independent security review): actor ids, IPs and snapshots used to sit in audit_log forever, metadata accepted any key
 * (an IP or email there outlived any erasure), and reads had no caller check. Used by: GDPR compliance, SOC2, debugging,
 * fraud detection, governance approval. Touches: the database behind the connection; no network.
 */
public class AuditLoggingService implements AutoCloseable {

    /** Metadata keys log() accepts; anything else is 400 metadata_key_not_allowed. */
    public static final Set<String> METADATA_KEYS = Set.of("feature_flag", "erased_rows");
    private static final Set<String> ACTOR_TYPES = Set.of("user", "service", "api_key");

    private final Connection connection;
    private final ObjectMapper objectMapper;
    private final AtomicLong idSequence;
    private final Clock clock;
    private final Duration retention;
    private final SecureRandom random = new SecureRandom();

    // ------------------------------------------------------------------
    // Types
    // ------------------------------------------------------------------

    /**
     * A refused call: HTTP-style status (400, 403, 404) and a stable error code such as subject_required.
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-10). Touches: nothing.
     */
    public static class AuditException extends RuntimeException {
        private final int status;
        private final String code;

        public AuditException(int status, String code) {
            super(code);
            this.status = status;
            this.code = code;
        }

        public int status() {
            return status;
        }

        public String code() {
            return code;
        }
    }

    /**
     * The verified caller of a read, built by the application's authentication layer from the session, never from
     * request input. Reads need {@code admin}. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-10).
     */
    public record Caller(String id, boolean admin) {
        public static Caller admin(String id) {
            return new Caller(id, true);
        }

        public static Caller user(String id) {
            return new Caller(id, false);
        }
    }

    /**
     * One mutation to log. log() is an internal call made by the system that changed the data; when an end user is the
     * actor, actorId is the authenticated caller's id, never a value from a request body.
     * <ul>
     *   <li>actorType 'user' needs actorId; 'api_key' needs actorId (the key id) and actorUserId (the key's owner);
     *       'service' needs actorService (its name).</li>
     *   <li>subjectUserId: required unless resourceType is 'user' (then the subject is resourceId); a user id or the
     *       literal "none".</li>
     *   <li>metadata: only the keys feature_flag and erased_rows.</li>
     * </ul>
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     */
    public static final class LogRequest {
        public String actorType;
        public String actorId;
        public String actorUserId;
        public String actorService;
        public String ip;
        public String userAgent;
        public String requestId;
        public String subjectUserId;
        public String action;
        public String resourceType;
        public String resourceId;
        public JsonNode oldValue;
        public JsonNode newValue;
        public String whyChainId;
        public JsonNode metadata;

        /** A user-actor entry. */
        public static LogRequest byUser(String actorId, String action, String resourceType, String resourceId) {
            LogRequest r = new LogRequest();
            r.actorType = "user";
            r.actorId = actorId;
            r.action = action;
            r.resourceType = resourceType;
            r.resourceId = resourceId;
            return r;
        }

        /** A service-actor entry. */
        public static LogRequest byService(String service, String action, String resourceType, String resourceId) {
            LogRequest r = new LogRequest();
            r.actorType = "service";
            r.actorService = service;
            r.action = action;
            r.resourceType = resourceType;
            r.resourceId = resourceId;
            return r;
        }

        public LogRequest subject(String userIdOrNone) {
            this.subjectUserId = userIdOrNone;
            return this;
        }

        public LogRequest values(JsonNode oldValue, JsonNode newValue) {
            this.oldValue = oldValue;
            this.newValue = newValue;
            return this;
        }

        public LogRequest request(String ip, String userAgent, String requestId) {
            this.ip = ip;
            this.userAgent = userAgent;
            this.requestId = requestId;
            return this;
        }

        public LogRequest why(String whyChainId) {
            this.whyChainId = whyChainId;
            return this;
        }

        public LogRequest meta(JsonNode metadata) {
            this.metadata = metadata;
            return this;
        }
    }

    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /**
     * Service on the system UTC clock with a 365-day retention period. Creates the schema if missing.
     * Touches: the database.
     */
    public AuditLoggingService(Connection connection) throws SQLException {
        this(connection, Clock.systemUTC(), Duration.ofDays(365));
    }

    /**
     * Service with an injectable clock and the configured retention period for personal data (apply_retention).
     * In: connection, clock, retention (> 0). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-09).
     * Touches: the database (creates the three tables and their indexes).
     */
    public AuditLoggingService(Connection connection, Clock clock, Duration retention) throws SQLException {
        if (retention == null || retention.isNegative() || retention.isZero()) {
            throw new IllegalArgumentException("retention must be positive");
        }
        this.connection = connection;
        this.clock = Objects.requireNonNull(clock);
        this.retention = retention;
        // Decimals are read as BigDecimal, so 0.100000000000000001 and ...002 stay different when Replay
        // compares values (as doubles they were equal; CodeRabbit, PR 18, 2026-11-09).
        this.objectMapper = new ObjectMapper()
                .enable(com.fasterxml.jackson.databind.DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);
        initializeSchema();
        long max = 0;
        try (Statement st = connection.createStatement(); ResultSet rs = st.executeQuery("SELECT COALESCE(MAX(id), 0) FROM audit_log")) {
            if (rs.next()) max = rs.getLong(1);
        }
        this.idSequence = new AtomicLong(max);
    }

    /**
     * Creates audit_log, audit_subjects and audit_personal with the spec's indexes: (action, resource_type, timestamp)
     * on audit_log and (subject_ref, role) on audit_personal, so actor_id filters resolve through audit_subjects and
     * audit_personal. Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    private void initializeSchema() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id              BIGINT PRIMARY KEY,
                    timestamp       TIMESTAMP WITH TIME ZONE NOT NULL,
                    actor_type      VARCHAR(20) NOT NULL,
                    actor_service   VARCHAR(255),
                    action          VARCHAR(255) NOT NULL,
                    resource_type   VARCHAR(255) NOT NULL,
                    resource_id     VARCHAR(255),
                    old_value       TEXT,
                    new_value       TEXT,
                    why_chain_id    VARCHAR(255),
                    personal_roles  VARCHAR(20) NOT NULL,
                    metadata        TEXT
                )""");
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS audit_subjects (
                    subject_ref  VARCHAR(32) PRIMARY KEY,
                    user_id      VARCHAR(255) NOT NULL UNIQUE,
                    created_at   TIMESTAMP WITH TIME ZONE NOT NULL
                )""");
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS audit_personal (
                    log_id       BIGINT NOT NULL,
                    subject_ref  VARCHAR(32) NOT NULL REFERENCES audit_subjects (subject_ref),
                    role         VARCHAR(10) NOT NULL,
                    data         TEXT NOT NULL,
                    PRIMARY KEY (log_id, role)
                )""");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_query ON audit_log (action, resource_type, timestamp, id)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log (resource_type, resource_id, id)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log (timestamp, id)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_audit_personal_subject ON audit_personal (subject_ref, role, log_id)");
        }
    }

    // ------------------------------------------------------------------
    // Endpoint 1: Log mutation (called BEFORE commit)
    // ------------------------------------------------------------------

    /**
     * Logs one mutation. Checks, in order: actor_type (400 invalid_actor_type), action / resource_type (400 *_required),
     * the actor (400 actor_required, actor_user_required for an api_key entry, actor_service_required), the data subject
     * (400 subject_required for a non-'user' entry without subject_user_id, 400 subject_mismatch when it contradicts a
     * 'user' resource_id), metadata keys (400 metadata_key_not_allowed). Then, in ONE transaction: find or create the
     * subjects (random subject_ref), insert the audit_log row and its audit_personal rows.
     * In: LogRequest. Out: {success: true, log_id}. Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-10).
     * Touches: the database.
     */
    public synchronized Map<String, Object> log(LogRequest r) throws SQLException {
        if (r == null || r.actorType == null || !ACTOR_TYPES.contains(r.actorType)) {
            throw new AuditException(400, "invalid_actor_type");
        }
        if (isBlank(r.action)) throw new AuditException(400, "action_required");
        if (isBlank(r.resourceType)) throw new AuditException(400, "resource_type_required");
        String actorSubjectUser = null;
        switch (r.actorType) {
            case "user" -> {
                if (isBlank(r.actorId)) throw new AuditException(400, "actor_required");
                actorSubjectUser = r.actorId;
            }
            case "api_key" -> {
                if (isBlank(r.actorId)) throw new AuditException(400, "actor_required");
                if (isBlank(r.actorUserId)) throw new AuditException(400, "actor_user_required");
                actorSubjectUser = r.actorUserId;
            }
            default -> {
                if (isBlank(r.actorService)) throw new AuditException(400, "actor_service_required");
            }
        }
        String subjectUser;
        if ("user".equals(r.resourceType)) {
            if (isBlank(r.resourceId)) throw new AuditException(400, "resource_id_required");
            if (r.subjectUserId != null && !r.subjectUserId.equals(r.resourceId)) {
                throw new AuditException(400, "subject_mismatch");
            }
            subjectUser = r.resourceId;
        } else {
            if (isBlank(r.subjectUserId)) throw new AuditException(400, "subject_required");
            subjectUser = "none".equals(r.subjectUserId) ? null : r.subjectUserId;
        }
        String metaJson = null;
        JsonNode meta = r.metadata;
        if (meta != null && !meta.isNull() && !meta.isMissingNode()) {
            if (!meta.isObject()) throw new AuditException(400, "metadata_key_not_allowed");
            Iterator<String> names = meta.fieldNames();
            while (names.hasNext()) {
                if (!METADATA_KEYS.contains(names.next())) throw new AuditException(400, "metadata_key_not_allowed");
            }
            metaJson = meta.toString();
        }

        long id = idSequence.incrementAndGet();
        Instant now = clock.instant();
        String roles = String.join(",", actorSubjectUser != null && subjectUser != null ? List.of("actor", "subject")
                : actorSubjectUser != null ? List.of("actor") : subjectUser != null ? List.of("subject") : List.of());
        boolean autoCommit = connection.getAutoCommit();
        connection.setAutoCommit(false);
        try {
            String actorRef = actorSubjectUser == null ? null : findOrCreateSubject(actorSubjectUser, now);
            String subjectRef = subjectUser == null ? null : findOrCreateSubject(subjectUser, now);
            try (PreparedStatement ps = connection.prepareStatement("""
                    INSERT INTO audit_log (id, timestamp, actor_type, actor_service, action, resource_type, resource_id,
                                           old_value, new_value, why_chain_id, personal_roles, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""")) {
                ps.setLong(1, id);
                ps.setTimestamp(2, Timestamp.from(now));
                ps.setString(3, r.actorType);
                ps.setString(4, "service".equals(r.actorType) ? r.actorService : null);
                ps.setString(5, r.action);
                ps.setString(6, r.resourceType);
                boolean inLog = subjectRef == null;
                ps.setString(7, inLog ? r.resourceId : null);
                ps.setString(8, inLog ? toJsonString(r.oldValue) : null);
                ps.setString(9, inLog ? toJsonString(r.newValue) : null);
                ps.setString(10, inLog ? r.whyChainId : null);
                ps.setString(11, roles);
                ps.setString(12, metaJson);
                ps.executeUpdate();
            }
            if (actorRef != null) {
                ObjectNode data = objectMapper.createObjectNode();
                data.put("actor_id", r.actorId);
                data.put("ip", r.ip);
                data.put("user_agent", r.userAgent);
                data.put("request_id", r.requestId);
                insertPersonal(id, actorRef, "actor", data);
            }
            if (subjectRef != null) {
                ObjectNode data = objectMapper.createObjectNode();
                data.put("resource_id", r.resourceId);
                data.set("old_value", r.oldValue == null ? NullNode.getInstance() : r.oldValue);
                data.set("new_value", r.newValue == null ? NullNode.getInstance() : r.newValue);
                data.put("why_chain_id", r.whyChainId);
                insertPersonal(id, subjectRef, "subject", data);
            }
            connection.commit();
        } catch (SQLException | RuntimeException e) {
            connection.rollback();
            throw e;
        } finally {
            connection.setAutoCommit(autoCommit);
        }
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", true);
        response.put("log_id", String.valueOf(id));
        return response;
    }

    /**
     * Finds the user's subject_ref or creates one: 16 random bytes in hex, never derived from the user id (insert if
     * absent on user_id). In: user id, now. Out: subject_ref. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (inside the caller's transaction).
     */
    private String findOrCreateSubject(String userId, Instant now) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement("SELECT subject_ref FROM audit_subjects WHERE user_id = ?")) {
            ps.setString(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getString(1);
            }
        }
        byte[] b = new byte[16];
        random.nextBytes(b);
        String ref = HexFormat.of().formatHex(b);
        try (PreparedStatement ps = connection.prepareStatement(
                "INSERT INTO audit_subjects (subject_ref, user_id, created_at) VALUES (?, ?, ?)")) {
            ps.setString(1, ref);
            ps.setString(2, userId);
            ps.setTimestamp(3, Timestamp.from(now));
            ps.executeUpdate();
        }
        return ref;
    }

    private void insertPersonal(long logId, String subjectRef, String role, JsonNode data) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(
                "INSERT INTO audit_personal (log_id, subject_ref, role, data) VALUES (?, ?, ?, ?)")) {
            ps.setLong(1, logId);
            ps.setString(2, subjectRef);
            ps.setString(3, role);
            ps.setString(4, data.toString());
            ps.executeUpdate();
        }
    }

    // ------------------------------------------------------------------
    // Endpoint 5 / 6: erasure and retention
    // ------------------------------------------------------------------

    /**
     * erase_subject(user_id): deletes every audit_personal row under the user's subject_ref, then the user's
     * audit_subjects row, in one transaction; no audit_log row is touched. Then adds exactly one entry:
     * 'audit_subject_erased', actor_type 'service', resource_type 'user', no subject, resource_id NULL,
     * personal_roles '', metadata {erased_rows}. Nothing may log this user afterwards.
     * In: user id. Out: {erased_rows} (audit_personal rows deleted). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
     * (AUDIT-08). Touches: the database.
     */
    public synchronized Map<String, Object> eraseSubject(String userId) throws SQLException {
        boolean autoCommit = connection.getAutoCommit();
        connection.setAutoCommit(false);
        int erased = 0;
        try {
            String ref = null;
            try (PreparedStatement ps = connection.prepareStatement("SELECT subject_ref FROM audit_subjects WHERE user_id = ?")) {
                ps.setString(1, userId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) ref = rs.getString(1);
                }
            }
            if (ref != null) {
                try (PreparedStatement ps = connection.prepareStatement("DELETE FROM audit_personal WHERE subject_ref = ?")) {
                    ps.setString(1, ref);
                    erased = ps.executeUpdate();
                }
                try (PreparedStatement ps = connection.prepareStatement("DELETE FROM audit_subjects WHERE subject_ref = ?")) {
                    ps.setString(1, ref);
                    ps.executeUpdate();
                }
            }
            long id = idSequence.incrementAndGet();
            try (PreparedStatement ps = connection.prepareStatement("""
                    INSERT INTO audit_log (id, timestamp, actor_type, actor_service, action, resource_type, resource_id,
                                           old_value, new_value, why_chain_id, personal_roles, metadata)
                    VALUES (?, ?, 'service', 'audit', 'audit_subject_erased', 'user', NULL, NULL, NULL, NULL, '', ?)""")) {
                ps.setLong(1, id);
                ps.setTimestamp(2, Timestamp.from(clock.instant()));
                ps.setString(3, "{\"erased_rows\":" + erased + "}");
                ps.executeUpdate();
            }
            connection.commit();
        } catch (SQLException | RuntimeException e) {
            connection.rollback();
            throw e;
        } finally {
            connection.setAutoCommit(autoCommit);
        }
        return Map.of("erased_rows", erased);
    }

    /**
     * apply_retention(now): deletes the audit_personal rows of entries older than the retention period, then every
     * audit_subjects row left with no audit_personal rows; audit_log rows stay. In: now. Out: {erased_rows}.
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-09). Touches: the database.
     */
    public synchronized Map<String, Object> applyRetention(Instant now) throws SQLException {
        Timestamp cutoff = Timestamp.from(now.minus(retention));
        boolean autoCommit = connection.getAutoCommit();
        connection.setAutoCommit(false);
        int erased;
        try {
            try (PreparedStatement ps = connection.prepareStatement(
                    "DELETE FROM audit_personal WHERE log_id IN (SELECT id FROM audit_log WHERE timestamp < ?)")) {
                ps.setTimestamp(1, cutoff);
                erased = ps.executeUpdate();
            }
            try (Statement st = connection.createStatement()) {
                st.executeUpdate("DELETE FROM audit_subjects s WHERE NOT EXISTS "
                        + "(SELECT 1 FROM audit_personal p WHERE p.subject_ref = s.subject_ref)");
            }
            connection.commit();
        } catch (SQLException | RuntimeException e) {
            connection.rollback();
            throw e;
        } finally {
            connection.setAutoCommit(autoCommit);
        }
        return Map.of("erased_rows", erased);
    }

    // ------------------------------------------------------------------
    // Endpoint 2: Query logs (admin only)
    // ------------------------------------------------------------------

    /**
     * Query audit logs with optional filters and pagination; admins only (403 forbidden otherwise).
     * actor_id resolves through audit_subjects and audit_personal (an erased actor matches nothing); action supports a
     * trailing "*" wildcard; dates are inclusive ISO days (UTC).
     * Out: {logs: [{id, timestamp, actor_id, actor_type, actor_service, action, resource_type, resource_id, old_value,
     * new_value, why_chain_id, metadata, personal_erased}], total, has_more}.
     * Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-08/10). Touches: reads the database.
     */
    public Map<String, Object> queryLogs(Caller caller, String actorId, String action, String resourceType,
                                         int limit, int offset, String dateFrom, String dateTo) throws SQLException {
        requireAdmin(caller);
        if (limit <= 0) limit = 100;
        if (offset < 0) offset = 0;

        List<String> where = new ArrayList<>();
        List<Object> params = new ArrayList<>();
        String from = "audit_log l";
        if (!isBlank(actorId)) {
            // Resolve the actor through audit_subjects first (an erased actor has no row, so nothing matches), then
            // through the (subject_ref, role, log_id) index of audit_personal.
            String ref = null;
            try (PreparedStatement ps = connection.prepareStatement("SELECT subject_ref FROM audit_subjects WHERE user_id = ?")) {
                ps.setString(1, actorId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) ref = rs.getString(1);
                }
            }
            if (ref == null) {
                Map<String, Object> empty = new LinkedHashMap<>();
                empty.put("logs", new ArrayList<>());
                empty.put("total", 0L);
                empty.put("has_more", false);
                return empty;
            }
            from = "audit_personal p JOIN audit_log l ON l.id = p.log_id";
            where.add("p.subject_ref = ?");
            params.add(ref);
            where.add("p.role = 'actor'");
        }
        if (!isBlank(action)) {
            if (action.endsWith("*")) {
                where.add("l.action LIKE ? ESCAPE '\\'");
                params.add(escapeLike(action.substring(0, action.length() - 1)) + "%");
            } else {
                where.add("l.action = ?");
                params.add(action);
            }
        }
        if (!isBlank(resourceType)) {
            where.add("l.resource_type = ?");
            params.add(resourceType);
        }
        if (!isBlank(dateFrom)) {
            where.add("l.timestamp >= ?");
            params.add(Timestamp.from(LocalDate.parse(dateFrom).atStartOfDay().toInstant(ZoneOffset.UTC)));
        }
        if (!isBlank(dateTo)) {
            where.add("l.timestamp < ?");
            params.add(Timestamp.from(LocalDate.parse(dateTo).plusDays(1).atStartOfDay().toInstant(ZoneOffset.UTC)));
        }
        String whereSql = where.isEmpty() ? "" : " WHERE " + String.join(" AND ", where);

        long total = 0;
        try (PreparedStatement ps = connection.prepareStatement("SELECT COUNT(*) FROM " + from + whereSql)) {
            bindParams(ps, params);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) total = rs.getLong(1);
            }
        }
        List<Map<String, Object>> logs = new ArrayList<>();
        try (PreparedStatement ps = connection.prepareStatement("SELECT l.* FROM " + from + whereSql
                + " ORDER BY l.timestamp ASC, l.id ASC LIMIT ? OFFSET ?")) {
            bindParams(ps, params);
            ps.setInt(params.size() + 1, limit);
            ps.setInt(params.size() + 2, offset);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) logs.add(mapRow(rs));
            }
        }
        attachPersonal(logs);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("logs", logs);
        response.put("total", total);
        response.put("has_more", (offset + limit) < total);
        return response;
    }

    // ------------------------------------------------------------------
    // Endpoint 3: Replay (admin only)
    // ------------------------------------------------------------------

    /**
     * The resource state at the time of the entry (its old_value) and whether a later entry for the same resource holds
     * a different value. An entry whose subject row was erased answers {log_id, timestamp, erased: true,
     * resource_state_at_time: null, has_diverged: null}; any other entry answers erased: false with its state.
     * Admins only (403). Unknown id: NoSuchElementException.
     * Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Changed the same day (Phase B.2): erased: false is
     * returned for a live entry too. Touches: reads the database.
     */
    public Map<String, Object> replay(Caller caller, String logId) throws SQLException {
        requireAdmin(caller);
        long id;
        try {
            id = Long.parseLong(logId);
        } catch (NumberFormatException e) {
            throw new NoSuchElementException("Invalid log_id: " + logId);
        }
        Map<String, Object> entry;
        try (PreparedStatement ps = connection.prepareStatement("SELECT * FROM audit_log WHERE id = ?")) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new NoSuchElementException("Log entry not found: " + logId);
                entry = mapRow(rs);
            }
        }
        List<Map<String, Object>> one = new ArrayList<>(List.of(entry));
        attachPersonal(one);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("log_id", logId);
        response.put("timestamp", entry.get("timestamp"));
        boolean hasSubject = roles(entry).contains("subject");
        String subjectRef = hasSubject ? personalRef(id, "subject") : null;
        if (hasSubject && subjectRef == null) {
            response.put("erased", true);
            response.put("resource_state_at_time", null);
            response.put("has_diverged", null);
            return response;
        }
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2: replay's "erased" reflects the entry's subject row):
        // a live entry says erased: false, so callers read one field in every case.
        response.put("erased", false);
        response.put("resource_state_at_time", entry.get("old_value"));
        response.put("has_diverged", checkDivergence(id, (String) entry.get("resource_type"),
                (String) entry.get("resource_id"), (JsonNode) entry.get("new_value"), subjectRef));
        return response;
    }

    /**
     * True when any later entry for the same resource holds a different new_value (A, A, B has diverged). For an entry
     * with a subject the later entries are read from that subject's rows. Values compare as JSON with exact decimals.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the database.
     */
    private boolean checkDivergence(long logId, String resourceType, String resourceId, JsonNode newValue,
                                    String subjectRef) throws SQLException {
        if (subjectRef == null) {
            try (PreparedStatement ps = connection.prepareStatement(
                    "SELECT new_value FROM audit_log WHERE resource_type = ? AND resource_id = ? AND id > ? ORDER BY id")) {
                ps.setString(1, resourceType);
                ps.setString(2, resourceId);
                ps.setLong(3, logId);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        if (!Objects.equals(newValue, parseJson(rs.getString(1)))) return true;
                    }
                }
            }
            return false;
        }
        try (PreparedStatement ps = connection.prepareStatement("""
                SELECT p.data FROM audit_personal p JOIN audit_log l ON l.id = p.log_id
                WHERE p.subject_ref = ? AND p.role = 'subject' AND l.resource_type = ? AND l.id > ? ORDER BY l.id""")) {
            ps.setString(1, subjectRef);
            ps.setString(2, resourceType);
            ps.setLong(3, logId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    JsonNode data = parseJson(rs.getString(1));
                    if (Objects.equals(resourceId, text(data.get("resource_id")))
                            && !Objects.equals(newValue, data.get("new_value"))) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    // ------------------------------------------------------------------
    // Endpoint 4: Search (admin only)
    // ------------------------------------------------------------------

    /**
     * Search over action, resource_type and resource_id (also a subject entry's resource_id); admins only (403).
     * In: caller, term, optional resource type, limit (default 50). Out: {results: [...]}, newest first.
     * Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the database.
     */
    public Map<String, Object> search(Caller caller, String query, String resourceType, int limit) throws SQLException {
        requireAdmin(caller);
        if (limit <= 0) limit = 50;
        List<String> where = new ArrayList<>();
        List<Object> params = new ArrayList<>();
        if (!isBlank(query)) {
            String like = "%" + escapeLike(query) + "%";
            where.add("(l.action LIKE ? ESCAPE '\\' OR l.resource_type LIKE ? ESCAPE '\\' OR l.resource_id LIKE ? ESCAPE '\\'"
                    + " OR EXISTS (SELECT 1 FROM audit_personal p WHERE p.log_id = l.id AND p.role = 'subject'"
                    + " AND p.data LIKE ? ESCAPE '\\'))");
            params.add(like);
            params.add(like);
            params.add(like);
            params.add("%\"resource_id\":\"%" + escapeLike(query) + "%\"%");
        }
        if (!isBlank(resourceType)) {
            where.add("l.resource_type = ?");
            params.add(resourceType);
        }
        String whereSql = where.isEmpty() ? "" : " WHERE " + String.join(" AND ", where);
        List<Map<String, Object>> results = new ArrayList<>();
        try (PreparedStatement ps = connection.prepareStatement("SELECT l.* FROM audit_log l" + whereSql
                + " ORDER BY l.timestamp DESC, l.id DESC LIMIT ?")) {
            bindParams(ps, params);
            ps.setInt(params.size() + 1, limit);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) results.add(mapRow(rs));
            }
        }
        attachPersonal(results);
        return Map.of("results", results);
    }

    // ------------------------------------------------------------------
    // Immutability enforcement
    // ------------------------------------------------------------------

    /**
     * Updating an audit log entry always fails: the table is append-only. In production also revoke UPDATE/DELETE
     * grants on audit_log. Throws UnsupportedOperationException.
     */
    public void updateLog(String logId) {
        throw new UnsupportedOperationException(
                "Audit log entries are immutable. UPDATE on log_id=" + logId + " is not permitted.");
    }

    /** Deleting an audit log entry always fails (append-only). Throws UnsupportedOperationException. */
    public void deleteLog(String logId) {
        throw new UnsupportedOperationException(
                "Audit log entries are immutable. DELETE on log_id=" + logId + " is not permitted.");
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static void requireAdmin(Caller caller) {
        if (caller == null || !caller.admin()) {
            throw new AuditException(403, "forbidden");
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private static String escapeLike(String s) {
        return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }

    private static Set<String> roles(Map<String, Object> entry) {
        String r = (String) entry.get("personal_roles");
        return r == null || r.isEmpty() ? Set.of() : Set.of(r.split(","));
    }

    private String personalRef(long logId, String role) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT subject_ref FROM audit_personal WHERE log_id = ? AND role = ?")) {
            ps.setLong(1, logId);
            ps.setString(2, role);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        }
    }

    /** Fills actor_id and the subject fields from audit_personal and sets personal_erased. Touches: reads the database. */
    private void attachPersonal(List<Map<String, Object>> logs) throws SQLException {
        if (logs.isEmpty()) return;
        Map<Long, Map<String, JsonNode>> personal = new HashMap<>();
        StringBuilder in = new StringBuilder();
        for (int i = 0; i < logs.size(); i++) in.append(i == 0 ? "?" : ",?");
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT log_id, role, data FROM audit_personal WHERE log_id IN (" + in + ")")) {
            for (int i = 0; i < logs.size(); i++) ps.setLong(i + 1, Long.parseLong((String) logs.get(i).get("id")));
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    personal.computeIfAbsent(rs.getLong(1), k -> new HashMap<>()).put(rs.getString(2), parseJson(rs.getString(3)));
                }
            }
        }
        for (Map<String, Object> log : logs) {
            Map<String, JsonNode> rows = personal.getOrDefault(Long.parseLong((String) log.get("id")), Map.of());
            Set<String> roles = roles(log);
            boolean erased = false;
            if (roles.contains("actor")) {
                JsonNode a = rows.get("actor");
                if (a == null) erased = true;
                log.put("actor_id", a == null ? null : text(a.get("actor_id")));
            }
            if (roles.contains("subject")) {
                JsonNode s = rows.get("subject");
                if (s == null) {
                    erased = true;
                } else {
                    log.put("resource_id", text(s.get("resource_id")));
                    log.put("old_value", s.has("old_value") ? s.get("old_value") : NullNode.getInstance());
                    log.put("new_value", s.has("new_value") ? s.get("new_value") : NullNode.getInstance());
                    log.put("why_chain_id", text(s.get("why_chain_id")));
                }
            }
            log.put("personal_erased", erased);
        }
    }

    private static String text(JsonNode n) {
        return n == null || n.isNull() ? null : n.asText();
    }

    private Map<String, Object> mapRow(ResultSet rs) throws SQLException {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("id", String.valueOf(rs.getLong("id")));
        row.put("timestamp", rs.getTimestamp("timestamp").toInstant().toString());
        row.put("actor_id", null);
        row.put("actor_type", rs.getString("actor_type"));
        row.put("actor_service", rs.getString("actor_service"));
        row.put("action", rs.getString("action"));
        row.put("resource_type", rs.getString("resource_type"));
        row.put("resource_id", rs.getString("resource_id"));
        row.put("old_value", parseJson(rs.getString("old_value")));
        row.put("new_value", parseJson(rs.getString("new_value")));
        row.put("why_chain_id", rs.getString("why_chain_id"));
        row.put("personal_roles", rs.getString("personal_roles"));
        row.put("metadata", parseJson(rs.getString("metadata")));
        row.put("personal_erased", false);
        return row;
    }

    private void bindParams(PreparedStatement ps, List<Object> params) throws SQLException {
        for (int i = 0; i < params.size(); i++) {
            Object p = params.get(i);
            if (p instanceof Timestamp ts) {
                ps.setTimestamp(i + 1, ts);
            } else if (p instanceof String s) {
                ps.setString(i + 1, s);
            } else {
                ps.setObject(i + 1, p);
            }
        }
    }

    private String toJsonString(JsonNode node) {
        if (node == null || node instanceof MissingNode || node instanceof NullNode) {
            return null;
        }
        return node.toString();
    }

    private JsonNode parseJson(String json) {
        if (json == null || json.isBlank()) {
            return NullNode.getInstance();
        }
        try {
            return objectMapper.readTree(json);
        } catch (JsonProcessingException e) {
            return new TextNode(json);
        }
    }

    @Override
    public void close() throws SQLException {
        if (connection != null && !connection.isClosed()) {
            connection.close();
        }
    }

    /** Converts a map or bean to a JsonNode for LogRequest values. Pure. */
    public static JsonNode toJsonNode(Object obj) {
        if (obj == null) return NullNode.getInstance();
        return new ObjectMapper().valueToTree(obj);
    }
}

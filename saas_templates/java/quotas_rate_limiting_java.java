import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.sql.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Quotas and rate limiting by tier (spec: GEMINI_DISPATCH_MASTER_SPEC, template #5). Every API call passes, in
 * order: per-IP rate limit (10/second), per-user rate limit (100/minute), feature gate by tier, monthly API call
 * quota (solo 1,000, team 10,000, enterprise unlimited) and, for uploads, the storage quota (solo 1e9 bytes, team
 * 100e9, enterprise unlimited). Time comes from the injected Clock, so tests are deterministic.
 *
 * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the usage_metrics column "month" is a reserved
 * word in H2 (every test failed creating the table), so it is usage_month; every instance shared one in-memory
 * database, so usage leaked between instances; the usage counter was overwritten with 1 on each call instead of
 * incremented, so the monthly quota could never be reached; the 403 always named "team" as the minimum tier.
 * Touches: a private in-memory H2 database per instance. No network, no money.
 */
public class QuotaManager implements AutoCloseable {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final Connection conn;
    private final Clock clock;

    /**
     * Creates a manager on the system UTC clock with its own in-memory database. Touches: in-memory H2.
     * Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
     */
    public QuotaManager() throws SQLException {
        this(Clock.systemUTC());
    }

    /**
     * Creates a manager on the given clock with its own private in-memory database.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: one database per instance (it was a shared
     * "test" database that kept every earlier instance's usage). Touches: in-memory H2.
     */
    public QuotaManager(Clock clock) throws SQLException {
        this.clock = clock;
        this.conn = DriverManager.getConnection(
                "jdbc:h2:mem:quotas_" + UUID.randomUUID().toString().replace("-", ""));
        initSchema();
    }

    /**
     * Creates usage_metrics, api_calls and user_files. The spec's usage_metrics.month is stored as usage_month
     * because MONTH is a reserved word in H2 (and a function name in MySQL).
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    private void initSchema() throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS usage_metrics (" +
                    "user_id VARCHAR(255) NOT NULL, usage_month VARCHAR(7) NOT NULL, call_count INT NOT NULL, " +
                    "storage_bytes BIGINT NOT NULL, updated_at TIMESTAMP, PRIMARY KEY (user_id, usage_month))");
            stmt.execute("CREATE TABLE IF NOT EXISTS api_calls (" +
                    "id IDENTITY PRIMARY KEY, user_id VARCHAR(255), ip VARCHAR(45), endpoint VARCHAR(255), " +
                    "timestamp TIMESTAMP, status_code INT, response_time_ms INT)");
            stmt.execute("CREATE TABLE IF NOT EXISTS user_files (" +
                    "id IDENTITY PRIMARY KEY, user_id VARCHAR(255), file_size BIGINT, uploaded_at TIMESTAMP)");
            // Indexes for the two rate-limit window queries (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: without them
            // every call scanned all of api_calls, so QUOTA-13's 10,001 enterprise calls were quadratic).
            stmt.execute("CREATE INDEX IF NOT EXISTS api_calls_user_ts ON api_calls (user_id, timestamp)");
            stmt.execute("CREATE INDEX IF NOT EXISTS api_calls_ip_ts ON api_calls (ip, timestamp)");
        }
    }

    /**
     * Runs every gate for one API call and, if all pass, stores the upload (if any), records the call and
     * increments the month's usage. Input: user, endpoint, client IP, optional uploaded bytes, feature name.
     * Output: Response 200, or 429 (ip_rate_limit_exceeded / rate_limit_exceeded / quota_exceeded),
     * 403 (feature_not_available_in_tier, with tier, minimum_tier and upgrade_url) or 413 (storage_quota_exceeded) with
     * a JSON body. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (quotas spec, Phase B.2: the feature-gate refusal
     * is named feature_not_available_in_tier in every language; it was feature_not_available).
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: synchronized, so two concurrent calls cannot
     * both pass the same last unit of quota; the 403 names the real minimum tier and an upgrade hint.
     * Touches: the database.
     */
    public synchronized Response handleApiCall(User user, String endpoint, String ip, byte[] incomingFile, String feature) throws SQLException {
        return handleApiCall(user, endpoint, ip, incomingFile == null ? -1L : (long) incomingFile.length, feature);
    }

    /**
     * The same gates as {@link #handleApiCall(User, String, String, byte[], String)}, for an upload whose size is known
     * (e.g. from Content-Length) without its bytes in memory. In: user, endpoint, IP, incoming size in bytes (-1 = not an
     * upload), feature. Out: Response as above. Why: QUOTA-13 ("enterprise storage upload of any size stored": a size
     * over every other tier's limit cannot be held in a Java byte array); 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * A limit of -1 is unlimited in every quota. Touches: the database.
     */
    public synchronized Response handleApiCall(User user, String endpoint, String ip, long incomingSize, String feature) throws SQLException {
        // Rate limit per IP
        if (rateLimitPerIp(ip)) {
            return errorResponse(429, "ip_rate_limit_exceeded", Map.of("reset_seconds", 1));
        }

        // Rate limit per user
        if (rateLimitPerUser(user.getId())) {
            return errorResponse(429, "rate_limit_exceeded", Map.of("reset_seconds", 60));
        }

        // Feature gate
        if (!featureGate(user, feature)) {
            // Spec shape (Phase B.2, 2026-11-10): 403 {error, tier, minimum_tier, upgrade_url}, every field present; a
            // feature no tier has gets minimum_tier null and the plain upgrade page.
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("tier", user.getTier().name().toLowerCase(Locale.ROOT));
            Tier minimum = minimumTier(feature);
            details.put("minimum_tier", minimum == null ? null : minimum.name().toLowerCase(Locale.ROOT));
            details.put("upgrade_url", minimum == null ? "/billing/upgrade"
                    : "/billing/upgrade?tier=" + minimum.name().toLowerCase(Locale.ROOT));
            return errorResponse(403, "feature_not_available_in_tier", details);
        }

        // API quota
        if (!apiQuotaCheck(user)) {
            return errorResponse(429, "quota_exceeded", Map.of(
                    "current", getCurrentApiUsage(user),
                    "limit", getApiLimit(user),
                    "reset_date", getResetDate()
            ));
        }

        // Storage quota if file upload
        if (incomingSize >= 0) {
            if (!storageQuotaCheck(user, incomingSize)) {
                return errorResponse(413, "storage_quota_exceeded", Map.of(
                        "usage", getCurrentStorageUsage(user),
                        "limit", getStorageLimit(user)
                ));
            }
            storeFile(user, incomingSize);
        }

        // Record API call
        recordApiCall(user, ip, endpoint, 200);

        // Increment usage
        incrementApiUsage(user);

        return successResponse(200, Map.of("message", "call succeeded"));
    }

    private boolean rateLimitPerUser(String userId) throws SQLException {
        String sql = "SELECT COUNT(*) FROM api_calls WHERE user_id = ? AND timestamp > ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, userId);
            ps.setTimestamp(2, Timestamp.from(clock.instant().minus(Duration.ofMinutes(1))));
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1) >= 100;
            }
        }
    }

    private boolean rateLimitPerIp(String ip) throws SQLException {
        String sql = "SELECT COUNT(*) FROM api_calls WHERE ip = ? AND timestamp > ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, ip);
            ps.setTimestamp(2, Timestamp.from(clock.instant().minus(Duration.ofSeconds(1))));
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1) >= 10;
            }
        }
    }

    /** Feature -> tiers allowed to use it (spec's feature_gate_by_tier). Unknown features are allowed to nobody. */
    private static final Map<String, Set<Tier>> FEATURES = Map.of(
            "feature_a", EnumSet.of(Tier.TEAM, Tier.ENTERPRISE),
            "feature_b", EnumSet.of(Tier.ENTERPRISE),
            "feature_c", EnumSet.of(Tier.SOLO, Tier.TEAM, Tier.ENTERPRISE)
    );

    /**
     * True when the user's tier may use the feature. Pure. Repaired 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP: the table moved to the FEATURES constant so minimumTier can share it.
     */
    private boolean featureGate(User user, String feature) {
        return FEATURES.getOrDefault(feature, Set.of()).contains(user.getTier());
    }

    /**
     * Lowest tier that may use the feature, or null for an unknown feature. Pure.
     * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the 403 said "team" even for enterprise-only
     * features.
     */
    private static Tier minimumTier(String feature) {
        Set<Tier> allowed = FEATURES.get(feature);
        if (allowed == null || allowed.isEmpty()) return null;
        return Collections.min(allowed);
    }

    private boolean apiQuotaCheck(User user) throws SQLException {
        int current = getCurrentApiUsage(user);
        int limit = getApiLimit(user);
        return limit == -1 || (current + 1) <= limit;   // -1 = unlimited (QUOTA-13)
    }

    /**
     * Calls the user has made this month (0 if none). Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: reads usage_month (the column
     * was the reserved word "month"). Touches: reads the database.
     */
    private int getCurrentApiUsage(User user) throws SQLException {
        String sql = "SELECT SUM(call_count) FROM usage_metrics WHERE user_id = ? AND usage_month = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, user.getId());
            ps.setString(2, currentMonth());
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }

    private int getApiLimit(User user) {
        return switch (user.getTier()) {
            case SOLO -> 1000;
            case TEAM -> 10000;
            case ENTERPRISE -> -1;
        };
    }

    private boolean storageQuotaCheck(User user, long incomingSize) throws SQLException {
        long current = getCurrentStorageUsage(user);
        long limit = getStorageLimit(user);
        return limit == -1 || (current + incomingSize) <= limit;   // -1 = unlimited (QUOTA-13)
    }

    private long getCurrentStorageUsage(User user) throws SQLException {
        String sql = "SELECT SUM(file_size) FROM user_files WHERE user_id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, user.getId());
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getLong(1);
            }
        }
    }

    private long getStorageLimit(User user) {
        return switch (user.getTier()) {
            case SOLO -> 1_000_000_000L;
            case TEAM -> 100_000_000_000L;
            case ENTERPRISE -> -1;
        };
    }

    /**
     * Adds one call to the user's usage for the current month, creating the month's row on first use.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: it MERGEd a row with call_count = 1 every
     * time, so usage never passed 1 and the monthly quota never triggered. Touches: the database.
     */
    private void incrementApiUsage(User user) throws SQLException {
        String month = currentMonth();
        Timestamp now = Timestamp.from(clock.instant());
        String update = "UPDATE usage_metrics SET call_count = call_count + 1, updated_at = ? " +
                "WHERE user_id = ? AND usage_month = ?";
        try (PreparedStatement ps = conn.prepareStatement(update)) {
            ps.setTimestamp(1, now);
            ps.setString(2, user.getId());
            ps.setString(3, month);
            if (ps.executeUpdate() > 0) return;
        }
        String insert = "INSERT INTO usage_metrics (user_id, usage_month, call_count, storage_bytes, updated_at) " +
                "VALUES (?, ?, 1, 0, ?)";
        try (PreparedStatement ps = conn.prepareStatement(insert)) {
            ps.setString(1, user.getId());
            ps.setString(2, month);
            ps.setTimestamp(3, now);
            ps.executeUpdate();
        }
    }

    private void storeFile(User user, long size) throws SQLException {
        String sql = "INSERT INTO user_files (user_id, file_size, uploaded_at) VALUES (?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, user.getId());
            ps.setLong(2, size);
            ps.setTimestamp(3, Timestamp.from(clock.instant()));
            ps.executeUpdate();
        }
    }

    private void recordApiCall(User user, String ip, String endpoint, int statusCode) throws SQLException {
        String sql = "INSERT INTO api_calls (user_id, ip, endpoint, timestamp, status_code, response_time_ms) VALUES (?, ?, ?, ?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, user.getId());
            ps.setString(2, ip);
            ps.setString(3, endpoint);
            ps.setTimestamp(4, Timestamp.from(clock.instant()));
            ps.setInt(5, statusCode);
            ps.setInt(6, 0);
            ps.executeUpdate();
        }
    }

    private String currentMonth() {
        return YearMonth.from(clock.instant().atZone(ZoneOffset.UTC)).toString();
    }

    private String getResetDate() {
        LocalDate nextMonth = YearMonth.from(clock.instant().atZone(ZoneOffset.UTC)).plusMonths(1).atDay(1);
        return nextMonth.atStartOfDay(ZoneOffset.UTC).toString();
    }

    private Response errorResponse(int status, String error, Map<String, Object> details) {
        ObjectNode node = MAPPER.createObjectNode();
        node.put("error", error);
        details.forEach((k, v) -> node.putPOJO(k, v));
        return new Response(status, node.toString());
    }

    private Response successResponse(int status, Map<String, Object> details) {
        ObjectNode node = MAPPER.createObjectNode();
        details.forEach((k, v) -> node.putPOJO(k, v));
        return new Response(status, node.toString());
    }

    /**
     * Closes this manager's database connection, which drops its in-memory database.
     * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    @Override
    public void close() throws SQLException {
        conn.close();
    }

    public static class User {
        private final String id;
        private Tier tier;

        public User(String id, Tier tier) {
            this.id = id;
            this.tier = tier;
        }

        public String getId() { return id; }
        public Tier getTier() { return tier; }
        public void setTier(Tier tier) { this.tier = tier; }
    }

    public enum Tier { SOLO, TEAM, ENTERPRISE }

    public static class Response {
        private final int statusCode;
        private final String body;

        public Response(int statusCode, String body) {
            this.statusCode = statusCode;
            this.body = body;
        }

        public int getStatusCode() { return statusCode; }
        public String getBody() { return body; }
    }
}
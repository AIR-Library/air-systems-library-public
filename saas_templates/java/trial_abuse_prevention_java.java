import java.sql.*;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import javax.sql.DataSource;

/**
 * Trial abuse prevention: the six gates of the spec (GEMINI_DISPATCH_MASTER_SPEC, template #3), each answering
 * PASS, CHALLENGE or FAIL from the trial_abuse_ledger, signups, device_fingerprints, users, stripe_events and
 * refunds tables. Time comes from an injectable Clock so decisions are reproducible.
 *
 * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. The file did not compile (DataSource was never
 * imported) and the tests could not see GateDecision (it was nested; it is now a top-level type in this file).
 * Behaviour fixes against the spec: the device gate hashed HashMap.toString() (not canonical) and called 5 users
 * CHALLENGE although the spec says FAIL at 5 or more; the trial-timing gate returned CHALLENGE for every old trial
 * before ever reaching FAIL and judged "never added payment" from subscription status instead of
 * payment_added_date; the IP gate used MySQL interval syntax H2 rejects; ledger JSON escaped quotes as
 * backslashes; email history matched case-sensitively, so Test@x.com escaped a prior test@x.com.
 * Touches: the database behind the DataSource. No network, no money.
 */
public class TrialAbusePrevention {
    private final DataSource dataSource;
    private final Clock clock;
    /** Trial length in days for gate 5 (spec: configurable, default 14). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private final int trialDays;

    /**
     * Creates the gates on the system UTC clock. Input: a DataSource holding the tables. Touches: nothing yet.
     * Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
     */
    public TrialAbusePrevention(DataSource dataSource) {
        this(dataSource, Clock.systemUTC());
    }

    /**
     * Creates the gates on the given clock (tests pass a fixed one). Added 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing yet.
     */
    public TrialAbusePrevention(DataSource dataSource, Clock clock) {
        this(dataSource, clock, 14);
    }

    /**
     * Gates on the given clock with a configured trial length. In: DataSource, clock, trial days (>= 1). Added
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec: "trial_days is configuration, default 14"). Touches: nothing.
     */
    public TrialAbusePrevention(DataSource dataSource, Clock clock, int trialDays) {
        if (trialDays < 1) throw new IllegalArgumentException("trialDays must be >= 1");
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.trialDays = trialDays;
    }

    /**
     * Gate 1, EMAIL_TRIAL_HISTORY: prior completed or chargebacked trials for this email (case-insensitive).
     * Output: PASS for none, CHALLENGE for 1, FAIL for 2 or more.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: compares emails case-insensitively.
     * Touches: reads the database.
     */
    public GateDecision checkEmailTrialHistory(String email) throws SQLException {
        String sql = "SELECT COUNT(*) FROM trial_abuse_ledger WHERE LOWER(email) = LOWER(?) " +
                "AND subscription_status IN ('completed', 'chargebacked')";
        int count = countOne(sql, ps -> ps.setString(1, email == null ? "" : email.trim()));
        if (count == 0) return GateDecision.PASS;
        if (count == 1) return GateDecision.CHALLENGE;
        return GateDecision.FAIL;
    }

    /**
     * Gate 3, IP_SIGNUP_RATE_LIMIT: signups from this IP in the last 24 hours (by this object's clock).
     * Output: PASS under 5, CHALLENGE for 5 to 9, FAIL for 10 or more.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the cutoff is a bound parameter instead of
     * "NOW() - INTERVAL 24 HOURS", which H2 rejects. Touches: reads the database.
     */
    public GateDecision checkIpSignupRateLimit(String ip) throws SQLException {
        String sql = "SELECT COUNT(*) FROM signups WHERE ip = ? AND created_at > ?";
        Timestamp cutoff = Timestamp.from(clock.instant().minus(24, ChronoUnit.HOURS));
        int count = countOne(sql, ps -> {
            ps.setString(1, ip);
            ps.setTimestamp(2, cutoff);
        });
        if (count < 5) return GateDecision.PASS;
        if (count < 10) return GateDecision.CHALLENGE;
        return GateDecision.FAIL;
    }

    /**
     * Gate 2, PAYMENT_METHOD_HISTORY: completed or chargebacked trials that used this Stripe payment method.
     * Output: PASS under 2, CHALLENGE for exactly 2, FAIL for 3 or more.
     * Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the database.
     */
    public GateDecision checkPaymentMethodHistory(String stripePaymentMethodId) throws SQLException {
        String sql = "SELECT COUNT(*) FROM trial_abuse_ledger WHERE stripe_payment_method_id = ? " +
                "AND subscription_status IN ('completed', 'chargebacked')";
        int count = countOne(sql, ps -> ps.setString(1, stripePaymentMethodId));
        if (count < 2) return GateDecision.PASS;
        if (count == 2) return GateDecision.CHALLENGE;
        return GateDecision.FAIL;
    }

    /** Gate 4 without a user (an anonymous check): counts every user on the device. */
    public GateDecision checkDeviceFingerprint(String userAgent, String screenResolution, String timezone, String browserLanguage) throws SQLException, NoSuchAlgorithmException {
        return checkDeviceFingerprint(null, userAgent, screenResolution, timezone, browserLanguage);
    }

    /**
     * Gate 4, DEVICE_FINGERPRINT (amended 2026-11-10). count = distinct OTHER users on this device (null-safe: with no
     * user id every user counts). Decision, in this order: FAIL if count >= 5; PASS if count < 2; PASS if this user
     * already has a row for this device; CHALLENGE otherwise. Reads only; the device row is written by
     * checkAndRecordDevice after the decision. In: user id (may be null), the four browser attributes. Out: decision.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (TRIAL-09/14): the count included the user itself and
     * there was no known-device rule. Touches: reads the database.
     */
    public GateDecision checkDeviceFingerprint(Long userId, String userAgent, String screenResolution, String timezone, String browserLanguage) throws SQLException, NoSuchAlgorithmException {
        String hash = deviceHash(userAgent, screenResolution, timezone, browserLanguage);
        int count = countOne("SELECT COUNT(DISTINCT user_id) FROM device_fingerprints WHERE device_hash = ? AND (CAST(? AS BIGINT) IS NULL OR user_id <> ?)",
                ps -> {
                    ps.setString(1, hash);
                    if (userId == null) {
                        ps.setNull(2, Types.BIGINT);
                        ps.setNull(3, Types.BIGINT);
                    } else {
                        ps.setLong(2, userId);
                        ps.setLong(3, userId);
                    }
                });
        if (count >= 5) return GateDecision.FAIL;
        if (count < 2) return GateDecision.PASS;
        if (userId != null && countOne("SELECT COUNT(*) FROM device_fingerprints WHERE device_hash = ? AND user_id = ?",
                ps -> {
                    ps.setString(1, hash);
                    ps.setLong(2, userId);
                }) > 0) {
            return GateDecision.PASS;
        }
        return GateDecision.CHALLENGE;
    }

    /**
     * The signup / login step for gate 4: runs the gate FIRST, then writes the device row only for PASS or CHALLENGE
     * (a FAIL records nothing). In: user id, browser attributes. Out: the decision. Why: spec amendment 2026-11-10 —
     * recording before checking made every later check of a device farm see its own row; TRIAL-14.
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads and writes the database.
     */
    public GateDecision checkAndRecordDevice(Long userId, String userAgent, String screenResolution, String timezone, String browserLanguage) throws SQLException, NoSuchAlgorithmException {
        GateDecision decision = checkDeviceFingerprint(userId, userAgent, screenResolution, timezone, browserLanguage);
        if (decision != GateDecision.FAIL && userId != null) {
            insertDeviceFingerprint(userId, deviceHash(userAgent, screenResolution, timezone, browserLanguage),
                    userAgent, screenResolution, timezone);
        }
        return decision;
    }

    /**
     * The device hash the spec defines: SHA-256 (lowercase hex) of the device's attributes as JSON with sorted
     * keys, written exactly as Python's json.dumps(device, sort_keys=True) writes it, so every language's
     * template computes the same hash for the same device. Null attributes are stored as "".
     * Input: the four browser attributes. Output: a 64-character hex string.
     * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the gate hashed HashMap.toString(), whose
     * format is not a contract, and callers had no way to compute the hash they must store. Touches: nothing.
     */
    public static String deviceHash(String userAgent, String screenResolution, String timezone, String browserLanguage) throws NoSuchAlgorithmException {
        Map<String, Object> device = new TreeMap<>();
        device.put("browser_language", browserLanguage == null ? "" : browserLanguage);
        device.put("screen_resolution", screenResolution == null ? "" : screenResolution);
        device.put("timezone", timezone == null ? "" : timezone);
        device.put("user_agent", userAgent == null ? "" : userAgent);
        return sha256Hex(toJson(device));
    }

    /** Gate 5 with the configured trial length (default 14 days; set through the three-argument constructor). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    public GateDecision checkTrialPaymentTiming(Long userId) throws SQLException {
        return checkTrialPaymentTiming(userId, trialDays);
    }

    /**
     * Gate 5, TRIAL_PAYMENT_TIMING (amended 2026-11-10), judged when a payment method is being added, so the payment
     * date is now. trial_end = users.created_at + trialDays; days_after_trial = floor((now - trial_end) / 1 day),
     * rounded toward negative infinity (Math.floorDiv); earlier_payment = the ledger already has a payment_added_date
     * for the user. PASS if days_after_trial < 5; FAIL if days_after_trial >= 90 and no earlier payment; CHALLENGE
     * otherwise. In: user id, trial length in days. Out: the decision; SQLException if the user does not exist.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (TRIAL-10/11/15): the old rule counted from the trial
     * START and used different thresholds. Touches: reads the database.
     */
    public GateDecision checkTrialPaymentTiming(Long userId, int trialDays) throws SQLException {
        Instant trialStart;
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement("SELECT created_at FROM users WHERE id = ?")) {
            ps.setLong(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next() || rs.getTimestamp("created_at") == null) {
                    throw new SQLException("User not found: " + userId);
                }
                trialStart = rs.getTimestamp("created_at").toInstant();
            }
        }
        Instant trialEnd = trialStart.plus(trialDays, ChronoUnit.DAYS);
        long daysAfterTrial = Math.floorDiv(Duration.between(trialEnd, clock.instant()).toMillis(), 86_400_000L);
        boolean earlierPayment = latestPaymentAddedDate(userId) != null;
        if (daysAfterTrial < 5) return GateDecision.PASS;
        if (daysAfterTrial >= 90 && !earlierPayment) return GateDecision.FAIL;
        return GateDecision.CHALLENGE;
    }

    /**
     * Latest payment_added_date recorded for the user in trial_abuse_ledger, or null if none.
     * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (replaces hasPriorSuccessfulSubscription, which
     * judged payment by subscription status). Touches: reads the database.
     */
    private Instant latestPaymentAddedDate(Long userId) throws SQLException {
        String sql = "SELECT MAX(payment_added_date) FROM trial_abuse_ledger WHERE user_id = ?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    Timestamp ts = rs.getTimestamp(1);
                    return ts == null ? null : ts.toInstant();
                }
            }
        }
        return null;
    }

    /**
     * Gate 6, CHARGEBACK_HISTORY: Stripe chargeback events for the user's Stripe customer plus refunds marked
     * chargebacked. Output: PASS for 0, CHALLENGE for 1, FAIL for 2 or more.
     * Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the database.
     */
    public GateDecision checkChargebackHistory(Long userId) throws SQLException {
        String stripeCustomerId = getStripeCustomerId(userId);
        int stripeChargebacks = stripeCustomerId == null ? 0 : countOne(
                "SELECT COUNT(*) FROM stripe_events WHERE customer = ? AND type LIKE '%chargeback%'",
                ps -> ps.setString(1, stripeCustomerId));
        int refundChargebacks = countOne(
                "SELECT COUNT(*) FROM refunds WHERE user_id = ? AND status = 'chargebacked'",
                ps -> ps.setLong(1, userId));

        int totalChargebacks = stripeChargebacks + refundChargebacks;
        if (totalChargebacks == 0) return GateDecision.PASS;
        if (totalChargebacks == 1) return GateDecision.CHALLENGE;
        return GateDecision.FAIL;
    }

    /**
     * The user's Stripe customer id (null if the user has none); SQLException if the user does not exist.
     * Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the database.
     */
    private String getStripeCustomerId(Long userId) throws SQLException {
        String sql = "SELECT stripe_customer_id FROM users WHERE id = ?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("stripe_customer_id");
                }
            }
        }
        throw new SQLException("User not found: " + userId);
    }

    /**
     * Records one gate decision (the why-chain) with its inputs and outputs as JSON.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the timestamp comes from the clock and the
     * JSON is correctly escaped. Touches: writes the database.
     */
    public void logGateDecision(Long userId, String gateName, GateDecision decision, Map<String, Object> ruleInputs, Map<String, Object> ruleOutputs) throws SQLException {
        String sql = "INSERT INTO gate_decisions (user_id, gate_name, decision, rule_inputs, rule_outputs, created_at) VALUES (?, ?, ?, ?, ?, ?)";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, userId);
            ps.setString(2, gateName);
            ps.setString(3, decision.name());
            ps.setString(4, toJson(ruleInputs));
            ps.setString(5, toJson(ruleOutputs));
            ps.setTimestamp(6, Timestamp.from(clock.instant()));
            ps.executeUpdate();
        }
    }

    /**
     * Adds the signup's ledger row (signup and trial start = now) and returns its id.
     * Input: user id, email, IP, device hash (from deviceHash). Output: the new row's id, or null if the driver
     * returned none.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: returns the id updateAbuseLedgerPayment needs
     * (it asked for generated keys and dropped them); times come from the clock. Touches: writes the database.
     */
    public Long createAbuseLedgerEntry(Long userId, String email, String ip, String deviceHash) throws SQLException {
        String sql = "INSERT INTO trial_abuse_ledger (user_id, email, ip, device_fingerprint, signup_date, trial_started_at, gate_flags, created_at) VALUES (?, ?, ?, ?, ?, ?, '{}', ?)";
        Timestamp now = Timestamp.from(clock.instant());
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setLong(1, userId);
            ps.setString(2, email);
            ps.setString(3, ip);
            ps.setString(4, deviceHash);
            ps.setTimestamp(5, now);
            ps.setTimestamp(6, now);
            ps.setTimestamp(7, now);
            ps.executeUpdate();
            try (ResultSet keys = ps.getGeneratedKeys()) {
                return keys.next() ? keys.getLong(1) : null;
            }
        }
    }

    /**
     * Records the payment method added for a ledger row. Repaired 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP: the date comes from the clock. Touches: writes the database.
     */
    public void updateAbuseLedgerPayment(Long abuseLedgerId, String stripePaymentMethodId) throws SQLException {
        String sql = "UPDATE trial_abuse_ledger SET payment_added_date = ?, stripe_payment_method_id = ? WHERE id = ?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setTimestamp(1, Timestamp.from(clock.instant()));
            ps.setString(2, stripePaymentMethodId);
            ps.setLong(3, abuseLedgerId);
            ps.executeUpdate();
        }
    }

    /**
     * Stores that a user used a device. deviceHash should come from deviceHash(...).
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the date comes from the clock.
     * Touches: writes the database.
     */
    public void insertDeviceFingerprint(Long userId, String deviceHash, String userAgent, String screenResolution, String timezone) throws SQLException {
        String sql = "INSERT INTO device_fingerprints (user_id, device_hash, user_agent, screen_resolution, timezone, created_at) VALUES (?, ?, ?, ?, ?, ?)";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, userId);
            ps.setString(2, deviceHash);
            ps.setString(3, userAgent);
            ps.setString(4, screenResolution);
            ps.setString(5, timezone);
            ps.setTimestamp(6, Timestamp.from(clock.instant()));
            ps.executeUpdate();
        }
    }

    /** Binds parameters on a prepared statement. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. */
    @FunctionalInterface
    private interface Binder {
        void bind(PreparedStatement ps) throws SQLException;
    }

    /**
     * Runs a parameterized COUNT query and returns its single value (0 if no row).
     * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP to replace six copies of the same JDBC code.
     * Touches: reads the database.
     */
    private int countOne(String sql, Binder binder) throws SQLException {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            binder.bind(ps);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        }
    }

    /**
     * Serializes a flat map to JSON in Python json.dumps form ({"k": v, ...}): strings escaped, numbers and
     * booleans bare, other values as strings. Null or empty map gives "{}".
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: keys are escaped too; static so deviceHash
     * can use it. Touches: nothing (pure).
     */
    private static String toJson(Map<String, Object> map) {
        if (map == null || map.isEmpty()) return "{}";
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!first) sb.append(", ");
            first = false;
            sb.append('"').append(escapeJson(entry.getKey())).append('"');
            sb.append(": ");
            Object value = entry.getValue();
            if (value == null) {
                sb.append("null");
            } else if (value instanceof Number || value instanceof Boolean) {
                sb.append(value);
            } else {
                sb.append('"').append(escapeJson(value.toString())).append('"');
            }
        }
        sb.append("}");
        return sb.toString();
    }

    /**
     * Escapes a string for a JSON string literal. Non-ASCII is written as \\uXXXX, as Python's json.dumps does by
     * default, so device hashes agree across languages.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: a quote was written as two backslashes,
     * corrupting the stored JSON. Touches: nothing (pure).
     */
    private static String escapeJson(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20 || c > 0x7e) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    /**
     * SHA-256 of the UTF-8 bytes, as lowercase hex (64 characters, fits device_fingerprint VARCHAR(64)).
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: hex instead of Base64, matching the Python
     * template. Touches: nothing (pure).
     */
    private static String sha256Hex(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hash);
    }

    /**
     * DDL for the three tables this template owns (executable on H2 and MySQL). The spec's schema has no NOT NULL
     * on the ledger's ip, signup_date or trial_started_at; the dates default to now so imported history rows
     * (e.g. a past completed trial with no recorded IP) can be stored.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: ip was NOT NULL and the dates had no
     * default, so a ledger row without them could not be written.
     */
    public static final String[] DDL_STATEMENTS = {
        "CREATE TABLE IF NOT EXISTS trial_abuse_ledger (" +
                "id BIGINT AUTO_INCREMENT PRIMARY KEY," +
                "user_id BIGINT NOT NULL," +
                "email VARCHAR(255) NOT NULL," +
                "stripe_payment_method_id VARCHAR(255)," +
                "ip VARCHAR(45)," +
                "device_fingerprint VARCHAR(64)," +
                "signup_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL," +
                "trial_started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL," +
                "payment_added_date TIMESTAMP," +
                "subscription_status VARCHAR(20)," +
                "chargeback_count INT DEFAULT 0," +
                "refund_count INT DEFAULT 0," +
                "gate_flags JSON," +
                "alert_reason TEXT," +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
        ");",
        "CREATE TABLE IF NOT EXISTS device_fingerprints (" +
                "id BIGINT AUTO_INCREMENT PRIMARY KEY," +
                "user_id BIGINT NOT NULL," +
                "device_hash VARCHAR(64) NOT NULL," +
                "user_agent TEXT," +
                "screen_resolution VARCHAR(20)," +
                "timezone VARCHAR(50)," +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
        ");",
        "CREATE TABLE IF NOT EXISTS gate_decisions (" +
                "id BIGINT AUTO_INCREMENT PRIMARY KEY," +
                "user_id BIGINT NOT NULL," +
                "gate_name VARCHAR(50) NOT NULL," +
                "decision VARCHAR(20) NOT NULL," +
                "rule_inputs JSON," +
                "rule_outputs JSON," +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
        ");"
    };
}

/**
 * Outcome of one trial-abuse gate: PASS (allow), CHALLENGE (allow but flag or verify), FAIL (reject).
 * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: moved out of TrialAbusePrevention to a
 * top-level type in this file because the tests (and the spec's examples) name it GateDecision, and a class in the
 * unnamed package cannot import a nested type. It is package-private because a Java file may hold only one public
 * type; when you copy this template into a package, give it its own GateDecision.java and make it public.
 */
enum GateDecision { PASS, CHALLENGE, FAIL }

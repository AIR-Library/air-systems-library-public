import static org.junit.Assert.*;
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: explicit JUnit imports (the library's runner
// recognises a JUnit suite by "org.junit.Test"; with only "org.junit.*" it looked for a main method and failed)
// and the missing ChronoUnit import (testTrialPaymentTimingFail could not compile).
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import java.sql.*;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
import javax.sql.DataSource;
import org.h2.jdbcx.JdbcDataSource;

public class TrialAbusePreventionTest {
    private static DataSource dataSource;
    private TrialAbusePrevention tap;

    @BeforeClass
    public static void setUpDb() throws Exception {
        dataSource = new JdbcDataSource();
        ((JdbcDataSource) dataSource).setURL("jdbc:h2:mem:test;DB_CLOSE_DELAY=-1");
        Connection conn = dataSource.getConnection();
        try {
            Statement stmt = conn.createStatement();
            for (String ddl : TrialAbusePrevention.DDL_STATEMENTS) {
                stmt.execute(ddl);
            }
            // Create additional tables required by the tests
            stmt.execute("CREATE TABLE IF NOT EXISTS signups (id BIGINT AUTO_INCREMENT PRIMARY KEY, ip VARCHAR(45), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
            stmt.execute("CREATE TABLE IF NOT EXISTS users (id BIGINT AUTO_INCREMENT PRIMARY KEY, stripe_customer_id VARCHAR(255), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
            stmt.execute("CREATE TABLE IF NOT EXISTS stripe_events (id BIGINT AUTO_INCREMENT PRIMARY KEY, customer VARCHAR(255), type VARCHAR(255))");
            stmt.execute("CREATE TABLE IF NOT EXISTS refunds (id BIGINT AUTO_INCREMENT PRIMARY KEY, user_id BIGINT, status VARCHAR(20))");
        } finally {
            conn.close();
        }
    }

    @Before
    public void setUp() throws Exception {
        tap = new TrialAbusePrevention(dataSource);
        clearTables();
    }

    private void clearTables() throws SQLException {
        Connection conn = dataSource.getConnection();
        try {
            Statement stmt = conn.createStatement();
            stmt.execute("DELETE FROM gate_decisions");
            stmt.execute("DELETE FROM device_fingerprints");
            stmt.execute("DELETE FROM trial_abuse_ledger");
            stmt.execute("DELETE FROM signups");
            stmt.execute("DELETE FROM users");
            stmt.execute("DELETE FROM stripe_events");
            stmt.execute("DELETE FROM refunds");
        } finally {
            conn.close();
        }
    }

    // TRIAL-01
    @Test
    public void testEmailTrialHistoryPass() throws Exception {
        GateDecision decision = tap.checkEmailTrialHistory("new@example.com");
        assertEquals(GateDecision.PASS, decision);
    }

    // TRIAL-02
    @Test
    public void testEmailTrialHistoryChallenge() throws Exception {
        // Create a user with one completed trial
        Long userId = createUser("test@example.com", "completed");
        GateDecision decision = tap.checkEmailTrialHistory("test@example.com");
        assertEquals(GateDecision.CHALLENGE, decision);
    }

    // TRIAL-03
    @Test
    public void testEmailTrialHistoryFail() throws Exception {
        // Create two completed trials
        createUser("test@example.com", "completed");
        createUser("test@example.com", "completed");
        GateDecision decision = tap.checkEmailTrialHistory("test@example.com");
        assertEquals(GateDecision.FAIL, decision);
    }

    // TRIAL-04
    @Test
    public void testPaymentMethodHistoryPass() throws Exception {
        GateDecision decision = tap.checkPaymentMethodHistory("pm_new");
        assertEquals(GateDecision.PASS, decision);
    }

    // TRIAL-05
    @Test
    public void testPaymentMethodHistoryFail() throws Exception {
        // Create three completed trials with same payment method
        for (int i = 0; i < 3; i++) {
            Long userId = createUser("user" + i + "@example.com", "completed");
            updateAbuseLedgerPayment(userId, "pm_reused");
        }
        GateDecision decision = tap.checkPaymentMethodHistory("pm_reused");
        assertEquals(GateDecision.FAIL, decision);
    }

    // TRIAL-06
    @Test
    public void testIpSignupRateLimitPass() throws Exception {
        GateDecision decision = tap.checkIpSignupRateLimit("1.2.3.4");
        assertEquals(GateDecision.PASS, decision);
    }

    // TRIAL-07
    @Test
    public void testIpSignupRateLimitFail() throws Exception {
        // Create 10 signups from same IP in last 24 hours
        for (int i = 0; i < 10; i++) {
            insertSignup("1.2.3.4");
        }
        GateDecision decision = tap.checkIpSignupRateLimit("1.2.3.4");
        assertEquals(GateDecision.FAIL, decision);
    }

    // TRIAL-08
    @Test
    public void testDeviceFingerprintPass() throws Exception {
        GateDecision decision = tap.checkDeviceFingerprint("UA", "1920x1080", "UTC", "en");
        assertEquals(GateDecision.PASS, decision);
    }

    /** Five users on one device: FAIL. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: stores TrialAbusePrevention.deviceHash of that device instead of the literal "hash123". Touches: in-memory H2. */
    // TRIAL-09
    @Test
    public void testDeviceFingerprintFail() throws Exception {
        // Insert 5 different users with same device fingerprint. Changed 2026-11-10, session
        // session_012zDydZCZ4AChqhEZ4oVtaP: the rows held the literal "hash123", which no SHA-256 of the device
        // (the spec's device_hash) can equal, so the gate could never see these users; they now store the hash
        // of the same device the gate is asked about.
        String deviceHash = TrialAbusePrevention.deviceHash("UA", "1920x1080", "UTC", "en");
        for (int i = 0; i < 5; i++) {
            Long userId = createUser("user" + i + "@example.com", "completed");
            tap.insertDeviceFingerprint(userId, deviceHash, "UA", "1920x1080", "UTC");
        }
        GateDecision decision = tap.checkDeviceFingerprint("UA", "1920x1080", "UTC", "en");
        assertEquals(GateDecision.FAIL, decision);
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (TRIAL-09 amendment): a sixth user's check counts the 5 OTHER
        // users and fails.
        Long sixth = createUser("user6@example.com", null);
        assertEquals(GateDecision.FAIL, tap.checkDeviceFingerprint(sixth, "UA", "1920x1080", "UTC", "en"));
    }

    /** Fixed "now" for the timing tests. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static final Instant NOW = Instant.parse("2026-06-01T12:00:00Z");

    /**
     * A user whose 14-day trial ended daysAfterTrial days before NOW (negative: still in the trial), on gates with a
     * fixed clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test database.
     */
    private Long userWhoseTrialEnded(long daysAfterTrial, String email) throws SQLException {
        Long userId = createUser(email, null);
        updateUserCreatedAt(userId, NOW.minus(14 + daysAfterTrial, ChronoUnit.DAYS));
        return userId;
    }

    private TrialAbusePrevention fixedGates() {
        return new TrialAbusePrevention(dataSource, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    /**
     * TRIAL-10: a first payment during the trial and one 4 days after it ended both PASS. Changed 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP: spec amendment (days counted from the trial END, floor); the test used the
     * wall clock and only the during-trial case.
     */
    // TRIAL-10
    @Test
    public void testTrialPaymentTimingPass() throws Exception {
        TrialAbusePrevention gates = fixedGates();
        assertEquals(GateDecision.PASS, gates.checkTrialPaymentTiming(userWhoseTrialEnded(-10, "during@example.com")));
        assertEquals(GateDecision.PASS, gates.checkTrialPaymentTiming(userWhoseTrialEnded(4, "four@example.com"), 14));
        // 4 days and 23 hours is still day 4 (floor).
        Long almostFive = createUser("almost5@example.com", null);
        updateUserCreatedAt(almostFive, NOW.minus(14 + 5, ChronoUnit.DAYS).plus(1, ChronoUnit.HOURS));
        assertEquals(GateDecision.PASS, gates.checkTrialPaymentTiming(almostFive));
    }

    /**
     * TRIAL-11: a first payment 90 days after the trial ended, with no earlier payment, FAILs. Changed 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP: spec amendment; fixed clock.
     */
    // TRIAL-11
    @Test
    public void testTrialPaymentTimingFail() throws Exception {
        assertEquals(GateDecision.FAIL, fixedGates().checkTrialPaymentTiming(userWhoseTrialEnded(90, "ninety@example.com")));
    }

    /**
     * TRIAL-15: 5 and 89 days after the trial CHALLENGE; 90 days WITH an earlier payment CHALLENGE; trial_days is
     * configuration (a 30-day trial moves every boundary). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     */
    // TRIAL-15
    @Test
    public void testTrialPaymentTimingBoundaries() throws Exception {
        TrialAbusePrevention gates = fixedGates();
        assertEquals(GateDecision.CHALLENGE, gates.checkTrialPaymentTiming(userWhoseTrialEnded(5, "five@example.com")));
        assertEquals(GateDecision.CHALLENGE, gates.checkTrialPaymentTiming(userWhoseTrialEnded(89, "e89@example.com")));
        Long paidBefore = userWhoseTrialEnded(90, "paidbefore@example.com");
        Connection conn = dataSource.getConnection();
        try (PreparedStatement ps = conn.prepareStatement("UPDATE trial_abuse_ledger SET payment_added_date = ? WHERE user_id = ?")) {
            ps.setTimestamp(1, Timestamp.from(NOW.minus(100, ChronoUnit.DAYS)));
            ps.setLong(2, paidBefore);
            ps.executeUpdate();
        } finally {
            conn.close();
        }
        assertEquals(GateDecision.CHALLENGE, gates.checkTrialPaymentTiming(paidBefore));
        TrialAbusePrevention thirtyDayTrial = new TrialAbusePrevention(dataSource, Clock.fixed(NOW, ZoneOffset.UTC), 30);
        // Created 34 days ago: 4 days after a 30-day trial (PASS), 20 days after a 14-day one (CHALLENGE).
        Long u = createUser("thirty@example.com", null);
        updateUserCreatedAt(u, NOW.minus(34, ChronoUnit.DAYS));
        assertEquals(GateDecision.PASS, thirtyDayTrial.checkTrialPaymentTiming(u));
        assertEquals(GateDecision.CHALLENGE, gates.checkTrialPaymentTiming(u));
    }

    /**
     * TRIAL-14: 4 OTHER users on a device -> CHALLENGE for a new user; exactly 5 -> FAIL, even for a user who already
     * has the device; a FAIL records no device row; a PASS/CHALLENGE through checkAndRecordDevice records one; a user
     * who already has the device (with 2-4 others) PASSes. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     */
    // TRIAL-14
    @Test
    public void testDeviceFingerprintBoundaries() throws Exception {
        String ua = "Farm", res = "800x600", tz = "UTC", lang = "en";
        String hash = TrialAbusePrevention.deviceHash(ua, res, tz, lang);
        Long[] users = new Long[7];
        for (int i = 0; i < users.length; i++) users[i] = createUser("farm" + i + "@example.com", null);
        for (int i = 0; i < 4; i++) {
            GateDecision d = tap.checkAndRecordDevice(users[i], ua, res, tz, lang);
            assertNotEquals(GateDecision.FAIL, d);
        }
        // users[0] already has the device and 3 others share it: PASS (known device).
        assertEquals(GateDecision.PASS, tap.checkDeviceFingerprint(users[0], ua, res, tz, lang));
        // A new user sees 4 others: CHALLENGE, and is recorded.
        assertEquals(GateDecision.CHALLENGE, tap.checkAndRecordDevice(users[4], ua, res, tz, lang));
        assertEquals(1, deviceRows(hash, users[4]));
        // Now 5 users: a new user sees exactly 5 others -> FAIL, and no row is written.
        assertEquals(GateDecision.FAIL, tap.checkAndRecordDevice(users[5], ua, res, tz, lang));
        assertEquals(0, deviceRows(hash, users[5]));
        // A user who already has the device but sees 5 others also FAILs (FAIL is checked first).
        tap.insertDeviceFingerprint(users[6], hash, ua, res, tz);
        assertEquals(GateDecision.FAIL, tap.checkDeviceFingerprint(users[6], ua, res, tz, lang));
    }

    private int deviceRows(String hash, Long userId) throws SQLException {
        Connection conn = dataSource.getConnection();
        try (PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) FROM device_fingerprints WHERE device_hash = ? AND user_id = ?")) {
            ps.setString(1, hash);
            ps.setLong(2, userId);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        } finally {
            conn.close();
        }
    }

    // TRIAL-12
    @Test
    public void testChargebackHistoryPass() throws Exception {
        Long userId = createUser("user@example.com", null);
        // Ensure user has stripe customer ID
        setStripeCustomerId(userId, "cus_123");
        GateDecision decision = tap.checkChargebackHistory(userId);
        assertEquals(GateDecision.PASS, decision);
    }

    // TRIAL-13
    @Test
    public void testChargebackHistoryFail() throws Exception {
        Long userId = createUser("user@example.com", null);
        setStripeCustomerId(userId, "cus_123");
        // Add two chargebacks: one from stripe_events, one from refunds
        insertStripeEvent("cus_123", "chargeback.dispute.created");
        insertRefund(userId, "chargebacked");
        GateDecision decision = tap.checkChargebackHistory(userId);
        assertEquals(GateDecision.FAIL, decision);
    }

    // Helper methods
    private Long createUser(String email, String subscriptionStatus) throws SQLException {
        Connection conn = dataSource.getConnection();
        try {
            PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO users (stripe_customer_id, created_at) VALUES (?, NOW())",
                Statement.RETURN_GENERATED_KEYS
            );
            ps.setString(1, "cus_" + email.hashCode());
            ps.executeUpdate();
            ResultSet rs = ps.getGeneratedKeys();
            Long userId = null;
            if (rs.next()) {
                userId = rs.getLong(1);
            }
            // Create abuse ledger entry
            PreparedStatement ps2 = conn.prepareStatement(
                "INSERT INTO trial_abuse_ledger (user_id, email, subscription_status, created_at) VALUES (?, ?, ?, NOW())"
            );
            ps2.setLong(1, userId);
            ps2.setString(2, email);
            ps2.setString(3, subscriptionStatus);
            ps2.executeUpdate();
            return userId;
        } finally {
            conn.close();
        }
    }

    private void updateAbuseLedgerPayment(Long userId, String stripePaymentMethodId) throws SQLException {
        Connection conn = dataSource.getConnection();
        try {
            PreparedStatement ps = conn.prepareStatement(
                "UPDATE trial_abuse_ledger SET stripe_payment_method_id = ?, payment_added_date = NOW() WHERE user_id = ? AND subscription_status = 'completed' ORDER BY id DESC LIMIT 1"
            );
            ps.setString(1, stripePaymentMethodId);
            ps.setLong(2, userId);
            ps.executeUpdate();
        } finally {
            conn.close();
        }
    }

    private void insertSignup(String ip) throws SQLException {
        Connection conn = dataSource.getConnection();
        try {
            PreparedStatement ps = conn.prepareStatement("INSERT INTO signups (ip) VALUES (?)");
            ps.setString(1, ip);
            ps.executeUpdate();
        } finally {
            conn.close();
        }
    }

    private void updateUserCreatedAt(Long userId, Instant instant) throws SQLException {
        Connection conn = dataSource.getConnection();
        try {
            PreparedStatement ps = conn.prepareStatement("UPDATE users SET created_at = ? WHERE id = ?");
            ps.setTimestamp(1, Timestamp.from(instant));
            ps.setLong(2, userId);
            ps.executeUpdate();
        } finally {
            conn.close();
        }
    }

    private void setStripeCustomerId(Long userId, String stripeCustomerId) throws SQLException {
        Connection conn = dataSource.getConnection();
        try {
            PreparedStatement ps = conn.prepareStatement("UPDATE users SET stripe_customer_id = ? WHERE id = ?");
            ps.setString(1, stripeCustomerId);
            ps.setLong(2, userId);
            ps.executeUpdate();
        } finally {
            conn.close();
        }
    }

    private void insertStripeEvent(String customer, String type) throws SQLException {
        Connection conn = dataSource.getConnection();
        try {
            PreparedStatement ps = conn.prepareStatement("INSERT INTO stripe_events (customer, type) VALUES (?, ?)");
            ps.setString(1, customer);
            ps.setString(2, type);
            ps.executeUpdate();
        } finally {
            conn.close();
        }
    }

    private void insertRefund(Long userId, String status) throws SQLException {
        Connection conn = dataSource.getConnection();
        try {
            PreparedStatement ps = conn.prepareStatement("INSERT INTO refunds (user_id, status) VALUES (?, ?)");
            ps.setLong(1, userId);
            ps.setString(2, status);
            ps.executeUpdate();
        } finally {
            conn.close();
        }
    }
}
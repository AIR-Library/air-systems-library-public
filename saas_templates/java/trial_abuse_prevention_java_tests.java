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

    @Test
    public void testEmailTrialHistoryPass() throws Exception {
        GateDecision decision = tap.checkEmailTrialHistory("new@example.com");
        assertEquals(GateDecision.PASS, decision);
    }

    @Test
    public void testEmailTrialHistoryChallenge() throws Exception {
        // Create a user with one completed trial
        Long userId = createUser("test@example.com", "completed");
        GateDecision decision = tap.checkEmailTrialHistory("test@example.com");
        assertEquals(GateDecision.CHALLENGE, decision);
    }

    @Test
    public void testEmailTrialHistoryFail() throws Exception {
        // Create two completed trials
        createUser("test@example.com", "completed");
        createUser("test@example.com", "completed");
        GateDecision decision = tap.checkEmailTrialHistory("test@example.com");
        assertEquals(GateDecision.FAIL, decision);
    }

    @Test
    public void testPaymentMethodHistoryPass() throws Exception {
        GateDecision decision = tap.checkPaymentMethodHistory("pm_new");
        assertEquals(GateDecision.PASS, decision);
    }

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

    @Test
    public void testIpSignupRateLimitPass() throws Exception {
        GateDecision decision = tap.checkIpSignupRateLimit("1.2.3.4");
        assertEquals(GateDecision.PASS, decision);
    }

    @Test
    public void testIpSignupRateLimitFail() throws Exception {
        // Create 10 signups from same IP in last 24 hours
        for (int i = 0; i < 10; i++) {
            insertSignup("1.2.3.4");
        }
        GateDecision decision = tap.checkIpSignupRateLimit("1.2.3.4");
        assertEquals(GateDecision.FAIL, decision);
    }

    @Test
    public void testDeviceFingerprintPass() throws Exception {
        GateDecision decision = tap.checkDeviceFingerprint("UA", "1920x1080", "UTC", "en");
        assertEquals(GateDecision.PASS, decision);
    }

    /** Five users on one device: FAIL. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: stores TrialAbusePrevention.deviceHash of that device instead of the literal "hash123". Touches: in-memory H2. */
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
    }

    @Test
    public void testTrialPaymentTimingPass() throws Exception {
        Long userId = createUser("user@example.com", null); // trial just started
        // Set user created_at to now
        updateUserCreatedAt(userId, Instant.now());
        GateDecision decision = tap.checkTrialPaymentTiming(userId, 14); // 14-day trial
        assertEquals(GateDecision.PASS, decision);
    }

    @Test
    public void testTrialPaymentTimingFail() throws Exception {
        Long userId = createUser("user@example.com", null);
        // Set trial started 100 days ago
        Instant trialStart = Instant.now().minus(100, ChronoUnit.DAYS);
        updateUserCreatedAt(userId, trialStart);
        // Ensure no prior successful subscription
        GateDecision decision = tap.checkTrialPaymentTiming(userId, 14);
        assertEquals(GateDecision.FAIL, decision);
    }

    @Test
    public void testChargebackHistoryPass() throws Exception {
        Long userId = createUser("user@example.com", null);
        // Ensure user has stripe customer ID
        setStripeCustomerId(userId, "cus_123");
        GateDecision decision = tap.checkChargebackHistory(userId);
        assertEquals(GateDecision.PASS, decision);
    }

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
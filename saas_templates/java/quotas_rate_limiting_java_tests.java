import org.junit.jupiter.api.*;
import java.sql.*;
import java.time.*;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for QuotaManager, one per line of the spec's TESTS REQUIRED.
 *
 * Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the clock is a test clock the tests move forward.
 * With a clock frozen at one instant, the spec's own rate limits (10 calls per second per IP, 100 per minute per
 * user) must reject the 11th call, so "1000 calls succeed" and "99 calls from one IP succeed" could not pass
 * against any implementation of the spec. The quota tests now space calls one second apart and the per-user tests
 * 200 ms apart (5 per second per IP, all inside one minute), which keeps every original expectation.
 */
public class QuotaManagerTest {
    private QuotaManager qm;
    private QuotaManager.User soloUser;
    private QuotaManager.User teamUser;
    private QuotaManager.User enterpriseUser;
    private MutableClock fixedClock;

    /**
     * A clock that only moves when a test moves it. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
     */
    static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) { this.now = start; }

        void advance(Duration d) { now = now.plus(d); }

        void set(Instant instant) { now = instant; }

        @Override public ZoneId getZone() { return ZoneOffset.UTC; }

        @Override public Clock withZone(ZoneId zone) { return this; }

        @Override public Instant instant() { return now; }
    }

    /** Fresh manager on a test clock at 2024-01-01T00:00Z. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: MutableClock instead of a frozen clock. Touches: in-memory H2. */
    @BeforeEach
    public void setUp() throws Exception {
        fixedClock = new MutableClock(Instant.parse("2024-01-01T00:00:00Z"));
        qm = new QuotaManager(fixedClock);
        soloUser = new QuotaManager.User("solo1", QuotaManager.Tier.SOLO);
        teamUser = new QuotaManager.User("team1", QuotaManager.Tier.TEAM);
        enterpriseUser = new QuotaManager.User("ent1", QuotaManager.Tier.ENTERPRISE);
    }

    /** 1,000 solo calls pass, the 1,001st gets quota_exceeded. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: calls 1 s apart so the spec's rate limits do not fire first. */
    /**
     * QUOTA-13: -1 is unlimited in every quota. An enterprise upload larger than the team limit (150e9 bytes, given by
     * size) is stored, a second one on top of it too, and 10,001 enterprise calls in one month (past solo's 1,000 and
     * team's 10,000) all answer 200. In/out: none. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the
     * test manager's in-memory H2.
     */
    // QUOTA-13
    @Test
    public void testMinusOneIsUnlimitedForEnterprise() throws Exception {
        fixedClock.advance(Duration.ofSeconds(1));
        assertEquals(200, qm.handleApiCall(enterpriseUser, "/upload", "10.0.0.1", 150_000_000_000L, "feature_c").getStatusCode());
        fixedClock.advance(Duration.ofSeconds(1));
        assertEquals(200, qm.handleApiCall(enterpriseUser, "/upload", "10.0.0.1", 150_000_000_000L, "feature_c").getStatusCode());
        // The same size is refused for a team user, so the pass above is the -1 rule and not a missing check.
        fixedClock.advance(Duration.ofSeconds(1));
        assertEquals(413, qm.handleApiCall(teamUser, "/upload", "10.0.0.2", 150_000_000_000L, "feature_c").getStatusCode());
        for (int i = 0; i < 10_001; i++) {
            fixedClock.advance(Duration.ofSeconds(1));
            QuotaManager.Response r = qm.handleApiCall(enterpriseUser, "/test", "10.0.0.1", null, "feature_c");
            assertEquals(200, r.getStatusCode(), "enterprise call " + (i + 1) + " answered " + r.getBody());
        }
    }

    // QUOTA-01
    @Test
    public void testApiQuotaPass() throws Exception {
        for (int i = 0; i < 1000; i++) {
            fixedClock.advance(Duration.ofSeconds(1));
            QuotaManager.Response r = qm.handleApiCall(soloUser, "/test", "127.0.0.1", null, "feature_c");
            assertEquals(200, r.getStatusCode());
        }
        // 1001st call should fail
        fixedClock.advance(Duration.ofSeconds(1));
        QuotaManager.Response r = qm.handleApiCall(soloUser, "/test", "127.0.0.1", null, "feature_c");
        assertEquals(429, r.getStatusCode());
        assertTrue(r.getBody().contains("quota_exceeded"));
    }

    /** Past the monthly quota a call gets 429 quota_exceeded. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: calls 1 s apart; asserts the error code too. */
    // QUOTA-02
    @Test
    public void testApiQuotaFail() throws Exception {
        for (int i = 0; i < 1001; i++) {
            fixedClock.advance(Duration.ofSeconds(1));
            qm.handleApiCall(soloUser, "/test", "127.0.0.1", null, "feature_c");
        }
        fixedClock.advance(Duration.ofSeconds(1));
        QuotaManager.Response r = qm.handleApiCall(soloUser, "/test", "127.0.0.1", null, "feature_c");
        assertEquals(429, r.getStatusCode());
        assertTrue(r.getBody().contains("quota_exceeded"));
    }

    // QUOTA-03
    @Test
    public void testStorageQuotaPass() throws Exception {
        byte[] file = new byte[500_000_000]; // 500 MB
        QuotaManager.Response r = qm.handleApiCall(soloUser, "/upload", "127.0.0.1", file, "feature_c");
        assertEquals(200, r.getStatusCode());
    }

    // QUOTA-04
    @Test
    public void testStorageQuotaFail() throws Exception {
        byte[] file = new byte[1_200_000_000]; // 1.2 GB
        QuotaManager.Response r = qm.handleApiCall(soloUser, "/upload", "127.0.0.1", file, "feature_c");
        assertEquals(413, r.getStatusCode());
        assertTrue(r.getBody().contains("storage_quota_exceeded"));
    }

    /** 99 calls in a minute pass. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: 200 ms apart (5 per second per IP, under the IP limit). */
    // QUOTA-05
    @Test
    public void testRateLimitPerUserPass() throws Exception {
        for (int i = 0; i < 99; i++) {
            fixedClock.advance(Duration.ofMillis(200));
            QuotaManager.Response r = qm.handleApiCall(teamUser, "/test", "127.0.0.1", null, "feature_c");
            assertEquals(200, r.getStatusCode());
        }
    }

    /** The 101st call within a minute gets rate_limit_exceeded. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: 200 ms apart; each of the first 100 asserted 200. */
    // QUOTA-06
    @Test
    public void testRateLimitPerUserFail() throws Exception {
        for (int i = 0; i < 100; i++) {
            fixedClock.advance(Duration.ofMillis(200));
            assertEquals(200, qm.handleApiCall(teamUser, "/test", "127.0.0.1", null, "feature_c").getStatusCode());
        }
        fixedClock.advance(Duration.ofMillis(200));
        QuotaManager.Response r = qm.handleApiCall(teamUser, "/test", "127.0.0.1", null, "feature_c");
        assertEquals(429, r.getStatusCode());
        assertTrue(r.getBody().contains("rate_limit_exceeded"));
    }

    // QUOTA-07
    @Test
    public void testRateLimitPerIpPass() throws Exception {
        for (int i = 0; i < 9; i++) {
            QuotaManager.Response r = qm.handleApiCall(teamUser, "/test", "192.168.1.1", null, "feature_c");
            assertEquals(200, r.getStatusCode());
        }
    }

    // QUOTA-08
    @Test
    public void testRateLimitPerIpFail() throws Exception {
        for (int i = 0; i < 10; i++) {
            qm.handleApiCall(teamUser, "/test", "192.168.1.1", null, "feature_c");
        }
        QuotaManager.Response r = qm.handleApiCall(teamUser, "/test", "192.168.1.1", null, "feature_c");
        assertEquals(429, r.getStatusCode());
        assertTrue(r.getBody().contains("ip_rate_limit_exceeded"));
    }

    // QUOTA-09
    @Test
    public void testFeatureGatePass() throws Exception {
        QuotaManager.Response r = qm.handleApiCall(teamUser, "/feature", "127.0.0.1", null, "feature_a");
        assertEquals(200, r.getStatusCode());
    }

    // QUOTA-10
    @Test
    public void testFeatureGateFail() throws Exception {
        QuotaManager.Response r = qm.handleApiCall(soloUser, "/feature", "127.0.0.1", null, "feature_a");
        assertEquals(403, r.getStatusCode());
        assertTrue(r.getBody().contains("feature_not_available"));
    }

    /** Usage resets in a new month. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: exhausts January on one manager, then moves its clock to February. */
    // QUOTA-11
    @Test
    public void testMonthRollover() throws Exception {
        // Use up January's quota. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the test made one
        // call and then built a new QuotaManager, which proved nothing about rollover once each instance has its
        // own database; it now exhausts the month and moves the same manager's clock into February.
        for (int i = 0; i < 1000; i++) {
            fixedClock.advance(Duration.ofSeconds(1));
            qm.handleApiCall(soloUser, "/test", "127.0.0.1", null, "feature_c");
        }
        fixedClock.advance(Duration.ofSeconds(1));
        assertEquals(429, qm.handleApiCall(soloUser, "/test", "127.0.0.1", null, "feature_c").getStatusCode());
        // Advance clock to next month
        fixedClock.set(Instant.parse("2024-02-01T00:00:00Z"));
        // Should start fresh
        QuotaManager.Response r = qm.handleApiCall(soloUser, "/test", "127.0.0.1", null, "feature_c");
        assertEquals(200, r.getStatusCode());
    }

    /** An upgrade lifts the limit immediately. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: calls 1 s apart; asserts the solo limit was reached first. */
    // QUOTA-12
    @Test
    public void testTierUpgrade() throws Exception {
        // Solo user makes 1000 calls
        for (int i = 0; i < 1000; i++) {
            fixedClock.advance(Duration.ofSeconds(1));
            qm.handleApiCall(soloUser, "/test", "127.0.0.1", null, "feature_c");
        }
        fixedClock.advance(Duration.ofSeconds(1));
        assertEquals(429, qm.handleApiCall(soloUser, "/test", "127.0.0.1", null, "feature_c").getStatusCode());
        // Upgrade to team
        soloUser.setTier(QuotaManager.Tier.TEAM);
        // Should allow more calls
        fixedClock.advance(Duration.ofSeconds(1));
        QuotaManager.Response r = qm.handleApiCall(soloUser, "/test", "127.0.0.1", null, "feature_c");
        assertEquals(200, r.getStatusCode());
    }
}
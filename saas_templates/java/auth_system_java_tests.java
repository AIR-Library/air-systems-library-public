import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class AuthSystemTests {

    // The token tests sign with this key, so the service must use it (it no longer has a hard-coded one).
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    static final String TEST_JWT_SECRET = "test-only-jwt-secret-0123456789abcdef";
    static final java.util.List<String> SENT = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
    /** Last code the fake mailer was handed, by email (codes are only hashed in the database since AUTH-16, 2026-11-10). */
    static final Map<String, String> CODES = new java.util.concurrent.ConcurrentHashMap<>();

    /** Fixed 32+ byte HMAC key for stored secrets (spec d270fa3: tests pass a fixed test key). 2026-11-10,
     *  session_012zDydZCZ4AChqhEZ4oVtaP. */
    static final String TEST_SECRET_KEY = "test-secret-key-0123456789abcdef-auth";

    static {
        System.setProperty("AUTH_JWT_SECRET", TEST_JWT_SECRET);
        // spec d270fa3 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): AuthSystem refuses to load without this key.
        System.setProperty("AUTH_SECRET_KEY", TEST_SECRET_KEY);
    }

    /**
     * The value the module stores for a secret: lowercase hex HMAC-SHA256(TEST_SECRET_KEY, value). In: the secret.
     * Out: 64 hex characters. Why: spec d270fa3: keyed HMAC for stored secrets; the tests used the module's plain
     * SHA-256 helper (AuthSystem.sha256Hex) until 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: nothing.
     */
    static String hmacHex(String value) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(TEST_SECRET_KEY.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256"));
            return java.util.HexFormat.of().formatHex(mac.doFinal(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (java.security.GeneralSecurityException e) {
            throw new AssertionError(e);
        }
    }

    /**
     * Plain, unkeyed SHA-256 hex of a secret, which the module must no longer store. In: the secret. Out: 64 hex
     * characters. Why: spec d270fa3: keyed HMAC for stored secrets (AUTH-16 asserts the stored value is not this).
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    static String plainSha256Hex(String value) {
        try {
            return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (java.security.GeneralSecurityException e) {
            throw new AssertionError(e);
        }
    }

    /**
     * Fake OAuth provider client: accepts only the codes it was told about and answers with a fixed identity, so a test
     * can tell the provider's user id apart from the code. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (the
     * implementation's DummyOAuthProvider, which ignored the code, was replaced by an injected client; AUTH spec
     * "Secrets at rest"). Touches: memory only.
     */
    static final class FakeOAuthProvider implements AuthSystem.OAuthProvider {
        final Map<String, AuthSystem.OAuthIdentity> byCode = new java.util.concurrent.ConcurrentHashMap<>();
        final java.util.List<String> exchanged = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
        FakeOAuthProvider accept(String code, String sub, String email, boolean verified) {
            byCode.put(code, new AuthSystem.OAuthIdentity(sub, email, verified));
            return this;
        }
        /**
         * Records the code and returns the identity registered for it, or null for an unknown code. In: the code.
         * Out: the identity or null. @Override added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (code review on
         * PR 21: it implements OAuthProvider.exchangeCode). Touches: memory only.
         */
        @Override
        public AuthSystem.OAuthIdentity exchangeCode(String code) {
            exchanged.add(code);
            return byCode.get(code);
        }
    }

    static final FakeOAuthProvider GOOGLE = new FakeOAuthProvider();

    /**
     * Installs the fake mailer and the fake OAuth provider. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the
     * mailer now also keeps the code (the database holds only its hash), and the provider is a FakeOAuthProvider.
     */
    @BeforeAll
    public static void setup() {
        GOOGLE.accept("code123", "google-sub-new", "newuser@example.com", true);
        AuthSystem.OAuthProviderRegistry.register("google", GOOGLE);
        AuthSystem.setEmailSender((email, code) -> { SENT.add(email); CODES.put(email, code); });
    }

    /** Puts the real clock back after a test that moved it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    @AfterEach
    public void restoreClock() {
        AuthSystem.setClock(java.time.Clock.systemUTC());
    }

    /** A fresh OAuth state for the provider (fails the test if refused). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static String newState(String provider) {
        Map<String, Object> start = AuthSystem.oauthStart(provider);
        assertEquals(Boolean.TRUE, start.get("success"), String.valueOf(start));
        return (String) start.get("state");
    }

    // AUTH-01
    @Test
    public void testSignupHappyPath() {
        Map<String, Object> res = AuthSystem.signup("john@example.com", "StrongPassword123456", "John", "1.2.3.4");
        assertTrue((Boolean)res.get("success"));
        assertEquals("pending_verification", res.get("status"));
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the row says "email sent" (through the injected sender).
        assertTrue(SENT.contains("john@example.com"));
    }

    // AUTH-02
    @Test
    public void testSignupDuplicateEmail() {
        AuthSystem.signup("dup@example.com", "StrongPassword123456", "Dup", "1.2.3.4");
        Map<String, Object> res = AuthSystem.signup("dup@example.com", "StrongPassword123456", "Dup2", "1.2.3.5");
        assertFalse((Boolean)res.get("success"));
        assertEquals("email_already_exists", res.get("error"));
    }

    // AUTH-03
    @Test
    public void testSignupWeakPassword() {
        Map<String, Object> res = AuthSystem.signup("weak@example.com", "short", "Weak", "1.2.3.6");
        assertFalse((Boolean)res.get("success"));
        assertEquals("password_rejected", res.get("error"));
        assertEquals("too_short", res.get("message"));
        assertEquals("too_short", res.get("reason"));
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-03 amendment): length is checked before the blocklist.
        res = AuthSystem.signup("weak2@example.com", "password123", "Weak", "1.2.3.66");
        assertEquals("password_rejected", res.get("error"));
        assertEquals("too_short", res.get("reason"));
    }

    // AUTH-04
    @Test
    public void testSignupIpRateLimit() {
        for (int i = 0; i < 5; i++) {
            AuthSystem.signup("ipuser" + i + "@example.com", "StrongPassword123456", "IPUser", "192.168.0.1");
        }
        Map<String, Object> res = AuthSystem.signup("ipuser6@example.com", "StrongPassword123456", "IPUser", "192.168.0.1");
        assertFalse((Boolean)res.get("success"));
        assertEquals("too_many_signups_from_ip", res.get("error"));
    }

    // AUTH-05
    @Test
    public void testVerifyEmailHappyPath() {
        Map<String, Object> signup = AuthSystem.signup("verify@example.com", "StrongPassword123456", "Verify", "1.2.3.7");
        String code = extractCodeFromEmail("verify@example.com");
        Map<String, Object> res = AuthSystem.verifyEmail("verify@example.com", code);
        assertTrue((Boolean)res.get("success"));
        assertEquals("verified", res.get("status"));
    }

    // AUTH-06
    @Test
    public void testVerifyEmailExpiredCode() {
        Map<String, Object> signup = AuthSystem.signup("expire@example.com", "StrongPassword123456", "Expire", "1.2.3.8");
        String code = extractCodeFromEmail("expire@example.com");
        // Manually expire
        expireCode(code);
        Map<String, Object> res = AuthSystem.verifyEmail("expire@example.com", code);
        assertFalse((Boolean)res.get("success"));
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the spec's AUTH-06 answer is code_expired (it asserted
        // code_invalid, which the implementation gave for every failure).
        assertEquals("code_expired", res.get("error"));
    }

    /**
     * Phase B.3 ruling (d4f4ed7): 5 wrong verification codes invalidate the user's current code, so the right code is
     * then code_invalid too; after only 4 wrong codes the right code still verifies. Added 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory H2 (verification_codes, users).
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.4 ruling af92d76): tagged AUTH-17, the id the ruling
     * gave this rule (it was tagged AUTH-05, which testVerifyEmailHappyPath still names); it now also asserts each of
     * the 4 wrong tries is code_invalid and that a newly sent code verifies. Nothing it asserted before changed.
     */
    // AUTH-17
    @Test
    public void testFiveWrongCodesInvalidateTheCode() {
        AuthSystem.signup("guess5@example.com", "StrongPassword123456", "Guess", "1.2.9.1");
        String code = extractCodeFromEmail("guess5@example.com");
        String wrong = code.equals("000000") ? "111111" : "000000";
        for (int i = 0; i < 5; i++) {
            assertEquals("code_invalid", AuthSystem.verifyEmail("guess5@example.com", wrong).get("error"), "wrong try " + i);
        }
        Map<String, Object> res = AuthSystem.verifyEmail("guess5@example.com", code);
        assertFalse((Boolean) res.get("success"));
        assertEquals("code_invalid", res.get("error"), "the right code after 5 wrong ones");

        // AUTH-17 (Phase B.4, af92d76, 2026-11-10): a newly sent code (a fresh row, stored as its HMAC) works again.
        String guessId = queryString("SELECT id FROM users WHERE email = ?", "guess5@example.com");
        try (java.sql.Connection conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:authdb;DB_CLOSE_DELAY=-1");
             java.sql.PreparedStatement ps = conn.prepareStatement(
                     "INSERT INTO verification_codes (user_id, code_hash, created_at, expires_at, type) VALUES (?, ?, ?, ?, 'email')")) {
            ps.setLong(1, Long.parseLong(guessId));
            ps.setString(2, hmacHex("654321"));
            ps.setTimestamp(3, java.sql.Timestamp.from(java.time.Instant.now()));
            ps.setTimestamp(4, java.sql.Timestamp.from(java.time.Instant.now().plusSeconds(3600)));
            assertEquals(1, ps.executeUpdate());
        } catch (java.sql.SQLException e) {
            throw new AssertionError(e);
        }
        assertEquals("verified", AuthSystem.verifyEmail("guess5@example.com", "654321").get("status"), "a newly sent code verifies");

        AuthSystem.signup("guess4@example.com", "StrongPassword123456", "Guess", "1.2.9.2");
        String code4 = extractCodeFromEmail("guess4@example.com");
        String wrong4 = code4.equals("000000") ? "111111" : "000000";
        for (int i = 0; i < 4; i++) {
            // AUTH-17 (2026-11-10): each wrong try is now asserted too.
            assertEquals("code_invalid", AuthSystem.verifyEmail("guess4@example.com", wrong4).get("error"), "wrong try " + i);
        }
        assertEquals("verified", AuthSystem.verifyEmail("guess4@example.com", code4).get("status"), "4 wrong tries leave it valid");
    }

    // AUTH-07
    @Test
    public void testLoginHappyPathNoMfa() {
        Map<String, Object> signup = AuthSystem.signup("login@example.com", "StrongPassword123456", "Login", "1.2.3.9");
        String code = extractCodeFromEmail("login@example.com");
        AuthSystem.verifyEmail("login@example.com", code);
        Map<String, Object> res = AuthSystem.login("login@example.com", "StrongPassword123456", "device1", "1.2.3.9");
        assertTrue((Boolean)res.get("success"));
        assertEquals("authenticated", res.get("status"));
        assertNotNull(res.get("token"));
    }

    // AUTH-08
    @Test
    public void testLoginWithMfaEnabled() {
        Map<String, Object> signup = AuthSystem.signup("mfa@example.com", "StrongPassword123456", "MFA", "1.2.3.10");
        String code = extractCodeFromEmail("mfa@example.com");
        AuthSystem.verifyEmail("mfa@example.com", code);
        enableMfa("mfa@example.com");
        Map<String, Object> res = AuthSystem.login("mfa@example.com", "StrongPassword123456", "device2", "1.2.3.10");
        assertTrue((Boolean)res.get("success"));
        assertEquals("mfa_required", res.get("status"));
        assertNotNull(res.get("challenge_id"));
    }

    // AUTH-09
    @Test
    public void testLoginInvalidPassword() {
        Map<String, Object> signup = AuthSystem.signup("badpass@example.com", "StrongPassword123456", "BadPass", "1.2.3.11");
        String code = extractCodeFromEmail("badpass@example.com");
        AuthSystem.verifyEmail("badpass@example.com", code);
        Map<String, Object> res = AuthSystem.login("badpass@example.com", "WrongPassword", "device3", "1.2.3.11");
        assertFalse((Boolean)res.get("success"));
        assertEquals("invalid_credentials", res.get("error"));
    }

    // AUTH-10
    @Test
    public void testOauthCallbackHappyPathNewUser() {
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the state now comes from oauthStart (a made-up
        // "state123" is refused since state is validated), and the link must hold the provider's id, not the code.
        Map<String, Object> res = AuthSystem.oauthCallback("google", "code123", newState("google"));
        assertTrue((Boolean)res.get("success"));
        assertEquals("authenticated", res.get("status"));
        assertNotNull(res.get("token"));
        assertNotNull(res.get("refresh_token"));
        assertTrue(GOOGLE.exchanged.contains("code123"));
        assertEquals(1, countRows("SELECT COUNT(*) FROM oauth_links WHERE provider_user_id = ?", "google-sub-new"));
        assertEquals(0, countRows("SELECT COUNT(*) FROM oauth_links WHERE provider_user_id = ?", "code123"));
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: "user created + oauth linked" checked in the database.
        assertEquals(1, countRows("SELECT COUNT(*) FROM users WHERE email = ?", "newuser@example.com"));
        assertEquals(1, countRows("SELECT COUNT(*) FROM oauth_links WHERE provider = 'google' AND user_id = (SELECT id FROM users WHERE email = ?)", "newuser@example.com"));
    }

    // AUTH-11
    @Test
    public void testOauthCallbackExistingUser() {
        // Register a provider that returns the existing user's email
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: fake provider client and a real state (see AUTH-10).
        AuthSystem.OAuthProviderRegistry.register("google_existing",
                new FakeOAuthProvider().accept("code123", "google-sub-existing", "existing@example.com", true));
        AuthSystem.signup("existing@example.com", "StrongPassword123456", "Existing", "1.2.3.12");
        String code = extractCodeFromEmail("existing@example.com");
        AuthSystem.verifyEmail("existing@example.com", code);
        Map<String, Object> res = AuthSystem.oauthCallback("google_existing", "code123", newState("google_existing"));
        assertTrue((Boolean)res.get("success"));
        assertEquals("authenticated", res.get("status"));
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: "linked to existing account" checked in the database: still one
        // user with that email, and the provider link points at it.
        assertEquals(1, countRows("SELECT COUNT(*) FROM users WHERE email = ?", "existing@example.com"));
        assertEquals(1, countRows("SELECT COUNT(*) FROM oauth_links WHERE provider = 'google_existing' AND user_id = (SELECT id FROM users WHERE email = ?)", "existing@example.com"));
    }

    /** COUNT(*) of a one-parameter query on the test database. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads H2. */
    private int countRows(String sql, String param) {
        try (java.sql.Connection conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:authdb;DB_CLOSE_DELAY=-1");
             java.sql.PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, param);
            try (java.sql.ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        } catch (java.sql.SQLException e) {
            throw new AssertionError(e);
        }
    }

    // AUTH-12
    @Test
    public void testMfaChallengeHappyPath() {
        Map<String, Object> signup = AuthSystem.signup("mfa2@example.com", "StrongPassword123456", "MFA2", "1.2.3.13");
        String code = extractCodeFromEmail("mfa2@example.com");
        AuthSystem.verifyEmail("mfa2@example.com", code);
        enableMfa("mfa2@example.com");
        Map<String, Object> loginRes = AuthSystem.login("mfa2@example.com", "StrongPassword123456", "device4", "1.2.3.13");
        String challengeId = (String)loginRes.get("challenge_id");
        String totp = generateTotpForUser("mfa2@example.com");
        Map<String, Object> res = AuthSystem.mfaChallenge(challengeId, totp);
        assertTrue((Boolean)res.get("success"));
        assertEquals("authenticated", res.get("status"));
        assertNotNull(res.get("token"));
    }

    // AUTH-13
    @Test
    public void testMfaChallengeWrongCode() {
        Map<String, Object> signup = AuthSystem.signup("mfa3@example.com", "StrongPassword123456", "MFA3", "1.2.3.14");
        String code = extractCodeFromEmail("mfa3@example.com");
        AuthSystem.verifyEmail("mfa3@example.com", code);
        enableMfa("mfa3@example.com");
        Map<String, Object> loginRes = AuthSystem.login("mfa3@example.com", "StrongPassword123456", "device5", "1.2.3.14");
        String challengeId = (String)loginRes.get("challenge_id");
        Map<String, Object> res = AuthSystem.mfaChallenge(challengeId, "000000");
        assertFalse((Boolean)res.get("success"));
        assertEquals("invalid_code", res.get("error"));
    }

    // AUTH-14
    @Test
    public void testTokenRefreshHappyPath() {
        Map<String, Object> signup = AuthSystem.signup("refresh@example.com", "StrongPassword123456", "Refresh", "1.2.3.15");
        String code = extractCodeFromEmail("refresh@example.com");
        AuthSystem.verifyEmail("refresh@example.com", code);
        Map<String, Object> loginRes = AuthSystem.login("refresh@example.com", "StrongPassword123456", "device6", "1.2.3.15");
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-16): the token comes from login's answer; the
        // database holds only its hash, so it can no longer be read back from the sessions table.
        String refreshToken = (String)loginRes.get("refresh_token");
        Map<String, Object> res = AuthSystem.tokenRefresh(refreshToken);
        assertTrue((Boolean)res.get("success"));
        assertEquals("ok", res.get("status"));
        assertNotNull(res.get("token"));
    }

    // AUTH-15
    @Test
    public void testTokenRefreshBannedUser() {
        Map<String, Object> signup = AuthSystem.signup("ban@example.com", "StrongPassword123456", "Ban", "1.2.3.16");
        String code = extractCodeFromEmail("ban@example.com");
        AuthSystem.verifyEmail("ban@example.com", code);
        banUser("ban@example.com");
        Map<String, Object> loginRes = AuthSystem.login("ban@example.com", "StrongPassword123456", "device7", "1.2.3.16");
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-16): refresh token from login's answer.
        String refreshToken = (String)loginRes.get("refresh_token");
        assertNotNull(refreshToken);
        Map<String, Object> res = AuthSystem.tokenRefresh(refreshToken);
        assertFalse((Boolean)res.get("success"));
        assertEquals("user_banned", res.get("error"));
    }

    @Test
    public void testVerifyAccessTokenValid() {
        AuthSystem.signup("verifytoken@example.com", "StrongPassword123456", "VerifyToken", "1.2.3.17");
        String code = extractCodeFromEmail("verifytoken@example.com");
        AuthSystem.verifyEmail("verifytoken@example.com", code);
        Map<String, Object> loginRes = AuthSystem.login("verifytoken@example.com", "StrongPassword123456", "device8", "1.2.3.17");
        String token = (String)loginRes.get("token");
        Map<String, Object> res = AuthSystem.verifyAccessToken(token);
        assertTrue((Boolean)res.get("success"));
        assertEquals("ok", res.get("status"));
        assertNotNull(res.get("user"));
        Map<String, Object> user = (Map<String, Object>)res.get("user");
        assertEquals("verifytoken@example.com", user.get("email"));
    }

    @Test
    public void testVerifyAccessTokenExpired() {
        // Create a token that's already expired by manipulating the system
        // We'll use a token with a past expiration
        String expiredToken = createExpiredToken(1L);
        Map<String, Object> res = AuthSystem.verifyAccessToken(expiredToken);
        assertFalse((Boolean)res.get("success"));
        assertEquals("token_expired", res.get("error"));
    }

    @Test
    public void testVerifyAccessTokenInvalidSignature() {
        // Create a token with wrong secret
        String invalidToken = createTokenWithWrongSecret(1L);
        Map<String, Object> res = AuthSystem.verifyAccessToken(invalidToken);
        assertFalse((Boolean)res.get("success"));
        assertEquals("invalid_token", res.get("error"));
    }

    @Test
    public void testVerifyAccessTokenBannedUser() {
        AuthSystem.signup("bantoken@example.com", "StrongPassword123456", "BanToken", "1.2.3.18");
        String code = extractCodeFromEmail("bantoken@example.com");
        AuthSystem.verifyEmail("bantoken@example.com", code);
        banUser("bantoken@example.com");
        Map<String, Object> loginRes = AuthSystem.login("bantoken@example.com", "StrongPassword123456", "device9", "1.2.3.18");
        String token = (String)loginRes.get("token");
        Map<String, Object> res = AuthSystem.verifyAccessToken(token);
        assertFalse((Boolean)res.get("success"));
        assertEquals("user_banned", res.get("error"));
    }

    /**
     * Blocklisted passwords are rejected with reason "blocklisted". Changed 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-03 amendment: too_short, too_long, blocklisted in that order): the common
     * password, the name and the service name used here were shorter than 15 characters, so they are now too_short;
     * the test uses 15+ character values for the blocklist cases and expects too_short for "auth_system".
     */
    @Test
    public void testPasswordBlocklistRejection() {
        // Test common password rejection
        Map<String, Object> res = AuthSystem.signup("block1@example.com", "passwordpassword", "Block1", "1.2.3.19");
        assertFalse((Boolean)res.get("success"));
        assertEquals("password_rejected", res.get("error"));
        assertEquals("blocklisted", res.get("reason"));

        // Test email as password rejection
        res = AuthSystem.signup("block2@example.com", "block2@example.com", "Block2", "1.2.3.20");
        assertFalse((Boolean)res.get("success"));
        assertEquals("password_rejected", res.get("error"));
        assertEquals("blocklisted", res.get("reason"));

        // Test name as password rejection
        res = AuthSystem.signup("block3@example.com", "Blocked Name Person", "Blocked Name Person", "1.2.3.21");
        assertFalse((Boolean)res.get("success"));
        assertEquals("password_rejected", res.get("error"));
        assertEquals("blocklisted", res.get("reason"));

        // The service name is shorter than 15 characters, so the first failing check is the length.
        res = AuthSystem.signup("block4@example.com", "auth_system", "Block4", "1.2.3.22");
        assertFalse((Boolean)res.get("success"));
        assertEquals("password_rejected", res.get("error"));
        assertEquals("too_short", res.get("reason"));
    }

    @Test
    public void testPasswordMaxLength() {
        // 64 chars should be allowed
        String pass64 = "A".repeat(64);
        Map<String, Object> res = AuthSystem.signup("maxlen@example.com", pass64, "MaxLen", "1.2.3.23");
        assertTrue((Boolean)res.get("success"));

        // 65 chars should be rejected
        String pass65 = "A".repeat(65);
        res = AuthSystem.signup("maxlen2@example.com", pass65, "MaxLen2", "1.2.3.24");
        assertFalse((Boolean)res.get("success"));
        assertEquals("password_rejected", res.get("error"));
        assertEquals("too_long", res.get("message"));
        assertEquals("too_long", res.get("reason"));
    }

    @Test
    public void testLoginRateLimit() {
        AuthSystem.signup("ratelimit@example.com", "StrongPassword123456", "RateLimit", "1.2.3.25");
        String code = extractCodeFromEmail("ratelimit@example.com");
        AuthSystem.verifyEmail("ratelimit@example.com", code);

        // 5 failed attempts
        for (int i = 0; i < 5; i++) {
            Map<String, Object> res = AuthSystem.login("ratelimit@example.com", "WrongPassword", "device", "1.2.3.25");
            assertFalse((Boolean)res.get("success"));
        }

        // 6th attempt should be rate limited
        Map<String, Object> res = AuthSystem.login("ratelimit@example.com", "WrongPassword", "device", "1.2.3.25");
        assertFalse((Boolean)res.get("success"));
        assertEquals("too_many_attempts", res.get("error"));

        // The right password is refused too while the limit holds, or the limit would stop nothing.
        Map<String, Object> right = AuthSystem.login("ratelimit@example.com", "StrongPassword123456", "device", "1.2.3.25");
        assertEquals("too_many_attempts", right.get("error"));
    }

    /**
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec d270fa3: keyed HMAC for stored secrets): each stored
     * value must equal HMAC-SHA256(TEST_SECRET_KEY, value) and must not equal its plain SHA-256.
     * AUTH-16: login returns a refresh_token that token_refresh accepts; sessions keep only its SHA-256; the email
     * verification code and the MFA challenge id are stored only as code_hash. Added 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 spec amendment). Touches: H2 (reads sessions, verification_codes).
     */
    // AUTH-16
    @Test
    public void testRefreshTokenAndCodesStoredOnlyAsHashes() {
        AuthSystem.signup("hashes@example.com", "StrongPassword123456", "Hashes", "1.2.3.40");
        String code = extractCodeFromEmail("hashes@example.com");
        assertNotNull(code);
        assertFalse(columns("verification_codes").contains("CODE"), "verification_codes must not have a plain code column");
        assertEquals(hmacHex(code), queryString(
                "SELECT code_hash FROM verification_codes WHERE user_id = (SELECT id FROM users WHERE email = ?) AND type = 'email'",
                "hashes@example.com"));
        // spec d270fa3 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): keyed, so not the code's plain SHA-256.
        assertNotEquals(plainSha256Hex(code), queryString(
                "SELECT code_hash FROM verification_codes WHERE user_id = (SELECT id FROM users WHERE email = ?) AND type = 'email'",
                "hashes@example.com"));
        assertEquals("verified", AuthSystem.verifyEmail("hashes@example.com", code).get("status"));

        Map<String, Object> loginRes = AuthSystem.login("hashes@example.com", "StrongPassword123456", "dev", "1.2.3.40");
        String refreshToken = (String) loginRes.get("refresh_token");
        assertNotNull(refreshToken);
        String sessionId = (String) loginRes.get("session_id");
        assertFalse(columns("sessions").contains("REFRESH_TOKEN"), "sessions must not have a plain refresh_token column");
        String stored = queryString("SELECT refresh_token_hash FROM sessions WHERE id = ?", sessionId);
        assertEquals(hmacHex(refreshToken), stored);
        assertNotEquals(plainSha256Hex(refreshToken), stored); // spec d270fa3, 2026-11-10
        assertNotEquals(refreshToken, stored);
        // The stored hash is not itself a usable refresh token.
        assertEquals("invalid_token", AuthSystem.tokenRefresh(stored).get("error"));
        Map<String, Object> refreshed = AuthSystem.tokenRefresh(refreshToken);
        assertEquals("ok", refreshed.get("status"), String.valueOf(refreshed));
        assertNotNull(refreshed.get("token"));

        // MFA: the challenge id is hashed too, and the session the challenge creates also returns a refresh token.
        AuthSystem.signup("hashes-mfa@example.com", "StrongPassword123456", "HashesMfa", "1.2.3.41");
        AuthSystem.verifyEmail("hashes-mfa@example.com", extractCodeFromEmail("hashes-mfa@example.com"));
        enableMfa("hashes-mfa@example.com");
        String challengeId = (String) AuthSystem.login("hashes-mfa@example.com", "StrongPassword123456", "dev", "1.2.3.41").get("challenge_id");
        assertEquals(hmacHex(challengeId), queryString(
                "SELECT code_hash FROM verification_codes WHERE user_id = (SELECT id FROM users WHERE email = ?) AND type = 'mfa'",
                "hashes-mfa@example.com"));
        Map<String, Object> mfa = AuthSystem.mfaChallenge(challengeId, generateTotpForUser("hashes-mfa@example.com"));
        assertEquals("authenticated", mfa.get("status"), String.valueOf(mfa));
        assertEquals("ok", AuthSystem.tokenRefresh((String) mfa.get("refresh_token")).get("status"));
    }

    /**
     * AUTH-16: the service refuses to start without a 32-byte key. Loading AuthSystem afresh (its own class loader,
     * same class path) with AUTH_SECRET_KEY empty or 31 bytes fails in class initialisation with
     * IllegalStateException, before the database is opened; secretKeyFrom refuses null, empty and 31-byte keys and
     * accepts 32 bytes; the loaded service stores HMAC-SHA256(TEST_SECRET_KEY, value), not a plain SHA-256.
     * In: the AUTH_SECRET_KEY system property (restored afterwards). Out: assertions. Why: spec d270fa3: keyed HMAC
     * for stored secrets ("the service refuses to start without it"). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the AUTH_SECRET_KEY system property, a throwaway class loader.
     */
    // AUTH-16
    @Test
    public void testServiceRefusesToStartWithoutSecretKey() throws Exception {
        assertThrows(IllegalStateException.class, () -> AuthSystem.secretKeyFrom(null));
        assertThrows(IllegalStateException.class, () -> AuthSystem.secretKeyFrom(""));
        assertThrows(IllegalStateException.class, () -> AuthSystem.secretKeyFrom("k".repeat(31)));
        assertEquals(32, AuthSystem.secretKeyFrom("k".repeat(32)).length);

        java.util.List<java.net.URL> urls = new java.util.ArrayList<>();
        for (Class<?> c : new Class<?>[] { AuthSystem.class, JWT.class, org.mindrot.jbcrypt.BCrypt.class,
                com.fasterxml.jackson.databind.ObjectMapper.class, com.fasterxml.jackson.core.type.TypeReference.class,
                com.fasterxml.jackson.annotation.JsonProperty.class, Class.forName("org.h2.Driver") }) {
            urls.add(c.getProtectionDomain().getCodeSource().getLocation());
        }
        try {
            for (String bad : new String[] { "", "k".repeat(31) }) {
                System.setProperty("AUTH_SECRET_KEY", bad);
                try (java.net.URLClassLoader fresh = new java.net.URLClassLoader(
                        urls.toArray(new java.net.URL[0]), ClassLoader.getPlatformClassLoader())) {
                    ExceptionInInitializerError e = assertThrows(ExceptionInInitializerError.class,
                            () -> Class.forName("AuthSystem", true, fresh));
                    assertInstanceOf(IllegalStateException.class, e.getCause());
                    assertTrue(e.getCause().getMessage().contains("AUTH_SECRET_KEY"), e.getCause().getMessage());
                }
            }
        } finally {
            System.setProperty("AUTH_SECRET_KEY", TEST_SECRET_KEY);
        }
        assertEquals(hmacHex("123456"), AuthSystem.secretHash("123456"));
        assertNotEquals(plainSha256Hex("123456"), AuthSystem.secretHash("123456"));
    }

    /**
     * OAuth state: an unknown state, a reused state, a state older than 10 minutes and a state issued for another
     * provider are all refused with invalid_state, and the provider is never asked to exchange the code for them; the
     * state is stored only as its SHA-256 (its HMAC-SHA256 under the test key since spec d270fa3, 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH spec "Secrets at
     * rest" amendment; java SECURITY bug: the state was not validated). Touches: H2, the injected clock.
     */
    // AUTH-10
    @Test
    public void testOauthStateIsSingleUseAndExpires() {
        FakeOAuthProvider p = new FakeOAuthProvider()
                .accept("c1", "sub-1", "state1@example.com", true)
                .accept("c2", "sub-1", "state1@example.com", true)
                .accept("c3", "sub-1", "state1@example.com", true)
                .accept("c4", "sub-1", "state1@example.com", true);
        AuthSystem.OAuthProviderRegistry.register("statecheck", p);
        AuthSystem.OAuthProviderRegistry.register("statecheck_other", new FakeOAuthProvider());

        assertEquals("invalid_state", AuthSystem.oauthCallback("statecheck", "c1", "made-up-state").get("error"));
        assertEquals("invalid_state", AuthSystem.oauthCallback("statecheck", "c1", null).get("error"));

        String state = newState("statecheck");
        assertEquals(hmacHex(state), queryString("SELECT state_hash FROM oauth_states WHERE state_hash = ?", hmacHex(state)));
        // spec d270fa3 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): the stored state hash is keyed, not a plain SHA-256.
        assertEquals(0, countRows("SELECT COUNT(*) FROM oauth_states WHERE state_hash = ?", plainSha256Hex(state)));
        assertEquals(0, countRows("SELECT COUNT(*) FROM oauth_states WHERE state_hash = ?", state));
        assertEquals("authenticated", AuthSystem.oauthCallback("statecheck", "c1", state).get("status"));
        assertEquals("invalid_state", AuthSystem.oauthCallback("statecheck", "c2", state).get("error"), "a state is single-use");

        String other = newState("statecheck_other");
        assertEquals("invalid_state", AuthSystem.oauthCallback("statecheck", "c3", other).get("error"), "state is bound to its provider");

        String old = newState("statecheck");
        AuthSystem.setClock(java.time.Clock.offset(java.time.Clock.systemUTC(), java.time.Duration.ofMinutes(10).plusSeconds(1)));
        assertEquals("invalid_state", AuthSystem.oauthCallback("statecheck", "c4", old).get("error"), "a state expires after 10 minutes");
        AuthSystem.setClock(java.time.Clock.systemUTC());

        // Only the one valid callback reached the provider.
        assertEquals(java.util.List.of("c1"), p.exchanged);
        // A code the provider refuses is not an identity.
        assertEquals("oauth_exchange_failed", AuthSystem.oauthCallback("statecheck", "never-issued", newState("statecheck")).get("error"));
        // A provider-unverified email is refused.
        p.accept("c5", "sub-5", "unverified@example.com", false);
        assertEquals("email_not_verified", AuthSystem.oauthCallback("statecheck", "c5", newState("statecheck")).get("error"));
        assertEquals(0, countRows("SELECT COUNT(*) FROM users WHERE email = ?", "unverified@example.com"));
    }

    /**
     * A password holding a control character is judged only by the spec's three reasons: a 15+ character one is
     * accepted. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (java bug list: the "invalid_chars" reason is not in
     * the spec). Touches: H2 (creates a user).
     */
    // AUTH-01
    @Test
    public void testControlCharacterIsNotARejectionReason() {
        Map<String, Object> res = AuthSystem.signup("ctrl@example.com", "Strong\tPassword123456", "Ctrl", "1.2.3.42");
        assertEquals(Boolean.TRUE, res.get("success"), String.valueOf(res));
        assertEquals("pending_verification", res.get("status"));
    }

    /* ---------- Helper Methods for Tests ---------- */
    /**
     * The code the fake mailer was handed for this address. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
     * (AUTH-16): it read the plain code from verification_codes, which now holds only code_hash.
     */
    private String extractCodeFromEmail(String email) {
        return CODES.get(email);
    }

    /**
     * Moves a code's expiry into the past. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-16): matches the
     * row by code_hash = SHA-256(code); since spec d270fa3 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP) by
     * code_hash = HMAC-SHA256(TEST_SECRET_KEY, code). Touches: H2.
     */
    private void expireCode(String code) {
        try {
            java.sql.Connection conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:authdb;DB_CLOSE_DELAY=-1");
            java.sql.PreparedStatement ps = conn.prepareStatement(
                    "UPDATE verification_codes SET expires_at = ? WHERE code_hash = ?");
            ps.setTimestamp(1, java.sql.Timestamp.from(java.time.Instant.now().minusSeconds(1)));
            ps.setString(2, hmacHex(code));
            assertEquals(1, ps.executeUpdate());
        } catch (java.sql.SQLException e) {
            throw new AssertionError(e);
        }
    }

    private void enableMfa(String email) {
        try {
            java.sql.Connection conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:authdb;DB_CLOSE_DELAY=-1");
            java.sql.PreparedStatement ps = conn.prepareStatement(
                    "UPDATE users SET mfa_enabled = TRUE, mfa_secret = ? WHERE email = ?");
            String secret = java.util.Base64.getEncoder().encodeToString("secretkey".getBytes());
            ps.setString(1, secret);
            ps.setString(2, email);
            ps.executeUpdate();
        } catch (Exception e) {}
    }

    private String generateTotpForUser(String email) {
        try {
            java.sql.Connection conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:authdb;DB_CLOSE_DELAY=-1");
            java.sql.PreparedStatement ps = conn.prepareStatement(
                    "SELECT mfa_secret FROM users WHERE email = ?");
            ps.setString(1, email);
            java.sql.ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                String secret = rs.getString(1);
                return AuthSystem.generateTotpCode(secret);
            }
        } catch (Exception e) {}
        return "000000";
    }

    private void banUser(String email) {
        try {
            java.sql.Connection conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:authdb;DB_CLOSE_DELAY=-1");
            java.sql.PreparedStatement ps = conn.prepareStatement(
                    "UPDATE users SET status = 'banned' WHERE email = ?");
            ps.setString(1, email);
            ps.executeUpdate();
        } catch (Exception e) {}
    }

    /**
     * One string column of a one-parameter query (null when no row). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
     * (replaces getRefreshTokenBySessionId, which read the plain refresh token the sessions table no longer has).
     * Touches: reads H2.
     */
    private String queryString(String sql, String param) {
        try (java.sql.Connection conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:authdb;DB_CLOSE_DELAY=-1");
             java.sql.PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, param);
            try (java.sql.ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        } catch (java.sql.SQLException e) {
            throw new AssertionError(e);
        }
    }

    /** Column names of a table, upper case (H2). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads H2. */
    private java.util.Set<String> columns(String table) {
        java.util.Set<String> cols = new java.util.HashSet<>();
        try (java.sql.Connection conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:authdb;DB_CLOSE_DELAY=-1");
             java.sql.PreparedStatement ps = conn.prepareStatement(
                     "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ?")) {
            ps.setString(1, table.toUpperCase());
            try (java.sql.ResultSet rs = ps.executeQuery()) {
                while (rs.next()) cols.add(rs.getString(1).toUpperCase());
            }
        } catch (java.sql.SQLException e) {
            throw new AssertionError(e);
        }
        return cols;
    }

    private String createExpiredToken(long userId) {
        try {
            Algorithm alg = Algorithm.HMAC256(TEST_JWT_SECRET);
            return JWT.create()
                    .withClaim("user_id", userId)
                    .withClaim("tier", "basic")
                    .withExpiresAt(java.util.Date.from(java.time.Instant.now().minusSeconds(3600)))
                    .sign(alg);
        } catch (Exception e) {
            return "";
        }
    }

    private String createTokenWithWrongSecret(long userId) {
        try {
            Algorithm alg = Algorithm.HMAC256("wrong_secret");
            return JWT.create()
                    .withClaim("user_id", userId)
                    .withClaim("tier", "basic")
                    .withExpiresAt(java.util.Date.from(java.time.Instant.now().plusSeconds(3600)))
                    .sign(alg);
        } catch (Exception e) {
            return "";
        }
    }
}

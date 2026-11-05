import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class AuthSystemTests {

    @BeforeAll
    public static void setup() {
        // Register dummy OAuth provider
        AuthSystem.OAuthProviderRegistry.register("google", new AuthSystem.DummyOAuthProvider("newuser@example.com"));
    }

    @Test
    public void testSignupHappyPath() {
        Map<String, Object> res = AuthSystem.signup("john@example.com", "StrongPassword123456", "John", "1.2.3.4");
        assertTrue((Boolean)res.get("success"));
        assertEquals("pending_verification", res.get("status"));
    }

    @Test
    public void testSignupDuplicateEmail() {
        AuthSystem.signup("dup@example.com", "StrongPassword123456", "Dup", "1.2.3.4");
        Map<String, Object> res = AuthSystem.signup("dup@example.com", "StrongPassword123456", "Dup2", "1.2.3.5");
        assertFalse((Boolean)res.get("success"));
        assertEquals("email_already_exists", res.get("error"));
    }

    @Test
    public void testSignupWeakPassword() {
        Map<String, Object> res = AuthSystem.signup("weak@example.com", "short", "Weak", "1.2.3.6");
        assertFalse((Boolean)res.get("success"));
        assertEquals("password_rejected", res.get("error"));
        assertEquals("too_short", res.get("message"));
    }

    @Test
    public void testSignupIpRateLimit() {
        for (int i = 0; i < 5; i++) {
            AuthSystem.signup("ipuser" + i + "@example.com", "StrongPassword123456", "IPUser", "192.168.0.1");
        }
        Map<String, Object> res = AuthSystem.signup("ipuser6@example.com", "StrongPassword123456", "IPUser", "192.168.0.1");
        assertFalse((Boolean)res.get("success"));
        assertEquals("too_many_signups_from_ip", res.get("error"));
    }

    @Test
    public void testVerifyEmailHappyPath() {
        Map<String, Object> signup = AuthSystem.signup("verify@example.com", "StrongPassword123456", "Verify", "1.2.3.7");
        String code = extractCodeFromEmail("verify@example.com");
        Map<String, Object> res = AuthSystem.verifyEmail("verify@example.com", code);
        assertTrue((Boolean)res.get("success"));
        assertEquals("verified", res.get("status"));
    }

    @Test
    public void testVerifyEmailExpiredCode() {
        Map<String, Object> signup = AuthSystem.signup("expire@example.com", "StrongPassword123456", "Expire", "1.2.3.8");
        String code = extractCodeFromEmail("expire@example.com");
        // Manually expire
        expireCode(code);
        Map<String, Object> res = AuthSystem.verifyEmail("expire@example.com", code);
        assertFalse((Boolean)res.get("success"));
        assertEquals("code_invalid", res.get("error"));
    }

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

    @Test
    public void testLoginInvalidPassword() {
        Map<String, Object> signup = AuthSystem.signup("badpass@example.com", "StrongPassword123456", "BadPass", "1.2.3.11");
        String code = extractCodeFromEmail("badpass@example.com");
        AuthSystem.verifyEmail("badpass@example.com", code);
        Map<String, Object> res = AuthSystem.login("badpass@example.com", "WrongPassword", "device3", "1.2.3.11");
        assertFalse((Boolean)res.get("success"));
        assertEquals("invalid_credentials", res.get("error"));
    }

    @Test
    public void testOauthCallbackHappyPathNewUser() {
        Map<String, Object> res = AuthSystem.oauthCallback("google", "code123", "state123");
        assertTrue((Boolean)res.get("success"));
        assertEquals("authenticated", res.get("status"));
        assertNotNull(res.get("token"));
    }

    @Test
    public void testOauthCallbackExistingUser() {
        // Register a provider that returns the existing user's email
        AuthSystem.OAuthProviderRegistry.register("google_existing",
                new AuthSystem.DummyOAuthProvider("existing@example.com"));
        AuthSystem.signup("existing@example.com", "StrongPassword123456", "Existing", "1.2.3.12");
        String code = extractCodeFromEmail("existing@example.com");
        AuthSystem.verifyEmail("existing@example.com", code);
        Map<String, Object> res = AuthSystem.oauthCallback("google_existing", "code123", "state123");
        assertTrue((Boolean)res.get("success"));
        assertEquals("authenticated", res.get("status"));
    }

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

    @Test
    public void testTokenRefreshHappyPath() {
        Map<String, Object> signup = AuthSystem.signup("refresh@example.com", "StrongPassword123456", "Refresh", "1.2.3.15");
        String code = extractCodeFromEmail("refresh@example.com");
        AuthSystem.verifyEmail("refresh@example.com", code);
        Map<String, Object> loginRes = AuthSystem.login("refresh@example.com", "StrongPassword123456", "device6", "1.2.3.15");
        String sessionId = (String)loginRes.get("session_id");
        String refreshToken = getRefreshTokenBySessionId(sessionId);
        Map<String, Object> res = AuthSystem.tokenRefresh(refreshToken);
        assertTrue((Boolean)res.get("success"));
        assertEquals("ok", res.get("status"));
        assertNotNull(res.get("token"));
    }

    @Test
    public void testTokenRefreshBannedUser() {
        Map<String, Object> signup = AuthSystem.signup("ban@example.com", "StrongPassword123456", "Ban", "1.2.3.16");
        String code = extractCodeFromEmail("ban@example.com");
        AuthSystem.verifyEmail("ban@example.com", code);
        banUser("ban@example.com");
        Map<String, Object> loginRes = AuthSystem.login("ban@example.com", "StrongPassword123456", "device7", "1.2.3.16");
        String sessionId = (String)loginRes.get("session_id");
        String refreshToken = getRefreshTokenBySessionId(sessionId);
        Map<String, Object> res = AuthSystem.tokenRefresh(refreshToken);
        assertFalse((Boolean)res.get("success"));
        assertEquals("user_banned", res.get("error"));
    }

    @Test
    public void testVerifyAccessTokenValid() {
        Map<String, Object> signup = AuthSystem.signup("verifytoken@example.com", "StrongPassword123456", "VerifyToken", "1.2.3.17");
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
        Map<String, Object> signup = AuthSystem.signup("bantoken@example.com", "StrongPassword123456", "BanToken", "1.2.3.18");
        String code = extractCodeFromEmail("bantoken@example.com");
        AuthSystem.verifyEmail("bantoken@example.com", code);
        banUser("bantoken@example.com");
        Map<String, Object> loginRes = AuthSystem.login("bantoken@example.com", "StrongPassword123456", "device9", "1.2.3.18");
        String token = (String)loginRes.get("token");
        Map<String, Object> res = AuthSystem.verifyAccessToken(token);
        assertFalse((Boolean)res.get("success"));
        assertEquals("user_banned", res.get("error"));
    }

    @Test
    public void testPasswordBlocklistRejection() {
        // Test common password rejection
        Map<String, Object> res = AuthSystem.signup("block1@example.com", "password123456", "Block1", "1.2.3.19");
        assertFalse((Boolean)res.get("success"));
        assertEquals("password_rejected", res.get("error"));
        assertEquals("blocklisted", res.get("message"));

        // Test email as password rejection
        res = AuthSystem.signup("block2@example.com", "block2@example.com", "Block2", "1.2.3.20");
        assertFalse((Boolean)res.get("success"));
        assertEquals("password_rejected", res.get("error"));
        assertEquals("blocklisted", res.get("message"));

        // Test name as password rejection
        res = AuthSystem.signup("block3@example.com", "Block3", "Block3", "1.2.3.21");
        assertFalse((Boolean)res.get("success"));
        assertEquals("password_rejected", res.get("error"));
        assertEquals("blocklisted", res.get("message"));

        // Test service name as password rejection
        res = AuthSystem.signup("block4@example.com", "auth_system", "Block4", "1.2.3.22");
        assertFalse((Boolean)res.get("success"));
        assertEquals("password_rejected", res.get("error"));
        assertEquals("blocklisted", res.get("message"));
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
    }

    @Test
    public void testLoginRateLimit() {
        Map<String, Object> signup = AuthSystem.signup("ratelimit@example.com", "StrongPassword123456", "RateLimit", "1.2.3.25");
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
    }

    /* ---------- Helper Methods for Tests ---------- */
    private String extractCodeFromEmail(String email) {
        // In real scenario, capture from email; here we query DB
        try {
            java.sql.Connection conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:authdb;DB_CLOSE_DELAY=-1");
            java.sql.PreparedStatement ps = conn.prepareStatement(
                    "SELECT code FROM verification_codes WHERE user_id = (SELECT id FROM users WHERE email = ?) AND type='email'");
            ps.setString(1, email);
            java.sql.ResultSet rs = ps.executeQuery();
            if (rs.next()) return rs.getString(1);
        } catch (Exception e) {}
        return null;
    }

    private void expireCode(String code) {
        try {
            java.sql.Connection conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:authdb;DB_CLOSE_DELAY=-1");
            java.sql.PreparedStatement ps = conn.prepareStatement(
                    "UPDATE verification_codes SET expires_at = ? WHERE code = ?");
            ps.setTimestamp(1, java.sql.Timestamp.from(java.time.Instant.now().minusSeconds(1)));
            ps.setString(2, code);
            ps.executeUpdate();
        } catch (Exception e) {}
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

    private String getRefreshTokenBySessionId(String sessionId) {
        try {
            java.sql.Connection conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:authdb;DB_CLOSE_DELAY=-1");
            java.sql.PreparedStatement ps = conn.prepareStatement(
                    "SELECT refresh_token FROM sessions WHERE id = ?");
            ps.setString(1, sessionId);
            java.sql.ResultSet rs = ps.executeQuery();
            if (rs.next()) return rs.getString(1);
        } catch (Exception e) {}
        return null;
    }

    private String createExpiredToken(long userId) {
        try {
            Algorithm alg = Algorithm.HMAC256("secret");
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

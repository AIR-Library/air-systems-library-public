import java.sql.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import org.mindrot.jbcrypt.BCrypt;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;

/**
 * Auth System Implementation
 */
public class AuthSystem {

    /* ---------- Database ---------- */
    private static final String DB_URL = "jdbc:h2:mem:authdb;DB_CLOSE_DELAY=-1";
    private static final Connection conn;

    static {
        try {
            conn = DriverManager.getConnection(DB_URL);
            runMigrations();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    private static void runMigrations() throws SQLException {
        String users = "CREATE TABLE IF NOT EXISTS users (" +
                "id IDENTITY PRIMARY KEY, email VARCHAR(255) UNIQUE, password_hash VARCHAR(255), " +
                "tier VARCHAR(50) DEFAULT 'basic', status VARCHAR(20), email_verified_at TIMESTAMP, " +
                "mfa_secret VARCHAR(255), mfa_enabled BOOLEAN DEFAULT FALSE, name VARCHAR(255))";
        String sessions = "CREATE TABLE IF NOT EXISTS sessions (" +
                "id VARCHAR(255) PRIMARY KEY, user_id BIGINT, refresh_token VARCHAR(255), " +
                "created_at TIMESTAMP, expires_at TIMESTAMP, ip VARCHAR(45), device_id VARCHAR(255))";
        String audit = "CREATE TABLE IF NOT EXISTS audit_log (" +
                "timestamp TIMESTAMP, actor_id BIGINT, action VARCHAR(255), resource_type VARCHAR(50), " +
                "resource_id VARCHAR(255), old_value VARCHAR(255), new_value VARCHAR(255))";
        String verCodes = "CREATE TABLE IF NOT EXISTS verification_codes (" +
                "id IDENTITY PRIMARY KEY, user_id BIGINT, code VARCHAR(255), created_at TIMESTAMP, " +
                "expires_at TIMESTAMP, type VARCHAR(10))";
        String oauthLinks = "CREATE TABLE IF NOT EXISTS oauth_links (" +
                "id IDENTITY PRIMARY KEY, user_id BIGINT, provider VARCHAR(50), provider_user_id VARCHAR(255))";

        try (Statement st = conn.createStatement()) {
            st.execute(users);
            st.execute(sessions);
            st.execute(audit);
            st.execute(verCodes);
            st.execute(oauthLinks);
        }
    }

    /* ---------- Utilities ---------- */
    private static final SecureRandom random = new SecureRandom();
    private static final DateTimeFormatter iso = DateTimeFormatter.ISO_INSTANT;
    private static final ObjectMapper mapper = new ObjectMapper();
    /**
     * JWT signing key. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec rule "No secret is hard-coded"): it was
     * the literal "secret", so anyone could mint tokens. It comes from AUTH_JWT_SECRET (environment, or system property for
     * tests), which must be at least 32 bytes; without one a random 32-byte key is generated per process (tokens then
     * stop working on restart, which fails safe). Touches: reads the environment.
     */
    private static final Algorithm jwtAlg = Algorithm.HMAC256(jwtSecret());

    private static byte[] jwtSecret() {
        String configured = System.getProperty("AUTH_JWT_SECRET", System.getenv("AUTH_JWT_SECRET"));
        if (configured != null && !configured.isEmpty()) {
            byte[] bytes = configured.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            if (bytes.length < 32) {
                throw new IllegalStateException("AUTH_JWT_SECRET must be at least 32 bytes");
            }
            return bytes;
        }
        byte[] generated = new byte[32];
        new SecureRandom().nextBytes(generated);
        return generated;
    }

    /**
     * Where verification codes go. The default sends nothing and never prints the code (it is a secret).
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: sendEmail printed every code to stdout (spec rule
     * "No secret is ... written to a log"). Replace with a real mailer; tests may install a fake. Touches: email.
     */
    public interface EmailSender {
        void sendVerificationCode(String email, String code);
    }

    private static volatile EmailSender emailSender = (email, code) -> { };

    /** Installs the email sender (a fake in tests). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing else. */
    public static void setEmailSender(EmailSender sender) {
        emailSender = Objects.requireNonNull(sender);
    }
    private static final int TOTP_TIME_STEP = 30;
    private static final int TOTP_DIGITS = 6;

    private static final Set<String> commonPasswords = Set.of(
            "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567",
            "1234567890", "abc123", "password123", "password123456", "admin", "letmein", "welcome", "monkey", "dragon",
            "master", "hello", "freedom", "whatever", "qazwsx", "trustno1", "654321", "jordan23",
            "harley", "password1", "123123", "superman", "iloveyou", "sunshine", "princess", "football",
            "baseball", "shadow", "michael", "ninja", "mustang", "jennifer", "hunter", "2000", "tigger",
            // 15+ characters: with length checked first (AUTH-03, 2026-11-10), only these can still be "blocklisted".
            "123456789012345", "1234567890123456", "passwordpassword", "password1234567", "qwertyuiopasdfgh",
            "qwertyuiopasdfghjkl", "iloveyouiloveyou", "trustno1trustno1", "aaaaaaaaaaaaaaa", "letmeinletmein1"
    );

    /* ---------- Rate Limiter ---------- */
    private static final ConcurrentHashMap<String, List<Instant>> signupAttempts = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, List<Instant>> loginAttempts = new ConcurrentHashMap<>();

    private static void recordAttempt(ConcurrentHashMap<String, List<Instant>> map, String key, Duration window) {
        Instant now = Instant.now();
        map.compute(key, (k, list) -> {
            if (list == null) list = new ArrayList<>();
            list.removeIf(t -> t.isBefore(now.minus(window)));
            list.add(now);
            return list;
        });
    }

    private static boolean isRateLimited(ConcurrentHashMap<String, List<Instant>> map, String key, int max, Duration window) {
        // Only attempts inside the window count. Pruning here as well matters: a blocked caller never records the attempt
        // that used to prune the list, so the block lasted forever (2026-11-08, session f3daac6e, from review of PR 17).
        Instant cutoff = Instant.now().minus(window);
        List<Instant> list = map.computeIfPresent(key, (k, v) -> {
            v.removeIf(t -> t.isBefore(cutoff));
            return v;
        });
        return list != null && list.size() >= max;
    }

    /* ---------- TOTP Implementation (RFC 6238) ---------- */
    private static int generateTotp(byte[] key, Instant time, int timeStep, int digits) {
        long counter = time.getEpochSecond() / timeStep;
        byte[] counterBytes = new byte[8];
        for (int i = 7; i >= 0; i--) {
            counterBytes[i] = (byte)(counter & 0xFF);
            counter >>= 8;
        }

        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(counterBytes);

            int offset = hash[hash.length - 1] & 0xF;
            int binary = ((hash[offset] & 0x7F) << 24) |
                         ((hash[offset + 1] & 0xFF) << 16) |
                         ((hash[offset + 2] & 0xFF) << 8) |
                         (hash[offset + 3] & 0xFF);

            int otp = binary % (int)Math.pow(10, digits);
            return otp;
        } catch (Exception e) {
            throw new RuntimeException("TOTP generation failed", e);
        }
    }

    private static boolean verifyTotp(byte[] key, String code, Instant time) {
        int expected = generateTotp(key, time, TOTP_TIME_STEP, TOTP_DIGITS);
        String expectedStr = String.format("%0" + TOTP_DIGITS + "d", expected);
        return MessageDigest.isEqual(expectedStr.getBytes(StandardCharsets.US_ASCII), code.getBytes(StandardCharsets.US_ASCII));
    }

    public static boolean verifyTotp(String secret, String code) {
        try {
            byte[] key = Base64.getDecoder().decode(secret);
            return verifyTotp(key, code, Instant.now());
        } catch (Exception e) {
            return false;
        }
    }

    public static String generateTotpCode(String secret) {
        try {
            byte[] key = Base64.getDecoder().decode(secret);
            int totp = generateTotp(key, Instant.now(), TOTP_TIME_STEP, TOTP_DIGITS);
            return String.format("%0" + TOTP_DIGITS + "d", totp);
        } catch (Exception e) {
            throw new RuntimeException("TOTP generation failed", e);
        }
    }

    /* ---------- Auth Service ---------- */
    public static Map<String, Object> signup(String email, String password, String name, String ip) {
        List<String> decisions = new ArrayList<>();
        try {
            // Rate limit
            if (isRateLimited(signupAttempts, ip, 5, Duration.ofHours(24))) {
                decisions.add("rate_limit_ip_24h");
                return error("too_many_signups_from_ip", "Rate limit exceeded");
            }
            recordAttempt(signupAttempts, ip, Duration.ofHours(24));

            // Email unique
            if (userExists(email)) {
                decisions.add("email_unique");
                return error("email_already_exists", "Email already registered");
            }

            // Password strength
            String pwReason = passwordStrengthCheck(password, email, name);
            if (pwReason != null) {
                decisions.add("password_strength");
                Map<String, Object> rejected = error("password_rejected", pwReason);
                rejected.put("reason", pwReason);   // AUTH-03: {error: "password_rejected", reason}
                return rejected;
            }

            // Create user
            String hash = BCrypt.hashpw(password, BCrypt.gensalt());
            long userId = insertUser(email, hash, name);
            decisions.add("user_created");

            // Send verification email
            String code = generateCode();
            insertVerificationCode(userId, code, "email");
            sendEmail(email, code);

            logWhy("signup", decisions);
            auditLog(userId, "user_created", "users", String.valueOf(userId), null, null);
            return success(Map.of(
                    "status", "pending_verification",
                    "email", email,
                    "message", "check email"
            ));
        } catch (Exception e) {
            return error("internal_error", e.getMessage());
        }
    }

    public static Map<String, Object> verifyEmail(String email, String code) {
        List<String> decisions = new ArrayList<>();
        try {
            Long userId = getUserIdByEmail(email);
            if (userId == null) return error("invalid_email", "Email not found");
            decisions.add("user_exists");

            // AUTH-06 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): an expired code is "code_expired", not
            // "code_invalid" as before; the expired row is deleted so it can never be used.
            VerificationCode any = getVerificationCodeIgnoringExpiry(userId, code, "email");
            if (any != null && Instant.now().isAfter(any.expiresAt)) {
                deleteVerificationCode(any.id);
                decisions.add("code_valid");
                return error("code_expired", "Code expired");
            }
            VerificationCode vc = any;
            if (vc == null) {
                decisions.add("code_invalid");
                return error("code_invalid", "Invalid code");
            }
            decisions.add("code_valid");

            // Mark verified
            updateEmailVerifiedAt(userId);
            deleteVerificationCode(vc.id);
            decisions.add("email_verified");

            logWhy("verify_email", decisions);
            auditLog(userId, "email_verified", "users", String.valueOf(userId), null, null);
            return success(Map.of(
                    "status", "verified",
                    "user_id", userId,
                    "message", "ready to login"
            ));
        } catch (Exception e) {
            return error("internal_error", e.getMessage());
        }
    }

    public static Map<String, Object> login(String email, String password, String deviceId, String ip) {
        List<String> decisions = new ArrayList<>();
        try {
            Long userId = getUserIdByEmail(email);
            if (userId == null) {
                decisions.add("user_exists");
                return error("invalid_credentials", "Invalid credentials");
            }
            decisions.add("user_exists");

            if (!isEmailVerified(userId)) {
                decisions.add("user_verified");
                return error("email_not_verified", "Email not verified");
            }

            // The limit is checked before the password: checked only after a wrong one, it never stopped the right guess
            // (2026-11-08, session f3daac6e, from review).
            if (isRateLimited(loginAttempts, ip + ":" + userId, 5, Duration.ofMinutes(15))) {
                decisions.add("rate_limit");
                return error("too_many_attempts", "Too many failed attempts");
            }
            if (!checkPassword(userId, password)) {
                decisions.add("password_correct");
                recordAttempt(loginAttempts, ip + ":" + userId, Duration.ofMinutes(15));
                return error("invalid_credentials", "Invalid credentials");
            }
            decisions.add("password_correct");

            // MFA check
            if (isMfaEnabled(userId)) {
                decisions.add("mfa_gate");
                String challengeId = generateCode();
                insertVerificationCode(userId, challengeId, "mfa");
                return success(Map.of(
                        "status", "mfa_required",
                        "challenge_id", challengeId
                ));
            }

            // Create session
            return createSessionAndToken(userId, email, ip, deviceId, decisions, "login", "session_created");
        } catch (Exception e) {
            return error("internal_error", e.getMessage());
        }
    }

    public static Map<String, Object> oauthCallback(String provider, String code, String state) {
        List<String> decisions = new ArrayList<>();
        try {
            // Validate state (simplified)
            if (state == null || state.isEmpty()) {
                decisions.add("state_valid");
                return error("invalid_state", "State invalid");
            }
            decisions.add("state_valid");

            // Simulate provider email extraction
            String email = OAuthProviderRegistry.get(provider).getEmail(code);
            if (email == null) {
                decisions.add("email_verified");
                return error("email_not_verified", "Provider email not verified");
            }
            decisions.add("email_verified");

            Long userId = getUserIdByEmail(email);
            if (userId == null) {
                // New user
                String hash = BCrypt.hashpw(generateRandomPassword(), BCrypt.gensalt());
                userId = insertUser(email, hash, null);
                decisions.add("user_created");
                // Mark verified
                updateEmailVerifiedAt(userId);
            } else {
                decisions.add("user_exists");
            }

            // Link provider
            linkOAuth(userId, provider, code);
            decisions.add("oauth_linked");

            // Create session
            return createSessionAndToken(userId, email, null, null, decisions, "oauth_callback", "oauth_login");
        } catch (Exception e) {
            return error("internal_error", e.getMessage());
        }
    }

    public static Map<String, Object> mfaChallenge(String challengeId, String code) {
        List<String> decisions = new ArrayList<>();
        try {
            VerificationCode vc = getVerificationCodeByCode(challengeId, "mfa");
            if (vc == null) {
                decisions.add("challenge_valid");
                return error("invalid_code", "Challenge not found or expired");
            }
            decisions.add("challenge_valid");

            Long userId = vc.userId;
            String secret = getMfaSecret(userId);
            if (secret == null) {
                decisions.add("code_correct");
                return error("invalid_code", "MFA not enabled");
            }

            if (!verifyTotp(secret, code)) {
                decisions.add("code_correct");
                return error("invalid_code", "Invalid MFA code");
            }
            decisions.add("code_correct");

            // Mark challenge verified
            deleteVerificationCode(vc.id);
            decisions.add("challenge_verified");

            // Create session
            return createSessionAndToken(userId, getEmail(userId), null, null, decisions, "mfa_challenge", "mfa_verified");
        } catch (Exception e) {
            return error("internal_error", e.getMessage());
        }
    }

    public static Map<String, Object> tokenRefresh(String refreshToken) {
        List<String> decisions = new ArrayList<>();
        try {
            Session session = getSessionByRefreshToken(refreshToken);
            if (session == null) {
                decisions.add("token_valid");
                return error("invalid_token", "Refresh token invalid");
            }
            decisions.add("token_valid");

            if (Instant.now().isAfter(session.expiresAt)) {
                decisions.add("token_expired");
                return error("token_expired", "Refresh token expired");
            }

            Long userId = session.userId;
            if (isUserBanned(userId)) {
                decisions.add("user_active");
                return error("user_banned", "User is banned");
            }
            decisions.add("user_active");

            // Issue new token
            String token = JWT.create()
                    .withClaim("user_id", userId)
                    .withClaim("tier", getTier(userId))
                    .withExpiresAt(java.util.Date.from(Instant.now().plus(Duration.ofHours(1))))
                    .sign(jwtAlg);

            decisions.add("token_issued");
            logWhy("token_refresh", decisions);
            auditLog(userId, "token_refreshed", "sessions", session.id, null, null);
            return success(Map.of(
                    "status", "ok",
                    "token", token,
                    "expires_in", 3600
            ));
        } catch (Exception e) {
            return error("internal_error", e.getMessage());
        }
    }

    public static Map<String, Object> verifyAccessToken(String token) {
        List<String> decisions = new ArrayList<>();
        try {
            // java-jwt checks the signature before the expiry, so only a genuine token can report that it expired.
            DecodedJWT jwt = JWT.require(jwtAlg).build().verify(token);
            decisions.add("signature_valid");
            decisions.add("not_expired");

            Long userId = jwt.getClaim("user_id").asLong();
            if (userId == null) {
                return error("invalid_token", "Token missing user_id");
            }

            if (isUserBanned(userId)) {
                decisions.add("user_active");
                return error("user_banned", "User is banned");
            }
            decisions.add("user_active");

            logWhy("verify_access_token", decisions);
            return success(Map.of(
                    "status", "ok",
                    "user", Map.of(
                            "id", userId,
                            "email", getEmail(userId),
                            "tier", getTier(userId)
                    )
            ));
        } catch (TokenExpiredException e) {
            return error("token_expired", "Token has expired");
        } catch (JWTVerificationException e) {
            return error("invalid_token", "Invalid token signature");
        } catch (Exception e) {
            return error("internal_error", e.getMessage());
        }
    }

    private static Map<String, Object> createSessionAndToken(long userId, String email, String ip, String deviceId,
            List<String> decisions, String flow, String auditAction) throws SQLException {
        String sessionId = UUID.randomUUID().toString();
        String refreshToken = UUID.randomUUID().toString();
        Instant now = Instant.now();
        Instant exp = now.plus(Duration.ofHours(1));
        insertSession(sessionId, userId, refreshToken, now, exp, ip, deviceId);
        decisions.add("session_created");

        String token = JWT.create()
                .withClaim("user_id", userId)
                .withClaim("tier", getTier(userId))
                .withExpiresAt(java.util.Date.from(exp))
                .sign(jwtAlg);

        logWhy(flow, decisions);
        auditLog(userId, auditAction, "sessions", sessionId, null, null);
        return success(Map.of(
                "status", "authenticated",
                "session_id", sessionId,
                "token", token,
                "expires_in", exp.getEpochSecond() - now.getEpochSecond(),
                "user", Map.of(
                        "id", userId,
                        "email", email,
                        "tier", getTier(userId)
                )
        ));
    }

    /* ---------- Helper Methods ---------- */
    private static boolean userExists(String email) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT id FROM users WHERE email = ?")) {
            ps.setString(1, email);
            ResultSet rs = ps.executeQuery();
            return rs.next();
        }
    }

    private static long insertUser(String email, String hash, String name) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO users (email, password_hash, tier, status, name) VALUES (?, ?, 'basic', 'unverified', ?)",
                Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, email);
            ps.setString(2, hash);
            ps.setString(3, name);
            ps.executeUpdate();
            ResultSet rs = ps.getGeneratedKeys();
            rs.next();
            return rs.getLong(1);
        }
    }

    private static Long getUserIdByEmail(String email) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT id FROM users WHERE email = ?")) {
            ps.setString(1, email);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) return rs.getLong(1);
            return null;
        }
    }

    private static String getEmail(long userId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT email FROM users WHERE id = ?")) {
            ps.setLong(1, userId);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) return rs.getString(1);
            return null;
        }
    }

    private static String getTier(long userId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT tier FROM users WHERE id = ?")) {
            ps.setLong(1, userId);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) return rs.getString(1);
            return "basic";
        }
    }

    private static boolean isEmailVerified(long userId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT email_verified_at FROM users WHERE id = ?")) {
            ps.setLong(1, userId);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) return rs.getTimestamp(1) != null;
            return false;
        }
    }

    private static void updateEmailVerifiedAt(long userId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("UPDATE users SET email_verified_at = ? WHERE id = ?")) {
            ps.setTimestamp(1, java.sql.Timestamp.from(Instant.now()));
            ps.setLong(2, userId);
            ps.executeUpdate();
        }
    }

    private static boolean checkPassword(long userId, String password) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT password_hash FROM users WHERE id = ?")) {
            ps.setLong(1, userId);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                String hash = rs.getString(1);
                return BCrypt.checkpw(password, hash);
            }
            return false;
        }
    }

    private static boolean isMfaEnabled(long userId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT mfa_enabled FROM users WHERE id = ?")) {
            ps.setLong(1, userId);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) return rs.getBoolean(1);
            return false;
        }
    }

    private static String getMfaSecret(long userId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT mfa_secret FROM users WHERE id = ?")) {
            ps.setLong(1, userId);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) return rs.getString(1);
            return null;
        }
    }

    private static void insertSession(String sessionId, long userId, String refreshToken,
                                      Instant createdAt, Instant expiresAt, String ip, String deviceId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO sessions (id, user_id, refresh_token, created_at, expires_at, ip, device_id) VALUES (?, ?, ?, ?, ?, ?, ?)")) {
            ps.setString(1, sessionId);
            ps.setLong(2, userId);
            ps.setString(3, refreshToken);
            ps.setTimestamp(4, java.sql.Timestamp.from(createdAt));
            ps.setTimestamp(5, java.sql.Timestamp.from(expiresAt));
            ps.setString(6, ip);
            ps.setString(7, deviceId);
            ps.executeUpdate();
        }
    }

    private static Session getSessionByRefreshToken(String refreshToken) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id, user_id, created_at, expires_at, ip, device_id FROM sessions WHERE refresh_token = ?")) {
            ps.setString(1, refreshToken);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                return new Session(
                        rs.getString(1),
                        rs.getLong(2),
                        rs.getTimestamp(3).toInstant(),
                        rs.getTimestamp(4).toInstant(),
                        rs.getString(5),
                        rs.getString(6)
                );
            }
            return null;
        }
    }

    private static boolean isUserBanned(long userId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT status FROM users WHERE id = ?")) {
            ps.setLong(1, userId);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                String status = rs.getString(1);
                return status != null && (status.equals("suspended") || status.equals("banned"));
            }
            return false;
        }
    }

    private static void linkOAuth(long userId, String provider, String providerUserId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO oauth_links (user_id, provider, provider_user_id) VALUES (?, ?, ?)")) {
            ps.setLong(1, userId);
            ps.setString(2, provider);
            ps.setString(3, providerUserId);
            ps.executeUpdate();
        }
    }

    private static String generateCode() {
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static void insertVerificationCode(long userId, String code, String type) throws SQLException {
        Instant now = Instant.now();
        Instant exp = now.plus(Duration.ofHours(24));
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO verification_codes (user_id, code, created_at, expires_at, type) VALUES (?, ?, ?, ?, ?)")) {
            ps.setLong(1, userId);
            ps.setString(2, code);
            ps.setTimestamp(3, java.sql.Timestamp.from(now));
            ps.setTimestamp(4, java.sql.Timestamp.from(exp));
            ps.setString(5, type);
            ps.executeUpdate();
        }
    }

    /**
     * The user's code row of that type matching code, expired or not (null if none). In: user id, code, type.
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP so verify_email can answer code_expired (AUTH-06).
     * Touches: reads the database.
     */
    private static VerificationCode getVerificationCodeIgnoringExpiry(long userId, String code, String type) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id, user_id, code, created_at, expires_at, type FROM verification_codes WHERE user_id = ? AND code = ? AND type = ?")) {
            ps.setLong(1, userId);
            ps.setString(2, code);
            ps.setString(3, type);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                return new VerificationCode(rs.getLong(1), rs.getLong(2), rs.getString(3),
                        rs.getTimestamp(4).toInstant(), rs.getTimestamp(5).toInstant(), rs.getString(6));
            }
            return null;
        }
    }

    private static VerificationCode getVerificationCode(long userId, String code, String type) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id, user_id, code, created_at, expires_at, type FROM verification_codes WHERE user_id = ? AND code = ? AND type = ?")) {
            ps.setLong(1, userId);
            ps.setString(2, code);
            ps.setString(3, type);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                VerificationCode vc = new VerificationCode(
                        rs.getLong(1),
                        rs.getLong(2),
                        rs.getString(3),
                        rs.getTimestamp(4).toInstant(),
                        rs.getTimestamp(5).toInstant(),
                        rs.getString(6)
                );
                if (Instant.now().isAfter(vc.expiresAt)) return null;
                return vc;
            }
            return null;
        }
    }

    private static VerificationCode getVerificationCodeByCode(String code, String type) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id, user_id, code, created_at, expires_at, type FROM verification_codes WHERE code = ? AND type = ?")) {
            ps.setString(1, code);
            ps.setString(2, type);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                VerificationCode vc = new VerificationCode(
                        rs.getLong(1),
                        rs.getLong(2),
                        rs.getString(3),
                        rs.getTimestamp(4).toInstant(),
                        rs.getTimestamp(5).toInstant(),
                        rs.getString(6)
                );
                if (Instant.now().isAfter(vc.expiresAt)) return null;
                return vc;
            }
            return null;
        }
    }

    private static void deleteVerificationCode(long id) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("DELETE FROM verification_codes WHERE id = ?")) {
            ps.setLong(1, id);
            ps.executeUpdate();
        }
    }

    /**
     * NIST SP 800-63B-4 password check. In: password, the user's email and name. Out: null when accepted, else the
     * reason "too_short" (< 15 characters), "too_long" (> 64) or "blocklisted" (common value, the user's email or name,
     * or the service name), checked IN THAT ORDER, first failure wins ("password123" is too_short).
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-03 amendment): length now comes before the blocklist,
     * length counts Unicode characters (code points), not UTF-16 units, and the blocklist has 15+ character entries.
     * Touches: nothing.
     */
    private static String passwordStrengthCheck(String password, String email, String name) {
        if (password == null) return "too_short";
        int length = password.codePointCount(0, password.length());
        if (length < 15) return "too_short";
        if (length > 64) return "too_long";

        String lower = password.toLowerCase(Locale.ROOT);
        if (commonPasswords.contains(lower)) return "blocklisted";
        if (password.equalsIgnoreCase(email) || password.equalsIgnoreCase(name) || password.equalsIgnoreCase("auth_system"))
            return "blocklisted";

        // Allow all printable ASCII, spaces, and Unicode - just reject control characters
        if (password.codePoints().anyMatch(c -> Character.isISOControl(c))) return "invalid_chars";

        return null;
    }

    /** Hands the code to the configured EmailSender; never logs it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: email. */
    private static void sendEmail(String email, String code) {
        emailSender.sendVerificationCode(email, code);
    }

    private static void logWhy(String flow, List<String> decisions) {
        System.out.println("why_chain(flow=\"" + flow + "\", decision_points=" + decisions + ")");
    }

    private static void auditLog(Long actorId, String action, String resourceType, String resourceId,
                                 String oldValue, String newValue) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO audit_log (timestamp, actor_id, action, resource_type, resource_id, old_value, new_value) VALUES (?, ?, ?, ?, ?, ?, ?)")) {
            ps.setTimestamp(1, java.sql.Timestamp.from(Instant.now()));
            ps.setObject(2, actorId);
            ps.setString(3, action);
            ps.setString(4, resourceType);
            ps.setString(5, resourceId);
            ps.setString(6, oldValue);
            ps.setString(7, newValue);
            ps.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static Map<String, Object> success(Map<String, Object> data) {
        Map<String, Object> res = new HashMap<>();
        res.put("success", true);
        res.putAll(data);
        return res;
    }

    private static Map<String, Object> error(String code, String message) {
        Map<String, Object> res = new HashMap<>();
        res.put("success", false);
        res.put("error", code);
        res.put("message", message);
        return res;
    }

    private static String generateRandomPassword() {
        return "P@ssw0rd" + random.nextInt(1000);
    }

    /* ---------- Inner Classes ---------- */
    private static class VerificationCode {
        long id;
        long userId;
        String code;
        Instant createdAt;
        Instant expiresAt;
        String type;
        VerificationCode(long id, long userId, String code, Instant createdAt, Instant expiresAt, String type) {
            this.id = id; this.userId = userId; this.code = code; this.createdAt = createdAt; this.expiresAt = expiresAt; this.type = type;
        }
    }

    private static class Session {
        String id;
        long userId;
        Instant createdAt;
        Instant expiresAt;
        String ip;
        String deviceId;
        Session(String id, long userId, Instant createdAt, Instant expiresAt, String ip, String deviceId) {
            this.id = id; this.userId = userId; this.createdAt = createdAt; this.expiresAt = expiresAt; this.ip = ip; this.deviceId = deviceId;
        }
    }

    /* ---------- OAuth Provider Registry ---------- */
    public interface OAuthProvider {
        String getEmail(String code);
    }

    public static class DummyOAuthProvider implements OAuthProvider {
        private final String email;
        DummyOAuthProvider(String email) { this.email = email; }
        public String getEmail(String code) { return email; }
    }

    public static class OAuthProviderRegistry {
        private static final Map<String, OAuthProvider> providers = new HashMap<>();
        public static void register(String name, OAuthProvider provider) { providers.put(name, provider); }
        public static OAuthProvider get(String name) { return providers.get(name); }
    }

    /* ---------- Main for demonstration (optional) ---------- */
    public static void main(String[] args) throws Exception {
        OAuthProviderRegistry.register("google", new DummyOAuthProvider("user@example.com"));
        System.out.println(mapToJson(signup("user@example.com", "StrongPassword123456", "Alice", "127.0.0.1")));
        // Further demo omitted
    }

    private static String mapToJson(Map<String, Object> map) throws Exception {
        return mapper.writeValueAsString(map);
    }
}

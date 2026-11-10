import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.IntFunction;
import java.util.function.LongSupplier;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * TOTP two-factor sign-in (spec docs/specs/totp_two_factor.md): enroll an authenticator app, verify 6-digit codes
 * with one step of drift each way, never accept a code twice, lock after repeated wrong codes, a hard lock after 100
 * failures in a row, and one-time recovery codes. Secrets are sealed with AES-256-GCM; recovery codes are stored only
 * as HMAC-SHA256 under their own key.
 *
 * In: the verified caller's user id and the code they typed. Out: a result map with "status" (and "error" for a
 * refusal); never an unhandled exception for a caller's input.
 * Why: Phase D wave 1, owner request 2026-11-10 (TOTP-01 to TOTP-14). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the injected Store (database in production, memory in tests); no network, no files, no money. Never logs
 * or returns a secret, a code or a key except the secret in enroll_start's answer and the codes in enroll_confirm's.
 */
public final class TotpTwoFactor {
    public static final int STEP = 30;
    public static final int DIGITS = 6;
    public static final int LOCK_FAILURES = 5;
    public static final int LOCK_SECONDS = 900;
    public static final int HARD_LOCK_FAILURES = 100;
    public static final int RECOVERY_CODES = 8;
    public static final String RECOVERY_ALPHABET = "23456789abcdefghjkmnpqrstvwxyz";
    private static final String B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /**
     * Construction failure (fail closed). code is "invalid_key". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: nothing.
     */
    public static final class ConfigException extends RuntimeException {
        public final String code;

        /** In: the code. Out: the exception; its message is the code, never a key. */
        public ConfigException(String code) {
            super(code);
            this.code = code;
        }
    }

    /** base32_decode's refusal: "invalid_base32". */
    public static final class InvalidBase32Exception extends IllegalArgumentException {
        /** Out: the exception with the message invalid_base32. */
        public InvalidBase32Exception() {
            super("invalid_base32");
        }
    }

    /** A totp_enrollments row. confirmedAt is null until enroll_confirm. */
    public record Enrollment(String userId, String secretEnc, Long confirmedAt, long lastUsedStep,
                             int failedSinceSuccess, long createdAt) {}

    /** A totp_recovery_codes row. usedAt is null until it signs in. */
    public record RecoveryCode(String userId, String codeHash, long createdAt, Long usedAt) {}

    /**
     * Storage for the three tables. Every write that decides something is ONE conditional write, so parallel calls
     * cannot both win (CLAIM, TRY, confirm, recovery use). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (memory in tests).
     */
    public interface Store {
        /** The user's enrollment row, or null. Touches: reads the database. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        Enrollment getEnrollment(String userId);

        /** Writes an unconfirmed row, replacing an unconfirmed one. False (nothing written) when a confirmed row exists. */
        boolean putUnconfirmed(Enrollment e);

        /** UPDATE ... SET confirmed_at, last_used_step, failed_since_success = 0 WHERE confirmed_at IS NULL AND secret_enc = read. */
        boolean confirm(String userId, long now, long step, String secretEncRead);

        /** CLAIM: UPDATE ... SET last_used_step = step, failed_since_success = 0 WHERE confirmed AND last_used_step < step. */
        boolean claim(String userId, long step);

        /** failed_since_success = failed_since_success + 1. */
        void addFailure(String userId);

        /** failed_since_success = 0. */
        void resetFailures(String userId);

        /** TRY: insert (user_id, now) when fewer than 5 rows have at > now - 900. The new row's id, or -1 (locked). */
        long tryInsert(String userId, long now);

        /** Deletes one totp_failures row by id. */
        void deleteFailure(long id);

        /** The `at` of the user's totp_failures rows with at > since, newest first. */
        List<Long> failuresAfter(String userId, long since);

        /** Inserts recovery code hashes. */
        void addRecoveryCodes(String userId, List<String> hashes, long now);

        /** UPDATE ... SET used_at = now WHERE user_id AND code_hash AND used_at IS NULL. True when one row changed. */
        boolean useRecoveryCode(String userId, String codeHash, long now);

        /** The user's recovery codes with used_at IS NULL. */
        int unusedRecoveryCodes(String userId);

        /** Every recovery code row of the user (for inspection). */
        List<RecoveryCode> recoveryCodes(String userId);

        /** Deletes the user's enrollment, recovery codes and failures. */
        void deleteAll(String userId);
    }

    /**
     * In-memory Store: every method is synchronized, so each conditional write is atomic. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    public static final class InMemoryStore implements Store {
        private final Map<String, Enrollment> enrollments = new LinkedHashMap<>();
        private final List<RecoveryCode> codes = new ArrayList<>();
        private final Map<Long, long[]> failures = new LinkedHashMap<>();
        private final Map<Long, String> failureUser = new LinkedHashMap<>();
        private long nextFailureId = 1;

        @Override
        public synchronized Enrollment getEnrollment(String userId) {
            return enrollments.get(userId);
        }

        /** Test hook: replaces a row as it is (to damage secret_enc). */
        public synchronized void overwrite(Enrollment e) {
            enrollments.put(e.userId(), e);
        }

        @Override
        public synchronized boolean putUnconfirmed(Enrollment e) {
            Enrollment old = enrollments.get(e.userId());
            if (old != null && old.confirmedAt() != null) return false;
            enrollments.put(e.userId(), e);
            return true;
        }

        @Override
        public synchronized boolean confirm(String userId, long now, long step, String secretEncRead) {
            Enrollment e = enrollments.get(userId);
            if (e == null || e.confirmedAt() != null || !e.secretEnc().equals(secretEncRead)) return false;
            enrollments.put(userId, new Enrollment(userId, e.secretEnc(), now, step, 0, e.createdAt()));
            return true;
        }

        @Override
        public synchronized boolean claim(String userId, long step) {
            Enrollment e = enrollments.get(userId);
            if (e == null || e.confirmedAt() == null || e.lastUsedStep() >= step) return false;
            enrollments.put(userId, new Enrollment(userId, e.secretEnc(), e.confirmedAt(), step, 0, e.createdAt()));
            return true;
        }

        @Override
        public synchronized void addFailure(String userId) {
            Enrollment e = enrollments.get(userId);
            if (e != null) {
                enrollments.put(userId, new Enrollment(userId, e.secretEnc(), e.confirmedAt(), e.lastUsedStep(),
                        e.failedSinceSuccess() + 1, e.createdAt()));
            }
        }

        @Override
        public synchronized void resetFailures(String userId) {
            Enrollment e = enrollments.get(userId);
            if (e != null) {
                enrollments.put(userId, new Enrollment(userId, e.secretEnc(), e.confirmedAt(), e.lastUsedStep(), 0, e.createdAt()));
            }
        }

        @Override
        public synchronized long tryInsert(String userId, long now) {
            if (failuresAfter(userId, now - LOCK_SECONDS).size() >= LOCK_FAILURES) return -1;
            long id = nextFailureId++;
            failures.put(id, new long[] {now});
            failureUser.put(id, userId);
            return id;
        }

        @Override
        public synchronized void deleteFailure(long id) {
            failures.remove(id);
            failureUser.remove(id);
        }

        @Override
        public synchronized List<Long> failuresAfter(String userId, long since) {
            List<Long> out = new ArrayList<>();
            for (Map.Entry<Long, long[]> f : failures.entrySet()) {
                if (failureUser.get(f.getKey()).equals(userId) && f.getValue()[0] > since) out.add(f.getValue()[0]);
            }
            out.sort((a, b) -> Long.compare(b, a));
            return out;
        }

        /** Every failure row of the user (count). */
        public synchronized int failureRows(String userId) {
            int n = 0;
            for (String u : failureUser.values()) if (u.equals(userId)) n++;
            return n;
        }

        @Override
        public synchronized void addRecoveryCodes(String userId, List<String> hashes, long now) {
            for (String h : hashes) codes.add(new RecoveryCode(userId, h, now, null));
        }

        @Override
        public synchronized boolean useRecoveryCode(String userId, String codeHash, long now) {
            for (int i = 0; i < codes.size(); i++) {
                RecoveryCode c = codes.get(i);
                if (c.userId().equals(userId) && c.codeHash().equals(codeHash) && c.usedAt() == null) {
                    codes.set(i, new RecoveryCode(userId, codeHash, c.createdAt(), now));
                    return true;
                }
            }
            return false;
        }

        @Override
        public synchronized int unusedRecoveryCodes(String userId) {
            int n = 0;
            for (RecoveryCode c : codes) if (c.userId().equals(userId) && c.usedAt() == null) n++;
            return n;
        }

        @Override
        public synchronized List<RecoveryCode> recoveryCodes(String userId) {
            List<RecoveryCode> out = new ArrayList<>();
            for (RecoveryCode c : codes) if (c.userId().equals(userId)) out.add(c);
            return out;
        }

        @Override
        public synchronized void deleteAll(String userId) {
            enrollments.remove(userId);
            codes.removeIf(c -> c.userId().equals(userId));
            List<Long> ids = new ArrayList<>();
            for (Map.Entry<Long, String> f : failureUser.entrySet()) if (f.getValue().equals(userId)) ids.add(f.getKey());
            for (Long id : ids) deleteFailure(id);
        }
    }

    private final Store store;
    private final byte[] encryptionKey;
    private final byte[] recoveryHashKey;
    private final String issuer;
    private final LongSupplier clock;
    private final IntFunction<byte[]> randomBytes;

    /**
     * In: the store, encryption_key (exactly 32 bytes), recovery_hash_key (at least 32 bytes), issuer, clock (Unix
     * seconds) and random_bytes(n) (null = SecureRandom). Out: the service. Throws ConfigException("invalid_key") for a
     * key of the wrong size (fail closed, TOTP-11). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    public TotpTwoFactor(Store store, byte[] encryptionKey, byte[] recoveryHashKey, String issuer, LongSupplier clock,
                         IntFunction<byte[]> randomBytes) {
        if (encryptionKey == null || encryptionKey.length != 32 || recoveryHashKey == null || recoveryHashKey.length < 32) {
            throw new ConfigException("invalid_key");
        }
        this.store = store;
        this.encryptionKey = encryptionKey.clone();
        this.recoveryHashKey = recoveryHashKey.clone();
        this.issuer = issuer;
        this.clock = clock;
        if (randomBytes == null) {
            SecureRandom rng = new SecureRandom();
            this.randomBytes = n -> {
                byte[] b = new byte[n];
                rng.nextBytes(b);
                return b;
            };
        } else {
            this.randomBytes = randomBytes;
        }
    }

    // ------------------------------------------------------------------------------------------------ pure functions
    /**
     * base32_encode: RFC 4648 alphabet, upper case, no padding. In: bytes. Out: text. TOTP-02.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public static String base32Encode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int buffer = 0, bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                sb.append(B32.charAt((buffer >> (bits - 5)) & 31));
                bits -= 5;
            }
        }
        if (bits > 0) sb.append(B32.charAt((buffer << (5 - bits)) & 31));
        return sb.toString();
    }

    /**
     * base32_decode: removes ASCII spaces, "-" and "=", maps a-z to A-Z; every other character must be in the alphabet,
     * at least one must remain and the length must not be 1, 3 or 6 modulo 8. Leftover bits are dropped.
     * In: text. Out: bytes. Throws InvalidBase32Exception. TOTP-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: nothing.
     */
    public static byte[] base32Decode(String text) {
        if (text == null) throw new InvalidBase32Exception();
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == ' ' || c == '-' || c == '=') continue;
            if (c >= 'a' && c <= 'z') c = (char) (c - 32);
            if (B32.indexOf(c) < 0) throw new InvalidBase32Exception();
            s.append(c);
        }
        int m = s.length() % 8;
        if (s.length() == 0 || m == 1 || m == 3 || m == 6) throw new InvalidBase32Exception();
        byte[] out = new byte[s.length() * 5 / 8];
        int buffer = 0, bits = 0, k = 0;
        for (int i = 0; i < s.length(); i++) {
            buffer = (buffer << 5) | B32.indexOf(s.charAt(i));
            bits += 5;
            if (bits >= 8) {
                out[k++] = (byte) ((buffer >> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        return out;
    }

    /** HMAC. In: algorithm, key, message. Out: the MAC. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static byte[] hmac(String alg, byte[] key, byte[] msg) {
        try {
            Mac mac = Mac.getInstance(alg);
            mac.init(new SecretKeySpec(key, alg));
            return mac.doFinal(msg);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("hmac unavailable");
        }
    }

    /** In: bytes. Out: lower-case hex. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    /**
     * hotp(key, counter, digits): RFC 4226 with a 64-bit counter. In: key bytes, counter, digits. Out: the code text,
     * left-padded with "0". TOTP-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public static String hotp(byte[] key, long counter, int digits) {
        byte[] mac = hmac("HmacSHA1", key, ByteBuffer.allocate(8).putLong(counter).array());
        int o = mac[19] & 0x0f;
        long v = ((mac[o] & 0x7fL) << 24) | ((mac[o + 1] & 0xffL) << 16) | ((mac[o + 2] & 0xffL) << 8) | (mac[o + 3] & 0xffL);
        long mod = 1;
        for (int i = 0; i < digits; i++) mod *= 10;
        String s = Long.toString(v % mod);
        return "0".repeat(digits - s.length()) + s;
    }

    /** hotp with 6 digits. */
    public static String hotp(byte[] key, long counter) {
        return hotp(key, counter, DIGITS);
    }

    /**
     * totp_at(secret_base32, unix_time, digits) = hotp(base32_decode(secret), floor(unix_time / 30), digits). TOTP-01.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public static String totpAt(String secretBase32, long unixTime, int digits) {
        return hotp(base32Decode(secretBase32), Math.floorDiv(unixTime, STEP), digits);
    }

    /** totp_at with 6 digits. */
    public static String totpAt(String secretBase32, long unixTime) {
        return totpAt(secretBase32, unixTime, DIGITS);
    }

    /** generate_secret(): base32_encode(random_bytes(20)), 32 characters. TOTP-02. */
    public String generateSecret() {
        return base32Encode(randomBytes.apply(20));
    }

    /** pct(s): every UTF-8 byte outside [A-Za-z0-9._~-] as %XX (upper case). In: text. Out: encoded text. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static String pct(String s) {
        StringBuilder sb = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xff;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '~' || c == '-') {
                sb.append((char) c);
            } else {
                sb.append('%').append(String.format("%02X", c));
            }
        }
        return sb.toString();
    }

    /**
     * otpauth_uri(secret, issuer, account_label): the Key URI that authenticator apps read. TOTP-03.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public static String otpauthUri(String secret, String issuer, String accountLabel) {
        return "otpauth://totp/" + pct(issuer + ":" + accountLabel) + "?secret=" + secret + "&issuer=" + pct(issuer)
                + "&algorithm=SHA1&digits=6&period=30";
    }

    /**
     * seal(key32, nonce12, plaintext, aad) -> "v1." + base64(nonce + ciphertext + tag), AES-256-GCM. TOTP-11.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public static String seal(byte[] key, byte[] nonce, String plaintext, String aad) {
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            c.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
            byte[] ct = c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] all = new byte[nonce.length + ct.length];
            System.arraycopy(nonce, 0, all, 0, nonce.length);
            System.arraycopy(ct, 0, all, nonce.length, ct.length);
            return "v1." + Base64.getEncoder().encodeToString(all);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("aes-gcm unavailable");
        }
    }

    /**
     * open(key32, sealed, aad): the plaintext, or null for a missing "v1." prefix, bad base64, fewer than 28 bytes, or a
     * tag that does not verify. TOTP-10, TOTP-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public static String open(byte[] key, String sealed, String aad) {
        if (sealed == null || !sealed.startsWith("v1.")) return null;
        byte[] all;
        try {
            all = Base64.getDecoder().decode(sealed.substring(3));
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (all.length < 28 || key == null || key.length != 32) return null;
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, all, 0, 12));
            c.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
            byte[] pt = c.doFinal(all, 12, all.length - 12);
            return new String(pt, StandardCharsets.UTF_8);
        } catch (AEADBadTagException e) {
            return null;
        } catch (GeneralSecurityException e) {
            return null;
        }
    }

    /** TOTP INPUT: the code without ASCII spaces and "-" when that is exactly 6 ASCII digits; else null. */
    static String totpInput(String code) {
        if (code == null || code.length() > 64) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < code.length(); i++) {
            char c = code.charAt(i);
            if (c == ' ' || c == '-') continue;
            if (c < '0' || c > '9') return null;
            sb.append(c);
        }
        return sb.length() == 6 ? sb.toString() : null;
    }

    /** RECOVERY INPUT: A-Z mapped to a-z, spaces and "-" removed, exactly 12 symbols of the alphabet; else null. */
    static String recoveryInput(String code) {
        if (code == null || code.length() > 64) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < code.length(); i++) {
            char c = code.charAt(i);
            if (c == ' ' || c == '-') continue;
            if (c >= 'A' && c <= 'Z') c = (char) (c + 32);
            if (RECOVERY_ALPHABET.indexOf(c) < 0) return null;
            sb.append(c);
        }
        return sb.length() == 12 ? sb.toString() : null;
    }

    /**
     * code_hash = lower-case hex HMAC-SHA256(recovery_hash_key, "recovery:" + user_id + ":" + RECOVERY INPUT form).
     * In: user id and a code in any accepted spelling. Out: the hash, or null when it is not a recovery code. TOTP-08.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public String recoveryCodeHash(String userId, String code) {
        String r = recoveryInput(code);
        if (r == null) return null;
        return hex(hmac("HmacSHA256", recoveryHashKey, ("recovery:" + userId + ":" + r).getBytes(StandardCharsets.UTF_8)));
    }

    // ------------------------------------------------------------------------------------------------ flows
    /** A refusal. In: HTTP status, error code. Out: {status, error}. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static Map<String, Object> refuse(int status, String error) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", status);
        m.put("error", error);
        return m;
    }

    /** LOCKED answer. In: user, now. Out: 429 locked with retry_after = the 5th most recent failure + 900 - now. Touches: reads the store. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private Map<String, Object> locked(String userId, long now) {
        Map<String, Object> m = refuse(429, "locked");
        List<Long> f = store.failuresAfter(userId, now - LOCK_SECONDS);
        long at = f.size() >= LOCK_FAILURES ? f.get(LOCK_FAILURES - 1) : now;
        m.put("retry_after", at + LOCK_SECONDS - now);
        return m;
    }

    /** FAILURE: the slot row stays; failed_since_success + 1; 401 invalid_code. */
    private Map<String, Object> failure(String userId) {
        store.addFailure(userId);
        return refuse(401, "invalid_code");
    }

    /** MATCH: the largest step s + d (d = -1, 0, +1, s + d >= 0) whose code equals the input, compared in constant time
     * with no early exit; -1 when none. */
    private static long match(byte[] key, String input, long now) {
        long s = Math.floorDiv(now, STEP);
        long best = -1;
        byte[] in = input.getBytes(StandardCharsets.US_ASCII);
        for (int d = -1; d <= 1; d++) {
            long step = s + d;
            if (step < 0) continue;
            boolean eq = MessageDigest.isEqual(hotp(key, step).getBytes(StandardCharsets.US_ASCII), in);
            if (eq && step > best) best = step;
        }
        return best;
    }

    /**
     * enroll_start(user_id, account_label) -> {status 200, secret, otpauth_uri}, or 409 already_enrolled. Writes the
     * sealed secret only (an unconfirmed row is replaced). TOTP-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the store (totp_enrollments).
     */
    public Map<String, Object> enrollStart(String userId, String accountLabel) {
        Enrollment e = store.getEnrollment(userId);
        if (e != null && e.confirmedAt() != null) return refuse(409, "already_enrolled");
        long now = clock.getAsLong();
        String secret = generateSecret();
        byte[] nonce = randomBytes.apply(12);
        String enc = seal(encryptionKey, nonce, secret, "totp:" + userId);
        if (!store.putUnconfirmed(new Enrollment(userId, enc, null, 0, 0, now))) return refuse(409, "already_enrolled");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", 200);
        m.put("secret", secret);
        m.put("otpauth_uri", otpauthUri(secret, issuer, accountLabel));
        return m;
    }

    /** One recovery code: 12 symbols, one random_bytes(1) call each, bytes >= 240 drawn again. */
    private String drawRecoveryCode() {
        StringBuilder sb = new StringBuilder();
        while (sb.length() < 14) {
            if (sb.length() == 4 || sb.length() == 9) {
                sb.append('-');
                continue;
            }
            int b = randomBytes.apply(1)[0] & 0xff;
            if (b >= 240) continue;
            sb.append(RECOVERY_ALPHABET.charAt(b % 30));
        }
        return sb.toString();
    }

    /**
     * enroll_confirm(user_id, code) -> {status 200, recovery_codes: 8 texts}, or 409 enrollment_not_started / 409
     * already_enrolled / 429 locked / 401 invalid_code / 503 secret_unreadable, checked in the spec's order. Stores only
     * the codes' keyed hashes. TOTP-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the store (all three tables).
     */
    public Map<String, Object> enrollConfirm(String userId, String code) {
        Enrollment e = store.getEnrollment(userId);
        if (e == null) return refuse(409, "enrollment_not_started");
        if (e.confirmedAt() != null) return refuse(409, "already_enrolled");
        long now = clock.getAsLong();
        long slot = store.tryInsert(userId, now);
        if (slot < 0) return locked(userId, now);
        String input = totpInput(code);
        if (input == null) return failure(userId);
        String secret = open(encryptionKey, e.secretEnc(), "totp:" + userId);
        if (secret == null) {
            store.deleteFailure(slot);
            return refuse(503, "secret_unreadable");
        }
        long step = match(base32Decode(secret), input, now);
        if (step < 0) return failure(userId);
        if (!store.confirm(userId, now, step, e.secretEnc())) {
            Enrollment again = store.getEnrollment(userId);
            if (again != null && again.confirmedAt() != null) {
                store.deleteFailure(slot);
                return refuse(409, "already_enrolled");
            }
            return failure(userId);
        }
        List<String> plain = new ArrayList<>();
        List<String> hashes = new ArrayList<>();
        while (plain.size() < RECOVERY_CODES) {
            String c = drawRecoveryCode();
            if (plain.contains(c)) continue;
            plain.add(c);
            hashes.add(recoveryCodeHash(userId, c));
        }
        store.addRecoveryCodes(userId, hashes, now);
        store.deleteFailure(slot);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", 200);
        m.put("recovery_codes", plain);
        return m;
    }

    /**
     * verify(user_id, code) -> {status 200, ok: true, method: "totp" | "recovery_code", recovery_codes_left}, or 409
     * not_enrolled / 429 locked (retry_after) / 429 recovery_required / 503 secret_unreadable / 401 invalid_code.
     * TRY is counted before any code is looked at. TOTP-05..10, TOTP-13, TOTP-14.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
     */
    public Map<String, Object> verify(String userId, String code) {
        return check(userId, code);
    }

    /** verify's steps 1-5 (shared by verify and disable). In: user, code. Out: the ok answer or a refusal. Touches: the store. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private Map<String, Object> check(String userId, String code) {
        Enrollment e = store.getEnrollment(userId);
        if (e == null || e.confirmedAt() == null) return refuse(409, "not_enrolled");
        long now = clock.getAsLong();
        long slot = store.tryInsert(userId, now);
        if (slot < 0) return locked(userId, now);
        String input = totpInput(code);
        String method;
        if (input != null) {
            if (e.failedSinceSuccess() >= HARD_LOCK_FAILURES) {
                store.deleteFailure(slot);
                return refuse(429, "recovery_required");
            }
            String secret = open(encryptionKey, e.secretEnc(), "totp:" + userId);
            if (secret == null) {
                store.deleteFailure(slot);
                return refuse(503, "secret_unreadable");
            }
            long step = match(base32Decode(secret), input, now);
            if (step < 0 || step <= e.lastUsedStep()) return failure(userId);
            if (!store.claim(userId, step)) return failure(userId);
            method = "totp";
        } else {
            String h = recoveryCodeHash(userId, code);
            if (h == null || !store.useRecoveryCode(userId, h, now)) return failure(userId);
            store.resetFailures(userId);
            method = "recovery_code";
        }
        store.deleteFailure(slot);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", 200);
        m.put("ok", true);
        m.put("method", method);
        m.put("recovery_codes_left", store.unusedRecoveryCodes(userId));
        return m;
    }

    /**
     * disable(user_id, code) -> {status 200, disabled: true}: verify's steps 1-5 with the same refusals; on ok deletes
     * the enrollment, recovery codes and failures. TOTP-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the store.
     */
    public Map<String, Object> disable(String userId, String code) {
        Map<String, Object> r = check(userId, code);
        if (!Integer.valueOf(200).equals(r.get("status"))) return r;
        store.deleteAll(userId);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", 200);
        m.put("disabled", true);
        return m;
    }

    /**
     * status(user_id) -> {enrolled, locked_until (Long or null), recovery_required, recovery_codes_left}. Changes
     * nothing. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the store.
     */
    public Map<String, Object> status(String userId) {
        long now = clock.getAsLong();
        Enrollment e = store.getEnrollment(userId);
        List<Long> f = store.failuresAfter(userId, now - LOCK_SECONDS);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("enrolled", e != null && e.confirmedAt() != null);
        m.put("locked_until", f.size() >= LOCK_FAILURES ? (Object) (f.get(LOCK_FAILURES - 1) + LOCK_SECONDS) : null);
        m.put("recovery_required", e != null && e.confirmedAt() != null && e.failedSinceSuccess() >= HARD_LOCK_FAILURES);
        m.put("recovery_codes_left", store.unusedRecoveryCodes(userId));
        return m;
    }
}

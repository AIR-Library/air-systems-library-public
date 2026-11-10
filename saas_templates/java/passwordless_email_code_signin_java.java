import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.IntFunction;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Passwordless email code sign-in (spec docs/specs/passwordless_email_code_signin.md): sign in, and sign up, with a
 * 6-digit code sent by email. One code per address at a time, valid 600 s, usable once, 5 tries, counted before the
 * compare; limits per address, per IP and per day; the same answer whether or not the address has an account. Codes,
 * addresses and IPs are stored only as HMAC-SHA256 under the server's secret.
 *
 * In: the typed address, the typed code and the client IP as the HTTP layer saw it. Out: result maps with "status"
 * (refusals carry "error"); never an unhandled exception. Construction fails closed (not_configured).
 * Why: Phase D wave 1, owner request 2026-11-10 (EMAILCODE-01 to EMAILCODE-14). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the injected Store (database; memory in tests), the injected sender (email, network in production; a
 * fake in tests) and revoke_unproven (the application's credentials). No money. Never logs a code, an address or the
 * secret.
 */
public final class PasswordlessEmailCodeSignin {
    public static final long CODE_TTL = 600;
    public static final int CODE_ATTEMPTS = 5;
    public static final int START_PER_EMAIL_HOUR = 5;
    public static final int START_PER_EMAIL_DAY = 10;
    public static final int START_PER_IP_HOUR = 20;
    public static final int VERIFY_PER_IP_HOUR = 30;
    public static final int VERIFY_PER_EMAIL_HOUR = 10;
    private static final Pattern EMAIL = Pattern.compile("[a-z0-9][a-z0-9._%+=-]*@[a-z0-9-]+(\\.[a-z0-9-]+)+");
    private static final String ZEROS = "0".repeat(64);

    /** Construction failure: "not_configured". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    public static final class ConfigException extends RuntimeException {
        public final String code;

        /** In: the code. Out: the exception; its message never holds the secret. */
        public ConfigException(String code) {
            super(code);
            this.code = code;
        }
    }

    /** The email sender: true when the mail was accepted. Must not log the code. Touches: network (real sender). */
    public interface Sender {
        /** In: address, code, lifetime. Out: true when accepted; may raise. Touches: email (network). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        boolean sendCode(String to, String code, long expiresInSeconds) throws Exception;
    }

    /** Removes every credential an unproven account carries (password, OAuth links, sessions, keys, TOTP). */
    public interface RevokeUnproven {
        /** In: the account id. Out: none; raises on failure. Touches: the application's credential stores. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        void revoke(String accountId) throws Exception;
    }

    /** An accounts row. status: active | suspended | closed. */
    public record Account(String id, String email, Long emailVerifiedAt, String status, long createdAt) {}

    /** An email_codes row (keyed by email_hash). */
    public record CodeRow(String emailHash, String codeHash, long expiresAt, int attempts, long createdAt) {}

    /**
     * Storage. Every write that decides something is one atomic statement: BUMP, the try count, the use-up delete.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (memory in tests).
     */
    public interface Store {
        /** The account with this email, or null. Touches: reads the database. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        Account findAccountByEmail(String email);

        /** Inserts the account unless a row with that email exists; returns the row for the email afterwards. */
        Account insertAccountIfAbsent(Account a);

        /** email_verified_at = now. */
        void markVerified(String accountId, long now);

        /** Writes the code row, replacing the address's earlier one. */
        void putCode(CodeRow row);

        /** The code row for the address hash, or null. Touches: reads the database. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        CodeRow getCode(String emailHash);

        /** DELETE ... WHERE email_hash = :h AND code_hash = :c. True when one row was deleted. */
        boolean deleteCode(String emailHash, String codeHash);

        /** UPDATE ... SET attempts = attempts + 1 WHERE email_hash AND attempts < 5 AND expires_at > now; the row after, or null. */
        CodeRow countTry(String emailHash, long now);

        /** Deletes the row when it is expired (expires_at <= now) or used up (attempts >= 5). */
        void deleteDeadCode(String emailHash, long now);

        /** BUMP: inserts (key, window_start, 1) or adds 1; the count after it. */
        long bump(String key, long windowStart);
    }

    /**
     * In-memory Store, synchronized; counts account reads (EMAILCODE-07). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: memory only.
     */
    public static final class InMemoryStore implements Store {
        public final Map<String, Account> accounts = new LinkedHashMap<>();
        public final Map<String, CodeRow> codes = new LinkedHashMap<>();
        public final Map<String, Long> windows = new LinkedHashMap<>();
        public int accountReads = 0;

        @Override
        public synchronized Account findAccountByEmail(String email) {
            accountReads++;
            for (Account a : accounts.values()) if (a.email().equals(email)) return a;
            return null;
        }

        @Override
        public synchronized Account insertAccountIfAbsent(Account a) {
            Account found = findAccountByEmail(a.email());
            if (found != null) return found;
            accounts.put(a.id(), a);
            return a;
        }

        @Override
        public synchronized void markVerified(String accountId, long now) {
            Account a = accounts.get(accountId);
            if (a != null) accounts.put(accountId, new Account(a.id(), a.email(), now, a.status(), a.createdAt()));
        }

        /** Test hook: writes an account row as it is. */
        public synchronized void putAccount(Account a) {
            accounts.put(a.id(), a);
        }

        @Override
        public synchronized void putCode(CodeRow row) {
            codes.put(row.emailHash(), row);
        }

        @Override
        public synchronized CodeRow getCode(String emailHash) {
            return codes.get(emailHash);
        }

        @Override
        public synchronized boolean deleteCode(String emailHash, String codeHash) {
            CodeRow r = codes.get(emailHash);
            if (r == null || !r.codeHash().equals(codeHash)) return false;
            codes.remove(emailHash);
            return true;
        }

        @Override
        public synchronized CodeRow countTry(String emailHash, long now) {
            CodeRow r = codes.get(emailHash);
            if (r == null || r.attempts() >= CODE_ATTEMPTS || r.expiresAt() <= now) return null;
            CodeRow n = new CodeRow(r.emailHash(), r.codeHash(), r.expiresAt(), r.attempts() + 1, r.createdAt());
            codes.put(emailHash, n);
            return n;
        }

        @Override
        public synchronized void deleteDeadCode(String emailHash, long now) {
            CodeRow r = codes.get(emailHash);
            if (r != null && (r.expiresAt() <= now || r.attempts() >= CODE_ATTEMPTS)) codes.remove(emailHash);
        }

        @Override
        public synchronized long bump(String key, long windowStart) {
            String k = key + "\u0000" + windowStart;
            long c = windows.getOrDefault(k, 0L) + 1;
            windows.put(k, c);
            return c;
        }
    }

    private final Store store;
    private final byte[] secret;
    private final Sender sender;
    private final RevokeUnproven revokeUnproven;
    private final LongSupplier clock;
    private final IntFunction<byte[]> randomBytes;
    private final Supplier<String> generateCode;

    /**
     * In: store, secret (at least 32 bytes), sender, revoke_unproven (null = does nothing), clock, random_bytes (null =
     * SecureRandom), generate_code (null = CODE from random_bytes). Out: the service. Throws ConfigException
     * ("not_configured") for a short secret or no sender (EMAILCODE-12). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: memory only.
     */
    public PasswordlessEmailCodeSignin(Store store, byte[] secret, Sender sender, RevokeUnproven revokeUnproven,
                                       LongSupplier clock, IntFunction<byte[]> randomBytes, Supplier<String> generateCode) {
        if (secret == null || secret.length < 32 || sender == null) throw new ConfigException("not_configured");
        this.store = store;
        this.secret = secret.clone();
        this.sender = sender;
        this.revokeUnproven = revokeUnproven == null ? id -> { } : revokeUnproven;
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
        this.generateCode = generateCode == null ? this::defaultCode : generateCode;
    }

    // ------------------------------------------------------------------------------------------------ helpers
    /**
     * normalize_email(raw): trims space, tab, CR and LF, maps A-Z to a-z, then requires 3 to 254 characters matching
     * the spec's pattern as a whole. Out: the address or null. EMAILCODE-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: nothing.
     */
    public static String normalizeEmail(String raw) {
        if (raw == null) return null;
        int a = 0, b = raw.length();
        while (a < b && isTrim(raw.charAt(a))) a++;
        while (b > a && isTrim(raw.charAt(b - 1))) b--;
        char[] c = raw.substring(a, b).toCharArray();
        for (int i = 0; i < c.length; i++) if (c[i] >= 'A' && c[i] <= 'Z') c[i] = (char) (c[i] + 32);
        String e = new String(c);
        if (e.length() < 3 || e.length() > 254 || !EMAIL.matcher(e).matches()) return null;
        return e;
    }

    /** In: a character. Out: true for space, tab, CR, LF (the only characters trimmed). Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean isTrim(char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    }

    /** hmac_hex(text): lower-case hex HMAC-SHA256(secret, UTF-8 of text). */
    public String hmacHex(String text) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            StringBuilder sb = new StringBuilder();
            for (byte v : mac.doFinal(text.getBytes(StandardCharsets.UTF_8))) sb.append(String.format("%02x", v & 0xff));
            return sb.toString();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("hmac unavailable");
        }
    }

    /** email_hash(email) = hmac_hex("email:" + email). EMAILCODE-02. */
    public String emailHash(String email) {
        return hmacHex("email:" + email);
    }

    /** code_hash(email, code) = hmac_hex("code:" + email_hash(email) + ":" + code). EMAILCODE-02. */
    public String codeHash(String email, String code) {
        return hmacHex("code:" + emailHash(email) + ":" + code);
    }

    /** ip_hash(ip) = the first 32 characters of hmac_hex("ip:" + ip). EMAILCODE-02. */
    public String ipHash(String ip) {
        return hmacHex("ip:" + ip).substring(0, 32);
    }

    /** EK(email): the first 32 characters of email_hash(email). Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private String ek(String email) {
        return emailHash(email).substring(0, 32);
    }

    /** BUMP(key, span): one atomic insert-or-add in the clock window. In: key, 3600 or 86400. Out: the count after it. Touches: the store. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private long bump(String key, long span) {
        long now = clock.getAsLong();
        return store.bump(key, now - Math.floorMod(now, span));
    }

    /**
     * CODE: an unsigned big-endian 32-bit number from random_bytes(4), drawn again when >= 4294000000, then mod
     * 1000000 with 6 digits. Every code is equally likely. EMAILCODE-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the random source.
     */
    public String defaultCode() {
        while (true) {
            byte[] b = randomBytes.apply(4);
            long n = ((b[0] & 0xffL) << 24) | ((b[1] & 0xffL) << 16) | ((b[2] & 0xffL) << 8) | (b[3] & 0xffL);
            if (n >= 4294000000L) continue;
            String s = Long.toString(n % 1000000);
            return "0".repeat(6 - s.length()) + s;
        }
    }

    /** A refusal. In: HTTP status, error code. Out: {status, error}. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static Map<String, Object> refuse(int status, String error) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", status);
        m.put("error", error);
        return m;
    }

    /** Constant-time comparison of two hex texts. In: a, b. Out: equal or not. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean ctEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.US_ASCII), b.getBytes(StandardCharsets.US_ASCII));
    }

    // ------------------------------------------------------------------------------------------------ endpoints
    /**
     * start(email, ip) -> {status 202, sent: true, expires_in: 600}, or 422 invalid_email / 429 too_many_requests (IP
     * per hour, then address per hour and per day, both always counted) / 503 send_failed (the code just written is
     * removed). Never reads accounts. EMAILCODE-01, 02, 07, 08, 09, 12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the store (email_codes, rate_windows), the sender (email).
     */
    public Map<String, Object> start(String email, String ip) {
        String e = normalizeEmail(email);
        if (e == null) return refuse(422, "invalid_email");
        String ipText = ip == null ? "unknown" : ip;
        if (bump("start-ip#" + ipHash(ipText), 3600) > START_PER_IP_HOUR) return refuse(429, "too_many_requests");
        long h = bump("start-email#" + ek(e), 3600);
        long d = bump("start-email-day#" + ek(e), 86400);
        if (h > START_PER_EMAIL_HOUR || d > START_PER_EMAIL_DAY) return refuse(429, "too_many_requests");
        long now = clock.getAsLong();
        String code = generateCode.get();
        String eh = emailHash(e), ch = codeHash(e, code);
        store.putCode(new CodeRow(eh, ch, now + CODE_TTL, 0, now));
        boolean sent;
        try {
            sent = sender.sendCode(e, code, CODE_TTL);
        } catch (Exception ex) {
            sent = false;
        }
        if (!sent) {
            store.deleteCode(eh, ch);
            return refuse(503, "send_failed");
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", 202);
        m.put("sent", true);
        m.put("expires_in", CODE_TTL);
        return m;
    }

    /**
     * verify(email, code, ip) -> {status 200, account_id, email, new_account}, or 429 too_many_requests (IP, then
     * address) / 400 invalid_code (one answer for wrong, expired, used, exhausted and never-requested codes) / 500
     * processing_failed (revoke_unproven raised) / 403 account_unavailable (only after a right code). The try is
     * counted before the compare; exactly one request can use a code up. EMAILCODE-01, 03..07, 10, 11, 13, 14.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, revoke_unproven.
     */
    public Map<String, Object> verify(String email, String code, String ip) {
        String ipText = ip == null ? "unknown" : ip;
        if (bump("verify-ip#" + ipHash(ipText), 3600) > VERIFY_PER_IP_HOUR) return refuse(429, "too_many_requests");
        String e = normalizeEmail(email);
        String c = null;
        if (code != null) {
            StringBuilder sb = new StringBuilder();
            boolean ok = true;
            for (int i = 0; i < code.length(); i++) {
                char x = code.charAt(i);
                if (x == ' ' || x == '-') continue;
                if (x < '0' || x > '9') ok = false;
                sb.append(x);
            }
            if (ok && sb.length() == 6) c = sb.toString();
        }
        if (e == null || c == null) return refuse(400, "invalid_code");
        if (bump("verify-email#" + ek(e), 3600) > VERIFY_PER_EMAIL_HOUR) return refuse(429, "too_many_requests");
        long now = clock.getAsLong();
        String eh = emailHash(e);
        String given = codeHash(e, c);
        CodeRow row = store.countTry(eh, now);
        if (row == null) {
            store.deleteDeadCode(eh, now);
            ctEquals(given, ZEROS);
            return refuse(400, "invalid_code");
        }
        if (!ctEquals(given, row.codeHash())) {
            if (row.attempts() >= CODE_ATTEMPTS) store.deleteCode(eh, row.codeHash());
            return refuse(400, "invalid_code");
        }
        if (!store.deleteCode(eh, row.codeHash())) return refuse(400, "invalid_code");
        byte[] idb = randomBytes.apply(16);
        StringBuilder id = new StringBuilder();
        for (byte v : idb) id.append(String.format("%02x", v & 0xff));
        Account acct = store.insertAccountIfAbsent(new Account(id.toString(), e, now, "active", now));
        boolean isNew = acct.id().equals(id.toString());
        if (acct.emailVerifiedAt() == null) {
            try {
                revokeUnproven.revoke(acct.id());
            } catch (Exception ex) {
                return refuse(500, "processing_failed");
            }
            store.markVerified(acct.id(), now);
        }
        if (!"active".equals(acct.status())) return refuse(403, "account_unavailable");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", 200);
        m.put("account_id", acct.id());
        m.put("email", e);
        m.put("new_account", isNew);
        return m;
    }
}

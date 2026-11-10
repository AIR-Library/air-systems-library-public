import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.IntFunction;

/**
 * Tests for TotpTwoFactor (spec docs/specs/totp_two_factor.md, TOTP-01 to TOTP-14), with an injected clock and an
 * injected queue of random bytes. Run through main(); any failed check exits 1.
 * Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only (no database, files, network or money).
 */
public class totp_two_factor_java_tests {

    static final byte[] K = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    static final String KB32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    /** Runs every test. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only. */
    public static void main(String[] args) {
        try {
            testHotpAndTotpVectors();
            testBase32();
            testEnrollStart();
            testEnrollConfirm();
            testWindow();
            testReplay();
            testInputShapes();
            testRecoveryCodes();
            testLock();
            testSecretUnreadable();
            testSealOpenAndKeys();
            testDisable();
            testNotEnrolledAndIsolation();
            testHardLock();
            System.out.println("All tests passed");
        } catch (Throwable e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    // ------------------------------------------------------------------------------------------------ helpers
    /** Fails with msg unless cond holds. */
    static void check(boolean cond, String msg) {
        if (!cond) throw new AssertionError(msg);
    }

    /** The bytes start, start+1, ..., start+n-1. */
    static byte[] seq(int start, int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte) (start + i);
        return b;
    }

    /** A settable clock. */
    static final class Clock {
        long now;

        Clock(long now) {
            this.now = now;
        }
    }

    /** random_bytes as a queue of bytes served in order, whatever n is asked; falls back to a counter when empty. */
    static final class ByteQueue implements IntFunction<byte[]> {
        final ArrayDeque<Byte> q = new ArrayDeque<>();
        int fallback = 1;

        /** Test helper: appends bytes to the queue. Touches: memory only. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        void add(byte[] b) {
            for (byte x : b) q.add(x);
        }

        @Override
        public byte[] apply(int n) {
            byte[] out = new byte[n];
            for (int i = 0; i < n; i++) out[i] = q.isEmpty() ? (byte) (fallback++ * 37 % 240) : q.poll();
            return out;
        }
    }

    /** A test fixture: store, clock, random queue and service. */
    static final class Fx {
        final TotpTwoFactor.InMemoryStore store = new TotpTwoFactor.InMemoryStore();
        final Clock clock;
        final ByteQueue rnd = new ByteQueue();
        final TotpTwoFactor svc;

        Fx(long now) {
            clock = new Clock(now);
            svc = new TotpTwoFactor(store, seq(0, 32), seq(0x40, 32), "Example App", () -> clock.now, rnd);
        }

        /** Enrolls and confirms user with the secret K at the current time; returns the recovery codes. */
        @SuppressWarnings("unchecked")
        List<String> enroll(String user) {
            rnd.add(K);
            rnd.add(seq(0xa0, 12));
            Map<String, Object> s = svc.enrollStart(user, user + "@example.com");
            check(KB32.equals(s.get("secret")), "secret is K");
            Map<String, Object> c = svc.enrollConfirm(user, TotpTwoFactor.totpAt(KB32, clock.now));
            check(Integer.valueOf(200).equals(c.get("status")), "confirm ok " + c);
            return (List<String>) c.get("recovery_codes");
        }
    }

    /** Test helper: true when the result has this status and error (no error for null). Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static boolean is(Map<String, Object> r, int status, String error) {
        return Integer.valueOf(status).equals(r.get("status")) && (error == null ? !r.containsKey("error") : error.equals(r.get("error")));
    }

    // ------------------------------------------------------------------------------------------------ tests
    // TOTP-01
    /** RFC 4226 HOTP values, RFC 6238 TOTP values in 8 and 6 digits (T = 20000000000), and a 64-bit counter. */
    static void testHotpAndTotpVectors() {
        String[] want = {"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"};
        for (int c = 0; c < 10; c++) check(TotpTwoFactor.hotp(K, c).equals(want[c]), "hotp " + c);
        check(TotpTwoFactor.hotp(K, 4294967296L).equals("999456"), "hotp above 32 bits");
        long[] ts = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
        String[] w8 = {"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"};
        String[] w6 = {"287082", "081804", "050471", "005924", "279037", "353130"};
        for (int i = 0; i < ts.length; i++) {
            check(TotpTwoFactor.totpAt(KB32, ts[i], 8).equals(w8[i]), "totp 8 digits at " + ts[i]);
            check(TotpTwoFactor.totpAt(KB32, ts[i], 6).equals(w6[i]), "totp 6 digits at " + ts[i]);
        }
    }

    /** Test helper: true when base32_decode refuses the text with invalid_base32. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static boolean invalidB32(String s) {
        try {
            TotpTwoFactor.base32Decode(s);
            return false;
        } catch (TotpTwoFactor.InvalidBase32Exception e) {
            return true;
        }
    }

    // TOTP-02
    /** base32 RFC 4648 vectors without padding, lenient decode, invalid characters and lengths, generate_secret. */
    static void testBase32() {
        String[][] v = {{"", ""}, {"f", "MY"}, {"fo", "MZXQ"}, {"foo", "MZXW6"}, {"foob", "MZXW6YQ"}, {"fooba", "MZXW6YTB"}, {"foobar", "MZXW6YTBOI"}};
        for (String[] x : v) {
            check(TotpTwoFactor.base32Encode(x[0].getBytes(StandardCharsets.US_ASCII)).equals(x[1]), "encode " + x[0]);
            if (!x[0].isEmpty()) check(new String(TotpTwoFactor.base32Decode(x[1]), StandardCharsets.US_ASCII).equals(x[0]), "decode " + x[1]);
        }
        check(TotpTwoFactor.base32Encode(K).equals(KB32), "encode K");
        check(new String(TotpTwoFactor.base32Decode("mzxw 6ytb-oi=="), StandardCharsets.US_ASCII).equals("foobar"), "lenient decode");
        check(new String(TotpTwoFactor.base32Decode("MZ"), StandardCharsets.US_ASCII).equals("f"), "MZ -> f");
        for (String bad : new String[] {"MZXW6YT1", "", "M", "MZX", "MZXW6Y"}) check(invalidB32(bad), "invalid_base32: " + bad);
        Fx fx = new Fx(1000);
        TotpTwoFactor real = new TotpTwoFactor(fx.store, seq(0, 32), seq(0x40, 32), "X", () -> 1000L, null);
        String s = real.generateSecret();
        check(s.length() == 32 && TotpTwoFactor.base32Decode(s).length == 20, "generate_secret: 32 characters, 20 bytes");
    }

    // TOTP-03
    /** enroll_start: the secret, the exact URI, only the sealed secret stored (the spec's string), replaced on retry. */
    static void testEnrollStart() {
        Fx fx = new Fx(1111111000L);
        fx.rnd.add(K);
        fx.rnd.add(seq(0xa0, 12));
        Map<String, Object> r = fx.svc.enrollStart("user_1", "alice@example.com");
        check(is(r, 200, null) && KB32.equals(r.get("secret")), "enroll_start answer " + r);
        check(("otpauth://totp/Example%20App%3Aalice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example%20App"
                + "&algorithm=SHA1&digits=6&period=30").equals(r.get("otpauth_uri")), "otpauth uri " + r.get("otpauth_uri"));
        TotpTwoFactor.Enrollment e = fx.store.getEnrollment("user_1");
        check("v1.oKGio6SlpqeoqaqroV0maQKFQOklPLSHVjWKjzfpA1TV+QA621cV0i7kP1B5d8k2owRGDhH/FzF0f662".equals(e.secretEnc()),
                "sealed secret " + e.secretEnc());
        check(!e.secretEnc().contains(KB32) && e.confirmedAt() == null, "the store never holds the base32 text");
        Map<String, Object> r2 = fx.svc.enrollStart("user_1", "alice@example.com");
        check(is(r2, 200, null) && !KB32.equals(r2.get("secret")), "a second enroll_start replaces the secret");
        check(!fx.store.getEnrollment("user_1").secretEnc().equals(e.secretEnc()), "the stored secret changed");
        check(is(fx.svc.enrollConfirm("user_1", TotpTwoFactor.totpAt(KB32, fx.clock.now)), 401, "invalid_code"),
                "the replaced secret's code no longer confirms");
        check(is(fx.svc.enrollConfirm("user_1", TotpTwoFactor.totpAt((String) r2.get("secret"), fx.clock.now)), 200, null),
                "the new secret confirms");
    }

    // TOTP-04
    /** enroll_confirm: 8 codes (the spec's, from the byte stream), keyed hashes only, then the 409s. */
    @SuppressWarnings("unchecked")
    static void testEnrollConfirm() {
        Fx fx = new Fx(1111111000L);
        check(is(fx.svc.enrollConfirm("user_1", "123456"), 409, "enrollment_not_started"), "confirm before start");
        fx.rnd.add(K);
        fx.rnd.add(seq(0xa0, 12));
        byte[] stream = new byte[101];
        for (int k = 0; k < 101; k++) stream[k] = (byte) ((7 * k) % 256);
        fx.rnd.add(stream);
        fx.svc.enrollStart("user_1", "alice");
        String code = TotpTwoFactor.totpAt(KB32, fx.clock.now);
        Map<String, Object> c = fx.svc.enrollConfirm("user_1", code);
        check(is(c, 200, null), "confirm " + c);
        List<String> codes = (List<String>) c.get("recovery_codes");
        List<String> want = Arrays.asList("29gq-y7en-w5ck", "t3ah-rz8f-px6d", "mv4b-js29-gqy5", "ckt3-ahrz-8fpx",
                "6dmv-4bjs-29gq", "y7en-w5ck-t8fp", "x6dm-v4bj-s29g", "qy7e-nw5c-kt3a");
        check(codes.equals(want), "the spec's 8 codes: " + codes);
        check(fx.rnd.q.isEmpty(), "exactly 101 bytes drawn");
        for (String x : codes) check(x.matches("[23456789abcdefghjkmnpqrstvwxyz]{4}-[23456789abcdefghjkmnpqrstvwxyz]{4}-[23456789abcdefghjkmnpqrstvwxyz]{4}"), "shape " + x);
        List<TotpTwoFactor.RecoveryCode> rows = fx.store.recoveryCodes("user_1");
        check(rows.size() == 8, "8 rows");
        check(rows.get(0).codeHash().equals("d9199ecad0b35d9e2f18857343d7fe79dd5f8425f1c460c88fe18f5c4b4a2645"), "keyed hash of the first");
        for (TotpTwoFactor.RecoveryCode r : rows) {
            for (String x : codes) check(!r.codeHash().contains(x) && !r.codeHash().contains(x.replace("-", "")), "no plain code stored");
        }
        check(is(fx.svc.verify("user_1", code), 401, "invalid_code"), "the confirming code is refused by verify");
        check(is(fx.svc.enrollConfirm("user_1", code), 409, "already_enrolled"), "second confirm");
        check(is(fx.svc.enrollStart("user_1", "alice"), 409, "already_enrolled"), "enroll_start after confirm");
    }

    // TOTP-05
    /** The window vector: two steps away is refused (checked first); previous, current and next are accepted. */
    static void testWindow() {
        Fx fx = new Fx(1111111000L);
        fx.enroll("user_1");
        fx.clock.now = 1111111109L;
        check(is(fx.svc.verify("user_1", "150727"), 401, "invalid_code"), "two steps back refused");
        check(is(fx.svc.verify("user_1", "266759"), 401, "invalid_code"), "two steps ahead refused");
        for (String c : new String[] {"731029", "081804", "050471"}) {
            Map<String, Object> r = fx.svc.verify("user_1", c);
            check(is(r, 200, null) && "totp".equals(r.get("method")) && Boolean.TRUE.equals(r.get("ok")), "accepted " + c + " " + r);
        }
    }

    // TOTP-06
    /** Replay: an accepted code is refused again; earlier steps refused, later accepted; the store's claim once. */
    static void testReplay() {
        Fx fx = new Fx(1111111000L);
        fx.enroll("user_1");
        fx.clock.now = 1111111109L;
        check(is(fx.svc.verify("user_1", "081804"), 200, null), "current accepted");
        check(is(fx.svc.verify("user_1", "081804"), 401, "invalid_code"), "replay refused");
        check(is(fx.svc.verify("user_1", "731029"), 401, "invalid_code"), "earlier step refused");
        check(is(fx.svc.verify("user_1", "050471"), 200, null), "later step accepted");
        long step = fx.store.getEnrollment("user_1").lastUsedStep() + 5;
        check(fx.store.claim("user_1", step), "claim once");
        check(!fx.store.claim("user_1", step), "claim twice changes no row");
    }

    // TOTP-07
    /** Spaces and dashes accepted; malformed inputs are 401 and add one failure each (each on its own user). */
    static void testInputShapes() {
        for (String spelling : new String[] {"081 804", "081-804", "081804"}) {
            Fx fx = new Fx(1111111000L);
            fx.enroll("u");
            fx.clock.now = 1111111109L;
            check(is(fx.svc.verify("u", spelling), 200, null), "accepted spelling " + spelling);
        }
        String[] bad = {"12345", "1234567", "abcdef", "", null, "1".repeat(65), "١٢٣٤٥٦"};
        int i = 0;
        Fx fx = new Fx(1111111000L);
        for (String b : bad) {
            String u = "user_" + (i++);
            fx.enroll(u);
            Map<String, Object> r = fx.svc.verify(u, b);
            check(is(r, 401, "invalid_code"), "refused input " + b + " " + r);
            check(fx.store.failureRows(u) == 1 && fx.store.getEnrollment(u).failedSinceSuccess() == 1, "one failure for " + b);
        }
    }

    // TOTP-08
    /** Recovery codes: once each, any case and without dashes, never for another user, stored as the keyed hash. */
    static void testRecoveryCodes() throws Exception {
        Fx fx = new Fx(1111111000L);
        List<String> codes = fx.enroll("user_1");
        fx.enroll("user_2");
        Map<String, Object> r = fx.svc.verify("user_1", codes.get(0));
        check(is(r, 200, null) && "recovery_code".equals(r.get("method")) && Integer.valueOf(7).equals(r.get("recovery_codes_left")), "recovery " + r);
        check(is(fx.svc.verify("user_1", codes.get(0)), 401, "invalid_code"), "used again");
        check(is(fx.svc.verify("user_1", codes.get(1).toUpperCase()), 200, null), "upper case");
        check(is(fx.svc.verify("user_1", codes.get(2).replace("-", "")), 200, null), "without dashes");
        check(is(fx.svc.verify("user_2", codes.get(3)), 401, "invalid_code"), "user A's code for user B");
        check(fx.svc.recoveryCodeHash("user_1", "K7MQ-2XPT-9HCW").equals("5a93360f78c7f03de7336a625adf93bf238749d8da4aaf734271b327c52347a3"), "spec keyed hash");
        String stored = fx.store.recoveryCodes("user_1").get(4).codeHash();
        check(stored.equals(fx.svc.recoveryCodeHash("user_1", codes.get(4))), "stored hash is the keyed hash");
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        StringBuilder plain = new StringBuilder();
        for (byte b : sha.digest(codes.get(4).replace("-", "").getBytes(StandardCharsets.UTF_8))) plain.append(String.format("%02x", b & 0xff));
        check(!stored.equals(plain.toString()), "not a plain SHA-256");
    }

    // TOTP-09
    /** Lock: 5 failures in 900 s lock even a correct code without adding a failure; 899 s locked, 900 s accepted. */
    static void testLock() {
        Fx fx = new Fx(1111111000L);
        fx.enroll("user_1");
        long t0 = 1111112000L;
        for (int i = 0; i < 5; i++) {
            fx.clock.now = t0 + i;
            check(is(fx.svc.verify("user_1", "000000".equals(TotpTwoFactor.totpAt(KB32, fx.clock.now)) ? "111111" : "000000"), 401, "invalid_code"), "failure " + i);
        }
        fx.clock.now = t0 + 10;
        Map<String, Object> r = fx.svc.verify("user_1", TotpTwoFactor.totpAt(KB32, fx.clock.now));
        check(is(r, 429, "locked") && Long.valueOf(t0 + 900 - (t0 + 10)).equals(r.get("retry_after")), "locked with retry_after " + r);
        check(fx.store.failureRows("user_1") == 5 && fx.store.getEnrollment("user_1").failedSinceSuccess() == 5, "no failure added");
        check(Long.valueOf(t0 + 900).equals(fx.svc.status("user_1").get("locked_until")), "status locked_until");
        fx.clock.now = t0 + 899;
        check(is(fx.svc.verify("user_1", TotpTwoFactor.totpAt(KB32, fx.clock.now)), 429, "locked"), "899 s: still locked");
        fx.clock.now = t0 + 900;
        check(is(fx.svc.verify("user_1", TotpTwoFactor.totpAt(KB32, fx.clock.now)), 200, null), "900 s: accepted");
        TotpTwoFactor.InMemoryStore s = new TotpTwoFactor.InMemoryStore();
        for (int i = 0; i < 5; i++) check(s.tryInsert("x", 5000 + i) > 0, "try write " + i);
        check(s.tryInsert("x", 5010) < 0, "a 6th try write in the window fails");
    }

    // TOTP-10
    /** A secret that cannot be opened is 503 secret_unreadable with no failure; a recovery code still works. */
    static void testSecretUnreadable() {
        Fx fx = new Fx(1111111000L);
        List<String> codes = fx.enroll("user_1");
        fx.clock.now = 1111111109L;
        TotpTwoFactor other = new TotpTwoFactor(fx.store, seq(1, 32), seq(0x40, 32), "Example App", () -> fx.clock.now, fx.rnd);
        Map<String, Object> r = other.verify("user_1", "081804");
        check(is(r, 503, "secret_unreadable"), "another key " + r);
        check(fx.store.failureRows("user_1") == 0 && fx.store.getEnrollment("user_1").failedSinceSuccess() == 0, "no failure");
        TotpTwoFactor.Enrollment e = fx.store.getEnrollment("user_1");
        char[] ch = e.secretEnc().toCharArray();
        ch[20] = ch[20] == 'A' ? 'B' : 'A';
        fx.store.overwrite(new TotpTwoFactor.Enrollment(e.userId(), new String(ch), e.confirmedAt(), e.lastUsedStep(), e.failedSinceSuccess(), e.createdAt()));
        check(is(fx.svc.verify("user_1", "081804"), 503, "secret_unreadable"), "one changed character");
        check(is(fx.svc.verify("user_1", "000000"), 503, "secret_unreadable"), "a wrong 6-digit code too");
        check(fx.store.failureRows("user_1") == 0, "still no failure");
        Map<String, Object> rc = fx.svc.verify("user_1", codes.get(0));
        check(is(rc, 200, null) && "recovery_code".equals(rc.get("method")), "a recovery code still signs in");
    }

    // TOTP-11
    /** seal gives the spec's string, open reverses it and refuses another aad, key or one changed character; key sizes. */
    static void testSealOpenAndKeys() {
        String sealed = TotpTwoFactor.seal(seq(0, 32), seq(0xa0, 12), KB32, "totp:user_1");
        check(sealed.equals("v1.oKGio6SlpqeoqaqroV0maQKFQOklPLSHVjWKjzfpA1TV+QA621cV0i7kP1B5d8k2owRGDhH/FzF0f662"), "seal vector " + sealed);
        check(KB32.equals(TotpTwoFactor.open(seq(0, 32), sealed, "totp:user_1")), "open");
        check(TotpTwoFactor.open(seq(0, 32), sealed, "totp:user_2") == null, "another user's aad");
        check(TotpTwoFactor.open(seq(1, 32), sealed, "totp:user_1") == null, "another key");
        char[] ch = sealed.toCharArray();
        ch[10] = ch[10] == 'x' ? 'y' : 'x';
        check(TotpTwoFactor.open(seq(0, 32), new String(ch), "totp:user_1") == null, "one changed character");
        check(TotpTwoFactor.open(seq(0, 32), sealed.substring(3), "totp:user_1") == null, "missing prefix");
        check(TotpTwoFactor.open(seq(0, 32), "v1.!!!", "totp:user_1") == null, "bad base64");
        check(TotpTwoFactor.open(seq(0, 32), "v1.AAAA", "totp:user_1") == null, "too short");
        TotpTwoFactor.InMemoryStore st = new TotpTwoFactor.InMemoryStore();
        for (byte[][] keys : new byte[][][] {{seq(0, 31), seq(0x40, 32)}, {seq(0, 33), seq(0x40, 32)}, {seq(0, 32), seq(0x40, 31)}}) {
            boolean refused = false;
            try {
                new TotpTwoFactor(st, keys[0], keys[1], "X", () -> 0L, null);
            } catch (TotpTwoFactor.ConfigException e) {
                refused = "invalid_key".equals(e.code);
            }
            check(refused, "a key of the wrong size is refused at construction");
        }
        new TotpTwoFactor(st, seq(0, 32), seq(0x40, 64), "X", () -> 0L, null);
    }

    // TOTP-12
    /** disable with a valid code deletes everything; with a wrong code it is 401 and deletes nothing. */
    static void testDisable() {
        Fx fx = new Fx(1111111000L);
        fx.enroll("user_1");
        fx.clock.now = 1111111109L;
        check(is(fx.svc.disable("user_1", "000000"), 401, "invalid_code"), "wrong code");
        check(fx.store.getEnrollment("user_1") != null && fx.store.recoveryCodes("user_1").size() == 8, "nothing deleted");
        Map<String, Object> d = fx.svc.disable("user_1", "081804");
        check(is(d, 200, null) && Boolean.TRUE.equals(d.get("disabled")), "disabled " + d);
        check(fx.store.getEnrollment("user_1") == null && fx.store.recoveryCodes("user_1").isEmpty() && fx.store.failureRows("user_1") == 0,
                "enrollment, codes and failures deleted");
        check(is(fx.svc.verify("user_1", "050471"), 409, "not_enrolled"), "then not_enrolled");
        check(Boolean.FALSE.equals(fx.svc.status("user_1").get("enrolled")), "status not enrolled");
        fx.rnd.add(K);
        fx.rnd.add(seq(0xa0, 12));
        check(is(fx.svc.enrollStart("user_1", "alice"), 200, null), "can enroll again");
    }

    // TOTP-13
    /** verify and disable before confirm are 409 not_enrolled with the right code; users never share codes. */
    static void testNotEnrolledAndIsolation() {
        Fx fx = new Fx(1111111000L);
        fx.rnd.add(K);
        fx.rnd.add(seq(0xa0, 12));
        fx.svc.enrollStart("user_1", "alice");
        String code = TotpTwoFactor.totpAt(KB32, fx.clock.now);
        check(is(fx.svc.verify("user_1", code), 409, "not_enrolled"), "verify before confirm");
        check(is(fx.svc.disable("user_1", code), 409, "not_enrolled"), "disable before confirm");
        check(is(fx.svc.verify("nobody", code), 409, "not_enrolled"), "verify with no row");
        fx.svc.enrollConfirm("user_1", code);
        fx.rnd.add(seq(0x10, 20));
        fx.rnd.add(seq(0xb0, 12));
        Map<String, Object> s2 = fx.svc.enrollStart("user_2", "bob");
        String sec2 = (String) s2.get("secret");
        check(!sec2.equals(KB32), "different secrets");
        check(is(fx.svc.enrollConfirm("user_2", TotpTwoFactor.totpAt(sec2, fx.clock.now)), 200, null), "user 2 confirmed");
        fx.clock.now += 60;
        String c1 = TotpTwoFactor.totpAt(KB32, fx.clock.now), c2 = TotpTwoFactor.totpAt(sec2, fx.clock.now);
        check(!c1.equals(c2), "codes differ at this time");
        check(is(fx.svc.verify("user_2", c1), 401, "invalid_code"), "user 1's code for user 2");
        check(is(fx.svc.verify("user_1", c2), 401, "invalid_code"), "user 2's code for user 1");
        check(is(fx.svc.verify("user_1", c1), 200, null) && is(fx.svc.verify("user_2", c2), 200, null), "own codes work");
    }

    /** n FAILUREs for the user, 5 per lock window, moving the clock 900 s after each 5th. */
    static void failMany(Fx fx, String user, int n) {
        for (int i = 0; i < n; i++) {
            String good = TotpTwoFactor.totpAt(KB32, fx.clock.now);
            check(is(fx.svc.verify(user, good.equals("000000") ? "111111" : "000000"), 401, "invalid_code"), "failure " + i);
            if ((i + 1) % 5 == 0) fx.clock.now += 900;
        }
    }

    // TOTP-14
    /** After 100 failures a correct code is 429 recovery_required (no failure, however long); a recovery code ends it. */
    static void testHardLock() {
        Fx fx = new Fx(1111111000L);
        List<String> codes = fx.enroll("user_1");
        fx.clock.now += 900;
        failMany(fx, "user_1", 100);
        check(fx.store.getEnrollment("user_1").failedSinceSuccess() == 100, "100 failures counted");
        int rows = fx.store.failureRows("user_1");
        Map<String, Object> r = fx.svc.verify("user_1", TotpTwoFactor.totpAt(KB32, fx.clock.now));
        check(is(r, 429, "recovery_required") && !r.containsKey("retry_after"), "recovery_required " + r);
        fx.clock.now += 86400L * 365;
        check(is(fx.svc.verify("user_1", TotpTwoFactor.totpAt(KB32, fx.clock.now)), 429, "recovery_required"), "a year later too");
        check(fx.store.failureRows("user_1") == rows && fx.store.getEnrollment("user_1").failedSinceSuccess() == 100, "no failure added");
        check(Boolean.TRUE.equals(fx.svc.status("user_1").get("recovery_required")), "status recovery_required");
        check(is(fx.svc.verify("user_1", codes.get(0)), 200, null), "a recovery code signs in");
        check(fx.store.getEnrollment("user_1").failedSinceSuccess() == 0, "count back to 0");
        fx.clock.now += 30;
        check(is(fx.svc.verify("user_1", TotpTwoFactor.totpAt(KB32, fx.clock.now)), 200, null), "a correct code works again");

        Fx g = new Fx(1111111000L);
        g.enroll("user_2");
        g.clock.now += 900;
        failMany(g, "user_2", 99);
        g.clock.now += 900;
        check(is(g.svc.verify("user_2", TotpTwoFactor.totpAt(KB32, g.clock.now)), 200, null), "success at 99 failures");
        g.clock.now += 900;
        failMany(g, "user_2", 99);
        g.clock.now += 900;
        check(g.store.getEnrollment("user_2").failedSinceSuccess() == 99, "the count started again");
        check(is(g.svc.verify("user_2", TotpTwoFactor.totpAt(KB32, g.clock.now)), 200, null), "198 failures with a success between: accepted");
    }
}

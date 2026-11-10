import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.IntFunction;

/**
 * Tests for PasswordlessEmailCodeSignin (spec docs/specs/passwordless_email_code_signin.md, EMAILCODE-01 to
 * EMAILCODE-14), with a recording fake sender (no network), a recording revoke_unproven, an injected clock, injected
 * codes and an injected byte queue. Run through main(); a failed check exits 1.
 * Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only (no database, files, network or money).
 */
public class passwordless_email_code_signin_java_tests {

    static final byte[] SECRET = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
    static final long T0 = 1699920000L;

    /** Runs every test. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only. */
    public static void main(String[] args) {
        try {
            testSignInAndSignUp();
            testStorageHashes();
            testSingleUse();
            testExpiry();
            testFiveTries();
            testNewStartReplaces();
            testNoEnumeration();
            testSendsPerAddress();
            testSendsPerIp();
            testTriesPerIpAndAddress();
            testInputShapes();
            testSendFailureAndConfig();
            testUnavailableAccounts();
            testCodesAndGenerator();
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

    /** A fake sender recording (to, code, expires_in); answers `answer`, or raises when raise is set. */
    static final class FakeSender implements PasswordlessEmailCodeSignin.Sender {
        final List<String[]> calls = new ArrayList<>();
        boolean answer = true, raise = false;

        @Override
        public boolean sendCode(String to, String code, long expiresIn) throws Exception {
            calls.add(new String[] {to, code, Long.toString(expiresIn)});
            if (raise) throw new java.io.IOException("smtp down");
            return answer;
        }

        /** Test helper: the code of the last send. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        String lastCode() {
            return calls.get(calls.size() - 1)[1];
        }
    }

    /** A byte queue served in order; a counter when empty. */
    static final class ByteQueue implements IntFunction<byte[]> {
        final ArrayDeque<Byte> q = new ArrayDeque<>();
        int counter = 0;

        /** Test helper: appends bytes to the queue. Touches: memory only. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        void add(int... b) {
            for (int x : b) q.add((byte) x);
        }

        @Override
        public byte[] apply(int n) {
            byte[] out = new byte[n];
            for (int i = 0; i < n; i++) out[i] = q.isEmpty() ? (byte) (counter++ * 61 + 3) : q.poll();
            return out;
        }
    }

    /** Test fixture: store, fakes, clock and service. Touches: memory only. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static final class Fx {
        final PasswordlessEmailCodeSignin.InMemoryStore store = new PasswordlessEmailCodeSignin.InMemoryStore();
        final FakeSender sender = new FakeSender();
        final List<String> revoked = new ArrayList<>();
        final ByteQueue rnd = new ByteQueue();
        final ArrayDeque<String> codes = new ArrayDeque<>();
        boolean revokeRaises = false;
        long now = T0;
        final PasswordlessEmailCodeSignin svc;
        int nextCode = 100000;

        Fx() {
            svc = new PasswordlessEmailCodeSignin(store, SECRET, sender, id -> {
                revoked.add(id);
                if (revokeRaises) throw new IllegalStateException("revoke failed");
            }, () -> now, rnd, () -> codes.isEmpty() ? Integer.toString(nextCode++) : codes.poll());
        }

        /** Starts a code for email from ip and returns the code the sender got. */
        String send(String email, String ip) {
            check(is(svc.start(email, ip), 202, null), "start for " + email);
            return sender.lastCode();
        }
    }

    /** Test helper: true when the result has this status and error (no error for null). Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static boolean is(Map<String, Object> r, int status, String error) {
        return Integer.valueOf(status).equals(r.get("status")) && (error == null ? !r.containsKey("error") : error.equals(r.get("error")));
    }

    // ------------------------------------------------------------------------------------------------ tests
    // EMAILCODE-01
    /** start 202 and one 6-digit code; verify signs up then signs in; an unverified row is revoked once, then verified. */
    static void testSignInAndSignUp() {
        Fx fx = new Fx();
        Map<String, Object> s = fx.svc.start("user@example.com", "203.0.113.7");
        check(is(s, 202, null) && Boolean.TRUE.equals(s.get("sent")) && Long.valueOf(600).equals(s.get("expires_in")) && s.size() == 3, "start " + s);
        check(fx.sender.calls.size() == 1 && fx.sender.calls.get(0)[0].equals("user@example.com") && fx.sender.lastCode().matches("[0-9]{6}")
                && fx.sender.calls.get(0)[2].equals("600"), "one 6-digit code sent");
        Map<String, Object> v = fx.svc.verify("user@example.com", fx.sender.lastCode(), "203.0.113.7");
        check(is(v, 200, null) && Boolean.TRUE.equals(v.get("new_account")) && "user@example.com".equals(v.get("email")), "sign up " + v);
        String id = (String) v.get("account_id");
        PasswordlessEmailCodeSignin.Account a = fx.store.accounts.get(id);
        check(a != null && a.emailVerifiedAt() == fx.now && a.status().equals("active"), "account exists, verified");
        fx.now += 60;
        Map<String, Object> v2 = fx.svc.verify("user@example.com", fx.send("user@example.com", "203.0.113.7"), "203.0.113.7");
        check(is(v2, 200, null) && id.equals(v2.get("account_id")) && Boolean.FALSE.equals(v2.get("new_account")), "sign in " + v2);
        check(fx.revoked.isEmpty(), "an account made by verify never calls revoke_unproven");
        fx.store.putAccount(new PasswordlessEmailCodeSignin.Account("acct_invited", "invited@example.com", null, "active", 1L));
        Map<String, Object> v3 = fx.svc.verify("invited@example.com", fx.send("invited@example.com", "198.51.100.1"), "198.51.100.1");
        check(is(v3, 200, null) && "acct_invited".equals(v3.get("account_id")) && Boolean.FALSE.equals(v3.get("new_account")), "invited " + v3);
        check(fx.revoked.equals(List.of("acct_invited")), "revoke_unproven called once with its id");
        check(Long.valueOf(fx.now).equals(fx.store.accounts.get("acct_invited").emailVerifiedAt()), "then verified");
        Fx g = new Fx();
        g.store.putAccount(new PasswordlessEmailCodeSignin.Account("acct_x", "x@example.com", null, "active", 1L));
        g.revokeRaises = true;
        check(is(g.svc.verify("x@example.com", g.send("x@example.com", "1.2.3.4"), "1.2.3.4"), 500, "processing_failed"), "revoke raises -> 500");
        check(g.store.accounts.get("acct_x").emailVerifiedAt() == null, "the row stays unverified");
    }

    // EMAILCODE-02
    /** The spec's hashes and rate keys; the tables hold no address, IP, code or plain SHA-256 of the code. */
    static void testStorageHashes() throws Exception {
        Fx fx = new Fx();
        check(fx.svc.emailHash("user@example.com").equals("587522269e243312a5d6f20bcdc78dc97a3e644e2ad702cdb94ac9550c03b346"), "email_hash");
        check(fx.svc.codeHash("user@example.com", "123456").equals("761f222c89dc1744c480d21e141277cc9af815ee0e2a1d7489c9282594728b5b"), "code_hash");
        check(fx.svc.ipHash("203.0.113.7").equals("e01c4eeb03c058165d49564dcaf561cf"), "ip_hash");
        fx.codes.add("123456");
        fx.svc.start("user@example.com", "203.0.113.7");
        PasswordlessEmailCodeSignin.CodeRow r = fx.store.getCode("587522269e243312a5d6f20bcdc78dc97a3e644e2ad702cdb94ac9550c03b346");
        check(r != null && r.codeHash().equals("761f222c89dc1744c480d21e141277cc9af815ee0e2a1d7489c9282594728b5b") && r.attempts() == 0
                && r.expiresAt() == T0 + 600, "stored row " + r);
        List<String> keys = new ArrayList<>();
        for (String k : fx.store.windows.keySet()) keys.add(k.substring(0, k.indexOf('\u0000')));
        check(keys.equals(List.of("start-ip#e01c4eeb03c058165d49564dcaf561cf", "start-email#587522269e243312a5d6f20bcdc78dc9",
                "start-email-day#587522269e243312a5d6f20bcdc78dc9")), "rate keys " + keys);
        StringBuilder sha = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest("123456".getBytes(StandardCharsets.US_ASCII))) sha.append(String.format("%02x", b & 0xff));
        String dump = fx.store.codes.toString() + fx.store.windows.toString();
        for (String bad : new String[] {"user@example.com", "203.0.113.7", "123456", sha.toString()}) {
            check(!dump.contains(bad), "the tables do not hold " + bad);
        }
    }

    // EMAILCODE-03
    /** The right code a second time is 400 invalid_code. */
    static void testSingleUse() {
        Fx fx = new Fx();
        String c = fx.send("a@x.com", "1.1.1.1");
        check(is(fx.svc.verify("a@x.com", c, "1.1.1.1"), 200, null), "first use");
        check(is(fx.svc.verify("a@x.com", c, "1.1.1.1"), 400, "invalid_code"), "second use");
    }

    // EMAILCODE-04
    /** Accepted 599 s after start; 400 at 600 s. */
    static void testExpiry() {
        Fx fx = new Fx();
        String c = fx.send("a@x.com", "1.1.1.1");
        fx.now = T0 + 599;
        check(is(fx.svc.verify("a@x.com", c, "1.1.1.1"), 200, null), "599 s");
        Fx g = new Fx();
        String d = g.send("a@x.com", "1.1.1.1");
        g.now = T0 + 600;
        check(is(g.svc.verify("a@x.com", d, "1.1.1.1"), 400, "invalid_code"), "600 s");
        check(g.store.codes.isEmpty(), "the expired row is deleted");
    }

    /** Test helper: a 6-digit code that differs from c. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static String wrong(String c) {
        return c.equals("000000") ? "111111" : "000000";
    }

    // EMAILCODE-05
    /** After 5 wrong codes the right one is refused; after 4 the right one (the 5th try) is accepted. */
    static void testFiveTries() {
        Fx fx = new Fx();
        String c = fx.send("a@x.com", "1.1.1.1");
        for (int i = 0; i < 5; i++) check(is(fx.svc.verify("a@x.com", wrong(c), "1.1.1.1"), 400, "invalid_code"), "wrong " + i);
        check(fx.store.codes.isEmpty(), "the 5th wrong try deletes the row");
        check(is(fx.svc.verify("a@x.com", c, "1.1.1.1"), 400, "invalid_code"), "then the right code is refused");
        Fx g = new Fx();
        String d = g.send("a@x.com", "1.1.1.1");
        for (int i = 0; i < 4; i++) g.svc.verify("a@x.com", wrong(d), "1.1.1.1");
        check(is(g.svc.verify("a@x.com", d, "1.1.1.1"), 200, null), "the 5th try with the right code");
    }

    // EMAILCODE-06
    /** A new start replaces the code; the earlier one is refused; the tries start again at 0. */
    static void testNewStartReplaces() {
        Fx fx = new Fx();
        String c1 = fx.send("a@x.com", "1.1.1.1");
        for (int i = 0; i < 4; i++) fx.svc.verify("a@x.com", wrong(c1), "1.1.1.1");
        String c2 = fx.send("a@x.com", "1.1.1.1");
        check(!c1.equals(c2), "a different code");
        check(fx.store.getCode(fx.svc.emailHash("a@x.com")).attempts() == 0, "tries start again at 0");
        check(is(fx.svc.verify("a@x.com", c1, "1.1.1.1"), 400, "invalid_code"), "the earlier code is refused");
        for (int i = 0; i < 3; i++) fx.svc.verify("a@x.com", wrong(c2), "1.1.1.1");
        check(is(fx.svc.verify("a@x.com", c2, "1.1.1.1"), 200, null), "the new code works on its 5th try");
    }

    // EMAILCODE-07
    /** start answers alike for known and unknown addresses and never reads accounts; verify's 400 bodies are identical. */
    static void testNoEnumeration() {
        Fx fx = new Fx();
        fx.store.putAccount(new PasswordlessEmailCodeSignin.Account("acct_1", "known@x.com", 1L, "active", 1L));
        int reads = fx.store.accountReads;
        Map<String, Object> a = fx.svc.start("known@x.com", "1.1.1.1");
        Map<String, Object> b = fx.svc.start("unknown@x.com", "1.1.1.1");
        check(a.equals(b), "same answer " + a + " / " + b);
        check(fx.sender.calls.size() == 2 && fx.sender.calls.get(0)[2].equals(fx.sender.calls.get(1)[2])
                && fx.sender.calls.get(0)[1].matches("[0-9]{6}") && fx.sender.calls.get(1)[1].matches("[0-9]{6}"), "same kind of sender call");
        check(fx.store.accountReads == reads, "start never reads accounts");
        String kc = fx.sender.calls.get(0)[1];
        Map<String, Object> wrongCode = fx.svc.verify("known@x.com", wrong(kc), "1.1.1.1");
        Map<String, Object> neverAsked = fx.svc.verify("never@x.com", "123456", "1.1.1.1");
        fx.svc.verify("known@x.com", kc, "1.1.1.1");
        Map<String, Object> used = fx.svc.verify("known@x.com", kc, "1.1.1.1");
        String uc = fx.sender.calls.get(1)[1];
        fx.now += 600;
        Map<String, Object> expired = fx.svc.verify("unknown@x.com", uc, "1.1.1.1");
        check(wrongCode.equals(neverAsked) && neverAsked.equals(used) && used.equals(expired) && is(used, 400, "invalid_code") && used.size() == 2,
                "one 400 body: " + wrongCode + used + expired + neverAsked);
    }

    // EMAILCODE-08
    /** 6th start for an address in an hour is 429 and sends nothing; next hour works; the 11th in a day is 429. */
    static void testSendsPerAddress() {
        Fx fx = new Fx();
        for (int i = 0; i < 5; i++) fx.send("a@x.com", "10.0.0." + i);
        int sent = fx.sender.calls.size();
        check(is(fx.svc.start("a@x.com", "10.0.1.1"), 429, "too_many_requests"), "6th in the hour");
        check(fx.sender.calls.size() == sent, "nothing sent");
        fx.now = T0 + 3600;
        for (int i = 0; i < 4; i++) fx.send("a@x.com", "10.0.2." + i);
        check(is(fx.svc.start("a@x.com", "10.0.3.1"), 429, "too_many_requests"), "the 11th in the day (a refused start counts)");
        fx.now = T0 + 86400;
        check(is(fx.svc.start("a@x.com", "10.0.4.1"), 202, null), "the next day works");
    }

    // EMAILCODE-09
    /** The 21st start from one IP in an hour is 429; another IP is not affected. */
    static void testSendsPerIp() {
        Fx fx = new Fx();
        for (int i = 0; i < 20; i++) fx.send("u" + i + "@x.com", "203.0.113.7");
        check(is(fx.svc.start("u20@x.com", "203.0.113.7"), 429, "too_many_requests"), "21st from one IP");
        check(is(fx.svc.start("u21@x.com", "203.0.113.8"), 202, null), "another IP");
    }

    // EMAILCODE-10
    /** The 31st verify from one IP in an hour is 429 even with the right code; the 11th for one address too. */
    static void testTriesPerIpAndAddress() {
        Fx fx = new Fx();
        String good = fx.send("target@x.com", "9.9.9.9");
        for (int i = 0; i < 30; i++) fx.svc.verify("v" + i + "@x.com", "123456", "203.0.113.7");
        check(is(fx.svc.verify("target@x.com", good, "203.0.113.7"), 429, "too_many_requests"), "31st from one IP, right code");
        check(is(fx.svc.verify("target@x.com", good, "203.0.113.8"), 200, null), "another IP is not affected");

        Fx g = new Fx();
        int ip = 0;
        String code = null;
        for (int round = 0; round < 3; round++) {
            code = g.send("b@x.com", "8.8.8." + round);
            int tries = round < 2 ? 4 : 2;
            for (int i = 0; i < tries; i++) {
                check(is(g.svc.verify("b@x.com", wrong(code), "1.0.0." + (ip++)), 400, "invalid_code"), "wrong try");
            }
        }
        check(is(g.svc.verify("b@x.com", code, "1.0.0." + (ip++)), 429, "too_many_requests"), "11th verify for one address, right code, new IP");
        g.now = T0 + 3600;
        check(is(g.svc.verify("b@x.com", code, "1.0.0." + ip), 400, "invalid_code"),
                "the next hour is counted afresh: the (now expired) code gets 400, not 429");
    }

    // EMAILCODE-11
    /** Trim and case rules, malformed addresses, spaced and dashed codes, and malformed codes that spend no try. */
    static void testInputShapes() {
        Fx fx = new Fx();
        String c = fx.send(" A@X.com ", "1.1.1.1");
        check(fx.sender.calls.get(0)[0].equals("a@x.com"), "sent to a@x.com");
        Map<String, Object> v = fx.svc.verify(" A@X.com ", c, "1.1.1.1");
        check(is(v, 200, null) && "a@x.com".equals(v.get("email")), "signs in a@x.com " + v);
        String[] badEmails = {"a@b", "a b@x.com", "a@x..com", ".a@x.com", "a@x.com,b@y.com", "<a@x.com>", "a@x.com ", "a@x.com\u000b",
            "a@x.com\u0000", "K@x.com", "", null};
        for (String e : badEmails) {
            check(is(fx.svc.start(e, "1.1.1.1"), 422, "invalid_email"), "start refuses " + e);
            check(is(fx.svc.verify(e, "123456", "1.1.1.1"), 400, "invalid_code"), "verify refuses " + e);
            check(PasswordlessEmailCodeSignin.normalizeEmail(e) == null, "normalize_email refuses " + e);
        }
        check("a@x.com".equals(PasswordlessEmailCodeSignin.normalizeEmail(" A@X.com ")), "normalize_email");
        for (String spelled : new String[] {"123 456", "123-456"}) {
            Fx g = new Fx();
            g.codes.add("123456");
            g.send("s@x.com", "1.1.1.1");
            check(is(g.svc.verify("s@x.com", spelled, "1.1.1.1"), 200, null), "accepted as " + spelled);
        }
        Fx h = new Fx();
        String hc = h.send("h@x.com", "1.1.1.1");
        for (String bad : new String[] {"12345", "1234567", "abcdef", "١٢٣٤٥٦", null}) {
            check(is(h.svc.verify("h@x.com", bad, "1.1.1.1"), 400, "invalid_code"), "malformed code " + bad);
        }
        check(h.store.getCode(h.svc.emailHash("h@x.com")).attempts() == 0, "no try spent");
        check(is(h.svc.verify("h@x.com", hc, "1.1.1.1"), 200, null), "the code still works");
    }

    // EMAILCODE-12
    /** A sender that fails or raises: 503 send_failed and no code left; bad configuration fails construction. */
    static void testSendFailureAndConfig() {
        Fx fx = new Fx();
        fx.sender.answer = false;
        check(is(fx.svc.start("a@x.com", "1.1.1.1"), 503, "send_failed"), "sender false");
        check(fx.store.codes.isEmpty(), "no code left");
        fx.sender.answer = true;
        fx.sender.raise = true;
        check(is(fx.svc.start("b@x.com", "1.1.1.1"), 503, "send_failed"), "sender raises");
        check(fx.store.codes.isEmpty(), "no code left after a raise");
        for (Object[] cfg : new Object[][] {{new byte[31], new FakeSender()}, {SECRET, null}, {null, new FakeSender()}}) {
            boolean refused = false;
            try {
                new PasswordlessEmailCodeSignin(new PasswordlessEmailCodeSignin.InMemoryStore(), (byte[]) cfg[0],
                        (PasswordlessEmailCodeSignin.Sender) cfg[1], null, () -> 0L, null, null);
            } catch (PasswordlessEmailCodeSignin.ConfigException e) {
                refused = "not_configured".equals(e.code);
            }
            check(refused, "construction fails with not_configured");
        }
    }

    // EMAILCODE-13
    /** A suspended or closed account: the right code is 403 account_unavailable, and the code is used up. */
    static void testUnavailableAccounts() {
        for (String status : new String[] {"suspended", "closed"}) {
            Fx fx = new Fx();
            fx.store.putAccount(new PasswordlessEmailCodeSignin.Account("acct_" + status, "s@x.com", 1L, status, 1L));
            String c = fx.send("s@x.com", "1.1.1.1");
            check(is(fx.svc.verify("s@x.com", c, "1.1.1.1"), 403, "account_unavailable"), status + " -> 403");
            check(fx.store.codes.isEmpty(), "the code is used up");
            check(is(fx.svc.verify("s@x.com", c, "1.1.1.1"), 400, "invalid_code"), status + ": then 400");
        }
    }

    // EMAILCODE-14
    /** A code is bound to its address; "000042" keeps its zeros; the default generator gives the spec's codes. */
    static void testCodesAndGenerator() {
        Fx fx = new Fx();
        String ca = fx.send("a@x.com", "1.1.1.1");
        String cb = fx.send("b@x.com", "1.1.1.1");
        check(!ca.equals(cb), "two different codes");
        check(is(fx.svc.verify("b@x.com", ca, "1.1.1.1"), 400, "invalid_code"), "a's code is refused for b");
        check(is(fx.svc.verify("c@x.com", ca, "1.1.1.1"), 400, "invalid_code"), "a's code for an address that never asked");
        check(is(fx.svc.verify("b@x.com", cb, "1.1.1.1"), 200, null) && is(fx.svc.verify("a@x.com", ca, "1.1.1.1"), 200, null), "each code for its own address");
        Fx z = new Fx();
        z.codes.add("000042");
        z.svc.start("z@x.com", "1.1.1.1");
        check(z.sender.lastCode().equals("000042"), "the sender gets 000042");
        check(is(z.svc.verify("z@x.com", "000042", "1.1.1.1"), 200, null), "000042 signs in");
        ByteQueue q = new ByteQueue();
        q.add(0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0xff, 0xf1, 0x3d, 0x7f, 0xff, 0xf1, 0x3d, 0x80, 0x00, 0x00, 0x00, 0x2a);
        PasswordlessEmailCodeSignin d = new PasswordlessEmailCodeSignin(new PasswordlessEmailCodeSignin.InMemoryStore(), SECRET, new FakeSender(), null, () -> T0, q, null);
        check(d.defaultCode().equals("483648"), "ff ff ff ff drawn again, then 483648");
        check(d.defaultCode().equals("999999"), "999999");
        check(d.defaultCode().equals("000042"), "ff f1 3d 80 drawn again, then 000042");
        check(q.q.isEmpty(), "every byte used");
        PasswordlessEmailCodeSignin real = new PasswordlessEmailCodeSignin(new PasswordlessEmailCodeSignin.InMemoryStore(), SECRET, new FakeSender(), null, () -> T0, null, null);
        for (int i = 0; i < 50; i++) check(real.defaultCode().matches("[0-9]{6}"), "default generator: 6 digits");
    }
}

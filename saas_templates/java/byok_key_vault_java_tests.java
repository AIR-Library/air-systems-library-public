import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.IntFunction;

/**
 * Tests for ByokKeyVault (spec docs/specs/byok_key_vault.md, VAULT-01 to VAULT-14): a fake provider client (no
 * network), an injected clock and an injected queue of random bytes. Run through main(); a failed check exits 1.
 * Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only (no database, files, network or money).
 */
public class byok_key_vault_java_tests {

    static final String KEY = "acme_" + "k3y0123456789abcdefghWXYZ";

    /** Runs every test. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only. */
    public static void main(String[] args) {
        try {
            testSaveHappyPath();
            testKnownAnswer();
            testRefusalsBeforeProvider();
            testProviderAnswers();
            testListKeys();
            testUseKey();
            testIsolation();
            testTamperedRows();
            testReplace();
            testRotation();
            testRewrapCountsAFailingRow();
            testKeyUnavailableAndConfig();
            testHourlyLimit();
            testDelete();
            testRealRandomness();
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

    /** Test helper: the bytes start, start+1, ... (n of them). Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static byte[] seq(int start, int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte) (start + i);
        return b;
    }

    /** random_bytes as a queue served in order; when empty, a counter keeps the output distinct. */
    static final class ByteQueue implements IntFunction<byte[]> {
        final ArrayDeque<Byte> q = new ArrayDeque<>();
        int counter = 0;

        /** Test helper: appends bytes to the queue. Touches: memory only. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        void add(byte[] b) {
            for (byte x : b) q.add(x);
        }

        @Override
        public byte[] apply(int n) {
            byte[] out = new byte[n];
            for (int i = 0; i < n; i++) out[i] = q.isEmpty() ? (byte) (counter++ * 131 + 7) : q.poll();
            return out;
        }
    }

    /** A fake provider client that records its calls and answers `answer` (or throws when answer is "throw"). */
    static final class FakeClient implements ByokKeyVault.ProviderClient {
        final List<String> calls = new ArrayList<>();
        String answer = "ok";

        @Override
        public String check(String provider, String key) throws Exception {
            calls.add(provider + "|" + key);
            if ("throw".equals(answer)) throw new java.io.IOException("connection reset");
            return answer;
        }
    }

    /** Test fixture: store, fakes, clock and service. Touches: memory only. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static final class Fx {
        final ByokKeyVault.InMemoryStore store = new ByokKeyVault.InMemoryStore();
        final FakeClient client = new FakeClient();
        final ByteQueue rnd = new ByteQueue();
        long now = 1699920000L;
        ByokKeyVault vault;

        Fx() {
            vault = make(keyring("k1"), "k1");
        }

        /** Test helper: a vault on the fixture's store with this keyring and active key. Touches: memory only. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        ByokKeyVault make(Map<String, byte[]> keys, String active) {
            return new ByokKeyVault(store, keys, active, providers(), client, () -> now, rnd);
        }
    }

    /** Test helper: k1 = 00..1f, k2 = 40..5f. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static Map<String, byte[]> keyring(String... ids) {
        Map<String, byte[]> m = new LinkedHashMap<>();
        for (String id : ids) m.put(id, id.equals("k1") ? seq(0, 32) : seq(0x40, 32));
        return m;
    }

    /** Test helper: providers acme and beta (prefix + 16 <= min 24 <= max 200). Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static Map<String, ByokKeyVault.ProviderConfig> providers() {
        Map<String, ByokKeyVault.ProviderConfig> p = new LinkedHashMap<>();
        p.put("acme", new ByokKeyVault.ProviderConfig("acme_", 24, 200));
        p.put("beta", new ByokKeyVault.ProviderConfig("beta_", 24, 200));
        return p;
    }

    /** Test helper: true when the result has this status and error (no error for null). Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static boolean is(Map<String, Object> r, int status, String error) {
        return Integer.valueOf(status).equals(r.get("status")) && (error == null ? !r.containsKey("error") : error.equals(r.get("error")));
    }

    /** XORs 01 into byte 20 of the decoded value and encodes it again. */
    static String flipByte20(String b64) {
        byte[] d = Base64.getDecoder().decode(b64);
        d[20] ^= 1;
        return Base64.getEncoder().encodeToString(d);
    }

    // ------------------------------------------------------------------------------------------------ tests
    // VAULT-01
    /** save_key: one provider call with the key, a row without the key, the answer shape, a key_saved audit row. */
    static void testSaveHappyPath() {
        Fx fx = new Fx();
        Map<String, Object> r = fx.vault.saveKey("user_1", "acme", KEY);
        check(is(r, 200, null) && "acme".equals(r.get("provider")) && "WXYZ".equals(r.get("hint")) && "k1".equals(r.get("key_id"))
                && Long.valueOf(fx.now).equals(r.get("created_at")) && r.size() == 5, "answer " + r);
        check(fx.client.calls.equals(List.of("acme|" + KEY)), "provider called once with the key");
        ByokKeyVault.KeyRow row = fx.store.get("user_1", "acme");
        check(row.keyId().equals("k1") && !row.wrappedDek().isEmpty() && !row.ciphertext().isEmpty() && row.hint().equals("WXYZ"), "row");
        check(!row.toString().contains(KEY) && !row.toString().contains("k3y0123456789"), "the row holds no key");
        List<Map<String, Object>> audit = fx.vault.listAudit("user_1");
        check(audit.size() == 1 && "key_saved".equals(audit.get(0).get("action")) && "k1".equals(audit.get(0).get("key_id")), "audit " + audit);
        check(!audit.toString().contains(KEY), "audit holds no key");
    }

    // VAULT-02
    /** Known answer: the spec's ciphertext and wrapped_dek; use_key returns the key. */
    static void testKnownAnswer() {
        Fx fx = new Fx();
        fx.rnd.add(seq(0x20, 32));
        fx.rnd.add(seq(0x60, 12));
        fx.rnd.add(seq(0x70, 12));
        check(is(fx.vault.saveKey("user_1", "acme", KEY), 200, null), "saved");
        ByokKeyVault.KeyRow row = fx.store.get("user_1", "acme");
        check(row.ciphertext().equals("YGFiY2RlZmdoaWprg/fAzqy7SCzJdVWPIX9FTko++mAiaT2vbM/uMNaLHZjhWoVBGl1vBtJurMStRQ=="), "ciphertext " + row.ciphertext());
        check(row.wrappedDek().equals("cHFyc3R1dnd4eXp7N6aYBJfsuhNsAxz5/W2f+J0G974wrnqNnbcDf3iKKAEOSVqlT/aJkU58qxAv2nPf"), "wrapped_dek " + row.wrappedDek());
        Map<String, Object> u = fx.vault.useKey("user_1", "acme", "chat.completion");
        check(is(u, 200, null) && KEY.equals(u.get("key")), "use_key returns the key");
    }

    // VAULT-03
    /** unknown_provider and every invalid_key_format; the provider is not called and nothing is stored. */
    static void testRefusalsBeforeProvider() {
        Fx fx = new Fx();
        check(is(fx.vault.saveKey("user_1", "nope", KEY), 404, "unknown_provider"), "unknown provider");
        String[] bad = {"beta_" + "k3y0123456789abcdefghWXYZ", "acme_" + "short", "acme_" + "x".repeat(196),
            "acme_" + "k3y0123456789 abcdefghWXYZ", "acme_" + "k3y0123456789\nabcdefghWXYZ", KEY + " ", KEY + "\u000b", KEY + "\u0000", null};
        for (String b : bad) {
            check(is(fx.vault.saveKey("user_1", "acme", b), 400, "invalid_key_format"), "invalid_key_format for " + (b == null ? "null" : b.replace("\n", "\\n")));
        }
        check(fx.client.calls.isEmpty(), "the provider was never called");
        check(fx.store.get("user_1", "acme") == null && fx.store.allAudit().isEmpty(), "nothing stored");
        Map<String, Object> ok = fx.vault.saveKey("user_1", "acme", " \t" + KEY + "\r\n");
        check(is(ok, 200, null) && "WXYZ".equals(ok.get("hint")), "space, tab, CR and LF are trimmed");
        check(fx.client.calls.equals(List.of("acme|" + KEY)), "the trimmed key is checked");
        check(is(fx.vault.saveKey("user_1", "acme", "acme_" + "x".repeat(195)), 200, null), "200 characters accepted");
    }

    // VAULT-04
    /** rejected -> 400 key_rejected; unreachable, other answers, raised errors -> 502; no row, no audit; counted. */
    static void testProviderAnswers() {
        Fx fx = new Fx();
        fx.client.answer = "rejected";
        check(is(fx.vault.saveKey("user_1", "acme", KEY), 400, "key_rejected"), "rejected");
        for (String a : new String[] {"unreachable", "maybe", "throw"}) {
            fx.client.answer = a;
            check(is(fx.vault.saveKey("user_1", "acme", KEY), 502, "provider_unreachable"), "unreachable for " + a);
        }
        check(fx.store.get("user_1", "acme") == null && fx.store.allAudit().isEmpty(), "no row and no audit row");
        for (int i = 0; i < 6; i++) check(fx.store.bumpWindow("user_1", 1699920000L), "window slot " + i);
        check(!fx.store.bumpWindow("user_1", 1699920000L), "the 4 checks were counted (10 in all)");
    }

    // VAULT-05
    /** list_keys: the five fields, sorted by provider, and nothing secret in its serialized form. */
    static void testListKeys() {
        Fx fx = new Fx();
        fx.vault.saveKey("user_1", "beta", "beta_" + "k3y0123456789abcdefgh1234");
        fx.vault.saveKey("user_1", "acme", KEY);
        fx.now += 5;
        fx.vault.useKey("user_1", "acme", "x");
        List<Map<String, Object>> l = fx.vault.listKeys("user_1");
        check(l.size() == 2 && "acme".equals(l.get(0).get("provider")) && "beta".equals(l.get(1).get("provider")), "sorted " + l);
        check(l.get(0).keySet().equals(new java.util.LinkedHashSet<>(List.of("provider", "hint", "key_id", "created_at", "last_used_at"))), "fields");
        check(Long.valueOf(fx.now).equals(l.get(0).get("last_used_at")) && l.get(1).get("last_used_at") == null, "last_used_at");
        String s = l.toString();
        ByokKeyVault.KeyRow row = fx.store.get("user_1", "acme");
        check(!s.contains(KEY) && !s.contains(row.ciphertext()) && !s.contains(row.wrappedDek()) && !s.contains("k3y0123456789"), "serialized form " + s);
    }

    // VAULT-06
    /** use_key: the key, last_used_at, a key_used audit row with the purpose; invalid_purpose; storage_failed: no key. */
    static void testUseKey() {
        Fx fx = new Fx();
        fx.vault.saveKey("user_1", "acme", KEY);
        fx.now += 100;
        Map<String, Object> u = fx.vault.useKey("user_1", "acme", "chat:completion-v1.2_x");
        check(is(u, 200, null) && KEY.equals(u.get("key")), "use_key");
        check(Long.valueOf(fx.now).equals(fx.store.get("user_1", "acme").lastUsedAt()), "last_used_at = clock");
        List<Map<String, Object>> a = fx.vault.listAudit("user_1");
        check(a.size() == 2 && "key_used".equals(a.get(1).get("action")) && "chat:completion-v1.2_x".equals(a.get(1).get("purpose")), "audit " + a);
        for (String p : new String[] {"", "has space", "slash/no", "é", "x".repeat(101), null}) {
            check(is(fx.vault.useKey("user_1", "acme", p), 400, "invalid_purpose"), "invalid purpose " + p);
        }
        fx.store.failWrites = true;
        Map<String, Object> f = fx.vault.useKey("user_1", "acme", "x");
        check(is(f, 500, "storage_failed") && !f.containsKey("key"), "storage_failed with no key " + f);
        fx.store.failWrites = false;
        check(fx.vault.listAudit("user_1").size() == 2, "the failed use wrote no audit row");
        String all = fx.store.allAudit().toString() + fx.vault.listAudit("user_1") + f;
        check(!all.contains(KEY), "no audit row and no refusal holds the key");
    }

    // VAULT-07
    /** Another user's list is empty, use is 404 and delete is false; A's key stays. */
    static void testIsolation() {
        Fx fx = new Fx();
        fx.vault.saveKey("user_A", "acme", KEY);
        check(fx.vault.listKeys("user_B").isEmpty(), "B's list is empty");
        check(is(fx.vault.useKey("user_B", "acme", "x"), 404, "key_not_found"), "B cannot use A's key");
        Map<String, Object> d = fx.vault.deleteKey("user_B", "acme");
        check(Boolean.FALSE.equals(d.get("deleted")), "B cannot delete A's key");
        check(KEY.equals(fx.vault.useKey("user_A", "acme", "x").get("key")), "A's key is untouched");
    }

    // VAULT-08
    /** Moved, edited or malformed rows are 500 key_unreadable, never an exception. */
    static void testTamperedRows() {
        Fx fx = new Fx();
        fx.vault.saveKey("user_1", "acme", KEY);
        ByokKeyVault.KeyRow r = fx.store.get("user_1", "acme");
        fx.store.put(new ByokKeyVault.KeyRow("user_2", "acme", r.keyId(), r.wrappedDek(), r.ciphertext(), r.hint(), r.createdAt(), null));
        check(is(fx.vault.useKey("user_2", "acme", "x"), 500, "key_unreadable"), "moved to another user");
        fx.store.put(new ByokKeyVault.KeyRow("user_1", "beta", r.keyId(), r.wrappedDek(), r.ciphertext(), r.hint(), r.createdAt(), null));
        check(is(fx.vault.useKey("user_1", "beta", "x"), 500, "key_unreadable"), "moved to another provider");
        String[][] variants = {
            {flipByte20(r.ciphertext()), r.wrappedDek()},
            {r.ciphertext(), flipByte20(r.wrappedDek())},
            {"not base64 !!", r.wrappedDek()},
            {r.ciphertext(), "%%%"},
            {Base64.getEncoder().encodeToString(new byte[27]), r.wrappedDek()},
            {r.ciphertext(), Base64.getEncoder().encodeToString(new byte[10])}};
        for (String[] v : variants) {
            fx.store.put(new ByokKeyVault.KeyRow("user_1", "acme", r.keyId(), v[1], v[0], r.hint(), r.createdAt(), null));
            check(is(fx.vault.useKey("user_1", "acme", "x"), 500, "key_unreadable"), "tampered row " + v[0] + " / " + v[1]);
        }
    }

    // VAULT-09
    /** Saving again replaces the key: one row, a new DEK and nonces, the new hint, the new key. */
    static void testReplace() {
        Fx fx = new Fx();
        fx.vault.saveKey("user_1", "acme", KEY);
        ByokKeyVault.KeyRow a = fx.store.get("user_1", "acme");
        String key2 = "acme_" + "n3wk3y0123456789abcdABCD";
        Map<String, Object> r = fx.vault.saveKey("user_1", "acme", key2);
        check(is(r, 200, null) && "ABCD".equals(r.get("hint")), "second save");
        ByokKeyVault.KeyRow b = fx.store.get("user_1", "acme");
        check(fx.vault.listKeys("user_1").size() == 1, "one row");
        byte[] ca = Base64.getDecoder().decode(a.ciphertext()), cb = Base64.getDecoder().decode(b.ciphertext());
        byte[] wa = Base64.getDecoder().decode(a.wrappedDek()), wb = Base64.getDecoder().decode(b.wrappedDek());
        check(!java.util.Arrays.equals(java.util.Arrays.copyOf(ca, 12), java.util.Arrays.copyOf(cb, 12)), "new data nonce");
        check(!java.util.Arrays.equals(java.util.Arrays.copyOf(wa, 12), java.util.Arrays.copyOf(wb, 12)), "new wrap nonce");
        check(!a.wrappedDek().equals(b.wrappedDek()), "new wrapped DEK");
        check(b.hint().equals("ABCD") && key2.equals(fx.vault.useKey("user_1", "acme", "x").get("key")), "the new key");
    }

    // VAULT-10
    /** Rotation: new saves under k2, rewrap() re-wraps the old row (the spec's string), k1 can then leave. */
    static void testRotation() {
        Fx fx = new Fx();
        fx.rnd.add(seq(0x20, 32));
        fx.rnd.add(seq(0x60, 12));
        fx.rnd.add(seq(0x70, 12));
        fx.vault.saveKey("user_1", "acme", KEY);
        String ct = fx.store.get("user_1", "acme").ciphertext();
        ByokKeyVault v2 = fx.make(keyring("k1", "k2"), "k2");
        String key2 = "beta_" + "k3y0123456789abcdefgh9876";
        check("k2".equals(v2.saveKey("user_2", "beta", key2).get("key_id")), "a new save is wrapped under k2");
        fx.rnd.add(seq(0x80, 12));
        Map<String, Object> rw = v2.rewrap();
        check(Integer.valueOf(1).equals(rw.get("rewrapped")) && Integer.valueOf(0).equals(rw.get("failed")), "rewrap " + rw);
        ByokKeyVault.KeyRow r = fx.store.get("user_1", "acme");
        check(r.keyId().equals("k2") && r.ciphertext().equals(ct), "key_id k2, same ciphertext");
        check(r.wrappedDek().equals("gIGCg4SFhoeIiYqLDX+c5AZRDKRAQ7oDXo+7DcjN++F5UtAjxrdC7+0oX0MOT3cH13mFkfvVnrrN/V6R"), "rewrapped " + r.wrappedDek());
        check("key_rewrapped".equals(v2.listAudit("user_1").get(1).get("action")), "audit key_rewrapped");
        ByokKeyVault v3 = fx.make(keyring("k2"), "k2");
        check(KEY.equals(v3.useKey("user_1", "acme", "x").get("key")) && key2.equals(v3.useKey("user_2", "beta", "x").get("key")), "every key opens without k1");
        check(!fx.store.rewrap("user_1", "acme", "k2", "other", "stale-value", fx.now), "conditional rewrap write: no row changed");
        check(fx.store.get("user_1", "acme").wrappedDek().equals(r.wrappedDek()), "row unchanged");
    }

    /**
     * A Store that delegates to an InMemoryStore but whose rewrap write throws for one user, as a database error
     * would. Why: the rewrap gap of review findings 4525344188 / 4525344204. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    static final class FailingRewrapStore implements ByokKeyVault.Store {
        final ByokKeyVault.InMemoryStore inner;
        final String failUser;

        /** In: the store to delegate to, the user whose rewrap write throws. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
         *  Every Store method below carries @Override so a change to the interface fails to compile here (code-quality
         *  review on PR 22). */
        FailingRewrapStore(ByokKeyVault.InMemoryStore inner, String failUser) {
            this.inner = inner;
            this.failUser = failUser;
        }

        @Override
        public ByokKeyVault.KeyRow get(String u, String p) { return inner.get(u, p); }
        @Override
        public List<ByokKeyVault.KeyRow> listForUser(String u) { return inner.listForUser(u); }
        @Override
        public List<ByokKeyVault.KeyRow> listAll() { return inner.listAll(); }
        @Override
        public void saveWithAudit(ByokKeyVault.KeyRow row, String action, long at) { inner.saveWithAudit(row, action, at); }
        @Override
        public void markUsedWithAudit(String u, String p, long now, String purpose, String keyId) { inner.markUsedWithAudit(u, p, now, purpose, keyId); }
        @Override
        public boolean deleteWithAudit(String u, String p, long now) { return inner.deleteWithAudit(u, p, now); }
        @Override
        public boolean bumpWindow(String u, long w) { return inner.bumpWindow(u, w); }
        @Override
        public List<ByokKeyVault.AuditRow> audit(String u) { return inner.audit(u); }

        /** Throws for failUser (nothing written); otherwise the real conditional write. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        @Override
        public boolean rewrap(String u, String p, String newKeyId, String newWrapped, String wrappedRead, long now) {
            if (u.equals(failUser)) throw new IllegalStateException("disk I/O error");
            return inner.rewrap(u, p, newKeyId, newWrapped, wrappedRead, now);
        }
    }

    // VAULT-10
    /**
     * A failing row between two good ones: three rows under k1; with k2 active, the middle row's store write throws:
     * rewrap() returns {rewrapped: 2, failed: 1}, the first and third rows are under k2 and open, the middle row is
     * unchanged under k1. Then a random source that is short for the middle row's nonce: again {rewrapped: 2,
     * failed: 1}, and every key still opens. In: none. Out: checks. Why: the rewrap gap of review findings 4525344188
     * / 4525344204, found in Java by the previous fix pass. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: memory only.
     */
    static void testRewrapCountsAFailingRow() {
        String[] users = {"user_1", "user_2", "user_3"};
        Fx fx = new Fx();
        for (String u : users) fx.vault.saveKey(u, "acme", KEY);
        ByokKeyVault.KeyRow before = fx.store.get("user_2", "acme");
        FailingRewrapStore failing = new FailingRewrapStore(fx.store, "user_2");
        ByokKeyVault v2 = new ByokKeyVault(failing, keyring("k1", "k2"), "k2", providers(), fx.client, () -> fx.now, fx.rnd);
        Map<String, Object> rw = v2.rewrap();
        check(Integer.valueOf(2).equals(rw.get("rewrapped")) && Integer.valueOf(1).equals(rw.get("failed")), "a failing store write is counted " + rw);
        check(fx.store.get("user_1", "acme").keyId().equals("k2") && fx.store.get("user_3", "acme").keyId().equals("k2"), "the good rows are under k2");
        check(before.equals(fx.store.get("user_2", "acme")), "the failing row is unchanged");
        for (String u : users) check(KEY.equals(v2.useKey(u, "acme", "x").get("key")), u + " opens");

        Fx fy = new Fx();
        for (String u : users) fy.vault.saveKey(u, "acme", KEY);
        int[] calls = {0};
        IntFunction<byte[]> shortSecond = n -> fy.rnd.apply(++calls[0] == 2 ? n - 1 : n);
        ByokKeyVault w2 = new ByokKeyVault(fy.store, keyring("k1", "k2"), "k2", providers(), fy.client, () -> fy.now, shortSecond);
        Map<String, Object> rw2 = w2.rewrap();
        check(Integer.valueOf(2).equals(rw2.get("rewrapped")) && Integer.valueOf(1).equals(rw2.get("failed")), "a short nonce is counted " + rw2);
        check(fy.store.get("user_2", "acme").keyId().equals("k1"), "the row with the short nonce stays under k1");
        for (String u : users) check(KEY.equals(w2.useKey(u, "acme", "x").get("key")), u + " opens after a short nonce");
    }

    /** Test helper: true when the constructor call fails with this ConfigException code. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static boolean refusedConfig(Runnable r, String code) {
        try {
            r.run();
            return false;
        } catch (ByokKeyVault.ConfigException e) {
            return code.equals(e.code);
        }
    }

    // VAULT-11
    /** key_unavailable for an unknown key id; construction refuses bad master keys and provider configs. */
    static void testKeyUnavailableAndConfig() {
        Fx fx = new Fx();
        fx.vault.saveKey("user_1", "acme", KEY);
        ByokKeyVault.KeyRow r = fx.store.get("user_1", "acme");
        fx.store.put(new ByokKeyVault.KeyRow("user_1", "acme", "k9", r.wrappedDek(), r.ciphertext(), r.hint(), r.createdAt(), null));
        check(is(fx.vault.useKey("user_1", "acme", "x"), 503, "key_unavailable"), "key id not in the keyring");
        Map<String, byte[]> shortKey = new LinkedHashMap<>();
        shortKey.put("k1", seq(0, 31));
        check(refusedConfig(() -> fx.make(shortKey, "k1"), "invalid_master_key"), "31-byte master key");
        check(refusedConfig(() -> fx.make(keyring("k1"), "k2"), "invalid_master_key"), "active id not in the keyring");
        Map<String, byte[]> badId = new LinkedHashMap<>();
        badId.put("bad id!", seq(0, 32));
        check(refusedConfig(() -> fx.make(badId, "bad id!"), "invalid_master_key"), "malformed key id");
        Map<String, ByokKeyVault.ProviderConfig> p = new LinkedHashMap<>();
        p.put("acme", new ByokKeyVault.ProviderConfig("acme_", 20, 200));
        check(refusedConfig(() -> new ByokKeyVault(fx.store, keyring("k1"), "k1", p, fx.client, () -> 0L, null), "invalid_provider_config"),
                "min_length 20 is under 5 + 16");
    }

    // VAULT-12
    /** 10 provider checks per user per clock hour; the 11th is 429 with retry_after; other users and hours unaffected. */
    static void testHourlyLimit() {
        Fx fx = new Fx();
        check(is(fx.vault.saveKey("user_1", "acme", "acme_" + "bad"), 400, "invalid_key_format"), "malformed key");
        for (int i = 0; i < 10; i++) {
            fx.now = 1699920000L + i * 10;
            check(is(fx.vault.saveKey("user_1", "acme", KEY), 200, null), "save " + i);
        }
        int calls = fx.client.calls.size();
        fx.now = 1699920000L + 1000;
        Map<String, Object> r = fx.vault.saveKey("user_1", "acme", KEY);
        check(is(r, 429, "rate_limited") && Long.valueOf(2600).equals(r.get("retry_after")), "11th " + r);
        check(fx.client.calls.size() == calls, "the 11th calls no provider");
        check(is(fx.vault.saveKey("user_2", "acme", KEY), 200, null), "another user is not affected");
        fx.now = 1699923600L;
        check(is(fx.vault.saveKey("user_1", "acme", KEY), 200, null), "the next hour works");
        ByokKeyVault.InMemoryStore s = new ByokKeyVault.InMemoryStore();
        for (int i = 0; i < 10; i++) check(s.bumpWindow("u", 1699920000L), "window write " + i);
        check(!s.bumpWindow("u", 1699920000L), "the 11th window write changes no row");
    }

    // VAULT-13
    /** delete_key removes the row with key_deleted; again is false with no audit row; use is then 404. */
    static void testDelete() {
        Fx fx = new Fx();
        fx.vault.saveKey("user_1", "acme", KEY);
        Map<String, Object> d = fx.vault.deleteKey("user_1", "acme");
        check(is(d, 200, null) && Boolean.TRUE.equals(d.get("deleted")), "deleted");
        check(fx.store.get("user_1", "acme") == null, "row gone");
        List<Map<String, Object>> a = fx.vault.listAudit("user_1");
        check(a.size() == 2 && "key_deleted".equals(a.get(1).get("action")), "key_deleted " + a);
        check(Boolean.FALSE.equals(fx.vault.deleteKey("user_1", "acme").get("deleted")), "second delete false");
        check(fx.vault.listAudit("user_1").size() == 2, "no audit row for the second delete");
        check(is(fx.vault.useKey("user_1", "acme", "x"), 404, "key_not_found"), "then 404");
    }

    // VAULT-14
    /** With real randomness the same key for two users gives different ciphertexts, wrapped DEKs and nonces. */
    static void testRealRandomness() {
        ByokKeyVault.InMemoryStore st = new ByokKeyVault.InMemoryStore();
        FakeClient c = new FakeClient();
        ByokKeyVault v = new ByokKeyVault(st, keyring("k1"), "k1", providers(), c, () -> 1699920000L, null);
        v.saveKey("user_1", "acme", KEY);
        v.saveKey("user_2", "acme", KEY);
        ByokKeyVault.KeyRow a = st.get("user_1", "acme"), b = st.get("user_2", "acme");
        check(!a.ciphertext().equals(b.ciphertext()) && !a.wrappedDek().equals(b.wrappedDek()), "different ciphertext and wrapped DEK");
        byte[] ca = Base64.getDecoder().decode(a.ciphertext()), cb = Base64.getDecoder().decode(b.ciphertext());
        byte[] wa = Base64.getDecoder().decode(a.wrappedDek()), wb = Base64.getDecoder().decode(b.wrappedDek());
        check(!java.util.Arrays.equals(java.util.Arrays.copyOf(ca, 12), java.util.Arrays.copyOf(cb, 12))
                && !java.util.Arrays.equals(java.util.Arrays.copyOf(wa, 12), java.util.Arrays.copyOf(wb, 12)), "different nonces");
        check(KEY.equals(v.useKey("user_1", "acme", "x").get("key")) && KEY.equals(v.useKey("user_2", "acme", "x").get("key")), "both open");
    }
}

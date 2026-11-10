// Tests for the BYOK key vault template (docs/specs/byok_key_vault.md, VAULT-01..VAULT-14), with the spec's fixed
// vectors. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1, owner request 2026-11-10).
// Offline: a fake provider client, an injected clock and injected random bytes; the in-memory store. Touches: process
// memory only. Key-shaped values are built from pieces at run time.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using AOI.ByokKeyVault;

/// <summary>The VAULT-01..VAULT-14 tests, run by Main (a console harness). Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.</summary>
public static class ByokKeyVaultTests
{
    private static int _failures;
    private static int _checks;

    /// <summary>Runs every test and returns 1 when any check failed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the console.</summary>
    public static int Main()
    {
        TestSaveKeyHappyPath();
        TestKnownAnswer();
        TestKeyFormatRefusals();
        TestProviderVerdicts();
        TestListKeys();
        TestUseKey();
        TestIsolation();
        TestTamperedRows();
        TestSaveAgainReplaces();
        TestRotation();
        TestKeyUnavailableAndConstruction();
        TestHourlyWindow();
        TestDeleteKey();
        TestRealRandomness();
        Console.WriteLine($"\n=== Results: {_checks} checks, {_failures} failures ===");
        return _failures > 0 ? 1 : 0;
    }

    /// <summary>Counts one check; prints FAIL with the message when it is false. Touches: the console. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static void Check(bool condition, string message)
    {
        _checks++;
        if (!condition) { _failures++; Console.WriteLine("FAIL: " + message); }
    }

    /// <summary>Counts one equality check; prints both values on failure. Touches: the console. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static void Eq<T>(T expected, T actual, string message)
    {
        _checks++;
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            _failures++;
            Console.WriteLine($"FAIL: {message} -- expected <{expected}>, got <{actual}>");
        }
    }

    /// <summary>count bytes start, start+1, ... Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static byte[] Range(int start, int count) => Enumerable.Range(start, count).Select(i => (byte)i).ToArray();
    private static readonly byte[] K1 = Range(0x00, 32);
    private static readonly byte[] K2 = Range(0x40, 32);
    private static readonly string Key = "acme_" + "k3y0123456789abcdefghWXYZ";
    private static readonly string BetaKey = "beta_" + "Zz9876543210zyxwvutsrQRST";

    /// <summary>A provider client that records its calls and answers Verdict (or throws when Throw is set). No network. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private sealed class FakeProvider : IProviderClient
    {
        public List<(string Provider, string Key)> Calls = new List<(string, string)>();
        public string Verdict = "ok";
        public bool Throw;
        /// <summary>Records the call and answers Verdict, or throws when Throw is set. Touches: process memory. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public string Check(string provider, string key)
        {
            Calls.Add((provider, key));
            if (Throw) throw new InvalidOperationException("network down");
            return Verdict;
        }
    }

    /// <summary>random_bytes serving queued bytes in order whatever n is asked. Touches: process memory. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private sealed class ByteQueue
    {
        private readonly Queue<byte> _q = new Queue<byte>();
        /// <summary>Queues bytes to serve. Touches: process memory. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public void Add(params byte[][] parts) { foreach (var p in parts) foreach (var b in p) _q.Enqueue(b); }
        /// <summary>Serves n queued bytes (0x99 once the queue is empty). Touches: process memory. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public byte[] Take(int n) => Enumerable.Range(0, n).Select(_ => _q.Count > 0 ? _q.Dequeue() : (byte)0x99).ToArray();
    }

    /// <summary>The vault under test with its store, provider, clock and byte queue. Touches: process memory. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private sealed class Rig
    {
        public InMemoryVaultStore Store = new InMemoryVaultStore();
        public FakeProvider Provider = new FakeProvider();
        public ByteQueue Bytes = new ByteQueue();
        public long Now = 1699920000;
        public ByokKeyVault Vault;

        /// <summary>The test providers acme and beta (prefix + 19 minimum). Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public static Dictionary<string, ProviderConfig> Providers() => new Dictionary<string, ProviderConfig>
        {
            ["acme"] = new ProviderConfig { Prefix = "acme_", MinLength = 24, MaxLength = 200 },
            ["beta"] = new ProviderConfig { Prefix = "beta_", MinLength = 24, MaxLength = 200 },
        };

        /// <summary>A k1 vault over a fresh store; random bytes from the queue, or the CSPRNG when realRandom. Touches: process memory. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public Rig(bool realRandom = false)
        {
            Vault = Build(new Dictionary<string, byte[]> { ["k1"] = K1 }, "k1", realRandom);
        }

        /// <summary>A vault over this rig's store with another keyring. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public ByokKeyVault Build(Dictionary<string, byte[]> keys, string active, bool realRandom = false) =>
            new ByokKeyVault(Store, keys, active, Providers(), Provider, () => Now, realRandom ? null : n => Bytes.Take(n));
    }

    /// <summary>The JSON form of a value, to search it for leaks. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static string Json(object o) => JsonSerializer.Serialize(o);

    /// <summary>
    /// save_key: one provider check with the key; the row holds key_id, wrapped_dek, ciphertext and hint WXYZ and nowhere
    /// the key; the answer is {provider, hint, key_id, created_at}; an audit row key_saved exists. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // VAULT-01
    public static void TestSaveKeyHappyPath()
    {
        var rig = new Rig();
        rig.Bytes.Add(Range(0x20, 32), Range(0x60, 12), Range(0x70, 12));
        var r = rig.Vault.SaveKey("user_1", "acme", "  " + Key + "\r\n");
        Eq(200, r.Status, "status");
        Eq(("acme", "WXYZ", "k1", (long?)1699920000), (r.Provider, r.Hint, r.KeyId, r.CreatedAt), "answer");
        Eq(null, r.Key, "the answer never holds the key");
        Eq(1, rig.Provider.Calls.Count, "one provider check");
        Eq(("acme", Key), rig.Provider.Calls[0], "checked with the trimmed key");
        var row = rig.Store.GetRow("user_1", "acme");
        Check(row != null && row.KeyId == "k1" && row.WrappedDek.Length > 0 && row.Ciphertext.Length > 0 && row.Hint == "WXYZ", "row fields");
        Check(!Json(row).Contains(Key) && !Json(row).Contains("k3y0123456789abcdefgh"), "the key is nowhere in the row");
        var audit = rig.Vault.ListAudit("user_1");
        Eq(1, audit.Count, "one audit row");
        Eq(("key_saved", "acme", "k1", 1699920000L), (audit[0].Action, audit[0].Provider, audit[0].KeyId, audit[0].At), "key_saved");
        Check(!Json(audit).Contains(Key), "the audit row never holds the key");
    }

    /// <summary>
    /// Known answer: with k1, the spec's random bytes and key, the stored ciphertext and wrapped_dek are the spec's two
    /// strings and use_key returns the key. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // VAULT-02
    public static void TestKnownAnswer()
    {
        var rig = new Rig();
        rig.Bytes.Add(Range(0x20, 32), Range(0x60, 12), Range(0x70, 12));
        Check(rig.Vault.SaveKey("user_1", "acme", Key).Ok, "saved");
        var row = rig.Store.GetRow("user_1", "acme");
        Eq("YGFiY2RlZmdoaWprg/fAzqy7SCzJdVWPIX9FTko++mAiaT2vbM/uMNaLHZjhWoVBGl1vBtJurMStRQ==", row.Ciphertext, "ciphertext");
        Eq("cHFyc3R1dnd4eXp7N6aYBJfsuhNsAxz5/W2f+J0G974wrnqNnbcDf3iKKAEOSVqlT/aJkU58qxAv2nPf", row.WrappedDek, "wrapped_dek");
        Eq(Key, rig.Vault.UseKey("user_1", "acme", "chat").Key, "use_key returns the key");
    }

    /// <summary>
    /// unknown provider 404; wrong prefix, too short, too long, a space or line break inside, not text (null) and a key
    /// followed by U+00A0, U+000B or U+0000 are 400 invalid_key_format; the provider is never called and nothing is
    /// stored. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // VAULT-03
    public static void TestKeyFormatRefusals()
    {
        var rig = new Rig();
        var unknown = rig.Vault.SaveKey("user_1", "nope", Key);
        Eq((404, "unknown_provider"), (unknown.Status, unknown.Error), "unknown provider");
        var bad = new[]
        {
            "beta_" + "k3y0123456789abcdefghWXYZ", "acme_" + "k3y0123456789abcd", "acme_" + new string('a', 196),
            "acme_" + "k3y01234 56789abcdefghWXYZ", "acme_" + "k3y01234\n56789abcdefghWXYZ", null,
            Key + " ", Key + "\u000b", Key + "\u0000", "acme_" + "k3y0123456789abcdéfghWXYZ",
        };
        foreach (var k in bad)
        {
            var r = rig.Vault.SaveKey("user_1", "acme", k);
            Eq((400, "invalid_key_format"), (r.Status, r.Error), "refused: " + (k == null ? "null" : k.Length.ToString()));
        }
        Eq(0, rig.Provider.Calls.Count, "the provider is never called");
        Eq(0, rig.Store.AllRows().Count, "nothing stored");
        Eq(0, rig.Store.AllAudit().Count, "no audit row");
        Check(rig.Vault.SaveKey("user_1", "acme", "acme_" + new string('a', 195)).Ok, "exactly max_length (200) is accepted");
        Check(rig.Vault.SaveKey("user_2", "acme", "acme_" + new string('a', 19)).Ok, "exactly min_length (24) is accepted");
    }

    /// <summary>
    /// "rejected" is 400 key_rejected; "unreachable", another answer or a raised error is 502 provider_unreachable; no
    /// row and no audit row is written, and the check is still counted. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: process memory.
    /// </summary>
    // VAULT-04
    public static void TestProviderVerdicts()
    {
        var rig = new Rig();
        rig.Provider.Verdict = "rejected";
        Eq((400, "key_rejected"), (rig.Vault.SaveKey("user_1", "acme", Key).Status, rig.Vault.SaveKey("user_1", "acme", Key).Error), "rejected");
        foreach (var v in new[] { "unreachable", "maybe" })
        {
            rig.Provider.Verdict = v;
            var r = rig.Vault.SaveKey("user_1", "acme", Key);
            Eq((502, "provider_unreachable"), (r.Status, r.Error), v);
        }
        rig.Provider.Throw = true;
        var thrown = rig.Vault.SaveKey("user_1", "acme", Key);
        Eq((502, "provider_unreachable"), (thrown.Status, thrown.Error), "a raised error");
        Eq(0, rig.Store.AllRows().Count, "no row");
        Eq(0, rig.Store.AllAudit().Count, "no audit row");
        rig.Provider.Throw = false;
        rig.Provider.Verdict = "ok";
        // 5 checks were counted above: 5 more fit in the hour, the 11th is refused
        for (var i = 0; i < 5; i++) Check(rig.Vault.SaveKey("user_1", "acme", Key).Ok, $"save {i + 6} of the hour");
        Eq(429, rig.Vault.SaveKey("user_1", "acme", Key).Status, "the refused checks were counted");
    }

    /// <summary>
    /// list_keys returns provider, hint, key_id, created_at and last_used_at sorted by provider; serialized it holds
    /// neither the key nor the ciphertext nor wrapped_dek. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    /// </summary>
    // VAULT-05
    public static void TestListKeys()
    {
        var rig = new Rig(realRandom: true);
        rig.Vault.SaveKey("user_1", "beta", BetaKey);
        rig.Now += 5;
        rig.Vault.SaveKey("user_1", "acme", Key);
        rig.Now += 5;
        rig.Vault.UseKey("user_1", "acme", "chat");
        var list = rig.Vault.ListKeys("user_1");
        Eq("acme,beta", string.Join(",", list.Select(l => l.Provider)), "sorted by provider");
        Eq(("WXYZ", "k1", 1699920005L, (long?)1699920010), (list[0].Hint, list[0].KeyId, list[0].CreatedAt, list[0].LastUsedAt), "acme entry");
        Eq(("QRST", (long?)null), (list[1].Hint, list[1].LastUsedAt), "beta entry");
        var json = Json(list);
        foreach (var row in rig.Store.AllRows())
            Check(!json.Contains(row.Ciphertext) && !json.Contains(row.WrappedDek), "no ciphertext or wrapped_dek in the listing");
        Check(!json.Contains(Key) && !json.Contains(BetaKey), "no key in the listing");
    }

    /// <summary>
    /// use_key returns the key, sets last_used_at and writes key_used with the purpose; an empty purpose or one with a
    /// character outside [A-Za-z0-9_.:-] is 400 invalid_purpose; when the audit write fails it is 500 storage_failed
    /// with no key; no audit row and no refusal holds the key. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: process memory.
    /// </summary>
    // VAULT-06
    public static void TestUseKey()
    {
        var rig = new Rig(realRandom: true);
        rig.Vault.SaveKey("user_1", "acme", Key);
        rig.Now += 42;
        var r = rig.Vault.UseKey("user_1", "acme", "chat.completion:v1-x_y");
        Eq((200, Key), (r.Status, r.Key), "use_key");
        Eq((long?)(1699920042), rig.Store.GetRow("user_1", "acme").LastUsedAt, "last_used_at");
        var used = rig.Vault.ListAudit("user_1").Last();
        Eq(("key_used", "chat.completion:v1-x_y", 1699920042L), (used.Action, used.Purpose, used.At), "key_used audit row");
        var refusals = new List<VaultResult>();
        foreach (var p in new[] { "", null, "bad purpose", "slash/no", new string('a', 101), "café" })
        {
            var bad = rig.Vault.UseKey("user_1", "acme", p);
            Eq((400, "invalid_purpose"), (bad.Status, bad.Error), "purpose refused");
            refusals.Add(bad);
        }
        rig.Store.FailAuditWrites = true;
        rig.Now += 10;
        var failed = rig.Vault.UseKey("user_1", "acme", "chat");
        Eq((500, "storage_failed", (string)null), (failed.Status, failed.Error, failed.Key), "audit failure: no key");
        Eq((long?)(1699920042), rig.Store.GetRow("user_1", "acme").LastUsedAt, "last_used_at unchanged");
        refusals.Add(failed);
        Check(!Json(refusals).Contains(Key) && !Json(rig.Store.AllAudit()).Contains(Key), "no refusal and no audit row holds the key");
    }

    /// <summary>
    /// Isolation: user B's list is empty, use_key for A's provider is 404 key_not_found and delete_key is {deleted:
    /// false}; A's key is untouched. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // VAULT-07
    public static void TestIsolation()
    {
        var rig = new Rig(realRandom: true);
        rig.Vault.SaveKey("user_a", "acme", Key);
        Eq(0, rig.Vault.ListKeys("user_b").Count, "B's list is empty");
        var use = rig.Vault.UseKey("user_b", "acme", "chat");
        Eq((404, "key_not_found"), (use.Status, use.Error), "B cannot use A's key");
        Eq((bool?)false, rig.Vault.DeleteKey("user_b", "acme").Deleted, "B cannot delete A's key");
        Eq(Key, rig.Vault.UseKey("user_a", "acme", "chat").Key, "A's key is untouched");
        Check(rig.Vault.ListAudit("user_b").Count == 0, "no audit row for B");
    }

    /// <summary>Decodes base64, XORs 01 into byte 20 and encodes again. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static string Flip20(string b64)
    {
        var raw = Convert.FromBase64String(b64);
        raw[20] ^= 0x01;
        return Convert.ToBase64String(raw);
    }

    /// <summary>
    /// A row moved to another user or provider, a changed byte of the decoded ciphertext or wrapped_dek, a value that is
    /// not base64 and one that is too short each make use_key 500 key_unreadable, never an exception. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // VAULT-08
    public static void TestTamperedRows()
    {
        var rig = new Rig(realRandom: true);
        rig.Vault.SaveKey("user_a", "acme", Key);
        var original = rig.Store.GetRow("user_a", "acme");
        var cases = new List<(string Name, ProviderKeyRow Row)>();
        var moved = original.Copy(); moved.UserId = "user_b"; cases.Add(("moved to another user", moved));
        var otherProvider = original.Copy(); otherProvider.Provider = "beta"; cases.Add(("moved to another provider", otherProvider));
        var ct = original.Copy(); ct.Ciphertext = Flip20(ct.Ciphertext); cases.Add(("changed ciphertext byte", ct));
        var wd = original.Copy(); wd.WrappedDek = Flip20(wd.WrappedDek); cases.Add(("changed wrapped_dek byte", wd));
        var notB64 = original.Copy(); notB64.Ciphertext = "not base64 !!"; cases.Add(("ciphertext not base64", notB64));
        var notB64w = original.Copy(); notB64w.WrappedDek = "%%%"; cases.Add(("wrapped_dek not base64", notB64w));
        var shortCt = original.Copy(); shortCt.Ciphertext = Convert.ToBase64String(new byte[27]); cases.Add(("ciphertext too short", shortCt));
        var shortWd = original.Copy(); shortWd.WrappedDek = Convert.ToBase64String(new byte[10]); cases.Add(("wrapped_dek too short", shortWd));
        foreach (var (name, row) in cases)
        {
            rig.Store.PutRow(original);
            rig.Store.PutRow(row);
            VaultResult r;
            try { r = rig.Vault.UseKey(row.UserId, row.Provider, "chat"); }
            catch (Exception e) { Check(false, name + " threw " + e.GetType().Name); continue; }
            Eq((500, "key_unreadable", (string)null), (r.Status, r.Error, r.Key), name);
        }
    }

    /// <summary>
    /// Saving again for the same provider replaces the key: one row, a new DEK and new nonces, the new hint, and use_key
    /// returns the new key. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // VAULT-09
    public static void TestSaveAgainReplaces()
    {
        var rig = new Rig();
        rig.Bytes.Add(Range(0x20, 32), Range(0x60, 12), Range(0x70, 12));
        rig.Vault.SaveKey("user_1", "acme", Key);
        var first = rig.Store.GetRow("user_1", "acme");
        rig.Bytes.Add(Range(0xa0, 32), Range(0xc0, 12), Range(0xd0, 12));
        var second = "acme_" + "n3wK3yValue0000000000ABCD";
        Eq("ABCD", rig.Vault.SaveKey("user_1", "acme", second).Hint, "new hint");
        Eq(1, rig.Store.AllRows().Count, "one row");
        var row = rig.Store.GetRow("user_1", "acme");
        Check(Convert.FromBase64String(row.Ciphertext).Take(12).SequenceEqual(Range(0xc0, 12)), "new data nonce");
        Check(Convert.FromBase64String(row.WrappedDek).Take(12).SequenceEqual(Range(0xd0, 12)), "new wrap nonce");
        Check(row.WrappedDek != first.WrappedDek && row.Ciphertext != first.Ciphertext, "new DEK, new ciphertext");
        Eq(second, rig.Vault.UseKey("user_1", "acme", "chat").Key, "use_key returns the new key");
    }

    /// <summary>
    /// Rotation: with k2 active a new save is wrapped under k2; rewrap() re-wraps the k1 row, keeps its ciphertext,
    /// returns (1, 0) and stores the spec's string; with k1 removed every key still opens; the store's rewrap write
    /// changes nothing when wrapped_dek moved on. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // VAULT-10
    public static void TestRotation()
    {
        var rig = new Rig();
        rig.Bytes.Add(Range(0x20, 32), Range(0x60, 12), Range(0x70, 12));
        rig.Vault.SaveKey("user_1", "acme", Key);
        var before = rig.Store.GetRow("user_1", "acme");
        var both = new Dictionary<string, byte[]> { ["k1"] = K1, ["k2"] = K2 };
        var fresh = rig.Build(both, "k2", realRandom: true);
        Eq("k2", fresh.SaveKey("user_2", "beta", BetaKey).KeyId, "a new save is wrapped under k2");
        var rotating = rig.Build(both, "k2");
        rig.Bytes.Add(Range(0x80, 12));
        Eq((1, 0), rotating.Rewrap(), "rewrap() = {rewrapped: 1, failed: 0}");
        var after = rig.Store.GetRow("user_1", "acme");
        Eq("k2", after.KeyId, "key_id k2");
        Eq(before.Ciphertext, after.Ciphertext, "ciphertext unchanged");
        Eq("gIGCg4SFhoeIiYqLDX+c5AZRDKRAQ7oDXo+7DcjN++F5UtAjxrdC7+0oX0MOT3cH13mFkfvVnrrN/V6R", after.WrappedDek, "the spec's rewrapped string");
        Eq("key_rewrapped", rig.Vault.ListAudit("user_1").Last().Action, "key_rewrapped audit row");
        var onlyK2 = rig.Build(new Dictionary<string, byte[]> { ["k2"] = K2 }, "k2");
        Eq(Key, onlyK2.UseKey("user_1", "acme", "chat").Key, "the rewrapped key opens without k1");
        Eq(BetaKey, onlyK2.UseKey("user_2", "beta", "chat").Key, "the k2 key opens");
        Eq((0, 0), onlyK2.Rewrap(), "nothing left to rewrap");
        Check(!rig.Store.Rewrap("user_1", "acme", "k2", "x", before.WrappedDek, 0), "a stale wrapped_dek changes no row");
        Eq(after.WrappedDek, rig.Store.GetRow("user_1", "acme").WrappedDek, "row unchanged");
    }

    /// <summary>
    /// A row whose key_id is not in the keyring is 503 key_unavailable; a master key that is not 32 bytes, a malformed
    /// key id or an active id not in the keyring fails construction (invalid_master_key); a provider with min_length
    /// under its prefix + 16 fails with invalid_provider_config. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: process memory.
    /// </summary>
    // VAULT-11
    public static void TestKeyUnavailableAndConstruction()
    {
        var rig = new Rig(realRandom: true);
        rig.Vault.SaveKey("user_1", "acme", Key);
        var row = rig.Store.GetRow("user_1", "acme");
        row.KeyId = "k9";
        rig.Store.PutRow(row);
        var r = rig.Vault.UseKey("user_1", "acme", "chat");
        Eq((503, "key_unavailable"), (r.Status, r.Error), "unknown key id");

        // Builds a vault; out: the VaultConfigException code, or null when it was built. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        string Refused(Func<ByokKeyVault> build)
        {
            try { build(); return null; }
            catch (VaultConfigException e) { return e.Code; }
        }
        var acme = Rig.Providers();
        var client = new FakeProvider();
        Eq("invalid_master_key", Refused(() => new ByokKeyVault(new InMemoryVaultStore(), new Dictionary<string, byte[]> { ["k1"] = new byte[31] }, "k1", acme, client)), "31-byte master key");
        Eq("invalid_master_key", Refused(() => new ByokKeyVault(new InMemoryVaultStore(), new Dictionary<string, byte[]> { ["k1"] = K1 }, "k2", acme, client)), "active id not in the keyring");
        Eq("invalid_master_key", Refused(() => new ByokKeyVault(new InMemoryVaultStore(), new Dictionary<string, byte[]> { ["bad id"] = K1 }, "bad id", acme, client)), "malformed key id");
        var low = new Dictionary<string, ProviderConfig> { ["acme"] = new ProviderConfig { Prefix = "acme_", MinLength = 20, MaxLength = 200 } };
        Eq("invalid_provider_config", Refused(() => new ByokKeyVault(new InMemoryVaultStore(), new Dictionary<string, byte[]> { ["k1"] = K1 }, "k1", low, client)), "min_length under prefix + 16");
        var okCfg = new Dictionary<string, ProviderConfig> { ["acme"] = new ProviderConfig { Prefix = "acme_", MinLength = 21, MaxLength = 200 } };
        Eq(null, Refused(() => new ByokKeyVault(new InMemoryVaultStore(), new Dictionary<string, byte[]> { ["k1"] = K1 }, "k1", okCfg, client)), "min_length = prefix + 16 is accepted");
    }

    /// <summary>
    /// At most 10 provider checks per user per clock hour: the 11th is 429 rate_limited with retry_after and calls no
    /// provider; another user is not affected; the next hour works; a malformed key does not count; the store's window
    /// write succeeds 10 times in one hour and not an 11th. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    /// </summary>
    // VAULT-12
    public static void TestHourlyWindow()
    {
        var rig = new Rig(realRandom: true) { Now = 1699920000 };
        for (var i = 0; i < 3; i++) Eq(400, rig.Vault.SaveKey("user_1", "acme", "acme_short").Status, "a malformed key");
        for (var i = 0; i < 10; i++)
        {
            rig.Now = 1699920000 + i * 60;
            Check(rig.Vault.SaveKey("user_1", "acme", Key).Ok, $"check {i + 1} of the hour");
        }
        var calls = rig.Provider.Calls.Count;
        rig.Now = 1699920000 + 3000;
        var limited = rig.Vault.SaveKey("user_1", "acme", Key);
        Eq((429, "rate_limited", (long?)600), (limited.Status, limited.Error, limited.RetryAfter), "the 11th is rate limited");
        Eq(calls, rig.Provider.Calls.Count, "and calls no provider");
        Check(rig.Vault.SaveKey("user_2", "acme", Key).Ok, "another user is not affected");
        rig.Now = 1699923600;
        Check(rig.Vault.SaveKey("user_1", "acme", Key).Ok, "the next hour works again");

        var store = new InMemoryVaultStore();
        for (var i = 0; i < 10; i++) Check(store.BumpSaveWindow("u", 1699920000), $"window write {i + 1}");
        Check(!store.BumpSaveWindow("u", 1699920000), "the 11th window write changes nothing");
    }

    /// <summary>
    /// delete_key removes the row and writes key_deleted; a second delete is {deleted: false} with no audit row; use_key
    /// is then 404 key_not_found. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // VAULT-13
    public static void TestDeleteKey()
    {
        var rig = new Rig(realRandom: true);
        rig.Vault.SaveKey("user_1", "acme", Key);
        Eq((bool?)true, rig.Vault.DeleteKey("user_1", "acme").Deleted, "deleted");
        Check(rig.Store.GetRow("user_1", "acme") == null, "row removed");
        Eq("key_saved,key_deleted", string.Join(",", rig.Vault.ListAudit("user_1").Select(a => a.Action)), "key_deleted audited");
        Eq((bool?)false, rig.Vault.DeleteKey("user_1", "acme").Deleted, "second delete");
        Eq(2, rig.Vault.ListAudit("user_1").Count, "no audit row for the second delete");
        Eq((404, "key_not_found"), (rig.Vault.UseKey("user_1", "acme", "chat").Status, rig.Vault.UseKey("user_1", "acme", "chat").Error), "use_key after delete");
    }

    /// <summary>
    /// With real randomness the same key saved for two users gives different ciphertext, wrapped_dek and nonces.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory, the system CSPRNG.
    /// </summary>
    // VAULT-14
    public static void TestRealRandomness()
    {
        var rig = new Rig(realRandom: true);
        rig.Vault.SaveKey("user_1", "acme", Key);
        rig.Vault.SaveKey("user_2", "acme", Key);
        var a = rig.Store.GetRow("user_1", "acme");
        var b = rig.Store.GetRow("user_2", "acme");
        Check(a.Ciphertext != b.Ciphertext, "different ciphertext");
        Check(a.WrappedDek != b.WrappedDek, "different wrapped_dek");
        Check(!Convert.FromBase64String(a.Ciphertext).Take(12).SequenceEqual(Convert.FromBase64String(b.Ciphertext).Take(12)), "different data nonces");
        Check(!Convert.FromBase64String(a.WrappedDek).Take(12).SequenceEqual(Convert.FromBase64String(b.WrappedDek).Take(12)), "different wrap nonces");
        Eq(Key, rig.Vault.UseKey("user_2", "acme", "chat").Key, "both open");
    }
}

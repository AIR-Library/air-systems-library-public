// Tests for the TOTP two-factor template (docs/specs/totp_two_factor.md, TOTP-01..TOTP-14), with the spec's fixed
// vectors. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1, owner request 2026-11-10).
// Offline: an injected clock and an injected queue of random bytes; the in-memory store. Touches: process memory only.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AOI.TotpTwoFactor;

/// <summary>The TOTP-01..TOTP-14 tests, run by Main (a console harness). Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.</summary>
public static class TotpTwoFactorTests
{
    private static int _failures;
    private static int _checks;

    /// <summary>Runs every test and returns 1 when any check failed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the console.</summary>
    public static int Main()
    {
        TestHotpAndTotpVectors();
        TestBase32();
        TestEnrollStartStoresOnlySealedSecret();
        TestEnrollConfirmRecoveryCodes();
        TestVerifyWindow();
        TestReplayGuard();
        TestInputShapes();
        TestRecoveryCodeSignIn();
        TestLockAfterFiveFailures();
        TestUnreadableSecret();
        TestSealOpenAndConstruction();
        TestDisable();
        TestNotEnrolledAndIsolation();
        TestHardLock();
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

    private static readonly byte[] K = Encoding.ASCII.GetBytes("12345678901234567890");
    private static readonly byte[] EncKey = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] RecKey = Enumerable.Range(0x40, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] Nonce = Enumerable.Range(0xa0, 12).Select(i => (byte)i).ToArray();

    /// <summary>
    /// random_bytes for tests: serves queued bytes in order whatever n is asked, then the CSPRNG once the queue is empty;
    /// counts the bytes drawn. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    private sealed class ByteQueue
    {
        private readonly Queue<byte> _q = new Queue<byte>();
        public int Drawn;
        /// <summary>Queues bytes to serve. Touches: process memory. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public void Add(IEnumerable<byte> bytes) { foreach (var b in bytes) _q.Enqueue(b); }
        /// <summary>Serves n bytes: queued ones first, then the CSPRNG; counts them. Touches: process memory. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public byte[] Take(int n)
        {
            var r = new byte[n];
            for (var i = 0; i < n; i++) r[i] = _q.Count > 0 ? _q.Dequeue() : RandomNumberGenerator.GetBytes(1)[0];
            Drawn += n;
            return r;
        }
    }

    /// <summary>One system under test with its store, clock and byte queue. Touches: process memory. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private sealed class Rig
    {
        public InMemoryTotpStore Store = new InMemoryTotpStore();
        public ByteQueue Bytes = new ByteQueue();
        public long Now = 1111111000;
        public TotpTwoFactor Sys;
        /// <summary>A system over a fresh store, the movable clock and the byte queue. Touches: process memory. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public Rig(string issuer = "Example App") { Sys = new TotpTwoFactor(Store, EncKey, RecKey, issuer, () => Now, n => Bytes.Take(n)); }

        /// <summary>The current code for a secret at the rig's clock (hotp is proven by TOTP-01). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public string Code(byte[] secret, long offsetSteps = 0) => TotpTwoFactor.Hotp(secret, Now / 30 + offsetSteps);

        /// <summary>Enrolls and confirms a user with this secret at the current clock. Out: the recovery codes. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public List<string> Enroll(string user, byte[] secret)
        {
            Bytes.Add(secret);
            Bytes.Add(Nonce);
            var s = Sys.EnrollStart(user, user + "@example.com");
            if (!s.Ok) throw new Exception("enroll_start failed: " + s.Error);
            var c = Sys.EnrollConfirm(user, Code(secret));
            if (!c.Ok) throw new Exception("enroll_confirm failed: " + c.Error);
            return c.RecoveryCodes;
        }

        /// <summary>A 6-digit code that matches none of the window's three steps. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public string Wrong(byte[] secret)
        {
            var window = new[] { Code(secret, -1), Code(secret), Code(secret, 1) };
            for (var v = 0; ; v++)
            {
                var c = v.ToString("D6");
                if (!window.Contains(c)) return c;
            }
        }
    }

    /// <summary>Lower-case hex of bytes. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    /// <summary>
    /// hotp gives the RFC 4226 values for counters 0-9 and 4294967296; totp_at gives the RFC 6238 SHA-1 values in 8 and 6
    /// digits, T = 20000000000 included. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
    /// </summary>
    // TOTP-01
    public static void TestHotpAndTotpVectors()
    {
        var expected = new[] { "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489" };
        for (var c = 0; c < 10; c++) Eq(expected[c], TotpTwoFactor.Hotp(K, c), $"hotp(K, {c})");
        Eq("999456", TotpTwoFactor.Hotp(K, 4294967296L), "hotp(K, 2^32) uses all 8 counter bytes");
        var secret = TotpTwoFactor.Base32Encode(K);
        var rows = new (long T, string D8, string D6)[]
        {
            (59, "94287082", "287082"), (1111111109, "07081804", "081804"), (1111111111, "14050471", "050471"),
            (1234567890, "89005924", "005924"), (2000000000, "69279037", "279037"), (20000000000, "65353130", "353130"),
        };
        foreach (var (t, d8, d6) in rows)
        {
            Eq(d8, TotpTwoFactor.TotpAt(secret, t, 8), $"totp_at({t}, 8)");
            Eq(d6, TotpTwoFactor.TotpAt(secret, t, 6), $"totp_at({t}, 6)");
        }
    }

    /// <summary>
    /// base32: the RFC 4648 vectors encode without padding and decode back; decode ignores spaces, dashes, "=" and case;
    /// a bad character, an empty text and a length of 1, 3 or 6 mod 8 are invalid; generate_secret is 32 characters that
    /// decode to 20 bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
    /// </summary>
    // TOTP-02
    public static void TestBase32()
    {
        Eq("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", TotpTwoFactor.Base32Encode(K), "base32(K)");
        var vectors = new[] { ("", ""), ("f", "MY"), ("fo", "MZXQ"), ("foo", "MZXW6"), ("foob", "MZXW6YQ"), ("fooba", "MZXW6YTB"), ("foobar", "MZXW6YTBOI") };
        foreach (var (plain, enc) in vectors)
        {
            Eq(enc, TotpTwoFactor.Base32Encode(Encoding.ASCII.GetBytes(plain)), $"encode '{plain}'");
            if (plain.Length > 0) Eq(plain, Encoding.ASCII.GetString(TotpTwoFactor.Base32Decode(enc)), $"decode '{enc}'");
        }
        Eq("foobar", Encoding.ASCII.GetString(TotpTwoFactor.Base32Decode("mzxw 6ytb-oi==")), "decode ignores space, dash, = and case");
        Eq("f", Encoding.ASCII.GetString(TotpTwoFactor.Base32Decode("MZ")), "decode MZ");
        foreach (var bad in new[] { "MZXW6YT1", "", "M", "MZX", "MZXW6Y", "MZ!W" })
            Check(TotpTwoFactor.Base32Decode(bad) == null, $"'{bad}' is invalid_base32");
        var rig = new Rig();
        var gen = rig.Sys.GenerateSecret();
        Eq(32, gen.Length, "generate_secret length");
        Eq(20, TotpTwoFactor.Base32Decode(gen).Length, "generate_secret decodes to 20 bytes");
    }

    /// <summary>
    /// enroll_start returns the secret and the exact otpauth URI; the store holds only the spec's sealed string, never
    /// the base32 text; a second enroll_start before confirming replaces the secret. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // TOTP-03
    public static void TestEnrollStartStoresOnlySealedSecret()
    {
        var rig = new Rig("Example App");
        rig.Bytes.Add(K);
        rig.Bytes.Add(Nonce);
        var r = rig.Sys.EnrollStart("user_1", "alice@example.com");
        Eq(200, r.Status, "enroll_start status");
        Eq("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", r.Secret, "secret");
        Eq("otpauth://totp/Example%20App%3Aalice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example%20App&algorithm=SHA1&digits=6&period=30", r.OtpauthUri, "otpauth URI");
        var row = rig.Store.GetEnrollment("user_1");
        Eq("v1.oKGio6SlpqeoqaqroV0maQKFQOklPLSHVjWKjzfpA1TV+QA621cV0i7kP1B5d8k2owRGDhH/FzF0f662", row.SecretEnc, "stored sealed secret");
        Check(!row.SecretEnc.Contains(r.Secret), "the store never holds the base32 secret");
        Check(row.ConfirmedAt == null, "unconfirmed");

        rig.Bytes.Add(Encoding.ASCII.GetBytes("abcdefghijabcdefghij"));
        rig.Bytes.Add(Nonce);
        var again = rig.Sys.EnrollStart("user_1", "alice@example.com");
        Eq(TotpTwoFactor.Base32Encode(Encoding.ASCII.GetBytes("abcdefghijabcdefghij")), again.Secret, "the second secret");
        Check(again.Ok && again.Secret != r.Secret, "a second enroll_start draws a new secret");
        Check(rig.Store.GetEnrollment("user_1").SecretEnc != row.SecretEnc, "and replaces the stored one");
        Check(rig.Sys.EnrollConfirm("user_1", TotpTwoFactor.Hotp(K, rig.Now / 30)).Status == 401, "the first secret's code no longer confirms");
        Check(rig.Sys.EnrollConfirm("user_1", TotpTwoFactor.TotpAt(again.Secret, rig.Now)).Ok, "the new secret's code confirms");
    }

    /// <summary>
    /// enroll_confirm returns 8 codes shaped xxxx-xxxx-xxxx and stores only their keyed hashes; the confirming code is
    /// then refused by verify; second confirm, confirm with nothing started and enroll_start after confirming are 409;
    /// with the spec's byte stream the codes and the first stored hash are the spec's, and 101 bytes are drawn.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // TOTP-04
    public static void TestEnrollConfirmRecoveryCodes()
    {
        var rig = new Rig();
        Eq("enrollment_not_started", rig.Sys.EnrollConfirm("user_1", "123456").Error, "confirm with nothing started");
        Eq(409, rig.Sys.EnrollConfirm("user_1", "123456").Status, "409");
        rig.Bytes.Add(K);
        rig.Bytes.Add(Nonce);
        rig.Sys.EnrollStart("user_1", "alice");
        var before = rig.Bytes.Drawn;
        rig.Bytes.Add(Enumerable.Range(0, 200).Select(k => (byte)((7 * k) % 256)));
        var code = rig.Code(K);
        var r = rig.Sys.EnrollConfirm("user_1", code);
        Eq(200, r.Status, "confirm ok");
        var expected = new[]
        {
            "29gq-y7en-w5ck", "t3ah-rz8f-px6d", "mv4b-js29-gqy5", "ckt3-ahrz-8fpx",
            "6dmv-4bjs-29gq", "y7en-w5ck-t8fp", "x6dm-v4bj-s29g", "qy7e-nw5c-kt3a",
        };
        Eq(string.Join(" ", expected), string.Join(" ", r.RecoveryCodes), "the spec's 8 codes");
        Eq(101, rig.Bytes.Drawn - before, "101 bytes drawn");
        Check(r.RecoveryCodes.All(c => Regex.IsMatch(c, "^[23456789abcdefghjkmnpqrstvwxyz]{4}-[23456789abcdefghjkmnpqrstvwxyz]{4}-[23456789abcdefghjkmnpqrstvwxyz]{4}$")), "shape xxxx-xxxx-xxxx");
        var stored = rig.Store.RecoveryCodes("user_1");
        Eq(8, stored.Count, "8 rows");
        Eq("d9199ecad0b35d9e2f18857343d7fe79dd5f8425f1c460c88fe18f5c4b4a2645", stored[0].CodeHash, "stored hash of the first code");
        Check(stored.All(s => r.RecoveryCodes.All(c => !s.CodeHash.Contains(c.Replace("-", "")))), "no code stored in clear");
        Eq("invalid_code", rig.Sys.Verify("user_1", code).Error, "the confirming code is refused by verify");
        Eq("already_enrolled", rig.Sys.EnrollConfirm("user_1", code).Error, "second confirm");
        Eq(409, rig.Sys.EnrollConfirm("user_1", code).Status, "second confirm 409");
        Eq("already_enrolled", rig.Sys.EnrollStart("user_1", "alice").Error, "enroll_start after confirm");
        Eq(409, rig.Sys.EnrollStart("user_1", "alice").Status, "enroll_start after confirm 409");
    }

    /// <summary>
    /// The window vector: confirmed at 1111111000, at 1111111109 the codes two steps back and two ahead are 401 (checked
    /// first), then the previous, current and next steps' codes are accepted in that order. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // TOTP-05
    public static void TestVerifyWindow()
    {
        var rig = new Rig { Now = 1111111000 };
        rig.Enroll("user_1", K);
        rig.Now = 1111111109;
        foreach (var refused in new[] { "150727", "266759" })
        {
            var r = rig.Sys.Verify("user_1", refused);
            Eq((401, "invalid_code"), (r.Status, r.Error), $"{refused} is outside the window");
        }
        foreach (var accepted in new[] { "731029", "081804", "050471" })
        {
            var r = rig.Sys.Verify("user_1", accepted);
            Eq((200, "totp"), (r.Status, r.Method), $"{accepted} is accepted");
        }
    }

    /// <summary>
    /// Replay: an accepted code is 401 the second time; once a step is accepted an earlier step's code is 401 and a
    /// later step's code is accepted; the store's claim succeeds once per step. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // TOTP-06
    public static void TestReplayGuard()
    {
        var rig = new Rig { Now = 1111111000 };
        rig.Enroll("user_1", K);
        rig.Now = 1111111109;
        Check(rig.Sys.Verify("user_1", "081804").Ok, "current code accepted");
        Eq(401, rig.Sys.Verify("user_1", "081804").Status, "the same code again is 401");
        Eq(401, rig.Sys.Verify("user_1", "731029").Status, "an earlier step's code is 401");
        Check(rig.Sys.Verify("user_1", "050471").Ok, "a later step's code is accepted");

        var store = new InMemoryTotpStore();
        store.ReplaceUnconfirmed("u", "v1.x", 0);
        store.Confirm("u", 0, 10, "v1.x");
        Check(store.Claim("u", 11), "claim of step 11 succeeds");
        Check(!store.Claim("u", 11), "the second claim of step 11 changes nothing");
        Check(!store.Claim("u", 10), "an older step changes nothing");
    }

    /// <summary>
    /// Input: "081 804" and "081-804" are accepted like "081804" (each on a fresh enrollment); 5 digits, 7 digits,
    /// letters, empty, missing, over 64 characters and non-ASCII digits are 401 invalid_code (no exception) and each
    /// adds one failure (each on its own user). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // TOTP-07
    public static void TestInputShapes()
    {
        var rig = new Rig { Now = 1111111000 };
        var spellings = new[] { "081804", "081 804", "081-804" };
        for (var i = 0; i < spellings.Length; i++) rig.Enroll("ok" + i, K);
        var bad = new[] { "12345", "1234567", "abcdef", "", null, new string('1', 65), "٠٨١٨٠٤" };
        for (var i = 0; i < bad.Length; i++) rig.Enroll("bad" + i, K);
        rig.Now = 1111111109;
        for (var i = 0; i < spellings.Length; i++)
            Check(rig.Sys.Verify("ok" + i, spellings[i]).Ok, $"'{spellings[i]}' accepted");
        for (var i = 0; i < bad.Length; i++)
        {
            TotpResult r = null;
            try { r = rig.Sys.Verify("bad" + i, bad[i]); }
            catch (Exception e) { Check(false, $"input #{i} threw {e.GetType().Name}"); continue; }
            Eq((401, "invalid_code"), (r.Status, r.Error), $"input #{i} is invalid_code");
            Eq(1, rig.Store.FailureCount("bad" + i), $"input #{i} adds one failure row");
            Eq(1, rig.Store.GetEnrollment("bad" + i).FailedSinceSuccess, $"input #{i} adds one to failed_since_success");
        }
    }

    /// <summary>
    /// A recovery code signs in once (recovery_code, 7 left), also typed upper case or without dashes (each its own
    /// code); used again it is 401; user A's code is 401 for user B; the stored hash is the spec's keyed hash, not a
    /// plain SHA-256. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // TOTP-08
    public static void TestRecoveryCodeSignIn()
    {
        var rig = new Rig();
        Eq("5a93360f78c7f03de7336a625adf93bf238749d8da4aaf734271b327c52347a3", rig.Sys.RecoveryCodeHash("user_1", "k7mq2xpt9hcw"), "the spec's keyed hash");
        var codesA = rig.Enroll("user_1", K);
        var codesB = rig.Enroll("user_2", Encoding.ASCII.GetBytes("abcdefghijabcdefghij"));
        var r = rig.Sys.Verify("user_1", codesA[0]);
        Eq((200, "recovery_code", 7), (r.Status, r.Method, r.RecoveryCodesLeft), "first use");
        Eq((401, "invalid_code"), (rig.Sys.Verify("user_1", codesA[0]).Status, rig.Sys.Verify("user_1", codesA[0]).Error), "used again");
        var upper = rig.Sys.Verify("user_1", codesA[1].ToUpperInvariant());
        Eq(("recovery_code", 6), (upper.Method, upper.RecoveryCodesLeft), "upper case accepted");
        var plain = rig.Sys.Verify("user_1", codesA[2].Replace("-", ""));
        Eq(("recovery_code", 5), (plain.Method, plain.RecoveryCodesLeft), "without dashes accepted");
        Eq(401, rig.Sys.Verify("user_2", codesA[3]).Status, "user A's code is 401 for user B");
        Eq(8, rig.Sys.Status("user_2").RecoveryCodesLeft, "user B's codes untouched");
        var stored = rig.Store.RecoveryCodes("user_1");
        Eq(rig.Sys.RecoveryCodeHash("user_1", codesA[3].Replace("-", "")), stored[3].CodeHash, "stored = keyed hash");
        var plainSha = Hex(SHA256.HashData(Encoding.UTF8.GetBytes("recovery:user_1:" + codesA[3].Replace("-", ""))));
        Check(stored[3].CodeHash != plainSha && stored[3].CodeHash != Hex(SHA256.HashData(Encoding.UTF8.GetBytes(codesA[3]))), "not a plain SHA-256");
        Check(codesB.Count == 8, "user B has its own codes");
    }

    /// <summary>
    /// Lock: after 5 failures inside 900 s the next verify is 429 locked with retry_after, with a correct code too, and
    /// adds no failure; 899 s after the oldest it is still locked; at 900 s a correct code is accepted; the store's try
    /// write succeeds 5 times in a window and not a 6th. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    /// </summary>
    // TOTP-09
    public static void TestLockAfterFiveFailures()
    {
        var rig = new Rig { Now = 1700000000 };
        rig.Enroll("user_1", K);
        var t0 = rig.Now + 100;
        for (var i = 0; i < 5; i++)
        {
            rig.Now = t0 + i;
            Eq(401, rig.Sys.Verify("user_1", rig.Wrong(K)).Status, $"wrong code {i + 1}");
        }
        rig.Now = t0 + 10;
        var locked = rig.Sys.Verify("user_1", rig.Code(K));
        Eq((429, "locked", (long?)890), (locked.Status, locked.Error, locked.RetryAfter), "locked, with a correct code too");
        Eq(5, rig.Store.FailureCount("user_1"), "a locked answer adds no failure");
        Eq(5, rig.Store.GetEnrollment("user_1").FailedSinceSuccess, "nor failed_since_success");
        Eq(t0 + 900, rig.Sys.Status("user_1").LockedUntil, "status.locked_until");
        rig.Now = t0 + 899;
        var still = rig.Sys.Verify("user_1", rig.Code(K));
        Eq((429, (long?)1), (still.Status, still.RetryAfter), "899 s after the oldest it is still locked");
        rig.Now = t0 + 900;
        Check(rig.Sys.Verify("user_1", rig.Code(K)).Ok, "at 900 s a correct code is accepted");

        var store = new InMemoryTotpStore();
        for (var i = 0; i < 5; i++) Check(store.TrySlot("u", 1000 + i) != null, $"try {i + 1} gets a slot");
        Check(store.TrySlot("u", 1010) == null, "the 6th try in the window gets none");
        Check(store.TrySlot("u", 1900) != null, "after the window a slot frees up");
    }

    /// <summary>
    /// A sealed secret that cannot be opened (another key, or one changed character) makes verify 503 secret_unreadable
    /// for a 6-digit code, never not_enrolled or invalid_code, with no failure added; a recovery code still signs in.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // TOTP-10
    public static void TestUnreadableSecret()
    {
        var rig = new Rig();
        var codes = rig.Enroll("user_1", K);
        var original = rig.Store.GetEnrollment("user_1").SecretEnc;
        var otherKey = Enumerable.Range(100, 32).Select(i => (byte)i).ToArray();
        var changed = original.Substring(0, 10) + (original[10] == 'A' ? 'B' : 'A') + original.Substring(11);
        foreach (var bad in new[] { TotpTwoFactor.Seal(otherKey, Nonce, TotpTwoFactor.Base32Encode(K), "totp:user_1"), changed })
        {
            rig.Store.SetSecretEnc("user_1", bad);
            rig.Now += 60;
            var r = rig.Sys.Verify("user_1", rig.Code(K));
            Eq((503, "secret_unreadable"), (r.Status, r.Error), "unreadable secret");
            Eq(0, rig.Store.FailureCount("user_1"), "no failure row");
            Eq(0, rig.Store.GetEnrollment("user_1").FailedSinceSuccess, "no failure counted");
        }
        var rec = rig.Sys.Verify("user_1", codes[0]);
        Eq((200, "recovery_code"), (rec.Status, rec.Method), "a recovery code still signs in");
    }

    /// <summary>
    /// seal with the spec's key, nonce and aad gives the spec's string and open returns the secret; another aad, another
    /// key or one changed character opens nothing; a key of the wrong size is refused at construction (invalid_key).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
    /// </summary>
    // TOTP-11
    public static void TestSealOpenAndConstruction()
    {
        var secret = TotpTwoFactor.Base32Encode(K);
        var sealedText = TotpTwoFactor.Seal(EncKey, Nonce, secret, "totp:user_1");
        Eq("v1.oKGio6SlpqeoqaqroV0maQKFQOklPLSHVjWKjzfpA1TV+QA621cV0i7kP1B5d8k2owRGDhH/FzF0f662", sealedText, "seal vector");
        Eq(secret, TotpTwoFactor.Open(EncKey, sealedText, "totp:user_1"), "open");
        Eq(null, TotpTwoFactor.Open(EncKey, sealedText, "totp:user_2"), "another user's aad");
        Eq(null, TotpTwoFactor.Open(RecKey, sealedText, "totp:user_1"), "another key");
        var changed = sealedText.Substring(0, 20) + (sealedText[20] == 'A' ? 'B' : 'A') + sealedText.Substring(21);
        Eq(null, TotpTwoFactor.Open(EncKey, changed, "totp:user_1"), "one changed character");
        Eq(null, TotpTwoFactor.Open(EncKey, "v2." + sealedText.Substring(3), "totp:user_1"), "no v1. prefix");
        Eq(null, TotpTwoFactor.Open(EncKey, "v1.!!!", "totp:user_1"), "bad base64");
        Eq(null, TotpTwoFactor.Open(EncKey, "v1." + Convert.ToBase64String(new byte[27]), "totp:user_1"), "fewer than 28 bytes");
        foreach (var (enc, rec, name) in new[] { (new byte[31], RecKey, "31-byte encryption key"), (new byte[33], RecKey, "33-byte encryption key"), (EncKey, new byte[31], "31-byte recovery key") })
        {
            string code = null;
            try { new TotpTwoFactor(new InMemoryTotpStore(), enc, rec, "x"); }
            catch (TotpConfigException e) { code = e.Code; }
            Eq("invalid_key", code, name + " is refused");
        }
    }

    /// <summary>
    /// disable with a valid code deletes the enrollment, its recovery codes and its failures, then verify is 409
    /// not_enrolled; disable with a wrong code is 401 and deletes nothing. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: process memory.
    /// </summary>
    // TOTP-12
    public static void TestDisable()
    {
        var rig = new Rig();
        rig.Enroll("user_1", K);
        rig.Now += 60;
        var wrong = rig.Sys.Disable("user_1", rig.Wrong(K));
        Eq((401, "invalid_code"), (wrong.Status, wrong.Error), "disable with a wrong code");
        Check(rig.Store.GetEnrollment("user_1") != null && rig.Store.RecoveryCodes("user_1").Count == 8, "nothing deleted");
        Eq(1, rig.Store.FailureCount("user_1"), "the failure stays");
        var ok = rig.Sys.Disable("user_1", rig.Code(K));
        Check(ok.Ok && ok.Disabled, "disable with a valid code");
        Check(rig.Store.GetEnrollment("user_1") == null, "enrollment deleted");
        Eq(0, rig.Store.RecoveryCodes("user_1").Count, "recovery codes deleted");
        Eq(0, rig.Store.FailureCount("user_1"), "failures deleted");
        Eq((409, "not_enrolled"), (rig.Sys.Verify("user_1", rig.Code(K)).Status, rig.Sys.Verify("user_1", rig.Code(K)).Error), "verify is then not_enrolled");
        Check(!rig.Sys.Status("user_1").Enrolled, "status not enrolled");
    }

    /// <summary>
    /// verify and disable before enroll_confirm are 409 not_enrolled with the right code too; two users with different
    /// secrets never accept each other's codes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // TOTP-13
    public static void TestNotEnrolledAndIsolation()
    {
        var rig = new Rig();
        rig.Bytes.Add(K);
        rig.Bytes.Add(Nonce);
        rig.Sys.EnrollStart("user_1", "a");
        Eq((409, "not_enrolled"), (rig.Sys.Verify("user_1", rig.Code(K)).Status, rig.Sys.Verify("user_1", rig.Code(K)).Error), "verify before confirm");
        Eq((409, "not_enrolled"), (rig.Sys.Disable("user_1", rig.Code(K)).Status, rig.Sys.Disable("user_1", rig.Code(K)).Error), "disable before confirm");
        Eq(0, rig.Store.FailureCount("user_1"), "no try is counted");
        Eq("not_enrolled", rig.Sys.Verify("nobody", "123456").Error, "no row at all");

        var rig2 = new Rig();
        var kb = Encoding.ASCII.GetBytes("abcdefghijabcdefghij");
        rig2.Enroll("a", K);
        rig2.Enroll("b", kb);
        rig2.Now += 300;
        var codeA = rig2.Code(K);
        var codeB = rig2.Code(kb);
        Check(codeA != codeB, "the two secrets give different codes here");
        Eq(401, rig2.Sys.Verify("b", codeA).Status, "A's code is refused for B");
        Eq(401, rig2.Sys.Verify("a", codeB).Status, "B's code is refused for A");
        Check(rig2.Sys.Verify("a", codeA).Ok && rig2.Sys.Verify("b", codeB).Ok, "each user's own code works");
    }

    /// <summary>
    /// Long-run guessing: after 100 failures (20 lock windows of 5) a correct code is 429 recovery_required however far
    /// the clock moves, adding no failure; a recovery code then signs in and a correct code is accepted again; a
    /// success before the 100th failure starts the count again. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: process memory.
    /// </summary>
    // TOTP-14
    public static void TestHardLock()
    {
        var rig = new Rig { Now = 1700000000 };
        var codes = rig.Enroll("user_1", K);
        rig.Now += 900;
        for (var w = 0; w < 20; w++)
        {
            for (var i = 0; i < 5; i++) Eq(401, rig.Sys.Verify("user_1", rig.Wrong(K)).Status, $"window {w} failure {i}");
            rig.Now += 900;
        }
        Eq(100, rig.Store.GetEnrollment("user_1").FailedSinceSuccess, "100 failures counted");
        var r = rig.Sys.Verify("user_1", rig.Code(K));
        Eq((429, "recovery_required", (long?)null), (r.Status, r.Error, r.RetryAfter), "a correct code is recovery_required");
        rig.Now += 10_000_000;
        var rowsBefore = rig.Store.FailureCount("user_1");
        Eq("recovery_required", rig.Sys.Verify("user_1", rig.Code(K)).Error, "however far the clock moves");
        Eq(100, rig.Store.GetEnrollment("user_1").FailedSinceSuccess, "no failure added");
        Eq(rowsBefore, rig.Store.FailureCount("user_1"), "the 429 left no slot row");
        Check(rig.Sys.Status("user_1").RecoveryRequired, "status.recovery_required");
        var rec = rig.Sys.Verify("user_1", codes[0]);
        Eq((200, "recovery_code"), (rec.Status, rec.Method), "a recovery code signs in");
        Eq(0, rig.Store.GetEnrollment("user_1").FailedSinceSuccess, "and resets the count");
        rig.Now += 30;
        Check(rig.Sys.Verify("user_1", rig.Code(K)).Ok, "a correct code is accepted again");

        var rig2 = new Rig { Now = 1700000000 };
        rig2.Enroll("u2", K);
        rig2.Now += 900;
        for (var n = 0; n < 99; n++)
        {
            Eq(401, rig2.Sys.Verify("u2", rig2.Wrong(K)).Status, $"failure {n}");
            if (n % 5 == 4) rig2.Now += 900;
        }
        rig2.Now += 900;
        Check(rig2.Sys.Verify("u2", rig2.Code(K)).Ok, "a success after 99 failures");
        Eq(0, rig2.Store.GetEnrollment("u2").FailedSinceSuccess, "starts the count again");
        rig2.Now += 30;
        Eq(401, rig2.Sys.Verify("u2", rig2.Wrong(K)).Status, "one more failure");
        rig2.Now += 30;
        Check(rig2.Sys.Verify("u2", rig2.Code(K)).Ok, "is not a hard lock");
    }
}

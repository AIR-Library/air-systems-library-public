// Tests for the passwordless email-code sign-in template (docs/specs/passwordless_email_code_signin.md,
// EMAILCODE-01..EMAILCODE-14), with the spec's fixed vectors. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
// (Phase D wave 1, owner request 2026-11-10). Offline: a recording fake sender, an injected clock, injected codes and
// random bytes; the in-memory store. Touches: process memory only.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AOI.PasswordlessEmailCode;

/// <summary>The EMAILCODE-01..EMAILCODE-14 tests, run by Main (a console harness). Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.</summary>
public static class PasswordlessEmailCodeTests
{
    private static int _failures;
    private static int _checks;

    /// <summary>Runs every test and returns 1 when any check failed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the console.</summary>
    public static int Main()
    {
        TestStartAndVerifyHappyPath();
        TestStorageHoldsOnlyKeyedHashes();
        TestSingleUse();
        TestExpiry();
        TestFiveTriesPerCode();
        TestNewStartReplacesCode();
        TestNoEnumeration();
        TestSendsPerAddress();
        TestSendsPerIp();
        TestTriesPerIpAndPerAddress();
        TestInputNormalisation();
        TestSendFailureAndConstruction();
        TestUnavailableAccount();
        TestCodeBindingAndGenerator();
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

    private static readonly byte[] Secret = Encoding.ASCII.GetBytes("0123456789abcdef0123456789abcdef");
    private const string Ip = "203.0.113.7";

    /// <summary>A sender that records its calls; Mode "ok", "false" or "throw". No network. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private sealed class FakeSender : ICodeSender
    {
        public List<(string To, string Code, int ExpiresIn)> Calls = new List<(string, string, int)>();
        public string Mode = "ok";
        /// <summary>Records the call; answers true, false or throws as Mode says. Touches: process memory. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public bool SendCode(string to, string code, int expiresInSeconds)
        {
            Calls.Add((to, code, expiresInSeconds));
            if (Mode == "throw") throw new InvalidOperationException("smtp down");
            return Mode == "ok";
        }
    }

    /// <summary>The system under test, with its store, sender, clock, revoke log and queued codes. Touches: memory. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private sealed class Rig
    {
        public InMemoryEmailCodeStore Store = new InMemoryEmailCodeStore();
        public FakeSender Sender = new FakeSender();
        public long Now = 1699920000;
        public List<string> Revoked = new List<string>();
        public bool RevokeThrows;
        public Queue<string> Codes = new Queue<string>();
        public PasswordlessEmailCode Sys;
        private int _next = 100000;

        /// <summary>A system over a fresh store with the recording sender, the movable clock, the revoke log and queued codes. Touches: process memory. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public Rig()
        {
            Sys = new PasswordlessEmailCode(Store, Secret, Sender, id =>
            {
                Revoked.Add(id);
                if (RevokeThrows) throw new InvalidOperationException("revoke failed");
            }, () => Now, null, () => Codes.Count > 0 ? Codes.Dequeue() : (_next++).ToString("D6"));
        }

        /// <summary>start, then the code the sender got. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public string StartAndCode(string email, string ip = Ip)
        {
            var r = Sys.Start(email, ip);
            if (r.Status != 202) throw new Exception("start refused: " + r.Error);
            return Sender.Calls.Last().Code;
        }
    }

    /// <summary>Lower-case hex of bytes. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
    /// <summary>The JSON form of an answer, to compare two answers whole. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static string Shape(EmailCodeResult r) => JsonSerializer.Serialize(r);

    /// <summary>
    /// start is 202 {sent, expires_in 600} and the sender gets one 6-digit code; verify with it is 200, new_account true,
    /// and the account exists verified; a second sign-in gives the same id, new_account false; an unverified existing
    /// row gets revoke_unproven once and is then verified; an account made by verify never calls it. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // EMAILCODE-01
    public static void TestStartAndVerifyHappyPath()
    {
        var rig = new Rig();
        var s = rig.Sys.Start("user@example.com", Ip);
        Eq((202, true, (int?)600, (string)null), (s.Status, s.Sent, s.ExpiresIn, s.Error), "start answer");
        Eq(1, rig.Sender.Calls.Count, "one email");
        var code = rig.Sender.Calls[0].Code;
        Check(code.Length == 6 && code.All(c => c >= '0' && c <= '9'), "a 6-digit code");
        Eq(("user@example.com", 600), (rig.Sender.Calls[0].To, rig.Sender.Calls[0].ExpiresIn), "sent to the address, valid 600 s");
        var v = rig.Sys.Verify("user@example.com", code, Ip);
        Eq((200, true, "user@example.com"), (v.Status, v.NewAccount, v.Email), "verify answer");
        var acct = rig.Store.AllAccounts().Single();
        Eq((v.AccountId, (long?)rig.Now, "active"), (acct.Id, acct.EmailVerifiedAt, acct.Status), "account created verified");
        Eq(32, acct.Id.Length, "id is 32 hex characters");
        rig.Now += 60;
        var again = rig.Sys.Verify("user@example.com", rig.StartAndCode("user@example.com"), Ip);
        Eq((200, v.AccountId, false), (again.Status, again.AccountId, again.NewAccount), "second sign-in: same account");
        Eq(0, rig.Revoked.Count, "an account made by verify never calls revoke_unproven");

        rig.Store.PutAccount(new Account { Id = "invited_1", Email = "invited@example.com", EmailVerifiedAt = null, Status = "active", CreatedAt = 1 });
        var inv = rig.Sys.Verify("invited@example.com", rig.StartAndCode("invited@example.com"), Ip);
        Eq((200, "invited_1", false), (inv.Status, inv.AccountId, inv.NewAccount), "unverified row signs in");
        Eq("invited_1", string.Join(",", rig.Revoked), "revoke_unproven called once with its id");
        Eq((long?)rig.Now, rig.Store.AllAccounts().Single(a => a.Id == "invited_1").EmailVerifiedAt, "then email_verified_at is set");

        rig.Store.PutAccount(new Account { Id = "invited_2", Email = "second@example.com", EmailVerifiedAt = null, Status = "active", CreatedAt = 1 });
        rig.RevokeThrows = true;
        var failed = rig.Sys.Verify("second@example.com", rig.StartAndCode("second@example.com"), Ip);
        Eq((500, "processing_failed"), (failed.Status, failed.Error), "revoke_unproven raising is 500");
        Eq((long?)null, rig.Store.AllAccounts().Single(a => a.Id == "invited_2").EmailVerifiedAt, "and the row stays unverified");
    }

    /// <summary>
    /// The spec's hashes; start with code 123456 stores exactly that code_hash under that email_hash with the spec's
    /// window keys; neither table holds the address, the IP, the code or a plain SHA-256 of the code. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // EMAILCODE-02
    public static void TestStorageHoldsOnlyKeyedHashes()
    {
        var rig = new Rig();
        Eq("587522269e243312a5d6f20bcdc78dc97a3e644e2ad702cdb94ac9550c03b346", rig.Sys.EmailHash("user@example.com"), "email_hash");
        Eq("761f222c89dc1744c480d21e141277cc9af815ee0e2a1d7489c9282594728b5b", rig.Sys.CodeHash("user@example.com", "123456"), "code_hash");
        Eq("e01c4eeb03c058165d49564dcaf561cf", rig.Sys.IpHash("203.0.113.7"), "ip_hash");
        rig.Codes.Enqueue("123456");
        rig.Sys.Start("user@example.com", "203.0.113.7");
        var row = rig.Store.GetCode("587522269e243312a5d6f20bcdc78dc97a3e644e2ad702cdb94ac9550c03b346");
        Eq("761f222c89dc1744c480d21e141277cc9af815ee0e2a1d7489c9282594728b5b", row?.CodeHash, "stored code_hash");
        Eq(("start-email#587522269e243312a5d6f20bcdc78dc9,start-email-day#587522269e243312a5d6f20bcdc78dc9,start-ip#e01c4eeb03c058165d49564dcaf561cf"),
            string.Join(",", rig.Store.AllWindows().Select(w => w.Key).OrderBy(k => k, StringComparer.Ordinal)), "window keys");
        var dump = JsonSerializer.Serialize(rig.Store.AllCodes()) + JsonSerializer.Serialize(rig.Store.AllWindows().Select(w => new { w.Key, w.WindowStart, w.Count }));
        foreach (var leak in new[] { "user@example.com", "203.0.113.7", "123456", Hex(SHA256.HashData(Encoding.UTF8.GetBytes("123456"))) })
            Check(!dump.Contains(leak), "the tables do not hold " + (leak.Length > 20 ? "the plain SHA-256" : leak));
    }

    /// <summary>The right code a second time is 400 invalid_code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.</summary>
    // EMAILCODE-03
    public static void TestSingleUse()
    {
        var rig = new Rig();
        var code = rig.StartAndCode("user@example.com");
        Eq(200, rig.Sys.Verify("user@example.com", code, Ip).Status, "first use");
        var second = rig.Sys.Verify("user@example.com", code, Ip);
        Eq((400, "invalid_code"), (second.Status, second.Error), "second use");
    }

    /// <summary>Accepted 599 s after start, 400 invalid_code at 600 s. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.</summary>
    // EMAILCODE-04
    public static void TestExpiry()
    {
        var rig = new Rig();
        var t0 = rig.Now;
        var a = rig.StartAndCode("a@example.com");
        var b = rig.StartAndCode("b@example.com");
        rig.Now = t0 + 599;
        Eq(200, rig.Sys.Verify("a@example.com", a, Ip).Status, "599 s");
        rig.Now = t0 + 600;
        var late = rig.Sys.Verify("b@example.com", b, Ip);
        Eq((400, "invalid_code"), (late.Status, late.Error), "600 s");
        Check(rig.Store.GetCode(rig.Sys.EmailHash("b@example.com")) == null, "the expired row is deleted");
    }

    /// <summary>
    /// Five tries per code: after 5 wrong codes the right one is invalid_code; after 4 wrong codes the right one (the 5th
    /// try) is accepted. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // EMAILCODE-05
    public static void TestFiveTriesPerCode()
    {
        var rig = new Rig();
        rig.Codes.Enqueue("111111");
        var code = rig.StartAndCode("five@example.com");
        for (var i = 0; i < 5; i++) Eq(400, rig.Sys.Verify("five@example.com", "00000" + i, Ip).Status, $"wrong {i + 1}");
        Check(rig.Store.GetCode(rig.Sys.EmailHash("five@example.com")) == null, "the 5th wrong try deletes the row");
        Eq((400, "invalid_code"), (rig.Sys.Verify("five@example.com", code, Ip).Status, rig.Sys.Verify("five@example.com", code, Ip).Error), "the right one after 5 wrong");

        rig.Codes.Enqueue("222222");
        var code2 = rig.StartAndCode("four@example.com");
        for (var i = 0; i < 4; i++) Eq(400, rig.Sys.Verify("four@example.com", "00000" + i, Ip).Status, $"wrong {i + 1}");
        Eq(200, rig.Sys.Verify("four@example.com", code2, Ip).Status, "the right one as the 5th try");
    }

    /// <summary>
    /// A new start replaces the code: the earlier code is invalid_code, the new one is accepted, and the tries start at 0.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // EMAILCODE-06
    public static void TestNewStartReplacesCode()
    {
        var rig = new Rig();
        rig.Codes.Enqueue("111111");
        rig.Codes.Enqueue("222222");
        var first = rig.StartAndCode("user@example.com");
        for (var i = 0; i < 3; i++) rig.Sys.Verify("user@example.com", "00000" + i, Ip);
        Eq(3, rig.Store.GetCode(rig.Sys.EmailHash("user@example.com")).Attempts, "3 tries spent");
        var second = rig.StartAndCode("user@example.com");
        Eq(0, rig.Store.GetCode(rig.Sys.EmailHash("user@example.com")).Attempts, "tries start again at 0");
        Eq((400, "invalid_code"), (rig.Sys.Verify("user@example.com", first, Ip).Status, rig.Sys.Verify("user@example.com", first, Ip).Error), "the earlier code");
        for (var i = 0; i < 2; i++) rig.Sys.Verify("user@example.com", "00000" + i, Ip);
        Eq(200, rig.Sys.Verify("user@example.com", second, Ip).Status, "the new code is accepted on its 5th try");
    }

    /// <summary>
    /// No enumeration: start answers the same and the sender gets the same kind of call for a known and an unknown
    /// address, and start never reads accounts; verify gives one 400 body for a wrong, expired, used and never-requested
    /// code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // EMAILCODE-07
    public static void TestNoEnumeration()
    {
        var rig = new Rig();
        rig.Store.PutAccount(new Account { Id = "known", Email = "known@example.com", EmailVerifiedAt = 1, Status = "active", CreatedAt = 1 });
        var known = rig.Sys.Start("known@example.com", Ip);
        var unknown = rig.Sys.Start("unknown@example.com", Ip);
        Eq(Shape(known), Shape(unknown), "the same start answer");
        Eq(0, rig.Store.AccountReads, "start never reads accounts");
        Eq((rig.Sender.Calls[0].Code.Length, rig.Sender.Calls[0].ExpiresIn), (rig.Sender.Calls[1].Code.Length, rig.Sender.Calls[1].ExpiresIn), "the same kind of email");

        var wrong = rig.Sys.Verify("known@example.com", "000000", Ip);
        var usedCode = rig.Sender.Calls[1].Code;
        rig.Sys.Verify("unknown@example.com", usedCode, Ip);
        var used = rig.Sys.Verify("unknown@example.com", usedCode, Ip);
        var never = rig.Sys.Verify("never@example.com", "123456", Ip);
        var expiring = rig.StartAndCode("exp@example.com");
        rig.Now += 600;
        var expired = rig.Sys.Verify("exp@example.com", expiring, Ip);
        foreach (var (name, r) in new[] { ("used", used), ("never requested", never), ("expired", expired) })
            Eq(Shape(wrong), Shape(r), name + " has the same 400 body as a wrong code");
        Eq(400, wrong.Status, "400");
    }

    /// <summary>
    /// Sends per address: the 6th start in a clock hour is 429 and sends nothing; the next hour works; the 11th in a
    /// clock day is 429 (a refused start still counts toward the day). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: process memory.
    /// </summary>
    // EMAILCODE-08
    public static void TestSendsPerAddress()
    {
        var rig = new Rig { Now = 1699920000 };
        for (var i = 0; i < 5; i++) Eq(202, rig.Sys.Start("user@example.com", "198.51.100." + i).Status, $"start {i + 1}");
        var sixth = rig.Sys.Start("user@example.com", "198.51.100.9");
        Eq((429, "too_many_requests"), (sixth.Status, sixth.Error), "6th start in the hour");
        Eq(5, rig.Sender.Calls.Count, "the 6th sends nothing");
        rig.Now = 1699923600;
        for (var i = 0; i < 4; i++) Eq(202, rig.Sys.Start("user@example.com", Ip).Status, $"start {i + 7} (next hour)");
        Eq(429, rig.Sys.Start("user@example.com", Ip).Status, "the 11th of the day");
        Eq(9, rig.Sender.Calls.Count, "9 emails in all");
        rig.Now = 1700006400;
        Eq(202, rig.Sys.Start("user@example.com", Ip).Status, "the next day works");
    }

    /// <summary>
    /// Sends per IP: the 21st start from one IP in a clock hour, each for another address, is 429; another IP is not
    /// affected. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // EMAILCODE-09
    public static void TestSendsPerIp()
    {
        var rig = new Rig { Now = 1699920000 };
        for (var i = 0; i < 20; i++) Eq(202, rig.Sys.Start($"u{i}@example.com", Ip).Status, $"start {i + 1}");
        Eq((429, "too_many_requests"), (rig.Sys.Start("u20@example.com", Ip).Status, rig.Sys.Start("u21@example.com", Ip).Error), "the 21st from the IP");
        Eq(202, rig.Sys.Start("u20@example.com", "198.51.100.1").Status, "another IP");
    }

    /// <summary>
    /// Tries per IP and per address: the 31st verify from one IP in an hour is 429 with the right code too; the 11th
    /// verify for one address in an hour is 429 whatever IP and however many new codes. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // EMAILCODE-10
    public static void TestTriesPerIpAndPerAddress()
    {
        var rig = new Rig { Now = 1699920000 };
        var code = rig.StartAndCode("target@example.com", "198.51.100.1");
        for (var i = 0; i < 30; i++) Eq(400, rig.Sys.Verify($"v{i}@example.com", "123456", Ip).Status, $"verify {i + 1} from the IP");
        var limited = rig.Sys.Verify("target@example.com", code, Ip);
        Eq((429, "too_many_requests"), (limited.Status, limited.Error), "the 31st from the IP, right code");
        Eq(200, rig.Sys.Verify("target@example.com", code, "198.51.100.2").Status, "another IP still signs in");

        var rig2 = new Rig { Now = 1699920000 };
        for (var i = 0; i < 10; i++)
        {
            if (i % 3 == 0) rig2.StartAndCode("addr@example.com", "192.0.2." + i);
            Eq(400, rig2.Sys.Verify("addr@example.com", "000000", "198.51.100." + i).Status, $"verify {i + 1} for the address");
        }
        var fresh = rig2.StartAndCode("addr@example.com", "192.0.2.99");
        var eleventh = rig2.Sys.Verify("addr@example.com", fresh, "198.51.100.200");
        Eq((429, "too_many_requests"), (eleventh.Status, eleventh.Error), "the 11th for the address, a new IP and a new code");
        rig2.Now = 1699923600;
        Eq(200, rig2.Sys.Verify("addr@example.com", rig2.StartAndCode("addr@example.com", "192.0.2.100"), "198.51.100.200").Status, "the next hour signs in");
    }

    /// <summary>
    /// Input: " A@X.com " signs in a@x.com; a malformed address is 422 at start and 400 at verify; only space, tab, CR, LF
    /// are trimmed and only A-Z lower-cased (U+00A0, U+000B, U+0000, U+212A refused); "123 456" and "123-456" are
    /// accepted (each its own code); 5 digits, 7 digits, letters and six non-ASCII digits are 400 and spend no try.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // EMAILCODE-11
    public static void TestInputNormalisation()
    {
        Eq("a@x.com", PasswordlessEmailCode.NormalizeEmail(" A@X.com "), "normalize");
        foreach (var bad in new[] { "a@b", "a b@x.com", "a@x..com", ".a@x.com", "a@x.com,b@y.com", "<a@x.com>", "a@x.com ", "a@x.com\u000b", "a@x.com\u0000", "K@x.com", null, "" })
            Eq(null, PasswordlessEmailCode.NormalizeEmail(bad), "refused: " + (bad == null ? "null" : string.Join(" ", bad.Select(c => ((int)c).ToString("x")))));

        var rig = new Rig();
        var code = rig.StartAndCode(" A@X.com ");
        Eq("a@x.com", rig.Sender.Calls.Last().To, "sent to the normalised address");
        var v = rig.Sys.Verify(" A@X.com ", code, Ip);
        Eq((200, "a@x.com"), (v.Status, v.Email), "signs in a@x.com");
        foreach (var bad in new[] { "a@b", "a@x.com ", "a@x.com\u000b", "a@x.com\u0000", "K@x.com" })
        {
            Eq((422, "invalid_email"), (rig.Sys.Start(bad, Ip).Status, rig.Sys.Start(bad, Ip).Error), "start refuses a malformed address");
            Eq((400, "invalid_code"), (rig.Sys.Verify(bad, "123456", Ip).Status, rig.Sys.Verify(bad, "123456", Ip).Error), "verify refuses it as invalid_code");
        }
        rig.Codes.Enqueue("123456");
        rig.StartAndCode("space@example.com");
        Eq(200, rig.Sys.Verify("space@example.com", "123 456", Ip).Status, "'123 456'");
        rig.Codes.Enqueue("123456");
        rig.StartAndCode("dash@example.com");
        Eq(200, rig.Sys.Verify("dash@example.com", "123-456", Ip).Status, "'123-456'");

        rig.Codes.Enqueue("123456");
        rig.StartAndCode("shape@example.com");
        foreach (var shape in new[] { "12345", "1234567", "abcdef", "١٢٣٤٥٦", null })
        {
            Eq((400, "invalid_code"), (rig.Sys.Verify("shape@example.com", shape, Ip).Status, rig.Sys.Verify("shape@example.com", shape, Ip).Error), "malformed code");
        }
        Eq(0, rig.Store.GetCode(rig.Sys.EmailHash("shape@example.com")).Attempts, "no try of the code spent");
        Eq(200, rig.Sys.Verify("shape@example.com", "123456", Ip).Status, "the code still works");
    }

    /// <summary>
    /// A sender that returns false or raises makes start 503 send_failed and leaves no code; a secret under 32 bytes or
    /// no sender fails construction with not_configured. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    /// </summary>
    // EMAILCODE-12
    public static void TestSendFailureAndConstruction()
    {
        foreach (var mode in new[] { "false", "throw" })
        {
            var rig = new Rig();
            rig.Sender.Mode = mode;
            var r = rig.Sys.Start("user@example.com", Ip);
            Eq((503, "send_failed"), (r.Status, r.Error), "sender " + mode);
            Check(rig.Store.GetCode(rig.Sys.EmailHash("user@example.com")) == null, "no code left (" + mode + ")");
        }
        // Builds a system; out: the EmailCodeConfigException code, or null when it was built. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        string Refused(Func<PasswordlessEmailCode> build)
        {
            try { build(); return null; }
            catch (EmailCodeConfigException e) { return e.Code; }
        }
        Eq("not_configured", Refused(() => new PasswordlessEmailCode(new InMemoryEmailCodeStore(), new byte[31], new FakeSender())), "31-byte secret");
        Eq("not_configured", Refused(() => new PasswordlessEmailCode(new InMemoryEmailCodeStore(), Secret, null)), "no sender");
        Eq(null, Refused(() => new PasswordlessEmailCode(new InMemoryEmailCodeStore(), new byte[32], new FakeSender())), "32 bytes is enough");
    }

    /// <summary>
    /// A suspended or closed account: the right code is 403 account_unavailable and the code is used up. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // EMAILCODE-13
    public static void TestUnavailableAccount()
    {
        var rig = new Rig();
        foreach (var status in new[] { "suspended", "closed" })
        {
            var email = status + "@example.com";
            rig.Store.PutAccount(new Account { Id = status, Email = email, EmailVerifiedAt = 1, Status = status, CreatedAt = 1 });
            var code = rig.StartAndCode(email);
            var r = rig.Sys.Verify(email, code, Ip);
            Eq((403, "account_unavailable", (string)null), (r.Status, r.Error, r.AccountId), status);
            Check(rig.Store.GetCode(rig.Sys.EmailHash(email)) == null, "the code is used up");
            Eq(400, rig.Sys.Verify(email, code, Ip).Status, "and is 400 after");
        }
    }

    /// <summary>
    /// A code for one address is invalid_code for another; an injected "000042" keeps its zeros and signs in; the default
    /// generator gives 6 digits and, with the spec's bytes, "483648", "999999" and "000042". 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // EMAILCODE-14
    public static void TestCodeBindingAndGenerator()
    {
        var rig = new Rig();
        var forA = rig.StartAndCode("a@example.com");
        rig.StartAndCode("b@example.com");
        Eq((400, "invalid_code"), (rig.Sys.Verify("b@example.com", forA, Ip).Status, rig.Sys.Verify("b@example.com", forA, Ip).Error), "a's code is refused for b");
        rig.Codes.Enqueue("000042");
        Eq("000042", rig.StartAndCode("zeros@example.com"), "the sender gets 000042");
        Eq(200, rig.Sys.Verify("zeros@example.com", "000042", Ip).Status, "000042 signs in");

        var bytes = new Queue<byte>(new byte[] { 0xff, 0xff, 0xff, 0xff, 0x80, 0, 0, 0, 0xff, 0xf1, 0x3d, 0x7f, 0xff, 0xf1, 0x3d, 0x80, 0, 0, 0, 0x2a });
        var gen = new PasswordlessEmailCode(new InMemoryEmailCodeStore(), Secret, new FakeSender(), null, () => 0,
            n => Enumerable.Range(0, n).Select(_ => bytes.Dequeue()).ToArray());
        Eq("483648", gen.GenerateCode(), "ff ff ff ff drawn again, then 80 00 00 00");
        Eq("999999", gen.GenerateCode(), "ff f1 3d 7f");
        Eq("000042", gen.GenerateCode(), "ff f1 3d 80 drawn again, then 00 00 00 2a");
        Eq(0, bytes.Count, "every byte used");
        var real = new PasswordlessEmailCode(new InMemoryEmailCodeStore(), Secret, new FakeSender());
        for (var i = 0; i < 50; i++)
        {
            var c = real.GenerateCode();
            Check(c.Length == 6 && c.All(ch => ch >= '0' && ch <= '9'), "default generator: 6 digits 0-9");
        }
    }
}

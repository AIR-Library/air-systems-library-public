// Tests for the secret & PII screening template (docs/specs/secret_pii_screening.md, SCREEN-01..SCREEN-14), with
// every fixed vector of the spec. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1, owner request
// 2026-11-10). Offline. Key-shaped values are built from two or more pieces at run time, as the spec writes them, so
// a repository secret scanner never blocks a commit. Touches: process memory only.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using AOI.SecretPiiScreening;

/// <summary>The SCREEN-01..SCREEN-14 tests, run by Main (a console harness). Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.</summary>
public static class SecretPiiScreeningTests
{
    private static int _failures;
    private static int _checks;

    /// <summary>Runs every test and returns 1 when any check failed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the console.</summary>
    public static int Main()
    {
        TestCleanTexts();
        TestKeyShapes();
        TestPrivateKeys();
        TestBearerAndUrl();
        TestKeyValue();
        TestEmailPhoneSsn();
        TestCards();
        TestIpAddresses();
        TestRejectMode();
        TestStripMode();
        TestOverlapsAndCodePoints();
        TestMaskAndHash();
        TestEscapes();
        TestInputRefusalsAndHostileInputs();
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

    // ------------------------------------------------------------------ the spec's vectors (built from pieces)

    private static readonly string K1 = "sk-" + "abcdEFGH12345678ijklMNOP";
    private static readonly string K2 = "sk_" + "live_" + "A1b2C3d4E5f6G7h8I9j0K1l2";
    private static readonly string K3 = "pk_" + "test_" + "A1b2C3d4E5f6G7h8I9j0K1l2";
    private static readonly string K4 = "AKIA" + "IOSFODNN7EXAMPLE";
    private static readonly string K5 = "ghp_" + "16C7e42F292c6912E7710c838347Ae178B4a";
    private static readonly string K6 = "github_pat_" + "11ABCDEFG0abcdefghij_KLMNOPQRSTUVWXYZ0123456789";
    private static readonly string K7 = "xoxb-" + "1234567890-abcdefghijklmnopqrstuvwx";
    private static readonly string K8 = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q";
    private static readonly string K9 = "whsec_" + "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    private static readonly string J = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0" + "." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    private static readonly string B = "-----BEGIN RSA " + "PRIVATE KEY-----";
    private static readonly string E = "-----END RSA " + "PRIVATE KEY-----";
    private const string L1 = "MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumga0R2LiajO16aI4Uxa2b9nb";
    private const string L2 = "AKELFOxNOFICTIONALKEYMATERIALFORTESTINGPURPOSESONLY1234567890AB";
    private static readonly string P1 = B + "\n" + L1 + "\n" + L2 + "\n" + E;
    private static readonly string P2 = B + "\n" + "Proc-Type: 4,ENCRYPTED\n" + "DEK-Info: AES-256-CBC,A1B2C3D4E5F60718293A4B5C6D7E8F90\n" + "\n" + L1 + "\n" + E;
    private static readonly string P3 = B + "\n" + "api_key=looksLikeASecretButItsJustPemBase64Content\n" + E;
    private static readonly string P4 = B + "\n" + L1 + "\n" + L2 + " (cut";
    private static readonly string G = "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----" + "\nVersion: GnuPG v2\n\n" + L1 + "\n" + L2 + "\n=AbCd\n" + "-----END PGP " + "PRIVATE KEY BLOCK-----";
    private const string T = "Contact jane@example.com or call 555-123-4567 for help.";
    private static readonly byte[] HashKey = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

    /// <summary>s repeated n times. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static string Rep(string s, int n) => string.Concat(Enumerable.Repeat(s, n));

    /// <summary>Every vector that has findings, collected for SCREEN-10's strip-and-rescreen. Filled by the vector tests. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static readonly List<string> WithFindings = new List<string>();

    /// <summary>"label a-b, label c-d" of the findings, or "nothing". Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static string Show(IEnumerable<Finding> fs)
    {
        var list = fs.Select(f => $"{f.Label} {f.Start}-{f.End}").ToList();
        return list.Count == 0 ? "nothing" : string.Join(", ", list);
    }

    /// <summary>
    /// Asserts scan_text's findings for one vector and, for "nothing", that reject mode accepts the text unchanged;
    /// otherwise that reject mode is 422 with the same findings. Touches: process memory.
    /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    private static void Expect(string text, string expected, string id)
    {
        var s = new Screener();
        Eq(expected, Show(s.ScanText(text)), $"{id} scan of [{Shorten(text)}]");
        var r = s.ScreenText(text, "reject");
        if (expected == "nothing")
            Check(r.Ok && r.Text == text && r.Findings.Count == 0, $"{id} reject accepts [{Shorten(text)}] (got {r.Error})");
        else
        {
            Eq((422, "secrets_or_pii_detected", expected), (r.Status, r.Error, Show(r.Findings)), $"{id} reject refuses [{Shorten(text)}]");
            WithFindings.Add(text);
        }
    }

    /// <summary>A short printable form of a text for a failure message. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static string Shorten(string s) => (s.Length > 40 ? s.Substring(0, 40) + "..." : s).Replace("\n", "\\n");

    // ------------------------------------------------------------------ tests

    /// <summary>The four clean texts are {ok: true}, unchanged, findings [] in both modes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    // SCREEN-01
    public static void TestCleanTexts()
    {
        var s = new Screener(HashKey);
        var clean = new[]
        {
            "User: let's plan the export feature.\nAssistant: I built the CSV export button and will add a progress bar.\n",
            "def get_cache_key(user_id):\n    return f'user:{user_id}'\n\nclass TokenBucket:\n    def __init__(self, capacity):\n        self.capacity = capacity\n",
            "Please reset your password before the next login.",
            "version 1.2.3.4.5 released at 12:30:45 on 2026-11-10, build 20261110123045, order 1234567890",
        };
        foreach (var text in clean)
            foreach (var mode in new[] { "reject", "strip" })
            {
                var r = s.ScreenText(text, mode);
                Eq((true, 200, text, 0), (r.Ok, r.Status, r.Text, r.Findings.Count), $"clean text in {mode}: {Shorten(text)}");
            }
    }

    /// <summary>Every key shape with its label and exact span; the four near-misses are not found. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    // SCREEN-02
    public static void TestKeyShapes()
    {
        Expect("here is my key: " + K1, "openai_style_api_key 16-43", "SCREEN-02");
        Expect("STRIPE_KEY=" + K2, "stripe_style_api_key 11-43", "SCREEN-02");
        Expect(K3 + " used in the demo", "stripe_style_api_key 0-32", "SCREEN-02");
        Expect("AWS_ACCESS_KEY_ID=" + K4, "aws_access_key_id 18-38", "SCREEN-02");
        Expect("token: " + K5, "github_token 7-47", "SCREEN-02");
        Expect("use " + K6 + " now", "github_token 4-62", "SCREEN-02");
        Expect(K7, "slack_token 0-40", "SCREEN-02");
        Expect("key=" + K8 + "&x=1", "google_api_key 4-43", "SCREEN-02");
        Expect("secret " + K9 + ".", "webhook_signing_secret 7-45", "SCREEN-02");
        Expect("Authorization token captured: " + J, "jwt 30-162", "SCREEN-02");
        Expect("ASIA" + "IOSFODNN7EXAMPLE", "aws_access_key_id 0-20", "SCREEN-02");
        Expect("task-" + "abcdEFGH12345678ijklMNOP", "nothing", "SCREEN-02");
        Expect("X" + K4, "nothing", "SCREEN-02");
        Expect(K2 + "_x", "nothing", "SCREEN-02");
        Expect("class sk-spinner-three-bounce is used", "nothing", "SCREEN-02");
    }

    /// <summary>Private key blocks: whole, encrypted, cut off, quoted, in a diff, PGP, escaped line breaks; a bare header is not. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    // SCREEN-03
    public static void TestPrivateKeys()
    {
        Expect("a " + P1 + " b", "pem_private_key 2-192", "SCREEN-03");
        Expect(P2, "pem_private_key 0-205", "SCREEN-03");
        Expect(P3, "pem_private_key 0-112", "SCREEN-03");
        Expect("api_key=looksLikeASecretButItsJustPemBase64Content", "generic_key_value_assignment 8-50", "SCREEN-03");
        Expect("x " + P4, "pem_private_key 2-162", "SCREEN-03");
        Expect("-" + B + "\n-" + L1 + "\n-" + L2 + "\n-" + E, "pem_private_key 1-163", "SCREEN-03");
        Expect("> " + B + "\n> " + L1 + "\n> " + L2 + "\n> " + E, "pem_private_key 2-198", "SCREEN-03");
        Expect(G, "pem_private_key 0-227", "SCREEN-03");
        Expect(B + "\n" + Rep("A", 30) + "\\n" + Rep("A", 30), "pem_private_key 0-94", "SCREEN-03");
        Expect(B + "\n" + Rep("A", 29) + "\\n" + Rep("A", 30), "nothing", "SCREEN-03");
        Expect(B + "\n" + Rep("A", 59), "nothing", "SCREEN-03");
        Expect("Look for the line " + B + " in the file.", "nothing", "SCREEN-03");
    }

    /// <summary>Bearer tokens and URL passwords (the token or password is the span); prose, placeholders and URLs without one are not. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    // SCREEN-04
    public static void TestBearerAndUrl()
    {
        Expect("curl -H 'Authorization: Bearer abc123DEF456ghi789JKL'", "bearer_token 31-52", "SCREEN-04");
        Expect("authorization: BEARER abc123DEF456ghi789JKL", "bearer_token 22-43", "SCREEN-04");
        Expect("Bearer authentication is required", "nothing", "SCREEN-04");
        Expect("Bearer " + J, "jwt 7-139", "SCREEN-04");
        Expect("postgres://app:S3cr3t-Pa55@db.internal:5432/app", "url_credentials 15-26", "SCREEN-04");
        Expect("ssh://git:hunter2secret@host/repo", "url_credentials 10-23", "SCREEN-04");
        Expect("https://user:password@example.com/", "nothing", "SCREEN-04");
        Expect("https://jane@example.com/x", "nothing", "SCREEN-04");
        Expect("redis://:Sup3rS3cretValue@cache.example.com:6379/0", "url_credentials 9-25", "SCREEN-04");
        Expect("http://localhost:8080/@foo and https://example.com/a:b@c", "nothing", "SCREEN-04");
        Expect("Our API uses Bearer authentication.", "nothing", "SCREEN-04");
        Expect("Send the header with bearer token-based auth", "nothing", "SCREEN-04");
    }

    /// <summary>key = value secrets in every form, and every reference, placeholder and redacted value that is not one. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    // SCREEN-05
    public static void TestKeyValue()
    {
        const string G13 = "generic_key_value_assignment";
        var found = new (string Text, string Span)[]
        {
            ("DB_PASSWORD=Sup3rS3cretValue!\n", "12-29"), ("internal_api_key: \"zx91-nq7f-88ab-lorem\"", "19-39"),
            ("{\"password\": \"hunter2hunter2\"}", "14-28"), ("{\\\"password\\\":\\\"hunter2hunter2\\\"}", "16-30"),
            ("db_password: CorrectHorseBatteryStaple", "13-38"), ("the db_password: CorrectHorseBatteryStaple9 I mentioned", "17-43"),
            ("password: DOMAIN\\Administrator1", "10-31"), ("API_KEY = 'Zx91Nq7f88ab'", "11-23"), ("token=abc12345;next", "6-14"),
            ("password: p\u00e4ssw\u00f6rd123", "10-21"), (Rep("a", 40) + "token=abc12345def", "46-57"),
            ("'password' => 'Sup3rS3cretValue!',", "15-32"), ("password := \"Sup3rS3cretValue!\"", "13-30"),
            ("password: hunter2!", "10-18"), ("password: P@ss(w0rd)1x", "10-22"), ("token: ab12.cd34.ef56gh78", "7-25"),
            ("\u0130 token=abc12345", "8-16"),
        };
        foreach (var (text, span) in found) Expect(text, G13 + " " + span, "SCREEN-05");
        var nothing = new[]
        {
            Rep("a", 41) + "token=abc12345def", "API_KEY=your_key_here", "password: changeme", "pwd=abc123", "Secret: whatever the team decides",
            "password: WordPress", "My favorite crypto token: Ethereum has been volatile", "class TokenBucket:",
            "Please reset your password before the next login.", "secrets: abc12345def", "password: gr\u00f6\u00dferes",
            "password: [REDACTED:generic_key_value_assignment]", "The password: required.", "token: optional,", "password: changeme.",
            "password: undefined,", "password = os.getenv(\"DB_PASSWORD\")", "api_key = os.environ[\"API_KEY\"]",
            "secret_key = settings.SECRET_KEY", "apiKey: process.env.STRIPE_KEY,", "token = getAccessTokenSilently();",
            "password: req.body.password,", "API_KEY=$API_KEY", "token=${TOKEN}", "api_key: <YOUR_API_KEY>", "Password: ********",
            "token: Optional[str] = None", "password = models.CharField(max_length=128)", "to\u212aen=abc12345def", "password: abcdefgh\u0663",
        };
        foreach (var text in nothing) Expect(text, "nothing", "SCREEN-05");
    }

    /// <summary>Email addresses, phone numbers and SSNs; a bare 10-digit number, an address before "_" and impossible SSNs are not. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    // SCREEN-06
    public static void TestEmailPhoneSsn()
    {
        Expect("Contact jane@example.com or call 555-123-4567 for help.", "email_address 8-24, phone_number 33-45", "SCREEN-06");
        Expect("<jane.doe+tag@mail.example.co.uk>", "email_address 1-32", "SCREEN-06");
        Expect("see https://example.com/contact?email=jane@example.com", "email_address 38-54", "SCREEN-06");
        Expect("call (555) 123-4567 now", "phone_number 5-19", "SCREEN-06");
        Expect("+1 555-123-4567", "phone_number 0-15", "SCREEN-06");
        Expect("reach me at +442071838750.", "phone_number 12-25", "SCREEN-06");
        Expect("SSN 123-45-6789", "ssn 4-15", "SCREEN-06");
        Expect("order 5551234567 shipped", "nothing", "SCREEN-06");
        Expect("jane@example.com_backup", "nothing", "SCREEN-06");
        Expect("user@localhost and a@b", "nothing", "SCREEN-06");
        Expect("SSN 000-12-3456, 666-12-3456, 900-12-3456, 123-00-4567, 123-45-0000", "nothing", "SCREEN-06");
    }

    /// <summary>Card numbers need a network prefix and Luhn; spaces, dashes and a short number after are handled; non-cards are not found. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    // SCREEN-07
    public static void TestCards()
    {
        Expect("card 4242 4242 4242 4242 exp 12/27", "credit_card_number 5-24", "SCREEN-07");
        Expect("5555-5555-5555-4444", "credit_card_number 0-19", "SCREEN-07");
        Expect("378282246310005", "credit_card_number 0-15", "SCREEN-07");
        Expect("card 4242 4242 4242 4242 123", "credit_card_number 5-24", "SCREEN-07");
        Expect("4242 4242 4242 4242 1234 5678", "credit_card_number 0-19", "SCREEN-07");
        Expect("4242 4242 4242 4241", "nothing", "SCREEN-07");
        Expect("1234 5678 1234 5670", "nothing", "SCREEN-07");
        Expect("ts 1700000000000 ms", "nothing", "SCREEN-07");
        Expect("42424242424242424242424", "nothing", "SCREEN-07");
        Expect("x4242424242424242", "nothing", "SCREEN-07");
        Expect("4242424242424242x", "nothing", "SCREEN-07");
        Expect("3782 822463 10005", "credit_card_number 0-17", "SCREEN-07");
        Expect("card 4222 2222 2222 2 end", "credit_card_number 5-21", "SCREEN-07");
        Expect("2 2 6 14 8 15 20 6 13", "nothing", "SCREEN-07");
        Expect("4 8 15 16 23 42 4 8 15 16 23 42 108", "nothing", "SCREEN-07");
    }

    /// <summary>Public IPv4 and global IPv6 are found; private, loopback, link-local, multicast, bad octets, versions, .0, clock times and MACs are not. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    // SCREEN-08
    public static void TestIpAddresses()
    {
        Expect("client 203.0.113.7 connected", "ip_address 7-18", "SCREEN-08");
        Expect("from 198.51.100.24.", "ip_address 5-18", "SCREEN-08");
        Expect("addr 2001:db8::8a2e:370:7334 ok", "ip_address 5-28", "SCREEN-08");
        Expect("[2001:0db8:0000:0000:0000:ff00:0042:8329]", "ip_address 1-40", "SCREEN-08");
        Expect("8.8.8.8 and 172.32.0.1 and 2606:4700:4700::1111", "ip_address 0-7, ip_address 12-22, ip_address 27-47", "SCREEN-08");
        Expect("127.0.0.1 10.0.0.5 192.168.1.1 172.16.0.1 169.254.1.1 0.0.0.0 224.0.0.1 255.255.255.255", "nothing", "SCREEN-08");
        Expect("999.1.1.1 and 256.1.1.1 and 08.8.8.8", "nothing", "SCREEN-08");
        Expect("1.2.3.4.5 and v8.8.8.8", "nothing", "SCREEN-08");
        Expect("12:30:45 and aa:bb:cc:dd:ee:ff", "nothing", "SCREEN-08");
        Expect("::1 and fe80::1 and fc00::1", "nothing", "SCREEN-08");
        Expect("db::add(x) and dead::beef", "nothing", "SCREEN-08");
        Expect("Version=1.0.0.0, Culture=neutral", "nothing", "SCREEN-08");
    }

    private static readonly JsonSerializerOptions Raw = new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary>
    /// Reject: 422 secrets_or_pii_detected with the findings and neither the text nor a matched value anywhere in the
    /// result; with categories ["secret"] the same text is ok with findings []. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    // SCREEN-09
    public static void TestRejectMode()
    {
        var s = new Screener(HashKey);
        var r = s.ScreenText(T, "reject");
        Eq((false, 422, "secrets_or_pii_detected", "email_address 8-24, phone_number 33-45"), (r.Ok, r.Status, r.Error, Show(r.Findings)), "reject");
        Eq(null, r.Text, "a refusal carries no text");
        var json = JsonSerializer.Serialize(r, Raw);
        foreach (var leak in new[] { T, "jane@example.com", "555-123-4567", "jane", "4567" })
            Check(!json.Contains(leak), "the result does not hold " + leak);
        var secretsOnly = s.ScreenText(T, "reject", new[] { "secret" });
        Eq((true, 200, T, 0), (secretsOnly.Ok, secretsOnly.Status, secretsOnly.Text, secretsOnly.Findings.Count), "categories [secret]");
        Eq("ip_address 7-18", Show(s.ScanText("client 203.0.113.7 sk", new[] { "pii" })), "categories [pii] scans pii only");
    }

    /// <summary>
    /// Strip: each finding becomes [REDACTED:label] with every other character unchanged; screening the output again
    /// (reject) is ok with no findings, for every vector above; a match that only appears once its neighbour is redacted
    /// makes strip answer 422. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    // SCREEN-10
    public static void TestStripMode()
    {
        var s = new Screener(HashKey);
        var r = s.ScreenText(T, "strip");
        Eq((true, 200, "Contact [REDACTED:email_address] or call [REDACTED:phone_number] for help."), (r.Ok, r.Status, r.Text), "strip T");
        Eq("email_address 8-24, phone_number 33-45", Show(r.Findings), "the same two findings");
        Eq(r.Text, Screener.RedactText(T, r.Findings), "redact_text gives the same text");
        Check(WithFindings.Count > 60, "the vector list was collected");
        foreach (var text in WithFindings)
        {
            var stripped = s.ScreenText(text, "strip");
            Check(stripped.Ok && stripped.Findings.Count > 0, $"strip succeeds for [{Shorten(text)}] (got {stripped.Error})");
            if (!stripped.Ok) continue;
            var again = s.ScreenText(stripped.Text, "reject");
            Check(again.Ok && again.Findings.Count == 0, $"the stripped text passes reject [{Shorten(stripped.Text)}]");
            Check(stripped.Text.Contains("[REDACTED:" + stripped.Findings[0].Label + "]"), "the marker names the label");
        }
        var both = s.ScreenText("jane@example.com555-123-4567", "strip");
        Eq((422, "secrets_or_pii_detected", "phone_number 16-28, email_address -1--1"), (both.Status, both.Error, Show(both.Findings)), "a match revealed by redaction");
        Eq(null, both.Text, "no text returned");
    }

    /// <summary>Overlaps: earliest start, then longest, then the earlier detector; offsets in code points. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    // SCREEN-11
    public static void TestOverlapsAndCodePoints()
    {
        Expect("\u00e9\U0001F600 a@b.co", "email_address 3-9", "SCREEN-11");
        Expect("token=" + K1, "openai_style_api_key 6-33", "SCREEN-11");
        Expect("Bearer " + K1, "openai_style_api_key 7-34", "SCREEN-11");
        var s = new Screener();
        var fs = s.ScanText("Contact jane@example.com " + P3 + " token=" + K1 + " https://a:" + K9 + "@x.io 4242 4242 4242 4242");
        for (var i = 1; i < fs.Count; i++) Check(fs[i].Start >= fs[i - 1].End, "no character is in two findings");
        var strip = s.ScreenText("\u00e9\U0001F600 a@b.co", "strip");
        Eq("\u00e9\U0001F600 [REDACTED:email_address]", strip.Text, "redaction at code-point offsets");
    }

    /// <summary>mask, value_hash with the configured key (the spec's values) or null without one, and a short key refused. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    // SCREEN-12
    public static void TestMaskAndHash()
    {
        Eq(Rep("*", 15), Screener.Mask(Rep("a", 15)), "mask of 15 characters");
        Eq("ab************op", Screener.Mask("abcdefghijklmnop"), "mask of 16 characters");
        Eq("sk" + Rep("*", 23) + "OP", Screener.Mask(K1), "mask(K1)");
        var r = new Screener(HashKey).ScreenText(T, "strip", new[] { "pii" });
        var expected = "[{\"Category\":\"pii\",\"Label\":\"email_address\",\"Start\":8,\"End\":24,\"Preview\":\"ja************om\",\"ValueHash\":\"9487588974759d303d5d44401791a603ad85fda9276d43f7436077d709d9da10\",\"Encoded\":false}," +
                       "{\"Category\":\"pii\",\"Label\":\"phone_number\",\"Start\":33,\"End\":45,\"Preview\":\"************\",\"ValueHash\":\"ee171612a2f4984e73ec9377b4d10f2b76125f5adf8e4315f12e77ebb2cd41c3\",\"Encoded\":false}]";
        Eq(expected, JsonSerializer.Serialize(r.Findings, Raw), "the strip answer's findings, exactly");
        Check(new Screener().ScanText(T).All(f => f.ValueHash == null), "no key: value_hash is null");
        string code = null;
        try { new Screener(new byte[31]); }
        catch (ScreenerConfigException e) { code = e.Code; }
        Eq("invalid_hash_key", code, "a 31-byte key is refused");
    }

    /// <summary>
    /// E1-E8: secrets behind one or two layers of JSON escapes are refused in both modes (encoded, start -1); a mention
    /// of an escape is accepted; strip succeeds when the direct redaction removed the secret; escapes left after 8 passes
    /// are refused. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    // SCREEN-13
    public static void TestEscapes()
    {
        var s = new Screener(HashKey);
        var e1 = "{\"note\": \"sk\\u002d" + "abcdEFGH12345678ijklMNOP\"}";
        var e2 = "{\"outer\": \"{\\\"k\\\": \\\"sk\\\\u002d" + "abcdEFGH12345678ijklMNOP\\\"}\"}";
        var e3 = "{\"msg\": \"the escape \\u00e9 prints an e-acute and \\n is a newline\"}";
        var e4 = "{\"contact\": \"jane\\u0040example.com\"}";
        var e5 = "{\"emoji\": \"\\ud83d\\ude00 ok\", \"path\": \"C:\\\\Users\\\\name\\\\notes.txt\"}";
        var e6 = "{\"key\": \"" + P1.Replace("\n", "\\n") + "\"}";
        var e7 = "{\"key\": \"" + P2.Replace("\n", "\\n") + "\"}";
        var e8 = new string('\\', 600) + "n";
        // The findings as "label start-end [encoded]". Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        string Hidden(ScreenResult r) => string.Join(", ", r.Findings.Select(f => $"{f.Label} {f.Start}-{f.End}{(f.Encoded ? " encoded" : "")}"));
        foreach (var mode in new[] { "reject", "strip" })
        {
            foreach (var (name, text, label) in new[] { ("E1", e1, "openai_style_api_key"), ("E2", e2, "openai_style_api_key"), ("E4", e4, "email_address"), ("E7", e7, "pem_private_key"), ("E8", e8, "unresolved_escape") })
            {
                var r = s.ScreenText(text, mode);
                Eq((422, "secrets_or_pii_detected", label + " -1--1 encoded", (string)null), (r.Status, r.Error, Hidden(r), r.Text), $"{name} {mode}");
            }
            foreach (var (name, text) in new[] { ("E3", e3), ("E5", e5) })
            {
                var r = s.ScreenText(text, mode);
                Eq((true, 200, text, 0), (r.Ok, r.Status, r.Text, r.Findings.Count), $"{name} {mode}");
            }
        }
        var e6r = s.ScreenText(e6, "reject");
        Eq((422, "pem_private_key 9-202"), (e6r.Status, Hidden(e6r)), "E6 reject");
        var e6s = s.ScreenText(e6, "strip");
        Eq((true, "{\"key\": \"[REDACTED:pem_private_key]\"}"), (e6s.Ok, e6s.Text), "E6 strip");
        Eq(("x", false), (Screener.ResolveEscapes("x").Text, Screener.ResolveEscapes("x").Unresolved), "no escape");
        Eq("\U0001F600 \uFFFD", Screener.ResolveEscapes("\\ud83d\\ude00 \\ud83d").Text, "a pair and a lone surrogate");
        Check(Screener.ResolveEscapes(e8).Unresolved, "E8 is unresolved after 8 passes");
    }

    /// <summary>
    /// invalid_mode, invalid_categories and text_too_large come before any scan; each hostile 200,000-character input is
    /// screened in strip mode in under 2 seconds ("token=$" * 28571 added for the lead's ruling fed6e7b: detector 13
    /// must stay linear); an unpaired surrogate is invalid_text. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    // SCREEN-14
    public static void TestInputRefusalsAndHostileInputs()
    {
        var s = new Screener();
        Eq((400, "invalid_mode"), (s.ScreenText("x", "mask").Status, s.ScreenText("x", "mask").Error), "mode mask");
        Eq("invalid_mode", s.ScreenText(T, "mask").Error, "the mode is checked before any scan");
        Eq((400, "invalid_categories"), (s.ScreenText("x", "reject", new string[0]).Status, s.ScreenText("x", "reject", new string[0]).Error), "categories []");
        Eq("invalid_categories", s.ScreenText(T, "reject", new[] { "secret", "keys" }).Error, "categories [secret, keys]");
        var e5 = Rep("\u00e9", 5);
        var small = new Screener(null, 9);
        Eq((413, "text_too_large"), (small.ScreenText(e5).Status, small.ScreenText(e5).Error), "10 bytes over max_bytes 9");
        Eq("text_too_large", new Screener(null, 9).ScreenText(Rep("4242 4242 4242 4242 ", 1)).Error, "too large before any scan");
        Check(new Screener(null, 10).ScreenText(e5).Ok, "10 bytes with max_bytes 10");
        Eq((400, "invalid_text"), (s.ScreenText("ab\uD800cd").Status, s.ScreenText("ab\uD800cd").Error), "an unpaired surrogate");
        Eq("invalid_text", s.ScreenText("\uDC00").Error, "a lone low surrogate");
        Eq("invalid_text", s.ScreenText(null).Error, "a missing text");

        var hostile = new (string Name, string Text)[]
        {
            ("a.", Rep("a.", 100000)), ("BEGIN headers", Rep("-----BEGIN " + "PRIVATE KEY-----", 7400)), ("1234-", Rep("1234-", 40000)),
            ("eyJ", Rep("eyJ", 66666)), ("xeyJ-", Rep("xeyJ-", 40000)), ("xsk-", Rep("xsk-", 50000)), ("password + spaces", "password" + new string(' ', 199990)),
            ("token=[REDACTED:", Rep("token=[REDACTED:", 12500)), ("token=$ (spec fed6e7b)", Rep("token=$", 28571)), ("a://b:", Rep("a://b:", 33000)), ("ab:", Rep("ab:", 66000)),
            ("1.1.", Rep("1.1.", 50000)), ("\\n", Rep("\\n", 100000)), ("B + LF", B + new string('\n', 199969)),
            ("B + key lines", B + Rep("\n" + Rep("A", 64), 3000)),
        };
        foreach (var (name, text) in hostile)
        {
            var sw = Stopwatch.StartNew();
            var r = s.ScreenText(text, "strip");
            sw.Stop();
            Check(r.Status != 500, $"hostile {name}: no screening failure (got {r.Error})");
            Check(sw.Elapsed.TotalSeconds < 2, $"hostile {name}: under 2 seconds (took {sw.Elapsed.TotalSeconds:F2} s)");
        }
    }
}

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Tests for SecretPiiScreening (spec docs/specs/secret_pii_screening.md, SCREEN-01 to SCREEN-14). Every key-shaped
 * value is built from two or more pieces at run time, so a repository secret scanner never blocks a commit.
 * Run by tools/run_suites.py through main(); any failed check exits 1.
 * Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only (no database, files, network or money).
 */
public class secret_pii_screening_java_tests {

    static final String K1 = "sk-" + "abcdEFGH12345678ijklMNOP";
    static final String K2 = "sk_" + "live_" + "A1b2C3d4E5f6G7h8I9j0K1l2";
    static final String K3 = "pk_" + "test_" + "A1b2C3d4E5f6G7h8I9j0K1l2";
    static final String K4 = "AKIA" + "IOSFODNN7EXAMPLE";
    static final String K5 = "ghp_" + "16C7e42F292c6912E7710c838347Ae178B4a";
    static final String K6 = "github_pat_" + "11ABCDEFG0abcdefghij_KLMNOPQRSTUVWXYZ0123456789";
    static final String K7 = "xoxb-" + "1234567890-abcdefghijklmnopqrstuvwx";
    static final String K8 = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q";
    static final String K9 = "whsec_" + "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    static final String J = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
            + "." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    static final String B = "-----BEGIN RSA " + "PRIVATE KEY-----";
    static final String E = "-----END RSA " + "PRIVATE KEY-----";
    static final String L1 = "MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumga0R2LiajO16aI4Uxa2b9nb";
    static final String L2 = "AKELFOxNOFICTIONALKEYMATERIALFORTESTINGPURPOSESONLY1234567890AB";
    static final String P1 = B + "\n" + L1 + "\n" + L2 + "\n" + E;
    static final String P2 = B + "\n" + "Proc-Type: 4,ENCRYPTED\n" + "DEK-Info: AES-256-CBC,A1B2C3D4E5F60718293A4B5C6D7E8F90\n" + "\n" + L1 + "\n" + E;
    static final String P3 = B + "\n" + "api_key=looksLikeASecretButItsJustPemBase64Content\n" + E;
    static final String P4 = B + "\n" + L1 + "\n" + L2 + " (cut";
    static final String G = "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----" + "\nVersion: GnuPG v2\n\n" + L1 + "\n" + L2 + "\n=AbCd\n"
            + "-----END PGP " + "PRIVATE KEY BLOCK-----";
    static final String T = "Contact jane@example.com or call 555-123-4567 for help.";

    static int vectorsChecked = 0;

    /**
     * Runs every test; exits 1 on the first failure. In: none. Out: exit code. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    public static void main(String[] args) {
        try {
            testCleanTextsPass();
            testKeyShapes();
            testPrivateKeyBlocks();
            testBearerAndUrlCredentials();
            testKeyValueAssignments();
            testEmailPhoneSsn();
            testCardNumbers();
            testIpAddresses();
            testRejectModeHoldsNoValue();
            testStripModeRedactsAndRescreens();
            testOverlapsAndCodePoints();
            testMaskHashAndKeyLength();
            testHiddenEscapes();
            testInputChecksAndHostileInputs();
            System.out.println("All tests passed (" + vectorsChecked + " vectors)");
        } catch (Throwable e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    // ------------------------------------------------------------------------------------------------ helpers
    /** Fails with msg unless cond holds (Java assert is off in the runner). Touches: nothing. */
    static void check(boolean cond, String msg) {
        if (!cond) throw new AssertionError(msg);
    }

    /** A screener with the spec's hash key, the 32 bytes 00 01 ... 1f. */
    static SecretPiiScreening screener() {
        byte[] k = new byte[32];
        for (int i = 0; i < 32; i++) k[i] = (byte) i;
        return new SecretPiiScreening(k);
    }

    /** "label s-e, ..." for the findings, or "nothing". */
    static String describe(List<SecretPiiScreening.Finding> fs) {
        if (fs.isEmpty()) return "nothing";
        StringBuilder sb = new StringBuilder();
        for (SecretPiiScreening.Finding f : fs) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(f.label()).append(' ').append(f.start()).append('-').append(f.end());
        }
        return sb.toString();
    }

    /**
     * Asserts scan_text(text) gives exactly `want` ("label s-e, ..." or "nothing"); for a vector with findings it also
     * strips the text and screens the output again in reject mode (SCREEN-10: ok, no findings) unless the hidden
     * check refuses the stripped text. Touches: memory only.
     */
    static void vec(SecretPiiScreening s, String text, String want) {
        String got = describe(s.scanText(text));
        check(got.equals(want), "vector " + text.replace("\n", "\\n") + " -> want " + want + ", got " + got);
        vectorsChecked++;
        if (!want.equals("nothing")) {
            SecretPiiScreening.Result r = s.screenText(text, "strip");
            if (r.ok) {
                SecretPiiScreening.Result r2 = s.screenText(r.text, "reject");
                check(r2.ok && r2.findings.isEmpty(), "strip output screens clean: " + r.text);
                for (SecretPiiScreening.Finding f : s.scanText(text)) {
                    check(r.text.contains("[REDACTED:" + f.label() + "]"), "marker names the label " + f.label());
                }
            }
        }
    }

    // ------------------------------------------------------------------------------------------------ tests
    // SCREEN-01
    /** The four clean texts are ok, unchanged, with findings [] in both modes. */
    static void testCleanTextsPass() {
        SecretPiiScreening s = screener();
        String[] clean = {
            "User: let's plan the export feature.\nAssistant: I built the CSV export button and will add a progress bar.\n",
            "def get_cache_key(user_id):\n    return f'user:{user_id}'\n\nclass TokenBucket:\n    def __init__(self, capacity):\n        self.capacity = capacity\n",
            "Please reset your password before the next login.",
            "version 1.2.3.4.5 released at 12:30:45 on 2026-11-10, build 20261110123045, order 1234567890"};
        for (String t : clean) {
            for (String mode : new String[] {"reject", "strip"}) {
                SecretPiiScreening.Result r = s.screenText(t, mode);
                check(r.ok && r.status == 200 && t.equals(r.text) && r.findings.isEmpty(), "clean text passes " + mode + ": " + r);
            }
        }
    }

    // SCREEN-02
    /** Every key shape with its label and exact span; the four near-misses are not found. */
    static void testKeyShapes() {
        SecretPiiScreening s = screener();
        vec(s, "here is my key: " + K1, "openai_style_api_key 16-43");
        vec(s, "STRIPE_KEY=" + K2, "stripe_style_api_key 11-43");
        vec(s, K3 + " used in the demo", "stripe_style_api_key 0-32");
        vec(s, "AWS_ACCESS_KEY_ID=" + K4, "aws_access_key_id 18-38");
        vec(s, "token: " + K5, "github_token 7-47");
        vec(s, "use " + K6 + " now", "github_token 4-62");
        vec(s, K7, "slack_token 0-40");
        vec(s, "key=" + K8 + "&x=1", "google_api_key 4-43");
        vec(s, "secret " + K9 + ".", "webhook_signing_secret 7-45");
        vec(s, "Authorization token captured: " + J, "jwt 30-162");
        vec(s, "ASIA" + "IOSFODNN7EXAMPLE", "aws_access_key_id 0-20");
        vec(s, "task-" + "abcdEFGH12345678ijklMNOP", "nothing");
        vec(s, "X" + K4, "nothing");
        vec(s, K2 + "_x", "nothing");
        vec(s, "class sk-spinner-three-bounce is used", "nothing");
    }

    // SCREEN-03
    /** Private key blocks: whole block, encrypted header, cut-off blocks (quoted, diffed, escaped), 60-character rule. */
    static void testPrivateKeyBlocks() {
        SecretPiiScreening s = screener();
        vec(s, "a " + P1 + " b", "pem_private_key 2-192");
        vec(s, P2, "pem_private_key 0-205");
        vec(s, P3, "pem_private_key 0-112");
        vec(s, "api_key=looksLikeASecretButItsJustPemBase64Content", "generic_key_value_assignment 8-50");
        vec(s, "x " + P4, "pem_private_key 2-162");
        vec(s, "-" + B + "\n-" + L1 + "\n-" + L2 + "\n-" + E, "pem_private_key 1-163");
        vec(s, "> " + B + "\n> " + L1 + "\n> " + L2 + "\n> " + E, "pem_private_key 2-198");
        vec(s, G, "pem_private_key 0-227");
        vec(s, B + "\n" + "A".repeat(30) + "\\n" + "A".repeat(30), "pem_private_key 0-94");
        vec(s, B + "\n" + "A".repeat(29) + "\\n" + "A".repeat(30), "nothing");
        vec(s, B + "\n" + "A".repeat(59), "nothing");
        vec(s, "Look for the line " + B + " in the file.", "nothing");
    }

    // SCREEN-04
    /** Bearer tokens and URL passwords: only the token or password is the span; prose and placeholders are not found. */
    static void testBearerAndUrlCredentials() {
        SecretPiiScreening s = screener();
        vec(s, "curl -H 'Authorization: Bearer abc123DEF456ghi789JKL'", "bearer_token 31-52");
        vec(s, "authorization: BEARER abc123DEF456ghi789JKL", "bearer_token 22-43");
        vec(s, "Bearer authentication is required", "nothing");
        vec(s, "Bearer " + J, "jwt 7-139");
        vec(s, "postgres://app:S3cr3t-Pa55@db.internal:5432/app", "url_credentials 15-26");
        vec(s, "ssh://git:hunter2secret@host/repo", "url_credentials 10-23");
        vec(s, "https://user:password@example.com/", "nothing");
        vec(s, "https://jane@example.com/x", "nothing");
        vec(s, "redis://:Sup3rS3cretValue@cache.example.com:6379/0", "url_credentials 9-25");
        vec(s, "http://localhost:8080/@foo and https://example.com/a:b@c", "nothing");
        vec(s, "Our API uses Bearer authentication.", "nothing");
        vec(s, "Send the header with bearer token-based auth", "nothing");
    }

    // SCREEN-05
    /** key = value secrets in every form; placeholders, short values, words, references and redacted values are not. */
    static void testKeyValueAssignments() {
        SecretPiiScreening s = screener();
        String kv = "generic_key_value_assignment ";
        vec(s, "DB_PASSWORD=Sup3rS3cretValue!\n", kv + "12-29");
        vec(s, "internal_api_key: \"zx91-nq7f-88ab-lorem\"", kv + "19-39");
        vec(s, "{\"password\": \"hunter2hunter2\"}", kv + "14-28");
        vec(s, "{\\\"password\\\":\\\"hunter2hunter2\\\"}", kv + "16-30");
        vec(s, "db_password: CorrectHorseBatteryStaple", kv + "13-38");
        vec(s, "the db_password: CorrectHorseBatteryStaple9 I mentioned", kv + "17-43");
        vec(s, "password: DOMAIN\\Administrator1", kv + "10-31");
        vec(s, "API_KEY = 'Zx91Nq7f88ab'", kv + "11-23");
        vec(s, "token=abc12345;next", kv + "6-14");
        vec(s, "password: p\u00e4ssw\u00f6rd123", kv + "10-21");
        vec(s, "a".repeat(40) + "token=abc12345def", kv + "46-57");
        vec(s, "a".repeat(41) + "token=abc12345def", "nothing");
        vec(s, "API_KEY=your_key_here", "nothing");
        vec(s, "password: changeme", "nothing");
        vec(s, "pwd=abc123", "nothing");
        vec(s, "Secret: whatever the team decides", "nothing");
        vec(s, "password: WordPress", "nothing");
        vec(s, "My favorite crypto token: Ethereum has been volatile", "nothing");
        vec(s, "class TokenBucket:", "nothing");
        vec(s, "Please reset your password before the next login.", "nothing");
        vec(s, "secrets: abc12345def", "nothing");
        vec(s, "password: gr\u00f6\u00dferes", "nothing");
        vec(s, "password: [REDACTED:generic_key_value_assignment]", "nothing");
        vec(s, "'password' => 'Sup3rS3cretValue!',", kv + "15-32");
        vec(s, "password := \"Sup3rS3cretValue!\"", kv + "13-30");
        vec(s, "password: hunter2!", kv + "10-18");
        vec(s, "password: P@ss(w0rd)1x", kv + "10-22");
        vec(s, "token: ab12.cd34.ef56gh78", kv + "7-25");
        vec(s, "\u0130 token=abc12345", kv + "8-16");
        vec(s, "The password: required.", "nothing");
        vec(s, "token: optional,", "nothing");
        vec(s, "password: changeme.", "nothing");
        vec(s, "password: undefined,", "nothing");
        vec(s, "password = os.getenv(\"DB_PASSWORD\")", "nothing");
        vec(s, "api_key = os.environ[\"API_KEY\"]", "nothing");
        vec(s, "secret_key = settings.SECRET_KEY", "nothing");
        vec(s, "apiKey: process.env.STRIPE_KEY,", "nothing");
        vec(s, "token = getAccessTokenSilently();", "nothing");
        vec(s, "password: req.body.password,", "nothing");
        vec(s, "API_KEY=$API_KEY", "nothing");
        vec(s, "token=${TOKEN}", "nothing");
        vec(s, "api_key: <YOUR_API_KEY>", "nothing");
        vec(s, "Password: ********", "nothing");
        vec(s, "token: Optional[str] = None", "nothing");
        vec(s, "password = models.CharField(max_length=128)", "nothing");
        vec(s, "to\u212aen=abc12345def", "nothing");
        vec(s, "password: abcdefgh\u0663", "nothing");
    }

    // SCREEN-06
    /** Emails, phones and SSNs are found; a bare 10-digit number, address + "_" and impossible SSNs are not. */
    static void testEmailPhoneSsn() {
        SecretPiiScreening s = screener();
        vec(s, T, "email_address 8-24, phone_number 33-45");
        vec(s, "<jane.doe+tag@mail.example.co.uk>", "email_address 1-32");
        vec(s, "see https://example.com/contact?email=jane@example.com", "email_address 38-54");
        vec(s, "call (555) 123-4567 now", "phone_number 5-19");
        vec(s, "+1 555-123-4567", "phone_number 0-15");
        vec(s, "reach me at +442071838750.", "phone_number 12-25");
        vec(s, "SSN 123-45-6789", "ssn 4-15");
        vec(s, "order 5551234567 shipped", "nothing");
        vec(s, "jane@example.com_backup", "nothing");
        vec(s, "user@localhost and a@b", "nothing");
        vec(s, "SSN 000-12-3456, 666-12-3456, 900-12-3456, 123-00-4567, 123-45-0000", "nothing");
    }

    // SCREEN-07
    /** Cards need a network prefix and Luhn; spaces and dashes; a trailing short number; small-number rows are not cards. */
    static void testCardNumbers() {
        SecretPiiScreening s = screener();
        String cc = "credit_card_number ";
        vec(s, "card 4242 4242 4242 4242 exp 12/27", cc + "5-24");
        vec(s, "5555-5555-5555-4444", cc + "0-19");
        vec(s, "378282246310005", cc + "0-15");
        vec(s, "card 4242 4242 4242 4242 123", cc + "5-24");
        vec(s, "4242 4242 4242 4242 1234 5678", cc + "0-19");
        vec(s, "4242 4242 4242 4241", "nothing");
        vec(s, "1234 5678 1234 5670", "nothing");
        vec(s, "ts 1700000000000 ms", "nothing");
        vec(s, "42424242424242424242424", "nothing");
        vec(s, "x4242424242424242", "nothing");
        vec(s, "4242424242424242x", "nothing");
        vec(s, "3782 822463 10005", cc + "0-17");
        vec(s, "card 4222 2222 2222 2 end", cc + "5-21");
        vec(s, "2 2 6 14 8 15 20 6 13", "nothing");
        vec(s, "4 8 15 16 23 42 4 8 15 16 23 42 108", "nothing");
    }

    // SCREEN-08
    /** Public IPv4 and global IPv6 are found; private, loopback, link-local, multicast, versions, clocks, MACs are not. */
    static void testIpAddresses() {
        SecretPiiScreening s = screener();
        vec(s, "client 203.0.113.7 connected", "ip_address 7-18");
        vec(s, "from 198.51.100.24.", "ip_address 5-18");
        vec(s, "addr 2001:db8::8a2e:370:7334 ok", "ip_address 5-28");
        vec(s, "[2001:0db8:0000:0000:0000:ff00:0042:8329]", "ip_address 1-40");
        vec(s, "8.8.8.8 and 172.32.0.1 and 2606:4700:4700::1111", "ip_address 0-7, ip_address 12-22, ip_address 27-47");
        vec(s, "127.0.0.1 10.0.0.5 192.168.1.1 172.16.0.1 169.254.1.1 0.0.0.0 224.0.0.1 255.255.255.255", "nothing");
        vec(s, "999.1.1.1 and 256.1.1.1 and 08.8.8.8", "nothing");
        vec(s, "1.2.3.4.5 and v8.8.8.8", "nothing");
        vec(s, "12:30:45 and aa:bb:cc:dd:ee:ff", "nothing");
        vec(s, "::1 and fe80::1 and fc00::1", "nothing");
        vec(s, "db::add(x) and dead::beef", "nothing");
        vec(s, "Version=1.0.0.0, Culture=neutral", "nothing");
    }

    // SCREEN-09
    /** Reject mode: 422 with the findings and neither the text nor a matched value; ["secret"] only: ok, []. */
    static void testRejectModeHoldsNoValue() {
        SecretPiiScreening s = screener();
        SecretPiiScreening.Result r = s.screenText(T);
        check(!r.ok && r.status == 422 && "secrets_or_pii_detected".equals(r.error) && r.text == null, "reject answer " + r);
        check(describe(r.findings).equals("email_address 8-24, phone_number 33-45"), "reject findings " + r);
        String json = r.toJson();
        check(!json.contains("jane@example.com") && !json.contains("555-123-4567") && !json.contains("Contact"),
                "the result holds neither the text nor a matched value: " + json);
        SecretPiiScreening.Result secretOnly = s.screenText(T, "reject", List.of("secret"));
        check(secretOnly.ok && secretOnly.status == 200 && T.equals(secretOnly.text) && secretOnly.findings.isEmpty(),
                "secret-only screening is ok: " + secretOnly);
        String keyText = "here is my key: " + K1;
        String kj = s.screenText(keyText).toJson();
        check(!kj.contains(K1) && !kj.contains("abcdEFGH12345678ijklMNOP"), "no key in a refusal");
    }

    // SCREEN-10
    /** Strip: markers name labels, other characters unchanged, output screens clean; a neighbour match makes strip 422. */
    static void testStripModeRedactsAndRescreens() {
        SecretPiiScreening s = screener();
        SecretPiiScreening.Result r = s.screenText(T, "strip");
        check(r.ok && r.status == 200, "strip ok " + r);
        check("Contact [REDACTED:email_address] or call [REDACTED:phone_number] for help.".equals(r.text), "strip text " + r.text);
        check(describe(r.findings).equals("email_address 8-24, phone_number 33-45"), "strip findings");
        SecretPiiScreening.Result again = s.screenText(r.text, "reject");
        check(again.ok && again.findings.isEmpty(), "stripped text screens clean");
        SecretPiiScreening.Result pii = s.screenText(T, "strip", List.of("pii"));
        check(pii.ok && pii.text.equals(r.text) && pii.findings.size() == 2, "strip with categories [pii]");
        SecretPiiScreening.Result n = s.screenText("jane@example.com555-123-4567", "strip");
        check(!n.ok && n.status == 422 && "secrets_or_pii_detected".equals(n.error) && n.text == null, "neighbour 422 " + n);
        check(n.findings.size() == 2, "two findings");
        SecretPiiScreening.Finding a = n.findings.get(0), b = n.findings.get(1);
        check(a.label().equals("phone_number") && a.start() == 16 && a.end() == 28, "first the number " + a);
        check(b.label().equals("email_address") && b.start() == -1 && b.end() == -1 && !b.encoded(), "then the address " + b);
    }

    // SCREEN-11
    /** Overlaps resolve by start, length, detector; offsets count code points past a 2-byte and a 4-byte character. */
    static void testOverlapsAndCodePoints() {
        SecretPiiScreening s = screener();
        vec(s, "\u00e9\uD83D\uDE00 a@b.co", "email_address 3-9");
        vec(s, "token=" + K1, "openai_style_api_key 6-33");
        vec(s, "Bearer " + K1, "openai_style_api_key 7-34");
        String red = SecretPiiScreening.redactText("\u00e9\uD83D\uDE00 a@b.co", s.scanText("\u00e9\uD83D\uDE00 a@b.co"));
        check(red.equals("\u00e9\uD83D\uDE00 [REDACTED:email_address]"), "redaction counts code points: " + red);
    }

    // SCREEN-12
    /** mask, value_hash (the spec's values), null without a key, and a short key refused at construction. */
    static void testMaskHashAndKeyLength() {
        check(SecretPiiScreening.mask("a".repeat(15)).equals("*".repeat(15)), "mask under 16");
        check(SecretPiiScreening.mask("abcdefghijklmnop").equals("ab************op"), "mask 16");
        check(SecretPiiScreening.mask(K1).equals("sk" + "*".repeat(23) + "OP"), "mask K1");
        SecretPiiScreening s = screener();
        List<SecretPiiScreening.Finding> f = s.screenText(T).findings;
        check(f.get(0).preview().equals("ja************om"), "email preview");
        check("9487588974759d303d5d44401791a603ad85fda9276d43f7436077d709d9da10".equals(f.get(0).valueHash()), "email hash");
        check(f.get(1).preview().equals("************"), "phone preview");
        check("ee171612a2f4984e73ec9377b4d10f2b76125f5adf8e4315f12e77ebb2cd41c3".equals(f.get(1).valueHash()), "phone hash");
        check(f.get(0).category().equals("pii") && !f.get(0).encoded(), "category and encoded");
        check(f.get(0).toJson().equals("{\"category\": \"pii\", \"label\": \"email_address\", \"start\": 8, \"end\": 24, "
                + "\"preview\": \"ja************om\", \"value_hash\": \"9487588974759d303d5d44401791a603ad85fda9276d43f7436077d709d9da10\", "
                + "\"encoded\": false}"), "finding json " + f.get(0).toJson());
        SecretPiiScreening noKey = new SecretPiiScreening();
        check(noKey.scanText(T).get(0).valueHash() == null, "no key -> null hash");
        boolean refused = false;
        try {
            new SecretPiiScreening(new byte[31]);
        } catch (SecretPiiScreening.ScreenerConfigException e) {
            refused = "invalid_hash_key".equals(e.code);
        }
        check(refused, "a 31-byte key is refused at construction");
    }

    /** One SCREEN-13 vector: both modes; "ok" (text unchanged), "encoded:<label>", or a direct finding. */
    static void escapeVec(SecretPiiScreening s, String text, String rejectWant, String stripWant) {
        for (String mode : new String[] {"reject", "strip"}) {
            String want = mode.equals("reject") ? rejectWant : stripWant;
            SecretPiiScreening.Result r = s.screenText(text, mode);
            if (want.equals("ok")) {
                check(r.ok && text.equals(r.text) && r.findings.isEmpty(), mode + " ok for " + text + ": " + r);
            } else if (want.startsWith("encoded:")) {
                String label = want.substring(8);
                check(!r.ok && r.status == 422 && r.text == null, mode + " 422 for " + text + ": " + r);
                boolean found = false;
                for (SecretPiiScreening.Finding f : r.findings) {
                    if (f.label().equals(label) && f.encoded() && f.start() == -1 && f.end() == -1) found = true;
                }
                check(found, mode + " has " + label + " encoded: " + r);
            } else if (want.startsWith("text:")) {
                check(r.ok && r.text.equals(want.substring(5)), mode + " text for " + text + ": " + r);
            } else {
                check(!r.ok && r.status == 422 && describe(r.findings).equals(want), mode + " direct " + want + ": " + r);
            }
            vectorsChecked++;
        }
    }

    // SCREEN-13
    /** Secrets behind JSON escapes (one or two layers) are refused in both modes with encoded: true (E1-E8). */
    static void testHiddenEscapes() {
        SecretPiiScreening s = screener();
        String bs = "\\";
        String e1 = "{\"note\": \"sk" + bs + "u002dabcdEFGH12345678ijklMNOP\"}";
        String e2 = "{\"outer\": \"{" + bs + "\"k" + bs + "\": " + bs + "\"sk" + bs + bs + "u002dabcdEFGH12345678ijklMNOP" + bs + "\"}\"}";
        String e3 = "{\"msg\": \"the escape " + bs + "u00e9 prints an e-acute and " + bs + "n is a newline\"}";
        String e4 = "{\"contact\": \"jane" + bs + "u0040example.com\"}";
        String e5 = "{\"emoji\": \"" + bs + "ud83d" + bs + "ude00 ok\", \"path\": \"C:" + bs + bs + "Users" + bs + bs + "name" + bs + bs + "notes.txt\"}";
        String e6 = "{\"key\": \"" + P1.replace("\n", bs + "n") + "\"}";
        String e7 = "{\"key\": \"" + P2.replace("\n", bs + "n") + "\"}";
        String e8 = bs.repeat(600) + "n";
        escapeVec(s, e1, "encoded:openai_style_api_key", "encoded:openai_style_api_key");
        escapeVec(s, e2, "encoded:openai_style_api_key", "encoded:openai_style_api_key");
        escapeVec(s, e3, "ok", "ok");
        escapeVec(s, e4, "encoded:email_address", "encoded:email_address");
        escapeVec(s, e5, "ok", "ok");
        escapeVec(s, e6, "pem_private_key 9-202", "text:{\"key\": \"[REDACTED:pem_private_key]\"}");
        escapeVec(s, e7, "encoded:pem_private_key", "encoded:pem_private_key");
        escapeVec(s, e8, "encoded:unresolved_escape", "encoded:unresolved_escape");
        SecretPiiScreening.Result r8 = s.screenText(e8);
        SecretPiiScreening.Finding u = r8.findings.get(r8.findings.size() - 1);
        check(u.category().equals("secret") && u.preview().equals("***") && u.valueHash() == null, "unresolved_escape shape " + u);
        SecretPiiScreening.Result r8p = s.screenText(e8, "reject", List.of("pii"));
        check(!r8p.ok && r8p.findings.get(0).label().equals("unresolved_escape"), "unresolved_escape whatever the categories");
        SecretPiiScreening.Resolved res = SecretPiiScreening.resolveEscapes(bs + "ud83d" + bs + "ude00" + bs + "ud800x");
        check(res.text().equals("\uD83D\uDE00\uFFFDx") && !res.unresolved(), "surrogate pair and lone surrogate: " + res);
    }

    // SCREEN-14
    /**
     * invalid_mode, invalid_categories, text_too_large before any scan; each hostile 200,000-character input < 2 s.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: "token=$" * 28571 added (spec ruling fed6e7b).
     */
    static void testInputChecksAndHostileInputs() {
        SecretPiiScreening s = screener();
        SecretPiiScreening.Result m = s.screenText("x", "mask");
        check(!m.ok && m.status == 400 && "invalid_mode".equals(m.error) && m.findings == null, "invalid_mode " + m);
        SecretPiiScreening.Result c1 = s.screenText("x", "reject", List.of());
        check(!c1.ok && c1.status == 400 && "invalid_categories".equals(c1.error), "empty categories " + c1);
        SecretPiiScreening.Result c2 = s.screenText("x", "reject", List.of("secret", "keys"));
        check(!c2.ok && c2.status == 400 && "invalid_categories".equals(c2.error), "unknown category " + c2);
        byte[] k = new byte[32];
        SecretPiiScreening nine = new SecretPiiScreening(k, 9);
        SecretPiiScreening ten = new SecretPiiScreening(k, 10);
        SecretPiiScreening.Result big = nine.screenText("\u00e9".repeat(5));
        check(!big.ok && big.status == 413 && "text_too_large".equals(big.error), "413 " + big);
        check(ten.screenText("\u00e9".repeat(5)).ok, "10 bytes with max 10 is ok");
        SecretPiiScreening.Result tooBigSecret = nine.screenText("here is my key: " + K1, "strip");
        check(tooBigSecret.status == 413 && tooBigSecret.findings == null, "413 comes before any scan");
        SecretPiiScreening.Result bad = s.screenText("abc\uD800def");
        check(!bad.ok && bad.status == 400 && "invalid_text".equals(bad.error), "unpaired surrogate -> invalid_text");
        check(s.screenText(null).status == 400 && "invalid_text".equals(s.screenText(null).error), "missing text -> invalid_text");

        List<String> hostile = new ArrayList<>();
        hostile.add("a.".repeat(100000));
        hostile.add(("-----BEGIN " + "PRIVATE KEY-----").repeat(7400));
        hostile.add("1234-".repeat(40000));
        hostile.add("eyJ".repeat(66666));
        hostile.add("xeyJ-".repeat(40000));
        hostile.add("xsk-".repeat(50000));
        hostile.add("password" + " ".repeat(199990));
        hostile.add("token=[REDACTED:".repeat(12500));
        hostile.add("token=$".repeat(28571));   // added by spec ruling fed6e7b (detector 13 must stay linear)
        hostile.add("a://b:".repeat(33000));
        hostile.add("ab:".repeat(66000));
        hostile.add("1.1.".repeat(50000));
        hostile.add("\\n".repeat(100000));
        hostile.add(B + "\n".repeat(199969));
        hostile.add(B + ("\n" + "A".repeat(64)).repeat(3000));
        for (String h : hostile) {
            long t0 = System.nanoTime();
            SecretPiiScreening.Result r = s.screenText(h, "strip");
            long ms = (System.nanoTime() - t0) / 1_000_000;
            check(r.status != 500, "hostile input screened without failing: " + r.error);
            check(ms < 2000, "hostile input (" + h.substring(0, 12).replace("\n", "\\n") + "...) took " + ms + " ms");
        }
        check(s.screenText(B + ("\n" + "A".repeat(64)).repeat(3000), "strip").ok, "a long key block strips to a marker");
    }
}

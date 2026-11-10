//! Secret & PII screening tests (docs/specs/secret_pii_screening.md, SCREEN-01..14).
//! Every key-shaped value is built from two or more pieces at run time, as the spec's vectors are written with
//! "+", so a repository secret scanner never blocks a commit.
//! Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: memory only.
use super::*;
use std::time::{Duration, Instant};

/// What: join string pieces at run time. In: pieces. Out: one String. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: nothing.
fn j(parts: &[&str]) -> String {
    parts.concat()
}

/// What: the spec's key vectors K1..K9, J, B, E, L1, L2, P1..P4, G (built from pieces).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
struct V {
    k1: String,
    k2: String,
    k3: String,
    k4: String,
    k5: String,
    k6: String,
    k7: String,
    k8: String,
    k9: String,
    jw: String,
    b: String,
    e: String,
    l1: String,
    l2: String,
    p1: String,
    p2: String,
    p3: String,
    p4: String,
    g: String,
}

/// What: build the vectors. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn v() -> V {
    let b = j(&["-----BEGIN RSA ", "PRIVATE KEY-----"]);
    let e = j(&["-----END RSA ", "PRIVATE KEY-----"]);
    let l1 = "MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumga0R2LiajO16aI4Uxa2b9nb".to_string();
    let l2 = "AKELFOxNOFICTIONALKEYMATERIALFORTESTINGPURPOSESONLY1234567890AB".to_string();
    V {
        k1: j(&["sk-", "abcdEFGH12345678ijklMNOP"]),
        k2: j(&["sk_", "live_", "A1b2C3d4E5f6G7h8I9j0K1l2"]),
        k3: j(&["pk_", "test_", "A1b2C3d4E5f6G7h8I9j0K1l2"]),
        k4: j(&["AKIA", "IOSFODNN7EXAMPLE"]),
        k5: j(&["ghp_", "16C7e42F292c6912E7710c838347Ae178B4a"]),
        k6: j(&["github_pat_", "11ABCDEFG0abcdefghij_KLMNOPQRSTUVWXYZ0123456789"]),
        k7: j(&["xoxb-", "1234567890-abcdefghijklmnopqrstuvwx"]),
        k8: j(&["AIza", "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"]),
        k9: j(&["whsec_", "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"]),
        jw: j(&["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", ".", "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0", ".", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"]),
        p1: j(&[&b, "\n", &l1, "\n", &l2, "\n", &e]),
        p2: j(&[&b, "\n", "Proc-Type: 4,ENCRYPTED\n", "DEK-Info: AES-256-CBC,A1B2C3D4E5F60718293A4B5C6D7E8F90\n", "\n", &l1, "\n", &e]),
        p3: j(&[&b, "\n", "api_key=looksLikeASecretButItsJustPemBase64Content\n", &e]),
        p4: j(&[&b, "\n", &l1, "\n", &l2, " (cut"]),
        g: j(&["-----BEGIN PGP ", "PRIVATE KEY BLOCK-----", "\nVersion: GnuPG v2\n\n", &l1, "\n", &l2, "\n=AbCd\n", "-----END PGP ", "PRIVATE KEY BLOCK-----"]),
        b,
        e,
        l1,
        l2,
    }
}

type Case = (String, Vec<(&'static str, i64, i64)>);

/// What: the SCREEN-02 vectors: text and expected (label, start, end). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: nothing.
fn cases_02() -> Vec<Case> {
    let x = v();
    vec![
        (j(&["here is my key: ", &x.k1]), vec![("openai_style_api_key", 16, 43)]),
        (j(&["STRIPE_KEY=", &x.k2]), vec![("stripe_style_api_key", 11, 43)]),
        (j(&[&x.k3, " used in the demo"]), vec![("stripe_style_api_key", 0, 32)]),
        (j(&["AWS_ACCESS_KEY_ID=", &x.k4]), vec![("aws_access_key_id", 18, 38)]),
        (j(&["token: ", &x.k5]), vec![("github_token", 7, 47)]),
        (j(&["use ", &x.k6, " now"]), vec![("github_token", 4, 62)]),
        (x.k7.clone(), vec![("slack_token", 0, 40)]),
        (j(&["key=", &x.k8, "&x=1"]), vec![("google_api_key", 4, 43)]),
        (j(&["secret ", &x.k9, "."]), vec![("webhook_signing_secret", 7, 45)]),
        (j(&["Authorization token captured: ", &x.jw]), vec![("jwt", 30, 162)]),
        (j(&["ASIA", "IOSFODNN7EXAMPLE"]), vec![("aws_access_key_id", 0, 20)]),
        (j(&["task-", "abcdEFGH12345678ijklMNOP"]), vec![]),
        (j(&["X", &x.k4]), vec![]),
        (j(&[&x.k2, "_x"]), vec![]),
        ("class sk-spinner-three-bounce is used".to_string(), vec![]),
    ]
}

/// What: the SCREEN-03 vectors. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn cases_03() -> Vec<Case> {
    let x = v();
    vec![
        (j(&["a ", &x.p1, " b"]), vec![("pem_private_key", 2, 192)]),
        (x.p2.clone(), vec![("pem_private_key", 0, 205)]),
        (x.p3.clone(), vec![("pem_private_key", 0, 112)]),
        ("api_key=looksLikeASecretButItsJustPemBase64Content".to_string(), vec![("generic_key_value_assignment", 8, 50)]),
        (j(&["x ", &x.p4]), vec![("pem_private_key", 2, 162)]),
        (j(&["-", &x.b, "\n-", &x.l1, "\n-", &x.l2, "\n-", &x.e]), vec![("pem_private_key", 1, 163)]),
        (j(&["> ", &x.b, "\n> ", &x.l1, "\n> ", &x.l2, "\n> ", &x.e]), vec![("pem_private_key", 2, 198)]),
        (x.g.clone(), vec![("pem_private_key", 0, 227)]),
        (j(&[&x.b, "\n", &"A".repeat(30), "\\n", &"A".repeat(30)]), vec![("pem_private_key", 0, 94)]),
        (j(&[&x.b, "\n", &"A".repeat(29), "\\n", &"A".repeat(30)]), vec![]),
        (j(&[&x.b, "\n", &"A".repeat(59)]), vec![]),
        (j(&["Look for the line ", &x.b, " in the file."]), vec![]),
    ]
}

/// What: the SCREEN-04 vectors. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn cases_04() -> Vec<Case> {
    let x = v();
    vec![
        ("curl -H 'Authorization: Bearer abc123DEF456ghi789JKL'".to_string(), vec![("bearer_token", 31, 52)]),
        ("authorization: BEARER abc123DEF456ghi789JKL".to_string(), vec![("bearer_token", 22, 43)]),
        ("Bearer authentication is required".to_string(), vec![]),
        (j(&["Bearer ", &x.jw]), vec![("jwt", 7, 139)]),
        (j(&["postgres://app:", "S3cr3t-Pa55@db.internal:5432/app"]), vec![("url_credentials", 15, 26)]),
        (j(&["ssh://git:", "hunter2secret@host/repo"]), vec![("url_credentials", 10, 23)]),
        ("https://user:password@example.com/".to_string(), vec![]),
        ("https://jane@example.com/x".to_string(), vec![]),
        // the scheme is built from pieces so the runner never reads it as a package name
        (j(&["red", "is://:", "Sup3rS3cretValue@cache.example.com:6379/0"]), vec![("url_credentials", 9, 25)]),
        ("http://localhost:8080/@foo and https://example.com/a:b@c".to_string(), vec![]),
        ("Our API uses Bearer authentication.".to_string(), vec![]),
        ("Send the header with bearer token-based auth".to_string(), vec![]),
    ]
}

/// What: the SCREEN-05 vectors. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn cases_05() -> Vec<Case> {
    let g = "generic_key_value_assignment";
    let mut v: Vec<Case> = vec![
        ("DB_PASSWORD=Sup3rS3cretValue!\n".into(), vec![(g, 12, 29)]),
        ("internal_api_key: \"zx91-nq7f-88ab-lorem\"".into(), vec![(g, 19, 39)]),
        ("{\"password\": \"hunter2hunter2\"}".into(), vec![(g, 14, 28)]),
        ("{\\\"password\\\":\\\"hunter2hunter2\\\"}".into(), vec![(g, 16, 30)]),
        ("db_password: CorrectHorseBatteryStaple".into(), vec![(g, 13, 38)]),
        ("the db_password: CorrectHorseBatteryStaple9 I mentioned".into(), vec![(g, 17, 43)]),
        ("password: DOMAIN\\Administrator1".into(), vec![(g, 10, 31)]),
        ("API_KEY = 'Zx91Nq7f88ab'".into(), vec![(g, 11, 23)]),
        ("token=abc12345;next".into(), vec![(g, 6, 14)]),
        ("password: p\u{00e4}ssw\u{00f6}rd123".into(), vec![(g, 10, 21)]),
        (j(&[&"a".repeat(40), "token=abc12345def"]), vec![(g, 46, 57)]),
        (j(&[&"a".repeat(41), "token=abc12345def"]), vec![]),
        ("'password' => 'Sup3rS3cretValue!',".into(), vec![(g, 15, 32)]),
        ("password := \"Sup3rS3cretValue!\"".into(), vec![(g, 13, 30)]),
        ("password: hunter2!".into(), vec![(g, 10, 18)]),
        ("password: P@ss(w0rd)1x".into(), vec![(g, 10, 22)]),
        ("token: ab12.cd34.ef56gh78".into(), vec![(g, 7, 25)]),
        ("\u{0130} token=abc12345".into(), vec![(g, 8, 16)]),
    ];
    for t in [
        "API_KEY=your_key_here", "password: changeme", "pwd=abc123", "Secret: whatever the team decides",
        "password: WordPress", "My favorite crypto token: Ethereum has been volatile", "class TokenBucket:",
        "Please reset your password before the next login.", "secrets: abc12345def", "password: gr\u{00f6}\u{00df}eres",
        "password: [REDACTED:generic_key_value_assignment]", "The password: required.", "token: optional,",
        "password: changeme.", "password: undefined,", "password = os.getenv(\"DB_PASSWORD\")",
        "api_key = os.environ[\"API_KEY\"]", "secret_key = settings.SECRET_KEY", "apiKey: process.env.STRIPE_KEY,",
        "token = getAccessTokenSilently();", "password: req.body.password,", "API_KEY=$API_KEY", "token=${TOKEN}",
        "api_key: <YOUR_API_KEY>", "Password: ********", "token: Optional[str] = None",
        "password = models.CharField(max_length=128)", "to\u{212a}en=abc12345def", "password: abcdefgh\u{0663}",
    ] {
        v.push((t.to_string(), vec![]));
    }
    v
}

/// What: the SCREEN-06 vectors. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn cases_06() -> Vec<Case> {
    vec![
        ("Contact jane@example.com or call 555-123-4567 for help.".into(), vec![("email_address", 8, 24), ("phone_number", 33, 45)]),
        ("<jane.doe+tag@mail.example.co.uk>".into(), vec![("email_address", 1, 32)]),
        ("see https://example.com/contact?email=jane@example.com".into(), vec![("email_address", 38, 54)]),
        ("call (555) 123-4567 now".into(), vec![("phone_number", 5, 19)]),
        ("+1 555-123-4567".into(), vec![("phone_number", 0, 15)]),
        ("reach me at +442071838750.".into(), vec![("phone_number", 12, 25)]),
        ("SSN 123-45-6789".into(), vec![("ssn", 4, 15)]),
        ("order 5551234567 shipped".into(), vec![]),
        ("jane@example.com_backup".into(), vec![]),
        ("user@localhost and a@b".into(), vec![]),
        ("SSN 000-12-3456, 666-12-3456, 900-12-3456, 123-00-4567, 123-45-0000".into(), vec![]),
    ]
}

/// What: the SCREEN-07 vectors. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn cases_07() -> Vec<Case> {
    let c = "credit_card_number";
    vec![
        ("card 4242 4242 4242 4242 exp 12/27".into(), vec![(c, 5, 24)]),
        ("5555-5555-5555-4444".into(), vec![(c, 0, 19)]),
        ("378282246310005".into(), vec![(c, 0, 15)]),
        ("card 4242 4242 4242 4242 123".into(), vec![(c, 5, 24)]),
        ("4242 4242 4242 4242 1234 5678".into(), vec![(c, 0, 19)]),
        ("4242 4242 4242 4241".into(), vec![]),
        ("1234 5678 1234 5670".into(), vec![]),
        ("ts 1700000000000 ms".into(), vec![]),
        ("42424242424242424242424".into(), vec![]),
        ("x4242424242424242".into(), vec![]),
        ("4242424242424242x".into(), vec![]),
        ("3782 822463 10005".into(), vec![(c, 0, 17)]),
        ("card 4222 2222 2222 2 end".into(), vec![(c, 5, 21)]),
        ("2 2 6 14 8 15 20 6 13".into(), vec![]),
        ("4 8 15 16 23 42 4 8 15 16 23 42 108".into(), vec![]),
    ]
}

/// What: the SCREEN-08 vectors. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn cases_08() -> Vec<Case> {
    let ip = "ip_address";
    vec![
        ("client 203.0.113.7 connected".into(), vec![(ip, 7, 18)]),
        ("from 198.51.100.24.".into(), vec![(ip, 5, 18)]),
        ("addr 2001:db8::8a2e:370:7334 ok".into(), vec![(ip, 5, 28)]),
        ("[2001:0db8:0000:0000:0000:ff00:0042:8329]".into(), vec![(ip, 1, 40)]),
        ("8.8.8.8 and 172.32.0.1 and 2606:4700:4700::1111".into(), vec![(ip, 0, 7), (ip, 12, 22), (ip, 27, 47)]),
        ("127.0.0.1 10.0.0.5 192.168.1.1 172.16.0.1 169.254.1.1 0.0.0.0 224.0.0.1 255.255.255.255".into(), vec![]),
        ("999.1.1.1 and 256.1.1.1 and 08.8.8.8".into(), vec![]),
        ("1.2.3.4.5 and v8.8.8.8".into(), vec![]),
        ("12:30:45 and aa:bb:cc:dd:ee:ff".into(), vec![]),
        ("::1 and fe80::1 and fc00::1".into(), vec![]),
        ("db::add(x) and dead::beef".into(), vec![]),
        ("Version=1.0.0.0, Culture=neutral".into(), vec![]),
    ]
}

/// What: a screener without a hash key. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
fn screener() -> Screener {
    Screener::new(None, DEFAULT_MAX_BYTES).unwrap()
}

/// What: the 32-byte hash key 00 01 ... 1f of the spec. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn hash_key() -> Vec<u8> {
    (0u8..32).collect()
}

/// What: assert that scan_text of each case gives exactly its (label, start, end) list, all categories.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
fn assert_cases(cases: &[Case]) {
    let s = screener();
    for (text, want) in cases {
        let got: Vec<(String, i64, i64)> = s.scan_text(text, &["secret", "pii"]).iter().map(|f| (f.label.clone(), f.start, f.end)).collect();
        let want: Vec<(String, i64, i64)> = want.iter().map(|(l, a, b)| (l.to_string(), *a, *b)).collect();
        assert_eq!(got, want, "vector {:?}", text);
    }
}

/// What: SCREEN-01, the four clean texts are ok, unchanged, with no findings, in both modes.
/// Why: SCREEN-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// SCREEN-01
#[test]
fn test_screen_01_clean_texts_pass() {
    let s = screener();
    for t in [
        "User: let's plan the export feature.\nAssistant: I built the CSV export button and will add a progress bar.\n",
        "def get_cache_key(user_id):\n    return f'user:{user_id}'\n\nclass TokenBucket:\n    def __init__(self, capacity):\n        self.capacity = capacity\n",
        "Please reset your password before the next login.",
        "version 1.2.3.4.5 released at 12:30:45 on 2026-11-10, build 20261110123045, order 1234567890",
    ] {
        for mode in ["reject", "strip"] {
            let r = s.screen_text(t, mode, &["secret", "pii"]);
            assert!(r.ok, "{:?}", t);
            assert_eq!(r.status, 200);
            assert_eq!(r.text.as_deref(), Some(t));
            assert!(r.findings.is_empty());
        }
    }
}

/// What: SCREEN-02, every key shape with its label and span; the four near-misses are not found.
/// Why: SCREEN-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// SCREEN-02
#[test]
fn test_screen_02_key_shapes() {
    assert_cases(&cases_02());
}

/// What: SCREEN-03, private key blocks (complete, encrypted, cut off, quoted, removed in a diff, escaped).
/// Why: SCREEN-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// SCREEN-03
#[test]
fn test_screen_03_private_key_blocks() {
    assert_cases(&cases_03());
}

/// What: SCREEN-04, bearer tokens and URL passwords; prose and placeholders are not found.
/// Why: SCREEN-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// SCREEN-04
#[test]
fn test_screen_04_bearer_and_url_credentials() {
    assert_cases(&cases_04());
}

/// What: SCREEN-05, key = value secrets in every form; placeholders, references and plain words are not.
/// Why: SCREEN-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// SCREEN-05
#[test]
fn test_screen_05_key_value_assignments() {
    assert_cases(&cases_05());
}

/// What: SCREEN-06, email, phone and SSN; the near-misses are not found.
/// Why: SCREEN-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// SCREEN-06
#[test]
fn test_screen_06_email_phone_ssn() {
    assert_cases(&cases_06());
}

/// What: SCREEN-07, card numbers need a card prefix and Luhn; small numbers in a row are not cards.
/// Why: SCREEN-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// SCREEN-07
#[test]
fn test_screen_07_card_numbers() {
    assert_cases(&cases_07());
}

/// What: SCREEN-08, public IPv4 and global IPv6 only. Why: SCREEN-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory.
// SCREEN-08
#[test]
fn test_screen_08_ip_addresses() {
    assert_cases(&cases_08());
}

/// What: SCREEN-09, reject mode refuses with the findings, and the serialized result holds neither the text
/// nor a matched value; with categories ["secret"] the same text is ok with no findings.
/// Why: SCREEN-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// SCREEN-09
#[test]
fn test_screen_09_reject_mode() {
    let key = hash_key();
    let s = Screener::new(Some(&key), DEFAULT_MAX_BYTES).unwrap();
    let t = "Contact jane@example.com or call 555-123-4567 for help.";
    let r = s.screen_text(t, "reject", &["secret", "pii"]);
    assert!(!r.ok);
    assert_eq!(r.status, 422);
    assert_eq!(r.error.as_deref(), Some("secrets_or_pii_detected"));
    assert_eq!(r.text, None);
    assert_eq!(r.findings.len(), 2);
    assert_eq!((r.findings[0].label.as_str(), r.findings[0].start, r.findings[0].end), ("email_address", 8, 24));
    assert_eq!((r.findings[1].label.as_str(), r.findings[1].start, r.findings[1].end), ("phone_number", 33, 45));
    let json = r.to_json().to_string();
    assert!(!json.contains("\"text\""));
    assert!(!json.contains("jane@example.com"));
    assert!(!json.contains("555-123-4567"));
    assert!(!json.contains("Contact"));
    let r2 = s.screen_text(t, "reject", &["secret"]);
    assert!(r2.ok);
    assert_eq!(r2.status, 200);
    assert_eq!(r2.text.as_deref(), Some(t));
    assert!(r2.findings.is_empty());
}

/// What: SCREEN-10, strip mode replaces each finding with its marker and nothing else; the output passes a
/// second screening in reject mode, for every vector with a finding; a match that appears only once its
/// neighbour is redacted makes strip answer 422.
/// Why: SCREEN-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// SCREEN-10
#[test]
fn test_screen_10_strip_mode() {
    let key = hash_key();
    let s = Screener::new(Some(&key), DEFAULT_MAX_BYTES).unwrap();
    let t = "Contact jane@example.com or call 555-123-4567 for help.";
    let r = s.screen_text(t, "strip", &["secret", "pii"]);
    assert!(r.ok);
    assert_eq!(r.status, 200);
    assert_eq!(r.text.as_deref(), Some("Contact [REDACTED:email_address] or call [REDACTED:phone_number] for help."));
    assert_eq!(r.findings.len(), 2);
    let again = s.screen_text(r.text.as_deref().unwrap(), "reject", &["secret", "pii"]);
    assert!(again.ok && again.findings.is_empty());

    let mut all = Vec::new();
    for set in [cases_02(), cases_03(), cases_04(), cases_05(), cases_06(), cases_07(), cases_08()] {
        all.extend(set);
    }
    for (text, want) in all.iter().filter(|(_, w)| !w.is_empty()) {
        let r = s.screen_text(text, "strip", &["secret", "pii"]);
        assert!(r.ok, "strip of {:?}: {:?}", text, r);
        let out = r.text.unwrap();
        for (label, _, _) in want {
            assert!(out.contains(&format!("[REDACTED:{}]", label)), "{:?}", out);
        }
        // every other character is unchanged: rebuild from the original and the findings
        assert_eq!(out, redact_text(text, &r.findings));
        let again = s.screen_text(&out, "reject", &["secret", "pii"]);
        assert!(again.ok && again.findings.is_empty(), "re-screen of {:?}: {:?}", out, again);
    }

    let r = s.screen_text("jane@example.com555-123-4567", "strip", &["secret", "pii"]);
    assert!(!r.ok);
    assert_eq!(r.status, 422);
    assert_eq!(r.error.as_deref(), Some("secrets_or_pii_detected"));
    assert_eq!(r.text, None);
    let got: Vec<(&str, i64, i64)> = r.findings.iter().map(|f| (f.label.as_str(), f.start, f.end)).collect();
    assert_eq!(got, vec![("phone_number", 16, 28), ("email_address", -1, -1)]);
}

/// What: SCREEN-11, overlaps (earliest start, longest span, earlier detector) and code-point positions.
/// Why: SCREEN-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// SCREEN-11
#[test]
fn test_screen_11_overlaps_and_code_points() {
    let x = v();
    assert_cases(&[
        ("\u{00e9}\u{1F600} a@b.co".to_string(), vec![("email_address", 3, 9)]),
        (j(&["token=", &x.k1]), vec![("openai_style_api_key", 6, 33)]),
        (j(&["Bearer ", &x.k1]), vec![("openai_style_api_key", 7, 34)]),
    ]);
    // no character is in two findings
    let s = screener();
    let f = s.scan_text(&j(&["token=", &x.k1, " and Bearer ", &x.jw]), &["secret", "pii"]);
    for w in f.windows(2) {
        assert!(w[0].end <= w[1].start);
    }
}

/// What: SCREEN-12, mask, value_hash with the spec's key and values, null without a key, short key refused.
/// Why: SCREEN-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// SCREEN-12
#[test]
fn test_screen_12_mask_and_value_hash() {
    let x = v();
    assert_eq!(mask(&"a".repeat(15)), "*".repeat(15));
    assert_eq!(mask("abcdefghijklmnop"), "ab************op");
    assert_eq!(mask(&x.k1), j(&["sk", &"*".repeat(23), "OP"]));
    let key = hash_key();
    let s = Screener::new(Some(&key), DEFAULT_MAX_BYTES).unwrap();
    let t = "Contact jane@example.com or call 555-123-4567 for help.";
    let r = s.screen_text(t, "strip", &["pii"]);
    assert!(r.ok);
    assert_eq!(
        r.findings,
        vec![
            Finding { category: "pii".into(), label: "email_address".into(), start: 8, end: 24, preview: "ja************om".into(), value_hash: Some("9487588974759d303d5d44401791a603ad85fda9276d43f7436077d709d9da10".into()), encoded: false },
            Finding { category: "pii".into(), label: "phone_number".into(), start: 33, end: 45, preview: "************".into(), value_hash: Some("ee171612a2f4984e73ec9377b4d10f2b76125f5adf8e4315f12e77ebb2cd41c3".into()), encoded: false },
        ]
    );
    let none = screener().scan_text(t, &["pii"]);
    assert_eq!(none[0].value_hash, None);
    assert_eq!(none[1].value_hash, None);
    assert_eq!(Screener::new(Some(&key[..31]), DEFAULT_MAX_BYTES).err(), Some("invalid_hash_key".to_string()));
}

/// What: SCREEN-13, secrets behind JSON escapes are refused in both modes (vectors E1-E8).
/// Why: SCREEN-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// SCREEN-13
#[test]
fn test_screen_13_hidden_behind_escapes() {
    let x = v();
    let s = screener();
    let enc = |r: &ScreenResult, label: &str| {
        assert!(!r.ok, "{:?}", r);
        assert_eq!(r.status, 422);
        assert_eq!(r.error.as_deref(), Some("secrets_or_pii_detected"));
        assert_eq!(r.text, None);
        assert!(r.findings.iter().any(|f| f.label == label && f.encoded && f.start == -1 && f.end == -1), "{:?}", r.findings);
    };
    let e1 = j(&["{\"note\": \"sk\\u002d", "abcdEFGH12345678ijklMNOP\"}"]);
    let e2 = j(&["{\"outer\": \"{\\\"k\\\": \\\"sk\\\\u002d", "abcdEFGH12345678ijklMNOP\\\"}\"}"]);
    let e3 = "{\"msg\": \"the escape \\u00e9 prints an e-acute and \\n is a newline\"}".to_string();
    let e4 = "{\"contact\": \"jane\\u0040example.com\"}".to_string();
    let e5 = "{\"emoji\": \"\\ud83d\\ude00 ok\", \"path\": \"C:\\\\Users\\\\name\\\\notes.txt\"}".to_string();
    let e6 = j(&["{\"key\": \"", &x.p1.replace('\n', "\\n"), "\"}"]);
    let e7 = j(&["{\"key\": \"", &x.p2.replace('\n', "\\n"), "\"}"]);
    let e8 = j(&[&"\\".repeat(600), "n"]);
    for mode in ["reject", "strip"] {
        enc(&s.screen_text(&e1, mode, &["secret", "pii"]), "openai_style_api_key");
        enc(&s.screen_text(&e2, mode, &["secret", "pii"]), "openai_style_api_key");
        for clean in [&e3, &e5] {
            let r = s.screen_text(clean, mode, &["secret", "pii"]);
            assert!(r.ok, "{:?}", r);
            assert_eq!(r.text.as_deref(), Some(clean.as_str()));
            assert!(r.findings.is_empty());
        }
        enc(&s.screen_text(&e4, mode, &["secret", "pii"]), "email_address");
        enc(&s.screen_text(&e7, mode, &["secret", "pii"]), "pem_private_key");
        let r8 = s.screen_text(&e8, mode, &["secret", "pii"]);
        enc(&r8, "unresolved_escape");
        let u = r8.findings.iter().find(|f| f.label == "unresolved_escape").unwrap();
        assert_eq!((u.category.as_str(), u.preview.as_str(), u.value_hash.clone()), ("secret", "***", None));
    }
    let r6 = s.screen_text(&e6, "reject", &["secret", "pii"]);
    assert_eq!(r6.status, 422);
    assert_eq!(r6.findings.iter().map(|f| (f.label.as_str(), f.start, f.end, f.encoded)).collect::<Vec<_>>(), vec![("pem_private_key", 9, 202, false)]);
    let r6s = s.screen_text(&e6, "strip", &["secret", "pii"]);
    assert!(r6s.ok, "{:?}", r6s);
    assert_eq!(r6s.text.as_deref(), Some("{\"key\": \"[REDACTED:pem_private_key]\"}"));
    assert!(resolve_escapes(&e8).unresolved);
}

/// What: SCREEN-14, input checks before any scan (invalid_mode, invalid_categories, text_too_large at the
/// byte limit) and each hostile 200,000-character input screened in strip mode in under 2 seconds.
/// Why: SCREEN-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// SCREEN-14
#[test]
fn test_screen_14_input_checks_and_hostile_inputs() {
    let s = screener();
    let r = s.screen_text("x", "mask", &["secret", "pii"]);
    assert_eq!((r.ok, r.status, r.error.as_deref()), (false, 400, Some("invalid_mode")));
    let r = s.screen_text("x", "reject", &[]);
    assert_eq!((r.status, r.error.as_deref()), (400, Some("invalid_categories")));
    let r = s.screen_text("x", "reject", &["secret", "keys"]);
    assert_eq!((r.status, r.error.as_deref()), (400, Some("invalid_categories")));
    let t = "\u{00e9}".repeat(5);
    let r = Screener::new(None, 9).unwrap().screen_text(&t, "reject", &["secret", "pii"]);
    assert_eq!((r.status, r.error.as_deref(), r.text.clone()), (413, Some("text_too_large"), None));
    let r = Screener::new(None, 10).unwrap().screen_text(&t, "reject", &["secret", "pii"]);
    assert!(r.ok);
    let x = v();
    let begin = j(&["-----BEGIN ", "PRIVATE KEY-----"]);
    let hostile: Vec<String> = vec![
        "a.".repeat(100000),
        begin.repeat(7400),
        "1234-".repeat(40000),
        "eyJ".repeat(66666),
        "xeyJ-".repeat(40000),
        "xsk-".repeat(50000),
        j(&["password", &" ".repeat(199990)]),
        "token=[REDACTED:".repeat(12500),
        // added by the 2026-11-10 ruling (spec commit fed6e7b): quadratic if each value is measured per match
        "token=$".repeat(28571),
        "a://b:".repeat(33000),
        "ab:".repeat(66000),
        "1.1.".repeat(50000),
        "\\n".repeat(100000),
        j(&[&x.b, &"\n".repeat(199969)]),
        j(&[&x.b, &j(&["\n", &"A".repeat(64)]).repeat(3000)]),
    ];
    for h in &hostile {
        let t0 = Instant::now();
        let r = s.screen_text(h, "strip", &["secret", "pii"]);
        let took = t0.elapsed();
        assert!(r.status == 200 || r.status == 422, "status {}", r.status);
        assert!(took < Duration::from_secs(2), "{} chars starting {:?} took {:?}", h.chars().count(), &h[..12], took);
    }
}

//! Passwordless email code sign-in tests (docs/specs/passwordless_email_code_signin.md, EMAILCODE-01..14),
//! with an injected clock, a fake sender and a fake revoke hook that record their calls (no network), and an
//! injected code generator.
//! Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: memory only.
use super::*;
use sha2::Digest;
use std::collections::VecDeque;
use std::sync::atomic::AtomicI64;

const T0: i64 = 1699920000;
const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
const IP: &str = "203.0.113.7";

/// What: the test harness. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
struct H {
    store: Arc<InMemoryStore>,
    now: Arc<AtomicI64>,
    sent: Arc<Mutex<Vec<(String, String, i64)>>>,
    send_answer: Arc<Mutex<Result<bool, String>>>,
    revoked: Arc<Mutex<Vec<String>>>,
    codes: Arc<Mutex<VecDeque<String>>>,
    svc: EmailCodeSignin,
}

/// What: a harness; queued codes come first, then the default CODE generator on the system CSPRNG.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
fn harness() -> H {
    let store = Arc::new(InMemoryStore::default());
    let now = Arc::new(AtomicI64::new(T0));
    let sent: Arc<Mutex<Vec<(String, String, i64)>>> = Arc::new(Mutex::new(Vec::new()));
    let send_answer: Arc<Mutex<Result<bool, String>>> = Arc::new(Mutex::new(Ok(true)));
    let revoked: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let codes: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::new()));
    let (c, s, a, r, q) = (now.clone(), sent.clone(), send_answer.clone(), revoked.clone(), codes.clone());
    let rnd = system_random();
    let svc = EmailCodeSignin::new(
        SECRET,
        Some(Arc::new(move |to: &str, code: &str, ttl: i64| {
            s.lock().unwrap().push((to.to_string(), code.to_string(), ttl));
            a.lock().unwrap().clone()
        })),
        store.clone(),
        Arc::new(move || c.load(Ordering::SeqCst)),
    )
    .unwrap()
    .with_revoke(Arc::new(move |id: &str| {
        r.lock().unwrap().push(id.to_string());
        Ok(())
    }))
    .with_code_generator(Arc::new(move || q.lock().unwrap().pop_front().unwrap_or_else(|| code_from_random(&rnd))));
    H { store, now, sent, send_answer, revoked, codes, svc }
}

/// What: harness helpers. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
impl H {
    /// What: set the clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn at(&self, t: i64) {
        self.now.store(t, Ordering::SeqCst);
    }
    /// What: start for an address and return the code the sender got. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: memory.
    fn send(&self, email: &str) -> String {
        self.svc.start(email, IP).unwrap();
        self.sent.lock().unwrap().last().unwrap().1.clone()
    }
    /// What: seed an account row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn seed(&self, id: &str, email: &str, verified: Option<i64>, status: &str) {
        self.store.tables.lock().unwrap().accounts.push(Account { id: id.into(), email: email.into(), email_verified_at: verified, status: status.into(), created_at: 1 });
    }
    /// What: the account row for an email. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn account(&self, email: &str) -> Option<Account> {
        self.store.tables.lock().unwrap().accounts.iter().find(|a| a.email == email).cloned()
    }
    /// What: the stored code row for an email. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn code_row(&self, email: &str) -> Option<CodeRow> {
        let h = self.svc.email_hash(email);
        self.store.tables.lock().unwrap().email_codes.get(&h).cloned()
    }
}

/// What: a wrong 6-digit code for `right`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn wrong(right: &str) -> String {
    if right == "111111" { "222222".into() } else { "111111".into() }
}

/// What: the one 400 body. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn invalid() -> Refusal {
    refuse("invalid_code", 400)
}

/// What: EMAILCODE-01, start and verify; a second sign-in finds the same account; an unverified existing row
/// is revoked once and then verified; an account made by verify is never revoked.
/// Why: EMAILCODE-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// EMAILCODE-01
#[test]
fn test_emailcode_01_sign_in_and_sign_up() {
    let h = harness();
    assert_eq!(h.svc.start("user@example.com", IP).unwrap(), Started { status: 202, sent: true, expires_in: 600 });
    let calls = h.sent.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!((calls[0].0.as_str(), calls[0].2), ("user@example.com", 600));
    assert!(calls[0].1.len() == 6 && calls[0].1.bytes().all(|b| b.is_ascii_digit()));
    let first = h.svc.verify("user@example.com", &calls[0].1, IP).unwrap();
    assert_eq!((first.status, first.email.as_str(), first.new_account), (200, "user@example.com", true));
    assert_eq!(first.account_id.len(), 32);
    let a = h.account("user@example.com").unwrap();
    assert_eq!((a.id.clone(), a.email_verified_at, a.status.as_str()), (first.account_id.clone(), Some(T0), "active"));
    let code = h.send("user@example.com");
    let second = h.svc.verify("user@example.com", &code, IP).unwrap();
    assert_eq!((second.account_id, second.new_account), (first.account_id, false));
    assert!(h.revoked.lock().unwrap().is_empty());
    // a row that exists unverified (an invitation, a password sign-up)
    h.seed("acct_unproven", "invited@example.com", None, "active");
    h.at(T0 + 5);
    let code = h.send("invited@example.com");
    let r = h.svc.verify("invited@example.com", &code, IP).unwrap();
    assert_eq!((r.account_id.as_str(), r.new_account), ("acct_unproven", false));
    assert_eq!(*h.revoked.lock().unwrap(), vec!["acct_unproven".to_string()]);
    assert_eq!(h.account("invited@example.com").unwrap().email_verified_at, Some(T0 + 5));
}

/// What: EMAILCODE-02, the stored hashes are the spec's values and no table holds the address, the IP, the
/// code or a plain SHA-256 of the code.
/// Why: EMAILCODE-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// EMAILCODE-02
#[test]
fn test_emailcode_02_storage() {
    let h = harness();
    assert_eq!(h.svc.email_hash("user@example.com"), "587522269e243312a5d6f20bcdc78dc97a3e644e2ad702cdb94ac9550c03b346");
    assert_eq!(h.svc.code_hash("user@example.com", "123456"), "761f222c89dc1744c480d21e141277cc9af815ee0e2a1d7489c9282594728b5b");
    assert_eq!(h.svc.ip_hash(IP), "e01c4eeb03c058165d49564dcaf561cf");
    h.codes.lock().unwrap().push_back("123456".into());
    h.svc.start("user@example.com", IP).unwrap();
    let t = h.store.tables.lock().unwrap().clone();
    let row = t.email_codes.get("587522269e243312a5d6f20bcdc78dc97a3e644e2ad702cdb94ac9550c03b346").unwrap();
    assert_eq!(row.code_hash, "761f222c89dc1744c480d21e141277cc9af815ee0e2a1d7489c9282594728b5b");
    assert_eq!((row.expires_at, row.attempts, row.created_at), (T0 + 600, 0, T0));
    let mut keys: Vec<String> = t.rate_windows.keys().map(|k| k.0.clone()).collect();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "start-email#587522269e243312a5d6f20bcdc78dc9".to_string(),
            "start-email-day#587522269e243312a5d6f20bcdc78dc9".to_string(),
            "start-ip#e01c4eeb03c058165d49564dcaf561cf".to_string(),
        ]
    );
    let dump = format!("{:?}{:?}", t.email_codes, t.rate_windows);
    let plain: String = sha2::Sha256::digest(b"123456").iter().map(|b| format!("{:02x}", b)).collect();
    for s in ["user@example.com", IP, "123456", plain.as_str()] {
        assert!(!dump.contains(s), "{}", s);
    }
}

/// What: EMAILCODE-02, a missing IP: ip_hash("") equals ip_hash("unknown"), and a start with no IP bumps the
/// "start-ip#" key of "unknown", so requests without an IP share one rate window.
/// In: none. Out: panics on a mismatch.
/// Why: spec CONVENTIONS (a missing IP is the text "unknown"); review finding 4525101359.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// EMAILCODE-02
#[test]
fn test_emailcode_02_missing_ip_is_unknown() {
    let h = harness();
    let unknown = h.svc.ip_hash("unknown");
    assert_eq!(h.svc.ip_hash(""), unknown);
    assert_ne!(h.svc.ip_hash(""), h.svc.hmac_hex("ip:")[..32].to_string());
    h.svc.start("user@example.com", "").unwrap();
    let t = h.store.tables.lock().unwrap().clone();
    assert!(t.rate_windows.keys().any(|k| k.0 == format!("start-ip#{}", unknown)));
}

/// What: EMAILCODE-03, a code works once. Why: EMAILCODE-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory.
// EMAILCODE-03
#[test]
fn test_emailcode_03_single_use() {
    let h = harness();
    let code = h.send("a@x.com");
    assert!(h.svc.verify("a@x.com", &code, IP).is_ok());
    assert_eq!(h.svc.verify("a@x.com", &code, IP).unwrap_err(), invalid());
}

/// What: EMAILCODE-04, accepted 599 s after start, refused at 600 s. Why: EMAILCODE-04.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// EMAILCODE-04
#[test]
fn test_emailcode_04_expiry() {
    let h = harness();
    let a = h.send("a@x.com");
    let b = h.send("b@x.com");
    h.at(T0 + 599);
    assert!(h.svc.verify("a@x.com", &a, IP).is_ok());
    h.at(T0 + 600);
    assert_eq!(h.svc.verify("b@x.com", &b, IP).unwrap_err(), invalid());
    assert!(h.code_row("b@x.com").is_none());
}

/// What: EMAILCODE-05, five tries per code. Why: EMAILCODE-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory.
// EMAILCODE-05
#[test]
fn test_emailcode_05_five_tries() {
    let h = harness();
    let a = h.send("a@x.com");
    for _ in 0..5 {
        assert_eq!(h.svc.verify("a@x.com", &wrong(&a), IP).unwrap_err(), invalid());
    }
    assert!(h.code_row("a@x.com").is_none());
    assert_eq!(h.svc.verify("a@x.com", &a, IP).unwrap_err(), invalid());
    let b = h.send("b@x.com");
    for _ in 0..4 {
        assert_eq!(h.svc.verify("b@x.com", &wrong(&b), IP).unwrap_err(), invalid());
    }
    assert!(h.svc.verify("b@x.com", &b, IP).is_ok());
}

/// What: EMAILCODE-06, a new start replaces the code and its try count. Why: EMAILCODE-06.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// EMAILCODE-06
#[test]
fn test_emailcode_06_new_start_replaces() {
    let h = harness();
    h.codes.lock().unwrap().extend(["111111".to_string(), "333333".to_string()]);
    let first = h.send("a@x.com");
    for _ in 0..4 {
        h.svc.verify("a@x.com", "999999", IP).unwrap_err();
    }
    let second = h.send("a@x.com");
    assert_eq!(h.code_row("a@x.com").unwrap().attempts, 0);
    assert_eq!(h.svc.verify("a@x.com", &first, IP).unwrap_err(), invalid());
    for _ in 0..3 {
        h.svc.verify("a@x.com", "999999", IP).unwrap_err();
    }
    let r = h.svc.verify("a@x.com", &second, IP).unwrap();
    assert_eq!(r.email, "a@x.com");
}

/// What: EMAILCODE-07, no enumeration: start answers and sends alike for known and unknown addresses and never
/// reads accounts; verify's 400 body is the same for every code fault.
/// Why: EMAILCODE-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// EMAILCODE-07
#[test]
fn test_emailcode_07_no_enumeration() {
    let h = harness();
    h.seed("acct_known", "known@x.com", Some(1), "active");
    let a = h.svc.start("known@x.com", IP).unwrap();
    let b = h.svc.start("unknown@x.com", IP).unwrap();
    assert_eq!(a, b);
    let calls = h.sent.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    for (to, code, ttl) in &calls {
        assert!(to.ends_with("@x.com") && code.len() == 6 && *ttl == 600);
    }
    assert_eq!(h.store.account_reads.load(Ordering::SeqCst), 0);
    let wrong_code = h.svc.verify("known@x.com", &wrong(&calls[0].1), IP).unwrap_err();
    let used_code = {
        let c = h.send("used@x.com");
        h.svc.verify("used@x.com", &c, IP).unwrap();
        h.svc.verify("used@x.com", &c, IP).unwrap_err()
    };
    let never = h.svc.verify("never@x.com", "123456", IP).unwrap_err();
    h.at(T0 + 600);
    let expired = h.svc.verify("unknown@x.com", &calls[1].1, IP).unwrap_err();
    for r in [wrong_code, used_code, never, expired] {
        assert_eq!(r, invalid());
    }
}

/// What: EMAILCODE-08, sends per address: 5 an hour, 10 a day, refused starts count toward the day.
/// Why: EMAILCODE-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// EMAILCODE-08
#[test]
fn test_emailcode_08_sends_per_address() {
    let h = harness();
    for _ in 0..5 {
        assert!(h.svc.start("a@x.com", IP).is_ok());
    }
    assert_eq!(h.svc.start("a@x.com", IP).unwrap_err(), refuse("too_many_requests", 429));
    assert_eq!(h.sent.lock().unwrap().len(), 5);
    h.at(T0 + 3600);
    for _ in 0..4 {
        assert!(h.svc.start("a@x.com", IP).is_ok());
    }
    assert_eq!(h.svc.start("a@x.com", IP).unwrap_err(), refuse("too_many_requests", 429));
    assert_eq!(h.sent.lock().unwrap().len(), 9);
    h.at(T0 + 86400);
    assert!(h.svc.start("a@x.com", IP).is_ok());
}

/// What: EMAILCODE-09, sends per IP: the 21st start from one IP in an hour is 429; another IP is not affected.
/// Why: EMAILCODE-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// EMAILCODE-09
#[test]
fn test_emailcode_09_sends_per_ip() {
    let h = harness();
    for i in 0..20 {
        assert!(h.svc.start(&format!("u{}@x.com", i), IP).is_ok());
    }
    assert_eq!(h.svc.start("u20@x.com", IP).unwrap_err(), refuse("too_many_requests", 429));
    assert!(h.svc.start("u20@x.com", "198.51.100.9").is_ok());
}

/// What: EMAILCODE-10, tries per IP (31st is 429, right code too) and per address (11th is 429 from any IP,
/// whatever new codes were sent). Why: EMAILCODE-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// EMAILCODE-10
#[test]
fn test_emailcode_10_tries_per_ip_and_address() {
    let h = harness();
    let right = h.send("target@x.com");
    for i in 0..30 {
        assert_eq!(h.svc.verify(&format!("v{}@x.com", i), "123456", "198.51.100.1").unwrap_err(), invalid());
    }
    assert_eq!(h.svc.verify("target@x.com", &right, "198.51.100.1").unwrap_err(), refuse("too_many_requests", 429));
    assert!(h.svc.verify("target@x.com", &right, "198.51.100.2").is_ok());

    let h = harness();
    let mut n = 0;
    for _ in 0..2 {
        let c = h.send("b@x.com");
        for _ in 0..5 {
            n += 1;
            assert_eq!(h.svc.verify("b@x.com", &wrong(&c), &format!("10.0.0.{}", n)).unwrap_err(), invalid());
        }
    }
    let c = h.send("b@x.com");
    assert_eq!(h.svc.verify("b@x.com", &c, "10.0.1.1").unwrap_err(), refuse("too_many_requests", 429));
    h.at(T0 + 3600);
    let c = h.send("b@x.com");
    assert!(h.svc.verify("b@x.com", &c, "10.0.1.1").is_ok());
}

/// What: EMAILCODE-11, input handling: trimming and ASCII lower case only, malformed addresses, code
/// separators, and malformed codes that spend no try.
/// Why: EMAILCODE-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// EMAILCODE-11
#[test]
fn test_emailcode_11_input() {
    assert_eq!(normalize_email(" A@X.com ").as_deref(), Some("a@x.com"));
    for bad in ["a@b", "a b@x.com", "a@x..com", ".a@x.com", "a@x.com,b@y.com", "<a@x.com>", "a@x.com\u{00a0}", "a@x.com\u{000b}", "a@x.com\u{0000}", "\u{212a}@x.com"] {
        assert_eq!(normalize_email(bad), None, "{:?}", bad);
    }
    let h = harness();
    let code = h.send(" A@X.com ");
    assert_eq!(h.sent.lock().unwrap()[0].0, "a@x.com");
    assert_eq!(h.svc.verify(" A@X.com ", &code, IP).unwrap().email, "a@x.com");
    assert_eq!(h.svc.start("a@b", IP).unwrap_err(), refuse("invalid_email", 422));
    assert_eq!(h.svc.start("\u{212a}@x.com", IP).unwrap_err(), refuse("invalid_email", 422));
    assert_eq!(h.svc.verify("a@b", "123456", IP).unwrap_err(), invalid());
    h.codes.lock().unwrap().extend(["123456".to_string(), "123456".to_string(), "123456".to_string()]);
    h.send("s@x.com");
    assert!(h.svc.verify("s@x.com", "123 456", IP).is_ok());
    h.send("d@x.com");
    assert!(h.svc.verify("d@x.com", "123-456", IP).is_ok());
    h.send("m@x.com");
    for bad in ["12345", "1234567", "abcdef", "\u{0661}\u{0662}\u{0663}\u{0664}\u{0665}\u{0666}"] {
        assert_eq!(h.svc.verify("m@x.com", bad, IP).unwrap_err(), invalid());
        assert_eq!(h.code_row("m@x.com").unwrap().attempts, 0);
    }
    assert!(h.svc.verify("m@x.com", "123456", IP).is_ok());
}

/// What: EMAILCODE-12, a failing sender is 503 send_failed with no code left; bad configuration fails.
/// Why: EMAILCODE-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// EMAILCODE-12
#[test]
fn test_emailcode_12_send_failed_and_configuration() {
    let h = harness();
    *h.send_answer.lock().unwrap() = Ok(false);
    assert_eq!(h.svc.start("a@x.com", IP).unwrap_err(), refuse("send_failed", 503));
    assert!(h.code_row("a@x.com").is_none());
    *h.send_answer.lock().unwrap() = Err("smtp down".into());
    assert_eq!(h.svc.start("b@x.com", IP).unwrap_err(), refuse("send_failed", 503));
    assert!(h.code_row("b@x.com").is_none());
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::default());
    let clock: Clock = Arc::new(|| T0);
    let sender: Sender = Arc::new(|_: &str, _: &str, _: i64| Ok(true));
    assert_eq!(EmailCodeSignin::new(&SECRET[..31], Some(sender.clone()), store.clone(), clock.clone()).err(), Some("not_configured".to_string()));
    assert_eq!(EmailCodeSignin::new(SECRET, None, store.clone(), clock.clone()).err(), Some("not_configured".to_string()));
    assert!(EmailCodeSignin::new(SECRET, Some(sender), store, clock).is_ok());
}

/// What: EMAILCODE-13, a suspended or closed account: the right code is 403 and the code is used up.
/// Why: EMAILCODE-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// EMAILCODE-13
#[test]
fn test_emailcode_13_unavailable_account() {
    let h = harness();
    for (id, email, status) in [("acct_s", "s@x.com", "suspended"), ("acct_c", "c@x.com", "closed")] {
        h.seed(id, email, Some(1), status);
        let code = h.send(email);
        assert_eq!(h.svc.verify(email, &code, IP).unwrap_err(), refuse("account_unavailable", 403));
        assert!(h.code_row(email).is_none());
        assert_eq!(h.svc.verify(email, &code, IP).unwrap_err(), invalid());
    }
}

/// What: EMAILCODE-14, a code is bound to its address; leading zeros are kept; the default generator.
/// Why: EMAILCODE-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory, the OS random source.
// EMAILCODE-14
#[test]
fn test_emailcode_14_codes() {
    let h = harness();
    let a = h.send("a@x.com");
    assert_eq!(h.svc.verify("b@x.com", &a, IP).unwrap_err(), invalid());
    h.codes.lock().unwrap().push_back("000042".into());
    assert_eq!(h.send("z@x.com"), "000042");
    assert!(h.svc.verify("z@x.com", "000042", IP).is_ok());
    let queue = Arc::new(Mutex::new(VecDeque::from(vec![
        0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0xff, 0xf1, 0x3d, 0x7f, 0xff, 0xf1, 0x3d, 0x80, 0x00, 0x00, 0x00, 0x2a,
    ])));
    let q = queue.clone();
    let rb: RandomBytes = Arc::new(move |n| (0..n).map(|_| q.lock().unwrap().pop_front().unwrap()).collect());
    assert_eq!(code_from_random(&rb), "483648");
    assert_eq!(code_from_random(&rb), "999999");
    assert_eq!(code_from_random(&rb), "000042");
    assert!(queue.lock().unwrap().is_empty());
    // the service's default generator draws from its random source
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::default());
    let sent: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let s2 = sent.clone();
    let q2 = Arc::new(Mutex::new(VecDeque::from(vec![0x80u8, 0, 0, 0])));
    let svc = EmailCodeSignin::new(SECRET, Some(Arc::new(move |_: &str, c: &str, _: i64| { s2.lock().unwrap().push(c.to_string()); Ok(true) })), store, Arc::new(|| T0))
        .unwrap()
        .with_random(Arc::new(move |n| (0..n).map(|_| q2.lock().unwrap().pop_front().unwrap_or(7)).collect()));
    svc.start("r@x.com", IP).unwrap();
    assert_eq!(sent.lock().unwrap()[0], "483648");
    for _ in 0..50 {
        let c = code_from_random(&system_random());
        assert!(c.len() == 6 && c.bytes().all(|b| b.is_ascii_digit()));
    }
}

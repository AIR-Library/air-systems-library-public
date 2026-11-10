//! TOTP two-factor tests (docs/specs/totp_two_factor.md, TOTP-01..14), with an injected clock and an injected
//! byte queue (served in order, whatever n is asked; a xorshift stream after the queue runs out).
//! Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: memory only.
use super::*;
use sha2::Digest;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, Ordering};

const K: &[u8] = b"12345678901234567890";
const KB32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/// What: the test harness: a store, a settable clock and a byte queue. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory.
struct H {
    store: Arc<InMemoryStore>,
    now: Arc<AtomicI64>,
    queue: Arc<Mutex<VecDeque<u8>>>,
    svc: TotpTwoFactor,
}

/// What: encryption_key 00..1f. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn enc_key() -> Vec<u8> {
    (0u8..32).collect()
}

/// What: recovery_hash_key 40..5f. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn rec_key() -> Vec<u8> {
    (0x40u8..0x60).collect()
}

/// What: a harness with the spec's keys, clock at `now`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
fn harness(now: i64) -> H {
    let store = Arc::new(InMemoryStore::default());
    harness_on(store, now, &enc_key())
}

/// What: a harness over a given store and encryption key. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
fn harness_on(store: Arc<InMemoryStore>, now: i64, key: &[u8]) -> H {
    let clock_now = Arc::new(AtomicI64::new(now));
    let queue: Arc<Mutex<VecDeque<u8>>> = Arc::new(Mutex::new(VecDeque::new()));
    // after the queue: a xorshift stream (a plain counter repeats recovery codes and would loop forever)
    let counter = Arc::new(Mutex::new(0x9E37_79B9_7F4A_7C15u64));
    let c = clock_now.clone();
    let q = queue.clone();
    let svc = TotpTwoFactor::new(
        key,
        &rec_key(),
        "Example App",
        store.clone(),
        Arc::new(move || c.load(Ordering::SeqCst)),
        Some(Arc::new(move |n| {
            let mut q = q.lock().unwrap();
            let mut ctr = counter.lock().unwrap();
            (0..n).map(|_| q.pop_front().unwrap_or_else(|| {
                *ctr ^= *ctr << 13;
                *ctr ^= *ctr >> 7;
                *ctr ^= *ctr << 17;
                (*ctr >> 24) as u8
            })).collect()
        })),
    )
    .unwrap();
    H { store, now: clock_now, queue, svc }
}

/// What: methods of the harness. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
impl H {
    /// What: set the clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn at(&self, t: i64) {
        self.now.store(t, Ordering::SeqCst);
    }
    /// What: queue bytes for random_bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn push(&self, bytes: &[u8]) {
        self.queue.lock().unwrap().extend(bytes.iter().copied());
    }
    /// What: enroll `user` with secret K at now = t (start + confirm); returns the recovery codes.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn enroll_k(&self, user: &str, t: i64) -> Vec<String> {
        self.at(t);
        self.push(K);
        self.push(&(0xa0u8..0xac).collect::<Vec<u8>>());
        let s = self.svc.enroll_start(user, "alice@example.com").unwrap();
        assert_eq!(s.secret, KB32);
        self.svc.enroll_confirm(user, Some(&code_at(t))).unwrap()
    }
    /// What: the user's enrollment row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn row(&self, user: &str) -> Enrollment {
        self.store.get_enrollment(user).unwrap()
    }
    /// What: the number of failure rows of the user. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn failure_rows(&self, user: &str) -> usize {
        self.store.tables.lock().unwrap().failures.iter().filter(|f| f.user_id == user).count()
    }
}

/// What: the 6-digit code of secret K at time t. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn code_at(t: i64) -> String {
    totp_at(KB32, t, 6).unwrap()
}

/// What: a 6-digit code that matches none of the window's three steps at time t.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn wrong_at(t: i64) -> String {
    let near = [code_at(t - 30), code_at(t), code_at(t + 30)];
    (0..1000000).map(|n| format!("{:06}", n)).find(|c| !near.contains(c)).unwrap()
}

/// What: TOTP-01, RFC 4226 and RFC 6238 vectors, and a counter above 32 bits.
/// Why: TOTP-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
// TOTP-01
#[test]
fn test_totp_01_rfc_vectors() {
    let want = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
    for (c, w) in want.iter().enumerate() {
        assert_eq!(hotp(K, c as u64, 6), *w);
    }
    assert_eq!(hotp(K, 4294967296, 6), "999456");
    let rows: [(i64, &str, &str); 6] = [
        (59, "94287082", "287082"),
        (1111111109, "07081804", "081804"),
        (1111111111, "14050471", "050471"),
        (1234567890, "89005924", "005924"),
        (2000000000, "69279037", "279037"),
        (20000000000, "65353130", "353130"),
    ];
    for (t, eight, six) in rows {
        assert_eq!(totp_at(&base32_encode(K), t, 8).unwrap(), eight);
        assert_eq!(totp_at(&base32_encode(K), t, 6).unwrap(), six);
    }
}

/// What: TOTP-02, base32 vectors, lenient decode, invalid characters and lengths, generate_secret.
/// Why: TOTP-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// TOTP-02
#[test]
fn test_totp_02_base32() {
    assert_eq!(base32_encode(K), KB32);
    for (plain, enc) in [("", ""), ("f", "MY"), ("fo", "MZXQ"), ("foo", "MZXW6"), ("foob", "MZXW6YQ"), ("fooba", "MZXW6YTB"), ("foobar", "MZXW6YTBOI")] {
        assert_eq!(base32_encode(plain.as_bytes()), enc);
        if !enc.is_empty() {
            assert_eq!(base32_decode(enc).unwrap(), plain.as_bytes());
        }
    }
    assert_eq!(base32_decode("mzxw 6ytb-oi==").unwrap(), b"foobar");
    assert_eq!(base32_decode("MZ").unwrap(), b"f");
    for bad in ["MZXW6YT1", "", "M", "MZX", "MZXW6Y", "MZXW\u{00e9}"] {
        assert_eq!(base32_decode(bad), Err("invalid_base32".to_string()), "{:?}", bad);
    }
    let h = harness(1000);
    let s = h.svc.generate_secret();
    assert_eq!(s.len(), 32);
    assert_eq!(base32_decode(&s).unwrap().len(), 20);
}

/// What: TOTP-03, enroll_start's answer, the sealed secret in the store (spec string), and replacement.
/// Why: TOTP-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// TOTP-03
#[test]
fn test_totp_03_enroll_start() {
    let h = harness(1111111000);
    h.push(K);
    h.push(&(0xa0u8..0xac).collect::<Vec<u8>>());
    let s = h.svc.enroll_start("user_1", "alice@example.com").unwrap();
    assert_eq!(s.secret, KB32);
    assert_eq!(
        s.otpauth_uri,
        "otpauth://totp/Example%20App%3Aalice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example%20App&algorithm=SHA1&digits=6&period=30"
    );
    let row = h.row("user_1");
    assert_eq!(row.secret_enc, "v1.oKGio6SlpqeoqaqroV0maQKFQOklPLSHVjWKjzfpA1TV+QA621cV0i7kP1B5d8k2owRGDhH/FzF0f662");
    assert_eq!(row.confirmed_at, None);
    assert!(!format!("{:?}", h.store.tables.lock().unwrap()).contains(KB32));
    // a second start before confirming replaces the secret
    let s2 = h.svc.enroll_start("user_1", "alice@example.com").unwrap();
    assert_ne!(s2.secret, s.secret);
    assert_ne!(h.row("user_1").secret_enc, row.secret_enc);
    assert_eq!(h.store.tables.lock().unwrap().enrollments.len(), 1);
}

/// What: TOTP-04, enroll_confirm gives the spec's 8 recovery codes, stores only keyed hashes, and the
/// 409 answers; the confirming code is then refused.
/// Why: TOTP-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// TOTP-04
#[test]
fn test_totp_04_enroll_confirm() {
    let h = harness(1111111000);
    assert_eq!(h.svc.enroll_confirm("user_1", Some("123456")).unwrap_err(), refuse("enrollment_not_started", 409));
    h.push(K);
    h.push(&(0xa0u8..0xac).collect::<Vec<u8>>());
    h.svc.enroll_start("user_1", "alice@example.com").unwrap();
    h.push(&(0..300u32).map(|k| ((7 * k) % 256) as u8).collect::<Vec<u8>>());
    let code = code_at(1111111000);
    let codes = h.svc.enroll_confirm("user_1", Some(&code)).unwrap();
    assert_eq!(
        codes,
        vec!["29gq-y7en-w5ck", "t3ah-rz8f-px6d", "mv4b-js29-gqy5", "ckt3-ahrz-8fpx", "6dmv-4bjs-29gq", "y7en-w5ck-t8fp", "x6dm-v4bj-s29g", "qy7e-nw5c-kt3a"]
    );
    // 101 bytes drawn: 199 of the 300 queued are left
    assert_eq!(h.queue.lock().unwrap().len(), 199);
    for c in &codes {
        assert_eq!(c.len(), 14);
        assert_eq!((&c[4..5], &c[9..10]), ("-", "-"));
    }
    let t = h.store.tables.lock().unwrap().clone();
    assert_eq!(t.recovery.len(), 8);
    assert_eq!(t.recovery[0].code_hash, "d9199ecad0b35d9e2f18857343d7fe79dd5f8425f1c460c88fe18f5c4b4a2645");
    let dump = format!("{:?}", t);
    for c in &codes {
        assert!(!dump.contains(c.as_str()) && !dump.contains(&c.replace('-', "")));
    }
    assert!(h.row("user_1").confirmed_at.is_some());
    assert_eq!(h.svc.verify("user_1", Some(&code)).unwrap_err(), refuse("invalid_code", 401));
    assert_eq!(h.svc.enroll_confirm("user_1", Some(&code)).unwrap_err(), refuse("already_enrolled", 409));
    assert_eq!(h.svc.enroll_start("user_1", "alice@example.com").unwrap_err(), refuse("already_enrolled", 409));
}

/// What: TOTP-05, the window: previous, current and next step accepted; two back and two ahead refused.
/// Why: TOTP-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// TOTP-05
#[test]
fn test_totp_05_window() {
    let h = harness(1111111000);
    h.enroll_k("user_1", 1111111000);
    h.at(1111111109);
    assert_eq!(h.svc.verify("user_1", Some("150727")).unwrap_err(), refuse("invalid_code", 401));
    assert_eq!(h.svc.verify("user_1", Some("266759")).unwrap_err(), refuse("invalid_code", 401));
    for c in ["731029", "081804", "050471"] {
        let v = h.svc.verify("user_1", Some(c)).unwrap();
        assert_eq!((v.ok, v.method.as_str()), (true, "totp"));
    }
}

/// What: TOTP-06, replay guard: a used code, an earlier step's code, a later step accepted; claim once per step.
/// Why: TOTP-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// TOTP-06
#[test]
fn test_totp_06_replay() {
    let h = harness(1111111000);
    h.enroll_k("user_1", 1111111000);
    h.at(1111111109);
    assert!(h.svc.verify("user_1", Some("081804")).is_ok());
    assert_eq!(h.svc.verify("user_1", Some("081804")).unwrap_err(), refuse("invalid_code", 401));
    assert_eq!(h.svc.verify("user_1", Some("731029")).unwrap_err(), refuse("invalid_code", 401));
    assert!(h.svc.verify("user_1", Some("050471")).is_ok());
    assert_eq!(h.row("user_1").last_used_step, 37037037);
    assert!(h.store.claim("user_1", 37037040));
    assert!(!h.store.claim("user_1", 37037040));
}

/// What: TOTP-07, separators are accepted; malformed codes are 401 and each adds one failure.
/// Why: TOTP-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// TOTP-07
#[test]
fn test_totp_07_input_forms() {
    let h = harness(1111111000);
    for (i, c) in ["081804", "081 804", "081-804"].iter().enumerate() {
        let u = format!("ok_{}", i);
        h.enroll_k(&u, 1111111000);
        h.at(1111111109);
        assert_eq!(h.svc.verify(&u, Some(c)).unwrap().method, "totp");
    }
    let long = "1".repeat(65);
    let bad: [Option<&str>; 7] = [Some("12345"), Some("1234567"), Some("abcdef"), Some(""), None, Some(&long), Some("\u{0661}\u{0662}\u{0663}\u{0664}\u{0665}\u{0666}")];
    for (i, c) in bad.iter().enumerate() {
        let u = format!("bad_{}", i);
        h.enroll_k(&u, 1111111000);
        h.at(1111111109);
        assert_eq!(h.svc.verify(&u, *c).unwrap_err(), refuse("invalid_code", 401), "{:?}", c);
        assert_eq!(h.row(&u).failed_since_success, 1);
        assert_eq!(h.failure_rows(&u), 1);
    }
}

/// What: TOTP-08, recovery codes: once each, any case, no dashes; not across users; keyed hash stored.
/// Why: TOTP-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// TOTP-08
#[test]
fn test_totp_08_recovery_codes() {
    let h = harness(1111111000);
    let codes = h.enroll_k("user_1", 1111111000);
    let codes_b = h.enroll_k("user_b", 1111111000);
    let v = h.svc.verify("user_1", Some(&codes[0])).unwrap();
    assert_eq!((v.method.as_str(), v.recovery_codes_left), ("recovery_code", 7));
    assert_eq!(h.svc.verify("user_1", Some(&codes[0])).unwrap_err(), refuse("invalid_code", 401));
    let v = h.svc.verify("user_1", Some(&codes[1].to_uppercase())).unwrap();
    assert_eq!((v.method.as_str(), v.recovery_codes_left), ("recovery_code", 6));
    let v = h.svc.verify("user_1", Some(&codes[2].replace('-', ""))).unwrap();
    assert_eq!(v.recovery_codes_left, 5);
    assert_eq!(h.svc.verify("user_b", Some(&codes[3])).unwrap_err(), refuse("invalid_code", 401));
    assert_eq!(h.store.recovery_codes_left("user_b"), codes_b.len());
    // the stored hash is the keyed hash, not a plain SHA-256
    let keyed = h.svc.recovery_code_hash("user_1", "k7mq2xpt9hcw");
    assert_eq!(keyed, "5a93360f78c7f03de7336a625adf93bf238749d8da4aaf734271b327c52347a3");
    assert_eq!(recovery_input("K7MQ-2XPT-9HCW").unwrap(), "k7mq2xpt9hcw");
    let plain: String = sha2::Sha256::digest(b"k7mq2xpt9hcw").iter().map(|b| format!("{:02x}", b)).collect();
    assert_ne!(keyed, plain);
    let first = h.store.tables.lock().unwrap().recovery.iter().find(|r| r.user_id == "user_1").unwrap().code_hash.clone();
    assert_eq!(first, h.svc.recovery_code_hash("user_1", &codes[0].replace('-', "")));
}

/// What: TOTP-09, the lock: 5 failures in 900 s lock even a correct code without adding a failure, until 900 s
/// after the oldest; the store's try write gives 5 slots in a window and not a 6th.
/// Why: TOTP-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// TOTP-09
#[test]
fn test_totp_09_lock() {
    let h = harness(1111111000);
    h.enroll_k("user_1", 1111111000);
    let t0 = 1111200000;
    h.at(t0);
    for _ in 0..5 {
        assert_eq!(h.svc.verify("user_1", Some(&wrong_at(t0))).unwrap_err(), refuse("invalid_code", 401));
    }
    let r = h.svc.verify("user_1", Some(&code_at(t0))).unwrap_err();
    assert_eq!(r, Refusal { error: "locked".into(), status: 429, retry_after: Some(900) });
    assert_eq!(h.failure_rows("user_1"), 5);
    assert_eq!(h.row("user_1").failed_since_success, 5);
    assert_eq!(h.svc.status("user_1").locked_until, Some(t0 + 900));
    h.at(t0 + 899);
    assert_eq!(h.svc.verify("user_1", Some(&code_at(t0 + 899))).unwrap_err().retry_after, Some(1));
    h.at(t0 + 900);
    assert_eq!(h.svc.verify("user_1", Some(&code_at(t0 + 900))).unwrap().method, "totp");
    assert_eq!(h.row("user_1").failed_since_success, 0);
    // the store's try write
    let s = InMemoryStore::default();
    for _ in 0..5 {
        assert!(s.try_slot("u", 5000).is_some());
    }
    assert!(s.try_slot("u", 5000).is_none());
    assert!(s.try_slot("u", 5900).is_some());
}

/// What: TOTP-10, an unreadable sealed secret is 503 secret_unreadable with no failure; a recovery code works.
/// Why: TOTP-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// TOTP-10
#[test]
fn test_totp_10_secret_unreadable() {
    let h = harness(1111111000);
    let codes = h.enroll_k("user_1", 1111111000);
    let other = harness_on(h.store.clone(), 1111111109, &[7u8; 32]);
    assert_eq!(other.svc.verify("user_1", Some("081804")).unwrap_err(), refuse("secret_unreadable", 503));
    assert_eq!(h.failure_rows("user_1"), 0);
    assert_eq!(h.row("user_1").failed_since_success, 0);
    // one changed character of the sealed text
    {
        let mut t = h.store.tables.lock().unwrap();
        let r = t.enrollments.get_mut("user_1").unwrap();
        let mut chars: Vec<char> = r.secret_enc.chars().collect();
        chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
        r.secret_enc = chars.into_iter().collect();
    }
    h.at(1111111109);
    assert_eq!(h.svc.verify("user_1", Some("081804")).unwrap_err(), refuse("secret_unreadable", 503));
    assert_eq!(h.failure_rows("user_1"), 0);
    assert_eq!(h.svc.verify("user_1", Some(&codes[0])).unwrap().method, "recovery_code");
}

/// What: TOTP-11, seal/open known answer, open refusals, construction refusals.
/// Why: TOTP-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
// TOTP-11
#[test]
fn test_totp_11_seal_open() {
    let nonce: Vec<u8> = (0xa0u8..0xac).collect();
    let sealed = seal(&enc_key(), &nonce, KB32.as_bytes(), "totp:user_1");
    assert_eq!(sealed, "v1.oKGio6SlpqeoqaqroV0maQKFQOklPLSHVjWKjzfpA1TV+QA621cV0i7kP1B5d8k2owRGDhH/FzF0f662");
    assert_eq!(open(&enc_key(), &sealed, "totp:user_1").unwrap(), KB32.as_bytes());
    assert_eq!(open(&enc_key(), &sealed, "totp:user_2"), None);
    assert_eq!(open(&[9u8; 32], &sealed, "totp:user_1"), None);
    let mut changed: Vec<char> = sealed.chars().collect();
    changed[20] = if changed[20] == 'x' { 'y' } else { 'x' };
    assert_eq!(open(&enc_key(), &changed.into_iter().collect::<String>(), "totp:user_1"), None);
    assert_eq!(open(&enc_key(), "v1.AAAA", "totp:user_1"), None);
    assert_eq!(open(&enc_key(), "oKGio6SlpqeoqaqroV0maQ", "totp:user_1"), None);
    assert_eq!(open(&enc_key(), "v1.!!!", "totp:user_1"), None);
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::default());
    let clock: Clock = Arc::new(|| 0);
    for (ek, rk) in [(vec![0u8; 31], rec_key()), (vec![0u8; 33], rec_key()), (enc_key(), vec![0u8; 31])] {
        assert_eq!(TotpTwoFactor::new(&ek, &rk, "X", store.clone(), clock.clone(), None).err(), Some("invalid_key".to_string()));
    }
    assert!(TotpTwoFactor::new(&enc_key(), &vec![0u8; 64], "X", store, clock, None).is_ok());
}

/// What: TOTP-12, disable with a valid code deletes everything; with a wrong code deletes nothing.
/// Why: TOTP-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// TOTP-12
#[test]
fn test_totp_12_disable() {
    let h = harness(1111111000);
    h.enroll_k("user_1", 1111111000);
    h.at(1111111109);
    assert_eq!(h.svc.disable("user_1", Some(&wrong_at(1111111109))).unwrap_err(), refuse("invalid_code", 401));
    assert!(h.store.get_enrollment("user_1").is_some());
    assert_eq!(h.store.recovery_codes_left("user_1"), 8);
    assert_eq!(h.failure_rows("user_1"), 1);
    assert_eq!(h.svc.disable("user_1", Some("081804")), Ok(true));
    let t = h.store.tables.lock().unwrap().clone();
    assert!(t.enrollments.get("user_1").is_none());
    assert!(t.recovery.iter().all(|r| r.user_id != "user_1"));
    assert!(t.failures.iter().all(|f| f.user_id != "user_1"));
    assert_eq!(h.svc.verify("user_1", Some("050471")).unwrap_err(), refuse("not_enrolled", 409));
    assert!(!h.svc.status("user_1").enrolled);
}

/// What: TOTP-13, before confirmation verify and disable are 409 not_enrolled with the right code; two users
/// never accept each other's codes.
/// Why: TOTP-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// TOTP-13
#[test]
fn test_totp_13_not_enrolled_and_isolation() {
    let h = harness(1111111000);
    h.push(K);
    h.push(&(0xa0u8..0xac).collect::<Vec<u8>>());
    h.svc.enroll_start("user_1", "a").unwrap();
    let right = code_at(1111111000);
    assert_eq!(h.svc.verify("user_1", Some(&right)).unwrap_err(), refuse("not_enrolled", 409));
    assert_eq!(h.svc.disable("user_1", Some(&right)).unwrap_err(), refuse("not_enrolled", 409));
    assert_eq!(h.svc.verify("nobody", Some(&right)).unwrap_err(), refuse("not_enrolled", 409));
    h.svc.enroll_confirm("user_1", Some(&right)).unwrap();
    // user_2 has its own random secret
    h.push(&[0x55u8; 20]);
    let s2 = h.svc.enroll_start("user_2", "b").unwrap();
    assert_ne!(s2.secret, KB32);
    h.svc.enroll_confirm("user_2", Some(&totp_at(&s2.secret, 1111111000, 6).unwrap())).unwrap();
    let t = 1111111200;
    h.at(t);
    let c1 = code_at(t);
    let c2 = totp_at(&s2.secret, t, 6).unwrap();
    assert_ne!(c1, c2);
    assert_eq!(h.svc.verify("user_2", Some(&c1)).unwrap_err(), refuse("invalid_code", 401));
    assert_eq!(h.svc.verify("user_1", Some(&c2)).unwrap_err(), refuse("invalid_code", 401));
    assert!(h.svc.verify("user_1", Some(&c1)).is_ok());
    assert!(h.svc.verify("user_2", Some(&c2)).is_ok());
}

/// What: TOTP-14, after 100 failures with no success a correct 6-digit code is 429 recovery_required with
/// no failure added, however far the clock moves; a recovery code clears it; a success before the 100th
/// failure starts the count again.
/// Why: TOTP-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// TOTP-14
#[test]
fn test_totp_14_hard_lock() {
    let h = harness(1111111000);
    let codes = h.enroll_k("user_1", 1111111000);
    let mut t = 1111200000;
    for _ in 0..20 {
        h.at(t);
        for _ in 0..5 {
            assert_eq!(h.svc.verify("user_1", Some(&wrong_at(t))).unwrap_err().error, "invalid_code");
        }
        t += 900;
    }
    assert_eq!(h.row("user_1").failed_since_success, 100);
    h.at(t);
    assert_eq!(h.svc.verify("user_1", Some(&code_at(t))).unwrap_err(), refuse("recovery_required", 429));
    assert!(h.svc.status("user_1").recovery_required);
    h.at(t + 10_000_000);
    assert_eq!(h.svc.verify("user_1", Some(&code_at(t + 10_000_000))).unwrap_err(), refuse("recovery_required", 429));
    assert_eq!(h.row("user_1").failed_since_success, 100);
    assert_eq!(h.svc.verify("user_1", Some(&codes[0])).unwrap().method, "recovery_code");
    assert_eq!(h.row("user_1").failed_since_success, 0);
    assert_eq!(h.svc.verify("user_1", Some(&code_at(t + 10_000_000))).unwrap().method, "totp");

    // 99 failures, a success, then one failure: the count starts again
    let h = harness(1111111000);
    h.enroll_k("user_1", 1111111000);
    let mut t = 1111200000;
    for i in 0..99 {
        if i % 5 == 0 && i > 0 {
            t += 900;
        }
        h.at(t);
        h.svc.verify("user_1", Some(&wrong_at(t))).unwrap_err();
    }
    assert_eq!(h.row("user_1").failed_since_success, 99);
    t += 900;
    h.at(t);
    assert!(h.svc.verify("user_1", Some(&code_at(t))).is_ok());
    h.svc.verify("user_1", Some(&wrong_at(t))).unwrap_err();
    assert_eq!(h.row("user_1").failed_since_success, 1);
    h.at(t + 30);
    assert!(h.svc.verify("user_1", Some(&code_at(t + 30))).is_ok());
}

//! BYOK key vault tests (docs/specs/byok_key_vault.md, VAULT-01..14), with an injected clock, an injected byte
//! queue (a xorshift stream after it runs out) and a fake provider client that records its calls: no network.
//! Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: memory only.
use super::*;
use std::collections::VecDeque;
use std::sync::atomic::AtomicI64;

const T0: i64 = 1699920000;

/// What: the spec's key, built from two pieces. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn key() -> String {
    ["acme_", "k3y0123456789abcdefghWXYZ"].concat()
}

/// What: master key k1 = 00..1f. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn k1() -> Vec<u8> {
    (0u8..32).collect()
}

/// What: master key k2 = 40..5f. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn k2() -> Vec<u8> {
    (0x40u8..0x60).collect()
}

/// What: the providers: acme (spec) and beta. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn providers() -> HashMap<String, ProviderConfig> {
    let mut p = HashMap::new();
    p.insert("acme".to_string(), ProviderConfig { prefix: "acme_".into(), min_length: 24, max_length: 200 });
    p.insert("beta".to_string(), ProviderConfig { prefix: "beta_".into(), min_length: 24, max_length: 200 });
    p
}

/// What: the test harness. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
struct H {
    store: Arc<InMemoryStore>,
    now: Arc<AtomicI64>,
    queue: Arc<Mutex<VecDeque<u8>>>,
    calls: Arc<Mutex<Vec<(String, String)>>>,
    answer: Arc<Mutex<Result<String, String>>>,
    vault: KeyVault,
}

/// What: a harness with the given keyring over a store (new when None). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory.
fn harness_with(keys: Vec<(&str, Vec<u8>)>, active: &str, store: Option<Arc<InMemoryStore>>, real_random: bool) -> H {
    let store = store.unwrap_or_default();
    let now = Arc::new(AtomicI64::new(T0));
    let queue: Arc<Mutex<VecDeque<u8>>> = Arc::new(Mutex::new(VecDeque::new()));
    let calls: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let answer: Arc<Mutex<Result<String, String>>> = Arc::new(Mutex::new(Ok("ok".to_string())));
    let (c, q, cl, an) = (now.clone(), queue.clone(), calls.clone(), answer.clone());
    let state = Arc::new(Mutex::new(0x2545_F491_4F6C_DD1Du64));
    let rb: RandomBytes = Arc::new(move |n| {
        let mut q = q.lock().unwrap();
        let mut s = state.lock().unwrap();
        (0..n)
            .map(|_| {
                q.pop_front().unwrap_or_else(|| {
                    *s ^= *s << 13;
                    *s ^= *s >> 7;
                    *s ^= *s << 17;
                    (*s >> 24) as u8
                })
            })
            .collect()
    });
    let vault = KeyVault::new(
        keys.into_iter().map(|(id, k)| (id.to_string(), k)).collect(),
        active,
        providers(),
        Arc::new(move |p: &str, k: &str| {
            cl.lock().unwrap().push((p.to_string(), k.to_string()));
            an.lock().unwrap().clone()
        }),
        store.clone(),
        Arc::new(move || c.load(Ordering::SeqCst)),
        if real_random { None } else { Some(rb) },
    )
    .unwrap();
    H { store, now, queue, calls, answer, vault }
}

/// What: a harness with k1 active. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
fn harness() -> H {
    harness_with(vec![("k1", k1())], "k1", None, false)
}

/// What: harness helpers. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
impl H {
    /// What: queue the spec's random bytes for one save. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn push_spec_bytes(&self) {
        let mut q = self.queue.lock().unwrap();
        q.extend(0x20u8..0x40);
        q.extend(0x60u8..0x6c);
        q.extend(0x70u8..0x7c);
    }
    /// What: a copy of the tables. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn tables(&self) -> Tables {
        self.store.tables.lock().unwrap().clone()
    }
    /// What: the row for (user, provider). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn row(&self, user: &str, provider: &str) -> KeyRow {
        self.store.get(user, provider).unwrap()
    }
}

/// What: decode a stored base64 value. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn raw(s: &str) -> Vec<u8> {
    B64.decode(s).unwrap()
}

/// What: VAULT-01, the happy path: one provider call with the key, the row holds no key, the answer, audit.
/// Why: VAULT-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// VAULT-01
#[test]
fn test_vault_01_save_key() {
    let h = harness();
    let saved = h.vault.save_key("user_1", "acme", &key()).unwrap();
    assert_eq!(saved, Saved { provider: "acme".into(), hint: "WXYZ".into(), key_id: "k1".into(), created_at: T0 });
    assert_eq!(*h.calls.lock().unwrap(), vec![("acme".to_string(), key())]);
    let row = h.row("user_1", "acme");
    assert_eq!((row.key_id.as_str(), row.hint.as_str(), row.last_used_at), ("k1", "WXYZ", None));
    assert!(!row.wrapped_dek.is_empty() && !row.ciphertext.is_empty());
    assert!(!format!("{:?}", h.tables()).contains(&key()));
    let audit = h.vault.list_audit("user_1");
    assert_eq!(audit, vec![AuditEntry { at: T0, action: "key_saved".into(), provider: "acme".into(), purpose: None, key_id: "k1".into() }]);
}

/// What: VAULT-02, the known answer: the spec's ciphertext and wrapped_dek; use_key returns the key.
/// Why: VAULT-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// VAULT-02
#[test]
fn test_vault_02_known_answer() {
    let h = harness();
    h.push_spec_bytes();
    h.vault.save_key("user_1", "acme", &key()).unwrap();
    let row = h.row("user_1", "acme");
    assert_eq!(row.ciphertext, "YGFiY2RlZmdoaWprg/fAzqy7SCzJdVWPIX9FTko++mAiaT2vbM/uMNaLHZjhWoVBGl1vBtJurMStRQ==");
    assert_eq!(row.wrapped_dek, "cHFyc3R1dnd4eXp7N6aYBJfsuhNsAxz5/W2f+J0G974wrnqNnbcDf3iKKAEOSVqlT/aJkU58qxAv2nPf");
    assert_eq!(h.vault.use_key("user_1", "acme", "chat").unwrap(), key());
}

/// What: VAULT-03, unknown provider and malformed keys are refused before any provider call or write;
/// only space, tab, CR and LF are trimmed.
/// Why: VAULT-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// VAULT-03
#[test]
fn test_vault_03_key_format() {
    let h = harness();
    assert_eq!(h.vault.save_key("user_1", "nope", &key()).unwrap_err(), refuse("unknown_provider", 404));
    let k = key();
    let bad = vec![
        ["beta_", &k[5..]].concat(),
        "acme_short1234567".to_string(),
        ["acme_", &"x".repeat(196)].concat(),
        ["acme_k3y0123 456789abcdefghWXYZ"].concat(),
        ["acme_k3y0123\n456789abcdefghWXYZ"].concat(),
        [k.as_str(), "\u{00a0}"].concat(),
        [k.as_str(), "\u{000b}"].concat(),
        [k.as_str(), "\u{0000}"].concat(),
    ];
    for b in &bad {
        assert_eq!(h.vault.save_key("user_1", "acme", b).unwrap_err(), refuse("invalid_key_format", 400), "{:?}", b);
    }
    assert!(h.calls.lock().unwrap().is_empty());
    let t = h.tables();
    assert!(t.keys.is_empty() && t.audit.is_empty() && t.windows.is_empty());
    // leading and trailing space, tab, CR, LF are trimmed
    let saved = h.vault.save_key("user_1", "acme", &[" \t", k.as_str(), "\r\n"].concat()).unwrap();
    assert_eq!(saved.hint, "WXYZ");
    assert_eq!(h.calls.lock().unwrap()[0].1, k);
}

/// What: VAULT-04, provider answers: rejected 400; unreachable, another value or an error 502; nothing
/// written, but the check is counted.
/// Why: VAULT-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// VAULT-04
#[test]
fn test_vault_04_provider_answers() {
    let h = harness();
    let cases: Vec<(Result<String, String>, Refusal)> = vec![
        (Ok("rejected".into()), refuse("key_rejected", 400)),
        (Ok("unreachable".into()), refuse("provider_unreachable", 502)),
        (Ok("maybe".into()), refuse("provider_unreachable", 502)),
        (Err("timeout".into()), refuse("provider_unreachable", 502)),
    ];
    for (i, (answer, want)) in cases.into_iter().enumerate() {
        *h.answer.lock().unwrap() = answer;
        assert_eq!(h.vault.save_key("user_1", "acme", &key()).unwrap_err(), want);
        let t = h.tables();
        assert!(t.keys.is_empty() && t.audit.is_empty());
        assert_eq!(t.windows.get(&("user_1".to_string(), T0)), Some(&(i as i64 + 1)));
    }
}

/// What: VAULT-05, list_keys fields and order, with no key material in its serialized form.
/// Why: VAULT-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// VAULT-05
#[test]
fn test_vault_05_list_keys() {
    let h = harness();
    let kb = ["beta_", "z9y8x7w6v5u4t3s2r1q0ABCD"].concat();
    h.vault.save_key("user_1", "beta", &kb).unwrap();
    h.now.store(T0 + 5, Ordering::SeqCst);
    h.vault.save_key("user_1", "acme", &key()).unwrap();
    h.vault.use_key("user_1", "acme", "chat").unwrap();
    let list = h.vault.list_keys("user_1");
    assert_eq!(
        list,
        vec![
            KeyInfo { provider: "acme".into(), hint: "WXYZ".into(), key_id: "k1".into(), created_at: T0 + 5, last_used_at: Some(T0 + 5) },
            KeyInfo { provider: "beta".into(), hint: "ABCD".into(), key_id: "k1".into(), created_at: T0, last_used_at: None },
        ]
    );
    let json = serde_json::Value::Array(list.iter().map(|k| k.to_json()).collect()).to_string();
    for secret in [key(), kb, h.row("user_1", "acme").ciphertext, h.row("user_1", "acme").wrapped_dek] {
        assert!(!json.contains(&secret));
    }
    assert!(!json.contains("ciphertext") && !json.contains("wrapped_dek"));
}

/// What: VAULT-06, use_key returns the key, sets last_used_at, writes key_used with the purpose; bad purposes
/// are 400; a failed audit write is 500 storage_failed with no key; no refusal or audit row holds the key.
/// Why: VAULT-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// VAULT-06
#[test]
fn test_vault_06_use_key() {
    let h = harness();
    h.vault.save_key("user_1", "acme", &key()).unwrap();
    h.now.store(T0 + 77, Ordering::SeqCst);
    assert_eq!(h.vault.use_key("user_1", "acme", "chat.completion:v1-a_b").unwrap(), key());
    assert_eq!(h.row("user_1", "acme").last_used_at, Some(T0 + 77));
    let audit = h.vault.list_audit("user_1");
    assert_eq!(audit[1], AuditEntry { at: T0 + 77, action: "key_used".into(), provider: "acme".into(), purpose: Some("chat.completion:v1-a_b".into()), key_id: "k1".into() });
    for bad in ["", "two words", "slash/no", &"a".repeat(101)] {
        assert_eq!(h.vault.use_key("user_1", "acme", bad).unwrap_err(), refuse("invalid_purpose", 400));
    }
    h.store.fail_audit.store(true, Ordering::SeqCst);
    h.now.store(T0 + 99, Ordering::SeqCst);
    let r = h.vault.use_key("user_1", "acme", "chat").unwrap_err();
    assert_eq!(r, refuse("storage_failed", 500));
    assert!(!format!("{:?}", r).contains(&key()));
    assert_eq!(h.row("user_1", "acme").last_used_at, Some(T0 + 77));
    assert_eq!(h.vault.list_audit("user_1").len(), 2);
    assert!(!format!("{:?}", h.tables().audit).contains(&key()));
}

/// What: VAULT-07, isolation between users. Why: VAULT-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory.
// VAULT-07
#[test]
fn test_vault_07_isolation() {
    let h = harness();
    h.vault.save_key("user_a", "acme", &key()).unwrap();
    assert!(h.vault.list_keys("user_b").is_empty());
    assert_eq!(h.vault.use_key("user_b", "acme", "chat").unwrap_err(), refuse("key_not_found", 404));
    assert_eq!(h.vault.delete_key("user_b", "acme"), Ok(false));
    assert_eq!(h.vault.use_key("user_a", "acme", "chat").unwrap(), key());
    assert_eq!(h.vault.list_keys("user_a").len(), 1);
}

/// What: VAULT-08, moved rows, changed bytes and malformed stored values are 500 key_unreadable, never a panic.
/// Why: VAULT-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// VAULT-08
#[test]
fn test_vault_08_tampered_rows() {
    let h = harness();
    h.vault.save_key("user_1", "acme", &key()).unwrap();
    let orig = h.row("user_1", "acme");
    let unreadable = refuse("key_unreadable", 500);
    let flip = |s: &str| {
        let mut b = raw(s);
        b[20] ^= 0x01;
        B64.encode(b)
    };
    let put = |r: KeyRow| {
        h.store.tables.lock().unwrap().keys.insert((r.user_id.clone(), r.provider.clone()), r);
    };
    // moved to another user, and to another provider
    put(KeyRow { user_id: "user_2".into(), ..orig.clone() });
    assert_eq!(h.vault.use_key("user_2", "acme", "chat").unwrap_err(), unreadable);
    put(KeyRow { provider: "beta".into(), ..orig.clone() });
    assert_eq!(h.vault.use_key("user_1", "beta", "chat").unwrap_err(), unreadable);
    // damaged values
    for damaged in [
        KeyRow { ciphertext: flip(&orig.ciphertext), ..orig.clone() },
        KeyRow { wrapped_dek: flip(&orig.wrapped_dek), ..orig.clone() },
        KeyRow { ciphertext: "!!not base64!!".into(), ..orig.clone() },
        KeyRow { wrapped_dek: "AAAA".into(), ..orig.clone() },
        KeyRow { ciphertext: B64.encode([0u8; 27]), ..orig.clone() },
    ] {
        put(damaged);
        assert_eq!(h.vault.use_key("user_1", "acme", "chat").unwrap_err(), unreadable);
    }
    put(orig);
    assert_eq!(h.vault.use_key("user_1", "acme", "chat").unwrap(), key());
}

/// What: VAULT-09, saving again replaces the key with a new DEK, new nonces and the new hint.
/// Why: VAULT-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// VAULT-09
#[test]
fn test_vault_09_replace() {
    let h = harness();
    h.vault.save_key("user_1", "acme", &key()).unwrap();
    let first = h.row("user_1", "acme");
    let k2 = ["acme_", "n3w0123456789abcdefghLMNO"].concat();
    let saved = h.vault.save_key("user_1", "acme", &k2).unwrap();
    assert_eq!(saved.hint, "LMNO");
    let second = h.row("user_1", "acme");
    assert_eq!(h.tables().keys.len(), 1);
    assert_ne!(raw(&first.ciphertext)[..12], raw(&second.ciphertext)[..12]);
    assert_ne!(raw(&first.wrapped_dek)[..12], raw(&second.wrapped_dek)[..12]);
    assert_ne!(first.wrapped_dek, second.wrapped_dek);
    assert_eq!(h.vault.use_key("user_1", "acme", "chat").unwrap(), k2);
}

/// What: VAULT-10, rotation: new saves under k2, rewrap() moves old rows (spec string), k1 can then leave;
/// the store's rewrap write refuses a row whose wrapped_dek changed.
/// Why: VAULT-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// VAULT-10
#[test]
fn test_vault_10_rotation() {
    let h1 = harness();
    h1.push_spec_bytes();
    h1.vault.save_key("user_1", "acme", &key()).unwrap();
    let before = h1.row("user_1", "acme");
    let h2 = harness_with(vec![("k1", k1()), ("k2", k2())], "k2", Some(h1.store.clone()), false);
    let kb = ["beta_", "z9y8x7w6v5u4t3s2r1q0ABCD"].concat();
    assert_eq!(h2.vault.save_key("user_1", "beta", &kb).unwrap().key_id, "k2");
    h2.queue.lock().unwrap().extend(0x80u8..0x8c);
    assert_eq!(h2.vault.rewrap(), RewrapResult { rewrapped: 1, failed: 0 });
    let after = h2.row("user_1", "acme");
    assert_eq!(after.key_id, "k2");
    assert_eq!(after.ciphertext, before.ciphertext);
    assert_eq!(after.wrapped_dek, "gIGCg4SFhoeIiYqLDX+c5AZRDKRAQ7oDXo+7DcjN++F5UtAjxrdC7+0oX0MOT3cH13mFkfvVnrrN/V6R");
    assert_eq!(h2.vault.list_audit("user_1").last().unwrap().action, "key_rewrapped");
    let h3 = harness_with(vec![("k2", k2())], "k2", Some(h1.store.clone()), false);
    assert_eq!(h3.vault.use_key("user_1", "acme", "chat").unwrap(), key());
    assert_eq!(h3.vault.use_key("user_1", "beta", "chat").unwrap(), kb);
    // the conditional write
    let audit = AuditRow { id: 0, user_id: "user_1".into(), provider: "acme".into(), action: "key_rewrapped".into(), purpose: None, key_id: "k2".into(), at: T0 };
    assert_eq!(h1.store.rewrap("user_1", "acme", "k2", "new", &before.wrapped_dek, audit.clone()), Ok(false));
    assert_eq!(h1.row("user_1", "acme").wrapped_dek, after.wrapped_dek);
    assert_eq!(h1.store.rewrap("user_1", "acme", "k2", &after.wrapped_dek, &after.wrapped_dek, audit), Ok(true));
}

/// What: VAULT-11, an unknown master key id is 503; bad keyrings and provider configs fail construction.
/// Why: VAULT-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// VAULT-11
#[test]
fn test_vault_11_configuration() {
    let h = harness();
    h.vault.save_key("user_1", "acme", &key()).unwrap();
    h.store.tables.lock().unwrap().keys.values_mut().for_each(|r| r.key_id = "k9".into());
    assert_eq!(h.vault.use_key("user_1", "acme", "chat").unwrap_err(), refuse("key_unavailable", 503));
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::default());
    let clock: Clock = Arc::new(|| T0);
    let client: ProviderClient = Arc::new(|_: &str, _: &str| Ok("ok".to_string()));
    let mk = |pairs: Vec<(&str, Vec<u8>)>| pairs.into_iter().map(|(a, b)| (a.to_string(), b)).collect::<HashMap<_, _>>();
    let build = |keys: HashMap<String, Vec<u8>>, active: &str, provs: HashMap<String, ProviderConfig>| {
        KeyVault::new(keys, active, provs, client.clone(), store.clone(), clock.clone(), None).err()
    };
    assert_eq!(build(mk(vec![("k1", vec![0u8; 31])]), "k1", providers()), Some("invalid_master_key".into()));
    assert_eq!(build(mk(vec![("k1", k1())]), "k2", providers()), Some("invalid_master_key".into()));
    assert_eq!(build(mk(vec![("bad id", k1())]), "bad id", providers()), Some("invalid_master_key".into()));
    let mut p = HashMap::new();
    p.insert("acme".to_string(), ProviderConfig { prefix: "acme_".into(), min_length: 20, max_length: 200 });
    assert_eq!(build(mk(vec![("k1", k1())]), "k1", p), Some("invalid_provider_config".into()));
    assert_eq!(build(mk(vec![("k1", k1())]), "k1", providers()), None);
}

/// What: VAULT-12, 10 provider checks per user per clock hour; the 11th is 429 with retry_after and no call;
/// other users and the next hour are not affected; a malformed key does not count; the window write.
/// Why: VAULT-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// VAULT-12
#[test]
fn test_vault_12_hourly_limit() {
    let h = harness();
    assert_eq!(h.vault.save_key("user_1", "acme", "acme_bad").unwrap_err().error, "invalid_key_format");
    for _ in 0..10 {
        h.vault.save_key("user_1", "acme", &key()).unwrap();
    }
    h.now.store(T0 + 600, Ordering::SeqCst);
    let r = h.vault.save_key("user_1", "acme", &key()).unwrap_err();
    assert_eq!(r, Refusal { error: "rate_limited".into(), status: 429, retry_after: Some(3000) });
    assert_eq!(h.calls.lock().unwrap().len(), 10);
    assert!(h.vault.save_key("user_2", "acme", &key()).is_ok());
    h.now.store(T0 + 3600, Ordering::SeqCst);
    assert!(h.vault.save_key("user_1", "acme", &key()).is_ok());
    let s = InMemoryStore::default();
    for _ in 0..10 {
        assert!(s.count_check("u", T0));
    }
    assert!(!s.count_check("u", T0));
    assert!(s.count_check("u", T0 + 3600));
}

/// What: VAULT-13, delete_key removes the row and writes key_deleted; a second delete is false with no audit.
/// Why: VAULT-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// VAULT-13
#[test]
fn test_vault_13_delete() {
    let h = harness();
    h.vault.save_key("user_1", "acme", &key()).unwrap();
    assert_eq!(h.vault.delete_key("user_1", "acme"), Ok(true));
    assert!(h.tables().keys.is_empty());
    assert_eq!(h.vault.list_audit("user_1").last().unwrap().action, "key_deleted");
    assert_eq!(h.vault.delete_key("user_1", "acme"), Ok(false));
    assert_eq!(h.vault.list_audit("user_1").len(), 2);
    assert_eq!(h.vault.use_key("user_1", "acme", "chat").unwrap_err(), refuse("key_not_found", 404));
}

/// What: VAULT-14, with real randomness the same key for two users gives different ciphertext, wrapped DEK
/// and nonces. Why: VAULT-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory, the OS random source.
// VAULT-14
#[test]
fn test_vault_14_real_randomness() {
    let h = harness_with(vec![("k1", k1())], "k1", None, true);
    h.vault.save_key("user_1", "acme", &key()).unwrap();
    h.vault.save_key("user_2", "acme", &key()).unwrap();
    let (a, b) = (h.row("user_1", "acme"), h.row("user_2", "acme"));
    assert_ne!(a.ciphertext, b.ciphertext);
    assert_ne!(a.wrapped_dek, b.wrapped_dek);
    assert_ne!(raw(&a.ciphertext)[..12], raw(&b.ciphertext)[..12]);
    assert_ne!(raw(&a.wrapped_dek)[..12], raw(&b.wrapped_dek)[..12]);
    assert_eq!(h.vault.use_key("user_2", "acme", "chat").unwrap(), key());
}

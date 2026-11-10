//! BYOK key vault: users' own provider API keys, envelope-encrypted at rest (AES-256-GCM).
//!
//! What: save_key checks the key's shape, counts the provider check in an hourly window (10 per user), asks
//! the injected provider client, then stores the key under a fresh data key (DEK) that is itself wrapped by
//! the active master key; both AAD texts bind the row to its user, provider and master key id. use_key opens
//! it for its owner only and records every use in the same transaction; rewrap() moves rows to a new master
//! key with a conditional write. Every refusal is a returned `Refusal`, never a panic.
//! Why: Phase D wave 1, owner request 2026-11-10 (docs/specs/byok_key_vault.md, VAULT-01..14).
//! 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: the injected store (memory in `InMemoryStore`), the injected provider client (the network in a
//! real deployment; a fake in tests), clock and random source. No files, no money. The plain key appears
//! only in save_key's input and use_key's result: never in a refusal, an audit row or a log.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub const SAVES_PER_HOUR: i64 = 10;

/// The injected clock: whole seconds since the Unix epoch.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;
/// The injected random source: n bytes.
pub type RandomBytes = Arc<dyn Fn(usize) -> Vec<u8> + Send + Sync>;
/// The injected provider client: check(provider, key) -> "ok" | "rejected" | "unreachable", or Err (raised).
pub type ProviderClient = Arc<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>;

/// What: a refusal {error, status} plus retry_after for 429. Never holds a key.
/// Why: spec CONVENTIONS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub error: String,
    pub status: u16,
    pub retry_after: Option<i64>,
}

/// What: build a refusal without retry_after. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn refuse(error: &str, status: u16) -> Refusal {
    Refusal { error: error.to_string(), status, retry_after: None }
}

/// What: a provider's key shape {prefix, min_length, max_length}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConfig {
    pub prefix: String,
    pub min_length: usize,
    pub max_length: usize,
}

/// What: a row of provider_keys. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRow {
    pub user_id: String,
    pub provider: String,
    pub key_id: String,
    pub wrapped_dek: String,
    pub ciphertext: String,
    pub hint: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

/// What: a row of provider_key_audit. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    pub id: u64,
    pub user_id: String,
    pub provider: String,
    pub action: String,
    pub purpose: Option<String>,
    pub key_id: String,
    pub at: i64,
}

/// What: save_key's answer {provider, hint, key_id, created_at}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Saved {
    pub provider: String,
    pub hint: String,
    pub key_id: String,
    pub created_at: i64,
}

/// What: one entry of list_keys. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    pub provider: String,
    pub hint: String,
    pub key_id: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

/// What: methods of `KeyInfo`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
impl KeyInfo {
    /// What: the entry as JSON with the spec's field names. Out: a serde_json value.
    /// Why: VAULT-05 (the serialized list holds no key material). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: nothing.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({"provider": self.provider, "hint": self.hint, "key_id": self.key_id,
                           "created_at": self.created_at, "last_used_at": self.last_used_at})
    }
}

/// What: one entry of list_audit {at, action, provider, purpose, key_id}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub at: i64,
    pub action: String,
    pub provider: String,
    pub purpose: Option<String>,
    pub key_id: String,
}

/// What: rewrap()'s answer {rewrapped, failed}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RewrapResult {
    pub rewrapped: u64,
    pub failed: u64,
}

/// What: the store. Each method that the spec calls one transaction or one conditional write is one call,
/// and returns Err when the storage fails (then nothing of it is written).
/// Why: spec SCHEMA and ENDPOINTS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: whatever the implementation uses.
pub trait Store: Send + Sync {
    /// What: the window write: insert (user, w, 1) or add 1 while count < 10; true when a row changed.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn count_check(&self, user_id: &str, window_start: i64) -> bool;
    /// What: replace the user's row for the provider and add the audit row, in one transaction.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn save(&self, row: KeyRow, audit: AuditRow) -> Result<(), String>;
    /// What: the row for (user, provider). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn get(&self, user_id: &str, provider: &str) -> Option<KeyRow>;
    /// What: the user's rows. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn list(&self, user_id: &str) -> Vec<KeyRow>;
    /// What: set last_used_at and add the audit row, in one transaction. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn mark_used(&self, user_id: &str, provider: &str, now: i64, audit: AuditRow) -> Result<(), String>;
    /// What: delete the row and add the audit row in one transaction; false (and no audit) when there was none.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn delete(&self, user_id: &str, provider: &str, audit: AuditRow) -> Result<bool, String>;
    /// What: every row, in (user_id, provider) order. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn all_rows(&self) -> Vec<KeyRow>;
    /// What: UPDATE key_id, wrapped_dek WHERE user, provider AND wrapped_dek = :read, plus the audit row when a
    /// row changed; true when one row changed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn rewrap(&self, user_id: &str, provider: &str, key_id: &str, new_wrapped: &str, wrapped_read: &str, audit: AuditRow) -> Result<bool, String>;
    /// What: the user's audit rows, oldest first. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn audit(&self, user_id: &str) -> Vec<AuditRow>;
}

/// What: the in-memory tables (public so tests can move or damage rows). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Default, Clone)]
pub struct Tables {
    pub keys: BTreeMap<(String, String), KeyRow>,
    pub audit: Vec<AuditRow>,
    pub windows: HashMap<(String, i64), i64>,
    pub next_id: u64,
}

/// What: an in-memory store; one mutex makes every call atomic. `fail_audit` makes every audit write fail
/// (so the whole transaction fails), for VAULT-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
#[derive(Default)]
pub struct InMemoryStore {
    pub tables: Mutex<Tables>,
    pub fail_audit: AtomicBool,
}

/// What: helpers of `InMemoryStore`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
impl InMemoryStore {
    /// What: append an audit row with the next id, or fail when `fail_audit` is set.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn add_audit(&self, t: &mut Tables, mut a: AuditRow) -> Result<(), String> {
        if self.fail_audit.load(Ordering::SeqCst) {
            return Err("audit write failed".into());
        }
        t.next_id += 1;
        a.id = t.next_id;
        t.audit.push(a);
        Ok(())
    }
}

/// What: `Store` for `InMemoryStore`; each method is documented on the trait. Transactions check the audit
/// write before changing anything, so a failure leaves the tables as they were.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
impl Store for InMemoryStore {
    fn count_check(&self, user_id: &str, window_start: i64) -> bool {
        let mut t = self.tables.lock().unwrap();
        let c = t.windows.entry((user_id.to_string(), window_start)).or_insert(0);
        if *c >= SAVES_PER_HOUR {
            return false;
        }
        *c += 1;
        true
    }
    fn save(&self, row: KeyRow, audit: AuditRow) -> Result<(), String> {
        let mut t = self.tables.lock().unwrap();
        self.add_audit(&mut t, audit)?;
        t.keys.insert((row.user_id.clone(), row.provider.clone()), row);
        Ok(())
    }
    fn get(&self, user_id: &str, provider: &str) -> Option<KeyRow> {
        self.tables.lock().unwrap().keys.get(&(user_id.to_string(), provider.to_string())).cloned()
    }
    fn list(&self, user_id: &str) -> Vec<KeyRow> {
        self.tables.lock().unwrap().keys.values().filter(|r| r.user_id == user_id).cloned().collect()
    }
    fn mark_used(&self, user_id: &str, provider: &str, now: i64, audit: AuditRow) -> Result<(), String> {
        let mut t = self.tables.lock().unwrap();
        if !t.keys.contains_key(&(user_id.to_string(), provider.to_string())) {
            return Err("row gone".into());
        }
        self.add_audit(&mut t, audit)?;
        t.keys.get_mut(&(user_id.to_string(), provider.to_string())).expect("checked").last_used_at = Some(now);
        Ok(())
    }
    fn delete(&self, user_id: &str, provider: &str, audit: AuditRow) -> Result<bool, String> {
        let mut t = self.tables.lock().unwrap();
        if !t.keys.contains_key(&(user_id.to_string(), provider.to_string())) {
            return Ok(false);
        }
        self.add_audit(&mut t, audit)?;
        t.keys.remove(&(user_id.to_string(), provider.to_string()));
        Ok(true)
    }
    fn all_rows(&self) -> Vec<KeyRow> {
        self.tables.lock().unwrap().keys.values().cloned().collect()
    }
    fn rewrap(&self, user_id: &str, provider: &str, key_id: &str, new_wrapped: &str, wrapped_read: &str, audit: AuditRow) -> Result<bool, String> {
        let mut t = self.tables.lock().unwrap();
        let k = (user_id.to_string(), provider.to_string());
        match t.keys.get(&k) {
            Some(r) if r.wrapped_dek == wrapped_read => {}
            _ => return Ok(false),
        }
        self.add_audit(&mut t, audit)?;
        let r = t.keys.get_mut(&k).expect("checked");
        r.key_id = key_id.to_string();
        r.wrapped_dek = new_wrapped.to_string();
        Ok(true)
    }
    fn audit(&self, user_id: &str) -> Vec<AuditRow> {
        self.tables.lock().unwrap().audit.iter().filter(|a| a.user_id == user_id).cloned().collect()
    }
}

/// What: AES-256-GCM encrypt; the result is nonce + ciphertext + tag. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: nothing.
fn gcm_seal(key: &[u8], nonce: &[u8], plain: &[u8], aad: &str) -> Vec<u8> {
    let c = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let mut out = nonce.to_vec();
    out.extend(c.encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad: aad.as_bytes() }).expect("encrypt"));
    out
}

/// What: decode base64 and AES-256-GCM decrypt nonce + ciphertext + tag; None for bad base64, fewer than 28
/// bytes, a key that is not 32 bytes or a tag that fails. Never panics. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: nothing.
fn gcm_open(key: &[u8], stored: &str, aad: &str) -> Option<Vec<u8>> {
    let raw = B64.decode(stored).ok()?;
    if raw.len() < 28 {
        return None;
    }
    let c = Aes256Gcm::new_from_slice(key).ok()?;
    c.decrypt(Nonce::from_slice(&raw[..12]), Payload { msg: &raw[12..], aad: aad.as_bytes() }).ok()
}

/// What: true for text of 1..=max characters, each matching the predicate. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: nothing.
fn shaped(s: &str, max: usize, ok: impl Fn(char) -> bool) -> bool {
    let n = s.chars().count();
    n >= 1 && n <= max && s.chars().all(ok)
}

/// What: the system CSPRNG as a RandomBytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the OS random source.
pub fn system_random() -> RandomBytes {
    Arc::new(|n| {
        use rand::RngCore;
        let mut v = vec![0u8; n];
        rand::rngs::OsRng.fill_bytes(&mut v);
        v
    })
}

/// What: the vault: keyring, providers, client, store, clock and random source. Why: spec CONFIGURATION.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the provider client.
pub struct KeyVault {
    master_keys: HashMap<String, Vec<u8>>,
    active_key_id: String,
    providers: HashMap<String, ProviderConfig>,
    client: ProviderClient,
    store: Arc<dyn Store>,
    clock: Clock,
    random_bytes: RandomBytes,
}

/// What: the flows of the spec. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the provider client.
impl KeyVault {
    /// What: construct, checking the configuration. In: master keys, active key id, providers, client, store,
    /// clock, random source (None = system CSPRNG). Out: the vault, or Err("invalid_master_key") /
    /// Err("invalid_provider_config") (fail closed).
    /// Why: spec CONFIGURATION, VAULT-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn new(
        master_keys: HashMap<String, Vec<u8>>,
        active_key_id: &str,
        providers: HashMap<String, ProviderConfig>,
        client: ProviderClient,
        store: Arc<dyn Store>,
        clock: Clock,
        random_bytes: Option<RandomBytes>,
    ) -> Result<Self, String> {
        let id_ok = |id: &str| shaped(id, 32, |c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if master_keys.iter().any(|(id, k)| !id_ok(id) || k.len() != 32) || !master_keys.contains_key(active_key_id) {
            return Err("invalid_master_key".to_string());
        }
        for (id, p) in &providers {
            let pid_ok = shaped(id, 32, |c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
            if !pid_ok || p.min_length < 20 || p.min_length > p.max_length || p.max_length > 4096 || p.min_length < p.prefix.chars().count() + 16 {
                return Err("invalid_provider_config".to_string());
            }
        }
        Ok(KeyVault {
            master_keys,
            active_key_id: active_key_id.to_string(),
            providers,
            client,
            store,
            clock,
            random_bytes: random_bytes.unwrap_or_else(system_random),
        })
    }

    /// What: an audit row (id set by the store). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn audit_row(user_id: &str, provider: &str, action: &str, purpose: Option<&str>, key_id: &str, at: i64) -> AuditRow {
        AuditRow { id: 0, user_id: user_id.into(), provider: provider.into(), action: action.into(), purpose: purpose.map(|p| p.to_string()), key_id: key_id.into(), at }
    }

    /// What: save_key(user_id, provider, key): steps 1-6 of the spec. Out: {provider, hint, key_id, created_at}.
    /// Why: spec save_key, VAULT-01..04, VAULT-09, VAULT-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: the store, the provider client (network in production), the random source.
    pub fn save_key(&self, user_id: &str, provider: &str, key: &str) -> Result<Saved, Refusal> {
        let cfg = self.providers.get(provider).ok_or_else(|| refuse("unknown_provider", 404))?;
        let k = key.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'));
        let n = k.chars().count();
        if !k.starts_with(&cfg.prefix) || n < cfg.min_length || n > cfg.max_length || !k.chars().all(|c| ('\u{21}'..='\u{7e}').contains(&c)) {
            return Err(refuse("invalid_key_format", 400));
        }
        let now = (self.clock)();
        let w = now - now.rem_euclid(3600);
        if !self.store.count_check(user_id, w) {
            return Err(Refusal { error: "rate_limited".into(), status: 429, retry_after: Some(w + 3600 - now) });
        }
        match (self.client)(provider, k) {
            Ok(v) if v == "ok" => {}
            Ok(v) if v == "rejected" => return Err(refuse("key_rejected", 400)),
            _ => return Err(refuse("provider_unreachable", 502)),
        }
        let dek = (self.random_bytes)(32);
        let data_nonce = (self.random_bytes)(12);
        let wrap_nonce = (self.random_bytes)(12);
        let kid = self.active_key_id.clone();
        let ciphertext = B64.encode(gcm_seal(&dek, &data_nonce, k.as_bytes(), &format!("byok:data:{}:{}", provider, user_id)));
        let wrapped = B64.encode(gcm_seal(&self.master_keys[&kid], &wrap_nonce, &dek, &format!("byok:dek:{}:{}:{}", kid, provider, user_id)));
        let chars: Vec<char> = k.chars().collect();
        let hint: String = chars[chars.len() - 4..].iter().collect();
        let row = KeyRow {
            user_id: user_id.into(),
            provider: provider.into(),
            key_id: kid.clone(),
            wrapped_dek: wrapped,
            ciphertext,
            hint: hint.clone(),
            created_at: now,
            last_used_at: None,
        };
        self.store
            .save(row, Self::audit_row(user_id, provider, "key_saved", None, &kid, now))
            .map_err(|_| refuse("storage_failed", 500))?;
        Ok(Saved { provider: provider.into(), hint, key_id: kid, created_at: now })
    }

    /// What: list_keys(user_id): provider, hint, key_id, created_at, last_used_at, sorted by provider (bytes).
    /// Why: spec list_keys, VAULT-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store (read).
    pub fn list_keys(&self, user_id: &str) -> Vec<KeyInfo> {
        let mut v: Vec<KeyInfo> = self
            .store
            .list(user_id)
            .into_iter()
            .map(|r| KeyInfo { provider: r.provider, hint: r.hint, key_id: r.key_id, created_at: r.created_at, last_used_at: r.last_used_at })
            .collect();
        v.sort_by(|a, b| a.provider.as_bytes().cmp(b.provider.as_bytes()));
        v
    }

    /// What: open a row: unwrap the DEK with the row's master key, then decrypt the key. Out: the key, or the
    /// refusal (503 key_unavailable, 500 key_unreadable). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn open_row(&self, row: &KeyRow) -> Result<String, Refusal> {
        let mk = self.master_keys.get(&row.key_id).ok_or_else(|| refuse("key_unavailable", 503))?;
        let unreadable = || refuse("key_unreadable", 500);
        let dek = gcm_open(mk, &row.wrapped_dek, &format!("byok:dek:{}:{}:{}", row.key_id, row.provider, row.user_id)).ok_or_else(unreadable)?;
        if dek.len() != 32 {
            return Err(unreadable());
        }
        let plain = gcm_open(&dek, &row.ciphertext, &format!("byok:data:{}:{}", row.provider, row.user_id)).ok_or_else(unreadable)?;
        String::from_utf8(plain).map_err(|_| unreadable())
    }

    /// What: use_key(user_id, provider, purpose): the key for a server-side call, recorded with its purpose.
    /// Out: the key, or the refusal of steps 1-5. Why: spec use_key, VAULT-06..08, VAULT-11.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
    pub fn use_key(&self, user_id: &str, provider: &str, purpose: &str) -> Result<String, Refusal> {
        if !shaped(purpose, 100, |c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-')) {
            return Err(refuse("invalid_purpose", 400));
        }
        let row = self.store.get(user_id, provider).ok_or_else(|| refuse("key_not_found", 404))?;
        let key = self.open_row(&row)?;
        let now = (self.clock)();
        self.store
            .mark_used(user_id, provider, now, Self::audit_row(user_id, provider, "key_used", Some(purpose), &row.key_id, now))
            .map_err(|_| refuse("storage_failed", 500))?;
        Ok(key)
    }

    /// What: delete_key(user_id, provider): true and a key_deleted audit row, or false when there was no row.
    /// Why: spec delete_key, VAULT-07, VAULT-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
    pub fn delete_key(&self, user_id: &str, provider: &str) -> Result<bool, Refusal> {
        let key_id = match self.store.get(user_id, provider) {
            Some(r) => r.key_id,
            None => return Ok(false),
        };
        let now = (self.clock)();
        self.store
            .delete(user_id, provider, Self::audit_row(user_id, provider, "key_deleted", None, &key_id, now))
            .map_err(|_| refuse("storage_failed", 500))
    }

    /// What: rewrap() (operator only): re-wrap every DEK not under the active master key; a row changed meanwhile
    /// is left and counted in neither number. Out: {rewrapped, failed}. Ciphertext is never touched.
    /// Why: spec rewrap, VAULT-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the random source.
    pub fn rewrap(&self) -> RewrapResult {
        let (mut done, mut failed) = (0u64, 0u64);
        let active = self.active_key_id.clone();
        for row in self.store.all_rows() {
            if row.key_id == active {
                continue;
            }
            let dek = self
                .master_keys
                .get(&row.key_id)
                .and_then(|mk| gcm_open(mk, &row.wrapped_dek, &format!("byok:dek:{}:{}:{}", row.key_id, row.provider, row.user_id)));
            let dek = match dek {
                Some(d) if d.len() == 32 => d,
                _ => {
                    failed += 1;
                    continue;
                }
            };
            let nonce = (self.random_bytes)(12);
            let new_wrapped = B64.encode(gcm_seal(&self.master_keys[&active], &nonce, &dek, &format!("byok:dek:{}:{}:{}", active, row.provider, row.user_id)));
            let now = (self.clock)();
            let audit = Self::audit_row(&row.user_id, &row.provider, "key_rewrapped", None, &active, now);
            match self.store.rewrap(&row.user_id, &row.provider, &active, &new_wrapped, &row.wrapped_dek, audit) {
                Ok(true) => done += 1,
                Ok(false) => {}
                Err(_) => failed += 1,
            }
        }
        RewrapResult { rewrapped: done, failed }
    }

    /// What: list_audit(user_id): {at, action, provider, purpose, key_id}, oldest first.
    /// Why: spec list_audit. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store (read).
    pub fn list_audit(&self, user_id: &str) -> Vec<AuditEntry> {
        self.store
            .audit(user_id)
            .into_iter()
            .map(|a| AuditEntry { at: a.at, action: a.action, provider: a.provider, purpose: a.purpose, key_id: a.key_id })
            .collect()
    }
}

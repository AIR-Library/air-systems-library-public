//! Passwordless email code sign-in: a 6-digit code by email signs in, and signs up, with no password.
//!
//! What: start() normalizes the address, counts sends per IP and per address (hour and day), stores only
//! HMACs of the address and the code, and calls the injected sender; verify() counts tries per IP and per
//! address, counts the code's own try BEFORE comparing (one conditional write), uses the code up with a
//! conditional delete, then finds or creates the account (revoking what an unproven row carried).
//! The same answer whether or not an address has an account. Every refusal is a returned `Refusal`.
//! Why: Phase D wave 1, owner request 2026-11-10 (docs/specs/passwordless_email_code_signin.md, EMAILCODE-01..14).
//! 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: the injected store (memory in `InMemoryStore`), the injected sender (email in production; a
//! fake in tests), the revoke hook, clock and random source. No files, no money. Never logs the code, the
//! address or the secret.

use hmac::{Hmac, Mac};
use regex::Regex;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

pub const CODE_TTL: i64 = 600;
pub const CODE_ATTEMPTS: i64 = 5;
pub const START_PER_EMAIL_HOUR: i64 = 5;
pub const START_PER_EMAIL_DAY: i64 = 10;
pub const START_PER_IP_HOUR: i64 = 20;
pub const VERIFY_PER_IP_HOUR: i64 = 30;
pub const VERIFY_PER_EMAIL_HOUR: i64 = 10;

/// The injected clock: whole seconds since the Unix epoch.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;
/// The injected random source: n bytes.
pub type RandomBytes = Arc<dyn Fn(usize) -> Vec<u8> + Send + Sync>;
/// The injected sender: send_code(to, code, expires_in_seconds) -> Ok(true | false), or Err (raised).
pub type Sender = Arc<dyn Fn(&str, &str, i64) -> Result<bool, String> + Send + Sync>;
/// revoke_unproven(account_id): Ok, or Err (raised).
pub type Revoke = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;
/// generate_code(): a 6-digit text.
pub type CodeGenerator = Arc<dyn Fn() -> String + Send + Sync>;

/// What: a refusal {error, status}. Why: spec CONVENTIONS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub error: String,
    pub status: u16,
}

/// What: build a refusal. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn refuse(error: &str, status: u16) -> Refusal {
    Refusal { error: error.to_string(), status }
}

/// What: start's answer {status: 202, sent: true, expires_in: 600}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Started {
    pub status: u16,
    pub sent: bool,
    pub expires_in: i64,
}

/// What: verify's answer {status: 200, account_id, email, new_account}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedIn {
    pub status: u16,
    pub account_id: String,
    pub email: String,
    pub new_account: bool,
}

/// What: a row of accounts. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub id: String,
    pub email: String,
    pub email_verified_at: Option<i64>,
    pub status: String,
    pub created_at: i64,
}

/// What: a row of email_codes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRow {
    pub email_hash: String,
    pub code_hash: String,
    pub expires_at: i64,
    pub attempts: i64,
    pub created_at: i64,
}

/// What: the store; each method is one atomic statement of the spec.
/// Why: spec SCHEMA, BUMP, verify steps 4, 6, 7. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: whatever the implementation uses.
pub trait Store: Send + Sync {
    /// What: BUMP: insert (key, window_start, 1) or add 1; the count after it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn bump(&self, key: &str, window_start: i64) -> i64;
    /// What: write the code row, replacing an earlier one for the address. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn put_code(&self, row: CodeRow);
    /// What: DELETE WHERE email_hash = :h AND code_hash = :c; true when a row was deleted.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn delete_code(&self, email_hash: &str, code_hash: &str) -> bool;
    /// What: UPDATE attempts = attempts + 1 WHERE email_hash = :h AND attempts < 5 AND expires_at > :now;
    /// the stored code_hash and the new attempts, or None when no row changed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn count_try(&self, email_hash: &str, now: i64) -> Option<(String, i64)>;
    /// What: delete the address's row when it is expired or used up. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn delete_dead_code(&self, email_hash: &str, now: i64);
    /// What: insert the account unless one has the email, then return the row for the email.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn insert_or_get_account(&self, candidate: Account) -> Account;
    /// What: set email_verified_at on the account. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn mark_verified(&self, account_id: &str, now: i64);
}

/// What: the in-memory tables (public so tests can read them and seed accounts).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
#[derive(Debug, Default, Clone)]
pub struct Tables {
    pub accounts: Vec<Account>,
    pub email_codes: HashMap<String, CodeRow>,
    pub rate_windows: HashMap<(String, i64), i64>,
}

/// What: an in-memory store; one mutex makes every call atomic. `account_reads` counts every read of
/// accounts (EMAILCODE-07: start never reads them). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
#[derive(Default)]
pub struct InMemoryStore {
    pub tables: Mutex<Tables>,
    pub account_reads: AtomicUsize,
}

/// What: `Store` for `InMemoryStore`; each method is documented on the trait.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
impl Store for InMemoryStore {
    fn bump(&self, key: &str, window_start: i64) -> i64 {
        let mut t = self.tables.lock().unwrap();
        let c = t.rate_windows.entry((key.to_string(), window_start)).or_insert(0);
        *c += 1;
        *c
    }
    fn put_code(&self, row: CodeRow) {
        self.tables.lock().unwrap().email_codes.insert(row.email_hash.clone(), row);
    }
    fn delete_code(&self, email_hash: &str, code_hash: &str) -> bool {
        let mut t = self.tables.lock().unwrap();
        if matches!(t.email_codes.get(email_hash), Some(r) if r.code_hash == code_hash) {
            t.email_codes.remove(email_hash);
            return true;
        }
        false
    }
    fn count_try(&self, email_hash: &str, now: i64) -> Option<(String, i64)> {
        let mut t = self.tables.lock().unwrap();
        match t.email_codes.get_mut(email_hash) {
            Some(r) if r.attempts < CODE_ATTEMPTS && r.expires_at > now => {
                r.attempts += 1;
                Some((r.code_hash.clone(), r.attempts))
            }
            _ => None,
        }
    }
    fn delete_dead_code(&self, email_hash: &str, now: i64) {
        let mut t = self.tables.lock().unwrap();
        if matches!(t.email_codes.get(email_hash), Some(r) if r.attempts >= CODE_ATTEMPTS || r.expires_at <= now) {
            t.email_codes.remove(email_hash);
        }
    }
    fn insert_or_get_account(&self, candidate: Account) -> Account {
        self.account_reads.fetch_add(1, Ordering::SeqCst);
        let mut t = self.tables.lock().unwrap();
        if let Some(a) = t.accounts.iter().find(|a| a.email == candidate.email) {
            return a.clone();
        }
        t.accounts.push(candidate.clone());
        candidate
    }
    fn mark_verified(&self, account_id: &str, now: i64) {
        if let Some(a) = self.tables.lock().unwrap().accounts.iter_mut().find(|a| a.id == account_id) {
            a.email_verified_at = Some(now);
        }
    }
}

/// What: lower-case hex of bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// What: constant-time equality of two texts (an XOR fold; the lengths are public).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// What: normalize_email(raw): trim space, tab, CR, LF; A-Z to a-z; 3-254 characters matching the spec's pattern.
/// In: the raw text. Out: the address, or None. Why: spec HELPERS, EMAILCODE-11.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn normalize_email(raw: &str) -> Option<String> {
    let t = raw.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'));
    let e: String = t.chars().map(|c| if c.is_ascii_uppercase() { c.to_ascii_lowercase() } else { c }).collect();
    let n = e.chars().count();
    if !(3..=254).contains(&n) {
        return None;
    }
    let re = Regex::new(r"^[a-z0-9][a-z0-9._%+=-]*@[a-z0-9-]+(?:\.[a-z0-9-]+)+$").expect("pattern compiles");
    if re.is_match(&e) { Some(e) } else { None }
}

/// What: CODE from a random source: 4 bytes as an unsigned big-endian number, >= 4294000000 drawn again,
/// n mod 1000000 with 6 digits. Why: spec HELPERS (CODE), EMAILCODE-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: the random source.
pub fn code_from_random(random_bytes: &RandomBytes) -> String {
    loop {
        let b = random_bytes(4);
        let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        if n < 4_294_000_000 {
            return format!("{:06}", n % 1_000_000);
        }
    }
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

/// What: the service and its injected parts. Why: spec CONFIGURATION. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: the store, the sender.
pub struct EmailCodeSignin {
    secret: Vec<u8>,
    sender: Sender,
    revoke_unproven: Revoke,
    store: Arc<dyn Store>,
    clock: Clock,
    random_bytes: RandomBytes,
    generate_code: Option<CodeGenerator>,
}

/// What: the flows of the spec. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the sender.
impl EmailCodeSignin {
    /// What: construct. In: secret (at least 32 bytes), sender (required), store, clock. Out: the service, or
    /// Err("not_configured") (fail closed). revoke_unproven defaults to doing nothing, random_bytes to the
    /// system CSPRNG and generate_code to CODE; the with_* methods replace them.
    /// Why: spec CONFIGURATION, EMAILCODE-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn new(secret: &[u8], sender: Option<Sender>, store: Arc<dyn Store>, clock: Clock) -> Result<Self, String> {
        let sender = match sender {
            Some(s) if secret.len() >= 32 => s,
            _ => return Err("not_configured".to_string()),
        };
        Ok(EmailCodeSignin {
            secret: secret.to_vec(),
            sender,
            revoke_unproven: Arc::new(|_| Ok(())),
            store,
            clock,
            random_bytes: system_random(),
            generate_code: None,
        })
    }

    /// What: set revoke_unproven. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn with_revoke(mut self, revoke: Revoke) -> Self {
        self.revoke_unproven = revoke;
        self
    }

    /// What: set random_bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn with_random(mut self, random_bytes: RandomBytes) -> Self {
        self.random_bytes = random_bytes;
        self
    }

    /// What: set generate_code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn with_code_generator(mut self, g: CodeGenerator) -> Self {
        self.generate_code = Some(g);
        self
    }

    /// What: hmac_hex(text) = hex HMAC-SHA256(secret, text). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn hmac_hex(&self, text: &str) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.secret).expect("any key length");
        mac.update(text.as_bytes());
        hex(&mac.finalize().into_bytes())
    }

    /// What: email_hash(email) = hmac_hex("email:" + email). Why: spec HELPERS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: nothing.
    pub fn email_hash(&self, email: &str) -> String {
        self.hmac_hex(&format!("email:{}", email))
    }

    /// What: code_hash(email, code) = hmac_hex("code:" + email_hash(email) + ":" + code).
    /// Why: spec HELPERS, EMAILCODE-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn code_hash(&self, email: &str, code: &str) -> String {
        self.hmac_hex(&format!("code:{}:{}", self.email_hash(email), code))
    }

    /// What: ip_hash(ip) = the first 32 characters of hmac_hex("ip:" + ip). A missing IP (the empty string, Rust's
    /// absent value for this &str parameter) is the text "unknown", as the spec's CONVENTIONS say, so every
    /// request without an IP shares one rate key.
    /// In: the client IP. Out: 32 hex characters.
    /// Why: spec HELPERS and CONVENTIONS; review finding 4525101359 (an empty IP hashed "ip:" instead of
    /// "ip:unknown"). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn ip_hash(&self, ip: &str) -> String {
        let ip = if ip.is_empty() { "unknown" } else { ip };
        self.hmac_hex(&format!("ip:{}", ip))[..32].to_string()
    }

    /// What: EK(email) = the first 32 characters of email_hash(email). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: nothing.
    fn ek(&self, email: &str) -> String {
        self.email_hash(email)[..32].to_string()
    }

    /// What: BUMP(key, span) with window_start = now - (now mod span). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: the store.
    fn bump(&self, key: &str, span: i64, now: i64) -> i64 {
        self.store.bump(key, now - now.rem_euclid(span))
    }

    /// What: the configured generator, or CODE over random_bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: the random source.
    fn new_code(&self) -> String {
        match &self.generate_code {
            Some(g) => g(),
            None => code_from_random(&self.random_bytes),
        }
    }

    /// What: start(email, ip): steps 1-6 of the spec. Never reads accounts.
    /// Out: {202, sent, 600}, or 422 invalid_email, 429 too_many_requests, 503 send_failed.
    /// Why: spec start, EMAILCODE-01, 07, 08, 09, 12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: the store, the sender (email in production).
    pub fn start(&self, email: &str, ip: &str) -> Result<Started, Refusal> {
        let e = normalize_email(email).ok_or_else(|| refuse("invalid_email", 422))?;
        let now = (self.clock)();
        if self.bump(&format!("start-ip#{}", self.ip_hash(ip)), 3600, now) > START_PER_IP_HOUR {
            return Err(refuse("too_many_requests", 429));
        }
        let ek = self.ek(&e);
        let h = self.bump(&format!("start-email#{}", ek), 3600, now);
        let d = self.bump(&format!("start-email-day#{}", ek), 86400, now);
        if h > START_PER_EMAIL_HOUR || d > START_PER_EMAIL_DAY {
            return Err(refuse("too_many_requests", 429));
        }
        let code = self.new_code();
        let eh = self.email_hash(&e);
        let ch = self.code_hash(&e, &code);
        self.store.put_code(CodeRow { email_hash: eh.clone(), code_hash: ch.clone(), expires_at: now + CODE_TTL, attempts: 0, created_at: now });
        match (self.sender)(&e, &code, CODE_TTL) {
            Ok(true) => Ok(Started { status: 202, sent: true, expires_in: CODE_TTL }),
            _ => {
                self.store.delete_code(&eh, &ch);
                Err(refuse("send_failed", 503))
            }
        }
    }

    /// What: verify(email, code, ip): steps 1-9 of the spec. Out: {200, account_id, email, new_account}, or
    /// 429 too_many_requests, 400 invalid_code (one body for every code fault), 500 processing_failed,
    /// 403 account_unavailable. Why: spec verify, EMAILCODE-01, 03..07, 10, 11, 13, 14.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the revoke hook, the random source.
    pub fn verify(&self, email: &str, code: &str, ip: &str) -> Result<SignedIn, Refusal> {
        let now = (self.clock)();
        if self.bump(&format!("verify-ip#{}", self.ip_hash(ip)), 3600, now) > VERIFY_PER_IP_HOUR {
            return Err(refuse("too_many_requests", 429));
        }
        let c: String = code.chars().filter(|&ch| ch != ' ' && ch != '-').collect();
        let e = match normalize_email(email) {
            Some(e) if c.len() == 6 && c.bytes().all(|b| b.is_ascii_digit()) => e,
            _ => return Err(refuse("invalid_code", 400)),
        };
        if self.bump(&format!("verify-email#{}", self.ek(&e)), 3600, now) > VERIFY_PER_EMAIL_HOUR {
            return Err(refuse("too_many_requests", 429));
        }
        let eh = self.email_hash(&e);
        let mine = self.code_hash(&e, &c);
        let (stored, attempts) = match self.store.count_try(&eh, now) {
            Some(x) => x,
            None => {
                self.store.delete_dead_code(&eh, now);
                let _ = constant_time_eq(&mine, &"0".repeat(64));
                return Err(refuse("invalid_code", 400));
            }
        };
        if !constant_time_eq(&mine, &stored) {
            if attempts >= CODE_ATTEMPTS {
                self.store.delete_code(&eh, &stored);
            }
            return Err(refuse("invalid_code", 400));
        }
        if !self.store.delete_code(&eh, &stored) {
            return Err(refuse("invalid_code", 400));
        }
        let id = hex(&(self.random_bytes)(16));
        let acct = self.store.insert_or_get_account(Account { id: id.clone(), email: e.clone(), email_verified_at: Some(now), status: "active".into(), created_at: now });
        let new_account = acct.id == id;
        if !new_account && acct.email_verified_at.is_none() {
            if (self.revoke_unproven)(&acct.id).is_err() {
                return Err(refuse("processing_failed", 500));
            }
            self.store.mark_verified(&acct.id, now);
        }
        if acct.status != "active" {
            return Err(refuse("account_unavailable", 403));
        }
        Ok(SignedIn { status: 200, account_id: acct.id, email: e, new_account })
    }
}

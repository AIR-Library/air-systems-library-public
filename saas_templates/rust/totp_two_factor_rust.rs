//! TOTP two-factor: authenticator codes (RFC 6238 over RFC 4226) and one-time recovery codes.
//!
//! What: enroll a user's authenticator (secret sealed with AES-256-GCM, bound to the user by its aad), confirm
//! it with a first code, verify 6-digit codes with one 30-second step of drift each way and a replay guard,
//! lock after 5 failures in 900 seconds (the try is counted before any code is looked at), stop checking
//! codes after 100 failures with no success (recovery_required), and sign in with one-time recovery codes
//! stored only as keyed HMACs. Every refusal is a returned `Refusal`, never a panic.
//! Why: Phase D wave 1, owner request 2026-11-10 (docs/specs/totp_two_factor.md, TOTP-01..14).
//! 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: the injected store (memory in `InMemoryStore`); the injected clock and random source. No network,
//! no files, no money. Never logs or returns a secret, a code, a recovery code hash input or a key.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub const STEP: i64 = 30;
pub const DIGITS: u32 = 6;
pub const LOCK_FAILURES: usize = 5;
pub const LOCK_SECONDS: i64 = 900;
pub const HARD_LOCK_FAILURES: i64 = 100;
pub const RECOVERY_CODES: usize = 8;
pub const RECOVERY_ALPHABET: &str = "23456789abcdefghjkmnpqrstvwxyz";
const B32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The injected clock: whole seconds since the Unix epoch.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;
/// The injected random source: n bytes.
pub type RandomBytes = Arc<dyn Fn(usize) -> Vec<u8> + Send + Sync>;

/// What: a refusal {error, status} plus retry_after for 429 locked.
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

/// What: enroll_start's answer. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollStart {
    pub secret: String,
    pub otpauth_uri: String,
}

/// What: verify's ok answer: method "totp" | "recovery_code" and the unused recovery codes left.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub ok: bool,
    pub method: String,
    pub recovery_codes_left: usize,
}

/// What: status's answer. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub enrolled: bool,
    pub locked_until: Option<i64>,
    pub recovery_required: bool,
    pub recovery_codes_left: usize,
}

/// What: a row of totp_enrollments. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrollment {
    pub user_id: String,
    pub secret_enc: String,
    pub confirmed_at: Option<i64>,
    pub last_used_step: i64,
    pub failed_since_success: i64,
    pub created_at: i64,
}

/// What: a row of totp_recovery_codes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRow {
    pub id: u64,
    pub user_id: String,
    pub code_hash: String,
    pub created_at: i64,
    pub used_at: Option<i64>,
}

/// What: a row of totp_failures (also the TRY slot). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureRow {
    pub id: u64,
    pub user_id: String,
    pub at: i64,
}

/// What: the storage the flows need; every write that the spec writes as one SQL statement is one atomic call.
/// Why: spec SCHEMA, TRY, CLAIM, step 7 of enroll_confirm. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: whatever the implementation uses.
pub trait Store: Send + Sync {
    /// What: the user's enrollment row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn get_enrollment(&self, user_id: &str) -> Option<Enrollment>;
    /// What: write an unconfirmed row, replacing an unconfirmed one; false when a confirmed row exists.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn put_unconfirmed(&self, row: Enrollment) -> bool;
    /// What: UPDATE ... SET confirmed_at, last_used_step, failed_since_success = 0 WHERE confirmed_at IS NULL
    /// AND secret_enc = :read; true when a row changed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn confirm(&self, user_id: &str, now: i64, step: i64, secret_enc_read: &str) -> bool;
    /// What: CLAIM(step): set last_used_step and failed_since_success = 0 where confirmed and last_used_step < step.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn claim(&self, user_id: &str, step: i64) -> bool;
    /// What: TRY: insert a failure row at now when fewer than 5 rows have at > now - 900; the row's id, or None.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn try_slot(&self, user_id: &str, now: i64) -> Option<u64>;
    /// What: delete one slot row by id. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn release_slot(&self, slot: u64);
    /// What: failed_since_success + 1. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn add_failure(&self, user_id: &str);
    /// What: failed_since_success = 0. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn reset_failures(&self, user_id: &str);
    /// What: the `at` of the user's failure rows with at > since, newest first. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn failures_since(&self, user_id: &str, since: i64) -> Vec<i64>;
    /// What: store recovery code hashes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn add_recovery_codes(&self, user_id: &str, hashes: &[String], now: i64);
    /// What: UPDATE ... SET used_at = now WHERE user, hash, used_at IS NULL; true when one row changed.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn use_recovery_code(&self, user_id: &str, code_hash: &str, now: i64) -> bool;
    /// What: the user's unused recovery codes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn recovery_codes_left(&self, user_id: &str) -> usize;
    /// What: delete the user's enrollment, recovery codes and failures. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn delete_user(&self, user_id: &str);
}

/// What: the in-memory store's tables (public so tests can read and damage rows).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
#[derive(Debug, Default, Clone)]
pub struct Tables {
    pub enrollments: HashMap<String, Enrollment>,
    pub recovery: Vec<RecoveryRow>,
    pub failures: Vec<FailureRow>,
    pub next_id: u64,
}

/// What: an in-memory store; one mutex makes each call atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory only.
#[derive(Default)]
pub struct InMemoryStore {
    pub tables: Mutex<Tables>,
}

/// What: `Store` for `InMemoryStore`; each method is documented on the trait.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
impl Store for InMemoryStore {
    fn get_enrollment(&self, user_id: &str) -> Option<Enrollment> {
        self.tables.lock().unwrap().enrollments.get(user_id).cloned()
    }
    fn put_unconfirmed(&self, row: Enrollment) -> bool {
        let mut t = self.tables.lock().unwrap();
        if let Some(r) = t.enrollments.get(&row.user_id) {
            if r.confirmed_at.is_some() {
                return false;
            }
        }
        t.enrollments.insert(row.user_id.clone(), row);
        true
    }
    fn confirm(&self, user_id: &str, now: i64, step: i64, secret_enc_read: &str) -> bool {
        let mut t = self.tables.lock().unwrap();
        match t.enrollments.get_mut(user_id) {
            Some(r) if r.confirmed_at.is_none() && r.secret_enc == secret_enc_read => {
                r.confirmed_at = Some(now);
                r.last_used_step = step;
                r.failed_since_success = 0;
                true
            }
            _ => false,
        }
    }
    fn claim(&self, user_id: &str, step: i64) -> bool {
        let mut t = self.tables.lock().unwrap();
        match t.enrollments.get_mut(user_id) {
            Some(r) if r.confirmed_at.is_some() && r.last_used_step < step => {
                r.last_used_step = step;
                r.failed_since_success = 0;
                true
            }
            _ => false,
        }
    }
    fn try_slot(&self, user_id: &str, now: i64) -> Option<u64> {
        let mut t = self.tables.lock().unwrap();
        let in_window = t.failures.iter().filter(|f| f.user_id == user_id && f.at > now - LOCK_SECONDS).count();
        if in_window >= LOCK_FAILURES {
            return None;
        }
        t.next_id += 1;
        let id = t.next_id;
        t.failures.push(FailureRow { id, user_id: user_id.to_string(), at: now });
        Some(id)
    }
    fn release_slot(&self, slot: u64) {
        self.tables.lock().unwrap().failures.retain(|f| f.id != slot);
    }
    fn add_failure(&self, user_id: &str) {
        if let Some(r) = self.tables.lock().unwrap().enrollments.get_mut(user_id) {
            r.failed_since_success += 1;
        }
    }
    fn reset_failures(&self, user_id: &str) {
        if let Some(r) = self.tables.lock().unwrap().enrollments.get_mut(user_id) {
            r.failed_since_success = 0;
        }
    }
    fn failures_since(&self, user_id: &str, since: i64) -> Vec<i64> {
        let t = self.tables.lock().unwrap();
        let mut v: Vec<(i64, u64)> = t.failures.iter().filter(|f| f.user_id == user_id && f.at > since).map(|f| (f.at, f.id)).collect();
        v.sort_by(|a, b| b.cmp(a));
        v.into_iter().map(|x| x.0).collect()
    }
    fn add_recovery_codes(&self, user_id: &str, hashes: &[String], now: i64) {
        let mut t = self.tables.lock().unwrap();
        for h in hashes {
            t.next_id += 1;
            let id = t.next_id;
            t.recovery.push(RecoveryRow { id, user_id: user_id.to_string(), code_hash: h.clone(), created_at: now, used_at: None });
        }
    }
    fn use_recovery_code(&self, user_id: &str, code_hash: &str, now: i64) -> bool {
        let mut t = self.tables.lock().unwrap();
        match t.recovery.iter_mut().find(|r| r.user_id == user_id && r.code_hash == code_hash && r.used_at.is_none()) {
            Some(r) => {
                r.used_at = Some(now);
                true
            }
            None => false,
        }
    }
    fn recovery_codes_left(&self, user_id: &str) -> usize {
        self.tables.lock().unwrap().recovery.iter().filter(|r| r.user_id == user_id && r.used_at.is_none()).count()
    }
    fn delete_user(&self, user_id: &str) {
        let mut t = self.tables.lock().unwrap();
        t.enrollments.remove(user_id);
        t.recovery.retain(|r| r.user_id != user_id);
        t.failures.retain(|f| f.user_id != user_id);
    }
}

/// What: lower-case hex of bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// What: constant-time equality: an XOR fold over equal-length bytes (lengths are not secret here).
/// Why: spec PRIMITIVES (constant time). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// What: base32_encode: RFC 4648 alphabet, upper case, no padding. In: bytes. Out: text.
/// Why: spec PURE FUNCTIONS, TOTP-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(B32[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
        buf &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// What: base32_decode: drop spaces, "-" and "="; a-z as A-Z; refuse other characters, an empty result and a
/// length of 1, 3 or 6 modulo 8. In: text. Out: bytes, or Err("invalid_base32").
/// Why: spec PURE FUNCTIONS, TOTP-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn base32_decode(text: &str) -> Result<Vec<u8>, String> {
    let bad = || "invalid_base32".to_string();
    let mut vals = Vec::new();
    for c in text.chars() {
        if c == ' ' || c == '-' || c == '=' {
            continue;
        }
        let u = c.to_ascii_uppercase();
        if !u.is_ascii() {
            return Err(bad());
        }
        match B32.iter().position(|&x| x == u as u8) {
            Some(v) => vals.push(v as u32),
            None => return Err(bad()),
        }
    }
    if vals.is_empty() || matches!(vals.len() % 8, 1 | 3 | 6) {
        return Err(bad());
    }
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for v in vals {
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push(((buf >> (bits - 8)) & 0xFF) as u8);
            bits -= 8;
        }
        buf &= (1 << bits) - 1;
    }
    Ok(out)
}

/// What: hotp(key, counter, digits): HMAC-SHA1 over the 8-byte big-endian counter, dynamic truncation.
/// Why: RFC 4226, spec PURE FUNCTIONS, TOTP-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn hotp(key: &[u8], counter: u64, digits: u32) -> String {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("any key length");
    mac.update(&counter.to_be_bytes());
    let m = mac.finalize().into_bytes();
    let o = (m[19] & 0x0f) as usize;
    let v = (((m[o] & 0x7f) as u64) << 24) | ((m[o + 1] as u64) << 16) | ((m[o + 2] as u64) << 8) | m[o + 3] as u64;
    format!("{:0width$}", v % 10u64.pow(digits), width = digits as usize)
}

/// What: totp_at(secret_base32, unix_time, digits) = hotp(decode(secret), floor(time / 30), digits).
/// Why: RFC 6238, TOTP-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn totp_at(secret_base32: &str, unix_time: i64, digits: u32) -> Result<String, String> {
    let key = base32_decode(secret_base32)?;
    Ok(hotp(&key, unix_time.div_euclid(STEP) as u64, digits))
}

/// What: pct(s): every UTF-8 byte outside [A-Za-z0-9._~-] as "%" + two upper-case hex digits.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn pct(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-') { (b as char).to_string() } else { format!("%{:02X}", b) })
        .collect()
}

/// What: otpauth_uri(secret, issuer, account_label), the Key URI authenticator apps read.
/// Why: spec PURE FUNCTIONS, TOTP-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn otpauth_uri(secret: &str, issuer: &str, account_label: &str) -> String {
    format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        pct(&format!("{}:{}", issuer, account_label)),
        secret,
        pct(issuer)
    )
}

/// What: seal(key32, nonce12, plaintext, aad) = "v1." + base64(nonce + AES-256-GCM ciphertext + tag).
/// Why: spec PURE FUNCTIONS, TOTP-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn seal(key32: &[u8], nonce12: &[u8], plaintext: &[u8], aad: &str) -> String {
    let cipher = Aes256Gcm::new_from_slice(key32).expect("32-byte key");
    let ct = cipher.encrypt(Nonce::from_slice(nonce12), Payload { msg: plaintext, aad: aad.as_bytes() }).expect("encrypt");
    let mut all = nonce12.to_vec();
    all.extend(ct);
    format!("v1.{}", B64.encode(all))
}

/// What: open(key32, sealed, aad): the plaintext, or None for a missing "v1." prefix, bad base64, fewer than
/// 28 bytes, a key that is not 32 bytes, or a tag that does not verify. Never panics.
/// Why: spec PURE FUNCTIONS, TOTP-10, TOTP-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn open(key32: &[u8], sealed: &str, aad: &str) -> Option<Vec<u8>> {
    let body = sealed.strip_prefix("v1.")?;
    let raw = B64.decode(body).ok()?;
    if raw.len() < 28 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key32).ok()?;
    cipher.decrypt(Nonce::from_slice(&raw[..12]), Payload { msg: &raw[12..], aad: aad.as_bytes() }).ok()
}

/// What: TOTP INPUT: the code without ASCII spaces and "-" when that is exactly 6 ASCII digits (64 chars max).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn totp_input(code: &str) -> Option<String> {
    if code.chars().count() > 64 {
        return None;
    }
    let c: String = code.chars().filter(|&ch| ch != ' ' && ch != '-').collect();
    if c.len() == 6 && c.bytes().all(|b| b.is_ascii_digit()) { Some(c) } else { None }
}

/// What: RECOVERY INPUT: A-Z to a-z, without ASCII spaces and "-"; exactly 12 symbols of the alphabet.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn recovery_input(code: &str) -> Option<String> {
    if code.chars().count() > 64 {
        return None;
    }
    let c: String = code.chars().filter(|&ch| ch != ' ' && ch != '-').map(|ch| ch.to_ascii_lowercase()).collect();
    if c.chars().count() == 12 && c.chars().all(|ch| RECOVERY_ALPHABET.contains(ch)) { Some(c) } else { None }
}

/// What: the system: configuration, store, clock and random source. Why: spec CONFIGURATION.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
pub struct TotpTwoFactor {
    encryption_key: Vec<u8>,
    recovery_hash_key: Vec<u8>,
    issuer: String,
    store: Arc<dyn Store>,
    clock: Clock,
    random_bytes: RandomBytes,
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

/// What: the flows of the spec. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
impl TotpTwoFactor {
    /// What: construct. In: encryption_key (exactly 32 bytes), recovery_hash_key (at least 32 bytes), issuer,
    /// store, clock, random source (None = system CSPRNG). Out: the system, or Err("invalid_key") (fail closed).
    /// Why: spec CONFIGURATION, TOTP-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn new(encryption_key: &[u8], recovery_hash_key: &[u8], issuer: &str, store: Arc<dyn Store>, clock: Clock, random_bytes: Option<RandomBytes>) -> Result<Self, String> {
        if encryption_key.len() != 32 || recovery_hash_key.len() < 32 {
            return Err("invalid_key".to_string());
        }
        Ok(TotpTwoFactor {
            encryption_key: encryption_key.to_vec(),
            recovery_hash_key: recovery_hash_key.to_vec(),
            issuer: issuer.to_string(),
            store,
            clock,
            random_bytes: random_bytes.unwrap_or_else(system_random),
        })
    }

    /// What: generate_secret() = base32_encode(random_bytes(20)), 32 characters.
    /// Why: spec PURE FUNCTIONS, TOTP-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the random source.
    pub fn generate_secret(&self) -> String {
        base32_encode(&(self.random_bytes)(20))
    }

    /// What: code_hash = hex HMAC-SHA256(recovery_hash_key, "recovery:" + user + ":" + recovery input form).
    /// Why: spec RECOVERY CODES, TOTP-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn recovery_code_hash(&self, user_id: &str, input_form: &str) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.recovery_hash_key).expect("any key length");
        mac.update(format!("recovery:{}:{}", user_id, input_form).as_bytes());
        hex(&mac.finalize().into_bytes())
    }

    /// What: retry_after for a locked user: the `at` of the 5th most recent row in the window + 900 - now.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store (read).
    fn locked_until(&self, user_id: &str, now: i64) -> Option<i64> {
        let ats = self.store.failures_since(user_id, now - LOCK_SECONDS);
        if ats.len() >= LOCK_FAILURES { Some(ats[LOCK_FAILURES - 1] + LOCK_SECONDS) } else { None }
    }

    /// What: TRY, answering 429 locked with retry_after when there is no slot. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: the store.
    fn take_slot(&self, user_id: &str, now: i64) -> Result<u64, Refusal> {
        match self.store.try_slot(user_id, now) {
            Some(s) => Ok(s),
            None => {
                let until = self.locked_until(user_id, now).unwrap_or(now + LOCK_SECONDS);
                Err(Refusal { error: "locked".into(), status: 429, retry_after: Some(until - now) })
            }
        }
    }

    /// What: FAILURE: the slot row stays; failed_since_success + 1; 401 invalid_code.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
    fn failure(&self, user_id: &str) -> Refusal {
        self.store.add_failure(user_id);
        refuse("invalid_code", 401)
    }

    /// What: a non-FAILURE answer: delete this call's slot row, then answer. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: the store.
    fn release<T>(&self, slot: u64, answer: Result<T, Refusal>) -> Result<T, Refusal> {
        self.store.release_slot(slot);
        answer
    }

    /// What: MATCH: the largest step s + d (d = -1, 0, +1, s + d >= 0) whose code equals the input, comparing all
    /// three in constant time with no early exit. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn match_step(&self, key: &[u8], input: &str, now: i64) -> Option<i64> {
        let s = now.div_euclid(STEP);
        let mut found = None;
        for d in -1..=1i64 {
            let step = s + d;
            if step < 0 {
                continue;
            }
            if constant_time_eq(hotp(key, step as u64, DIGITS).as_bytes(), input.as_bytes()) {
                found = Some(step);
            }
        }
        found
    }

    /// What: open the user's sealed secret and decode it; None when it cannot be opened.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn secret_key(&self, row: &Enrollment) -> Option<Vec<u8>> {
        let plain = open(&self.encryption_key, &row.secret_enc, &format!("totp:{}", row.user_id))?;
        base32_decode(std::str::from_utf8(&plain).ok()?).ok()
    }

    /// What: enroll_start(user_id, account_label): 409 already_enrolled for a confirmed row; else a new
    /// secret, sealed with a fresh nonce, replaces any unconfirmed row. Out: {secret, otpauth_uri}.
    /// Why: spec FLOWS, TOTP-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the random source.
    pub fn enroll_start(&self, user_id: &str, account_label: &str) -> Result<EnrollStart, Refusal> {
        if matches!(self.store.get_enrollment(user_id), Some(r) if r.confirmed_at.is_some()) {
            return Err(refuse("already_enrolled", 409));
        }
        let now = (self.clock)();
        let secret = self.generate_secret();
        let nonce = (self.random_bytes)(12);
        let row = Enrollment {
            user_id: user_id.to_string(),
            secret_enc: seal(&self.encryption_key, &nonce, secret.as_bytes(), &format!("totp:{}", user_id)),
            confirmed_at: None,
            last_used_step: 0,
            failed_since_success: 0,
            created_at: now,
        };
        if !self.store.put_unconfirmed(row) {
            return Err(refuse("already_enrolled", 409));
        }
        let uri = otpauth_uri(&secret, &self.issuer, account_label);
        Ok(EnrollStart { secret, otpauth_uri: uri })
    }

    /// What: enroll_confirm(user_id, code): steps 1-8 of the spec. Out: the 8 recovery codes (shown only here).
    /// Why: spec FLOWS, TOTP-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the random source.
    pub fn enroll_confirm(&self, user_id: &str, code: Option<&str>) -> Result<Vec<String>, Refusal> {
        let row = match self.store.get_enrollment(user_id) {
            None => return Err(refuse("enrollment_not_started", 409)),
            Some(r) => r,
        };
        if row.confirmed_at.is_some() {
            return Err(refuse("already_enrolled", 409));
        }
        let now = (self.clock)();
        let slot = self.take_slot(user_id, now)?;
        let input = match code.and_then(totp_input) {
            Some(i) => i,
            None => return Err(self.failure(user_id)),
        };
        let key = match self.secret_key(&row) {
            Some(k) => k,
            None => return self.release(slot, Err(refuse("secret_unreadable", 503))),
        };
        let step = match self.match_step(&key, &input, now) {
            Some(s) => s,
            None => return Err(self.failure(user_id)),
        };
        if !self.store.confirm(user_id, now, step, &row.secret_enc) {
            if matches!(self.store.get_enrollment(user_id), Some(r) if r.confirmed_at.is_some()) {
                return self.release(slot, Err(refuse("already_enrolled", 409)));
            }
            return Err(self.failure(user_id));
        }
        let codes = self.make_recovery_codes();
        let hashes: Vec<String> = codes.iter().map(|c| self.recovery_code_hash(user_id, &c.replace('-', ""))).collect();
        self.store.add_recovery_codes(user_id, &hashes, now);
        self.release(slot, Ok(codes))
    }

    /// What: draw 8 distinct recovery codes, one byte per symbol (b >= 240 drawn again), shown xxxx-xxxx-xxxx.
    /// Why: spec RECOVERY CODES. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the random source.
    fn make_recovery_codes(&self) -> Vec<String> {
        let alphabet: Vec<char> = RECOVERY_ALPHABET.chars().collect();
        let mut codes: Vec<String> = Vec::new();
        while codes.len() < RECOVERY_CODES {
            let mut s = String::new();
            for i in 0..12 {
                if i == 4 || i == 8 {
                    s.push('-');
                }
                loop {
                    let b = (self.random_bytes)(1)[0];
                    if b < 240 {
                        s.push(alphabet[(b % 30) as usize]);
                        break;
                    }
                }
            }
            if !codes.contains(&s) {
                codes.push(s);
            }
        }
        codes
    }

    /// What: steps 1-5 of verify (shared by verify and disable). Out: the method on success.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
    fn check_code(&self, user_id: &str, code: Option<&str>) -> Result<&'static str, Refusal> {
        let row = match self.store.get_enrollment(user_id) {
            Some(r) if r.confirmed_at.is_some() => r,
            _ => return Err(refuse("not_enrolled", 409)),
        };
        let now = (self.clock)();
        let slot = self.take_slot(user_id, now)?;
        if let Some(input) = code.and_then(totp_input) {
            if row.failed_since_success >= HARD_LOCK_FAILURES {
                return self.release(slot, Err(refuse("recovery_required", 429)));
            }
            let key = match self.secret_key(&row) {
                Some(k) => k,
                None => return self.release(slot, Err(refuse("secret_unreadable", 503))),
            };
            match self.match_step(&key, &input, now) {
                Some(step) if step > row.last_used_step && self.store.claim(user_id, step) => self.release(slot, Ok("totp")),
                _ => Err(self.failure(user_id)),
            }
        } else if let Some(input) = code.and_then(recovery_input) {
            let h = self.recovery_code_hash(user_id, &input);
            if self.store.use_recovery_code(user_id, &h, now) {
                self.store.reset_failures(user_id);
                self.release(slot, Ok("recovery_code"))
            } else {
                Err(self.failure(user_id))
            }
        } else {
            Err(self.failure(user_id))
        }
    }

    /// What: verify(user_id, code) -> {ok, method, recovery_codes_left}, or the refusal of steps 1-5.
    /// Why: spec FLOWS, TOTP-05..10, TOTP-13, TOTP-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
    pub fn verify(&self, user_id: &str, code: Option<&str>) -> Result<Verified, Refusal> {
        let method = self.check_code(user_id, code)?;
        Ok(Verified { ok: true, method: method.to_string(), recovery_codes_left: self.store.recovery_codes_left(user_id) })
    }

    /// What: disable(user_id, code): verify's steps 1-5; on ok delete the enrollment, recovery codes and failures.
    /// Why: spec FLOWS, TOTP-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
    pub fn disable(&self, user_id: &str, code: Option<&str>) -> Result<bool, Refusal> {
        self.check_code(user_id, code)?;
        self.store.delete_user(user_id);
        Ok(true)
    }

    /// What: status(user_id): enrolled, locked_until, recovery_required, recovery_codes_left; reads only.
    /// Why: spec FLOWS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store (read).
    pub fn status(&self, user_id: &str) -> Status {
        let now = (self.clock)();
        let row = self.store.get_enrollment(user_id).filter(|r| r.confirmed_at.is_some());
        Status {
            enrolled: row.is_some(),
            locked_until: self.locked_until(user_id, now),
            recovery_required: row.map(|r| r.failed_since_success >= HARD_LOCK_FAILURES).unwrap_or(false),
            recovery_codes_left: self.store.recovery_codes_left(user_id),
        }
    }
}

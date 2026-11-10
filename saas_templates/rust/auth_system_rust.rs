//! Auth system: signup with email verification, login with optional TOTP MFA, OAuth login, refresh
//! and access tokens (GEMINI dispatch spec, template #1).
//!
//! What: `AuthSystem` keeps users, sessions, codes and audit/why-chain rows in SQLite. Passwords follow
//! NIST SP 800-63B-4 (15-64+ characters, no composition rules, a blocklist plus the user's own email,
//! name and the service name) and are bcrypt-hashed. Email codes, refresh tokens and OAuth states are
//! random, stored only as keyed hashes (HMAC-SHA256 under the server key, spec d270fa3), compared in
//! constant time and single-use. Access tokens are
//! HS256 JWTs verified with the algorithm FIXED (the header's `alg` is never trusted; `none` is
//! refused). Failed logins are limited to 5 per 15 minutes per IP and per account; signups to 5 per IP
//! per 24 hours.
//! Why: the old file did not compile (it was written against an ORM pool its tests replaced with an
//! empty struct), and its tests expected one input to give two different answers. Rewritten
//! 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: the SQLite database it owns; email through `Mailer`; OAuth providers through
//! `OAuthProvider` (network in production); the clock; OS randomness. No money.
//! Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec d270fa3: keyed HMAC for stored secrets):
//! the stored hashes were a plain SHA-256, which a leaked table of 6-digit codes gives up to brute force;
//! `AuthSystem::new` now takes the HMAC key (AUTH_SECRET_KEY, 32+ bytes) and refuses to start without it.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bcrypt::{hash, verify, DEFAULT_COST};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, TOTP};

/// Name of the service, which may not be used as a password.
pub const SERVICE_NAME: &str = "aoi";
/// Minimum password length for a single-factor password (NIST SP 800-63B-4).
pub const MIN_PASSWORD_LEN: usize = 15;
/// Maximum accepted password length (at least 64 is required; 128 is allowed here).
pub const MAX_PASSWORD_LEN: usize = 128;
/// Access token lifetime in seconds.
pub const ACCESS_TOKEN_SECS: i64 = 15 * 60;
/// Refresh token (session) lifetime in seconds.
pub const REFRESH_TOKEN_SECS: i64 = 30 * 24 * 3600;
/// Common passwords that are always refused (extend with a full breached-password list in production).
pub const BLOCKLIST: [&str; 12] = [
    "password", "password123456789", "123456789012345", "qwertyuiopasdfgh", "iloveyouiloveyou", "letmeinletmein1",
    "passwordpassword", "111111111111111", "000000000000000", "abcdefghijklmnop", "welcome123456789", "adminadminadmin",
];

/// What: every auth failure, with the spec's codes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    EmailAlreadyExists,
    PasswordTooShort,
    PasswordTooLong,
    PasswordBlocklisted,
    InvalidInput(String),
    TooManySignups,
    TooManyAttempts,
    InvalidCode,
    /// verify_email's refusal of a wrong, used-up or unknown code: 400 code_invalid (Phase B.3/B.4, 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP; it answered 401 invalid_code, and 429 after 5 wrong codes).
    CodeInvalid,
    CodeExpired,
    InvalidCredentials,
    EmailNotVerified,
    InvalidState,
    ProviderEmailNotVerified,
    OAuthFailed,
    InvalidToken,
    TokenExpired,
    UserBanned,
    /// resend_verification's 4th request for one email within the hour: 429 too_many_requests (AUTH-18,
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
    TooManyRequests,
    Internal(String),
}

/// What: methods of `AuthError`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl AuthError {
    /// What: the spec's `{error, message, code}` body and HTTP status. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn to_response(&self) -> (Value, u16) {
        let (code, status, reason) = match self {
            AuthError::EmailAlreadyExists => ("email_already_exists", 409, None),
            AuthError::PasswordTooShort => ("password_rejected", 400, Some("too_short")),
            AuthError::PasswordTooLong => ("password_rejected", 400, Some("too_long")),
            AuthError::PasswordBlocklisted => ("password_rejected", 400, Some("blocklisted")),
            AuthError::InvalidInput(_) => ("invalid_input", 400, None),
            AuthError::TooManySignups => ("too_many_signups_from_ip", 429, None),
            AuthError::TooManyAttempts => ("too_many_attempts", 429, None),
            AuthError::InvalidCode => ("invalid_code", 401, None),
            AuthError::CodeInvalid => ("code_invalid", 400, None),
            AuthError::CodeExpired => ("code_expired", 400, None),
            AuthError::InvalidCredentials => ("invalid_credentials", 401, None),
            AuthError::EmailNotVerified => ("email_not_verified", 403, None),
            AuthError::InvalidState => ("invalid_state", 400, None),
            AuthError::ProviderEmailNotVerified => ("email_not_verified_by_provider", 403, None),
            AuthError::OAuthFailed => ("oauth_failed", 502, None),
            AuthError::InvalidToken => ("invalid_token", 401, None),
            AuthError::TokenExpired => ("token_expired", 401, None),
            AuthError::UserBanned => ("user_banned", 403, None),
            AuthError::TooManyRequests => ("too_many_requests", 429, None),
            AuthError::Internal(_) => ("internal_error", 500, None),
        };
        let mut body = json!({ "error": code, "message": self.to_string(), "code": status });
        if let Some(r) = reason {
            body["reason"] = json!(r);
        }
        (body, status)
    }
}

/// What: `fmt::Display` for `AuthError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl fmt::Display for AuthError {
    /// What: human-readable text of `fmt::Display for AuthError` (never secrets). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Internal(_) => write!(f, "internal error"),
            AuthError::InvalidInput(field) => write!(f, "invalid {}", field),
            other => write!(f, "{:?}", other),
        }
    }
}

/// What: `std::error::Error` for `AuthError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl std::error::Error for AuthError {}

/// What: `From<rusqlite::Error>` for `AuthError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl From<rusqlite::Error> for AuthError {
    /// What: convert the error of `From<rusqlite::Error> for AuthError`, keeping its message for logs. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn from(e: rusqlite::Error) -> Self {
        AuthError::Internal(e.to_string())
    }
}

/// What: signup input. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    pub name: String,
}

/// What: email verification input. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone)]
pub struct VerifyEmailRequest {
    pub email: String,
    pub code_or_token: String,
}

/// What: login input (`ip` and `device_id` come from the server's view of the request).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub device_id: String,
    pub ip: String,
}

/// What: OAuth callback input. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone)]
pub struct OAuthCallbackRequest {
    pub provider: String,
    pub code: String,
    pub state: String,
}

/// What: MFA challenge input. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone)]
pub struct MFAChallengeRequest {
    pub challenge_id: String,
    pub code: String,
}

/// What: refresh input. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone)]
pub struct TokenRefreshRequest {
    pub refresh_token: String,
}

/// What: access-token check input. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone)]
pub struct VerifyAccessTokenRequest {
    pub token: String,
}

/// What: the public part of a user. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq)]
pub struct PublicUser {
    pub id: i64,
    pub email: String,
    pub tier: String,
}

/// What: what a successful flow returns; `status()` is the spec's status string.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthData {
    PendingVerification { email: String, message: String },
    Verified { user_id: i64, message: String },
    Authenticated { session_id: String, token: String, refresh_token: String, expires_in: i64, user: PublicUser },
    MfaRequired { challenge_id: String },
    Refreshed { token: String, expires_in: i64 },
    TokenValid { user: PublicUser },
    /// resend_verification's 202 {status: "sent"}, the same for every email (AUTH-18, 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP).
    Sent,
}

/// What: methods of `AuthData`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl AuthData {
    /// What: the spec's status string for this result. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn status(&self) -> &'static str {
        match self {
            AuthData::PendingVerification { .. } => "pending_verification",
            AuthData::Verified { .. } => "verified",
            AuthData::Authenticated { .. } => "authenticated",
            AuthData::MfaRequired { .. } => "mfa_required",
            AuthData::Refreshed { .. } | AuthData::TokenValid { .. } => "ok",
            AuthData::Sent => "sent",
        }
    }
}

/// What: a successful response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthResponse {
    pub success: bool,
    pub data: AuthData,
}

/// What: one email the service sent. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// What: the email sender (SMTP or a provider API in production). 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: network in a real implementation.
pub trait Mailer: Send {
    /// What: `send` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn send(&self, email: Email) -> Result<(), String>;
}

/// What: an in-memory outbox; clones share it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Clone, Default)]
pub struct InMemoryMailer {
    pub sent: Arc<Mutex<Vec<Email>>>,
}

/// What: `Mailer` for `InMemoryMailer`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl Mailer for InMemoryMailer {
    /// What: `send` of `Mailer for InMemoryMailer`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn send(&self, email: Email) -> Result<(), String> {
        self.sent.lock().map_err(|_| "lock".to_string())?.push(email);
        Ok(())
    }
}

/// What: what an OAuth provider says about the user after the code exchange.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq)]
pub struct OAuthProfile {
    pub provider_user_id: String,
    pub email: String,
    pub email_verified: bool,
}

/// What: exchanges an authorization code with a provider (Google, GitHub, ...). 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: network in a real implementation.
pub trait OAuthProvider: Send {
    /// What: `exchange_code` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn exchange_code(&self, provider: &str, code: &str) -> Result<OAuthProfile, String>;
}

/// What: an in-memory provider: `codes` maps "provider:code" to a profile. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
#[derive(Clone, Default)]
pub struct FakeOAuthProvider {
    pub codes: Arc<Mutex<HashMap<String, OAuthProfile>>>,
}

/// What: `OAuthProvider` for `FakeOAuthProvider`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl OAuthProvider for FakeOAuthProvider {
    /// What: `exchange_code` of `OAuthProvider for FakeOAuthProvider`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn exchange_code(&self, provider: &str, code: &str) -> Result<OAuthProfile, String> {
        self.codes.lock().map_err(|_| "lock".to_string())?.get(&format!("{}:{}", provider, code)).cloned().ok_or_else(|| "unknown code".into())
    }
}

/// What: `n` OS-random bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: OS randomness.
fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

/// What: lowercase hex. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// What: lowercase hex HMAC-SHA256(key, s), the only form secrets (email codes, refresh tokens, OAuth
/// states) are stored in. In: the key, the secret. Out: 64 hex characters. Why: spec d270fa3: keyed HMAC
/// for stored secrets (it replaced the plain SHA-256 helper `sha256_hex`). 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn hmac_sha256_hex(key: &[u8], s: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(s.as_bytes());
    hex(&mac.finalize().into_bytes())
}

/// What: the shortest HMAC key the service starts with (spec d270fa3: AUTH_SECRET_KEY, at least 32
/// bytes). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
pub const MIN_SECRET_KEY_BYTES: usize = 32;

/// What: constant-time equality. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// What: RFC 4648 base32 (no padding) for showing a TOTP secret. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP.
pub fn base32_encode(bytes: &[u8]) -> String {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut out, mut buf, mut bits) = (String::new(), 0u32, 0u32);
    for b in bytes {
        buf = (buf << 8) | *b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(A[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(A[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// What: RFC 4648 base32 decode (case-insensitive, no padding). 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0u32);
    for c in s.trim_end_matches('=').chars() {
        let v = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u32 - 'A' as u32,
            c @ '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return None,
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push((buf >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    Some(out)
}

/// What: the 6-digit TOTP code (SHA-1, 30 s, RFC 6238) for a base32 secret at a time. Used by
/// authenticator apps and by tests. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn totp_code(secret_b32: &str, unix_time: u64) -> Option<String> {
    let totp = TOTP::new(Algorithm::SHA1, 6, 0, 30, base32_decode(secret_b32)?).ok()?;
    Some(totp.generate(unix_time))
}

/// What: NIST password check. In: password, email, name. Out: `()` or the rejection reason.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn check_password(password: &str, email: &str, name: &str) -> Result<(), AuthError> {
    let len = password.chars().count();
    if len < MIN_PASSWORD_LEN {
        return Err(AuthError::PasswordTooShort);
    }
    if len > MAX_PASSWORD_LEN {
        return Err(AuthError::PasswordTooLong);
    }
    let lower = password.to_lowercase();
    let own = [email.trim().to_lowercase(), name.trim().to_lowercase(), SERVICE_NAME.to_string()];
    if BLOCKLIST.contains(&lower.as_str()) || own.iter().any(|o| !o.is_empty() && lower == *o) {
        return Err(AuthError::PasswordBlocklisted);
    }
    Ok(())
}

/// What: the auth service. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: see module doc.
pub struct AuthSystem {
    conn: Connection,
    jwt_secret: Vec<u8>,
    /// HMAC key for stored secrets (spec d270fa3, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
    secret_key: Vec<u8>,
    bcrypt_cost: u32,
    mailer: Box<dyn Mailer>,
    oauth: Box<dyn OAuthProvider>,
    clock: Box<dyn Fn() -> i64 + Send>,
    dummy_hash: OnceLock<String>,
}

/// What: methods of `AuthSystem`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl AuthSystem {
    /// What: a service on a connection (tables created) with an HS256 secret of at least 32 bytes
    /// (RFC 7518: the key must be as long as the hash output), bcrypt's default cost, an in-memory
    /// mailer and no OAuth codes. Out: the service or `InvalidInput("jwt_secret")`.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (DDL).
    /// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets:
    /// `secret_key` is the HMAC key every stored secret is kept under, injected like the JWT secret (load
    /// it from the AUTH_SECRET_KEY environment variable). Out: `InvalidInput("secret_key ...")` when it is
    /// shorter than 32 bytes, before any table is touched, so the service refuses to start without it.
    pub fn new(conn: Connection, jwt_secret: String, secret_key: String) -> Result<Self, AuthError> {
        if secret_key.len() < MIN_SECRET_KEY_BYTES {
            return Err(AuthError::InvalidInput("secret_key (AUTH_SECRET_KEY needs 32+ bytes)".into()));
        }
        if jwt_secret.len() < 32 {
            return Err(AuthError::InvalidInput("jwt_secret (needs 32+ bytes)".into()));
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, password_hash TEXT NULL,
                name TEXT NOT NULL, tier TEXT NOT NULL DEFAULT 'solo', status TEXT NOT NULL, email_verified_at INTEGER NULL,
                mfa_secret TEXT NULL, mfa_enabled INTEGER NOT NULL DEFAULT 0, mfa_last_step INTEGER NULL, created_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, refresh_token_hash TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, ip TEXT, device_id TEXT, revoked_at INTEGER NULL);
             CREATE TABLE IF NOT EXISTS verification_codes (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, code_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, type TEXT NOT NULL CHECK (type IN ('email','mfa')),
                attempts INTEGER NOT NULL DEFAULT 0, consumed_at INTEGER NULL);
             CREATE TABLE IF NOT EXISTS oauth_states (state_hash TEXT PRIMARY KEY, provider TEXT NOT NULL, expires_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS oauth_links (provider TEXT NOT NULL, provider_user_id TEXT NOT NULL, user_id INTEGER NOT NULL,
                PRIMARY KEY (provider, provider_user_id));
             CREATE TABLE IF NOT EXISTS attempts (kind TEXT NOT NULL, key TEXT NOT NULL, at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, actor_id INTEGER NULL,
                action TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT NULL, old_value TEXT NULL, new_value TEXT NULL);
             CREATE TABLE IF NOT EXISTS why_chain (id INTEGER PRIMARY KEY AUTOINCREMENT, flow TEXT NOT NULL, decision_points TEXT NOT NULL,
                outcome TEXT NOT NULL, created_at INTEGER NOT NULL);",
        )?;
        Ok(Self {
            conn,
            jwt_secret: jwt_secret.into_bytes(),
            secret_key: secret_key.into_bytes(),
            bcrypt_cost: DEFAULT_COST,
            mailer: Box::new(InMemoryMailer::default()),
            oauth: Box::new(FakeOAuthProvider::default()),
            clock: Box::new(|| SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)),
            dummy_hash: OnceLock::new(),
        })
    }

    /// What: the stored form of a secret: lowercase hex HMAC-SHA256(secret_key, s). In: the secret. Out:
    /// 64 hex characters. Why: spec d270fa3: keyed HMAC for stored secrets. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn hash_secret(&self, s: &str) -> String {
        hmac_sha256_hex(&self.secret_key, s)
    }

    /// What: set the bcrypt cost (4-31; tests use 4 because debug builds hash slowly).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn with_bcrypt_cost(mut self, cost: u32) -> Self {
        self.bcrypt_cost = cost.clamp(4, 31);
        self
    }

    /// What: set the mailer. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn with_mailer(mut self, mailer: Box<dyn Mailer>) -> Self {
        self.mailer = mailer;
        self
    }

    /// What: set the OAuth provider client. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn with_oauth(mut self, oauth: Box<dyn OAuthProvider>) -> Self {
        self.oauth = oauth;
        self
    }

    /// What: set the clock (Unix seconds). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> i64 + Send>) -> Self {
        self.clock = clock;
        self
    }

    /// What: current time. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn now(&self) -> i64 {
        (self.clock)()
    }

    /// What: write the why-chain row for a flow. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database.
    fn why(&self, flow: &str, points: &[&str], outcome: &str) {
        let _ = self.conn.execute(
            "INSERT INTO why_chain (flow, decision_points, outcome, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![flow, json!(points).to_string(), outcome, self.now()],
        );
    }

    /// What: write an audit row (never a password or token). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database.
    fn audit(&self, actor: Option<i64>, action: &str, resource_id: Option<String>, new_value: Value) -> Result<(), AuthError> {
        self.conn.execute(
            "INSERT INTO audit_log (timestamp, actor_id, action, resource_type, resource_id, new_value) VALUES (?1, ?2, ?3, 'user', ?4, ?5)",
            params![self.now(), actor, action, resource_id, new_value.to_string()],
        )?;
        Ok(())
    }

    /// What: count recent attempts of a kind for a key, and optionally record one more.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn attempts(&self, kind: &str, key: &str, window: i64) -> Result<i64, AuthError> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM attempts WHERE kind = ?1 AND key = ?2 AND at > ?3",
            params![kind, key, self.now() - window],
            |r| r.get(0),
        )?)
    }

    /// What: record one attempt. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn record_attempt(&self, kind: &str, key: &str) -> Result<(), AuthError> {
        self.conn.execute("INSERT INTO attempts (kind, key, at) VALUES (?1, ?2, ?3)", params![kind, key, self.now()])?;
        Ok(())
    }

    /// What: create a user from the public signup form, with no per-IP limit (for trusted internal
    /// callers only; web handlers use `signup_with_ip`). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: as `signup_with_ip`.
    pub fn signup(&mut self, req: SignupRequest) -> Result<AuthResponse, AuthError> {
        self.signup_with_ip(req, "")
    }

    /// What: flow 1. Gates: email valid and unused, NIST password rules, at most 5 signups per IP per
    /// 24 hours. Creates an unverified user and emails a 6-digit code valid 15 minutes.
    /// Out: pending_verification. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database, email, bcrypt.
    pub fn signup_with_ip(&mut self, req: SignupRequest, ip: &str) -> Result<AuthResponse, AuthError> {
        let email = req.email.trim().to_lowercase();
        if !email.contains('@') || email.len() > 254 || email.starts_with('@') || email.ends_with('@') {
            return Err(AuthError::InvalidInput("email".into()));
        }
        if !ip.is_empty() && self.attempts("signup_ip", ip, 24 * 3600)? >= 5 {
            self.why("signup", &["email_unique", "password_strength", "rate_limit_ip_24h"], "rate_limited");
            return Err(AuthError::TooManySignups);
        }
        check_password(&req.password, &email, &req.name)?;
        let exists: i64 = self.conn.query_row("SELECT COUNT(*) FROM users WHERE email = ?1", params![email], |r| r.get(0))?;
        if exists > 0 {
            self.why("signup", &["email_unique"], "duplicate");
            return Err(AuthError::EmailAlreadyExists);
        }
        let password_hash = hash(&req.password, self.bcrypt_cost).map_err(|e| AuthError::Internal(e.to_string()))?;
        self.conn.execute(
            "INSERT INTO users (email, password_hash, name, status, created_at) VALUES (?1, ?2, ?3, 'unverified', ?4)",
            params![email, password_hash, req.name.trim(), self.now()],
        )?;
        let user_id = self.conn.last_insert_rowid();
        if !ip.is_empty() {
            self.record_attempt("signup_ip", ip)?;
        }
        self.send_email_code(user_id, &email)?;
        self.why("signup", &["email_unique", "password_strength", "rate_limit_ip_24h"], "created");
        self.audit(Some(user_id), "user_created", Some(user_id.to_string()), json!({ "email": email }))?;
        Ok(AuthResponse { success: true, data: AuthData::PendingVerification { email, message: "check email".into() } })
    }

    /// What: issue and email a new 6-digit verification code (earlier unused codes stop working).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, email.
    /// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
    fn send_email_code(&self, user_id: i64, email: &str) -> Result<(), AuthError> {
        let n = u32::from_be_bytes(random_bytes(4).try_into().unwrap_or([0; 4])) % 1_000_000;
        let code = format!("{:06}", n);
        let now = self.now();
        self.conn.execute("UPDATE verification_codes SET consumed_at = ?2 WHERE user_id = ?1 AND type = 'email' AND consumed_at IS NULL", params![user_id, now])?;
        self.conn.execute(
            "INSERT INTO verification_codes (id, user_id, code_hash, created_at, expires_at, type) VALUES (?1, ?2, ?3, ?4, ?5, 'email')",
            params![hex(&random_bytes(16)), user_id, self.hash_secret(&code), now, now + 15 * 60],
        )?;
        self.mailer
            .send(Email { to: email.to_string(), subject: "Your verification code".into(), body: format!("Your code is {}", code) })
            .map_err(AuthError::Internal)
    }

    /// What: flow 2b, resend_verification. At most 3 requests per email per hour are accepted: the count and this
    /// request's row are one conditional INSERT into `attempts` (kind "resend_email"), and a 4th within the hour is
    /// `TooManyRequests` (429 too_many_requests) and sends nothing. For an unverified user it deletes the user's email
    /// codes, stores a new 6-digit code (attempts 0, its HMAC-SHA256 under the secret key, 10-minute expiry) and emails
    /// it through the mailer. An unknown or already verified email gets the same `Sent` (202 {status: "sent"}) and
    /// nothing is sent, so the answer never says whether an account exists; those requests count toward the limit too.
    /// In: the email (trimmed and lower-cased, as signup stores it). Out: `Sent`, or `TooManyRequests` / `Internal`.
    /// Why: AUTH-18 (auth spec flow 2b, commit 0eb5a4e): after 5 wrong codes (AUTH-17) nothing could issue a new code,
    /// so anyone who knew an email could block its verification. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (attempts, users read, verification_codes, audit_log, why_chain), the mailer.
    pub fn resend_verification(&mut self, email: &str) -> Result<AuthResponse, AuthError> {
        let email = email.trim().to_lowercase();
        let now = self.now();
        let accepted = self.conn.execute(
            "INSERT INTO attempts (kind, key, at) SELECT 'resend_email', ?1, ?2
             WHERE (SELECT COUNT(*) FROM attempts WHERE kind = 'resend_email' AND key = ?1 AND at > ?3) < 3",
            params![email, now, now - 3600],
        )?;
        if accepted != 1 {
            self.why("resend_verification", &["rate_limit_email_1h"], "rate_limited");
            return Err(AuthError::TooManyRequests);
        }
        let sent = AuthResponse { success: true, data: AuthData::Sent };
        let user: Option<(i64, Option<i64>)> = self
            .conn
            .query_row("SELECT id, email_verified_at FROM users WHERE email = ?1", params![email], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        let user_id = match user {
            Some((id, None)) => id,
            _ => {
                // Unknown or already verified: the same answer as a real resend, and no email (no account enumeration).
                self.why("resend_verification", &["rate_limit_email_1h", "user_unverified"], "not_sent");
                return Ok(sent);
            }
        };
        let n = u32::from_be_bytes(random_bytes(4).try_into().unwrap_or([0; 4])) % 1_000_000;
        let code = format!("{:06}", n);
        self.conn.execute("DELETE FROM verification_codes WHERE user_id = ?1 AND type = 'email'", params![user_id])?;
        self.conn.execute(
            "INSERT INTO verification_codes (id, user_id, code_hash, created_at, expires_at, type, attempts) VALUES (?1, ?2, ?3, ?4, ?5, 'email', 0)",
            params![hex(&random_bytes(16)), user_id, self.hash_secret(&code), now, now + 10 * 60],
        )?;
        self.mailer
            .send(Email { to: email.clone(), subject: "Your verification code".into(), body: format!("Your code is {}", code) })
            .map_err(AuthError::Internal)?;
        self.why("resend_verification", &["rate_limit_email_1h", "user_unverified"], "sent");
        self.audit(Some(user_id), "verification_resent", Some(user_id.to_string()), json!({}))?;
        Ok(sent)
    }

    /// What: flow 2. Gates: an unexpired, unused code that matches (5 tries), user still unverified.
    /// Unknown emails give `CodeInvalid` (no account probing). Out: verified.
    /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec Phase B.3 and B.4, AUTH-17): a wrong code is
    /// 400 code_invalid (was 401 invalid_code), and after 5 wrong codes the current code is dead: every further
    /// try, the right code included, is 400 code_invalid (was 429 too_many_attempts) until a new code is sent.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    /// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
    pub fn verify_email(&mut self, req: VerifyEmailRequest) -> Result<AuthResponse, AuthError> {
        let email = req.email.trim().to_lowercase();
        let user: Option<(i64, Option<i64>)> = self.conn.query_row("SELECT id, email_verified_at FROM users WHERE email = ?1", params![email], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
        let Some((user_id, verified_at)) = user else { return Err(AuthError::CodeInvalid) };
        if verified_at.is_some() {
            return Err(AuthError::CodeInvalid);
        }
        let code: Option<(String, String, i64, i64)> = self
            .conn
            .query_row(
                "SELECT id, code_hash, expires_at, attempts FROM verification_codes WHERE user_id = ?1 AND type = 'email' AND consumed_at IS NULL
                 ORDER BY created_at DESC, rowid DESC LIMIT 1",
                params![user_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((code_id, code_hash, expires_at, attempts)) = code else { return Err(AuthError::CodeInvalid) };
        if attempts >= 5 {
            return Err(AuthError::CodeInvalid);
        }
        if !ct_eq(self.hash_secret(req.code_or_token.trim()).as_bytes(), code_hash.as_bytes()) {
            self.conn.execute("UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ?1", params![code_id])?;
            self.why("verify_email", &["code_valid"], "wrong_code");
            return Err(AuthError::CodeInvalid);
        }
        if self.now() >= expires_at {
            return Err(AuthError::CodeExpired);
        }
        let now = self.now();
        self.conn.execute("UPDATE verification_codes SET consumed_at = ?2 WHERE id = ?1", params![code_id, now])?;
        self.conn.execute("UPDATE users SET email_verified_at = ?2, status = 'active' WHERE id = ?1 AND status = 'unverified'", params![user_id, now])?;
        self.why("verify_email", &["code_valid", "user_unverified"], "verified");
        self.audit(Some(user_id), "email_verified", Some(user_id.to_string()), json!({}))?;
        Ok(AuthResponse { success: true, data: AuthData::Verified { user_id, message: "ready to login".into() } })
    }

    /// What: an HS256 JWT for a user (sub, tier, iat, exp, typ "access"). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn issue_access_token(&self, user: &PublicUser) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let now = self.now();
        let claims = json!({ "sub": user.id, "tier": user.tier, "iat": now, "exp": now + ACCESS_TOKEN_SECS, "typ": "access" });
        let body = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.jwt_secret).expect("HMAC accepts any key length");
        mac.update(format!("{}.{}", header, body).as_bytes());
        format!("{}.{}.{}", header, body, URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }

    /// What: create a session with a random refresh token (stored hashed) and an access token.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    /// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
    fn create_session(&self, user: &PublicUser, ip: &str, device_id: &str) -> Result<AuthData, AuthError> {
        let session_id = hex(&random_bytes(16));
        let refresh = URL_SAFE_NO_PAD.encode(random_bytes(32));
        let now = self.now();
        self.conn.execute(
            "INSERT INTO sessions (id, user_id, refresh_token_hash, created_at, expires_at, ip, device_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![session_id, user.id, self.hash_secret(&refresh), now, now + REFRESH_TOKEN_SECS, ip, device_id],
        )?;
        self.audit(Some(user.id), "session_created", Some(session_id.clone()), json!({ "ip": ip, "device_id": device_id }))?;
        Ok(AuthData::Authenticated { session_id, token: self.issue_access_token(user), refresh_token: refresh, expires_in: ACCESS_TOKEN_SECS, user: user.clone() })
    }

    /// What: load (public user, status, mfa_enabled) by id. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn load_user(&self, user_id: i64) -> Result<Option<(PublicUser, String, bool)>, AuthError> {
        Ok(self
            .conn
            .query_row("SELECT id, email, tier, status, mfa_enabled FROM users WHERE id = ?1", params![user_id], |r| {
                Ok((PublicUser { id: r.get(0)?, email: r.get(1)?, tier: r.get(2)? }, r.get(3)?, r.get::<_, i64>(4)? != 0))
            })
            .optional()?)
    }

    /// What: flow 3. Gates: at most 5 failed logins per 15 minutes per IP and per account; password
    /// checked with bcrypt (a dummy hash is checked for unknown emails, so timing does not reveal
    /// accounts); email verified; banned/suspended refused; MFA users get a 5-minute challenge.
    /// Out: authenticated (session, tokens) or mfa_required. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database, bcrypt.
    pub fn login(&mut self, req: LoginRequest) -> Result<AuthResponse, AuthError> {
        let email = req.email.trim().to_lowercase();
        let window = 15 * 60;
        if self.attempts("login_ip", &req.ip, window)? >= 5 || self.attempts("login_user", &email, window)? >= 5 {
            self.why("login", &["rate_limit"], "rate_limited");
            return Err(AuthError::TooManyAttempts);
        }
        let row: Option<(i64, Option<String>, Option<i64>, String)> = self
            .conn
            .query_row("SELECT id, password_hash, email_verified_at, status FROM users WHERE email = ?1", params![email], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .optional()?;
        let ok = match &row {
            Some((_, Some(h), _, _)) => verify(&req.password, h).unwrap_or(false),
            _ => {
                // same bcrypt work for unknown emails, so response time does not reveal accounts
                let dummy = self.dummy_hash.get_or_init(|| hash("timing-equaliser-not-a-password", self.bcrypt_cost).unwrap_or_default());
                let _ = verify(&req.password, dummy);
                false
            }
        };
        if !ok {
            self.record_attempt("login_ip", &req.ip)?;
            self.record_attempt("login_user", &email)?;
            self.why("login", &["user_exists", "password_correct"], "invalid_credentials");
            return Err(AuthError::InvalidCredentials);
        }
        let (user_id, _, verified_at, status) = row.expect("checked above");
        if verified_at.is_none() {
            return Err(AuthError::EmailNotVerified);
        }
        if status == "banned" || status == "suspended" {
            return Err(AuthError::UserBanned);
        }
        let (user, _, mfa) = self.load_user(user_id)?.ok_or(AuthError::InvalidCredentials)?;
        if mfa {
            let challenge_id = hex(&random_bytes(16));
            let now = self.now();
            self.conn.execute(
                "INSERT INTO verification_codes (id, user_id, code_hash, created_at, expires_at, type) VALUES (?1, ?2, '', ?3, ?4, 'mfa')",
                params![challenge_id, user_id, now, now + 5 * 60],
            )?;
            self.why("login", &["user_exists", "password_correct", "mfa_gate", "rate_limit"], "mfa_required");
            return Ok(AuthResponse { success: true, data: AuthData::MfaRequired { challenge_id } });
        }
        self.why("login", &["user_exists", "password_correct", "mfa_gate", "rate_limit"], "authenticated");
        Ok(AuthResponse { success: true, data: self.create_session(&user, &req.ip, &req.device_id)? })
    }

    /// What: begin TOTP enrollment for a signed-in user: store a new 160-bit secret (not yet enabled)
    /// and return it in base32 for the authenticator app. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database.
    pub fn start_mfa_enrollment(&mut self, user_id: i64) -> Result<String, AuthError> {
        let secret = base32_encode(&random_bytes(20));
        let n = self.conn.execute("UPDATE users SET mfa_secret = ?2, mfa_enabled = 0 WHERE id = ?1", params![user_id, secret])?;
        if n == 0 {
            return Err(AuthError::InvalidCredentials);
        }
        Ok(secret)
    }

    /// What: finish enrollment with a current code from the app; MFA is on from then.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub fn confirm_mfa_enrollment(&mut self, user_id: i64, code: &str) -> Result<(), AuthError> {
        self.check_totp(user_id, code)?;
        self.conn.execute("UPDATE users SET mfa_enabled = 1 WHERE id = ?1", params![user_id])?;
        self.audit(Some(user_id), "mfa_enabled", Some(user_id.to_string()), json!({}))
    }

    /// What: check a TOTP code (current step only) and refuse a code from a step already used.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn check_totp(&self, user_id: i64, code: &str) -> Result<(), AuthError> {
        let (secret, last): (Option<String>, Option<i64>) =
            self.conn.query_row("SELECT mfa_secret, mfa_last_step FROM users WHERE id = ?1", params![user_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        let secret = secret.ok_or(AuthError::InvalidCode)?;
        let now = self.now().max(0) as u64;
        let step = (now / 30) as i64;
        let expected = totp_code(&secret, now).ok_or(AuthError::InvalidCode)?;
        if last == Some(step) || !ct_eq(expected.as_bytes(), code.trim().as_bytes()) {
            return Err(AuthError::InvalidCode);
        }
        self.conn.execute("UPDATE users SET mfa_last_step = ?2 WHERE id = ?1", params![user_id, step])?;
        Ok(())
    }

    /// What: flow 5. Gates: an unexpired, unused challenge (5 tries) and a correct TOTP code.
    /// Out: authenticated. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub fn mfa_challenge(&mut self, req: MFAChallengeRequest) -> Result<AuthResponse, AuthError> {
        let ch: Option<(i64, i64, i64)> = self
            .conn
            .query_row(
                "SELECT user_id, expires_at, attempts FROM verification_codes WHERE id = ?1 AND type = 'mfa' AND consumed_at IS NULL",
                params![req.challenge_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((user_id, expires_at, attempts)) = ch else { return Err(AuthError::InvalidCode) };
        if self.now() >= expires_at {
            return Err(AuthError::CodeExpired);
        }
        if attempts >= 5 {
            return Err(AuthError::TooManyAttempts);
        }
        if let Err(e) = self.check_totp(user_id, &req.code) {
            self.conn.execute("UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ?1", params![req.challenge_id])?;
            self.why("mfa_challenge", &["challenge_valid", "code_correct"], "wrong_code");
            return Err(e);
        }
        self.conn.execute("UPDATE verification_codes SET consumed_at = ?2 WHERE id = ?1", params![req.challenge_id, self.now()])?;
        let (user, status, _) = self.load_user(user_id)?.ok_or(AuthError::InvalidCode)?;
        if status == "banned" || status == "suspended" {
            return Err(AuthError::UserBanned);
        }
        self.why("mfa_challenge", &["challenge_valid", "code_correct"], "authenticated");
        self.audit(Some(user_id), "mfa_verified", Some(user_id.to_string()), json!({}))?;
        Ok(AuthResponse { success: true, data: self.create_session(&user, "", "")? })
    }

    /// What: begin an OAuth login: a random state (stored hashed, 10 minutes) to put in the provider
    /// redirect. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    /// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
    pub fn oauth_start(&mut self, provider: &str) -> Result<String, AuthError> {
        let state = URL_SAFE_NO_PAD.encode(random_bytes(24));
        self.conn.execute(
            "INSERT INTO oauth_states (state_hash, provider, expires_at) VALUES (?1, ?2, ?3)",
            params![self.hash_secret(&state), provider, self.now() + 600],
        )?;
        Ok(state)
    }

    /// What: flow 4. Gates: the state was issued for this provider, is unexpired and is used once;
    /// the provider verified the email. New email: an active user is created; existing email: the
    /// provider is linked to it. Out: authenticated. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database, the OAuth provider.
    /// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
    pub fn oauth_callback(&mut self, req: OAuthCallbackRequest) -> Result<AuthResponse, AuthError> {
        let consumed = self.conn.execute(
            "DELETE FROM oauth_states WHERE state_hash = ?1 AND provider = ?2 AND expires_at > ?3",
            params![self.hash_secret(&req.state), req.provider, self.now()],
        )?;
        if consumed != 1 {
            self.why("oauth_callback", &["state_valid"], "invalid_state");
            return Err(AuthError::InvalidState);
        }
        let profile = self.oauth.exchange_code(&req.provider, &req.code).map_err(|_| AuthError::OAuthFailed)?;
        if !profile.email_verified {
            self.why("oauth_callback", &["state_valid", "email_verified"], "email_not_verified");
            return Err(AuthError::ProviderEmailNotVerified);
        }
        let email = profile.email.trim().to_lowercase();
        let linked: Option<i64> = self
            .conn
            .query_row("SELECT user_id FROM oauth_links WHERE provider = ?1 AND provider_user_id = ?2", params![req.provider, profile.provider_user_id], |r| r.get(0))
            .optional()?;
        let user_id = match linked {
            Some(id) => id,
            None => {
                let existing: Option<i64> = self.conn.query_row("SELECT id FROM users WHERE email = ?1", params![email], |r| r.get(0)).optional()?;
                let id = match existing {
                    Some(id) => {
                        self.conn.execute("UPDATE users SET email_verified_at = COALESCE(email_verified_at, ?2), status = CASE WHEN status = 'unverified' THEN 'active' ELSE status END WHERE id = ?1", params![id, self.now()])?;
                        id
                    }
                    None => {
                        self.conn.execute(
                            "INSERT INTO users (email, password_hash, name, status, email_verified_at, created_at) VALUES (?1, NULL, '', 'active', ?2, ?2)",
                            params![email, self.now()],
                        )?;
                        let id = self.conn.last_insert_rowid();
                        self.audit(Some(id), "user_created", Some(id.to_string()), json!({ "email": email, "provider": req.provider }))?;
                        id
                    }
                };
                self.conn.execute("INSERT INTO oauth_links (provider, provider_user_id, user_id) VALUES (?1, ?2, ?3)", params![req.provider, profile.provider_user_id, id])?;
                id
            }
        };
        let (user, status, _) = self.load_user(user_id)?.ok_or(AuthError::OAuthFailed)?;
        if status == "banned" || status == "suspended" {
            return Err(AuthError::UserBanned);
        }
        self.why("oauth_callback", &["state_valid", "email_verified"], "authenticated");
        let data = self.create_session(&user, "", "")?;
        self.audit(Some(user_id), "oauth_login", Some(user_id.to_string()), json!({ "provider": req.provider }))?;
        Ok(AuthResponse { success: true, data })
    }

    /// What: flow 6. Gates: the refresh token matches a live, unexpired session; the user is not banned
    /// or suspended. Out: a new access token. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database.
    /// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
    pub fn token_refresh(&mut self, req: TokenRefreshRequest) -> Result<AuthResponse, AuthError> {
        let row: Option<(i64, i64)> = self
            .conn
            .query_row(
                "SELECT user_id, expires_at FROM sessions WHERE refresh_token_hash = ?1 AND revoked_at IS NULL",
                params![self.hash_secret(req.refresh_token.trim())],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (user_id, expires_at) = row.ok_or(AuthError::InvalidToken)?;
        if self.now() >= expires_at {
            return Err(AuthError::TokenExpired);
        }
        let (user, status, _) = self.load_user(user_id)?.ok_or(AuthError::InvalidToken)?;
        if status == "banned" || status == "suspended" {
            self.why("token_refresh", &["token_valid", "user_active"], "user_banned");
            return Err(AuthError::UserBanned);
        }
        self.why("token_refresh", &["token_valid", "user_active"], "ok");
        self.audit(Some(user_id), "token_refreshed", Some(user_id.to_string()), json!({}))?;
        Ok(AuthResponse { success: true, data: AuthData::Refreshed { token: self.issue_access_token(&user), expires_in: ACCESS_TOKEN_SECS } })
    }

    /// What: flow 7. Recompute HS256 over header.payload with the FIXED algorithm and compare in
    /// constant time; refuse a header whose alg is not HS256 (so "none" and others never pass); check
    /// expiry and that the user exists and is active. Out: the user. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
    pub fn verify_access_token(&mut self, req: VerifyAccessTokenRequest) -> Result<AuthResponse, AuthError> {
        let parts: Vec<&str> = req.token.trim().split('.').collect();
        let [h, p, s] = parts[..] else { return Err(AuthError::InvalidToken) };
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.jwt_secret).expect("HMAC accepts any key length");
        mac.update(format!("{}.{}", h, p).as_bytes());
        let expected = mac.finalize().into_bytes();
        let given = URL_SAFE_NO_PAD.decode(s).map_err(|_| AuthError::InvalidToken)?;
        if !ct_eq(&expected, &given) {
            return Err(AuthError::InvalidToken);
        }
        let header: Value = URL_SAFE_NO_PAD.decode(h).ok().and_then(|b| serde_json::from_slice(&b).ok()).ok_or(AuthError::InvalidToken)?;
        if header["alg"] != "HS256" {
            return Err(AuthError::InvalidToken);
        }
        let claims: Value = URL_SAFE_NO_PAD.decode(p).ok().and_then(|b| serde_json::from_slice(&b).ok()).ok_or(AuthError::InvalidToken)?;
        if claims["typ"] != "access" {
            return Err(AuthError::InvalidToken);
        }
        let exp = claims["exp"].as_i64().ok_or(AuthError::InvalidToken)?;
        if self.now() >= exp {
            return Err(AuthError::TokenExpired);
        }
        let user_id = claims["sub"].as_i64().ok_or(AuthError::InvalidToken)?;
        let (user, status, _) = self.load_user(user_id)?.ok_or(AuthError::InvalidToken)?;
        if status == "banned" || status == "suspended" {
            return Err(AuthError::UserBanned);
        }
        self.why("verify_access_token", &["signature_valid", "not_expired", "user_active"], "ok");
        Ok(AuthResponse { success: true, data: AuthData::TokenValid { user } })
    }

    /// What: set a user's status (active, suspended, banned), as the admin system does. Sessions are
    /// kept so a banned user's refresh is answered "user_banned"; every flow checks the status.
    /// Reactivating restores them. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub fn set_user_status(&mut self, actor_id: i64, user_id: i64, status: &str) -> Result<(), AuthError> {
        if !["active", "suspended", "banned"].contains(&status) {
            return Err(AuthError::InvalidInput("status".into()));
        }
        let old: Option<String> = self.conn.query_row("SELECT status FROM users WHERE id = ?1", params![user_id], |r| r.get(0)).optional()?;
        let old = old.ok_or(AuthError::InvalidInput("user".into()))?;
        self.conn.execute("UPDATE users SET status = ?2 WHERE id = ?1", params![user_id, status])?;
        self.conn.execute(
            "INSERT INTO audit_log (timestamp, actor_id, action, resource_type, resource_id, old_value, new_value) VALUES (?1, ?2, 'user_status_changed', 'user', ?3, ?4, ?5)",
            params![self.now(), actor_id, user_id.to_string(), json!({ "status": old }).to_string(), json!({ "status": status }).to_string()],
        )?;
        Ok(())
    }
}

//! API keys and service accounts: scoped, rate-limited, rotatable keys (TIER 2 spec, system 5).
//!
//! What: `Database` issues keys `sk_live_<43 random chars>` shown once; only a bcrypt hash and a short
//! public lookup slice are stored. `use_api_key` finds the row by the lookup slice, bcrypt-verifies the
//! whole key, then checks that the key is active (not revoked, not expired, rotation grace not over),
//! that its scopes cover the endpoint (`GET /api/<resource>` needs `read:<resource>`, other methods
//! `write:<resource>`, `*` covers all), and its hourly limit (a sliding hour, so no bucket-boundary
//! burst); every call is logged in `api_key_usage`. Keys can be listed (never the secret), revoked,
//! rotated (old key keeps working 24 hours), and reported on.
//! Why: the old file needed live Postgres and Redis servers, kept every struct private so no test could
//! name it, and ended in a `main`. Rewritten on SQLite, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: the SQLite database it owns; the clock; OS randomness. No network, no money.

use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use uuid::Uuid;

/// Prefix of production keys (spec key format).
pub const KEY_PREFIX: &str = "sk_live_";
/// Characters of the random part used as the public lookup id.
const LOOKUP_LEN: usize = 12;
/// How long a rotated key keeps working (spec: 24 hours).
pub const ROTATION_GRACE_HOURS: i64 = 24;

/// What: API key errors; their text is what callers show (and what the tests check).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiKeyError {
    /// 401: no key matches.
    InvalidKey,
    /// 401: revoked, expired or past its rotation grace period.
    NotActive,
    /// 403: the key's scopes do not cover the endpoint.
    Forbidden(String),
    /// 429: the hourly limit is used up.
    RateLimited,
    /// 404: no such key for this user.
    NotFound,
    /// 400: bad input.
    Invalid(String),
    /// 500.
    Db(String),
}

/// What: methods of `ApiKeyError`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl ApiKeyError {
    /// What: the HTTP status for the error. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn status(&self) -> u16 {
        match self {
            ApiKeyError::InvalidKey | ApiKeyError::NotActive => 401,
            ApiKeyError::Forbidden(_) => 403,
            ApiKeyError::RateLimited => 429,
            ApiKeyError::NotFound => 404,
            ApiKeyError::Invalid(_) => 400,
            ApiKeyError::Db(_) => 500,
        }
    }
}

/// What: `fmt::Display` for `ApiKeyError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl fmt::Display for ApiKeyError {
    /// What: human-readable text of `fmt::Display for ApiKeyError` (never secrets). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiKeyError::InvalidKey => write!(f, "Invalid API key"),
            ApiKeyError::NotActive => write!(f, "API key is not active"),
            ApiKeyError::Forbidden(scope) => write!(f, "API key does not have permission: requires {}", scope),
            ApiKeyError::RateLimited => write!(f, "Rate limit exceeded"),
            ApiKeyError::NotFound => write!(f, "API key not found"),
            ApiKeyError::Invalid(m) => write!(f, "Invalid request: {}", m),
            ApiKeyError::Db(_) => write!(f, "Internal error"),
        }
    }
}

/// What: `std::error::Error` for `ApiKeyError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl std::error::Error for ApiKeyError {}

/// What: `From<rusqlite::Error>` for `ApiKeyError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl From<rusqlite::Error> for ApiKeyError {
    /// What: convert the error of `From<rusqlite::Error> for ApiKeyError`, keeping its message for logs. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn from(e: rusqlite::Error) -> Self {
        ApiKeyError::Db(e.to_string())
    }
}

/// What: spec endpoint 1 request. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub scopes: Vec<String>,
    /// RFC 3339 time, or `YYYY-MM-DD` (end of that day, UTC).
    pub expires_at: Option<String>,
    /// Requests per hour.
    pub rate_limit: i32,
}

/// What: spec endpoint 1 response; `key` is shown only here. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApiKeyResponse {
    pub api_key_id: String,
    pub key: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub rate_limit: i32,
}

/// What: a key as listed (never its secret or hash). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
    pub rate_limit: i32,
    pub is_active: bool,
}

/// What: spec endpoint 2 response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListApiKeysResponse {
    pub keys: Vec<ApiKeyInfo>,
}

/// What: spec endpoint 3 response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeApiKeyResponse {
    pub success: bool,
    pub revoked_at: String,
}

/// What: spec endpoint 4 response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateApiKeyResponse {
    pub new_api_key_id: String,
    pub new_key: String,
    pub old_key_revoked_at: String,
    pub grace_period_ends_at: String,
}

/// What: spec endpoint 6 response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageStatsResponse {
    pub api_key_id: String,
    pub total_requests: i64,
    pub requests_by_endpoint: HashMap<String, i64>,
    pub rate_limit_hits: i64,
    pub errors: HashMap<String, i64>,
}

/// What: spec endpoint 7 response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminListApiKeysResponse {
    pub keys: Vec<ApiKeyInfo>,
    pub total: i64,
}

/// What: the authenticated key, as `use_api_key` returns it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizedKey {
    pub api_key_id: Uuid,
    pub user_id: Uuid,
    pub scopes: Vec<String>,
}

/// What: the key store and checker. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
pub struct Database {
    conn: Mutex<Connection>,
    bcrypt_cost: u32,
    clock: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>,
}

/// What: time as stored. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// What: parse an RFC 3339 time, or a `YYYY-MM-DD` date as the end of that day UTC.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(t) = DateTime::parse_from_rfc3339(s.trim()) {
        return Some(t.with_timezone(&Utc));
    }
    chrono::NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d").ok().and_then(|d| d.and_hms_opt(23, 59, 59)).map(|t| t.and_utc())
}

/// What: the scope an endpoint needs: `GET /api/<resource>...` -> `read:<resource>`, other methods
/// `write:<resource>`; `None` for paths outside `/api/` (denied). 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn required_scope(endpoint: &str, method: &str) -> Option<String> {
    let resource = endpoint.strip_prefix("/api/")?.split(|c| c == '/' || c == '?').next()?;
    if resource.is_empty() || !resource.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return None;
    }
    let verb = if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") { "read" } else { "write" };
    Some(format!("{}:{}", verb, resource))
}

/// What: methods of `Database`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl Database {
    /// What: a store on a connection with bcrypt's default cost (production). Creates the tables.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (DDL).
    pub fn new(conn: Connection) -> Result<Self, ApiKeyError> {
        Self::with_cost(conn, DEFAULT_COST)
    }

    /// What: a store on a private in-memory database with bcrypt cost 4 (the minimum), because debug
    /// builds hash slowly; for tests and demos only. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: memory.
    pub async fn new_in_memory() -> Result<Self, ApiKeyError> {
        Self::with_cost(Connection::open_in_memory()?, 4)
    }

    /// What: a store with an explicit bcrypt cost (4-31). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (DDL).
    pub fn with_cost(conn: Connection, bcrypt_cost: u32) -> Result<Self, ApiKeyError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS api_keys (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL,
                key_lookup TEXT NOT NULL, key_secret_hash TEXT NOT NULL, scopes TEXT NOT NULL, rate_limit INTEGER NOT NULL,
                expires_at TEXT NULL, created_at TEXT NOT NULL, last_used_at TEXT NULL, is_active INTEGER NOT NULL,
                revoked_at TEXT NULL, grace_ends_at TEXT NULL, seq INTEGER NOT NULL);
             CREATE INDEX IF NOT EXISTS api_keys_lookup ON api_keys (key_lookup);
             CREATE TABLE IF NOT EXISTS api_key_usage (id INTEGER PRIMARY KEY AUTOINCREMENT, api_key_id TEXT NOT NULL,
                endpoint TEXT NOT NULL, method TEXT NOT NULL, status INTEGER NOT NULL, timestamp TEXT NOT NULL);
             CREATE INDEX IF NOT EXISTS api_key_usage_key ON api_key_usage (api_key_id, timestamp);",
        )?;
        Ok(Self { conn: Mutex::new(conn), bcrypt_cost, clock: Box::new(Utc::now) })
    }

    /// What: replace the clock (for expiry and rotation tests). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// What: the connection. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What: insert a new key row and return (id, plaintext key). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, OS randomness, bcrypt.
    fn insert_key(&self, user_id: Uuid, name: &str, scopes: &[String], rate_limit: i32, expires_at: Option<DateTime<Utc>>) -> Result<(Uuid, String, DateTime<Utc>), ApiKeyError> {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let random: String = base64_url(&secret);
        let key = format!("{}{}", KEY_PREFIX, random);
        let lookup = random[..LOOKUP_LEN].to_string();
        let key_hash = hash(&key, self.bcrypt_cost).map_err(|e| ApiKeyError::Db(e.to_string()))?;
        let id = Uuid::new_v4();
        let now = (self.clock)();
        let conn = self.conn();
        conn.execute(
            "INSERT INTO api_keys (id, user_id, name, key_lookup, key_secret_hash, scopes, rate_limit, expires_at, created_at, is_active, seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, (SELECT COALESCE(MAX(seq), 0) + 1 FROM api_keys))",
            params![id.to_string(), user_id.to_string(), name, lookup, key_hash, serde_json::to_string(scopes).unwrap_or_default(),
                rate_limit, expires_at.map(ts), ts(now)],
        )?;
        Ok((id, key, now))
    }

    /// What: create a key for the authenticated user (spec endpoint 1). Scopes must be `*` or
    /// `<verb>:<resource>`; rate limit 1-1,000,000 per hour. Out: the key, shown once.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub async fn create_api_key(&self, user_id: Uuid, req: CreateApiKeyRequest) -> Result<CreateApiKeyResponse, ApiKeyError> {
        let name = req.name.trim();
        if name.is_empty() || name.len() > 100 {
            return Err(ApiKeyError::Invalid("name".into()));
        }
        if req.scopes.is_empty() || req.scopes.iter().any(|s| s != "*" && !s.split_once(':').map(|(a, b)| !a.is_empty() && !b.is_empty()).unwrap_or(false)) {
            return Err(ApiKeyError::Invalid("scopes".into()));
        }
        if !(1..=1_000_000).contains(&req.rate_limit) {
            return Err(ApiKeyError::Invalid("rate_limit".into()));
        }
        let expires = match &req.expires_at {
            Some(s) => Some(parse_time(s).ok_or_else(|| ApiKeyError::Invalid("expires_at".into()))?),
            None => None,
        };
        let (id, key, created) = self.insert_key(user_id, name, &req.scopes, req.rate_limit, expires)?;
        Ok(CreateApiKeyResponse { api_key_id: id.to_string(), key, created_at: ts(created), expires_at: expires.map(ts), rate_limit: req.rate_limit })
    }

    /// What: map a key row to its listing. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn info_row(&self, r: &rusqlite::Row) -> rusqlite::Result<ApiKeyInfo> {
        let scopes: String = r.get("scopes")?;
        let id: String = r.get("id")?;
        let user: String = r.get("user_id")?;
        let active = r.get::<_, i64>("is_active")? != 0;
        let expires: Option<String> = r.get("expires_at")?;
        let grace: Option<String> = r.get("grace_ends_at")?;
        let now = (self.clock)();
        let live = active
            && expires.as_deref().and_then(parse_time).map(|t| now < t).unwrap_or(true)
            && grace.as_deref().and_then(parse_time).map(|t| now < t).unwrap_or(true);
        Ok(ApiKeyInfo {
            id: Uuid::parse_str(&id).unwrap_or_default(),
            user_id: Uuid::parse_str(&user).unwrap_or_default(),
            name: r.get("name")?,
            scopes: serde_json::from_str(&scopes).unwrap_or_default(),
            created_at: r.get("created_at")?,
            last_used_at: r.get("last_used_at")?,
            expires_at: expires,
            rate_limit: r.get("rate_limit")?,
            is_active: live,
        })
    }

    /// What: the user's keys, masked (spec endpoint 2). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (read).
    pub async fn list_api_keys(&self, user_id: Uuid) -> Result<ListApiKeysResponse, ApiKeyError> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT * FROM api_keys WHERE user_id = ?1 ORDER BY seq")?;
        let keys = stmt.query_map(params![user_id.to_string()], |r| self.info_row(r))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(ListApiKeysResponse { keys })
    }

    /// What: revoke one of the user's keys at once (spec endpoint 3); another user's key is "not found".
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub async fn revoke_api_key(&self, api_key_id: Uuid, user_id: Uuid) -> Result<RevokeApiKeyResponse, ApiKeyError> {
        let now = ts((self.clock)());
        let n = self.conn().execute(
            "UPDATE api_keys SET is_active = 0, revoked_at = COALESCE(revoked_at, ?3) WHERE id = ?1 AND user_id = ?2",
            params![api_key_id.to_string(), user_id.to_string(), now],
        )?;
        if n == 0 {
            return Err(ApiKeyError::NotFound);
        }
        Ok(RevokeApiKeyResponse { success: true, revoked_at: now })
    }

    /// What: rotate one of the user's live keys (spec endpoint 4): a new key with the same name, scopes
    /// and limit; the old key keeps working for 24 hours, then stops. Out: the new key (shown once).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub async fn rotate_api_key(&self, api_key_id: Uuid, user_id: Uuid) -> Result<RotateApiKeyResponse, ApiKeyError> {
        let old = {
            let conn = self.conn();
            conn.query_row("SELECT * FROM api_keys WHERE id = ?1 AND user_id = ?2", params![api_key_id.to_string(), user_id.to_string()], |r| self.info_row(r))
                .optional()?
                .ok_or(ApiKeyError::NotFound)?
        };
        if !old.is_active {
            return Err(ApiKeyError::NotActive);
        }
        let expires = old.expires_at.as_deref().and_then(parse_time);
        let (new_id, new_key, now) = self.insert_key(user_id, &old.name, &old.scopes, old.rate_limit, expires)?;
        let grace = now + Duration::hours(ROTATION_GRACE_HOURS);
        self.conn().execute(
            "UPDATE api_keys SET revoked_at = ?2, grace_ends_at = ?3 WHERE id = ?1",
            params![api_key_id.to_string(), ts(now), ts(grace)],
        )?;
        Ok(RotateApiKeyResponse { new_api_key_id: new_id.to_string(), new_key, old_key_revoked_at: ts(now), grace_period_ends_at: ts(grace) })
    }

    /// What: log one use of a key. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn log_usage(conn: &Connection, key_id: &str, endpoint: &str, method: &str, status: u16, now: DateTime<Utc>) -> Result<(), ApiKeyError> {
        conn.execute(
            "INSERT INTO api_key_usage (api_key_id, endpoint, method, status, timestamp) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![key_id, endpoint, method.to_ascii_uppercase(), status, ts(now)],
        )?;
        Ok(())
    }

    /// What: authenticate and authorize one request (spec endpoint 5). In: the bearer key, endpoint,
    /// method. Out: the key's identity, or `InvalidKey`/`NotActive` (401), `Forbidden` (403),
    /// `RateLimited` (429). Every call on a known key is logged with its status.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, bcrypt.
    pub async fn use_api_key(&self, key: &str, endpoint: &str, method: &str) -> Result<AuthorizedKey, ApiKeyError> {
        let key = key.trim().strip_prefix("Bearer ").unwrap_or(key.trim());
        let random = key.strip_prefix(KEY_PREFIX).ok_or(ApiKeyError::InvalidKey)?;
        if random.len() < LOOKUP_LEN || !random.is_char_boundary(LOOKUP_LEN) {
            return Err(ApiKeyError::InvalidKey);
        }
        let candidates: Vec<(String, String)> = {
            let conn = self.conn();
            let mut stmt = conn.prepare("SELECT id, key_secret_hash FROM api_keys WHERE key_lookup = ?1")?;
            let rows = stmt.query_map(params![&random[..LOOKUP_LEN]], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        // bcrypt's verify compares in constant time
        let key_id = candidates.into_iter().find(|(_, h)| verify(key, h).unwrap_or(false)).map(|(id, _)| id).ok_or(ApiKeyError::InvalidKey)?;
        let now = (self.clock)();
        let conn = self.conn();
        let info = conn.query_row("SELECT * FROM api_keys WHERE id = ?1", params![key_id], |r| self.info_row(r))?;
        if !info.is_active {
            Self::log_usage(&conn, &key_id, endpoint, method, 401, now)?;
            return Err(ApiKeyError::NotActive);
        }
        let needed = required_scope(endpoint, method);
        let allowed = info.scopes.iter().any(|s| s == "*") || needed.as_ref().map(|n| info.scopes.contains(n)).unwrap_or(false);
        if !allowed {
            Self::log_usage(&conn, &key_id, endpoint, method, 403, now)?;
            return Err(ApiKeyError::Forbidden(needed.unwrap_or_else(|| "an /api/ endpoint".into())));
        }
        let used: i64 = conn.query_row(
            "SELECT COUNT(*) FROM api_key_usage WHERE api_key_id = ?1 AND status < 400 AND timestamp > ?2",
            params![key_id, ts(now - Duration::hours(1))],
            |r| r.get(0),
        )?;
        if used >= info.rate_limit as i64 {
            Self::log_usage(&conn, &key_id, endpoint, method, 429, now)?;
            return Err(ApiKeyError::RateLimited);
        }
        Self::log_usage(&conn, &key_id, endpoint, method, 200, now)?;
        conn.execute("UPDATE api_keys SET last_used_at = ?2 WHERE id = ?1", params![key_id, ts(now)])?;
        Ok(AuthorizedKey { api_key_id: info.id, user_id: info.user_id, scopes: info.scopes })
    }

    /// What: usage of one of the user's keys between two times (spec endpoint 6): total, per
    /// "METHOD endpoint", rate-limit hits and error statuses. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (read).
    pub async fn get_usage_stats(&self, api_key_id: Uuid, user_id: Uuid, from: &str, to: &str) -> Result<UsageStatsResponse, ApiKeyError> {
        let from = parse_time(from).ok_or_else(|| ApiKeyError::Invalid("from".into()))?;
        let to = parse_time(to).ok_or_else(|| ApiKeyError::Invalid("to".into()))?;
        let conn = self.conn();
        let owned: i64 = conn.query_row(
            "SELECT COUNT(*) FROM api_keys WHERE id = ?1 AND user_id = ?2",
            params![api_key_id.to_string(), user_id.to_string()],
            |r| r.get(0),
        )?;
        if owned == 0 {
            return Err(ApiKeyError::NotFound);
        }
        let mut stmt = conn.prepare(
            "SELECT method, endpoint, status, COUNT(*) FROM api_key_usage WHERE api_key_id = ?1 AND timestamp >= ?2 AND timestamp <= ?3
             GROUP BY method, endpoint, status",
        )?;
        let rows = stmt
            .query_map(params![api_key_id.to_string(), ts(from), ts(to)], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut stats = UsageStatsResponse { api_key_id: api_key_id.to_string(), total_requests: 0, requests_by_endpoint: HashMap::new(), rate_limit_hits: 0, errors: HashMap::new() };
        for (method, endpoint, status, n) in rows {
            stats.total_requests += n;
            *stats.requests_by_endpoint.entry(format!("{} {}", method, endpoint)).or_insert(0) += n;
            if status == 429 {
                stats.rate_limit_hits += n;
            }
            if status >= 400 {
                *stats.errors.entry(status.to_string()).or_insert(0) += n;
            }
        }
        Ok(stats)
    }

    /// What: every key, optionally by user and status "active"/"inactive" (spec endpoint 7). The
    /// caller must already have checked the actor is an admin. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
    pub async fn admin_list_api_keys(&self, user_id: Option<Uuid>, status: Option<String>) -> Result<AdminListApiKeysResponse, ApiKeyError> {
        let want = match status.as_deref() {
            None => None,
            Some("active") => Some(true),
            Some("inactive") => Some(false),
            Some(other) => return Err(ApiKeyError::Invalid(format!("status {}", other))),
        };
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT * FROM api_keys WHERE (?1 IS NULL OR user_id = ?1) ORDER BY seq")?;
        let keys: Vec<ApiKeyInfo> = stmt
            .query_map(params![user_id.map(|u| u.to_string())], |r| self.info_row(r))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .filter(|k| want.map(|w| k.is_active == w).unwrap_or(true))
            .collect();
        Ok(AdminListApiKeysResponse { total: keys.len() as i64, keys })
    }
}

/// What: URL-safe base64 without padding (43 chars for 32 bytes). 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn base64_url(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, b)| acc | (*b as u32) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

//! Audit logging: an append-only event log with replay, and personal data kept beside it so it can be
//! erased (TIER 2 spec, system: audit_logging).
//!
//! What: `AuditLogger` writes each mutation as an event row in `audit_log` (append-only: UPDATE and DELETE
//! are refused by triggers). Anything that leads back to a person lives in `audit_personal`, under a random
//! `subject_ref` from `audit_subjects`: the acting user's id, IP, user agent and request id (role 'actor'),
//! and for an entry about a user, its resource id, old/new values and why-chain id (role 'subject').
//! `erase_subject(user)` and `apply_retention(now)` delete personal and subject rows only; the events stay.
//! Reads (query, replay, search) are admin-only, and show `personal_erased: true` once an entry's personal
//! rows are gone.
//! Why: rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, for the AUDIT-08/09/10 amendment (after review
//! on PR 19 and an independent security review): the old log kept actor ids, IPs (in metadata) and
//! snapshots in the immutable table, so a user could never be erased without rewriting it; anyone could read
//! it; and the action wildcard did not escape `_`.
//! Touches: the SQLite database it is given (in memory for tests); the clock; OS randomness (ids and
//! subject refs). No network, no money.

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use rusqlite::{params, Connection, OptionalExtension, Result as RusqliteResult, Row};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::fmt;
use std::sync::{Mutex, MutexGuard};
use uuid::Uuid;

/// The only metadata keys log() accepts (anything else could carry personal data past erasure).
pub const ALLOWED_METADATA_KEYS: [&str; 2] = ["feature_flag", "erased_rows"];
/// Default retention period for personal data, in days (configure per purpose and legal obligation).
pub const DEFAULT_RETENTION_DAYS: i64 = 365;

/// What: audit errors with the spec's codes: `BadRequest(code)` is 400 (subject_required,
/// subject_mismatch, metadata_key_not_allowed, actor_user_required, ...), `Forbidden` 403 (a read by a
/// non-admin), `NotFound` 404, `Db` 500. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-10).
/// Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    BadRequest(&'static str),
    Forbidden,
    NotFound,
    Db(String),
}

/// What: methods of `AuditError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl AuditError {
    /// What: the HTTP status. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn status(&self) -> u16 {
        match self {
            AuditError::BadRequest(_) => 400,
            AuditError::Forbidden => 403,
            AuditError::NotFound => 404,
            AuditError::Db(_) => 500,
        }
    }

    /// What: the error code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn code(&self) -> &'static str {
        match self {
            AuditError::BadRequest(c) => c,
            AuditError::Forbidden => "admin_only",
            AuditError::NotFound => "not_found",
            AuditError::Db(_) => "internal_error",
        }
    }

    /// What: the `{error, code}` body and status. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn to_response(&self) -> (Value, u16) {
        (json!({ "error": self.code(), "code": self.status() }), self.status())
    }
}

/// What: `fmt::Display` for `AuditError` (never the database message's data). 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
impl fmt::Display for AuditError {
    /// What: the code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code())
    }
}

/// What: `std::error::Error` for `AuditError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl std::error::Error for AuditError {}

/// What: `From<rusqlite::Error>` for `AuditError` (no row is `NotFound`). 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
impl From<rusqlite::Error> for AuditError {
    /// What: convert. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn from(e: rusqlite::Error) -> Self {
        match e {
            rusqlite::Error::QueryReturnedNoRows => AuditError::NotFound,
            other => AuditError::Db(other.to_string()),
        }
    }
}

/// What: the verified caller of a read, built by the server from the authenticated session (never from
/// request input). Reads are admin-only. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-10).
/// Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub id: String,
    pub is_admin: bool,
}

/// What: constructors of `Caller`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl Caller {
    /// What: an admin caller. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn admin(id: &str) -> Self {
        Self { id: id.to_string(), is_admin: true }
    }
    /// What: a caller without the admin role. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn user(id: &str) -> Self {
        Self { id: id.to_string(), is_admin: false }
    }
}

/// What: one entry as reads return it. Personal fields (actor_id, ip, user_agent, request_id, and for an
/// entry about a user resource_id, old_value, new_value, why_chain_id) come from `audit_personal`; once
/// those rows are erased they are null and `personal_erased` is true. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub timestamp: String,
    pub actor_id: Option<String>,
    pub actor_type: String,
    pub actor_service: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub old_value: Value,
    pub new_value: Value,
    pub why_chain_id: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub personal_roles: String,
    pub personal_erased: bool,
    pub metadata: Value,
}

/// What: the log request. `actor_id` is the authenticated caller's (never taken from a client body when
/// an end user is the actor); `actor_user_id` is the owner of an API key (required for 'api_key');
/// `actor_service` names a service actor; `subject_user_id` is the user the entry is about, or "none"
/// (required unless resource_type is 'user', where the subject is the resource id); ip, user_agent and
/// request_id are the actor's request details, stored as personal data. Changed 2026-11-10 (AUDIT-08/10).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogMutationRequest {
    pub actor_id: Option<String>,
    pub actor_type: String,
    pub actor_service: Option<String>,
    pub actor_user_id: Option<String>,
    pub subject_user_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub old_value: Value,
    pub new_value: Value,
    pub why_chain_id: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub metadata: Option<Value>,
}

/// What: log response `{success, log_id}`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogMutationResponse {
    pub success: bool,
    pub log_id: String,
}

/// What: query filters; `action` may end in or contain `*` (wildcard). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Default)]
pub struct QueryLogsParams {
    pub actor_id: Option<String>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub date_from: Option<String>,
    pub date_to: Option<String>,
}

/// What: query response `{logs, total, has_more}`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLogsResponse {
    pub logs: Vec<AuditLogEntry>,
    pub total: usize,
    pub has_more: bool,
}

/// What: replay response. For an entry whose subject rows were erased: `erased: true`,
/// `resource_state_at_time: null`, `has_diverged: null`. Changed 2026-11-10 (AUDIT-08).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResponse {
    pub log_id: String,
    pub timestamp: String,
    pub erased: bool,
    pub resource_state_at_time: Value,
    pub has_diverged: Option<bool>,
}

/// What: search response `{results}`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResponse {
    pub results: Vec<AuditLogEntry>,
}

/// What: erase / retention result `{erased_rows}` (audit_personal rows deleted). 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EraseResponse {
    pub erased_rows: usize,
}

/// The columns of `audit_log` that reads select, in `map_row` order (alias `l`).
const LOG_COLUMNS: &str = "l.id, l.timestamp, l.actor_type, l.actor_service, l.action, l.resource_type, l.resource_id,
    l.old_value, l.new_value, l.why_chain_id, l.personal_roles, l.metadata";

/// What: the audit logger. `conn` is public so operators and tests can inspect the tables (the triggers
/// still refuse UPDATE/DELETE on events). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: the database, the clock.
pub struct AuditLogger {
    pub conn: Mutex<Connection>,
    clock: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>,
    retention_days: i64,
}

/// What: a time as stored (RFC 3339, UTC, milliseconds, `Z`; fixed width so text order is time order).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// What: a SQL LIKE pattern for an action filter: `*` is the wildcard, and `%`, `_` and `\` in the rest are
/// literal (escaped with `\`). In: the filter. Out: the pattern. Why: AUDIT-07; the old pattern let `_`
/// match any character. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn like_pattern(filter: &str) -> String {
    let mut out = String::with_capacity(filter.len() + 4);
    for c in filter.chars() {
        match c {
            '*' => out.push('%'),
            '%' | '_' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            other => out.push(other),
        }
    }
    out
}

/// What: methods of `AuditLogger`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl AuditLogger {
    /// What: a logger on a connection with the system clock and the default retention. Call `init_db`.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing yet.
    pub fn new(conn: Connection) -> Self {
        Self { conn: Mutex::new(conn), clock: Box::new(Utc::now), retention_days: DEFAULT_RETENTION_DAYS }
    }

    /// What: replace the clock (timestamps and retention tests). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// What: set the retention period for personal data, in days. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-09).
    pub fn with_retention_days(mut self, days: i64) -> Self {
        self.retention_days = days;
        self
    }

    /// What: the connection, even after another thread panicked holding it. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn db(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What: create the three tables, their indexes, and the triggers that refuse UPDATE and DELETE on
    /// `audit_log` and UPDATE on `audit_personal`; turn on foreign keys. Out: `()` or a SQLite error.
    /// Why: spec schema as amended 2026-11-10 (AUDIT-08). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (DDL).
    pub fn init_db(&self) -> RusqliteResult<()> {
        self.db().execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'service', 'api_key')),
                actor_service TEXT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NULL,
                old_value TEXT NULL,
                new_value TEXT NULL,
                why_chain_id TEXT NULL,
                personal_roles TEXT NOT NULL,
                metadata TEXT NOT NULL);
             CREATE INDEX IF NOT EXISTS idx_audit_log_query ON audit_log (action, resource_type, timestamp);
             CREATE TABLE IF NOT EXISTS audit_subjects (
                subject_ref TEXT PRIMARY KEY,
                user_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS audit_personal (
                log_id TEXT NOT NULL REFERENCES audit_log (id),
                subject_ref TEXT NOT NULL REFERENCES audit_subjects (subject_ref),
                role TEXT NOT NULL CHECK (role IN ('actor', 'subject')),
                data TEXT NOT NULL,
                PRIMARY KEY (log_id, role));
             CREATE INDEX IF NOT EXISTS idx_audit_personal_subject ON audit_personal (subject_ref, role);
             CREATE TRIGGER IF NOT EXISTS audit_log_prevent_update BEFORE UPDATE ON audit_log
             BEGIN SELECT RAISE(FAIL, 'Audit logs are immutable and cannot be updated'); END;
             CREATE TRIGGER IF NOT EXISTS audit_log_prevent_delete BEFORE DELETE ON audit_log
             BEGIN SELECT RAISE(FAIL, 'Audit logs are immutable and cannot be deleted'); END;
             CREATE TRIGGER IF NOT EXISTS audit_personal_prevent_update BEFORE UPDATE ON audit_personal
             BEGIN SELECT RAISE(FAIL, 'Audit personal rows are never updated'); END;",
        )
    }

    /// What: the subject_ref of a user, created (random 128 bits, never derived from the id) the first
    /// time the user appears; insert-if-absent on user_id. In: the transaction, user id, now.
    /// Out: the subject_ref. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn subject_ref(tx: &Connection, user_id: &str, now: &str) -> RusqliteResult<String> {
        tx.execute(
            "INSERT INTO audit_subjects (subject_ref, user_id, created_at) VALUES (?1, ?2, ?3) ON CONFLICT (user_id) DO NOTHING",
            params![Uuid::new_v4().simple().to_string(), user_id, now],
        )?;
        tx.query_row("SELECT subject_ref FROM audit_subjects WHERE user_id = ?1", params![user_id], |r| r.get(0))
    }

    /// What: log one mutation (call it BEFORE commit). Checks, each a 400: actor_type must be user,
    /// service or api_key (invalid_actor_type); metadata may hold only feature_flag and erased_rows
    /// (metadata_key_not_allowed); for resource_type 'user' the subject is the resource id and a different
    /// subject_user_id is subject_mismatch, for any other resource_type subject_user_id (a user id or
    /// "none") is required (subject_required); a 'user' actor needs actor_id (actor_required), an
    /// 'api_key' actor needs actor_user_id (actor_user_required), a 'service' actor needs actor_service
    /// (actor_service_required; changed 2026-11-10, Phase B.2: actor_id no longer stands in for it, as the
    /// spec's refusal list now says). Then, in ONE transaction: the subjects are found or created,
    /// the event row is inserted (resource_id, old/new values and why_chain_id only when the subject is
    /// "none"), and its 'actor' row ({actor_id, ip, user_agent, request_id}) and 'subject' row
    /// ({resource_id, old_value, new_value, why_chain_id}) go to audit_personal.
    /// In: the request. Out: `{success, log_id}` or an `AuditError`.
    /// Why: spec endpoint 1 as amended 2026-11-10 (AUDIT-08/10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database, clock, OS randomness.
    pub fn log_mutation(&self, req: LogMutationRequest) -> Result<LogMutationResponse, AuditError> {
        if !["user", "service", "api_key"].contains(&req.actor_type.as_str()) {
            return Err(AuditError::BadRequest("invalid_actor_type"));
        }
        let metadata = match req.metadata {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(m)) => m,
            Some(_) => return Err(AuditError::BadRequest("metadata_key_not_allowed")),
        };
        if metadata.keys().any(|k| !ALLOWED_METADATA_KEYS.contains(&k.as_str())) {
            return Err(AuditError::BadRequest("metadata_key_not_allowed"));
        }
        let subject: Option<String> = if req.resource_type == "user" {
            if let Some(s) = &req.subject_user_id {
                if *s != req.resource_id {
                    return Err(AuditError::BadRequest("subject_mismatch"));
                }
            }
            Some(req.resource_id.clone())
        } else {
            match req.subject_user_id.as_deref() {
                None | Some("") => return Err(AuditError::BadRequest("subject_required")),
                Some("none") => None,
                Some(u) => Some(u.to_string()),
            }
        };
        let nonempty = |v: &Option<String>| v.as_ref().filter(|s| !s.is_empty()).cloned();
        let (actor_person, actor_service): (Option<String>, Option<String>) = match req.actor_type.as_str() {
            "user" => (Some(nonempty(&req.actor_id).ok_or(AuditError::BadRequest("actor_required"))?), None),
            "api_key" => (Some(nonempty(&req.actor_user_id).ok_or(AuditError::BadRequest("actor_user_required"))?), None),
            _ => (None, Some(nonempty(&req.actor_service).ok_or(AuditError::BadRequest("actor_service_required"))?)),
        };
        let mut roles = Vec::new();
        if actor_person.is_some() {
            roles.push("actor");
        }
        if subject.is_some() {
            roles.push("subject");
        }
        let log_id = Uuid::new_v4().to_string();
        let now = ts((self.clock)());
        let json_text = |v: &Value| v.to_string();
        let mut conn = self.db();
        let tx = conn.transaction()?;
        let (rid, old, new, why) = if subject.is_none() {
            (Some(req.resource_id.clone()), Some(json_text(&req.old_value)), Some(json_text(&req.new_value)), req.why_chain_id.clone())
        } else {
            (None, None, None, None)
        };
        tx.execute(
            "INSERT INTO audit_log (id, timestamp, actor_type, actor_service, action, resource_type, resource_id, old_value, new_value,
                why_chain_id, personal_roles, metadata) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![log_id, now, req.actor_type, actor_service, req.action, req.resource_type, rid, old, new, why, roles.join(","),
                Value::Object(metadata).to_string()],
        )?;
        if let Some(person) = &actor_person {
            let sref = Self::subject_ref(&tx, person, &now)?;
            let data = json!({ "actor_id": req.actor_id, "ip": req.ip, "user_agent": req.user_agent, "request_id": req.request_id });
            tx.execute("INSERT INTO audit_personal (log_id, subject_ref, role, data) VALUES (?1, ?2, 'actor', ?3)", params![log_id, sref, data.to_string()])?;
        }
        if let Some(person) = &subject {
            let sref = Self::subject_ref(&tx, person, &now)?;
            let data = json!({ "resource_id": req.resource_id, "old_value": req.old_value, "new_value": req.new_value, "why_chain_id": req.why_chain_id });
            tx.execute("INSERT INTO audit_personal (log_id, subject_ref, role, data) VALUES (?1, ?2, 'subject', ?3)", params![log_id, sref, data.to_string()])?;
        }
        tx.commit()?;
        Ok(LogMutationResponse { success: true, log_id })
    }

    /// What: refuse a read unless the verified caller is an admin. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-10). Touches: nothing.
    fn require_admin(caller: &Caller) -> Result<(), AuditError> {
        if caller.is_admin { Ok(()) } else { Err(AuditError::Forbidden) }
    }

    /// What: build a read entry from an audit_log row (`LOG_COLUMNS` order) and its personal rows.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
    fn entry(conn: &Connection, row: &Row) -> RusqliteResult<AuditLogEntry> {
        let parse = |s: Option<String>| s.and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
        let id: String = row.get(0)?;
        let roles: String = row.get(10)?;
        let mut e = AuditLogEntry {
            id: id.clone(),
            timestamp: row.get(1)?,
            actor_id: None,
            actor_type: row.get(2)?,
            actor_service: row.get(3)?,
            action: row.get(4)?,
            resource_type: row.get(5)?,
            resource_id: row.get(6)?,
            old_value: parse(row.get(7)?),
            new_value: parse(row.get(8)?),
            why_chain_id: row.get(9)?,
            ip: None,
            user_agent: None,
            request_id: None,
            personal_roles: roles.clone(),
            personal_erased: false,
            metadata: parse(row.get(11)?),
        };
        let text = |v: &Value, k: &str| v.get(k).and_then(|x| x.as_str().map(str::to_string).or_else(|| (!x.is_null()).then(|| x.to_string())));
        for role in roles.split(',').filter(|r| !r.is_empty()) {
            let data: Option<String> = conn
                .query_row("SELECT data FROM audit_personal WHERE log_id = ?1 AND role = ?2", params![id, role], |r| r.get(0))
                .optional()?;
            let Some(data) = data.and_then(|d| serde_json::from_str::<Value>(&d).ok()) else {
                e.personal_erased = true;
                continue;
            };
            if role == "actor" {
                e.actor_id = text(&data, "actor_id");
                e.ip = text(&data, "ip");
                e.user_agent = text(&data, "user_agent");
                e.request_id = text(&data, "request_id");
            } else {
                e.resource_id = text(&data, "resource_id");
                e.old_value = data.get("old_value").cloned().unwrap_or(Value::Null);
                e.new_value = data.get("new_value").cloned().unwrap_or(Value::Null);
                e.why_chain_id = text(&data, "why_chain_id");
            }
        }
        Ok(e)
    }

    /// What: query logs, newest first (ties by insertion), with filters: actor_id (resolved through
    /// audit_subjects and the 'actor' personal rows, so an erased actor matches nothing), action (with
    /// `*` wildcards), resource_type, date range; limit (default 100) and offset. Admin only (403).
    /// In: caller, filters. Out: `{logs, total, has_more}`. Why: spec endpoint 2; actor filter and
    /// admin gate amended 2026-11-10 (AUDIT-08/10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (read).
    pub fn query_logs(&self, caller: &Caller, filter: QueryLogsParams) -> Result<QueryLogsResponse, AuditError> {
        Self::require_admin(caller)?;
        let conn = self.db();
        let mut conditions: Vec<&str> = Vec::new();
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        // With an actor filter the scan starts from the user's few personal rows (CROSS JOIN fixes the
        // order), so it stays fast however large the log is.
        let from = if let Some(actor) = &filter.actor_id {
            args.push(rusqlite::types::Value::Text(actor.clone()));
            "audit_subjects s CROSS JOIN audit_personal p CROSS JOIN audit_log l"
        } else {
            "audit_log l"
        };
        if filter.actor_id.is_some() {
            conditions.push("s.user_id = ? AND p.subject_ref = s.subject_ref AND p.role = 'actor' AND l.id = p.log_id");
        }
        if let Some(action) = &filter.action {
            if action.contains('*') {
                conditions.push("l.action LIKE ? ESCAPE '\\'");
                args.push(rusqlite::types::Value::Text(like_pattern(action)));
            } else {
                conditions.push("l.action = ?");
                args.push(rusqlite::types::Value::Text(action.clone()));
            }
        }
        if let Some(rt) = &filter.resource_type {
            conditions.push("l.resource_type = ?");
            args.push(rusqlite::types::Value::Text(rt.clone()));
        }
        if let Some(d) = &filter.date_from {
            conditions.push("l.timestamp >= ?");
            args.push(rusqlite::types::Value::Text(d.clone()));
        }
        if let Some(d) = &filter.date_to {
            conditions.push("l.timestamp <= ?");
            args.push(rusqlite::types::Value::Text(d.clone()));
        }
        let where_clause = if conditions.is_empty() { String::new() } else { format!("WHERE {}", conditions.join(" AND ")) };
        let total: usize = conn.query_row(
            &format!("SELECT COUNT(*) FROM {} {}", from, where_clause),
            rusqlite::params_from_iter(args.iter()),
            |r| r.get::<_, i64>(0),
        )? as usize;
        let limit = filter.limit.unwrap_or(100);
        let offset = filter.offset.unwrap_or(0);
        let mut page_args = args;
        page_args.push(rusqlite::types::Value::Integer(limit as i64));
        page_args.push(rusqlite::types::Value::Integer(offset as i64));
        let mut stmt = conn.prepare(&format!(
            "SELECT {} FROM {} {} ORDER BY l.timestamp DESC, l.rowid DESC LIMIT ? OFFSET ?",
            LOG_COLUMNS, from, where_clause
        ))?;
        let logs = stmt
            .query_map(rusqlite::params_from_iter(page_args.iter()), |row| Self::entry(&conn, row))?
            .collect::<RusqliteResult<Vec<_>>>()?;
        let has_more = offset + logs.len() < total;
        Ok(QueryLogsResponse { logs, total, has_more })
    }

    /// What: replay an entry: the resource's state at that moment (its old_value) and whether a newer
    /// entry for the same resource left it in a different state. An entry whose subject rows were erased
    /// returns `{erased: true, resource_state_at_time: null, has_diverged: null}`. Admin only (403).
    /// In: caller, log id. Out: `ReplayResponse` or `NotFound`. Why: spec endpoint 3; erasure amended
    /// 2026-11-10 (AUDIT-08). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
    pub fn replay(&self, caller: &Caller, log_id: &str) -> Result<ReplayResponse, AuditError> {
        Self::require_admin(caller)?;
        let conn = self.db();
        let target = conn.query_row(&format!("SELECT {} FROM audit_log l WHERE l.id = ?1", LOG_COLUMNS), params![log_id], |row| Self::entry(&conn, row))?;
        let subject_erased = target.personal_roles.split(',').any(|r| r == "subject")
            && conn.query_row("SELECT COUNT(*) FROM audit_personal WHERE log_id = ?1 AND role = 'subject'", params![log_id], |r| r.get::<_, i64>(0))? == 0;
        if subject_erased {
            return Ok(ReplayResponse { log_id: target.id, timestamp: target.timestamp, erased: true, resource_state_at_time: Value::Null, has_diverged: None });
        }
        let latest: Option<(String, Option<String>)> = conn
            .query_row(
                "SELECT l.id, COALESCE(l.new_value, json_extract(p.data, '$.new_value'))
                 FROM audit_log l LEFT JOIN audit_personal p ON p.log_id = l.id AND p.role = 'subject'
                 WHERE l.resource_type = ?1 AND COALESCE(l.resource_id, json_extract(p.data, '$.resource_id')) = ?2
                 ORDER BY l.timestamp DESC, l.rowid DESC LIMIT 1",
                params![target.resource_type, target.resource_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let has_diverged = match latest {
            Some((id, new_value)) => {
                let new_value: Value = new_value.and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
                id != target.id && new_value != target.new_value
            }
            None => false,
        };
        Ok(ReplayResponse { log_id: target.id, timestamp: target.timestamp, erased: false, resource_state_at_time: target.old_value, has_diverged: Some(has_diverged) })
    }

    /// What: full-text search (substring, case-insensitive for ASCII) over actions, resource types and
    /// the resource fields of entries (an entry's subject data while it is retained), newest first.
    /// Admin only (403). In: caller, query, optional resource type, limit (default 50).
    /// Out: `{results}`. Why: spec endpoint 4; admin gate and erasure amended 2026-11-10 (AUDIT-08/10).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
    pub fn search(&self, caller: &Caller, q: &str, resource_type: Option<&str>, limit: Option<usize>) -> Result<SearchResponse, AuditError> {
        Self::require_admin(caller)?;
        let conn = self.db();
        let literal: String = q.chars().flat_map(|c| if matches!(c, '%' | '_' | '\\') { vec!['\\', c] } else { vec![c] }).collect();
        let pattern = format!("%{}%", literal);
        let mut stmt = conn.prepare(&format!(
            "SELECT {} FROM audit_log l LEFT JOIN audit_personal p ON p.log_id = l.id AND p.role = 'subject'
             WHERE (l.action LIKE ?1 ESCAPE '\\' OR l.resource_type LIKE ?1 ESCAPE '\\' OR l.resource_id LIKE ?1 ESCAPE '\\'
                    OR l.old_value LIKE ?1 ESCAPE '\\' OR l.new_value LIKE ?1 ESCAPE '\\' OR p.data LIKE ?1 ESCAPE '\\')
               AND (?2 IS NULL OR l.resource_type = ?2)
             ORDER BY l.timestamp DESC, l.rowid DESC LIMIT ?3",
            LOG_COLUMNS
        ))?;
        let results = stmt
            .query_map(params![pattern, resource_type, limit.unwrap_or(50) as i64], |row| Self::entry(&conn, row))?
            .collect::<RusqliteResult<Vec<_>>>()?;
        Ok(SearchResponse { results })
    }

    /// What: erase a data subject (statutory erasure, or account deletion in data_export_compliance): in
    /// one transaction, delete every audit_personal row with the user's subject_ref and then the user's
    /// audit_subjects row, then add exactly one entry: action 'audit_subject_erased', actor_type 'service'
    /// (actor_service 'audit'), resource_type 'user', resource_id NULL, personal_roles '', metadata
    /// {erased_rows}. No audit_log row is updated or deleted. Nothing may log this user afterwards.
    /// In: user id. Out: `{erased_rows}`. Why: spec endpoint 5, amended 2026-11-10 (AUDIT-08).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, clock.
    pub fn erase_subject(&self, user_id: &str) -> Result<EraseResponse, AuditError> {
        let now = ts((self.clock)());
        let mut conn = self.db();
        let tx = conn.transaction()?;
        let sref: Option<String> = tx.query_row("SELECT subject_ref FROM audit_subjects WHERE user_id = ?1", params![user_id], |r| r.get(0)).optional()?;
        let mut erased_rows = 0;
        if let Some(sref) = sref {
            erased_rows = tx.execute("DELETE FROM audit_personal WHERE subject_ref = ?1", params![sref])?;
            tx.execute("DELETE FROM audit_subjects WHERE subject_ref = ?1", params![sref])?;
        }
        tx.execute(
            "INSERT INTO audit_log (id, timestamp, actor_type, actor_service, action, resource_type, resource_id, old_value, new_value,
                why_chain_id, personal_roles, metadata)
             VALUES (?1, ?2, 'service', 'audit', 'audit_subject_erased', 'user', NULL, NULL, NULL, NULL, '', ?3)",
            params![Uuid::new_v4().to_string(), now, json!({ "erased_rows": erased_rows }).to_string()],
        )?;
        tx.commit()?;
        Ok(EraseResponse { erased_rows })
    }

    /// What: apply the retention period: delete the audit_personal rows of entries older than
    /// `retention_days` before `now`, then every audit_subjects row left with no personal rows. No
    /// audit_log row is removed. In: now. Out: `{erased_rows}`. Why: spec endpoint 6 (AUDIT-09).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub fn apply_retention(&self, now: DateTime<Utc>) -> Result<EraseResponse, AuditError> {
        let cutoff = ts(now - Duration::days(self.retention_days));
        let mut conn = self.db();
        let tx = conn.transaction()?;
        let erased_rows = tx.execute(
            "DELETE FROM audit_personal WHERE log_id IN (SELECT id FROM audit_log WHERE timestamp < ?1)",
            params![cutoff],
        )?;
        tx.execute("DELETE FROM audit_subjects WHERE NOT EXISTS (SELECT 1 FROM audit_personal p WHERE p.subject_ref = audit_subjects.subject_ref)", [])?;
        tx.commit()?;
        Ok(EraseResponse { erased_rows })
    }
}

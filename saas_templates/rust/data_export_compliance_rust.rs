//! Data export and compliance (GDPR/CCPA): user data exports and account deletion with a grace period
//! (TIER 2 spec, system 3).
//!
//! What: `ComplianceService` records export requests, generates the export (profile, sessions,
//! activity, files, preferences, transactions, audit trail) as JSON or CSV, stores it through a
//! `FileStorage`, and emails a download link signed with HMAC-SHA256 that expires after 7 days. Account
//! deletion needs the emailed confirmation token (stored only as a SHA-256 hash), waits a 30-day grace
//! period during which the user can cancel, and then removes the user's export files from storage and
//! cascades over every user table (export requests included) except the audit log, so an old signed
//! link stops working (CodeRabbit review on PR 19, 2026-11-10). Every request and action is written to
//! the audit log.
//! Why: the old file could not compile anywhere without a live Postgres server at build time
//! (compile-time-checked SQL macros), real S3 and SMTP clients, and it stored the deletion token in
//! clear text. Rewritten on SQLite with storage and email behind traits, 2026-11-10,
//! session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: the SQLite database it owns; files through `FileStorage` (S3 in production, memory in
//! tests); email through `Mailer` (network in production); the clock; OS randomness. No money.

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
pub use rusqlite::params;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
pub use serde_json::json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

/// Export download links live 7 days (spec).
pub const EXPORT_LINK_DAYS: i64 = 7;
/// Deletion grace period: 30 days (spec, GDPR).
pub const GRACE_PERIOD_DAYS: i64 = 30;
/// User-data tables the cascade deletes from (the audit log is kept on purpose).
pub const CASCADE_TABLES: [&str; 6] = ["sessions", "activity", "files", "preferences", "transactions", "api_keys"];

/// What: compliance errors. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComplianceError {
    Db(String),
    Storage(String),
    Email(String),
    UserNotFound,
    ExportNotFound,
    DeletionNotFound,
    TokenMismatch,
    NotAllowed(String),
    InvalidLink,
    LinkExpired,
}

/// What: `fmt::Display` for `ComplianceError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl fmt::Display for ComplianceError {
    /// What: human-readable text of `fmt::Display for ComplianceError` (never secrets). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// What: `std::error::Error` for `ComplianceError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl std::error::Error for ComplianceError {}

/// What: `From<rusqlite::Error>` for `ComplianceError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl From<rusqlite::Error> for ComplianceError {
    /// What: convert the error of `From<rusqlite::Error> for ComplianceError`, keeping its message for logs. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn from(e: rusqlite::Error) -> Self {
        ComplianceError::Db(e.to_string())
    }
}

/// What: export file format. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Json,
    Csv,
}

/// What: export request state. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExportStatus {
    Pending,
    Completed,
    Failed,
}

/// What: deletion request state; `Approved` means confirmed by email and waiting out the grace
/// period. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeletionStatus {
    Pending,
    Approved,
    Completed,
    Cancelled,
}

/// What: why a deletion was requested (spec reasons). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeletionReason {
    UserRequested,
    GdprRequest,
    GdprRightToBeForgotten,
    Other,
}

/// What: stored names for the enums. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
macro_rules! names {
    ($t:ty { $($v:ident => $s:expr),* $(,)? }) => {
        impl $t {
            /// What: the stored name. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
            pub fn as_str(&self) -> &'static str { match self { $(Self::$v => $s),* } }
            /// What: parse a stored name. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
            pub fn parse(s: &str) -> Option<Self> { match s { $($s => Some(Self::$v),)* _ => None } }
        }
    };
}
names!(ExportFormat { Json => "json", Csv => "csv" });
names!(ExportStatus { Pending => "pending", Completed => "completed", Failed => "failed" });
names!(DeletionStatus { Pending => "pending", Approved => "approved", Completed => "completed", Cancelled => "cancelled" });
names!(DeletionReason { UserRequested => "user_requested", GdprRequest => "gdpr_request", GdprRightToBeForgotten => "gdpr_right_to_be_forgotten", Other => "other" });

/// What: an `export_requests` row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRequest {
    pub id: String,
    pub user_id: i64,
    pub requested_at: DateTime<Utc>,
    pub status: ExportStatus,
    pub format: ExportFormat,
    pub file_url: Option<String>,
    pub completed_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// What: a `deletion_requests` row (the token's hash is never returned). 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionRequest {
    pub id: String,
    pub user_id: i64,
    pub requested_at: DateTime<Utc>,
    pub status: DeletionStatus,
    pub reason: DeletionReason,
    pub scheduled_for: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// What: spec endpoint 1 response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Serialize)]
pub struct ExportResponse {
    pub success: bool,
    pub export_id: String,
    pub status: ExportStatus,
    pub will_email_at: DateTime<Utc>,
}

/// What: spec endpoint 2 response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Serialize)]
pub struct ExportStatusResponse {
    pub export_id: String,
    pub status: ExportStatus,
    pub file_url: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub requested_at: DateTime<Utc>,
}

/// What: spec endpoint 3 response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Serialize)]
pub struct DeletionResponse {
    pub success: bool,
    pub deletion_id: String,
    pub status: DeletionStatus,
    pub will_delete_at: DateTime<Utc>,
}

/// What: spec endpoint 4 response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Serialize)]
pub struct ConfirmDeletionResponse {
    pub success: bool,
    pub deletion_scheduled_for: DateTime<Utc>,
}

/// What: spec endpoint 5 response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Serialize)]
pub struct CancelDeletionResponse {
    pub success: bool,
    pub status: DeletionStatus,
}

/// What: spec endpoint 6 response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Serialize)]
pub struct ExportListResponse {
    pub exports: Vec<ExportRequest>,
    pub total: i64,
}

/// What: spec endpoint 7 response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Serialize)]
pub struct DeletionListResponse {
    pub deletions: Vec<DeletionRequest>,
    pub total: i64,
}

/// What: where export files go (an encrypted S3 bucket in production). In: key and bytes.
/// Out: `()` or a message. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the storage service.
pub trait FileStorage: Send {
    /// What: `put` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn put(&self, key: &str, bytes: &[u8]) -> Result<(), String>;
    /// What: `get` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    /// What: remove the file at `key`; removing a key that is already gone is `Ok` (idempotent, so a
    /// failed account deletion can simply be retried). In: key. Out: `()` or a message.
    /// Why: CodeRabbit review on PR 19: account deletion left the user's export files in storage, so a
    /// recent download link still served their data after the account was gone. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the storage service (deletes a file).
    fn delete(&self, key: &str) -> Result<(), String>;
}

/// What: in-memory storage; clones share files. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory.
#[derive(Clone, Default)]
pub struct InMemoryFileStorage {
    pub files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

/// What: `FileStorage` for `InMemoryFileStorage`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl FileStorage for InMemoryFileStorage {
    /// What: `put` of `FileStorage for InMemoryFileStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn put(&self, key: &str, bytes: &[u8]) -> Result<(), String> {
        self.files.lock().map_err(|_| "lock poisoned".to_string())?.insert(key.to_string(), bytes.to_vec());
        Ok(())
    }
    /// What: `get` of `FileStorage for InMemoryFileStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.files.lock().ok()?.get(key).cloned()
    }
    /// What: `delete` of `FileStorage for InMemoryFileStorage`: drops the key from the map (a missing key
    /// is `Ok`). In: key. Out: `()` or "lock poisoned". Why: CodeRabbit review on PR 19 (export files must
    /// go with the account). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn delete(&self, key: &str) -> Result<(), String> {
        self.files.lock().map_err(|_| "lock poisoned".to_string())?.remove(key);
        Ok(())
    }
}

/// What: one sent email. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq)]
pub struct SentEmail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// What: the email provider (SMTP in production). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: the network in a real implementation.
pub trait Mailer: Send {
    /// What: `send` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn send(&self, email: SentEmail) -> Result<(), String>;
}

/// What: an outbox in memory; clones share it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Clone, Default)]
pub struct InMemoryMailer {
    pub sent: Arc<Mutex<Vec<SentEmail>>>,
}

/// What: `Mailer` for `InMemoryMailer`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl Mailer for InMemoryMailer {
    /// What: `send` of `Mailer for InMemoryMailer`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn send(&self, email: SentEmail) -> Result<(), String> {
        self.sent.lock().map_err(|_| "lock poisoned".to_string())?.push(email);
        Ok(())
    }
}

/// What: the service. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: see the module doc.
pub struct ComplianceService {
    db: Mutex<Connection>,
    storage: Box<dyn FileStorage>,
    mailer: Box<dyn Mailer>,
    signing_key: Vec<u8>,
    base_url: String,
    clock: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>,
}

/// What: a time as stored. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// What: parse a stored time. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn parse_ts(s: Option<String>) -> Option<DateTime<Utc>> {
    s.and_then(|s| DateTime::parse_from_rfc3339(&s).ok()).map(|d| d.with_timezone(&Utc))
}

/// What: `n` OS-random bytes as hex. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex(&b)
}

/// What: lowercase hex. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// What: constant-time equality. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// What: one CSV field, quoted when needed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn csv_field(s: &str) -> String {
    // A leading = + - @ would run as a formula in a spreadsheet; prefix it.
    let s = if s.starts_with(['=', '+', '-', '@']) { format!("'{}", s) } else { s.to_string() };
    if s.contains([',', '"', '\n', '\r']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s }
}

/// What: methods of `ComplianceService`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl ComplianceService {
    /// What: a service on a connection (tables created), with storage, mailer, a link-signing key
    /// (at least 32 bytes, from configuration) and the public base URL. Out: the service or an error.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (DDL).
    pub fn new(conn: Connection, storage: Box<dyn FileStorage>, mailer: Box<dyn Mailer>, signing_key: &[u8], base_url: &str) -> Result<Self, ComplianceError> {
        if signing_key.len() < 32 {
            return Err(ComplianceError::NotAllowed("signing key must be at least 32 bytes".into()));
        }
        conn.execute_batch(MIGRATIONS)?;
        Ok(Self {
            db: Mutex::new(conn),
            storage,
            mailer,
            signing_key: signing_key.to_vec(),
            base_url: base_url.trim_end_matches('/').to_string(),
            clock: Box::new(Utc::now),
        })
    }

    /// What: replace the clock (tests of the 7-day and 30-day windows). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// What: the shared connection, for the application's own user tables. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub fn db(&self) -> MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What: append an audit row (kept through deletion). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database.
    fn audit(&self, conn: &Connection, user_id: i64, action: &str, details: Value) -> Result<(), ComplianceError> {
        conn.execute(
            "INSERT INTO audit_log (id, user_id, action, created_at, details) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![random_hex(16), user_id, action, ts((self.clock)()), details.to_string()],
        )?;
        Ok(())
    }

    /// What: the user's email, or `UserNotFound`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn user_email(conn: &Connection, user_id: i64) -> Result<String, ComplianceError> {
        conn.query_row("SELECT email FROM users WHERE id = ?1", params![user_id], |r| r.get(0))
            .optional()?
            .ok_or(ComplianceError::UserNotFound)
    }

    /// What: record an export request (spec endpoint 1); the file is made by a background job calling
    /// `generate_export_file`. In: the authenticated user, format. Out: pending export.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub async fn request_data_export(&self, user_id: i64, format: ExportFormat) -> Result<ExportResponse, ComplianceError> {
        let conn = self.db();
        Self::user_email(&conn, user_id)?;
        let id = random_hex(16);
        let now = (self.clock)();
        conn.execute(
            "INSERT INTO export_requests (id, user_id, requested_at, status, format) VALUES (?1, ?2, ?3, 'pending', ?4)",
            params![id, user_id, ts(now), format.as_str()],
        )?;
        self.audit(&conn, user_id, "data_export_requested", json!({ "export_id": id, "format": format.as_str() }))?;
        Ok(ExportResponse { success: true, export_id: id, status: ExportStatus::Pending, will_email_at: now })
    }

    /// What: every data category of a user as JSON. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (read).
    fn collect_user_data(conn: &Connection, user_id: i64) -> Result<Value, ComplianceError> {
        let rows = |sql: &str| -> Result<Vec<Value>, ComplianceError> {
            let mut stmt = conn.prepare(sql)?;
            let cols: Vec<String> = stmt.column_names().iter().map(|c| c.to_string()).collect();
            let out = stmt
                .query_map(params![user_id], |r| {
                    let mut obj = serde_json::Map::new();
                    for (i, c) in cols.iter().enumerate() {
                        let v = match r.get::<_, rusqlite::types::Value>(i)? {
                            rusqlite::types::Value::Null => Value::Null,
                            rusqlite::types::Value::Integer(n) => json!(n),
                            rusqlite::types::Value::Real(f) => json!(f),
                            rusqlite::types::Value::Text(t) => json!(t),
                            rusqlite::types::Value::Blob(b) => json!(hex(&b)),
                        };
                        obj.insert(c.clone(), v);
                    }
                    Ok(Value::Object(obj))
                })?
                .collect::<rusqlite::Result<Vec<Value>>>()?;
            Ok(out)
        };
        Ok(json!({
            "profile": rows("SELECT id, email, name, created_at, tier, status FROM users WHERE id = ?1")?.into_iter().next().unwrap_or(Value::Null),
            "sessions": rows("SELECT * FROM sessions WHERE user_id = ?1 ORDER BY rowid")?,
            "activity": rows("SELECT * FROM activity WHERE user_id = ?1 ORDER BY rowid")?,
            "files": rows("SELECT * FROM files WHERE user_id = ?1 ORDER BY rowid")?,
            "preferences": rows("SELECT * FROM preferences WHERE user_id = ?1 ORDER BY rowid")?,
            "transactions": rows("SELECT * FROM transactions WHERE user_id = ?1 ORDER BY rowid")?,
            "audit_trail": rows("SELECT id, action, created_at, details FROM audit_log WHERE user_id = ?1 ORDER BY rowid")?,
        }))
    }

    /// What: the export as CSV: `category,record` with each record as JSON. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn to_csv(data: &Value) -> String {
        let mut out = String::from("category,record\n");
        for cat in ["profile", "sessions", "activity", "files", "preferences", "transactions", "audit_trail"] {
            let items = match &data[cat] {
                Value::Array(a) => a.clone(),
                Value::Null => vec![],
                other => vec![other.clone()],
            };
            for item in items {
                out.push_str(&format!("{},{}\n", cat, csv_field(&item.to_string())));
            }
        }
        out
    }

    /// What: the signature of a download link. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn link_sig(&self, export_id: &str, ext: &str, expires: i64) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.signing_key).expect("HMAC accepts any key length");
        mac.update(format!("{}.{}:{}", export_id, ext, expires).as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// What: build the export file for a pending request (the background job's work): collect every
    /// category, store the JSON or CSV file, set a signed download link valid 7 days, email it to the
    /// user, and audit. In: export id, the owning user, the format (must match the request).
    /// Out: `()`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database, file storage, email.
    pub async fn generate_export_file(&self, export_id: String, user_id: i64, format: ExportFormat) -> Result<(), ComplianceError> {
        let conn = self.db();
        let req = Self::load_export(&conn, &export_id)?.filter(|e| e.user_id == user_id).ok_or(ComplianceError::ExportNotFound)?;
        if req.status != ExportStatus::Pending || req.format != format {
            return Err(ComplianceError::NotAllowed("export is not pending in that format".into()));
        }
        let data = Self::collect_user_data(&conn, user_id)?;
        let (bytes, ext) = match format {
            ExportFormat::Json => (serde_json::to_vec_pretty(&data).unwrap_or_default(), "json"),
            ExportFormat::Csv => (Self::to_csv(&data).into_bytes(), "csv"),
        };
        let key = format!("exports/{}/{}.{}", user_id, export_id, ext);
        if let Err(e) = self.storage.put(&key, &bytes) {
            conn.execute("UPDATE export_requests SET status = 'failed' WHERE id = ?1", params![export_id])?;
            return Err(ComplianceError::Storage(e));
        }
        let now = (self.clock)();
        let expires = now + Duration::days(EXPORT_LINK_DAYS);
        let sig = hex(&self.link_sig(&export_id, ext, expires.timestamp()));
        let url = format!("{}/compliance/download/{}/{}/{}.{}", self.base_url, expires.timestamp(), sig, export_id, ext);
        conn.execute(
            "UPDATE export_requests SET status = 'completed', file_key = ?2, file_url = ?3, completed_at = ?4, expires_at = ?5 WHERE id = ?1",
            params![export_id, key, url, ts(now), ts(expires)],
        )?;
        let to = Self::user_email(&conn, user_id)?;
        self.mailer
            .send(SentEmail { to, subject: "Your data export is ready".into(), body: format!("Download your data (valid {} days): {}", EXPORT_LINK_DAYS, url) })
            .map_err(ComplianceError::Email)?;
        self.audit(&conn, user_id, "data_export_completed", json!({ "export_id": export_id, "format": ext }))?;
        Ok(())
    }

    /// What: serve a download link: checks the HMAC in constant time and the 7-day expiry, then that the
    /// export request row still exists and is `completed` and that its file is still in storage.
    /// In: the URL path after `/compliance/download/` (`<expires>/<sig>/<id>.<ext>`). Out: file bytes,
    /// `InvalidLink`, `LinkExpired`, or `ExportNotFound` when the row or file is gone (for example after
    /// the account was deleted). Why: spec "Signed URLs: 7-day expiry, download-only"; the row/status
    /// check was added for the CodeRabbit review on PR 19 (a valid signature alone must not outlive the
    /// account). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read), file storage.
    pub fn download(&self, path: &str) -> Result<Vec<u8>, ComplianceError> {
        let parts: Vec<&str> = path.split('/').collect();
        let [exp, sig, file] = parts[..] else { return Err(ComplianceError::InvalidLink) };
        let (export_id, ext) = file.rsplit_once('.').ok_or(ComplianceError::InvalidLink)?;
        let expires: i64 = exp.parse().map_err(|_| ComplianceError::InvalidLink)?;
        if !ct_eq(sig.as_bytes(), hex(&self.link_sig(export_id, ext, expires)).as_bytes()) {
            return Err(ComplianceError::InvalidLink);
        }
        if (self.clock)().timestamp() >= expires {
            return Err(ComplianceError::LinkExpired);
        }
        let key: Option<String> = self
            .db()
            .query_row("SELECT file_key FROM export_requests WHERE id = ?1 AND status = 'completed'", params![export_id], |r| r.get(0))
            .optional()?
            .flatten();
        key.and_then(|k| self.storage.get(&k)).ok_or(ComplianceError::ExportNotFound)
    }

    /// What: read one export row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn load_export(conn: &Connection, id: &str) -> Result<Option<ExportRequest>, ComplianceError> {
        Ok(conn
            .query_row(
                "SELECT id, user_id, requested_at, status, format, file_url, completed_at, expires_at FROM export_requests WHERE id = ?1",
                params![id],
                Self::export_row,
            )
            .optional()?)
    }

    /// What: map an export row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn export_row(r: &rusqlite::Row) -> rusqlite::Result<ExportRequest> {
        let status: String = r.get(3)?;
        let format: String = r.get(4)?;
        Ok(ExportRequest {
            id: r.get(0)?,
            user_id: r.get(1)?,
            requested_at: parse_ts(r.get(2)?).unwrap_or_else(Utc::now),
            status: ExportStatus::parse(&status).unwrap_or(ExportStatus::Failed),
            format: ExportFormat::parse(&format).unwrap_or(ExportFormat::Json),
            file_url: r.get(5)?,
            completed_at: parse_ts(r.get(6)?),
            expires_at: parse_ts(r.get(7)?),
        })
    }

    /// What: an export's status for its owner (spec endpoint 2); another user's export is "not found".
    /// In: the authenticated user, export id. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (read).
    pub async fn check_export_status(&self, user_id: i64, export_id: String) -> Result<ExportStatusResponse, ComplianceError> {
        let e = Self::load_export(&self.db(), &export_id)?.filter(|e| e.user_id == user_id).ok_or(ComplianceError::ExportNotFound)?;
        Ok(ExportStatusResponse { export_id: e.id, status: e.status, file_url: e.file_url, expires_at: e.expires_at, requested_at: e.requested_at })
    }

    /// What: start a deletion (spec endpoint 3): a pending request scheduled 30 days out, and an email
    /// with a one-time confirmation token (only its SHA-256 is stored). In: the authenticated user,
    /// reason. Out: pending deletion. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database, email, OS randomness.
    pub async fn request_account_deletion(&self, user_id: i64, reason: DeletionReason) -> Result<DeletionResponse, ComplianceError> {
        let conn = self.db();
        let to = Self::user_email(&conn, user_id)?;
        let id = random_hex(16);
        let token = random_hex(32);
        let now = (self.clock)();
        let scheduled = now + Duration::days(GRACE_PERIOD_DAYS);
        conn.execute(
            "INSERT INTO deletion_requests (id, user_id, requested_at, status, reason, scheduled_for, token_hash)
             VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?6)",
            params![id, user_id, ts(now), reason.as_str(), ts(scheduled), hex(&Sha256::digest(token.as_bytes()))],
        )?;
        self.mailer
            .send(SentEmail {
                to,
                subject: "Confirm your account deletion".into(),
                body: format!("Confirm: {}/compliance/delete/{}/confirm?token={}", self.base_url, id, token),
            })
            .map_err(ComplianceError::Email)?;
        self.audit(&conn, user_id, "deletion_requested", json!({ "deletion_id": id, "reason": reason.as_str() }))?;
        Ok(DeletionResponse { success: true, deletion_id: id, status: DeletionStatus::Pending, will_delete_at: scheduled })
    }

    /// What: map a deletion row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn deletion_row(r: &rusqlite::Row) -> rusqlite::Result<DeletionRequest> {
        let status: String = r.get(3)?;
        let reason: String = r.get(4)?;
        Ok(DeletionRequest {
            id: r.get(0)?,
            user_id: r.get(1)?,
            requested_at: parse_ts(r.get(2)?).unwrap_or_else(Utc::now),
            status: DeletionStatus::parse(&status).unwrap_or(DeletionStatus::Pending),
            reason: DeletionReason::parse(&reason).unwrap_or(DeletionReason::Other),
            scheduled_for: parse_ts(r.get(5)?).unwrap_or_else(Utc::now),
            deleted_at: parse_ts(r.get(6)?),
        })
    }

    /// What: confirm a deletion with the emailed token (spec endpoint 4); constant-time hash
    /// comparison; pending -> approved. Out: when it will run. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub async fn confirm_deletion(&self, deletion_id: String, token: &str) -> Result<ConfirmDeletionResponse, ComplianceError> {
        let conn = self.db();
        let row: Option<(DeletionRequest, String)> = conn
            .query_row(
                "SELECT id, user_id, requested_at, status, reason, scheduled_for, deleted_at, token_hash FROM deletion_requests WHERE id = ?1",
                params![deletion_id],
                |r| Ok((Self::deletion_row(r)?, r.get(7)?)),
            )
            .optional()?;
        let (d, hash) = row.ok_or(ComplianceError::DeletionNotFound)?;
        if !ct_eq(hex(&Sha256::digest(token.as_bytes())).as_bytes(), hash.as_bytes()) {
            return Err(ComplianceError::TokenMismatch);
        }
        if d.status != DeletionStatus::Pending {
            return Err(ComplianceError::NotAllowed(format!("deletion is {}", d.status.as_str())));
        }
        conn.execute("UPDATE deletion_requests SET status = 'approved' WHERE id = ?1 AND status = 'pending'", params![d.id])?;
        self.audit(&conn, d.user_id, "deletion_confirmed", json!({ "deletion_id": d.id }))?;
        Ok(ConfirmDeletionResponse { success: true, deletion_scheduled_for: d.scheduled_for })
    }

    /// What: cancel the user's own deletion within the grace period (spec endpoint 5). In: the
    /// authenticated user, deletion id. Out: cancelled. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database.
    pub async fn cancel_deletion(&self, user_id: i64, deletion_id: String) -> Result<CancelDeletionResponse, ComplianceError> {
        let conn = self.db();
        let d = conn
            .query_row(
                "SELECT id, user_id, requested_at, status, reason, scheduled_for, deleted_at FROM deletion_requests WHERE id = ?1",
                params![deletion_id],
                Self::deletion_row,
            )
            .optional()?
            .filter(|d| d.user_id == user_id)
            .ok_or(ComplianceError::DeletionNotFound)?;
        if !matches!(d.status, DeletionStatus::Pending | DeletionStatus::Approved) || (self.clock)() >= d.scheduled_for {
            return Err(ComplianceError::NotAllowed("the grace period is over or the request is closed".into()));
        }
        conn.execute("UPDATE deletion_requests SET status = 'cancelled' WHERE id = ?1", params![d.id])?;
        self.audit(&conn, user_id, "deletion_cancelled", json!({ "deletion_id": d.id }))?;
        Ok(CancelDeletionResponse { success: true, status: DeletionStatus::Cancelled })
    }

    /// What: run every confirmed deletion whose grace period has ended (call from a scheduled job).
    /// A user whose export files could not be removed from storage is skipped: the request stays
    /// `approved` (so the next run retries it), an audit row `deletion_cleanup_failed` is written, and
    /// the other due users are still processed. Out: how many users were deleted; database errors are
    /// returned. Why: the retry behaviour was added for the CodeRabbit review on PR 19 (export files
    /// must go with the account, and a storage outage must not lose the deletion). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, file storage (deletes export files).
    pub async fn process_due_deletions(&self) -> Result<usize, ComplianceError> {
        let now = ts((self.clock)());
        let due: Vec<(String, i64)> = {
            let conn = self.db();
            let mut stmt = conn.prepare("SELECT id, user_id FROM deletion_requests WHERE status = 'approved' AND scheduled_for <= ?1 ORDER BY rowid")?;
            let rows = stmt.query_map(params![now], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let mut deleted = 0;
        for (id, user_id) in &due {
            match self.cascade_delete_user(*user_id).await {
                Ok(()) => {}
                Err(ComplianceError::Storage(e)) => {
                    let conn = self.db();
                    self.audit(&conn, *user_id, "deletion_cleanup_failed", json!({ "deletion_id": id, "error": e }))?;
                    continue;
                }
                Err(e) => return Err(e),
            }
            self.db().execute("UPDATE deletion_requests SET status = 'completed', deleted_at = ?2 WHERE id = ?1", params![id, now])?;
            deleted += 1;
        }
        Ok(deleted)
    }

    /// What: delete the user's export files from storage, then (in one transaction) the user's export
    /// requests, rows in every user table and the user, keeping the audit log (spec "except audit_log
    /// (keep for compliance)"); writes an audit row with counts. If any export file cannot be removed
    /// it returns `Storage` before the transaction starts, so nothing is deleted and the call can be
    /// retried (removing a file twice is fine). In: user id. Out: `()`.
    /// Why: export cleanup added for the CodeRabbit review on PR 19: the files and `export_requests`
    /// rows used to survive the deletion, so a recent signed link still downloaded the user's data.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, file storage (deletes files).
    pub async fn cascade_delete_user(&self, user_id: i64) -> Result<(), ComplianceError> {
        let mut conn = self.db();
        let keys: Vec<String> = {
            let mut stmt = conn.prepare("SELECT file_key FROM export_requests WHERE user_id = ?1 AND file_key IS NOT NULL ORDER BY rowid")?;
            let rows = stmt.query_map(params![user_id], |r| r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
            rows
        };
        for key in &keys {
            self.storage.delete(key).map_err(ComplianceError::Storage)?;
        }
        let tx = conn.transaction()?;
        let mut counts = serde_json::Map::new();
        let n = tx.execute("DELETE FROM export_requests WHERE user_id = ?1", params![user_id])?;
        counts.insert("export_requests".to_string(), json!(n));
        counts.insert("export_files".to_string(), json!(keys.len()));
        for table in CASCADE_TABLES {
            let n = tx.execute(&format!("DELETE FROM {} WHERE user_id = ?1", table), params![user_id])?;
            counts.insert(table.to_string(), json!(n));
        }
        tx.execute("DELETE FROM users WHERE id = ?1", params![user_id])?;
        tx.execute(
            "INSERT INTO audit_log (id, user_id, action, created_at, details) VALUES (?1, ?2, 'user_deleted_cascade', ?3, ?4)",
            params![random_hex(16), user_id, ts((self.clock)()), Value::Object(counts).to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// What: export requests, optionally by user and status, in request order (spec endpoint 6;
    /// the caller must have checked that the actor is an admin). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
    pub async fn list_exports(&self, user_id: Option<i64>, status: Option<ExportStatus>) -> Result<ExportListResponse, ComplianceError> {
        let conn = self.db();
        let mut stmt = conn.prepare(
            "SELECT id, user_id, requested_at, status, format, file_url, completed_at, expires_at FROM export_requests
             WHERE (?1 IS NULL OR user_id = ?1) AND (?2 IS NULL OR status = ?2) ORDER BY rowid",
        )?;
        let exports = stmt.query_map(params![user_id, status.map(|s| s.as_str())], Self::export_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(ExportListResponse { total: exports.len() as i64, exports })
    }

    /// What: deletion requests, optionally by status, in request order (spec endpoint 7; admin only,
    /// checked by the caller). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
    pub async fn list_deletions(&self, status: Option<DeletionStatus>) -> Result<DeletionListResponse, ComplianceError> {
        let conn = self.db();
        let mut stmt = conn.prepare(
            "SELECT id, user_id, requested_at, status, reason, scheduled_for, deleted_at FROM deletion_requests
             WHERE (?1 IS NULL OR status = ?1) ORDER BY rowid",
        )?;
        let deletions = stmt.query_map(params![status.map(|s| s.as_str())], Self::deletion_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(DeletionListResponse { total: deletions.len() as i64, deletions })
    }
}

/// The schema: the spec's two tables (plus file key, schedule and token hash), the audit log, and
/// the application's user tables that exports read and the cascade deletes.
pub const MIGRATIONS: &str = "
CREATE TABLE IF NOT EXISTS export_requests (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, requested_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','completed','failed')), format TEXT NOT NULL CHECK (format IN ('json','csv')),
    file_key TEXT NULL, file_url TEXT NULL, completed_at TEXT NULL, expires_at TEXT NULL);
CREATE TABLE IF NOT EXISTS deletion_requests (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, requested_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','approved','completed','cancelled')), reason TEXT NOT NULL,
    scheduled_for TEXT NOT NULL, deleted_at TEXT NULL, token_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (id TEXT PRIMARY KEY, user_id INTEGER, action TEXT NOT NULL, created_at TEXT NOT NULL, details TEXT);
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT NOT NULL, name TEXT NOT NULL, created_at TEXT NOT NULL,
    tier TEXT NOT NULL, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, ip TEXT, device TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS activity (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, action TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS files (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, name TEXT, size_bytes INTEGER);
CREATE TABLE IF NOT EXISTS preferences (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, key TEXT, value TEXT);
CREATE TABLE IF NOT EXISTS transactions (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, kind TEXT, amount_cents INTEGER, created_at TEXT);
CREATE TABLE IF NOT EXISTS api_keys (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, name TEXT);
";

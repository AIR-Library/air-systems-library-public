//! Data export and compliance (GDPR/CCPA): user data exports and account deletion with a grace period
//! (TIER 2 spec, system 3).
//!
//! What: `ComplianceService` records export requests, generates the export (profile, sessions,
//! activity, files, preferences, transactions, audit trail) as JSON or CSV, stores it through a
//! `FileStorage`, and emails a download link signed with HMAC-SHA256 that expires after 7 days. Account
//! deletion needs the emailed confirmation token (stored only as a SHA-256 hash), waits a 30-day grace
//! period during which the user can cancel (none for a statutory reason), and then removes the user's export files from storage and
//! cascades over every user table (export requests included) except the audit log, so an old signed
//! link stops working (CodeRabbit review on PR 19, 2026-11-10). Every request and action is written to
//! the audit log.
//! Why: the old file could not compile anywhere without a live Postgres server at build time
//! (compile-time-checked SQL macros), real S3 and SMTP clients, and it stored the deletion token in
//! clear text. Rewritten on SQLite with storage and email behind traits, 2026-11-10,
//! session_012zDydZCZ4AChqhEZ4oVtaP.
//! Amended 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP, EXPORT-05/12/13/14): statutory reasons get no
//! grace period and are erased on confirm; the confirmation token expires after 24 hours and is
//! single-use; confirm and cancel act only on the caller's own request; the cascade logs
//! 'user_deleted_cascade', then calls an injected `AuditEraser` last, and nulls deletion_requests.user_id;
//! the admin lists check the verified caller's role.
//! Amended 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP, Phase B.2, EXPORT-15): a wrong, reused or expired
//! token is one 400 invalid_confirmation_token; a cancelled request is 409 deletion_not_pending; a
//! completed one (it has no owner) and another user's are 404 not_found (`ComplianceError::code`/`status`). The cascade
//! now also clears user_id on this module's own audit_log rows, so nothing personal remains.
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
/// Deletion grace period for user_requested / other: 30 days (a product choice; statutory reasons get none).
pub const GRACE_PERIOD_DAYS: i64 = 30;
/// A deletion confirmation token is valid 24 hours (2026-11-10 amendment, EXPORT-14).
pub const CONFIRM_TOKEN_HOURS: i64 = 24;
/// User-data tables the cascade deletes from (the audit log is kept on purpose).
pub const CASCADE_TABLES: [&str; 6] = ["sessions", "activity", "files", "preferences", "transactions", "api_keys"];

/// What: compliance errors; `code()` and `status()` give the spec's error code and HTTP status.
/// Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP, Phase B.2, EXPORT-15): `TokenMismatch` and
/// `TokenExpired` became one `InvalidConfirmationToken` (a wrong, reused or expired token gets one answer,
/// 400 invalid_confirmation_token, so the reply never says which); `DeletionNotPending` (409) is a request
/// that is cancelled or completed; `GracePeriodOver` (409) is a cancel after will_delete_at. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComplianceError {
    Db(String),
    Storage(String),
    Email(String),
    UserNotFound,
    ExportNotFound,
    /// Another user's deletion request, or none: 404 not_found (EXPORT-14/15).
    DeletionNotFound,
    /// A wrong, reused or expired confirmation token: 400 invalid_confirmation_token (EXPORT-15).
    InvalidConfirmationToken,
    /// Confirm or cancel of a request no longer pending: 409 deletion_not_pending (EXPORT-15).
    DeletionNotPending,
    /// Cancel after the grace period ended: 409 grace_period_over.
    GracePeriodOver,
    AuditErase(String),
    NotAllowed(String),
    InvalidLink,
    LinkExpired,
}

/// What: the spec's error code and HTTP status for each `ComplianceError`. In: the error.
/// Out: (`code()`: the `{error: ...}` string, `status()`: the HTTP status). Why: EXPORT-15 (Phase B.2: one
/// answer in every language: 404 not_found, 400 invalid_confirmation_token, 409 deletion_not_pending).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
impl ComplianceError {
    /// What: the error code a server puts in `{error: ...}`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: nothing.
    pub fn code(&self) -> &'static str {
        match self {
            ComplianceError::Db(_) | ComplianceError::Storage(_) | ComplianceError::Email(_) | ComplianceError::AuditErase(_) => "internal_error",
            ComplianceError::UserNotFound => "user_not_found",
            ComplianceError::ExportNotFound | ComplianceError::DeletionNotFound => "not_found",
            ComplianceError::InvalidConfirmationToken => "invalid_confirmation_token",
            ComplianceError::DeletionNotPending => "deletion_not_pending",
            ComplianceError::GracePeriodOver => "grace_period_over",
            ComplianceError::NotAllowed(_) => "forbidden",
            ComplianceError::InvalidLink => "invalid_link",
            ComplianceError::LinkExpired => "link_expired",
        }
    }

    /// What: the HTTP status for the error. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn status(&self) -> u16 {
        match self {
            ComplianceError::Db(_) | ComplianceError::Storage(_) | ComplianceError::Email(_) | ComplianceError::AuditErase(_) => 500,
            ComplianceError::UserNotFound | ComplianceError::ExportNotFound | ComplianceError::DeletionNotFound => 404,
            ComplianceError::InvalidConfirmationToken => 400,
            ComplianceError::DeletionNotPending | ComplianceError::GracePeriodOver => 409,
            ComplianceError::NotAllowed(_) => 403,
            ComplianceError::InvalidLink => 403,
            ComplianceError::LinkExpired => 410,
        }
    }
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

/// What: statutory-reason test for `DeletionReason`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl DeletionReason {
    /// What: true for a statutory erasure request (gdpr_request, gdpr_right_to_be_forgotten), which must
    /// be completed without undue delay and so gets no grace period. Out: bool.
    /// Why: 2026-11-10 amendment (EXPORT-05/12). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn is_statutory(&self) -> bool {
        matches!(self, DeletionReason::GdprRequest | DeletionReason::GdprRightToBeForgotten)
    }
}

/// What: the verified caller of an admin endpoint, built by the server from the authenticated session
/// (never from a request body, query or header). Why: identity from the verified caller (specs README);
/// the admin lists (endpoints 6 and 7) relied on the caller having checked the role. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caller {
    pub user_id: i64,
    pub is_admin: bool,
}

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
    /// NULL (None) once the deletion completed, so the row cannot re-identify erased audit entries.
    pub user_id: Option<i64>,
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

/// What: the audit system's erasure entry point (audit_logging.md `erase_subject`), injected like the
/// mailer so tests pass a fake. The cascade calls it LAST, after the user's rows are deleted and
/// 'user_deleted_cascade' is logged. In: user id. Out: `()` or a message (the cascade then rolls back).
/// Why: 2026-11-10 amendment (EXPORT-13): nothing erased the user's personal data in the audit tables.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the audit store in a real implementation.
pub trait AuditEraser: Send {
    /// What: erase the subject's personal audit data. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn erase_subject(&self, user_id: i64) -> Result<(), String>;
}

/// What: the default eraser until one is configured: it refuses, so no account is deleted while its
/// audit personal data would be left behind (fail closed). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: nothing.
pub struct UnconfiguredAuditEraser;

/// What: `AuditEraser` for `UnconfiguredAuditEraser`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl AuditEraser for UnconfiguredAuditEraser {
    /// What: always an error. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn erase_subject(&self, _user_id: i64) -> Result<(), String> {
        Err("audit eraser not configured".into())
    }
}

/// What: the service. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: see the module doc.
pub struct ComplianceService {
    db: Mutex<Connection>,
    storage: Box<dyn FileStorage>,
    mailer: Box<dyn Mailer>,
    audit_eraser: Box<dyn AuditEraser>,
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
            audit_eraser: Box::new(UnconfiguredAuditEraser),
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

    /// What: set the audit eraser the deletion cascade calls last (EXPORT-13). In: the eraser.
    /// Out: the service. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn with_audit_eraser(mut self, eraser: Box<dyn AuditEraser>) -> Self {
        self.audit_eraser = eraser;
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

    /// What: start a deletion (spec endpoint 3). will_delete_at = requested_at + 30 days for
    /// user_requested / other (the user can cancel), and = requested_at for a statutory reason
    /// (gdpr_request, gdpr_right_to_be_forgotten: no grace period). Nothing is deleted yet: the user must
    /// confirm with the emailed token: 32 OS-random bytes, stored only as SHA-256, single-use, valid 24
    /// hours, bound to this deletion id. In: the authenticated user (from the server's session), reason.
    /// Out: pending deletion. Why: 2026-11-10 amendment (EXPORT-05/12/14).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, email, OS randomness.
    pub async fn request_account_deletion(&self, user_id: i64, reason: DeletionReason) -> Result<DeletionResponse, ComplianceError> {
        let conn = self.db();
        let to = Self::user_email(&conn, user_id)?;
        let id = random_hex(16);
        let token = random_hex(32);
        let now = (self.clock)();
        let scheduled = if reason.is_statutory() { now } else { now + Duration::days(GRACE_PERIOD_DAYS) };
        conn.execute(
            "INSERT INTO deletion_requests (id, user_id, requested_at, status, reason, scheduled_for, token_hash, token_expires_at)
             VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?6, ?7)",
            params![id, user_id, ts(now), reason.as_str(), ts(scheduled), hex(&Sha256::digest(token.as_bytes())), ts(now + Duration::hours(CONFIRM_TOKEN_HOURS))],
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

    /// What: the caller's own deletion request with its token hash and token expiry, or `DeletionNotFound`
    /// (404 not_found) for none and for anyone else's, so the two cannot be told apart. A completed request
    /// has no owner any more (user_id NULL, EXPORT-13), so it is 404 to every caller; the status filter
    /// keeps that true even for a completed row that still names a user. In: connection, the verified caller, deletion id.
    /// Out: (request, token hash, token expiry). Why: EXPORT-14/15. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (read).
    fn own_deletion(conn: &Connection, user_id: i64, deletion_id: &str) -> Result<(DeletionRequest, String, Option<String>), ComplianceError> {
        conn.query_row(
            "SELECT id, user_id, requested_at, status, reason, scheduled_for, deleted_at, token_hash, token_expires_at
             FROM deletion_requests WHERE id = ?1 AND user_id = ?2 AND status != 'completed'",
            params![deletion_id, user_id],
            |r| Ok((Self::deletion_row(r)?, r.get(7)?, r.get(8)?)),
        )
        .optional()?
        .ok_or(ComplianceError::DeletionNotFound)
    }

    /// What: refuse a cancelled request with `DeletionNotPending` (409 deletion_not_pending). Checked before
    /// the token, so a cancelled request's token, spent or not, never reads as a wrong token. (A completed
    /// request never gets here: `own_deletion` answers 404 for it.) In: the request. Out: `()` or the error.
    /// Why: EXPORT-15 (Phase B.2, as amended in commit 3abb340: completed is 404, cancelled is 409).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn refuse_if_closed(d: &DeletionRequest) -> Result<(), ComplianceError> {
        if matches!(d.status, DeletionStatus::Cancelled) {
            return Err(ComplianceError::DeletionNotPending);
        }
        Ok(())
    }

    /// What: confirm the caller's own deletion with the emailed token (spec endpoint 4). Order: the
    /// request must be the caller's and not completed (else `DeletionNotFound`, 404 not_found, for anyone
    /// else's and for a completed one); it must not be cancelled (else `DeletionNotPending`, 409); the token's SHA-256 must match in
    /// constant time and the token must be under 24 hours old, else `InvalidConfirmationToken` (400) for a
    /// wrong, reused (a used token's hash is cleared) or expired token alike; the request must be pending
    /// (an approved one already spent its token, so it is refused as a reused token above). Then pending
    /// -> approved and the token is spent. For a statutory reason the cascade runs before this returns:
    /// status 'completed', deleted_at = deletion_scheduled_for = now (if the cascade fails, the request
    /// stays approved and due now, and the error is returned).
    /// In: the authenticated user (from the server's session), deletion id, token. Out: when it runs.
    /// Why: 2026-11-10 amendment (EXPORT-12/14); changed 2026-11-10 for EXPORT-15 (Phase B.2: one 400 for a
    /// wrong, reused or expired token; 409 for a closed request). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database; for a statutory reason also file storage and the audit eraser.
    pub async fn confirm_deletion(&self, user_id: i64, deletion_id: String, token: &str) -> Result<ConfirmDeletionResponse, ComplianceError> {
        let (d, now) = {
            let conn = self.db();
            let (d, hash, expires) = Self::own_deletion(&conn, user_id, &deletion_id)?;
            Self::refuse_if_closed(&d)?;
            let now = (self.clock)();
            let matches = !hash.is_empty() && ct_eq(hex(&Sha256::digest(token.as_bytes())).as_bytes(), hash.as_bytes());
            let expired = parse_ts(expires).map_or(true, |e| now >= e);
            if !matches || expired {
                return Err(ComplianceError::InvalidConfirmationToken);
            }
            if d.status != DeletionStatus::Pending {
                return Err(ComplianceError::DeletionNotPending);
            }
            let scheduled = if d.reason.is_statutory() { now } else { d.scheduled_for };
            let n = conn.execute(
                "UPDATE deletion_requests SET status = 'approved', token_hash = '', scheduled_for = ?3
                 WHERE id = ?1 AND user_id = ?2 AND status = 'pending' AND token_hash = ?4",
                params![d.id, user_id, ts(scheduled), hash],
            )?;
            if n != 1 {
                return Err(ComplianceError::InvalidConfirmationToken);
            }
            self.audit(&conn, user_id, "deletion_confirmed", json!({ "deletion_id": d.id }))?;
            (DeletionRequest { scheduled_for: scheduled, ..d }, now)
        };
        if d.reason.is_statutory() {
            self.cascade(user_id, Some(&d.id)).await?;
            return Ok(ConfirmDeletionResponse { success: true, deletion_scheduled_for: now });
        }
        Ok(ConfirmDeletionResponse { success: true, deletion_scheduled_for: d.scheduled_for })
    }

    /// What: cancel the caller's own deletion within the grace period (spec endpoint 5). Anyone else's
    /// request, and a completed one, is `DeletionNotFound` (404 not_found); a cancelled one is
    /// `DeletionNotPending` (409 deletion_not_pending); after will_delete_at it is `GracePeriodOver` (409). The token is spent.
    /// In: the authenticated user, deletion id. Out: cancelled. Changed 2026-11-10 for EXPORT-15 (Phase B.2:
    /// a closed request was a generic `NotAllowed`). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database.
    pub async fn cancel_deletion(&self, user_id: i64, deletion_id: String) -> Result<CancelDeletionResponse, ComplianceError> {
        let conn = self.db();
        let (d, _, _) = Self::own_deletion(&conn, user_id, &deletion_id)?;
        Self::refuse_if_closed(&d)?;
        if (self.clock)() >= d.scheduled_for {
            return Err(ComplianceError::GracePeriodOver);
        }
        conn.execute("UPDATE deletion_requests SET status = 'cancelled', token_hash = '' WHERE id = ?1", params![d.id])?;
        self.audit(&conn, user_id, "deletion_cancelled", json!({ "deletion_id": d.id }))?;
        Ok(CancelDeletionResponse { success: true, status: DeletionStatus::Cancelled })
    }

    /// What: run every confirmed deletion whose grace period has ended (call from a scheduled job).
    /// A user whose export files could not be removed from storage, or whose audit data could not be
    /// erased, is skipped: the request stays `approved` (so the next run retries it), an audit row
    /// `deletion_cleanup_failed` is written, and the other due users are still processed. Out: how many
    /// users were deleted; database errors are returned. Why: the retry behaviour was added for the
    /// CodeRabbit review on PR 19 (export files must go with the account, and a storage outage must not
    /// lose the deletion); the eraser case for the 2026-11-10 amendment (EXPORT-13). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, file storage (deletes export files), audit eraser.
    pub async fn process_due_deletions(&self) -> Result<usize, ComplianceError> {
        let now = ts((self.clock)());
        let due: Vec<(String, i64)> = {
            let conn = self.db();
            let mut stmt = conn.prepare(
                "SELECT id, user_id FROM deletion_requests WHERE status = 'approved' AND user_id IS NOT NULL AND scheduled_for <= ?1 ORDER BY rowid",
            )?;
            let rows = stmt.query_map(params![now], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let mut deleted = 0;
        for (id, user_id) in &due {
            match self.cascade(*user_id, Some(id)).await {
                Ok(()) => deleted += 1,
                Err(ComplianceError::Storage(e)) | Err(ComplianceError::AuditErase(e)) => {
                    let conn = self.db();
                    self.audit(&conn, *user_id, "deletion_cleanup_failed", json!({ "deletion_id": id, "error": e }))?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(deleted)
    }

    /// What: `cascade` with no deletion request (an operator's direct erasure). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as `cascade`.
    pub async fn cascade_delete_user(&self, user_id: i64) -> Result<(), ComplianceError> {
        self.cascade(user_id, None).await
    }

    /// What: delete the user's export files from storage, then in ONE transaction, in this order:
    /// (1) delete the user's rows (export requests, every user table, the user), never the audit tables;
    /// (2) log 'user_deleted_cascade' with the user as subject (counts only); complete the deletion
    /// request and set deletion_requests.user_id NULL for every request of this user (so the rows cannot
    /// re-identify erased audit entries); (3) erase: this module's own audit_log rows keep their action,
    /// time and details but their user_id is set NULL, then the audit eraser's erase_subject(user_id) is
    /// called LAST, then commit. Nothing logs this user afterwards, and nothing personal is left in this
    /// module's tables. If an export file cannot be removed it returns
    /// `Storage` before the transaction starts; if the eraser fails the transaction rolls back
    /// (`AuditErase`); either way nothing is deleted and the call can be retried.
    /// In: user id, the deletion request being completed (if any). Out: `()`.
    /// Why: export cleanup for the CodeRabbit review on PR 19; order, eraser and NULL user_id for the
    /// 2026-11-10 amendment (EXPORT-13); the local audit_log user_id is cleared since 2026-11-10 (Phase B.2
    /// bug: it kept the deleted user's id, so the audit rows still named them after the cascade).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database, file storage (deletes files), the audit eraser.
    async fn cascade(&self, user_id: i64, deletion_id: Option<&str>) -> Result<(), ComplianceError> {
        let mut conn = self.db();
        let keys: Vec<String> = {
            let mut stmt = conn.prepare("SELECT file_key FROM export_requests WHERE user_id = ?1 AND file_key IS NOT NULL ORDER BY rowid")?;
            let rows = stmt.query_map(params![user_id], |r| r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
            rows
        };
        for key in &keys {
            self.storage.delete(key).map_err(ComplianceError::Storage)?;
        }
        let now = ts((self.clock)());
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
            params![random_hex(16), user_id, now, Value::Object(counts).to_string()],
        )?;
        if let Some(id) = deletion_id {
            tx.execute("UPDATE deletion_requests SET status = 'completed', deleted_at = ?2, scheduled_for = ?2 WHERE id = ?1", params![id, now])?;
        }
        tx.execute(
            "UPDATE deletion_requests SET status = CASE WHEN status IN ('pending', 'approved') THEN 'cancelled' ELSE status END,
                token_hash = '', user_id = NULL WHERE user_id = ?1",
            params![user_id],
        )?;
        // Phase B.2 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): the rows stay (EXPORT-08), the link to the person goes.
        tx.execute("UPDATE audit_log SET user_id = NULL WHERE user_id = ?1", params![user_id])?;
        self.audit_eraser.erase_subject(user_id).map_err(ComplianceError::AuditErase)?;
        tx.commit()?;
        Ok(())
    }

    /// What: export requests, optionally by user and status, in request order (spec endpoint 6, admin
    /// only). In: the verified caller (`NotAllowed` unless admin), filters. Out: the list and total.
    /// Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the admin check moved here from "checked by
    /// the caller", so it cannot be forgotten. Touches: database (read).
    pub async fn list_exports(&self, caller: &Caller, user_id: Option<i64>, status: Option<ExportStatus>) -> Result<ExportListResponse, ComplianceError> {
        if !caller.is_admin {
            return Err(ComplianceError::NotAllowed("admin only".into()));
        }
        let conn = self.db();
        let mut stmt = conn.prepare(
            "SELECT id, user_id, requested_at, status, format, file_url, completed_at, expires_at FROM export_requests
             WHERE (?1 IS NULL OR user_id = ?1) AND (?2 IS NULL OR status = ?2) ORDER BY rowid",
        )?;
        let exports = stmt.query_map(params![user_id, status.map(|s| s.as_str())], Self::export_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(ExportListResponse { total: exports.len() as i64, exports })
    }

    /// What: deletion requests, optionally by status, in request order (spec endpoint 7, admin only).
    /// In: the verified caller (`NotAllowed` unless admin), filter. Out: the list and total.
    /// Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the admin check moved here. Touches: database (read).
    pub async fn list_deletions(&self, caller: &Caller, status: Option<DeletionStatus>) -> Result<DeletionListResponse, ComplianceError> {
        if !caller.is_admin {
            return Err(ComplianceError::NotAllowed("admin only".into()));
        }
        let conn = self.db();
        let mut stmt = conn.prepare(
            "SELECT id, user_id, requested_at, status, reason, scheduled_for, deleted_at FROM deletion_requests
             WHERE (?1 IS NULL OR status = ?1) ORDER BY rowid",
        )?;
        let deletions = stmt.query_map(params![status.map(|s| s.as_str())], Self::deletion_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(DeletionListResponse { total: deletions.len() as i64, deletions })
    }
}

/// The schema: the spec's two tables (plus file key, schedule, token hash and token expiry; deletion
/// user_id is nullable since 2026-11-10, EXPORT-13), the audit log (user_id NULL once the user is erased,
/// 2026-11-10 Phase B.2), and
/// the application's user tables that exports read and the cascade deletes.
pub const MIGRATIONS: &str = "
CREATE TABLE IF NOT EXISTS export_requests (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, requested_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','completed','failed')), format TEXT NOT NULL CHECK (format IN ('json','csv')),
    file_key TEXT NULL, file_url TEXT NULL, completed_at TEXT NULL, expires_at TEXT NULL);
CREATE TABLE IF NOT EXISTS deletion_requests (id TEXT PRIMARY KEY, user_id INTEGER NULL, requested_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','approved','completed','cancelled')), reason TEXT NOT NULL,
    scheduled_for TEXT NOT NULL, deleted_at TEXT NULL, token_hash TEXT NOT NULL, token_expires_at TEXT NULL);
CREATE TABLE IF NOT EXISTS audit_log (id TEXT PRIMARY KEY, user_id INTEGER NULL, action TEXT NOT NULL, created_at TEXT NOT NULL, details TEXT);
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT NOT NULL, name TEXT NOT NULL, created_at TEXT NOT NULL,
    tier TEXT NOT NULL, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, ip TEXT, device TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS activity (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, action TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS files (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, name TEXT, size_bytes INTEGER);
CREATE TABLE IF NOT EXISTS preferences (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, key TEXT, value TEXT);
CREATE TABLE IF NOT EXISTS transactions (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, kind TEXT, amount_cents INTEGER, created_at TEXT);
CREATE TABLE IF NOT EXISTS api_keys (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, name TEXT);
";

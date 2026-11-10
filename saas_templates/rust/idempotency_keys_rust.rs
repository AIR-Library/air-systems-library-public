//! Idempotency keys: safe retries for POST and PATCH (TIER 3 spec, system 5, from IETF
//! draft-ietf-httpapi-idempotency-key-header-07).
//!
//! What: `handle` claims (scope, key) atomically, runs the operation at most once, stores its response
//! and serves that stored response to identical retries for 24 hours. A missing key on a required
//! operation is 400, a different request under the same key is 422 (even while the first is still in
//! progress), an identical request still in progress is 409; all errors are application/problem+json.
//! An operation that fails or panics frees the key so a retry can run it.
//! Why: the old file did not compile against its tests (the record map was private, `thiserror` errors
//! had no `PartialEq`), its SQL store returned "unimplemented" for every call, and it carried a second
//! copy of the tests inside the implementation. Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: memory, or SQLite through `SqlStore`; runs the caller's operation (which may move money,
//! which is why it must run at most once); no network of its own.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How long a key is remembered (spec: 24 hours).
pub const KEY_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Longest accepted key, in bytes.
pub const MAX_KEY_LEN: usize = 255;

/// What: a record's state. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordStatus {
    InProgress,
    Completed,
}

/// What: one row of `idempotency_records`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq)]
pub struct IdempotencyRecord {
    pub scope: String,
    pub idem_key: String,
    pub request_fingerprint: String,
    pub status: RecordStatus,
    pub response_status: Option<i32>,
    pub response_body: Option<String>,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}

/// What: a store failure. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    NotFound,
    Database(String),
}

/// What: the outcome of an atomic claim. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq)]
pub enum Claim {
    /// The key was free (or its record had expired); the new in-progress record is now stored.
    Claimed,
    /// A live record already holds the key.
    Existing(IdempotencyRecord),
}

/// What: the storage the handler needs. Why: spec storage contract; `claim` is the atomic
/// insert-if-absent ("so two concurrent requests cannot both run"), treating an expired record as
/// absent. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: whatever the implementation uses.
pub trait Store: Send + Sync {
    /// What: `claim` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn claim(&self, record: IdempotencyRecord, now: SystemTime) -> Result<Claim, StoreError>;
    /// What: `complete` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn complete(&self, scope: &str, idem_key: &str, status: i32, body: &str) -> Result<(), StoreError>;
    /// What: `delete` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn delete(&self, scope: &str, idem_key: &str) -> Result<(), StoreError>;
    /// What: `purge_expired` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn purge_expired(&self, now: SystemTime) -> Result<usize, StoreError>;
}

/// What: the in-memory store; `records` is public so tests can age a record.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
#[derive(Default)]
pub struct InMemoryStore {
    pub records: Mutex<HashMap<(String, String), IdempotencyRecord>>,
}

/// What: methods of `InMemoryStore`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl InMemoryStore {
    /// What: an empty store. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    pub fn new() -> Self {
        Self::default()
    }
}

/// What: a poisoned lock as a store error. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn poisoned<T>(_: T) -> StoreError {
    StoreError::Database("lock poisoned".into())
}

/// What: `Store` for `InMemoryStore`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl Store for InMemoryStore {
    /// What: claim under one lock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn claim(&self, record: IdempotencyRecord, now: SystemTime) -> Result<Claim, StoreError> {
        let mut records = self.records.lock().map_err(poisoned)?;
        let key = (record.scope.clone(), record.idem_key.clone());
        if let Some(existing) = records.get(&key) {
            if existing.expires_at > now {
                return Ok(Claim::Existing(existing.clone()));
            }
        }
        records.insert(key, record);
        Ok(Claim::Claimed)
    }
    /// What: store the response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn complete(&self, scope: &str, idem_key: &str, status: i32, body: &str) -> Result<(), StoreError> {
        let mut records = self.records.lock().map_err(poisoned)?;
        let r = records.get_mut(&(scope.to_string(), idem_key.to_string())).ok_or(StoreError::NotFound)?;
        r.status = RecordStatus::Completed;
        r.response_status = Some(status);
        r.response_body = Some(body.to_string());
        Ok(())
    }
    /// What: free a key. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn delete(&self, scope: &str, idem_key: &str) -> Result<(), StoreError> {
        let mut records = self.records.lock().map_err(poisoned)?;
        records.remove(&(scope.to_string(), idem_key.to_string())).map(|_| ()).ok_or(StoreError::NotFound)
    }
    /// What: drop expired records; returns how many. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn purge_expired(&self, now: SystemTime) -> Result<usize, StoreError> {
        let mut records = self.records.lock().map_err(poisoned)?;
        let before = records.len();
        records.retain(|_, r| r.expires_at > now);
        Ok(before - records.len())
    }
}

/// The spec's table as executable DDL.
pub const SQL_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS idempotency_records (
    scope TEXT NOT NULL, idem_key TEXT NOT NULL, request_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('in_progress', 'completed')), response_status INTEGER NULL,
    response_body TEXT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    PRIMARY KEY (scope, idem_key));";

/// What: the production store on SQLite. The claim is one statement: insert, or take over the row only
/// if it has expired. Why: the old SQL store was a stub. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: the SQLite database it is given.
pub struct SqlStore {
    conn: Mutex<rusqlite::Connection>,
}

/// What: SystemTime as Unix milliseconds. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn to_ms(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// What: Unix milliseconds as SystemTime. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn from_ms(ms: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(ms.max(0) as u64)
}

/// What: a SQLite error as a store error. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn sql_err(e: rusqlite::Error) -> StoreError {
    StoreError::Database(e.to_string())
}

/// What: methods of `SqlStore`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl SqlStore {
    /// What: wrap a connection and create the table. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (DDL).
    pub fn new(conn: rusqlite::Connection) -> Result<Self, StoreError> {
        conn.execute_batch(SQL_SCHEMA).map_err(sql_err)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// What: a store on a private in-memory database. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn new_in_memory() -> Result<Self, StoreError> {
        Self::new(rusqlite::Connection::open_in_memory().map_err(sql_err)?)
    }
}

/// What: `Store` for `SqlStore`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl Store for SqlStore {
    /// What: atomic claim (UPSERT that only replaces an expired row). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn claim(&self, r: IdempotencyRecord, now: SystemTime) -> Result<Claim, StoreError> {
        let conn = self.conn.lock().map_err(poisoned)?;
        let n = conn
            .execute(
                "INSERT INTO idempotency_records (scope, idem_key, request_fingerprint, status, response_status,
                    response_body, created_at, expires_at) VALUES (?1, ?2, ?3, 'in_progress', NULL, NULL, ?4, ?5)
                 ON CONFLICT (scope, idem_key) DO UPDATE SET request_fingerprint = excluded.request_fingerprint,
                    status = 'in_progress', response_status = NULL, response_body = NULL,
                    created_at = excluded.created_at, expires_at = excluded.expires_at
                 WHERE idempotency_records.expires_at <= ?6",
                rusqlite::params![r.scope, r.idem_key, r.request_fingerprint, to_ms(r.created_at), to_ms(r.expires_at), to_ms(now)],
            )
            .map_err(sql_err)?;
        if n == 1 {
            return Ok(Claim::Claimed);
        }
        conn.query_row(
            "SELECT scope, idem_key, request_fingerprint, status, response_status, response_body, created_at, expires_at
             FROM idempotency_records WHERE scope = ?1 AND idem_key = ?2",
            rusqlite::params![r.scope, r.idem_key],
            |row| {
                let status: String = row.get(3)?;
                Ok(Claim::Existing(IdempotencyRecord {
                    scope: row.get(0)?,
                    idem_key: row.get(1)?,
                    request_fingerprint: row.get(2)?,
                    status: if status == "completed" { RecordStatus::Completed } else { RecordStatus::InProgress },
                    response_status: row.get(4)?,
                    response_body: row.get(5)?,
                    created_at: from_ms(row.get(6)?),
                    expires_at: from_ms(row.get(7)?),
                }))
            },
        )
        .map_err(sql_err)
    }
    /// What: store the response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn complete(&self, scope: &str, idem_key: &str, status: i32, body: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(poisoned)?;
        let n = conn
            .execute(
                "UPDATE idempotency_records SET status = 'completed', response_status = ?3, response_body = ?4
                 WHERE scope = ?1 AND idem_key = ?2",
                rusqlite::params![scope, idem_key, status, body],
            )
            .map_err(sql_err)?;
        if n == 1 { Ok(()) } else { Err(StoreError::NotFound) }
    }
    /// What: free a key. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn delete(&self, scope: &str, idem_key: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(poisoned)?;
        let n = conn
            .execute("DELETE FROM idempotency_records WHERE scope = ?1 AND idem_key = ?2", rusqlite::params![scope, idem_key])
            .map_err(sql_err)?;
        if n == 1 { Ok(()) } else { Err(StoreError::NotFound) }
    }
    /// What: drop expired rows. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn purge_expired(&self, now: SystemTime) -> Result<usize, StoreError> {
        let conn = self.conn.lock().map_err(poisoned)?;
        conn.execute("DELETE FROM idempotency_records WHERE expires_at <= ?1", rusqlite::params![to_ms(now)]).map_err(sql_err)
    }
}

/// What: SHA-256 hex of `method + " " + path + "\n" + body`. Why: spec fingerprint.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn compute_fingerprint(method: &str, path: &str, body: &str) -> String {
    Sha256::digest(format!("{} {}\n{}", method, path, body).as_bytes()).iter().map(|b| format!("{:02x}", b)).collect()
}

/// What: does this request need a key? POST and PATCH by default. Why: spec `is_required`.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn is_required(method: &str, _path: &str) -> bool {
    matches!(method.to_ascii_uppercase().as_str(), "POST" | "PATCH")
}

/// What: remove expired records now. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
pub fn purge_expired(store: &dyn Store) -> Result<usize, StoreError> {
    store.purge_expired(SystemTime::now())
}

/// What: an RFC 7807 problem response. In: status, type slug, title, detail. Out: (status, content
/// type, JSON body). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn problem(status: i32, slug: &str, title: &str, detail: &str) -> (i32, String, String) {
    let body = serde_json::json!({
        "type": format!("https://developer.example.com/problems/{}", slug),
        "title": title,
        "detail": detail,
    });
    (status, "application/problem+json".to_string(), body.to_string())
}

/// What: run `operation` at most once per (scope, key) and replay its response. Check order (spec):
/// missing key on a required operation -> 400; claim; existing record with a different fingerprint
/// -> 422; same fingerprint in progress -> 409; completed -> the stored status and body. A freshly
/// claimed key runs the operation; success is stored and served as application/json; an `Err` frees the
/// key and returns a 500 problem (its text is not echoed); a panic frees the key and is re-raised.
/// In: scope (the authenticated client id, never from the request body), key, method, path, body,
/// operation. Out: (status, content type, body).
/// Why: spec `handle`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: the store, the clock, and whatever the operation touches (possibly money).
pub fn handle<F>(
    store: &dyn Store,
    scope: String,
    idempotency_key: Option<String>,
    method: String,
    path: String,
    body: String,
    operation: F,
) -> (i32, String, String)
where
    F: FnOnce() -> Result<(i32, String), String>,
{
    let key = match idempotency_key {
        Some(k) if !k.is_empty() && k.len() <= MAX_KEY_LEN => k,
        Some(_) => return problem(400, "idempotency-key-invalid", "Invalid Idempotency-Key", "The Idempotency-Key header must be 1 to 255 characters."),
        None if is_required(&method, &path) => {
            return problem(400, "idempotency-key-missing", "Idempotency-Key is missing", "This operation requires an Idempotency-Key header.")
        }
        None => {
            return match operation() {
                Ok((status, out)) => (status, "application/json".to_string(), out),
                Err(_) => problem(500, "operation-failed", "Operation failed", "The operation did not complete."),
            }
        }
    };
    let now = SystemTime::now();
    let fingerprint = compute_fingerprint(&method, &path, &body);
    let record = IdempotencyRecord {
        scope: scope.clone(),
        idem_key: key.clone(),
        request_fingerprint: fingerprint.clone(),
        status: RecordStatus::InProgress,
        response_status: None,
        response_body: None,
        created_at: now,
        expires_at: now + KEY_TTL,
    };
    match store.claim(record, now) {
        Err(_) => return problem(500, "storage-error", "Storage error", "The idempotency record could not be read."),
        Ok(Claim::Existing(existing)) => {
            if existing.request_fingerprint != fingerprint {
                return problem(422, "idempotency-key-reused", "Idempotency-Key reused", "This key was already used with a different request payload.");
            }
            if existing.status == RecordStatus::InProgress {
                return problem(409, "idempotency-request-outstanding", "Request in progress", "A request with this key is still being processed.");
            }
            return (
                existing.response_status.unwrap_or(200),
                "application/json".to_string(),
                existing.response_body.unwrap_or_default(),
            );
        }
        Ok(Claim::Claimed) => {}
    }
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok((status, out))) => {
            if store.complete(&scope, &key, status, &out).is_err() {
                // The work ran; never let a retry run it again silently. The record stays in progress.
                return problem(500, "storage-error", "Storage error", "The response could not be stored.");
            }
            (status, "application/json".to_string(), out)
        }
        Ok(Err(_)) => {
            let _ = store.delete(&scope, &key);
            problem(500, "operation-failed", "Operation failed", "The operation did not complete; it is safe to retry.")
        }
        Err(panic) => {
            let _ = store.delete(&scope, &key);
            resume_unwind(panic)
        }
    }
}

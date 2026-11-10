//! Idempotency keys: safe retries for POST and PATCH (TIER 3 spec, system 5, from IETF
//! draft-ietf-httpapi-idempotency-key-header-07).
//!
//! What: `handle` claims (scope, key) atomically, runs the operation at most once, stores its response
//! and serves that stored response to identical retries for 24 hours. A missing key on a required
//! operation is 400, a different request under the same key is 422 (even while the first is still in
//! progress), an identical request still in progress is 409; all errors are application/problem+json.
//! An operation that fails with `OpError::Failed` frees the key so a retry can run it; any other error
//! or a panic leaves the key 'uncertain' (retry -> 409 outcome_unknown) until an operator calls
//! `release` or `resolve` (2026-11-10 amendment, IDEM-07/08/10/11, session_012zDydZCZ4AChqhEZ4oVtaP).
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

/// What: a record's state. `Uncertain` (2026-11-10 amendment, IDEM-10): the operation failed with an
/// error that does not prove it did nothing, so the key stays taken until an operator settles it.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordStatus {
    InProgress,
    Completed,
    Uncertain,
}

/// What: the status as stored in SQL. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
impl RecordStatus {
    /// What: the spec's text for the status ('in_progress' | 'completed' | 'uncertain').
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordStatus::InProgress => "in_progress",
            RecordStatus::Completed => "completed",
            RecordStatus::Uncertain => "uncertain",
        }
    }
}

/// What: one row of `idempotency_records`. `seq` is the store's insertion number, used only to break
/// ties in `list_uncertain` (spec common rule: ties by insertion order).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
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
    pub seq: u64,
}

/// What: the status a record really has at `now`: an 'in_progress' record past its expires_at is
/// 'uncertain' (a killed process or any exit the handler could not catch; treating it as absent would
/// charge twice). In: record, now. Out: the effective status.
/// Why: 2026-11-10 amendment (IDEM-07). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn effective_status(r: &IdempotencyRecord, now: SystemTime) -> RecordStatus {
    match r.status {
        RecordStatus::InProgress if r.expires_at <= now => RecordStatus::Uncertain,
        ref s => s.clone(),
    }
}

/// What: one entry of the reconciliation work list. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq)]
pub struct UncertainKey {
    pub scope: String,
    pub idem_key: String,
    pub created_at: SystemTime,
}

/// What: a store failure. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    NotFound,
    Database(String),
}

/// What: how an operation fails. `Failed` is a DEFINITE failure (it did nothing: a validation error, a
/// provider decline): the key is freed and a retry runs again (IDEM-08). `Other` is any other error (a
/// timeout, a dropped connection, a crash after the provider was called): the outcome is unknown, so the
/// key becomes 'uncertain' and a retry gets 409 outcome_unknown (IDEM-10). A panic counts as `Other`.
/// Why: 2026-11-10 amendment (the spec names `OpError::Failed` for Rust).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpError {
    Failed(String),
    Other(String),
}

/// What: the outcome of an atomic claim. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq)]
pub enum Claim {
    /// The key was free (or its 'completed' record had expired); the new in-progress record is now stored.
    Claimed,
    /// A live record already holds the key.
    Existing(IdempotencyRecord),
}

/// What: the storage the handler needs. Why: spec storage contract; `claim` is the atomic
/// insert-if-absent ("so two concurrent requests cannot both run"), treating only an expired
/// 'completed' record as absent; `release` and `resolve` are each one conditional write on an uncertain
/// record (2026-11-10 amendment: of two concurrent calls exactly one returns true).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: whatever the implementation uses.
pub trait Store: Send + Sync {
    /// What: insert the in-progress record unless a live one holds the key. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn claim(&self, record: IdempotencyRecord, now: SystemTime) -> Result<Claim, StoreError>;
    /// What: store the operation's response on the in-progress record. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn complete(&self, scope: &str, idem_key: &str, status: i32, body: &str) -> Result<(), StoreError>;
    /// What: free the key after a definite failure. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn delete(&self, scope: &str, idem_key: &str) -> Result<(), StoreError>;
    /// What: set the in-progress record to 'uncertain' (IDEM-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn mark_uncertain(&self, scope: &str, idem_key: &str) -> Result<(), StoreError>;
    /// What: delete the record only if it is uncertain at `now`; true if this call deleted it.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn release(&self, scope: &str, idem_key: &str, now: SystemTime) -> Result<bool, StoreError>;
    /// What: make an uncertain record 'completed' with this response and expires_at = now + 24h; true if
    /// this call changed it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn resolve(&self, scope: &str, idem_key: &str, status: i32, body: &str, now: SystemTime) -> Result<bool, StoreError>;
    /// What: uncertain records at `now`, oldest first (ties by insertion), at most `limit`.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn list_uncertain(&self, limit: usize, now: SystemTime) -> Result<Vec<UncertainKey>, StoreError>;
    /// What: drop expired 'completed' records only; returns how many. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn purge_expired(&self, now: SystemTime) -> Result<usize, StoreError>;
}

/// What: the in-memory store; `records` is public so tests can age a record.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
#[derive(Default)]
pub struct InMemoryStore {
    pub records: Mutex<HashMap<(String, String), IdempotencyRecord>>,
    next_seq: Mutex<u64>,
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

/// What: `Store` for `InMemoryStore`; every method works under the one records lock, so each is atomic.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
impl Store for InMemoryStore {
    /// What: claim under one lock; only an expired 'completed' record is replaced (2026-11-10 amendment).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn claim(&self, mut record: IdempotencyRecord, now: SystemTime) -> Result<Claim, StoreError> {
        let mut records = self.records.lock().map_err(poisoned)?;
        let key = (record.scope.clone(), record.idem_key.clone());
        if let Some(existing) = records.get(&key) {
            if !(existing.status == RecordStatus::Completed && existing.expires_at <= now) {
                return Ok(Claim::Existing(existing.clone()));
            }
        }
        let mut seq = self.next_seq.lock().map_err(poisoned)?;
        *seq += 1;
        record.seq = *seq;
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
    /// What: mark the record uncertain. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn mark_uncertain(&self, scope: &str, idem_key: &str) -> Result<(), StoreError> {
        let mut records = self.records.lock().map_err(poisoned)?;
        let r = records.get_mut(&(scope.to_string(), idem_key.to_string())).ok_or(StoreError::NotFound)?;
        r.status = RecordStatus::Uncertain;
        Ok(())
    }
    /// What: delete if uncertain, under the lock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn release(&self, scope: &str, idem_key: &str, now: SystemTime) -> Result<bool, StoreError> {
        let mut records = self.records.lock().map_err(poisoned)?;
        let key = (scope.to_string(), idem_key.to_string());
        match records.get(&key) {
            Some(r) if effective_status(r, now) == RecordStatus::Uncertain => {
                records.remove(&key);
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    /// What: complete if uncertain, under the lock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn resolve(&self, scope: &str, idem_key: &str, status: i32, body: &str, now: SystemTime) -> Result<bool, StoreError> {
        let mut records = self.records.lock().map_err(poisoned)?;
        match records.get_mut(&(scope.to_string(), idem_key.to_string())) {
            Some(r) if effective_status(r, now) == RecordStatus::Uncertain => {
                r.status = RecordStatus::Completed;
                r.response_status = Some(status);
                r.response_body = Some(body.to_string());
                r.expires_at = now + KEY_TTL;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    /// What: the uncertain keys, oldest first. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn list_uncertain(&self, limit: usize, now: SystemTime) -> Result<Vec<UncertainKey>, StoreError> {
        let records = self.records.lock().map_err(poisoned)?;
        let mut rows: Vec<&IdempotencyRecord> = records.values().filter(|r| effective_status(r, now) == RecordStatus::Uncertain).collect();
        rows.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.seq.cmp(&b.seq)));
        Ok(rows
            .into_iter()
            .take(limit)
            .map(|r| UncertainKey { scope: r.scope.clone(), idem_key: r.idem_key.clone(), created_at: r.created_at })
            .collect())
    }
    /// What: drop expired completed records; returns how many. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn purge_expired(&self, now: SystemTime) -> Result<usize, StoreError> {
        let mut records = self.records.lock().map_err(poisoned)?;
        let before = records.len();
        records.retain(|_, r| !(r.status == RecordStatus::Completed && r.expires_at <= now));
        Ok(before - records.len())
    }
}

/// The spec's table as executable DDL.
pub const SQL_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS idempotency_records (
    scope TEXT NOT NULL, idem_key TEXT NOT NULL, request_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('in_progress', 'completed', 'uncertain')), response_status INTEGER NULL,
    response_body TEXT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    PRIMARY KEY (scope, idem_key));";

/// SQL condition (after `scope = ?1 AND idem_key = ?2`) that a row is uncertain at time `?N`: stored
/// 'uncertain', or 'in_progress' past its expires_at (2026-11-10 amendment).
const UNCERTAIN_AT: &str = "(status = 'uncertain' OR (status = 'in_progress' AND expires_at <= ?3))";

/// What: the production store on SQLite. The claim is one statement: insert, or take over the row only
/// if it is an expired 'completed' row. Why: the old SQL store was a stub.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the SQLite database it is given.
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

/// What: `Store` for `SqlStore`; each method is one parameterized statement (plus a read after a lost
/// claim). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
impl Store for SqlStore {
    /// What: atomic claim (UPSERT that only replaces an expired 'completed' row). 2026-11-10,
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
                 WHERE idempotency_records.status = 'completed' AND idempotency_records.expires_at <= ?6",
                rusqlite::params![r.scope, r.idem_key, r.request_fingerprint, to_ms(r.created_at), to_ms(r.expires_at), to_ms(now)],
            )
            .map_err(sql_err)?;
        if n == 1 {
            return Ok(Claim::Claimed);
        }
        conn.query_row(
            "SELECT scope, idem_key, request_fingerprint, status, response_status, response_body, created_at, expires_at, rowid
             FROM idempotency_records WHERE scope = ?1 AND idem_key = ?2",
            rusqlite::params![r.scope, r.idem_key],
            |row| {
                let status: String = row.get(3)?;
                Ok(Claim::Existing(IdempotencyRecord {
                    scope: row.get(0)?,
                    idem_key: row.get(1)?,
                    request_fingerprint: row.get(2)?,
                    status: match status.as_str() {
                        "completed" => RecordStatus::Completed,
                        "uncertain" => RecordStatus::Uncertain,
                        _ => RecordStatus::InProgress,
                    },
                    response_status: row.get(4)?,
                    response_body: row.get(5)?,
                    created_at: from_ms(row.get(6)?),
                    expires_at: from_ms(row.get(7)?),
                    seq: row.get::<_, i64>(8)? as u64,
                }))
            },
        )
        .map_err(sql_err)
    }
    /// What: store the response on the in-progress row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn complete(&self, scope: &str, idem_key: &str, status: i32, body: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(poisoned)?;
        let n = conn
            .execute(
                "UPDATE idempotency_records SET status = 'completed', response_status = ?3, response_body = ?4
                 WHERE scope = ?1 AND idem_key = ?2 AND status = 'in_progress'",
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
    /// What: set the in-progress row to 'uncertain'. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn mark_uncertain(&self, scope: &str, idem_key: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(poisoned)?;
        let n = conn
            .execute(
                "UPDATE idempotency_records SET status = 'uncertain' WHERE scope = ?1 AND idem_key = ?2 AND status = 'in_progress'",
                rusqlite::params![scope, idem_key],
            )
            .map_err(sql_err)?;
        if n == 1 { Ok(()) } else { Err(StoreError::NotFound) }
    }
    /// What: one conditional DELETE of an uncertain row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn release(&self, scope: &str, idem_key: &str, now: SystemTime) -> Result<bool, StoreError> {
        let conn = self.conn.lock().map_err(poisoned)?;
        let sql = format!("DELETE FROM idempotency_records WHERE scope = ?1 AND idem_key = ?2 AND {}", UNCERTAIN_AT);
        let n = conn.execute(&sql, rusqlite::params![scope, idem_key, to_ms(now)]).map_err(sql_err)?;
        Ok(n == 1)
    }
    /// What: one conditional UPDATE of an uncertain row to 'completed', expires_at = now + 24h.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn resolve(&self, scope: &str, idem_key: &str, status: i32, body: &str, now: SystemTime) -> Result<bool, StoreError> {
        let conn = self.conn.lock().map_err(poisoned)?;
        let sql = format!(
            "UPDATE idempotency_records SET status = 'completed', response_status = ?4, response_body = ?5, expires_at = ?6
             WHERE scope = ?1 AND idem_key = ?2 AND {}",
            UNCERTAIN_AT
        );
        let n = conn
            .execute(&sql, rusqlite::params![scope, idem_key, to_ms(now), status, body, to_ms(now + KEY_TTL)])
            .map_err(sql_err)?;
        Ok(n == 1)
    }
    /// What: the uncertain rows, oldest first (ties by rowid). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn list_uncertain(&self, limit: usize, now: SystemTime) -> Result<Vec<UncertainKey>, StoreError> {
        let conn = self.conn.lock().map_err(poisoned)?;
        let mut stmt = conn
            .prepare(
                "SELECT scope, idem_key, created_at FROM idempotency_records
                 WHERE status = 'uncertain' OR (status = 'in_progress' AND expires_at <= ?1)
                 ORDER BY created_at, rowid LIMIT ?2",
            )
            .map_err(sql_err)?;
        let rows = stmt
            .query_map(rusqlite::params![to_ms(now), limit as i64], |row| {
                Ok(UncertainKey { scope: row.get(0)?, idem_key: row.get(1)?, created_at: from_ms(row.get(2)?) })
            })
            .map_err(sql_err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sql_err)
    }
    /// What: drop expired completed rows. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn purge_expired(&self, now: SystemTime) -> Result<usize, StoreError> {
        let conn = self.conn.lock().map_err(poisoned)?;
        conn.execute("DELETE FROM idempotency_records WHERE status = 'completed' AND expires_at <= ?1", rusqlite::params![to_ms(now)])
            .map_err(sql_err)
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

/// What: remove expired 'completed' records now (uncertain and in-progress records are kept).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
pub fn purge_expired(store: &dyn Store) -> Result<usize, StoreError> {
    store.purge_expired(SystemTime::now())
}

/// What: operator / reconciliation function: free an 'uncertain' key once reconciliation shows the first
/// attempt did nothing, so a retry runs the operation. In: store, the stored record's scope (never from
/// request input), key. Out: true if this call freed it; false (nothing changed) for a key that is not
/// uncertain. Never exposed as a client route. Why: 2026-11-10 amendment (IDEM-10).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
pub fn release(store: &dyn Store, scope: &str, idempotency_key: &str) -> Result<bool, StoreError> {
    store.release(scope, idempotency_key, SystemTime::now())
}

/// What: operator / reconciliation function: store the outcome reconciliation found for an 'uncertain'
/// key as 'completed' with expires_at = now + 24h, so a retry gets it. In: store, scope, key, status,
/// body. Out: true if this call stored it; false (nothing changed) for a key that is not uncertain.
/// Never exposed as a client route. Why: 2026-11-10 amendment (IDEM-11).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
pub fn resolve(store: &dyn Store, scope: &str, idempotency_key: &str, status: i32, body: &str) -> Result<bool, StoreError> {
    store.resolve(scope, idempotency_key, status, body, SystemTime::now())
}

/// What: operator / reconciliation function: the uncertain keys, oldest first, at most `limit`.
/// In: store, limit. Out: [{scope, idem_key, created_at}]. Why: 2026-11-10 amendment.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
pub fn list_uncertain(store: &dyn Store, limit: usize) -> Result<Vec<UncertainKey>, StoreError> {
    store.list_uncertain(limit, SystemTime::now())
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

/// What: `handle_at` at the current time. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: as `handle_at`.
pub fn handle<F>(
    store: &dyn Store,
    scope: String,
    idempotency_key: Option<String>,
    method: String,
    path: String,
    body: String,
    operation: F,
) -> Result<(i32, String, String), OpError>
where
    F: FnOnce() -> Result<(i32, String), OpError>,
{
    handle_at(store, SystemTime::now(), scope, idempotency_key, method, path, body, operation)
}

/// What: run `operation` at most once per (scope, key) and replay its response. Check order (spec):
/// missing key on a required operation -> 400; claim; existing record with a different fingerprint
/// -> 422 (even while in progress); same fingerprint in progress -> 409; uncertain (stored, or in
/// progress past expires_at) -> 409 problem type "outcome_unknown" and the operation does not run;
/// completed -> the stored status and body. A freshly claimed key runs the operation; success is stored
/// and served as application/json. `Err(OpError::Failed)` deletes the record and is returned (re-raised)
/// so a retry runs again; `Err(OpError::Other)` or a panic sets the record to 'uncertain' and is
/// returned / re-raised (the charge may have happened, so a retry must not run it).
/// In: store, now, scope (the authenticated client id, never from the request body), key, method, path,
/// body, operation. Out: Ok((status, content type, body)) or the operation's own error.
/// Why: spec `handle`; uncertain outcome added by the 2026-11-10 amendment (IDEM-07/08/10).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: the store, and whatever the operation touches (possibly money).
#[allow(clippy::too_many_arguments)]
pub fn handle_at<F>(
    store: &dyn Store,
    now: SystemTime,
    scope: String,
    idempotency_key: Option<String>,
    method: String,
    path: String,
    body: String,
    operation: F,
) -> Result<(i32, String, String), OpError>
where
    F: FnOnce() -> Result<(i32, String), OpError>,
{
    let key = match idempotency_key {
        Some(k) if !k.is_empty() && k.len() <= MAX_KEY_LEN => k,
        Some(_) => return Ok(problem(400, "idempotency-key-invalid", "Invalid Idempotency-Key", "The Idempotency-Key header must be 1 to 255 characters.")),
        None if is_required(&method, &path) => {
            return Ok(problem(400, "idempotency-key-missing", "Idempotency-Key is missing", "This operation requires an Idempotency-Key header."))
        }
        None => {
            let (status, out) = operation()?;
            return Ok((status, "application/json".to_string(), out));
        }
    };
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
        seq: 0,
    };
    match store.claim(record, now) {
        Err(_) => return Ok(problem(500, "storage-error", "Storage error", "The idempotency record could not be read.")),
        Ok(Claim::Existing(existing)) => {
            if existing.request_fingerprint != fingerprint {
                return Ok(problem(422, "idempotency-key-reused", "Idempotency-Key reused", "This key was already used with a different request payload."));
            }
            return Ok(match effective_status(&existing, now) {
                RecordStatus::InProgress => {
                    problem(409, "idempotency-request-outstanding", "Request in progress", "A request with this key is still being processed.")
                }
                RecordStatus::Uncertain => problem(
                    409,
                    "outcome_unknown",
                    "Outcome unknown",
                    "The first request with this key ended without a known outcome; it will not be run again until it is reconciled.",
                ),
                RecordStatus::Completed => (
                    existing.response_status.unwrap_or(200),
                    "application/json".to_string(),
                    existing.response_body.unwrap_or_default(),
                ),
            });
        }
        Ok(Claim::Claimed) => {}
    }
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok((status, out))) => {
            if store.complete(&scope, &key, status, &out).is_err() {
                // The work ran; never let a retry run it again silently. The record stays in progress.
                return Ok(problem(500, "storage-error", "Storage error", "The response could not be stored."));
            }
            Ok((status, "application/json".to_string(), out))
        }
        Ok(Err(OpError::Failed(msg))) => {
            let _ = store.delete(&scope, &key);
            Err(OpError::Failed(msg))
        }
        Ok(Err(other)) => {
            let _ = store.mark_uncertain(&scope, &key);
            Err(other)
        }
        Err(panic) => {
            let _ = store.mark_uncertain(&scope, &key);
            resume_unwind(panic)
        }
    }
}

//! File uploads: validated storage and expiring signed download links (TIER 3 spec, system 3,
//! from the OWASP File Upload Cheat Sheet).
//!
//! What: `FileUploads` accepts a file from an org member, checks its extension against an allowlist,
//! its size against a limit and its first bytes against the real signature for that extension, stores
//! the bytes under a random name in a configured directory, and records metadata in a `FileStore`.
//! Downloads go through HMAC-SHA256 signed links over (file_id, expires_at) that expire, are compared in
//! constant time, and re-check the caller's membership. Deleted files can no longer be linked or read.
//! Why: the earlier Rust build did not compile (missing `HashSet` import, non-`Clone` store, an error
//! type without `PartialEq`), took no caller on download, accepted 4-byte PNG/GIF prefixes and used the
//! wall clock in its tests. Repaired 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: files in the configured storage directory; SQLite through `SqliteFileStore` when used;
//! no network, no money.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// What: every way an upload, link or download can fail. In: none. Out: an error value that tests
/// compare with `assert_eq!`. Why: the old enum wrapped `std::io::Error`, which has no `PartialEq`,
/// so no test compiled; storage errors now carry a message string instead.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileUploadError {
    /// The caller is not a member of the file's org (or not the owner, for delete).
    Unauthorized,
    /// No file with that id in that org.
    NotFound,
    /// The extension is not in the allowlist, or the name has no extension.
    InvalidExtension,
    /// The bytes are larger than the configured limit.
    SizeLimitExceeded,
    /// The first bytes do not match the extension's signature (or a text file holds NUL bytes).
    InvalidMagicBytes,
    /// Nothing is left of the name after sanitising.
    InvalidFilename,
    /// Writing or reading the stored bytes, or the metadata store, failed.
    StorageError(String),
    /// The link is malformed or its signature does not match.
    InvalidToken,
    /// The link's expiry time has passed.
    TokenExpired,
    /// The file was soft-deleted.
    FileDeleted,
    /// The requested link lifetime is outside 1..=86400 seconds.
    InvalidTtl,
}

/// What: `std::fmt::Display` for `FileUploadError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl std::fmt::Display for FileUploadError {
    /// What: a short human message for the error. In: the error. Out: text (never secret data).
    /// Why: errors are shown to callers; the old enum relied on a derive crate.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileUploadError::StorageError(m) => write!(f, "storage error: {}", m),
            other => write!(f, "{:?}", other),
        }
    }
}

/// What: `std::error::Error` for `FileUploadError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl std::error::Error for FileUploadError {}

/// What: the metadata row for one stored file (the spec's `files` table). In/Out: plain data.
/// Why: unchanged shape, kept for the tests. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: nothing.
#[derive(Debug, Clone, PartialEq)]
pub struct FileRecord {
    pub id: String,
    pub org_id: String,
    pub owner_user_id: String,
    pub stored_name: String,
    pub original_name: String,
    pub extension: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub sha256: [u8; 32],
    pub created_at: u64,
    pub deleted_at: Option<u64>,
}

/// What: the reads and writes file uploads need from a metadata store. In: records and ids.
/// Out: records, or `StorageError`. Why: the spec's storage contract (an in-memory store for tests and
/// a SQL store for production). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: whatever the implementation stores to.
pub trait FileStore: Send + Sync {
    /// Save a new record whose `id` the service generated.
    fn insert_file(&self, record: &FileRecord) -> Result<(), FileUploadError>;
    /// Load a record by id, deleted or not; `None` when there is none.
    fn get_file(&self, file_id: &str) -> Option<FileRecord>;
    /// Mark a record deleted at `deleted_at`; `NotFound` when there is none.
    fn soft_delete_file(&self, file_id: &str, deleted_at: u64) -> Result<(), FileUploadError>;
}

/// What: an in-memory `FileStore`; clones share the same data. In/Out: see `FileStore`.
/// Why: tests need one store seen by several services (the old struct was not `Clone`, so the tests
/// did not compile). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
#[derive(Clone, Default)]
pub struct InMemoryFileStore {
    data: Arc<Mutex<HashMap<String, FileRecord>>>,
}

/// What: methods of `InMemoryFileStore`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl InMemoryFileStore {
    /// What: an empty store. In: none. Out: the store. Why: test and example setup.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
    pub fn new() -> Self {
        Self::default()
    }
}

/// What: `FileStore` for `InMemoryFileStore`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl FileStore for InMemoryFileStore {
    /// What: insert a record, refusing a duplicate id. In: the record. Out: `()` or `StorageError`.
    /// Why: ids are random; a collision must not overwrite another file.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
    fn insert_file(&self, record: &FileRecord) -> Result<(), FileUploadError> {
        let mut data = self.data.lock().map_err(|_| FileUploadError::StorageError("lock poisoned".into()))?;
        if data.contains_key(&record.id) {
            return Err(FileUploadError::StorageError("duplicate file id".into()));
        }
        data.insert(record.id.clone(), record.clone());
        Ok(())
    }

    /// What: copy of the record with this id. In: id. Out: `Option<FileRecord>`. Why: lookups.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
    fn get_file(&self, file_id: &str) -> Option<FileRecord> {
        self.data.lock().ok()?.get(file_id).cloned()
    }

    /// What: set `deleted_at` once. In: id, time. Out: `()` or `NotFound`. Why: soft delete keeps
    /// the audit trail. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
    fn soft_delete_file(&self, file_id: &str, deleted_at: u64) -> Result<(), FileUploadError> {
        let mut data = self.data.lock().map_err(|_| FileUploadError::StorageError("lock poisoned".into()))?;
        match data.get_mut(file_id) {
            Some(r) => {
                if r.deleted_at.is_none() {
                    r.deleted_at = Some(deleted_at);
                }
                Ok(())
            }
            None => Err(FileUploadError::NotFound),
        }
    }
}

/// What: the production `FileStore` on SQLite, with the spec's `files` table as DDL.
/// In/Out: see `FileStore`. Why: the old "SQL store" was a stub that failed every call.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the SQLite database it is given.
pub struct SqliteFileStore {
    conn: Mutex<rusqlite::Connection>,
}

/// What: methods of `SqliteFileStore`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl SqliteFileStore {
    /// What: wrap a connection and create the `files` table if missing. In: an open connection.
    /// Out: the store or `StorageError`. Why: executable schema per the spec.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (DDL).
    pub fn new(conn: rusqlite::Connection) -> Result<Self, FileUploadError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY, org_id TEXT NOT NULL, owner_user_id TEXT NOT NULL,
                stored_name TEXT NOT NULL UNIQUE, original_name TEXT NOT NULL, extension TEXT NOT NULL,
                mime_type TEXT NOT NULL, size_bytes INTEGER NOT NULL, sha256 BLOB NOT NULL,
                created_at INTEGER NOT NULL, deleted_at INTEGER NULL);
             CREATE INDEX IF NOT EXISTS files_org ON files(org_id);",
        )
        .map_err(sql_err)?;
        Ok(Self { conn: Mutex::new(conn) })
    }
}

/// What: turn a SQLite error into a `StorageError` without leaking the query. In: the error.
/// Out: `FileUploadError`. Why: one mapping for every SQL call. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn sql_err(e: rusqlite::Error) -> FileUploadError {
    FileUploadError::StorageError(e.to_string())
}

/// What: `FileStore` for `SqliteFileStore`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl FileStore for SqliteFileStore {
    /// What: parameterised INSERT of one record. In: record. Out: `()` or `StorageError`.
    /// Why: production storage. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn insert_file(&self, r: &FileRecord) -> Result<(), FileUploadError> {
        let conn = self.conn.lock().map_err(|_| FileUploadError::StorageError("lock poisoned".into()))?;
        conn.execute(
            "INSERT INTO files (id, org_id, owner_user_id, stored_name, original_name, extension, mime_type,
                                size_bytes, sha256, created_at, deleted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![r.id, r.org_id, r.owner_user_id, r.stored_name, r.original_name, r.extension,
                r.mime_type, r.size_bytes as i64, r.sha256.to_vec(), r.created_at as i64,
                r.deleted_at.map(|d| d as i64)],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    /// What: parameterised SELECT by id. In: id. Out: the record or `None`. Why: lookups.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
    fn get_file(&self, file_id: &str) -> Option<FileRecord> {
        let conn = self.conn.lock().ok()?;
        conn.query_row(
            "SELECT id, org_id, owner_user_id, stored_name, original_name, extension, mime_type, size_bytes,
                    sha256, created_at, deleted_at FROM files WHERE id = ?1",
            rusqlite::params![file_id],
            |row| {
                let hash: Vec<u8> = row.get(8)?;
                let mut sha256 = [0u8; 32];
                if hash.len() == 32 {
                    sha256.copy_from_slice(&hash);
                }
                Ok(FileRecord {
                    id: row.get(0)?,
                    org_id: row.get(1)?,
                    owner_user_id: row.get(2)?,
                    stored_name: row.get(3)?,
                    original_name: row.get(4)?,
                    extension: row.get(5)?,
                    mime_type: row.get(6)?,
                    size_bytes: row.get::<_, i64>(7)? as u64,
                    sha256,
                    created_at: row.get::<_, i64>(9)? as u64,
                    deleted_at: row.get::<_, Option<i64>>(10)?.map(|d| d as u64),
                })
            },
        )
        .ok()
    }

    /// What: set `deleted_at` once. In: id, time. Out: `()` or `NotFound`. Why: soft delete.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (write).
    fn soft_delete_file(&self, file_id: &str, deleted_at: u64) -> Result<(), FileUploadError> {
        let conn = self.conn.lock().map_err(|_| FileUploadError::StorageError("lock poisoned".into()))?;
        let exists: i64 = conn
            .query_row("SELECT COUNT(*) FROM files WHERE id = ?1", rusqlite::params![file_id], |r| r.get(0))
            .map_err(sql_err)?;
        if exists == 0 {
            return Err(FileUploadError::NotFound);
        }
        conn.execute(
            "UPDATE files SET deleted_at = ?2 WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![file_id, deleted_at as i64],
        )
        .map_err(sql_err)?;
        Ok(())
    }
}

/// What: answers "is this user a member of this org?". In: user id, org id. Out: bool.
/// Why: the spec's "only allow authorized users"; membership lives in the org system, so it is
/// injected. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: whatever the implementation reads.
pub trait Authorizer: Send + Sync {
    /// What: `is_member` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn is_member(&self, user_id: &str, org_id: &str) -> bool;
}

/// What: test authorizer that says yes to everyone. Why: test fixture.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub struct AlwaysAuthorizer;

/// What: `Authorizer` for `AlwaysAuthorizer`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl Authorizer for AlwaysAuthorizer {
    /// What: `is_member` of `Authorizer for AlwaysAuthorizer`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn is_member(&self, _user_id: &str, _org_id: &str) -> bool {
        true
    }
}

/// What: test authorizer that says no to everyone. Why: test fixture for non-members.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub struct NeverAuthorizer;

/// What: `Authorizer` for `NeverAuthorizer`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl Authorizer for NeverAuthorizer {
    /// What: `is_member` of `Authorizer for NeverAuthorizer`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn is_member(&self, _user_id: &str, _org_id: &str) -> bool {
        false
    }
}

/// What: the time source, in Unix seconds. In: none. Out: seconds. Why: link expiry must be testable
/// without sleeping (the old test slept 2 s on the wall clock). 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the system clock for `SystemClock` only.
pub trait Clock: Send + Sync {
    /// What: `now` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn now(&self) -> u64;
}

/// What: the real clock. Why: production default. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: the system clock.
pub struct SystemClock;

/// What: `Clock` for `SystemClock`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl Clock for SystemClock {
    /// What: `now` of `Clock for SystemClock`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn now(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }
}

/// What: a settable clock; clones share the same time. In: a start time. Out: the clock.
/// Why: deterministic expiry tests. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
#[derive(Clone)]
pub struct ManualClock(Arc<AtomicU64>);

/// What: methods of `ManualClock`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl ManualClock {
    /// What: a clock reading `start`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    pub fn new(start: u64) -> Self {
        ManualClock(Arc::new(AtomicU64::new(start)))
    }
    /// What: move the clock forward by `secs`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

/// What: `Clock` for `ManualClock`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl Clock for ManualClock {
    /// What: `now` of `Clock for ManualClock`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Longest link lifetime the service will sign, in seconds (one day).
pub const MAX_LINK_TTL: u64 = 86_400;
/// Longest display name kept, in characters (spec: "Set a filename length limit").
pub const MAX_FILENAME_LEN: usize = 255;

/// What: the upload service. In: a store, an authorizer, a 32-byte signing secret, a storage
/// directory, a size limit and an extension allowlist. Why: the spec's four functions.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: storage directory, store, clock.
pub struct FileUploads<S: FileStore, A: Authorizer> {
    store: S,
    authorizer: A,
    secret: [u8; 32],
    storage_dir: PathBuf,
    max_size: u64,
    extension_allowlist: HashSet<String>,
    clock: Box<dyn Clock>,
}

/// What: the spec's default extension allowlist. In: none. Out: the set.
/// Why: callers that have no policy of their own get the spec's list.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn default_allowlist() -> HashSet<String> {
    ["pdf", "png", "jpg", "jpeg", "gif", "txt", "csv", "docx", "xlsx"].iter().map(|s| s.to_string()).collect()
}

/// What: methods of `FileUploads<S, A>`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl<S: FileStore, A: Authorizer> FileUploads<S, A> {
    /// What: build the service with the system clock. In: see the struct. Out: the service.
    /// Why: unchanged signature for existing callers; the secret must come from configuration, never
    /// code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing until used.
    pub fn new(
        store: S,
        authorizer: A,
        secret: [u8; 32],
        storage_dir: PathBuf,
        max_size: u64,
        extension_allowlist: HashSet<String>,
    ) -> Self {
        let extension_allowlist = extension_allowlist.into_iter().map(|e| e.to_lowercase()).collect();
        Self { store, authorizer, secret, storage_dir, max_size, extension_allowlist, clock: Box::new(SystemClock) }
    }

    /// What: replace the clock. In: any `Clock`. Out: the service. Why: deterministic expiry tests.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn with_clock(mut self, clock: impl Clock + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// What: validate and store an upload. In: caller, org, original name, bytes, declared content
    /// type (ignored: "it can be spoofed"). Out: the new random file id, or the first failing check in
    /// this order: membership, name, extension, size, signature, storage.
    /// Why: spec rules (allowlist, magic bytes, generated name, size limit, members only).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: writes one file to the storage
    /// directory and one record to the store.
    pub fn upload(
        &self,
        user_id: &str,
        org_id: &str,
        original_filename: &str,
        bytes: &[u8],
        _declared_content_type: &str,
    ) -> Result<String, FileUploadError> {
        if !self.authorizer.is_member(user_id, org_id) {
            return Err(FileUploadError::Unauthorized);
        }
        let display_name = sanitize_filename(original_filename)?;
        let extension = extension_of(&display_name)?;
        if !self.extension_allowlist.contains(&extension) {
            return Err(FileUploadError::InvalidExtension);
        }
        if bytes.len() as u64 > self.max_size {
            return Err(FileUploadError::SizeLimitExceeded);
        }
        if !magic_bytes_match(bytes, &extension) {
            return Err(FileUploadError::InvalidMagicBytes);
        }

        let file_id = random_hex_id();
        let stored_name = file_id.clone();
        fs::create_dir_all(&self.storage_dir).map_err(|e| FileUploadError::StorageError(e.to_string()))?;
        let path = self.storage_dir.join(&stored_name);
        // create_new: never overwrite an existing stored file.
        {
            use std::io::Write;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|e| FileUploadError::StorageError(e.to_string()))?;
            f.write_all(bytes).map_err(|e| FileUploadError::StorageError(e.to_string()))?;
        }

        let record = FileRecord {
            id: file_id.clone(),
            org_id: org_id.to_string(),
            owner_user_id: user_id.to_string(),
            stored_name,
            original_name: display_name,
            mime_type: mime_type_for(&extension).to_string(),
            extension,
            size_bytes: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            created_at: self.clock.now(),
            deleted_at: None,
        };
        if let Err(e) = self.store.insert_file(&record) {
            let _ = fs::remove_file(&path);
            return Err(e);
        }
        Ok(file_id)
    }

    /// What: sign a download link for a live file. In: caller, org, file id, lifetime in seconds
    /// (1..=86400). Out: a token `<file_id>.<expires_at>.<hex HMAC-SHA256>`.
    /// Why: spec "HMAC-signed over (file_id, expires_at) ... expiring"; a deleted file cannot be
    /// linked. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the store and clock.
    pub fn create_download_link(
        &self,
        user_id: &str,
        org_id: &str,
        file_id: &str,
        ttl_seconds: u64,
    ) -> Result<String, FileUploadError> {
        if ttl_seconds == 0 || ttl_seconds > MAX_LINK_TTL {
            return Err(FileUploadError::InvalidTtl);
        }
        let record = self.visible_record(user_id, org_id, file_id)?;
        let expires_at = self.clock.now() + ttl_seconds;
        let sig = self.sign(&record.id, expires_at);
        Ok(format!("{}.{}.{}", record.id, expires_at, to_hex(&sig)))
    }

    /// What: return a file's bytes for a valid, unexpired link, re-checking the caller.
    /// In: caller, token. Out: the bytes, or `InvalidToken` (malformed or bad signature),
    /// `TokenExpired`, `NotFound`, `FileDeleted`, `Unauthorized`.
    /// Why: spec "download() also re-checks the caller may see the file" and constant-time compare.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the store and one stored file.
    pub fn download(&self, user_id: &str, token: &str) -> Result<Vec<u8>, FileUploadError> {
        let (file_id, expires_at, sig) = parse_token(token).ok_or(FileUploadError::InvalidToken)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).map_err(|_| FileUploadError::InvalidToken)?;
        mac.update(signed_message(&file_id, expires_at).as_bytes());
        // verify_slice compares in constant time.
        mac.verify_slice(&sig).map_err(|_| FileUploadError::InvalidToken)?;
        if self.clock.now() >= expires_at {
            return Err(FileUploadError::TokenExpired);
        }
        let record = self.store.get_file(&file_id).ok_or(FileUploadError::NotFound)?;
        if record.deleted_at.is_some() {
            return Err(FileUploadError::FileDeleted);
        }
        if !self.authorizer.is_member(user_id, &record.org_id) {
            return Err(FileUploadError::Unauthorized);
        }
        fs::read(self.storage_dir.join(&record.stored_name)).map_err(|e| FileUploadError::StorageError(e.to_string()))
    }

    /// What: soft-delete a file. In: caller, org, file id. Out: `()`, or `Unauthorized` (not a member,
    /// or not the uploader), `NotFound`, `FileDeleted` (already deleted).
    /// Why: spec "delete_file(user, file_id) -> soft delete"; only the uploader may delete, as in the
    /// Python reference. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: writes the store.
    pub fn delete_file(&self, user_id: &str, org_id: &str, file_id: &str) -> Result<(), FileUploadError> {
        let record = self.visible_record(user_id, org_id, file_id)?;
        if record.owner_user_id != user_id {
            return Err(FileUploadError::Unauthorized);
        }
        self.store.soft_delete_file(&record.id, self.clock.now())
    }

    /// What: load a live file the caller may see. In: caller, org, id. Out: the record, or
    /// `Unauthorized` (caller not in `org_id`), `NotFound` (no such file in that org: never load by id
    /// alone), `FileDeleted`. Why: one IDOR-safe lookup for link and delete.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the store.
    fn visible_record(&self, user_id: &str, org_id: &str, file_id: &str) -> Result<FileRecord, FileUploadError> {
        if !self.authorizer.is_member(user_id, org_id) {
            return Err(FileUploadError::Unauthorized);
        }
        let record = self.store.get_file(file_id).filter(|r| r.org_id == org_id).ok_or(FileUploadError::NotFound)?;
        if record.deleted_at.is_some() {
            return Err(FileUploadError::FileDeleted);
        }
        Ok(record)
    }

    /// What: HMAC-SHA256 of `file_id:expires_at` with the service secret. In: id, expiry.
    /// Out: 32 bytes. Why: link signing. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn sign(&self, file_id: &str, expires_at: u64) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).expect("HMAC accepts any key length");
        mac.update(signed_message(file_id, expires_at).as_bytes());
        mac.finalize().into_bytes().to_vec()
    }
}

/// What: the exact bytes a link signs. In: id, expiry. Out: `"<id>:<expiry>"`. Why: one definition
/// for signing and checking. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn signed_message(file_id: &str, expires_at: u64) -> String {
    format!("{}:{}", file_id, expires_at)
}

/// What: strictly parse `<32 lowercase hex>.<1-12 digits>.<64 lowercase hex>`. In: token.
/// Out: (file id, expiry, signature bytes) or `None`. Why: spec "a malformed token is an ordinary
/// invalid link, never an unhandled parse exception". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: nothing.
fn parse_token(token: &str) -> Option<(String, u64, Vec<u8>)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let (id, exp, sig) = (parts[0], parts[1], parts[2]);
    let is_hex = |s: &str| s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if id.len() != 32 || !is_hex(id) || sig.len() != 64 || !is_hex(sig) {
        return None;
    }
    if exp.is_empty() || exp.len() > 12 || !exp.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let expires_at = exp.parse().ok()?;
    let sig_bytes = (0..32).map(|i| u8::from_str_radix(&sig[i * 2..i * 2 + 2], 16)).collect::<Result<Vec<u8>, _>>().ok()?;
    Some((id.to_string(), expires_at, sig_bytes))
}

/// What: lowercase hex of bytes. In: bytes. Out: string. Why: token and id encoding.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// What: 16 random bytes from the OS as 32 hex chars. In: none. Out: id.
/// Why: spec "store under a random id" generated by the application.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the OS random source.
fn random_hex_id() -> String {
    let mut buf = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    to_hex(&buf)
}

/// What: the display name with path parts, `.`/`..` and control characters removed; remaining path
/// segments are joined with `_` (`../../etc/passwd.png` -> `etc_passwd.png`); at most 255 chars.
/// In: the client's name. Out: the name or `InvalidFilename` when nothing is left.
/// Why: spec "original name only kept for display, sanitised". 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn sanitize_filename(filename: &str) -> Result<String, FileUploadError> {
    let no_controls: String = filename.chars().filter(|c| !c.is_control()).collect();
    let joined = no_controls
        .split(|c| c == '/' || c == '\\')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .collect::<Vec<_>>()
        .join("_");
    let truncated: String = joined.chars().take(MAX_FILENAME_LEN).collect();
    if truncated.is_empty() {
        return Err(FileUploadError::InvalidFilename);
    }
    Ok(truncated)
}

/// What: the lowercase text after the last `.`. In: a sanitised name. Out: the extension, or
/// `InvalidExtension` when there is none. Why: allowlist and signature checks.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn extension_of(name: &str) -> Result<String, FileUploadError> {
    match name.rfind('.') {
        Some(i) if i + 1 < name.len() => Ok(name[i + 1..].to_lowercase()),
        _ => Err(FileUploadError::InvalidExtension),
    }
}

/// What: does the content start with the full signature for its extension? In: bytes, extension.
/// Out: bool. Why: spec signatures (PNG 8 bytes, JPEG FF D8 FF, GIF87a/GIF89a, %PDF-, ZIP 50 4B 03 04;
/// text without NUL); the old code accepted 4-byte prefixes. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn magic_bytes_match(bytes: &[u8], extension: &str) -> bool {
    match extension {
        "png" => bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
        "jpg" | "jpeg" => bytes.starts_with(&[0xFF, 0xD8, 0xFF]),
        "gif" => bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"),
        "pdf" => bytes.starts_with(b"%PDF-"),
        "docx" | "xlsx" => bytes.starts_with(&[0x50, 0x4B, 0x03, 0x04]),
        "txt" | "csv" => !bytes.contains(&0),
        _ => false,
    }
}

/// What: the MIME type the service serves for an extension. In: extension. Out: MIME type.
/// Why: never trust the client's declared type. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: nothing.
fn mime_type_for(extension: &str) -> &'static str {
    match extension {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "pdf" => "application/pdf",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "txt" => "text/plain",
        "csv" => "text/csv",
        _ => "application/octet-stream",
    }
}

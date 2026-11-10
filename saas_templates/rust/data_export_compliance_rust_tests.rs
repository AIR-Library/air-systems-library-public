//! Data export and compliance tests (TIER 2 spec, system 3).
//!
//! Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the old file needed a live Postgres server
//! (`TEST_DATABASE_URL`, and query macros that check SQL against a database at COMPILE time), a
//! real S3 client and an SMTP transport, so it could not build or run on any machine without them. The
//! same five tests now run on in-memory SQLite with the in-memory file storage and mailer; their
//! names and assertions are kept. Changes per test: the export and deletion owner is passed to
//! `check_export_status` and `cancel_deletion` (a record is never loaded by id alone); the deletion
//! token is read from the confirmation email instead of the database, which now stores only its hash.
//! Two spec tests were added (signed link expiry, grace period). Touches: memory only.

use super::*;
use chrono::{TimeZone, Utc};
use std::sync::atomic::{AtomicI64, Ordering};

/// What: a fake audit eraser that records each erase_subject call. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-13). Touches: memory.
#[derive(Clone, Default)]
struct RecordingEraser {
    calls: Arc<Mutex<Vec<i64>>>,
}

/// What: `AuditEraser` for the fake: records the user id. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl AuditEraser for RecordingEraser {
    /// What: record the call. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn erase_subject(&self, user_id: i64) -> Result<(), String> {
        self.calls.lock().unwrap().push(user_id);
        Ok(())
    }
}

/// What: the confirmation token in the last email. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn last_token(mailer: &InMemoryMailer) -> String {
    mailer.sent.lock().unwrap().last().unwrap().body.split("token=").nth(1).unwrap().to_string()
}

/// What: a service with Alice (user 1), in-memory storage and mailer, a recording audit eraser, and a
/// clock the test can move. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the cascade now needs
/// an audit eraser (EXPORT-13). Touches: memory.
fn build_service() -> (ComplianceService, InMemoryMailer, Arc<AtomicI64>) {
    let mailer = InMemoryMailer::default();
    let now = Arc::new(AtomicI64::new(Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap().timestamp()));
    let clock = now.clone();
    let svc = ComplianceService::new(
        Connection::open_in_memory().unwrap(),
        Box::new(InMemoryFileStorage::default()),
        Box::new(mailer.clone()),
        &[7u8; 32],
        "https://example.com",
    )
    .unwrap()
    .with_clock(Box::new(move || Utc.timestamp_opt(clock.load(Ordering::SeqCst), 0).unwrap()))
    .with_audit_eraser(Box::new(RecordingEraser::default()));
    svc.db()
        .execute(
            "INSERT INTO users (id, email, name, created_at, tier, status) VALUES (1, 'alice@example.com', 'Alice', '2025-01-01T00:00:00Z', 'pro', 'active')",
            [],
        )
        .unwrap();
    (svc, mailer, now)
}

// EXPORT-01
// EXPORT-02
// EXPORT-03
#[tokio::test]
async fn test_export_json_flow() {
    let (svc, mailer, _) = build_service();

    // Request export
    let resp = svc.request_data_export(1, ExportFormat::Json).await.expect("request export");
    assert!(resp.success);
    assert_eq!(resp.status, ExportStatus::Pending);

    // Simulate background job completion
    svc.generate_export_file(resp.export_id.clone(), 1, ExportFormat::Json).await.expect("generate export");

    // Check status
    let status = svc.check_export_status(1, resp.export_id.clone()).await.expect("check status");
    assert_eq!(status.status, ExportStatus::Completed);
    assert!(status.file_url.is_some());
    assert!(status.expires_at.unwrap() > Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap());

    // Verify email sent with the download link, and every data category is in the file
    let sent = mailer.sent.lock().unwrap().clone();
    let url = status.file_url.unwrap();
    assert!(sent.iter().any(|m| m.to == "alice@example.com" && m.body.contains(&url)));
    let path = url.split("/compliance/download/").nth(1).unwrap();
    let data: serde_json::Value = serde_json::from_slice(&svc.download(path).unwrap()).unwrap();
    for cat in ["profile", "sessions", "activity", "files", "preferences", "transactions", "audit_trail"] {
        assert!(data.get(cat).is_some(), "missing {}", cat);
    }
    assert_eq!(data["profile"]["email"], "alice@example.com");
}

// EXPORT-01
#[tokio::test]
async fn test_export_csv_flow() {
    let (svc, _, _) = build_service();

    let resp = svc.request_data_export(1, ExportFormat::Csv).await.expect("request export csv");
    svc.generate_export_file(resp.export_id.clone(), 1, ExportFormat::Csv).await.expect("generate csv export");

    let status = svc.check_export_status(1, resp.export_id).await.unwrap();
    assert_eq!(status.status, ExportStatus::Completed);
    assert!(status.file_url.unwrap().ends_with(".csv"));
}

/// What: EXPORT-06/09: a deletion is confirmed with the emailed token (a wrong one is refused) and
/// cancelled within the grace period. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: confirm takes the caller (EXPORT-14).
/// Touches: memory only.
// EXPORT-06
// EXPORT-09
#[tokio::test]
async fn test_deletion_grace_period_and_cancel() {
    let (svc, mailer, _) = build_service();

    // Request deletion
    let del_resp = svc.request_account_deletion(1, DeletionReason::UserRequested).await.expect("request deletion");
    assert_eq!(del_resp.status, DeletionStatus::Pending);

    // Confirm deletion with the token from the confirmation email
    let body = mailer.sent.lock().unwrap().last().unwrap().body.clone();
    let token = body.split("token=").nth(1).unwrap().to_string();
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: confirm now takes the caller (EXPORT-14: own request only)
    assert!(svc.confirm_deletion(1, del_resp.deletion_id.clone(), "wrong").await.is_err());

    let confirm = svc.confirm_deletion(1, del_resp.deletion_id.clone(), &token).await.expect("confirm deletion");
    assert!(confirm.success);

    // Cancel within grace period
    let cancel = svc.cancel_deletion(1, del_resp.deletion_id).await.expect("cancel deletion");
    assert_eq!(cancel.status, DeletionStatus::Cancelled);
}

/// What: EXPORT-07/08: the cascade deletes sessions and API keys and keeps the audit log. Changed
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the API-key assertion was added. Corrected 2026-11-10
/// (session_012zDydZCZ4AChqhEZ4oVtaP, Phase B.2 bug): the kept login row no longer names the user (its
/// user_id is NULL); it asserted the row still carried user_id 1. Touches: memory only.
// EXPORT-07
// EXPORT-08
#[tokio::test]
async fn test_cascade_delete_preserves_audit_log() {
    let (svc, _, _) = build_service();

    // Insert dummy related rows
    svc.db().execute("INSERT INTO sessions (id, user_id) VALUES (?1, ?2)", params!["s1", 1]).unwrap();
    svc.db().execute("INSERT INTO api_keys (id, user_id) VALUES (?1, ?2)", params!["k1", 1]).unwrap();
    svc.db()
        .execute(
            "INSERT INTO audit_log (id, user_id, action, created_at, details) VALUES (?1, ?2, ?3, ?4, ?5)",
            params!["a1", 1, "login", "2026-01-15T12:00:00Z", json!({}).to_string()],
        )
        .unwrap();

    // Directly call cascade delete (as if grace period elapsed)
    svc.cascade_delete_user(1).await.expect("cascade delete");

    // Sessions should be gone
    let sess_cnt: i64 = svc.db().query_row("SELECT COUNT(*) FROM sessions WHERE user_id = ?1", params![1], |r| r.get(0)).unwrap();
    assert_eq!(sess_cnt, 0);
    let key_cnt: i64 = svc.db().query_row("SELECT COUNT(*) FROM api_keys WHERE user_id = ?1", params![1], |r| r.get(0)).unwrap();
    assert_eq!(key_cnt, 0);

    // Audit log must still exist (the login row, plus the cascade's own record), without the user's id
    // (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, Phase B.2: nothing personal remains after the cascade)
    let audit_cnt: i64 = svc
        .db()
        .query_row("SELECT COUNT(*) FROM audit_log WHERE id = 'a1' AND user_id IS NULL AND action = 'login'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(audit_cnt, 1);
    let named: i64 = svc.db().query_row("SELECT COUNT(*) FROM audit_log WHERE user_id = ?1", params![1], |r| r.get(0)).unwrap();
    assert_eq!(named, 0, "no audit row names the deleted user");
}

/// What: EXPORT-10: an admin sees every export and deletion request; a non-admin is refused. Changed
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the lists take the verified caller. Touches: memory only.
// EXPORT-10
#[tokio::test]
async fn test_admin_list_exports_and_deletions() {
    let (svc, _, _) = build_service();

    // Create two exports
    let e1 = svc.request_data_export(1, ExportFormat::Json).await.unwrap();
    let e2 = svc.request_data_export(1, ExportFormat::Csv).await.unwrap();

    // Create a deletion request
    let d1 = svc.request_account_deletion(1, DeletionReason::GdprRequest).await.unwrap();

    // List exports (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the lists take the verified caller and
    // refuse a non-admin)
    let admin = Caller { user_id: 99, is_admin: true };
    let user = Caller { user_id: 1, is_admin: false };
    assert!(matches!(svc.list_exports(&user, None, None).await, Err(ComplianceError::NotAllowed(_))));
    assert!(matches!(svc.list_deletions(&user, None).await, Err(ComplianceError::NotAllowed(_))));
    let list = svc.list_exports(&admin, Some(1), Some(ExportStatus::Pending)).await.unwrap();
    assert_eq!(list.total, 2);
    assert!(list.exports.iter().any(|e| e.id == e1.export_id));
    assert!(list.exports.iter().any(|e| e.id == e2.export_id));

    // List deletions
    let dlist = svc.list_deletions(&admin, Some(DeletionStatus::Pending)).await.unwrap();
    assert_eq!(dlist.total, 1);
    assert_eq!(dlist.deletions[0].id, d1.deletion_id);
}

/// Added 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP), spec "Signed URL works, expires after 7 days":
/// the link downloads, a changed signature does not, and the same link fails after 7 days.
// EXPORT-04
#[tokio::test]
async fn test_signed_link_works_and_expires_after_7_days() {
    let (svc, _, now) = build_service();
    let resp = svc.request_data_export(1, ExportFormat::Json).await.unwrap();
    svc.generate_export_file(resp.export_id.clone(), 1, ExportFormat::Json).await.unwrap();
    let url = svc.check_export_status(1, resp.export_id).await.unwrap().file_url.unwrap();
    let path = url.split("/compliance/download/").nth(1).unwrap().to_string();
    assert!(svc.download(&path).is_ok());
    let mut tampered: Vec<char> = path.chars().collect();
    let i = path.find('/').unwrap() + 1;
    tampered[i] = if tampered[i] == 'a' { 'b' } else { 'a' };
    assert_eq!(svc.download(&tampered.into_iter().collect::<String>()), Err(ComplianceError::InvalidLink));
    now.fetch_add(7 * 86_400, Ordering::SeqCst);
    assert_eq!(svc.download(&path), Err(ComplianceError::LinkExpired));
}

/// Added 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP), spec "30-day grace period enforced": a confirmed
/// deletion does not run before 30 days, runs after, and keeps the audit log. Changed the same day for
/// the EXPORT-05/12 amendment: the reason is user_requested (a statutory reason now has no grace
/// period), will_delete_at is requested_at + 30 days, and confirm takes the caller. Corrected 2026-11-10
/// (Phase B.2 bug): the kept audit rows are counted without user_id, which the cascade now clears, and a
/// cancel after the grace period is the 409 `GracePeriodOver`. Changed 2026-11-10 (Phase B.3 ruling): its
/// status and code are asserted too.
// EXPORT-05
#[tokio::test]
async fn test_deletion_runs_only_after_grace_period() {
    let (svc, mailer, now) = build_service();
    let d = svc.request_account_deletion(1, DeletionReason::UserRequested).await.unwrap();
    let requested_at = Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();
    assert_eq!(d.will_delete_at, requested_at + chrono::Duration::days(30));
    let token = last_token(&mailer);
    let confirm = svc.confirm_deletion(1, d.deletion_id.clone(), &token).await.unwrap();
    assert_eq!(confirm.deletion_scheduled_for, requested_at + chrono::Duration::days(30));
    now.fetch_add(29 * 86_400, Ordering::SeqCst);
    assert_eq!(svc.process_due_deletions().await.unwrap(), 0);
    now.fetch_add(86_400, Ordering::SeqCst);
    let late = svc.cancel_deletion(1, d.deletion_id.clone()).await.unwrap_err();
    assert_eq!(late, ComplianceError::GracePeriodOver);
    // Phase B.3 ruling (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): the exact answer is 409 grace_period_over,
    // and the refused cancel leaves the due deletion to run
    assert_eq!((late.status(), late.code()), (409, "grace_period_over"));
    assert_eq!(svc.process_due_deletions().await.unwrap(), 1);
    let users: i64 = svc.db().query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).unwrap();
    assert_eq!(users, 0);
    let audit: i64 = svc.db().query_row("SELECT COUNT(*) FROM audit_log WHERE user_id IS NULL", [], |r| r.get(0)).unwrap();
    assert!(audit >= 3);
    let named: i64 = svc.db().query_row("SELECT COUNT(*) FROM audit_log WHERE user_id = 1", [], |r| r.get(0)).unwrap();
    assert_eq!(named, 0);
}

/// What: EXPORT-16: a pending (unconfirmed) request is cancelled even after will_delete_at; a confirmed one is
/// cancelled one second before will_delete_at, and gets 409 grace_period_over exactly at it and after it, staying
/// confirmed. In: none. Out: panics on a wrong answer. Why: spec Phase B.3 / B.4 rulings.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
// EXPORT-16
#[tokio::test]
async fn test_cancel_pending_always_confirmed_until_will_delete_at() {
    let day = 86_400;
    // pending, past will_delete_at: cancelled
    let (svc, _mailer, now) = build_service();
    let d = svc.request_account_deletion(1, DeletionReason::UserRequested).await.unwrap();
    now.fetch_add(31 * day, Ordering::SeqCst);
    assert_eq!(svc.cancel_deletion(1, d.deletion_id.clone()).await.unwrap().status, DeletionStatus::Cancelled);
    // confirmed, one second before will_delete_at: cancelled
    let (svc, mailer, now) = build_service();
    let d = svc.request_account_deletion(1, DeletionReason::UserRequested).await.unwrap();
    svc.confirm_deletion(1, d.deletion_id.clone(), &last_token(&mailer)).await.unwrap();
    now.fetch_add(30 * day - 1, Ordering::SeqCst);
    assert_eq!(svc.cancel_deletion(1, d.deletion_id.clone()).await.unwrap().status, DeletionStatus::Cancelled);
    // confirmed, exactly at and after will_delete_at: 409, still confirmed
    for extra in [0, 1, day] {
        let (svc, mailer, now) = build_service();
        let d = svc.request_account_deletion(1, DeletionReason::UserRequested).await.unwrap();
        svc.confirm_deletion(1, d.deletion_id.clone(), &last_token(&mailer)).await.unwrap();
        now.fetch_add(30 * day + extra, Ordering::SeqCst);
        let err = svc.cancel_deletion(1, d.deletion_id.clone()).await.unwrap_err();
        assert_eq!((err.status(), err.code()), (409, "grace_period_over"));
        let status: String = svc.db().query_row("SELECT status FROM deletion_requests WHERE id = ?1", rusqlite::params![d.deletion_id], |r| r.get(0)).unwrap();
        assert_eq!(status, "approved");
    }
}

/// Added 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP), CodeRabbit review on PR 19: an export made
/// late in the grace period has a link that is still inside its 7 days when the deletion runs. After
/// the deletion that link is refused, the file is gone from storage and the export row is gone.
/// Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP) for the EXPORT-12/13 amendment: the reason is
/// user_requested (a statutory reason now has no grace period) and the service has an audit eraser.
/// Corrected 2026-11-10 (Phase B.2 bug): the cascade's audit row no longer carries user_id 1.
/// Touches: memory only.
#[tokio::test]
async fn test_deletion_removes_exports_and_refuses_old_link() {
    let storage = InMemoryFileStorage::default();
    let mailer = InMemoryMailer::default();
    let now = Arc::new(AtomicI64::new(Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap().timestamp()));
    let clock = now.clone();
    let svc = ComplianceService::new(Connection::open_in_memory().unwrap(), Box::new(storage.clone()), Box::new(mailer.clone()), &[7u8; 32], "https://example.com")
        .unwrap()
        .with_clock(Box::new(move || Utc.timestamp_opt(clock.load(Ordering::SeqCst), 0).unwrap()))
        .with_audit_eraser(Box::new(RecordingEraser::default()));
    svc.db()
        .execute("INSERT INTO users (id, email, name, created_at, tier, status) VALUES (1, 'alice@example.com', 'Alice', '2025-01-01T00:00:00Z', 'pro', 'active')", [])
        .unwrap();
    let d = svc.request_account_deletion(1, DeletionReason::UserRequested).await.unwrap();
    let token = last_token(&mailer);
    svc.confirm_deletion(1, d.deletion_id.clone(), &token).await.unwrap();

    // Day 25: export, so the 7-day link is still valid on day 30.
    now.fetch_add(25 * 86_400, Ordering::SeqCst);
    let e = svc.request_data_export(1, ExportFormat::Json).await.unwrap();
    svc.generate_export_file(e.export_id.clone(), 1, ExportFormat::Json).await.unwrap();
    let url = svc.check_export_status(1, e.export_id.clone()).await.unwrap().file_url.unwrap();
    let path = url.split("/compliance/download/").nth(1).unwrap().to_string();
    assert!(svc.download(&path).is_ok());
    assert_eq!(storage.files.lock().unwrap().len(), 1);

    // Day 30: the grace period is over and the deletion runs.
    now.fetch_add(5 * 86_400, Ordering::SeqCst);
    assert_eq!(svc.process_due_deletions().await.unwrap(), 1);
    assert_eq!(svc.download(&path), Err(ComplianceError::ExportNotFound));
    assert!(storage.files.lock().unwrap().is_empty(), "export file must be removed from storage");
    let rows: i64 = svc.db().query_row("SELECT COUNT(*) FROM export_requests WHERE user_id = 1", [], |r| r.get(0)).unwrap();
    assert_eq!(rows, 0);
    let audit: i64 = svc.db().query_row("SELECT COUNT(*) FROM audit_log WHERE user_id IS NULL AND action = 'user_deleted_cascade'", [], |r| r.get(0)).unwrap();
    assert_eq!(audit, 1);
}

/// What: a store whose `delete` fails until `fail` is cleared (storage outage during a deletion).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, CodeRabbit review on PR 19. Touches: memory.
#[derive(Clone, Default)]
struct FlakyDeleteStorage {
    inner: InMemoryFileStorage,
    fail: Arc<std::sync::atomic::AtomicBool>,
}

/// What: `FileStorage` for the test store: put/get pass through, `delete` errors while `fail` is set.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
impl FileStorage for FlakyDeleteStorage {
    /// What: store the file in memory. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn put(&self, key: &str, bytes: &[u8]) -> Result<(), String> {
        self.inner.put(key, bytes)
    }
    /// What: read the file from memory. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.inner.get(key)
    }
    /// What: fail while `fail` is set, else remove. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn delete(&self, key: &str) -> Result<(), String> {
        if self.fail.load(Ordering::SeqCst) {
            return Err("storage unavailable".into());
        }
        self.inner.delete(key)
    }
}

/// Added 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP), CodeRabbit review on PR 19: if the export files
/// cannot be removed, nothing is deleted and the request stays approved; the next run completes it.
/// Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the service has an audit eraser, confirm takes
/// the caller and the admin list takes an admin caller. Touches: memory only.
#[tokio::test]
async fn test_deletion_is_retried_when_export_cleanup_fails() {
    let storage = FlakyDeleteStorage::default();
    let mailer = InMemoryMailer::default();
    let now = Arc::new(AtomicI64::new(Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap().timestamp()));
    let clock = now.clone();
    let svc = ComplianceService::new(Connection::open_in_memory().unwrap(), Box::new(storage.clone()), Box::new(mailer.clone()), &[7u8; 32], "https://example.com")
        .unwrap()
        .with_clock(Box::new(move || Utc.timestamp_opt(clock.load(Ordering::SeqCst), 0).unwrap()))
        .with_audit_eraser(Box::new(RecordingEraser::default()));
    svc.db()
        .execute("INSERT INTO users (id, email, name, created_at, tier, status) VALUES (1, 'alice@example.com', 'Alice', '2025-01-01T00:00:00Z', 'pro', 'active')", [])
        .unwrap();
    let e = svc.request_data_export(1, ExportFormat::Csv).await.unwrap();
    svc.generate_export_file(e.export_id, 1, ExportFormat::Csv).await.unwrap();
    let d = svc.request_account_deletion(1, DeletionReason::UserRequested).await.unwrap();
    let token = last_token(&mailer);
    svc.confirm_deletion(1, d.deletion_id.clone(), &token).await.unwrap();
    now.fetch_add(30 * 86_400, Ordering::SeqCst);

    storage.fail.store(true, Ordering::SeqCst);
    assert_eq!(svc.process_due_deletions().await.unwrap(), 0);
    let users: i64 = svc.db().query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).unwrap();
    assert_eq!(users, 1, "nothing is deleted while the export files remain");
    let pending = svc.list_deletions(&Caller { user_id: 99, is_admin: true }, Some(DeletionStatus::Approved)).await.unwrap();
    assert_eq!(pending.total, 1);

    storage.fail.store(false, Ordering::SeqCst);
    assert_eq!(svc.process_due_deletions().await.unwrap(), 1);
    assert!(storage.inner.files.lock().unwrap().is_empty());
    let users: i64 = svc.db().query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).unwrap();
    assert_eq!(users, 0);
}

/// What: EXPORT-11: every export and deletion request and action is in the audit log with its ids
/// (the why-chain: which request, which reason), in order. In: none. Out: panics on a wrong log.
/// Why: the spec's required test EXPORT-11 had no Rust test. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory only.
// EXPORT-11
#[tokio::test]
async fn test_all_requests_are_audited() {
    let (svc, mailer, _) = build_service();
    let e = svc.request_data_export(1, ExportFormat::Json).await.unwrap();
    svc.generate_export_file(e.export_id.clone(), 1, ExportFormat::Json).await.unwrap();
    let d = svc.request_account_deletion(1, DeletionReason::UserRequested).await.unwrap();
    svc.confirm_deletion(1, d.deletion_id.clone(), &last_token(&mailer)).await.unwrap();
    svc.cancel_deletion(1, d.deletion_id.clone()).await.unwrap();
    let rows: Vec<(String, String)> = {
        let conn = svc.db();
        let mut stmt = conn.prepare("SELECT action, details FROM audit_log WHERE user_id = 1 ORDER BY rowid").unwrap();
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        rows
    };
    let actions: Vec<&str> = rows.iter().map(|(a, _)| a.as_str()).collect();
    assert_eq!(actions, ["data_export_requested", "data_export_completed", "deletion_requested", "deletion_confirmed", "deletion_cancelled"]);
    let details: Vec<Value> = rows.iter().map(|(_, d)| serde_json::from_str(d).unwrap()).collect();
    assert_eq!(details[0]["export_id"], e.export_id.as_str());
    assert_eq!(details[2]["deletion_id"], d.deletion_id.as_str());
    assert_eq!(details[2]["reason"], "user_requested");
}

/// What: EXPORT-12: a gdpr_request and a gdpr_right_to_be_forgotten request are not held for 30 days:
/// will_delete_at = requested_at, nothing is deleted before confirm, and confirm runs the cascade before
/// it returns (status completed, deleted_at = deletion_scheduled_for = now). In: none. Out: panics.
/// Why: 2026-11-10 amendment (EXPORT-12). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
// EXPORT-12
#[tokio::test]
async fn test_statutory_deletion_has_no_grace_period() {
    for reason in [DeletionReason::GdprRequest, DeletionReason::GdprRightToBeForgotten] {
        let (svc, mailer, now) = build_service();
        let requested_at = Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();
        let d = svc.request_account_deletion(1, reason).await.unwrap();
        assert_eq!(d.will_delete_at, requested_at);
        assert_eq!(svc.process_due_deletions().await.unwrap(), 0, "nothing runs before confirm");
        now.fetch_add(3600, Ordering::SeqCst);
        let confirm = svc.confirm_deletion(1, d.deletion_id.clone(), &last_token(&mailer)).await.unwrap();
        let confirmed_at = requested_at + chrono::Duration::hours(1);
        assert_eq!(confirm.deletion_scheduled_for, confirmed_at);
        let users: i64 = svc.db().query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).unwrap();
        assert_eq!(users, 0, "{:?}: deleted on confirm", reason);
        let list = svc.list_deletions(&Caller { user_id: 99, is_admin: true }, None).await.unwrap();
        assert_eq!(list.deletions[0].status, DeletionStatus::Completed);
        assert_eq!(list.deletions[0].deleted_at, Some(confirmed_at));
        assert_eq!(list.deletions[0].scheduled_for, confirmed_at);
    }
}

/// What: an audit eraser on its own connection to the same shared-cache in-memory database, reading
/// uncommitted rows, so it can see the cascade's state at the moment it is called: whether the user
/// row still exists, the last audit row's action and its user_id, and how many audit rows still name the
/// user. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-13). Changed 2026-11-10 (Phase B.2 bug): it
/// read the last action "for the user"; the cascade now clears the user's id on the local audit rows just
/// before calling the eraser, so it reads the last row overall and the count still naming the user.
/// Touches: in-memory SQLite (read).
struct ObservingEraser {
    conn: Mutex<Connection>,
    seen: Arc<Mutex<Vec<(i64, i64, Option<(String, Option<i64>)>, i64)>>>,
}

/// What: `AuditEraser` for the observing fake. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl AuditEraser for ObservingEraser {
    /// What: record (user id, user rows left, last audit row's (action, user_id), audit rows still naming
    /// the user). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP; changed the same day (Phase B.2 bug).
    /// Touches: in-memory SQLite (read).
    fn erase_subject(&self, user_id: i64) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let users: i64 = conn.query_row("SELECT COUNT(*) FROM users WHERE id = ?1", params![user_id], |r| r.get(0)).map_err(|e| e.to_string())?;
        let last: Option<(String, Option<i64>)> = conn
            .query_row("SELECT action, user_id FROM audit_log ORDER BY rowid DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()
            .map_err(|e| e.to_string())?;
        let named: i64 = conn.query_row("SELECT COUNT(*) FROM audit_log WHERE user_id = ?1", params![user_id], |r| r.get(0)).map_err(|e| e.to_string())?;
        self.seen.lock().unwrap().push((user_id, users, last, named));
        Ok(())
    }
}

/// What: a fake audit eraser that always fails. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
struct FailingEraser;

/// What: `AuditEraser` for the failing fake. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl AuditEraser for FailingEraser {
    /// What: always an error. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn erase_subject(&self, _user_id: i64) -> Result<(), String> {
        Err("audit store down".into())
    }
}

/// What: EXPORT-13: the cascade deletes the user's rows, logs 'user_deleted_cascade', then calls
/// erase_subject(user_id) LAST (when it is called the user row is already gone and the last audit row
/// for the user is the cascade's); nothing is logged for the user after it; deletion_requests.user_id
/// is NULL once completed. A failing eraser rolls the whole cascade back, and with no eraser configured
/// nothing is deleted. In: none. Out: panics on a wrong order. Why: 2026-11-10 amendment (EXPORT-13).
/// Corrected 2026-11-10 (Phase B.2 bug): the local audit rows no longer carry user_id 1 when the eraser
/// runs or after, so the "last row" checks read the last row overall and its NULL user_id.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite (shared cache).
// EXPORT-13
#[tokio::test]
async fn test_cascade_calls_audit_eraser_last() {
    use rusqlite::OpenFlags;
    let uri = "file:export13?mode=memory&cache=shared";
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_URI;
    let main = Connection::open_with_flags(uri, flags).unwrap();
    let observer = Connection::open_with_flags(uri, flags).unwrap();
    observer.execute_batch("PRAGMA read_uncommitted = true;").unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mailer = InMemoryMailer::default();
    let svc = ComplianceService::new(main, Box::new(InMemoryFileStorage::default()), Box::new(mailer.clone()), &[7u8; 32], "https://example.com")
        .unwrap()
        .with_audit_eraser(Box::new(ObservingEraser { conn: Mutex::new(observer), seen: seen.clone() }));
    svc.db()
        .execute("INSERT INTO users (id, email, name, created_at, tier, status) VALUES (1, 'alice@example.com', 'Alice', '2025-01-01T00:00:00Z', 'pro', 'active')", [])
        .unwrap();
    svc.db().execute("INSERT INTO sessions (id, user_id) VALUES ('s1', 1)", []).unwrap();
    let d = svc.request_account_deletion(1, DeletionReason::GdprRightToBeForgotten).await.unwrap();
    svc.confirm_deletion(1, d.deletion_id.clone(), &last_token(&mailer)).await.unwrap();

    assert_eq!(*seen.lock().unwrap(), vec![(1, 0, Some(("user_deleted_cascade".to_string(), None)), 0)]);
    let last: (String, Option<i64>) =
        svc.db().query_row("SELECT action, user_id FROM audit_log ORDER BY rowid DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!(last, ("user_deleted_cascade".to_string(), None), "nothing is logged for the user after the eraser");
    let named: i64 = svc.db().query_row("SELECT COUNT(*) FROM audit_log WHERE user_id = 1", [], |r| r.get(0)).unwrap();
    assert_eq!(named, 0, "no audit row names the erased user");
    let (uid, status): (Option<i64>, String) =
        svc.db().query_row("SELECT user_id, status FROM deletion_requests WHERE id = ?1", params![d.deletion_id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!((uid, status.as_str()), (None, "completed"));
}

/// What: EXPORT-13 failure path: a failing eraser rolls the cascade back (user, sessions and the
/// approved request stay, no 'user_deleted_cascade' row), and an unconfigured eraser refuses too.
/// In: none. Out: panics on a partial delete. Why: 2026-11-10 amendment (EXPORT-13, one transaction).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
// EXPORT-13
#[tokio::test]
async fn test_cascade_rolls_back_when_audit_erase_fails() {
    for eraser in [Box::new(FailingEraser) as Box<dyn AuditEraser>, Box::new(UnconfiguredAuditEraser)] {
        let mailer = InMemoryMailer::default();
        let svc = ComplianceService::new(Connection::open_in_memory().unwrap(), Box::new(InMemoryFileStorage::default()), Box::new(mailer.clone()), &[7u8; 32], "https://example.com")
            .unwrap()
            .with_audit_eraser(eraser);
        svc.db()
            .execute("INSERT INTO users (id, email, name, created_at, tier, status) VALUES (1, 'alice@example.com', 'Alice', '2025-01-01T00:00:00Z', 'pro', 'active')", [])
            .unwrap();
        svc.db().execute("INSERT INTO sessions (id, user_id) VALUES ('s1', 1)", []).unwrap();
        let d = svc.request_account_deletion(1, DeletionReason::GdprRequest).await.unwrap();
        assert!(matches!(svc.confirm_deletion(1, d.deletion_id.clone(), &last_token(&mailer)).await, Err(ComplianceError::AuditErase(_))));
        let counts: (i64, i64, i64) = svc
            .db()
            .query_row(
                "SELECT (SELECT COUNT(*) FROM users), (SELECT COUNT(*) FROM sessions), (SELECT COUNT(*) FROM audit_log WHERE action = 'user_deleted_cascade')",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(counts, (1, 1, 0));
        let status: String = svc.db().query_row("SELECT status FROM deletion_requests WHERE id = ?1", params![d.deletion_id], |r| r.get(0)).unwrap();
        assert_eq!(status, "approved", "stays due, so the scheduled job retries it");
    }
}

/// What: EXPORT-14: nothing is deleted before confirm; a wrong token, a reused token and a token over
/// 24 hours old are refused; another user's deletion request is 404 (DeletionNotFound) for confirm and
/// cancel. In: none. Out: panics on a wrong answer. Why: 2026-11-10 amendment (EXPORT-14).
/// Corrected 2026-11-10 (Phase B.2, EXPORT-15): the wrong and expired token assertions expected
/// `TokenMismatch` and `TokenExpired`; the spec now gives both one answer, `InvalidConfirmationToken`
/// (400 invalid_confirmation_token), and the 404 carries code not_found.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
// EXPORT-14
#[tokio::test]
async fn test_deletion_confirmation_token_rules() {
    let (svc, mailer, now) = build_service();
    svc.db()
        .execute("INSERT INTO users (id, email, name, created_at, tier, status) VALUES (2, 'bob@example.com', 'Bob', '2025-01-01T00:00:00Z', 'pro', 'active')", [])
        .unwrap();
    let d = svc.request_account_deletion(1, DeletionReason::GdprRequest).await.unwrap();
    let token = last_token(&mailer);
    assert_eq!(token.len(), 64, "32 random bytes as hex");
    assert_eq!(svc.process_due_deletions().await.unwrap(), 0);
    let users: i64 = svc.db().query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).unwrap();
    assert_eq!(users, 2, "nothing deleted before confirm");
    let stored: String = svc.db().query_row("SELECT token_hash FROM deletion_requests WHERE id = ?1", params![d.deletion_id], |r| r.get(0)).unwrap();
    assert_ne!(stored, token, "only the hash is stored");

    // another user's request: 404 for confirm (even with the right token) and cancel
    assert_eq!(svc.confirm_deletion(2, d.deletion_id.clone(), &token).await.unwrap_err(), ComplianceError::DeletionNotFound);
    assert_eq!(svc.cancel_deletion(2, d.deletion_id.clone()).await.unwrap_err(), ComplianceError::DeletionNotFound);
    assert_eq!((ComplianceError::DeletionNotFound.status(), ComplianceError::DeletionNotFound.code()), (404, "not_found"));
    // wrong token
    assert_eq!(svc.confirm_deletion(1, d.deletion_id.clone(), &"0".repeat(64)).await.unwrap_err(), ComplianceError::InvalidConfirmationToken);
    // a token is bound to its own deletion id
    let d2 = svc.request_account_deletion(2, DeletionReason::UserRequested).await.unwrap();
    let token2 = last_token(&mailer);
    assert_eq!(svc.confirm_deletion(1, d.deletion_id.clone(), &token2).await.unwrap_err(), ComplianceError::InvalidConfirmationToken);
    // expired after 24 hours
    now.fetch_add(24 * 3600, Ordering::SeqCst);
    assert_eq!(svc.confirm_deletion(1, d.deletion_id.clone(), &token).await.unwrap_err(), ComplianceError::InvalidConfirmationToken);
    let users: i64 = svc.db().query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).unwrap();
    assert_eq!(users, 2);
    // a fresh request: confirm once, then the same token is refused
    let d3 = svc.request_account_deletion(1, DeletionReason::UserRequested).await.unwrap();
    let token3 = last_token(&mailer);
    svc.confirm_deletion(1, d3.deletion_id.clone(), &token3).await.unwrap();
    assert!(svc.confirm_deletion(1, d3.deletion_id.clone(), &token3).await.is_err());
    let _ = d2;
}

/// What: EXPORT-15: a wrong, a reused and an expired token all get the same 400
/// invalid_confirmation_token (same variant, code and status) and leave the request as it was; confirm and
/// cancel of a cancelled request get 409 deletion_not_pending, even with that request's still-valid token;
/// confirm and cancel of a completed request get 404 not_found (it has no owner any more), whether it was
/// completed by the cascade (user_id NULL) or is a completed row that still names its user; nothing
/// changes. In: none. Out: panics on a wrong answer. Why: EXPORT-15 (Phase B.2: one answer in every
/// language; completed -> 404 as amended in commit 3abb340). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory only.
// EXPORT-15
#[tokio::test]
async fn test_confirmation_one_answer_and_closed_request_codes() {
    let (svc, mailer, now) = build_service();
    let status_of = |id: &str| -> String { svc.db().query_row("SELECT status FROM deletion_requests WHERE id = ?1", params![id], |r| r.get(0)).unwrap() };
    let mut answers = Vec::new();
    // wrong
    let wrong = svc.request_account_deletion(1, DeletionReason::UserRequested).await.unwrap();
    answers.push(svc.confirm_deletion(1, wrong.deletion_id.clone(), &"f".repeat(64)).await.unwrap_err());
    assert_eq!(status_of(&wrong.deletion_id), "pending");
    // reused
    let reused = svc.request_account_deletion(1, DeletionReason::UserRequested).await.unwrap();
    let reused_token = last_token(&mailer);
    svc.confirm_deletion(1, reused.deletion_id.clone(), &reused_token).await.unwrap();
    answers.push(svc.confirm_deletion(1, reused.deletion_id.clone(), &reused_token).await.unwrap_err());
    assert_eq!(status_of(&reused.deletion_id), "approved");
    // expired (24 hours and one second later)
    let expired = svc.request_account_deletion(1, DeletionReason::UserRequested).await.unwrap();
    let expired_token = last_token(&mailer);
    now.fetch_add(24 * 3600 + 1, Ordering::SeqCst);
    answers.push(svc.confirm_deletion(1, expired.deletion_id.clone(), &expired_token).await.unwrap_err());
    assert_eq!(status_of(&expired.deletion_id), "pending");
    for a in &answers {
        assert_eq!(a, &ComplianceError::InvalidConfirmationToken);
        assert_eq!((a.status(), a.code()), (400, "invalid_confirmation_token"));
        assert_eq!(a.to_string(), answers[0].to_string(), "the reply never says which");
    }
    let users: i64 = svc.db().query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).unwrap();
    assert_eq!(users, 1, "nothing deleted");

    // cancelled: a fresh request with its still-valid token, cancelled by the owner -> 409
    let cancelled = svc.request_account_deletion(1, DeletionReason::UserRequested).await.unwrap();
    let cancelled_token = last_token(&mailer);
    svc.cancel_deletion(1, cancelled.deletion_id.clone()).await.unwrap();
    let c = svc.confirm_deletion(1, cancelled.deletion_id.clone(), &cancelled_token).await.unwrap_err();
    assert_eq!(c, ComplianceError::DeletionNotPending);
    assert_eq!((c.status(), c.code()), (409, "deletion_not_pending"));
    assert_eq!(svc.cancel_deletion(1, cancelled.deletion_id.clone()).await.unwrap_err(), ComplianceError::DeletionNotPending);
    assert_eq!(status_of(&cancelled.deletion_id), "cancelled", "nothing changed");

    // completed but still naming its user (a row completed by another path), token still valid -> 404
    let marked = svc.request_account_deletion(1, DeletionReason::UserRequested).await.unwrap();
    let marked_token = last_token(&mailer);
    svc.db().execute("UPDATE deletion_requests SET status = 'completed' WHERE id = ?1", params![marked.deletion_id]).unwrap();
    let c = svc.confirm_deletion(1, marked.deletion_id.clone(), &marked_token).await.unwrap_err();
    assert_eq!((c.clone(), c.status(), c.code()), (ComplianceError::DeletionNotFound, 404, "not_found"));
    assert_eq!(svc.cancel_deletion(1, marked.deletion_id.clone()).await.unwrap_err(), ComplianceError::DeletionNotFound);
    assert_eq!(status_of(&marked.deletion_id), "completed", "nothing changed");

    // completed by the cascade (statutory, erased on confirm): user_id is NULL -> 404 to the old owner
    let gone = svc.request_account_deletion(1, DeletionReason::GdprRequest).await.unwrap();
    let gone_token = last_token(&mailer);
    svc.confirm_deletion(1, gone.deletion_id.clone(), &gone_token).await.unwrap();
    assert_eq!(status_of(&gone.deletion_id), "completed");
    assert_eq!(svc.confirm_deletion(1, gone.deletion_id.clone(), &gone_token).await.unwrap_err(), ComplianceError::DeletionNotFound);
    assert_eq!(svc.cancel_deletion(1, gone.deletion_id.clone()).await.unwrap_err(), ComplianceError::DeletionNotFound);
}

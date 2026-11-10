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

/// What: a service with Alice (user 1), in-memory storage and mailer, and a clock the test can move.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
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
    .with_clock(Box::new(move || Utc.timestamp_opt(clock.load(Ordering::SeqCst), 0).unwrap()));
    svc.db()
        .execute(
            "INSERT INTO users (id, email, name, created_at, tier, status) VALUES (1, 'alice@example.com', 'Alice', '2025-01-01T00:00:00Z', 'pro', 'active')",
            [],
        )
        .unwrap();
    (svc, mailer, now)
}

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

#[tokio::test]
async fn test_export_csv_flow() {
    let (svc, _, _) = build_service();

    let resp = svc.request_data_export(1, ExportFormat::Csv).await.expect("request export csv");
    svc.generate_export_file(resp.export_id.clone(), 1, ExportFormat::Csv).await.expect("generate csv export");

    let status = svc.check_export_status(1, resp.export_id).await.unwrap();
    assert_eq!(status.status, ExportStatus::Completed);
    assert!(status.file_url.unwrap().ends_with(".csv"));
}

#[tokio::test]
async fn test_deletion_grace_period_and_cancel() {
    let (svc, mailer, _) = build_service();

    // Request deletion
    let del_resp = svc.request_account_deletion(1, DeletionReason::UserRequested).await.expect("request deletion");
    assert_eq!(del_resp.status, DeletionStatus::Pending);

    // Confirm deletion with the token from the confirmation email
    let body = mailer.sent.lock().unwrap().last().unwrap().body.clone();
    let token = body.split("token=").nth(1).unwrap().to_string();
    assert!(svc.confirm_deletion(del_resp.deletion_id.clone(), "wrong").await.is_err());

    let confirm = svc.confirm_deletion(del_resp.deletion_id.clone(), &token).await.expect("confirm deletion");
    assert!(confirm.success);

    // Cancel within grace period
    let cancel = svc.cancel_deletion(1, del_resp.deletion_id).await.expect("cancel deletion");
    assert_eq!(cancel.status, DeletionStatus::Cancelled);
}

#[tokio::test]
async fn test_cascade_delete_preserves_audit_log() {
    let (svc, _, _) = build_service();

    // Insert dummy related rows
    svc.db().execute("INSERT INTO sessions (id, user_id) VALUES (?1, ?2)", params!["s1", 1]).unwrap();
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

    // Audit log must still exist (the login row, plus the cascade's own record)
    let audit_cnt: i64 = svc
        .db()
        .query_row("SELECT COUNT(*) FROM audit_log WHERE user_id = ?1 AND action = 'login'", params![1], |r| r.get(0))
        .unwrap();
    assert_eq!(audit_cnt, 1);
}

#[tokio::test]
async fn test_admin_list_exports_and_deletions() {
    let (svc, _, _) = build_service();

    // Create two exports
    let e1 = svc.request_data_export(1, ExportFormat::Json).await.unwrap();
    let e2 = svc.request_data_export(1, ExportFormat::Csv).await.unwrap();

    // Create a deletion request
    let d1 = svc.request_account_deletion(1, DeletionReason::GdprRequest).await.unwrap();

    // List exports
    let list = svc.list_exports(Some(1), Some(ExportStatus::Pending)).await.unwrap();
    assert_eq!(list.total, 2);
    assert!(list.exports.iter().any(|e| e.id == e1.export_id));
    assert!(list.exports.iter().any(|e| e.id == e2.export_id));

    // List deletions
    let dlist = svc.list_deletions(Some(DeletionStatus::Pending)).await.unwrap();
    assert_eq!(dlist.total, 1);
    assert_eq!(dlist.deletions[0].id, d1.deletion_id);
}

/// Added 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP), spec "Signed URL works, expires after 7 days":
/// the link downloads, a changed signature does not, and the same link fails after 7 days.
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
/// deletion does not run before 30 days, runs after, and keeps the audit log.
#[tokio::test]
async fn test_deletion_runs_only_after_grace_period() {
    let (svc, mailer, now) = build_service();
    let d = svc.request_account_deletion(1, DeletionReason::GdprRightToBeForgotten).await.unwrap();
    let token = mailer.sent.lock().unwrap().last().unwrap().body.split("token=").nth(1).unwrap().to_string();
    svc.confirm_deletion(d.deletion_id.clone(), &token).await.unwrap();
    now.fetch_add(29 * 86_400, Ordering::SeqCst);
    assert_eq!(svc.process_due_deletions().await.unwrap(), 0);
    now.fetch_add(86_400, Ordering::SeqCst);
    assert!(svc.cancel_deletion(1, d.deletion_id.clone()).await.is_err());
    assert_eq!(svc.process_due_deletions().await.unwrap(), 1);
    let users: i64 = svc.db().query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).unwrap();
    assert_eq!(users, 0);
    let audit: i64 = svc.db().query_row("SELECT COUNT(*) FROM audit_log WHERE user_id = 1", [], |r| r.get(0)).unwrap();
    assert!(audit >= 3);
}

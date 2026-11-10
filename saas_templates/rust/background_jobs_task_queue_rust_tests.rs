//! Background jobs tests (TIER 2 spec, system 4). Touches: in-memory SQLite and a worker thread.
use super::*;
use chrono::{Duration as ChronoDuration, Utc};
use r2d2_sqlite::SqliteConnectionManager;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{sleep, timeout};

/// Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the pool is limited to ONE connection.
/// Each connection of a `:memory:` manager opens its own empty database, so with r2d2's default of 10
/// connections the worker and the test could read different databases (the jobs table existed on one
/// connection only). Touches: memory only.
fn init_pool() -> DbPool {
    let manager = SqliteConnectionManager::memory();
    let pool = r2d2::Pool::builder().max_size(1).build(manager).expect("Failed to create pool");
    pool
}

#[tokio::test]
async fn test_enqueue_and_worker_completes() {
    let pool = init_pool();
    let queue = Arc::new(JobQueue::new(pool).unwrap());
    queue.clone().start_worker();

    let req = EnqueueRequest {
        task_type: "send_bulk_email".into(),
        params: json!({ "total": 20 }),
        scheduled_at: None,
        max_retries: 3,
    };
    let resp = queue.enqueue(req).unwrap();
    assert_eq!(resp.success, true);
    let job_id = resp.job_id;

    // Wait for job to complete (max 5 seconds)
    let completed = timeout(
        std::time::Duration::from_secs(5),
        async {
            loop {
                let job = queue.get(job_id).unwrap();
                if job.status == JobStatus::Completed {
                    break;
                }
                sleep(std::time::Duration::from_millis(100)).await;
            }
        },
    )
    .await;
    assert!(completed.is_ok());

    let job = queue.get(job_id).unwrap();
    assert_eq!(job.status, JobStatus::Completed);
    assert_eq!(job.progress.unwrap(), "20/20");
    let result = job.result.unwrap();
    assert_eq!(result["sent"], 20);
}

#[tokio::test]
async fn test_retry_on_failure_and_exponential_backoff() {
    let pool = init_pool();
    let queue = Arc::new(JobQueue::new(pool).unwrap());
    queue.clone().start_worker();

    // This job will fail at halfway point, triggering retries
    let req = EnqueueRequest {
        task_type: "send_bulk_email".into(),
        params: json!({ "total": 10, "fail": true }),
        scheduled_at: None,
        max_retries: 2,
    };
    let resp = queue.enqueue(req).unwrap();
    let job_id = resp.job_id;

    // Wait enough time for retries (1s + 2s backoffs)
    let completed = timeout(
        std::time::Duration::from_secs(10),
        async {
            loop {
                let job = queue.get(job_id).unwrap();
                if job.status == JobStatus::Completed {
                    break;
                }
                if job.status == JobStatus::Failed && job.retry_count == 2 {
                    // Should have exhausted retries
                    break;
                }
                sleep(std::time::Duration::from_millis(200)).await;
            }
        },
    )
    .await;
    assert!(completed.is_ok());

    let job = queue.get(job_id).unwrap();
    // Since we set max_retries=2, after two failures it should be failed
    assert_eq!(job.status, JobStatus::Failed);
    assert_eq!(job.retry_count, 2);
    assert!(job.error.unwrap().contains("Simulated failure"));
}

#[tokio::test]
async fn test_successful_retry_after_failure() {
    let pool = init_pool();
    let queue = Arc::new(JobQueue::new(pool).unwrap());
    queue.clone().start_worker();

    // First attempt fails, second succeeds (fail flag removed after first run)
    let req = EnqueueRequest {
        task_type: "send_bulk_email".into(),
        params: json!({ "total": 5, "fail": true }),
        scheduled_at: None,
        max_retries: 3,
    };
    let resp = queue.enqueue(req).unwrap();
    let job_id = resp.job_id;

    // After first failure, manually clear the fail flag to allow success on retry
    let mut attempts = 0;
    loop {
        let job = queue.get(job_id).unwrap();
        if job.status == JobStatus::Failed && job.retry_count == 1 {
            // Update params to remove fail flag
            let conn = queue.conn().unwrap();
            conn.execute(
                "UPDATE jobs SET params = ?1 WHERE id = ?2",
                params![
                    json!({ "total": 5 }).to_string(),
                    job_id
                ],
            )
            .unwrap();
            break;
        }
        attempts += 1;
        if attempts > 20 {
            panic!("Job did not fail as expected");
        }
        sleep(std::time::Duration::from_millis(200)).await;
    }

    // Wait for job to eventually complete
    let completed = timeout(
        std::time::Duration::from_secs(10),
        async {
            loop {
                let job = queue.get(job_id).unwrap();
                if job.status == JobStatus::Completed {
                    break;
                }
                sleep(std::time::Duration::from_millis(200)).await;
            }
        },
    )
    .await;
    assert!(completed.is_ok());

    let job = queue.get(job_id).unwrap();
    assert_eq!(job.status, JobStatus::Completed);
    assert_eq!(job.retry_count, 1);
    assert_eq!(job.progress.unwrap(), "5/5");
}

#[tokio::test]
async fn test_cancel_before_start() {
    let pool = init_pool();
    let queue = Arc::new(JobQueue::new(pool).unwrap());
    // No worker started to ensure job stays enqueued
    let req = EnqueueRequest {
        task_type: "daily_report".into(),
        params: json!({}),
        scheduled_at: None,
        max_retries: 1,
    };
    let resp = queue.enqueue(req).unwrap();
    let job_id = resp.job_id;

    let cancel_resp = queue.cancel(job_id).unwrap();
    assert_eq!(cancel_resp.success, true);
    assert_eq!(cancel_resp.status, JobStatus::Cancelled);

    let job = queue.get(job_id).unwrap();
    assert_eq!(job.status, JobStatus::Cancelled);
}

#[tokio::test]
async fn test_progress_updates() {
    let pool = init_pool();
    let queue = Arc::new(JobQueue::new(pool).unwrap());
    queue.clone().start_worker();

    let req = EnqueueRequest {
        task_type: "export_generate".into(),
        params: json!({ "items": 50 }),
        scheduled_at: None,
        max_retries: 1,
    };
    let resp = queue.enqueue(req).unwrap();
    let job_id = resp.job_id;

    // Poll progress while running
    let mut observed = false;
    let _ = timeout(
        std::time::Duration::from_secs(5),
        async {
            loop {
                let job = queue.get(job_id).unwrap();
                if let Some(prog) = job.progress.clone() {
                    if prog != "0/0" && prog != "50/50" {
                        observed = true;
                        break;
                    }
                }
                if job.status == JobStatus::Completed {
                    break;
                }
                sleep(std::time::Duration::from_millis(100)).await;
            }
        },
    )
    .await;
    assert!(observed, "Progress was never updated during execution");
}

#[tokio::test]
async fn test_scheduled_job_runs_after_time() {
    let pool = init_pool();
    let queue = Arc::new(JobQueue::new(pool).unwrap());
    queue.clone().start_worker();

    let future = Utc::now() + ChronoDuration::seconds(3);
    let req = EnqueueRequest {
        task_type: "daily_report".into(),
        params: json!({}),
        scheduled_at: Some(future),
        max_retries: 1,
    };
    let resp = queue.enqueue(req).unwrap();
    let job_id = resp.job_id;

    // Immediately check status is still enqueued
    let job = queue.get(job_id).unwrap();
    assert_eq!(job.status, JobStatus::Enqueued);

    // Wait 4 seconds and ensure it has run
    let completed = timeout(
        std::time::Duration::from_secs(6),
        async {
            loop {
                let job = queue.get(job_id).unwrap();
                if job.status == JobStatus::Completed {
                    break;
                }
                sleep(std::time::Duration::from_millis(200)).await;
            }
        },
    )
    .await;
    assert!(completed.is_ok());
    let job = queue.get(job_id).unwrap();
    assert_eq!(job.status, JobStatus::Completed);
}

#[tokio::test]
async fn test_bulk_job_large_item_count() {
    let pool = init_pool();
    let queue = Arc::new(JobQueue::new(pool).unwrap());
    queue.clone().start_worker();

    let req = EnqueueRequest {
        task_type: "send_bulk_email".into(),
        params: json!({ "total": 10_000 }),
        scheduled_at: None,
        max_retries: 1,
    };
    let resp = queue.enqueue(req).unwrap();
    let job_id = resp.job_id;

    // Wait up to 30 seconds for completion
    let completed = timeout(
        std::time::Duration::from_secs(30),
        async {
            loop {
                let job = queue.get(job_id).unwrap();
                if job.status == JobStatus::Completed {
                    break;
                }
                sleep(std::time::Duration::from_millis(500)).await;
            }
        },
    )
    .await;
    assert!(completed.is_ok(), "Bulk job did not finish in time");
    let job = queue.get(job_id).unwrap();
    assert_eq!(job.status, JobStatus::Completed);
    assert_eq!(job.progress.unwrap(), "10000/10000");
}
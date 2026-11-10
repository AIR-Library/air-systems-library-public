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

// JOBS-02
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

/// What: JOBS-04 on the real worker: max_retries 2 -> failed with retry_count 2 after three runs.
/// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: only the comment (it said "after two failures"). Touches: in-memory SQLite, a worker thread.
// JOBS-04
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
    // Since we set max_retries=2, after three runs (the first attempt and two retries) it is failed with
    // retry_count = 2 (comment corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, JOBS-04 amendment)
    assert_eq!(job.status, JobStatus::Failed);
    assert_eq!(job.retry_count, 2);
    assert!(job.error.unwrap().contains("Simulated failure"));
}

/// What: a job that fails once succeeds on its retry (retry_count 1). Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: a job
/// waiting for its retry is now 'enqueued' (JOBS-03 amendment), not 'failed'. Touches: in-memory SQLite, a worker thread.
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

    // After first failure, manually clear the fail flag to allow success on retry.
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (JOBS-03 amendment): a job waiting for its retry is
    // 'enqueued' with retry_count = 1 (it used to be 'failed' while waiting).
    let mut attempts = 0;
    loop {
        let job = queue.get(job_id).unwrap();
        if job.status == JobStatus::Enqueued && job.retry_count == 1 {
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

// JOBS-05
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

// JOBS-06
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

// JOBS-07
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

// JOBS-08
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
/// What: a queue on one in-memory connection whose clock reads `now` (milliseconds), and a task
/// "always_fails" that counts its runs. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
fn clocked_queue() -> (JobQueue, Arc<std::sync::atomic::AtomicI64>, Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
    let now = Arc::new(AtomicI64::new(1_767_225_600_000));
    let clock = now.clone();
    let queue = JobQueue::new(init_pool())
        .unwrap()
        .with_clock(Box::new(move || chrono::DateTime::from_timestamp_millis(clock.load(Ordering::SeqCst)).unwrap()));
    let runs = Arc::new(AtomicUsize::new(0));
    let r = runs.clone();
    queue.register_task("always_fails", Arc::new(move |_params, _progress| {
        r.fetch_add(1, Ordering::SeqCst);
        Err("provider timeout".to_string())
    }));
    (queue, now, runs)
}

/// What: JOBS-03: a failing job is retried with exponential backoff: retry 1 after 1 s, retry 2 after
/// 2 s, retry 3 after 4 s; while it waits it is 'enqueued' with retry_count = n and next_retry_at =
/// failed_at + 2^(n-1) s, and the worker skips it until then. In: none. Out: panics on a wrong state.
/// Why: 2026-11-10 amendment (JOBS-03), deterministic with an injected clock.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
// JOBS-03
#[tokio::test]
async fn test_backoff_schedule_with_clock() {
    use std::sync::atomic::Ordering;
    let (queue, now, runs) = clocked_queue();
    let job_id = queue.enqueue(EnqueueRequest { task_type: "always_fails".into(), params: json!({}), scheduled_at: None, max_retries: 3 }).unwrap().job_id;
    assert!(queue.process_one_job().unwrap());
    for (n, wait_ms) in [(1, 1_000i64), (2, 2_000), (3, 4_000)] {
        let job = queue.get(job_id).unwrap();
        assert_eq!((job.status, job.retry_count), (JobStatus::Enqueued, n), "waiting for retry {}", n);
        let failed_at = now.load(Ordering::SeqCst);
        assert_eq!(job.next_retry_at.unwrap().timestamp_millis(), failed_at + wait_ms);
        now.fetch_add(wait_ms - 1, Ordering::SeqCst);
        assert!(!queue.process_one_job().unwrap(), "skipped before next_retry_at");
        assert_eq!(runs.load(Ordering::SeqCst), n as usize);
        now.fetch_add(1, Ordering::SeqCst);
        assert!(queue.process_one_job().unwrap(), "retry {} runs at next_retry_at", n);
    }
    assert_eq!(runs.load(Ordering::SeqCst), 4);
}

/// What: JOBS-04: with max_retries = 3 the job runs 4 times, then it is 'failed' with retry_count = 3,
/// no next_retry_at and the last error; the worker never runs it again; with max_retries = 0 it runs
/// once. In: none. Out: panics on a wrong state. Why: 2026-11-10 amendment (JOBS-04).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
// JOBS-04
#[tokio::test]
async fn test_max_retries_counts_retries_after_first_attempt() {
    use std::sync::atomic::Ordering;
    let (queue, now, runs) = clocked_queue();
    let job_id = queue.enqueue(EnqueueRequest { task_type: "always_fails".into(), params: json!({}), scheduled_at: None, max_retries: 3 }).unwrap().job_id;
    for _ in 0..10 {
        queue.process_one_job().unwrap();
        now.fetch_add(60_000, Ordering::SeqCst);
    }
    let job = queue.get(job_id).unwrap();
    assert_eq!(runs.load(Ordering::SeqCst), 4);
    assert_eq!((job.status, job.retry_count, job.next_retry_at), (JobStatus::Failed, 3, None));
    assert_eq!(job.error.as_deref(), Some("provider timeout"));
    let once = queue.enqueue(EnqueueRequest { task_type: "always_fails".into(), params: json!({}), scheduled_at: None, max_retries: 0 }).unwrap().job_id;
    assert!(queue.process_one_job().unwrap());
    assert!(!queue.process_one_job().unwrap());
    assert_eq!((queue.get(once).unwrap().status, runs.load(Ordering::SeqCst)), (JobStatus::Failed, 5));
}

/// What: JOBS-09: results are available after completion (and refused before it). In: none.
/// Out: panics on a wrong answer. Why: the spec's required test JOBS-09 had no tagged Rust test.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
// JOBS-09
#[tokio::test]
async fn test_results_available_after_completion() {
    let (queue, _, _) = clocked_queue();
    let job_id = queue.enqueue(EnqueueRequest { task_type: "send_bulk_email".into(), params: json!({ "total": 3 }), scheduled_at: None, max_retries: 0 }).unwrap().job_id;
    assert!(queue.get_results(job_id).is_err());
    assert!(queue.process_one_job().unwrap());
    let results = queue.get_results(job_id).unwrap();
    assert_eq!(results.status, JobStatus::Completed);
    assert_eq!(results.result["sent"], 3);
    assert!(results.completed_at.is_some());
}

/// What: JOBS-01: an enqueued job is picked up by the worker and is 'running' (with started_at) while
/// its task runs; the task reads its own row through the same pool. In: none. Out: panics on a wrong
/// state. Why: the old JOBS-01 candidate only waited for completion and never saw 'running'.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
// JOBS-01
#[tokio::test]
async fn test_worker_marks_job_running() {
    let pool = init_pool();
    let queue = JobQueue::new(pool.clone()).unwrap();
    let seen = Arc::new(std::sync::Mutex::new(None));
    let s = seen.clone();
    queue.register_task("observe", Arc::new(move |params, _progress| {
        let id = params["id"].as_i64().unwrap_or(0);
        let conn = pool.get().map_err(|e| e.to_string())?;
        let row: (String, Option<String>) = conn
            .query_row("SELECT status, started_at FROM jobs WHERE id = ?1", params![id], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|e| e.to_string())?;
        *s.lock().unwrap() = Some(row);
        Ok(json!({}))
    }));
    let job_id = queue.enqueue(EnqueueRequest { task_type: "observe".into(), params: json!({ "id": 1 }), scheduled_at: None, max_retries: 0 }).unwrap().job_id;
    assert_eq!(job_id, 1);
    assert_eq!(queue.get(job_id).unwrap().status, JobStatus::Enqueued);
    assert!(queue.process_one_job().unwrap());
    let (status, started_at) = seen.lock().unwrap().clone().expect("the task ran");
    assert_eq!(status, "running");
    assert!(started_at.is_some());
    assert_eq!(queue.get(job_id).unwrap().status, JobStatus::Completed);
}

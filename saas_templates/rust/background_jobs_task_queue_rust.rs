//! Background jobs and task queue (TIER 2 spec, system 4).
//!
//! What: `JobQueue` stores jobs in SQLite, a worker thread claims due jobs one at a time with a single
//! atomic UPDATE, runs the registered task handler, reports progress ("X/Y") while it runs, and records
//! the result; a failed attempt is retried with exponential backoff: retry n waits 2^(n-1) s (1 s, 2 s,
//! 4 s, ...) as 'enqueued' with retry_count = n, and `max_retries` counts the retries after the first
//! attempt, so a job runs at most max_retries + 1 times and then is 'failed' with retry_count =
//! max_retries (2026-11-10 amendment, JOBS-03/04, session_012zDydZCZ4AChqhEZ4oVtaP). Jobs can be scheduled for later, cancelled before they start,
//! listed, re-enqueued after failure, and every attempt is written to `job_runs`.
//! Why: the old file did not compile (`NO_PARAMS` and `query_named` are gone from the SQLite crate,
//! `JobStatus` had both derived and hand-written serde impls, errors without `From`), and held a
//! connection while a task ran. Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: the SQLite pool it is given; one worker thread per `start_worker`; the clock. The built-in
//! example tasks only count and sleep; real tasks (email, webhooks, exports) are registered by the
//! application with `register_task`. No network, no money.

use chrono::{DateTime, SecondsFormat, Utc};
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
pub use rusqlite::params;
use rusqlite::{OptionalExtension, Row};
use serde::{Deserialize, Serialize};
pub use serde_json::json;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock, Weak};
use std::time::Duration as StdDuration;

/// The pool type the queue runs on.
pub type DbPool = Pool<SqliteConnectionManager>;

/// What: queue errors. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug)]
pub enum JobError {
    Db(String),
    NotFound,
    Invalid(String),
}

/// What: `fmt::Display` for `JobError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl fmt::Display for JobError {
    /// What: human-readable text of `fmt::Display for JobError` (never secrets). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JobError::Db(m) => write!(f, "database error: {}", m),
            JobError::NotFound => write!(f, "job not found"),
            JobError::Invalid(m) => write!(f, "invalid operation: {}", m),
        }
    }
}

/// What: `std::error::Error` for `JobError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl std::error::Error for JobError {}

/// What: `From<rusqlite::Error>` for `JobError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl From<rusqlite::Error> for JobError {
    /// What: convert the error of `From<rusqlite::Error> for JobError`, keeping its message for logs. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn from(e: rusqlite::Error) -> Self {
        JobError::Db(e.to_string())
    }
}

/// What: `From<r2d2::Error>` for `JobError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl From<r2d2::Error> for JobError {
    /// What: convert the error of `From<r2d2::Error> for JobError`, keeping its message for logs. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn from(e: r2d2::Error) -> Self {
        JobError::Db(e.to_string())
    }
}

/// What: a job's state. A job waiting for a retry is `Enqueued` with `next_retry_at` set; `Failed` is
/// final (changed 2026-11-10, JOBS-03/04). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Enqueued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// What: methods of `JobStatus`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl JobStatus {
    /// What: the stored name. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn as_str(&self) -> &'static str {
        match self {
            JobStatus::Enqueued => "enqueued",
            JobStatus::Running => "running",
            JobStatus::Completed => "completed",
            JobStatus::Failed => "failed",
            JobStatus::Cancelled => "cancelled",
        }
    }

    /// What: parse a stored name. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn parse(s: &str) -> Option<JobStatus> {
        Some(match s {
            "enqueued" => JobStatus::Enqueued,
            "running" => JobStatus::Running,
            "completed" => JobStatus::Completed,
            "failed" => JobStatus::Failed,
            "cancelled" => JobStatus::Cancelled,
            _ => return None,
        })
    }
}

/// What: one job row (spec table `jobs`). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: i64,
    pub task_type: String,
    pub params: JsonValue,
    pub status: JobStatus,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub progress: Option<String>,
    pub result: Option<JsonValue>,
    pub error: Option<String>,
    pub retry_count: i32,
    pub max_retries: i32,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub scheduled_at: Option<DateTime<Utc>>,
}

/// What: the enqueue request (spec endpoint 1). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnqueueRequest {
    pub task_type: String,
    pub params: JsonValue,
    #[serde(default)]
    pub scheduled_at: Option<DateTime<Utc>>,
    #[serde(default = "default_max_retries")]
    pub max_retries: i32,
}

/// What: default retries after the first attempt (3 -> up to 4 runs). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn default_max_retries() -> i32 {
    3
}

/// What: spec endpoint 1 response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnqueueResponse {
    pub success: bool,
    pub job_id: i64,
    pub status: JobStatus,
}

/// What: spec endpoint 4 response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelResponse {
    pub success: bool,
    pub status: JobStatus,
}

/// What: spec endpoint 5 response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryResponse {
    pub success: bool,
    pub new_job_id: i64,
    pub status: JobStatus,
}

/// What: spec endpoint 6 response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultResponse {
    pub job_id: i64,
    pub status: JobStatus,
    pub result: JsonValue,
    pub completed_at: Option<DateTime<Utc>>,
}

/// What: how a task reports progress: `progress(done, total)`. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP.
pub type Progress<'a> = &'a mut dyn FnMut(u64, u64);
/// What: a task handler: params and a progress reporter in, a JSON result or an error message out.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
pub type TaskFn = Arc<dyn Fn(&JsonValue, Progress) -> Result<JsonValue, String> + Send + Sync>;

/// What: the queue. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite, worker thread.
pub struct JobQueue {
    pool: DbPool,
    tasks: RwLock<HashMap<String, TaskFn>>,
    backoff_base: StdDuration,
    poll_interval: StdDuration,
    clock: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>,
}

/// What: a time as stored (RFC 3339, milliseconds, `Z`), so text order is time order.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// What: parse a stored time. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn parse_ts(s: Option<String>) -> Option<DateTime<Utc>> {
    s.and_then(|s| DateTime::parse_from_rfc3339(&s).ok()).map(|d| d.with_timezone(&Utc))
}

/// What: methods of `JobQueue`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl JobQueue {
    /// What: a queue on the pool with the built-in example tasks, 1 s backoff base and 50 ms polling.
    /// The pool must reach ONE database: a pooled `:memory:` manager gives every connection its own
    /// empty database, so use `max_size(1)` for in-memory pools. In: pool. Out: the queue (tables
    /// created). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (DDL).
    pub fn new(pool: DbPool) -> Result<Self, JobError> {
        let q = JobQueue {
            pool,
            tasks: RwLock::new(HashMap::new()),
            backoff_base: StdDuration::from_secs(1),
            poll_interval: StdDuration::from_millis(50),
            clock: Box::new(Utc::now),
        };
        q.run_migrations()?;
        q.register_builtin_tasks();
        Ok(q)
    }

    /// What: replace the clock (tests of backoff and scheduling). In: the clock. Out: the queue.
    /// Why: deterministic tests (specs README: injectable clock). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// What: the queue's current time. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the clock.
    fn now(&self) -> DateTime<Utc> {
        (self.clock)()
    }

    /// What: a pooled connection. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the pool.
    pub fn conn(&self) -> Result<PooledConnection<SqliteConnectionManager>, JobError> {
        Ok(self.pool.get()?)
    }

    /// What: create `jobs` and `job_runs`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (DDL).
    fn run_migrations(&self) -> Result<(), JobError> {
        self.conn()?.execute_batch(
            "CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, task_type TEXT NOT NULL, params TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('enqueued','running','completed','failed','cancelled')),
                created_at TEXT NOT NULL, started_at TEXT NULL, completed_at TEXT NULL, progress TEXT NULL,
                result TEXT NULL, error TEXT NULL, retry_count INTEGER NOT NULL DEFAULT 0,
                max_retries INTEGER NOT NULL, next_retry_at TEXT NULL, scheduled_at TEXT NULL);
             CREATE INDEX IF NOT EXISTS jobs_due ON jobs (status, scheduled_at, next_retry_at);
             CREATE TABLE IF NOT EXISTS job_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL REFERENCES jobs(id), status TEXT NOT NULL,
                started_at TEXT NOT NULL, completed_at TEXT NULL, result TEXT NULL);",
        )?;
        Ok(())
    }

    /// What: add or replace a task handler. Why: applications plug in the spec's tasks (bulk email via
    /// Notifications, webhook retries via Webhooks, ...). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: memory.
    pub fn register_task(&self, task_type: &str, handler: TaskFn) {
        if let Ok(mut t) = self.tasks.write() {
            t.insert(task_type.to_string(), handler);
        }
    }

    /// What: example handlers that only count, so the queue works out of the box:
    /// `send_bulk_email` {total, fail?} counts `total` items (with `fail: true` it stops half way with
    /// "Simulated failure", to exercise retries); `export_generate` {items} takes 10 ms per item;
    /// `daily_report`, `cleanup_old_sessions`, `webhook_retry`, `delete_user_cascade` return a summary.
    /// Replace them with real ones. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn register_builtin_tasks(&self) {
        self.register_task("send_bulk_email", Arc::new(|params, progress| {
            let total = params.get("total").and_then(JsonValue::as_u64).unwrap_or(0);
            let fail = params.get("fail").and_then(JsonValue::as_bool).unwrap_or(false);
            let mut sent = 0u64;
            for i in 0..total {
                if fail && i == total / 2 {
                    progress(sent, total);
                    return Err(format!("Simulated failure after {} of {} items", sent, total));
                }
                sent += 1;
                if sent % 100 == 0 {
                    progress(sent, total);
                }
            }
            progress(sent, total);
            Ok(json!({ "task_type": "send_bulk_email", "sent": sent, "failed": 0, "skipped": 0, "errors": [] }))
        }));
        self.register_task("export_generate", Arc::new(|params, progress| {
            let items = params.get("items").and_then(JsonValue::as_u64).unwrap_or(0);
            for i in 1..=items {
                std::thread::sleep(StdDuration::from_millis(10));
                progress(i, items);
            }
            Ok(json!({ "task_type": "export_generate", "exported": items }))
        }));
        for name in ["daily_report", "cleanup_old_sessions", "webhook_retry", "delete_user_cascade"] {
            self.register_task(name, Arc::new(move |_params, progress| {
                progress(1, 1);
                Ok(json!({ "task_type": name, "status": "ok" }))
            }));
        }
    }

    /// What: add a job (spec endpoint 1). Unknown task types and negative retries are refused
    /// (max_retries = 0 is allowed since 2026-11-10: it counts retries after the first attempt, so 0
    /// means "run once"). In: request. Out: id and status enqueued.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, clock.
    pub fn enqueue(&self, req: EnqueueRequest) -> Result<EnqueueResponse, JobError> {
        if !self.tasks.read().map(|t| t.contains_key(&req.task_type)).unwrap_or(false) {
            return Err(JobError::Invalid(format!("unknown task type {:?}", req.task_type)));
        }
        if req.max_retries < 0 {
            return Err(JobError::Invalid("max_retries must not be negative".into()));
        }
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO jobs (task_type, params, status, created_at, max_retries, scheduled_at)
             VALUES (?1, ?2, 'enqueued', ?3, ?4, ?5)",
            params![req.task_type, req.params.to_string(), ts(self.now()), req.max_retries, req.scheduled_at.map(ts)],
        )?;
        Ok(EnqueueResponse { success: true, job_id: conn.last_insert_rowid(), status: JobStatus::Enqueued })
    }

    /// What: read one job row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn row_to_job(row: &Row) -> rusqlite::Result<Job> {
        let params: String = row.get("params")?;
        let status: String = row.get("status")?;
        let result: Option<String> = row.get("result")?;
        Ok(Job {
            id: row.get("id")?,
            task_type: row.get("task_type")?,
            params: serde_json::from_str(&params).unwrap_or(JsonValue::Null),
            status: JobStatus::parse(&status).unwrap_or(JobStatus::Failed),
            created_at: parse_ts(row.get("created_at")?).unwrap_or_else(Utc::now),
            started_at: parse_ts(row.get("started_at")?),
            completed_at: parse_ts(row.get("completed_at")?),
            progress: row.get("progress")?,
            result: result.and_then(|r| serde_json::from_str(&r).ok()),
            error: row.get("error")?,
            retry_count: row.get("retry_count")?,
            max_retries: row.get("max_retries")?,
            next_retry_at: parse_ts(row.get("next_retry_at")?),
            scheduled_at: parse_ts(row.get("scheduled_at")?),
        })
    }

    /// What: a job by id (spec endpoint 2). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (read).
    pub fn get(&self, job_id: i64) -> Result<Job, JobError> {
        self.conn()?
            .query_row("SELECT * FROM jobs WHERE id = ?1", params![job_id], Self::row_to_job)
            .optional()?
            .ok_or(JobError::NotFound)
    }

    /// What: jobs filtered by status and task type, oldest first (spec endpoint 3). In: filters,
    /// limit (1-1000). Out: (jobs, total matching). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (read).
    pub fn list(&self, status: Option<JobStatus>, task_type: Option<&str>, limit: usize) -> Result<(Vec<Job>, i64), JobError> {
        let conn = self.conn()?;
        let status = status.map(|s| s.as_str());
        let total: i64 = conn.query_row(
            "SELECT COUNT(*) FROM jobs WHERE (?1 IS NULL OR status = ?1) AND (?2 IS NULL OR task_type = ?2)",
            params![status, task_type],
            |r| r.get(0),
        )?;
        let mut stmt = conn.prepare(
            "SELECT * FROM jobs WHERE (?1 IS NULL OR status = ?1) AND (?2 IS NULL OR task_type = ?2) ORDER BY id LIMIT ?3",
        )?;
        let jobs = stmt
            .query_map(params![status, task_type, limit.clamp(1, 1000) as i64], Self::row_to_job)?
            .collect::<rusqlite::Result<Vec<Job>>>()?;
        Ok((jobs, total))
    }

    /// What: cancel a job that has not started (spec endpoint 4); a job waiting for a retry is enqueued
    /// and can be cancelled too. Out: cancelled, or `Invalid` when it is running or finished.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, clock.
    pub fn cancel(&self, job_id: i64) -> Result<CancelResponse, JobError> {
        let n = self.conn()?.execute(
            "UPDATE jobs SET status = 'cancelled', completed_at = ?2, next_retry_at = NULL WHERE id = ?1 AND status = 'enqueued'",
            params![job_id, ts(self.now())],
        )?;
        if n == 1 {
            return Ok(CancelResponse { success: true, status: JobStatus::Cancelled });
        }
        let job = self.get(job_id)?;
        Err(JobError::Invalid(format!("job is {}, only an enqueued job can be cancelled", job.status.as_str())))
    }

    /// What: enqueue a fresh copy of a finally-failed job (spec endpoint 5). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub fn retry(&self, job_id: i64) -> Result<RetryResponse, JobError> {
        let job = self.get(job_id)?;
        if job.status != JobStatus::Failed {
            return Err(JobError::Invalid("only a job that has finally failed can be retried".into()));
        }
        let resp = self.enqueue(EnqueueRequest { task_type: job.task_type, params: job.params, scheduled_at: None, max_retries: job.max_retries })?;
        Ok(RetryResponse { success: true, new_job_id: resp.job_id, status: JobStatus::Enqueued })
    }

    /// What: a completed job's result (spec endpoint 6). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (read).
    pub fn get_results(&self, job_id: i64) -> Result<ResultResponse, JobError> {
        let job = self.get(job_id)?;
        if job.status != JobStatus::Completed {
            return Err(JobError::Invalid("job has not completed".into()));
        }
        Ok(ResultResponse { job_id, status: job.status, result: job.result.unwrap_or(JsonValue::Null), completed_at: job.completed_at })
    }

    /// What: start a worker thread that keeps processing due jobs. It holds only a weak reference, so
    /// it stops on its own once the queue is dropped. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: spawns a thread.
    pub fn start_worker(self: Arc<Self>) {
        let weak: Weak<JobQueue> = Arc::downgrade(&self);
        let interval = self.poll_interval;
        drop(self);
        std::thread::spawn(move || loop {
            let Some(queue) = weak.upgrade() else { break };
            let worked = queue.process_one_job().unwrap_or(false);
            drop(queue);
            if !worked {
                std::thread::sleep(interval);
            }
        });
    }

    /// What: claim the oldest due job with one atomic UPDATE (an enqueued job whose `scheduled_at` and
    /// `next_retry_at` have both passed), run it without holding a connection, and record the outcome.
    /// A failure while retries remain (retry_count < max_retries) puts the job back to 'enqueued' with
    /// retry_count = n and next_retry_at = failed_at + 2^(n-1) x the backoff base (1 s, 2 s, 4 s, ...);
    /// the worker skips it until then. When attempt max_retries + 1 fails the job is 'failed' with
    /// retry_count = max_retries. Out: whether a job was processed.
    /// Why: spec worker, "Atomic updates", "Scheduled jobs", "Retry" (amended 2026-11-10, JOBS-03/04).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, the task handler, clock.
    pub fn process_one_job(&self) -> Result<bool, JobError> {
        let now = ts(self.now());
        let claimed: Option<Job> = {
            let conn = self.conn()?;
            conn.query_row(
                "UPDATE jobs SET status = 'running', started_at = ?1, next_retry_at = NULL
                 WHERE id = (SELECT id FROM jobs
                     WHERE status = 'enqueued' AND (scheduled_at IS NULL OR scheduled_at <= ?1)
                       AND (next_retry_at IS NULL OR next_retry_at <= ?1)
                     ORDER BY id LIMIT 1)
                 RETURNING *",
                params![now],
                Self::row_to_job,
            )
            .optional()?
        };
        let Some(job) = claimed else { return Ok(false) };
        let run_id = {
            let conn = self.conn()?;
            conn.execute("INSERT INTO job_runs (job_id, status, started_at) VALUES (?1, 'running', ?2)", params![job.id, now])?;
            conn.last_insert_rowid()
        };
        let handler = self.tasks.read().ok().and_then(|t| t.get(&job.task_type).cloned());
        let outcome = match handler {
            Some(h) => {
                let mut report = |done: u64, total: u64| {
                    if let Ok(conn) = self.conn() {
                        let _ = conn.execute("UPDATE jobs SET progress = ?2 WHERE id = ?1", params![job.id, format!("{}/{}", done, total)]);
                    }
                };
                h(&job.params, &mut report)
            }
            None => Err(format!("no handler for task type {}", job.task_type)),
        };
        let failed_at = self.now();
        let finished = ts(failed_at);
        let conn = self.conn()?;
        match outcome {
            Ok(result) => {
                conn.execute(
                    "UPDATE jobs SET status = 'completed', completed_at = ?2, result = ?3, error = NULL WHERE id = ?1",
                    params![job.id, finished, result.to_string()],
                )?;
                conn.execute("UPDATE job_runs SET status = 'completed', completed_at = ?2, result = ?3 WHERE id = ?1",
                    params![run_id, finished, result.to_string()])?;
            }
            Err(error) => {
                if job.retry_count < job.max_retries {
                    let n = job.retry_count + 1;
                    let delay = self.backoff_base.saturating_mul(2u32.saturating_pow((n - 1) as u32));
                    let next = failed_at + chrono::Duration::from_std(delay).unwrap_or_else(|_| chrono::Duration::days(365));
                    conn.execute(
                        "UPDATE jobs SET status = 'enqueued', error = ?2, retry_count = ?3, next_retry_at = ?4 WHERE id = ?1",
                        params![job.id, error, n, ts(next)],
                    )?;
                } else {
                    conn.execute(
                        "UPDATE jobs SET status = 'failed', error = ?2, retry_count = ?3, next_retry_at = NULL, completed_at = ?4 WHERE id = ?1",
                        params![job.id, error, job.max_retries, finished],
                    )?;
                }
                conn.execute("UPDATE job_runs SET status = 'failed', completed_at = ?2, result = ?3 WHERE id = ?1",
                    params![run_id, finished, json!({ "error": error }).to_string()])?;
            }
        }
        Ok(true)
    }
}

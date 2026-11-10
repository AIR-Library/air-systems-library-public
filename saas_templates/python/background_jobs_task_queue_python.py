"""Background jobs and task queue: a SQLite-backed job queue with a polling worker thread.

What it does
    Jobs are rows in ``jobs`` (TIER_2 spec, system 4). ``enqueue_job`` stores a job as ``enqueued``;
    the worker thread claims the oldest due job atomically (``BEGIN IMMEDIATE``), marks it ``running``,
    calls the handler registered for its ``task_type`` with ``(params, progress_callback)`` and stores
    the handler's return value as the JSON ``result``. A handler that raises is retried with
    exponential backoff (1 s, 2 s, 4 s, ... per the spec) until ``max_retries`` retries have been
    used; then the job is ``failed``. Every attempt is recorded in ``job_runs``.

Inputs / outputs
    Plain Python dicts in the shapes of the spec's endpoints (enqueue, status, list, cancel, retry,
    results). Unknown job ids raise ``ValueError("Job <id> not found")``; illegal transitions
    (cancel a started job, retry a job that has not failed) raise ``ValueError``.

Why (repair 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP)
    The file was cut off in the middle of ``_send_bulk_email_handler``: five built-in handlers did
    not exist, so the constructor raised ``AttributeError`` and all 15 tests failed. While rebuilding
    it, the behaviour was brought in line with the spec and the passing Java implementation:
    backoff starts at 1 s, ``max_retries`` counts retries (not attempts), only failed jobs can be
    retried, cancel is a single atomic conditional UPDATE, jobs are claimed in insertion order,
    ``scheduled_at`` is normalised to UTC before it is compared, and the invented recipients the old
    bulk-email handler made up ("user0@example.com", ...) are gone.

What it touches
    The SQLite file at ``db_path`` (tables jobs, job_runs, sessions, users). No network: e-mail
    and webhook delivery go through the ``EmailSender`` and ``WebhookSender`` interfaces, whose
    in-memory fakes are the defaults; wire real SMTP/HTTP clients in production. No money.
"""
import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional

JOB_STATUSES = ("enqueued", "running", "completed", "failed", "cancelled")


class NonRetryableJobError(Exception):
    """Raised by a handler for a failure that retrying cannot fix (bad params, 4xx answer).

    The worker marks the job ``failed`` at once instead of scheduling a retry.
    Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
    """


class EmailSender:
    """Interface for sending one e-mail; implement ``send`` with your SMTP/API client.

    ``send(to, template_key, variables)`` returns nothing and raises on failure.
    Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP, so ``send_bulk_email`` uses a real
    delivery seam instead of inventing recipients. Touches the network in real implementations.
    """

    def send(self, to: str, template_key: str, variables: Dict[str, Any]) -> None:
        raise NotImplementedError


class InMemoryEmailSender(EmailSender):
    """Fake ``EmailSender`` that records messages in ``self.sent``; addresses in ``fail_for`` raise.

    Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
    """

    def __init__(self, fail_for: Optional[set] = None):
        self.sent: List[Dict[str, Any]] = []
        self.fail_for = set(fail_for or ())
        self._lock = threading.Lock()

    def send(self, to: str, template_key: str, variables: Dict[str, Any]) -> None:
        if to in self.fail_for:
            raise RuntimeError("email_bounced")
        with self._lock:
            self.sent.append({"to": to, "template_key": template_key, "variables": dict(variables)})


class WebhookSender:
    """Interface for one webhook POST; ``post(url, body)`` returns the HTTP status code.

    It may raise on a connection error. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
    Touches the network in real implementations.
    """

    def post(self, url: str, body: Dict[str, Any]) -> int:
        raise NotImplementedError


class InMemoryWebhookSender(WebhookSender):
    """Fake ``WebhookSender``: records posts in ``self.posts`` and answers ``status_by_url`` (default 200).

    Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
    """

    def __init__(self, status_by_url: Optional[Dict[str, int]] = None):
        self.posts: List[Dict[str, Any]] = []
        self.status_by_url = dict(status_by_url or {})
        self._lock = threading.Lock()

    def post(self, url: str, body: Dict[str, Any]) -> int:
        with self._lock:
            self.posts.append({"url": url, "body": body})
        return self.status_by_url.get(url, 200)


def _utc_now() -> datetime:
    """Return the current time as an aware UTC datetime. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP."""
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    """Format an aware datetime as UTC ISO-8601 with microseconds, so stored times compare as text.

    Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: one fixed format makes the SQL
    ``<=`` comparisons on scheduled_at / next_retry_at correct. Touches nothing.
    """
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _normalize_scheduled_at(value: Any) -> Optional[str]:
    """Turn a ``scheduled_at`` (ISO string, 'Z' allowed, or datetime; naive means UTC) into ``_iso`` form.

    Returns None for None and raises ValueError for anything unparseable. Added 2026-11-10, session
    session_012zDydZCZ4AChqhEZ4oVtaP: the old code compared the caller's raw string with the clock as
    text, so '...Z' or '+02:00' inputs ran at the wrong time. Touches nothing.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"Invalid scheduled_at: {value!r}") from None
    else:
        raise ValueError(f"Invalid scheduled_at: {value!r}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return _iso(dt)


class BackgroundJobSystem:
    """Job queue plus worker thread over one SQLite database (see the module docstring).

    Rebuilt 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (the original file was truncated).
    Touches the SQLite file at ``db_path``; senders are injected.
    """

    POLL_INTERVAL_SECONDS = 0.05

    def __init__(self, db_path: str = "background_jobs.db",
                 email_sender: Optional[EmailSender] = None,
                 webhook_sender: Optional[WebhookSender] = None):
        """Open/create the schema at ``db_path`` and register the built-in task handlers.

        ``email_sender`` / ``webhook_sender`` default to the in-memory fakes. 2026-11-10, session
        session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (CREATE TABLE IF NOT EXISTS).
        """
        self.db_path = db_path
        self.email_sender = email_sender or InMemoryEmailSender()
        self.webhook_sender = webhook_sender or InMemoryWebhookSender()
        self._handlers: Dict[str, Callable[[Dict[str, Any], Callable[[int, int], None]], Any]] = {}
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._init_db()
        self._register_default_handlers()

    # ------------------------------------------------------------------ storage

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection that commits on success, rolls back on error and is always closed.

        2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: replaces ``with sqlite3.connect()``,
        which commits but never closes. Touches the database.
        """
        conn = sqlite3.connect(self.db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create the jobs, job_runs, sessions and users tables if missing. 2026-11-10, session
        session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database."""
        with self._conn() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                task_type TEXT NOT NULL,
                params TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                progress TEXT,
                result TEXT,
                error TEXT,
                retry_count INTEGER NOT NULL DEFAULT 0,
                max_retries INTEGER NOT NULL DEFAULT 3,
                next_retry_at TEXT,
                scheduled_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
            CREATE TABLE IF NOT EXISTS job_runs (
                id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                result TEXT,
                FOREIGN KEY(job_id) REFERENCES jobs(id)
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL
            );
            """)

    @staticmethod
    def _row_to_job(row: sqlite3.Row) -> Dict[str, Any]:
        """Map a jobs row to the status response (spec endpoint 2 plus params/error/retry fields).

        ``params`` is returned as the stored JSON text; ``result`` is decoded. 2026-11-10, session
        session_012zDydZCZ4AChqhEZ4oVtaP: the old status omitted completed_at, error, retry_count,
        max_retries and params, which the tests read. Touches nothing.
        """
        return {
            "job_id": row["id"],
            "task_type": row["task_type"],
            "status": row["status"],
            "params": row["params"],
            "progress": row["progress"],
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "result": json.loads(row["result"]) if row["result"] else None,
            "error": row["error"],
            "retry_count": row["retry_count"],
            "max_retries": row["max_retries"],
            "next_retry_at": row["next_retry_at"],
            "scheduled_at": row["scheduled_at"],
        }

    # ------------------------------------------------------------------ handlers

    def register_handler(self, task_type: str, handler_func: Callable[[Dict[str, Any], Callable[[int, int], None]], Any]) -> None:
        """Register ``handler_func(params, progress_callback) -> result`` for ``task_type``.

        The result must be JSON-serialisable. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches memory only.
        """
        if not isinstance(task_type, str) or not task_type:
            raise ValueError("task_type must be a non-empty string")
        self._handlers[task_type] = handler_func

    def _register_default_handlers(self) -> None:
        """Register the spec's built-in tasks. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP:
        five of these methods were missing (the AttributeError that failed every test). Touches memory."""
        self.register_handler("send_bulk_email", self._send_bulk_email_handler)
        self.register_handler("webhook_retry", self._webhook_retry_handler)
        self.register_handler("export_generate", self._export_generate_handler)
        self.register_handler("daily_report", self._daily_report_handler)
        self.register_handler("daily_report_generate", self._daily_report_handler)  # the spec's example name
        self.register_handler("cleanup_old_sessions", self._cleanup_old_sessions_handler)
        self.register_handler("delete_user_cascade", self._delete_user_cascade_handler)

    # ------------------------------------------------------------------ API

    def enqueue_job(self, task_type: str, params: Optional[Dict[str, Any]] = None,
                    scheduled_at: Any = None, max_retries: int = 3) -> Dict[str, Any]:
        """POST /jobs/enqueue: store a job as ``enqueued`` and return ``{success, job_id, status}``.

        Inputs: task_type (non-empty str), params (JSON-serialisable dict), scheduled_at (ISO string or
        datetime, optional), max_retries (int >= 0, retries after the first attempt). Raises ValueError
        on bad input. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: input validation and UTC
        normalisation of scheduled_at added. Touches the database (one INSERT); never runs the job.
        """
        if not isinstance(task_type, str) or not task_type:
            raise ValueError("task_type must be a non-empty string")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            raise ValueError("params must be an object")
        if isinstance(max_retries, bool) or not isinstance(max_retries, int) or max_retries < 0:
            raise ValueError("max_retries must be a non-negative integer")
        try:
            params_str = json.dumps(params)
        except (TypeError, ValueError):
            raise ValueError("params must be JSON-serialisable") from None
        scheduled = _normalize_scheduled_at(scheduled_at)
        job_id = str(uuid.uuid4())
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO jobs (id, task_type, params, status, created_at, max_retries, scheduled_at) "
                "VALUES (?, ?, ?, 'enqueued', ?, ?, ?)",
                (job_id, task_type, params_str, _iso(_utc_now()), max_retries, scheduled),
            )
        return {"success": True, "job_id": job_id, "status": "enqueued"}

    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """GET /jobs/:job_id: the job's current state (see ``_row_to_job``); ValueError if unknown.

        2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (read).
        """
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if not row:
            raise ValueError(f"Job {job_id} not found")
        return self._row_to_job(row)

    def list_jobs(self, status: Optional[str] = None, task_type: Optional[str] = None,
                  limit: int = 10) -> Dict[str, Any]:
        """GET /jobs: ``{jobs, total}`` filtered by status/task_type, newest first, at most ``limit``.

        Ties on created_at are broken by insertion order (rowid). 2026-11-10, session
        session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (read).
        """
        if status is not None and status not in JOB_STATUSES:
            raise ValueError(f"Invalid status: {status}")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        where, args = " WHERE 1=1", []
        if status:
            where += " AND status = ?"
            args.append(status)
        if task_type:
            where += " AND task_type = ?"
            args.append(task_type)
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM jobs" + where, args).fetchone()[0]
            rows = conn.execute("SELECT * FROM jobs" + where + " ORDER BY created_at DESC, rowid DESC LIMIT ?",
                                args + [limit]).fetchall()
        return {"jobs": [self._row_to_job(r) for r in rows], "total": total}

    def cancel_job(self, job_id: str) -> Dict[str, Any]:
        """DELETE /jobs/:job_id: cancel a job that has not started; ValueError otherwise.

        One conditional UPDATE (``WHERE status = 'enqueued'``), so a worker cannot claim the job
        between the check and the write. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the old
        read-then-write could cancel a job the worker had just started. Touches the database.
        """
        with self._conn() as conn:
            cur = conn.execute("UPDATE jobs SET status = 'cancelled' WHERE id = ? AND status = 'enqueued'", (job_id,))
            if cur.rowcount == 1:
                return {"success": True, "status": "cancelled"}
            exists = conn.execute("SELECT 1 FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if not exists:
            raise ValueError(f"Job {job_id} not found")
        raise ValueError("Cannot cancel job that has already started or completed")

    def retry_job(self, job_id: str) -> Dict[str, Any]:
        """POST /jobs/:job_id/retry: enqueue a fresh copy of a ``failed`` job.

        Returns ``{success, new_job_id, status: 'enqueued'}``; ValueError if the job is unknown or has
        not failed. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the old code re-ran jobs in
        any state (the spec and Java allow failed jobs only). Touches the database.
        """
        new_job_id = str(uuid.uuid4())
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if not row:
                raise ValueError(f"Job {job_id} not found")
            if row["status"] != "failed":
                raise ValueError(f"Cannot retry job {job_id}: only failed jobs can be retried (status is {row['status']})")
            conn.execute(
                "INSERT INTO jobs (id, task_type, params, status, created_at, max_retries) VALUES (?, ?, ?, 'enqueued', ?, ?)",
                (new_job_id, row["task_type"], row["params"], _iso(_utc_now()), row["max_retries"]),
            )
        return {"success": True, "new_job_id": new_job_id, "status": "enqueued"}

    def get_job_results(self, job_id: str) -> Dict[str, Any]:
        """GET /jobs/:job_id/results: ``{job_id, status, result, completed_at}``; ValueError if unknown.

        2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (read).
        """
        job = self.get_job_status(job_id)
        return {"job_id": job["job_id"], "status": job["status"], "result": job["result"],
                "completed_at": job["completed_at"]}

    # ------------------------------------------------------------------ worker

    def start_worker(self) -> None:
        """Start the daemon worker thread (no-op if running). 2026-11-10, session
        session_012zDydZCZ4AChqhEZ4oVtaP. Touches a thread and the database."""
        if self._worker_thread and self._worker_thread.is_alive():
            return
        self._stop_event.clear()
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()

    def stop_worker(self) -> None:
        """Ask the worker to stop and wait up to 5 s for the current job to finish. Safe to call twice.

        2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the worker thread.
        """
        self._stop_event.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=5)

    def run_pending(self) -> int:
        """Run every job that is due now on the calling thread; return how many ran.

        For cron-style use and deterministic tests without the thread. 2026-11-10, session
        session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database and whatever the handlers touch.
        """
        count = 0
        while True:
            job = self._claim_next_job()
            if not job:
                return count
            self._execute_job(job)
            count += 1

    def _worker_loop(self) -> None:
        """Claim and run due jobs until stopped, sleeping POLL_INTERVAL_SECONDS when idle.

        2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
        """
        while not self._stop_event.is_set():
            job = self._claim_next_job()
            if job:
                self._execute_job(job)
            else:
                self._stop_event.wait(self.POLL_INTERVAL_SECONDS)

    def _claim_next_job(self) -> Optional[Dict[str, Any]]:
        """Atomically move the oldest due ``enqueued`` job to ``running`` and return it (or None).

        Due means scheduled_at and next_retry_at are unset or not in the future. ``BEGIN IMMEDIATE``
        takes the write lock first, so two workers never claim the same job; jobs are taken in
        insertion order. Progress is cleared for the new attempt. 2026-11-10, session
        session_012zDydZCZ4AChqhEZ4oVtaP: the old claim had no ORDER BY and wrote a made-up
        '0/100' progress. Touches the database.
        """
        now = _iso(_utc_now())
        conn = sqlite3.connect(self.db_path, timeout=15, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT id, task_type, params, retry_count, max_retries FROM jobs "
                "WHERE status = 'enqueued' AND (scheduled_at IS NULL OR scheduled_at <= ?) "
                "AND (next_retry_at IS NULL OR next_retry_at <= ?) ORDER BY rowid LIMIT 1",
                (now, now),
            ).fetchone()
            if not row:
                conn.execute("COMMIT")
                return None
            conn.execute("UPDATE jobs SET status = 'running', started_at = ?, progress = NULL WHERE id = ?",
                         (now, row["id"]))
            conn.execute("COMMIT")
            return {"id": row["id"], "task_type": row["task_type"], "params": json.loads(row["params"]),
                    "retry_count": row["retry_count"], "max_retries": row["max_retries"], "started_at": now}
        except sqlite3.Error:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            return None
        finally:
            conn.close()

    def _record_run(self, conn: sqlite3.Connection, job_id: str, status: str, started_at: str,
                    completed_at: str, result_json: str) -> None:
        """Insert one ``job_runs`` row for an attempt. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches the database (caller's transaction)."""
        conn.execute(
            "INSERT INTO job_runs (id, job_id, status, started_at, completed_at, result) VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), job_id, status, started_at, completed_at, result_json),
        )

    def _execute_job(self, job: Dict[str, Any]) -> None:
        """Run one claimed job's handler and store completion or hand the error to ``_handle_failure``.

        The handler gets ``progress_callback(current, total)``, which stores 'current/total' at once so
        GET /jobs/:id shows live progress. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: an
        unknown task type or a ``NonRetryableJobError`` now fails without retries. Touches the
        database and whatever the handler touches.
        """
        job_id = job["id"]

        def progress_callback(current: int, total: int) -> None:
            with self._conn() as conn:
                conn.execute("UPDATE jobs SET progress = ? WHERE id = ?", (f"{int(current)}/{int(total)}", job_id))

        handler = self._handlers.get(job["task_type"])
        if handler is None:
            self._handle_failure(job, f"No handler registered for task type: {job['task_type']}", retryable=False)
            return
        try:
            result = handler(job["params"], progress_callback)
            result_str = json.dumps(result)
        except NonRetryableJobError as e:
            self._handle_failure(job, str(e), retryable=False)
            return
        except Exception as e:  # any handler failure is retried with backoff
            self._handle_failure(job, str(e) or e.__class__.__name__, retryable=True)
            return
        completed_at = _iso(_utc_now())
        with self._conn() as conn:
            conn.execute(
                "UPDATE jobs SET status = 'completed', completed_at = ?, result = ?, error = NULL, next_retry_at = NULL "
                "WHERE id = ?",
                (completed_at, result_str, job_id),
            )
            self._record_run(conn, job_id, "completed", job["started_at"], completed_at, result_str)

    def _handle_failure(self, job: Dict[str, Any], error_msg: str, retryable: bool) -> None:
        """Schedule the next retry (backoff 2**(n-1) seconds for retry n: 1 s, 2 s, 4 s, ...) or fail the job.

        ``retry_count`` is the number of retries used; once it equals ``max_retries`` the next failure
        is final and the job becomes ``failed`` with retry_count unchanged. 2026-11-10, session
        session_012zDydZCZ4AChqhEZ4oVtaP: matches the spec's "1s, 2s, 4s, 8s ... up to max_retries" and
        the Java implementation (the old code waited 2**retry_count before the increment). Touches
        the database.
        """
        now = _utc_now()
        completed_at = _iso(now)
        run_result = json.dumps({"error": error_msg})
        next_retry = job["retry_count"] + 1
        with self._conn() as conn:
            if retryable and next_retry <= job["max_retries"]:
                next_retry_at = _iso(now + timedelta(seconds=2 ** (next_retry - 1)))
                conn.execute(
                    "UPDATE jobs SET status = 'enqueued', retry_count = ?, next_retry_at = ?, error = ? WHERE id = ?",
                    (next_retry, next_retry_at, error_msg, job["id"]),
                )
            else:
                conn.execute(
                    "UPDATE jobs SET status = 'failed', completed_at = ?, error = ?, next_retry_at = NULL WHERE id = ?",
                    (completed_at, error_msg, job["id"]),
                )
            self._record_run(conn, job["id"], "failed", job["started_at"], completed_at, run_result)

    # ------------------------------------------------------------------ built-in tasks

    def _send_bulk_email_handler(self, params: Dict[str, Any], progress_callback: Callable[[int, int], None]) -> Dict[str, Any]:
        """Task send_bulk_email: send ``template_key`` to each of ``params['recipients']`` via ``email_sender``.

        Each recipient is ``{"user_id", "email", "opted_out"?}`` or a bare address. Opted-out or
        address-less recipients are skipped; a send that raises is counted as failed with its error.
        Returns ``{task_type, sent, failed, skipped, errors}`` (spec endpoint 6). Progress after each
        recipient. Recipients are never invented. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches the e-mail sender (network in production).
        """
        template_key = params.get("template_key")
        if not template_key:
            raise NonRetryableJobError("template_key is required")
        recipients = params.get("recipients", [])
        if not isinstance(recipients, list):
            raise NonRetryableJobError("recipients must be a list")
        variables = params.get("variables") or {}
        total = len(recipients)
        sent = failed = skipped = 0
        errors: List[Dict[str, Any]] = []
        for idx, rec in enumerate(recipients, start=1):
            if isinstance(rec, str):
                rec = {"user_id": None, "email": rec}
            email = rec.get("email") if isinstance(rec, dict) else None
            if not email or rec.get("opted_out"):
                skipped += 1
            else:
                try:
                    self.email_sender.send(email, template_key, variables)
                    sent += 1
                except Exception as e:
                    failed += 1
                    errors.append({"user_id": rec.get("user_id"), "error": str(e) or e.__class__.__name__})
            progress_callback(idx, total)
        return {"task_type": "send_bulk_email", "sent": sent, "failed": failed, "skipped": skipped, "errors": errors}

    def _webhook_retry_handler(self, params: Dict[str, Any], progress_callback: Callable[[int, int], None]) -> Dict[str, Any]:
        """Task webhook_retry: re-POST ``params['payload']`` to ``params['url']`` via ``webhook_sender``.

        A 2xx answer completes the job; a 5xx answer or connection error raises so the queue retries
        with backoff (spec: "500+ failures auto-retry"); any other answer fails the job without
        retrying. Returns ``{task_type, url, status_code}``. 2026-11-10, session
        session_012zDydZCZ4AChqhEZ4oVtaP: the method was missing. Touches the webhook sender (network).
        """
        url = params.get("url")
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            raise NonRetryableJobError("url must be an http(s) URL")
        status_code = self.webhook_sender.post(url, params.get("payload") or {})
        progress_callback(1, 1)
        if 200 <= status_code < 300:
            return {"task_type": "webhook_retry", "url": url, "status_code": status_code}
        if status_code >= 500:
            raise RuntimeError(f"webhook delivery failed with HTTP {status_code}")
        raise NonRetryableJobError(f"webhook rejected with HTTP {status_code}")

    def _export_generate_handler(self, params: Dict[str, Any], progress_callback: Callable[[int, int], None]) -> Dict[str, Any]:
        """Task export_generate: build a JSON export of one user's rows held in this database.

        Input ``user_id``. Output ``{task_type, user_id, data: {users: [...], sessions: [...]}, record_count}``.
        A full GDPR export belongs to the Data Export system; this is the queue-side hook it plugs into.
        2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the method was missing. Touches the
        database (read).
        """
        user_id = params.get("user_id")
        if not user_id:
            raise NonRetryableJobError("user_id is required")
        with self._conn() as conn:
            users = [dict(r) for r in conn.execute("SELECT id, email FROM users WHERE id = ?", (str(user_id),))]
            progress_callback(1, 2)
            sessions = [dict(r) for r in conn.execute(
                "SELECT id, created_at FROM sessions WHERE user_id = ? ORDER BY created_at, rowid", (str(user_id),))]
            progress_callback(2, 2)
        return {"task_type": "export_generate", "user_id": str(user_id),
                "data": {"users": users, "sessions": sessions}, "record_count": len(users) + len(sessions)}

    def _daily_report_handler(self, params: Dict[str, Any], progress_callback: Callable[[int, int], None]) -> Dict[str, Any]:
        """Task daily_report: count the jobs created in the 24 hours before ``params['as_of']`` (default now), by status.

        Output ``{task_type, period_start, period_end, jobs_by_status, total_jobs}``. Real numbers from
        this database, never fabricated metrics. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP:
        the method was missing. Touches the database (read).
        """
        end = _normalize_scheduled_at(params.get("as_of")) or _iso(_utc_now())
        start = _iso(datetime.fromisoformat(end) - timedelta(days=1))
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS n FROM jobs WHERE created_at >= ? AND created_at < ? GROUP BY status ORDER BY status",
                (start, end),
            ).fetchall()
        by_status = {s: 0 for s in JOB_STATUSES}
        for r in rows:
            by_status[r["status"]] = r["n"]
        progress_callback(1, 1)
        return {"task_type": "daily_report", "period_start": start, "period_end": end,
                "jobs_by_status": by_status, "total_jobs": sum(by_status.values())}

    def _cleanup_old_sessions_handler(self, params: Dict[str, Any], progress_callback: Callable[[int, int], None]) -> Dict[str, Any]:
        """Task cleanup_old_sessions: delete sessions older than ``params['days']`` (default 30, spec).

        Output ``{task_type, days, deleted}``. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the
        method was missing. Touches the database (DELETE).
        """
        days = params.get("days", 30)
        if isinstance(days, bool) or not isinstance(days, int) or days < 1:
            raise NonRetryableJobError("days must be a positive integer")
        cutoff = _iso(_utc_now() - timedelta(days=days))
        with self._conn() as conn:
            deleted = conn.execute("DELETE FROM sessions WHERE created_at < ?", (cutoff,)).rowcount
        progress_callback(1, 1)
        return {"task_type": "cleanup_old_sessions", "days": days, "deleted": deleted}

    def _delete_user_cascade_handler(self, params: Dict[str, Any], progress_callback: Callable[[int, int], None]) -> Dict[str, Any]:
        """Task delete_user_cascade: delete a user and their sessions in one transaction.

        Input ``user_id``. Output ``{task_type, user_id, sessions_deleted, user_deleted}``. Running it
        twice is harmless. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the method was missing.
        Touches the database (DELETE).
        """
        user_id = params.get("user_id")
        if not user_id:
            raise NonRetryableJobError("user_id is required")
        with self._conn() as conn:
            sessions_deleted = conn.execute("DELETE FROM sessions WHERE user_id = ?", (str(user_id),)).rowcount
            user_deleted = conn.execute("DELETE FROM users WHERE id = ?", (str(user_id),)).rowcount
        progress_callback(1, 1)
        return {"task_type": "delete_user_cascade", "user_id": str(user_id),
                "sessions_deleted": sessions_deleted, "user_deleted": user_deleted == 1}

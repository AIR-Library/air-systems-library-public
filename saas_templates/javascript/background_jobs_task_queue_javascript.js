'use strict';

/**
 * Background jobs and task queue: a database-backed queue (SQLite through better-sqlite3), a polling worker, retries
 * with exponential backoff (1 s, 2 s, 4 s, ...), scheduled jobs, progress and results.
 * Contract: TIER_2_MASTER_SPEC_6SYSTEMS.txt, SYSTEM 4.
 *
 * Repair, 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. The suite hung until the runner's 300 s timeout:
 * the worker was a `setInterval` started when the module loaded and never stopped, so the test process could not exit.
 * Two tests also failed: `get()` did not return `retry_count`, and a job that ran out of retries reported one retry
 * more than it was allowed. Now:
 *   - the worker runs only after `start()` and `stop()` ends it; its timer is unref'd;
 *   - time comes from an injectable clock (`now`), and `tick()` runs every due job, so tests drive the queue
 *     exactly instead of sleeping against a real timer;
 *   - backoff follows the spec (1 s before the first retry, then 2 s, 4 s, ...), as the passing Java template does;
 *   - task handlers no longer fail at random (`Math.random`) or sleep to fake work: they call injected services,
 *     whose in-memory defaults succeed, and yield to the event loop so a long job does not block requests;
 *   - unknown task types are refused at enqueue, every run is recorded in job_runs, claims stay atomic.
 *
 * Touches: the SQLite database given (jobs, job_runs), and whatever services are injected (e-mail, webhooks, user
 * deletion); the defaults touch memory only. No network.
 */

const crypto = require('crypto');
const express = require('express');
const Database = require('better-sqlite3');
const EventEmitter = require('events');

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    task_type TEXT NOT NULL,
    params TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('enqueued','running','completed','failed','cancelled')),
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
CREATE INDEX IF NOT EXISTS jobs_due ON jobs (status, scheduled_at, next_retry_at);

CREATE TABLE IF NOT EXISTS job_runs (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    result TEXT,
    FOREIGN KEY(job_id) REFERENCES jobs(id)
);
`;

const MAX_RETRIES_LIMIT = 10;
const YIELD_EVERY = 100; // items processed between yields to the event loop

/**
 * Delay before retry number `retryNumber` (1-based): base, 2 x base, 4 x base, ...
 * In: retry number, base delay in ms (default 1000). Out: milliseconds.
 * Why: spec "Retry: Exponential backoff (1s, 2s, 4s, 8s, ...)"; the old formula started at 2 s, so a job allowed one
 * retry was still waiting when it should have failed (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
 */
function exponentialBackoffMs(retryNumber, baseMs = 1000) {
  return baseMs * 2 ** (retryNumber - 1);
}

/**
 * Lets other callbacks (HTTP requests, timers) run before a long job continues. Out: a promise.
 * Why: spec "Bulk job: 10,000 items processed without blocking request" (2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
 */
function yieldToEventLoop() {
  return new Promise((resolve) => setImmediate(resolve));
}

/**
 * In-memory stand-ins for the systems the example tasks call. Replace them with real ones (the Notifications,
 * Webhooks and Data Export templates) through `createJobService({ services })`.
 * Out: { sendEmail, deliverWebhook, deleteSessionsBefore, deleteUserCascade, sentEmails, deliveredWebhooks }.
 * Why: the handlers used to fail at random and sleep to imitate work, so results changed from run to run (2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP). Touches: memory only.
 */
function createInMemoryServices() {
  const sentEmails = [];
  const deliveredWebhooks = [];
  return {
    sentEmails,
    deliveredWebhooks,
    async sendEmail(message) { sentEmails.push(message); },
    async deliverWebhook(delivery) { deliveredWebhooks.push(delivery); },
    async deleteSessionsBefore() { return 0; },
    async deleteUserCascade(userId) { return { deleted_user_id: userId }; },
  };
}

/**
 * The task types this queue can run. Each handler: async (params, ctx) => result, where ctx = { job_id, progress(done,
 * total), services, now(), db }. A handler that throws fails the run, and the job is retried with backoff.
 * Why: spec "TASKS TO BUILD". Rewritten 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP) to be deterministic and to
 * report real counts. Touches: whatever the injected services touch; daily_report reads the jobs table.
 */
const TASK_HANDLERS = {
  async send_bulk_email(params, ctx) {
    const recipients = Array.isArray(params.recipients)
      ? params.recipients
      : Array.from({ length: Number(params.total) || 0 }, (_, i) => ({ user_id: i + 1, email: `user${i + 1}@example.com` }));
    const result = { task_type: 'send_bulk_email', sent: 0, failed: 0, skipped: 0, errors: [], total: recipients.length };
    for (let i = 0; i < recipients.length; i += 1) {
      const r = recipients[i];
      if (r.opted_out) {
        result.skipped += 1;
        result.errors.push({ user_id: r.user_id, error: 'opted_out' });
      } else {
        try {
          await ctx.services.sendEmail({ to: r.email, user_id: r.user_id, template_key: params.template_key || null });
          result.sent += 1;
        } catch (err) {
          result.failed += 1;
          result.errors.push({ user_id: r.user_id, error: err.message });
        }
      }
      ctx.progress(i + 1, recipients.length);
      if ((i + 1) % YIELD_EVERY === 0) await yieldToEventLoop();
    }
    return result;
  },

  async webhook_retry(params, ctx) {
    const deliveries = Array.isArray(params.deliveries) ? params.deliveries : [];
    const result = { task_type: 'webhook_retry', delivered: 0, failed: 0, errors: [] };
    for (let i = 0; i < deliveries.length; i += 1) {
      try {
        await ctx.services.deliverWebhook(deliveries[i]);
        result.delivered += 1;
      } catch (err) {
        result.failed += 1;
        result.errors.push({ delivery: i, error: err.message });
      }
      ctx.progress(i + 1, deliveries.length);
      if ((i + 1) % YIELD_EVERY === 0) await yieldToEventLoop();
    }
    return result;
  },

  async export_generate(params, ctx) {
    const items = Number(params.items) || 0;
    for (let i = 1; i <= items; i += 1) {
      ctx.progress(i, items);
      if (i % YIELD_EVERY === 0) await yieldToEventLoop();
    }
    return { task_type: 'export_generate', exported: items };
  },

  async daily_report(params, ctx) {
    const rows = ctx.db.prepare('SELECT status, COUNT(*) AS n FROM jobs GROUP BY status ORDER BY status').all();
    ctx.progress(1, 1);
    return {
      task_type: 'daily_report',
      report: 'daily_metrics',
      generated_at: new Date(ctx.now()).toISOString(),
      jobs_by_status: Object.fromEntries(rows.map((r) => [r.status, r.n])),
    };
  },

  async cleanup_old_sessions(params, ctx) {
    const days = Number(params.older_than_days) || 30;
    const cutoff = new Date(ctx.now() - days * 24 * 60 * 60 * 1000).toISOString();
    const cleaned = await ctx.services.deleteSessionsBefore(cutoff);
    ctx.progress(1, 1);
    return { task_type: 'cleanup_old_sessions', cleaned, cutoff };
  },

  async delete_user_cascade(params, ctx) {
    if (params.user_id == null) throw new Error('params.user_id is required');
    const out = await ctx.services.deleteUserCascade(params.user_id);
    ctx.progress(1, 1);
    return { task_type: 'delete_user_cascade', ...out };
  },
};

/**
 * Error with an HTTP status, for the routes. Why: not-found, invalid input and wrong state answer 404, 400 and 409
 * instead of one generic 400 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
 */
class JobError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/**
 * The queue and its worker.
 *
 * In: a better-sqlite3 database with SCHEMA_SQL applied, and options
 *   now            clock in ms (default Date.now); every timestamp and every "is it due" check uses it
 *   pollIntervalMs how often start()'s timer calls tick() (default 1000)
 *   retryBaseMs    first retry delay (default 1000)
 *   handlers       task_type -> handler (default TASK_HANDLERS)
 *   services       what the handlers call (default createInMemoryServices())
 * Events: 'progress' { job_id, progress }, 'completed' { job_id }, 'failed' { job_id, error }, 'retry' { job_id,
 * retry_count, next_retry_at }.
 *
 * Why: the old manager started a never-ending timer in its constructor (the 300 s hang) and read the wall clock
 * directly (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: database (jobs, job_runs), injected services.
 */
class JobManager extends EventEmitter {
  constructor(db, options = {}) {
    super();
    this.db = db;
    this.now = options.now || Date.now;
    this.pollIntervalMs = options.pollIntervalMs || 1000;
    this.retryBaseMs = options.retryBaseMs || 1000;
    this.handlers = options.handlers || TASK_HANDLERS;
    this.services = options.services || createInMemoryServices();
    this.timer = null;
    this.currentTick = null;
  }

  /** Current clock time as ISO-8601. Out: string. Why: one clock for every timestamp (2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing. */
  nowIso() {
    return new Date(this.now()).toISOString();
  }

  /**
   * Adds a job to the queue.
   * In: { task_type, params (object), scheduled_at (ISO-8601 or null), max_retries (0-10, default 3) }.
   * Out: { success: true, job_id, status: 'enqueued' }; throws JobError(400) on invalid input.
   * Why: spec endpoint 1; now refuses unknown task types and malformed times instead of storing jobs that can only
   * fail (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: database.
   */
  enqueue({ task_type: taskType, params, scheduled_at: scheduledAt, max_retries: maxRetries = 3 }) {
    if (!taskType || !Object.prototype.hasOwnProperty.call(this.handlers, taskType)) {
      throw new JobError(400, `Unknown task_type: ${taskType}`);
    }
    if (params === null || typeof params !== 'object' || Array.isArray(params)) {
      throw new JobError(400, 'params must be an object');
    }
    if (!Number.isInteger(maxRetries) || maxRetries < 0 || maxRetries > MAX_RETRIES_LIMIT) {
      throw new JobError(400, `max_retries must be an integer from 0 to ${MAX_RETRIES_LIMIT}`);
    }
    let scheduled = null;
    if (scheduledAt != null) {
      const ms = Date.parse(scheduledAt);
      if (Number.isNaN(ms)) throw new JobError(400, 'scheduled_at must be an ISO-8601 time');
      scheduled = new Date(ms).toISOString();
    }
    const id = crypto.randomUUID();
    this.db.prepare(`
      INSERT INTO jobs (id, task_type, params, status, created_at, max_retries, scheduled_at)
      VALUES (?, ?, ?, 'enqueued', ?, ?, ?)
    `).run(id, taskType, JSON.stringify(params), this.nowIso(), maxRetries, scheduled);
    return { success: true, job_id: id, status: 'enqueued' };
  }

  /**
   * One job's status. In: job id. Out: the spec's status object plus retry_count, max_retries, error, scheduled_at,
   * or null when there is no such job.
   * Why: spec endpoint 2; retry_count was missing (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: database.
   */
  get(jobId) {
    const row = this.db.prepare('SELECT * FROM jobs WHERE id = ?').get(jobId);
    if (!row) return null;
    return {
      job_id: row.id,
      task_type: row.task_type,
      status: row.status,
      progress: row.progress,
      created_at: row.created_at,
      started_at: row.started_at,
      completed_at: row.completed_at,
      scheduled_at: row.scheduled_at,
      result: row.result ? JSON.parse(row.result) : null,
      error: row.error,
      retry_count: row.retry_count,
      max_retries: row.max_retries,
      next_retry_at: row.next_retry_at,
    };
  }

  /**
   * Lists jobs, newest first (ties by insertion order).
   * In: { status, task_type, limit (1-100, default 10), offset }. Out: { jobs, total }.
   * Why: spec endpoint 3 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: bounded limit, stable order). Touches: database.
   */
  list({ status, task_type: taskType, limit = 10, offset = 0 } = {}) {
    const conditions = [];
    const args = [];
    if (status) { conditions.push('status = ?'); args.push(String(status)); }
    if (taskType) { conditions.push('task_type = ?'); args.push(String(taskType)); }
    const where = conditions.length ? ` WHERE ${conditions.join(' AND ')}` : '';
    const lim = Math.min(Math.max(Number(limit) || 10, 1), 100);
    const off = Math.max(Number(offset) || 0, 0);
    const rows = this.db.prepare(`SELECT * FROM jobs${where} ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?`)
      .all(...args, lim, off);
    const { cnt } = this.db.prepare(`SELECT COUNT(*) AS cnt FROM jobs${where}`).get(...args);
    return {
      jobs: rows.map((r) => ({
        job_id: r.id,
        task_type: r.task_type,
        status: r.status,
        progress: r.progress,
        created_at: r.created_at,
        started_at: r.started_at,
        completed_at: r.completed_at,
      })),
      total: cnt,
    };
  }

  /**
   * Cancels a job that is not running. In: job id. Out: { success: true, status: 'cancelled' }; JobError 404 / 409.
   * Why: spec endpoint 4; the check and the update are now one statement, so a worker cannot claim the job in
   * between (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: database.
   */
  cancel(jobId) {
    const info = this.db.prepare(`UPDATE jobs SET status = 'cancelled', completed_at = ?
      WHERE id = ? AND status = 'enqueued'`).run(this.nowIso(), jobId);
    if (info.changes === 0) {
      if (!this.db.prepare('SELECT 1 FROM jobs WHERE id = ?').get(jobId)) throw new JobError(404, 'Job not found');
      throw new JobError(409, 'Only enqueued jobs can be cancelled');
    }
    return { success: true, status: 'cancelled' };
  }

  /**
   * Re-enqueues a failed job as a new job with the same task and params.
   * In: job id. Out: { success: true, new_job_id, status: 'enqueued' }; JobError 404 / 409.
   * Why: spec endpoint 5 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: documented, uses the clock). Touches: database.
   */
  retry(jobId) {
    const orig = this.db.prepare('SELECT * FROM jobs WHERE id = ?').get(jobId);
    if (!orig) throw new JobError(404, 'Job not found');
    if (orig.status !== 'failed') throw new JobError(409, 'Only failed jobs can be retried');
    const newId = crypto.randomUUID();
    this.db.prepare(`
      INSERT INTO jobs (id, task_type, params, status, created_at, max_retries)
      VALUES (?, ?, ?, 'enqueued', ?, ?)
    `).run(newId, orig.task_type, orig.params, this.nowIso(), orig.max_retries);
    return { success: true, new_job_id: newId, status: 'enqueued' };
  }

  /**
   * Results of a completed job. In: job id. Out: { job_id, status, result, completed_at }; JobError 404 / 409.
   * Why: spec endpoint 6 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: status codes). Touches: database.
   */
  getResults(jobId) {
    const row = this.db.prepare('SELECT * FROM jobs WHERE id = ?').get(jobId);
    if (!row) throw new JobError(404, 'Job not found');
    if (row.status !== 'completed') throw new JobError(409, 'Job not completed');
    return {
      job_id: row.id,
      status: row.status,
      result: row.result ? JSON.parse(row.result) : null,
      completed_at: row.completed_at,
    };
  }

  /**
   * Atomically claims the oldest due job (enqueued, scheduled_at and next_retry_at not in the future; ties broken by
   * insertion order) and records a run for it.
   * Out: the claimed row, or null. Why: spec "Atomic updates" and "Scheduled jobs: check scheduled_at" (2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP: one transaction, job_runs recorded). Touches: database.
   */
  claimNext() {
    const nowIso = this.nowIso();
    return this.db.transaction(() => {
      const job = this.db.prepare(`
        SELECT * FROM jobs
        WHERE status = 'enqueued'
          AND (scheduled_at IS NULL OR scheduled_at <= ?)
          AND (next_retry_at IS NULL OR next_retry_at <= ?)
        ORDER BY created_at ASC, rowid ASC
        LIMIT 1
      `).get(nowIso, nowIso);
      if (!job) return null;
      const info = this.db.prepare(`UPDATE jobs SET status = 'running', started_at = ?, progress = '0/0'
        WHERE id = ? AND status = 'enqueued'`).run(nowIso, job.id);
      if (info.changes === 0) return null;
      const runId = crypto.randomUUID();
      this.db.prepare(`INSERT INTO job_runs (id, job_id, status, started_at) VALUES (?, ?, 'running', ?)`)
        .run(runId, job.id, nowIso);
      return { ...job, run_id: runId };
    })();
  }

  /**
   * Runs one claimed job to the end and records the outcome: completed with its result; or, on an error, enqueued
   * again with retry_count + 1 and next_retry_at = now + backoff; or failed once max_retries retries have been used
   * (retry_count then stays at max_retries).
   * In: the row from claimNext(). Out: a promise. Why: spec retry rules; the old code reported max_retries + 1
   * retries on the failed job (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: database, injected services.
   */
  async runJob(job) {
    const ctx = {
      job_id: job.id,
      db: this.db,
      now: this.now,
      services: this.services,
      progress: (done, total) => {
        const progress = `${done}/${total}`;
        this.db.prepare('UPDATE jobs SET progress = ? WHERE id = ?').run(progress, job.id);
        this.emit('progress', { job_id: job.id, progress });
      },
    };
    try {
      const handler = this.handlers[job.task_type];
      if (!handler) throw new Error(`No handler for task_type ${job.task_type}`);
      const result = await handler(JSON.parse(job.params), ctx);
      const resultJson = JSON.stringify(result === undefined ? null : result);
      const doneAt = this.nowIso();
      this.db.prepare(`UPDATE jobs SET status = 'completed', completed_at = ?, result = ?, error = NULL,
        next_retry_at = NULL WHERE id = ?`).run(doneAt, resultJson, job.id);
      this.db.prepare(`UPDATE job_runs SET status = 'completed', completed_at = ?, result = ? WHERE id = ?`)
        .run(doneAt, resultJson, job.run_id);
      this.emit('completed', { job_id: job.id });
    } catch (err) {
      const message = err && err.message ? err.message : String(err);
      const at = this.nowIso();
      this.db.prepare(`UPDATE job_runs SET status = 'failed', completed_at = ?, result = ? WHERE id = ?`)
        .run(at, JSON.stringify({ error: message }), job.run_id);
      const retryNumber = job.retry_count + 1;
      if (retryNumber <= job.max_retries) {
        const nextRetryAt = new Date(this.now() + exponentialBackoffMs(retryNumber, this.retryBaseMs)).toISOString();
        this.db.prepare(`UPDATE jobs SET status = 'enqueued', retry_count = ?, next_retry_at = ?, error = ?,
          progress = NULL WHERE id = ?`).run(retryNumber, nextRetryAt, message, job.id);
        this.emit('retry', { job_id: job.id, retry_count: retryNumber, next_retry_at: nextRetryAt });
      } else {
        this.db.prepare(`UPDATE jobs SET status = 'failed', completed_at = ?, error = ?, next_retry_at = NULL
          WHERE id = ?`).run(at, message, job.id);
        this.emit('failed', { job_id: job.id, error: message });
      }
    }
  }

  /**
   * One poll of the worker: runs every job that is due now, one after another, oldest first. If a tick is already in
   * progress, returns that one instead of starting a second.
   * Out: a promise of the number of runs. Why: lets the timer and tests drive the queue the same way, and keeps one
   * job running at a time (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: database, injected services.
   */
  tick() {
    if (this.currentTick) return this.currentTick;
    this.currentTick = (async () => {
      let runs = 0;
      for (let job = this.claimNext(); job; job = this.claimNext()) {
        await this.runJob(job);
        runs += 1;
      }
      return runs;
    })().finally(() => { this.currentTick = null; });
    return this.currentTick;
  }

  /**
   * Starts polling every pollIntervalMs. The timer is unref'd, so it never keeps the process alive by itself.
   * Out: this. Why: the worker used to start in the constructor and never stop, which hung the test run for 300 s
   * (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: a timer.
   */
  start() {
    if (!this.timer) {
      this.timer = setInterval(() => {
        this.tick().catch((err) => console.error('job worker tick failed:', err && err.message));
      }, this.pollIntervalMs);
      if (typeof this.timer.unref === 'function') this.timer.unref();
    }
    return this;
  }

  /**
   * Stops polling and waits for the job that is running, if any. Out: a promise.
   * Why: clean shutdown, and an exit path for tests (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: a timer.
   */
  async stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    if (this.currentTick) await this.currentTick;
  }
}

/**
 * Builds the job service: database, manager and HTTP routes.
 * In: { db (default new in-memory better-sqlite3), now, pollIntervalMs, retryBaseMs, handlers, services,
 * autoStart (default false) }. Out: { app, db, jobManager }.
 * Why: the old module built one app, one database and a running worker as a side effect of `require` (2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP). Touches: database; starts a timer only with autoStart.
 */
function createJobService(options = {}) {
  const db = options.db || new Database(':memory:');
  db.exec(SCHEMA_SQL);
  const jobManager = new JobManager(db, options);
  if (options.autoStart) jobManager.start();

  const app = express();
  app.use(express.json({ limit: '1mb' }));

  /**
   * Wraps a route: JobError becomes its status with { success: false, error }, anything else a 500.
   * Why: one error shape (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
   */
  const route = (fn) => (req, res) => {
    try {
      res.json(fn(req));
    } catch (err) {
      const status = err instanceof JobError ? err.status : 500;
      if (status === 500) console.error('job route failed:', err && err.message);
      res.status(status).json({ success: false, error: status === 500 ? 'internal_error' : err.message });
    }
  };

  /**
   * Routes (spec endpoints 1-6): POST /jobs/enqueue, GET /jobs, GET /jobs/:id, DELETE /jobs/:id (cancel),
   * POST /jobs/:id/retry, GET /jobs/:id/results. Each delegates to JobManager; errors answer { success: false, error }
   * with 400, 404 or 409. Add authentication in front of them before exposing the service.
   * Why: 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: proper status codes, unknown task types refused. Touches: database.
   */
  app.post('/jobs/enqueue', route((req) => jobManager.enqueue(req.body || {})));
  app.get('/jobs', route((req) => jobManager.list(req.query)));
  app.get('/jobs/:job_id', route((req) => {
    const job = jobManager.get(req.params.job_id);
    if (!job) throw new JobError(404, 'Job not found');
    return job;
  }));
  app.delete('/jobs/:job_id', route((req) => jobManager.cancel(req.params.job_id)));
  app.post('/jobs/:job_id/retry', route((req) => jobManager.retry(req.params.job_id)));
  app.get('/jobs/:job_id/results', route((req) => jobManager.getResults(req.params.job_id)));

  return { app, db, jobManager };
}

// Run as a server: `JOBS_DB_FILE=jobs.sqlite3 node background_jobs_task_queue_javascript.js`
if (require.main === module) {
  const { app } = createJobService({ db: new Database(process.env.JOBS_DB_FILE || 'jobs.sqlite3'), autoStart: true });
  const port = Number(process.env.PORT) || 3000;
  app.listen(port, () => console.log(`Background job service listening on ${port}`));
}

module.exports = {
  createJobService,
  createInMemoryServices,
  JobManager,
  JobError,
  TASK_HANDLERS,
  SCHEMA_SQL,
  exponentialBackoffMs,
};

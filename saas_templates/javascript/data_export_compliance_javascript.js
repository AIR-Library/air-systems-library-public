'use strict';

/**
 * Data export and account deletion (GDPR / CCPA): a user exports everything held about them (JSON or CSV, delivered
 * by an e-mailed, signed, 7-day download link) and deletes their account (e-mail confirmation, 30-day grace period in
 * which they can cancel, then a cascade delete that keeps the audit log). Admins list both kinds of request.
 * Contract: TIER_2_MASTER_SPEC_6SYSTEMS.txt, SYSTEM 3.
 *
 * Who the caller is: an access token from the auth system (auth_system_javascript.js signs `{ user_id, tier }` with
 * HS256 and JWT_SECRET) in `Authorization: Bearer <token>`. The user row is read on every request; the admin routes
 * check the tier stored there.
 *
 * Outside services sit behind interfaces so the template runs with no network:
 *   storage      put / signedUrl / delete (S3ExportStorage for AWS S3 with SSE; InMemoryExportStorage, the fake the
 *                tests use, signs URLs with an HMAC and enforces their expiry);
 *   transporter  anything with nodemailer's `sendMail` (default: nodemailer's streamTransport, which builds the message
 *                and sends nothing).
 *
 * Repair, 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Six of nine tests failed:
 *   - export generation called the real AWS S3 from the tests (no credentials, so every export failed);
 *   - the 30-day grace period was a setTimeout of 2,592,000,000 ms, beyond Node's 32-bit timer limit, so Node ran it
 *     after 1 ms: a confirmed deletion wiped the account at once and later requests found no user;
 *   - admin routes trusted an `x-admin: true` header any client can send, and the user's identity was a bare
 *     `x-user-id` header; the old tests' admin calls were refused with 401 because they sent no user at all.
 * Also fixed: confirmation tokens were stored and compared in plain text (now SHA-256, constant-time); admin listings
 * handed out every user's download links and confirmation tokens; CSV cells were not escaped (formula injection);
 * export files stayed in storage after the account was deleted; the schema was used before it was created.
 *
 * Touches: the SQLite database (personal data: read for export, deleted on confirmed deletion), file storage (export
 * files), e-mail. Nothing secret is logged.
 */

const crypto = require('crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const { rateLimit } = require('express-rate-limit');
const nodemailer = require('nodemailer');
const sqlite3 = require('sqlite3');
const util = require('util');

const DAY_MS = 24 * 60 * 60 * 1000;
const GRACE_PERIOD_MS = 30 * DAY_MS;
const DOWNLOAD_TTL_SECONDS = 7 * 24 * 60 * 60;
const DELETION_REASONS = ['user_requested', 'gdpr_request', 'gdpr_right_to_be_forgotten', 'other'];

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    name TEXT,
    created_at TEXT,
    tier TEXT,
    status TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY, user_id TEXT, ip TEXT, device TEXT, created_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS activity (
    id TEXT PRIMARY KEY, user_id TEXT, type TEXT, details TEXT, created_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY, user_id TEXT, filename TEXT, size INTEGER, created_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS preferences (
    user_id TEXT PRIMARY KEY, notifications TEXT, theme TEXT, language TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY, user_id TEXT, amount REAL, currency TEXT, type TEXT, created_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY, user_id TEXT, name TEXT, created_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    action TEXT,
    details TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS export_requests (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    requested_at TEXT,
    status TEXT CHECK(status IN ('pending','completed','failed')),
    format TEXT CHECK(format IN ('json','csv')),
    storage_key TEXT,
    file_url TEXT,
    completed_at TEXT,
    expires_at TEXT
);
CREATE TABLE IF NOT EXISTS deletion_requests (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    requested_at TEXT,
    status TEXT CHECK(status IN ('pending','approved','completed','cancelled')),
    reason TEXT,
    confirmation_token_hash TEXT,
    will_delete_at TEXT,
    confirmed_at TEXT,
    cancelled_at TEXT,
    deleted_at TEXT
);
`;

/**
 * SHA-256 of a token, hex. In: token. Out: hash.
 * Why: deletion confirmation tokens were stored in plain text, so a database leak could confirm anyone's deletion
 * (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
 */
function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

/**
 * Compares two strings in constant time. In: two values. Out: true only for equal strings of equal length.
 * Why: token and signature checks must not leak through timing (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
 * Touches: nothing.
 */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

/**
 * Writes one CSV cell: quoted when it holds a comma, quote or line break, and prefixed with ' when it starts with
 * = + - @ (so a spreadsheet does not run it as a formula). In: any value. Out: string.
 * Why: values were joined with commas as they were, which broke rows and allowed formula injection (2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
 */
function csvCell(value) {
  if (value === null || value === undefined) return '';
  let text = String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/**
 * Turns the collected data into CSV: one section per category, each with a header line.
 * In: { profile, sessions, ... } as built by collectUserData. Out: CSV text.
 * Why: spec "Export: JSON and CSV formats" (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: escaped cells, columns
 * from the union of keys). Touches: nothing.
 */
function toCsv(data) {
  const lines = [];
  for (const [title, value] of Object.entries(data)) {
    lines.push(`--- ${title} ---`);
    const rows = Array.isArray(value) ? value : (value ? [value] : []);
    if (rows.length) {
      const columns = [...new Set(rows.flatMap((r) => Object.keys(r)))];
      lines.push(columns.map(csvCell).join(','));
      for (const r of rows) lines.push(columns.map((c) => csvCell(r[c])).join(','));
    }
    lines.push('');
  }
  return lines.join('\n');
}

/**
 * Export file storage kept in memory, with download links signed by an HMAC that stop working after their expiry.
 * The fake the tests use; behaves like S3 presigned GET URLs.
 * In (constructor): { secret (default random), now (clock in ms), baseUrl }.
 * Why: the template called the real AWS S3 from its tests (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
 * Touches: memory only.
 */
class InMemoryExportStorage {
  constructor({ secret, now, baseUrl } = {}) {
    this.secret = secret || crypto.randomBytes(32).toString('hex');
    this.now = now || Date.now;
    this.baseUrl = baseUrl || 'https://storage.example.com/exports';
    this.objects = new Map();
  }

  /** Stores a file. In: key, body, { contentType }. Out: a promise. Touches: memory. */
  async put(key, body, { contentType } = {}) {
    this.objects.set(key, { body: String(body), contentType: contentType || 'application/octet-stream' });
  }

  /** HMAC over key and expiry. In: key, expiry (unix seconds). Out: hex. Touches: nothing. */
  sign(key, expires) {
    return crypto.createHmac('sha256', this.secret).update(`GET\n${key}\n${expires}`).digest('hex');
  }

  /**
   * A download-only link to a stored file. In: key, lifetime in seconds. Out: a promise of the URL.
   * Touches: nothing.
   */
  async signedUrl(key, expiresInSeconds) {
    const expires = Math.floor(this.now() / 1000) + expiresInSeconds;
    const q = new URLSearchParams({ key, expires: String(expires), signature: this.sign(key, expires) });
    return `${this.baseUrl}?${q.toString()}`;
  }

  /**
   * Serves a file through a signed link, as the storage service would.
   * In: URL. Out: a promise of { body, contentType }; rejects with "signed_url_invalid", "signed_url_expired" or
   * "not_found". Touches: memory (read).
   */
  async getBySignedUrl(url) {
    const q = new URL(url).searchParams;
    const key = q.get('key');
    const expires = Number(q.get('expires'));
    if (!key || !Number.isInteger(expires) || !safeEqual(q.get('signature'), this.sign(key, expires))) {
      throw new Error('signed_url_invalid');
    }
    if (Math.floor(this.now() / 1000) > expires) throw new Error('signed_url_expired');
    const object = this.objects.get(key);
    if (!object) throw new Error('not_found');
    return { ...object };
  }

  /** Removes a file. In: key. Out: a promise. Touches: memory. */
  async delete(key) {
    this.objects.delete(key);
  }
}

/**
 * Export file storage on AWS S3: encrypted at rest (SSE AES256), presigned GET links.
 * In (constructor): { bucket, region, client } (client: an @aws-sdk/client-s3 S3Client; built from region if absent).
 * Why: production counterpart of InMemoryExportStorage, same interface (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
 * Touches: network (AWS S3), the export files in the bucket.
 */
class S3ExportStorage {
  constructor({ bucket, region, client } = {}) {
    /* eslint-disable global-require */
    this.s3 = require('@aws-sdk/client-s3');
    this.presigner = require('@aws-sdk/s3-request-presigner');
    /* eslint-enable global-require */
    this.bucket = bucket;
    this.client = client || new this.s3.S3Client({ region });
  }

  async put(key, body, { contentType } = {}) {
    await this.client.send(new this.s3.PutObjectCommand({
      Bucket: this.bucket, Key: key, Body: body, ServerSideEncryption: 'AES256', ContentType: contentType,
    }));
  }

  async signedUrl(key, expiresInSeconds) {
    return this.presigner.getSignedUrl(this.client, new this.s3.GetObjectCommand({ Bucket: this.bucket, Key: key }),
      { expiresIn: expiresInSeconds });
  }

  async delete(key) {
    await this.client.send(new this.s3.DeleteObjectCommand({ Bucket: this.bucket, Key: key }));
  }
}

/**
 * Builds the compliance service.
 *
 * In (all optional):
 *   now          clock in ms (default Date.now); the grace period and link expiry are measured on it
 *   jwtSecret    secret of the auth system's access tokens (default env JWT_SECRET, else random per process)
 *   storage      export storage (default InMemoryExportStorage; use S3ExportStorage in production)
 *   transporter  nodemailer-style transport (default streamTransport: builds messages, sends nothing)
 *   baseUrl      origin of the links in e-mails (default env BASE_URL or http://localhost:3000)
 *   emailFrom    sender address (default env EMAIL_FROM or no-reply@example.com)
 *   dbFile       SQLite file (default ':memory:')
 *   autoRunJobs  run export jobs as soon as they are queued (default true; tests pass false and call runPendingJobs)
 * Out: { app, db, run, all, get, ready, storage, transporter, runPendingJobs, processDueDeletions, close }.
 *
 * Why: the old module ran its export job against real S3, scheduled deletions with an overflowing setTimeout and
 * trusted identity headers (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
 * Touches: database, storage, e-mail.
 */
function createComplianceService(options = {}) {
  const now = options.now || Date.now;
  const jwtSecret = options.jwtSecret || process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
  const storage = options.storage || new InMemoryExportStorage({ now });
  const transporter = options.transporter
    || nodemailer.createTransport({ streamTransport: true, newline: 'unix', buffer: true });
  const baseUrl = options.baseUrl || process.env.BASE_URL || 'http://localhost:3000';
  const emailFrom = options.emailFrom || process.env.EMAIL_FROM || 'no-reply@example.com';
  const autoRunJobs = options.autoRunJobs !== false;

  const db = new sqlite3.Database(options.dbFile || ':memory:');
  const run = util.promisify(db.run.bind(db));
  const all = util.promisify(db.all.bind(db));
  const get = util.promisify(db.get.bind(db));
  const ready = util.promisify(db.exec.bind(db))(SCHEMA_SQL);

  const iso = (ms) => new Date(ms).toISOString();

  /**
   * Appends an audit row; audit rows are never deleted, not even with the account.
   * In: user id, action, details object. Out: a promise. Why: spec "Audit trail: Every export and deletion request
   * logged" (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: details as JSON, clock-based time). Touches: database.
   */
  function audit(userId, action, details = {}) {
    return run('INSERT INTO audit_log (id, user_id, action, details, created_at) VALUES (?,?,?,?,?)',
      [crypto.randomUUID(), userId, action, JSON.stringify(details), iso(now())]);
  }

  /**
   * Runs statements as one SQLite transaction. In: async fn. Out: fn's result; rolls back if it throws.
   * Why: a cascade delete must not stop half way (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: database.
   */
  async function inTransaction(fn) {
    await run('BEGIN IMMEDIATE');
    try {
      const out = await fn();
      await run('COMMIT');
      return out;
    } catch (err) {
      await run('ROLLBACK');
      throw err;
    }
  }

  /**
   * Everything held about one user, by the spec's categories (file contents are not included, only their list).
   * In: user id. Out: a promise of { profile, sessions, activity, files, preferences, transactions, api_keys,
   * audit_trail }. Why: spec "EXPORT DATA INCLUDES" (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: database.
   */
  async function collectUserData(userId) {
    return {
      profile: await get('SELECT id, email, name, created_at, tier, status FROM users WHERE id = ?', [userId]),
      sessions: await all('SELECT ip, device, created_at FROM sessions WHERE user_id = ? ORDER BY created_at, rowid', [userId]),
      activity: await all('SELECT type, details, created_at FROM activity WHERE user_id = ? ORDER BY created_at, rowid', [userId]),
      files: await all('SELECT filename, size, created_at FROM files WHERE user_id = ? ORDER BY created_at, rowid', [userId]),
      preferences: await get('SELECT notifications, theme, language FROM preferences WHERE user_id = ?', [userId]),
      transactions: await all('SELECT amount, currency, type, created_at FROM transactions WHERE user_id = ? ORDER BY created_at, rowid', [userId]),
      api_keys: await all('SELECT name, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at, rowid', [userId]),
      audit_trail: await all('SELECT action, details, created_at FROM audit_log WHERE user_id = ? ORDER BY created_at, rowid', [userId]),
    };
  }

  /**
   * The background export job: builds the file, stores it, signs a 7-day link, e-mails it, audits it. On any error
   * the request is marked failed and audited (the error text only, nothing personal).
   * In: export id. Out: a promise. Why: spec endpoint 1 "Behind scenes" (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
   * Touches: database, storage, e-mail.
   */
  async function generateExport(exportId) {
    const req = await get('SELECT * FROM export_requests WHERE id = ?', [exportId]);
    if (!req || req.status !== 'pending') return;
    try {
      const data = await collectUserData(req.user_id);
      if (!data.profile) throw new Error('user_not_found');
      const body = req.format === 'json' ? JSON.stringify(data, null, 2) : toCsv(data);
      const key = `exports/${req.user_id}/${exportId}.${req.format}`;
      await storage.put(key, body, { contentType: req.format === 'json' ? 'application/json' : 'text/csv' });
      const fileUrl = await storage.signedUrl(key, DOWNLOAD_TTL_SECONDS);
      const completedMs = now();
      await run(`UPDATE export_requests SET status = 'completed', storage_key = ?, file_url = ?, completed_at = ?,
        expires_at = ? WHERE id = ?`, [key, fileUrl, iso(completedMs), iso(completedMs + DOWNLOAD_TTL_SECONDS * 1000), exportId]);
      await transporter.sendMail({
        from: emailFrom,
        to: data.profile.email,
        subject: 'Your data export is ready',
        text: `Your data export is ready. Download it here (valid for 7 days): ${fileUrl}`,
      });
      await audit(req.user_id, 'data_export_completed', { export_id: exportId, format: req.format });
    } catch (err) {
      await run(`UPDATE export_requests SET status = 'failed' WHERE id = ?`, [exportId]);
      await audit(req.user_id, 'data_export_failed', { export_id: exportId, error: err.message });
    }
  }

  const queue = [];
  let draining = null;

  /**
   * Runs every queued export job, in the order they were queued, and resolves when the queue is empty.
   * Out: a promise. Why: tests and shutdown wait for background work explicitly instead of sleeping (2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP). Touches: as generateExport.
   */
  function runPendingJobs() {
    if (!draining) {
      draining = (async () => {
        while (queue.length) await generateExport(queue.shift());
      })().finally(() => { draining = null; });
    }
    return draining;
  }

  /**
   * Carries out every confirmed deletion whose grace period has ended: deletes the user's export files from storage,
   * then, in one transaction, every row about the user (sessions, activity, files, preferences, transactions, API
   * keys, export requests, the user) except the audit log, and marks the request completed.
   * Out: a promise of the deletion ids completed. Call it on a schedule (start() does, hourly).
   * Why: replaces a 30-day setTimeout that Node fired after 1 ms (32-bit overflow) and that was lost on restart
   * (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: database (deletes personal data), storage.
   */
  async function processDueDeletions() {
    const due = await all(`SELECT * FROM deletion_requests WHERE status = 'approved' AND will_delete_at <= ?
      ORDER BY will_delete_at, rowid`, [iso(now())]);
    const done = [];
    for (const d of due) {
      const exportsToRemove = await all('SELECT storage_key FROM export_requests WHERE user_id = ? AND storage_key IS NOT NULL', [d.user_id]);
      for (const e of exportsToRemove) await storage.delete(e.storage_key);
      const counts = await inTransaction(async () => {
        const c = {};
        for (const table of ['sessions', 'activity', 'files', 'preferences', 'transactions', 'api_keys', 'export_requests']) {
          const before = await get(`SELECT COUNT(*) AS n FROM ${table} WHERE user_id = ?`, [d.user_id]);
          await run(`DELETE FROM ${table} WHERE user_id = ?`, [d.user_id]);
          c[table] = before.n;
        }
        await run('DELETE FROM users WHERE id = ?', [d.user_id]);
        await run(`UPDATE deletion_requests SET status = 'completed', deleted_at = ? WHERE id = ?`, [iso(now()), d.id]);
        await run(`UPDATE deletion_requests SET status = 'cancelled', cancelled_at = ?
          WHERE user_id = ? AND status IN ('pending','approved') AND id != ?`, [iso(now()), d.user_id, d.id]);
        return c;
      });
      await audit(d.user_id, 'account_deleted', { deletion_id: d.id, deleted_items: counts });
      done.push(d.id);
    }
    return done;
  }

  const app = express();
  /**
   * Limits how often one address can call the compliance API, before the token check or any database read runs.
   * In: options.rateLimit (requests per 15 minutes; default COMPLIANCE_RATE_LIMIT or 300). Out: 429 past the limit.
   * Why: code scanning alert js/missing-rate-limiting on PR 19 (the authorization middleware reads the database for
   * every request, so one client could flood it or guess tokens). Same limiter as admin_system. 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only, one counter per address; with more than one server, give
   * it a shared store such as Redis. Behind a proxy set TRUST_PROXY to the number of proxies, as in admin_system.
   */
  const complianceLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: Number(options.rateLimit) || Number(process.env.COMPLIANCE_RATE_LIMIT) || 300,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
  });
  if (process.env.TRUST_PROXY) {
    app.set('trust proxy', Number(process.env.TRUST_PROXY) || process.env.TRUST_PROXY);
  }
  app.use(complianceLimiter);
  app.use(express.json({ limit: '10kb' }));

  /**
   * Express middleware: identifies the caller from the auth system's Bearer access token and loads the user row.
   * Sets req.user = { id, email, tier }. Out: 401 or next().
   * Why: identity was a bare x-user-id header any client could set (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
   * Touches: database (read).
   */
  async function authenticate(req, res, next) {
    try {
      const match = /^Bearer ([A-Za-z0-9_.-]+)$/.exec(req.get('authorization') || '');
      if (!match) return res.status(401).json({ error: 'authentication_required' });
      let payload;
      try {
        payload = jwt.verify(match[1], jwtSecret, { algorithms: ['HS256'] });
      } catch (e) {
        return res.status(401).json({ error: 'invalid_token' });
      }
      const user = payload && payload.user_id != null
        ? await get('SELECT id, email, tier, status FROM users WHERE id = ?', [String(payload.user_id)])
        : null;
      if (!user || user.status !== 'active') return res.status(401).json({ error: 'invalid_token' });
      req.user = { id: user.id, email: user.email, tier: user.tier };
      return next();
    } catch (err) {
      return next(err);
    }
  }

  /**
   * Express middleware: admin-only gate on the tier stored for the caller. Out: 403 admin_only, or next().
   * Why: the gate trusted an `x-admin: true` header (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
   */
  function requireAdmin(req, res, next) {
    if (req.user.tier !== 'admin' && req.user.tier !== 'owner') {
      return res.status(403).json({ error: 'admin_only' });
    }
    return next();
  }

  /**
   * Wraps an async route so a thrown error answers 500 instead of leaving the request hanging.
   * Why: the old routes had no error handling (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
   */
  const route = (fn) => (req, res, next) => Promise.resolve(fn(req, res)).catch(next);

  app.use(authenticate);

  /**
   * POST /compliance/export { format: 'json'|'csv' }: queues an export of the caller's data.
   * Out: { success, export_id, status: 'pending', will_email_at (estimate) }.
   * Why: spec endpoint; rebuilt 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP behind the token gate (see module header). Touches: database, job queue.
   */
  app.post('/compliance/export', route(async (req, res) => {
    const { format } = req.body || {};
    if (!['json', 'csv'].includes(format)) return res.status(400).json({ error: 'invalid_format' });
    const exportId = crypto.randomUUID();
    const requestedMs = now();
    await run(`INSERT INTO export_requests (id, user_id, requested_at, status, format) VALUES (?,?,?,'pending',?)`,
      [exportId, req.user.id, iso(requestedMs), format]);
    await audit(req.user.id, 'data_export_requested', { export_id: exportId, format });
    queue.push(exportId);
    if (autoRunJobs) setImmediate(() => { runPendingJobs(); });
    return res.json({ success: true, export_id: exportId, status: 'pending', will_email_at: iso(requestedMs + 5 * 60 * 1000) });
  }));

  /**
   * GET /compliance/exports/:export_id: status of one of the caller's own exports (404 for anyone else's).
   * Out: { export_id, status, file_url, expires_at, requested_at }.
   * Why: spec endpoint; rebuilt 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP behind the token gate (see module header). Touches: database (read).
   */
  app.get('/compliance/exports/:export_id', route(async (req, res) => {
    const e = await get('SELECT * FROM export_requests WHERE id = ? AND user_id = ?', [req.params.export_id, req.user.id]);
    if (!e) return res.status(404).json({ error: 'export_not_found' });
    return res.json({
      export_id: e.id, status: e.status, file_url: e.file_url, expires_at: e.expires_at, requested_at: e.requested_at,
    });
  }));

  /**
   * POST /compliance/delete { reason }: records a pending deletion and e-mails a confirmation link; the account
   * is deleted 30 days after the request if confirmed. Out: { success, deletion_id, status, will_delete_at }.
   * Why: spec endpoint; rebuilt 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP behind the token gate (see module header). Touches: database, e-mail.
   */
  app.post('/compliance/delete', route(async (req, res) => {
    const { reason } = req.body || {};
    if (!DELETION_REASONS.includes(reason)) return res.status(400).json({ error: 'invalid_reason' });
    const deletionId = crypto.randomUUID();
    const token = crypto.randomBytes(20).toString('hex');
    const requestedMs = now();
    const willDeleteAt = iso(requestedMs + GRACE_PERIOD_MS);
    await run(`INSERT INTO deletion_requests (id, user_id, requested_at, status, reason, confirmation_token_hash,
      will_delete_at) VALUES (?,?,?,'pending',?,?,?)`, [deletionId, req.user.id, iso(requestedMs), reason, sha256(token), willDeleteAt]);
    await audit(req.user.id, 'deletion_requested', { deletion_id: deletionId, reason });
    await transporter.sendMail({
      from: emailFrom,
      to: req.user.email,
      subject: 'Confirm your account deletion',
      text: `Please confirm deletion by visiting: ${baseUrl}/compliance/delete/${deletionId}/confirm?token=${token}\n`
        + `Your account will be deleted on ${willDeleteAt}. Until then you can cancel.`,
    });
    return res.json({ success: true, deletion_id: deletionId, status: 'pending', will_delete_at: willDeleteAt });
  }));

  /**
   * POST /compliance/delete/:id/confirm { confirmation_token }: approves the caller's pending request.
   * Out: { success, deletion_scheduled_for }; 400 wrong token, 409 not pending, 410 past its date.
   * Why: spec endpoint; rebuilt 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP behind the token gate (see module header). Touches: database.
   */
  app.post('/compliance/delete/:deletion_id/confirm', route(async (req, res) => {
    const token = (req.body && req.body.confirmation_token) || '';
    const d = await get('SELECT * FROM deletion_requests WHERE id = ? AND user_id = ?', [req.params.deletion_id, req.user.id]);
    if (!d) return res.status(404).json({ error: 'deletion_not_found' });
    if (d.status !== 'pending') return res.status(409).json({ error: 'deletion_not_pending' });
    if (Date.parse(d.will_delete_at) <= now()) return res.status(410).json({ error: 'deletion_request_expired' });
    if (typeof token !== 'string' || !safeEqual(sha256(token), d.confirmation_token_hash)) {
      return res.status(400).json({ error: 'invalid_confirmation_token' });
    }
    await run(`UPDATE deletion_requests SET status = 'approved', confirmed_at = ? WHERE id = ? AND status = 'pending'`,
      [iso(now()), d.id]);
    await audit(req.user.id, 'deletion_confirmed', { deletion_id: d.id });
    return res.json({ success: true, deletion_scheduled_for: d.will_delete_at });
  }));

  /**
   * DELETE /compliance/delete/:id: cancels the caller's pending or approved request before its date.
   * Out: { success, status: 'cancelled' }; 409 otherwise.
   * Why: spec endpoint; rebuilt 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP behind the token gate (see module header). Touches: database.
   */
  app.delete('/compliance/delete/:deletion_id', route(async (req, res) => {
    const d = await get('SELECT * FROM deletion_requests WHERE id = ? AND user_id = ?', [req.params.deletion_id, req.user.id]);
    if (!d) return res.status(404).json({ error: 'deletion_not_found' });
    if (d.status !== 'pending' && d.status !== 'approved') return res.status(409).json({ error: 'cannot_cancel' });
    if (Date.parse(d.will_delete_at) <= now()) return res.status(409).json({ error: 'grace_period_over' });
    await run(`UPDATE deletion_requests SET status = 'cancelled', cancelled_at = ? WHERE id = ?`, [iso(now()), d.id]);
    await audit(req.user.id, 'deletion_cancelled', { deletion_id: d.id });
    return res.json({ success: true, status: 'cancelled' });
  }));

  /**
   * GET /admin/compliance/exports?user_id&status (admin): every export request, without download links (they
   * would hand the admin every user's data). Out: { exports, total }. The listing itself is audited.
   * Why: spec endpoint; rebuilt 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP behind the token gate (see module header). Touches: database.
   */
  app.get('/admin/compliance/exports', requireAdmin, route(async (req, res) => {
    const conditions = [];
    const params = [];
    if (req.query.user_id) { conditions.push('user_id = ?'); params.push(String(req.query.user_id)); }
    if (req.query.status) { conditions.push('status = ?'); params.push(String(req.query.status)); }
    const where = conditions.length ? ` WHERE ${conditions.join(' AND ')}` : '';
    const rows = await all(`SELECT id AS export_id, user_id, requested_at, status, format, completed_at, expires_at
      FROM export_requests${where} ORDER BY requested_at, rowid`, params);
    await audit(req.user.id, 'admin_listed_exports', { filters: req.query });
    return res.json({ exports: rows, total: rows.length });
  }));

  /**
   * GET /admin/compliance/deletions?status (admin): every deletion request, without token hashes.
   * Out: { deletions, total }. The listing itself is audited.
   * Why: spec endpoint; rebuilt 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP behind the token gate (see module header). Touches: database.
   */
  app.get('/admin/compliance/deletions', requireAdmin, route(async (req, res) => {
    const params = [];
    let where = '';
    if (req.query.status) { where = ' WHERE status = ?'; params.push(String(req.query.status)); }
    const rows = await all(`SELECT id AS deletion_id, user_id, requested_at, status, reason, will_delete_at, confirmed_at,
      cancelled_at, deleted_at FROM deletion_requests${where} ORDER BY requested_at, rowid`, params);
    await audit(req.user.id, 'admin_listed_deletions', { filters: req.query });
    return res.json({ deletions: rows, total: rows.length });
  }));

  app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
    if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'invalid_json' });
    console.error('compliance request failed:', err && err.message);
    return res.status(500).json({ error: 'internal_error' });
  });

  let sweeper = null;
  return {
    app,
    db,
    run,
    all,
    get,
    ready,
    storage,
    transporter,
    runPendingJobs,
    processDueDeletions,
    /**
     * Starts the hourly deletion sweep (timer unref'd). Out: nothing. Why: deletions are due by date, not by timer
     * (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: a timer.
     */
    start() {
      if (!sweeper) {
        sweeper = setInterval(() => {
          processDueDeletions().catch((err) => console.error('deletion sweep failed:', err.message));
        }, 60 * 60 * 1000);
        sweeper.unref();
      }
    },
    /**
     * Stops the sweep, waits for queued exports, closes the database. Out: a promise. Touches: database.
     * Why: clean shutdown and test teardown (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
     */
    async close() {
      if (sweeper) clearInterval(sweeper);
      await runPendingJobs();
      await util.promisify(db.close.bind(db))();
    },
  };
}

// Run as a server: JWT_SECRET=... S3_BUCKET=... node data_export_compliance_javascript.js
if (require.main === module) {
  const service = createComplianceService({
    dbFile: process.env.COMPLIANCE_DB_FILE || 'compliance.sqlite3',
    storage: process.env.S3_BUCKET
      ? new S3ExportStorage({ bucket: process.env.S3_BUCKET, region: process.env.S3_REGION || 'us-east-1' })
      : undefined,
  });
  service.ready.then(() => {
    service.start();
    const port = Number(process.env.PORT) || 3000;
    service.app.listen(port, () => console.log(`Compliance service listening on port ${port}`));
  });
}

module.exports = {
  createComplianceService,
  InMemoryExportStorage,
  S3ExportStorage,
  toCsv,
  csvCell,
  SCHEMA_SQL,
  GRACE_PERIOD_MS,
};

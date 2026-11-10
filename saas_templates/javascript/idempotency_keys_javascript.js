const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

/**
 * Idempotency keys (docs/specs/idempotency_keys.md, IETF draft-ietf-httpapi-idempotency-key-header-07).
 *
 * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Reworked for the amended spec (IDEM-07/08/10/11):
 *   - status 'in_progress' | 'completed' | 'uncertain';
 *   - OperationFailed (a definite failure) frees the key; ANY other error marks it 'uncertain' and a retry gets
 *     409 outcome_unknown without running the operation (the old code deleted the key on every error, so a timeout
 *     after the provider had charged let a retry charge twice);
 *   - only 'completed' records expire; an 'in_progress' record past expires_at is treated as 'uncertain' and a claim
 *     never replaces it;
 *   - release() / resolve() / listUncertain() are operator functions (never client routes); release and resolve are
 *     each ONE conditional write, so of two concurrent calls exactly one returns true;
 *   - time comes from an injectable clock (config.now / the `now` argument), never Date.now() inside a decision.
 * Touches: the store given (memory or SQLite).
 */

/**
 * OperationFailed: thrown by an operation to report a DEFINITE failure (it did nothing: a validation error, a provider
 * decline). handle() then deletes the in_progress record and rethrows, so a retry runs again (IDEM-08).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
class OperationFailed extends Error {
  constructor(message = 'operation failed', options) {
    super(message, options);
    this.name = 'OperationFailed';
  }
}

/** Interface every store implements. All times are epoch milliseconds passed in by the caller. */
class IdempotencyStore {
  /** Insert-if-absent, or replace an expired 'completed' record. Out: { claimed: true } | { claimed: false, record }. */
  async claim(scope, idemKey, fingerprint, now, expiresAt) { throw new Error('Not implemented'); }
  /** in_progress -> completed with the response. */
  async complete(scope, idemKey, status, body) { throw new Error('Not implemented'); }
  /** Deletes the record only while it is in_progress (OperationFailed). */
  async deleteInProgress(scope, idemKey) { throw new Error('Not implemented'); }
  /** in_progress -> uncertain (any error other than OperationFailed). */
  async markUncertain(scope, idemKey) { throw new Error('Not implemented'); }
  /** Deletes an uncertain (or expired in_progress) record. Out: true when this call deleted it. */
  async release(scope, idemKey, now) { throw new Error('Not implemented'); }
  /** uncertain (or expired in_progress) -> completed with the response, expires_at = now + ttl. Out: bool. */
  async resolve(scope, idemKey, status, body, now, expiresAt) { throw new Error('Not implemented'); }
  /** Uncertain records (expired in_progress included), oldest first: [{scope, idem_key, created_at}]. */
  async listUncertain(limit, now) { throw new Error('Not implemented'); }
  /** Deletes 'completed' records whose expires_at has passed; never in_progress or uncertain ones. */
  async purgeExpired(now) { throw new Error('Not implemented'); }
}

/**
 * True when a record counts as 'uncertain' at time now: stored as uncertain, or in_progress past expires_at (a
 * killed process). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function isUncertain(record, now) {
  return record.status === 'uncertain' || (record.status === 'in_progress' && record.expires_at <= now);
}

/**
 * In-memory store. Every method runs to completion without awaiting in between, so each one is atomic on Node's
 * single thread (the claim is insert-if-absent; release/resolve are one conditional write).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
 */
class InMemoryStore extends IdempotencyStore {
  constructor() {
    super();
    this.records = new Map();
    this._seq = 0;
  }

  _key(scope, idemKey) {
    return JSON.stringify([String(scope), String(idemKey)]);
  }

  async claim(scope, idemKey, fingerprint, now, expiresAt) {
    const key = this._key(scope, idemKey);
    const existing = this.records.get(key);
    if (existing && !(existing.status === 'completed' && existing.expires_at <= now)) {
      return { claimed: false, record: { ...existing } };
    }
    if (existing) this.records.delete(key); // an expired completed record counts as absent
    this.records.set(key, {
      scope, idem_key: idemKey, request_fingerprint: fingerprint, status: 'in_progress',
      response_status: null, response_body: null, created_at: now, expires_at: expiresAt, seq: this._seq++
    });
    return { claimed: true };
  }

  async get(scope, idemKey) {
    const record = this.records.get(this._key(scope, idemKey));
    return record ? { ...record } : null;
  }

  async complete(scope, idemKey, status, body) {
    const record = this.records.get(this._key(scope, idemKey));
    if (record && record.status === 'in_progress') {
      record.status = 'completed';
      record.response_status = status;
      record.response_body = body;
    }
  }

  async deleteInProgress(scope, idemKey) {
    const key = this._key(scope, idemKey);
    const record = this.records.get(key);
    if (record && record.status === 'in_progress') this.records.delete(key);
  }

  async markUncertain(scope, idemKey) {
    const record = this.records.get(this._key(scope, idemKey));
    if (record && record.status === 'in_progress') record.status = 'uncertain';
  }

  async release(scope, idemKey, now) {
    const key = this._key(scope, idemKey);
    const record = this.records.get(key);
    if (!record || !isUncertain(record, now)) return false;
    this.records.delete(key);
    return true;
  }

  async resolve(scope, idemKey, status, body, now, expiresAt) {
    const record = this.records.get(this._key(scope, idemKey));
    if (!record || !isUncertain(record, now)) return false;
    record.status = 'completed';
    record.response_status = status;
    record.response_body = body;
    record.expires_at = expiresAt;
    return true;
  }

  async listUncertain(limit, now) {
    return Array.from(this.records.values())
      .filter(r => isUncertain(r, now))
      .sort((a, b) => (a.created_at - b.created_at) || (a.seq - b.seq))
      .slice(0, limit)
      .map(r => ({ scope: r.scope, idem_key: r.idem_key, created_at: r.created_at }));
  }

  async purgeExpired(now) {
    for (const [key, record] of this.records.entries()) {
      if (record.status === 'completed' && record.expires_at <= now) this.records.delete(key);
    }
  }
}

/**
 * SQLite store (node:sqlite) following the spec's schema. Every statement is parameterized; the claim is one
 * INSERT ... ON CONFLICT DO UPDATE that only replaces an expired 'completed' row; release/resolve are one
 * conditional DELETE/UPDATE each. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the SQLite database.
 */
class SqliteStore extends IdempotencyStore {
  constructor(dbPath = ':memory:') {
    super();
    this.db = new DatabaseSync(dbPath);
    this._init();
  }

  _init() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS idempotency_records (
        scope TEXT NOT NULL,
        idem_key TEXT NOT NULL,
        request_fingerprint TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('in_progress', 'completed', 'uncertain')),
        response_status INTEGER,
        response_body TEXT,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        PRIMARY KEY (scope, idem_key)
      )
    `);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_expires_at ON idempotency_records(expires_at)`);
  }

  async claim(scope, idemKey, fingerprint, now, expiresAt) {
    const result = this.db.prepare(`
      INSERT INTO idempotency_records (scope, idem_key, request_fingerprint, status, response_status, response_body, created_at, expires_at)
      VALUES (?, ?, ?, 'in_progress', NULL, NULL, ?, ?)
      ON CONFLICT(scope, idem_key) DO UPDATE SET
        request_fingerprint = excluded.request_fingerprint,
        status = 'in_progress',
        response_status = NULL,
        response_body = NULL,
        created_at = excluded.created_at,
        expires_at = excluded.expires_at
      WHERE idempotency_records.status = 'completed' AND idempotency_records.expires_at <= ?
    `).run(scope, idemKey, fingerprint, now, expiresAt, now);
    if (result.changes > 0) return { claimed: true };
    return { claimed: false, record: await this.get(scope, idemKey) };
  }

  async get(scope, idemKey) {
    const row = this.db.prepare('SELECT * FROM idempotency_records WHERE scope = ? AND idem_key = ?').get(scope, idemKey);
    return row ? { ...row } : null;
  }

  async complete(scope, idemKey, status, body) {
    this.db.prepare(`UPDATE idempotency_records SET status = 'completed', response_status = ?, response_body = ?
      WHERE scope = ? AND idem_key = ? AND status = 'in_progress'`).run(status, body, scope, idemKey);
  }

  async deleteInProgress(scope, idemKey) {
    this.db.prepare(`DELETE FROM idempotency_records WHERE scope = ? AND idem_key = ? AND status = 'in_progress'`)
      .run(scope, idemKey);
  }

  async markUncertain(scope, idemKey) {
    this.db.prepare(`UPDATE idempotency_records SET status = 'uncertain'
      WHERE scope = ? AND idem_key = ? AND status = 'in_progress'`).run(scope, idemKey);
  }

  async release(scope, idemKey, now) {
    const r = this.db.prepare(`DELETE FROM idempotency_records WHERE scope = ? AND idem_key = ?
      AND (status = 'uncertain' OR (status = 'in_progress' AND expires_at <= ?))`).run(scope, idemKey, now);
    return r.changes === 1;
  }

  async resolve(scope, idemKey, status, body, now, expiresAt) {
    const r = this.db.prepare(`UPDATE idempotency_records
      SET status = 'completed', response_status = ?, response_body = ?, expires_at = ?
      WHERE scope = ? AND idem_key = ?
        AND (status = 'uncertain' OR (status = 'in_progress' AND expires_at <= ?))`)
      .run(status, body, expiresAt, scope, idemKey, now);
    return r.changes === 1;
  }

  async listUncertain(limit, now) {
    return this.db.prepare(`SELECT scope, idem_key, created_at FROM idempotency_records
      WHERE status = 'uncertain' OR (status = 'in_progress' AND expires_at <= ?)
      ORDER BY created_at ASC, rowid ASC LIMIT ?`).all(now, limit).map(r => ({ ...r }));
  }

  async purgeExpired(now) {
    this.db.prepare(`DELETE FROM idempotency_records WHERE status = 'completed' AND expires_at <= ?`).run(now);
  }

  close() {
    this.db.close();
  }
}

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_IDEMPOTENT_METHODS = new Set(['POST', 'PATCH']);

function computeFingerprint(method, path, body) {
  const bodyStr = body === undefined || body === null ? '' : JSON.stringify(body);
  const input = `${method} ${path}\n${bodyStr}`;
  return crypto.createHash('sha256').update(input).digest('hex');
}

/**
 * problemResponse(status, title, detail, type?) -> { status, content_type: 'application/problem+json', body }.
 * Body is RFC 7807 {type, title, detail} (IDEM-09). type defaults to a URL built from the title.
 * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] optional explicit type (outcome_unknown). Touches nothing.
 */
function problemResponse(status, title, detail, type) {
  return {
    status,
    content_type: 'application/problem+json',
    body: JSON.stringify({ type: type || `https://developer.example.com/idempotency#${title.toLowerCase().replace(/\s+/g, '-')}`, title, detail })
  };
}

const OUTCOME_UNKNOWN_TYPE = 'https://developer.example.com/problems/outcome_unknown';

/** 409 outcome_unknown problem (IDEM-07, IDEM-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function outcomeUnknown() {
  return problemResponse(409, 'Outcome unknown',
    'The first request with this Idempotency-Key ended without a known outcome; it will not be run again until it is reconciled.',
    OUTCOME_UNKNOWN_TYPE);
}

function isRequired(method, path, config = {}) {
  const methods = config.idempotentMethods || DEFAULT_IDEMPOTENT_METHODS;
  return methods.has(method.toUpperCase());
}

/** The clock in config (ms since epoch), Date.now by default. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function clockOf(config) {
  return typeof config.now === 'function' ? config.now : () => Date.now();
}

/** Serializes an operation's response body. */
function bodyText(body) {
  return typeof body === 'string' ? body : JSON.stringify(body);
}

/**
 * handle(scope, idempotencyKey, method, path, body, operation, config) -> { status, content_type, body }.
 * In: scope = the authenticated client id (never request input); operation() -> {status, body}; config { store,
 * ttlMs (24 h), now (clock, ms), idempotentMethods }. Check order (spec): missing key on a required method -> 400;
 * different fingerprint -> 422 (even while in progress or uncertain); in progress -> 409; uncertain (or in_progress
 * past expires_at) -> 409 outcome_unknown, the operation does not run; completed -> the stored response. A claimed
 * key runs the operation once: success completes it; OperationFailed deletes it and rethrows (IDEM-08); any other
 * error marks it 'uncertain' and rethrows (IDEM-10).
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the store and whatever the operation touches.
 */
async function handle(scope, idempotencyKey, method, path, body, operation, config = {}) {
  const ttl = config.ttlMs || DEFAULT_TTL_MS;
  const store = config.store;
  const now = clockOf(config)();

  if (!idempotencyKey) {
    if (isRequired(method, path, config)) {
      return problemResponse(400, 'Missing Idempotency Key', 'The Idempotency-Key header is required for this operation');
    }
    const result = await operation();
    return { status: result.status, content_type: 'application/json', body: bodyText(result.body) };
  }

  const fingerprint = computeFingerprint(method, path, body);
  const claim = await store.claim(scope, idempotencyKey, fingerprint, now, now + ttl);

  if (!claim.claimed) {
    const record = claim.record;
    if (!record) {
      // The row vanished between the claim and the read (released concurrently): ask the client to retry.
      return problemResponse(409, 'Conflict', 'Request with this idempotency key is already in progress');
    }
    if (record.request_fingerprint !== fingerprint) {
      return problemResponse(422, 'Unprocessable Content', 'Idempotency key reused with different request payload');
    }
    if (isUncertain(record, now)) return outcomeUnknown();
    if (record.status === 'in_progress') {
      return problemResponse(409, 'Conflict', 'Request with this idempotency key is already in progress');
    }
    return { status: record.response_status, content_type: 'application/json', body: record.response_body };
  }

  let result;
  try {
    result = await operation();
  } catch (error) {
    if (error instanceof OperationFailed) {
      await store.deleteInProgress(scope, idempotencyKey);
    } else {
      await store.markUncertain(scope, idempotencyKey);
    }
    throw error;
  }
  const responseBody = bodyText(result.body);
  await store.complete(scope, idempotencyKey, result.status, responseBody);
  return { status: result.status, content_type: 'application/json', body: responseBody };
}

/**
 * release(scope, idempotencyKey, config) -> bool. OPERATOR / reconciliation only, never a client route; scope is the
 * stored record's scope (e.g. from listUncertain), never request input. Frees an 'uncertain' key (or an in_progress
 * one past expires_at) so a retry runs the operation; false and no change otherwise. One conditional write.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-10). Touches the store.
 */
async function release(scope, idempotencyKey, config = {}) {
  return config.store.release(scope, idempotencyKey, clockOf(config)());
}

/**
 * resolve(scope, idempotencyKey, status, body, config) -> bool. OPERATOR only. Stores the reconciled outcome of an
 * 'uncertain' key as 'completed' with expires_at = now + 24 h (config.ttlMs), so a retry gets that response without
 * running the operation; false and no change for a key that is not uncertain. One conditional write.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-11). Touches the store.
 */
async function resolve(scope, idempotencyKey, status, body, config = {}) {
  const now = clockOf(config)();
  return config.store.resolve(scope, idempotencyKey, status, bodyText(body), now, now + (config.ttlMs || DEFAULT_TTL_MS));
}

/**
 * listUncertain(limit, config) -> [{scope, idem_key, created_at}], oldest first: the reconciliation work list.
 * OPERATOR only. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the store (read).
 */
async function listUncertain(limit, config = {}) {
  return config.store.listUncertain(limit, clockOf(config)());
}

/**
 * purgeExpired(config): deletes expired 'completed' records only; in_progress and uncertain ones are kept.
 * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] clock injected. Touches the store.
 */
async function purgeExpired(config = {}) {
  await config.store.purgeExpired(clockOf(config)());
}

module.exports = {
  IdempotencyStore,
  InMemoryStore,
  SqliteStore,
  OperationFailed,
  computeFingerprint,
  isRequired,
  handle,
  release,
  resolve,
  listUncertain,
  purgeExpired,
  problemResponse,
  DEFAULT_TTL_MS,
  DEFAULT_IDEMPOTENT_METHODS
};

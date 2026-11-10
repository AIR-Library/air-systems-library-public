'use strict';
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

/**
 * Passwordless email code sign-in (docs/specs/passwordless_email_code_signin.md): sign in, and sign up, with a
 * 6-digit code sent by email. One code per address at a time, valid 10 minutes, usable once, 5 tries; limits per
 * address, per IP and per clock hour/day; the same answers whether or not the address has an account. The code,
 * the address and the IP are stored only as HMAC-SHA256 under the server's secret.
 *
 * Why: Phase D wave 1, owner request 2026-11-10 (EMAILCODE-01..EMAILCODE-14).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the database given (SQLite, the spec's SCHEMA, parameterized single statements for BUMP and verify's
 * steps 4 and 6); email through the injected sender (network in production, a fake in tests). No files or money.
 * Never logs the code, the address or the secret.
 */

const CODE_TTL = 600;
const CODE_ATTEMPTS = 5;
const START_PER_EMAIL_HOUR = 5;
const START_PER_EMAIL_DAY = 10;
const START_PER_IP_HOUR = 20;
const VERIFY_PER_IP_HOUR = 30;
const VERIFY_PER_EMAIL_HOUR = 10;
const ZEROS64 = Buffer.from('0'.repeat(64), 'utf8');
const EMAIL_RE = /^[a-z0-9][a-z0-9._%+=-]*@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/;

/**
 * EmailCodeError: thrown only at construction ("not_configured") so no service exists without a secret and a
 * sender. In: code. Out: Error with `.code`. Why: EMAILCODE-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches nothing.
 */
class EmailCodeError extends Error {
  /**
   * In: the error code. Out: the error, with `.code` set and the code as its only message (no secret).
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1). Touches nothing.
   */
  constructor(code) {
    super(code);
    this.name = 'EmailCodeError';
    this.code = code;
  }
}

/**
 * normalize_email(raw): trims only space, tab, CR, LF; lower-cases only A-Z; 3 to 254 characters matching the
 * spec's pattern in whole. In: anything. Out: the address, or null. Why: EMAILCODE-11.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function normalizeEmail(raw) {
  if (typeof raw !== 'string') return null;
  const e = raw.replace(/^[ \t\r\n]+/, '').replace(/[ \t\r\n]+$/, '').replace(/[A-Z]/g, c => c.toLowerCase());
  if (e.length < 3 || e.length > 254 || !EMAIL_RE.test(e)) return null;
  return e;
}

/**
 * CODE: random_bytes(4) as an unsigned big-endian 32-bit number, drawn again while >= 4294000000, then mod 10^6
 * with 6 digits. In: randomBytes(n). Out: 6-digit string. Why: EMAILCODE-14.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing (calls randomBytes).
 */
function generateCode(randomBytes = n => crypto.randomBytes(n)) {
  for (;;) {
    const n = Buffer.from(randomBytes(4)).readUInt32BE(0);
    if (n >= 4294000000) continue;
    return String(n % 1000000).padStart(6, '0');
  }
}

/* ------------------------------------------------------------------ store */

/**
 * SQLite store (node:sqlite) on the spec's SCHEMA. In: a DatabaseSync (default a new in-memory one).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
 */
class SqliteEmailCodeStore {
  /**
   * Creates the spec's SCHEMA tables when absent. In: a DatabaseSync (default a new in-memory one). Out: the store.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1). Touches the database.
   */
  constructor(db = new DatabaseSync(':memory:')) {
    this.db = db;
    db.exec(`
      CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, email_verified_at INTEGER NULL,
        status TEXT NOT NULL DEFAULT 'active', created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS email_codes (
        email_hash TEXT PRIMARY KEY, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS rate_windows (
        key TEXT NOT NULL, window_start INTEGER NOT NULL, count INTEGER NOT NULL, PRIMARY KEY (key, window_start));`);
  }

  /**
   * BUMP: inserts (key, window_start, 1) or adds 1, in ONE statement. Out: the count after it.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  bump(key, windowStart) {
    return this.db.prepare(
      `INSERT INTO rate_windows (key, window_start, count) VALUES (?, ?, 1)
       ON CONFLICT (key, window_start) DO UPDATE SET count = rate_windows.count + 1 RETURNING count`)
      .get(key, windowStart).count;
  }

  /** Writes the code row, replacing an earlier one. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  putCode(emailHash, codeHash, expiresAt, now) {
    this.db.prepare(
      `INSERT INTO email_codes (email_hash, code_hash, expires_at, attempts, created_at) VALUES (?, ?, ?, 0, ?)
       ON CONFLICT (email_hash) DO UPDATE SET code_hash = excluded.code_hash, expires_at = excluded.expires_at,
         attempts = 0, created_at = excluded.created_at`).run(emailHash, codeHash, expiresAt, now);
  }

  /**
   * Removes the row only while it still holds this code. Out: rows deleted.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  deleteCode(emailHash, codeHash) {
    return this.db.prepare('DELETE FROM email_codes WHERE email_hash = ? AND code_hash = ?').run(emailHash, codeHash).changes;
  }

  /**
   * verify step 4: counts the try in ONE conditional write. Out: {code_hash, attempts} or null when no row changed.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  countTry(emailHash, now) {
    return this.db.prepare(
      `UPDATE email_codes SET attempts = attempts + 1 WHERE email_hash = ? AND attempts < ? AND expires_at > ?
       RETURNING code_hash, attempts`).get(emailHash, CODE_ATTEMPTS, now) || null;
  }

  /** Deletes the address's row when expired or used up. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  deleteDeadCode(emailHash, now) {
    this.db.prepare('DELETE FROM email_codes WHERE email_hash = ? AND (expires_at <= ? OR attempts >= ?)').run(emailHash, now, CODE_ATTEMPTS);
  }

  /** The code row or null. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  getCode(emailHash) {
    return this.db.prepare('SELECT * FROM email_codes WHERE email_hash = ?').get(emailHash) || null;
  }

  /**
   * Inserts a verified account unless the email exists. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches the database.
   */
  insertAccountIfAbsent(id, email, now) {
    this.db.prepare(
      `INSERT INTO accounts (id, email, email_verified_at, status, created_at) VALUES (?, ?, ?, 'active', ?)
       ON CONFLICT (email) DO NOTHING`).run(id, email, now, now);
  }

  /** The account row by email, or null. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  findAccountByEmail(email) {
    return this.db.prepare('SELECT * FROM accounts WHERE email = ?').get(email) || null;
  }

  /** Sets email_verified_at while it is null. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  markVerified(id, now) {
    this.db.prepare('UPDATE accounts SET email_verified_at = ? WHERE id = ? AND email_verified_at IS NULL').run(now, id);
  }
}

/* ------------------------------------------------------------------ service */

/**
 * EmailCodeSignin: start and verify. Build it with createEmailCodeSignin().
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the store and the sender.
 */
class EmailCodeSignin {
  /**
   * In: {store, secret (>= 32 bytes), sender: {sendCode(to, code, expiresIn) -> bool | Promise<bool>},
   * revokeUnproven(account_id), clock() -> seconds, randomBytes(n), generateCode()}. Throws
   * EmailCodeError("not_configured") without a 32-byte secret or a sender (EMAILCODE-12).
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
   */
  constructor({ store, secret, sender, revokeUnproven, clock, randomBytes, generateCode: gen } = {}) {
    const key = typeof secret === 'string' ? Buffer.from(secret, 'utf8') : (secret ? Buffer.from(secret) : null);
    if (!key || key.length < 32 || !sender || typeof sender.sendCode !== 'function') throw new EmailCodeError('not_configured');
    Object.defineProperty(this, '_secret', { value: key, enumerable: false });
    this.store = store || new SqliteEmailCodeStore();
    this.sender = sender;
    this.revokeUnproven = revokeUnproven || (() => {});
    this.clock = clock || (() => Math.floor(Date.now() / 1000));
    this.randomBytes = randomBytes || (n => crypto.randomBytes(n));
    this.generateCode = gen || (() => generateCode(this.randomBytes));
  }

  /** hmac_hex(text). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
  hmacHex(text) {
    return crypto.createHmac('sha256', this._secret).update(text, 'utf8').digest('hex');
  }

  /** email_hash(email). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
  emailHash(email) {
    return this.hmacHex('email:' + email);
  }

  /** code_hash(email, code). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
  codeHash(email, code) {
    return this.hmacHex('code:' + this.emailHash(email) + ':' + code);
  }

  /** ip_hash(ip): the first 32 hex characters. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
  ipHash(ip) {
    return this.hmacHex('ip:' + (typeof ip === 'string' && ip.length > 0 ? ip : 'unknown')).slice(0, 32);
  }

  /** BUMP(key, span) at the clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  bump(key, span, now) {
    return this.store.bump(key, now - (now % span));
  }

  /**
   * start(email, ip) -> {status: 202, sent: true, expires_in: 600} or a refusal (422 invalid_email,
   * 429 too_many_requests, 503 send_failed). Never reads accounts. Why: EMAILCODE-01, EMAILCODE-07..09, EMAILCODE-12.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database and the sender.
   */
  async start(email, ip) {
    const e = normalizeEmail(email);
    if (e === null) return { error: 'invalid_email', status: 422 };
    const now = this.clock();
    if (this.bump('start-ip#' + this.ipHash(ip), 3600, now) > START_PER_IP_HOUR) return { error: 'too_many_requests', status: 429 };
    const ek = this.emailHash(e).slice(0, 32);
    const h = this.bump('start-email#' + ek, 3600, now);
    const d = this.bump('start-email-day#' + ek, 86400, now);
    if (h > START_PER_EMAIL_HOUR || d > START_PER_EMAIL_DAY) return { error: 'too_many_requests', status: 429 };
    const code = this.generateCode();
    const eh = this.emailHash(e);
    const ch = this.codeHash(e, code);
    this.store.putCode(eh, ch, now + CODE_TTL, now);
    let sent;
    try {
      sent = await this.sender.sendCode(e, code, CODE_TTL);
    } catch (err) {
      sent = false;
    }
    if (sent !== true) {
      this.store.deleteCode(eh, ch);
      return { error: 'send_failed', status: 503 };
    }
    return { status: 202, sent: true, expires_in: CODE_TTL };
  }

  /**
   * verify(email, code, ip) -> {status: 200, account_id, email, new_account} or a refusal (429, 400 invalid_code,
   * 403 account_unavailable, 500 processing_failed), in the spec's order: the try is counted before the compare,
   * and the code is used up by one conditional DELETE. Why: EMAILCODE-01, EMAILCODE-03..07, EMAILCODE-10, 11, 13, 14.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database and revoke_unproven.
   */
  async verify(email, code, ip) {
    const invalid = { error: 'invalid_code', status: 400 };
    const now = this.clock();
    if (this.bump('verify-ip#' + this.ipHash(ip), 3600, now) > VERIFY_PER_IP_HOUR) return { error: 'too_many_requests', status: 429 };
    const e = normalizeEmail(email);
    const c = typeof code === 'string' ? code.replace(/[ -]/g, '') : '';
    if (e === null || !/^[0-9]{6}$/.test(c)) return invalid;
    const eh = this.emailHash(e);
    if (this.bump('verify-email#' + eh.slice(0, 32), 3600, now) > VERIFY_PER_EMAIL_HOUR) return { error: 'too_many_requests', status: 429 };
    const given = Buffer.from(this.codeHash(e, c), 'utf8');
    const row = this.store.countTry(eh, now);
    if (!row) {
      this.store.deleteDeadCode(eh, now);
      crypto.timingSafeEqual(given, ZEROS64);
      return invalid;
    }
    if (!crypto.timingSafeEqual(given, Buffer.from(row.code_hash, 'utf8'))) {
      if (row.attempts >= CODE_ATTEMPTS) this.store.deleteCode(eh, row.code_hash);
      return invalid;
    }
    if (this.store.deleteCode(eh, row.code_hash) !== 1) return invalid;
    const id = Buffer.from(this.randomBytes(16)).subarray(0, 16).toString('hex');
    this.store.insertAccountIfAbsent(id, e, now);
    const account = this.store.findAccountByEmail(e);
    const newAccount = account.id === id;
    if (account.email_verified_at === null) {
      try {
        await this.revokeUnproven(account.id);
      } catch (err) {
        return { error: 'processing_failed', status: 500 };
      }
      this.store.markVerified(account.id, now);
    }
    if (account.status !== 'active') return { error: 'account_unavailable', status: 403 };
    return { status: 200, account_id: account.id, email: e, new_account: newAccount };
  }
}

/**
 * createEmailCodeSignin(config): see EmailCodeSignin. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches memory only.
 */
function createEmailCodeSignin(config) {
  return new EmailCodeSignin(config);
}

module.exports = {
  normalizeEmail, generateCode, createEmailCodeSignin, EmailCodeSignin, SqliteEmailCodeStore, EmailCodeError
};

'use strict';
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

/**
 * TOTP two-factor (docs/specs/totp_two_factor.md): enroll an authenticator app, verify 6-digit codes with one step
 * of drift each way, never accept a code twice, lock after repeated wrong codes, a hard lock after 100 failures in a
 * row, and one-time recovery codes. Implements RFC 4226 (HOTP), RFC 6238 (TOTP), RFC 4648 (base32) and AES-256-GCM
 * sealing of the secret at rest.
 *
 * Why: Phase D wave 1, owner request 2026-11-10 (TOTP-01..TOTP-14).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the database given (the SQLite store follows the spec's SCHEMA; every statement is parameterized).
 * No network, files or money. Never logs or returns a secret, code, recovery code or key outside the answers the
 * spec names.
 */

const STEP = 30;
const DIGITS = 6;
const LOCK_FAILURES = 5;
const LOCK_SECONDS = 900;
const HARD_LOCK_FAILURES = 100;
const RECOVERY_CODES = 8;
const RECOVERY_ALPHABET = '23456789abcdefghjkmnpqrstvwxyz';
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * TotpError: thrown only at construction for a key of the wrong size (code "invalid_key"), so no service exists.
 * In: code. Out: Error with `.code`. Why: TOTP-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
class TotpError extends Error {
  /**
   * In: the error code. Out: the error, with `.code` set and the code as its only message (no secret).
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1). Touches nothing.
   */
  constructor(code) {
    super(code);
    this.name = 'TotpError';
    this.code = code;
  }
}

/* ------------------------------------------------------------------ pure functions */

/**
 * base32_encode(bytes): RFC 4648 alphabet, upper case, no "=" padding. In: Buffer | Uint8Array. Out: string.
 * Why: TOTP-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function base32Encode(bytes) {
  let out = '';
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/**
 * base32_decode(text): removes ASCII spaces, "-" and "=", upper-cases a-z, checks every character and the length
 * (1, 3 or 6 modulo 8, or nothing left, is invalid), then decodes 5 bits per character, dropping leftover bits.
 * In: string. Out: Buffer, or {error: "invalid_base32"}. Why: TOTP-02.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function base32Decode(text) {
  if (typeof text !== 'string') return { error: 'invalid_base32' };
  let clean = '';
  for (const ch of text) {
    if (ch === ' ' || ch === '-' || ch === '=') continue;
    const up = ch >= 'a' && ch <= 'z' ? ch.toUpperCase() : ch;
    if (!BASE32_ALPHABET.includes(up) || up.length !== 1) return { error: 'invalid_base32' };
    clean += up;
  }
  const rem = clean.length % 8;
  if (clean.length === 0 || rem === 1 || rem === 3 || rem === 6) return { error: 'invalid_base32' };
  const out = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    value = (value << 5) | BASE32_ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
    value &= (1 << bits) - 1;
  }
  return Buffer.from(out);
}

/**
 * hotp(key_bytes, counter, digits): RFC 4226 with an 8-byte big-endian counter (64-bit, never cut to 32 bits).
 * In: key Buffer, counter (number or bigint >= 0), digits (default 6). Out: zero-padded string. Why: TOTP-01.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function hotp(keyBytes, counter, digits = DIGITS) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = crypto.createHmac('sha1', keyBytes).update(msg).digest();
  const o = mac[19] & 0x0f;
  const v = ((mac[o] & 0x7f) * 0x1000000) + (mac[o + 1] << 16) + (mac[o + 2] << 8) + mac[o + 3];
  return String(v % (10 ** digits)).padStart(digits, '0');
}

/**
 * totp_at(secret_base32, unix_time, digits) = hotp(base32_decode(secret), floor(unix_time / 30), digits).
 * In: base32 secret, whole seconds, digits. Out: string, or {error: "invalid_base32"}. Why: TOTP-01.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function totpAt(secretBase32, unixTime, digits = DIGITS) {
  const key = base32Decode(secretBase32);
  if (!Buffer.isBuffer(key)) return key;
  return hotp(key, Math.floor(unixTime / STEP), digits);
}

/**
 * pct(s): every UTF-8 byte not in [A-Za-z0-9._~-] becomes "%" + two upper-case hex digits. In: string. Out: string.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function pct(s) {
  let out = '';
  for (const b of Buffer.from(s, 'utf8')) {
    const c = String.fromCharCode(b);
    if (/^[A-Za-z0-9._~-]$/.test(c)) out += c;
    else out += '%' + b.toString(16).toUpperCase().padStart(2, '0');
  }
  return out;
}

/**
 * otpauth_uri(secret, issuer, account_label): the Key URI an authenticator app reads. In: strings. Out: string.
 * Why: TOTP-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function otpauthUri(secret, issuer, accountLabel) {
  return 'otpauth://totp/' + pct(issuer + ':' + accountLabel) + '?secret=' + secret + '&issuer=' + pct(issuer) +
    '&algorithm=SHA1&digits=6&period=30';
}

/**
 * seal(key32, nonce12, plaintext, aad) -> "v1." + base64(nonce + ciphertext + tag), AES-256-GCM, 16-byte tag.
 * In: 32-byte key, 12-byte nonce, plaintext string, aad string. Out: string. Why: TOTP-11.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function seal(key32, nonce12, plaintext, aad) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key32, nonce12, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  return 'v1.' + Buffer.concat([Buffer.from(nonce12), ct, cipher.getAuthTag()]).toString('base64');
}

/**
 * Strict RFC 4648 section 4 base64 decode: the text must be the canonical encoding of its bytes.
 * In: string. Out: Buffer | null. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function strictBase64(text) {
  if (text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) return null;
  const buf = Buffer.from(text, 'base64');
  return buf.toString('base64') === text ? buf : null;
}

/**
 * open(key32, sealed, aad) -> the plaintext, or null for a missing "v1." prefix, bad base64, fewer than 28 bytes,
 * or a tag that does not verify. In: key, sealed string, aad string. Out: string | null. Why: TOTP-10, TOTP-11.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function open(key32, sealed, aad) {
  try {
    if (typeof sealed !== 'string' || !sealed.startsWith('v1.')) return null;
    const raw = strictBase64(sealed.slice(3));
    if (!raw || raw.length < 28) return null;
    const decipher = crypto.createDecipheriv('aes-256-gcm', key32, raw.subarray(0, 12), { authTagLength: 16 });
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(raw.subarray(raw.length - 16));
    const pt = Buffer.concat([decipher.update(raw.subarray(12, raw.length - 16)), decipher.final()]);
    return pt.toString('utf8');
  } catch (err) {
    return null;
  }
}

/**
 * TOTP INPUT: the code without ASCII spaces and "-" is exactly 6 characters 0-9. A code over 64 characters is not.
 * In: anything. Out: the 6 digits, or null. Why: TOTP-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function totpInput(code) {
  if (typeof code !== 'string' || code.length > 64) return null;
  const s = code.replace(/[ -]/g, '');
  return /^[0-9]{6}$/.test(s) ? s : null;
}

/**
 * RECOVERY INPUT: A-Z mapped to a-z, ASCII spaces and "-" removed; exactly 12 characters of the RECOVERY
 * ALPHABET. A code over 64 characters is not. In: anything. Out: the normal form, or null. Why: TOTP-08.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function recoveryInput(code) {
  if (typeof code !== 'string' || code.length > 64) return null;
  const s = code.replace(/[A-Z]/g, c => c.toLowerCase()).replace(/[ -]/g, '');
  if (s.length !== 12) return null;
  for (const ch of s) if (!RECOVERY_ALPHABET.includes(ch)) return null;
  return s;
}

/**
 * code_hash = lower-case hex HMAC-SHA256(recovery_hash_key, "recovery:" + user_id + ":" + RECOVERY INPUT form).
 * In: key, user id, the code (any accepted spelling). Out: hex string, or null when the code is not a RECOVERY
 * INPUT. Why: TOTP-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function recoveryCodeHash(recoveryHashKey, userId, code) {
  const form = recoveryInput(code);
  if (form === null) return null;
  return crypto.createHmac('sha256', recoveryHashKey).update('recovery:' + userId + ':' + form, 'utf8').digest('hex');
}

/* ------------------------------------------------------------------ store */

/**
 * SQLite store (node:sqlite) on the spec's SCHEMA. Each method is one parameterized statement, so the TRY insert,
 * CLAIM and the recovery-code use are each one atomic conditional write. In: a DatabaseSync (default a new
 * in-memory one). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
 */
class SqliteTotpStore {
  /**
   * Creates the spec's SCHEMA tables when absent. In: a DatabaseSync (default a new in-memory one). Out: the store.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1). Touches the database.
   */
  constructor(db = new DatabaseSync(':memory:')) {
    this.db = db;
    db.exec(`
      CREATE TABLE IF NOT EXISTS totp_enrollments (
        user_id TEXT PRIMARY KEY, secret_enc TEXT NOT NULL, confirmed_at INTEGER NULL,
        last_used_step INTEGER NOT NULL DEFAULT 0, failed_since_success INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS totp_recovery_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, code_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL, used_at INTEGER NULL, UNIQUE (user_id, code_hash));
      CREATE TABLE IF NOT EXISTS totp_failures (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, at INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS totp_failures_user_at ON totp_failures (user_id, at);`);
  }

  /** The user's enrollment row or null. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  getEnrollment(userId) {
    return this.db.prepare('SELECT * FROM totp_enrollments WHERE user_id = ?').get(userId) || null;
  }

  /**
   * Writes a fresh unconfirmed row, replacing an unconfirmed one (never a confirmed one). Out: true when written.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  putUnconfirmed(userId, secretEnc, now) {
    const r = this.db.prepare(
      `INSERT INTO totp_enrollments (user_id, secret_enc, confirmed_at, last_used_step, failed_since_success, created_at)
       VALUES (?, ?, NULL, 0, 0, ?)
       ON CONFLICT(user_id) DO UPDATE SET secret_enc = excluded.secret_enc, confirmed_at = NULL, last_used_step = 0,
         failed_since_success = 0, created_at = excluded.created_at
       WHERE totp_enrollments.confirmed_at IS NULL`).run(userId, secretEnc, now);
    return r.changes === 1;
  }

  /**
   * enroll_confirm step 7: confirms the row only while unconfirmed and holding the secret that was opened.
   * Out: rows changed (0 or 1). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  confirm(userId, now, step, secretEncRead) {
    return this.db.prepare(
      `UPDATE totp_enrollments SET confirmed_at = ?, last_used_step = ?, failed_since_success = 0
       WHERE user_id = ? AND confirmed_at IS NULL AND secret_enc = ?`).run(now, step, userId, secretEncRead).changes;
  }

  /**
   * CLAIM(step): one conditional write; of two requests with the same step exactly one changes a row.
   * Out: rows changed (0 or 1). Why: TOTP-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  claim(userId, step) {
    return this.db.prepare(
      `UPDATE totp_enrollments SET last_used_step = ?, failed_since_success = 0
       WHERE user_id = ? AND confirmed_at IS NOT NULL AND last_used_step < ?`).run(step, userId, step).changes;
  }

  /**
   * TRY(user_id): inserts the slot row only while fewer than 5 rows are inside the window, in one statement.
   * Out: the slot row's id, or null when the user is locked. Why: TOTP-09.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  tryInsert(userId, now) {
    const r = this.db.prepare(
      `INSERT INTO totp_failures (user_id, at) SELECT ?, ?
       WHERE (SELECT COUNT(*) FROM totp_failures WHERE user_id = ? AND at > ?) < ?`)
      .run(userId, now, userId, now - LOCK_SECONDS, LOCK_FAILURES);
    return r.changes === 1 ? Number(r.lastInsertRowid) : null;
  }

  /** Deletes one slot row by id (an answer that is not a FAILURE). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  deleteSlot(slotId) {
    this.db.prepare('DELETE FROM totp_failures WHERE id = ?').run(slotId);
  }

  /** FAILURE: failed_since_success + 1 in one statement. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  addFailure(userId) {
    this.db.prepare('UPDATE totp_enrollments SET failed_since_success = failed_since_success + 1 WHERE user_id = ?').run(userId);
  }

  /** An ok recovery-code answer: failed_since_success = 0. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  resetFailures(userId) {
    this.db.prepare('UPDATE totp_enrollments SET failed_since_success = 0 WHERE user_id = ?').run(userId);
  }

  /**
   * The `at` of the 5th most recent failure inside the window, or null when the user is not LOCKED.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  fifthRecentFailureAt(userId, now) {
    const row = this.db.prepare(
      'SELECT at FROM totp_failures WHERE user_id = ? AND at > ? ORDER BY at DESC, id DESC LIMIT 1 OFFSET ?')
      .get(userId, now - LOCK_SECONDS, LOCK_FAILURES - 1);
    return row ? row.at : null;
  }

  /** Number of failure rows the user has (any age). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  failureCount(userId) {
    return this.db.prepare('SELECT COUNT(*) AS n FROM totp_failures WHERE user_id = ?').get(userId).n;
  }

  /** Stores the recovery code hashes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  insertRecoveryHashes(userId, hashes, now) {
    const stmt = this.db.prepare('INSERT INTO totp_recovery_codes (user_id, code_hash, created_at, used_at) VALUES (?, ?, ?, NULL)');
    for (const h of hashes) stmt.run(userId, h, now);
  }

  /**
   * Uses a recovery code once: one conditional write. Out: rows changed (0 or 1). Why: TOTP-08.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  useRecoveryCode(userId, codeHash, now) {
    return this.db.prepare(
      'UPDATE totp_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL')
      .run(now, userId, codeHash).changes;
  }

  /** Unused recovery codes of the user. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  recoveryCodesLeft(userId) {
    return this.db.prepare('SELECT COUNT(*) AS n FROM totp_recovery_codes WHERE user_id = ? AND used_at IS NULL').get(userId).n;
  }

  /** The user's stored recovery code hashes, in insertion order. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  recoveryHashes(userId) {
    return this.db.prepare('SELECT code_hash FROM totp_recovery_codes WHERE user_id = ? ORDER BY id').all(userId).map(r => r.code_hash);
  }

  /** disable: deletes the enrollment, recovery codes and failures. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  deleteUser(userId) {
    this.db.prepare('DELETE FROM totp_enrollments WHERE user_id = ?').run(userId);
    this.db.prepare('DELETE FROM totp_recovery_codes WHERE user_id = ?').run(userId);
    this.db.prepare('DELETE FROM totp_failures WHERE user_id = ?').run(userId);
  }
}

/* ------------------------------------------------------------------ service */

/**
 * TotpService: the flows of the spec. Build it with createTotpService().
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the store given.
 */
class TotpService {
  /**
   * In: {store, encryptionKey (exactly 32 bytes), recoveryHashKey (>= 32 bytes), issuer, clock() -> seconds,
   * randomBytes(n) -> Buffer (default crypto.randomBytes)}. Throws TotpError("invalid_key") for a key of the wrong
   * size (TOTP-11). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
   */
  constructor({ store, encryptionKey, recoveryHashKey, issuer, clock, randomBytes } = {}) {
    const enc = encryptionKey ? Buffer.from(encryptionKey) : null;
    const rec = recoveryHashKey ? Buffer.from(recoveryHashKey) : null;
    if (!enc || enc.length !== 32 || !rec || rec.length < 32) throw new TotpError('invalid_key');
    Object.defineProperty(this, '_enc', { value: enc, enumerable: false });
    Object.defineProperty(this, '_rec', { value: rec, enumerable: false });
    this.store = store || new SqliteTotpStore();
    this.issuer = issuer;
    this.clock = clock || (() => Math.floor(Date.now() / 1000));
    this.randomBytes = randomBytes || (n => crypto.randomBytes(n));
  }

  /** generate_secret(): base32 of 20 random bytes (32 characters). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
  generateSecret() {
    return base32Encode(Buffer.from(this.randomBytes(20)).subarray(0, 20));
  }

  /**
   * enroll_start(user_id, account_label) -> {secret, otpauth_uri} | 409 already_enrolled. Stores only the sealed
   * secret. Why: TOTP-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  enrollStart(userId, accountLabel) {
    const row = this.store.getEnrollment(userId);
    if (row && row.confirmed_at !== null) return { error: 'already_enrolled', status: 409 };
    const secret = this.generateSecret();
    const nonce = Buffer.from(this.randomBytes(12)).subarray(0, 12);
    const now = this.clock();
    if (!this.store.putUnconfirmed(userId, seal(this._enc, nonce, secret, 'totp:' + userId), now)) {
      return { error: 'already_enrolled', status: 409 };
    }
    return { secret, otpauth_uri: otpauthUri(secret, this.issuer, accountLabel) };
  }

  /**
   * MATCH: compares the codes of steps s-1, s, s+1 in constant time with no early exit; the result is the LARGEST
   * equal step, or null. In: key, 6-digit input, now. Out: step | null. Why: TOTP-05, TOTP-06.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  match(key, input, now) {
    const s = Math.floor(now / STEP);
    const given = Buffer.from(input, 'utf8');
    let found = null;
    for (let d = -1; d <= 1; d++) {
      const step = s + d;
      if (step < 0) continue;
      const equal = crypto.timingSafeEqual(Buffer.from(hotp(key, step), 'utf8'), given);
      if (equal) found = step;
    }
    return found;
  }

  /**
   * The 429 locked answer with retry_after, from the 5th most recent failure in the window.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  lockedAnswer(userId, now) {
    const at = this.store.fifthRecentFailureAt(userId, now);
    const retryAfter = at === null ? LOCK_SECONDS : at + LOCK_SECONDS - now;
    return { error: 'locked', status: 429, retry_after: retryAfter };
  }

  /**
   * FAILURE: the slot row stays as the failure; failed_since_success + 1. Out: 401 invalid_code.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  failure(userId) {
    this.store.addFailure(userId);
    return { error: 'invalid_code', status: 401 };
  }

  /**
   * One RECOVERY CODE: 12 symbols drawn one byte at a time (b >= 240 drawn again), shown as xxxx-xxxx-xxxx.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing (calls randomBytes).
   */
  drawRecoveryCode() {
    let s = '';
    while (s.length < 12) {
      const b = Buffer.from(this.randomBytes(1))[0];
      if (b >= 240) continue;
      s += RECOVERY_ALPHABET[b % 30];
    }
    return s.slice(0, 4) + '-' + s.slice(4, 8) + '-' + s.slice(8, 12);
  }

  /**
   * enroll_confirm(user_id, code) -> {recovery_codes: [8]} or a refusal, in the spec's order of checks.
   * Why: TOTP-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  enrollConfirm(userId, code) {
    const row = this.store.getEnrollment(userId);
    if (!row) return { error: 'enrollment_not_started', status: 409 };
    if (row.confirmed_at !== null) return { error: 'already_enrolled', status: 409 };
    const now = this.clock();
    const slot = this.store.tryInsert(userId, now);
    if (slot === null) return this.lockedAnswer(userId, now);
    const input = totpInput(code);
    if (input === null) return this.failure(userId);
    const secret = open(this._enc, row.secret_enc, 'totp:' + userId);
    if (secret === null) {
      this.store.deleteSlot(slot);
      return { error: 'secret_unreadable', status: 503 };
    }
    const key = base32Decode(secret);
    const step = Buffer.isBuffer(key) ? this.match(key, input, now) : null;
    if (step === null) return this.failure(userId);
    if (this.store.confirm(userId, now, step, row.secret_enc) !== 1) {
      const again = this.store.getEnrollment(userId);
      if (again && again.confirmed_at !== null) {
        this.store.deleteSlot(slot);
        return { error: 'already_enrolled', status: 409 };
      }
      return this.failure(userId);
    }
    const codes = [];
    while (codes.length < RECOVERY_CODES) {
      const c = this.drawRecoveryCode();
      if (!codes.includes(c)) codes.push(c);
    }
    this.store.insertRecoveryHashes(userId, codes.map(c => recoveryCodeHash(this._rec, userId, c)), now);
    this.store.deleteSlot(slot);
    return { recovery_codes: codes };
  }

  /**
   * Steps 1-5 of verify, shared by verify and disable. Out: {ok: true, method} or a refusal.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  check(userId, code) {
    const row = this.store.getEnrollment(userId);
    if (!row || row.confirmed_at === null) return { error: 'not_enrolled', status: 409 };
    const now = this.clock();
    const slot = this.store.tryInsert(userId, now);
    if (slot === null) return this.lockedAnswer(userId, now);
    const input = totpInput(code);
    if (input !== null) {
      if (row.failed_since_success >= HARD_LOCK_FAILURES) {
        this.store.deleteSlot(slot);
        return { error: 'recovery_required', status: 429 };
      }
      const secret = open(this._enc, row.secret_enc, 'totp:' + userId);
      const key = secret === null ? null : base32Decode(secret);
      if (!Buffer.isBuffer(key)) {
        this.store.deleteSlot(slot);
        return { error: 'secret_unreadable', status: 503 };
      }
      const step = this.match(key, input, now);
      if (step === null || step <= row.last_used_step) return this.failure(userId);
      if (this.store.claim(userId, step) !== 1) return this.failure(userId);
      this.store.deleteSlot(slot);
      return { ok: true, method: 'totp' };
    }
    const hash = recoveryCodeHash(this._rec, userId, code);
    if (hash !== null) {
      if (this.store.useRecoveryCode(userId, hash, now) !== 1) return this.failure(userId);
      this.store.resetFailures(userId);
      this.store.deleteSlot(slot);
      return { ok: true, method: 'recovery_code' };
    }
    return this.failure(userId);
  }

  /**
   * verify(user_id, code) -> {ok: true, method, recovery_codes_left} or a refusal. Why: TOTP-05..TOTP-10,
   * TOTP-13, TOTP-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  verify(userId, code) {
    const r = this.check(userId, code);
    if (!r.ok) return r;
    return { ok: true, method: r.method, recovery_codes_left: this.store.recoveryCodesLeft(userId) };
  }

  /**
   * disable(user_id, code) -> {disabled: true} after steps 1-5 of verify; deletes the enrollment, recovery codes
   * and failures. Why: TOTP-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  disable(userId, code) {
    const r = this.check(userId, code);
    if (!r.ok) return r;
    this.store.deleteUser(userId);
    return { disabled: true };
  }

  /**
   * status(user_id) -> {enrolled, locked_until, recovery_required, recovery_codes_left}. Reads only.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (read).
   */
  status(userId) {
    const row = this.store.getEnrollment(userId);
    const enrolled = !!row && row.confirmed_at !== null;
    const at = this.store.fifthRecentFailureAt(userId, this.clock());
    return {
      enrolled,
      locked_until: at === null ? null : at + LOCK_SECONDS,
      recovery_required: enrolled && row.failed_since_success >= HARD_LOCK_FAILURES,
      recovery_codes_left: this.store.recoveryCodesLeft(userId)
    };
  }
}

/**
 * createTotpService(config): see TotpService. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
 */
function createTotpService(config) {
  return new TotpService(config);
}

module.exports = {
  base32Encode, base32Decode, hotp, totpAt, otpauthUri, seal, open, recoveryCodeHash, totpInput, recoveryInput,
  SqliteTotpStore, TotpService, TotpError, createTotpService, RECOVERY_ALPHABET
};

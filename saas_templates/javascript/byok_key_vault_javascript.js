'use strict';
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

/**
 * BYOK key vault (docs/specs/byok_key_vault.md): a user stores their own API key for a third-party provider. The
 * key is encrypted at rest with envelope encryption (a fresh AES-256-GCM data key per stored key, wrapped by a
 * master key), shown again only as a 4-character hint, opened only for the user who saved it, and every use is
 * audited. Provider checks are limited to 10 per user per clock hour so the vault is no oracle for stolen keys.
 *
 * Why: Phase D wave 1, owner request 2026-11-10 (VAULT-01..VAULT-14).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the database given (SQLite, the spec's SCHEMA, parameterized statements, transactions); the network
 * only through the injected provider client (the real one makes one read-only call per save). No files or money.
 * The key never appears in a refusal, an audit row, a log or an exception message.
 */

const SAVES_PER_HOUR = 10;
const KEY_ID_RE = /^[A-Za-z0-9_-]{1,32}$/;
const PROVIDER_ID_RE = /^[a-z0-9_]{1,32}$/;
const PURPOSE_RE = /^[A-Za-z0-9_.:-]{1,100}$/;

/**
 * VaultError: thrown only at construction for a bad configuration ("invalid_master_key",
 * "invalid_provider_config"), so no vault exists (fail closed). In: code. Out: Error with `.code`. Why: VAULT-11.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
class VaultError extends Error {
  /**
   * In: the error code. Out: the error, with `.code` set and the code as its only message (no secret).
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1). Touches nothing.
   */
  constructor(code) {
    super(code);
    this.name = 'VaultError';
    this.code = code;
  }
}

/* ------------------------------------------------------------------ crypto helpers */

/**
 * GCM(key, nonce, plaintext, aad) = ciphertext followed by its 16-byte tag (AES-256-GCM, 12-byte nonce).
 * In: 32-byte key, 12-byte nonce, Buffer plaintext, aad text. Out: Buffer. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function gcmSeal(key, nonce, plaintext, aad) {
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  c.setAAD(Buffer.from(aad, 'utf8'));
  return Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
}

/**
 * Opens base64(nonce + ciphertext + tag). Out: the plaintext Buffer, or null for text that is not canonical
 * base64, fewer than 28 bytes, or a tag that does not verify (lengths checked before slicing).
 * In: key, base64 text, aad. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function gcmOpenB64(key, text, aad) {
  try {
    if (typeof text !== 'string' || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) return null;
    const raw = Buffer.from(text, 'base64');
    if (raw.toString('base64') !== text || raw.length < 28) return null;
    const d = crypto.createDecipheriv('aes-256-gcm', key, raw.subarray(0, 12), { authTagLength: 16 });
    d.setAAD(Buffer.from(aad, 'utf8'));
    d.setAuthTag(raw.subarray(raw.length - 16));
    return Buffer.concat([d.update(raw.subarray(12, raw.length - 16)), d.final()]);
  } catch (err) {
    return null;
  }
}

/** aad of the data ciphertext. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
function dataAad(provider, userId) {
  return 'byok:data:' + provider + ':' + userId;
}

/** aad of the wrapped DEK. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
function dekAad(keyId, provider, userId) {
  return 'byok:dek:' + keyId + ':' + provider + ':' + userId;
}

/* ------------------------------------------------------------------ store */

/**
 * SQLite store (node:sqlite) on the spec's SCHEMA. Multi-statement writes run in one transaction; the save window
 * is one conditional upsert. In: a DatabaseSync (default a new in-memory one).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
 */
class SqliteVaultStore {
  /**
   * Creates the spec's SCHEMA tables when absent. In: a DatabaseSync (default a new in-memory one). Out: the store.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1). Touches the database.
   */
  constructor(db = new DatabaseSync(':memory:')) {
    this.db = db;
    db.exec(`
      CREATE TABLE IF NOT EXISTS provider_keys (
        user_id TEXT NOT NULL, provider TEXT NOT NULL, key_id TEXT NOT NULL, wrapped_dek TEXT NOT NULL,
        ciphertext TEXT NOT NULL, hint TEXT NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER NULL,
        PRIMARY KEY (user_id, provider));
      CREATE TABLE IF NOT EXISTS provider_key_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, provider TEXT NOT NULL, action TEXT NOT NULL,
        purpose TEXT NULL, key_id TEXT NOT NULL, at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS provider_key_save_windows (
        user_id TEXT NOT NULL, window_start INTEGER NOT NULL, count INTEGER NOT NULL,
        PRIMARY KEY (user_id, window_start));`);
  }

  /**
   * Runs fn inside BEGIN / COMMIT, rolling back on any error (which is rethrown). In: fn. Out: fn's result.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  transaction(fn) {
    this.db.exec('BEGIN');
    try {
      const out = fn();
      this.db.exec('COMMIT');
      return out;
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  /**
   * Counts one provider check in the hour window: insert, or add 1 while the count is under 10, in ONE statement.
   * Out: true when counted, false when the window is full. Why: VAULT-12.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  countCheck(userId, windowStart) {
    const r = this.db.prepare(
      `INSERT INTO provider_key_save_windows (user_id, window_start, count) VALUES (?, ?, 1)
       ON CONFLICT (user_id, window_start) DO UPDATE SET count = provider_key_save_windows.count + 1
       WHERE provider_key_save_windows.count < ?`).run(userId, windowStart, SAVES_PER_HOUR);
    return r.changes === 1;
  }

  /** The window's count (0 when absent). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  windowCount(userId, windowStart) {
    const row = this.db.prepare('SELECT count FROM provider_key_save_windows WHERE user_id = ? AND window_start = ?')
      .get(userId, windowStart);
    return row ? row.count : 0;
  }

  /**
   * Inserts one audit row. In: {user_id, provider, action, purpose, key_id, at}. Overridable in tests to fail.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  insertAudit(a) {
    this.db.prepare('INSERT INTO provider_key_audit (user_id, provider, action, purpose, key_id, at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(a.user_id, a.provider, a.action, a.purpose, a.key_id, a.at);
  }

  /**
   * Writes the row (replacing the user's earlier row for the provider) and the key_saved audit row in one
   * transaction. In: the row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  saveRow(row) {
    this.transaction(() => {
      this.db.prepare(
        `INSERT INTO provider_keys (user_id, provider, key_id, wrapped_dek, ciphertext, hint, created_at, last_used_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
         ON CONFLICT (user_id, provider) DO UPDATE SET key_id = excluded.key_id, wrapped_dek = excluded.wrapped_dek,
           ciphertext = excluded.ciphertext, hint = excluded.hint, created_at = excluded.created_at, last_used_at = NULL`)
        .run(row.user_id, row.provider, row.key_id, row.wrapped_dek, row.ciphertext, row.hint, row.created_at);
      this.insertAudit({ user_id: row.user_id, provider: row.provider, action: 'key_saved', purpose: null, key_id: row.key_id, at: row.created_at });
    });
  }

  /** The (user, provider) row or null. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  getRow(userId, provider) {
    return this.db.prepare('SELECT * FROM provider_keys WHERE user_id = ? AND provider = ?').get(userId, provider) || null;
  }

  /** The user's rows sorted by provider (BINARY = byte order). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  listRows(userId) {
    return this.db.prepare('SELECT * FROM provider_keys WHERE user_id = ? ORDER BY provider COLLATE BINARY').all(userId);
  }

  /**
   * use_key step 5: last_used_at = now and the key_used audit row, one transaction.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  markUsed(userId, provider, now, purpose, keyId) {
    this.transaction(() => {
      this.db.prepare('UPDATE provider_keys SET last_used_at = ? WHERE user_id = ? AND provider = ?').run(now, userId, provider);
      this.insertAudit({ user_id: userId, provider, action: 'key_used', purpose, key_id: keyId, at: now });
    });
  }

  /**
   * Deletes the row and, when one was deleted, writes key_deleted, in one transaction. Out: true when deleted.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  deleteRow(userId, provider, now) {
    return this.transaction(() => {
      const row = this.getRow(userId, provider);
      if (!row) return false;
      this.db.prepare('DELETE FROM provider_keys WHERE user_id = ? AND provider = ?').run(userId, provider);
      this.insertAudit({ user_id: userId, provider, action: 'key_deleted', purpose: null, key_id: row.key_id, at: now });
      return true;
    });
  }

  /**
   * Rows not under the active key, in (user_id, provider) order. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches the database.
   */
  rowsNotUnder(activeKeyId) {
    return this.db.prepare('SELECT * FROM provider_keys WHERE key_id <> ? ORDER BY user_id COLLATE BINARY, provider COLLATE BINARY')
      .all(activeKeyId);
  }

  /**
   * The rewrap write: only while the row still holds the wrapped_dek that was read; on one changed row the
   * key_rewrapped audit row too, in one transaction. Out: rows changed (0 or 1). Why: VAULT-10.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  rewrapRow(userId, provider, activeKeyId, newWrapped, wrappedRead, now) {
    return this.transaction(() => {
      const changes = this.db.prepare(
        'UPDATE provider_keys SET key_id = ?, wrapped_dek = ? WHERE user_id = ? AND provider = ? AND wrapped_dek = ?')
        .run(activeKeyId, newWrapped, userId, provider, wrappedRead).changes;
      if (changes === 1) {
        this.insertAudit({ user_id: userId, provider, action: 'key_rewrapped', purpose: null, key_id: activeKeyId, at: now });
      }
      return changes;
    });
  }

  /** The user's audit rows, oldest first. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  listAudit(userId) {
    return this.db.prepare('SELECT at, action, provider, purpose, key_id FROM provider_key_audit WHERE user_id = ? ORDER BY id')
      .all(userId).map(r => ({ at: r.at, action: r.action, provider: r.provider, purpose: r.purpose, key_id: r.key_id }));
  }
}

/* ------------------------------------------------------------------ vault */

/**
 * KeyVault: the flows of the spec. Build it with createKeyVault().
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the store and the injected provider client.
 */
class KeyVault {
  /**
   * In: {store, masterKeys: {key_id: 32 bytes}, activeKeyId, providers: {id: {prefix, min_length, max_length}},
   * providerClient: {check(provider, key) -> "ok" | "rejected" | "unreachable" (or a Promise of one)},
   * clock() -> seconds, randomBytes(n) -> Buffer}. Throws VaultError("invalid_master_key" |
   * "invalid_provider_config") for a bad configuration (VAULT-11). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches memory only.
   */
  constructor({ store, masterKeys, activeKeyId, providers, providerClient, clock, randomBytes } = {}) {
    const keys = new Map();
    for (const [id, k] of Object.entries(masterKeys || {})) {
      const buf = Buffer.isBuffer(k) || k instanceof Uint8Array ? Buffer.from(k) : null;
      if (!KEY_ID_RE.test(id) || !buf || buf.length !== 32) throw new VaultError('invalid_master_key');
      keys.set(id, buf);
    }
    if (typeof activeKeyId !== 'string' || !keys.has(activeKeyId)) throw new VaultError('invalid_master_key');
    const provs = new Map();
    for (const [id, p] of Object.entries(providers || {})) {
      const ok = PROVIDER_ID_RE.test(id) && p && typeof p.prefix === 'string' &&
        Number.isInteger(p.min_length) && Number.isInteger(p.max_length) &&
        p.min_length >= 20 && p.min_length <= p.max_length && p.max_length <= 4096 &&
        p.min_length >= p.prefix.length + 16;
      if (!ok) throw new VaultError('invalid_provider_config');
      provs.set(id, { prefix: p.prefix, min_length: p.min_length, max_length: p.max_length });
    }
    Object.defineProperty(this, '_keys', { value: keys, enumerable: false });
    this.activeKeyId = activeKeyId;
    this.providers = provs;
    this.store = store || new SqliteVaultStore();
    this.providerClient = providerClient;
    this.clock = clock || (() => Math.floor(Date.now() / 1000));
    this.randomBytes = randomBytes || (n => crypto.randomBytes(n));
  }

  /** n random bytes from the injected source. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
  draw(n) {
    return Buffer.from(this.randomBytes(n)).subarray(0, n);
  }

  /**
   * save_key(user_id, provider, key) -> {provider, hint, key_id, created_at} or a refusal, in the spec's order:
   * unknown provider, key format, the hourly check count, the provider check, the envelope write.
   * Async because the provider check is a network call. Why: VAULT-01..VAULT-04, VAULT-09, VAULT-12.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database and the provider client.
   */
  async saveKey(userId, provider, key) {
    const p = this.providers.get(provider);
    if (!p) return { error: 'unknown_provider', status: 404 };
    if (typeof key !== 'string') return { error: 'invalid_key_format', status: 400 };
    const k = key.replace(/^[ \t\r\n]+/, '').replace(/[ \t\r\n]+$/, '');
    let printable = true;
    for (let i = 0; i < k.length; i++) {
      const c = k.charCodeAt(i);
      if (c < 0x21 || c > 0x7e) { printable = false; break; }
    }
    if (!printable || !k.startsWith(p.prefix) || k.length < p.min_length || k.length > p.max_length) {
      return { error: 'invalid_key_format', status: 400 };
    }
    const now = this.clock();
    const w = now - (now % 3600);
    if (!this.store.countCheck(userId, w)) return { error: 'rate_limited', status: 429, retry_after: w + 3600 - now };
    let verdict;
    try {
      verdict = await this.providerClient.check(provider, k);
    } catch (err) {
      return { error: 'provider_unreachable', status: 502 };
    }
    if (verdict === 'rejected') return { error: 'key_rejected', status: 400 };
    if (verdict !== 'ok') return { error: 'provider_unreachable', status: 502 };
    const dek = this.draw(32);
    const dataNonce = this.draw(12);
    const wrapNonce = this.draw(12);
    const keyId = this.activeKeyId;
    const row = {
      user_id: userId, provider, key_id: keyId,
      ciphertext: Buffer.concat([dataNonce, gcmSeal(dek, dataNonce, Buffer.from(k, 'utf8'), dataAad(provider, userId))]).toString('base64'),
      wrapped_dek: Buffer.concat([wrapNonce, gcmSeal(this._keys.get(keyId), wrapNonce, dek, dekAad(keyId, provider, userId))]).toString('base64'),
      hint: k.slice(-4), created_at: now
    };
    dek.fill(0);
    try {
      this.store.saveRow(row);
    } catch (err) {
      return { error: 'storage_failed', status: 500 };
    }
    return { provider, hint: row.hint, key_id: keyId, created_at: now };
  }

  /**
   * list_keys(user_id) -> [{provider, hint, key_id, created_at, last_used_at}] sorted by provider; never the key,
   * ciphertext or wrapped_dek. Why: VAULT-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  listKeys(userId) {
    return this.store.listRows(userId).map(r => ({
      provider: r.provider, hint: r.hint, key_id: r.key_id, created_at: r.created_at, last_used_at: r.last_used_at
    }));
  }

  /**
   * use_key(user_id, provider, purpose) -> {key} or a refusal. SERVER-SIDE ONLY. Unknown master key id is 503,
   * anything that does not open is 500 key_unreadable, a failed audit write is 500 storage_failed with no key.
   * Why: VAULT-06..VAULT-08, VAULT-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  useKey(userId, provider, purpose) {
    if (typeof purpose !== 'string' || !PURPOSE_RE.test(purpose)) return { error: 'invalid_purpose', status: 400 };
    const row = this.store.getRow(userId, provider);
    if (!row) return { error: 'key_not_found', status: 404 };
    const master = this._keys.get(row.key_id);
    if (!master) return { error: 'key_unavailable', status: 503 };
    const dek = gcmOpenB64(master, row.wrapped_dek, dekAad(row.key_id, provider, userId));
    if (!dek || dek.length !== 32) return { error: 'key_unreadable', status: 500 };
    const plain = gcmOpenB64(dek, row.ciphertext, dataAad(provider, userId));
    dek.fill(0);
    if (!plain) return { error: 'key_unreadable', status: 500 };
    try {
      this.store.markUsed(userId, provider, this.clock(), purpose, row.key_id);
    } catch (err) {
      plain.fill(0);
      return { error: 'storage_failed', status: 500 };
    }
    return { key: plain.toString('utf8') };
  }

  /**
   * delete_key(user_id, provider) -> {deleted: true} with key_deleted, or {deleted: false} with no audit row.
   * When the store fails (the delete and its audit row are one transaction, rolled back together) the answer is
   * the returned refusal {error: 'storage_failed', status: 500}, never an exception, as in the C#, Go, PHP and
   * Rust ports and the spec's CONVENTIONS (a refusal is a returned value).
   * In: userId, provider. Out: {deleted} or {error, status}.
   * Why: VAULT-07, VAULT-13; review finding 4525101278 (a store failure was thrown). 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  deleteKey(userId, provider) {
    try {
      return { deleted: this.store.deleteRow(userId, provider, this.clock()) };
    } catch (err) {
      return { error: 'storage_failed', status: 500 };
    }
  }

  /**
   * rewrap() -> {rewrapped, failed}. OPERATOR ONLY. Re-wraps each DEK not under the active key; the write is
   * conditional on the wrapped_dek that was read, and the ciphertext is never touched. A row whose write fails
   * in the store (rolled back with its audit row) counts in `failed` and the run goes on with the next row, as
   * the Rust and TypeScript ports do: one bad write never stops the operator run partway.
   * In: none. Out: {rewrapped, failed}.
   * Why: VAULT-10; review finding 4525101278 (a rewrapRow failure stopped the run). 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  rewrap() {
    let rewrapped = 0;
    let failed = 0;
    for (const row of this.store.rowsNotUnder(this.activeKeyId)) {
      const master = this._keys.get(row.key_id);
      const dek = master ? gcmOpenB64(master, row.wrapped_dek, dekAad(row.key_id, row.provider, row.user_id)) : null;
      if (!dek || dek.length !== 32) { failed++; continue; }
      const wrapNonce = this.draw(12);
      const active = this.activeKeyId;
      const newWrapped = Buffer.concat([
        wrapNonce, gcmSeal(this._keys.get(active), wrapNonce, dek, dekAad(active, row.provider, row.user_id))
      ]).toString('base64');
      dek.fill(0);
      try {
        if (this.store.rewrapRow(row.user_id, row.provider, active, newWrapped, row.wrapped_dek, this.clock()) === 1) rewrapped++;
      } catch (err) {
        failed++;
      }
    }
    return { rewrapped, failed };
  }

  /**
   * list_audit(user_id) -> [{at, action, provider, purpose, key_id}], oldest first.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  listAudit(userId) {
    return this.store.listAudit(userId);
  }
}

/**
 * createKeyVault(config): see KeyVault. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
 */
function createKeyVault(config) {
  return new KeyVault(config);
}

module.exports = { createKeyVault, KeyVault, SqliteVaultStore, VaultError, SAVES_PER_HOUR };

/**
 * BYOK key vault (docs/specs/byok_key_vault.md): a user's own API key for a third-party provider, stored with
 * envelope encryption (a fresh AES-256-GCM data key per stored key, wrapped by a master key), shown again only as a
 * 4-character hint, opened only for the user who saved it, every use recorded, and master keys rotated by rewrap().
 *
 * Exports: VaultError (construction failures), ProviderClient, VaultStore with InMemoryVaultStore, and KeyVault
 * (saveKey, listKeys, useKey, deleteKey, rewrap, listAudit).
 *
 * Why: Phase D wave 1, owner request 2026-11-10 (six new systems). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the injected store (process memory for the in-memory one) and the injected provider client (the network,
 * for a real one; tests pass a fake). No files, no money.
 */
import { createCipheriv, createDecipheriv, randomBytes as cryptoRandomBytes } from 'crypto';

/** Provider checks allowed per user per clock hour (spec SAVES_PER_HOUR). */
export const SAVES_PER_HOUR = 10;

/** A refusal: the spec error code and the HTTP status a route serves it with (plus retry_after for 429). */
export interface VaultRefusal {
  error: string;
  status: number;
  retry_after?: number;
}

/**
 * Thrown by the KeyVault constructor: code "invalid_master_key" or "invalid_provider_config" (fail closed). The
 * message never holds a key. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export class VaultError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = 'VaultError';
  }
}

/** One provider's key shape (spec CONFIGURATION providers). */
export interface ProviderConfig {
  prefix: string;
  min_length: number;
  max_length: number;
}

/**
 * The injected provider client: check(provider, key) -> "ok" | "rejected" | "unreachable". The real one makes one
 * read-only call to the provider; tests pass a fake. It may answer synchronously or with a promise, and may throw.
 */
export interface ProviderClient {
  check(provider: string, key: string): string | Promise<string>;
}

/** A provider_keys row (spec SCHEMA). */
export interface ProviderKeyRow {
  user_id: string;
  provider: string;
  key_id: string;
  wrapped_dek: string;
  ciphertext: string;
  hint: string;
  created_at: number;
  last_used_at: number | null;
}

/** A provider_key_audit row (spec SCHEMA). */
export interface AuditRow {
  id: number;
  user_id: string;
  provider: string;
  action: 'key_saved' | 'key_used' | 'key_deleted' | 'key_rewrapped';
  purpose: string | null;
  key_id: string;
  at: number;
}

/** An audit row before the store gives it its id. */
export type NewAudit = Omit<AuditRow, 'id'>;

/**
 * The storage contract (spec SCHEMA). Each method is one atomic step or one transaction; a method that throws has
 * written nothing. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the backing store.
 */
export interface VaultStore {
  /** The row for (user, provider) (a copy), or undefined. */
  getRow(userId: string, provider: string): ProviderKeyRow | undefined;
  /** The user's rows (copies). */
  listRows(userId: string): ProviderKeyRow[];
  /** INSERT ... ON CONFLICT DO UPDATE SET count = count + 1 WHERE count < 10. true when a row changed. */
  bumpSaveWindow(userId: string, windowStart: number): boolean;
  /** ONE transaction: replace the user's row for the provider and add the audit row. Throws: nothing written. */
  saveRow(row: ProviderKeyRow, audit: NewAudit): void;
  /** ONE transaction: last_used_at = now and the audit row key_used. Throws: nothing written. */
  markUsed(userId: string, provider: string, now: number, audit: NewAudit): void;
  /** Deletes the row and adds the audit row in one transaction; false (and no audit row) when there was none. */
  deleteRow(userId: string, provider: string, audit: NewAudit): boolean;
  /** Every row whose key_id is not the active one (copies), in (user_id, provider) byte order. */
  rowsNotUnder(activeKeyId: string): ProviderKeyRow[];
  /** UPDATE ... SET key_id, wrapped_dek WHERE user, provider AND wrapped_dek = read, with its audit row. */
  rewrapRow(userId: string, provider: string, wrappedRead: string, keyId: string, wrapped: string, audit: NewAudit): boolean;
  /** The user's audit rows, oldest first. */
  listAudit(userId: string): AuditRow[];
}

/**
 * Byte-order (ordinal) comparison of two texts by their UTF-8 bytes, never by locale. Touches nothing.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 */
function ordinal(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

/**
 * In-memory VaultStore. Each method runs to completion (atomic). failAuditWrites makes every audit insert throw, so
 * tests can see a transaction roll back. Public fields are for tests to read what is stored.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
 */
export class InMemoryVaultStore implements VaultStore {
  rows = new Map<string, ProviderKeyRow>();
  audit: AuditRow[] = [];
  windows = new Map<string, number>();
  failAuditWrites = false;
  private nextAuditId = 1;

  /** The map key for (user, provider). */
  key(userId: string, provider: string): string {
    return JSON.stringify([userId, provider]);
  }

  /** Builds an audit row with the next id, or throws when audit writes are made to fail. */
  private auditRow(a: NewAudit): AuditRow {
    if (this.failAuditWrites) throw new Error('audit write failed');
    return { id: this.nextAuditId++, ...a };
  }

  /** The row for (user, provider) (a copy), or undefined. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  getRow(userId: string, provider: string): ProviderKeyRow | undefined {
    const row = this.rows.get(this.key(userId, provider));
    return row ? { ...row } : undefined;
  }

  /** The user's rows (copies). In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  listRows(userId: string): ProviderKeyRow[] {
    return [...this.rows.values()].filter((r) => r.user_id === userId).map((r) => ({ ...r }));
  }

  /** INSERT ... ON CONFLICT DO UPDATE SET count = count + 1 WHERE count < 10. true when a row changed. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  bumpSaveWindow(userId: string, windowStart: number): boolean {
    const k = JSON.stringify([userId, windowStart]);
    const count = this.windows.get(k) ?? 0;
    if (count >= SAVES_PER_HOUR) return false;
    this.windows.set(k, count + 1);
    return true;
  }

  /** ONE transaction: replace the user's row for the provider and add the audit row. Throws: nothing written. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  saveRow(row: ProviderKeyRow, audit: NewAudit): void {
    const a = this.auditRow(audit);
    this.rows.set(this.key(row.user_id, row.provider), { ...row });
    this.audit.push(a);
  }

  /** ONE transaction: last_used_at = now and the audit row key_used. Throws: nothing written. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  markUsed(userId: string, provider: string, now: number, audit: NewAudit): void {
    const row = this.rows.get(this.key(userId, provider));
    if (!row) throw new Error('row gone');
    const a = this.auditRow(audit);
    row.last_used_at = now;
    this.audit.push(a);
  }

  /** Deletes the row and adds the audit row in one transaction; false (and no audit row) when there was none. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  deleteRow(userId: string, provider: string, audit: NewAudit): boolean {
    const k = this.key(userId, provider);
    if (!this.rows.has(k)) return false;
    const a = this.auditRow(audit);
    this.rows.delete(k);
    this.audit.push(a);
    return true;
  }

  /** Every row whose key_id is not the active one (copies), in (user_id, provider) byte order. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  rowsNotUnder(activeKeyId: string): ProviderKeyRow[] {
    return [...this.rows.values()]
      .filter((r) => r.key_id !== activeKeyId)
      .sort((a, b) => ordinal(a.user_id, b.user_id) || ordinal(a.provider, b.provider))
      .map((r) => ({ ...r }));
  }

  /** UPDATE ... SET key_id, wrapped_dek WHERE user, provider AND wrapped_dek = read, with its audit row. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  rewrapRow(userId: string, provider: string, wrappedRead: string, keyId: string, wrapped: string, audit: NewAudit): boolean {
    const row = this.rows.get(this.key(userId, provider));
    if (!row || row.wrapped_dek !== wrappedRead) return false;
    const a = this.auditRow(audit);
    row.key_id = keyId;
    row.wrapped_dek = wrapped;
    this.audit.push(a);
    return true;
  }

  /** The user's audit rows, oldest first. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  listAudit(userId: string): AuditRow[] {
    return this.audit.filter((a) => a.user_id === userId).sort((x, y) => x.id - y.id).map((a) => ({ ...a }));
  }
}

/* ------------------------------------------------------------------ crypto helpers */

/**
 * AES-256-GCM with a 12-byte nonce: the ciphertext followed by its 16-byte tag. In: key, nonce, plaintext, aad text.
 * Out: bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function gcmSeal(key: Buffer, nonce: Buffer, plaintext: Buffer, aad: string): Buffer {
  const c = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  c.setAAD(Buffer.from(aad, 'utf8'));
  return Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
}

/**
 * Opens nonce12 + ciphertext + tag16. In: key, the bytes, aad text. Out: the plaintext, or null for fewer than 28
 * bytes or a tag that does not verify. Never throws. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function gcmOpen(key: Buffer, blob: Buffer, aad: string): Buffer | null {
  try {
    if (blob.length < 28) return null;
    const d = createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12), { authTagLength: 16 });
    d.setAAD(Buffer.from(aad, 'utf8'));
    d.setAuthTag(blob.subarray(blob.length - 16));
    return Buffer.concat([d.update(blob.subarray(12, blob.length - 16)), d.final()]);
  } catch {
    return null;
  }
}

/**
 * Strict RFC 4648 section 4 base64 (with padding): null for anything not canonical. In: text. Out: bytes or null.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function strictBase64(text: unknown): Buffer | null {
  if (typeof text !== 'string' || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) return null;
  const bytes = Buffer.from(text, 'base64');
  return bytes.toString('base64') === text ? bytes : null;
}

/** Removes leading and trailing space, tab, CR and LF only (spec save_key step 2). Touches nothing. */
function trimKey(s: string): string {
  const ws = (c: string) => c === ' ' || c === '\t' || c === '\r' || c === '\n';
  let a = 0;
  let b = s.length;
  while (a < b && ws(s[a])) a++;
  while (b > a && ws(s[b - 1])) b--;
  return s.slice(a, b);
}

/* ------------------------------------------------------------------ vault */

/** The injected configuration (spec CONFIGURATION). */
export interface VaultOptions {
  masterKeys: Record<string, Uint8Array>;
  activeKeyId: string;
  providers: Record<string, ProviderConfig>;
  providerClient: ProviderClient;
  store?: VaultStore;
  /** Whole seconds since the epoch. */
  clock?: () => number;
  /** n random bytes; default the system CSPRNG. */
  randomBytes?: (n: number) => Buffer;
}

/**
 * The key vault. Construction fails closed: VaultError("invalid_master_key") for a master key that is not 32 bytes,
 * a malformed key id or an active_key_id not in the keyring; VaultError("invalid_provider_config") for a provider
 * that breaks the id, length or prefix rules. Every flow answers with a returned value, never an exception, and the
 * key appears only in saveKey's input and useKey's result. Why: spec ENDPOINTS (VAULT-01..14). 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the provider client, the clock, the random source.
 */
export class KeyVault {
  readonly store: VaultStore;
  private readonly masterKeys: Map<string, Buffer>;
  private readonly activeKeyId: string;
  private readonly providers: Map<string, ProviderConfig>;
  private readonly client: ProviderClient;
  private readonly clock: () => number;
  private readonly randomBytes: (n: number) => Buffer;

  /**
   * In: VaultOptions. Out: the vault. Throws VaultError (VAULT-11). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches nothing.
   */
  constructor(options: VaultOptions) {
    this.masterKeys = new Map();
    for (const [id, key] of Object.entries(options.masterKeys ?? {})) {
      if (!/^[A-Za-z0-9_-]{1,32}$/.test(id) || !key || key.length !== 32) throw new VaultError('invalid_master_key');
      this.masterKeys.set(id, Buffer.from(key));
    }
    if (typeof options.activeKeyId !== 'string' || !this.masterKeys.has(options.activeKeyId)) {
      throw new VaultError('invalid_master_key');
    }
    this.providers = new Map();
    for (const [id, p] of Object.entries(options.providers ?? {})) {
      const ok = /^[a-z0-9_]{1,32}$/.test(id) && p && typeof p.prefix === 'string' &&
        Number.isInteger(p.min_length) && Number.isInteger(p.max_length) &&
        p.min_length >= 20 && p.min_length <= p.max_length && p.max_length <= 4096 &&
        p.min_length >= p.prefix.length + 16;
      if (!ok) throw new VaultError('invalid_provider_config');
      this.providers.set(id, { ...p });
    }
    this.activeKeyId = options.activeKeyId;
    this.client = options.providerClient;
    this.store = options.store ?? new InMemoryVaultStore();
    this.clock = options.clock ?? (() => Math.floor(Date.now() / 1000));
    this.randomBytes = options.randomBytes ?? cryptoRandomBytes;
  }

  /** The data-key aad: "byok:data:" + provider + ":" + user_id. Touches nothing. */
  private dataAad(provider: string, userId: string): string {
    return 'byok:data:' + provider + ':' + userId;
  }

  /** The wrap aad: "byok:dek:" + key_id + ":" + provider + ":" + user_id. Touches nothing. */
  private dekAad(keyId: string, provider: string, userId: string): string {
    return 'byok:dek:' + keyId + ':' + provider + ':' + userId;
  }

  /**
   * Saves (or replaces) the user's key for a provider after one provider check. Steps in the spec's order: unknown
   * provider 404; key format 400 invalid_key_format; the hourly check window (counted first, one conditional write)
   * 429 rate_limited with retry_after; the provider check (400 key_rejected, 502 provider_unreachable); then the
   * envelope and the row + audit row in one transaction (500 storage_failed).
   * In: the verified user id, provider id, key (any value). Out: {provider, hint, key_id, created_at} or a refusal.
   * Why: spec save_key (VAULT-01..04, 09, 12). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: the store, the provider client (network for a real one), the clock, the random source.
   */
  async saveKey(userId: string, provider: string, key: unknown):
      Promise<{ provider: string; hint: string; key_id: string; created_at: number } | VaultRefusal> {
    const cfg = this.providers.get(provider);
    if (!cfg) return { error: 'unknown_provider', status: 404 };
    if (typeof key !== 'string') return { error: 'invalid_key_format', status: 400 };
    const k = trimKey(key);
    let printable = true;
    for (let i = 0; i < k.length; i++) {
      const c = k.charCodeAt(i);
      if (c < 0x21 || c > 0x7e) printable = false;
    }
    if (!printable || !k.startsWith(cfg.prefix) || k.length < cfg.min_length || k.length > cfg.max_length) {
      return { error: 'invalid_key_format', status: 400 };
    }
    const now = this.clock();
    const w = now - (now % 3600);
    if (!this.store.bumpSaveWindow(userId, w)) return { error: 'rate_limited', status: 429, retry_after: w + 3600 - now };
    let verdict: unknown;
    try {
      verdict = await this.client.check(provider, k);
    } catch {
      return { error: 'provider_unreachable', status: 502 };
    }
    if (verdict === 'rejected') return { error: 'key_rejected', status: 400 };
    if (verdict !== 'ok') return { error: 'provider_unreachable', status: 502 };
    try {
      const dek = this.randomBytes(32);
      const dataNonce = this.randomBytes(12);
      const wrapNonce = this.randomBytes(12);
      const ciphertext = Buffer.concat([dataNonce, gcmSeal(dek, dataNonce, Buffer.from(k, 'utf8'), this.dataAad(provider, userId))]);
      const keyId = this.activeKeyId;
      const wrapped = Buffer.concat([wrapNonce, gcmSeal(this.masterKeys.get(keyId)!, wrapNonce, dek, this.dekAad(keyId, provider, userId))]);
      dek.fill(0);
      const row: ProviderKeyRow = {
        user_id: userId, provider, key_id: keyId, wrapped_dek: wrapped.toString('base64'),
        ciphertext: ciphertext.toString('base64'), hint: k.slice(-4), created_at: now, last_used_at: null,
      };
      this.store.saveRow(row, { user_id: userId, provider, action: 'key_saved', purpose: null, key_id: keyId, at: now });
      return { provider, hint: row.hint, key_id: keyId, created_at: now };
    } catch {
      return { error: 'storage_failed', status: 500 };
    }
  }

  /**
   * The user's saved keys without any secret: [{provider, hint, key_id, created_at, last_used_at}] sorted by
   * provider (ordinal). In: user id. Why: spec list_keys (VAULT-05). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: the store (read).
   */
  listKeys(userId: string): { provider: string; hint: string; key_id: string; created_at: number; last_used_at: number | null }[] {
    return this.store.listRows(userId)
      .sort((a, b) => ordinal(a.provider, b.provider))
      .map((r) => ({ provider: r.provider, hint: r.hint, key_id: r.key_id, created_at: r.created_at, last_used_at: r.last_used_at }));
  }

  /**
   * SERVER-SIDE ONLY: opens the user's key to call the provider for them. Steps: purpose 400 invalid_purpose; no row
   * 404 key_not_found; key_id not in the keyring 503 key_unavailable; unwrap or decrypt fails (bad base64, too
   * short, DEK not 32 bytes, failed tag) 500 key_unreadable; last_used_at + audit key_used in one transaction, else
   * 500 storage_failed and NO key. In: user id, provider, purpose. Out: {key} or a refusal.
   * Why: spec use_key (VAULT-06..08, 10, 11, 13). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: the store, the clock.
   */
  useKey(userId: string, provider: string, purpose: unknown): { key: string } | VaultRefusal {
    if (typeof purpose !== 'string' || !/^[A-Za-z0-9_.:-]{1,100}$/.test(purpose)) return { error: 'invalid_purpose', status: 400 };
    const row = this.store.getRow(userId, provider);
    if (!row) return { error: 'key_not_found', status: 404 };
    const master = this.masterKeys.get(row.key_id);
    if (!master) return { error: 'key_unavailable', status: 503 };
    const key = this.openRow(row, master);
    if (key === null) return { error: 'key_unreadable', status: 500 };
    const now = this.clock();
    try {
      this.store.markUsed(userId, provider, now, { user_id: userId, provider, action: 'key_used', purpose, key_id: row.key_id, at: now });
    } catch {
      return { error: 'storage_failed', status: 500 };
    }
    return { key };
  }

  /**
   * Unwraps the DEK and decrypts the key of a row. In: the row, its master key. Out: the key, or null on any fault
   * (never throws). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  private openRow(row: ProviderKeyRow, master: Buffer): string | null {
    const dek = this.unwrap(row, master);
    if (dek === null) return null;
    const ct = strictBase64(row.ciphertext);
    if (ct === null) return null;
    const plain = gcmOpen(dek, ct, this.dataAad(row.provider, row.user_id));
    dek.fill(0);
    return plain === null ? null : plain.toString('utf8');
  }

  /** Unwraps a row's DEK with a master key: null for bad base64, a failed tag or a DEK that is not 32 bytes. */
  private unwrap(row: ProviderKeyRow, master: Buffer): Buffer | null {
    const wrapped = strictBase64(row.wrapped_dek);
    if (wrapped === null) return null;
    const dek = gcmOpen(master, wrapped, this.dekAad(row.key_id, row.provider, row.user_id));
    return dek !== null && dek.length === 32 ? dek : null;
  }

  /**
   * Deletes the user's key for a provider. In: user id, provider. Out: {deleted: true} with the audit row
   * key_deleted, or {deleted: false} (no audit row). Why: spec delete_key (VAULT-07, 13). 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the clock.
   */
  deleteKey(userId: string, provider: string): { deleted: boolean } {
    const row = this.store.getRow(userId, provider);
    if (!row) return { deleted: false };
    const now = this.clock();
    const deleted = this.store.deleteRow(userId, provider, {
      user_id: userId, provider, action: 'key_deleted', purpose: null, key_id: row.key_id, at: now,
    });
    return { deleted };
  }

  /**
   * OPERATOR ONLY: re-wraps every row not under the active master key, in (user_id, provider) order. A missing master
   * key or a failed tag counts in failed; a row changed since it was read is left alone and counted in neither.
   * ciphertext is never touched. In: nothing. Out: {rewrapped, failed}. Why: spec rewrap (VAULT-10). 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the clock, the random source.
   */
  rewrap(): { rewrapped: number; failed: number } {
    let rewrapped = 0;
    let failed = 0;
    const active = this.masterKeys.get(this.activeKeyId)!;
    for (const row of this.store.rowsNotUnder(this.activeKeyId)) {
      const master = this.masterKeys.get(row.key_id);
      const dek = master ? this.unwrap(row, master) : null;
      if (dek === null) {
        failed++;
        continue;
      }
      const nonce = this.randomBytes(12);
      const wrapped = Buffer.concat([nonce, gcmSeal(active, nonce, dek, this.dekAad(this.activeKeyId, row.provider, row.user_id))]);
      dek.fill(0);
      const now = this.clock();
      try {
        if (this.store.rewrapRow(row.user_id, row.provider, row.wrapped_dek, this.activeKeyId, wrapped.toString('base64'), {
          user_id: row.user_id, provider: row.provider, action: 'key_rewrapped', purpose: null, key_id: this.activeKeyId, at: now,
        })) rewrapped++;
      } catch {
        failed++;
      }
    }
    return { rewrapped, failed };
  }

  /**
   * The user's audit trail, oldest first: [{at, action, provider, purpose, key_id}]. Never holds a key.
   * Why: spec list_audit. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store (read).
   */
  listAudit(userId: string): { at: number; action: string; provider: string; purpose: string | null; key_id: string }[] {
    return this.store.listAudit(userId).map((a) => ({ at: a.at, action: a.action, provider: a.provider, purpose: a.purpose, key_id: a.key_id }));
  }
}

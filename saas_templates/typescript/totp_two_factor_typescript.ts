/**
 * TOTP two-factor (docs/specs/totp_two_factor.md): authenticator-app codes (RFC 6238 over RFC 4226) with one step
 * of clock drift each way, a replay guard, an attempt lock counted before any code is looked at, a hard lock after
 * 100 failures, and one-time recovery codes stored only as keyed hashes. The TOTP secret is stored sealed with
 * AES-256-GCM, never as its base32 text.
 *
 * Exports: the pure functions (base32Encode, base32Decode, hotp, totpAt, generateSecret, otpauthUri, seal, open),
 * the TotpStore interface with its in-memory implementation, and TotpTwoFactor (enrollStart, enrollConfirm, verify,
 * disable, status).
 *
 * Why: Phase D wave 1, owner request 2026-11-10 (six new systems). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the injected store (process memory for the in-memory one); no network, no files, no money.
 */
import { createCipheriv, createDecipheriv, createHmac, randomBytes as cryptoRandomBytes, timingSafeEqual } from 'crypto';

/** 30-second steps, 6 digits, one step of drift each way (spec CONFIGURATION). */
export const STEP = 30;
export const DIGITS = 6;
export const WINDOW = 1;
/** 5 failures inside 900 seconds lock the user (spec TRY / LOCKED). */
export const LOCK_FAILURES = 5;
export const LOCK_SECONDS = 900;
/** 100 failures with no success between them stop TOTP codes until a recovery code is used (spec HARD LOCK). */
export const HARD_LOCK_FAILURES = 100;
/** Recovery codes made at enroll_confirm (spec RECOVERY CODES). */
export const RECOVERY_CODES = 8;
/** The 30 recovery-code symbols: no 0 1 i l o u. */
export const RECOVERY_ALPHABET = '23456789abcdefghjkmnpqrstvwxyz';
/** A code longer than this is neither a TOTP nor a recovery input (tested first). */
const MAX_INPUT_LENGTH = 64;
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** A refusal: the spec error code and the HTTP status a route serves it with (plus retry_after for 429 locked). */
export interface TotpRefusal {
  error: string;
  status: number;
  retry_after?: number;
}

/**
 * Thrown by base32Decode for invalid base32 and by the TotpTwoFactor constructor for a key of the wrong size.
 * code is the spec error code ("invalid_base32" | "invalid_key"); the message never holds a key or a secret.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export class TotpError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = 'TotpError';
  }
}

/* ------------------------------------------------------------------ pure functions */

/**
 * RFC 4648 base32, alphabet A-Z 2-7, upper case, WITHOUT "=" padding. In: bytes. Out: the text.
 * Why: spec PURE FUNCTIONS (TOTP-02). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export function base32Encode(bytes: Uint8Array): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const b of bytes) {
    buffer = (buffer << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += BASE32_ALPHABET[(buffer << (5 - bits)) & 31];
  return out;
}

/**
 * RFC 4648 base32 decode. ASCII spaces, "-" and "=" are removed and a-z mapped to A-Z; every remaining character
 * must be in the alphabet, at least one must remain, and a remaining length of 1, 3 or 6 modulo 8 is refused (no
 * bytes encode to it). Leftover bits that do not fill a byte are dropped.
 * In: the text. Out: the bytes. Throws TotpError("invalid_base32"). Why: spec base32_decode (TOTP-02); the checks
 * are done here, never by a library. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export function base32Decode(text: string): Buffer {
  if (typeof text !== 'string') throw new TotpError('invalid_base32');
  let clean = '';
  for (const ch of text) {
    if (ch === ' ' || ch === '-' || ch === '=') continue;
    const c = ch >= 'a' && ch <= 'z' ? String.fromCharCode(ch.charCodeAt(0) - 32) : ch;
    if (!BASE32_ALPHABET.includes(c) || c.length !== 1) throw new TotpError('invalid_base32');
    clean += c;
  }
  const rem = clean.length % 8;
  if (clean.length === 0 || rem === 1 || rem === 3 || rem === 6) throw new TotpError('invalid_base32');
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const c of clean) {
    buffer = (buffer << 5) | BASE32_ALPHABET.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      out.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
      buffer &= (1 << bits) - 1;
    }
  }
  return Buffer.from(out);
}

/**
 * RFC 4226 HOTP: HMAC-SHA1(key, counter as 8 bytes big-endian), dynamic truncation, v mod 10^digits left-padded
 * with "0". The counter is a 64-bit value (4294967296 is not 0). In: key bytes, counter (number or bigint), digits.
 * Out: the code text. Why: spec hotp (TOTP-01). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export function hotp(key: Uint8Array, counter: number | bigint, digits: number = DIGITS): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', Buffer.from(key)).update(msg).digest();
  const o = mac[19] & 0x0f;
  const v = ((mac[o] & 0x7f) * 2 ** 24) + (mac[o + 1] << 16) + (mac[o + 2] << 8) + mac[o + 3];
  return String(v % 10 ** digits).padStart(digits, '0');
}

/**
 * RFC 6238 TOTP at a given time: hotp(base32Decode(secret), floor(unix_time / 30), digits).
 * In: the base32 secret, whole seconds since the epoch, digits. Out: the code text. Throws TotpError for a bad
 * secret. Why: spec totp_at (TOTP-01). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export function totpAt(secretBase32: string, unixTime: number, digits: number = DIGITS): string {
  return hotp(base32Decode(secretBase32), Math.floor(unixTime / STEP), digits);
}

/**
 * A new TOTP secret: base32Encode(random_bytes(20)), 32 characters. In: the random source (default the CSPRNG).
 * Out: the secret. Why: spec generate_secret (TOTP-02). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the random source.
 */
export function generateSecret(randomBytes: (n: number) => Buffer = cryptoRandomBytes): string {
  return base32Encode(randomBytes(20));
}

/**
 * Percent-encodes every UTF-8 byte not in [A-Za-z0-9._~-] as "%" + two upper-case hex digits (spec pct).
 * In: text. Out: the encoded text. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function pct(s: string): string {
  let out = '';
  for (const b of Buffer.from(s, 'utf8')) {
    const c = String.fromCharCode(b);
    out += /[A-Za-z0-9._~-]/.test(c) ? c : '%' + b.toString(16).toUpperCase().padStart(2, '0');
  }
  return out;
}

/**
 * The otpauth:// URI an authenticator app reads (spec otpauth_uri). In: secret, issuer, account label.
 * Out: the URI. Why: TOTP-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export function otpauthUri(secret: string, issuer: string, accountLabel: string): string {
  return 'otpauth://totp/' + pct(issuer + ':' + accountLabel) + '?secret=' + secret + '&issuer=' + pct(issuer) +
    '&algorithm=SHA1&digits=6&period=30';
}

/**
 * AES-256-GCM seal: "v1." + base64(nonce12 + ciphertext + tag16), aad = the UTF-8 of the aad text.
 * In: 32-byte key, 12-byte nonce, plaintext, aad. Out: the sealed text. Why: spec seal (TOTP-11).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export function seal(key: Uint8Array, nonce: Uint8Array, plaintext: string, aad: string): string {
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(nonce), { authTagLength: 16 });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  return 'v1.' + Buffer.concat([Buffer.from(nonce), ct, cipher.getAuthTag()]).toString('base64');
}

/**
 * Strict RFC 4648 section 4 base64 (with padding) decode: null for anything that is not canonical base64.
 * In: text. Out: bytes or null. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function strictBase64(text: string): Buffer | null {
  if (typeof text !== 'string' || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) return null;
  const bytes = Buffer.from(text, 'base64');
  return bytes.toString('base64') === text ? bytes : null;
}

/**
 * Opens a sealed text. In: 32-byte key, the sealed text, aad. Out: the plaintext, or null for a missing "v1."
 * prefix, bad base64, fewer than 28 bytes, or a tag that does not verify (wrong key, wrong aad, any changed byte).
 * Never throws. Why: spec open (TOTP-10/11). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export function open(key: Uint8Array, sealed: string, aad: string): string | null {
  try {
    if (typeof sealed !== 'string' || !sealed.startsWith('v1.')) return null;
    const raw = strictBase64(sealed.slice(3));
    if (raw === null || raw.length < 28) return null;
    const decipher = createDecipheriv('aes-256-gcm', Buffer.from(key), raw.subarray(0, 12), { authTagLength: 16 });
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(raw.subarray(raw.length - 16));
    const pt = Buffer.concat([decipher.update(raw.subarray(12, raw.length - 16)), decipher.final()]);
    return pt.toString('utf8');
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ store */

/** A totp_enrollments row (spec SCHEMA). */
export interface EnrollmentRow {
  user_id: string;
  secret_enc: string;
  confirmed_at: number | null;
  last_used_step: number;
  failed_since_success: number;
  created_at: number;
}

/**
 * The storage contract (spec SCHEMA). Every method is one atomic step, as the spec's conditional statements are.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the backing store.
 */
export interface TotpStore {
  /** The user's enrollment row (a copy), or undefined. */
  getEnrollment(userId: string): EnrollmentRow | undefined;
  /** Writes an unconfirmed row, replacing an unconfirmed one; false (nothing written) when a confirmed row exists. */
  putUnconfirmed(row: EnrollmentRow): boolean;
  /** UPDATE ... SET confirmed_at, last_used_step, failed_since_success = 0 WHERE unconfirmed AND secret_enc = read. */
  confirm(userId: string, now: number, step: number, secretEncRead: string): boolean;
  /** CLAIM: UPDATE ... SET last_used_step = step, failed_since_success = 0 WHERE confirmed AND last_used_step < step. */
  claimStep(userId: string, step: number): boolean;
  /** TRY: inserts a failure row (user, now) only while fewer than 5 rows have at > now - 900. Out: its id or null. */
  tryInsert(userId: string, now: number): number | null;
  /** Deletes one failure row by id (an answer that is not a FAILURE gives its slot back). */
  deleteTry(id: number): void;
  /** FAILURE: failed_since_success + 1 for the user's enrollment row. */
  addFailure(userId: string): void;
  /** Sets failed_since_success = 0 (a recovery-code success). */
  resetFailures(userId: string): void;
  /** The `at` values of the user's failure rows with at > since, most recent first. */
  failuresSince(userId: string, since: number): number[];
  /** Stores recovery code hashes for the user. */
  insertRecoveryCodes(userId: string, hashes: string[], now: number): void;
  /** UPDATE ... SET used_at = now WHERE user, code_hash and used_at IS NULL; true when one row changed. */
  useRecoveryCode(userId: string, codeHash: string, now: number): boolean;
  /** The user's recovery codes with used_at IS NULL. */
  recoveryCodesLeft(userId: string): number;
  /** Deletes the user's enrollment, recovery codes and failures. */
  deleteAll(userId: string): void;
}

/** A totp_recovery_codes row. */
interface RecoveryRow {
  user_id: string;
  code_hash: string;
  created_at: number;
  used_at: number | null;
}

/**
 * In-memory TotpStore. JavaScript runs each method to completion, so each is atomic. A SQL store runs the spec's
 * statements, parameterized. Public fields are for tests to read (what is stored). 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
 */
export class InMemoryTotpStore implements TotpStore {
  enrollments = new Map<string, EnrollmentRow>();
  recovery: RecoveryRow[] = [];
  failures: { id: number; user_id: string; at: number }[] = [];
  private nextId = 1;

  /** The user's enrollment row (a copy), or undefined. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  getEnrollment(userId: string): EnrollmentRow | undefined {
    const row = this.enrollments.get(userId);
    return row ? { ...row } : undefined;
  }

  /** Writes an unconfirmed row, replacing an unconfirmed one; false (nothing written) when a confirmed row exists. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  putUnconfirmed(row: EnrollmentRow): boolean {
    const cur = this.enrollments.get(row.user_id);
    if (cur && cur.confirmed_at !== null) return false;
    this.enrollments.set(row.user_id, { ...row });
    return true;
  }

  /** UPDATE ... SET confirmed_at, last_used_step, failed_since_success = 0 WHERE unconfirmed AND secret_enc = read. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  confirm(userId: string, now: number, step: number, secretEncRead: string): boolean {
    const row = this.enrollments.get(userId);
    if (!row || row.confirmed_at !== null || row.secret_enc !== secretEncRead) return false;
    row.confirmed_at = now;
    row.last_used_step = step;
    row.failed_since_success = 0;
    return true;
  }

  /** CLAIM: UPDATE ... SET last_used_step = step, failed_since_success = 0 WHERE confirmed AND last_used_step < step. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  claimStep(userId: string, step: number): boolean {
    const row = this.enrollments.get(userId);
    if (!row || row.confirmed_at === null || !(row.last_used_step < step)) return false;
    row.last_used_step = step;
    row.failed_since_success = 0;
    return true;
  }

  /** TRY: inserts a failure row (user, now) only while fewer than 5 rows have at > now - 900. Out: its id or null. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  tryInsert(userId: string, now: number): number | null {
    const inWindow = this.failures.filter((f) => f.user_id === userId && f.at > now - LOCK_SECONDS).length;
    if (inWindow >= LOCK_FAILURES) return null;
    const id = this.nextId++;
    this.failures.push({ id, user_id: userId, at: now });
    return id;
  }

  /** Deletes one failure row by id (an answer that is not a FAILURE gives its slot back). In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  deleteTry(id: number): void {
    this.failures = this.failures.filter((f) => f.id !== id);
  }

  /** FAILURE: failed_since_success + 1 for the user's enrollment row. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  addFailure(userId: string): void {
    const row = this.enrollments.get(userId);
    if (row) row.failed_since_success += 1;
  }

  /** Sets failed_since_success = 0 (a recovery-code success). In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  resetFailures(userId: string): void {
    const row = this.enrollments.get(userId);
    if (row) row.failed_since_success = 0;
  }

  /** The `at` values of the user's failure rows with at > since, most recent first. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  failuresSince(userId: string, since: number): number[] {
    return this.failures.filter((f) => f.user_id === userId && f.at > since).map((f) => f.at).sort((a, b) => b - a);
  }

  /** Stores recovery code hashes for the user. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  insertRecoveryCodes(userId: string, hashes: string[], now: number): void {
    for (const h of hashes) {
      if (!this.recovery.some((r) => r.user_id === userId && r.code_hash === h)) {
        this.recovery.push({ user_id: userId, code_hash: h, created_at: now, used_at: null });
      }
    }
  }

  /** UPDATE ... SET used_at = now WHERE user, code_hash and used_at IS NULL; true when one row changed. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  useRecoveryCode(userId: string, codeHash: string, now: number): boolean {
    const row = this.recovery.find((r) => r.user_id === userId && r.code_hash === codeHash && r.used_at === null);
    if (!row) return false;
    row.used_at = now;
    return true;
  }

  /** The user's recovery codes with used_at IS NULL. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  recoveryCodesLeft(userId: string): number {
    return this.recovery.filter((r) => r.user_id === userId && r.used_at === null).length;
  }

  /** Deletes the user's enrollment, recovery codes and failures. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  deleteAll(userId: string): void {
    this.enrollments.delete(userId);
    this.recovery = this.recovery.filter((r) => r.user_id !== userId);
    this.failures = this.failures.filter((f) => f.user_id !== userId);
  }
}

/* ------------------------------------------------------------------ service */

/** The injected configuration (spec CONFIGURATION). */
export interface TotpOptions {
  encryptionKey: Uint8Array;
  recoveryHashKey: Uint8Array;
  issuer: string;
  store?: TotpStore;
  /** Whole seconds since the epoch. */
  clock?: () => number;
  /** n random bytes; default the system CSPRNG. */
  randomBytes?: (n: number) => Buffer;
}

/** verify's success answer. */
export interface VerifyOk {
  ok: true;
  method: 'totp' | 'recovery_code';
  recovery_codes_left: number;
}

/** The internal outcome of verify's steps 1-5, shared by verify and disable. */
type CheckOutcome = { ok: true; method: 'totp' | 'recovery_code' } | TotpRefusal;

/**
 * TOTP two-factor service. Construction fails closed (TotpError "invalid_key") when encryption_key is not exactly
 * 32 bytes or recovery_hash_key is under 32 bytes. Every flow answers with a returned value, never an exception, and
 * never returns or logs a secret, a code or a key except where the spec says (enroll_start's secret, enroll_confirm's
 * recovery codes). Why: spec FLOWS (TOTP-03..14). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the injected store; the clock; the random source.
 */
export class TotpTwoFactor {
  readonly store: TotpStore;
  private readonly encryptionKey: Buffer;
  private readonly recoveryHashKey: Buffer;
  private readonly issuer: string;
  private readonly clock: () => number;
  private readonly randomBytes: (n: number) => Buffer;

  /**
   * In: TotpOptions. Out: the service. Throws TotpError("invalid_key") for a key of the wrong size (TOTP-11).
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  constructor(options: TotpOptions) {
    if (!options || !options.encryptionKey || options.encryptionKey.length !== 32) throw new TotpError('invalid_key');
    if (!options.recoveryHashKey || options.recoveryHashKey.length < 32) throw new TotpError('invalid_key');
    this.encryptionKey = Buffer.from(options.encryptionKey);
    this.recoveryHashKey = Buffer.from(options.recoveryHashKey);
    this.issuer = options.issuer;
    this.store = options.store ?? new InMemoryTotpStore();
    this.clock = options.clock ?? (() => Math.floor(Date.now() / 1000));
    this.randomBytes = options.randomBytes ?? cryptoRandomBytes;
  }

  /** The aad that binds a sealed secret to its user: "totp:" + user_id. Touches nothing. */
  private aad(userId: string): string {
    return 'totp:' + userId;
  }

  /**
   * Starts (or restarts, while unconfirmed) an enrollment: a new secret sealed under encryption_key, stored with
   * confirmed_at null. In: the verified user id, the account label. Out: {secret, otpauth_uri} or 409
   * already_enrolled. Why: spec enroll_start (TOTP-03). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: the store, the random source, the clock.
   */
  enrollStart(userId: string, accountLabel: string): { secret: string; otpauth_uri: string } | TotpRefusal {
    const existing = this.store.getEnrollment(userId);
    if (existing && existing.confirmed_at !== null) return { error: 'already_enrolled', status: 409 };
    const secret = generateSecret(this.randomBytes);
    const nonce = this.randomBytes(12);
    const row: EnrollmentRow = {
      user_id: userId,
      secret_enc: seal(this.encryptionKey, nonce, secret, this.aad(userId)),
      confirmed_at: null,
      last_used_step: 0,
      failed_since_success: 0,
      created_at: this.clock(),
    };
    if (!this.store.putUnconfirmed(row)) return { error: 'already_enrolled', status: 409 };
    return { secret, otpauth_uri: otpauthUri(secret, this.issuer, accountLabel) };
  }

  /**
   * Confirms an enrollment with the current code and makes the 8 recovery codes (shown only here; only their keyed
   * hashes are stored). In: user id, code. Out: {recovery_codes} or 409 enrollment_not_started / already_enrolled,
   * 429 locked, 401 invalid_code, 503 secret_unreadable. Why: spec enroll_confirm (TOTP-04). 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the random source, the clock.
   */
  enrollConfirm(userId: string, code: unknown): { recovery_codes: string[] } | TotpRefusal {
    const row = this.store.getEnrollment(userId);
    if (!row) return { error: 'enrollment_not_started', status: 409 };
    if (row.confirmed_at !== null) return { error: 'already_enrolled', status: 409 };
    const now = this.clock();
    const slot = this.store.tryInsert(userId, now);
    if (slot === null) return this.lockedAnswer(userId, now);
    const input = totpInput(code);
    if (input === null) return this.failure(userId);
    const secret = open(this.encryptionKey, row.secret_enc, this.aad(userId));
    if (secret === null) return this.release(slot, { error: 'secret_unreadable', status: 503 });
    const step = this.match(secret, input, now);
    if (step === null) return this.failure(userId);
    if (!this.store.confirm(userId, now, step, row.secret_enc)) {
      const cur = this.store.getEnrollment(userId);
      if (cur && cur.confirmed_at !== null) return this.release(slot, { error: 'already_enrolled', status: 409 });
      return this.failure(userId);
    }
    const codes = this.makeRecoveryCodes();
    this.store.insertRecoveryCodes(userId, codes.map((c) => this.recoveryHash(userId, recoveryInput(c)!)), now);
    this.store.deleteTry(slot);
    return { recovery_codes: codes };
  }

  /**
   * Verifies a second-factor code: a 6-digit TOTP code or a recovery code. In: user id, code (any value; a missing
   * or non-text code is 401 invalid_code). Out: {ok: true, method, recovery_codes_left} or 409 not_enrolled, 429
   * locked (with retry_after), 429 recovery_required, 503 secret_unreadable, 401 invalid_code. Why: spec verify
   * (TOTP-05..10, 13, 14). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the clock.
   */
  verify(userId: string, code: unknown): VerifyOk | TotpRefusal {
    const out = this.check(userId, code);
    if (!('ok' in out)) return out;
    return { ok: true, method: out.method, recovery_codes_left: this.store.recoveryCodesLeft(userId) };
  }

  /**
   * Turns 2FA off: steps 1-5 of verify with the same answers; on ok the user's enrollment, recovery codes and
   * failures are deleted. In: user id, code. Out: {disabled: true} or verify's refusals. Why: spec disable (TOTP-12).
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the clock.
   */
  disable(userId: string, code: unknown): { disabled: true } | TotpRefusal {
    const out = this.check(userId, code);
    if (!('ok' in out)) return out;
    this.store.deleteAll(userId);
    return { disabled: true };
  }

  /**
   * Reads the user's 2FA state without changing anything. In: user id. Out: {enrolled, locked_until,
   * recovery_required, recovery_codes_left}. Why: spec status (auth_system's mfa_enabled_check). 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store (read), the clock.
   */
  status(userId: string): { enrolled: boolean; locked_until: number | null; recovery_required: boolean; recovery_codes_left: number } {
    const row = this.store.getEnrollment(userId);
    const enrolled = !!row && row.confirmed_at !== null;
    const now = this.clock();
    const recent = this.store.failuresSince(userId, now - LOCK_SECONDS);
    return {
      enrolled,
      locked_until: recent.length >= LOCK_FAILURES ? recent[LOCK_FAILURES - 1] + LOCK_SECONDS : null,
      recovery_required: enrolled && row!.failed_since_success >= HARD_LOCK_FAILURES,
      recovery_codes_left: this.store.recoveryCodesLeft(userId),
    };
  }

  /**
   * verify's steps 1-5 (shared with disable). In: user id, code. Out: {ok, method} or a refusal. Each answer that
   * is not a FAILURE gives this call's slot back. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: the store, the clock.
   */
  private check(userId: string, code: unknown): CheckOutcome {
    const row = this.store.getEnrollment(userId);
    if (!row || row.confirmed_at === null) return { error: 'not_enrolled', status: 409 };
    const now = this.clock();
    const slot = this.store.tryInsert(userId, now);
    if (slot === null) return this.lockedAnswer(userId, now);
    const totp = totpInput(code);
    if (totp !== null) {
      if (row.failed_since_success >= HARD_LOCK_FAILURES) return this.release(slot, { error: 'recovery_required', status: 429 });
      const secret = open(this.encryptionKey, row.secret_enc, this.aad(userId));
      if (secret === null) return this.release(slot, { error: 'secret_unreadable', status: 503 });
      const step = this.match(secret, totp, now);
      if (step === null || step <= row.last_used_step) return this.failure(userId);
      if (!this.store.claimStep(userId, step)) return this.failure(userId);
      this.store.deleteTry(slot);
      return { ok: true, method: 'totp' };
    }
    const recovery = recoveryInput(code);
    if (recovery !== null) {
      if (this.store.useRecoveryCode(userId, this.recoveryHash(userId, recovery), now)) {
        this.store.resetFailures(userId);
        this.store.deleteTry(slot);
        return { ok: true, method: 'recovery_code' };
      }
      return this.failure(userId);
    }
    return this.failure(userId);
  }

  /**
   * MATCH: compares the input with hotp at steps s-1, s, s+1 (skipping negative steps), ALL in constant time with
   * no early exit, and returns the LARGEST step that was equal, or null. In: base32 secret, 6-digit input, now.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  private match(secret: string, input: string, now: number): number | null {
    let key: Buffer;
    try {
      key = base32Decode(secret);
    } catch {
      return null;
    }
    const s = Math.floor(now / STEP);
    const given = Buffer.from(input, 'ascii');
    let found: number | null = null;
    for (let d = -WINDOW; d <= WINDOW; d++) {
      if (s + d < 0) continue;
      const equal = timingSafeEqual(Buffer.from(hotp(key, s + d), 'ascii'), given);
      if (equal) found = s + d;
    }
    return found;
  }

  /**
   * FAILURE: the slot row stays as the failure and failed_since_success goes up by one. Out: 401 invalid_code.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
   */
  private failure(userId: string): TotpRefusal {
    this.store.addFailure(userId);
    return { error: 'invalid_code', status: 401 };
  }

  /** Gives this call's slot back and returns the answer. Touches: the store. */
  private release<T>(slot: number, answer: T): T {
    this.store.deleteTry(slot);
    return answer;
  }

  /**
   * 429 locked with retry_after = (the at of the 5th most recent failure in the window) + 900 - now.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store (read).
   */
  private lockedAnswer(userId: string, now: number): TotpRefusal {
    const recent = this.store.failuresSince(userId, now - LOCK_SECONDS);
    const fifth = recent[Math.min(LOCK_FAILURES, recent.length) - 1] ?? now;
    return { error: 'locked', status: 429, retry_after: fifth + LOCK_SECONDS - now };
  }

  /**
   * code_hash = lower-case hex HMAC-SHA256(recovery_hash_key, "recovery:" + user_id + ":" + RECOVERY INPUT form).
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  recoveryHash(userId: string, normalized: string): string {
    return createHmac('sha256', this.recoveryHashKey).update('recovery:' + userId + ':' + normalized, 'utf8').digest('hex');
  }

  /**
   * 8 distinct recovery codes, xxxx-xxxx-xxxx: symbols drawn one byte at a time (random_bytes(1) each), b >= 240
   * drawn again, else alphabet[b mod 30]; a code equal to an earlier one of the set is dropped and drawn again.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the random source.
   */
  private makeRecoveryCodes(): string[] {
    const codes: string[] = [];
    while (codes.length < RECOVERY_CODES) {
      let symbols = '';
      while (symbols.length < 12) {
        const b = this.randomBytes(1)[0];
        if (b >= 240) continue;
        symbols += RECOVERY_ALPHABET[b % 30];
      }
      const code = `${symbols.slice(0, 4)}-${symbols.slice(4, 8)}-${symbols.slice(8, 12)}`;
      if (!codes.includes(code)) codes.push(code);
    }
    return codes;
  }
}

/**
 * TOTP INPUT: a text of at most 64 characters which, without its ASCII spaces and "-", is exactly 6 characters 0-9.
 * In: any value. Out: the 6 digits, or null. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export function totpInput(code: unknown): string | null {
  if (typeof code !== 'string' || code.length > MAX_INPUT_LENGTH) return null;
  const c = code.replace(/[ -]/g, '');
  return /^[0-9]{6}$/.test(c) ? c : null;
}

/**
 * RECOVERY INPUT: a text of at most 64 characters which, with A-Z mapped to a-z and its ASCII spaces and "-"
 * removed, is exactly 12 characters of the recovery alphabet. In: any value. Out: the 12 symbols, or null.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export function recoveryInput(code: unknown): string | null {
  if (typeof code !== 'string' || code.length > MAX_INPUT_LENGTH) return null;
  const c = code.replace(/[A-Z]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) + 32)).replace(/[ -]/g, '');
  if (c.length !== 12) return null;
  for (const ch of c) if (!RECOVERY_ALPHABET.includes(ch)) return null;
  return c;
}

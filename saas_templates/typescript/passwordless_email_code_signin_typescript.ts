/**
 * Passwordless email code sign-in (docs/specs/passwordless_email_code_signin.md): sign in, and sign up, with a
 * 6-digit code sent by email. One code per address at a time, valid 600 seconds, usable once, 5 tries; limits per
 * address and per IP; the same answer whether or not the address has an account. The code, the address and the IP
 * are stored only as HMAC-SHA256 under the server's secret (accounts.email is the one clear copy of an address).
 *
 * Exports: SigninError (construction failure), normalizeEmail, the SigninStore interface with InMemorySigninStore,
 * and EmailCodeSignin (start, verify, and the hash helpers the spec names).
 *
 * Why: Phase D wave 1, owner request 2026-11-10 (six new systems). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the injected store (process memory for the in-memory one), the injected email sender (the network for a
 * real one; tests pass a fake) and the injected revoke_unproven callback. No files, no money.
 */
import { createHmac, randomBytes as cryptoRandomBytes, timingSafeEqual } from 'crypto';

export const CODE_TTL = 600;
export const CODE_ATTEMPTS = 5;
export const START_PER_EMAIL_HOUR = 5;
export const START_PER_EMAIL_DAY = 10;
export const START_PER_IP_HOUR = 20;
export const VERIFY_PER_IP_HOUR = 30;
export const VERIFY_PER_EMAIL_HOUR = 10;
const ZEROS = '0'.repeat(64);

/** A refusal: the spec error code and the HTTP status a route serves it with. */
export interface SigninRefusal {
  error: string;
  status: number;
}

/**
 * Thrown by the EmailCodeSignin constructor: code "not_configured" (a secret under 32 bytes, or no sender). The
 * message never holds the secret. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export class SigninError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = 'SigninError';
  }
}

/** An accounts row (spec SCHEMA). */
export interface AccountRow {
  id: string;
  email: string;
  email_verified_at: number | null;
  status: 'active' | 'suspended' | 'closed';
  created_at: number;
}

/** An email_codes row (spec SCHEMA). */
export interface CodeRow {
  email_hash: string;
  code_hash: string;
  expires_at: number;
  attempts: number;
  created_at: number;
}

/**
 * The storage contract (spec SCHEMA). Each method is one atomic statement (or a transaction that locks the row),
 * never a read followed by a write. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the backing store.
 */
export interface SigninStore {
  /** BUMP: inserts (key, window_start, 1) or adds 1; returns the count after it. */
  bump(key: string, windowStart: number): number;
  /** Writes the address's code row, replacing an earlier one. */
  putCode(row: CodeRow): void;
  /** DELETE ... WHERE email_hash = h AND code_hash = c; true when one row was deleted. */
  deleteCodeIf(emailHash: string, codeHash: string): boolean;
  /** UPDATE ... SET attempts = attempts + 1 WHERE email_hash = h AND attempts < 5 AND expires_at > now, returning
   *  the stored code_hash and the new attempts; null when no row changed. */
  countTry(emailHash: string, now: number): { code_hash: string; attempts: number } | null;
  /** Deletes the address's row when it is expired at now or used up (attempts >= 5). */
  deleteDeadCode(emailHash: string, now: number): void;
  /** Deletes the address's row whatever it holds. */
  deleteCode(emailHash: string): void;
  /** The account with this email, or undefined. */
  findAccountByEmail(email: string): AccountRow | undefined;
  /** Inserts the account unless a row with its email exists. */
  insertAccountIfAbsent(row: AccountRow): void;
  /** Sets email_verified_at = now for the account. */
  markVerified(accountId: string, now: number): void;
}

/**
 * In-memory SigninStore. Each method runs to completion (atomic). Public fields are for tests to read what is
 * stored; accountReads counts account lookups (start must never read accounts). 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
 */
export class InMemorySigninStore implements SigninStore {
  codes = new Map<string, CodeRow>();
  windows = new Map<string, { key: string; window_start: number; count: number }>();
  accounts = new Map<string, AccountRow>();
  accountReads = 0;

  /** BUMP: inserts (key, window_start, 1) or adds 1; returns the count after it. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  bump(key: string, windowStart: number): number {
    const k = JSON.stringify([key, windowStart]);
    const row = this.windows.get(k) ?? { key, window_start: windowStart, count: 0 };
    row.count += 1;
    this.windows.set(k, row);
    return row.count;
  }

  /** Writes the address's code row, replacing an earlier one. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  putCode(row: CodeRow): void {
    this.codes.set(row.email_hash, { ...row });
  }

  /** DELETE ... WHERE email_hash = h AND code_hash = c; true when one row was deleted. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  deleteCodeIf(emailHash: string, codeHash: string): boolean {
    const row = this.codes.get(emailHash);
    if (!row || row.code_hash !== codeHash) return false;
    this.codes.delete(emailHash);
    return true;
  }

  /** UPDATE ... SET attempts = attempts + 1 WHERE email_hash = h AND attempts < 5 AND expires_at > now, returning the stored code_hash and the new attempts; null when no row changed. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  countTry(emailHash: string, now: number): { code_hash: string; attempts: number } | null {
    const row = this.codes.get(emailHash);
    if (!row || row.attempts >= CODE_ATTEMPTS || !(row.expires_at > now)) return null;
    row.attempts += 1;
    return { code_hash: row.code_hash, attempts: row.attempts };
  }

  /** Deletes the address's row when it is expired at now or used up (attempts >= 5). In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  deleteDeadCode(emailHash: string, now: number): void {
    const row = this.codes.get(emailHash);
    if (row && (row.expires_at <= now || row.attempts >= CODE_ATTEMPTS)) this.codes.delete(emailHash);
  }

  /** Deletes the address's row whatever it holds. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  deleteCode(emailHash: string): void {
    this.codes.delete(emailHash);
  }

  /** The account with this email, or undefined. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  findAccountByEmail(email: string): AccountRow | undefined {
    this.accountReads++;
    const row = [...this.accounts.values()].find((a) => a.email === email);
    return row ? { ...row } : undefined;
  }

  /** Inserts the account unless a row with its email exists. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  insertAccountIfAbsent(row: AccountRow): void {
    if ([...this.accounts.values()].some((a) => a.email === row.email)) return;
    this.accounts.set(row.id, { ...row });
  }

  /** Sets email_verified_at = now for the account. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  markVerified(accountId: string, now: number): void {
    const row = this.accounts.get(accountId);
    if (row) row.email_verified_at = now;
  }
}

/**
 * normalize_email: removes leading and trailing space, tab, CR and LF, maps A-Z to a-z (nothing else), and accepts
 * 3 to 254 characters that WHOLLY match [a-z0-9][a-z0-9._%+=-]*@[a-z0-9-]+(\.[a-z0-9-]+)+.
 * In: any value. Out: the address, or null. Why: spec HELPERS (EMAILCODE-11). 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export function normalizeEmail(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const ws = (c: string) => c === ' ' || c === '\t' || c === '\r' || c === '\n';
  let a = 0;
  let b = raw.length;
  while (a < b && ws(raw[a])) a++;
  while (b > a && ws(raw[b - 1])) b--;
  const e = raw.slice(a, b).replace(/[A-Z]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) + 32));
  if (e.length < 3 || e.length > 254) return null;
  return /^[a-z0-9][a-z0-9._%+=-]*@[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(e) ? e : null;
}

/** The email sender: send_code(to, code, expires_in_seconds) -> true | false, or it raises. */
export interface CodeSender {
  sendCode(to: string, code: string, expiresInSeconds: number): boolean | Promise<boolean>;
}

/** The injected configuration (spec CONFIGURATION). */
export interface SigninOptions {
  secret: Uint8Array | string;
  sender: CodeSender;
  revokeUnproven?: (accountId: string) => void | Promise<void>;
  store?: SigninStore;
  /** Whole seconds since the epoch. */
  clock?: () => number;
  /** n random bytes; default the system CSPRNG. */
  randomBytes?: (n: number) => Buffer;
  /** Overrides the CODE generator (tests inject a known code). */
  generateCode?: () => string;
}

/**
 * The sign-in service. Construction fails closed (SigninError "not_configured") without a 32-byte secret or a
 * sender. Every flow answers with a returned value, never an exception, and never logs the code, the address or the
 * secret. Why: spec ENDPOINTS (EMAILCODE-01..14). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the store, the sender, revoke_unproven, the clock, the random source.
 */
export class EmailCodeSignin {
  readonly store: SigninStore;
  private readonly secret: Buffer;
  private readonly sender: CodeSender;
  private readonly revokeUnproven: (accountId: string) => void | Promise<void>;
  private readonly clock: () => number;
  private readonly randomBytes: (n: number) => Buffer;
  private readonly makeCode: () => string;

  /**
   * In: SigninOptions. Out: the service. Throws SigninError("not_configured") (EMAILCODE-12). 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  constructor(options: SigninOptions) {
    const secret = options && options.secret !== undefined && options.secret !== null
      ? (typeof options.secret === 'string' ? Buffer.from(options.secret, 'utf8') : Buffer.from(options.secret)) : Buffer.alloc(0);
    if (secret.length < 32 || !options.sender || typeof options.sender.sendCode !== 'function') throw new SigninError('not_configured');
    this.secret = secret;
    this.sender = options.sender;
    this.revokeUnproven = options.revokeUnproven ?? (() => undefined);
    this.store = options.store ?? new InMemorySigninStore();
    this.clock = options.clock ?? (() => Math.floor(Date.now() / 1000));
    this.randomBytes = options.randomBytes ?? cryptoRandomBytes;
    this.makeCode = options.generateCode ?? (() => this.generateCode());
  }

  /** hmac_hex(text): lower-case hex HMAC-SHA256(secret, UTF-8 of text). Touches nothing. */
  hmacHex(text: string): string {
    return createHmac('sha256', this.secret).update(text, 'utf8').digest('hex');
  }

  /** email_hash(email) = hmac_hex("email:" + email). Touches nothing. */
  emailHash(email: string): string {
    return this.hmacHex('email:' + email);
  }

  /** code_hash(email, code) = hmac_hex("code:" + email_hash(email) + ":" + code). Touches nothing. */
  codeHash(email: string, code: string): string {
    return this.hmacHex('code:' + this.emailHash(email) + ':' + code);
  }

  /** ip_hash(ip) = the first 32 characters of hmac_hex("ip:" + ip). Touches nothing. */
  ipHash(ip: string): string {
    return this.hmacHex('ip:' + ip).slice(0, 32);
  }

  /** EK(email) = the first 32 characters of email_hash(email). Touches nothing. */
  private ek(email: string): string {
    return this.emailHash(email).slice(0, 32);
  }

  /** BUMP(key, span): one atomic count in the clock window of span seconds. Out: the count after it. */
  private bump(key: string, span: number, now: number): number {
    return this.store.bump(key, now - (now % span));
  }

  /**
   * CODE: n = random_bytes(4) as an UNSIGNED big-endian 32-bit number; n >= 4294000000 is drawn again; the code is
   * n mod 1000000 with 6 digits, leading zeros kept (every code equally likely). Out: the code. Why: spec CODE
   * (EMAILCODE-14). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the random source.
   */
  generateCode(): string {
    for (;;) {
      const n = this.randomBytes(4).readUInt32BE(0);
      if (n >= 4294000000) continue;
      return String(n % 1000000).padStart(6, '0');
    }
  }

  /**
   * Sends a sign-in code. Steps: invalid address 422 invalid_email; 20 starts per IP per hour, 5 per address per
   * hour and 10 per address per day (both address counts always bumped) 429 too_many_requests; the code row is
   * written, replacing an earlier one; a sender that returns false or raises removes that code (only it) and answers
   * 503 send_failed. Never reads accounts. In: the address, the client IP (missing: "unknown"). Out: {status: 202,
   * sent: true, expires_in: 600} or a refusal. Why: spec start. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: the store, the sender (network for a real one), the clock, the random source.
   */
  async start(email: unknown, ip?: string | null): Promise<{ status: 202; sent: true; expires_in: number } | SigninRefusal> {
    const e = normalizeEmail(email);
    if (e === null) return { error: 'invalid_email', status: 422 };
    const now = this.clock();
    const clientIp = typeof ip === 'string' && ip !== '' ? ip : 'unknown';
    if (this.bump('start-ip#' + this.ipHash(clientIp), 3600, now) > START_PER_IP_HOUR) return { error: 'too_many_requests', status: 429 };
    const h = this.bump('start-email#' + this.ek(e), 3600, now);
    const d = this.bump('start-email-day#' + this.ek(e), 86400, now);
    if (h > START_PER_EMAIL_HOUR || d > START_PER_EMAIL_DAY) return { error: 'too_many_requests', status: 429 };
    const code = this.makeCode();
    const emailHash = this.emailHash(e);
    const codeHash = this.codeHash(e, code);
    this.store.putCode({ email_hash: emailHash, code_hash: codeHash, expires_at: now + CODE_TTL, attempts: 0, created_at: now });
    let sent = false;
    try {
      sent = (await this.sender.sendCode(e, code, CODE_TTL)) === true;
    } catch {
      sent = false;
    }
    if (!sent) {
      this.store.deleteCodeIf(emailHash, codeHash);
      return { error: 'send_failed', status: 503 };
    }
    return { status: 202, sent: true, expires_in: CODE_TTL };
  }

  /**
   * Checks a code and signs in (or up). Steps: 30 verifies per IP per hour 429; malformed address or code 400
   * invalid_code (spends no try); 10 verifies per address per hour 429; the try counted first by one conditional
   * write (none: dead row removed, a dummy constant-time compare, 400); a wrong code 400 (the row deleted at its 5th
   * try); the code used up by a conditional delete (lost race 400); the account found or made (an existing
   * unverified row is passed to revoke_unproven before it is verified; a raise is 500 processing_failed); a
   * suspended or closed account 403 account_unavailable. In: address, code, client IP. Out: {status: 200,
   * account_id, email, new_account} or a refusal. Why: spec verify. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: the store, revoke_unproven, the clock, the random source.
   */
  async verify(email: unknown, code: unknown, ip?: string | null):
      Promise<{ status: 200; account_id: string; email: string; new_account: boolean } | SigninRefusal> {
    const now = this.clock();
    const clientIp = typeof ip === 'string' && ip !== '' ? ip : 'unknown';
    const invalid: SigninRefusal = { error: 'invalid_code', status: 400 };
    if (this.bump('verify-ip#' + this.ipHash(clientIp), 3600, now) > VERIFY_PER_IP_HOUR) return { error: 'too_many_requests', status: 429 };
    const e = normalizeEmail(email);
    const c = typeof code === 'string' ? code.replace(/[ -]/g, '') : '';
    if (e === null || !/^[0-9]{6}$/.test(c)) return invalid;
    if (this.bump('verify-email#' + this.ek(e), 3600, now) > VERIFY_PER_EMAIL_HOUR) return { error: 'too_many_requests', status: 429 };
    const emailHash = this.emailHash(e);
    const given = this.codeHash(e, c);
    const counted = this.store.countTry(emailHash, now);
    if (counted === null) {
      this.store.deleteDeadCode(emailHash, now);
      timingSafeEqual(Buffer.from(given, 'utf8'), Buffer.from(ZEROS, 'utf8'));
      return invalid;
    }
    const stored = Buffer.from(String(counted.code_hash), 'utf8');
    const same = stored.length === 64 && timingSafeEqual(Buffer.from(given, 'utf8'), stored);
    if (!same) {
      if (counted.attempts >= CODE_ATTEMPTS) this.store.deleteCodeIf(emailHash, counted.code_hash);
      return invalid;
    }
    if (!this.store.deleteCodeIf(emailHash, counted.code_hash)) return invalid;
    const id = this.randomBytes(16).toString('hex');
    this.store.insertAccountIfAbsent({ id, email: e, email_verified_at: now, status: 'active', created_at: now });
    const account = this.store.findAccountByEmail(e);
    if (!account) return { error: 'processing_failed', status: 500 };
    const newAccount = account.id === id;
    if (account.email_verified_at === null) {
      try {
        await this.revokeUnproven(account.id);
      } catch {
        return { error: 'processing_failed', status: 500 };
      }
      this.store.markVerified(account.id, now);
    }
    if (account.status !== 'active') return { error: 'account_unavailable', status: 403 };
    return { status: 200, account_id: account.id, email: e, new_account: newAccount };
  }
}

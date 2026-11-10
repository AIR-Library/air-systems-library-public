import bcrypt from 'bcrypt';
import speakeasy from 'speakeasy';
import jwt from 'jsonwebtoken';
import { createHmac, randomBytes, randomInt, timingSafeEqual } from 'crypto';

/**
 * The schema this module expects (PostgreSQL). Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-16 and the
 * spec's "Secrets at rest" line, Phase B.2): sessions keep only refresh_token_hash (SHA-256 hex) and their own id;
 * verification_codes keep only code_hash; oauth_states (new) keep only state_hash; oauth_links is declared (it was
 * used but never created); the sessions column typo "INET ip" is fixed. The ALTERs move older tables over: a stored
 * plaintext refresh token or code is dropped (those sessions and codes stop working; users sign in or ask for a code
 * again), because a database read must not hand out a usable credential. Exported so a deployment can run it.
 * Touches nothing by itself.
 */
export const AUTH_DDL = `
-- Users table
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  name VARCHAR(255),
  password_hash VARCHAR(255),
  tier VARCHAR(50) DEFAULT 'free',
  status VARCHAR(20) DEFAULT 'unverified',
  email_verified_at TIMESTAMP WITH TIME ZONE,
  mfa_secret VARCHAR(255),
  mfa_enabled BOOLEAN DEFAULT FALSE
);

-- Sessions table: the refresh token is stored only as its SHA-256 (hex).
CREATE TABLE IF NOT EXISTS sessions (
  id VARCHAR(64) PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  refresh_token_hash CHAR(64) UNIQUE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  ip INET,
  device_id VARCHAR(255)
);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS refresh_token_hash CHAR(64);
ALTER TABLE sessions DROP COLUMN IF EXISTS refresh_token;

-- Audit log table
CREATE TABLE IF NOT EXISTS audit_log (
  id SERIAL PRIMARY KEY,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  actor_id INTEGER REFERENCES users(id),
  action VARCHAR(255) NOT NULL,
  resource_type VARCHAR(255),
  resource_id VARCHAR(255),
  old_value JSONB,
  new_value JSONB
);

-- Verification codes table
CREATE TABLE IF NOT EXISTS verification_codes (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  code_hash CHAR(64) NOT NULL,                -- SHA-256 hex of the emailed code or the MFA challenge id
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  type VARCHAR(10) CHECK (type IN ('email', 'mfa')) NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0
);
-- Tables made before 2026-11-08 lack the MFA attempt count.
ALTER TABLE verification_codes ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE verification_codes ADD COLUMN IF NOT EXISTS code_hash CHAR(64);
ALTER TABLE verification_codes DROP COLUMN IF EXISTS code;

-- OAuth links: the provider's own user id, never the one-time authorization code.
CREATE TABLE IF NOT EXISTS oauth_links (
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  provider VARCHAR(50) NOT NULL,
  provider_user_id VARCHAR(255) NOT NULL,
  PRIMARY KEY (provider, provider_user_id)
);

-- OAuth state values, stored only as their SHA-256: single-use, 10 minutes, bound to the provider.
CREATE TABLE IF NOT EXISTS oauth_states (
  state_hash CHAR(64) PRIMARY KEY,
  provider VARCHAR(50) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  used_at TIMESTAMP WITH TIME ZONE
);
`;

interface Db {
  query: (text: string, params?: any[]) => Promise<any[]>;
  execute: (text: string, params?: any[]) => Promise<{ affectedRows: number; insertId: number }>;
}

interface EmailSender {
  sendVerificationEmail: (email: string, code: string) => Promise<void>;
}

interface Logger {
  info: (message: string, meta?: any) => void;
  error: (message: string, meta?: any) => void;
}

interface RateLimiter {
  check: (key: string) => boolean;
}

/**
 * What an OAuth provider says about the person after the authorization code is exchanged.
 * provider_user_id is the provider's own stable id for the person. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 */
export interface OAuthIdentity {
  provider_user_id: string;
  email: string;
  email_verified: boolean;
}

/**
 * The injected OAuth provider client: exchanges a provider's authorization code for the person's identity (in
 * production a call to the provider's token and userinfo endpoints; tests pass a fake). Returns null when the provider
 * refuses the code. Why: AUTH spec "the callback exchanges the provider's code through an injected provider client
 * (never uses the code itself as an identity)" (Phase B.2, 2026-11-10); the callback used to invent the email from the
 * provider name and store the code as the provider user id. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the network (the provider), in production.
 */
export interface OAuthProviderClient {
  exchangeCode: (provider: string, code: string) => Promise<OAuthIdentity | null>;
}

/**
 * Every refusal: the spec's error code, a human-readable message and the HTTP status the route answers with.
 * Why: typescript bug list (Phase B.2, 2026-11-10): auth errors carried no HTTP status. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP.
 */
export interface AuthError {
  error: string;
  message: string;
  http_status: number;
  reason?: string;
}

/**
 * The HTTP status and message of each error code (the AUTH table's statuses; the rest follow the same rules: a bad
 * client value 400, a failed credential 401, a refusal 403, a conflict 409, a limit 429, a server fault 500/503).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 typescript bug: no status). Touches nothing.
 */
const AUTH_ERRORS: Readonly<Record<string, [number, string]>> = {
  email_already_exists: [409, 'An account with this email already exists.'],
  password_rejected: [400, 'Choose a different password.'],
  too_many_signups_from_ip: [429, 'Too many signups from this address; try again later.'],
  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.4, af92d76): a wrong code is now code_invalid, so the two
  // messages were reworded to match (code_expired said "wrong or has expired").
  code_expired: [400, 'The code has expired; ask for a new code.'],
  code_invalid: [400, 'The code is wrong, or too many wrong codes were tried; ask for a new code.'],
  token_expired: [401, 'The token has expired.'],
  already_verified: [409, 'This email is already verified.'],
  invalid_credentials: [401, 'Email or password is wrong.'],
  too_many_login_attempts: [429, 'Too many sign-in attempts; try again later.'],
  invalid_code: [401, 'The code is wrong or the challenge has expired.'],
  invalid_token: [401, 'The token is not valid.'],
  user_banned: [403, 'This account is suspended.'],
  invalid_state: [400, 'The sign-in link is invalid, expired or already used; start again.'],
  oauth_exchange_failed: [401, 'The provider did not accept the sign-in.'],
  email_not_verified: [403, 'The provider has not verified this email.'],
  oauth_not_configured: [503, 'Sign-in with this provider is not available.'],
  internal_error: [500, 'Something went wrong.'],
};

/**
 * Builds the refusal for an error code. In: the code and optional extra fields (reason). Out: { error, message,
 * http_status, ...extra }. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 typescript bug). Touches nothing.
 */
function fail(code: string, extra: { reason?: string } = {}): AuthError {
  const [http_status, message] = AUTH_ERRORS[code] ?? [500, 'Something went wrong.'];
  return { error: code, message, http_status, ...extra };
}

/**
 * Keyed hash of a secret: HMAC-SHA256(key, value) as 64 lower-case hex characters, how refresh tokens, verification
 * codes, MFA challenge ids and OAuth states are stored (AUTH-16, "Secrets at rest"). In: the key bytes, the secret.
 * Out: 64 hex characters. Why: spec d270fa3: keyed HMAC for stored secrets (it replaced the plain SHA-256 helper
 * sha256Hex). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export function hmacSha256Hex(key: Buffer, value: string): string {
  return createHmac('sha256', key).update(String(value ?? ''), 'utf8').digest('hex');
}

/** Minimum HMAC key length in bytes (spec d270fa3). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
export const MIN_SECRET_KEY_BYTES = 32;

/**
 * The HMAC key for stored secrets: options.secretKey if given, else the AUTH_SECRET_KEY environment variable.
 * In: the configured key or undefined. Out: the key bytes. Throws when there is none or it is shorter than 32 bytes,
 * so the service refuses to start without one. Why: spec d270fa3: keyed HMAC for stored secrets. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the process environment (read only).
 */
function loadSecretKey(configured: string | Buffer | undefined): Buffer {
  const raw = configured ?? process.env.AUTH_SECRET_KEY ?? '';
  const key = Buffer.isBuffer(raw) ? raw : Buffer.from(String(raw), 'utf8');
  if (key.length < MIN_SECRET_KEY_BYTES) {
    throw new Error('AUTH_SECRET_KEY must be set and at least 32 bytes');
  }
  return key;
}

/**
 * Compares two SHA-256 hex digests in constant time; false for anything that is not 64 hex characters.
 * In: two hex strings. Out: true when equal. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH spec "compared in
 * constant time"). Touches nothing.
 */
function sameHash(a: unknown, b: unknown): boolean {
  if (typeof a !== 'string' || typeof b !== 'string' || !/^[0-9a-f]{64}$/i.test(a) || !/^[0-9a-f]{64}$/i.test(b)) {
    return false;
  }
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

/**
 * Wrong verification codes one user's current code survives (AUTH spec flow 2, Phase B.3 ruling): after 5 wrong
 * codes that code is spent and every further try, the right code included, is 400 code_invalid until a new code is
 * sent. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
const MAX_EMAIL_CODE_ATTEMPTS = 5;

/** How long an OAuth state is valid (AUTH spec: 10 minutes). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;

class AuthSystem {
  private db: Db;
  private emailSender: EmailSender;
  private logger: Logger;
  private jwtSecret: string;
  private secretKey: Buffer;
  private bcryptSaltRounds: number;
  private tokenExpiry: string;
  private refreshTokenExpiry: string;
  private signupIpLimiter: Map<string, number[]>;
  private loginLimiter: Map<string, number[]>;
  private signupWindowMs: number;
  private maxSignupsPerIP: number;
  private loginWindowMs: number;
  private maxLoginAttempts: number;
  private oauthClient: OAuthProviderClient | null;
  private now: () => Date;

  /**
   * In: the database, email sender, logger and options: jwtSecret, bcrypt rounds, token lifetimes, rate-limit
   * windows, and (added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, Phase B.2) oauthClient, the injected provider
   * client the OAuth callback exchanges codes through (none: OAuth answers 503 oauth_not_configured), and now, the
   * clock OAuth state expiry reads (default the system clock). Out: the service. Touches nothing.
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets. options.secretKey
   * (else the AUTH_SECRET_KEY environment variable) keys the HMAC-SHA256 every stored secret is kept as; the
   * constructor throws when it is missing or shorter than 32 bytes, so the service refuses to start. Touches: the
   * process environment (read only).
   */
  constructor(
    db: Db,
    emailSender: EmailSender,
    logger: Logger,
    options: {
      jwtSecret: string;
      secretKey?: string | Buffer;
      bcryptSaltRounds?: number;
      tokenExpiry?: string;
      refreshTokenExpiry?: string;
      signupWindowMs?: number;
      maxSignupsPerIP?: number;
      loginWindowMs?: number;
      maxLoginAttempts?: number;
      oauthClient?: OAuthProviderClient;
      now?: () => Date;
    } = {}
  ) {
    this.secretKey = loadSecretKey(options.secretKey);
    this.db = db;
    this.emailSender = emailSender;
    this.logger = logger;
    this.jwtSecret = options.jwtSecret;
    this.bcryptSaltRounds = options.bcryptSaltRounds ?? 12;
    this.tokenExpiry = options.tokenExpiry ?? '15m';
    this.refreshTokenExpiry = options.refreshTokenExpiry ?? '7d';
    this.signupWindowMs = options.signupWindowMs ?? 24 * 60 * 60 * 1000;
    this.maxSignupsPerIP = options.maxSignupsPerIP ?? 5;
    this.loginWindowMs = options.loginWindowMs ?? 15 * 60 * 1000;
    this.maxLoginAttempts = options.maxLoginAttempts ?? 5;
    this.signupIpLimiter = new Map();
    this.loginLimiter = new Map();
    this.oauthClient = options.oauthClient ?? null;
    this.now = options.now ?? (() => new Date());
  }

  /**
   * The stored form of a refresh token, verification code, MFA challenge id or OAuth state: lowercase hex
   * HMAC-SHA256(secretKey, value). In: the secret. Out: 64 hex characters. Why: spec d270fa3: keyed HMAC for stored
   * secrets. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  private hashSecret(value: string): string {
    return hmacSha256Hex(this.secretKey, value);
  }

  private async hashPassword(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(this.bcryptSaltRounds);
    return bcrypt.hash(password, salt);
  }

  private async comparePassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  private generateToken(userId: number, tier: string): string {
    return jwt.sign({ userId, tier }, this.jwtSecret, { expiresIn: this.tokenExpiry });
  }

  private generateRefreshToken(): string {
    return randomBytes(32).toString('hex');
  }

  /** A six digit code from the secure random source; Math.random can be predicted. 2026-11-05, session f3daac6e. */
  private generateVerificationCode(): string {
    return randomInt(100000, 1000000).toString();
  }

  private verifyTotp(secret: string, token: string): boolean {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 1
    });
  }

  private async rateLimitSignup(ip: string): Promise<boolean> {
    const now = Date.now();
    const windowStart = now - this.signupWindowMs;
    const timestamps = this.signupIpLimiter.get(ip) ?? [];
    const valid = timestamps.filter(t => t > windowStart);
    if (valid.length >= this.maxSignupsPerIP) return false;
    valid.push(now);
    this.signupIpLimiter.set(ip, valid);
    return true;
  }

  private async rateLimitLogin(ip: string, email: string): Promise<boolean> {
    const now = Date.now();
    const windowStart = now - this.loginWindowMs;
    const key = `${ip}:${email}`;
    const timestamps = this.loginLimiter.get(key) ?? [];
    const valid = timestamps.filter(t => t > windowStart);
    if (valid.length >= this.maxLoginAttempts) return false;
    valid.push(now);
    this.loginLimiter.set(key, valid);
    return true;
  }

  private async logWhyChain(flow: string, decision_points: string[]): Promise<void> {
    this.logger.info(`why_chain: flow=${flow}, decision_points=${JSON.stringify(decision_points)}`);
  }

  private async logAudit(action: string, userId: number | null, metadata: Record<string, any> = {}): Promise<void> {
    await this.db.execute(
      'INSERT INTO audit_log (actor_id, action, resource_type, resource_id, new_value) VALUES ($1, $2, $3, $4, $5)',
      [userId, action, 'auth', null, JSON.stringify(metadata)]
    );
  }

  /**
   * Bundled common passwords (lower-case), the same list as the other languages. Only entries of 15+ characters
   * can decide a rejection, because too_short runs first. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   */
  static readonly PASSWORD_BLOCKLIST: ReadonlySet<string> = new Set([
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'letmein', 'dragon', 'baseball',
    'iloveyou', 'passwordpassword', '123456789012345', '1234567890123456', 'qwertyuiopasdfgh',
    'qwertyuiopasdfghjkl', 'iloveyouiloveyou', 'letmeinletmeinletmein', 'aaaaaaaaaaaaaaa',
  ]);

  /** The service's own name, which is never accepted as a password. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
  static readonly SERVICE_NAME = 'SaasAuth';

  /**
   * The reason a password is rejected, or null when it is accepted.
   *
   * In: the password and the user's email and name. Out: 'too_short' (< 15 characters), 'too_long' (> 64),
   * 'blocklisted' (in the bundled list, or equal to the email, the name or the service name, ignoring case), or
   * null. Checks run in that order and the first failure wins; lengths count Unicode code points, not UTF-16 units.
   * Why: AUTH-03 as amended 2026-11-10 (NIST SP 800-63B-4 rules). The old blocklist held only short entries, which
   * the length check always caught first, and compared the email and name case-sensitively.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  static passwordRejection(password: string, email: string, name: string): 'too_short' | 'too_long' | 'blocklisted' | null {
    const length = Array.from(password).length;
    if (length < 15) return 'too_short';
    if (length > 64) return 'too_long';
    const lowered = password.toLowerCase();
    if (
      AuthSystem.PASSWORD_BLOCKLIST.has(lowered) ||
      lowered === (email ?? '').toLowerCase() ||
      lowered === (name ?? '').toLowerCase() ||
      lowered === AuthSystem.SERVICE_NAME.toLowerCase()
    ) {
      return 'blocklisted';
    }
    return null;
  }

  /**
   * Creates a session for a user: a random session id and a refresh token (32 random bytes, hex), of which only the
   * HMAC-SHA256 is stored (refresh_token_hash); valid 7 days. In: user id, client IP, device id. Out: the session id and
   * the raw refresh token, which only the caller sees. Why: AUTH-16 (Phase B.2, 2026-11-10): sessions stored the
   * refresh token in plain text, and the session id returned was not stored at all. 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (sessions).
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
   */
  private async createSession(userId: number, ip: string, deviceId: string): Promise<{ sessionId: string; refreshToken: string }> {
    const sessionId = randomBytes(16).toString('hex');
    const refreshToken = this.generateRefreshToken();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    await this.db.execute(
      'INSERT INTO sessions (id, user_id, refresh_token_hash, expires_at, ip, device_id) VALUES ($1, $2, $3, $4, $5, $6)',
      [sessionId, userId, this.hashSecret(refreshToken), expiresAt, ip, deviceId]
    );
    return { sessionId, refreshToken };
  }

  /**
   * Signs a user up: IP rate limit, unique email, password rules, then creates the unverified user and sends the
   * verification code.
   *
   * In: email, password, name and the request's client IP (from the server, never from the body; default
   * '0.0.0.0' keeps old callers working). Out: {status: 'pending_verification', ...} or {error, message,
   * http_status, reason?}: 429 too_many_signups_from_ip, 409 email_already_exists, 400 password_rejected.
   * Why: AUTH-01..04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: a weak password now returns
   * {error: 'password_rejected', reason} (AUTH-03 amendment; 'password_too_weak' is gone), and the IP is a
   * parameter instead of a constant, so the 5-per-24h limit is per address rather than global. Phase B.2 the same
   * day: errors carry their HTTP status, and the emailed code is stored only as its HMAC-SHA256 (code_hash, AUTH-16).
   * Touches: the database, the email sender, the audit log.
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
   */
  async signup(email: string, password: string, name: string, ip: string = '0.0.0.0'): Promise<any> {
    try {
      if (!(await this.rateLimitSignup(ip))) {
        await this.logWhyChain('signup', ['email_unique', 'password_strength', 'rate_limit_ip_24h']);
        return fail('too_many_signups_from_ip');
      }

      const existingUser = await this.db.query('SELECT id FROM users WHERE email = $1', [email]);
      if (existingUser.length > 0) {
        await this.logWhyChain('signup', ['email_unique', 'password_strength', 'rate_limit_ip_24h']);
        return fail('email_already_exists');
      }

      const rejection = AuthSystem.passwordRejection(password, email, name);
      if (rejection !== null) {
        await this.logWhyChain('signup', ['email_unique', 'password_strength', 'rate_limit_ip_24h']);
        return fail('password_rejected', { reason: rejection });
      }

      const passwordHash = await this.hashPassword(password);
      const result = await this.db.execute(
        'INSERT INTO users (email, password_hash, name) VALUES ($1, $2, $3) RETURNING id, email',
        [email, passwordHash, name]
      );
      const userId = result.insertId;
      const code = this.generateVerificationCode();
      await this.db.execute(
        'INSERT INTO verification_codes (user_id, code_hash, type, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL \'10 minutes\')',
        [userId, this.hashSecret(code), 'email']
      );
      await this.emailSender.sendVerificationEmail(email, code);
      await this.logWhyChain('signup', ['email_unique', 'password_strength', 'rate_limit_ip_24h']);
      await this.logAudit('user_created', userId, { email });
      return { status: 'pending_verification', email, message: 'check email' };
    } catch (err) {
      this.logger.error('Signup error', { err });
      return fail('internal_error');
    }
  }

  /**
   * Whether the given code is one of the user's expired email codes (HMAC compared in constant time with each).
   * In: user id, the code as given. Out: true when an expired code matches. Why: Phase B.4 ruling (af92d76): an
   * expired code is 400 code_expired and a wrong one 400 code_invalid, so verify_email must tell them apart.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (verification_codes, read only).
   */
  private async expiredCodeMatches(userId: unknown, code_or_token: string): Promise<boolean> {
    const expired = await this.db.query(
      'SELECT id, code_hash FROM verification_codes WHERE user_id = $1 AND type = \'email\' AND expires_at <= NOW()',
      [userId]
    );
    const given = this.hashSecret(code_or_token);
    let found = false;
    for (const row of expired) {
      if (sameHash(row.code_hash, given)) found = true; // every row is compared
    }
    return found;
  }

  /**
   * Verifies an email with the emailed code. In: email and code. Out: {status: 'verified', user_id, message} or
   * {error, message, http_status}: 400 code_invalid (unknown email or wrong code), 400 code_expired (expired code), 409
   * already_verified. The user's live email codes are read and each stored code_hash is compared with the HMAC-SHA256 of
   * the given code in constant time; the matching row is deleted.
   * Why: AUTH-05/06; changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, AUTH-16 and the spec's "Secrets
   * at rest" line): the code was stored and matched in plain text in SQL; errors now carry their HTTP status.
   * Touches: the database (users, verification_codes), the audit log.
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.3 ruling (auth flow 2 "Attempts"): each try is COUNTED
   * FIRST on every live code that still has tries left, with one conditional write per row (UPDATE ... SET attempts =
   * attempts + 1 WHERE id = ? AND attempts < 5), and only the rows whose write succeeded are compared. After 5 wrong
   * codes the user's current code is spent: every further try, the right code too, is 400 code_invalid until a new
   * code is sent (a new code row starts at 0 attempts). Before, a 6-digit code could be guessed by retrying.
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.4 ruling (af92d76, AUTH-17): a wrong code (and an unknown
   * email, which must not read differently) is now 400 code_invalid; it was 400 code_expired. Only a code that matches
   * one of the user's expired codes is 400 code_expired (expiredCodeMatches). Touches: the same tables.
   */
  async verify_email(email: string, code_or_token: string): Promise<any> {
    try {
      const user = await this.db.query('SELECT id, email_verified_at FROM users WHERE email = $1', [email]);
      if (user.length === 0) {
        await this.logWhyChain('verify_email', ['code_valid', 'user_unverified']);
        return fail('code_invalid'); // Phase B.4 (af92d76): was code_expired; same answer as a wrong code
      }
      if (user[0].email_verified_at !== null) {
        await this.logWhyChain('verify_email', ['code_valid', 'user_unverified']);
        return fail('already_verified');
      }

      const live = await this.db.query(
        'SELECT id, code_hash, attempts FROM verification_codes WHERE user_id = $1 AND type = \'email\' AND expires_at > NOW()',
        [user[0].id]
      );
      if (live.length === 0) {
        await this.logWhyChain('verify_email', ['code_valid', 'user_unverified']);
        // Phase B.4 (af92d76): code_expired only for an expired code that matches; anything else is code_invalid.
        return fail(await this.expiredCodeMatches(user[0].id, code_or_token) ? 'code_expired' : 'code_invalid');
      }
      // Count the try first, one conditional write per live code; a code with 5 wrong tries takes no more.
      const counted: any[] = [];
      for (const row of live) {
        const res = await this.db.execute(
          'UPDATE verification_codes SET attempts = attempts + 1 WHERE id = $1 AND attempts < $2',
          [row.id, MAX_EMAIL_CODE_ATTEMPTS]
        );
        if (res.affectedRows === 1) counted.push(row);
      }
      if (counted.length === 0) {
        await this.logWhyChain('verify_email', ['code_valid', 'user_unverified']);
        return fail('code_invalid');
      }
      const given = this.hashSecret(code_or_token);
      let match: any = null;
      for (const row of counted) {
        if (sameHash(row.code_hash, given)) match = row; // every row is compared, so the time does not say which
      }
      if (match === null) {
        await this.logWhyChain('verify_email', ['code_valid', 'user_unverified']);
        // Phase B.4 (af92d76, AUTH-17): a wrong code is code_invalid (it was code_expired).
        return fail(await this.expiredCodeMatches(user[0].id, code_or_token) ? 'code_expired' : 'code_invalid');
      }

      await this.db.execute(
        'UPDATE users SET email_verified_at = NOW() WHERE id = $1',
        [user[0].id]
      );
      await this.db.execute(
        'DELETE FROM verification_codes WHERE id = $1',
        [match.id]
      );
      await this.logWhyChain('verify_email', ['code_valid', 'user_unverified']);
      await this.logAudit('email_verified', user[0].id);
      return { status: 'verified', user_id: user[0].id, message: 'ready to login' };
    } catch (err) {
      this.logger.error('Verify email error', { err });
      return fail('internal_error');
    }
  }

  /**
   * Signs a user in. In: email, password, device id, client IP. Out: {status: 'authenticated', session_id, token,
   * refresh_token, expires_in, user}, or {status: 'mfa_required', challenge_id, http_status: 202} when MFA is on, or
   * {error, message, http_status}: 429 too_many_login_attempts, 401 invalid_credentials.
   * The MFA challenge id is stored only as its HMAC-SHA256 (code_hash); the session stores only refresh_token_hash.
   * Why: AUTH-07/08/09; changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, AUTH-16): it returned no
   * refresh_token (token_refresh could not be called), stored the refresh token and the challenge id in plain text,
   * and its errors carried no HTTP status. Touches: the database (users, verification_codes, sessions), the audit log.
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
   */
  async login(email: string, password: string, device_id: string, ip: string): Promise<any> {
    try {
      if (!(await this.rateLimitLogin(ip, email))) {
        await this.logWhyChain('login', ['user_exists', 'password_correct', 'mfa_gate', 'rate_limit']);
        return fail('too_many_login_attempts');
      }

      const user = await this.db.query('SELECT id, email, password_hash, tier, mfa_enabled, mfa_secret FROM users WHERE email = $1 AND email_verified_at IS NOT NULL', [email]);
      if (user.length === 0) {
        await this.logWhyChain('login', ['user_exists', 'password_correct', 'mfa_gate', 'rate_limit']);
        await this.logAudit('failed_login', null, { email, ip, device_id, reason: 'user_not_found_or_unverified' });
        return fail('invalid_credentials');
      }

      const passwordCorrect = await this.comparePassword(password, user[0].password_hash);
      if (!passwordCorrect) {
        await this.logWhyChain('login', ['user_exists', 'password_correct', 'mfa_gate', 'rate_limit']);
        await this.logAudit('failed_login', user[0].id, { email, ip, device_id, reason: 'wrong_password' });
        return fail('invalid_credentials');
      }

      if (user[0].mfa_enabled) {
        const challengeId = randomBytes(16).toString('hex');
        await this.db.execute(
          'INSERT INTO verification_codes (user_id, code_hash, type, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL \'10 minutes\')',
          [user[0].id, this.hashSecret(challengeId), 'mfa']
        );
        await this.logWhyChain('login', ['user_exists', 'password_correct', 'mfa_gate', 'rate_limit']);
        // The audit entry names the challenge by its hash: the raw id is what the client presents.
        await this.logAudit('mfa_challenge_initiated', user[0].id, { challenge_hash: this.hashSecret(challengeId) });
        return { status: 'mfa_required', challenge_id: challengeId, http_status: 202 };
      }

      const { sessionId, refreshToken } = await this.createSession(user[0].id, ip, device_id);
      const token = this.generateToken(user[0].id, user[0].tier);
      await this.logWhyChain('login', ['user_exists', 'password_correct', 'mfa_gate', 'rate_limit']);
      await this.logAudit('session_created', user[0].id, { session_id: sessionId, ip, device_id });
      return {
        status: 'authenticated',
        session_id: sessionId,
        token,
        refresh_token: refreshToken,
        expires_in: 900, // 15 minutes in seconds
        user: { id: user[0].id, email: user[0].email, tier: user[0].tier }
      };
    } catch (err) {
      this.logger.error('Login error', { err });
      return fail('internal_error');
    }
  }

  /**
   * Starts an OAuth sign-in: issues the state value the provider must hand back to oauth_callback. The state is 32
   * random bytes (base64url), stored only as its HMAC-SHA256, bound to the provider, single-use and valid 10 minutes.
   * In: the provider name. Out: {status: 'ok', state, expires_in: 600} or {error, message, http_status}: 503
   * oauth_not_configured when no provider client is injected.
   * Why: AUTH spec "OAuth state is single-use and expires in 10 minutes" (Phase B.2, 2026-11-10): the state was
   * never checked. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (oauth_states).
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
   */
  async oauth_start(provider: string): Promise<any> {
    try {
      if (this.oauthClient === null) return fail('oauth_not_configured');
      const state = randomBytes(32).toString('base64url');
      const created = this.now();
      await this.db.execute(
        'INSERT INTO oauth_states (state_hash, provider, created_at, expires_at) VALUES ($1, $2, $3, $4)',
        [this.hashSecret(state), provider, created, new Date(created.getTime() + OAUTH_STATE_TTL_MS)]
      );
      return { status: 'ok', state, expires_in: OAUTH_STATE_TTL_MS / 1000 };
    } catch (err) {
      this.logger.error('OAuth start error', { err });
      return fail('internal_error');
    }
  }

  /**
   * Uses up an OAuth state: true only for a state oauth_start issued for this provider, not expired and not used
   * before. One conditional UPDATE marks it used, so two callbacks with the same state cannot both pass.
   * In: provider, state. Out: true when valid. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH spec, Phase B.2).
   * Touches: the database (oauth_states).
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
   */
  private async consumeOAuthState(provider: string, state: string): Promise<boolean> {
    if (typeof state !== 'string' || state.length === 0) return false;
    const now = this.now();
    const res = await this.db.execute(
      'UPDATE oauth_states SET used_at = $1 WHERE state_hash = $2 AND provider = $3 AND used_at IS NULL AND expires_at > $1',
      [now, this.hashSecret(state), provider]
    );
    return res.affectedRows === 1;
  }

  /**
   * The OAuth callback (spec flow 4). Gates, in order: state_valid (issued by oauth_start for this provider, under
   * 10 minutes old, not used before; used up here), the code exchange through the injected provider client,
   * email_verified_by_provider. Then the account: the one already linked to this provider identity, else the one
   * with this email (Case B, linked now), else a new verified user (Case A, linked). The link stores the provider's
   * own user id, never the code. Creates a session.
   * In: provider, the provider's authorization code, the state. Out: {status: 'authenticated', session_id, token,
   * refresh_token, expires_in, user} or {error, message, http_status}: 503 oauth_not_configured, 400 invalid_state,
   * 401 oauth_exchange_failed, 403 email_not_verified.
   * Why: AUTH-10/11, AUTH-16 and the spec's "Secrets at rest" line (Phase B.2, 2026-11-10): the state was never
   * checked, the email was invented from the provider's name (so anyone could sign in as user@<provider>.com), the
   * code was stored as the provider user id, the session id was a constant and no refresh token was returned.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (oauth_states, users, oauth_links, sessions),
   * the provider client (network in production), the audit log.
   */
  async oauth_callback(provider: string, code: string, state: string): Promise<any> {
    try {
      if (this.oauthClient === null) return fail('oauth_not_configured');
      if (!(await this.consumeOAuthState(provider, state))) {
        await this.logWhyChain('oauth_callback', ['state_valid:failed']);
        return fail('invalid_state');
      }
      const identity = await this.oauthClient.exchangeCode(provider, code);
      if (!identity || typeof identity.provider_user_id !== 'string' || identity.provider_user_id === '' ||
          typeof identity.email !== 'string' || identity.email === '') {
        await this.logWhyChain('oauth_callback', ['state_valid', 'code_exchange:failed']);
        return fail('oauth_exchange_failed');
      }
      if (identity.email_verified !== true) {
        await this.logWhyChain('oauth_callback', ['state_valid', 'email_verified:failed']);
        return fail('email_not_verified');
      }

      let userId: number;
      const linked = await this.db.query(
        'SELECT user_id FROM oauth_links WHERE provider = $1 AND provider_user_id = $2',
        [provider, identity.provider_user_id]
      );
      if (linked.length > 0) {
        userId = linked[0].user_id;
      } else {
        const existingUser = await this.db.query('SELECT id, email FROM users WHERE email = $1', [identity.email]);
        if (existingUser.length === 0) {
          const result = await this.db.execute(
            'INSERT INTO users (email, status, email_verified_at) VALUES ($1, \'verified\', NOW()) RETURNING id',
            [identity.email]
          );
          userId = result.insertId;
        } else {
          userId = existingUser[0].id;
        }
        await this.db.execute(
          'INSERT INTO oauth_links (user_id, provider, provider_user_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
          [userId, provider, identity.provider_user_id]
        );
      }
      const user = await this.db.query('SELECT id, email, tier FROM users WHERE id = $1', [userId]);
      const { sessionId, refreshToken } = await this.createSession(userId, '0.0.0.0', 'oauth');
      await this.logWhyChain('oauth_callback', ['state_valid', 'email_verified']);
      await this.logAudit('oauth_login', userId, { provider, session_id: sessionId });
      const token = this.generateToken(user[0].id, user[0].tier);
      return {
        status: 'authenticated',
        session_id: sessionId,
        token,
        refresh_token: refreshToken,
        expires_in: 900,
        user: { id: user[0].id, email: user[0].email, tier: user[0].tier }
      };
    } catch (err) {
      this.logger.error('OAuth callback error', { err });
      return fail('internal_error');
    }
  }

  /**
   * Completes an MFA sign-in. In: the challenge id from login and the TOTP code. Out: {status: 'authenticated',
   * session_id, token, refresh_token, expires_in, user} or 401 {error: 'invalid_code', message, http_status}.
   * The challenge is found by the HMAC-SHA256 of its id (code_hash) and compared again in constant time; five wrong codes
   * end it; it is used up by a single DELETE, so only one caller can sign in with it.
   * Why: AUTH-12/13; changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, AUTH-16): the challenge id was
   * stored in plain text, no refresh_token was returned, and errors carried no HTTP status.
   * Touches: the database (verification_codes, users, sessions), the audit log.
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
   */
  async mfa_challenge(challenge_id: string, code: string): Promise<any> {
    try {
      const challengeHash = this.hashSecret(challenge_id);
      const challenge = await this.db.query(
        'SELECT user_id, code_hash FROM verification_codes WHERE code_hash = $1 AND type = \'mfa\' AND expires_at > NOW()',
        [challengeHash]
      );
      if (challenge.length === 0 || !sameHash(challenge[0].code_hash, challengeHash)) {
        await this.logWhyChain('mfa_challenge', ['challenge_valid', 'code_correct']);
        return fail('invalid_code');
      }

      const user = await this.db.query('SELECT mfa_secret FROM users WHERE id = $1', [challenge[0].user_id]);
      if (user.length === 0 || !user[0].mfa_secret) {
        await this.logWhyChain('mfa_challenge', ['challenge_valid', 'code_correct']);
        return fail('invalid_code');
      }

      const isValid = this.verifyTotp(user[0].mfa_secret, code);
      if (!isValid) {
        // Each wrong code counts; after five the challenge is gone and the user signs in again, so a six digit code
        // cannot be guessed (2026-11-08, session f3daac6e, from review of PR 17).
        await this.db.execute('UPDATE verification_codes SET attempts = attempts + 1 WHERE code_hash = $1', [challengeHash]);
        await this.db.execute('DELETE FROM verification_codes WHERE code_hash = $1 AND attempts >= $2', [challengeHash, 5]);
        await this.logWhyChain('mfa_challenge', ['challenge_valid', 'code_correct']);
        await this.logAudit('mfa_failed', challenge[0].user_id);
        return fail('invalid_code');
      }

      // Use the challenge up. Only the call that deletes it may sign in, so two at once cannot both get a session
      // (2026-11-08, session f3daac6e, from review).
      const consumed = await this.db.execute(
        'DELETE FROM verification_codes WHERE code_hash = $1',
        [challengeHash]
      );
      if (consumed.affectedRows !== 1) {
        await this.logWhyChain('mfa_challenge', ['challenge_valid', 'code_correct']);
        return fail('invalid_code');
      }
      const { sessionId, refreshToken } = await this.createSession(challenge[0].user_id, '0.0.0.0', 'unknown');
      const userDetails = await this.db.query('SELECT id, email, tier FROM users WHERE id = $1', [challenge[0].user_id]);
      const token = this.generateToken(challenge[0].user_id, userDetails[0].tier);
      await this.logWhyChain('mfa_challenge', ['challenge_valid', 'code_correct']);
      await this.logAudit('mfa_verified', challenge[0].user_id);
      return {
        status: 'authenticated',
        session_id: sessionId,
        token,
        refresh_token: refreshToken,
        expires_in: 900,
        user: { id: userDetails[0].id, email: userDetails[0].email, tier: userDetails[0].tier }
      };
    } catch (err) {
      this.logger.error('MFA challenge error', { err });
      return fail('internal_error');
    }
  }

  /**
   * Issues a new access token for a refresh token. In: the refresh_token a session-creating flow returned. Out:
   * {status: 'ok', token, expires_in} or {error, message, http_status}: 401 invalid_token (unknown or expired),
   * 403 user_banned (status suspended or banned). The session is found by the token's HMAC-SHA256 (refresh_token_hash)
   * and the stored hash is compared again in constant time.
   * Why: AUTH-14/15; changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, AUTH-16): it looked the token up
   * in plain text, and errors carried no HTTP status. Touches: the database (sessions, users), the audit log.
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
   */
  async token_refresh(refresh_token: string): Promise<any> {
    try {
      const tokenHash = this.hashSecret(refresh_token);
      const session = await this.db.query(
        'SELECT s.user_id, s.refresh_token_hash, u.tier, u.status FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.refresh_token_hash = $1 AND s.expires_at > NOW()',
        [tokenHash]
      );
      if (session.length === 0 || !sameHash(session[0].refresh_token_hash, tokenHash)) {
        await this.logWhyChain('token_refresh', ['token_valid', 'user_active']);
        return fail('invalid_token');
      }
      if (session[0].status === 'suspended' || session[0].status === 'banned') {
        await this.logWhyChain('token_refresh', ['token_valid', 'user_active']);
        await this.logAudit('token_refresh_blocked', session[0].user_id, { reason: 'user_banned' });
        return fail('user_banned');
      }
      const newToken = this.generateToken(session[0].user_id, session[0].tier);
      await this.logWhyChain('token_refresh', ['token_valid', 'user_active']);
      await this.logAudit('token_refreshed', session[0].user_id);
      return { status: 'ok', token: newToken, expires_in: 900 };
    } catch (err) {
      this.logger.error('Token refresh error', { err });
      return fail('internal_error');
    }
  }

  /**
   * Verifies an access token (spec flow 7): the step every authenticated request calls, which produces the verified
   * user that permissions_rbac's require_authenticated(current_user) assumes. Read-only.
   * Gates, in order: signature_valid (HS256 ONLY: the algorithm is passed explicitly to jwt.verify, the token's own
   * header alg is never trusted and "none" is refused), not_expired (against the injected clock), and
   * user_exists_and_active (status not 'suspended' or 'banned').
   * In: the token (the `token` a session-creating flow or token_refresh returned). Out: {status: 'ok', user: {id,
   * email, tier}} or {error, message, http_status}: 401 invalid_token (bad signature, another algorithm, malformed,
   * no user id, unknown user), 401 token_expired, 403 user_banned.
   * Why: auth spec flow 7, missing from the TypeScript build (Phase D wave 1, owner request 2026-11-10).
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (one parameterized read of users).
   */
  async verify_access_token(token: string): Promise<any> {
    const decisions = ['signature_valid', 'not_expired', 'user_active'];
    try {
      let claims: any;
      try {
        claims = jwt.verify(String(token ?? ''), this.jwtSecret, {
          algorithms: ['HS256'],
          clockTimestamp: Math.floor(this.now().getTime() / 1000),
        });
      } catch (err: any) {
        await this.logWhyChain('verify_access_token', decisions);
        return fail(err?.name === 'TokenExpiredError' ? 'token_expired' : 'invalid_token');
      }
      const userId = claims && typeof claims === 'object' ? claims.userId : undefined;
      if (typeof userId !== 'number' || !Number.isSafeInteger(userId)) {
        await this.logWhyChain('verify_access_token', decisions);
        return fail('invalid_token');
      }
      const rows = await this.db.query('SELECT id, email, tier, status FROM users WHERE id = $1', [userId]);
      if (rows.length === 0) {
        await this.logWhyChain('verify_access_token', decisions);
        return fail('invalid_token');
      }
      if (rows[0].status === 'suspended' || rows[0].status === 'banned') {
        await this.logWhyChain('verify_access_token', decisions);
        return fail('user_banned');
      }
      await this.logWhyChain('verify_access_token', decisions);
      return { status: 'ok', user: { id: rows[0].id, email: rows[0].email, tier: rows[0].tier } };
    } catch (err) {
      this.logger.error('Verify access token error', { err });
      return fail('internal_error');
    }
  }
}

export default AuthSystem;

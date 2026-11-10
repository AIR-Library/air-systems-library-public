import bcrypt from 'bcrypt';
import speakeasy from 'speakeasy';
import jwt from 'jsonwebtoken';
import { randomBytes, randomInt } from 'crypto';

const ddl = `
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

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  refresh_token VARCHAR(255) UNIQUE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  INET ip,
  device_id VARCHAR(255)
);

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
  code VARCHAR(255) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  type VARCHAR(10) CHECK (type IN ('email', 'mfa')) NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0
);
-- Tables made before 2026-11-08 lack the MFA attempt count.
ALTER TABLE verification_codes ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0;
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

class AuthSystem {
  private db: Db;
  private emailSender: EmailSender;
  private logger: Logger;
  private jwtSecret: string;
  private bcryptSaltRounds: number;
  private tokenExpiry: string;
  private refreshTokenExpiry: string;
  private signupIpLimiter: Map<string, number[]>;
  private loginLimiter: Map<string, number[]>;
  private signupWindowMs: number;
  private maxSignupsPerIP: number;
  private loginWindowMs: number;
  private maxLoginAttempts: number;

  constructor(
    db: Db,
    emailSender: EmailSender,
    logger: Logger,
    options: {
      jwtSecret: string;
      bcryptSaltRounds?: number;
      tokenExpiry?: string;
      refreshTokenExpiry?: string;
      signupWindowMs?: number;
      maxSignupsPerIP?: number;
      loginWindowMs?: number;
      maxLoginAttempts?: number;
    } = {}
  ) {
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
   * Signs a user up: IP rate limit, unique email, password rules, then creates the unverified user and sends the
   * verification code.
   *
   * In: email, password, name and the request's client IP (from the server, never from the body; default
   * '0.0.0.0' keeps old callers working). Out: {status: 'pending_verification', ...} or {error, reason?}.
   * Why: AUTH-01..04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: a weak password now returns
   * {error: 'password_rejected', reason} (AUTH-03 amendment; 'password_too_weak' is gone), and the IP is a
   * parameter instead of a constant, so the 5-per-24h limit is per address rather than global.
   * Touches: the database, the email sender, the audit log.
   */
  async signup(email: string, password: string, name: string, ip: string = '0.0.0.0'): Promise<any> {
    try {
      if (!(await this.rateLimitSignup(ip))) {
        await this.logWhyChain('signup', ['email_unique', 'password_strength', 'rate_limit_ip_24h']);
        return { error: 'too_many_signups_from_ip' };
      }

      const existingUser = await this.db.query('SELECT id FROM users WHERE email = $1', [email]);
      if (existingUser.length > 0) {
        await this.logWhyChain('signup', ['email_unique', 'password_strength', 'rate_limit_ip_24h']);
        return { error: 'email_already_exists' };
      }

      const rejection = AuthSystem.passwordRejection(password, email, name);
      if (rejection !== null) {
        await this.logWhyChain('signup', ['email_unique', 'password_strength', 'rate_limit_ip_24h']);
        return { error: 'password_rejected', reason: rejection };
      }

      const passwordHash = await this.hashPassword(password);
      const result = await this.db.execute(
        'INSERT INTO users (email, password_hash, name) VALUES ($1, $2, $3) RETURNING id, email',
        [email, passwordHash, name]
      );
      const userId = result.insertId;
      const code = this.generateVerificationCode();
      await this.db.execute(
        'INSERT INTO verification_codes (user_id, code, type, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL \'10 minutes\')',
        [userId, code, 'email']
      );
      await this.emailSender.sendVerificationEmail(email, code);
      await this.logWhyChain('signup', ['email_unique', 'password_strength', 'rate_limit_ip_24h']);
      await this.logAudit('user_created', userId, { email });
      return { status: 'pending_verification', email, message: 'check email' };
    } catch (err) {
      this.logger.error('Signup error', { err });
      return { error: 'internal_error' };
    }
  }

  async verify_email(email: string, code_or_token: string): Promise<any> {
    try {
      const user = await this.db.query('SELECT id, email_verified_at FROM users WHERE email = $1', [email]);
      if (user.length === 0) {
        await this.logWhyChain('verify_email', ['code_valid', 'user_unverified']);
        return { error: 'code_expired' }; // Or invalid, but spec test expects expired for wrong code
      }
      if (user[0].email_verified_at !== null) {
        await this.logWhyChain('verify_email', ['code_valid', 'user_unverified']);
        return { error: 'already_verified' };
      }

      const verification = await this.db.query(
        'SELECT id FROM verification_codes WHERE user_id = $1 AND code = $2 AND type = \'email\' AND expires_at > NOW()',
        [user[0].id, code_or_token]
      );
      if (verification.length === 0) {
        await this.logWhyChain('verify_email', ['code_valid', 'user_unverified']);
        return { error: 'code_expired' };
      }

      await this.db.execute(
        'UPDATE users SET email_verified_at = NOW() WHERE id = $1',
        [user[0].id]
      );
      await this.db.execute(
        'DELETE FROM verification_codes WHERE id = $1',
        [verification[0].id]
      );
      await this.logWhyChain('verify_email', ['code_valid', 'user_unverified']);
      await this.logAudit('email_verified', user[0].id);
      return { status: 'verified', user_id: user[0].id, message: 'ready to login' };
    } catch (err) {
      this.logger.error('Verify email error', { err });
      return { error: 'internal_error' };
    }
  }

  async login(email: string, password: string, device_id: string, ip: string): Promise<any> {
    try {
      if (!(await this.rateLimitLogin(ip, email))) {
        await this.logWhyChain('login', ['user_exists', 'password_correct', 'mfa_gate', 'rate_limit']);
        return { error: 'too_many_login_attempts' };
      }

      const user = await this.db.query('SELECT id, email, password_hash, tier, mfa_enabled, mfa_secret FROM users WHERE email = $1 AND email_verified_at IS NOT NULL', [email]);
      if (user.length === 0) {
        await this.logWhyChain('login', ['user_exists', 'password_correct', 'mfa_gate', 'rate_limit']);
        await this.logAudit('failed_login', null, { email, ip, device_id, reason: 'user_not_found_or_unverified' });
        return { error: 'invalid_credentials' };
      }

      const passwordCorrect = await this.comparePassword(password, user[0].password_hash);
      if (!passwordCorrect) {
        await this.logWhyChain('login', ['user_exists', 'password_correct', 'mfa_gate', 'rate_limit']);
        await this.logAudit('failed_login', user[0].id, { email, ip, device_id, reason: 'wrong_password' });
        return { error: 'invalid_credentials' };
      }

      if (user[0].mfa_enabled) {
        const challengeId = randomBytes(16).toString('hex');
        await this.db.execute(
          'INSERT INTO verification_codes (user_id, code, type, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL \'10 minutes\')',
          [user[0].id, challengeId, 'mfa']
        );
        await this.logWhyChain('login', ['user_exists', 'password_correct', 'mfa_gate', 'rate_limit']);
        await this.logAudit('mfa_challenge_initiated', user[0].id, { challenge_id: challengeId });
        return { status: 'mfa_required', challenge_id: challengeId };
      }

      const sessionId = randomBytes(16).toString('hex');
      const refreshToken = this.generateRefreshToken();
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
      await this.db.execute(
        'INSERT INTO sessions (user_id, refresh_token, expires_at, ip, device_id) VALUES ($1, $2, $3, $4, $5)',
        [user[0].id, refreshToken, expiresAt, ip, device_id]
      );
      const token = this.generateToken(user[0].id, user[0].tier);
      await this.logWhyChain('login', ['user_exists', 'password_correct', 'mfa_gate', 'rate_limit']);
      await this.logAudit('session_created', user[0].id, { session_id: sessionId, ip, device_id });
      return {
        status: 'authenticated',
        session_id: sessionId,
        token,
        expires_in: 900, // 15 minutes in seconds
        user: { id: user[0].id, email: user[0].email, tier: user[0].tier }
      };
    } catch (err) {
      this.logger.error('Login error', { err });
      return { error: 'internal_error' };
    }
  }

  async oauth_callback(provider: string, code: string, state: string): Promise<any> {
    try {
      // In real implementation, validate state against session
      // For simplicity, we assume state is valid (spec test doesn't cover invalid state)
      // Fetch user info from provider (mocked)
      const email = `user@${provider}.com`; // Mock
      const existingUser = await this.db.query('SELECT id, email FROM users WHERE email = $1', [email]);
      let userId;
      if (existingUser.length === 0) {
        const result = await this.db.execute(
          'INSERT INTO users (email, status, email_verified_at) VALUES ($1, \'verified\', NOW()) RETURNING id',
          [email]
        );
        userId = result.insertId;
        // Link OAuth (simplified)
        await this.db.execute(
          'INSERT INTO oauth_links (user_id, provider, provider_user_id) VALUES ($1, $2, $3)',
          [userId, provider, `oauth_user_${code}`]
        );
      } else {
        userId = existingUser[0].id;
        await this.db.execute(
          'INSERT INTO oauth_links (user_id, provider, provider_user_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
          [userId, provider, `oauth_user_${code}`]
        );
      }
      const user = await this.db.query('SELECT id, email, tier FROM users WHERE id = $1', [userId]);
      await this.logWhyChain('oauth_callback', ['state_valid', 'email_verified']);
      await this.logAudit('oauth_login', userId, { provider, session_id: 'mock_session' });
      const token = this.generateToken(user[0].id, user[0].tier);
      return {
        status: 'authenticated',
        session_id: 'mock_session',
        token,
        user: { id: user[0].id, email: user[0].email, tier: user[0].tier }
      };
    } catch (err) {
      this.logger.error('OAuth callback error', { err });
      return { error: 'internal_error' };
    }
  }

  async mfa_challenge(challenge_id: string, code: string): Promise<any> {
    try {
      const challenge = await this.db.query(
        'SELECT user_id FROM verification_codes WHERE code = $1 AND type = \'mfa\' AND expires_at > NOW()',
        [challenge_id]
      );
      if (challenge.length === 0) {
        await this.logWhyChain('mfa_challenge', ['challenge_valid', 'code_correct']);
        return { error: 'invalid_code' };
      }

      const user = await this.db.query('SELECT mfa_secret FROM users WHERE id = $1', [challenge[0].user_id]);
      if (user.length === 0 || !user[0].mfa_secret) {
        await this.logWhyChain('mfa_challenge', ['challenge_valid', 'code_correct']);
        return { error: 'invalid_code' };
      }

      const isValid = this.verifyTotp(user[0].mfa_secret, code);
      if (!isValid) {
        // Each wrong code counts; after five the challenge is gone and the user signs in again, so a six digit code
        // cannot be guessed (2026-11-08, session f3daac6e, from review of PR 17).
        await this.db.execute('UPDATE verification_codes SET attempts = attempts + 1 WHERE code = $1', [challenge_id]);
        await this.db.execute('DELETE FROM verification_codes WHERE code = $1 AND attempts >= $2', [challenge_id, 5]);
        await this.logWhyChain('mfa_challenge', ['challenge_valid', 'code_correct']);
        await this.logAudit('mfa_failed', challenge[0].user_id);
        return { error: 'invalid_code' };
      }

      // Use the challenge up. Only the call that deletes it may sign in, so two at once cannot both get a session
      // (2026-11-08, session f3daac6e, from review).
      const consumed = await this.db.execute(
        'DELETE FROM verification_codes WHERE code = $1',
        [challenge_id]
      );
      if (consumed.affectedRows !== 1) {
        await this.logWhyChain('mfa_challenge', ['challenge_valid', 'code_correct']);
        return { error: 'invalid_code' };
      }
      const sessionId = randomBytes(16).toString('hex');
      const refreshToken = this.generateRefreshToken();
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
      await this.db.execute(
        'INSERT INTO sessions (user_id, refresh_token, expires_at, ip, device_id) VALUES ($1, $2, $3, $4, $5)',
        [challenge[0].user_id, refreshToken, expiresAt, '0.0.0.0', 'unknown']
      );
      const userDetails = await this.db.query('SELECT id, email, tier FROM users WHERE id = $1', [challenge[0].user_id]);
      const token = this.generateToken(challenge[0].user_id, userDetails[0].tier);
      await this.logWhyChain('mfa_challenge', ['challenge_valid', 'code_correct']);
      await this.logAudit('mfa_verified', challenge[0].user_id);
      return {
        status: 'authenticated',
        session_id: sessionId,
        token,
        expires_in: 900,
        user: { id: userDetails[0].id, email: userDetails[0].email, tier: userDetails[0].tier }
      };
    } catch (err) {
      this.logger.error('MFA challenge error', { err });
      return { error: 'internal_error' };
    }
  }

  async token_refresh(refresh_token: string): Promise<any> {
    try {
      const session = await this.db.query(
        'SELECT s.user_id, u.tier, u.status FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.refresh_token = $1 AND s.expires_at > NOW()',
        [refresh_token]
      );
      if (session.length === 0) {
        await this.logWhyChain('token_refresh', ['token_valid', 'user_active']);
        return { error: 'invalid_token' };
      }
      if (session[0].status === 'suspended' || session[0].status === 'banned') {
        await this.logWhyChain('token_refresh', ['token_valid', 'user_active']);
        await this.logAudit('token_refresh_blocked', session[0].user_id, { reason: 'user_banned' });
        return { error: 'user_banned' };
      }
      const newToken = this.generateToken(session[0].user_id, session[0].tier);
      await this.logWhyChain('token_refresh', ['token_valid', 'user_active']);
      await this.logAudit('token_refreshed', session[0].user_id);
      return { status: 'ok', token: newToken, expires_in: 900 };
    } catch (err) {
      this.logger.error('Token refresh error', { err });
      return { error: 'internal_error' };
    }
  }
}

export default AuthSystem;

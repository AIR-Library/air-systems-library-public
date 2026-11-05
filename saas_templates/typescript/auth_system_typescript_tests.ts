import speakeasy from 'speakeasy';
import jwt from 'jsonwebtoken';
import AuthSystem from './auth_system_typescript';

/**
 * Tests for AuthSystem: the same cases as the other languages (signup, verify_email, login, oauth_callback,
 * mfa_challenge, token_refresh), plus the two audit entries and the MFA lookup that were broken until 2026-11-05.
 *
 * Why this file changed: it needed a live PostgreSQL server on localhost, which no test run has, and it expected
 * a constructor, named exports and error fields the class never had. Rewritten against an in-memory stand-in on
 * 2026-11-05 by session f3daac6e (AIR record finding:2026-11-05:3a00300d16).
 * Touches: memory only. No database, network or mail.
 */

type Row = Record<string, any>;

/** An in-memory stand-in for the database, answering the statements AuthSystem sends. */
class FakeDb {
  users: Row[] = [];
  codes: Row[] = [];
  sessions: Row[] = [];
  audit: Row[] = [];
  oauthLinks: Row[] = [];
  private nextId = 1;

  private id(): number {
    return this.nextId++;
  }

  async query(sql: string, params: any[] = []): Promise<Row[]> {
    const live = (c: Row) => c.expires_at.getTime() > Date.now();
    if (sql.includes('FROM users WHERE email = $1')) {
      const verifiedOnly = sql.includes('email_verified_at IS NOT NULL');
      return this.users.filter((u) => u.email === params[0] && (!verifiedOnly || u.email_verified_at !== null));
    }
    if (sql.includes('FROM users WHERE id = $1')) {
      return this.users.filter((u) => u.id === params[0]);
    }
    if (sql.includes('FROM verification_codes WHERE user_id = $1 AND code = $2')) {
      return this.codes.filter((c) => c.user_id === params[0] && c.code === params[1] && c.type === 'email' && live(c));
    }
    if (sql.includes('FROM verification_codes WHERE code = $1')) {
      return this.codes.filter((c) => c.code === params[0] && c.type === 'mfa' && live(c));
    }
    if (sql.includes('FROM sessions s JOIN users u')) {
      return this.sessions
        .filter((s) => s.refresh_token === params[0] && s.expires_at.getTime() > Date.now())
        .map((s) => {
          const user = this.users.find((u) => u.id === s.user_id) as Row;
          return { user_id: s.user_id, tier: user.tier, status: user.status };
        });
    }
    throw new Error(`FakeDb has no answer for: ${sql}`);
  }

  async execute(sql: string, params: any[] = []): Promise<{ insertId: number }> {
    if (sql.startsWith('INSERT INTO audit_log')) {
      this.audit.push({ actor_id: params[0], action: params[1], new_value: params[4] });
      return { insertId: 0 };
    }
    if (sql.startsWith('INSERT INTO users (email, password_hash, name)')) {
      const id = this.id();
      this.users.push({
        id, email: params[0], password_hash: params[1], name: params[2], tier: 'free', status: 'unverified',
        email_verified_at: null, mfa_enabled: false, mfa_secret: null,
      });
      return { insertId: id };
    }
    if (sql.startsWith('INSERT INTO users (email, status, email_verified_at)')) {
      const id = this.id();
      this.users.push({
        id, email: params[0], password_hash: null, name: null, tier: 'free', status: 'verified',
        email_verified_at: new Date(), mfa_enabled: false, mfa_secret: null,
      });
      return { insertId: id };
    }
    if (sql.startsWith('INSERT INTO verification_codes')) {
      const id = this.id();
      this.codes.push({
        id, user_id: params[0], code: params[1], type: params[2], expires_at: new Date(Date.now() + 10 * 60 * 1000),
      });
      return { insertId: id };
    }
    if (sql.startsWith('UPDATE users SET email_verified_at')) {
      const user = this.users.find((u) => u.id === params[0]) as Row;
      user.email_verified_at = new Date();
      user.status = 'verified';
      return { insertId: 0 };
    }
    if (sql.startsWith('DELETE FROM verification_codes WHERE id = $1')) {
      this.codes = this.codes.filter((c) => c.id !== params[0]);
      return { insertId: 0 };
    }
    if (sql.startsWith('DELETE FROM verification_codes WHERE code = $1')) {
      this.codes = this.codes.filter((c) => c.code !== params[0]);
      return { insertId: 0 };
    }
    if (sql.startsWith('INSERT INTO sessions')) {
      this.sessions.push({
        user_id: params[0], refresh_token: params[1], expires_at: params[2], ip: params[3], device_id: params[4],
      });
      return { insertId: 0 };
    }
    if (sql.startsWith('INSERT INTO oauth_links')) {
      this.oauthLinks.push({ user_id: params[0], provider: params[1], provider_user_id: params[2] });
      return { insertId: 0 };
    }
    throw new Error(`FakeDb has no answer for: ${sql}`);
  }

  auditActions(): string[] {
    return this.audit.map((a) => a.action);
  }
}

const SECRET = 'test-secret';
const STRONG = 'thisisaverygoodpassword123';

describe('AuthSystem', () => {
  let db: FakeDb;
  let mail: { to: string; code: string }[];
  let errors: unknown[];
  let auth: AuthSystem;

  beforeEach(() => {
    db = new FakeDb();
    mail = [];
    errors = [];
    const sender = {
      sendVerificationEmail: async (to: string, code: string) => {
        mail.push({ to, code });
      },
    };
    const logger = { info: () => undefined, error: (...args: unknown[]) => errors.push(args) };
    auth = new AuthSystem(db as any, sender as any, logger as any, { jwtSecret: SECRET, bcryptSaltRounds: 4 });
  });

  /** Signs up and verifies a user. Out: the user's row. */
  async function verifiedUser(email = 'test@example.com'): Promise<Row> {
    await auth.signup(email, STRONG, 'Test User');
    const { code } = mail[mail.length - 1];
    await auth.verify_email(email, code);
    return db.users.find((u) => u.email === email) as Row;
  }

  /** Signs up a user with MFA on and logs in. Out: the TOTP secret and the challenge id. */
  async function mfaChallenge(): Promise<{ secret: string; challengeId: string }> {
    const user = await verifiedUser();
    const secret = speakeasy.generateSecret().base32;
    user.mfa_enabled = true;
    user.mfa_secret = secret;
    const result = await auth.login(user.email, STRONG, 'device123', '1.2.3.4');
    expect(result.status).toBe('mfa_required');
    return { secret, challengeId: result.challenge_id };
  }

  describe('signup', () => {
    it('happy path (valid email, strong password) → user created, email sent', async () => {
      const result = await auth.signup('test@example.com', STRONG, 'Test User');

      expect(result).toEqual({ status: 'pending_verification', email: 'test@example.com', message: 'check email' });
      expect(db.users).toHaveLength(1);
      expect(db.users[0].password_hash).not.toContain(STRONG);
      expect(mail).toHaveLength(1);
      expect(mail[0].code).toMatch(/^\d{6}$/);
      expect(db.auditActions()).toContain('user_created');
    });

    it('signup duplicate email → {error: "email_already_exists"}', async () => {
      await auth.signup('test@example.com', STRONG, 'Test User');

      const result = await auth.signup('test@example.com', 'anothergoodpassword456', 'Test User 2');

      expect(result).toEqual({ error: 'email_already_exists' });
      expect(db.users).toHaveLength(1);
    });

    it('signup weak password → {error: "password_too_weak"}', async () => {
      expect(await auth.signup('a@example.com', 'short', 'A')).toEqual({ error: 'password_too_weak', reason: 'too_short' });
      expect(await auth.signup('b@example.com', 'x'.repeat(65), 'B')).toEqual({ error: 'password_too_weak', reason: 'too_long' });
      expect(db.users).toHaveLength(0);
    });

    it('signup IP rate limit → {error: "too_many_signups_from_ip"}', async () => {
      for (let i = 0; i < 5; i++) {
        await auth.signup(`user${i}@example.com`, STRONG, `User ${i}`);
      }

      const result = await auth.signup('one-too-many@example.com', STRONG, 'Late');

      expect(result).toEqual({ error: 'too_many_signups_from_ip' });
      expect(db.users).toHaveLength(5);
    });
  });

  describe('verify_email', () => {
    it('verify_email happy path → user verified, code used up', async () => {
      await auth.signup('test@example.com', STRONG, 'Test User');

      const result = await auth.verify_email('test@example.com', mail[0].code);

      expect(result).toEqual({ status: 'verified', user_id: db.users[0].id, message: 'ready to login' });
      expect(db.users[0].email_verified_at).not.toBeNull();
      expect(db.codes).toHaveLength(0);
    });

    it('verify_email expired code → {error: "code_expired"}', async () => {
      await auth.signup('test@example.com', STRONG, 'Test User');
      db.codes[0].expires_at = new Date(Date.now() - 60 * 60 * 1000);

      expect(await auth.verify_email('test@example.com', mail[0].code)).toEqual({ error: 'code_expired' });
      expect(db.users[0].email_verified_at).toBeNull();
    });
  });

  describe('login', () => {
    it('login happy path (no MFA) → token returned', async () => {
      const user = await verifiedUser();

      const result = await auth.login(user.email, STRONG, 'device123', '1.2.3.4');

      expect(result).toMatchObject({
        status: 'authenticated',
        expires_in: 900,
        user: { id: user.id, email: user.email, tier: 'free' },
      });
      const decoded = jwt.verify(result.token, SECRET) as { userId: number; tier: string };
      expect(decoded.userId).toBe(user.id);
      expect(db.sessions).toHaveLength(1);
    });

    it('login with MFA enabled → {status: "mfa_required", challenge_id}', async () => {
      const { challengeId } = await mfaChallenge();

      expect(challengeId).toEqual(expect.any(String));
      expect(db.sessions).toHaveLength(0);
    });

    it('login invalid password → {error: "invalid_credentials"}', async () => {
      const user = await verifiedUser();

      expect(await auth.login(user.email, 'wrongpassword', 'device123', '1.2.3.4')).toEqual({ error: 'invalid_credentials' });
      expect(db.auditActions()).toContain('failed_login');
    });

    it('login attempts are rate limited per address and email', async () => {
      const user = await verifiedUser();
      for (let i = 0; i < 5; i++) {
        await auth.login(user.email, 'wrongpassword', 'device123', '1.2.3.4');
      }

      expect(await auth.login(user.email, STRONG, 'device123', '1.2.3.4')).toEqual({ error: 'too_many_login_attempts' });
    });
  });

  describe('oauth_callback', () => {
    it('oauth_callback happy path (new user) → user created + oauth linked', async () => {
      const result = await auth.oauth_callback('google', 'authcode', 'valid_state');

      expect(result).toMatchObject({ status: 'authenticated', user: { email: 'user@google.com', tier: 'free' } });
      expect(db.users[0].status).toBe('verified');
      expect(db.oauthLinks).toHaveLength(1);
    });

    it('oauth_callback existing user → oauth linked to existing account', async () => {
      const user = await verifiedUser('user@github.com');

      const result = await auth.oauth_callback('github', 'authcode', 'valid_state');

      expect(result.user.id).toBe(user.id);
      expect(db.users).toHaveLength(1);
      expect(db.oauthLinks[0].user_id).toBe(user.id);
      expect(db.auditActions()).toContain('oauth_login');
    });
  });

  describe('mfa_challenge', () => {
    it('mfa_challenge happy path → token returned, challenge used up, actor audited', async () => {
      const { secret, challengeId } = await mfaChallenge();
      const code = speakeasy.totp({ secret, encoding: 'base32' });

      const result = await auth.mfa_challenge(challengeId, code);

      expect(result).toMatchObject({ status: 'authenticated', user: { email: 'test@example.com', tier: 'free' } });
      expect(db.codes.filter((c) => c.type === 'mfa')).toHaveLength(0);
      expect(db.audit.find((a) => a.action === 'mfa_verified')?.actor_id).toBe(db.users[0].id);
      expect(errors).toHaveLength(0);
    });

    it('mfa_challenge wrong code → {error: "invalid_code"}', async () => {
      const { challengeId } = await mfaChallenge();

      expect(await auth.mfa_challenge(challengeId, '000000')).toEqual({ error: 'invalid_code' });
      expect(db.auditActions()).toContain('mfa_failed');
      expect(db.sessions).toHaveLength(0);
    });

    it('mfa_challenge unknown challenge → {error: "invalid_code"}', async () => {
      expect(await auth.mfa_challenge('no-such-challenge', '123456')).toEqual({ error: 'invalid_code' });
    });
  });

  describe('token_refresh', () => {
    it('token_refresh happy path → new token issued, actor audited', async () => {
      const user = await verifiedUser();
      await auth.login(user.email, STRONG, 'device123', '1.2.3.4');

      const result = await auth.token_refresh(db.sessions[0].refresh_token);

      expect(result).toEqual({ status: 'ok', token: expect.any(String), expires_in: 900 });
      expect(db.audit.find((a) => a.action === 'token_refreshed')?.actor_id).toBe(user.id);
    });

    it('token_refresh banned user → {error: "user_banned"}', async () => {
      const user = await verifiedUser();
      await auth.login(user.email, STRONG, 'device123', '1.2.3.4');
      user.status = 'banned';

      expect(await auth.token_refresh(db.sessions[0].refresh_token)).toEqual({ error: 'user_banned' });
      expect(db.auditActions()).toContain('token_refresh_blocked');
    });

    it('token_refresh unknown token → {error: "invalid_token"}', async () => {
      expect(await auth.token_refresh('no-such-token')).toEqual({ error: 'invalid_token' });
    });
  });
});

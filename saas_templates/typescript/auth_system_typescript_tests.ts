import speakeasy from 'speakeasy';
import jwt from 'jsonwebtoken';
import { createHash, createHmac } from 'crypto';
import AuthSystem, { OAuthIdentity } from './auth_system_typescript';

/**
 * Tests for AuthSystem: the same cases as the other languages (signup, verify_email, login, oauth_callback,
 * mfa_challenge, token_refresh), plus the two audit entries and the MFA lookup that were broken until 2026-11-05.
 *
 * Why this file changed: it needed a live PostgreSQL server on localhost, which no test run has, and it expected
 * a constructor, named exports and error fields the class never had. Rewritten against an in-memory stand-in on
 * 2026-11-05 by session f3daac6e (AIR record finding:2026-11-05:3a00300d16).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): the stand-in answers the new statements (refresh_token_hash,
 * code_hash, oauth_states, the oauth_links lookup); every refusal is now asserted with its HTTP status (typescript bug:
 * auth errors carried none); OAuth goes through oauth_start's state and an injected fake provider client; AUTH-16 is
 * new. Each changed assertion carries a comment saying why.
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
  oauthStates: Row[] = [];
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
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-16): codes, challenges and refresh tokens are looked up by
    // their SHA-256; OAuth links by the provider's user id.
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.4, af92d76): the user's expired email codes, which
    // verify_email reads to tell an expired code (code_expired) from a wrong one (code_invalid).
    if (sql.includes("FROM verification_codes WHERE user_id = $1 AND type = 'email' AND expires_at <= NOW()")) {
      return this.codes.filter((c) => c.user_id === params[0] && c.type === 'email' && !live(c));
    }
    if (sql.includes("FROM verification_codes WHERE user_id = $1 AND type = 'email'")) {
      return this.codes.filter((c) => c.user_id === params[0] && c.type === 'email' && live(c));
    }
    if (sql.includes('FROM verification_codes WHERE code_hash = $1')) {
      return this.codes.filter((c) => c.code_hash === params[0] && c.type === 'mfa' && live(c));
    }
    if (sql.includes('FROM sessions s JOIN users u')) {
      return this.sessions
        .filter((s) => s.refresh_token_hash === params[0] && s.expires_at.getTime() > Date.now())
        .map((s) => {
          const user = this.users.find((u) => u.id === s.user_id) as Row;
          return { user_id: s.user_id, refresh_token_hash: s.refresh_token_hash, tier: user.tier, status: user.status };
        });
    }
    if (sql.includes('FROM oauth_links WHERE provider = $1 AND provider_user_id = $2')) {
      return this.oauthLinks.filter((l) => l.provider === params[0] && l.provider_user_id === params[1]);
    }
    throw new Error(`FakeDb has no answer for: ${sql}`);
  }

  async execute(sql: string, params: any[] = []): Promise<{ insertId: number; affectedRows?: number }> {
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
    if (sql.startsWith('INSERT INTO verification_codes (user_id, code_hash, type')) {
      const id = this.id();
      this.codes.push({
        id, user_id: params[0], code_hash: params[1], type: params[2], expires_at: new Date(Date.now() + 10 * 60 * 1000),
        attempts: 0,
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
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.3 ruling): verify_email counts each try first on each
    // live code, one conditional write per row, and reports whether the row took it.
    if (sql.startsWith('UPDATE verification_codes SET attempts = attempts + 1 WHERE id = $1 AND attempts < $2')) {
      const hit = this.codes.filter((c) => c.id === params[0] && c.attempts < params[1]);
      hit.forEach((c) => { c.attempts += 1; });
      return { insertId: 0, affectedRows: hit.length };
    }
    if (sql.startsWith('UPDATE verification_codes SET attempts = attempts + 1 WHERE code_hash = $1')) {
      this.codes.filter((c) => c.code_hash === params[0]).forEach((c) => { c.attempts += 1; });
      return { insertId: 0 };
    }
    if (sql.startsWith('DELETE FROM verification_codes WHERE code_hash = $1 AND attempts >= $2')) {
      const before = this.codes.length;
      this.codes = this.codes.filter((c) => !(c.code_hash === params[0] && c.attempts >= params[1]));
      return { insertId: 0, affectedRows: before - this.codes.length };
    }
    if (sql.startsWith('DELETE FROM verification_codes WHERE code_hash = $1')) {
      const before = this.codes.length;
      this.codes = this.codes.filter((c) => c.code_hash !== params[0]);
      return { insertId: 0, affectedRows: before - this.codes.length };
    }
    if (sql.startsWith('INSERT INTO sessions (id, user_id, refresh_token_hash, expires_at, ip, device_id)')) {
      this.sessions.push({
        id: params[0], user_id: params[1], refresh_token_hash: params[2], expires_at: params[3], ip: params[4], device_id: params[5],
      });
      return { insertId: 0 };
    }
    if (sql.startsWith('INSERT INTO oauth_links')) {
      if (!this.oauthLinks.some((l) => l.provider === params[1] && l.provider_user_id === params[2])) {
        this.oauthLinks.push({ user_id: params[0], provider: params[1], provider_user_id: params[2] });
      }
      return { insertId: 0 };
    }
    if (sql.startsWith('INSERT INTO oauth_states (state_hash, provider, created_at, expires_at)')) {
      this.oauthStates.push({ state_hash: params[0], provider: params[1], created_at: params[2], expires_at: params[3], used_at: null });
      return { insertId: 0 };
    }
    if (sql.startsWith('UPDATE oauth_states SET used_at = $1 WHERE state_hash = $2 AND provider = $3 AND used_at IS NULL AND expires_at > $1')) {
      const hit = this.oauthStates.filter((st) => st.state_hash === params[1] && st.provider === params[2] && st.used_at === null
        && st.expires_at.getTime() > params[0].getTime());
      hit.forEach((st) => { st.used_at = params[0]; });
      return { insertId: 0, affectedRows: hit.length };
    }
    throw new Error(`FakeDb has no answer for: ${sql}`);
  }

  auditActions(): string[] {
    return this.audit.map((a) => a.action);
  }
}

const SECRET = 'test-secret';
const STRONG = 'thisisaverygoodpassword123';

/** Fixed 32+ byte HMAC key for stored secrets (spec d270fa3: tests pass a fixed test key). 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. */
const TEST_SECRET_KEY = 'test-secret-key-0123456789abcdef-auth';

/**
 * HMAC-SHA256(TEST_SECRET_KEY, value) as lowercase hex: the value the module stores for a secret (AUTH-16). In: the
 * secret. Out: 64 hex characters. Why: spec d270fa3: keyed HMAC for stored secrets; this helper computed a plain
 * SHA-256 until 2026-11-10 (changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches nothing.
 */
function sha256(value: string): string {
  return createHmac('sha256', TEST_SECRET_KEY).update(value, 'utf8').digest('hex');
}

/**
 * Plain, unkeyed SHA-256 hex, which the module must no longer store. In: the secret. Out: 64 hex characters. Why:
 * spec d270fa3: keyed HMAC for stored secrets (AUTH-16 asserts the stored value is not this). 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function plainSha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/**
 * The refusal the module returns for an error code: { error, message, http_status } plus any extra fields.
 * In: code, HTTP status, extras. Out: the expected object. Why: Phase B.2 typescript bug (auth errors had no status).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function refused(error: string, http_status: number, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { error, message: expect.any(String), http_status, ...extra };
}

describe('AuthSystem', () => {
  let db: FakeDb;
  let mail: { to: string; code: string }[];
  let errors: unknown[];
  let auth: AuthSystem;
  /** The fake provider's answers by code, the codes it was asked to exchange, and the injected clock. */
  let identities: Record<string, OAuthIdentity>;
  let exchanged: string[];
  let clock: Date;

  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): the service now takes an injected OAuth provider client
  // (a fake that answers from `identities`) and a clock (OAuth state expiry).
  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec d270fa3: keyed HMAC for stored secrets): and the fixed
  // TEST_SECRET_KEY.
  beforeEach(() => {
    identities = {};
    exchanged = [];
    clock = new Date();
    db = new FakeDb();
    mail = [];
    errors = [];
    const sender = {
      sendVerificationEmail: async (to: string, code: string) => {
        mail.push({ to, code });
      },
    };
    const logger = { info: () => undefined, error: (...args: unknown[]) => errors.push(args) };
    const oauthClient = {
      exchangeCode: async (_provider: string, code: string) => {
        exchanged.push(code);
        return identities[code] ?? null;
      },
    };
    auth = new AuthSystem(db as any, sender as any, logger as any, {
      jwtSecret: SECRET, secretKey: TEST_SECRET_KEY, bcryptSaltRounds: 4, oauthClient, now: () => clock,
    });
  });

  /**
   * An OAuth sign-in as the provider would drive it: oauth_start, then the callback with that state and a code the
   * fake provider maps to `identity`. In: provider, code, identity. Out: the callback's answer.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 OAuth state and provider client).
   */
  async function oauthSignIn(provider: string, code: string, identity: OAuthIdentity): Promise<any> {
    identities[code] = identity;
    const start = await auth.oauth_start(provider);
    expect(start).toEqual({ status: 'ok', state: expect.any(String), expires_in: 600 });
    return auth.oauth_callback(provider, code, start.state);
  }

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
    // AUTH-01
    it('happy path (valid email, strong password) → user created, email sent', async () => {
      const result = await auth.signup('test@example.com', STRONG, 'Test User');

      expect(result).toEqual({ status: 'pending_verification', email: 'test@example.com', message: 'check email' });
      expect(db.users).toHaveLength(1);
      expect(db.users[0].password_hash).not.toContain(STRONG);
      expect(mail).toHaveLength(1);
      expect(mail[0].code).toMatch(/^\d{6}$/);
      expect(db.auditActions()).toContain('user_created');
    });

    // AUTH-02
    it('signup duplicate email → {error: "email_already_exists"}', async () => {
      await auth.signup('test@example.com', STRONG, 'Test User');

      const result = await auth.signup('test@example.com', 'anothergoodpassword456', 'Test User 2');

      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): the refusal now carries its 409 and a message.
      expect(result).toEqual(refused('email_already_exists', 409));
      expect(db.users).toHaveLength(1);
    });

    // AUTH-03
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the spec amendment renamed the error to "password_rejected"
    // (no "password_too_weak" anywhere) and fixed the order too_short, too_long, blocklisted, first failure wins.
    // Each attempt passes its own client IP so the 5-per-IP signup limit is not what answers.
    // Phase B.2 the same day: each refusal now carries its 400 and a message.
    it('signup weak password → {error: "password_rejected", reason}', async () => {
      const rejected = (reason: string) => refused('password_rejected', 400, { reason });
      expect(await auth.signup('a@example.com', 'short', 'A', '10.0.0.1')).toEqual(rejected('too_short'));
      expect(await auth.signup('b@example.com', 'x'.repeat(65), 'B', '10.0.0.2')).toEqual(rejected('too_long'));
      expect(await auth.signup('c@example.com', 'password123', 'C', '10.0.0.3')).toEqual(rejected('too_short'));
      expect(await auth.signup('d@example.com', 'PasswordPassword', 'D', '10.0.0.4')).toEqual(rejected('blocklisted'));
      expect(await auth.signup('Long.Name@Example.com', 'long.name@example.com', 'E', '10.0.0.5')).toEqual(rejected('blocklisted'));
      expect(await auth.signup('f@example.com', 'Correct Horse Battery', 'correct horse battery', '10.0.0.6')).toEqual(rejected('blocklisted'));
      expect(db.users).toHaveLength(0);
    });

    // AUTH-04
    it('signup IP rate limit → {error: "too_many_signups_from_ip"}', async () => {
      for (let i = 0; i < 5; i++) {
        await auth.signup(`user${i}@example.com`, STRONG, `User ${i}`);
      }

      const result = await auth.signup('one-too-many@example.com', STRONG, 'Late');

      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): the refusal now carries its 429.
      expect(result).toEqual(refused('too_many_signups_from_ip', 429));
      expect(db.users).toHaveLength(5);
    });
  });

  describe('verify_email', () => {
    // AUTH-05
    it('verify_email happy path → user verified, code used up', async () => {
      await auth.signup('test@example.com', STRONG, 'Test User');

      const result = await auth.verify_email('test@example.com', mail[0].code);

      expect(result).toEqual({ status: 'verified', user_id: db.users[0].id, message: 'ready to login' });
      expect(db.users[0].email_verified_at).not.toBeNull();
      expect(db.codes).toHaveLength(0);
    });

    // AUTH-06
    it('verify_email expired code → {error: "code_expired"}', async () => {
      await auth.signup('test@example.com', STRONG, 'Test User');
      db.codes[0].expires_at = new Date(Date.now() - 60 * 60 * 1000);

      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): the refusal now carries its 400.
      expect(await auth.verify_email('test@example.com', mail[0].code)).toEqual(refused('code_expired', 400));
      expect(db.users[0].email_verified_at).toBeNull();
    });
  });

  describe('login', () => {
    // AUTH-07
    it('login happy path (no MFA) → token returned', async () => {
      const user = await verifiedUser();

      const result = await auth.login(user.email, STRONG, 'device123', '1.2.3.4');

      expect(result).toMatchObject({
        status: 'authenticated',
        expires_in: 900,
        user: { id: user.id, email: user.email, tier: 'free' },
      });
      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-16): login also returns the refresh token.
      expect(result.refresh_token).toMatch(/^[0-9a-f]{64}$/);
      const decoded = jwt.verify(result.token, SECRET) as { userId: number; tier: string };
      expect(decoded.userId).toBe(user.id);
      expect(db.sessions).toHaveLength(1);
    });

    // AUTH-08
    it('login with MFA enabled → {status: "mfa_required", challenge_id}', async () => {
      const { challengeId } = await mfaChallenge();

      expect(challengeId).toEqual(expect.any(String));
      expect(db.sessions).toHaveLength(0);
      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): the spec's 202, and the challenge id is stored only
      // as its SHA-256.
      const again = await auth.login('test@example.com', STRONG, 'device123', '1.2.3.5');
      expect(again).toEqual({ status: 'mfa_required', challenge_id: expect.any(String), http_status: 202 });
      expect(JSON.stringify(db.codes)).not.toContain(again.challenge_id);
      expect(db.codes.some((c) => c.code_hash === sha256(again.challenge_id))).toBe(true);
    });

    // AUTH-09
    it('login invalid password → {error: "invalid_credentials"}', async () => {
      const user = await verifiedUser();

      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): the refusal now carries its 401.
      expect(await auth.login(user.email, 'wrongpassword', 'device123', '1.2.3.4')).toEqual(refused('invalid_credentials', 401));
      expect(db.auditActions()).toContain('failed_login');
    });

    it('login attempts are rate limited per address and email', async () => {
      const user = await verifiedUser();
      for (let i = 0; i < 5; i++) {
        await auth.login(user.email, 'wrongpassword', 'device123', '1.2.3.4');
      }

      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): the refusal now carries its 429.
      expect(await auth.login(user.email, STRONG, 'device123', '1.2.3.4')).toEqual(refused('too_many_login_attempts', 429));
    });
  });

  describe('oauth_callback', () => {
    // AUTH-10
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 AUTH spec): the callback now needs a state from
    // oauth_start and exchanges the code through the injected provider client; the email comes from the provider
    // (it was invented from the provider's name) and the link holds the provider's user id, never the code.
    it('oauth_callback happy path (new user) → user created + oauth linked', async () => {
      const result = await oauthSignIn('google', 'authcode', { provider_user_id: 'g-123', email: 'user@google.com', email_verified: true });

      expect(result).toMatchObject({ status: 'authenticated', user: { email: 'user@google.com', tier: 'free' } });
      expect(db.users[0].status).toBe('verified');
      expect(db.oauthLinks).toEqual([{ user_id: db.users[0].id, provider: 'google', provider_user_id: 'g-123' }]);
      expect(exchanged).toEqual(['authcode']);
      expect(result.refresh_token).toMatch(/^[0-9a-f]{64}$/);
      expect((await auth.token_refresh(result.refresh_token)).status).toBe('ok');
    });

    // AUTH-11
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: through oauth_start and the provider client, as AUTH-10.
    it('oauth_callback existing user → oauth linked to existing account', async () => {
      const user = await verifiedUser('user@github.com');

      const result = await oauthSignIn('github', 'authcode', { provider_user_id: 'gh-9', email: 'user@github.com', email_verified: true });

      expect(result.user.id).toBe(user.id);
      expect(db.users).toHaveLength(1);
      expect(db.oauthLinks[0].user_id).toBe(user.id);
      expect(db.oauthLinks[0].provider_user_id).toBe('gh-9');
      expect(db.auditActions()).toContain('oauth_login');
    });

    /**
     * AUTH spec "Secrets at rest" (Phase B.2, under AUTH-10): the OAuth state is single-use, bound to its provider,
     * expires after 10 minutes and is stored only as its SHA-256; a made-up state is 400 invalid_state and the code is
     * never exchanged; a code the provider refuses is 401 oauth_exchange_failed; an email the provider has not
     * verified is 403 email_not_verified; nothing is created by any refusal.
     * In: the fake provider client and clock. Out: assertions only. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: memory only.
     */
    // AUTH-10
    it('oauth state is single-use, provider-bound, 10 minutes; the code goes through the provider client', async () => {
      identities.code1 = { provider_user_id: 'g-1', email: 'one@example.com', email_verified: true };
      expect(await auth.oauth_callback('google', 'code1', 'made-up-state')).toEqual(refused('invalid_state', 400));
      expect(exchanged).toEqual([]);

      const start = await auth.oauth_start('google');
      expect(JSON.stringify(db.oauthStates)).not.toContain(start.state);
      expect(db.oauthStates[0].state_hash).toBe(sha256(start.state));
      expect(db.oauthStates[0].state_hash).not.toBe(plainSha256(start.state)); // spec d270fa3, 2026-11-10: keyed
      expect(await auth.oauth_callback('github', 'code1', start.state)).toEqual(refused('invalid_state', 400));
      expect((await auth.oauth_callback('google', 'code1', start.state)).status).toBe('authenticated');
      expect(await auth.oauth_callback('google', 'code1', start.state)).toEqual(refused('invalid_state', 400));

      const late = await auth.oauth_start('google');
      clock = new Date(clock.getTime() + 10 * 60 * 1000);
      expect(await auth.oauth_callback('google', 'code1', late.state)).toEqual(refused('invalid_state', 400));

      const refusedCode = await auth.oauth_start('google');
      expect(await auth.oauth_callback('google', 'unknown-code', refusedCode.state)).toEqual(refused('oauth_exchange_failed', 401));
      identities.unverified = { provider_user_id: 'g-2', email: 'two@example.com', email_verified: false };
      const unverified = await auth.oauth_start('google');
      expect(await auth.oauth_callback('google', 'unverified', unverified.state)).toEqual(refused('email_not_verified', 403));
      expect(db.users.map((u) => u.email)).toEqual(['one@example.com']);
      expect(db.oauthLinks.map((l) => l.provider_user_id)).toEqual(['g-1']);
    });
  });

  describe('mfa_challenge', () => {
    // AUTH-12
    it('mfa_challenge happy path → token returned, challenge used up, actor audited', async () => {
      const { secret, challengeId } = await mfaChallenge();
      const code = speakeasy.totp({ secret, encoding: 'base32' });

      const result = await auth.mfa_challenge(challengeId, code);

      expect(result).toMatchObject({ status: 'authenticated', user: { email: 'test@example.com', tier: 'free' } });
      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-16): MFA verify also returns a refresh token that works.
      expect((await auth.token_refresh(result.refresh_token)).status).toBe('ok');
      expect(db.codes.filter((c) => c.type === 'mfa')).toHaveLength(0);
      expect(db.audit.find((a) => a.action === 'mfa_verified')?.actor_id).toBe(db.users[0].id);
      expect(errors).toHaveLength(0);
    });

    // AUTH-13
    it('mfa_challenge wrong code → {error: "invalid_code"}', async () => {
      const { challengeId } = await mfaChallenge();

      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): the refusal now carries its 401.
      expect(await auth.mfa_challenge(challengeId, '000000')).toEqual(refused('invalid_code', 401));
      expect(db.auditActions()).toContain('mfa_failed');
      expect(db.sessions).toHaveLength(0);
    });

    it('five wrong codes end the challenge, even for the right code after', async () => {
      const { secret, challengeId } = await mfaChallenge();
      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): each refusal now carries its 401.
      for (let i = 0; i < 5; i++) {
        expect(await auth.mfa_challenge(challengeId, '000000')).toEqual(refused('invalid_code', 401));
      }

      const code = speakeasy.totp({ secret, encoding: 'base32' });
      expect(await auth.mfa_challenge(challengeId, code)).toEqual(refused('invalid_code', 401));
      expect(db.sessions).toHaveLength(0);
    });

    it('a challenge works only once', async () => {
      const { secret, challengeId } = await mfaChallenge();
      const code = speakeasy.totp({ secret, encoding: 'base32' });
      expect((await auth.mfa_challenge(challengeId, code)).status).toBe('authenticated');

      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): the refusal now carries its 401.
      expect(await auth.mfa_challenge(challengeId, code)).toEqual(refused('invalid_code', 401));
      expect(db.sessions).toHaveLength(1);
    });

    it('mfa_challenge unknown challenge → {error: "invalid_code"}', async () => {
      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): the refusal now carries its 401.
      expect(await auth.mfa_challenge('no-such-challenge', '123456')).toEqual(refused('invalid_code', 401));
    });
  });

  describe('token_refresh', () => {
    // AUTH-14
    it('token_refresh happy path → new token issued, actor audited', async () => {
      const user = await verifiedUser();
      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-16): the refresh token comes from login's answer; the
      // sessions table no longer holds it.
      const session = await auth.login(user.email, STRONG, 'device123', '1.2.3.4');

      const result = await auth.token_refresh(session.refresh_token);

      expect(result).toEqual({ status: 'ok', token: expect.any(String), expires_in: 900 });
      expect(db.audit.find((a) => a.action === 'token_refreshed')?.actor_id).toBe(user.id);
    });

    // AUTH-15
    it('token_refresh banned user → {error: "user_banned"}', async () => {
      const user = await verifiedUser();
      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-16 / Phase B.2): the refresh token comes from login's
      // answer, and the refusal carries its 403.
      const session = await auth.login(user.email, STRONG, 'device123', '1.2.3.4');
      user.status = 'banned';

      expect(await auth.token_refresh(session.refresh_token)).toEqual(refused('user_banned', 403));
      expect(db.auditActions()).toContain('token_refresh_blocked');
    });

    it('token_refresh unknown token → {error: "invalid_token"}', async () => {
      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): the refusal now carries its 401.
      expect(await auth.token_refresh('no-such-token')).toEqual(refused('invalid_token', 401));
    });
  });

  /**
   * AUTH-16: login returns a refresh_token that token_refresh accepts; the sessions table holds only its SHA-256
   * (no column or value in any session row is the token); the stored hash itself is not accepted as a refresh token;
   * the emailed verification code is stored only as its SHA-256 (no row holds the code) and still verifies.
   * In: the in-memory stand-in. Out: assertions only. Why: AUTH-16 and the spec's "Secrets at rest" line (Phase B.2,
   * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
   * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec d270fa3: keyed HMAC for stored secrets): stored values
   * must equal HMAC-SHA256(TEST_SECRET_KEY, value) and not the plain SHA-256; and the service refuses to start
   * without a 32-byte key.
   */
  describe('secrets at rest', () => {
    // AUTH-16
    it('login refresh_token works with token_refresh; sessions and codes hold only SHA-256 hashes', async () => {
      await auth.signup('hash@example.com', STRONG, 'Hash User');
      const { code } = mail[mail.length - 1];
      expect(JSON.stringify(db.codes)).not.toContain(code);
      expect(db.codes).toHaveLength(1);
      expect(db.codes[0].code_hash).toBe(sha256(code));
      expect(db.codes[0].code_hash).not.toBe(plainSha256(code)); // spec d270fa3 (2026-11-10): keyed, not plain SHA-256
      expect(db.codes[0]).not.toHaveProperty('code');
      // Phase B.4 (af92d76, 2026-11-10): a wrong code is code_invalid (this asserted code_expired).
      expect(await auth.verify_email('hash@example.com', '000000' === code ? '111111' : '000000')).toEqual(refused('code_invalid', 400));
      expect((await auth.verify_email('hash@example.com', code)).status).toBe('verified');

      const session = await auth.login('hash@example.com', STRONG, 'device-h', '1.2.3.9');
      expect(session.status).toBe('authenticated');
      expect(session.refresh_token).toMatch(/^[0-9a-f]{64}$/);
      expect(db.sessions).toHaveLength(1);
      expect(db.sessions[0]).toMatchObject({ id: session.session_id, refresh_token_hash: sha256(session.refresh_token) });
      expect(db.sessions[0]).not.toHaveProperty('refresh_token');
      expect(db.sessions[0].refresh_token_hash).not.toBe(plainSha256(session.refresh_token)); // spec d270fa3
      expect(JSON.stringify(db.sessions)).not.toContain(session.refresh_token);

      const refreshed = await auth.token_refresh(session.refresh_token);
      expect(refreshed).toEqual({ status: 'ok', token: expect.any(String), expires_in: 900 });
      expect((jwt.verify(refreshed.token, SECRET) as { userId: number }).userId).toBe(db.users[0].id);
      expect(await auth.token_refresh(db.sessions[0].refresh_token_hash)).toEqual(refused('invalid_token', 401));
    });

    /**
     * The service refuses to start without a 32-byte key: the constructor throws with no secretKey and no
     * AUTH_SECRET_KEY, with an empty key and with a 31-byte key (option or environment); a 32-byte AUTH_SECRET_KEY is
     * accepted. In: the in-memory stand-in, process.env. Out: assertions only. Why: spec d270fa3: keyed HMAC for
     * stored secrets ("the service refuses to start without it"). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: process.env (restored afterwards), memory only.
     */
    // AUTH-16
    it('refuses to start without an AUTH_SECRET_KEY of at least 32 bytes', async () => {
      const saved = process.env.AUTH_SECRET_KEY;
      const make = (secretKey?: string) => new AuthSystem(new FakeDb() as any, {} as any, {} as any,
        secretKey === undefined ? { jwtSecret: SECRET } : { jwtSecret: SECRET, secretKey });
      try {
        delete process.env.AUTH_SECRET_KEY;
        expect(() => make()).toThrow(/AUTH_SECRET_KEY/);
        expect(() => make('')).toThrow(/AUTH_SECRET_KEY/);
        expect(() => make('k'.repeat(31))).toThrow(/AUTH_SECRET_KEY/);
        process.env.AUTH_SECRET_KEY = 'k'.repeat(31);
        expect(() => make()).toThrow(/AUTH_SECRET_KEY/);
        process.env.AUTH_SECRET_KEY = TEST_SECRET_KEY;
        expect(make()).toBeInstanceOf(AuthSystem);
      } finally {
        if (saved === undefined) delete process.env.AUTH_SECRET_KEY; else process.env.AUTH_SECRET_KEY = saved;
      }
    });
  });

  /**
   * verify_email attempts (auth flow 2, Phase B.3 ruling): 5 wrong codes invalidate the user's current code, so the
   * 6th try is 400 code_invalid even with the right code and the user stays unverified; with 4 wrong codes the right
   * one (the 5th try) still verifies; a newly sent code (a new code row, 0 attempts) works again.
   * In: the in-memory stand-in. Out: assertions only. Why: Phase D wave 1, owner request 2026-11-10 (B.3 rulings).
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
   * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.4 ruling af92d76): tagged AUTH-17, the id the ruling
   * gave this rule, and each wrong code now asserts 400 code_invalid (it asserted code_expired, which af92d76 rules
   * out for a wrong code).
   */
  describe('verify_email attempts', () => {
    // AUTH-17
    it('5 wrong codes invalidate the code: the right code is then 400 code_invalid until a new code is sent', async () => {
      await auth.signup('guess@example.com', STRONG, 'Guess User');
      const { code } = mail[mail.length - 1];
      const wrong = code === '000000' ? '111111' : '000000';
      for (let i = 0; i < 5; i++) {
        // Phase B.4 (af92d76, 2026-11-10): was code_expired.
        expect(await auth.verify_email('guess@example.com', wrong)).toEqual(refused('code_invalid', 400));
      }
      expect(await auth.verify_email('guess@example.com', code)).toEqual(refused('code_invalid', 400));
      expect(await auth.verify_email('guess@example.com', wrong)).toEqual(refused('code_invalid', 400));
      const user = db.users.find((u) => u.email === 'guess@example.com') as Row;
      expect(user.email_verified_at).toBeNull();
      expect(db.codes.filter((c) => c.user_id === user.id)[0].attempts).toBe(5);

      // A new code is sent: a fresh row with 0 attempts, which verifies.
      await db.execute('INSERT INTO verification_codes (user_id, code_hash, type, expires_at) VALUES ($1, $2, $3, NOW())',
        [user.id, sha256('424242'), 'email']);
      expect((await auth.verify_email('guess@example.com', '424242')).status).toBe('verified');
    });

    // AUTH-17
    it('4 wrong codes, then the right code on the 5th try is accepted', async () => {
      await auth.signup('four@example.com', STRONG, 'Four User');
      const { code } = mail[mail.length - 1];
      const wrong = code === '000000' ? '111111' : '000000';
      for (let i = 0; i < 4; i++) {
        // Phase B.4 (af92d76, 2026-11-10): was code_expired.
        expect(await auth.verify_email('four@example.com', wrong)).toEqual(refused('code_invalid', 400));
      }
      expect(await auth.verify_email('four@example.com', code)).toMatchObject({ status: 'verified' });
    });
  });

  /**
   * verify_access_token (auth flow 7): a token from login verifies to {status: 'ok', user: {id, email, tier}}; a
   * token signed with another key, with another HMAC algorithm (HS512, same key), with alg "none", a malformed one and
   * one naming no user are 401 invalid_token; one past its expiry on the injected clock is 401 token_expired; a
   * suspended or banned user is 403 user_banned; a token for a user that no longer exists is 401 invalid_token.
   * In: the in-memory stand-in and the injected clock. Out: assertions only. Why: auth spec flow 7 was missing from
   * the TypeScript build (Phase D wave 1, owner request 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: memory only.
   */
  describe('verify_access_token', () => {
    it('accepts a valid HS256 token and refuses every other one with the spec error', async () => {
      const user = await verifiedUser('tok@example.com');
      const session = await auth.login('tok@example.com', STRONG, 'device-t', '1.2.3.10');
      expect(await auth.verify_access_token(session.token)).toEqual({
        status: 'ok', user: { id: user.id, email: 'tok@example.com', tier: 'free' },
      });

      const payload = { userId: user.id, tier: 'free' };
      expect(await auth.verify_access_token(jwt.sign(payload, 'another-secret'))).toEqual(refused('invalid_token', 401));
      expect(await auth.verify_access_token(jwt.sign(payload, SECRET, { algorithm: 'HS512' }))).toEqual(refused('invalid_token', 401));
      const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
      const unsigned = `${b64({ alg: 'none', typ: 'JWT' })}.${b64(payload)}.`;
      expect(await auth.verify_access_token(unsigned)).toEqual(refused('invalid_token', 401));
      expect(await auth.verify_access_token('not-a-token')).toEqual(refused('invalid_token', 401));
      expect(await auth.verify_access_token('')).toEqual(refused('invalid_token', 401));
      expect(await auth.verify_access_token(jwt.sign({ tier: 'free' }, SECRET))).toEqual(refused('invalid_token', 401));
      expect(await auth.verify_access_token(jwt.sign({ userId: 999999, tier: 'free' }, SECRET))).toEqual(refused('invalid_token', 401));

      clock = new Date(clock.getTime() + 16 * 60 * 1000);
      expect(await auth.verify_access_token(session.token)).toEqual(refused('token_expired', 401));
      clock = new Date(clock.getTime() - 16 * 60 * 1000);

      user.status = 'suspended';
      expect(await auth.verify_access_token(session.token)).toEqual(refused('user_banned', 403));
      user.status = 'banned';
      expect(await auth.verify_access_token(session.token)).toEqual(refused('user_banned', 403));
    });
  });
});

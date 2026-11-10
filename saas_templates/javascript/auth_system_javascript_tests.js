// Fixed 32+ byte HMAC key for stored secrets (spec d270fa3: tests pass a fixed test key). The module reads
// AUTH_SECRET_KEY when it loads, so it is set before the require below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
const TEST_SECRET_KEY = 'test-secret-key-0123456789abcdef-auth';
process.env.AUTH_SECRET_KEY = TEST_SECRET_KEY;
const crypto = require('crypto');
const { initDB, configure, signup, verify_email, login, oauth_start, oauth_callback, mfa_challenge, token_refresh, dbPromise,
  resetRateLimits, sentEmails } = require('./auth_system_javascript');
const { expect } = require('@jest/globals');
const speakeasy = require('speakeasy');

// Fake OAuth provider client (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, Phase B.2 / AUTH-16): the callback must
// exchange the provider's code through an injected client, so the test maps each code to the identity the provider
// would return. A code it does not know is refused, as a real provider would.
const oauthIdentities = new Map();
const fakeGoogle = {
  async exchangeCode(code) {
    if (!oauthIdentities.has(code)) throw new Error('invalid_grant');
    return oauthIdentities.get(code);
  },
};
/**
 * The value the module stores for a secret: lowercase hex HMAC-SHA256(TEST_SECRET_KEY, value). In: a string. Out: 64
 * hex characters. Why: spec d270fa3: keyed HMAC for stored secrets; the tests used the module's plain SHA-256 helper
 * before 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function sha256(value) {
  return crypto.createHmac('sha256', TEST_SECRET_KEY).update(String(value), 'utf8').digest('hex');
}

/**
 * Plain, unkeyed SHA-256 hex of a secret, which the module must no longer store. In: a string. Out: 64 hex chars.
 * Why: spec d270fa3: keyed HMAC for stored secrets (AUTH-16 asserts the stored value is not this). 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function plainSha256(value) {
  return crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');
}

let clock = null; // null: the real clock; a number: a fixed time the test moves

beforeAll(async () => {
  configure({ oauthProviders: { google: fakeGoogle }, now: () => (clock === null ? Date.now() : clock) });
  await initDB();
});

beforeEach(() => {
  resetRateLimits();
  clock = null;
});

/**
 * The verification code e-mailed to `email` (the newest one). In: address. Out: the code.
 * Why: codes are stored only as their SHA-256 now (AUTH-16), so a test reads the code from the e-mail the user gets,
 * as a user would, instead of from the database. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function emailedCode(email) {
  const mail = [...sentEmails].reverse().find(m => m.to === email);
  return /code is ([0-9a-f]{6})\b/.exec(mail.text)[1];
}

/**
 * Runs the OAuth flow the way a browser does: oauth_start for a state, then the callback with the provider's code.
 * In: the identity the fake provider returns for the code. Out: the callback's answer.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-10/11/16). Touches: the test database.
 */
async function oauthLogin(identity, ip, device) {
  const code = `code-${Math.random().toString(16).slice(2)}`;
  oauthIdentities.set(code, identity);
  const { state } = await oauth_start('google');
  return oauth_callback('google', code, state, ip, device);
}

describe('Auth System Tests', () => {
  const ip = '1.2.3.4';
  const device = 'device123';

  // AUTH-01
  test('signup happy path', async () => {
    const res = await signup('user@example.com', 'StrongPassword123456', 'Alice', ip);
    expect(res.success).toBe(true);
    expect(res.status).toBe('pending_verification');
  });

  // AUTH-02
  test('signup duplicate email', async () => {
    await signup('dup@example.com', 'StrongPassword123456', 'Bob', ip);
    const res = await signup('dup@example.com', 'StrongPassword123456', 'Bob', ip);
    expect(res.error).toBe('email_already_exists');
    expect(res.status).toBe(409); // Phase B.2 bug fix, 2026-11-10: errors carry the spec's HTTP status
  });

  // AUTH-03
  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the spec's code is password_rejected with a reason (was password_too_weak).
  test('signup weak password', async () => {
    const res = await signup('weak@example.com', 'short', 'Carol', ip);
    expect(res.error).toBe('password_rejected');
    expect(res.status).toBe(400); // Phase B.2 bug fix, 2026-11-10: errors carry the spec's HTTP status
    expect(res.reason).toBe('too_short');
    // first failure wins: "password123" is too_short, not blocklisted
    expect((await signup('weak2@example.com', 'password123', 'Carol', ip)).reason).toBe('too_short');
    expect((await signup('weak3@example.com', 'x'.repeat(65), 'Carol', ip)).reason).toBe('too_long');
    expect((await signup('weak4@example.com', 'weak4@example.com-padding', 'Carol', ip)).reason).toBe('blocklisted');
  });

  // AUTH-04
  test('signup IP rate limit', async () => {
    for (let i = 0; i < 5; i++) {
      await signup(`rate${i}@example.com`, 'StrongPassword123456', 'Dave', ip);
    }
    const res = await signup('rate6@example.com', 'StrongPassword123456', 'Dave', ip);
    expect(res.error).toBe('too_many_signups_from_ip');
    expect(res.status).toBe(429); // Phase B.2 bug fix, 2026-11-10: errors carry the spec's HTTP status
  });

  // AUTH-05
  test('verify_email happy path', async () => {
    const email = 'verify@example.com';
    await signup(email, 'StrongPassword123456', 'Eve', ip);
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-16): the code is read from the e-mail; the database keeps
    // only its hash.
    const res = await verify_email(email, emailedCode(email));
    expect(res.success).toBe(true);
    expect(res.status).toBe('verified');
  });

  // AUTH-06
  test('verify_email expired code', async () => {
    const email = 'expire@example.com';
    await signup(email, 'StrongPassword123456', 'Frank', ip);
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-16): the code comes from the e-mail (the database keeps only
    // its hash), and the clock moves past the 24 hours instead of the row being edited.
    clock = Date.now() + 24 * 60 * 60 * 1000 + 1000;
    const res = await verify_email(email, emailedCode(email));
    expect(res.error).toBe('code_expired');
    expect(res.status).toBe(400);
  });

  // AUTH-07
  test('login happy path (no MFA)', async () => {
    const email = 'login@example.com';
    await signup(email, 'StrongPassword123456', 'Grace', ip);
    const db = await dbPromise;
    await verify_email(email, emailedCode(email)); // AUTH-16 (2026-11-10): the code comes from the e-mail
    const res = await login(email, 'StrongPassword123456', device, ip);
    expect(res.success).toBe(true);
    expect(res.status).toBe('authenticated');
    expect(res.token).toBeDefined();
    expect(res.refresh_token).toBeDefined(); // Phase B.2, 2026-11-10: login returns its refresh_token
  });

  // AUTH-08
  test('login with MFA enabled', async () => {
    const email = 'mfa@example.com';
    await signup(email, 'StrongPassword123456', 'Heidi', ip);
    const db = await dbPromise;
    await verify_email(email, emailedCode(email)); // AUTH-16 (2026-11-10): the code comes from the e-mail
    const secret = speakeasy.generateSecret().base32;
    await db.run(`UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE email = ?`, secret, email);
    const res = await login(email, 'StrongPassword123456', device, ip);
    expect(res.success).toBe(true);
    expect(res.status).toBe('mfa_required');
    expect(res.challenge_id).toBeDefined();
  });

  // AUTH-09
  test('login invalid password', async () => {
    const email = 'badpass@example.com';
    await signup(email, 'StrongPassword123456', 'Ivan', ip);
    const db = await dbPromise;
    await verify_email(email, emailedCode(email)); // AUTH-16 (2026-11-10): the code comes from the e-mail
    const res = await login(email, 'WrongPassword', device, ip);
    expect(res.error).toBe('invalid_credentials');
    expect(res.status).toBe(401); // Phase B.2 bug fix, 2026-11-10: errors carry the spec's HTTP status
  });

  // AUTH-10
  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, AUTH-16): the test passed the e-mail as the "code" and a
  // made-up state, which the old callback accepted. It now takes a state from oauth_start and a code the provider
  // client exchanges for the identity; the user is the provider's e-mail and gets a refresh_token.
  test('oauth_callback happy path (new user)', async () => {
    const email = 'oauthnew@example.com';
    const res = await oauthLogin({ provider_user_id: 'g-new', email, email_verified: true }, ip, device);
    expect(res.success).toBe(true);
    expect(res.status).toBe('authenticated');
    expect(res.user.email).toBe(email);
    expect(res.refresh_token).toBeDefined();
    const db = await dbPromise;
    const user = await db.get(`SELECT * FROM users WHERE email = ?`, email);
    expect(user.status).toBe('verified');
    expect(user.email_verified_at).toBeTruthy();
  });

  // AUTH-11
  test('oauth_callback existing user', async () => {
    const email = 'oauthexist@example.com';
    await signup(email, 'StrongPassword123456', 'Judy', ip);
    const db = await dbPromise;
    await verify_email(email, emailedCode(email)); // AUTH-16 (2026-11-10): the code comes from the e-mail
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): through oauth_start and the provider client (above).
    const res = await oauthLogin({ provider_user_id: 'g-exist', email, email_verified: true }, ip, device);
    expect(res.success).toBe(true);
    expect(res.status).toBe('authenticated');
    expect(res.user.email).toBe(email);
    const userRow = await db.get(`SELECT id FROM users WHERE email = ?`, email);
    expect(res.user.id).toBe(userRow.id);
    const link = await db.get(`SELECT user_id FROM oauth_links WHERE provider = 'google' AND provider_user_id = 'g-exist'`);
    expect(link.user_id).toBe(userRow.id);
  });

  // AUTH-12
  test('mfa_challenge happy path', async () => {
    const email = 'mfa2@example.com';
    await signup(email, 'StrongPassword123456', 'Ken', ip);
    const db = await dbPromise;
    await verify_email(email, emailedCode(email)); // AUTH-16 (2026-11-10): the code comes from the e-mail
    const secret = speakeasy.generateSecret().base32;
    await db.run(`UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE email = ?`, secret, email);
    const loginRes = await login(email, 'StrongPassword123456', device, ip);
    const challenge_id = loginRes.challenge_id;
    const totp = speakeasy.totp({ secret, encoding: 'base32' });
    const res = await mfa_challenge(challenge_id, totp, ip, device);
    expect(res.success).toBe(true);
    expect(res.status).toBe('authenticated');
    expect(res.token).toBeDefined();
    // Phase B.2, 2026-11-10: MFA verify returns its refresh_token, which token_refresh accepts
    expect((await token_refresh(res.refresh_token)).status).toBe('ok');
  });

  // AUTH-13
  test('mfa_challenge wrong code', async () => {
    const email = 'mfa3@example.com';
    await signup(email, 'StrongPassword123456', 'Leo', ip);
    const db = await dbPromise;
    await verify_email(email, emailedCode(email)); // AUTH-16 (2026-11-10): the code comes from the e-mail
    const secret = speakeasy.generateSecret().base32;
    await db.run(`UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE email = ?`, secret, email);
    const loginRes = await login(email, 'StrongPassword123456', device, ip);
    const challenge_id = loginRes.challenge_id;
    const res = await mfa_challenge(challenge_id, 'wrongcode', ip, device);
    expect(res.error).toBe('invalid_code');
    expect(res.status).toBe(401); // Phase B.2 bug fix, 2026-11-10: errors carry the spec's HTTP status
  });

  // AUTH-14
  test('token_refresh happy path', async () => {
    const email = 'refresh@example.com';
    await signup(email, 'StrongPassword123456', 'Mia', ip);
    const db = await dbPromise;
    await verify_email(email, emailedCode(email)); // AUTH-16 (2026-11-10): the code comes from the e-mail
    const loginRes = await login(email, 'StrongPassword123456', device, ip);
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-16): the refresh token comes from login's answer; the
    // sessions table keeps only its hash.
    const res = await token_refresh(loginRes.refresh_token);
    expect(res.success).toBe(true);
    expect(res.status).toBe('ok');
    expect(res.token).toBeDefined();
  });

  // AUTH-15
  test('token_refresh banned user', async () => {
    const email = 'banned@example.com';
    await signup(email, 'StrongPassword123456', 'Nina', ip);
    const db = await dbPromise;
    await verify_email(email, emailedCode(email)); // AUTH-16 (2026-11-10): the code comes from the e-mail
    const loginRes = await login(email, 'StrongPassword123456', device, ip);
    await db.run(`UPDATE users SET status = 'banned' WHERE email = ?`, email);
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-16): the refresh token comes from login's answer.
    const res = await token_refresh(loginRes.refresh_token);
    expect(res.error).toBe('user_banned');
    expect(res.status).toBe(403); // Phase B.2 bug fix: errors carry the spec's HTTP status
  });

  /**
   * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec d270fa3: keyed HMAC for stored secrets): stored values
   * must equal HMAC-SHA256(TEST_SECRET_KEY, value) and not the plain SHA-256.
   * AUTH-16: login returns a refresh_token that token_refresh accepts; the sessions table holds only its SHA-256 (no
   * column holds the token); a verification code is stored only as its hash (no column holds the e-mailed code); a
   * wrong or altered refresh token is 401 invalid_token. In: the module with the test clock. Out: assertions.
   * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the test database.
   */
  // AUTH-16
  test('refresh_token from login works; sessions keep only its SHA-256; codes are stored only as hashes', async () => {
    const email = 'secrets@example.com';
    await signup(email, 'StrongPassword123456', 'Olga', ip);
    const code = emailedCode(email);
    const db = await dbPromise;
    const user = await db.get(`SELECT id FROM users WHERE email = ?`, email);
    const codeRow = await db.get(`SELECT * FROM verification_codes WHERE user_id = ? AND type = 'email'`, user.id);
    expect(codeRow.code_hash).toBe(sha256(code));
    expect(codeRow.code_hash).not.toBe(plainSha256(code)); // spec d270fa3 (2026-11-10): keyed, not plain SHA-256
    expect(Object.values(codeRow)).not.toContain(code);
    const codeColumns = (await db.all(`PRAGMA table_info(verification_codes)`)).map(c => c.name);
    expect(codeColumns).toContain('code_hash');
    expect(codeColumns).not.toContain('code');
    await verify_email(email, code);

    const res = await login(email, 'StrongPassword123456', device, ip);
    expect(res.refresh_token).toMatch(/^[0-9a-f-]{36}\.[0-9a-f]{64}$/);
    const row = await db.get(`SELECT * FROM sessions WHERE id = ?`, res.session_id);
    expect(row.refresh_token_hash).toBe(sha256(res.refresh_token));
    expect(row.refresh_token_hash).not.toBe(plainSha256(res.refresh_token)); // spec d270fa3 (2026-11-10)
    expect(JSON.stringify(row)).not.toContain(res.refresh_token.split('.')[1]);
    const sessionColumns = (await db.all(`PRAGMA table_info(sessions)`)).map(c => c.name);
    expect(sessionColumns).toContain('refresh_token_hash');
    expect(sessionColumns).not.toContain('refresh_token');

    const refreshed = await token_refresh(res.refresh_token);
    expect(refreshed).toMatchObject({ success: true, status: 'ok' });
    expect(refreshed.token).toBeDefined();
    // the stored hash itself is not a usable credential, nor is an altered token
    expect(await token_refresh(row.refresh_token_hash)).toMatchObject({ error: 'invalid_token', status: 401 });
    const altered = res.refresh_token.slice(0, -1) + (res.refresh_token.endsWith('0') ? '1' : '0');
    expect(await token_refresh(altered)).toMatchObject({ error: 'invalid_token', status: 401 });
    expect(await token_refresh(undefined)).toMatchObject({ error: 'invalid_token', status: 401 });
  });

  /**
   * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec d270fa3): the stored state is its HMAC-SHA256 under
   * TEST_SECRET_KEY, not its plain SHA-256.
   * AUTH-16 / auth spec "Secrets at rest" for OAuth: the state is stored only as its SHA-256; it works once (a reused
   * state is 400 invalid_state), expires after 10 minutes, and a made-up state is refused; the callback exchanges the
   * code through the provider client, so the code is never an identity (a code that is an e-mail address logs nobody
   * in as that address); an unverified provider e-mail is 403 email_not_verified; the session's refresh_token works.
   * In: the module with the fake provider and the test clock. Out: assertions.
   * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the test database.
   */
  // AUTH-16 AUTH-10
  test('OAuth state is hashed, single-use and expires in 10 minutes; the code goes through the provider client', async () => {
    const db = await dbPromise;
    oauthIdentities.set('code-ok', { provider_user_id: 'g-77', email: 'oauth77@example.com', email_verified: true });
    const { state, expires_in } = await oauth_start('google');
    expect(expires_in).toBe(600);
    const stored = await db.get(`SELECT * FROM oauth_states WHERE state_hash = ?`, sha256(state));
    expect(stored).toBeDefined();
    expect(sha256(state)).not.toBe(plainSha256(state)); // spec d270fa3 (2026-11-10): the state's keyed HMAC is stored
    expect(JSON.stringify(stored)).not.toContain(state);

    const ok = await oauth_callback('google', 'code-ok', state, ip, device);
    expect(ok.status).toBe('authenticated');
    expect((await token_refresh(ok.refresh_token)).status).toBe('ok');
    expect(await oauth_callback('google', 'code-ok', state, ip, device)).toMatchObject({ error: 'invalid_state', status: 400 });
    expect(await oauth_callback('google', 'code-ok', 'made-up-state', ip, device)).toMatchObject({ error: 'invalid_state', status: 400 });

    clock = Date.now();
    const late = await oauth_start('google');
    clock += 10 * 60 * 1000 + 1;
    expect(await oauth_callback('google', 'code-ok', late.state, ip, device)).toMatchObject({ error: 'invalid_state', status: 400 });
    clock = null;

    // the code is not an identity: an e-mail address as the code is refused by the provider, and logs nobody in
    await signup('victim@example.com', 'StrongPassword123456', 'Victim', '10.9.9.9');
    const forged = await oauth_start('google');
    expect(await oauth_callback('google', 'victim@example.com', forged.state, ip, device))
      .toMatchObject({ error: 'oauth_exchange_failed', status: 401 });
    expect(await db.get(`SELECT COUNT(*) AS n FROM oauth_links WHERE user_id = (SELECT id FROM users WHERE email = 'victim@example.com')`))
      .toEqual({ n: 0 });

    const unverified = await oauthLogin({ provider_user_id: 'g-88', email: 'unverified@example.com', email_verified: false }, ip, device);
    expect(unverified).toMatchObject({ error: 'email_not_verified', status: 403 });
    expect(await db.get(`SELECT id FROM users WHERE email = 'unverified@example.com'`)).toBeUndefined();
    expect(await oauth_start('nope')).toMatchObject({ error: 'unknown_provider', status: 400 });
  });

  /**
   * AUTH-16: the service refuses to start without a 32-byte AUTH_SECRET_KEY: loading the module throws when the
   * variable is unset, empty or 31 bytes, and loads with a 32-byte key. In: process.env, a fresh module registry.
   * Out: assertions. Why: spec d270fa3: keyed HMAC for stored secrets ("the service refuses to start without it").
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process.env (restored afterwards); opens one extra
   * in-memory SQLite handle for the 32-byte load.
   */
  // AUTH-16
  test('the module refuses to start without an AUTH_SECRET_KEY of at least 32 bytes', () => {
    const saved = process.env.AUTH_SECRET_KEY;
    try {
      for (const bad of [undefined, '', 'k'.repeat(31)]) {
        if (bad === undefined) delete process.env.AUTH_SECRET_KEY; else process.env.AUTH_SECRET_KEY = bad;
        jest.isolateModules(() => {
          expect(() => require('./auth_system_javascript')).toThrow(/AUTH_SECRET_KEY/);
        });
      }
      process.env.AUTH_SECRET_KEY = 'k'.repeat(32);
      jest.isolateModules(() => {
        expect(require('./auth_system_javascript').hashSecret('123456'))
          .toBe(crypto.createHmac('sha256', 'k'.repeat(32)).update('123456').digest('hex'));
      });
    } finally {
      process.env.AUTH_SECRET_KEY = saved;
    }
  });
});

module.exports = {};

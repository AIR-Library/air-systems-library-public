/**
 * Auth system: signup with e-mail verification, password login with optional TOTP MFA, OAuth login, refresh and
 * access-token verification. Contract: docs/specs/auth_system.md.
 *
 * Secrets at rest (auth spec, amended 2026-11-10, Phase B.2; AUTH-16): refresh tokens, e-mail verification codes and
 * OAuth state values are stored only as their keyed hash, lowercase hex HMAC-SHA256(AUTH_SECRET_KEY, value), and
 * compared in constant time, so a database read hands out no usable credential (spec d270fa3, 2026-11-10: a plain
 * SHA-256 of a 6-digit code could be brute-forced from a leaked table). The module refuses to load without an
 * AUTH_SECRET_KEY environment variable of at least 32 bytes. Every flow that creates a session (login, MFA verify, OAuth) returns the session's refresh_token,
 * the value token_refresh() takes. OAuth state is single-use and expires in 10 minutes, and oauth_callback exchanges
 * the provider's code through an injected provider client: it never uses the code itself as an identity (before this
 * change the "code" WAS the e-mail address, so anyone could log in as anyone).
 *
 * Every error carries the HTTP status the spec gives it, as `status` (a number) beside `error` and `message`
 * (Phase B.2 bug fix: errors had no status).
 *
 * Outside services are injected with configure(): `mailer` ({ send({ to, subject, text }) }, default an in-memory
 * outbox, `sentEmails`), `oauthProviders` ({ <provider>: { exchangeCode(code) -> { provider_user_id, email,
 * email_verified } } }, default none) and `now` (clock in ms).
 *
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2). Touches: the SQLite database (users, sessions,
 * verification_codes, oauth_states, oauth_links, audit_log), the mailer, the OAuth provider clients (network, in a
 * real deployment).
 */
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const DB_PATH = ':memory:';
// The signing key comes from the deployment's own configuration. A key written in public code lets anyone mint tokens.
// Without one, each start makes a random key, so tokens only last until a restart (2026-11-08, session f3daac6e, from review).
const JWT_SECRET = process.env.JWT_SECRET || require('crypto').randomBytes(32).toString('hex');

/**
 * The HMAC key for stored secrets, read from the AUTH_SECRET_KEY environment variable as the JWT secret is read from
 * JWT_SECRET. In: process.env.AUTH_SECRET_KEY. Out: the key as a Buffer. Throws when it is missing or shorter than
 * 32 bytes, so the service refuses to start (require() fails) without one. Why: spec d270fa3: keyed HMAC for stored
 * secrets. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the process environment (read only).
 */
function loadSecretKey(value) {
  const key = Buffer.from(typeof value === 'string' ? value : '', 'utf8');
  if (key.length < 32) throw new Error('AUTH_SECRET_KEY must be set and at least 32 bytes');
  return key;
}
const AUTH_SECRET_KEY = loadSecretKey(process.env.AUTH_SECRET_KEY);
const ACCESS_TOKEN_EXPIRES = '15m';
const REFRESH_TOKEN_EXPIRES_DAYS = 30;
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000; // OAuth state expires in 10 minutes (auth spec, Phase B.2)
const SERVICE_NAME = 'auth_system';

const BLOCKLIST = [
  '123456', 'password', '12345678', 'qwerty', 'abc123', 'football',
  'monkey', 'letmein', 'shadow', 'master', '666666', 'qwerty123',
  '123123', 'admin', 'welcome', 'login', 'princess', 'solo', 'passw0rd'
];

const dbPromise = open({
  filename: DB_PATH,
  driver: sqlite3.Database
});

const rateLimits = {
  signup: new Map(), // ip -> [{ts}]
  loginFail: new Map() // key(ip+user) -> [{ts}]
};

/** E-mails "sent" by the default in-memory mailer, newest last ({ to, subject, text }). Tests read codes here. */
const sentEmails = [];

/** Injected services and clock; see configure(). */
const settings = {
  mailer: { async send(message) { sentEmails.push({ ...message }); } },
  oauthProviders: {},
  now: () => Date.now(),
};

/**
 * Sets the injected services. In: { mailer?, oauthProviders?, now? } (any subset; the rest keep their value).
 * Out: nothing. Why: the verification e-mail was never sent, OAuth trusted the code as an e-mail, and expiry could
 * not be tested without a clock (Phase B.2, AUTH-16). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: module settings only.
 */
function configure(options = {}) {
  if (options.mailer) settings.mailer = options.mailer;
  if (options.oauthProviders) settings.oauthProviders = options.oauthProviders;
  if (options.now) settings.now = options.now;
}

/**
 * Creates the tables. sessions keeps refresh_token_hash only, verification_codes keeps code_hash only (NULL for a
 * TOTP challenge, which sends no code), oauth_states keeps state_hash only (auth spec "Secrets at rest", Phase B.2).
 * In: nothing. Out: a promise. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-16: the plain refresh_token
 * and code columns are gone; oauth_states and oauth_links are new). Touches: the database.
 * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.3: verification_codes.attempts counts the tries made against
 * a code (auth flow 2 "Attempts": 5 wrong codes invalidate it).
 */
async function initDB() {
  const db = await dbPromise;
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT,
      tier TEXT DEFAULT 'free',
      status TEXT DEFAULT 'unverified',
      email_verified_at TEXT,
      mfa_secret TEXT,
      mfa_enabled INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      refresh_token_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      ip TEXT,
      device_id TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      timestamp TEXT NOT NULL,
      actor_id TEXT,
      action TEXT NOT NULL,
      resource_type TEXT,
      resource_id TEXT,
      old_value TEXT,
      new_value TEXT
    );
    CREATE TABLE IF NOT EXISTS verification_codes (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      code_hash TEXT,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      type TEXT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS oauth_states (
      state_hash TEXT PRIMARY KEY,
      provider TEXT NOT NULL,
      binding_hash TEXT,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used_at TEXT
    );
    CREATE TABLE IF NOT EXISTS oauth_links (
      provider TEXT NOT NULL,
      provider_user_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (provider, provider_user_id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);
}

/** The clock in ms (configure({ now })). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
function nowMs() { return settings.now(); }

/** The clock as an ISO 8601 UTC string. Changed 2026-11-10 (reads the injectable clock). Touches: nothing. */
function now() { return new Date(nowMs()).toISOString(); }

function logWhyChain(flow, decisionPoints) {
  // placeholder for logging decision chain
}

/**
 * The spec's error answer with its HTTP status. In: HTTP status, error code, message, extra fields. Out:
 * { error, status, message, ...extra }. Why: Phase B.2 bug fix (errors carried no status though the spec gives one).
 * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function fail(status, error, message, extra = {}) {
  return { error, status, message, ...extra };
}

/**
 * Keyed hash of a secret: lowercase hex HMAC-SHA256(AUTH_SECRET_KEY, value). In: a string. Out: 64 hex characters.
 * Why: refresh tokens, verification codes and OAuth states are stored only as this (AUTH-16); spec d270fa3: keyed
 * HMAC for stored secrets (it replaced the plain SHA-256 helper `sha256`). 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function hashSecret(value) {
  return crypto.createHmac('sha256', AUTH_SECRET_KEY).update(String(value), 'utf8').digest('hex');
}

/**
 * Constant-time comparison of two hex digests. In: two strings (either may be null). Out: true when equal.
 * Why: the spec compares stored secrets in constant time (AUTH-16). Added 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function safeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

async function logAudit({ actor_id, action, resource_type, resource_id, old_value, new_value }) {
  const db = await dbPromise;
  await db.run(`
    INSERT INTO audit_log (timestamp, actor_id, action, resource_type, resource_id, old_value, new_value)
    VALUES (?,?,?,?,?,?,?)`,
    now(), actor_id, action, resource_type, resource_id, old_value, new_value);
}

async function hashPassword(pw) {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(pw, salt);
}

async function verifyPassword(pw, hash) {
  return bcrypt.compare(pw, hash);
}

/**
 * Wrong tries one e-mail verification code takes before it is spent (auth flow 2 "Attempts").
 * Phase B.3, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
const MAX_EMAIL_CODE_ATTEMPTS = 5;

function generateCode() {
  return crypto.randomBytes(3).toString('hex'); // 6 chars
}

function generateToken(user) {
  return jwt.sign({ user_id: user.id, tier: user.tier }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES, algorithm: 'HS256' });
}

/**
 * Creates a session and its refresh token. The refresh token is "<session_id>.<64 hex>" (32 random bytes); only its
 * HMAC-SHA256 is stored (refresh_token_hash), and the session id in front lets token_refresh find the row and compare the
 * hash in constant time.
 * In: user { id, tier }, ip, device id. Out: { session_id, token, expires_in, refresh_token }.
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-16: the plain token was stored). Touches: sessions,
 * audit_log.
 * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
 */
async function createSession(user, ip, device_id) {
  const db = await dbPromise;
  const session_id = uuidv4();
  const refresh_token = `${session_id}.${crypto.randomBytes(32).toString('hex')}`;
  const created_at = now();
  const expires_at = new Date(nowMs() + REFRESH_TOKEN_EXPIRES_DAYS * 24 * 60 * 60 * 1000).toISOString();
  await db.run(`
    INSERT INTO sessions (id, user_id, refresh_token_hash, created_at, expires_at, ip, device_id)
    VALUES (?,?,?,?,?,?,?)`,
    session_id, user.id, hashSecret(refresh_token), created_at, expires_at, ip, device_id);
  await logAudit({ actor_id: user.id, action: 'session_created', resource_type: 'session', resource_id: session_id, old_value: null, new_value: null });
  return { session_id, token: generateToken(user), expires_in: 900, refresh_token };
}

/**
 * The success answer of every flow that creates a session. In: the session from createSession, the user row.
 * Out: { success, status: 'authenticated', session_id, token, refresh_token, expires_in, user: { id, email, tier } }.
 * Why: every such flow returns its refresh_token (auth spec, Phase B.2). Added 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function authenticated(session, user) {
  return {
    success: true,
    status: 'authenticated',
    session_id: session.session_id,
    token: session.token,
    refresh_token: session.refresh_token,
    expires_in: session.expires_in,
    user: { id: user.id, email: user.email, tier: user.tier },
  };
}

function isRateLimitedSignup(ip) {
  const nowTs = nowMs();
  const window = 24 * 60 * 60 * 1000;
  const limit = 5;
  const list = rateLimits.signup.get(ip) || [];
  const recent = list.filter(ts => nowTs - ts < window);
  if (recent.length >= limit) return true;
  recent.push(nowTs);
  rateLimits.signup.set(ip, recent);
  return false;
}

function isRateLimitedLogin(ip, userId) {
  const key = `${ip}:${userId}`;
  const nowTs = nowMs();
  const window = 15 * 60 * 1000;
  const limit = 5;
  const list = rateLimits.loginFail.get(key) || [];
  const recent = list.filter(ts => nowTs - ts < window);
  if (recent.length >= limit) return true;
  recent.push(nowTs);
  rateLimits.loginFail.set(key, recent);
  return false;
}

function clearLoginFail(ip, userId) {
  const key = `${ip}:${userId}`;
  rateLimits.loginFail.delete(key);
}

/**
 * checkPasswordStrength(password, email, name) -> null | "too_short" | "too_long" | "blocklisted".
 * In: the candidate password and the user's own email and name. Out: null when the password is accepted,
 * otherwise the spec's rejection reason. Checks run too_short (< 15), too_long (> 64), blocklisted (bundled
 * list, or the user's own email / name / the service name) and the first failure wins, so "password123" is
 * too_short (auth_system.md PASSWORD RULES, AUTH-03 amended 2026-11-10). An empty email or name never
 * matches (an empty string is contained in every password).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function checkPasswordStrength(password, email, name) {
  if (password.length < 15) return 'too_short';
  if (password.length > 64) return 'too_long';
  const lower = password.toLowerCase();
  const own = [email, name, SERVICE_NAME].filter(v => typeof v === 'string' && v.length > 0).map(v => v.toLowerCase());
  if (BLOCKLIST.includes(lower) || own.some(v => lower.includes(v))) return 'blocklisted';
  return null;
}

/**
 * signup(email, password, name, ip) -> {success, status: "pending_verification", email} | {error, status, ...}.
 * Gates in order: rate_limit_ip_24h (429 too_many_signups_from_ip), email_unique (409 email_already_exists),
 * password_strength (400 password_rejected with reason; AUTH-03). Then the user is created, a verification code is
 * stored as its HMAC-SHA256 only (code_hash) and the plain code is e-mailed through the mailer.
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-03; Phase B.2: statuses on errors, code_hash, and the
 * verification e-mail is really sent; the plain code was stored and never sent). Touches the users,
 * verification_codes and audit tables, and the mailer.
 * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
 */
async function signup(email, password, name, ip) {
  const db = await dbPromise;
  if (isRateLimitedSignup(ip)) {
    return fail(429, 'too_many_signups_from_ip', 'Rate limit exceeded');
  }
  const existing = await db.get(`SELECT id FROM users WHERE email = ?`, email);
  if (existing) {
    return fail(409, 'email_already_exists', 'Email already registered');
  }
  const rejected = checkPasswordStrength(password, email, name);
  if (rejected) {
    return fail(400, 'password_rejected', 'Password rejected', { reason: rejected });
  }
  const hash = await hashPassword(password);
  const user_id = uuidv4();
  await db.run(`
    INSERT INTO users (id, email, password_hash, tier, status, mfa_enabled)
    VALUES (?,?,?,?,?,?)`,
    user_id, email, hash, 'free', 'unverified', 0);
  logWhyChain('signup', ['email_unique', 'password_strength', 'rate_limit_ip_24h']);
  await logAudit({ actor_id: user_id, action: 'user_created', resource_type: 'user', resource_id: user_id, old_value: null, new_value: null });
  // create the verification code: stored only as its HMAC-SHA256, sent to the user in plain
  const code = generateCode();
  const code_id = uuidv4();
  const created_at = now();
  const expires_at = new Date(nowMs() + 24 * 60 * 60 * 1000).toISOString();
  await db.run(`
    INSERT INTO verification_codes (id, user_id, code_hash, created_at, expires_at, type)
    VALUES (?,?,?,?,?,?)`,
    code_id, user_id, hashSecret(code), created_at, expires_at, 'email');
  await settings.mailer.send({
    to: email,
    subject: 'Verify your e-mail address',
    text: `Your verification code is ${code}. It expires in 24 hours.`,
  });
  return { success: true, status: 'pending_verification', email, message: 'check email' };
}

/**
 * verify_email(email, code) -> { success, status: 'verified', user_id } | { error, status, message }.
 * Gates: code_valid (its HMAC-SHA256 matches a stored code_hash, compared in constant time; 400 invalid_code; past
 * expires_at 400 code_expired), user_unverified (409 already_verified). The used code is deleted.
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2: code_hash, statuses, the injectable clock).
 * Phase B.3 (same day, same session): each try is counted on the user's codes before the compare (a conditional
 * UPDATE ... WHERE attempts < 5); after 5 wrong codes the current code is spent and every further try, even with the
 * right code, is 400 code_invalid until a new code is sent. Before, a 6-digit code could be guessed by retrying.
 * Touches: users, verification_codes, audit_log.
 * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
 */
async function verify_email(email, code) {
  const db = await dbPromise;
  const user = await db.get(`SELECT * FROM users WHERE email = ?`, email);
  if (!user) return fail(400, 'invalid_code', 'Invalid code');
  if (user.email_verified_at) return fail(409, 'already_verified', 'Already verified');
  const presented = hashSecret(code == null ? '' : code);
  const rows = await db.all(`SELECT * FROM verification_codes WHERE user_id = ? AND type = 'email'`, user.id);
  // Phase B.3 (auth flow 2 "Attempts"): COUNT THE TRY FIRST, one conditional write per code that still has tries
  // left; only the codes whose write succeeded are compared. Once the user's codes have taken 5 wrong tries, every
  // further try, the right code included, is 400 code_invalid until a new code is sent (a new row starts at 0).
  const counted = [];
  for (const row of rows) {
    const res = await db.run(
      `UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ? AND attempts < ?`, row.id, MAX_EMAIL_CODE_ATTEMPTS);
    if (res.changes === 1) counted.push(row);
  }
  if (rows.length > 0 && counted.length === 0) return fail(400, 'code_invalid', 'Too many wrong codes; ask for a new code');
  let record = null;
  for (const r of counted) {
    if (safeEqualHex(presented, r.code_hash)) record = r; // every code is compared: the time says nothing about which
  }
  if (!record) return fail(400, 'invalid_code', 'Invalid code');
  if (Date.parse(record.expires_at) < nowMs()) {
    return fail(400, 'code_expired', 'Code expired');
  }
  await db.run(`UPDATE users SET email_verified_at = ? WHERE id = ?`, now(), user.id);
  await db.run(`DELETE FROM verification_codes WHERE id = ?`, record.id);
  logWhyChain('verify_email', ['code_valid', 'user_unverified']);
  await logAudit({ actor_id: user.id, action: 'email_verified', resource_type: 'user', resource_id: user.id, old_value: null, new_value: null });
  return { success: true, status: 'verified', user_id: user.id, message: 'ready to login' };
}

/**
 * login(email, password, device_id, ip) -> authenticated (with refresh_token) | { success, status: 'mfa_required',
 * challenge_id } | { error, status, message }.
 * Gates: user_exists_and_verified and password_correct (401 invalid_credentials), rate_limit (429
 * too_many_attempts after 5 failures per 15 min per ip/user), mfa gate. An MFA challenge row stores no code (TOTP is
 * checked against the user's secret in mfa_challenge), so its code_hash is NULL.
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2: refresh_token returned, statuses on errors, the
 * TOTP code is no longer written to the database). Touches: users (read), sessions, verification_codes, audit_log.
 */
async function login(email, password, device_id, ip) {
  const db = await dbPromise;
  const user = await db.get(`SELECT * FROM users WHERE email = ?`, email);
  if (!user || !user.email_verified_at || !user.password_hash) {
    return fail(401, 'invalid_credentials', 'Invalid credentials');
  }
  const pwdOk = await verifyPassword(password, user.password_hash);
  if (!pwdOk) {
    if (isRateLimitedLogin(ip, user.id)) {
      return fail(429, 'too_many_attempts', 'Too many failed attempts');
    }
    return fail(401, 'invalid_credentials', 'Invalid credentials');
  }
  clearLoginFail(ip, user.id);
  if (user.mfa_enabled) {
    const challenge_id = uuidv4();
    const created_at = now();
    const expires_at = new Date(nowMs() + 5 * 60 * 1000).toISOString();
    await db.run(`
      INSERT INTO verification_codes (id, user_id, code_hash, created_at, expires_at, type)
      VALUES (?,?,?,?,?,?)`,
      challenge_id, user.id, null, created_at, expires_at, 'mfa');
    logWhyChain('login', ['user_exists', 'password_correct', 'mfa_gate', 'rate_limit']);
    await logAudit({ actor_id: user.id, action: 'mfa_challenge_created', resource_type: 'challenge', resource_id: challenge_id, old_value: null, new_value: null });
    return { success: true, status: 'mfa_required', challenge_id };
  }
  const session = await createSession(user, ip, device_id);
  logWhyChain('login', ['user_exists', 'password_correct', 'mfa_gate', 'rate_limit']);
  return authenticated(session, user);
}

/**
 * oauth_start(provider, binding) -> { success, state, expires_in: 600 } | { error, status, message }.
 * Makes the OAuth state for the provider's authorize URL: 32 random bytes, stored only as its HMAC-SHA256 with the
 * provider, an optional binding (the browser's pre-login session id, also hashed) and an expiry 10 minutes ahead.
 * Unknown or unconfigured provider: 400 unknown_provider.
 * Why: auth spec "OAuth state is single-use and expires in 10 minutes" (Phase B.2, AUTH-16); there was no state at
 * all. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: oauth_states.
 * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
 */
async function oauth_start(provider, binding = null) {
  if (!settings.oauthProviders[provider]) return fail(400, 'unknown_provider', 'OAuth provider is not configured');
  const db = await dbPromise;
  const state = crypto.randomBytes(32).toString('hex');
  await db.run(`INSERT INTO oauth_states (state_hash, provider, binding_hash, created_at, expires_at) VALUES (?,?,?,?,?)`,
    hashSecret(state), provider, binding == null ? null : hashSecret(binding), now(), new Date(nowMs() + OAUTH_STATE_TTL_MS).toISOString());
  return { success: true, state, expires_in: OAUTH_STATE_TTL_MS / 1000 };
}

/**
 * oauth_callback(provider, code, state, ip, device_id, binding) -> authenticated (with refresh_token) |
 * { error, status, message }.
 * Gates, in order: provider configured (400 unknown_provider); state_valid: the state's HMAC-SHA256 names an unused,
 * unexpired state for this provider whose binding matches (400 invalid_state), consumed by one conditional write so
 * it works once; the provider client exchanges the code (401 oauth_exchange_failed if it refuses or returns no
 * identity); email_verified_by_provider (403 email_not_verified). Then: the (provider, provider_user_id) link decides
 * the user (Case B), else the e-mail (Case B, and the link is made), else a new verified user (Case A). An existing
 * account that never verified its e-mail is claimed: it is marked verified and its password is cleared, since
 * whoever set that password never proved they own the address. A provider id linked to another user is 409
 * oauth_account_conflict. The code is never used as an identity.
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, AUTH-10/11/16: the code was taken as the e-mail
 * and no state was checked). Touches: oauth_states, oauth_links, users, sessions, audit_log, the provider client.
 * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
 */
async function oauth_callback(provider, code, state, ip, device_id, binding = null) {
  const client = settings.oauthProviders[provider];
  if (!client) return fail(400, 'unknown_provider', 'OAuth provider is not configured');
  const db = await dbPromise;
  const stateRow = typeof state === 'string' && state.length > 0
    ? await db.get(`SELECT * FROM oauth_states WHERE state_hash = ?`, hashSecret(state))
    : null;
  const bindingOk = stateRow && (stateRow.binding_hash == null
    || (binding != null && safeEqualHex(hashSecret(binding), stateRow.binding_hash)));
  if (!stateRow || stateRow.provider !== provider || stateRow.used_at || !bindingOk
      || Date.parse(stateRow.expires_at) <= nowMs()) {
    return fail(400, 'invalid_state', 'OAuth state is missing, expired or already used');
  }
  const consumed = await db.run(`UPDATE oauth_states SET used_at = ? WHERE state_hash = ? AND used_at IS NULL`,
    now(), stateRow.state_hash);
  if (consumed.changes !== 1) return fail(400, 'invalid_state', 'OAuth state is missing, expired or already used');

  let identity;
  try {
    identity = await client.exchangeCode(code);
  } catch (e) {
    identity = null;
  }
  if (!identity || !identity.provider_user_id || !identity.email) {
    return fail(401, 'oauth_exchange_failed', 'The provider did not accept the code');
  }
  if (identity.email_verified !== true) {
    return fail(403, 'email_not_verified', 'The provider has not verified this e-mail address');
  }
  const providerUserId = String(identity.provider_user_id);
  const email = String(identity.email);

  const link = await db.get(`SELECT user_id FROM oauth_links WHERE provider = ? AND provider_user_id = ?`, provider, providerUserId);
  let user = link
    ? await db.get(`SELECT * FROM users WHERE id = ?`, link.user_id)
    : await db.get(`SELECT * FROM users WHERE email = ?`, email);
  if (!user) {
    const user_id = uuidv4();
    await db.run(`
      INSERT INTO users (id, email, tier, status, email_verified_at, mfa_enabled)
      VALUES (?,?,?,?,?,?)`,
      user_id, email, 'free', 'verified', now(), 0);
    await logAudit({ actor_id: user_id, action: 'user_created', resource_type: 'user', resource_id: user_id, old_value: null, new_value: null });
    user = await db.get(`SELECT * FROM users WHERE id = ?`, user_id);
  } else if (!user.email_verified_at) {
    await db.run(`UPDATE users SET email_verified_at = ?, password_hash = NULL WHERE id = ?`, now(), user.id);
    user = await db.get(`SELECT * FROM users WHERE id = ?`, user.id);
  }
  if (!link) {
    const other = await db.get(`SELECT user_id FROM oauth_links WHERE provider = ? AND provider_user_id = ?`, provider, providerUserId);
    if (other && other.user_id !== user.id) {
      return fail(409, 'oauth_account_conflict', 'This provider account is linked to another user');
    }
    await db.run(`INSERT OR IGNORE INTO oauth_links (provider, provider_user_id, user_id, created_at) VALUES (?,?,?,?)`,
      provider, providerUserId, user.id, now());
  }
  if (['suspended', 'banned'].includes(user.status)) {
    return fail(403, 'user_banned', 'User banned');
  }
  const session = await createSession(user, ip, device_id);
  logWhyChain('oauth_callback', ['state_valid', 'email_verified']);
  await logAudit({ actor_id: user.id, action: 'oauth_login', resource_type: 'user', resource_id: user.id, old_value: null, new_value: provider });
  return authenticated(session, user);
}

/**
 * mfa_challenge(challenge_id, code, ip, device_id) -> authenticated (with refresh_token) | { error, status, message }.
 * Gates: challenge_exists_and_valid (401 invalid_code if unknown, 401 code_expired after 5 minutes), code_correct:
 * a TOTP for the user's secret, one 30 s step of drift allowed (401 invalid_code). The challenge is deleted on use.
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2: refresh_token returned, statuses on errors; the
 * code is checked with speakeasy.totp.verify instead of against a copy stored in the database). Touches:
 * verification_codes, users (read), sessions, audit_log.
 */
async function mfa_challenge(challenge_id, code, ip, device_id) {
  const db = await dbPromise;
  const record = await db.get(`
    SELECT * FROM verification_codes WHERE id = ? AND type = 'mfa'`, challenge_id);
  if (!record) return fail(401, 'invalid_code', 'Invalid challenge');
  if (Date.parse(record.expires_at) < nowMs()) {
    return fail(401, 'code_expired', 'Challenge expired');
  }
  const user = await db.get(`SELECT * FROM users WHERE id = ?`, record.user_id);
  const ok = !!user && !!user.mfa_secret && typeof code === 'string' && /^\d{6}$/.test(code)
    && speakeasy.totp.verify({ secret: user.mfa_secret, encoding: 'base32', token: code, window: 1, time: Math.floor(nowMs() / 1000) });
  if (!ok) {
    return fail(401, 'invalid_code', 'Invalid code');
  }
  const deleted = await db.run(`DELETE FROM verification_codes WHERE id = ?`, challenge_id);
  if (deleted.changes !== 1) return fail(401, 'invalid_code', 'Invalid challenge');
  const session = await createSession(user, ip, device_id);
  logWhyChain('mfa_challenge', ['challenge_valid', 'code_correct']);
  await logAudit({ actor_id: user.id, action: 'mfa_verified', resource_type: 'user', resource_id: user.id, old_value: null, new_value: null });
  return authenticated(session, user);
}

/**
 * token_refresh(refresh_token) -> { success, status: 'ok', token, expires_in } | { error, status, message }.
 * Gates: token_valid: "<session_id>.<secret>", the session exists and the token's HMAC-SHA256 equals its
 * refresh_token_hash in constant time (401 invalid_token), not past expires_at (401 token_expired);
 * user_not_banned (403 user_banned).
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, AUTH-14/15/16: the token was looked up in plain
 * text; statuses on errors). Touches: sessions and users (read), audit_log.
 * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
 */
async function token_refresh(refresh_token) {
  const db = await dbPromise;
  const match = typeof refresh_token === 'string' ? /^([0-9a-f-]{36})\.[0-9a-f]{64}$/.exec(refresh_token) : null;
  const session = match ? await db.get(`SELECT * FROM sessions WHERE id = ?`, match[1]) : null;
  if (!session || !safeEqualHex(hashSecret(refresh_token), session.refresh_token_hash)) {
    return fail(401, 'invalid_token', 'Invalid refresh token');
  }
  if (Date.parse(session.expires_at) < nowMs()) {
    return fail(401, 'token_expired', 'Refresh token expired');
  }
  const user = await db.get(`SELECT * FROM users WHERE id = ?`, session.user_id);
  if (!user || ['suspended', 'banned'].includes(user.status)) {
    return fail(403, 'user_banned', 'User banned');
  }
  const newToken = generateToken(user);
  logWhyChain('token_refresh', ['token_valid', 'user_active']);
  await logAudit({ actor_id: user.id, action: 'token_refreshed', resource_type: 'session', resource_id: session.id, old_value: null, new_value: null });
  return { success: true, status: 'ok', token: newToken, expires_in: 900 };
}

/**
 * verify_access_token(token) -> { success, status: 'ok', user } | { error, status, message }.
 * Gates: signature (HS256 only, passed explicitly; 401 invalid_token), not expired (401 token_expired), user exists
 * and is not suspended or banned (403 user_banned). Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2:
 * statuses on errors). Touches: users (read).
 */
async function verify_access_token(token) {
  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch (e) {
    if (e.name === 'TokenExpiredError') {
      return fail(401, 'token_expired', 'Token expired');
    }
    return fail(401, 'invalid_token', 'Invalid token');
  }
  const db = await dbPromise;
  const user = await db.get(`SELECT * FROM users WHERE id = ?`, payload.user_id);
  if (!user || ['suspended', 'banned'].includes(user.status)) {
    return fail(403, 'user_banned', 'User banned');
  }
  logWhyChain('verify_access_token', ['signature_valid', 'not_expired', 'user_active']);
  return { success: true, status: 'ok', user: { id: user.id, email: user.email, tier: user.tier } };
}

function resetRateLimits() {
  rateLimits.signup.clear();
  rateLimits.loginFail.clear();
}

module.exports = {
  initDB,
  configure,
  signup,
  verify_email,
  login,
  oauth_start,
  oauth_callback,
  mfa_challenge,
  token_refresh,
  verify_access_token,
  dbPromise,
  rateLimits,
  resetRateLimits,
  sentEmails,
  hashSecret,
};

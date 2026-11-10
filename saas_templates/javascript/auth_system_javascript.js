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
const ACCESS_TOKEN_EXPIRES = '15m';
const REFRESH_TOKEN_EXPIRES_DAYS = 30;
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
      refresh_token TEXT NOT NULL,
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
      code TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      type TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);
}

function now() { return new Date().toISOString(); }

function logWhyChain(flow, decisionPoints) {
  // placeholder for logging decision chain
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

function generateCode() {
  return crypto.randomBytes(3).toString('hex'); // 6 chars
}

function generateToken(user) {
  return jwt.sign({ user_id: user.id, tier: user.tier }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES, algorithm: 'HS256' });
}

function generateRefreshToken() {
  return crypto.randomBytes(32).toString('hex');
}

async function createSession(user, ip, device_id) {
  const db = await dbPromise;
  const session_id = uuidv4();
  const refresh_token = generateRefreshToken();
  const created_at = now();
  const expires_at = new Date(Date.now() + REFRESH_TOKEN_EXPIRES_DAYS * 24 * 60 * 60 * 1000).toISOString();
  await db.run(`
    INSERT INTO sessions (id, user_id, refresh_token, created_at, expires_at, ip, device_id)
    VALUES (?,?,?,?,?,?,?)`,
    session_id, user.id, refresh_token, created_at, expires_at, ip, device_id);
  await logAudit({ actor_id: user.id, action: 'session_created', resource_type: 'session', resource_id: session_id, old_value: null, new_value: null });
  return { session_id, token: generateToken(user), expires_in: 900, refresh_token };
}

function isRateLimitedSignup(ip) {
  const nowTs = Date.now();
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
  const nowTs = Date.now();
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
 * signup(email, password, name, ip) -> {success, status: "pending_verification", email} | {error, ...}.
 * Gates in order: rate_limit_ip_24h, email_unique, password_strength. A weak password returns
 * {error: "password_rejected", reason} (AUTH-03, amended 2026-11-10; was "password_too_weak").
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the users, verification_codes and audit tables.
 */
async function signup(email, password, name, ip) {
  const db = await dbPromise;
  if (isRateLimitedSignup(ip)) {
    return { error: 'too_many_signups_from_ip', message: 'Rate limit exceeded' };
  }
  const existing = await db.get(`SELECT id FROM users WHERE email = ?`, email);
  if (existing) {
    return { error: 'email_already_exists', message: 'Email already registered' };
  }
  const rejected = checkPasswordStrength(password, email, name);
  if (rejected) {
    return { error: 'password_rejected', reason: rejected, message: 'Password rejected' };
  }
  const hash = await hashPassword(password);
  const user_id = uuidv4();
  await db.run(`
    INSERT INTO users (id, email, password_hash, tier, status, mfa_enabled)
    VALUES (?,?,?,?,?,?)`,
    user_id, email, hash, 'free', 'unverified', 0);
  logWhyChain('signup', ['email_unique', 'password_strength', 'rate_limit_ip_24h']);
  await logAudit({ actor_id: user_id, action: 'user_created', resource_type: 'user', resource_id: user_id, old_value: null, new_value: null });
  // create verification code
  const code = generateCode();
  const code_id = uuidv4();
  const created_at = now();
  const expires_at = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  await db.run(`
    INSERT INTO verification_codes (id, user_id, code, created_at, expires_at, type)
    VALUES (?,?,?,?,?,?)`,
    code_id, user_id, code, created_at, expires_at, 'email');
  // simulate email send by storing code
  return { success: true, status: 'pending_verification', email, message: 'check email' };
}

async function verify_email(email, code) {
  const db = await dbPromise;
  const user = await db.get(`SELECT * FROM users WHERE email = ?`, email);
  if (!user) return { error: 'invalid_code', message: 'Invalid code' };
  if (user.email_verified_at) return { error: 'already_verified', message: 'Already verified' };
  const record = await db.get(`
    SELECT * FROM verification_codes WHERE user_id = ? AND code = ? AND type = 'email'`,
    user.id, code);
  if (!record) return { error: 'invalid_code', message: 'Invalid code' };
  if (new Date(record.expires_at) < new Date()) {
    return { error: 'code_expired', message: 'Code expired' };
  }
  await db.run(`UPDATE users SET email_verified_at = ? WHERE id = ?`, now(), user.id);
  await db.run(`DELETE FROM verification_codes WHERE id = ?`, record.id);
  logWhyChain('verify_email', ['code_valid', 'user_unverified']);
  await logAudit({ actor_id: user.id, action: 'email_verified', resource_type: 'user', resource_id: user.id, old_value: null, new_value: null });
  return { success: true, status: 'verified', user_id: user.id, message: 'ready to login' };
}

async function login(email, password, device_id, ip) {
  const db = await dbPromise;
  const user = await db.get(`SELECT * FROM users WHERE email = ?`, email);
  if (!user || !user.email_verified_at) {
    return { error: 'invalid_credentials', message: 'Invalid credentials' };
  }
  const pwdOk = await verifyPassword(password, user.password_hash);
  if (!pwdOk) {
    if (isRateLimitedLogin(ip, user.id)) {
      return { error: 'too_many_attempts', message: 'Too many failed attempts' };
    }
    return { error: 'invalid_credentials', message: 'Invalid credentials' };
  }
  clearLoginFail(ip, user.id);
  if (user.mfa_enabled) {
    const challenge_id = uuidv4();
    const code = speakeasy.totp({ secret: user.mfa_secret, encoding: 'base32' });
    const created_at = now();
    const expires_at = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    await db.run(`
      INSERT INTO verification_codes (id, user_id, code, created_at, expires_at, type)
      VALUES (?,?,?,?,?,?)`,
      challenge_id, user.id, code, created_at, expires_at, 'mfa');
    logWhyChain('login', ['user_exists', 'password_correct', 'mfa_gate', 'rate_limit']);
    await logAudit({ actor_id: user.id, action: 'mfa_challenge_created', resource_type: 'challenge', resource_id: challenge_id, old_value: null, new_value: null });
    return { success: true, status: 'mfa_required', challenge_id };
  }
  const session = await createSession(user, ip, device_id);
  logWhyChain('login', ['user_exists', 'password_correct', 'mfa_gate', 'rate_limit']);
  return { success: true, status: 'authenticated', session_id: session.session_id, token: session.token, expires_in: session.expires_in, user: { id: user.id, email: user.email, tier: user.tier } };
}

async function oauth_callback(provider, code, state, ip, device_id) {
  const db = await dbPromise;
  // For simplicity, assume provider returns email in code (mock)
  const email = code; // in real case, exchange code for token and get email
  const user = await db.get(`SELECT * FROM users WHERE email = ?`, email);
  let user_id;
  if (!user) {
    user_id = uuidv4();
    await db.run(`
      INSERT INTO users (id, email, tier, status, mfa_enabled)
      VALUES (?,?,?,?,?)`,
      user_id, email, 'free', 'verified', 0);
    await logAudit({ actor_id: user_id, action: 'user_created', resource_type: 'user', resource_id: user_id, old_value: null, new_value: null });
  } else {
    user_id = user.id;
  }
  // link provider - omitted for brevity
  const session = await createSession({ id: user_id, tier: 'free' }, ip, device_id);
  logWhyChain('oauth_callback', ['state_valid', 'email_verified']);
  await logAudit({ actor_id: user_id, action: 'oauth_login', resource_type: 'user', resource_id: user_id, old_value: null, new_value: null });
  return { success: true, status: 'authenticated', session_id: session.session_id, token: session.token, user: { id: user_id, email, tier: 'free' } };
}

async function mfa_challenge(challenge_id, code, ip, device_id) {
  const db = await dbPromise;
  const record = await db.get(`
    SELECT * FROM verification_codes WHERE id = ? AND type = 'mfa'`, challenge_id);
  if (!record) return { error: 'invalid_code', message: 'Invalid challenge' };
  if (new Date(record.expires_at) < new Date()) {
    return { error: 'code_expired', message: 'Challenge expired' };
  }
  if (record.code !== code) {
    return { error: 'invalid_code', message: 'Invalid code' };
  }
  const user = await db.get(`SELECT * FROM users WHERE id = ?`, record.user_id);
  await db.run(`DELETE FROM verification_codes WHERE id = ?`, challenge_id);
  const session = await createSession(user, ip, device_id);
  logWhyChain('mfa_challenge', ['challenge_valid', 'code_correct']);
  await logAudit({ actor_id: user.id, action: 'mfa_verified', resource_type: 'user', resource_id: user.id, old_value: null, new_value: null });
  return { success: true, status: 'authenticated', session_id: session.session_id, token: session.token, expires_in: session.expires_in, user: { id: user.id, email: user.email, tier: user.tier } };
}

async function token_refresh(refresh_token) {
  const db = await dbPromise;
  const session = await db.get(`
    SELECT * FROM sessions WHERE refresh_token = ?`, refresh_token);
  if (!session) return { error: 'invalid_token', message: 'Invalid refresh token' };
  if (new Date(session.expires_at) < new Date()) {
    return { error: 'token_expired', message: 'Refresh token expired' };
  }
  const user = await db.get(`SELECT * FROM users WHERE id = ?`, session.user_id);
  if (!user || ['suspended', 'banned'].includes(user.status)) {
    return { error: 'user_banned', message: 'User banned' };
  }
  const newToken = generateToken(user);
  logWhyChain('token_refresh', ['token_valid', 'user_active']);
  await logAudit({ actor_id: user.id, action: 'token_refreshed', resource_type: 'session', resource_id: session.id, old_value: null, new_value: null });
  return { success: true, status: 'ok', token: newToken, expires_in: 900 };
}

async function verify_access_token(token) {
  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch (e) {
    if (e.name === 'TokenExpiredError') {
      return { error: 'token_expired', message: 'Token expired' };
    }
    return { error: 'invalid_token', message: 'Invalid token' };
  }
  const db = await dbPromise;
  const user = await db.get(`SELECT * FROM users WHERE id = ?`, payload.user_id);
  if (!user || ['suspended', 'banned'].includes(user.status)) {
    return { error: 'user_banned', message: 'User banned' };
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
  signup,
  verify_email,
  login,
  oauth_callback,
  mfa_challenge,
  token_refresh,
  verify_access_token,
  dbPromise,
  rateLimits,
  resetRateLimits
};

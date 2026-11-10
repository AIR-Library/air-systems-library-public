'use strict';

const crypto = require('crypto');
const bcrypt = require('bcrypt');

const BCRYPT_ROUNDS = 10;
const GRACE_PERIOD_MS = 24 * 60 * 60 * 1000;
const RATE_WINDOW_MS = 60 * 60 * 1000;

const SCOPES = {
  READ_USERS: 'read:users',
  WRITE_USERS: 'write:users',
  READ_DEPLOYMENTS: 'read:deployments',
  WRITE_DEPLOYMENTS: 'write:deployments',
  READ_INVOICES: 'read:invoices',
  WRITE_BILLING: 'write:billing',
  WEBHOOK_MANAGE: 'webhook:manage',
  ALL: '*',
};

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  key_secret_hash TEXT NOT NULL,
  scopes TEXT NOT NULL,
  rate_limit INTEGER NOT NULL DEFAULT 1000,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  rotated_at TEXT,
  grace_period_ends_at TEXT,
  previous_key_secret_hash TEXT
);

CREATE TABLE IF NOT EXISTS api_key_usage (
  id TEXT PRIMARY KEY,
  api_key_id TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  method TEXT NOT NULL,
  status INTEGER NOT NULL,
  timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_key_time ON api_key_usage(api_key_id, timestamp);
`;

class ApiKeyError extends Error {
  constructor(status, message, code) {
    super(message);
    this.name = 'ApiKeyError';
    this.status = status;
    this.code = code;
  }
}

function nowIso() {
  return new Date().toISOString();
}

function generateKey(env) {
  const prefix = env === 'test' ? 'sk_test_' : 'sk_live_';
  const rand = crypto.randomBytes(24).toString('base64url');
  return prefix + rand;
}

function generateId() {
  return 'key_' + crypto.randomBytes(12).toString('hex');
}

function generateUsageId() {
  return 'use_' + crypto.randomBytes(12).toString('hex');
}

function parseScopes(raw) {
  if (Array.isArray(raw)) return raw;
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      return [];
    }
  }
  return [];
}

function serializeScopes(scopes) {
  return JSON.stringify(scopes);
}

function scopeMatches(required, granted) {
  if (granted.includes(SCOPES.ALL)) return true;
  return granted.includes(required);
}

function requiredScopeFor(method, path) {
  const m = String(method).toUpperCase();
  const p = String(path).replace(/\/+$/, '');
  const seg = p.split('/').filter(Boolean);
  const resource = seg[0] || '';
  const isWrite = m === 'POST' || m === 'PUT' || m === 'PATCH' || m === 'DELETE';

  if (resource === 'users') {
    return isWrite ? SCOPES.WRITE_USERS : SCOPES.READ_USERS;
  }
  if (resource === 'deployments') {
    return isWrite ? SCOPES.WRITE_DEPLOYMENTS : SCOPES.READ_DEPLOYMENTS;
  }
  if (resource === 'invoices') {
    return isWrite ? SCOPES.WRITE_BILLING : SCOPES.READ_INVOICES;
  }
  if (resource === 'billing' || resource === 'subscriptions') {
    return SCOPES.WRITE_BILLING;
  }
  if (resource === 'webhooks') {
    return SCOPES.WEBHOOK_MANAGE;
  }
  return null;
}

class InMemoryStore {
  constructor() {
    this.keys = new Map();
    this.usage = [];
    this.rateCounters = new Map();
  }

  insertKey(record) {
    this.keys.set(record.id, record);
    return record;
  }

  findKey(id) {
    return this.keys.get(id) || null;
  }

  updateKey(id, patch) {
    const rec = this.keys.get(id);
    if (!rec) return null;
    Object.assign(rec, patch);
    return rec;
  }

  listKeys() {
    return Array.from(this.keys.values());
  }

  addUsage(record) {
    this.usage.push(record);
    return record;
  }

  listUsage(keyId, from, to) {
    const fromMs = from ? new Date(from).getTime() : -Infinity;
    const toMs = to ? new Date(to).getTime() : Infinity;
    return this.usage.filter((u) => {
      if (u.api_key_id !== keyId) return false;
      const t = new Date(u.timestamp).getTime();
      return t >= fromMs && t <= toMs;
    });
  }

  incrementRate(keyId, windowStartMs) {
    const k = keyId + ':' + windowStartMs;
    const cur = this.rateCounters.get(k) || 0;
    const next = cur + 1;
    this.rateCounters.set(k, next);
    return next;
  }

  getRate(keyId, windowStartMs) {
    return this.rateCounters.get(keyId + ':' + windowStartMs) || 0;
  }
}

class ApiKeyService {
  constructor(options) {
    options = options || {};
    this.store = options.store || new InMemoryStore();
    this.env = options.env || 'live';
    this.now = options.now || nowIso;
    this.bcryptRounds = options.bcryptRounds || BCRYPT_ROUNDS;
  }

  async createKey(userId, payload) {
    if (!userId) throw new ApiKeyError(400, 'user_id is required', 'USER_REQUIRED');
    if (!payload || !payload.name) throw new ApiKeyError(400, 'name is required', 'NAME_REQUIRED');
    if (!Array.isArray(payload.scopes) || payload.scopes.length === 0) {
      throw new ApiKeyError(400, 'scopes must be a non-empty array', 'SCOPES_REQUIRED');
    }
    const rateLimit = payload.rate_limit != null ? Number(payload.rate_limit) : 1000;
    if (!Number.isFinite(rateLimit) || rateLimit <= 0) {
      throw new ApiKeyError(400, 'rate_limit must be a positive number', 'BAD_RATE_LIMIT');
    }
    let expiresAt = null;
    if (payload.expires_at) {
      const d = new Date(payload.expires_at);
      if (isNaN(d.getTime())) throw new ApiKeyError(400, 'invalid expires_at', 'BAD_EXPIRES');
      expiresAt = d.toISOString();
    }

    const key = generateKey(this.env);
    const hash = await bcrypt.hash(key, this.bcryptRounds);
    const createdAt = this.now();
    const id = generateId();

    const record = {
      id,
      user_id: userId,
      name: payload.name,
      key_secret_hash: hash,
      scopes: serializeScopes(payload.scopes),
      rate_limit: rateLimit,
      expires_at: expiresAt,
      created_at: createdAt,
      last_used_at: null,
      is_active: true,
      rotated_at: null,
      grace_period_ends_at: null,
      previous_key_secret_hash: null,
    };
    this.store.insertKey(record);

    return {
      api_key_id: id,
      key,
      created_at: createdAt,
      expires_at: expiresAt,
      rate_limit: rateLimit,
    };
  }

  /**
   * The caller's own key record, or a 404 for a key that does not exist or belongs to someone else (the same answer,
   * so a caller cannot probe other users' key ids). In: key id, the VERIFIED caller's user id (from the auth layer,
   * never the request body). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: revoke, rotate and usage took any key id
   * from any caller. Touches: the store (read).
   */
  _ownedKey(apiKeyId, callerUserId) {
    if (callerUserId == null || callerUserId === '') throw new ApiKeyError(401, 'Authentication required', 'AUTH_REQUIRED');
    const rec = this.store.findKey(apiKeyId);
    if (!rec || rec.user_id !== callerUserId) throw new ApiKeyError(404, 'API key not found', 'NOT_FOUND');
    return rec;
  }

  /**
   * listKeys(userId) -> { keys }: the keys of ONE user (the verified caller), never the secret.
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] a missing user id is 401; it used to list every user's keys.
   * Touches: the store (read).
   */
  listKeys(userId) {
    if (userId == null || userId === '') throw new ApiKeyError(401, 'Authentication required', 'AUTH_REQUIRED');
    const filtered = this.store.listKeys().filter((k) => k.user_id === userId);
    return {
      keys: filtered.map((k) => ({
        api_key_id: k.id,
        name: k.name,
        scopes: parseScopes(k.scopes),
        created_at: k.created_at,
        last_used_at: k.last_used_at,
        rate_limit: k.rate_limit,
        is_active: k.is_active,
      })),
    };
  }

  /**
   * revokeKey(apiKeyId, callerUserId) -> { success, revoked_at }: revokes one of the caller's own keys (KEYS-03).
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] owner check added (404 for anyone else's key). Touches: the store.
   */
  revokeKey(apiKeyId, callerUserId) {
    this._ownedKey(apiKeyId, callerUserId);
    const revokedAt = this.now();
    this.store.updateKey(apiKeyId, { is_active: false, rotated_at: revokedAt, grace_period_ends_at: null });
    return { success: true, revoked_at: revokedAt };
  }

  /**
   * rotateKey(apiKeyId, callerUserId) -> { new_key, old_key_revoked_at, grace_period_ends_at } for one of the caller's
   * own keys (KEYS-06). [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] owner check added. Touches: the store.
   */
  async rotateKey(apiKeyId, callerUserId) {
    const rec = this._ownedKey(apiKeyId, callerUserId);
    const nowMs = new Date(this.now()).getTime();
    // A revoked key stays revoked, and one grace period at a time: a second rotation would end the first one's early
    // for clients still on the original key (2026-11-08, session f3daac6e, from review).
    if (!rec.is_active) throw new ApiKeyError(409, 'API key is revoked', 'REVOKED');
    if (rec.grace_period_ends_at && new Date(rec.grace_period_ends_at).getTime() > nowMs) {
      throw new ApiKeyError(409, 'The previous rotation is still in its grace period', 'ROTATION_IN_PROGRESS');
    }
    const oldKeyRevokedAt = this.now();
    const gracePeriodEndsAt = new Date(nowMs + GRACE_PERIOD_MS).toISOString();
    const newKey = generateKey(this.env);
    const newHash = await bcrypt.hash(newKey, this.bcryptRounds);
    // Hashing yields to other requests. If the key was revoked or rotated meanwhile, writing now would undo that.
    const current = this.store.findKey(apiKeyId);
    if (!current || !current.is_active || current.key_secret_hash !== rec.key_secret_hash) {
      throw new ApiKeyError(409, 'API key changed during rotation', 'CONFLICT');
    }
    const oldHash = rec.key_secret_hash;
    this.store.updateKey(apiKeyId, {
      key_secret_hash: newHash,
      previous_key_secret_hash: oldHash,
      is_active: true,
      rotated_at: oldKeyRevokedAt,
      grace_period_ends_at: gracePeriodEndsAt,
    });
    return {
      new_key: newKey,
      old_key_revoked_at: oldKeyRevokedAt,
      grace_period_ends_at: gracePeriodEndsAt,
    };
  }

  async authenticate(apiKey, method, path) {
    if (!apiKey) throw new ApiKeyError(401, 'Missing API key', 'MISSING_KEY');
    const record = await this._findKeyBySecret(apiKey);
    if (!record) throw new ApiKeyError(401, 'Invalid API key', 'INVALID_KEY');

    const nowMs = new Date(this.now()).getTime();

    if (!record.is_active) {
      const inGrace = record.grace_period_ends_at && new Date(record.grace_period_ends_at).getTime() > nowMs;
      if (!inGrace) {
        this._logUsage(record.id, method, path, 401);
        throw new ApiKeyError(401, 'API key revoked', 'REVOKED');
      }
    }

    if (record.expires_at && new Date(record.expires_at).getTime() <= nowMs) {
      this._logUsage(record.id, method, path, 401);
      throw new ApiKeyError(401, 'API key expired', 'EXPIRED');
    }

    const required = requiredScopeFor(method, path);
    if (required) {
      const granted = parseScopes(record.scopes);
      if (!scopeMatches(required, granted)) {
        this._logUsage(record.id, method, path, 403);
        throw new ApiKeyError(403, 'Insufficient scope', 'FORBIDDEN');
      }
    }

    const windowStart = Math.floor(nowMs / RATE_WINDOW_MS) * RATE_WINDOW_MS;
    const count = this.store.incrementRate(record.id, windowStart);
    if (count > record.rate_limit) {
      this._logUsage(record.id, method, path, 429);
      throw new ApiKeyError(429, 'Rate limit exceeded', 'RATE_LIMITED');
    }

    this.store.updateKey(record.id, { last_used_at: this.now() });
    return { record, count };
  }

  async _findKeyBySecret(secret) {
    const all = this.store.listKeys();
    const nowMs = new Date(this.now()).getTime();
    for (const rec of all) {
      const match = await bcrypt.compare(secret, rec.key_secret_hash);
      if (match) return rec;
      if (rec.previous_key_secret_hash && rec.grace_period_ends_at) {
        const graceEndsMs = new Date(rec.grace_period_ends_at).getTime();
        if (nowMs < graceEndsMs) {
          const oldMatch = await bcrypt.compare(secret, rec.previous_key_secret_hash);
          if (oldMatch) return rec;
        }
      }
    }
    return null;
  }

  _logUsage(keyId, method, path, status) {
    this.store.addUsage({
      id: generateUsageId(),
      api_key_id: keyId,
      endpoint: path,
      method: String(method).toUpperCase(),
      status,
      timestamp: this.now(),
    });
  }

  logSuccess(keyId, method, path, status) {
    this._logUsage(keyId, method, path, status || 200);
  }

  /**
   * getUsageStats(apiKeyId, from, to, callerUserId) -> usage of one of the caller's own keys (KEYS-08).
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] owner check added. Touches: the store (read).
   */
  getUsageStats(apiKeyId, from, to, callerUserId) {
    this._ownedKey(apiKeyId, callerUserId);
    const rows = this.store.listUsage(apiKeyId, from, to);
    const byEndpoint = {};
    const errors = {};
    let rateLimitHits = 0;
    for (const r of rows) {
      const key = r.method + ' ' + r.endpoint;
      byEndpoint[key] = (byEndpoint[key] || 0) + 1;
      if (r.status === 429) rateLimitHits += 1;
      if (r.status >= 400) {
        const s = String(r.status);
        errors[s] = (errors[s] || 0) + 1;
      }
    }
    return {
      api_key_id: apiKeyId,
      total_requests: rows.length,
      requests_by_endpoint: byEndpoint,
      rate_limit_hits: rateLimitHits,
      errors,
    };
  }

  /**
   * adminListKeys(filters, caller) -> { keys, total }: every key for audit (KEYS-09), admin only.
   * In: { userId, status: 'active'|'inactive' }, the VERIFIED caller ({ role: 'admin' } or { is_admin: true }).
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] the admin check was missing (403 admin_only now). Touches: the store.
   */
  adminListKeys({ userId, status } = {}, caller) {
    if (!caller || (caller.role !== 'admin' && caller.is_admin !== true)) {
      throw new ApiKeyError(403, 'Admin only', 'ADMIN_ONLY');
    }
    let all = this.store.listKeys();
    if (userId) all = all.filter((k) => k.user_id === userId);
    if (status) {
      const want = status === 'active' ? true : false;
      all = all.filter((k) => k.is_active === want);
    }
    return {
      keys: all.map((k) => ({
        api_key_id: k.id,
        user_id: k.user_id,
        name: k.name,
        scopes: parseScopes(k.scopes),
        created_at: k.created_at,
        last_used_at: k.last_used_at,
        rate_limit: k.rate_limit,
        is_active: k.is_active,
        expires_at: k.expires_at,
      })),
      total: all.length,
    };
  }

  runExpiryCron() {
    const nowMs = new Date(this.now()).getTime();
    let expired = 0;
    for (const rec of this.store.listKeys()) {
      if (rec.is_active && rec.expires_at && new Date(rec.expires_at).getTime() <= nowMs) {
        this.store.updateKey(rec.id, { is_active: false });
        expired += 1;
      }
    }
    return { expired };
  }
}

function createService(options) {
  return new ApiKeyService(options);
}

module.exports = {
  ApiKeyService,
  ApiKeyError,
  InMemoryStore,
  SCOPES,
  SCHEMA_SQL,
  createService,
  generateKey,
  requiredScopeFor,
  scopeMatches,
  GRACE_PERIOD_MS,
  RATE_WINDOW_MS,
};

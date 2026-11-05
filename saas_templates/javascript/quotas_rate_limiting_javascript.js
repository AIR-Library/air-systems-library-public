'use strict';

const crypto = require('crypto');

const TIERS = Object.freeze({
  SOLO: 'solo',
  TEAM: 'team',
  ENTERPRISE: 'enterprise',
});

const API_CALL_LIMITS = Object.freeze({
  solo: 1000,
  team: 10000,
  enterprise: Infinity,
});

const STORAGE_LIMITS = Object.freeze({
  solo: 1e9,
  team: 100e9,
  enterprise: -1,
});

const RATE_LIMIT_PER_USER = 100;
const RATE_LIMIT_PER_IP = 10;

const FEATURE_TIERS = Object.freeze({
  feature_a: ['team', 'enterprise'],
  feature_b: ['enterprise'],
  feature_c: ['solo', 'team', 'enterprise'],
});

const TIER_ORDER = Object.freeze({
  solo: 0,
  team: 1,
  enterprise: 2,
});

const DDL = `
CREATE TABLE IF NOT EXISTS usage_metrics (
  user_id TEXT NOT NULL,
  month TEXT NOT NULL,
  call_count INTEGER NOT NULL DEFAULT 0,
  storage_bytes INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (user_id, month)
);

CREATE TABLE IF NOT EXISTS api_calls (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  ip TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  status_code INTEGER NOT NULL,
  response_time_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_calls_user_time ON api_calls (user_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_api_calls_ip_time ON api_calls (ip, timestamp);
`;

class QuotaError extends Error {
  constructor(statusCode, body) {
    super(body.error || 'quota_error');
    this.name = 'QuotaError';
    this.statusCode = statusCode;
    this.body = body;
  }
}

class InMemoryStore {
  constructor() {
    this.usageMetrics = new Map();
    this.apiCalls = [];
    this.files = new Map();
    this.users = new Map();
  }

  upsertUser(user) {
    this.users.set(user.user_id, { ...user });
  }

  getUser(userId) {
    return this.users.get(userId) || null;
  }

  getUsage(userId, month) {
    const key = `${userId}|${month}`;
    if (!this.usageMetrics.has(key)) {
      this.usageMetrics.set(key, {
        user_id: userId,
        month,
        call_count: 0,
        storage_bytes: 0,
        updated_at: new Date().toISOString(),
      });
    }
    return this.usageMetrics.get(key);
  }

  incrementCalls(userId, month, amount = 1) {
    const row = this.getUsage(userId, month);
    row.call_count += amount;
    row.updated_at = new Date().toISOString();
    return row;
  }

  addStorage(userId, month, bytes) {
    const row = this.getUsage(userId, month);
    row.storage_bytes += bytes;
    row.updated_at = new Date().toISOString();
    return row;
  }

  recordCall({ userId, ip, endpoint, timestamp, statusCode, responseTimeMs }) {
    const id = crypto.randomUUID();
    const row = {
      id,
      user_id: userId,
      ip,
      endpoint,
      timestamp: timestamp instanceof Date ? timestamp.toISOString() : timestamp,
      status_code: statusCode,
      response_time_ms: responseTimeMs,
    };
    this.apiCalls.push(row);
    return row;
  }

  countCallsForUserSince(userId, sinceIso) {
    return this.apiCalls.filter(
      (c) => c.user_id === userId && c.timestamp > sinceIso
    ).length;
  }

  countCallsForIpSince(ip, sinceIso) {
    return this.apiCalls.filter(
      (c) => c.ip === ip && c.timestamp > sinceIso
    ).length;
  }

  addFile(userId, file) {
    const list = this.files.get(userId) || [];
    list.push(file);
    this.files.set(userId, list);
  }

  totalStorageForUser(userId) {
    const list = this.files.get(userId) || [];
    return list.reduce((sum, f) => sum + f.size, 0);
  }

  clear() {
    this.usageMetrics.clear();
    this.apiCalls = [];
    this.files.clear();
    this.users.clear();
  }
}

class QuotaManager {
  constructor(options = {}) {
    this.store = options.store || new InMemoryStore();
    this.now = options.now || (() => new Date());
    this.log = options.log || (() => {});
  }

  _monthKey(date) {
    const d = date instanceof Date ? date : new Date(date);
    return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
  }

  _resetDateForMonth(monthKey) {
    const [y, m] = monthKey.split('-').map(Number);
    const next = new Date(Date.UTC(y, m, 1));
    return next.toISOString();
  }

  _logWhyChain(gate, payload) {
    this.log({ gate, ...payload });
  }

  checkApiCallQuota(userId, tier) {
    const now = this.now();
    const month = this._monthKey(now);
    const usage = this.store.getUsage(userId, month);
    const limit = API_CALL_LIMITS[tier];
    const current = usage.call_count;
    const pass = limit === Infinity || current + 1 <= limit;

    this._logWhyChain('api_quota_check', {
      user_id: userId,
      tier,
      current_usage: current,
      limit,
      pass,
    });

    if (!pass) {
      throw new QuotaError(429, {
        error: 'quota_exceeded',
        current: current,
        limit,
        reset_date: this._resetDateForMonth(month),
      });
    }

    this.store.incrementCalls(userId, month, 1);
    return { pass: true, current: current + 1, limit };
  }

  checkStorageQuota(userId, tier, incomingBytes) {
    const now = this.now();
    const month = this._monthKey(now);
    const usage = this.store.getUsage(userId, month);
    const limit = STORAGE_LIMITS[tier];
    const current = usage.storage_bytes;
    const pass = limit === -1 || current + incomingBytes <= limit;

    this._logWhyChain('storage_quota_check', {
      user_id: userId,
      tier,
      current_usage: current,
      limit,
      incoming: incomingBytes,
      pass,
    });

    if (!pass) {
      throw new QuotaError(413, {
        error: 'storage_quota_exceeded',
        current,
        limit,
      });
    }

    this.store.addStorage(userId, month, incomingBytes);
    return { pass: true, current: current + incomingBytes, limit };
  }

  checkRateLimitPerUser(userId, ip, endpoint, record = true) {
    const now = this.now();
    const since = new Date(now.getTime() - 60 * 1000);
    const count = this.store.countCallsForUserSince(userId, since.toISOString());
    const pass = count < RATE_LIMIT_PER_USER;

    if (!pass) {
      if (record) {
        this.store.recordCall({
          userId,
          ip,
          endpoint,
          timestamp: now,
          statusCode: 429,
          responseTimeMs: 0,
        });
      }
      throw new QuotaError(429, {
        error: 'rate_limit_exceeded',
        reset_seconds: 60,
      });
    }

    if (record) {
      this.store.recordCall({
        userId,
        ip,
        endpoint,
        timestamp: now,
        statusCode: 200,
        responseTimeMs: 0,
      });
    }
    return { pass: true, count: count + 1, limit: RATE_LIMIT_PER_USER };
  }

  checkRateLimitPerIp(ip, userId, endpoint, record = true) {
    const now = this.now();
    const since = new Date(now.getTime() - 1000);
    const count = this.store.countCallsForIpSince(ip, since.toISOString());
    const pass = count < RATE_LIMIT_PER_IP;

    if (!pass) {
      if (record) {
        this.store.recordCall({
          userId,
          ip,
          endpoint,
          timestamp: now,
          statusCode: 429,
          responseTimeMs: 0,
        });
      }
      throw new QuotaError(429, {
        error: 'ip_rate_limit_exceeded',
        reset_seconds: 1,
      });
    }

    if (record) {
      this.store.recordCall({
        userId,
        ip,
        endpoint,
        timestamp: now,
        statusCode: 200,
        responseTimeMs: 0,
      });
    }
    return { pass: true, count: count + 1, limit: RATE_LIMIT_PER_IP };
  }

  checkFeatureGate(userId, tier, feature) {
    const allowed = FEATURE_TIERS[feature];
    if (!allowed) {
      throw new QuotaError(404, {
        error: 'feature_not_found',
        feature,
      });
    }
    const pass = allowed.includes(tier);

    this._logWhyChain('feature_gate', {
      user_id: userId,
      feature,
      tier,
      allowed_tiers: allowed,
      pass,
    });

    if (!pass) {
      const minTier = allowed[0];
      throw new QuotaError(403, {
        error: 'feature_not_available_in_tier',
        tier,
        minimum_tier: minTier,
        upgrade_url: `/upgrade?from=${tier}&to=${minTier}`,
      });
    }

    return { pass: true, feature, tier, allowed_tiers: allowed };
  }

  handleApiRequest({ userId, ip, endpoint, tier }) {
    const now = this.now();
    try {
      this.checkRateLimitPerIp(ip, userId, endpoint, false);
      this.checkRateLimitPerUser(userId, ip, endpoint, false);
      this.checkApiCallQuota(userId, tier);
      this.store.recordCall({
        userId,
        ip,
        endpoint,
        timestamp: now,
        statusCode: 200,
        responseTimeMs: 0,
      });
      return { status: 200, body: { ok: true } };
    } catch (e) {
      if (e instanceof QuotaError) {
        this.store.recordCall({
          userId,
          ip,
          endpoint,
          timestamp: now,
          statusCode: e.statusCode,
          responseTimeMs: 0,
        });
      }
      throw e;
    }
  }

  handleFileUpload({ userId, tier, fileName, size }) {
    this.checkStorageQuota(userId, tier, size);
    this.store.addFile(userId, { name: fileName, size, uploaded_at: this.now().toISOString() });
    return { status: 200, body: { ok: true, file: fileName, size } };
  }

  handleFeatureAccess({ userId, tier, feature }) {
    this.checkFeatureGate(userId, tier, feature);
    return { status: 200, body: { ok: true, feature } };
  }
}

module.exports = {
  QuotaManager,
  QuotaError,
  InMemoryStore,
  TIERS,
  API_CALL_LIMITS,
  STORAGE_LIMITS,
  RATE_LIMIT_PER_USER,
  RATE_LIMIT_PER_IP,
  FEATURE_TIERS,
  TIER_ORDER,
  DDL,
};

import { Database, open } from 'sqlite';
import sqlite3 from 'sqlite3';
import { createHash, randomBytes } from 'crypto';
import bcrypt from 'bcryptjs';
import Redis from 'ioredis';
import { v4 as uuidv4 } from 'uuid';

export type Scope = string;
export type ApiKey = {
  api_key_id: string;
  user_id: string;
  name: string;
  key_secret_hash: string;
  scopes: Scope[];
  rate_limit: number;
  expires_at: string | null;
  created_at: string;
  last_used_at: string | null;
  is_active: boolean;
};

export type ApiKeyUsage = {
  id: string;
  api_key_id: string;
  endpoint: string;
  method: string;
  status: number;
  timestamp: string;
};

export type CreateApiKeyRequest = {
  user_id: string;
  name: string;
  scopes: Scope[];
  expires_at?: string;
  rate_limit?: number;
};

export type CreateApiKeyResponse = {
  api_key_id: string;
  key: string;
  created_at: string;
  expires_at: string | null;
  rate_limit: number;
};

export type ListApiKeysResponse = {
  keys: {
    api_key_id: string;
    name: string;
    scopes: Scope[];
    created_at: string;
    last_used_at: string | null;
    rate_limit: number;
    is_active: boolean;
  }[];
};

export type RevokeApiKeyResponse = {
  success: boolean;
  revoked_at: string;
};

export type RotateApiKeyResponse = {
  new_key: string;
  old_key_revoked_at: string;
  grace_period_ends_at: string;
};

export type UsageStatsResponse = {
  api_key_id: string;
  total_requests: number;
  requests_by_endpoint: Record<string, number>;
  rate_limit_hits: number;
  errors: Record<string, number>;
};

export type AdminListApiKeysResponse = {
  keys: {
    api_key_id: string;
    user_id: string;
    name: string;
    scopes: Scope[];
    created_at: string;
    last_used_at: string | null;
    rate_limit: number;
    is_active: boolean;
  }[];
  total: number;
};

export class ApiKeyService {
  private db!: Database<sqlite3.Database, sqlite3.Statement>;
  private redis!: Redis.Redis;
  private readonly redisPrefix = 'api_key_rate_limit:';
  private readonly gracePeriodMs = 24 * 60 * 60 * 1000; // 24h

  async init(dbPath = ':memory:', redisOptions?: Redis.RedisOptions) {
    this.db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    await this.db.exec(`
      CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        name TEXT NOT NULL,
        key_secret_hash TEXT NOT NULL,
        scopes TEXT NOT NULL,
        rate_limit INTEGER NOT NULL,
        expires_at TEXT,
        created_at TEXT NOT NULL,
        last_used_at TEXT,
        is_active INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS api_key_usage (
        id TEXT PRIMARY KEY,
        api_key_id TEXT NOT NULL,
        endpoint TEXT NOT NULL,
        method TEXT NOT NULL,
        status INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY(api_key_id) REFERENCES api_keys(id)
      );
    `);
    this.redis = new Redis(redisOptions);
  }

  private generateKey(): string {
    const prefix = 'sk_live_';
    const random = randomBytes(16).toString('hex');
    return `${prefix}${random}`;
  }

  async createApiKey(req: CreateApiKeyRequest): Promise<CreateApiKeyResponse> {
    const api_key_id = uuidv4();
    const key = this.generateKey();
    const key_secret_hash = await bcrypt.hash(key, 10);
    const scopes = JSON.stringify(req.scopes);
    const rate_limit = req.rate_limit ?? 1000;
    const expires_at = req.expires_at ?? null;
    const created_at = new Date().toISOString();
    await this.db.run(
      `INSERT INTO api_keys (id, user_id, name, key_secret_hash, scopes, rate_limit, expires_at, created_at, is_active)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`,
      api_key_id,
      req.user_id,
      req.name,
      key_secret_hash,
      scopes,
      rate_limit,
      expires_at,
      created_at
    );
    return {
      api_key_id,
      key,
      created_at,
      expires_at,
      rate_limit,
    };
  }

  async listApiKeys(user_id: string): Promise<ListApiKeysResponse> {
    const rows = await this.db.all(
      `SELECT id, name, scopes, created_at, last_used_at, rate_limit, is_active
       FROM api_keys WHERE user_id = ?`,
      user_id
    );
    return {
      keys: rows.map((r) => ({
        api_key_id: r.id,
        name: r.name,
        scopes: JSON.parse(r.scopes),
        created_at: r.created_at,
        last_used_at: r.last_used_at,
        rate_limit: r.rate_limit,
        is_active: !!r.is_active,
      })),
    };
  }

  async revokeApiKey(api_key_id: string): Promise<RevokeApiKeyResponse> {
    const revoked_at = new Date().toISOString();
    await this.db.run(
      `UPDATE api_keys SET is_active = 0, last_used_at = ? WHERE id = ?`,
      revoked_at,
      api_key_id
    );
    return { success: true, revoked_at };
  }

  async rotateApiKey(api_key_id: string): Promise<RotateApiKeyResponse> {
    const new_key = this.generateKey();
    const new_key_hash = await bcrypt.hash(new_key, 10);
    const new_id = uuidv4();
    const created_at = new Date().toISOString();
    const oldKeyRow = await this.db.get(
      `SELECT * FROM api_keys WHERE id = ?`,
      api_key_id
    );
    if (!oldKeyRow) throw new Error('API key not found');
    const old_revoked_at = new Date().toISOString();
    const grace_period_ends_at = new Date(
      Date.now() + this.gracePeriodMs
    ).toISOString();
    await this.db.run(
      `INSERT INTO api_keys (id, user_id, name, key_secret_hash, scopes, rate_limit, expires_at, created_at, is_active)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`,
      new_id,
      oldKeyRow.user_id,
      oldKeyRow.name,
      new_key_hash,
      oldKeyRow.scopes,
      oldKeyRow.rate_limit,
      oldKeyRow.expires_at,
      created_at
    );
    return {
      new_key,
      old_key_revoked_at: old_revoked_at,
      grace_period_ends_at,
    };
  }

  async validateApiKey(
    key: string,
    endpoint: string,
    method: string,
    requiredScope: Scope
  ): Promise<{ api_key_id: string; rate_limit: number }> {
    const rows = await this.db.all(
      `SELECT * FROM api_keys WHERE is_active = 1`
    );
    for (const row of rows) {
      const match = await bcrypt.compare(key, row.key_secret_hash);
      if (!match) continue;
      const now = new Date();
      if (row.expires_at && new Date(row.expires_at) < now) {
        throw { status: 401, message: 'Key expired' };
      }
      const scopes: Scope[] = JSON.parse(row.scopes);
      if (!scopes.includes(requiredScope) && !scopes.includes('*')) {
        throw { status: 403, message: 'Insufficient scope' };
      }
      const rateLimitKey = `${this.redisPrefix}${row.id}:${now
        .toISOString()
        .slice(0, 13)}`; // hour bucket
      const count = await this.redis.incr(rateLimitKey);
      if (count === 1) {
        await this.redis.expire(rateLimitKey, 3600);
      }
      if (count > row.rate_limit) {
        throw { status: 429, message: 'Rate limit exceeded' };
      }
      await this.db.run(
        `UPDATE api_keys SET last_used_at = ? WHERE id = ?`,
        now.toISOString(),
        row.id
      );
      await this.db.run(
        `INSERT INTO api_key_usage (id, api_key_id, endpoint, method, status, timestamp)
         VALUES (?, ?, ?, ?, ?, ?)`,
        uuidv4(),
        row.id,
        endpoint,
        method,
        200,
        now.toISOString()
      );
      return { api_key_id: row.id, rate_limit: row.rate_limit };
    }
    throw { status: 401, message: 'Invalid API key' };
  }

  async getUsageStats(
    api_key_id: string,
    from: string,
    to: string
  ): Promise<UsageStatsResponse> {
    const rows = await this.db.all(
      `SELECT endpoint, method, status, COUNT(*) as cnt
       FROM api_key_usage
       WHERE api_key_id = ?
         AND timestamp BETWEEN ? AND ?
       GROUP BY endpoint, method, status`,
      api_key_id,
      from,
      to
    );
    const total_requests = rows.reduce((sum, r) => sum + r.cnt, 0);
    const requests_by_endpoint: Record<string, number> = {};
    const errors: Record<string, number> = {};
    let rate_limit_hits = 0;
    for (const r of rows) {
      const key = `${r.method} ${r.endpoint}`;
      requests_by_endpoint[key] = (requests_by_endpoint[key] ?? 0) + r.cnt;
      if (r.status >= 400) {
        errors[r.status] = (errors[r.status] ?? 0) + r.cnt;
      }
      if (r.status === 429) rate_limit_hits += r.cnt;
    }
    return {
      api_key_id,
      total_requests,
      requests_by_endpoint,
      rate_limit_hits,
      errors: Object.fromEntries(
        Object.entries(errors).map(([k, v]) => [k, v])
      ),
    };
  }

  async adminListApiKeys(
    user_id?: string,
    status?: 'active' | 'revoked'
  ): Promise<AdminListApiKeysResponse> {
    const conditions: string[] = [];
    const params: any[] = [];
    if (user_id) {
      conditions.push('user_id = ?');
      params.push(user_id);
    }
    if (status) {
      conditions.push('is_active = ?');
      params.push(status === 'active' ? 1 : 0);
    }
    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const rows = await this.db.all(
      `SELECT id, user_id, name, scopes, created_at, last_used_at, rate_limit, is_active
       FROM api_keys ${where}`,
       ...params
    );
    const total = rows.length;
    return {
      keys: rows.map((r) => ({
        api_key_id: r.id,
        user_id: r.user_id,
        name: r.name,
        scopes: JSON.parse(r.scopes),
        created_at: r.created_at,
        last_used_at: r.last_used_at,
        rate_limit: r.rate_limit,
        is_active: !!r.is_active,
      })),
      total,
    };
  }

  async runExpiryJob() {
    const now = new Date().toISOString();
    await this.db.run(
      `UPDATE api_keys SET is_active = 0 WHERE expires_at IS NOT NULL AND expires_at < ? AND is_active = 1`,
      now
    );
  }
}
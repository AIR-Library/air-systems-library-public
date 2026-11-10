/**
 * API keys and service accounts (spec TIER_2 system 5): scoped `sk_live_` / `sk_test_` keys stored only as bcrypt
 * hashes, per-key hourly rate limits, revocation, rotation with a 24 h grace period, expiry, per-call usage log and
 * usage stats, and an admin listing.
 *
 * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. The suite hung until the runner killed it (300 s):
 * - its tests needed a Redis server on localhost (ioredis waits for it for ever); rate limits now go through a
 *   {@link RateLimitStore}, with {@link InMemoryRateLimitStore} for tests and single processes and
 *   {@link RedisRateLimitStore} (connects on first use) for production;
 * - every request bcrypt-checked every active key in turn (about 70 ms each), so the 1,001-request rate-limit test
 *   could not finish; a key now carries a public lookup id, so one row is checked, and a key verified once is
 *   recognised again from a SHA-256 digest compared in constant time while its stored hash is unchanged;
 * - rotation disabled the old key at once (the spec gives it 24 h), revoking overwrote last_used_at, and the admin
 *   listing dropped its parameters (the parameter fix is from community PR #10; that PR's other changes were not
 *   taken: it stopped rotation from ever disabling the old key and cut the rate-limit test to 2 requests).
 * Touches: the SQLite database (api_keys, api_key_usage), the rate-limit store (Redis over the network by default).
 * No money. Plaintext keys are returned once and never stored or logged.
 */
import { Database, open } from 'sqlite';
import sqlite3 from 'sqlite3';
import { createHash, randomBytes, timingSafeEqual } from 'crypto';
import bcrypt from 'bcryptjs';
import Redis, { RedisOptions } from 'ioredis';
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

/** An error with the HTTP status the route should answer (401, 403, 404, 409, 429). Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. */
export class ApiKeyError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiKeyError';
  }
}

/**
 * Where hourly rate-limit counters live. `increment` adds one to a counter, starting it with the given lifetime, and
 * returns the new value. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP, so tests need no Redis server.
 */
export interface RateLimitStore {
  increment(counterKey: string, ttlSeconds: number): Promise<number>;
  close?(): Promise<void>;
}

/**
 * Counters in this process's memory; expired counters are dropped as new ones are written. Right for tests and for
 * a single server process; use {@link RedisRateLimitStore} when several processes share the limit.
 * In/out: as {@link RateLimitStore}. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
 */
export class InMemoryRateLimitStore implements RateLimitStore {
  private counters = new Map<string, { value: number; expiresAt: number }>();

  constructor(private readonly now: () => number = () => Date.now()) {}

  async increment(counterKey: string, ttlSeconds: number): Promise<number> {
    const t = this.now();
    const entry = this.counters.get(counterKey);
    if (!entry || entry.expiresAt <= t) {
      if (this.counters.size > 10000) {
        for (const [k, v] of this.counters) if (v.expiresAt <= t) this.counters.delete(k);
      }
      this.counters.set(counterKey, { value: 1, expiresAt: t + ttlSeconds * 1000 });
      return 1;
    }
    entry.value += 1;
    return entry.value;
  }
}

/**
 * Counters in Redis (INCR and EXPIRE in one MULTI; the counter key names its hour, so the lifetime only cleans up), shared by every process. It connects on the first
 * request, not when created. In: ioredis options or a URL (default REDIS_URL, else localhost). Out: as
 * {@link RateLimitStore}. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: Redis (network).
 */
export class RedisRateLimitStore implements RateLimitStore {
  private readonly redis: Redis;

  constructor(options?: RedisOptions | string) {
    const target = options ?? process.env.REDIS_URL ?? 'redis://localhost:6379';
    this.redis = typeof target === 'string'
      ? new Redis(target, { lazyConnect: true })
      : new Redis({ ...target, lazyConnect: true });
  }

  async increment(counterKey: string, ttlSeconds: number): Promise<number> {
    const results = await this.redis.multi().incr(counterKey).expire(counterKey, ttlSeconds).exec();
    const [err, value] = results?.[0] ?? [new Error('rate limit counter failed'), null];
    if (err) throw err;
    return Number(value);
  }

  async close(): Promise<void> {
    await this.redis.quit();
  }
}

/**
 * Options for {@link ApiKeyService.init}: the rate-limit store (default Redis), Redis options for that default, the
 * clock (default the system clock), the bcrypt cost (default 10) and the key prefix environment ('live' or 'test').
 * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
 */
export type ApiKeyServiceOptions = {
  rateLimitStore?: RateLimitStore;
  redisOptions?: RedisOptions | string;
  now?: () => Date;
  bcryptRounds?: number;
  environment?: 'live' | 'test';
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

/** Bytes of the public lookup id and of the secret in a key (hex-encoded: 16 + 32 characters after the prefix). */
const LOOKUP_BYTES = 8;
const SECRET_BYTES = 16;
const KEY_PATTERN = /^sk_(live|test)_([0-9a-f]{16})([0-9a-f]{32})$/;
/** How many verified keys are remembered, so a busy key is not bcrypt-checked on every request. */
const VERIFIED_CACHE_LIMIT = 10000;

/**
 * The service. Call {@link ApiKeyService.init} first. Rewritten 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP
 * (see the module block). Touches: SQLite, the rate-limit store.
 */
export class ApiKeyService {
  /** The database; public so maintenance jobs (and tests) can run their own statements. */
  db!: Database<sqlite3.Database, sqlite3.Statement>;
  private rateLimits!: RateLimitStore;
  private now: () => Date = () => new Date();
  private bcryptRounds = 10;
  private environment: 'live' | 'test' = 'live';
  private readonly redisPrefix = 'api_key_rate_limit:';
  private readonly gracePeriodMs = 24 * 60 * 60 * 1000; // 24h
  /** api_key_id -> the stored bcrypt hash and the SHA-256 of the key that matched it. */
  private verified = new Map<string, { hash: string; digest: Buffer }>();

  /**
   * Opens the database, creates the tables and chooses the rate-limit store.
   * In: the SQLite path (default in-memory) and {@link ApiKeyServiceOptions}. Out: nothing.
   * Touches: SQLite (creates tables); no network until a rate limit is counted.
   */
  async init(dbPath = ':memory:', options: ApiKeyServiceOptions = {}) {
    this.db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    await this.db.exec(`
      CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        name TEXT NOT NULL,
        key_lookup TEXT NOT NULL UNIQUE,
        key_secret_hash TEXT NOT NULL,
        scopes TEXT NOT NULL,
        rate_limit INTEGER NOT NULL,
        expires_at TEXT,
        created_at TEXT NOT NULL,
        last_used_at TEXT,
        is_active INTEGER NOT NULL,
        revoked_at TEXT,
        rotated_at TEXT,
        replaced_by_id TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
      CREATE TABLE IF NOT EXISTS api_key_usage (
        id TEXT PRIMARY KEY,
        api_key_id TEXT NOT NULL,
        endpoint TEXT NOT NULL,
        method TEXT NOT NULL,
        status INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY(api_key_id) REFERENCES api_keys(id)
      );
      CREATE INDEX IF NOT EXISTS idx_api_key_usage_key_time ON api_key_usage(api_key_id, timestamp);
    `);
    this.now = options.now ?? (() => new Date());
    this.bcryptRounds = options.bcryptRounds ?? 10;
    this.environment = options.environment ?? 'live';
    this.rateLimits = options.rateLimitStore ?? new RedisRateLimitStore(options.redisOptions);
  }

  /**
   * Closes the database and the rate-limit store. In/out: nothing. Added 2026-11-10, session
   * session_012zDydZCZ4AChqhEZ4oVtaP, so nothing stays open after use. Touches: SQLite, the store.
   */
  async close(): Promise<void> {
    if (this.rateLimits?.close) await this.rateLimits.close();
    if (this.db) await this.db.close();
  }

  /**
   * A new key: "sk_live_" (or "sk_test_"), a 16-hex-character public lookup id, then a 32-hex-character secret, all
   * from the CSPRNG. In: nothing. Out: { key, lookup }. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP
   * (lookup id added). Touches: nothing.
   */
  private generateKey(): { key: string; lookup: string } {
    const lookup = randomBytes(LOOKUP_BYTES).toString('hex');
    const secret = randomBytes(SECRET_BYTES).toString('hex');
    return { key: `sk_${this.environment}_${lookup}${secret}`, lookup };
  }

  /**
   * Creates a key. In: { user_id, name, scopes, expires_at (optional; a date means 00:00 UTC that day),
   * rate_limit (requests per hour, default 1000) }. Out: { api_key_id, key (shown only here), created_at,
   * expires_at, rate_limit }. Touches: SQLite api_keys. Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
   */
  async createApiKey(req: CreateApiKeyRequest): Promise<CreateApiKeyResponse> {
    const api_key_id = uuidv4();
    const { key, lookup } = this.generateKey();
    const key_secret_hash = await bcrypt.hash(key, this.bcryptRounds);
    const scopes = JSON.stringify(req.scopes);
    const rate_limit = req.rate_limit ?? 1000;
    const expires_at = req.expires_at ?? null;
    const created_at = this.now().toISOString();
    await this.db.run(
      `INSERT INTO api_keys (id, user_id, name, key_lookup, key_secret_hash, scopes, rate_limit, expires_at, created_at, is_active)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
      api_key_id,
      req.user_id,
      req.name,
      lookup,
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

  /**
   * A user's keys, never the secret or its hash, oldest first. In: the user id. Out: { keys }.
   * Touches: SQLite. Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (stable order added).
   */
  async listApiKeys(user_id: string): Promise<ListApiKeysResponse> {
    const rows = await this.db.all(
      `SELECT id, name, scopes, created_at, last_used_at, rate_limit, is_active
       FROM api_keys WHERE user_id = ? ORDER BY created_at, rowid`,
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

  /**
   * Loads one key row, checking that it belongs to `ownerUserId` when one is given (pass the signed-in user from
   * your session, never a value from the request body). In: the key id and the optional owner. Out: the row.
   * Throws 404 when there is no such key for that owner. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: SQLite.
   */
  private async getOwnedKey(api_key_id: string, ownerUserId?: string): Promise<any> {
    const row = await this.db.get(`SELECT * FROM api_keys WHERE id = ?`, api_key_id);
    if (!row || (ownerUserId !== undefined && row.user_id !== ownerUserId)) {
      throw new ApiKeyError(404, 'API key not found');
    }
    return row;
  }

  /**
   * Revokes a key at once (also ends a rotation grace period). In: the key id and, from a route, the signed-in
   * owner. Out: { success, revoked_at }. Throws 404 for an unknown key.
   * Why changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): it wrote the revocation time into last_used_at.
   * Touches: SQLite api_keys.
   */
  async revokeApiKey(api_key_id: string, ownerUserId?: string): Promise<RevokeApiKeyResponse> {
    await this.getOwnedKey(api_key_id, ownerUserId);
    const revoked_at = this.now().toISOString();
    await this.db.run(
      `UPDATE api_keys SET is_active = 0, revoked_at = ? WHERE id = ?`,
      revoked_at,
      api_key_id
    );
    this.verified.delete(api_key_id);
    return { success: true, revoked_at };
  }

  /**
   * Rotates a key: a new key with the same user, name, scopes, limit and expiry, while the old key keeps working for
   * the 24 h grace period (its expires_at becomes the end of the grace period, or stays earlier if it was earlier).
   * In: the key id and, from a route, the signed-in owner. Out: { new_key (shown only here), old_key_revoked_at
   * (when the rotation happened), grace_period_ends_at }. Throws 404 for an unknown key and 409 for a revoked or
   * already-rotated one.
   * Why changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): the old key was disabled at once, so the
   * spec's grace period never existed (failing test "Rotate"). Touches: SQLite api_keys.
   */
  async rotateApiKey(api_key_id: string, ownerUserId?: string): Promise<RotateApiKeyResponse> {
    const oldKeyRow = await this.getOwnedKey(api_key_id, ownerUserId);
    if (!oldKeyRow.is_active || oldKeyRow.rotated_at) {
      throw new ApiKeyError(409, 'API key is revoked or already rotated');
    }
    const { key: new_key, lookup } = this.generateKey();
    const new_key_hash = await bcrypt.hash(new_key, this.bcryptRounds);
    const new_id = uuidv4();
    const now = this.now();
    const rotated_at = now.toISOString();
    const graceEnd = new Date(now.getTime() + this.gracePeriodMs);
    const oldExpiry = oldKeyRow.expires_at ? new Date(oldKeyRow.expires_at) : null;
    const oldKeyExpiresAt = oldExpiry && oldExpiry < graceEnd ? oldKeyRow.expires_at : graceEnd.toISOString();
    await this.db.exec('BEGIN');
    try {
      await this.db.run(
        `INSERT INTO api_keys (id, user_id, name, key_lookup, key_secret_hash, scopes, rate_limit, expires_at, created_at, is_active)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
        new_id,
        oldKeyRow.user_id,
        oldKeyRow.name,
        lookup,
        new_key_hash,
        oldKeyRow.scopes,
        oldKeyRow.rate_limit,
        oldKeyRow.expires_at,
        rotated_at
      );
      await this.db.run(
        `UPDATE api_keys SET expires_at = ?, rotated_at = ?, replaced_by_id = ? WHERE id = ?`,
        oldKeyExpiresAt,
        rotated_at,
        new_id,
        api_key_id
      );
      await this.db.exec('COMMIT');
    } catch (err) {
      await this.db.exec('ROLLBACK');
      throw err;
    }
    return {
      new_key,
      old_key_revoked_at: rotated_at,
      grace_period_ends_at: graceEnd.toISOString(),
    };
  }

  /**
   * Whether `key` is the key whose bcrypt hash is stored on `row`. A key verified before against the same stored
   * hash is recognised from its SHA-256 digest (constant-time comparison); anything else is bcrypt-checked.
   * In: the presented key and the row. Out: true or false. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: memory (the cache of verified keys).
   */
  private async keyMatches(key: string, row: any): Promise<boolean> {
    const digest = createHash('sha256').update(key).digest();
    const known = this.verified.get(row.id);
    if (known && known.hash === row.key_secret_hash && timingSafeEqual(known.digest, digest)) {
      return true;
    }
    const match = await bcrypt.compare(key, row.key_secret_hash);
    if (match) {
      if (this.verified.size >= VERIFIED_CACHE_LIMIT) {
        const oldest = this.verified.keys().next().value;
        if (oldest !== undefined) this.verified.delete(oldest);
      }
      this.verified.set(row.id, { hash: row.key_secret_hash, digest });
    }
    return match;
  }

  /**
   * Records one call made with a key. In: key id, endpoint, method, HTTP status, time. Out: nothing.
   * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP, so denied calls (401/403/429) are counted too.
   * Touches: SQLite api_key_usage.
   */
  private async logUsage(api_key_id: string, endpoint: string, method: string, status: number, at: Date): Promise<void> {
    await this.db.run(
      `INSERT INTO api_key_usage (id, api_key_id, endpoint, method, status, timestamp)
       VALUES (?, ?, ?, ?, ?, ?)`,
      uuidv4(),
      api_key_id,
      endpoint,
      method.toUpperCase(),
      status,
      at.toISOString()
    );
  }

  /**
   * The per-request check (spec endpoint 5), for the key from "Authorization: Bearer <key>".
   * Order: malformed, unknown or revoked key -> 401; expired (expires_at reached) -> 401; scope missing (and no
   * "*") -> 403; more than rate_limit calls in this UTC hour -> 429. Every call by a known key is logged with its
   * status; a successful call also sets last_used_at.
   * In: the key, endpoint, method and the scope the endpoint needs. Out: { api_key_id, rate_limit }; throws
   * {@link ApiKeyError} with the status otherwise.
   * Why changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): one indexed lookup instead of bcrypt over every
   * active key, the store interface instead of a hard Redis connection, the service clock. Touches: SQLite, the store.
   */
  async validateApiKey(
    key: string,
    endpoint: string,
    method: string,
    requiredScope: Scope
  ): Promise<{ api_key_id: string; rate_limit: number }> {
    const parsed = KEY_PATTERN.exec(typeof key === 'string' ? key : '');
    if (!parsed) throw new ApiKeyError(401, 'Invalid API key');
    const row = await this.db.get(`SELECT * FROM api_keys WHERE key_lookup = ?`, parsed[2]);
    if (!row || !(await this.keyMatches(key, row))) {
      throw new ApiKeyError(401, 'Invalid API key');
    }
    const now = this.now();
    if (!row.is_active) {
      await this.logUsage(row.id, endpoint, method, 401, now);
      throw new ApiKeyError(401, 'API key revoked');
    }
    if (row.expires_at && new Date(row.expires_at) <= now) {
      await this.logUsage(row.id, endpoint, method, 401, now);
      throw new ApiKeyError(401, 'Key expired');
    }
    const scopes: Scope[] = JSON.parse(row.scopes);
    if (!scopes.includes(requiredScope) && !scopes.includes('*')) {
      await this.logUsage(row.id, endpoint, method, 403, now);
      throw new ApiKeyError(403, 'Insufficient scope');
    }
    const rateLimitKey = `${this.redisPrefix}${row.id}:${now.toISOString().slice(0, 13)}`; // UTC hour bucket
    const count = await this.rateLimits.increment(rateLimitKey, 7200);
    if (count > row.rate_limit) {
      await this.logUsage(row.id, endpoint, method, 429, now);
      throw new ApiKeyError(429, 'Rate limit exceeded');
    }
    await this.db.run(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`, now.toISOString(), row.id);
    await this.logUsage(row.id, endpoint, method, 200, now);
    return { api_key_id: row.id, rate_limit: row.rate_limit };
  }

  /**
   * Usage of one key between two dates (spec endpoint 6). A date-only `to` includes that whole UTC day.
   * In: the key id, from, to and, from a route, the signed-in owner. Out: { api_key_id, total_requests,
   * requests_by_endpoint ("METHOD /path"), rate_limit_hits, errors (by status) }.
   * Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the last day of the range was cut off at 00:00.
   * Touches: SQLite api_key_usage.
   */
  async getUsageStats(
    api_key_id: string,
    from: string,
    to: string,
    ownerUserId?: string
  ): Promise<UsageStatsResponse> {
    if (ownerUserId !== undefined) await this.getOwnedKey(api_key_id, ownerUserId);
    const dateOnly = /^\d{4}-\d{2}-\d{2}$/;
    const toExclusive = dateOnly.test(to)
      ? new Date(Date.parse(`${to}T00:00:00Z`) + 24 * 60 * 60 * 1000).toISOString()
      : null;
    const rows = await this.db.all(
      `SELECT endpoint, method, status, COUNT(*) as cnt
       FROM api_key_usage
       WHERE api_key_id = ?
         AND timestamp >= ?
         AND ${toExclusive ? 'timestamp < ?' : 'timestamp <= ?'}
       GROUP BY endpoint, method, status
       ORDER BY endpoint, method, status`,
      api_key_id,
      from,
      toExclusive ?? to
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
      errors,
    };
  }

  /**
   * Every key for an admin audit, optionally one user's and only active or revoked ones (spec endpoint 7). Check that
   * the caller is an admin in your route before calling. In: user id, status. Out: { keys, total }.
   * Why changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): the filter values were never passed to the
   * query (fix taken from community PR #10), so any filter matched nothing; stable order added. Touches: SQLite.
   */
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
       FROM api_keys ${where} ORDER BY created_at, rowid`,
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

  /**
   * The expiry job (spec: "cron job checks expires_at"): marks every key whose expires_at has passed as inactive,
   * which also ends rotated keys after their grace period. In/out: nothing. Touches: SQLite api_keys.
   * Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (uses the service clock).
   */
  async runExpiryJob() {
    const now = this.now().toISOString();
    await this.db.run(
      `UPDATE api_keys SET is_active = 0 WHERE expires_at IS NOT NULL AND expires_at <= ? AND is_active = 1`,
      now
    );
  }
}

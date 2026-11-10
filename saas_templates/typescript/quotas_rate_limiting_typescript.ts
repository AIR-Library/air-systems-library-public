import { createHash } from "crypto";

export type Tier = "solo" | "team" | "enterprise";

export interface UsageMetricsRow {
  user_id: string;
  month: string;
  call_count: number;
  storage_bytes: number;
  updated_at: string;
}

export interface ApiCallRow {
  id: string;
  user_id: string;
  ip: string;
  endpoint: string;
  timestamp: string;
  status_code: number;
  response_time_ms: number;
}

export interface User {
  id: string;
  tier: Tier;
}

export interface QuotaLimits {
  api_calls: number;
  storage_bytes: number;
}

export interface QuotaCheckResult {
  pass: boolean;
  error?: {
    error: string;
    current?: number;
    limit?: number;
    reset_date?: string;
    reset_seconds?: number;
    usage?: number;
    tier?: string;
    minimum_tier?: string;
    upgrade_url?: string;
  };
}

export interface WhyChainEntry {
  gate: string;
  user_id: string;
  tier: Tier;
  current_usage: number;
  limit: number;
  timestamp: string;
}

export interface FeatureGateResult {
  pass: boolean;
  error?: {
    error: string;
    tier: string;
    minimum_tier: string;
    upgrade_url: string;
  };
}

export interface RateLimitResult {
  pass: boolean;
  error?: {
    error: string;
    reset_seconds: number;
  };
}

export interface QuotaService {
  checkApiCallQuota(userId: string, tier: Tier): Promise<QuotaCheckResult>;
  checkStorageQuota(userId: string, tier: Tier, incomingFileSize: number): Promise<QuotaCheckResult>;
  checkRateLimitPerUser(userId: string): Promise<RateLimitResult>;
  checkRateLimitPerIp(ip: string): Promise<RateLimitResult>;
  checkFeatureGate(userId: string, tier: Tier, feature: string): Promise<FeatureGateResult>;
  incrementUsage(userId: string, tier: Tier): Promise<void>;
  addStorage(userId: string, bytes: number): Promise<void>;
  recordApiCall(call: Omit<ApiCallRow, "id">): Promise<void>;
  getUsageMetrics(userId: string, month: string): Promise<UsageMetricsRow | null>;
  resetMonthUsage(userId: string, oldMonth: string, newMonth: string): Promise<void>;
  upgradeTier(userId: string, newTier: Tier): Promise<void>;
  getWhyChain(): WhyChainEntry[];
}

export const API_CALL_LIMITS: Record<Tier, number> = {
  solo: 1000,
  team: 10000,
  enterprise: Infinity,
};

export const STORAGE_LIMITS: Record<Tier, number> = {
  solo: 1e9,
  team: 100e9,
  enterprise: -1,
};

export const RATE_LIMIT_PER_USER = 100;
export const RATE_LIMIT_PER_IP = 10;

export const FEATURE_GATES: Record<string, Tier[]> = {
  feature_a: ["team", "enterprise"],
  feature_b: ["enterprise"],
  feature_c: ["solo", "team", "enterprise"],
};

export const UPGRADE_URLS: Record<Tier, string> = {
  solo: "https://example.com/upgrade/team",
  team: "https://example.com/upgrade/enterprise",
  enterprise: "https://example.com/upgrade/enterprise",
};

/**
 * The billing month of a moment, as "YYYY-MM" in UTC. In: the moment (default: now). Out: e.g. "2024-01".
 * Why: it read the machine's local month, so the same instant fell in different months on different servers, and it
 * could not be asked about any moment but the present, so month rollover could not be tested (repair of the failing
 * check "Old month metrics should exist", 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
 */
export function getCurrentMonth(now: Date = new Date()): string {
  const year = now.getUTCFullYear();
  const month = String(now.getUTCMonth() + 1).padStart(2, "0");
  return `${year}-${month}`;
}

/**
 * When the monthly quota resets: midnight UTC on the first day of the next month, as an ISO string.
 * In: the moment (default: now). Out: e.g. "2024-02-01T00:00:00.000Z".
 * Why: it used local time, unlike the UTC month key above (2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP).
 * Touches: nothing.
 */
export function getResetDate(now: Date = new Date()): string {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1)).toISOString();
}

/**
 * Options for {@link InMemoryQuotaService}. `now` is the clock the service reads for the billing month and the
 * rate-limit windows (default: the system clock); tests and replays pass a fixed clock.
 * Why: a quota service whose month cannot be pinned cannot be tested across a month rollover (2026-11-10, session
 * session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
 */
export interface QuotaServiceOptions {
  now?: () => Date;
}

/**
 * In-memory quota and rate-limit service (spec GEMINI_DISPATCH_MASTER_SPEC, quotas): monthly API-call and storage
 * quotas per tier, per-user (100/min) and per-IP (10/s) rate limits, tier feature gates and month rollover.
 * In: an optional clock ({@link QuotaServiceOptions}). Out: the {@link QuotaService} methods.
 * Why: changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP) so every date it uses comes from one injectable
 * clock; before, month rollover depended on the real calendar month. Touches: process memory only.
 */
export class InMemoryQuotaService implements QuotaService {
  private readonly now: () => Date;
  private usageMetrics: Map<string, UsageMetricsRow> = new Map();
  private apiCalls: ApiCallRow[] = [];
  private users: Map<string, User> = new Map();
  private whyChain: WhyChainEntry[] = [];
  private callIdCounter: number = 0;

  /**
   * In: options; `now` overrides the clock. Out: a new empty service. Why/date/touches: see the class block.
   */
  constructor(options: QuotaServiceOptions = {}) {
    this.now = options.now ?? (() => new Date());
  }

  /** The billing month by this service's clock. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
  private month(): string {
    return getCurrentMonth(this.now());
  }

  private getKey(userId: string, month: string): string {
    return `${userId}:${month}`;
  }

  /**
   * Appends one gate decision to the why-chain, stamped by the service clock. In: the entry. Out: nothing.
   * Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (service clock). Touches: memory.
   */
  private logWhyChain(entry: Omit<WhyChainEntry, "timestamp">): void {
    this.whyChain.push({
      ...entry,
      timestamp: this.now().toISOString(),
    });
  }

  /**
   * Monthly API-call quota for a tier: passes while this call stays within the limit, else quota_exceeded with
   * current, limit and reset_date (first of next month, UTC). In: user id, tier. Out: { pass, error? }.
   * Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: month and reset date from the service clock. Touches: memory.
   */
  async checkApiCallQuota(userId: string, tier: Tier): Promise<QuotaCheckResult> {
    const month = this.month();
    const key = this.getKey(userId, month);
    const currentUsage = this.usageMetrics.get(key)?.call_count ?? 0;
    const limit = API_CALL_LIMITS[tier];

    this.logWhyChain({
      gate: "api_quota_check",
      user_id: userId,
      tier,
      current_usage: currentUsage,
      limit: limit === Infinity ? -1 : limit,
    });

    if (limit === Infinity) {
      return { pass: true };
    }

    if (currentUsage + 1 <= limit) {
      return { pass: true };
    }

    return {
      pass: false,
      error: {
        error: "quota_exceeded",
        current: currentUsage,
        limit,
        reset_date: getResetDate(this.now()),
      },
    };
  }

  /**
   * Storage quota for a tier: passes while current + incoming bytes fit, else storage_quota_exceeded.
   * In: user id, tier, incoming size. Out: { pass, error? }. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (service clock). Touches: memory.
   */
  async checkStorageQuota(userId: string, tier: Tier, incomingFileSize: number): Promise<QuotaCheckResult> {
    const month = this.month();
    const key = this.getKey(userId, month);
    const currentStorage = this.usageMetrics.get(key)?.storage_bytes ?? 0;
    const limit = STORAGE_LIMITS[tier];

    this.logWhyChain({
      gate: "storage_quota_check",
      user_id: userId,
      tier,
      current_usage: currentStorage,
      limit: limit === -1 ? -1 : limit,
    });

    if (limit === -1) {
      return { pass: true };
    }

    if (currentStorage + incomingFileSize <= limit) {
      return { pass: true };
    }

    return {
      pass: false,
      error: {
        error: "storage_quota_exceeded",
        current: currentStorage,
        limit,
      },
    };
  }

  /**
   * Per-user limit: fewer than RATE_LIMIT_PER_USER calls in the last 60 s pass, else rate_limit_exceeded
   * (reset_seconds 60). In: user id. Out: { pass, error? }. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (service clock). Touches: memory.
   */
  async checkRateLimitPerUser(userId: string): Promise<RateLimitResult> {
    const now = this.now().getTime();
    const oneMinuteAgo = now - 60000;
    const count = this.apiCalls.filter(
      (call) => call.user_id === userId && new Date(call.timestamp).getTime() > oneMinuteAgo
    ).length;

    if (count < RATE_LIMIT_PER_USER) {
      return { pass: true };
    }

    return {
      pass: false,
      error: {
        error: "rate_limit_exceeded",
        reset_seconds: 60,
      },
    };
  }

  /**
   * Per-IP limit: fewer than RATE_LIMIT_PER_IP calls in the last second pass, else ip_rate_limit_exceeded
   * (reset_seconds 1). In: IP. Out: { pass, error? }. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (service clock). Touches: memory.
   */
  async checkRateLimitPerIp(ip: string): Promise<RateLimitResult> {
    const now = this.now().getTime();
    const oneSecondAgo = now - 1000;
    const count = this.apiCalls.filter(
      (call) => call.ip === ip && new Date(call.timestamp).getTime() > oneSecondAgo
    ).length;

    if (count < RATE_LIMIT_PER_IP) {
      return { pass: true };
    }

    return {
      pass: false,
      error: {
        error: "ip_rate_limit_exceeded",
        reset_seconds: 1,
      },
    };
  }

  async checkFeatureGate(userId: string, tier: Tier, feature: string): Promise<FeatureGateResult> {
    const allowedTiers = FEATURE_GATES[feature];

    if (!allowedTiers) {
      return { pass: true };
    }

    this.logWhyChain({
      gate: "feature_gate",
      user_id: userId,
      tier,
      current_usage: 0,
      limit: allowedTiers.length,
    });

    if (allowedTiers.includes(tier)) {
      return { pass: true };
    }

    const minimumTier = allowedTiers[0];
    return {
      pass: false,
      error: {
        error: "feature_not_available_in_tier",
        tier,
        minimum_tier: minimumTier,
        upgrade_url: UPGRADE_URLS[tier],
      },
    };
  }

  /**
   * Counts one API call in the current month's usage row. In: user id, tier. Out: nothing.
   * Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (service clock). Touches: memory.
   */
  async incrementUsage(userId: string, tier: Tier): Promise<void> {
    const month = this.month();
    const key = this.getKey(userId, month);
    const existing = this.usageMetrics.get(key);

    if (existing) {
      existing.call_count += 1;
      existing.updated_at = this.now().toISOString();
    } else {
      this.usageMetrics.set(key, {
        user_id: userId,
        month,
        call_count: 1,
        storage_bytes: 0,
        updated_at: this.now().toISOString(),
      });
    }
  }

  /**
   * Adds stored bytes to the current month's usage row. In: user id, bytes. Out: nothing.
   * Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (service clock). Touches: memory.
   */
  async addStorage(userId: string, bytes: number): Promise<void> {
    const month = this.month();
    const key = this.getKey(userId, month);
    const existing = this.usageMetrics.get(key);

    if (existing) {
      existing.storage_bytes += bytes;
      existing.updated_at = this.now().toISOString();
    } else {
      this.usageMetrics.set(key, {
        user_id: userId,
        month,
        call_count: 0,
        storage_bytes: bytes,
        updated_at: this.now().toISOString(),
      });
    }
  }

  /**
   * Logs one API call for the rate limits. In: the call without id. Out: nothing.
   * Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (service clock in the id seed). Touches: memory.
   */
  async recordApiCall(call: Omit<ApiCallRow, "id">): Promise<void> {
    this.callIdCounter += 1;
    const id = createHash("md5").update(`${this.callIdCounter}-${this.now().getTime()}`).digest("hex");
    this.apiCalls.push({
      id,
      ...call,
    });
  }

  async getUsageMetrics(userId: string, month: string): Promise<UsageMetricsRow | null> {
    const key = this.getKey(userId, month);
    return this.usageMetrics.get(key) ?? null;
  }

  async resetMonthUsage(userId: string, oldMonth: string, newMonth: string): Promise<void> {
    const oldKey = this.getKey(userId, oldMonth);
    const newKey = this.getKey(userId, newMonth);
    const oldMetrics = this.usageMetrics.get(oldKey);

    if (oldMetrics) {
      this.usageMetrics.set(newKey, {
        user_id: userId,
        month: newMonth,
        call_count: 0,
        storage_bytes: oldMetrics.storage_bytes,
        updated_at: this.now().toISOString(),
      });
      this.usageMetrics.delete(oldKey);
    }
  }

  async upgradeTier(userId: string, newTier: Tier): Promise<void> {
    const user = this.users.get(userId);
    if (user) {
      user.tier = newTier;
    }
  }

  getWhyChain(): WhyChainEntry[] {
    return [...this.whyChain];
  }

  setUser(user: User): void {
    this.users.set(user.id, user);
  }

  getUser(userId: string): User | undefined {
    return this.users.get(userId);
  }

  clearApiCalls(): void {
    this.apiCalls = [];
  }

  clearUsage(): void {
    this.usageMetrics.clear();
  }

  clearWhyChain(): void {
    this.whyChain = [];
  }
}

export const DDL_SCHEMA = `
CREATE TABLE IF NOT EXISTS usage_metrics (
  user_id VARCHAR(255) NOT NULL,
  month VARCHAR(7) NOT NULL,
  call_count INTEGER NOT NULL DEFAULT 0,
  storage_bytes BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, month)
);

CREATE TABLE IF NOT EXISTS api_calls (
  id VARCHAR(255) PRIMARY KEY,
  user_id VARCHAR(255) NOT NULL,
  ip VARCHAR(45) NOT NULL,
  endpoint VARCHAR(500) NOT NULL,
  timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status_code INTEGER NOT NULL,
  response_time_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_calls_user_timestamp ON api_calls (user_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_api_calls_ip_timestamp ON api_calls (ip, timestamp);
`;

export function createQuotaService(): InMemoryQuotaService {
  return new InMemoryQuotaService();
}
/**
 * Quota & rate-limiting tests, one jest test per check.
 * Why: this file was a hand-written runner (runAllTests) that the library's runner counted as 0 framework tests, and
 * its month-rollover check read the real calendar month. Converted to jest 2026-11-10, session
 * session_012zDydZCZ4AChqhEZ4oVtaP: every check and assertion is kept, each check is now its own test, and the
 * rollover check pins the service clock to January 2024. Touches: process memory only.
 */
import { describe, test } from "@jest/globals";
import {
  InMemoryQuotaService,
  getCurrentMonth,
  API_CALL_LIMITS,
  STORAGE_LIMITS,
  RATE_LIMIT_PER_USER,
  RATE_LIMIT_PER_IP,
  FEATURE_GATES,
  Tier,
  User,
} from "./quotas_rate_limiting_typescript";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

function assertEqual<T>(actual: T, expected: T, message: string): void {
  if (actual !== expected) {
    throw new Error(`Assertion failed: ${message}. Expected ${expected}, got ${actual}`);
  }
}

async function testApiQuotaPass(): Promise<void> {
  const service = new InMemoryQuotaService();
  const userId = "user1";
  const tier: Tier = "solo";

  const result = await service.checkApiCallQuota(userId, tier);
  assert(result.pass, "api_quota PASS should return pass: true");

  await service.incrementUsage(userId, tier);
  const metrics = await service.getUsageMetrics(userId, getCurrentMonth());
  assert(metrics !== null, "Usage metrics should exist after increment");
  assertEqual(metrics!.call_count, 1, "Usage should be incremented to 1");

  console.log("✓ api_quota PASS → call succeeds, usage incremented");
}

async function testApiQuotaFail(): Promise<void> {
  const service = new InMemoryQuotaService();
  const userId = "user2";
  const tier: Tier = "solo";
  const limit = API_CALL_LIMITS[tier];

  for (let i = 0; i < limit; i++) {
    await service.incrementUsage(userId, tier);
  }

  const result = await service.checkApiCallQuota(userId, tier);
  assert(!result.pass, "api_quota FAIL should return pass: false");
  assert(result.error !== undefined, "Error should be present");
  assertEqual(result.error!.error, "quota_exceeded", "Error type should be quota_exceeded");
  assertEqual(result.error!.current, limit, "Current usage should equal limit");
  assertEqual(result.error!.limit, limit, "Limit should be correct");
  assert(result.error!.reset_date !== undefined, "Reset date should be present");

  console.log("✓ api_quota FAIL → call rejected 429");
}

async function testStorageQuotaPass(): Promise<void> {
  const service = new InMemoryQuotaService();
  const userId = "user3";
  const tier: Tier = "solo";
  const incomingSize = 1000;

  const result = await service.checkStorageQuota(userId, tier, incomingSize);
  assert(result.pass, "storage_quota PASS should return pass: true");

  await service.addStorage(userId, incomingSize);
  const metrics = await service.getUsageMetrics(userId, getCurrentMonth());
  assert(metrics !== null, "Usage metrics should exist");
  assertEqual(metrics!.storage_bytes, incomingSize, "Storage should be updated");

  console.log("✓ storage_quota PASS → file stored");
}

async function testStorageQuotaFail(): Promise<void> {
  const service = new InMemoryQuotaService();
  const userId = "user4";
  const tier: Tier = "solo";
  const limit = STORAGE_LIMITS[tier];

  await service.addStorage(userId, limit - 100);

  const result = await service.checkStorageQuota(userId, tier, 200);
  assert(!result.pass, "storage_quota FAIL should return pass: false");
  assert(result.error !== undefined, "Error should be present");
  assertEqual(result.error!.error, "storage_quota_exceeded", "Error type should be storage_quota_exceeded");
  assertEqual(result.error!.current, limit - 100, "Current storage should be correct");
  assertEqual(result.error!.limit, limit, "Limit should be correct");

  console.log("✓ storage_quota FAIL → upload rejected 413");
}

async function testRateLimitPerUserPass(): Promise<void> {
  const service = new InMemoryQuotaService();
  const userId = "user5";
  const ip = "192.168.1.1";

  for (let i = 0; i < RATE_LIMIT_PER_USER - 1; i++) {
    await service.recordApiCall({
      user_id: userId,
      ip,
      endpoint: "/api/test",
      timestamp: new Date().toISOString(),
      status_code: 200,
      response_time_ms: 50,
    });
  }

  const result = await service.checkRateLimitPerUser(userId);
  assert(result.pass, "rate_limit_per_user PASS should return pass: true");

  console.log("✓ rate_limit_per_user PASS → < 100/min allowed");
}

async function testRateLimitPerUserFail(): Promise<void> {
  const service = new InMemoryQuotaService();
  const userId = "user6";
  const ip = "192.168.1.2";

  for (let i = 0; i < RATE_LIMIT_PER_USER; i++) {
    await service.recordApiCall({
      user_id: userId,
      ip,
      endpoint: "/api/test",
      timestamp: new Date().toISOString(),
      status_code: 200,
      response_time_ms: 50,
    });
  }

  const result = await service.checkRateLimitPerUser(userId);
  assert(!result.pass, "rate_limit_per_user FAIL should return pass: false");
  assert(result.error !== undefined, "Error should be present");
  assertEqual(result.error!.error, "rate_limit_exceeded", "Error type should be rate_limit_exceeded");
  assertEqual(result.error!.reset_seconds, 60, "Reset seconds should be 60");

  console.log("✓ rate_limit_per_user FAIL → 100+/min rejected 429");
}

async function testRateLimitPerIpPass(): Promise<void> {
  const service = new InMemoryQuotaService();
  const userId = "user7";
  const ip = "192.168.1.3";

  for (let i = 0; i < RATE_LIMIT_PER_IP - 1; i++) {
    await service.recordApiCall({
      user_id: userId,
      ip,
      endpoint: "/api/test",
      timestamp: new Date().toISOString(),
      status_code: 200,
      response_time_ms: 50,
    });
  }

  const result = await service.checkRateLimitPerIp(ip);
  assert(result.pass, "rate_limit_per_ip PASS should return pass: true");

  console.log("✓ rate_limit_per_ip PASS → < 10/sec allowed");
}

async function testRateLimitPerIpFail(): Promise<void> {
  const service = new InMemoryQuotaService();
  const userId = "user8";
  const ip = "192.168.1.4";

  for (let i = 0; i < RATE_LIMIT_PER_IP; i++) {
    await service.recordApiCall({
      user_id: userId,
      ip,
      endpoint: "/api/test",
      timestamp: new Date().toISOString(),
      status_code: 200,
      response_time_ms: 50,
    });
  }

  const result = await service.checkRateLimitPerIp(ip);
  assert(!result.pass, "rate_limit_per_ip FAIL should return pass: false");
  assert(result.error !== undefined, "Error should be present");
  assertEqual(result.error!.error, "ip_rate_limit_exceeded", "Error type should be ip_rate_limit_exceeded");
  assertEqual(result.error!.reset_seconds, 1, "Reset seconds should be 1");

  console.log("✓ rate_limit_per_ip FAIL → 10+/sec rejected 429");
}

async function testFeatureGatePass(): Promise<void> {
  const service = new InMemoryQuotaService();
  const userId = "user9";
  const tier: Tier = "team";

  const result = await service.checkFeatureGate(userId, tier, "feature_a");
  assert(result.pass, "feature_gate PASS should return pass: true");

  const resultC = await service.checkFeatureGate(userId, tier, "feature_c");
  assert(resultC.pass, "feature_c should be available for team tier");

  console.log("✓ feature_gate PASS → feature available in tier");
}

async function testFeatureGateFail(): Promise<void> {
  const service = new InMemoryQuotaService();
  const userId = "user10";
  const tier: Tier = "solo";

  const result = await service.checkFeatureGate(userId, tier, "feature_a");
  assert(!result.pass, "feature_gate FAIL should return pass: false");
  assert(result.error !== undefined, "Error should be present");
  assertEqual(result.error!.error, "feature_not_available_in_tier", "Error type should be feature_not_available_in_tier");
  assertEqual(result.error!.tier, "solo", "Tier should be solo");
  assertEqual(result.error!.minimum_tier, "team", "Minimum tier should be team");
  assert(result.error!.upgrade_url !== undefined, "Upgrade URL should be present");

  const resultB = await service.checkFeatureGate(userId, tier, "feature_b");
  assert(!resultB.pass, "feature_b should not be available for solo");
  assertEqual(resultB.error!.minimum_tier, "enterprise", "Minimum tier for feature_b should be enterprise");

  console.log("✓ feature_gate FAIL → feature unavailable, 403 with upgrade hint");
}

async function testMonthRollover(): Promise<void> {
  // The usage is recorded "now"; the check reads it back as month 2024-01, so "now" must be in January 2024.
  const service = new InMemoryQuotaService({ now: () => new Date(Date.UTC(2024, 0, 15, 12, 0, 0)) });
  const userId = "user11";
  const tier: Tier = "solo";
  const oldMonth = "2024-01";
  const newMonth = "2024-02";

  await service.addStorage(userId, 500000);
  for (let i = 0; i < 100; i++) {
    await service.incrementUsage(userId, tier);
  }

  const oldMetrics = await service.getUsageMetrics(userId, oldMonth);
  assert(oldMetrics !== null, "Old month metrics should exist");
  assertEqual(oldMetrics!.call_count, 100, "Call count should be 100");
  assertEqual(oldMetrics!.storage_bytes, 500000, "Storage should be 500000");

  await service.resetMonthUsage(userId, oldMonth, newMonth);

  const newMetrics = await service.getUsageMetrics(userId, newMonth);
  assert(newMetrics !== null, "New month metrics should exist");
  assertEqual(newMetrics!.call_count, 0, "Call count should reset to 0");
  assertEqual(newMetrics!.storage_bytes, 500000, "Storage should persist");

  const oldMetricsAfter = await service.getUsageMetrics(userId, oldMonth);
  assert(oldMetricsAfter === null, "Old month metrics should be removed");

  console.log("✓ month rollover → usage_metrics reset for new month");
}

async function testTierUpgrade(): Promise<void> {
  const service = new InMemoryQuotaService();
  const userId = "user12";
  const user: User = { id: userId, tier: "solo" };
  service.setUser(user);

  const soloLimit = API_CALL_LIMITS["solo"];
  for (let i = 0; i < soloLimit; i++) {
    await service.incrementUsage(userId, "solo");
  }

  const soloResult = await service.checkApiCallQuota(userId, "solo");
  assert(!soloResult.pass, "Should fail with solo tier at limit");

  await service.upgradeTier(userId, "team");
  const updatedUser = service.getUser(userId);
  assertEqual(updatedUser!.tier, "team", "Tier should be updated to team");

  const teamResult = await service.checkApiCallQuota(userId, "team");
  assert(teamResult.pass, "Should pass with team tier after upgrade");

  console.log("✓ tier upgrade → limits updated immediately");
}

describe("Quota & Rate Limiting", () => {
  test("api_quota PASS → call succeeds, usage incremented", testApiQuotaPass);
  test("api_quota FAIL → call rejected 429", testApiQuotaFail);
  test("storage_quota PASS → file stored", testStorageQuotaPass);
  test("storage_quota FAIL → upload rejected 413", testStorageQuotaFail);
  test("rate_limit_per_user PASS → < 100/min allowed", testRateLimitPerUserPass);
  test("rate_limit_per_user FAIL → 100+/min rejected 429", testRateLimitPerUserFail);
  test("rate_limit_per_ip PASS → < 10/sec allowed", testRateLimitPerIpPass);
  test("rate_limit_per_ip FAIL → 10+/sec rejected 429", testRateLimitPerIpFail);
  test("feature_gate PASS → feature available in tier", testFeatureGatePass);
  test("feature_gate FAIL → feature unavailable, 403 with upgrade hint", testFeatureGateFail);
  test("month rollover → usage_metrics reset for new month", testMonthRollover);
  test("tier upgrade → limits updated immediately", testTierUpgrade);
});

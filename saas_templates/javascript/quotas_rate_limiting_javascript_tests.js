'use strict';

const assert = require('assert');
const {
  QuotaManager,
  QuotaError,
  InMemoryStore,
  TIERS,
  API_CALL_LIMITS,
  STORAGE_LIMITS,
  RATE_LIMIT_PER_USER,
  RATE_LIMIT_PER_IP,
  FEATURE_TIERS,
} = require('./quotas_rate_limiting_javascript');

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (err) {
    failed++;
    failures.push({ name, err });
    console.log(`  ✗ ${name}`);
    console.log(`    ${err.message}`);
  }
}

function makeManager(overrides = {}) {
  const store = new InMemoryStore();
  const logs = [];
  const manager = new QuotaManager({
    store,
    now: overrides.now || (() => new Date('2025-01-15T12:00:00.000Z')),
    log: (entry) => logs.push(entry),
  });
  return { manager, store, logs };
}

function expectQuotaError(fn, expectedStatus, expectedErrorKey) {
  let caught = null;
  try {
    fn();
  } catch (e) {
    caught = e;
  }
  assert.ok(caught, 'expected an error to be thrown');
  assert.ok(caught instanceof QuotaError, `expected QuotaError, got ${caught.constructor.name}`);
  assert.strictEqual(caught.statusCode, expectedStatus, `expected status ${expectedStatus}, got ${caught.statusCode}`);
  assert.strictEqual(caught.body.error, expectedErrorKey, `expected error "${expectedErrorKey}", got "${caught.body.error}"`);
  return caught;
}

console.log('Quotas & Rate Limiting - Test Suite\n');

// 1. api_quota PASS
// QUOTA-01
test('api_quota PASS → call succeeds, usage incremented', () => {
  const { manager, store } = makeManager();
  store.upsertUser({ user_id: 'u1', tier: 'solo' });
  const result = manager.checkApiCallQuota('u1', 'solo');
  assert.strictEqual(result.pass, true);
  assert.strictEqual(result.current, 1);
  const usage = store.getUsage('u1', '2025-01');
  assert.strictEqual(usage.call_count, 1);
});

// 2. api_quota FAIL
// QUOTA-02
test('api_quota FAIL → call rejected 429', () => {
  const { manager, store } = makeManager();
  store.upsertUser({ user_id: 'u1', tier: 'solo' });
  store.incrementCalls('u1', '2025-01', 1000);
  const err = expectQuotaError(
    () => manager.checkApiCallQuota('u1', 'solo'),
    429,
    'quota_exceeded'
  );
  assert.strictEqual(err.body.current, 1000);
  assert.strictEqual(err.body.limit, 1000);
  assert.ok(err.body.reset_date, 'reset_date should be present');
});

// 3. storage_quota PASS
// QUOTA-03
test('storage_quota PASS → file stored', () => {
  const { manager, store } = makeManager();
  store.upsertUser({ user_id: 'u1', tier: 'solo' });
  const result = manager.handleFileUpload({
    userId: 'u1',
    tier: 'solo',
    fileName: 'test.txt',
    size: 1024,
  });
  assert.strictEqual(result.status, 200);
  const usage = store.getUsage('u1', '2025-01');
  assert.strictEqual(usage.storage_bytes, 1024);
});

// 4. storage_quota FAIL
// QUOTA-04
test('storage_quota FAIL → upload rejected 413', () => {
  const { manager, store } = makeManager();
  store.upsertUser({ user_id: 'u1', tier: 'solo' });
  store.addStorage('u1', '2025-01', 1e9 - 100);
  const err = expectQuotaError(
    () => manager.handleFileUpload({
      userId: 'u1',
      tier: 'solo',
      fileName: 'big.bin',
      size: 200,
    }),
    413,
    'storage_quota_exceeded'
  );
  assert.strictEqual(err.body.current, 1e9 - 100);
  assert.strictEqual(err.body.limit, 1e9);
});

// 5. rate_limit_per_user PASS
// QUOTA-05
test('rate_limit_per_user PASS → < 100/min allowed', () => {
  const { manager } = makeManager();
  for (let i = 0; i < 99; i++) {
    manager.checkRateLimitPerUser('u1', '1.2.3.4', '/api/test');
  }
  const result = manager.checkRateLimitPerUser('u1', '1.2.3.4', '/api/test');
  assert.strictEqual(result.pass, true);
  assert.strictEqual(result.count, 100);
});

// 6. rate_limit_per_user FAIL
// QUOTA-06
test('rate_limit_per_user FAIL → 100+/min rejected 429', () => {
  const { manager } = makeManager();
  for (let i = 0; i < 100; i++) {
    manager.checkRateLimitPerUser('u1', '1.2.3.4', '/api/test');
  }
  const err = expectQuotaError(
    () => manager.checkRateLimitPerUser('u1', '1.2.3.4', '/api/test'),
    429,
    'rate_limit_exceeded'
  );
  assert.strictEqual(err.body.reset_seconds, 60);
});

// 7. rate_limit_per_ip PASS
// QUOTA-07
test('rate_limit_per_ip PASS → < 10/sec allowed', () => {
  const { manager } = makeManager();
  for (let i = 0; i < 9; i++) {
    manager.checkRateLimitPerIp('1.2.3.4', `u${i}`, '/api/test');
  }
  const result = manager.checkRateLimitPerIp('1.2.3.4', 'u9', '/api/test');
  assert.strictEqual(result.pass, true);
  assert.strictEqual(result.count, 10);
});

// 8. rate_limit_per_ip FAIL
// QUOTA-08
test('rate_limit_per_ip FAIL → 10+/sec rejected 429', () => {
  const { manager } = makeManager();
  for (let i = 0; i < 10; i++) {
    manager.checkRateLimitPerIp('1.2.3.4', `u${i}`, '/api/test');
  }
  const err = expectQuotaError(
    () => manager.checkRateLimitPerIp('1.2.3.4', 'u10', '/api/test'),
    429,
    'ip_rate_limit_exceeded'
  );
  assert.strictEqual(err.body.reset_seconds, 1);
});

// 9. feature_gate PASS
// QUOTA-09
test('feature_gate PASS → feature available in tier', () => {
  const { manager } = makeManager();
  const result = manager.checkFeatureGate('u1', 'team', 'feature_a');
  assert.strictEqual(result.pass, true);
  assert.deepStrictEqual(result.allowed_tiers, ['team', 'enterprise']);
});

// 10. feature_gate FAIL
// QUOTA-10
test('feature_gate FAIL → feature unavailable, 403 with upgrade hint', () => {
  const { manager } = makeManager();
  const err = expectQuotaError(
    () => manager.checkFeatureGate('u1', 'solo', 'feature_a'),
    403,
    'feature_not_available_in_tier'
  );
  assert.strictEqual(err.body.tier, 'solo');
  assert.strictEqual(err.body.minimum_tier, 'team');
  assert.ok(err.body.upgrade_url.includes('upgrade'), 'upgrade_url should contain upgrade path');
});

// 11. month rollover
// QUOTA-11
test('month rollover → usage_metrics reset for new month', () => {
  const store = new InMemoryStore();
  const manager = new QuotaManager({
    store,
    now: () => new Date('2025-01-31T23:59:59.000Z'),
    log: () => {},
  });
  store.upsertUser({ user_id: 'u1', tier: 'solo' });
  manager.checkApiCallQuota('u1', 'solo');
  manager.checkApiCallQuota('u1', 'solo');
  assert.strictEqual(store.getUsage('u1', '2025-01').call_count, 2);

  const manager2 = new QuotaManager({
    store,
    now: () => new Date('2025-02-01T00:00:00.000Z'),
    log: () => {},
  });
  const result = manager2.checkApiCallQuota('u1', 'solo');
  assert.strictEqual(result.current, 1);
  assert.strictEqual(store.getUsage('u1', '2025-02').call_count, 1);
  assert.strictEqual(store.getUsage('u1', '2025-01').call_count, 2);
});

// 12. tier upgrade
// QUOTA-12
test('tier upgrade → limits updated immediately', () => {
  const { manager, store } = makeManager();
  store.upsertUser({ user_id: 'u1', tier: 'solo' });
  store.incrementCalls('u1', '2025-01', 1000);

  expectQuotaError(
    () => manager.checkApiCallQuota('u1', 'solo'),
    429,
    'quota_exceeded'
  );

  store.upsertUser({ user_id: 'u1', tier: 'team' });
  const result = manager.checkApiCallQuota('u1', 'team');
  assert.strictEqual(result.pass, true);
  assert.strictEqual(result.current, 1001);
  assert.strictEqual(result.limit, 10000);
});

// Additional: enterprise unlimited
test('enterprise tier has unlimited API calls', () => {
  const { manager, store } = makeManager();
  store.upsertUser({ user_id: 'u1', tier: 'enterprise' });
  store.incrementCalls('u1', '2025-01', 999999);
  const result = manager.checkApiCallQuota('u1', 'enterprise');
  assert.strictEqual(result.pass, true);
  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the spec's unlimited is -1 in every quota (QUOTA-13), not Infinity.
  assert.strictEqual(result.limit, -1);
});

/**
 * QUOTA-13: a limit of -1 is unlimited. An enterprise upload far past every other tier's storage limit is stored,
 * and enterprise API calls past every other tier's monthly limit (team: 10000) never get 429 from the quota.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the in-memory store only.
 */
// QUOTA-13
test('a limit of -1 is unlimited for enterprise storage and API calls', () => {
  const { manager, store } = makeManager();
  store.upsertUser({ user_id: 'ent', tier: 'enterprise' });
  assert.strictEqual(API_CALL_LIMITS.enterprise, -1);
  assert.strictEqual(STORAGE_LIMITS.enterprise, -1);
  const huge = 500e12;
  const up = manager.handleFileUpload({ userId: 'ent', tier: 'enterprise', fileName: 'huge.bin', size: huge });
  assert.strictEqual(up.status, 200);
  assert.strictEqual(store.getUsage('ent', '2025-01').storage_bytes, huge);
  const calls = API_CALL_LIMITS.team + 5;
  for (let i = 0; i < calls; i++) {
    const r = manager.checkApiCallQuota('ent', 'enterprise');
    assert.strictEqual(r.pass, true);
  }
  assert.strictEqual(store.getUsage('ent', '2025-01').call_count, calls);
});

// Additional: enterprise unlimited storage
test('enterprise tier has unlimited storage', () => {
  const { manager, store } = makeManager();
  store.upsertUser({ user_id: 'u1', tier: 'enterprise' });
  store.addStorage('u1', '2025-01', 999e9);
  const result = manager.checkStorageQuota('u1', 'enterprise', 1e9);
  assert.strictEqual(result.pass, true);
  assert.strictEqual(result.limit, -1);
});

// Additional: feature_b only enterprise
test('feature_b only available to enterprise', () => {
  const { manager } = makeManager();
  expectQuotaError(
    () => manager.checkFeatureGate('u1', 'team', 'feature_b'),
    403,
    'feature_not_available_in_tier'
  );
  const result = manager.checkFeatureGate('u1', 'enterprise', 'feature_b');
  assert.strictEqual(result.pass, true);
});

// Additional: feature_c available to all
test('feature_c available to all tiers', () => {
  const { manager } = makeManager();
  for (const tier of ['solo', 'team', 'enterprise']) {
    const result = manager.checkFeatureGate('u1', tier, 'feature_c');
    assert.strictEqual(result.pass, true);
  }
});

// Additional: unknown feature
test('unknown feature returns 404', () => {
  const { manager } = makeManager();
  const err = expectQuotaError(
    () => manager.checkFeatureGate('u1', 'solo', 'feature_zzz'),
    404,
    'feature_not_found'
  );
  assert.strictEqual(err.body.feature, 'feature_zzz');
});

// Additional: handleApiRequest full flow
test('handleApiRequest full flow succeeds', () => {
  const { manager, store } = makeManager();
  store.upsertUser({ user_id: 'u1', tier: 'solo' });
  const result = manager.handleApiRequest({
    userId: 'u1',
    ip: '1.2.3.4',
    endpoint: '/api/data',
    tier: 'solo',
  });
  assert.strictEqual(result.status, 200);
  assert.strictEqual(store.getUsage('u1', '2025-01').call_count, 1);
});

// Additional: handleApiRequest respects IP rate limit
test('handleApiRequest respects IP rate limit', () => {
  const { manager, store } = makeManager();
  store.upsertUser({ user_id: 'u1', tier: 'solo' });
  for (let i = 0; i < 10; i++) {
    manager.handleApiRequest({
      userId: `u${i}`,
      ip: '1.2.3.4',
      endpoint: '/api/data',
      tier: 'solo',
    });
  }
  const err = expectQuotaError(
    () => manager.handleApiRequest({
      userId: 'u10',
      ip: '1.2.3.4',
      endpoint: '/api/data',
      tier: 'solo',
    }),
    429,
    'ip_rate_limit_exceeded'
  );
  assert.strictEqual(err.body.reset_seconds, 1);
});

// Additional: why_chain logging
test('why_chain logging captures gate details', () => {
  const { manager, logs } = makeManager();
  manager.checkApiCallQuota('u1', 'solo');
  assert.ok(logs.length >= 1);
  const entry = logs[0];
  assert.strictEqual(entry.gate, 'api_quota_check');
  assert.strictEqual(entry.user_id, 'u1');
  assert.strictEqual(entry.tier, 'solo');
  assert.strictEqual(entry.current_usage, 0);
  assert.strictEqual(entry.limit, 1000);
  assert.strictEqual(entry.pass, true);
});

// Additional: storage quota boundary
test('storage_quota boundary: exact limit passes', () => {
  const { manager, store } = makeManager();
  store.upsertUser({ user_id: 'u1', tier: 'solo' });
  store.addStorage('u1', '2025-01', 1e9 - 512);
  const result = manager.checkStorageQuota('u1', 'solo', 512);
  assert.strictEqual(result.pass, true);
  assert.strictEqual(result.current, 1e9);
});

// Additional: storage quota boundary: one byte over fails
test('storage_quota boundary: one byte over fails', () => {
  const { manager, store } = makeManager();
  store.upsertUser({ user_id: 'u1', tier: 'solo' });
  store.addStorage('u1', '2025-01', 1e9 - 511);
  expectQuotaError(
    () => manager.checkStorageQuota('u1', 'solo', 512),
    413,
    'storage_quota_exceeded'
  );
});

console.log(`\nResults: ${passed} passed, ${failed} failed, ${passed + failed} total`);
if (failed > 0) {
  console.log('\nFailures:');
  for (const f of failures) {
    console.log(`  - ${f.name}: ${f.err.message}`);
  }
  process.exit(1);
} else {
  process.exit(0);
}

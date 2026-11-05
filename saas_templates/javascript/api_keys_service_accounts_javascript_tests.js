'use strict';

const assert = require('assert');
const {
  ApiKeyService,
  ApiKeyError,
  InMemoryStore,
  SCOPES,
  SCHEMA_SQL,
  createService,
  requiredScopeFor,
  scopeMatches,
} = require('./api_keys_service_accounts_javascript.js');

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      passed += 1;
      console.log('  ✓ ' + name);
    })
    .catch((err) => {
      failed += 1;
      failures.push({ name, err });
      console.log('  ✗ ' + name);
      console.log('      ' + (err && err.message ? err.message : err));
    });
}

function makeService(overrides) {
  const store = new InMemoryStore();
  const svc = new ApiKeyService(Object.assign({ store, env: 'live' }, overrides || {}));
  return { svc, store };
}

function expectStatus(promise, status) {
  return promise.then(
    () => {
      throw new Error('expected error with status ' + status + ' but resolved');
    },
    (err) => {
      assert.ok(err instanceof ApiKeyError, 'expected ApiKeyError, got ' + (err && err.name));
      assert.strictEqual(err.status, status, 'expected status ' + status + ' got ' + err.status);
    }
  );
}

async function main() {
  console.log('API Keys & Service Accounts — JavaScript test suite\n');

  await test('schema DDL is present and defines both tables', () => {
    assert.ok(typeof SCHEMA_SQL === 'string' && SCHEMA_SQL.length > 0);
    assert.ok(SCHEMA_SQL.includes('CREATE TABLE IF NOT EXISTS api_keys'));
    assert.ok(SCHEMA_SQL.includes('CREATE TABLE IF NOT EXISTS api_key_usage'));
    assert.ok(SCHEMA_SQL.includes('key_secret_hash'));
    assert.ok(SCHEMA_SQL.includes('rate_limit'));
  });

  await test('create key with scopes returns key shown once and metadata', async () => {
    const { svc } = makeService();
    const res = await svc.createKey('user_1', {
      name: 'My Integration',
      scopes: [SCOPES.READ_DEPLOYMENTS, SCOPES.WEBHOOK_MANAGE],
      expires_at: '2026-12-31',
      rate_limit: 1000,
    });
    assert.ok(res.api_key_id, 'api_key_id present');
    assert.ok(res.key.startsWith('sk_live_'), 'key has live prefix');
    assert.ok(res.created_at, 'created_at present');
    assert.strictEqual(res.rate_limit, 1000);
    assert.ok(res.expires_at, 'expires_at present');
    const listed = svc.listKeys('user_1');
    assert.strictEqual(listed.keys.length, 1);
    assert.strictEqual(listed.keys[0].key, undefined, 'key must NOT be in list');
    assert.deepStrictEqual(listed.keys[0].scopes, [SCOPES.READ_DEPLOYMENTS, SCOPES.WEBHOOK_MANAGE]);
  });

  await test('create key validates required fields', async () => {
    const { svc } = makeService();
    await expectStatus(svc.createKey('u', { scopes: ['read:users'] }), 400);
    await expectStatus(svc.createKey('u', { name: 'x', scopes: [] }), 400);
    await expectStatus(svc.createKey(null, { name: 'x', scopes: ['read:users'] }), 400);
  });

  await test('use key: request succeeds with Authorization header', async () => {
    const { svc } = makeService();
    const created = await svc.createKey('user_1', {
      name: 'Int',
      scopes: [SCOPES.READ_DEPLOYMENTS],
      rate_limit: 1000,
    });
    const auth = await svc.authenticate(created.key, 'GET', '/deployments');
    assert.ok(auth.record, 'authenticated record returned');
    assert.strictEqual(auth.record.id, created.api_key_id);
    svc.logSuccess(created.api_key_id, 'GET', '/deployments', 200);
    const stats = svc.getUsageStats(created.api_key_id);
    assert.strictEqual(stats.total_requests, 1);
    assert.strictEqual(stats.requests_by_endpoint['GET /deployments'], 1);
  });

  await test('revoke key: subsequent requests return 401', async () => {
    const { svc } = makeService();
    const created = await svc.createKey('user_1', { name: 'Int', scopes: [SCOPES.READ_DEPLOYMENTS] });
    await svc.authenticate(created.key, 'GET', '/deployments');
    const rev = svc.revokeKey(created.api_key_id);
    assert.strictEqual(rev.success, true);
    assert.ok(rev.revoked_at);
    await expectStatus(svc.authenticate(created.key, 'GET', '/deployments'), 401);
  });

  await test('rate limit: 1001st request in hour returns 429', async () => {
    const { svc } = makeService();
    const created = await svc.createKey('user_1', {
      name: 'Int',
      scopes: [SCOPES.READ_DEPLOYMENTS],
      rate_limit: 1000,
    });
    for (let i = 0; i < 1000; i++) {
      await svc.authenticate(created.key, 'GET', '/deployments');
    }
    await expectStatus(svc.authenticate(created.key, 'GET', '/deployments'), 429);
  });

  await test('scope check: read:deployments key cannot write deployments (403)', async () => {
    const { svc } = makeService();
    const created = await svc.createKey('user_1', {
      name: 'Int',
      scopes: [SCOPES.READ_DEPLOYMENTS],
      rate_limit: 1000,
    });
    await expectStatus(svc.authenticate(created.key, 'POST', '/deployments'), 403);
  });

  await test('wildcard scope (*) grants all actions', async () => {
    const { svc } = makeService();
    const created = await svc.createKey('user_1', { name: 'Int', scopes: [SCOPES.ALL], rate_limit: 1000 });
    await svc.authenticate(created.key, 'POST', '/deployments');
    await svc.authenticate(created.key, 'DELETE', '/webhooks');
    assert.ok(true);
  });

  await test('rotate: new key works, old key stops after grace period', async () => {
    const { svc } = makeService();
    const created = await svc.createKey('user_1', {
      name: 'Int',
      scopes: [SCOPES.READ_DEPLOYMENTS],
      rate_limit: 1000,
    });
    const base = new Date('2026-09-24T10:00:00.000Z');
    let t = base.getTime();
    const svc2 = new ApiKeyService({
      store: svc.store,
      env: 'live',
      now: () => new Date(t).toISOString(),
    });
    const rot = await svc2.rotateKey(created.api_key_id);
    assert.ok(rot.new_key.startsWith('sk_live_'));
    assert.ok(rot.old_key_revoked_at);
    assert.ok(rot.grace_period_ends_at);
    await svc2.authenticate(rot.new_key, 'GET', '/deployments');
    t = base.getTime() + 25 * 60 * 60 * 1000;
    const svc3 = new ApiKeyService({
      store: svc.store,
      env: 'live',
      now: () => new Date(t).toISOString(),
    });
    await expectStatus(svc3.authenticate(created.key, 'GET', '/deployments'), 401);
    await svc3.authenticate(rot.new_key, 'GET', '/deployments');
  });

  await test('rotate: old key still works within grace period', async () => {
    const { svc } = makeService();
    const created = await svc.createKey('user_1', {
      name: 'Int',
      scopes: [SCOPES.READ_DEPLOYMENTS],
      rate_limit: 1000,
    });
    const base = new Date('2026-09-24T10:00:00.000Z');
    let t = base.getTime();
    const svc2 = new ApiKeyService({
      store: svc.store,
      env: 'live',
      now: () => new Date(t).toISOString(),
    });
    const rot = await svc2.rotateKey(created.api_key_id);
    t = base.getTime() + 12 * 60 * 60 * 1000;
    const svc3 = new ApiKeyService({
      store: svc.store,
      env: 'live',
      now: () => new Date(t).toISOString(),
    });
    await svc3.authenticate(created.key, 'GET', '/deployments');
    t = base.getTime() + 25 * 60 * 60 * 1000;
    const svc4 = new ApiKeyService({
      store: svc.store,
      env: 'live',
      now: () => new Date(t).toISOString(),
    });
    await expectStatus(svc4.authenticate(created.key, 'GET', '/deployments'), 401);
  });

  await test('expired key: after expires_at, request returns 401', async () => {
    const { svc } = makeService();
    const created = await svc.createKey('user_1', {
      name: 'Int',
      scopes: [SCOPES.READ_DEPLOYMENTS],
      expires_at: '2026-01-01T00:00:00.000Z',
      rate_limit: 1000,
    });
    const future = new ApiKeyService({
      store: svc.store,
      env: 'live',
      now: () => '2026-06-01T00:00:00.000Z',
    });
    await expectStatus(future.authenticate(created.key, 'GET', '/deployments'), 401);
  });

  await test('expiry cron marks expired keys inactive', async () => {
    const { svc } = makeService();
    await svc.createKey('user_1', {
      name: 'Old',
      scopes: [SCOPES.READ_DEPLOYMENTS],
      expires_at: '2026-01-01T00:00:00.000Z',
    });
    await svc.createKey('user_1', {
      name: 'New',
      scopes: [SCOPES.READ_DEPLOYMENTS],
      expires_at: '2027-01-01T00:00:00.000Z',
    });
    const future = new ApiKeyService({
      store: svc.store,
      env: 'live',
      now: () => '2026-06-01T00:00:00.000Z',
    });
    const res = future.runExpiryCron();
    assert.strictEqual(res.expired, 1);
    const listed = future.listKeys('user_1');
    const old = listed.keys.find((k) => k.name === 'Old');
    const neu = listed.keys.find((k) => k.name === 'New');
    assert.strictEqual(old.is_active, false);
    assert.strictEqual(neu.is_active, true);
  });

  await test('usage stats: requests counted per endpoint with errors and rate hits', async () => {
    const fixedNow = () => '2026-09-15T12:00:00.000Z';
    const { svc } = makeService({ now: fixedNow });
    const created = await svc.createKey('user_1', {
      name: 'Int',
      scopes: [SCOPES.READ_DEPLOYMENTS, SCOPES.WEBHOOK_MANAGE],
      rate_limit: 1000,
    });
    for (let i = 0; i < 40; i++) {
      await svc.authenticate(created.key, 'GET', '/deployments');
      svc.logSuccess(created.api_key_id, 'GET', '/deployments', 200);
    }
    for (let i = 0; i < 10; i++) {
      await svc.authenticate(created.key, 'POST', '/webhooks');
      svc.logSuccess(created.api_key_id, 'POST', '/webhooks', 200);
    }
    svc._logUsage(created.api_key_id, 'GET', '/deployments', 404);
    svc._logUsage(created.api_key_id, 'GET', '/deployments', 500);
    svc._logUsage(created.api_key_id, 'GET', '/deployments', 429);
    const stats = svc.getUsageStats(created.api_key_id, '2026-09-01', '2026-09-24');
    assert.strictEqual(stats.api_key_id, created.api_key_id);
    assert.strictEqual(stats.total_requests, 53);
    assert.strictEqual(stats.requests_by_endpoint['GET /deployments'], 43);
    assert.strictEqual(stats.requests_by_endpoint['POST /webhooks'], 10);
    assert.strictEqual(stats.rate_limit_hits, 1);
    assert.strictEqual(stats.errors['404'], 1);
    assert.strictEqual(stats.errors['500'], 1);
    assert.strictEqual(stats.errors['429'], 1);
  });

  await test('admin audit: all keys visible to admin with filters', async () => {
    const { svc } = makeService();
    await svc.createKey('user_1', { name: 'A', scopes: [SCOPES.READ_DEPLOYMENTS] });
    await svc.createKey('user_2', { name: 'B', scopes: [SCOPES.READ_USERS] });
    await svc.createKey('user_1', { name: 'C', scopes: [SCOPES.READ_INVOICES] });
    const all = svc.adminListKeys();
    assert.strictEqual(all.total, 3);
    const forUser = svc.adminListKeys({ userId: 'user_1' });
    assert.strictEqual(forUser.total, 2);
    const active = svc.adminListKeys({ status: 'active' });
    assert.strictEqual(active.total, 3);
    svc.revokeKey(forUser.keys[0].api_key_id);
    const activeAfter = svc.adminListKeys({ status: 'active' });
    assert.strictEqual(activeAfter.total, 2);
  });

  await test('missing key returns 401', async () => {
    const { svc } = makeService();
    await expectStatus(svc.authenticate(null, 'GET', '/deployments'), 401);
    await expectStatus(svc.authenticate('sk_live_bogus', 'GET', '/deployments'), 401);
  });

  await test('scope mapping helper behaves correctly', () => {
    assert.strictEqual(requiredScopeFor('GET', '/users'), SCOPES.READ_USERS);
    assert.strictEqual(requiredScopeFor('POST', '/users'), SCOPES.WRITE_USERS);
    assert.strictEqual(requiredScopeFor('GET', '/deployments'), SCOPES.READ_DEPLOYMENTS);
    assert.strictEqual(requiredScopeFor('PUT', '/deployments'), SCOPES.WRITE_DEPLOYMENTS);
    assert.strictEqual(requiredScopeFor('GET', '/invoices'), SCOPES.READ_INVOICES);
    assert.strictEqual(requiredScopeFor('POST', '/subscriptions'), SCOPES.WRITE_BILLING);
    assert.strictEqual(requiredScopeFor('DELETE', '/webhooks'), SCOPES.WEBHOOK_MANAGE);
    assert.ok(scopeMatches(SCOPES.READ_DEPLOYMENTS, [SCOPES.ALL]));
    assert.ok(!scopeMatches(SCOPES.WRITE_DEPLOYMENTS, [SCOPES.READ_DEPLOYMENTS]));
  });

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  if (failed > 0) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error('Test runner error:', err);
  process.exitCode = 1;
});

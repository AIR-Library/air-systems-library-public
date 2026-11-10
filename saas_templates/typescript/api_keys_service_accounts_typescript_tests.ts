import { ApiKeyService, Scope, InMemoryRateLimitStore } from './api_keys_service_accounts_typescript';
import { jest } from '@jest/globals';

/*
 * Test changes 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP):
 * - The suite opened two real Redis connections to localhost:6379 (`new Redis()` and init's options) and spied on
 *   only incr/expire; with no Redis server ioredis waited for ever and the runner killed the suite at 300 s. The
 *   service now takes a rate-limit store, and the tests use the in-memory one: no network.
 * - The service runs on a fixed clock (10:30 UTC on 2026-06-15), so the hourly rate-limit window cannot roll over in
 *   the middle of the 1,001-request test and the usage-stats range ('2026-01-01'..'2026-12-31') does not depend on
 *   the year the suite runs in. The expired-key test takes "a minute ago" from that clock instead of Date.now().
 */
const FIXED_NOW = new Date('2026-06-15T10:30:00.000Z');

describe('API Key Service', () => {
  let service: ApiKeyService;

  beforeAll(async () => {
    service = new ApiKeyService();
    await service.init(':memory:', {
      rateLimitStore: new InMemoryRateLimitStore(() => FIXED_NOW.getTime()),
      now: () => FIXED_NOW,
    });
  });

  afterAll(async () => {
    await service.close();
  });

  const userId = 'user-123';
  const scopes: Scope[] = ['read:deployments', 'write:webhooks'];

  // KEYS-01
  test('Create key with scopes', async () => {
    const res = await service.createApiKey({
      user_id: userId,
      name: 'My Integration',
      scopes,
      expires_at: '2026-12-31',
      rate_limit: 1000,
    });
    expect(res).toHaveProperty('api_key_id');
    expect(res).toHaveProperty('key');
    expect(res.expires_at).toBe('2026-12-31');
    expect(res.rate_limit).toBe(1000);
  });

  // KEYS-02
  test('Use key: request succeeds with Authorization header', async () => {
    const { api_key_id, key } = await service.createApiKey({
      user_id: userId,
      name: 'Use Test',
      scopes,
    });
    const validation = await service.validateApiKey(
      key,
      '/deployments',
      'GET',
      'read:deployments'
    );
    expect(validation.api_key_id).toBe(api_key_id);
  });

  // KEYS-03
  test('Revoke key: subsequent requests return 401', async () => {
    const { api_key_id, key } = await service.createApiKey({
      user_id: userId,
      name: 'Revoke Test',
      scopes,
    });
    await service.revokeApiKey(api_key_id);
    await expect(
      service.validateApiKey(key, '/deployments', 'GET', 'read:deployments')
    ).rejects.toMatchObject({ status: 401 });
  });

  // KEYS-04
  test('Rate limit: 1001st request in hour returns 429', async () => {
    const { key } = await service.createApiKey({
      user_id: userId,
      name: 'Rate Limit Test',
      scopes,
      rate_limit: 1000,
    });
    const endpoint = '/deployments';
    const method = 'GET';
    const scope = 'read:deployments';
    for (let i = 0; i < 1000; i++) {
      await service.validateApiKey(key, endpoint, method, scope);
    }
    await expect(
      service.validateApiKey(key, endpoint, method, scope)
    ).rejects.toMatchObject({ status: 429 });
  });

  // KEYS-05
  test('Scope check: key with read:deployments cannot write deployments (403)', async () => {
    const { key } = await service.createApiKey({
      user_id: userId,
      name: 'Scope Test',
      scopes: ['read:deployments'],
    });
    await expect(
      service.validateApiKey(key, '/deployments', 'POST', 'write:deployments')
    ).rejects.toMatchObject({ status: 403 });
  });

  // KEYS-06
  test('Rotate: new key works, old key stops after grace period', async () => {
    const { api_key_id, key: oldKey } = await service.createApiKey({
      user_id: userId,
      name: 'Rotate Test',
      scopes,
    });
    const rotation = await service.rotateApiKey(api_key_id);
    const newKey = rotation.new_key;
    // Old key still works within grace period
    await service.validateApiKey(oldKey, '/deployments', 'GET', 'read:deployments');
    // Simulate grace period expiry
    await service.db.run(
      `UPDATE api_keys SET is_active = 0 WHERE id = ?`,
      api_key_id
    );
    await expect(
      service.validateApiKey(oldKey, '/deployments', 'GET', 'read:deployments')
    ).rejects.toMatchObject({ status: 401 });
    // New key works
    await service.validateApiKey(newKey, '/deployments', 'GET', 'read:deployments');
  });

  // KEYS-06
  test('Rotate: old key expires by itself when the 24 h grace period ends', async () => {
    // Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): the test above ends the grace period by hand; this
    // one moves a clock past it.
    let now = FIXED_NOW.getTime();
    const clocked = new ApiKeyService();
    await clocked.init(':memory:', { rateLimitStore: new InMemoryRateLimitStore(() => now), now: () => new Date(now) });
    try {
      const { api_key_id, key: oldKey } = await clocked.createApiKey({ user_id: userId, name: 'Grace Test', scopes });
      const rotation = await clocked.rotateApiKey(api_key_id);
      now += 23 * 60 * 60 * 1000;
      await clocked.validateApiKey(oldKey, '/deployments', 'GET', 'read:deployments');
      now += 2 * 60 * 60 * 1000;
      await expect(
        clocked.validateApiKey(oldKey, '/deployments', 'GET', 'read:deployments')
      ).rejects.toMatchObject({ status: 401 });
      await clocked.validateApiKey(rotation.new_key, '/deployments', 'GET', 'read:deployments');
      await expect(clocked.rotateApiKey(api_key_id)).rejects.toMatchObject({ status: 409 });
    } finally {
      await clocked.close();
    }
  });

  // KEYS-07
  test('Expired key: after expires_at, request returns 401', async () => {
    const { key } = await service.createApiKey({
      user_id: userId,
      name: 'Expire Test',
      scopes,
      expires_at: new Date(FIXED_NOW.getTime() - 1000 * 60).toISOString().split('T')[0],
    });
    await expect(
      service.validateApiKey(key, '/deployments', 'GET', 'read:deployments')
    ).rejects.toMatchObject({ status: 401 });
  });

  // KEYS-08
  test('Usage stats: requests counted per endpoint', async () => {
    const { api_key_id, key } = await service.createApiKey({
      user_id: userId,
      name: 'Stats Test',
      scopes,
    });
    await service.validateApiKey(key, '/deployments', 'GET', 'read:deployments');
    await service.validateApiKey(key, '/webhooks', 'POST', 'write:webhooks');
    const stats = await service.getUsageStats(
      api_key_id,
      '2026-01-01',
      '2026-12-31'
    );
    expect(stats.total_requests).toBe(2);
    expect(stats.requests_by_endpoint['GET /deployments']).toBe(1);
    expect(stats.requests_by_endpoint['POST /webhooks']).toBe(1);
  });

  // KEYS-09
  test('Admin audit: all keys visible to admin', async () => {
    const { api_key_id } = await service.createApiKey({
      user_id: userId,
      name: 'Admin Test',
      scopes,
    });
    const adminRes = await service.adminListApiKeys(userId, 'active');
    expect(adminRes.total).toBeGreaterThanOrEqual(1);
    const found = adminRes.keys.find((k) => k.api_key_id === api_key_id);
    expect(found).toBeDefined();
  });
});
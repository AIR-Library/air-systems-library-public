import { ApiKeyService, Scope } from './api_keys_service_accounts_typescript';
import Redis from 'ioredis';
import { jest } from '@jest/globals';

describe('API Key Service', () => {
  let service: ApiKeyService;
  let redisMock: Redis.Redis;

  beforeAll(async () => {
    redisMock = new Redis();
    jest.spyOn(redisMock, 'incr').mockImplementation(async (key: string) => {
      const val = await redisMock.get(key);
      const num = val ? parseInt(val, 10) : 0;
      await redisMock.set(key, (num + 1).toString());
      return num + 1;
    });
    jest.spyOn(redisMock, 'expire').mockImplementation(async () => 0);
    service = new ApiKeyService();
    await service.init(':memory:');
    service.redis = redisMock;
  });

  afterAll(async () => {
  });

  const userId = 'user-123';
  const scopes: Scope[] = ['read:deployments', 'write:webhooks'];

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

  test('Rate limit: 1001st request in hour returns 429', async () => {
    const { key } = await service.createApiKey({
      user_id: userId,
      name: 'Rate Limit Test',
      scopes,
      rate_limit: 2,
    });
    const endpoint = '/deployments';
    const method = 'GET';
    const scope = 'read:deployments';
    for (let i = 0; i < 2; i++) {
      await service.validateApiKey(key, endpoint, method, scope);
    }
    await expect(
      service.validateApiKey(key, endpoint, method, scope)
    ).rejects.toMatchObject({ status: 429 });
  });

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

  test('Expired key: after expires_at, request returns 401', async () => {
    const { key } = await service.createApiKey({
      user_id: userId,
      name: 'Expire Test',
      scopes,
      expires_at: new Date(Date.now() - 1000 * 60).toISOString().split('T')[0],
    });
    await expect(
      service.validateApiKey(key, '/deployments', 'GET', 'read:deployments')
    ).rejects.toMatchObject({ status: 401 });
  });

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
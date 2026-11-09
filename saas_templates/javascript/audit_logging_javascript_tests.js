import { describe, test, expect, beforeEach } from 'vitest';
const { AuditLogger } = require('./audit_logging_javascript.js');

describe('AuditLogger', () => {
  let logger;

  beforeEach(() => {
    logger = new AuditLogger();
  });

  test('testHappyPathLogMutationAndQuery', async () => {
    const logData = {
      actor_id: 123,
      actor_type: 'user',
      action: 'subscription_changed',
      resource_type: 'subscription',
      resource_id: 456,
      old_value: { tier: 'team', billing_date: '2026-10-15' },
      new_value: { tier: 'enterprise', billing_date: '2026-10-15' },
      why_chain_id: 'wc_789',
      metadata: { ip: '127.0.0.1', user_agent: 'Mozilla/5.0' }
    };

    const res = await logger.logMutation(logData);
    expect(res.success).toBe(true);
    expect(typeof res.log_id).toBe('string');
    expect(res.log_id.length).toBeGreaterThan(0);

    const queryRes = await logger.queryLogs({ actor_id: 123 });
    expect(queryRes.logs.length).toBe(1);
    expect(queryRes.total).toBe(1);
    expect(queryRes.has_more).toBe(false);

    const log = queryRes.logs[0];
    expect(log.id).toBe(res.log_id);
    expect(log.timestamp).toBeDefined();
    expect(typeof log.timestamp).toBe('string');
    expect(log.actor_id).toBe(123);
    expect(log.action).toBe('subscription_changed');
    expect(log.resource_type).toBe('subscription');
    expect(log.resource_id).toBe('456');
    expect(log.old_value).toEqual(logData.old_value);
    expect(log.new_value).toEqual(logData.new_value);
    expect(log.why_chain_id).toBe('wc_789');
  });

  test('testReplayDivergenceDetection', async () => {
    const log1 = await logger.logMutation({
      actor_id: 123,
      actor_type: 'user',
      action: 'user_created',
      resource_type: 'user',
      resource_id: 'user_999',
      old_value: null,
      new_value: { status: 'active', email: 'test@example.com' }
    });

    const replay1 = await logger.replay(log1.log_id);
    expect(replay1.log_id).toBe(log1.log_id);
    expect(replay1.timestamp).toBeDefined();
    expect(replay1.resource_state_at_time).toBeNull();
    expect(replay1.has_diverged).toBe(false);

    await logger.logMutation({
      actor_id: 123,
      actor_type: 'user',
      action: 'user_suspended',
      resource_type: 'user',
      resource_id: 'user_999',
      old_value: { status: 'active', email: 'test@example.com' },
      new_value: { status: 'suspended', email: 'test@example.com' }
    });

    const replay2 = await logger.replay(log1.log_id);
    expect(replay2.has_diverged).toBe(true);

    const replay3 = await logger.replay(log1.log_id, { status: 'active', email: 'test@example.com' });
    expect(replay3.has_diverged).toBe(true);

    const log4 = await logger.logMutation({
      actor_id: 456,
      actor_type: 'user',
      action: 'user_created',
      resource_type: 'user',
      resource_id: 'user_888',
      old_value: null,
      new_value: { status: 'pending', email: 'other@example.com' }
    });
    const replay4 = await logger.replay(log4.log_id, { status: 'pending', email: 'other@example.com' });
    expect(replay4.has_diverged).toBe(false);
    expect(replay4.resource_state_at_time).toBeNull();
  });

  test('testFilteringActorActionResourceType', async () => {
    await logger.logMutation({ actor_id: 'user_a', actor_type: 'user', action: 'user_created', resource_type: 'user', resource_id: '1' });
    await logger.logMutation({ actor_id: 'user_b', actor_type: 'user', action: 'user_suspended', resource_type: 'user', resource_id: '2' });
    await logger.logMutation({ actor_id: 'user_a', actor_type: 'user', action: 'billing_changed', resource_type: 'billing', resource_id: '3' });

    const filterRes = await logger.queryLogs({ actor_id: 'user_a', resource_type: 'user' });
    expect(filterRes.logs.length).toBe(1);
    expect(filterRes.total).toBe(1);
    expect(filterRes.has_more).toBe(false);
    expect(filterRes.logs[0].action).toBe('user_created');
    expect(filterRes.logs[0].actor_id).toBe('user_a');
    expect(filterRes.logs[0].resource_type).toBe('user');
  });

  test('testPaginationLimitOffset', async () => {
    for (let i = 0; i < 15; i++) {
      await logger.logMutation({
        actor_id: 'paginator',
        actor_type: 'user',
        action: 'item_created',
        resource_type: 'item',
        resource_id: String(i)
      });
    }

    const page1 = await logger.queryLogs({ actor_id: 'paginator', limit: 10, offset: 0 });
    expect(page1.logs.length).toBe(10);
    expect(page1.has_more).toBe(true);
    expect(page1.total).toBe(15);

    const page2 = await logger.queryLogs({ actor_id: 'paginator', limit: 10, offset: 10 });
    expect(page2.logs.length).toBe(5);
    expect(page2.has_more).toBe(false);
    expect(page2.total).toBe(15);

    const page1Ids = new Set(page1.logs.map(l => l.id));
    const page2Ids = new Set(page2.logs.map(l => l.id));
    for (const id of page1Ids) {
      expect(page2Ids.has(id)).toBe(false);
    }

    for (let i = 0; i < page1.logs.length - 1; i++) {
      expect(page1.logs[i].timestamp >= page1.logs[i + 1].timestamp).toBe(true);
    }
    for (let i = 0; i < page2.logs.length - 1; i++) {
      expect(page2.logs[i].timestamp >= page2.logs[i + 1].timestamp).toBe(true);
    }
  });

  test('testPerformanceOneMillionLogs', async () => {
    const perfLogger = new AuditLogger();
    const batchSize = 1000000;
    const mockLogs = [];
    const baseTime = Date.now();

    for (let i = 0; i < batchSize; i++) {
      const actorId = `user_${i % 1000}`;
      const action = i % 2 === 0 ? 'user_created' : 'user_suspended';
      const resourceType = 'user';
      const resourceId = `res_${i}`;
      const timestamp = new Date(baseTime - i * 1000).toISOString();

      const log = {
        id: `uuid_${i}`,
        timestamp,
        actor_id: actorId,
        actor_type: 'user',
        action,
        resource_type: resourceType,
        resource_id: resourceId,
        old_value: null,
        new_value: { index: i },
        why_chain_id: null,
        metadata: null
      };
      Object.freeze(log);
      if (log.new_value) Object.freeze(log.new_value);
      mockLogs.push(log);
    }

    perfLogger.logs = mockLogs;
    for (let i = 0; i < mockLogs.length; i++) {
      const log = mockLogs[i];
      perfLogger.indexById.set(log.id, log);

      const actorKey = String(log.actor_id);
      if (!perfLogger.indexByActor.has(actorKey)) perfLogger.indexByActor.set(actorKey, []);
      perfLogger.indexByActor.get(actorKey).push(log);

      if (!perfLogger.indexByAction.has(log.action)) perfLogger.indexByAction.set(log.action, []);
      perfLogger.indexByAction.get(log.action).push(log);

      if (!perfLogger.indexByResourceType.has(log.resource_type)) perfLogger.indexByResourceType.set(log.resource_type, []);
      perfLogger.indexByResourceType.get(log.resource_type).push(log);
    }

    const queryStart = Date.now();
    const queryRes = await perfLogger.queryLogs({
      actor_id: 'user_500',
      action: 'user_created',
      resource_type: 'user',
      limit: 50
    });
    const queryDuration = Date.now() - queryStart;
    console.log(`Query returned ${queryRes.logs.length} results in ${queryDuration}ms`);
    expect(queryDuration).toBeLessThan(100);
    expect(queryRes.logs.length).toBeLessThanOrEqual(50);
    expect(queryRes.total).toBeGreaterThanOrEqual(50);
  });

  test('testImmutabilityUpdateDeleteForbidden', async () => {
    const log = await logger.logMutation({
      actor_id: 'system',
      actor_type: 'service',
      action: 'system_init',
      resource_type: 'system',
      resource_id: '0'
    });

    let updateThrew = false;
    try {
      await logger.updateLog(log.log_id, { action: 'hacked' });
    } catch (err) {
      updateThrew = true;
      expect(err.message).toContain('immutable');
    }
    expect(updateThrew).toBe(true);

    let deleteThrew = false;
    try {
      await logger.deleteLog(log.log_id);
    } catch (err) {
      deleteThrew = true;
      expect(err.message).toContain('immutable');
    }
    expect(deleteThrew).toBe(true);
  });

  test('testWildcardActionMatching', async () => {
    await logger.logMutation({ actor_id: 1, actor_type: 'user', action: 'user_created', resource_type: 'user', resource_id: '1' });
    await logger.logMutation({ actor_id: 1, actor_type: 'user', action: 'user_suspended', resource_type: 'user', resource_id: '2' });
    await logger.logMutation({ actor_id: 1, actor_type: 'user', action: 'billing_changed', resource_type: 'billing', resource_id: '3' });

    const wildcardRes = await logger.queryLogs({ action: 'user_*' });
    expect(wildcardRes.logs.length).toBe(2);
    expect(wildcardRes.total).toBe(2);
    expect(wildcardRes.has_more).toBe(false);

    const actions = wildcardRes.logs.map(l => l.action);
    expect(actions).toContain('user_created');
    expect(actions).toContain('user_suspended');
    expect(actions).not.toContain('billing_changed');

    for (const action of actions) {
      expect(action.startsWith('user_')).toBe(true);
    }
  });
});

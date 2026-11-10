import { describe, test, expect, beforeEach } from 'vitest';
const { AuditLogger, AuditError } = require('./audit_logging_javascript.js');

// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: reads are admin-only now (AUDIT-10), so the tests read as a verified
// admin caller; time comes from a clock the tests move, so ordering never depends on the machine's speed.
const ADMIN = { id: 'admin-1', role: 'admin' };
const BASE = Date.parse('2026-01-01T00:00:00.000Z');

/** Expects fn to reject with an AuditError of this status and code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
async function expectAuditError(fn, status, code) {
  let caught = null;
  try { await fn(); } catch (e) { caught = e; }
  expect(caught).toBeInstanceOf(AuditError);
  expect(caught.status).toBe(status);
  expect(caught.code).toBe(code);
}

describe('AuditLogger', () => {
  let logger;
  let clock;

  beforeEach(() => {
    clock = BASE;
    logger = new AuditLogger({ now: () => (clock += 1000) });
  });

  // AUDIT-01
  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: ip and user agent go in the entry's actor row now (metadata may hold
  // only feature_flag / erased_rows), and a subscription entry names its data subject (subject_user_id).
  test('testHappyPathLogMutationAndQuery', async () => {
    const logData = {
      actor_id: 123,
      actor_type: 'user',
      subject_user_id: 123,
      action: 'subscription_changed',
      resource_type: 'subscription',
      resource_id: 456,
      old_value: { tier: 'team', billing_date: '2026-10-15' },
      new_value: { tier: 'enterprise', billing_date: '2026-10-15' },
      why_chain_id: 'wc_789',
      ip: '127.0.0.1',
      user_agent: 'Mozilla/5.0'
    };

    const res = await logger.logMutation(logData);
    expect(res.success).toBe(true);
    expect(typeof res.log_id).toBe('string');
    expect(res.log_id.length).toBeGreaterThan(0);

    const queryRes = await logger.queryLogs({ actor_id: 123 }, ADMIN);
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
    expect(log.personal_erased).toBe(false);
    // The event row itself holds none of it: the snapshots are in the subject row, ip and agent in the actor row.
    const tables = logger.tables(ADMIN);
    expect(tables.audit_log[0]).toMatchObject({ resource_id: null, old_value: null, new_value: null, why_chain_id: null,
      personal_roles: 'actor,subject', metadata: null });
    expect(tables.audit_personal.find((r) => r.role === 'actor').data).toEqual(
      { actor_id: 123, ip: '127.0.0.1', user_agent: 'Mozilla/5.0', request_id: null });
  });

  // AUDIT-02
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

    const replay1 = await logger.replay(log1.log_id, null, ADMIN);
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

    const replay2 = await logger.replay(log1.log_id, null, ADMIN);
    expect(replay2.has_diverged).toBe(true);

    const replay3 = await logger.replay(log1.log_id, { status: 'active', email: 'test@example.com' }, ADMIN);
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
    const replay4 = await logger.replay(log4.log_id, { status: 'pending', email: 'other@example.com' }, ADMIN);
    expect(replay4.has_diverged).toBe(false);
    expect(replay4.resource_state_at_time).toBeNull();
  });

  // AUDIT-03
  test('testFilteringActorActionResourceType', async () => {
    await logger.logMutation({ actor_id: 'user_a', actor_type: 'user', action: 'user_created', resource_type: 'user', resource_id: '1' });
    await logger.logMutation({ actor_id: 'user_b', actor_type: 'user', action: 'user_suspended', resource_type: 'user', resource_id: '2' });
    await logger.logMutation({ actor_id: 'user_a', actor_type: 'user', action: 'billing_changed', resource_type: 'billing', resource_id: '3', subject_user_id: 'user_a' });
    await logger.logMutation({ actor_id: 'user_a', actor_type: 'user', action: 'user_suspended', resource_type: 'user', resource_id: '4' });

    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: all three filters together, as the row says (was two).
    const all3 = await logger.queryLogs({ actor_id: 'user_a', action: 'user_created', resource_type: 'user' }, ADMIN);
    expect(all3.logs.map((l) => l.resource_id)).toEqual(['1']);

    const filterRes = await logger.queryLogs({ actor_id: 'user_a', resource_type: 'user', action: 'user_c*' }, ADMIN);
    expect(filterRes.logs.length).toBe(1);
    expect(filterRes.total).toBe(1);
    expect(filterRes.has_more).toBe(false);
    expect(filterRes.logs[0].action).toBe('user_created');
    expect(filterRes.logs[0].actor_id).toBe('user_a');
    expect(filterRes.logs[0].resource_type).toBe('user');
  });

  // AUDIT-04
  test('testPaginationLimitOffset', async () => {
    for (let i = 0; i < 15; i++) {
      await logger.logMutation({
        actor_id: 'paginator',
        actor_type: 'user',
        action: 'item_created',
        resource_type: 'item',
        subject_user_id: 'none',
        resource_id: String(i)
      });
    }

    const page1 = await logger.queryLogs({ actor_id: 'paginator', limit: 10, offset: 0 }, ADMIN);
    expect(page1.logs.length).toBe(10);
    expect(page1.has_more).toBe(true);
    expect(page1.total).toBe(15);

    const page2 = await logger.queryLogs({ actor_id: 'paginator', limit: 10, offset: 10 }, ADMIN);
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

  // AUDIT-05
  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the million entries are now written through log() (the old test
  // filled private arrays that the rebuilt store no longer has); the query budget is unchanged (< 100 ms).
  test('testPerformanceOneMillionLogs', async () => {
    let t = BASE;
    const perfLogger = new AuditLogger({ now: () => t });
    const batchSize = 1000000;
    for (let i = 0; i < batchSize; i++) {
      t = BASE + i * 1000;
      await perfLogger.log({
        actor_id: `user_${i % 1000}`,
        actor_type: 'user',
        action: i % 2 === 0 ? 'user_created' : 'user_suspended',
        resource_type: 'user',
        resource_id: `res_${i % 5000}`,
      });
    }
    expect(perfLogger.logs.length).toBe(batchSize);

    const queryStart = process.hrtime.bigint();
    const queryRes = await perfLogger.queryLogs({
      actor_id: 'user_500',
      action: 'user_created',
      resource_type: 'user',
      limit: 50
    }, ADMIN);
    const queryDuration = Number(process.hrtime.bigint() - queryStart) / 1e6;
    console.log(`Query returned ${queryRes.logs.length} results in ${queryDuration}ms`);
    expect(queryDuration).toBeLessThan(100);
    expect(queryRes.logs.length).toBe(50);
    expect(queryRes.total).toBe(1000);
    expect(queryRes.logs.every((l) => l.actor_id === 'user_500' && l.action === 'user_created')).toBe(true);
  // Building the million entries takes several seconds, so only the setup gets the time; the query must still be
  // < 100 ms (first measured 2026-11-09, session 04ec72ff).
  }, 300_000);

  // AUDIT-06
  test('testImmutabilityUpdateDeleteForbidden', async () => {
    const log = await logger.logMutation({
      actor_id: 'system',
      actor_type: 'service',
      action: 'system_init',
      resource_type: 'system',
      subject_user_id: 'none',
      resource_id: '0'
    });
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the stored row itself cannot be changed either.
    expect(Object.isFrozen(logger.logs[0])).toBe(true);
    expect(() => { 'use strict'; logger.logs[0].action = 'hacked'; }).toThrow();

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

  // AUDIT-07
  test('testWildcardActionMatching', async () => {
    await logger.logMutation({ actor_id: 1, actor_type: 'user', action: 'user_created', resource_type: 'user', resource_id: '1' });
    await logger.logMutation({ actor_id: 1, actor_type: 'user', action: 'user_suspended', resource_type: 'user', resource_id: '2' });
    await logger.logMutation({ actor_id: 1, actor_type: 'user', action: 'billing_changed', resource_type: 'billing', resource_id: '3', subject_user_id: 1 });

    const wildcardRes = await logger.queryLogs({ action: 'user_*' }, ADMIN);
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

  /**
   * AUDIT-08: erase_subject removes the user's id, email and IP from every retained row of audit_log, audit_personal
   * and audit_subjects (distinctive values: id 987654321, email erase.me@example.test, IP 203.0.113.77); every earlier
   * audit_log row is unchanged and exactly one 'audit_subject_erased' row is added; queries show the user's entries
   * with personal_erased true, an actor_id filter for the user finds nothing, replay reports erased, and the other
   * users' data is untouched. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
   */
  // AUDIT-08
  test('eraseSubject leaves no trace of the user in any table', async () => {
    const UID = 987654321;
    const EMAIL = 'erase.me@example.test';
    const IP = '203.0.113.77';
    const created = await logger.log({ actor_id: UID, actor_type: 'user', action: 'user_created', resource_type: 'user',
      resource_id: UID, new_value: { email: EMAIL, status: 'active' }, ip: IP, user_agent: 'UA/1', request_id: 'req-1' });
    await logger.log({ actor_id: UID, actor_type: 'user', subject_user_id: UID, action: 'subscription_changed',
      resource_type: 'subscription', resource_id: 'sub_9', old_value: { tier: 'solo', billing_email: EMAIL },
      new_value: { tier: 'team', billing_email: EMAIL }, why_chain_id: 'wc_1', ip: IP });
    await logger.log({ actor_id: 'admin-7', actor_type: 'user', action: 'user_suspended', resource_type: 'user',
      resource_id: UID, old_value: { email: EMAIL, status: 'active' }, new_value: { email: EMAIL, status: 'suspended' },
      ip: '198.51.100.1' });
    await logger.log({ actor_id: 'key_42', actor_type: 'api_key', actor_user_id: UID, subject_user_id: 'none',
      action: 'deployment_created', resource_type: 'deployment', resource_id: 'dep_1', ip: IP });
    await logger.log({ actor_id: 'other-user', actor_type: 'user', action: 'user_created', resource_type: 'user',
      resource_id: 'other-user', new_value: { email: 'keep@example.test' }, ip: '192.0.2.5' });

    const before = logger.tables(ADMIN);
    const result = await logger.eraseSubject(UID);
    expect(result.erased_rows).toBe(6); // actor rows of entries 1, 2 and 4; subject rows of entries 1, 2 and 3
    const after = logger.tables(ADMIN);

    const dump = JSON.stringify(after);
    for (const needle of [String(UID), EMAIL, IP]) expect(dump.includes(needle)).toBe(false);
    expect(after.audit_log.slice(0, before.audit_log.length)).toEqual(before.audit_log);
    expect(after.audit_log).toHaveLength(before.audit_log.length + 1);
    const added = after.audit_log[after.audit_log.length - 1];
    expect(added).toMatchObject({ action: 'audit_subject_erased', actor_type: 'service', resource_type: 'user',
      resource_id: null, personal_roles: '', metadata: { erased_rows: 6 } });

    const q = await logger.queryLogs({ action: 'user_*' }, ADMIN);
    const erasedEntry = q.logs.find((l) => l.id === created.log_id);
    expect(erasedEntry).toMatchObject({ personal_erased: true, actor_id: null, resource_id: null, new_value: null });
    const other = q.logs.find((l) => l.resource_id === 'other-user');
    expect(other).toMatchObject({ personal_erased: false, actor_id: 'other-user', new_value: { email: 'keep@example.test' } });
    expect((await logger.queryLogs({ actor_id: UID }, ADMIN)).total).toBe(0);
    expect((await logger.queryLogs({ actor_id: String(UID) }, ADMIN)).total).toBe(0);
    expect((await logger.search(EMAIL, null, 50, ADMIN)).results).toHaveLength(0);
    expect(await logger.replay(created.log_id, null, ADMIN)).toEqual({ log_id: created.log_id,
      timestamp: before.audit_log[0].timestamp, erased: true, resource_state_at_time: null, has_diverged: null });
  });

  /**
   * AUDIT-09: apply_retention erases the personal data of entries older than the retention period (and subjects left
   * with none); newer entries keep theirs; no audit_log row is removed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches memory only.
   */
  // AUDIT-09
  test('applyRetention erases old personal data only and keeps every event', async () => {
    let t = BASE;
    const retained = new AuditLogger({ now: () => t, retentionDays: 30 });
    await retained.log({ actor_id: 'old-user', actor_type: 'user', action: 'user_created', resource_type: 'user',
      resource_id: 'old-user', new_value: { email: 'old@example.test' }, ip: '192.0.2.10' });
    t = BASE + 20 * 24 * 60 * 60 * 1000;
    await retained.log({ actor_id: 'new-user', actor_type: 'user', action: 'user_created', resource_type: 'user',
      resource_id: 'new-user', new_value: { email: 'new@example.test' }, ip: '192.0.2.20' });
    const before = retained.tables(ADMIN);

    const now = BASE + 40 * 24 * 60 * 60 * 1000;
    const res = await retained.applyRetention(now);
    expect(res.erased_rows).toBe(2);
    const after = retained.tables(ADMIN);
    expect(after.audit_log).toEqual(before.audit_log);
    const dump = JSON.stringify(after);
    expect(dump.includes('old@example.test')).toBe(false);
    expect(dump.includes('192.0.2.10')).toBe(false);
    expect(dump.includes('old-user')).toBe(false);
    expect(dump.includes('new@example.test')).toBe(true);
    expect(after.audit_subjects.map((s) => s.user_id)).toEqual(['new-user']);
    const logs = (await retained.queryLogs({}, ADMIN)).logs;
    expect(logs.map((l) => l.personal_erased)).toEqual([false, true]);
    expect((await retained.applyRetention(now)).erased_rows).toBe(0);
  });

  /**
   * AUDIT-10: log() refuses a non-'user' entry without subject_user_id (400 subject_required), a metadata key other
   * than feature_flag / erased_rows (400 metadata_key_not_allowed), an api_key entry without actor_user_id
   * (400 actor_user_required) and a user entry naming another subject (400 subject_mismatch); nothing is written by a
   * refused call; every read by a caller who is not an admin gets 403. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches memory only.
   */
  // AUDIT-10
  test('log() validation codes and admin-only reads', async () => {
    await expectAuditError(() => logger.log({ actor_id: 1, action: 'subscription_changed', resource_type: 'subscription',
      resource_id: 5 }), 400, 'subject_required');
    await expectAuditError(() => logger.log({ actor_id: 1, action: 'flag_set', resource_type: 'flag', subject_user_id: 'none',
      resource_id: 'f', metadata: { feature_flag: 'x', ip: '192.0.2.1' } }), 400, 'metadata_key_not_allowed');
    await expectAuditError(() => logger.log({ actor_id: 'key_1', actor_type: 'api_key', action: 'deployment_created',
      resource_type: 'deployment', subject_user_id: 'none', resource_id: 'd' }), 400, 'actor_user_required');
    await expectAuditError(() => logger.log({ actor_id: 1, action: 'user_suspended', resource_type: 'user',
      resource_id: 2, subject_user_id: 3 }), 400, 'subject_mismatch');
    expect(logger.logs).toHaveLength(0);
    expect(logger.subjectsByUser.size).toBe(0);

    const ok = await logger.log({ actor_id: 1, action: 'flag_set', resource_type: 'flag', subject_user_id: 'none',
      resource_id: 'f', metadata: { feature_flag: 'beta' } });
    expect(ok.success).toBe(true);
    for (const caller of [undefined, null, { id: 1, role: 'member' }, { id: 1 }]) {
      await expectAuditError(() => logger.queryLogs({}, caller), 403, 'admin_only');
      await expectAuditError(() => logger.replay(ok.log_id, null, caller), 403, 'admin_only');
      await expectAuditError(() => logger.search('flag', null, 50, caller), 403, 'admin_only');
    }
    expect((await logger.queryLogs({}, ADMIN)).total).toBe(1);
  });
});

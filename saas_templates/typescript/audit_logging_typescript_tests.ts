/**
 * Audit logging tests against a real in-memory SQLite (better-sqlite3) through the logger's Database interface.
 *
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: adapted to the AUDIT-08/09/10 amendments and given the spec ids.
 * - Each test gets a fresh database: audit_log is append-only now, so the old "DELETE FROM audit_log" reset is
 *   (rightly) refused by its trigger.
 * - Reads take the verified caller (admins only, AUDIT-10), and entries on a resource other than 'user' name their
 *   data subject (subject_user_id, or 'none'). The assertions of the earlier tests are otherwise unchanged.
 * - Added: AUDIT-05 (1,000,000 entries, 100 ms budget), AUDIT-06 (UPDATE/DELETE refused), AUDIT-08, AUDIT-09 and
 *   AUDIT-10. Touches: in-memory SQLite only.
 */
import Database, { Database as BetterSqliteDatabase } from 'better-sqlite3';
import { AuditLogger, AuditError, Database as AuditDatabase, QueryResult } from './audit_logging_typescript';

class SqliteTestDatabase implements AuditDatabase {
  private db: BetterSqliteDatabase;

  constructor() {
    this.db = new Database(':memory:');
    this.db.pragma('journal_mode = WAL');
  }

  /** The underlying handle, for seeding and for checks outside the logger. */
  get raw(): BetterSqliteDatabase {
    return this.db;
  }

  private convertPlaceholders(sql: string): string {
    // Replace PostgreSQL ILIKE with SQLite LIKE (case-insensitive by default for ASCII)
    sql = sql.replace(/ILIKE/gi, 'LIKE');
    // Replace $1, $2, ... with ? placeholders
    return sql.replace(/\$(\d+)/g, () => '?');
  }

  async query(text: string, values?: any[]): Promise<QueryResult> {
    const sql = this.convertPlaceholders(text);

    // Handle multi-statement SQL (e.g., CREATE TABLE + CREATE INDEX) when no parameters
    if ((!values || values.length === 0) && sql.includes(';')) {
      const statements = sql.split(';').map(s => s.trim()).filter(s => s.length > 0);
      if (statements.length > 1) {
        this.db.exec(sql);
        return { rows: [], rowCount: 0 };
      }
    }

    const stmt = this.db.prepare(sql);

    if (sql.trim().toUpperCase().startsWith('SELECT')) {
      const rows = values ? stmt.all(...values) : stmt.all();
      return { rows, rowCount: rows.length };
    }
    const result = values ? stmt.run(...values) : stmt.run();
    return { rows: [], rowCount: result.changes };
  }

  async close(): Promise<void> {
    this.db.close();
  }
}

const ADMIN = { id: 1, is_admin: true };

let testDb: SqliteTestDatabase;
let auditLogger: AuditLogger;

beforeEach(async () => {
  testDb = new SqliteTestDatabase();
  await testDb.query(AuditLogger.CREATE_TABLE_SQL_SQLITE);
  auditLogger = new AuditLogger(testDb);
});

afterEach(async () => {
  await testDb.close();
});

describe('logMutation', () => {
  // AUDIT-01
  it('should log a mutation and return log_id, and query it back', async () => {
    const input = {
      actor_id: 123,
      actor_type: 'user' as const,
      subject_user_id: 789,
      action: 'subscription_changed',
      resource_type: 'subscription',
      resource_id: 456,
      old_value: { tier: 'team', billing_date: '2026-10-15' },
      new_value: { tier: 'enterprise', billing_date: '2026-10-15' },
      why_chain_id: 'wc_789'
    };

    const result = await auditLogger.logMutation(input);
    expect(result).toEqual({ success: true, log_id: expect.any(String) });
    expect(result.log_id.length).toBe(36);

    const back = await auditLogger.queryLogs(ADMIN, {});
    expect(back.total).toBe(1);
    expect(back.logs[0]).toMatchObject({
      id: result.log_id, actor_id: 123, action: 'subscription_changed', resource_type: 'subscription',
      resource_id: 456, old_value: input.old_value, new_value: input.new_value, why_chain_id: 'wc_789',
      personal_erased: false,
    });
  });

  it('should handle null actor_id', async () => {
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 audit amendment): a 'service' actor must name its
    // service (400 actor_service_required otherwise), so this entry now carries actor_service.
    const input = {
      actor_id: null,
      actor_type: 'service' as const,
      actor_service: 'backup',
      subject_user_id: 'none',
      action: 'system_backup',
      resource_type: 'database',
      resource_id: 'db_001',
      old_value: { size: '100GB' },
      new_value: { size: '150GB' }
    };

    const result = await auditLogger.logMutation(input);
    expect(result.success).toBe(true);
  });
});

describe('queryLogs', () => {
  const baseLog = {
    actor_id: 100,
    actor_type: 'user' as const,
    action: 'user_created',
    resource_type: 'user',
    resource_id: 1,
    old_value: null,
    new_value: { id: 1, name: 'Test User' }
  };

  beforeEach(async () => {
    await auditLogger.logMutation(baseLog);
    await auditLogger.logMutation({
      ...baseLog,
      actor_id: 200,
      action: 'user_updated',
      resource_id: 2,
      old_value: { id: 2, name: 'Old Name' },
      new_value: { id: 2, name: 'New Name' }
    });
    await auditLogger.logMutation({
      ...baseLog,
      actor_id: 100,
      action: 'user_suspended',
      resource_id: 3,
      old_value: { id: 3, status: 'active' },
      new_value: { id: 3, status: 'suspended' }
    });
  });

  it('should filter by actor_id', async () => {
    const result = await auditLogger.queryLogs(ADMIN, { actor_id: 100 });
    expect(result.total).toBe(2);
    expect(result.logs.length).toBe(2);
    expect(result.logs.every(log => log.actor_id === 100)).toBe(true);
  });

  // AUDIT-07
  it('should filter by action with wildcard', async () => {
    await auditLogger.logMutation({ ...baseLog, action: 'userXcreated', resource_id: 9 });
    const result = await auditLogger.queryLogs(ADMIN, { action: 'user_*' });
    // "_" is literal: userXcreated does not match user_*
    expect(result.total).toBe(3);
    expect(result.logs.map(l => l.action).sort()).toEqual(['user_created', 'user_suspended', 'user_updated']);
  });

  it('should filter by resource_type', async () => {
    const result = await auditLogger.queryLogs(ADMIN, { resource_type: 'user' });
    expect(result.total).toBe(3);
  });

  // AUDIT-03
  it('combines actor_id, action and resource_type', async () => {
    await auditLogger.logMutation({ ...baseLog, actor_id: 100, action: 'billing_changed', resource_type: 'subscription',
      subject_user_id: 'none', resource_id: 'sub_1' });
    const result = await auditLogger.queryLogs(ADMIN, { actor_id: 100, action: 'user_*', resource_type: 'user' });
    expect(result.total).toBe(2);
    expect(result.logs.map(l => l.action).sort()).toEqual(['user_created', 'user_suspended']);
  });

  // AUDIT-04
  it('should paginate with limit and offset', async () => {
    const firstPage = await auditLogger.queryLogs(ADMIN, { limit: 2, offset: 0 });
    expect(firstPage.logs.length).toBe(2);
    expect(firstPage.has_more).toBe(true);

    const secondPage = await auditLogger.queryLogs(ADMIN, { limit: 2, offset: 2 });
    expect(secondPage.logs.length).toBe(1);
    expect(secondPage.has_more).toBe(false);
    const ids = [...firstPage.logs, ...secondPage.logs].map(l => l.id);
    expect(new Set(ids).size).toBe(3);
  });

  it('should filter by date range', async () => {
    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
    const tomorrow = new Date(Date.now() + 86400000).toISOString().split('T')[0];
    const result = await auditLogger.queryLogs(ADMIN, { date_from: yesterday, date_to: tomorrow });
    expect(result.total).toBe(3);
  });

  it('includes rows written on the date_to day itself', async () => {
    // The bound is compared as text on SQLite; "YYYY-MM-DD 23:59:59.999" sorted before every ISO time of that
    // day, so the last day of a range was empty (CodeRabbit, PR 18).
    const today = new Date().toISOString().split('T')[0];
    const result = await auditLogger.queryLogs(ADMIN, { date_from: today, date_to: today });
    expect(result.total).toBe(3);
  });

  it('should return total and has_more correctly', async () => {
    const result = await auditLogger.queryLogs(ADMIN, {});
    expect(result.total).toBe(3);
    expect(result.has_more).toBe(false);
  });
});

describe('replay', () => {
  it('should return state at log time and detect no divergence when unchanged', async () => {
    const logResult = await auditLogger.logMutation({
      actor_id: 1,
      actor_type: 'user',
      action: 'user_created',
      resource_type: 'user',
      resource_id: 1,
      old_value: null,
      new_value: { id: 1, name: 'Alice' }
    });

    const replayResult = await auditLogger.replay(ADMIN, logResult.log_id);
    expect(replayResult).toEqual({
      log_id: logResult.log_id,
      timestamp: expect.any(String),
      resource_state_at_time: null,
      has_diverged: false
    });
  });

  // AUDIT-02
  it('should detect divergence when resource changed after log', async () => {
    const logResult = await auditLogger.logMutation({
      actor_id: 1,
      actor_type: 'user',
      action: 'user_created',
      resource_type: 'user',
      resource_id: 1,
      old_value: null,
      new_value: { id: 1, name: 'Alice' }
    });

    await auditLogger.logMutation({
      actor_id: 2,
      actor_type: 'user',
      action: 'user_updated',
      resource_type: 'user',
      resource_id: 1,
      old_value: { id: 1, name: 'Alice' },
      new_value: { id: 1, name: 'Alice Updated' }
    });

    const replayResult = await auditLogger.replay(ADMIN, logResult.log_id);
    expect(replayResult.resource_state_at_time).toBeNull();
    expect(replayResult.has_diverged).toBe(true);
  });

  // AUDIT-02
  it('detects divergence for a resource with no data subject too', async () => {
    const first = await auditLogger.log({ actor_type: 'service', actor_service: 'deployer', subject_user_id: 'none',
      action: 'deployment_created', resource_type: 'deployment', resource_id: 'd1', old_value: null, new_value: { v: 1 } });
    const second = await auditLogger.log({ actor_type: 'service', actor_service: 'deployer', subject_user_id: 'none',
      action: 'deployment_updated', resource_type: 'deployment', resource_id: 'd1', old_value: { v: 1 }, new_value: { v: 2 } });
    expect((await auditLogger.replay(ADMIN, first.log_id)).has_diverged).toBe(true);
    expect(await auditLogger.replay(ADMIN, second.log_id)).toMatchObject({ resource_state_at_time: { v: 1 }, has_diverged: false });
  });

  it('should handle resource deletion as divergence', async () => {
    // Note: This test assumes deletion is represented by a log setting new_value to null
    const createLog = await auditLogger.logMutation({
      actor_id: 1,
      actor_type: 'user',
      action: 'user_created',
      resource_type: 'user',
      resource_id: 1,
      old_value: null,
      new_value: { id: 1, name: 'Alice' }
    });

    await auditLogger.logMutation({
      actor_id: 2,
      actor_type: 'user',
      action: 'user_deleted',
      resource_type: 'user',
      resource_id: 1,
      old_value: { id: 1, name: 'Alice' },
      new_value: null
    });

    const replayResult = await auditLogger.replay(ADMIN, createLog.log_id);
    expect(replayResult.resource_state_at_time).toBeNull();
    expect(replayResult.has_diverged).toBe(true); // Because current state (null) != new_value of create log ({ id: 1, name: 'Alice' })
  });

  it('should throw error for non-existent log', async () => {
    await expect(auditLogger.replay(ADMIN, 'non-existent-id')).rejects.toThrow('Log not found');
  });
});

describe('search', () => {
  beforeEach(async () => {
    await auditLogger.logMutation({
      actor_id: 1,
      actor_type: 'user',
      action: 'user_email_updated',
      resource_type: 'user',
      resource_id: 1,
      old_value: { email: 'old@example.com' },
      new_value: { email: 'new@example.com' }
    });

    await auditLogger.logMutation({
      actor_id: 2,
      actor_type: 'user',
      action: 'profile_updated',
      resource_type: 'user',
      resource_id: 2,
      old_value: { bio: 'Old bio' },
      new_value: { bio: 'New bio' }
    });
  });

  it('should search in action and resource_type', async () => {
    const result = await auditLogger.search(ADMIN, { q: 'email' });
    expect(result.results.length).toBe(1);
    expect(result.results[0].action).toBe('user_email_updated');
  });

  it('should filter by resource_type in search', async () => {
    const result = await auditLogger.search(ADMIN, { q: 'updated', resource_type: 'user' });
    expect(result.results.length).toBe(2);
  });

  it('should limit results', async () => {
    const result = await auditLogger.search(ADMIN, { q: 'updated', limit: 1 });
    expect(result.results.length).toBe(1);
  });
});

/**
 * AUDIT-06: audit_log is append-only: UPDATE and DELETE are refused by the database, and audit_personal rows are
 * never updated. In: one logged entry. Out: assertions only. Why: AUDIT-06 had no test here.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
 */
describe('immutability', () => {
  // AUDIT-06
  it('refuses UPDATE and DELETE on audit_log and UPDATE on audit_personal', async () => {
    const { log_id } = await auditLogger.log({ actor_type: 'user', actor_id: 5, action: 'user_created', resource_type: 'user',
      resource_id: 5, new_value: { id: 5 } });
    await expect(testDb.query(`UPDATE audit_log SET action = 'tampered' WHERE id = $1`, [log_id])).rejects.toThrow(/append-only/);
    await expect(testDb.query(`DELETE FROM audit_log WHERE id = $1`, [log_id])).rejects.toThrow(/append-only/);
    await expect(testDb.query(`UPDATE audit_personal SET data = '{}' WHERE log_id = $1`, [log_id])).rejects.toThrow(/never updated/);
    const back = await auditLogger.queryLogs(ADMIN, {});
    expect(back.logs[0].action).toBe('user_created');
  });
});

/**
 * AUDIT-08: erase_subject. The user (id 987654321, email erase.me@example.test, IP 203.0.113.77) appears as an actor,
 * as the subject of a 'user' entry, and as the subject of a subscription entry an admin wrote. After erase_subject no
 * retained row of audit_log, audit_personal or audit_subjects holds any of the three values; every earlier audit_log
 * row is byte-for-byte unchanged; exactly one row is added ('audit_subject_erased', personal_roles '', metadata
 * {erased_rows}); queries show the user's entries with personal_erased true; an actor_id filter for the user finds
 * nothing; replay of an erased subject entry says erased. The admin's own actor data survives.
 * Why: AUDIT-08 amendment 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
 */
describe('erase_subject', () => {
  // AUDIT-08
  it('removes every trace of the user and keeps every event', async () => {
    const USER = 987654321;
    const EMAIL = 'erase.me@example.test';
    const IP = '203.0.113.77';
    await auditLogger.log({ actor_type: 'user', actor_id: USER, ip: IP, user_agent: 'UA', request_id: 'req-1',
      action: 'user_created', resource_type: 'user', resource_id: USER, old_value: null, new_value: { id: USER, email: EMAIL } });
    const sub = await auditLogger.log({ actor_type: 'user', actor_id: 42, ip: '198.51.100.9', subject_user_id: USER,
      action: 'subscription_changed', resource_type: 'subscription', resource_id: 'sub_9',
      old_value: { owner: EMAIL, tier: 'team' }, new_value: { owner: EMAIL, tier: 'enterprise' }, why_chain_id: 'wc_1' });
    await auditLogger.log({ actor_type: 'api_key', actor_id: 'key_7', actor_user_id: USER, ip: IP, subject_user_id: 'none',
      action: 'deployment_created', resource_type: 'deployment', resource_id: 'dep_1', new_value: { region: 'eu' } });
    await auditLogger.log({ actor_type: 'user', actor_id: 42, action: 'user_created', resource_type: 'user', resource_id: 42,
      new_value: { id: 42 } });

    const raw = testDb.raw;
    const logBefore = raw.prepare('SELECT * FROM audit_log ORDER BY seq').all();

    const out = await auditLogger.erase_subject(USER);
    expect(out.erased_rows).toBe(4);   // actor + subject of entry 1, subject of entry 2, actor of entry 3

    const logAfter = raw.prepare('SELECT * FROM audit_log ORDER BY seq').all() as any[];
    expect(logAfter.slice(0, logBefore.length)).toEqual(logBefore);
    expect(logAfter.length).toBe(logBefore.length + 1);
    const added = logAfter[logAfter.length - 1];
    expect(added).toMatchObject({ action: 'audit_subject_erased', actor_type: 'service', resource_type: 'user',
      resource_id: null, personal_roles: '' });
    expect(JSON.parse(added.metadata)).toEqual({ erased_rows: 4 });

    const everything = JSON.stringify([
      raw.prepare('SELECT * FROM audit_log').all(),
      raw.prepare('SELECT * FROM audit_personal').all(),
      raw.prepare('SELECT * FROM audit_subjects').all(),
    ]);
    for (const needle of [String(USER), EMAIL, IP]) {
      expect(everything.includes(needle)).toBe(false);
    }

    const all = await auditLogger.queryLogs(ADMIN, { limit: 100 });
    const byId = new Map(all.logs.map(l => [l.id, l]));
    expect(byId.get(sub.log_id)).toMatchObject({ personal_erased: true, resource_id: null, old_value: null, new_value: null,
      actor_id: 42 });
    expect(all.logs.filter(l => l.personal_erased).length).toBe(3);
    expect((await auditLogger.queryLogs(ADMIN, { actor_id: USER })).total).toBe(0);
    expect((await auditLogger.queryLogs(ADMIN, { actor_id: 42 })).total).toBe(2);
    expect(await auditLogger.replay(ADMIN, sub.log_id)).toEqual({
      log_id: sub.log_id, timestamp: expect.any(String), erased: true, resource_state_at_time: null, has_diverged: null });
  });
});

/**
 * AUDIT-09: apply_retention erases the personal data of entries older than the retention period (here 30 days on
 * an injected clock), keeps newer entries' data, removes no audit_log row, and drops a subject left with no rows.
 * Why: AUDIT-09 amendment 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
 */
describe('apply_retention', () => {
  // AUDIT-09
  it('erases old personal data only and keeps every event', async () => {
    let now = new Date('2026-01-01T00:00:00.000Z');
    const logger = new AuditLogger(testDb, { now: () => now, retentionDays: 30 });
    const old = await logger.log({ actor_type: 'user', actor_id: 7, ip: '192.0.2.1', action: 'user_created',
      resource_type: 'user', resource_id: 7, new_value: { id: 7 } });
    now = new Date('2026-02-15T00:00:00.000Z');
    const recent = await logger.log({ actor_type: 'user', actor_id: 8, ip: '192.0.2.2', action: 'user_created',
      resource_type: 'user', resource_id: 8, new_value: { id: 8 } });

    const before = (testDb.raw.prepare('SELECT COUNT(*) AS n FROM audit_log').get() as any).n;
    const out = await logger.apply_retention(new Date('2026-02-20T00:00:00.000Z'));
    expect(out.erased_rows).toBe(2);
    expect((testDb.raw.prepare('SELECT COUNT(*) AS n FROM audit_log').get() as any).n).toBe(before);
    const logs = await logger.queryLogs(ADMIN, {});
    const byId = new Map(logs.logs.map(l => [l.id, l]));
    expect(byId.get(old.log_id)).toMatchObject({ personal_erased: true, actor_id: null, resource_id: null });
    expect(byId.get(recent.log_id)).toMatchObject({ personal_erased: false, actor_id: 8, resource_id: 8 });
    const subjects = testDb.raw.prepare('SELECT user_id FROM audit_subjects').all().map((r: any) => r.user_id);
    expect(subjects).toEqual(['8']);
  });
});

/**
 * AUDIT-10: log() refuses a non-'user' entry without subject_user_id (400 subject_required), a metadata key other
 * than feature_flag / erased_rows (400 metadata_key_not_allowed), an api_key entry without actor_user_id (400
 * actor_user_required), and a 'user' entry whose subject differs from its resource (400 subject_mismatch); reads by
 * a non-admin (or no) caller get 403. Nothing is written by a refused call.
 * Why: AUDIT-10 amendment 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
 */
describe('validation and access', () => {
  // AUDIT-10
  it('refuses the entries the spec forbids and non-admin reads', async () => {
    const base = { actor_type: 'user' as const, actor_id: 1, action: 'billing_changed', resource_type: 'subscription',
      resource_id: 's1', new_value: { tier: 'team' } };
    const code = async (p: Promise<unknown>) => {
      try {
        await p;
      } catch (e) {
        expect(e).toBeInstanceOf(AuditError);
        return [(e as AuditError).status, (e as AuditError).code];
      }
      return 'no error';
    };
    expect(await code(auditLogger.log(base))).toEqual([400, 'subject_required']);
    expect(await code(auditLogger.log({ ...base, subject_user_id: 'none', metadata: { ip: '1.2.3.4' } })))
      .toEqual([400, 'metadata_key_not_allowed']);
    expect(await code(auditLogger.log({ ...base, subject_user_id: 'none', actor_type: 'api_key', actor_id: 'key_1' })))
      .toEqual([400, 'actor_user_required']);
    expect(await code(auditLogger.log({ ...base, resource_type: 'user', resource_id: 5, subject_user_id: 6 })))
      .toEqual([400, 'subject_mismatch']);
    expect((testDb.raw.prepare('SELECT COUNT(*) AS n FROM audit_log').get() as any).n).toBe(0);

    await auditLogger.log({ ...base, subject_user_id: 'none', metadata: { feature_flag: 'new_billing' } });
    const reader = { id: 2, is_admin: false };
    expect(await code(auditLogger.queryLogs(reader, {}))).toEqual([403, 'forbidden']);
    expect(await code(auditLogger.search(reader, { q: 'billing' }))).toEqual([403, 'forbidden']);
    expect(await code(auditLogger.replay(reader, 'x'))).toEqual([403, 'forbidden']);
    expect(await code(auditLogger.queryLogs(null as any, {}))).toEqual([403, 'forbidden']);
    expect((await auditLogger.queryLogs(ADMIN, {})).logs[0].metadata).toEqual({ feature_flag: 'new_billing' });
  });

  /**
   * AUDIT-10 (Phase B.2 audit amendment): log() refuses actor_type other than user / service / api_key (400
   * invalid_actor_type), a 'user' actor without actor_id (400 actor_required) and a 'service' actor without
   * actor_service, or with an empty one (400 actor_service_required); nothing is written; a service entry that names
   * its service is stored with it. In: the shared logger. Out: assertions only. Why: the spec now names these three
   * refusals in every language. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
   */
  // AUDIT-10
  it('refuses invalid_actor_type, actor_required and actor_service_required', async () => {
    const base = { action: 'deployment_created', resource_type: 'deployment', resource_id: 'd1', subject_user_id: 'none',
      new_value: { region: 'eu' } };
    const code = async (p: Promise<unknown>) => {
      try {
        await p;
      } catch (e) {
        expect(e).toBeInstanceOf(AuditError);
        return [(e as AuditError).status, (e as AuditError).code];
      }
      return 'no error';
    };
    expect(await code(auditLogger.log({ ...base, actor_type: 'robot' as any, actor_id: 1 }))).toEqual([400, 'invalid_actor_type']);
    expect(await code(auditLogger.log({ ...base, actor_type: 'user' }))).toEqual([400, 'actor_required']);
    expect(await code(auditLogger.log({ ...base, actor_type: 'user', actor_id: null }))).toEqual([400, 'actor_required']);
    expect(await code(auditLogger.log({ ...base, actor_type: 'service' }))).toEqual([400, 'actor_service_required']);
    expect(await code(auditLogger.log({ ...base, actor_type: 'service', actor_id: 'deployer' }))).toEqual([400, 'actor_service_required']);
    expect(await code(auditLogger.log({ ...base, actor_type: 'service', actor_service: '' }))).toEqual([400, 'actor_service_required']);
    expect((testDb.raw.prepare('SELECT COUNT(*) AS n FROM audit_log').get() as any).n).toBe(0);

    await auditLogger.log({ ...base, actor_type: 'service', actor_service: 'deployer' });
    expect(testDb.raw.prepare('SELECT actor_type, actor_service FROM audit_log').all()).toEqual([
      { actor_type: 'service', actor_service: 'deployer' }]);
  });
});

/**
 * AUDIT-08 (Phase B.2 audit amendment): replay's `erased` reflects the entry's SUBJECT row only. An admin (actor row)
 * acting on a user (subject row): erasing the admin removes 1 personal row (erased_rows = 1) and replay still shows
 * the user's state; erasing the user removes that subject row (erased_rows = 1) and replay then answers erased: true.
 * In: the shared logger. Out: assertions only. Why: the spec now says erased_rows counts audit_personal rows deleted
 * and replay's erased follows the subject row, in every language. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: in-memory SQLite.
 */
describe('replay after erasure', () => {
  // AUDIT-08
  it('reports erased only when the entry\'s subject row is gone', async () => {
    const ADMIN_ID = 5001;
    const USER_ID = 5002;
    const entry = await auditLogger.log({ actor_type: 'user', actor_id: ADMIN_ID, ip: '192.0.2.50', subject_user_id: USER_ID,
      action: 'subscription_changed', resource_type: 'subscription', resource_id: 'sub_77',
      old_value: { tier: 'solo' }, new_value: { tier: 'team' } });
    const state = { log_id: entry.log_id, timestamp: expect.any(String), resource_state_at_time: { tier: 'solo' }, has_diverged: false };
    expect(await auditLogger.replay(ADMIN, entry.log_id)).toEqual(state);

    expect(await auditLogger.erase_subject(ADMIN_ID)).toEqual({ erased_rows: 1 });   // the actor row
    const afterAdmin = await auditLogger.replay(ADMIN, entry.log_id);
    expect(afterAdmin).toEqual(state);
    expect(afterAdmin).not.toHaveProperty('erased');

    expect(await auditLogger.erase_subject(USER_ID)).toEqual({ erased_rows: 1 });    // the subject row
    expect(await auditLogger.replay(ADMIN, entry.log_id)).toEqual({
      log_id: entry.log_id, timestamp: expect.any(String), erased: true, resource_state_at_time: null, has_diverged: null });
    expect(await auditLogger.erase_subject(USER_ID)).toEqual({ erased_rows: 0 });    // nothing left to delete
  });
});

/**
 * AUDIT-05: with 1,000,000 entries (each with an actor row; 997 actors) every query shape returns within the 100 ms
 * contract: actor + action wildcard + resource_type, an action wildcard alone, and the newest page. The rows are
 * seeded straight into the schema in one transaction (writing them through log() would take minutes), then
 * analyze() refreshes the planner statistics as after any bulk load; the queries go through the logger. In: a fresh database. Out: assertions only. Why: AUDIT-05 had no test here.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
 */
describe('performance', () => {
  // AUDIT-05
  it('queries 1,000,000 entries in under 100 ms', async () => {
    const raw = testDb.raw;
    const N = 1_000_000;
    const actions = ['user_created', 'user_updated', 'billing_changed', 'deployment_created'];
    const types = ['user', 'user', 'subscription', 'deployment'];
    const insLog = raw.prepare(`INSERT INTO audit_log (id, timestamp, actor_type, actor_service, action, resource_type,
      resource_id, old_value, new_value, why_chain_id, personal_roles, metadata) VALUES (?, ?, 'user', NULL, ?, ?, ?, NULL, '{}', NULL, 'actor', NULL)`);
    const insSubj = raw.prepare(`INSERT INTO audit_subjects (subject_ref, user_id, created_at) VALUES (?, ?, ?)`);
    const insPers = raw.prepare(`INSERT INTO audit_personal (log_id, subject_ref, role, data) VALUES (?, ?, 'actor', ?)`);
    const t0 = Date.parse('2025-01-01T00:00:00.000Z');
    raw.transaction(() => {
      for (let a = 0; a < 997; a++) insSubj.run(`ref${a}`, String(a), '2025-01-01T00:00:00.000Z');
      for (let i = 0; i < N; i++) {
        const id = `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`;
        const k = i % 4;
        insLog.run(id, new Date(t0 + i * 1000).toISOString(), actions[k], types[k], String(i));
        insPers.run(id, `ref${i % 997}`, `{"actor_id":${i % 997}}`);
      }
    })();

    const timed = async (params: any) => {
      const start = process.hrtime.bigint();
      const res = await auditLogger.queryLogs(ADMIN, params);
      return { ms: Number(process.hrtime.bigint() - start) / 1e6, res };
    };
    // After a bulk load the planner statistics are refreshed (Postgres does this itself; see analyze()), and the
    // statements are warmed once, as in a running service.
    await auditLogger.analyze();
    await auditLogger.queryLogs(ADMIN, { limit: 1 });

    const a = await timed({ actor_id: 7, action: 'user_*', resource_type: 'user', limit: 100 });
    let expected = 0;
    for (let i = 7; i < N; i += 997) if (i % 4 < 2) expected++;
    expect(a.res.total).toBe(expected);
    expect(a.res.logs.length).toBe(100);
    expect(a.res.logs.every(l => l.actor_id === 7 && l.action.startsWith('user_'))).toBe(true);
    expect(a.ms).toBeLessThan(100);

    const b = await timed({ action: 'billing_*', limit: 100 });
    expect(b.res.total).toBe(250_000);
    expect(b.ms).toBeLessThan(100);

    const c = await timed({ limit: 100, offset: 0 });
    expect(c.res.total).toBe(N);
    expect(c.res.logs[0].id).toBe(`00000000-0000-4000-8000-${String(N - 1).padStart(12, '0')}`);
    expect(c.ms).toBeLessThan(100);
  }, 240_000);
});

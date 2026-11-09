import Database, { Database as BetterSqliteDatabase } from 'better-sqlite3';
import { AuditLogger, Database as AuditDatabase, QueryResult } from './audit_logging_typescript';

class SqliteTestDatabase implements AuditDatabase {
  private db: BetterSqliteDatabase;

  constructor() {
    this.db = new Database(':memory:');
    this.db.pragma('journal_mode = WAL');
  }

  private convertPlaceholders(sql: string): string {
    // Replace PostgreSQL ILIKE with SQLite LIKE (case-insensitive by default for ASCII)
    sql = sql.replace(/ILIKE/gi, 'LIKE');
    // Replace $1, $2, ... with ? placeholders
    let index = 0;
    return sql.replace(/\$(\d+)/g, () => {
      index++;
      return '?';
    });
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
      return {
        rows: rows.map(row => ({
          ...row,
          old_value: row.old_value ? JSON.parse(row.old_value) : null,
          new_value: row.new_value ? JSON.parse(row.new_value) : null,
          metadata: row.metadata ? JSON.parse(row.metadata) : null
        })),
        rowCount: rows.length
      };
    } else {
      const result = values ? stmt.run(...values) : stmt.run();
      return {
        rows: [],
        rowCount: result.changes
      };
    }
  }

  async close(): Promise<void> {
    this.db.close();
  }
}

let testDb: SqliteTestDatabase;
let auditLogger: AuditLogger;

beforeAll(async () => {
  testDb = new SqliteTestDatabase();
  await testDb.query(AuditLogger.CREATE_TABLE_SQL_SQLITE);
  auditLogger = new AuditLogger(testDb);
});

afterAll(async () => {
  await testDb.close();
});

beforeEach(async () => {
  await testDb.query('DELETE FROM audit_log');
});

describe('logMutation', () => {
  it('should log a mutation and return log_id', async () => {
    const input = {
      actor_id: 123,
      actor_type: 'user',
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
  });

  it('should handle null actor_id', async () => {
    const input = {
      actor_id: null,
      actor_type: 'service',
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
    actor_type: 'user',
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
    const result = await auditLogger.queryLogs({ actor_id: 100 });
    expect(result.total).toBe(2);
    expect(result.logs.length).toBe(2);
    expect(result.logs.every(log => log.actor_id === 100)).toBe(true);
  });

  it('should filter by action with wildcard', async () => {
    const result = await auditLogger.queryLogs({ action: 'user_*' });
    expect(result.total).toBe(3);
  });

  it('should filter by resource_type', async () => {
    const result = await auditLogger.queryLogs({ resource_type: 'user' });
    expect(result.total).toBe(3);
  });

  it('should paginate with limit and offset', async () => {
    const firstPage = await auditLogger.queryLogs({ limit: 2, offset: 0 });
    expect(firstPage.logs.length).toBe(2);
    expect(firstPage.has_more).toBe(true);

    const secondPage = await auditLogger.queryLogs({ limit: 2, offset: 2 });
    expect(secondPage.logs.length).toBe(1);
    expect(secondPage.has_more).toBe(false);
  });

  it('should filter by date range', async () => {
    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
    const tomorrow = new Date(Date.now() + 86400000).toISOString().split('T')[0];
    const result = await auditLogger.queryLogs({ date_from: yesterday, date_to: tomorrow });
    expect(result.total).toBe(3);
  });

  it('includes rows written on the date_to day itself', async () => {
    // The bound is compared as text on SQLite; "YYYY-MM-DD 23:59:59.999" sorted before every ISO time of that
    // day, so the last day of a range was empty (CodeRabbit, PR 18).
    const today = new Date().toISOString().split('T')[0];
    const result = await auditLogger.queryLogs({ date_from: today, date_to: today });
    expect(result.total).toBe(3);
  });

  it('should return total and has_more correctly', async () => {
    const result = await auditLogger.queryLogs({});
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

    const replayResult = await auditLogger.replay(logResult.log_id);
    expect(replayResult).toEqual({
      log_id: logResult.log_id,
      timestamp: expect.any(String),
      resource_state_at_time: null,
      has_diverged: false
    });
  });

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

    const replayResult = await auditLogger.replay(logResult.log_id);
    expect(replayResult.resource_state_at_time).toBeNull();
    expect(replayResult.has_diverged).toBe(true);
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

    const replayResult = await auditLogger.replay(createLog.log_id);
    expect(replayResult.resource_state_at_time).toBeNull();
    expect(replayResult.has_diverged).toBe(true); // Because current state (null) != new_value of create log ({ id: 1, name: 'Alice' })
  });

  it('should throw error for non-existent log', async () => {
    await expect(auditLogger.replay('non-existent-id')).rejects.toThrow('Log not found');
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
    const result = await auditLogger.search({ q: 'email' });
    expect(result.results.length).toBe(1);
    expect(result.results[0].action).toBe('user_email_updated');
  });

  it('should filter by resource_type in search', async () => {
    const result = await auditLogger.search({ q: 'updated', resource_type: 'user' });
    expect(result.results.length).toBe(2);
  });

  it('should limit results', async () => {
    const result = await auditLogger.search({ q: 'updated', limit: 1 });
    expect(result.results.length).toBe(1);
  });
});

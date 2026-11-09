export interface QueryResult {
  rows: any[];
  rowCount: number | null;
}

/**
 * The connection the logger writes through. JSON columns (old_value, new_value, metadata) come back already parsed,
 * as pg does for jsonb; an adapter for a database that stores them as text parses them in query().
 */
export interface Database {
  query(text: string, values?: any[]): Promise<QueryResult>;
  close?(): Promise<void>;
}

export class AuditLogger {
  private db: Database;

  /**
   * The event's real time, set here and not by the database: SQLite's CURRENT_TIMESTAMP has no zone and whole
   * seconds only, so it was read back as local time. An ISO string in UTC has fixed width and sorts correctly as
   * text; Postgres reads it into its timestamptz column. Two writes in one millisecond share a time; the seq
   * column, numbered by the database in insertion order, puts them in order (ORDER BY timestamp, seq). Times are
   * never nudged forward to make them unique: that made bursts look like future events (review on PR 18).
   */
  private eventTime(): string {
    return new Date().toISOString();
  }

  constructor(db: Database) {
    this.db = db;
  }

  static CREATE_TABLE_SQL = `
    CREATE TABLE IF NOT EXISTS audit_log (
      id UUID PRIMARY KEY,
      seq BIGSERIAL NOT NULL,
      timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      actor_id TEXT,
      actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'service', 'api_key')),
      action TEXT NOT NULL,
      resource_type TEXT NOT NULL,
      resource_id TEXT NOT NULL,
      old_value JSONB,
      new_value JSONB,
      why_chain_id TEXT,
      metadata JSONB
    );

    CREATE INDEX IF NOT EXISTS idx_audit_log_actor_action_resource_timestamp ON audit_log (actor_id, action, resource_type, timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_log_resource_type_resource_id_timestamp ON audit_log (resource_type, resource_id, timestamp);
  `;

  static CREATE_TABLE_SQL_SQLITE = `
    CREATE TABLE IF NOT EXISTS audit_log (
      seq INTEGER PRIMARY KEY,
      id TEXT NOT NULL UNIQUE,
      timestamp TEXT NOT NULL,
      actor_id TEXT,
      actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'service', 'api_key')),
      action TEXT NOT NULL,
      resource_type TEXT NOT NULL,
      resource_id TEXT NOT NULL,
      old_value TEXT,
      new_value TEXT,
      why_chain_id TEXT,
      metadata TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_audit_log_actor_action_resource_timestamp ON audit_log (actor_id, action, resource_type, timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_log_resource_type_resource_id_timestamp ON audit_log (resource_type, resource_id, timestamp);
  `;

  async logMutation(input: {
    actor_id: string | number | null;
    actor_type: 'user' | 'service' | 'api_key';
    action: string;
    resource_type: string;
    resource_id: string | number;
    old_value: any;
    new_value: any;
    why_chain_id?: string | null;
    metadata?: any;
  }): Promise<{ success: true; log_id: string }> {
    const logId = this.generateUuid();
    const {
      actor_id,
      actor_type,
      action,
      resource_type,
      resource_id,
      old_value,
      new_value,
      why_chain_id = null,
      metadata = null
    } = input;

    const actorIdStr = actor_id === null ? null : String(actor_id);
    const resourceIdStr = String(resource_id);

    await this.db.query(
      `INSERT INTO audit_log (
        id, timestamp, actor_id, actor_type, action, resource_type, resource_id, old_value, new_value, why_chain_id, metadata
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
      )`,
      [
        logId,
        this.eventTime(),
        actorIdStr,
        actor_type,
        action,
        resource_type,
        resourceIdStr,
        JSON.stringify(old_value),
        JSON.stringify(new_value),
        why_chain_id,
        JSON.stringify(metadata)
      ]
    );

    return { success: true, log_id: logId };
  }

  async queryLogs(params: {
    actor_id?: string | number | null;
    action?: string;
    resource_type?: string;
    limit?: number;
    offset?: number;
    date_from?: string;
    date_to?: string;
  }): Promise<{
    logs: Array<{
      id: string;
      timestamp: string;
      actor_id: string | number | null;
      action: string;
      resource_type: string;
      resource_id: string | number;
      old_value: any;
      new_value: any;
      why_chain_id: string | null;
    }>;
    total: number;
    has_more: boolean;
  }> {
    const whereConditions: string[] = [];
    const values: any[] = [];
    let paramIndex = 1;

    if (params.actor_id !== undefined && params.actor_id !== null) {
      whereConditions.push(`actor_id = $${paramIndex++}`);
      values.push(String(params.actor_id));
    } else if (params.actor_id === null) {
      whereConditions.push('actor_id IS NULL');
    }

    if (params.action) {
      const actionPattern = params.action.replace(/\*/g, '%');
      whereConditions.push(`action ILIKE $${paramIndex++}`);
      values.push(actionPattern);
    }

    if (params.resource_type) {
      whereConditions.push(`resource_type = $${paramIndex++}`);
      values.push(params.resource_type);
    }

    if (params.date_from) {
      whereConditions.push(`timestamp >= $${paramIndex++}`);
      values.push(`${params.date_from} 00:00:00`);
    }

    if (params.date_to) {
      whereConditions.push(`timestamp <= $${paramIndex++}`);
      values.push(`${params.date_to} 23:59:59.999`);
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

    const countResult = await this.db.query(
      `SELECT COUNT(*) as count FROM audit_log ${whereClause}`,
      values
    );
    const total = parseInt(String(countResult.rows[0]?.count ?? countResult.rows[0]?.['COUNT(*)'] ?? '0'), 10);

    const limit = params.limit ?? 100;
    const offset = params.offset ?? 0;

    const logsResult = await this.db.query(
      `SELECT id, timestamp, actor_id, action, resource_type, resource_id, old_value, new_value, why_chain_id
       FROM audit_log ${whereClause}
       ORDER BY timestamp DESC, seq DESC
       LIMIT $${paramIndex++} OFFSET $${paramIndex++}`,
      [...values, limit, offset]
    );

    const logs = logsResult.rows.map(row => ({
      id: row.id,
      timestamp: row.timestamp.toISOString ? row.timestamp.toISOString() : new Date(row.timestamp).toISOString(),
      actor_id: row.actor_id === null ? null : (isNaN(Number(row.actor_id)) ? row.actor_id : Number(row.actor_id)),
      action: row.action,
      resource_type: row.resource_type,
      resource_id: row.resource_id === null ? null : (isNaN(Number(row.resource_id)) ? row.resource_id : Number(row.resource_id)),
      old_value: row.old_value,
      new_value: row.new_value,
      why_chain_id: row.why_chain_id ?? null
    }));

    return {
      logs,
      total,
      has_more: offset + logs.length < total
    };
  }

  async replay(logId: string): Promise<{
    log_id: string;
    timestamp: string;
    resource_state_at_time: any;
    has_diverged: boolean
  }> {
    const logResult = await this.db.query(
      `SELECT id, timestamp, actor_id, action, resource_type, resource_id, old_value, new_value, why_chain_id
       FROM audit_log
       WHERE id = $1`,
      [logId]
    );

    if (logResult.rowCount === 0 || logResult.rows.length === 0) {
      throw new Error(`Log not found: ${logId}`);
    }

    const log = logResult.rows[0];
    const resourceType = log.resource_type;
    const resourceId = String(log.resource_id);

    const resourceLogsResult = await this.db.query(
      `SELECT * FROM audit_log
       WHERE resource_type = $1 AND resource_id = $2
       ORDER BY timestamp ASC, seq ASC`,
      [resourceType, resourceId]
    );

    let stateNow = null;

    for (const row of resourceLogsResult.rows) {
      stateNow = row.new_value;
    }

    const logNewValue = log.new_value;
    const hasDiverged = JSON.stringify(stateNow) !== JSON.stringify(logNewValue);

    return {
      log_id: log.id,
      timestamp: log.timestamp.toISOString ? log.timestamp.toISOString() : new Date(log.timestamp).toISOString(),
      resource_state_at_time: log.old_value,
      has_diverged: hasDiverged
    };
  }

  async search(params: {
    q: string;
    resource_type?: string;
    limit?: number;
  }): Promise<{
    results: Array<{
      id: string;
      timestamp: string;
      actor_id: string | number | null;
      action: string;
      resource_type: string;
      resource_id: string | number;
      old_value: any;
      new_value: any;
      why_chain_id: string | null;
    }>
  }> {
    const whereConditions: string[] = [];
    const values: any[] = [];
    let paramIndex = 1;

    const searchTerm = `%${params.q}%`;
    whereConditions.push(`(action ILIKE $${paramIndex++} OR resource_type ILIKE $${paramIndex++})`);
    values.push(searchTerm);
    values.push(searchTerm);

    if (params.resource_type) {
      whereConditions.push(`resource_type = $${paramIndex++}`);
      values.push(params.resource_type);
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

    const limit = params.limit ?? 50;

    const result = await this.db.query(
      `SELECT id, timestamp, actor_id, action, resource_type, resource_id, old_value, new_value, why_chain_id
       FROM audit_log ${whereClause}
       ORDER BY timestamp DESC, seq DESC
       LIMIT $${paramIndex++}`,
      [...values, limit]
    );

    const results = result.rows.map(row => ({
      id: row.id,
      timestamp: row.timestamp.toISOString ? row.timestamp.toISOString() : new Date(row.timestamp).toISOString(),
      actor_id: row.actor_id === null ? null : (isNaN(Number(row.actor_id)) ? row.actor_id : Number(row.actor_id)),
      action: row.action,
      resource_type: row.resource_type,
      resource_id: row.resource_id === null ? null : (isNaN(Number(row.resource_id)) ? row.resource_id : Number(row.resource_id)),
      old_value: row.old_value,
      new_value: row.new_value,
      why_chain_id: row.why_chain_id ?? null
    }));

    return { results };
  }

  private generateUuid(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }
}

/**
 * Audit logging (docs/specs/audit_logging.md): an append-only event log whose personal data lives beside it, so a
 * person can be erased without rewriting a single event.
 *
 * Tables: audit_log (events only; UPDATE and DELETE refused by triggers), audit_personal (one 'actor' and/or one
 * 'subject' row per entry, holding everything that leads back to a person) and audit_subjects (user_id -> a random
 * subject_ref). Exports: AuditLogger (log / logMutation, queryLogs, replay, search, erase_subject, apply_retention),
 * AuditError, and the schema for Postgres and SQLite.
 *
 * Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, for the AUDIT-08/09/10 amendments: the previous build kept
 * actor ids, resource ids and snapshots in audit_log itself, so personal data could not be erased without editing
 * the log; nothing stopped UPDATE/DELETE on it; metadata took any key; reads had no admin check; ids came from
 * Math.random. Touches: the database passed in (parameterized SQL only).
 */
import { randomBytes, randomUUID } from 'crypto';

export interface QueryResult {
  rows: any[];
  rowCount: number | null;
}

/**
 * The connection the logger writes through ($1, $2 placeholders, Postgres style). JSON columns may come back parsed
 * (pg does this for jsonb) or as text; the logger accepts both. Statements 'BEGIN', 'COMMIT' and 'ROLLBACK' must
 * work on it, and every call must use the same connection (the logger serialises its own transactions).
 */
export interface Database {
  query(text: string, values?: any[]): Promise<QueryResult>;
  close?(): Promise<void>;
}

/**
 * An error with an HTTP status and a stable code: 400 subject_required / subject_mismatch / metadata_key_not_allowed
 * / actor_user_required / actor_required / actor_service_required / invalid_actor_type, 403 forbidden, 404 not_found.
 * (actor_service_required added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, Phase B.2.)
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export class AuditError extends Error {
  constructor(public readonly code: string, message: string, public readonly status: number) {
    super(message);
    this.name = 'AuditError';
  }
}

/** The verified caller of a read: only an admin may read the log (AUDIT-10). */
export interface AuditCaller {
  id: string | number;
  is_admin: boolean;
}

export type ActorType = 'user' | 'service' | 'api_key';

/** What log() takes. subject_user_id is required for every resource_type except 'user' (a user id or 'none'). */
export interface LogInput {
  actor_type: ActorType;
  /** The acting user ('user'), or the key's id ('api_key'). From the authenticated caller, never a request body. */
  actor_id?: string | number | null;
  /** The key's owner, required when actor_type is 'api_key'. */
  actor_user_id?: string | number | null;
  /** The service's name when actor_type is 'service'. */
  actor_service?: string | null;
  subject_user_id?: string | number | null;
  action: string;
  resource_type: string;
  resource_id?: string | number | null;
  old_value?: any;
  new_value?: any;
  why_chain_id?: string | null;
  ip?: string | null;
  user_agent?: string | null;
  request_id?: string | null;
  /** Only feature_flag and erased_rows. */
  metadata?: Record<string, unknown> | null;
}

/** One entry as reads return it. Personal fields are null and personal_erased true once erased. */
export interface AuditEntry {
  id: string;
  timestamp: string;
  actor_type: ActorType;
  actor_service: string | null;
  actor_id: string | number | null;
  action: string;
  resource_type: string;
  resource_id: string | number | null;
  old_value: any;
  new_value: any;
  why_chain_id: string | null;
  metadata: Record<string, unknown> | null;
  personal_erased: boolean;
}

const METADATA_KEYS = new Set(['feature_flag', 'erased_rows']);
const ACTOR_TYPES = new Set<ActorType>(['user', 'service', 'api_key']);
const DAY_MS = 24 * 60 * 60 * 1000;

/** Parses a JSON column that may already be parsed. Touches nothing. */
function json(value: any): any {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') {
    try {
      return JSON.parse(value);
    } catch {
      return value;
    }
  }
  return value;
}

/** A stored id read back: numeric text becomes a number, as the previous build returned it. Touches nothing. */
function idOut(value: any): string | number | null {
  if (value === null || value === undefined) return null;
  const s = String(value);
  return /^-?\d{1,15}$/.test(s) ? Number(s) : s;
}

export class AuditLogger {
  private db: Database;
  private now: () => Date;
  private retentionDays: number;
  private lock: Promise<unknown> = Promise.resolve();

  /**
   * In: the database, and options: `now` (clock, default the system clock) and `retentionDays` (personal data kept
   * this long, default 365). Out: the logger. Why: the injectable-clock rule and AUDIT-09's configured retention.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  constructor(db: Database, options: { now?: () => Date; retentionDays?: number } = {}) {
    this.db = db;
    this.now = options.now ?? (() => new Date());
    this.retentionDays = options.retentionDays ?? 365;
  }

  /** Postgres schema: the three tables, indexes, and triggers that refuse UPDATE/DELETE on audit_log. */
  static CREATE_TABLE_SQL = `
    CREATE TABLE IF NOT EXISTS audit_log (
      seq BIGSERIAL NOT NULL,
      id UUID PRIMARY KEY,
      timestamp TEXT NOT NULL,
      actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'service', 'api_key')),
      actor_service TEXT,
      action TEXT COLLATE "C" NOT NULL,
      resource_type TEXT NOT NULL,
      resource_id TEXT,
      old_value JSONB,
      new_value JSONB,
      why_chain_id TEXT,
      personal_roles TEXT NOT NULL DEFAULT '',
      metadata JSONB
    );
    CREATE INDEX IF NOT EXISTS idx_audit_log_action_type_ts ON audit_log (action, resource_type, timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_log_type_ts ON audit_log (resource_type, timestamp, seq);
    CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log (timestamp, seq);
    CREATE TABLE IF NOT EXISTS audit_subjects (
      subject_ref TEXT PRIMARY KEY,
      user_id TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_personal (
      log_id UUID NOT NULL,
      subject_ref TEXT NOT NULL REFERENCES audit_subjects(subject_ref),
      role TEXT NOT NULL CHECK (role IN ('actor', 'subject')),
      data JSONB NOT NULL,
      PRIMARY KEY (log_id, role)
    );
    CREATE INDEX IF NOT EXISTS idx_audit_personal_subject_role ON audit_personal (subject_ref, role);
    CREATE OR REPLACE FUNCTION audit_refuse_change() RETURNS trigger AS $$
      BEGIN RAISE EXCEPTION '% is append-only', TG_TABLE_NAME; END;
    $$ LANGUAGE plpgsql;
    DROP TRIGGER IF EXISTS audit_log_append_only ON audit_log;
    CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log
      FOR EACH ROW EXECUTE FUNCTION audit_refuse_change();
    DROP TRIGGER IF EXISTS audit_personal_no_update ON audit_personal;
    CREATE TRIGGER audit_personal_no_update BEFORE UPDATE ON audit_personal
      FOR EACH ROW EXECUTE FUNCTION audit_refuse_change();
  `;

  /** SQLite schema: the same tables, indexes and append-only triggers (used by the tests). */
  static CREATE_TABLE_SQL_SQLITE = `
    CREATE TABLE IF NOT EXISTS audit_log (
      seq INTEGER PRIMARY KEY,
      id TEXT NOT NULL UNIQUE,
      timestamp TEXT NOT NULL,
      actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'service', 'api_key')),
      actor_service TEXT,
      action TEXT NOT NULL,
      resource_type TEXT NOT NULL,
      resource_id TEXT,
      old_value TEXT,
      new_value TEXT,
      why_chain_id TEXT,
      personal_roles TEXT NOT NULL DEFAULT '',
      metadata TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_audit_log_action_type_ts ON audit_log (action, resource_type, timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_log_type_ts ON audit_log (resource_type, timestamp, seq);
    CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log (timestamp, seq);
    CREATE TABLE IF NOT EXISTS audit_subjects (
      subject_ref TEXT PRIMARY KEY,
      user_id TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_personal (
      log_id TEXT NOT NULL,
      subject_ref TEXT NOT NULL REFERENCES audit_subjects(subject_ref),
      role TEXT NOT NULL CHECK (role IN ('actor', 'subject')),
      data TEXT NOT NULL,
      PRIMARY KEY (log_id, role)
    );
    CREATE INDEX IF NOT EXISTS idx_audit_personal_subject_role ON audit_personal (subject_ref, role);
    CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
      BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
    CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
      BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
    CREATE TRIGGER IF NOT EXISTS audit_personal_no_update BEFORE UPDATE ON audit_personal
      BEGIN SELECT RAISE(ABORT, 'audit_personal rows are never updated'); END;
  `;

  /**
   * Runs fn inside BEGIN ... COMMIT (ROLLBACK and rethrow on error), one transaction at a time on this logger.
   * In: fn. Out: fn's result. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
   */
  private async transaction<T>(fn: () => Promise<T>): Promise<T> {
    const run = async (): Promise<T> => {
      await this.db.query('BEGIN');
      try {
        const out = await fn();
        await this.db.query('COMMIT');
        return out;
      } catch (err) {
        try {
          await this.db.query('ROLLBACK');
        } catch {
          // the original error is the one to report
        }
        throw err;
      }
    };
    const next = this.lock.then(run, run);
    this.lock = next.catch(() => undefined);
    return next;
  }

  /**
   * The subject_ref for a user, created (a random 128-bit value, never derived from the id) the first time the user
   * appears, with insert-if-absent on user_id. In: the user id. Out: the subject_ref. Must run inside a transaction.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: audit_subjects.
   */
  private async subjectRef(userId: string): Promise<string> {
    await this.db.query(
      `INSERT INTO audit_subjects (subject_ref, user_id, created_at) VALUES ($1, $2, $3) ON CONFLICT (user_id) DO NOTHING`,
      [randomBytes(16).toString('hex'), userId, this.now().toISOString()]
    );
    const res = await this.db.query(`SELECT subject_ref FROM audit_subjects WHERE user_id = $1`, [userId]);
    return res.rows[0].subject_ref;
  }

  /**
   * Validates one entry against the spec's rules. In: the input. Out: the resolved subject user id ('none' or an
   * id). Throws AuditError 400 (codes in the AUDIT-10 row and the schema notes): invalid_actor_type (actor_type not
   * user / service / api_key), actor_required (a 'user' actor without actor_id), actor_service_required (a 'service'
   * actor without actor_service), actor_user_required, subject_required, subject_mismatch, metadata_key_not_allowed.
   * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 audit amendment): a 'service' actor without
   * actor_service was accepted (actor_id stood in for it, or it was stored NULL). Touches nothing.
   */
  private validate(input: LogInput): string {
    if (!ACTOR_TYPES.has(input.actor_type)) {
      throw new AuditError('invalid_actor_type', `actor_type must be user, service or api_key`, 400);
    }
    if (input.metadata !== null && input.metadata !== undefined) {
      if (typeof input.metadata !== 'object' || Array.isArray(input.metadata)) {
        throw new AuditError('metadata_key_not_allowed', 'metadata must be an object', 400);
      }
      for (const key of Object.keys(input.metadata)) {
        if (!METADATA_KEYS.has(key)) {
          throw new AuditError('metadata_key_not_allowed', `metadata key not allowed: ${key}`, 400);
        }
      }
    }
    const given = input.subject_user_id;
    let subject: string;
    if (input.resource_type === 'user') {
      const rid = input.resource_id;
      if (rid === null || rid === undefined) {
        if (given !== 'none') throw new AuditError('subject_required', 'a user entry needs its resource_id', 400);
        subject = 'none';
      } else {
        subject = String(rid);
        if (given !== null && given !== undefined && String(given) !== subject) {
          throw new AuditError('subject_mismatch', 'subject_user_id must equal resource_id for resource_type user', 400);
        }
      }
    } else {
      if (given === null || given === undefined || String(given) === '') {
        throw new AuditError('subject_required', 'subject_user_id is required (a user id or "none")', 400);
      }
      subject = String(given);
    }
    if (input.actor_type === 'user' && (input.actor_id === null || input.actor_id === undefined)) {
      throw new AuditError('actor_required', 'a user actor needs actor_id', 400);
    }
    if (input.actor_type === 'service' && (typeof input.actor_service !== 'string' || input.actor_service.trim() === '')) {
      throw new AuditError('actor_service_required', 'a service actor needs actor_service (the service name)', 400);
    }
    if (input.actor_type === 'api_key' && (input.actor_user_id === null || input.actor_user_id === undefined)) {
      throw new AuditError('actor_user_required', 'an api_key actor needs actor_user_id (the key owner)', 400);
    }
    return subject;
  }

  /**
   * Logs one mutation (call it before the mutation commits). Over HTTP this is service-authenticated only, and
   * actor_id is the authenticated caller's, never a body value.
   *
   * In: LogInput. Out: { success: true, log_id }. In one transaction: finds or creates the subject rows, inserts
   * the audit_log event (resource_id, old/new values and why_chain_id only when the subject is 'none'), the 'actor'
   * row {actor_id, ip, user_agent, request_id} for a user or api_key actor, and the 'subject' row {resource_id,
   * old_value, new_value, why_chain_id} for an entry with a data subject. Errors: AuditError 400 per validate().
   * Why: AUDIT-08/10 amendment 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: audit_log, audit_personal, audit_subjects.
   */
  async log(input: LogInput): Promise<{ success: true; log_id: string }> {
    const subject = this.validate(input);
    return this.transaction(() => this.insertEntry(input, subject));
  }

  /** The previous name of log(); same behaviour. */
  async logMutation(input: LogInput): Promise<{ success: true; log_id: string }> {
    return this.log(input);
  }

  /**
   * Inserts one validated entry and its personal rows; the caller holds the transaction. In: input and subject.
   * Out: { success, log_id }. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP; Phase B.2 the same day: actor_service is
   * taken only from actor_service (validate() now requires it for a service actor; actor_id no longer stands in).
   * Touches: the three audit tables.
   */
  private async insertEntry(input: LogInput, subject: string): Promise<{ success: true; log_id: string }> {
    const logId = randomUUID();
    const hasSubject = subject !== 'none';
    const actorUser = input.actor_type === 'user' ? input.actor_id : input.actor_type === 'api_key' ? input.actor_user_id : null;
    const hasActor = actorUser !== null && actorUser !== undefined;
    const roles = [hasActor ? 'actor' : '', hasSubject ? 'subject' : ''].filter(Boolean).join(',');
    const actorService = input.actor_type === 'service' ? (input.actor_service ?? null) : null;
    const val = (v: any) => (v === undefined ? null : JSON.stringify(v));

    await this.db.query(
      `INSERT INTO audit_log (id, timestamp, actor_type, actor_service, action, resource_type, resource_id,
         old_value, new_value, why_chain_id, personal_roles, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [
        logId,
        this.now().toISOString(),
        input.actor_type,
        actorService,
        input.action,
        input.resource_type,
        hasSubject || input.resource_id === null || input.resource_id === undefined ? null : String(input.resource_id),
        hasSubject ? null : val(input.old_value ?? null),
        hasSubject ? null : val(input.new_value ?? null),
        hasSubject ? null : input.why_chain_id ?? null,
        roles,
        input.metadata ? JSON.stringify(input.metadata) : null,
      ]
    );
    if (hasActor) {
      const ref = await this.subjectRef(String(actorUser));
      await this.db.query(
        `INSERT INTO audit_personal (log_id, subject_ref, role, data) VALUES ($1, $2, 'actor', $3)`,
        [logId, ref, JSON.stringify({
          actor_id: input.actor_id ?? null,
          ip: input.ip ?? null,
          user_agent: input.user_agent ?? null,
          request_id: input.request_id ?? null,
        })]
      );
    }
    if (hasSubject) {
      const ref = await this.subjectRef(subject);
      await this.db.query(
        `INSERT INTO audit_personal (log_id, subject_ref, role, data) VALUES ($1, $2, 'subject', $3)`,
        [logId, ref, JSON.stringify({
          resource_id: input.resource_id === null || input.resource_id === undefined ? null : String(input.resource_id),
          old_value: input.old_value ?? null,
          new_value: input.new_value ?? null,
          why_chain_id: input.why_chain_id ?? null,
        })]
      );
    }
    return { success: true, log_id: logId };
  }

  /** Refuses a read by anyone but an admin (403 forbidden, AUDIT-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
  private requireAdmin(caller: AuditCaller | null | undefined): void {
    if (!caller || caller.is_admin !== true) {
      throw new AuditError('forbidden', 'audit reads are for admins only', 403);
    }
  }

  /**
   * Turns audit_log rows into entries, reading their personal rows in one query. In: rows (id, timestamp, actor_type,
   * actor_service, action, resource_type, resource_id, old_value, new_value, why_chain_id, personal_roles, metadata).
   * Out: entries in the same order. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads audit_personal.
   */
  private async decorate(rows: any[]): Promise<AuditEntry[]> {
    const personal = new Map<string, { actor?: any; subject?: any }>();
    if (rows.length > 0) {
      const placeholders = rows.map((_, i) => `$${i + 1}`).join(', ');
      const res = await this.db.query(
        `SELECT log_id, role, data FROM audit_personal WHERE log_id IN (${placeholders})`,
        rows.map((r) => r.id)
      );
      for (const p of res.rows) {
        const slot = personal.get(p.log_id) ?? {};
        slot[p.role as 'actor' | 'subject'] = json(p.data);
        personal.set(p.log_id, slot);
      }
    }
    return rows.map((row) => {
      const roles = String(row.personal_roles ?? '').split(',').filter(Boolean);
      const p = personal.get(row.id) ?? {};
      const erased = roles.some((r) => !(p as any)[r]);
      const subj = roles.includes('subject') ? p.subject : null;
      return {
        id: row.id,
        timestamp: typeof row.timestamp === 'string' ? row.timestamp : new Date(row.timestamp).toISOString(),
        actor_type: row.actor_type,
        actor_service: row.actor_service ?? null,
        actor_id: p.actor ? idOut(p.actor.actor_id) : null,
        action: row.action,
        resource_type: row.resource_type,
        resource_id: roles.includes('subject') ? idOut(subj?.resource_id ?? null) : idOut(row.resource_id),
        old_value: roles.includes('subject') ? (subj?.old_value ?? null) : json(row.old_value),
        new_value: roles.includes('subject') ? (subj?.new_value ?? null) : json(row.new_value),
        why_chain_id: roles.includes('subject') ? (subj?.why_chain_id ?? null) : (row.why_chain_id ?? null),
        metadata: json(row.metadata),
        personal_erased: erased,
      };
    });
  }

  /**
   * Builds the FROM and WHERE clauses for the filters, over audit_log aliased l. action takes '*' as a wildcard
   * (other LIKE characters are literal); a trailing-only wildcard also gets a range on action so its index is used.
   * actor_id resolves through audit_subjects and the 'actor' rows (an erased actor never matches), and the query is
   * then driven FROM the actor's rows (CROSS JOIN keeps SQLite from scanning the whole log in time order first; each
   * entry has at most one actor row, so nothing is counted twice). Out: { from, where, values }.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  private filters(params: { actor_id?: string | number | null; action?: string; resource_type?: string;
    date_from?: string; date_to?: string }): { from: string; where: string; values: any[] } {
    const conds: string[] = [];
    const values: any[] = [];
    const p = () => `$${values.length}`;
    let from = 'audit_log l';
    if (params.actor_id !== undefined && params.actor_id !== null) {
      values.push(String(params.actor_id));
      from = 'audit_subjects s CROSS JOIN audit_personal ap CROSS JOIN audit_log l';
      conds.push(`s.user_id = ${p()}`, `ap.subject_ref = s.subject_ref`, `ap.role = 'actor'`, `l.id = ap.log_id`);
    }
    if (params.action) {
      const pattern = params.action.replace(/[\\%_]/g, '\\$&').replace(/\*/g, '%');
      values.push(pattern);
      conds.push(`l.action LIKE ${p()} ESCAPE '\\'`);
      const star = params.action.indexOf('*');
      if (star === params.action.length - 1 && star > 0) {
        const prefix = params.action.slice(0, -1);
        const upper = prefix.slice(0, -1) + String.fromCharCode(prefix.charCodeAt(prefix.length - 1) + 1);
        values.push(prefix);
        conds.push(`l.action >= ${p()}`);
        values.push(upper);
        conds.push(`l.action < ${p()}`);
      }
    }
    if (params.resource_type) {
      values.push(params.resource_type);
      conds.push(`l.resource_type = ${p()}`);
    }
    if (params.date_from) {
      values.push(`${params.date_from}T00:00:00.000Z`);
      conds.push(`l.timestamp >= ${p()}`);
    }
    if (params.date_to) {
      values.push(`${params.date_to}T23:59:59.999Z`);
      conds.push(`l.timestamp <= ${p()}`);
    }
    return { from, where: conds.length ? `WHERE ${conds.join(' AND ')}` : '', values };
  }

  /**
   * Refreshes the query planner's statistics (ANALYZE, valid on Postgres and SQLite). Run it after a bulk load or
   * on a schedule; Postgres's autovacuum does it by itself, SQLite does not, and without statistics SQLite may sort
   * a large wildcard match instead of walking the time index. In/out: nothing. 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-05). Touches: database statistics only.
   */
  async analyze(): Promise<void> {
    await this.db.query('ANALYZE');
  }

  /**
   * Admin-only query with filters and pagination, newest first (ties by insertion order, newest first).
   * In: the verified caller and { actor_id, action ('user_*' wildcard), resource_type, limit (default 100), offset,
   * date_from, date_to }. Out: { logs, total, has_more }; erased entries show null personal fields and
   * personal_erased true. Errors: 403 forbidden for a non-admin. Why: AUDIT-01/03/04/07/08/10.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the audit tables.
   */
  async queryLogs(caller: AuditCaller, params: {
    actor_id?: string | number | null;
    action?: string;
    resource_type?: string;
    limit?: number;
    offset?: number;
    date_from?: string;
    date_to?: string;
  } = {}): Promise<{ logs: AuditEntry[]; total: number; has_more: boolean }> {
    this.requireAdmin(caller);
    const { from, where, values } = this.filters(params);
    const countResult = await this.db.query(`SELECT COUNT(*) AS count FROM ${from} ${where}`, values);
    const total = Number(countResult.rows[0]?.count ?? 0);
    const limit = Math.max(0, params.limit ?? 100);
    const offset = Math.max(0, params.offset ?? 0);
    const n = values.length;
    const rows = await this.db.query(
      `SELECT l.id, l.timestamp, l.actor_type, l.actor_service, l.action, l.resource_type, l.resource_id, l.old_value,
              l.new_value, l.why_chain_id, l.personal_roles, l.metadata
       FROM ${from} ${where}
       ORDER BY l.timestamp DESC, l.seq DESC
       LIMIT $${n + 1} OFFSET $${n + 2}`,
      [...values, limit, offset]
    );
    const logs = await this.decorate(rows.rows);
    return { logs, total, has_more: offset + logs.length < total };
  }

  /**
   * Admin-only replay: the resource's state before the entry, and whether a later entry changed the resource since
   * (its latest new_value differs from this entry's). Entries about the same resource are those with the same
   * resource_type and resource_id (for a subject entry: the same subject and resource_id in its subject row).
   * In: the verified caller and the log id. Out: { log_id, timestamp, resource_state_at_time, has_diverged }, or
   * { log_id, timestamp, erased: true, resource_state_at_time: null, has_diverged: null } once the subject row is
   * erased. Errors: 403 forbidden, 404 not_found. Why: AUDIT-02/08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: reads the audit tables.
   */
  async replay(caller: AuditCaller, logId: string): Promise<{
    log_id: string;
    timestamp: string;
    resource_state_at_time: any;
    has_diverged: boolean | null;
    erased?: true;
  }> {
    this.requireAdmin(caller);
    const res = await this.db.query(
      `SELECT seq, id, timestamp, actor_type, actor_service, action, resource_type, resource_id, old_value, new_value,
              why_chain_id, personal_roles, metadata
       FROM audit_log WHERE id = $1`,
      [logId]
    );
    if (res.rows.length === 0) {
      throw new AuditError('not_found', `Log not found: ${logId}`, 404);
    }
    const row = res.rows[0];
    const [entry] = await this.decorate([row]);
    const roles = String(row.personal_roles ?? '').split(',').filter(Boolean);

    if (roles.includes('subject')) {
      const subj = await this.db.query(
        `SELECT subject_ref, data FROM audit_personal WHERE log_id = $1 AND role = 'subject'`, [logId]);
      if (subj.rows.length === 0) {
        return { log_id: entry.id, timestamp: entry.timestamp, erased: true, resource_state_at_time: null, has_diverged: null };
      }
      const mine = json(subj.rows[0].data);
      const later = await this.db.query(
        `SELECT l.seq, ap.data FROM audit_log l JOIN audit_personal ap ON ap.log_id = l.id AND ap.role = 'subject'
         WHERE l.resource_type = $1 AND ap.subject_ref = $2
         ORDER BY l.timestamp ASC, l.seq ASC`,
        [row.resource_type, subj.rows[0].subject_ref]
      );
      let stateNow: any = mine.new_value ?? null;
      for (const r of later.rows) {
        const d = json(r.data);
        if (String(d.resource_id) === String(mine.resource_id)) stateNow = d.new_value ?? null;
      }
      return {
        log_id: entry.id,
        timestamp: entry.timestamp,
        resource_state_at_time: mine.old_value ?? null,
        has_diverged: JSON.stringify(stateNow) !== JSON.stringify(mine.new_value ?? null),
      };
    }

    const same = await this.db.query(
      `SELECT new_value FROM audit_log WHERE resource_type = $1 AND resource_id = $2 AND personal_roles NOT LIKE '%subject%'
       ORDER BY timestamp ASC, seq ASC`,
      [row.resource_type, row.resource_id]
    );
    let stateNow: any = json(row.new_value);
    for (const r of same.rows) stateNow = json(r.new_value);
    return {
      log_id: entry.id,
      timestamp: entry.timestamp,
      resource_state_at_time: json(row.old_value),
      has_diverged: JSON.stringify(stateNow) !== JSON.stringify(json(row.new_value)),
    };
  }

  /**
   * Admin-only search over actions and resource types (case-insensitive substring), newest first.
   * In: the verified caller and { q, resource_type, limit (default 50) }. Out: { results }. Errors: 403 forbidden.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: admin check and the new entry shape. Touches: reads the audit tables.
   */
  async search(caller: AuditCaller, params: { q: string; resource_type?: string; limit?: number }): Promise<{ results: AuditEntry[] }> {
    this.requireAdmin(caller);
    const term = `%${String(params.q ?? '').replace(/[\\%_]/g, '\\$&')}%`;
    const values: any[] = [term, term];
    let where = `WHERE (LOWER(action) LIKE LOWER($1) ESCAPE '\\' OR LOWER(resource_type) LIKE LOWER($2) ESCAPE '\\')`;
    if (params.resource_type) {
      values.push(params.resource_type);
      where += ` AND resource_type = $${values.length}`;
    }
    values.push(Math.max(0, params.limit ?? 50));
    const rows = await this.db.query(
      `SELECT id, timestamp, actor_type, actor_service, action, resource_type, resource_id, old_value, new_value,
              why_chain_id, personal_roles, metadata
       FROM audit_log ${where}
       ORDER BY timestamp DESC, seq DESC
       LIMIT $${values.length}`,
      values
    );
    return { results: await this.decorate(rows.rows) };
  }

  /**
   * Erases a data subject: in one transaction deletes every audit_personal row under the user's subject_ref and the
   * user's audit_subjects row, then adds exactly one entry 'audit_subject_erased' (actor_type service, resource_type
   * user, subject 'none', resource_id NULL, personal_roles '', metadata {erased_rows}). No audit_log row is changed.
   * In: the user id. Out: { erased_rows } (audit_personal rows deleted). Why: AUDIT-08 amendment 2026-11-10 (used by
   * data_export_compliance's account deletion). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: audit_personal, audit_subjects, one audit_log insert.
   */
  async erase_subject(userId: string | number): Promise<{ erased_rows: number }> {
    return this.transaction(async () => {
      const ref = await this.db.query(`SELECT subject_ref FROM audit_subjects WHERE user_id = $1`, [String(userId)]);
      let erased = 0;
      if (ref.rows.length > 0) {
        const subjectRef = ref.rows[0].subject_ref;
        const del = await this.db.query(`DELETE FROM audit_personal WHERE subject_ref = $1`, [subjectRef]);
        erased = Number(del.rowCount ?? 0);
        await this.db.query(`DELETE FROM audit_subjects WHERE subject_ref = $1`, [subjectRef]);
      }
      await this.insertEntry({
        actor_type: 'service',
        actor_service: 'audit',
        action: 'audit_subject_erased',
        resource_type: 'user',
        resource_id: null,
        subject_user_id: 'none',
        metadata: { erased_rows: erased },
      }, 'none');
      return { erased_rows: erased };
    });
  }

  /**
   * Retention: deletes the audit_personal rows of entries older than the configured retention period, then every
   * audit_subjects row left with no audit_personal row. audit_log rows stay. In: now (default the clock).
   * Out: { erased_rows }. Why: AUDIT-09 amendment 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: audit_personal, audit_subjects.
   */
  async apply_retention(now: Date = this.now()): Promise<{ erased_rows: number }> {
    const cutoff = new Date(now.getTime() - this.retentionDays * DAY_MS).toISOString();
    return this.transaction(async () => {
      const del = await this.db.query(
        `DELETE FROM audit_personal WHERE log_id IN (SELECT id FROM audit_log WHERE timestamp < $1)`, [cutoff]);
      await this.db.query(
        `DELETE FROM audit_subjects WHERE NOT EXISTS (SELECT 1 FROM audit_personal ap WHERE ap.subject_ref = audit_subjects.subject_ref)`);
      return { erased_rows: Number(del.rowCount ?? 0) };
    });
  }
}

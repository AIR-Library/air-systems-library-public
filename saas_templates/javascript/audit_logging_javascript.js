'use strict';

/**
 * Audit logging (docs/specs/audit_logging.md): every mutation is logged immutably and can be queried, replayed and
 * searched by admins.
 *
 * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Rebuilt for the amended spec (AUDIT-08/09/10). The log keeps
 * EVENTS only; personal data lives beside it so it can be erased without rewriting an event:
 *   audit_log       append-only events (no update, no delete). For an entry with a data subject, resource_id,
 *                   old_value, new_value and why_chain_id are NULL here and live in its 'subject' row.
 *   audit_personal  (log_id, subject_ref, role 'actor'|'subject', data): the actor's id, ip, user_agent and
 *                   request_id ('actor'), and the snapshots ('subject'). Deleted only by eraseSubject() and
 *                   applyRetention().
 *   audit_subjects  (subject_ref, user_id, created_at): subject_ref is 128 random bits, never derived from the id,
 *                   so once this row is gone nothing links the log to the person.
 * log() validates (400 subject_required, subject_mismatch, metadata_key_not_allowed, actor_user_required) and writes
 * the subject, the entry and its personal rows in one synchronous step (atomic on Node's single thread). Reads are
 * admin-only (403 admin_only). Erased entries read back with their personal fields null and personal_erased: true.
 * The old version stored ip and user agent in metadata and the subject's data in the permanent log, so nothing could
 * be erased.
 *
 * Touches: memory only (DDL is the matching SQL schema for a SQL store).
 */

const crypto = require('crypto');

const DDL = `
CREATE TABLE audit_log (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    actor_type TEXT NOT NULL CHECK(actor_type IN ('user', 'service', 'api_key')),
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
CREATE INDEX idx_audit_log_query ON audit_log (action, resource_type, timestamp);

CREATE TABLE audit_subjects (
    subject_ref TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE audit_personal (
    log_id TEXT NOT NULL REFERENCES audit_log(id),
    subject_ref TEXT NOT NULL REFERENCES audit_subjects(subject_ref),
    role TEXT NOT NULL CHECK(role IN ('actor', 'subject')),
    data TEXT NOT NULL,
    PRIMARY KEY (log_id, role)
);
CREATE INDEX idx_audit_personal_subject ON audit_personal (subject_ref, role);

CREATE TRIGGER audit_log_prevent_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'Table audit_log is immutable: UPDATE operations are forbidden.');
END;

CREATE TRIGGER audit_log_prevent_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'Table audit_log is immutable: DELETE operations are forbidden.');
END;

CREATE TRIGGER audit_personal_prevent_update
BEFORE UPDATE ON audit_personal
BEGIN
    SELECT RAISE(ABORT, 'Table audit_personal rows are never updated.');
END;
`;

const ACTOR_TYPES = ['user', 'service', 'api_key'];
const METADATA_KEYS = ['feature_flag', 'erased_rows'];
const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * An audit error with an HTTP status and a spec error code (400 subject_required, 403 admin_only, ...).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
class AuditError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.name = 'AuditError';
    this.status = status;
    this.code = code;
    this.error = code;
  }
}

/** Deep copy of a JSON value (undefined -> null). */
function copyJson(value) {
  return value === undefined ? null : JSON.parse(JSON.stringify(value));
}

/** Freezes an object and every object inside it. */
function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const v of Object.values(value)) deepFreeze(v);
  }
  return value;
}

function matchWildcard(pattern, value) {
  if (!pattern) return true;
  if (pattern === '*') return true;
  const regexStr = '^' + pattern.replace(/[-\/\\^$*+?.()|[\]{}]/g, m => m === '*' ? '.*' : '\\' + m) + '$';
  return new RegExp(regexStr).test(value);
}

/**
 * The audit logger.
 * In (constructor options): now () -> epoch ms (default Date.now); retentionDays (default 2555, about seven years:
 * set it by purpose and the legal obligations that apply); isAdmin(caller) -> bool (default: caller.role === 'admin'
 * or caller.is_admin === true), where caller is the VERIFIED caller from the auth layer, never request input.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
 */
class AuditLogger {
  static DDL = DDL;

  constructor(options = {}) {
    this.now = typeof options.now === 'function' ? options.now : () => Date.now();
    this.retentionDays = options.retentionDays != null ? options.retentionDays : 2555;
    this.isAdmin = typeof options.isAdmin === 'function'
      ? options.isAdmin
      : (caller) => !!caller && (caller.role === 'admin' || caller.is_admin === true);

    this.logs = [];                    // audit_log rows, frozen, in insertion order
    this.indexById = new Map();        // log id -> { row, seq }
    this.indexByAction = new Map();    // action -> [seq]
    this.indexByResourceType = new Map(); // resource_type -> [seq]
    this.personal = new Map();         // log id -> { actor?: personalRow, subject?: personalRow }
    this.personalBySubject = new Map(); // subject_ref -> { actor: Set<seq>, subject: Set<seq> }
    this.subjectsByUser = new Map();   // user_id (string) -> audit_subjects row
    this.subjectsByRef = new Map();    // subject_ref -> audit_subjects row
    this.resourceIndex = new Map();    // resource_type + "\u0000" + resource_id -> [seq] (live rows only)
  }

  /* ------------------------------------------------------------------ writing */

  /**
   * Finds the subject for a user, creating it (random subject_ref) the first time (insert-if-absent).
   * In: user id. Out: the audit_subjects row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory.
   */
  _subjectFor(userId, at) {
    const key = String(userId);
    let row = this.subjectsByUser.get(key);
    if (!row) {
      row = { subject_ref: crypto.randomBytes(16).toString('hex'), user_id: key, created_at: at };
      this.subjectsByUser.set(key, row);
      this.subjectsByRef.set(row.subject_ref, row);
      this.personalBySubject.set(row.subject_ref, { actor: new Set(), subject: new Set() });
    }
    return row;
  }

  _push(map, key, seq) {
    let list = map.get(key);
    if (!list) {
      list = [];
      map.set(key, list);
    }
    list.push(seq);
  }

  /**
   * log(entry) -> { success: true, log_id }. Throws AuditError 400 on invalid input. Spec endpoint 1, rules:
   *   - action and resource_type are required; actor_type is 'user' | 'service' | 'api_key' (default 'user');
   *   - metadata may hold only feature_flag and erased_rows (400 metadata_key_not_allowed);
   *   - the data subject: for resource_type 'user' the resource_id (a different subject_user_id is 400
   *     subject_mismatch); for every other resource_type subject_user_id is REQUIRED, a user id or 'none'
   *     (400 subject_required);
   *   - an 'api_key' entry requires actor_user_id, the key's owner (400 actor_user_required);
   *   - with a subject, resource_id, old_value, new_value and why_chain_id go in its 'subject' row, not in audit_log;
   *     for a 'user' or 'api_key' actor, {actor_id, ip, user_agent, request_id} go in its 'actor' row;
   *     a 'service' actor is named in actor_service (entry.actor_service, else entry.actor_id).
   * Subject, entry and personal rows are written in one synchronous step.
   * In: { actor_id, actor_type, actor_service, actor_user_id, subject_user_id, action, resource_type, resource_id,
   * old_value, new_value, why_chain_id, ip, user_agent, request_id, metadata }.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-08/10). Touches memory.
   */
  async log(entry) {
    const e = entry || {};
    if (!e.action) throw new AuditError(400, 'action_required', 'action is required');
    if (!e.resource_type) throw new AuditError(400, 'resource_type_required', 'resource_type is required');
    const actorType = e.actor_type == null ? 'user' : e.actor_type;
    if (!ACTOR_TYPES.includes(actorType)) throw new AuditError(400, 'invalid_actor_type', 'invalid actor_type');
    let metadata = null;
    if (e.metadata != null) {
      if (typeof e.metadata !== 'object' || Array.isArray(e.metadata)) {
        throw new AuditError(400, 'metadata_key_not_allowed', 'metadata must be an object');
      }
      for (const key of Object.keys(e.metadata)) {
        if (!METADATA_KEYS.includes(key)) {
          throw new AuditError(400, 'metadata_key_not_allowed', `metadata key not allowed: ${key}`);
        }
      }
      metadata = copyJson(e.metadata);
    }

    let subjectUser;
    if (e.resource_type === 'user') {
      if (e.resource_id == null) throw new AuditError(400, 'subject_required', 'a user entry needs its resource_id');
      if (e.subject_user_id != null && String(e.subject_user_id) !== String(e.resource_id)) {
        throw new AuditError(400, 'subject_mismatch', 'subject_user_id differs from the user resource_id');
      }
      subjectUser = String(e.resource_id);
    } else {
      if (e.subject_user_id == null || e.subject_user_id === '') {
        throw new AuditError(400, 'subject_required', 'subject_user_id is required (a user id or "none")');
      }
      subjectUser = e.subject_user_id === 'none' ? null : String(e.subject_user_id);
    }

    let actorUser = null;
    if (actorType === 'api_key') {
      if (e.actor_user_id == null || e.actor_user_id === '') {
        throw new AuditError(400, 'actor_user_required', 'an api_key entry needs actor_user_id (the key owner)');
      }
      actorUser = String(e.actor_user_id);
    } else if (actorType === 'user' && e.actor_id != null) {
      actorUser = String(e.actor_id);
    }

    const logId = crypto.randomUUID();
    const timestamp = new Date(this.now()).toISOString();
    const roles = [];
    if (actorUser !== null) roles.push('actor');
    if (subjectUser !== null) roles.push('subject');

    const row = deepFreeze({
      id: logId,
      timestamp,
      actor_type: actorType,
      actor_service: actorType === 'service' ? String(e.actor_service != null ? e.actor_service : (e.actor_id != null ? e.actor_id : 'unknown')) : null,
      action: String(e.action),
      resource_type: String(e.resource_type),
      resource_id: subjectUser === null && e.resource_id != null ? String(e.resource_id) : null,
      old_value: subjectUser === null ? copyJson(e.old_value) : null,
      new_value: subjectUser === null ? copyJson(e.new_value) : null,
      why_chain_id: subjectUser === null && e.why_chain_id != null ? e.why_chain_id : null,
      personal_roles: roles.join(','),
      metadata,
    });

    // From here on nothing can throw: the subject, the entry and its personal rows land together.
    const seq = this.logs.length;
    this.logs.push(row);
    this.indexById.set(logId, { row, seq });
    this._push(this.indexByAction, row.action, seq);
    this._push(this.indexByResourceType, row.resource_type, seq);
    const personal = {};
    if (actorUser !== null) {
      const subject = this._subjectFor(actorUser, timestamp);
      personal.actor = deepFreeze({
        log_id: logId,
        subject_ref: subject.subject_ref,
        role: 'actor',
        data: copyJson({
          actor_id: e.actor_id != null ? e.actor_id : null,
          ip: e.ip != null ? e.ip : null,
          user_agent: e.user_agent != null ? e.user_agent : null,
          request_id: e.request_id != null ? e.request_id : null,
        }),
      });
      this.personalBySubject.get(subject.subject_ref).actor.add(seq);
    }
    if (subjectUser !== null) {
      const subject = this._subjectFor(subjectUser, timestamp);
      personal.subject = deepFreeze({
        log_id: logId,
        subject_ref: subject.subject_ref,
        role: 'subject',
        data: copyJson({
          resource_id: e.resource_id != null ? String(e.resource_id) : null,
          old_value: e.old_value === undefined ? null : e.old_value,
          new_value: e.new_value === undefined ? null : e.new_value,
          why_chain_id: e.why_chain_id != null ? e.why_chain_id : null,
        }),
      });
      this.personalBySubject.get(subject.subject_ref).subject.add(seq);
    }
    if (personal.actor || personal.subject) this.personal.set(logId, personal);
    const rid = personal.subject ? personal.subject.data.resource_id : row.resource_id;
    if (rid != null) this._push(this.resourceIndex, `${row.resource_type}\u0000${rid}`, seq);
    return { success: true, log_id: logId };
  }

  /** The old name of log(); same contract. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
  async logMutation(entry) {
    return this.log(entry);
  }

  /* ------------------------------------------------------------------ erasure */

  /**
   * Deletes the personal rows of the given log seqs for one role set, keeping every index consistent.
   * Out: the number of audit_personal rows deleted. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory.
   */
  _deletePersonal(seq, role) {
    const row = this.logs[seq];
    const personal = this.personal.get(row.id);
    if (!personal || !personal[role]) return 0;
    const pr = personal[role];
    const bucket = this.personalBySubject.get(pr.subject_ref);
    if (bucket) bucket[role].delete(seq);
    if (role === 'subject') {
      const key = `${row.resource_type}\u0000${pr.data.resource_id}`;
      const list = this.resourceIndex.get(key);
      if (list) {
        const at = list.indexOf(seq);
        if (at >= 0) list.splice(at, 1);
        if (list.length === 0) this.resourceIndex.delete(key);
      }
    }
    const rest = { ...personal };
    delete rest[role];
    if (rest.actor || rest.subject) this.personal.set(row.id, rest);
    else this.personal.delete(row.id);
    return 1;
  }

  /** Drops a subject row (and its index bucket). */
  _dropSubject(subjectRef) {
    const subject = this.subjectsByRef.get(subjectRef);
    if (!subject) return;
    this.subjectsByRef.delete(subjectRef);
    this.subjectsByUser.delete(subject.user_id);
    this.personalBySubject.delete(subjectRef);
  }

  /**
   * eraseSubject(user_id) -> { erased_rows }: deletes every audit_personal row with the user's subject_ref (both
   * roles), then the user's audit_subjects row, in one synchronous step; no audit_log row is updated or deleted.
   * Then adds exactly one entry: action 'audit_subject_erased', actor_type 'service', resource_type 'user',
   * subject 'none', resource_id NULL, personal_roles '', metadata {erased_rows}. Nothing may log this user afterwards.
   * Spec endpoint 5 (AUDIT-08). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory.
   */
  async eraseSubject(userId) {
    let erased = 0;
    const subject = this.subjectsByUser.get(String(userId));
    if (subject) {
      const bucket = this.personalBySubject.get(subject.subject_ref);
      for (const role of ['actor', 'subject']) {
        for (const seq of Array.from(bucket[role])) erased += this._deletePersonal(seq, role);
      }
      this._dropSubject(subject.subject_ref);
    }
    this._appendServiceEntry('audit_subject_erased', { erased_rows: erased });
    return { erased_rows: erased };
  }

  /** Spec name for eraseSubject. */
  async erase_subject(userId) {
    return this.eraseSubject(userId);
  }

  /**
   * applyRetention(now) -> { erased_rows }: deletes the audit_personal rows of entries older than retentionDays
   * before now, and every audit_subjects row left with no personal rows. audit_log rows stay (AUDIT-09).
   * In: now (Date, ms or ISO; default the clock). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory.
   */
  async applyRetention(now) {
    const nowMs = now == null ? this.now() : new Date(now).getTime();
    const cutoff = new Date(nowMs - this.retentionDays * DAY_MS).toISOString();
    let erased = 0;
    const touched = new Set();
    for (const [logId, personal] of Array.from(this.personal.entries())) {
      const { row, seq } = this.indexById.get(logId);
      if (row.timestamp >= cutoff) continue;
      for (const role of ['actor', 'subject']) {
        if (personal[role]) {
          touched.add(personal[role].subject_ref);
          erased += this._deletePersonal(seq, role);
        }
      }
    }
    for (const ref of touched) {
      const bucket = this.personalBySubject.get(ref);
      if (bucket && bucket.actor.size === 0 && bucket.subject.size === 0) this._dropSubject(ref);
    }
    return { erased_rows: erased };
  }

  /** Spec name for applyRetention. */
  async apply_retention(now) {
    return this.applyRetention(now);
  }

  /** Appends a service entry with subject 'none' and no personal rows (used by eraseSubject). */
  _appendServiceEntry(action, metadata) {
    const row = deepFreeze({
      id: crypto.randomUUID(),
      timestamp: new Date(this.now()).toISOString(),
      actor_type: 'service',
      actor_service: 'audit',
      action,
      resource_type: 'user',
      resource_id: null,
      old_value: null,
      new_value: null,
      why_chain_id: null,
      personal_roles: '',
      metadata: copyJson(metadata),
    });
    const seq = this.logs.length;
    this.logs.push(row);
    this.indexById.set(row.id, { row, seq });
    this._push(this.indexByAction, row.action, seq);
    this._push(this.indexByResourceType, row.resource_type, seq);
    return row;
  }

  /* ------------------------------------------------------------------ reading */

  /** Throws 403 admin_only unless the verified caller is an admin. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
  _requireAdmin(caller) {
    if (!this.isAdmin(caller)) throw new AuditError(403, 'admin_only', 'audit reads are for admins only');
  }

  /**
   * The read view of one entry: its event fields joined with whatever personal rows remain. personal_erased is true
   * when the entry was written with personal rows (personal_roles) and one of them is gone; those fields read null.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  _view(row) {
    const personal = this.personal.get(row.id) || {};
    const roles = row.personal_roles ? row.personal_roles.split(',') : [];
    const erased = roles.some((r) => !personal[r]);
    const subject = personal.subject ? personal.subject.data : null;
    const actor = personal.actor ? personal.actor.data : null;
    const hasSubject = roles.includes('subject');
    return {
      id: row.id,
      timestamp: row.timestamp,
      actor_type: row.actor_type,
      actor_id: actor ? actor.actor_id : null,
      actor_service: row.actor_service,
      action: row.action,
      resource_type: row.resource_type,
      resource_id: hasSubject ? (subject ? subject.resource_id : null) : row.resource_id,
      old_value: copyJson(hasSubject ? (subject ? subject.old_value : null) : row.old_value),
      new_value: copyJson(hasSubject ? (subject ? subject.new_value : null) : row.new_value),
      why_chain_id: hasSubject ? (subject ? subject.why_chain_id : null) : row.why_chain_id,
      metadata: copyJson(row.metadata),
      personal_erased: erased,
    };
  }

  /**
   * queryLogs(filters, caller) -> { logs, total, has_more }. Admin-only (403). Filters: actor_id (resolved through
   * audit_subjects and the actor rows, so an erased actor matches nothing), action (exact or with *), resource_type,
   * date_from, date_to, limit (100), offset (0). Newest first; equal timestamps keep insertion order.
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] admin gate and the personal-data join (AUDIT-08/10).
   * Touches memory (read).
   */
  async queryLogs(filters = {}, caller) {
    this._requireAdmin(caller);
    const { actor_id, action, resource_type, limit = 100, offset = 0, date_from, date_to } = filters;
    let candidates = null; // ascending seqs
    if (actor_id !== undefined && actor_id !== null) {
      const subject = this.subjectsByUser.get(String(actor_id));
      const bucket = subject ? this.personalBySubject.get(subject.subject_ref) : null;
      candidates = bucket ? Array.from(bucket.actor).sort((a, b) => a - b) : [];
      // the actor row must name this actor id (an api_key entry's actor row is under its owner)
      candidates = candidates.filter((seq) => {
        const p = this.personal.get(this.logs[seq].id);
        return p && p.actor && String(p.actor.data.actor_id) === String(actor_id);
      });
    }
    if (action !== undefined && !String(action).includes('*')) {
      const list = this.indexByAction.get(action) || [];
      if (candidates === null || list.length < candidates.length) candidates = list;
    }
    if (resource_type !== undefined) {
      const list = this.indexByResourceType.get(resource_type) || [];
      if (candidates === null || list.length < candidates.length) candidates = list;
    }

    const matched = [];
    const check = (seq) => {
      const row = this.logs[seq];
      if (action !== undefined) {
        if (String(action).includes('*') ? !matchWildcard(action, row.action) : row.action !== action) return;
      }
      if (resource_type !== undefined && row.resource_type !== resource_type) return;
      if (date_from !== undefined && row.timestamp < date_from) return;
      if (date_to !== undefined && row.timestamp > date_to) return;
      if (actor_id !== undefined && actor_id !== null) {
        const p = this.personal.get(row.id);
        if (!p || !p.actor || String(p.actor.data.actor_id) !== String(actor_id)) return;
      }
      matched.push(seq);
    };
    if (candidates === null) for (let seq = 0; seq < this.logs.length; seq++) check(seq);
    else for (const seq of candidates) check(seq);

    // Newest first; equal timestamps in insertion order (stable sort over ascending seqs).
    matched.sort((a, b) => (this.logs[a].timestamp < this.logs[b].timestamp ? 1
      : this.logs[a].timestamp > this.logs[b].timestamp ? -1 : a - b));
    const total = matched.length;
    const page = matched.slice(offset, offset + limit);
    return { logs: page.map((seq) => this._view(this.logs[seq])), total, has_more: offset + limit < total };
  }

  /**
   * replay(logId, currentState, caller) -> { log_id, timestamp, resource_state_at_time, has_diverged }. Admin-only.
   * has_diverged: a later entry on the same resource exists (later time, or same time written after), or
   * currentState differs from the entry's new_value. An entry whose subject row is erased returns
   * { log_id, timestamp, erased: true, resource_state_at_time: null, has_diverged: null }. Throws for an unknown id.
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] admin gate, erased replay. Touches memory (read).
   */
  async replay(logId, currentState = null, caller) {
    this._requireAdmin(caller);
    const hit = this.indexById.get(logId);
    if (!hit) throw new AuditError(404, 'log_not_found', `Log entry not found: ${logId}`);
    const { row, seq } = hit;
    const view = this._view(row);
    const roles = row.personal_roles ? row.personal_roles.split(',') : [];
    if (roles.includes('subject') && !(this.personal.get(row.id) || {}).subject) {
      return { log_id: row.id, timestamp: row.timestamp, erased: true, resource_state_at_time: null, has_diverged: null };
    }
    let hasDiverged = false;
    if (view.resource_id != null) {
      for (const other of this.resourceIndex.get(`${row.resource_type}\u0000${view.resource_id}`) || []) {
        const o = this.logs[other];
        if (other !== seq && (o.timestamp > row.timestamp || (o.timestamp === row.timestamp && other > seq))) {
          hasDiverged = true;
          break;
        }
      }
    }
    if (currentState !== null && !hasDiverged && JSON.stringify(view.new_value) !== JSON.stringify(currentState)) {
      hasDiverged = true;
    }
    return {
      log_id: row.id,
      timestamp: row.timestamp,
      resource_state_at_time: view.old_value,
      has_diverged: hasDiverged,
    };
  }

  /**
   * search(q, resourceType, limit, caller) -> { results }. Admin-only. Case-insensitive substring over action,
   * resource_id, actor_id and the snapshots that still exist (erased data can no longer be found), in insertion order.
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] admin gate, personal-data join. Touches memory (read).
   */
  async search(q, resourceType = null, limit = 50, caller) {
    this._requireAdmin(caller);
    const query = String(q || '').toLowerCase();
    const results = [];
    const seqs = resourceType ? (this.indexByResourceType.get(resourceType) || []) : this.logs.map((_, i) => i);
    for (const seq of seqs) {
      const view = this._view(this.logs[seq]);
      const hay = [view.action, view.resource_id, view.actor_id, view.actor_service,
        view.old_value ? JSON.stringify(view.old_value) : '', view.new_value ? JSON.stringify(view.new_value) : '']
        .filter((v) => v != null).map((v) => String(v).toLowerCase());
      if (hay.some((v) => v.includes(query))) {
        results.push(view);
        if (results.length >= limit) break;
      }
    }
    return { results };
  }

  /**
   * Every retained row of the three tables, for inspection (and the AUDIT-08 proof that nothing about an erased user
   * remains). Out: { audit_log, audit_personal, audit_subjects } as plain copies. Admin-only.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory (read).
   */
  tables(caller) {
    this._requireAdmin(caller);
    const personalRows = [];
    for (const p of this.personal.values()) {
      if (p.actor) personalRows.push(p.actor);
      if (p.subject) personalRows.push(p.subject);
    }
    return copyJson({
      audit_log: this.logs,
      audit_personal: personalRows,
      audit_subjects: Array.from(this.subjectsByRef.values()),
    });
  }

  async updateLog(logId, newData) {
    throw new Error("Table 'audit_log' is immutable: UPDATE operations are forbidden.");
  }

  /**
   * Always throws: the audit log is immutable. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
   */
  async deleteLog(logId) {
    throw new Error("Table 'audit_log' is immutable: DELETE operations are forbidden.");
  }
}

module.exports = { AuditLogger, AuditError, DDL };

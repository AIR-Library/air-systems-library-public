const crypto = require('crypto');

const DDL = `
CREATE TABLE audit_log (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    actor_id TEXT,
    actor_type TEXT CHECK(actor_type IN ('user', 'service', 'api_key')),
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    why_chain_id TEXT,
    metadata TEXT
);

CREATE INDEX idx_audit_log_query 
ON audit_log (actor_id, action, resource_type, timestamp);

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
`;

function generateUUID() {
  return crypto.randomUUID ? crypto.randomUUID() : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

function matchWildcard(pattern, value) {
  if (!pattern) return true;
  if (pattern === '*') return true;
  const regexStr = '^' + pattern.replace(/[-\/\\^$*+?.()|[\]{}]/g, m => m === '*' ? '.*' : '\\' + m) + '$';
  const regex = new RegExp(regexStr);
  return regex.test(value);
}

class AuditLogger {
  static DDL = DDL;

  constructor() {
    this.logs = [];
    this.indexById = new Map();
    this.indexByActor = new Map();
    this.indexByAction = new Map();
    this.indexByResourceType = new Map();
  }

  /**
   * Appends one frozen audit entry and indexes it. Input: actor, action, resource and values; resource_id may be
   * a number. Output: { success, log_id }. Throws on a missing field. Touches: memory only. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
   */
  async logMutation(entry) {
    if (!entry.action) {
      throw new Error("Action is required");
    }
    if (!entry.resource_type) {
      throw new Error("Resource type is required");
    }
    if (entry.resource_id == null) {
      throw new Error("Resource ID is required");
    }
    if (entry.actor_type && !['user', 'service', 'api_key'].includes(entry.actor_type)) {
      throw new Error("Invalid actor_type");
    }

    const logId = generateUUID();
    const timestamp = new Date().toISOString();

    const logRecord = {
      id: logId,
      timestamp,
      actor_id: entry.actor_id !== undefined ? entry.actor_id : null,
      actor_type: entry.actor_type !== undefined ? entry.actor_type : null,
      action: entry.action,
      resource_type: entry.resource_type,
      resource_id: String(entry.resource_id),
      old_value: entry.old_value !== undefined ? JSON.parse(JSON.stringify(entry.old_value)) : null,
      new_value: entry.new_value !== undefined ? JSON.parse(JSON.stringify(entry.new_value)) : null,
      why_chain_id: entry.why_chain_id !== undefined ? entry.why_chain_id : null,
      metadata: entry.metadata !== undefined ? JSON.parse(JSON.stringify(entry.metadata)) : null
    };

    Object.freeze(logRecord);
    if (logRecord.old_value) Object.freeze(logRecord.old_value);
    if (logRecord.new_value) Object.freeze(logRecord.new_value);
    if (logRecord.metadata) Object.freeze(logRecord.metadata);

    this.logs.push(logRecord);
    this._indexRecord(logRecord);

    return { success: true, log_id: logId };
  }

  _indexRecord(log) {
    this.indexById.set(log.id, log);

    const actorKey = log.actor_id !== null && log.actor_id !== undefined ? String(log.actor_id) : 'null';
    if (!this.indexByActor.has(actorKey)) {
      this.indexByActor.set(actorKey, []);
    }
    this.indexByActor.get(actorKey).push(log);

    if (!this.indexByAction.has(log.action)) {
      this.indexByAction.set(log.action, []);
    }
    this.indexByAction.get(log.action).push(log);

    if (!this.indexByResourceType.has(log.resource_type)) {
      this.indexByResourceType.set(log.resource_type, []);
    }
    this.indexByResourceType.get(log.resource_type).push(log);
  }

  async queryLogs(filters = {}) {
    const { actor_id, action, resource_type, limit = 100, offset = 0, date_from, date_to } = filters;

    let candidates = null;

    if (actor_id !== undefined) {
      const actorKey = actor_id !== null ? String(actor_id) : 'null';
      candidates = this.indexByActor.get(actorKey) || [];
    }

    if (action !== undefined && !action.includes('*')) {
      const actionCandidates = this.indexByAction.get(action) || [];
      if (candidates === null || actionCandidates.length < candidates.length) {
        candidates = actionCandidates;
      }
    }

    if (resource_type !== undefined) {
      const resourceCandidates = this.indexByResourceType.get(resource_type) || [];
      if (candidates === null || resourceCandidates.length < candidates.length) {
        candidates = resourceCandidates;
      }
    }

    if (candidates === null) {
      candidates = this.logs;
    }

    const filtered = [];
    for (let i = 0; i < candidates.length; i++) {
      const log = candidates[i];

      if (actor_id !== undefined) {
        const actorKey = actor_id !== null ? String(actor_id) : 'null';
        const logActorKey = log.actor_id !== null && log.actor_id !== undefined ? String(log.actor_id) : 'null';
        if (logActorKey !== actorKey) continue;
      }

      if (action !== undefined) {
        if (action.includes('*')) {
          if (!matchWildcard(action, log.action)) continue;
        } else {
          if (log.action !== action) continue;
        }
      }

      if (resource_type !== undefined && log.resource_type !== resource_type) {
        continue;
      }

      if (date_from !== undefined && log.timestamp < date_from) {
        continue;
      }

      if (date_to !== undefined && log.timestamp > date_to) {
        continue;
      }

      filtered.push(log);
    }

    filtered.sort((a, b) => b.timestamp.localeCompare(a.timestamp));

    const total = filtered.length;
    const start = offset;
    const end = offset + limit;
    const paginated = filtered.slice(start, end);
    const has_more = end < total;

    return {
      logs: paginated.map(log => ({
        id: log.id,
        timestamp: log.timestamp,
        actor_id: log.actor_id,
        action: log.action,
        resource_type: log.resource_type,
        resource_id: log.resource_id,
        old_value: log.old_value,
        new_value: log.new_value,
        why_chain_id: log.why_chain_id
      })),
      total,
      has_more
    };
  }

  /**
   * Returns the state an entry recorded and whether a later entry (later time, or same millisecond written after)
   * or the given current state differs. Throws for an unknown id. Touches: memory only. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
   */
  async replay(logId, currentState = null) {
    const log = this.indexById.get(logId);
    if (!log) {
      throw new Error(`Log entry not found: ${logId}`);
    }

    let hasDiverged = false;
    const resourceLogs = this.indexByResourceType.get(log.resource_type) || [];
    // The index keeps write order, so a mutation with the same millisecond written after this one is later too.
    // Comparing timestamps alone missed it (failed 96 of 100 runs; Codex review on PR 18, 2026-11-09).
    const self = resourceLogs.indexOf(log);
    for (let i = 0; i < resourceLogs.length; i++) {
      const rLog = resourceLogs[i];
      const later = rLog.timestamp > log.timestamp || (rLog.timestamp === log.timestamp && i > self);
      if (rLog.resource_id === log.resource_id && rLog.id !== log.id && later) {
        hasDiverged = true;
        break;
      }
    }

    if (currentState !== null && !hasDiverged) {
      const newValueStr = JSON.stringify(log.new_value);
      const currentStateStr = JSON.stringify(currentState);
      if (newValueStr !== currentStateStr) {
        hasDiverged = true;
      }
    }

    return {
      log_id: log.id,
      timestamp: log.timestamp,
      resource_state_at_time: log.old_value ? JSON.parse(JSON.stringify(log.old_value)) : null,
      has_diverged: hasDiverged
    };
  }

  async search(q, resourceType = null, limit = 50) {
    const query = (q || '').toLowerCase();
    const results = [];

    const candidates = resourceType ? (this.indexByResourceType.get(resourceType) || []) : this.logs;

    for (let i = 0; i < candidates.length; i++) {
      const log = candidates[i];

      if (resourceType && log.resource_type !== resourceType) {
        continue;
      }

      const actionMatch = log.action.toLowerCase().includes(query);
      const resourceIdMatch = String(log.resource_id).toLowerCase().includes(query);
      const actorIdMatch = log.actor_id ? String(log.actor_id).toLowerCase().includes(query) : false;

      let valueMatch = false;
      if (!actionMatch && !resourceIdMatch && !actorIdMatch) {
        const oldValStr = log.old_value ? JSON.stringify(log.old_value).toLowerCase() : '';
        const newValStr = log.new_value ? JSON.stringify(log.new_value).toLowerCase() : '';
        const metaStr = log.metadata ? JSON.stringify(log.metadata).toLowerCase() : '';
        if (oldValStr.includes(query) || newValStr.includes(query) || metaStr.includes(query)) {
          valueMatch = true;
        }
      }

      if (actionMatch || resourceIdMatch || actorIdMatch || valueMatch) {
        results.push({
          id: log.id,
          timestamp: log.timestamp,
          actor_id: log.actor_id,
          action: log.action,
          resource_type: log.resource_type,
          resource_id: log.resource_id,
          old_value: log.old_value,
          new_value: log.new_value,
          why_chain_id: log.why_chain_id
        });
        if (results.length >= limit) {
          break;
        }
      }
    }

    return { results };
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

module.exports = { AuditLogger, DDL };

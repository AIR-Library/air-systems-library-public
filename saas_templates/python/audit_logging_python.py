# Repaired 2026-11-03: an in-memory logger keeps one connection, so every call sees the same database (each call
#   used to open a new, empty one).
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: SQLite only.
# Repaired 2026-11-04: query performance optimization for large datasets.
# Rebuilt 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, for the amended spec (AUDIT-08/09/10; docs/specs/audit_logging.md,
#   amended after review on PR 19 and an independent security review):
#   - audit_log keeps events only. For an entry with a data subject, resource_id, old_value, new_value and
#     why_chain_id live in its 'subject' row of audit_personal; the acting user's id, ip, user_agent and
#     request_id live in its 'actor' row. Both rows point at audit_subjects by a RANDOM subject_ref, so deleting
#     the audit_subjects row and the personal rows leaves nothing in the log that leads back to the person.
#   - log_mutation() requires subject_user_id (a user id or 'none') for every resource_type except 'user', allows
#     only the metadata keys feature_flag / erased_rows, requires actor_user_id for an api_key actor, and writes the
#     subject, the entry and its personal rows in ONE transaction.
#   - erase_subject() and apply_retention() delete personal and subject rows only, never an audit_log row;
#     erase_subject() adds exactly one 'audit_subject_erased' entry.
#   - Reads (query, replay, search) are for admins only (403 otherwise) and show personal_erased after erasure.
#   - Time comes from an injectable clock; ties are broken by insertion order (rowid), not by the random id.
# Touches: SQLite only.
import datetime
import json
import secrets
import sqlite3
import threading
import uuid
from typing import Any, Dict, Iterable, List, Optional, Tuple

ACTOR_TYPES = ("user", "service", "api_key")
ALLOWED_METADATA_KEYS = frozenset({"feature_flag", "erased_rows"})
DEFAULT_RETENTION_DAYS = 365
ERASER_SERVICE = "audit"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
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
    metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log (action, resource_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp);
-- covers the per-entry lookup of an actor_id query (id -> action, resource_type, timestamp) without reading rows
CREATE INDEX IF NOT EXISTS idx_audit_log_id_filters ON audit_log (id, action, resource_type, timestamp);

CREATE TABLE IF NOT EXISTS audit_subjects (
    subject_ref TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_personal (
    log_id TEXT NOT NULL REFERENCES audit_log (id),
    subject_ref TEXT NOT NULL REFERENCES audit_subjects (subject_ref),
    role TEXT NOT NULL CHECK (role IN ('actor', 'subject')),
    data TEXT NOT NULL,
    PRIMARY KEY (log_id, role)
);
CREATE INDEX IF NOT EXISTS idx_audit_personal_subject ON audit_personal (subject_ref, role, log_id);

CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'Audit logs are immutable and cannot be updated.'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'Audit logs are immutable and cannot be deleted.'); END;
CREATE TRIGGER IF NOT EXISTS audit_personal_no_update BEFORE UPDATE ON audit_personal
BEGIN SELECT RAISE(ABORT, 'Audit personal rows are immutable and cannot be updated.'); END;
"""


class AuditError(Exception):
    """A refused audit call: HTTP-style status and error code (400 subject_required, subject_mismatch,
    metadata_key_not_allowed, actor_user_required, invalid_actor_type; 403 admin_only; 404 log_not_found).

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-10).
    Touches nothing."""

    def __init__(self, status: int, code: str, message: str = ""):
        """Hold the HTTP-style status and error code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        self.status = status
        self.code = code
        super().__init__(message or code)


def _iso(dt: datetime.datetime) -> str:
    """Fixed-width UTC ISO-8601 with microseconds and Z, so stored times compare as text. 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _like_escape(text: str) -> str:
    """Escape LIKE wildcards (\\, %, _) so user text matches literally (used with ESCAPE '\\').
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: 'user_*' became LIKE 'user_%', where '_' matched any character.
    Touches nothing."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _is_admin(caller: Any) -> bool:
    """True if the verified caller is an admin: a dict with is_admin True, or an object with .is_admin True.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-10). Touches nothing."""
    if isinstance(caller, dict):
        return caller.get("is_admin") is True
    return getattr(caller, "is_admin", False) is True


class AuditLogger:
    def __init__(self, db_path: str = ":memory:", clock=None, retention_days: int = DEFAULT_RETENTION_DAYS):
        """Open the audit store on ONE shared connection (an in-memory database is per connection).

        In: db_path; (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP) clock returning an aware UTC datetime
        (default the wall clock) and retention_days for apply_retention() (configuration; default 365).
        Touches: SQLite (creates the tables, indexes and immutability triggers)."""
        self.db_path = db_path
        self.clock = clock or (lambda: datetime.datetime.now(datetime.timezone.utc))
        self.retention_days = retention_days
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(db_path, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA_SQL)

    def _get_connection(self) -> sqlite3.Connection:
        return self.conn

    # ------------------------------------------------------------------ writing
    def _subject_ref(self, conn: sqlite3.Connection, user_id: str, now: str) -> str:
        """Find or create the user's random subject_ref (insert-if-absent on user_id), inside the caller's
        transaction. 128 random bits, never derived from the user id. 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP. Touches: audit_subjects."""
        conn.execute("INSERT OR IGNORE INTO audit_subjects (subject_ref, user_id, created_at) VALUES (?, ?, ?)",
                     (secrets.token_hex(16), user_id, now))
        return conn.execute("SELECT subject_ref FROM audit_subjects WHERE user_id = ?", (user_id,)).fetchone()[0]

    def log_mutation(
        self,
        actor_id: Optional[Any],
        actor_type: str,
        action: str,
        resource_type: str,
        resource_id: Any,
        old_value: Optional[Dict[str, Any]],
        new_value: Optional[Dict[str, Any]],
        why_chain_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        *,
        subject_user_id: Optional[Any] = None,
        actor_user_id: Optional[Any] = None,
        actor_service: Optional[str] = None,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /audit/log (an internal, service-authenticated call; actor_id is the verified caller's).

        In: the actor (actor_id, actor_type 'user'|'service'|'api_key', actor_user_id = the api key's owner,
        actor_service = the service name, required for a service actor), the action and resource, old/new values,
        why_chain_id, metadata (only feature_flag / erased_rows), subject_user_id (required unless resource_type
        is 'user': a user id or 'none'), and the request's ip, user_agent and request_id.
        Out: {success: True, log_id}. Errors (AuditError 400): invalid_actor_type, actor_required (a 'user' actor
        without actor_id), actor_service_required (a 'service' actor without actor_service), metadata_key_not_allowed,
        subject_required, subject_mismatch, actor_user_required (an api_key actor without actor_user_id).
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2: a 'user' actor without actor_id was
        actor_user_required, and a 'service' actor without actor_service silently took str(actor_id) as its name;
        the spec now names actor_required and actor_service_required.
        Writes in ONE transaction: the subject(s) in audit_subjects, the audit_log event (resource fields only
        when the subject is 'none'), the 'subject' row {resource_id, old_value, new_value, why_chain_id} and the
        'actor' row {actor_id, ip, user_agent, request_id} (user / api_key actors).
        Why: AUDIT-01/10 as amended 2026-11-10 (personal data beside the log so it can be erased).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite."""
        if actor_type not in ACTOR_TYPES:
            raise AuditError(400, "invalid_actor_type", f"actor_type must be one of {ACTOR_TYPES}")
        metadata = dict(metadata or {})
        bad_keys = sorted(set(metadata) - ALLOWED_METADATA_KEYS)
        if bad_keys:
            raise AuditError(400, "metadata_key_not_allowed", f"metadata keys not allowed: {bad_keys}")
        if resource_type == "user":
            if resource_id is None:
                raise AuditError(400, "subject_required", "a 'user' entry needs its resource_id")
            subject = str(resource_id)
            if subject_user_id is not None and str(subject_user_id) != subject:
                raise AuditError(400, "subject_mismatch", "subject_user_id differs from the user resource_id")
        else:
            if subject_user_id is None or str(subject_user_id) == "":
                raise AuditError(400, "subject_required", "subject_user_id (a user id or 'none') is required")
            subject = None if str(subject_user_id) == "none" else str(subject_user_id)
        actor_owner: Optional[str] = None
        if actor_type == "user":
            if actor_id is None or str(actor_id) == "":
                raise AuditError(400, "actor_required", "a user actor needs actor_id")
            actor_owner = str(actor_id)
        elif actor_type == "api_key":
            if actor_user_id is None or str(actor_user_id) == "":
                raise AuditError(400, "actor_user_required", "an api_key entry needs actor_user_id (the key's owner)")
            actor_owner = str(actor_user_id)
        elif actor_service is None or str(actor_service) == "":
            raise AuditError(400, "actor_service_required", "a service actor needs actor_service (its name)")
        service_name = str(actor_service) if actor_type == "service" else None

        log_id = str(uuid.uuid4())
        now = _iso(self.clock())
        roles = [r for r, present in (("actor", actor_owner is not None), ("subject", subject is not None)) if present]
        subject_data = {"resource_id": None if resource_id is None else str(resource_id),
                        "old_value": old_value, "new_value": new_value, "why_chain_id": why_chain_id}
        in_log = subject is None  # resource fields stay in audit_log only for an entry with no data subject
        with self._lock:
            conn = self.conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "INSERT INTO audit_log (id, timestamp, actor_type, actor_service, action, resource_type, "
                    "resource_id, old_value, new_value, why_chain_id, personal_roles, metadata) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (log_id, now, actor_type, service_name, action, resource_type,
                     subject_data["resource_id"] if in_log else None,
                     json.dumps(old_value) if in_log and old_value is not None else None,
                     json.dumps(new_value) if in_log and new_value is not None else None,
                     why_chain_id if in_log else None, ",".join(roles), json.dumps(metadata, sort_keys=True)))
                if actor_owner is not None:
                    conn.execute(
                        "INSERT INTO audit_personal (log_id, subject_ref, role, data) VALUES (?, ?, 'actor', ?)",
                        (log_id, self._subject_ref(conn, actor_owner, now),
                         json.dumps({"actor_id": None if actor_id is None else str(actor_id), "ip": ip,
                                     "user_agent": user_agent, "request_id": request_id})))
                if subject is not None:
                    conn.execute(
                        "INSERT INTO audit_personal (log_id, subject_ref, role, data) VALUES (?, ?, 'subject', ?)",
                        (log_id, self._subject_ref(conn, subject, now), json.dumps(subject_data)))
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return {"success": True, "log_id": log_id}

    # ------------------------------------------------------------------ erasure and retention
    def erase_subject(self, user_id: Any) -> Dict[str, int]:
        """Erase a data subject: delete every audit_personal row with the user's subject_ref, then the
        audit_subjects row, in one transaction, and add exactly one 'audit_subject_erased' entry (actor_type
        'service', resource_type 'user', no resource_id, personal_roles '', metadata {erased_rows}).
        No audit_log row is updated or deleted. In: user_id. Out: {erased_rows}.
        Why: AUDIT-08 (spec amended 2026-11-10); data_export_compliance calls it LAST in its cascade.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite."""
        with self._lock:
            conn = self.conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT subject_ref FROM audit_subjects WHERE user_id = ?", (str(user_id),)).fetchone()
                erased = 0
                if row is not None:
                    erased = conn.execute("DELETE FROM audit_personal WHERE subject_ref = ?", (row[0],)).rowcount
                    conn.execute("DELETE FROM audit_subjects WHERE subject_ref = ?", (row[0],))
                self._insert_service_entry(conn, "audit_subject_erased", {"erased_rows": erased})
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return {"erased_rows": erased}

    def apply_retention(self, now: Optional[datetime.datetime] = None) -> Dict[str, int]:
        """Erase the personal data of entries older than retention_days, and any audit_subjects row left with no
        personal rows. audit_log rows stay. In: now (default the clock). Out: {erased_rows}.
        Why: AUDIT-09 (spec amended 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite."""
        cutoff = _iso((now or self.clock()) - datetime.timedelta(days=self.retention_days))
        with self._lock:
            conn = self.conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                erased = conn.execute(
                    "DELETE FROM audit_personal WHERE log_id IN (SELECT id FROM audit_log WHERE timestamp < ?)",
                    (cutoff,)).rowcount
                conn.execute("DELETE FROM audit_subjects WHERE subject_ref NOT IN "
                             "(SELECT DISTINCT subject_ref FROM audit_personal)")
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return {"erased_rows": erased}

    def _insert_service_entry(self, conn: sqlite3.Connection, action: str, metadata: Dict[str, Any]) -> str:
        """Append an entry by the audit service itself about no subject (inside the caller's transaction).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: audit_log."""
        log_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO audit_log (id, timestamp, actor_type, actor_service, action, resource_type, resource_id, "
            "old_value, new_value, why_chain_id, personal_roles, metadata) "
            "VALUES (?, ?, 'service', ?, ?, 'user', NULL, NULL, NULL, NULL, '', ?)",
            (log_id, _iso(self.clock()), ERASER_SERVICE, action, json.dumps(metadata, sort_keys=True)))
        return log_id

    # ------------------------------------------------------------------ reading (admins only)
    def _require_admin(self, caller: Any) -> None:
        """AuditError 403 admin_only unless the verified caller is an admin (AUDIT-10). In: caller. Out: None.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        if not _is_admin(caller):
            raise AuditError(403, "admin_only", "audit reads are for admins only")

    def _personal_for(self, log_ids: List[str]) -> Dict[Tuple[str, str], Dict[str, Any]]:
        """{(log_id, role): data} for the given entries. Touches: SQLite (read)."""
        found: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for start in range(0, len(log_ids), 500):
            chunk = log_ids[start:start + 500]
            marks = ",".join("?" * len(chunk))
            for r in self.conn.execute(f"SELECT log_id, role, data FROM audit_personal WHERE log_id IN ({marks})", chunk):
                found[(r["log_id"], r["role"])] = json.loads(r["data"])
        return found

    def _present(self, rows: Iterable[sqlite3.Row]) -> List[Dict[str, Any]]:
        """Turn audit_log rows into the read shape, joining their personal rows; an entry whose personal rows are
        gone shows those fields as null and personal_erased True. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches: SQLite (read)."""
        rows = list(rows)
        personal = self._personal_for([r["id"] for r in rows])
        out = []
        for row in rows:
            roles = [x for x in (row["personal_roles"] or "").split(",") if x]
            actor = personal.get((row["id"], "actor"))
            subject = personal.get((row["id"], "subject"))
            erased = any((row["id"], role) not in personal for role in roles)
            if "subject" in roles:
                resource = subject or {"resource_id": None, "old_value": None, "new_value": None, "why_chain_id": None}
            else:
                resource = {"resource_id": row["resource_id"],
                            "old_value": json.loads(row["old_value"]) if row["old_value"] else None,
                            "new_value": json.loads(row["new_value"]) if row["new_value"] else None,
                            "why_chain_id": row["why_chain_id"]}
            out.append({
                "id": row["id"],
                "timestamp": row["timestamp"],
                "actor_id": actor["actor_id"] if actor else (row["actor_service"] if row["actor_type"] == "service" else None),
                "actor_type": row["actor_type"],
                "actor_service": row["actor_service"],
                "ip": actor["ip"] if actor else None,
                "user_agent": actor["user_agent"] if actor else None,
                "request_id": actor["request_id"] if actor else None,
                "action": row["action"],
                "resource_type": row["resource_type"],
                "resource_id": resource["resource_id"],
                "old_value": resource["old_value"],
                "new_value": resource["new_value"],
                "why_chain_id": resource["why_chain_id"],
                "metadata": json.loads(row["metadata"]) if row["metadata"] else {},
                "personal_erased": erased,
            })
        return out

    def query_logs(
        self,
        actor_id: Optional[Any] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        *,
        caller: Any = None,
    ) -> Dict[str, Any]:
        """GET /audit/logs (admins only: AuditError 403 admin_only otherwise).

        In: filters (actor_id, action with '*' wildcards, resource_type, date_from/date_to ISO), limit, offset and
        the verified caller. Out: {logs, total, has_more}, newest first, ties in reverse insertion order.
        actor_id resolves through audit_subjects and audit_personal ('actor' rows), so an erased actor matches
        nothing; a service actor matches by its name. [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] AUDIT-03/04/
        07/08/10 as amended; '_' in a wildcard pattern is now literal. Touches: SQLite (read)."""
        self._require_admin(caller)
        source = "audit_log l"
        where: List[str] = []
        params: List[Any] = []
        if actor_id is not None:
            ref = self.conn.execute("SELECT subject_ref FROM audit_subjects WHERE user_id = ?", (str(actor_id),)).fetchone()
            if ref is not None:
                # CROSS JOIN makes SQLite walk the actor's personal rows first (it would otherwise scan every
                # entry with the action); both steps then use covering indexes (AUDIT-05: < 100 ms at 1M rows).
                source = "audit_personal p CROSS JOIN audit_log l ON l.id = p.log_id"
                where.append("p.subject_ref = ? AND p.role = 'actor'")
                params.append(ref[0])
            else:
                where.append("l.actor_type = 'service' AND l.actor_service = ?")
                params.append(str(actor_id))
        if action is not None:
            if "*" in action:
                where.append("l.action LIKE ? ESCAPE '\\'")
                params.append(_like_escape(action).replace("*", "%"))
            else:
                where.append("l.action = ?")
                params.append(action)
        if resource_type is not None:
            where.append("l.resource_type = ?")
            params.append(resource_type)
        if date_from is not None:
            where.append("l.timestamp >= ?")
            params.append(date_from)
        if date_to is not None:
            where.append("l.timestamp <= ?")
            params.append(date_to)
        where_sql = (" WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            total = self.conn.execute(f"SELECT COUNT(*) FROM {source}{where_sql}", params).fetchone()[0]
            rows = self.conn.execute(
                f"SELECT l.* FROM {source}{where_sql} ORDER BY l.timestamp DESC, l.rowid DESC LIMIT ? OFFSET ?",
                params + [limit, offset]).fetchall()
            logs = self._present(rows)
        return {"logs": logs, "total": total, "has_more": (offset + len(logs)) < total}

    def replay(self, log_id: str, *, caller: Any = None) -> Dict[str, Any]:
        """GET /audit/replay/:log_id (admins only). Out: {log_id, timestamp, resource_state_at_time (the entry's
        old_value), has_diverged (a later entry for the same resource left a different new_value)}; for an entry
        whose subject rows are gone: {log_id, timestamp, erased: True, resource_state_at_time: None,
        has_diverged: None}. AuditError 404 log_not_found. [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP]
        AUDIT-02/08 as amended. [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2 bug fix: `erased` now
        follows the entry's SUBJECT row only; it was reported when just the actor row was gone (an erased admin
        hid the state of a user who was not erased). Touches: SQLite (read)."""
        self._require_admin(caller)
        with self._lock:
            row = self.conn.execute("SELECT * FROM audit_log WHERE id = ?", (log_id,)).fetchone()
            if not row:
                raise AuditError(404, "log_not_found", f"Log entry with id {log_id} not found.")
            entry = self._present([row])[0]
            roles = [x for x in (row["personal_roles"] or "").split(",") if x]
            subject_gone = "subject" in roles and self.conn.execute(
                "SELECT 1 FROM audit_personal WHERE log_id = ? AND role = 'subject'", (log_id,)).fetchone() is None
            if subject_gone:
                return {"log_id": log_id, "timestamp": row["timestamp"], "erased": True,
                        "resource_state_at_time": None, "has_diverged": None}
            if "subject" in roles:
                ref = self.conn.execute("SELECT subject_ref FROM audit_personal WHERE log_id = ? AND role = 'subject'",
                                        (log_id,)).fetchone()[0]
                latest = self.conn.execute(
                    "SELECT l.id, p.data FROM audit_personal p JOIN audit_log l ON l.id = p.log_id "
                    "WHERE p.subject_ref = ? AND p.role = 'subject' AND l.resource_type = ? "
                    "AND json_extract(p.data, '$.resource_id') IS ? ORDER BY l.timestamp DESC, l.rowid DESC LIMIT 1",
                    (ref, row["resource_type"], entry["resource_id"])).fetchone()
                latest_new = json.loads(latest["data"])["new_value"] if latest else None
            else:
                latest = self.conn.execute(
                    "SELECT id, new_value FROM audit_log WHERE resource_type = ? AND resource_id IS ? "
                    "ORDER BY timestamp DESC, rowid DESC LIMIT 1", (row["resource_type"], row["resource_id"])).fetchone()
                latest_new = json.loads(latest["new_value"]) if latest and latest["new_value"] else None
        has_diverged = bool(latest and latest["id"] != log_id and latest_new != entry["new_value"])
        return {"log_id": log_id, "timestamp": row["timestamp"],
                "resource_state_at_time": entry["old_value"], "has_diverged": has_diverged}

    def search(self, q: str, resource_type: Optional[str] = None, limit: int = 50, *, caller: Any = None) -> Dict[str, Any]:
        """GET /audit/search (admins only): entries whose action, resource type, values or metadata contain q
        (literally; LIKE wildcards in q are escaped), newest first. Out: {results} in the query_logs() shape.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Values of an entry with a subject are searched in its
        'subject' row; erased data is no longer there to match. Touches: SQLite (read)."""
        self._require_admin(caller)
        term = f"%{_like_escape(q)}%"
        like = " LIKE ? ESCAPE '\\'"
        sql = (f"SELECT l.* FROM audit_log l WHERE (l.action{like} OR l.resource_type{like} OR l.old_value{like} "
               f"OR l.new_value{like} OR l.metadata{like} "
               f"OR l.id IN (SELECT log_id FROM audit_personal WHERE role = 'subject' AND data{like}))")
        params: List[Any] = [term] * 6
        if resource_type is not None:
            sql += " AND l.resource_type = ?"
            params.append(resource_type)
        sql += " ORDER BY l.timestamp DESC, l.rowid DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
            return {"results": self._present(rows)}

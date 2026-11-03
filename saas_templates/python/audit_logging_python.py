# Repaired 2026-11-03: an in-memory logger keeps one connection, so every call sees the same database (each call
#   used to open a new, empty one).
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: SQLite only.
import sqlite3
import json
import uuid
import datetime
from typing import Any, Dict, Optional, List

class AuditLogger:
    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        # One shared connection so every call reaches the same store.
        # With ":memory:" databases, sqlite3.connect(":memory:") creates a NEW
        # empty database on every call.
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        return self.conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
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
            """)
            # Indexing for fast queries
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_log_query 
                ON audit_log(actor_id, action, resource_type, timestamp);
            """)
            # Immutability Triggers
            # Using RAISE(ABORT, ...) ensures a sqlite3.IntegrityError is raised,
            # which is the standard behavior for constraint/trigger violations in Python's sqlite3.
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS audit_log_no_update
                BEFORE UPDATE ON audit_log
                BEGIN
                    SELECT RAISE(ABORT, 'Audit logs are immutable and cannot be updated.');
                END;
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
                BEFORE DELETE ON audit_log
                BEGIN
                    SELECT RAISE(ABORT, 'Audit logs are immutable and cannot be deleted.');
                END;
            """)
            conn.commit()

    def log_mutation(
        self,
        actor_id: Optional[Any],
        actor_type: str,
        action: str,
        resource_type: str,
        resource_id: Any,
        old_value: Dict[str, Any],
        new_value: Dict[str, Any],
        why_chain_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        log_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        actor_id_str = str(actor_id) if actor_id is not None else None
        resource_id_str = str(resource_id)

        old_value_json = json.dumps(old_value)
        new_value_json = json.dumps(new_value)
        metadata_json = json.dumps(metadata) if metadata is not None else json.dumps({})

        with self._get_connection() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO audit_log (
                        id, timestamp, actor_id, actor_type, action, 
                        resource_type, resource_id, old_value, new_value, 
                        why_chain_id, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        log_id, timestamp, actor_id_str, actor_type, action,
                        resource_type, resource_id_str, old_value_json, new_value_json,
                        why_chain_id, metadata_json
                    )
                )
                conn.commit()
            except sqlite3.Error as e:
                raise RuntimeError(f"Failed to log mutation: {e}")

        return {"success": True, "log_id": log_id}

    def query_logs(
        self,
        actor_id: Optional[Any] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None
    ) -> Dict[str, Any]:
        query = "SELECT * FROM audit_log WHERE 1=1"
        params: List[Any] = []

        if actor_id is not None:
            query += " AND actor_id = ?"
            params.append(str(actor_id))

        if action is not None:
            if "*" in action:
                query += " AND action LIKE ?"
                params.append(action.replace("*", "%"))
            else:
                query += " AND action = ?"
                params.append(action)

        if resource_type is not None:
            query += " AND resource_type = ?"
            params.append(resource_type)

        if date_from is not None:
            query += " AND timestamp >= ?"
            params.append(date_from)

        if date_to is not None:
            query += " AND timestamp <= ?"
            params.append(date_to)

        # Count total matching records
        count_query = f"SELECT COUNT(*) as total FROM ({query})"
        
        # Order and paginate
        query += " ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?"
        params_with_pagination = params + [limit, offset]

        with self._get_connection() as conn:
            total_row = conn.execute(count_query, params).fetchone()
            total = total_row["total"] if total_row else 0

            cursor = conn.execute(query, params_with_pagination)
            rows = cursor.fetchall()

        logs = []
        for row in rows:
            logs.append({
                "id": row["id"],
                "timestamp": row["timestamp"],
                "actor_id": row["actor_id"],
                "actor_type": row["actor_type"],
                "action": row["action"],
                "resource_type": row["resource_type"],
                "resource_id": row["resource_id"],
                "old_value": json.loads(row["old_value"]) if row["old_value"] else None,
                "new_value": json.loads(row["new_value"]) if row["new_value"] else None,
                "why_chain_id": row["why_chain_id"],
                "metadata": json.loads(row["metadata"]) if row["metadata"] else {}
            })

        has_more = (offset + len(logs)) < total

        return {
            "logs": logs,
            "total": total,
            "has_more": has_more
        }

    def replay(self, log_id: str) -> Dict[str, Any]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM audit_log WHERE id = ?", (log_id,)).fetchone()
            if not row:
                raise ValueError(f"Log entry with id {log_id} not found.")

            resource_type = row["resource_type"]
            resource_id = row["resource_id"]
            timestamp = row["timestamp"]

            # Find the latest state of this resource
            latest_row = conn.execute(
                """
                SELECT * FROM audit_log 
                WHERE resource_type = ? AND resource_id = ? 
                ORDER BY timestamp DESC, id DESC LIMIT 1
                """,
                (resource_type, resource_id)
            ).fetchone()

        old_value = json.loads(row["old_value"]) if row["old_value"] else None
        this_new_value = json.loads(row["new_value"]) if row["new_value"] else None
        latest_new_value = json.loads(latest_row["new_value"]) if latest_row and latest_row["new_value"] else None

        # Divergence check: Has the state changed since this log's mutation?
        # If there are newer logs that changed the state to something else, it has diverged.
        has_diverged = False
        if latest_row and latest_row["id"] != log_id:
            if this_new_value != latest_new_value:
                has_diverged = True

        return {
            "log_id": log_id,
            "timestamp": timestamp,
            "resource_state_at_time": old_value,
            "has_diverged": has_diverged
        }

    def search(self, q: str, resource_type: Optional[str] = None, limit: int = 50) -> Dict[str, Any]:
        query = """
            SELECT * FROM audit_log 
            WHERE (action LIKE ? OR resource_type LIKE ? OR old_value LIKE ? OR new_value LIKE ? OR metadata LIKE ?)
        """
        search_term = f"%{q}%"
        params: List[Any] = [search_term, search_term, search_term, search_term, search_term]

        if resource_type is not None:
            query += " AND resource_type = ?"
            params.append(resource_type)

        query += " ORDER BY timestamp DESC, id DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()

        results = []
        for row in rows:
            results.append({
                "id": row["id"],
                "timestamp": row["timestamp"],
                "actor_id": row["actor_id"],
                "actor_type": row["actor_type"],
                "action": row["action"],
                "resource_type": row["resource_type"],
                "resource_id": row["resource_id"],
                "old_value": json.loads(row["old_value"]) if row["old_value"] else None,
                "new_value": json.loads(row["new_value"]) if row["new_value"] else None,
                "why_chain_id": row["why_chain_id"],
                "metadata": json.loads(row["metadata"]) if row["metadata"] else {}
            })

        return {"results": results}

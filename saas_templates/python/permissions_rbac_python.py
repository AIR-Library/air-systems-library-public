# Repaired 2026-11-03: users belong to an organization (org_id, ON DELETE CASCADE, foreign keys on), so deleting an
#   organization removes its users, keys and sessions, as the spec says; each cascade's audit row
#   is written inside its transaction and kept or rolled back with the delete; counts are per org.
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: SQLite only.
import sqlite3
import json
import time
from contextvars import ContextVar
from typing import Callable, Any, Dict, Optional

# ---------- Database Setup ----------

DB_PATH = ':memory:'
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
conn.row_factory = sqlite3.Row
conn.execute('PRAGMA foreign_keys = ON')
cursor = conn.cursor()

def init_db() -> None:
    """Create all tables required for RBAC and cascade operations."""
    schema = """
    CREATE TABLE IF NOT EXISTS organizations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        tier TEXT NOT NULL CHECK(tier IN ('owner','admin','member','public','service')),
        org_id INTEGER,
        FOREIGN KEY(org_id) REFERENCES organizations(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        key TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        path TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS preferences (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        pref_key TEXT NOT NULL,
        pref_value TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS deployments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        FOREIGN KEY(org_id) REFERENCES organizations(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS dns_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        deployment_id INTEGER NOT NULL,
        record TEXT NOT NULL,
        FOREIGN KEY(deployment_id) REFERENCES deployments(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS theme_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        deployment_id INTEGER NOT NULL,
        config TEXT NOT NULL,
        FOREIGN KEY(deployment_id) REFERENCES deployments(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS deployment_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        deployment_id INTEGER NOT NULL,
        log TEXT NOT NULL,
        FOREIGN KEY(deployment_id) REFERENCES deployments(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        action TEXT NOT NULL,
        user_id INTEGER,
        endpoint TEXT,
        required_tier TEXT,
        user_tier TEXT,
        decision TEXT,
        details TEXT
    );
    """
    conn.executescript(schema)
    conn.commit()

init_db()

# ---------- Context Management ----------

_current_user: ContextVar[Optional[Dict[str, Any]]] = ContextVar('_current_user', default=None)

def set_current_user(user: Optional[Dict[str, Any]]) -> None:
    _current_user.set(user)

def get_current_user() -> Optional[Dict[str, Any]]:
    return _current_user.get()

# ---------- Helper Functions ----------

def json_error(error_code: str, message: str, http_status: int) -> Dict[str, Any]:
    return {"error": error_code, "message": message, "code": http_status}

def audit_log(action: str,
              user_id: Optional[int] = None,
              endpoint: Optional[str] = None,
              required_tier: Optional[str] = None,
              user_tier: Optional[str] = None,
              decision: Optional[str] = None,
              details: Optional[Dict[str, Any]] = None) -> None:
    """Write one audit row. Inside an open transaction (a cascade delete) the row joins it, so it is kept or
    rolled back together with the delete it records; otherwise it is committed at once."""
    ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    in_tx = conn.in_transaction
    conn.execute(
        "INSERT INTO audit_log (timestamp, action, user_id, endpoint, required_tier, user_tier, decision, details) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (ts, action, user_id, endpoint, required_tier, user_tier, decision, json.dumps(details) if details else None)
    )
    if not in_tx:
        conn.commit()

# Tier hierarchy for checks
_TIER_RANK = {
    "public": 0,
    "member": 1,
    "admin": 2,
    "owner": 3,
    "service": 4  # service is highest but rarely used for endpoint checks
}

def _has_at_least(user_tier: str, required_tier: str) -> bool:
    return _TIER_RANK.get(user_tier, -1) >= _TIER_RANK.get(required_tier, -1)

# ---------- Permission Decorators ----------

def _permission_decorator(required_tier: str, error_key: str, http_status: int):
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            user = get_current_user()
            user_id = user.get('id') if user else None
            user_tier = user.get('tier') if user else None
            decision = "FAIL"
            if user is None:
                # authentication required
                audit_log(
                    action="permission_check",
                    user_id=None,
                    endpoint=func.__name__,
                    required_tier=required_tier,
                    user_tier=None,
                    decision=decision,
                    details={"reason": "no_user"}
                )
                return json_error("authentication_required", "Authentication required", 401)
            if not _has_at_least(user_tier, required_tier):
                audit_log(
                    action="permission_check",
                    user_id=user_id,
                    endpoint=func.__name__,
                    required_tier=required_tier,
                    user_tier=user_tier,
                    decision=decision,
                    details={"reason": error_key}
                )
                return json_error(error_key, f"{error_key.replace('_', ' ')}", http_status)
            decision = "PASS"
            audit_log(
                action="permission_check",
                user_id=user_id,
                endpoint=func.__name__,
                required_tier=required_tier,
                user_tier=user_tier,
                decision=decision,
                details=None
            )
            result = func(*args, **kwargs)
            # Ensure permission check overhead stays low (<10ms) – measured by caller if needed
            elapsed_ms = (time.perf_counter() - start) * 1000
            return result
        return wrapper
    return decorator

require_owner = _permission_decorator("owner", "owner_only", 403)
require_admin = _permission_decorator("admin", "admin_only", 403)
require_authenticated = _permission_decorator("public", "authentication_required", 401)  # public tier means any logged user

# ---------- Cascade Delete Implementations ----------

# For testing: allow injection of a failure hook
_cascade_failure_hook: Optional[Callable[[str], None]] = None

def set_cascade_failure_hook(hook: Optional[Callable[[str], None]]) -> None:
    global _cascade_failure_hook
    _cascade_failure_hook = hook

def delete_user(user_id: int) -> Dict[str, Any]:
    try:
        conn.execute('BEGIN')
        # Count related records before deletion for audit details
        sess_cnt = conn.execute('SELECT COUNT(*) FROM sessions WHERE user_id=?', (user_id,)).fetchone()[0]
        key_cnt = conn.execute('SELECT COUNT(*) FROM api_keys WHERE user_id=?', (user_id,)).fetchone()[0]
        file_cnt = conn.execute('SELECT COUNT(*) FROM files WHERE user_id=?', (user_id,)).fetchone()[0]
        pref_cnt = conn.execute('SELECT COUNT(*) FROM preferences WHERE user_id=?', (user_id,)).fetchone()[0]
        
        if _cascade_failure_hook:
            _cascade_failure_hook('users')
        
        conn.execute('DELETE FROM users WHERE id=?', (user_id,))
        audit_log(
            action="user_deleted_cascade",
            user_id=user_id,
            details={"sessions": sess_cnt, "keys": key_cnt, "files": file_cnt, "preferences": pref_cnt}
        )
        conn.execute('COMMIT')
        return {"status": "success"}
    except Exception as e:
        if conn.in_transaction:
            conn.execute('ROLLBACK')
        return json_error("cascade_failure", str(e), 500)

def delete_deployment(deployment_id: int) -> Dict[str, Any]:
    try:
        conn.execute('BEGIN')
        dns_cnt = conn.execute('SELECT COUNT(*) FROM dns_records WHERE deployment_id=?', (deployment_id,)).fetchone()[0]
        theme_cnt = conn.execute('SELECT COUNT(*) FROM theme_configs WHERE deployment_id=?', (deployment_id,)).fetchone()[0]
        log_cnt = conn.execute('SELECT COUNT(*) FROM deployment_logs WHERE deployment_id=?', (deployment_id,)).fetchone()[0]
        
        if _cascade_failure_hook:
            _cascade_failure_hook('deployments')
        
        conn.execute('DELETE FROM deployments WHERE id=?', (deployment_id,))
        audit_log(
            action="deployment_deleted_cascade",
            user_id=get_current_user().get('id') if get_current_user() else None,
            details={"dns": dns_cnt, "themes": theme_cnt, "logs": log_cnt, "archived": True}
        )
        conn.execute('COMMIT')
        return {"status": "success"}
    except Exception as e:
        if conn.in_transaction:
            conn.execute('ROLLBACK')
        return json_error("cascade_failure", str(e), 500)

def delete_organization(org_id: int) -> Dict[str, Any]:
    try:
        conn.execute('BEGIN')
        dep_cnt = conn.execute('SELECT COUNT(*) FROM deployments WHERE org_id=?', (org_id,)).fetchone()[0]
        user_cnt = conn.execute('SELECT COUNT(*) FROM users WHERE org_id=?', (org_id,)).fetchone()[0]
        key_cnt = conn.execute('SELECT COUNT(*) FROM api_keys WHERE user_id IN (SELECT id FROM users WHERE org_id=?)', (org_id,)).fetchone()[0]
        sess_cnt = conn.execute('SELECT COUNT(*) FROM sessions WHERE user_id IN (SELECT id FROM users WHERE org_id=?)', (org_id,)).fetchone()[0]
        
        if _cascade_failure_hook:
            _cascade_failure_hook('organizations')
        
        conn.execute('DELETE FROM organizations WHERE id=?', (org_id,))
        audit_log(
            action="org_deleted_cascade",
            user_id=get_current_user().get('id') if get_current_user() else None,
            details={"deployments": dep_cnt, "users": user_cnt, "api_keys": key_cnt, "sessions": sess_cnt}
        )
        conn.execute('COMMIT')
        return {"status": "success"}
    except Exception as e:
        if conn.in_transaction:
            conn.execute('ROLLBACK')
        return json_error("cascade_failure", str(e), 500)

# ---------- Example Endpoints (for testing) ----------

@require_owner
def admin_create_user(username: str, tier: str) -> Dict[str, Any]:
    try:
        conn.execute('INSERT INTO users (username, tier) VALUES (?, ?)', (username, tier))
        conn.commit()
        return {"status": "user_created", "username": username, "tier": tier}
    except sqlite3.IntegrityError as e:
        return json_error("user_exists", str(e), 400)

@require_admin
def admin_list_customers() -> Dict[str, Any]:
    rows = conn.execute('SELECT id, name FROM organizations').fetchall()
    customers = [{"id": r["id"], "name": r["name"]} for r in rows]
    return {"customers": customers}

@require_authenticated
def public_signup(username: str) -> Dict[str, Any]:
    # Public signup creates a member user
    try:
        conn.execute('INSERT INTO users (username, tier) VALUES (?, ?)', (username, 'member'))
        conn.commit()
        return {"status": "signed_up", "username": username}
    except sqlite3.IntegrityError as e:
        return json_error("user_exists", str(e), 400)

# Tests updated with the fix 2026-11-03: users belong to an organization (org_id, ON DELETE CASCADE, foreign keys on), so deleting an
#   organization removes its users, keys and sessions, as the spec says; each cascade's audit row
#   is written inside its transaction and kept or rolled back with the delete; counts are per org.
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: SQLite only.
import json
import pytest
import time
from typing import Optional
from permissions_rbac_python import (
    conn,
    set_current_user,
    admin_create_user,
    admin_list_customers,
    public_signup,
    delete_user,
    delete_deployment,
    delete_organization,
    json_error,
    set_cascade_failure_hook,
)


# Helper to reset DB between tests
@pytest.fixture(autouse=True)
def reset_db():
    # Clear all tables
    conn.executescript(
        """
        DELETE FROM audit_log;
        DELETE FROM sessions;
        DELETE FROM api_keys;
        DELETE FROM files;
        DELETE FROM preferences;
        DELETE FROM dns_records;
        DELETE FROM theme_configs;
        DELETE FROM deployment_logs;
        DELETE FROM deployments;
        DELETE FROM organizations;
        DELETE FROM users;
        """
    )
    conn.commit()
    yield
    # Ensure clean state after each test
    conn.executescript(
        """
        DELETE FROM audit_log;
        DELETE FROM sessions;
        DELETE FROM api_keys;
        DELETE FROM files;
        DELETE FROM preferences;
        DELETE FROM dns_records;
        DELETE FROM theme_configs;
        DELETE FROM deployment_logs;
        DELETE FROM deployments;
        DELETE FROM organizations;
        DELETE FROM users;
        """
    )
    conn.commit()
    set_current_user(None)
    set_cascade_failure_hook(None)


def create_user(username: str, tier: str, org_id: Optional[int] = None) -> int:
    if org_id is not None:
        cur = conn.execute("INSERT INTO users (username, tier, org_id) VALUES (?, ?, ?)", (username, tier, org_id))
    else:
        cur = conn.execute("INSERT INTO users (username, tier) VALUES (?, ?)", (username, tier))
    conn.commit()
    return cur.lastrowid


def test_require_owner_on_non_owner():
    uid = create_user("alice", "member")
    set_current_user({"id": uid, "username": "alice", "tier": "member"})
    resp = admin_create_user("bob", "member")
    assert resp["error"] == "owner_only"
    assert resp["code"] == 403


def test_require_admin_on_member():
    uid = create_user("charlie", "member")
    set_current_user({"id": uid, "username": "charlie", "tier": "member"})
    resp = admin_list_customers()
    assert resp["error"] == "admin_only"
    assert resp["code"] == 403


def test_require_authenticated_on_public():
    set_current_user(None)
    resp = public_signup("dave")
    assert resp["error"] == "authentication_required"
    assert resp["code"] == 401


def test_cascade_delete_user():
    uid = create_user("eve", "member")
    conn.execute("INSERT INTO sessions (user_id, token) VALUES (?, ?)", (uid, "tok1"))
    conn.execute("INSERT INTO api_keys (user_id, key) VALUES (?, ?)", (uid, "key1"))
    conn.execute("INSERT INTO files (user_id, path) VALUES (?, ?)", (uid, "/tmp/file"))
    conn.execute(
        "INSERT INTO preferences (user_id, pref_key, pref_value) VALUES (?, ?, ?)",
        (uid, "theme", "dark"),
    )
    conn.commit()
    set_current_user({"id": uid, "username": "eve", "tier": "member"})
    resp = delete_user(uid)
    assert resp["status"] == "success"
    # Verify cascade deletions
    assert conn.execute("SELECT COUNT(*) FROM users WHERE id=?", (uid,)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM sessions WHERE user_id=?", (uid,)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM api_keys WHERE user_id=?", (uid,)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM files WHERE user_id=?", (uid,)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM preferences WHERE user_id=?", (uid,)).fetchone()[0] == 0


def test_cascade_delete_deployment():
    org_id = conn.execute("INSERT INTO organizations (name) VALUES (?)", ("OrgX",)).lastrowid
    dep_id = conn.execute(
        "INSERT INTO deployments (org_id, name) VALUES (?, ?)", (org_id, "Dep1")
    ).lastrowid
    conn.execute(
        "INSERT INTO dns_records (deployment_id, record) VALUES (?, ?)", (dep_id, "A record")
    )
    conn.execute(
        "INSERT INTO theme_configs (deployment_id, config) VALUES (?, ?)",
        (dep_id, "{}"),
    )
    conn.execute(
        "INSERT INTO deployment_logs (deployment_id, log) VALUES (?, ?)",
        (dep_id, "log entry"),
    )
    conn.commit()
    set_current_user({"id": 1, "username": "owner", "tier": "owner"})
    resp = delete_deployment(dep_id)
    assert resp["status"] == "success"
    # Verify cascade deletions
    assert conn.execute("SELECT COUNT(*) FROM deployments WHERE id=?", (dep_id,)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM dns_records WHERE deployment_id=?", (dep_id,)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM theme_configs WHERE deployment_id=?", (dep_id,)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM deployment_logs WHERE deployment_id=?", (dep_id,)).fetchone()[0] == 0


def test_cascade_delete_org():
    org_id = conn.execute("INSERT INTO organizations (name) VALUES (?)", ("OrgY",)).lastrowid
    dep_id = conn.execute(
        "INSERT INTO deployments (org_id, name) VALUES (?, ?)", (org_id, "DepA")
    ).lastrowid
    user_id = create_user("frank", "member", org_id=org_id)
    conn.execute("INSERT INTO sessions (user_id, token) VALUES (?, ?)", (user_id, "tok2"))
    conn.execute("INSERT INTO api_keys (user_id, key) VALUES (?, ?)", (user_id, "key2"))
    conn.commit()
    set_current_user({"id": 1, "username": "owner", "tier": "owner"})
    resp = delete_organization(org_id)
    assert resp["status"] == "success"
    # Verify organization and its deployments are removed
    assert conn.execute("SELECT COUNT(*) FROM organizations WHERE id=?", (org_id,)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM deployments WHERE org_id=?", (org_id,)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM users WHERE id=?", (user_id,)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM sessions WHERE user_id=?", (user_id,)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM api_keys WHERE user_id=?", (user_id,)).fetchone()[0] == 0


def test_cascade_on_error_rollback():
    def failing_hook(table: str):
        if table == 'users':
            raise Exception("forced failure")
    
    set_cascade_failure_hook(failing_hook)
    uid = create_user("grace", "member")
    set_current_user({"id": uid, "username": "grace", "tier": "member"})
    resp = delete_user(uid)
    assert resp["error"] == "cascade_failure"
    # Ensure the user was not partially deleted
    assert conn.execute("SELECT COUNT(*) FROM users WHERE id=?", (uid,)).fetchone()[0] == 1
    # ... and no audit row claims a cascade that was rolled back
    assert conn.execute(
        "SELECT COUNT(*) FROM audit_log WHERE action='user_deleted_cascade' AND user_id=?", (uid,)
    ).fetchone()[0] == 0
    set_cascade_failure_hook(None)


def test_cascade_delete_is_audited_and_committed():
    # The cascade's audit row is written in the same transaction as the delete and is committed with it
    # (2026-11-03: a buffered version lost this row when nothing flushed it).
    uid = create_user("henry", "member")
    conn.execute("INSERT INTO sessions (user_id, token) VALUES (?, ?)", (uid, "tok3"))
    conn.commit()
    set_current_user({"id": uid, "username": "henry", "tier": "member"})
    assert delete_user(uid)["status"] == "success"
    assert not conn.in_transaction
    row = conn.execute(
        "SELECT details FROM audit_log WHERE action='user_deleted_cascade' AND user_id=?", (uid,)
    ).fetchone()
    assert row is not None
    assert json.loads(row[0])["sessions"] == 1


def test_permission_audit_logged():
    uid = create_user("henry", "member")
    set_current_user({"id": uid, "username": "henry", "tier": "member"})
    # Successful permission check (public_signup)
    _ = public_signup("new_user")
    # Failed permission check (admin_create_user)
    _ = admin_create_user("bob", "member")
    rows = conn.execute("SELECT * FROM audit_log WHERE user_id=?", (uid,)).fetchall()
    actions = [r["action"] for r in rows]
    assert "permission_check" in actions
    decisions = {r["decision"] for r in rows}
    assert decisions == {"PASS", "FAIL"}


def test_tier_hierarchy():
    owner_id = create_user("owner_user", "owner")
    admin_id = create_user("admin_user", "admin")
    member_id = create_user("member_user", "member")
    # Owner can perform admin-level action
    set_current_user({"id": owner_id, "username": "owner_user", "tier": "owner"})
    resp = admin_list_customers()
    assert "customers" in resp
    # Admin cannot perform owner-only action
    set_current_user({"id": admin_id, "username": "admin_user", "tier": "admin"})
    resp = admin_create_user("new", "member")
    assert resp["error"] == "owner_only"
    # Member cannot perform admin-level action
    set_current_user({"id": member_id, "username": "member_user", "tier": "member"})
    resp = admin_list_customers()
    assert resp["error"] == "admin_only"


def test_permission_check_response_time():
    uid = create_user("tim", "member")
    set_current_user({"id": uid, "username": "tim", "tier": "member"})
    start = time.perf_counter()
    _ = public_signup("another")
    elapsed_ms = (time.perf_counter() - start) * 1000
    assert elapsed_ms < 10, f"Permission check took {elapsed_ms}ms, exceeds 10ms"

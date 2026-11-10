import pytest
import sqlite3
from organizations_teams_python import (
    OrganizationsTeams, InMemoryStore, SqlStore, Options,
    User, Org, Membership, OrgError, SCHEMA_SQL
)

T0 = 1700000000

def make_users():
    return {
        'owner': User('u-owner', 'owner@example.com'),
        'admin': User('u-admin', 'admin@example.com'),
        'member': User('u-member', 'member@example.com'),
        'outsider': User('u-out', 'out@example.com'),
        'x': User('u-x', 'x@example.com'),
        'z': User('u-z', 'z@example.com'),
        'o2': User('u-o2', 'o2@example.com'),
        'new': User('u-new', 'new@example.com'),
    }

def counter_random():
    k = [0]
    def gen(n: int) -> bytes:
        k[0] += 1
        return bytes([k[0] % 256]) * n
    return gen

def assert_error(fn, code: str, status: int):
    with pytest.raises(OrgError) as ei:
        fn()
    assert ei.value.code == code
    assert ei.value.status == status

# ORG-01
def test_non_member_cannot_read_members_of_another_org():
    users = make_users()
    clock = [T0]
    svc = OrganizationsTeams(InMemoryStore(), Options(clock=lambda: clock[0]))
    alpha = svc.create_org(users['owner'], "Alpha")
    beta = svc.create_org(users['outsider'], "Beta")
    fake_id = "f" * 64

    for op in [
        lambda: svc.list_members(users['outsider'], alpha.id),
        lambda: svc.get_org(users['outsider'], alpha.id),
        lambda: svc.invite(users['outsider'], alpha.id, "x@example.com", "member"),
        lambda: svc.change_role(users['outsider'], alpha.id, users['owner'].id, "admin"),
        lambda: svc.remove_member(users['outsider'], alpha.id, users['owner'].id),
        lambda: svc.leave_org(users['outsider'], alpha.id),
    ]:
        assert_error(op, "ORG_NOT_FOUND", 404)

    for op in [
        lambda: svc.list_members(users['outsider'], fake_id),
        lambda: svc.get_org(users['outsider'], fake_id),
    ]:
        assert_error(op, "ORG_NOT_FOUND", 404)

    assert svc.get_org(users['outsider'], beta.id).id == beta.id

    anon = User("", "")
    assert_error(lambda: svc.list_members(anon, alpha.id), "UNAUTHENTICATED", 401)
    assert_error(lambda: svc.create_org(anon, "Gamma"), "UNAUTHENTICATED", 401)

# ORG-02
def test_member_cannot_invite_admin_can():
    users = make_users()
    clock = [T0]
    svc = OrganizationsTeams(InMemoryStore(), Options(clock=lambda: clock[0]))
    org = svc.create_org(users['owner'], "TestOrg")
    token_m = svc.invite(users['owner'], org.id, "member@example.com", "member")
    svc.accept_invitation(users['member'], token_m)
    token_a = svc.invite(users['owner'], org.id, "admin@example.com", "admin")
    svc.accept_invitation(users['admin'], token_a)

    assert_error(lambda: svc.invite(users['member'], org.id, "new@example.com", "member"), "FORBIDDEN", 403)

    token_new = svc.invite(users['admin'], org.id, "new@example.com", "member")
    assert len(token_new) == 64 and all(c in '0123456789abcdef' for c in token_new)
    mem = svc.accept_invitation(users['new'], token_new)
    assert mem.role == "member"

    assert_error(lambda: svc.invite(users['admin'], org.id, "another@example.com", "owner"), "FORBIDDEN", 403)

# ORG-03
def test_admin_cannot_remove_owner_and_last_owner_cannot_leave():
    users = make_users()
    clock = [T0]
    svc = OrganizationsTeams(InMemoryStore(), Options(clock=lambda: clock[0]))
    org = svc.create_org(users['owner'], "TestOrg")
    token_a = svc.invite(users['owner'], org.id, "admin@example.com", "admin")
    svc.accept_invitation(users['admin'], token_a)
    token_m = svc.invite(users['owner'], org.id, "member@example.com", "member")
    svc.accept_invitation(users['member'], token_m)

    assert_error(lambda: svc.remove_member(users['admin'], org.id, users['owner'].id), "FORBIDDEN", 403)
    assert_error(lambda: svc.change_role(users['admin'], org.id, users['owner'].id, "member"), "FORBIDDEN", 403)
    assert_error(lambda: svc.change_role(users['admin'], org.id, users['member'].id, "owner"), "FORBIDDEN", 403)
    svc.remove_member(users['admin'], org.id, users['member'].id)
    members = svc.list_members(users['owner'], org.id)
    assert len(members) == 2
    assert all(m.user_id != users['member'].id for m in members)

    assert_error(lambda: svc.leave_org(users['owner'], org.id), "LAST_OWNER", 409)
    assert_error(lambda: svc.change_role(users['owner'], org.id, users['owner'].id, "admin"), "LAST_OWNER", 409)
    assert_error(lambda: svc.remove_member(users['owner'], org.id, users['owner'].id), "LAST_OWNER", 409)
    members = svc.list_members(users['owner'], org.id)
    assert any(m.user_id == users['owner'].id and m.role == "owner" for m in members)

# ORG-04
def test_invitation_works_once_second_use_fails():
    users = make_users()
    clock = [T0]
    svc = OrganizationsTeams(InMemoryStore(), Options(clock=lambda: clock[0]))
    org = svc.create_org(users['owner'], "TestOrg")
    token = svc.invite(users['owner'], org.id, "x@example.com", "member")
    mem = svc.accept_invitation(users['x'], token)
    assert mem.org_id == org.id
    assert mem.user_id == users['x'].id
    assert mem.role == "member"
    assert mem.created_at == T0

    assert_error(lambda: svc.accept_invitation(users['x'], token), "INVITATION_USED", 410)

    token2 = svc.invite(users['owner'], org.id, "x@example.com", "member")
    assert_error(lambda: svc.accept_invitation(users['x'], token2), "ALREADY_MEMBER", 409)

# ORG-05
def test_expired_invitation_fails():
    users = make_users()
    clock = [T0]
    svc = OrganizationsTeams(InMemoryStore(), Options(clock=lambda: clock[0]))
    org = svc.create_org(users['owner'], "TestOrg")
    token = svc.invite(users['owner'], org.id, "x@example.com", "member")
    clock[0] = T0 + 691200
    assert_error(lambda: svc.accept_invitation(users['x'], token), "INVITATION_EXPIRED", 410)
    members = svc.list_members(users['owner'], org.id)
    assert len(members) == 1

# ORG-05
def test_accept_with_different_email_fails():
    users = make_users()
    clock = [T0]
    svc = OrganizationsTeams(InMemoryStore(), Options(clock=lambda: clock[0]))
    org = svc.create_org(users['owner'], "TestOrg")
    token = svc.invite(users['owner'], org.id, "  X@Example.COM ", "member")
    assert_error(lambda: svc.accept_invitation(users['z'], token), "EMAIL_MISMATCH", 403)
    mem = svc.accept_invitation(users['x'], token)
    assert mem.role == "member"

# ORG-06
def test_raw_token_not_stored_in_database():
    clock = [T0]
    rand = counter_random()
    svc = OrganizationsTeams(InMemoryStore(), Options(clock=lambda: clock[0], random_bytes=rand))
    org = svc.create_org(User('u-owner', 'owner@example.com'), "TestOrg")
    assert org.id == "01" * 16
    token = svc.invite(User('u-owner', 'owner@example.com'), org.id, "x@example.com", "member")
    assert token == "02" * 32
    dump = svc._store.debug_dump()
    assert token not in dump
    expected_hash = "749f1a97ff6cd00ea46ccb3a47bb123283fe56c8fa324bea295d928f558161df"
    assert expected_hash in dump
    svc.accept_invitation(User('u-x', 'x@example.com'), token)
    members = svc.list_members(User('u-owner', 'owner@example.com'), org.id)
    assert len(members) == 2

    conn = sqlite3.connect(":memory:", check_same_thread=False)
    store = SqlStore(conn)
    store.create_schema()
    clock2 = [T0]
    rand2 = counter_random()
    svc2 = OrganizationsTeams(store, Options(clock=lambda: clock2[0], random_bytes=rand2))
    org2 = svc2.create_org(User('u-owner', 'owner@example.com'), "TestOrg")
    assert org2.id == "01" * 16
    token2 = svc2.invite(User('u-owner', 'owner@example.com'), org2.id, "x@example.com", "member")
    assert token2 == "02" * 32
    cur = conn.execute("SELECT * FROM organizations")
    for row in cur.fetchall():
        for v in row:
            assert token2 not in str(v)
    cur = conn.execute("SELECT * FROM memberships")
    for row in cur.fetchall():
        for v in row:
            assert token2 not in str(v)
    cur = conn.execute("SELECT * FROM invitations")
    rows = cur.fetchall()
    found_hash = False
    for row in rows:
        for v in row:
            assert token2 not in str(v)
            if str(v) == expected_hash:
                found_hash = True
    assert found_hash, "token hash not found in invitations table"
    members2 = svc2.list_members(User('u-owner', 'owner@example.com'), org2.id)
    assert len(members2) == 1
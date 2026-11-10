import { test } from 'node:test';
import assert from 'node:assert/strict';
import { OrganizationsTeams, InMemoryStore } from './organizations_teams_typescript.ts';
import { createHash } from 'node:crypto';

function createService() {
  const store = new InMemoryStore();
  return new OrganizationsTeams(store);
}

// ORG-01
test('non-member cannot read members of another org (IDOR attempt)', () => {
  const svc = createService();

  const org1 = svc.createOrg('user1', 'Org One');
  const org1Id = org1.body.id;

  const org2 = svc.createOrg('user2', 'Org Two');
  const org2Id = org2.body.id;

  assert.throws(
    () => svc.listMembers('user1', org2Id),
    /not found/
  );
});

// ORG-02
test('member cannot invite; admin can', () => {
  const svc = createService();

  const org = svc.createOrg('owner', 'Test Org');
  const orgId = org.body.id;

  // Owner invites admin
  const inviteResult = svc.invite('owner', orgId, 'admin@example.com', 'admin');
  const adminToken = inviteResult.body.token;
  svc.acceptInvitation('admin@example.com', adminToken);

  // Admin can invite
  const adminInvite = svc.invite('admin@example.com', orgId, 'member@example.com', 'member');
  assert.equal(adminInvite.status, 201);
  const memberToken = adminInvite.body.token;
  svc.acceptInvitation('member@example.com', memberToken);

  // Member cannot invite
  assert.throws(
    () => svc.invite('member@example.com', orgId, 'another@example.com', 'member'),
    /forbidden/
  );
});

// ORG-03
test('admin cannot remove owner; last owner cannot leave', () => {
  const svc = createService();

  const org = svc.createOrg('owner', 'Test Org');
  const orgId = org.body.id;

  // Invite admin
  const inviteResult = svc.invite('owner', orgId, 'admin@example.com', 'admin');
  svc.acceptInvitation('admin@example.com', inviteResult.body.token);

  // Admin tries to remove owner - should fail
  assert.throws(
    () => svc.removeMember('admin@example.com', orgId, 'owner'),
    /forbidden/
  );

  // Owner tries to leave - should fail (last owner)
  assert.throws(
    () => svc.leaveOrg('owner', orgId),
    /last owner protected/
  );
});

// ORG-04
test('invitation works once; second use fails', () => {
  const svc = createService();

  const org = svc.createOrg('owner', 'Test Org');
  const orgId = org.body.id;

  const inviteResult = svc.invite('owner', orgId, 'user@example.com', 'member');
  const rawToken = inviteResult.body.token;

  // First acceptance works
  const firstAccept = svc.acceptInvitation('user@example.com', rawToken);
  assert.equal(firstAccept.status, 200);

  // Second acceptance fails
  assert.throws(
    () => svc.acceptInvitation('user@example.com', rawToken),
    /already used/
  );
});

// ORG-05
// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: uses the service's injected clock instead of replacing the
// global Date (the spec requires an injectable clock; same assertion as before).
test('expired invitation fails', () => {
  let nowMs = Date.parse('2023-01-01T00:00:00Z');
  const svc = new OrganizationsTeams(new InMemoryStore(), () => nowMs);

  const org = svc.createOrg('owner', 'Test Org');
  const orgId = org.body.id;

  // Create invitation that expires in 7 days (2023-01-08)
  const inviteResult = svc.invite('owner', orgId, 'user@example.com', 'member');
  const rawToken = inviteResult.body.token;

  // Move time to after expiration (2023-01-09)
  nowMs = Date.parse('2023-01-09T00:00:00Z');
  assert.throws(
    () => svc.acceptInvitation('user@example.com', rawToken),
    /expired/
  );
});

// ORG-05
test('accepting with different email fails', () => {
  const svc = createService();

  const org = svc.createOrg('owner', 'Test Org');
  const orgId = org.body.id;

  const inviteResult = svc.invite('owner', orgId, 'user@example.com', 'member');
  const rawToken = inviteResult.body.token;

  // Attempt to accept with different email
  assert.throws(
    () => svc.acceptInvitation('different@example.com', rawToken),
    /email mismatch/
  );
});

// ORG-06
test('raw token is not stored anywhere in the database', () => {
  const store = new InMemoryStore();
  const svc = new OrganizationsTeams(store);

  const org = svc.createOrg('owner', 'Test Org');
  const orgId = org.body.id;

  const inviteResult = svc.invite('owner', orgId, 'user@example.com', 'member');
  const rawToken = inviteResult.body.token;

  // Check that raw token is not in invitations map
  for (const inv of (store as any).invitations.values()) {
    assert.notEqual(inv.token_hash, rawToken);
    // Verify it's actually the hash
    const expectedHash = createHash('sha256').update(rawToken).digest('hex');
    assert.equal(inv.token_hash, expectedHash);
  }
});

test('change_role on non-member fails with not found', () => {
  const svc = createService();

  const org = svc.createOrg('owner', 'Test Org');
  const orgId = org.body.id;

  assert.throws(
    () => svc.changeRole('owner', orgId, 'nonexistent', 'admin'),
    /not found/
  );
});

test('remove_member on non-member fails with not found', () => {
  const svc = createService();

  const org = svc.createOrg('owner', 'Test Org');
  const orgId = org.body.id;

  assert.throws(
    () => svc.removeMember('owner', orgId, 'nonexistent'),
    /not found/
  );
});

test('admin cannot demote owner', () => {
  const svc = createService();

  const org = svc.createOrg('owner', 'Test Org');
  const orgId = org.body.id;

  const inviteResult = svc.invite('owner', orgId, 'admin@example.com', 'admin');
  svc.acceptInvitation('admin@example.com', inviteResult.body.token);

  assert.throws(
    () => svc.changeRole('admin@example.com', orgId, 'owner', 'admin'),
    /forbidden/
  );
});

test('admin cannot promote to owner', () => {
  const svc = createService();

  const org = svc.createOrg('owner', 'Test Org');
  const orgId = org.body.id;

  const inviteResult = svc.invite('owner', orgId, 'admin@example.com', 'admin');
  svc.acceptInvitation('admin@example.com', inviteResult.body.token);

  const inviteResult2 = svc.invite('owner', orgId, 'member@example.com', 'member');
  svc.acceptInvitation('member@example.com', inviteResult2.body.token);

  assert.throws(
    () => svc.changeRole('admin@example.com', orgId, 'member@example.com', 'owner'),
    /forbidden/
  );
});

/**
 * ORG-02 / ORG-03: only an owner grants the owner role: an admin cannot invite an owner, an owner can; with
 * two owners one may demote the other, and the remaining sole owner still cannot leave or be removed.
 * In: an in-memory service. Out: assertions only. Why: the spec's "only an OWNER may grant the owner role,
 * so an org can have several owners and one of them can then leave"; the TypeScript build refused every
 * owner invite and every change to an owner. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: in-memory store only.
 */
// ORG-03
test('only an owner grants owner; one of several owners can step down, the last cannot', () => {
  const svc = createService();
  const orgId = svc.createOrg('owner', 'Test Org').body.id;
  svc.acceptInvitation('admin@example.com', svc.invite('owner', orgId, 'admin@example.com', 'admin').body.token);
  assert.throws(() => svc.invite('admin@example.com', orgId, 'x@example.com', 'owner'), /forbidden/);

  const second = svc.invite('owner', orgId, 'co@example.com', 'owner');
  svc.acceptInvitation('co@example.com', second.body.token);
  assert.throws(() => svc.removeMember('admin@example.com', orgId, 'co@example.com'), /forbidden/);

  assert.equal(svc.changeRole('co@example.com', orgId, 'owner', 'member').body.role, 'member');
  assert.throws(() => svc.changeRole('co@example.com', orgId, 'co@example.com', 'admin'), /last owner protected/);
  assert.throws(() => svc.leaveOrg('co@example.com', orgId), /last owner protected/);
  assert.throws(() => svc.changeRole('co@example.com', orgId, 'owner', 'superuser' as any), /invalid role/);
});

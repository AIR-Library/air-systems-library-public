const { OrganizationsTeams, InMemoryStore } = require('./organizations_teams_javascript.js');
const assert = require('node:assert');
const test = require('node:test');

function makeUser(id, email) {
  return { id, email };
}

// ORG-01
test('a non-member cannot read members of another org (IDOR attempt by id)', () => {
  const store = new InMemoryStore();
  const system = new OrganizationsTeams(store);

  const owner = makeUser(1, 'owner@example.com');
  const result = system.createOrg(owner, 'Org One');
  assert.strictEqual(result.status, 201);
  const orgId = result.body.id;

  const outsider = makeUser(99, 'outsider@example.com');
  const listResult = system.listMembers(outsider, orgId);
  assert.strictEqual(listResult.status, 404);

  const getResult = system.getOrg(outsider, orgId);
  assert.strictEqual(getResult.status, 404);
});

// ORG-02
test('a member cannot invite; an admin can', () => {
  const store = new InMemoryStore();
  const system = new OrganizationsTeams(store);

  const owner = makeUser(1, 'owner@example.com');
  const result = system.createOrg(owner, 'Org Two');
  assert.strictEqual(result.status, 201);
  const orgId = result.body.id;

  const member = makeUser(2, 'member@example.com');
  system.invite(owner, orgId, member.email, 'member');
  const acceptResult = system.acceptInvitation(member, system.invite(owner, orgId, member.email, 'member').body.token);
  assert.strictEqual(acceptResult.status, 201);

  const memberInvite = system.invite(member, orgId, 'new@example.com', 'member');
  assert.strictEqual(memberInvite.status, 403);

  const admin = makeUser(3, 'admin@example.com');
  system.invite(owner, orgId, admin.email, 'admin');
  const adminAccept = system.acceptInvitation(admin, system.invite(owner, orgId, admin.email, 'admin').body.token);
  assert.strictEqual(adminAccept.status, 201);

  const adminInvite = system.invite(admin, orgId, 'new2@example.com', 'member');
  assert.strictEqual(adminInvite.status, 201);
});

// ORG-03
test('an admin cannot remove the owner; the last owner cannot leave', () => {
  const store = new InMemoryStore();
  const system = new OrganizationsTeams(store);

  const owner = makeUser(1, 'owner@example.com');
  const result = system.createOrg(owner, 'Org Three');
  assert.strictEqual(result.status, 201);
  const orgId = result.body.id;

  const admin = makeUser(2, 'admin@example.com');
  const inviteRes = system.invite(owner, orgId, admin.email, 'admin');
  assert.strictEqual(inviteRes.status, 201);
  const adminAccept = system.acceptInvitation(admin, inviteRes.body.token);
  assert.strictEqual(adminAccept.status, 201);

  const removeOwner = system.removeMember(admin, orgId, owner.id);
  assert.strictEqual(removeOwner.status, 403);

  const leaveOwner = system.leaveOrg(owner, orgId);
  assert.strictEqual(leaveOwner.status, 400);
});

// ORG-04
test('an invitation works once; the second use fails', () => {
  const store = new InMemoryStore();
  const system = new OrganizationsTeams(store);

  const owner = makeUser(1, 'owner@example.com');
  const result = system.createOrg(owner, 'Org Four');
  assert.strictEqual(result.status, 201);
  const orgId = result.body.id;

  const inviteRes = system.invite(owner, orgId, 'new@example.com', 'member');
  assert.strictEqual(inviteRes.status, 201);
  const token = inviteRes.body.token;

  const newUser = makeUser(2, 'new@example.com');
  const firstAccept = system.acceptInvitation(newUser, token);
  assert.strictEqual(firstAccept.status, 201);

  const secondAccept = system.acceptInvitation(newUser, token);
  assert.strictEqual(secondAccept.status, 410);
});

// ORG-05
test('an expired invitation fails; accepting with a different email fails', () => {
  const store = new InMemoryStore();
  const system = new OrganizationsTeams(store);

  const owner = makeUser(1, 'owner@example.com');
  const result = system.createOrg(owner, 'Org Five');
  assert.strictEqual(result.status, 201);
  const orgId = result.body.id;

  const inviteRes = system.invite(owner, orgId, 'new@example.com', 'member');
  assert.strictEqual(inviteRes.status, 201);
  const token = inviteRes.body.token;

  const invitation = store.getInvitationByTokenHash(
    require('crypto').createHash('sha256').update(Buffer.from(token, 'hex')).digest('hex')
  );
  invitation.expires_at = new Date(Date.now() - 1000).toISOString();

  const expiredUser = makeUser(2, 'new@example.com');
  const expiredResult = system.acceptInvitation(expiredUser, token);
  assert.strictEqual(expiredResult.status, 410);

  const freshInvite = system.invite(owner, orgId, 'new@example.com', 'member');
  assert.strictEqual(freshInvite.status, 201);
  const freshToken = freshInvite.body.token;

  const wrongEmailUser = makeUser(3, 'wrong@example.com');
  const wrongResult = system.acceptInvitation(wrongEmailUser, freshToken);
  assert.strictEqual(wrongResult.status, 403);
});

// ORG-06
test('the raw token is not stored anywhere in the database', () => {
  const store = new InMemoryStore();
  const system = new OrganizationsTeams(store);

  const owner = makeUser(1, 'owner@example.com');
  const result = system.createOrg(owner, 'Org Six');
  assert.strictEqual(result.status, 201);
  const orgId = result.body.id;

  const inviteRes = system.invite(owner, orgId, 'new@example.com', 'member');
  assert.strictEqual(inviteRes.status, 201);
  const token = inviteRes.body.token;

  for (const invitation of store.invitations.values()) {
    assert.notStrictEqual(invitation.token_hash, token);
    assert.ok(!JSON.stringify(invitation).includes(token));
  }
});
import { createHash, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

type Role = 'owner' | 'admin' | 'member';

interface Organization {
  id: string;
  name: string;
  slug: string;
  created_at: string;
}

interface Membership {
  org_id: string;
  user_id: string;
  role: Role;
  created_at: string;
}

interface Invitation {
  id: string;
  org_id: string;
  email: string;
  role: Role;
  token_hash: string;
  expires_at: string;
  accepted_at: string | null;
  invited_by: string;
  created_at: string;
}

interface Store {
  createOrg(org: Organization): void;
  getOrgById(id: string): Organization | undefined;
  getOrgBySlug(slug: string): Organization | undefined;
  createMembership(membership: Membership): void;
  getMembership(orgId: string, userId: string): Membership | undefined;
  getMemberships(orgId: string): Membership[];
  updateMembershipRole(orgId: string, userId: string, role: Role): boolean;
  deleteMembership(orgId: string, userId: string): boolean;
  countOwners(orgId: string): number;
  createInvitation(invitation: Invitation): void;
  getInvitationByTokenHash(tokenHash: string): Invitation | undefined;
  markInvitationAccepted(invitationId: string, acceptedAt: string): boolean;
}

class InMemoryStore implements Store {
  private orgs = new Map<string, Organization>();
  private orgsBySlug = new Map<string, string>();
  private memberships = new Map<string, Map<string, Membership>>();
  private invitations = new Map<string, Invitation>();
  private invitationsByTokenHash = new Map<string, string>();

  createOrg(org: Organization): void {
    this.orgs.set(org.id, org);
    this.orgsBySlug.set(org.slug, org.id);
    this.memberships.set(org.id, new Map());
  }

  getOrgById(id: string): Organization | undefined {
    return this.orgs.get(id);
  }

  getOrgBySlug(slug: string): Organization | undefined {
    const id = this.orgsBySlug.get(slug);
    return id ? this.orgs.get(id) : undefined;
  }

  createMembership(membership: Membership): void {
    let orgMembers = this.memberships.get(membership.org_id);
    if (!orgMembers) {
      orgMembers = new Map();
      this.memberships.set(membership.org_id, orgMembers);
    }
    orgMembers.set(membership.user_id, membership);
  }

  getMembership(orgId: string, userId: string): Membership | undefined {
    return this.memberships.get(orgId)?.get(userId);
  }

  getMemberships(orgId: string): Membership[] {
    return Array.from(this.memberships.get(orgId)?.values() ?? []);
  }

  updateMembershipRole(orgId: string, userId: string, role: Role): boolean {
    const membership = this.memberships.get(orgId)?.get(userId);
    if (!membership) return false;
    membership.role = role;
    return true;
  }

  deleteMembership(orgId: string, userId: string): boolean {
    return this.memberships.get(orgId)?.delete(userId) ?? false;
  }

  countOwners(orgId: string): number {
    let count = 0;
    for (const m of this.memberships.get(orgId)?.values() ?? []) {
      if (m.role === 'owner') count++;
    }
    return count;
  }

  createInvitation(invitation: Invitation): void {
    this.invitations.set(invitation.id, invitation);
    this.invitationsByTokenHash.set(invitation.token_hash, invitation.id);
  }

  getInvitationByTokenHash(tokenHash: string): Invitation | undefined {
    const id = this.invitationsByTokenHash.get(tokenHash);
    return id ? this.invitations.get(id) : undefined;
  }

  markInvitationAccepted(invitationId: string, acceptedAt: string): boolean {
    const inv = this.invitations.get(invitationId);
    if (!inv || inv.accepted_at !== null) return false;
    inv.accepted_at = acceptedAt;
    return true;
  }
}

class SqlStore implements Store {
  private db: DatabaseSync;

  constructor(dbPath: string = ':memory:') {
    this.db = new DatabaseSync(dbPath);
    this.initSchema();
  }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS organizations (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        slug TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS memberships (
        org_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('owner','admin','member')),
        created_at TEXT NOT NULL,
        PRIMARY KEY (org_id, user_id),
        FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS invitations (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('owner','admin','member')),
        token_hash TEXT UNIQUE NOT NULL,
        expires_at TEXT NOT NULL,
        accepted_at TEXT,
        invited_by TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_invitations_token_hash ON invitations(token_hash);
    `);
  }

  createOrg(org: Organization): void {
    this.db.prepare('INSERT INTO organizations (id, name, slug, created_at) VALUES (?, ?, ?, ?)')
      .run(org.id, org.name, org.slug, org.created_at);
  }

  getOrgById(id: string): Organization | undefined {
    const row = this.db.prepare('SELECT id, name, slug, created_at FROM organizations WHERE id = ?').get(id) as Organization | undefined;
    return row;
  }

  getOrgBySlug(slug: string): Organization | undefined {
    const row = this.db.prepare('SELECT id, name, slug, created_at FROM organizations WHERE slug = ?').get(slug) as Organization | undefined;
    return row;
  }

  createMembership(membership: Membership): void {
    this.db.prepare('INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)')
      .run(membership.org_id, membership.user_id, membership.role, membership.created_at);
  }

  getMembership(orgId: string, userId: string): Membership | undefined {
    const row = this.db.prepare('SELECT org_id, user_id, role, created_at FROM memberships WHERE org_id = ? AND user_id = ?')
      .get(orgId, userId) as Membership | undefined;
    return row;
  }

  getMemberships(orgId: string): Membership[] {
    const rows = this.db.prepare('SELECT org_id, user_id, role, created_at FROM memberships WHERE org_id = ?')
      .all(orgId) as Membership[];
    return rows;
  }

  updateMembershipRole(orgId: string, userId: string, role: Role): boolean {
    const result = this.db.prepare('UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?')
      .run(role, orgId, userId);
    return result.changes > 0;
  }

  deleteMembership(orgId: string, userId: string): boolean {
    const result = this.db.prepare('DELETE FROM memberships WHERE org_id = ? AND user_id = ?')
      .run(orgId, userId);
    return result.changes > 0;
  }

  countOwners(orgId: string): number {
    const row = this.db.prepare('SELECT COUNT(*) as count FROM memberships WHERE org_id = ? AND role = ?')
      .get(orgId, 'owner') as { count: number } | undefined;
    return row?.count ?? 0;
  }

  createInvitation(invitation: Invitation): void {
    this.db.prepare(`
      INSERT INTO invitations (id, org_id, email, role, token_hash, expires_at, accepted_at, invited_by, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      invitation.id,
      invitation.org_id,
      invitation.email,
      invitation.role,
      invitation.token_hash,
      invitation.expires_at,
      invitation.accepted_at,
      invitation.invited_by,
      invitation.created_at
    );
  }

  getInvitationByTokenHash(tokenHash: string): Invitation | undefined {
    const row = this.db.prepare(`
      SELECT id, org_id, email, role, token_hash, expires_at, accepted_at, invited_by, created_at
      FROM invitations WHERE token_hash = ?
    `).get(tokenHash) as Invitation | undefined;
    return row;
  }

  markInvitationAccepted(invitationId: string, acceptedAt: string): boolean {
    const result = this.db.prepare('UPDATE invitations SET accepted_at = ? WHERE id = ? AND accepted_at IS NULL')
      .run(acceptedAt, invitationId);
    return result.changes > 0;
  }

  close(): void {
    this.db.close();
  }
}

function generateId(): string {
  return randomBytes(16).toString('hex');
}

function generateSlug(name: string): string {
  const base = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
  const suffix = randomBytes(4).toString('hex');
  return `${base}-${suffix}`;
}

function addDays(iso: string, days: number): string {
  const d = new Date(iso);
  d.setDate(d.getDate() + days);
  return d.toISOString();
}

function generateToken(): string {
  return randomBytes(32).toString('hex');
}

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

const ROLES: Role[] = ['owner', 'admin', 'member'];

export class OrganizationsTeams {
  private store: Store;
  private now: () => number;

  /**
   * Builds the service over a store.
   *
   * In: the store and an optional clock `now` (epoch milliseconds; default Date.now). Out: the service.
   * Why: the spec requires an injectable clock where time matters (invitation expiry, ORG-05); the test
   * used to replace the global Date. Clock added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: nothing until called.
   */
  constructor(store: Store, now: () => number = () => Date.now()) {
    this.store = store;
    this.now = now;
  }

  /** Current time as an ISO string from the injected clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
  private nowIso(): string {
    return new Date(this.now()).toISOString();
  }

  /** Throws 'invalid role' unless role is owner, admin or member. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
  private assertRole(role: string): void {
    if (!ROLES.includes(role as Role)) {
      throw new Error('invalid role');
    }
  }

  private getMembershipOrThrow(actor: string, orgId: string): Membership {
    const membership = this.store.getMembership(orgId, actor);
    if (!membership) {
      throw new Error('not found');
    }
    return membership;
  }

  private requireRole(membership: Membership, ...allowedRoles: Role[]): void {
    if (!allowedRoles.includes(membership.role)) {
      throw new Error('forbidden');
    }
  }

  private assertNotLastOwner(orgId: string, userId: string): void {
    const ownerCount = this.store.countOwners(orgId);
    if (ownerCount <= 1) {
      const membership = this.store.getMembership(orgId, userId);
      if (membership?.role === 'owner') {
        throw new Error('last owner protected');
      }
    }
  }

  /**
   * Creates an org with the verified user as its owner. In: user, name. Out: 201 with the org.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: created_at from the injected clock. Touches: the store.
   */
  createOrg(user: string, name: string): { status: number; content_type: string; body: any } {
    const orgId = generateId();
    const slug = generateSlug(name);
    const createdAt = this.nowIso();
    const org: Organization = { id: orgId, name, slug, created_at: createdAt };
    const membership: Membership = { org_id: orgId, user_id: user, role: 'owner', created_at: createdAt };

    this.store.createOrg(org);
    this.store.createMembership(membership);

    return { status: 201, content_type: 'application/json', body: org };
  }

  /**
   * Invites an email address into the org; returns the raw token once (only its SHA-256 is stored).
   *
   * In: the verified actor, org id, email and role. Out: 201 {token}. Throws 'not found' for a non-member,
   * 'forbidden' for a member, or for a non-owner granting the owner role.
   * Why: ORG-02; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the spec says ONLY an owner may grant the
   * owner role, so an owner may invite an owner (this used to be refused for everyone). Touches: the store.
   */
  invite(actor: string, orgId: string, email: string, role: Role): { status: number; content_type: string; body: any } {
    const actorMembership = this.getMembershipOrThrow(actor, orgId);
    this.requireRole(actorMembership, 'admin', 'owner');
    this.assertRole(role);

    if (role === 'owner' && actorMembership.role !== 'owner') {
      throw new Error('forbidden');
    }

    const rawToken = generateToken();
    const tokenHash = hashToken(rawToken);
    const invitationId = generateId();
    const createdAt = this.nowIso();
    const expiresAt = addDays(createdAt, 7);

    const invitation: Invitation = {
      id: invitationId,
      org_id: orgId,
      email: email.toLowerCase(),
      role,
      token_hash: tokenHash,
      expires_at: expiresAt,
      accepted_at: null,
      invited_by: actor,
      created_at: createdAt,
    };

    this.store.createInvitation(invitation);

    return { status: 201, content_type: 'application/json', body: { token: rawToken } };
  }

  /**
   * Accepts an invitation for the verified user: the token is looked up by its SHA-256, must be unused and
   * unexpired (on the injected clock) and addressed to this user's email; it is marked used with a conditional
   * write. In: the user (email) and the raw token. Out: 200 with the new membership. Throws 'not found',
   * 'already used', 'expired', 'email mismatch'. Why: ORG-04/05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: expiry uses the injected clock.
   * Touches: the store.
   */
  acceptInvitation(user: string, rawToken: string): { status: number; content_type: string; body: any } {
    const tokenHash = hashToken(rawToken);
    const invitation = this.store.getInvitationByTokenHash(tokenHash);

    if (!invitation) {
      throw new Error('not found');
    }

    if (invitation.accepted_at !== null) {
      throw new Error('already used');
    }

    if (new Date(invitation.expires_at).getTime() < this.now()) {
      throw new Error('expired');
    }

    if (user.toLowerCase() !== invitation.email) {
      throw new Error('email mismatch');
    }

    const acceptedAt = this.nowIso();
    const marked = this.store.markInvitationAccepted(invitation.id, acceptedAt);
    if (!marked) {
      throw new Error('already used');
    }

    const membership: Membership = {
      org_id: invitation.org_id,
      user_id: user,
      role: invitation.role,
      created_at: acceptedAt,
    };

    this.store.createMembership(membership);

    return { status: 200, content_type: 'application/json', body: membership };
  }

  /**
   * Changes an existing member's role.
   *
   * In: the verified actor, org id, target user id and new role. Out: 200 with the updated membership.
   * Throws 'not found' (actor or target not a member), 'forbidden' (member actor, or an admin touching an
   * owner or granting owner), 'last owner protected' (demoting the only owner).
   * Why: ORG-03 and the least-privilege rule; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: an OWNER may
   * now demote another owner while one owner remains (the spec allows several owners, one of whom can then
   * step down); before, nobody could ever change an owner. Touches: the store.
   */
  changeRole(actor: string, orgId: string, userId: string, role: Role): { status: number; content_type: string; body: any } {
    const actorMembership = this.getMembershipOrThrow(actor, orgId);
    this.requireRole(actorMembership, 'admin', 'owner');
    this.assertRole(role);

    const targetMembership = this.store.getMembership(orgId, userId);
    if (!targetMembership) {
      throw new Error('not found');
    }

    if (targetMembership.role === 'owner' && actorMembership.role !== 'owner') {
      throw new Error('forbidden');
    }

    if (actorMembership.role === 'admin' && role === 'owner') {
      throw new Error('forbidden');
    }

    if (targetMembership.role === 'owner' && role !== 'owner') {
      this.assertNotLastOwner(orgId, userId);
    }

    this.store.updateMembershipRole(orgId, userId, role);

    const updated = this.store.getMembership(orgId, userId)!;
    return { status: 200, content_type: 'application/json', body: updated };
  }

  /**
   * Removes an existing member.
   *
   * In: the verified actor, org id and target user id. Out: 204. Throws 'not found', 'forbidden' (member
   * actor, or an admin removing an owner) or 'last owner protected'.
   * Why: ORG-03; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: an owner may remove another owner while one
   * owner remains, matching the other languages; admins still never touch an owner. Touches: the store.
   */
  removeMember(actor: string, orgId: string, userId: string): { status: number; content_type: string; body: any } {
    const actorMembership = this.getMembershipOrThrow(actor, orgId);
    this.requireRole(actorMembership, 'admin', 'owner');

    const targetMembership = this.store.getMembership(orgId, userId);
    if (!targetMembership) {
      throw new Error('not found');
    }

    if (targetMembership.role === 'owner') {
      if (actorMembership.role !== 'owner') {
        throw new Error('forbidden');
      }
      this.assertNotLastOwner(orgId, userId);
    }

    this.store.deleteMembership(orgId, userId);

    return { status: 204, content_type: 'application/json', body: null };
  }

  leaveOrg(user: string, orgId: string): { status: number; content_type: string; body: any } {
    const membership = this.getMembershipOrThrow(user, orgId);

    if (membership.role === 'owner') {
      this.assertNotLastOwner(orgId, user);
    }

    this.store.deleteMembership(orgId, user);

    return { status: 204, content_type: 'application/json', body: null };
  }

  listMembers(actor: string, orgId: string): { status: number; content_type: string; body: any } {
    this.getMembershipOrThrow(actor, orgId);
    const members = this.store.getMemberships(orgId);
    return { status: 200, content_type: 'application/json', body: members };
  }

  getOrg(actor: string, orgId: string): { status: number; content_type: string; body: any } {
    this.getMembershipOrThrow(actor, orgId);
    const org = this.store.getOrgById(orgId);
    if (!org) {
      throw new Error('not found');
    }
    return { status: 200, content_type: 'application/json', body: org };
  }
}

export { InMemoryStore, SqlStore, type Store, type Organization, type Membership, type Invitation, type Role };
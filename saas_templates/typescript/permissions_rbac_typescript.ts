import { performance } from "perf_hooks";

/* ---------- Types & Enums ---------- */
export type Tier = "public" | "member" | "admin" | "owner";

export interface User {
  id: string;
  tier: Tier;
}

export interface AuditEntry {
  timestamp: string; // UTC ISO 8601
  action: string;
  userId?: string;
  endpoint?: string;
  requiredTier?: Tier;
  userTier?: Tier;
  decision?: "PASS" | "FAIL";
  details?: any;
}

/* ---------- In‑Memory DB ---------- */

/** An API key row: a key with an orgId belongs to that org; a key without one is the user's personal key. */
export interface ApiKeyRow {
  userId: string;
  orgId?: string | null;
}

/** A membership row (org_id, user_id, role) as in organizations_teams.md. */
export interface MembershipRow {
  orgId: string;
  userId: string;
  role: "owner" | "admin" | "member";
}

/**
 * The in-memory database behind the RBAC examples.
 *
 * Why changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (RBAC-06/RBAC-07): organizations now have membership
 * rows (org_id, user_id, role) and invitations, API keys may carry an orgId, and transactions are real: the
 * snapshot is a deep copy of every table (the old shallow copy shared the Sets in orgDeployments, so a rolled-back
 * delete stayed deleted), and transactions nest (the org cascade used to open a second transaction per deployment,
 * whose commit threw the outer snapshot away). Touches: process memory only.
 */
class InMemoryDB {
  // Primary tables
  users = new Map<string, User>();
  sessions = new Map<string, { userId: string }>();
  apiKeys = new Map<string, ApiKeyRow>();
  files = new Map<string, { ownerId: string }>();
  preferences = new Map<string, { userId: string }>();

  deployments = new Map<string, { orgId: string }>();
  dnsRecords = new Map<string, { deploymentId: string }>();
  themeConfigs = new Map<string, { deploymentId: string }>();
  deploymentLogs = new Map<string, { deploymentId: string }>();

  organizations = new Map<string, { }>();
  orgDeployments = new Map<string, Set<string>>(); // orgId -> deploymentIds
  memberships = new Map<string, MembershipRow>(); // `${orgId}:${userId}` -> row
  invitations = new Map<string, { orgId: string; email: string }>();

  // Audit log
  auditLog: AuditEntry[] = [];

  private static readonly TABLES = [
    "users", "sessions", "apiKeys", "files", "preferences", "deployments", "dnsRecords", "themeConfigs",
    "deploymentLogs", "organizations", "orgDeployments", "memberships", "invitations", "auditLog",
  ] as const;

  private snapshot: Record<string, unknown> | null = null;
  private depth = 0;

  /**
   * Starts a transaction, or joins the one already open (depth counter). In: nothing. Out: nothing.
   * The outermost call takes a deep copy of every table. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   */
  beginTransaction() {
    if (this.depth === 0) {
      const snap: Record<string, unknown> = {};
      for (const t of InMemoryDB.TABLES) snap[t] = structuredClone((this as any)[t]);
      this.snapshot = snap;
    }
    this.depth++;
  }

  /** Ends one level; the outermost commit drops the snapshot. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
  commitTransaction() {
    if (this.depth === 0) return;
    this.depth--;
    if (this.depth === 0) this.snapshot = null;
  }

  /**
   * Restores every table to the outermost transaction's start and closes the transaction at every level.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   */
  rollbackTransaction() {
    if (this.snapshot) {
      for (const t of InMemoryDB.TABLES) (this as any)[t] = this.snapshot[t];
    }
    this.snapshot = null;
    this.depth = 0;
  }

  /**
   * Runs fn inside a transaction (joining an open one), committing on success and rolling everything back on an
   * error, which is rethrown. In: fn. Out: fn's result. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   */
  inTransaction<T>(fn: () => T): T {
    this.beginTransaction();
    try {
      const out = fn();
      this.commitTransaction();
      return out;
    } catch (e) {
      this.rollbackTransaction();
      throw e;
    }
  }

  /** Adds or replaces a membership row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory. */
  addMembership(orgId: string, userId: string, role: MembershipRow["role"]) {
    this.memberships.set(`${orgId}:${userId}`, { orgId, userId, role });
  }

  /* ---------- Audit ---------- */
  log(entry: AuditEntry) {
    entry.timestamp = new Date().toISOString();
    this.auditLog.push(entry);
  }

  /* ---------- DDL (for reference) ---------- */
  getDDL(): string {
    return `
CREATE TABLE users (id TEXT PRIMARY KEY, tier TEXT NOT NULL);
CREATE TABLE sessions (id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id));
CREATE TABLE api_keys (id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id), org_id TEXT NULL REFERENCES organizations(id));
CREATE TABLE files (id TEXT PRIMARY KEY, owner_id TEXT REFERENCES users(id));
CREATE TABLE preferences (id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id));

CREATE TABLE organizations (id TEXT PRIMARY KEY);
CREATE TABLE memberships (org_id TEXT REFERENCES organizations(id), user_id TEXT REFERENCES users(id),
                          role TEXT CHECK (role IN ('owner','admin','member')), UNIQUE (org_id, user_id));
CREATE TABLE invitations (id TEXT PRIMARY KEY, org_id TEXT REFERENCES organizations(id), email TEXT);
CREATE TABLE org_deployments (org_id TEXT, deployment_id TEXT);

CREATE TABLE deployments (id TEXT PRIMARY KEY, org_id TEXT REFERENCES organizations(id));
CREATE TABLE dns_records (id TEXT PRIMARY KEY, deployment_id TEXT REFERENCES deployments(id));
CREATE TABLE theme_configs (id TEXT PRIMARY KEY, deployment_id TEXT REFERENCES deployments(id));
CREATE TABLE deployment_logs (id TEXT PRIMARY KEY, deployment_id TEXT REFERENCES deployments(id));

CREATE TABLE audit_log (timestamp TEXT, action TEXT, user_id TEXT, endpoint TEXT,
                        required_tier TEXT, user_tier TEXT, decision TEXT, details TEXT);
`;
  }
}

/* ---------- Singleton DB Instance ---------- */
export const db = new InMemoryDB();

/* ---------- Errors ---------- */
export class HttpError extends Error {
  public code: number;
  public error: string;
  constructor(error: string, message: string, code: number) {
    super(message);
    this.error = error;
    this.code = code;
  }
}

/* ---------- Permission Middleware ---------- */
function auditPermissionCheck(
  user: User | null,
  endpoint: string,
  requiredTier: Tier,
  decision: "PASS" | "FAIL"
) {
  db.log({
    action: "permission_check",
    userId: user?.id,
    endpoint,
    requiredTier,
    userTier: user?.tier,
    decision,
  });
}

function requireOwner(currentUser: User | null, endpoint: string): void {
  const start = performance.now();
  if (!currentUser) {
    auditPermissionCheck(null, endpoint, "owner", "FAIL");
    throw new HttpError("authentication_required", "Authentication required", 401);
  }
  if (currentUser.tier !== "owner") {
    auditPermissionCheck(currentUser, endpoint, "owner", "FAIL");
    throw new HttpError("owner_only", "Owner only action", 403);
  }
  auditPermissionCheck(currentUser, endpoint, "owner", "PASS");
  const elapsed = performance.now() - start;
  if (elapsed > 10) console.warn(`Permission check >10ms: ${elapsed}ms`);
}

function requireAdmin(currentUser: User | null, endpoint: string): void {
  const start = performance.now();
  if (!currentUser) {
    auditPermissionCheck(null, endpoint, "admin", "FAIL");
    throw new HttpError("authentication_required", "Authentication required", 401);
  }
  if (!["admin", "owner"].includes(currentUser.tier)) {
    auditPermissionCheck(currentUser, endpoint, "admin", "FAIL");
    throw new HttpError("admin_only", "Admin only action", 403);
  }
  auditPermissionCheck(currentUser, endpoint, "admin", "PASS");
  const elapsed = performance.now() - start;
  if (elapsed > 10) console.warn(`Permission check >10ms: ${elapsed}ms`);
}

function requireAuthenticated(currentUser: User | null, endpoint: string): void {
  const start = performance.now();
  if (!currentUser) {
    auditPermissionCheck(null, endpoint, "public", "FAIL");
    throw new HttpError("authentication_required", "Authentication required", 401);
  }
  auditPermissionCheck(currentUser, endpoint, "public", "PASS");
  const elapsed = performance.now() - start;
  if (elapsed > 10) console.warn(`Permission check >10ms: ${elapsed}ms`);
}

/* ---------- Example Endpoints ---------- */
export function adminCreateUser(currentUser: User | null, newUser: User) {
  requireOwner(currentUser, "adminCreateUser");
  if (db.users.has(newUser.id)) {
    throw new HttpError("conflict", "User already exists", 409);
  }
  db.users.set(newUser.id, newUser);
  return { success: true };
}

export function adminListCustomers(currentUser: User | null) {
  requireAdmin(currentUser, "adminListCustomers");
  // For demo, return all organization IDs
  return Array.from(db.organizations.keys());
}

/* ---------- Cascade Delete Implementations ---------- */

/**
 * Archives a deployment before it is deleted (spec: "archive to S3"). In: the deployment id. Out: nothing; an
 * error aborts and rolls back the whole cascade. The default does nothing; setDeploymentArchiver injects a real
 * one (and lets tests force a failure part-way through a cascade, RBAC-07).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: whatever the injected archiver touches (S3).
 */
let deploymentArchiver: (deploymentId: string) => void = () => {};

/** Replaces the deployment archiver; pass nothing to restore the no-op. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
export function setDeploymentArchiver(fn?: (deploymentId: string) => void) {
  deploymentArchiver = fn ?? (() => {});
}

/**
 * Deletes one user and everything that is theirs, in one transaction: sessions, API keys, files, preferences.
 * In: user id. Out: {success: true}; 404 when the user does not exist. Logs user_deleted_cascade.
 * Why: RBAC-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: runs through inTransaction (rolls back on any error).
 * Touches: the in-memory database.
 */
export function deleteUser(userId: string) {
  const user = db.users.get(userId);
  if (!user) {
    throw new HttpError("not_found", "User not found", 404);
  }
  return db.inTransaction(() => {
    const removeWhere = <V>(table: Map<string, V>, match: (v: V) => boolean): number => {
      let n = 0;
      for (const [id, row] of Array.from(table)) {
        if (match(row)) {
          table.delete(id);
          n++;
        }
      }
      return n;
    };
    const deletedSessions = removeWhere(db.sessions, (s) => s.userId === userId);
    const deletedKeys = removeWhere(db.apiKeys, (k) => k.userId === userId);
    const deletedFiles = removeWhere(db.files, (f) => f.ownerId === userId);
    const deletedPrefs = removeWhere(db.preferences, (p) => p.userId === userId);
    db.users.delete(userId);

    db.log({
      action: "user_deleted_cascade",
      userId,
      details: {
        sessions: deletedSessions,
        keys: deletedKeys,
        files: deletedFiles,
        preferences: deletedPrefs,
      },
    });
    return { success: true };
  });
}

/**
 * The deployment cascade without its own transaction (the caller holds one): DNS records, theme configs and logs
 * deleted, the deployment archived, then deleted. In: deployment id. Out: the counts. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory database and the archiver.
 */
function cascadeDeployment(deploymentId: string) {
  const deployment = db.deployments.get(deploymentId);
  if (!deployment) {
    throw new HttpError("not_found", "Deployment not found", 404);
  }
  const removeWhere = (table: Map<string, { deploymentId: string }>): number => {
    let n = 0;
    for (const [id, row] of Array.from(table)) {
      if (row.deploymentId === deploymentId) {
        table.delete(id);
        n++;
      }
    }
    return n;
  };
  const dns = removeWhere(db.dnsRecords);
  const themes = removeWhere(db.themeConfigs);
  const logs = removeWhere(db.deploymentLogs);
  deploymentArchiver(deploymentId);

  db.orgDeployments.get(deployment.orgId)?.delete(deploymentId);
  db.deployments.delete(deploymentId);

  db.log({
    action: "deployment_deleted_cascade",
    userId: null,
    details: { deploymentId, dns, themes, logs, archived: true },
  });
  return { dns, themes, logs };
}

/**
 * Deletes a deployment and its DNS records, theme configs and logs in one transaction. In: deployment id.
 * Out: {success: true}; 404 when missing. Why: RBAC-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: shares
 * cascadeDeployment with the org cascade. Touches: the in-memory database and the archiver.
 */
export function deleteDeployment(deploymentId: string) {
  if (!db.deployments.has(deploymentId)) {
    throw new HttpError("not_found", "Deployment not found", 404);
  }
  return db.inTransaction(() => {
    cascadeDeployment(deploymentId);
    return { success: true };
  });
}

/**
 * Deletes an organization, by an owner of that org only.
 *
 * In: the verified caller and the org id. Out: {success: true, deleted_items}. Errors: 401 with no caller; 404
 * when the org does not exist or the caller's membership row for it is not 'owner' (a global tier is not enough,
 * and a stranger cannot learn the org exists).
 * Cascade, in one transaction: the org's deployments (each with the deployment cascade), API keys whose orgId is
 * this org, all its invitations and its membership rows, then the org. NEVER a user account, a session or a
 * personal API key (no orgId): users may belong to other orgs, and those memberships are untouched.
 * Logs org_deleted_cascade with {deployments, api_keys, invitations, memberships}.
 * Why: RBAC-06 as amended 2026-11-10 (review on PR 19): this deleted every member's user account and needed no
 * caller at all. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory database and the archiver.
 */
export function deleteOrganization(currentUser: User | null, orgId: string) {
  if (!currentUser) {
    auditPermissionCheck(null, "deleteOrganization", "owner", "FAIL");
    throw new HttpError("authentication_required", "Authentication required", 401);
  }
  const membership = db.memberships.get(`${orgId}:${currentUser.id}`);
  if (!db.organizations.has(orgId) || !membership || membership.role !== "owner") {
    auditPermissionCheck(currentUser, "deleteOrganization", "owner", "FAIL");
    throw new HttpError("not_found", "Organization not found", 404);
  }
  auditPermissionCheck(currentUser, "deleteOrganization", "owner", "PASS");

  return db.inTransaction(() => {
    let deployments = 0;
    for (const [depId, dep] of Array.from(db.deployments)) {
      if (dep.orgId === orgId) {
        cascadeDeployment(depId);
        deployments++;
      }
    }
    db.orgDeployments.delete(orgId);

    let apiKeys = 0;
    for (const [kid, key] of Array.from(db.apiKeys)) {
      if (key.orgId != null && key.orgId === orgId) {
        db.apiKeys.delete(kid);
        apiKeys++;
      }
    }
    let invitations = 0;
    for (const [iid, inv] of Array.from(db.invitations)) {
      if (inv.orgId === orgId) {
        db.invitations.delete(iid);
        invitations++;
      }
    }
    let memberships = 0;
    for (const [mid, m] of Array.from(db.memberships)) {
      if (m.orgId === orgId) {
        db.memberships.delete(mid);
        memberships++;
      }
    }

    db.organizations.delete(orgId);

    const deleted_items = { deployments, api_keys: apiKeys, invitations, memberships };
    db.log({
      action: "org_deleted_cascade",
      userId: currentUser.id,
      details: { orgId, ...deleted_items },
    });
    return { success: true, deleted_items };
  });
}

/* ---------- Exported Middleware for external use ---------- */
export const permissionMiddleware = {
  requireOwner,
  requireAdmin,
  requireAuthenticated,
};
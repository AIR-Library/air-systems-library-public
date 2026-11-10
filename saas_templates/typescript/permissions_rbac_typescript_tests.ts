import { db, permissionMiddleware, HttpError, User, Tier, adminCreateUser, adminListCustomers, deleteUser, deleteDeployment, deleteOrganization, setDeploymentArchiver } from "./permissions_rbac_typescript";
import { performance } from "perf_hooks";

function resetDB() {
  db.users.clear();
  db.sessions.clear();
  db.apiKeys.clear();
  db.files.clear();
  db.preferences.clear();
  db.deployments.clear();
  db.dnsRecords.clear();
  db.themeConfigs.clear();
  db.deploymentLogs.clear();
  db.organizations.clear();
  db.orgDeployments.clear();
  db.memberships.clear();
  db.invitations.clear();
  db.auditLog = [];
  setDeploymentArchiver();
}

/* ---------- Helper to create users ---------- */
function makeUser(id: string, tier: Tier): User {
  const u: User = { id, tier };
  db.users.set(id, u);
  return u;
}

/* ---------- Tests ---------- */
describe("Permission Middleware", () => {
  beforeEach(() => {
    resetDB();
  });

  // RBAC-01
  test("require_owner on non-owner → 403", () => {
    const user = makeUser("u1", "admin");
    expect(() => permissionMiddleware.requireOwner(user, "test")).toThrow(HttpError);
    try {
      permissionMiddleware.requireOwner(user, "test");
    } catch (e) {
      const err = e as HttpError;
      expect(err.code).toBe(403);
      expect(err.error).toBe("owner_only");
    }
  });

  // RBAC-02
  test("require_admin on member → 403", () => {
    const user = makeUser("u2", "member");
    expect(() => permissionMiddleware.requireAdmin(user, "test")).toThrow(HttpError);
    try {
      permissionMiddleware.requireAdmin(user, "test");
    } catch (e) {
      const err = e as HttpError;
      expect(err.code).toBe(403);
      expect(err.error).toBe("admin_only");
    }
  });

  // RBAC-03
  test("require_authenticated on public → 401", () => {
    expect(() => permissionMiddleware.requireAuthenticated(null, "test")).toThrow(HttpError);
    try {
      permissionMiddleware.requireAuthenticated(null, "test");
    } catch (e) {
      const err = e as HttpError;
      expect(err.code).toBe(401);
      expect(err.error).toBe("authentication_required");
    }
  });

  // RBAC-09
  test("tier hierarchy – member cannot do admin actions", () => {
    const member = makeUser("u3", "member");
    expect(() => permissionMiddleware.requireAdmin(member, "adminEndpoint")).toThrow(HttpError);
  });

  // RBAC-09
  test("tier hierarchy – admin cannot do owner actions", () => {
    const admin = makeUser("u4", "admin");
    expect(() => permissionMiddleware.requireOwner(admin, "ownerEndpoint")).toThrow(HttpError);
  });

  // RBAC-10
  test("permission check response time < 10ms", () => {
    const admin = makeUser("u5", "admin");
    const start = performance.now();
    permissionMiddleware.requireAdmin(admin, "fastCheck");
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(10);
  });
});

describe("Cascade Delete", () => {
  beforeEach(() => {
    resetDB();
  });

  // RBAC-04
  test("cascade_delete user → all related records deleted in transaction", () => {
    const user = makeUser("u10", "member");
    // create related records
    db.sessions.set("s1", { userId: "u10" });
    db.apiKeys.set("k1", { userId: "u10" });
    db.files.set("f1", { ownerId: "u10" });
    db.preferences.set("p1", { userId: "u10" });

    const result = deleteUser("u10");
    expect(result.success).toBe(true);
    expect(db.sessions.has("s1")).toBe(false);
    expect(db.apiKeys.has("k1")).toBe(false);
    expect(db.files.has("f1")).toBe(false);
    expect(db.preferences.has("p1")).toBe(false);
    expect(db.users.has("u10")).toBe(false);
  });

  // RBAC-05
  test("cascade_delete deployment → all related records deleted", () => {
    const orgId = "org1";
    db.organizations.set(orgId, {});
    db.deployments.set("d1", { orgId });
    db.dnsRecords.set("dns1", { deploymentId: "d1" });
    db.themeConfigs.set("theme1", { deploymentId: "d1" });
    db.deploymentLogs.set("log1", { deploymentId: "d1" });
    db.orgDeployments.set(orgId, new Set(["d1"]));

    const result = deleteDeployment("d1");
    expect(result.success).toBe(true);
    expect(db.deployments.has("d1")).toBe(false);
    expect(db.dnsRecords.has("dns1")).toBe(false);
    expect(db.themeConfigs.has("theme1")).toBe(false);
    expect(db.deploymentLogs.has("log1")).toBe(false);
    expect(db.orgDeployments.get(orgId)?.has("d1")).toBeFalsy();
  });

  // RBAC-06
  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: rewritten for the RBAC-06 amendment. The old test called
  // deleteOrganization with no caller and asserted that every member's USER ACCOUNT was deleted; the spec now says
  // only an owner of that org may delete it, and user accounts, sessions and personal API keys are never deleted.
  test("cascade_delete org → owner only; org rows deleted; users, sessions and personal keys kept", () => {
    const orgId = "org2";
    db.organizations.set(orgId, {});
    db.organizations.set("org3", {});
    const owner = makeUser("uOwner", "member");
    const admin = makeUser("uA", "admin");
    makeUser("uB", "member");
    const otherOwner = makeUser("uOther", "owner");
    db.addMembership(orgId, "uOwner", "owner");
    db.addMembership(orgId, "uA", "admin");
    db.addMembership(orgId, "uB", "member");
    db.addMembership("org3", "uB", "member");
    db.addMembership("org3", "uOther", "owner");
    db.sessions.set("sB", { userId: "uB" });
    db.apiKeys.set("orgKey", { userId: "uA", orgId });
    db.apiKeys.set("personalKey", { userId: "uB", orgId: null });
    db.apiKeys.set("org3Key", { userId: "uB", orgId: "org3" });
    db.invitations.set("inv1", { orgId, email: "x@example.com" });
    db.invitations.set("inv3", { orgId: "org3", email: "y@example.com" });
    db.deployments.set("depA", { orgId });
    db.deployments.set("depB", { orgId });
    db.deployments.set("dep3", { orgId: "org3" });
    db.orgDeployments.set(orgId, new Set(["depA", "depB"]));
    db.dnsRecords.set("dnsA", { deploymentId: "depA" });
    db.dnsRecords.set("dnsB", { deploymentId: "depB" });
    db.dnsRecords.set("dns3", { deploymentId: "dep3" });

    // Another org's owner (even with the global "owner" tier), an admin of this org, and nobody: refused.
    for (const caller of [otherOwner, admin]) {
      try {
        deleteOrganization(caller, orgId);
        throw new Error("expected 404");
      } catch (e) {
        expect((e as HttpError).code).toBe(404);
      }
    }
    expect(() => deleteOrganization(null, orgId)).toThrow(HttpError);
    expect(db.organizations.has(orgId)).toBe(true);
    expect(db.deployments.has("depA")).toBe(true);

    const result = deleteOrganization(owner, orgId);
    expect(result.success).toBe(true);
    expect(result.deleted_items).toEqual({ deployments: 2, api_keys: 1, invitations: 1, memberships: 3 });
    expect(db.organizations.has(orgId)).toBe(false);
    expect(db.deployments.has("depA")).toBe(false);
    expect(db.deployments.has("depB")).toBe(false);
    expect(db.dnsRecords.has("dnsA")).toBe(false);
    expect(db.dnsRecords.has("dnsB")).toBe(false);
    expect(db.apiKeys.has("orgKey")).toBe(false);
    expect(db.invitations.has("inv1")).toBe(false);
    expect([...db.memberships.values()].some((m) => m.orgId === orgId)).toBe(false);
    // kept: every user account, their sessions, personal keys, and everything of org3
    for (const uid of ["uOwner", "uA", "uB", "uOther"]) expect(db.users.has(uid)).toBe(true);
    expect(db.sessions.has("sB")).toBe(true);
    expect(db.apiKeys.has("personalKey")).toBe(true);
    expect(db.apiKeys.has("org3Key")).toBe(true);
    expect(db.memberships.get("org3:uB")).toEqual({ orgId: "org3", userId: "uB", role: "member" });
    expect(db.invitations.has("inv3")).toBe(true);
    expect(db.deployments.has("dep3")).toBe(true);
    expect(db.dnsRecords.has("dns3")).toBe(true);
    const log = db.auditLog.find((e) => e.action === "org_deleted_cascade");
    expect(log?.details).toMatchObject({ orgId, deployments: 2, api_keys: 1, invitations: 1, memberships: 3 });
  });

  // RBAC-07
  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the old test ran its own copy of a delete loop and its own
  // rollback, so it never exercised the library. This one makes the library's org cascade fail part-way (the
  // archiver throws on the second deployment, after the first deployment and its DNS rows were deleted) and
  // checks that nothing at all was deleted.
  test("cascade on error → rollback (no partial deletes)", () => {
    const orgId = "orgErr";
    db.organizations.set(orgId, {});
    const owner = makeUser("uErr", "member");
    db.addMembership(orgId, "uErr", "owner");
    db.apiKeys.set("kErr", { userId: "uErr", orgId });
    db.invitations.set("iErr", { orgId, email: "e@example.com" });
    db.deployments.set("d1", { orgId });
    db.deployments.set("d2", { orgId });
    db.orgDeployments.set(orgId, new Set(["d1", "d2"]));
    db.dnsRecords.set("dns1", { deploymentId: "d1" });
    db.dnsRecords.set("dns2", { deploymentId: "d2" });
    const logLength = db.auditLog.length;
    setDeploymentArchiver((id) => {
      if (id === "d2") throw new Error("S3 unavailable");
    });

    expect(() => deleteOrganization(owner, orgId)).toThrow("S3 unavailable");

    expect(db.organizations.has(orgId)).toBe(true);
    expect(db.deployments.has("d1")).toBe(true);
    expect(db.deployments.has("d2")).toBe(true);
    expect(db.dnsRecords.has("dns1")).toBe(true);
    expect(db.dnsRecords.has("dns2")).toBe(true);
    expect(db.orgDeployments.get(orgId)?.has("d1")).toBe(true);
    expect(db.apiKeys.has("kErr")).toBe(true);
    expect(db.invitations.has("iErr")).toBe(true);
    expect(db.memberships.get(`${orgId}:uErr`)?.role).toBe("owner");
    expect(db.auditLog.some((e, i) => i >= logLength && e.action === "deployment_deleted_cascade")).toBe(false);

    // deleteDeployment rolls back the same way on its own.
    setDeploymentArchiver(() => { throw new Error("S3 unavailable"); });
    expect(() => deleteDeployment("d1")).toThrow("S3 unavailable");
    expect(db.dnsRecords.has("dns1")).toBe(true);
  });
});

describe("Audit Logging", () => {
  beforeEach(() => {
    resetDB();
  });

  // RBAC-08
  test("permission audit logged → queries show who accessed what", () => {
    const admin = makeUser("admin1", "admin");
    try {
      permissionMiddleware.requireAdmin(admin, "adminListCustomers");
    } catch (_) {}
    const entry = db.auditLog.find(e => e.action === "permission_check" && e.userId === "admin1");
    expect(entry).toBeDefined();
    expect(entry?.endpoint).toBe("adminListCustomers");
    expect(entry?.requiredTier).toBe("admin");
    expect(entry?.decision).toBe("PASS");
  });
});

/* ---------- Run tests ---------- */
if (require.main === module) {
  // Simple runner for environments without jest
  const { run } = require("jest");
  run();
}
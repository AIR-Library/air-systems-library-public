using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using AOI.Rbac;
using Xunit;

namespace AOI.Rbac.Tests
{
    public class RbacTests
    {
        private readonly RbacSystem _rbac;
        private readonly AuditLogStore _auditLog;

        public RbacTests()
        {
            _auditLog = new AuditLogStore();
            _rbac = new RbacSystem(_auditLog);
        }

        private User CreateUser(Tier tier, Guid? orgId = null)
            => new User { Id = Guid.NewGuid(), Email = $"user_{tier}@test.com", Tier = tier, OrganizationId = orgId };

        // ─────────────────────────────────────────────────────────────────────
        // TEST 1: require_owner on non-owner → 403
        // ─────────────────────────────────────────────────────────────────────
        // RBAC-01
        [Fact]
        public void RequireOwner_NonOwner_Returns403()
        {
            var admin = CreateUser(Tier.Admin);
            var result = _rbac.Guard.RequireOwner(admin, "/api/admin/create-user");

            Assert.False(result.Allowed);
            Assert.NotNull(result.Error);
            Assert.Equal("owner_only", result.Error!.Error);
            Assert.Equal(403, result.Error.Code);
        }

        [Fact]
        public void RequireOwner_Member_Returns403()
        {
            var member = CreateUser(Tier.Member);
            var result = _rbac.Guard.RequireOwner(member, "/api/admin/create-user");

            Assert.False(result.Allowed);
            Assert.Equal("owner_only", result.Error!.Error);
            Assert.Equal(403, result.Error.Code);
        }

        [Fact]
        public void RequireOwner_Public_Returns403()
        {
            var pub = CreateUser(Tier.Public);
            var result = _rbac.Guard.RequireOwner(pub, "/api/admin/create-user");

            Assert.False(result.Allowed);
            Assert.Equal("owner_only", result.Error!.Error);
            Assert.Equal(403, result.Error.Code);
        }

        [Fact]
        public void RequireOwner_Owner_ReturnsPass()
        {
            var owner = CreateUser(Tier.Owner);
            var result = _rbac.Guard.RequireOwner(owner, "/api/admin/create-user");

            Assert.True(result.Allowed);
            Assert.Null(result.Error);
        }

        [Fact]
        public void RequireOwner_NullUser_Returns401()
        {
            var result = _rbac.Guard.RequireOwner(null, "/api/admin/create-user");

            Assert.False(result.Allowed);
            Assert.Equal("authentication_required", result.Error!.Error);
            Assert.Equal(401, result.Error.Code);
        }

        // ─────────────────────────────────────────────────────────────────────
        // TEST 2: require_admin on member → 403
        // ─────────────────────────────────────────────────────────────────────
        // RBAC-02
        [Fact]
        public void RequireAdmin_Member_Returns403()
        {
            var member = CreateUser(Tier.Member);
            var result = _rbac.Guard.RequireAdmin(member, "/api/admin/list-customers");

            Assert.False(result.Allowed);
            Assert.Equal("admin_only", result.Error!.Error);
            Assert.Equal(403, result.Error.Code);
        }

        [Fact]
        public void RequireAdmin_Public_Returns403()
        {
            var pub = CreateUser(Tier.Public);
            var result = _rbac.Guard.RequireAdmin(pub, "/api/admin/list-customers");

            Assert.False(result.Allowed);
            Assert.Equal("admin_only", result.Error!.Error);
            Assert.Equal(403, result.Error.Code);
        }

        [Fact]
        public void RequireAdmin_Admin_ReturnsPass()
        {
            var admin = CreateUser(Tier.Admin);
            var result = _rbac.Guard.RequireAdmin(admin, "/api/admin/list-customers");

            Assert.True(result.Allowed);
            Assert.Null(result.Error);
        }

        [Fact]
        public void RequireAdmin_Owner_ReturnsPass()
        {
            var owner = CreateUser(Tier.Owner);
            var result = _rbac.Guard.RequireAdmin(owner, "/api/admin/list-customers");

            Assert.True(result.Allowed);
            Assert.Null(result.Error);
        }

        [Fact]
        public void RequireAdmin_NullUser_Returns401()
        {
            var result = _rbac.Guard.RequireAdmin(null, "/api/admin/list-customers");

            Assert.False(result.Allowed);
            Assert.Equal("authentication_required", result.Error!.Error);
            Assert.Equal(401, result.Error.Code);
        }

        // ─────────────────────────────────────────────────────────────────────
        // TEST 3: require_authenticated on public → 401
        // ─────────────────────────────────────────────────────────────────────
        // RBAC-03
        [Fact]
        public void RequireAuthenticated_NullUser_Returns401()
        {
            var result = _rbac.Guard.RequireAuthenticated(null, "/api/profile");

            Assert.False(result.Allowed);
            Assert.Equal("authentication_required", result.Error!.Error);
            Assert.Equal(401, result.Error.Code);
        }

        [Fact]
        public void RequireAuthenticated_PublicUser_ReturnsPass()
        {
            var pub = CreateUser(Tier.Public);
            var result = _rbac.Guard.RequireAuthenticated(pub, "/api/profile");

            Assert.True(result.Allowed);
            Assert.Null(result.Error);
        }

        [Fact]
        public void RequireAuthenticated_Member_ReturnsPass()
        {
            var member = CreateUser(Tier.Member);
            var result = _rbac.Guard.RequireAuthenticated(member, "/api/profile");

            Assert.True(result.Allowed);
        }

        [Fact]
        public void RequireAuthenticated_Admin_ReturnsPass()
        {
            var admin = CreateUser(Tier.Admin);
            var result = _rbac.Guard.RequireAuthenticated(admin, "/api/profile");

            Assert.True(result.Allowed);
        }

        [Fact]
        public void RequireAuthenticated_Owner_ReturnsPass()
        {
            var owner = CreateUser(Tier.Owner);
            var result = _rbac.Guard.RequireAuthenticated(owner, "/api/profile");

            Assert.True(result.Allowed);
        }

        // ─────────────────────────────────────────────────────────────────────
        // TEST 4: cascade_delete user → all related records deleted in transaction
        // ─────────────────────────────────────────────────────────────────────
        // RBAC-04
        [Fact]
        public void CascadeDeleteUser_DeletesAllRelatedRecords()
        {
            var userId = Guid.NewGuid();
            var context = new CascadeDeleteContext
            {
                Sessions = new List<Guid> { Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid() },
                ApiKeys = new List<Guid> { Guid.NewGuid(), Guid.NewGuid() },
                Files = new List<Guid> { Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid() },
                Preferences = new List<string> { "theme", "language", "notifications" }
            };

            var (success, error) = _rbac.CascadeService.DeleteUser(userId, context);

            Assert.True(success);
            Assert.Null(error);
            Assert.Empty(context.Sessions);
            Assert.Empty(context.ApiKeys);
            Assert.Empty(context.Files);
            Assert.Empty(context.Preferences);

            // Verify audit log
            var auditEntries = _auditLog.QueryByAction("user_deleted_cascade");
            Assert.Single(auditEntries);
            var entry = auditEntries[0];
            Assert.Equal(userId, entry.UserId);
            Assert.NotNull(entry.DeletedItems);
            Assert.Equal(3, entry.DeletedItems!["sessions"]);
            Assert.Equal(2, entry.DeletedItems!["keys"]);
            Assert.Equal(4, entry.DeletedItems!["files"]);
            Assert.Equal(3, entry.DeletedItems!["preferences"]);
        }

        [Fact]
        public void CascadeDeleteUser_EmptyContext_Succeeds()
        {
            var userId = Guid.NewGuid();
            var context = new CascadeDeleteContext();

            var (success, error) = _rbac.CascadeService.DeleteUser(userId, context);

            Assert.True(success);
            Assert.Null(error);

            var auditEntries = _auditLog.QueryByAction("user_deleted_cascade");
            Assert.Single(auditEntries);
            Assert.Equal(0, auditEntries[0].DeletedItems!["sessions"]);
        }

        // ─────────────────────────────────────────────────────────────────────
        // TEST 5: cascade_delete deployment → all related records deleted
        // ─────────────────────────────────────────────────────────────────────
        // RBAC-05
        [Fact]
        public void CascadeDeleteDeployment_DeletesAllRelatedRecords()
        {
            var deploymentId = Guid.NewGuid();
            var context = new CascadeDeleteContext
            {
                DnsRecords = new List<string> { "a.example.com", "www.example.com", "api.example.com" },
                ThemeConfigs = new List<string> { "default", "dark" },
                DeploymentLogs = new List<string> { "log1", "log2", "log3", "log4" }
            };

            var (success, error) = _rbac.CascadeService.DeleteDeployment(deploymentId, context);

            Assert.True(success);
            Assert.Null(error);
            Assert.Empty(context.DnsRecords);
            Assert.Empty(context.ThemeConfigs);
            Assert.Empty(context.DeploymentLogs);
            Assert.True(context.ArchivedToS3);

            var auditEntries = _auditLog.QueryByAction("deployment_deleted_cascade");
            Assert.Single(auditEntries);
            var entry = auditEntries[0];
            Assert.Equal(deploymentId.ToString(), entry.DeploymentId);
            Assert.Equal(3, entry.DeletedItems!["dns"]);
            Assert.Equal(2, entry.DeletedItems!["theme_configs"]);
            Assert.Equal(4, entry.DeletedItems!["deployment_logs"]);
            Assert.Equal(1, entry.DeletedItems!["archived_to_s3"]);
        }

        // ─────────────────────────────────────────────────────────────────────
        // TEST 6: cascade_delete org (RBAC-06, amended 2026-11-10)
        // ─────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Builds two orgs: org A (owner, a member who also belongs to org B, two deployments with child rows, one org
        /// key, one invitation) and org B (its own owner and key). Every user also has a personal key and a session.
        /// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
        /// </summary>
        private static (OrgDataStore Store, Guid OrgA, Guid OrgB, User OwnerA, User Shared, User OwnerB) BuildOrgs()
        {
            var store = new OrgDataStore();
            Guid orgA = Guid.NewGuid(), orgB = Guid.NewGuid();
            var ownerA = new User { Id = Guid.NewGuid(), Email = "a@test.com", Tier = Tier.Owner };
            var shared = new User { Id = Guid.NewGuid(), Email = "shared@test.com", Tier = Tier.Member };
            var ownerB = new User { Id = Guid.NewGuid(), Email = "b@test.com", Tier = Tier.Owner };
            store.Users.AddRange(new[] { ownerA, shared, ownerB });
            foreach (var u in store.Users)
            {
                store.Sessions.Add((Guid.NewGuid(), u.Id));
                store.ApiKeys.Add(new OrgApiKey { UserId = u.Id, OrgId = null });
            }
            store.Memberships.Add(new OrgMembership { OrgId = orgA, UserId = ownerA.Id, Role = "owner" });
            store.Memberships.Add(new OrgMembership { OrgId = orgA, UserId = shared.Id, Role = "member" });
            store.Memberships.Add(new OrgMembership { OrgId = orgB, UserId = ownerB.Id, Role = "owner" });
            store.Memberships.Add(new OrgMembership { OrgId = orgB, UserId = shared.Id, Role = "admin" });
            store.ApiKeys.Add(new OrgApiKey { UserId = ownerA.Id, OrgId = orgA });
            store.ApiKeys.Add(new OrgApiKey { UserId = ownerB.Id, OrgId = orgB });
            store.Invitations.Add(new OrgInvitation { OrgId = orgA, Email = "new@test.com" });
            store.Invitations.Add(new OrgInvitation { OrgId = orgB, Email = "other@test.com" });
            for (var i = 0; i < 2; i++)
                store.Deployments.Add(new OrgDeployment
                {
                    OrgId = orgA,
                    Children = new CascadeDeleteContext { DnsRecords = new() { "a" }, ThemeConfigs = new() { "t" }, DeploymentLogs = new() { "l" } }
                });
            store.Deployments.Add(new OrgDeployment { OrgId = orgB });
            return (store, orgA, orgB, ownerA, shared, ownerB);
        }

        /// <summary>
        /// RBAC-06: org B's owner (a global owner tier) gets 404 and nothing changes; org A's owner deletes org A's
        /// deployments (with their child rows), org key, invitations and memberships, while every user, session and
        /// personal key, and the shared member's org-B membership, stay. Rewritten 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP: the old test expected the org cascade to delete user accounts.
        /// </summary>
        // RBAC-06
        [Fact]
        public void CascadeDeleteOrganization_DeletesAllNestedRecords()
        {
            var (store, orgA, orgB, ownerA, shared, ownerB) = BuildOrgs();

            var (refused, notFound) = _rbac.TransactionalService.DeleteOrganizationTransactional(ownerB, orgA, store);
            Assert.False(refused);
            Assert.Equal(404, notFound!.Code);
            Assert.Equal(3, store.Deployments.Count);
            Assert.Equal(4, store.Memberships.Count);

            var (memberTried, memberError) = _rbac.TransactionalService.DeleteOrganizationTransactional(shared, orgA, store);
            Assert.False(memberTried);
            Assert.Equal(404, memberError!.Code);

            var orgADeployments = store.Deployments.Where(d => d.OrgId == orgA).ToList();
            var (success, error) = _rbac.TransactionalService.DeleteOrganizationTransactional(ownerA, orgA, store);

            Assert.True(success);
            Assert.Null(error);
            Assert.DoesNotContain(store.Deployments, d => d.OrgId == orgA);
            Assert.All(orgADeployments, d => Assert.Empty(d.Children.DnsRecords));
            Assert.DoesNotContain(store.ApiKeys, k => k.OrgId == orgA);
            Assert.DoesNotContain(store.Invitations, i => i.OrgId == orgA);
            Assert.DoesNotContain(store.Memberships, m => m.OrgId == orgA);
            // kept: accounts, sessions, personal keys, org B and the shared member's org-B membership
            Assert.Equal(3, store.Users.Count);
            Assert.Equal(3, store.Sessions.Count);
            Assert.Equal(3, store.ApiKeys.Count(k => k.OrgId == null));
            Assert.Contains(store.Memberships, m => m.OrgId == orgB && m.UserId == shared.Id && m.Role == "admin");
            Assert.Contains(store.ApiKeys, k => k.OrgId == orgB);
            Assert.Single(store.Deployments, d => d.OrgId == orgB);
            Assert.Single(store.Invitations, i => i.OrgId == orgB);

            var auditEntries = _auditLog.QueryByAction("org_deleted_cascade");
            Assert.Single(auditEntries);
            var entry = auditEntries[0];
            Assert.Equal(orgA.ToString(), entry.OrganizationId);
            Assert.Equal(2, entry.DeletedItems!["deployments"]);
            Assert.Equal(1, entry.DeletedItems!["api_keys"]);
            Assert.Equal(1, entry.DeletedItems!["invitations"]);
            Assert.Equal(2, entry.DeletedItems!["memberships"]);
            Assert.False(entry.DeletedItems!.ContainsKey("users"));
            Assert.Equal(2, _auditLog.QueryByAction("deployment_deleted_cascade").Count);
        }

        // ─────────────────────────────────────────────────────────────────────
        // TEST 7: cascade on error → rollback (no partial deletes)
        // ─────────────────────────────────────────────────────────────────────
        /// <summary>
        /// RBAC-07 on the real transactional service: the fault hook throws when the cascade reaches "files", after
        /// sessions and keys were already cleared; everything is restored and no audit row remains. Rewritten
        /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the old test exercised a failing service defined in this file,
        /// so it never tested the implementation's rollback.
        /// </summary>
        // RBAC-07
        [Fact]
        public void CascadeDeleteUser_RollbackOnFailure_NoPartialDeletes()
        {
            var userId = Guid.NewGuid();
            var context = new CascadeDeleteContext
            {
                Sessions = new List<Guid> { Guid.NewGuid(), Guid.NewGuid() },
                ApiKeys = new List<Guid> { Guid.NewGuid() },
                Files = new List<Guid> { Guid.NewGuid() },
                Preferences = new List<string> { "theme" },
                BeforeDelete = table => { if (table == "files") throw new InvalidOperationException("Simulated DB failure during cascade"); }
            };

            var (success, error) = _rbac.TransactionalService.DeleteUserTransactional(userId, context);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Equal(500, error!.Code);

            // Verify rollback: context should be restored
            Assert.Equal(2, context.Sessions.Count);
            Assert.Equal(1, context.ApiKeys.Count);
            Assert.Equal(1, context.Files.Count);
            Assert.Equal(1, context.Preferences.Count);
            Assert.Empty(_auditLog.QueryByAction("user_deleted_cascade"));
        }

        /// <summary>RBAC-07 for a deployment: fails at theme_configs after DNS rows were cleared; all restored. Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (real service).</summary>
        [Fact]
        public void CascadeDeleteDeployment_RollbackOnFailure_NoPartialDeletes()
        {
            var deploymentId = Guid.NewGuid();
            var context = new CascadeDeleteContext
            {
                DnsRecords = new List<string> { "a.example.com" },
                ThemeConfigs = new List<string> { "default" },
                DeploymentLogs = new List<string> { "log1" },
                BeforeDelete = table => { if (table == "theme_configs") throw new InvalidOperationException("Simulated DB failure during cascade"); }
            };

            var (success, error) = _rbac.TransactionalService.DeleteDeploymentTransactional(deploymentId, context);

            Assert.False(success);
            Assert.NotNull(error);

            // Verify rollback
            Assert.Single(context.DnsRecords);
            Assert.Single(context.ThemeConfigs);
            Assert.Single(context.DeploymentLogs);
            Assert.False(context.ArchivedToS3);
        }

        /// <summary>
        /// RBAC-07 for an organization: fails at "invitations" after both deployments' rows, the deployments and the org
        /// key were deleted (and two deployment audit rows written); everything, audit included, is restored.
        /// Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (real service, RBAC-06 model).
        /// </summary>
        [Fact]
        public void CascadeDeleteOrganization_RollbackOnFailure_NoPartialDeletes()
        {
            var (store, orgA, _, ownerA, _, _) = BuildOrgs();
            store.BeforeDelete = table => { if (table == "invitations") throw new InvalidOperationException("Simulated DB failure during cascade"); };

            var (success, error) = _rbac.TransactionalService.DeleteOrganizationTransactional(ownerA, orgA, store);

            Assert.False(success);
            Assert.NotNull(error);
            Assert.Equal(500, error!.Code);

            // Verify rollback
            Assert.Equal(2, store.Deployments.Count(d => d.OrgId == orgA));
            Assert.All(store.Deployments.Where(d => d.OrgId == orgA), d => Assert.Single(d.Children.DnsRecords));
            Assert.Single(store.ApiKeys, k => k.OrgId == orgA);
            Assert.Single(store.Invitations, i => i.OrgId == orgA);
            Assert.Equal(2, store.Memberships.Count(m => m.OrgId == orgA));
            Assert.Empty(_auditLog.QueryByAction("deployment_deleted_cascade"));
            Assert.Empty(_auditLog.QueryByAction("org_deleted_cascade"));
        }

        // ─────────────────────────────────────────────────────────────────────
        // TEST 8: permission audit logged → queries show who accessed what
        // ─────────────────────────────────────────────────────────────────────
        // RBAC-08
        [Fact]
        public void PermissionAudit_LogsAllChecks()
        {
            var owner = CreateUser(Tier.Owner);
            var admin = CreateUser(Tier.Admin);
            var member = CreateUser(Tier.Member);

            // Owner passes owner check
            _rbac.Guard.RequireOwner(owner, "/api/admin/create-user");
            // Admin fails owner check
            _rbac.Guard.RequireOwner(admin, "/api/admin/create-user");
            // Member fails admin check
            _rbac.Guard.RequireAdmin(member, "/api/admin/list-customers");
            // Admin passes admin check
            _rbac.Guard.RequireAdmin(admin, "/api/admin/list-customers");
            // Null fails authenticated check
            _rbac.Guard.RequireAuthenticated(null, "/api/profile");
            // Member passes authenticated check
            _rbac.Guard.RequireAuthenticated(member, "/api/profile");

            var allEntries = _auditLog.GetAll();
            Assert.Equal(6, allEntries.Count);

            // Verify PASS entries
            var passEntries = _auditLog.QueryByDecision("PASS");
            Assert.Equal(3, passEntries.Count);

            // Verify FAIL entries
            var failEntries = _auditLog.QueryByDecision("FAIL");
            Assert.Equal(3, failEntries.Count);

            // Verify specific user's audit trail
            var adminEntries = _auditLog.QueryByUserId(admin.Id);
            Assert.Equal(2, adminEntries.Count);
            Assert.Contains(adminEntries, e => e.Decision == "FAIL" && e.RequiredTier == "owner");
            Assert.Contains(adminEntries, e => e.Decision == "PASS" && e.RequiredTier == "admin");

            // Verify action type
            var permissionChecks = _auditLog.QueryByAction("permission_check");
            Assert.Equal(6, permissionChecks.Count);
        }

        [Fact]
        public void PermissionAudit_RecordsEndpointAndTiers()
        {
            var member = CreateUser(Tier.Member);
            _rbac.Guard.RequireAdmin(member, "/api/admin/list-customers");

            var entries = _auditLog.QueryByAction("permission_check");
            Assert.Single(entries);
            var entry = entries[0];
            Assert.Equal("/api/admin/list-customers", entry.Endpoint);
            Assert.Equal("admin", entry.RequiredTier);
            Assert.Equal("Member", entry.UserTier);
            Assert.Equal("FAIL", entry.Decision);
            Assert.Equal(member.Id, entry.UserId);
        }

        [Fact]
        public void PermissionAudit_RecordsPassForForensics()
        {
            var owner = CreateUser(Tier.Owner);
            _rbac.Guard.RequireOwner(owner, "/api/admin/create-user");

            var entries = _auditLog.QueryByAction("permission_check");
            Assert.Single(entries);
            Assert.Equal("PASS", entries[0].Decision);
            Assert.Equal("owner", entries[0].RequiredTier);
            Assert.Equal("Owner", entries[0].UserTier);
        }

        // ─────────────────────────────────────────────────────────────────────
        // TEST 9: tier hierarchy → member cannot do admin actions, admin cannot do owner actions
        // ─────────────────────────────────────────────────────────────────────
        // RBAC-09
        [Fact]
        public void TierHierarchy_MemberCannotDoAdminActions()
        {
            var member = CreateUser(Tier.Member);
            var result = _rbac.Guard.RequireAdmin(member, "/api/admin/list-customers");

            Assert.False(result.Allowed);
            Assert.Equal("admin_only", result.Error!.Error);
            Assert.Equal(403, result.Error.Code);
        }

        // RBAC-09
        [Fact]
        public void TierHierarchy_AdminCannotDoOwnerActions()
        {
            var admin = CreateUser(Tier.Admin);
            var result = _rbac.Guard.RequireOwner(admin, "/api/admin/create-user");

            Assert.False(result.Allowed);
            Assert.Equal("owner_only", result.Error!.Error);
            Assert.Equal(403, result.Error.Code);
        }

        [Fact]
        public void TierHierarchy_PublicCannotDoMemberActions()
        {
            var pub = CreateUser(Tier.Public);
            // Public can authenticate but cannot do admin/owner actions
            var authResult = _rbac.Guard.RequireAuthenticated(pub, "/api/profile");
            Assert.True(authResult.Allowed);

            var adminResult = _rbac.Guard.RequireAdmin(pub, "/api/admin/list-customers");
            Assert.False(adminResult.Allowed);

            var ownerResult = _rbac.Guard.RequireOwner(pub, "/api/admin/create-user");
            Assert.False(ownerResult.Allowed);
        }

        [Fact]
        public void TierHierarchy_AdminCanDoAdminAndLowerActions()
        {
            var admin = CreateUser(Tier.Admin);

            var adminResult = _rbac.Guard.RequireAdmin(admin, "/api/admin/list-customers");
            Assert.True(adminResult.Allowed);

            var authResult = _rbac.Guard.RequireAuthenticated(admin, "/api/profile");
            Assert.True(authResult.Allowed);
        }

        [Fact]
        public void TierHierarchy_OwnerCanDoAllActions()
        {
            var owner = CreateUser(Tier.Owner);

            var ownerResult = _rbac.Guard.RequireOwner(owner, "/api/admin/create-user");
            Assert.True(ownerResult.Allowed);

            var adminResult = _rbac.Guard.RequireAdmin(owner, "/api/admin/list-customers");
            Assert.True(adminResult.Allowed);

            var authResult = _rbac.Guard.RequireAuthenticated(owner, "/api/profile");
            Assert.True(authResult.Allowed);
        }

        [Fact]
        public void TierHierarchy_MemberCanDoAuthenticatedActions()
        {
            var member = CreateUser(Tier.Member);
            var result = _rbac.Guard.RequireAuthenticated(member, "/api/profile");
            Assert.True(result.Allowed);
        }

        // ─────────────────────────────────────────────────────────────────────
        // TEST 10: permission check response time < 10ms → no performance impact
        // ─────────────────────────────────────────────────────────────────────
        // RBAC-10
        [Fact]
        public void PermissionCheck_ResponseTime_Under10ms()
        {
            var owner = CreateUser(Tier.Owner);
            var admin = CreateUser(Tier.Admin);
            var member = CreateUser(Tier.Member);
            var pub = CreateUser(Tier.Public);

            // Warm up
            for (int i = 0; i < 100; i++)
            {
                _rbac.Guard.RequireOwner(owner, "/api/test");
                _rbac.Guard.RequireAdmin(admin, "/api/test");
                _rbac.Guard.RequireAuthenticated(member, "/api/test");
            }

            var sw = Stopwatch.StartNew();
            const int iterations = 1000;

            for (int i = 0; i < iterations; i++)
            {
                _rbac.Guard.RequireOwner(owner, "/api/test");
                _rbac.Guard.RequireAdmin(admin, "/api/test");
                _rbac.Guard.RequireAuthenticated(member, "/api/test");
                _rbac.Guard.RequireOwner(pub, "/api/test");
            }

            sw.Stop();
            var avgMs = sw.Elapsed.TotalMilliseconds / iterations;

            Assert.True(avgMs < 10, $"Average permission check took {avgMs:F3}ms, expected < 10ms");
        }

        [Fact]
        public void PermissionCheck_SingleCheck_Under10ms()
        {
            var owner = CreateUser(Tier.Owner);

            var sw = Stopwatch.StartNew();
            var result = _rbac.Guard.RequireOwner(owner, "/api/admin/create-user");
            sw.Stop();

            Assert.True(sw.Elapsed.TotalMilliseconds < 10,
                $"Single permission check took {sw.Elapsed.TotalMilliseconds:F3}ms, expected < 10ms");
            Assert.True(result.Allowed);
        }

        // ─────────────────────────────────────────────────────────────────────
        // Additional coverage: error response JSON shapes
        // ─────────────────────────────────────────────────────────────────────
        [Fact]
        public void ErrorResponse_OwnerOnly_MatchesSpecJson()
        {
            var error = ErrorResponse.OwnerOnly();
            var json = error.ToJson();
            var doc = JsonDocument.Parse(json);

            Assert.Equal("owner_only", doc.RootElement.GetProperty("Error").GetString());
            Assert.Equal(403, doc.RootElement.GetProperty("Code").GetInt32());
        }

        [Fact]
        public void ErrorResponse_AdminOnly_MatchesSpecJson()
        {
            var error = ErrorResponse.AdminOnly();
            var json = error.ToJson();
            var doc = JsonDocument.Parse(json);

            Assert.Equal("admin_only", doc.RootElement.GetProperty("Error").GetString());
            Assert.Equal(403, doc.RootElement.GetProperty("Code").GetInt32());
        }

        [Fact]
        public void ErrorResponse_AuthenticationRequired_MatchesSpecJson()
        {
            var error = ErrorResponse.AuthenticationRequired();
            var json = error.ToJson();
            var doc = JsonDocument.Parse(json);

            Assert.Equal("authentication_required", doc.RootElement.GetProperty("Error").GetString());
            Assert.Equal(401, doc.RootElement.GetProperty("Code").GetInt32());
        }

        // ─────────────────────────────────────────────────────────────────────
        // Additional: cascade audit log entries
        // ─────────────────────────────────────────────────────────────────────
        [Fact]
        public void CascadeAudit_UserDeleted_LoggedWithCorrectAction()
        {
            var userId = Guid.NewGuid();
            var context = new CascadeDeleteContext
            {
                Sessions = new List<Guid> { Guid.NewGuid() },
                ApiKeys = new List<Guid> { Guid.NewGuid() },
                Files = new List<Guid> { Guid.NewGuid() },
                Preferences = new List<string> { "theme" }
            };

            _rbac.CascadeService.DeleteUser(userId, context);

            var entries = _auditLog.QueryByAction("user_deleted_cascade");
            Assert.Single(entries);
            Assert.Equal(userId, entries[0].UserId);
            Assert.NotNull(entries[0].DeletedItems);
        }

        [Fact]
        public void CascadeAudit_DeploymentDeleted_LoggedWithCorrectAction()
        {
            var deploymentId = Guid.NewGuid();
            var context = new CascadeDeleteContext
            {
                DnsRecords = new List<string> { "a.example.com" },
                ThemeConfigs = new List<string> { "default" },
                DeploymentLogs = new List<string> { "log1" }
            };

            _rbac.CascadeService.DeleteDeployment(deploymentId, context);

            var entries = _auditLog.QueryByAction("deployment_deleted_cascade");
            Assert.Single(entries);
            Assert.Equal(deploymentId.ToString(), entries[0].DeploymentId);
        }

        /// <summary>The org cascade logs org_deleted_cascade with the org id and the caller. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (RBAC-06 model).</summary>
        [Fact]
        public void CascadeAudit_OrgDeleted_LoggedWithCorrectAction()
        {
            var (store, orgA, _, ownerA, _, _) = BuildOrgs();

            _rbac.CascadeService.DeleteOrganization(ownerA, orgA, store);

            var entries = _auditLog.QueryByAction("org_deleted_cascade");
            Assert.Single(entries);
            Assert.Equal(orgA.ToString(), entries[0].OrganizationId);
            Assert.Equal(ownerA.Id, entries[0].UserId);
        }

    }
}
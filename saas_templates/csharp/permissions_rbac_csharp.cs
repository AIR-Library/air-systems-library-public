using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AOI.Rbac
{
    // ─────────────────────────────────────────────────────────────────────────
    // Tier hierarchy: public < member < admin < owner (each level includes lower)
    // ─────────────────────────────────────────────────────────────────────────
    public enum Tier
    {
        Public = 0,
        Member = 1,
        Admin = 2,
        Owner = 3
    }

    public class User
    {
        public Guid Id { get; set; }
        public string Email { get; set; } = string.Empty;
        public Tier Tier { get; set; }
        public Guid? OrganizationId { get; set; }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Error response shapes (must match spec JSON exactly)
    // ─────────────────────────────────────────────────────────────────────────
    public class ErrorResponse
    {
        public string Error { get; set; } = string.Empty;
        public int? Code { get; set; }
        public string? Message { get; set; }

        public static ErrorResponse PermissionDenied(string code, int httpStatus, string? message = null)
            => new ErrorResponse { Error = code, Code = httpStatus, Message = message };

        public static ErrorResponse OwnerOnly()
            => new ErrorResponse { Error = "owner_only", Code = 403, Message = "Owner access required" };

        public static ErrorResponse AdminOnly()
            => new ErrorResponse { Error = "admin_only", Code = 403, Message = "Admin access required" };

        public static ErrorResponse AuthenticationRequired()
            => new ErrorResponse { Error = "authentication_required", Code = 401, Message = "Authentication required" };

        public string ToJson() => JsonSerializer.Serialize(this);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Audit log entry
    // ─────────────────────────────────────────────────────────────────────────
    public class AuditLogEntry
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Action { get; set; } = string.Empty;
        public Guid? UserId { get; set; }
        public string? Endpoint { get; set; }
        public string? RequiredTier { get; set; }
        public string? UserTier { get; set; }
        public string Decision { get; set; } = string.Empty; // "PASS" | "FAIL"
        public Dictionary<string, int>? DeletedItems { get; set; }
        public string? DeploymentId { get; set; }
        public string? OrganizationId { get; set; }
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;

        public string ToJson() => JsonSerializer.Serialize(this);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Audit log store (in-memory, thread-safe)
    // ─────────────────────────────────────────────────────────────────────────
    public class AuditLogStore
    {
        private readonly List<AuditLogEntry> _entries = new();
        private readonly object _lock = new();

        public void Log(AuditLogEntry entry)
        {
            lock (_lock)
            {
                _entries.Add(entry);
            }
        }

        public IReadOnlyList<AuditLogEntry> GetAll()
        {
            lock (_lock)
            {
                return _entries.ToList();
            }
        }

        public IReadOnlyList<AuditLogEntry> QueryByAction(string action)
        {
            lock (_lock)
            {
                return _entries.Where(e => e.Action == action).ToList();
            }
        }

        public IReadOnlyList<AuditLogEntry> QueryByUserId(Guid userId)
        {
            lock (_lock)
            {
                return _entries.Where(e => e.UserId == userId).ToList();
            }
        }

        public IReadOnlyList<AuditLogEntry> QueryByDecision(string decision)
        {
            lock (_lock)
            {
                return _entries.Where(e => e.Decision == decision).ToList();
            }
        }

        public void Clear()
        {
            lock (_lock)
            {
                _entries.Clear();
            }
        }

        /// <summary>The number of entries. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (transaction mark).</summary>
        public int Count
        {
            get { lock (_lock) { return _entries.Count; } }
        }

        /// <summary>
        /// Drops every entry after the first <paramref name="count"/>: the rollback of a failed cascade's audit rows.
        /// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
        /// </summary>
        public void TruncateTo(int count)
        {
            lock (_lock)
            {
                if (count < _entries.Count)
                    _entries.RemoveRange(count, _entries.Count - count);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Permission check result
    // ─────────────────────────────────────────────────────────────────────────
    public class PermissionCheckResult
    {
        public bool Allowed { get; set; }
        public ErrorResponse? Error { get; set; }
        public AuditLogEntry? AuditEntry { get; set; }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Permission middleware / guard
    // ─────────────────────────────────────────────────────────────────────────
    public class PermissionGuard
    {
        private readonly AuditLogStore _auditLog;

        public PermissionGuard(AuditLogStore auditLog)
        {
            _auditLog = auditLog;
        }

        /// <summary>
        /// require_owner: only owner tier passes.
        /// </summary>
        public PermissionCheckResult RequireOwner(User? currentUser, string endpoint)
        {
            var userTier = currentUser?.Tier.ToString() ?? "none";
            var requiredTier = "owner";

            if (currentUser == null)
            {
                var error = ErrorResponse.AuthenticationRequired();
                var audit = new AuditLogEntry
                {
                    Action = "permission_check",
                    UserId = null,
                    Endpoint = endpoint,
                    RequiredTier = requiredTier,
                    UserTier = userTier,
                    Decision = "FAIL"
                };
                _auditLog.Log(audit);
                return new PermissionCheckResult { Allowed = false, Error = error, AuditEntry = audit };
            }

            if (currentUser.Tier != Tier.Owner)
            {
                var error = ErrorResponse.OwnerOnly();
                var audit = new AuditLogEntry
                {
                    Action = "permission_check",
                    UserId = currentUser.Id,
                    Endpoint = endpoint,
                    RequiredTier = requiredTier,
                    UserTier = userTier,
                    Decision = "FAIL"
                };
                _auditLog.Log(audit);
                return new PermissionCheckResult { Allowed = false, Error = error, AuditEntry = audit };
            }

            var passAudit = new AuditLogEntry
            {
                Action = "permission_check",
                UserId = currentUser.Id,
                Endpoint = endpoint,
                RequiredTier = requiredTier,
                UserTier = userTier,
                Decision = "PASS"
            };
            _auditLog.Log(passAudit);
            return new PermissionCheckResult { Allowed = true, AuditEntry = passAudit };
        }

        /// <summary>
        /// require_admin: admin or owner tier passes.
        /// </summary>
        public PermissionCheckResult RequireAdmin(User? currentUser, string endpoint)
        {
            var userTier = currentUser?.Tier.ToString() ?? "none";
            var requiredTier = "admin";

            if (currentUser == null)
            {
                var error = ErrorResponse.AuthenticationRequired();
                var audit = new AuditLogEntry
                {
                    Action = "permission_check",
                    UserId = null,
                    Endpoint = endpoint,
                    RequiredTier = requiredTier,
                    UserTier = userTier,
                    Decision = "FAIL"
                };
                _auditLog.Log(audit);
                return new PermissionCheckResult { Allowed = false, Error = error, AuditEntry = audit };
            }

            if (currentUser.Tier != Tier.Admin && currentUser.Tier != Tier.Owner)
            {
                var error = ErrorResponse.AdminOnly();
                var audit = new AuditLogEntry
                {
                    Action = "permission_check",
                    UserId = currentUser.Id,
                    Endpoint = endpoint,
                    RequiredTier = requiredTier,
                    UserTier = userTier,
                    Decision = "FAIL"
                };
                _auditLog.Log(audit);
                return new PermissionCheckResult { Allowed = false, Error = error, AuditEntry = audit };
            }

            var passAudit = new AuditLogEntry
            {
                Action = "permission_check",
                UserId = currentUser.Id,
                Endpoint = endpoint,
                RequiredTier = requiredTier,
                UserTier = userTier,
                Decision = "PASS"
            };
            _auditLog.Log(passAudit);
            return new PermissionCheckResult { Allowed = true, AuditEntry = passAudit };
        }

        /// <summary>
        /// require_authenticated: any non-null user passes.
        /// </summary>
        public PermissionCheckResult RequireAuthenticated(User? currentUser, string endpoint)
        {
            var userTier = currentUser?.Tier.ToString() ?? "none";
            var requiredTier = "authenticated";

            if (currentUser == null)
            {
                var error = ErrorResponse.AuthenticationRequired();
                var audit = new AuditLogEntry
                {
                    Action = "permission_check",
                    UserId = null,
                    Endpoint = endpoint,
                    RequiredTier = requiredTier,
                    UserTier = userTier,
                    Decision = "FAIL"
                };
                _auditLog.Log(audit);
                return new PermissionCheckResult { Allowed = false, Error = error, AuditEntry = audit };
            }

            var passAudit = new AuditLogEntry
            {
                Action = "permission_check",
                UserId = currentUser.Id,
                Endpoint = endpoint,
                RequiredTier = requiredTier,
                UserTier = userTier,
                Decision = "PASS"
            };
            _auditLog.Log(passAudit);
            return new PermissionCheckResult { Allowed = true, AuditEntry = passAudit };
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Cascade delete context (simulates transactional data store)
    // ─────────────────────────────────────────────────────────────────────────
    /// <summary>
    /// The rows a user or deployment cascade deletes (an in-memory stand-in for the tables).
    /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the organization fields (Deployments, Users, OrgApiKeys,
    /// OrgSessions) were removed with the old org cascade, which deleted user accounts (RBAC-06 forbids it; the org
    /// cascade now works on <see cref="OrgDataStore"/>). <see cref="BeforeDelete"/> is a fault hook: it runs before each
    /// table is deleted, so RBAC-07 can make the real cascade fail part-way. Touches: memory only.
    /// </summary>
    public class CascadeDeleteContext
    {
        public List<Guid> Sessions { get; set; } = new();
        public List<Guid> ApiKeys { get; set; } = new();
        public List<Guid> Files { get; set; } = new();
        public List<string> Preferences { get; set; } = new();
        public List<string> DnsRecords { get; set; } = new();
        public List<string> ThemeConfigs { get; set; } = new();
        public List<string> DeploymentLogs { get; set; } = new();
        public bool ArchivedToS3 { get; set; }

        /// <summary>Called with a table name ("sessions", "api_keys", ...) before that table's rows are deleted; may throw.</summary>
        public Action<string>? BeforeDelete { get; set; }

        /// <summary>A copy of every list and flag (the hook is shared). Used to roll a failed cascade back.</summary>
        public CascadeDeleteContext Snapshot() => new CascadeDeleteContext
        {
            Sessions = new List<Guid>(Sessions),
            ApiKeys = new List<Guid>(ApiKeys),
            Files = new List<Guid>(Files),
            Preferences = new List<string>(Preferences),
            DnsRecords = new List<string>(DnsRecords),
            ThemeConfigs = new List<string>(ThemeConfigs),
            DeploymentLogs = new List<string>(DeploymentLogs),
            ArchivedToS3 = ArchivedToS3,
            BeforeDelete = BeforeDelete
        };

        /// <summary>Puts back every list and flag from <paramref name="snapshot"/>.</summary>
        public void RestoreFrom(CascadeDeleteContext snapshot)
        {
            Sessions = snapshot.Sessions;
            ApiKeys = snapshot.ApiKeys;
            Files = snapshot.Files;
            Preferences = snapshot.Preferences;
            DnsRecords = snapshot.DnsRecords;
            ThemeConfigs = snapshot.ThemeConfigs;
            DeploymentLogs = snapshot.DeploymentLogs;
            ArchivedToS3 = snapshot.ArchivedToS3;
        }
    }

    /// <summary>A membership row (org_id, user_id, role) as in organizations_teams.md. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public class OrgMembership
    {
        public Guid OrgId { get; set; }
        public Guid UserId { get; set; }
        public string Role { get; set; } = "member"; // owner | admin | member
    }

    /// <summary>An API key row. OrgId null = a personal key that belongs to its user. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public class OrgApiKey
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public Guid UserId { get; set; }
        public Guid? OrgId { get; set; }
    }

    /// <summary>An invitation row of an organization. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public class OrgInvitation
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public Guid OrgId { get; set; }
        public string Email { get; set; } = string.Empty;
    }

    /// <summary>A deployment row of an organization, with the rows its own cascade deletes. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public class OrgDeployment
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public Guid OrgId { get; set; }
        public CascadeDeleteContext Children { get; set; } = new();
    }

    /// <summary>
    /// The tables an organization cascade reads and deletes (in-memory). Users and Sessions are here so a test can prove
    /// they are KEPT. <see cref="BeforeDelete"/> is the fault hook for RBAC-07. Added 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP (RBAC-06 amendment). Touches: memory only.
    /// </summary>
    public class OrgDataStore
    {
        public List<User> Users { get; set; } = new();
        public List<(Guid Id, Guid UserId)> Sessions { get; set; } = new();
        public List<OrgMembership> Memberships { get; set; } = new();
        public List<OrgApiKey> ApiKeys { get; set; } = new();
        public List<OrgInvitation> Invitations { get; set; } = new();
        public List<OrgDeployment> Deployments { get; set; } = new();

        /// <summary>Called with a table name before that table's rows are deleted; may throw.</summary>
        public Action<string>? BeforeDelete { get; set; }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Cascade delete service (transactional with rollback)
    // ─────────────────────────────────────────────────────────────────────────
    public class CascadeDeleteService
    {
        private readonly AuditLogStore _auditLog;

        public CascadeDeleteService(AuditLogStore auditLog)
        {
            _auditLog = auditLog;
        }

        /// <summary>
        /// delete_user cascade:
        ///   delete_all_sessions, delete_all_api_keys, delete_all_files, clear_preferences
        ///   Log: audit_log(action="user_deleted_cascade", user_id, deleted_items={sessions: N, keys: M, files: K})
        /// Not transactional by itself (a failure part-way leaves partial deletes); callers use
        /// <see cref="TransactionalCascadeService.DeleteUserTransactional"/>. Changed 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP: calls the context's BeforeDelete hook per table; a no-op catch/rethrow removed.
        /// </summary>
        public (bool Success, ErrorResponse? Error) DeleteUser(Guid userId, CascadeDeleteContext context)
        {
            var sessionsDeleted = context.Sessions.Count;
            var keysDeleted = context.ApiKeys.Count;
            var filesDeleted = context.Files.Count;
            var prefsCleared = context.Preferences.Count;

            context.BeforeDelete?.Invoke("sessions");
            context.Sessions.Clear();
            context.BeforeDelete?.Invoke("api_keys");
            context.ApiKeys.Clear();
            context.BeforeDelete?.Invoke("files");
            context.Files.Clear();
            context.BeforeDelete?.Invoke("preferences");
            context.Preferences.Clear();

            _auditLog.Log(new AuditLogEntry
            {
                Action = "user_deleted_cascade",
                UserId = userId,
                DeletedItems = new Dictionary<string, int>
                {
                    { "sessions", sessionsDeleted },
                    { "keys", keysDeleted },
                    { "files", filesDeleted },
                    { "preferences", prefsCleared }
                }
            });

            return (true, null);
        }

        /// <summary>
        /// delete_deployment cascade:
        ///   delete_all_dns_records, delete_all_theme_configs, delete_all_deployment_logs, archive to S3
        ///   Log: audit_log(action="deployment_deleted_cascade", deployment_id, deleted_items={dns: N, ...})
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: BeforeDelete hook per table; no-op catch removed.
        /// </summary>
        public (bool Success, ErrorResponse? Error) DeleteDeployment(Guid deploymentId, CascadeDeleteContext context)
        {
            var dnsDeleted = context.DnsRecords.Count;
            var themesDeleted = context.ThemeConfigs.Count;
            var logsDeleted = context.DeploymentLogs.Count;

            context.BeforeDelete?.Invoke("dns_records");
            context.DnsRecords.Clear();
            context.BeforeDelete?.Invoke("theme_configs");
            context.ThemeConfigs.Clear();
            context.BeforeDelete?.Invoke("deployment_logs");
            context.DeploymentLogs.Clear();
            context.ArchivedToS3 = true;

            _auditLog.Log(new AuditLogEntry
            {
                Action = "deployment_deleted_cascade",
                DeploymentId = deploymentId.ToString(),
                DeletedItems = new Dictionary<string, int>
                {
                    { "dns", dnsDeleted },
                    { "theme_configs", themesDeleted },
                    { "deployment_logs", logsDeleted },
                    { "archived_to_s3", context.ArchivedToS3 ? 1 : 0 }
                }
            });

            return (true, null);
        }

        /// <summary>
        /// delete_organization cascade (RBAC-06, amended 2026-11-10).
        /// Gate: <paramref name="caller"/> (the verified caller, never a request field) must have a membership row for
        /// <paramref name="orgId"/> with role 'owner'; otherwise 404 not_found, so another org's owner learns nothing
        /// (null caller -> 401). A global owner tier is NOT enough.
        /// Cascade: the org's deployments (each with the deployment cascade), API keys whose org_id is this org, all
        /// its invitations and its membership rows. Never a user account, a session or a personal API key (org_id null),
        /// and never another org's membership. Log: org_deleted_cascade with deleted_items {deployments, api_keys,
        /// invitations, memberships}. Not transactional by itself; see
        /// <see cref="TransactionalCascadeService.DeleteOrganizationTransactional"/>.
        /// Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the old version took no caller and deleted every
        /// member's user account and sessions. Touches: the store and the audit log (memory).
        /// </summary>
        public (bool Success, ErrorResponse? Error) DeleteOrganization(User? caller, Guid orgId, OrgDataStore store)
        {
            if (caller == null)
                return (false, ErrorResponse.AuthenticationRequired());
            if (!store.Memberships.Any(m => m.OrgId == orgId && m.UserId == caller.Id && m.Role == "owner"))
                return (false, ErrorResponse.PermissionDenied("not_found", 404, "Organization not found"));

            var deployments = store.Deployments.Where(d => d.OrgId == orgId).ToList();
            foreach (var dep in deployments)
                DeleteDeployment(dep.Id, dep.Children);
            store.BeforeDelete?.Invoke("deployments");
            store.Deployments.RemoveAll(d => d.OrgId == orgId);

            store.BeforeDelete?.Invoke("api_keys");
            var keys = store.ApiKeys.RemoveAll(k => k.OrgId == orgId);
            store.BeforeDelete?.Invoke("invitations");
            var invitations = store.Invitations.RemoveAll(i => i.OrgId == orgId);
            store.BeforeDelete?.Invoke("memberships");
            var memberships = store.Memberships.RemoveAll(m => m.OrgId == orgId);

            _auditLog.Log(new AuditLogEntry
            {
                Action = "org_deleted_cascade",
                UserId = caller.Id,
                OrganizationId = orgId.ToString(),
                DeletedItems = new Dictionary<string, int>
                {
                    { "deployments", deployments.Count },
                    { "api_keys", keys },
                    { "invitations", invitations },
                    { "memberships", memberships }
                }
            });

            return (true, null);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Transactional cascade wrapper (rollback on error)
    // ─────────────────────────────────────────────────────────────────────────
    /// <summary>
    /// Runs a cascade as one transaction: on any failure every table and the audit log are put back as they were and
    /// a 500 cascade_rollback error is returned (RBAC-07, no partial deletes). Changed 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP: also rolls back audit entries written by the failed cascade, and the org
    /// cascade is the RBAC-06 one. Touches: the given store and the audit log (memory).
    /// </summary>
    public class TransactionalCascadeService
    {
        private readonly CascadeDeleteService _cascadeService;
        private readonly AuditLogStore _auditLog;

        public TransactionalCascadeService(CascadeDeleteService cascadeService, AuditLogStore auditLog)
        {
            _cascadeService = cascadeService;
            _auditLog = auditLog;
        }

        private static ErrorResponse Rollback() =>
            ErrorResponse.PermissionDenied("cascade_rollback", 500, "Cascade delete failed, transaction rolled back");

        /// <summary>delete_user in one transaction. Out: (true, null) or (false, 500 cascade_rollback) with nothing deleted.</summary>
        public (bool Success, ErrorResponse? Error) DeleteUserTransactional(Guid userId, CascadeDeleteContext context)
        {
            var snapshot = context.Snapshot();
            var auditMark = _auditLog.Count;
            try
            {
                return _cascadeService.DeleteUser(userId, context);
            }
            catch (Exception)
            {
                context.RestoreFrom(snapshot);
                _auditLog.TruncateTo(auditMark);
                return (false, Rollback());
            }
        }

        /// <summary>delete_deployment in one transaction. Out: (true, null) or (false, 500 cascade_rollback) with nothing deleted.</summary>
        public (bool Success, ErrorResponse? Error) DeleteDeploymentTransactional(Guid deploymentId, CascadeDeleteContext context)
        {
            var snapshot = context.Snapshot();
            var auditMark = _auditLog.Count;
            try
            {
                return _cascadeService.DeleteDeployment(deploymentId, context);
            }
            catch (Exception)
            {
                context.RestoreFrom(snapshot);
                _auditLog.TruncateTo(auditMark);
                return (false, Rollback());
            }
        }

        /// <summary>
        /// delete_organization (RBAC-06 gate and cascade) in one transaction. Out: (true, null), the gate's 401/404, or
        /// (false, 500 cascade_rollback) with every table, every deployment's rows and the audit log restored.
        /// </summary>
        public (bool Success, ErrorResponse? Error) DeleteOrganizationTransactional(User? caller, Guid orgId, OrgDataStore store)
        {
            var deployments = store.Deployments.ToList();
            var children = deployments.Select(d => d.Children.Snapshot()).ToList();
            var keys = store.ApiKeys.ToList();
            var invitations = store.Invitations.ToList();
            var memberships = store.Memberships.ToList();
            var auditMark = _auditLog.Count;
            try
            {
                return _cascadeService.DeleteOrganization(caller, orgId, store);
            }
            catch (Exception)
            {
                for (var i = 0; i < deployments.Count; i++)
                    deployments[i].Children.RestoreFrom(children[i]);
                store.Deployments = deployments;
                store.ApiKeys = keys;
                store.Invitations = invitations;
                store.Memberships = memberships;
                _auditLog.TruncateTo(auditMark);
                return (false, Rollback());
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RBAC System facade
    // ─────────────────────────────────────────────────────────────────────────
    public class RbacSystem
    {
        public AuditLogStore AuditLog { get; }
        public PermissionGuard Guard { get; }
        public CascadeDeleteService CascadeService { get; }
        public TransactionalCascadeService TransactionalService { get; }

        public RbacSystem()
        {
            AuditLog = new AuditLogStore();
            Guard = new PermissionGuard(AuditLog);
            CascadeService = new CascadeDeleteService(AuditLog);
            TransactionalService = new TransactionalCascadeService(CascadeService, AuditLog);
        }

        public RbacSystem(AuditLogStore auditLog)
        {
            AuditLog = auditLog;
            Guard = new PermissionGuard(auditLog);
            CascadeService = new CascadeDeleteService(auditLog);
            TransactionalService = new TransactionalCascadeService(CascadeService, auditLog);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Database schema (executable DDL)
    // ─────────────────────────────────────────────────────────────────────────
    public static class RbacSchema
    {
        public const string Ddl = @"
-- RBAC & Permissions Schema
-- Tier hierarchy: public(0) < member(1) < admin(2) < owner(3)

CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(255) NOT NULL UNIQUE,
    tier            SMALLINT NOT NULL DEFAULT 0 CHECK (tier IN (0, 1, 2, 3)),
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS organizations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      VARCHAR(512) NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash        VARCHAR(512) NOT NULL,
    name            VARCHAR(255),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS files (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename        VARCHAR(512) NOT NULL,
    storage_path    VARCHAR(1024) NOT NULL,
    size_bytes      BIGINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS preferences (
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key             VARCHAR(255) NOT NULL,
    value           TEXT,
    PRIMARY KEY (user_id, key)
);

CREATE TABLE IF NOT EXISTS deployments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    status          VARCHAR(50) NOT NULL DEFAULT 'pending',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dns_records (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    deployment_id   UUID NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    record_type     VARCHAR(20) NOT NULL,
    hostname        VARCHAR(512) NOT NULL,
    value           VARCHAR(512) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS theme_configs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    deployment_id   UUID NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    theme_name      VARCHAR(255) NOT NULL,
    config_json     JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS deployment_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    deployment_id   UUID NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    level           VARCHAR(20) NOT NULL,
    message         TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action          VARCHAR(100) NOT NULL,
    user_id         UUID,
    endpoint        VARCHAR(512),
    required_tier   VARCHAR(50),
    user_tier       VARCHAR(50),
    decision        VARCHAR(10) NOT NULL CHECK (decision IN ('PASS', 'FAIL')),
    deleted_items   JSONB,
    deployment_id   UUID,
    organization_id UUID,
    timestamp_utc   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_decision ON audit_log(decision);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id);
CREATE INDEX IF NOT EXISTS idx_deployments_org_id ON deployments(organization_id);
CREATE INDEX IF NOT EXISTS idx_dns_deployment_id ON dns_records(deployment_id);
CREATE INDEX IF NOT EXISTS idx_theme_deployment_id ON theme_configs(deployment_id);
CREATE INDEX IF NOT EXISTS idx_logs_deployment_id ON deployment_logs(deployment_id);
";
    }
}
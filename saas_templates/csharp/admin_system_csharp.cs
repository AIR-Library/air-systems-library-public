using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

// DDL (for reference, not executed in this in‑memory implementation)
/*
CREATE TABLE users (
    user_id      UUID PRIMARY KEY,
    email        TEXT UNIQUE NOT NULL,
    name         TEXT NOT NULL,
    tier         TEXT NOT NULL,          -- owner, admin, user
    status       TEXT NOT NULL,          -- active, suspended
    created_at   TIMESTAMP NOT NULL,
    password_hash TEXT,
    csrf_token   TEXT NOT NULL
);

CREATE TABLE customers (
    customer_id   UUID PRIMARY KEY,
    email         TEXT NOT NULL,
    name          TEXT NOT NULL,
    tier          TEXT NOT NULL,
    signup_date   TIMESTAMP NOT NULL,
    invoice_count INT NOT NULL,
    status        TEXT NOT NULL,
    stripe_subscription_id TEXT,
    payment_method TEXT,
    address       TEXT,
    notes         TEXT
);

CREATE TABLE deployments (
    deployment_id UUID PRIMARY KEY,
    customer_id   UUID REFERENCES customers(customer_id),
    domain        TEXT UNIQUE NOT NULL,
    tier          TEXT NOT NULL,
    status        TEXT NOT NULL,          -- draft, live, suspended, archived
    theme_id      UUID,
    published_at  TIMESTAMP,
    suspend_reason TEXT,
    archived_at   TIMESTAMP
);

CREATE TABLE invoices (
    invoice_id     UUID PRIMARY KEY,
    customer_id    UUID REFERENCES customers(customer_id),
    amount         NUMERIC NOT NULL,
    status         TEXT NOT NULL,          -- succeeded, failed, pending
    created_at     TIMESTAMP NOT NULL
);

CREATE TABLE refunds (
    refund_id   UUID PRIMARY KEY,
    invoice_id  UUID NOT NULL,
    amount      NUMERIC NOT NULL,
    reason      TEXT NOT NULL,
    status      TEXT NOT NULL,          -- queued, processed
    created_by  UUID REFERENCES users(user_id),
    created_at  TIMESTAMP NOT NULL
);

CREATE TABLE governance_actions (
    action_id   UUID PRIMARY KEY,
    action_type TEXT NOT NULL,
    actor_id    UUID REFERENCES users(user_id),
    target_resource_id UUID,
    reason      TEXT,
    submitted_at TIMESTAMP NOT NULL,
    status      TEXT NOT NULL,          -- pending, approved, rejected
    approved_by UUID,
    approved_at TIMESTAMP,
    rejection_reason TEXT
);

CREATE TABLE audit_log (
    log_id      UUID PRIMARY KEY,
    timestamp   TIMESTAMP NOT NULL,
    actor_id    UUID REFERENCES users(user_id),
    action      TEXT NOT NULL,
    resource_type TEXT,
    resource_id UUID,
    old_value   TEXT,
    new_value   TEXT,
    reason      TEXT
);
*/

namespace AdminSystem
{
    // Enums
    public enum Role { Owner, Admin, User }
    public enum DeploymentStatus { Draft, Live, Suspended, Archived }

    // Models
    public class User
    {
        public Guid UserId { get; set; } = Guid.NewGuid();
        public string Email { get; set; }
        public string Name { get; set; }
        public Role Tier { get; set; }
        public string Status { get; set; } = "active";
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public string CsrfToken { get; set; } = Guid.NewGuid().ToString("N");
    }

    public class Customer
    {
        public Guid CustomerId { get; set; } = Guid.NewGuid();
        public string Email { get; set; }
        public string Name { get; set; }
        public Role Tier { get; set; }
        public DateTime SignupDate { get; set; } = DateTime.UtcNow;
        public int InvoiceCount { get; set; } = 0;
        public string Status { get; set; } = "active";
        public string StripeSubscriptionId { get; set; }
        public string PaymentMethod { get; set; }
        public string Address { get; set; }
        public string Notes { get; set; }
    }

    public class Deployment
    {
        public Guid DeploymentId { get; set; } = Guid.NewGuid();
        public Guid CustomerId { get; set; }
        public string Domain { get; set; }
        public Role Tier { get; set; }
        public DeploymentStatus Status { get; set; } = DeploymentStatus.Draft;
        public Guid ThemeId { get; set; }
        public DateTime? PublishedAt { get; set; }
        public string SuspendReason { get; set; }
        public DateTime? ArchivedAt { get; set; }
    }

    public class Invoice
    {
        public Guid InvoiceId { get; set; } = Guid.NewGuid();
        public Guid CustomerId { get; set; }
        public decimal Amount { get; set; }
        public string Status { get; set; } = "succeeded";
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    public class Refund
    {
        public Guid RefundId { get; set; } = Guid.NewGuid();
        public Guid InvoiceId { get; set; }
        public decimal Amount { get; set; }
        public string Reason { get; set; }
        public string Status { get; set; } = "queued";
        public Guid CreatedBy { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    public class GovernanceAction
    {
        public Guid ActionId { get; set; } = Guid.NewGuid();
        public string ActionType { get; set; }
        public Guid ActorId { get; set; }
        public Guid TargetResourceId { get; set; }
        public string Reason { get; set; }
        public DateTime SubmittedAt { get; set; } = DateTime.UtcNow;
        public string Status { get; set; } = "pending"; // pending, approved, rejected
        public Guid? ApprovedBy { get; set; }
        public DateTime? ApprovedAt { get; set; }
        public string RejectionReason { get; set; }
    }

    public class AuditLogEntry
    {
        public Guid LogId { get; set; } = Guid.NewGuid();
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public Guid ActorId { get; set; }
        public string Action { get; set; }
        public string ResourceType { get; set; }
        public Guid? ResourceId { get; set; }
        public string OldValue { get; set; }
        public string NewValue { get; set; }
        public string Reason { get; set; }
    }

    // In‑memory "database"
    public static class Database
    {
        public static List<User> Users = new List<User>();
        public static List<Customer> Customers = new List<Customer>();
        public static List<Deployment> Deployments = new List<Deployment>();
        public static List<Invoice> Invoices = new List<Invoice>();
        public static List<Refund> Refunds = new List<Refund>();
        public static List<GovernanceAction> GovernanceActions = new List<GovernanceAction>();
        public static List<AuditLogEntry> AuditLog = new List<AuditLogEntry>();
    }

    // Auth context (simplified)
    public static class AuthContext
    {
        public static User CurrentUser { get; set; }
    }

    // CSRF validation (per-user token)
    public static class CsrfValidator
    {
        public static void Verify(string token)
        {
            if (AuthContext.CurrentUser == null)
                throw new ApiException("unauthorized", "No authenticated user");

            if (string.IsNullOrWhiteSpace(token) || token != AuthContext.CurrentUser.CsrfToken)
                throw new ApiException("csrf_invalid", "Invalid CSRF token");
        }

        public static string GenerateToken(User user)
        {
            user.CsrfToken = Guid.NewGuid().ToString("N");
            return user.CsrfToken;
        }
    }

    // Validation helpers
    public static class Validation
    {
        private static readonly Regex EmailRegex = new Regex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.Compiled);

        public static void ValidateEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email) || !EmailRegex.IsMatch(email))
                throw new ApiException("invalid_email", "Email format is invalid");
        }

        public static void ValidateName(string name)
        {
            if (string.IsNullOrWhiteSpace(name) || name.Length > 100)
                throw new ApiException("invalid_name", "Name must be 1-100 characters");
        }

        public static void ValidateTier(string tier, bool allowOwner = false)
        {
            if (!Enum.TryParse<Role>(tier, true, out var role))
                throw new ApiException("invalid_tier", "Tier is not recognized");

            if (!allowOwner && role == Role.Owner)
                throw new ApiException("invalid_tier", "Owner tier cannot be assigned via this operation");
        }

        public static void ValidatePositiveAmount(decimal amount)
        {
            if (amount <= 0)
                throw new ApiException("invalid_amount", "Amount must be positive");
        }
    }

    // Audit logging
    public static class AuditLogger
    {
        public static void Log(string action, Guid actorId, string resourceType = null,
            Guid? resourceId = null, string oldValue = null, string newValue = null, string reason = null)
        {
            Database.AuditLog.Add(new AuditLogEntry
            {
                ActorId = actorId,
                Action = action,
                ResourceType = resourceType,
                ResourceId = resourceId,
                OldValue = oldValue,
                NewValue = newValue,
                Reason = reason
            });
        }
    }

    // Mock Stripe client
    public static class StripeClient
    {
        public static void UpdateSubscription(string subscriptionId, string priceId)
        {
            // In real implementation this would call Stripe API.
            // Here we just simulate success.
            if (string.IsNullOrWhiteSpace(subscriptionId) || string.IsNullOrWhiteSpace(priceId))
                throw new ApiException("stripe_error", "Invalid Stripe parameters");
        }
    }

    // Safety flags
    public static class SafetyFlags
    {
        public static bool CanPublish { get; set; } = true;
    }

    // API exception
    public class ApiException : Exception
    {
        public string Code { get; }
        public ApiException(string code, string message) : base(message) => Code = code;
    }

    // Response wrappers
    public class SuccessResponse
    {
        public bool Success { get; set; } = true;
    }

    public class ErrorResponse
    {
        public string Error { get; set; }
        public string Message { get; set; }
    }

    // Admin controller
    public class AdminController
    {
        // ---------- USERS ----------
        public object CreateUser(string csrfToken, string email, string name, string tier, bool notify)
        {
            CsrfValidator.Verify(csrfToken);
            RequireOwner();

            Validation.ValidateEmail(email);
            Validation.ValidateName(name);
            Validation.ValidateTier(tier, allowOwner: false); // Cannot create Owner via API
            var role = (Role)Enum.Parse(typeof(Role), tier, true);

            if (Database.Users.Any(u => u.Email.Equals(email, StringComparison.OrdinalIgnoreCase)))
                throw new ApiException("email_exists", "Email already exists");

            var user = new User
            {
                Email = email,
                Name = name,
                Tier = role
            };

            AuditLogger.Log("user_created", AuthContext.CurrentUser.UserId,
                resourceType: "user", resourceId: user.UserId,
                newValue: $"email={email},tier={tier}");

            Database.Users.Add(user);

            // Simulate invite email / one‑time password
            if (notify)
            {
                // Email sending omitted.
            }

            return new
            {
                success = true,
                user_id = user.UserId,
                email = user.Email,
                tier = user.Tier.ToString(),
                created_at = user.CreatedAt
            };
        }

        public object ResetPassword(string csrfToken, Guid userId)
        {
            CsrfValidator.Verify(csrfToken);
            RequireOwner();

            var target = Database.Users.FirstOrDefault(u => u.UserId == userId)
                ?? throw new ApiException("user_not_found", "User does not exist");

            // Check last active owner FIRST (more specific protection)
            if (IsLastActiveOwner(target))
                throw new ApiException("cannot_reset_last_owner", "Cannot reset password of last active owner");

            if (target.UserId == AuthContext.CurrentUser.UserId)
                throw new ApiException("cannot_reset_own_password", "Cannot reset own password");

            AuditLogger.Log("password_reset_initiated", AuthContext.CurrentUser.UserId,
                resourceType: "user", resourceId: target.UserId);

            // Simulate token generation and email
            // Omitted.

            return new { success = true, status = "reset_email_sent" };
        }

        public object ChangeUserRole(string csrfToken, Guid userId, string newTier)
        {
            CsrfValidator.Verify(csrfToken);
            RequireOwner();

            Validation.ValidateTier(newTier, allowOwner: false); // Cannot promote to Owner via API
            var newRole = (Role)Enum.Parse(typeof(Role), newTier, true);

            var target = Database.Users.FirstOrDefault(u => u.UserId == userId)
                ?? throw new ApiException("user_not_found", "User does not exist");

            // Check last active owner FIRST (more specific protection)
            if (IsLastActiveOwner(target) && newRole != Role.Owner)
                throw new ApiException("cannot_demote_last_owner", "Cannot demote last active owner");

            if (target.UserId == AuthContext.CurrentUser.UserId)
                throw new ApiException("cannot_change_own_role", "Cannot change own role");

            var oldTier = target.Tier.ToString();

            AuditLogger.Log("role_changed", AuthContext.CurrentUser.UserId,
                resourceType: "user", resourceId: target.UserId,
                oldValue: oldTier, newValue: newTier);

            target.Tier = newRole;

            return new
            {
                success = true,
                user_id = target.UserId,
                old_tier = oldTier,
                new_tier = newTier
            };
        }

        public object SuspendUser(string csrfToken, Guid userId, string reason)
        {
            CsrfValidator.Verify(csrfToken);
            RequireOwner();

            var target = Database.Users.FirstOrDefault(u => u.UserId == userId)
                ?? throw new ApiException("user_not_found", "User does not exist");

            // Check last active owner FIRST (more specific protection)
            if (IsLastActiveOwner(target))
                throw new ApiException("cannot_suspend_last_owner", "Cannot suspend last active owner");

            if (target.UserId == AuthContext.CurrentUser.UserId)
                throw new ApiException("cannot_suspend_yourself", "Cannot suspend yourself");

            AuditLogger.Log("user_suspended", AuthContext.CurrentUser.UserId,
                resourceType: "user", resourceId: target.UserId,
                reason: reason, oldValue: target.Status, newValue: "suspended");

            target.Status = "suspended";

            return new { success = true, user_id = target.UserId, suspended = true };
        }

        // ---------- CUSTOMERS ----------
        public object ListCustomers(string csrfToken, int page = 1, int pageSize = 20)
        {
            CsrfValidator.Verify(csrfToken);
            RequireAdminOrOwner();

            var skip = (page - 1) * pageSize;
            var items = Database.Customers.Skip(skip).Take(pageSize).Select(c => (object)new
            {
                customer_id = c.CustomerId,
                email = c.Email,
                name = c.Name,
                tier = c.Tier.ToString(),
                signup_date = c.SignupDate,
                invoice_count = c.InvoiceCount,
                status = c.Status
            }).ToList();

            return items;
        }

        public object GetCustomerDetail(string csrfToken, Guid customerId)
        {
            CsrfValidator.Verify(csrfToken);
            RequireAdminOrOwner();

            var c = Database.Customers.FirstOrDefault(x => x.CustomerId == customerId)
                ?? throw new ApiException("customer_not_found", "Customer does not exist");

            return new
            {
                customer_id = c.CustomerId,
                email = c.Email,
                name = c.Name,
                tier = c.Tier.ToString(),
                subscription_status = c.Status,
                payment_method = c.PaymentMethod,
                address = c.Address,
                notes = c.Notes
            };
        }

        public object ChangeCustomerPlan(string csrfToken, Guid customerId, string newTier)
        {
            CsrfValidator.Verify(csrfToken);
            RequireOwner();

            Validation.ValidateTier(newTier, allowOwner: false); // Customers cannot be Owner tier
            var newRole = (Role)Enum.Parse(typeof(Role), newTier, true);

            var cust = Database.Customers.FirstOrDefault(c => c.CustomerId == customerId)
                ?? throw new ApiException("customer_not_found", "Customer does not exist");

            var oldTier = cust.Tier.ToString();

            // Simulate Stripe call
            var priceId = $"price_{newTier.ToLower()}";
            StripeClient.UpdateSubscription(cust.StripeSubscriptionId, priceId);

            AuditLogger.Log("plan_changed", AuthContext.CurrentUser.UserId,
                resourceType: "customer", resourceId: cust.CustomerId,
                oldValue: oldTier, newValue: newTier);

            cust.Tier = newRole;

            return new
            {
                success = true,
                customer_id = cust.CustomerId,
                old_tier = oldTier,
                new_tier = newTier,
                effective_date = DateTime.UtcNow
            };
        }

        public object QueueRefund(string csrfToken, Guid invoiceId, decimal amount, string reason)
        {
            CsrfValidator.Verify(csrfToken);
            RequireOwner();

            Validation.ValidatePositiveAmount(amount);

            var invoice = Database.Invoices.FirstOrDefault(i => i.InvoiceId == invoiceId)
                ?? throw new ApiException("invoice_not_found", "Invoice does not exist");

            if (!invoice.Status.Equals("succeeded", StringComparison.OrdinalIgnoreCase))
                throw new ApiException("invalid_invoice_status", "Invoice must have succeeded status");

            // Refunds already queued or made on this invoice count against it: the total never passes what was paid.
            var alreadyRefunded = Database.Refunds
                .Where(r => r.InvoiceId == invoiceId && !r.Status.Equals("rejected", StringComparison.OrdinalIgnoreCase))
                .Sum(r => r.Amount);
            if (alreadyRefunded + amount > invoice.Amount)
                throw new ApiException("refund_exceeds_invoice", "Refunds would exceed the invoice amount");

            var refund = new Refund
            {
                InvoiceId = invoiceId,
                Amount = amount,
                Reason = reason,
                CreatedBy = AuthContext.CurrentUser.UserId
            };

            AuditLogger.Log("refund_queued", AuthContext.CurrentUser.UserId,
                resourceType: "refund", resourceId: refund.RefundId,
                newValue: $"invoice={invoiceId},amount={amount}");

            Database.Refunds.Add(refund);

            return new
            {
                success = true,
                refund_id = refund.RefundId,
                status = refund.Status,
                amount = refund.Amount
            };
        }

        // ---------- DEPLOYMENTS ----------
        public object ListDeployments(string csrfToken, int page = 1, int pageSize = 20)
        {
            CsrfValidator.Verify(csrfToken);
            RequireAdminOrOwner();

            var skip = (page - 1) * pageSize;
            var items = Database.Deployments.Skip(skip).Take(pageSize).Select(d => new
            {
                deployment_id = d.DeploymentId,
                customer_id = d.CustomerId,
                domain = d.Domain,
                tier = d.Tier.ToString(),
                status = d.Status.ToString().ToLower(),
                theme = d.ThemeId,
                published_at = d.PublishedAt
            }).ToList();

            return items;
        }

        public object CreateDeployment(string csrfToken, Guid customerId, string domain, string tier, Guid themeId)
        {
            CsrfValidator.Verify(csrfToken);
            RequireOwner();

            Validation.ValidateTier(tier, allowOwner: false); // Deployments cannot be Owner tier
            var role = (Role)Enum.Parse(typeof(Role), tier, true);

            if (!Database.Customers.Any(c => c.CustomerId == customerId))
                throw new ApiException("customer_not_found", "Customer does not exist");

            if (Database.Deployments.Any(d => d.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase)))
                throw new ApiException("domain_exists", "Domain already registered");

            // Assume theme existence check passes.

            var deployment = new Deployment
            {
                CustomerId = customerId,
                Domain = domain,
                Tier = role,
                ThemeId = themeId
            };

            AuditLogger.Log("deployment_created", AuthContext.CurrentUser.UserId,
                resourceType: "deployment", resourceId: deployment.DeploymentId,
                newValue: $"domain={domain},tier={tier}");

            Database.Deployments.Add(deployment);

            return new
            {
                success = true,
                deployment_id = deployment.DeploymentId,
                domain = deployment.Domain,
                tier = deployment.Tier.ToString()
            };
        }

        public object PublishDeployment(string csrfToken, Guid deploymentId)
        {
            CsrfValidator.Verify(csrfToken);
            RequireOwner();
            if (!SafetyFlags.CanPublish)
                throw new ApiException("publish_blocked", "Publishing is currently disabled");

            var dep = Database.Deployments.FirstOrDefault(d => d.DeploymentId == deploymentId)
                ?? throw new ApiException("deployment_not_found", "Deployment does not exist");

            if (dep.Status != DeploymentStatus.Draft)
                throw new ApiException("invalid_state", "Only draft deployments can be published");

            // Assume domain verification and theme set checks pass.

            AuditLogger.Log("deployment_published", AuthContext.CurrentUser.UserId,
                resourceType: "deployment", resourceId: dep.DeploymentId,
                oldValue: dep.Status.ToString(), newValue: DeploymentStatus.Live.ToString());

            dep.Status = DeploymentStatus.Live;
            dep.PublishedAt = DateTime.UtcNow;

            var publicUrl = $"https://{dep.Domain}";

            return new
            {
                success = true,
                deployment_id = dep.DeploymentId,
                status = "live",
                public_url = publicUrl
            };
        }

        public object SuspendDeployment(string csrfToken, Guid deploymentId, string reason)
        {
            CsrfValidator.Verify(csrfToken);
            RequireOwner();

            var dep = Database.Deployments.FirstOrDefault(d => d.DeploymentId == deploymentId)
                ?? throw new ApiException("deployment_not_found", "Deployment does not exist");

            AuditLogger.Log("deployment_suspended", AuthContext.CurrentUser.UserId,
                resourceType: "deployment", resourceId: dep.DeploymentId,
                oldValue: dep.Status.ToString(), newValue: DeploymentStatus.Suspended.ToString(),
                reason: reason);

            dep.Status = DeploymentStatus.Suspended;
            dep.SuspendReason = reason;

            return new { success = true, deployment_id = dep.DeploymentId, status = "suspended" };
        }

        public object RetireDeployment(string csrfToken, Guid deploymentId)
        {
            CsrfValidator.Verify(csrfToken);
            RequireOwner();

            var dep = Database.Deployments.FirstOrDefault(d => d.DeploymentId == deploymentId)
                ?? throw new ApiException("deployment_not_found", "Deployment does not exist");

            AuditLogger.Log("deployment_archived", AuthContext.CurrentUser.UserId,
                resourceType: "deployment", resourceId: dep.DeploymentId,
                oldValue: dep.Status.ToString(), newValue: DeploymentStatus.Archived.ToString());

            dep.Status = DeploymentStatus.Archived;
            dep.ArchivedAt = DateTime.UtcNow;

            return new { success = true, deployment_id = dep.DeploymentId, status = "archived" };
        }

        // ---------- GOVERNANCE ----------
        public object ListGovernanceActions(string csrfToken, int page = 1, int pageSize = 20)
        {
            CsrfValidator.Verify(csrfToken);
            RequireOwnerOrAdmin();

            var skip = (page - 1) * pageSize;
            var items = Database.GovernanceActions
                .Where(a => a.Status == "pending")
                .Skip(skip).Take(pageSize)
                .Select(a => new
                {
                    action_id = a.ActionId,
                    action_type = a.ActionType,
                    actor = a.ActorId,
                    target_resource_id = a.TargetResourceId,
                    reason = a.Reason,
                    submitted_at = a.SubmittedAt,
                    status = a.Status
                }).ToList();

            return items;
        }

        public object DecideGovernanceAction(string csrfToken, Guid actionId, string decide, string reason = null)
        {
            CsrfValidator.Verify(csrfToken);
            RequireOwner();

            var ga = Database.GovernanceActions.FirstOrDefault(a => a.ActionId == actionId)
                ?? throw new ApiException("action_not_found", "Governance action not found");

            if (ga.Status != "pending")
                throw new ApiException("invalid_state", "Action already decided");

            if (decide.Equals("approve", StringComparison.OrdinalIgnoreCase))
            {
                // Execute original action (simplified: just mark as approved)
                ga.Status = "approved";
                ga.ApprovedBy = AuthContext.CurrentUser.UserId;
                ga.ApprovedAt = DateTime.UtcNow;

                AuditLogger.Log("action_approved", AuthContext.CurrentUser.UserId,
                    resourceType: "governance_action", resourceId: ga.ActionId,
                    newValue: "approved");

                // In a real system we would invoke the original action logic.
                return new { success = true, action_id = ga.ActionId, status = "approved" };
            }
            else if (decide.Equals("reject", StringComparison.OrdinalIgnoreCase))
            {
                if (string.IsNullOrWhiteSpace(reason))
                    throw new ApiException("missing_reason", "Rejection reason required");

                ga.Status = "rejected";
                ga.RejectionReason = reason;

                AuditLogger.Log("action_rejected", AuthContext.CurrentUser.UserId,
                    resourceType: "governance_action", resourceId: ga.ActionId,
                    reason: reason);

                return new { success = true, action_id = ga.ActionId, status = "rejected" };
            }
            else
            {
                throw new ApiException("invalid_decision", "Decision must be approve or reject");
            }
        }

        public object SearchAuditLog(string csrfToken, string actionType = null,
            Guid? resourceId = null, DateTime? start = null, DateTime? end = null,
            int limit = 100, int offset = 0)
        {
            CsrfValidator.Verify(csrfToken);
            RequireOwnerOrAdmin();

            var query = Database.AuditLog.AsQueryable();

            if (!string.IsNullOrWhiteSpace(actionType))
                query = query.Where(l => l.Action == actionType);
            if (resourceId.HasValue)
                query = query.Where(l => l.ResourceId == resourceId);
            if (start.HasValue)
                query = query.Where(l => l.Timestamp >= start.Value);
            if (end.HasValue)
                query = query.Where(l => l.Timestamp <= end.Value);

            var results = query
                .OrderByDescending(l => l.Timestamp)
                .Skip(offset)
                .Take(limit)
                .Select(l => (object)new
                {
                    timestamp = l.Timestamp,
                    actor_id = l.ActorId,
                    action = l.Action,
                    resource_type = l.ResourceType,
                    resource_id = l.ResourceId,
                    old_value = l.OldValue,
                    new_value = l.NewValue,
                    reason = l.Reason
                }).ToList();

            return results;
        }

        // ---------- HELPERS ----------
        private void RequireOwner()
        {
            if (AuthContext.CurrentUser == null || AuthContext.CurrentUser.Tier != Role.Owner)
                throw new ApiException("owner_only", "Owner privileges required");
        }

        private void RequireAdminOrOwner()
        {
            if (AuthContext.CurrentUser == null ||
                !(AuthContext.CurrentUser.Tier == Role.Owner || AuthContext.CurrentUser.Tier == Role.Admin))
                throw new ApiException("admin_or_owner_required", "Admin or Owner privileges required");
        }

        private void RequireOwnerOrAdmin()
        {
            RequireAdminOrOwner(); // same check
        }

        private bool IsLastActiveOwner(User candidate)
        {
            if (candidate.Tier != Role.Owner) return false;
            var activeOwners = Database.Users.Count(u => u.Tier == Role.Owner && u.Status == "active");
            return activeOwners <= 1;
        }
    }
}

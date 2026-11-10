using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
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
    tier          TEXT NOT NULL,          -- plan: solo, team, enterprise
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
    domain_verified BOOLEAN NOT NULL DEFAULT FALSE,
    config        JSON NOT NULL,          -- initialised at create
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

        /// <summary>
        /// SHA-256 (hex) of the latest password-reset or invite token; the raw token only goes to the user's email.
        /// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (reset and invite sent nothing before). Pure data.
        /// </summary>
        public string PasswordTokenHash { get; set; }

        /// <summary>When <see cref="PasswordTokenHash"/> stops working (1 hour after issue).</summary>
        public DateTime? PasswordTokenExpiresAt { get; set; }
    }

    public class Customer
    {
        public Guid CustomerId { get; set; } = Guid.NewGuid();
        public string Email { get; set; }
        public string Name { get; set; }

        /// <summary>
        /// The customer's plan: solo, team or enterprise. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: it was
        /// a staff Role (Owner/Admin/User), so change_plan moved customers to "Admin". Pure data.
        /// </summary>
        public string Tier { get; set; } = "solo";
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

        /// <summary>True once the customer's domain is verified; publish requires it (spec: Check domain_verified). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public bool DomainVerified { get; set; }

        /// <summary>The deployment's configuration, initialised by create (ADMIN-14). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public Dictionary<string, string> Config { get; set; } = new Dictionary<string, string>();
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
        /// <summary>
        /// Checks the CSRF token sent with a write against the current user's token.
        /// Input: the token. Throws ApiException (unauthorized / invalid_csrf) when there is no user or it does not match.
        /// Was a constant shared by everyone; now per user. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
        public static void Verify(string token)
        {
            if (AuthContext.CurrentUser == null)
                throw new ApiException("unauthorized", "No authenticated user");

            // constant-time compare (docs/specs/README.md "Secure by default"; was !=, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
            var expected = AuthContext.CurrentUser.CsrfToken;
            if (string.IsNullOrWhiteSpace(token) || string.IsNullOrEmpty(expected) ||
                !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(token), Encoding.UTF8.GetBytes(expected)))
                throw new ApiException("csrf_invalid", "Invalid CSRF token");
        }

        /// <summary>
        /// Issues a new random CSRF token for <paramref name="user"/> and stores it on the user.
        /// Output: the token to embed in the page. Touches: the in-memory user record. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
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

        /// <summary>
        /// Validates a tier name: it must parse to a defined Role, and Owner only when <paramref name="allowOwner"/>.
        /// Throws ApiException(invalid_tier) otherwise; "99" no longer passes as (Role)99. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
        public static void ValidateTier(string tier, bool allowOwner = false)
        {
            // TryParse accepts any number ("99" -> (Role)99); only a defined role passes (CodeRabbit, PR 18).
            if (!Enum.TryParse<Role>(tier, true, out var role) || !Enum.IsDefined(typeof(Role), role))
                throw new ApiException("invalid_tier", "Tier is not recognized");

            if (!allowOwner && role == Role.Owner)
                throw new ApiException("invalid_tier", "Owner tier cannot be assigned via this operation");
        }

        /// <summary>The customer plans change_plan accepts.</summary>
        public static readonly string[] PlanTiers = { "solo", "team", "enterprise" };

        /// <summary>
        /// Validates a customer plan tier (solo, team, enterprise; case-insensitive) and returns it lower-cased.
        /// Throws ApiException(invalid_tier, 400) otherwise. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: change_plan
        /// validated customer plans as staff roles. Pure.
        /// </summary>
        public static string ValidatePlanTier(string tier)
        {
            var t = tier?.Trim().ToLowerInvariant();
            if (t == null || Array.IndexOf(PlanTiers, t) < 0)
                throw new ApiException("invalid_tier", "Tier is not recognized");
            return t;
        }

        /// <summary>
        /// Refuses an amount of zero or less with ApiException(invalid_amount). Used by refunds. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
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

    /// <summary>
    /// The Stripe calls admin change_plan makes (billing_subscriptions.md flow 2). Production uses
    /// <see cref="StripeNetAdminClient"/>; tests pass a fake, so no test touches the network.
    /// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-12 amendment): the old static mock took a bare price,
    /// which in Stripe adds a second item and bills both plans. Touches: Stripe (network, money) in production.
    /// </summary>
    public interface IAdminStripeClient
    {
        /// <summary>stripe.subscriptions.retrieve: the ids of the subscription's items, in Stripe's order.</summary>
        IReadOnlyList<string> RetrieveSubscriptionItemIds(string subscriptionId);

        /// <summary>stripe.subscriptions.update(subscriptionId, {items: [{id: itemId, price: priceId}], proration_behavior}).</summary>
        void UpdateSubscriptionItem(string subscriptionId, string itemId, string priceId, string prorationBehavior);
    }

    /// <summary>
    /// Stripe.net adapter for <see cref="IAdminStripeClient"/>, keyed by STRIPE_SECRET_KEY (never hard-coded; read on
    /// first use). Provider errors become ApiException(stripe_error, 502). Added 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: environment, Stripe's API (network, money).
    /// </summary>
    public class StripeNetAdminClient : IAdminStripeClient
    {
        private Stripe.StripeClient _client;

        private Stripe.StripeClient Client()
        {
            if (_client != null) return _client;
            var key = Environment.GetEnvironmentVariable("STRIPE_SECRET_KEY");
            if (string.IsNullOrWhiteSpace(key))
                throw new ApiException("stripe_error", "STRIPE_SECRET_KEY not set");
            return _client = new Stripe.StripeClient(key);
        }

        /// <inheritdoc/>
        public IReadOnlyList<string> RetrieveSubscriptionItemIds(string subscriptionId)
        {
            try
            {
                var sub = new Stripe.SubscriptionService(Client()).Get(subscriptionId);
                return sub?.Items?.Data?.Select(i => i.Id).ToList() ?? new List<string>();
            }
            catch (Stripe.StripeException e)
            {
                throw new ApiException("stripe_error", "The payment provider rejected the request: " + e.StripeError?.Code);
            }
        }

        /// <inheritdoc/>
        public void UpdateSubscriptionItem(string subscriptionId, string itemId, string priceId, string prorationBehavior)
        {
            try
            {
                new Stripe.SubscriptionService(Client()).Update(subscriptionId, new Stripe.SubscriptionUpdateOptions
                {
                    Items = new List<Stripe.SubscriptionItemOptions> { new Stripe.SubscriptionItemOptions { Id = itemId, Price = priceId } },
                    ProrationBehavior = prorationBehavior
                });
            }
            catch (Stripe.StripeException e)
            {
                throw new ApiException("stripe_error", "The payment provider rejected the request: " + e.StripeError?.Code);
            }
        }
    }

    /// <summary>
    /// The emails admin actions send. Tests pass a fake; production wires the app's mail sender.
    /// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: ADMIN-01 "invite sent" and ADMIN-04 "email sent" had no
    /// sender at all. Touches: email (network) in production.
    /// </summary>
    public interface IAdminMailer
    {
        /// <summary>Sends a new user the invite with their one-time set-password token.</summary>
        void SendInvite(string email, string oneTimeToken);

        /// <summary>Sends a user the password-reset link token.</summary>
        void SendPasswordReset(string email, string resetToken);
    }

    /// <summary>
    /// What approving a governance action runs: action_type -> executor(action) returning a short execution result.
    /// ADMIN-16 "approve -> action executed". "suspend_user" is built in; an app registers the rest. Added 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP (approve only flipped the status). Touches: whatever an executor touches.
    /// </summary>
    public static class GovernanceExecutors
    {
        public static readonly Dictionary<string, Func<GovernanceAction, string>> ByType = new Dictionary<string, Func<GovernanceAction, string>>();

        /// <summary>Clears the registry and restores the built-in executors (used between tests).</summary>
        public static void Reset()
        {
            ByType.Clear();
            ByType["suspend_user"] = ga =>
            {
                var user = Database.Users.FirstOrDefault(u => u.UserId == ga.TargetResourceId)
                    ?? throw new ApiException("user_not_found", "User does not exist");
                user.Status = "suspended";
                return "user_suspended";
            };
        }

        static GovernanceExecutors() => Reset();
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

        /// <summary>
        /// The HTTP status the route returns. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the spec names 403
        /// owner_only, 409 email_exists and 400 for the other refusals; 409 subscription_item_ambiguous (ADMIN-12).
        /// </summary>
        public int Status { get; }

        /// <summary>An error with a code, a message and the status (default chosen from the code; see <see cref="DefaultStatus"/>).</summary>
        public ApiException(string code, string message, int? status = null) : base(message)
        {
            Code = code;
            Status = status ?? DefaultStatus(code);
        }

        /// <summary>401 unauthorized; 403 permission and CSRF refusals; 404 *_not_found; 409 conflicts; 502 stripe_error; 400 otherwise. Pure.</summary>
        public static int DefaultStatus(string code) => code switch
        {
            "unauthorized" => 401,
            "owner_only" or "admin_or_owner_required" or "csrf_invalid" or "publish_blocked" => 403,
            "email_exists" or "domain_exists" or "subscription_item_ambiguous" => 409,
            "stripe_error" => 502,
            _ when code != null && code.EndsWith("_not_found") => 404,
            _ => 400
        };
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
        private readonly IAdminStripeClient _stripe;
        private readonly IAdminMailer _mailer;

        /// <summary>
        /// Issues a one-time token for <paramref name="user"/>: 32 random bytes (URL-safe base64) returned once, stored
        /// only as its SHA-256, valid 1 hour. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the user record.
        /// </summary>
        private static string IssuePasswordToken(User user)
        {
            var raw = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            user.PasswordTokenHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant();
            user.PasswordTokenExpiresAt = DateTime.UtcNow.AddHours(1);
            return raw;
        }
        private readonly IReadOnlyDictionary<string, string> _priceIds;

        /// <summary>
        /// Builds the controller. In: the Stripe client (default: the Stripe.net adapter keyed by STRIPE_SECRET_KEY) and
        /// the price id of each plan (default price_solo, price_team, price_enterprise). The caller's identity is always
        /// AuthContext.CurrentUser, set by the authentication layer, never a request field.
        /// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (injectable Stripe for ADMIN-12). Touches nothing.
        /// </summary>
        public AdminController(IAdminStripeClient stripe = null, IReadOnlyDictionary<string, string> priceIds = null,
            IAdminMailer mailer = null)
        {
            _mailer = mailer;
            _stripe = stripe ?? new StripeNetAdminClient();
            _priceIds = priceIds ?? new Dictionary<string, string>
            {
                { "solo", "price_solo" }, { "team", "price_team" }, { "enterprise", "price_enterprise" }
            };
        }

        // ---------- USERS ----------
        /// <summary>
        /// Owner-only: creates a staff user (User or Admin; never Owner) after the CSRF check. Refuses a duplicate email
        /// (409 email_exists) and a non-owner (403 owner_only). Issues a one-time set-password token: emailed as an invite
        /// when notify is true and a mailer is configured (ADMIN-01), otherwise returned once as one_time_password.
        /// Output: { success, user_id, email, tier, created_at, invite_sent, one_time_password }.
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the invite is really sent. Touches: the in-memory user
        /// and audit records, email through the mailer.
        /// </summary>
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

            // Invite email, or the one-time password shown once to the owner when notify is false or no mailer is
            // configured (spec: "send invite email (or show one-time password)"; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
            var oneTimeToken = IssuePasswordToken(user);
            var invited = notify && _mailer != null;
            if (invited)
                _mailer.SendInvite(user.Email, oneTimeToken);

            return new
            {
                success = true,
                user_id = user.UserId,
                email = user.Email,
                tier = user.Tier.ToString(),
                created_at = user.CreatedAt,
                invite_sent = invited,
                one_time_password = invited ? null : oneTimeToken
            };
        }

        /// <summary>
        /// Owner-only: resets a user's password after the CSRF check.
        /// Refuses the caller's own account (400 cannot_reset_own_password), then an unknown user, then the last active
        /// owner, in the spec's gate-then-check order (changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Output: { success, ... }.
        /// Touches: the in-memory user and audit records. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
        public object ResetPassword(string csrfToken, Guid userId)
        {
            CsrfValidator.Verify(csrfToken);
            RequireOwner();

            // Gate before check (spec order; changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): own account first.
            if (userId == AuthContext.CurrentUser.UserId)
                throw new ApiException("cannot_reset_own_password", "Cannot reset own password");

            var target = Database.Users.FirstOrDefault(u => u.UserId == userId)
                ?? throw new ApiException("user_not_found", "User does not exist");

            if (IsLastActiveOwner(target))
                throw new ApiException("cannot_reset_last_owner", "Cannot reset password of last active owner");

            AuditLogger.Log("password_reset_initiated", AuthContext.CurrentUser.UserId,
                resourceType: "user", resourceId: target.UserId);

            // generate the reset token and email the link (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: nothing was sent)
            if (_mailer == null)
                throw new ApiException("email_not_configured", "No mail sender is configured", 503);
            _mailer.SendPasswordReset(target.Email, IssuePasswordToken(target));

            return new { success = true, status = "reset_email_sent" };
        }

        /// <summary>
        /// Owner-only: changes a user's tier after the CSRF check; the Owner tier cannot be assigned here.
        /// Refuses the caller's own role, then an unknown user, then demoting the last active owner (spec order; changed
        /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Output: { success, old/new tier }.
        /// Touches: the in-memory user and audit records. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
        public object ChangeUserRole(string csrfToken, Guid userId, string newTier)
        {
            CsrfValidator.Verify(csrfToken);
            RequireOwner();

            Validation.ValidateTier(newTier, allowOwner: false); // Cannot promote to Owner via API
            var newRole = (Role)Enum.Parse(typeof(Role), newTier, true);

            // Gate before check (spec order; changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): own account first.
            if (userId == AuthContext.CurrentUser.UserId)
                throw new ApiException("cannot_change_own_role", "Cannot change own role");

            var target = Database.Users.FirstOrDefault(u => u.UserId == userId)
                ?? throw new ApiException("user_not_found", "User does not exist");

            if (IsLastActiveOwner(target) && newRole != Role.Owner)
                throw new ApiException("cannot_demote_last_owner", "Cannot demote last active owner");

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

        /// <summary>
        /// Owner-only: suspends a user with a reason after the CSRF check.
        /// Refuses the caller (cannot_suspend_yourself), then an unknown user, then the last active owner (spec order;
        /// changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: the in-memory user and audit records. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
        public object SuspendUser(string csrfToken, Guid userId, string reason)
        {
            CsrfValidator.Verify(csrfToken);
            RequireOwner();

            // Gate before check (spec order; changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): own account first.
            if (userId == AuthContext.CurrentUser.UserId)
                throw new ApiException("cannot_suspend_yourself", "Cannot suspend yourself");

            var target = Database.Users.FirstOrDefault(u => u.UserId == userId)
                ?? throw new ApiException("user_not_found", "User does not exist");

            if (IsLastActiveOwner(target))
                throw new ApiException("cannot_suspend_last_owner", "Cannot suspend last active owner");

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
                tier = c.Tier,
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
                tier = c.Tier,
                subscription_status = c.Status,
                payment_method = c.PaymentMethod,
                address = c.Address,
                notes = c.Notes
            };
        }

        /// <summary>
        /// Owner-only: moves a customer to another plan (solo, team, enterprise) after the CSRF check, by billing's
        /// change_plan rule (billing_subscriptions.md flow 2, ADMIN-12 amended 2026-11-10):
        /// unknown tier -> 400 invalid_tier; unknown customer -> 404 customer_not_found; retrieve the subscription and
        /// refuse one without exactly one item -> 409 subscription_item_ambiguous; all before any update. Then
        /// stripe.subscriptions.update with {items: [{id: current_item_id, price}], proration_behavior:
        /// 'create_prorations'} (a bare price would add a second item and bill both plans), audit "plan_changed".
        /// Output: { success, customer_id, old_tier, new_tier, effective_date }.
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: plans instead of staff roles; injected Stripe client;
        /// item id rule. Touches: Stripe (network, money), the in-memory customer and audit records.
        /// </summary>
        public object ChangeCustomerPlan(string csrfToken, Guid customerId, string newTier)
        {
            CsrfValidator.Verify(csrfToken);
            RequireOwner();

            var tier = Validation.ValidatePlanTier(newTier);
            if (!_priceIds.TryGetValue(tier, out var priceId))
                throw new ApiException("invalid_tier", "Tier has no price");

            var cust = Database.Customers.FirstOrDefault(c => c.CustomerId == customerId)
                ?? throw new ApiException("customer_not_found", "Customer does not exist");
            if (string.IsNullOrWhiteSpace(cust.StripeSubscriptionId))
                throw new ApiException("subscription_not_found", "Customer has no subscription");

            var itemIds = _stripe.RetrieveSubscriptionItemIds(cust.StripeSubscriptionId);
            if (itemIds == null || itemIds.Count != 1)
                throw new ApiException("subscription_item_ambiguous", "The subscription does not have exactly one item");

            _stripe.UpdateSubscriptionItem(cust.StripeSubscriptionId, itemIds[0], priceId, "create_prorations");

            var oldTier = cust.Tier;
            AuditLogger.Log("plan_changed", AuthContext.CurrentUser.UserId,
                resourceType: "customer", resourceId: cust.CustomerId,
                oldValue: oldTier, newValue: tier);

            cust.Tier = tier;

            return new
            {
                success = true,
                customer_id = cust.CustomerId,
                old_tier = oldTier,
                new_tier = tier,
                effective_date = DateTime.UtcNow
            };
        }

        /// <summary>
        /// Owner-only: queues a refund on an invoice after the CSRF check.
        /// The amount must be positive, the invoice must exist and have succeeded, and all refunds on it may not exceed its amount.
        /// Output: { success, status: queued, amount }. Touches: the in-memory refund and audit records. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
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

        /// <summary>
        /// Owner-only: creates a deployment for a customer after the CSRF check; the tier cannot be Owner.
        /// Refuses an unknown customer and a domain already registered. Touches: the in-memory deployment and audit records. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
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

            // init config (ADMIN-14; added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: there was no config)
            var deployment = new Deployment
            {
                CustomerId = customerId,
                Domain = domain,
                Tier = role,
                ThemeId = themeId,
                Config = new Dictionary<string, string>
                {
                    { "domain", domain },
                    { "theme_id", themeId.ToString() },
                    { "tier", role.ToString() },
                    { "created_by", AuthContext.CurrentUser.UserId.ToString() }
                }
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

        /// <summary>
        /// Owner-only, double-gated publish (ADMIN-15): CSRF, owner, then SafetyFlags.CanPublish (403 publish_blocked);
        /// the deployment must be a draft with a verified domain and a theme. Sets status 'live' and published_at.
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: domain_verified and theme_set are checked (they were
        /// assumed). Touches: the in-memory deployment and audit records.
        /// </summary>
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

            // spec Check: domain_verified, theme_set (were assumed; enforced 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
            if (!dep.DomainVerified)
                throw new ApiException("domain_not_verified", "The deployment's domain is not verified");
            if (dep.ThemeId == Guid.Empty)
                throw new ApiException("theme_not_set", "The deployment has no theme");

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

        /// <summary>
        /// Owner-only decision on a pending governance action. approve: runs the action's executor
        /// (<see cref="GovernanceExecutors"/>; 400 unsupported_action_type when none), then status 'approved',
        /// approved_by, approved_at, audit "action_approved" with the execution result (ADMIN-16). reject: requires a
        /// reason (400 missing_reason), status 'rejected', audit "action_rejected" with the reason (ADMIN-17).
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: approve executes the action. Touches: the in-memory
        /// governance and audit records, and whatever the executor touches.
        /// </summary>
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
                // Execute the original action first; an action with no executor stays pending
                // (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: approve used to mark it approved without running it)
                if (!GovernanceExecutors.ByType.TryGetValue(ga.ActionType ?? "", out var execute))
                    throw new ApiException("unsupported_action_type", "No executor for this action type");
                var executionResult = execute(ga);

                ga.Status = "approved";
                ga.ApprovedBy = AuthContext.CurrentUser.UserId;
                ga.ApprovedAt = DateTime.UtcNow;

                AuditLogger.Log("action_approved", AuthContext.CurrentUser.UserId,
                    resourceType: "governance_action", resourceId: ga.ActionId,
                    newValue: executionResult);

                return new { success = true, action_id = ga.ActionId, status = "approved", execution_result = executionResult };
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

        /// <summary>
        /// Owner or admin: filters the admin audit log by action, resource and time window after the CSRF check.
        /// Output: the matching entries, newest first. Touches: reads the in-memory audit log only. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
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

        /// <summary>
        /// True when <paramref name="candidate"/> is an Owner and no other active Owner exists. Reads users only. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
        private bool IsLastActiveOwner(User candidate)
        {
            if (candidate.Tier != Role.Owner) return false;
            var activeOwners = Database.Users.Count(u => u.Tier == Role.Owner && u.Status == "active");
            return activeOwners <= 1;
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;
using AdminSystem;

/// <summary>
/// Records the Stripe calls change_plan makes and answers retrieve with <see cref="ItemIds"/>. No network.
/// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-12 amendment).
/// </summary>
public class FakeAdminStripe : IAdminStripeClient
{
    public List<string> ItemIds = new List<string> { "si_1" };
    public List<(string Sub, string Item, string Price, string Proration)> Updates = new List<(string, string, string, string)>();

    public IReadOnlyList<string> RetrieveSubscriptionItemIds(string subscriptionId) => ItemIds;

    public void UpdateSubscriptionItem(string subscriptionId, string itemId, string priceId, string prorationBehavior) =>
        Updates.Add((subscriptionId, itemId, priceId, prorationBehavior));
}

/// <summary>Records the emails admin actions send. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. No network.</summary>
public class FakeAdminMailer : IAdminMailer
{
    public List<(string Kind, string Email, string Token)> Sent = new List<(string, string, string)>();
    public void SendInvite(string email, string oneTimeToken) => Sent.Add(("invite", email, oneTimeToken));
    public void SendPasswordReset(string email, string resetToken) => Sent.Add(("reset", email, resetToken));
}

public class AdminControllerTests
{
    private readonly FakeAdminStripe _stripe = new FakeAdminStripe();
    private readonly FakeAdminMailer _mailer = new FakeAdminMailer();
    private readonly AdminController _controller;

    /// <summary>
    /// Clears the shared state and builds the controller with the fake Stripe client and mailer.
    /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: fakes injected; governance executors reset.
    /// </summary>
    public AdminControllerTests()
    {
        _controller = new AdminController(_stripe, mailer: _mailer);
        GovernanceExecutors.Reset();
        // Clear all static state before each test to ensure isolation
        Database.Users.Clear();
        Database.Customers.Clear();
        Database.Deployments.Clear();
        Database.Invoices.Clear();
        Database.Refunds.Clear();
        Database.GovernanceActions.Clear();
        Database.AuditLog.Clear();
        AuthContext.CurrentUser = null;
        SafetyFlags.CanPublish = true;
    }

    private User CreateOwner(string email = "owner@example.com")
    {
        var owner = new User
        {
            Email = email,
            Name = "Owner",
            Tier = Role.Owner
        };
        Database.Users.Add(owner);
        return owner;
    }

    private User CreateAdmin(string email = "admin@example.com")
    {
        var admin = new User
        {
            Email = email,
            Name = "Admin",
            Tier = Role.Admin
        };
        Database.Users.Add(admin);
        return admin;
    }

    private User CreateUser(string email = "user@example.com")
    {
        var user = new User
        {
            Email = email,
            Name = "User",
            Tier = Role.User
        };
        Database.Users.Add(user);
        return user;
    }

    private Customer CreateCustomer()
    {
        var cust = new Customer
        {
            Email = "cust@example.com",
            Name = "Customer",
            Tier = "solo", // customers carry a plan, not a staff role (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
            StripeSubscriptionId = "sub_123"
        };
        Database.Customers.Add(cust);
        return cust;
    }

    private Deployment CreateDeployment(Guid customerId, string domain = "example.com")
    {
        var dep = new Deployment
        {
            CustomerId = customerId,
            Domain = domain,
            Tier = "team", // a deployment's tier is its plan (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, Phase B.2; was Role.User)
            ThemeId = Guid.NewGuid(),
            DomainVerified = true // publish now checks it (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
        };
        Database.Deployments.Add(dep);
        return dep;
    }

    private Invoice CreateInvoice(Guid customerId, decimal amount = 100.00m, string status = "succeeded")
    {
        var inv = new Invoice
        {
            CustomerId = customerId,
            Amount = amount,
            Status = status
        };
        Database.Invoices.Add(inv);
        return inv;
    }

    private string GetCsrfToken(User user)
    {
        return user.CsrfToken;
    }

    private void SetupAuth(User user)
    {
        AuthContext.CurrentUser = user;
        // Ensure CSRF token exists
        if (string.IsNullOrEmpty(user.CsrfToken))
        {
            user.CsrfToken = Guid.NewGuid().ToString("N");
        }
    }

    // ---------- USER TESTS ----------
    // ADMIN-01
    [Fact]
    public void CreateUser_HappyPath()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var result = _controller.CreateUser(csrf, "new@example.com", "New User", "User", true);
        Assert.True(((dynamic)result).success);
        Assert.Equal("new@example.com", ((dynamic)result).email);
        Assert.Equal("User", ((dynamic)result).tier);
        // ADMIN-01 "user created + invite sent" (asserts added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
        Assert.Contains(Database.Users, u => u.Email == "new@example.com");
        Assert.True(((dynamic)result).invite_sent);
        Assert.Single(_mailer.Sent);
        Assert.Equal(("invite", "new@example.com"), (_mailer.Sent[0].Kind, _mailer.Sent[0].Email));
        Assert.Null(((dynamic)result).one_time_password);
        Assert.Contains(Database.AuditLog, l => l.Action == "user_created");
    }

    // ADMIN-02
    [Fact]
    public void CreateUser_DuplicateEmail()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);
        CreateUser("dup@example.com");

        var ex = Assert.Throws<ApiException>(() =>
            _controller.CreateUser(csrf, "dup@example.com", "Dup", "User", false));
        Assert.Equal("email_exists", ex.Code);
        Assert.Equal(409, ex.Status);
    }

    // ADMIN-03
    [Fact]
    public void CreateUser_NonOwner()
    {
        var admin = CreateAdmin();
        SetupAuth(admin);
        var csrf = GetCsrfToken(admin);

        var ex = Assert.Throws<ApiException>(() =>
            _controller.CreateUser(csrf, "test@example.com", "Test", "User", false));
        Assert.Equal("owner_only", ex.Code);
        Assert.Equal(403, ex.Status);
    }

    [Fact]
    public void CreateUser_InvalidTier_OwnerNotAllowed()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var ex = Assert.Throws<ApiException>(() =>
            _controller.CreateUser(csrf, "test@example.com", "Test", "Owner", false));
        Assert.Equal("invalid_tier", ex.Code);
    }

    // ADMIN-04
    [Fact]
    public void ResetPassword_HappyPath()
    {
        var owner = CreateOwner();
        var user = CreateUser("reset@example.com");
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var result = _controller.ResetPassword(csrf, user.UserId);
        Assert.True(((dynamic)result).success);
        Assert.Equal("reset_email_sent", ((dynamic)result).status);
        // ADMIN-04 "email sent" (asserts added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP); only the token's hash is kept
        Assert.Single(_mailer.Sent);
        Assert.Equal(("reset", "reset@example.com"), (_mailer.Sent[0].Kind, _mailer.Sent[0].Email));
        Assert.NotEqual(_mailer.Sent[0].Token, user.PasswordTokenHash);
        Assert.Equal(64, user.PasswordTokenHash.Length);
    }

    // ADMIN-05
    [Fact]
    public void ResetPassword_OwnAccount()
    {
        var owner = CreateOwner();
        // Add a second owner so the first is not the last active owner
        CreateOwner("owner2@example.com");
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var ex = Assert.Throws<ApiException>(() =>
            _controller.ResetPassword(csrf, owner.UserId));
        Assert.Equal("cannot_reset_own_password", ex.Code);
        Assert.Equal(400, ex.Status);
    }

    /// <summary>
    /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the spec checks the own-account gate before the last-owner
    /// check, so the sole owner resetting their own password now gets cannot_reset_own_password. The last-owner refusal
    /// is shown on another owner who is the last ACTIVE owner because the acting owner is suspended.
    /// </summary>
    [Fact]
    public void ResetPassword_LastOwner()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var own = Assert.Throws<ApiException>(() =>
            _controller.ResetPassword(csrf, owner.UserId));
        Assert.Equal("cannot_reset_own_password", own.Code);

        var owner2 = CreateOwner("owner2@example.com");
        owner.Status = "suspended";
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, ADMIN-19): this step made the target the last
        // ACTIVE owner by suspending the acting owner. A suspended caller is now refused before any gate with 403
        // account_suspended, so that is what this step proves, and the target is unchanged. (With an active acting
        // owner the target is never the last active owner, so the last-owner refusal for another user cannot be
        // reached through the API any more; reported in the Phase B.2 handoff.)
        var ex = Assert.Throws<ApiException>(() =>
            _controller.ResetPassword(csrf, owner2.UserId));
        Assert.Equal("account_suspended", ex.Code);
        Assert.Equal(403, ex.Status);
        Assert.Null(owner2.PasswordTokenHash);
    }

    // ADMIN-06
    [Fact]
    public void ChangeRole_HappyPath()
    {
        var owner = CreateOwner();
        var user = CreateUser("changerole@example.com");
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var result = _controller.ChangeUserRole(csrf, user.UserId, "Admin");
        Assert.True(((dynamic)result).success);
        Assert.Equal("User", ((dynamic)result).old_tier);
        Assert.Equal("Admin", ((dynamic)result).new_tier);
        // ADMIN-06 "role changed + audit logged" (asserts added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
        Assert.Equal(Role.Admin, user.Tier);
        Assert.Contains(Database.AuditLog, l => l.Action == "role_changed" && l.ResourceId == user.UserId && l.OldValue == "User" && l.NewValue == "Admin");
    }

    [Fact]
    public void ChangeRole_OwnAccount()
    {
        var owner = CreateOwner();
        // Add a second owner so the first is not the last active owner
        CreateOwner("owner2@example.com");
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var ex = Assert.Throws<ApiException>(() =>
            _controller.ChangeUserRole(csrf, owner.UserId, "User"));
        Assert.Equal("cannot_change_own_role", ex.Code);
    }

    /// <summary>
    /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: own-account gate first (spec order), so the sole owner
    /// demoting themselves gets cannot_change_own_role; demoting another owner who is the last ACTIVE owner (the actor
    /// is suspended) is cannot_demote_last_owner and the role is unchanged.
    /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.3): its ADMIN-07 tag moved to
    /// Governance_ChangeRole_LastOwner_StaysPending, the path the spec now proves ADMIN-07 on; this test still proves
    /// the own-role and suspended-caller refusals (no assertion removed).
    /// </summary>
    [Fact]
    public void ChangeRole_LastOwner()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var own = Assert.Throws<ApiException>(() =>
            _controller.ChangeUserRole(csrf, owner.UserId, "Admin"));
        Assert.Equal("cannot_change_own_role", own.Code);

        var owner2 = CreateOwner("owner2@example.com");
        owner.Status = "suspended";
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, ADMIN-19): this step made the target the last
        // ACTIVE owner by suspending the acting owner. A suspended caller is now refused before any gate with 403
        // account_suspended, so that is what this step proves, and the target is unchanged. (With an active acting
        // owner the target is never the last active owner, so the last-owner refusal for another user cannot be
        // reached through the API any more; reported in the Phase B.2 handoff.)
        var ex = Assert.Throws<ApiException>(() =>
            _controller.ChangeUserRole(csrf, owner2.UserId, "Admin"));
        Assert.Equal("account_suspended", ex.Code);
        Assert.Equal(403, ex.Status);
        Assert.Equal(Role.Owner, owner2.Tier);
    }

    [Fact]
    public void ChangeRole_InvalidTier_OwnerNotAllowed()
    {
        var owner = CreateOwner();
        var user = CreateUser("test@example.com");
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var ex = Assert.Throws<ApiException>(() =>
            _controller.ChangeUserRole(csrf, user.UserId, "Owner"));
        Assert.Equal("invalid_tier", ex.Code);
    }

    // ADMIN-08
    [Fact]
    public void SuspendUser_HappyPath()
    {
        var owner = CreateOwner();
        var user = CreateUser("suspend@example.com");
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var result = _controller.SuspendUser(csrf, user.UserId, "Violation");
        Assert.True(((dynamic)result).success);
        Assert.True(((dynamic)result).suspended);
        Assert.Equal("suspended", user.Status); // ADMIN-08 "status changed" (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
    }

    // ADMIN-09
    [Fact]
    public void SuspendUser_OwnAccount()
    {
        var owner = CreateOwner();
        // Add a second owner so the first is not the last active owner
        CreateOwner("owner2@example.com");
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var ex = Assert.Throws<ApiException>(() =>
            _controller.SuspendUser(csrf, owner.UserId, "Self"));
        Assert.Equal("cannot_suspend_yourself", ex.Code);
    }

    /// <summary>
    /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: own-account gate first (spec order), so the sole owner gets
    /// cannot_suspend_yourself; suspending another owner who is the last ACTIVE owner is cannot_suspend_last_owner.
    /// </summary>
    [Fact]
    public void SuspendUser_LastOwner()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var own = Assert.Throws<ApiException>(() =>
            _controller.SuspendUser(csrf, owner.UserId, "Self"));
        Assert.Equal("cannot_suspend_yourself", own.Code);

        var owner2 = CreateOwner("owner2@example.com");
        owner.Status = "suspended";
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, ADMIN-19): this step made the target the last
        // ACTIVE owner by suspending the acting owner. A suspended caller is now refused before any gate with 403
        // account_suspended, so that is what this step proves, and the target is unchanged. (With an active acting
        // owner the target is never the last active owner, so the last-owner refusal for another user cannot be
        // reached through the API any more; reported in the Phase B.2 handoff.)
        var ex = Assert.Throws<ApiException>(() =>
            _controller.SuspendUser(csrf, owner2.UserId, "Last"));
        Assert.Equal("account_suspended", ex.Code);
        Assert.Equal(403, ex.Status);
        Assert.Equal("active", owner2.Status);
    }

    // ---------- CUSTOMER TESTS ----------
    // ADMIN-10
    [Fact]
    public void Customers_List_Pagination()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        // Add 30 customers
        for (int i = 0; i < 30; i++)
        {
            Database.Customers.Add(new Customer
            {
                Email = $"c{i}@example.com",
                Name = $"Cust{i}",
                Tier = "team"
            });
        }

        var result = _controller.ListCustomers(csrf, page: 2, pageSize: 10) as List<object>;
        Assert.Equal(10, result.Count);
        // ADMIN-10 "pagination works, all fields present" (asserts added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
        dynamic first = result[0];
        Assert.Equal("c10@example.com", first.email);
        Assert.Equal("Cust10", first.name);
        Assert.Equal("team", first.tier);
        Assert.Equal("active", first.status);
        Assert.Equal(0, first.invoice_count);
        Assert.IsType<Guid>(first.customer_id);
        Assert.IsType<DateTime>(first.signup_date);
        Assert.Equal(10, (_controller.ListCustomers(csrf, page: 3, pageSize: 10) as List<object>).Count);
        Assert.Empty(_controller.ListCustomers(csrf, page: 4, pageSize: 10) as List<object>);
    }

    // ADMIN-11
    [Fact]
    public void Customer_Detail_AllFields()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);
        var cust = CreateCustomer();

        cust.PaymentMethod = "card_visa_4242";
        cust.Address = "1 Main St";
        cust.Notes = "VIP";
        var result = _controller.GetCustomerDetail(csrf, cust.CustomerId);
        Assert.Equal(cust.CustomerId, ((dynamic)result).customer_id);
        Assert.Equal(cust.Email, ((dynamic)result).email);
        Assert.Equal(cust.Name, ((dynamic)result).name);
        // ADMIN-11 "all fields present" (asserts added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
        Assert.Equal("solo", ((dynamic)result).tier);
        Assert.Equal("active", ((dynamic)result).subscription_status);
        Assert.Equal("card_visa_4242", ((dynamic)result).payment_method);
        Assert.Equal("1 Main St", ((dynamic)result).address);
        Assert.Equal("VIP", ((dynamic)result).notes);
    }

    // ADMIN-12
    [Fact]
    public void ChangePlan_StripeCalledAndAuditLogged()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);
        var cust = CreateCustomer();

        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-12 amendment): a customer moves between plans,
        // and Stripe is updated on the subscription's one existing item with the new price and create_prorations.
        var result = _controller.ChangeCustomerPlan(csrf, cust.CustomerId, "team");
        Assert.True(((dynamic)result).success);
        Assert.Equal("solo", ((dynamic)result).old_tier);
        Assert.Equal("team", ((dynamic)result).new_tier);
        Assert.Equal(new[] { ("sub_123", "si_1", "price_team", "create_prorations") }, _stripe.Updates);
        Assert.Equal("team", cust.Tier);
        Assert.Contains(Database.AuditLog, l => l.Action == "plan_changed" && l.ResourceId == cust.CustomerId && l.OldValue == "solo" && l.NewValue == "team");
    }

    /// <summary>
    /// ADMIN-12 refusals, both before any update: an unknown plan is 400 invalid_tier; a subscription with no item or
    /// two items is 409 subscription_item_ambiguous. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    // ADMIN-12
    [Fact]
    public void ChangePlan_UnknownTierOrNotExactlyOneItem_NoUpdate()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);
        var cust = CreateCustomer();

        var bad = Assert.Throws<ApiException>(() => _controller.ChangeCustomerPlan(csrf, cust.CustomerId, "platinum"));
        Assert.Equal("invalid_tier", bad.Code);
        Assert.Equal(400, bad.Status);

        foreach (var items in new[] { new List<string>(), new List<string> { "si_a", "si_b" } })
        {
            _stripe.ItemIds = items;
            var ex = Assert.Throws<ApiException>(() => _controller.ChangeCustomerPlan(csrf, cust.CustomerId, "team"));
            Assert.Equal("subscription_item_ambiguous", ex.Code);
            Assert.Equal(409, ex.Status);
        }

        Assert.Empty(_stripe.Updates);
        Assert.Equal("solo", cust.Tier);
        Assert.DoesNotContain(Database.AuditLog, l => l.Action == "plan_changed");
    }

    [Fact]
    public void ChangePlan_InvalidTier_OwnerNotAllowed()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);
        var cust = CreateCustomer();

        var ex = Assert.Throws<ApiException>(() =>
            _controller.ChangeCustomerPlan(csrf, cust.CustomerId, "Owner"));
        Assert.Equal("invalid_tier", ex.Code);
    }

    // ADMIN-13
    [Fact]
    public void QueueRefund_CreatedWithQueuedStatus()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);
        var cust = CreateCustomer();
        var invoice = CreateInvoice(cust.CustomerId);

        var refundResult = _controller.QueueRefund(csrf, invoice.InvoiceId, 100.00m, "Customer request");
        Assert.True(((dynamic)refundResult).success);
        Assert.Equal("queued", ((dynamic)refundResult).status);
        Assert.Equal(100.00m, ((dynamic)refundResult).amount);
        // ADMIN-13 "refund record created" (asserts added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
        var row = Assert.Single(Database.Refunds);
        Assert.Equal("queued", row.Status);
        Assert.Equal(owner.UserId, row.CreatedBy);
    }

    [Fact]
    public void QueueRefund_NegativeAmount_Rejected()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);
        var cust = CreateCustomer();
        var invoice = CreateInvoice(cust.CustomerId);

        var ex = Assert.Throws<ApiException>(() =>
            _controller.QueueRefund(csrf, invoice.InvoiceId, -50.00m, "Invalid"));
        Assert.Equal("invalid_amount", ex.Code);
    }

    [Fact]
    public void QueueRefund_UnknownInvoice_Rejected()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var ex = Assert.Throws<ApiException>(() =>
            _controller.QueueRefund(csrf, Guid.NewGuid(), 100.00m, "Unknown invoice"));
        Assert.Equal("invoice_not_found", ex.Code);
    }

    [Fact]
    public void QueueRefund_FailedInvoice_Rejected()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);
        var cust = CreateCustomer();
        var invoice = CreateInvoice(cust.CustomerId, 100.00m, "failed");

        var ex = Assert.Throws<ApiException>(() =>
            _controller.QueueRefund(csrf, invoice.InvoiceId, 50.00m, "Failed invoice"));
        Assert.Equal("invalid_invoice_status", ex.Code);
    }

    [Fact]
    public void QueueRefund_TotalAboveInvoice_Rejected()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);
        var cust = CreateCustomer();
        var invoice = CreateInvoice(cust.CustomerId, 100.00m);

        _controller.QueueRefund(csrf, invoice.InvoiceId, 60.00m, "Partial");
        var ex = Assert.Throws<ApiException>(() =>
            _controller.QueueRefund(csrf, invoice.InvoiceId, 50.00m, "Second partial"));
        Assert.Equal("refund_exceeds_invoice", ex.Code);
    }

    [Fact]
    public void ValidateTier_UndefinedNumber_Rejected()
    {
        // Enum.TryParse accepts "99" as (Role)99; it names no role (CodeRabbit, PR 18).
        var ex = Assert.Throws<ApiException>(() => Validation.ValidateTier("99"));
        Assert.Equal("invalid_tier", ex.Code);
    }

    // ---------- DEPLOYMENT TESTS ----------
    // ADMIN-14
    [Fact]
    public void CreateDeployment_HappyPath()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);
        var cust = CreateCustomer();

        var themeId = Guid.NewGuid();
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, admin spec TIERS): the tier is a plan; this
        // test passed the staff role "User", which is now 400 invalid_tier.
        var result = _controller.CreateDeployment(csrf, cust.CustomerId, "newsite.com", "team", themeId);
        Assert.True(((dynamic)result).success);
        Assert.Equal("newsite.com", ((dynamic)result).domain);
        Assert.Equal("team", ((dynamic)result).tier);
        // ADMIN-14 "deployment created + config initialized" (asserts added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
        var dep = Assert.Single(Database.Deployments);
        Assert.Equal(DeploymentStatus.Draft, dep.Status);
        Assert.Equal("newsite.com", dep.Config["domain"]);
        Assert.Equal(themeId.ToString(), dep.Config["theme_id"]);
        Assert.Equal("team", dep.Tier);
        Assert.False(dep.DomainVerified); // a new deployment's domain is not verified yet (Phase B.2)
    }

    [Fact]
    public void CreateDeployment_InvalidTier_OwnerNotAllowed()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);
        var cust = CreateCustomer();

        var ex = Assert.Throws<ApiException>(() =>
            _controller.CreateDeployment(csrf, cust.CustomerId, "newsite.com", "Owner", Guid.NewGuid()));
        Assert.Equal("invalid_tier", ex.Code);
    }

    // ADMIN-15
    [Fact]
    public void PublishDeployment_DoubleGateChecked()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);
        var cust = CreateCustomer();
        var dep = CreateDeployment(cust.CustomerId, "publish.com");

        var result = _controller.PublishDeployment(csrf, dep.DeploymentId);
        Assert.True(((dynamic)result).success);
        Assert.Equal("live", ((dynamic)result).status);
        Assert.Equal(DeploymentStatus.Live, dep.Status);
        Assert.NotNull(dep.PublishedAt);

        // the first gate: an admin (not owner) is refused; an unverified domain is refused (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
        var unverified = CreateDeployment(cust.CustomerId, "unverified.com");
        unverified.DomainVerified = false;
        Assert.Equal("domain_not_verified", Assert.Throws<ApiException>(() => _controller.PublishDeployment(csrf, unverified.DeploymentId)).Code);
        var admin = CreateAdmin();
        SetupAuth(admin);
        unverified.DomainVerified = true;
        Assert.Equal("owner_only", Assert.Throws<ApiException>(() => _controller.PublishDeployment(GetCsrfToken(admin), unverified.DeploymentId)).Code);
        Assert.Equal(DeploymentStatus.Draft, unverified.Status);
    }

    [Fact]
    public void PublishDeployment_BlockedWhenSafetyFlagOff()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);
        var cust = CreateCustomer();
        var dep = CreateDeployment(cust.CustomerId, "blocked.com");

        SafetyFlags.CanPublish = false;
        try
        {
            var ex = Assert.Throws<ApiException>(() =>
                _controller.PublishDeployment(csrf, dep.DeploymentId));
            Assert.Equal("publish_blocked", ex.Code);
        }
        finally
        {
            SafetyFlags.CanPublish = true;
        }
    }

    // ---------- GOVERNANCE TESTS ----------
    // ADMIN-16
    [Fact]
    public void Governance_Approve_ExecutesAndLogs()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var ga = new GovernanceAction
        {
            ActionType = "test_action",
            ActorId = owner.UserId,
            TargetResourceId = Guid.NewGuid(),
            Reason = "Testing"
        };
        Database.GovernanceActions.Add(ga);
        // ADMIN-16 "action executed": approve runs the action's executor (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
        var executed = new List<Guid>();
        GovernanceExecutors.ByType["test_action"] = a => { executed.Add(a.TargetResourceId); return "done"; };

        var result = _controller.DecideGovernanceAction(csrf, ga.ActionId, "approve");
        Assert.True(((dynamic)result).success);
        Assert.Equal("approved", ((dynamic)result).status);
        Assert.Equal(new[] { ga.TargetResourceId }, executed);
        Assert.Equal("approved", ga.Status);
        Assert.Equal(owner.UserId, ga.ApprovedBy);
        Assert.Contains(Database.AuditLog, l => l.Action == "action_approved" && l.NewValue == "done");

        // the built-in suspend_user executor really suspends; an action type with no executor stays pending
        var target = CreateUser("target@example.com");
        var suspend = new GovernanceAction { ActionType = "suspend_user", ActorId = owner.UserId, TargetResourceId = target.UserId, Reason = "abuse" };
        var unknown = new GovernanceAction { ActionType = "no_such_type", ActorId = owner.UserId, TargetResourceId = Guid.NewGuid(), Reason = "?" };
        Database.GovernanceActions.Add(suspend);
        Database.GovernanceActions.Add(unknown);
        _controller.DecideGovernanceAction(csrf, suspend.ActionId, "approve");
        Assert.Equal("suspended", target.Status);
        Assert.Equal("unsupported_action_type", Assert.Throws<ApiException>(() => _controller.DecideGovernanceAction(csrf, unknown.ActionId, "approve")).Code);
        Assert.Equal("pending", unknown.Status);
    }

    /// <summary>
    /// ADMIN-07 (admin spec LAST OWNER, Phase B.3): an admin's change_role demoting the only active owner is submitted
    /// for governance; the owner approving it gets 400 cannot_demote_last_owner, the action stays pending, the owner's
    /// tier is unchanged and nothing is audited. With a second active owner the same kind of action is approved and
    /// the role changes (role_changed audited). In: nothing. Out: asserts. Added 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory admin state.
    /// </summary>
    // ADMIN-07
    [Fact]
    public void Governance_ChangeRole_LastOwner_StaysPending()
    {
        var owner = CreateOwner();
        var admin = CreateAdmin();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var demote = new GovernanceAction
        {
            ActionType = "change_role", ActorId = admin.UserId, TargetResourceId = owner.UserId,
            NewValue = "Admin", Reason = "hand over"
        };
        Database.GovernanceActions.Add(demote);
        var auditBefore = Database.AuditLog.Count;

        var ex = Assert.Throws<ApiException>(() => _controller.DecideGovernanceAction(csrf, demote.ActionId, "approve"));
        Assert.Equal("cannot_demote_last_owner", ex.Code);
        Assert.Equal(400, ex.Status);
        Assert.Equal("pending", demote.Status);
        Assert.Null(demote.ApprovedBy);
        Assert.Equal(Role.Owner, owner.Tier);
        Assert.Equal(auditBefore, Database.AuditLog.Count);

        // with a second active owner the governance change_role runs
        var owner2 = CreateOwner("owner2@example.com");
        var second = new GovernanceAction
        {
            ActionType = "change_role", ActorId = admin.UserId, TargetResourceId = owner2.UserId,
            NewValue = "User", Reason = "role change"
        };
        Database.GovernanceActions.Add(second);
        var result = _controller.DecideGovernanceAction(csrf, second.ActionId, "approve");
        Assert.Equal("approved", ((dynamic)result).status);
        Assert.Equal("role_changed", ((dynamic)result).execution_result);
        Assert.Equal(Role.User, owner2.Tier);
        Assert.Contains(Database.AuditLog, l => l.Action == "role_changed" && l.ResourceId == owner2.UserId && l.OldValue == "Owner" && l.NewValue == "User");
    }

    /// <summary>
    /// ADMIN-07 (admin spec LAST OWNER, approver rule): an admin's governance change_role that targets the approving
    /// owner, while a second active owner exists (so the last-owner check passes), is refused with 400
    /// cannot_change_own_role; the action stays pending, the approver's tier is unchanged and nothing is audited.
    /// With the only active owner as target the last-owner answer still comes first.
    /// In: nothing. Out: asserts. Why: review finding 4525101209. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: the in-memory admin state.
    /// </summary>
    // ADMIN-07
    [Fact]
    public void Governance_ChangeRole_TargetIsApprover_Refused()
    {
        var owner = CreateOwner();
        var admin = CreateAdmin();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);
        var self = new GovernanceAction
        {
            ActionType = "change_role", ActorId = admin.UserId, TargetResourceId = owner.UserId,
            NewValue = "Admin", Reason = "hand over"
        };
        Database.GovernanceActions.Add(self);
        // the only active owner: the last-owner check answers first
        Assert.Equal("cannot_demote_last_owner", Assert.Throws<ApiException>(() => _controller.DecideGovernanceAction(csrf, self.ActionId, "approve")).Code);

        CreateOwner("owner2@example.com");
        var auditBefore = Database.AuditLog.Count;
        var ex = Assert.Throws<ApiException>(() => _controller.DecideGovernanceAction(csrf, self.ActionId, "approve"));
        Assert.Equal("cannot_change_own_role", ex.Code);
        Assert.Equal(400, ex.Status);
        Assert.Equal("pending", self.Status);
        Assert.Null(self.ApprovedBy);
        Assert.Equal(Role.Owner, owner.Tier);
        Assert.Equal(auditBefore, Database.AuditLog.Count);
    }

    // ADMIN-17
    [Fact]
    public void Governance_Reject_LogsReason()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var ga = new GovernanceAction
        {
            ActionType = "test_action",
            ActorId = owner.UserId,
            TargetResourceId = Guid.NewGuid(),
            Reason = "Testing"
        };
        Database.GovernanceActions.Add(ga);

        var result = _controller.DecideGovernanceAction(csrf, ga.ActionId, "reject", "Not needed");
        Assert.True(((dynamic)result).success);
        Assert.Equal("rejected", ((dynamic)result).status);
        // ADMIN-17 "reason logged" (asserts added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
        Assert.Equal("Not needed", ga.RejectionReason);
        Assert.Contains(Database.AuditLog, l => l.Action == "action_rejected" && l.ResourceId == ga.ActionId && l.Reason == "Not needed");
    }

    [Fact]
    public void Governance_Reject_MissingReason_Rejected()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var ga = new GovernanceAction
        {
            ActionType = "test_action",
            ActorId = owner.UserId,
            TargetResourceId = Guid.NewGuid(),
            Reason = "Testing"
        };
        Database.GovernanceActions.Add(ga);

        var ex = Assert.Throws<ApiException>(() =>
            _controller.DecideGovernanceAction(csrf, ga.ActionId, "reject", ""));
        Assert.Equal("missing_reason", ex.Code);
    }

    // ADMIN-18
    [Fact]
    public void AuditLog_Search_FiltersAndPagination()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        // Insert audit entries
        for (int i = 0; i < 5; i++)
        {
            AuditLogger.Log("test_action", owner.UserId, "test", Guid.NewGuid(),
                oldValue: $"old{i}", newValue: $"new{i}");
        }

        var result = _controller.SearchAuditLog(csrf, actionType: "test_action", limit: 3, offset: 1) as List<object>;
        Assert.Equal(3, result.Count);
        // ADMIN-18 filters (asserts added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): other actions are excluded,
        // offset moves the window, and a resource filter finds exactly that resource's entry
        AuditLogger.Log("other_action", owner.UserId, "test", Guid.NewGuid());
        Assert.All(result, r => Assert.Equal("test_action", ((dynamic)r).action));
        Assert.Equal(2, (_controller.SearchAuditLog(csrf, actionType: "test_action", limit: 3, offset: 3) as List<object>).Count);
        var oneResource = Database.AuditLog[2].ResourceId;
        var byResource = _controller.SearchAuditLog(csrf, resourceId: oneResource) as List<object>;
        Assert.Equal(oneResource, ((dynamic)Assert.Single(byResource)).resource_id);
    }

    // ---------- CSRF TESTS ----------
    [Fact]
    public void Csrf_InvalidToken_Rejected()
    {
        var owner = CreateOwner();
        SetupAuth(owner);

        var ex = Assert.Throws<ApiException>(() =>
            _controller.CreateUser("invalid_token", "test@example.com", "Test", "User", false));
        Assert.Equal("csrf_invalid", ex.Code);
    }

    [Fact]
    public void Csrf_MissingToken_Rejected()
    {
        var owner = CreateOwner();
        SetupAuth(owner);

        var ex = Assert.Throws<ApiException>(() =>
            _controller.CreateUser("", "test@example.com", "Test", "User", false));
        Assert.Equal("csrf_invalid", ex.Code);
    }

    [Fact]
    public void Csrf_TokenIsPerUser()
    {
        var owner1 = CreateOwner("owner1@example.com");
        var owner2 = CreateOwner("owner2@example.com");
        SetupAuth(owner1);
        var csrf1 = GetCsrfToken(owner1);

        // owner1's token should work for owner1
        var result = _controller.CreateUser(csrf1, "test1@example.com", "Test1", "User", false);
        Assert.True(((dynamic)result).success);

        // owner1's token should NOT work for owner2
        SetupAuth(owner2);
        var ex = Assert.Throws<ApiException>(() =>
            _controller.CreateUser(csrf1, "test2@example.com", "Test2", "User", false));
        Assert.Equal("csrf_invalid", ex.Code);
    }

    /// <summary>
    /// ADMIN-19: an owner whose account was suspended (by another owner) is refused by every admin action with 403
    /// account_suspended, before any gate (even with a wrong CSRF token), and nothing changes: no user, customer,
    /// deployment, refund, governance or audit record. In: nothing. Out: asserts. Added 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2). Touches: the in-memory admin state.
    /// </summary>
    // ADMIN-19
    [Fact]
    public void SuspendedOwner_EveryAction_AccountSuspended_NothingChanged()
    {
        var owner1 = CreateOwner("owner1@example.com");
        var owner2 = CreateOwner("owner2@example.com");
        var target = CreateUser("target@example.com");
        var cust = CreateCustomer();
        var inv = CreateInvoice(cust.CustomerId);
        var dep = CreateDeployment(cust.CustomerId, "suspended-owner.com");
        var ga = new GovernanceAction { ActionType = "suspend_user", ActorId = owner2.UserId, TargetResourceId = target.UserId, Reason = "abuse" };
        Database.GovernanceActions.Add(ga);

        SetupAuth(owner2);
        _controller.SuspendUser(GetCsrfToken(owner2), owner1.UserId, "compromised");
        var auditBefore = Database.AuditLog.Count;

        SetupAuth(owner1);
        var csrf = GetCsrfToken(owner1);
        var actions = new List<Func<object>>
        {
            () => _controller.CreateUser(csrf, "new@example.com", "New", "User", false),
            () => _controller.CreateUser("wrong-csrf", "new@example.com", "New", "User", false),
            () => _controller.ResetPassword(csrf, target.UserId),
            () => _controller.ChangeUserRole(csrf, target.UserId, "Admin"),
            () => _controller.SuspendUser(csrf, target.UserId, "x"),
            () => _controller.SuspendUser(csrf, owner2.UserId, "revenge"),
            () => _controller.ListCustomers(csrf),
            () => _controller.GetCustomerDetail(csrf, cust.CustomerId),
            () => _controller.ChangeCustomerPlan(csrf, cust.CustomerId, "team"),
            () => _controller.QueueRefund(csrf, inv.InvoiceId, 10m, "x"),
            () => _controller.ListDeployments(csrf),
            () => _controller.CreateDeployment(csrf, cust.CustomerId, "another.com", "team", Guid.NewGuid()),
            () => _controller.PublishDeployment(csrf, dep.DeploymentId),
            () => _controller.SuspendDeployment(csrf, dep.DeploymentId, "x"),
            () => _controller.RetireDeployment(csrf, dep.DeploymentId),
            () => _controller.ListGovernanceActions(csrf),
            () => _controller.DecideGovernanceAction(csrf, ga.ActionId, "approve"),
            () => _controller.SearchAuditLog(csrf),
            // Phase B.3 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): refused before the CSRF check too
            () => _controller.ChangeUserRole("wrong-csrf", target.UserId, "Admin"),
            () => _controller.DecideGovernanceAction("wrong-csrf", ga.ActionId, "approve"),
            () => _controller.SearchAuditLog(null),
        };
        foreach (var action in actions)
        {
            var ex = Assert.Throws<ApiException>(() => action());
            Assert.Equal("account_suspended", ex.Code);
            Assert.Equal(403, ex.Status);
        }

        Assert.Equal(3, Database.Users.Count);
        Assert.Equal(Role.User, target.Tier);
        Assert.Equal("active", target.Status);
        Assert.Equal("active", owner2.Status);
        Assert.Null(target.PasswordTokenHash);
        Assert.Equal("solo", cust.Tier);
        Assert.Empty(_stripe.Updates);
        Assert.Empty(Database.Refunds);
        Assert.Single(Database.Deployments);
        Assert.Equal(DeploymentStatus.Draft, dep.Status);
        Assert.Equal("pending", ga.Status);
        Assert.Equal(auditBefore, Database.AuditLog.Count);
        Assert.Empty(_mailer.Sent);
    }

    /// <summary>
    /// Admin spec TIERS (Phase B.2): users.tier is the staff role and a customer's or deployment's tier is the plan;
    /// a plan given where a role is expected, or a role where a plan is expected, is 400 invalid_tier and changes
    /// nothing. In: nothing. Out: asserts. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory
    /// admin state.
    /// </summary>
    // ADMIN-14
    [Fact]
    public void Tiers_RoleAndPlanAreNeverMixed_InvalidTier()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);
        var user = CreateUser();
        var cust = CreateCustomer();

        void InvalidTier(Func<object> action)
        {
            var ex = Assert.Throws<ApiException>(() => action());
            Assert.Equal("invalid_tier", ex.Code);
            Assert.Equal(400, ex.Status);
        }
        InvalidTier(() => _controller.CreateUser(csrf, "plan@example.com", "Plan", "team", false));
        InvalidTier(() => _controller.ChangeUserRole(csrf, user.UserId, "enterprise"));
        InvalidTier(() => _controller.ChangeCustomerPlan(csrf, cust.CustomerId, "admin"));
        InvalidTier(() => _controller.CreateDeployment(csrf, cust.CustomerId, "role.com", "admin", Guid.NewGuid()));
        InvalidTier(() => _controller.CreateDeployment(csrf, cust.CustomerId, "role.com", "user", Guid.NewGuid()));

        Assert.Equal(2, Database.Users.Count);
        Assert.Equal(Role.User, user.Tier);
        Assert.Equal("solo", cust.Tier);
        Assert.Empty(Database.Deployments);
        Assert.Empty(Database.AuditLog);
    }
}

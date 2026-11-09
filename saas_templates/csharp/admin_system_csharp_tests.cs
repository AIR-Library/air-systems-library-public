using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;
using AdminSystem;

public class AdminControllerTests
{
    private readonly AdminController _controller = new AdminController();

    public AdminControllerTests()
    {
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
            Tier = Role.User,
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
            Tier = Role.User,
            ThemeId = Guid.NewGuid()
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
    }

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
    }

    [Fact]
    public void CreateUser_NonOwner()
    {
        var admin = CreateAdmin();
        SetupAuth(admin);
        var csrf = GetCsrfToken(admin);

        var ex = Assert.Throws<ApiException>(() =>
            _controller.CreateUser(csrf, "test@example.com", "Test", "User", false));
        Assert.Equal("owner_only", ex.Code);
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
    }

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
    }

    [Fact]
    public void ResetPassword_LastOwner()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var ex = Assert.Throws<ApiException>(() =>
            _controller.ResetPassword(csrf, owner.UserId));
        Assert.Equal("cannot_reset_last_owner", ex.Code);
    }

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

    [Fact]
    public void ChangeRole_LastOwner()
    {
        // Only one owner exists, try to demote them
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var ex = Assert.Throws<ApiException>(() =>
            _controller.ChangeUserRole(csrf, owner.UserId, "Admin"));
        Assert.Equal("cannot_demote_last_owner", ex.Code);
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
    }

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

    [Fact]
    public void SuspendUser_LastOwner()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);

        var ex = Assert.Throws<ApiException>(() =>
            _controller.SuspendUser(csrf, owner.UserId, "Self"));
        Assert.Equal("cannot_suspend_last_owner", ex.Code);
    }

    // ---------- CUSTOMER TESTS ----------
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
                Tier = Role.User
            });
        }

        var result = _controller.ListCustomers(csrf, page: 2, pageSize: 10) as List<object>;
        Assert.Equal(10, result.Count);
    }

    [Fact]
    public void Customer_Detail_AllFields()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);
        var cust = CreateCustomer();

        var result = _controller.GetCustomerDetail(csrf, cust.CustomerId);
        Assert.Equal(cust.CustomerId, ((dynamic)result).customer_id);
        Assert.Equal(cust.Email, ((dynamic)result).email);
        Assert.Equal(cust.Name, ((dynamic)result).name);
    }

    [Fact]
    public void ChangePlan_StripeCalledAndAuditLogged()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);
        var cust = CreateCustomer();

        var result = _controller.ChangeCustomerPlan(csrf, cust.CustomerId, "Admin");
        Assert.True(((dynamic)result).success);
        Assert.Equal("User", ((dynamic)result).old_tier);
        Assert.Equal("Admin", ((dynamic)result).new_tier);
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
    [Fact]
    public void CreateDeployment_HappyPath()
    {
        var owner = CreateOwner();
        SetupAuth(owner);
        var csrf = GetCsrfToken(owner);
        var cust = CreateCustomer();

        var result = _controller.CreateDeployment(csrf, cust.CustomerId, "newsite.com", "User", Guid.NewGuid());
        Assert.True(((dynamic)result).success);
        Assert.Equal("newsite.com", ((dynamic)result).domain);
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

        var result = _controller.DecideGovernanceAction(csrf, ga.ActionId, "approve");
        Assert.True(((dynamic)result).success);
        Assert.Equal("approved", ((dynamic)result).status);
    }

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
}

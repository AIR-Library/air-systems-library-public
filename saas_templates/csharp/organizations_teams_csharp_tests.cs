using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using AOI.OrganizationsTeams;

public static class OrganizationsTeamsTests
{
    private static int _passed = 0;
    private static int _failed = 0;

    public static int Main()
    {
        TestNonMemberCannotReadMembersOfAnotherOrg();
        TestMemberCannotInviteAdminCan();
        TestAdminCannotRemoveOwnerLastOwnerCannotLeave();
        TestInvitationWorksOnceSecondUseFails();
        TestExpiredInvitationFailsDifferentEmailFails();
        TestRawTokenNotStoredInDatabase();

        Console.WriteLine($"\n=== Results: {_passed} passed, {_failed} failed ===");
        return _failed > 0 ? 1 : 0;
    }

    private static void Assert(bool condition, string testName, string message = "")
    {
        if (condition)
        {
            Console.WriteLine($"  PASS: {testName}");
            _passed++;
        }
        else
        {
            Console.WriteLine($"  FAIL: {testName} - {message}");
            _failed++;
        }
    }

    private static OrganizationsService CreateService(IStore store) => new OrganizationsService(store);

    private static string RandomId() => Guid.NewGuid().ToString("N");
    private static byte[] RandomToken() { var b = new byte[32]; RandomNumberGenerator.Fill(b); return b; }

    // Test 1: a non-member cannot read members of another org (IDOR attempt by id)
    // ORG-01
    public static void TestNonMemberCannotReadMembersOfAnotherOrg()
    {
        var store = new InMemoryStore();
        var svc = CreateService(store);

        var user1 = RandomId();
        var user2 = RandomId();
        var user3 = RandomId();

        // user1 creates org
        var createResult = svc.CreateOrg(user1, "Org One");
        Assert(createResult.Status == 201, "TestNonMemberCannotReadMembersOfAnotherOrg - create org");
        var orgId = ExtractJsonValue(createResult.Body, "id");

        // user2 creates another org
        var createResult2 = svc.CreateOrg(user2, "Org Two");
        Assert(createResult2.Status == 201, "TestNonMemberCannotReadMembersOfAnotherOrg - create org2");
        var orgId2 = ExtractJsonValue(createResult2.Body, "id");

        // user3 tries to list members of org1 (not a member)
        var listResult = svc.ListMembers(user3, orgId);
        Assert(listResult.Status == 404, "TestNonMemberCannotReadMembersOfAnotherOrg - non-member gets 404");

        // user3 tries to get org1 (not a member)
        var getResult = svc.GetOrg(user3, orgId);
        Assert(getResult.Status == 404, "TestNonMemberCannotReadMembersOfAnotherOrg - non-member get org gets 404");

        // user2 (member of org2) tries to list members of org1
        var listResult2 = svc.ListMembers(user2, orgId);
        Assert(listResult2.Status == 404, "TestNonMemberCannotReadMembersOfAnotherOrg - member of other org gets 404");
    }

    // Test 2: a member cannot invite; an admin can
    // ORG-02
    public static void TestMemberCannotInviteAdminCan()
    {
        var store = new InMemoryStore();
        var svc = CreateService(store);

        var owner = RandomId();
        var admin = RandomId();
        var member = RandomId();
        var inviteeEmail = "newuser@example.com";

        var createResult = svc.CreateOrg(owner, "Test Org");
        Assert(createResult.Status == 201, "TestMemberCannotInviteAdminCan - create org");
        var orgId = ExtractJsonValue(createResult.Body, "id");

        // Add admin via direct store manipulation (simulating invite+accept flow)
        var adminMembership = new Membership(orgId, admin, Role.Admin, DateTime.UtcNow);
        store.AddMembership(adminMembership);

        // Add member
        var memberMembership = new Membership(orgId, member, Role.Member, DateTime.UtcNow);
        store.AddMembership(memberMembership);

        // Member tries to invite - should fail
        var inviteByMember = svc.Invite(member, orgId, inviteeEmail, Role.Member);
        Assert(inviteByMember.Status == 403, "TestMemberCannotInviteAdminCan - member invite returns 403");

        // Admin invites - should succeed
        var inviteByAdmin = svc.Invite(admin, orgId, inviteeEmail, Role.Member);
        Assert(inviteByAdmin.Status == 201, "TestMemberCannotInviteAdminCan - admin invite returns 201");
        Assert(!string.IsNullOrEmpty(inviteByAdmin.RawToken), "TestMemberCannotInviteAdminCan - raw token returned");

        // Owner invites - should succeed
        var inviteByOwner = svc.Invite(owner, orgId, "another@example.com", Role.Admin);
        Assert(inviteByOwner.Status == 201, "TestMemberCannotInviteAdminCan - owner invite returns 201");
    }

    // Test 3: an admin cannot remove the owner; the last owner cannot leave
    // ORG-03
    public static void TestAdminCannotRemoveOwnerLastOwnerCannotLeave()
    {
        var store = new InMemoryStore();
        var svc = CreateService(store);

        var owner = RandomId();
        var admin = RandomId();
        var member = RandomId();

        var createResult = svc.CreateOrg(owner, "Test Org");
        Assert(createResult.Status == 201, "TestAdminCannotRemoveOwnerLastOwnerCannotLeave - create org");
        var orgId = ExtractJsonValue(createResult.Body, "id");

        // Add admin and member
        store.AddMembership(new Membership(orgId, admin, Role.Admin, DateTime.UtcNow));
        store.AddMembership(new Membership(orgId, member, Role.Member, DateTime.UtcNow));

        // Admin tries to remove owner - should fail
        var removeByAdmin = svc.RemoveMember(admin, orgId, owner);
        Assert(removeByAdmin.Status == 403, "TestAdminCannotRemoveOwnerLastOwnerCannotLeave - admin remove owner returns 403");

        // Owner tries to leave (last owner) - should fail
        var leaveByOwner = svc.LeaveOrg(owner, orgId);
        Assert(leaveByOwner.Status == 403, "TestAdminCannotRemoveOwnerLastOwnerCannotLeave - last owner leave returns 403");

        // Add second owner
        var owner2 = RandomId();
        store.AddMembership(new Membership(orgId, owner2, Role.Owner, DateTime.UtcNow));

        // Now owner can leave
        var leaveByOwner2 = svc.LeaveOrg(owner, orgId);
        Assert(leaveByOwner2.Status == 200, "TestAdminCannotRemoveOwnerLastOwnerCannotLeave - owner leaves when 2 owners returns 200");

        // Owner2 tries to leave (now last owner) - should fail
        var leaveByOwner3 = svc.LeaveOrg(owner2, orgId);
        Assert(leaveByOwner3.Status == 403, "TestAdminCannotRemoveOwnerLastOwnerCannotLeave - last remaining owner cannot leave");
    }

    // Test 4: an invitation works once; the second use fails
    // ORG-04
    public static void TestInvitationWorksOnceSecondUseFails()
    {
        var store = new InMemoryStore();
        var svc = CreateService(store);

        var owner = RandomId();
        var user1 = RandomId();
        var user2 = RandomId();
        var email = "invitee@example.com";

        var createResult = svc.CreateOrg(owner, "Test Org");
        Assert(createResult.Status == 201, "TestInvitationWorksOnceSecondUseFails - create org");
        var orgId = ExtractJsonValue(createResult.Body, "id");

        // Owner invites
        var inviteResult = svc.Invite(owner, orgId, email, Role.Member);
        Assert(inviteResult.Status == 201, "TestInvitationWorksOnceSecondUseFails - invite succeeds");
        var rawToken = inviteResult.RawToken!;

        // First user accepts - should succeed
        var accept1 = svc.AcceptInvitation(user1, email, rawToken);
        Assert(accept1.Status == 200, "TestInvitationWorksOnceSecondUseFails - first accept succeeds");

        // Second user tries same token - should fail
        var accept2 = svc.AcceptInvitation(user2, email, rawToken);
        Assert(accept2.Status == 409, "TestInvitationWorksOnceSecondUseFails - second accept returns 409");

        // First user tries again - should fail
        var accept3 = svc.AcceptInvitation(user1, email, rawToken);
        Assert(accept3.Status == 409, "TestInvitationWorksOnceSecondUseFails - third accept returns 409");
    }

    // Test 5: an expired invitation fails; accepting with a different email fails
    // ORG-05
    public static void TestExpiredInvitationFailsDifferentEmailFails()
    {
        var store = new InMemoryStore();
        var svc = CreateService(store);

        var owner = RandomId();
        var user = RandomId();
        var email = "invitee@example.com";
        var wrongEmail = "wrong@example.com";

        var createResult = svc.CreateOrg(owner, "Test Org");
        Assert(createResult.Status == 201, "TestExpiredInvitationFailsDifferentEmailFails - create org");
        var orgId = ExtractJsonValue(createResult.Body, "id");

        // Create expired invitation manually (bypass service to control expiry)
        var expiredToken = RandomToken();
        var expiredTokenHash = Convert.ToHexString(SHA256.HashData(expiredToken)).ToLowerInvariant();
        var expiredInvitation = new Invitation(
            RandomId(), orgId, email, Role.Member, expiredTokenHash,
            DateTime.UtcNow.AddDays(-1), null, owner, DateTime.UtcNow.AddDays(-8));
        store.CreateInvitation(expiredInvitation);
        var expiredRawToken = Convert.ToBase64String(expiredToken);

        // Try to accept expired invitation
        var acceptExpired = svc.AcceptInvitation(user, email, expiredRawToken);
        Assert(acceptExpired.Status == 410, "TestExpiredInvitationFailsDifferentEmailFails - expired invitation returns 410");

        // Create valid invitation
        var validToken = RandomToken();
        var validTokenHash = Convert.ToHexString(SHA256.HashData(validToken)).ToLowerInvariant();
        var validInvitation = new Invitation(
            RandomId(), orgId, email, Role.Member, validTokenHash,
            DateTime.UtcNow.AddDays(7), null, owner, DateTime.UtcNow);
        store.CreateInvitation(validInvitation);
        var validRawToken = Convert.ToBase64String(validToken);

        // Try to accept with wrong email
        var acceptWrongEmail = svc.AcceptInvitation(user, wrongEmail, validRawToken);
        Assert(acceptWrongEmail.Status == 403, "TestExpiredInvitationFailsDifferentEmailFails - wrong email returns 403");

        // Accept with correct email - should succeed
        var acceptCorrect = svc.AcceptInvitation(user, email, validRawToken);
        Assert(acceptCorrect.Status == 200, "TestExpiredInvitationFailsDifferentEmailFails - correct email succeeds");
    }

    // Test 6: the raw token is not stored anywhere in the database
    // ORG-06
    public static void TestRawTokenNotStoredInDatabase()
    {
        var store = new InMemoryStore();
        var svc = CreateService(store);

        var owner = RandomId();
        var email = "invitee@example.com";

        var createResult = svc.CreateOrg(owner, "Test Org");
        Assert(createResult.Status == 201, "TestRawTokenNotStoredInDatabase - create org");
        var orgId = ExtractJsonValue(createResult.Body, "id");

        // Invite
        var inviteResult = svc.Invite(owner, orgId, email, Role.Member);
        Assert(inviteResult.Status == 201, "TestRawTokenNotStoredInDatabase - invite succeeds");
        var rawToken = inviteResult.RawToken!;

        // Verify raw token is not in any invitation record
        var tokenBytes = Convert.FromBase64String(rawToken);
        var tokenHash = Convert.ToHexString(SHA256.HashData(tokenBytes)).ToLowerInvariant();

        // Check all invitations in store - none should have the raw token
        var allInvitations = GetAllInvitationsFromStore(store);
        foreach (var inv in allInvitations)
        {
            Assert(inv.TokenHash == tokenHash, "TestRawTokenNotStoredInDatabase - stored hash matches computed hash");
            Assert(inv.TokenHash != rawToken, "TestRawTokenNotStoredInDatabase - raw token not stored as hash");
            // The raw token is base64, hash is hex - they're fundamentally different formats
            Assert(inv.TokenHash.Length == 64, "TestRawTokenNotStoredInDatabase - hash is 64 hex chars (SHA-256)");
        }

        // Also verify the raw token is not equal to any stored field
        foreach (var inv in allInvitations)
        {
            Assert(inv.Id != rawToken, "TestRawTokenNotStoredInDatabase - raw token not in id");
            Assert(inv.Email != rawToken, "TestRawTokenNotStoredInDatabase - raw token not in email");
            Assert(inv.InvitedBy != rawToken, "TestRawTokenNotStoredInDatabase - raw token not in invited_by");
        }
    }

    private static List<Invitation> GetAllInvitationsFromStore(InMemoryStore store)
    {
        // Use reflection to access private field for testing
        var field = typeof(InMemoryStore).GetField("_invitations", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var dict = (Dictionary<string, Invitation>)field!.GetValue(store)!;
        return dict.Values.ToList();
    }

    private static string ExtractJsonValue(string json, string key)
    {
        var pattern = $"\"{key}\":\"";
        var idx = json.IndexOf(pattern);
        if (idx < 0) return "";
        idx += pattern.Length;
        var end = json.IndexOf('"', idx);
        return json.Substring(idx, end - idx);
    }
}
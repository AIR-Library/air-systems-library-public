package organizations_teams

import (
	"testing"
	"time"
)

// ORG-01
func TestNonMemberCannotReadMembersOfAnotherOrg(t *testing.T) {
	store := NewInMemoryStore()
	service := NewOrganizationsTeams(store)

	// Create org1 with user1 as owner
	user1 := User{ID: "user1", Email: "user1@example.com"}
	org1, err := service.CreateOrg(user1, "Org1")
	if err != nil {
		t.Fatalf("Failed to create org1: %v", err)
	}

	// Create org2 with user2 as owner
	user2 := User{ID: "user2", Email: "user2@example.com"}
	org2, err := service.CreateOrg(user2, "Org2")
	if err != nil {
		t.Fatalf("Failed to create org2: %v", err)
	}

	// user2 tries to list members of org1 (IDOR attempt)
	_, err = service.ListMembers(user2, org1.ID)
	if err == nil {
		t.Fatal("Expected error when non-member tries to list members of another org")
	}
	if err.Error() != "not found" {
		t.Fatalf("Expected 'not found' error, got: %v", err)
	}

	// user2 tries to get org1 (IDOR attempt)
	_, err = service.GetOrg(user2, org1.ID)
	if err == nil {
		t.Fatal("Expected error when non-member tries to get another org")
	}
	if err.Error() != "not found" {
		t.Fatalf("Expected 'not found' error, got: %v", err)
	}

	// Verify org2 is accessible to user2
	_, err = service.GetOrg(user2, org2.ID)
	if err != nil {
		t.Fatalf("Expected to get org2, got error: %v", err)
	}
}

// ORG-02
func TestMemberCannotInviteAdminCan(t *testing.T) {
	store := NewInMemoryStore()
	service := NewOrganizationsTeams(store)

	// Create org with user1 as owner
	user1 := User{ID: "user1", Email: "user1@example.com"}
	org, err := service.CreateOrg(user1, "TestOrg")
	if err != nil {
		t.Fatalf("Failed to create org: %v", err)
	}

	// Invite user2 as admin
	rawToken, err := service.Invite(user1, org.ID, "user2@example.com", RoleAdmin)
	if err != nil {
		t.Fatalf("Failed to invite user2: %v", err)
	}

	// user2 accepts invitation
	user2 := User{ID: "user2", Email: "user2@example.com"}
	membership, err := service.AcceptInvitation(user2, rawToken)
	if err != nil {
		t.Fatalf("Failed to accept invitation: %v", err)
	}
	if membership.Role != RoleAdmin {
		t.Fatalf("Expected role admin, got: %v", membership.Role)
	}

	// user2 (admin) invites user3
	_, err = service.Invite(user2, org.ID, "user3@example.com", RoleMember)
	if err != nil {
		t.Fatalf("Admin should be able to invite: %v", err)
	}

	// Invite user4 as member
	rawToken4, err := service.Invite(user1, org.ID, "user4@example.com", RoleMember)
	if err != nil {
		t.Fatalf("Failed to invite user4: %v", err)
	}

	// user4 accepts invitation
	user4 := User{ID: "user4", Email: "user4@example.com"}
	_, err = service.AcceptInvitation(user4, rawToken4)
	if err != nil {
		t.Fatalf("Failed to accept invitation: %v", err)
	}

	// user4 (member) tries to invite user5
	_, err = service.Invite(user4, org.ID, "user5@example.com", RoleMember)
	if err == nil {
		t.Fatal("Expected error when member tries to invite")
	}
	if err.Error() != "forbidden" {
		t.Fatalf("Expected 'forbidden' error, got: %v", err)
	}
}

// ORG-03
func TestAdminCannotRemoveOwnerLastOwnerCannotLeave(t *testing.T) {
	store := NewInMemoryStore()
	service := NewOrganizationsTeams(store)

	// Create org with user1 as owner
	user1 := User{ID: "user1", Email: "user1@example.com"}
	org, err := service.CreateOrg(user1, "TestOrg")
	if err != nil {
		t.Fatalf("Failed to create org: %v", err)
	}

	// Invite user2 as admin
	rawToken, err := service.Invite(user1, org.ID, "user2@example.com", RoleAdmin)
	if err != nil {
		t.Fatalf("Failed to invite user2: %v", err)
	}

	// user2 accepts invitation
	user2 := User{ID: "user2", Email: "user2@example.com"}
	_, err = service.AcceptInvitation(user2, rawToken)
	if err != nil {
		t.Fatalf("Failed to accept invitation: %v", err)
	}

	// user2 (admin) tries to remove user1 (owner)
	err = service.RemoveMember(user2, org.ID, user1.ID)
	if err == nil {
		t.Fatal("Expected error when admin tries to remove owner")
	}
	if err.Error() != "forbidden" {
		t.Fatalf("Expected 'forbidden' error, got: %v", err)
	}

	// user1 (owner) tries to leave
	err = service.LeaveOrg(user1, org.ID)
	if err == nil {
		t.Fatal("Expected error when last owner tries to leave")
	}
	if err.Error() != "cannot leave as the last owner" {
		t.Fatalf("Expected 'cannot leave as the last owner' error, got: %v", err)
	}
}

// ORG-04
func TestInvitationWorksOnceSecondUseFails(t *testing.T) {
	store := NewInMemoryStore()
	service := NewOrganizationsTeams(store)

	// Create org with user1 as owner
	user1 := User{ID: "user1", Email: "user1@example.com"}
	org, err := service.CreateOrg(user1, "TestOrg")
	if err != nil {
		t.Fatalf("Failed to create org: %v", err)
	}

	// Invite user2
	rawToken, err := service.Invite(user1, org.ID, "user2@example.com", RoleMember)
	if err != nil {
		t.Fatalf("Failed to invite user2: %v", err)
	}

	// user2 accepts invitation
	user2 := User{ID: "user2", Email: "user2@example.com"}
	_, err = service.AcceptInvitation(user2, rawToken)
	if err != nil {
		t.Fatalf("Failed to accept invitation: %v", err)
	}

	// Try to accept the same invitation again
	_, err = service.AcceptInvitation(user2, rawToken)
	if err == nil {
		t.Fatal("Expected error when accepting invitation twice")
	}
	if err.Error() != "invitation already accepted" {
		t.Fatalf("Expected 'invitation already accepted' error, got: %v", err)
	}
}

// ORG-05
func TestExpiredInvitationFailsEmailMismatchFails(t *testing.T) {
	store := NewInMemoryStore()
	service := NewOrganizationsTeams(store)

	// Create org with user1 as owner
	user1 := User{ID: "user1", Email: "user1@example.com"}
	org, err := service.CreateOrg(user1, "TestOrg")
	if err != nil {
		t.Fatalf("Failed to create org: %v", err)
	}

	// Invite user2
	rawToken, err := service.Invite(user1, org.ID, "user2@example.com", RoleMember)
	if err != nil {
		t.Fatalf("Failed to invite user2: %v", err)
	}

	// Manually expire the invitation
	tokenHash := hashToken(rawToken)
	invitation, err := store.GetInvitationByTokenHash(tokenHash)
	if err != nil {
		t.Fatalf("Failed to get invitation: %v", err)
	}
	invitation.ExpiresAt = time.Now().Add(-1 * time.Hour)
	err = store.UpdateInvitation(invitation)
	if err != nil {
		t.Fatalf("Failed to update invitation: %v", err)
	}

	// Try to accept expired invitation
	user2 := User{ID: "user2", Email: "user2@example.com"}
	_, err = service.AcceptInvitation(user2, rawToken)
	if err == nil {
		t.Fatal("Expected error when accepting expired invitation")
	}
	if err.Error() != "invitation expired" {
		t.Fatalf("Expected 'invitation expired' error, got: %v", err)
	}

	// Test email mismatch
	rawToken2, err := service.Invite(user1, org.ID, "user3@example.com", RoleMember)
	if err != nil {
		t.Fatalf("Failed to invite user3: %v", err)
	}

	// user2 tries to accept user3's invitation
	user2Wrong := User{ID: "user2", Email: "user2@example.com"}
	_, err = service.AcceptInvitation(user2Wrong, rawToken2)
	if err == nil {
		t.Fatal("Expected error when accepting invitation with wrong email")
	}
	if err.Error() != "email mismatch" {
		t.Fatalf("Expected 'email mismatch' error, got: %v", err)
	}
}

// ORG-06
func TestRawTokenNotStoredInDatabase(t *testing.T) {
	store := NewInMemoryStore()
	service := NewOrganizationsTeams(store)

	// Create org with user1 as owner
	user1 := User{ID: "user1", Email: "user1@example.com"}
	org, err := service.CreateOrg(user1, "TestOrg")
	if err != nil {
		t.Fatalf("Failed to create org: %v", err)
	}

	// Invite user2
	rawToken, err := service.Invite(user1, org.ID, "user2@example.com", RoleMember)
	if err != nil {
		t.Fatalf("Failed to invite user2: %v", err)
	}

	// Check that the raw token is not stored in the invitation
	tokenHash := hashToken(rawToken)
	invitation, err := store.GetInvitationByTokenHash(tokenHash)
	if err != nil {
		t.Fatalf("Failed to get invitation: %v", err)
	}

	// The token hash should not equal the raw token
	if invitation.TokenHash == rawToken {
		t.Fatal("Raw token should not be stored in the database")
	}

	// The token hash should be a SHA-256 hash of the raw token
	expectedHash := hashToken(rawToken)
	if invitation.TokenHash != expectedHash {
		t.Fatalf("Expected token hash %s, got %s", expectedHash, invitation.TokenHash)
	}
}
// TestOnlyOwnerGrantsOwnerAdminManagesMembers proves the spec's least-privilege rules beyond ORG-02/03:
// an admin can remove and re-role a plain member, but cannot invite or promote anyone to owner, and an
// owner can. Why: the spec (amended 2026-09-26) says only an owner may grant the owner role; Go let an
// admin invite an owner. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory store.
func TestOnlyOwnerGrantsOwnerAdminManagesMembers(t *testing.T) {
	service := NewOrganizationsTeams(NewInMemoryStore())
	owner := User{ID: "owner", Email: "owner@example.com"}
	org, err := service.CreateOrg(owner, "Org")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	join := func(u User, role Role) {
		tok, err := service.Invite(owner, org.ID, u.Email, role)
		if err != nil {
			t.Fatalf("invite %s: %v", u.ID, err)
		}
		if _, err := service.AcceptInvitation(u, tok); err != nil {
			t.Fatalf("accept %s: %v", u.ID, err)
		}
	}
	admin := User{ID: "admin", Email: "admin@example.com"}
	member := User{ID: "member", Email: "member@example.com"}
	join(admin, RoleAdmin)
	join(member, RoleMember)

	if _, err := service.Invite(admin, org.ID, "x@example.com", RoleOwner); err == nil || err.Error() != "forbidden" {
		t.Fatalf("admin inviting an owner: want forbidden, got %v", err)
	}
	if err := service.ChangeRole(admin, org.ID, member.ID, RoleOwner); err == nil || err.Error() != "forbidden" {
		t.Fatalf("admin promoting to owner: want forbidden, got %v", err)
	}
	if err := service.ChangeRole(admin, org.ID, owner.ID, RoleMember); err == nil || err.Error() != "forbidden" {
		t.Fatalf("admin demoting the owner: want forbidden, got %v", err)
	}
	if err := service.ChangeRole(admin, org.ID, member.ID, RoleAdmin); err != nil {
		t.Fatalf("admin changing a member's role: %v", err)
	}
	if err := service.RemoveMember(admin, org.ID, member.ID); err != nil {
		t.Fatalf("admin removing a member: %v", err)
	}
	if err := service.ChangeRole(owner, org.ID, admin.ID, RoleOwner); err != nil {
		t.Fatalf("owner promoting to owner: %v", err)
	}
	if err := service.LeaveOrg(owner, org.ID); err != nil {
		t.Fatalf("one of two owners leaving: %v", err)
	}
}

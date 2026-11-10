package rbac

import (
	"testing"
	"time"
)

// RBAC-01
func TestRequireOwnerNonOwner(t *testing.T) {
	ResetAllData()
	user := &User{ID: "u1", Tier: TierMember}
	err := RequireOwner(user, "admin_create_user")
	if err == nil {
		t.Fatalf("expected error for non‑owner")
	}
	rbErr, ok := err.(*RBACError)
	if !ok {
		t.Fatalf("expected RBACError, got %T", err)
	}
	if rbErr.Code != 403 || rbErr.Message != "owner_only" {
		t.Fatalf("unexpected error: %+v", rbErr)
	}
	// audit entry should be recorded
	logs := GetAuditLog()
	if len(logs) == 0 {
		t.Fatalf("audit log missing")
	}
	last := logs[len(logs)-1]
	if last.Decision != "FAIL" || last.RequiredTier != TierOwner {
		t.Fatalf("audit entry incorrect: %+v", last)
	}
}

// RBAC-02
func TestRequireAdminMember(t *testing.T) {
	ResetAllData()
	user := &User{ID: "u2", Tier: TierMember}
	err := RequireAdmin(user, "admin_list_customers")
	if err == nil {
		t.Fatalf("expected error for member on admin check")
	}
	rbErr, ok := err.(*RBACError)
	if !ok {
		t.Fatalf("expected RBACError")
	}
	if rbErr.Code != 403 || rbErr.Message != "admin_only" {
		t.Fatalf("unexpected error: %+v", rbErr)
	}
}

// RBAC-03
func TestRequireAuthenticatedPublic(t *testing.T) {
	ResetAllData()
	err := RequireAuthenticated(nil, "some_endpoint")
	if err == nil {
		t.Fatalf("expected authentication error")
	}
	rbErr, ok := err.(*RBACError)
	if !ok {
		t.Fatalf("expected RBACError")
	}
	if rbErr.Code != 401 || rbErr.Message != "authentication_required" {
		t.Fatalf("unexpected error: %+v", rbErr)
	}
}

// RBAC-04
func TestCascadeDeleteUser(t *testing.T) {
	ResetAllData()
	// create user and related records
	user := &User{ID: "u3", Tier: TierMember}
	users[user.ID] = user
	sessions["s1"] = &Session{ID: "s1", UserID: user.ID}
	apiKeys["k1"] = &APIKey{ID: "k1", UserID: user.ID}
	files["f1"] = &File{ID: "f1", OwnerID: user.ID}
	preferences["p1"] = &Preference{ID: "p1", UserID: user.ID}

	if err := DeleteUser(user.ID); err != nil {
		t.Fatalf("DeleteUser returned error: %v", err)
	}
	if _, ok := GetUser(user.ID); ok {
		t.Fatalf("user not deleted")
	}
	if _, ok := GetSession("s1"); ok {
		t.Fatalf("session not deleted")
	}
	if _, ok := GetAPIKey("k1"); ok {
		t.Fatalf("apikey not deleted")
	}
	if _, ok := GetFile("f1"); ok {
		t.Fatalf("file not deleted")
	}
	if _, ok := GetPreference("p1"); ok {
		t.Fatalf("preference not deleted")
	}
	// audit entry
	found := false
	for _, e := range GetAuditLog() {
		if e.Action == "user_deleted_cascade" && e.UserID == user.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("audit log for user cascade missing")
	}
}

// RBAC-05
func TestCascadeDeleteDeployment(t *testing.T) {
	ResetAllData()
	dep := &Deployment{ID: "d1", OrgID: "org1"}
	deployments[dep.ID] = dep
	dnsRecords["dns1"] = &DNSRecord{ID: "dns1", DeploymentID: dep.ID}
	themeConfigs["tc1"] = &ThemeConfig{ID: "tc1", DeploymentID: dep.ID}
	deploymentLogs["log1"] = &DeploymentLog{ID: "log1", DeploymentID: dep.ID}

	if err := DeleteDeployment(dep.ID); err != nil {
		t.Fatalf("DeleteDeployment error: %v", err)
	}
	if _, ok := GetDeployment(dep.ID); ok {
		t.Fatalf("deployment not deleted")
	}
	if _, ok := GetDNSRecord("dns1"); ok {
		t.Fatalf("dns record not deleted")
	}
	if _, ok := GetThemeConfig("tc1"); ok {
		t.Fatalf("theme config not deleted")
	}
	if _, ok := GetDeploymentLog("log1"); ok {
		t.Fatalf("deployment log not deleted")
	}
}

// TestCascadeDeleteOrganization proves RBAC-06 as amended 2026-11-10: only an owner of the org (by its
// membership row) may delete it, another org's owner gets 404; the org's deployments (with their DNS,
// theme and logs), org API keys, invitations and memberships go; every member's user account, session
// and personal API key stays, and a member's membership of another org is untouched.
// Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the old test asserted that the org's users,
// their sessions and their keys were deleted, which the amended spec forbids. Touches: in-memory store.
// RBAC-06
func TestCascadeDeleteOrganization(t *testing.T) {
	ResetAllData()
	organizations["orgA"] = &Organization{ID: "orgA"}
	organizations["orgB"] = &Organization{ID: "orgB"}
	owner := &User{ID: "ownerA", Tier: TierOwner}
	otherOwner := &User{ID: "ownerB", Tier: TierOwner}
	member := &User{ID: "memberAB", Tier: TierMember}
	for _, u := range []*User{owner, otherOwner, member} {
		users[u.ID] = u
	}
	AddMembership("orgA", owner.ID, TierOwner)
	AddMembership("orgA", member.ID, TierMember)
	AddMembership("orgB", otherOwner.ID, TierOwner)
	AddMembership("orgB", member.ID, TierAdmin)

	deployments["dA"] = &Deployment{ID: "dA", OrgID: "orgA"}
	dnsRecords["dnsA"] = &DNSRecord{ID: "dnsA", DeploymentID: "dA"}
	deployments["dB"] = &Deployment{ID: "dB", OrgID: "orgB"}
	apiKeys["orgKeyA"] = &APIKey{ID: "orgKeyA", UserID: member.ID, OrgID: "orgA"}
	apiKeys["orgKeyB"] = &APIKey{ID: "orgKeyB", UserID: member.ID, OrgID: "orgB"}
	apiKeys["personal"] = &APIKey{ID: "personal", UserID: member.ID}
	sessions["sM"] = &Session{ID: "sM", UserID: member.ID}
	invitations["invA"] = &Invitation{ID: "invA", OrgID: "orgA", Email: "x@example.com"}
	invitations["invB"] = &Invitation{ID: "invB", OrgID: "orgB", Email: "y@example.com"}

	// Another org's owner, a member of the org, and an unknown org: 404, nothing deleted.
	for _, try := range []struct {
		who *User
		org string
	}{{otherOwner, "orgA"}, {member, "orgA"}, {owner, "orgZ"}} {
		err := DeleteOrganization(try.who, try.org)
		if e, ok := err.(*RBACError); !ok || e.Code != 404 {
			t.Fatalf("%s deleting %s: want 404, got %v", try.who.ID, try.org, err)
		}
	}
	if _, ok := GetOrganization("orgA"); !ok {
		t.Fatalf("a refused delete removed the org")
	}
	if err := DeleteOrganization(nil, "orgA"); err == nil || err.(*RBACError).Code != 401 {
		t.Fatalf("no caller: want 401, got %v", err)
	}

	if err := DeleteOrganization(owner, "orgA"); err != nil {
		t.Fatalf("DeleteOrganization error: %v", err)
	}
	gone := map[string]bool{}
	_, gone["org"] = GetOrganization("orgA")
	_, gone["deployment"] = GetDeployment("dA")
	_, gone["dns"] = GetDNSRecord("dnsA")
	_, gone["org key"] = GetAPIKey("orgKeyA")
	_, gone["invitation"] = GetInvitation("invA")
	_, gone["owner membership"] = GetMembership("orgA", owner.ID)
	_, gone["member membership"] = GetMembership("orgA", member.ID)
	for what, still := range gone {
		if still {
			t.Errorf("%s of the deleted org was kept", what)
		}
	}
	kept := map[string]bool{}
	_, kept["owner account"] = GetUser(owner.ID)
	_, kept["member account"] = GetUser(member.ID)
	_, kept["member session"] = GetSession("sM")
	_, kept["personal key"] = GetAPIKey("personal")
	_, kept["other org"] = GetOrganization("orgB")
	_, kept["other org deployment"] = GetDeployment("dB")
	_, kept["other org key"] = GetAPIKey("orgKeyB")
	_, kept["other org invitation"] = GetInvitation("invB")
	_, kept["member's other membership"] = GetMembership("orgB", member.ID)
	for what, ok := range kept {
		if !ok {
			t.Errorf("%s was deleted", what)
		}
	}
	if m, _ := GetMembership("orgB", member.ID); m == nil || m.Role != TierAdmin {
		t.Errorf("the member's orgB membership changed: %+v", m)
	}
	var logged *AuditEntry
	for _, e := range GetAuditLog() {
		if e.Action == "org_deleted_cascade" {
			e := e
			logged = &e
		}
	}
	want := map[string]int{"deployments": 1, "api_keys": 1, "invitations": 1, "memberships": 2}
	if logged == nil || logged.TargetID != "orgA" || logged.UserID != owner.ID {
		t.Fatalf("org_deleted_cascade audit entry missing or wrong: %+v", logged)
	}
	for k, v := range want {
		if logged.DeletedItems[k] != v {
			t.Errorf("deleted_items[%s] = %d, want %d", k, logged.DeletedItems[k], v)
		}
	}
}

// RBAC-07
func TestCascadeRollbackOnError(t *testing.T) {
	ResetAllData()
	user := &User{ID: "uRollback", Tier: TierMember}
	users[user.ID] = user
	sessions["sRollback"] = &Session{ID: "sRollback", UserID: user.ID}

	SetCascadeInjectError(true)
	err := DeleteUser(user.ID)
	if err == nil {
		t.Fatalf("expected simulated error")
	}
	// ensure data unchanged
	if _, ok := GetUser(user.ID); !ok {
		t.Fatalf("user should still exist after rollback")
	}
	if _, ok := GetSession("sRollback"); !ok {
		t.Fatalf("session should still exist after rollback")
	}
	SetCascadeInjectError(false)
}

// RBAC-08
func TestPermissionAuditLogged(t *testing.T) {
	ResetAllData()
	owner := &User{ID: "owner1", Tier: TierOwner}
	users[owner.ID] = owner

	// successful check
	if err := RequireOwner(owner, "admin_create_user"); err != nil {
		t.Fatalf("owner should pass")
	}
	// failed check
	nonOwner := &User{ID: "nonowner", Tier: TierMember}
	_ = RequireOwner(nonOwner, "admin_create_user")

	logs := GetAuditLog()
	var passFound, failFound bool
	for _, e := range logs {
		if e.UserID == owner.ID && e.Decision == "PASS" && e.RequiredTier == TierOwner {
			passFound = true
		}
		if e.UserID == nonOwner.ID && e.Decision == "FAIL" && e.RequiredTier == TierOwner {
			failFound = true
		}
	}
	if !passFound || !failFound {
		t.Fatalf("audit entries for pass/fail missing")
	}
}

// RBAC-09
func TestTierHierarchy(t *testing.T) {
	ResetAllData()
	owner := &User{ID: "o1", Tier: TierOwner}
	admin := &User{ID: "a1", Tier: TierAdmin}
	member := &User{ID: "m1", Tier: TierMember}

	if err := RequireAdmin(admin, "admin_action"); err != nil {
		t.Fatalf("admin should be allowed")
	}
	if err := RequireOwner(owner, "owner_action"); err != nil {
		t.Fatalf("owner should be allowed")
	}
	if err := RequireOwner(admin, "owner_action"); err == nil {
		t.Fatalf("admin should NOT be allowed owner action")
	}
	if err := RequireAdmin(member, "admin_action"); err == nil {
		t.Fatalf("member should NOT be allowed admin action")
	}
}

// RBAC-10
func TestPermissionCheckResponseTime(t *testing.T) {
	ResetAllData()
	user := &User{ID: "fast", Tier: TierOwner}
	start := time.Now()
	if err := RequireOwner(user, "fast_endpoint"); err != nil {
		t.Fatalf("owner check failed")
	}
	elapsed := time.Since(start)
	if elapsed > 10*time.Millisecond {
		t.Fatalf("permission check took %v, exceeds 10ms", elapsed)
	}
}
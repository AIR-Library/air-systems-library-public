package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// fakeBilling is the in-memory PlanChanger the tests install instead of Stripe: it records each
// call and never touches the network. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
type fakeBilling struct {
	calls []string // "subscriptionID->tier"
}

// ChangePlan records the call and succeeds. Inputs: subscription id, tier. Output: nil.
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
func (f *fakeBilling) ChangePlan(_ context.Context, subscriptionID, tier string) error {
	f.calls = append(f.calls, subscriptionID+"->"+tier)
	return nil
}

func setupTestEnv(t *testing.T) *http.ServeMux {
	if err := InitDB(":memory:"); err != nil {
		t.Fatalf("DB init failed: %v", err)
	}
	mux := http.NewServeMux()
	RegisterRoutes(mux)
	return mux
}

// Helper to perform request with auth & CSRF
func doRequest(mux *http.ServeMux, method, path string, body map[string]string, userID int64, role string, extraHeaders map[string]string) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-ID", strconv.FormatInt(userID, 10))
	req.Header.Set("X-User-Role", role)
	if method == http.MethodPost {
		req.Header.Set(csrfHeader, csrfToken)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	AuthMiddleware(mux).ServeHTTP(rr, req)
	return rr
}

// ---------- Tests ----------
func TestCreateUserHappyPath(t *testing.T) {
	mux := setupTestEnv(t)
	// create owner first
	_, err := db.Exec(`INSERT INTO users (email,name,role,status,created_at) VALUES (?,?,?,?,?)`,
		"owner@example.com", "Owner", "owner", "active", time.Now().UTC())
	if err != nil {
		t.Fatalf("owner insert failed: %v", err)
	}
	row := db.QueryRow(`SELECT id FROM users WHERE email=?`, "owner@example.com")
	var ownerID int64
	row.Scan(&ownerID)

	payload := map[string]string{
		"action": "create",
		"email":  "newuser@example.com",
		"name":   "New User",
		"tier":   "admin",
	}
	resp := doRequest(mux, http.MethodPost, "/admin/users/action", payload, ownerID, "owner", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["success"] != true {
		t.Fatalf("expected success true")
	}
	if out["email"] != "newuser@example.com" {
		t.Fatalf("email mismatch")
	}
}

func TestCreateUserDuplicateEmail(t *testing.T) {
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	// duplicate email
	_, _ = db.Exec(`INSERT INTO users (email,name,role,status,created_at) VALUES (?,?,?,?,?)`,
		"dup@example.com", "Dup", "admin", "active", time.Now().UTC())
	payload := map[string]string{
		"action": "create",
		"email":  "dup@example.com",
		"name":   "Another",
		"tier":   "user",
	}
	resp := doRequest(mux, http.MethodPost, "/admin/users/action", payload, ownerID, "owner", nil)
	if resp.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", resp.Code)
	}
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["error"] != "email_exists" {
		t.Fatalf("expected email_exists error")
	}
}

func TestCreateUserNonOwner(t *testing.T) {
	mux := setupTestEnv(t)
	seedOwner(t) // an owner exists; the caller below is an admin
	// create a non-owner user
	_, _ = db.Exec(`INSERT INTO users (email,name,role,status,created_at) VALUES (?,?,?,?,?)`,
		"admin@example.com", "Admin", "admin", "active", time.Now().UTC())
	row := db.QueryRow(`SELECT id FROM users WHERE email=?`, "admin@example.com")
	var adminID int64
	row.Scan(&adminID)

	payload := map[string]string{
		"action": "create",
		"email":  "new2@example.com",
		"name":   "New2",
		"tier":   "user",
	}
	resp := doRequest(mux, http.MethodPost, "/admin/users/action", payload, adminID, "admin", nil)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.Code)
	}
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["error"] != "owner_only" {
		t.Fatalf("expected owner_only error")
	}
}

func TestResetPasswordHappyPath(t *testing.T) {
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	// create target user
	_, _ = db.Exec(`INSERT INTO users (email,name,role,status,created_at) VALUES (?,?,?,?,?)`,
		"user@example.com", "User", "user", "active", time.Now().UTC())
	row := db.QueryRow(`SELECT id FROM users WHERE email=?`, "user@example.com")
	var userID int64
	row.Scan(&userID)

	payload := map[string]string{
		"action":   "reset_password",
		"user_id":  strconv.FormatInt(userID, 10),
	}
	resp := doRequest(mux, http.MethodPost, "/admin/users/action", payload, ownerID, "owner", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["status"] != "reset_email_sent" {
		t.Fatalf("unexpected status")
	}
}

func TestResetPasswordOwnAccount(t *testing.T) {
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	payload := map[string]string{
		"action":  "reset_password",
		"user_id": strconv.FormatInt(ownerID, 10),
	}
	resp := doRequest(mux, http.MethodPost, "/admin/users/action", payload, ownerID, "owner", nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.Code)
	}
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["error"] != "cannot_reset_own_password" {
		t.Fatalf("expected cannot_reset_own_password")
	}
}

func TestChangeRoleHappyPath(t *testing.T) {
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	// create user
	_, _ = db.Exec(`INSERT INTO users (email,name,role,status,created_at) VALUES (?,?,?,?,?)`,
		"user2@example.com", "User2", "user", "active", time.Now().UTC())
	row := db.QueryRow(`SELECT id FROM users WHERE email=?`, "user2@example.com")
	var userID int64
	row.Scan(&userID)

	payload := map[string]string{
		"action":   "change_role",
		"user_id":  strconv.FormatInt(userID, 10),
		"new_tier": "admin",
	}
	resp := doRequest(mux, http.MethodPost, "/admin/users/action", payload, ownerID, "owner", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["new_tier"] != "admin" {
		t.Fatalf("role not changed")
	}
}

func TestChangeRoleLastOwner(t *testing.T) {
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	// attempt to demote self (last owner)
	payload := map[string]string{
		"action":   "change_role",
		"user_id":  strconv.FormatInt(ownerID, 10),
		"new_tier": "admin",
	}
	resp := doRequest(mux, http.MethodPost, "/admin/users/action", payload, ownerID, "owner", nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.Code)
	}
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["error"] != "cannot_change_own_role" {
		t.Fatalf("expected cannot_change_own_role")
	}
}

func TestSuspendUserHappyPath(t *testing.T) {
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	_, _ = db.Exec(`INSERT INTO users (email,name,role,status,created_at) VALUES (?,?,?,?,?)`,
		"user3@example.com", "User3", "user", "active", time.Now().UTC())
	row := db.QueryRow(`SELECT id FROM users WHERE email=?`, "user3@example.com")
	var userID int64
	row.Scan(&userID)

	payload := map[string]string{
		"action":   "suspend",
		"user_id":  strconv.FormatInt(userID, 10),
		"reason":   "policy violation",
	}
	resp := doRequest(mux, http.MethodPost, "/admin/users/action", payload, ownerID, "owner", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["suspended"] != true {
		t.Fatalf("suspend flag missing")
	}
}

func TestSuspendOwnAccount(t *testing.T) {
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	payload := map[string]string{
		"action":  "suspend",
		"user_id": strconv.FormatInt(ownerID, 10),
		"reason":  "self",
	}
	resp := doRequest(mux, http.MethodPost, "/admin/users/action", payload, ownerID, "owner", nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400")
	}
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["error"] != "cannot_suspend_yourself" {
		t.Fatalf("expected cannot_suspend_yourself")
	}
}

func TestCustomersListPagination(t *testing.T) {
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	// insert 3 customers
	for i := 1; i <= 3; i++ {
		_, _ = db.Exec(`INSERT INTO customers (email,name,tier,signup_date,invoice_count,status) VALUES (?,?,?,?,?,?)`,
			"c"+strconv.Itoa(i)+"@example.com", "Cust"+strconv.Itoa(i), "user", time.Now().UTC(), i, "active")
	}
	resp := doRequest(mux, http.MethodGet, "/admin/customers?limit=2&offset=1", nil, ownerID, "owner", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200")
	}
	var list []map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&list)
	if len(list) != 2 {
		t.Fatalf("expected 2 items, got %d", len(list))
	}
	if list[0]["email"] != "c2@example.com" {
		t.Fatalf("unexpected first item")
	}
}

func TestCustomersDetail(t *testing.T) {
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	_, _ = db.Exec(`INSERT INTO customers (email,name,tier,signup_date,invoice_count,status) VALUES (?,?,?,?,?,?)`,
		"detail@example.com", "Detail", "admin", time.Now().UTC(), 5, "active")
	row := db.QueryRow(`SELECT id FROM customers WHERE email=?`, "detail@example.com")
	var cid int64
	row.Scan(&cid)

	resp := doRequest(mux, http.MethodGet, "/admin/customers/"+strconv.FormatInt(cid, 10), nil, ownerID, "owner", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200")
	}
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["email"] != "detail@example.com" {
		t.Fatalf("email mismatch")
	}
	if out["subscription_status"] != "active" {
		t.Fatalf("status mismatch")
	}
}

func TestChangePlanStripeCalled(t *testing.T) {
	// Stripe sits behind the PlanChanger interface; the in-memory fake proves it was called without
	// any network call (a dummy key against the real API can only fail).
	fake := &fakeBilling{}
	prev := Billing
	Billing = fake
	defer func() { Billing = prev }()
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	_, _ = db.Exec(`INSERT INTO customers (email,name,tier,signup_date,invoice_count,status,stripe_subscription_id) VALUES (?,?,?,?,?,?,?)`,
		"plan@example.com", "PlanUser", "user", time.Now().UTC(), 0, "active", "sub_123")
	row := db.QueryRow(`SELECT id FROM customers WHERE email=?`, "plan@example.com")
	var cid int64
	row.Scan(&cid)

	payload := map[string]string{
		"action":    "change_plan",
		"new_tier":  "admin",
	}
	resp := doRequest(mux, http.MethodPost, "/admin/customers/"+strconv.FormatInt(cid, 10)+"/action", payload, ownerID, "owner", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["new_tier"] != "admin" {
		t.Fatalf("plan not changed")
	}
	if len(fake.calls) != 1 || fake.calls[0] != "sub_123->admin" {
		t.Fatalf("expected one Stripe plan change for sub_123 to admin, got %v", fake.calls)
	}
}

func TestQueueRefund(t *testing.T) {
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	// create dummy invoice record (not a real table, assume exists)
	_, _ = db.Exec(`INSERT INTO refunds (invoice_id, amount, reason, status, created_by, created_at) VALUES (?,?,?,?,?,?)`,
		1, 1000, "test", "succeeded", ownerID, time.Now().UTC())
	payload := map[string]string{
		"action":     "queue_refund",
		"invoice_id": "1",
		"amount":     "500",
		"reason":     "partial",
	}
	resp := doRequest(mux, http.MethodPost, "/admin/customers/1/action", payload, ownerID, "owner", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200")
	}
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["status"] != "queued" {
		t.Fatalf("refund not queued")
	}
}

func TestCreateDeployment(t *testing.T) {
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	_, _ = db.Exec(`INSERT INTO customers (email,name,tier,signup_date,invoice_count,status) VALUES (?,?,?,?,?,?)`,
		"dep@example.com", "DepCust", "user", time.Now().UTC(), 0, "active")
	row := db.QueryRow(`SELECT id FROM customers WHERE email=?`, "dep@example.com")
	var cid int64
	row.Scan(&cid)

	payload := map[string]string{
		"action":      "create",
		"customer_id": strconv.FormatInt(cid, 10),
		"domain":      "example.com",
		"tier":        "user",
		"theme_id":    "1",
	}
	resp := doRequest(mux, http.MethodPost, "/admin/deployments/action", payload, ownerID, "owner", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200")
	}
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["domain"] != "example.com" {
		t.Fatalf("domain mismatch")
	}
}

func TestPublishDeployment(t *testing.T) {
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	_, _ = db.Exec(`INSERT INTO deployments (customer_id,domain,tier,theme_id,status) VALUES (?,?,?,?,?)`,
		1, "pub.com", "user", 1, "draft")
	row := db.QueryRow(`SELECT id FROM deployments WHERE domain=?`, "pub.com")
	var depID int64
	row.Scan(&depID)

	payload := map[string]string{
		"action":        "publish",
		"deployment_id": strconv.FormatInt(depID, 10),
	}
	headers := map[string]string{
		"X-Can-Publish": "true",
	}
	resp := doRequest(mux, http.MethodPost, "/admin/deployments/action", payload, ownerID, "owner", headers)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200")
	}
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["status"] != "live" {
		t.Fatalf("deployment not live")
	}
}

func TestGovernanceApprove(t *testing.T) {
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	_, _ = db.Exec(`INSERT INTO actions (action_type,actor_id,submitted_at,status) VALUES (?,?,?,?)`,
		"user_create", 2, time.Now().UTC(), "pending")
	row := db.QueryRow(`SELECT id FROM actions WHERE action_type='user_create'`)
	var actID int64
	row.Scan(&actID)

	payload := map[string]string{
		"decide": "approve",
	}
	resp := doRequest(mux, http.MethodPost, "/admin/governance/actions/"+strconv.FormatInt(actID, 10)+"/decide", payload, ownerID, "owner", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200")
	}
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["status"] != "approved" {
		t.Fatalf("not approved")
	}
}

func TestGovernanceReject(t *testing.T) {
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	_, _ = db.Exec(`INSERT INTO actions (action_type,actor_id,submitted_at,status) VALUES (?,?,?,?)`,
		"user_delete", 2, time.Now().UTC(), "pending")
	row := db.QueryRow(`SELECT id FROM actions WHERE action_type='user_delete'`)
	var actID int64
	row.Scan(&actID)

	payload := map[string]string{
		"decide": "reject",
		"reason": "not allowed",
	}
	resp := doRequest(mux, http.MethodPost, "/admin/governance/actions/"+strconv.FormatInt(actID, 10)+"/decide", payload, ownerID, "owner", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200")
	}
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["status"] != "rejected" {
		t.Fatalf("not rejected")
	}
}

func TestAuditLogSearch(t *testing.T) {
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	// create audit entries
	_, _ = db.Exec(`INSERT INTO audit_log (timestamp,actor_id,action,resource_type,resource_id) VALUES (?,?,?,?,?)`,
		time.Now().UTC(), ownerID, "test_action", "user", 1)
	resp := doRequest(mux, http.MethodGet, "/admin/governance/audit-log?limit=10", nil, ownerID, "owner", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200")
	}
	var list []map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&list)
	if len(list) == 0 {
		t.Fatalf("expected at least one audit entry")
	}
	if list[0]["action"] != "test_action" {
		t.Fatalf("unexpected audit action")
	}
}

// ---------- Helper ----------
func seedOwner(t *testing.T) int64 {
	_, err := db.Exec(`INSERT INTO users (email,name,role,status,created_at) VALUES (?,?,?,?,?)`,
		"owner2@example.com", "Owner2", "owner", "active", time.Now().UTC())
	if err != nil {
		t.Fatalf("seed owner failed: %v", err)
	}
	row := db.QueryRow(`SELECT id FROM users WHERE email=?`, "owner2@example.com")
	var id int64
	row.Scan(&id)
	return id
}

// ---------- End of Tests ----------
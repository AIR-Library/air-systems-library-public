package admin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"database/sql"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeBilling is the in-memory PlanChanger the tests install instead of Stripe: it records each
// update and never touches the network. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP;
// changed the same day (ADMIN-12): it answers the subscription's items and records the item id and
// price each update is sent.
type fakeBilling struct {
	items map[string][]string // subscription -> item ids (default: one item "si_<subscription>")
	calls []string            // "subscriptionID|itemID|priceID"
}

// PriceID maps a tier to "price_<tier>".
func (f *fakeBilling) PriceID(tier string) (string, error) { return "price_" + tier, nil }

// SubscriptionItems returns the configured items.
func (f *fakeBilling) SubscriptionItems(_ context.Context, subscriptionID string) ([]string, error) {
	if ids, ok := f.items[subscriptionID]; ok {
		return ids, nil
	}
	return []string{"si_" + subscriptionID}, nil
}

// UpdateSubscriptionItem records the update and succeeds.
func (f *fakeBilling) UpdateSubscriptionItem(_ context.Context, subscriptionID, itemID, priceID string) error {
	f.calls = append(f.calls, subscriptionID+"|"+itemID+"|"+priceID)
	return nil
}

// fakeMail records the invites and reset links the admin system sends (no network in tests).
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-01, ADMIN-04).
type fakeMail struct {
	invites, resets map[string]string // email -> token
}

func (f *fakeMail) SendInvite(email, token string) error        { f.invites[email] = token; return nil }
func (f *fakeMail) SendPasswordReset(email, token string) error { f.resets[email] = token; return nil }

// tokenStored reports whether the SHA-256 of token is stored for purpose (and the raw token is not).
func tokenStored(t *testing.T, token, purpose string) bool {
	t.Helper()
	h := sha256.Sum256([]byte(token))
	var n, raw int
	db.QueryRow(`SELECT COUNT(*) FROM user_tokens WHERE token_hash=? AND purpose=?`, hex.EncodeToString(h[:]), purpose).Scan(&n)
	db.QueryRow(`SELECT COUNT(*) FROM user_tokens WHERE token_hash=?`, token).Scan(&raw)
	return n == 1 && raw == 0
}

// setupTestEnv opens a fresh in-memory database, registers the routes, and opts in to reading the
// caller's id from X-User-ID (TrustedHeaderResolver), which the tests stand in for a trusted proxy.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review on PR 19: the
// default resolver now fails closed, so the tests opt in explicitly). Touches: the test database.
func setupTestEnv(t *testing.T) *http.ServeMux {
	ResolveUserID = TrustedHeaderResolver("X-User-ID")
	Mail = &fakeMail{invites: map[string]string{}, resets: map[string]string{}} // 2026-11-10: emails are really sent
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
// ADMIN-01
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
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: ADMIN-01 says "invite sent"; the invite carries a token
	// stored only as its hash.
	invite := Mail.(*fakeMail).invites["newuser@example.com"]
	if invite == "" || !tokenStored(t, invite, "invite") {
		t.Fatalf("invite not sent, or its token not stored as a hash: %q", invite)
	}
}

// ADMIN-02
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

// ADMIN-03
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

// ADMIN-04
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
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: ADMIN-04 says "email sent"; prove it reached the mailer.
	reset := Mail.(*fakeMail).resets["user@example.com"]
	if reset == "" || !tokenStored(t, reset, "password_reset") {
		t.Fatalf("reset email not sent, or its token not stored as a hash: %q", reset)
	}
}

// ADMIN-05
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

// ADMIN-06
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
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: ADMIN-06 also says "audit logged".
	var role string
	var audits int
	db.QueryRow(`SELECT role FROM users WHERE id=?`, userID).Scan(&role)
	db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='role_changed' AND resource_id=? AND old_value='user' AND new_value='admin'`, userID).Scan(&audits)
	if role != "admin" || audits != 1 {
		t.Fatalf("role %q, role_changed audit rows %d", role, audits)
	}
}

// ADMIN-07
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

// ADMIN-08
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

// ADMIN-09
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

// ADMIN-10
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
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: ADMIN-10 also says "all fields present".
	for _, f := range []string{"customer_id", "email", "name", "tier", "signup_date", "invoice_count", "status"} {
		if _, ok := list[0][f]; !ok {
			t.Errorf("customers list is missing %s", f)
		}
	}
}

// ADMIN-11
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
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: ADMIN-11 says "all fields present".
	for _, f := range []string{"customer_id", "email", "name", "tier", "subscription_status", "payment_method", "address", "notes"} {
		if _, ok := out[f]; !ok {
			t.Errorf("customer detail is missing %s", f)
		}
	}
}

// ADMIN-12
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
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-12, amended): the update carries the existing item
	// id and the new price, so no second item is added.
	if len(fake.calls) != 1 || fake.calls[0] != "sub_123|si_sub_123|price_admin" {
		t.Fatalf("expected one update of item si_sub_123 to price_admin, got %v", fake.calls)
	}
	var audits int
	db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='plan_changed' AND resource_id=?`, cid).Scan(&audits)
	if audits != 1 {
		t.Fatalf("expected one plan_changed audit row, got %d", audits)
	}
	// An unknown tier is 400, a subscription with two items is 409; neither reaches the update.
	path := "/admin/customers/" + strconv.FormatInt(cid, 10) + "/action"
	if r := doRequest(mux, http.MethodPost, path, map[string]string{"action": "change_plan", "new_tier": "platinum"}, ownerID, "owner", nil); r.Code != http.StatusBadRequest {
		t.Fatalf("unknown tier: expected 400, got %d", r.Code)
	}
	fake.items = map[string][]string{"sub_123": {"si_a", "si_b"}}
	r := doRequest(mux, http.MethodPost, path, map[string]string{"action": "change_plan", "new_tier": "user"}, ownerID, "owner", nil)
	var amb map[string]interface{}
	_ = json.NewDecoder(r.Body).Decode(&amb)
	if r.Code != http.StatusConflict || amb["error"] != "subscription_item_ambiguous" {
		t.Fatalf("two items: expected 409 subscription_item_ambiguous, got %d %v", r.Code, amb)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("a refused change must not update Stripe: %v", fake.calls)
	}
}

// ADMIN-13
func TestQueueRefund(t *testing.T) {
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: queue_refund now checks the invoice (spec: "invoice exists,
	// status='succeeded'"), so the test seeds a real invoice of customer 1 instead of a fake refund row.
	_, _ = db.Exec(`INSERT INTO customers (id,email,name,tier,signup_date,invoice_count,status) VALUES (1,?,?,?,?,?,?)`,
		"ref@example.com", "Ref", "user", time.Now().UTC(), 1, "active")
	_, _ = db.Exec(`INSERT INTO invoices (id, customer_id, amount, status) VALUES (1, 1, 1000, 'succeeded')`)
	_, _ = db.Exec(`INSERT INTO invoices (id, customer_id, amount, status) VALUES (2, 1, 1000, 'failed')`)
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
	var st string
	if err := db.QueryRow(`SELECT status FROM refunds WHERE id=?`, int64(out["refund_id"].(float64))).Scan(&st); err != nil || st != "queued" {
		t.Fatalf("refund row: %q (%v)", st, err)
	}
	// The invoice checks: unknown or another customer's invoice, a failed invoice, and a total above it.
	for _, c := range []struct {
		invoice, amount, code string
		status             int
	}{
		{"99", "10", "invoice_not_found", http.StatusNotFound},
		{"2", "10", "invalid_invoice_status", http.StatusBadRequest},
		{"1", "501", "refund_exceeds_invoice", http.StatusBadRequest},
		{"1", "0", "invalid_amount", http.StatusBadRequest},
	} {
		r := doRequest(mux, http.MethodPost, "/admin/customers/1/action",
			map[string]string{"action": "queue_refund", "invoice_id": c.invoice, "amount": c.amount, "reason": "x"}, ownerID, "owner", nil)
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.Code != c.status || body["error"] != c.code {
			t.Errorf("invoice %s amount %s: expected %d %s, got %d %v", c.invoice, c.amount, c.status, c.code, r.Code, body)
		}
	}
	if r := doRequest(mux, http.MethodPost, "/admin/customers/2/action",
		map[string]string{"action": "queue_refund", "invoice_id": "1", "amount": "10", "reason": "x"}, ownerID, "owner", nil); r.Code != http.StatusNotFound {
		t.Errorf("another customer's invoice: expected 404, got %d", r.Code)
	}
}

// ADMIN-14
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
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: ADMIN-14 also says "config initialized".
	var theme int64
	if err := db.QueryRow(`SELECT theme_id FROM deployment_configs WHERE deployment_id=?`, int64(out["deployment_id"].(float64))).Scan(&theme); err != nil || theme != 1 {
		t.Fatalf("deployment config not initialised: %d (%v)", theme, err)
	}
}

// ADMIN-15
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
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: ADMIN-15 says "double-gate checked": with the server-side
	// flag off, an owner still cannot publish (the request header is ignored), and an admin never can.
	_, _ = db.Exec(`INSERT INTO deployments (customer_id,domain,tier,theme_id,status) VALUES (?,?,?,?,?)`, 1, "gate.com", "user", 1, "draft")
	var gateID int64
	db.QueryRow(`SELECT id FROM deployments WHERE domain='gate.com'`).Scan(&gateID)
	gate := map[string]string{"action": "publish", "deployment_id": strconv.FormatInt(gateID, 10)}
	SafetyFlags.CanPublish = false
	r := doRequest(mux, http.MethodPost, "/admin/deployments/action", gate, ownerID, "owner", headers)
	SafetyFlags.CanPublish = true
	if r.Code != http.StatusForbidden {
		t.Fatalf("publish with the safety flag off: expected 403, got %d", r.Code)
	}
	res, _ := db.Exec(`INSERT INTO users (email,name,role,status,created_at) VALUES (?,?,?,?,?)`, "adm@example.com", "Adm", "admin", "active", time.Now().UTC())
	adminID, _ := res.LastInsertId()
	if r := doRequest(mux, http.MethodPost, "/admin/deployments/action", gate, adminID, "owner", headers); r.Code != http.StatusForbidden {
		t.Fatalf("publish by an admin: expected 403, got %d", r.Code)
	}
	var st string
	db.QueryRow(`SELECT status FROM deployments WHERE id=?`, gateID).Scan(&st)
	if st != "draft" {
		t.Fatalf("a refused publish changed the status to %q", st)
	}
}

// ADMIN-16
func TestGovernanceApprove(t *testing.T) {
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-16: "action executed"): approval now runs the
	// action, so the test submits one with an executor (change_role on a real user) and checks it ran; an
	// action type without an executor is refused and stays pending.
	res, _ := db.Exec(`INSERT INTO users (email,name,role,status,created_at) VALUES (?,?,?,?,?)`,
		"target@example.com", "Target", "user", "active", time.Now().UTC())
	targetID, _ := res.LastInsertId()
	_, _ = db.Exec(`INSERT INTO actions (action_type,actor_id,target_resource_id,params,submitted_at,status) VALUES (?,?,?,?,?,?)`,
		"change_role", 2, targetID, `{"new_tier":"admin"}`, time.Now().UTC(), "pending")
	row := db.QueryRow(`SELECT id FROM actions WHERE action_type='change_role'`)
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
	var role string
	var result sql.NullString
	db.QueryRow(`SELECT role FROM users WHERE id=?`, targetID).Scan(&role)
	db.QueryRow(`SELECT execution_result FROM actions WHERE id=?`, actID).Scan(&result)
	if role != "admin" || !strings.Contains(result.String, `"new_tier":"admin"`) {
		t.Fatalf("the approved action did not run: role %q, result %q", role, result.String)
	}
	res, _ = db.Exec(`INSERT INTO actions (action_type,actor_id,submitted_at,status) VALUES (?,?,?,?)`, "launch_rocket", 2, time.Now().UTC(), "pending")
	otherID, _ := res.LastInsertId()
	r := doRequest(mux, http.MethodPost, "/admin/governance/actions/"+strconv.FormatInt(otherID, 10)+"/decide", payload, ownerID, "owner", nil)
	var st string
	db.QueryRow(`SELECT status FROM actions WHERE id=?`, otherID).Scan(&st)
	if r.Code != http.StatusUnprocessableEntity || st != "pending" {
		t.Fatalf("an action with no executor must not be approved: %d, status %q", r.Code, st)
	}
}

// ADMIN-17
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
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: ADMIN-17 also says "reason logged".
	var reason, rejection string
	db.QueryRow(`SELECT reason FROM audit_log WHERE action='action_rejected' AND resource_id=?`, actID).Scan(&reason)
	db.QueryRow(`SELECT rejection_reason FROM actions WHERE id=?`, actID).Scan(&rejection)
	if reason != "not allowed" || rejection != "not allowed" {
		t.Fatalf("reason not logged: audit %q, action %q", reason, rejection)
	}
}

// countDecisionAudits counts the action_approved / action_rejected audit rows for one action.
// Input: the action id. Output: the count. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP
// (CodeRabbit review on PR 19). Touches: the test SQLite database (read).
func countDecisionAudits(t *testing.T, actID int64) int {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE resource_type='action' AND resource_id=?
		AND action IN ('action_approved','action_rejected')`, actID).Scan(&n); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return n
}

// TestGovernanceDecideTwiceConflicts: once an action is approved, a second decide on it (here a
// reject) gets 409 action_not_pending, leaves the action approved and writes no second audit row.
// It also calls decideAction directly on the decided action, which is what a request that passed the
// status check just before a concurrent one committed would reach: the conditional UPDATE must still
// answer 409 and write nothing. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit
// review on PR 19). Touches: the test SQLite database.
func TestGovernanceDecideTwiceConflicts(t *testing.T) {
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: approval executes the action, so it is one with an
	// executor (suspend_user on a real user); "user_create" has none and would now be refused.
	ures, _ := db.Exec(`INSERT INTO users (email,name,role,status,created_at) VALUES (?,?,?,?,?)`,
		"victim@example.com", "Victim", "user", "active", time.Now().UTC())
	targetID, _ := ures.LastInsertId()
	res, err := db.Exec(`INSERT INTO actions (action_type,actor_id,target_resource_id,params,submitted_at,status) VALUES (?,?,?,?,?,?)`,
		"suspend_user", 2, targetID, `{"reason":"abuse"}`, time.Now().UTC(), "pending")
	if err != nil {
		t.Fatalf("seed action: %v", err)
	}
	actID, _ := res.LastInsertId()
	path := "/admin/governance/actions/" + strconv.FormatInt(actID, 10) + "/decide"

	first := doRequest(mux, http.MethodPost, path, map[string]string{"decide": "approve"}, ownerID, "owner", nil)
	if first.Code != http.StatusOK {
		t.Fatalf("first decide: expected 200, got %d %s", first.Code, first.Body.String())
	}
	if got := countDecisionAudits(t, actID); got != 1 {
		t.Fatalf("after first decide: expected 1 audit row, got %d", got)
	}

	second := doRequest(mux, http.MethodPost, path, map[string]string{"decide": "reject", "reason": "too late"}, ownerID, "owner", nil)
	if second.Code != http.StatusConflict {
		t.Fatalf("second decide: expected 409, got %d %s", second.Code, second.Body.String())
	}
	var out map[string]interface{}
	_ = json.NewDecoder(second.Body).Decode(&out)
	if out["error"] != "action_not_pending" {
		t.Fatalf("second decide: expected action_not_pending, got %v", out["error"])
	}

	status, body := decideAction(ownerID, actID, "approve", "")
	if status != http.StatusConflict || body["error"] != "action_not_pending" {
		t.Fatalf("racing decide: expected 409 action_not_pending, got %d %v", status, body)
	}
	status, body = decideAction(ownerID, actID, "reject", "racing")
	if status != http.StatusConflict {
		t.Fatalf("racing reject: expected 409, got %d %v", status, body)
	}

	if got := countDecisionAudits(t, actID); got != 1 {
		t.Fatalf("expected exactly 1 audit row after the conflicting decides, got %d", got)
	}
	var st string
	if err := db.QueryRow(`SELECT status FROM actions WHERE id=?`, actID).Scan(&st); err != nil || st != "approved" {
		t.Fatalf("expected the action to stay approved, got %q (%v)", st, err)
	}
}

// TestDefaultResolverFailsClosed: with no resolver installed (the default), a request carrying an
// active owner's id in X-User-ID gets 401 and does not reach the handler; no user is created.
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review on PR 19, security).
// Touches: the test SQLite database.
func TestDefaultResolverFailsClosed(t *testing.T) {
	mux := setupTestEnv(t)
	ownerID := seedOwner(t)
	ResolveUserID = nil
	defer func() { ResolveUserID = TrustedHeaderResolver("X-User-ID") }()

	read := doRequest(mux, http.MethodGet, "/admin/customers", nil, ownerID, "owner", nil)
	if read.Code != http.StatusUnauthorized {
		t.Fatalf("GET with owner X-User-ID and no resolver: expected 401, got %d %s", read.Code, read.Body.String())
	}
	payload := map[string]string{"action": "create", "email": "forged@example.com", "name": "Forged", "tier": "owner"}
	write := doRequest(mux, http.MethodPost, "/admin/users/action", payload, ownerID, "owner", nil)
	if write.Code != http.StatusUnauthorized {
		t.Fatalf("POST with owner X-User-ID and no resolver: expected 401, got %d %s", write.Code, write.Body.String())
	}
	var out map[string]interface{}
	_ = json.NewDecoder(write.Body).Decode(&out)
	if out["error"] != "unauthenticated" {
		t.Fatalf("expected error unauthenticated, got %v", out["error"])
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM users WHERE email='forged@example.com'`).Scan(&n)
	if n != 0 {
		t.Fatalf("expected no user created, found %d", n)
	}
}

// ADMIN-18
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
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: ADMIN-18 says "correct filters applied, pagination works".
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		_, _ = db.Exec(`INSERT INTO audit_log (timestamp,actor_id,action,resource_type,resource_id) VALUES (?,?,?,?,?)`,
			base.Add(time.Duration(i)*time.Hour), ownerID, "page_action", "user", 7)
	}
	get := func(q string) []map[string]interface{} {
		r := doRequest(mux, http.MethodGet, "/admin/governance/audit-log?"+q, nil, ownerID, "owner", nil)
		var l []map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&l)
		return l
	}
	if l := get("action_type=page_action&resource_id=7&limit=2&offset=0"); len(l) != 2 {
		t.Fatalf("page 1: expected 2, got %d", len(l))
	}
	if l := get("action_type=page_action&limit=2&offset=4"); len(l) != 1 {
		t.Fatalf("last page: expected 1, got %d", len(l))
	}
	for _, e := range get("action_type=page_action&limit=100") {
		if e["action"] != "page_action" {
			t.Fatalf("the action filter let %v through", e["action"])
		}
	}
	if l := get("action_type=page_action&resource_id=8"); len(l) != 0 {
		t.Fatalf("the resource filter let %d rows through", len(l))
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
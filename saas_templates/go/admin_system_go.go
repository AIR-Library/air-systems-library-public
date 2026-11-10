// Package admin is the AOI Systems Library admin-system template: owner/admin gated user,
// customer, deployment and governance administration over SQLite, with CSRF on every POST and an
// audit_log row for every mutation.
//
// Repair 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): the suite failed at `go mod tidy`
// because it imported github.com/stripe/stripe-go/v74/sub, a package that does not exist. Stripe now
// sits behind the PlanChanger interface (a stdlib HTTPS adapter for production, an in-memory fake in
// tests), handlers read JSON or form bodies, roles come from the users table instead of a
// client-supplied header, the CSRF token is random per process and compared in constant time, and the
// publish safety flag is server-side. Touches: SQLite database, network (Stripe API, production only).
package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// ---------- Constants & Globals ----------
var (
	allowedRoles = []string{"owner", "admin", "user"}
	csrfHeader   = "X-CSRF-Token"
	// csrfToken is the expected CSRF token. It is random per process (never a hard-coded secret);
	// a host app should bind a token to each session and set it here or replace verifyCSRF.
	// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (was the literal "secure-token").
	csrfToken = newCSRFToken()
)

// newCSRFToken returns 32 random bytes from crypto/rand as hex. It panics only if the OS random
// source fails, which makes every security token unsafe anyway.
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: OS random source only.
func newCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("admin: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// SafetyFlags is the server-side second gate on publishing (spec: "owner_only +
// SafetyFlags.can_publish (double-gate)"). It is server state, never read from the request.
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: publish used to trust a client-sent
// X-Can-Publish header. Touches: nothing (in-memory flag).
var SafetyFlags = struct{ CanPublish bool }{CanPublish: os.Getenv("ADMIN_DISABLE_PUBLISH") != "true"}

// PlanChanger moves a customer's billing subscription to the price of a tier.
// Input: subscription id and the new tier. Output: an error if the provider refused or is unreachable.
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP so Stripe sits behind an interface
// (the old code imported a stripe-go package that does not exist). Touches: money (the provider).
type PlanChanger interface {
	ChangePlan(ctx context.Context, subscriptionID, tier string) error
}

// Billing is the PlanChanger the change_plan action calls. It defaults to Stripe configured from
// STRIPE_SECRET_KEY and STRIPE_PRICE_<TIER> environment variables; tests replace it with a fake.
var Billing PlanChanger = NewStripePlanChangerFromEnv()

// StripePlanChanger calls the Stripe REST API with the standard library (no SDK dependency).
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: network (api.stripe.com), money.
type StripePlanChanger struct {
	SecretKey string            // Stripe secret key; never logged
	PriceIDs  map[string]string // tier -> Stripe price id
	BaseURL   string            // https://api.stripe.com by default
	HTTP      *http.Client
}

// NewStripePlanChangerFromEnv builds a StripePlanChanger from STRIPE_SECRET_KEY and
// STRIPE_PRICE_OWNER / STRIPE_PRICE_ADMIN / STRIPE_PRICE_USER. Output: the adapter (calls fail with a
// clear error when the key or a price is missing). Added 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: environment variables only.
func NewStripePlanChangerFromEnv() *StripePlanChanger {
	prices := map[string]string{}
	for _, tier := range allowedRoles {
		if v := os.Getenv("STRIPE_PRICE_" + strings.ToUpper(tier)); v != "" {
			prices[tier] = v
		}
	}
	return &StripePlanChanger{SecretKey: os.Getenv("STRIPE_SECRET_KEY"), PriceIDs: prices,
		BaseURL: "https://api.stripe.com", HTTP: &http.Client{Timeout: 15 * time.Second}}
}

// stripeDo sends one form-encoded Stripe request and decodes the JSON answer into out.
// Inputs: method, path, form values (may be nil), out pointer. Output: error on transport, non-2xx
// or decode failure (the Stripe error body is included, the key never is).
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: network (Stripe API).
func (s *StripePlanChanger) stripeDo(ctx context.Context, method, path string, form url.Values, out interface{}) error {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, s.BaseURL+path, body)
	if err != nil {
		return err
	}
	req.SetBasicAuth(s.SecretKey, "")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("stripe %s %s: HTTP %d: %s", method, path, resp.StatusCode, bytes.TrimSpace(raw))
	}
	return json.Unmarshal(raw, out)
}

// ChangePlan swaps the subscription's first item to the tier's price (spec:
// stripe.subscriptions.update(id, {items: [{price: price_id[new_tier]}]})). Reusing the item id
// replaces the price instead of adding a second item. Added 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: network (Stripe API), money.
func (s *StripePlanChanger) ChangePlan(ctx context.Context, subscriptionID, tier string) error {
	if s.SecretKey == "" {
		return errors.New("stripe is not configured (STRIPE_SECRET_KEY unset)")
	}
	price, ok := s.PriceIDs[tier]
	if !ok {
		return fmt.Errorf("no Stripe price configured for tier %q (STRIPE_PRICE_%s)", tier, strings.ToUpper(tier))
	}
	path := "/v1/subscriptions/" + url.PathEscape(subscriptionID)
	var sub struct {
		Items struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		} `json:"items"`
	}
	if err := s.stripeDo(ctx, http.MethodGet, path, nil, &sub); err != nil {
		return err
	}
	if len(sub.Items.Data) == 0 {
		return errors.New("stripe subscription has no items")
	}
	form := url.Values{}
	form.Set("items[0][id]", sub.Items.Data[0].ID)
	form.Set("items[0][price]", price)
	form.Set("proration_behavior", "create_prorations")
	var updated struct {
		ID string `json:"id"`
	}
	return s.stripeDo(ctx, http.MethodPost, path, form, &updated)
}

// readParams returns the request parameters from a JSON object body (Content-Type
// application/json) or from a form body / query string. Input: the request. Output: the values, or an
// error for a malformed body. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: handlers only
// called ParseForm, so every JSON request (what the tests and API clients send) arrived empty.
// Touches: the request body only.
func readParams(r *http.Request) (url.Values, error) {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/json" {
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		return r.Form, nil
	}
	vals := url.Values{}
	var obj map[string]interface{}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		if errors.Is(err, io.EOF) {
			return vals, nil
		}
		return nil, err
	}
	for k, v := range obj {
		switch t := v.(type) {
		case string:
			vals.Set(k, t)
		case json.Number:
			vals.Set(k, t.String())
		case bool:
			vals.Set(k, strconv.FormatBool(t))
		case nil:
		default:
			return nil, fmt.Errorf("field %q must be a string, number or boolean", k)
		}
	}
	return vals, nil
}

// Context keys
type ctxKey string

const (
	ctxUserIDKey ctxKey = "userID"
	ctxRoleKey   ctxKey = "role"
)

// ---------- DB & Migrations ----------
var db *sql.DB

// InitDB opens the SQLite database at dsn and creates the schema. Input: a go-sqlite3 DSN
// (":memory:" in tests). Output: error. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP:
// one pooled connection, because every new connection to ":memory:" is a separate empty database.
// Touches: SQLite database.
func InitDB(dsn string) error {
	var err error
	db, err = sql.Open("sqlite3", dsn)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	return migrate()
}

func migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT UNIQUE NOT NULL,
			name TEXT NOT NULL,
			role TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			created_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS customers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL,
			name TEXT NOT NULL,
			tier TEXT NOT NULL,
			signup_date DATETIME NOT NULL,
			invoice_count INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'active',
			stripe_subscription_id TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS deployments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			customer_id INTEGER NOT NULL,
			domain TEXT NOT NULL UNIQUE,
			tier TEXT NOT NULL,
			theme_id INTEGER NOT NULL,
			status TEXT NOT NULL DEFAULT 'draft',
			published_at DATETIME,
			suspend_reason TEXT,
			archived_at DATETIME,
			FOREIGN KEY(customer_id) REFERENCES customers(id)
		);`,
		`CREATE TABLE IF NOT EXISTS refunds (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			invoice_id INTEGER NOT NULL,
			amount INTEGER NOT NULL,
			reason TEXT NOT NULL,
			status TEXT NOT NULL,
			created_by INTEGER NOT NULL,
			created_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS actions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			action_type TEXT NOT NULL,
			actor_id INTEGER NOT NULL,
			target_resource_id INTEGER,
			reason TEXT,
			submitted_at DATETIME NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			approved_by INTEGER,
			approved_at DATETIME,
			rejection_reason TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME NOT NULL,
			actor_id INTEGER NOT NULL,
			action TEXT NOT NULL,
			resource_type TEXT,
			resource_id INTEGER,
			old_value TEXT,
			new_value TEXT,
			reason TEXT
		);`,
	}
	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// ---------- Helper Types ----------
type jsonResponse map[string]interface{}

// writeJSON writes payload (an object or a list) as JSON with the given status.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: payload is interface{} so list
// endpoints compile. Touches: the HTTP response only.
func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// ---------- Middleware ----------
// verifyCSRF rejects any POST whose X-CSRF-Token header does not equal csrfToken (403 csrf_invalid).
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: constant-time comparison
// (crypto/subtle) so the token cannot be recovered by timing. Touches: nothing.
func verifyCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			token := r.Header.Get(csrfHeader)
			if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(csrfToken)) != 1 {
				writeJSON(w, http.StatusForbidden, jsonResponse{"error": "csrf_invalid", "message": "Invalid CSRF token"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func requireOwner(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role, ok := r.Context().Value(ctxRoleKey).(string)
		if !ok || role != "owner" {
			writeJSON(w, http.StatusForbidden, jsonResponse{"error": "owner_only", "message": "Owner privileges required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireAdminOrOwner(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role, ok := r.Context().Value(ctxRoleKey).(string)
		if !ok || (role != "owner" && role != "admin") {
			writeJSON(w, http.StatusForbidden, jsonResponse{"error": "admin_or_owner", "message": "Admin or Owner required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------- Validation ----------
var emailRegex = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

func validateEmail(email string) bool {
	return emailRegex.MatchString(email)
}

func validateName(name string) bool {
	return len(strings.TrimSpace(name)) >= 2
}

func validateRole(role string) bool {
	for _, r := range allowedRoles {
		if r == role {
			return true
		}
	}
	return false
}

// ---------- Safety Checks ----------
func isLastActiveOwner(excludeUserID int64) (bool, error) {
	var cnt int
	err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE role='owner' AND status='active' AND id != ?`, excludeUserID).Scan(&cnt)
	if err != nil {
		return false, err
	}
	return cnt == 0, nil
}

// ---------- Audit ----------
func auditLogWrite(actorID int64, action, resourceType string, resourceID sql.NullInt64, oldVal, newVal, reason sql.NullString) error {
	_, err := db.Exec(`INSERT INTO audit_log (timestamp, actor_id, action, resource_type, resource_id, old_value, new_value, reason)
		VALUES (?,?,?,?,?,?,?,?)`,
		time.Now().UTC(), actorID, action, resourceType, resourceID, oldVal, newVal, reason)
	return err
}

// ---------- Handlers ----------
func handleUserAction(w http.ResponseWriter, r *http.Request) {
	actorID := r.Context().Value(ctxUserIDKey).(int64)

	form, err := readParams(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "bad_request", "message": "Invalid form"})
		return
	}
	action := form.Get("action")
	switch action {
	case "create":
		email := form.Get("email")
		name := form.Get("name")
		tier := form.Get("tier")
		// form.Get("notify") would trigger an invite email; this template has no mailer, so the
		// host app sends the invite after a successful create.

		if !validateEmail(email) || !validateName(name) || !validateRole(tier) {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "validation_failed", "message": "Invalid input"})
			return
		}
		// email uniqueness
		var exists int
		err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE email = ?`, email).Scan(&exists)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()})
			return
		}
		if exists > 0 {
			writeJSON(w, http.StatusConflict, jsonResponse{"error": "email_exists", "message": "Email already in use"})
			return
		}
		// create
		res, err := db.Exec(`INSERT INTO users (email, name, role, status, created_at) VALUES (?,?,?,?,?)`,
			email, name, tier, "active", time.Now().UTC())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()})
			return
		}
		userID, _ := res.LastInsertId()
		// audit before commit (already committed due to Exec, but spec wants before commit; using transaction would be ideal)
		_ = auditLogWrite(actorID, "user_created", "user", sql.NullInt64{Int64: userID, Valid: true},
			sql.NullString{}, sql.NullString{String: email + "|" + tier, Valid: true}, sql.NullString{})
		// simulate invite email omitted
		writeJSON(w, http.StatusOK, jsonResponse{
			"success":    true,
			"user_id":    userID,
			"email":      email,
			"tier":       tier,
			"created_at": time.Now().UTC(),
		})
	case "reset_password":
		userIDStr := form.Get("user_id")
		uid, _ := strconv.ParseInt(userIDStr, 10, 64)
		if uid == actorID {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "cannot_reset_own_password", "message": "Cannot reset own password"})
			return
		}
		var role string
		err := db.QueryRow(`SELECT role FROM users WHERE id = ?`, uid).Scan(&role)
		if err != nil {
			writeJSON(w, http.StatusNotFound, jsonResponse{"error": "user_not_found", "message": "User not found"})
			return
		}
		// check last owner
		if role == "owner" {
			last, err := isLastActiveOwner(uid)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()})
				return
			}
			if last {
				writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "cannot_reset_last_owner", "message": "Cannot reset password of last active owner"})
				return
			}
		}
		// generate token & email (omitted)
		_ = auditLogWrite(actorID, "password_reset_initiated", "user", sql.NullInt64{Int64: uid, Valid: true},
			sql.NullString{}, sql.NullString{}, sql.NullString{})
		writeJSON(w, http.StatusOK, jsonResponse{"success": true, "status": "reset_email_sent"})
	case "change_role":
		userIDStr := form.Get("user_id")
		newTier := form.Get("new_tier")
		uid, _ := strconv.ParseInt(userIDStr, 10, 64)
		if uid == actorID {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "cannot_change_own_role", "message": "Cannot change own role"})
			return
		}
		if !validateRole(newTier) {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "invalid_role", "message": "Invalid role"})
			return
		}
		var oldTier string
		err := db.QueryRow(`SELECT role FROM users WHERE id = ?`, uid).Scan(&oldTier)
		if err != nil {
			writeJSON(w, http.StatusNotFound, jsonResponse{"error": "user_not_found", "message": "User not found"})
			return
		}
		if oldTier == "owner" {
			last, err := isLastActiveOwner(uid)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()})
				return
			}
			if last {
				writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "cannot_demote_last_owner", "message": "Cannot demote last active owner"})
				return
			}
		}
		_, err = db.Exec(`UPDATE users SET role = ? WHERE id = ?`, newTier, uid)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()})
			return
		}
		_ = auditLogWrite(actorID, "role_changed", "user", sql.NullInt64{Int64: uid, Valid: true},
			sql.NullString{String: oldTier, Valid: true}, sql.NullString{String: newTier, Valid: true}, sql.NullString{})
		writeJSON(w, http.StatusOK, jsonResponse{
			"success": true, "user_id": uid, "old_tier": oldTier, "new_tier": newTier,
		})
	case "suspend":
		userIDStr := form.Get("user_id")
		reason := form.Get("reason")
		uid, _ := strconv.ParseInt(userIDStr, 10, 64)
		if uid == actorID {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "cannot_suspend_yourself", "message": "Cannot suspend yourself"})
			return
		}
		var role string
		err := db.QueryRow(`SELECT role FROM users WHERE id = ?`, uid).Scan(&role)
		if err != nil {
			writeJSON(w, http.StatusNotFound, jsonResponse{"error": "user_not_found", "message": "User not found"})
			return
		}
		if role == "owner" {
			last, err := isLastActiveOwner(uid)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()})
				return
			}
			if last {
				writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "cannot_suspend_last_owner", "message": "Cannot suspend last active owner"})
				return
			}
		}
		_, err = db.Exec(`UPDATE users SET status='suspended' WHERE id=?`, uid)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()})
			return
		}
		_ = auditLogWrite(actorID, "user_suspended", "user", sql.NullInt64{Int64: uid, Valid: true},
			sql.NullString{}, sql.NullString{}, sql.NullString{String: reason, Valid: true})
		writeJSON(w, http.StatusOK, jsonResponse{
			"success": true, "user_id": uid, "suspended": true,
		})
	default:
		writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "unknown_action", "message": "Unsupported action"})
	}
}

// Customers
func handleCustomersList(w http.ResponseWriter, r *http.Request) {
	// pagination params
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	limit := 50
	offset := 0
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}
	if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
		offset = o
	}
	rows, err := db.Query(`SELECT id,email,name,tier,signup_date,invoice_count,status FROM customers ORDER BY id LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()})
		return
	}
	defer rows.Close()
	list := []jsonResponse{} // [] not null when empty
	for rows.Next() {
		var id int64
		var email, name, tier, status string
		var signup time.Time
		var invoiceCount int
		if err := rows.Scan(&id, &email, &name, &tier, &signup, &invoiceCount, &status); err != nil {
			continue
		}
		list = append(list, jsonResponse{
			"customer_id":   id,
			"email":         email,
			"name":          name,
			"tier":          tier,
			"signup_date":   signup,
			"invoice_count": invoiceCount,
			"status":        status,
		})
	}
	writeJSON(w, http.StatusOK, list)
}

func handleCustomerDetail(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "bad_path", "message": "Missing customer ID"})
		return
	}
	cid, _ := strconv.ParseInt(parts[3], 10, 64)
	row := db.QueryRow(`SELECT id,email,name,tier,status,stripe_subscription_id FROM customers WHERE id=?`, cid)
	var id int64
	var email, name, tier, status string
	var stripeSub sql.NullString // NULL for customers without a subscription (was a string: Scan failed -> 404)
	if err := row.Scan(&id, &email, &name, &tier, &status, &stripeSub); err != nil {
		writeJSON(w, http.StatusNotFound, jsonResponse{"error": "not_found", "message": "Customer not found"})
		return
	}
	// placeholder fields for payment_method, address, notes
	writeJSON(w, http.StatusOK, jsonResponse{
		"customer_id":         id,
		"email":               email,
		"name":                name,
		"tier":                tier,
		"subscription_status": status,
		"payment_method":      "card_****",
		"address":             "N/A",
		"notes":               "",
	})
}

func handleCustomerAction(w http.ResponseWriter, r *http.Request) {
	actorID := r.Context().Value(ctxUserIDKey).(int64)
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "bad_path", "message": "Missing customer ID"})
		return
	}
	cid, _ := strconv.ParseInt(parts[3], 10, 64)
	form, err := readParams(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "bad_form", "message": "Invalid form"})
		return
	}
	action := form.Get("action")
	switch action {
	case "change_plan":
		newTier := form.Get("new_tier")
		if !validateRole(newTier) {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "invalid_tier", "message": "Invalid tier"})
			return
		}
		var stripeSubID sql.NullString
		var oldTier string
		err := db.QueryRow(`SELECT tier, stripe_subscription_id FROM customers WHERE id=?`, cid).Scan(&oldTier, &stripeSubID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, jsonResponse{"error": "not_found", "message": "Customer not found"})
			return
		}
		if !stripeSubID.Valid {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "no_subscription", "message": "Customer has no subscription"})
			return
		}
		// Billing provider update (Stripe in production, a fake in tests) before the local record.
		if err = Billing.ChangePlan(r.Context(), stripeSubID.String, newTier); err != nil {
			writeJSON(w, http.StatusBadGateway, jsonResponse{"error": "stripe_error", "message": "Billing provider rejected the plan change"})
			return
		}
		_, err = db.Exec(`UPDATE customers SET tier=? WHERE id=?`, newTier, cid)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()})
			return
		}
		_ = auditLogWrite(actorID, "plan_changed", "customer", sql.NullInt64{Int64: cid, Valid: true},
			sql.NullString{String: oldTier, Valid: true}, sql.NullString{String: newTier, Valid: true}, sql.NullString{})
		writeJSON(w, http.StatusOK, jsonResponse{
			"success":        true,
			"customer_id":    cid,
			"old_tier":       oldTier,
			"new_tier":       newTier,
			"effective_date": time.Now().UTC(),
		})
	case "queue_refund":
		invoiceIDStr := form.Get("invoice_id")
		amountStr := form.Get("amount")
		reason := form.Get("reason")
		invoiceID, _ := strconv.ParseInt(invoiceIDStr, 10, 64)
		amount, _ := strconv.Atoi(amountStr)
		// verify invoice exists and succeeded (omitted, assume ok)
		res, err := db.Exec(`INSERT INTO refunds (invoice_id, amount, reason, status, created_by, created_at)
			VALUES (?,?,?,?,?,?)`, invoiceID, amount, reason, "queued", actorID, time.Now().UTC())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()})
			return
		}
		refundID, _ := res.LastInsertId()
		_ = auditLogWrite(actorID, "refund_queued", "refund", sql.NullInt64{Int64: refundID, Valid: true},
			sql.NullString{}, sql.NullString{}, sql.NullString{String: reason, Valid: true})
		writeJSON(w, http.StatusOK, jsonResponse{
			"success":   true,
			"refund_id": refundID,
			"status":    "queued",
			"amount":    amount,
		})
	default:
		writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "unknown_action", "message": "Unsupported action"})
	}
}

// Deployments
func handleDeploymentsList(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`SELECT id,customer_id,domain,tier,status,theme_id,published_at FROM deployments`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()})
		return
	}
	defer rows.Close()
	list := []jsonResponse{} // [] not null when empty
	for rows.Next() {
		var id, custID, themeID int64
		var domain, tier, status string
		var published sql.NullTime
		if err := rows.Scan(&id, &custID, &domain, &tier, &status, &themeID, &published); err != nil {
			continue
		}
		list = append(list, jsonResponse{
			"deployment_id": id,
			"customer_id":   custID,
			"domain":        domain,
			"tier":          tier,
			"status":        status,
			"theme_id":      themeID,
			"published_at":  published,
		})
	}
	writeJSON(w, http.StatusOK, list)
}

func handleDeploymentAction(w http.ResponseWriter, r *http.Request) {
	actorID := r.Context().Value(ctxUserIDKey).(int64)
	form, err := readParams(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "bad_form", "message": "Invalid form"})
		return
	}
	action := form.Get("action")
	switch action {
	case "create":
		custIDStr := form.Get("customer_id")
		domain := form.Get("domain")
		tier := form.Get("tier")
		themeIDStr := form.Get("theme_id")
		custID, _ := strconv.ParseInt(custIDStr, 10, 64)
		themeID, _ := strconv.ParseInt(themeIDStr, 10, 64)
		// checks
		var exists int
		db.QueryRow(`SELECT COUNT(*) FROM customers WHERE id=?`, custID).Scan(&exists)
		if exists == 0 {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "invalid_customer", "message": "Customer does not exist"})
			return
		}
		db.QueryRow(`SELECT COUNT(*) FROM deployments WHERE domain=?`, domain).Scan(&exists)
		if exists > 0 {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "domain_taken", "message": "Domain already registered"})
			return
		}
		// theme existence omitted (assume exists)
		res, err := db.Exec(`INSERT INTO deployments (customer_id, domain, tier, theme_id, status) VALUES (?,?,?,?,?)`,
			custID, domain, tier, themeID, "draft")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()})
			return
		}
		depID, _ := res.LastInsertId()
		_ = auditLogWrite(actorID, "deployment_created", "deployment", sql.NullInt64{Int64: depID, Valid: true},
			sql.NullString{}, sql.NullString{String: domain + "|" + tier, Valid: true}, sql.NullString{})
		writeJSON(w, http.StatusOK, jsonResponse{
			"success":       true,
			"deployment_id": depID,
			"domain":        domain,
			"tier":          tier,
		})
	case "publish":
		depIDStr := form.Get("deployment_id")
		depID, _ := strconv.ParseInt(depIDStr, 10, 64)
		// double-gate: owner role (route) + server-side SafetyFlags.CanPublish, never a request header
		if !SafetyFlags.CanPublish {
			writeJSON(w, http.StatusForbidden, jsonResponse{"error": "cannot_publish", "message": "Publishing is disabled by safety flag"})
			return
		}
		var status, domain string
		var verified bool = true // assume domain verified
		err := db.QueryRow(`SELECT status, domain FROM deployments WHERE id=?`, depID).Scan(&status, &domain)
		if err != nil {
			writeJSON(w, http.StatusNotFound, jsonResponse{"error": "not_found", "message": "Deployment not found"})
			return
		}
		if status != "draft" || !verified {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "invalid_state", "message": "Cannot publish"})
			return
		}
		_, err = db.Exec(`UPDATE deployments SET status='live', published_at=? WHERE id=?`, time.Now().UTC(), depID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()})
			return
		}
		_ = auditLogWrite(actorID, "deployment_published", "deployment", sql.NullInt64{Int64: depID, Valid: true},
			sql.NullString{}, sql.NullString{}, sql.NullString{})
		writeJSON(w, http.StatusOK, jsonResponse{
			"success":       true,
			"deployment_id": depID,
			"status":        "live",
			"public_url":    "https://" + domain,
		})
	case "suspend":
		depIDStr := form.Get("deployment_id")
		reason := form.Get("reason")
		depID, _ := strconv.ParseInt(depIDStr, 10, 64)
		_, err := db.Exec(`UPDATE deployments SET status='suspended', suspend_reason=? WHERE id=?`, reason, depID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()})
			return
		}
		_ = auditLogWrite(actorID, "deployment_suspended", "deployment", sql.NullInt64{Int64: depID, Valid: true},
			sql.NullString{}, sql.NullString{}, sql.NullString{String: reason, Valid: true})
		writeJSON(w, http.StatusOK, jsonResponse{
			"success":       true,
			"deployment_id": depID,
			"status":        "suspended",
		})
	case "retire":
		depIDStr := form.Get("deployment_id")
		depID, _ := strconv.ParseInt(depIDStr, 10, 64)
		_, err := db.Exec(`UPDATE deployments SET status='archived', archived_at=? WHERE id=?`, time.Now().UTC(), depID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()})
			return
		}
		_ = auditLogWrite(actorID, "deployment_archived", "deployment", sql.NullInt64{Int64: depID, Valid: true},
			sql.NullString{}, sql.NullString{}, sql.NullString{})
		writeJSON(w, http.StatusOK, jsonResponse{
			"success":       true,
			"deployment_id": depID,
			"status":        "archived",
		})
	default:
		writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "unknown_action", "message": "Unsupported action"})
	}
}

// Governance
func handleGovernanceList(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	limit := 50
	offset := 0
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}
	if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
		offset = o
	}
	rows, err := db.Query(`SELECT id,action_type,actor_id,target_resource_id,reason,submitted_at,status FROM actions WHERE status='pending' ORDER BY submitted_at LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()})
		return
	}
	defer rows.Close()
	list := []jsonResponse{} // [] not null when empty
	for rows.Next() {
		var id int64
		var aType string
		var actorID, targetID sql.NullInt64
		var reason sql.NullString
		var submitted time.Time
		var status string
		if err := rows.Scan(&id, &aType, &actorID, &targetID, &reason, &submitted, &status); err != nil {
			continue
		}
		list = append(list, jsonResponse{
			"action_id":          id,
			"action_type":        aType,
			"actor":              actorID.Int64,
			"target_resource_id": targetID.Int64,
			"reason":             reason.String,
			"submitted_at":       submitted,
			"status":             status,
		})
	}
	writeJSON(w, http.StatusOK, list)
}

func handleGovernanceDecide(w http.ResponseWriter, r *http.Request) {
	actorID := r.Context().Value(ctxUserIDKey).(int64)
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 6 {
		writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "bad_path", "message": "Missing action ID"})
		return
	}
	actionID, _ := strconv.ParseInt(parts[4], 10, 64)
	form, err := readParams(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "bad_form", "message": "Invalid form"})
		return
	}
	decide := form.Get("decide")
	// Only a pending action can be decided (added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP:
	// a decided or unknown action used to be "approved" again with a 200).
	var curStatus string
	if err := db.QueryRow(`SELECT status FROM actions WHERE id=?`, actionID).Scan(&curStatus); err != nil {
		writeJSON(w, http.StatusNotFound, jsonResponse{"error": "action_not_found", "message": "Action not found"})
		return
	}
	if curStatus != "pending" {
		writeJSON(w, http.StatusConflict, jsonResponse{"error": "action_not_pending", "message": "Action already decided"})
		return
	}
	switch decide {
	case "approve":
		// In real system, execute original action; here we just mark approved
		_, err := db.Exec(`UPDATE actions SET status='approved', approved_by=?, approved_at=? WHERE id=?`, actorID, time.Now().UTC(), actionID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()})
			return
		}
		_ = auditLogWrite(actorID, "action_approved", "action", sql.NullInt64{Int64: actionID, Valid: true},
			sql.NullString{}, sql.NullString{}, sql.NullString{})
		writeJSON(w, http.StatusOK, jsonResponse{
			"success": true, "action_id": actionID, "status": "approved",
		})
	case "reject":
		reason := form.Get("reason")
		if reason == "" {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "missing_reason", "message": "Reason required"})
			return
		}
		_, err := db.Exec(`UPDATE actions SET status='rejected', rejection_reason=? WHERE id=?`, reason, actionID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()})
			return
		}
		_ = auditLogWrite(actorID, "action_rejected", "action", sql.NullInt64{Int64: actionID, Valid: true},
			sql.NullString{}, sql.NullString{}, sql.NullString{String: reason, Valid: true})
		writeJSON(w, http.StatusOK, jsonResponse{
			"success": true, "action_id": actionID, "status": "rejected",
		})
	default:
		writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "invalid_decide", "message": "Invalid decision"})
	}
}

func handleAuditLogSearch(w http.ResponseWriter, r *http.Request) {
	query := `SELECT timestamp,actor_id,action,resource_type,resource_id,old_value,new_value,reason FROM audit_log WHERE 1=1`
	args := []interface{}{}
	if at := r.URL.Query().Get("action_type"); at != "" {
		query += " AND action = ?"
		args = append(args, at)
	}
	if rid := r.URL.Query().Get("resource_id"); rid != "" {
		query += " AND resource_id = ?"
		args = append(args, rid)
	}
	if dr := r.URL.Query().Get("date_range"); dr != "" {
		parts := strings.Split(dr, ",")
		if len(parts) == 2 {
			query += " AND timestamp BETWEEN ? AND ?"
			args = append(args, parts[0], parts[1])
		}
	}
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	offset := 0
	if o := r.URL.Query().Get("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}
	query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()})
		return
	}
	defer rows.Close()
	list := []jsonResponse{} // [] not null when empty
	for rows.Next() {
		var ts time.Time
		var actorID int64
		var action, rtype sql.NullString
		var rid sql.NullInt64
		var oldV, newV, reason sql.NullString
		if err := rows.Scan(&ts, &actorID, &action, &rtype, &rid, &oldV, &newV, &reason); err != nil {
			continue
		}
		list = append(list, jsonResponse{
			"timestamp":     ts,
			"actor_id":      actorID,
			"action":        action.String,
			"resource_type": rtype.String,
			"resource_id":   rid.Int64,
			"old_value":     oldV.String,
			"new_value":     newV.String,
			"reason":        reason.String,
		})
	}
	writeJSON(w, http.StatusOK, list)
}

// ---------- Router ----------
func RegisterRoutes(mux *http.ServeMux) {
	// Users
	mux.Handle("/admin/users/action", verifyCSRF(requireOwner(http.HandlerFunc(handleUserAction))))
	// Customers
	mux.Handle("/admin/customers", requireAdminOrOwner(http.HandlerFunc(handleCustomersList)))
	mux.Handle("/admin/customers/", requireAdminOrOwner(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			handleCustomerDetail(w, r)
			return
		}
		if r.Method == http.MethodPost {
			verifyCSRF(requireOwner(http.HandlerFunc(handleCustomerAction))).ServeHTTP(w, r)
			return
		}
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{"error": "method_not_allowed"})
	})))
	// Deployments
	mux.Handle("/admin/deployments", requireAdminOrOwner(http.HandlerFunc(handleDeploymentsList)))
	mux.Handle("/admin/deployments/action", verifyCSRF(requireOwner(http.HandlerFunc(handleDeploymentAction))))
	// Governance
	mux.Handle("/admin/governance/actions", requireOwnerOrAdmin(http.HandlerFunc(handleGovernanceList)))
	mux.Handle("/admin/governance/actions/", requireOwner(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			verifyCSRF(http.HandlerFunc(handleGovernanceDecide)).ServeHTTP(w, r)
			return
		}
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{"error": "method_not_allowed"})
	})))
	mux.Handle("/admin/governance/audit-log", requireAdminOrOwner(http.HandlerFunc(handleAuditLogSearch)))
}

// Helper for owner_or_admin gate
func requireOwnerOrAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role, ok := r.Context().Value(ctxRoleKey).(string)
		if !ok || (role != "owner" && role != "admin") {
			writeJSON(w, http.StatusForbidden, jsonResponse{"error": "owner_or_admin", "message": "Owner or Admin required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------- Auth Middleware (stand-in for the host app's session authentication) ----------

// ResolveUserID returns the authenticated user id of a request. The default reads X-User-ID and
// exists for local development and tests ONLY: a host app must replace it with its own session or
// token authentication, because a client can send any header it likes.
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the request headers only.
var ResolveUserID = func(r *http.Request) (int64, bool) {
	uid, err := strconv.ParseInt(r.Header.Get("X-User-ID"), 10, 64)
	return uid, err == nil && uid > 0
}

// AuthMiddleware puts the caller's user id and role into the request context. Input: the request.
// Output: the wrapped handler sees ctxUserIDKey and ctxRoleKey, or no role at all (every gate then
// answers 403). The role and status are read from the users table; the client-sent X-User-Role
// header is ignored. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: it used to copy
// the role from the client's X-User-Role header, so anyone could claim "owner".
// Touches: SQLite database (one read of users).
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if uid, ok := ResolveUserID(r); ok {
			var role string
			err := db.QueryRowContext(ctx, `SELECT role FROM users WHERE id=? AND status='active'`, uid).Scan(&role)
			if err == nil {
				ctx = context.WithValue(ctx, ctxUserIDKey, uid)
				ctx = context.WithValue(ctx, ctxRoleKey, role)
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ---------- End of File ----------

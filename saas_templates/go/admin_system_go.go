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
//
// Phase B, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: change_plan follows billing change_plan (ADMIN-12,
// amended): the handler retrieves the subscription's items, refuses anything but exactly one (409
// subscription_item_ambiguous) before any update, and updates {id: current_item_id, price} with
// proration_behavior create_prorations; queue_refund checks the invoice (it assumed it existed and had
// succeeded); approving a governance action executes it in the same transaction (it only marked it
// approved); create and reset_password really send the invite / reset email through the injectable
// Mail, with a single-use token stored as its SHA-256; every mutation writes its audit row in the same
// transaction as the change.
package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
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

// PlanChanger is the part of the billing provider change_plan needs: the price for a tier, the item ids
// of a subscription (stripe.subscriptions.retrieve) and an update of ONE item's price
// (stripe.subscriptions.update with {items: [{id, price}], proration_behavior: 'create_prorations'}).
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-12, amended): it was a single ChangePlan call
// that hid the item handling, so a test could not see that the existing item id was sent, and a
// subscription with several items had its first item silently repriced. Touches: money (the provider).
type PlanChanger interface {
	PriceID(tier string) (string, error)
	SubscriptionItems(ctx context.Context, subscriptionID string) ([]string, error)
	UpdateSubscriptionItem(ctx context.Context, subscriptionID, itemID, priceID string) error
}

// Billing is the PlanChanger the change_plan action calls. It defaults to Stripe configured from
// STRIPE_SECRET_KEY and STRIPE_PRICE_<TIER> environment variables; tests replace it with a fake.
var Billing PlanChanger = NewStripePlanChangerFromEnv()

// Mailer sends the admin system's emails: the invite of a created user and a password-reset link. Each
// carries a single-use token whose SHA-256 alone is stored. Added 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-01, ADMIN-04: both emails were "omitted"). Touches: network.
type Mailer interface {
	SendInvite(email, token string) error
	SendPasswordReset(email, token string) error
}

// Mail is the Mailer the user actions use. Nil (the default) makes create and reset_password answer
// 503 mail_unavailable rather than claim an email was sent. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
var Mail Mailer

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
	if s.SecretKey == "" {
		return errors.New("stripe is not configured (STRIPE_SECRET_KEY unset)")
	}
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

// PriceID returns the configured Stripe price for a tier. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: nothing.
func (s *StripePlanChanger) PriceID(tier string) (string, error) {
	price, ok := s.PriceIDs[tier]
	if !ok {
		return "", fmt.Errorf("no Stripe price configured for tier %q (STRIPE_PRICE_%s)", tier, strings.ToUpper(tier))
	}
	return price, nil
}

// SubscriptionItems calls stripe.subscriptions.retrieve and returns the item ids.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-12). Touches: network (Stripe API).
func (s *StripePlanChanger) SubscriptionItems(ctx context.Context, subscriptionID string) ([]string, error) {
	var sub struct {
		Items struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		} `json:"items"`
	}
	if err := s.stripeDo(ctx, http.MethodGet, "/v1/subscriptions/"+url.PathEscape(subscriptionID), nil, &sub); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(sub.Items.Data))
	for _, it := range sub.Items.Data {
		ids = append(ids, it.ID)
	}
	return ids, nil
}

// UpdateSubscriptionItem calls stripe.subscriptions.update(id, {items: [{id: itemID, price: priceID}],
// proration_behavior: 'create_prorations'}): the existing item gets the new price, no second item is added.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-12). Touches: network (Stripe API), money.
func (s *StripePlanChanger) UpdateSubscriptionItem(ctx context.Context, subscriptionID, itemID, priceID string) error {
	form := url.Values{}
	form.Set("items[0][id]", itemID)
	form.Set("items[0][price]", priceID)
	form.Set("proration_behavior", "create_prorations")
	var updated struct {
		ID string `json:"id"`
	}
	return s.stripeDo(ctx, http.MethodPost, "/v1/subscriptions/"+url.PathEscape(subscriptionID), form, &updated)
}

// newToken returns a 32-byte random token (hex) and its SHA-256 (hex), which is all that is stored.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: OS random source.
func newToken() (raw, hash string) {
	raw = newCSRFToken()
	h := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(h[:])
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
			rejection_reason TEXT,
			params TEXT,
			execution_result TEXT
		);`,
		// invoices and user_tokens added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: queue_refund checks the
		// invoice (ADMIN-13), and invite / reset tokens are stored as SHA-256 (ADMIN-01, ADMIN-04).
		`CREATE TABLE IF NOT EXISTS invoices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			customer_id INTEGER NOT NULL,
			amount INTEGER NOT NULL,
			status TEXT NOT NULL,
			FOREIGN KEY(customer_id) REFERENCES customers(id)
		);`,
		`CREATE TABLE IF NOT EXISTS deployment_configs (
			deployment_id INTEGER PRIMARY KEY,
			theme_id INTEGER NOT NULL,
			settings TEXT NOT NULL DEFAULT '{}',
			created_at DATETIME NOT NULL,
			FOREIGN KEY(deployment_id) REFERENCES deployments(id)
		);`,
		`CREATE TABLE IF NOT EXISTS user_tokens (
			token_hash TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			purpose TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			used_at DATETIME
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
	return auditLogWriteWith(db, actorID, action, resourceType, resourceID, oldVal, newVal, reason)
}

// sqlExecer is what both *sql.DB and *sql.Tx offer for a write, so an audit row can be written inside
// the caller's transaction. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit
// review on PR 19). Touches: nothing by itself.
type sqlExecer interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
}

// auditLogWriteWith inserts one audit_log row through ex (the database, or an open transaction so the
// row commits or rolls back with the change it records). Inputs: ex, the actor, action, resource type
// and id, old/new values and reason. Output: the insert's error. Why: CodeRabbit review on PR 19, the
// governance decision and its audit row must be one transaction (2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP). Touches: SQLite audit_log.
func auditLogWriteWith(ex sqlExecer, actorID int64, action, resourceType string, resourceID sql.NullInt64, oldVal, newVal, reason sql.NullString) error {
	_, err := ex.Exec(`INSERT INTO audit_log (timestamp, actor_id, action, resource_type, resource_id, old_value, new_value, reason)
		VALUES (?,?,?,?,?,?,?,?)`,
		time.Now().UTC(), actorID, action, resourceType, resourceID, oldVal, newVal, reason)
	return err
}

// ---------- Handlers ----------

// handleUserAction is POST /admin/users/action (owner, CSRF): create (sends the invite), reset_password
// (sends the reset link), change_role, suspend. Each change and its audit row are one transaction; the
// actor id comes from the authenticated context, never the body. Changed 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-01/04: emails really sent; transactions). Touches: SQLite, Mail.
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
		// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-01): the invite is sent through Mail with a
		// single-use 7-day token; the user, the token hash and the audit row are one transaction, rolled
		// back if the email cannot be sent.
		if Mail == nil {
			writeJSON(w, http.StatusServiceUnavailable, jsonResponse{"error": "mail_unavailable", "message": "No mailer is configured"})
			return
		}
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
		tx, err := db.Begin()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"})
			return
		}
		defer tx.Rollback()
		res, err := tx.Exec(`INSERT INTO users (email, name, role, status, created_at) VALUES (?,?,?,?,?)`,
			email, name, tier, "active", time.Now().UTC())
		if err != nil {
			writeJSON(w, http.StatusConflict, jsonResponse{"error": "email_exists", "message": "Email already in use"})
			return
		}
		userID, _ := res.LastInsertId()
		invite, inviteHash := newToken()
		if _, err := tx.Exec(`INSERT INTO user_tokens (token_hash, user_id, purpose, expires_at) VALUES (?,?,?,?)`,
			inviteHash, userID, "invite", time.Now().UTC().Add(7*24*time.Hour)); err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"})
			return
		}
		if err := auditLogWriteWith(tx, actorID, "user_created", "user", sql.NullInt64{Int64: userID, Valid: true},
			sql.NullString{}, sql.NullString{String: email + "|" + tier, Valid: true}, sql.NullString{}); err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"})
			return
		}
		if err := Mail.SendInvite(email, invite); err != nil {
			writeJSON(w, http.StatusBadGateway, jsonResponse{"error": "mail_failed", "message": "The invite email could not be sent"})
			return
		}
		if err := tx.Commit(); err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"})
			return
		}
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
		var role, targetEmail string
		err := db.QueryRow(`SELECT role, email FROM users WHERE id = ?`, uid).Scan(&role, &targetEmail)
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
		// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-04): a single-use 1-hour token (only its hash is
		// stored) is emailed through Mail; token and audit row commit only if the email was sent.
		if Mail == nil {
			writeJSON(w, http.StatusServiceUnavailable, jsonResponse{"error": "mail_unavailable", "message": "No mailer is configured"})
			return
		}
		tx, err := db.Begin()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"})
			return
		}
		defer tx.Rollback()
		reset, resetHash := newToken()
		if _, err := tx.Exec(`INSERT INTO user_tokens (token_hash, user_id, purpose, expires_at) VALUES (?,?,?,?)`,
			resetHash, uid, "password_reset", time.Now().UTC().Add(time.Hour)); err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"})
			return
		}
		if err := auditLogWriteWith(tx, actorID, "password_reset_initiated", "user", sql.NullInt64{Int64: uid, Valid: true},
			sql.NullString{}, sql.NullString{}, sql.NullString{}); err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"})
			return
		}
		if err := Mail.SendPasswordReset(targetEmail, reset); err != nil {
			writeJSON(w, http.StatusBadGateway, jsonResponse{"error": "mail_failed", "message": "The reset email could not be sent"})
			return
		}
		if err := tx.Commit(); err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"})
			return
		}
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
		// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the change and its audit row are one transaction.
		if err := inTx(func(tx *sql.Tx) error {
			if _, err := tx.Exec(`UPDATE users SET role = ? WHERE id = ?`, newTier, uid); err != nil {
				return err
			}
			return auditLogWriteWith(tx, actorID, "role_changed", "user", sql.NullInt64{Int64: uid, Valid: true},
				sql.NullString{String: oldTier, Valid: true}, sql.NullString{String: newTier, Valid: true}, sql.NullString{})
		}); err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"})
			return
		}
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
		// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the change and its audit row are one transaction.
		if err := inTx(func(tx *sql.Tx) error {
			if _, err := tx.Exec(`UPDATE users SET status='suspended' WHERE id=?`, uid); err != nil {
				return err
			}
			return auditLogWriteWith(tx, actorID, "user_suspended", "user", sql.NullInt64{Int64: uid, Valid: true},
				sql.NullString{}, sql.NullString{}, sql.NullString{String: reason, Valid: true})
		}); err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"})
			return
		}
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

// inTx runs fn in one transaction and commits only if fn succeeds. Added 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP (spec: "Every mutation: audit_log write before commit"). Touches: SQLite.
func inTx(fn func(tx *sql.Tx) error) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// handleCustomerAction is POST /admin/customers/{customer_id}/action (owner, CSRF).
//
// change_plan (ADMIN-12, amended 2026-11-10): unknown tier -> 400 invalid_tier; unknown customer -> 404;
// no subscription -> 400 no_subscription; the subscription's items are retrieved and anything but exactly
// one item -> 409 subscription_item_ambiguous, both before any update; then the provider updates
// {id: current_item_id, price} with create_prorations, and the tier and its audit row are written in one
// transaction. Output {success, customer_id, old_tier, new_tier, effective_date}.
// queue_refund (ADMIN-13): the invoice must exist and belong to this customer (404 invoice_not_found), be
// 'succeeded' (400 invalid_invoice_status), the amount positive (400 invalid_amount) and, with refunds
// already queued or executed, not above the invoice (400 refund_exceeds_invoice); the refund row
// (status 'queued') and its audit row are one transaction. Output {success, refund_id, status, amount}.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: change_plan hid the item handling in the provider
// and queue_refund assumed the invoice existed and had succeeded. Touches: SQLite, the billing provider (money).
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
	dbError := func() {
		writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"})
	}
	switch form.Get("action") {
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
		price, err := Billing.PriceID(newTier)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "price_not_configured", "message": "No price is configured for that tier"})
			return
		}
		items, err := Billing.SubscriptionItems(r.Context(), stripeSubID.String)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, jsonResponse{"error": "stripe_error", "message": "Billing provider could not read the subscription"})
			return
		}
		if len(items) != 1 {
			writeJSON(w, http.StatusConflict, jsonResponse{"error": "subscription_item_ambiguous", "message": "The subscription does not have exactly one item"})
			return
		}
		if err := Billing.UpdateSubscriptionItem(r.Context(), stripeSubID.String, items[0], price); err != nil {
			writeJSON(w, http.StatusBadGateway, jsonResponse{"error": "stripe_error", "message": "Billing provider rejected the plan change"})
			return
		}
		if err := inTx(func(tx *sql.Tx) error {
			if _, err := tx.Exec(`UPDATE customers SET tier=? WHERE id=?`, newTier, cid); err != nil {
				return err
			}
			return auditLogWriteWith(tx, actorID, "plan_changed", "customer", sql.NullInt64{Int64: cid, Valid: true},
				sql.NullString{String: oldTier, Valid: true}, sql.NullString{String: newTier, Valid: true}, sql.NullString{})
		}); err != nil {
			dbError()
			return
		}
		writeJSON(w, http.StatusOK, jsonResponse{
			"success":        true,
			"customer_id":    cid,
			"old_tier":       oldTier,
			"new_tier":       newTier,
			"effective_date": time.Now().UTC(),
		})
	case "queue_refund":
		reason := strings.TrimSpace(form.Get("reason"))
		invoiceID, errID := strconv.ParseInt(form.Get("invoice_id"), 10, 64)
		amount, errAmt := strconv.ParseInt(form.Get("amount"), 10, 64)
		if errID != nil || reason == "" {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "missing_fields", "message": "invoice_id, amount and reason are required"})
			return
		}
		if errAmt != nil || amount <= 0 {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "invalid_amount", "message": "amount must be a positive integer"})
			return
		}
		var refundID int64
		var status int
		var body jsonResponse
		err := inTx(func(tx *sql.Tx) error {
			var invAmount int64
			var invStatus string
			if err := tx.QueryRow(`SELECT amount, status FROM invoices WHERE id=? AND customer_id=?`, invoiceID, cid).Scan(&invAmount, &invStatus); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					status, body = http.StatusNotFound, jsonResponse{"error": "invoice_not_found", "message": "Invoice not found"}
					return errDone
				}
				return err
			}
			if invStatus != "succeeded" {
				status, body = http.StatusBadRequest, jsonResponse{"error": "invalid_invoice_status", "message": "Only a succeeded invoice can be refunded"}
				return errDone
			}
			var refunded int64
			if err := tx.QueryRow(`SELECT COALESCE(SUM(amount),0) FROM refunds WHERE invoice_id=? AND status IN ('queued','executed')`, invoiceID).Scan(&refunded); err != nil {
				return err
			}
			if refunded+amount > invAmount {
				status, body = http.StatusBadRequest, jsonResponse{"error": "refund_exceeds_invoice", "message": "Refunds would exceed the invoice amount"}
				return errDone
			}
			res, err := tx.Exec(`INSERT INTO refunds (invoice_id, amount, reason, status, created_by, created_at) VALUES (?,?,?,?,?,?)`,
				invoiceID, amount, reason, "queued", actorID, time.Now().UTC())
			if err != nil {
				return err
			}
			refundID, _ = res.LastInsertId()
			return auditLogWriteWith(tx, actorID, "refund_queued", "refund", sql.NullInt64{Int64: refundID, Valid: true},
				sql.NullString{}, sql.NullString{String: fmt.Sprintf(`{"invoice_id":%d,"amount":%d}`, invoiceID, amount), Valid: true},
				sql.NullString{String: reason, Valid: true})
		})
		if errors.Is(err, errDone) {
			writeJSON(w, status, body)
			return
		}
		if err != nil {
			dbError()
			return
		}
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

// errDone stops an inTx function early with an answer already chosen (the transaction rolls back).
var errDone = errors.New("answered")

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

// handleDeploymentAction is POST /admin/deployments/action (owner, CSRF): create, publish (double gate:
// owner + server-side SafetyFlags.CanPublish; only from 'draft'), suspend, retire. Each change and its audit
// row are one transaction. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
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
		// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the record and its audit row are one transaction.
		var depID int64
		if err := inTx(func(tx *sql.Tx) error {
			res, err := tx.Exec(`INSERT INTO deployments (customer_id, domain, tier, theme_id, status) VALUES (?,?,?,?,?)`,
				custID, domain, tier, themeID, "draft")
			if err != nil {
				return err
			}
			depID, _ = res.LastInsertId()
			// "init config" (ADMIN-14): the deployment's configuration row, added 2026-11-10,
			// session_012zDydZCZ4AChqhEZ4oVtaP (nothing was initialised).
			if _, err := tx.Exec(`INSERT INTO deployment_configs (deployment_id, theme_id, settings, created_at) VALUES (?,?,?,?)`,
				depID, themeID, `{"tier":"`+tier+`"}`, time.Now().UTC()); err != nil {
				return err
			}
			return auditLogWriteWith(tx, actorID, "deployment_created", "deployment", sql.NullInt64{Int64: depID, Valid: true},
				sql.NullString{}, sql.NullString{String: domain + "|" + tier, Valid: true}, sql.NullString{})
		}); err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"})
			return
		}
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
		// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: conditional on status='draft', with its audit row, in one
		// transaction, so two concurrent publishes cannot both succeed.
		published := false
		if err := inTx(func(tx *sql.Tx) error {
			res, err := tx.Exec(`UPDATE deployments SET status='live', published_at=? WHERE id=? AND status='draft'`, time.Now().UTC(), depID)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return nil
			}
			published = true
			return auditLogWriteWith(tx, actorID, "deployment_published", "deployment", sql.NullInt64{Int64: depID, Valid: true},
				sql.NullString{}, sql.NullString{}, sql.NullString{})
		}); err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"})
			return
		}
		if !published {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "invalid_state", "message": "Cannot publish"})
			return
		}
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
		// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: an unknown deployment is 404 (it answered success), and
		// the change and its audit row are one transaction.
		found := false
		if err := inTx(func(tx *sql.Tx) error {
			res, err := tx.Exec(`UPDATE deployments SET status='suspended', suspend_reason=? WHERE id=?`, reason, depID)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return nil
			}
			found = true
			return auditLogWriteWith(tx, actorID, "deployment_suspended", "deployment", sql.NullInt64{Int64: depID, Valid: true},
				sql.NullString{}, sql.NullString{}, sql.NullString{String: reason, Valid: true})
		}); err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"})
			return
		}
		if !found {
			writeJSON(w, http.StatusNotFound, jsonResponse{"error": "not_found", "message": "Deployment not found"})
			return
		}
		writeJSON(w, http.StatusOK, jsonResponse{
			"success":       true,
			"deployment_id": depID,
			"status":        "suspended",
		})
	case "retire":
		depIDStr := form.Get("deployment_id")
		depID, _ := strconv.ParseInt(depIDStr, 10, 64)
		// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: 404 for an unknown deployment; one transaction.
		found := false
		if err := inTx(func(tx *sql.Tx) error {
			res, err := tx.Exec(`UPDATE deployments SET status='archived', archived_at=? WHERE id=?`, time.Now().UTC(), depID)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return nil
			}
			found = true
			return auditLogWriteWith(tx, actorID, "deployment_archived", "deployment", sql.NullInt64{Int64: depID, Valid: true},
				sql.NullString{}, sql.NullString{}, sql.NullString{})
		}); err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"})
			return
		}
		if !found {
			writeJSON(w, http.StatusNotFound, jsonResponse{"error": "not_found", "message": "Deployment not found"})
			return
		}
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

// handleGovernanceDecide is POST /admin/governance/actions/{id}/decide (owner): decide=approve, or
// decide=reject with a reason. Output: 200 {success, action_id, status}; 400 bad_path, bad_form,
// invalid_decide or missing_reason; 404 action_not_found; 409 action_not_pending when the action is
// already decided, including when a concurrent request decided it first; 500 db_error.
// The read of the status only tells 404 from 409; the decision itself is decideAction, whose update
// is conditional on status='pending', so two concurrent requests cannot both act.
// Why changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: a decided or unknown action used to
// be "approved" again with a 200; later the same day, CodeRabbit review on PR 19: the check and the
// unconditional UPDATE raced. Touches: SQLite actions and audit_log.
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
	var curStatus string
	if err := db.QueryRow(`SELECT status FROM actions WHERE id=?`, actionID).Scan(&curStatus); err != nil {
		writeJSON(w, http.StatusNotFound, jsonResponse{"error": "action_not_found", "message": "Action not found"})
		return
	}
	if curStatus != "pending" {
		writeJSON(w, http.StatusConflict, jsonResponse{"error": "action_not_pending", "message": "Action already decided"})
		return
	}
	reason := form.Get("reason")
	switch decide {
	case "approve":
	case "reject":
		if reason == "" {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "missing_reason", "message": "Reason required"})
			return
		}
	default:
		writeJSON(w, http.StatusBadRequest, jsonResponse{"error": "invalid_decide", "message": "Invalid decision"})
		return
	}
	status, payload := decideAction(actorID, actionID, decide, reason)
	writeJSON(w, status, payload)
}

// decideAction applies one governance decision in a single transaction: the status change (approve:
// status='approved', approved_by, approved_at; reject: status='rejected', rejection_reason), the
// action's execution (executeAction; added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: approving used to
// only mark it approved), and its audit row
// (action_approved / action_rejected). The UPDATE carries AND status='pending' and its RowsAffected is
// checked, so when another request has already decided the action nothing is changed, no audit row is
// written, and the answer is 409 action_not_pending.
// Inputs: the deciding owner's id, the action id, decide ("approve" or "reject"; anything else is 400
// invalid_decide), and the rejection reason. Output: the HTTP status and JSON body to send.
// Why: CodeRabbit review on PR 19 (2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP): the handler
// read the status and then ran an unconditional UPDATE ... WHERE id=?, so two concurrent decide
// requests could both act and write two audit rows. Touches: SQLite actions and audit_log.
func decideAction(actorID, actionID int64, decide, reason string) (int, jsonResponse) {
	var (
		query     string
		args      []interface{}
		auditName string
		auditWhy  sql.NullString
		newStatus string
	)
	switch decide {
	case "approve":
		query = `UPDATE actions SET status='approved', approved_by=?, approved_at=? WHERE id=? AND status='pending'`
		args = []interface{}{actorID, time.Now().UTC(), actionID}
		auditName, newStatus = "action_approved", "approved"
	case "reject":
		query = `UPDATE actions SET status='rejected', rejection_reason=? WHERE id=? AND status='pending'`
		args = []interface{}{reason, actionID}
		auditName, newStatus = "action_rejected", "rejected"
		auditWhy = sql.NullString{String: reason, Valid: true}
	default:
		return http.StatusBadRequest, jsonResponse{"error": "invalid_decide", "message": "Invalid decision"}
	}
	dbError := func(err error) (int, jsonResponse) {
		return http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": err.Error()}
	}
	tx, err := db.Begin()
	if err != nil {
		return dbError(err)
	}
	defer tx.Rollback() // no-op after a successful Commit
	res, err := tx.Exec(query, args...)
	if err != nil {
		return dbError(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return dbError(err)
	}
	if n == 0 {
		return http.StatusConflict, jsonResponse{"error": "action_not_pending", "message": "Action already decided"}
	}
	var result sql.NullString
	if decide == "approve" {
		// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-16): approving executes the original action in
		// this transaction; if it cannot run, nothing is approved.
		out, status, body := executeAction(tx, actorID, actionID)
		if body != nil {
			return status, body
		}
		result = sql.NullString{String: out, Valid: true}
		if _, err := tx.Exec(`UPDATE actions SET execution_result=? WHERE id=?`, out, actionID); err != nil {
			return dbError(err)
		}
	}
	if err := auditLogWriteWith(tx, actorID, auditName, "action", sql.NullInt64{Int64: actionID, Valid: true},
		sql.NullString{}, result, auditWhy); err != nil {
		return dbError(err)
	}
	if err := tx.Commit(); err != nil {
		return dbError(err)
	}
	return http.StatusOK, jsonResponse{"success": true, "action_id": actionID, "status": newStatus}
}

// executeAction runs an approved governance action inside tx and returns its execution result as JSON.
// Supported action types: "change_role" (params {"new_tier"}) and "suspend_user" (params {"reason"}) on
// the target user, with the same checks as the direct actions (the last active owner is never demoted or
// suspended). Any other type, a missing target or bad params answers with an error status and body (the
// caller rolls back, so the action stays pending). Out: (result JSON, 0, nil) or (_, status, body).
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-16: "execute the original action"; approval
// used to only mark it approved). Touches: SQLite users and audit_log (inside tx).
func executeAction(tx *sql.Tx, actorID, actionID int64) (string, int, jsonResponse) {
	var actionType string
	var target sql.NullInt64
	var params sql.NullString
	if err := tx.QueryRow(`SELECT action_type, target_resource_id, params FROM actions WHERE id=?`, actionID).Scan(&actionType, &target, &params); err != nil {
		return "", http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"}
	}
	p := map[string]string{}
	if params.Valid && params.String != "" {
		if err := json.Unmarshal([]byte(params.String), &p); err != nil {
			return "", http.StatusUnprocessableEntity, jsonResponse{"error": "invalid_action_params", "message": "Action params are not valid JSON"}
		}
	}
	if actionType != "change_role" && actionType != "suspend_user" {
		return "", http.StatusUnprocessableEntity, jsonResponse{"error": "unsupported_action_type", "message": "No executor for action type " + actionType}
	}
	var role, status string
	if !target.Valid || tx.QueryRow(`SELECT role, status FROM users WHERE id=?`, target.Int64).Scan(&role, &status) != nil {
		return "", http.StatusUnprocessableEntity, jsonResponse{"error": "target_not_found", "message": "The action's target user does not exist"}
	}
	lastOwner := false
	if role == "owner" {
		var others int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM users WHERE role='owner' AND status='active' AND id != ?`, target.Int64).Scan(&others); err != nil {
			return "", http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"}
		}
		lastOwner = others == 0
	}
	uid := sql.NullInt64{Int64: target.Int64, Valid: true}
	switch actionType {
	case "change_role":
		newTier := p["new_tier"]
		if !validateRole(newTier) {
			return "", http.StatusUnprocessableEntity, jsonResponse{"error": "invalid_action_params", "message": "change_role needs a valid new_tier"}
		}
		if lastOwner && newTier != "owner" {
			return "", http.StatusBadRequest, jsonResponse{"error": "cannot_demote_last_owner", "message": "Cannot demote last active owner"}
		}
		if _, err := tx.Exec(`UPDATE users SET role=? WHERE id=?`, newTier, target.Int64); err != nil {
			return "", http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"}
		}
		if err := auditLogWriteWith(tx, actorID, "role_changed", "user", uid, sql.NullString{String: role, Valid: true},
			sql.NullString{String: newTier, Valid: true}, sql.NullString{}); err != nil {
			return "", http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"}
		}
		out, _ := json.Marshal(map[string]string{"old_tier": role, "new_tier": newTier})
		return string(out), 0, nil
	default: // suspend_user
		if lastOwner {
			return "", http.StatusBadRequest, jsonResponse{"error": "cannot_suspend_last_owner", "message": "Cannot suspend last active owner"}
		}
		if _, err := tx.Exec(`UPDATE users SET status='suspended' WHERE id=?`, target.Int64); err != nil {
			return "", http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"}
		}
		if err := auditLogWriteWith(tx, actorID, "user_suspended", "user", uid, sql.NullString{}, sql.NullString{},
			sql.NullString{String: p["reason"], Valid: p["reason"] != ""}); err != nil {
			return "", http.StatusInternalServerError, jsonResponse{"error": "db_error", "message": "database error"}
		}
		out, _ := json.Marshal(map[string]interface{}{"user_id": target.Int64, "suspended": true})
		return string(out), 0, nil
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

// IdentityResolver returns the authenticated user id of a request, and false when the request carries
// no identity it trusts. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review
// on PR 19). Touches: whatever the host's implementation reads (session store, token verifier, ...).
type IdentityResolver func(r *http.Request) (int64, bool)

// ResolveUserID is the identity resolver AuthMiddleware uses. It is nil by default, and then every
// request is refused with 401 (fail closed): the host app must install its own session or token
// authentication here, or opt in to TrustedHeaderResolver behind a proxy it controls.
// Why changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review on PR 19,
// security): the default used to read X-User-ID, so a host that exposed AuthMiddleware unchanged let
// any caller act as an active owner by sending that owner's id. Touches: nothing by itself.
var ResolveUserID IdentityResolver

// TrustedHeaderResolver returns a resolver that reads the user id from the named request header (for
// example "X-User-ID"). Install it ONLY behind a reverse proxy that authenticates the caller, sets that
// header itself and strips any copy the client sent; anywhere else a client can claim any id.
// Input: the header name. Output: the resolver (false for a missing, non-numeric or non-positive id).
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review on PR 19: reading the
// header is now an explicit opt-in, not the default). Touches: the request headers only.
func TrustedHeaderResolver(header string) IdentityResolver {
	return func(r *http.Request) (int64, bool) {
		uid, err := strconv.ParseInt(r.Header.Get(header), 10, 64)
		return uid, err == nil && uid > 0
	}
}

// AuthMiddleware puts the caller's user id and role into the request context. Input: the request.
// Output: the wrapped handler sees ctxUserIDKey and ctxRoleKey; when no resolver is configured
// (ResolveUserID is nil), the resolver finds no identity, or the user is unknown or not active, the
// request is answered 401 {"error": "unauthenticated"} and never reaches the handler. The role and
// status are read from the users table; the client-sent X-User-Role header is ignored.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: it used to copy the role from the
// client's X-User-Role header, so anyone could claim "owner"; later the same day (CodeRabbit review on
// PR 19, security) it fails closed instead of trusting X-User-ID by default.
// Touches: SQLite database (one read of users).
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		unauthenticated := func(msg string) {
			writeJSON(w, http.StatusUnauthorized, jsonResponse{"error": "unauthenticated", "message": msg})
		}
		resolve := ResolveUserID
		if resolve == nil {
			unauthenticated("No identity resolver is configured")
			return
		}
		uid, ok := resolve(r)
		if !ok {
			unauthenticated("Authentication required")
			return
		}
		ctx := r.Context()
		var role string
		if err := db.QueryRowContext(ctx, `SELECT role FROM users WHERE id=? AND status='active'`, uid).Scan(&role); err != nil {
			unauthenticated("Authentication required")
			return
		}
		ctx = context.WithValue(ctx, ctxUserIDKey, uid)
		ctx = context.WithValue(ctx, ctxRoleKey, role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ---------- End of File ----------

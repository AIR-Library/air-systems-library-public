package auth

// Package auth is the AOI Systems Library auth template: signup with NIST SP 800-63B-4 password
// rules, email verification, login with optional TOTP MFA, OAuth callback with state and a provider
// exchange, refresh, and HS256 access-token verification.
//
// Phase B, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: AUTH-03 now answers password_rejected with a
// reason (too_short, too_long, blocklisted, first failure wins); the JWT secret is per instance, never a
// constant; the verification email goes through an injectable EmailSender; MFA verifies the TOTP code
// against the challenge the caller names (it used to take the newest challenge of ANY user); OAuth
// checks a single-use state and takes the email from an injectable provider exchange (it used to take
// the email from the client's code); the login failure limit is enforced (it was counted, never
// checked). Touches: SQLite, the injected email sender and OAuth provider (network in production).
//
// Phase B.2, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-16 and the spec's "Secrets at rest" line):
// every flow that creates a session (login, MFA, OAuth) returns its refresh_token, which TokenRefresh
// accepts; sessions keep only refresh_token_hash (HMAC-SHA256) and verification_codes only code_hash (the email
// code's HMAC-SHA256, or the MFA challenge id's), so a database read hands out no usable credential. OAuth state
// stays single-use, 10 minutes, stored as its hash, and the provider code is exchanged through the injected
// OAuthProvider.
//
// spec d270fa3, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (keyed HMAC for stored secrets): those hashes
// are now HMAC-SHA256 under a server key (Options.SecretKey, else the AUTH_SECRET_KEY environment variable,
// at least 32 bytes; the constructor refuses to start without it), not a plain SHA-256, because a 6-digit
// code's plain hash can be brute-forced from a leaked table. Touches also: the process environment (read).
import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	accessTokenTTL     = time.Hour
	refreshTokenTTL    = 24 * time.Hour
	verificationTTL    = 15 * time.Minute
	mfaChallengeTTL    = 5 * time.Minute
	oauthStateTTL      = 10 * time.Minute
	serviceName        = "MyService"
	maxSignupPerIP24h  = 5
	maxLoginFails15m   = 5
	passwordMinLength  = 15
	passwordMaxLength  = 64
)

var (
	commonPasswords = []string{
		"123456", "password", "123456789", "qwerty", "111111", "12345678",
	}
)

// ---------- Database schema ----------
var schema = []string{
	`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT NOT NULL UNIQUE,
		password_hash TEXT,
		tier TEXT NOT NULL DEFAULT 'free',
		status TEXT NOT NULL DEFAULT 'unverified',
		email_verified_at TEXT,
		mfa_secret TEXT,
		mfa_enabled INTEGER NOT NULL DEFAULT 0,
		name TEXT
	);`,
	`CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		refresh_token_hash TEXT NOT NULL UNIQUE, -- HMAC-SHA256 of the refresh token; the token itself is never stored (Phase B.2, 2026-11-10)
		created_at TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		ip TEXT,
		device_id TEXT,
		FOREIGN KEY(user_id) REFERENCES users(id)
	);`,
	`CREATE TABLE IF NOT EXISTS audit_log (
		timestamp TEXT NOT NULL,
		actor_id INTEGER,
		action TEXT NOT NULL,
		resource_type TEXT,
		resource_id INTEGER,
		old_value TEXT,
		new_value TEXT
	);`,
	`CREATE TABLE IF NOT EXISTS verification_codes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		code_hash TEXT NOT NULL, -- HMAC-SHA256 of the email code or MFA challenge id; never the value (Phase B.2, 2026-11-10)
		created_at TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		type TEXT NOT NULL,
		attempts INTEGER NOT NULL DEFAULT 0, -- tries of this email code (Phase B.3, 2026-11-10: 5 wrong ones invalidate it)
		FOREIGN KEY(user_id) REFERENCES users(id)
	);`,
	// oauth_states and oauth_accounts added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the state an
	// oauth_callback must match (stored as a HMAC-SHA256 hash, single use) and the provider links AUTH-10/11
	// require.
	`CREATE TABLE IF NOT EXISTS oauth_states (
		state_hash TEXT PRIMARY KEY,
		provider TEXT NOT NULL,
		expires_at TEXT NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS oauth_accounts (
		provider TEXT NOT NULL,
		provider_user_id TEXT NOT NULL,
		user_id INTEGER NOT NULL,
		created_at TEXT NOT NULL,
		PRIMARY KEY (provider, provider_user_id),
		FOREIGN KEY(user_id) REFERENCES users(id)
	);`,
}

// ---------- Helper types ----------
type jsonResponse map[string]interface{}

func jsonSuccess(data map[string]interface{}) jsonResponse {
	resp := jsonResponse{"success": true}
	for k, v := range data {
		resp[k] = v
	}
	return resp
}

func jsonError(code, message string) jsonResponse {
	return jsonResponse{"success": false, "error": code, "message": message}
}

// passwordRejected is the AUTH-03 answer: {error: "password_rejected", reason}, reason one of
// too_short, too_long, blocklisted. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (was
// password_too_weak, which the amended spec removes). Touches nothing.
func passwordRejected(reason string) jsonResponse {
	resp := jsonError("password_rejected", "Password rejected: "+reason)
	resp["reason"] = reason
	return resp
}

// ---------- Logging ----------
func whyChain(flow string, decisionPoints []string) {
	log.Printf("why_chain flow=%s decisions=%v", flow, decisionPoints)
}

func auditLog(ctx context.Context, db *sql.DB, actorID sql.NullInt64, action, resourceType string, resourceID sql.NullInt64, oldVal, newVal string) {
	_, _ = db.ExecContext(ctx,
		`INSERT INTO audit_log (timestamp, actor_id, action, resource_type, resource_id, old_value, new_value)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339), actorID, action, resourceType, resourceID, oldVal, newVal)
}

// ---------- Rate limiting (in‑memory) ----------
type rateBucket struct {
	count int
	reset time.Time
}

// rateLimiter holds fixed-window counters behind a mutex. Changed 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP: the buckets were package globals without a lock, shared by every
// AuthSystem and racing between goroutines. Touches: memory only.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rateBucket
}

// hit adds one to key's window and reports whether the count was already at max (refused).
// In: key, the max and the window, and the current time. Added 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func (r *rateLimiter) hit(key string, max int, window time.Duration, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.buckets[key]
	if !ok || now.After(b.reset) {
		b = &rateBucket{reset: now.Add(window)}
		r.buckets[key] = b
	}
	if b.count >= max {
		return false
	}
	b.count++
	return true
}

// blocked reports whether key's window is at max without counting. Added 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP (the login limit was counted but never checked). Touches: memory.
func (r *rateLimiter) blocked(key string, max int, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.buckets[key]
	return ok && !now.After(b.reset) && b.count >= max
}

// reset forgets key's window. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (r *rateLimiter) reset(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.buckets, key)
}

// ---------- Password utilities ----------
// isBlocklisted reports whether pw is a common password or IS the user's email, name or the service
// name (case-insensitive; empty values never match). In: password, email, name. Out: bool.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the spec says "as the password", and the old
// substring test made every password blocklisted when the name was empty. Touches nothing.
func isBlocklisted(pw, email, name string) bool {
	lower := strings.ToLower(pw)
	for _, own := range []string{email, name, serviceName} {
		if own != "" && lower == strings.ToLower(own) {
			return true
		}
	}
	for _, blk := range commonPasswords {
		if lower == blk {
			return true
		}
	}
	return false
}

// validatePassword applies the spec's password rules in order, first failure wins: too_short (< 15
// characters), too_long (> 64), blocklisted (a bundled common password, or the user's own email or
// name, or the service name, compared case-insensitively). Length counts Unicode characters, not bytes.
// In: the password, email and name. Out: "" or the reason.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-03): the reason is the answer (no
// password_too_weak error); byte length made "ééééééééé" count double; and the blocklist used
// "contains", so an empty name rejected every password.
func validatePassword(pw, email, name string) string {
	n := utf8.RuneCountInString(pw)
	if n < passwordMinLength {
		return "too_short"
	}
	if n > passwordMaxLength {
		return "too_long"
	}
	if isBlocklisted(pw, email, name) {
		return "blocklisted"
	}
	return ""
}

// ---------- Token utilities ----------
func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// createAccessToken signs an HS256 JWT {user_id, tier, iat, exp} with this instance's secret.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the secret was a hard-coded constant (spec
// README: no secret is hard-coded). Touches nothing.
func (a *AuthSystem) createAccessToken(userID int64, tier string) (string, error) {
	now := a.now()
	claims := jwt.MapClaims{
		"user_id": userID,
		"tier":    tier,
		"exp":     now.Add(accessTokenTTL).Unix(),
		"iat":     now.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(a.jwtSecret)
}

// hmacSHA256Hex is the lowercase hex HMAC-SHA256(key, s): the only form in which refresh tokens,
// verification codes, MFA challenge ids and OAuth states are stored. In: the key, the secret. Out: 64 hex
// characters. Why: spec d270fa3: keyed HMAC for stored secrets (it replaced the plain SHA-256 helper
// sha256Hex). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func hmacSHA256Hex(key []byte, s string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return hex.EncodeToString(m.Sum(nil))
}

// hashSecret is the stored form of a secret under this instance's key: hmacSHA256Hex(a.secretKey, s).
// In: the secret. Out: 64 hex characters. Why: spec d270fa3: keyed HMAC for stored secrets.
// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func (a *AuthSystem) hashSecret(s string) string {
	return hmacSHA256Hex(a.secretKey, s)
}

// minSecretKeyBytes is the shortest HMAC key the service starts with (spec d270fa3: AUTH_SECRET_KEY, at
// least 32 bytes). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
const minSecretKeyBytes = 32

// constantTimeEqual compares two secrets without leaking where they differ.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec README: secrets compared in constant time).
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// EmailSender delivers the signup verification email. Production wraps an email provider; tests pass
// a fake. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-01 "email sent"; the email was
// omitted). Touches: network in production.
type EmailSender interface {
	SendVerificationEmail(ctx context.Context, email, code string) error
}

// OAuthIdentity is what a provider returns for an authorization code.
type OAuthIdentity struct {
	ProviderUserID string
	Email          string
	EmailVerified  bool
}

// OAuthProvider exchanges an authorization code with the provider (server to server) for the user's
// identity. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the callback used the client's code
// AS the email, so anyone could sign in as anyone. Touches: network in production.
type OAuthProvider interface {
	ExchangeCode(ctx context.Context, provider, code string) (OAuthIdentity, error)
}

// Options configures NewAuthSystemWithOptions. JWTSecret must be at least 32 bytes (a random one is
// generated when empty); Now is the clock (nil = time.Now). Added 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
// SecretKey (added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, spec d270fa3: keyed HMAC for stored
// secrets) keys the HMAC-SHA256 every stored secret is kept as; empty means the AUTH_SECRET_KEY
// environment variable. It must be at least 32 bytes, or the constructor returns an error.
type Options struct {
	JWTSecret []byte
	SecretKey []byte
	Email     EmailSender
	OAuth     OAuthProvider
	Now       func() time.Time
}

// ---------- Core flows ----------
type AuthSystem struct {
	db        *sql.DB
	jwtSecret []byte
	secretKey []byte // HMAC key for stored secrets (spec d270fa3, 2026-11-10)
	email     EmailSender
	oauth     OAuthProvider
	now       func() time.Time
	signups   *rateLimiter
	loginFail *rateLimiter
}

// NewAuthSystem creates an instance on an in-memory SQLite DB with a random JWT secret and no email
// sender or OAuth provider (signup then refuses with email_unavailable, and OAuth with
// oauth_unavailable, rather than pretend). Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Since spec d270fa3 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP) it reads the HMAC key from
// AUTH_SECRET_KEY and returns an error when that is unset or shorter than 32 bytes. Touches: SQLite,
// the process environment (read).
func NewAuthSystem() (*AuthSystem, error) {
	return NewAuthSystemWithOptions(Options{})
}

// NewAuthSystemWithOptions creates an instance on an in-memory SQLite DB (one connection, since
// every new :memory: connection is a separate empty database).
// In: Options. Out: the system, or an error for a JWT secret shorter than 32 bytes.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite; crypto/rand.
// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: the HMAC key
// is opts.SecretKey, else AUTH_SECRET_KEY; with neither, or one shorter than 32 bytes, it returns an error
// before opening the database, so the service refuses to start. Touches also: the process environment (read).
func NewAuthSystemWithOptions(opts Options) (*AuthSystem, error) {
	secretKey := opts.SecretKey
	if len(secretKey) == 0 {
		secretKey = []byte(os.Getenv("AUTH_SECRET_KEY"))
	}
	if len(secretKey) < minSecretKeyBytes {
		return nil, errors.New("AUTH_SECRET_KEY must be set and at least 32 bytes")
	}
	secretKey = append([]byte(nil), secretKey...)
	secret := opts.JWTSecret
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
	} else if len(secret) < 32 {
		return nil, errors.New("jwt secret must be at least 32 bytes")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			return nil, err
		}
	}
	return &AuthSystem{db: db, jwtSecret: secret, secretKey: secretKey, email: opts.Email, oauth: opts.OAuth, now: now,
		signups: &rateLimiter{buckets: map[string]*rateBucket{}}, loginFail: &rateLimiter{buckets: map[string]*rateBucket{}}}, nil
}

// getUserIDByEmail retrieves user ID by email (test helper).
func (a *AuthSystem) getUserIDByEmail(ctx context.Context, email string) (int64, error) {
	var userID int64
	err := a.db.QueryRowContext(ctx, `SELECT id FROM users WHERE email = ?`, email).Scan(&userID)
	return userID, err
}

// createSession stores a session with a fresh refresh token and returns its id, an access token and the
// refresh token. Only the refresh token's HMAC-SHA256 is stored (refresh_token_hash); the caller hands the
// token itself to the client, once. In: user id, tier, ip and device id. Out: session id, access token,
// refresh token, error. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (one place for login, OAuth and
// MFA, which each repeated it). Changed the same day (Phase B.2, AUTH-16): it stored the refresh token in
// plain text and returned none, so no flow could hand it out. Touches: SQLite (sessions); crypto/rand.
// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
func (a *AuthSystem) createSession(ctx context.Context, userID int64, tier, ip, deviceID string) (string, string, string, error) {
	sessionID, err := generateRandomString(24)
	if err != nil {
		return "", "", "", err
	}
	refreshToken, err := generateRandomString(32)
	if err != nil {
		return "", "", "", err
	}
	now := a.now().UTC()
	if _, err = a.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, refresh_token_hash, created_at, expires_at, ip, device_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sessionID, userID, a.hashSecret(refreshToken), now.Format(time.RFC3339), now.Add(refreshTokenTTL).Format(time.RFC3339),
		ip, deviceID); err != nil {
		return "", "", "", err
	}
	token, err := a.createAccessToken(userID, tier)
	return sessionID, token, refreshToken, err
}

// Signup creates an unverified user and emails a verification code.
// In: email, password, name and the caller's IP. Out: {success, status: "pending_verification",
// email, message} or {error: too_many_signups_from_ip | email_already_exists | password_rejected
// (with reason) | email_unavailable | internal_error}.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-01, AUTH-03): password_rejected with a
// reason replaces password_too_weak; the verification email is really sent through EmailSender, and a
// failed send rolls the user back so the address can sign up again. Changed the same day (Phase B.2,
// AUTH-16): the code is stored only as its HMAC-SHA256 (code_hash); the email carries the code itself.
// Touches: SQLite, the email sender.
// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
func (a *AuthSystem) Signup(ctx context.Context, email, password, name, ip string) jsonResponse {
	decision := []string{}
	if !a.signups.hit(ip, maxSignupPerIP24h, 24*time.Hour, a.now()) {
		whyChain("signup", []string{"rate_limit_ip_24h"})
		return jsonError("too_many_signups_from_ip", "Rate limit exceeded")
	}
	decision = append(decision, "rate_limit_ip_24h")

	var exists int
	if err := a.db.QueryRowContext(ctx, "SELECT COUNT(1) FROM users WHERE email = ?", email).Scan(&exists); err != nil {
		return jsonError("internal_error", "database error")
	}
	if exists > 0 {
		whyChain("signup", []string{"email_unique"})
		return jsonError("email_already_exists", "Email already registered")
	}
	decision = append(decision, "email_unique")

	if reason := validatePassword(password, email, name); reason != "" {
		whyChain("signup", []string{"password_strength"})
		return passwordRejected(reason)
	}
	decision = append(decision, "password_strength")
	if a.email == nil {
		return jsonError("email_unavailable", "No email sender is configured")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return jsonError("internal_error", "hash error")
	}
	code, err := generateRandomString(6)
	if err != nil {
		return jsonError("internal_error", "random source error")
	}
	now := a.now().UTC()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return jsonError("internal_error", "database error")
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO users (email, password_hash, name, status) VALUES (?, ?, ?, 'unverified')`,
		email, string(hash), name)
	if err != nil {
		return jsonError("email_already_exists", "Email already registered")
	}
	userID, _ := res.LastInsertId()
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO verification_codes (user_id, code_hash, created_at, expires_at, type) VALUES (?, ?, ?, ?, 'email')`,
		userID, a.hashSecret(code), now.Format(time.RFC3339), now.Add(verificationTTL).Format(time.RFC3339)); err != nil {
		return jsonError("internal_error", "database error")
	}
	if err := a.email.SendVerificationEmail(ctx, email, code); err != nil {
		return jsonError("email_unavailable", "The verification email could not be sent")
	}
	if err := tx.Commit(); err != nil {
		return jsonError("internal_error", "database error")
	}

	whyChain("signup", decision)
	auditLog(ctx, a.db, sql.NullInt64{Int64: userID, Valid: true},
		"user_created", "user", sql.NullInt64{Int64: userID, Valid: true}, "", "")

	return jsonSuccess(map[string]interface{}{
		"status":  "pending_verification",
		"email":   email,
		"message": "check email",
	})
}

// VerifyEmail marks a user verified when the code matches (constant time) and has not expired.
// In: email and code. Out: {success, status: "verified", user_id, message} or {error: code_invalid |
// code_expired}. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: constant-time compare and the
// injectable clock; the same day (Phase B.2, AUTH-16) the HMAC-SHA256 of the given code is compared, in constant
// time, with the stored code_hash (the code was stored in plain text). Touches: SQLite.
// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.3 (commit d4f4ed7): at most 5 tries per code, counted by
// a conditional write on verification_codes.attempts before the compare; the 6th and later get code_invalid.
func (a *AuthSystem) VerifyEmail(ctx context.Context, email, code string) jsonResponse {
	decision := []string{}
	var userID, codeID int64
	var storedHash, expiresAt string
	var emailVerifiedAt sql.NullString
	err := a.db.QueryRowContext(ctx,
		`SELECT vc.id, vc.user_id, vc.code_hash, vc.expires_at, u.email_verified_at
		 FROM verification_codes vc
		 JOIN users u ON u.id = vc.user_id
		 WHERE u.email = ? AND vc.type = 'email' ORDER BY vc.id DESC LIMIT 1`,
		email).Scan(&codeID, &userID, &storedHash, &expiresAt, &emailVerifiedAt)
	if err != nil {
		whyChain("verify_email", []string{"code_valid"})
		return jsonError("code_invalid", "Invalid verification code")
	}
	// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.3 (commit d4f4ed7, auth spec flow 2 "Attempts"): every
	// try is counted first, in one conditional write, before the code is compared. A code that already had 5
	// tries is invalid, so after 5 wrong codes even the right one gets code_invalid until a new code is sent
	// (a new code is a new row with 0 tries). The right code on the 5th try still verifies.
	res, err := a.db.ExecContext(ctx, `UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ? AND attempts < 5`, codeID)
	if err != nil {
		return jsonError("internal_error", "database error")
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		whyChain("verify_email", []string{"code_valid"})
		return jsonError("code_invalid", "Invalid verification code")
	}
	if !constantTimeEqual(storedHash, a.hashSecret(code)) {
		whyChain("verify_email", []string{"code_valid"})
		return jsonError("code_invalid", "Invalid verification code")
	}
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil || !a.now().Before(exp) {
		whyChain("verify_email", []string{"code_valid"})
		return jsonError("code_expired", "Verification code expired")
	}
	decision = append(decision, "code_valid")
	if emailVerifiedAt.Valid {
		whyChain("verify_email", decision)
		return jsonError("code_invalid", "Email already verified")
	}
	decision = append(decision, "user_unverified")
	if _, err = a.db.ExecContext(ctx,
		`UPDATE users SET email_verified_at = ?, status = 'verified' WHERE id = ?`,
		a.now().UTC().Format(time.RFC3339), userID); err != nil {
		return jsonError("internal_error", "database error")
	}
	_, _ = a.db.ExecContext(ctx, `DELETE FROM verification_codes WHERE user_id = ? AND type = 'email'`, userID)

	whyChain("verify_email", decision)
	auditLog(ctx, a.db, sql.NullInt64{Int64: userID, Valid: true},
		"email_verified", "user", sql.NullInt64{Int64: userID, Valid: true}, "", "")
	return jsonSuccess(map[string]interface{}{
		"status":  "verified",
		"user_id": userID,
		"message": "ready to login",
	})
}

// Login checks the password and either opens a session or, with MFA on, starts a challenge.
// In: email, password, device id, IP. Out: {success, status: "authenticated", session_id, token,
// refresh_token, expires_in, user} or {success, status: "mfa_required", challenge_id} or {error:
// invalid_credentials | too_many_login_attempts | internal_error}. refresh_token added 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, AUTH-16: login returned none).
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the 5-failures-per-15-minutes limit per
// ip+email is now enforced before the password is checked (it was counted, never read); the MFA
// challenge row stores the HMAC-SHA256 of a random challenge id, and the code is checked later against the
// user's TOTP secret, not stored. Touches: SQLite.
// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
func (a *AuthSystem) Login(ctx context.Context, email, password, deviceID, ip string) jsonResponse {
	decision := []string{}
	rateKey := ip + "\x00" + strings.ToLower(email)
	if a.loginFail.blocked(rateKey, maxLoginFails15m, a.now()) {
		whyChain("login", []string{"rate_limit"})
		return jsonError("too_many_login_attempts", "Too many failed logins; try again later")
	}
	var userID int64
	var pwHash sql.NullString
	var mfaEnabled int
	var tier, status string
	err := a.db.QueryRowContext(ctx,
		`SELECT id, password_hash, mfa_enabled, tier, status FROM users WHERE email = ?`,
		email).Scan(&userID, &pwHash, &mfaEnabled, &tier, &status)
	if err != nil || !pwHash.Valid {
		a.loginFail.hit(rateKey, maxLoginFails15m, 15*time.Minute, a.now())
		whyChain("login", []string{"user_exists"})
		return jsonError("invalid_credentials", "Invalid email or password")
	}
	decision = append(decision, "user_exists")
	if err := bcrypt.CompareHashAndPassword([]byte(pwHash.String), []byte(password)); err != nil {
		a.loginFail.hit(rateKey, maxLoginFails15m, 15*time.Minute, a.now())
		whyChain("login", decision)
		return jsonError("invalid_credentials", "Invalid email or password")
	}
	if status != "verified" {
		whyChain("login", decision)
		return jsonError("invalid_credentials", "Email not verified")
	}
	decision = append(decision, "password_correct", "rate_limit")
	a.loginFail.reset(rateKey)

	if mfaEnabled == 1 {
		challengeID, err := generateRandomString(24)
		if err != nil {
			return jsonError("internal_error", "random source error")
		}
		now := a.now().UTC()
		if _, err := a.db.ExecContext(ctx,
			`INSERT INTO verification_codes (user_id, code_hash, created_at, expires_at, type) VALUES (?, ?, ?, ?, 'mfa')`,
			userID, a.hashSecret(challengeID), now.Format(time.RFC3339), now.Add(mfaChallengeTTL).Format(time.RFC3339)); err != nil {
			return jsonError("internal_error", "database error")
		}
		whyChain("login", append(decision, "mfa_gate"))
		return jsonSuccess(map[string]interface{}{
			"status":       "mfa_required",
			"challenge_id": challengeID,
		})
	}
	decision = append(decision, "mfa_gate")
	sessionID, accessToken, refreshToken, err := a.createSession(ctx, userID, tier, ip, deviceID)
	if err != nil {
		return jsonError("internal_error", "session error")
	}
	whyChain("login", decision)
	auditLog(ctx, a.db, sql.NullInt64{Int64: userID, Valid: true},
		"session_created", "session", sql.NullInt64{Int64: userID, Valid: true}, "", "")

	return jsonSuccess(map[string]interface{}{
		"status":        "authenticated",
		"session_id":    sessionID,
		"token":         accessToken,
		"refresh_token": refreshToken,
		"expires_in":    int(accessTokenTTL.Seconds()),
		"user": map[string]interface{}{
			"id":    userID,
			"email": email,
			"tier":  tier,
		},
	})
}

// StartOAuth begins an OAuth sign-in: it returns a random state to send to the provider and keeps
// only its HMAC-SHA256, for 10 minutes, bound to the provider. In: the provider name. Out: the state.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: oauth_callback's state_valid gate ("matches
// session, not expired") had nothing to match. Touches: SQLite (oauth_states); crypto/rand.
// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
func (a *AuthSystem) StartOAuth(ctx context.Context, provider string) (string, error) {
	state, err := generateRandomString(32)
	if err != nil {
		return "", err
	}
	_, err = a.db.ExecContext(ctx, `INSERT INTO oauth_states (state_hash, provider, expires_at) VALUES (?, ?, ?)`,
		a.hashSecret(state), provider, a.now().Add(oauthStateTTL).UTC().Format(time.RFC3339))
	return state, err
}

// OAuthCallback finishes an OAuth sign-in: the state must be one StartOAuth issued for this provider,
// unexpired and unused (it is consumed); the code is exchanged with the provider for the identity,
// whose email the provider must have verified. Case A: a new email creates a verified user. Case B:
// an existing email links the provider to that account. Either way the provider identity is linked
// in oauth_accounts and a session is opened.
// In: provider, code, state. Out: {success, status: "authenticated", session_id, token, refresh_token,
// expires_in, user} or {error: invalid_state | oauth_unavailable | oauth_exchange_failed |
// email_not_verified | oauth_account_conflict | internal_error}. refresh_token and expires_in added
// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, AUTH-16: every flow that creates a session
// returns its refresh token).
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the old callback skipped the state check and
// used the client's code AS the email, so anyone could sign in as any account. Touches: SQLite, the
// OAuth provider (network in production).
// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
func (a *AuthSystem) OAuthCallback(ctx context.Context, provider, code, state string) jsonResponse {
	res, err := a.db.ExecContext(ctx, `DELETE FROM oauth_states WHERE state_hash = ? AND provider = ? AND expires_at > ?`,
		a.hashSecret(state), provider, a.now().UTC().Format(time.RFC3339))
	if err != nil {
		return jsonError("internal_error", "database error")
	}
	if n, _ := res.RowsAffected(); n != 1 {
		whyChain("oauth_callback", []string{"state_valid"})
		return jsonError("invalid_state", "OAuth state is missing, expired or already used")
	}
	decision := []string{"state_valid"}
	if a.oauth == nil {
		return jsonError("oauth_unavailable", "No OAuth provider is configured")
	}
	id, err := a.oauth.ExchangeCode(ctx, provider, code)
	if err != nil || id.ProviderUserID == "" || id.Email == "" {
		return jsonError("oauth_exchange_failed", "The provider did not accept the code")
	}
	if !id.EmailVerified {
		whyChain("oauth_callback", append(decision, "email_verified"))
		return jsonError("email_not_verified", "The provider has not verified this email")
	}
	decision = append(decision, "email_verified")

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return jsonError("internal_error", "database error")
	}
	defer tx.Rollback()
	var userID int64
	var tier string
	err = tx.QueryRowContext(ctx, "SELECT id, tier FROM users WHERE email = ?", id.Email).Scan(&userID, &tier)
	if err == sql.ErrNoRows {
		r, err := tx.ExecContext(ctx,
			`INSERT INTO users (email, status, tier, email_verified_at) VALUES (?, 'verified', 'free', ?)`,
			id.Email, a.now().UTC().Format(time.RFC3339))
		if err != nil {
			return jsonError("internal_error", "database error")
		}
		userID, _ = r.LastInsertId()
		tier = "free"
	} else if err != nil {
		return jsonError("internal_error", "database error")
	}
	var linkedTo int64
	err = tx.QueryRowContext(ctx, `SELECT user_id FROM oauth_accounts WHERE provider = ? AND provider_user_id = ?`,
		provider, id.ProviderUserID).Scan(&linkedTo)
	switch {
	case err == sql.ErrNoRows:
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO oauth_accounts (provider, provider_user_id, user_id, created_at) VALUES (?, ?, ?, ?)`,
			provider, id.ProviderUserID, userID, a.now().UTC().Format(time.RFC3339)); err != nil {
			return jsonError("internal_error", "database error")
		}
	case err != nil:
		return jsonError("internal_error", "database error")
	case linkedTo != userID:
		return jsonError("oauth_account_conflict", "This provider account is linked to another user")
	}
	if err := tx.Commit(); err != nil {
		return jsonError("internal_error", "database error")
	}
	sessionID, accessToken, refreshToken, err := a.createSession(ctx, userID, tier, "", "")
	if err != nil {
		return jsonError("internal_error", "session error")
	}
	whyChain("oauth_callback", decision)
	auditLog(ctx, a.db, sql.NullInt64{Int64: userID, Valid: true},
		"oauth_login", "session", sql.NullInt64{Int64: userID, Valid: true}, "", provider)

	return jsonSuccess(map[string]interface{}{
		"status":        "authenticated",
		"session_id":    sessionID,
		"token":         accessToken,
		"refresh_token": refreshToken,
		"expires_in":    int(accessTokenTTL.Seconds()),
		"user": map[string]interface{}{
			"id":    userID,
			"email": id.Email,
			"tier":  tier,
		},
	})
}

// MFAChallenge completes an MFA login: the challenge the caller names must exist and be unexpired,
// and the code must be a valid TOTP for that challenge's user (30 s steps, one step of skew). The
// challenge is consumed on success.
// In: challenge id (from Login) and the 6-digit code. Out: {success, status: "authenticated",
// session_id, token, refresh_token, expires_in, user} or {error: invalid_code | code_expired}.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: it used to ignore challenge_id and compare the
// code with the newest MFA row of ANY user, so one user's code could log in as another. Changed again the
// same day (Phase B.2, AUTH-16): the answer carries refresh_token (and expires_in), and the challenge is
// found by its code_hash. Touches: SQLite.
// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
func (a *AuthSystem) MFAChallenge(ctx context.Context, challengeID, code string) jsonResponse {
	var rowID, userID int64
	var expiresAt string
	var secret sql.NullString
	var tier string
	err := a.db.QueryRowContext(ctx,
		`SELECT vc.id, vc.user_id, vc.expires_at, u.mfa_secret, u.tier FROM verification_codes vc
		 JOIN users u ON u.id = vc.user_id WHERE vc.type = 'mfa' AND vc.code_hash = ?`,
		a.hashSecret(challengeID)).Scan(&rowID, &userID, &expiresAt, &secret, &tier)
	if err != nil || !secret.Valid || secret.String == "" {
		whyChain("mfa_challenge", []string{"challenge_valid"})
		return jsonError("invalid_code", "Challenge not found")
	}
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil || !a.now().Before(exp) {
		whyChain("mfa_challenge", []string{"challenge_valid"})
		return jsonError("code_expired", "MFA challenge expired")
	}
	decision := []string{"challenge_valid"}
	ok, err := totp.ValidateCustom(code, secret.String, a.now().UTC(), totp.ValidateOpts{Period: 30, Skew: 1, Digits: 6})
	if err != nil || !ok {
		whyChain("mfa_challenge", decision)
		return jsonError("invalid_code", "Invalid MFA code")
	}
	decision = append(decision, "code_correct")
	res, err := a.db.ExecContext(ctx, `DELETE FROM verification_codes WHERE id = ?`, rowID)
	if err != nil {
		return jsonError("internal_error", "database error")
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return jsonError("invalid_code", "Challenge already used")
	}
	sessionID, accessToken, refreshToken, err := a.createSession(ctx, userID, tier, "", "")
	if err != nil {
		return jsonError("internal_error", "session error")
	}
	whyChain("mfa_challenge", decision)
	auditLog(ctx, a.db, sql.NullInt64{Int64: userID, Valid: true},
		"mfa_verified", "user", sql.NullInt64{Int64: userID, Valid: true}, "", "")

	return jsonSuccess(map[string]interface{}{
		"status":        "authenticated",
		"session_id":    sessionID,
		"token":         accessToken,
		"refresh_token": refreshToken,
		"expires_in":    int(accessTokenTTL.Seconds()),
		"user": map[string]interface{}{
			"id":   userID,
			"tier": tier,
		},
	})
}

// TokenRefresh issues a new access token for a valid, unexpired refresh token of an active user.
// In: the refresh token. Out: {success, status: "ok", token, expires_in} or {error: invalid_token |
// token_expired | user_banned}. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the instance's
// secret and clock. Changed again the same day (Phase B.2, AUTH-16): the session is found by the HMAC-SHA256 of
// the given token (refresh_token_hash), and the stored hash is compared with it in constant time; the
// table no longer holds the token itself. Touches: SQLite.
// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: secrets are now stored and compared as HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
func (a *AuthSystem) TokenRefresh(ctx context.Context, refreshToken string) jsonResponse {
	decision := []string{}
	var userID int64
	var storedHash, expiresAt string
	given := a.hashSecret(refreshToken)
	err := a.db.QueryRowContext(ctx,
		`SELECT user_id, refresh_token_hash, expires_at FROM sessions WHERE refresh_token_hash = ?`,
		given).Scan(&userID, &storedHash, &expiresAt)
	if err != nil || refreshToken == "" || !constantTimeEqual(storedHash, given) {
		whyChain("token_refresh", []string{"token_valid"})
		return jsonError("invalid_token", "Refresh token not found")
	}
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil || !a.now().Before(exp) {
		whyChain("token_refresh", []string{"token_valid"})
		return jsonError("token_expired", "Refresh token expired")
	}
	decision = append(decision, "token_valid")
	var status, tier string
	if err = a.db.QueryRowContext(ctx, "SELECT status, tier FROM users WHERE id = ?", userID).Scan(&status, &tier); err != nil {
		return jsonError("invalid_token", "User not found")
	}
	if status == "banned" || status == "suspended" {
		whyChain("token_refresh", append(decision, "user_active"))
		return jsonError("user_banned", "User is banned or suspended")
	}
	decision = append(decision, "user_active")
	newToken, err := a.createAccessToken(userID, tier)
	if err != nil {
		return jsonError("internal_error", "token error")
	}
	whyChain("token_refresh", decision)
	auditLog(ctx, a.db, sql.NullInt64{Int64: userID, Valid: true},
		"token_refreshed", "user", sql.NullInt64{Int64: userID, Valid: true}, "", "")

	return jsonSuccess(map[string]interface{}{
		"status":     "ok",
		"token":      newToken,
		"expires_in": int(accessTokenTTL.Seconds()),
	})
}

// VerifyAccessToken checks an access token: HS256 only (passed explicitly, the header's alg is never
// trusted), signature before claims, exp required, then the user must exist and be active.
// In: the token. Out: {success, status: "ok", user: {id, email, tier}} or {error: invalid_token |
// token_expired | user_banned}. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the instance's
// secret and clock. Touches: SQLite (read).
func (a *AuthSystem) VerifyAccessToken(ctx context.Context, tokenStr string) jsonResponse {
	decision := []string{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(a.now))
	claims := jwt.MapClaims{}
	_, err := parser.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return a.jwtSecret, nil
	})
	if errors.Is(err, jwt.ErrTokenExpired) {
		whyChain("verify_access_token", append(decision, "signature_valid"))
		return jsonError("token_expired", "Token has expired")
	}
	if err != nil {
		whyChain("verify_access_token", []string{"signature_valid"})
		return jsonError("invalid_token", "Signature verification failed")
	}
	decision = append(decision, "signature_valid", "not_expired")

	uidFloat, ok := claims["user_id"].(float64)
	if !ok {
		return jsonError("invalid_token", "Invalid token payload")
	}
	userID := int64(uidFloat)
	var status, email, tier string
	if err = a.db.QueryRowContext(ctx, `SELECT status, email, tier FROM users WHERE id = ?`,
		userID).Scan(&status, &email, &tier); err != nil {
		return jsonError("invalid_token", "User not found")
	}
	if status == "banned" || status == "suspended" {
		whyChain("verify_access_token", append(decision, "user_active"))
		return jsonError("user_banned", "User is banned or suspended")
	}
	decision = append(decision, "user_active")
	whyChain("verify_access_token", decision)
	return jsonSuccess(map[string]interface{}{
		"status": "ok",
		"user": map[string]interface{}{
			"id":    userID,
			"email": email,
			"tier":  tier,
		},
	})
}

// Helper to marshal response (used by HTTP layer if needed)
func MarshalResponse(resp jsonResponse) []byte {
	b, _ := json.Marshal(resp)
	return b
}

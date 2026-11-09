package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/mail"
	"strings"
	"time"

	_ "modernc.org/sqlite"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtSecret          = "replace-with-secure-secret"
	accessTokenTTL     = time.Hour
	refreshTokenTTL    = 24 * time.Hour
	verificationTTL    = 15 * time.Minute
	mfaChallengeTTL    = 5 * time.Minute
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
		refresh_token TEXT NOT NULL,
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
		code TEXT NOT NULL,
		created_at TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		type TEXT NOT NULL,
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

var (
	signupIPBuckets  = map[string]*rateBucket{}
	loginFailBuckets = map[string]*rateBucket{}
)

func checkSignupRate(ip string) error {
	b, ok := signupIPBuckets[ip]
	if !ok || time.Now().After(b.reset) {
		b = &rateBucket{count: 0, reset: time.Now().Add(24 * time.Hour)}
		signupIPBuckets[ip] = b
	}
	if b.count >= maxSignupPerIP24h {
		return errors.New("too_many_signups_from_ip")
	}
	b.count++
	return nil
}

func checkLoginRate(key string) error {
	b, ok := loginFailBuckets[key]
	if !ok || time.Now().After(b.reset) {
		b = &rateBucket{count: 0, reset: time.Now().Add(15 * time.Minute)}
		loginFailBuckets[key] = b
	}
	if b.count >= maxLoginFails15m {
		return errors.New("too_many_login_attempts")
	}
	b.count++
	return nil

}

func resetLoginRate(key string) {
	delete(loginFailBuckets, key)
}

// ---------- Password utilities ----------
func isBlocklisted(pw, email, name string) bool {
	lower := strings.ToLower(pw)
	if strings.Contains(lower, strings.ToLower(email)) ||
		strings.Contains(lower, strings.ToLower(name)) ||
		strings.Contains(lower, strings.ToLower(serviceName)) {
		return true
	}
	for _, blk := range commonPasswords {
		if lower == blk {
			return true
		}
	}
	return false
}

func validatePassword(pw, email, name string) (string, error) {
	if len(pw) < passwordMinLength {
		return "too_short", errors.New("password_too_weak")
	}
	if len(pw) > passwordMaxLength {
		return "too_long", errors.New("password_too_weak")
	}
	if isBlocklisted(pw, email, name) {
		return "blocklisted", errors.New("password_too_weak")
	}
	return "", nil
}

// ---------- Token utilities ----------
func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func createAccessToken(userID int64, tier string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"tier":    tier,
		"exp":     time.Now().Add(accessTokenTTL).Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

// ---------- Core flows ----------
type AuthSystem struct {
	db *sql.DB
}

// NewAuthSystem creates a new instance with an in‑memory SQLite DB (useful for tests).
func NewAuthSystem() (*AuthSystem, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			return nil, err
		}
	}
	return &AuthSystem{db: db}, nil
}

// getLatestVerificationCode is a test helper to retrieve the most recent verification code for a user.
func (a *AuthSystem) getLatestVerificationCode(ctx context.Context, userID int64, codeType string) (string, error) {
	var code string
	err := a.db.QueryRowContext(ctx,
		`SELECT code FROM verification_codes WHERE user_id = ? AND type = ? ORDER BY id DESC LIMIT 1`,
		userID, codeType).Scan(&code)
	return code, err
}

// getUserIDByEmail retrieves user ID by email (test helper).
func (a *AuthSystem) getUserIDByEmail(ctx context.Context, email string) (int64, error) {
	var userID int64
	err := a.db.QueryRowContext(ctx, `SELECT id FROM users WHERE email = ?`, email).Scan(&userID)
	return userID, err
}

// 1. signup
func (a *AuthSystem) Signup(ctx context.Context, email, password, name, ip string) jsonResponse {
	decision := []string{}
	// rate limit
	if err := checkSignupRate(ip); err != nil {
		whyChain("signup", []string{"rate_limit_ip_24h"})
		return jsonError("too_many_signups_from_ip", "Rate limit exceeded")
	}
	decision = append(decision, "rate_limit_ip_24h")

	// email uniqueness
	var exists int
	err := a.db.QueryRowContext(ctx, "SELECT COUNT(1) FROM users WHERE email = ?", email).Scan(&exists)
	if err != nil {
		return jsonError("internal_error", err.Error())
	}
	if exists > 0 {
		whyChain("signup", []string{"email_unique"})
		return jsonError("email_already_exists", "Email already registered")
	}
	decision = append(decision, "email_unique")

	// password strength
	if reason, err := validatePassword(password, email, name); err != nil {
		whyChain("signup", []string{"password_strength"})
		return jsonError("password_too_weak", fmt.Sprintf("Password rejected: %s", reason))
	}
	decision = append(decision, "password_strength")

	// hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return jsonError("internal_error", err.Error())
	}

	// create user
	res, err := a.db.ExecContext(ctx,
		`INSERT INTO users (email, password_hash, name, status) VALUES (?, ?, ?, 'unverified')`,
		email, string(hash), name)
	if err != nil {
		return jsonError("internal_error", err.Error())
	}
	userID, _ := res.LastInsertId()

	// create verification code
	code, _ := generateRandomString(6)
	_, _ = a.db.ExecContext(ctx,
		`INSERT INTO verification_codes (user_id, code, created_at, expires_at, type)
		 VALUES (?, ?, ?, ?, 'email')`,
		userID, code, time.Now().UTC().Format(time.RFC3339),
		time.Now().Add(verificationTTL).UTC().Format(time.RFC3339))

	// (email sending omitted)

	whyChain("signup", decision)
	auditLog(ctx, a.db, sql.NullInt64{Int64: userID, Valid: true},
		"user_created", "user", sql.NullInt64{Int64: userID, Valid: true}, "", "")

	return jsonSuccess(map[string]interface{}{
		"status":  "pending_verification",
		"email":   email,
		"message": "check email",
	})
}

// 2. verify_email
func (a *AuthSystem) VerifyEmail(ctx context.Context, email, code string) jsonResponse {
	decision := []string{}
	var userID int64
	var storedCode, expiresAt string
	var emailVerifiedAt sql.NullString
	err := a.db.QueryRowContext(ctx,
		`SELECT vc.user_id, vc.code, vc.expires_at, u.email_verified_at
		 FROM verification_codes vc
		 JOIN users u ON u.id = vc.user_id
		 WHERE u.email = ? AND vc.type = 'email'`,
		email).Scan(&userID, &storedCode, &expiresAt, &emailVerifiedAt)
	if err != nil {
		whyChain("verify_email", []string{"code_valid"})
		return jsonError("code_invalid", "Invalid verification code")
	}
	decision = append(decision, "code_valid")
	if storedCode != code {
		whyChain("verify_email", decision)
		return jsonError("code_invalid", "Invalid verification code")
	}
	exp, _ := time.Parse(time.RFC3339, expiresAt)
	if time.Now().After(exp) {
		whyChain("verify_email", decision)
		return jsonError("code_expired", "Verification code expired")
	}
	if emailVerifiedAt.Valid {
		whyChain("verify_email", decision)
		return jsonError("code_invalid", "Email already verified")
	}
	decision = append(decision, "user_unverified")
	_, err = a.db.ExecContext(ctx,
		`UPDATE users SET email_verified_at = ?, status = 'verified' WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339), userID)
	if err != nil {
		return jsonError("internal_error", err.Error())
	}
	_, _ = a.db.ExecContext(ctx, `DELETE FROM verification_codes WHERE user_id = ? AND type = 'email'`, userID)

	whyChain("verify_email", decision)
	auditLog(ctx, a.db, sql.NullInt64{Int64: userID, Valid: true},
		"email_verified", "user", sql.NullInt64{Int64: userID, Valid: true}, "", "")

	return jsonSuccess(map[string]interface{}{
		"status":   "verified",
		"user_id":  userID,
		"message":  "ready to login",
	})
}

// 3. login
func (a *AuthSystem) Login(ctx context.Context, email, password, deviceID, ip string) jsonResponse {
	decision := []string{}
	var userID int64
	var pwHash string
	var mfaEnabled int
	var tier, status string
	err := a.db.QueryRowContext(ctx,
		`SELECT id, password_hash, mfa_enabled, tier, status FROM users WHERE email = ?`,
		email).Scan(&userID, &pwHash, &mfaEnabled, &tier, &status)
	if err != nil {
		whyChain("login", []string{"user_exists"})
		return jsonError("invalid_credentials", "Invalid email or password")
	}
	decision = append(decision, "user_exists")
	if status != "verified" {
		whyChain("login", decision)
		return jsonError("invalid_credentials", "Email not verified")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(pwHash), []byte(password)); err != nil {
		whyChain("login", decision)
		_ = checkLoginRate(fmt.Sprintf("%s:%s", ip, email))
		return jsonError("invalid_credentials", "Invalid email or password")
	}
	decision = append(decision, "password_correct")
	resetLoginRate(fmt.Sprintf("%s:%s", ip, email))

	if mfaEnabled == 1 {
		// create MFA challenge using user's mfa_secret
		var mfaSecret string
		err := a.db.QueryRowContext(ctx, `SELECT mfa_secret FROM users WHERE id = ?`, userID).Scan(&mfaSecret)
		if err != nil || mfaSecret == "" {
			return jsonError("internal_error", "MFA not configured")
		}
		challengeID, _ := generateRandomString(12)
		// A malformed secret gives an empty code, which must never be stored as a valid answer (2026-11-08, session f3daac6e, from review).
		code, genErr := totp.GenerateCodeCustom(mfaSecret, time.Now(), totp.ValidateOpts{Period: 30, Skew: 1})
		if genErr != nil || code == "" {
			return jsonError("internal_error", "MFA not configured")
		}
		_, _ = a.db.ExecContext(ctx,
			`INSERT INTO verification_codes (user_id, code, created_at, expires_at, type)
			 VALUES (?, ?, ?, ?, 'mfa')`,
			userID, code,
			time.Now().UTC().Format(time.RFC3339),
			time.Now().Add(mfaChallengeTTL).UTC().Format(time.RFC3339))
		whyChain("login", append(decision, "mfa_gate"))
		return jsonSuccess(map[string]interface{}{
			"status":       "mfa_required",
			"challenge_id": challengeID,
		})
	}
	decision = append(decision, "mfa_gate")
	// create session
	sessionID, _ := generateRandomString(24)
	refreshToken, _ := generateRandomString(32)
	now := time.Now().UTC()
	_, err = a.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, refresh_token, created_at, expires_at, ip, device_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sessionID, userID, refreshToken,
		now.Format(time.RFC3339),
		now.Add(refreshTokenTTL).Format(time.RFC3339),
		ip, deviceID)
	if err != nil {
		return jsonError("internal_error", err.Error())
	}
	accessToken, err := createAccessToken(userID, tier)
	if err != nil {
		return jsonError("internal_error", err.Error())
	}
	whyChain("login", decision)
	auditLog(ctx, a.db, sql.NullInt64{Int64: userID, Valid: true},
		"session_created", "session", sql.NullInt64{Int64: userID, Valid: true}, "", "")

	return jsonSuccess(map[string]interface{}{
		"status":       "authenticated",
		"session_id":   sessionID,
		"token":        accessToken,
		"expires_in":   int(accessTokenTTL.Seconds()),
		"user": map[string]interface{}{
			"id":   userID,
			"email": email,
			"tier": tier,
		},
	})
}

// 4. oauth_callback
func (a *AuthSystem) OAuthCallback(ctx context.Context, provider, code, state string) jsonResponse {
	decision := []string{}
	// For simplicity, assume state is valid and code contains email
	email := code // in real flow, exchange code for user info
	if _, err := mail.ParseAddress(email); err != nil {
		whyChain("oauth_callback", []string{"state_valid"})
		return jsonError("invalid_provider_data", "Invalid email from provider")
	}
	decision = append(decision, "state_valid")
	var userID int64
	var tier string
	err := a.db.QueryRowContext(ctx, "SELECT id, tier FROM users WHERE email = ?", email).Scan(&userID, &tier)
	if err == sql.ErrNoRows {
		// new user
		res, err := a.db.ExecContext(ctx,
			`INSERT INTO users (email, status, tier) VALUES (?, 'verified', 'free')`,
			email)
		if err != nil {
			return jsonError("internal_error", err.Error())
		}
		userID, _ = res.LastInsertId()
		tier = "free"
		decision = append(decision, "new_user")
	} else if err != nil {
		return jsonError("internal_error", err.Error())
	}
	decision = append(decision, "email_verified")
	// create session
	sessionID, _ := generateRandomString(24)
	refreshToken, _ := generateRandomString(32)
	now := time.Now().UTC()
	_, err = a.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, refresh_token, created_at, expires_at, ip, device_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sessionID, userID, refreshToken,
		now.Format(time.RFC3339),
		now.Add(refreshTokenTTL).Format(time.RFC3339),
		"", "")
	if err != nil {
		return jsonError("internal_error", err.Error())
	}
	accessToken, _ := createAccessToken(userID, tier)
	whyChain("oauth_callback", decision)
	auditLog(ctx, a.db, sql.NullInt64{Int64: userID, Valid: true},
		"oauth_login", "session", sql.NullInt64{Int64: userID, Valid: true}, "", "")

	return jsonSuccess(map[string]interface{}{
		"status":     "authenticated",
		"session_id": sessionID,
		"token":      accessToken,
		"user": map[string]interface{}{
			"id":   userID,
			"email": email,
			"tier": tier,
		},
	})
}

// 5. mfa_challenge
func (a *AuthSystem) MFAChallenge(ctx context.Context, challengeID, code string) jsonResponse {
	decision := []string{}
	var userID int64
	var storedCode, expiresAt string
	err := a.db.QueryRowContext(ctx,
		`SELECT user_id, code, expires_at FROM verification_codes WHERE type='mfa' ORDER BY id DESC LIMIT 1`,
	).Scan(&userID, &storedCode, &expiresAt)
	if err != nil {
		whyChain("mfa_challenge", []string{"challenge_valid"})
		return jsonError("invalid_code", "Challenge not found")
	}
	decision = append(decision, "challenge_valid")
	if storedCode != code {
		whyChain("mfa_challenge", decision)
		return jsonError("invalid_code", "Invalid MFA code")
	}
	exp, _ := time.Parse(time.RFC3339, expiresAt)
	if time.Now().After(exp) {
		whyChain("mfa_challenge", decision)
		return jsonError("code_expired", "MFA code expired")
	}
	decision = append(decision, "code_correct")
	// delete challenge
	_, _ = a.db.ExecContext(ctx, `DELETE FROM verification_codes WHERE user_id = ? AND type='mfa'`, userID)

	// create session
	sessionID, _ := generateRandomString(24)
	refreshToken, _ := generateRandomString(32)
	now := time.Now().UTC()
	var tier string
	_ = a.db.QueryRowContext(ctx, "SELECT tier FROM users WHERE id = ?", userID).Scan(&tier)
	_, err = a.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, refresh_token, created_at, expires_at, ip, device_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sessionID, userID, refreshToken,
		now.Format(time.RFC3339),
		now.Add(refreshTokenTTL).Format(time.RFC3339),
		"", "")
	if err != nil {
		return jsonError("internal_error", err.Error())
	}
	accessToken, _ := createAccessToken(userID, tier)
	whyChain("mfa_challenge", decision)
	auditLog(ctx, a.db, sql.NullInt64{Int64: userID, Valid: true},
		"mfa_verified", "user", sql.NullInt64{Int64: userID, Valid: true}, "", "")

	return jsonSuccess(map[string]interface{}{
		"status":     "authenticated",
		"session_id": sessionID,
		"token":      accessToken,
		"user": map[string]interface{}{
			"id":   userID,
			"tier": tier,
		},
	})
}

// 6. token_refresh
func (a *AuthSystem) TokenRefresh(ctx context.Context, refreshToken string) jsonResponse {
	decision := []string{}
	var userID int64
	var expiresAt string
	err := a.db.QueryRowContext(ctx,
		`SELECT user_id, expires_at FROM sessions WHERE refresh_token = ?`,
		refreshToken).Scan(&userID, &expiresAt)
	if err != nil {
		whyChain("token_refresh", []string{"token_valid"})
		return jsonError("invalid_token", "Refresh token not found")
	}
	decision = append(decision, "token_valid")
	exp, _ := time.Parse(time.RFC3339, expiresAt)
	if time.Now().After(exp) {
		whyChain("token_refresh", decision)
		return jsonError("token_expired", "Refresh token expired")
	}
	var status, tier string
	err = a.db.QueryRowContext(ctx, "SELECT status, tier FROM users WHERE id = ?", userID).Scan(&status, &tier)
	if err != nil {
		return jsonError("internal_error", err.Error())
	}
	if status == "banned" || status == "suspended" {
		whyChain("token_refresh", append(decision, "user_active"))
		return jsonError("user_banned", "User is banned or suspended")
	}
	decision = append(decision, "user_active")
	// issue new access token
	newToken, err := createAccessToken(userID, tier)
	if err != nil {
		return jsonError("internal_error", err.Error())
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

// 7. verify_access_token
func (a *AuthSystem) VerifyAccessToken(ctx context.Context, tokenStr string) jsonResponse {
	decision := []string{}
	// The library checks the signature before the claims, so only a genuine token can report that it expired.
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
	claims := jwt.MapClaims{}
	_, err := parser.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
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
	err = a.db.QueryRowContext(ctx,
		`SELECT status, email, tier FROM users WHERE id = ?`,
		userID).Scan(&status, &email, &tier)
	if err != nil {
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

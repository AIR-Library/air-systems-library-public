package auth

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestSignupHappyPath(t *testing.T) {
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	ip := "192.0.2.1"
	resp := as.Signup(ctx, "alice@example.com", "StrongPassword!12345", "Alice", ip)
	success, ok := resp["success"].(bool)
	if !ok || !success || resp["status"] != "pending_verification" {
		t.Fatalf("unexpected response: %v", resp)
	}
}

func TestSignupDuplicateEmail(t *testing.T) {
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	ip := "192.0.2.2"
	_ = as.Signup(ctx, "bob@example.com", "AnotherStrongPass!67890", "Bob", ip)
	resp := as.Signup(ctx, "bob@example.com", "NewPass!1234567890", "Bob2", ip)
	if resp["error"] != "email_already_exists" {
		t.Fatalf("expected duplicate email error, got %v", resp)
	}
}

func TestSignupWeakPassword(t *testing.T) {
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	ip := "192.0.2.3"
	resp := as.Signup(ctx, "carol@example.com", "short", "Carol", ip)
	if resp["error"] != "password_too_weak" {
		t.Fatalf("expected weak password error, got %v", resp)
	}
}

func TestSignupIPRateLimit(t *testing.T) {
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	ip := "192.0.2.4"
	for i := 0; i < 5; i++ {
		_ = as.Signup(ctx, fmt.Sprintf("user%d@example.com", i), "StrongPassword!12345", "User", ip)
	}
	resp := as.Signup(ctx, "exceed@example.com", "StrongPassword!12345", "Exceed", ip)
	if resp["error"] != "too_many_signups_from_ip" {
		t.Fatalf("expected rate limit error, got %v", resp)
	}
}

func TestVerifyEmailHappyPath(t *testing.T) {
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	ip := "192.0.2.5"
	resp := as.Signup(ctx, "dave@example.com", "StrongPassword!12345", "Dave", ip)
	success, ok := resp["success"].(bool)
	if !ok || !success {
		t.Fatalf("signup failed: %v", resp)
	}

	userID, err := as.getUserIDByEmail(ctx, "dave@example.com")
	if err != nil {
		t.Fatalf("getUserIDByEmail failed: %v", err)
	}

	code, err := as.getLatestVerificationCode(ctx, userID, "email")
	if err != nil {
		t.Fatalf("getLatestVerificationCode failed: %v", err)
	}

	resp = as.VerifyEmail(ctx, "dave@example.com", code)
	if resp["status"] != "verified" {
		t.Fatalf("expected verified status, got %v", resp)
	}
}

func TestVerifyEmailExpiredCode(t *testing.T) {
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	ip := "192.0.2.6"
	resp := as.Signup(ctx, "eve@example.com", "StrongPassword!12345", "Eve", ip)
	success, ok := resp["success"].(bool)
	if !ok || !success {
		t.Fatalf("signup failed: %v", resp)
	}

	userID, err := as.getUserIDByEmail(ctx, "eve@example.com")
	if err != nil {
		t.Fatalf("getUserIDByEmail failed: %v", err)
	}

	// manually expire only this user's code
	_, err = as.db.ExecContext(ctx,
		`UPDATE verification_codes SET expires_at = ? WHERE user_id = ? AND type = 'email'`,
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), userID)
	if err != nil {
		t.Fatalf("expire code failed: %v", err)
	}

	code, err := as.getLatestVerificationCode(ctx, userID, "email")
	if err != nil {
		t.Fatalf("getLatestVerificationCode failed: %v", err)
	}

	resp = as.VerifyEmail(ctx, "eve@example.com", code)
	if resp["error"] != "code_expired" {
		t.Fatalf("expected code_expired error, got %v", resp)
	}
}

func TestLoginHappyPathNoMFA(t *testing.T) {
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	ip := "192.0.2.7"
	resp := as.Signup(ctx, "frank@example.com", "StrongPassword!12345", "Frank", ip)
	success, ok := resp["success"].(bool)
	if !ok || !success {
		t.Fatalf("signup failed: %v", resp)
	}

	userID, err := as.getUserIDByEmail(ctx, "frank@example.com")
	if err != nil {
		t.Fatalf("getUserIDByEmail failed: %v", err)
	}

	code, err := as.getLatestVerificationCode(ctx, userID, "email")
	if err != nil {
		t.Fatalf("getLatestVerificationCode failed: %v", err)
	}
	_ = as.VerifyEmail(ctx, "frank@example.com", code)

	resp = as.Login(ctx, "frank@example.com", "StrongPassword!12345", "dev1", ip)
	if resp["status"] != "authenticated" {
		t.Fatalf("expected authenticated, got %v", resp)
	}
}

func TestLoginWithMFAEnabled(t *testing.T) {
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	ip := "192.0.2.8"
	resp := as.Signup(ctx, "grace@example.com", "StrongPassword!12345", "Grace", ip)
	success, ok := resp["success"].(bool)
	if !ok || !success {
		t.Fatalf("signup failed: %v", resp)
	}

	userID, err := as.getUserIDByEmail(ctx, "grace@example.com")
	if err != nil {
		t.Fatalf("getUserIDByEmail failed: %v", err)
	}

	code, err := as.getLatestVerificationCode(ctx, userID, "email")
	if err != nil {
		t.Fatalf("getLatestVerificationCode failed: %v", err)
	}
	_ = as.VerifyEmail(ctx, "grace@example.com", code)

	// enable MFA
	_, err = as.db.ExecContext(ctx, `UPDATE users SET mfa_enabled = 1, mfa_secret = ? WHERE email = ?`,
		"BASE32SECRET", "grace@example.com")
	if err != nil {
		t.Fatalf("enable MFA failed: %v", err)
	}

	resp = as.Login(ctx, "grace@example.com", "StrongPassword!12345", "dev2", ip)
	if resp["status"] != "mfa_required" {
		t.Fatalf("expected mfa_required, got %v", resp)
	}
}

func TestLoginInvalidPassword(t *testing.T) {
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	ip := "192.0.2.9"
	resp := as.Signup(ctx, "henry@example.com", "StrongPassword!12345", "Henry", ip)
	success, ok := resp["success"].(bool)
	if !ok || !success {
		t.Fatalf("signup failed: %v", resp)
	}

	userID, err := as.getUserIDByEmail(ctx, "henry@example.com")
	if err != nil {
		t.Fatalf("getUserIDByEmail failed: %v", err)
	}

	code, err := as.getLatestVerificationCode(ctx, userID, "email")
	if err != nil {
		t.Fatalf("getLatestVerificationCode failed: %v", err)
	}
	_ = as.VerifyEmail(ctx, "henry@example.com", code)

	resp = as.Login(ctx, "henry@example.com", "WrongPassword!", "dev3", ip)
	if resp["error"] != "invalid_credentials" {
		t.Fatalf("expected invalid_credentials, got %v", resp)
	}
}

func TestOAuthCallbackNewUser(t *testing.T) {
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	resp := as.OAuthCallback(ctx, "google", "newuser@example.com", "validstate")
	if resp["status"] != "authenticated" {
		t.Fatalf("expected authenticated, got %v", resp)
	}
}

func TestOAuthCallbackExistingUser(t *testing.T) {
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	ip := "192.0.2.10"
	resp := as.Signup(ctx, "ivy@example.com", "StrongPassword!12345", "Ivy", ip)
	success, ok := resp["success"].(bool)
	if !ok || !success {
		t.Fatalf("signup failed: %v", resp)
	}

	userID, err := as.getUserIDByEmail(ctx, "ivy@example.com")
	if err != nil {
		t.Fatalf("getUserIDByEmail failed: %v", err)
	}

	code, err := as.getLatestVerificationCode(ctx, userID, "email")
	if err != nil {
		t.Fatalf("getLatestVerificationCode failed: %v", err)
	}
	_ = as.VerifyEmail(ctx, "ivy@example.com", code)

	resp = as.OAuthCallback(ctx, "github", "ivy@example.com", "validstate")
	if resp["status"] != "authenticated" {
		t.Fatalf("expected authenticated, got %v", resp)
	}
}

func TestMFAChallengeHappyPath(t *testing.T) {
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	ip := "192.0.2.11"
	resp := as.Signup(ctx, "jack@example.com", "StrongPassword!12345", "Jack", ip)
	success, ok := resp["success"].(bool)
	if !ok || !success {
		t.Fatalf("signup failed: %v", resp)
	}

	userID, err := as.getUserIDByEmail(ctx, "jack@example.com")
	if err != nil {
		t.Fatalf("getUserIDByEmail failed: %v", err)
	}

	code, err := as.getLatestVerificationCode(ctx, userID, "email")
	if err != nil {
		t.Fatalf("getLatestVerificationCode failed: %v", err)
	}
	_ = as.VerifyEmail(ctx, "jack@example.com", code)

	// enable MFA and trigger login to create challenge
	_, err = as.db.ExecContext(ctx, `UPDATE users SET mfa_enabled = 1, mfa_secret = ? WHERE email = ?`,
		"BASE32SECRET", "jack@example.com")
	if err != nil {
		t.Fatalf("enable MFA failed: %v", err)
	}
	loginResp := as.Login(ctx, "jack@example.com", "StrongPassword!12345", "dev4", ip)
	challengeID, ok := loginResp["challenge_id"].(string)
	if !ok {
		t.Fatalf("no challenge_id in login response: %v", loginResp)
	}

	// fetch generated MFA code
	mfaCode, err := as.getLatestVerificationCode(ctx, userID, "mfa")
	if err != nil {
		t.Fatalf("getLatestVerificationCode for MFA failed: %v", err)
	}

	resp = as.MFAChallenge(ctx, challengeID, mfaCode)
	if resp["status"] != "authenticated" {
		t.Fatalf("expected authenticated, got %v", resp)
	}
}

func TestMFAChallengeWrongCode(t *testing.T) {
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	ip := "192.0.2.12"
	resp := as.Signup(ctx, "kate@example.com", "StrongPassword!12345", "Kate", ip)
	success, ok := resp["success"].(bool)
	if !ok || !success {
		t.Fatalf("signup failed: %v", resp)
	}

	userID, err := as.getUserIDByEmail(ctx, "kate@example.com")
	if err != nil {
		t.Fatalf("getUserIDByEmail failed: %v", err)
	}

	code, err := as.getLatestVerificationCode(ctx, userID, "email")
	if err != nil {
		t.Fatalf("getLatestVerificationCode failed: %v", err)
	}
	_ = as.VerifyEmail(ctx, "kate@example.com", code)

	_, err = as.db.ExecContext(ctx, `UPDATE users SET mfa_enabled = 1, mfa_secret = ? WHERE email = ?`,
		"BASE32SECRET", "kate@example.com")
	if err != nil {
		t.Fatalf("enable MFA failed: %v", err)
	}
	loginResp := as.Login(ctx, "kate@example.com", "StrongPassword!12345", "dev5", ip)
	challengeID, ok := loginResp["challenge_id"].(string)
	if !ok {
		t.Fatalf("no challenge_id in login response: %v", loginResp)
	}

	resp = as.MFAChallenge(ctx, challengeID, "000000")
	if resp["error"] != "invalid_code" {
		t.Fatalf("expected invalid_code, got %v", resp)
	}
}

func TestTokenRefreshHappyPath(t *testing.T) {
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	ip := "192.0.2.13"
	resp := as.Signup(ctx, "leo@example.com", "StrongPassword!12345", "Leo", ip)
	success, ok := resp["success"].(bool)
	if !ok || !success {
		t.Fatalf("signup failed: %v", resp)
	}

	userID, err := as.getUserIDByEmail(ctx, "leo@example.com")
	if err != nil {
		t.Fatalf("getUserIDByEmail failed: %v", err)
	}

	code, err := as.getLatestVerificationCode(ctx, userID, "email")
	if err != nil {
		t.Fatalf("getLatestVerificationCode failed: %v", err)
	}
	_ = as.VerifyEmail(ctx, "leo@example.com", code)

	loginResp := as.Login(ctx, "leo@example.com", "StrongPassword!12345", "dev6", ip)
	if loginResp["status"] != "authenticated" {
		t.Fatalf("login failed: %v", loginResp)
	}

	// fetch refresh token from sessions
	var rt string
	err = as.db.QueryRowContext(ctx,
		`SELECT refresh_token FROM sessions WHERE user_id = ?`,
		userID).Scan(&rt)
	if err != nil {
		t.Fatalf("fetch refresh_token failed: %v", err)
	}

	resp = as.TokenRefresh(ctx, rt)
	if resp["status"] != "ok" {
		t.Fatalf("expected ok, got %v", resp)
	}
}

func TestTokenRefreshBannedUser(t *testing.T) {
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	ip := "192.0.2.14"
	resp := as.Signup(ctx, "mia@example.com", "StrongPassword!12345", "Mia", ip)
	success, ok := resp["success"].(bool)
	if !ok || !success {
		t.Fatalf("signup failed: %v", resp)
	}

	userID, err := as.getUserIDByEmail(ctx, "mia@example.com")
	if err != nil {
		t.Fatalf("getUserIDByEmail failed: %v", err)
	}

	code, err := as.getLatestVerificationCode(ctx, userID, "email")
	if err != nil {
		t.Fatalf("getLatestVerificationCode failed: %v", err)
	}
	_ = as.VerifyEmail(ctx, "mia@example.com", code)

	// create session manually
	sessionID, _ := generateRandomString(24)
	rt, _ := generateRandomString(32)
	now := time.Now().UTC()
	_, err = as.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, refresh_token, created_at, expires_at, ip, device_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sessionID, userID, rt,
		now.Format(time.RFC3339),
		now.Add(refreshTokenTTL).Format(time.RFC3339),
		ip, "dev7")
	if err != nil {
		t.Fatalf("insert session failed: %v", err)
	}
	// ban user
	_, err = as.db.ExecContext(ctx, `UPDATE users SET status = 'banned' WHERE id = ?`, userID)
	if err != nil {
		t.Fatalf("ban user failed: %v", err)
	}

	resp = as.TokenRefresh(ctx, rt)
	if resp["error"] != "user_banned" {
		t.Fatalf("expected user_banned, got %v", resp)
	}
}

func TestVerifyAccessTokenValid(t *testing.T) {
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	ip := "192.0.2.15"
	resp := as.Signup(ctx, "nina@example.com", "StrongPassword!12345", "Nina", ip)
	success, ok := resp["success"].(bool)
	if !ok || !success {
		t.Fatalf("signup failed: %v", resp)
	}

	userID, err := as.getUserIDByEmail(ctx, "nina@example.com")
	if err != nil {
		t.Fatalf("getUserIDByEmail failed: %v", err)
	}

	code, err := as.getLatestVerificationCode(ctx, userID, "email")
	if err != nil {
		t.Fatalf("getLatestVerificationCode failed: %v", err)
	}
	_ = as.VerifyEmail(ctx, "nina@example.com", code)

	loginResp := as.Login(ctx, "nina@example.com", "StrongPassword!12345", "dev8", ip)
	if loginResp["status"] != "authenticated" {
		t.Fatalf("login failed: %v", loginResp)
	}

	token := loginResp["token"].(string)
	resp = as.VerifyAccessToken(ctx, token)
	if resp["status"] != "ok" {
		t.Fatalf("expected ok, got %v", resp)
	}
	if resp["user"].(map[string]interface{})["email"] != "nina@example.com" {
		t.Fatalf("expected email nina@example.com, got %v", resp["user"])
	}
}

func TestVerifyAccessTokenExpired(t *testing.T) {
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	// Create an expired token manually
	expiredToken := createExpiredToken(1, "free")
	resp := as.VerifyAccessToken(ctx, expiredToken)
	if resp["error"] != "token_expired" {
		t.Fatalf("expected token_expired, got %v", resp)
	}
}

func TestVerifyAccessTokenBannedUser(t *testing.T) {
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	ip := "192.0.2.16"
	resp := as.Signup(ctx, "oscar@example.com", "StrongPassword!12345", "Oscar", ip)
	success, ok := resp["success"].(bool)
	if !ok || !success {
		t.Fatalf("signup failed: %v", resp)
	}

	userID, err := as.getUserIDByEmail(ctx, "oscar@example.com")
	if err != nil {
		t.Fatalf("getUserIDByEmail failed: %v", err)
	}

	code, err := as.getLatestVerificationCode(ctx, userID, "email")
	if err != nil {
		t.Fatalf("getLatestVerificationCode failed: %v", err)
	}
	_ = as.VerifyEmail(ctx, "oscar@example.com", code)

	loginResp := as.Login(ctx, "oscar@example.com", "StrongPassword!12345", "dev9", ip)
	if loginResp["status"] != "authenticated" {
		t.Fatalf("login failed: %v", loginResp)
	}

	token := loginResp["token"].(string)
	// ban user
	_, err = as.db.ExecContext(ctx, `UPDATE users SET status = 'banned' WHERE id = ?`, userID)
	if err != nil {
		t.Fatalf("ban user failed: %v", err)
	}

	resp = as.VerifyAccessToken(ctx, token)
	if resp["error"] != "user_banned" {
		t.Fatalf("expected user_banned, got %v", resp)
	}
}

func TestVerifyAccessTokenInvalidSignature(t *testing.T) {
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	// Create a token with wrong secret
	invalidToken := createTokenWithSecret(1, "free", "wrong-secret")
	resp := as.VerifyAccessToken(ctx, invalidToken)
	if resp["error"] != "invalid_token" {
		t.Fatalf("expected invalid_token, got %v", resp)
	}
}

// Helper to create an expired token for testing
func createExpiredToken(userID int64, tier string) string {
	claims := jwt.MapClaims{
		"user_id": userID,
		"tier":    tier,
		"exp":     time.Now().Add(-time.Hour).Unix(),
		"iat":     time.Now().Add(-2*time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := token.SignedString([]byte(jwtSecret))
	return s
}

// Helper to create a token with a different secret for testing
func createTokenWithSecret(userID int64, tier, secret string) string {
	claims := jwt.MapClaims{
		"user_id": userID,
		"tier":    tier,
		"exp":     time.Now().Add(time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := token.SignedString([]byte(secret))
	return s
}

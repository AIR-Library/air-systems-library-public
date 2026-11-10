package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
)

// testSecretKey is the fixed 32+ byte HMAC key every test instance gets (spec d270fa3: tests pass a fixed
// test key). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
var testSecretKey = []byte("test-secret-key-0123456789abcdef-auth")

// sha256Hex is the value the module stores for a secret: lowercase hex HMAC-SHA256(testSecretKey, s).
// In: the secret. Out: 64 hex characters. Why: spec d270fa3: keyed HMAC for stored secrets; the tests used
// the module's plain SHA-256 helper of this name until 2026-11-10 (changed 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP). Touches nothing.
func sha256Hex(s string) string {
	m := hmac.New(sha256.New, testSecretKey)
	m.Write([]byte(s))
	return hex.EncodeToString(m.Sum(nil))
}

// plainSHA256Hex is the plain, unkeyed SHA-256 hex of s, which the module must no longer store. In: the
// secret. Out: 64 hex characters. Why: spec d270fa3: keyed HMAC for stored secrets (AUTH-16 asserts the
// stored value is not this). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func plainSHA256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// fakeMailer records verification emails instead of sending them (no network in tests).
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-01 "email sent").
type fakeMailer struct{ sent map[string]string } // email -> code

// SendVerificationEmail records the code for the address.
func (f *fakeMailer) SendVerificationEmail(_ context.Context, email, code string) error {
	f.sent[email] = code
	return nil
}

// fakeOAuth answers ExchangeCode from a fixed table of code -> identity (no network in tests).
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-10/11).
type fakeOAuth struct{ ids map[string]OAuthIdentity }

// ExchangeCode returns the identity for a known code, else an error.
func (f *fakeOAuth) ExchangeCode(_ context.Context, _ string, code string) (OAuthIdentity, error) {
	id, ok := f.ids[code]
	if !ok {
		return OAuthIdentity{}, errors.New("unknown code")
	}
	return id, nil
}

// getLatestVerificationCode returns the email verification code the fake mailer sent to the user (the
// database keeps only its SHA-256, so the code can no longer be read back from verification_codes). In: the
// user id and the code type (only "email" is sent by mail). Out: the code, or an error when none was sent.
// Moved here from the implementation 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, AUTH-16:
// verification codes are stored only as code_hash). Touches: in-memory SQLite (one read of users).
func (a *AuthSystem) getLatestVerificationCode(ctx context.Context, userID int64, codeType string) (string, error) {
	if codeType != "email" {
		return "", fmt.Errorf("only email codes are sent by mail, not %q", codeType)
	}
	var email string
	if err := a.db.QueryRowContext(ctx, `SELECT email FROM users WHERE id = ?`, userID).Scan(&email); err != nil {
		return "", err
	}
	code, ok := a.email.(*fakeMailer).sent[email]
	if !ok {
		return "", fmt.Errorf("no verification email was sent to %s", email)
	}
	return code, nil
}

// newTestAuth builds an AuthSystem with the fake mailer and OAuth provider.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: NewAuthSystem alone has no email sender, and
// signup refuses rather than pretend to send. Touches: in-memory SQLite.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec d270fa3: keyed HMAC for stored secrets):
// passes the fixed testSecretKey.
func newTestAuth(t *testing.T) (*AuthSystem, error) {
	t.Helper()
	return NewAuthSystemWithOptions(Options{
		SecretKey: testSecretKey,
		Email: &fakeMailer{sent: map[string]string{}},
		OAuth: &fakeOAuth{ids: map[string]OAuthIdentity{
			"code-new":      {ProviderUserID: "g-1", Email: "newuser@example.com", EmailVerified: true},
			"code-ivy":      {ProviderUserID: "gh-7", Email: "ivy@example.com", EmailVerified: true},
			"code-unverified": {ProviderUserID: "g-2", Email: "x@example.com", EmailVerified: false},
		}},
	})
}

// AUTH-01
func TestSignupHappyPath(t *testing.T) {
	as, err := newTestAuth(t)
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
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: AUTH-01 also says "user created, email sent".
	userID, err := as.getUserIDByEmail(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("user not created: %v", err)
	}
	// Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, AUTH-16): the code is stored only as
	// its SHA-256 (its keyed HMAC since spec d270fa3, 2026-11-10), so the test checks the stored code_hash is the hash of the code that was emailed (it read
	// a plain-text code column).
	var storedHash string
	if err := as.db.QueryRowContext(ctx, `SELECT code_hash FROM verification_codes WHERE user_id = ? AND type = 'email'`, userID).Scan(&storedHash); err != nil {
		t.Fatalf("no verification code: %v", err)
	}
	if sent := as.email.(*fakeMailer).sent["alice@example.com"]; sent == "" || storedHash != sha256Hex(sent) {
		t.Fatalf("verification email not sent with the stored code: sent %q, stored hash %q", sent, storedHash)
	}
}

// AUTH-02
func TestSignupDuplicateEmail(t *testing.T) {
	as, err := newTestAuth(t)
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

// AUTH-03
func TestSignupWeakPassword(t *testing.T) {
	as, err := newTestAuth(t)
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	ip := "192.0.2.3"
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the amended AUTH-03 answers
	// {error: "password_rejected", reason} (password_too_weak is gone); checks run too_short, too_long,
	// blocklisted and the first failure wins, so "password123" is too_short, not blocklisted.
	cases := []struct{ pw, name, reason string }{
		{"short", "Carol", "too_short"},
		{"password123", "Carol", "too_short"},
		{strings.Repeat("a", 65), "Carol", "too_long"},
		{"Carol Danvers Marvel", "Carol Danvers Marvel", "blocklisted"},
		{"carol@example.com", "Carol", "blocklisted"},
	}
	for _, c := range cases {
		resp := as.Signup(ctx, "carol@example.com", c.pw, c.name, ip)
		if resp["error"] != "password_rejected" || resp["reason"] != c.reason {
			t.Fatalf("%q: expected password_rejected/%s, got %v", c.pw, c.reason, resp)
		}
	}
	if _, err := as.getUserIDByEmail(ctx, "carol@example.com"); err == nil {
		t.Fatalf("a rejected password must not create the user")
	}
	// 15 characters with an empty name is accepted (an empty name used to blocklist everything).
	if resp := as.Signup(ctx, "carol@example.com", "correct horse b", "", "192.0.2.33"); resp["success"] != true {
		t.Fatalf("a 15-character password should be accepted: %v", resp)
	}
}

// AUTH-04
func TestSignupIPRateLimit(t *testing.T) {
	as, err := newTestAuth(t)
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

// AUTH-05
func TestVerifyEmailHappyPath(t *testing.T) {
	as, err := newTestAuth(t)
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

// AUTH-06
func TestVerifyEmailExpiredCode(t *testing.T) {
	as, err := newTestAuth(t)
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

// AUTH-07
func TestLoginHappyPathNoMFA(t *testing.T) {
	as, err := newTestAuth(t)
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

// AUTH-08
func TestLoginWithMFAEnabled(t *testing.T) {
	as, err := newTestAuth(t)
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

// AUTH-09
func TestLoginInvalidPassword(t *testing.T) {
	as, err := newTestAuth(t)
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

// AUTH-10
func TestOAuthCallbackNewUser(t *testing.T) {
	as, err := newTestAuth(t)
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the callback now needs a state from StartOAuth and
	// gets the email from the provider exchange, not from the code (which used to BE the email).
	state, err := as.StartOAuth(ctx, "google")
	if err != nil {
		t.Fatalf("StartOAuth: %v", err)
	}
	resp := as.OAuthCallback(ctx, "google", "code-new", state)
	if resp["status"] != "authenticated" {
		t.Fatalf("expected authenticated, got %v", resp)
	}
	userID, err := as.getUserIDByEmail(ctx, "newuser@example.com")
	if err != nil {
		t.Fatalf("user not created: %v", err)
	}
	var linked int64
	if err := as.db.QueryRow(`SELECT user_id FROM oauth_accounts WHERE provider='google' AND provider_user_id='g-1'`).Scan(&linked); err != nil || linked != userID {
		t.Fatalf("oauth not linked to the new user: %d (%v)", linked, err)
	}
	// The state is single use, a made-up state fails, and an unverified provider email is refused.
	if r := as.OAuthCallback(ctx, "google", "code-new", state); r["error"] != "invalid_state" {
		t.Fatalf("reused state: expected invalid_state, got %v", r)
	}
	if r := as.OAuthCallback(ctx, "google", "code-new", "validstate"); r["error"] != "invalid_state" {
		t.Fatalf("unknown state: expected invalid_state, got %v", r)
	}
	state2, _ := as.StartOAuth(ctx, "google")
	if r := as.OAuthCallback(ctx, "google", "code-unverified", state2); r["error"] != "email_not_verified" {
		t.Fatalf("unverified email: expected email_not_verified, got %v", r)
	}
	// A code that names an email directly is not an identity.
	state3, _ := as.StartOAuth(ctx, "google")
	if r := as.OAuthCallback(ctx, "google", "victim@example.com", state3); r["error"] != "oauth_exchange_failed" {
		t.Fatalf("raw email as code: expected oauth_exchange_failed, got %v", r)
	}
}

// AUTH-11
func TestOAuthCallbackExistingUser(t *testing.T) {
	as, err := newTestAuth(t)
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

	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: state from StartOAuth, identity from the provider.
	state, err := as.StartOAuth(ctx, "github")
	if err != nil {
		t.Fatalf("StartOAuth: %v", err)
	}
	resp = as.OAuthCallback(ctx, "github", "code-ivy", state)
	if resp["status"] != "authenticated" {
		t.Fatalf("expected authenticated, got %v", resp)
	}
	if got := resp["user"].(map[string]interface{})["id"]; got != userID {
		t.Fatalf("expected the existing user %d, got %v", userID, got)
	}
	var linked int64
	if err := as.db.QueryRow(`SELECT user_id FROM oauth_accounts WHERE provider='github' AND provider_user_id='gh-7'`).Scan(&linked); err != nil || linked != userID {
		t.Fatalf("oauth not linked to the existing account: %d (%v)", linked, err)
	}
	var users int
	_ = as.db.QueryRow(`SELECT COUNT(*) FROM users WHERE email='ivy@example.com'`).Scan(&users)
	if users != 1 {
		t.Fatalf("expected one account for ivy, got %d", users)
	}
}

// AUTH-12
func TestMFAChallengeHappyPath(t *testing.T) {
	as, err := newTestAuth(t)
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

	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the code is the user's current TOTP (as from an
	// authenticator app); the challenge no longer stores a code for the test to read back.
	mfaCode, err := totp.GenerateCode("BASE32SECRET", time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	resp = as.MFAChallenge(ctx, challengeID, mfaCode)
	if resp["status"] != "authenticated" {
		t.Fatalf("expected authenticated, got %v", resp)
	}
}

// AUTH-13
func TestMFAChallengeWrongCode(t *testing.T) {
	as, err := newTestAuth(t)
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

// AUTH-14
func TestTokenRefreshHappyPath(t *testing.T) {
	as, err := newTestAuth(t)
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

	// Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, AUTH-16): the refresh token comes from
	// the login answer; the sessions table no longer holds it (the test read it from there).
	rt, _ := loginResp["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("login returned no refresh_token: %v", loginResp)
	}

	resp = as.TokenRefresh(ctx, rt)
	if resp["status"] != "ok" {
		t.Fatalf("expected ok, got %v", resp)
	}
}

// AUTH-15
func TestTokenRefreshBannedUser(t *testing.T) {
	as, err := newTestAuth(t)
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
	// Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, AUTH-16): the column is now
	// refresh_token_hash and holds the token's SHA-256. Since spec d270fa3 (2026-11-10,
	// session_012zDydZCZ4AChqhEZ4oVtaP) that is the keyed HMAC-SHA256 under testSecretKey (sha256Hex below).
	_, err = as.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, refresh_token_hash, created_at, expires_at, ip, device_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sessionID, userID, sha256Hex(rt),
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
	as, err := newTestAuth(t)
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
	as, err := newTestAuth(t)
	if err != nil {
		t.Fatalf("NewAuthSystem failed: %v", err)
	}
	ctx := context.Background()
	// Create an expired token manually
	expiredToken := createExpiredToken(as, 1, "free")
	resp := as.VerifyAccessToken(ctx, expiredToken)
	if resp["error"] != "token_expired" {
		t.Fatalf("expected token_expired, got %v", resp)
	}
}

func TestVerifyAccessTokenBannedUser(t *testing.T) {
	as, err := newTestAuth(t)
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
	as, err := newTestAuth(t)
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

// createExpiredToken signs an expired token with the system's own secret.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the secret is per instance now, not a constant.
func createExpiredToken(as *AuthSystem, userID int64, tier string) string {
	claims := jwt.MapClaims{
		"user_id": userID,
		"tier":    tier,
		"exp":     time.Now().Add(-time.Hour).Unix(),
		"iat":     time.Now().Add(-2*time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := token.SignedString(as.jwtSecret)
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

// TestMFAChallengeBoundToItsUser proves a challenge only accepts its own user's TOTP: user B's valid
// code against user A's challenge is invalid_code, and A's challenge then still works once.
// Why: MFAChallenge ignored challenge_id and took the newest MFA row of any user (found 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP). Touches: in-memory SQLite.
func TestMFAChallengeBoundToItsUser(t *testing.T) {
	fixed := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC) // a fixed clock: the two codes below differ at it
	// spec d270fa3 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): the fixed test HMAC key.
	as, err := NewAuthSystemWithOptions(Options{SecretKey: testSecretKey, Email: &fakeMailer{sent: map[string]string{}}, Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	login := func(email, secret, ip string) string {
		if r := as.Signup(ctx, email, "StrongPassword!12345", "", ip); r["success"] != true {
			t.Fatalf("signup %s: %v", email, r)
		}
		_ = as.VerifyEmail(ctx, email, as.email.(*fakeMailer).sent[email])
		if _, err := as.db.ExecContext(ctx, `UPDATE users SET mfa_enabled = 1, mfa_secret = ? WHERE email = ?`, secret, email); err != nil {
			t.Fatal(err)
		}
		r := as.Login(ctx, email, "StrongPassword!12345", "d", ip)
		id, ok := r["challenge_id"].(string)
		if !ok {
			t.Fatalf("no challenge for %s: %v", email, r)
		}
		return id
	}
	challengeA := login("a@example.com", "JBSWY3DPEHPK3PXP", "198.51.100.1")
	_ = login("b@example.com", "KRSXG5CTMVRXEZLU", "198.51.100.2")
	codeB, _ := totp.GenerateCode("KRSXG5CTMVRXEZLU", fixed)
	codeA, _ := totp.GenerateCode("JBSWY3DPEHPK3PXP", fixed)
	if codeA == codeB {
		t.Fatalf("pick secrets whose codes differ at the fixed time")
	}
	if r := as.MFAChallenge(ctx, challengeA, codeB); r["error"] != "invalid_code" {
		t.Fatalf("B's code on A's challenge: expected invalid_code, got %v", r)
	}
	if r := as.MFAChallenge(ctx, challengeA, codeA); r["status"] != "authenticated" {
		t.Fatalf("A's code on A's challenge: expected authenticated, got %v", r)
	}
	if r := as.MFAChallenge(ctx, challengeA, codeA); r["error"] != "invalid_code" {
		t.Fatalf("a used challenge: expected invalid_code, got %v", r)
	}
}

// TestLoginFailureLimitEnforced proves the 5-failures-per-15-minutes limit per ip+email: the sixth
// attempt is refused even with the right password. Why: failures were counted but never checked
// (found 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: in-memory SQLite.
func TestLoginFailureLimitEnforced(t *testing.T) {
	as, err := newTestAuth(t)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ip := "198.51.100.9"
	_ = as.Signup(ctx, "p@example.com", "StrongPassword!12345", "P", ip)
	_ = as.VerifyEmail(ctx, "p@example.com", as.email.(*fakeMailer).sent["p@example.com"])
	for i := 0; i < 5; i++ {
		if r := as.Login(ctx, "p@example.com", "wrong password here", "d", ip); r["error"] != "invalid_credentials" {
			t.Fatalf("attempt %d: %v", i, r)
		}
	}
	if r := as.Login(ctx, "p@example.com", "StrongPassword!12345", "d", ip); r["error"] != "too_many_login_attempts" {
		t.Fatalf("expected too_many_login_attempts, got %v", r)
	}
}

// TestRefreshTokenAndSecretsAtRest proves AUTH-16: login returns a refresh_token that TokenRefresh accepts;
// the sessions table holds only its SHA-256 (no column holds the token, so a database read hands out nothing
// usable: the stored hash itself is refused by TokenRefresh); a verification code and an MFA challenge id
// are stored only as their hashes; the MFA and OAuth flows return a refresh_token TokenRefresh accepts too.
// Input: none; output: test failures. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2).
// Touches: in-memory SQLite, the fake mailer and OAuth provider.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec d270fa3: keyed HMAC for stored secrets): each
// stored value must equal HMAC-SHA256(testSecretKey, value) and must not equal its plain SHA-256.
// AUTH-16
func TestRefreshTokenAndSecretsAtRest(t *testing.T) {
	fixed := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	mailer := &fakeMailer{sent: map[string]string{}}
	as, err := NewAuthSystemWithOptions(Options{SecretKey: testSecretKey, Email: mailer, Now: func() time.Time { return fixed },
		OAuth: &fakeOAuth{ids: map[string]OAuthIdentity{"code-rt": {ProviderUserID: "g-rt", Email: "rt@example.com", EmailVerified: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if r := as.Signup(ctx, "quinn@example.com", "StrongPassword!12345", "Quinn", "203.0.113.16"); r["success"] != true {
		t.Fatalf("signup: %v", r)
	}
	sent := mailer.sent["quinn@example.com"]
	var codeHash string
	if err := as.db.QueryRowContext(ctx, `SELECT code_hash FROM verification_codes WHERE type = 'email'`).Scan(&codeHash); err != nil {
		t.Fatal(err)
	}
	if codeHash != sha256Hex(sent) || strings.Contains(dumpTable(t, as, "verification_codes"), sent) {
		t.Fatalf("the email code must be stored only as its HMAC-SHA256 under the test key")
	}
	// spec d270fa3 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): keyed, so not the plain SHA-256.
	if codeHash == plainSHA256Hex(sent) {
		t.Fatalf("the email code must not be stored as its plain SHA-256")
	}
	if r := as.VerifyEmail(ctx, "quinn@example.com", codeHash); r["error"] != "code_invalid" {
		t.Fatalf("the stored hash must not verify the email: %v", r)
	}
	if r := as.VerifyEmail(ctx, "quinn@example.com", sent); r["status"] != "verified" {
		t.Fatalf("verify: %v", r)
	}

	login := as.Login(ctx, "quinn@example.com", "StrongPassword!12345", "dev", "203.0.113.16")
	rt, _ := login["refresh_token"].(string)
	if login["status"] != "authenticated" || len(rt) < 32 {
		t.Fatalf("login must return a refresh_token: %v", login)
	}
	var stored string
	if err := as.db.QueryRowContext(ctx, `SELECT refresh_token_hash FROM sessions WHERE id = ?`, login["session_id"]).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dumpTable(t, as, "sessions"), stored) {
		t.Fatalf("dumpTable must show the stored values as text, or the checks below prove nothing")
	}
	if stored != sha256Hex(rt) || strings.Contains(dumpTable(t, as, "sessions"), rt) {
		t.Fatalf("sessions must hold only the refresh token's HMAC-SHA256 under the test key")
	}
	if stored == plainSHA256Hex(rt) { // spec d270fa3, 2026-11-10
		t.Fatalf("sessions must not hold the refresh token's plain SHA-256")
	}
	if r := as.TokenRefresh(ctx, rt); r["status"] != "ok" || r["token"] == "" {
		t.Fatalf("TokenRefresh must accept login's refresh_token: %v", r)
	}
	if r := as.TokenRefresh(ctx, stored); r["error"] != "invalid_token" {
		t.Fatalf("the stored hash must not work as a refresh token: %v", r)
	}

	// MFA: the challenge id is stored only as its hash, and the session it opens has a working refresh token.
	if _, err := as.db.ExecContext(ctx, `UPDATE users SET mfa_enabled = 1, mfa_secret = 'JBSWY3DPEHPK3PXP' WHERE email = 'quinn@example.com'`); err != nil {
		t.Fatal(err)
	}
	ch := as.Login(ctx, "quinn@example.com", "StrongPassword!12345", "dev", "203.0.113.16")
	challengeID, _ := ch["challenge_id"].(string)
	if challengeID == "" || strings.Contains(dumpTable(t, as, "verification_codes"), challengeID) {
		t.Fatalf("the MFA challenge id must be stored only as its hash: %v", ch)
	}
	code, _ := totp.GenerateCode("JBSWY3DPEHPK3PXP", fixed)
	mfa := as.MFAChallenge(ctx, challengeID, code)
	if mrt, _ := mfa["refresh_token"].(string); mfa["status"] != "authenticated" || as.TokenRefresh(ctx, mrt)["status"] != "ok" {
		t.Fatalf("MFA must return a refresh_token TokenRefresh accepts: %v", mfa)
	}

	// OAuth: the state is single use and lives 10 minutes; the callback's session has a working refresh token.
	state, err := as.StartOAuth(ctx, "google")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(dumpTable(t, as, "oauth_states"), state) {
		t.Fatalf("the OAuth state must be stored only as its hash")
	}
	// spec d270fa3 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): the state's keyed HMAC is stored, not its plain SHA-256.
	if states := dumpTable(t, as, "oauth_states"); !strings.Contains(states, sha256Hex(state)) || strings.Contains(states, plainSHA256Hex(state)) {
		t.Fatalf("the OAuth state must be stored as its HMAC-SHA256 under the test key")
	}
	oa := as.OAuthCallback(ctx, "google", "code-rt", state)
	if ort, _ := oa["refresh_token"].(string); oa["status"] != "authenticated" || as.TokenRefresh(ctx, ort)["status"] != "ok" {
		t.Fatalf("OAuth must return a refresh_token TokenRefresh accepts: %v", oa)
	}
	if r := as.OAuthCallback(ctx, "google", "code-rt", state); r["error"] != "invalid_state" {
		t.Fatalf("a used state: expected invalid_state, got %v", r)
	}
	late, _ := as.StartOAuth(ctx, "google")
	as.now = func() time.Time { return fixed.Add(10 * time.Minute) }
	if r := as.OAuthCallback(ctx, "google", "code-rt", late); r["error"] != "invalid_state" {
		t.Fatalf("a state 10 minutes old: expected invalid_state, got %v", r)
	}
	as.now = func() time.Time { return fixed }
	inTime, _ := as.StartOAuth(ctx, "google")
	as.now = func() time.Time { return fixed.Add(10*time.Minute - time.Second) }
	if r := as.OAuthCallback(ctx, "google", "code-rt", inTime); r["status"] != "authenticated" {
		t.Fatalf("a state just under 10 minutes old must work: %v", r)
	}
}

// dumpTable returns every value of every row of table as one string, so a test can prove a secret appears
// nowhere in it. In: the test, the system and a table name from this file. Out: the text.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, AUTH-16). Touches: in-memory SQLite (read).
func dumpTable(t *testing.T, as *AuthSystem, table string) string {
	t.Helper()
	rows, err := as.db.Query("SELECT * FROM " + table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var b strings.Builder
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for _, v := range vals {
			fmt.Fprintf(&b, "%v|", v)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// TestServiceRefusesToStartWithoutSecretKey proves the service refuses to start without a 32-byte HMAC
// key: NewAuthSystemWithOptions and NewAuthSystem return an error when neither Options.SecretKey nor
// AUTH_SECRET_KEY is set, or the key is 31 bytes; a 32-byte AUTH_SECRET_KEY starts it, and secrets are
// stored as HMAC-SHA256 under that key, not as a plain SHA-256. Input: none; output: test failures.
// Why: spec d270fa3: keyed HMAC for stored secrets ("the service refuses to start without it").
// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the AUTH_SECRET_KEY environment variable (t.Setenv
// restores it), in-memory SQLite.
// AUTH-16
func TestServiceRefusesToStartWithoutSecretKey(t *testing.T) {
	t.Setenv("AUTH_SECRET_KEY", "")
	if as, err := NewAuthSystem(); err == nil || as != nil || !strings.Contains(err.Error(), "AUTH_SECRET_KEY") {
		t.Fatalf("NewAuthSystem without a key must refuse to start: %v", err)
	}
	if _, err := NewAuthSystemWithOptions(Options{SecretKey: []byte(strings.Repeat("k", 31))}); err == nil {
		t.Fatalf("a 31-byte Options.SecretKey must refuse to start")
	}
	t.Setenv("AUTH_SECRET_KEY", strings.Repeat("k", 31))
	if _, err := NewAuthSystem(); err == nil {
		t.Fatalf("a 31-byte AUTH_SECRET_KEY must refuse to start")
	}
	t.Setenv("AUTH_SECRET_KEY", string(testSecretKey))
	as, err := NewAuthSystem()
	if err != nil {
		t.Fatalf("a 32-byte AUTH_SECRET_KEY must start the service: %v", err)
	}
	if got := as.hashSecret("123456"); got != sha256Hex("123456") || got == plainSHA256Hex("123456") {
		t.Fatalf("stored hash must be HMAC-SHA256(AUTH_SECRET_KEY, value), got %s", got)
	}
}

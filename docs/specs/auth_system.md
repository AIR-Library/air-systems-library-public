# Auth System

Reference contract for `saas_templates/<lang>/auth_system_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# AUTH-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `AUTH-01` | signup happy path (valid email, strong password) → user created, email sent |
| `AUTH-02` | signup duplicate email → 409 {error: "email_already_exists"} |
| `AUTH-03` | signup weak password → 400 {error: "password_rejected", reason: "too_short"} |
| `AUTH-04` | signup IP rate limit → 429 {error: "too_many_signups_from_ip"} |
| `AUTH-05` | verify_email happy path → user status changed to verified |
| `AUTH-06` | verify_email expired code → 400 {error: "code_expired"} |
| `AUTH-07` | login happy path (no MFA) → token returned |
| `AUTH-08` | login with MFA enabled → 202 {status: "mfa_required", challenge_id} |
| `AUTH-09` | login invalid password → 401 {error: "invalid_credentials"} |
| `AUTH-10` | oauth_callback happy path (new user) → user created + oauth linked |
| `AUTH-11` | oauth_callback existing user → oauth linked to existing account |
| `AUTH-12` | mfa_challenge happy path → token returned |
| `AUTH-13` | mfa_challenge wrong code → 401 {error: "invalid_code"} |
| `AUTH-14` | token_refresh happy path → new token issued |
| `AUTH-15` | token_refresh banned user → 403 {error: "user_banned"} |
| `AUTH-16` | login returns a refresh_token that token_refresh accepts; the sessions table holds only its HMAC-SHA256 under AUTH_SECRET_KEY, a verification code is stored only as its HMAC, and the service refuses to start without a 32-byte key |
| `AUTH-17` | verify_email: a wrong code is 400 code_invalid; after 5 wrong codes the right code is also 400 code_invalid; after 4 wrong codes the right one verifies; a newly sent code works again |
| `AUTH-18` | resend_verification: a code spent by 5 wrong tries is replaced, and the new code verifies; a 4th resend within the hour is 429 too_many_requests; an unknown and a verified email get the same 202 sent and no email |

## Contract

```text
FLOWS TO BUILD (exact sequence — no deviations):

  1. signup(email, password, name)
     Gates: email_unique, password_strength (see PASSWORD RULES below), rate_limit_ip_24h (5 max)

     PASSWORD RULES -- NIST SP 800-63B-4. These apply everywhere password_strength is checked
     (signup, password change, password reset). MFA is optional in this system, so a password is
     often the ONLY factor:
       - minimum length 15 characters ("SHALL require passwords that are used as a single-factor
         authentication mechanism to be a minimum of 15 characters")
       - allow a maximum of at least 64 characters; accept all printable ASCII, spaces and Unicode
       - DO NOT require character types -- no "must contain upper/digit/special" rule of any kind
         ("SHALL NOT impose other composition rules")
       - REJECT any password on a blocklist of commonly used, expected or compromised values
         ("SHALL be required to choose a different password"): ship a bundled common-passwords
         list, and also reject the user's own email / name / the service name as the password
       - never store a password hint; never force periodic password changes
     On rejection return {error: "password_rejected", reason: "too_short" | "too_long" | "blocklisted"}
     Checks run in that order and the first failure wins ("password123" is too_short, not blocklisted).
     -- never a message asking for upper-case, digits or symbols.
     Action: create user with status='unverified', hash password, send verification email
     Log: why_chain(flow="signup", decision_points=["email_unique", "password_strength", "rate_limit_ip_24h"])
     Log: audit_log(action="user_created", user_id, email)
     Return: {status: "pending_verification", email, message: "check email"}

  2. verify_email(email, code_or_token)
     Gates: code_valid (not expired, matches), user_unverified (email_verified_at is null)
     Answers: a wrong code is 400 {error: "code_invalid"}; an expired code is 400 {error: "code_expired"}.
     Amended 2026-11-10 (Phase B.4: one answer in every language).
     Attempts: 5 wrong codes for one user invalidate that user's current code: further tries, even with the
     right code, get 400 {error: "code_invalid"} until a new code is sent (a 6-digit code must not be guessable
     by retrying). Amended 2026-11-10 (Phase B.3).
     Action: mark user.email_verified_at = NOW(), delete verification code
     Log: why_chain(flow="verify_email", decision_points=["code_valid", "user_unverified"])
     Log: audit_log(action="email_verified", user_id)
     Return: {status: "verified", user_id, message: "ready to login"}

  2b. resend_verification(email)
     For an unverified user: deletes the user's email codes, issues a new 6-digit code (attempts 0, stored as its
     keyed hash, 10-minute expiry) and emails it. At most 3 resends per email per hour: a 4th within the hour is
     429 {error: "too_many_requests"} and sends nothing. An unknown or already verified email gets the same
     202 {status: "sent"} as a real resend and sends nothing, so the answer never says whether an account
     exists. Why: without it, 5 wrong codes (AUTH-17) would lock a user out of verifying for good. Amended
     2026-11-10 after review on PR 22.
  3. login(email, password, device_id, ip)
     Gates: user_exists_and_verified, password_correct, mfa_enabled_check, rate_limit (5 failed per 15min per ip/user)
     Sub-flow if MFA enabled: return {status: "mfa_required", challenge_id}
     Sub-flow if MFA disabled: create session + token
     Log: why_chain(flow="login", decision_points=["user_exists", "password_correct", "mfa_gate", "rate_limit"])
     Log: audit_log(action="session_created", user_id, session_id, ip, device_id)
     Return: {status: "authenticated", session_id, token, refresh_token, expires_in, user: {id, email, tier}}
     Every flow that creates a session (login, MFA verify, OAuth) returns its refresh_token, the value
     token_refresh() takes. Amended 2026-11-10 (Phase B.2).

  4. oauth_callback(provider, code, state)
     Gates: state_valid (matches session, not expired), email_verified_by_provider
     Case A: new user (email not in DB) → create user with status='verified', link oauth
     Case B: existing user (email exists) → link oauth provider to account
     Log: why_chain(flow="oauth_callback", decision_points=["state_valid", "email_verified"])
     Log: audit_log(action="oauth_login", provider, user_id, session_id)
     Return: {status: "authenticated", session_id, token, user: {id, email, tier}}

  5. mfa_challenge(challenge_id, code)
     Gates: challenge_exists_and_valid (not expired), code_correct (totp_verify or sms_match)
     Action: mark challenge verified, create session + token
     Log: why_chain(flow="mfa_challenge", decision_points=["challenge_valid", "code_correct"])
     Log: audit_log(action="mfa_verified", user_id)
     Return: {status: "authenticated", session_id, token, user}

  6. token_refresh(refresh_token)
     Gates: token_valid (decode succeeds, not expired), user_not_banned (status != 'suspended'|'banned')

     TOKEN VERIFICATION RULE -- RFC 8725 section 3.1 ("MUST NOT use any other algorithms"). Everywhere a
     token is verified (refresh, authenticated requests, anything that decodes a JWT):
       - pass the allowed algorithm(s) EXPLICITLY to the verify call -- e.g. jsonwebtoken
         verify(token, key, {algorithms: ['HS256']}), PyJWT decode(..., algorithms=['HS256']),
         Go jwt.WithValidMethods([]string{"HS256"}), .NET ValidAlgorithms = {"HS256"}
       - never read the algorithm from the token's own header to decide how to verify it
       - never accept alg "none"
     Hand-rolled verification must recompute the signature with a FIXED algorithm and compare it in
     constant time.
     Action: issue new access token
     Log: why_chain(flow="token_refresh", decision_points=["token_valid", "user_active"])
     Log: audit_log(action="token_refreshed", user_id)
     Return: {status: "ok", token, expires_in}

  7. verify_access_token(token)
     This is the step that connects AUTH to PERMISSIONS & RBAC. That system's
     require_authenticated(current_user) assumes a verified user already exists -- this flow produces
     it, and every authenticated request calls it. Without it the library issues tokens nobody checks.
     Gates: signature_valid (HS256 ONLY -- follow the TOKEN VERIFICATION RULE above: algorithm passed
            explicitly, header alg never trusted, "none" rejected), not_expired,
            user_exists_and_active (status not 'suspended' | 'banned')
     Action: none -- read-only
     Log: why_chain(flow="verify_access_token", decision_points=["signature_valid", "not_expired", "user_active"])
     Return: {status: "ok", user: {id, email, tier}}
             or {error: "invalid_token" | "token_expired" | "user_banned"}

IMPLEMENTATION REQUIREMENTS:
  - Hash passwords with bcrypt (never log plaintext)
  - TOTP: use standard library (Python: pyotp, JS: speakeasy, Java: com.google.authenticator, etc.)
    Where totp_two_factor is installed, its verify() is the gate; a package is used only to compute codes.
  - JWT: sign with HS256, include user_id and tier
  - Timestamps: UTC, ISO 8601 format
  - Response: always JSON {success: true, ...} or {error: "code", message: "..."}
  - Database: users table (id, email, password_hash, tier, status, email_verified_at, mfa_secret, mfa_enabled)
  - Database: sessions table (id, user_id, refresh_token_hash, created_at, expires_at, ip, device_id)
  - Secrets at rest: refresh tokens, email/MFA verification codes and OAuth state values are stored only as
    a keyed hash, lowercase hex HMAC-SHA256(secret_key, value), and compared in constant time; a database
    read must not hand out a usable credential. secret_key comes from configuration (AUTH_SECRET_KEY, at
    least 32 bytes; the service refuses to start without it; tests pass a fixed test key). A plain SHA-256
    is not enough: a 6-digit code has a million values, so a leaked table could be reversed by brute force.
    Amended again 2026-11-10 after a code-scanning finding on PR 21.
    OAuth state is single-use and expires in 10 minutes; the callback exchanges the provider's code through
    an injected provider client (never uses the code itself as an identity). Amended 2026-11-10 (Phase B.2).
  - Database: audit_log table (timestamp, actor_id, action, resource_type, resource_id, old_value, new_value)
  - Database: verification_codes table (id, user_id, code_hash, created_at, expires_at, type='email'|'mfa')

TESTS REQUIRED:
  - **AUTH-01** signup happy path (valid email, strong password) → user created, email sent
  - **AUTH-02** signup duplicate email → 409 {error: "email_already_exists"}
  - **AUTH-03** signup weak password → 400 {error: "password_rejected", reason: "too_short"}
  - **AUTH-04** signup IP rate limit → 429 {error: "too_many_signups_from_ip"}
  - **AUTH-05** verify_email happy path → user status changed to verified
  - **AUTH-06** verify_email expired code → 400 {error: "code_expired"}
  - **AUTH-07** login happy path (no MFA) → token returned
  - **AUTH-08** login with MFA enabled → 202 {status: "mfa_required", challenge_id}
  - **AUTH-09** login invalid password → 401 {error: "invalid_credentials"}
  - **AUTH-10** oauth_callback happy path (new user) → user created + oauth linked
  - **AUTH-11** oauth_callback existing user → oauth linked to existing account
  - **AUTH-12** mfa_challenge happy path → token returned
  - **AUTH-13** mfa_challenge wrong code → 401 {error: "invalid_code"}
  - **AUTH-14** token_refresh happy path → new token issued
  - **AUTH-15** token_refresh banned user → 403 {error: "user_banned"}
  - **AUTH-16** login returns a refresh_token that token_refresh accepts; the sessions table holds only its HMAC-SHA256 under AUTH_SECRET_KEY, a verification code is stored only as its HMAC, and the service refuses to start without a 32-byte key
  - **AUTH-17** verify_email: a wrong code is 400 code_invalid; after 5 wrong codes the right code is also 400 code_invalid; after 4 wrong codes the right one verifies; a newly sent code works again
  - **AUTH-18** resend_verification: a code spent by 5 wrong tries is replaced, and the new code verifies; a 4th resend within the hour is 429 too_many_requests; an unknown and a verified email get the same 202 sent and no email
```

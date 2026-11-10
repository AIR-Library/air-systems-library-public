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
| `AUTH-03` | signup weak password → 400 {error: "password_too_weak"} |
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
     -- never a message asking for upper-case, digits or symbols.
     Action: create user with status='unverified', hash password, send verification email
     Log: why_chain(flow="signup", decision_points=["email_unique", "password_strength", "rate_limit_ip_24h"])
     Log: audit_log(action="user_created", user_id, email)
     Return: {status: "pending_verification", email, message: "check email"}

  2. verify_email(email, code_or_token)
     Gates: code_valid (not expired, matches), user_unverified (email_verified_at is null)
     Action: mark user.email_verified_at = NOW(), delete verification code
     Log: why_chain(flow="verify_email", decision_points=["code_valid", "user_unverified"])
     Log: audit_log(action="email_verified", user_id)
     Return: {status: "verified", user_id, message: "ready to login"}

  3. login(email, password, device_id, ip)
     Gates: user_exists_and_verified, password_correct, mfa_enabled_check, rate_limit (5 failed per 15min per ip/user)
     Sub-flow if MFA enabled: return {status: "mfa_required", challenge_id}
     Sub-flow if MFA disabled: create session + token
     Log: why_chain(flow="login", decision_points=["user_exists", "password_correct", "mfa_gate", "rate_limit"])
     Log: audit_log(action="session_created", user_id, session_id, ip, device_id)
     Return: {status: "authenticated", session_id, token, expires_in, user: {id, email, tier}}

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
  - JWT: sign with HS256, include user_id and tier
  - Timestamps: UTC, ISO 8601 format
  - Response: always JSON {success: true, ...} or {error: "code", message: "..."}
  - Database: users table (id, email, password_hash, tier, status, email_verified_at, mfa_secret, mfa_enabled)
  - Database: sessions table (id, user_id, refresh_token, created_at, expires_at, ip, device_id)
  - Database: audit_log table (timestamp, actor_id, action, resource_type, resource_id, old_value, new_value)
  - Database: verification_codes table (id, user_id, code, created_at, expires_at, type='email'|'mfa')

TESTS REQUIRED:
  - **AUTH-01** signup happy path (valid email, strong password) → user created, email sent
  - **AUTH-02** signup duplicate email → 409 {error: "email_already_exists"}
  - **AUTH-03** signup weak password → 400 {error: "password_too_weak"}
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
```

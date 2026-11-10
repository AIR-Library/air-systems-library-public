//! Auth system tests (GEMINI spec, template #1).
//!
//! Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the old tests could not compile (ORM and
//! mocking imports, a `MockDbPool` that implemented nothing) and could not pass against any
//! implementation: with no setup, the same login gave "authenticated" in one test and "mfa_required" in
//! another, the same refresh token was "ok" in one and "banned" in another, a duplicate email was
//! expected without a first signup, and fixed codes ("123456") were expected to match random ones.
//! Each test keeps its name and its final assertions and now creates the state it assumes through the
//! public API (signup, verify with the emailed code, enable MFA, ban). Passwords are 15+ characters as
//! NIST SP 800-63B-4 requires ("password123456" is 14 and would be rightly refused), and the HS256
//! secret is 32+ bytes as RFC 7518 requires. Touches: in-memory SQLite only.

use super::*;
use std::sync::atomic::{AtomicI64, Ordering};

const PASSWORD: &str = "correct horse battery staple";
const JWT_SECRET: &str = "test-only-hs256-secret-0123456789abcdef";
/// What: the fixed 32+ byte HMAC key for stored secrets (spec d270fa3: tests pass a fixed test key).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
const TEST_SECRET_KEY: &str = "test-secret-key-0123456789abcdef-auth";

/// What: the value the module stores for a secret, lowercase hex HMAC-SHA256(TEST_SECRET_KEY, s). In: the
/// secret. Out: 64 hex characters. Why: spec d270fa3: keyed HMAC for stored secrets; the tests used the
/// module's plain SHA-256 helper of this name until 2026-11-10 (changed 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
fn sha256_hex(s: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(TEST_SECRET_KEY.as_bytes()).unwrap();
    mac.update(s.as_bytes());
    hex(&mac.finalize().into_bytes())
}

/// What: the plain, unkeyed SHA-256 hex of s, which the module must no longer store. In: the secret.
/// Out: 64 hex characters. Why: spec d270fa3: keyed HMAC for stored secrets (AUTH-16 asserts the stored
/// value is not this). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn plain_sha256_hex(s: &str) -> String {
    use sha2::Digest;
    hex(&Sha256::digest(s.as_bytes()))
}

/// What: an auth system on in-memory SQLite with a fixed clock, bcrypt cost 4, an in-memory mailer and
/// a fake OAuth provider; returns handles to all of them. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec d270fa3): passes the fixed TEST_SECRET_KEY.
fn setup() -> (AuthSystem, InMemoryMailer, FakeOAuthProvider, Arc<AtomicI64>) {
    let mailer = InMemoryMailer::default();
    let oauth = FakeOAuthProvider::default();
    let now = Arc::new(AtomicI64::new(1_767_225_600));
    let clock = now.clone();
    let sys = AuthSystem::new(Connection::open_in_memory().unwrap(), JWT_SECRET.to_string(), TEST_SECRET_KEY.to_string())
        .unwrap()
        .with_bcrypt_cost(4)
        .with_mailer(Box::new(mailer.clone()))
        .with_oauth(Box::new(oauth.clone()))
        .with_clock(Box::new(move || clock.load(Ordering::SeqCst)));
    (sys, mailer, oauth, now)
}

/// What: the code in the last email sent to an address. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn last_code(mailer: &InMemoryMailer, to: &str) -> String {
    let sent = mailer.sent.lock().unwrap();
    let body = &sent.iter().rev().find(|m| m.to == to).unwrap().body;
    body.rsplit(' ').next().unwrap().to_string()
}

/// What: sign up and verify a user; returns the user id. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn verified_user(sys: &mut AuthSystem, mailer: &InMemoryMailer, email: &str) -> i64 {
    sys.signup(SignupRequest { email: email.into(), password: PASSWORD.into(), name: "Test User".into() }).unwrap();
    let code = last_code(mailer, email);
    match sys.verify_email(VerifyEmailRequest { email: email.into(), code_or_token: code }).unwrap().data {
        AuthData::Verified { user_id, .. } => user_id,
        other => panic!("unexpected {:?}", other),
    }
}

/// What: a login request for the test password. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn login_req(email: &str, password: &str) -> LoginRequest {
    LoginRequest { email: email.into(), password: password.into(), device_id: "device123".into(), ip: "127.0.0.1".into() }
}

// AUTH-01
#[test]
fn test_signup_happy_path() {
    let (mut auth_system, mailer, _, _) = setup();
    let signup_req = SignupRequest { email: "test@example.com".to_string(), password: PASSWORD.to_string(), name: "Test User".to_string() };

    let result = auth_system.signup(signup_req);
    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.success);
    assert_eq!(response.data.status(), "pending_verification");
    // verification email sent
    assert_eq!(mailer.sent.lock().unwrap().len(), 1);
}

// AUTH-02
#[test]
fn test_signup_duplicate_email() {
    let (mut auth_system, _, _, _) = setup();
    let first = SignupRequest { email: "existing@example.com".to_string(), password: PASSWORD.to_string(), name: "Test User".to_string() };
    auth_system.signup(first).unwrap();

    let signup_req = SignupRequest { email: "existing@example.com".to_string(), password: PASSWORD.to_string(), name: "Test User".to_string() };
    let result = auth_system.signup(signup_req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), AuthError::EmailAlreadyExists);
}

/// What: AUTH-03: a 5-character password is refused as 400 password_rejected / too_short. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP:
/// the wire answer (status, error, reason) is now asserted. Touches: in-memory SQLite.
// AUTH-03
#[test]
fn test_signup_weak_password() {
    let (mut auth_system, _, _, _) = setup();
    let signup_req = SignupRequest { email: "test@example.com".to_string(), password: "short".to_string(), name: "Test User".to_string() };

    let result = auth_system.signup(signup_req);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err, AuthError::PasswordTooShort);
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: AUTH-03 now names the wire answer, 400 password_rejected/too_short.
    let (body, status) = err.to_response();
    assert_eq!(status, 400);
    assert_eq!(body["error"], "password_rejected");
    assert_eq!(body["reason"], "too_short");
}

/// What: AUTH-03's order rule: too_short, too_long, blocklisted, first failure wins ("password123" is
/// too_short although it is on every common list); a 129-character password is too_long; a 15+ character
/// common or own-email password is blocklisted. In: none. Out: panics on a wrong reason.
/// Why: 2026-11-10 spec amendment (AUTH-03). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
// AUTH-03
#[test]
fn test_signup_password_rejection_order() {
    let (mut auth_system, _, _, _) = setup();
    let reason = |sys: &mut AuthSystem, email: &str, pw: String| {
        let err = sys.signup(SignupRequest { email: email.into(), password: pw, name: "Test User".into() }).unwrap_err();
        let (body, status) = err.to_response();
        assert_eq!(status, 400);
        assert_eq!(body["error"], "password_rejected");
        body["reason"].as_str().unwrap().to_string()
    };
    assert_eq!(reason(&mut auth_system, "a@example.com", "password123".into()), "too_short");
    assert_eq!(reason(&mut auth_system, "a@example.com", "x".repeat(MAX_PASSWORD_LEN + 1)), "too_long");
    assert_eq!(reason(&mut auth_system, "a@example.com", "passwordpassword".into()), "blocklisted");
    assert_eq!(reason(&mut auth_system, "long.address@example.com", "long.address@example.com".into()), "blocklisted");
    // no user was created by any rejected signup
    assert!(auth_system.signup(SignupRequest { email: "a@example.com".into(), password: PASSWORD.into(), name: "Test User".into() }).is_ok());
}

/// What: AUTH-04: the sixth signup from one IP within 24 hours is refused with 429
/// too_many_signups_from_ip; another IP is not affected. In: none. Out: panics on a wrong answer.
/// Why: the spec's required test AUTH-04 had no Rust test. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: in-memory SQLite.
// AUTH-04
#[test]
fn test_signup_ip_rate_limit() {
    let (mut auth_system, _, _, _) = setup();
    for i in 0..5 {
        let req = SignupRequest { email: format!("user{}@example.com", i), password: PASSWORD.into(), name: "Test User".into() };
        auth_system.signup_with_ip(req, "198.51.100.7").unwrap();
    }
    let req = SignupRequest { email: "user5@example.com".into(), password: PASSWORD.into(), name: "Test User".into() };
    let err = auth_system.signup_with_ip(req.clone(), "198.51.100.7").unwrap_err();
    assert_eq!(err, AuthError::TooManySignups);
    let (body, status) = err.to_response();
    assert_eq!(status, 429);
    assert_eq!(body["error"], "too_many_signups_from_ip");
    assert!(auth_system.signup_with_ip(req, "198.51.100.8").is_ok());
}

/// What: AUTH-06: the right code after its 15 minutes is refused with 400 code_expired and the user
/// stays unverified. In: none. Out: panics on a wrong answer.
/// Why: the spec's required test AUTH-06 had no Rust test. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: in-memory SQLite.
// AUTH-06
#[test]
fn test_verify_email_expired_code() {
    let (mut auth_system, mailer, _, now) = setup();
    auth_system.signup(SignupRequest { email: "test@example.com".into(), password: PASSWORD.into(), name: "Test User".into() }).unwrap();
    let code = last_code(&mailer, "test@example.com");
    now.fetch_add(15 * 60, Ordering::SeqCst);
    let err = auth_system.verify_email(VerifyEmailRequest { email: "test@example.com".into(), code_or_token: code }).unwrap_err();
    assert_eq!(err, AuthError::CodeExpired);
    let (body, status) = err.to_response();
    assert_eq!(status, 400);
    assert_eq!(body["error"], "code_expired");
    // still unverified: login is refused
    assert_eq!(auth_system.login(login_req("test@example.com", PASSWORD)).unwrap_err(), AuthError::EmailNotVerified);
}

// AUTH-05
#[test]
fn test_verify_email_happy_path() {
    let (mut auth_system, mailer, _, _) = setup();
    auth_system.signup(SignupRequest { email: "test@example.com".into(), password: PASSWORD.into(), name: "Test User".into() }).unwrap();
    // a wrong code does not verify (changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, spec Phase B.4: the
    // answer is 400 code_invalid, it was 401 invalid_code)
    assert_eq!(
        auth_system.verify_email(VerifyEmailRequest { email: "test@example.com".into(), code_or_token: "not-the-code".into() }).unwrap_err(),
        AuthError::CodeInvalid
    );

    let verify_req = VerifyEmailRequest { email: "test@example.com".to_string(), code_or_token: last_code(&mailer, "test@example.com") };
    let result = auth_system.verify_email(verify_req);
    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.success);
    assert_eq!(response.data.status(), "verified");
}

/// What: AUTH-17: a wrong verification code is 400 code_invalid; after 5 wrong codes the right code is also
/// 400 code_invalid and the user stays unverified; after 4 wrong codes the right one verifies; a newly sent code
/// works again. In: none. Out: panics on a wrong answer. Why: spec Phase B.3 / B.4 (AUTH-17).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
// AUTH-17
#[test]
fn test_verify_email_five_wrong_codes_kill_the_code() {
    let (mut auth_system, mailer, _, _) = setup();
    let verify = |sys: &mut AuthSystem, email: &str, code: &str| sys.verify_email(VerifyEmailRequest { email: email.into(), code_or_token: code.into() });
    let wrong_for = |code: &str| if code == "000000" { "111111".to_string() } else { "000000".to_string() };
    // five wrong codes, then the right one is refused too
    auth_system.signup(SignupRequest { email: "five@example.com".into(), password: PASSWORD.into(), name: "Five".into() }).unwrap();
    let code = last_code(&mailer, "five@example.com");
    for _ in 0..5 {
        let err = verify(&mut auth_system, "five@example.com", &wrong_for(&code)).unwrap_err();
        assert_eq!(err, AuthError::CodeInvalid);
        let (body, status) = err.to_response();
        assert_eq!((status, body["error"].as_str()), (400, Some("code_invalid")));
    }
    let err = verify(&mut auth_system, "five@example.com", &code).unwrap_err();
    assert_eq!(err, AuthError::CodeInvalid);
    assert_eq!(err.to_response().1, 400);
    assert_eq!(auth_system.login(login_req("five@example.com", PASSWORD)).unwrap_err(), AuthError::EmailNotVerified);
    // a newly sent code works again
    let user_id: i64 = auth_system.conn.query_row("SELECT id FROM users WHERE email = 'five@example.com'", [], |r| r.get(0)).unwrap();
    auth_system.send_email_code(user_id, "five@example.com").unwrap();
    let fresh = last_code(&mailer, "five@example.com");
    assert_eq!(verify(&mut auth_system, "five@example.com", &fresh).unwrap().data.status(), "verified");
    // four wrong codes, then the right one (the fifth try) verifies
    auth_system.signup(SignupRequest { email: "four@example.com".into(), password: PASSWORD.into(), name: "Four".into() }).unwrap();
    let code = last_code(&mailer, "four@example.com");
    for _ in 0..4 {
        assert_eq!(verify(&mut auth_system, "four@example.com", &wrong_for(&code)).unwrap_err(), AuthError::CodeInvalid);
    }
    assert_eq!(verify(&mut auth_system, "four@example.com", &code).unwrap().data.status(), "verified");
}

/// What: AUTH-18, resend_verification (auth spec flow 2b): a code spent by 5 wrong tries is replaced by a new
/// 6-digit code (the only email code row, 0 attempts, stored as its HMAC, expiring in 10 minutes), which is emailed
/// and verifies; a 4th resend for one email within the hour is 429 too_many_requests and sends nothing, and after the
/// hour one is accepted again; an unknown and an already verified email get the same 202 sent and no email.
/// In: none. Out: panics on a wrong answer. Why: AUTH-18 (commit 0eb5a4e). 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite; the in-memory mailer; the fixed clock.
// AUTH-18
#[test]
fn test_resend_verification_replaces_limits_and_hides_accounts() {
    let (mut sys, mailer, _, now) = setup();
    let sent_count = |m: &InMemoryMailer| m.sent.lock().unwrap().len();
    sys.signup(SignupRequest { email: "resend@example.com".into(), password: PASSWORD.into(), name: "Resend".into() }).unwrap();
    let old = last_code(&mailer, "resend@example.com");
    let wrong = if old == "000000" { "111111" } else { "000000" };
    for _ in 0..5 {
        let err = sys.verify_email(VerifyEmailRequest { email: "resend@example.com".into(), code_or_token: wrong.into() }).unwrap_err();
        assert_eq!(err, AuthError::CodeInvalid);
    }
    let err = sys.verify_email(VerifyEmailRequest { email: "resend@example.com".into(), code_or_token: old.clone() }).unwrap_err();
    assert_eq!(err, AuthError::CodeInvalid);
    let before = sent_count(&mailer);
    let r = sys.resend_verification("resend@example.com").unwrap();
    assert_eq!(r, AuthResponse { success: true, data: AuthData::Sent });
    assert_eq!(r.data.status(), "sent");
    assert_eq!(sent_count(&mailer), before + 1);
    let fresh = last_code(&mailer, "resend@example.com");
    assert!(fresh.len() == 6 && fresh.bytes().all(|b| b.is_ascii_digit()), "a 6-digit code: {fresh}");
    let rows: Vec<(String, i64, i64)> = {
        let mut st = sys
            .conn
            .prepare("SELECT vc.code_hash, vc.attempts, vc.expires_at FROM verification_codes vc JOIN users u ON u.id = vc.user_id WHERE u.email = 'resend@example.com' AND vc.type = 'email'")
            .unwrap();
        let mapped = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        mapped.map(|x| x.unwrap()).collect()
    };
    assert_eq!(rows, vec![(sha256_hex(&fresh), 0, now.load(Ordering::SeqCst) + 600)]);
    assert_eq!(sys.verify_email(VerifyEmailRequest { email: "resend@example.com".into(), code_or_token: fresh }).unwrap().data.status(), "verified");

    sys.signup(SignupRequest { email: "limit@example.com".into(), password: PASSWORD.into(), name: "Limit".into() }).unwrap();
    for _ in 0..3 {
        assert_eq!(sys.resend_verification("limit@example.com").unwrap().data, AuthData::Sent);
    }
    let before = sent_count(&mailer);
    now.fetch_add(59 * 60, Ordering::SeqCst);
    let err = sys.resend_verification("limit@example.com").unwrap_err();
    assert_eq!(err, AuthError::TooManyRequests);
    let (body, status) = err.to_response();
    assert_eq!((status, body["error"].as_str()), (429, Some("too_many_requests")));
    assert_eq!(sent_count(&mailer), before);
    now.fetch_add(2 * 60, Ordering::SeqCst);
    assert_eq!(sys.resend_verification("limit@example.com").unwrap().data, AuthData::Sent);
    assert_eq!(sent_count(&mailer), before + 1);

    let before = sent_count(&mailer);
    let unknown = sys.resend_verification("nobody@example.com").unwrap();
    let verified = sys.resend_verification("resend@example.com").unwrap();
    assert_eq!(unknown, AuthResponse { success: true, data: AuthData::Sent });
    assert_eq!(verified, unknown);
    assert_eq!(sent_count(&mailer), before);
}

// AUTH-07
#[test]
fn test_login_happy_path() {
    let (mut auth_system, mailer, _, _) = setup();
    verified_user(&mut auth_system, &mailer, "test@example.com");

    let result = auth_system.login(login_req("test@example.com", PASSWORD));
    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.success);
    assert_eq!(response.data.status(), "authenticated");
}

// AUTH-08
#[test]
fn test_login_with_mfa() {
    let (mut auth_system, mailer, _, now) = setup();
    let user_id = verified_user(&mut auth_system, &mailer, "test@example.com");
    let secret = auth_system.start_mfa_enrollment(user_id).unwrap();
    auth_system.confirm_mfa_enrollment(user_id, &totp_code(&secret, now.load(Ordering::SeqCst) as u64).unwrap()).unwrap();

    let result = auth_system.login(login_req("test@example.com", PASSWORD));
    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.success);
    assert_eq!(response.data.status(), "mfa_required");
}

// AUTH-09
#[test]
fn test_login_invalid_password() {
    let (mut auth_system, mailer, _, _) = setup();
    verified_user(&mut auth_system, &mailer, "test@example.com");

    let result = auth_system.login(login_req("test@example.com", "wrongpassword"));
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
}

// AUTH-10
#[test]
fn test_oauth_callback_new_user() {
    let (mut auth_system, _, oauth, _) = setup();
    oauth.codes.lock().unwrap().insert(
        "google:code123".into(),
        OAuthProfile { provider_user_id: "g-1".into(), email: "new@example.com".into(), email_verified: true },
    );
    let state = auth_system.oauth_start("google").unwrap();

    let oauth_req = OAuthCallbackRequest { provider: "google".to_string(), code: "code123".to_string(), state };
    let result = auth_system.oauth_callback(oauth_req);
    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.success);
    assert_eq!(response.data.status(), "authenticated");
    // a forged state is refused
    let forged = OAuthCallbackRequest { provider: "google".into(), code: "code123".into(), state: "state123".into() };
    assert_eq!(auth_system.oauth_callback(forged).unwrap_err(), AuthError::InvalidState);
}

// AUTH-11
#[test]
fn test_oauth_callback_existing_user() {
    let (mut auth_system, mailer, oauth, _) = setup();
    let user_id = verified_user(&mut auth_system, &mailer, "test@example.com");
    oauth.codes.lock().unwrap().insert(
        "google:code123".into(),
        OAuthProfile { provider_user_id: "g-2".into(), email: "test@example.com".into(), email_verified: true },
    );
    let state = auth_system.oauth_start("google").unwrap();

    let oauth_req = OAuthCallbackRequest { provider: "google".to_string(), code: "code123".to_string(), state };
    let result = auth_system.oauth_callback(oauth_req);
    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.success);
    assert_eq!(response.data.status(), "authenticated");
    // linked to the existing account, not a new one
    match response.data {
        AuthData::Authenticated { user, .. } => assert_eq!(user.id, user_id),
        other => panic!("unexpected {:?}", other),
    }
}

// AUTH-12
#[test]
fn test_mfa_challenge_happy_path() {
    let (mut auth_system, mailer, _, now) = setup();
    let user_id = verified_user(&mut auth_system, &mailer, "test@example.com");
    let secret = auth_system.start_mfa_enrollment(user_id).unwrap();
    auth_system.confirm_mfa_enrollment(user_id, &totp_code(&secret, now.load(Ordering::SeqCst) as u64).unwrap()).unwrap();
    let challenge_id = match auth_system.login(login_req("test@example.com", PASSWORD)).unwrap().data {
        AuthData::MfaRequired { challenge_id } => challenge_id,
        other => panic!("unexpected {:?}", other),
    };
    now.fetch_add(30, Ordering::SeqCst); // next TOTP step (a code is accepted once per step)

    let mfa_req = MFAChallengeRequest { challenge_id, code: totp_code(&secret, now.load(Ordering::SeqCst) as u64).unwrap() };
    let result = auth_system.mfa_challenge(mfa_req);
    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.success);
    assert_eq!(response.data.status(), "authenticated");
}

// AUTH-13
#[test]
fn test_mfa_challenge_wrong_code() {
    let (mut auth_system, mailer, _, now) = setup();
    let user_id = verified_user(&mut auth_system, &mailer, "test@example.com");
    let secret = auth_system.start_mfa_enrollment(user_id).unwrap();
    auth_system.confirm_mfa_enrollment(user_id, &totp_code(&secret, now.load(Ordering::SeqCst) as u64).unwrap()).unwrap();
    let challenge_id = match auth_system.login(login_req("test@example.com", PASSWORD)).unwrap().data {
        AuthData::MfaRequired { challenge_id } => challenge_id,
        other => panic!("unexpected {:?}", other),
    };

    let mfa_req = MFAChallengeRequest { challenge_id, code: "wrongcode".to_string() };
    let result = auth_system.mfa_challenge(mfa_req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), AuthError::InvalidCode);
}

// AUTH-14
#[test]
fn test_token_refresh_happy_path() {
    let (mut auth_system, mailer, _, _) = setup();
    verified_user(&mut auth_system, &mailer, "test@example.com");
    let refresh_token = match auth_system.login(login_req("test@example.com", PASSWORD)).unwrap().data {
        AuthData::Authenticated { refresh_token, .. } => refresh_token,
        other => panic!("unexpected {:?}", other),
    };

    let refresh_req = TokenRefreshRequest { refresh_token };
    let result = auth_system.token_refresh(refresh_req);
    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.success);
    assert_eq!(response.data.status(), "ok");
}

// AUTH-15
#[test]
fn test_token_refresh_banned_user() {
    let (mut auth_system, mailer, _, _) = setup();
    let user_id = verified_user(&mut auth_system, &mailer, "test@example.com");
    let refresh_token = match auth_system.login(login_req("test@example.com", PASSWORD)).unwrap().data {
        AuthData::Authenticated { refresh_token, .. } => refresh_token,
        other => panic!("unexpected {:?}", other),
    };
    auth_system.set_user_status(0, user_id, "banned").unwrap();

    let refresh_req = TokenRefreshRequest { refresh_token };
    let result = auth_system.token_refresh(refresh_req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), AuthError::UserBanned);
}

#[test]
fn test_verify_access_token() {
    let (mut auth_system, mailer, _, now) = setup();
    verified_user(&mut auth_system, &mailer, "test@example.com");
    let token = match auth_system.login(login_req("test@example.com", PASSWORD)).unwrap().data {
        AuthData::Authenticated { token, .. } => token,
        other => panic!("unexpected {:?}", other),
    };

    let verify_req = VerifyAccessTokenRequest { token: token.clone() };
    let result = auth_system.verify_access_token(verify_req);
    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.success);
    assert_eq!(response.data.status(), "ok");

    // RFC 8725: an "alg":"none" token with the same claims is refused, and so is an expired one
    let parts: Vec<&str> = token.split('.').collect();
    let none_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let forged = format!("{}.{}.", none_header, parts[1]);
    assert_eq!(auth_system.verify_access_token(VerifyAccessTokenRequest { token: forged }).unwrap_err(), AuthError::InvalidToken);
    now.fetch_add(ACCESS_TOKEN_SECS, Ordering::SeqCst);
    assert_eq!(auth_system.verify_access_token(VerifyAccessTokenRequest { token }).unwrap_err(), AuthError::TokenExpired);
}

/// What: the refresh token of an Authenticated result. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
/// (AUTH-16). Touches: nothing.
fn refresh_of(data: AuthData) -> String {
    match data {
        AuthData::Authenticated { refresh_token, .. } => refresh_token,
        other => panic!("unexpected {:?}", other),
    }
}

/// What: AUTH-16 and the auth spec's "Secrets at rest" line (Phase B.2): login, MFA verify and OAuth each
/// return a refresh_token that token_refresh accepts; the sessions table holds only its SHA-256 (no
/// column of any session row contains a raw token); a verification code is stored only as its SHA-256
/// (code_hash, never the emailed code); an OAuth state is stored only as its SHA-256, works once and
/// expires after 10 minutes; the callback exchanges the provider code through the injected provider
/// client, so a code the provider does not know fails (502 oauth_failed) even when it looks like an
/// email. In: none. Out: panics on a leak or a refused token. Why: AUTH-16 (Phase B.2, 2026-11-10).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite only.
/// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec d270fa3: keyed HMAC for stored secrets):
/// each stored value must equal HMAC-SHA256(TEST_SECRET_KEY, value) and not its plain SHA-256.
// AUTH-16
#[test]
fn test_refresh_tokens_and_secrets_at_rest() {
    let (mut sys, mailer, oauth, now) = setup();

    // verification code: only its hash is stored
    sys.signup(SignupRequest { email: "a@example.com".into(), password: PASSWORD.into(), name: "Test User".into() }).unwrap();
    let code = last_code(&mailer, "a@example.com");
    let cols: Vec<String> = sys.conn.prepare("SELECT name FROM pragma_table_info('verification_codes')").unwrap()
        .query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
    assert!(cols.contains(&"code_hash".to_string()) && !cols.contains(&"code".to_string()));
    let stored: String = sys.conn.query_row("SELECT code_hash FROM verification_codes WHERE type = 'email'", [], |r| r.get(0)).unwrap();
    assert_eq!(stored, sha256_hex(&code));
    assert_ne!(stored, plain_sha256_hex(&code), "spec d270fa3 (2026-11-10): keyed HMAC, not a plain SHA-256");
    assert_ne!(stored, code);
    sys.verify_email(VerifyEmailRequest { email: "a@example.com".into(), code_or_token: code }).unwrap();

    // login returns a refresh token that token_refresh accepts
    let mut tokens = vec![refresh_of(sys.login(login_req("a@example.com", PASSWORD)).unwrap().data)];

    // MFA verify returns one too
    let b = verified_user(&mut sys, &mailer, "b@example.com");
    let secret = sys.start_mfa_enrollment(b).unwrap();
    sys.confirm_mfa_enrollment(b, &totp_code(&secret, now.load(Ordering::SeqCst) as u64).unwrap()).unwrap();
    let challenge_id = match sys.login(login_req("b@example.com", PASSWORD)).unwrap().data {
        AuthData::MfaRequired { challenge_id } => challenge_id,
        other => panic!("unexpected {:?}", other),
    };
    now.fetch_add(30, Ordering::SeqCst);
    let code = totp_code(&secret, now.load(Ordering::SeqCst) as u64).unwrap();
    tokens.push(refresh_of(sys.mfa_challenge(MFAChallengeRequest { challenge_id, code }).unwrap().data));

    // OAuth returns one too; the state is hashed, single-use and lives 10 minutes
    oauth.codes.lock().unwrap().insert(
        "google:pc-1".into(),
        OAuthProfile { provider_user_id: "g-16".into(), email: "c@example.com".into(), email_verified: true },
    );
    let state = sys.oauth_start("google").unwrap();
    let state_hash: String = sys.conn.query_row("SELECT state_hash FROM oauth_states", [], |r| r.get(0)).unwrap();
    assert_eq!(state_hash, sha256_hex(&state));
    assert_ne!(state_hash, plain_sha256_hex(&state), "spec d270fa3: the state's keyed HMAC is stored");
    tokens.push(refresh_of(sys.oauth_callback(OAuthCallbackRequest { provider: "google".into(), code: "pc-1".into(), state: state.clone() }).unwrap().data));
    assert_eq!(
        sys.oauth_callback(OAuthCallbackRequest { provider: "google".into(), code: "pc-1".into(), state }).unwrap_err(),
        AuthError::InvalidState,
        "a state works once"
    );
    let late = sys.oauth_start("google").unwrap();
    now.fetch_add(600, Ordering::SeqCst);
    assert_eq!(
        sys.oauth_callback(OAuthCallbackRequest { provider: "google".into(), code: "pc-1".into(), state: late }).unwrap_err(),
        AuthError::InvalidState,
        "a state expires after 10 minutes"
    );
    // the code is exchanged through the provider client, never used as an identity
    let fresh = sys.oauth_start("google").unwrap();
    let err = sys.oauth_callback(OAuthCallbackRequest { provider: "google".into(), code: "a@example.com".into(), state: fresh }).unwrap_err();
    assert_eq!(err, AuthError::OAuthFailed);
    assert_eq!(err.to_response().1, 502);

    // every refresh token is accepted, and the sessions table holds only SHA-256 hashes of them
    let hashes: Vec<String> = sys.conn.prepare("SELECT refresh_token_hash FROM sessions ORDER BY rowid").unwrap()
        .query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
    assert_eq!(hashes.len(), 3);
    let cols: Vec<String> = sys.conn.prepare("SELECT name FROM pragma_table_info('sessions')").unwrap()
        .query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
    assert!(!cols.contains(&"refresh_token".to_string()));
    let dump: Vec<String> = sys.conn.prepare("SELECT id || '|' || user_id || '|' || refresh_token_hash || '|' || COALESCE(ip, '') || '|' || COALESCE(device_id, '') FROM sessions").unwrap()
        .query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
    for (i, t) in tokens.iter().enumerate() {
        assert!(hashes.contains(&sha256_hex(t)), "token {} stored as its HMAC-SHA256 under the test key", i);
        assert!(!hashes.contains(&plain_sha256_hex(t)), "token {} not stored as its plain SHA-256 (spec d270fa3)", i);
        assert!(dump.iter().all(|row| !row.contains(t.as_str())), "token {} not stored raw", i);
        let r = sys.token_refresh(TokenRefreshRequest { refresh_token: t.clone() }).unwrap();
        assert_eq!(r.data.status(), "ok", "token {} accepted", i);
    }
    // a stored hash is not itself a usable credential
    assert_eq!(sys.token_refresh(TokenRefreshRequest { refresh_token: hashes[0].clone() }).unwrap_err(), AuthError::InvalidToken);
}

/// What: AUTH-16: the service refuses to start without a 32-byte HMAC key: `AuthSystem::new` returns
/// `InvalidInput` for an empty or 31-byte `secret_key`, and with a 32-byte key it
/// starts and stores HMAC-SHA256(key, value), not the plain SHA-256. In: none. Out: panics on a wrong
/// answer. Why: spec d270fa3: keyed HMAC for stored secrets ("the service refuses to start without it").
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite only.
// AUTH-16
#[test]
fn test_service_refuses_to_start_without_a_32_byte_secret_key() {
    for bad in ["", &"k".repeat(31)] {
        let conn = Connection::open_in_memory().unwrap();
        match AuthSystem::new(conn, JWT_SECRET.to_string(), bad.to_string()) {
            Err(AuthError::InvalidInput(m)) => assert!(m.contains("AUTH_SECRET_KEY"), "{}", m),
            Err(e) => panic!("a {}-byte key: unexpected error {:?}", bad.len(), e),
            Ok(_) => panic!("a {}-byte key must refuse to start", bad.len()),
        }
    }
    let sys = AuthSystem::new(Connection::open_in_memory().unwrap(), JWT_SECRET.to_string(), TEST_SECRET_KEY.to_string()).unwrap();
    assert_eq!(sys.hash_secret("123456"), sha256_hex("123456"));
    assert_ne!(sys.hash_secret("123456"), plain_sha256_hex("123456"));
}

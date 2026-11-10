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

/// What: an auth system on in-memory SQLite with a fixed clock, bcrypt cost 4, an in-memory mailer and
/// a fake OAuth provider; returns handles to all of them. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn setup() -> (AuthSystem, InMemoryMailer, FakeOAuthProvider, Arc<AtomicI64>) {
    let mailer = InMemoryMailer::default();
    let oauth = FakeOAuthProvider::default();
    let now = Arc::new(AtomicI64::new(1_767_225_600));
    let clock = now.clone();
    let sys = AuthSystem::new(Connection::open_in_memory().unwrap(), JWT_SECRET.to_string())
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
    // a wrong code does not verify
    assert_eq!(
        auth_system.verify_email(VerifyEmailRequest { email: "test@example.com".into(), code_or_token: "not-the-code".into() }).unwrap_err(),
        AuthError::InvalidCode
    );

    let verify_req = VerifyEmailRequest { email: "test@example.com".to_string(), code_or_token: last_code(&mailer, "test@example.com") };
    let result = auth_system.verify_email(verify_req);
    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.success);
    assert_eq!(response.data.status(), "verified");
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

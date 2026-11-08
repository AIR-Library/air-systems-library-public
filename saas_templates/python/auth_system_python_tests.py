import pytest
import sqlite3
import tempfile
import os
import json
from datetime import datetime, timedelta, timezone
import pyotp
from auth_system_python import AuthSystem

@pytest.fixture
def auth_system():
    # Create an in-memory database
    db_connection = sqlite3.connect(':memory:')
    db_connection.row_factory = sqlite3.Row
    auth = AuthSystem(db_connection, jwt_secret='test_secret', bcrypt_rounds=4)
    yield auth
    db_connection.close()

def test_signup_happy_path(auth_system):
    result = auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    assert result['status'] == 'pending_verification'
    assert result['email'] == 'test@example.com'
    # Check user created
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id, email, status FROM users WHERE email = 'test@example.com'")
    user = cursor.fetchone()
    assert user is not None
    assert user['status'] == 'unverified'
    # Check verification code exists
    cursor.execute("SELECT COUNT(*) FROM verification_codes WHERE user_id = ?", (user['id'],))
    assert cursor.fetchone()[0] == 1

def test_signup_duplicate_email(auth_system):
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    result = auth_system.signup('test@example.com', 'b' * 16, 'Test User 2', '127.0.0.1')
    assert result['error'] == 'email_already_exists'

def test_signup_weak_password_too_short(auth_system):
    result = auth_system.signup('test@example.com', 'short', 'Test User', '127.0.0.1')
    assert result['error'] == 'password_rejected'
    assert result['reason'] == 'too_short'

def test_signup_weak_password_too_long(auth_system):
    result = auth_system.signup('test@example.com', 'a' * 65, 'Test User', '127.0.0.1')
    assert result['error'] == 'password_rejected'
    assert result['reason'] == 'too_long'

def test_signup_weak_password_blocklisted(auth_system):
    result = auth_system.signup('test@example.com', 'password', 'Test User', '127.0.0.1')
    assert result['error'] == 'password_rejected'
    assert result['reason'] == 'blocklisted'
    result = auth_system.signup('test2@example.com', 'test2@example.com', 'Test User', '127.0.0.1')
    assert result['error'] == 'password_rejected'
    assert result['reason'] == 'blocklisted'
    result = auth_system.signup('test3@example.com', 'Test User', 'Test User', '127.0.0.1')
    assert result['error'] == 'password_rejected'
    assert result['reason'] == 'blocklisted'
    result = auth_system.signup('test4@example.com', 'SaasAuth', 'Test User', '127.0.0.1')
    assert result['error'] == 'password_rejected'
    assert result['reason'] == 'blocklisted'

def test_signup_ip_rate_limit(auth_system):
    ip = '192.168.1.100'
    for i in range(6):
        result = auth_system.signup(f'test{i}@example.com', 'a' * 16, f'Test User {i}', ip)
        if i < 5:
            assert result['status'] == 'pending_verification', f"Signup {i} failed: {result}"
        else:
            assert result['error'] == 'too_many_signups_from_ip', f"Signup {i} should be rate limited: {result}"

def test_verify_email_happy_path(auth_system):
    # First signup
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    user_id = None
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'test@example.com'")
    user = cursor.fetchone()
    user_id = user['id']
    # Get the verification code
    cursor.execute("SELECT code FROM verification_codes WHERE user_id = ? AND type = 'email'", (user_id,))
    code = cursor.fetchone()['code']
    # Verify
    result = auth_system.verify_email('test@example.com', code)
    assert result['status'] == 'verified'
    assert result['user_id'] == user_id
    # Check user is verified
    cursor.execute("SELECT email_verified_at, status FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    assert user['email_verified_at'] is not None
    assert user['status'] == 'verified'
    # Check verification code is deleted
    cursor.execute("SELECT COUNT(*) FROM verification_codes WHERE user_id = ? AND type = 'email'", (user_id,))
    assert cursor.fetchone()[0] == 0

def test_verify_email_expired_code(auth_system):
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'test@example.com'")
    user_id = cursor.fetchone()['id']
    # Manually insert an expired code
    expired_time = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
    cursor.execute(
        "INSERT INTO verification_codes (user_id, code, created_at, expires_at, type) VALUES (?, ?, ?, ?, ?)",
        (user_id, 'expired', expired_time, expired_time, 'email')
    )
    auth_system.db.commit()
    result = auth_system.verify_email('test@example.com', 'expired')
    assert result['error'] == 'code_expired'

def test_login_happy_path_no_mfa(auth_system):
    # Create verified user
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'test@example.com'")
    user_id = cursor.fetchone()['id']
    # Verify email
    cursor.execute("SELECT code FROM verification_codes WHERE user_id = ? AND type = 'email'", (user_id,))
    code = cursor.fetchone()['code']
    auth_system.verify_email('test@example.com', code)
    # Login
    result = auth_system.login('test@example.com', 'a' * 16, 'device123', '192.168.1.1')
    assert result['status'] == 'authenticated'
    assert 'token' in result
    assert result['user']['id'] == user_id
    assert result['user']['email'] == 'test@example.com'
    # Check session created
    cursor.execute("SELECT COUNT(*) FROM sessions WHERE user_id = ?", (user_id,))
    assert cursor.fetchone()[0] == 1

def test_login_with_mfa_enabled(auth_system):
    # We need to enable MFA for a user. Since there's no direct method, we'll manually set mfa_secret and mfa_enabled
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'test@example.com'")
    user_id = cursor.fetchone()['id']
    # Verify email to make user verified
    cursor.execute("SELECT code FROM verification_codes WHERE user_id = ? AND type = 'email'", (user_id,))
    code = cursor.fetchone()['code']
    auth_system.verify_email('test@example.com', code)
    # Enable MFA manually
    mfa_secret = pyotp.random_base32()
    cursor.execute(
        "UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE id = ?",
        (mfa_secret, user_id)
    )
    auth_system.db.commit()
    # Login should trigger MFA
    result = auth_system.login('test@example.com', 'a' * 16, 'device123', '192.168.1.1')
    assert result['status'] == 'mfa_required'
    assert 'challenge_id' in result
    challenge_id = result['challenge_id']
    # Now verify MFA challenge
    totp = pyotp.TOTP(mfa_secret)
    mfa_code = totp.now()
    mfa_result = auth_system.mfa_challenge(challenge_id, mfa_code)
    assert mfa_result['status'] == 'authenticated'
    assert 'token' in mfa_result
    assert mfa_result['user']['id'] == user_id

def test_login_invalid_password(auth_system):
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'test@example.com'")
    user_id = cursor.fetchone()['id']
    cursor.execute("SELECT code FROM verification_codes WHERE user_id = ? AND type = 'email'", (user_id,))
    code = cursor.fetchone()['code']
    auth_system.verify_email('test@example.com', code)
    result = auth_system.login('test@example.com', 'wrongpassword', 'device123', '192.168.1.1')
    assert result['error'] == 'invalid_credentials'
    # Check rate limit logged
    cursor.execute("SELECT COUNT(*) FROM rate_limit_log WHERE ip = '192.168.1.1' AND identifier = 'test@example.com' AND type = 'login'")
    assert cursor.fetchone()[0] == 1

def test_login_rate_limit(auth_system):
    # Create verified user
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'test@example.com'")
    user_id = cursor.fetchone()['id']
    cursor.execute("SELECT code FROM verification_codes WHERE user_id = ? AND type = 'email'", (user_id,))
    code = cursor.fetchone()['code']
    auth_system.verify_email('test@example.com', code)
    ip = '192.168.1.50'
    # 5 failed attempts
    for i in range(5):
        result = auth_system.login('test@example.com', 'wrongpassword', 'device123', ip)
        assert result['error'] == 'invalid_credentials'
    # 6th attempt should be rate limited
    result = auth_system.login('test@example.com', 'wrongpassword', 'device123', ip)
    assert result['error'] == 'too_many_failed_logins'

def test_oauth_callback_new_user(auth_system):
    result = auth_system.oauth_callback('google', 'auth_code', 'state')
    assert result['status'] == 'authenticated'
    assert result['user']['tier'] == 'free'
    assert result['user']['email'].endswith('@google.com')
    # Check user created and verified
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id, email, status, email_verified_at FROM users WHERE email = ?", (result['user']['email'],))
    user = cursor.fetchone()
    assert user is not None
    assert user['status'] == 'verified'
    assert user['email_verified_at'] is not None
    # Check OAuth account linked
    cursor.execute("SELECT * FROM oauth_accounts WHERE user_id = ? AND provider = 'google'", (user['id'],))
    oauth = cursor.fetchone()
    assert oauth is not None
    # Check session created
    cursor.execute("SELECT COUNT(*) FROM sessions WHERE user_id = ?", (user['id'],))
    assert cursor.fetchone()[0] == 1

def test_oauth_callback_ignores_email_in_state(auth_system):
    """state passes through the visitor's browser, so an e-mail placed there must never choose the account."""
    state = json.dumps({'email': 'victim@example.com'})
    result = auth_system.oauth_callback('github', 'auth_code', state)
    assert result['user']['email'] != 'victim@example.com'


def test_oauth_callback_existing_user(auth_system):
    # First create a user via email
    auth_system.signup('existing@example.com', 'a' * 16, 'Existing User', '127.0.0.1')
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'existing@example.com'")
    user_id = cursor.fetchone()['id']
    cursor.execute("SELECT code FROM verification_codes WHERE user_id = ? AND type = 'email'", (user_id,))
    code = cursor.fetchone()['code']
    auth_system.verify_email('existing@example.com', code)
    # Now OAuth with the same e-mail, as the provider reports it
    auth_system.oauth_profile = lambda provider, code: {'id': 'gh-42', 'email': 'existing@example.com', 'email_verified': True}
    result = auth_system.oauth_callback('github', 'auth_code', 'state')
    assert result['status'] == 'authenticated'
    assert result['user']['id'] == user_id
    assert result['user']['email'] == 'existing@example.com'
    # Check OAuth account linked
    cursor.execute("SELECT * FROM oauth_accounts WHERE user_id = ? AND provider = 'github'", (user_id,))
    oauth = cursor.fetchone()
    assert oauth is not None
    # Check no duplicate user
    cursor.execute("SELECT COUNT(*) FROM users WHERE email = 'existing@example.com'")
    assert cursor.fetchone()[0] == 1

def test_mfa_challenge_happy_path(auth_system):
    # Setup user with MFA enabled
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'test@example.com'")
    user_id = cursor.fetchone()['id']
    cursor.execute("SELECT code FROM verification_codes WHERE user_id = ? AND type = 'email'", (user_id,))
    code = cursor.fetchone()['code']
    auth_system.verify_email('test@example.com', code)
    # Enable MFA
    mfa_secret = pyotp.random_base32()
    cursor.execute(
        "UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE id = ?",
        (mfa_secret, user_id)
    )
    auth_system.db.commit()
    # Create a challenge directly (simulate login's MFA challenge creation)
    totp = pyotp.TOTP(mfa_secret)
    current_code = totp.now()
    cursor.execute(
        """INSERT INTO verification_codes (user_id, code, created_at, expires_at, type)
           VALUES (?, ?, ?, ?, ?)""",
        (user_id, current_code, datetime.now(timezone.utc).isoformat(),
         (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(), 'mfa')
    )
    challenge_id = cursor.lastrowid
    auth_system.db.commit()
    # Call mfa_challenge with correct code
    result = auth_system.mfa_challenge(challenge_id, current_code)
    assert result['status'] == 'authenticated'
    assert 'token' in result
    assert result['user']['id'] == user_id
    assert result['user']['email'] == 'test@example.com'
    # Challenge should be deleted
    cursor.execute("SELECT COUNT(*) FROM verification_codes WHERE id = ?", (challenge_id,))
    assert cursor.fetchone()[0] == 0

def test_mfa_challenge_wrong_code(auth_system):
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'test@example.com'")
    user_id = cursor.fetchone()['id']
    cursor.execute("SELECT code FROM verification_codes WHERE user_id = ? AND type = 'email'", (user_id,))
    code = cursor.fetchone()['code']
    auth_system.verify_email('test@example.com', code)
    mfa_secret = pyotp.random_base32()
    cursor.execute(
        "UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE id = ?",
        (mfa_secret, user_id)
    )
    auth_system.db.commit()
    totp = pyotp.TOTP(mfa_secret)
    current_code = totp.now()
    cursor.execute(
        """INSERT INTO verification_codes (user_id, code, created_at, expires_at, type)
           VALUES (?, ?, ?, ?, ?)""",
        (user_id, current_code, datetime.now(timezone.utc).isoformat(),
         (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(), 'mfa')
    )
    challenge_id = cursor.lastrowid
    auth_system.db.commit()
    # Wrong code
    result = auth_system.mfa_challenge(challenge_id, '000000')
    assert result['error'] == 'invalid_code'

def test_token_refresh_happy_path(auth_system):
    # Create verified user and login to get refresh token
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'test@example.com'")
    cursor.fetchone()


def test_oauth_callback_refuses_an_unverified_email(auth_system):
    """The provider must vouch for the address before it can sign anyone in. 2026-11-08, from review."""
    auth_system.oauth_profile = lambda provider, code: {'id': 'gh-7', 'email': 'someone@example.com', 'email_verified': False}
    assert auth_system.oauth_callback('github', 'auth_code', 'state') == {'error': 'email_not_verified'}


def test_oauth_callback_finds_a_returning_user_by_provider_id(auth_system):
    """A user whose e-mail changed at the provider still reaches the same account. 2026-11-08, from review."""
    auth_system.oauth_profile = lambda provider, code: {'id': 'gh-9', 'email': 'old@example.com', 'email_verified': True}
    first = auth_system.oauth_callback('github', 'code-1', 'state')
    auth_system.oauth_profile = lambda provider, code: {'id': 'gh-9', 'email': 'new@example.com', 'email_verified': True}
    second = auth_system.oauth_callback('github', 'code-2', 'state')
    assert second['user']['id'] == first['user']['id']

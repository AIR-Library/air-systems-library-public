import pytest
import sqlite3
import tempfile
import os
import json
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import pyotp
from auth_system_python import AuthSystem

# [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2 (AUTH-16, "Secrets at rest"): the database keeps only
# SHA-256 hashes of verification codes and refresh tokens, so the tests take each code from the (fake) email
# sender and each refresh token from the flow's response, never from a table; rows a test inserts by hand store
# code_hash; OAuth tests get their state from oauth_start() and pass a fake provider client.


# Fixed 32+ byte HMAC key the tests pass to the module (spec d270fa3: tests pass a fixed test key).
# 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
TEST_SECRET_KEY = 'test-secret-key-0123456789abcdef-auth'


def _sha(value):
    """HMAC-SHA256(TEST_SECRET_KEY, value) as lowercase hex: the value the module stores for a secret. In: the
    secret. Out: 64 hex chars. Why: spec d270fa3: keyed HMAC for stored secrets; this helper computed a plain
    SHA-256 until 2026-11-10 (changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches nothing."""
    return hmac.new(TEST_SECRET_KEY.encode('utf-8'), value.encode('utf-8'), hashlib.sha256).hexdigest()


def _plain_sha256(value):
    """Plain, unkeyed SHA-256 hex of a secret, which the module must no longer store. In: the secret. Out: 64 hex
    chars. Why: spec d270fa3: keyed HMAC for stored secrets (AUTH-16 asserts the stored value is not this).
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


@pytest.fixture
def auth_system():
    """An AuthSystem on an in-memory database whose email sender records (email, code) in auth.sent_codes.
    Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2: codes are no longer readable from the
    database). Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec d270fa3: keyed HMAC for stored secrets):
    passes the fixed TEST_SECRET_KEY. Touches: in-memory SQLite only."""
    # Create an in-memory database
    db_connection = sqlite3.connect(':memory:')
    db_connection.row_factory = sqlite3.Row
    auth = AuthSystem(db_connection, jwt_secret='test_secret', bcrypt_rounds=4, secret_key=TEST_SECRET_KEY)
    auth.sent_codes = []
    auth.email_sender = lambda email, code: auth.sent_codes.append((email, code))
    yield auth
    db_connection.close()


def _sent_code(auth_system, email):
    """The newest verification code the fake sender delivered to email. 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2). Touches nothing."""
    return [code for to, code in auth_system.sent_codes if to == email][-1]


class FakeOAuthClient:
    """A fake provider client: exchange(provider, code) returns the profile registered for that one-time code and
    raises for any other code, like a provider's token endpoint. Records every exchange. 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, auth "Secrets at rest"). Touches nothing; no network."""

    def __init__(self, profiles):
        """profiles: {code: profile dict}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.profiles = dict(profiles)
        self.exchanged = []

    def __call__(self, provider, code):
        """Exchange code (once) for its profile, or raise ValueError("invalid_grant"). 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.exchanged.append((provider, code))
        if code not in self.profiles:
            raise ValueError("invalid_grant")
        return self.profiles.pop(code)

# AUTH-01
def test_signup_happy_path(auth_system):
    # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Also asserts the verification email is sent, through a fake
    # sender (AUTH-01 "email sent").
    """Signup creates an unverified user and sends the stored code to the email.
    In: the test fixtures. Out: assertions. Why: AUTH-01. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: checks the fake email sender.
    Touches: in-memory SQLite only."""
    sent = []
    auth_system.email_sender = lambda email, code: sent.append((email, code))
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
    # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2 (AUTH-16): the table keeps the code's SHA-256 only.
    cursor.execute("SELECT code_hash FROM verification_codes WHERE user_id = ?", (user['id'],))
    assert len(sent) == 1 and sent[0][0] == 'test@example.com'
    assert cursor.fetchone()['code_hash'] == _sha(sent[0][1])

# AUTH-02
def test_signup_duplicate_email(auth_system):
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    result = auth_system.signup('test@example.com', 'b' * 16, 'Test User 2', '127.0.0.1')
    assert result['error'] == 'email_already_exists'

# AUTH-03
def test_signup_weak_password_too_short(auth_system):
    result = auth_system.signup('test@example.com', 'short', 'Test User', '127.0.0.1')
    assert result['error'] == 'password_rejected'
    assert result['reason'] == 'too_short'

def test_signup_weak_password_too_long(auth_system):
    result = auth_system.signup('test@example.com', 'a' * 65, 'Test User', '127.0.0.1')
    assert result['error'] == 'password_rejected'
    assert result['reason'] == 'too_long'

# AUTH-03
# [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Changed for the amended AUTH-03: checks run too_short, too_long,
# blocklisted and the first failure wins, so the old short blocklisted passwords ("password", "SaasAuth") are
# now too_short; blocklisted is proved with passwords of 15+ characters.
def test_signup_weak_password_blocklisted(auth_system):
    """A 15-64 char password that is common, or equals the email or name, is "blocklisted"; a short common one
    is "too_short". In: the auth_system fixture. Out: assertions only. Why: AUTH-03 (amended 2026-11-10).
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the fixture's in-memory SQLite database."""
    result = auth_system.signup('test@example.com', 'password', 'Test User', '127.0.0.1')
    assert result == {'error': 'password_rejected', 'reason': 'too_short'}
    result = auth_system.signup('test1@example.com', 'password123', 'Test User', '127.0.0.1')
    assert result == {'error': 'password_rejected', 'reason': 'too_short'}
    result = auth_system.signup('test@example.com', 'PasswordPassword', 'Test User', '127.0.0.1')
    assert result['error'] == 'password_rejected'
    assert result['reason'] == 'blocklisted'
    result = auth_system.signup('longaddress2@example.com', 'LongAddress2@example.com', 'Test User', '127.0.0.1')
    assert result['error'] == 'password_rejected'
    assert result['reason'] == 'blocklisted'
    result = auth_system.signup('test3@example.com', 'Theodora Winterbottom', 'Theodora Winterbottom', '127.0.0.1')
    assert result['error'] == 'password_rejected'
    assert result['reason'] == 'blocklisted'
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    assert cursor.fetchone()[0] == 0

# AUTH-04
def test_signup_ip_rate_limit(auth_system):
    ip = '192.168.1.100'
    for i in range(6):
        result = auth_system.signup(f'test{i}@example.com', 'a' * 16, f'Test User {i}', ip)
        if i < 5:
            assert result['status'] == 'pending_verification', f"Signup {i} failed: {result}"
        else:
            assert result['error'] == 'too_many_signups_from_ip', f"Signup {i} should be rate limited: {result}"

# AUTH-05
def test_verify_email_happy_path(auth_system):
    # First signup
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    user_id = None
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'test@example.com'")
    user = cursor.fetchone()
    user_id = user['id']
    # Get the verification code (from the email; the table keeps only its hash)
    code = _sent_code(auth_system, 'test@example.com')
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

# AUTH-06
def test_verify_email_expired_code(auth_system):
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'test@example.com'")
    user_id = cursor.fetchone()['id']
    # Manually insert an expired code
    expired_time = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
    cursor.execute(
        "INSERT INTO verification_codes (user_id, code_hash, created_at, expires_at, type) VALUES (?, ?, ?, ?, ?)",
        (user_id, _sha('expired'), expired_time, expired_time, 'email')
    )
    auth_system.db.commit()
    result = auth_system.verify_email('test@example.com', 'expired')
    assert result['error'] == 'code_expired'

# AUTH-17
def test_verify_email_five_wrong_codes_invalidate_the_code(auth_system):
    """5 wrong verification codes invalidate the user's current code: every further try, the right code included,
    is {error: "code_invalid"} and the user stays unverified, until a new code is stored; that new code verifies.
    Another user's code is not affected. In: the fixture. Out: assertions. Why: the Phase B.3 ruling in
    auth_system.md flow 2 ("Attempts"). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    Touches: in-memory SQLite only.
    Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.4, af92d76): tagged AUTH-17, the id the ruling
    gave this rule, and each wrong code now asserts {error: "code_invalid"} (it asserted code_expired, the
    answer af92d76 rules out for a wrong code)."""
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    auth_system.signup('other@example.com', 'a' * 16, 'Other User', '127.0.0.1')
    code = _sent_code(auth_system, 'test@example.com')
    wrong = '%06d' % ((int(code) + 1) % 1000000) if code.isdigit() else 'wrong-code'
    # Phase B.4 (af92d76, 2026-11-10): a wrong code is code_invalid (this asserted code_expired before).
    for _ in range(5):
        assert auth_system.verify_email('test@example.com', wrong) == {'error': 'code_invalid'}
    assert auth_system.verify_email('test@example.com', code) == {'error': 'code_invalid'}
    assert auth_system.verify_email('test@example.com', wrong) == {'error': 'code_invalid'}
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id, email_verified_at FROM users WHERE email = 'test@example.com'")
    user = cursor.fetchone()
    assert user['email_verified_at'] is None
    # A new code is sent (stored as its HMAC, as signup stores one): it works.
    expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    cursor.execute("INSERT INTO verification_codes (user_id, code_hash, created_at, expires_at, type) "
                   "VALUES (?, ?, ?, ?, 'email')", (user['id'], _sha('654321'), expires, expires))
    auth_system.db.commit()
    assert auth_system.verify_email('test@example.com', '654321')['status'] == 'verified'
    # 4 wrong codes do not invalidate: the 5th try with the right code verifies.
    other = _sent_code(auth_system, 'other@example.com')
    other_wrong = '%06d' % ((int(other) + 1) % 1000000) if other.isdigit() else 'wrong-code'
    # Phase B.4 (af92d76, 2026-11-10): a wrong code is code_invalid (this asserted code_expired before).
    for _ in range(4):
        assert auth_system.verify_email('other@example.com', other_wrong) == {'error': 'code_invalid'}
    assert auth_system.verify_email('other@example.com', other)['status'] == 'verified'


# AUTH-18
def test_resend_verification_replaces_spent_code_limits_and_hides_accounts(auth_system):
    """resend_verification (auth spec flow 2b): a code spent by 5 wrong tries is replaced by a new one (the only email
    code row, attempts 0, stored as its HMAC, expiring in 10 minutes), which is emailed and verifies; a 4th resend for
    one email within the hour is {error: "too_many_requests"} and sends nothing, and after the hour a resend works
    again; an unknown and an already verified email get the same {status: "sent"} as a real resend and no email.
    In: the fixture, with an injected clock. Out: assertions. Why: AUTH-18 (commit 0eb5a4e). 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite only; the fake email sender."""
    now = [datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)]
    auth_system.clock = lambda: now[0]
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    old = _sent_code(auth_system, 'test@example.com')
    wrong = '%06d' % ((int(old) + 1) % 1000000)
    for _ in range(5):
        assert auth_system.verify_email('test@example.com', wrong) == {'error': 'code_invalid'}
    assert auth_system.verify_email('test@example.com', old) == {'error': 'code_invalid'}
    sent_before = len(auth_system.sent_codes)
    assert auth_system.resend_verification('test@example.com') == {'status': 'sent'}
    assert len(auth_system.sent_codes) == sent_before + 1
    to, new = auth_system.sent_codes[-1]
    assert to == 'test@example.com' and len(new) == 6 and new.isdigit()
    rows = auth_system.db.execute(
        "SELECT code_hash, attempts, expires_at FROM verification_codes vc JOIN users u ON u.id = vc.user_id "
        "WHERE u.email = 'test@example.com' AND vc.type = 'email'").fetchall()
    assert len(rows) == 1
    assert rows[0]['code_hash'] == _sha(new) and rows[0]['attempts'] == 0
    assert datetime.fromisoformat(rows[0]['expires_at']) == now[0] + timedelta(minutes=10)
    assert auth_system.verify_email('test@example.com', new)['status'] == 'verified'

    # 3 resends per email per hour; the 4th is refused and sends nothing; an hour later one is accepted again.
    auth_system.signup('other@example.com', 'a' * 16, 'Other User', '127.0.0.1')
    for _ in range(3):
        assert auth_system.resend_verification('other@example.com') == {'status': 'sent'}
    sent_before = len(auth_system.sent_codes)
    now[0] += timedelta(minutes=59)
    assert auth_system.resend_verification('other@example.com') == {'error': 'too_many_requests'}
    assert len(auth_system.sent_codes) == sent_before
    now[0] += timedelta(minutes=2)
    assert auth_system.resend_verification('other@example.com') == {'status': 'sent'}
    assert len(auth_system.sent_codes) == sent_before + 1

    # Unknown and verified emails: the same answer as a real resend, and no email.
    sent_before = len(auth_system.sent_codes)
    unknown = auth_system.resend_verification('nobody@example.com')
    verified = auth_system.resend_verification('test@example.com')
    assert unknown == verified == {'status': 'sent'}
    assert len(auth_system.sent_codes) == sent_before
    assert auth_system.db.execute(
        "SELECT COUNT(*) FROM verification_codes vc JOIN users u ON u.id = vc.user_id "
        "WHERE u.email = 'test@example.com'").fetchone()[0] == 0


def _file_auth(path):
    """An AuthSystem on its own connection to the SQLite file at path, with a recording email sender, as one
    request's worker would have. In: the file path. Out: the AuthSystem. Why: review finding 4525101305 (a race
    needs two connections). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: that SQLite file."""
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    auth = AuthSystem(conn, jwt_secret='test_secret', bcrypt_rounds=4, secret_key=TEST_SECRET_KEY)
    auth.sent_codes = []
    auth.email_sender = lambda email, code: auth.sent_codes.append((email, code))
    return auth


# AUTH-17
def test_verify_email_attempts_counted_in_database_when_tries_race(tmp_path):
    """The race of review finding 4525101305, made deterministic with two connections to one database file. Four
    wrong codes are tried. Request A (the right code) reads the user's codes; before A goes on, request B (another
    connection) tries a 5th wrong code, which spends the code. A must then answer code_invalid and the user must
    stay unverified: the count is taken in the database when A writes, not from what A read. Before the fix A
    compared using its stale read (attempts = 4) and verified on what was really the 6th try.
    In: pytest's tmp_path. Out: assertions. Why: review finding 4525101305 (CWE-367), auth spec flow 2 "Attempts".
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: a SQLite file under tmp_path."""
    db_file = tmp_path / 'auth.db'
    a = _file_auth(db_file)
    b = _file_auth(db_file)
    try:
        a.signup('race@example.com', 'a' * 16, 'Race User', '127.0.0.1')
        code = _sent_code(a, 'race@example.com')
        wrong = '%06d' % ((int(code) + 1) % 1000000)
        for _ in range(4):
            assert b.verify_email('race@example.com', wrong) == {'error': 'code_invalid'}
        real_hash = a._hash_secret
        raced = []

        def hash_then_let_b_in(value):
            """A's first hash runs after A read the codes: let B try a 5th wrong code then. 2026-11-10,
            session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the SQLite file (through B)."""
            if not raced:
                raced.append(b.verify_email('race@example.com', wrong))
            return real_hash(value)

        a._hash_secret = hash_then_let_b_in
        assert a.verify_email('race@example.com', code) == {'error': 'code_invalid'}
        assert raced == [{'error': 'code_invalid'}]
        a._hash_secret = real_hash
        row = b.db.execute("SELECT email_verified_at FROM users WHERE email = 'race@example.com'").fetchone()
        assert row['email_verified_at'] is None
        attempts = b.db.execute("SELECT attempts FROM verification_codes").fetchone()['attempts']
        assert attempts == 5
        assert b.verify_email('race@example.com', code) == {'error': 'code_invalid'}
    finally:
        a.db.close()
        b.db.close()


# AUTH-17
def test_verify_email_why_chain_never_commits_the_flow_early(auth_system):
    """_log_why_chain commits; during verify_email it is only ever called with no transaction open, for a wrong, an
    expired, a spent and the right code, so it can never commit part of the flow early. The answers are the spec's.
    In: the fixture. Out: assertions. Why: review finding 4525101305. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    Touches: in-memory SQLite only."""
    open_at_call = []
    real_log = auth_system._log_why_chain

    def watching_log(flow, points):
        """Records whether a transaction is open, then logs. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        open_at_call.append(auth_system.db.in_transaction)
        return real_log(flow, points)

    auth_system._log_why_chain = watching_log
    auth_system.signup('t@example.com', 'a' * 16, 'T', '127.0.0.1')
    auth_system.signup('x@example.com', 'a' * 16, 'X', '127.0.0.1')
    code = _sent_code(auth_system, 't@example.com')
    wrong = '%06d' % ((int(code) + 1) % 1000000)
    assert auth_system.verify_email('t@example.com', wrong) == {'error': 'code_invalid'}
    old = _sent_code(auth_system, 'x@example.com')
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    auth_system.db.execute("UPDATE verification_codes SET expires_at = ? WHERE code_hash = ?", (past, _sha(old)))
    auth_system.db.commit()
    assert auth_system.verify_email('x@example.com', old) == {'error': 'code_expired'}
    attempts = auth_system.db.execute("SELECT attempts FROM verification_codes WHERE code_hash = ?",
                                      (_sha(old),)).fetchone()[0]
    assert attempts == 0
    for _ in range(4):
        assert auth_system.verify_email('t@example.com', wrong) == {'error': 'code_invalid'}
    assert auth_system.verify_email('t@example.com', code) == {'error': 'code_invalid'}
    expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    user_id = auth_system.db.execute("SELECT id FROM users WHERE email = 't@example.com'").fetchone()[0]
    auth_system.db.execute("INSERT INTO verification_codes (user_id, code_hash, created_at, expires_at, type) "
                           "VALUES (?, ?, ?, ?, 'email')", (user_id, _sha('654321'), expires, expires))
    auth_system.db.commit()
    assert auth_system.verify_email('t@example.com', '654321')['status'] == 'verified'
    assert len(open_at_call) >= 8 and not any(open_at_call)

# AUTH-07
def test_login_happy_path_no_mfa(auth_system):
    # Create verified user
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'test@example.com'")
    user_id = cursor.fetchone()['id']
    # Verify email
    code = _sent_code(auth_system, 'test@example.com')
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

# AUTH-08
def test_login_with_mfa_enabled(auth_system):
    # We need to enable MFA for a user. Since there's no direct method, we'll manually set mfa_secret and mfa_enabled
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'test@example.com'")
    user_id = cursor.fetchone()['id']
    # Verify email to make user verified
    code = _sent_code(auth_system, 'test@example.com')
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

# AUTH-09
def test_login_invalid_password(auth_system):
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'test@example.com'")
    user_id = cursor.fetchone()['id']
    code = _sent_code(auth_system, 'test@example.com')
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
    code = _sent_code(auth_system, 'test@example.com')
    auth_system.verify_email('test@example.com', code)
    ip = '192.168.1.50'
    # 5 failed attempts
    for i in range(5):
        result = auth_system.login('test@example.com', 'wrongpassword', 'device123', ip)
        assert result['error'] == 'invalid_credentials'
    # 6th attempt should be rate limited
    result = auth_system.login('test@example.com', 'wrongpassword', 'device123', ip)
    assert result['error'] == 'too_many_failed_logins'

# AUTH-10
def test_oauth_callback_new_user(auth_system):
    """A first OAuth sign-in creates a verified user, links the provider account and opens a session.
    Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, auth "Secrets at rest"): the state now comes
    from oauth_start() and the profile from a fake provider client (the module's default client invented a user
    for any code and is now a refusal). Touches: in-memory SQLite only."""
    auth_system.oauth_profile = FakeOAuthClient(
        {'auth_code': {'id': 'g-1', 'email': 'newuser@google.com', 'email_verified': True}})
    state = auth_system.oauth_start('google')['state']
    result = auth_system.oauth_callback('google', 'auth_code', state)
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
    """state passes through the visitor's browser, so an e-mail placed there must never choose the account.
    Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): a state the server never issued is now
    refused outright (invalid_state, no user made); an issued state still signs in only the provider's account."""
    auth_system.oauth_profile = FakeOAuthClient(
        {'auth_code': {'id': 'gh-1', 'email': 'attacker@example.com', 'email_verified': True}})
    state = json.dumps({'email': 'victim@example.com'})
    assert auth_system.oauth_callback('github', 'auth_code', state) == {'error': 'invalid_state'}
    issued = auth_system.oauth_start('github')['state']
    result = auth_system.oauth_callback('github', 'auth_code', issued)
    assert result['user']['email'] == 'attacker@example.com'
    assert result['user']['email'] != 'victim@example.com'


# AUTH-11
def test_oauth_callback_existing_user(auth_system):
    # First create a user via email
    auth_system.signup('existing@example.com', 'a' * 16, 'Existing User', '127.0.0.1')
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'existing@example.com'")
    user_id = cursor.fetchone()['id']
    code = _sent_code(auth_system, 'existing@example.com')
    auth_system.verify_email('existing@example.com', code)
    # Now OAuth with the same e-mail, as the provider reports it
    auth_system.oauth_profile = lambda provider, code: {'id': 'gh-42', 'email': 'existing@example.com', 'email_verified': True}
    # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2: the state must be one oauth_start() issued.
    result = auth_system.oauth_callback('github', 'auth_code', auth_system.oauth_start('github')['state'])
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

# AUTH-12
def test_mfa_challenge_happy_path(auth_system):
    # Setup user with MFA enabled
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'test@example.com'")
    user_id = cursor.fetchone()['id']
    code = _sent_code(auth_system, 'test@example.com')
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
        """INSERT INTO verification_codes (user_id, code_hash, created_at, expires_at, type)
           VALUES (?, ?, ?, ?, ?)""",
        (user_id, _sha(current_code), datetime.now(timezone.utc).isoformat(),
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

# AUTH-13
def test_mfa_challenge_wrong_code(auth_system):
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'test@example.com'")
    user_id = cursor.fetchone()['id']
    code = _sent_code(auth_system, 'test@example.com')
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
        """INSERT INTO verification_codes (user_id, code_hash, created_at, expires_at, type)
           VALUES (?, ?, ?, ?, ?)""",
        (user_id, _sha(current_code), datetime.now(timezone.utc).isoformat(),
         (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(), 'mfa')
    )
    challenge_id = cursor.lastrowid
    auth_system.db.commit()
    # Wrong code
    result = auth_system.mfa_challenge(challenge_id, '000000')
    assert result['error'] == 'invalid_code'

def _login_and_get_refresh_token(auth_system):
    """Sign up, verify and log in test@example.com; return (user_id, the session's refresh token).

    In: the auth_system fixture. Out: (user_id, refresh_token). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, AUTH-16): the refresh token now comes from
    login's response (it was read from the sessions table, which keeps only its hash now).
    Touches: the fixture's in-memory SQLite database."""
    auth_system.signup('test@example.com', 'a' * 16, 'Test User', '127.0.0.1')
    cursor = auth_system.db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'test@example.com'")
    user_id = cursor.fetchone()['id']
    auth_system.verify_email('test@example.com', _sent_code(auth_system, 'test@example.com'))
    login = auth_system.login('test@example.com', 'a' * 16, 'device123', '192.168.1.1')
    assert login['status'] == 'authenticated'
    return user_id, login['refresh_token']


# AUTH-14
# [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Completed: the test stopped after signup and never called
# token_refresh.
def test_token_refresh_happy_path(auth_system):
    """A valid refresh token gets a new access token that verifies as the same user.
    In: the fixture. Out: assertions. Why: AUTH-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    Touches: the fixture's in-memory SQLite database."""
    user_id, refresh_token = _login_and_get_refresh_token(auth_system)
    result = auth_system.token_refresh(refresh_token)
    assert result['status'] == 'ok'
    assert result['expires_in'] == 15 * 60
    verified = auth_system.verify_access_token(result['token'])
    assert verified['status'] == 'ok'
    assert verified['user']['id'] == user_id
    assert auth_system.token_refresh('not-a-real-token') == {'error': 'invalid_token'}


# AUTH-15
def test_token_refresh_banned_user(auth_system):
    """A banned user's refresh token gets {error: "user_banned"} and no token.
    In: the fixture. Out: assertions. Why: AUTH-15 had no test. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    Touches: the fixture's in-memory SQLite database."""
    user_id, refresh_token = _login_and_get_refresh_token(auth_system)
    auth_system.db.execute("UPDATE users SET status = 'banned' WHERE id = ?", (user_id,))
    auth_system.db.commit()
    result = auth_system.token_refresh(refresh_token)
    assert result == {'error': 'user_banned'}


def test_oauth_callback_refuses_an_unverified_email(auth_system):
    """The provider must vouch for the address before it can sign anyone in. 2026-11-08, from review."""
    auth_system.oauth_profile = lambda provider, code: {'id': 'gh-7', 'email': 'someone@example.com', 'email_verified': False}
    # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2: the state must be one oauth_start() issued.
    state = auth_system.oauth_start('github')['state']
    assert auth_system.oauth_callback('github', 'auth_code', state) == {'error': 'email_not_verified'}


def test_oauth_callback_finds_a_returning_user_by_provider_id(auth_system):
    """A user whose e-mail changed at the provider still reaches the same account. 2026-11-08, from review."""
    auth_system.oauth_profile = lambda provider, code: {'id': 'gh-9', 'email': 'old@example.com', 'email_verified': True}
    # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2: each callback needs its own issued state.
    first = auth_system.oauth_callback('github', 'code-1', auth_system.oauth_start('github')['state'])
    auth_system.oauth_profile = lambda provider, code: {'id': 'gh-9', 'email': 'new@example.com', 'email_verified': True}
    second = auth_system.oauth_callback('github', 'code-2', auth_system.oauth_start('github')['state'])
    assert second['user']['id'] == first['user']['id']


def test_mfa_challenge_treats_non_ascii_input_as_a_wrong_code(auth_system):
    """Full-width digits are a wrong code, not a crash. 2026-11-08, from review."""
    cursor = auth_system.db.cursor()
    cursor.execute("INSERT INTO users (email, password_hash, tier, status, created_at, updated_at) VALUES "
                   "('mfa@example.com', NULL, 'free', 'verified', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')")
    user_id = cursor.lastrowid
    cursor.execute("INSERT INTO verification_codes (user_id, code_hash, created_at, expires_at, type) VALUES (?, ?, ?, ?, 'mfa')",
                   (user_id, _sha('123456'), '2026-01-01T00:00:00+00:00', '2999-01-01T00:00:00+00:00'))
    auth_system.db.commit()
    assert auth_system.mfa_challenge(cursor.lastrowid, '１２３４５６') == {'error': 'invalid_code'}


# AUTH-16
def test_every_session_flow_returns_a_refresh_token_stored_only_as_its_hash(auth_system):
    """login, mfa_challenge and oauth_callback each return a refresh_token that token_refresh accepts; the
    sessions table has refresh_token_hash (no refresh_token column) holding each token's SHA-256, and no table
    holds a refresh token or the emailed verification code in plain text (verification_codes keeps code_hash).
    In: the fixture, a fake OAuth client. Out: assertions. Why: AUTH-16 and the Phase B.2 python bug (login
    returned no refresh token). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite only.
    Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec d270fa3: keyed HMAC for stored secrets): every
    stored value must equal HMAC-SHA256(TEST_SECRET_KEY, value) and must not equal its plain SHA-256."""
    auth_system.signup('sixteen@example.com', 'a' * 16, 'Sixteen', '127.0.0.1')
    code = _sent_code(auth_system, 'sixteen@example.com')
    cursor = auth_system.db.cursor()
    columns = {row[1] for row in cursor.execute("PRAGMA table_info(verification_codes)")}
    assert 'code_hash' in columns and 'code' not in columns
    stored = cursor.execute("SELECT code_hash FROM verification_codes WHERE type = 'email'").fetchone()['code_hash']
    assert stored == _sha(code)
    # spec d270fa3 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): keyed HMAC, not a plain SHA-256.
    assert stored != _plain_sha256(code)
    assert code not in _all_rows_text(auth_system)
    auth_system.verify_email('sixteen@example.com', code)

    tokens = []
    login = auth_system.login('sixteen@example.com', 'a' * 16, 'device16', '192.0.2.16')
    tokens.append(login['refresh_token'])

    mfa_secret = pyotp.random_base32()
    cursor.execute("UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE email = 'sixteen@example.com'", (mfa_secret,))
    auth_system.db.commit()
    challenge = auth_system.login('sixteen@example.com', 'a' * 16, 'device16', '192.0.2.16')
    mfa_code = pyotp.TOTP(mfa_secret).now()
    challenge_hash = cursor.execute("SELECT code_hash FROM verification_codes WHERE id = ?",
                                    (challenge['challenge_id'],)).fetchone()['code_hash']
    assert challenge_hash == _sha(mfa_code) and challenge_hash != _plain_sha256(mfa_code)  # spec d270fa3
    tokens.append(auth_system.mfa_challenge(challenge['challenge_id'], mfa_code)['refresh_token'])

    auth_system.oauth_profile = FakeOAuthClient({'c16': {'id': 'g-16', 'email': 'o16@example.com', 'email_verified': True}})
    tokens.append(auth_system.oauth_callback('google', 'c16', auth_system.oauth_start('google')['state'])['refresh_token'])

    columns = {row[1] for row in cursor.execute("PRAGMA table_info(sessions)")}
    assert 'refresh_token_hash' in columns and 'refresh_token' not in columns
    hashes = {row['refresh_token_hash'] for row in cursor.execute("SELECT refresh_token_hash FROM sessions")}
    assert hashes == {_sha(t) for t in tokens}
    assert hashes.isdisjoint({_plain_sha256(t) for t in tokens})  # spec d270fa3, 2026-11-10
    text = _all_rows_text(auth_system)
    for token in tokens:
        assert isinstance(token, str) and len(token) >= 43
        assert token not in text
        result = auth_system.token_refresh(token)
        assert result['status'] == 'ok' and auth_system.verify_access_token(result['token'])['status'] == 'ok'
    # The stored hash is not itself a usable token.
    assert auth_system.token_refresh(_sha(tokens[0])) == {'error': 'invalid_token'}


def _all_rows_text(auth_system):
    """Every value in every table, as one string. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-16).
    Touches: the fixture's database (read)."""
    cursor = auth_system.db.cursor()
    tables = [r[0] for r in cursor.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
    return "\n".join(str(tuple(row)) for t in tables for row in cursor.execute(f"SELECT * FROM {t}"))


# AUTH-16
def test_oauth_state_single_use_expires_in_10_minutes_and_code_is_exchanged(auth_system):
    """OAuth state works once, only for the provider it was issued for, and not after 10 minutes; a state never
    issued is refused; the callback exchanges the code through the provider client, and a code the provider
    rejects is refused with no user made (the code is never an identity). Only the state's SHA-256 is stored.
    In: the fixture with an injected clock, a fake OAuth client. Out: assertions. Why: the auth spec's "Secrets
    at rest" line (Phase B.2, 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    Touches: in-memory SQLite only."""
    now = [datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)]
    auth_system.clock = lambda: now[0]
    client = FakeOAuthClient({'good': {'id': 'g-77', 'email': 'g77@example.com', 'email_verified': True}})
    auth_system.oauth_profile = client

    issued = auth_system.oauth_start('google')
    assert issued['expires_in'] == 600
    cursor = auth_system.db.cursor()
    assert [r['state_hash'] for r in cursor.execute("SELECT state_hash FROM oauth_states")] == [_sha(issued['state'])]
    assert _sha(issued['state']) != _plain_sha256(issued['state'])  # spec d270fa3, 2026-11-10: keyed, not plain

    assert auth_system.oauth_callback('google', 'good', 'never-issued') == {'error': 'invalid_state'}
    assert auth_system.oauth_callback('github', 'good', issued['state']) == {'error': 'invalid_state'}  # spent too
    assert client.exchanged == []

    state = auth_system.oauth_start('google')['state']
    assert auth_system.oauth_callback('google', 'forged-code', state) == {'error': 'oauth_exchange_failed'}
    assert client.exchanged == [('google', 'forged-code')]
    assert cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0

    state = auth_system.oauth_start('google')['state']
    first = auth_system.oauth_callback('google', 'good', state)
    assert first['status'] == 'authenticated' and first['user']['email'] == 'g77@example.com'
    client.profiles['good'] = {'id': 'g-77', 'email': 'g77@example.com', 'email_verified': True}
    assert auth_system.oauth_callback('google', 'good', state) == {'error': 'invalid_state'}  # reused

    late = auth_system.oauth_start('google')['state']
    now[0] = now[0] + timedelta(minutes=10)
    assert auth_system.oauth_callback('google', 'good', late) == {'error': 'invalid_state'}
    fresh = auth_system.oauth_start('google')['state']
    now[0] = now[0] + timedelta(minutes=9, seconds=59)
    assert auth_system.oauth_callback('google', 'good', fresh)['user']['id'] == first['user']['id']


# AUTH-16
@pytest.mark.parametrize('key', [None, '', 'k' * 31, b'k' * 31])
def test_service_refuses_to_start_without_a_32_byte_secret_key(monkeypatch, key):
    """AuthSystem refuses to start (raises ValueError) when neither secret_key nor AUTH_SECRET_KEY gives a key,
    or the key is shorter than 32 bytes; a 32-byte key from AUTH_SECRET_KEY is accepted and keys the stored HMAC.
    In: pytest's monkeypatch, a missing or short key. Out: assertions. Why: spec d270fa3: keyed HMAC for stored
    secrets ("the service refuses to start without it"). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    Touches: the process environment (patched), in-memory SQLite only."""
    monkeypatch.delenv('AUTH_SECRET_KEY', raising=False)
    db_connection = sqlite3.connect(':memory:')
    with pytest.raises(ValueError):
        AuthSystem(db_connection, jwt_secret='test_secret', bcrypt_rounds=4, secret_key=key)
    if key is not None:
        monkeypatch.setenv('AUTH_SECRET_KEY', key if isinstance(key, str) else key.decode())
        with pytest.raises(ValueError):
            AuthSystem(db_connection, jwt_secret='test_secret', bcrypt_rounds=4)
    monkeypatch.setenv('AUTH_SECRET_KEY', TEST_SECRET_KEY)
    from_env = AuthSystem(db_connection, jwt_secret='test_secret', bcrypt_rounds=4)
    assert from_env._hash_secret('123456') == _sha('123456') != _plain_sha256('123456')
    db_connection.close()

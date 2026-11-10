import bcrypt
import pyotp
import jwt
import secrets
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional, Dict, Any
import hmac
import sqlite3
import time
import os

# OAuth state lifetime (auth spec, "Secrets at rest": single-use, expires in 10 minutes). Phase B.2, 2026-11-10,
# session_012zDydZCZ4AChqhEZ4oVtaP.
OAUTH_STATE_TTL = timedelta(minutes=10)


# Minimum length of the HMAC key for stored secrets (spec d270fa3: AUTH_SECRET_KEY, at least 32 bytes).
# 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
MIN_SECRET_KEY_BYTES = 32


def _load_secret_key(secret_key) -> bytes:
    """The HMAC key for stored secrets, as bytes: the secret_key argument if given, else the AUTH_SECRET_KEY
    environment variable. In: str, bytes or None. Out: the key bytes. Raises ValueError when there is no key or it
    is shorter than 32 bytes, so the service refuses to start without one. Why: spec d270fa3: keyed HMAC for
    stored secrets (a plain SHA-256 of a 6-digit code can be brute-forced from a leaked table; code scanning
    flagged it). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the process environment (read only)."""
    if secret_key is None:
        secret_key = os.environ.get("AUTH_SECRET_KEY")
    if isinstance(secret_key, str):
        secret_key = secret_key.encode("utf-8")
    if not secret_key or len(secret_key) < MIN_SECRET_KEY_BYTES:
        raise ValueError("AUTH_SECRET_KEY must be set and at least 32 bytes")
    return bytes(secret_key)


def _hmac_hex(key: bytes, value: str) -> str:
    """Lowercase hex HMAC-SHA256(key, value's UTF-8 bytes): the only form in which refresh tokens, verification
    codes and OAuth state values are stored. In: the key, the secret. Out: 64 hex chars. Why: spec d270fa3: keyed
    HMAC for stored secrets (replaces the plain SHA-256 of Phase B.2). 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def _unconfigured_oauth_client(provider: str, code: str) -> Dict[str, Any]:
    """Default OAuth provider client: refuses, so no account is ever made up. A real client exchanges the code at
    the provider's token endpoint and returns the verified profile {id, email, email_verified}.
    In: provider, code. Out: never returns; raises RuntimeError. Why: the auth spec (Phase B.2, 2026-11-10): the
    callback exchanges the code through an injected provider client; the old default invented a new user for any
    code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    raise RuntimeError("no OAuth provider client configured")


class AuthSystem:
    def __init__(self, db_connection: sqlite3.Connection, jwt_secret: Optional[str] = None,
                 bcrypt_rounds: int = 12, access_token_expires_minutes: int = 15,
                 refresh_token_expires_days: int = 7, email_verification_expires_hours: int = 24,
                 mfa_challenge_expires_minutes: int = 5, signup_rate_limit: int = 24,
                 signup_rate_limit_max: int = 5, login_rate_limit: int = 15,
                 login_rate_limit_max: int = 5,
                 oauth_profile: Optional[Callable[[str, str], Dict[str, Any]]] = None,
                 email_sender: Optional[Callable[[str, str], None]] = None,
                 clock: Optional[Callable[[], datetime]] = None,
                 secret_key: Optional[Any] = None):
        """Set up the auth system on one SQLite connection.

        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets. secret_key
        (str or bytes, else the AUTH_SECRET_KEY environment variable) keys the HMAC-SHA256 under which refresh
        tokens, verification codes and OAuth state are stored. Raises ValueError, before touching the database,
        when it is missing or shorter than 32 bytes: the service refuses to start without it.

        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] New optional email_sender(email, code): signup sends the
        verification code through it (AUTH-01 "email sent"; docs/specs/README.md: email goes through an
        injectable sender, tests pass a fake). The default sends nothing; wire a real mailer in production.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2: oauth_profile(provider, code) is the injected
        OAuth provider client that exchanges the one-time code for the verified profile {id, email,
        email_verified}; the default now refuses (it invented a user for any code). clock() returns the aware UTC
        now (default the wall clock), so state expiry can be tested.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.3: email_code_max_attempts = 5 wrong verify_email
        codes invalidate the current code (auth_system.md flow 2, "Attempts").
        Touches: SQLite (creates tables); network only through the injected sender/oauth_profile."""
        self._secret_key = _load_secret_key(secret_key)
        self.email_sender = email_sender or (lambda email, code: None)
        self.db = db_connection
        self.clock = clock
        # Exchanges a provider's one-time code for the user's verified profile: pass a real provider client.
        self.oauth_profile = oauth_profile or _unconfigured_oauth_client
        self.mfa_max_attempts = 5
        self.email_code_max_attempts = 5
        # AUTH-18 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): resend_verification limits and the resent code's life.
        self.resend_max_per_hour = 3
        self.resend_code_expires_minutes = 10
        self.jwt_secret = jwt_secret or secrets.token_urlsafe(32)
        self.bcrypt_rounds = bcrypt_rounds
        self.access_token_expires_minutes = access_token_expires_minutes
        self.refresh_token_expires_days = refresh_token_expires_days
        self.email_verification_expires_hours = email_verification_expires_hours
        self.mfa_challenge_expires_minutes = mfa_challenge_expires_minutes
        self.signup_rate_limit = signup_rate_limit * 3600  # convert hours to seconds
        self.signup_rate_limit_max = signup_rate_limit_max
        self.login_rate_limit = login_rate_limit * 60  # convert minutes to seconds
        self.login_rate_limit_max = login_rate_limit_max
        self._ensure_tables()

    def _now(self) -> datetime:
        """Return current UTC time as timezone-aware datetime: the injected clock's, else the wall clock's.
        Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2: injectable for the OAuth state expiry
        test). Touches nothing."""
        return self.clock() if self.clock is not None else datetime.now(timezone.utc)

    @staticmethod
    def _parse_time(value: str) -> datetime:
        """A stored time as an aware UTC datetime. Rows written before 2026-11-05 have no offset, and comparing them
        with an aware time raised TypeError (2026-11-08, session f3daac6e, from review)."""
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    def _now_iso(self) -> str:
        """Return current UTC time as ISO format string."""
        return self._now().isoformat()

    def _hash_secret(self, value: str) -> str:
        """The stored form of a refresh token, verification code or OAuth state: lowercase hex
        HMAC-SHA256(secret_key, value). In: the secret. Out: 64 hex chars. Why: spec d270fa3: keyed HMAC for
        stored secrets. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        return _hmac_hex(self._secret_key, value)

    def _ensure_tables(self):
        """Create the tables. [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2 (AUTH-16, "Secrets at
        rest"): sessions keep refresh_token_hash and verification_codes keep code_hash, never the secret, and
        oauth_states holds the HMAC-SHA256 of each issued OAuth state. A sessions or verification_codes table from
        before this change holds plain-text secrets; it is dropped and recreated, which signs those sessions out
        and voids those codes (they cannot be hashed in place without keeping the plain text readable).
        In/Out: none. Touches: SQLite (DDL).
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: each stored or compared secret is now HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256)."""
        cursor = self.db.cursor()
        for table, plain_column in (("sessions", "refresh_token"), ("verification_codes", "code")):
            if plain_column in {row[1] for row in cursor.execute(f"PRAGMA table_info({table})")}:
                cursor.execute(f"DROP TABLE {table}")
        cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT,
            tier TEXT NOT NULL DEFAULT 'free',
            status TEXT NOT NULL DEFAULT 'unverified',
            email_verified_at TEXT,
            mfa_secret TEXT,
            mfa_enabled BOOLEAN DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            refresh_token_hash TEXT UNIQUE NOT NULL,  -- HMAC-SHA256 hex of the refresh token (AUTH-16)
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            ip TEXT,
            device_id TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS verification_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,  -- HMAC-SHA256 hex of the emailed / expected code (AUTH-16)
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            type TEXT NOT NULL CHECK (type IN ('email', 'mfa')),
            attempts INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS oauth_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            provider TEXT NOT NULL,
            provider_user_id TEXT NOT NULL,
            access_token TEXT,
            refresh_token TEXT,
            expires_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(provider, provider_user_id)
        );
        CREATE TABLE IF NOT EXISTS oauth_states (
            state_hash TEXT PRIMARY KEY,  -- HMAC-SHA256 hex of the state sent to the provider; single-use
            provider TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor_id INTEGER,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id INTEGER,
            old_value TEXT,
            new_value TEXT
        );
        CREATE TABLE IF NOT EXISTS why_chain_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            flow TEXT NOT NULL,
            decision_points TEXT NOT NULL
        );
        -- AUTH-18 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): one row per accepted resend_verification request,
        -- for every email asked about (known or not), so the 3-per-hour limit answers the same for any address.
        CREATE TABLE IF NOT EXISTS verification_resends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            requested_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_verification_resends_email ON verification_resends(email, requested_at);
        CREATE TABLE IF NOT EXISTS rate_limit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            identifier TEXT NOT NULL,
            type TEXT NOT NULL CHECK (type IN ('signup', 'login')),
            timestamp TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token_hash ON sessions(refresh_token_hash);
        CREATE INDEX IF NOT EXISTS idx_verification_codes_user_id_type ON verification_codes(user_id, type);
        CREATE INDEX IF NOT EXISTS idx_oauth_accounts_provider_provider_user_id ON oauth_accounts(provider, provider_user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_why_chain_log_timestamp ON why_chain_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_rate_limit_log_ip_identifier_type_timestamp ON rate_limit_log(ip, identifier, type, timestamp);
        """)
        # Tables made before 2026-11-08 lack the MFA attempt count; add it so a wrong code still counts.
        columns = {row[1] for row in cursor.execute("PRAGMA table_info(verification_codes)")}
        if "attempts" not in columns:
            cursor.execute("ALTER TABLE verification_codes ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")
        self.db.commit()

    def _create_session(self, cursor: sqlite3.Cursor, user_id: int, ip: Optional[str] = None,
                        device_id: Optional[str] = None) -> tuple:
        """Insert a session for user_id and return (session_id, refresh_token). The refresh token is 32 random
        bytes (URL-safe); only its HMAC-SHA256 is stored, so reading the sessions table hands out nothing usable.
        The caller commits. In: an open cursor, the user id, the request's ip and device id. Out: (session id,
        the plain refresh token, which the caller returns to the client once). Why: AUTH-16 (Phase B.2,
        2026-11-10): every flow that creates a session returns its refresh_token, and sessions stored it in plain
        text. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite (sessions).
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: each stored or compared secret is now HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256)."""
        refresh_token = secrets.token_urlsafe(32)
        cursor.execute(
            """INSERT INTO sessions (user_id, refresh_token_hash, created_at, expires_at, ip, device_id)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user_id, self._hash_secret(refresh_token), self._now_iso(),
             (self._now() + timedelta(days=self.refresh_token_expires_days)).isoformat(), ip, device_id)
        )
        return cursor.lastrowid, refresh_token

    def _log_why_chain(self, flow: str, decision_points: list):
        cursor = self.db.cursor()
        cursor.execute(
            "INSERT INTO why_chain_log (timestamp, flow, decision_points) VALUES (?, ?, ?)",
            (self._now_iso(), flow, json.dumps(decision_points))
        )
        self.db.commit()

    def _log_audit_log(self, action: str, actor_id: Optional[int] = None,
                       resource_type: Optional[str] = None, resource_id: Optional[int] = None,
                       old_value: Optional[Dict] = None, new_value: Optional[Dict] = None):
        cursor = self.db.cursor()
        cursor.execute(
            """INSERT INTO audit_log
               (timestamp, actor_id, action, resource_type, resource_id, old_value, new_value)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (self._now_iso(), actor_id, action, resource_type, resource_id,
             json.dumps(old_value) if old_value else None,
             json.dumps(new_value) if new_value else None)
        )
        self.db.commit()

    def _hash_password(self, password: str) -> str:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=self.bcrypt_rounds)).decode('utf-8')

    def _verify_password(self, password: str, password_hash: str) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

    def _generate_verification_code(self, length: int = 6) -> str:
        return ''.join(secrets.choice('0123456789') for _ in range(length))

    def _generate_token(self, user_id: int, tier: str, token_type: str = 'access') -> str:
        now = self._now()
        if token_type == 'access':
            expires = now + timedelta(minutes=self.access_token_expires_minutes)
        else:
            expires = now + timedelta(days=self.refresh_token_expires_days)
        payload = {
            'user_id': user_id,
            'tier': tier,
            'exp': expires.timestamp(),
            'iat': now.timestamp(),
            'type': token_type
        }
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')

    def _verify_token(self, token: str, token_type: str = 'access') -> Dict:
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            if payload.get('type') != token_type:
                raise jwt.InvalidTokenError
            return payload
        except jwt.ExpiredSignatureError:
            raise jwt.ExpiredSignatureError
        except jwt.InvalidTokenError:
            raise jwt.InvalidTokenError

    def _is_rate_limited(self, ip: str, identifier: str, type_: str) -> bool:
        cutoff = self._now() - timedelta(seconds=(
            self.signup_rate_limit if type_ == 'signup' else self.login_rate_limit))
        cursor = self.db.cursor()
        cursor.execute(
            """SELECT COUNT(*) FROM rate_limit_log
               WHERE ip = ? AND identifier = ? AND type = ? AND timestamp >= ?""",
            (ip, identifier, type_, cutoff.isoformat())
        )
        count = cursor.fetchone()[0]
        return count >= (self.signup_rate_limit_max if type_ == 'signup' else self.login_rate_limit_max)

    def _log_rate_limit_attempt(self, ip: str, identifier: str, type_: str):
        cursor = self.db.cursor()
        cursor.execute(
            "INSERT INTO rate_limit_log (ip, identifier, type, timestamp) VALUES (?, ?, ?, ?)",
            (ip, identifier, type_, self._now_iso())
        )
        self.db.commit()

    # Bundled common passwords (lower-case). Only entries of 15+ characters can ever be the deciding check,
    # because too_short runs first; the short ones are kept so the list reads as the familiar one.
    PASSWORD_BLOCKLIST = frozenset([
        "password", "123456", "12345678", "qwerty", "abc123", "monkey", "letmein", "dragon", "baseball",
        "iloveyou", "passwordpassword", "123456789012345", "1234567890123456", "qwertyuiopasdfgh",
        "qwertyuiopasdfghjkl", "iloveyouiloveyou", "letmeinletmeinletmein", "aaaaaaaaaaaaaaa",
    ])
    SERVICE_NAME = "SaasAuth"

    def _password_rejection(self, password: str, email: str, name: str) -> Optional[str]:
        """The reason a signup password is rejected, or None if it is accepted.

        In: the password, and the user's email and name. Out: "too_short" (< 15 chars), "too_long" (> 64),
        "blocklisted" (in the bundled list, or equal to the email, the name or the service name, ignoring
        case), or None. Checks run in that order and the first failure wins.
        Why: AUTH-03 as amended 2026-11-10 (NIST SP 800-63B rules in docs/specs/auth_system.md).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        if len(password) < 15:
            return "too_short"
        if len(password) > 64:
            return "too_long"
        lowered = password.lower()
        if (lowered in self.PASSWORD_BLOCKLIST or lowered == email.lower()
                or lowered == (name or "").lower() or lowered == self.SERVICE_NAME.lower()):
            return "blocklisted"
        return None

    def signup(self, email: str, password: str, name: str, ip: str) -> Dict[str, Any]:
        """Flow 1: create an unverified user and send the verification code.

        In: email, password, name, the server-observed IP. Out: {status: "pending_verification", email, message} or
        {error: "too_many_signups_from_ip" | "email_already_exists" | "password_rejected", reason}.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Password checks run too_short, too_long, blocklisted (AUTH-03 as amended) and the code is sent
        through the injected email_sender (AUTH-01). [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2
        (AUTH-16): only the code's HMAC-SHA256 is stored. Touches: SQLite, the email sender.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: each stored or compared secret is now HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256)."""
        decision_points = []
        # rate_limit_ip_24h
        if self._is_rate_limited(ip, ip, 'signup'):
            self._log_why_chain("signup", decision_points + ["rate_limit_ip_24h:failed"])
            return {"error": "too_many_signups_from_ip"}
        decision_points.append("rate_limit_ip_24h")
        self._log_rate_limit_attempt(ip, ip, 'signup')
        # email_unique
        cursor = self.db.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            self._log_why_chain("signup", decision_points + ["email_unique:failed"])
            return {"error": "email_already_exists"}
        decision_points.append("email_unique")
        # password_strength -- [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] AUTH-03 as amended: the checks run
        # too_short, too_long, blocklisted, and the first failure wins ("password123" is too_short, not
        # blocklisted). The blocklist used to run first. Touches nothing but this request.
        rejection = self._password_rejection(password, email, name)
        if rejection is not None:
            self._log_why_chain("signup", decision_points + ["password_strength:failed"])
            return {"error": "password_rejected", "reason": rejection}
        decision_points.append("password_strength")
        # All gates passed
        password_hash = self._hash_password(password)
        now_iso = self._now_iso()
        cursor.execute(
            """INSERT INTO users (email, password_hash, tier, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (email, password_hash, 'free', 'unverified', now_iso, now_iso)
        )
        user_id = cursor.lastrowid
        # Send verification email (mock)
        code = self._generate_verification_code()
        cursor.execute(
            """INSERT INTO verification_codes (user_id, code_hash, created_at, expires_at, type)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, self._hash_secret(code), now_iso,
             (self._now() + timedelta(hours=self.email_verification_expires_hours)).isoformat(), 'email')
        )
        self.db.commit()
        # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] AUTH-01: the verification email goes out through the
        # injected sender, after the user and code are committed.
        self.email_sender(email, code)
        self._log_why_chain("signup", decision_points)
        self._log_audit_log("user_created", actor_id=user_id, resource_type="user", resource_id=user_id,
                           old_value=None, new_value={"email": email, "status": "unverified"})
        return {"status": "pending_verification", "email": email, "message": "check email"}

    def verify_email(self, email: str, code_or_token: str) -> Dict[str, Any]:
        """Flow 2: mark the user verified when the emailed code matches and has not expired.

        In: email, the code. Out: {status: "verified", user_id, message} or {error: "invalid_email" |
        "email_already_verified" | "code_expired"}. [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] The code is now
        compared in constant time in Python (docs/specs/README.md); it was matched with "code = ?" in SQL.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2 (AUTH-16): the supplied code's HMAC-SHA256 is
        compared with the stored code_hash. Touches: SQLite (users, verification_codes, audit_log).
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: each stored or compared secret is now HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256).
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.3 (auth_system.md flow 2, "Attempts"): each wrong code
        adds one to the attempts of the user's current (unexpired) email codes; a code with 5 wrong attempts is
        invalidated, and every further try, the right code included, answers {error: "code_invalid"} until a new
        code is stored (a 6-digit code must not be guessable by retrying).
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.4 (af92d76, AUTH-17): a wrong code now answers
        {error: "code_invalid"} (it answered code_expired); only a code that matches a stored code whose expires_at
        has passed answers {error: "code_expired"}, and that try does not count as wrong. Both are the spec's 400
        answers. Touches: SQLite (users, verification_codes, audit_log).
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Review finding 4525101305 (CWE-367): the attempts were read,
        the code compared, and the wrong try written after, so concurrent requests that all read attempts = 4 could
        each compare a guess. Now every try against a current code is counted FIRST, in one conditional write
        (UPDATE ... SET attempts = attempts + 1 WHERE id = ? AND attempts < 5 AND expires_at > now), committed, and the
        code is compared only when that write changed one row, as Go, JavaScript and TypeScript do. The right code
        on a counted 5th try still verifies; after 5 counted tries every try is code_invalid. A code matching only
        an EXPIRED row is still code_expired and is not counted (an expired code cannot verify, so it is compared
        before counting). _log_why_chain and _log_audit_log commit, so they are called only when no transaction of
        this flow is open: they cannot commit any of it early."""
        decision_points = []
        cursor = self.db.cursor()
        cursor.execute("SELECT id, email_verified_at FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        if not user:
            self._log_why_chain("verify_email", decision_points + ["user_exists:failed"])
            return {"error": "invalid_email"}
        user_id, email_verified_at = user
        if email_verified_at is not None:
            self._log_why_chain("verify_email", decision_points + ["user_unverified:failed"])
            return {"error": "email_already_verified"}
        decision_points.append("user_unverified")
        now_iso = self._now_iso()
        cursor.execute(
            """SELECT id, code_hash, attempts FROM verification_codes
               WHERE user_id = ? AND type = 'email' AND expires_at > ? ORDER BY id""",
            (user_id, now_iso)
        )
        current = cursor.fetchall()
        live = [row for row in current if (row[2] or 0) < self.email_code_max_attempts]
        supplied = self._hash_secret(code_or_token if isinstance(code_or_token, str) else "").encode("utf-8")
        if current and not live:
            # Every current code is spent (5 counted tries): code_invalid until a new code is sent; nothing compared.
            self._log_why_chain("verify_email", [*decision_points, "code_valid:failed"])
            return {"error": "code_invalid"}
        # Phase B.4 (af92d76): the right code past its expiry is code_expired, and that try is not counted. Only
        # EXPIRED rows are compared here; an expired code can never verify, so this compare gives a guesser nothing.
        cursor.execute(
            """SELECT code_hash FROM verification_codes
               WHERE user_id = ? AND type = 'email' AND expires_at <= ?""",
            (user_id, now_iso)
        )
        if any(hmac.compare_digest(str(row[0]).encode("utf-8"), supplied) for row in cursor.fetchall()):
            self._log_why_chain("verify_email", [*decision_points, "code_valid:failed"])
            return {"error": "code_expired"}
        # Review finding 4525101305 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): COUNT FIRST, in one conditional
        # write per code, and compare only a code whose count succeeded (one row changed). The count is committed
        # before the compare, so concurrent requests on other connections can never compare more than 5 tries
        # between them; the read above is only a pre-filter, the write decides.
        code_record = None
        for candidate in live:
            cursor.execute(
                """UPDATE verification_codes SET attempts = attempts + 1
                   WHERE id = ? AND attempts < ? AND expires_at > ?""",
                (candidate[0], self.email_code_max_attempts, now_iso)
            )
            counted = cursor.rowcount == 1
            self.db.commit()
            if counted and hmac.compare_digest(str(candidate[1]).encode("utf-8"), supplied):
                code_record = candidate
                break
        if not code_record:
            self._log_why_chain("verify_email", [*decision_points, "code_valid:failed"])
            return {"error": "code_invalid"}
        decision_points.append("code_valid")
        cursor.execute("UPDATE users SET email_verified_at = ?, status = 'verified', updated_at = ? WHERE id = ?",
                       (now_iso, now_iso, user_id))
        cursor.execute("DELETE FROM verification_codes WHERE id = ?", (code_record[0],))
        self.db.commit()
        # The why chain and the audit row are written only now, with no transaction open: their own commit can
        # never commit part of this flow early (review finding 4525101305).
        self._log_why_chain("verify_email", decision_points)
        self._log_audit_log("email_verified", actor_id=user_id, resource_type="user", resource_id=user_id,
                           old_value={"email_verified_at": None, "status": "unverified"}, 
                           new_value={"email_verified_at": now_iso, "status": "verified"})
        return {"status": "verified", "user_id": user_id, "message": "ready to login"}

    def resend_verification(self, email: str) -> Dict[str, Any]:
        """Flow 2b: replace an unverified user's email code and email the new one.

        In: the email. Out: {status: "sent"} (the spec's 202) or {error: "too_many_requests"} (the spec's 429).
        For an unverified user it deletes the user's email codes, stores a new 6-digit code (attempts 0, its
        HMAC-SHA256 under AUTH_SECRET_KEY, 10-minute expiry) and sends it through the injected email_sender. At most 3
        requests per email per hour are accepted: the 4th within the hour is too_many_requests and sends nothing. An
        unknown or already verified email gets the same {status: "sent"} and nothing is sent, so the answer never says
        whether an account exists; those requests count toward the limit too, so the 429 says nothing either. The
        count and the new request's row are one conditional INSERT, so concurrent requests cannot pass the limit.
        Why: AUTH-18 (auth_system.md flow 2b, commit 0eb5a4e): after 5 wrong codes (AUTH-17) nothing could issue a new
        code, so anyone who knew an email could block its verification. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches: SQLite (verification_resends, users read, verification_codes, audit_log, why_chain_log), the email
        sender (network in production)."""
        if not isinstance(email, str):
            email = ""
        now = self._now()
        cursor = self.db.cursor()
        cursor.execute(
            """INSERT INTO verification_resends (email, requested_at)
               SELECT ?, ? WHERE (SELECT COUNT(*) FROM verification_resends
                                  WHERE email = ? AND requested_at > ?) < ?""",
            (email, now.isoformat(), email, (now - timedelta(hours=1)).isoformat(), self.resend_max_per_hour)
        )
        accepted = cursor.rowcount == 1
        self.db.commit()
        if not accepted:
            self._log_why_chain("resend_verification", ["rate_limit_email_1h:failed"])
            return {"error": "too_many_requests"}
        cursor.execute("SELECT id, email_verified_at FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        if not user or user[1] is not None:
            # Unknown or already verified: the same answer as a real resend, and no email (no account enumeration).
            self._log_why_chain("resend_verification", ["rate_limit_email_1h", "user_unverified:failed"])
            return {"status": "sent"}
        user_id = user[0]
        code = self._generate_verification_code()
        cursor.execute("DELETE FROM verification_codes WHERE user_id = ? AND type = 'email'", (user_id,))
        cursor.execute(
            """INSERT INTO verification_codes (user_id, code_hash, created_at, expires_at, type, attempts)
               VALUES (?, ?, ?, ?, 'email', 0)""",
            (user_id, self._hash_secret(code), now.isoformat(),
             (now + timedelta(minutes=self.resend_code_expires_minutes)).isoformat())
        )
        self.db.commit()
        self.email_sender(email, code)
        self._log_why_chain("resend_verification", ["rate_limit_email_1h", "user_unverified"])
        self._log_audit_log("verification_resent", actor_id=user_id, resource_type="user", resource_id=user_id)
        return {"status": "sent"}

    def login(self, email: str, password: str, device_id: str, ip: str) -> Dict[str, Any]:
        """Flow 3: sign in with email and password; an MFA user gets a challenge instead of a session.

        In: email, password, device id, the server-observed IP. Out: {status: "authenticated", session_id,
        token, refresh_token, expires_in, user: {id, email, tier}} or {status: "mfa_required", challenge_id} or
        {error: "too_many_failed_logins" | "invalid_credentials" | "unverified_email"}.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2 bug fix (AUTH-16): login now returns the
        session's refresh_token (it returned none, so token_refresh could never be used) and stores only its
        HMAC-SHA256; the MFA challenge stores only the expected code's HMAC-SHA256.
        Touches: SQLite (users read; sessions, verification_codes, rate_limit_log, audit_log, why_chain_log).
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: each stored or compared secret is now HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256)."""
        decision_points = []
        # rate_limit (5 failed per 15min per ip/user)
        if self._is_rate_limited(ip, email, 'login'):
            self._log_why_chain("login", decision_points + ["rate_limit:failed"])
            return {"error": "too_many_failed_logins"}
        decision_points.append("rate_limit")
        # user_exists
        cursor = self.db.cursor()
        cursor.execute("SELECT id, password_hash, status, email_verified_at, mfa_secret, mfa_enabled, tier FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        if not user:
            self._log_why_chain("login", decision_points + ["user_exists:failed"])
            self._log_rate_limit_attempt(ip, email, 'login')
            return {"error": "invalid_credentials"}
        user_id, password_hash, status, email_verified_at, mfa_secret, mfa_enabled, tier = user
        decision_points.append("user_exists")
        # password_correct
        if not self._verify_password(password, password_hash):
            self._log_why_chain("login", decision_points + ["password_correct:failed"])
            self._log_rate_limit_attempt(ip, email, 'login')
            return {"error": "invalid_credentials"}
        decision_points.append("password_correct")
        # user_verified
        if status != 'verified' or email_verified_at is None:
            self._log_why_chain("login", decision_points + ["user_exists_and_verified:failed"])
            return {"error": "unverified_email"}
        # mfa_enabled_check
        if mfa_enabled:
            decision_points.append("mfa_gate:enabled")
            # Generate MFA challenge
            totp = pyotp.TOTP(mfa_secret)
            current_code = totp.now()
            now_iso = self._now_iso()
            cursor.execute(
                """INSERT INTO verification_codes (user_id, code_hash, created_at, expires_at, type)
                   VALUES (?, ?, ?, ?, ?)""",
                (user_id, self._hash_secret(current_code), now_iso,
                 (self._now() + timedelta(minutes=self.mfa_challenge_expires_minutes)).isoformat(), 'mfa')
            )
            challenge_id = cursor.lastrowid
            self.db.commit()
            self._log_why_chain("login", decision_points)
            self._log_audit_log("mfa_challenge_initiated", actor_id=user_id, resource_type="user", resource_id=user_id,
                               old_value=None, new_value={"challenge_id": challenge_id})
            return {"status": "mfa_required", "challenge_id": challenge_id}
        decision_points.append("mfa_gate:disabled")
        # rate_limit (for failed attempts, but we passed so we clear? spec doesn't say to clear on success, but we'll not log failed attempt for this success)
        # We'll not log this attempt as failed since we passed
        # Create session
        access_token = self._generate_token(user_id, tier, 'access')
        session_id, refresh_token = self._create_session(cursor, user_id, ip, device_id)
        self.db.commit()
        self._log_why_chain("login", decision_points)
        self._log_audit_log("session_created", actor_id=user_id, resource_type="session", resource_id=session_id,
                           old_value=None, new_value={"user_id": user_id, "ip": ip, "device_id": device_id})
        return {
            "status": "authenticated",
            "session_id": session_id,
            "token": access_token,
            "refresh_token": refresh_token,
            "expires_in": self.access_token_expires_minutes * 60,
            "user": {"id": user_id, "email": email, "tier": tier}
        }

    def oauth_start(self, provider: str) -> Dict[str, Any]:
        """Begin an OAuth sign-in: issue the state value to send to the provider (and to keep in the visitor's
        session cookie, which the caller compares with the callback's state before calling oauth_callback).

        In: the provider name. Out: {state, expires_in: 600}. The state is 32 random bytes (URL-safe); only its
        HMAC-SHA256 is stored, with the provider and an expiry 10 minutes ahead. Why: the auth spec's "Secrets at
        rest" line (Phase B.2, 2026-11-10): OAuth state is single-use and expires in 10 minutes; nothing issued
        or checked it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite (oauth_states).
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: each stored or compared secret is now HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256)."""
        state = secrets.token_urlsafe(32)
        now = self._now()
        cursor = self.db.cursor()
        cursor.execute("DELETE FROM oauth_states WHERE expires_at <= ?", (now.isoformat(),))
        cursor.execute("INSERT INTO oauth_states (state_hash, provider, created_at, expires_at) VALUES (?, ?, ?, ?)",
                       (self._hash_secret(state), provider, now.isoformat(), (now + OAUTH_STATE_TTL).isoformat()))
        self.db.commit()
        return {"state": state, "expires_in": int(OAUTH_STATE_TTL.total_seconds())}

    def _consume_oauth_state(self, provider: str, state: Any) -> bool:
        """Spend an issued OAuth state: True only for a state oauth_start() issued for this provider, under 10
        minutes old and not used before; it is deleted either way, so it works once. The hash is compared in
        constant time, and only the call whose DELETE removes the row wins (two concurrent callbacks cannot both
        pass). In: provider, the state from the callback. Out: bool. Why: auth spec "Secrets at rest" (Phase B.2,
        2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite (oauth_states).
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: each stored or compared secret is now HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256)."""
        if not isinstance(state, str) or not state:
            return False
        supplied = self._hash_secret(state)
        cursor = self.db.cursor()
        row = cursor.execute("SELECT state_hash, provider, expires_at FROM oauth_states WHERE state_hash = ?",
                             (supplied,)).fetchone()
        if row is None or not hmac.compare_digest(str(row[0]).encode("ascii"), supplied.encode("ascii")):
            return False
        cursor.execute("DELETE FROM oauth_states WHERE state_hash = ?", (supplied,))
        won = cursor.rowcount == 1
        self.db.commit()
        return won and row[1] == provider and self._parse_time(row[2]) > self._now()

    def oauth_callback(self, provider: str, code: str, state: str) -> Dict[str, Any]:
        """Flow 4: finish an OAuth sign-in. Out: {status: "authenticated", session_id, token, refresh_token,
        user} or {error: "invalid_state" | "oauth_exchange_failed" | "email_not_verified"}.

        In: the provider, the provider's one-time code and the state from the redirect. Gates, in order: the
        state is one oauth_start() issued for this provider, unexpired (10 min) and unused (it is spent here);
        the code is exchanged through the injected provider client (oauth_profile) for the verified profile,
        and the code itself never identifies anyone; the provider vouches for the email. Then the account found
        by provider id, else by email, is linked, or a verified user is created.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2 (AUTH-16, "Secrets at rest"): state is now
        checked server-side and single-use, a failed exchange is refused, and the refresh_token is returned
        (stored only as its HMAC-SHA256). Touches: SQLite (oauth_states, users, oauth_accounts, sessions, audit_log,
        why_chain_log); network through the provider client.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: each stored or compared secret is now HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256)."""
        decision_points = []
        # state_valid: the caller also matches state to the visitor's session cookie. state passes through the
        # visitor's browser, so nothing inside it is ever trusted: the e-mail comes only from the provider.
        # 2026-11-05, session f3daac6e: an earlier repair read the e-mail from state, which let anyone log in as anyone.
        if not self._consume_oauth_state(provider, state):
            self._log_why_chain("oauth_callback", decision_points + ["state_valid:failed"])
            return {"error": "invalid_state"}
        decision_points.append("state_valid")
        try:
            profile = self.oauth_profile(provider, code)
        except Exception:
            profile = None
        if not isinstance(profile, dict) or not profile.get("id") or not profile.get("email"):
            self._log_why_chain("oauth_callback", decision_points + ["code_exchange:failed"])
            return {"error": "oauth_exchange_failed"}
        # The provider must vouch for the address, or anyone could sign in by adding someone else's e-mail to their
        # account there (2026-11-08, session f3daac6e, from review).
        if not profile.get("email_verified"):
            self._log_why_chain("oauth_callback", decision_points + ["email_verified:failed"])
            return {"error": "email_not_verified"}
        email = profile["email"]
        provider_user_id = str(profile["id"])   # the provider's stable id for this person, not a random value
        decision_points.append("email_verified")
        cursor = self.db.cursor()
        # A returning user is found by the provider's id first: their e-mail at the provider may have changed (2026-11-08, session f3daac6e, from review of PR 17).
        cursor.execute("SELECT user_id FROM oauth_accounts WHERE provider = ? AND provider_user_id = ?",
                       (provider, provider_user_id))
        linked = cursor.fetchone()
        if linked:
            cursor.execute("SELECT id FROM users WHERE id = ?", (linked[0],))
        else:
            cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        now_iso = self._now_iso()
        if user:
            user_id = user[0]
            # Link OAuth to existing user
            cursor.execute(
                """INSERT OR IGNORE INTO oauth_accounts (user_id, provider, provider_user_id, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (user_id, provider, provider_user_id, now_iso, now_iso)
            )
            # If user is not verified, we don't change status? Spec says existing user -> link oauth provider to account
            # We'll assume the user is already verified (since OAuth email is verified)
            # Generate tokens
            cursor.execute("SELECT tier FROM users WHERE id = ?", (user_id,))
            tier = cursor.fetchone()[0]
            access_token = self._generate_token(user_id, tier, 'access')
            session_id, refresh_token = self._create_session(cursor, user_id)
            self.db.commit()
            self._log_why_chain("oauth_callback", decision_points)
            self._log_audit_log("oauth_login", actor_id=user_id, resource_type="user", resource_id=user_id,
                               old_value=None, new_value={"provider": provider, "session_id": session_id})
            return {
                "status": "authenticated",
                "session_id": session_id,
                "token": access_token,
                "refresh_token": refresh_token,
                "user": {"id": user_id, "email": email, "tier": tier}
            }
        else:
            # New user
            cursor.execute(
                """INSERT INTO users (email, password_hash, tier, status, email_verified_at, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (email, None, 'free', 'verified', now_iso, now_iso, now_iso)
            )
            user_id = cursor.lastrowid
            cursor.execute(
                """INSERT INTO oauth_accounts (user_id, provider, provider_user_id, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (user_id, provider, provider_user_id, now_iso, now_iso)
            )
            # Generate tokens
            access_token = self._generate_token(user_id, 'free', 'access')
            session_id, refresh_token = self._create_session(cursor, user_id)
            self.db.commit()
            self._log_why_chain("oauth_callback", decision_points)
            self._log_audit_log("oauth_login", actor_id=user_id, resource_type="user", resource_id=user_id,
                               old_value=None, new_value={"provider": provider, "session_id": session_id, "new_user": True})
            return {
                "status": "authenticated",
                "session_id": session_id,
                "token": access_token,
                "refresh_token": refresh_token,
                "user": {"id": user_id, "email": email, "tier": "free"}
            }

    def mfa_challenge(self, challenge_id: int, code: str) -> Dict[str, Any]:
        """Flow 5: answer the MFA challenge login issued. Out: {status: "authenticated", session_id, token,
        refresh_token, user} or {error: "invalid_challenge" | "challenge_expired" | "invalid_code"}.

        In: the challenge id and the code the user typed. The code's HMAC-SHA256 is compared in constant time with
        the challenge's code_hash; wrong codes count and the challenge is deleted after mfa_max_attempts.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2 (AUTH-16): the challenge stores only the code's
        hash, and the new session's refresh_token is returned (stored only as its HMAC-SHA256).
        Touches: SQLite (verification_codes, users, sessions, audit_log, why_chain_log).
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: each stored or compared secret is now HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256)."""
        decision_points = []
        cursor = self.db.cursor()
        cursor.execute(
            """SELECT user_id, code_hash, expires_at FROM verification_codes
               WHERE id = ? AND type = 'mfa'""",
            (challenge_id,)
        )
        challenge = cursor.fetchone()
        if not challenge:
            self._log_why_chain("mfa_challenge", decision_points + ["challenge_exists_and_valid:failed"])
            return {"error": "invalid_challenge"}
        user_id, stored_code, expires_at = challenge
        if self._parse_time(expires_at) < self._now():
            self._log_why_chain("mfa_challenge", decision_points + ["challenge_exists_and_valid:failed"])
            return {"error": "challenge_expired"}
        decision_points.append("challenge_valid")
        # Bytes, not str: compare_digest raises TypeError on non-ASCII text such as full-width digits (from review).
        if not hmac.compare_digest(self._hash_secret(str(code)).encode("ascii"), str(stored_code).encode("utf-8")):
            # Each wrong code counts; after mfa_max_attempts the challenge is gone and the user signs in again, so a
            # six digit code cannot be guessed (2026-11-08, session f3daac6e, from review).
            cursor.execute("UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ?", (challenge_id,))
            cursor.execute("DELETE FROM verification_codes WHERE id = ? AND attempts >= ?",
                           (challenge_id, self.mfa_max_attempts))
            self.db.commit()
            self._log_why_chain("mfa_challenge", decision_points + ["code_correct:failed"])
            return {"error": "invalid_code"}
        decision_points.append("code_correct")
        # Use the challenge up. Only the call that deletes it may sign in, so two at once cannot both get a session.
        cursor.execute("DELETE FROM verification_codes WHERE id = ?", (challenge_id,))
        if cursor.rowcount != 1:
            self._log_why_chain("mfa_challenge", decision_points + ["challenge_consumed:failed"])
            return {"error": "invalid_challenge"}
        # Create session
        cursor.execute("SELECT tier FROM users WHERE id = ?", (user_id,))
        tier = cursor.fetchone()[0]
        access_token = self._generate_token(user_id, tier, 'access')
        session_id, refresh_token = self._create_session(cursor, user_id)
        self.db.commit()
        self._log_why_chain("mfa_challenge", decision_points)
        self._log_audit_log("mfa_verified", actor_id=user_id, resource_type="user", resource_id=user_id,
                           old_value=None, new_value={"challenge_id": challenge_id})
        # Fetch email for response
        cursor.execute("SELECT email FROM users WHERE id = ?", (user_id,))
        email = cursor.fetchone()[0]
        return {
            "status": "authenticated",
            "session_id": session_id,
            "token": access_token,
            "refresh_token": refresh_token,
            "user": {"id": user_id, "email": email, "tier": tier}
        }

    def token_refresh(self, refresh_token: str) -> Dict[str, Any]:
        """Flow 6: a new access token for a session's refresh token. Out: {status: "ok", token, expires_in} or
        {error: "invalid_token" | "token_expired" | "user_banned"}.

        In: the refresh_token that login, mfa_challenge or oauth_callback returned. Its HMAC-SHA256 finds the session
        and is compared with the stored refresh_token_hash in constant time.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2 (AUTH-16): sessions keep only the hash; the
        token was looked up in plain text. Touches: SQLite (sessions, users read; audit_log, why_chain_log).
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: each stored or compared secret is now HMAC-SHA256 under AUTH_SECRET_KEY (was a plain SHA-256)."""
        decision_points = []
        cursor = self.db.cursor()
        supplied = self._hash_secret(refresh_token if isinstance(refresh_token, str) else "")
        cursor.execute(
            """SELECT s.user_id, s.expires_at, u.status, u.tier, s.refresh_token_hash
               FROM sessions s
               JOIN users u ON s.user_id = u.id
               WHERE s.refresh_token_hash = ?""",
            (supplied,)
        )
        session = cursor.fetchone()
        if session and not hmac.compare_digest(str(session[4]).encode("ascii"), supplied.encode("ascii")):
            session = None
        if not session:
            self._log_why_chain("token_refresh", decision_points + ["token_valid:failed"])
            return {"error": "invalid_token"}
        user_id, expires_at, status, tier = session[0], session[1], session[2], session[3]
        if self._parse_time(expires_at) < self._now():
            self._log_why_chain("token_refresh", decision_points + ["token_valid:failed"])
            return {"error": "token_expired"}
        if status in ('suspended', 'banned'):
            self._log_why_chain("token_refresh", decision_points + ["user_not_banned:failed"])
            return {"error": "user_banned"}
        decision_points.append("token_valid")
        decision_points.append("user_active")
        # Issue new access token
        access_token = self._generate_token(user_id, tier, 'access')
        self.db.commit()
        self._log_why_chain("token_refresh", decision_points)
        self._log_audit_log("token_refreshed", actor_id=user_id, resource_type="user", resource_id=user_id,
                           old_value=None, new_value={"token_refreshed": True})
        return {
            "status": "ok",
            "token": access_token,
            "expires_in": self.access_token_expires_minutes * 60
        }

    def verify_access_token(self, token: str) -> Dict[str, Any]:
        decision_points = []
        try:
            payload = self._verify_token(token, 'access')
            user_id = payload['user_id']
            tier = payload['tier']
            decision_points.append("signature_valid")
            decision_points.append("not_expired")
            cursor = self.db.cursor()
            cursor.execute("SELECT status, email FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            if not user:
                self._log_why_chain("verify_access_token", decision_points + ["user_exists_and_active:failed"])
                return {"error": "invalid_token"}
            status, email = user
            if status in ('suspended', 'banned'):
                self._log_why_chain("verify_access_token", decision_points + ["user_exists_and_active:failed"])
                return {"error": "user_banned"}
            decision_points.append("user_active")
            self._log_why_chain("verify_access_token", decision_points)
            return {"status": "ok", "user": {"id": user_id, "email": email, "tier": tier}}
        except jwt.ExpiredSignatureError:
            self._log_why_chain("verify_access_token", decision_points + ["not_expired:failed"])
            return {"error": "token_expired"}
        except jwt.InvalidTokenError:
            self._log_why_chain("verify_access_token", decision_points + ["signature_valid:failed"])
            return {"error": "invalid_token"}

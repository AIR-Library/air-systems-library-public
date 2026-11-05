import bcrypt
import pyotp
import jwt
import secrets
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional, Tuple, Dict, Any
import sqlite3
import time

class AuthSystem:
    def __init__(self, db_connection: sqlite3.Connection, jwt_secret: Optional[str] = None,
                 bcrypt_rounds: int = 12, access_token_expires_minutes: int = 15,
                 refresh_token_expires_days: int = 7, email_verification_expires_hours: int = 24,
                 mfa_challenge_expires_minutes: int = 5, signup_rate_limit: int = 24,
                 signup_rate_limit_max: int = 5, login_rate_limit: int = 15,
                 login_rate_limit_max: int = 5,
                 oauth_profile: Optional[Callable[[str, str], Dict[str, Any]]] = None):
        self.db = db_connection
        # Exchanges a provider's one-time code for the user's verified profile. Replace this with a real call to the
        # provider. The default invents a user, so the template runs without one.
        self.oauth_profile = oauth_profile or (
            lambda provider, code: {"email": f"user_{secrets.token_hex(4)}@{provider}.com"})
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
        """Return current UTC time as timezone-aware datetime."""
        return datetime.now(timezone.utc)

    def _now_iso(self) -> str:
        """Return current UTC time as ISO format string."""
        return self._now().isoformat()

    def _ensure_tables(self):
        cursor = self.db.cursor()
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
            refresh_token TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            ip TEXT,
            device_id TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS verification_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            type TEXT NOT NULL CHECK (type IN ('email', 'mfa')),
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
        CREATE TABLE IF NOT EXISTS rate_limit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            identifier TEXT NOT NULL,
            type TEXT NOT NULL CHECK (type IN ('signup', 'login')),
            timestamp TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token ON sessions(refresh_token);
        CREATE INDEX IF NOT EXISTS idx_verification_codes_user_id_type ON verification_codes(user_id, type);
        CREATE INDEX IF NOT EXISTS idx_oauth_accounts_provider_provider_user_id ON oauth_accounts(provider, provider_user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_why_chain_log_timestamp ON why_chain_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_rate_limit_log_ip_identifier_type_timestamp ON rate_limit_log(ip, identifier, type, timestamp);
        """)
        self.db.commit()

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

    def signup(self, email: str, password: str, name: str, ip: str) -> Dict[str, Any]:
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
        # password_strength: blocklist first (includes email, name, service name)
        blocklist = ["password", "123456", "12345678", "qwerty", "abc123", "monkey", "letmein", "dragon", "baseball", "iloveyou"]
        service_name = "SaasAuth"
        if (password in blocklist or 
            password.lower() == email.lower() or 
            password.lower() == name.lower() or 
            password.lower() == service_name.lower()):
            self._log_why_chain("signup", decision_points + ["password_strength:failed"])
            return {"error": "password_rejected", "reason": "blocklisted"}
        decision_points.append("password_strength:blocklist")
        # password length
        if len(password) < 15:
            self._log_why_chain("signup", decision_points + ["password_strength:failed"])
            return {"error": "password_rejected", "reason": "too_short"}
        if len(password) > 64:
            self._log_why_chain("signup", decision_points + ["password_strength:failed"])
            return {"error": "password_rejected", "reason": "too_long"}
        decision_points.append("password_strength:length")
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
            """INSERT INTO verification_codes (user_id, code, created_at, expires_at, type)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, code, now_iso,
             (self._now() + timedelta(hours=self.email_verification_expires_hours)).isoformat(), 'email')
        )
        self.db.commit()
        self._log_why_chain("signup", decision_points)
        self._log_audit_log("user_created", actor_id=user_id, resource_type="user", resource_id=user_id,
                           old_value=None, new_value={"email": email, "status": "unverified"})
        return {"status": "pending_verification", "email": email, "message": "check email"}

    def verify_email(self, email: str, code_or_token: str) -> Dict[str, Any]:
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
        cursor.execute(
            """SELECT id, expires_at FROM verification_codes
               WHERE user_id = ? AND code = ? AND type = 'email' AND expires_at > ?""",
            (user_id, code_or_token, self._now_iso())
        )
        code_record = cursor.fetchone()
        if not code_record:
            self._log_why_chain("verify_email", decision_points + ["code_valid:failed"])
            return {"error": "code_expired"}
        decision_points.append("code_valid")
        now_iso = self._now_iso()
        cursor.execute("UPDATE users SET email_verified_at = ?, status = 'verified', updated_at = ? WHERE id = ?",
                       (now_iso, now_iso, user_id))
        cursor.execute("DELETE FROM verification_codes WHERE id = ?", (code_record[0],))
        self.db.commit()
        self._log_why_chain("verify_email", decision_points)
        self._log_audit_log("email_verified", actor_id=user_id, resource_type="user", resource_id=user_id,
                           old_value={"email_verified_at": None, "status": "unverified"}, 
                           new_value={"email_verified_at": now_iso, "status": "verified"})
        return {"status": "verified", "user_id": user_id, "message": "ready to login"}

    def login(self, email: str, password: str, device_id: str, ip: str) -> Dict[str, Any]:
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
                """INSERT INTO verification_codes (user_id, code, created_at, expires_at, type)
                   VALUES (?, ?, ?, ?, ?)""",
                (user_id, current_code, now_iso,
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
        refresh_token = secrets.token_urlsafe(32)
        access_token = self._generate_token(user_id, tier, 'access')
        now_iso = self._now_iso()
        cursor.execute(
            """INSERT INTO sessions (user_id, refresh_token, created_at, expires_at, ip, device_id)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user_id, refresh_token, now_iso,
             (self._now() + timedelta(days=self.refresh_token_expires_days)).isoformat(), ip, device_id)
        )
        session_id = cursor.lastrowid
        self.db.commit()
        self._log_why_chain("login", decision_points)
        self._log_audit_log("session_created", actor_id=user_id, resource_type="session", resource_id=session_id,
                           old_value=None, new_value={"user_id": user_id, "ip": ip, "device_id": device_id})
        return {
            "status": "authenticated",
            "session_id": session_id,
            "token": access_token,
            "expires_in": self.access_token_expires_minutes * 60,
            "user": {"id": user_id, "email": email, "tier": tier}
        }

    def oauth_callback(self, provider: str, code: str, state: str) -> Dict[str, Any]:
        decision_points = []
        # state_valid: the caller matches state to the visitor's session before calling this. state passes through the
        # visitor's browser, so nothing inside it is ever trusted: the e-mail comes only from the provider.
        # 2026-11-05, session f3daac6e: an earlier repair read the e-mail from state, which let anyone log in as anyone.
        decision_points.append("state_valid")
        email = self.oauth_profile(provider, code)["email"]
        # email_verified_by_provider: we assume it's verified
        decision_points.append("email_verified")
        cursor = self.db.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        now_iso = self._now_iso()
        if user:
            user_id = user[0]
            # Link OAuth to existing user
            cursor.execute(
                """INSERT OR IGNORE INTO oauth_accounts (user_id, provider, provider_user_id, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (user_id, provider, secrets.token_hex(16), now_iso, now_iso)
            )
            # If user is not verified, we don't change status? Spec says existing user -> link oauth provider to account
            # We'll assume the user is already verified (since OAuth email is verified)
            # Generate tokens
            cursor.execute("SELECT tier FROM users WHERE id = ?", (user_id,))
            tier = cursor.fetchone()[0]
            access_token = self._generate_token(user_id, tier, 'access')
            refresh_token = secrets.token_urlsafe(32)
            cursor.execute(
                """INSERT INTO sessions (user_id, refresh_token, created_at, expires_at)
                   VALUES (?, ?, ?, ?)""",
                (user_id, refresh_token, now_iso,
                 (self._now() + timedelta(days=self.refresh_token_expires_days)).isoformat())
            )
            session_id = cursor.lastrowid
            self.db.commit()
            self._log_why_chain("oauth_callback", decision_points)
            self._log_audit_log("oauth_login", actor_id=user_id, resource_type="user", resource_id=user_id,
                               old_value=None, new_value={"provider": provider, "session_id": session_id})
            return {
                "status": "authenticated",
                "session_id": session_id,
                "token": access_token,
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
                (user_id, provider, secrets.token_hex(16), now_iso, now_iso)
            )
            # Generate tokens
            access_token = self._generate_token(user_id, 'free', 'access')
            refresh_token = secrets.token_urlsafe(32)
            cursor.execute(
                """INSERT INTO sessions (user_id, refresh_token, created_at, expires_at)
                   VALUES (?, ?, ?, ?)""",
                (user_id, refresh_token, now_iso,
                 (self._now() + timedelta(days=self.refresh_token_expires_days)).isoformat())
            )
            session_id = cursor.lastrowid
            self.db.commit()
            self._log_why_chain("oauth_callback", decision_points)
            self._log_audit_log("oauth_login", actor_id=user_id, resource_type="user", resource_id=user_id,
                               old_value=None, new_value={"provider": provider, "session_id": session_id, "new_user": True})
            return {
                "status": "authenticated",
                "session_id": session_id,
                "token": access_token,
                "user": {"id": user_id, "email": email, "tier": "free"}
            }

    def mfa_challenge(self, challenge_id: int, code: str) -> Dict[str, Any]:
        decision_points = []
        cursor = self.db.cursor()
        cursor.execute(
            """SELECT user_id, code, expires_at FROM verification_codes
               WHERE id = ? AND type = 'mfa'""",
            (challenge_id,)
        )
        challenge = cursor.fetchone()
        if not challenge:
            self._log_why_chain("mfa_challenge", decision_points + ["challenge_exists_and_valid:failed"])
            return {"error": "invalid_challenge"}
        user_id, stored_code, expires_at = challenge
        if datetime.fromisoformat(expires_at) < self._now():
            self._log_why_chain("mfa_challenge", decision_points + ["challenge_exists_and_valid:failed"])
            return {"error": "challenge_expired"}
        decision_points.append("challenge_valid")
        if code != stored_code:
            self._log_why_chain("mfa_challenge", decision_points + ["code_correct:failed"])
            return {"error": "invalid_code"}
        decision_points.append("code_correct")
        # Mark challenge as verified (delete it)
        cursor.execute("DELETE FROM verification_codes WHERE id = ?", (challenge_id,))
        # Create session
        cursor.execute("SELECT tier FROM users WHERE id = ?", (user_id,))
        tier = cursor.fetchone()[0]
        access_token = self._generate_token(user_id, tier, 'access')
        refresh_token = secrets.token_urlsafe(32)
        now_iso = self._now_iso()
        cursor.execute(
            """INSERT INTO sessions (user_id, refresh_token, created_at, expires_at)
               VALUES (?, ?, ?, ?)""",
            (user_id, refresh_token, now_iso,
             (self._now() + timedelta(days=self.refresh_token_expires_days)).isoformat())
        )
        session_id = cursor.lastrowid
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
            "user": {"id": user_id, "email": email, "tier": tier}
        }

    def token_refresh(self, refresh_token: str) -> Dict[str, Any]:
        decision_points = []
        cursor = self.db.cursor()
        cursor.execute(
            """SELECT s.user_id, s.expires_at, u.status, u.tier
               FROM sessions s
               JOIN users u ON s.user_id = u.id
               WHERE s.refresh_token = ?""",
            (refresh_token,)
        )
        session = cursor.fetchone()
        if not session:
            self._log_why_chain("token_refresh", decision_points + ["token_valid:failed"])
            return {"error": "invalid_token"}
        user_id, expires_at, status, tier = session
        if datetime.fromisoformat(expires_at) < self._now():
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

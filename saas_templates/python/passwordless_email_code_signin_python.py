"""Passwordless email code sign-in (docs/specs/passwordless_email_code_signin.md): sign in, and sign up, with a
6-digit code sent by email. One code per address at a time, valid 600 seconds, usable once, 5 tries, rate limits
per address and per IP, and the same answer whether or not the address has an account.

Why: Phase D wave 1, owner request 2026-11-10 (EMAILCODE-01 to EMAILCODE-14). 2026-11-10,
session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the injected store (SQLite, tables accounts, email_codes, rate_windows)
and the injected sender (email over the network in production, a fake in tests). No files or money. The code, the
address and the IP are stored only as HMAC-SHA256 under the server's secret (accounts.email excepted); none of
them, nor the secret, is logged.

Inputs and outputs: EmailCodeSignin(store, secret, sender, clock, random_bytes, generate_code, revoke_unproven)
with start and verify. A refusal is a RETURNED dict {error, status}.
"""
import hashlib
import hmac
import os
import re
import sqlite3
import threading
import time
from typing import Callable, Optional

CODE_TTL = 600
CODE_ATTEMPTS = 5
START_PER_EMAIL_HOUR = 5
START_PER_EMAIL_DAY = 10
START_PER_IP_HOUR = 20
VERIFY_PER_IP_HOUR = 30
VERIFY_PER_EMAIL_HOUR = 10
_EMAIL_RE = re.compile(r"[a-z0-9][a-z0-9._%+=-]*@[a-z0-9-]+(\.[a-z0-9-]+)+")
_ZEROS64 = "0" * 64


class EmailCodeConfigError(Exception):
    """Construction refused (fail closed): code "not_configured". Holds no secret.

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""

    def __init__(self, code: str):
        """In: the error code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        super().__init__(code)
        self.code = code


def _err(error: str, status: int) -> dict:
    """A refusal {error, status}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return {"error": error, "status": status}


def normalize_email(raw) -> Optional[str]:
    """Trim only space, tab, CR, LF; map only A-Z to a-z; 3 to 254 characters and the WHOLE text matches
    [a-z0-9][a-z0-9._%+=-]*@[a-z0-9-]+(\\.[a-z0-9-]+)+. Out: the address or None.

    Why: EMAILCODE-11 (str.strip and str.lower would accept U+00A0, U+000B and U+212A). 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    if not isinstance(raw, str):
        return None
    e = raw.strip(" \t\r\n")
    e = "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in e)
    if not (3 <= len(e) <= 254) or _EMAIL_RE.fullmatch(e) is None:
        return None
    return e


def code_from_bytes(random_bytes: Callable[[int], bytes]) -> str:
    """CODE: n = random_bytes(4) as an UNSIGNED big-endian 32-bit number, drawn again while n >= 4294000000; the
    code is n mod 1000000 with 6 digits (leading zeros kept). Every code is equally likely.

    Why: EMAILCODE-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    while True:
        n = int.from_bytes(random_bytes(4), "big")
        if n < 4294000000:
            return "%06d" % (n % 1000000)


# ------------------------------------------------------------------------------------------------------ store
class SqliteEmailCodeStore:
    """The store on SQLite with the spec's schema: one shared connection guarded by a lock. BUMP and verify's
    steps 4 and 6 are single statements or one locked transaction, never a read followed by a separate write.

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the SQLite database (memory or file)."""

    def __init__(self, path: str = ":memory:"):
        """Open the database and create the tables. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.lock = threading.RLock()
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE,
                email_verified_at INT NULL, status TEXT NOT NULL DEFAULT 'active', created_at INT NOT NULL);
            CREATE TABLE IF NOT EXISTS email_codes (email_hash TEXT PRIMARY KEY, code_hash TEXT NOT NULL,
                expires_at INT NOT NULL, attempts INT NOT NULL DEFAULT 0, created_at INT NOT NULL);
            CREATE TABLE IF NOT EXISTS rate_windows (key TEXT, window_start INT, count INT NOT NULL,
                PRIMARY KEY (key, window_start));
        """)

    def _tx(self, fn):
        """Run fn(conn) in one locked transaction. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                out = fn(self.conn)
                self.conn.execute("COMMIT")
                return out
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise

    def bump(self, key: str, window_start: int) -> int:
        """BUMP: insert (key, window_start, 1) or add 1, atomically. Out: the count after it.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        def fn(conn):
            """The statements of this one locked transaction, on conn. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database."""
            conn.execute("INSERT INTO rate_windows (key, window_start, count) VALUES (?, ?, 1) "
                         "ON CONFLICT (key, window_start) DO UPDATE SET count = rate_windows.count + 1",
                         (key, window_start))
            return conn.execute("SELECT count FROM rate_windows WHERE key = ? AND window_start = ?",
                                (key, window_start)).fetchone()[0]
        return self._tx(fn)

    def put_code(self, email_hash: str, code_hash: str, expires_at: int, now: int) -> None:
        """Write the address's code row, replacing an earlier one (attempts 0). 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            self.conn.execute("INSERT OR REPLACE INTO email_codes (email_hash, code_hash, expires_at, attempts, "
                              "created_at) VALUES (?, ?, ?, 0, ?)", (email_hash, code_hash, expires_at, now))

    def delete_code_if(self, email_hash: str, code_hash: str) -> int:
        """DELETE the row only while it holds code_hash. Out: rows deleted. 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            return self.conn.execute("DELETE FROM email_codes WHERE email_hash = ? AND code_hash = ?",
                                     (email_hash, code_hash)).rowcount

    def count_try(self, email_hash: str, now: int):
        """verify step 4: attempts + 1 WHERE attempts < 5 AND expires_at > now, returning (code_hash, attempts), in
        one locked transaction; None when no row changed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        def fn(conn):
            """The statements of this one locked transaction, on conn. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database."""
            cur = conn.execute("UPDATE email_codes SET attempts = attempts + 1 WHERE email_hash = ? AND "
                               "attempts < ? AND expires_at > ?", (email_hash, CODE_ATTEMPTS, now))
            if cur.rowcount != 1:
                return None
            return tuple(conn.execute("SELECT code_hash, attempts FROM email_codes WHERE email_hash = ?",
                                      (email_hash,)).fetchone())
        return self._tx(fn)

    def delete_dead(self, email_hash: str, now: int) -> None:
        """Delete the address's row when it is expired or used up. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            self.conn.execute("DELETE FROM email_codes WHERE email_hash = ? AND (expires_at <= ? OR attempts >= ?)",
                              (email_hash, now, CODE_ATTEMPTS))

    def find_account(self, email: str) -> Optional[dict]:
        """The account row for an address, or None. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            cur = self.conn.execute("SELECT id, email, email_verified_at, status, created_at FROM accounts "
                                    "WHERE email = ?", (email,))
            r = cur.fetchone()
            return dict(zip([d[0] for d in cur.description], r)) if r else None

    def insert_verified(self, account_id: str, email: str, now: int) -> None:
        """Insert a verified 'active' account unless the address already has one. 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            self.conn.execute("INSERT INTO accounts (id, email, email_verified_at, status, created_at) "
                              "VALUES (?, ?, ?, 'active', ?) ON CONFLICT (email) DO NOTHING",
                              (account_id, email, now, now))

    def mark_verified(self, account_id: str, now: int) -> None:
        """Set email_verified_at = now. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            self.conn.execute("UPDATE accounts SET email_verified_at = ? WHERE id = ?", (now, account_id))


# ---------------------------------------------------------------------------------------------------- service
class EmailCodeSignin:
    """start and verify over an injected store, secret, sender, clock, random source, code generator and
    revoke_unproven hook. Why: EMAILCODE-01..14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    Touches: the store and the sender."""

    def __init__(self, store: SqliteEmailCodeStore, secret, sender, clock: Optional[Callable[[], int]] = None,
                 random_bytes: Optional[Callable[[int], bytes]] = None,
                 generate_code: Optional[Callable[[], str]] = None,
                 revoke_unproven: Optional[Callable[[str], None]] = None):
        """A secret under 32 bytes (str taken as UTF-8) or no sender -> EmailCodeConfigError("not_configured").
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        if not isinstance(secret, (bytes, bytearray)) or len(secret) < 32 or sender is None:
            raise EmailCodeConfigError("not_configured")
        self.store = store
        self._secret = bytes(secret)
        self.sender = sender
        self.clock = clock or (lambda: int(time.time()))
        self.random_bytes = random_bytes or os.urandom
        self._generate = generate_code
        self.revoke_unproven = revoke_unproven or (lambda account_id: None)

    def _now(self) -> int:
        """The injected clock as an int. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        return int(self.clock())

    def generate_code(self) -> str:
        """The injected generator, or CODE from random_bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        return self._generate() if self._generate is not None else code_from_bytes(self.random_bytes)

    def hmac_hex(self, text: str) -> str:
        """Lower-case hex HMAC-SHA256(secret, UTF-8 of text). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        return hmac.new(self._secret, text.encode("utf-8"), hashlib.sha256).hexdigest()

    def email_hash(self, email: str) -> str:
        """hmac_hex("email:" + email). Why: EMAILCODE-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        return self.hmac_hex("email:" + email)

    def code_hash(self, email: str, code: str) -> str:
        """hmac_hex("code:" + email_hash(email) + ":" + code). Why: EMAILCODE-02, 14. 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP."""
        return self.hmac_hex("code:" + self.email_hash(email) + ":" + code)

    def ip_hash(self, ip) -> str:
        """The first 32 characters of hmac_hex("ip:" + ip); a missing ip is "unknown". 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP."""
        if not isinstance(ip, str) or ip == "":
            ip = "unknown"
        return self.hmac_hex("ip:" + ip)[:32]

    def _ek(self, email: str) -> str:
        """EK: the first 32 characters of email_hash. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        return self.email_hash(email)[:32]

    def _bump(self, key: str, span: int, now: int) -> int:
        """BUMP(key, span) in the clock window that holds now. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        return self.store.bump(key, now - (now % span))

    def start(self, email, ip) -> dict:
        """start, steps 1-6: never reads accounts, so a known and an unknown address get the same answer and email.
        Out: {status: 202, sent: true, expires_in: 600} or a refusal. Why: EMAILCODE-01, 07, 08, 09, 12.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the sender (email)."""
        now = self._now()
        e = normalize_email(email)
        if e is None:
            return _err("invalid_email", 422)
        if self._bump("start-ip#" + self.ip_hash(ip), 3600, now) > START_PER_IP_HOUR:
            return _err("too_many_requests", 429)
        ek = self._ek(e)
        h = self._bump("start-email#" + ek, 3600, now)
        d = self._bump("start-email-day#" + ek, 86400, now)
        if h > START_PER_EMAIL_HOUR or d > START_PER_EMAIL_DAY:
            return _err("too_many_requests", 429)
        code = self.generate_code()
        eh = self.email_hash(e)
        new_hash = self.code_hash(e, code)
        self.store.put_code(eh, new_hash, now + CODE_TTL, now)
        try:
            sent = self.sender.send_code(e, code, CODE_TTL)
        except Exception:  # noqa: BLE001 - a raising sender is a failed send; its message is not echoed
            sent = False
        if sent is not True:
            self.store.delete_code_if(eh, new_hash)
            return _err("send_failed", 503)
        return {"status": 202, "sent": True, "expires_in": CODE_TTL}

    def verify(self, email, code, ip) -> dict:
        """verify, steps 1-9: count the IP and address tries, count the code's try before comparing, compare in
        constant time, use the code up with one DELETE, then find or make the account.
        Out: {status: 200, account_id, email, new_account} or a refusal. Why: EMAILCODE-01, 03..07, 10, 11, 13, 14.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store."""
        now = self._now()
        if self._bump("verify-ip#" + self.ip_hash(ip), 3600, now) > VERIFY_PER_IP_HOUR:
            return _err("too_many_requests", 429)
        e = normalize_email(email)
        c = code.replace(" ", "").replace("-", "") if isinstance(code, str) else None
        if e is None or c is None or len(c) != 6 or not all("0" <= ch <= "9" for ch in c):
            return _err("invalid_code", 400)
        if self._bump("verify-email#" + self._ek(e), 3600, now) > VERIFY_PER_EMAIL_HOUR:
            return _err("too_many_requests", 429)
        eh = self.email_hash(e)
        offered = self.code_hash(e, c)
        counted = self.store.count_try(eh, now)
        if counted is None:
            self.store.delete_dead(eh, now)
            hmac.compare_digest(offered, _ZEROS64)  # the same work as a real compare
            return _err("invalid_code", 400)
        stored, attempts = counted
        if not hmac.compare_digest(offered, stored):
            if attempts >= CODE_ATTEMPTS:
                self.store.delete_code_if(eh, stored)
            return _err("invalid_code", 400)
        if self.store.delete_code_if(eh, stored) != 1:
            return _err("invalid_code", 400)
        new_id = self.random_bytes(16).hex()
        self.store.insert_verified(new_id, e, now)
        row = self.store.find_account(e)
        new_account = row["id"] == new_id
        if row["email_verified_at"] is None:
            try:
                self.revoke_unproven(row["id"])
            except Exception:  # noqa: BLE001 - leave the row unverified
                return _err("processing_failed", 500)
            self.store.mark_verified(row["id"], now)
        if row["status"] != "active":
            return _err("account_unavailable", 403)
        return {"status": 200, "account_id": row["id"], "email": e, "new_account": new_account}

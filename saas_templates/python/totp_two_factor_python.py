"""TOTP two-factor (docs/specs/totp_two_factor.md): authenticator-app codes (RFC 6238) with one step of drift each
way, a replay guard, a lock after repeated wrong codes, a hard lock after 100, and one-time recovery codes.

Why: Phase D wave 1, owner request 2026-11-10 (TOTP-01 to TOTP-14). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
Touches: the injected store (SQLite, the spec's schema; tests use one shared in-memory connection). No network,
files or money. Never logs or returns a secret (outside enroll_start's answer), a code, a recovery code or a key.

Inputs and outputs: TotpService(store, encryption_key, recovery_hash_key, issuer, clock, random_bytes) with
enroll_start, enroll_confirm, verify, disable and status. A refusal is a RETURNED dict {error, status[, retry_after]}.
"""
import base64
import hashlib
import hmac
import os
import sqlite3
import threading
import time
from typing import Callable, List, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

STEP = 30
DIGITS = 6
WINDOW = 1
LOCK_FAILURES = 5
LOCK_SECONDS = 900
HARD_LOCK_FAILURES = 100
RECOVERY_CODES = 8
RECOVERY_ALPHABET = "23456789abcdefghjkmnpqrstvwxyz"
B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
MAX_CODE_CHARS = 64


class TotpConfigError(Exception):
    """Construction refused (fail closed): code "invalid_key". The message never holds a key.

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""

    def __init__(self, code: str):
        """In: the error code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        super().__init__(code)
        self.code = code


class Base32Error(ValueError):
    """base32_decode's refusal, code "invalid_base32" (a pure helper raises; the flows never see it).

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""

    def __init__(self):
        """2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        super().__init__("invalid_base32")
        self.code = "invalid_base32"


# ------------------------------------------------------------------------------------------- pure functions
def base32_encode(data: bytes) -> str:
    """RFC 4648 base32, alphabet A-Z 2-7, upper case, NO "=" padding.

    In: bytes. Out: text. Why: TOTP-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return base64.b32encode(bytes(data)).decode("ascii").rstrip("=")


def base32_decode(text: str) -> bytes:
    """Decode base32: drop ASCII spaces, "-" and "="; map a-z to A-Z; every character must be in the alphabet,
    at least one must remain, and a length of 1, 3 or 6 modulo 8 is refused. Leftover bits are dropped.

    In: text. Out: bytes; raises Base32Error("invalid_base32"). Why: TOTP-02 (checked here, before any library:
    Python's b32decode raises on those lengths). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    if not isinstance(text, str):
        raise Base32Error()
    chars = []
    for c in text:
        if c in " -=":
            continue
        if "a" <= c <= "z":
            c = chr(ord(c) - 32)
        if c not in B32_ALPHABET:
            raise Base32Error()
        chars.append(c)
    if not chars or len(chars) % 8 in (1, 3, 6):
        raise Base32Error()
    out = bytearray()
    acc = 0
    bits = 0
    for c in chars:
        acc = (acc << 5) | B32_ALPHABET.index(c)
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
            acc &= (1 << bits) - 1
    return bytes(out)


def hotp(key_bytes: bytes, counter: int, digits: int = DIGITS) -> str:
    """RFC 4226 HOTP: HMAC-SHA1 over the 8-byte big-endian counter, dynamic truncation, mod 10^digits, zero-padded.

    In: key, counter (64-bit), digits. Out: the code text. Why: TOTP-01. 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    mac = hmac.new(bytes(key_bytes), int(counter).to_bytes(8, "big"), hashlib.sha1).digest()
    o = mac[19] & 0x0F
    v = int.from_bytes(mac[o:o + 4], "big") & 0x7FFFFFFF
    return str(v % (10 ** digits)).zfill(digits)


def totp_at(secret_base32: str, unix_time: int, digits: int = DIGITS) -> str:
    """totp_at = hotp(base32_decode(secret), floor(unix_time / 30), digits).

    Why: TOTP-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return hotp(base32_decode(secret_base32), int(unix_time) // STEP, digits)


def _pct(s: str) -> str:
    """Percent-encode every UTF-8 byte not in [A-Za-z0-9._~-] as %XX (upper-case hex).

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    safe = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-"
    return "".join(chr(b) if b in safe else "%{:02X}".format(b) for b in s.encode("utf-8"))


def otpauth_uri(secret: str, issuer: str, account_label: str) -> str:
    """The Key URI an authenticator app reads.

    In: base32 secret, issuer, label. Out: "otpauth://totp/...". Why: TOTP-03. 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return ("otpauth://totp/" + _pct(issuer + ":" + account_label) + "?secret=" + secret + "&issuer=" + _pct(issuer)
            + "&algorithm=SHA1&digits=6&period=30")


def seal(key32: bytes, nonce12: bytes, plaintext: str, aad: str) -> str:
    """AES-256-GCM: "v1." + base64(nonce + ciphertext + 16-byte tag), aad = UTF-8 of the aad text.

    Why: TOTP-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    ct = AESGCM(bytes(key32)).encrypt(bytes(nonce12), plaintext.encode("utf-8"), aad.encode("utf-8"))
    return "v1." + base64.b64encode(bytes(nonce12) + ct).decode("ascii")


def open_sealed(key32: bytes, sealed, aad: str) -> Optional[str]:
    """The spec's open(): the plaintext, or None for a missing "v1." prefix, bad base64, fewer than 28 bytes, a tag
    that does not verify (wrong key, wrong aad, any changed byte) or plaintext that is not UTF-8. Named open_sealed
    so it does not shadow Python's built-in open.

    Why: TOTP-10, TOTP-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    try:
        if not isinstance(sealed, str) or not sealed.startswith("v1.") or len(key32) != 32:
            return None
        raw = base64.b64decode(sealed[3:].encode("ascii"), validate=True)
        if len(raw) < 28:
            return None
        pt = AESGCM(bytes(key32)).decrypt(raw[:12], raw[12:], aad.encode("utf-8"))
        return pt.decode("utf-8")
    except (InvalidTag, ValueError, UnicodeError):
        return None


def _strip_spaces_dashes(code: str) -> str:
    """Remove every ASCII space and "-". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return code.replace(" ", "").replace("-", "")


def totp_input(code) -> Optional[str]:
    """TOTP INPUT: at most 64 characters; without spaces and "-", exactly 6 characters 0-9. Out: those 6 or None.

    Why: TOTP-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    if not isinstance(code, str) or len(code) > MAX_CODE_CHARS:
        return None
    c = _strip_spaces_dashes(code)
    if len(c) == 6 and all("0" <= ch <= "9" for ch in c):
        return c
    return None


def recovery_input(code) -> Optional[str]:
    """RECOVERY INPUT: at most 64 characters; A-Z to a-z, spaces and "-" removed, exactly 12 symbols of the
    RECOVERY ALPHABET. Out: that form or None. Why: TOTP-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    if not isinstance(code, str) or len(code) > MAX_CODE_CHARS:
        return None
    lowered = "".join(chr(ord(ch) + 32) if "A" <= ch <= "Z" else ch for ch in code)
    c = _strip_spaces_dashes(lowered)
    if len(c) == 12 and all(ch in RECOVERY_ALPHABET for ch in c):
        return c
    return None


# ------------------------------------------------------------------------------------------------------ store
class TotpStore:
    """The store interface: every method is ONE atomic statement (see the spec's SQL).

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches whatever backs the store."""

    def get_enrollment(self, user_id: str) -> Optional[dict]:
        """The user's totp_enrollments row as a dict, or None. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        raise NotImplementedError

    def put_unconfirmed(self, user_id: str, secret_enc: str, now: int) -> bool:
        """Insert the row, or replace an UNCONFIRMED one. Out: False when a confirmed row is there. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        raise NotImplementedError

    def confirm(self, user_id: str, now: int, step: int, secret_enc_read: str) -> bool:
        """enroll_confirm step 7's conditional UPDATE. Out: True when one row changed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        raise NotImplementedError

    def claim(self, user_id: str, step: int) -> bool:
        """CLAIM(step): set last_used_step and reset failed_since_success only when last_used_step < step. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        raise NotImplementedError

    def try_slot(self, user_id: str, now: int) -> Optional[int]:
        """TRY: insert a totp_failures row only while the window holds fewer than 5. Out: its id, or None. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        raise NotImplementedError

    def delete_slot(self, slot_id: int) -> None:
        """Delete this call's slot row, and only it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        raise NotImplementedError

    def add_failure(self, user_id: str) -> None:
        """FAILURE: failed_since_success + 1 (the slot row stays as the failure). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        raise NotImplementedError

    def reset_failed(self, user_id: str) -> None:
        """failed_since_success = 0 (a recovery code signed in). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        raise NotImplementedError

    def failures_since(self, user_id: str, after: int) -> List[int]:
        """The `at` of the user's failure rows with at > after, most recent first. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        raise NotImplementedError

    def add_recovery_codes(self, user_id: str, hashes: List[str], now: int) -> None:
        """Store the keyed hashes of a new set of recovery codes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        raise NotImplementedError

    def use_recovery_code(self, user_id: str, code_hash: str, now: int) -> bool:
        """Mark an unused code used, in one conditional UPDATE. Out: True when one row changed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        raise NotImplementedError

    def recovery_codes_left(self, user_id: str) -> int:
        """How many of the user's codes have used_at IS NULL. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        raise NotImplementedError

    def delete_user(self, user_id: str) -> None:
        """Delete the user's enrollment, recovery codes and failures. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        raise NotImplementedError


class SqliteTotpStore(TotpStore):
    """TotpStore on SQLite with the spec's schema. One connection, shared by every call and thread, guarded by a
    lock (":memory:" opened per connection would be a new empty database).

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the SQLite database (memory or file)."""

    def __init__(self, path: str = ":memory:"):
        """Open the database and create the tables. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.lock = threading.RLock()
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS totp_enrollments (user_id TEXT PRIMARY KEY, secret_enc TEXT NOT NULL,
                confirmed_at INT NULL, last_used_step INT NOT NULL DEFAULT 0,
                failed_since_success INT NOT NULL DEFAULT 0, created_at INT NOT NULL);
            CREATE TABLE IF NOT EXISTS totp_recovery_codes (id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL, code_hash TEXT NOT NULL, created_at INT NOT NULL, used_at INT NULL,
                UNIQUE (user_id, code_hash));
            CREATE TABLE IF NOT EXISTS totp_failures (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL,
                at INT NOT NULL);
        """)

    def _x(self, sql: str, args=()) -> sqlite3.Cursor:
        """Run one parameterized statement under the lock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            return self.conn.execute(sql, args)

    def get_enrollment(self, user_id):
        """See TotpStore.get_enrollment. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        row = self._x("SELECT user_id, secret_enc, confirmed_at, last_used_step, failed_since_success, created_at "
                      "FROM totp_enrollments WHERE user_id = ?", (user_id,)).fetchone()
        if row is None:
            return None
        keys = ("user_id", "secret_enc", "confirmed_at", "last_used_step", "failed_since_success", "created_at")
        return dict(zip(keys, row))

    def put_unconfirmed(self, user_id, secret_enc, now):
        """See TotpStore.put_unconfirmed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        cur = self._x(
            "INSERT INTO totp_enrollments (user_id, secret_enc, confirmed_at, last_used_step, failed_since_success, "
            "created_at) VALUES (?, ?, NULL, 0, 0, ?) ON CONFLICT (user_id) DO UPDATE SET "
            "secret_enc = excluded.secret_enc, confirmed_at = NULL, last_used_step = 0, failed_since_success = 0, "
            "created_at = excluded.created_at WHERE totp_enrollments.confirmed_at IS NULL",
            (user_id, secret_enc, now))
        return cur.rowcount == 1

    def confirm(self, user_id, now, step, secret_enc_read):
        """See TotpStore.confirm. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        cur = self._x("UPDATE totp_enrollments SET confirmed_at = ?, last_used_step = ?, failed_since_success = 0 "
                      "WHERE user_id = ? AND confirmed_at IS NULL AND secret_enc = ?",
                      (now, step, user_id, secret_enc_read))
        return cur.rowcount == 1

    def claim(self, user_id, step):
        """See TotpStore.claim. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        cur = self._x("UPDATE totp_enrollments SET last_used_step = ?, failed_since_success = 0 "
                      "WHERE user_id = ? AND confirmed_at IS NOT NULL AND last_used_step < ?", (step, user_id, step))
        return cur.rowcount == 1

    def try_slot(self, user_id, now):
        """See TotpStore.try_slot. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO totp_failures (user_id, at) SELECT ?, ? WHERE (SELECT COUNT(*) FROM totp_failures "
                "WHERE user_id = ? AND at > ? - 900) < 5", (user_id, now, user_id, now))
            return cur.lastrowid if cur.rowcount == 1 else None

    def delete_slot(self, slot_id):
        """See TotpStore.delete_slot. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self._x("DELETE FROM totp_failures WHERE id = ?", (slot_id,))

    def add_failure(self, user_id):
        """See TotpStore.add_failure. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self._x("UPDATE totp_enrollments SET failed_since_success = failed_since_success + 1 WHERE user_id = ?",
                (user_id,))

    def reset_failed(self, user_id):
        """See TotpStore.reset_failed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self._x("UPDATE totp_enrollments SET failed_since_success = 0 WHERE user_id = ?", (user_id,))

    def failures_since(self, user_id, after):
        """See TotpStore.failures_since. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        rows = self._x("SELECT at FROM totp_failures WHERE user_id = ? AND at > ? ORDER BY at DESC, id DESC",
                       (user_id, after)).fetchall()
        return [r[0] for r in rows]

    def add_recovery_codes(self, user_id, hashes, now):
        """See TotpStore.add_recovery_codes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            self.conn.execute("BEGIN")
            try:
                for h in hashes:
                    self.conn.execute("INSERT INTO totp_recovery_codes (user_id, code_hash, created_at, used_at) "
                                      "VALUES (?, ?, ?, NULL)", (user_id, h, now))
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise

    def use_recovery_code(self, user_id, code_hash, now):
        """See TotpStore.use_recovery_code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        cur = self._x("UPDATE totp_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? "
                      "AND used_at IS NULL", (now, user_id, code_hash))
        return cur.rowcount == 1

    def recovery_codes_left(self, user_id):
        """See TotpStore.recovery_codes_left. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        return self._x("SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = ? AND used_at IS NULL",
                       (user_id,)).fetchone()[0]

    def delete_user(self, user_id):
        """See TotpStore.delete_user. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            self.conn.execute("BEGIN")
            try:
                for table in ("totp_enrollments", "totp_recovery_codes", "totp_failures"):
                    self.conn.execute("DELETE FROM " + table + " WHERE user_id = ?", (user_id,))
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise


# ---------------------------------------------------------------------------------------------------- service
def _err(error: str, status: int, **extra) -> dict:
    """A refusal {error, status, ...}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    out = {"error": error, "status": status}
    out.update(extra)
    return out


class TotpService:
    """The TOTP flows of the spec over an injected store, keys, issuer, clock and random source.

    Why: TOTP-03..14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store."""

    def __init__(self, store: TotpStore, encryption_key: bytes, recovery_hash_key: bytes, issuer: str,
                 clock: Optional[Callable[[], int]] = None, random_bytes: Optional[Callable[[int], bytes]] = None):
        """Check the keys (encryption_key exactly 32 bytes, recovery_hash_key at least 32) or raise
        TotpConfigError("invalid_key"). clock defaults to time.time, random_bytes to os.urandom (CSPRNG).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        if not isinstance(encryption_key, (bytes, bytearray)) or len(encryption_key) != 32:
            raise TotpConfigError("invalid_key")
        if not isinstance(recovery_hash_key, (bytes, bytearray)) or len(recovery_hash_key) < 32:
            raise TotpConfigError("invalid_key")
        self.store = store
        self._enc_key = bytes(encryption_key)
        self._rec_key = bytes(recovery_hash_key)
        self.issuer = issuer
        self.clock = clock or (lambda: int(time.time()))
        self.random_bytes = random_bytes or os.urandom

    def _now(self) -> int:
        """The injected clock as an int. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        return int(self.clock())

    def generate_secret(self) -> str:
        """base32_encode(random_bytes(20)): 32 characters. Why: TOTP-02. 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        return base32_encode(self.random_bytes(20))

    def recovery_code_hash(self, user_id: str, code_input_form: str) -> str:
        """Lower-case hex HMAC-SHA256(recovery_hash_key, "recovery:" + user_id + ":" + the RECOVERY INPUT form).

        Why: TOTP-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        return hmac.new(self._rec_key, ("recovery:" + user_id + ":" + code_input_form).encode("utf-8"),
                        hashlib.sha256).hexdigest()

    def _make_recovery_codes(self) -> List[str]:
        """8 codes of 12 symbols, drawn one byte at a time (b >= 240 drawn again), shown as xxxx-xxxx-xxxx; a code
        equal to an earlier one of the set is dropped. Why: TOTP-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        codes: List[str] = []
        while len(codes) < RECOVERY_CODES:
            symbols = []
            while len(symbols) < 12:
                b = self.random_bytes(1)[0]
                if b >= 240:
                    continue
                symbols.append(RECOVERY_ALPHABET[b % 30])
            raw = "".join(symbols)
            code = raw[0:4] + "-" + raw[4:8] + "-" + raw[8:12]
            if code not in codes:
                codes.append(code)
        return codes

    def _match(self, key: bytes, code6: str, now: int) -> Optional[int]:
        """MATCH: compare the input with the codes of steps s-1, s, s+1 in constant time, all of them, no early exit.
        Out: the LARGEST equal step, or None. Why: TOTP-05, TOTP-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        s = now // STEP
        best = None
        for d in range(-WINDOW, WINDOW + 1):
            step = s + d
            if step < 0:
                continue
            if hmac.compare_digest(hotp(key, step).encode("ascii"), code6.encode("ascii")):
                best = step
        return best

    def _locked_answer(self, user_id: str, now: int) -> dict:
        """429 locked with retry_after = the 5th most recent failure's at + 900 - now.

        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the store."""
        recent = self.store.failures_since(user_id, now - LOCK_SECONDS)
        at5 = recent[LOCK_FAILURES - 1] if len(recent) >= LOCK_FAILURES else now
        return _err("locked", 429, retry_after=at5 + LOCK_SECONDS - now)

    def _failure(self, user_id: str) -> dict:
        """FAILURE: the slot row stays; failed_since_success + 1; 401 invalid_code.

        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store."""
        self.store.add_failure(user_id)
        return _err("invalid_code", 401)

    def _open_secret(self, user_id: str, row: dict) -> Optional[bytes]:
        """Open the row's sealed secret and decode it, or None when it cannot be opened.

        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        secret = open_sealed(self._enc_key, row["secret_enc"], "totp:" + user_id)
        if secret is None:
            return None
        try:
            return base32_decode(secret)
        except Base32Error:
            return None

    def enroll_start(self, user_id: str, account_label: str) -> dict:
        """enroll_start: 409 already_enrolled for a confirmed row; else a new secret, sealed under
        "totp:" + user_id (an unconfirmed row is replaced). Out: {secret, otpauth_uri}.
        Why: TOTP-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store."""
        now = self._now()
        row = self.store.get_enrollment(user_id)
        if row is not None and row["confirmed_at"] is not None:
            return _err("already_enrolled", 409)
        secret = self.generate_secret()
        nonce = self.random_bytes(12)
        sealed = seal(self._enc_key, nonce, secret, "totp:" + user_id)
        if not self.store.put_unconfirmed(user_id, sealed, now):
            return _err("already_enrolled", 409)
        return {"secret": secret, "otpauth_uri": otpauth_uri(secret, self.issuer, account_label)}

    def enroll_confirm(self, user_id: str, code) -> dict:
        """enroll_confirm, steps 1-8: confirm with a current code. Out: {recovery_codes: [8 texts]} or a refusal.

        Why: TOTP-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store."""
        now = self._now()
        row = self.store.get_enrollment(user_id)
        if row is None:
            return _err("enrollment_not_started", 409)
        if row["confirmed_at"] is not None:
            return _err("already_enrolled", 409)
        slot = self.store.try_slot(user_id, now)
        if slot is None:
            return self._locked_answer(user_id, now)
        c = totp_input(code)
        if c is None:
            return self._failure(user_id)
        key = self._open_secret(user_id, row)
        if key is None:
            self.store.delete_slot(slot)
            return _err("secret_unreadable", 503)
        step = self._match(key, c, now)
        if step is None:
            return self._failure(user_id)
        if not self.store.confirm(user_id, now, step, row["secret_enc"]):
            again = self.store.get_enrollment(user_id)
            if again is not None and again["confirmed_at"] is not None:
                self.store.delete_slot(slot)
                return _err("already_enrolled", 409)
            return self._failure(user_id)
        codes = self._make_recovery_codes()
        self.store.add_recovery_codes(user_id, [self.recovery_code_hash(user_id, _strip_spaces_dashes(x))
                                                for x in codes], now)
        self.store.delete_slot(slot)
        return {"recovery_codes": codes}

    def _check(self, user_id: str, code, now: int):
        """verify steps 1-5. Out: (refusal, None, slot) or (None, method, slot).

        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store."""
        row = self.store.get_enrollment(user_id)
        if row is None or row["confirmed_at"] is None:
            return _err("not_enrolled", 409), None, None
        slot = self.store.try_slot(user_id, now)
        if slot is None:
            return self._locked_answer(user_id, now), None, None
        c = totp_input(code)
        if c is not None:
            if row["failed_since_success"] >= HARD_LOCK_FAILURES:
                self.store.delete_slot(slot)
                return _err("recovery_required", 429), None, slot
            key = self._open_secret(user_id, row)
            if key is None:
                self.store.delete_slot(slot)
                return _err("secret_unreadable", 503), None, slot
            step = self._match(key, c, now)
            if step is None or step <= row["last_used_step"]:
                return self._failure(user_id), None, slot
            if not self.store.claim(user_id, step):
                return self._failure(user_id), None, slot
            return None, "totp", slot
        r = recovery_input(code)
        if r is not None:
            if self.store.use_recovery_code(user_id, self.recovery_code_hash(user_id, r), now):
                self.store.reset_failed(user_id)
                return None, "recovery_code", slot
            return self._failure(user_id), None, slot
        return self._failure(user_id), None, slot

    def verify(self, user_id: str, code) -> dict:
        """verify: {ok: true, method: "totp" | "recovery_code", recovery_codes_left} or a refusal.

        Why: TOTP-05..10, 13, 14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store."""
        now = self._now()
        refusal, method, slot = self._check(user_id, code, now)
        if refusal is not None:
            return refusal
        self.store.delete_slot(slot)
        return {"ok": True, "method": method, "recovery_codes_left": self.store.recovery_codes_left(user_id)}

    def disable(self, user_id: str, code) -> dict:
        """disable: verify's steps 1-5 with the same answers; on ok delete the enrollment, recovery codes and
        failures. Out: {disabled: true} or a refusal. Why: TOTP-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches: the store."""
        now = self._now()
        refusal, _method, _slot = self._check(user_id, code, now)
        if refusal is not None:
            return refusal
        self.store.delete_user(user_id)
        return {"disabled": True}

    def status(self, user_id: str) -> dict:
        """status: {enrolled, locked_until, recovery_required, recovery_codes_left}; reading it changes nothing.

        Why: the auth_system relation (mfa_enabled_check). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches: reads the store."""
        now = self._now()
        row = self.store.get_enrollment(user_id)
        enrolled = row is not None and row["confirmed_at"] is not None
        recent = self.store.failures_since(user_id, now - LOCK_SECONDS)
        locked_until = recent[LOCK_FAILURES - 1] + LOCK_SECONDS if len(recent) >= LOCK_FAILURES else None
        return {"enrolled": enrolled, "locked_until": locked_until,
                "recovery_required": bool(enrolled and row["failed_since_success"] >= HARD_LOCK_FAILURES),
                "recovery_codes_left": self.store.recovery_codes_left(user_id)}

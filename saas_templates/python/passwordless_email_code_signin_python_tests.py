"""Tests for passwordless_email_code_signin_python (docs/specs/passwordless_email_code_signin.md), with the spec's
fixed vectors.

Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
Touches: an in-memory SQLite database per test; the sender is a fake (no network, files or money).
"""
import hashlib
import os

import pytest

from passwordless_email_code_signin_python import (
    EmailCodeConfigError,
    EmailCodeSignin,
    SqliteEmailCodeStore,
    normalize_email,
)

SECRET = b"0123456789abcdef0123456789abcdef"
HOUR0 = 1699920000
IP = "203.0.113.7"
ACCEPTED = {"status": 202, "sent": True, "expires_in": 600}
INVALID = {"error": "invalid_code", "status": 400}
TOO_MANY = {"error": "too_many_requests", "status": 429}


class Clock:
    """A settable clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""

    def __init__(self, now: int):
        """Start at now. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.now = now

    def __call__(self) -> int:
        """The current time. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        return self.now


class FakeSender:
    """Records send_code calls; answers `result` or raises it when it is an exception. No network.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""

    def __init__(self, result=True):
        """In: the answer. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.result = result
        self.calls = []

    def send_code(self, to, code, expires_in_seconds):
        """Record and answer. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.calls.append((to, code, expires_in_seconds))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    def last_code(self):
        """The code of the last call. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        return self.calls[-1][1]


class CountingStore(SqliteEmailCodeStore):
    """A store that counts account reads and writes, to prove start never touches accounts.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""

    def __init__(self):
        """2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        super().__init__()
        self.account_calls = 0

    def find_account(self, email):
        """Count, then read. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.account_calls += 1
        return super().find_account(email)

    def insert_verified(self, account_id, email, now):
        """Count, then insert. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.account_calls += 1
        return super().insert_verified(account_id, email, now)


class ByteQueue:
    """random_bytes(n) from a queue, os.urandom once empty. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""

    def __init__(self, data: bytes = b""):
        """In: queued bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.data = bytearray(data)

    def __call__(self, n: int) -> bytes:
        """Serve n bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        if len(self.data) >= n:
            out = bytes(self.data[:n])
            del self.data[:n]
            return out
        return os.urandom(n)


def make(now=HOUR0, store=None, sender=None, codes=None, revoke=None, rnd=None):
    """A service; codes is a list of codes generate_code serves in order (None: the default generator).
    Out: (service, clock, sender, store). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    store = store or SqliteEmailCodeStore()
    clock = Clock(now)
    sender = sender or FakeSender()
    gen = None
    if codes is not None:
        queue = list(codes)
        gen = lambda: queue.pop(0)  # noqa: E731
    svc = EmailCodeSignin(store, SECRET, sender, clock=clock, random_bytes=rnd, generate_code=gen,
                          revoke_unproven=revoke)
    return svc, clock, sender, store


def attempts(store, svc, email):
    """The attempts of an address's code row, or None. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    r = store.conn.execute("SELECT attempts FROM email_codes WHERE email_hash = ?", (svc.email_hash(email),)).fetchone()
    return None if r is None else r[0]


def wrong(code):
    """Another 6-digit code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    return "%06d" % ((int(code) + 1) % 1000000)


# EMAILCODE-01
def test_emailcode_01_sign_up_then_sign_in():
    """start is 202 and sends one 6-digit code; verify makes a verified account (new_account true); a second sign-in
    gives the same id with new_account false; an unverified existing row calls revoke_unproven once and is then
    verified; an account made by verify never calls it. EMAILCODE-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    revoked = []
    svc, clock, sender, store = make(revoke=revoked.append)
    assert svc.start("user@example.com", IP) == ACCEPTED
    assert len(sender.calls) == 1
    to, code, ttl = sender.calls[0]
    assert to == "user@example.com" and ttl == 600 and len(code) == 6 and code.isascii() and code.isdigit()
    r = svc.verify("user@example.com", code, IP)
    assert r["status"] == 200 and r["new_account"] is True and r["email"] == "user@example.com"
    assert len(r["account_id"]) == 32
    acc = store.find_account("user@example.com")
    assert acc["id"] == r["account_id"] and acc["email_verified_at"] == HOUR0 and acc["status"] == "active"
    clock.now += 60
    svc.start("user@example.com", IP)
    r2 = svc.verify("user@example.com", sender.last_code(), IP)
    assert r2 == {"status": 200, "account_id": r["account_id"], "email": "user@example.com", "new_account": False}
    assert revoked == []
    store.conn.execute("INSERT INTO accounts (id, email, email_verified_at, status, created_at) "
                       "VALUES ('invited1', 'invited@example.com', NULL, 'active', 1)")
    svc.start("invited@example.com", IP)
    r3 = svc.verify("invited@example.com", sender.last_code(), IP)
    assert r3 == {"status": 200, "account_id": "invited1", "email": "invited@example.com", "new_account": False}
    assert revoked == ["invited1"]
    assert store.find_account("invited@example.com")["email_verified_at"] == clock.now


# EMAILCODE-02
def test_emailcode_02_storage_holds_only_keyed_hashes():
    """The spec's email_hash, code_hash and ip_hash; start stores that code_hash under that email_hash with the
    spec's rate_windows keys; nothing stored holds the address, the IP, the code or a plain SHA-256 of the code.
    EMAILCODE-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, _, _, store = make(codes=["123456"])
    assert svc.email_hash("user@example.com") == "587522269e243312a5d6f20bcdc78dc97a3e644e2ad702cdb94ac9550c03b346"
    assert svc.code_hash("user@example.com", "123456") == \
        "761f222c89dc1744c480d21e141277cc9af815ee0e2a1d7489c9282594728b5b"
    assert svc.ip_hash("203.0.113.7") == "e01c4eeb03c058165d49564dcaf561cf"
    assert svc.start("user@example.com", "203.0.113.7") == ACCEPTED
    assert store.conn.execute("SELECT email_hash, code_hash, attempts, expires_at FROM email_codes").fetchall() == [
        ("587522269e243312a5d6f20bcdc78dc97a3e644e2ad702cdb94ac9550c03b346",
         "761f222c89dc1744c480d21e141277cc9af815ee0e2a1d7489c9282594728b5b", 0, HOUR0 + 600)]
    keys = sorted(r[0] for r in store.conn.execute("SELECT key FROM rate_windows"))
    assert keys == sorted(["start-ip#e01c4eeb03c058165d49564dcaf561cf",
                           "start-email#587522269e243312a5d6f20bcdc78dc9",
                           "start-email-day#587522269e243312a5d6f20bcdc78dc9"])
    dump = "\n".join(line for line in store.conn.iterdump() if "email_codes" in line or "rate_windows" in line)
    for secret in ("user@example.com", "203.0.113.7", "123456", hashlib.sha256(b"123456").hexdigest()):
        assert secret not in dump


# EMAILCODE-03
def test_emailcode_03_single_use():
    """The right code a second time is 400 invalid_code. EMAILCODE-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    svc, _, sender, _ = make()
    svc.start("a@x.com", IP)
    assert svc.verify("a@x.com", sender.last_code(), IP)["status"] == 200
    assert svc.verify("a@x.com", sender.last_code(), IP) == INVALID


# EMAILCODE-04
def test_emailcode_04_expiry():
    """Accepted 599 seconds after start; 400 invalid_code at 600 seconds. EMAILCODE-04.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, clock, sender, store = make()
    svc.start("a@x.com", IP)
    clock.now = HOUR0 + 599
    assert svc.verify("a@x.com", sender.last_code(), IP)["status"] == 200
    svc2, clock2, sender2, store2 = make()
    svc2.start("a@x.com", IP)
    clock2.now = HOUR0 + 600
    assert svc2.verify("a@x.com", sender2.last_code(), IP) == INVALID
    assert attempts(store2, svc2, "a@x.com") is None


# EMAILCODE-05
def test_emailcode_05_five_tries_per_code():
    """After 5 wrong codes the right one is 400; after 4 wrong codes the right one (the 5th try) is accepted.
    EMAILCODE-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, _, sender, store = make()
    svc.start("a@x.com", IP)
    code = sender.last_code()
    for _ in range(5):
        assert svc.verify("a@x.com", wrong(code), IP) == INVALID
    assert attempts(store, svc, "a@x.com") is None
    assert svc.verify("a@x.com", code, IP) == INVALID
    svc, _, sender, _ = make()
    svc.start("b@x.com", IP)
    code = sender.last_code()
    for _ in range(4):
        assert svc.verify("b@x.com", wrong(code), IP) == INVALID
    assert svc.verify("b@x.com", code, IP)["status"] == 200


# EMAILCODE-06
def test_emailcode_06_new_start_replaces_the_code():
    """A new start replaces the code: the earlier code is 400, the new one is accepted, and the tries start at 0.
    EMAILCODE-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, _, sender, store = make(codes=["111111", "222222"])
    svc.start("a@x.com", IP)
    for _ in range(4):
        assert svc.verify("a@x.com", "999999", IP) == INVALID
    assert attempts(store, svc, "a@x.com") == 4
    svc.start("a@x.com", IP)
    assert attempts(store, svc, "a@x.com") == 0
    assert svc.verify("a@x.com", "111111", IP) == INVALID
    for _ in range(3):
        assert svc.verify("a@x.com", "999999", IP) == INVALID
    assert attempts(store, svc, "a@x.com") == 4
    assert svc.verify("a@x.com", "222222", IP)["status"] == 200


# EMAILCODE-07
def test_emailcode_07_no_enumeration():
    """start answers alike, sends alike and never reads accounts for a known and an unknown address; verify gives
    one 400 body for a wrong, an expired, a used code and an address that never asked. EMAILCODE-07.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    store = CountingStore()
    store.conn.execute("INSERT INTO accounts (id, email, email_verified_at, status, created_at) "
                       "VALUES ('k1', 'known@x.com', 1, 'active', 1)")
    svc, clock, sender, _ = make(store=store)
    assert svc.start("known@x.com", IP) == svc.start("unknown@x.com", IP) == ACCEPTED
    assert store.account_calls == 0
    (to1, c1, t1), (to2, c2, t2) = sender.calls
    assert (to1, t1, len(c1)) == ("known@x.com", 600, 6) and (to2, t2, len(c2)) == ("unknown@x.com", 600, 6)
    answers = [svc.verify("known@x.com", wrong(c1), IP)]
    assert svc.verify("known@x.com", c1, IP)["status"] == 200
    answers.append(svc.verify("known@x.com", c1, IP))
    clock.now += 600
    answers.append(svc.verify("unknown@x.com", c2, IP))
    answers.append(svc.verify("never@x.com", "123456", IP))
    assert answers == [INVALID] * 4


# EMAILCODE-08
def test_emailcode_08_sends_per_address():
    """The 6th start for one address in a clock hour is 429 and sends nothing; the next hour works; the 11th in a
    clock day is 429 (a refused start still counts toward the day). EMAILCODE-08.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, clock, sender, _ = make()
    for i in range(5):
        clock.now = HOUR0 + i
        assert svc.start("a@x.com", "198.51.100.%d" % i) == ACCEPTED
    assert svc.start("a@x.com", "198.51.100.9") == TOO_MANY
    assert len(sender.calls) == 5
    clock.now = HOUR0 + 3600
    for i in range(4):
        assert svc.start("a@x.com", IP) == ACCEPTED
    assert svc.start("a@x.com", IP) == TOO_MANY
    assert len(sender.calls) == 9
    clock.now = HOUR0 + 86400
    assert svc.start("a@x.com", IP) == ACCEPTED


# EMAILCODE-09
def test_emailcode_09_sends_per_ip():
    """The 21st start from one IP in a clock hour, each for another address, is 429; another IP is not affected.
    EMAILCODE-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, _, sender, _ = make()
    for i in range(20):
        assert svc.start("u%d@x.com" % i, IP) == ACCEPTED
    assert svc.start("u20@x.com", IP) == TOO_MANY
    assert svc.start("u20@x.com", "198.51.100.1") == ACCEPTED
    assert len(sender.calls) == 21


# EMAILCODE-10
def test_emailcode_10_tries_per_ip_and_per_address():
    """The 31st verify from one IP in a clock hour is 429 with the right code too; the 11th verify for one address
    in a clock hour is 429 from any IP however many new codes were sent. EMAILCODE-10.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, _, sender, _ = make()
    svc.start("target@x.com", "192.0.2.1")
    code = sender.last_code()
    for i in range(30):
        assert svc.verify("other%d@x.com" % i, "123456", IP) == INVALID
    assert svc.verify("target@x.com", code, IP) == TOO_MANY
    assert svc.verify("target@x.com", code, "192.0.2.50")["status"] == 200
    svc, _, sender, _ = make()
    n = 0
    for round_ in range(5):
        svc.start("a@x.com", "192.0.2.%d" % round_)
        for _ in range(2):
            assert svc.verify("a@x.com", "000000" if sender.last_code() != "000000" else "000001",
                              "198.51.100.%d" % n) == INVALID
            n += 1
    assert n == 10
    assert svc.verify("a@x.com", sender.last_code(), "203.0.113.99") == TOO_MANY


# EMAILCODE-11
def test_emailcode_11_input_forms():
    """" A@X.com " signs in a@x.com; malformed addresses are 422 at start and 400 at verify; only space, tab, CR and
    LF are trimmed and only A-Z lower-cased; "123 456" and "123-456" are accepted; 5 and 7 digits, letters and six
    non-ASCII digits are 400 and spend no try. EMAILCODE-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    assert normalize_email(" A@X.com ") == "a@x.com"
    bad = ["a@b", "a b@x.com", "a@x..com", ".a@x.com", "a@x.com,b@y.com", "<a@x.com>", "a@x.com ",
           "a@x.com\u000b", "a@x.com\u0000", "K@x.com", "", None, "a" * 250 + "@x.com"]
    for raw in bad:
        assert normalize_email(raw) is None, repr(raw)
    svc, _, sender, store = make(codes=["123456", "123456", "123456"])
    for raw in bad:
        assert svc.start(raw, IP) == {"error": "invalid_email", "status": 422}, repr(raw)
        assert svc.verify(raw, "123456", IP) == INVALID, repr(raw)
    assert sender.calls == []
    assert svc.start(" A@X.com ", IP) == ACCEPTED and sender.calls[-1][0] == "a@x.com"
    for code in ("12345", "1234567", "abcdef", "١٢٣٤٥٦", None):
        assert svc.verify("a@x.com", code, IP) == INVALID, repr(code)
    assert attempts(store, svc, "a@x.com") == 0
    assert svc.verify(" A@X.com ", "123 456", IP)["email"] == "a@x.com"
    svc.start("a@x.com", IP)
    assert svc.verify("a@x.com", "123-456", IP)["status"] == 200
    svc.start("a@x.com", IP)
    assert svc.verify("a@x.com", " 12-34 56 ", IP)["status"] == 200


# EMAILCODE-12
def test_emailcode_12_send_failure_and_configuration():
    """A sender that returns false or raises makes start 503 send_failed and leaves no code; a secret under 32
    bytes or no sender fails construction with not_configured. EMAILCODE-12. 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    for result in (False, RuntimeError("smtp down")):
        svc, _, sender, store = make(sender=FakeSender(result))
        assert svc.start("a@x.com", IP) == {"error": "send_failed", "status": 503}
        assert len(sender.calls) == 1
        assert store.conn.execute("SELECT COUNT(*) FROM email_codes").fetchone()[0] == 0
    store = SqliteEmailCodeStore()
    for secret, sender in ((SECRET[:31], FakeSender()), (SECRET, None), ("", FakeSender())):
        with pytest.raises(EmailCodeConfigError) as err:
            EmailCodeSignin(store, secret, sender)
        assert err.value.code == "not_configured"


# EMAILCODE-13
def test_emailcode_13_unavailable_accounts():
    """A suspended or closed account: the right code is 403 account_unavailable, and the code is used up.
    EMAILCODE-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, _, sender, store = make()
    for status in ("suspended", "closed"):
        email = status + "@x.com"
        store.conn.execute("INSERT INTO accounts (id, email, email_verified_at, status, created_at) "
                           "VALUES (?, ?, 1, ?, 1)", ("id_" + status, email, status))
        svc.start(email, IP)
        code = sender.last_code()
        assert svc.verify(email, code, IP) == {"error": "account_unavailable", "status": 403}
        assert attempts(store, svc, email) is None
        assert svc.verify(email, code, IP) == INVALID


# EMAILCODE-14
def test_emailcode_14_code_binding_and_generator():
    """A code sent to one address is 400 for another; an injected "000042" keeps its zeros and signs in; the
    default generator gives 6 digits and, from the spec's bytes, the spec's codes. EMAILCODE-14.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, _, sender, _ = make(codes=["000042", "000042"])
    svc.start("a@x.com", IP)
    assert svc.verify("b@x.com", "000042", IP) == INVALID
    svc.start("b@x.com", IP)
    assert sender.calls[-1][1] == "000042"
    assert svc.verify("b@x.com", "000042", IP)["status"] == 200
    assert svc.verify("a@x.com", "000042", IP)["status"] == 200
    rnd = ByteQueue(bytes.fromhex("ffffffff80000000fff13d7ffff13d800000002a"))
    gen, _, _, _ = make(rnd=rnd)
    assert [gen.generate_code() for _ in range(3)] == ["483648", "999999", "000042"]
    assert rnd.data == bytearray()
    plain, _, _, _ = make()
    for _ in range(50):
        c = plain.generate_code()
        assert len(c) == 6 and all("0" <= ch <= "9" for ch in c)

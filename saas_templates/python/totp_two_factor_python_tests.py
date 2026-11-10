"""Tests for totp_two_factor_python (docs/specs/totp_two_factor.md), with the spec's fixed vectors.

Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
Touches: an in-memory SQLite database per test. No network, files or money.
"""
import hashlib
import os

import pytest

from totp_two_factor_python import (
    Base32Error,
    SqliteTotpStore,
    TotpConfigError,
    TotpService,
    base32_decode,
    base32_encode,
    hotp,
    open_sealed,
    otpauth_uri,
    seal,
    totp_at,
)

K = b"12345678901234567890"
KB32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
ENC_KEY = bytes(range(32))
REC_KEY = bytes(range(0x40, 0x60))
NONCE = bytes(range(0xA0, 0xAC))
SEALED_VECTOR = "v1.oKGio6SlpqeoqaqroV0maQKFQOklPLSHVjWKjzfpA1TV+QA621cV0i7kP1B5d8k2owRGDhH/FzF0f662"
SPEC_CODES = ["29gq-y7en-w5ck", "t3ah-rz8f-px6d", "mv4b-js29-gqy5", "ckt3-ahrz-8fpx",
              "6dmv-4bjs-29gq", "y7en-w5ck-t8fp", "x6dm-v4bj-s29g", "qy7e-nw5c-kt3a"]


class Clock:
    """A settable clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""

    def __init__(self, now: int):
        """Start at now. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.now = now

    def __call__(self) -> int:
        """The current time. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        return self.now


class ByteQueue:
    """random_bytes(n) served from a queue in order, whatever n is asked; os.urandom once the queue is empty.
    Counts the bytes it served from the queue. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""

    def __init__(self, data: bytes = b""):
        """In: the queued bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.data = bytearray(data)
        self.served = 0

    def push(self, data: bytes) -> None:
        """Queue more bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.data += data

    def __call__(self, n: int) -> bytes:
        """Serve n bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        if len(self.data) >= n:
            out = bytes(self.data[:n])
            del self.data[:n]
            self.served += n
            return out
        return os.urandom(n)


def make(now=1111111000, rnd=None, store=None, enc_key=ENC_KEY):
    """A service with a fresh store (or the given one), the spec's keys and a settable clock.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: a new in-memory SQLite database."""
    clock = Clock(now)
    rnd = rnd or ByteQueue()
    store = store or SqliteTotpStore()
    return TotpService(store, enc_key, REC_KEY, "Example App", clock=clock, random_bytes=rnd), clock, rnd, store


def enroll(svc, clock, user="user_1", with_k=None):
    """enroll_start and enroll_confirm at the clock's time; with_k queues K first so the secret is K's.
    Out: (secret, recovery codes). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the service's store."""
    if with_k is not None:
        with_k.push(K)
    started = svc.enroll_start(user, "alice@example.com")
    secret = started["secret"]
    done = svc.enroll_confirm(user, totp_at(secret, clock.now))
    return secret, done["recovery_codes"]


def wrong_code(secret, now):
    """A 6-digit code equal to none of the three window codes at now. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    window = {totp_at(secret, now + d * 30) for d in (-1, 0, 1)}
    for i in range(1000000):
        c = str(i).zfill(6)
        if c not in window:
            return c


def failed_count(store, user):
    """The row's failed_since_success. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    return store.get_enrollment(user)["failed_since_success"]


def failure_rows(store, user):
    """How many totp_failures rows the user has. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    return store.conn.execute("SELECT COUNT(*) FROM totp_failures WHERE user_id = ?", (user,)).fetchone()[0]


# TOTP-01
def test_totp_01_hotp_and_totp_vectors():
    """RFC 4226 HOTP for counters 0-9, RFC 6238 SHA-1 TOTP in 8 and 6 digits (T = 20000000000 too), and a counter
    above 32 bits. TOTP-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    assert [hotp(K, c) for c in range(10)] == ["755224", "287082", "359152", "969429", "338314", "254676",
                                              "287922", "162583", "399871", "520489"]
    assert hotp(K, 4294967296) == "999456"
    table = [(59, "94287082", "287082"), (1111111109, "07081804", "081804"), (1111111111, "14050471", "050471"),
             (1234567890, "89005924", "005924"), (2000000000, "69279037", "279037"),
             (20000000000, "65353130", "353130")]
    for t, eight, six in table:
        assert totp_at(KB32, t, 8) == eight
        assert totp_at(KB32, t, 6) == six
        assert totp_at(KB32, t) == six


# TOTP-02
def test_totp_02_base32():
    """RFC 4648 vectors without padding and back; decode ignores spaces, dashes, "=" and case; bad characters and
    lengths 1, 3, 6 mod 8 are invalid_base32; generate_secret is 32 characters for 20 bytes. TOTP-02.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    vectors = {b"": "", b"f": "MY", b"fo": "MZXQ", b"foo": "MZXW6", b"foob": "MZXW6YQ", b"fooba": "MZXW6YTB",
               b"foobar": "MZXW6YTBOI"}
    for raw, enc in vectors.items():
        assert base32_encode(raw) == enc
        if enc:
            assert base32_decode(enc) == raw
    assert base32_encode(K) == KB32
    assert base32_decode("mzxw 6ytb-oi==") == b"foobar"
    assert base32_decode("MZ") == b"f"
    for bad in ("MZXW6YT1", "", "M", "MZX", "MZXW6Y", "MZ!W"):
        with pytest.raises(Base32Error) as err:
            base32_decode(bad)
        assert err.value.code == "invalid_base32"
    svc, _, _, _ = make()
    s = svc.generate_secret()
    assert len(s) == 32 and len(base32_decode(s)) == 20


# TOTP-03
def test_totp_03_enroll_start_seals_the_secret():
    """enroll_start returns the secret and the exact URI; the store holds only the sealed secret (the spec's string
    with the injected bytes); a second start before confirming replaces it. TOTP-03.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    rnd = ByteQueue(K + NONCE)
    svc, _, _, store = make(rnd=rnd)
    r = svc.enroll_start("user_1", "alice@example.com")
    assert r == {"secret": KB32, "otpauth_uri": "otpauth://totp/Example%20App%3Aalice%40example.com?secret="
                 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example%20App&algorithm=SHA1&digits=6&period=30"}
    assert otpauth_uri(KB32, "Example App", "alice@example.com") == r["otpauth_uri"]
    row = store.get_enrollment("user_1")
    assert row["secret_enc"] == SEALED_VECTOR and row["confirmed_at"] is None
    dump = "\n".join(store.conn.iterdump())
    assert KB32 not in dump
    r2 = svc.enroll_start("user_1", "alice@example.com")
    assert r2["secret"] != KB32
    assert store.get_enrollment("user_1")["secret_enc"] != SEALED_VECTOR
    assert store.conn.execute("SELECT COUNT(*) FROM totp_enrollments").fetchone()[0] == 1


# TOTP-04
def test_totp_04_enroll_confirm_and_recovery_codes():
    """enroll_confirm gives the spec's 8 codes from the spec's byte stream, stores only keyed hashes, the confirming
    code is then refused; 409 for a second confirm, for no enrollment and for enroll_start after confirming.
    TOTP-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    stream = bytes((7 * k) % 256 for k in range(200))
    rnd = ByteQueue(K + NONCE + stream)
    svc, clock, _, store = make(now=1111111109, rnd=rnd)
    assert svc.enroll_confirm("user_1", "081804") == {"error": "enrollment_not_started", "status": 409}
    svc.enroll_start("user_1", "alice@example.com")
    assert rnd.served == 32
    r = svc.enroll_confirm("user_1", "081804")
    assert r == {"recovery_codes": SPEC_CODES}
    assert rnd.served == 32 + 101
    hashes = [x[0] for x in store.conn.execute(
        "SELECT code_hash FROM totp_recovery_codes WHERE user_id = 'user_1' ORDER BY id").fetchall()]
    assert len(hashes) == 8
    assert hashes[0] == "d9199ecad0b35d9e2f18857343d7fe79dd5f8425f1c460c88fe18f5c4b4a2645"
    dump = "\n".join(store.conn.iterdump())
    for code in SPEC_CODES:
        assert code not in dump and code.replace("-", "") not in dump
    assert svc.verify("user_1", "081804") == {"error": "invalid_code", "status": 401}
    assert svc.enroll_confirm("user_1", "081804") == {"error": "already_enrolled", "status": 409}
    assert svc.enroll_start("user_1", "alice@example.com") == {"error": "already_enrolled", "status": 409}


# TOTP-05
def test_totp_05_window():
    """The previous, current and next step are accepted; two steps back and two ahead are 401 (refusals first).
    TOTP-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, clock, rnd, _ = make(now=1111111000)
    enroll(svc, clock, with_k=rnd)
    clock.now = 1111111109
    assert svc.verify("user_1", "150727") == {"error": "invalid_code", "status": 401}
    assert svc.verify("user_1", "266759") == {"error": "invalid_code", "status": 401}
    for code in ("731029", "081804", "050471"):
        r = svc.verify("user_1", code)
        assert r["ok"] is True and r["method"] == "totp" and r["recovery_codes_left"] == 8, code


# TOTP-06
def test_totp_06_replay_guard():
    """An accepted code is 401 the second time; an earlier step after a later one is 401; a later step is
    accepted; the store's claim succeeds once per step. TOTP-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    svc, clock, rnd, store = make(now=1111111000)
    enroll(svc, clock, with_k=rnd)
    clock.now = 1111111109
    assert svc.verify("user_1", "081804")["ok"] is True
    assert svc.verify("user_1", "081804") == {"error": "invalid_code", "status": 401}
    assert svc.verify("user_1", "731029") == {"error": "invalid_code", "status": 401}
    assert svc.verify("user_1", "050471")["ok"] is True
    step = store.get_enrollment("user_1")["last_used_step"]
    assert store.claim("user_1", step + 5) is True
    assert store.claim("user_1", step + 5) is False


# TOTP-07
def test_totp_07_input_forms():
    """"081 804" and "081-804" are accepted like "081804"; 5 and 7 digits, letters, "", None, over 64 characters
    and non-ASCII digits are 401 invalid_code and each adds one failure. TOTP-07.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, clock, rnd, store = make(now=1111111000)
    for i, spelling in enumerate(("081804", "081 804", "081-804")):
        clock.now = 1111111000
        enroll(svc, clock, user="ok_%d" % i, with_k=rnd)
        clock.now = 1111111109
        assert svc.verify("ok_%d" % i, spelling)["ok"] is True, spelling
    bad = ["08180", "0818041", "abcdef", "", None, "081804" + " " * 59, "٠٨١٨٠٤"]
    for i, code in enumerate(bad):
        user = "bad_%d" % i
        clock.now = 1111111000
        enroll(svc, clock, user=user, with_k=rnd)
        clock.now = 1111111109
        assert svc.verify(user, code) == {"error": "invalid_code", "status": 401}, repr(code)
        assert failed_count(store, user) == 1 and failure_rows(store, user) == 1, repr(code)


# TOTP-08
def test_totp_08_recovery_codes():
    """A recovery code signs in once (left 7), also in upper case and without dashes; used again 401; another user's
    code 401; its stored hash is the spec's keyed hash, not a plain SHA-256. TOTP-08.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, clock, rnd, store = make(now=1111111000)
    _, codes_a = enroll(svc, clock, user="user_a")
    _, codes_b = enroll(svc, clock, user="user_b")
    assert svc.verify("user_a", codes_a[0]) == {"ok": True, "method": "recovery_code", "recovery_codes_left": 7}
    assert svc.verify("user_a", codes_a[0]) == {"error": "invalid_code", "status": 401}
    assert svc.verify("user_a", codes_a[1].upper())["recovery_codes_left"] == 6
    assert svc.verify("user_a", codes_a[2].replace("-", ""))["recovery_codes_left"] == 5
    assert svc.verify("user_b", codes_a[3]) == {"error": "invalid_code", "status": 401}
    assert svc.recovery_code_hash("user_1", "k7mq2xpt9hcw") == \
        "5a93360f78c7f03de7336a625adf93bf238749d8da4aaf734271b327c52347a3"
    stored = {x[0] for x in store.conn.execute("SELECT code_hash FROM totp_recovery_codes").fetchall()}
    assert svc.recovery_code_hash("user_a", codes_a[4].replace("-", "")) in stored
    assert hashlib.sha256(codes_a[4].replace("-", "").encode()).hexdigest() not in stored
    assert hashlib.sha256(codes_a[4].encode()).hexdigest() not in stored


# TOTP-09
def test_totp_09_lock():
    """5 failures in 900 s lock the next verify (429 locked with retry_after, a correct code too, no failure added);
    still locked at 899 s after the oldest, accepted at 900 s; the store's try write succeeds 5 times, not a 6th.
    TOTP-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, clock, rnd, store = make(now=1111111000)
    secret, _ = enroll(svc, clock)
    t0 = 1111111109
    clock.now = t0
    for _ in range(5):
        assert svc.verify("user_1", wrong_code(secret, t0)) == {"error": "invalid_code", "status": 401}
    assert svc.verify("user_1", totp_at(secret, t0)) == {"error": "locked", "status": 429, "retry_after": 900}
    assert failed_count(store, "user_1") == 5 and failure_rows(store, "user_1") == 5
    assert svc.status("user_1")["locked_until"] == t0 + 900
    clock.now = t0 + 899
    assert svc.verify("user_1", totp_at(secret, clock.now)) == {"error": "locked", "status": 429, "retry_after": 1}
    clock.now = t0 + 900
    r = svc.verify("user_1", totp_at(secret, clock.now))
    assert r["ok"] is True and r["method"] == "totp"
    slots = [store.try_slot("fresh", 5000) for _ in range(6)]
    assert all(s is not None for s in slots[:5]) and slots[5] is None


# TOTP-10
def test_totp_10_unreadable_secret():
    """A secret sealed under another key, or with one changed character, is 503 secret_unreadable for a 6-digit
    code, adds no failure, and a recovery code still signs in. TOTP-10.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, clock, rnd, store = make(now=1111111000)
    secret, codes = enroll(svc, clock)
    other = TotpService(store, bytes(range(1, 33)), REC_KEY, "Example App", clock=clock, random_bytes=rnd)
    clock.now = 1111111109
    assert other.verify("user_1", totp_at(secret, clock.now)) == {"error": "secret_unreadable", "status": 503}
    assert failed_count(store, "user_1") == 0 and failure_rows(store, "user_1") == 0
    assert other.verify("user_1", codes[0])["method"] == "recovery_code"
    enc = store.get_enrollment("user_1")["secret_enc"]
    changed = enc[:10] + ("A" if enc[10] != "A" else "B") + enc[11:]
    store.conn.execute("UPDATE totp_enrollments SET secret_enc = ? WHERE user_id = 'user_1'", (changed,))
    assert svc.verify("user_1", totp_at(secret, clock.now)) == {"error": "secret_unreadable", "status": 503}
    assert failed_count(store, "user_1") == 0 and failure_rows(store, "user_1") == 0
    assert svc.verify("user_1", codes[1]) == {"ok": True, "method": "recovery_code", "recovery_codes_left": 6}


# TOTP-11
def test_totp_11_seal_open_and_key_sizes():
    """seal gives the spec's string and open returns the secret; another aad, another key or one changed character
    gives nothing; wrong key sizes fail construction. TOTP-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    sealed = seal(ENC_KEY, NONCE, KB32, "totp:user_1")
    assert sealed == SEALED_VECTOR
    assert open_sealed(ENC_KEY, sealed, "totp:user_1") == KB32
    assert open_sealed(ENC_KEY, sealed, "totp:user_2") is None
    assert open_sealed(bytes(range(1, 33)), sealed, "totp:user_1") is None
    changed = sealed[:20] + ("A" if sealed[20] != "A" else "B") + sealed[21:]
    assert open_sealed(ENC_KEY, changed, "totp:user_1") is None
    assert open_sealed(ENC_KEY, sealed[3:], "totp:user_1") is None
    assert open_sealed(ENC_KEY, "v1.!!!", "totp:user_1") is None
    assert open_sealed(ENC_KEY, "v1.AAAA", "totp:user_1") is None
    store = SqliteTotpStore()
    for enc, rec in ((bytes(31), REC_KEY), (bytes(33), REC_KEY), (ENC_KEY, bytes(31))):
        with pytest.raises(TotpConfigError) as err:
            TotpService(store, enc, rec, "x")
        assert err.value.code == "invalid_key"
    assert TotpService(store, ENC_KEY, bytes(64), "x") is not None


# TOTP-12
def test_totp_12_disable():
    """disable with a valid code deletes the enrollment, its recovery codes and failures, then verify is 409
    not_enrolled; disable with a wrong code is 401 and deletes nothing. TOTP-12.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, clock, rnd, store = make(now=1111111000)
    secret, _ = enroll(svc, clock)
    clock.now = 1111111109
    assert svc.disable("user_1", wrong_code(secret, clock.now)) == {"error": "invalid_code", "status": 401}
    assert store.get_enrollment("user_1") is not None and store.recovery_codes_left("user_1") == 8
    assert failure_rows(store, "user_1") == 1
    assert svc.disable("user_1", totp_at(secret, clock.now)) == {"disabled": True}
    assert store.get_enrollment("user_1") is None
    assert store.recovery_codes_left("user_1") == 0 and failure_rows(store, "user_1") == 0
    assert svc.verify("user_1", totp_at(secret, clock.now + 30)) == {"error": "not_enrolled", "status": 409}
    assert "secret" in svc.enroll_start("user_1", "alice@example.com")


# TOTP-13
def test_totp_13_not_enrolled_and_user_isolation():
    """verify and disable before enroll_confirm are 409 not_enrolled, with the right code too; two users with
    different secrets never accept each other's codes. TOTP-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    svc, clock, rnd, store = make(now=1111111000)
    secret = svc.enroll_start("user_1", "a")["secret"]
    right = totp_at(secret, clock.now)
    assert svc.verify("user_1", right) == {"error": "not_enrolled", "status": 409}
    assert svc.disable("user_1", right) == {"error": "not_enrolled", "status": 409}
    assert svc.verify("nobody", right) == {"error": "not_enrolled", "status": 409}
    assert svc.enroll_confirm("user_1", right)["recovery_codes"]
    secret_b, _ = enroll(svc, clock, user="user_b")
    assert secret_b != secret
    clock.now = 1111111109
    code_a, code_b = totp_at(secret, clock.now), totp_at(secret_b, clock.now)
    assert code_a != code_b
    assert svc.verify("user_b", code_a) == {"error": "invalid_code", "status": 401}
    assert svc.verify("user_1", code_b) == {"error": "invalid_code", "status": 401}
    assert svc.verify("user_1", code_a)["ok"] is True
    assert svc.verify("user_b", code_b)["ok"] is True


def _fail_windows(svc, clock, secret, user, failures):
    """Add `failures` wrong codes, 5 per window, moving the clock 900 s between windows. Out: nothing.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the service's store."""
    done = 0
    while done < failures:
        for _ in range(min(5, failures - done)):
            assert svc.verify(user, wrong_code(secret, clock.now)) == {"error": "invalid_code", "status": 401}
            done += 1
        clock.now += 900


# TOTP-14
def test_totp_14_hard_lock_after_100_failures():
    """After 100 failures with no success a correct code is 429 recovery_required however far the clock moves and
    adds no failure; a recovery code signs in and resets; a success before the 100th starts the count again.
    TOTP-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, clock, rnd, store = make(now=1111111000)
    secret, codes = enroll(svc, clock)
    clock.now += 900
    _fail_windows(svc, clock, secret, "user_1", 100)
    assert failed_count(store, "user_1") == 100
    assert svc.verify("user_1", totp_at(secret, clock.now)) == {"error": "recovery_required", "status": 429}
    clock.now += 10 ** 7
    assert svc.verify("user_1", totp_at(secret, clock.now)) == {"error": "recovery_required", "status": 429}
    assert failed_count(store, "user_1") == 100
    assert svc.status("user_1")["recovery_required"] is True
    assert svc.verify("user_1", codes[0])["method"] == "recovery_code"
    assert failed_count(store, "user_1") == 0
    clock.now += 30
    assert svc.verify("user_1", totp_at(secret, clock.now))["method"] == "totp"
    # a success before the 100th failure starts the count again
    clock.now += 900
    _fail_windows(svc, clock, secret, "user_1", 99)
    assert failed_count(store, "user_1") == 99
    assert svc.verify("user_1", totp_at(secret, clock.now))["method"] == "totp"
    _fail_windows(svc, clock, secret, "user_1", 5)
    assert failed_count(store, "user_1") == 5
    assert svc.verify("user_1", totp_at(secret, clock.now))["method"] == "totp"

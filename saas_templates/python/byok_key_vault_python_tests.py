"""Tests for byok_key_vault_python (docs/specs/byok_key_vault.md), with the spec's fixed vectors.

Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
Touches: an in-memory SQLite database per test; the provider client is a fake (no network, files or money).
"""
import base64
import json
import os
import sqlite3

import pytest

from byok_key_vault_python import KeyVault, SqliteVaultStore, VaultConfigError

KEY = "acme_" + "k3y0123456789abcdefghWXYZ"
K1 = bytes(range(32))
K2 = bytes(range(0x40, 0x60))
PROVIDERS = {"acme": {"prefix": "acme_", "min_length": 24, "max_length": 200},
             "beta": {"prefix": "beta_", "min_length": 24, "max_length": 200}}
SPEC_BYTES = bytes(range(0x20, 0x40)) + bytes(range(0x60, 0x6C)) + bytes(range(0x70, 0x7C))
SPEC_CIPHERTEXT = "YGFiY2RlZmdoaWprg/fAzqy7SCzJdVWPIX9FTko++mAiaT2vbM/uMNaLHZjhWoVBGl1vBtJurMStRQ=="
SPEC_WRAPPED = "cHFyc3R1dnd4eXp7N6aYBJfsuhNsAxz5/W2f+J0G974wrnqNnbcDf3iKKAEOSVqlT/aJkU58qxAv2nPf"
SPEC_REWRAPPED = "gIGCg4SFhoeIiYqLDX+c5AZRDKRAQ7oDXo+7DcjN++F5UtAjxrdC7+0oX0MOT3cH13mFkfvVnrrN/V6R"
HOUR0 = 1699920000


class Clock:
    """A settable clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""

    def __init__(self, now: int):
        """Start at now. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.now = now

    def __call__(self) -> int:
        """The current time. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        return self.now


class ByteQueue:
    """random_bytes(n) from a queue in order; os.urandom once it is empty. 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""

    def __init__(self, data: bytes = b""):
        """In: queued bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.data = bytearray(data)

    def push(self, data: bytes) -> None:
        """Queue more bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.data += data

    def __call__(self, n: int) -> bytes:
        """Serve n bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        if len(self.data) >= n:
            out = bytes(self.data[:n])
            del self.data[:n]
            return out
        return os.urandom(n)


class FakeProvider:
    """A provider client that records its calls and answers a fixed verdict, or raises. No network.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""

    def __init__(self, verdict="ok"):
        """In: the verdict, or an exception instance to raise. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.verdict = verdict
        self.calls = []

    def check(self, provider, key):
        """Record the call; answer or raise. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.calls.append((provider, key))
        if isinstance(self.verdict, Exception):
            raise self.verdict
        return self.verdict


class FailingAuditStore(SqliteVaultStore):
    """A store whose key_used audit write fails, to prove use_key returns no key then. 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""

    fail_actions = ("key_used",)

    def _insert_audit(self, conn, user_id, provider, action, purpose, key_id, at):
        """Raise for the actions in fail_actions. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        if action in self.fail_actions:
            raise sqlite3.OperationalError("audit write failed")
        super()._insert_audit(conn, user_id, provider, action, purpose, key_id, at)


def make(store=None, keys=None, active="k1", client=None, rnd=None, now=HOUR0):
    """A vault with the spec's provider config and keyring (or the given ones). Out: (vault, clock, client, rnd,
    store). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: a new in-memory SQLite database."""
    store = store or SqliteVaultStore()
    clock = Clock(now)
    client = client or FakeProvider()
    rnd = rnd or ByteQueue()
    vault = KeyVault(store, keys or {"k1": K1}, active, PROVIDERS, client, clock=clock, random_bytes=rnd)
    return vault, clock, client, rnd, store


def dump(store):
    """Every table's content as text. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    return "\n".join(store.conn.iterdump())


def count(store, table):
    """Rows in a table. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    return store.conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]


# VAULT-01
def test_vault_01_save_happy_path():
    """The provider check is called once with the key; the row holds key_id, wrapped_dek, ciphertext and the hint
    and nowhere the key; the answer's shape; a key_saved audit row. VAULT-01.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    vault, clock, client, _, store = make()
    r = vault.save_key("user_1", "acme", KEY)
    assert r == {"provider": "acme", "hint": "WXYZ", "key_id": "k1", "created_at": HOUR0}
    assert client.calls == [("acme", KEY)]
    row = store.get_row("user_1", "acme")
    assert row["key_id"] == "k1" and row["hint"] == "WXYZ" and row["wrapped_dek"] and row["ciphertext"]
    assert row["last_used_at"] is None
    assert KEY not in dump(store) and "k3y0123456789abcdefgh" not in dump(store)
    assert vault.list_audit("user_1") == [
        {"at": HOUR0, "action": "key_saved", "provider": "acme", "purpose": None, "key_id": "k1"}]


# VAULT-02
def test_vault_02_known_answer():
    """With k1, the injected bytes and the spec's key, the stored ciphertext and wrapped_dek are the spec's
    strings and use_key returns the key. VAULT-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    vault, _, _, _, store = make(rnd=ByteQueue(SPEC_BYTES))
    vault.save_key("user_1", "acme", KEY)
    row = store.get_row("user_1", "acme")
    assert row["ciphertext"] == SPEC_CIPHERTEXT
    assert row["wrapped_dek"] == SPEC_WRAPPED
    assert vault.use_key("user_1", "acme", "chat.completion") == {"key": KEY}


# VAULT-03
def test_vault_03_format_checks():
    """unknown_provider and invalid_key_format (wrong prefix, short, long, space or line break inside, not text,
    U+00A0 / U+000B / U+0000 after it); only space, tab, CR, LF are trimmed; the client is never called and nothing
    is stored. VAULT-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    vault, _, client, _, store = make()
    assert vault.save_key("user_1", "nope", KEY) == {"error": "unknown_provider", "status": 404}
    bad = ["beta_" + "k3y0123456789abcdefghWXYZ", "acme_" + "a" * 18, "acme_" + "a" * 196,
           "acme_k3y0123 456789abcdefghWXYZ", "acme_k3y0123\n456789abcdefghWXYZ", None, b"acme_k3y0123456789abcdWXYZ",
           12345, KEY + " ", KEY + "\u000b", KEY + "\u0000", "acme_k3y0123456789abcdefghéXYZ"]
    for k in bad:
        assert vault.save_key("user_1", "acme", k) == {"error": "invalid_key_format", "status": 400}, repr(k)
    assert client.calls == []
    for table in ("provider_keys", "provider_key_audit", "provider_key_save_windows"):
        assert count(store, table) == 0
    assert vault.save_key("user_1", "acme", "acme_" + "a" * 19)["hint"] == "aaaa"
    assert vault.save_key("user_1", "acme", "acme_" + "a" * 195)["hint"] == "aaaa"
    r = vault.save_key("user_1", "acme", " \t\r\n" + KEY + "\n\r\t ")
    assert r["hint"] == "WXYZ" and client.calls[-1] == ("acme", KEY)
    assert vault.use_key("user_1", "acme", "test") == {"key": KEY}


# VAULT-04
def test_vault_04_provider_answers():
    """"rejected" -> 400 key_rejected; "unreachable", another answer or a raised error -> 502 provider_unreachable;
    no row and no audit row, but the check is counted. VAULT-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    cases = [("rejected", {"error": "key_rejected", "status": 400}),
             ("unreachable", {"error": "provider_unreachable", "status": 502}),
             ("maybe", {"error": "provider_unreachable", "status": 502}),
             (None, {"error": "provider_unreachable", "status": 502}),
             (RuntimeError("boom " + KEY), {"error": "provider_unreachable", "status": 502})]
    store = SqliteVaultStore()
    for i, (verdict, want) in enumerate(cases):
        client = FakeProvider(verdict)
        vault, _, _, _, _ = make(store=store, client=client)
        r = vault.save_key("user_1", "acme", KEY)
        assert r == want, repr(verdict)
        assert KEY not in json.dumps(r)
        assert len(client.calls) == 1
    assert count(store, "provider_keys") == 0 and count(store, "provider_key_audit") == 0
    assert store.conn.execute("SELECT count FROM provider_key_save_windows WHERE user_id = 'user_1'").fetchone()[0] == 5


# VAULT-05
def test_vault_05_list_keys():
    """list_keys gives provider, hint, key_id, created_at, last_used_at sorted by provider, and its serialized form
    holds neither the key nor ciphertext nor wrapped_dek. VAULT-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    vault, clock, _, _, store = make()
    beta_key = "beta_" + "z9y8x7w6v5u4t3s2r1q0ABCD"
    vault.save_key("user_1", "beta", beta_key)
    clock.now += 5
    vault.save_key("user_1", "acme", KEY)
    listed = vault.list_keys("user_1")
    assert listed == [
        {"provider": "acme", "hint": "WXYZ", "key_id": "k1", "created_at": HOUR0 + 5, "last_used_at": None},
        {"provider": "beta", "hint": "ABCD", "key_id": "k1", "created_at": HOUR0, "last_used_at": None}]
    blob = json.dumps(listed)
    for p in ("acme", "beta"):
        row = store.get_row("user_1", p)
        assert row["ciphertext"] not in blob and row["wrapped_dek"] not in blob
    assert KEY not in blob and beta_key not in blob


# VAULT-06
def test_vault_06_use_key_records_every_use():
    """use_key returns the key, sets last_used_at, writes key_used with the purpose; bad purposes are 400; a failed
    audit write is 500 storage_failed with no key; no audit row or refusal holds the key. VAULT-06.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    vault, clock, _, _, store = make()
    vault.save_key("user_1", "acme", KEY)
    clock.now += 60
    assert vault.use_key("user_1", "acme", "chat.completion:v1") == {"key": KEY}
    assert store.get_row("user_1", "acme")["last_used_at"] == HOUR0 + 60
    assert vault.list_audit("user_1")[-1] == {"at": HOUR0 + 60, "action": "key_used", "provider": "acme",
                                              "purpose": "chat.completion:v1", "key_id": "k1"}
    refusals = []
    for purpose in ("", "has space", "semi;colon", "x" * 101, None, "café"):
        r = vault.use_key("user_1", "acme", purpose)
        assert r == {"error": "invalid_purpose", "status": 400}, repr(purpose)
        refusals.append(r)
    assert vault.use_key("user_1", "acme", "x" * 100) == {"key": KEY}
    failing = FailingAuditStore()
    v2, c2, _, _, _ = make(store=failing)
    v2.save_key("user_1", "acme", KEY)
    c2.now += 60
    r = v2.use_key("user_1", "acme", "chat")
    assert r == {"error": "storage_failed", "status": 500}
    refusals.append(r)
    assert failing.get_row("user_1", "acme")["last_used_at"] is None
    assert [a["action"] for a in v2.list_audit("user_1")] == ["key_saved"]
    assert KEY not in json.dumps(refusals)
    assert KEY not in json.dumps(vault.list_audit("user_1"))


# VAULT-07
def test_vault_07_isolation():
    """User B's list is empty, B's use_key for A's provider is 404, B's delete is {deleted: false}; A's key is
    untouched. VAULT-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    vault, _, _, _, store = make()
    vault.save_key("user_a", "acme", KEY)
    assert vault.list_keys("user_b") == []
    assert vault.use_key("user_b", "acme", "chat") == {"error": "key_not_found", "status": 404}
    assert vault.delete_key("user_b", "acme") == {"deleted": False}
    assert vault.use_key("user_a", "acme", "chat") == {"key": KEY}
    assert vault.list_audit("user_b") == []


def _xor_byte_20(value: str) -> str:
    """Decode base64, XOR 01 into byte 20, encode again. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    raw = bytearray(base64.b64decode(value))
    raw[20] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


# VAULT-08
def test_vault_08_tampered_rows_are_unreadable():
    """A row moved to another user or provider, one changed byte of the decoded ciphertext or wrapped_dek, and a
    value that is not base64 or too short are each 500 key_unreadable, never an exception. VAULT-08.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    unreadable = {"error": "key_unreadable", "status": 500}

    def fresh():
        """A vault with user_1's key saved. Out: (vault, store). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
        vault, _, _, _, store = make()
        vault.save_key("user_1", "acme", KEY)
        return vault, store

    vault, store = fresh()
    store.conn.execute("UPDATE provider_keys SET user_id = 'user_2'")
    assert vault.use_key("user_2", "acme", "chat") == unreadable
    vault, store = fresh()
    store.conn.execute("UPDATE provider_keys SET provider = 'beta'")
    assert vault.use_key("user_1", "beta", "chat") == unreadable
    for column in ("ciphertext", "wrapped_dek"):
        vault, store = fresh()
        value = store.get_row("user_1", "acme")[column]
        store.conn.execute("UPDATE provider_keys SET " + column + " = ?", (_xor_byte_20(value),))
        assert vault.use_key("user_1", "acme", "chat") == unreadable, column
        for broken in ("not base64 !!", base64.b64encode(b"x" * 27).decode()):
            store.conn.execute("UPDATE provider_keys SET " + column + " = ?", (broken,))
            assert vault.use_key("user_1", "acme", "chat") == unreadable, (column, broken)


# VAULT-09
def test_vault_09_save_again_replaces():
    """Saving again for the same provider: one row, a new DEK and new nonces, the new hint, use_key gives the new
    key. VAULT-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    vault, _, _, _, store = make()
    vault.save_key("user_1", "acme", KEY)
    first = store.get_row("user_1", "acme")
    new_key = "acme_" + "n3wk3y0123456789abcdQRST"
    assert vault.save_key("user_1", "acme", new_key)["hint"] == "QRST"
    second = store.get_row("user_1", "acme")
    assert count(store, "provider_keys") == 1
    assert second["hint"] == "QRST"
    assert second["ciphertext"] != first["ciphertext"] and second["wrapped_dek"] != first["wrapped_dek"]
    assert base64.b64decode(second["ciphertext"])[:12] != base64.b64decode(first["ciphertext"])[:12]
    assert base64.b64decode(second["wrapped_dek"])[:12] != base64.b64decode(first["wrapped_dek"])[:12]
    assert vault.use_key("user_1", "acme", "chat") == {"key": new_key}


# VAULT-10
def test_vault_10_rotation_and_rewrap():
    """With k2 active a new save is under k2; rewrap() re-wraps the k1 row under k2 (the spec's string with the
    injected nonce), changes no ciphertext, returns {rewrapped: 1, failed: 0}; without k1 every key opens; the
    store's rewrap write changes nothing when wrapped_dek changed meanwhile. VAULT-10.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    v1, clock, _, _, store = make(rnd=ByteQueue(SPEC_BYTES))
    v1.save_key("user_1", "acme", KEY)
    rnd2 = ByteQueue()
    v2 = KeyVault(store, {"k1": K1, "k2": K2}, "k2", PROVIDERS, FakeProvider(), clock=clock, random_bytes=rnd2)
    other_key = "acme_" + "0th3rk3y456789abcdefLMNO"
    assert v2.save_key("user_2", "acme", other_key)["key_id"] == "k2"
    rnd2.push(bytes(range(0x80, 0x8C)))
    assert v2.rewrap() == {"rewrapped": 1, "failed": 0}
    row = store.get_row("user_1", "acme")
    assert row["key_id"] == "k2" and row["wrapped_dek"] == SPEC_REWRAPPED and row["ciphertext"] == SPEC_CIPHERTEXT
    assert v2.list_audit("user_1")[-1]["action"] == "key_rewrapped"
    assert v2.rewrap() == {"rewrapped": 0, "failed": 0}
    v3 = KeyVault(store, {"k2": K2}, "k2", PROVIDERS, FakeProvider(), clock=clock)
    assert v3.use_key("user_1", "acme", "chat") == {"key": KEY}
    assert v3.use_key("user_2", "acme", "chat") == {"key": other_key}
    assert store.rewrap_row("user_1", "acme", "k2", "AAAA", "not-the-wrapped-dek-read", clock.now) is False
    assert store.get_row("user_1", "acme")["wrapped_dek"] == SPEC_REWRAPPED


# VAULT-11
def test_vault_11_keyring_and_config_checks():
    """A row under a key_id not in the keyring is 503 key_unavailable; bad master keys and an absent active id fail
    with invalid_master_key; min_length under prefix + 16 fails with invalid_provider_config. VAULT-11.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    vault, _, _, _, store = make()
    vault.save_key("user_1", "acme", KEY)
    store.conn.execute("UPDATE provider_keys SET key_id = 'k9'")
    assert vault.use_key("user_1", "acme", "chat") == {"error": "key_unavailable", "status": 503}
    s = SqliteVaultStore()
    for keys, active in (({"k1": bytes(31)}, "k1"), ({"k1": bytes(33)}, "k1"), ({"k1": K1}, "k2"),
                         ({"bad id!": K1}, "bad id!"), ({}, "k1")):
        with pytest.raises(VaultConfigError) as err:
            KeyVault(s, keys, active, PROVIDERS, FakeProvider())
        assert err.value.code == "invalid_master_key"
    for cfg in ({"prefix": "acme_", "min_length": 20, "max_length": 200},
                {"prefix": "acme_", "min_length": 24, "max_length": 5000},
                {"prefix": "acme_", "min_length": 30, "max_length": 24}):
        with pytest.raises(VaultConfigError) as err:
            KeyVault(s, {"k1": K1}, "k1", {"acme": cfg}, FakeProvider())
        assert err.value.code == "invalid_provider_config"
    assert KeyVault(s, {"k1": K1}, "k1", {"acme": {"prefix": "acme_", "min_length": 21, "max_length": 21}},
                    FakeProvider()) is not None


# VAULT-12
def test_vault_12_hourly_check_limit():
    """At most 10 provider checks per user per clock hour: the 11th is 429 with retry_after and calls no provider;
    another user is not affected; the next hour works; a malformed key does not count; the store's window write
    succeeds 10 times, not an 11th. VAULT-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    vault, clock, client, _, store = make(now=HOUR0)
    assert vault.save_key("user_1", "acme", "acme_short")["error"] == "invalid_key_format"
    for i in range(10):
        clock.now = HOUR0 + i
        assert vault.save_key("user_1", "acme", KEY)["hint"] == "WXYZ"
    clock.now = HOUR0 + 600
    assert vault.save_key("user_1", "acme", KEY) == {"error": "rate_limited", "status": 429, "retry_after": 3000}
    assert len(client.calls) == 10
    assert vault.save_key("user_2", "acme", KEY)["hint"] == "WXYZ"
    clock.now = HOUR0 + 3600
    assert vault.save_key("user_1", "acme", KEY)["hint"] == "WXYZ"
    results = [store.bump_window("u_w", HOUR0) for _ in range(11)]
    assert results == [True] * 10 + [False]


# VAULT-13
def test_vault_13_delete():
    """delete_key removes the row and writes key_deleted; a second delete is {deleted: false} with no audit row;
    use_key is then 404. VAULT-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    vault, clock, _, _, store = make()
    vault.save_key("user_1", "acme", KEY)
    clock.now += 10
    assert vault.delete_key("user_1", "acme") == {"deleted": True}
    assert store.get_row("user_1", "acme") is None
    assert vault.delete_key("user_1", "acme") == {"deleted": False}
    assert [a["action"] for a in vault.list_audit("user_1")] == ["key_saved", "key_deleted"]
    assert vault.list_audit("user_1")[-1] == {"at": HOUR0 + 10, "action": "key_deleted", "provider": "acme",
                                              "purpose": None, "key_id": "k1"}
    assert vault.use_key("user_1", "acme", "chat") == {"error": "key_not_found", "status": 404}


# VAULT-13
def test_vault_13_delete_with_failing_store():
    """When the key_deleted audit write fails, delete_key returns 500 storage_failed (not an exception), the row
    stays (the transaction rolled back) and no key_deleted row exists; on a working store the delete then succeeds.
    In: none. Out: assertions. Why: VAULT-13, spec CONVENTIONS; review finding 4525101312.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    failing = FailingAuditStore()
    vault, clock, _, _, _ = make(store=failing)
    vault.save_key("user_1", "acme", KEY)
    failing.fail_actions = ("key_deleted",)
    clock.now += 10
    assert vault.delete_key("user_1", "acme") == {"error": "storage_failed", "status": 500}
    assert failing.get_row("user_1", "acme") is not None
    assert [a["action"] for a in vault.list_audit("user_1")] == ["key_saved"]
    failing.fail_actions = ()
    assert vault.delete_key("user_1", "acme") == {"deleted": True}


# VAULT-14
def test_vault_14_real_randomness():
    """With real randomness the same key for two users gives different ciphertext, wrapped_dek and nonces.
    VAULT-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    store = SqliteVaultStore()
    vault = KeyVault(store, {"k1": K1}, "k1", PROVIDERS, FakeProvider())
    vault.save_key("user_a", "acme", KEY)
    vault.save_key("user_b", "acme", KEY)
    a, b = store.get_row("user_a", "acme"), store.get_row("user_b", "acme")
    assert a["ciphertext"] != b["ciphertext"] and a["wrapped_dek"] != b["wrapped_dek"]
    assert base64.b64decode(a["ciphertext"])[:12] != base64.b64decode(b["ciphertext"])[:12]
    assert base64.b64decode(a["wrapped_dek"])[:12] != base64.b64decode(b["wrapped_dek"])[:12]
    assert vault.use_key("user_a", "acme", "x") == {"key": KEY} and vault.use_key("user_b", "acme", "x") == {"key": KEY}

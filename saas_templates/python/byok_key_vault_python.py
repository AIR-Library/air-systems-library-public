"""BYOK key vault (docs/specs/byok_key_vault.md): a user's own provider API key, stored under envelope encryption
(one AES-256-GCM data key per stored key, wrapped by a master key), shown again only as a 4-character hint,
opened only for its owner, and every use recorded.

Why: Phase D wave 1, owner request 2026-11-10 (VAULT-01 to VAULT-14). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
Touches: the injected store (SQLite, the spec's schema) and the injected provider client (network in production,
a fake in tests). No files or money. The key never appears in a result other than use_key's, a refusal, a log,
an audit row or an exception message.

Inputs and outputs: KeyVault(store, master_keys, active_key_id, providers, provider_client, clock, random_bytes)
with save_key, list_keys, use_key, delete_key, rewrap and list_audit. A refusal is a RETURNED dict {error, status}.
"""
import base64
import binascii
import os
import re
import sqlite3
import threading
import time
from typing import Callable, Dict, List, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SAVES_PER_HOUR = 10
_KEY_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")
_PROVIDER_RE = re.compile(r"[a-z0-9_]{1,32}")
_PURPOSE_RE = re.compile(r"[A-Za-z0-9_.:-]{1,100}")


class VaultConfigError(Exception):
    """Construction refused (fail closed): "invalid_master_key" or "invalid_provider_config". Holds no key.

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""

    def __init__(self, code: str):
        """In: the error code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        super().__init__(code)
        self.code = code


def _err(error: str, status: int, **extra) -> dict:
    """A refusal {error, status, ...}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    out = {"error": error, "status": status}
    out.update(extra)
    return out


def gcm_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: str) -> str:
    """base64(nonce + AES-256-GCM ciphertext + 16-byte tag), aad = UTF-8 of the aad text.

    Why: ENVELOPE (VAULT-02). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return base64.b64encode(nonce + AESGCM(key).encrypt(nonce, plaintext, aad.encode("utf-8"))).decode("ascii")


def gcm_open(key: bytes, stored, aad: str) -> Optional[bytes]:
    """Open a gcm_seal value: None for text that is not base64, fewer than 28 bytes, or a tag that fails.
    Lengths are checked before slicing; never raises. Why: VAULT-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    Touches nothing."""
    try:
        if not isinstance(stored, str):
            return None
        raw = base64.b64decode(stored.encode("ascii"), validate=True)
        if len(raw) < 28:
            return None
        return AESGCM(key).decrypt(raw[:12], raw[12:], aad.encode("utf-8"))
    except (InvalidTag, ValueError, binascii.Error, UnicodeError):
        return None


def data_aad(provider: str, user_id: str) -> str:
    """The aad of the ciphertext: "byok:data:" + provider + ":" + user_id. 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return "byok:data:" + provider + ":" + user_id


def dek_aad(key_id: str, provider: str, user_id: str) -> str:
    """The aad of the wrapped DEK: "byok:dek:" + key_id + ":" + provider + ":" + user_id. 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return "byok:dek:" + key_id + ":" + provider + ":" + user_id


# ------------------------------------------------------------------------------------------------------ store
class SqliteVaultStore:
    """The vault's store on SQLite with the spec's schema. One shared connection guarded by a lock; each method is
    one statement or one transaction. _insert_audit is the single place an audit row is written (a test overrides
    it to make the audit write fail).

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the SQLite database (memory or file)."""

    def __init__(self, path: str = ":memory:"):
        """Open the database and create the tables. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.lock = threading.RLock()
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS provider_keys (user_id TEXT, provider TEXT, key_id TEXT NOT NULL,
                wrapped_dek TEXT NOT NULL, ciphertext TEXT NOT NULL, hint TEXT NOT NULL, created_at INT NOT NULL,
                last_used_at INT NULL, PRIMARY KEY (user_id, provider));
            CREATE TABLE IF NOT EXISTS provider_key_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT,
                provider TEXT, action TEXT, purpose TEXT NULL, key_id TEXT, at INT);
            CREATE TABLE IF NOT EXISTS provider_key_save_windows (user_id TEXT, window_start INT, count INT,
                PRIMARY KEY (user_id, window_start));
        """)

    def _tx(self, fn):
        """Run fn(conn) in one transaction; roll back and re-raise on any error. 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database."""
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                out = fn(self.conn)
                self.conn.execute("COMMIT")
                return out
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise

    def _insert_audit(self, conn, user_id: str, provider: str, action: str, purpose: Optional[str], key_id: str,
                      at: int) -> None:
        """Insert one provider_key_audit row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        conn.execute("INSERT INTO provider_key_audit (user_id, provider, action, purpose, key_id, at) "
                     "VALUES (?, ?, ?, ?, ?, ?)", (user_id, provider, action, purpose, key_id, at))

    def bump_window(self, user_id: str, window_start: int, limit: int = SAVES_PER_HOUR) -> bool:
        """Count one provider check in ONE conditional upsert (insert 1, or add 1 while count < limit).
        Out: True when a row changed. Why: VAULT-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO provider_key_save_windows (user_id, window_start, count) VALUES (?, ?, 1) "
                "ON CONFLICT (user_id, window_start) DO UPDATE SET count = provider_key_save_windows.count + 1 "
                "WHERE provider_key_save_windows.count < ?", (user_id, window_start, limit))
            return cur.rowcount == 1

    def save_row(self, row: dict, at: int) -> None:
        """Replace the user's row for the provider and add the key_saved audit row, in one transaction.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database."""
        def fn(conn):
            """The statements of this one transaction, on conn. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database."""
            conn.execute("INSERT OR REPLACE INTO provider_keys (user_id, provider, key_id, wrapped_dek, ciphertext, "
                         "hint, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
                         (row["user_id"], row["provider"], row["key_id"], row["wrapped_dek"], row["ciphertext"],
                          row["hint"], row["created_at"]))
            self._insert_audit(conn, row["user_id"], row["provider"], "key_saved", None, row["key_id"], at)
        self._tx(fn)

    def get_row(self, user_id: str, provider: str) -> Optional[dict]:
        """The (user_id, provider) row as a dict, or None. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            cur = self.conn.execute("SELECT user_id, provider, key_id, wrapped_dek, ciphertext, hint, created_at, "
                                    "last_used_at FROM provider_keys WHERE user_id = ? AND provider = ?",
                                    (user_id, provider))
            r = cur.fetchone()
            return dict(zip([d[0] for d in cur.description], r)) if r else None

    def list_rows(self, user_id: str) -> List[dict]:
        """The user's rows (provider, hint, key_id, created_at, last_used_at), ordered by provider (binary).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            cur = self.conn.execute("SELECT provider, hint, key_id, created_at, last_used_at FROM provider_keys "
                                    "WHERE user_id = ? ORDER BY provider COLLATE BINARY", (user_id,))
            names = [d[0] for d in cur.description]
            return [dict(zip(names, r)) for r in cur.fetchall()]

    def mark_used(self, user_id: str, provider: str, purpose: str, key_id: str, now: int) -> None:
        """last_used_at = now and the key_used audit row, in one transaction. 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database."""
        def fn(conn):
            """The statements of this one transaction, on conn. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database."""
            conn.execute("UPDATE provider_keys SET last_used_at = ? WHERE user_id = ? AND provider = ?",
                         (now, user_id, provider))
            self._insert_audit(conn, user_id, provider, "key_used", purpose, key_id, now)
        self._tx(fn)

    def delete_row(self, user_id: str, provider: str, now: int) -> bool:
        """Delete the row and add key_deleted, in one transaction. Out: False (and no audit row) when there was
        none. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database."""
        def fn(conn):
            """The statements of this one transaction, on conn. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database."""
            r = conn.execute("SELECT key_id FROM provider_keys WHERE user_id = ? AND provider = ?",
                             (user_id, provider)).fetchone()
            if r is None:
                return False
            conn.execute("DELETE FROM provider_keys WHERE user_id = ? AND provider = ?", (user_id, provider))
            self._insert_audit(conn, user_id, provider, "key_deleted", None, r[0], now)
            return True
        return self._tx(fn)

    def rows_not_under(self, key_id: str) -> List[dict]:
        """Rows whose key_id is not key_id, in (user_id, provider) order. 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            cur = self.conn.execute("SELECT user_id, provider, key_id, wrapped_dek FROM provider_keys "
                                    "WHERE key_id <> ? ORDER BY user_id COLLATE BINARY, provider COLLATE BINARY",
                                    (key_id,))
            names = [d[0] for d in cur.description]
            return [dict(zip(names, r)) for r in cur.fetchall()]

    def rewrap_row(self, user_id: str, provider: str, active: str, new_wrapped: str, wrapped_read: str,
                   now: int) -> bool:
        """The conditional rewrap UPDATE (only while the row still holds wrapped_read) and, when it changed the row,
        the key_rewrapped audit row, in one transaction. Out: True when one row changed. Why: VAULT-10.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database."""
        def fn(conn):
            """The statements of this one transaction, on conn. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database."""
            cur = conn.execute("UPDATE provider_keys SET key_id = ?, wrapped_dek = ? WHERE user_id = ? AND "
                               "provider = ? AND wrapped_dek = ?", (active, new_wrapped, user_id, provider,
                                                                     wrapped_read))
            if cur.rowcount != 1:
                return False
            self._insert_audit(conn, user_id, provider, "key_rewrapped", None, active, now)
            return True
        return self._tx(fn)

    def list_audit(self, user_id: str) -> List[dict]:
        """The user's audit rows {at, action, provider, purpose, key_id}, oldest first. 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            rows = self.conn.execute("SELECT at, action, provider, purpose, key_id FROM provider_key_audit "
                                     "WHERE user_id = ? ORDER BY id", (user_id,)).fetchall()
        return [{"at": r[0], "action": r[1], "provider": r[2], "purpose": r[3], "key_id": r[4]} for r in rows]


# ------------------------------------------------------------------------------------------------------ vault
class KeyVault:
    """The vault's functions over an injected store, keyring, providers, provider client, clock and random source.

    Why: VAULT-01..14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store and the provider client."""

    def __init__(self, store: SqliteVaultStore, master_keys: Dict[str, bytes], active_key_id: str,
                 providers: Dict[str, dict], provider_client, clock: Optional[Callable[[], int]] = None,
                 random_bytes: Optional[Callable[[int], bytes]] = None):
        """Validate the keyring (32-byte keys, ids matching [A-Za-z0-9_-]{1,32}, active id present) or raise
        VaultConfigError("invalid_master_key"); validate each provider or raise "invalid_provider_config".
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        if not isinstance(master_keys, dict) or not master_keys:
            raise VaultConfigError("invalid_master_key")
        for kid, key in master_keys.items():
            if (not isinstance(kid, str) or _KEY_ID_RE.fullmatch(kid) is None
                    or not isinstance(key, (bytes, bytearray)) or len(key) != 32):
                raise VaultConfigError("invalid_master_key")
        if not isinstance(active_key_id, str) or active_key_id not in master_keys:
            raise VaultConfigError("invalid_master_key")
        for pid, cfg in (providers or {}).items():
            try:
                prefix, lo, hi = cfg["prefix"], cfg["min_length"], cfg["max_length"]
            except (KeyError, TypeError):
                raise VaultConfigError("invalid_provider_config")
            if (not isinstance(pid, str) or _PROVIDER_RE.fullmatch(pid) is None or not isinstance(prefix, str)
                    or not all(isinstance(x, int) and not isinstance(x, bool) for x in (lo, hi))
                    or not (20 <= lo <= hi <= 4096) or lo < len(prefix) + 16):
                raise VaultConfigError("invalid_provider_config")
        self.store = store
        self.master_keys = {k: bytes(v) for k, v in master_keys.items()}
        self.active_key_id = active_key_id
        self.providers = dict(providers or {})
        self.client = provider_client
        self.clock = clock or (lambda: int(time.time()))
        self.random_bytes = random_bytes or os.urandom

    def _now(self) -> int:
        """The injected clock as an int. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        return int(self.clock())

    def save_key(self, user_id: str, provider: str, key) -> dict:
        """save_key, steps 1-6: format check, count the provider check, call it, store the envelope with its audit
        row. Out: {provider, hint, key_id, created_at} or a refusal. Why: VAULT-01..04, 09, 12.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the provider client (network)."""
        now = self._now()
        cfg = self.providers.get(provider) if isinstance(provider, str) else None
        if cfg is None:
            return _err("unknown_provider", 404)
        if not isinstance(key, str):
            return _err("invalid_key_format", 400)
        k = key.strip(" \t\r\n")
        if (not k.startswith(cfg["prefix"]) or not (cfg["min_length"] <= len(k) <= cfg["max_length"])
                or any(not ("!" <= c <= "~") for c in k)):
            return _err("invalid_key_format", 400)
        w = now - (now % 3600)
        if not self.store.bump_window(user_id, w):
            return _err("rate_limited", 429, retry_after=w + 3600 - now)
        try:
            verdict = self.client.check(provider, k)
        except Exception:  # noqa: BLE001 - a raised error is "unreachable"; its message may hold the key
            verdict = "unreachable"
        if verdict == "rejected":
            return _err("key_rejected", 400)
        if verdict != "ok":
            return _err("provider_unreachable", 502)
        try:
            dek = self.random_bytes(32)
            data_nonce = self.random_bytes(12)
            wrap_nonce = self.random_bytes(12)
            kid = self.active_key_id
            row = {
                "user_id": user_id, "provider": provider, "key_id": kid,
                "ciphertext": gcm_seal(dek, data_nonce, k.encode("utf-8"), data_aad(provider, user_id)),
                "wrapped_dek": gcm_seal(self.master_keys[kid], wrap_nonce, dek, dek_aad(kid, provider, user_id)),
                "hint": k[-4:], "created_at": now,
            }
            self.store.save_row(row, now)
        except Exception:  # noqa: BLE001 - fail closed without echoing anything
            return _err("storage_failed", 500)
        return {"provider": provider, "hint": row["hint"], "key_id": kid, "created_at": now}

    def list_keys(self, user_id: str) -> List[dict]:
        """list_keys: [{provider, hint, key_id, created_at, last_used_at}] sorted by provider; never the key,
        ciphertext or wrapped_dek. Why: VAULT-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store."""
        return self.store.list_rows(user_id)

    def _open_key(self, row: dict, master: bytes) -> Optional[str]:
        """Unwrap the DEK with master and decrypt the key; None for any failure (bad base64, short, tag, DEK size,
        not UTF-8). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        dek = gcm_open(master, row["wrapped_dek"], dek_aad(row["key_id"], row["provider"], row["user_id"]))
        if dek is None or len(dek) != 32:
            return None
        plain = gcm_open(dek, row["ciphertext"], data_aad(row["provider"], row["user_id"]))
        if plain is None:
            return None
        try:
            return plain.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def use_key(self, user_id: str, provider: str, purpose) -> dict:
        """use_key (SERVER-SIDE ONLY), steps 1-5: purpose check, row, key id, open, record the use in one
        transaction. Out: {key} or a refusal; no key when the record fails. Why: VAULT-06, 07, 08, 11.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store."""
        now = self._now()
        if not isinstance(purpose, str) or _PURPOSE_RE.fullmatch(purpose) is None:
            return _err("invalid_purpose", 400)
        row = self.store.get_row(user_id, provider)
        if row is None:
            return _err("key_not_found", 404)
        master = self.master_keys.get(row["key_id"])
        if master is None:
            return _err("key_unavailable", 503)
        key = self._open_key(row, master)
        if key is None:
            return _err("key_unreadable", 500)
        try:
            self.store.mark_used(user_id, provider, purpose, row["key_id"], now)
        except Exception:  # noqa: BLE001 - every use is recorded, or it did not happen
            return _err("storage_failed", 500)
        return {"key": key}

    def delete_key(self, user_id: str, provider: str) -> dict:
        """delete_key: {deleted: true} with a key_deleted audit row, or {deleted: false} when there was no row.
        When the store fails (the delete and its audit row are one transaction, rolled back together) the answer
        is the returned refusal 500 storage_failed, never an exception, as save_key and use_key answer and as the
        C#, Go, PHP and Rust ports do (spec CONVENTIONS: a refusal is a returned value).
        In: user_id, provider. Out: {deleted} or {error, status}.
        Why: VAULT-07, 13; review finding 4525101312 (a store failure was raised). 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store."""
        try:
            return {"deleted": bool(self.store.delete_row(user_id, provider, self._now()))}
        except Exception:  # noqa: BLE001 - fail closed without echoing anything
            return _err("storage_failed", 500)

    def rewrap(self) -> dict:
        """rewrap (OPERATOR ONLY): re-wrap each DEK not under active_key_id, in (user_id, provider) order, writing
        only if the row still holds the wrapped_dek read. ciphertext is never touched. Out: {rewrapped, failed}.
        Why: VAULT-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
        Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (review finding 4525344204): a row whose nonce, seal or
        store write raises is counted in failed and the next row is still rewrapped; such an error used to end
        rewrap() with an exception and no {rewrapped, failed} count. Nothing of the error is echoed."""
        now = self._now()
        rewrapped = failed = 0
        active = self.active_key_id
        for row in self.store.rows_not_under(active):
            master = self.master_keys.get(row["key_id"])
            dek = None
            if master is not None:
                dek = gcm_open(master, row["wrapped_dek"], dek_aad(row["key_id"], row["provider"], row["user_id"]))
            if dek is None or len(dek) != 32:
                failed += 1
                continue
            try:
                wrap_nonce = self.random_bytes(12)
                if not isinstance(wrap_nonce, (bytes, bytearray)) or len(wrap_nonce) != 12:
                    raise ValueError("random_bytes_short")
                new_wrapped = gcm_seal(self.master_keys[active], bytes(wrap_nonce), dek,
                                       dek_aad(active, row["provider"], row["user_id"]))
                if self.store.rewrap_row(row["user_id"], row["provider"], active, new_wrapped, row["wrapped_dek"],
                                         now):
                    rewrapped += 1
            except Exception:  # noqa: BLE001 -- review finding 4525344204: count the row, go on, echo nothing
                failed += 1
        return {"rewrapped": rewrapped, "failed": failed}

    def list_audit(self, user_id: str) -> List[dict]:
        """list_audit: [{at, action, provider, purpose, key_id}], oldest first. 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store."""
        return self.store.list_audit(user_id)

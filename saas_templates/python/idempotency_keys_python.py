"""Idempotency keys (docs/specs/idempotency_keys.md): the same request with the same key runs once.

Amended 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-07/08/10/11, spec amended after review on PR 19 and an
independent security review): a record is 'in_progress', 'completed' or 'uncertain'. An operation that raises
OperationFailed frees its key; any other error leaves the key 'uncertain' (a retry gets 409 outcome_unknown and the
operation does not run) until an operator calls release() or resolve(). Only 'completed' records expire; an
'in_progress' record past expires_at is treated as 'uncertain'. release(), resolve() and list_uncertain() are
operator functions, never client routes. Touches: the injected store (memory or SQL).
"""
import hashlib
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from typing import Optional, List, Callable, Any

DEFAULT_TTL_SECONDS = 86400

def ascii_upper(s: str) -> str:
    return ''.join(c.upper() if 'a' <= c <= 'z' else c for c in s)

def compute_fingerprint(method: str, path: str, body: str) -> str:
    m = ascii_upper(method or "")
    p = path or ""
    b = body or ""
    data = (m + " " + p + "\n" + b).encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def _valid_key(key: str) -> bool:
    if not isinstance(key, str):
        return False
    if len(key) < 1 or len(key) > 255:
        return False
    return all(0x20 <= ord(c) <= 0x7E for c in key)

@dataclass
class IdempotencyOptions:
    clock: Callable[[], int] = field(default_factory=lambda: int(time.time()))
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    required_methods: tuple = ("POST", "PATCH")

    def __post_init__(self):
        if self.ttl_seconds < 1:
            raise IdempotencyError("INVALID_OPTIONS", 500, "ttl_seconds must be >= 1")
        self.required_methods = tuple(ascii_upper(m) for m in self.required_methods)

@dataclass
class IdempotencyRecord:
    scope: str
    idem_key: str
    request_fingerprint: str
    status: str
    response_status: Optional[int]
    response_body: Optional[str]
    created_at: int
    expires_at: int

class IdempotencyError(Exception):
    def __init__(self, code: str, status: int, message: str):
        self.code = code
        self.status = status
        self.message = message
        super().__init__(message)


class OperationFailed(Exception):
    """Raised by an operation to report a DEFINITE failure: it did nothing (a validation error, a provider decline).

    handle() then deletes the in_progress record and re-raises, so a retry with the same key runs again (IDEM-08).
    Any other exception means the outcome is unknown and leaves the key 'uncertain' (IDEM-10).
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""


def _effective_status(rec: IdempotencyRecord, now: int) -> str:
    """The status handle() and the operator functions act on: an 'in_progress' record past expires_at is
    'uncertain' (its process died without recording an outcome), otherwise the stored status.
    Why: IDEM-07 as amended 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    if rec.status == "in_progress" and rec.expires_at <= now:
        return "uncertain"
    return rec.status


class Store:
    """Storage for idempotency records. Every method is one atomic step.

    [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Gained mark_uncertain, release, resolve and list_uncertain
    (IDEM-10/11); try_claim replaces only an expired 'completed' record; purge_expired deletes only expired
    'completed' records. Touches: whatever backs the store."""

    def try_claim(self, record: IdempotencyRecord, now: int) -> bool:
        """Insert an in_progress record if the key is absent or holds an expired 'completed' record. Out: True if claimed."""
        raise NotImplementedError
    def get(self, scope: str, idem_key: str) -> Optional[IdempotencyRecord]:
        raise NotImplementedError
    def complete(self, scope: str, idem_key: str, created_at: int, response_status: int, response_body: str) -> None:
        raise NotImplementedError
    def delete(self, scope: str, idem_key: str, created_at: int) -> None:
        """Delete this claim's in_progress record (OperationFailed: the key is free again)."""
        raise NotImplementedError
    def mark_uncertain(self, scope: str, idem_key: str, created_at: int) -> None:
        """Set this claim's in_progress record to 'uncertain' (the operation raised: outcome unknown)."""
        raise NotImplementedError
    def release(self, scope: str, idem_key: str, now: int) -> bool:
        """Delete the record only if it is (effectively) 'uncertain', in ONE conditional write. Out: True if deleted."""
        raise NotImplementedError
    def resolve(self, scope: str, idem_key: str, now: int, response_status: int, response_body: str,
                expires_at: int) -> bool:
        """Store a reconciled response as 'completed' only if the record is (effectively) 'uncertain', in ONE
        conditional write. Out: True if stored."""
        raise NotImplementedError
    def list_uncertain(self, now: int, limit: int) -> List[dict]:
        """[{scope, idem_key, created_at}] of (effectively) 'uncertain' records, oldest first, then insertion order."""
        raise NotImplementedError
    def purge_expired(self, now: int) -> int:
        """Delete 'completed' records whose expires_at <= now. Out: how many."""
        raise NotImplementedError


class InMemoryStore(Store):
    """Store in a dict guarded by one lock, so each method is atomic. Rewritten 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP, for the 'uncertain' status (IDEM-07/10/11). Touches memory only."""

    def __init__(self):
        """An empty store: records keyed by (scope, key) in insertion order, guarded by one lock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self._records = {}  # insertion-ordered: (scope, key) -> IdempotencyRecord
        self._lock = threading.Lock()

    def try_claim(self, record: IdempotencyRecord, now: int) -> bool:
        """See Store.try_claim: insert, or replace only an expired 'completed' record."""
        with self._lock:
            key = (record.scope, record.idem_key)
            existing = self._records.get(key)
            if existing is None or (existing.status == "completed" and existing.expires_at <= now):
                self._records.pop(key, None)
                self._records[key] = IdempotencyRecord(
                    scope=record.scope,
                    idem_key=record.idem_key,
                    request_fingerprint=record.request_fingerprint,
                    status="in_progress",
                    response_status=None,
                    response_body=None,
                    created_at=record.created_at,
                    expires_at=record.expires_at
                )
                return True
            return False

    def get(self, scope: str, idem_key: str) -> Optional[IdempotencyRecord]:
        """See Store.get: a copy of the record, or None."""
        with self._lock:
            rec = self._records.get((scope, idem_key))
            return None if rec is None else IdempotencyRecord(**vars(rec))

    def complete(self, scope: str, idem_key: str, created_at: int, response_status: int, response_body: str) -> None:
        """See Store.complete: in_progress -> completed for this claim only."""
        with self._lock:
            existing = self._records.get((scope, idem_key))
            if existing and existing.status == "in_progress" and existing.created_at == created_at:
                existing.status = "completed"
                existing.response_status = response_status
                existing.response_body = response_body

    def delete(self, scope: str, idem_key: str, created_at: int) -> None:
        with self._lock:
            key = (scope, idem_key)
            existing = self._records.get(key)
            if existing and existing.status == "in_progress" and existing.created_at == created_at:
                del self._records[key]

    def mark_uncertain(self, scope: str, idem_key: str, created_at: int) -> None:
        """See Store.mark_uncertain."""
        with self._lock:
            existing = self._records.get((scope, idem_key))
            if existing and existing.status == "in_progress" and existing.created_at == created_at:
                existing.status = "uncertain"

    def release(self, scope: str, idem_key: str, now: int) -> bool:
        """See Store.release: one atomic check-and-delete under the lock."""
        with self._lock:
            key = (scope, idem_key)
            existing = self._records.get(key)
            if existing is None or _effective_status(existing, now) != "uncertain":
                return False
            del self._records[key]
            return True

    def resolve(self, scope: str, idem_key: str, now: int, response_status: int, response_body: str,
                expires_at: int) -> bool:
        """See Store.resolve: one atomic check-and-update under the lock."""
        with self._lock:
            existing = self._records.get((scope, idem_key))
            if existing is None or _effective_status(existing, now) != "uncertain":
                return False
            existing.status = "completed"
            existing.response_status = response_status
            existing.response_body = response_body
            existing.expires_at = expires_at
            return True

    def list_uncertain(self, now: int, limit: int) -> List[dict]:
        """See Store.list_uncertain."""
        with self._lock:
            found = [r for r in self._records.values() if _effective_status(r, now) == "uncertain"]
        found.sort(key=lambda r: r.created_at)  # stable: equal times keep insertion order
        return [{"scope": r.scope, "idem_key": r.idem_key, "created_at": r.created_at} for r in found[:limit]]

    def purge_expired(self, now: int) -> int:
        """See Store.purge_expired: completed records only."""
        with self._lock:
            keys = [k for k, v in self._records.items() if v.status == "completed" and v.expires_at <= now]
            for k in keys:
                del self._records[k]
            return len(keys)


# SQL condition for "this record is uncertain at time ?": stored 'uncertain', or 'in_progress' past expires_at.
_UNCERTAIN_SQL = "(status = 'uncertain' OR (status = 'in_progress' AND expires_at <= ?))"


class SqlStore(Store):
    """Store in the spec's idempotency_records table; every write is one parameterized, conditional statement.
    Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, for the 'uncertain' status (IDEM-07/10/11).
    Touches: the given SQLite connection."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn
        self._lock = threading.Lock()
        self.migrate()

    def migrate(self):
        """Create the table (status 'in_progress' | 'completed' | 'uncertain') and its indexes if absent."""
        with self._lock:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS idempotency_records (
                    scope TEXT NOT NULL,
                    idem_key TEXT NOT NULL,
                    request_fingerprint TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('in_progress', 'completed', 'uncertain')),
                    response_status INTEGER NULL,
                    response_body TEXT NULL,
                    created_at BIGINT NOT NULL,
                    expires_at BIGINT NOT NULL,
                    PRIMARY KEY (scope, idem_key)
                )
            """)
            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_idempotency_records_expires_at
                ON idempotency_records (expires_at)
            """)
            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_idempotency_records_status
                ON idempotency_records (status, created_at)
            """)
            self._conn.commit()

    def _write(self, sql: str, params: tuple) -> int:
        """Run one write statement, commit, and return its rowcount (lock held by caller)."""
        cursor = self._conn.execute(sql, params)
        self._conn.commit()
        return cursor.rowcount

    def try_claim(self, record: IdempotencyRecord, now: int) -> bool:
        """See Store.try_claim: one INSERT ... ON CONFLICT DO UPDATE ... WHERE status = 'completed' AND expired."""
        with self._lock:
            return self._write("""
                INSERT INTO idempotency_records
                    (scope, idem_key, request_fingerprint, status, response_status, response_body, created_at, expires_at)
                VALUES (?, ?, ?, 'in_progress', NULL, NULL, ?, ?)
                ON CONFLICT (scope, idem_key) DO UPDATE SET
                    request_fingerprint = excluded.request_fingerprint,
                    status = 'in_progress',
                    response_status = NULL,
                    response_body = NULL,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at
                WHERE idempotency_records.status = 'completed' AND idempotency_records.expires_at <= ?
            """, (record.scope, record.idem_key, record.request_fingerprint,
                  record.created_at, record.expires_at, now)) == 1

    def get(self, scope: str, idem_key: str) -> Optional[IdempotencyRecord]:
        """See Store.get."""
        with self._lock:
            row = self._conn.execute("""
                SELECT scope, idem_key, request_fingerprint, status, response_status, response_body, created_at, expires_at
                FROM idempotency_records WHERE scope = ? AND idem_key = ?
            """, (scope, idem_key)).fetchone()
            if row is None:
                return None
            return IdempotencyRecord(
                scope=row[0], idem_key=row[1], request_fingerprint=row[2],
                status=row[3], response_status=row[4], response_body=row[5],
                created_at=row[6], expires_at=row[7]
            )

    def complete(self, scope: str, idem_key: str, created_at: int, response_status: int, response_body: str) -> None:
        """See Store.complete."""
        with self._lock:
            self._write("""
                UPDATE idempotency_records
                SET status = 'completed', response_status = ?, response_body = ?
                WHERE scope = ? AND idem_key = ? AND created_at = ? AND status = 'in_progress'
            """, (response_status, response_body, scope, idem_key, created_at))

    def delete(self, scope: str, idem_key: str, created_at: int) -> None:
        """See Store.delete."""
        with self._lock:
            self._write("""
                DELETE FROM idempotency_records
                WHERE scope = ? AND idem_key = ? AND created_at = ? AND status = 'in_progress'
            """, (scope, idem_key, created_at))

    def mark_uncertain(self, scope: str, idem_key: str, created_at: int) -> None:
        """See Store.mark_uncertain."""
        with self._lock:
            self._write("""
                UPDATE idempotency_records SET status = 'uncertain'
                WHERE scope = ? AND idem_key = ? AND created_at = ? AND status = 'in_progress'
            """, (scope, idem_key, created_at))

    def release(self, scope: str, idem_key: str, now: int) -> bool:
        """See Store.release: one conditional DELETE, so of two concurrent calls exactly one returns True."""
        with self._lock:
            return self._write(
                "DELETE FROM idempotency_records WHERE scope = ? AND idem_key = ? AND " + _UNCERTAIN_SQL,
                (scope, idem_key, now)) == 1

    def resolve(self, scope: str, idem_key: str, now: int, response_status: int, response_body: str,
                expires_at: int) -> bool:
        """See Store.resolve: one conditional UPDATE, so of two concurrent calls exactly one returns True."""
        with self._lock:
            return self._write(
                "UPDATE idempotency_records SET status = 'completed', response_status = ?, response_body = ?, "
                "expires_at = ? WHERE scope = ? AND idem_key = ? AND " + _UNCERTAIN_SQL,
                (response_status, response_body, expires_at, scope, idem_key, now)) == 1

    def list_uncertain(self, now: int, limit: int) -> List[dict]:
        """See Store.list_uncertain."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT scope, idem_key, created_at FROM idempotency_records WHERE " + _UNCERTAIN_SQL +
                " ORDER BY created_at, rowid LIMIT ?", (now, limit)).fetchall()
        return [{"scope": r[0], "idem_key": r[1], "created_at": r[2]} for r in rows]

    def purge_expired(self, now: int) -> int:
        """See Store.purge_expired."""
        with self._lock:
            return self._write(
                "DELETE FROM idempotency_records WHERE status = 'completed' AND expires_at <= ?", (now,))


class IdempotencyService:
    def __init__(self, store: Store, options: Optional[IdempotencyOptions] = None):
        self._store = store
        if options is None:
            options = IdempotencyOptions()
        self._options = options

    def is_required(self, method: str, path: str) -> bool:
        return ascii_upper(method or "") in self._options.required_methods

    def purge_expired(self) -> int:
        """Delete expired 'completed' records; 'uncertain' ones (stored or effective) are kept.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-07). Touches the store."""
        return self._store.purge_expired(self._options.clock())

    # -- operator / reconciliation functions: never exposed to API clients --------------------------------
    def release(self, scope: str, idempotency_key: str) -> bool:
        """Operator: free an 'uncertain' key once reconciliation shows the first attempt did nothing.

        In: the stored record's scope and key (from list_uncertain(), never from request input). Out: True if the
        key was uncertain and is now free; False (nothing changed) otherwise. One conditional write, so of two
        concurrent calls exactly one returns True. Why: IDEM-10 (spec amended 2026-11-10).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the store."""
        return self._store.release(scope, idempotency_key, self._options.clock())

    def resolve(self, scope: str, idempotency_key: str, status: int, body: str) -> bool:
        """Operator: store the outcome reconciliation found for an 'uncertain' key as 'completed'.

        In: the stored scope and key, the response status and body to serve. Out: True if stored (expires_at =
        now + ttl, 24 h by default); False (nothing changed) for a key that is not uncertain. One conditional
        write. Why: IDEM-11 (spec amended 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches the store."""
        self._check_result({"status": status, "body": body})
        now = self._options.clock()
        return self._store.resolve(scope, idempotency_key, now, status, body, now + self._options.ttl_seconds)

    def list_uncertain(self, limit: int = 100) -> List[dict]:
        """Operator: the reconciliation work list, [{scope, idem_key, created_at}] oldest first.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-10/11). Touches the store (read)."""
        return self._store.list_uncertain(self._options.clock(), limit)

    def handle(self, scope: str, idempotency_key: Optional[str], method: str, path: str, body: Optional[str], operation: Callable[[], Any]) -> dict:
        """Run ``operation`` at most once per (scope, key) and replay its stored response.

        In: scope (the authenticated client id), the Idempotency-Key, method, path, body and the operation
        (returns {status, body}). Out: {status, content_type, body}. Check order: missing/invalid key -> 400;
        different fingerprint -> 422; same fingerprint in progress -> 409; uncertain (stored, or in_progress past
        expires_at) -> 409 outcome_unknown, the operation does not run; completed -> the stored response.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] IDEM-07/08/10/11 as amended. Touches the store and
        whatever the operation touches."""
        M = ascii_upper(method or "")
        path = path or ""
        body = body or ""

        if M not in self._options.required_methods:
            r = operation()
            self._check_result(r)
            return {"status": r["status"], "content_type": "application/json", "body": r["body"]}

        if scope is None or scope == "":
            raise IdempotencyError("SCOPE_REQUIRED", 500, "scope is required")

        if idempotency_key is None or idempotency_key == "":
            return self._problem(400, "IDEMPOTENCY_KEY_MISSING")

        if not _valid_key(idempotency_key):
            return self._problem(400, "IDEMPOTENCY_KEY_INVALID")

        fp = compute_fingerprint(M, path, body)
        now = self._options.clock()
        rec = IdempotencyRecord(
            scope=scope, idem_key=idempotency_key, request_fingerprint=fp,
            status="in_progress", response_status=None, response_body=None,
            created_at=now, expires_at=now + self._options.ttl_seconds
        )

        for _ in range(2):
            if self._store.try_claim(rec, now):
                return self._run_claimed(rec, operation)
            ex = self._store.get(scope, idempotency_key)
            if ex is None or (ex.status == "completed" and ex.expires_at <= now):
                continue  # freed or expired between the claim and the read: claim again
            if ex.request_fingerprint != fp:
                return self._problem(422, "IDEMPOTENCY_KEY_REUSED")
            status = _effective_status(ex, now)
            if status == "in_progress":
                return self._problem(409, "REQUEST_IN_PROGRESS")
            if status == "uncertain":
                return self._problem(409, "OUTCOME_UNKNOWN")
            return {"status": ex.response_status, "content_type": "application/json", "body": ex.response_body}

        return self._problem(409, "REQUEST_IN_PROGRESS")

    def _run_claimed(self, rec: IdempotencyRecord, operation: Callable[[], Any]) -> dict:
        """Run the operation under a fresh claim and record its outcome.

        OperationFailed -> delete the claim (the key is free) and re-raise (IDEM-08). Any other exception, or a
        result that is not a valid {status, body} -> mark the key 'uncertain' and re-raise (IDEM-10): the
        operation may have taken effect, so it must not run again until an operator settles it. A store that
        fails while recording leaves the claim in_progress (409, then uncertain once it expires).
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Every error used to delete the claim, so a retry after a
        timeout could charge twice. Touches the store and whatever the operation touches."""
        try:
            r = operation()
        except OperationFailed:
            self._store.delete(rec.scope, rec.idem_key, rec.created_at)
            raise
        except BaseException:
            self._store.mark_uncertain(rec.scope, rec.idem_key, rec.created_at)
            raise

        try:
            self._check_result(r)
        except IdempotencyError:
            self._store.mark_uncertain(rec.scope, rec.idem_key, rec.created_at)
            raise
        self._store.complete(rec.scope, rec.idem_key, rec.created_at, r["status"], r["body"])
        return {"status": r["status"], "content_type": "application/json", "body": r["body"]}

    def _check_result(self, r: Any) -> None:
        if not isinstance(r, dict):
            raise IdempotencyError("INVALID_OPERATION_RESULT", 500, "operation result must be a dict")
        if "status" not in r or "body" not in r:
            raise IdempotencyError("INVALID_OPERATION_RESULT", 500, "operation result must have status and body")
        status = r["status"]
        if isinstance(status, bool) or not isinstance(status, int):
            raise IdempotencyError("INVALID_OPERATION_RESULT", 500, "status must be an integer")
        if status < 100 or status > 599:
            raise IdempotencyError("INVALID_OPERATION_RESULT", 500, "status must be between 100 and 599")
        if not isinstance(r["body"], str):
            raise IdempotencyError("INVALID_OPERATION_RESULT", 500, "body must be a string")

    def _problem(self, status: int, code: str) -> dict:
        """An RFC 7807 problem response {status, content_type "application/problem+json", body {type, title,
        detail}}. OUTCOME_UNKNOWN (type .../outcome_unknown) added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
        (IDEM-07/10). Touches nothing."""
        bodies = {
            "IDEMPOTENCY_KEY_MISSING": '{"type":"https://developer.example.com/problems/idempotency-key-missing","title":"Idempotency-Key is missing","detail":"This operation requires an Idempotency-Key request header."}',
            "IDEMPOTENCY_KEY_INVALID": '{"type":"https://developer.example.com/problems/idempotency-key-invalid","title":"Idempotency-Key is invalid","detail":"An Idempotency-Key must be 1 to 255 printable ASCII characters."}',
            "IDEMPOTENCY_KEY_REUSED": '{"type":"https://developer.example.com/problems/idempotency-key-reused","title":"Idempotency-Key is already used","detail":"This Idempotency-Key was already used with a different request payload."}',
            "REQUEST_IN_PROGRESS": '{"type":"https://developer.example.com/problems/idempotency-request-outstanding","title":"A request is outstanding for this Idempotency-Key","detail":"A request with the same Idempotency-Key is still being processed. Retry later."}',
            "OUTCOME_UNKNOWN": '{"type":"https://developer.example.com/problems/outcome_unknown","title":"Outcome unknown","detail":"The first request with this Idempotency-Key ended without a known outcome; it will not be run again until it is reconciled."}',
        }
        return {"status": status, "content_type": "application/problem+json", "body": bodies[code]}

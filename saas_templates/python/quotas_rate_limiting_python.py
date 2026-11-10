# Repaired 2026-11-03: the tests use the spec's storage units.
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: SQLite only.
"""
quotas_rate_limiting_python.py

Production-quality Quotas & Rate Limiting module for a reusable SaaS library.
Implements Template #5: QUOTAS & RATE LIMITING with an identical API contract
across all supported languages.

Tiers:
  - solo:       1,000 API calls/month, 1 GB storage
  - team:       10,000 API calls/month, 100 GB storage
  - enterprise: unlimited API calls, unlimited storage

Gates (checked in order on every API request):
  1. api_call_quota
  2. storage_quota
  3. rate_limit_per_user
  4. rate_limit_per_ip
  5. feature_gate_by_tier
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TIERS = ("solo", "team", "enterprise")

API_CALL_LIMITS: Dict[str, int] = {
    "solo": 1_000,
    "team": 10_000,
    "enterprise": -1,  # unlimited
}

STORAGE_LIMITS: Dict[str, int] = {
    "solo": 1_000_000_000,       # 1 GB
    "team": 100_000_000_000,     # 100 GB
    "enterprise": -1,            # unlimited
}

RATE_LIMIT_PER_USER_PER_MINUTE = 100
RATE_LIMIT_PER_IP_PER_SECOND = 10

FEATURE_GATES: Dict[str, List[str]] = {
    "feature_a": ["team", "enterprise"],
    "feature_b": ["enterprise"],
    "feature_c": ["solo", "team", "enterprise"],
}

UPGRADE_URL = "https://example.com/pricing/upgrade"

# ---------------------------------------------------------------------------
# Database schema (executable DDL)
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS usage_metrics (
    user_id      TEXT    NOT NULL,
    month        TEXT    NOT NULL,
    call_count   INTEGER NOT NULL DEFAULT 0,
    storage_bytes INTEGER NOT NULL DEFAULT 0,
    updated_at   TEXT    NOT NULL,
    PRIMARY KEY (user_id, month)
);

CREATE TABLE IF NOT EXISTS api_calls (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id           TEXT    NOT NULL,
    ip                TEXT    NOT NULL,
    endpoint          TEXT    NOT NULL,
    timestamp         TEXT    NOT NULL,
    status_code       INTEGER NOT NULL,
    response_time_ms  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_api_calls_user_ts
    ON api_calls (user_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_api_calls_ip_ts
    ON api_calls (ip, timestamp);
"""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class User:
    user_id: str
    tier: str
    ip: str = "127.0.0.1"


@dataclass
class GateResult:
    """Result of a single gate check."""
    passed: bool
    status_code: int
    body: Dict[str, Any]
    gate: str


@dataclass
class QuotaDecision:
    """Aggregated decision after all gates."""
    allowed: bool
    status_code: int
    body: Dict[str, Any]
    gate_results: List[GateResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Why-chain logging
# ---------------------------------------------------------------------------

class WhyChainLogger:
    """
    Thread-safe in-memory why-chain logger.
    In production this would ship to a structured log sink (e.g. ELK, Datadog).
    """

    def __init__(self, clock: Optional[Any] = None) -> None:
        """In: an optional clock returning an aware UTC datetime (added 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP, so entry timestamps follow the engine's injected clock). Touches memory."""
        self._now = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.Lock()
        self._entries: List[Dict[str, Any]] = []

    def log(self, gate: str, **kwargs: Any) -> None:
        """Append one why-chain entry stamped with the injected clock ([2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP]). Touches memory."""
        entry = {
            "ts": self._now().isoformat(),
            "gate": gate,
            **kwargs,
        }
        with self._lock:
            self._entries.append(entry)

    def get_entries(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._entries)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------

class QuotaEngine:
    """
    Central quota and rate-limiting engine.

    Usage:
        engine = QuotaEngine()
        decision = engine.check_request(user, endpoint="/v1/data",
                                        incoming_file_size=0,
                                        feature=None)
        if not decision.allowed:
            return decision.status_code, decision.body
        # ... handle request ...
        engine.record_api_call(user, endpoint, status_code=200,
                               response_time_ms=12)
    """

    def __init__(self, db_path: str = ":memory:", clock: Optional[Any] = None) -> None:
        """Open the engine on one SQLite database.

        In: db_path, and (added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP) an optional clock, a function
        returning an aware UTC datetime; default the wall clock. Why: docs/specs/README.md ("time comes from an
        injectable clock"), so QUOTA-11 can prove a real month rollover and no test depends on the date.
        Touches: SQLite (creates the schema)."""
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._db_path = db_path
        self._local = threading.local()
        self._logger = WhyChainLogger(self._clock)
        self._init_db()

    # -- database helpers ---------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript(SCHEMA_SQL)
        conn.commit()

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn is not None:
            self._local.conn.close()
            self._local.conn = None

    # -- month helper -------------------------------------------------------

    def _now(self) -> datetime:
        """The engine's current UTC time from the injected clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
        (deterministic tests, docs/specs/README.md). Touches nothing."""
        return self._clock()

    def _current_month(self) -> str:
        """The current month key "YYYY-MM" from the injected clock (was the wall clock until 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP; QUOTA-11). Touches nothing."""
        return self._now().strftime("%Y-%m")

    def _next_month_reset_date(self) -> str:
        """The first instant of next month, ISO-8601 UTC, from the injected clock (2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP). Touches nothing."""
        now = self._now()
        if now.month == 12:
            reset = datetime(now.year + 1, 1, 1, tzinfo=timezone.utc)
        else:
            reset = datetime(now.year, now.month + 1, 1, tzinfo=timezone.utc)
        return reset.strftime("%Y-%m-%dT%H:%M:%SZ")

    # -- gate 1: api_call_quota ---------------------------------------------

    def _check_api_call_quota(self, user: User) -> GateResult:
        month = self._current_month()
        limit = API_CALL_LIMITS.get(user.tier, 0)
        conn = self._get_conn()
        row = conn.execute(
            "SELECT call_count FROM usage_metrics WHERE user_id = ? AND month = ?",
            (user.user_id, month),
        ).fetchone()
        current_usage = row[0] if row else 0

        if limit == -1:
            passed = True
        else:
            passed = (current_usage + 1) <= limit

        self._logger.log(
            gate="api_quota_check",
            user_id=user.user_id,
            tier=user.tier,
            current_usage=current_usage,
            limit=limit,
            passed=passed,
        )

        if not passed:
            return GateResult(
                passed=False,
                status_code=429,
                body={
                    "error": "quota_exceeded",
                    "current": current_usage,
                    "limit": limit,
                    "reset_date": self._next_month_reset_date(),
                },
                gate="api_call_quota",
            )
        return GateResult(passed=True, status_code=200, body={}, gate="api_call_quota")

    # -- gate 2: storage_quota ----------------------------------------------

    def _check_storage_quota(self, user: User, incoming_file_size: int) -> GateResult:
        limit = STORAGE_LIMITS.get(user.tier, 0)
        conn = self._get_conn()
        row = conn.execute(
            "SELECT storage_bytes FROM usage_metrics WHERE user_id = ? AND month = ?",
            (user.user_id, self._current_month()),
        ).fetchone()
        current_storage = row[0] if row else 0

        if limit == -1:
            passed = True
        else:
            passed = (current_storage + incoming_file_size) <= limit

        self._logger.log(
            gate="storage_quota_check",
            user_id=user.user_id,
            tier=user.tier,
            current_usage=current_storage,
            limit=limit,
            passed=passed,
        )

        if not passed:
            return GateResult(
                passed=False,
                status_code=413,
                body={
                    "error": "storage_quota_exceeded",
                    "current": current_storage,
                    "limit": limit,
                },
                gate="storage_quota",
            )
        return GateResult(passed=True, status_code=200, body={}, gate="storage_quota")

    # -- gate 3: rate_limit_per_user ----------------------------------------

    def _check_rate_limit_per_user(self, user: User) -> GateResult:
        """Gate 3: under 100 calls in the last 60 s for this user, by the injected clock ([2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP]).
        Out: GateResult (429 rate_limit_exceeded). Touches: SQLite (read)."""
        conn = self._get_conn()
        now = self._now()
        one_min_ago = now.timestamp() - 60
        row = conn.execute(
            "SELECT COUNT(*) FROM api_calls WHERE user_id = ? AND timestamp > ?",
            (user.user_id, datetime.fromtimestamp(one_min_ago, tz=timezone.utc).isoformat()),
        ).fetchone()
        count = row[0] if row else 0
        passed = count < RATE_LIMIT_PER_USER_PER_MINUTE

        self._logger.log(
            gate="rate_limit_per_user",
            user_id=user.user_id,
            count=count,
            limit=RATE_LIMIT_PER_USER_PER_MINUTE,
            passed=passed,
        )

        if not passed:
            return GateResult(
                passed=False,
                status_code=429,
                body={
                    "error": "rate_limit_exceeded",
                    "reset_seconds": 60,
                },
                gate="rate_limit_per_user",
            )
        return GateResult(passed=True, status_code=200, body={}, gate="rate_limit_per_user")

    # -- gate 4: rate_limit_per_ip ------------------------------------------

    def _check_rate_limit_per_ip(self, user: User) -> GateResult:
        """Gate 4: under 10 calls in the last second from this IP, by the injected clock ([2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP]).
        Out: GateResult (429). Touches: SQLite (read)."""
        conn = self._get_conn()
        now = self._now()
        one_sec_ago = now.timestamp() - 1
        row = conn.execute(
            "SELECT COUNT(*) FROM api_calls WHERE ip = ? AND timestamp > ?",
            (user.ip, datetime.fromtimestamp(one_sec_ago, tz=timezone.utc).isoformat()),
        ).fetchone()
        count = row[0] if row else 0
        passed = count < RATE_LIMIT_PER_IP_PER_SECOND

        self._logger.log(
            gate="rate_limit_per_ip",
            ip=user.ip,
            count=count,
            limit=RATE_LIMIT_PER_IP_PER_SECOND,
            passed=passed,
        )

        if not passed:
            return GateResult(
                passed=False,
                status_code=429,
                body={
                    "error": "ip_rate_limit_exceeded",
                    "reset_seconds": 1,
                },
                gate="rate_limit_per_ip",
            )
        return GateResult(passed=True, status_code=200, body={}, gate="rate_limit_per_ip")

    # -- gate 5: feature_gate_by_tier ---------------------------------------

    def _check_feature_gate(self, user: User, feature: str) -> GateResult:
        allowed_tiers = FEATURE_GATES.get(feature, [])
        passed = user.tier in allowed_tiers

        self._logger.log(
            gate="feature_gate",
            user_id=user.user_id,
            feature=feature,
            tier=user.tier,
            allowed_tiers=allowed_tiers,
            passed=passed,
        )

        if not passed:
            # Determine minimum tier required
            min_tier = None
            tier_order = {"solo": 0, "team": 1, "enterprise": 2}
            for t in allowed_tiers:
                if min_tier is None or tier_order.get(t, 99) < tier_order.get(min_tier, 99):
                    min_tier = t
            return GateResult(
                passed=False,
                status_code=403,
                body={
                    "error": "feature_not_available_in_tier",
                    "tier": user.tier,
                    "minimum_tier": min_tier,
                    "upgrade_url": UPGRADE_URL,
                },
                gate="feature_gate",
            )
        return GateResult(passed=True, status_code=200, body={}, gate="feature_gate")

    # -- public API ----------------------------------------------------------

    def check_request(
        self,
        user: User,
        endpoint: str = "/",
        incoming_file_size: int = 0,
        feature: Optional[str] = None,
    ) -> QuotaDecision:
        """
        Run all quota/rate-limit gates in order.
        Returns a QuotaDecision with the first failing gate (if any).
        """
        results: List[GateResult] = []

        # Gate 1: api_call_quota
        r1 = self._check_api_call_quota(user)
        results.append(r1)
        if not r1.passed:
            return QuotaDecision(allowed=False, status_code=r1.status_code,
                                 body=r1.body, gate_results=results)

        # Gate 2: storage_quota
        r2 = self._check_storage_quota(user, incoming_file_size)
        results.append(r2)
        if not r2.passed:
            return QuotaDecision(allowed=False, status_code=r2.status_code,
                                 body=r2.body, gate_results=results)

        # Gate 3: rate_limit_per_user
        r3 = self._check_rate_limit_per_user(user)
        results.append(r3)
        if not r3.passed:
            return QuotaDecision(allowed=False, status_code=r3.status_code,
                                 body=r3.body, gate_results=results)

        # Gate 4: rate_limit_per_ip
        r4 = self._check_rate_limit_per_ip(user)
        results.append(r4)
        if not r4.passed:
            return QuotaDecision(allowed=False, status_code=r4.status_code,
                                 body=r4.body, gate_results=results)

        # Gate 5: feature_gate_by_tier
        if feature is not None:
            r5 = self._check_feature_gate(user, feature)
            results.append(r5)
            if not r5.passed:
                return QuotaDecision(allowed=False, status_code=r5.status_code,
                                     body=r5.body, gate_results=results)

        return QuotaDecision(allowed=True, status_code=200, body={}, gate_results=results)

    def record_api_call(
        self,
        user: User,
        endpoint: str,
        status_code: int = 200,
        response_time_ms: int = 0,
    ) -> None:
        """
        Record an API call and increment the monthly usage counter.
        Call this AFTER a successful request to persist usage.
        """
        conn = self._get_conn()
        month = self._current_month()
        now_iso = self._now().isoformat()

        # Upsert usage_metrics
        conn.execute(
            """
            INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
            VALUES (?, ?, 1, 0, ?)
            ON CONFLICT(user_id, month)
            DO UPDATE SET call_count = call_count + 1, updated_at = ?
            """,
            (user.user_id, month, now_iso, now_iso),
        )

        # Insert api_calls row
        conn.execute(
            """
            INSERT INTO api_calls (user_id, ip, endpoint, timestamp, status_code, response_time_ms)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user.user_id, user.ip, endpoint, now_iso, status_code, response_time_ms),
        )
        conn.commit()

    def record_storage(
        self,
        user: User,
        bytes_added: int,
    ) -> None:
        """Record storage usage for a file upload."""
        conn = self._get_conn()
        month = self._current_month()
        now_iso = self._now().isoformat()

        conn.execute(
            """
            INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
            VALUES (?, ?, 0, ?, ?)
            ON CONFLICT(user_id, month)
            DO UPDATE SET storage_bytes = storage_bytes + ?, updated_at = ?
            """,
            (user.user_id, month, bytes_added, now_iso, bytes_added, now_iso),
        )
        conn.commit()

    def get_usage(self, user_id: str, month: Optional[str] = None) -> Dict[str, Any]:
        """Return current usage for a user."""
        if month is None:
            month = self._current_month()
        conn = self._get_conn()
        row = conn.execute(
            "SELECT call_count, storage_bytes FROM usage_metrics WHERE user_id = ? AND month = ?",
            (user_id, month),
        ).fetchone()
        if row is None:
            return {"call_count": 0, "storage_bytes": 0, "month": month}
        return {"call_count": row[0], "storage_bytes": row[1], "month": month}

    def upgrade_tier(self, user_id: str, new_tier: str) -> None:
        """
        Upgrade a user's tier. Limits are read dynamically from TIERS maps,
        so the new tier takes effect immediately on the next check_request.
        This method is a hook for persistence in a real system.
        """
        if new_tier not in TIERS:
            raise ValueError(f"Invalid tier: {new_tier}. Must be one of {TIERS}")
        # In a real system, update the users table here.
        # For this module, tier is carried on the User object, so the caller
        # should update their User instance. This method exists for API parity.
        pass

    def reset_monthly_usage(self, user_id: str) -> None:
        """
        Reset usage counters for the current month (e.g. on month rollover).
        In production this would be triggered by a cron job.
        """
        conn = self._get_conn()
        month = self._current_month()
        conn.execute(
            "UPDATE usage_metrics SET call_count = 0, storage_bytes = 0, updated_at = ? WHERE user_id = ? AND month = ?",
            (self._now().isoformat(), user_id, month),
        )
        conn.commit()

    def get_why_chain(self) -> List[Dict[str, Any]]:
        """Return all logged why-chain entries (for debugging/audit)."""
        return self._logger.get_entries()

    def clear_why_chain(self) -> None:
        self._logger.clear()


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_engine(db_path: str = ":memory:") -> QuotaEngine:
    """Factory function for creating a QuotaEngine instance."""
    return QuotaEngine(db_path=db_path)


# ---------------------------------------------------------------------------
# JSON serialization helpers (for HTTP frameworks)
# ---------------------------------------------------------------------------

def decision_to_json(decision: QuotaDecision) -> Tuple[int, str]:
    """
    Convert a QuotaDecision to (status_code, json_body) for HTTP response.
    """
    body = decision.body if decision.body else {"status": "ok"}
    return decision.status_code, json.dumps(body, indent=2)


# ---------------------------------------------------------------------------
# Module-level singleton (optional, for simple use cases)
# ---------------------------------------------------------------------------

_default_engine: Optional[QuotaEngine] = None
_default_lock = threading.Lock()


def get_default_engine() -> QuotaEngine:
    """Get or create the default in-memory engine."""
    global _default_engine
    with _default_lock:
        if _default_engine is None:
            _default_engine = QuotaEngine(db_path=":memory:")
        return _default_engine


def check_request(
    user: User,
    endpoint: str = "/",
    incoming_file_size: int = 0,
    feature: Optional[str] = None,
) -> QuotaDecision:
    """Module-level convenience: check request against default engine."""
    return get_default_engine().check_request(
        user, endpoint=endpoint, incoming_file_size=incoming_file_size, feature=feature
    )


def record_api_call(
    user: User,
    endpoint: str,
    status_code: int = 200,
    response_time_ms: int = 0,
) -> None:
    """Module-level convenience: record an API call on the default engine."""
    get_default_engine().record_api_call(
        user, endpoint=endpoint, status_code=status_code, response_time_ms=response_time_ms
    )


def record_storage(user: User, bytes_added: int) -> None:
    """Module-level convenience: record storage on the default engine."""
    get_default_engine().record_storage(user, bytes_added)


def get_usage(user_id: str, month: Optional[str] = None) -> Dict[str, Any]:
    """Module-level convenience: get usage from default engine."""
    return get_default_engine().get_usage(user_id, month)


def upgrade_tier(user_id: str, new_tier: str) -> None:
    """Module-level convenience: upgrade tier on default engine."""
    get_default_engine().upgrade_tier(user_id, new_tier)


def reset_monthly_usage(user_id: str) -> None:
    """Module-level convenience: reset monthly usage on default engine."""
    get_default_engine().reset_monthly_usage(user_id)


def get_why_chain() -> List[Dict[str, Any]]:
    """Module-level convenience: get why-chain from default engine."""
    return get_default_engine().get_why_chain()


def clear_why_chain() -> None:
    """Module-level convenience: clear why-chain on default engine."""
    get_default_engine().clear_why_chain()


def reset_default_engine() -> None:
    """Reset the default engine (useful in tests)."""
    global _default_engine
    with _default_lock:
        if _default_engine is not None:
            _default_engine.close()
            _default_engine = None


__all__ = [
    "QuotaEngine",
    "User",
    "GateResult",
    "QuotaDecision",
    "WhyChainLogger",
    "TIERS",
    "API_CALL_LIMITS",
    "STORAGE_LIMITS",
    "RATE_LIMIT_PER_USER_PER_MINUTE",
    "RATE_LIMIT_PER_IP_PER_SECOND",
    "FEATURE_GATES",
    "UPGRADE_URL",
    "SCHEMA_SQL",
    "create_engine",
    "get_default_engine",
    "check_request",
    "record_api_call",
    "record_storage",
    "get_usage",
    "upgrade_tier",
    "reset_monthly_usage",
    "get_why_chain",
    "clear_why_chain",
    "reset_default_engine",
    "decision_to_json",
]

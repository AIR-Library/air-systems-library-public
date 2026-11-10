# Tests updated with the fix 2026-11-03: the tests use the spec's storage units.
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: SQLite only.
"""
quotas_rate_limiting_python_tests.py

Complete test suite for the Quotas & Rate Limiting module.
Covers every case listed in the spec's TESTS section.

Run with:
    python -m pytest quotas_rate_limiting_python_tests.py -v
or:
    python quotas_rate_limiting_python_tests.py
"""

from __future__ import annotations

import json
import time
import unittest
from datetime import datetime, timezone
from typing import Any, Dict, List

from quotas_rate_limiting_python import (
    API_CALL_LIMITS,
    FEATURE_GATES,
    QuotaEngine,
    STORAGE_LIMITS,
    TIERS,
    User,
    create_engine,
    decision_to_json,
)


class TestQuotaEngineBase(unittest.TestCase):
    """Base class that creates a fresh engine per test."""

    def setUp(self) -> None:
        self.engine = QuotaEngine(db_path=":memory:")

    def tearDown(self) -> None:
        self.engine.close()


# ---------------------------------------------------------------------------
# 1. api_call_quota
# ---------------------------------------------------------------------------

class TestApiCallQuota(TestQuotaEngineBase):

    # QUOTA-01
    def test_api_quota_pass_call_succeeds_usage_incremented(self) -> None:
        """✓ api_quota PASS → call succeeds, usage incremented"""
        user = User(user_id="u1", tier="solo", ip="10.0.0.1")

        decision = self.engine.check_request(user, endpoint="/v1/data")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.status_code, 200)

        # Record the call
        self.engine.record_api_call(user, endpoint="/v1/data", status_code=200, response_time_ms=10)

        usage = self.engine.get_usage("u1")
        self.assertEqual(usage["call_count"], 1)

    # QUOTA-02
    def test_api_quota_fail_call_rejected_429(self) -> None:
        """✓ api_quota FAIL → call rejected 429"""
        user = User(user_id="u2", tier="solo", ip="10.0.0.2")

        # Simulate that the user has already used 1000 calls (the solo limit)
        month = self.engine._current_month()
        conn = self.engine._get_conn()
        conn.execute(
            """
            INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
            VALUES (?, ?, ?, 0, ?)
            """,
            ("u2", month, API_CALL_LIMITS["solo"], datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

        decision = self.engine.check_request(user, endpoint="/v1/data")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.status_code, 429)
        self.assertEqual(decision.body["error"], "quota_exceeded")
        self.assertEqual(decision.body["current"], 1000)
        self.assertEqual(decision.body["limit"], 1000)
        self.assertIn("reset_date", decision.body)

    def test_api_quota_team_tier_higher_limit(self) -> None:
        """Team tier allows 10,000 calls."""
        user = User(user_id="u3", tier="team", ip="10.0.0.3")

        # Simulate 9,999 calls used
        month = self.engine._current_month()
        conn = self.engine._get_conn()
        conn.execute(
            """
            INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
            VALUES (?, ?, ?, 0, ?)
            """,
            ("u3", month, 9999, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

        # 10,000th call should pass
        decision = self.engine.check_request(user, endpoint="/v1/data")
        self.assertTrue(decision.allowed)

        # Record it
        self.engine.record_api_call(user, endpoint="/v1/data")

        # 10,001st call should fail
        decision2 = self.engine.check_request(user, endpoint="/v1/data")
        self.assertFalse(decision2.allowed)
        self.assertEqual(decision2.status_code, 429)

    # QUOTA-13
    def test_api_quota_enterprise_unlimited(self) -> None:
        """Enterprise tier has unlimited API calls."""
        user = User(user_id="u4", tier="enterprise", ip="10.0.0.4")

        # Simulate a huge number of calls
        month = self.engine._current_month()
        conn = self.engine._get_conn()
        conn.execute(
            """
            INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
            VALUES (?, ?, ?, 0, ?)
            """,
            ("u4", month, 999_999_999, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

        decision = self.engine.check_request(user, endpoint="/v1/data")
        self.assertTrue(decision.allowed)


# ---------------------------------------------------------------------------
# 2. storage_quota
# ---------------------------------------------------------------------------

class TestStorageQuota(TestQuotaEngineBase):

    # QUOTA-03
    def test_storage_quota_pass_file_stored(self) -> None:
        """✓ storage_quota PASS → file stored"""
        user = User(user_id="s1", tier="solo", ip="10.0.0.10")

        # Upload a 500 MB file (well within 1 GB limit)
        file_size = 500 * 1024 * 1024
        decision = self.engine.check_request(user, endpoint="/v1/upload", incoming_file_size=file_size)
        self.assertTrue(decision.allowed)

        # Record storage
        self.engine.record_storage(user, file_size)

        usage = self.engine.get_usage("s1")
        self.assertEqual(usage["storage_bytes"], file_size)

    # QUOTA-04
    def test_storage_quota_fail_upload_rejected_413(self) -> None:
        """✓ storage_quota FAIL → upload rejected 413"""
        user = User(user_id="s2", tier="solo", ip="10.0.0.11")

        # Simulate that the user already has 900 MB stored
        month = self.engine._current_month()
        conn = self.engine._get_conn()
        conn.execute(
            """
            INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
            VALUES (?, ?, 0, ?, ?)
            """,
            ("s2", month, 900 * 1024 * 1024, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

        # Try to upload a 200 MB file (total would be 1.1 GB > 1 GB limit)
        file_size = 200 * 1024 * 1024
        decision = self.engine.check_request(user, endpoint="/v1/upload", incoming_file_size=file_size)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.status_code, 413)
        self.assertEqual(decision.body["error"], "storage_quota_exceeded")
        self.assertEqual(decision.body["current"], 900 * 1024 * 1024)
        self.assertEqual(decision.body["limit"], 1_000_000_000)

    def test_storage_quota_team_tier(self) -> None:
        """Team tier allows 100 GB storage."""
        user = User(user_id="s3", tier="team", ip="10.0.0.12")

        # Simulate 99 GB used (decimal GB, matching the spec's 100e9 limit)
        month = self.engine._current_month()
        conn = self.engine._get_conn()
        conn.execute(
            """
            INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
            VALUES (?, ?, 0, ?, ?)
            """,
            ("s3", month, 99 * 1_000_000_000, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

        # Upload 1 GB (total 100 GB, exactly at limit)
        file_size = 1_000_000_000
        decision = self.engine.check_request(user, endpoint="/v1/upload", incoming_file_size=file_size)
        self.assertTrue(decision.allowed)

    # QUOTA-13
    def test_storage_quota_enterprise_unlimited(self) -> None:
        """Enterprise tier has unlimited storage."""
        user = User(user_id="s4", tier="enterprise", ip="10.0.0.13")

        # Simulate 500 TB used
        month = self.engine._current_month()
        conn = self.engine._get_conn()
        conn.execute(
            """
            INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
            VALUES (?, ?, 0, ?, ?)
            """,
            ("s4", month, 500 * 1024 * 1024 * 1024 * 1024, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

        # Upload another 1 TB
        file_size = 1024 * 1024 * 1024 * 1024
        decision = self.engine.check_request(user, endpoint="/v1/upload", incoming_file_size=file_size)
        self.assertTrue(decision.allowed)


# ---------------------------------------------------------------------------
# 3. rate_limit_per_user
# ---------------------------------------------------------------------------

class TestRateLimitPerUser(TestQuotaEngineBase):

    # QUOTA-05
    def test_rate_limit_per_user_pass_under_100_per_min(self) -> None:
        """✓ rate_limit_per_user PASS → < 100/min allowed"""
        user = User(user_id="r1", tier="solo", ip="10.0.0.20")

        # Record 50 API calls, each from a different IP so the per-IP
        # rate limit (10/sec) does not fire before the per-user check.
        for i in range(50):
            call_user = User(user_id="r1", tier="solo", ip=f"10.0.1.{i}")
            self.engine.record_api_call(call_user, endpoint=f"/v1/data/{i}", status_code=200)

        # 51st call should pass
        decision = self.engine.check_request(user, endpoint="/v1/data/50")
        self.assertTrue(decision.allowed)

    # QUOTA-06
    def test_rate_limit_per_user_fail_100_plus_per_min(self) -> None:
        """✓ rate_limit_per_user FAIL → 100+/min rejected 429"""
        user = User(user_id="r2", tier="solo", ip="10.0.0.21")

        # Record 100 API calls
        for i in range(100):
            self.engine.record_api_call(user, endpoint=f"/v1/data/{i}", status_code=200)

        # 101st call should fail
        decision = self.engine.check_request(user, endpoint="/v1/data/100")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.status_code, 429)
        self.assertEqual(decision.body["error"], "rate_limit_exceeded")
        self.assertEqual(decision.body["reset_seconds"], 60)

    def test_rate_limit_per_user_all_tiers_same_limit(self) -> None:
        """Rate limit is 100/min for all tiers."""
        for tier in TIERS:
            user = User(user_id=f"r3_{tier}", tier=tier, ip=f"10.0.0.30")
            for i in range(100):
                self.engine.record_api_call(user, endpoint=f"/v1/data/{i}", status_code=200)
            decision = self.engine.check_request(user, endpoint="/v1/data/100")
            self.assertFalse(decision.allowed, f"Tier {tier} should be rate limited")
            self.assertEqual(decision.status_code, 429)


# ---------------------------------------------------------------------------
# 4. rate_limit_per_ip
# ---------------------------------------------------------------------------

class TestRateLimitPerIp(TestQuotaEngineBase):

    # QUOTA-07
    def test_rate_limit_per_ip_pass_under_10_per_sec(self) -> None:
        """✓ rate_limit_per_ip PASS → < 10/sec allowed"""
        user = User(user_id="ip1", tier="solo", ip="10.0.0.40")

        # Record 5 API calls from this IP
        for i in range(5):
            self.engine.record_api_call(user, endpoint=f"/v1/data/{i}", status_code=200)

        # 6th call should pass
        decision = self.engine.check_request(user, endpoint="/v1/data/5")
        self.assertTrue(decision.allowed)

    # QUOTA-08
    def test_rate_limit_per_ip_fail_10_plus_per_sec(self) -> None:
        """✓ rate_limit_per_ip FAIL → 10+/sec rejected 429"""
        user = User(user_id="ip2", tier="solo", ip="10.0.0.41")

        # Record 10 API calls from this IP
        for i in range(10):
            self.engine.record_api_call(user, endpoint=f"/v1/data/{i}", status_code=200)

        # 11th call should fail
        decision = self.engine.check_request(user, endpoint="/v1/data/10")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.status_code, 429)
        self.assertEqual(decision.body["error"], "ip_rate_limit_exceeded")
        self.assertEqual(decision.body["reset_seconds"], 1)

    def test_rate_limit_per_ip_different_ips_independent(self) -> None:
        """Different IPs have independent rate limits."""
        user1 = User(user_id="ip3a", tier="solo", ip="10.0.0.50")
        user2 = User(user_id="ip3b", tier="solo", ip="10.0.0.51")

        # Fill up IP 10.0.0.50
        for i in range(10):
            self.engine.record_api_call(user1, endpoint=f"/v1/data/{i}", status_code=200)

        # IP 10.0.0.50 should be blocked
        decision1 = self.engine.check_request(user1, endpoint="/v1/data/10")
        self.assertFalse(decision1.allowed)

        # IP 10.0.0.51 should still be allowed
        decision2 = self.engine.check_request(user2, endpoint="/v1/data/0")
        self.assertTrue(decision2.allowed)


# ---------------------------------------------------------------------------
# 5. feature_gate_by_tier
# ---------------------------------------------------------------------------

class TestFeatureGateByTier(TestQuotaEngineBase):

    # QUOTA-09
    def test_feature_gate_pass_feature_available_in_tier(self) -> None:
        """✓ feature_gate PASS → feature available in tier"""
        # feature_c is available to all tiers
        for tier in TIERS:
            user = User(user_id=f"fg_{tier}", tier=tier, ip="10.0.0.60")
            decision = self.engine.check_request(user, endpoint="/v1/feature_c", feature="feature_c")
            self.assertTrue(decision.allowed, f"feature_c should be available for {tier}")

        # feature_a is available to team and enterprise
        for tier in ("team", "enterprise"):
            user = User(user_id=f"fg_a_{tier}", tier=tier, ip="10.0.0.61")
            decision = self.engine.check_request(user, endpoint="/v1/feature_a", feature="feature_a")
            self.assertTrue(decision.allowed, f"feature_a should be available for {tier}")

        # feature_b is available to enterprise only
        user = User(user_id="fg_b_ent", tier="enterprise", ip="10.0.0.62")
        decision = self.engine.check_request(user, endpoint="/v1/feature_b", feature="feature_b")
        self.assertTrue(decision.allowed)

    # QUOTA-10
    def test_feature_gate_fail_feature_unavailable_403(self) -> None:
        """✓ feature_gate FAIL → feature unavailable, 403 with upgrade hint.

        In: the engine fixture. Out: assertions. Why: QUOTA-10. Updated 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 quotas amendment): also asserts the body is exactly
        {error: "feature_not_available_in_tier", tier, minimum_tier, upgrade_url}, the one shape in every
        language. Touches: the engine's in-memory state only."""
        # feature_a not available for solo
        user = User(user_id="fg_fail1", tier="solo", ip="10.0.0.70")
        decision = self.engine.check_request(user, endpoint="/v1/feature_a", feature="feature_a")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.status_code, 403)
        self.assertEqual(decision.body["error"], "feature_not_available_in_tier")
        self.assertEqual(decision.body["tier"], "solo")
        self.assertEqual(decision.body["minimum_tier"], "team")
        self.assertIn("upgrade_url", decision.body)
        self.assertEqual(set(decision.body), {"error", "tier", "minimum_tier", "upgrade_url"})
        self.assertTrue(decision.body["upgrade_url"])

        # feature_b not available for team
        user2 = User(user_id="fg_fail2", tier="team", ip="10.0.0.71")
        decision2 = self.engine.check_request(user2, endpoint="/v1/feature_b", feature="feature_b")
        self.assertFalse(decision2.allowed)
        self.assertEqual(decision2.status_code, 403)
        self.assertEqual(decision2.body["error"], "feature_not_available_in_tier")
        self.assertEqual(decision2.body["tier"], "team")
        self.assertEqual(decision2.body["minimum_tier"], "enterprise")

    def test_feature_gate_unknown_feature(self) -> None:
        """Unknown feature is not available to any tier."""
        user = User(user_id="fg_unknown", tier="enterprise", ip="10.0.0.72")
        decision = self.engine.check_request(user, endpoint="/v1/unknown", feature="feature_z")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.status_code, 403)


# ---------------------------------------------------------------------------
# 6. month rollover
# ---------------------------------------------------------------------------

class TestMonthRollover(TestQuotaEngineBase):

    # QUOTA-11
    def test_month_rollover_usage_metrics_reset(self) -> None:
        """✓ month rollover → usage_metrics reset for new month"""
        user = User(user_id="mr1", tier="solo", ip="10.0.0.80")

        # Record some usage in the current month
        for i in range(10):
            self.engine.record_api_call(user, endpoint=f"/v1/data/{i}", status_code=200)

        usage_before = self.engine.get_usage("mr1")
        self.assertEqual(usage_before["call_count"], 10)

        # Simulate month rollover by resetting
        self.engine.reset_monthly_usage("mr1")

        usage_after = self.engine.get_usage("mr1")
        self.assertEqual(usage_after["call_count"], 0)
        self.assertEqual(usage_after["storage_bytes"], 0)

    # QUOTA-11
    def test_month_rollover_with_injected_clock_resets_quota(self) -> None:
        """A solo user at the monthly limit in January is allowed again on 1 February, with zero usage.

        In: an engine on an injected clock at 2026-01-31T23:59:59Z, 1000 recorded solo calls. Out: asserts a
        429 quota_exceeded with reset_date 2026-02-01T00:00:00Z, then, with the clock moved to February,
        call_count 0 and an allowed request; January's row is kept.
        Why: QUOTA-11 ("month rollover -> usage_metrics reset for new month"); the older test only called
        reset_monthly_usage() by hand, because the engine read the wall clock.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: an in-memory SQLite database only.
        """
        now = [datetime(2026, 1, 31, 23, 59, 59, tzinfo=timezone.utc)]
        engine = QuotaEngine(db_path=":memory:", clock=lambda: now[0])
        try:
            user = User(user_id="mr3", tier="solo", ip="10.0.0.82")
            conn = engine._get_conn()
            conn.execute(
                "INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at) VALUES (?, ?, ?, 0, ?)",
                ("mr3", "2026-01", API_CALL_LIMITS["solo"], now[0].isoformat()),
            )
            conn.commit()
            blocked = engine.check_request(user, endpoint="/v1/data")
            self.assertEqual(blocked.status_code, 429)
            self.assertEqual(blocked.body["error"], "quota_exceeded")
            self.assertEqual(blocked.body["reset_date"], "2026-02-01T00:00:00Z")

            now[0] = datetime(2026, 2, 1, 0, 0, 1, tzinfo=timezone.utc)
            self.assertEqual(engine.get_usage("mr3")["call_count"], 0)
            self.assertTrue(engine.check_request(user, endpoint="/v1/data").allowed)
            self.assertEqual(engine.get_usage("mr3", month="2026-01")["call_count"], API_CALL_LIMITS["solo"])
        finally:
            engine.close()

    def test_month_rollover_new_month_new_counters(self) -> None:
        """Usage in a new month starts from zero."""
        user = User(user_id="mr2", tier="solo", ip="10.0.0.81")

        # Record usage
        self.engine.record_api_call(user, endpoint="/v1/data", status_code=200)
        self.engine.record_storage(user, 1024)

        # Simulate a new month by inserting a row for next month
        next_month = self.engine._current_month()
        # We can't easily change the system clock, so we verify that
        # a different month key produces zero usage
        conn = self.engine._get_conn()
        row = conn.execute(
            "SELECT call_count, storage_bytes FROM usage_metrics WHERE user_id = ? AND month = ?",
            ("mr2", "2099-01"),
        ).fetchone()
        self.assertIsNone(row)  # No usage in 2099-01


# ---------------------------------------------------------------------------
# 7. tier upgrade
# ---------------------------------------------------------------------------

class TestTierUpgrade(TestQuotaEngineBase):

    # QUOTA-12
    def test_tier_upgrade_limits_updated_immediately(self) -> None:
        """✓ tier upgrade → limits updated immediately"""
        user = User(user_id="tu1", tier="solo", ip="10.0.0.90")

        # Simulate that the user has used 900 of 1000 solo API calls
        month = self.engine._current_month()
        conn = self.engine._get_conn()
        conn.execute(
            """
            INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
            VALUES (?, ?, ?, 0, ?)
            """,
            ("tu1", month, 900, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

        # As solo, 101st call would fail (900 + 101 > 1000)
        # But let's check a call that would pass for solo (901st)
        decision_solo = self.engine.check_request(user, endpoint="/v1/data")
        self.assertTrue(decision_solo.allowed)  # 901 <= 1000

        # Now upgrade to team
        self.engine.upgrade_tier("tu1", "team")
        user.tier = "team"  # Update the user object to reflect the upgrade

        # As team, the limit is 10,000, so even with 900 used, many more calls pass
        decision_team = self.engine.check_request(user, endpoint="/v1/data")
        self.assertTrue(decision_team.allowed)

        # Verify the limit is now 10,000
        self.assertEqual(API_CALL_LIMITS["team"], 10_000)

    def test_tier_upgrade_storage_limit_updated(self) -> None:
        """Storage limit updates immediately on tier upgrade."""
        user = User(user_id="tu2", tier="solo", ip="10.0.0.91")

        # Simulate 900 MB used (within solo 1 GB limit)
        month = self.engine._current_month()
        conn = self.engine._get_conn()
        conn.execute(
            """
            INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
            VALUES (?, ?, 0, ?, ?)
            """,
            ("tu2", month, 900 * 1024 * 1024, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

        # As solo, uploading 200 MB would exceed 1 GB
        decision_solo = self.engine.check_request(user, endpoint="/v1/upload", incoming_file_size=200 * 1024 * 1024)
        self.assertFalse(decision_solo.allowed)
        self.assertEqual(decision_solo.status_code, 413)

        # Upgrade to team (100 GB limit)
        self.engine.upgrade_tier("tu2", "team")
        user.tier = "team"

        # Now the same upload should pass
        decision_team = self.engine.check_request(user, endpoint="/v1/upload", incoming_file_size=200 * 1024 * 1024)
        self.assertTrue(decision_team.allowed)


# ---------------------------------------------------------------------------
# Integration: gate ordering
# ---------------------------------------------------------------------------

class TestGateOrdering(TestQuotaEngineBase):

    def test_api_quota_checked_before_rate_limit(self) -> None:
        """API quota is checked before rate limit."""
        user = User(user_id="go1", tier="solo", ip="10.0.0.100")

        # Exhaust API quota
        month = self.engine._current_month()
        conn = self.engine._get_conn()
        conn.execute(
            """
            INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
            VALUES (?, ?, ?, 0, ?)
            """,
            ("go1", month, 1000, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

        # Also fill rate limit
        for i in range(100):
            self.engine.record_api_call(user, endpoint=f"/v1/data/{i}", status_code=200)

        # API quota should fail first (gate 1 before gate 3)
        decision = self.engine.check_request(user, endpoint="/v1/data")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.body["error"], "quota_exceeded")

    def test_storage_checked_before_rate_limit(self) -> None:
        """Storage quota is checked before rate limit."""
        user = User(user_id="go2", tier="solo", ip="10.0.0.101")

        # Exhaust storage
        month = self.engine._current_month()
        conn = self.engine._get_conn()
        conn.execute(
            """
            INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
            VALUES (?, ?, 0, ?, ?)
            """,
            ("go2", month, 1_000_000_000, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

        # Also fill rate limit
        for i in range(100):
            self.engine.record_api_call(user, endpoint=f"/v1/data/{i}", status_code=200)

        # Storage should fail first (gate 2 before gate 3)
        decision = self.engine.check_request(user, endpoint="/v1/upload", incoming_file_size=1024)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.body["error"], "storage_quota_exceeded")


# ---------------------------------------------------------------------------
# Why-chain logging
# ---------------------------------------------------------------------------

class TestWhyChainLogging(TestQuotaEngineBase):

    def test_why_chain_logged_on_pass(self) -> None:
        """Why-chain entries are logged on successful checks."""
        user = User(user_id="wc1", tier="solo", ip="10.0.0.110")
        self.engine.clear_why_chain()

        decision = self.engine.check_request(user, endpoint="/v1/data", feature="feature_c")
        self.assertTrue(decision.allowed)

        entries = self.engine.get_why_chain()
        gates = [e["gate"] for e in entries]
        self.assertIn("api_quota_check", gates)
        self.assertIn("storage_quota_check", gates)
        self.assertIn("rate_limit_per_user", gates)
        self.assertIn("rate_limit_per_ip", gates)
        self.assertIn("feature_gate", gates)

    def test_why_chain_logged_on_fail(self) -> None:
        """Why-chain entries are logged on failed checks."""
        user = User(user_id="wc2", tier="solo", ip="10.0.0.111")
        self.engine.clear_why_chain()

        # Exhaust API quota
        month = self.engine._current_month()
        conn = self.engine._get_conn()
        conn.execute(
            """
            INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
            VALUES (?, ?, ?, 0, ?)
            """,
            ("wc2", month, 1000, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

        decision = self.engine.check_request(user, endpoint="/v1/data")
        self.assertFalse(decision.allowed)

        entries = self.engine.get_why_chain()
        self.assertTrue(any(e["gate"] == "api_quota_check" and e["passed"] is False for e in entries))


# ---------------------------------------------------------------------------
# JSON serialization
# ---------------------------------------------------------------------------

class TestJsonSerialization(TestQuotaEngineBase):

    def test_decision_to_json_pass(self) -> None:
        """Successful decision serializes to 200 with ok status."""
        user = User(user_id="js1", tier="solo", ip="10.0.0.120")
        decision = self.engine.check_request(user, endpoint="/v1/data")
        status, body_str = decision_to_json(decision)
        self.assertEqual(status, 200)
        body = json.loads(body_str)
        self.assertEqual(body["status"], "ok")

    def test_decision_to_json_quota_exceeded(self) -> None:
        """Quota exceeded decision serializes to 429 with correct body."""
        user = User(user_id="js2", tier="solo", ip="10.0.0.121")
        month = self.engine._current_month()
        conn = self.engine._get_conn()
        conn.execute(
            """
            INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
            VALUES (?, ?, ?, 0, ?)
            """,
            ("js2", month, 1000, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

        decision = self.engine.check_request(user, endpoint="/v1/data")
        status, body_str = decision_to_json(decision)
        self.assertEqual(status, 429)
        body = json.loads(body_str)
        self.assertEqual(body["error"], "quota_exceeded")
        self.assertEqual(body["current"], 1000)
        self.assertEqual(body["limit"], 1000)
        self.assertIn("reset_date", body)

    def test_decision_to_json_feature_not_available(self) -> None:
        """Feature not available decision serializes to 403 with upgrade hint."""
        user = User(user_id="js3", tier="solo", ip="10.0.0.122")
        decision = self.engine.check_request(user, endpoint="/v1/feature_a", feature="feature_a")
        status, body_str = decision_to_json(decision)
        self.assertEqual(status, 403)
        body = json.loads(body_str)
        self.assertEqual(body["error"], "feature_not_available_in_tier")
        self.assertEqual(body["tier"], "solo")
        self.assertEqual(body["minimum_tier"], "team")
        self.assertIn("upgrade_url", body)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases(TestQuotaEngineBase):

    def test_zero_file_size_upload(self) -> None:
        """Zero-byte file upload should pass storage check."""
        user = User(user_id="ec1", tier="solo", ip="10.0.0.130")
        decision = self.engine.check_request(user, endpoint="/v1/upload", incoming_file_size=0)
        self.assertTrue(decision.allowed)

    def test_no_feature_specified(self) -> None:
        """Request without a feature should skip feature gate."""
        user = User(user_id="ec2", tier="solo", ip="10.0.0.131")
        decision = self.engine.check_request(user, endpoint="/v1/data")
        self.assertTrue(decision.allowed)
        gates = [r.gate for r in decision.gate_results]
        self.assertNotIn("feature_gate", gates)

    def test_multiple_users_independent(self) -> None:
        """Different users have independent quotas."""
        user1 = User(user_id="ec3a", tier="solo", ip="10.0.0.140")
        user2 = User(user_id="ec3b", tier="solo", ip="10.0.0.141")

        # Exhaust user1's API quota
        month = self.engine._current_month()
        conn = self.engine._get_conn()
        conn.execute(
            """
            INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
            VALUES (?, ?, ?, 0, ?)
            """,
            ("ec3a", month, 1000, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

        # user1 should be blocked
        d1 = self.engine.check_request(user1, endpoint="/v1/data")
        self.assertFalse(d1.allowed)

        # user2 should still be allowed
        d2 = self.engine.check_request(user2, endpoint="/v1/data")
        self.assertTrue(d2.allowed)

    def test_invalid_tier_raises(self) -> None:
        """Invalid tier in upgrade_tier raises ValueError."""
        with self.assertRaises(ValueError):
            self.engine.upgrade_tier("ec4", "platinum")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)

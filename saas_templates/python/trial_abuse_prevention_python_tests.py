# Tests updated with the fix 2026-11-03: the device check counts OTHER accounts on the device (a device already tied to this account
#   no longer passes by itself); the ledger row records its user_id; timezone-aware UTC times.
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: SQLite only.
# [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Amended spec (TRIAL-09/10/11/14/15): the engine runs on an injected
#   clock; signups whose test is not about the device each use their own device (signup now runs the device gate,
#   and a sixth account on one device is refused, so the old tests' shared device would trip it); payment timing
#   is measured from the end of the trial.
import unittest
import datetime
import json
from trial_abuse_prevention_python import TrialAbusePrevention

T0 = datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)


class TestTrialAbusePrevention(unittest.TestCase):
    def setUp(self):
        """A fresh engine on a fixed clock, a shared device and a counter for per-user devices. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.now = [T0]
        self.tap = TrialAbusePrevention(clock=lambda: self.now[0])
        self.ip = "192.0.2.1"
        self._n = 0
        self.device = {
            "user_agent": "Mozilla/5.0",
            "screen_resolution": "1920x1080",
            "timezone": "UTC",
            "browser_language": "en-US",
        }

    def _own_device(self) -> dict:
        """A device no other test user has (so the device gate stays PASS). 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        self._n += 1
        return dict(self.device, user_agent=f"Mozilla/5.0 (test {self._n})")

    def _user(self, email: str) -> int:
        """The user_id of the newest ledger row for email. Touches: the test database (read)."""
        return self.tap._fetchone(
            "SELECT user_id FROM trial_abuse_ledger WHERE email = ? ORDER BY id DESC LIMIT 1", (email,))["user_id"]

    def _complete_trial(self, email: str, payment_method: str) -> int:
        """Helper: signup and complete a trial, return user_id."""
        res = self.tap.signup(email, "pwd", self.ip, self._own_device())
        self.assertTrue(res["success"])
        user_id = self.tap._fetchone(
            "SELECT user_id FROM trial_abuse_ledger WHERE email = ? ORDER BY id DESC LIMIT 1", (email,)
        )["user_id"]
        res = self.tap.subscription_created(user_id, payment_method)
        self.assertTrue(res["success"])
        return user_id

    # TRIAL-01
    def test_email_trial_history_pass(self):
        """A new email signs up.
        In: the test fixtures. Out: assertions. Why: TRIAL-01. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: each signup uses its own device (signup now runs the device gate).
        Touches: in-memory SQLite only."""
        res = self.tap.signup("new@example.com", "pwd", self.ip, self._own_device())
        self.assertTrue(res["success"])

    # TRIAL-02
    def test_email_trial_history_challenge(self):
        # First signup completes a trial
        """An email with 1 earlier trial is challenged.
        In: the test fixtures. Out: assertions. Why: TRIAL-02. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: each signup uses its own device (signup now runs the device gate).
        Touches: in-memory SQLite only."""
        self._complete_trial("dup@example.com", "pm_1")
        # Second signup with same email -> CHALLENGE
        res = self.tap.signup("dup@example.com", "pwd", self.ip, self._own_device())
        self.assertIn("challenge", res)
        self.assertEqual(res["challenge"], "email_confirm")

    # TRIAL-03
    def test_email_trial_history_fail(self):
        # Two prior completed trials with same email
        """An email with 2 earlier trials is refused 409.
        In: the test fixtures. Out: assertions. Why: TRIAL-03. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: each signup uses its own device (signup now runs the device gate).
        Touches: in-memory SQLite only."""
        self._complete_trial("fail@example.com", "pm_1")
        self._complete_trial("fail@example.com", "pm_2")
        # Third signup with same email should fail
        res = self.tap.signup("fail@example.com", "pwd", self.ip, self._own_device())
        self.assertEqual(res["code"], 409)
        self.assertEqual(res["error"], "email_has_trial_history")

    # TRIAL-04
    def test_payment_method_history_pass(self):
        # First user completes with payment method
        """A card with 1 earlier trial passes.
        In: the test fixtures. Out: assertions. Why: TRIAL-04. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: each signup uses its own device (signup now runs the device gate).
        Touches: in-memory SQLite only."""
        self._complete_trial("pay1@example.com", "pm_shared")
        # Second user with same payment method -> PASS (count=1 < 2)
        res = self.tap.signup("pay2@example.com", "pwd", self.ip, self._own_device())
        self.assertTrue(res["success"])
        user_id2 = self.tap._fetchone(
            "SELECT user_id FROM trial_abuse_ledger WHERE email = ?", ("pay2@example.com",)
        )["user_id"]
        res = self.tap.subscription_created(user_id2, "pm_shared")
        self.assertTrue(res["success"])

    # TRIAL-05
    def test_payment_method_history_fail(self):
        # Three prior completed trials with same payment method
        """A card with 3 earlier trials is refused 403.
        In: the test fixtures. Out: assertions. Why: TRIAL-05. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: each signup uses its own device (signup now runs the device gate).
        Touches: in-memory SQLite only."""
        self._complete_trial("pmfail1@example.com", "pm_shared_fail")
        self._complete_trial("pmfail2@example.com", "pm_shared_fail")
        self._complete_trial("pmfail3@example.com", "pm_shared_fail")
        # Fourth user tries same payment method -> FAIL (count=3 >= 3)
        res = self.tap.signup("pmfail4@example.com", "pwd", self.ip, self._own_device())
        self.assertTrue(res["success"])
        user_id4 = self.tap._fetchone(
            "SELECT user_id FROM trial_abuse_ledger WHERE email = ?", ("pmfail4@example.com",)
        )["user_id"]
        res = self.tap.subscription_created(user_id4, "pm_shared_fail")
        self.assertEqual(res["code"], 403)
        self.assertEqual(res["error"], "payment_method_used_for_multiple_trials")

    # TRIAL-06
    def test_ip_signup_rate_limit_pass(self):
        """The 5th signup from an IP is allowed.
        In: the test fixtures. Out: assertions. Why: TRIAL-06. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: each signup uses its own device (signup now runs the device gate).
        Touches: in-memory SQLite only."""
        for _ in range(4):
            self.tap.signup(f"ip{_}@example.com", "pwd", self.ip, self._own_device())
        res = self.tap.signup("ip5@example.com", "pwd", self.ip, self._own_device())
        self.assertTrue(res["success"])

    # TRIAL-07
    def test_ip_signup_rate_limit_fail(self):
        """The 11th signup from an IP is refused 429.
        In: the test fixtures. Out: assertions. Why: TRIAL-07. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: each signup uses its own device (signup now runs the device gate).
        Touches: in-memory SQLite only."""
        for _ in range(10):
            self.tap.signup(f"ip{_}@example.com", "pwd", self.ip, self._own_device())
        res = self.tap.signup("ip10@example.com", "pwd", self.ip, self._own_device())
        self.assertEqual(res["code"], 429)
        self.assertEqual(res["error"], "too_many_signups_from_ip")

    # TRIAL-08
    def test_device_fingerprint_pass(self):
        self.tap.signup("devpass@example.com", "pwd", self.ip, self.device)
        user_id = self.tap._fetchone("SELECT user_id FROM trial_abuse_ledger WHERE email = ?", ("devpass@example.com",))["user_id"]
        res = self.tap.check_device_fingerprint(user_id, self.device)
        self.assertEqual(res["decision"], "PASS")

    # TRIAL-09
    # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Rewritten for the amended gate: the old test signed up 7 users on
    # one device (only possible because signup recorded the device before checking it) and checked an existing user.
    def test_device_fingerprint_fail(self):
        """Five users on a device: a sixth signup on it is refused 403 device_suspected_fraud and records nothing;
        a new user checked against it FAILs and gets no device row.
        In: the test engine. Out: assertions. Why: TRIAL-09. Touches: the test database."""
        for i in range(5):
            self.assertTrue(self.tap.signup(f"devfail{i}@example.com", "pwd", f"198.51.100.{i}", self.device)["success"])
        res = self.tap.signup("devfail5@example.com", "pwd", "198.51.100.9", self.device)
        self.assertEqual(res, {"error": "device_suspected_fraud", "code": 403})
        self.assertIsNone(self.tap._fetchone("SELECT 1 FROM trial_abuse_ledger WHERE email = ?", ("devfail5@example.com",)))
        self.assertEqual(self.tap._fetchone("SELECT COUNT(*) AS c FROM signups WHERE ip = ?", ("198.51.100.9",))["c"], 0)
        res = self.tap.check_device_fingerprint(999, self.device)
        self.assertEqual((res["decision"], res["matching_users"]), ("FAIL", 5))
        self.assertEqual(self._device_rows(999), 0)

    def _device_rows(self, user_id: int) -> int:
        """How many device rows a user has. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: test db (read)."""
        return self.tap._fetchone("SELECT COUNT(*) AS c FROM device_fingerprints WHERE user_id = ?", (user_id,))["c"]

    def _seed_device_users(self, user_ids) -> None:
        """Give each user id a row for self.device. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        for uid in user_ids:
            self.tap._record_device(uid, self.device, self.tap._hash_device(self.device))

    # TRIAL-14
    def test_device_fingerprint_boundaries(self):
        """4 other users -> CHALLENGE and the row is written; exactly 5 others -> FAIL even for a user who already
        has the device, and a FAIL writes no row; 1 other -> PASS; a user who has the device among 2-4 others PASS.
        In: seeded device rows. Out: assertions. Why: TRIAL-14 (amended 2026-11-10).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test database."""
        self._seed_device_users([1])
        self.assertEqual(self.tap.check_device_fingerprint(50, self.device)["decision"], "PASS")  # 1 other
        self._seed_device_users([2, 3])
        self.assertEqual(self.tap.check_device_fingerprint(50, self.device)["decision"], "PASS")  # has it already
        res = self.tap.check_device_fingerprint(60, self.device)  # others: 1, 2, 3, 50
        self.assertEqual((res["decision"], res["matching_users"]), ("CHALLENGE", 4))
        self.assertEqual(self._device_rows(60), 1)
        res = self.tap.check_device_fingerprint(70, self.device)  # others: 1, 2, 3, 50, 60
        self.assertEqual((res["decision"], res["matching_users"]), ("FAIL", 5))
        self.assertEqual(self._device_rows(70), 0)
        self._seed_device_users([80])
        res = self.tap.check_device_fingerprint(1, self.device)  # user 1 has it; others: 2, 3, 50, 60, 80
        self.assertEqual((res["decision"], res["matching_users"]), ("FAIL", 5))
        res = self.tap.check_device_fingerprint(None, self.device)  # null-safe: counts every user
        self.assertEqual((res["decision"], res["matching_users"]), ("FAIL", 6))

    def _signup_at(self, email: str) -> int:
        """Sign up email at the current clock time on its own device; return the user_id."""
        self.assertTrue(self.tap.signup(email, "pwd", self.ip, self._own_device())["success"])
        return self._user(email)

    # TRIAL-10
    # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Now pins the payment time with the clock: 4 days after the trial
    # ended (and, for a second user, during the trial).
    def test_trial_payment_timing_pass(self):
        """A first payment 4 days after the 14-day trial ended PASSes, and so does one during the trial.
        In: the clocked engine. Out: assertions. Why: TRIAL-10 (amended 2026-11-10). Touches: the test database."""
        user_id = self._signup_at("timingpass@example.com")
        during = self._signup_at("during@example.com")
        self.now[0] = T0 + datetime.timedelta(days=14 + 4, hours=23)
        res = self.tap.check_trial_payment_timing(user_id)
        self.assertEqual((res["decision"], res["days_after_trial"]), ("PASS", 4))
        self.assertTrue(self.tap.subscription_created(user_id, "pm_timing")["success"])
        self.now[0] = T0 + datetime.timedelta(days=3)
        res = self.tap.check_trial_payment_timing(during)
        self.assertEqual((res["decision"], res["days_after_trial"]), ("PASS", -11))
        self.now[0] = T0 + datetime.timedelta(days=13, hours=23)
        self.assertEqual(self.tap.check_trial_payment_timing(during)["days_after_trial"], -1)  # floor, not truncation

    # TRIAL-11
    # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Now 90 days after the trial ENDED (was 100 days after the start).
    def test_trial_payment_timing_fail(self):
        """A first payment 90 days after the trial ended, with no earlier payment, is refused 403.
        In: the clocked engine. Out: assertions. Why: TRIAL-11 (amended 2026-11-10). Touches: the test database."""
        user_id = self._signup_at("timingfail@example.com")
        self.now[0] = T0 + datetime.timedelta(days=14 + 90)
        res = self.tap.subscription_created(user_id, "pm_timing_fail")
        self.assertEqual(res["code"], 403)
        self.assertEqual(res["error"], "trial_ended_no_payment_cannot_retry")
        self.assertIsNone(self.tap.get_user(user_id)["payment_added_date"])

    # TRIAL-15
    def test_trial_payment_timing_boundaries(self):
        """5 and 89 days after the trial -> CHALLENGE; 90 days with an earlier payment -> CHALLENGE; trial_days
        is configurable. In: the clocked engine. Out: assertions. Why: TRIAL-15 (amended 2026-11-10).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test database."""
        user_id = self._signup_at("bounds@example.com")
        for days, decision in ((5, "CHALLENGE"), (89, "CHALLENGE"), (90, "FAIL")):
            self.now[0] = T0 + datetime.timedelta(days=14 + days)
            self.assertEqual(self.tap.check_trial_payment_timing(user_id)["decision"], decision, days)
        self.now[0] = T0 + datetime.timedelta(days=14 + 1)
        self.assertTrue(self.tap.subscription_created(user_id, "pm_bounds")["success"])  # an earlier payment
        self.now[0] = T0 + datetime.timedelta(days=14 + 90)
        res = self.tap.check_trial_payment_timing(user_id)
        self.assertEqual((res["decision"], res["earlier_payment"]), ("CHALLENGE", True))
        short = TrialAbusePrevention(clock=lambda: self.now[0], trial_days=7)
        self.now[0] = T0
        short.signup("short@example.com", "pwd", self.ip, self.device)
        self.now[0] = T0 + datetime.timedelta(days=7 + 5)
        self.assertEqual(short.check_trial_payment_timing(1)["decision"], "CHALLENGE")

    # TRIAL-11
    # TRIAL-15
    def test_trial_payment_timing_missing_user_or_ledger_row(self):
        """No users row -> FAIL user_not_found (and subscription_created refuses 403 user_not_found, recording
        nothing); a users row with no ledger row is judged from users.created_at with no earlier payment
        (4 days after the trial PASS, 89 CHALLENGE, 90 FAIL), and a payment then gets its ledger row.
        In: the clocked engine. Out: assertions. Why: the Phase B.2 amendment to gate 5 (2026-11-10).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test database."""
        res = self.tap.check_trial_payment_timing(999)
        self.assertEqual((res["decision"], res["reason"]), ("FAIL", "user_not_found"))
        self.assertEqual(self.tap.subscription_created(999, "pm_ghost"), {"error": "user_not_found", "code": 403})
        self.assertIsNone(self.tap.get_user(999))

        legacy = self.tap.add_user("legacy@example.com", created_at=T0 - datetime.timedelta(days=30))
        self.assertIsNone(self.tap.get_user(legacy))  # no ledger row
        for days, decision in ((4, "PASS"), (89, "CHALLENGE"), (90, "FAIL")):
            self.now[0] = T0 - datetime.timedelta(days=30) + datetime.timedelta(days=14 + days)
            res = self.tap.check_trial_payment_timing(legacy)
            self.assertEqual((res["decision"], res["days_after_trial"], res["earlier_payment"]),
                             (decision, days, False))
        self.now[0] = T0 - datetime.timedelta(days=30) + datetime.timedelta(days=14 + 4)
        self.assertTrue(self.tap.subscription_created(legacy, "pm_legacy")["success"])
        self.assertIsNotNone(self.tap.get_user(legacy)["payment_added_date"])
        self.now[0] = T0 - datetime.timedelta(days=30) + datetime.timedelta(days=14 + 90)
        self.assertEqual(self.tap.check_trial_payment_timing(legacy)["earlier_payment"], True)

    # TRIAL-12
    def test_chargeback_history_pass(self):
        """No chargebacks: the gate passes and the subscription is created.
        In: the test fixtures. Out: assertions. Why: TRIAL-12. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: each signup uses its own device (signup now runs the device gate).
        Touches: in-memory SQLite only."""
        user_id = self._signup_at("cbpass@example.com")
        self.assertEqual(self.tap.check_chargeback_history(user_id)["decision"], "PASS")
        res = self.tap.subscription_created(user_id, "pm_cb")
        self.assertTrue(res["success"])

    # TRIAL-13
    def test_chargeback_history_fail(self):
        """Two chargebacks: refused 403, prepayment required.
        In: the test fixtures. Out: assertions. Why: TRIAL-13. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: each signup uses its own device (signup now runs the device gate).
        Touches: in-memory SQLite only."""
        user_id = self._signup_at("cbfail@example.com")
        # Add two chargebacks
        self.tap.add_stripe_event(str(user_id), "chargeback")
        self.tap.add_stripe_event(str(user_id), "chargeback")
        res = self.tap.subscription_created(user_id, "pm_cb_fail")
        self.assertEqual(res["code"], 403)
        self.assertEqual(res["error"], "chargeback_history_requires_prepayment")

if __name__ == "__main__":
    unittest.main()

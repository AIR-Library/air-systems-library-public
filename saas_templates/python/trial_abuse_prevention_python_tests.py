# Tests updated with the fix 2026-11-03: the device check counts OTHER accounts on the device (a device already tied to this account
#   no longer passes by itself); the ledger row records its user_id; timezone-aware UTC times.
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: SQLite only.
import unittest
import datetime
import json
from trial_abuse_prevention_python import TrialAbusePrevention

class TestTrialAbusePrevention(unittest.TestCase):
    def setUp(self):
        self.tap = TrialAbusePrevention()
        self.ip = "192.0.2.1"
        self.device = {
            "user_agent": "Mozilla/5.0",
            "screen_resolution": "1920x1080",
            "timezone": "UTC",
            "browser_language": "en-US",
        }

    def _complete_trial(self, email: str, payment_method: str) -> int:
        """Helper: signup and complete a trial, return user_id."""
        res = self.tap.signup(email, "pwd", self.ip, self.device)
        self.assertTrue(res["success"])
        user_id = self.tap._fetchone(
            "SELECT user_id FROM trial_abuse_ledger WHERE email = ? ORDER BY id DESC LIMIT 1", (email,)
        )["user_id"]
        res = self.tap.subscription_created(user_id, payment_method)
        self.assertTrue(res["success"])
        return user_id

    def test_email_trial_history_pass(self):
        res = self.tap.signup("new@example.com", "pwd", self.ip, self.device)
        self.assertTrue(res["success"])

    def test_email_trial_history_challenge(self):
        # First signup completes a trial
        self._complete_trial("dup@example.com", "pm_1")
        # Second signup with same email -> CHALLENGE
        res = self.tap.signup("dup@example.com", "pwd", self.ip, self.device)
        self.assertIn("challenge", res)
        self.assertEqual(res["challenge"], "email_confirm")

    def test_email_trial_history_fail(self):
        # Two prior completed trials with same email
        self._complete_trial("fail@example.com", "pm_1")
        self._complete_trial("fail@example.com", "pm_2")
        # Third signup with same email should fail
        res = self.tap.signup("fail@example.com", "pwd", self.ip, self.device)
        self.assertEqual(res["code"], 409)
        self.assertEqual(res["error"], "email_has_trial_history")

    def test_payment_method_history_pass(self):
        # First user completes with payment method
        self._complete_trial("pay1@example.com", "pm_shared")
        # Second user with same payment method -> PASS (count=1 < 2)
        res = self.tap.signup("pay2@example.com", "pwd", self.ip, self.device)
        self.assertTrue(res["success"])
        user_id2 = self.tap._fetchone(
            "SELECT user_id FROM trial_abuse_ledger WHERE email = ?", ("pay2@example.com",)
        )["user_id"]
        res = self.tap.subscription_created(user_id2, "pm_shared")
        self.assertTrue(res["success"])

    def test_payment_method_history_fail(self):
        # Three prior completed trials with same payment method
        self._complete_trial("pmfail1@example.com", "pm_shared_fail")
        self._complete_trial("pmfail2@example.com", "pm_shared_fail")
        self._complete_trial("pmfail3@example.com", "pm_shared_fail")
        # Fourth user tries same payment method -> FAIL (count=3 >= 3)
        res = self.tap.signup("pmfail4@example.com", "pwd", self.ip, self.device)
        self.assertTrue(res["success"])
        user_id4 = self.tap._fetchone(
            "SELECT user_id FROM trial_abuse_ledger WHERE email = ?", ("pmfail4@example.com",)
        )["user_id"]
        res = self.tap.subscription_created(user_id4, "pm_shared_fail")
        self.assertEqual(res["code"], 403)
        self.assertEqual(res["error"], "payment_method_used_for_multiple_trials")

    def test_ip_signup_rate_limit_pass(self):
        for _ in range(4):
            self.tap.signup(f"ip{_}@example.com", "pwd", self.ip, self.device)
        res = self.tap.signup("ip5@example.com", "pwd", self.ip, self.device)
        self.assertTrue(res["success"])

    def test_ip_signup_rate_limit_fail(self):
        for _ in range(10):
            self.tap.signup(f"ip{_}@example.com", "pwd", self.ip, self.device)
        res = self.tap.signup("ip10@example.com", "pwd", self.ip, self.device)
        self.assertEqual(res["code"], 429)
        self.assertEqual(res["error"], "too_many_signups_from_ip")

    def test_device_fingerprint_pass(self):
        self.tap.signup("devpass@example.com", "pwd", self.ip, self.device)
        user_id = self.tap._fetchone("SELECT user_id FROM trial_abuse_ledger WHERE email = ?", ("devpass@example.com",))["user_id"]
        res = self.tap.check_device_fingerprint(user_id, self.device)
        self.assertEqual(res["decision"], "PASS")

    def test_device_fingerprint_fail(self):
        # Create 6 users with same device
        for i in range(6):
            self.tap.signup(f"devfail{i}@example.com", "pwd", self.ip, self.device)
        # New user with same device
        self.tap.signup("devfail6@example.com", "pwd", self.ip, self.device)
        user_id = self.tap._fetchone("SELECT user_id FROM trial_abuse_ledger WHERE email = ?", ("devfail6@example.com",))["user_id"]
        res = self.tap.check_device_fingerprint(user_id, self.device)
        self.assertEqual(res["decision"], "FAIL")

    def test_trial_payment_timing_pass(self):
        self.tap.signup("timingpass@example.com", "pwd", self.ip, self.device)
        user_id = self.tap._fetchone("SELECT user_id FROM trial_abuse_ledger WHERE email = ?", ("timingpass@example.com",))["user_id"]
        res = self.tap.subscription_created(user_id, "pm_timing")
        self.assertTrue(res["success"])

    def test_trial_payment_timing_fail(self):
        self.tap.signup("timingfail@example.com", "pwd", self.ip, self.device)
        user_id = self.tap._fetchone("SELECT user_id FROM trial_abuse_ledger WHERE email = ?", ("timingfail@example.com",))["user_id"]
        # Simulate trial ended 100 days ago, no payment added
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=100)
        self.tap._execute(
            """
            UPDATE trial_abuse_ledger
            SET trial_started_at = ?, subscription_status = 'completed'
            WHERE user_id = ?
            """,
            (past.isoformat(), user_id),
        )
        res = self.tap.subscription_created(user_id, "pm_timing_fail")
        self.assertEqual(res["code"], 403)
        self.assertEqual(res["error"], "trial_ended_no_payment_cannot_retry")

    def test_chargeback_history_pass(self):
        self.tap.signup("cbpass@example.com", "pwd", self.ip, self.device)
        user_id = self.tap._fetchone("SELECT user_id FROM trial_abuse_ledger WHERE email = ?", ("cbpass@example.com",))["user_id"]
        res = self.tap.subscription_created(user_id, "pm_cb")
        self.assertTrue(res["success"])

    def test_chargeback_history_fail(self):
        self.tap.signup("cbfail@example.com", "pwd", self.ip, self.device)
        user_id = self.tap._fetchone("SELECT user_id FROM trial_abuse_ledger WHERE email = ?", ("cbfail@example.com",))["user_id"]
        # Add two chargebacks
        self.tap.add_stripe_event(str(user_id), "chargeback")
        self.tap.add_stripe_event(str(user_id), "chargeback")
        res = self.tap.subscription_created(user_id, "pm_cb_fail")
        self.assertEqual(res["code"], 403)
        self.assertEqual(res["error"], "chargeback_history_requires_prepayment")

if __name__ == "__main__":
    unittest.main()

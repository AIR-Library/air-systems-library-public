# Tests updated with the fix 2026-11-03: uses the stripe package's current error classes and timezone-aware UTC times
#   (datetime.utcnow is deprecated).
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: Stripe API (mocked in tests), SQLite.
import os
import json
import time
import unittest
from unittest.mock import patch, MagicMock

import stripe
from billing_subscriptions_python import BillingSystem, iso_now

class TestBillingSystem(unittest.TestCase):
    def setUp(self):
        os.environ["STRIPE_SECRET_KEY"] = "sk_test_dummy"
        os.environ["STRIPE_WEBHOOK_SECRET"] = "whsec_dummy"
        self.bs = BillingSystem()
        # Mock stripe
        self.patcher = patch("billing_subscriptions_python.stripe")
        self.mock_stripe = self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def _make_mock_event(self, event_dict):
        """Create a mock Stripe event object with attribute access."""
        mock_event = MagicMock()
        mock_event.id = event_dict["id"]
        mock_event.type = event_dict["type"]
        mock_event.data = MagicMock()
        mock_event.data.object = MagicMock()
        for key, value in event_dict["data"]["object"].items():
            setattr(mock_event.data.object, key, value)
        # Handle nested items for subscription.updated
        if "items" in event_dict["data"]["object"]:
            mock_items = MagicMock()
            mock_items.data = []
            for item in event_dict["data"]["object"]["items"]["data"]:
                mock_item = MagicMock()
                mock_price = MagicMock()
                for pk, pv in item["price"].items():
                    setattr(mock_price, pk, pv)
                mock_item.price = mock_price
                mock_items.data.append(mock_item)
            mock_event.data.object.items = mock_items
        return mock_event

    # BILL-01
    def test_create_subscription_happy_path(self):
        mock_sub = MagicMock()
        mock_sub.id = "sub_123"
        mock_sub.status = "active"
        mock_sub.current_period_end = int(time.time()) + 30 * 24 * 3600
        self.mock_stripe.Subscription.create.return_value = mock_sub

        resp = self.bs.create_subscription("cus_abc", "solo")
        self.assertTrue(resp["success"])
        self.assertEqual(resp["subscription_id"], "sub_123")
        self.assertEqual(resp["tier"], "solo")
        self.assertEqual(resp["status"], "active")
        self.assertIn("next_billing_date", resp)

        # DB record exists
        rec = self.bs.db.fetchone(
            "SELECT * FROM subscriptions WHERE stripe_subscription_id = ?", ("sub_123",)
        )
        self.assertIsNotNone(rec)

    # BILL-02
    def test_create_subscription_invalid_tier(self):
        resp = self.bs.create_subscription("cus_abc", "gold")
        self.assertIn("error", resp)
        self.assertEqual(resp["error"], "invalid_tier")

    # BILL-03
    def test_change_plan_happy_path(self):
        # Setup existing subscription
        """change_plan updates the existing item with the new price, prorates, updates the row.
        In: the test fixtures. Out: assertions. Why: BILL-03. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: retrieve() is mocked and the modify() arguments are asserted.
        Touches: mocked Stripe, in-memory SQLite only."""
        self.bs.db.execute(
            """
            INSERT INTO subscriptions (stripe_subscription_id, customer_id, tier, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("sub_123", "cus_abc", "solo", "active", iso_now(), iso_now()),
        )
        mock_sub = MagicMock()
        mock_sub.id = "sub_123"
        mock_sub.status = "active"
        mock_sub.current_period_start = int(time.time())
        mock_sub.proration_amounts = [{"amount": 500}]
        self.mock_stripe.Subscription.modify.return_value = mock_sub
        # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] BILL-03 as amended: change_plan reads the one existing
        # item and updates THAT item, so the test now gives retrieve() an item and checks the update's arguments.
        self.mock_stripe.Subscription.retrieve.return_value = {
            "id": "sub_123", "items": {"data": [{"id": "si_existing", "price": {"id": "price_1UIxxxxxx_solo"}}]}}

        resp = self.bs.change_plan("sub_123", "team")
        self.assertTrue(resp["success"])
        self.assertEqual(resp["old_tier"], "solo")
        self.assertEqual(resp["new_tier"], "team")
        self.assertEqual(resp["proration_credit"], 5.0)
        self.mock_stripe.Subscription.modify.assert_called_once_with(
            "sub_123",
            items=[{"id": "si_existing", "price": "price_1UIxxxxxx_team"}],
            proration_behavior="create_prorations",
        )

        # DB updated
        rec = self.bs.db.fetchone(
            "SELECT tier, status FROM subscriptions WHERE stripe_subscription_id = ?", ("sub_123",)
        )
        self.assertEqual(rec[0], "team")
        self.assertEqual(rec[1], "active")

    # BILL-03
    def test_change_plan_rejects_unknown_tier_and_ambiguous_items_before_any_update(self):
        """An unknown tier is invalid_tier and a subscription with 0 or 2 items is subscription_item_ambiguous,
        and neither calls Stripe's update nor changes the row.

        In: a solo subscription row; retrieve() mocked to return 0 then 2 items. Out: assertions.
        Why: BILL-03 (amended 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches: mocked Stripe, in-memory SQLite."""
        self.bs.db.execute(
            """
            INSERT INTO subscriptions (stripe_subscription_id, customer_id, tier, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("sub_9", "cus_abc", "solo", "active", iso_now(), iso_now()),
        )
        resp = self.bs.change_plan("sub_9", "gold")
        self.assertEqual(resp["error"], "invalid_tier")
        self.mock_stripe.Subscription.retrieve.assert_not_called()
        for items in ([], [{"id": "si_a"}, {"id": "si_b"}]):
            self.mock_stripe.Subscription.retrieve.return_value = {"id": "sub_9", "items": {"data": items}}
            resp = self.bs.change_plan("sub_9", "team")
            self.assertEqual(resp["error"], "subscription_item_ambiguous")
        self.mock_stripe.Subscription.modify.assert_not_called()
        rec = self.bs.db.fetchone("SELECT tier FROM subscriptions WHERE stripe_subscription_id = ?", ("sub_9",))
        self.assertEqual(rec[0], "solo")

    # BILL-04
    def test_queue_refund_happy_path(self):
        # Insert invoice
        self.bs.db.execute(
            """
            INSERT INTO invoices (stripe_invoice_id, customer_id, amount, status, paid_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            ("inv_123", "cus_abc", 1000, "succeeded", iso_now()),
        )
        resp = self.bs.queue_refund("inv_123", 200, "duplicate charge", "admin")
        self.assertTrue(resp["success"])
        self.assertEqual(resp["status"], "queued")
        self.assertEqual(resp["amount"], 200)

        # Refund record exists
        rec = self.bs.db.fetchone(
            "SELECT amount, status FROM refunds WHERE id = ?", (resp["refund_id"],)
        )
        self.assertEqual(rec[0], 200)
        self.assertEqual(rec[1], "queued")

    # BILL-05
    def test_queue_refund_amount_exceeds_invoice(self):
        self.bs.db.execute(
            """
            INSERT INTO invoices (stripe_invoice_id, customer_id, amount, status, paid_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            ("inv_123", "cus_abc", 1000, "succeeded", iso_now()),
        )
        resp = self.bs.queue_refund("inv_123", 1200, "overcharge", "admin")
        self.assertIn("error", resp)
        self.assertEqual(resp["error"], "refund_exceeds_invoice")

    # BILL-06
    def test_handle_webhook_payment_succeeded(self):
        event_dict = {
            "id": "evt_123",
            "type": "invoice.payment_succeeded",
            "data": {
                "object": {
                    "id": "inv_123",
                    "customer": "cus_abc",
                    "amount_paid": 1000,
                }
            },
        }
        payload = json.dumps(event_dict)
        sig_header = "t=12345,v1=signature"

        # Mock signature verification to return proper event object
        self.mock_stripe.Webhook.construct_event.return_value = self._make_mock_event(event_dict)

        resp = self.bs.handle_stripe_webhook(payload, sig_header)
        self.assertTrue(resp["received"])

        # Invoice inserted
        rec = self.bs.db.fetchone(
            "SELECT stripe_invoice_id, amount FROM invoices WHERE stripe_invoice_id = ?", ("inv_123",)
        )
        self.assertIsNotNone(rec)
        self.assertEqual(rec[1], 1000)

    # BILL-07
    def test_handle_webhook_duplicate_event(self):
        # Insert event record
        self.bs.db.execute(
            "INSERT INTO events (stripe_event_id, event_type, processed_at) VALUES (?, ?, ?)",
            ("evt_123", "invoice.payment_succeeded", iso_now()),
        )
        event_dict = {
            "id": "evt_123",
            "type": "invoice.payment_succeeded",
            "data": {"object": {"id": "inv_123", "customer": "cus_abc", "amount_paid": 1000}},
        }
        payload = json.dumps(event_dict)
        sig_header = "t=12345,v1=signature"
        self.mock_stripe.Webhook.construct_event.return_value = self._make_mock_event(event_dict)

        resp = self.bs.handle_stripe_webhook(payload, sig_header)
        self.assertTrue(resp["received"])

    # BILL-08
    def test_handle_webhook_subscription_updated(self):
        event_dict = {
            "id": "evt_456",
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "id": "sub_123",
                    "customer": "cus_abc",
                    "status": "active",
                    "items": {
                        "data": [
                            {
                                "price": {"lookup_key": "team"},
                            }
                        ]
                    },
                }
            },
        }
        payload = json.dumps(event_dict)
        sig_header = "t=12345,v1=signature"
        self.mock_stripe.Webhook.construct_event.return_value = self._make_mock_event(event_dict)

        # Insert subscription
        self.bs.db.execute(
            """
            INSERT INTO subscriptions (stripe_subscription_id, customer_id, tier, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("sub_123", "cus_abc", "solo", "active", iso_now(), iso_now()),
        )

        resp = self.bs.handle_stripe_webhook(payload, sig_header)
        self.assertTrue(resp["received"])

        rec = self.bs.db.fetchone(
            "SELECT tier, status FROM subscriptions WHERE stripe_subscription_id = ?", ("sub_123",)
        )
        self.assertEqual(rec[0], "team")
        self.assertEqual(rec[1], "active")

    # BILL-09
    def test_webhook_signature_invalid(self):
        payload = "{}"
        sig_header = "invalid"
        self.mock_stripe.Webhook.construct_event.side_effect = stripe.SignatureVerificationError("Invalid signature", sig_header)
        resp = self.bs.handle_stripe_webhook(payload, sig_header)
        self.assertIn("error", resp)
        self.assertEqual(resp["error"], "invalid_signature")

    # BILL-10
    def test_webhook_response_time(self):
        event_dict = {
            "id": "evt_789",
            "type": "invoice.payment_succeeded",
            "data": {"object": {"id": "inv_123", "customer": "cus_abc", "amount_paid": 1000}},
        }
        payload = json.dumps(event_dict)
        sig_header = "t=12345,v1=signature"
        self.mock_stripe.Webhook.construct_event.return_value = self._make_mock_event(event_dict)

        start = time.time()
        resp = self.bs.handle_stripe_webhook(payload, sig_header)
        elapsed = time.time() - start
        self.assertTrue(elapsed < 3)
        self.assertTrue(resp["received"])

if __name__ == "__main__":
    unittest.main()

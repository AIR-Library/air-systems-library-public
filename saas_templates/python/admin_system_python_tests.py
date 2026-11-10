# Tests updated with the fix 2026-11-03: the audit table gained the column the code writes, and audit history is ordered by
#   timestamp, then id, so rows written in the same second keep a fixed order.
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: SQLite only.
import unittest
import os
import json
from admin_system_python import AdminSystem, HTTPError, CSRF_TOKEN

class FakeStripe:
    """A fake Stripe client: Subscription.retrieve returns the given items, Subscription.modify records its call.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-12). Touches nothing; no network."""

    class _Subscription:
        def __init__(self, items):
            """Hold the items retrieve() returns and the calls modify() received. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
            self.items = items
            self.modified = []

        def retrieve(self, subscription_id):
            """Return the subscription with the configured items (Stripe's shape). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
            return {"id": subscription_id, "items": {"data": list(self.items)}}

        def modify(self, subscription_id, **params):
            """Record (subscription_id, params) and return an active subscription. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
            self.modified.append((subscription_id, params))
            return {"id": subscription_id, "status": "active"}

    def __init__(self, items):
        """A fake client whose Subscription returns `items`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.Subscription = self._Subscription(items)


class TestAdminSystem(unittest.TestCase):
    def setUp(self):
        """A fresh AdminSystem (no Stripe client) with an owner and a normal user. Split 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite only."""
        self.sys = AdminSystem()
        self.setUp_users()

    def setUp_users(self):
        """Insert the owner and the normal user into self.sys. Split out of setUp 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP, so a test can rebuild self.sys with a fake Stripe client."""
        # Create an owner user
        cur = self.sys.conn.cursor()
        cur.execute(
            """INSERT INTO users (email, name, tier, created_at, last_active_at)
               VALUES ('owner@example.com', 'Owner', 'owner', ?, ?)""",
            (self._now(), self._now())
        )
        self.owner_id = cur.lastrowid
        # Create a normal user
        cur.execute(
            """INSERT INTO users (email, name, tier, created_at, last_active_at)
               VALUES ('user@example.com', 'User', 'user', ?, ?)""",
            (self._now(), self._now())
        )
        self.user_id = cur.lastrowid
        self.sys.conn.commit()

    def _now(self):
        return "2023-01-01T00:00:00Z"

    # ----- USERS DOMAIN TESTS -----
    # ADMIN-01
    def test_create_user_happy_path(self):
        payload = {
            "email": "newuser@example.com",
            "name": "New User",
            "tier": "admin",
            "notify": True
        }
        resp = self.sys.users_action(CSRF_TOKEN, self.owner_id, "create", payload)
        self.assertTrue(resp["success"])
        self.assertIn("user_id", resp)
        self.assertEqual(resp["email"], payload["email"])
        self.assertEqual(resp["tier"], payload["tier"])
        # Verify email sent
        self.assertTrue(any(email == payload["email"] for email, _ in self.sys.email_outbox))

    # ADMIN-02
    def test_create_user_duplicate_email(self):
        payload = {
            "email": "owner@example.com",
            "name": "Dup",
            "tier": "admin",
            "notify": False
        }
        with self.assertRaises(HTTPError) as ctx:
            self.sys.users_action(CSRF_TOKEN, self.owner_id, "create", payload)
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(ctx.exception.code, "email_exists")

    # ADMIN-03
    def test_create_user_non_owner(self):
        payload = {
            "email": "another@example.com",
            "name": "Another",
            "tier": "user",
            "notify": False
        }
        with self.assertRaises(HTTPError) as ctx:
            self.sys.users_action(CSRF_TOKEN, self.user_id, "create", payload)
        self.assertEqual(ctx.exception.status, 403)
        self.assertEqual(ctx.exception.code, "owner_only")

    # ADMIN-04
    def test_reset_password_happy_path(self):
        payload = {"user_id": self.user_id}
        resp = self.sys.users_action(CSRF_TOKEN, self.owner_id, "reset_password", payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["status"], "reset_email_sent")
        # Verify email sent
        target_email = self.sys._get_user_by_id(self.user_id)["email"]
        self.assertTrue(any(email == target_email for email, _ in self.sys.email_outbox))

    # ADMIN-05
    def test_reset_password_own_account(self):
        payload = {"user_id": self.owner_id}
        with self.assertRaises(HTTPError) as ctx:
            self.sys.users_action(CSRF_TOKEN, self.owner_id, "reset_password", payload)
        self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(ctx.exception.code, "cannot_reset_own_password")

    # ADMIN-06
    def test_change_role_happy_path(self):
        payload = {"user_id": self.user_id, "new_tier": "admin"}
        resp = self.sys.users_action(CSRF_TOKEN, self.owner_id, "change_role", payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["old_tier"], "user")
        self.assertEqual(resp["new_tier"], "admin")
        # Verify audit log entry
        cur = self.sys.conn.cursor()
        cur.execute("SELECT * FROM audit_log WHERE action='role_changed'")
        row = cur.fetchone()
        self.assertIsNotNone(row)
        details = json.loads(row["details"])
        self.assertEqual(details["old_tier"], "user")
        self.assertEqual(details["new_tier"], "admin")

    # ADMIN-07
    def test_change_role_last_owner(self):
        # Create a second owner, suspend the first owner, then try to demote the second owner
        cur = self.sys.conn.cursor()
        cur.execute(
            """INSERT INTO users (email, name, tier, created_at, last_active_at)
               VALUES ('owner2@example.com', 'Owner2', 'owner', ?, ?)""",
            (self._now(), self._now())
        )
        owner2_id = cur.lastrowid
        # Suspend the original owner (actor) so owner2 becomes the last active owner
        cur.execute("UPDATE users SET status = 'suspended' WHERE id = ?", (self.owner_id,))
        self.sys.conn.commit()

        # Now actor (original owner, suspended but still tier=owner) tries to demote owner2
        payload = {"user_id": owner2_id, "new_tier": "admin"}
        with self.assertRaises(HTTPError) as ctx:
            self.sys.users_action(CSRF_TOKEN, self.owner_id, "change_role", payload)
        self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(ctx.exception.code, "cannot_demote_last_owner")

    # ADMIN-08
    def test_suspend_user_happy_path(self):
        payload = {"user_id": self.user_id, "reason": "violation"}
        resp = self.sys.users_action(CSRF_TOKEN, self.owner_id, "suspend", payload)
        self.assertTrue(resp["success"])
        self.assertTrue(resp["suspended"])
        cur = self.sys.conn.cursor()
        cur.execute("SELECT status FROM users WHERE id = ?", (self.user_id,))
        self.assertEqual(cur.fetchone()["status"], "suspended")

    # ADMIN-09
    def test_suspend_own_account(self):
        payload = {"user_id": self.owner_id, "reason": "self"}
        with self.assertRaises(HTTPError) as ctx:
            self.sys.users_action(CSRF_TOKEN, self.owner_id, "suspend", payload)
        self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(ctx.exception.code, "cannot_suspend_yourself")

    # ----- CUSTOMERS DOMAIN TESTS -----
    # ADMIN-10
    def test_customers_list_pagination(self):
        cur = self.sys.conn.cursor()
        for i in range(5):
            cur.execute(
                """INSERT INTO customers (email, name, tier, signup_date)
                   VALUES (?, ?, ?, ?)""",
                (f"c{i}@example.com", f"Cust{i}", "user", self._now())
            )
        self.sys.conn.commit()
        result = self.sys.list_customers(self.owner_id, limit=2, offset=1)
        self.assertEqual(len(result), 2)
        self.assertIn("email", result[0])
        self.assertIn("signup_date", result[0])

    # ADMIN-11
    def test_customers_detail_fields(self):
        cur = self.sys.conn.cursor()
        cur.execute(
            """INSERT INTO customers (email, name, tier, signup_date, invoice_count, status,
                                      stripe_subscription_id, payment_method, address, notes)
               VALUES ('cust@example.com','Cust','user','2023-01-01','0','active','sub_123','card_abc','Addr','Note')"""
        )
        cust_id = cur.lastrowid
        self.sys.conn.commit()
        detail = self.sys.get_customer_detail(self.owner_id, cust_id)
        self.assertEqual(detail["email"], "cust@example.com")
        self.assertEqual(detail["stripe_subscription_id"], "sub_123")

    # ADMIN-12
    # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Changed for the amended ADMIN-12: a plan is a billing tier
    # (solo/team/enterprise), not a staff role ("user" -> "admin" before), and the test now checks the Stripe call:
    # the existing item id with the new price, no second item.
    def test_change_plan_stripe_called_and_audit(self):
        """change_plan updates the subscription's one existing item with the new price, then audits.
        In: a fake Stripe client. Out: assertions. Why: ADMIN-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches: in-memory SQLite, a fake Stripe client (no network)."""
        stripe_fake = FakeStripe([{"id": "si_1", "price": {"id": "price_1UIxxxxxx_solo"}}])
        self.sys = AdminSystem(stripe_client=stripe_fake)
        self.setUp_users()
        cur = self.sys.conn.cursor()
        cur.execute(
            """INSERT INTO customers (email, name, tier, signup_date, stripe_subscription_id)
               VALUES ('cust2@example.com','Cust2','solo','2023-01-01','sub_456')"""
        )
        cust_id = cur.lastrowid
        self.sys.conn.commit()
        payload = {"new_tier": "team"}
        resp = self.sys.customers_action(CSRF_TOKEN, self.owner_id, cust_id, "change_plan", payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["old_tier"], "solo")
        self.assertEqual(resp["new_tier"], "team")
        self.assertEqual(stripe_fake.Subscription.modified, [(
            "sub_456",
            {"items": [{"id": "si_1", "price": "price_1UIxxxxxx_team"}], "proration_behavior": "create_prorations"},
        )])
        # Verify audit
        cur.execute("SELECT * FROM audit_log WHERE action='plan_changed'")
        self.assertIsNotNone(cur.fetchone())

    # ADMIN-12
    def test_change_plan_unknown_tier_or_ambiguous_items_never_update(self):
        """An unknown plan tier is 400 invalid_tier, and a subscription with two items is 409
        subscription_item_ambiguous; neither updates Stripe, the customer row or the audit log.
        In: a fake Stripe client with two items. Out: assertions. Why: ADMIN-12 / BILL-03 (amended 2026-11-10).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite, a fake Stripe client."""
        stripe_fake = FakeStripe([{"id": "si_1"}, {"id": "si_2"}])
        self.sys = AdminSystem(stripe_client=stripe_fake)
        self.setUp_users()
        cur = self.sys.conn.cursor()
        cur.execute(
            """INSERT INTO customers (email, name, tier, signup_date, stripe_subscription_id)
               VALUES ('cust3@example.com','Cust3','solo','2023-01-01','sub_789')"""
        )
        cust_id = cur.lastrowid
        self.sys.conn.commit()
        for tier, status, code in (("admin", 400, "invalid_tier"), ("team", 409, "subscription_item_ambiguous")):
            with self.assertRaises(HTTPError) as cm:
                self.sys.customers_action(CSRF_TOKEN, self.owner_id, cust_id, "change_plan", {"new_tier": tier})
            self.assertEqual((cm.exception.status, cm.exception.code), (status, code))
        self.assertEqual(stripe_fake.Subscription.modified, [])
        cur.execute("SELECT tier FROM customers WHERE id = ?", (cust_id,))
        self.assertEqual(cur.fetchone()["tier"], "solo")
        cur.execute("SELECT COUNT(*) FROM audit_log WHERE action='plan_changed'")
        self.assertEqual(cur.fetchone()[0], 0)

    # ADMIN-13
    def test_queue_refund_record_created(self):
        payload = {"invoice_id": 1, "amount": 50.0, "reason": "overcharge"}
        resp = self.sys.customers_action(CSRF_TOKEN, self.owner_id, 0, "queue_refund", payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["status"], "queued")
        cur = self.sys.conn.cursor()
        cur.execute("SELECT * FROM refunds WHERE id = ?", (resp["refund_id"],))
        row = cur.fetchone()
        self.assertEqual(row["status"], "queued")
        self.assertEqual(row["amount"], 50.0)

    # ----- DEPLOYMENTS DOMAIN TESTS -----
    # ADMIN-14
    def test_create_deployment(self):
        # Need a customer first
        cur = self.sys.conn.cursor()
        cur.execute(
            """INSERT INTO customers (email, name, tier, signup_date)
               VALUES ('cust3@example.com','Cust3','user','2023-01-01')"""
        )
        cust_id = cur.lastrowid
        self.sys.conn.commit()
        payload = {
            "customer_id": cust_id,
            "domain": "example.com",
            "tier": "user",
            "theme_id": 1
        }
        resp = self.sys.deployments_action(CSRF_TOKEN, self.owner_id, "create", payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["domain"], "example.com")
        # Verify config init (no explicit check needed)

    # ADMIN-15
    def test_publish_deployment_double_gate(self):
        # Setup deployment
        cur = self.sys.conn.cursor()
        cur.execute(
            """INSERT INTO customers (email, name, tier, signup_date)
               VALUES ('cust4@example.com','Cust4','user','2023-01-01')"""
        )
        cust_id = cur.lastrowid
        cur.execute(
            """INSERT INTO deployments (customer_id, domain, tier, theme_id, status)
               VALUES (?, 'pub.com', 'user', 1, 'draft')""",
            (cust_id,)
        )
        dep_id = cur.lastrowid
        self.sys.conn.commit()
        payload = {"deployment_id": dep_id}
        resp = self.sys.deployments_action(CSRF_TOKEN, self.owner_id, "publish", payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["status"], "live")
        self.assertIn("public_url", resp)

    # ----- GOVERNANCE DOMAIN TESTS -----
    # ADMIN-16
    def test_governance_approve_executes_action(self):
        # Create a pending change_role action via governance
        action_id = self.sys.create_governance_action(
            actor_id=self.owner_id,
            action_type="change_role",
            target_resource_type="user",
            target_resource_id=self.user_id,
            params={"new_tier": "admin"}
        )
        payload = {}
        resp = self.sys.decide_governance_action(CSRF_TOKEN, self.owner_id, action_id, "approve", payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["status"], "approved")
        # Verify role changed
        cur = self.sys.conn.cursor()
        cur.execute("SELECT tier FROM users WHERE id = ?", (self.user_id,))
        self.assertEqual(cur.fetchone()["tier"], "admin")

    # ADMIN-17
    def test_governance_reject(self):
        action_id = self.sys.create_governance_action(
            actor_id=self.owner_id,
            action_type="change_role",
            target_resource_type="user",
            target_resource_id=self.user_id,
            params={"new_tier": "admin"}
        )
        payload = {"reason": "Not needed"}
        resp = self.sys.decide_governance_action(CSRF_TOKEN, self.owner_id, action_id, "reject", payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["status"], "rejected")
        # Verify status in DB
        cur = self.sys.conn.cursor()
        cur.execute("SELECT status, rejection_reason FROM governance_actions WHERE id = ?", (action_id,))
        row = cur.fetchone()
        self.assertEqual(row["status"], "rejected")
        self.assertEqual(row["rejection_reason"], "Not needed")

    # ADMIN-18
    def test_audit_log_search_filters_and_pagination(self):
        # Insert some audit logs with distinct timestamps for deterministic ordering
        cur = self.sys.conn.cursor()
        base_time = "2023-01-01T00:00:00Z"
        for i in range(5):
            # Each log gets a slightly later timestamp so DESC order is predictable
            ts = f"2023-01-01T00:00:{i:02d}Z"
            cur.execute(
                """INSERT INTO audit_log (timestamp, actor_id, action, resource_type, resource_id, details)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (ts, self.owner_id, "test_action", "user", i, json.dumps({"i": i}))
            )
        self.sys.conn.commit()
        filters = {"action_type": "test_action", "limit": 2, "offset": 1}
        results = self.sys.search_audit_log(self.owner_id, filters)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["action"], "test_action")
        # Ordered by timestamp DESC, then id DESC: timestamps are 00,01,02,03,04 -> DESC gives 04,03,02,01,00
        # offset=1 skips 04 (resource_id=4), first result is 03 (resource_id=3)
        self.assertEqual(results[0]["resource_id"], 3)  # because ordered DESC

if __name__ == "__main__":
    unittest.main()

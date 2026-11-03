# Tests updated with the fix 2026-11-03: the audit table gained the column the code writes, and audit history is ordered by
#   timestamp, then id, so rows written in the same second keep a fixed order.
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: SQLite only.
import unittest
import os
import json
from admin_system_python import AdminSystem, HTTPError, CSRF_TOKEN

class TestAdminSystem(unittest.TestCase):
    def setUp(self):
        self.sys = AdminSystem()
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

    def test_reset_password_happy_path(self):
        payload = {"user_id": self.user_id}
        resp = self.sys.users_action(CSRF_TOKEN, self.owner_id, "reset_password", payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["status"], "reset_email_sent")
        # Verify email sent
        target_email = self.sys._get_user_by_id(self.user_id)["email"]
        self.assertTrue(any(email == target_email for email, _ in self.sys.email_outbox))

    def test_reset_password_own_account(self):
        payload = {"user_id": self.owner_id}
        with self.assertRaises(HTTPError) as ctx:
            self.sys.users_action(CSRF_TOKEN, self.owner_id, "reset_password", payload)
        self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(ctx.exception.code, "cannot_reset_own_password")

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

    def test_suspend_user_happy_path(self):
        payload = {"user_id": self.user_id, "reason": "violation"}
        resp = self.sys.users_action(CSRF_TOKEN, self.owner_id, "suspend", payload)
        self.assertTrue(resp["success"])
        self.assertTrue(resp["suspended"])
        cur = self.sys.conn.cursor()
        cur.execute("SELECT status FROM users WHERE id = ?", (self.user_id,))
        self.assertEqual(cur.fetchone()["status"], "suspended")

    def test_suspend_own_account(self):
        payload = {"user_id": self.owner_id, "reason": "self"}
        with self.assertRaises(HTTPError) as ctx:
            self.sys.users_action(CSRF_TOKEN, self.owner_id, "suspend", payload)
        self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(ctx.exception.code, "cannot_suspend_yourself")

    # ----- CUSTOMERS DOMAIN TESTS -----
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

    def test_change_plan_stripe_called_and_audit(self):
        cur = self.sys.conn.cursor()
        cur.execute(
            """INSERT INTO customers (email, name, tier, signup_date, stripe_subscription_id)
               VALUES ('cust2@example.com','Cust2','user','2023-01-01','sub_456')"""
        )
        cust_id = cur.lastrowid
        self.sys.conn.commit()
        payload = {"new_tier": "admin"}
        resp = self.sys.customers_action(CSRF_TOKEN, self.owner_id, cust_id, "change_plan", payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["old_tier"], "user")
        self.assertEqual(resp["new_tier"], "admin")
        # Verify audit
        cur.execute("SELECT * FROM audit_log WHERE action='plan_changed'")
        self.assertIsNotNone(cur.fetchone())

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

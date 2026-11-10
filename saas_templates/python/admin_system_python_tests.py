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
        """Demoting the last active owner is 400 cannot_demote_last_owner and changes nothing.
        In: the test fixtures. Out: assertions. Why: ADMIN-07.
        Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, ADMIN-19): the old scenario had a
        SUSPENDED owner do the demoting, which ADMIN-19 now refuses first with 403 account_suspended (asserted
        below). An active owner cannot reach the last-owner refusal through action=change_role (the target is
        another owner, so two are active, and demoting yourself is cannot_change_own_role), so the refusal is now
        proven where it is reachable: the remaining owner approving a governance change_role that demotes them.
        Touches: in-memory SQLite only."""
        # Create a second owner, suspend the first owner, then try to demote the second owner
        cur = self.sys.conn.cursor()
        cur.execute(
            """INSERT INTO users (email, name, tier, created_at, last_active_at)
               VALUES ('owner2@example.com', 'Owner2', 'owner', ?, ?)""",
            (self._now(), self._now())
        )
        owner2_id = cur.lastrowid
        action_id = self.sys.create_governance_action(self.owner_id, "change_role", "user", owner2_id,
                                                      {"new_tier": "admin"})
        # Suspend the original owner (actor) so owner2 becomes the last active owner
        cur.execute("UPDATE users SET status = 'suspended' WHERE id = ?", (self.owner_id,))
        self.sys.conn.commit()

        # The suspended original owner is refused before any gate (ADMIN-19).
        payload = {"user_id": owner2_id, "new_tier": "admin"}
        with self.assertRaises(HTTPError) as ctx:
            self.sys.users_action(CSRF_TOKEN, self.owner_id, "change_role", payload)
        self.assertEqual((ctx.exception.status, ctx.exception.code), (403, "account_suspended"))

        # owner2, the last active owner, approving their own demotion.
        with self.assertRaises(HTTPError) as ctx:
            self.sys.decide_governance_action(CSRF_TOKEN, owner2_id, action_id, "approve", {})
        self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(ctx.exception.code, "cannot_demote_last_owner")
        self.assertEqual(self.sys._get_user_by_id(owner2_id)["tier"], "owner")
        cur.execute("SELECT status FROM governance_actions WHERE id = ?", (action_id,))
        self.assertEqual(cur.fetchone()[0], "pending")
        # and demoting themselves directly is the own-account gate
        with self.assertRaises(HTTPError) as ctx:
            self.sys.users_action(CSRF_TOKEN, owner2_id, "change_role", {"user_id": owner2_id, "new_tier": "admin"})
        self.assertEqual(ctx.exception.code, "cannot_change_own_role")

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

    def _customer_with_invoice(self, amount=100.0, status="succeeded", email="refund@example.com"):
        """Insert a customer and one invoice of theirs. In: the invoice amount and status. Out: (customer id,
        invoice id). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 queue_refund bug). Touches: the
        test database."""
        cur = self.sys.conn.cursor()
        cur.execute("INSERT INTO customers (email, name, tier, signup_date) VALUES (?, 'Refund', 'solo', ?)",
                    (email, self._now()))
        cust_id = cur.lastrowid
        cur.execute("INSERT INTO invoices (customer_id, amount, status) VALUES (?, ?, ?)", (cust_id, amount, status))
        self.sys.conn.commit()
        return cust_id, cur.lastrowid

    # ADMIN-13
    def test_queue_refund_record_created(self):
        """A refund of a succeeded invoice of the customer is queued.
        In: the test fixtures. Out: assertions. Why: ADMIN-13. Corrected 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 bug fix): it refunded invoice 1 of customer 0, neither of which
        existed; queue_refund now requires the invoice, so the test creates one. Touches: in-memory SQLite only."""
        cust_id, invoice_id = self._customer_with_invoice()
        payload = {"invoice_id": invoice_id, "amount": 50.0, "reason": "overcharge"}
        resp = self.sys.customers_action(CSRF_TOKEN, self.owner_id, cust_id, "queue_refund", payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["status"], "queued")
        cur = self.sys.conn.cursor()
        cur.execute("SELECT * FROM refunds WHERE id = ?", (resp["refund_id"],))
        row = cur.fetchone()
        self.assertEqual(row["status"], "queued")
        self.assertEqual(row["amount"], 50.0)

    # ADMIN-13
    def test_queue_refund_checks_the_invoice(self):
        """queue_refund refuses, writing nothing: an unknown invoice and another customer's invoice (404
        invoice_not_found), an invoice that did not succeed (400 invalid_invoice_status), a non-positive amount
        (400 invalid_amount) and refunds above the invoice amount (400 refund_exceeds_invoice); refunds up to the
        amount are queued. In: the test fixtures. Out: assertions. Why: Phase B.2 python bug (it assumed every
        invoice existed and had succeeded). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches: in-memory SQLite only."""
        cust_id, invoice_id = self._customer_with_invoice(amount=100.0)
        other_cust, other_invoice = self._customer_with_invoice(email="other@example.com")
        _, failed_invoice = self._customer_with_invoice(status="failed", email="failed@example.com")
        cur = self.sys.conn.cursor()
        cur.execute("UPDATE invoices SET customer_id = ? WHERE id = ?", (cust_id, failed_invoice))
        self.sys.conn.commit()

        def refund(invoice, amount, customer=cust_id):
            return self.sys.customers_action(CSRF_TOKEN, self.owner_id, customer, "queue_refund",
                                             {"invoice_id": invoice, "amount": amount, "reason": "r"})
        for invoice, amount, status, code in (
            (9999, 10.0, 404, "invoice_not_found"),
            (other_invoice, 10.0, 404, "invoice_not_found"),
            (failed_invoice, 10.0, 400, "invalid_invoice_status"),
            (invoice_id, 0, 400, "invalid_amount"),
            (invoice_id, -5.0, 400, "invalid_amount"),
            (invoice_id, 100.01, 400, "refund_exceeds_invoice"),
        ):
            with self.assertRaises(HTTPError) as cm:
                refund(invoice, amount)
            self.assertEqual((cm.exception.status, cm.exception.code), (status, code), (invoice, amount))
        cur.execute("SELECT COUNT(*) FROM refunds")
        self.assertEqual(cur.fetchone()[0], 0)
        cur.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'refund_queued'")
        self.assertEqual(cur.fetchone()[0], 0)
        self.assertEqual(refund(invoice_id, 60.0)["status"], "queued")
        with self.assertRaises(HTTPError) as cm:
            refund(invoice_id, 40.01)
        self.assertEqual(cm.exception.code, "refund_exceeds_invoice")
        self.assertEqual(refund(invoice_id, 40.0)["status"], "queued")
        self.assertEqual(refund(other_invoice, 1.0, customer=other_cust)["status"], "queued")

    # ----- DEPLOYMENTS DOMAIN TESTS -----
    # ADMIN-14
    def test_create_deployment(self):
        """A deployment is created for a customer on a PLAN tier, unverified; a staff role as its tier is 400
        invalid_tier and creates nothing. In: the test fixtures. Out: assertions. Why: ADMIN-14.
        Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 "TIERS"): it used the staff role "user" as
        a deployment's tier, which the spec now refuses; the tier is the plan "solo". Touches: in-memory SQLite."""
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
        with self.assertRaises(HTTPError) as cm:
            self.sys.deployments_action(CSRF_TOKEN, self.owner_id, "create", payload)
        self.assertEqual((cm.exception.status, cm.exception.code), (400, "invalid_tier"))
        self.assertEqual(self.sys.list_deployments(self.owner_id), [])
        payload["tier"] = "solo"
        resp = self.sys.deployments_action(CSRF_TOKEN, self.owner_id, "create", payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["domain"], "example.com")
        self.assertEqual(resp["tier"], "solo")
        cur.execute("SELECT domain_verified FROM deployments WHERE id = ?", (resp["deployment_id"],))
        self.assertEqual(cur.fetchone()[0], 0)
        # Verify config init (no explicit check needed)

    # ADMIN-15
    def test_publish_deployment_double_gate(self):
        """Publish needs a draft whose domain is verified: unverified is 400 domain_not_verified and stays
        draft; once mark_domain_verified() ran it goes live. In: the test fixtures. Out: assertions.
        Why: ADMIN-15. Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): deployments now carry
        domain_verified (default false) and publish requires it, so the test verifies the domain first; its
        deployment tier "user" (a staff role) is now the plan "solo". Touches: in-memory SQLite only."""
        # Setup deployment
        cur = self.sys.conn.cursor()
        cur.execute(
            """INSERT INTO customers (email, name, tier, signup_date)
               VALUES ('cust4@example.com','Cust4','user','2023-01-01')"""
        )
        cust_id = cur.lastrowid
        cur.execute(
            """INSERT INTO deployments (customer_id, domain, tier, theme_id, status)
               VALUES (?, 'pub.com', 'solo', 1, 'draft')""",
            (cust_id,)
        )
        dep_id = cur.lastrowid
        self.sys.conn.commit()
        payload = {"deployment_id": dep_id}
        with self.assertRaises(HTTPError) as cm:
            self.sys.deployments_action(CSRF_TOKEN, self.owner_id, "publish", payload)
        self.assertEqual((cm.exception.status, cm.exception.code), (400, "domain_not_verified"))
        cur.execute("SELECT status FROM deployments WHERE id = ?", (dep_id,))
        self.assertEqual(cur.fetchone()[0], "draft")
        self.sys.mark_domain_verified(dep_id)
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

    # ADMIN-06
    def test_role_and_plan_tiers_never_mix(self):
        """users.tier takes a staff role only and a plan takes a plan only: a plan value in create, change_role or
        a governance change_role, and a staff role in change_plan or create_deployment, are 400 invalid_tier and
        change nothing. In: the test fixtures. Out: assertions. Why: spec "TIERS" (Phase B.2).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite only."""
        cur = self.sys.conn.cursor()
        cur.execute("INSERT INTO customers (email, name, tier, signup_date, stripe_subscription_id) "
                    "VALUES ('t@example.com', 'T', 'solo', ?, 'sub_t')", (self._now(),))
        cust_id = cur.lastrowid
        self.sys.conn.commit()
        action_id = self.sys.create_governance_action(self.owner_id, "change_role", "user", self.user_id,
                                                      {"new_tier": "enterprise"})
        calls = [
            lambda: self.sys.users_action(CSRF_TOKEN, self.owner_id, "create",
                                          {"email": "t2@example.com", "name": "T", "tier": "team"}),
            lambda: self.sys.users_action(CSRF_TOKEN, self.owner_id, "change_role",
                                          {"user_id": self.user_id, "new_tier": "team"}),
            lambda: self.sys.decide_governance_action(CSRF_TOKEN, self.owner_id, action_id, "approve", {}),
            lambda: self.sys.customers_action(CSRF_TOKEN, self.owner_id, cust_id, "change_plan", {"new_tier": "owner"}),
            lambda: self.sys.deployments_action(CSRF_TOKEN, self.owner_id, "create",
                                                {"customer_id": cust_id, "domain": "t.com", "tier": "admin",
                                                 "theme_id": 1}),
        ]
        for call in calls:
            with self.assertRaises(HTTPError) as cm:
                call()
            self.assertEqual((cm.exception.status, cm.exception.code), (400, "invalid_tier"))
        self.assertEqual(self.sys._get_user_by_id(self.user_id)["tier"], "user")
        self.assertIsNone(self.sys._get_user_by_email("t2@example.com"))
        cur.execute("SELECT status FROM governance_actions WHERE id = ?", (action_id,))
        self.assertEqual(cur.fetchone()[0], "pending")
        self.assertEqual(self.sys.get_customer_detail(self.owner_id, cust_id)["tier"], "solo")
        self.assertEqual(self.sys.list_deployments(self.owner_id), [])
        cur.execute("SELECT COUNT(*) FROM audit_log")
        self.assertEqual(cur.fetchone()[0], 0)

    # ADMIN-19
    def test_suspended_owner_refused_before_any_gate(self):
        """A suspended owner calling any admin action, read or write, gets 403 account_suspended, before any gate
        (even with a wrong CSRF token), and nothing changes: no table row, email or Stripe call.
        In: the test fixtures and a fake Stripe client. Out: assertions. Why: ADMIN-19 (Phase B.2, 2026-11-10).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite, a fake Stripe client."""
        stripe_fake = FakeStripe([{"id": "si_1"}])
        self.sys = AdminSystem(stripe_client=stripe_fake)
        self.setUp_users()
        cur = self.sys.conn.cursor()
        cur.execute("INSERT INTO users (email, name, tier, status, created_at, last_active_at) "
                    "VALUES ('susp@example.com', 'Susp', 'owner', 'suspended', ?, ?)", (self._now(), self._now()))
        susp = cur.lastrowid
        cur.execute("INSERT INTO customers (email, name, tier, signup_date, stripe_subscription_id) "
                    "VALUES ('c19@example.com', 'C', 'solo', ?, 'sub_19')", (self._now(),))
        cust_id = cur.lastrowid
        cur.execute("INSERT INTO invoices (customer_id, amount, status) VALUES (?, 100, 'succeeded')", (cust_id,))
        invoice_id = cur.lastrowid
        cur.execute("INSERT INTO deployments (customer_id, domain, tier, theme_id, status, domain_verified) "
                    "VALUES (?, 'd19.com', 'solo', 1, 'draft', 1)", (cust_id,))
        dep_id = cur.lastrowid
        self.sys.conn.commit()
        action_id = self.sys.create_governance_action(self.owner_id, "change_role", "user", self.user_id,
                                                      {"new_tier": "admin"})

        def snapshot():
            tables = [r[0] for r in self.sys.conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' "
                                                          "AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            return {t: [tuple(r) for r in self.sys.conn.execute(f"SELECT * FROM {t} ORDER BY rowid")] for t in tables}
        before = snapshot()
        calls = []
        for csrf in (CSRF_TOKEN, "wrong-token"):
            calls += [
                lambda c=csrf: self.sys.users_action(c, susp, "create",
                                                     {"email": "n@example.com", "name": "N", "tier": "user", "notify": True}),
                lambda c=csrf: self.sys.users_action(c, susp, "reset_password", {"user_id": self.user_id}),
                lambda c=csrf: self.sys.users_action(c, susp, "change_role", {"user_id": self.user_id, "new_tier": "admin"}),
                lambda c=csrf: self.sys.users_action(c, susp, "suspend", {"user_id": self.user_id, "reason": "x"}),
                lambda c=csrf: self.sys.customers_action(c, susp, cust_id, "change_plan", {"new_tier": "team"}),
                lambda c=csrf: self.sys.customers_action(c, susp, cust_id, "queue_refund",
                                                         {"invoice_id": invoice_id, "amount": 10, "reason": "r"}),
                lambda c=csrf: self.sys.deployments_action(c, susp, "create", {"customer_id": cust_id, "domain": "n.com",
                                                                               "tier": "solo", "theme_id": 1}),
                lambda c=csrf: self.sys.deployments_action(c, susp, "publish", {"deployment_id": dep_id}),
                lambda c=csrf: self.sys.deployments_action(c, susp, "suspend", {"deployment_id": dep_id, "reason": "x"}),
                lambda c=csrf: self.sys.deployments_action(c, susp, "retire", {"deployment_id": dep_id}),
                lambda c=csrf: self.sys.decide_governance_action(c, susp, action_id, "approve", {}),
                lambda c=csrf: self.sys.decide_governance_action(c, susp, action_id, "reject", {"reason": "no"}),
            ]
        calls += [
            lambda: self.sys.list_customers(susp),
            lambda: self.sys.get_customer_detail(susp, cust_id),
            lambda: self.sys.list_deployments(susp),
            lambda: self.sys.list_pending_governance_actions(susp),
            lambda: self.sys.search_audit_log(susp, {}),
        ]
        for call in calls:
            with self.assertRaises(HTTPError) as cm:
                call()
            self.assertEqual((cm.exception.status, cm.exception.code), (403, "account_suspended"))
        self.assertEqual(snapshot(), before)
        self.assertEqual(self.sys.email_outbox, [])
        self.assertEqual(stripe_fake.Subscription.modified, [])
        # The active owner is unaffected.
        self.assertTrue(self.sys.list_customers(self.owner_id))


if __name__ == "__main__":
    unittest.main()

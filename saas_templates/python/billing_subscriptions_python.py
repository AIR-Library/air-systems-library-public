# Repaired 2026-11-03: uses the stripe package's current error classes and timezone-aware UTC times
#   (datetime.utcnow is deprecated).
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: Stripe API (mocked in tests), SQLite.
import os
import json
import time
import datetime
import sqlite3
from typing import Any, Dict, Optional

import stripe
from stripe import SignatureVerificationError, StripeError

# Stripe configuration
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")

# Price IDs mapping
PRICE_IDS = {
    "solo": "price_1UIxxxxxx_solo",
    "team": "price_1UIxxxxxx_team",
    "enterprise": "price_1UIxxxxxx_enterprise",
}

# Database schema
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS subscriptions (
    stripe_subscription_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    tier TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    cancelled_at TEXT
);

CREATE TABLE IF NOT EXISTS invoices (
    stripe_invoice_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    status TEXT NOT NULL,
    paid_at TEXT
);

CREATE TABLE IF NOT EXISTS refunds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    invoice_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    status TEXT NOT NULL,
    reason TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL,
    executed_at TEXT
);

CREATE TABLE IF NOT EXISTS events (
    stripe_event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    processed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    details TEXT,
    created_at TEXT NOT NULL
);
"""

def iso_now() -> str:
    return datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")

class Database:
    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA_SQL)
        self.conn.commit()

    def execute(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        cur = self.conn.cursor()
        cur.execute(query, params)
        self.conn.commit()
        return cur

    def fetchone(self, query: str, params: tuple = ()) -> Optional[tuple]:
        cur = self.conn.cursor()
        cur.execute(query, params)
        return cur.fetchone()

    def fetchall(self, query: str, params: tuple = ()) -> list:
        cur = self.conn.cursor()
        cur.execute(query, params)
        return cur.fetchall()

class BillingSystem:
    def __init__(self, db_path: str = ":memory:"):
        self.db = Database(db_path)

    def audit_log(self, action: str, details: Dict[str, Any]) -> None:
        self.db.execute(
            "INSERT INTO audit_logs (action, details, created_at) VALUES (?, ?, ?)",
            (action, json.dumps(details), iso_now()),
        )

    def create_subscription(self, customer_id: str, tier: str) -> Dict[str, Any]:
        if tier not in PRICE_IDS:
            return {"error": "invalid_tier", "message": f"Tier '{tier}' is not valid."}

        try:
            stripe_sub = stripe.Subscription.create(
                customer=customer_id,
                items=[{"price": PRICE_IDS[tier]}],
            )
        except StripeError as e:
            return {"error": "stripe_error", "message": str(e)}

        created_at = iso_now()
        self.db.execute(
            """
            INSERT INTO subscriptions (
                stripe_subscription_id, customer_id, tier, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                stripe_sub.id,
                customer_id,
                tier,
                stripe_sub.status,
                created_at,
                created_at,
            ),
        )
        self.audit_log(
            "subscription_created",
            {
                "customer_id": customer_id,
                "tier": tier,
                "stripe_sub_id": stripe_sub.id,
            },
        )
        next_billing_date = datetime.datetime.fromtimestamp(
            stripe_sub.current_period_end, datetime.UTC
        ).isoformat().replace("+00:00", "Z")

        return {
            "success": True,
            "subscription_id": stripe_sub.id,
            "tier": tier,
            "status": stripe_sub.status,
            "next_billing_date": next_billing_date,
        }

    def change_plan(self, subscription_id: str, new_tier: str) -> Dict[str, Any]:
        """Move a subscription to another tier by replacing the price on its one existing item.

        In: the Stripe subscription id and the new tier. Out: {success, subscription_id, old_tier, new_tier,
        effective_date, proration_credit}, or {error: "invalid_tier"} (400), {error: "subscription_not_found"},
        {error: "subscription_item_ambiguous"} (409, the subscription does not have exactly one item) or
        {error: "stripe_error"}. invalid_tier and subscription_item_ambiguous are both decided before any update.
        Why: BILL-03 as amended 2026-11-10 after review on PR 19: an update with a bare {price} makes Stripe ADD a
        second item and bill both plans, so the update names the current item id. 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP. Touches: Stripe (retrieve + update; money), SQLite (subscriptions,
        audit_log)."""
        if new_tier not in PRICE_IDS:
            return {"error": "invalid_tier", "message": f"Tier '{new_tier}' is not valid."}

        sub_record = self.db.fetchone(
            "SELECT tier, status FROM subscriptions WHERE stripe_subscription_id = ?",
            (subscription_id,),
        )
        if not sub_record:
            return {"error": "subscription_not_found", "message": "Subscription not found."}

        old_tier, old_status = sub_record
        try:
            current = stripe.Subscription.retrieve(subscription_id)
        except StripeError as e:
            return {"error": "stripe_error", "message": str(e)}
        items = current["items"]["data"]
        if len(items) != 1:
            return {"error": "subscription_item_ambiguous",
                    "message": "The subscription does not have exactly one item; change it by hand."}
        current_item_id = items[0]["id"]
        try:
            stripe_sub = stripe.Subscription.modify(
                subscription_id,
                items=[{"id": current_item_id, "price": PRICE_IDS[new_tier]}],
                proration_behavior="create_prorations",
            )
        except StripeError as e:
            return {"error": "stripe_error", "message": str(e)}

        proration_credit = 0
        if stripe_sub.proration_amounts:
            # Stripe returns proration_amounts as list of dicts with amount in cents
            proration_credit = sum(
                amt.get("amount", 0) for amt in stripe_sub.proration_amounts
            ) / 100.0

        updated_at = iso_now()
        self.db.execute(
            """
            UPDATE subscriptions
            SET tier = ?, status = ?, updated_at = ?
            WHERE stripe_subscription_id = ?
            """,
            (new_tier, stripe_sub.status, updated_at, subscription_id),
        )
        self.audit_log(
            "plan_changed",
            {
                "subscription_id": subscription_id,
                "old_tier": old_tier,
                "new_tier": new_tier,
                "proration_credits": proration_credit,
            },
        )
        effective_date = datetime.datetime.fromtimestamp(
            stripe_sub.current_period_start, datetime.UTC
        ).isoformat().replace("+00:00", "Z")

        return {
            "success": True,
            "subscription_id": subscription_id,
            "old_tier": old_tier,
            "new_tier": new_tier,
            "effective_date": effective_date,
            "proration_credit": proration_credit,
        }

    def queue_refund(self, invoice_id: str, amount: int, reason: str, created_by: str) -> Dict[str, Any]:
        invoice = self.db.fetchone(
            "SELECT amount, status FROM invoices WHERE stripe_invoice_id = ?",
            (invoice_id,),
        )
        if not invoice:
            return {"error": "invoice_not_found", "message": "Invoice not found."}
        invoice_amount, status = invoice
        if status != "succeeded":
            return {"error": "invoice_not_succeeded", "message": "Invoice not succeeded."}
        if amount > invoice_amount:
            return {"error": "refund_exceeds_invoice", "message": "Refund amount exceeds invoice."}

        created_at = iso_now()
        cur = self.db.execute(
            """
            INSERT INTO refunds (invoice_id, amount, status, reason, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (invoice_id, amount, "queued", reason, created_by, created_at),
        )
        refund_id = cur.lastrowid
        self.audit_log(
            "refund_queued",
            {"invoice_id": invoice_id, "amount": amount, "reason": reason},
        )
        return {
            "success": True,
            "refund_id": refund_id,
            "status": "queued",
            "amount": amount,
            "reason": reason,
        }

    def handle_stripe_webhook(self, payload: str, sig_header: str) -> Dict[str, Any]:
        """Verify Stripe's signature, then record and apply the event once (BILL-06..10).

        In: the raw payload and the Stripe-Signature header. Out: {received: true}, or {error, message} for a
        refusal; a bad signature is {error: "invalid_signature", status: 400, message}.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.3 (BILL-09 as amended): a bad signature answers HTTP
        400, Stripe's documented answer and the same as stripe_webhook_entitlements (it was 403); the answer now
        carries that status. Touches: STRIPE_WEBHOOK_SECRET (environment), the Stripe SDK's signature check, the
        database (events, invoices, subscriptions), the audit log."""
        webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")
        if not webhook_secret:
            return {"error": "missing_webhook_secret", "message": "Webhook secret not configured."}

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, webhook_secret
            )
        except SignatureVerificationError:
            return {"error": "invalid_signature", "status": 400, "message": "Invalid signature."}
        except Exception as e:
            return {"error": "invalid_payload", "message": str(e)}

        # Idempotency check
        existing = self.db.fetchone(
            "SELECT 1 FROM events WHERE stripe_event_id = ?", (event.id,)
        )
        if existing:
            return {"received": True}

        # Process event
        if event.type == "invoice.payment_succeeded":
            invoice = event.data.object
            self.db.execute(
                """
                INSERT OR IGNORE INTO invoices (
                    stripe_invoice_id, customer_id, amount, status, paid_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    invoice.id,
                    invoice.customer,
                    invoice.amount_paid,
                    "succeeded",
                    iso_now(),
                ),
            )
            self.audit_log(
                "payment_succeeded",
                {
                    "customer_id": invoice.customer,
                    "invoice_id": invoice.id,
                    "amount": invoice.amount_paid,
                },
            )
        elif event.type == "invoice.payment_failed":
            invoice = event.data.object
            # Find subscription linked to this invoice
            sub = stripe.Invoice.retrieve(invoice.id).subscription
            if sub:
                self.db.execute(
                    """
                    UPDATE subscriptions
                    SET status = ?, updated_at = ?
                    WHERE stripe_subscription_id = ?
                    """,
                    ("past_due", iso_now(), sub),
                )
            self.audit_log(
                "payment_failed",
                {
                    "customer_id": invoice.customer,
                    "invoice_id": invoice.id,
                    "reason": invoice.failure_reason,
                },
            )
        elif event.type == "customer.subscription.updated":
            sub = event.data.object
            tier = sub.items.data[0].price.lookup_key
            status = sub.status
            self.db.execute(
                """
                UPDATE subscriptions
                SET tier = ?, status = ?, updated_at = ?
                WHERE stripe_subscription_id = ?
                """,
                (tier, status, iso_now(), sub.id),
            )
            self.audit_log(
                "subscription_updated",
                {
                    "customer_id": sub.customer,
                    "old_tier": None,  # Not available in webhook
                    "new_tier": tier,
                },
            )
        elif event.type == "customer.subscription.deleted":
            sub = event.data.object
            self.db.execute(
                """
                UPDATE subscriptions
                SET status = ?, cancelled_at = ?, updated_at = ?
                WHERE stripe_subscription_id = ?
                """,
                ("cancelled", iso_now(), iso_now(), sub.id),
            )
            self.audit_log(
                "subscription_cancelled",
                {"customer_id": sub.customer},
            )

        # Record event as processed
        self.db.execute(
            "INSERT INTO events (stripe_event_id, event_type, processed_at) VALUES (?, ?, ?)",
            (event.id, event.type, iso_now()),
        )

        return {"received": True}

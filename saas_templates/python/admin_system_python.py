# Repaired 2026-11-03: the audit table gained the column the code writes, and audit history is ordered by
#   timestamp, then id, so rows written in the same second keep a fixed order.
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: SQLite only.
import os
import hmac
import secrets
import re
import uuid
import json
import sqlite3
import datetime
from typing import Any, Dict, List, Optional, Tuple

# ---------- Configuration ----------
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "sk_test_dummy")
# [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] The CSRF token is no longer the hard-coded "valid_csrf_token"
# (docs/specs/README.md: no secret is hard-coded). It comes from ADMIN_CSRF_TOKEN or is random per process; a real
# app issues one per session and passes it in.
CSRF_TOKEN = os.getenv("ADMIN_CSRF_TOKEN") or secrets.token_urlsafe(32)
# Billing plan tiers and their Stripe prices, as in billing_subscriptions.md (a customer's plan is a billing tier,
# not a staff role). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-12).
PLAN_PRICE_IDS = {
    "solo": "price_1UIxxxxxx_solo",
    "team": "price_1UIxxxxxx_team",
    "enterprise": "price_1UIxxxxxx_enterprise",
}
SAFETY_FLAGS = {"can_publish": True}
# users.tier is the STAFF ROLE; a customer's or deployment's tier is the PLAN (PLAN_PRICE_IDS' keys). The two are
# never mixed: a value from the wrong set is 400 invalid_tier. Spec "TIERS", Phase B.2, 2026-11-10,
# session_012zDydZCZ4AChqhEZ4oVtaP (create_deployment validated a plan against the staff roles).
ALLOWED_TIERS = {"owner", "admin", "user"}
PLAN_TIERS = frozenset(PLAN_PRICE_IDS)

# ---------- Exceptions ----------
class HTTPError(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status = status
        self.code = code
        self.message = message
        super().__init__(f"{status} {code}: {message}")

# ---------- Helper Functions ----------
def verify_csrf(token: str) -> None:
    """Refuse a request whose CSRF token is not the expected one.

    In: the token the request carried. Out: None, or HTTPError 403 csrf_invalid. Compared in constant time
    (docs/specs/README.md; was `!=` until 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches nothing."""
    if not isinstance(token, str) or not hmac.compare_digest(token.encode("utf-8"), CSRF_TOKEN.encode("utf-8")):
        raise HTTPError(403, "csrf_invalid", "Invalid CSRF token")

def validate_email(email: str) -> None:
    if not re.fullmatch(r"[^@]+@[^@]+\.[^@]+", email):
        raise HTTPError(400, "invalid_email", "Email format is invalid")

def validate_name(name: str) -> None:
    if not (1 <= len(name) <= 100):
        raise HTTPError(400, "invalid_name", "Name length must be 1-100 characters")

def validate_tier(tier: str) -> None:
    """Refuse a staff role that is not owner / admin / user (a plan value such as 'team' included).

    In: the role given for users.tier. Out: None, or HTTPError 400 invalid_tier. Why: spec "TIERS" (Phase B.2,
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: users.tier is the staff role). Touches nothing."""
    if tier not in ALLOWED_TIERS:
        raise HTTPError(400, "invalid_tier", f"Tier must be one of {sorted(ALLOWED_TIERS)}")


def validate_plan_tier(tier: str) -> None:
    """Refuse a plan that is not solo / team / enterprise (a staff role such as 'admin' included).

    In: the plan given for a customer or a deployment. Out: None, or HTTPError 400 invalid_tier. Why: spec
    "TIERS" (Phase B.2, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: create_deployment took staff roles).
    Touches nothing."""
    if tier not in PLAN_TIERS:
        raise HTTPError(400, "invalid_tier", f"Plan tier must be one of {sorted(PLAN_TIERS)}")

def now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")

# ---------- Core System ----------
class AdminSystem:
    def __init__(self, stripe_client: Any = None):
        """In-memory admin system.

        In: (added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP) an optional Stripe client exposing
        Subscription.retrieve / Subscription.modify; default the `stripe` package, imported on first use.
        Tests pass a fake (no network). Why: ADMIN-12, the plan change now really calls Stripe with the item id.
        Touches: in-memory SQLite; Stripe (money) only through the client."""
        self._stripe_client = stripe_client
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self._create_schema()
        self.email_outbox: List[Tuple[str, str]] = []  # (email, content) for testing

    # ----- Schema -----
    def _create_schema(self) -> None:
        cur = self.conn.cursor()
        cur.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            tier TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            last_active_at TEXT NOT NULL
        );
        CREATE TABLE customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            name TEXT NOT NULL,
            tier TEXT NOT NULL,
            signup_date TEXT NOT NULL,
            invoice_count INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'active',
            stripe_subscription_id TEXT,
            payment_method TEXT,
            address TEXT,
            notes TEXT
        );
        CREATE TABLE deployments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            domain TEXT UNIQUE NOT NULL,
            tier TEXT NOT NULL,
            theme_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft',
            -- [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2: publish requires a verified domain.
            domain_verified INTEGER NOT NULL DEFAULT 0,
            published_at TEXT,
            suspend_reason TEXT,
            archived_at TEXT,
            FOREIGN KEY(customer_id) REFERENCES customers(id)
        );
        -- [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2: queue_refund checks the invoice it refunds
        -- (it assumed every invoice existed and had succeeded). amount is in the same unit as refunds.amount.
        CREATE TABLE invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            status TEXT NOT NULL,
            FOREIGN KEY(customer_id) REFERENCES customers(id)
        );
        CREATE TABLE refunds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            reason TEXT NOT NULL,
            status TEXT NOT NULL,
            created_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(created_by) REFERENCES users(id)
        );
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id INTEGER,
            details TEXT,
            FOREIGN KEY(actor_id) REFERENCES users(id)
        );
        CREATE TABLE governance_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_type TEXT NOT NULL,
            actor_id INTEGER NOT NULL,
            target_resource_type TEXT NOT NULL,
            target_resource_id INTEGER NOT NULL,
            params TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            submitted_at TEXT NOT NULL,
            approved_by INTEGER,
            approved_at TEXT,
            rejection_reason TEXT,
            execution_result TEXT,
            FOREIGN KEY(actor_id) REFERENCES users(id),
            FOREIGN KEY(approved_by) REFERENCES users(id)
        );
        """)
        self.conn.commit()

    # ----- Gate Checks -----
    def _caller(self, current_user_id: int) -> sqlite3.Row:
        """The verified session user, refused if suspended, before any gate (CSRF included).

        In: the caller's user id. Out: their users row; HTTPError 404 user_not_found, or 403 account_suspended
        when users.status is 'suspended'. Why: ADMIN-19 (Phase B.2, 2026-11-10): a suspended owner kept every
        admin power. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite (read)."""
        user = self._get_user_by_id(current_user_id)
        if user["status"] == "suspended":
            raise HTTPError(403, "account_suspended", "Your account is suspended")
        return user

    def _require_owner(self, user: sqlite3.Row) -> None:
        if user["tier"] != "owner":
            raise HTTPError(403, "owner_only", "Owner privileges required")

    def _require_admin_or_owner(self, user: sqlite3.Row) -> None:
        if user["tier"] not in {"owner", "admin"}:
            raise HTTPError(403, "admin_or_owner_required", "Admin or Owner required")

    # ----- Audit Logging -----
    def _audit(self, actor_id: int, action: str,
               resource_type: Optional[str] = None,
               resource_id: Optional[int] = None,
               details: Optional[Dict[str, Any]] = None) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """INSERT INTO audit_log (timestamp, actor_id, action, resource_type, resource_id, details)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (now(), actor_id, action, resource_type, resource_id,
             json.dumps(details) if details else None)
        )
        # No commit here; caller will commit after mutation

    # ----- User Helpers -----
    def _get_user_by_id(self, user_id: int) -> sqlite3.Row:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPError(404, "user_not_found", "User does not exist")
        return row

    def _get_user_by_email(self, email: str) -> Optional[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        return cur.fetchone()

    def _count_active_owners(self) -> int:
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users WHERE tier = 'owner' AND status = 'active'")
        return cur.fetchone()[0]

    # ----- USERS DOMAIN -----
    def users_action(self, csrf_token: str, current_user_id: int,
                     action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """POST /admin/users/action: create, reset_password, change_role or suspend.

        In: the CSRF token, the verified caller's id, the action, its payload. Out: the action's result; HTTPError
        403 account_suspended (a suspended caller, before any gate), 403 csrf_invalid, 403 owner_only, 400
        invalid_action, or the action's own refusals. Why: ADMIN-01..09; ADMIN-19 added in Phase B.2.
        Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite, the email outbox."""
        cur_user = self._caller(current_user_id)  # ADMIN-19: before any gate (Phase B.2, 2026-11-10)
        verify_csrf(csrf_token)
        self._require_owner(cur_user)

        if action == "create":
            return self._users_create(cur_user, payload)
        elif action == "reset_password":
            return self._users_reset_password(cur_user, payload)
        elif action == "change_role":
            return self._users_change_role(cur_user, payload)
        elif action == "suspend":
            return self._users_suspend(cur_user, payload)
        else:
            raise HTTPError(400, "invalid_action", "Unsupported action")

    def _users_create(self, actor: sqlite3.Row, payload: Dict[str, Any]) -> Dict[str, Any]:
        email = payload.get("email")
        name = payload.get("name")
        tier = payload.get("tier")
        notify = payload.get("notify", False)

        if not all([email, name, tier]):
            raise HTTPError(400, "missing_fields", "email, name, and tier are required")
        validate_email(email)
        validate_name(name)
        validate_tier(tier)

        if self._get_user_by_email(email):
            raise HTTPError(409, "email_exists", "Email already exists")

        cur = self.conn.cursor()
        cur.execute(
            """INSERT INTO users (email, name, tier, created_at, last_active_at)
               VALUES (?, ?, ?, ?, ?)""",
            (email, name, tier, now(), now())
        )
        user_id = cur.lastrowid

        # Audit before commit
        self._audit(actor["id"], "user_created",
                    resource_type="user", resource_id=user_id,
                    details={"email": email, "tier": tier})

        self.conn.commit()

        if notify:
            self.email_outbox.append((email, f"Welcome {name}, your tier is {tier}"))

        return {
            "success": True,
            "user_id": user_id,
            "email": email,
            "tier": tier,
            "created_at": now()
        }

    def _users_reset_password(self, actor: sqlite3.Row, payload: Dict[str, Any]) -> Dict[str, Any]:
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPError(400, "missing_fields", "user_id required")
        if user_id == actor["id"]:
            raise HTTPError(400, "cannot_reset_own_password", "Cannot reset own password")
        target = self._get_user_by_id(user_id)

        # Ensure not last active owner
        if target["tier"] == "owner" and self._count_active_owners() == 1:
            raise HTTPError(400, "cannot_reset_last_owner", "Cannot reset password of last active owner")

        token = str(uuid.uuid4())
        self.email_outbox.append((target["email"], f"Password reset link: https://example.com/reset/{token}"))

        self._audit(actor["id"], "password_reset_initiated",
                    resource_type="user", resource_id=user_id,
                    details={"reset_token": token})

        self.conn.commit()
        return {"success": True, "status": "reset_email_sent"}

    def _users_change_role(self, actor: sqlite3.Row, payload: Dict[str, Any]) -> Dict[str, Any]:
        user_id = payload.get("user_id")
        new_tier = payload.get("new_tier")
        if not all([user_id, new_tier]):
            raise HTTPError(400, "missing_fields", "user_id and new_tier required")
        if user_id == actor["id"]:
            raise HTTPError(400, "cannot_change_own_role", "Cannot change own role")
        validate_tier(new_tier)
        target = self._get_user_by_id(user_id)

        if target["tier"] == "owner" and self._count_active_owners() == 1 and new_tier != "owner":
            raise HTTPError(400, "cannot_demote_last_owner", "Cannot demote last active owner")

        old_tier = target["tier"]
        cur = self.conn.cursor()
        cur.execute("UPDATE users SET tier = ?, last_active_at = ? WHERE id = ?",
                    (new_tier, now(), user_id))

        self._audit(actor["id"], "role_changed",
                    resource_type="user", resource_id=user_id,
                    details={"old_tier": old_tier, "new_tier": new_tier})

        self.conn.commit()
        return {"success": True, "user_id": user_id, "old_tier": old_tier, "new_tier": new_tier}

    def _users_suspend(self, actor: sqlite3.Row, payload: Dict[str, Any]) -> Dict[str, Any]:
        user_id = payload.get("user_id")
        reason = payload.get("reason")
        if not all([user_id, reason]):
            raise HTTPError(400, "missing_fields", "user_id and reason required")
        if user_id == actor["id"]:
            raise HTTPError(400, "cannot_suspend_yourself", "Cannot suspend yourself")
        target = self._get_user_by_id(user_id)

        if target["tier"] == "owner" and self._count_active_owners() == 1:
            raise HTTPError(400, "cannot_suspend_last_owner", "Cannot suspend last active owner")

        cur = self.conn.cursor()
        cur.execute("UPDATE users SET status = 'suspended', last_active_at = ? WHERE id = ?",
                    (now(), user_id))

        self._audit(actor["id"], "user_suspended",
                    resource_type="user", resource_id=user_id,
                    details={"reason": reason})

        self.conn.commit()
        return {"success": True, "user_id": user_id, "suspended": True}

    # ----- CUSTOMERS DOMAIN -----
    def list_customers(self, current_user_id: int, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """GET /admin/customers (admin or owner). In: caller id, limit, offset. Out: a page of customers.
        HTTPError 403 account_suspended first (ADMIN-19, Phase B.2), then 403 admin_or_owner_required.
        Why: ADMIN-10. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite (read)."""
        cur_user = self._caller(current_user_id)  # ADMIN-19 (Phase B.2, 2026-11-10)
        self._require_admin_or_owner(cur_user)
        cur = self.conn.cursor()
        cur.execute(
            """SELECT id, email, name, tier, signup_date, invoice_count, status
               FROM customers ORDER BY id LIMIT ? OFFSET ?""",
            (limit, offset)
        )
        rows = cur.fetchall()
        return [dict(row) for row in rows]

    def get_customer_detail(self, current_user_id: int, customer_id: int) -> Dict[str, Any]:
        """GET /admin/customers/{customer_id} (admin or owner). In: caller id, customer id. Out: the
        customer row; HTTPError 403 account_suspended first (ADMIN-19, Phase B.2), 403 admin_or_owner_required,
        404 customer_not_found. Why: ADMIN-11. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite (read)."""
        cur_user = self._caller(current_user_id)  # ADMIN-19 (Phase B.2, 2026-11-10)
        self._require_admin_or_owner(cur_user)
        cur = self.conn.cursor()
        cur.execute(
            """SELECT * FROM customers WHERE id = ?""",
            (customer_id,)
        )
        row = cur.fetchone()
        if not row:
            raise HTTPError(404, "customer_not_found", "Customer does not exist")
        return dict(row)

    def customers_action(self, csrf_token: str, current_user_id: int,
                         customer_id: int, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """POST /admin/customers/{customer_id}/action: change_plan or queue_refund (owner only).

        In: CSRF token, caller id, customer id, action, payload. Out: the action's result; HTTPError 403
        account_suspended (before any gate, ADMIN-19), 403 csrf_invalid, 403 owner_only, 400 invalid_action.
        queue_refund now receives the customer id, so the invoice must be this customer's (Phase B.2 bug).
        Why: ADMIN-12/13/19. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite, Stripe (money) for change_plan."""
        cur_user = self._caller(current_user_id)  # ADMIN-19: before any gate (Phase B.2, 2026-11-10)
        verify_csrf(csrf_token)
        self._require_owner(cur_user)

        if action == "change_plan":
            return self._customers_change_plan(cur_user, customer_id, payload)
        elif action == "queue_refund":
            return self._customers_queue_refund(cur_user, customer_id, payload)
        else:
            raise HTTPError(400, "invalid_action", "Unsupported action")

    def _customers_change_plan(self, actor: sqlite3.Row, customer_id: int,
                               payload: Dict[str, Any]) -> Dict[str, Any]:
        """Change a customer's plan through Stripe (billing_subscriptions.md flow 2), then record it.

        In: the acting owner's row, the customer id, payload {new_tier}. Out: {success, customer_id, old_tier,
        new_tier, effective_date}; HTTPError 400 invalid_tier (not a billing tier), 404 customer_not_found,
        400 no_stripe_subscription, 409 subscription_item_ambiguous (not exactly one item), 502 stripe_error.
        invalid_tier and subscription_item_ambiguous are decided before any Stripe update.
        Why: ADMIN-12 as amended 2026-11-10: update the existing item ({id, price}), never a bare {price}, which
        adds a second item and bills both plans; it used to validate against staff roles and call no Stripe.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: Stripe (money), SQLite (customers, audit_log)."""
        new_tier = payload.get("new_tier")
        if not new_tier:
            raise HTTPError(400, "missing_fields", "new_tier required")
        if new_tier not in PLAN_PRICE_IDS:
            raise HTTPError(400, "invalid_tier", f"Plan tier must be one of {sorted(PLAN_PRICE_IDS)}")

        cur = self.conn.cursor()
        cur.execute("SELECT * FROM customers WHERE id = ?", (customer_id,))
        cust = cur.fetchone()
        if not cust:
            raise HTTPError(404, "customer_not_found", "Customer does not exist")
        old_tier = cust["tier"]
        stripe_sub_id = cust["stripe_subscription_id"]
        if not stripe_sub_id:
            raise HTTPError(400, "no_stripe_subscription", "Customer has no Stripe subscription")

        self._stripe_update_subscription(stripe_sub_id, new_tier)

        cur.execute("UPDATE customers SET tier = ? WHERE id = ?",
                    (new_tier, customer_id))

        self._audit(actor["id"], "plan_changed",
                    resource_type="customer", resource_id=customer_id,
                    details={"old_tier": old_tier, "new_tier": new_tier})

        self.conn.commit()
        return {
            "success": True,
            "customer_id": customer_id,
            "old_tier": old_tier,
            "new_tier": new_tier,
            "effective_date": now()
        }

    def _stripe(self) -> Any:
        """The Stripe client: the injected one, else the `stripe` package with STRIPE_SECRET_KEY.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: imports stripe on first use."""
        if self._stripe_client is None:
            import stripe
            stripe.api_key = STRIPE_SECRET_KEY
            self._stripe_client = stripe
        return self._stripe_client

    def _stripe_update_subscription(self, subscription_id: str, new_tier: str) -> None:
        """Replace the price on the subscription's one item: retrieve it, require exactly one item, then
        Subscription.modify(id, items=[{id: item_id, price}], proration_behavior="create_prorations").

        In: the Stripe subscription id and a valid plan tier. Out: None; HTTPError 409
        subscription_item_ambiguous before any update, or 502 stripe_error. Why: ADMIN-12 / BILL-03 (amended
        2026-11-10); this was a no-op stub. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: Stripe (money)."""
        client = self._stripe()
        try:
            current = client.Subscription.retrieve(subscription_id)
        except Exception as e:  # a Stripe or network error is reported, never swallowed
            raise HTTPError(502, "stripe_error", str(e))
        items = current["items"]["data"]
        if len(items) != 1:
            raise HTTPError(409, "subscription_item_ambiguous", "The subscription does not have exactly one item")
        try:
            client.Subscription.modify(
                subscription_id,
                items=[{"id": items[0]["id"], "price": PLAN_PRICE_IDS[new_tier]}],
                proration_behavior="create_prorations",
            )
        except Exception as e:
            raise HTTPError(502, "stripe_error", str(e))

    def _customers_queue_refund(self, actor: sqlite3.Row, customer_id: int,
                                payload: Dict[str, Any]) -> Dict[str, Any]:
        """POST /admin/customers/{customer_id}/action, action=queue_refund: queue a refund of one invoice.

        In: the acting owner's row, the customer id from the path, payload {invoice_id, amount, reason}.
        Out: {success, refund_id, status 'queued', amount}. Refusals (HTTPError): 400 missing_fields; 400
        invalid_amount (not a positive number); 404 invoice_not_found (no such invoice, or it belongs to another
        customer); 400 invalid_invoice_status (not 'succeeded'); 400 refund_exceeds_invoice (queued and executed
        refunds plus this one would exceed the invoice amount). Nothing is written on a refusal.
        Why: Phase B.2 python bug (2026-11-10): it assumed the invoice existed and had succeeded, so any amount
        could be refunded against any invoice id; the spec's Check is "invoice exists, status='succeeded'", and the
        Go template's codes are used. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches: SQLite (invoices read; refunds, audit_log written). Money: only queues; nothing is paid out here."""
        invoice_id = payload.get("invoice_id")
        amount = payload.get("amount")
        reason = payload.get("reason")
        if invoice_id is None or amount is None or not reason:
            raise HTTPError(400, "missing_fields", "invoice_id, amount, and reason required")
        if isinstance(amount, bool) or not isinstance(amount, (int, float)) or not amount > 0:
            raise HTTPError(400, "invalid_amount", "amount must be a positive number")

        invoice = self.conn.execute("SELECT amount, status FROM invoices WHERE id = ? AND customer_id = ?",
                                    (invoice_id, customer_id)).fetchone()
        if invoice is None:
            raise HTTPError(404, "invoice_not_found", "Invoice not found")
        if invoice["status"] != "succeeded":
            raise HTTPError(400, "invalid_invoice_status", "Only a succeeded invoice can be refunded")
        refunded = self.conn.execute(
            "SELECT COALESCE(SUM(amount), 0) FROM refunds WHERE invoice_id = ? AND status IN ('queued', 'executed')",
            (invoice_id,)).fetchone()[0]
        if refunded + amount > invoice["amount"]:
            raise HTTPError(400, "refund_exceeds_invoice", "Refunds would exceed the invoice amount")

        cur = self.conn.cursor()
        cur.execute(
            """INSERT INTO refunds (invoice_id, amount, reason, status, created_by, created_at)
               VALUES (?, ?, ?, 'queued', ?, ?)""",
            (invoice_id, amount, reason, actor["id"], now())
        )
        refund_id = cur.lastrowid

        self._audit(actor["id"], "refund_queued",
                    resource_type="refund", resource_id=refund_id,
                    details={"invoice_id": invoice_id, "amount": amount, "reason": reason})

        self.conn.commit()
        return {
            "success": True,
            "refund_id": refund_id,
            "status": "queued",
            "amount": amount
        }

    # ----- DEPLOYMENTS DOMAIN -----
    def list_deployments(self, current_user_id: int) -> List[Dict[str, Any]]:
        """GET /admin/deployments (admin or owner). In: caller id. Out: every deployment.
        HTTPError 403 account_suspended first (ADMIN-19, Phase B.2), then 403 admin_or_owner_required.
        Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite (read)."""
        cur_user = self._caller(current_user_id)  # ADMIN-19 (Phase B.2, 2026-11-10)
        self._require_admin_or_owner(cur_user)
        cur = self.conn.cursor()
        cur.execute(
            """SELECT id, customer_id, domain, tier, status, theme_id, published_at
               FROM deployments ORDER BY id"""
        )
        rows = cur.fetchall()
        return [dict(row) for row in rows]

    def deployments_action(self, csrf_token: str, current_user_id: int,
                           action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """POST /admin/deployments/action: create, publish, suspend or retire (owner only).

        In: CSRF token, caller id, action, payload. Out: the action's result; HTTPError 403 account_suspended
        (before any gate, ADMIN-19), 403 csrf_invalid, 403 owner_only, 400 invalid_action. Why: ADMIN-14/15/19.
        Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite."""
        cur_user = self._caller(current_user_id)  # ADMIN-19: before any gate (Phase B.2, 2026-11-10)
        verify_csrf(csrf_token)
        self._require_owner(cur_user)

        if action == "create":
            return self._deployments_create(cur_user, payload)
        elif action == "publish":
            return self._deployments_publish(cur_user, payload)
        elif action == "suspend":
            return self._deployments_suspend(cur_user, payload)
        elif action == "retire":
            return self._deployments_retire(cur_user, payload)
        else:
            raise HTTPError(400, "invalid_action", "Unsupported action")

    def _deployments_create(self, actor: sqlite3.Row, payload: Dict[str, Any]) -> Dict[str, Any]:
        """action=create: a draft deployment for a customer. In: the acting owner's row, payload {customer_id,
        domain, tier (a PLAN: solo/team/enterprise), theme_id}. Out: {success, deployment_id, domain, tier};
        HTTPError 400 missing_fields, 400 invalid_tier (a staff role or unknown value), 404 customer_not_found,
        409 domain_exists. The domain starts unverified. Why: ADMIN-14; spec "TIERS" (Phase B.2: it validated
        the plan against staff roles). Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite (deployments, audit_log)."""
        customer_id = payload.get("customer_id")
        domain = payload.get("domain")
        tier = payload.get("tier")
        theme_id = payload.get("theme_id")
        if not all([customer_id, domain, tier, theme_id]):
            raise HTTPError(400, "missing_fields", "All fields required")
        # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2: a deployment's tier is the PLAN; it was checked
        # against the staff roles, so 'user' passed and 'team' was refused.
        validate_plan_tier(tier)

        cur = self.conn.cursor()
        cur.execute("SELECT * FROM customers WHERE id = ?", (customer_id,))
        if not cur.fetchone():
            raise HTTPError(404, "customer_not_found", "Customer does not exist")
        cur.execute("SELECT * FROM deployments WHERE domain = ?", (domain,))
        if cur.fetchone():
            raise HTTPError(409, "domain_exists", "Domain already registered")
        # Assume theme existence check passed

        cur.execute(
            """INSERT INTO deployments (customer_id, domain, tier, theme_id, status)
               VALUES (?, ?, ?, ?, 'draft')""",
            (customer_id, domain, tier, theme_id)
        )
        deployment_id = cur.lastrowid

        # Simulate config init (no-op)
        self._audit(actor["id"], "deployment_created",
                    resource_type="deployment", resource_id=deployment_id,
                    details={"customer_id": customer_id, "domain": domain, "tier": tier})

        self.conn.commit()
        return {"success": True, "deployment_id": deployment_id, "domain": domain, "tier": tier}

    def _deployments_publish(self, actor: sqlite3.Row, payload: Dict[str, Any]) -> Dict[str, Any]:
        """action=publish: make a draft deployment live. Double gate: owner (checked by the caller) and
        SAFETY_FLAGS['can_publish']. In: the acting owner's row, payload {deployment_id}. Out: {success,
        deployment_id, status 'live', public_url}; HTTPError 400 missing_fields, 403 publish_not_allowed, 404
        deployment_not_found, 400 invalid_status (not draft), 400 domain_not_verified. Why: ADMIN-15; Phase B.2
        (domain_verified was assumed). Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite (deployments, audit_log)."""
        deployment_id = payload.get("deployment_id")
        if not deployment_id:
            raise HTTPError(400, "missing_fields", "deployment_id required")
        if not SAFETY_FLAGS.get("can_publish"):
            raise HTTPError(403, "publish_not_allowed", "Publishing is disabled by safety flag")

        cur = self.conn.cursor()
        cur.execute("SELECT * FROM deployments WHERE id = ?", (deployment_id,))
        dep = cur.fetchone()
        if not dep:
            raise HTTPError(404, "deployment_not_found", "Deployment does not exist")
        if dep["status"] != "draft":
            raise HTTPError(400, "invalid_status", "Only draft deployments can be published")
        # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2: the spec's domain_verified check (it was assumed).
        # theme_set holds by construction: theme_id is NOT NULL and create requires it.
        if not dep["domain_verified"]:
            raise HTTPError(400, "domain_not_verified", "The deployment's domain is not verified")

        cur.execute(
            "UPDATE deployments SET status = 'live', published_at = ? WHERE id = ?",
            (now(), deployment_id)
        )
        self._audit(actor["id"], "deployment_published",
                    resource_type="deployment", resource_id=deployment_id,
                    details={"public_url": f"https://{dep['domain']}"})

        self.conn.commit()
        return {
            "success": True,
            "deployment_id": deployment_id,
            "status": "live",
            "public_url": f"https://{dep['domain']}"
        }

    def mark_domain_verified(self, deployment_id: int) -> None:
        """Record that a deployment's domain passed verification (called by the domain-verification job, e.g.
        after a DNS TXT check; not an admin action, so no gate). In: deployment id. Out: None, or HTTPError 404
        deployment_not_found. Why: spec "TIERS" paragraph (Phase B.2, 2026-11-10): deployments carry
        domain_verified, default false, and publish needs it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches: SQLite (deployments)."""
        cur = self.conn.execute("UPDATE deployments SET domain_verified = 1 WHERE id = ?", (deployment_id,))
        if cur.rowcount != 1:
            self.conn.rollback()
            raise HTTPError(404, "deployment_not_found", "Deployment does not exist")
        self.conn.commit()

    def _deployments_suspend(self, actor: sqlite3.Row, payload: Dict[str, Any]) -> Dict[str, Any]:
        deployment_id = payload.get("deployment_id")
        reason = payload.get("reason")
        if not all([deployment_id, reason]):
            raise HTTPError(400, "missing_fields", "deployment_id and reason required")
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM deployments WHERE id = ?", (deployment_id,))
        if not cur.fetchone():
            raise HTTPError(404, "deployment_not_found", "Deployment does not exist")
        cur.execute(
            "UPDATE deployments SET status = 'suspended', suspend_reason = ? WHERE id = ?",
            (reason, deployment_id)
        )
        self._audit(actor["id"], "deployment_suspended",
                    resource_type="deployment", resource_id=deployment_id,
                    details={"reason": reason})
        self.conn.commit()
        return {"success": True, "deployment_id": deployment_id, "status": "suspended"}

    def _deployments_retire(self, actor: sqlite3.Row, payload: Dict[str, Any]) -> Dict[str, Any]:
        deployment_id = payload.get("deployment_id")
        if not deployment_id:
            raise HTTPError(400, "missing_fields", "deployment_id required")
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM deployments WHERE id = ?", (deployment_id,))
        if not cur.fetchone():
            raise HTTPError(404, "deployment_not_found", "Deployment does not exist")
        cur.execute(
            "UPDATE deployments SET status = 'archived', archived_at = ? WHERE id = ?",
            (now(), deployment_id)
        )
        self._audit(actor["id"], "deployment_archived",
                    resource_type="deployment", resource_id=deployment_id,
                    details={})
        self.conn.commit()
        return {"success": True, "deployment_id": deployment_id, "status": "archived"}

    # ----- GOVERNANCE DOMAIN -----
    def list_pending_governance_actions(self, current_user_id: int, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """GET /admin/governance/actions (owner or admin). In: caller id, limit, offset. Out: pending
        actions. HTTPError 403 account_suspended first (ADMIN-19, Phase B.2), then 403 owner_or_admin_required.
        Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite (read)."""
        cur_user = self._caller(current_user_id)  # ADMIN-19 (Phase B.2, 2026-11-10)
        if cur_user["tier"] not in {"owner", "admin"}:
            raise HTTPError(403, "owner_or_admin_required", "Owner or Admin required")
        cur = self.conn.cursor()
        cur.execute(
            """SELECT * FROM governance_actions
               WHERE status = 'pending' ORDER BY submitted_at LIMIT ? OFFSET ?""",
            (limit, offset)
        )
        rows = cur.fetchall()
        return [dict(row) for row in rows]

    def decide_governance_action(self, csrf_token: str, current_user_id: int,
                                 action_id: int, decide: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """POST /admin/governance/actions/{action_id}/decide: approve (runs the action) or reject.

        In: CSRF token, caller id, action id, decide, payload {reason} for reject. Out: {success, action_id,
        status}; HTTPError 403 account_suspended (before any gate, ADMIN-19), 403 csrf_invalid, 403 owner_only,
        404 governance_action_not_found, 400 action_already_decided, 400 invalid_tier (a change_role to a plan
        value, Phase B.2 "TIERS"), 400 cannot_demote_last_owner (Phase B.2: the change_role Check now applies to
        an approved change too), 400 invalid_decision. Why: ADMIN-16/17/19. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Spec LAST OWNER, approver rule (the PR 22 review found C#, Java
        and Rust missing it; Python had the same gap): a change_role whose target is the approver is 400
        cannot_change_own_role, checked after the last-owner check and before any write, so the action stays
        pending."""
        actor = self._caller(current_user_id)  # ADMIN-19: before any gate (Phase B.2, 2026-11-10)
        verify_csrf(csrf_token)
        self._require_owner(actor)

        cur = self.conn.cursor()
        cur.execute("SELECT * FROM governance_actions WHERE id = ?", (action_id,))
        ga = cur.fetchone()
        if not ga:
            raise HTTPError(404, "governance_action_not_found", "Action does not exist")
        if ga["status"] != "pending":
            raise HTTPError(400, "action_already_decided", "Action already decided")

        if decide == "approve":
            # Execute original action (simplified)
            params = json.loads(ga["params"])
            if ga["action_type"] == "change_role":
                target_user_id = ga["target_resource_id"]
                new_tier = params["new_tier"]
                # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2 "TIERS": a role change takes a staff
                # role only (a plan value such as 'team' is 400 invalid_tier), as action=change_role does.
                validate_tier(new_tier)
                target_user = self._get_user_by_id(target_user_id)
                # Same last-owner Check as action=change_role (Phase B.2, 2026-11-10): an approved role change
                # may not demote the last active owner (e.g. the approver approving their own demotion after the
                # other owner was suspended).
                if target_user["tier"] == "owner" and new_tier != "owner" and self._count_active_owners() == 1:
                    raise HTTPError(400, "cannot_demote_last_owner", "Cannot demote last active owner")
                # Spec LAST OWNER, approver rule (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
                if target_user_id == actor["id"]:
                    raise HTTPError(400, "cannot_change_own_role", "Cannot change own role")
                old_tier = target_user["tier"]
                cur.execute("UPDATE users SET tier = ?, last_active_at = ? WHERE id = ?",
                            (new_tier, now(), target_user_id))
                self._audit(actor["id"], "role_changed",
                            resource_type="user", resource_id=target_user_id,
                            details={"old_tier": old_tier, "new_tier": new_tier})
                execution_result = {"old_tier": old_tier, "new_tier": new_tier}
            else:
                execution_result = {}

            cur.execute(
                """UPDATE governance_actions
                   SET status = 'approved', approved_by = ?, approved_at = ?, 
                       execution_result = ?
                   WHERE id = ?""",
                (actor["id"], now(), json.dumps(execution_result), action_id)
            )
            self._audit(actor["id"], "action_approved",
                        resource_type="governance_action", resource_id=action_id,
                        details=execution_result)
            self.conn.commit()
            return {"success": True, "action_id": action_id, "status": "approved"}

        elif decide == "reject":
            reason = payload.get("reason")
            if not reason:
                raise HTTPError(400, "missing_fields", "reason required for rejection")
            cur.execute(
                """UPDATE governance_actions
                   SET status = 'rejected', rejection_reason = ?, approved_by = ?, approved_at = ?
                   WHERE id = ?""",
                (reason, actor["id"], now(), action_id)
            )
            self._audit(actor["id"], "action_rejected",
                        resource_type="governance_action", resource_id=action_id,
                        details={"reason": reason})
            self.conn.commit()
            return {"success": True, "action_id": action_id, "status": "rejected"}
        else:
            raise HTTPError(400, "invalid_decision", "decide must be approve or reject")

    def search_audit_log(self, current_user_id: int,
                         filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """GET /admin/governance/audit-log (owner or admin). In: caller id, filters {action_type,
        resource_id, date_range, limit, offset}. Out: matching rows, newest first. HTTPError 403
        account_suspended first (ADMIN-19, Phase B.2), then 403 owner_or_admin_required. Why: ADMIN-18.
        Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite (read)."""
        cur_user = self._caller(current_user_id)  # ADMIN-19 (Phase B.2, 2026-11-10)
        if cur_user["tier"] not in {"owner", "admin"}:
            raise HTTPError(403, "owner_or_admin_required", "Owner or Admin required")
        limit = filters.get("limit", 100)
        offset = filters.get("offset", 0)
        conditions = []
        params: List[Any] = []

        if "action_type" in filters:
            conditions.append("action = ?")
            params.append(filters["action_type"])
        if "resource_id" in filters:
            conditions.append("resource_id = ?")
            params.append(filters["resource_id"])
        if "date_range" in filters:
            start, end = filters["date_range"]
            conditions.append("timestamp BETWEEN ? AND ?")
            params.extend([start, end])

        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        query = f"""SELECT * FROM audit_log {where_clause}
                    ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?"""
        params.extend([limit, offset])
        cur = self.conn.cursor()
        cur.execute(query, tuple(params))
        rows = cur.fetchall()
        return [dict(row) for row in rows]

    # ----- GOVERNANCE ACTION CREATION (helper for tests) -----
    def create_governance_action(self, actor_id: int, action_type: str,
                                 target_resource_type: str, target_resource_id: int,
                                 params: Dict[str, Any]) -> int:
        cur = self.conn.cursor()
        cur.execute(
            """INSERT INTO governance_actions
               (action_type, actor_id, target_resource_type, target_resource_id, params, status, submitted_at)
               VALUES (?, ?, ?, ?, ?, 'pending', ?)""",
            (action_type, actor_id, target_resource_type, target_resource_id,
             json.dumps(params), now())
        )
        self.conn.commit()
        return cur.lastrowid

"""Stripe webhook entitlements (docs/specs/stripe_webhook_entitlements.md): verify Stripe's signed webhook, apply
every event exactly once and in order, and keep one answer per user of what they are entitled to right now.

Why: Phase D wave 1, owner request 2026-11-10 (STRIPEWH-01 to STRIPEWH-14). 2026-11-10,
session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the injected store (SQLite, tables stripe_events and
entitlement_subscriptions) and the injected Stripe client (network in production, a fake in tests). Decides paid
access (money-adjacent) but never charges. Never logs the secret, the signature header or the payload.

Inputs and outputs: EntitlementService(store, webhook_secret, price_plans, stripe_client, user_exists, clock,
period_grace_seconds) with handle_webhook and get_entitlement; sign_payload and verify_signature are module
functions. Every answer is a RETURNED dict with its status, never an unhandled exception.
"""
import hashlib
import hmac
import json
import math
import re
import sqlite3
import threading
import time
from typing import Callable, Dict, Optional

TOLERANCE = 300
MAX_HEADER_BYTES = 4096
MAX_TIME = 99999999999
_EVT_RE = re.compile(r"evt_[A-Za-z0-9_]{1,200}")
_SUB_RE = re.compile(r"sub_[A-Za-z0-9_]{1,200}")
_STATUS_RE = re.compile(r"[a-z_]{1,32}")
_HEX64_RE = re.compile(r"[0-9a-f]{64}")
_T_RE = re.compile(r"[0-9]{1,12}")


def _err(error: str, status: int) -> dict:
    """A refusal {error, status}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return {"error": error, "status": status}


def _as_bytes(payload) -> bytes:
    """The raw body as bytes (a str is taken as its UTF-8). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload)
    if isinstance(payload, str):
        return payload.encode("utf-8")
    raise TypeError("payload must be bytes")


def sign_payload(payload, secret: str, timestamp: int) -> str:
    """"t=" + timestamp + ",v1=" + lower-case hex HMAC-SHA256(UTF-8 of the WHOLE secret, digits + "." + payload).

    In: raw body, secret, timestamp. Out: the Stripe-Signature header. Why: STRIPEWH-01 (tests and test clients).
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    digits = str(int(timestamp))
    mac = hmac.new(secret.encode("utf-8"), digits.encode("ascii") + b"." + _as_bytes(payload), hashlib.sha256)
    return "t=" + digits + ",v1=" + mac.hexdigest()


def verify_signature(payload, header, secret, now: int) -> dict:
    """verify_signature, steps 1-5: configured secret, header present, parse t and v1 candidates, constant-time
    compare against EVERY candidate, tolerance. Out: {ok: true, timestamp} or a refusal.

    Why: STRIPEWH-02..05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    if not isinstance(secret, str) or len(secret.encode("utf-8")) < 16:
        return _err("webhook_not_configured", 503)
    if header is None or header == "":
        return _err("missing_signature", 400)
    if not isinstance(header, str) or len(header.encode("utf-8")) > MAX_HEADER_BYTES:
        return _err("invalid_signature", 400)
    t_values = []
    candidates = []
    for element in header.split(","):
        element = element.strip(" ")
        if "=" not in element:
            continue
        name, value = element.split("=", 1)
        if name == "t":
            t_values.append(value)
        elif name == "v1" and _HEX64_RE.fullmatch(value):
            candidates.append(value)
    if len(t_values) != 1 or _T_RE.fullmatch(t_values[0]) is None:
        return _err("invalid_signature", 400)
    if not candidates:
        return _err("invalid_signature", 400)
    t = t_values[0]
    try:
        body = _as_bytes(payload)
    except TypeError:
        return _err("invalid_signature", 400)
    expected = hmac.new(secret.encode("utf-8"), t.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()
    matched = False
    for cand in candidates:  # every candidate is compared; no early exit
        if hmac.compare_digest(expected.encode("ascii"), cand.encode("ascii")):
            matched = True
    if not matched:
        return _err("invalid_signature", 400)
    if abs(int(now) - int(t)) > TOLERANCE:
        return _err("timestamp_out_of_tolerance", 400)
    return {"ok": True, "timestamp": int(t)}


def as_time(v) -> Optional[int]:
    """TIME: a JSON number (int or float, never bool) that is finite, whole and in 0..99999999999. Out: int or None.

    Why: STRIPEWH-06, STRIPEWH-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    if isinstance(v, float) and (not math.isfinite(v) or v != math.floor(v)):
        return None
    if v < 0 or v > MAX_TIME:
        return None
    return int(v)


def _reject_constant(_name):
    """json parse_constant hook: NaN and Infinity are not JSON. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    raise ValueError("not JSON")


def parse_event(payload: bytes) -> Optional[dict]:
    """Step 6: UTF-8 with no BOM, valid JSON, an object with id evt_..., type (1-100 printable ASCII), created
    (TIME) and data.object (an object). Out: the event dict or None. Anything the parser raises is None.

    Why: STRIPEWH-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    try:
        if payload.startswith(b"\xef\xbb\xbf"):
            return None
        event = json.loads(payload.decode("utf-8"), parse_constant=_reject_constant)
    except Exception:  # noqa: BLE001 - a depth limit or any parser error is invalid_payload
        return None
    if not isinstance(event, dict):
        return None
    eid, etype = event.get("id"), event.get("type")
    if not isinstance(eid, str) or _EVT_RE.fullmatch(eid) is None:
        return None
    if not isinstance(etype, str) or not (1 <= len(etype) <= 100) or any(not (" " <= c <= "~") for c in etype):
        return None
    if as_time(event.get("created")) is None:
        return None
    data = event.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("object"), dict):
        return None
    return event


def _get(obj, *path):
    """Follow dict keys / list indexes; None when any step is missing or of the wrong type.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    cur = obj
    for p in path:
        if isinstance(p, int):
            if not isinstance(cur, list) or len(cur) <= p:
                return None
            cur = cur[p]
        else:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(p)
    return cur


# ------------------------------------------------------------------------------------------------------ store
class SqliteEntitlementStore:
    """The store on SQLite with the spec's schema: one shared connection guarded by a lock. handle_webhook runs
    steps 7-9 inside one transaction on it.

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the SQLite database (memory or file)."""

    COLUMNS = ("stripe_subscription_id", "user_id", "stripe_customer_id", "price_id", "plan", "status",
               "current_period_end", "cancel_at_period_end", "event_at", "event_rank", "updated_at")

    def __init__(self, path: str = ":memory:"):
        """Open the database and create the tables. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.lock = threading.RLock()
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS stripe_events (event_id TEXT PRIMARY KEY, type TEXT, created INT,
                received_at INT, result TEXT);
            CREATE TABLE IF NOT EXISTS entitlement_subscriptions (stripe_subscription_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL, stripe_customer_id TEXT, price_id TEXT, plan TEXT NULL, status TEXT,
                current_period_end INT NOT NULL, cancel_at_period_end BOOL, event_at INT, event_rank INT,
                updated_at INT);
        """)

    def claim_event(self, event_id: str, etype: str, created: int, now: int) -> bool:
        """CLAIM: insert the event row; False when the id is already there (a duplicate key, not a read first).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        try:
            self.conn.execute("INSERT INTO stripe_events (event_id, type, created, received_at, result) "
                              "VALUES (?, ?, ?, ?, NULL)", (event_id, etype, created, now))
            return True
        except sqlite3.IntegrityError:
            return False

    def set_event_result(self, event_id: str, result: str) -> None:
        """Store the result in the event's row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.conn.execute("UPDATE stripe_events SET result = ? WHERE event_id = ?", (result, event_id))

    def _row(self, r) -> Optional[dict]:
        """A result tuple as a dict (cancel_at_period_end as bool). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        if r is None:
            return None
        d = dict(zip(self.COLUMNS, r))
        d["cancel_at_period_end"] = bool(d["cancel_at_period_end"])
        return d

    def get_subscription(self, sub_id: str) -> Optional[dict]:
        """The row for a subscription id, or None. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            return self._row(self.conn.execute("SELECT " + ", ".join(self.COLUMNS) + " FROM entitlement_subscriptions "
                                               "WHERE stripe_subscription_id = ?", (sub_id,)).fetchone())

    def users_for_customer(self, customer_id: str) -> list:
        """The distinct user_ids of rows with that stripe_customer_id. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            rows = self.conn.execute("SELECT DISTINCT user_id FROM entitlement_subscriptions "
                                     "WHERE stripe_customer_id = ?", (customer_id,)).fetchall()
        return [r[0] for r in rows]

    def rows_for_user(self, user_id: str) -> list:
        """Every row of a user. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            rows = self.conn.execute("SELECT " + ", ".join(self.COLUMNS) + " FROM entitlement_subscriptions "
                                     "WHERE user_id = ?", (user_id,)).fetchall()
        return [self._row(r) for r in rows]

    def write_subscription(self, row: dict) -> None:
        """Insert or replace a row (rule g). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.conn.execute("INSERT OR REPLACE INTO entitlement_subscriptions (" + ", ".join(self.COLUMNS) + ") "
                          "VALUES (" + ", ".join("?" * len(self.COLUMNS)) + ")",
                          tuple(row[c] for c in self.COLUMNS))

    def event_ids(self) -> list:
        """(event_id, result) of every recorded event, in insertion order. 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP."""
        with self.lock:
            return [tuple(r) for r in self.conn.execute("SELECT event_id, result FROM stripe_events ORDER BY rowid")]


# ---------------------------------------------------------------------------------------------------- service
class EntitlementService:
    """handle_webhook and get_entitlement over an injected store, secret, price plans, Stripe client, account
    lookup, clock and grace period. Why: STRIPEWH-01..14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    Touches: the store and the Stripe client."""

    def __init__(self, store: SqliteEntitlementStore, webhook_secret: str, price_plans: Dict[str, str],
                 stripe_client, user_exists: Callable[[str], bool], clock: Optional[Callable[[], int]] = None,
                 period_grace_seconds: int = 0):
        """Keep the configuration (verify_signature answers 503 for a secret under 16 bytes at every call).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        self.store = store
        self.webhook_secret = webhook_secret
        self.price_plans = dict(price_plans or {})
        self.client = stripe_client
        self.user_exists = user_exists
        self.clock = clock or (lambda: int(time.time()))
        self.period_grace_seconds = int(period_grace_seconds)

    def _now(self) -> int:
        """The injected clock as an int. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        return int(self.clock())

    def handle_webhook(self, payload, header) -> dict:
        """handle_webhook, steps 1-9: verify, parse, claim the event id, apply, store the result; steps 7-9 are one
        transaction and any error while applying undoes them (500 processing_failed, so Stripe retries).
        Out: {status: 200, received: true, result} or a refusal. Why: STRIPEWH-01..14.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the Stripe client (network)."""
        now = self._now()
        v = verify_signature(payload, header, self.webhook_secret, now)
        if not v.get("ok"):
            return v
        event = parse_event(_as_bytes(payload))
        if event is None:
            return _err("invalid_payload", 400)
        created = as_time(event["created"])
        conn = self.store.conn
        with self.store.lock:
            conn.execute("BEGIN IMMEDIATE")
            try:
                if not self.store.claim_event(event["id"], event["type"], created, now):
                    conn.execute("ROLLBACK")
                    return {"status": 200, "received": True, "result": "duplicate"}
                result = self._apply(event, created, now)
                self.store.set_event_result(event["id"], result)
                conn.execute("COMMIT")
            except Exception:  # noqa: BLE001 - undo the claim and every change; Stripe sends the event again
                conn.execute("ROLLBACK")
                return _err("processing_failed", 500)
        return {"status": 200, "received": True, "result": result}

    def _apply(self, event: dict, created: int, now: int) -> str:
        """APPLY(event) by its type. Out: "applied" | "stale" | "ignored". Raises on a client or store error.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the Stripe client."""
        etype = event["type"]
        obj = event["data"]["object"]
        if etype in ("customer.subscription.created", "customer.subscription.updated",
                     "customer.subscription.deleted"):
            rank = {"customer.subscription.created": 0, "customer.subscription.updated": 1,
                    "customer.subscription.deleted": 2}[etype]
            return self._subscription(obj, _get(obj, "metadata", "user_id"), rank, created, now, fetched=False)
        if etype == "checkout.session.completed":
            sub_id = obj.get("subscription")
            if obj.get("mode") != "subscription" or not isinstance(sub_id, str) or _SUB_RE.fullmatch(sub_id) is None:
                return "ignored"
            row = self.store.get_subscription(sub_id)
            if row is not None and (row["event_at"], row["event_rank"]) > (created, 1):
                return "stale"
            sub = self.client.retrieve_subscription(sub_id)
            hint = obj.get("client_reference_id")
            if not isinstance(hint, str) or hint == "":
                hint = _get(obj, "metadata", "user_id")
            return self._subscription(sub, hint, 1, created, now, fetched=True)
        return "ignored"

    def _price(self, sub, row: Optional[dict]):
        """Rule b: (price_id, plan, ignored). No row and an unknown or missing price -> ignored; with a row a known
        price sets its plan, a missing or unchanged price keeps the row's, another unknown price sets plan null.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        price_id = _get(sub, "items", "data", 0, "price", "id")
        if not isinstance(price_id, str):
            price_id = None
        if row is None:
            if price_id is None or price_id not in self.price_plans:
                return None, None, True
            return price_id, self.price_plans[price_id], False
        if price_id is not None and price_id in self.price_plans:
            return price_id, self.price_plans[price_id], False
        if price_id is None or price_id == row["price_id"]:
            return row["price_id"], row["plan"], False
        return price_id, None, False

    def _subscription(self, sub, hint, rank: int, event_at: int, now: int, fetched: bool) -> str:
        """SUBSCRIPTION(sub, hint, rank), rules a-g. Out: "applied" | "stale" | "ignored".

        At an equal (event_at, rank) of rank 0 or 1 the subscription is fetched and the rest of the rules (rule b's
        price included) run on the fetched object, so the row ends with what Stripe holds now.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the Stripe client."""
        if not isinstance(sub, dict):
            return "ignored"
        sub_id = sub.get("id")
        if not isinstance(sub_id, str) or _SUB_RE.fullmatch(sub_id) is None:
            return "ignored"
        row = self.store.get_subscription(sub_id)
        price_id, plan, ignored = self._price(sub, row)
        if ignored:
            return "ignored"
        if row is not None:
            user_id = row["user_id"]
        elif isinstance(hint, str) and hint != "" and self.user_exists(hint):
            user_id = hint
        else:
            customer = sub.get("customer")
            users = self.store.users_for_customer(customer) if isinstance(customer, str) and customer else []
            if len(users) != 1:
                return "ignored"
            user_id = users[0]
        if row is not None:
            if (event_at, rank) < (row["event_at"], row["event_rank"]):
                return "stale"
            if rank in (0, 1) and (event_at, rank) == (row["event_at"], row["event_rank"]) and not fetched:
                sub = self.client.retrieve_subscription(sub_id)
                if not isinstance(sub, dict):
                    return "ignored"
                price_id, plan, _ = self._price(sub, row)
        period_end = as_time(sub.get("current_period_end"))
        if period_end is None:
            ends = [as_time(_get(item, "current_period_end")) for item in (_get(sub, "items", "data") or [])]
            ends = [e for e in ends if e is not None]
            if ends:
                period_end = max(ends)
            else:
                period_end = row["current_period_end"] if row is not None else 0
        if rank == 2:
            status = "canceled"
        else:
            status = sub.get("status")
            if not isinstance(status, str) or _STATUS_RE.fullmatch(status) is None:
                return "ignored"
        customer = sub.get("customer")
        self.store.write_subscription({
            "stripe_subscription_id": sub_id, "user_id": user_id,
            "stripe_customer_id": customer if isinstance(customer, str) else None,
            "price_id": price_id, "plan": plan, "status": status, "current_period_end": period_end,
            "cancel_at_period_end": sub.get("cancel_at_period_end") is True, "event_at": event_at,
            "event_rank": rank, "updated_at": now})
        return "applied"

    def get_entitlement(self, user_id: str) -> dict:
        """get_entitlement: the best ENTITLING row (greatest period end, then event_at, then subscription id), else
        the latest row as not entitled, else the "none" answer. Computed from the clock at every call.
        Why: STRIPEWH-07, 10, 14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the store."""
        now = self._now()
        rows = self.store.rows_for_user(user_id)
        if not rows:
            return {"entitled": False, "plan": None, "status": "none", "current_period_end": None,
                    "cancel_at_period_end": False}
        entitling = [r for r in rows if r["plan"] is not None and r["status"] in ("active", "trialing")
                     and r["current_period_end"] + self.period_grace_seconds > now]
        if entitling:
            best = max(entitling, key=lambda r: (r["current_period_end"], r["event_at"],
                                                 r["stripe_subscription_id"].encode("utf-8")))
            return {"entitled": True, "plan": best["plan"], "status": best["status"],
                    "current_period_end": best["current_period_end"],
                    "cancel_at_period_end": best["cancel_at_period_end"]}
        latest = max(rows, key=lambda r: (r["event_at"], r["stripe_subscription_id"].encode("utf-8")))
        return {"entitled": False, "plan": None, "status": latest["status"],
                "current_period_end": latest["current_period_end"],
                "cancel_at_period_end": latest["cancel_at_period_end"]}

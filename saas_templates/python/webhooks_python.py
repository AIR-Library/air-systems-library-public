import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


@dataclass
class Endpoint:
    id: str
    org_id: str
    url: str
    secret: str
    event_types: List[str]
    active: bool
    failure_count: int
    created_at: float


@dataclass
class Message:
    """One event sent for one org. org_id added 2026-11-10 (HOOK-06, session_012zDydZCZ4AChqhEZ4oVtaP):
    the message records which tenant it belongs to so its deliveries can only target that tenant."""
    id: str
    org_id: str
    event_type: str
    payload: Dict[str, Any]
    created_at: float


@dataclass
class Delivery:
    id: int
    message_id: str
    endpoint_id: str
    attempt: int
    status_code: Optional[int]
    success: bool
    error: Optional[str]
    next_attempt_at: Optional[float]
    delivered_at: Optional[float]


class Store(ABC):
    @abstractmethod
    def create_endpoint(self, org_id: str, url: str, event_types: List[str]) -> Endpoint:
        pass

    @abstractmethod
    def get_endpoint(self, endpoint_id: str) -> Optional[Endpoint]:
        pass

    @abstractmethod
    def get_endpoints_for_event(self, org_id: str, event_type: str) -> List[Endpoint]:
        """Active endpoints OF org_id subscribed to exactly event_type, in creation order.

        In: the sending org and the event type. Out: the endpoints that get a delivery.
        Why: HOOK-06, an org's events never reach another org's endpoints (spec amended 2026-09-26).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the store."""
        pass

    @abstractmethod
    def update_endpoint(self, endpoint: Endpoint) -> None:
        pass

    @abstractmethod
    def create_message(self, org_id: str, event_type: str, payload: Dict[str, Any]) -> Message:
        """Store one message for org_id. In: org, event type, payload. Out: the Message with a "msg_" id.
        Why: HOOK-06 (messages carry their org). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: writes the store."""
        pass

    @abstractmethod
    def get_message(self, message_id: str) -> Optional[Message]:
        pass

    @abstractmethod
    def create_delivery(self, message_id: str, endpoint_id: str, attempt: int) -> Delivery:
        pass

    @abstractmethod
    def get_delivery(self, delivery_id: int) -> Optional[Delivery]:
        pass

    @abstractmethod
    def update_delivery(self, delivery: Delivery) -> None:
        pass

    @abstractmethod
    def get_pending_deliveries(self, before: float) -> List[Delivery]: pass


class InMemoryStore(Store):
    def __init__(self):
        self._lock = threading.RLock()
        self._endpoints: Dict[str, Endpoint] = {}
        self._messages: Dict[str, Message] = {}
        self._deliveries: Dict[int, Delivery] = {}
        self._delivery_counter = 0

    def create_endpoint(self, org_id: str, url: str, event_types: List[str]) -> Endpoint:
        with self._lock:
            endpoint_id = f"ep_{secrets.token_urlsafe(16)}"
            secret = generate_secret()
            now = time.time()
            endpoint = Endpoint(
                id=endpoint_id,
                org_id=org_id,
                url=url,
                secret=secret,
                event_types=event_types,
                active=True,
                failure_count=0,
                created_at=now,
            )
            self._endpoints[endpoint_id] = endpoint
            return endpoint

    def get_endpoint(self, endpoint_id: str) -> Optional[Endpoint]:
        with self._lock:
            return self._endpoints.get(endpoint_id)

    def get_endpoints_for_event(self, org_id: str, event_type: str) -> List[Endpoint]:
        """See Store.get_endpoints_for_event. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (HOOK-06)."""
        with self._lock:
            return [
                ep for ep in self._endpoints.values()
                if ep.active and ep.org_id == org_id and event_type in ep.event_types
            ]

    def update_endpoint(self, endpoint: Endpoint) -> None:
        with self._lock:
            self._endpoints[endpoint.id] = endpoint

    def create_message(self, org_id: str, event_type: str, payload: Dict[str, Any]) -> Message:
        """See Store.create_message. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (HOOK-06)."""
        with self._lock:
            message_id = f"msg_{secrets.token_urlsafe(16)}"
            now = time.time()
            message = Message(
                id=message_id,
                org_id=org_id,
                event_type=event_type,
                payload=payload,
                created_at=now,
            )
            self._messages[message_id] = message
            return message

    def get_message(self, message_id: str) -> Optional[Message]:
        with self._lock:
            return self._messages.get(message_id)

    def create_delivery(self, message_id: str, endpoint_id: str, attempt: int) -> Delivery:
        with self._lock:
            self._delivery_counter += 1
            delivery_id = self._delivery_counter
            now = time.time()
            delivery = Delivery(
                id=delivery_id,
                message_id=message_id,
                endpoint_id=endpoint_id,
                attempt=attempt,
                status_code=None,
                success=False,
                error=None,
                next_attempt_at=now,
                delivered_at=None,
            )
            self._deliveries[delivery_id] = delivery
            return delivery

    def get_delivery(self, delivery_id: int) -> Optional[Delivery]:
        with self._lock:
            return self._deliveries.get(delivery_id)

    def update_delivery(self, delivery: Delivery) -> None:
        with self._lock:
            self._deliveries[delivery.id] = delivery

    def get_pending_deliveries(self, before: float) -> List[Delivery]:
        with self._lock:
            return [
                d for d in self._deliveries.values()
                if not d.success
                and d.next_attempt_at is not None
                and d.next_attempt_at <= before
            ]


class SqliteStore(Store):
    def __init__(self, connection: sqlite3.Connection):
        self._conn = connection
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        """Create the webhook tables. [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] webhook_messages gained org_id (HOOK-06). Touches: SQLite."""
        with self._conn:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS webhook_endpoints (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    secret TEXT NOT NULL,
                    event_types TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    failure_count INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS webhook_messages (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS webhook_deliveries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id TEXT NOT NULL,
                    endpoint_id TEXT NOT NULL,
                    attempt INTEGER NOT NULL,
                    status_code INTEGER,
                    success INTEGER NOT NULL DEFAULT 0,
                    error TEXT,
                    next_attempt_at REAL,
                    delivered_at REAL,
                    FOREIGN KEY (message_id) REFERENCES webhook_messages(id),
                    FOREIGN KEY (endpoint_id) REFERENCES webhook_endpoints(id)
                );
                CREATE INDEX IF NOT EXISTS idx_deliveries_pending
                    ON webhook_deliveries (next_attempt_at)
                    WHERE success = 0 AND next_attempt_at IS NOT NULL;
            """)

    def create_endpoint(self, org_id: str, url: str, event_types: List[str]) -> Endpoint:
        endpoint_id = f"ep_{secrets.token_urlsafe(16)}"
        secret = generate_secret()
        now = time.time()
        with self._conn:
            self._conn.execute(
                "INSERT INTO webhook_endpoints (id, org_id, url, secret, event_types, active, failure_count, created_at) VALUES (?, ?, ?, ?, ?, 1, 0, ?)",
                (endpoint_id, org_id, url, secret, json.dumps(event_types), now),
            )
        return Endpoint(
            id=endpoint_id,
            org_id=org_id,
            url=url,
            secret=secret,
            event_types=event_types,
            active=True,
            failure_count=0,
            created_at=now,
        )

    def get_endpoint(self, endpoint_id: str) -> Optional[Endpoint]:
        row = self._conn.execute(
            "SELECT * FROM webhook_endpoints WHERE id = ?", (endpoint_id,)
        ).fetchone()
        if not row:
            return None
        return self._row_to_endpoint(row)

    def get_endpoints_for_event(self, org_id: str, event_type: str) -> List[Endpoint]:
        """See Store.get_endpoints_for_event. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (HOOK-06).

        Filters by org in SQL and matches the event type exactly in Python: the old LIKE '%"type"%' match
        treated "_" and "%" in an event type as wildcards and ignored the org. Touches: reads webhook_endpoints."""
        rows = self._conn.execute(
            "SELECT * FROM webhook_endpoints WHERE active = 1 AND org_id = ? ORDER BY rowid",
            (org_id,),
        ).fetchall()
        endpoints = [self._row_to_endpoint(row) for row in rows]
        return [ep for ep in endpoints if event_type in ep.event_types]

    def update_endpoint(self, endpoint: Endpoint) -> None:
        with self._conn:
            self._conn.execute(
                "UPDATE webhook_endpoints SET url = ?, secret = ?, event_types = ?, active = ?, failure_count = ? WHERE id = ?",
                (
                    endpoint.url,
                    endpoint.secret,
                    json.dumps(endpoint.event_types),
                    1 if endpoint.active else 0,
                    endpoint.failure_count,
                    endpoint.id,
                ),
            )

    def create_message(self, org_id: str, event_type: str, payload: Dict[str, Any]) -> Message:
        """See Store.create_message. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (HOOK-06). Touches: webhook_messages."""
        message_id = f"msg_{secrets.token_urlsafe(16)}"
        now = time.time()
        with self._conn:
            self._conn.execute(
                "INSERT INTO webhook_messages (id, org_id, event_type, payload, created_at) VALUES (?, ?, ?, ?, ?)",
                (message_id, org_id, event_type, json.dumps(payload), now),
            )
        return Message(id=message_id, org_id=org_id, event_type=event_type, payload=payload, created_at=now)

    def get_message(self, message_id: str) -> Optional[Message]:
        """The stored message (with its org_id since 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP), or None. Touches: SQLite (read)."""
        row = self._conn.execute(
            "SELECT * FROM webhook_messages WHERE id = ?", (message_id,)
        ).fetchone()
        if not row:
            return None
        return Message(
            id=row["id"],
            org_id=row["org_id"],
            event_type=row["event_type"],
            payload=json.loads(row["payload"]),
            created_at=row["created_at"],
        )

    def create_delivery(self, message_id: str, endpoint_id: str, attempt: int) -> Delivery:
        now = time.time()
        with self._conn:
            cur = self._conn.execute(
                """
                INSERT INTO webhook_deliveries 
                (message_id, endpoint_id, attempt, success, next_attempt_at) 
                VALUES (?, ?, ?, 0, ?)
                """,
                (message_id, endpoint_id, attempt, now),
            )
            delivery_id = cur.lastrowid
        return Delivery(
            id=delivery_id,
            message_id=message_id,
            endpoint_id=endpoint_id,
            attempt=attempt,
            status_code=None,
            success=False,
            error=None,
            next_attempt_at=now,
            delivered_at=None,
        )

    def get_delivery(self, delivery_id: int) -> Optional[Delivery]:
        row = self._conn.execute(
            "SELECT * FROM webhook_deliveries WHERE id = ?", (delivery_id,)
        ).fetchone()
        if not row:
            return None
        return self._row_to_delivery(row)

    def update_delivery(self, delivery: Delivery) -> None:
        with self._conn:
            self._conn.execute(
                "UPDATE webhook_deliveries SET status_code = ?, success = ?, error = ?, next_attempt_at = ?, delivered_at = ? WHERE id = ?",
                (
                    delivery.status_code,
                    1 if delivery.success else 0,
                    delivery.error,
                    delivery.next_attempt_at,
                    delivery.delivered_at,
                    delivery.id,
                ),
            )

    def get_pending_deliveries(self, before: float) -> List[Delivery]:
        rows = self._conn.execute(
            "SELECT * FROM webhook_deliveries WHERE success = 0 AND next_attempt_at IS NOT NULL AND next_attempt_at <= ?",
            (before,),
        ).fetchall()
        return [self._row_to_delivery(row) for row in rows]

    def _row_to_endpoint(self, row: sqlite3.Row) -> Endpoint:
        return Endpoint(
            id=row["id"],
            org_id=row["org_id"],
            url=row["url"],
            secret=row["secret"],
            event_types=json.loads(row["event_types"]),
            active=bool(row["active"]),
            failure_count=row["failure_count"],
            created_at=row["created_at"],
        )

    def _row_to_delivery(self, row: sqlite3.Row) -> Delivery:
        return Delivery(
            id=row["id"],
            message_id=row["message_id"],
            endpoint_id=row["endpoint_id"],
            attempt=row["attempt"],
            status_code=row["status_code"] if row["status_code"] is not None else None,
            success=bool(row["success"]),
            error=row["error"] if row["error"] is not None else None,
            next_attempt_at=row["next_attempt_at"] if row["next_attempt_at"] is not None else None,
            delivered_at=row["delivered_at"] if row["delivered_at"] is not None else None,
        )


def generate_secret() -> str:
    """Generate a webhook secret: whsec_ + base64(32 random bytes) = 24-64 bytes decoded."""
    random_bytes = secrets.token_bytes(32)
    encoded = base64.b64encode(random_bytes).decode("ascii")
    return f"whsec_{encoded}"


def decode_secret(secret: str) -> bytes:
    """Decode a whsec_ secret to raw key bytes."""
    if not secret.startswith("whsec_"):
        raise ValueError("Secret must start with 'whsec_'")
    encoded = secret[6:]
    return base64.b64decode(encoded)


def sign(secret: str, msg_id: str, timestamp: int, body: bytes) -> str:
    """Sign a webhook payload. Returns 'v1,<base64 signature>'."""
    key = decode_secret(secret)
    content = f"{msg_id}.{timestamp}.".encode("ascii") + body
    signature = hmac.new(key, content, hashlib.sha256).digest()
    encoded = base64.b64encode(signature).decode("ascii")
    return f"v1,{encoded}"


def verify(
    secret: str,
    headers: Dict[str, str],
    raw_body: bytes,
    tolerance_seconds: int = 300,
    now: Optional[int] = None,
) -> Union[bool, str]:
    """
    Verify a webhook signature (receiver side). Returns True on success, an error string on failure.

    In: the endpoint secret, the request headers, the raw body bytes, the tolerance in seconds and, new on
    2026-11-10, an optional injectable `now` (unix seconds; default the wall clock) so tests are deterministic
    (docs/specs/README.md, "time comes from an injectable clock"; session_012zDydZCZ4AChqhEZ4oVtaP).
    Out: True, or "missing required headers" / "invalid timestamp" / "timestamp outside tolerance" /
    "no matching signature". Signatures are compared in constant time. Touches nothing.
    """
    webhook_id = headers.get("webhook-id")
    webhook_timestamp = headers.get("webhook-timestamp")
    webhook_signature = headers.get("webhook-signature")

    if not webhook_id or not webhook_timestamp or not webhook_signature:
        return "missing required headers"

    try:
        timestamp = int(webhook_timestamp)
    except ValueError:
        return "invalid timestamp"

    now = int(time.time()) if now is None else int(now)
    if abs(now - timestamp) > tolerance_seconds:
        return "timestamp outside tolerance"

    signatures = webhook_signature.split()
    for sig in signatures:
        if not sig.startswith("v1,"):
            continue
        expected_sig = sig[3:]
        calculated = sign(secret, webhook_id, timestamp, raw_body)
        calculated_sig = calculated[3:]
        if hmac.compare_digest(expected_sig, calculated_sig):
            return True

    return "no matching signature"


RETRY_SCHEDULE = [5, 300, 1800, 7200, 18000, 36000, 36000]  # seconds
# An endpoint is disabled after this many consecutive fully-failed messages (every attempt failed). Spec rule;
# 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2: it was 5 failed attempts).
MAX_CONSECUTIVE_FAILED_MESSAGES = 5


def deliver(
    delivery: Delivery,
    store: Store,
    sender: Callable[[str, Dict[str, str], bytes], Tuple[int, bytes]],
) -> Delivery:
    """
    Deliver a webhook. sender(url, headers, body) -> (status_code, response_body).
    Updates and returns the delivery.

    In: one delivery attempt (attempt 0 is the first; each retry is a new delivery row with attempt + 1), the
    store and the sender. Out: the updated delivery. A 2xx marks success and resets the endpoint's
    failure_count; any other result schedules the next attempt from RETRY_SCHEDULE. Only when the LAST attempt
    of a message fails (attempt == len(RETRY_SCHEDULE), no retry left) is the message fully failed: then
    failure_count (consecutive fully-failed messages) goes up by one, and at 5 the endpoint is disabled.
    [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2 bug fix: it counted every failed ATTEMPT, so one
    message's first five retries disabled the endpoint; the spec says 5 consecutive fully-failed MESSAGES.
    Touches: the store (endpoint and delivery rows) and the network through the sender.
    """
    endpoint = store.get_endpoint(delivery.endpoint_id)
    if not endpoint:
        delivery.error = "endpoint not found"
        delivery.success = False
        return delivery

    message = store.get_message(delivery.message_id)
    if not message:
        delivery.error = "message not found"
        delivery.success = False
        return delivery

    timestamp = int(time.time())
    body = json.dumps(message.payload, separators=(",", ":")).encode("utf-8")
    signature = sign(endpoint.secret, delivery.message_id, timestamp, body)

    headers = {
        "webhook-id": delivery.message_id,
        "webhook-timestamp": str(timestamp),
        "webhook-signature": signature,
        "Content-Type": "application/json",
    }

    try:
        status_code, _ = sender(endpoint.url, headers, body)
    except Exception as e:
        status_code = 0
        delivery.error = str(e)

    delivery.status_code = status_code
    delivery.success = 200 <= status_code <= 299

    if delivery.success:
        delivery.delivered_at = time.time()
        delivery.next_attempt_at = None
        endpoint.failure_count = 0
    else:
        delivery.error = delivery.error or f"HTTP {status_code}"
        attempt = delivery.attempt
        if attempt < len(RETRY_SCHEDULE):
            delay = RETRY_SCHEDULE[attempt]
            delivery.next_attempt_at = time.time() + delay
        else:
            delivery.next_attempt_at = None
            # The message has fully failed for this endpoint: no retry is left.
            endpoint.failure_count += 1
            if endpoint.failure_count >= MAX_CONSECUTIVE_FAILED_MESSAGES:
                endpoint.active = False

    store.update_endpoint(endpoint)
    store.update_delivery(delivery)
    return delivery


def rotate_secret(endpoint_id: str, store: Store) -> str:
    endpoint = store.get_endpoint(endpoint_id)
    if not endpoint:
        raise ValueError("endpoint not found")
    new_secret = generate_secret()
    endpoint.secret = new_secret
    store.update_endpoint(endpoint)
    return new_secret


def create_endpoint(org_id: str, url: str, event_types: List[str], store: Store) -> Dict[str, str]:
    if not url.startswith("https://") and not url.startswith("http://localhost"):
        raise ValueError("URL must be https:// or http://localhost")
    endpoint = store.create_endpoint(org_id, url, event_types)
    return {"id": endpoint.id, "secret": endpoint.secret}


def send_event(org_id: str, event_type: str, payload: Dict[str, Any], store: Store) -> str:
    """Create ONE message for org_id and a pending delivery for every active endpoint of THAT org subscribed
    to event_type.

    In: the sending org (from the verified caller, never the payload), the event type, the payload, the store.
    Out: the new message id ("msg_...").
    Why: HOOK-06; the old signature had no org_id, so every event fanned out to every tenant's endpoints.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: writes webhook_messages and webhook_deliveries."""
    message = store.create_message(org_id, event_type, payload)
    endpoints = store.get_endpoints_for_event(org_id, event_type)
    for endpoint in endpoints:
        store.create_delivery(message.id, endpoint.id, 0)
    return message.id
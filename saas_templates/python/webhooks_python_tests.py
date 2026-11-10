import base64
import json
import time
from webhooks_python import (
    InMemoryStore,
    SqliteStore,
    create_endpoint,
    send_event,
    sign,
    verify,
    deliver,
    rotate_secret,
    generate_secret,
    decode_secret,
    RETRY_SCHEDULE,
)
import sqlite3


# HOOK-01
def test_sign_verify_roundtrip():
    store = InMemoryStore()
    secret = generate_secret()
    msg_id = "msg_test123"
    timestamp = int(time.time())
    body = b'{"event": "test", "data": 123}'

    signature = sign(secret, msg_id, timestamp, body)
    assert signature.startswith("v1,")

    headers = {
        "webhook-id": msg_id,
        "webhook-timestamp": str(timestamp),
        "webhook-signature": signature,
    }
    result = verify(secret, headers, body)
    assert result is True, f"Expected True, got {result}"


# HOOK-02
def test_changed_body_or_timestamp_fails():
    store = InMemoryStore()
    secret = generate_secret()
    msg_id = "msg_test456"
    timestamp = int(time.time())
    body = b'{"event": "test", "data": 123}'

    signature = sign(secret, msg_id, timestamp, body)

    # Changed body
    headers = {
        "webhook-id": msg_id,
        "webhook-timestamp": str(timestamp),
        "webhook-signature": signature,
    }
    result = verify(secret, headers, b'{"event": "test", "data": 999}')
    assert result != True, f"Expected failure for changed body, got {result}"

    # Changed timestamp
    headers2 = {
        "webhook-id": msg_id,
        "webhook-timestamp": str(timestamp + 1),
        "webhook-signature": signature,
    }
    result = verify(secret, headers2, body)
    assert result != True, f"Expected failure for changed timestamp, got {result}"


# HOOK-03
def test_old_timestamp_rejected():
    store = InMemoryStore()
    secret = generate_secret()
    msg_id = "msg_test789"
    timestamp = int(time.time()) - 400  # older than default 300s tolerance
    body = b'{"event": "test"}'

    signature = sign(secret, msg_id, timestamp, body)
    headers = {
        "webhook-id": msg_id,
        "webhook-timestamp": str(timestamp),
        "webhook-signature": signature,
    }
    result = verify(secret, headers, body, tolerance_seconds=300)
    assert result != True, f"Expected failure for old timestamp, got {result}"

    # But should pass with larger tolerance
    result = verify(secret, headers, body, tolerance_seconds=500)
    assert result is True, f"Expected success with larger tolerance, got {result}"


# HOOK-04
def test_multiple_signatures_one_matches():
    store = InMemoryStore()
    secret1 = generate_secret()
    secret2 = generate_secret()
    msg_id = "msg_test_multi"
    timestamp = int(time.time())
    body = b'{"event": "test"}'

    sig1 = sign(secret1, msg_id, timestamp, body)
    sig2 = sign(secret2, msg_id, timestamp, body)

    # Both signatures in header, space-separated
    headers = {
        "webhook-id": msg_id,
        "webhook-timestamp": str(timestamp),
        "webhook-signature": f"{sig1} {sig2}",
    }

    # Verify with secret1 should pass
    result = verify(secret1, headers, body)
    assert result is True, f"Expected True for secret1, got {result}"

    # Verify with secret2 should pass
    result = verify(secret2, headers, body)
    assert result is True, f"Expected True for secret2, got {result}"

    # Verify with wrong secret should fail
    secret3 = generate_secret()
    result = verify(secret3, headers, body)
    assert result != True, f"Expected failure for secret3, got {result}"


# HOOK-05
def test_response_codes_success_and_retry():
    """2xx marks success; 301, 400 and 500 schedule a retry.
    In: the test fixtures. Out: assertions. Why: HOOK-05. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: send_event now takes the org id.
    Touches: the in-memory store."""
    store = InMemoryStore()
    endpoint_data = create_endpoint("org1", "https://example.com/webhook", ["event.test"], store)
    endpoint_id = endpoint_data["id"]
    message_id = send_event("org1", "event.test", {"data": "test"}, store)

    delivery = store.get_pending_deliveries(time.time() + 1)[0]
    assert delivery.attempt == 0

    # 200 -> success
    def sender_200(url, headers, body):
        return (200, b"OK")

    deliver(delivery, store, sender_200)
    updated = store.get_delivery(delivery.id)
    assert updated.success is True
    assert updated.status_code == 200
    assert updated.delivered_at is not None
    assert updated.next_attempt_at is None

    # 301 -> failure, retry scheduled
    message_id2 = send_event("org1", "event.test", {"data": "test2"}, store)
    delivery2 = store.get_pending_deliveries(time.time() + 1)[0]

    def sender_301(url, headers, body):
        return (301, b"Moved")

    deliver(delivery2, store, sender_301)
    updated2 = store.get_delivery(delivery2.id)
    assert updated2.success is False
    assert updated2.status_code == 301
    assert updated2.next_attempt_at is not None
    assert updated2.next_attempt_at > time.time()

    # 400 -> failure, retry scheduled
    message_id3 = send_event("org1", "event.test", {"data": "test3"}, store)
    delivery3 = store.get_pending_deliveries(time.time() + 1)[0]

    def sender_400(url, headers, body):
        return (400, b"Bad Request")

    deliver(delivery3, store, sender_400)
    updated3 = store.get_delivery(delivery3.id)
    assert updated3.success is False
    assert updated3.status_code == 400
    assert updated3.next_attempt_at is not None

    # 500 -> failure, retry scheduled
    message_id4 = send_event("org1", "event.test", {"data": "test4"}, store)
    delivery4 = store.get_pending_deliveries(time.time() + 1)[0]

    def sender_500(url, headers, body):
        return (500, b"Server Error")

    deliver(delivery4, store, sender_500)
    updated4 = store.get_delivery(delivery4.id)
    assert updated4.success is False
    assert updated4.status_code == 500
    assert updated4.next_attempt_at is not None


# HOOK-07
def test_webhook_id_same_across_retries():
    """The webhook-id header the receiver sees is the same on every retry.
    In: the test fixtures. Out: assertions. Why: HOOK-07 (header now recorded). Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: send_event now takes the org id.
    Touches: the in-memory store."""
    store = InMemoryStore()
    endpoint_data = create_endpoint("org1", "https://example.com/webhook", ["event.test"], store)
    endpoint_id = endpoint_data["id"]
    message_id = send_event("org1", "event.test", {"data": "test"}, store)

    delivery = store.get_pending_deliveries(time.time() + 1)[0]
    original_msg_id = delivery.message_id

    # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] The sender now records the webhook-id header it receives,
    # so HOOK-07 checks the header the receiver sees, not only the stored message_id.
    seen_ids = []

    def sender_fail(url, headers, body):
        seen_ids.append(headers["webhook-id"])
        return (500, b"Error")

    # First attempt
    deliver(delivery, store, sender_fail)
    updated = store.get_delivery(delivery.id)
    assert updated.message_id == original_msg_id
    assert updated.attempt == 0

    # Simulate retry by creating next attempt delivery manually (as the system would)
    # The deliver function doesn't create the next delivery; that's a separate process
    # But we can verify the message_id stays the same by checking the delivery record
    next_delivery = store.create_delivery(message_id, endpoint_id, 1)
    deliver(next_delivery, store, sender_fail)
    updated2 = store.get_delivery(next_delivery.id)
    assert updated2.message_id == original_msg_id

    # Third attempt
    next_delivery2 = store.create_delivery(message_id, endpoint_id, 2)
    deliver(next_delivery2, store, sender_fail)
    updated3 = store.get_delivery(next_delivery2.id)
    assert updated3.message_id == original_msg_id
    assert seen_ids == [message_id, message_id, message_id]


# HOOK-06
def test_event_for_org_a_creates_no_delivery_for_org_b():
    """An event sent for org A creates deliveries only for org A's endpoints, in both stores.

    In: org A and org B each with an active endpoint subscribed to "invoice.paid" (and an org A endpoint on
    another type). Out: asserts exactly one delivery, to org A's subscribed endpoint, and none to org B's.
    Why: HOOK-06 (spec amended 2026-09-26: send_event takes org_id); the Python send_event had no org_id and
    fanned out to every tenant. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory and
    in-memory SQLite stores only, no network.
    """
    for store in (InMemoryStore(), SqliteStore(sqlite3.connect(":memory:"))):
        ep_a = create_endpoint("org_a", "https://a.example.com/hook", ["invoice.paid"], store)["id"]
        create_endpoint("org_a", "https://a.example.com/other", ["invoice_paid"], store)
        ep_b = create_endpoint("org_b", "https://b.example.com/hook", ["invoice.paid"], store)["id"]
        message_id = send_event("org_a", "invoice.paid", {"amount": 10}, store)
        pending = store.get_pending_deliveries(time.time() + 1)
        assert [(d.message_id, d.endpoint_id) for d in pending] == [(message_id, ep_a)]
        assert all(d.endpoint_id != ep_b for d in pending)
        assert store.get_message(message_id).org_id == "org_a"


# HOOK-08
def test_generated_secret_format():
    secret = generate_secret()
    assert secret.startswith("whsec_"), f"Secret doesn't start with whsec_: {secret}"

    encoded_part = secret[6:]
    decoded = base64.b64decode(encoded_part)
    assert 24 <= len(decoded) <= 64, f"Decoded secret length {len(decoded)} not in 24-64 range"

    # Also test decode_secret works
    key = decode_secret(secret)
    assert key == decoded


def test_endpoint_disabled_after_5_failures():
    """Five failed deliveries disable the endpoint.
    In: the test fixtures. Out: assertions. Why: spec retry rule. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: send_event now takes the org id.
    Touches: the in-memory store."""
    store = InMemoryStore()
    endpoint_data = create_endpoint("org1", "https://example.com/webhook", ["event.test"], store)
    endpoint_id = endpoint_data["id"]

    def sender_fail(url, headers, body):
        return (500, b"Error")

    for i in range(5):
        message_id = send_event("org1", "event.test", {"data": f"test{i}"}, store)
        delivery = store.get_pending_deliveries(time.time() + 1)[0]
        deliver(delivery, store, sender_fail)

    endpoint = store.get_endpoint(endpoint_id)
    assert endpoint.active is False, "Endpoint should be disabled after 5 failures"
    assert endpoint.failure_count == 5


def test_sqlite_store_persistence():
    """The SQLite store round-trips a delivery and its signature verifies.
    In: the test fixtures. Out: assertions. Why: spec schema. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: send_event now takes the org id.
    Touches: the in-memory store."""
    conn = sqlite3.connect(":memory:")
    store = SqliteStore(conn)

    endpoint_data = create_endpoint("org1", "https://example.com/webhook", ["event.test"], store)
    endpoint_id = endpoint_data["id"]
    secret = endpoint_data["secret"]

    message_id = send_event("org1", "event.test", {"data": "test"}, store)

    delivery = store.get_pending_deliveries(time.time() + 1)[0]
    assert delivery.message_id == message_id
    assert delivery.endpoint_id == endpoint_id
    assert delivery.attempt == 0

    def sender_ok(url, headers, body):
        return (200, b"OK")

    deliver(delivery, store, sender_ok)
    updated = store.get_delivery(delivery.id)
    assert updated.success is True

    # Verify secret works
    msg = store.get_message(message_id)
    timestamp = int(time.time())
    body = json.dumps(msg.payload, separators=(",", ":")).encode("utf-8")
    sig = sign(secret, message_id, timestamp, body)
    headers = {
        "webhook-id": message_id,
        "webhook-timestamp": str(timestamp),
        "webhook-signature": sig,
    }
    result = verify(secret, headers, body)
    assert result is True


def test_rotate_secret():
    store = InMemoryStore()
    endpoint_data = create_endpoint("org1", "https://example.com/webhook", ["event.test"], store)
    endpoint_id = endpoint_data["id"]
    old_secret = endpoint_data["secret"]

    new_secret = rotate_secret(endpoint_id, store)
    assert new_secret != old_secret
    assert new_secret.startswith("whsec_")

    endpoint = store.get_endpoint(endpoint_id)
    assert endpoint.secret == new_secret

    # Old secret should no longer work
    msg_id = "msg_rotate_test"
    timestamp = int(time.time())
    body = b'{"test": "rotate"}'
    sig_old = sign(old_secret, msg_id, timestamp, body)
    headers = {
        "webhook-id": msg_id,
        "webhook-timestamp": str(timestamp),
        "webhook-signature": sig_old,
    }
    result = verify(new_secret, headers, body)
    assert result != True

    # New secret should work
    sig_new = sign(new_secret, msg_id, timestamp, body)
    headers["webhook-signature"] = sig_new
    result = verify(new_secret, headers, body)
    assert result is True


def test_sender_exception_handled():
    """A sender that raises is a failed attempt with a retry, not an error.
    In: the test fixtures. Out: assertions. Why: spec deliver rule. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: send_event now takes the org id.
    Touches: the in-memory store."""
    store = InMemoryStore()
    endpoint_data = create_endpoint("org1", "https://example.com/webhook", ["event.test"], store)
    message_id = send_event("org1", "event.test", {"data": "test"}, store)
    delivery = store.get_pending_deliveries(time.time() + 1)[0]

    def sender_raises(url, headers, body):
        raise ConnectionError("network down")

    deliver(delivery, store, sender_raises)
    updated = store.get_delivery(delivery.id)
    assert updated.success is False
    assert updated.status_code == 0
    assert "network down" in updated.error
    assert updated.next_attempt_at is not None


if __name__ == "__main__":
    tests = [
        test_sign_verify_roundtrip,
        test_changed_body_or_timestamp_fails,
        test_old_timestamp_rejected,
        test_multiple_signatures_one_matches,
        test_response_codes_success_and_retry,
        test_webhook_id_same_across_retries,
        test_generated_secret_format,
        test_endpoint_disabled_after_5_failures,
        test_sqlite_store_persistence,
        test_rotate_secret,
        test_sender_exception_handled,
    ]

    failed = 0
    for test in tests:
        try:
            test()
            print(f"PASS: {test.__name__}")
        except Exception as e:
            print(f"FAIL: {test.__name__}: {e}")
            failed += 1

    if failed:
        print(f"\n{failed} test(s) failed")
        exit(1)
    else:
        print(f"\nAll {len(tests)} tests passed")
        exit(0)
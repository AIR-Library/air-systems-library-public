"""Tests for stripe_webhook_entitlements_python (docs/specs/stripe_webhook_entitlements.md), with the spec's vectors.

Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
Touches: an in-memory SQLite database per test; the Stripe client is a fake (no network, files or money).
"""
import hashlib
import json

from stripe_webhook_entitlements_python import (
    EntitlementService,
    SqliteEntitlementStore,
    sign_payload,
    verify_signature,
)

SECRET = "whsec_" + "test_secret_for_vectors"
NOW = 1700000000
BODY = (b'{"id":"evt_test_0001","type":"customer.subscription.updated","created":1700000000,'
        b'"data":{"object":{"id":"sub_test_0001","customer":"cus_test_0001","status":"active",'
        b'"current_period_end":1702592000,"cancel_at_period_end":false,'
        b'"metadata":{"user_id":"user_1"},"items":{"data":[{"price":{"id":"price_pro_monthly"}}]}}}}')
HEADER = "t=1700000000,v1=5bca2d8b83d83f9a52f3b25714245817b15ae87b9e73abcca2c7a514977a8ae5"
NONE_ANSWER = {"entitled": False, "plan": None, "status": "none", "current_period_end": None,
               "cancel_at_period_end": False}
PLANS = {"price_pro_monthly": "pro", "price_team_monthly": "team"}


class Clock:
    """A settable clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""

    def __init__(self, now: int):
        """Start at now. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.now = now

    def __call__(self) -> int:
        """The current time. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        return self.now


class FakeStripe:
    """retrieve_subscription from a dict of subscription objects; raises while `fail` is set. Records calls.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing (no network)."""

    def __init__(self):
        """Empty. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.subs = {}
        self.calls = []
        self.fail = False

    def retrieve_subscription(self, sub_id):
        """Return the stored object or raise. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.calls.append(sub_id)
        if self.fail:
            raise RuntimeError("stripe unavailable")
        return self.subs[sub_id]


def make(now=NOW, secret=SECRET, plans=None, users=("user_1", "user_2"), store=None, grace=0, client=None):
    """A service on a fresh store (or the given one). Out: (service, clock, client, store).
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: a new in-memory SQLite database."""
    store = store or SqliteEntitlementStore()
    clock = Clock(now)
    client = client or FakeStripe()
    svc = EntitlementService(store, secret, PLANS if plans is None else plans, client, lambda u: u in users,
                             clock=clock, period_grace_seconds=grace)
    return svc, clock, client, store


def sub(sub_id="sub_a", status="active", price="price_pro_monthly", period_end=NOW + 86400, user="user_1",
        customer="cus_1", cancel=False, items_extra=None):
    """A subscription object. user None leaves metadata out; price None leaves the items out.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    o = {"id": sub_id, "customer": customer, "status": status, "cancel_at_period_end": cancel}
    if period_end is not None:
        o["current_period_end"] = period_end
    if user is not None:
        o["metadata"] = {"user_id": user}
    if price is not None:
        item = {"price": {"id": price}}
        item.update(items_extra or {})
        o["items"] = {"data": [item]}
    return o


def body(evt_id, etype, created, obj):
    """A compact event body. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return json.dumps({"id": evt_id, "type": etype, "created": created, "data": {"object": obj}},
                      separators=(",", ":")).encode("utf-8")


def send(svc, clock, evt_id, etype, created, obj):
    """Sign a body at the clock's time and deliver it. Out: the answer. 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the service's store."""
    b = body(evt_id, etype, created, obj)
    return svc.handle_webhook(b, sign_payload(b, SECRET, clock.now))


def deliver_raw(svc, clock, raw):
    """Sign raw bytes and deliver them. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    return svc.handle_webhook(raw, sign_payload(raw, SECRET, clock.now))


def ok(result):
    """The 200 answer for a result. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    return {"status": 200, "received": True, "result": result}


def counts(store):
    """(events, subscriptions) row counts. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    c = store.conn
    return (c.execute("SELECT COUNT(*) FROM stripe_events").fetchone()[0],
            c.execute("SELECT COUNT(*) FROM entitlement_subscriptions").fetchone()[0])


# STRIPEWH-01
def test_stripewh_01_spec_vector():
    """sign_payload gives the spec's header; handle_webhook at now = 1700000000 is 200 applied; get_entitlement is
    the spec's answer. STRIPEWH-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    assert len(BODY) == 317
    assert hashlib.sha256(BODY).hexdigest() == "f2e8a2d52e46e4642dde0390c9def15047ff2178a8d33a9928698aca132cbe88"
    assert sign_payload(BODY, SECRET, 1700000000) == HEADER
    svc, _, _, _ = make(plans={"price_pro_monthly": "pro"}, users=("user_1",))
    assert svc.handle_webhook(BODY, HEADER) == ok("applied")
    assert svc.get_entitlement("user_1") == {"entitled": True, "plan": "pro", "status": "active",
                                             "current_period_end": 1702592000, "cancel_at_period_end": False}


# STRIPEWH-02
def test_stripewh_02_bad_signatures():
    """400 invalid_signature with nothing stored: another secret, a changed body byte, a changed t, no v1, a v1 not
    64 lower-case hex, only v0, two t. STRIPEWH-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    svc, _, _, store = make()
    v1 = HEADER.split("v1=")[1]
    changed = bytearray(BODY)
    changed[10] ^= 0x01
    headers = [
        (BODY, sign_payload(BODY, "whsec_" + "another_secret_value", NOW)),
        (bytes(changed), HEADER),
        (BODY, "t=1700000001,v1=" + v1),
        (BODY, "t=1700000000"),
        (BODY, "t=1700000000,v1=" + v1.upper()),
        (BODY, "t=1700000000,v1=" + v1[:63]),
        (BODY, "t=1700000000,v1=" + v1 + "0"),
        (BODY, "t=1700000000,v0=" + v1),
        (BODY, "t=1700000000,t=1700000000,v1=" + v1),
        (BODY, "t=17000000a0,v1=" + v1),
        (BODY, "t=1700000000,v1=" + v1 + "," + "x" * 4100),
    ]
    for raw, h in headers:
        assert svc.handle_webhook(raw, h) == {"error": "invalid_signature", "status": 400}, h[:40]
    assert counts(store) == (0, 0)


# STRIPEWH-03
def test_stripewh_03_missing_header_and_unconfigured_secret():
    """A missing or empty header is 400 missing_signature; a secret under 16 bytes is 503 webhook_not_configured
    for every call, whatever its signature. STRIPEWH-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    svc, _, _, store = make()
    assert svc.handle_webhook(BODY, None) == {"error": "missing_signature", "status": 400}
    assert svc.handle_webhook(BODY, "") == {"error": "missing_signature", "status": 400}
    short = "whsec_" + "short"
    bad, _, _, store2 = make(secret=short)
    for h in (sign_payload(BODY, short, NOW), HEADER, None, "", "garbage"):
        assert bad.handle_webhook(BODY, h) == {"error": "webhook_not_configured", "status": 503}
    assert verify_signature(BODY, HEADER, "", NOW) == {"error": "webhook_not_configured", "status": 503}
    assert counts(store) == (0, 0) and counts(store2) == (0, 0)


# STRIPEWH-04
def test_stripewh_04_tolerance():
    """300 s old accepted, 301 s old refused, 300 s ahead accepted, 301 s ahead refused (fresh store each time).
    STRIPEWH-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    for now, want in ((1700000300, ok("applied")),
                      (1700000301, {"error": "timestamp_out_of_tolerance", "status": 400}),
                      (1699999700, ok("applied")),
                      (1699999699, {"error": "timestamp_out_of_tolerance", "status": 400})):
        svc, _, _, store = make(now=now)
        assert svc.handle_webhook(BODY, HEADER) == want, now


# STRIPEWH-05
def test_stripewh_05_several_v1_values():
    """Two v1 values, the second right, with a v0 element and spaces after the commas, is accepted.
    STRIPEWH-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, _, _, _ = make()
    v1 = HEADER.split("v1=")[1]
    h = "t=1700000000, v1=" + "0" * 64 + ", v0=" + "1" * 64 + ", v1=" + v1
    assert verify_signature(BODY, h, SECRET, NOW) == {"ok": True, "timestamp": 1700000000}
    assert svc.handle_webhook(BODY, h) == ok("applied")


# STRIPEWH-06
def test_stripewh_06_invalid_payloads():
    """Signed bodies that are not JSON, not an object, lack an evt_ id, a type, a whole created or data.object are
    400 invalid_payload and not recorded; created true, "1700000000", 1700000000.5, -1, 100000000000 are refused;
    1700000000.0 is accepted. STRIPEWH-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    svc, clock, _, store = make()
    obj = sub()
    good = {"id": "evt_x", "type": "customer.subscription.created", "created": NOW, "data": {"object": obj}}

    def variant(**changes):
        """The good event with fields changed (KeyError removes one), as JSON bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        d = dict(good)
        for k, v in changes.items():
            if v is KeyError:
                d.pop(k)
            else:
                d[k] = v
        return json.dumps(d).encode("utf-8")

    raws = [b"not json", b"[1,2,3]", b'"text"', b"\xef\xbb\xbf" + variant(), b"\xff\xfe",
            variant(id="foo_1"), variant(id=KeyError), variant(type=KeyError), variant(type=""),
            variant(created=KeyError), variant(data={}), variant(data={"object": []}), variant(data=KeyError),
            variant(created=True), variant(created="1700000000"), variant(created=1700000000.5),
            variant(created=-1), variant(created=100000000000), b'{"id":"evt_x","type":"t","created":NaN,"data":{"object":{}}}',
            b'{"id":"evt_x","type":"t","created":1e400,"data":{"object":{}}}', b"[" * 100000 + b"]" * 100000]
    for raw in raws:
        assert deliver_raw(svc, clock, raw) == {"error": "invalid_payload", "status": 400}, raw[:60]
    assert counts(store) == (0, 0)
    assert deliver_raw(svc, clock, variant(created=1700000000.0)) == ok("applied")
    assert deliver_raw(svc, clock, variant(id="evt_y", created=1.7e9 + 1)) == ok("applied")


# STRIPEWH-07
def test_stripewh_07_created_grants_access():
    """customer.subscription.created (active, known price, metadata.user_id) gives the entitled answer; before it
    the "none" answer; another user's answer is unchanged. STRIPEWH-07. 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, clock, _, _ = make()
    assert svc.get_entitlement("user_1") == NONE_ANSWER
    assert svc.get_entitlement("user_2") == NONE_ANSWER
    r = send(svc, clock, "evt_1", "customer.subscription.created", 100, sub(period_end=NOW + 500, cancel=True))
    assert r == ok("applied")
    assert svc.get_entitlement("user_1") == {"entitled": True, "plan": "pro", "status": "active",
                                             "current_period_end": NOW + 500, "cancel_at_period_end": True}
    assert svc.get_entitlement("user_2") == NONE_ANSWER


# STRIPEWH-08
def test_stripewh_08_duplicate_event():
    """The same event id twice: the second is 200 duplicate and the row is unchanged. STRIPEWH-08.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, clock, _, store = make()
    assert send(svc, clock, "evt_1", "customer.subscription.created", 100, sub()) == ok("applied")
    before = store.get_subscription("sub_a")
    clock.now += 10
    assert send(svc, clock, "evt_1", "customer.subscription.created", 100, sub(status="canceled")) == ok("duplicate")
    assert store.get_subscription("sub_a") == before
    assert store.event_ids() == [("evt_1", "applied")]


# STRIPEWH-09
def test_stripewh_09_ordering():
    """An older event is stale; at an equal created a created-type event does not overwrite an updated one and a
    deleted one overwrites both; a second updated event at the same created fetches the subscription and the row
    ends with the fetched state. STRIPEWH-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    svc, clock, client, store = make()
    assert send(svc, clock, "evt_1", "customer.subscription.updated", 200, sub(period_end=NOW + 100)) == ok("applied")
    before = store.get_subscription("sub_a")
    assert send(svc, clock, "evt_2", "customer.subscription.updated", 100, sub(status="past_due")) == ok("stale")
    assert send(svc, clock, "evt_3", "customer.subscription.created", 200, sub(status="incomplete")) == ok("stale")
    assert store.get_subscription("sub_a") == before
    assert client.calls == []
    client.subs["sub_a"] = sub(status="past_due", period_end=NOW + 999, cancel=True)
    assert send(svc, clock, "evt_4", "customer.subscription.updated", 200, sub(status="active")) == ok("applied")
    assert client.calls == ["sub_a"]
    row = store.get_subscription("sub_a")
    assert (row["status"], row["current_period_end"], row["cancel_at_period_end"]) == ("past_due", NOW + 999, True)
    assert send(svc, clock, "evt_5", "customer.subscription.deleted", 200, sub(status="active")) == ok("applied")
    assert store.get_subscription("sub_a")["status"] == "canceled"
    assert client.calls == ["sub_a"]
    assert send(svc, clock, "evt_6", "customer.subscription.updated", 200, sub()) == ok("stale")
    assert send(svc, clock, "evt_7", "customer.subscription.created", 200, sub()) == ok("stale")
    assert store.get_subscription("sub_a")["status"] == "canceled"


# STRIPEWH-10
def test_stripewh_10_when_access_ends():
    """past_due, unpaid and canceled end access at once; an active row ends when current_period_end <= now (equal:
    not entitled, one second later: entitled); grace 60 lasts 60 seconds longer. STRIPEWH-10.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    for i, status in enumerate(("past_due", "unpaid", "canceled")):
        svc, clock, _, _ = make()
        send(svc, clock, "evt_a%d" % i, "customer.subscription.created", 100, sub())
        assert svc.get_entitlement("user_1")["entitled"] is True
        send(svc, clock, "evt_b%d" % i, "customer.subscription.updated", 101, sub(status=status))
        assert svc.get_entitlement("user_1") == {"entitled": False, "plan": None, "status": status,
                                                 "current_period_end": NOW + 86400, "cancel_at_period_end": False}
    svc, clock, _, store = make()
    send(svc, clock, "evt_1", "customer.subscription.created", 100, sub(sub_id="sub_eq", period_end=NOW))
    assert svc.get_entitlement("user_1")["entitled"] is False
    send(svc, clock, "evt_2", "customer.subscription.created", 100, sub(sub_id="sub_eq2", user="user_2",
                                                                        customer="cus_2", period_end=NOW + 1))
    assert svc.get_entitlement("user_2")["entitled"] is True
    clock.now = NOW + 1
    assert svc.get_entitlement("user_2")["entitled"] is False
    graced, gclock, _, _ = make(store=store, grace=60)
    gclock.now = NOW + 59
    assert graced.get_entitlement("user_1")["entitled"] is True
    gclock.now = NOW + 60
    assert graced.get_entitlement("user_1")["entitled"] is False


# STRIPEWH-11
def test_stripewh_11_period_end_sources():
    """The period end is the top-level current_period_end, else the largest items[].current_period_end; an event
    with neither keeps the stored value. STRIPEWH-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    svc, clock, _, store = make()
    o = sub(period_end=None)
    o["items"]["data"] = [{"price": {"id": "price_pro_monthly"}, "current_period_end": NOW + 100},
                          {"price": {"id": "price_pro_monthly"}, "current_period_end": NOW + 300},
                          {"price": {"id": "price_pro_monthly"}, "current_period_end": "NOW"}]
    assert send(svc, clock, "evt_1", "customer.subscription.created", 100, o) == ok("applied")
    assert store.get_subscription("sub_a")["current_period_end"] == NOW + 300
    top = sub(period_end=NOW + 700, items_extra={"current_period_end": NOW + 900})
    assert send(svc, clock, "evt_2", "customer.subscription.updated", 101, top) == ok("applied")
    assert store.get_subscription("sub_a")["current_period_end"] == NOW + 700
    assert send(svc, clock, "evt_3", "customer.subscription.updated", 102, sub(period_end=None)) == ok("applied")
    assert store.get_subscription("sub_a")["current_period_end"] == NOW + 700
    new = sub(sub_id="sub_new", period_end=None)
    assert send(svc, clock, "evt_4", "customer.subscription.created", 103, new) == ok("applied")
    assert store.get_subscription("sub_new")["current_period_end"] == 0


# STRIPEWH-12
def test_stripewh_12_ignored_events():
    """200 ignored, no change and the event id recorded, for an unknown price on a new subscription, an unknown
    user, an unhandled type and a malformed id; a deleted event for a stored subscription whose price left
    price_plans is applied; an update to an unknown price is applied and ends the entitlement. STRIPEWH-12.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, clock, _, store = make()
    assert send(svc, clock, "evt_1", "customer.subscription.created", 100, sub(price="price_unknown")) == ok("ignored")
    assert send(svc, clock, "evt_2", "customer.subscription.created", 100,
                sub(user="ghost", customer="cus_ghost")) == ok("ignored")
    assert send(svc, clock, "evt_3", "invoice.paid", 100, {"id": "in_1"}) == ok("ignored")
    assert send(svc, clock, "evt_4", "customer.subscription.created", 100, sub(sub_id="sub-bad!")) == ok("ignored")
    assert send(svc, clock, "evt_5", "customer.subscription.created", 100, sub(status="Active")) == ok("ignored")
    assert counts(store) == (5, 0)
    assert store.event_ids() == [("evt_%d" % i, "ignored") for i in range(1, 6)]
    assert svc.get_entitlement("user_1") == NONE_ANSWER and svc.get_entitlement("ghost") == NONE_ANSWER
    assert send(svc, clock, "evt_6", "customer.subscription.created", 100, sub()) == ok("applied")
    retired, _, _, _ = make(store=store, plans={"price_team_monthly": "team"})
    assert send(retired, clock, "evt_7", "customer.subscription.deleted", 101, sub()) == ok("applied")
    row = store.get_subscription("sub_a")
    assert (row["status"], row["plan"], row["price_id"]) == ("canceled", "pro", "price_pro_monthly")
    assert send(svc, clock, "evt_8", "customer.subscription.created", 100, sub(sub_id="sub_b")) == ok("applied")
    assert svc.get_entitlement("user_1")["entitled"] is True
    assert send(svc, clock, "evt_9", "customer.subscription.updated", 101,
                sub(sub_id="sub_b", price="price_legacy")) == ok("applied")
    row = store.get_subscription("sub_b")
    assert (row["price_id"], row["plan"], row["status"]) == ("price_legacy", None, "active")
    assert svc.get_entitlement("user_1")["entitled"] is False


# STRIPEWH-13
def test_stripewh_13_checkout_session_completed():
    """checkout.session.completed fetches the subscription by the session's id, the user is client_reference_id;
    a raising client is 500 processing_failed, the id is not recorded, and the redelivery is applied.
    STRIPEWH-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, clock, client, store = make()
    client.subs["sub_co"] = sub(sub_id="sub_co", user=None, customer="cus_9")
    session = {"id": "cs_1", "mode": "subscription", "subscription": "sub_co", "client_reference_id": "user_2"}
    client.fail = True
    assert send(svc, clock, "evt_co", "checkout.session.completed", 100, session) == {
        "error": "processing_failed", "status": 500}
    assert counts(store) == (0, 0)
    client.fail = False
    assert send(svc, clock, "evt_co", "checkout.session.completed", 100, session) == ok("applied")
    assert client.calls == ["sub_co", "sub_co"]
    assert store.get_subscription("sub_co")["user_id"] == "user_2"
    assert svc.get_entitlement("user_2")["entitled"] is True
    assert store.event_ids() == [("evt_co", "applied")]
    payment = {"id": "cs_2", "mode": "payment", "subscription": None, "client_reference_id": "user_1"}
    assert send(svc, clock, "evt_pay", "checkout.session.completed", 100, payment) == ok("ignored")
    assert client.calls == ["sub_co", "sub_co"]


# STRIPEWH-14
def test_stripewh_14_users_and_subscriptions():
    """One user with two subscriptions keeps the other's entitlement when one ends; an event without metadata
    finds its user through the stored subscription or the customer id; an event naming another user never moves a
    subscription. STRIPEWH-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite."""
    svc, clock, _, store = make()
    send(svc, clock, "evt_1", "customer.subscription.created", 100, sub(sub_id="sub_a", period_end=NOW + 500))
    send(svc, clock, "evt_2", "customer.subscription.created", 100,
         sub(sub_id="sub_b", price="price_team_monthly", period_end=NOW + 900))
    assert svc.get_entitlement("user_1")["plan"] == "team"
    send(svc, clock, "evt_3", "customer.subscription.deleted", 101, sub(sub_id="sub_b", user=None))
    assert svc.get_entitlement("user_1") == {"entitled": True, "plan": "pro", "status": "active",
                                             "current_period_end": NOW + 500, "cancel_at_period_end": False}
    assert store.get_subscription("sub_b")["user_id"] == "user_1"
    assert send(svc, clock, "evt_4", "customer.subscription.created", 102,
                sub(sub_id="sub_c", user=None, customer="cus_1")) == ok("applied")
    assert store.get_subscription("sub_c")["user_id"] == "user_1"
    assert send(svc, clock, "evt_5", "customer.subscription.updated", 103, sub(sub_id="sub_a", user="user_2",
                                                                                customer="cus_2")) == ok("applied")
    assert store.get_subscription("sub_a")["user_id"] == "user_1"
    assert svc.get_entitlement("user_2") == NONE_ANSWER
    assert send(svc, clock, "evt_6", "customer.subscription.created", 104,
                sub(sub_id="sub_d", user=None, customer="cus_unknown")) == ok("ignored")

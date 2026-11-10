//! Stripe webhook entitlements tests (docs/specs/stripe_webhook_entitlements.md, STRIPEWH-01..14), with an
//! injected clock, a fake Stripe client that records its calls (no network) and a fixed set of known users.
//! Secrets are built from pieces at run time.
//! Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: memory only.
use super::*;
use serde_json::json;
use sha2::Digest;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

const NOW: i64 = 1700000000;

/// What: the spec's signing secret, from two pieces. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn secret() -> String {
    ["whsec_", "test_secret_for_vectors"].concat()
}

/// What: the spec's 317-byte body. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn body() -> String {
    [
        r#"{"id":"evt_test_0001","type":"customer.subscription.updated","created":1700000000,"#,
        r#""data":{"object":{"id":"sub_test_0001","customer":"cus_test_0001","status":"active","#,
        r#""current_period_end":1702592000,"cancel_at_period_end":false,"#,
        r#""metadata":{"user_id":"user_1"},"items":{"data":[{"price":{"id":"price_pro_monthly"}}]}}}}"#,
    ]
    .concat()
}

/// What: the test harness. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
struct H {
    store: Arc<InMemoryStore>,
    now: Arc<AtomicI64>,
    remote: Arc<Mutex<HashMap<String, Value>>>,
    fail: Arc<AtomicBool>,
    calls: Arc<Mutex<Vec<String>>>,
    sys: WebhookEntitlements,
}

/// What: price_plans for the tests. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn plans() -> HashMap<String, String> {
    [("price_pro_monthly", "pro"), ("price_team_monthly", "team")].iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
}

/// What: a harness over a store (new when None) with the given secret, plans and grace.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
fn harness_with(store: Option<Arc<InMemoryStore>>, secret_text: &str, price_plans: HashMap<String, String>, grace: i64) -> H {
    let store = store.unwrap_or_default();
    let now = Arc::new(AtomicI64::new(NOW));
    let remote: Arc<Mutex<HashMap<String, Value>>> = Arc::new(Mutex::new(HashMap::new()));
    let fail = Arc::new(AtomicBool::new(false));
    let calls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let (c, r, f, cl) = (now.clone(), remote.clone(), fail.clone(), calls.clone());
    let sys = WebhookEntitlements::new(
        secret_text,
        price_plans,
        Arc::new(move |id: &str| {
            cl.lock().unwrap().push(id.to_string());
            if f.load(Ordering::SeqCst) {
                return Err("connection reset".into());
            }
            r.lock().unwrap().get(id).cloned().ok_or_else(|| "no such subscription".to_string())
        }),
        Arc::new(|u: &str| ["user_1", "user_2", "user_3"].contains(&u)),
        grace,
        store.clone(),
        Arc::new(move || c.load(Ordering::SeqCst)),
    );
    H { store, now, remote, fail, calls, sys }
}

/// What: the default harness. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
fn harness() -> H {
    harness_with(None, &secret(), plans(), 0)
}

/// What: a subscription object. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn sub(id: &str, user: Option<&str>, status: &str, price: Option<&str>, period_end: Option<i64>) -> Value {
    let mut o = json!({"id": id, "customer": "cus_1", "status": status, "cancel_at_period_end": false,
                       "items": {"data": [{"price": {"id": price}}]}});
    if price.is_none() {
        o["items"] = json!({"data": []});
    }
    if let Some(u) = user {
        o["metadata"] = json!({"user_id": u});
    }
    if let Some(p) = period_end {
        o["current_period_end"] = json!(p);
    }
    o
}

/// What: an event body. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn event(id: &str, ty: &str, created: i64, object: Value) -> String {
    json!({"id": id, "type": ty, "created": created, "data": {"object": object}}).to_string()
}

/// What: harness helpers. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
impl H {
    /// What: sign a body at the clock's time and deliver it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: memory.
    fn deliver(&self, body: &str) -> Result<Received, Refusal> {
        let t = self.now.load(Ordering::SeqCst);
        self.sys.handle_webhook(body.as_bytes(), Some(&sign_payload(body.as_bytes(), &secret(), t)))
    }
    /// What: deliver and return the result text. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn result(&self, body: &str) -> String {
        let r = self.deliver(body).unwrap();
        assert_eq!((r.status, r.received), (200, true));
        r.result
    }
    /// What: set the clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn at(&self, t: i64) {
        self.now.store(t, Ordering::SeqCst);
    }
    /// What: a copy of the tables. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn tables(&self) -> Tables {
        self.store.tables.lock().unwrap().clone()
    }
}

/// What: the "none" answer. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn none() -> Entitlement {
    Entitlement { entitled: false, plan: None, status: "none".into(), current_period_end: None, cancel_at_period_end: false }
}

/// What: STRIPEWH-01, the spec's vector: header, applied, entitlement. Why: STRIPEWH-01.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// STRIPEWH-01
#[test]
fn test_stripewh_01_known_answer() {
    let b = body();
    assert_eq!(b.len(), 317);
    let digest: String = sha2::Sha256::digest(b.as_bytes()).iter().map(|x| format!("{:02x}", x)).collect();
    assert_eq!(digest, "f2e8a2d52e46e4642dde0390c9def15047ff2178a8d33a9928698aca132cbe88");
    let header = sign_payload(b.as_bytes(), &secret(), 1700000000);
    assert_eq!(header, "t=1700000000,v1=5bca2d8b83d83f9a52f3b25714245817b15ae87b9e73abcca2c7a514977a8ae5");
    let h = harness();
    assert_eq!(h.sys.handle_webhook(b.as_bytes(), Some(&header)).unwrap(), Received { status: 200, received: true, result: "applied".into() });
    assert_eq!(
        h.sys.get_entitlement("user_1"),
        Entitlement { entitled: true, plan: Some("pro".into()), status: "active".into(), current_period_end: Some(1702592000), cancel_at_period_end: false }
    );
    assert_eq!(h.store.get_event("evt_test_0001").unwrap().result.as_deref(), Some("applied"));
}

/// What: STRIPEWH-02, every bad signature is 400 invalid_signature with nothing stored. Why: STRIPEWH-02.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// STRIPEWH-02
#[test]
fn test_stripewh_02_invalid_signatures() {
    let h = harness();
    let b = body();
    let good = sign_payload(b.as_bytes(), &secret(), NOW);
    let v1 = good.split("v1=").nth(1).unwrap().to_string();
    let mut changed = b.clone().into_bytes();
    changed[10] ^= 0x01;
    let cases: Vec<(Vec<u8>, String)> = vec![
        (b.clone().into_bytes(), sign_payload(b.as_bytes(), &["whsec_", "another_secret_value"].concat(), NOW)),
        (changed, good.clone()),
        (b.clone().into_bytes(), format!("t={},v1={}", NOW + 1, v1)),
        (b.clone().into_bytes(), format!("t={}", NOW)),
        (b.clone().into_bytes(), format!("t={},v1={}", NOW, v1.to_uppercase())),
        (b.clone().into_bytes(), format!("t={},v1={}", NOW, &v1[..63])),
        (b.clone().into_bytes(), format!("t={},v0={}", NOW, v1)),
        (b.clone().into_bytes(), format!("t={},t={},v1={}", NOW, NOW, v1)),
    ];
    for (payload, header) in cases {
        assert_eq!(h.sys.handle_webhook(&payload, Some(&header)).unwrap_err(), refuse("invalid_signature", 400), "{}", header);
    }
    assert_eq!(h.tables(), Tables::default());
}

/// What: STRIPEWH-03, a missing or empty header, and a short secret for every call.
/// Why: STRIPEWH-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// STRIPEWH-03
#[test]
fn test_stripewh_03_missing_signature_and_unconfigured() {
    let h = harness();
    let b = body();
    assert_eq!(h.sys.handle_webhook(b.as_bytes(), None).unwrap_err(), refuse("missing_signature", 400));
    assert_eq!(h.sys.handle_webhook(b.as_bytes(), Some("")).unwrap_err(), refuse("missing_signature", 400));
    let short = ["whsec_", "short"].concat();
    let h2 = harness_with(None, &short, plans(), 0);
    let unconfigured = refuse("webhook_not_configured", 503);
    assert_eq!(h2.sys.handle_webhook(b.as_bytes(), Some(&sign_payload(b.as_bytes(), &short, NOW))).unwrap_err(), unconfigured);
    assert_eq!(h2.sys.handle_webhook(b.as_bytes(), None).unwrap_err(), unconfigured);
    assert_eq!(h2.sys.handle_webhook(b"junk", Some("t=1,v1=00")).unwrap_err(), unconfigured);
    assert_eq!(h2.tables(), Tables::default());
}

/// What: STRIPEWH-04, 300 seconds either way is accepted, 301 is not. Why: STRIPEWH-04.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// STRIPEWH-04
#[test]
fn test_stripewh_04_tolerance() {
    let b = body();
    let header = sign_payload(b.as_bytes(), &secret(), NOW);
    for (now, ok) in [(1700000300, true), (1700000301, false), (1699999700, true), (1699999699, false)] {
        let h = harness();
        h.at(now);
        let r = h.sys.handle_webhook(b.as_bytes(), Some(&header));
        if ok {
            assert_eq!(r.unwrap().result, "applied");
        } else {
            assert_eq!(r.unwrap_err(), refuse("timestamp_out_of_tolerance", 400));
            assert_eq!(h.tables(), Tables::default());
        }
    }
}

/// What: STRIPEWH-05, two v1 values (the second right), a v0 and spaces after the commas.
/// Why: STRIPEWH-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// STRIPEWH-05
#[test]
fn test_stripewh_05_several_v1() {
    let h = harness();
    let b = body();
    let right = sign_payload(b.as_bytes(), &secret(), NOW).split("v1=").nth(1).unwrap().to_string();
    let header = format!("t={}, v1={}, v0={}, v1={}", NOW, "0".repeat(64), right, right);
    assert_eq!(h.sys.handle_webhook(b.as_bytes(), Some(&header)).unwrap().result, "applied");
}

/// What: STRIPEWH-06, correctly signed bodies that are not valid events are 400 invalid_payload and not
/// recorded; the TIME rule for created. Why: STRIPEWH-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// STRIPEWH-06
#[test]
fn test_stripewh_06_invalid_payload() {
    let h = harness();
    let obj = sub("sub_x", Some("user_1"), "active", Some("price_pro_monthly"), Some(NOW + 1000));
    let mut bodies: Vec<String> = vec![
        "not json".into(),
        "[1,2]".into(),
        json!({"id": "xyz_1", "type": "t", "created": NOW, "data": {"object": {}}}).to_string(),
        json!({"type": "t", "created": NOW, "data": {"object": {}}}).to_string(),
        json!({"id": "evt_1", "created": NOW, "data": {"object": {}}}).to_string(),
        json!({"id": "evt_1", "type": "t", "data": {"object": {}}}).to_string(),
        json!({"id": "evt_1", "type": "t", "created": NOW, "data": {}}).to_string(),
        json!({"id": "evt_1", "type": "t", "created": NOW, "data": {"object": "x"}}).to_string(),
        ["\u{feff}", &event("evt_bom", "customer.subscription.created", NOW, obj.clone())].concat(),
    ];
    for created in ["true", "\"1700000000\"", "1700000000.5", "-1", "100000000000"] {
        bodies.push(format!(r#"{{"id":"evt_c","type":"customer.subscription.created","created":{},"data":{{"object":{}}}}}"#, created, obj));
    }
    for b in &bodies {
        assert_eq!(h.deliver(b).unwrap_err(), refuse("invalid_payload", 400), "{}", b);
    }
    assert_eq!(h.tables(), Tables::default());
    let ok = format!(r#"{{"id":"evt_c","type":"customer.subscription.created","created":1700000000.0,"data":{{"object":{}}}}}"#, obj);
    assert_eq!(h.result(&ok), "applied");
    assert_eq!(h.store.get_event("evt_c").unwrap().created, 1700000000);
}

/// What: STRIPEWH-07, a created event grants; before it the "none" answer; another user is untouched.
/// Why: STRIPEWH-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// STRIPEWH-07
#[test]
fn test_stripewh_07_created_grants() {
    let h = harness();
    assert_eq!(h.sys.get_entitlement("user_1"), none());
    let mut s = sub("sub_1", Some("user_1"), "active", Some("price_team_monthly"), Some(NOW + 5000));
    s["cancel_at_period_end"] = json!(true);
    assert_eq!(h.result(&event("evt_1", "customer.subscription.created", NOW, s)), "applied");
    assert_eq!(
        h.sys.get_entitlement("user_1"),
        Entitlement { entitled: true, plan: Some("team".into()), status: "active".into(), current_period_end: Some(NOW + 5000), cancel_at_period_end: true }
    );
    assert_eq!(h.sys.get_entitlement("user_2"), none());
}

/// What: STRIPEWH-08, the same event twice: duplicate, row unchanged. Why: STRIPEWH-08.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// STRIPEWH-08
#[test]
fn test_stripewh_08_duplicate() {
    let h = harness();
    let b = event("evt_1", "customer.subscription.created", NOW, sub("sub_1", Some("user_1"), "active", Some("price_pro_monthly"), Some(NOW + 5000)));
    assert_eq!(h.result(&b), "applied");
    let before = h.tables();
    h.at(NOW + 10);
    assert_eq!(h.result(&b), "duplicate");
    assert_eq!(h.tables(), before);
}

/// What: STRIPEWH-09, ordering: an older event is stale; created < updated < deleted at an equal second; a
/// same-second updated tie fetches the subscription and ends with Stripe's state, price and plan included.
/// Why: STRIPEWH-09 and ruling fed6e7b. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// STRIPEWH-09
#[test]
fn test_stripewh_09_order() {
    let h = harness();
    let up = |id: &str, created: i64, status: &str| event(id, "customer.subscription.updated", created, sub("sub_1", Some("user_1"), status, Some("price_pro_monthly"), Some(NOW + 5000)));
    assert_eq!(h.result(&up("evt_1", 1700000200, "active")), "applied");
    let before = h.store.get_sub("sub_1").unwrap();
    assert_eq!(h.result(&up("evt_2", 1700000100, "past_due")), "stale");
    assert_eq!(h.store.get_sub("sub_1").unwrap(), before);
    let created_same = event("evt_3", "customer.subscription.created", 1700000200, sub("sub_1", Some("user_1"), "incomplete", Some("price_pro_monthly"), Some(NOW + 5000)));
    assert_eq!(h.result(&created_same), "stale");
    assert_eq!(h.store.get_sub("sub_1").unwrap(), before);
    assert!(h.calls.lock().unwrap().is_empty());
    let deleted_same = event("evt_4", "customer.subscription.deleted", 1700000200, sub("sub_1", Some("user_1"), "active", Some("price_pro_monthly"), Some(NOW + 5000)));
    assert_eq!(h.result(&deleted_same), "applied");
    assert_eq!(h.store.get_sub("sub_1").unwrap().status, "canceled");

    // a tie between two updated events of one second: ask Stripe
    assert_eq!(h.result(&event("evt_5", "customer.subscription.updated", 1700000300, sub("sub_2", Some("user_2"), "active", Some("price_pro_monthly"), Some(NOW + 5000)))), "applied");
    h.remote.lock().unwrap().insert("sub_2".into(), sub("sub_2", None, "unpaid", Some("price_team_monthly"), Some(NOW + 9000)));
    assert_eq!(h.result(&event("evt_6", "customer.subscription.updated", 1700000300, sub("sub_2", Some("user_2"), "past_due", Some("price_pro_monthly"), Some(NOW + 5000)))), "applied");
    assert_eq!(*h.calls.lock().unwrap(), vec!["sub_2".to_string()]);
    let r = h.store.get_sub("sub_2").unwrap();
    assert_eq!((r.status.as_str(), r.price_id.as_deref(), r.plan.as_deref(), r.current_period_end), ("unpaid", Some("price_team_monthly"), Some("team"), NOW + 9000));
}

/// What: STRIPEWH-10, when entitlement ends: past_due, unpaid, canceled at once; the period end (equal to now
/// ends it) and the grace period. Why: STRIPEWH-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// STRIPEWH-10
#[test]
fn test_stripewh_10_entitlement_ends() {
    let h = harness();
    let mut n = 0;
    let mut send = |h: &H, ty: &str, status: &str, end: i64| {
        n += 1;
        h.result(&event(&format!("evt_{}", n), ty, NOW + n, sub("sub_1", Some("user_1"), status, Some("price_pro_monthly"), Some(end))))
    };
    send(&h, "customer.subscription.created", "active", NOW + 5000);
    assert!(h.sys.get_entitlement("user_1").entitled);
    for status in ["past_due", "unpaid"] {
        send(&h, "customer.subscription.updated", status, NOW + 5000);
        let e = h.sys.get_entitlement("user_1");
        assert_eq!((e.entitled, e.plan, e.status.as_str()), (false, None, status));
        send(&h, "customer.subscription.updated", "active", NOW + 5000);
        assert!(h.sys.get_entitlement("user_1").entitled);
    }
    send(&h, "customer.subscription.deleted", "active", NOW + 5000);
    assert_eq!(h.sys.get_entitlement("user_1").status, "canceled");
    assert!(!h.sys.get_entitlement("user_1").entitled);

    let h = harness();
    h.result(&event("evt_a", "customer.subscription.created", NOW, sub("sub_a", Some("user_1"), "active", Some("price_pro_monthly"), Some(NOW + 100))));
    h.at(NOW + 99);
    assert!(h.sys.get_entitlement("user_1").entitled);
    h.at(NOW + 100);
    assert!(!h.sys.get_entitlement("user_1").entitled);
    let g = harness_with(Some(h.store.clone()), &secret(), plans(), 60);
    g.at(NOW + 159);
    assert!(g.sys.get_entitlement("user_1").entitled);
    g.at(NOW + 160);
    assert!(!g.sys.get_entitlement("user_1").entitled);
}

/// What: STRIPEWH-11, the period end from the top level, else the largest item's, else the stored value.
/// Why: STRIPEWH-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// STRIPEWH-11
#[test]
fn test_stripewh_11_period_end() {
    let h = harness();
    let mut s = sub("sub_1", Some("user_1"), "active", Some("price_pro_monthly"), None);
    s["items"] = json!({"data": [
        {"price": {"id": "price_pro_monthly"}, "current_period_end": NOW + 1000},
        {"price": {"id": "price_pro_monthly"}, "current_period_end": NOW + 3000},
        {"price": {"id": "price_pro_monthly"}, "current_period_end": NOW + 2000}]});
    h.result(&event("evt_1", "customer.subscription.created", NOW, s));
    assert_eq!(h.store.get_sub("sub_1").unwrap().current_period_end, NOW + 3000);
    let mut top = sub("sub_1", Some("user_1"), "active", Some("price_pro_monthly"), Some(NOW + 500));
    top["items"]["data"][0]["current_period_end"] = json!(NOW + 9999);
    h.result(&event("evt_2", "customer.subscription.updated", NOW + 1, top));
    assert_eq!(h.store.get_sub("sub_1").unwrap().current_period_end, NOW + 500);
    h.result(&event("evt_3", "customer.subscription.updated", NOW + 2, sub("sub_1", Some("user_1"), "active", Some("price_pro_monthly"), None)));
    assert_eq!(h.store.get_sub("sub_1").unwrap().current_period_end, NOW + 500);
}

/// What: STRIPEWH-12, ignored events change nothing but are recorded; a stored subscription still gets its
/// deleted event and its move to an unknown price. Why: STRIPEWH-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory.
// STRIPEWH-12
#[test]
fn test_stripewh_12_ignored() {
    let h = harness();
    let cases = [
        event("evt_i1", "customer.subscription.created", NOW, sub("sub_1", Some("user_1"), "active", Some("price_unknown"), Some(NOW + 5000))),
        event("evt_i2", "customer.subscription.created", NOW, sub("sub_2", Some("ghost"), "active", Some("price_pro_monthly"), Some(NOW + 5000))),
        event("evt_i3", "invoice.paid", NOW, json!({"id": "in_1"})),
        event("evt_i4", "customer.subscription.created", NOW, sub("subX_1", Some("user_1"), "active", Some("price_pro_monthly"), Some(NOW + 5000))),
    ];
    for b in &cases {
        assert_eq!(h.result(b), "ignored");
    }
    let t = h.tables();
    assert!(t.subs.is_empty());
    for id in ["evt_i1", "evt_i2", "evt_i3", "evt_i4"] {
        assert_eq!(t.events[id].result.as_deref(), Some("ignored"));
    }
    assert_eq!(h.sys.get_entitlement("user_1"), none());
    // stored subscriptions: a price that left price_plans, and a move to an unknown price
    h.result(&event("evt_a", "customer.subscription.created", NOW, sub("sub_a", Some("user_1"), "active", Some("price_pro_monthly"), Some(NOW + 5000))));
    h.result(&event("evt_b", "customer.subscription.created", NOW, sub("sub_b", Some("user_2"), "active", Some("price_pro_monthly"), Some(NOW + 5000))));
    let fewer: HashMap<String, String> = [("price_team_monthly".to_string(), "team".to_string())].into_iter().collect();
    let h2 = harness_with(Some(h.store.clone()), &secret(), fewer, 0);
    assert_eq!(h2.result(&event("evt_c", "customer.subscription.deleted", NOW + 1, sub("sub_a", Some("user_1"), "active", Some("price_pro_monthly"), Some(NOW + 5000)))), "applied");
    assert_eq!(h.store.get_sub("sub_a").unwrap().status, "canceled");
    assert!(h.sys.get_entitlement("user_2").entitled);
    assert_eq!(h.result(&event("evt_d", "customer.subscription.updated", NOW + 1, sub("sub_b", Some("user_2"), "active", Some("price_gone"), Some(NOW + 5000)))), "applied");
    let r = h.store.get_sub("sub_b").unwrap();
    assert_eq!((r.price_id.as_deref(), r.plan.clone()), (Some("price_gone"), None));
    assert!(!h.sys.get_entitlement("user_2").entitled);
}

/// What: STRIPEWH-13, checkout.session.completed fetches the subscription and uses client_reference_id; a
/// client error is 500 with the event not recorded, and the retry is applied.
/// Why: STRIPEWH-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// STRIPEWH-13
#[test]
fn test_stripewh_13_checkout() {
    let h = harness();
    h.remote.lock().unwrap().insert("sub_ck_1".into(), sub("sub_ck_1", None, "active", Some("price_pro_monthly"), Some(NOW + 7000)));
    let b = event("evt_ck", "checkout.session.completed", NOW, json!({"id": "cs_1", "mode": "subscription", "subscription": "sub_ck_1", "client_reference_id": "user_3"}));
    h.fail.store(true, Ordering::SeqCst);
    assert_eq!(h.deliver(&b).unwrap_err(), refuse("processing_failed", 500));
    assert!(h.store.get_event("evt_ck").is_none());
    assert_eq!(h.tables(), Tables::default());
    h.fail.store(false, Ordering::SeqCst);
    assert_eq!(h.result(&b), "applied");
    assert_eq!(*h.calls.lock().unwrap(), vec!["sub_ck_1".to_string(), "sub_ck_1".to_string()]);
    let e = h.sys.get_entitlement("user_3");
    assert_eq!((e.entitled, e.plan.as_deref(), e.current_period_end), (true, Some("pro"), Some(NOW + 7000)));
    let pay = event("evt_pay", "checkout.session.completed", NOW, json!({"id": "cs_2", "mode": "payment", "client_reference_id": "user_2"}));
    assert_eq!(h.result(&pay), "ignored");
}

/// What: STRIPEWH-14, two subscriptions for one user; finding the user without metadata; another user never
/// takes a subscription. Why: STRIPEWH-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// STRIPEWH-14
#[test]
fn test_stripewh_14_users_and_subscriptions() {
    let h = harness();
    h.result(&event("evt_1", "customer.subscription.created", NOW, sub("sub_a", Some("user_1"), "active", Some("price_team_monthly"), Some(NOW + 9000))));
    h.result(&event("evt_2", "customer.subscription.created", NOW, sub("sub_b", Some("user_1"), "active", Some("price_pro_monthly"), Some(NOW + 5000))));
    assert_eq!(h.sys.get_entitlement("user_1").plan.as_deref(), Some("team"));
    h.result(&event("evt_3", "customer.subscription.deleted", NOW + 1, sub("sub_a", None, "active", Some("price_team_monthly"), Some(NOW + 9000))));
    let e = h.sys.get_entitlement("user_1");
    assert_eq!((e.entitled, e.plan.as_deref(), e.current_period_end), (true, Some("pro"), Some(NOW + 5000)));
    // no metadata: the stored row, or the customer id of stored rows
    assert_eq!(h.result(&event("evt_4", "customer.subscription.updated", NOW + 2, sub("sub_b", None, "trialing", Some("price_pro_monthly"), Some(NOW + 5000)))), "applied");
    assert_eq!(h.store.get_sub("sub_b").unwrap().status, "trialing");
    assert_eq!(h.result(&event("evt_5", "customer.subscription.created", NOW + 2, sub("sub_c", None, "active", Some("price_pro_monthly"), Some(NOW + 6000)))), "applied");
    assert_eq!(h.store.get_sub("sub_c").unwrap().user_id, "user_1");
    // naming another user never moves a subscription
    assert_eq!(h.result(&event("evt_6", "customer.subscription.updated", NOW + 3, sub("sub_b", Some("user_2"), "active", Some("price_pro_monthly"), Some(NOW + 5000)))), "applied");
    assert_eq!(h.store.get_sub("sub_b").unwrap().user_id, "user_1");
    assert_eq!(h.sys.get_entitlement("user_2"), none());
}

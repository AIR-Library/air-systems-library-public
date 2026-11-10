//! Stripe webhook entitlements: verified Stripe events become one answer per user, "what are they entitled to now".
//!
//! What: verify_signature checks the Stripe-Signature header (t=..., v1=HMAC-SHA256 hex, every candidate
//! compared in constant time, 300 s tolerance) BEFORE the body is parsed; handle_webhook then validates the
//! event, claims its id, and applies it exactly once and in order (created, then rank created < updated <
//! deleted; a same-second tie asks Stripe through the injected client and re-applies rule b to what it
//! returns). Claim and apply are one transaction: any error rolls both back and answers 500, so Stripe's
//! retry is applied. get_entitlement decides from the clock at every call.
//! Why: Phase D wave 1, owner request 2026-11-10 (docs/specs/stripe_webhook_entitlements.md, STRIPEWH-01..14;
//! rule d re-applies rule b per the lead's ruling, spec commit fed6e7b).
//! 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: the injected store (memory in `InMemoryStore`), the injected Stripe client (the network in
//! production; a fake in tests) and clock. It decides paid access (money) but moves none. Never logs the
//! secret, the signature header or the payload.

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

pub const TOLERANCE: i64 = 300;
const MAX_TIME: f64 = 99_999_999_999.0;

/// The injected clock: whole seconds since the Unix epoch.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;
/// The injected client: retrieve_subscription(id) -> the subscription object, or Err (raised).
pub type StripeClient = Arc<dyn Fn(&str) -> Result<Value, String> + Send + Sync>;
/// The application's account lookup.
pub type UserExists = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// What: a refusal {error, status}. Why: spec CONVENTIONS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub error: String,
    pub status: u16,
}

/// What: build a refusal. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn refuse(error: &str, status: u16) -> Refusal {
    Refusal { error: error.to_string(), status }
}

/// What: handle_webhook's answer {status: 200, received: true, result}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    pub status: u16,
    pub received: bool,
    pub result: String,
}

/// What: get_entitlement's answer; `status` is the subscription's status ("none" without a row).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entitlement {
    pub entitled: bool,
    pub plan: Option<String>,
    pub status: String,
    pub current_period_end: Option<i64>,
    pub cancel_at_period_end: bool,
}

/// What: a row of stripe_events. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRow {
    pub event_id: String,
    pub event_type: String,
    pub created: i64,
    pub received_at: i64,
    pub result: Option<String>,
}

/// What: a row of entitlement_subscriptions. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubRow {
    pub stripe_subscription_id: String,
    pub user_id: String,
    pub stripe_customer_id: Option<String>,
    pub price_id: Option<String>,
    pub plan: Option<String>,
    pub status: String,
    pub current_period_end: i64,
    pub cancel_at_period_end: bool,
    pub event_at: i64,
    pub event_rank: i64,
    pub updated_at: i64,
}

/// What: what one transaction may do. Why: spec steps 7-9 (one transaction).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: whatever the implementation uses.
pub trait Tx {
    /// What: CLAIM: insert the event row; false when the id is already there (an insert that fails on the key).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn claim_event(&mut self, row: EventRow) -> bool;
    /// What: store the result in the event's row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn set_result(&mut self, event_id: &str, result: &str);
    /// What: the stored row for a subscription id. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn get_sub(&self, id: &str) -> Option<SubRow>;
    /// What: the stored rows with this customer id. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn subs_by_customer(&self, customer: &str) -> Vec<SubRow>;
    /// What: insert or replace a row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn put_sub(&mut self, row: SubRow);
}

/// What: the store: a transaction that commits on Ok and rolls back on Err, plus reads.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: whatever the implementation uses.
pub trait Store: Send + Sync {
    /// What: run f in one transaction; Ok commits every change, Err undoes all of them.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn transaction(&self, f: &mut dyn FnMut(&mut dyn Tx) -> Result<String, String>) -> Result<String, String>;
    /// What: the user's rows. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn subs_for_user(&self, user_id: &str) -> Vec<SubRow>;
    /// What: an event row by id. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn get_event(&self, event_id: &str) -> Option<EventRow>;
    /// What: a subscription row by id. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn get_sub(&self, id: &str) -> Option<SubRow>;
}

/// What: the in-memory tables; they are the `Tx` of a transaction. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tables {
    pub events: BTreeMap<String, EventRow>,
    pub subs: BTreeMap<String, SubRow>,
}

/// What: `Tx` for the tables; each method is documented on the trait. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory.
impl Tx for Tables {
    fn claim_event(&mut self, row: EventRow) -> bool {
        if self.events.contains_key(&row.event_id) {
            return false;
        }
        self.events.insert(row.event_id.clone(), row);
        true
    }
    fn set_result(&mut self, event_id: &str, result: &str) {
        if let Some(e) = self.events.get_mut(event_id) {
            e.result = Some(result.to_string());
        }
    }
    fn get_sub(&self, id: &str) -> Option<SubRow> {
        self.subs.get(id).cloned()
    }
    fn subs_by_customer(&self, customer: &str) -> Vec<SubRow> {
        self.subs.values().filter(|r| r.stripe_customer_id.as_deref() == Some(customer)).cloned().collect()
    }
    fn put_sub(&mut self, row: SubRow) {
        self.subs.insert(row.stripe_subscription_id.clone(), row);
    }
}

/// What: an in-memory store; a transaction works on a copy under the lock and keeps it only on Ok.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
#[derive(Default)]
pub struct InMemoryStore {
    pub tables: Mutex<Tables>,
}

/// What: `Store` for `InMemoryStore`; each method is documented on the trait. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory.
impl Store for InMemoryStore {
    fn transaction(&self, f: &mut dyn FnMut(&mut dyn Tx) -> Result<String, String>) -> Result<String, String> {
        let mut guard = self.tables.lock().unwrap();
        let mut work = guard.clone();
        let r = f(&mut work);
        if r.is_ok() {
            *guard = work;
        }
        r
    }
    fn subs_for_user(&self, user_id: &str) -> Vec<SubRow> {
        self.tables.lock().unwrap().subs.values().filter(|r| r.user_id == user_id).cloned().collect()
    }
    fn get_event(&self, event_id: &str) -> Option<EventRow> {
        self.tables.lock().unwrap().events.get(event_id).cloned()
    }
    fn get_sub(&self, id: &str) -> Option<SubRow> {
        self.tables.lock().unwrap().subs.get(id).cloned()
    }
}

/// What: lower-case hex HMAC-SHA256 of message under key. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn hmac_hex(key: &[u8], message: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    mac.update(message);
    mac.finalize().into_bytes().iter().map(|b| format!("{:02x}", b)).collect()
}

/// What: sign_payload(payload, secret, timestamp) = "t=" + timestamp + ",v1=" + hex HMAC-SHA256(the whole secret
/// text, timestamp + "." + payload). Why: spec sign_payload, STRIPEWH-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: nothing.
pub fn sign_payload(payload: &[u8], secret: &str, timestamp: i64) -> String {
    let mut msg = format!("{}.", timestamp).into_bytes();
    msg.extend_from_slice(payload);
    format!("t={},v1={}", timestamp, hmac_hex(secret.as_bytes(), &msg))
}

/// What: verify_signature(payload, header, secret, now): steps 1-5 of the spec. Out: the timestamp, or
/// 503 webhook_not_configured, 400 missing_signature, 400 invalid_signature, 400 timestamp_out_of_tolerance.
/// Why: spec verify_signature, STRIPEWH-02..05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn verify_signature(payload: &[u8], header: Option<&str>, secret: &str, now: i64) -> Result<i64, Refusal> {
    if secret.len() < 16 {
        return Err(refuse("webhook_not_configured", 503));
    }
    let header = match header {
        Some(h) if !h.is_empty() => h,
        _ => return Err(refuse("missing_signature", 400)),
    };
    let bad = || refuse("invalid_signature", 400);
    if header.len() > 4096 {
        return Err(bad());
    }
    let mut ts: Vec<&str> = Vec::new();
    let mut candidates: Vec<&str> = Vec::new();
    for element in header.split(',') {
        let element = element.trim_matches(' ');
        let (name, value) = match element.split_once('=') {
            Some(x) => x,
            None => continue,
        };
        if name == "t" {
            ts.push(value);
        } else if name == "v1" && value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            candidates.push(value);
        }
    }
    if ts.len() != 1 || ts[0].is_empty() || ts[0].len() > 12 || !ts[0].bytes().all(|b| b.is_ascii_digit()) || candidates.is_empty() {
        return Err(bad());
    }
    let t_text = ts[0];
    let mut msg = format!("{}.", t_text).into_bytes();
    msg.extend_from_slice(payload);
    let expected = hmac_hex(secret.as_bytes(), &msg);
    let mut any = 0u8;
    for c in &candidates {
        let diff = expected.bytes().zip(c.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y));
        any |= (diff == 0) as u8;
    }
    if any == 0 {
        return Err(bad());
    }
    let t: i64 = t_text.parse().map_err(|_| bad())?;
    if (now - t).abs() > TOLERANCE {
        return Err(refuse("timestamp_out_of_tolerance", 400));
    }
    Ok(t)
}

/// What: TIME: a JSON number (never a bool, text or null) whose value is a whole number 0..=99999999999.
/// Why: spec step 6 (the one number rule). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn as_time(v: &Value) -> Option<i64> {
    let n = v.as_number()?;
    if let Some(u) = n.as_u64() {
        return if u as f64 <= MAX_TIME { Some(u as i64) } else { None };
    }
    if n.as_i64().is_some() {
        return None; // a negative whole number
    }
    let f = n.as_f64()?;
    if f.is_finite() && f == f.floor() && (0.0..=MAX_TIME).contains(&f) { Some(f as i64) } else { None }
}

/// What: true when s is prefix + 1-200 characters of [A-Za-z0-9_] (the whole text).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn id_with_prefix(s: &str, prefix: &str) -> bool {
    match s.strip_prefix(prefix) {
        Some(rest) => !rest.is_empty() && rest.len() <= 200 && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        None => false,
    }
}

/// What: a value as a non-empty text. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn text(v: &Value) -> Option<String> {
    v.as_str().filter(|s| !s.is_empty()).map(|s| s.to_string())
}

/// What: the parsed fields of a valid event. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
struct Event {
    id: String,
    event_type: String,
    created: i64,
    object: Value,
}

/// What: the system. Why: spec CONFIGURATION. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: the store, the Stripe client.
pub struct WebhookEntitlements {
    webhook_secret: String,
    price_plans: HashMap<String, String>,
    client: StripeClient,
    user_exists: UserExists,
    period_grace_seconds: i64,
    store: Arc<dyn Store>,
    clock: Clock,
}

/// What: the flows of the spec. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the Stripe client.
impl WebhookEntitlements {
    /// What: construct. In: secret, price_plans, Stripe client, user_exists, period_grace_seconds, store, clock.
    /// A secret under 16 bytes is accepted here and answered 503 webhook_not_configured at every call (spec step 1).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn new(
        webhook_secret: &str,
        price_plans: HashMap<String, String>,
        client: StripeClient,
        user_exists: UserExists,
        period_grace_seconds: i64,
        store: Arc<dyn Store>,
        clock: Clock,
    ) -> Self {
        WebhookEntitlements { webhook_secret: webhook_secret.to_string(), price_plans, client, user_exists, period_grace_seconds, store, clock }
    }

    /// What: step 6: parse and validate the event (UTF-8, no byte-order mark, an object with an evt_ id, a type,
    /// a TIME created and an object data.object). Out: the event, or 400 invalid_payload.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn parse(payload: &[u8]) -> Result<Event, Refusal> {
        let bad = || refuse("invalid_payload", 400);
        if payload.starts_with(&[0xEF, 0xBB, 0xBF]) {
            return Err(bad());
        }
        let s = std::str::from_utf8(payload).map_err(|_| bad())?;
        let v: Value = serde_json::from_str(s).map_err(|_| bad())?;
        let o = v.as_object().ok_or_else(bad)?;
        let id = o.get("id").and_then(|x| x.as_str()).filter(|x| id_with_prefix(x, "evt_")).ok_or_else(bad)?;
        let ty = o
            .get("type")
            .and_then(|x| x.as_str())
            .filter(|t| (1..=100).contains(&t.chars().count()) && t.chars().all(|c| (' '..='~').contains(&c)))
            .ok_or_else(bad)?;
        let created = o.get("created").and_then(as_time).ok_or_else(bad)?;
        let object = o.get("data").and_then(|d| d.get("object")).filter(|x| x.is_object()).ok_or_else(bad)?;
        Ok(Event { id: id.to_string(), event_type: ty.to_string(), created, object: object.clone() })
    }

    /// What: handle_webhook(payload, header): verify, parse, claim, apply, all in the spec's order; claim and
    /// apply in one transaction. Out: {200, received, result}, or the refusal (400/503, or 500 processing_failed
    /// with nothing recorded). Why: spec handle_webhook, STRIPEWH-01..14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: the store, the Stripe client.
    pub fn handle_webhook(&self, payload: &[u8], header: Option<&str>) -> Result<Received, Refusal> {
        let now = (self.clock)();
        verify_signature(payload, header, &self.webhook_secret, now)?;
        let ev = Self::parse(payload)?;
        let outcome = self.store.transaction(&mut |tx: &mut dyn Tx| {
            let claimed = tx.claim_event(EventRow { event_id: ev.id.clone(), event_type: ev.event_type.clone(), created: ev.created, received_at: now, result: None });
            if !claimed {
                return Ok("duplicate".to_string());
            }
            let result = self.apply(tx, &ev, now)?;
            tx.set_result(&ev.id, &result);
            Ok(result)
        });
        match outcome {
            Ok(result) => Ok(Received { status: 200, received: true, result }),
            Err(_) => Err(refuse("processing_failed", 500)),
        }
    }

    /// What: APPLY(event) by type. Out: the result text, or Err (the Stripe client raised).
    /// Why: spec APPLY. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the transaction, the Stripe client.
    fn apply(&self, tx: &mut dyn Tx, ev: &Event, now: i64) -> Result<String, String> {
        let obj = &ev.object;
        let meta_user = || text(&obj["metadata"]["user_id"]);
        match ev.event_type.as_str() {
            "customer.subscription.created" => self.subscription(tx, obj.clone(), meta_user(), 0, ev.created, now, false),
            "customer.subscription.updated" => self.subscription(tx, obj.clone(), meta_user(), 1, ev.created, now, false),
            "customer.subscription.deleted" => self.subscription(tx, obj.clone(), meta_user(), 2, ev.created, now, false),
            "checkout.session.completed" => {
                let sub_id = match obj["subscription"].as_str() {
                    Some(s) if obj["mode"].as_str() == Some("subscription") && id_with_prefix(s, "sub_") => s.to_string(),
                    _ => return Ok("ignored".into()),
                };
                if let Some(row) = tx.get_sub(&sub_id) {
                    if (row.event_at, row.event_rank) > (ev.created, 1) {
                        return Ok("stale".into());
                    }
                }
                let sub = (self.client)(&sub_id)?;
                let hint = text(&obj["client_reference_id"]).or_else(meta_user);
                self.subscription(tx, sub, hint, 1, ev.created, now, true)
            }
            _ => Ok("ignored".into()),
        }
    }

    /// What: rule b's price and plan for a subscription object: (price_id, plan), or None when there is no row
    /// and the price is missing or unknown ("ignored"). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn price_and_plan(&self, sub: &Value, row: Option<&SubRow>) -> Option<(Option<String>, Option<String>)> {
        let price = sub["items"]["data"][0]["price"]["id"].as_str().map(|s| s.to_string());
        let known = price.as_ref().and_then(|p| self.price_plans.get(p)).cloned();
        match row {
            None => known.map(|plan| (price, Some(plan))),
            Some(r) => Some(match (&price, known) {
                (Some(_), Some(plan)) => (price.clone(), Some(plan)),
                (None, _) => (r.price_id.clone(), r.plan.clone()),
                (Some(p), None) if Some(p) == r.price_id.as_ref() => (r.price_id.clone(), r.plan.clone()),
                (Some(_), None) => (price.clone(), None),
            }),
        }
    }

    /// What: SUBSCRIPTION(sub, hint, rank) rules a-g; `fetched` is true when the object was just fetched
    /// (checkout), so a tie does not fetch again. After a tie fetch, rule b runs again on the fetched object
    /// (ruling fed6e7b). Out: "applied" | "stale" | "ignored", or Err (the Stripe client raised).
    /// Why: spec SUBSCRIPTION. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the transaction, the Stripe client.
    #[allow(clippy::too_many_arguments)]
    fn subscription(&self, tx: &mut dyn Tx, mut sub: Value, hint: Option<String>, rank: i64, event_at: i64, now: i64, fetched: bool) -> Result<String, String> {
        let id = match sub["id"].as_str() {
            Some(s) if id_with_prefix(s, "sub_") => s.to_string(),
            _ => return Ok("ignored".into()),
        };
        let row = tx.get_sub(&id);
        let (mut price_id, mut plan) = match self.price_and_plan(&sub, row.as_ref()) {
            Some(x) => x,
            None => return Ok("ignored".into()),
        };
        let user = match &row {
            Some(r) => r.user_id.clone(),
            None => {
                let by_hint = hint.filter(|h| (self.user_exists)(h));
                match by_hint {
                    Some(u) => u,
                    None => {
                        let owners: Vec<String> = sub["customer"].as_str().map(|c| tx.subs_by_customer(c)).unwrap_or_default().into_iter().map(|r| r.user_id).collect();
                        match owners.first() {
                            Some(first) if owners.iter().all(|u| u == first) => first.clone(),
                            _ => return Ok("ignored".into()),
                        }
                    }
                }
            }
        };
        if let Some(r) = &row {
            if (event_at, rank) < (r.event_at, r.event_rank) {
                return Ok("stale".into());
            }
            if rank <= 1 && (event_at, rank) == (r.event_at, r.event_rank) && !fetched {
                sub = (self.client)(&id)?;
                let again = self.price_and_plan(&sub, Some(r)).expect("a row exists");
                price_id = again.0;
                plan = again.1;
            }
        }
        let period_end = as_time(&sub["current_period_end"])
            .or_else(|| sub["items"]["data"].as_array().and_then(|items| items.iter().filter_map(|i| as_time(&i["current_period_end"])).max()))
            .or_else(|| row.as_ref().map(|r| r.current_period_end))
            .unwrap_or(0);
        let status = if rank == 2 {
            "canceled".to_string()
        } else {
            match sub["status"].as_str() {
                Some(s) if (1..=32).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') => s.to_string(),
                _ => return Ok("ignored".into()),
            }
        };
        tx.put_sub(SubRow {
            stripe_subscription_id: id,
            user_id: user,
            stripe_customer_id: sub["customer"].as_str().map(|s| s.to_string()),
            price_id,
            plan,
            status,
            current_period_end: period_end,
            cancel_at_period_end: sub["cancel_at_period_end"].as_bool() == Some(true),
            event_at,
            event_rank: rank,
            updated_at: now,
        });
        Ok("applied".into())
    }

    /// What: get_entitlement(user_id): the best ENTITLING row (greatest period end, event_at, id), else the
    /// latest row not entitled, else the "none" answer; decided from the clock at every call.
    /// Why: spec get_entitlement, STRIPEWH-07, 10, 14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store (read).
    pub fn get_entitlement(&self, user_id: &str) -> Entitlement {
        let now = (self.clock)();
        let rows = self.store.subs_for_user(user_id);
        let entitling = |r: &SubRow| r.plan.is_some() && (r.status == "active" || r.status == "trialing") && r.current_period_end + self.period_grace_seconds > now;
        let best = rows
            .iter()
            .filter(|r| entitling(r))
            .max_by(|a, b| (a.current_period_end, a.event_at, a.stripe_subscription_id.as_bytes()).cmp(&(b.current_period_end, b.event_at, b.stripe_subscription_id.as_bytes())));
        if let Some(r) = best {
            return Entitlement { entitled: true, plan: r.plan.clone(), status: r.status.clone(), current_period_end: Some(r.current_period_end), cancel_at_period_end: r.cancel_at_period_end };
        }
        match rows.iter().max_by(|a, b| (a.event_at, a.stripe_subscription_id.as_bytes()).cmp(&(b.event_at, b.stripe_subscription_id.as_bytes()))) {
            Some(r) => Entitlement { entitled: false, plan: None, status: r.status.clone(), current_period_end: Some(r.current_period_end), cancel_at_period_end: r.cancel_at_period_end },
            None => Entitlement { entitled: false, plan: None, status: "none".into(), current_period_end: None, cancel_at_period_end: false },
        }
    }
}

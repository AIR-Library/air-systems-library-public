//! Billing and subscriptions: tiers, plan changes, a refund queue and signed payment webhooks
//! (GEMINI dispatch spec, template #4).
//!
//! What: `BillingService` creates and changes subscriptions through a `PaymentProvider` (the hosted
//! payment API in production, `FakePaymentProvider` in tests), records them in SQLite, queues refunds
//! for a human to execute (never automatically), and processes the provider's webhooks: the
//! `t=<unix>,v1=<hex HMAC-SHA256 of "t.payload">` signature is checked in constant time with a 5-minute
//! tolerance BEFORE anything in the payload is trusted, and each event id is processed once.
//! Every action is written to the audit log.
//! Why: the old file and its tests could not compile: they used a mocking crate API that does not exist
//! (`expect_query().with(query!(...))`), a "MockStripe" type no crate provides, and Postgres macros
//! that need a live database while compiling; the webhook trusted its event id and type from fields
//! outside the signed body. Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: money (through the payment provider: subscriptions are charged; refunds are only queued),
//! the SQLite database it owns, the clock. The network only through the provider the caller injects.

use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

/// Webhook timestamps older or newer than this are refused (replay protection), in seconds.
pub const WEBHOOK_TOLERANCE_SECS: i64 = 300;

/// What: billing errors with the spec's codes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BillingError {
    InvalidTier(String),
    RefundExceedsInvoice,
    InvalidAmount,
    InvoiceNotPaid,
    InvalidSignature,
    InvalidEvent(String),
    NotFound(String),
    Provider(String),
    Db(String),
}

/// What: methods of `BillingError`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl BillingError {
    /// What: the spec's `{error, message, code}` body and status. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn to_response(&self) -> (Value, u16) {
        let (code, status) = match self {
            BillingError::InvalidTier(_) => ("invalid_tier", 400),
            BillingError::RefundExceedsInvoice => ("refund_exceeds_invoice", 400),
            BillingError::InvalidAmount => ("invalid_amount", 400),
            BillingError::InvoiceNotPaid => ("invoice_not_paid", 400),
            BillingError::InvalidSignature => ("invalid_signature", 403),
            BillingError::InvalidEvent(_) => ("invalid_event", 400),
            BillingError::NotFound(_) => ("not_found", 404),
            BillingError::Provider(_) => ("payment_provider_error", 502),
            BillingError::Db(_) => ("internal_error", 500),
        };
        (json!({ "error": code, "message": self.to_string(), "code": status }), status)
    }
}

/// What: `fmt::Display` for `BillingError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl fmt::Display for BillingError {
    /// What: human-readable text of `fmt::Display for BillingError` (never secrets). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BillingError::InvalidTier(t) => write!(f, "unknown tier {:?}", t),
            BillingError::RefundExceedsInvoice => write!(f, "refund exceeds the refundable invoice amount"),
            BillingError::InvalidAmount => write!(f, "amount must be positive"),
            BillingError::InvoiceNotPaid => write!(f, "invoice has not succeeded"),
            BillingError::InvalidSignature => write!(f, "webhook signature is invalid"),
            BillingError::InvalidEvent(m) => write!(f, "webhook event is invalid: {}", m),
            BillingError::NotFound(what) => write!(f, "{} not found", what),
            BillingError::Provider(_) => write!(f, "payment provider error"),
            BillingError::Db(_) => write!(f, "internal error"),
        }
    }
}

/// What: `std::error::Error` for `BillingError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl std::error::Error for BillingError {}

/// What: `From<rusqlite::Error>` for `BillingError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl From<rusqlite::Error> for BillingError {
    /// What: convert the error of `From<rusqlite::Error> for BillingError`, keeping its message for logs. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn from(e: rusqlite::Error) -> Self {
        BillingError::Db(e.to_string())
    }
}

/// What: the three tiers and their monthly price in cents (Solo $9.99, Team $19.99, Enterprise $99).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn tier_price_cents(tier: &str) -> Option<i64> {
    match tier {
        "solo" => Some(999),
        "team" => Some(1999),
        "enterprise" => Some(9900),
        _ => None,
    }
}

/// What: a subscription as the provider reports it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderSubscription {
    pub id: String,
    pub current_period_start: i64,
    pub current_period_end: i64,
    /// Credit for the unused part of the old plan, in cents (on plan changes).
    pub proration_credit_cents: i64,
}

/// What: the hosted payment API. In: customer/subscription ids and the provider's price id.
/// Out: the subscription, or an error message. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: money and the network in a real implementation.
pub trait PaymentProvider: Send {
    /// What: `create_subscription` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn create_subscription(&self, customer_id: &str, price_id: &str) -> Result<ProviderSubscription, String>;
    /// What: `update_subscription` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn update_subscription(&self, subscription_id: &str, price_id: &str) -> Result<ProviderSubscription, String>;
}

/// What: an in-memory provider that records each call; ids come from `next_subscription_id`.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
#[derive(Clone, Default)]
pub struct FakePaymentProvider {
    pub calls: Arc<Mutex<Vec<String>>>,
    pub next_subscription_id: Arc<Mutex<Option<String>>>,
    pub proration_credit_cents: i64,
    pub fail: bool,
}

/// What: methods of `FakePaymentProvider`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl FakePaymentProvider {
    /// What: a fake whose next created subscription has this id. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    pub fn with_subscription_id(id: &str) -> Self {
        let f = Self::default();
        *f.next_subscription_id.lock().unwrap() = Some(id.to_string());
        f
    }
}

/// What: `PaymentProvider` for `FakePaymentProvider`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl PaymentProvider for FakePaymentProvider {
    /// What: `create_subscription` of `PaymentProvider for FakePaymentProvider`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn create_subscription(&self, customer_id: &str, price_id: &str) -> Result<ProviderSubscription, String> {
        self.calls.lock().map_err(|_| "lock")?.push(format!("create {} {}", customer_id, price_id));
        if self.fail {
            return Err("provider unavailable".into());
        }
        let id = self.next_subscription_id.lock().map_err(|_| "lock")?.take().unwrap_or_else(|| format!("sub_{}", random_hex(8)));
        Ok(ProviderSubscription { id, current_period_start: 1_767_225_600, current_period_end: 1_769_904_000, proration_credit_cents: 0 })
    }
    /// What: `update_subscription` of `PaymentProvider for FakePaymentProvider`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn update_subscription(&self, subscription_id: &str, price_id: &str) -> Result<ProviderSubscription, String> {
        self.calls.lock().map_err(|_| "lock")?.push(format!("update {} {}", subscription_id, price_id));
        if self.fail {
            return Err("provider unavailable".into());
        }
        Ok(ProviderSubscription { id: subscription_id.to_string(), current_period_start: 1_767_225_600, current_period_end: 1_769_904_000, proration_credit_cents: self.proration_credit_cents })
    }
}

/// What: create-subscription input. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSubscriptionRequest {
    pub customer_id: String,
    pub tier: String,
}

/// What: change-plan input. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePlanRequest {
    pub subscription_id: String,
    pub new_tier: String,
}

/// What: refund input; `created_by` is the authenticated admin. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueRefundRequest {
    pub invoice_id: String,
    pub amount: i64,
    pub reason: String,
    pub created_by: String,
}

/// What: a webhook as received: the RAW request body and the signature header. Nothing in the body is
/// trusted until the signature over it is checked. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone)]
pub struct WebhookRequest {
    pub payload: String,
    pub signature: String,
}

/// What: a subscription row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SubscriptionRecord {
    pub stripe_subscription_id: String,
    pub customer_id: String,
    pub tier: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    pub cancelled_at: Option<String>,
}

/// What: an invoice row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InvoiceRecord {
    pub stripe_invoice_id: String,
    pub customer_id: String,
    pub amount: i64,
    pub status: String,
    pub paid_at: Option<String>,
}

/// What: `n` random bytes as hex. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: OS randomness.
fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// What: time as stored. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// What: the signature header for a payload: `t=<unix>,v1=<hex HMAC-SHA256(secret, "t.payload")>`.
/// Used by senders and tests. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn sign_webhook_payload(secret: &[u8], timestamp: i64, payload: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(format!("{}.{}", timestamp, payload).as_bytes());
    let sig: String = mac.finalize().into_bytes().iter().map(|b| format!("{:02x}", b)).collect();
    format!("t={},v1={}", timestamp, sig)
}

/// What: the billing service. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: see module doc.
pub struct BillingService {
    db: Mutex<Connection>,
    provider: Box<dyn PaymentProvider>,
    webhook_secret: Vec<u8>,
    price_ids: HashMap<String, String>,
    clock: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>,
}

/// What: methods of `BillingService`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl BillingService {
    /// What: a service on a connection (tables created), a provider, the webhook signing secret (from
    /// configuration, at least 16 bytes) and the provider's price id per tier. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (DDL).
    pub fn new(conn: Connection, provider: Box<dyn PaymentProvider>, webhook_secret: &[u8], price_ids: HashMap<String, String>) -> Result<Self, BillingError> {
        if webhook_secret.len() < 16 {
            return Err(BillingError::InvalidEvent("webhook secret too short".into()));
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS subscriptions (stripe_subscription_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL,
                tier TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, cancelled_at TEXT NULL);
             CREATE TABLE IF NOT EXISTS invoices (stripe_invoice_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, amount INTEGER NOT NULL,
                status TEXT NOT NULL, paid_at TEXT NULL);
             CREATE TABLE IF NOT EXISTS refunds (id TEXT PRIMARY KEY, invoice_id TEXT NOT NULL, amount INTEGER NOT NULL,
                status TEXT NOT NULL, reason TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL, executed_at TEXT NULL);
             CREATE TABLE IF NOT EXISTS events (stripe_event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, processed_at TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, customer_id TEXT NULL,
                details TEXT NOT NULL, created_at TEXT NOT NULL);",
        )?;
        Ok(Self { db: Mutex::new(conn), provider, webhook_secret: webhook_secret.to_vec(), price_ids, clock: Box::new(Utc::now) })
    }

    /// What: replace the clock (webhook tolerance tests). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// What: the connection (for reports and tests). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn db(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What: the provider price id for a known tier. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn price_for(&self, tier: &str) -> Result<String, BillingError> {
        tier_price_cents(tier).ok_or_else(|| BillingError::InvalidTier(tier.to_string()))?;
        self.price_ids.get(tier).cloned().ok_or_else(|| BillingError::InvalidTier(tier.to_string()))
    }

    /// What: the tier a provider price stands for: its `lookup_key` when that names a known tier, else
    /// the tier whose configured price id equals the price's `id`, else `None` (the caller keeps the
    /// stored tier). In: the `price` object of a subscription item. Out: a known tier or `None`.
    /// Why: CodeRabbit review on PR 19: a price without a lookup key (or with an unknown one) made
    /// `customer.subscription.updated` fail and roll back, so past_due/canceled/trialing were never
    /// saved. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn tier_for_price(&self, price: &Value) -> Option<String> {
        if let Some(key) = price["lookup_key"].as_str() {
            if tier_price_cents(key).is_some() {
                return Some(key.to_string());
            }
        }
        let id = price["id"].as_str()?;
        self.price_ids
            .iter()
            .find(|(tier, pid)| pid.as_str() == id && tier_price_cents(tier).is_some())
            .map(|(tier, _)| tier.clone())
    }

    /// What: append an audit row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn audit(conn: &Connection, action: &str, customer_id: Option<&str>, details: Value, now: DateTime<Utc>) -> Result<(), BillingError> {
        conn.execute(
            "INSERT INTO audit_log (action, customer_id, details, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![action, customer_id, details.to_string(), ts(now)],
        )?;
        Ok(())
    }

    /// What: subscribe a customer to a tier (flow 1): provider call, then the row and audit.
    /// In: customer id (the caller's own, from the session), tier. Out: `{success, subscription_id,
    /// tier, status, next_billing_date}`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: money (provider), database.
    pub async fn create_subscription(&self, request: CreateSubscriptionRequest) -> Result<Value, BillingError> {
        let price = self.price_for(&request.tier)?;
        if request.customer_id.trim().is_empty() {
            return Err(BillingError::NotFound("customer".into()));
        }
        let sub = self.provider.create_subscription(&request.customer_id, &price).map_err(BillingError::Provider)?;
        let now = (self.clock)();
        let conn = self.db();
        conn.execute(
            "INSERT INTO subscriptions (stripe_subscription_id, customer_id, tier, status, created_at, updated_at) VALUES (?1, ?2, ?3, 'active', ?4, ?4)",
            params![sub.id, request.customer_id, request.tier, ts(now)],
        )?;
        Self::audit(&conn, "subscription_created", Some(&request.customer_id), json!({ "tier": request.tier, "subscription_id": sub.id }), now)?;
        let next = Utc.timestamp_opt(sub.current_period_end, 0).single().map(ts);
        Ok(json!({ "success": true, "subscription_id": sub.id, "tier": request.tier, "status": "active", "next_billing_date": next }))
    }

    /// What: load a subscription row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn get_subscription(&self, id: &str) -> Result<Option<SubscriptionRecord>, BillingError> {
        Ok(self
            .db()
            .query_row(
                "SELECT stripe_subscription_id, customer_id, tier, status, created_at, updated_at, cancelled_at FROM subscriptions WHERE stripe_subscription_id = ?1",
                params![id],
                |r| Ok(SubscriptionRecord { stripe_subscription_id: r.get(0)?, customer_id: r.get(1)?, tier: r.get(2)?, status: r.get(3)?, created_at: r.get(4)?, updated_at: r.get(5)?, cancelled_at: r.get(6)? }),
            )
            .optional()?)
    }

    /// What: move a live subscription to another tier (flow 2). Out: `{success, subscription_id,
    /// old_tier, new_tier, effective_date, proration_credit}` (credit in cents, from the provider).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: money (provider), database.
    pub async fn change_plan(&self, request: ChangePlanRequest) -> Result<Value, BillingError> {
        let price = self.price_for(&request.new_tier)?;
        let old = self.get_subscription(&request.subscription_id)?.ok_or_else(|| BillingError::NotFound("subscription".into()))?;
        if old.status == "cancelled" {
            return Err(BillingError::InvalidEvent("subscription is cancelled".into()));
        }
        let sub = self.provider.update_subscription(&request.subscription_id, &price).map_err(BillingError::Provider)?;
        let now = (self.clock)();
        let conn = self.db();
        conn.execute(
            "UPDATE subscriptions SET tier = ?1, updated_at = ?2 WHERE stripe_subscription_id = ?3",
            params![request.new_tier, ts(now), request.subscription_id],
        )?;
        Self::audit(&conn, "plan_changed", Some(&old.customer_id),
            json!({ "subscription_id": request.subscription_id, "old_tier": old.tier, "new_tier": request.new_tier, "proration_credits": sub.proration_credit_cents }), now)?;
        Ok(json!({ "success": true, "subscription_id": request.subscription_id, "old_tier": old.tier, "new_tier": request.new_tier,
            "effective_date": ts(now), "proration_credit": sub.proration_credit_cents }))
    }

    /// What: queue a refund for an admin to execute later (flow 3): the invoice must exist and have
    /// succeeded, and the amount must be positive and at most what is still refundable (invoice amount
    /// minus refunds already queued or executed). Out: `{success, refund_id, status: "queued", amount,
    /// reason}`. Never moves money itself. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database.
    pub async fn queue_refund(&self, request: QueueRefundRequest) -> Result<Value, BillingError> {
        if request.amount <= 0 {
            return Err(BillingError::InvalidAmount);
        }
        let now = (self.clock)();
        let mut conn = self.db();
        let tx = conn.transaction()?;
        let (amount, status, customer): (i64, String, String) = tx
            .query_row("SELECT amount, status, customer_id FROM invoices WHERE stripe_invoice_id = ?1", params![request.invoice_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .optional()?
            .ok_or_else(|| BillingError::NotFound("invoice".into()))?;
        if status != "succeeded" {
            return Err(BillingError::InvoiceNotPaid);
        }
        let refunded: i64 = tx.query_row(
            "SELECT COALESCE(SUM(amount), 0) FROM refunds WHERE invoice_id = ?1 AND status IN ('queued', 'executed')",
            params![request.invoice_id],
            |r| r.get(0),
        )?;
        if request.amount > amount - refunded {
            return Err(BillingError::RefundExceedsInvoice);
        }
        let id = format!("ref_{}", random_hex(12));
        tx.execute(
            "INSERT INTO refunds (id, invoice_id, amount, status, reason, created_by, created_at) VALUES (?1, ?2, ?3, 'queued', ?4, ?5, ?6)",
            params![id, request.invoice_id, request.amount, request.reason, request.created_by, ts(now)],
        )?;
        Self::audit(&tx, "refund_queued", Some(&customer),
            json!({ "invoice_id": request.invoice_id, "amount": request.amount, "reason": request.reason, "created_by": request.created_by }), now)?;
        tx.commit()?;
        Ok(json!({ "success": true, "refund_id": id, "status": "queued", "amount": request.amount, "reason": request.reason }))
    }

    /// What: check `t=<unix>,v1=<hex>` against the raw payload in constant time, within the tolerance.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: clock.
    fn verify_signature(&self, payload: &str, header: &str) -> Result<(), BillingError> {
        let mut timestamp: Option<i64> = None;
        let mut candidates = Vec::new();
        for part in header.split(',') {
            match part.trim().split_once('=') {
                Some(("t", v)) => timestamp = v.parse().ok(),
                Some(("v1", v)) => candidates.push(v.to_string()),
                _ => {}
            }
        }
        let t = timestamp.ok_or(BillingError::InvalidSignature)?;
        if ((self.clock)().timestamp() - t).abs() > WEBHOOK_TOLERANCE_SECS {
            return Err(BillingError::InvalidSignature);
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.webhook_secret).map_err(|_| BillingError::InvalidSignature)?;
        mac.update(format!("{}.{}", t, payload).as_bytes());
        let expected = mac.finalize().into_bytes();
        let ok = candidates.iter().any(|c| {
            let bytes: Option<Vec<u8>> = (0..c.len() / 2).map(|i| u8::from_str_radix(c.get(i * 2..i * 2 + 2)?, 16).ok()).collect();
            match bytes {
                Some(b) if b.len() == expected.len() => b.iter().zip(expected.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0,
                _ => false,
            }
        });
        if ok { Ok(()) } else { Err(BillingError::InvalidSignature) }
    }

    /// What: process one provider webhook (flow 4): verify the signature first, then parse the signed
    /// body; record its event id in `events` inside the same transaction as its effects, so an event
    /// is applied once (a duplicate returns `{received: true}` and changes nothing) and a failure
    /// leaves it unprocessed for the provider's retry. Handles invoice.payment_succeeded,
    /// invoice.payment_failed, customer.subscription.updated and customer.subscription.deleted; other
    /// types are acknowledged. For customer.subscription.updated the tier comes from `tier_for_price`
    /// (lookup key, else configured price id, else the stored tier) and the status is always saved; an
    /// unknown subscription with an unknown price is acknowledged and audited but not recorded (changed
    /// for the CodeRabbit review on PR 19, 2026-11-10). Out: `{received: true}` or `InvalidSignature`
    /// (403) / `InvalidEvent`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, clock.
    pub async fn handle_stripe_webhook(&self, request: WebhookRequest) -> Result<Value, BillingError> {
        self.verify_signature(&request.payload, &request.signature)?;
        let event: Value = serde_json::from_str(&request.payload).map_err(|_| BillingError::InvalidEvent("body is not JSON".into()))?;
        let event_id = event["id"].as_str().filter(|s| !s.is_empty()).ok_or_else(|| BillingError::InvalidEvent("missing id".into()))?;
        let event_type = event["type"].as_str().ok_or_else(|| BillingError::InvalidEvent("missing type".into()))?;
        let obj = &event["data"]["object"];
        let now = (self.clock)();
        let mut conn = self.db();
        let tx = conn.transaction()?;
        let fresh = tx.execute(
            "INSERT OR IGNORE INTO events (stripe_event_id, event_type, processed_at) VALUES (?1, ?2, ?3)",
            params![event_id, event_type, ts(now)],
        )?;
        if fresh == 0 {
            return Ok(json!({ "received": true, "duplicate": true }));
        }
        let customer = obj["customer"].as_str();
        match event_type {
            "invoice.payment_succeeded" => {
                let invoice = obj["id"].as_str().ok_or_else(|| BillingError::InvalidEvent("invoice id".into()))?;
                let amount = obj["amount_paid"].as_i64().ok_or_else(|| BillingError::InvalidEvent("amount_paid".into()))?;
                tx.execute(
                    "INSERT INTO invoices (stripe_invoice_id, customer_id, amount, status, paid_at) VALUES (?1, ?2, ?3, 'succeeded', ?4)
                     ON CONFLICT (stripe_invoice_id) DO UPDATE SET status = 'succeeded', amount = excluded.amount, paid_at = excluded.paid_at",
                    params![invoice, customer.unwrap_or(""), amount, ts(now)],
                )?;
                Self::audit(&tx, "payment_succeeded", customer, json!({ "invoice_id": invoice, "amount": amount }), now)?;
            }
            "invoice.payment_failed" => {
                let customer_id = customer.ok_or_else(|| BillingError::InvalidEvent("customer".into()))?;
                tx.execute(
                    "UPDATE subscriptions SET status = 'past_due', updated_at = ?2 WHERE customer_id = ?1 AND status = 'active'",
                    params![customer_id, ts(now)],
                )?;
                Self::audit(&tx, "payment_failed", customer, json!({ "invoice_id": obj["id"], "reason": obj["last_payment_error"]["message"] }), now)?;
            }
            "customer.subscription.updated" => {
                let sub_id = obj["id"].as_str().ok_or_else(|| BillingError::InvalidEvent("subscription id".into()))?;
                let status = obj["status"].as_str().unwrap_or("active");
                let old_tier: Option<String> = tx.query_row("SELECT tier FROM subscriptions WHERE stripe_subscription_id = ?1", params![sub_id], |r| r.get(0)).optional()?;
                let tier = match (self.tier_for_price(&obj["items"]["data"][0]["price"]), &old_tier) {
                    (Some(t), _) => t,
                    (None, Some(stored)) => stored.clone(),
                    (None, None) => {
                        // Unknown subscription on an unknown price: nothing to attach it to. Acknowledge
                        // (the event id is kept so it is not reprocessed) and leave an audit trail.
                        Self::audit(&tx, "subscription_update_ignored", customer,
                            json!({ "subscription_id": sub_id, "status": status, "reason": "unknown subscription and price" }), now)?;
                        tx.commit()?;
                        return Ok(json!({ "received": true }));
                    }
                };
                let tier = tier.as_str();
                if old_tier.is_none() {
                    tx.execute(
                        "INSERT INTO subscriptions (stripe_subscription_id, customer_id, tier, status, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                        params![sub_id, customer.unwrap_or(""), tier, status, ts(now)],
                    )?;
                } else {
                    tx.execute(
                        "UPDATE subscriptions SET tier = ?1, status = ?2, updated_at = ?3 WHERE stripe_subscription_id = ?4",
                        params![tier, status, ts(now), sub_id],
                    )?;
                }
                Self::audit(&tx, "subscription_updated", customer, json!({ "subscription_id": sub_id, "old_tier": old_tier, "new_tier": tier, "status": status }), now)?;
            }
            "customer.subscription.deleted" => {
                let sub_id = obj["id"].as_str().ok_or_else(|| BillingError::InvalidEvent("subscription id".into()))?;
                tx.execute(
                    "UPDATE subscriptions SET status = 'cancelled', cancelled_at = ?2, updated_at = ?2 WHERE stripe_subscription_id = ?1",
                    params![sub_id, ts(now)],
                )?;
                Self::audit(&tx, "subscription_cancelled", customer, json!({ "subscription_id": sub_id }), now)?;
            }
            _ => {}
        }
        tx.commit()?;
        Ok(json!({ "received": true }))
    }
}

//! Billing and subscriptions tests (GEMINI spec, template #4).
//!
//! Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the old tests could not compile. They used
//! `MockDb`/`MockStripe` types that no crate defines, an `expect_query().with(query!(...))` mocking API
//! that does not exist, and Postgres query macros that need a live database while compiling. The same
//! ten tests now run against in-memory SQLite and `FakePaymentProvider`; each old "the mock expected
//! this INSERT once" is now an assertion on the stored rows, and every response assertion is kept.
//! Webhooks carry a real signature: "valid_signature" became a header signed with the test secret,
//! "invalid_signature" a header signed with another secret, because the service now verifies the
//! signature over the raw body (it used to trust an id and type sent outside the signed body), and
//! the state each test assumed (an existing subscription or invoice) is created through the public
//! API instead of through mocks. Touches: memory only.

use super::*;
use std::time::Duration;

const SECRET: &[u8] = b"whsec_test_secret_0123456789";
const NOW: i64 = 1_767_225_600; // 2026-01-01T00:00:00Z

/// What: a service on in-memory SQLite with a fake provider and a fixed clock. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
fn service(provider: FakePaymentProvider) -> BillingService {
    let prices: HashMap<String, String> =
        [("solo", "price_solo"), ("team", "price_team"), ("enterprise", "price_enterprise")].iter().map(|(t, p)| (t.to_string(), p.to_string())).collect();
    BillingService::new(Connection::open_in_memory().unwrap(), Box::new(provider), SECRET, prices)
        .unwrap()
        .with_clock(Box::new(|| Utc.timestamp_opt(NOW, 0).unwrap()))
}

/// What: a webhook request for an event, signed with `secret`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn signed(event: &Value, secret: &[u8]) -> WebhookRequest {
    let payload = event.to_string();
    WebhookRequest { signature: sign_webhook_payload(secret, NOW, &payload), payload }
}

/// What: count rows matching a WHERE clause. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn count(svc: &BillingService, table: &str, filter: &str) -> i64 {
    svc.db().query_row(&format!("SELECT COUNT(*) FROM {} WHERE {}", table, filter), [], |r| r.get(0)).unwrap()
}

/// What: the payment_succeeded event used by several tests. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn payment_succeeded() -> Value {
    serde_json::json!({
        "id": "evt_123",
        "type": "invoice.payment_succeeded",
        "data": { "object": { "id": "inv_123", "customer": "cust_123", "amount_paid": 10000 } }
    })
}

// BILL-01
#[tokio::test]
async fn test_create_subscription_happy_path() {
    let provider = FakePaymentProvider::with_subscription_id("sub_123");
    let service = service(provider.clone());
    let request = CreateSubscriptionRequest { customer_id: "cust_123".to_string(), tier: "solo".to_string() };

    let result = service.create_subscription(request).await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response["success"], true);
    assert_eq!(response["subscription_id"], "sub_123");
    assert_eq!(response["tier"], "solo");
    assert_eq!(response["status"], "active");

    // provider called once, subscription row and audit row written once
    assert_eq!(provider.calls.lock().unwrap().as_slice(), ["create cust_123 price_solo"]);
    assert_eq!(count(&service, "subscriptions", "stripe_subscription_id = 'sub_123' AND status = 'active'"), 1);
    assert_eq!(count(&service, "audit_log", "action = 'subscription_created'"), 1);
}

// BILL-02
#[tokio::test]
async fn test_create_subscription_invalid_tier() {
    let provider = FakePaymentProvider::default();
    let service = service(provider.clone());
    let request = CreateSubscriptionRequest { customer_id: "cust_123".to_string(), tier: "invalid".to_string() };

    let result = service.create_subscription(request).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, BillingError::InvalidTier(_)));
    assert_eq!(err.to_response().0["error"], "invalid_tier");
    assert_eq!(err.to_response().1, 400);
    assert!(provider.calls.lock().unwrap().is_empty());
}

/// What: BILL-03: change_plan retrieves the subscription and updates its existing item with the new price
/// and create_prorations, leaving one item; tier stored and audited. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP for the
/// BILL-03 amendment (the provider call used to send a bare price). Touches: memory only.
// BILL-03
#[tokio::test]
async fn test_change_plan_happy_path() {
    let provider = FakePaymentProvider { proration_credit_cents: 500, ..FakePaymentProvider::with_subscription_id("sub_123") };
    let service = service(provider.clone());
    service.create_subscription(CreateSubscriptionRequest { customer_id: "cust_123".into(), tier: "solo".into() }).await.unwrap();

    let request = ChangePlanRequest { subscription_id: "sub_123".to_string(), new_tier: "team".to_string() };
    let result = service.change_plan(request).await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response["success"], true);
    assert_eq!(response["subscription_id"], "sub_123");
    assert_eq!(response["old_tier"], "solo");
    assert_eq!(response["new_tier"], "team");
    assert_eq!(response["proration_credit"], 500);

    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (BILL-03 amendment): the update names the existing
    // item id with the new price and create_prorations, and the subscription still has ONE item
    assert_eq!(
        provider.calls.lock().unwrap()[1..].to_vec(),
        ["retrieve sub_123".to_string(), "update sub_123 si_sub_123=price_team create_prorations".to_string()]
    );
    assert_eq!(provider.items.lock().unwrap()["sub_123"], vec![SubscriptionItem { id: "si_sub_123".into(), price: "price_team".into() }]);
    assert_eq!(count(&service, "subscriptions", "stripe_subscription_id = 'sub_123' AND tier = 'team'"), 1);
    assert_eq!(count(&service, "audit_log", "action = 'plan_changed'"), 1);
}

/// What: BILL-03 refusals, both before any provider update: an unknown tier is 400 invalid_tier (no
/// provider call at all); a subscription with two items (or none) is 409 subscription_item_ambiguous
/// after the retrieve, and the tier is unchanged. In: none. Out: panics on a wrong answer.
/// Why: 2026-11-10 amendment (BILL-03). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
// BILL-03
#[tokio::test]
async fn test_change_plan_refusals_before_update() {
    let provider = FakePaymentProvider::with_subscription_id("sub_123");
    let service = service(provider.clone());
    service.create_subscription(CreateSubscriptionRequest { customer_id: "cust_123".into(), tier: "solo".into() }).await.unwrap();
    provider.calls.lock().unwrap().clear();

    let err = service.change_plan(ChangePlanRequest { subscription_id: "sub_123".into(), new_tier: "platinum".into() }).await.unwrap_err();
    assert_eq!((err.to_response().0["error"].clone(), err.to_response().1), (serde_json::json!("invalid_tier"), 400));
    assert!(provider.calls.lock().unwrap().is_empty());

    for items in [2usize, 0] {
        provider.items.lock().unwrap().insert(
            "sub_123".into(),
            (0..items).map(|i| SubscriptionItem { id: format!("si_{}", i), price: "price_solo".into() }).collect(),
        );
        provider.calls.lock().unwrap().clear();
        let err = service.change_plan(ChangePlanRequest { subscription_id: "sub_123".into(), new_tier: "team".into() }).await.unwrap_err();
        assert_eq!(err, BillingError::SubscriptionItemAmbiguous);
        assert_eq!((err.to_response().0["error"].clone(), err.to_response().1), (serde_json::json!("subscription_item_ambiguous"), 409));
        assert_eq!(provider.calls.lock().unwrap().as_slice(), ["retrieve sub_123"]);
    }
    assert_eq!(count(&service, "subscriptions", "stripe_subscription_id = 'sub_123' AND tier = 'solo'"), 1);
    assert_eq!(count(&service, "audit_log", "action = 'plan_changed'"), 0);
}

// BILL-04
#[tokio::test]
async fn test_queue_refund_happy_path() {
    let service = service(FakePaymentProvider::default());
    service.handle_stripe_webhook(signed(&payment_succeeded(), SECRET)).await.unwrap();

    let request = QueueRefundRequest { invoice_id: "inv_123".to_string(), amount: 5000, reason: "duplicate".to_string(), created_by: "admin".to_string() };
    let result = service.queue_refund(request).await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response["success"], true);
    assert_eq!(response["status"], "queued");
    assert_eq!(response["amount"], 5000);

    assert_eq!(count(&service, "refunds", "invoice_id = 'inv_123' AND status = 'queued' AND executed_at IS NULL"), 1);
    assert_eq!(count(&service, "audit_log", "action = 'refund_queued'"), 1);
}

// BILL-05
#[tokio::test]
async fn test_queue_refund_amount_exceeds_invoice() {
    let service = service(FakePaymentProvider::default());
    service.handle_stripe_webhook(signed(&payment_succeeded(), SECRET)).await.unwrap();

    let request = QueueRefundRequest { invoice_id: "inv_123".to_string(), amount: 15000, reason: "duplicate".to_string(), created_by: "admin".to_string() };
    let result = service.queue_refund(request).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), BillingError::RefundExceedsInvoice));
    assert_eq!(count(&service, "refunds", "1 = 1"), 0);
}

// BILL-06
#[tokio::test]
async fn test_handle_webhook_payment_succeeded() {
    let service = service(FakePaymentProvider::default());
    let result = service.handle_stripe_webhook(signed(&payment_succeeded(), SECRET)).await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response["received"], true);

    assert_eq!(count(&service, "invoices", "stripe_invoice_id = 'inv_123' AND status = 'succeeded' AND amount = 10000"), 1);
    assert_eq!(count(&service, "audit_log", "action = 'payment_succeeded'"), 1);
    assert_eq!(count(&service, "events", "stripe_event_id = 'evt_123'"), 1);
}

// BILL-07
#[tokio::test]
async fn test_handle_webhook_duplicate_event() {
    let service = service(FakePaymentProvider::default());
    service.handle_stripe_webhook(signed(&payment_succeeded(), SECRET)).await.unwrap();

    let result = service.handle_stripe_webhook(signed(&payment_succeeded(), SECRET)).await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response["received"], true);

    // processed once only
    assert_eq!(count(&service, "invoices", "1 = 1"), 1);
    assert_eq!(count(&service, "audit_log", "action = 'payment_succeeded'"), 1);
    assert_eq!(count(&service, "events", "1 = 1"), 1);
}

// BILL-08
#[tokio::test]
async fn test_handle_webhook_subscription_updated() {
    let service = service(FakePaymentProvider::with_subscription_id("sub_123"));
    service.create_subscription(CreateSubscriptionRequest { customer_id: "cust_123".into(), tier: "solo".into() }).await.unwrap();

    let event_data = serde_json::json!({
        "id": "evt_123",
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_123",
                "customer": "cust_123",
                "items": { "data": [{ "price": { "lookup_key": "team" } }] },
                "status": "active"
            }
        }
    });

    let result = service.handle_stripe_webhook(signed(&event_data, SECRET)).await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response["received"], true);

    assert_eq!(count(&service, "subscriptions", "stripe_subscription_id = 'sub_123' AND tier = 'team' AND status = 'active'"), 1);
    assert_eq!(count(&service, "audit_log", "action = 'subscription_updated'"), 1);
    assert_eq!(count(&service, "events", "stripe_event_id = 'evt_123'"), 1);
}

// BILL-10
#[tokio::test]
async fn test_webhook_response_time() {
    let service = service(FakePaymentProvider::default());

    let start = std::time::Instant::now();
    let result = service.handle_stripe_webhook(signed(&payment_succeeded(), SECRET)).await;
    let duration = start.elapsed();

    assert!(result.is_ok());
    assert!(duration < Duration::from_secs(3));
    let response = result.unwrap();
    assert_eq!(response["received"], true);
    assert_eq!(count(&service, "invoices", "1 = 1"), 1);
}

// BILL-09
#[tokio::test]
async fn test_webhook_signature_invalid() {
    let service = service(FakePaymentProvider::default());

    let result = service.handle_stripe_webhook(signed(&payment_succeeded(), b"some_other_secret_value")).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, BillingError::InvalidSignature));
    assert_eq!(err.to_response().1, 403);
    // nothing was processed or recorded
    assert_eq!(count(&service, "events", "1 = 1"), 0);
    assert_eq!(count(&service, "invoices", "1 = 1"), 0);
    // a valid signature over a different body is also refused
    let mut tampered = signed(&payment_succeeded(), SECRET);
    tampered.payload = tampered.payload.replace("10000", "1");
    assert!(matches!(service.handle_stripe_webhook(tampered).await.unwrap_err(), BillingError::InvalidSignature));
}

/// Added 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP), CodeRabbit review on PR 19: a
/// customer.subscription.updated whose price has no lookup key still saves the status. The tier comes
/// from the configured price id; with an unknown price id the stored tier is kept; an unknown
/// subscription on an unknown price is acknowledged without a row. Touches: memory only.
#[tokio::test]
async fn test_webhook_subscription_updated_without_lookup_key() {
    let service = service(FakePaymentProvider::with_subscription_id("sub_123"));
    service.create_subscription(CreateSubscriptionRequest { customer_id: "cust_123".into(), tier: "solo".into() }).await.unwrap();
    let event = |id: &str, sub: &str, price: Value, status: &str| {
        serde_json::json!({
            "id": id,
            "type": "customer.subscription.updated",
            "data": { "object": { "id": sub, "customer": "cust_123", "items": { "data": [{ "price": price }] }, "status": status } }
        })
    };

    // No lookup key, but a configured price id: tier follows the price, status is saved.
    let r = service.handle_stripe_webhook(signed(&event("evt_a", "sub_123", serde_json::json!({ "id": "price_team" }), "past_due"), SECRET)).await;
    assert_eq!(r.unwrap()["received"], true);
    assert_eq!(count(&service, "subscriptions", "stripe_subscription_id = 'sub_123' AND tier = 'team' AND status = 'past_due'"), 1);

    // No lookup key and an unknown price id: the stored tier is kept, the status is still saved.
    let r = service.handle_stripe_webhook(signed(&event("evt_b", "sub_123", serde_json::json!({ "id": "price_legacy_x" }), "canceled"), SECRET)).await;
    assert_eq!(r.unwrap()["received"], true);
    assert_eq!(count(&service, "subscriptions", "stripe_subscription_id = 'sub_123' AND tier = 'team' AND status = 'canceled'"), 1);

    // An unknown lookup key falls back the same way.
    let r = service.handle_stripe_webhook(signed(&event("evt_c", "sub_123", serde_json::json!({ "id": "price_legacy_x", "lookup_key": "gold" }), "trialing"), SECRET)).await;
    assert_eq!(r.unwrap()["received"], true);
    assert_eq!(count(&service, "subscriptions", "stripe_subscription_id = 'sub_123' AND tier = 'team' AND status = 'trialing'"), 1);

    // Unknown subscription and unknown price: acknowledged, nothing recorded, the event is not reprocessed.
    let r = service.handle_stripe_webhook(signed(&event("evt_d", "sub_unknown", serde_json::json!({ "id": "price_legacy_x" }), "active"), SECRET)).await;
    assert_eq!(r.unwrap()["received"], true);
    assert_eq!(count(&service, "subscriptions", "stripe_subscription_id = 'sub_unknown'"), 0);
    assert_eq!(count(&service, "audit_log", "action = 'subscription_update_ignored'"), 1);
    assert_eq!(count(&service, "events", "stripe_event_id = 'evt_d'"), 1);
}

# Billing & Subscriptions

Reference contract for `saas_templates/<lang>/billing_subscriptions_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# BILL-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `BILL-01` | create_subscription happy path → stripe call made, DB record created |
| `BILL-02` | create_subscription invalid tier → 400 {error: "invalid_tier"} |
| `BILL-03` | change_plan happy path → stripe updated with the existing item id and the new price (no second item), proration calculated |
| `BILL-04` | queue_refund happy path → refund record created with status='queued' |
| `BILL-05` | queue_refund amount exceeds invoice → 400 {error: "refund_exceeds_invoice"} |
| `BILL-06` | handle_webhook payment_succeeded → invoice marked succeeded, audit logged |
| `BILL-07` | handle_webhook duplicate event → idempotency check prevents double-processing |
| `BILL-08` | handle_webhook subscription_updated → tier updated, status changed |
| `BILL-09` | webhook signature invalid → 403 {error: "invalid_signature"} |
| `BILL-10` | webhook response time < 3 seconds → {received: true} |

## Contract

```text
FLOWS:

  1. create_subscription(customer_id, tier)
     Action:
       - Call stripe.subscriptions.create({customer: stripe_customer_id, items: [{price: price_id[tier]}]})
       - DB: subscriptions (stripe_subscription_id, customer_id, tier, status='active', created_at)
       - Log: audit_log(action="subscription_created", customer_id, tier, stripe_sub_id)
     Return: {success: true, subscription_id, tier, status: "active", next_billing_date}

  2. change_plan(subscription_id, new_tier)
     Action:
       - Read the subscription's current item id (stripe.subscriptions.retrieve, or the item id stored with the
         subscription), then call stripe.subscriptions.update(stripe_subscription_id,
           {items: [{id: current_item_id, price: price_id[new_tier]}], proration_behavior: 'create_prorations'})
         Without the item id Stripe ADDS a second item and bills both plans. Amended 2026-11-10 after review on PR 19.
       - DB: subscriptions.tier = new_tier, billing_cycle_anchor updated if needed
       - Log: audit_log(action="plan_changed", subscription_id, old_tier, new_tier, proration_credits)
     Return: {success: true, subscription_id, old_tier, new_tier, effective_date, proration_credit}

  3. queue_refund(invoice_id, amount, reason)
     Action:
       - Check: invoice exists, status='succeeded', amount <= invoice.amount
       - DB: refunds (invoice_id, amount, reason, status='queued', created_by, created_at)
       - Log: audit_log(action="refund_queued", invoice_id, amount, reason)
     Return: {success: true, refund_id, status: "queued", amount, reason}

  4. handle_stripe_webhook(event)
     Idempotency: Query events table by stripe_event_id first

     if event.type == "invoice.payment_succeeded":
       - Check: idempotency (not already processed)
       - DB: invoices (stripe_invoice_id, customer_id, amount, status='succeeded', paid_at)
       - Log: audit_log(action="payment_succeeded", customer_id, invoice_id, amount)

     if event.type == "invoice.payment_failed":
       - DB: subscriptions.status = 'past_due' (if not already)
       - Log: audit_log(action="payment_failed", customer_id, invoice_id, reason)

     if event.type == "customer.subscription.updated":
       - DB: subscriptions.tier = event.subscription.items[0].price.lookup_key, status = event.subscription.status
       - Log: audit_log(action="subscription_updated", customer_id, old_tier, new_tier)

     if event.type == "customer.subscription.deleted":
       - DB: subscriptions.status = 'cancelled', cancelled_at = NOW()
       - Log: audit_log(action="subscription_cancelled", customer_id)

     Return: {received: true} (Stripe expects 200 within 3 seconds)

IMPLEMENTATION REQUIREMENTS:
  - Stripe API key: use STRIPE_SECRET_KEY env var
  - Idempotency: store processed stripe_event_id in events table
  - Price IDs: {solo: "price_1UI...", team: "price_1UI...", enterprise: "price_1UI..."}
  - Timestamps: UTC, ISO 8601
  - Webhook signature: verify with STRIPE_WEBHOOK_SECRET before processing
  - Response: {success: true, ...} or {error: "code", message: "..."}
  - Database: subscriptions (stripe_subscription_id, customer_id, tier, status, created_at, updated_at, cancelled_at)
  - Database: invoices (stripe_invoice_id, customer_id, amount, status, paid_at)
  - Database: refunds (id, invoice_id, amount, status, reason, created_by, created_at, executed_at)
  - Database: events (stripe_event_id, event_type, processed_at)

TESTS REQUIRED:
  - **BILL-01** create_subscription happy path → stripe call made, DB record created
  - **BILL-02** create_subscription invalid tier → 400 {error: "invalid_tier"}
  - **BILL-03** change_plan happy path → stripe updated with the existing item id and the new price (no second item), proration calculated
  - **BILL-04** queue_refund happy path → refund record created with status='queued'
  - **BILL-05** queue_refund amount exceeds invoice → 400 {error: "refund_exceeds_invoice"}
  - **BILL-06** handle_webhook payment_succeeded → invoice marked succeeded, audit logged
  - **BILL-07** handle_webhook duplicate event → idempotency check prevents double-processing
  - **BILL-08** handle_webhook subscription_updated → tier updated, status changed
  - **BILL-09** webhook signature invalid → 403 {error: "invalid_signature"}
  - **BILL-10** webhook response time < 3 seconds → {received: true}
```

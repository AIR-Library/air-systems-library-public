const stripe = require('stripe');

// Database schema as executable DDL
const DB_SCHEMA = `
CREATE TABLE IF NOT EXISTS events (
  stripe_event_id VARCHAR(255) PRIMARY KEY,
  event_type VARCHAR(255) NOT NULL,
  processed_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS subscriptions (
  stripe_subscription_id VARCHAR(255) PRIMARY KEY,
  customer_id VARCHAR(255) NOT NULL,
  tier VARCHAR(50) NOT NULL,
  status VARCHAR(50) NOT NULL,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  cancelled_at TIMESTAMP NULL
);

CREATE TABLE IF NOT EXISTS invoices (
  stripe_invoice_id VARCHAR(255) PRIMARY KEY,
  customer_id VARCHAR(255) NOT NULL,
  amount DECIMAL(10,2) NOT NULL,
  status VARCHAR(50) NOT NULL,
  paid_at TIMESTAMP NULL
);

CREATE TABLE IF NOT EXISTS refunds (
  id SERIAL PRIMARY KEY,
  invoice_id VARCHAR(255) NOT NULL REFERENCES invoices(stripe_invoice_id),
  amount DECIMAL(10,2) NOT NULL,
  status VARCHAR(50) NOT NULL,
  reason TEXT,
  created_by VARCHAR(255) NOT NULL,
  created_at TIMESTAMP NOT NULL,
  executed_at TIMESTAMP NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id SERIAL PRIMARY KEY,
  action VARCHAR(255) NOT NULL,
  customer_id VARCHAR(255),
  tier VARCHAR(50),
  stripe_sub_id VARCHAR(255) REFERENCES subscriptions(stripe_subscription_id),
  invoice_id VARCHAR(255) REFERENCES invoices(stripe_invoice_id),
  amount DECIMAL(10,2),
  reason TEXT,
  old_tier VARCHAR(50),
  new_tier VARCHAR(50),
  proration_credits DECIMAL(10,2),
  created_at TIMESTAMP NOT NULL
);
`;

/**
 * createBillingSystem({stripeSecretKey, webhookSecret, db, priceIds?}) -> the billing flows of billing_subscriptions.md.
 * In: Stripe keys, a db adapter and optionally the tier -> Stripe price id map. Out: {create_subscription, change_plan,
 * queue_refund, handle_stripe_webhook, __stripeInstance}.
 * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] priceIds is configurable and the placeholders are distinct per tier:
 * every tier used to map to the same "price_1UI..." string, so a plan change could not change the price.
 * Touches: Stripe (network, money) through the client, the db adapter.
 */
function createBillingSystem({ stripeSecretKey, webhookSecret, db, priceIds }) {
  if (!stripeSecretKey) throw new Error('STRIPE_SECRET_KEY is required');
  if (!webhookSecret) throw new Error('STRIPE_WEBHOOK_SECRET is required');
  if (!db) throw new Error('Database adapter is required');

  const stripeInstance = stripe(stripeSecretKey);
  const PRICE_IDS = Object.freeze(Object.assign(Object.create(null), priceIds || {
    solo: "price_solo_placeholder",
    team: "price_team_placeholder",
    enterprise: "price_enterprise_placeholder"
  }));

  /**
   * create_subscription(customer_id, tier) -> { success, subscription_id, tier, status, next_billing_date } |
   * { error, status, message }: 400 invalid_tier (BILL-02), 502 stripe_error when Stripe refuses or is unreachable.
   * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 bug fix: errors carried no HTTP status).
   * Touches: Stripe (network, money), the db adapter.
   */
  async function create_subscription(customer_id, tier) {
    if (!PRICE_IDS[tier]) {
      return { error: "invalid_tier", status: 400, message: `Invalid tier: ${tier}` };
    }

    try {
      const subscription = await stripeInstance.subscriptions.create({
        customer: customer_id,
        items: [{ price: PRICE_IDS[tier] }],
        expand: ['latest_invoice.payment_intent']
      });

      const now = new Date().toISOString();
      const subscriptionData = {
        stripe_subscription_id: subscription.id,
        customer_id,
        tier,
        status: subscription.status,
        created_at: now,
        updated_at: now,
        cancelled_at: null
      };
      await db.createSubscription(subscriptionData);

      await db.createAuditLog({
        action: "subscription_created",
        customer_id,
        tier,
        stripe_sub_id: subscription.id,
        created_at: now
      });

      const next_billing_date = new Date(subscription.current_period_end * 1000).toISOString();
      return {
        success: true,
        subscription_id: subscription.id,
        tier,
        status: subscription.status,
        next_billing_date
      };
    } catch (error) {
      return { error: "stripe_error", status: 502, message: error.message };
    }
  }

  /**
   * change_plan(subscription_id, new_tier) -> {success, subscription_id, old_tier, new_tier, effective_date,
   * proration_credit} | {error, status, message}.
   * Order (billing_subscriptions.md flow 2, BILL-03, amended 2026-11-10): an unknown tier -> 400 invalid_tier;
   * an unknown subscription -> 404 subscription_not_found; stripe.subscriptions.retrieve, and a subscription
   * without exactly one item -> 409 subscription_item_ambiguous; all before any update. Then
   * stripe.subscriptions.update(id, {items: [{id: current_item_id, price}], proration_behavior: 'create_prorations'}).
   * Sending only {price} made Stripe ADD a second item and bill both plans.
   * proration_credit: the credit (in the invoice's minor units, as a string) from the negative proration lines of
   * the update's latest_invoice when Stripe returns it, else "0". A Stripe failure is 502 stripe_error.
   * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2: stripe_error carries its status too).
   * Touches: Stripe (network, money), subscriptions, audit_log.
   */
  async function change_plan(subscription_id, new_tier) {
    if (typeof new_tier !== 'string' || !Object.prototype.hasOwnProperty.call(PRICE_IDS, new_tier)) {
      return { error: "invalid_tier", status: 400, message: `Invalid tier: ${new_tier}` };
    }

    try {
      const existingSub = await db.getSubscriptionByStripeId(subscription_id);
      if (!existingSub) {
        return { error: "subscription_not_found", status: 404, message: `Subscription ${subscription_id} not found` };
      }
      const old_tier = existingSub.tier;

      const current = await stripeInstance.subscriptions.retrieve(subscription_id);
      const items = current && current.items && Array.isArray(current.items.data) ? current.items.data : [];
      if (items.length !== 1 || !items[0] || !items[0].id) {
        return {
          error: "subscription_item_ambiguous",
          status: 409,
          message: `Subscription ${subscription_id} must have exactly one item to change plan`
        };
      }

      const updatedSubscription = await stripeInstance.subscriptions.update(subscription_id, {
        items: [{ id: items[0].id, price: PRICE_IDS[new_tier] }],
        proration_behavior: 'create_prorations'
      });

      const now = new Date().toISOString();
      await db.updateSubscription(subscription_id, {
        tier: new_tier,
        status: updatedSubscription.status,
        updated_at: now
      });

      const proration_credit = prorationCredit(updatedSubscription.latest_invoice);

      await db.createAuditLog({
        action: "plan_changed",
        stripe_sub_id: subscription_id,
        old_tier,
        new_tier,
        proration_credits: proration_credit,
        created_at: now
      });

      const effective_date = new Date(updatedSubscription.billing_cycle_anchor * 1000).toISOString();
      return {
        success: true,
        subscription_id,
        old_tier,
        new_tier,
        effective_date,
        proration_credit: proration_credit.toString()
      };
    } catch (error) {
      return { error: "stripe_error", status: 502, message: error.message };
    }
  }

  /**
   * prorationCredit(invoice) -> integer credit in minor units (>= 0).
   * In: a Stripe invoice object (or an id string / null when not expanded). Out: minus the sum of the negative
   * proration line amounts, 0 when the lines are not present. Why: BILL-03 "proration calculated".
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  function prorationCredit(invoice) {
    const lines = invoice && typeof invoice === 'object' && invoice.lines && Array.isArray(invoice.lines.data)
      ? invoice.lines.data : [];
    let credit = 0;
    for (const line of lines) {
      if (line && line.proration && typeof line.amount === 'number' && line.amount < 0) credit += -line.amount;
    }
    return credit;
  }

  /**
   * queue_refund(invoice_id, amount, reason) -> { success, refund_id, status: 'queued', amount, reason } |
   * { error, status, message }: 404 invoice_not_found, 400 invoice_not_succeeded, 400 invalid_amount, 400
   * refund_exceeds_invoice (BILL-05), 500 database_error. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
   * (Phase B.2 bug fix: errors carried no HTTP status). Touches: the db adapter.
   */
  async function queue_refund(invoice_id, amount, reason) {
    try {
      const invoice = await db.getInvoiceByStripeId(invoice_id);
      if (!invoice) {
        return { error: "invoice_not_found", status: 404, message: `Invoice ${invoice_id} not found` };
      }
      if (invoice.status !== 'succeeded') {
        return { error: "invoice_not_succeeded", status: 400, message: `Invoice ${invoice_id} is not succeeded` };
      }
      // Number() reads the whole value: parseFloat('1_000') is 1, so the check passed while '1_000' was stored (2026-11-08, session f3daac6e, from review).
      // A whole number of cents: '50', '50.5' or '50.00'. Anything else, such as '0.001' or '1_000', is refused.
      const amountText = String(amount).trim();
      const refundAmount = /^\d+(\.\d{1,2})?$/.test(amountText) ? Number(amountText) : NaN;
      if (!Number.isFinite(refundAmount) || refundAmount <= 0) {
        return { error: "invalid_amount", status: 400, message: `Refund amount ${amount} is not a positive number` };
      }
      if (refundAmount > Number(invoice.amount)) {
        return { error: "refund_exceeds_invoice", status: 400, message: `Refund amount ${amount} exceeds invoice amount ${invoice.amount}` };
      }

      const now = new Date().toISOString();
      const refund = await db.createRefund({
        invoice_id,
        amount: refundAmount.toFixed(2),   // money keeps two decimals: '50.00'
        status: 'queued',
        reason,
        created_by: 'system', // In real implementation, this would come from auth context
        created_at: now
      });

      await db.createAuditLog({
        action: "refund_queued",
        invoice_id,
        amount: refundAmount.toFixed(2),
        reason,
        created_at: now
      });

      return {
        success: true,
        refund_id: refund.id,
        status: "queued",
        amount: refundAmount.toFixed(2),
        reason
      };
    } catch (error) {
      return { error: "database_error", status: 500, message: error.message };
    }
  }

  /**
   * handle_stripe_webhook(payload, signature) -> { received: true } | { error: 'invalid_signature', status: 400,
   * message } (BILL-09). Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 bug fix: the error carried
   * no HTTP status; Phase B.3, same day: 400, Stripe's documented answer and the same as stripe_webhook_entitlements,
   * was 403). Touches: Stripe signature check, the db adapter.
   */
  async function handle_stripe_webhook(payload, signature) {
    let event;
    try {
      event = stripeInstance.webhooks.constructEvent(payload, signature, webhookSecret);
    } catch (err) {
      return { error: "invalid_signature", status: 400, message: `Webhook Error: ${err.message}` };
    }

    // Idempotency check
    const existingEvent = await db.getEventByStripeId(event.id);
    if (existingEvent) {
      return { received: true };
    }

    try {
      if (event.type === "invoice.payment_succeeded") {
        const invoice = event.data.object;
        const now = new Date().toISOString();
        
        await db.createInvoice({
          stripe_invoice_id: invoice.id,
          customer_id: invoice.customer,
          amount: (invoice.amount_paid / 100).toString(),
          status: 'succeeded',
          paid_at: now
        });

        await db.createAuditLog({
          action: "payment_succeeded",
          customer_id: invoice.customer,
          invoice_id: invoice.id,
          amount: (invoice.amount_paid / 100).toString(),
          created_at: now
        });

      } else if (event.type === "invoice.payment_failed") {
        const invoice = event.data.object;
        await db.updateSubscriptionByCustomerId(invoice.customer, { status: 'past_due' });
        
        await db.createAuditLog({
          action: "payment_failed",
          customer_id: invoice.customer,
          invoice_id: invoice.id,
          reason: invoice.last_error ? invoice.last_error.message : 'unknown',
          created_at: new Date().toISOString()
        });

      } else if (event.type === "customer.subscription.updated") {
        const subscription = event.data.object;
        const new_tier = subscription.items.data[0].price.lookup_key ||
                        Object.keys(PRICE_IDS).find(key => PRICE_IDS[key] === subscription.items.data[0].price.id) ||
                        'unknown';
        const old_tier = await db.getSubscriptionTierByStripeId(subscription.id) || 'unknown';
        
        await db.updateSubscription(subscription.id, {
          tier: new_tier,
          status: subscription.status,
          updated_at: new Date().toISOString()
        });

        await db.createAuditLog({
          action: "subscription_updated",
          customer_id: subscription.customer,
          old_tier,
          new_tier,
          stripe_sub_id: subscription.id,
          created_at: new Date().toISOString()
        });

      } else if (event.type === "customer.subscription.deleted") {
        const subscription = event.data.object;
        await db.updateSubscription(subscription.id, {
          status: 'cancelled',
          cancelled_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        });

        await db.createAuditLog({
          action: "subscription_cancelled",
          customer_id: subscription.customer,
          stripe_sub_id: subscription.id,
          created_at: new Date().toISOString()
        });
      }

      // Record processed event
      await db.createEvent({
        stripe_event_id: event.id,
        event_type: event.type,
        processed_at: new Date().toISOString()
      });

      return { received: true };
    } catch (error) {
      // Even if DB operation fails, we still return 200 to Stripe to prevent retries
      // but log the error (in real implementation, you'd use a proper logger)
      console.error('Webhook processing error:', error);
      return { received: true };
    }
  }

  // Expose stripe instance for testing
  return {
    create_subscription,
    change_plan,
    queue_refund,
    handle_stripe_webhook,
    __stripeInstance: stripeInstance
  };
}

module.exports = { createBillingSystem, DB_SCHEMA };

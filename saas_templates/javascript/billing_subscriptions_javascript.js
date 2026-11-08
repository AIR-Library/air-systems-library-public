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

function createBillingSystem({ stripeSecretKey, webhookSecret, db }) {
  if (!stripeSecretKey) throw new Error('STRIPE_SECRET_KEY is required');
  if (!webhookSecret) throw new Error('STRIPE_WEBHOOK_SECRET is required');
  if (!db) throw new Error('Database adapter is required');

  const stripeInstance = stripe(stripeSecretKey);
  const PRICE_IDS = {
    solo: "price_1UI...",
    team: "price_1UI...",
    enterprise: "price_1UI..."
  };

  async function create_subscription(customer_id, tier) {
    if (!PRICE_IDS[tier]) {
      return { error: "invalid_tier", message: `Invalid tier: ${tier}` };
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
      return { error: "stripe_error", message: error.message };
    }
  }

  async function change_plan(subscription_id, new_tier) {
    if (!PRICE_IDS[new_tier]) {
      return { error: "invalid_tier", message: `Invalid tier: ${new_tier}` };
    }

    try {
      // Get old tier from DB — spec calls only stripe.subscriptions.update, not retrieve
      const existingSub = await db.getSubscriptionByStripeId(subscription_id);
      if (!existingSub) {
        return { error: "subscription_not_found", message: `Subscription ${subscription_id} not found` };
      }
      const old_tier = existingSub.tier;

      const updatedSubscription = await stripeInstance.subscriptions.update(subscription_id, {
        items: [{ price: PRICE_IDS[new_tier] }]
      });

      const now = new Date().toISOString();
      await db.updateSubscription(subscription_id, {
        tier: new_tier,
        status: updatedSubscription.status,
        updated_at: now
      });

      // Calculate proration credit (simplified — actual calculation would be more complex)
      const proration_credit = 0; // Placeholder - in reality would come from Stripe invoice

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
      return { error: "stripe_error", message: error.message };
    }
  }

  async function queue_refund(invoice_id, amount, reason) {
    try {
      const invoice = await db.getInvoiceByStripeId(invoice_id);
      if (!invoice) {
        return { error: "invoice_not_found", message: `Invoice ${invoice_id} not found` };
      }
      if (invoice.status !== 'succeeded') {
        return { error: "invoice_not_succeeded", message: `Invoice ${invoice_id} is not succeeded` };
      }
      // Number() reads the whole value: parseFloat('1_000') is 1, so the check passed while '1_000' was stored (2026-11-08, session f3daac6e, from review).
      // A whole number of cents: '50', '50.5' or '50.00'. Anything else, such as '0.001' or '1_000', is refused.
      const amountText = String(amount).trim();
      const refundAmount = /^\d+(\.\d{1,2})?$/.test(amountText) ? Number(amountText) : NaN;
      if (!Number.isFinite(refundAmount) || refundAmount <= 0) {
        return { error: "invalid_amount", message: `Refund amount ${amount} is not a positive number` };
      }
      if (refundAmount > Number(invoice.amount)) {
        return { error: "refund_exceeds_invoice", message: `Refund amount ${amount} exceeds invoice amount ${invoice.amount}` };
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
      return { error: "database_error", message: error.message };
    }
  }

  async function handle_stripe_webhook(payload, signature) {
    let event;
    try {
      event = stripeInstance.webhooks.constructEvent(payload, signature, webhookSecret);
    } catch (err) {
      return { error: "invalid_signature", message: `Webhook Error: ${err.message}` };
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

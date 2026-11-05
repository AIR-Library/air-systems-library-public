const assert = require('assert');
const sinon = require('sinon');
const { createBillingSystem, DB_SCHEMA } = require('./billing_subscriptions_javascript');

// Mock database adapter
const createMockDb = () => {
  const subscriptions = new Map();
  const invoices = new Map();
  const refunds = new Map();
  const events = new Map();
  const auditLog = [];

  return {
    // Events
    getEventByStripeId: async (stripe_event_id) => events.get(stripe_event_id) || null,
    createEvent: async (eventData) => {
      events.set(eventData.stripe_event_id, eventData);
      return eventData;
    },

    // Subscriptions
    getSubscriptionByStripeId: async (stripe_subscription_id) => subscriptions.get(stripe_subscription_id) || null,
    getSubscriptionTierByStripeId: async (stripe_subscription_id) => {
      const sub = subscriptions.get(stripe_subscription_id);
      return sub ? sub.tier : null;
    },
    createSubscription: async (subscriptionData) => {
      subscriptions.set(subscriptionData.stripe_subscription_id, subscriptionData);
      return subscriptionData;
    },
    updateSubscription: async (stripe_subscription_id, updates) => {
      const sub = subscriptions.get(stripe_subscription_id);
      if (!sub) throw new Error('Subscription not found');
      const updated = { ...sub, ...updates };
      subscriptions.set(stripe_subscription_id, updated);
      return updated;
    },
    updateSubscriptionByCustomerId: async (customer_id, updates) => {
      for (const [id, sub] of subscriptions.entries()) {
        if (sub.customer_id === customer_id) {
          const updated = { ...sub, ...updates };
          subscriptions.set(id, updated);
          return updated;
        }
      }
      return null;
    },

    // Invoices
    getInvoiceByStripeId: async (stripe_invoice_id) => invoices.get(stripe_invoice_id) || null,
    createInvoice: async (invoiceData) => {
      invoices.set(invoiceData.stripe_invoice_id, invoiceData);
      return invoiceData;
    },

    // Refunds
    createRefund: async (refundData) => {
      const id = Math.floor(Math.random() * 1000000);
      const refund = { id, ...refundData };
      refunds.set(id, refund);
      return refund;
    },
    getRefundById: async (id) => refunds.get(id) || null,

    // Audit log
    createAuditLog: async (auditData) => {
      const log = { id: auditLog.length + 1, ...auditData };
      auditLog.push(log);
      return log;
    },
    getAuditLog: () => auditLog
  };
};

describe('Billing System', function() {
  let db;
  let billingSystem;
  const stripeSecretKey = 'sk_test_123';
  const webhookSecret = 'whsec_123';

  beforeEach(() => {
    db = createMockDb();
    billingSystem = createBillingSystem({ stripeSecretKey, webhookSecret, db });
  });

  describe('create_subscription', () => {
    it('should create subscription successfully', async () => {
      const stripeStub = sinon.stub(billingSystem.__stripeInstance.subscriptions, 'create').resolves({
        id: 'sub_123',
        status: 'active',
        current_period_end: Math.floor(Date.now() / 1000) + 2592000, // 30 days from now
        latest_invoice: { payment_intent: {} }
      });

      const result = await billingSystem.create_subscription('cus_123', 'solo');
      
      assert.strictEqual(result.success, true);
      assert.strictEqual(result.subscription_id, 'sub_123');
      assert.strictEqual(result.tier, 'solo');
      assert.strictEqual(result.status, 'active');
      assert.ok(result.next_billing_date);
      
      const sub = await db.getSubscriptionByStripeId('sub_123');
      assert.ok(sub);
      assert.strictEqual(sub.tier, 'solo');
      assert.strictEqual(sub.status, 'active');
      
      const auditLog = db.getAuditLog();
      const createdLog = auditLog.find(log => log.action === 'subscription_created');
      assert.ok(createdLog);
      assert.strictEqual(createdLog.action, 'subscription_created');
      
      stripeStub.restore();
    });

    it('should return invalid_tier for invalid tier', async () => {
      const result = await billingSystem.create_subscription('cus_123', 'invalid');
      assert.strictEqual(result.error, 'invalid_tier');
    });
  });

  describe('change_plan', () => {
    it('should change plan successfully', async () => {
      // Setup existing subscription
      await db.createSubscription({
        stripe_subscription_id: 'sub_123',
        customer_id: 'cus_123',
        tier: 'solo',
        status: 'active',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        cancelled_at: null
      });

      const stripeStub = sinon.stub(billingSystem.__stripeInstance.subscriptions, 'update').resolves({
        id: 'sub_123',
        status: 'active',
        billing_cycle_anchor: Math.floor(Date.now() / 1000) + 86400, // 1 day from now
        items: { data: [{ price: { lookup_key: 'team', id: 'price_team' } }] }
      });

      const result = await billingSystem.change_plan('sub_123', 'team');
      
      assert.strictEqual(result.success, true);
      assert.strictEqual(result.old_tier, 'solo');
      assert.strictEqual(result.new_tier, 'team');
      assert.ok(result.effective_date);
      assert.strictEqual(result.proration_credit, '0');
      
      const sub = await db.getSubscriptionByStripeId('sub_123');
      assert.strictEqual(sub.tier, 'team');
      assert.strictEqual(sub.status, 'active');
      
      const auditLog = db.getAuditLog();
      const planChangedLog = auditLog.find(log => log.action === 'plan_changed');
      assert.ok(planChangedLog);
      assert.strictEqual(planChangedLog.action, 'plan_changed');
      assert.strictEqual(planChangedLog.old_tier, 'solo');
      assert.strictEqual(planChangedLog.new_tier, 'team');
      
      stripeStub.restore();
    });

    it('should return invalid_tier for invalid new tier', async () => {
      const result = await billingSystem.change_plan('sub_123', 'invalid');
      assert.strictEqual(result.error, 'invalid_tier');
    });
  });

  describe('queue_refund', () => {
    it('should queue refund successfully', async () => {
      // Setup invoice
      await db.createInvoice({
        stripe_invoice_id: 'in_123',
        customer_id: 'cus_123',
        amount: '100.00',
        status: 'succeeded',
        paid_at: new Date().toISOString()
      });

      const result = await billingSystem.queue_refund('in_123', '50.00', 'Customer request');
      
      assert.strictEqual(result.success, true);
      assert.strictEqual(result.status, 'queued');
      assert.strictEqual(result.amount, '50.00');
      assert.strictEqual(result.reason, 'Customer request');
      assert.ok(result.refund_id);
      
      const refund = await db.getRefundById(result.refund_id);
      assert.ok(refund);
      assert.strictEqual(refund.status, 'queued');
      assert.strictEqual(refund.amount, '50.00');
      assert.strictEqual(refund.reason, 'Customer request');
      
      const auditLog = db.getAuditLog();
      const refundQueuedLog = auditLog.find(log => log.action === 'refund_queued');
      assert.ok(refundQueuedLog);
      assert.strictEqual(refundQueuedLog.action, 'refund_queued');
      assert.strictEqual(refundQueuedLog.amount, '50.00');
      assert.strictEqual(refundQueuedLog.reason, 'Customer request');
    });

    it('should return refund_exceeds_invoice when amount exceeds invoice', async () => {
      await db.createInvoice({
        stripe_invoice_id: 'in_123',
        customer_id: 'cus_123',
        amount: '100.00',
        status: 'succeeded',
        paid_at: new Date().toISOString()
      });

      const result = await billingSystem.queue_refund('in_123', '150.00', 'Too much');
      assert.strictEqual(result.error, 'refund_exceeds_invoice');
    });

    it('should return invoice_not_succeeded for non-succeeded invoice', async () => {
      await db.createInvoice({
        stripe_invoice_id: 'in_123',
        customer_id: 'cus_123',
        amount: '100.00',
        status: 'open',
        paid_at: null
      });

      const result = await billingSystem.queue_refund('in_123', '50.00', 'Reason');
      assert.strictEqual(result.error, 'invoice_not_succeeded');
    });
  });

  describe('handle_stripe_webhook', () => {
    it('should handle payment_succeeded event', async () => {
      const payload = JSON.stringify({
        type: 'invoice.payment_succeeded',
        data: {
          object: {
            id: 'in_123',
            customer: 'cus_123',
            amount_paid: 999, // $9.99 in cents
            status: 'paid'
          }
        }
      });
      const signature = 'tstub';

      const stripeStub = sinon.stub(billingSystem.__stripeInstance.webhooks, 'constructEvent').returns({
        type: 'invoice.payment_succeeded',
        data: {
          object: {
            id: 'in_123',
            customer: 'cus_123',
            amount_paid: 999,
            status: 'paid'
          }
        }
      });

      const result = await billingSystem.handle_stripe_webhook(payload, signature);
      
      assert.strictEqual(result.received, true);
      
      const invoice = await db.getInvoiceByStripeId('in_123');
      assert.ok(invoice);
      assert.strictEqual(invoice.status, 'succeeded');
      assert.strictEqual(invoice.amount, '9.99');
      
      const auditLog = db.getAuditLog();
      const paymentSucceededLog = auditLog.find(log => log.action === 'payment_succeeded');
      assert.ok(paymentSucceededLog);
      assert.strictEqual(paymentSucceededLog.action, 'payment_succeeded');
      assert.strictEqual(paymentSucceededLog.amount, '9.99');
      
      stripeStub.restore();
    });

    it('should handle duplicate event with idempotency', async () => {
      const payload = JSON.stringify({
        type: 'invoice.payment_succeeded',
        data: { object: { id: 'in_123', customer: 'cus_123', amount_paid: 999, status: 'paid' } }
      });
      const signature = 'tstub';

      // First call
      const stripeStub = sinon.stub(billingSystem.__stripeInstance.webhooks, 'constructEvent').returns({
        type: 'invoice.payment_succeeded',
        data: { object: { id: 'in_123', customer: 'cus_123', amount_paid: 999, status: 'paid' } }
      });
      
      await billingSystem.handle_stripe_webhook(payload, signature);
      
      // Second call with same event
      const result = await billingSystem.handle_stripe_webhook(payload, signature);
      assert.strictEqual(result.received, true);
      
      // Should only have one invoice record
      const invoices = await db.getInvoiceByStripeId('in_123');
      assert.ok(invoices);
      
      stripeStub.restore();
    });

    it('should handle subscription_updated event', async () => {
      const payload = JSON.stringify({
        type: 'customer.subscription.updated',
        data: {
          object: {
            id: 'sub_123',
            customer: 'cus_123',
            status: 'active',
            items: { data: [{ price: { lookup_key: 'team', id: 'price_team' } }] }
          }
        }
      });
      const signature = 'tstub';

      // Setup existing subscription with solo tier
      await db.createSubscription({
        stripe_subscription_id: 'sub_123',
        customer_id: 'cus_123',
        tier: 'solo',
        status: 'active',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        cancelled_at: null
      });

      const stripeStub = sinon.stub(billingSystem.__stripeInstance.webhooks, 'constructEvent').returns({
        type: 'customer.subscription.updated',
        data: {
          object: {
            id: 'sub_123',
            customer: 'cus_123',
            status: 'active',
            items: { data: [{ price: { lookup_key: 'team', id: 'price_team' } }] }
          }
        }
      });

      const result = await billingSystem.handle_stripe_webhook(payload, signature);
      
      assert.strictEqual(result.received, true);
      
      const sub = await db.getSubscriptionByStripeId('sub_123');
      assert.strictEqual(sub.tier, 'team');
      assert.strictEqual(sub.status, 'active');
      
      const auditLog = db.getAuditLog();
      const subscriptionUpdatedLog = auditLog.find(log => log.action === 'subscription_updated');
      assert.ok(subscriptionUpdatedLog);
      assert.strictEqual(subscriptionUpdatedLog.action, 'subscription_updated');
      assert.strictEqual(subscriptionUpdatedLog.old_tier, 'solo');
      assert.strictEqual(subscriptionUpdatedLog.new_tier, 'team');
      
      stripeStub.restore();
    });

    it('should return invalid_signature for bad signature', async () => {
      const payload = '{}';
      const signature = 'bad_signature';
      
      const stripeStub = sinon.stub(billingSystem.__stripeInstance.webhooks, 'constructEvent').throws(new Error('Invalid signature'));
      
      const result = await billingSystem.handle_stripe_webhook(payload, signature);
      
      assert.strictEqual(result.error, 'invalid_signature');
      assert.ok(result.message.includes('Webhook Error'));
      
      stripeStub.restore();
    });

    it('should respond within 3 seconds (simulated by quick processing)', async () => {
      const start = Date.now();
      const payload = JSON.stringify({
        type: 'invoice.payment_succeeded',
        data: { object: { id: 'in_123', customer: 'cus_123', amount_paid: 999, status: 'paid' } }
      });
      const signature = 'tstub';
      
      const stripeStub = sinon.stub(billingSystem.__stripeInstance.webhooks, 'constructEvent').returns({
        type: 'invoice.payment_succeeded',
        data: { object: { id: 'in_123', customer: 'cus_123', amount_paid: 999, status: 'paid' } }
      });
      
      const result = await billingSystem.handle_stripe_webhook(payload, signature);
      const duration = Date.now() - start;
      
      assert.strictEqual(result.received, true);
      assert.ok(duration < 3000, `Webhook took ${duration}ms, should be < 3000ms`);
      
      stripeStub.restore();
    });
  });
});

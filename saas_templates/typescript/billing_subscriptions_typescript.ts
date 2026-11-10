import { Pool, QueryResult } from 'pg';
import Stripe from 'stripe';

// Database schema as executable DDL
export const CREATE_TABLES_SQL = `
CREATE TABLE IF NOT EXISTS subscriptions (
  id SERIAL PRIMARY KEY,
  stripe_subscription_id VARCHAR(255) UNIQUE NOT NULL,
  customer_id VARCHAR(255) NOT NULL,
  tier VARCHAR(50) NOT NULL,
  status VARCHAR(50) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  cancelled_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS invoices (
  id SERIAL PRIMARY KEY,
  stripe_invoice_id VARCHAR(255) UNIQUE NOT NULL,
  customer_id VARCHAR(255) NOT NULL,
  amount INTEGER NOT NULL,
  status VARCHAR(50) NOT NULL,
  paid_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS refunds (
  id SERIAL PRIMARY KEY,
  invoice_id INTEGER REFERENCES invoices(id),
  amount INTEGER NOT NULL,
  status VARCHAR(50) NOT NULL,
  reason TEXT NOT NULL,
  created_by VARCHAR(255) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  executed_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS events (
  id SERIAL PRIMARY KEY,
  stripe_event_id VARCHAR(255) UNIQUE NOT NULL,
  event_type VARCHAR(255) NOT NULL,
  processed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
  id SERIAL PRIMARY KEY,
  action VARCHAR(100) NOT NULL,
  customer_id VARCHAR(255),
  subscription_id VARCHAR(255),
  stripe_sub_id VARCHAR(255),
  invoice_id VARCHAR(255),
  tier VARCHAR(50),
  old_tier VARCHAR(50),
  new_tier VARCHAR(50),
  amount INTEGER,
  proration_credits INTEGER,
  reason TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
`;

/* The statements below are kept as constants so the code and its tests name exactly the same SQL. */
/** Queues a refund (status 'queued'; never executed automatically). Params: invoice row id, amount, reason, actor. */
export const INSERT_REFUND_SQL = `INSERT INTO refunds (invoice_id, amount, status, reason, created_by)
         VALUES ($1, $2, 'queued', $3, $4)
         RETURNING id`;
/** Records a paid invoice, or marks a known one paid. Params: Stripe invoice id, customer id, amount paid. */
export const UPSERT_PAID_INVOICE_SQL = `INSERT INTO invoices (stripe_invoice_id, customer_id, amount, status, paid_at)
         VALUES ($1, $2, $3, 'succeeded', NOW())
         ON CONFLICT (stripe_invoice_id) DO UPDATE SET
           status = EXCLUDED.status,
           paid_at = EXCLUDED.paid_at`;
/** Applies a subscription's tier and status from Stripe. Params: tier, status, Stripe subscription id. */
export const UPDATE_SUBSCRIPTION_FROM_STRIPE_SQL = `UPDATE subscriptions SET 
         tier = $1, 
         status = $2, 
         updated_at = NOW() 
         WHERE stripe_subscription_id = $3`;

interface StripePriceIds {
  solo: string;
  team: string;
  enterprise: string;
}

/**
 * The Stripe price for each tier: STRIPE_PRICE_SOLO / _TEAM / _ENTERPRISE, else the lookup keys price_solo,
 * price_team and price_enterprise. In: nothing (reads the environment). Out: the three price ids.
 * Why: the fallbacks were three identical placeholders ("price_1UI..."), so no tier could ever be told apart and the
 * happy-path tests got invalid_tier (2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP). Touches: environment.
 */
const getPriceIds = (): StripePriceIds => ({
  solo: process.env.STRIPE_PRICE_SOLO || 'price_solo',
  team: process.env.STRIPE_PRICE_TEAM || 'price_team',
  enterprise: process.env.STRIPE_PRICE_ENTERPRISE || 'price_enterprise'
});

/**
 * The Stripe price for a tier given by name ("solo") or by its configured price id. In: the tier. Out: the price id,
 * or null for anything else. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (spec: price_id[tier]).
 * Touches: environment.
 */
const resolvePrice = (tier: string): string | null => {
  const ids = getPriceIds();
  if (tier === 'solo' || tier === 'team' || tier === 'enterprise') return ids[tier];
  return [ids.solo, ids.team, ids.enterprise].includes(tier) ? tier : null;
};

let _stripe: Stripe | null = null;
let _dbPool: Pool | null = null;

/**
 * Creates the Stripe client and the Postgres pool. In: the Stripe secret key (STRIPE_SECRET_KEY) and the database
 * URL. Out: nothing. Touches: nothing until a call is made (then Stripe over the network and Postgres).
 * Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
 */
export const initialize = (stripeSecretKey: string, connectionString: string) => {
  _stripe = new Stripe(stripeSecretKey, { apiVersion: '2020-08-27' });
  _dbPool = new Pool({ connectionString });
};

/**
 * Uses the given Stripe client and/or Postgres pool instead of the ones initialize() built: an application that
 * already has a pool shares it, and tests pass fakes. In: { stripe?, pool? }. Out: nothing. Touches: module state.
 * Why: the tests replaced the clients by assigning to the module's exports object, which only works with one
 * compiler's CommonJS output (it does nothing under babel and throws under native ES modules), so every database
 * test ran against an empty mock (2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP).
 */
export const set_clients = (clients: { stripe?: Stripe; pool?: Pool }) => {
  if (clients.stripe) _stripe = clients.stripe;
  if (clients.pool) _dbPool = clients.pool;
};

const getStripe = (): Stripe => {
  if (!_stripe) {
    throw new Error('Stripe not initialized. Call initialize() first.');
  }
  return _stripe;
};

const getDbPool = (): Pool => {
  if (!_dbPool) {
    throw new Error('Database pool not initialized. Call initialize() first.');
  }
  return _dbPool;
};

/**
 * Rolls a transaction back without letting a failed rollback hide the error that caused it.
 * In: the pool client. Out: nothing. Why: when the database itself failed, ROLLBACK failed too and its exception
 * escaped the handler, so callers got a thrown error instead of { error, message } (failing test "should return error
 * on database failure", 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP). Touches: Postgres.
 */
const safeRollback = async (client: { query: (text: string) => Promise<unknown> }): Promise<void> => {
  try {
    await client.query('ROLLBACK');
  } catch {
    // The connection is already broken; the original error is what the caller needs.
  }
};

/**
 * Creates a Stripe subscription for a customer and records it (spec billing flow 1). In: the Stripe customer id and
 * the tier (name or price id). Out: { success, subscription_id, tier, status, next_billing_date } or { error, message }.
 * Touches: Stripe (network, money), Postgres subscriptions and audit_log. Documented 2026-11-10, session
 * session_012zDydZCZ4AChqhEZ4oVtaP (tier names accepted; a failed rollback no longer masks the error).
 */
export const create_subscription = async (customer_id: string, tier: string): Promise<{success: true, subscription_id: string, tier: string, status: string, next_billing_date: string} | {error: string, message: string}> => {
  const price = resolvePrice(tier);
  if (price === null) {
    return { error: 'invalid_tier', message: `Invalid tier: ${tier}` };
  }

  const stripe = getStripe();
  const pool = getDbPool();

  try {
    const subscription = await stripe.subscriptions.create({
      customer: customer_id,
      items: [{ price }],
      expand: ['latest_invoice.payment_intent']
    });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const res = await client.query(
        `INSERT INTO subscriptions (stripe_subscription_id, customer_id, tier, status, created_at)
         VALUES ($1, $2, $3, $4, NOW())
         RETURNING id, stripe_subscription_id, customer_id, tier, status, created_at`,
        [subscription.id, customer_id, price, subscription.status]
      );
      const dbRecord = res.rows[0];

      await client.query(
        `INSERT INTO audit_log (action, customer_id, tier, stripe_sub_id)
         VALUES ($1, $2, $3, $4)`,
        ['subscription_created', customer_id, price, subscription.id]
      );

      await client.query('COMMIT');

      const next_billing_date = new Date(subscription.current_period_end * 1000).toISOString();
      return {
        success: true,
        subscription_id: subscription.id,
        tier: subscription.items.data[0].price.lookup_key || price,
        status: subscription.status,
        next_billing_date
      };
    } catch (err) {
      await safeRollback(client);
      throw err;
    } finally {
      client.release();
    }
  } catch (err: any) {
    return { error: 'stripe_error', message: err.message };
  }
};

/**
 * Moves a subscription to another tier in Stripe with proration and records it (spec billing flow 2).
 * In: the Stripe subscription id and the new tier. Out: { success, subscription_id, old_tier, new_tier,
 * effective_date, proration_credit (dollars) } or { error, message }. Touches: Stripe (network, money), Postgres.
 * Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
 */
export const change_plan = async (subscription_id: string, new_tier_input: string): Promise<{success: true, subscription_id: string, old_tier: string, new_tier: string, effective_date: string, proration_credit: number} | {error: string, message: string}> => {
  const new_tier = resolvePrice(new_tier_input);
  if (new_tier === null) {
    return { error: 'invalid_tier', message: `Invalid tier: ${new_tier_input}` };
  }

  const stripe = getStripe();
  const pool = getDbPool();

  let client;
  try {
    client = await pool.connect();
    await client.query('BEGIN');

    // Get current subscription
    const subRes = await client.query(
      `SELECT stripe_subscription_id, tier FROM subscriptions WHERE stripe_subscription_id = $1`,
      [subscription_id]
    );
    if (subRes.rowCount === 0) {
      await safeRollback(client);
      return { error: 'subscription_not_found', message: `Subscription not found: ${subscription_id}` };
    }
    const old_tier = subRes.rows[0].tier;
    const stripe_subscription_id = subRes.rows[0].stripe_subscription_id;

    // Update in Stripe
    const subscription = await stripe.subscriptions.update(stripe_subscription_id, {
      items: [{ price: new_tier }],
      proration_behavior: 'create_prorations',
      expand: ['latest_invoice']
    });

    // Update DB
    await client.query(
      `UPDATE subscriptions SET tier = $1, updated_at = NOW() WHERE stripe_subscription_id = $2`,
      [new_tier, stripe_subscription_id]
    );

    // Calculate proration credit from latest invoice
    const proration_credit = subscription.latest_invoice ? 
      (subscription.latest_invoice as Stripe.Invoice).amount_due : 0;

    await client.query(
      `INSERT INTO audit_log (action, subscription_id, old_tier, new_tier, proration_credits)
       VALUES ($1, $2, $3, $4, $5)`,
      ['plan_changed', subscription_id, old_tier, new_tier, proration_credit]
    );

    await client.query('COMMIT');

    const effective_date = new Date(subscription.current_period_start * 1000).toISOString();
    return {
      success: true,
      subscription_id: subscription.id,
      old_tier,
      new_tier,
      effective_date,
      proration_credit: Math.abs(proration_credit) / 100 // Convert from cents to dollars
    };
  } catch (err: any) {
    if (client) {
      await safeRollback(client);
    }
    return { error: 'stripe_error', message: err.message };
  } finally {
    if (client) {
      client.release();
    }
  }
};

/**
 * Queues a refund for a paid invoice; it is never executed automatically (spec billing flow 3).
 * In: the Stripe invoice id, the amount (cents), the reason and who asked. Out: { success, refund_id, status:
 * 'queued', amount, reason } or { error, message }. Touches: Postgres invoices, refunds, audit_log.
 * Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
 */
export const queue_refund = async (invoice_id: string, amount: number, reason: string, created_by: string): Promise<{success: true, refund_id: number, status: string, amount: number, reason: string} | {error: string, message: string}> => {
  if (amount <= 0) {
    return { error: 'invalid_amount', message: 'Amount must be positive' };
  }

  const pool = getDbPool();
  let client;
  try {
    client = await pool.connect();
    await client.query('BEGIN');

    // Check invoice exists and is succeeded
    const invoiceRes = await client.query(
      `SELECT id, amount, status FROM invoices WHERE stripe_invoice_id = $1`,
      [invoice_id]
    );
    if (invoiceRes.rowCount === 0) {
      await safeRollback(client);
      return { error: 'invoice_not_found', message: `Invoice not found: ${invoice_id}` };
    }
    const invoice = invoiceRes.rows[0];
    if (invoice.status !== 'succeeded') {
      await safeRollback(client);
      return { error: 'invoice_not_succeeded', message: `Invoice status is ${invoice.status}, expected succeeded` };
    }
    if (amount > invoice.amount) {
      await safeRollback(client);
      return { error: 'refund_exceeds_invoice', message: `Refund amount ${amount} exceeds invoice amount ${invoice.amount}` };
    }

    // Create refund record
    const refundRes = await client.query(
      INSERT_REFUND_SQL,
      [invoice.id, amount, reason, created_by]
    );
    const refund_id = refundRes.rows[0].id;

    await client.query(
      `INSERT INTO audit_log (action, invoice_id, amount, reason)
       VALUES ($1, $2, $3, $4)`,
      ['refund_queued', invoice_id, amount, reason]
    );

    await client.query('COMMIT');

    return {
      success: true,
      refund_id,
      status: 'queued',
      amount,
      reason
    };
  } catch (err: any) {
    if (client) {
      await safeRollback(client);
    }
    return { error: 'database_error', message: err.message };
  } finally {
    if (client) {
      client.release();
    }
  }
};

/**
 * Applies one Stripe event once (spec billing flow 4): payment succeeded / failed, subscription updated / deleted;
 * other types are only recorded. The event id is recorded in the same transaction, and an id already recorded is
 * acknowledged without being applied again.
 * Only call this with an event whose signature was verified: {@link verify_and_handle_stripe_webhook} does that for
 * a raw request.
 * In: the Stripe event. Out: { received: true } or { error: 'webhook_processing_error', message }.
 * Why changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): the subscription-updated audit read the "old"
 * tier after overwriting it, so old and new were always equal; a failed ROLLBACK escaped as an exception.
 * Touches: Postgres events, invoices, subscriptions, audit_log.
 */
export const handle_stripe_webhook = async (event: Stripe.Event): Promise<{received: true} | {error: string, message: string}> => {
  const pool = getDbPool();
  let client;
  try {
    client = await pool.connect();
    await client.query('BEGIN');

    // Idempotency check
    const eventRes = await client.query(
      `SELECT id FROM events WHERE stripe_event_id = $1`,
      [event.id]
    );
    if (eventRes.rowCount > 0) {
      await client.query('COMMIT');
      return { received: true };
    }

    // Process event based on type
    switch (event.type) {
      case 'invoice.payment_succeeded': {
        const invoice = event.data.object as Stripe.Invoice;
        await client.query(UPSERT_PAID_INVOICE_SQL, [invoice.id, invoice.customer, invoice.amount_paid]);
        await client.query(
          `INSERT INTO audit_log (action, customer_id, invoice_id, amount)
           VALUES ($1, $2, $3, $4)`,
          ['payment_succeeded', invoice.customer, invoice.id, invoice.amount_paid]
        );
        break;
      }
      case 'invoice.payment_failed': {
        const invoice = event.data.object as Stripe.Invoice;
        await client.query(
          `UPDATE subscriptions SET status = 'past_due', updated_at = NOW() WHERE customer_id = $1 AND status <> 'past_due'`,
          [invoice.customer]
        );
        await client.query(
          `INSERT INTO audit_log (action, customer_id, invoice_id, reason)
           VALUES ($1, $2, $3, $4)`,
          ['payment_failed', invoice.customer, invoice.id, (invoice as any).last_payment_error?.message || 'unknown']
        );
        break;
      }
      case 'customer.subscription.updated': {
        const subscription = event.data.object as Stripe.Subscription;
        const new_tier = subscription.items.data[0].price.lookup_key;
        // Read the tier before it is overwritten, so the audit row says what it changed from.
        const before = await client.query(
          `SELECT tier FROM subscriptions WHERE stripe_subscription_id = $1`,
          [subscription.id]
        );
        const old_tier = before?.rows?.[0]?.tier ?? null;
        await client.query(UPDATE_SUBSCRIPTION_FROM_STRIPE_SQL, [new_tier, subscription.status, subscription.id]);
        await client.query(
          `INSERT INTO audit_log (action, customer_id, old_tier, new_tier)
           VALUES ($1, $2, $3, $4)`,
          ['subscription_updated', subscription.customer, old_tier, new_tier]
        );
        break;
      }
      case 'customer.subscription.deleted': {
        const subscription = event.data.object as Stripe.Subscription;
        await client.query(
          `UPDATE subscriptions SET 
           status = 'cancelled', 
           cancelled_at = NOW() 
           WHERE stripe_subscription_id = $1`,
          [subscription.id]
        );
        await client.query(
          `INSERT INTO audit_log (action, customer_id)
           VALUES ($1, $2)`,
          ['subscription_cancelled', subscription.customer]
        );
        break;
      }
      default:
        // Ignore other event types but still record as processed
        break;
    }

    // Record event as processed (UNIQUE: a concurrent duplicate fails here and its transaction rolls back).
    await client.query(
      `INSERT INTO events (stripe_event_id, event_type)
       VALUES ($1, $2)`,
      [event.id, event.type]
    );

    await client.query('COMMIT');
    return { received: true };
  } catch (err: any) {
    if (client) {
      await safeRollback(client);
    }
    return { error: 'webhook_processing_error', message: err.message };
  } finally {
    if (client) {
      client.release();
    }
  }
};

/**
 * Entry point for the webhook route: verifies the Stripe-Signature header against the raw request body with the
 * endpoint secret (Stripe's library checks the HMAC in constant time and rejects stale timestamps), then applies the
 * event with {@link handle_stripe_webhook}.
 * In: the raw body exactly as received, the Stripe-Signature header, and the secret (default STRIPE_WEBHOOK_SECRET).
 * Out: { received: true }, { error: 'invalid_signature', message, code: 403 }, { error: 'webhook_not_configured',
 * message, code: 500 } or the handler's error.
 * Why: the spec requires verification before processing and the TypeScript template had none (added 2026-11-10,
 * session session_012zDydZCZ4AChqhEZ4oVtaP). Touches: Postgres via the handler; nothing when the signature fails.
 */
export const verify_and_handle_stripe_webhook = async (
  rawBody: string | Buffer,
  signature: string | undefined,
  webhookSecret: string | undefined = process.env.STRIPE_WEBHOOK_SECRET
): Promise<{received: true} | {error: string, message: string, code?: number}> => {
  if (!webhookSecret) {
    return { error: 'webhook_not_configured', message: 'STRIPE_WEBHOOK_SECRET is not set', code: 500 };
  }
  let event: Stripe.Event;
  try {
    if (!signature) throw new Error('missing signature');
    event = getStripe().webhooks.constructEvent(rawBody, signature, webhookSecret);
  } catch {
    // The reason is not echoed: it would help someone probing the endpoint.
    return { error: 'invalid_signature', message: 'Webhook signature verification failed', code: 403 };
  }
  return handle_stripe_webhook(event);
};

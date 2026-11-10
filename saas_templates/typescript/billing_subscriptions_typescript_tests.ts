import { Pool } from 'pg';
import Stripe from 'stripe';
import {
  CREATE_TABLES_SQL,
  initialize,
  create_subscription,
  change_plan,
  queue_refund,
  handle_stripe_webhook,
  set_clients,
  verify_and_handle_stripe_webhook,
  MARK_SUBSCRIPTION_PAST_DUE_SQL,
  MARK_CUSTOMER_ACTIVE_SUBSCRIPTIONS_PAST_DUE_SQL
} from './billing_subscriptions_typescript';

/*
 * Test changes 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP), each because the old line could not work:
 * - The fakes were installed by assigning require(module)._stripe / ._dbPool. Under babel (this runner) that sets a
 *   property the module never reads, and under native ES modules it throws, so the module kept the empty mocks that
 *   initialize() built. They are now installed with set_clients().
 * - Four assertions checked mockPool.query, but the module runs its SQL in a transaction on the client from
 *   pool.connect() (BEGIN ... COMMIT), and the same tests give that client the replies; the pool-level mock is never
 *   called. They now check that client's query mock, with the same SQL and parameters.
 * - Added: the spec's "webhook signature invalid -> 403 invalid_signature" test, which this file did not have.
 */

// Mock Stripe
jest.mock('stripe');

// Mock pg
jest.mock('pg', () => {
  const originalModule = jest.requireActual('pg');
  return {
    ...originalModule,
    Pool: jest.fn().mockImplementation(() => {
      return {
        query: jest.fn(),
        connect: jest.fn().mockResolvedValue({
          query: jest.fn(),
          release: jest.fn(),
          rollback: jest.fn(),
          commit: jest.fn()
        })
      };
    })
  };
});

describe('Billing Subscriptions System', () => {
  const mockStripe = {
    subscriptions: {
      create: jest.fn(),
      retrieve: jest.fn(),
      update: jest.fn()
    },
    webhooks: {
      constructEvent: jest.fn()
    }
  };

  beforeEach(() => {
    jest.clearAllMocks();
    process.env.STRIPE_SECRET_KEY = 'sk_test_...';
    process.env.STRIPE_WEBHOOK_SECRET = 'whsec_...';
    process.env.DATABASE_URL = 'postgres://test:test@localhost:5432/test';
    
    // Initialize with mocks
    initialize(process.env.STRIPE_SECRET_KEY, process.env.DATABASE_URL);
    
    // Replace internal stripe instance with mock
    set_clients({ stripe: mockStripe as any });
  });

  describe('create_subscription', () => {
    // BILL-01
    it('should create subscription successfully', async () => {
      const mockSubscription = {
        id: 'sub_123',
        customer: 'cus_123',
        status: 'active',
        current_period_end: Math.floor(Date.now() / 1000) + 2592000, // 30 days from now
        items: {
          data: [
            {
              price: {
                lookup_key: 'price_solo'
              }
            }
          ]
        }
      };
      mockStripe.subscriptions.create.mockResolvedValue(mockSubscription);
      
      const mockPool = {
        query: jest.fn(),
        connect: jest.fn().mockResolvedValue({
          query: jest.fn(),
          release: jest.fn(),
          rollback: jest.fn(),
          commit: jest.fn()
        })
      };
      set_clients({ pool: mockPool as any });
      
      mockPool.connect.mockResolvedValue({
        query: jest.fn().mockImplementation((text, params) => {
          if (text.includes('INSERT INTO subscriptions')) {
            return Promise.resolve({ rows: [{ id: 1, stripe_subscription_id: 'sub_123', customer_id: 'cus_123', tier: 'price_solo', status: 'active', created_at: new Date() }] });
          }
          if (text.includes('INSERT INTO audit_log')) {
            return Promise.resolve({});
          }
          return Promise.resolve({});
        }),
        release: jest.fn(),
        rollback: jest.fn(),
        commit: jest.fn()
      });

      const result = await create_subscription('cus_123', 'price_solo');
      expect(result).toEqual({
        success: true,
        subscription_id: 'sub_123',
        tier: 'price_solo',
        status: 'active',
        next_billing_date: expect.any(String)
      });
      expect(mockStripe.subscriptions.create).toHaveBeenCalledWith({
        customer: 'cus_123',
        items: [{ price: 'price_solo' }],
        expand: ['latest_invoice.payment_intent']
      });
    });

    // BILL-02
    it('should return invalid_tier error for invalid tier', async () => {
      const result = await create_subscription('cus_123', 'invalid_tier');
      expect(result).toEqual({ error: 'invalid_tier', message: 'Invalid tier: invalid_tier' });
    });
  });

  describe('change_plan', () => {
    // BILL-03
    it('should change plan successfully', async () => {
      const mockSubscription = {
        id: 'sub_123',
        items: {
          data: [
            {
              price: {
                lookup_key: 'price_team'
              }
            }
          ]
        },
        current_period_start: Math.floor(Date.now() / 1000),
        latest_invoice: {
          amount_due: -500 // $5 credit
        }
      };
      mockStripe.subscriptions.retrieve.mockResolvedValue({ id: 'sub_123', items: { data: [{ id: 'si_solo_1', price: { id: 'price_solo' } }] } });
      mockStripe.subscriptions.update.mockResolvedValue(mockSubscription);
      
      const mockPool = {
        query: jest.fn(),
        connect: jest.fn().mockResolvedValue({
          query: jest.fn(),
          release: jest.fn(),
          rollback: jest.fn(),
          commit: jest.fn()
        })
      };
      set_clients({ pool: mockPool as any });
      
      mockPool.connect.mockResolvedValue({
        query: jest.fn().mockImplementation((text, params) => {
          if (text.includes('SELECT stripe_subscription_id, tier FROM subscriptions')) {
            return Promise.resolve({ rows: [{ stripe_subscription_id: 'sub_123', tier: 'price_solo' }], rowCount: 1 });
          }
          if (text.includes('UPDATE subscriptions SET tier')) {
            return Promise.resolve({});
          }
          if (text.includes('INSERT INTO audit_log')) {
            return Promise.resolve({});
          }
          return Promise.resolve({});
        }),
        release: jest.fn(),
        rollback: jest.fn(),
        commit: jest.fn()
      });

      const result = await change_plan('sub_123', 'price_team');
      expect(result).toEqual({
        success: true,
        subscription_id: 'sub_123',
        old_tier: 'price_solo',
        new_tier: 'price_team',
        effective_date: expect.any(String),
        proration_credit: 5 // $5 credit
      });
      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: BILL-03 amendment: the update must name the existing item
      // (si_solo_1), or Stripe adds a second item and bills both plans; this used to expect a bare { price }.
      expect(mockStripe.subscriptions.retrieve).toHaveBeenCalledWith('sub_123');
      expect(mockStripe.subscriptions.update).toHaveBeenCalledTimes(1);
      expect(mockStripe.subscriptions.update).toHaveBeenCalledWith('sub_123', {
        items: [{ id: 'si_solo_1', price: 'price_team' }],
        proration_behavior: 'create_prorations',
        expand: ['latest_invoice']
      });
    });

    // BILL-03
    it('should return invalid_tier error for invalid new tier', async () => {
      const result = await change_plan('sub_123', 'invalid_tier');
      expect(result).toEqual({ error: 'invalid_tier', message: 'Invalid tier: invalid_tier' });
      expect(mockStripe.subscriptions.retrieve).not.toHaveBeenCalled();
      expect(mockStripe.subscriptions.update).not.toHaveBeenCalled();
    });

    /**
     * BILL-03: a subscription with zero or two items is 409 subscription_item_ambiguous and Stripe is never
     * updated, nor the database tier. In: mocked Stripe and pg. Out: assertions only. Why: spec amendment
     * 2026-11-10 (both checks come before any update). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: mocks only.
     */
    // BILL-03
    it('refuses a subscription without exactly one item before any update (409 subscription_item_ambiguous)', async () => {
      for (const data of [[], [{ id: 'si_a' }, { id: 'si_b' }]]) {
        jest.clearAllMocks();
        const clientQuery = jest.fn().mockImplementation((text: string) => {
          if (text.includes('SELECT stripe_subscription_id, tier FROM subscriptions')) {
            return Promise.resolve({ rows: [{ stripe_subscription_id: 'sub_123', tier: 'price_solo' }], rowCount: 1 });
          }
          return Promise.resolve({});
        });
        set_clients({ pool: { query: jest.fn(), connect: jest.fn().mockResolvedValue({ query: clientQuery, release: jest.fn() }) } as any });
        mockStripe.subscriptions.retrieve.mockResolvedValue({ id: 'sub_123', items: { data } });

        const result = await change_plan('sub_123', 'price_team');
        expect(result).toMatchObject({ error: 'subscription_item_ambiguous' });
        expect(mockStripe.subscriptions.update).not.toHaveBeenCalled();
        expect(clientQuery.mock.calls.some(([text]) => /UPDATE subscriptions SET tier/.test(text))).toBe(false);
      }
    });

    it('should return subscription_not_found error', async () => {
      const mockPool = {
        query: jest.fn(),
        connect: jest.fn().mockResolvedValue({
          query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
          release: jest.fn(),
          rollback: jest.fn(),
          commit: jest.fn()
        })
      };
      set_clients({ pool: mockPool as any });
      
      const result = await change_plan('sub_999', 'price_team');
      expect(result).toEqual({ error: 'subscription_not_found', message: 'Subscription not found: sub_999' });
    });
  });

  describe('queue_refund', () => {
    // BILL-04
    it('should queue refund successfully', async () => {
      const mockPool = {
        query: jest.fn(),
        connect: jest.fn().mockResolvedValue({
          query: jest.fn().mockImplementation((text, params) => {
            if (text.includes('SELECT id, amount, status FROM invoices')) {
              return Promise.resolve({ rows: [{ id: 1, amount: 1000, status: 'succeeded' }], rowCount: 1 });
            }
            if (text.includes('INSERT INTO refunds')) {
              return Promise.resolve({ rows: [{ id: 101 }] });
            }
            if (text.includes('INSERT INTO audit_log')) {
              return Promise.resolve({});
            }
            return Promise.resolve({});
          }),
          release: jest.fn(),
          rollback: jest.fn(),
          commit: jest.fn()
        })
      };
      set_clients({ pool: mockPool as any });
      
      const result = await queue_refund('in_123', 500, 'Customer requested', 'admin');
      expect(result).toEqual({
        success: true,
        refund_id: 101,
        status: 'queued',
        amount: 500,
        reason: 'Customer requested'
      });
      expect((await mockPool.connect()).query).toHaveBeenCalledWith(
        `INSERT INTO refunds (invoice_id, amount, status, reason, created_by)
         VALUES ($1, $2, 'queued', $3, $4)
         RETURNING id`,
        [1, 500, 'Customer requested', 'admin']
      );
    });

    // BILL-05
    it('should return refund_exceeds_invoice error', async () => {
      const mockPool = {
        query: jest.fn(),
        connect: jest.fn().mockResolvedValue({
          query: jest.fn().mockResolvedValue({ rows: [{ id: 1, amount: 300, status: 'succeeded' }], rowCount: 1 }),
          release: jest.fn(),
          rollback: jest.fn(),
          commit: jest.fn()
        })
      };
      set_clients({ pool: mockPool as any });
      
      const result = await queue_refund('in_123', 500, 'Customer requested', 'admin');
      expect(result).toEqual({ error: 'refund_exceeds_invoice', message: 'Refund amount 500 exceeds invoice amount 300' });
    });

    it('should return invoice_not_succeeded error', async () => {
      const mockPool = {
        query: jest.fn(),
        connect: jest.fn().mockResolvedValue({
          query: jest.fn().mockResolvedValue({ rows: [{ id: 1, amount: 500, status: 'open' }], rowCount: 1 }),
          release: jest.fn(),
          rollback: jest.fn(),
          commit: jest.fn()
        })
      };
      set_clients({ pool: mockPool as any });
      
      const result = await queue_refund('in_123', 500, 'Customer requested', 'admin');
      expect(result).toEqual({ error: 'invoice_not_succeeded', message: 'Invoice status is open, expected succeeded' });
    });
  });

  describe('handle_stripe_webhook', () => {
    // BILL-06
    it('should handle invoice.payment_succeeded', async () => {
      const mockEvent = {
        id: 'evt_123',
        type: 'invoice.payment_succeeded',
        data: {
          object: {
            id: 'in_123',
            customer: 'cus_123',
            amount_paid: 1000
          }
        }
      };
      
      const mockPool = {
        query: jest.fn(),
        connect: jest.fn().mockResolvedValue({
          query: jest.fn().mockImplementation((text, params) => {
            if (text.includes('SELECT id FROM events WHERE stripe_event_id = $1')) {
              return Promise.resolve({ rows: [], rowCount: 0 });
            }
            if (text.includes('INSERT INTO invoices')) {
              return Promise.resolve({});
            }
            if (text.includes('INSERT INTO audit_log')) {
              return Promise.resolve({});
            }
            if (text.includes('INSERT INTO events')) {
              return Promise.resolve({});
            }
            return Promise.resolve({});
          }),
          release: jest.fn(),
          rollback: jest.fn(),
          commit: jest.fn()
        })
      };
      set_clients({ pool: mockPool as any });
      
      const result = await handle_stripe_webhook(mockEvent);
      expect(result).toEqual({ received: true });
      expect((await mockPool.connect()).query).toHaveBeenCalledWith(
        `INSERT INTO invoices (stripe_invoice_id, customer_id, amount, status, paid_at)
         VALUES ($1, $2, $3, 'succeeded', NOW())
         ON CONFLICT (stripe_invoice_id) DO UPDATE SET
           status = EXCLUDED.status,
           paid_at = EXCLUDED.paid_at`,
        ['in_123', 'cus_123', 1000]
      );
    });

    // BILL-07
    it('should handle duplicate event (idempotency)', async () => {
      const mockEvent = {
        id: 'evt_123',
        type: 'invoice.payment_succeeded',
        data: {
          object: {
            id: 'in_123',
            customer: 'cus_123',
            amount_paid: 1000
          }
        }
      };
      
      const mockPool = {
        query: jest.fn(),
        connect: jest.fn().mockResolvedValue({
          query: jest.fn().mockImplementation((text, params) => {
            if (text.includes('SELECT id FROM events WHERE stripe_event_id = $1')) {
              return Promise.resolve({ rows: [{ id: 1 }], rowCount: 1 });
            }
            return Promise.resolve({});
          }),
          release: jest.fn(),
          rollback: jest.fn(),
          commit: jest.fn()
        })
      };
      set_clients({ pool: mockPool as any });
      
      const result = await handle_stripe_webhook(mockEvent);
      expect(result).toEqual({ received: true });
      // Should not process the event again
      expect((await mockPool.connect()).query).not.toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO invoices'),
        expect.any(Array)
      );
    });

    // BILL-08
    it('should handle customer.subscription.updated', async () => {
      const mockEvent = {
        id: 'evt_123',
        type: 'customer.subscription.updated',
        data: {
          object: {
            id: 'sub_123',
            customer: 'cus_123',
            items: {
              data: [
                {
                  price: {
                    lookup_key: 'price_team'
                  }
                }
              ]
            },
            status: 'active'
          }
        }
      };
      
      const mockPool = {
        query: jest.fn(),
        connect: jest.fn().mockResolvedValue({
          query: jest.fn().mockImplementation((text, params) => {
            if (text.includes('SELECT id FROM events WHERE stripe_event_id = $1')) {
              return Promise.resolve({ rows: [], rowCount: 0 });
            }
            if (text.includes('UPDATE subscriptions SET tier')) {
              return Promise.resolve({});
            }
            if (text.includes('INSERT INTO audit_log')) {
              return Promise.resolve({});
            }
            if (text.includes('SELECT tier FROM subscriptions')) {
              return Promise.resolve({ rows: [{ tier: 'price_solo' }] });
            }
            if (text.includes('INSERT INTO events')) {
              return Promise.resolve({});
            }
            return Promise.resolve({});
          }),
          release: jest.fn(),
          rollback: jest.fn(),
          commit: jest.fn()
        })
      };
      set_clients({ pool: mockPool as any });
      
      const result = await handle_stripe_webhook(mockEvent);
      expect(result).toEqual({ received: true });
      expect((await mockPool.connect()).query).toHaveBeenCalledWith(
        `UPDATE subscriptions SET 
         tier = $1, 
         status = $2, 
         updated_at = NOW() 
         WHERE stripe_subscription_id = $3`,
        ['price_team', 'active', 'sub_123']
      );
    });

    it('should return error on database failure', async () => {
      const mockEvent = {
        id: 'evt_123',
        type: 'invoice.payment_succeeded',
        data: {
          object: {
            id: 'in_123',
            customer: 'cus_123',
            amount_paid: 1000
          }
        }
      };
      
      const mockPool = {
        query: jest.fn(),
        connect: jest.fn().mockResolvedValue({
          query: jest.fn().mockRejectedValue(new Error('DB error')),
          release: jest.fn(),
          rollback: jest.fn(),
          commit: jest.fn()
        })
      };
      set_clients({ pool: mockPool as any });
      
      const result = await handle_stripe_webhook(mockEvent);
      expect(result).toEqual({ error: 'webhook_processing_error', message: 'DB error' });
    });

    /**
     * A client whose subscriptions table lives in memory: it applies the two past_due statements the way Postgres
     * would (the row filter is read from the statement: by subscription id or by customer, and only 'active' rows),
     * and answers everything else with an empty result. In: the starting rows. Out: { client, rows }.
     * Why 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): CodeRabbit review on PR 19, payment_failed marked
     * every subscription of the customer past_due, cancelled ones included. Touches: memory only.
     */
    const subscriptionsClient = (rows: Array<{ stripe_subscription_id: string; customer_id: string; status: string }>) => {
      const client = {
        query: jest.fn().mockImplementation((text: string, params: any[] = []) => {
          if (text.includes('SELECT id FROM events WHERE stripe_event_id = $1')) {
            return Promise.resolve({ rows: [], rowCount: 0 });
          }
          if (/^\s*UPDATE subscriptions SET status = 'past_due'/.test(text)) {
            const bySubscription = /WHERE stripe_subscription_id = \$1/.test(text);
            const byCustomer = /WHERE customer_id = \$1/.test(text);
            const activeOnly = /AND status = 'active'/.test(text);
            const notPastDueOnly = /AND status <> 'past_due'/.test(text);
            let rowCount = 0;
            for (const row of rows) {
              const keyMatches = bySubscription ? row.stripe_subscription_id === params[0]
                : byCustomer ? row.customer_id === params[0] : false;
              const statusMatches = activeOnly ? row.status === 'active' : notPastDueOnly ? row.status !== 'past_due' : true;
              if (keyMatches && statusMatches) { row.status = 'past_due'; rowCount++; }
            }
            return Promise.resolve({ rows: [], rowCount });
          }
          return Promise.resolve({ rows: [], rowCount: 0 });
        }),
        release: jest.fn(),
      };
      return { client, rows };
    };

    it('payment_failed marks only the invoice\'s subscription past_due; cancelled and other active ones untouched', async () => {
      const { client, rows } = subscriptionsClient([
        { stripe_subscription_id: 'sub_failed', customer_id: 'cus_123', status: 'active' },
        { stripe_subscription_id: 'sub_other', customer_id: 'cus_123', status: 'active' },
        { stripe_subscription_id: 'sub_old', customer_id: 'cus_123', status: 'cancelled' },
      ]);
      set_clients({ pool: { query: jest.fn(), connect: jest.fn().mockResolvedValue(client) } as any });

      const result = await handle_stripe_webhook({
        id: 'evt_failed_1', type: 'invoice.payment_failed',
        data: { object: { id: 'in_failed', customer: 'cus_123', subscription: 'sub_failed' } },
      } as any);

      expect(result).toEqual({ received: true });
      expect(client.query).toHaveBeenCalledWith(MARK_SUBSCRIPTION_PAST_DUE_SQL, ['sub_failed']);
      expect(rows.map((r) => [r.stripe_subscription_id, r.status])).toEqual([
        ['sub_failed', 'past_due'],
        ['sub_other', 'active'],
        ['sub_old', 'cancelled'],
      ]);
    });

    it('payment_failed with no subscription on the invoice marks only active rows; cancelled stays cancelled', async () => {
      const { client, rows } = subscriptionsClient([
        { stripe_subscription_id: 'sub_live', customer_id: 'cus_123', status: 'active' },
        { stripe_subscription_id: 'sub_old', customer_id: 'cus_123', status: 'cancelled' },
        { stripe_subscription_id: 'sub_else', customer_id: 'cus_999', status: 'active' },
      ]);
      set_clients({ pool: { query: jest.fn(), connect: jest.fn().mockResolvedValue(client) } as any });

      const result = await handle_stripe_webhook({
        id: 'evt_failed_2', type: 'invoice.payment_failed',
        data: { object: { id: 'in_oneoff', customer: 'cus_123', subscription: null } },
      } as any);

      expect(result).toEqual({ received: true });
      expect(client.query).toHaveBeenCalledWith(MARK_CUSTOMER_ACTIVE_SUBSCRIPTIONS_PAST_DUE_SQL, ['cus_123']);
      expect(rows.map((r) => [r.stripe_subscription_id, r.status])).toEqual([
        ['sub_live', 'past_due'],
        ['sub_old', 'cancelled'],
        ['sub_else', 'active'],
      ]);
    });

    // BILL-09
    it('should reject a webhook whose signature is invalid (403 invalid_signature)', async () => {
      const mockPool = { query: jest.fn(), connect: jest.fn() };
      set_clients({ pool: mockPool as any });
      mockStripe.webhooks.constructEvent.mockImplementation(() => {
        throw new Error('No signatures found matching the expected signature for payload');
      });

      const result = await verify_and_handle_stripe_webhook('{"id":"evt_forged"}', 't=1,v1=bad', 'whsec_test');
      expect(result).toEqual({ error: 'invalid_signature', message: 'Webhook signature verification failed', code: 403 });
      expect(mockStripe.webhooks.constructEvent).toHaveBeenCalledWith('{"id":"evt_forged"}', 't=1,v1=bad', 'whsec_test');
      // Nothing is written for an unverified event.
      expect(mockPool.connect).not.toHaveBeenCalled();
    });

    /**
     * BILL-10: a verified webhook (payment_succeeded) is acknowledged with { received: true } well inside Stripe's
     * 3-second budget. In: a mocked verified event and a mocked database client. Out: assertions only.
     * Why: spec BILL-10 had no test here. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: mocks only.
     */
    // BILL-10
    it('acknowledges a verified webhook with {received: true} in under 3 seconds', async () => {
      const client = {
        query: jest.fn().mockImplementation((text: string) =>
          Promise.resolve(text.includes('FROM events') ? { rows: [], rowCount: 0 } : {})),
        release: jest.fn(),
      };
      set_clients({ pool: { query: jest.fn(), connect: jest.fn().mockResolvedValue(client) } as any });
      mockStripe.webhooks.constructEvent.mockReturnValue({
        id: 'evt_fast', type: 'invoice.payment_succeeded',
        data: { object: { id: 'in_fast', customer: 'cus_123', amount_paid: 1000 } },
      });

      const started = Date.now();
      const result = await verify_and_handle_stripe_webhook('{"id":"evt_fast"}', 't=1,v1=ok', 'whsec_test');
      expect(result).toEqual({ received: true });
      expect(Date.now() - started).toBeLessThan(3000);
    });
  });
});
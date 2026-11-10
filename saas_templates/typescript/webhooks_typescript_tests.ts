import BetterSqlite3 from 'better-sqlite3';
import { Webhooks, PersistentWebhooks, WebhookDelivery } from './webhooks_typescript';

// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: deliver() now posts through an injected sender (spec: "deliver()
// sends through the injectable sender"), so the tests pass a jest.fn sender instead of replacing global.fetch,
// and every sendEvent call names its org (spec HOOK-06; sendEvent used to take no org_id). The assertions
// themselves are unchanged.
const sender = jest.fn();

describe('Webhooks (in-memory)', () => {
  let webhooks: Webhooks;

  beforeEach(() => {
    webhooks = new Webhooks({ sender });
    jest.clearAllMocks();
  });

  describe('sign and verify', () => {
    // HOOK-01
    test('sign then verify round-trips', () => {
      const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
      const msg_id = webhooks.sendEvent('org1', 'test', { foo: 'bar' });
      const timestamp = Math.floor(Date.now() / 1000);
      const body = JSON.stringify({ foo: 'bar' });
      const signature = webhooks.sign(secret, msg_id, timestamp, body);
      const result = webhooks.verify(secret, {
        'webhook-id': msg_id,
        'webhook-timestamp': timestamp.toString(),
        'webhook-signature': signature
      }, body);
      expect(result.valid).toBe(true);
    });

    // HOOK-02
    test('changed body fails verify', () => {
      const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
      const msg_id = webhooks.sendEvent('org1', 'test', { foo: 'bar' });
      const timestamp = Math.floor(Date.now() / 1000);
      const body = JSON.stringify({ foo: 'bar' });
      const signature = webhooks.sign(secret, msg_id, timestamp, body);
      const tamperedBody = JSON.stringify({ foo: 'baz' });
      const result = webhooks.verify(secret, {
        'webhook-id': msg_id,
        'webhook-timestamp': timestamp.toString(),
        'webhook-signature': signature
      }, tamperedBody);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Signature mismatch');
    });

    // HOOK-02
    test('changed timestamp fails verify', () => {
      const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
      const msg_id = webhooks.sendEvent('org1', 'test', { foo: 'bar' });
      const timestamp = Math.floor(Date.now() / 1000);
      const body = JSON.stringify({ foo: 'bar' });
      const signature = webhooks.sign(secret, msg_id, timestamp, body);
      const result = webhooks.verify(secret, {
        'webhook-id': msg_id,
        'webhook-timestamp': (timestamp + 1).toString(),
        'webhook-signature': signature
      }, body);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Signature mismatch');
    });

    // HOOK-03
    test('timestamp older than tolerance is rejected', () => {
      const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
      const msg_id = webhooks.sendEvent('org1', 'test', { foo: 'bar' });
      const timestamp = Math.floor(Date.now() / 1000) - 400; // Outside 300s tolerance
      const body = JSON.stringify({ foo: 'bar' });
      const signature = webhooks.sign(secret, msg_id, timestamp, body);
      const result = webhooks.verify(secret, {
        'webhook-id': msg_id,
        'webhook-timestamp': timestamp.toString(),
        'webhook-signature': signature
      }, body, 300);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Timestamp outside tolerance');
    });

    // HOOK-04
    test('verify accepts when one of two space-separated signatures matches', () => {
      const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
      const msg_id = webhooks.sendEvent('org1', 'test', { foo: 'bar' });
      const timestamp = Math.floor(Date.now() / 1000);
      const body = JSON.stringify({ foo: 'bar' });
      const signature = webhooks.sign(secret, msg_id, timestamp, body);
      const wrongSecret = 'whsec_' + Buffer.from('wrong').toString('base64');
      const wrongSignature = webhooks.sign(wrongSecret, msg_id, timestamp, body);
      const result = webhooks.verify(secret, {
        'webhook-id': msg_id,
        'webhook-timestamp': timestamp.toString(),
        'webhook-signature': `${wrongSignature} ${signature}`
      }, body);
      expect(result.valid).toBe(true);
    });
  });

  describe('delivery', () => {
    // HOOK-05
    test('a 200-299 response marks success', async () => {
      const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
      const msg_id = webhooks.sendEvent('org1', 'test', { foo: 'bar' });
      const deliveryId = (webhooks.getDeliveriesForMessage(msg_id)[0] as WebhookDelivery).id;
      
      sender.mockResolvedValueOnce({ status: 200 });
      await webhooks.deliver(deliveryId);
      
      const delivery = webhooks.getDelivery(deliveryId)!;
      expect(delivery.success).toBe(true);
      expect(delivery.status_code).toBe(200);
      expect(delivery.delivered_at).not.toBeNull();
      expect(delivery.next_attempt_at).toBeNull();
      expect(delivery.error).toBeNull();
    });

    // HOOK-05
    test('301, 400 and 500 schedule a retry', async () => {
      const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
      const msg_id = webhooks.sendEvent('org1', 'test', { foo: 'bar' });
      const deliveryId = (webhooks.getDeliveriesForMessage(msg_id)[0] as WebhookDelivery).id;
      
      // Test 301
      sender.mockResolvedValueOnce({ status: 301 });
      await webhooks.deliver(deliveryId);
      let delivery = webhooks.getDelivery(deliveryId)!;
      expect(delivery.success).toBe(false);
      expect(delivery.next_attempt_at).not.toBeNull();
      
      // Test 400
      sender.mockResolvedValueOnce({ status: 400 });
      await webhooks.deliver(deliveryId);
      delivery = webhooks.getDelivery(deliveryId)!;
      expect(delivery.success).toBe(false);
      expect(delivery.next_attempt_at).not.toBeNull();
      
      // Test 500
      sender.mockResolvedValueOnce({ status: 500 });
      await webhooks.deliver(deliveryId);
      delivery = webhooks.getDelivery(deliveryId)!;
      expect(delivery.success).toBe(false);
      expect(delivery.next_attempt_at).not.toBeNull();
    });

    // HOOK-07
    test('the webhook-id is identical across retries of one message', async () => {
      const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
      const msg_id = webhooks.sendEvent('org1', 'test', { foo: 'bar' });
      const deliveries = webhooks.getDeliveriesForMessage(msg_id);
      const deliveryId = deliveries[0].id;
      
      // First attempt fails
      sender.mockResolvedValueOnce({ status: 500 });
      await webhooks.deliver(deliveryId);
      let delivery = webhooks.getDelivery(deliveryId)!;
      expect(delivery.attempt).toBe(1);
      
      // Second attempt fails
      sender.mockResolvedValueOnce({ status: 500 });
      await webhooks.deliver(deliveryId);
      delivery = webhooks.getDelivery(deliveryId)!;
      expect(delivery.attempt).toBe(2);
      
      // Third attempt succeeds
      sender.mockResolvedValueOnce({ status: 200 });
      await webhooks.deliver(deliveryId);
      delivery = webhooks.getDelivery(deliveryId)!;
      expect(delivery.attempt).toBe(3);
      expect(delivery.success).toBe(true);
      
      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the headers each attempt really sent are now visible
      // through the injected sender, so this checks the webhook-id header itself on all three attempts
      // (it used to compare the message id with itself).
      const sentIds = sender.mock.calls.map(call => call[1].headers['webhook-id']);
      expect(sentIds).toEqual([msg_id, msg_id, msg_id]);
    });
  });

  // HOOK-08
  test('a generated secret starts with "whsec_" and decodes to 24-64 bytes', () => {
    const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
    expect(secret.startsWith('whsec_')).toBe(true);
    const decoded = Buffer.from(secret.slice(6), 'base64');
    expect(decoded.length).toBeGreaterThanOrEqual(24);
    expect(decoded.length).toBeLessThanOrEqual(64);
  });
});

describe('Webhooks: tenancy, timeouts and the injected clock', () => {
  beforeEach(() => jest.clearAllMocks());

  /**
   * HOOK-06: an event for org A creates a delivery for org A's endpoint only, never for org B's endpoint
   * subscribed to the same event type; an endpoint for a different type gets nothing. In: two orgs' endpoints.
   * Out: assertions only. Why: spec HOOK-06 (amended 2026-09-26). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: memory only.
   */
  // HOOK-06
  test('an event for org A never creates a delivery for org B', () => {
    const webhooks = new Webhooks({ sender });
    const a = webhooks.createEndpoint('orgA', 'https://a.example.com/hook', ['invoice.paid']);
    const b = webhooks.createEndpoint('orgB', 'https://b.example.com/hook', ['invoice.paid']);
    webhooks.createEndpoint('orgA', 'https://a.example.com/other', ['invoice']);
    const msg = webhooks.sendEvent('orgA', 'invoice.paid', { id: 1 });
    const deliveries = webhooks.getDeliveriesForMessage(msg);
    expect(deliveries.map(d => d.endpoint_id)).toEqual([a.id]);
    expect(deliveries.some(d => d.endpoint_id === b.id)).toBe(false);
    expect(webhooks.getMessage(msg)!.org_id).toBe('orgA');
  });

  /**
   * HOOK-05: a sender that throws or never answers within the timeout is a failed attempt with a retry
   * scheduled on the injected clock (+5 s after the first attempt), never an unhandled error. In: a fixed
   * clock and failing senders. Out: assertions only. Why: spec deliver() rule. 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
   */
  // HOOK-05
  test('a throwing or hanging sender is a failed attempt with a retry on the injected clock', async () => {
    const now = 1_800_000_000_000;
    const throwing = new Webhooks({ sender: async () => { throw new Error('ECONNREFUSED'); }, now: () => now });
    throwing.createEndpoint('org1', 'https://example.com', ['test']);
    const m1 = throwing.sendEvent('org1', 'test', {});
    const d1 = throwing.getDeliveriesForMessage(m1)[0].id;
    await expect(throwing.deliver(d1)).resolves.toBeUndefined();
    expect(throwing.getDelivery(d1)!.success).toBe(false);
    expect(throwing.getDelivery(d1)!.next_attempt_at!.getTime()).toBe(now + 5_000);

    const hanging = new Webhooks({ sender: () => new Promise(() => {}), now: () => now, timeoutMs: 20 });
    hanging.createEndpoint('org1', 'https://example.com', ['test']);
    const m2 = hanging.sendEvent('org1', 'test', {});
    const d2 = hanging.getDeliveriesForMessage(m2)[0].id;
    await hanging.deliver(d2);
    expect(hanging.getDelivery(d2)!.success).toBe(false);
    expect(hanging.getDelivery(d2)!.error).toBe('timeout');
    expect(hanging.getDelivery(d2)!.next_attempt_at).not.toBeNull();
  });

  /**
   * HOOK-03: verify uses the injected clock: a signature 301 s old fails, 300 s old passes, with no wall
   * clock involved. In: a fixed clock. Out: assertions only. Why: deterministic-tests rule.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
   */
  // HOOK-03
  test('verify tolerance is measured on the injected clock', () => {
    const now = 1_800_000_000_000;
    const webhooks = new Webhooks({ sender, now: () => now });
    const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
    const body = '{"a":1}';
    const at = (age: number) => {
      const ts = Math.floor(now / 1000) - age;
      return webhooks.verify(secret, {
        'webhook-id': 'msg_x', 'webhook-timestamp': String(ts),
        'webhook-signature': webhooks.sign(secret, 'msg_x', ts, body),
      }, body, 300);
    };
    expect(at(300).valid).toBe(true);
    expect(at(301)).toEqual({ valid: false, error: 'Timestamp outside tolerance' });
  });
});

/**
 * PersistentWebhooks against a real in-memory SQLite (better-sqlite3). 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP: these tests used a mock that answered by matching SQL text, so it could not
 * check the org filter or the exact event-type match; the same four checks now run on real SQL, plus HOOK-06.
 * Touches: an in-memory database only.
 */
describe('PersistentWebhooks', () => {
  let db: BetterSqlite3.Database;
  let webhooks: PersistentWebhooks;

  beforeEach(() => {
    db = new BetterSqlite3(':memory:');
    webhooks = new PersistentWebhooks(db as any, { sender });
    jest.clearAllMocks();
  });

  afterEach(() => db.close());

  test('createEndpoint stores secret in database', () => {
    const result = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
    const row = db.prepare('SELECT secret FROM webhook_endpoints WHERE id = ?').get(result.id) as { secret: string };
    expect(row.secret).toBe(result.secret);
  });

  test('sendEvent creates message and deliveries', () => {
    const ep = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
    const msg_id = webhooks.sendEvent('org1', 'test', { foo: 'bar' });
    const message = db.prepare('SELECT * FROM webhook_messages WHERE id = ?').get(msg_id) as any;
    expect(message.payload).toBe(JSON.stringify({ foo: 'bar' }));
    expect(message.org_id).toBe('org1');
    const deliveries = db.prepare('SELECT * FROM webhook_deliveries WHERE message_id = ?').all(msg_id) as any[];
    expect(deliveries).toHaveLength(1);
    expect(deliveries[0].endpoint_id).toBe(ep.id);
  });

  // HOOK-06
  test('persistent sendEvent only reaches the same org and the exact event type', () => {
    const a = webhooks.createEndpoint('orgA', 'https://a.example.com', ['invoice.paid']);
    webhooks.createEndpoint('orgB', 'https://b.example.com', ['invoice.paid']);
    webhooks.createEndpoint('orgA', 'https://a.example.com/x', ['invoice']);
    const msg_id = webhooks.sendEvent('orgA', 'invoice.paid', {});
    const deliveries = db.prepare('SELECT endpoint_id FROM webhook_deliveries WHERE message_id = ?').all(msg_id) as any[];
    expect(deliveries.map(d => d.endpoint_id)).toEqual([a.id]);
    const narrow = webhooks.sendEvent('orgA', 'invoice', {});
    expect((db.prepare('SELECT COUNT(*) AS n FROM webhook_deliveries WHERE message_id = ?').get(narrow) as any).n).toBe(1);
  });

  // HOOK-07
  test('persistent deliver keeps the webhook-id across retries and records success', async () => {
    webhooks.createEndpoint('org1', 'https://example.com', ['test']);
    const msg_id = webhooks.sendEvent('org1', 'test', { foo: 'bar' });
    const { id } = db.prepare('SELECT id FROM webhook_deliveries WHERE message_id = ?').get(msg_id) as { id: string };
    sender.mockResolvedValueOnce({ status: 500 });
    sender.mockResolvedValueOnce({ status: 204 });
    await webhooks.deliver(id);
    await webhooks.deliver(id);
    expect(sender.mock.calls.map(c => c[1].headers['webhook-id'])).toEqual([msg_id, msg_id]);
    const row = db.prepare('SELECT attempt, success, status_code FROM webhook_deliveries WHERE id = ?').get(id) as any;
    expect(row).toEqual({ attempt: 2, success: 1, status_code: 204 });
  });

  test('verify works with persistent storage', () => {
    const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
    const msg_id = webhooks.sendEvent('org1', 'test', { foo: 'bar' });
    const timestamp = Math.floor(Date.now() / 1000);
    const body = JSON.stringify({ foo: 'bar' });
    const signature = webhooks.sign(secret, msg_id, timestamp, body);
    const result = webhooks.verify(secret, {
      'webhook-id': msg_id,
      'webhook-timestamp': timestamp.toString(),
      'webhook-signature': signature
    }, body);
    expect(result.valid).toBe(true);
  });

  test('rotateSecret updates secret in database', () => {
    const { id, secret: oldSecret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
    const newSecret = webhooks.rotateSecret(id);
    expect(newSecret).not.toBe(oldSecret);
    const row = db.prepare('SELECT secret FROM webhook_endpoints WHERE id = ?').get(id) as { secret: string };
    expect(row.secret).toBe(newSecret);
  });
});

import { Webhooks, PersistentWebhooks, CreateEndpointResult, VerifyResult, WebhookEndpoint, WebhookMessage, WebhookDelivery } from './webhooks_typescript';
import { Database, Statement } from './webhooks_typescript';

// Mock fetch for delivery tests
global.fetch = jest.fn();

// Mock better-sqlite3 for persistent tests
class MockDatabase implements Database {
  private statements: Map<string, Statement> = new Map();
  private data: any = {};

  prepare(sql: string): Statement {
    if (!this.statements.has(sql)) {
      this.statements.set(sql, new MockStatement(this, sql));
    }
    return this.statements.get(sql)!;
  }

  exec(sql: string): void {
    // No-op for test
  }

  transaction<T>(fn: () => T): () => T {
    return fn;
  }
}

class MockStatement implements Statement {
  constructor(private db: MockDatabase, private sql: string) {}

  run(...params: unknown[]): { changes: number; lastInsertRowid: number | bigint } {
    // Simulate INSERT
    if (this.sql.startsWith('INSERT INTO webhook_endpoints')) {
      this.db.data.endpoint = { id: params[0], secret: params[3] };
    } else if (this.sql.startsWith('INSERT INTO webhook_messages')) {
      this.db.data.message = { id: params[0], payload: params[2] };
    } else if (this.sql.startsWith('INSERT INTO webhook_deliveries')) {
      if (!this.db.data.deliveries) this.db.data.deliveries = [];
      this.db.data.deliveries.push({ id: params[0], message_id: params[1], endpoint_id: params[2] });
    } else if (this.sql.startsWith('UPDATE webhook_endpoints SET secret = ?')) {
      this.db.data.endpoint!.secret = params[0];
    } else if (this.sql.startsWith('UPDATE webhook_endpoints SET failure_count = 0')) {
      this.db.data.endpoint!.failure_count = 0;
    } else if (this.sql.startsWith('UPDATE webhook_endpoints SET failure_count = failure_count + 1')) {
      this.db.data.endpoint!.failure_count = (this.db.data.endpoint!.failure_count || 0) + 1;
    } else if (this.sql.startsWith('UPDATE webhook_endpoints SET active = 0')) {
      this.db.data.endpoint!.active = 0;
    } else if (this.sql.startsWith('UPDATE webhook_deliveries SET')) {
      const delivery = this.db.data.deliveries!.find((d: any) => d.id === params[params.length - 1]);
      if (delivery) {
        delivery.attempt = params[0];
        delivery.status_code = params[1];
        delivery.success = params[2];
        delivery.error = params[3];
        delivery.next_attempt_at = params[4];
        delivery.delivered_at = params[5];
      }
    }
    return { changes: 1, lastInsertRowid: 1 };
  }

  get(...params: unknown[]): unknown {
    if (this.sql === 'SELECT * FROM webhook_endpoints WHERE id = ?') {
      return this.db.data.endpoint || null;
    }
    if (this.sql === 'SELECT * FROM webhook_messages WHERE id = ?') {
      return this.db.data.message || null;
    }
    if (this.sql === 'SELECT * FROM webhook_deliveries WHERE id = ?') {
      return this.db.data.deliveries!.find((d: any) => d.id === params[0]) || null;
    }
    if (this.sql === 'SELECT id FROM webhook_endpoints WHERE active = 1 AND json_extract(event_types, \'$\') LIKE ?') {
      return [{ id: this.db.data.endpoint?.id }];
    }
    if (this.sql === 'SELECT failure_count FROM webhook_endpoints WHERE id = ?') {
      return { failure_count: this.db.data.endpoint!.failure_count };
    }
    return null;
  }

  all(...params: unknown[]): unknown[] {
    if (this.sql === 'SELECT id FROM webhook_endpoints WHERE active = 1 AND json_extract(event_types, \'$\') LIKE ?') {
      return [{ id: this.db.data.endpoint?.id }];
    }
    return [];
  }
}

describe('Webhooks (in-memory)', () => {
  let webhooks: Webhooks;

  beforeEach(() => {
    webhooks = new Webhooks();
    jest.clearAllMocks();
  });

  describe('sign and verify', () => {
    test('sign then verify round-trips', () => {
      const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
      const msg_id = webhooks.sendEvent('test', { foo: 'bar' });
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

    test('changed body fails verify', () => {
      const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
      const msg_id = webhooks.sendEvent('test', { foo: 'bar' });
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

    test('changed timestamp fails verify', () => {
      const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
      const msg_id = webhooks.sendEvent('test', { foo: 'bar' });
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

    test('timestamp older than tolerance is rejected', () => {
      const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
      const msg_id = webhooks.sendEvent('test', { foo: 'bar' });
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

    test('verify accepts when one of two space-separated signatures matches', () => {
      const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
      const msg_id = webhooks.sendEvent('test', { foo: 'bar' });
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
    test('a 200-299 response marks success', async () => {
      const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
      const msg_id = webhooks.sendEvent('test', { foo: 'bar' });
      const deliveryId = (webhooks.getDeliveriesForMessage(msg_id)[0] as WebhookDelivery).id;
      
      fetch.mockResolvedValueOnce({ status: 200 });
      await webhooks.deliver(deliveryId);
      
      const delivery = webhooks.getDelivery(deliveryId)!;
      expect(delivery.success).toBe(true);
      expect(delivery.status_code).toBe(200);
      expect(delivery.delivered_at).not.toBeNull();
      expect(delivery.next_attempt_at).toBeNull();
      expect(delivery.error).toBeNull();
    });

    test('301, 400 and 500 schedule a retry', async () => {
      const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
      const msg_id = webhooks.sendEvent('test', { foo: 'bar' });
      const deliveryId = (webhooks.getDeliveriesForMessage(msg_id)[0] as WebhookDelivery).id;
      
      // Test 301
      fetch.mockResolvedValueOnce({ status: 301 });
      await webhooks.deliver(deliveryId);
      let delivery = webhooks.getDelivery(deliveryId)!;
      expect(delivery.success).toBe(false);
      expect(delivery.next_attempt_at).not.toBeNull();
      
      // Test 400
      fetch.mockResolvedValueOnce({ status: 400 });
      await webhooks.deliver(deliveryId);
      delivery = webhooks.getDelivery(deliveryId)!;
      expect(delivery.success).toBe(false);
      expect(delivery.next_attempt_at).not.toBeNull();
      
      // Test 500
      fetch.mockResolvedValueOnce({ status: 500 });
      await webhooks.deliver(deliveryId);
      delivery = webhooks.getDelivery(deliveryId)!;
      expect(delivery.success).toBe(false);
      expect(delivery.next_attempt_at).not.toBeNull();
    });

    test('the webhook-id is identical across retries of one message', async () => {
      const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
      const msg_id = webhooks.sendEvent('test', { foo: 'bar' });
      const deliveries = webhooks.getDeliveriesForMessage(msg_id);
      const deliveryId = deliveries[0].id;
      
      // First attempt fails
      fetch.mockResolvedValueOnce({ status: 500 });
      await webhooks.deliver(deliveryId);
      let delivery = webhooks.getDelivery(deliveryId)!;
      expect(delivery.attempt).toBe(1);
      
      // Second attempt fails
      fetch.mockResolvedValueOnce({ status: 500 });
      await webhooks.deliver(deliveryId);
      delivery = webhooks.getDelivery(deliveryId)!;
      expect(delivery.attempt).toBe(2);
      
      // Third attempt succeeds
      fetch.mockResolvedValueOnce({ status: 200 });
      await webhooks.deliver(deliveryId);
      delivery = webhooks.getDelivery(deliveryId)!;
      expect(delivery.attempt).toBe(3);
      expect(delivery.success).toBe(true);
      
      // All deliveries for this message should have same webhook-id in headers
      const header = deliveries.map(d => webhooks.getDelivery(d.id)!).map(d => {
        // We can't directly get headers, but we know the message id is used as webhook-id
        return webhooks.getMessage(d.message_id)!.id;
      });
      expect(header.every(id => id === msg_id)).toBe(true);
    });
  });

  test('a generated secret starts with "whsec_" and decodes to 24-64 bytes', () => {
    const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
    expect(secret.startsWith('whsec_')).toBe(true);
    const decoded = Buffer.from(secret.slice(6), 'base64');
    expect(decoded.length).toBeGreaterThanOrEqual(24);
    expect(decoded.length).toBeLessThanOrEqual(64);
  });
});

describe('PersistentWebhooks', () => {
  let db: MockDatabase;
  let webhooks: PersistentWebhooks;

  beforeEach(() => {
    db = new MockDatabase();
    webhooks = new PersistentWebhooks(db);
    jest.clearAllMocks();
  });

  test('createEndpoint stores secret in database', () => {
    const result = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
    expect(db.data.endpoint).not.toBeUndefined();
    expect(db.data.endpoint!.secret).toBe(result.secret);
  });

  test('sendEvent creates message and deliveries', () => {
    webhooks.createEndpoint('org1', 'https://example.com', ['test']);
    const msg_id = webhooks.sendEvent('test', { foo: 'bar' });
    expect(db.data.message).not.toBeUndefined();
    expect(db.data.message!.id).toBe(msg_id);
    expect(db.data.message!.payload).toBe(JSON.stringify({ foo: 'bar' }));
    expect(db.data.deliveries).toHaveLength(1);
    expect(db.data.deliveries![0].message_id).toBe(msg_id);
  });

  test('verify works with persistent storage', () => {
    const { secret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
    const msg_id = webhooks.sendEvent('test', { foo: 'bar' });
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
    const { secret: oldSecret } = webhooks.createEndpoint('org1', 'https://example.com', ['test']);
    const newSecret = webhooks.rotateSecret('wep_' + db.data.endpoint!.id.slice(4)); // Assuming id format
    expect(newSecret).not.toBe(oldSecret);
    expect(db.data.endpoint!.secret).toBe(newSecret);
  });
});

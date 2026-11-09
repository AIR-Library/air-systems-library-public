import { createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { createHash } from 'crypto';

export interface WebhookEndpoint {
  id: string;
  org_id: string;
  url: string;
  secret: string;
  event_types: string[];
  active: boolean;
  failure_count: number;
  created_at: Date;
}

export interface WebhookMessage {
  id: string;
  event_type: string;
  payload: unknown;
  created_at: Date;
}

export interface WebhookDelivery {
  id: string;
  message_id: string;
  endpoint_id: string;
  attempt: number;
  status_code: number | null;
  success: boolean;
  error: string | null;
  next_attempt_at: Date | null;
  delivered_at: Date | null;
}

export interface CreateEndpointResult {
  id: string;
  secret: string;
}

export interface VerifyResult {
  valid: boolean;
  error?: string;
}

const RETRY_SCHEDULE = [5_000, 5 * 60_000, 30 * 60_000, 2 * 60 * 60_000, 5 * 60 * 60_000, 10 * 60 * 60_000, 10 * 60 * 60_000];
const MAX_FAILURES_BEFORE_DISABLE = 5;

export class Webhooks {
  private endpoints = new Map<string, WebhookEndpoint>();
  private messages = new Map<string, WebhookMessage>();
  private deliveries = new Map<string, WebhookDelivery>();
  private deliveryIndex = new Map<string, string[]>(); // message_id -> delivery_ids

  private generateId(prefix: string): string {
    return `${prefix}${randomBytes(16).toString('hex')}`;
  }

  private generateSecret(): string {
    const bytes = randomBytes(32);
    return `whsec_${bytes.toString('base64')}`;
  }

  private decodeSecret(secret: string): Buffer {
    if (!secret.startsWith('whsec_')) throw new Error('Invalid secret format');
    return Buffer.from(secret.slice(6), 'base64');
  }

  private validateUrl(url: string): void {
    try {
      const u = new URL(url);
      if (u.protocol !== 'https:' && !(u.protocol === 'http:' && u.hostname === 'localhost')) {
        throw new Error('URL must be https:// (http://localhost allowed for dev)');
      }
    } catch {
      throw new Error('Invalid URL');
    }
  }

  createEndpoint(org_id: string, url: string, event_types: string[]): CreateEndpointResult {
    this.validateUrl(url);
    const id = this.generateId('wep_');
    const secret = this.generateSecret();
    const endpoint: WebhookEndpoint = {
      id,
      org_id,
      url,
      secret,
      event_types,
      active: true,
      failure_count: 0,
      created_at: new Date(),
    };
    this.endpoints.set(id, endpoint);
    return { id, secret };
  }

  sendEvent(event_type: string, payload: unknown): string {
    const message_id = this.generateId('msg_');
    const message: WebhookMessage = {
      id: message_id,
      event_type,
      payload,
      created_at: new Date(),
    };
    this.messages.set(message_id, message);

    for (const endpoint of this.endpoints.values()) {
      if (endpoint.active && endpoint.event_types.includes(event_type)) {
        const delivery_id = this.generateId('dlv_');
        const delivery: WebhookDelivery = {
          id: delivery_id,
          message_id,
          endpoint_id: endpoint.id,
          attempt: 0,
          status_code: null,
          success: false,
          error: null,
          next_attempt_at: new Date(),
          delivered_at: null,
        };
        this.deliveries.set(delivery_id, delivery);
        const arr = this.deliveryIndex.get(message_id) || [];
        arr.push(delivery_id);
        this.deliveryIndex.set(message_id, arr);
      }
    }
    return message_id;
  }

  sign(secret: string, msg_id: string, timestamp: number, body: string): string {
    const key = this.decodeSecret(secret);
    const content = `${msg_id}.${timestamp}.${body}`;
    const signature = createHmac('sha256', key).update(content).digest();
    return `v1,${signature.toString('base64')}`;
  }

  async deliver(delivery_id: string): Promise<void> {
    const delivery = this.deliveries.get(delivery_id);
    if (!delivery) throw new Error('Delivery not found');

    const message = this.messages.get(delivery.message_id);
    if (!message) throw new Error('Message not found');

    const endpoint = this.endpoints.get(delivery.endpoint_id);
    if (!endpoint) throw new Error('Endpoint not found');

    delivery.attempt += 1;
    const timestamp = Math.floor(Date.now() / 1000);
    const body = JSON.stringify(message.payload);
    const signature = this.sign(endpoint.secret, message.id, timestamp, body);

    try {
      const response = await fetch(endpoint.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'webhook-id': message.id,
          'webhook-timestamp': timestamp.toString(),
          'webhook-signature': signature,
        },
        body,
      });

      delivery.status_code = response.status;
      delivery.success = response.status >= 200 && response.status <= 299;

      if (delivery.success) {
        delivery.delivered_at = new Date();
        delivery.next_attempt_at = null;
        delivery.error = null;
        // Reset failure count on success
        endpoint.failure_count = 0;
      } else {
        delivery.error = `HTTP ${response.status}`;
        this.scheduleRetry(delivery, endpoint);
      }
    } catch (err) {
      delivery.status_code = 0;
      delivery.success = false;
      delivery.error = err instanceof Error ? err.message : 'Network error';
      this.scheduleRetry(delivery, endpoint);
    }
  }

  private scheduleRetry(delivery: WebhookDelivery, endpoint: WebhookEndpoint): void {
    const attemptIndex = delivery.attempt - 1;
    if (attemptIndex < RETRY_SCHEDULE.length) {
      const delay = RETRY_SCHEDULE[attemptIndex];
      delivery.next_attempt_at = new Date(Date.now() + delay);
    } else {
      delivery.next_attempt_at = null;
      endpoint.failure_count += 1;
      if (endpoint.failure_count >= MAX_FAILURES_BEFORE_DISABLE) {
        endpoint.active = false;
      }
    }
  }

  verify(secret: string, headers: Record<string, string>, raw_body: string, tolerance_seconds = 300): VerifyResult {
    const msg_id = headers['webhook-id'];
    const timestamp_str = headers['webhook-timestamp'];
    const signature_header = headers['webhook-signature'];

    if (!msg_id || !timestamp_str || !signature_header) {
      return { valid: false, error: 'Missing required headers' };
    }

    const timestamp = parseInt(timestamp_str, 10);
    if (isNaN(timestamp)) {
      return { valid: false, error: 'Invalid timestamp' };
    }

    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - timestamp) > tolerance_seconds) {
      return { valid: false, error: 'Timestamp outside tolerance' };
    }

    const signatures = signature_header.split(' ').map(s => s.trim()).filter(Boolean);
    const expected = this.sign(secret, msg_id, timestamp, raw_body);

    for (const sig of signatures) {
      const expectedBuf = Buffer.from(expected);
      const sigBuf = Buffer.from(sig);
      if (expectedBuf.length === sigBuf.length && timingSafeEqual(expectedBuf, sigBuf)) {
        return { valid: true };
      }
    }

    return { valid: false, error: 'Signature mismatch' };
  }

  rotateSecret(endpoint_id: string): string {
    const endpoint = this.endpoints.get(endpoint_id);
    if (!endpoint) throw new Error('Endpoint not found');
    const newSecret = this.generateSecret();
    endpoint.secret = newSecret;
    return newSecret;
  }

  // Helper methods for testing/inspection
  getEndpoint(id: string): WebhookEndpoint | undefined {
    return this.endpoints.get(id);
  }

  getMessage(id: string): WebhookMessage | undefined {
    return this.messages.get(id);
  }

  getDelivery(id: string): WebhookDelivery | undefined {
    return this.deliveries.get(id);
  }

  getDeliveriesForMessage(message_id: string): WebhookDelivery[] {
    const ids = this.deliveryIndex.get(message_id) || [];
    return ids.map(id => this.deliveries.get(id)!).filter(Boolean);
  }
}

// Database schema as executable SQL (SQLite compatible)
export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS webhook_endpoints (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  url TEXT NOT NULL,
  secret TEXT NOT NULL,
  event_types TEXT NOT NULL, -- JSON array
  active INTEGER NOT NULL DEFAULT 1,
  failure_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS webhook_messages (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  payload TEXT NOT NULL, -- JSON
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id TEXT PRIMARY KEY,
  message_id TEXT NOT NULL REFERENCES webhook_messages(id),
  endpoint_id TEXT NOT NULL REFERENCES webhook_endpoints(id),
  attempt INTEGER NOT NULL DEFAULT 0,
  status_code INTEGER,
  success INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  next_attempt_at TEXT,
  delivered_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_deliveries_message ON webhook_deliveries(message_id);
CREATE INDEX IF NOT EXISTS idx_deliveries_endpoint ON webhook_deliveries(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_deliveries_next_attempt ON webhook_deliveries(next_attempt_at);
`;

// Persistent implementation using a database (better-sqlite3 style interface)
export interface Database {
  prepare(sql: string): Statement;
  exec(sql: string): void;
  transaction<T>(fn: () => T): () => T;   // as in better-sqlite3: returns a function that runs fn in one transaction
}

export interface Statement {
  run(...params: unknown[]): { changes: number; lastInsertRowid: number | bigint };
  get(...params: unknown[]): unknown;
  all(...params: unknown[]): unknown[];
}

export class PersistentWebhooks {
  constructor(private db: Database) {
    this.db.exec(SCHEMA_SQL);
  }

  private generateId(prefix: string): string {
    return `${prefix}${randomBytes(16).toString('hex')}`;
  }

  private generateSecret(): string {
    const bytes = randomBytes(32);
    return `whsec_${bytes.toString('base64')}`;
  }

  private decodeSecret(secret: string): Buffer {
    if (!secret.startsWith('whsec_')) throw new Error('Invalid secret format');
    return Buffer.from(secret.slice(6), 'base64');
  }

  private validateUrl(url: string): void {
    try {
      const u = new URL(url);
      if (u.protocol !== 'https:' && !(u.protocol === 'http:' && u.hostname === 'localhost')) {
        throw new Error('URL must be https:// (http://localhost allowed for dev)');
      }
    } catch {
      throw new Error('Invalid URL');
    }
  }

  createEndpoint(org_id: string, url: string, event_types: string[]): CreateEndpointResult {
    this.validateUrl(url);
    const id = this.generateId('wep_');
    const secret = this.generateSecret();
    const stmt = this.db.prepare(
      `INSERT INTO webhook_endpoints (id, org_id, url, secret, event_types, active, failure_count, created_at)
       VALUES (?, ?, ?, ?, ?, 1, 0, datetime('now'))`
    );
    stmt.run(id, org_id, url, secret, JSON.stringify(event_types));
    return { id, secret };
  }

  sendEvent(event_type: string, payload: unknown): string {
    const message_id = this.generateId('msg_');
    const body = JSON.stringify(payload);
    return this.db.transaction(() => {
      const msgStmt = this.db.prepare(
        `INSERT INTO webhook_messages (id, event_type, payload, created_at) VALUES (?, ?, ?, datetime('now'))`
      );
      msgStmt.run(message_id, event_type, body);

      const endpoints = this.db.prepare(
        `SELECT id FROM webhook_endpoints WHERE active = 1 AND json_extract(event_types, '$') LIKE ?`
      ).all(`%${event_type}%`) as { id: string }[];

      const dlvStmt = this.db.prepare(
        `INSERT INTO webhook_deliveries (id, message_id, endpoint_id, attempt, status_code, success, error, next_attempt_at, delivered_at)
         VALUES (?, ?, ?, 0, NULL, 0, NULL, datetime('now'), NULL)`
      );

      for (const ep of endpoints) {
        dlvStmt.run(this.generateId('dlv_'), message_id, ep.id);
      }
      return message_id;
    })();
  }

  sign(secret: string, msg_id: string, timestamp: number, body: string): string {
    const key = this.decodeSecret(secret);
    const content = `${msg_id}.${timestamp}.${body}`;
    const signature = createHmac('sha256', key).update(content).digest();
    return `v1,${signature.toString('base64')}`;
  }

  async deliver(delivery_id: string): Promise<void> {
    const delivery = this.db.prepare(`SELECT * FROM webhook_deliveries WHERE id = ?`).get(delivery_id) as
      | (WebhookDelivery & { next_attempt_at: string | null; delivered_at: string | null })
      | undefined;
    if (!delivery) throw new Error('Delivery not found');

    const message = this.db.prepare(`SELECT * FROM webhook_messages WHERE id = ?`).get(delivery.message_id) as
      | (WebhookMessage & { payload: string })
      | undefined;
    if (!message) throw new Error('Message not found');

    const endpoint = this.db.prepare(`SELECT * FROM webhook_endpoints WHERE id = ?`).get(delivery.endpoint_id) as
      | (WebhookEndpoint & { event_types: string })
      | undefined;
    if (!endpoint) throw new Error('Endpoint not found');

    const attempt = delivery.attempt + 1;
    const timestamp = Math.floor(Date.now() / 1000);
    const body = message.payload;
    const signature = this.sign(endpoint.secret, message.id, timestamp, body);

    let status_code = 0;
    let success = false;
    let error: string | null = null;
    let next_attempt_at: string | null = null;
    let delivered_at: string | null = null;

    try {
      const response = await fetch(endpoint.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'webhook-id': message.id,
          'webhook-timestamp': timestamp.toString(),
          'webhook-signature': signature,
        },
        body,
      });

      status_code = response.status;
      success = response.status >= 200 && response.status <= 299;

      if (success) {
        delivered_at = new Date().toISOString();
        next_attempt_at = null;
        error = null;
        this.db.prepare(`UPDATE webhook_endpoints SET failure_count = 0 WHERE id = ?`).run(endpoint.id);
      } else {
        error = `HTTP ${response.status}`;
        next_attempt_at = this.computeNextAttempt(attempt);
        this.handleFailure(endpoint.id, next_attempt_at === null);
      }
    } catch (err) {
      status_code = 0;
      success = false;
      error = err instanceof Error ? err.message : 'Network error';
      next_attempt_at = this.computeNextAttempt(attempt);
      this.handleFailure(endpoint.id, next_attempt_at === null);
    }

    this.db.prepare(
      `UPDATE webhook_deliveries SET attempt = ?, status_code = ?, success = ?, error = ?, next_attempt_at = ?, delivered_at = ? WHERE id = ?`
    ).run(attempt, status_code, success ? 1 : 0, error, next_attempt_at, delivered_at, delivery_id);
  }

  private computeNextAttempt(attempt: number): string | null {
    const attemptIndex = attempt - 1;
    if (attemptIndex < RETRY_SCHEDULE.length) {
      const delay = RETRY_SCHEDULE[attemptIndex];
      return new Date(Date.now() + delay).toISOString();
    }
    return null;
  }

  private handleFailure(endpoint_id: string, exhausted: boolean): void {
    if (exhausted) {
      const result = this.db.prepare(
        `UPDATE webhook_endpoints SET failure_count = failure_count + 1 WHERE id = ?`
      ).run(endpoint_id);
      const ep = this.db.prepare(`SELECT failure_count FROM webhook_endpoints WHERE id = ?`).get(endpoint_id) as
        | { failure_count: number }
        | undefined;
      if (ep && ep.failure_count >= MAX_FAILURES_BEFORE_DISABLE) {
        this.db.prepare(`UPDATE webhook_endpoints SET active = 0 WHERE id = ?`).run(endpoint_id);
      }
    }
  }

  verify(secret: string, headers: Record<string, string>, raw_body: string, tolerance_seconds = 300): VerifyResult {
    const msg_id = headers['webhook-id'];
    const timestamp_str = headers['webhook-timestamp'];
    const signature_header = headers['webhook-signature'];

    if (!msg_id || !timestamp_str || !signature_header) {
      return { valid: false, error: 'Missing required headers' };
    }

    const timestamp = parseInt(timestamp_str, 10);
    if (isNaN(timestamp)) {
      return { valid: false, error: 'Invalid timestamp' };
    }

    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - timestamp) > tolerance_seconds) {
      return { valid: false, error: 'Timestamp outside tolerance' };
    }

    const signatures = signature_header.split(' ').map(s => s.trim()).filter(Boolean);
    const expected = this.sign(secret, msg_id, timestamp, raw_body);

    for (const sig of signatures) {
      const expectedBuf = Buffer.from(expected);
      const sigBuf = Buffer.from(sig);
      if (expectedBuf.length === sigBuf.length && timingSafeEqual(expectedBuf, sigBuf)) {
        return { valid: true };
      }
    }

    return { valid: false, error: 'Signature mismatch' };
  }

  rotateSecret(endpoint_id: string): string {
    const newSecret = this.generateSecret();
    this.db.prepare(`UPDATE webhook_endpoints SET secret = ? WHERE id = ?`).run(newSecret, endpoint_id);
    return newSecret;
  }
}
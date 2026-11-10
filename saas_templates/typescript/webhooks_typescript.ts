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
  org_id: string;
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

/**
 * The injectable HTTP sender deliver() posts through (spec: no network in tests; a sender that raises or
 * times out is a failed attempt). It has fetch's shape, so `fetch` itself is the default.
 * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the network when it is the real fetch.
 */
export type WebhookSender = (
  url: string,
  init: { method: 'POST'; headers: Record<string, string>; body: string },
) => Promise<{ status: number }>;

/**
 * Options for both webhook services: `sender` (default global fetch), `now` (clock in epoch ms, default
 * Date.now) and `timeoutMs` (per-attempt limit, default 10 000 ms). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 */
export interface WebhookOptions {
  sender?: WebhookSender;
  now?: () => number;
  timeoutMs?: number;
}

/**
 * Sends one POST through the sender, failing with Error('timeout') when it takes longer than timeoutMs.
 *
 * In: sender, url, request, timeout. Out: the response status. Why: spec "a sender that ... times out
 * counts as a failed attempt"; the timer is always cleared so nothing is left running.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: whatever the sender touches (the network for fetch).
 */
async function postWithTimeout(
  sender: WebhookSender,
  url: string,
  init: { method: 'POST'; headers: Record<string, string>; body: string },
  timeoutMs: number,
): Promise<number> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('timeout')), timeoutMs);
  });
  try {
    const response = await Promise.race([sender(url, init), timeout]);
    return response.status;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

const RETRY_SCHEDULE = [5_000, 5 * 60_000, 30 * 60_000, 2 * 60 * 60_000, 5 * 60 * 60_000, 10 * 60 * 60_000, 10 * 60 * 60_000];
const MAX_FAILURES_BEFORE_DISABLE = 5;

export class Webhooks {
  private endpoints = new Map<string, WebhookEndpoint>();
  private messages = new Map<string, WebhookMessage>();
  private deliveries = new Map<string, WebhookDelivery>();
  private deliveryIndex = new Map<string, string[]>(); // message_id -> delivery_ids
  private sender: WebhookSender;
  private now: () => number;
  private timeoutMs: number;

  /**
   * In-memory webhook service. In: optional sender, clock and timeout (WebhookOptions). Out: the service.
   * Why: spec "deliver() sends through the injectable sender" and the injectable-clock rule; deliver() used
   * the global fetch and Date. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
   */
  constructor(options: WebhookOptions = {}) {
    this.sender = options.sender ?? ((url, init) => fetch(url, init));
    this.now = options.now ?? (() => Date.now());
    this.timeoutMs = options.timeoutMs ?? 10_000;
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

  /**
   * Registers an endpoint for an org: https only (http://localhost for development), secret "whsec_" + base64 of
   * 32 random bytes. In: org id, url, event types. Out: { id, secret }.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: created_at comes from the injected clock. Touches: memory or the database.
   */
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
      created_at: new Date(this.now()),
    };
    this.endpoints.set(id, endpoint);
    return { id, secret };
  }

  /**
   * Creates ONE message for org_id and a pending delivery for every active endpoint OF THAT ORG subscribed
   * to event_type (exact match).
   *
   * In: org_id, event_type, payload. Out: the message id ("msg_" + random). Why: HOOK-06 (spec amended
   * 2026-09-26): this took no org_id, so an event fanned out to every tenant's endpoints. org_id added
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
   */
  sendEvent(org_id: string, event_type: string, payload: unknown): string {
    const message_id = this.generateId('msg_');
    const message: WebhookMessage = {
      id: message_id,
      org_id,
      event_type,
      payload,
      created_at: new Date(this.now()),
    };
    this.messages.set(message_id, message);

    for (const endpoint of this.endpoints.values()) {
      if (endpoint.org_id === org_id && endpoint.active && endpoint.event_types.includes(event_type)) {
        const delivery_id = this.generateId('dlv_');
        const delivery: WebhookDelivery = {
          id: delivery_id,
          message_id,
          endpoint_id: endpoint.id,
          attempt: 0,
          status_code: null,
          success: false,
          error: null,
          next_attempt_at: new Date(this.now()),
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

  /**
   * Makes one delivery attempt: POSTs the raw JSON body with webhook-id (the message id, the same on every
   * retry), webhook-timestamp and webhook-signature through the injected sender; 2xx = success, anything
   * else, a thrown sender or a timeout = failure with the next retry scheduled.
   *
   * In: a delivery id. Out: nothing; updates the delivery and endpoint. Why: HOOK-05/HOOK-07;
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: uses the injected sender, clock and timeout instead of the
   * global fetch and Date. Touches: memory, and the network through the sender.
   */
  async deliver(delivery_id: string): Promise<void> {
    const delivery = this.deliveries.get(delivery_id);
    if (!delivery) throw new Error('Delivery not found');

    const message = this.messages.get(delivery.message_id);
    if (!message) throw new Error('Message not found');

    const endpoint = this.endpoints.get(delivery.endpoint_id);
    if (!endpoint) throw new Error('Endpoint not found');

    delivery.attempt += 1;
    const timestamp = Math.floor(this.now() / 1000);
    const body = JSON.stringify(message.payload);
    const signature = this.sign(endpoint.secret, message.id, timestamp, body);

    try {
      const status = await postWithTimeout(this.sender, endpoint.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'webhook-id': message.id,
          'webhook-timestamp': timestamp.toString(),
          'webhook-signature': signature,
        },
        body,
      }, this.timeoutMs);

      delivery.status_code = status;
      delivery.success = status >= 200 && status <= 299;

      if (delivery.success) {
        delivery.delivered_at = new Date(this.now());
        delivery.next_attempt_at = null;
        delivery.error = null;
        // Reset failure count on success
        endpoint.failure_count = 0;
      } else {
        delivery.error = `HTTP ${status}`;
        this.scheduleRetry(delivery, endpoint);
      }
    } catch (err) {
      delivery.status_code = 0;
      delivery.success = false;
      delivery.error = err instanceof Error ? err.message : 'Network error';
      this.scheduleRetry(delivery, endpoint);
    }
  }

  /**
   * After a failed attempt: the next retry per RETRY_SCHEDULE (5 s, 5 min, 30 min, 2 h, 5 h, 10 h, 10 h) from the
   * injected clock, or, once the schedule is spent, one more fully-failed message on the endpoint (disabled at 5).
   * In: the delivery and its endpoint. Out: nothing. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: injected clock. Touches: memory.
   */
  private scheduleRetry(delivery: WebhookDelivery, endpoint: WebhookEndpoint): void {
    const attemptIndex = delivery.attempt - 1;
    if (attemptIndex < RETRY_SCHEDULE.length) {
      const delay = RETRY_SCHEDULE[attemptIndex];
      delivery.next_attempt_at = new Date(this.now() + delay);
    } else {
      delivery.next_attempt_at = null;
      endpoint.failure_count += 1;
      if (endpoint.failure_count >= MAX_FAILURES_BEFORE_DISABLE) {
        endpoint.active = false;
      }
    }
  }

  /**
   * Receiver-side check: the three webhook headers present, the timestamp within tolerance of the injected clock,
   * and any one space-separated "v1,<sig>" matching HMAC-SHA256 over "id.timestamp.body" (constant-time compare).
   * In: secret, headers, raw body, tolerance (default 300 s). Out: { valid } or { valid: false, error }.
   * Why: HOOK-01..04; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: reads the injected clock instead of Date.now(). Touches nothing.
   */
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

    const now = Math.floor(this.now() / 1000);
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
  org_id TEXT NOT NULL,
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
  private sender: WebhookSender;
  private now: () => number;
  private timeoutMs: number;

  /**
   * SQL-backed webhook service. In: a better-sqlite3-style database and optional WebhookOptions.
   * Out: the service; creates the schema. Why: same as Webhooks; options added 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
   */
  constructor(private db: Database, options: WebhookOptions = {}) {
    this.db.exec(SCHEMA_SQL);
    this.sender = options.sender ?? ((url, init) => fetch(url, init));
    this.now = options.now ?? (() => Date.now());
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  /** The injected clock as an ISO string. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
  private nowIso(): string {
    return new Date(this.now()).toISOString();
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

  /**
   * Registers an endpoint for an org: https only (http://localhost for development), secret "whsec_" + base64 of
   * 32 random bytes. In: org id, url, event types. Out: { id, secret }.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: created_at comes from the injected clock. Touches: memory or the database.
   */
  createEndpoint(org_id: string, url: string, event_types: string[]): CreateEndpointResult {
    this.validateUrl(url);
    const id = this.generateId('wep_');
    const secret = this.generateSecret();
    const stmt = this.db.prepare(
      `INSERT INTO webhook_endpoints (id, org_id, url, secret, event_types, active, failure_count, created_at)
       VALUES (?, ?, ?, ?, ?, 1, 0, ?)`
    );
    stmt.run(id, org_id, url, secret, JSON.stringify(event_types), this.nowIso());
    return { id, secret };
  }

  /**
   * Creates ONE message for org_id and, in the same transaction, a pending delivery for every active
   * endpoint of THAT org whose event_types contains event_type exactly.
   *
   * In: org_id, event_type, payload. Out: the message id. Why: HOOK-06 (spec amended 2026-09-26); this took
   * no org_id and matched event types with LIKE '%type%', so it fanned out to every tenant and "user" also
   * matched "user.created". Now filters by org_id and uses json_each for an exact match. 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (parameterized SQL).
   */
  sendEvent(org_id: string, event_type: string, payload: unknown): string {
    const message_id = this.generateId('msg_');
    const body = JSON.stringify(payload);
    const at = this.nowIso();
    return this.db.transaction(() => {
      const msgStmt = this.db.prepare(
        `INSERT INTO webhook_messages (id, org_id, event_type, payload, created_at) VALUES (?, ?, ?, ?, ?)`
      );
      msgStmt.run(message_id, org_id, event_type, body, at);

      const endpoints = this.db.prepare(
        `SELECT e.id FROM webhook_endpoints e
          WHERE e.org_id = ? AND e.active = 1
            AND EXISTS (SELECT 1 FROM json_each(e.event_types) j WHERE j.value = ?)
          ORDER BY e.rowid`
      ).all(org_id, event_type) as { id: string }[];

      const dlvStmt = this.db.prepare(
        `INSERT INTO webhook_deliveries (id, message_id, endpoint_id, attempt, status_code, success, error, next_attempt_at, delivered_at)
         VALUES (?, ?, ?, 0, NULL, 0, NULL, ?, NULL)`
      );

      for (const ep of endpoints) {
        dlvStmt.run(this.generateId('dlv_'), message_id, ep.id, at);
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

  /**
   * One delivery attempt against the database rows; same rules as Webhooks.deliver (the stored raw body is
   * sent and signed unchanged). In: a delivery id. Out: nothing; updates the delivery and endpoint rows.
   * Why: HOOK-05/HOOK-07; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: injected sender, clock and timeout.
   * Touches: the database, and the network through the sender.
   */
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
    const timestamp = Math.floor(this.now() / 1000);
    const body = message.payload;
    const signature = this.sign(endpoint.secret, message.id, timestamp, body);

    let status_code = 0;
    let success = false;
    let error: string | null = null;
    let next_attempt_at: string | null = null;
    let delivered_at: string | null = null;

    try {
      status_code = await postWithTimeout(this.sender, endpoint.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'webhook-id': message.id,
          'webhook-timestamp': timestamp.toString(),
          'webhook-signature': signature,
        },
        body,
      }, this.timeoutMs);
      success = status_code >= 200 && status_code <= 299;

      if (success) {
        delivered_at = this.nowIso();
        next_attempt_at = null;
        error = null;
        this.db.prepare(`UPDATE webhook_endpoints SET failure_count = 0 WHERE id = ?`).run(endpoint.id);
      } else {
        error = `HTTP ${status_code}`;
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

  /**
   * The next attempt time after attempt n per RETRY_SCHEDULE, from the injected clock, or null once the schedule
   * is spent. In: the attempt number. Out: ISO time or null. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: injected clock. Touches nothing.
   */
  private computeNextAttempt(attempt: number): string | null {
    const attemptIndex = attempt - 1;
    if (attemptIndex < RETRY_SCHEDULE.length) {
      const delay = RETRY_SCHEDULE[attemptIndex];
      return new Date(this.now() + delay).toISOString();
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

  /**
   * Receiver-side check: the three webhook headers present, the timestamp within tolerance of the injected clock,
   * and any one space-separated "v1,<sig>" matching HMAC-SHA256 over "id.timestamp.body" (constant-time compare).
   * In: secret, headers, raw body, tolerance (default 300 s). Out: { valid } or { valid: false, error }.
   * Why: HOOK-01..04; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: reads the injected clock instead of Date.now(). Touches nothing.
   */
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

    const now = Math.floor(this.now() / 1000);
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
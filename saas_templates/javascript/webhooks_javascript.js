/* In‑memory store ---------------------------------------------------------- */
class InMemoryStore {
  constructor() {
    this.endpoints = new Map();   // id -> endpoint
    this.messages = new Map();    // id -> message
    this.deliveries = new Map();  // id -> delivery
    this._nextId = 1;
  }
  _genId(prefix) {
    return `${prefix}_${this._nextId++}`;
  }
  /* Endpoints ------------------------------------------------------------ */
  createEndpoint(org_id, url, event_types) {
    const id = this._genId('endpoint');
    const secretBytes = crypto.randomBytes(32);
    const secret = 'whsec_' + secretBytes.toString('base64');
    const endpoint = {
      id,
      org_id,
      url,
      secret,
      event_types: Array.isArray(event_types) ? event_types : [],
      active: true,
      failure_count: 0,
      created_at: clock(),
    };
    this.endpoints.set(id, endpoint);
    return { id, secret };
  }
  getEndpoint(id) {
    return this.endpoints.get(id);
  }
  updateEndpoint(id, updates) {
    const ep = this.endpoints.get(id);
    if (ep) Object.assign(ep, updates);
  }
  /* Messages ------------------------------------------------------------- */
  createMessage(org_id, event_type, payload) {
    const id = 'msg_' + crypto.randomBytes(16).toString('hex');
    const message = {
      id,
      org_id,
      event_type,
      payload,
      created_at: clock(),
    };
    this.messages.set(id, message);
    return message;
  }
  getMessage(id) {
    return this.messages.get(id);
  }
  /* Deliveries ------------------------------------------------------------ */
  createDelivery(message_id, endpoint_id) {
    const id = this._genId('delivery');
    const delivery = {
      id,
      message_id,
      endpoint_id,
      attempt: 0,
      status_code: null,
      success: false,
      error: null,
      next_attempt_at: Math.floor(clock() / 1000),
      delivered_at: null,
    };
    this.deliveries.set(id, delivery);
    return delivery;
  }
  getDelivery(id) {
    return this.deliveries.get(id);
  }
  updateDelivery(id, updates) {
    const d = this.deliveries.get(id);
    if (d) Object.assign(d, updates);
  }
}

/* Singleton store ---------------------------------------------------------- */
const crypto = require('crypto');

/* Clock --------------------------------------------------------------------- */
// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Time comes from an injectable clock (epoch ms), so signing, the
// tolerance check and retry scheduling can be tested at a fixed instant (docs/specs/README.md "Deterministic").
let clock = () => Date.now();

/**
 * setClock(fn): replaces the clock (fn() -> epoch milliseconds); setClock() restores Date.now.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches module state only.
 */
function setClock(fn) {
  clock = typeof fn === 'function' ? fn : () => Date.now();
}
const store = new InMemoryStore();

/* Helper: constant‑time compare ------------------------------------------- */
function constantTimeCompare(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/* API --------------------------------------------------------------------- */

/* create_endpoint(org_id, url, event_types) -> {id, secret} */
function create_endpoint(org_id, url, event_types) {
  // URL validation (https or http://localhost)
  if (!/^https:/.test(url) && !/^http:\/\/localhost/.test(url)) {
    throw new Error('URL must be https:// or http://localhost');
  }
  return store.createEndpoint(org_id, url, event_types);
}

/* send_event(org_id, event_type, payload) -> message_id */
function send_event(org_id, event_type, payload) {
  const message = store.createMessage(org_id, event_type, payload);
  // create deliveries for matching active endpoints
  for (const endpoint of store.endpoints.values()) {
    if (
      endpoint.org_id === org_id &&
      endpoint.active &&
      endpoint.event_types.includes(event_type)
    ) {
      store.createDelivery(message.id, endpoint.id);
    }
  }
  return message.id;
}

/**
 * sign(secret, msg_id, timestamp, body) -> "v1,<base64 HMAC-SHA256>".
 * In: a "whsec_" secret, the message id, the unix timestamp in seconds and the raw body string.
 * Out: the webhook-signature value for one key. Why: Standard Webhooks signing (HOOK-01/02).
 * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] fixed the key decoding (prefix is 6 characters).
 * Touches nothing (pure crypto).
 */
function sign(secret, msg_id, timestamp, body) {
  if (!secret.startsWith('whsec_')) {
    throw new Error('Invalid secret format');
  }
  // [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] The key is the base64 AFTER the 6-character "whsec_" prefix
  // (spec: "Key = base64-decode of the secret with its 'whsec_' prefix removed"). slice(5) kept the "_", which
  // Node decodes as a url-safe digit, so the key differed from every other language and signatures never interoperated.
  const key = Buffer.from(secret.slice(6), 'base64');
  const content = `${msg_id}.${timestamp}.${body}`;
  const hmac = crypto.createHmac('sha256', key).update(content).digest();
  const sig = hmac.toString('base64');
  return `v1,${sig}`;
}

/* verify(secret, headers, raw_body, tolerance_seconds=300) -> true|error */
function verify(secret, headers, raw_body, tolerance_seconds = 300) {
  const idHeader = headers['webhook-id'];
  const tsHeader = headers['webhook-timestamp'];
  const sigHeader = headers['webhook-signature'];
  if (!idHeader || !tsHeader || !sigHeader) {
    return 'missing required header';
  }
  const timestamp = parseInt(tsHeader, 10);
  if (Number.isNaN(timestamp)) {
    return 'invalid timestamp';
  }
  const now = Math.floor(clock() / 1000);
  if (Math.abs(now - timestamp) > tolerance_seconds) {
    return 'timestamp outside tolerance';
  }
  const signatures = sigHeader.split(' ');
  const msg_id = idHeader; // webhook-id is the delivery id, but verification uses msg_id from payload
  // In this implementation we assume the caller passes the correct msg_id via header.
  // For tests we will use the message id directly.
  for (const part of signatures) {
    const [scheme, b64] = part.split(',');
    if (scheme !== 'v1' || !b64) continue;
    const expected = sign(secret, msg_id, timestamp, raw_body);
    const expectedSig = expected.split(',')[1];
    if (constantTimeCompare(b64, expectedSig)) {
      return true;
    }
  }
  return 'signature mismatch';
}

/* rotate_secret(endpoint_id) -> new secret */
function rotate_secret(endpoint_id) {
  const endpoint = store.getEndpoint(endpoint_id);
  if (!endpoint) throw new Error('endpoint not found');
  const secretBytes = crypto.randomBytes(32);
  const newSecret = 'whsec_' + secretBytes.toString('base64');
  endpoint.secret = newSecret;
  return newSecret;
}

/* deliver(delivery, sender) -> updates store, returns delivery */
async function deliver(delivery, sender) {
  const del = store.getDelivery(delivery.id);
  if (!del) throw new Error('delivery not found');
  const endpoint = store.getEndpoint(del.endpoint_id);
  const message = store.getMessage(del.message_id);
  if (!endpoint || !message) throw new Error('invalid delivery data');

  const body = JSON.stringify(message.payload);
  const timestamp = Math.floor(clock() / 1000);
  const signature = sign(endpoint.secret, message.id, timestamp, body);
  const headers = {
    'webhook-id': message.id,
    'webhook-timestamp': timestamp.toString(),
    'webhook-signature': signature,
    'Content-Type': 'application/json',
  };

  let response;
  try {
    response = await sender(endpoint.url, headers, body);
  } catch (e) {
    response = { status: null, error: e };
  }

  const status = response.status;
  const success = typeof status === 'number' && status >= 200 && status < 300;

  const backoff = [5, 300, 1800, 7200, 18000, 36000, 36000];
  const attempt = del.attempt + 1;
  const updates = {
    attempt,
    status_code: status,
    success,
    error: success ? null : (response.error?.message || `status ${status}`),
    delivered_at: success ? clock() : null,
  };
  if (!success) {
    const delay = backoff[Math.min(attempt - 1, backoff.length - 1)];
    updates.next_attempt_at = Math.floor(clock() / 1000) + delay;
    // update endpoint failure count
    const newFailCount = endpoint.failure_count + 1;
    const epUpdates = { failure_count: newFailCount };
    if (newFailCount >= 5) epUpdates.active = false;
    store.updateEndpoint(endpoint.id, epUpdates);
  } else {
    // reset failure count on success
    store.updateEndpoint(endpoint.id, { failure_count: 0 });
  }
  store.updateDelivery(del.id, updates);
  return store.getDelivery(del.id);
}

/* Exported API ------------------------------------------------------------ */
module.exports = {
  create_endpoint,
  send_event,
  sign,
  verify,
  rotate_secret,
  deliver,
  setClock,
  // expose store for tests (read‑only)
  _store: store,
};
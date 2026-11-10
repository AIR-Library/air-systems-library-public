'use strict';
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

/**
 * Stripe webhook entitlements (docs/specs/stripe_webhook_entitlements.md): receive Stripe's webhook, prove it came
 * from Stripe (the Stripe-Signature scheme "t=<timestamp>,v1=<hex HMAC-SHA256>"), apply every event exactly once and
 * in order, and keep one answer per user: what they are entitled to right now. The webhook is the ONLY writer of
 * that answer; no function takes a plan, a status or a period end from a caller.
 *
 * Why: Phase D wave 1, owner request 2026-11-10 (STRIPEWH-01..STRIPEWH-14).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the database given (SQLite, the spec's SCHEMA, parameterized statements; CLAIM + APPLY in one
 * transaction); the network only through the injected Stripe client. Money: it decides paid access but moves no
 * money. Never logs the secret, the signature header or the payload.
 */

const TOLERANCE = 300;
const MAX_HEADER_BYTES = 4096;
const EVENT_ID_RE = /^evt_[A-Za-z0-9_]{1,200}$/;
const SUB_ID_RE = /^sub_[A-Za-z0-9_]{1,200}$/;
const STATUS_RE = /^[a-z_]{1,32}$/;
const RANK = { 'customer.subscription.created': 0, 'customer.subscription.updated': 1, 'customer.subscription.deleted': 2 };

/* ------------------------------------------------------------------ signature */

/**
 * The raw body as bytes: a Buffer/Uint8Array as is, a string as its UTF-8. In: payload. Out: Buffer.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function payloadBytes(payload) {
  if (Buffer.isBuffer(payload)) return payload;
  if (payload instanceof Uint8Array) return Buffer.from(payload);
  return Buffer.from(String(payload), 'utf8');
}

/**
 * Lower-case hex HMAC-SHA256(key = UTF-8 of secret, message = t + "." + payload). In: payload, secret, t text.
 * Out: 64 hex characters. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function hmacHex(payload, secret, tText) {
  return crypto.createHmac('sha256', Buffer.from(secret, 'utf8'))
    .update(Buffer.from(tText + '.', 'utf8')).update(payloadBytes(payload)).digest('hex');
}

/**
 * sign_payload(payload, secret, timestamp) -> "t=" + timestamp + ",v1=" + hex. The whole secret text,
 * "whsec_" included, is the HMAC key. In: payload (Buffer or string), secret, whole-second timestamp.
 * Out: header text. Why: STRIPEWH-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function signPayload(payload, secret, timestamp) {
  const t = String(timestamp);
  return 't=' + t + ',v1=' + hmacHex(payload, secret, t);
}

/**
 * verify_signature(payload, header, secret, now) -> {ok: true, timestamp} or {error, status}, in the spec's order:
 * secret too short (503), header missing (400 missing_signature), header malformed or no v1 matches (400
 * invalid_signature), timestamp outside 300 s (400 timestamp_out_of_tolerance). Every v1 candidate is compared in
 * constant time, with no early exit. Why: STRIPEWH-02..STRIPEWH-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches nothing.
 */
function verifySignature(payload, header, secret, now) {
  if (typeof secret !== 'string' || Buffer.byteLength(secret, 'utf8') < 16) {
    return { error: 'webhook_not_configured', status: 503 };
  }
  if (typeof header !== 'string' || header.length === 0) return { error: 'missing_signature', status: 400 };
  const invalid = { error: 'invalid_signature', status: 400 };
  if (Buffer.byteLength(header, 'utf8') > MAX_HEADER_BYTES) return invalid;
  const ts = [];
  const candidates = [];
  for (const raw of header.split(',')) {
    const el = raw.replace(/^ +/, '').replace(/ +$/, '');
    const eq = el.indexOf('=');
    if (eq === -1) continue;
    const name = el.slice(0, eq);
    const value = el.slice(eq + 1);
    if (name === 't') ts.push(value);
    else if (name === 'v1' && /^[0-9a-f]{64}$/.test(value)) candidates.push(value);
  }
  if (ts.length !== 1 || !/^[0-9]{1,12}$/.test(ts[0])) return invalid;
  if (candidates.length === 0) return invalid;
  const expected = Buffer.from(hmacHex(payload, secret, ts[0]), 'utf8');
  let match = false;
  for (const c of candidates) {
    const equal = crypto.timingSafeEqual(expected, Buffer.from(c, 'utf8'));
    match = match || equal;
  }
  if (!match) return invalid;
  const t = parseInt(ts[0], 10);
  if (Math.abs(now - t) > TOLERANCE) return { error: 'timestamp_out_of_tolerance', status: 400 };
  return { ok: true, timestamp: t };
}

/* ------------------------------------------------------------------ parsing helpers */

/** A plain JSON object (not null, not an array). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/**
 * TIME: a JSON number (never a boolean, text or null) that is finite, whole and in 0..99999999999.
 * In: any. Out: bool. Why: STRIPEWH-06, STRIPEWH-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function isTime(v) {
  return typeof v === 'number' && Number.isFinite(v) && Math.floor(v) === v && v >= 0 && v <= 99999999999;
}

/**
 * Step 6: valid UTF-8 with no byte-order mark, a JSON object with id, type, created (a TIME) and data.object.
 * In: payload. Out: the event object, or null. Why: STRIPEWH-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches nothing.
 */
function parseEvent(payload) {
  try {
    const bytes = payloadBytes(payload);
    if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return null;
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    const ev = JSON.parse(text);
    if (!isObject(ev)) return null;
    if (typeof ev.id !== 'string' || !EVENT_ID_RE.test(ev.id)) return null;
    if (typeof ev.type !== 'string' || ev.type.length < 1 || ev.type.length > 100 || !/^[\x20-\x7e]+$/.test(ev.type)) return null;
    if (!isTime(ev.created)) return null;
    if (!isObject(ev.data) || !isObject(ev.data.object)) return null;
    return ev;
  } catch (err) {
    return null;
  }
}

/* ------------------------------------------------------------------ store */

/**
 * SQLite store (node:sqlite) on the spec's SCHEMA. In: a DatabaseSync (default a new in-memory one).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
 */
class SqliteEntitlementStore {
  /**
   * Creates the spec's SCHEMA tables when absent. In: a DatabaseSync (default a new in-memory one). Out: the store.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1). Touches the database.
   */
  constructor(db = new DatabaseSync(':memory:')) {
    this.db = db;
    db.exec(`
      CREATE TABLE IF NOT EXISTS stripe_events (
        event_id TEXT PRIMARY KEY, type TEXT, created INTEGER, received_at INTEGER, result TEXT);
      CREATE TABLE IF NOT EXISTS entitlement_subscriptions (
        stripe_subscription_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, stripe_customer_id TEXT, price_id TEXT,
        plan TEXT NULL, status TEXT, current_period_end INTEGER NOT NULL, cancel_at_period_end INTEGER,
        event_at INTEGER, event_rank INTEGER, updated_at INTEGER);
      CREATE INDEX IF NOT EXISTS entitlement_subscriptions_user ON entitlement_subscriptions (user_id);
      CREATE INDEX IF NOT EXISTS entitlement_subscriptions_customer ON entitlement_subscriptions (stripe_customer_id);`);
  }

  /** BEGIN. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  begin() { this.db.exec('BEGIN'); }

  /** COMMIT. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  commit() { this.db.exec('COMMIT'); }

  /** ROLLBACK. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  rollback() { this.db.exec('ROLLBACK'); }

  /**
   * CLAIM: an insert that fails on a duplicate key. Out: true when this call inserted the event id.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
   */
  claimEvent(eventId, type, created, now) {
    return this.db.prepare(
      'INSERT INTO stripe_events (event_id, type, created, received_at, result) VALUES (?, ?, ?, ?, NULL) ON CONFLICT (event_id) DO NOTHING')
      .run(eventId, type, created, now).changes === 1;
  }

  /** Stores the event's result. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  setEventResult(eventId, result) {
    this.db.prepare('UPDATE stripe_events SET result = ? WHERE event_id = ?').run(result, eventId);
  }

  /** The stored event row or null. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  getEvent(eventId) {
    return this.db.prepare('SELECT * FROM stripe_events WHERE event_id = ?').get(eventId) || null;
  }

  /**
   * The subscription row (cancel_at_period_end as a boolean) or null. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches the database.
   */
  getSubscription(subId) {
    const r = this.db.prepare('SELECT * FROM entitlement_subscriptions WHERE stripe_subscription_id = ?').get(subId);
    return r ? { ...r, cancel_at_period_end: r.cancel_at_period_end === 1 } : null;
  }

  /** The distinct user ids of rows with this customer id. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  usersForCustomer(customerId) {
    return this.db.prepare('SELECT DISTINCT user_id FROM entitlement_subscriptions WHERE stripe_customer_id = ?')
      .all(customerId).map(r => r.user_id);
  }

  /** The user's rows. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  subscriptionsForUser(userId) {
    return this.db.prepare('SELECT * FROM entitlement_subscriptions WHERE user_id = ?').all(userId)
      .map(r => ({ ...r, cancel_at_period_end: r.cancel_at_period_end === 1 }));
  }

  /** Inserts or replaces the row (rule g). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  putSubscription(row) {
    this.db.prepare(
      `INSERT INTO entitlement_subscriptions (stripe_subscription_id, user_id, stripe_customer_id, price_id, plan, status,
         current_period_end, cancel_at_period_end, event_at, event_rank, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (stripe_subscription_id) DO UPDATE SET user_id = excluded.user_id,
         stripe_customer_id = excluded.stripe_customer_id, price_id = excluded.price_id, plan = excluded.plan,
         status = excluded.status, current_period_end = excluded.current_period_end,
         cancel_at_period_end = excluded.cancel_at_period_end, event_at = excluded.event_at,
         event_rank = excluded.event_rank, updated_at = excluded.updated_at`)
      .run(row.stripe_subscription_id, row.user_id, row.stripe_customer_id, row.price_id, row.plan, row.status,
        row.current_period_end, row.cancel_at_period_end ? 1 : 0, row.event_at, row.event_rank, row.updated_at);
  }
}

/* ------------------------------------------------------------------ service */

/**
 * StripeEntitlements: handle_webhook and get_entitlement. Build it with createStripeEntitlements().
 * handle_webhook calls run one at a time (a promise chain), so a transaction never spans two calls while the
 * Stripe client is awaited. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the store and the Stripe client.
 */
class StripeEntitlements {
  /**
   * In: {store, webhookSecret, pricePlans: {price_id: plan}, stripeClient: {retrieveSubscription(id)},
   * userExists(user_id) -> bool, periodGraceSeconds (default 0), clock() -> seconds}.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
   */
  constructor({ store, webhookSecret, pricePlans, stripeClient, userExists, periodGraceSeconds = 0, clock } = {}) {
    this.store = store || new SqliteEntitlementStore();
    Object.defineProperty(this, '_secret', { value: webhookSecret, enumerable: false });
    this.pricePlans = new Map(Object.entries(pricePlans || {}));
    this.stripeClient = stripeClient;
    this.userExists = userExists || (() => false);
    this.periodGraceSeconds = periodGraceSeconds;
    this.clock = clock || (() => Math.floor(Date.now() / 1000));
    this._queue = Promise.resolve();
  }

  /**
   * handle_webhook(payload, header) -> {status: 200, received: true, result} or {error, status}. Steps 1-5 verify,
   * 6 parses, 7-9 claim and apply in one transaction (any error rolls back the claim: 500 processing_failed).
   * In: the RAW body (Buffer or string) and the Stripe-Signature header. Why: STRIPEWH-01..STRIPEWH-14.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database and the Stripe client.
   */
  handleWebhook(payload, header) {
    const run = this._queue.then(() => this._handle(payload, header));
    this._queue = run.catch(() => {});
    return run;
  }

  /** The body of handleWebhook, run serially. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  async _handle(payload, header) {
    const now = this.clock();
    const v = verifySignature(payload, header, this._secret, now);
    if (!v.ok) return v;
    const ev = parseEvent(payload);
    if (!ev) return { error: 'invalid_payload', status: 400 };
    const store = this.store;
    store.begin();
    try {
      if (!store.claimEvent(ev.id, ev.type, ev.created, now)) {
        store.rollback();
        return { status: 200, received: true, result: 'duplicate' };
      }
      const result = await this.apply(ev, now);
      store.setEventResult(ev.id, result);
      store.commit();
      return { status: 200, received: true, result };
    } catch (err) {
      try { store.rollback(); } catch (e) { /* the transaction is already gone */ }
      return { error: 'processing_failed', status: 500 };
    }
  }

  /**
   * APPLY(event) by event.type. Out: "applied" | "stale" | "ignored". Throws when the Stripe client or the store
   * does (the caller turns that into 500). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database and
   * the Stripe client.
   */
  async apply(ev, now) {
    const obj = ev.data.object;
    if (Object.prototype.hasOwnProperty.call(RANK, ev.type)) {
      const hint = isObject(obj.metadata) ? obj.metadata.user_id : undefined;
      return this.subscription(obj, hint, RANK[ev.type], ev.created, now, false);
    }
    if (ev.type === 'checkout.session.completed') {
      const subId = obj.subscription;
      if (obj.mode !== 'subscription' || typeof subId !== 'string' || !SUB_ID_RE.test(subId)) return 'ignored';
      const row = this.store.getSubscription(subId);
      if (row && (row.event_at > ev.created || (row.event_at === ev.created && row.event_rank > 1))) return 'stale';
      const sub = await this.stripeClient.retrieveSubscription(subId);
      let hint = obj.client_reference_id;
      if (typeof hint !== 'string' || hint.length === 0) hint = isObject(obj.metadata) ? obj.metadata.user_id : undefined;
      return this.subscription(sub, hint, 1, ev.created, now, true);
    }
    return 'ignored';
  }

  /**
   * Rule b's price and plan for a subscription object against the stored row (or null when no row and the price
   * is unknown). In: sub, row. Out: {price_id, plan} | null. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches nothing.
   */
  priceAndPlan(sub, row) {
    let priceId;
    const items = isObject(sub.items) && Array.isArray(sub.items.data) ? sub.items.data : [];
    if (isObject(items[0]) && isObject(items[0].price) && typeof items[0].price.id === 'string') priceId = items[0].price.id;
    const known = priceId !== undefined && this.pricePlans.has(priceId);
    if (!row) return known ? { price_id: priceId, plan: this.pricePlans.get(priceId) } : null;
    if (known) return { price_id: priceId, plan: this.pricePlans.get(priceId) };
    if (priceId === undefined || priceId === row.price_id) return { price_id: row.price_id, plan: row.plan };
    return { price_id: priceId, plan: null };
  }

  /**
   * SUBSCRIPTION(sub, hint, rank) rules a-g. `fetched` is true when the object was just fetched from Stripe
   * (checkout), so an equal (event_at, rank) does not fetch again. Out: "applied" | "stale" | "ignored".
   * Why: STRIPEWH-07, STRIPEWH-09, STRIPEWH-11, STRIPEWH-12, STRIPEWH-14.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database and (rule d) the Stripe client.
   */
  async subscription(sub, hint, rank, eventAt, now, fetched) {
    if (!isObject(sub) || typeof sub.id !== 'string' || !SUB_ID_RE.test(sub.id)) return 'ignored';
    const row = this.store.getSubscription(sub.id);
    let pp = this.priceAndPlan(sub, row);
    if (!row && !pp) return 'ignored';
    let userId = null;
    if (row) {
      userId = row.user_id;
    } else if (typeof hint === 'string' && hint.length > 0 && this.userExists(hint)) {
      userId = hint;
    } else if (typeof sub.customer === 'string' && sub.customer.length > 0) {
      const users = this.store.usersForCustomer(sub.customer);
      if (users.length === 1) userId = users[0];
    }
    if (userId === null) return 'ignored';
    if (row) {
      if (eventAt < row.event_at || (eventAt === row.event_at && rank < row.event_rank)) return 'stale';
      if ((rank === 0 || rank === 1) && eventAt === row.event_at && rank === row.event_rank && !fetched) {
        const current = await this.stripeClient.retrieveSubscription(sub.id);
        if (!isObject(current)) return 'ignored';
        sub = { ...current, id: sub.id };
        pp = this.priceAndPlan(sub, row); // rule b again on the fetched object (lead ruling fed6e7b, 2026-11-10)
      }
    }
    let cpe;
    if (isTime(sub.current_period_end)) {
      cpe = sub.current_period_end;
    } else {
      const items = isObject(sub.items) && Array.isArray(sub.items.data) ? sub.items.data : [];
      const ends = items.filter(it => isObject(it) && isTime(it.current_period_end)).map(it => it.current_period_end);
      cpe = ends.length > 0 ? Math.max(...ends) : (row ? row.current_period_end : 0);
    }
    let status;
    if (rank === 2) status = 'canceled';
    else if (typeof sub.status === 'string' && STATUS_RE.test(sub.status)) status = sub.status;
    else return 'ignored';
    this.store.putSubscription({
      stripe_subscription_id: sub.id, user_id: userId,
      stripe_customer_id: typeof sub.customer === 'string' ? sub.customer : null,
      price_id: pp.price_id, plan: pp.plan, status, current_period_end: cpe,
      cancel_at_period_end: sub.cancel_at_period_end === true, event_at: eventAt, event_rank: rank, updated_at: now
    });
    return 'applied';
  }

  /**
   * get_entitlement(user_id) -> {entitled, plan, status, current_period_end, cancel_at_period_end}, computed from
   * the clock at every call (rules a-c). Why: STRIPEWH-07, STRIPEWH-10, STRIPEWH-14.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (read).
   */
  getEntitlement(userId) {
    const now = this.clock();
    const rows = this.store.subscriptionsForUser(userId);
    if (rows.length === 0) {
      return { entitled: false, plan: null, status: 'none', current_period_end: null, cancel_at_period_end: false };
    }
    const cmpId = (a, b) => (a.stripe_subscription_id < b.stripe_subscription_id ? -1 : a.stripe_subscription_id > b.stripe_subscription_id ? 1 : 0);
    const entitling = rows.filter(r => r.plan !== null && (r.status === 'active' || r.status === 'trialing') &&
      r.current_period_end + this.periodGraceSeconds > now);
    if (entitling.length > 0) {
      entitling.sort((a, b) => (b.current_period_end - a.current_period_end) || (b.event_at - a.event_at) || cmpId(b, a));
      const r = entitling[0];
      return { entitled: true, plan: r.plan, status: r.status, current_period_end: r.current_period_end, cancel_at_period_end: r.cancel_at_period_end };
    }
    rows.sort((a, b) => (b.event_at - a.event_at) || cmpId(b, a));
    const r = rows[0];
    return { entitled: false, plan: null, status: r.status, current_period_end: r.current_period_end, cancel_at_period_end: r.cancel_at_period_end };
  }
}

/**
 * createStripeEntitlements(config): see StripeEntitlements. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches memory only.
 */
function createStripeEntitlements(config) {
  return new StripeEntitlements(config);
}

module.exports = {
  signPayload, verifySignature, createStripeEntitlements, StripeEntitlements, SqliteEntitlementStore, TOLERANCE
};

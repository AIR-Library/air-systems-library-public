/**
 * Stripe webhook entitlements (docs/specs/stripe_webhook_entitlements.md): receives Stripe's webhook, proves it came
 * from Stripe (Stripe-Signature, HMAC-SHA256, 300 s tolerance), applies every event exactly once and in order, and
 * keeps one answer per user: what they are entitled to right now. The webhook is the ONLY writer of that answer.
 *
 * Exports: signPayload, verifySignature, the EntitlementStore interface with InMemoryEntitlementStore, and
 * StripeWebhookEntitlements (handleWebhook, getEntitlement).
 *
 * Why: Phase D wave 1, owner request 2026-11-10 (six new systems). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the injected store (process memory for the in-memory one) and the injected Stripe client (the network for
 * a real one; tests pass a fake). Decides paid access (money), but moves no money itself.
 */
import { createHmac, timingSafeEqual } from 'crypto';

/** Seconds a signed timestamp may be away from now (spec TOLERANCE). */
export const TOLERANCE = 300;
/** The largest TIME (spec: a whole number from 0 to 99999999999). */
const MAX_TIME = 99999999999;

/** A refusal: the HTTP status a route serves and the spec error code. */
export interface WebhookRefusal {
  status: number;
  error: string;
}

/** handle_webhook's 200 answer. */
export interface WebhookOk {
  status: 200;
  received: true;
  result: 'applied' | 'duplicate' | 'stale' | 'ignored';
}

/** get_entitlement's answer (`status` is the subscription's status in Stripe's spelling, not an HTTP status). */
export interface Entitlement {
  entitled: boolean;
  plan: string | null;
  status: string;
  current_period_end: number | null;
  cancel_at_period_end: boolean;
}

/** An entitlement_subscriptions row (spec SCHEMA). */
export interface SubscriptionRow {
  stripe_subscription_id: string;
  user_id: string;
  stripe_customer_id: string | null;
  price_id: string | null;
  plan: string | null;
  status: string;
  current_period_end: number;
  cancel_at_period_end: boolean;
  event_at: number;
  event_rank: number;
  updated_at: number;
}

/** A stripe_events row (spec SCHEMA). */
export interface EventRow {
  event_id: string;
  type: string;
  created: number;
  received_at: number;
  result: string | null;
}

/**
 * The storage contract. transaction() runs its function as ONE transaction: if it throws, every write made inside
 * it is undone. insertEvent is the CLAIM: an insert that fails on a duplicate id. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the backing store.
 */
export interface EntitlementStore {
  /** Runs fn as ONE transaction; when fn throws, every write made inside it is undone and the error re-thrown. */
  transaction<T>(fn: () => Promise<T>): Promise<T>;
  /** Inserts the event row; false when the id is already there. */
  insertEvent(row: EventRow): boolean;
  /** Stores the result in the event's row. */
  setEventResult(eventId: string, result: string): void;
  /** The event row, or undefined. */
  getEvent(eventId: string): EventRow | undefined;
  /** The row for a stripe_subscription_id, or undefined. */
  getSubscription(id: string): SubscriptionRow | undefined;
  /** Every row with this stripe_customer_id. */
  subscriptionsByCustomer(customerId: string): SubscriptionRow[];
  /** Every row of this user. */
  subscriptionsByUser(userId: string): SubscriptionRow[];
  /** Inserts or replaces the row for its stripe_subscription_id. */
  putSubscription(row: SubscriptionRow): void;
}

/**
 * In-memory EntitlementStore. transaction() snapshots both tables and restores them when the function throws.
 * Calls are not interleaved by this store; a SQL store uses a real transaction (and the CLAIM's primary key).
 * Public fields are for tests to read. failNextWrite makes the next putSubscription throw (a store fault).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
 */
export class InMemoryEntitlementStore implements EntitlementStore {
  events = new Map<string, EventRow>();
  subscriptions = new Map<string, SubscriptionRow>();
  failNextWrite = false;

  /** Runs fn as one transaction: both tables are snapshotted and restored when fn throws. In memory. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  async transaction<T>(fn: () => Promise<T>): Promise<T> {
    const events = new Map([...this.events].map(([k, v]) => [k, { ...v }]));
    const subs = new Map([...this.subscriptions].map(([k, v]) => [k, { ...v }]));
    try {
      return await fn();
    } catch (err) {
      this.events = events;
      this.subscriptions = subs;
      throw err;
    }
  }

  /** Inserts the event row; false when the id is already there. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  insertEvent(row: EventRow): boolean {
    if (this.events.has(row.event_id)) return false;
    this.events.set(row.event_id, { ...row });
    return true;
  }

  /** Stores the result in the event's row. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  setEventResult(eventId: string, result: string): void {
    const row = this.events.get(eventId);
    if (row) row.result = result;
  }

  /** The event row (a copy), or undefined. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  getEvent(eventId: string): EventRow | undefined {
    const row = this.events.get(eventId);
    return row ? { ...row } : undefined;
  }

  /** The subscription row (a copy), or undefined. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  getSubscription(id: string): SubscriptionRow | undefined {
    const row = this.subscriptions.get(id);
    return row ? { ...row } : undefined;
  }

  /** Every row with this stripe_customer_id. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  subscriptionsByCustomer(customerId: string): SubscriptionRow[] {
    return [...this.subscriptions.values()].filter((r) => r.stripe_customer_id === customerId).map((r) => ({ ...r }));
  }

  /** Every row of this user. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  subscriptionsByUser(userId: string): SubscriptionRow[] {
    return [...this.subscriptions.values()].filter((r) => r.user_id === userId).map((r) => ({ ...r }));
  }

  /** Inserts or replaces the row for its stripe_subscription_id. In memory, atomic. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory. */
  putSubscription(row: SubscriptionRow): void {
    if (this.failNextWrite) {
      this.failNextWrite = false;
      throw new Error('store write failed');
    }
    this.subscriptions.set(row.stripe_subscription_id, { ...row });
  }
}

/* ------------------------------------------------------------------ signature */

/** The payload as bytes: a Buffer as is, a string as its UTF-8. Touches nothing. */
function payloadBytes(payload: string | Uint8Array): Buffer {
  return typeof payload === 'string' ? Buffer.from(payload, 'utf8') : Buffer.from(payload);
}

/** Lower-case hex HMAC-SHA256(key = UTF-8 of secret, message = t + "." + payload). Touches nothing. */
function signatureHex(secret: string, t: string, payload: Buffer): string {
  return createHmac('sha256', Buffer.from(secret, 'utf8')).update(Buffer.concat([Buffer.from(t + '.', 'utf8'), payload])).digest('hex');
}

/**
 * Builds a Stripe-Signature header: "t=" + timestamp + ",v1=" + hex. The WHOLE secret text, "whsec_" included, is
 * the key. In: raw payload, secret, timestamp. Out: the header. Why: spec sign_payload (STRIPEWH-01), for tests and
 * test clients. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export function signPayload(payload: string | Uint8Array, secret: string, timestamp: number): string {
  const t = String(timestamp);
  return 't=' + t + ',v1=' + signatureHex(secret, t, payloadBytes(payload));
}

/**
 * Verifies a Stripe-Signature header before anything in the body is read. Steps: secret under 16 bytes 503
 * webhook_not_configured; header missing or empty 400 missing_signature; header over 4096 bytes, not exactly one t
 * of 1-12 digits, or no v1 of 64 lower-case hex 400 invalid_signature; every v1 compared in constant time with no
 * early stop, none equal 400 invalid_signature; |now - t| over 300 400 timestamp_out_of_tolerance.
 * In: raw payload, header, secret, now. Out: {ok: true, timestamp} or a refusal. Why: spec verify_signature
 * (STRIPEWH-02..05). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export function verifySignature(payload: string | Uint8Array, header: unknown, secret: string, now: number):
    { ok: true; timestamp: number } | WebhookRefusal {
  if (typeof secret !== 'string' || Buffer.byteLength(secret, 'utf8') < 16) return { status: 503, error: 'webhook_not_configured' };
  if (typeof header !== 'string' || header === '') return { status: 400, error: 'missing_signature' };
  const invalid: WebhookRefusal = { status: 400, error: 'invalid_signature' };
  if (Buffer.byteLength(header, 'utf8') > 4096) return invalid;
  const ts: string[] = [];
  const candidates: string[] = [];
  for (const raw of header.split(',')) {
    const el = raw.replace(/^ +| +$/g, '');
    const eq = el.indexOf('=');
    if (eq < 0) continue;
    const name = el.slice(0, eq);
    const value = el.slice(eq + 1);
    if (name === 't') ts.push(value);
    else if (name === 'v1' && /^[0-9a-f]{64}$/.test(value)) candidates.push(value);
  }
  if (ts.length !== 1 || !/^[0-9]{1,12}$/.test(ts[0])) return invalid;
  if (candidates.length === 0) return invalid;
  const expected = Buffer.from(signatureHex(secret, ts[0], payloadBytes(payload)), 'utf8');
  let matched = false;
  for (const c of candidates) {
    if (timingSafeEqual(expected, Buffer.from(c, 'utf8'))) matched = true;
  }
  if (!matched) return invalid;
  const t = Number(ts[0]);
  if (Math.abs(now - t) > TOLERANCE) return { status: 400, error: 'timestamp_out_of_tolerance' };
  return { ok: true, timestamp: t };
}

/* ------------------------------------------------------------------ parsing helpers */

/** A plain JSON object (not null, not an array). Touches nothing. */
function isObject(v: unknown): v is Record<string, any> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** TIME: a JSON number that is finite, whole and from 0 to 99999999999. Touches nothing. */
export function isTime(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v) && Math.floor(v) === v && v >= 0 && v <= MAX_TIME;
}

/** The value at obj[key] when obj is an object and has it as its own property. Touches nothing. */
function own(obj: unknown, key: string): any {
  return isObject(obj) && Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined;
}

/** A valid subscription id: sub_[A-Za-z0-9_]{1,200}, the whole text. Touches nothing. */
function isSubId(v: unknown): v is string {
  return typeof v === 'string' && /^sub_[A-Za-z0-9_]{1,200}$/.test(v);
}

/* ------------------------------------------------------------------ service */

/** The injected Stripe client: retrieve_subscription(id) -> the subscription object, or it raises. */
export interface StripeClient {
  retrieveSubscription(subscriptionId: string): unknown | Promise<unknown>;
}

/** The injected configuration (spec CONFIGURATION). */
export interface EntitlementOptions {
  webhookSecret: string;
  pricePlans: Record<string, string>;
  stripeClient: StripeClient;
  userExists: (userId: string) => boolean | Promise<boolean>;
  periodGraceSeconds?: number;
  store?: EntitlementStore;
  /** Whole seconds since the epoch. */
  clock?: () => number;
}

/** What APPLY returns. */
type ApplyResult = 'applied' | 'stale' | 'ignored';

/**
 * The webhook handler and the entitlement answer. Never logs the secret, the header or the payload. Every answer
 * is a returned value. Why: spec ENDPOINTS, APPLY and SUBSCRIPTION (STRIPEWH-01..14). 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the Stripe client, the clock.
 */
export class StripeWebhookEntitlements {
  readonly store: EntitlementStore;
  private readonly secret: string;
  private readonly plans: Map<string, string>;
  private readonly client: StripeClient;
  private readonly userExists: (userId: string) => boolean | Promise<boolean>;
  private readonly grace: number;
  private readonly clock: () => number;

  /**
   * In: EntitlementOptions. Out: the service. A short secret is not refused here: every call answers 503
   * webhook_not_configured (spec step 1). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  constructor(options: EntitlementOptions) {
    this.secret = options.webhookSecret;
    this.plans = new Map(Object.entries(options.pricePlans ?? {}));
    this.client = options.stripeClient;
    this.userExists = options.userExists;
    this.grace = options.periodGraceSeconds ?? 0;
    this.store = options.store ?? new InMemoryEntitlementStore();
    this.clock = options.clock ?? (() => Math.floor(Date.now() / 1000));
  }

  /**
   * Handles one delivery: verify (steps 1-5), parse and validate (6: 400 invalid_payload), CLAIM the event id (7:
   * 200 duplicate), APPLY and store the result (8), all of 7-9 in one transaction; any error while applying undoes
   * everything and answers 500 processing_failed so Stripe sends it again.
   * In: the RAW body (bytes or text), the Stripe-Signature header. Out: {status: 200, received: true, result} or a
   * refusal. Why: spec handle_webhook. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: the store, the Stripe client (network for a real one), the clock.
   */
  async handleWebhook(payload: string | Uint8Array, header: unknown): Promise<WebhookOk | WebhookRefusal> {
    const now = this.clock();
    const verified = verifySignature(payload, header, this.secret, now);
    if (!('ok' in verified)) return verified;
    const event = parseEvent(payloadBytes(payload));
    if (event === null) return { status: 400, error: 'invalid_payload' };
    try {
      return await this.store.transaction(async () => {
        if (!this.store.insertEvent({ event_id: event.id, type: event.type, created: event.created, received_at: now, result: null })) {
          return { status: 200 as const, received: true as const, result: 'duplicate' as const };
        }
        const result = await this.apply(event, now);
        this.store.setEventResult(event.id, result);
        return { status: 200 as const, received: true as const, result };
      });
    } catch {
      return { status: 500, error: 'processing_failed' };
    }
  }

  /**
   * APPLY(event) by type: the three subscription events with ranks 0, 1 and 2; checkout.session.completed fetches
   * the subscription through the Stripe client (after its own stale check); any other type is ignored.
   * In: the validated event, now. Out: the result. Throws when the Stripe client or the store raises.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the Stripe client.
   */
  private async apply(event: ParsedEvent, now: number): Promise<ApplyResult> {
    const obj = event.object;
    switch (event.type) {
      case 'customer.subscription.created':
        return this.subscription(obj, own(own(obj, 'metadata'), 'user_id'), 0, event.created, now, false);
      case 'customer.subscription.updated':
        return this.subscription(obj, own(own(obj, 'metadata'), 'user_id'), 1, event.created, now, false);
      case 'customer.subscription.deleted':
        return this.subscription(obj, own(own(obj, 'metadata'), 'user_id'), 2, event.created, now, false);
      case 'checkout.session.completed': {
        const subId = own(obj, 'subscription');
        if (own(obj, 'mode') !== 'subscription' || !isSubId(subId)) return 'ignored';
        const row = this.store.getSubscription(subId);
        if (row && compareOrder(row.event_at, row.event_rank, event.created, 1) > 0) return 'stale';
        const sub = await this.client.retrieveSubscription(subId);
        const ref = own(obj, 'client_reference_id');
        const hint = typeof ref === 'string' && ref !== '' ? ref : own(own(obj, 'metadata'), 'user_id');
        return this.subscription(sub, hint, 1, event.created, now, true);
      }
      default:
        return 'ignored';
    }
  }

  /**
   * SUBSCRIPTION(sub, hint, rank) rules a-g: id, price and plan, user, order (stale, or a fetch on an exact tie of
   * created and rank 0/1 unless just fetched), period end, status, then the row write. In: the subscription object,
   * the user hint, rank, event created, now, whether the object was just fetched. Out: the result. Throws when the
   * Stripe client or the store raises. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: the store, the Stripe client, the user_exists lookup.
   */
  private async subscription(subIn: unknown, hint: unknown, rank: number, eventAt: number, now: number, fetched: boolean):
      Promise<ApplyResult> {
    let sub: any = subIn;
    if (!isObject(sub) || !isSubId(own(sub, 'id'))) return 'ignored';
    const id: string = sub.id;
    const row = this.store.getSubscription(id);
    let priced = this.pricePlan(sub, row);
    if (priced === null) return 'ignored';
    let userId: string;
    if (row) {
      userId = row.user_id;
    } else if (typeof hint === 'string' && hint !== '' && (await this.userExists(hint))) {
      userId = hint;
    } else {
      const customer = own(sub, 'customer');
      const rows = typeof customer === 'string' && customer !== '' ? this.store.subscriptionsByCustomer(customer) : [];
      if (rows.length === 0 || rows.some((r) => r.user_id !== rows[0].user_id)) return 'ignored';
      userId = rows[0].user_id;
    }
    if (row) {
      const order = compareOrder(eventAt, rank, row.event_at, row.event_rank);
      if (order < 0) return 'stale';
      if (order === 0 && rank !== 2 && !fetched) {
        sub = await this.client.retrieveSubscription(id);
        if (!isObject(sub)) return 'ignored';
        priced = this.pricePlan(sub, row);
        if (priced === null) return 'ignored';
      }
    }
    let periodEnd: number;
    if (isTime(own(sub, 'current_period_end'))) {
      periodEnd = sub.current_period_end;
    } else {
      const items = own(own(sub, 'items'), 'data');
      const ends = Array.isArray(items) ? items.map((it) => own(it, 'current_period_end')).filter(isTime) : [];
      periodEnd = ends.length ? Math.max(...ends) : row ? row.current_period_end : 0;
    }
    let status: string;
    if (rank === 2) {
      status = 'canceled';
    } else {
      const s = own(sub, 'status');
      if (typeof s !== 'string' || !/^[a-z_]{1,32}$/.test(s)) return 'ignored';
      status = s;
    }
    const customer = own(sub, 'customer');
    this.store.putSubscription({
      stripe_subscription_id: id,
      user_id: userId,
      stripe_customer_id: typeof customer === 'string' ? customer : null,
      price_id: priced.price_id,
      plan: priced.plan,
      status,
      current_period_end: periodEnd,
      cancel_at_period_end: own(sub, 'cancel_at_period_end') === true,
      event_at: eventAt,
      event_rank: rank,
      updated_at: now,
    });
    return 'applied';
  }

  /**
   * Rule b: the price and plan a subscription object gives, or null when there is no row and the price is missing
   * or unknown (an unknown price never creates a row). With a row: a known price takes its plan; a missing price or
   * the row's own price keeps the row's price and plan; another unknown price sets plan null.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  private pricePlan(sub: unknown, row: SubscriptionRow | undefined): { price_id: string | null; plan: string | null } | null {
    const data = own(own(sub, 'items'), 'data');
    const first = Array.isArray(data) ? data[0] : undefined;
    const p = own(own(first, 'price'), 'id');
    const priceId = typeof p === 'string' ? p : null;
    const known = priceId !== null && this.plans.has(priceId);
    if (!row) return known ? { price_id: priceId, plan: this.plans.get(priceId!)! } : null;
    if (known) return { price_id: priceId, plan: this.plans.get(priceId!)! };
    if (priceId === null || priceId === row.price_id) return { price_id: row.price_id, plan: row.plan };
    return { price_id: priceId, plan: null };
  }

  /**
   * What the user is entitled to right now, computed from the clock at every call: the best ENTITLING row (greatest
   * period end, then event_at, then subscription id), else the newest row unentitled, else the "none" answer.
   * In: user id. Out: {entitled, plan, status, current_period_end, cancel_at_period_end}. Why: spec get_entitlement
   * (STRIPEWH-07, 10, 14). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store (read), the clock.
   */
  getEntitlement(userId: string): Entitlement {
    const now = this.clock();
    const rows = this.store.subscriptionsByUser(userId);
    if (rows.length === 0) {
      return { entitled: false, plan: null, status: 'none', current_period_end: null, cancel_at_period_end: false };
    }
    const byId = (a: SubscriptionRow, b: SubscriptionRow) =>
      Buffer.compare(Buffer.from(b.stripe_subscription_id, 'utf8'), Buffer.from(a.stripe_subscription_id, 'utf8'));
    const entitling = rows.filter((r) => r.plan !== null && (r.status === 'active' || r.status === 'trialing') &&
      r.current_period_end + this.grace > now);
    if (entitling.length) {
      const best = entitling.sort((a, b) => b.current_period_end - a.current_period_end || b.event_at - a.event_at || byId(a, b))[0];
      return { entitled: true, plan: best.plan, status: best.status, current_period_end: best.current_period_end,
        cancel_at_period_end: best.cancel_at_period_end };
    }
    const latest = rows.sort((a, b) => b.event_at - a.event_at || byId(a, b))[0];
    return { entitled: false, plan: null, status: latest.status, current_period_end: latest.current_period_end,
      cancel_at_period_end: latest.cancel_at_period_end };
  }
}

/** Compares (at1, rank1) with (at2, rank2), event_at first. Out: <0, 0 or >0. Touches nothing. */
function compareOrder(at1: number, rank1: number, at2: number, rank2: number): number {
  return at1 !== at2 ? at1 - at2 : rank1 - rank2;
}

/** A validated event. */
interface ParsedEvent {
  id: string;
  type: string;
  created: number;
  object: Record<string, any>;
}

/**
 * JSON.parse reviver: refuses any number that is not finite (JSON.parse reads 1e400 as Infinity), wherever it is.
 * In: the key and the parsed value. Out: the value unchanged; throws for Infinity / -Infinity, which parseEvent turns
 * into invalid_payload for the whole body. Why: spec db20a03 (Phase B.4): a body holding any non-finite number, not
 * only in a TIME field, is 400 invalid_payload. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function refuseNonFinite(_key: string, value: unknown): unknown {
  if (typeof value === 'number' && !Number.isFinite(value)) throw new SyntaxError('number is not finite');
  return value;
}

/**
 * Step 6: the body as strict UTF-8 with no byte-order mark, parsed as JSON, an object with id evt_[A-Za-z0-9_]{1,200},
 * type 1-100 characters U+0020-U+007E, created a TIME and data.object an object. In: the raw bytes. Out: the event,
 * or null (400 invalid_payload). Never throws. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec db20a03 (Phase B.4): parsed with refuseNonFinite, so a
 * non-finite number anywhere in the body (1e400 outside created too) is null; before, only a non-finite created was.
 */
function parseEvent(bytes: Buffer): ParsedEvent | null {
  try {
    if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return null;
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    const doc = JSON.parse(text, refuseNonFinite);
    if (!isObject(doc)) return null;
    const id = own(doc, 'id');
    const type = own(doc, 'type');
    const created = own(doc, 'created');
    const obj = own(own(doc, 'data'), 'object');
    if (typeof id !== 'string' || !/^evt_[A-Za-z0-9_]{1,200}$/.test(id)) return null;
    if (typeof type !== 'string' || !/^[\x20-\x7e]{1,100}$/.test(type)) return null;
    if (!isTime(created) || !isObject(obj)) return null;
    return { id, type, created, object: obj };
  } catch {
    return null;
  }
}

'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const {
  signPayload, verifySignature, createStripeEntitlements, SqliteEntitlementStore
} = require('./stripe_webhook_entitlements_javascript.js');

/*
 * Tests for docs/specs/stripe_webhook_entitlements.md (STRIPEWH-01..STRIPEWH-14) with the spec's TEST VECTORS.
 * Stripe is a fake client (no network) and time a settable clock; every body is signed with sign_payload.
 * Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches an in-memory SQLite database only.
 */

const SECRET = 'whsec_' + 'test_secret_for_vectors';
const NOW = 1700000000;
const BODY = '{"id":"evt_test_0001","type":"customer.subscription.updated","created":1700000000,' +
  '"data":{"object":{"id":"sub_test_0001","customer":"cus_test_0001","status":"active",' +
  '"current_period_end":1702592000,"cancel_at_period_end":false,' +
  '"metadata":{"user_id":"user_1"},"items":{"data":[{"price":{"id":"price_pro_monthly"}}]}}}}';
const SPEC_HEADER = 't=1700000000,v1=5bca2d8b83d83f9a52f3b25714245817b15ae87b9e73abcca2c7a514977a8ae5';
const NONE = { entitled: false, plan: null, status: 'none', current_period_end: null, cancel_at_period_end: false };
const PLANS = { price_pro_monthly: 'pro', price_team_monthly: 'team' };
const USERS = new Set(['user_1', 'user_2', 'user_9']);

/**
 * A fake Stripe client: retrieveSubscription answers from `subs` (or throws while `fail` is set) and records ids.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function fakeStripe() {
  const client = {
    subs: new Map(),
    calls: [],
    fail: false,
    async retrieveSubscription(id) {
      client.calls.push(id);
      if (client.fail) throw new Error('stripe unavailable');
      return client.subs.get(id);
    }
  };
  return client;
}

/**
 * A service with the spec's configuration, a settable clock and a fake Stripe client.
 * Out: {svc, store, stripe, clock}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches an in-memory database.
 */
function setup(opts = {}) {
  const clock = { t: opts.now || NOW };
  const store = opts.store || new SqliteEntitlementStore();
  const stripe = opts.stripe || fakeStripe();
  const svc = createStripeEntitlements({
    store, webhookSecret: opts.secret || SECRET, pricePlans: opts.plans || PLANS, stripeClient: stripe,
    userExists: u => USERS.has(u), periodGraceSeconds: opts.grace || 0, clock: () => clock.t
  });
  return { svc, store, stripe, clock };
}

/**
 * A subscription object. In: overrides ({id, customer, status, current_period_end, price, user, items...}).
 * Out: object. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function sub(o = {}) {
  const s = {
    id: o.id || 'sub_test_0001', customer: o.customer || 'cus_test_0001', status: o.status || 'active',
    current_period_end: o.current_period_end === undefined ? 1702592000 : o.current_period_end,
    cancel_at_period_end: o.cancel_at_period_end || false,
    items: o.items || { data: [{ price: { id: o.price || 'price_pro_monthly' } }] }
  };
  if (o.current_period_end === null) delete s.current_period_end;
  if (o.user !== null) s.metadata = { user_id: o.user || 'user_1' };
  return s;
}

/**
 * An event body. In: id, type, created, data object. Out: JSON text. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches nothing.
 */
function event(id, type, created, object) {
  return JSON.stringify({ id, type, created, data: { object } });
}

/**
 * Signs a body at the service's clock and delivers it. Out: the handle_webhook answer.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
 */
function deliver(env, body) {
  return env.svc.handleWebhook(body, signPayload(body, SECRET, env.clock.t));
}

/** Row counts of both tables. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (read). */
function counts(store) {
  return {
    events: store.db.prepare('SELECT COUNT(*) AS n FROM stripe_events').get().n,
    subs: store.db.prepare('SELECT COUNT(*) AS n FROM entitlement_subscriptions').get().n
  };
}

const APPLIED = { status: 200, received: true, result: 'applied' };
const STALE = { status: 200, received: true, result: 'stale' };
const IGNORED = { status: 200, received: true, result: 'ignored' };
const DUPLICATE = { status: 200, received: true, result: 'duplicate' };

/**
 * STRIPEWH-01: sign_payload with the spec's secret, timestamp and body gives the spec's header; handle_webhook
 * with that header at now = 1700000000 answers 200 applied, and get_entitlement("user_1") is the spec's answer.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: STRIPEWH-01, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the Stripe client is a fake: no network).
 */
// STRIPEWH-01
test('STRIPEWH-01 the spec header, 200 applied and the spec entitlement', async () => {
  assert.strictEqual(Buffer.byteLength(BODY), 317);
  assert.strictEqual(crypto.createHash('sha256').update(BODY).digest('hex'), 'f2e8a2d52e46e4642dde0390c9def15047ff2178a8d33a9928698aca132cbe88');
  assert.strictEqual(signPayload(BODY, SECRET, 1700000000), SPEC_HEADER);
  assert.strictEqual(signPayload(Buffer.from(BODY), SECRET, 1700000000), SPEC_HEADER);
  const env = setup();
  assert.deepStrictEqual(await env.svc.handleWebhook(Buffer.from(BODY), SPEC_HEADER), APPLIED);
  assert.deepStrictEqual(env.svc.getEntitlement('user_1'), {
    entitled: true, plan: 'pro', status: 'active', current_period_end: 1702592000, cancel_at_period_end: false
  });
  assert.strictEqual(env.store.getEvent('evt_test_0001').result, 'applied');
});

/**
 * STRIPEWH-02: 400 invalid_signature, with nothing stored, for: another secret; one changed byte of the body; a
 * changed t; no v1 element; a v1 that is not 64 lower-case hex characters; only a v0 element; two t elements.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: STRIPEWH-02, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the Stripe client is a fake: no network).
 */
// STRIPEWH-02
test('STRIPEWH-02 bad signatures are 400 invalid_signature and store nothing', async () => {
  const good = SPEC_HEADER.split('v1=')[1];
  const changedBody = Buffer.from(BODY);
  changedBody[100] ^= 0x01;
  const cases = [
    [BODY, signPayload(BODY, 'whsec_' + 'another_secret_value', NOW)],
    [changedBody, SPEC_HEADER],
    [BODY, 't=1700000001,v1=' + good],
    [BODY, 't=1700000000'],
    [BODY, 't=1700000000,v1=' + good.toUpperCase()],
    [BODY, 't=1700000000,v1=' + good.slice(0, 63)],
    [BODY, 't=1700000000,v0=' + good],
    [BODY, 't=1700000000,t=1700000000,v1=' + good],
    [BODY, 't=,v1=' + good],
    [BODY, 'v1=' + good],
    [BODY, 't=1700000000,v1=' + good + ',' + 'x'.repeat(4096)]
  ];
  const env = setup();
  for (const [body, header] of cases) {
    assert.deepStrictEqual(await env.svc.handleWebhook(body, header), { error: 'invalid_signature', status: 400 }, header.slice(0, 40));
  }
  assert.deepStrictEqual(counts(env.store), { events: 0, subs: 0 });
});

/**
 * STRIPEWH-03: a missing or empty header is 400 missing_signature; a webhook_secret under 16 bytes is 503
 * webhook_not_configured for every call, whatever its signature.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: STRIPEWH-03, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the Stripe client is a fake: no network).
 */
// STRIPEWH-03
test('STRIPEWH-03 missing header is 400 missing_signature; a short secret is 503 for every call', async () => {
  const env = setup();
  for (const header of [undefined, null, '']) {
    assert.deepStrictEqual(await env.svc.handleWebhook(BODY, header), { error: 'missing_signature', status: 400 });
  }
  const shortSecret = 'whsec_' + 'short1234';
  assert.strictEqual(Buffer.byteLength(shortSecret), 15);
  const env2 = setup({ secret: shortSecret });
  for (const header of [signPayload(BODY, shortSecret, NOW), SPEC_HEADER, '', undefined, 'garbage']) {
    assert.deepStrictEqual(await env2.svc.handleWebhook(BODY, header), { error: 'webhook_not_configured', status: 503 });
  }
  assert.deepStrictEqual(counts(env2.store), { events: 0, subs: 0 });
  assert.deepStrictEqual(verifySignature(BODY, SPEC_HEADER, SECRET.slice(0, 15), NOW), { error: 'webhook_not_configured', status: 503 });
  assert.deepStrictEqual(verifySignature(BODY, SPEC_HEADER, SECRET.slice(0, 16), NOW), { error: 'invalid_signature', status: 400 });
});

/**
 * STRIPEWH-04: tolerance: a correctly signed event whose t is 300 seconds old is accepted, 301 seconds old is 400
 * timestamp_out_of_tolerance, and 301 seconds in the future is refused the same way.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: STRIPEWH-04, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the Stripe client is a fake: no network).
 */
// STRIPEWH-04
test('STRIPEWH-04 tolerance: 300 seconds either way is accepted, 301 is refused', async () => {
  const out = { error: 'timestamp_out_of_tolerance', status: 400 };
  for (const [now, expected] of [[1700000300, APPLIED], [1700000301, out], [1699999700, APPLIED], [1699999699, out]]) {
    const env = setup({ now });
    assert.deepStrictEqual(await env.svc.handleWebhook(BODY, SPEC_HEADER), expected, String(now));
    assert.strictEqual(counts(env.store).events, expected === APPLIED ? 1 : 0);
  }
});

/**
 * STRIPEWH-05: a header with two v1 values is accepted when either is right (the second, in the test), also with a
 * v0 element and spaces after the commas.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: STRIPEWH-05, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the Stripe client is a fake: no network).
 */
// STRIPEWH-05
test('STRIPEWH-05 two v1 values: accepted when the second is right, with a v0 element and spaces', async () => {
  const good = SPEC_HEADER.split('v1=')[1];
  const wrong = 'ab'.repeat(32);
  const env = setup();
  const header = 't=1700000000, v1=' + wrong + ',  v1=' + good + ', v0=' + wrong + ', junk';
  assert.deepStrictEqual(await env.svc.handleWebhook(BODY, header), APPLIED);
  assert.deepStrictEqual(verifySignature(BODY, header, SECRET, NOW), { ok: true, timestamp: 1700000000 });
});

/**
 * STRIPEWH-06: a correctly signed body that is not JSON, is not an object, has no evt_ id, no type, no whole-
 * number created or no data.object is 400 invalid_payload, and its id is not recorded; created given as true, as
 * "1700000000", as 1700000000.5, as -1 or as 100000000000 is invalid_payload, and created 1700000000.0 is
 * accepted.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: STRIPEWH-06, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the Stripe client is a fake: no network).
 */
// STRIPEWH-06
test('STRIPEWH-06 correctly signed bodies that are not valid events are 400 invalid_payload and not recorded', async () => {
  const obj = sub();
  const bad = [
    'not json', '[1,2,3]', '"text"', 'null',
    JSON.stringify({ type: 'customer.subscription.updated', created: NOW, data: { object: obj } }),
    JSON.stringify({ id: 'abc_1', type: 'customer.subscription.updated', created: NOW, data: { object: obj } }),
    JSON.stringify({ id: 'evt_1', created: NOW, data: { object: obj } }),
    JSON.stringify({ id: 'evt_1', type: '', created: NOW, data: { object: obj } }),
    JSON.stringify({ id: 'evt_1', type: 'customer.subscription.updated', data: { object: obj } }),
    JSON.stringify({ id: 'evt_1', type: 'customer.subscription.updated', created: NOW, data: {} }),
    JSON.stringify({ id: 'evt_1', type: 'customer.subscription.updated', created: NOW, data: { object: [1] } }),
    JSON.stringify({ id: 'evt_1', type: 'customer.subscription.updated', created: NOW }),
    '{"id":"evt_1","type":"customer.subscription.updated","created":true,"data":{"object":{}}}',
    '{"id":"evt_1","type":"customer.subscription.updated","created":"1700000000","data":{"object":{}}}',
    '{"id":"evt_1","type":"customer.subscription.updated","created":1700000000.5,"data":{"object":{}}}',
    '{"id":"evt_1","type":"customer.subscription.updated","created":-1,"data":{"object":{}}}',
    '{"id":"evt_1","type":"customer.subscription.updated","created":100000000000,"data":{"object":{}}}',
    '{"id":"evt_1","type":"customer.subscription.updated","created":1e400,"data":{"object":{}}}',
    '{"id":"evt_1","type":"customer.subscription.updated","created":null,"data":{"object":{}}}'
  ];
  const env = setup();
  for (const body of bad) {
    assert.deepStrictEqual(await deliver(env, body), { error: 'invalid_payload', status: 400 }, body.slice(0, 60));
  }
  const bom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(BODY)]);
  assert.deepStrictEqual(await env.svc.handleWebhook(bom, signPayload(bom, SECRET, NOW)), { error: 'invalid_payload', status: 400 });
  const badUtf8 = Buffer.from(BODY.replace('user_1', 'user_ÿ'), 'latin1');
  assert.deepStrictEqual(await env.svc.handleWebhook(badUtf8, signPayload(badUtf8, SECRET, NOW)), { error: 'invalid_payload', status: 400 });
  assert.deepStrictEqual(counts(env.store), { events: 0, subs: 0 });
  const whole = BODY.replace('"created":1700000000', '"created":1700000000.0');
  assert.deepStrictEqual(await deliver(env, whole), APPLIED);
  assert.strictEqual(env.store.getEvent('evt_test_0001').created, 1700000000);
  const sci = BODY.replace('"created":1700000000', '"created":1.7e9');
  const fresh = setup();
  assert.deepStrictEqual(await deliver(fresh, sci), APPLIED);
  assert.strictEqual(fresh.store.getSubscription('sub_test_0001').event_at, 1700000000);
});

/**
 * STRIPEWH-07: customer.subscription.created with status active, a known price and metadata.user_id gives
 * {entitled: true, plan, status: "active", current_period_end, cancel_at_period_end}; before that event the user's
 * answer is the "none" answer, and the event leaves another user's answer as it was.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: STRIPEWH-07, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the Stripe client is a fake: no network).
 */
// STRIPEWH-07
test('STRIPEWH-07 subscription.created grants the plan; the user had the none answer before; others unchanged', async () => {
  const env = setup();
  await deliver(env, event('evt_other', 'customer.subscription.created', 100, sub({ id: 'sub_other', customer: 'cus_2', user: 'user_2', price: 'price_team_monthly', current_period_end: 1800000000 })));
  const other = env.svc.getEntitlement('user_2');
  assert.deepStrictEqual(env.svc.getEntitlement('user_1'), NONE);
  assert.deepStrictEqual(await deliver(env, event('evt_c1', 'customer.subscription.created', 200, sub({ cancel_at_period_end: true }))), APPLIED);
  assert.deepStrictEqual(env.svc.getEntitlement('user_1'), {
    entitled: true, plan: 'pro', status: 'active', current_period_end: 1702592000, cancel_at_period_end: true
  });
  assert.deepStrictEqual(env.svc.getEntitlement('user_2'), other);
  assert.deepStrictEqual(other, { entitled: true, plan: 'team', status: 'active', current_period_end: 1800000000, cancel_at_period_end: false });
});

/**
 * STRIPEWH-08: the same event id delivered twice: the second answer is 200 duplicate and the subscription row is
 * unchanged.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: STRIPEWH-08, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the Stripe client is a fake: no network).
 */
// STRIPEWH-08
test('STRIPEWH-08 the same event id twice: the second is 200 duplicate and changes nothing', async () => {
  const env = setup();
  assert.deepStrictEqual(await env.svc.handleWebhook(BODY, SPEC_HEADER), APPLIED);
  const row = env.store.getSubscription('sub_test_0001');
  env.clock.t += 5;
  const changed = BODY.replace('"status":"active"', '"status":"past_due"');
  assert.deepStrictEqual(await deliver(env, changed), DUPLICATE);
  assert.deepStrictEqual(env.store.getSubscription('sub_test_0001'), row);
  assert.deepStrictEqual(counts(env.store), { events: 1, subs: 1 });
});

/**
 * STRIPEWH-09: out of order: after an event created at 200, an event for the same subscription created at 100 is
 * 200 stale and changes nothing; at an equal created time a created-type event does not overwrite an updated one,
 * and a deleted one overwrites both; a second updated event with the same created as the stored one makes the
 * system fetch the subscription through the injected client, and the row ends with the fetched state.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: STRIPEWH-09, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the Stripe client is a fake: no network).
 */
// STRIPEWH-09
test('STRIPEWH-09 out of order: older is stale, rank orders one second, an equal updated event fetches from Stripe', async () => {
  const env = setup();
  assert.deepStrictEqual(await deliver(env, event('evt_a', 'customer.subscription.updated', 200, sub())), APPLIED);
  const row = env.store.getSubscription('sub_test_0001');
  assert.deepStrictEqual(await deliver(env, event('evt_b', 'customer.subscription.updated', 100, sub({ status: 'past_due' }))), STALE);
  assert.deepStrictEqual(env.store.getSubscription('sub_test_0001'), row);
  assert.strictEqual(env.store.getEvent('evt_b').result, 'stale');
  // Equal created: created-type (rank 0) never overwrites updated (rank 1).
  assert.deepStrictEqual(await deliver(env, event('evt_c', 'customer.subscription.created', 200, sub({ status: 'incomplete' }))), STALE);
  assert.strictEqual(env.store.getSubscription('sub_test_0001').status, 'active');
  // A second updated with the same created asks Stripe and ends with the fetched state.
  env.stripe.subs.set('sub_test_0001', sub({ status: 'past_due', current_period_end: 1703000000 }));
  assert.deepStrictEqual(await deliver(env, event('evt_d', 'customer.subscription.updated', 200, sub({ status: 'trialing' }))), APPLIED);
  assert.deepStrictEqual(env.stripe.calls, ['sub_test_0001']);
  const fetched = env.store.getSubscription('sub_test_0001');
  assert.strictEqual(fetched.status, 'past_due');
  assert.strictEqual(fetched.current_period_end, 1703000000);
  // Deleted (rank 2) at the same second overwrites both; afterwards created and updated of that second are stale.
  assert.deepStrictEqual(await deliver(env, event('evt_e', 'customer.subscription.deleted', 200, sub({ status: 'active' }))), APPLIED);
  assert.strictEqual(env.store.getSubscription('sub_test_0001').status, 'canceled');
  assert.deepStrictEqual(await deliver(env, event('evt_f', 'customer.subscription.updated', 200, sub())), STALE);
  assert.deepStrictEqual(await deliver(env, event('evt_g', 'customer.subscription.created', 200, sub())), STALE);
  assert.strictEqual(env.store.getSubscription('sub_test_0001').status, 'canceled');
  assert.strictEqual(env.stripe.calls.length, 1);
  // A created event at an equal second after a created event (same rank 0) fetches too.
  const env2 = setup();
  await deliver(env2, event('evt_h', 'customer.subscription.created', 300, sub({ status: 'incomplete' })));
  // Lead ruling fed6e7b: rule b (price_id and plan) runs again on the fetched object, so a price Stripe now holds
  // replaces the one in the event.
  env2.stripe.subs.set('sub_test_0001', sub({ status: 'active', price: 'price_team_monthly' }));
  assert.deepStrictEqual(await deliver(env2, event('evt_i', 'customer.subscription.created', 300, sub({ status: 'incomplete' }))), APPLIED);
  assert.deepStrictEqual(env2.stripe.calls, ['sub_test_0001']);
  const tie = env2.store.getSubscription('sub_test_0001');
  assert.strictEqual(tie.status, 'active');
  assert.strictEqual(tie.price_id, 'price_team_monthly');
  assert.strictEqual(tie.plan, 'team');
});

/**
 * STRIPEWH-10: the entitlement ends at once when the status becomes past_due, unpaid or canceled, and for an
 * active status when current_period_end <= now (equal to now: not entitled; one second after now: entitled); with
 * period_grace_seconds 60 it lasts 60 seconds longer.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: STRIPEWH-10, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the Stripe client is a fake: no network).
 */
// STRIPEWH-10
test('STRIPEWH-10 non-payment ends access at once; the period end is exclusive; grace extends it', async () => {
  for (const status of ['past_due', 'unpaid', 'canceled']) {
    const env = setup();
    await deliver(env, event('evt_1', 'customer.subscription.updated', 100, sub()));
    assert.strictEqual(env.svc.getEntitlement('user_1').entitled, true);
    assert.deepStrictEqual(await deliver(env, event('evt_2', 'customer.subscription.updated', 101, sub({ status }))), APPLIED);
    assert.deepStrictEqual(env.svc.getEntitlement('user_1'), {
      entitled: false, plan: null, status, current_period_end: 1702592000, cancel_at_period_end: false
    });
  }
  const env = setup();
  await deliver(env, event('evt_1', 'customer.subscription.updated', 100, sub({ status: 'trialing', current_period_end: NOW + 1 })));
  assert.deepStrictEqual(env.svc.getEntitlement('user_1'), { entitled: true, plan: 'pro', status: 'trialing', current_period_end: NOW + 1, cancel_at_period_end: false });
  env.clock.t = NOW + 1;
  assert.deepStrictEqual(env.svc.getEntitlement('user_1'), { entitled: false, plan: null, status: 'trialing', current_period_end: NOW + 1, cancel_at_period_end: false });
  const graced = setup({ grace: 60, store: env.store });
  graced.clock.t = NOW + 60;
  assert.strictEqual(graced.svc.getEntitlement('user_1').entitled, true);
  graced.clock.t = NOW + 61;
  assert.strictEqual(graced.svc.getEntitlement('user_1').entitled, false);
});

/**
 * STRIPEWH-11: the period end is the top-level current_period_end, else the largest
 * items.data[].current_period_end; an event with neither keeps the stored period end.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: STRIPEWH-11, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the Stripe client is a fake: no network).
 */
// STRIPEWH-11
test('STRIPEWH-11 period end: top level, else the largest item period end, else the stored one', async () => {
  const env = setup();
  await deliver(env, event('evt_1', 'customer.subscription.updated', 100, sub({ current_period_end: 1702000000 })));
  assert.strictEqual(env.store.getSubscription('sub_test_0001').current_period_end, 1702000000);
  const items = { data: [
    { price: { id: 'price_pro_monthly' }, current_period_end: 1703000000 },
    { price: { id: 'price_other' }, current_period_end: 1704000000 },
    { price: { id: 'price_x' }, current_period_end: 1705000000.5 }
  ] };
  await deliver(env, event('evt_2', 'customer.subscription.updated', 101, sub({ current_period_end: null, items })));
  assert.strictEqual(env.store.getSubscription('sub_test_0001').current_period_end, 1704000000);
  await deliver(env, event('evt_3', 'customer.subscription.updated', 102, sub({ current_period_end: null, status: 'trialing' })));
  const row = env.store.getSubscription('sub_test_0001');
  assert.strictEqual(row.current_period_end, 1704000000);
  assert.strictEqual(row.status, 'trialing');
  // A new row with neither period end stores 0 and entitles nobody.
  await deliver(env, event('evt_4', 'customer.subscription.created', 103, sub({ id: 'sub_new', user: 'user_2', customer: 'cus_2', current_period_end: null })));
  assert.strictEqual(env.store.getSubscription('sub_new').current_period_end, 0);
  assert.strictEqual(env.svc.getEntitlement('user_2').entitled, false);
});

/**
 * STRIPEWH-12: 200 ignored, with no entitlement change, for: a new subscription whose price is not in price_plans;
 * a user that does not exist; an event type the system does not handle; a malformed subscription id; each of these
 * event ids is still recorded; a deleted event for a stored subscription is applied even when its price has left
 * price_plans; an updated event that moves a stored subscription to a price that is not in price_plans is applied,
 * and the user is no longer entitled.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: STRIPEWH-12, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the Stripe client is a fake: no network).
 */
// STRIPEWH-12
test('STRIPEWH-12 ignored events change nothing but are recorded; stored subscriptions still end', async () => {
  const env = setup();
  const cases = [
    ['evt_i1', event('evt_i1', 'customer.subscription.created', 100, sub({ id: 'sub_unknown_price', price: 'price_free' }))],
    ['evt_i2', event('evt_i2', 'customer.subscription.created', 100, sub({ id: 'sub_ghost', user: 'ghost_user', customer: 'cus_ghost' }))],
    ['evt_i3', event('evt_i3', 'invoice.paid', 100, { id: 'in_1' })],
    ['evt_i4', event('evt_i4', 'customer.subscription.created', 100, sub({ id: 'sub-bad!' }))],
    ['evt_i5', event('evt_i5', 'customer.subscription.created', 100, sub({ id: 'sub_bad_status', status: 'Active!' }))],
    ['evt_i6', event('evt_i6', 'checkout.session.completed', 100, { mode: 'payment', subscription: 'sub_x' })]
  ];
  for (const [id, body] of cases) {
    assert.deepStrictEqual(await deliver(env, body), IGNORED, id);
    assert.strictEqual(env.store.getEvent(id).result, 'ignored');
  }
  assert.strictEqual(counts(env.store).subs, 0);
  assert.deepStrictEqual(env.svc.getEntitlement('user_1'), NONE);
  assert.strictEqual(env.stripe.calls.length, 0);
  // A stored subscription's deleted event applies even after its price left price_plans.
  await deliver(env, event('evt_s1', 'customer.subscription.created', 200, sub()));
  assert.strictEqual(env.svc.getEntitlement('user_1').entitled, true);
  const later = setup({ store: env.store, plans: {} });
  assert.deepStrictEqual(await deliver(later, event('evt_s2', 'customer.subscription.updated', 201, sub())), APPLIED);
  assert.strictEqual(later.store.getSubscription('sub_test_0001').plan, 'pro');
  assert.deepStrictEqual(await deliver(later, event('evt_s3', 'customer.subscription.deleted', 202, sub())), APPLIED);
  assert.deepStrictEqual(later.svc.getEntitlement('user_1'), { entitled: false, plan: null, status: 'canceled', current_period_end: 1702592000, cancel_at_period_end: false });
  // An updated event moving a stored subscription to an unknown price applies and ends the entitlement.
  const env2 = setup();
  await deliver(env2, event('evt_u1', 'customer.subscription.created', 200, sub()));
  assert.deepStrictEqual(await deliver(env2, event('evt_u2', 'customer.subscription.updated', 201, sub({ price: 'price_legacy' }))), APPLIED);
  const row = env2.store.getSubscription('sub_test_0001');
  assert.strictEqual(row.price_id, 'price_legacy');
  assert.strictEqual(row.plan, null);
  assert.deepStrictEqual(env2.svc.getEntitlement('user_1'), { entitled: false, plan: null, status: 'active', current_period_end: 1702592000, cancel_at_period_end: false });
});

/**
 * STRIPEWH-13: checkout.session.completed: the subscription is fetched through the injected client by the
 * session's subscription id and the user is client_reference_id; when the client raises, the answer is 500
 * processing_failed, the event id is NOT recorded, and the same event delivered again is applied.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: STRIPEWH-13, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the Stripe client is a fake: no network).
 */
// STRIPEWH-13
test('STRIPEWH-13 checkout.session.completed fetches the subscription; a client error is 500 and the retry applies', async () => {
  const env = setup();
  const session = { id: 'cs_test_1', mode: 'subscription', subscription: 'sub_co_1', client_reference_id: 'user_9', customer: 'cus_9' };
  const body = event('evt_co_1', 'checkout.session.completed', 100, session);
  env.stripe.fail = true;
  assert.deepStrictEqual(await deliver(env, body), { error: 'processing_failed', status: 500 });
  assert.strictEqual(env.store.getEvent('evt_co_1'), null);
  assert.deepStrictEqual(counts(env.store), { events: 0, subs: 0 });
  env.stripe.fail = false;
  env.stripe.subs.set('sub_co_1', sub({ id: 'sub_co_1', customer: 'cus_9', user: null, price: 'price_team_monthly', current_period_end: 1800000000 }));
  assert.deepStrictEqual(await deliver(env, body), APPLIED);
  assert.deepStrictEqual(env.stripe.calls, ['sub_co_1', 'sub_co_1']);
  assert.deepStrictEqual(env.svc.getEntitlement('user_9'), { entitled: true, plan: 'team', status: 'active', current_period_end: 1800000000, cancel_at_period_end: false });
  assert.strictEqual(env.store.getSubscription('sub_co_1').event_rank, 1);
  // An updated event of a later second is applied over it; an older checkout is then stale without a Stripe call.
  await deliver(env, event('evt_co_2', 'customer.subscription.updated', 150, sub({ id: 'sub_co_1', customer: 'cus_9', user: null, price: 'price_team_monthly' })));
  assert.deepStrictEqual(await deliver(env, event('evt_co_3', 'checkout.session.completed', 120, session)), STALE);
  assert.strictEqual(env.stripe.calls.length, 2);
});

/**
 * STRIPEWH-14: one user with two subscriptions: ending one leaves the entitlement the other gives; an event
 * without metadata finds its user through the stored subscription or the customer id; an event naming another user
 * never moves a subscription.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: STRIPEWH-14, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the Stripe client is a fake: no network).
 */
// STRIPEWH-14
test('STRIPEWH-14 two subscriptions per user; user found through the row or customer; a subscription never moves', async () => {
  const env = setup();
  await deliver(env, event('evt_1', 'customer.subscription.created', 100, sub({ id: 'sub_a', price: 'price_pro_monthly', current_period_end: 2000000000 })));
  await deliver(env, event('evt_2', 'customer.subscription.created', 101, sub({ id: 'sub_b', price: 'price_team_monthly', current_period_end: 1900000000 })));
  assert.strictEqual(env.svc.getEntitlement('user_1').plan, 'pro');
  assert.deepStrictEqual(await deliver(env, event('evt_3', 'customer.subscription.deleted', 102, sub({ id: 'sub_a' }))), APPLIED);
  assert.deepStrictEqual(env.svc.getEntitlement('user_1'), { entitled: true, plan: 'team', status: 'active', current_period_end: 1900000000, cancel_at_period_end: false });
  // No metadata: the stored row names the user.
  assert.deepStrictEqual(await deliver(env, event('evt_4', 'customer.subscription.updated', 103, sub({ id: 'sub_b', user: null, price: 'price_team_monthly', cancel_at_period_end: true }))), APPLIED);
  assert.strictEqual(env.svc.getEntitlement('user_1').cancel_at_period_end, true);
  // No metadata and no row: the customer id names the user.
  assert.deepStrictEqual(await deliver(env, event('evt_5', 'customer.subscription.created', 104, sub({ id: 'sub_c', user: null, price: 'price_pro_monthly', current_period_end: 2100000000 }))), APPLIED);
  assert.strictEqual(env.store.getSubscription('sub_c').user_id, 'user_1');
  assert.strictEqual(env.svc.getEntitlement('user_1').current_period_end, 2100000000);
  // An event naming another (existing) user never moves the subscription.
  assert.deepStrictEqual(await deliver(env, event('evt_6', 'customer.subscription.updated', 105, sub({ id: 'sub_c', user: 'user_2', price: 'price_pro_monthly', current_period_end: 2100000000 }))), APPLIED);
  assert.strictEqual(env.store.getSubscription('sub_c').user_id, 'user_1');
  assert.deepStrictEqual(env.svc.getEntitlement('user_2'), NONE);
  // A customer shared by two users names nobody.
  await deliver(env, event('evt_7', 'customer.subscription.created', 106, sub({ id: 'sub_d', user: 'user_2', customer: 'cus_shared' })));
  await deliver(env, event('evt_8', 'customer.subscription.created', 107, sub({ id: 'sub_e', user: 'user_9', customer: 'cus_shared' })));
  assert.deepStrictEqual(await deliver(env, event('evt_9', 'customer.subscription.created', 108, sub({ id: 'sub_f', user: null, customer: 'cus_shared' }))), IGNORED);
});

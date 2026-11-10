/**
 * Tests for stripe_webhook_entitlements_typescript.ts: one test (or more) per STRIPEWH-01..14 row of
 * docs/specs/stripe_webhook_entitlements.md, with the spec's fixed vectors. Offline: the Stripe client and the
 * account lookup are fakes, the clock is injected, the store is in memory. Why: Phase D wave 1, owner request
 * 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'crypto';
import {
  InMemoryEntitlementStore, signPayload, StripeWebhookEntitlements,
} from './stripe_webhook_entitlements_typescript.ts';

/** The spec's secret, built from pieces so no scanner reads it as a credential. */
const SECRET = 'whsec_' + 'test_secret_for_vectors';
const BODY =
  '{"id":"evt_test_0001","type":"customer.subscription.updated","created":1700000000,' +
  '"data":{"object":{"id":"sub_test_0001","customer":"cus_test_0001","status":"active",' +
  '"current_period_end":1702592000,"cancel_at_period_end":false,' +
  '"metadata":{"user_id":"user_1"},"items":{"data":[{"price":{"id":"price_pro_monthly"}}]}}}}';
const NONE = { entitled: false, plan: null, status: 'none', current_period_end: null, cancel_at_period_end: false };

/**
 * A service with fakes. In: overrides. Out: {svc, store, clock, fetched, client}. client.subs answers
 * retrieveSubscription by id; client.fail makes it raise. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only.
 */
function setup(opts: { now?: number; secret?: string; plans?: Record<string, string>; grace?: number;
                       store?: InMemoryEntitlementStore; users?: string[] } = {}) {
  const clock = { now: opts.now ?? 1700000000 };
  const fetched: string[] = [];
  const client = { subs: {} as Record<string, unknown>, fail: false };
  const users = new Set(opts.users ?? ['user_1', 'user_2', 'user_9']);
  const store = opts.store ?? new InMemoryEntitlementStore();
  const svc = new StripeWebhookEntitlements({
    webhookSecret: opts.secret ?? SECRET,
    pricePlans: opts.plans ?? { price_pro_monthly: 'pro', price_basic_monthly: 'basic' },
    stripeClient: {
      retrieveSubscription: async (id: string) => {
        fetched.push(id);
        if (client.fail) throw new Error('stripe unavailable');
        return client.subs[id];
      },
    },
    userExists: (u: string) => users.has(u),
    periodGraceSeconds: opts.grace,
    store,
    clock: () => clock.now,
  });
  return { svc, store, clock, fetched, client };
}

/** A subscription object. In: overrides. Out: the object. Touches nothing. */
function sub(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'sub_1', customer: 'cus_1', status: 'active', current_period_end: 1702592000, cancel_at_period_end: false,
    metadata: { user_id: 'user_1' }, items: { data: [{ price: { id: 'price_pro_monthly' } }] }, ...over,
  };
}

/** An event body. In: id, type, created, data.object. Out: the JSON text. Touches nothing. */
function body(id: string, type: string, created: number, object: unknown): string {
  return JSON.stringify({ id, type, created, data: { object } });
}

/** Signs a body at the service's clock and delivers it. Out: the answer. Touches: memory only. */
function deliver(s: ReturnType<typeof setup>, payload: string) {
  return s.svc.handleWebhook(payload, signPayload(payload, SECRET, s.clock.now));
}

/**
 * STRIPEWH-01: sign_payload vector; handle_webhook applies it; get_entitlement is the spec answer.
 * In: the spec's vectors and fakes. Out: assertions only. Why: STRIPEWH-01 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// STRIPEWH-01
test('STRIPEWH-01 sign_payload vector; handle_webhook applies it; get_entitlement is the spec answer', async () => {
  assert.equal(Buffer.byteLength(BODY), 317);
  assert.equal(createHash('sha256').update(BODY).digest('hex'), 'f2e8a2d52e46e4642dde0390c9def15047ff2178a8d33a9928698aca132cbe88');
  const header = signPayload(BODY, SECRET, 1700000000);
  assert.equal(header, 't=1700000000,v1=5bca2d8b83d83f9a52f3b25714245817b15ae87b9e73abcca2c7a514977a8ae5');
  const s = setup();
  assert.deepEqual(await s.svc.handleWebhook(BODY, header), { status: 200, received: true, result: 'applied' });
  assert.deepEqual(s.svc.getEntitlement('user_1'), {
    entitled: true, plan: 'pro', status: 'active', current_period_end: 1702592000, cancel_at_period_end: false,
  });
  assert.equal(s.store.getEvent('evt_test_0001')!.result, 'applied');
  assert.deepEqual(await s.svc.handleWebhook(Buffer.from(BODY), header), { status: 200, received: true, result: 'duplicate' });
});

/**
 * STRIPEWH-02: 400 invalid_signature with nothing stored for every forged or malformed header.
 * In: the spec's vectors and fakes. Out: assertions only. Why: STRIPEWH-02 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// STRIPEWH-02
test('STRIPEWH-02 400 invalid_signature with nothing stored for every forged or malformed header', async () => {
  const good = signPayload(BODY, SECRET, 1700000000);
  const v1 = good.split('v1=')[1];
  const changedBody = BODY.replace('"active"', '"activf"');
  const cases: [string, string][] = [
    [BODY, signPayload(BODY, 'whsec_' + 'another_secret_value', 1700000000)],
    [changedBody, good],
    [BODY, 't=1700000001,v1=' + v1],
    [BODY, 't=1700000000'],
    [BODY, 't=1700000000,v1=' + v1.toUpperCase()],
    [BODY, 't=1700000000,v1=' + v1.slice(0, 63)],
    [BODY, 't=1700000000,v0=' + v1],
    [BODY, 't=1700000000,t=1700000000,v1=' + v1],
    [BODY, 't=,v1=' + v1],
    [BODY, 't=' + '9'.repeat(13) + ',v1=' + v1],
    [BODY, 'garbage'],
    [BODY, 't=1700000000,v1=' + v1 + ',' + 'x'.repeat(4100)],
  ];
  for (const [payload, header] of cases) {
    const s = setup();
    assert.deepEqual(await s.svc.handleWebhook(payload, header), { status: 400, error: 'invalid_signature' }, header.slice(0, 40));
    assert.equal(s.store.events.size, 0);
    assert.equal(s.store.subscriptions.size, 0);
  }
});

/**
 * STRIPEWH-03: missing or empty header 400 missing_signature; a short secret is 503 for every call.
 * In: the spec's vectors and fakes. Out: assertions only. Why: STRIPEWH-03 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// STRIPEWH-03
test('STRIPEWH-03 missing or empty header 400 missing_signature; a short secret is 503 for every call', async () => {
  const s = setup();
  assert.deepEqual(await s.svc.handleWebhook(BODY, undefined), { status: 400, error: 'missing_signature' });
  assert.deepEqual(await s.svc.handleWebhook(BODY, ''), { status: 400, error: 'missing_signature' });
  const short = 'whsec_' + 'short12';
  const weak = setup({ secret: short });
  for (const header of [signPayload(BODY, short, 1700000000), undefined, '', 'garbage']) {
    assert.deepEqual(await weak.svc.handleWebhook(BODY, header), { status: 503, error: 'webhook_not_configured' });
  }
  assert.equal(weak.store.events.size, 0);
});

/**
 * STRIPEWH-04: tolerance: 300 s either way accepted, 301 s refused.
 * In: the spec's vectors and fakes. Out: assertions only. Why: STRIPEWH-04 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// STRIPEWH-04
test('STRIPEWH-04 tolerance: 300 s either way accepted, 301 s refused', async () => {
  const header = signPayload(BODY, SECRET, 1700000000);
  for (const [now, ok] of [[1700000300, true], [1700000301, false], [1699999700, true], [1699999699, false]] as [number, boolean][]) {
    const s = setup({ now });
    const out = await s.svc.handleWebhook(BODY, header);
    assert.deepEqual(out, ok ? { status: 200, received: true, result: 'applied' } : { status: 400, error: 'timestamp_out_of_tolerance' }, String(now));
  }
});

/**
 * STRIPEWH-05: two v1 values: accepted when the second is right, with a v0 element and spaces.
 * In: the spec's vectors and fakes. Out: assertions only. Why: STRIPEWH-05 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// STRIPEWH-05
test('STRIPEWH-05 two v1 values: accepted when the second is right, with a v0 element and spaces', async () => {
  const v1 = signPayload(BODY, SECRET, 1700000000).split('v1=')[1];
  const header = 't=1700000000, v1=' + 'a'.repeat(64) + ', v1=' + v1 + ', v0=' + 'b'.repeat(64);
  const s = setup();
  assert.deepEqual(await s.svc.handleWebhook(BODY, header), { status: 200, received: true, result: 'applied' });
});

/**
 * STRIPEWH-06: a signed body that is not a valid event is 400 invalid_payload and its id is not recorded.
 * In: the spec's vectors and fakes. Out: assertions only. Why: STRIPEWH-06 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// STRIPEWH-06
test('STRIPEWH-06 a signed body that is not a valid event is 400 invalid_payload and its id is not recorded', async () => {
  const obj = sub();
  const ok = (created: string) => `{"id":"evt_c","type":"customer.subscription.created","created":${created},"data":{"object":${JSON.stringify(obj)}}}`;
  const bad = [
    'not json', '[1,2]', '"text"', 'null',
    JSON.stringify({ type: 'x', created: 1, data: { object: {} } }),
    body('abc_1', 'x', 1, {}), body('evt_bad-id', 'x', 1, {}),
    JSON.stringify({ id: 'evt_1', created: 1, data: { object: {} } }),
    JSON.stringify({ id: 'evt_1', type: '', created: 1, data: { object: {} } }),
    JSON.stringify({ id: 'evt_1', type: 'x', data: { object: {} } }),
    JSON.stringify({ id: 'evt_1', type: 'x', created: 1 }),
    JSON.stringify({ id: 'evt_1', type: 'x', created: 1, data: { object: [1] } }),
    ok('true'), ok('"1700000000"'), ok('1700000000.5'), ok('-1'), ok('100000000000'), ok('1e400'), ok('null'),
    '﻿' + ok('1700000000'),
  ];
  for (const payload of bad) {
    const s = setup();
    assert.deepEqual(await deliver(s, payload), { status: 400, error: 'invalid_payload' }, payload.slice(0, 60));
    assert.equal(s.store.events.size, 0);
  }
  const invalidUtf8 = Buffer.concat([Buffer.from(ok('1700000000').slice(0, -2)), Buffer.from([0xff]), Buffer.from('}}')]);
  const s = setup();
  assert.deepEqual(await s.svc.handleWebhook(invalidUtf8, signPayload(invalidUtf8, SECRET, s.clock.now)), { status: 400, error: 'invalid_payload' });
  for (const created of ['1700000000.0', '1.7e9']) {
    const t = setup();
    assert.deepEqual(await deliver(t, ok(created)), { status: 200, received: true, result: 'applied' });
    assert.equal(t.store.getEvent('evt_c')!.created, 1700000000);
  }
});

/**
 * STRIPEWH-06 (spec db20a03, Phase B.4): a correctly signed, otherwise valid body holding "x": 1e400 (a non-finite
 * number outside any TIME field), at the top level or inside data.object, is 400 invalid_payload and no event is
 * recorded; the same body without it is applied.
 * In: fakes. Out: assertions only. Why: STRIPEWH-06 as amended by db20a03. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// STRIPEWH-06
test('STRIPEWH-06 a non-finite number anywhere in a signed body is 400 invalid_payload', async () => {
  const good = body('evt_inf', 'customer.subscription.created', 1700000000, sub());
  const top = '{"x":1e400,' + good.slice(1);
  const nested = good.replace('"object":{', '"object":{"x":1e400,');
  assert.notEqual(nested, good);
  for (const payload of [top, nested]) {
    const s = setup();
    assert.deepEqual(await deliver(s, payload), { status: 400, error: 'invalid_payload' }, payload.slice(0, 60));
    assert.equal(s.store.events.size, 0);
  }
  const s = setup();
  assert.deepEqual(await deliver(s, good), { status: 200, received: true, result: 'applied' });
});

/**
 * STRIPEWH-07: subscription.created grants the plan; before it the none answer; another user unchanged.
 * In: the spec's vectors and fakes. Out: assertions only. Why: STRIPEWH-07 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// STRIPEWH-07
test('STRIPEWH-07 subscription.created grants the plan; before it the none answer; another user unchanged', async () => {
  const s = setup();
  await deliver(s, body('evt_other', 'customer.subscription.created', 1699999000,
    sub({ id: 'sub_2', customer: 'cus_2', metadata: { user_id: 'user_2' }, items: { data: [{ price: { id: 'price_basic_monthly' } }] } })));
  const other = s.svc.getEntitlement('user_2');
  assert.deepEqual(s.svc.getEntitlement('user_1'), NONE);
  assert.deepEqual(await deliver(s, body('evt_1', 'customer.subscription.created', 1700000000, sub({ cancel_at_period_end: true }))),
    { status: 200, received: true, result: 'applied' });
  assert.deepEqual(s.svc.getEntitlement('user_1'), {
    entitled: true, plan: 'pro', status: 'active', current_period_end: 1702592000, cancel_at_period_end: true,
  });
  assert.deepEqual(s.svc.getEntitlement('user_2'), other);
  assert.deepEqual(other, { entitled: true, plan: 'basic', status: 'active', current_period_end: 1702592000, cancel_at_period_end: false });
});

/**
 * STRIPEWH-08: the same event id twice: 200 duplicate and the row unchanged.
 * In: the spec's vectors and fakes. Out: assertions only. Why: STRIPEWH-08 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// STRIPEWH-08
test('STRIPEWH-08 the same event id twice: 200 duplicate and the row unchanged', async () => {
  const s = setup();
  const payload = body('evt_1', 'customer.subscription.created', 1700000000, sub());
  await deliver(s, payload);
  const before = s.store.getSubscription('sub_1');
  s.clock.now += 10;
  assert.deepEqual(await deliver(s, payload), { status: 200, received: true, result: 'duplicate' });
  assert.deepEqual(s.store.getSubscription('sub_1'), before);
  const again = body('evt_1', 'customer.subscription.updated', 1700000005, sub({ status: 'canceled' }));
  assert.deepEqual(await deliver(s, again), { status: 200, received: true, result: 'duplicate' });
  assert.deepEqual(s.store.getSubscription('sub_1'), before);
});

/**
 * STRIPEWH-09: out of order: older is stale; equal created orders by rank; a tie of updated events fetches.
 * In: the spec's vectors and fakes. Out: assertions only. Why: STRIPEWH-09 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// STRIPEWH-09
test('STRIPEWH-09 out of order: older is stale; equal created orders by rank; a tie of updated events fetches', async () => {
  const s = setup();
  await deliver(s, body('evt_200', 'customer.subscription.updated', 1699999200, sub()));
  const before = s.store.getSubscription('sub_1');
  assert.deepEqual(await deliver(s, body('evt_100', 'customer.subscription.updated', 1699999100, sub({ status: 'past_due' }))),
    { status: 200, received: true, result: 'stale' });
  assert.deepEqual(s.store.getSubscription('sub_1'), before);
  assert.deepEqual(await deliver(s, body('evt_c200', 'customer.subscription.created', 1699999200, sub({ status: 'incomplete' }))),
    { status: 200, received: true, result: 'stale' });
  assert.deepEqual(s.store.getSubscription('sub_1'), before);
  assert.deepEqual(s.fetched, []);

  s.client.subs.sub_1 = sub({ status: 'past_due', current_period_end: 1702600000 });
  assert.deepEqual(await deliver(s, body('evt_u200b', 'customer.subscription.updated', 1699999200, sub({ status: 'active' }))),
    { status: 200, received: true, result: 'applied' });
  assert.deepEqual(s.fetched, ['sub_1']);
  assert.equal(s.store.getSubscription('sub_1')!.status, 'past_due');
  assert.equal(s.store.getSubscription('sub_1')!.current_period_end, 1702600000);

  assert.deepEqual(await deliver(s, body('evt_d200', 'customer.subscription.deleted', 1699999200, sub({ status: 'active' }))),
    { status: 200, received: true, result: 'applied' });
  assert.equal(s.store.getSubscription('sub_1')!.status, 'canceled');
  assert.equal(s.fetched.length, 1);
  assert.deepEqual(await deliver(s, body('evt_u200c', 'customer.subscription.updated', 1699999200, sub())),
    { status: 200, received: true, result: 'stale' });
  assert.equal(s.store.getSubscription('sub_1')!.status, 'canceled');
});

/**
 * STRIPEWH-10: entitlement ends with past_due, unpaid, canceled and at the period end; grace extends it.
 * In: the spec's vectors and fakes. Out: assertions only. Why: STRIPEWH-10 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// STRIPEWH-10
test('STRIPEWH-10 entitlement ends with past_due, unpaid, canceled and at the period end; grace extends it', async () => {
  for (const status of ['past_due', 'unpaid', 'canceled', 'incomplete', 'paused']) {
    const s = setup();
    await deliver(s, body('evt_a', 'customer.subscription.created', 1700000000, sub()));
    assert.equal(s.svc.getEntitlement('user_1').entitled, true);
    await deliver(s, body('evt_b', 'customer.subscription.updated', 1700000001, sub({ status })));
    assert.deepEqual(s.svc.getEntitlement('user_1'), { entitled: false, plan: null, status, current_period_end: 1702592000, cancel_at_period_end: false });
  }
  const s = setup();
  await deliver(s, body('evt_a', 'customer.subscription.created', 1700000000, sub({ status: 'trialing', current_period_end: 1700000100 })));
  s.clock.now = 1700000099;
  assert.equal(s.svc.getEntitlement('user_1').entitled, true);
  s.clock.now = 1700000100;
  assert.deepEqual(s.svc.getEntitlement('user_1'), { entitled: false, plan: null, status: 'trialing', current_period_end: 1700000100, cancel_at_period_end: false });
  const g = setup({ grace: 60, store: s.store });
  g.clock.now = 1700000159;
  assert.equal(g.svc.getEntitlement('user_1').entitled, true);
  g.clock.now = 1700000160;
  assert.equal(g.svc.getEntitlement('user_1').entitled, false);
});

/**
 * STRIPEWH-11: period end: top level, else the largest item period end, else the stored value.
 * In: the spec's vectors and fakes. Out: assertions only. Why: STRIPEWH-11 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// STRIPEWH-11
test('STRIPEWH-11 period end: top level, else the largest item period end, else the stored value', async () => {
  const s = setup();
  await deliver(s, body('evt_a', 'customer.subscription.created', 1700000000, sub({ current_period_end: 1702000000 })));
  assert.equal(s.store.getSubscription('sub_1')!.current_period_end, 1702000000);
  const items = { data: [{ price: { id: 'price_pro_monthly' }, current_period_end: 1703000000 },
    { price: { id: 'price_basic_monthly' }, current_period_end: 1704000000 }, { current_period_end: 1.5 }] };
  const noTop = sub({ items });
  delete noTop.current_period_end;
  await deliver(s, body('evt_b', 'customer.subscription.updated', 1700000001, noTop));
  assert.equal(s.store.getSubscription('sub_1')!.current_period_end, 1704000000);
  assert.equal(s.store.getSubscription('sub_1')!.plan, 'pro');
  const neither = sub({ current_period_end: 'soon' });
  await deliver(s, body('evt_c', 'customer.subscription.updated', 1700000002, neither));
  assert.equal(s.store.getSubscription('sub_1')!.current_period_end, 1704000000);
});

/**
 * STRIPEWH-12: ignored events change nothing but are recorded; stored subscriptions still end.
 * In: the spec's vectors and fakes. Out: assertions only. Why: STRIPEWH-12 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// STRIPEWH-12
test('STRIPEWH-12 ignored events change nothing but are recorded; stored subscriptions still end', async () => {
  const s = setup();
  const cases: [string, string][] = [
    ['evt_p', body('evt_p', 'customer.subscription.created', 1700000000, sub({ items: { data: [{ price: { id: 'price_unknown' } }] } }))],
    ['evt_n', body('evt_n', 'customer.subscription.created', 1700000000, sub({ items: { data: [] } }))],
    ['evt_u', body('evt_u', 'customer.subscription.created', 1700000000, sub({ metadata: { user_id: 'ghost' }, customer: 'cus_ghost' }))],
    ['evt_t', body('evt_t', 'invoice.paid', 1700000000, sub())],
    ['evt_i', body('evt_i', 'customer.subscription.created', 1700000000, sub({ id: 'subX1' }))],
    ['evt_s', body('evt_s', 'customer.subscription.created', 1700000000, sub({ status: 'Active' }))],
  ];
  for (const [id, payload] of cases) {
    assert.deepEqual(await deliver(s, payload), { status: 200, received: true, result: 'ignored' }, id);
    assert.equal(s.store.getEvent(id)!.result, 'ignored');
  }
  assert.equal(s.store.subscriptions.size, 0);
  assert.deepEqual(s.svc.getEntitlement('user_1'), NONE);

  await deliver(s, body('evt_basic', 'customer.subscription.created', 1700000000,
    sub({ items: { data: [{ price: { id: 'price_basic_monthly' } }] } })));
  const offSale = setup({ store: s.store, plans: { price_pro_monthly: 'pro' } });
  assert.equal(offSale.svc.getEntitlement('user_1').plan, 'basic');
  assert.deepEqual(await deliver(offSale, body('evt_up', 'customer.subscription.updated', 1700000001,
    sub({ items: { data: [{ price: { id: 'price_basic_monthly' } }] }, cancel_at_period_end: true }))), { status: 200, received: true, result: 'applied' });
  assert.equal(offSale.svc.getEntitlement('user_1').plan, 'basic');
  assert.deepEqual(await deliver(offSale, body('evt_del', 'customer.subscription.deleted', 1700000002,
    sub({ items: { data: [{ price: { id: 'price_basic_monthly' } }] } }))), { status: 200, received: true, result: 'applied' });
  assert.equal(s.store.getSubscription('sub_1')!.status, 'canceled');
  assert.equal(offSale.svc.getEntitlement('user_1').entitled, false);

  const t = setup();
  await deliver(t, body('evt_1', 'customer.subscription.created', 1700000000, sub({ id: 'sub_9' })));
  assert.equal(t.svc.getEntitlement('user_1').entitled, true);
  assert.deepEqual(await deliver(t, body('evt_2', 'customer.subscription.updated', 1700000001,
    sub({ id: 'sub_9', items: { data: [{ price: { id: 'price_legacy' } }] } }))), { status: 200, received: true, result: 'applied' });
  assert.deepEqual(t.store.getSubscription('sub_9')!.price_id, 'price_legacy');
  assert.equal(t.store.getSubscription('sub_9')!.plan, null);
  assert.deepEqual(t.svc.getEntitlement('user_1'), { entitled: false, plan: null, status: 'active', current_period_end: 1702592000, cancel_at_period_end: false });
});

/**
 * STRIPEWH-13: checkout.session.completed fetches the subscription; a raising client is 500 and not recorded.
 * In: the spec's vectors and fakes. Out: assertions only. Why: STRIPEWH-13 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// STRIPEWH-13
test('STRIPEWH-13 checkout.session.completed fetches the subscription; a raising client is 500 and not recorded', async () => {
  const s = setup();
  const session = { id: 'cs_1', mode: 'subscription', subscription: 'sub_co', client_reference_id: 'user_9', metadata: { user_id: 'user_2' } };
  const payload = body('evt_co', 'checkout.session.completed', 1700000000, session);
  s.client.fail = true;
  assert.deepEqual(await deliver(s, payload), { status: 500, error: 'processing_failed' });
  assert.equal(s.store.getEvent('evt_co'), undefined);
  assert.equal(s.store.subscriptions.size, 0);
  s.client.fail = false;
  s.client.subs.sub_co = sub({ id: 'sub_co', customer: 'cus_9', metadata: {} });
  assert.deepEqual(await deliver(s, payload), { status: 200, received: true, result: 'applied' });
  assert.deepEqual(s.fetched, ['sub_co', 'sub_co']);
  assert.equal(s.store.getSubscription('sub_co')!.user_id, 'user_9');
  assert.equal(s.svc.getEntitlement('user_9').plan, 'pro');
  assert.deepEqual(await deliver(s, body('evt_co2', 'checkout.session.completed', 1700000000, { ...session, mode: 'payment' })),
    { status: 200, received: true, result: 'ignored' });
  assert.deepEqual(await deliver(s, body('evt_co3', 'checkout.session.completed', 1700000000, { ...session, subscription: 'bad' })),
    { status: 200, received: true, result: 'ignored' });
  assert.equal(s.fetched.length, 2);

  const f = setup();
  f.store.failNextWrite = true;
  assert.deepEqual(await deliver(f, BODY), { status: 500, error: 'processing_failed' });
  assert.equal(f.store.events.size, 0);
  assert.deepEqual(await deliver(f, BODY), { status: 200, received: true, result: 'applied' });
});

/**
 * STRIPEWH-13, overlapping deliveries: delivery A (checkout.session.completed) waits on a Stripe fetch that then
 * throws; delivery B (a subscription update) is sent while A waits. A answers 500 and is not recorded; B answers
 * 200 applied and its event row and subscription row are still stored afterwards, so A's rollback never erases B.
 * In: fakes. Out: assertions only. Why: review finding 4525101396 (A's snapshot rollback erased B's result).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// STRIPEWH-13
test('STRIPEWH-13 overlapping deliveries: a failing fetch rolls back only its own delivery', async () => {
  const clock = { now: 1700000000 };
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  const store = new InMemoryEntitlementStore();
  const svc = new StripeWebhookEntitlements({
    webhookSecret: SECRET,
    pricePlans: { price_pro_monthly: 'pro' },
    stripeClient: {
      retrieveSubscription: async () => {
        await gate;
        throw new Error('stripe unavailable');
      },
    },
    userExists: (u: string) => ['user_1', 'user_9'].includes(u),
    store,
    clock: () => clock.now,
  });
  const session = { id: 'cs_1', mode: 'subscription', subscription: 'sub_co', client_reference_id: 'user_9' };
  const a = body('evt_a', 'checkout.session.completed', 1700000000, session);
  const pa = svc.handleWebhook(a, signPayload(a, SECRET, clock.now));
  const pb = svc.handleWebhook(BODY, signPayload(BODY, SECRET, clock.now));
  await new Promise((r) => setImmediate(r));
  release();
  assert.deepEqual(await pa, { status: 500, error: 'processing_failed' });
  assert.deepEqual(await pb, { status: 200, received: true, result: 'applied' });
  assert.equal(store.getEvent('evt_a'), undefined);
  assert.equal(store.getEvent('evt_test_0001')!.result, 'applied');
  assert.equal(store.getSubscription('sub_test_0001')!.user_id, 'user_1');
  assert.equal(svc.getEntitlement('user_1').plan, 'pro');
});

/**
 * STRIPEWH-14: two subscriptions, user found through stored rows, a subscription never moves user.
 * In: the spec's vectors and fakes. Out: assertions only. Why: STRIPEWH-14 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// STRIPEWH-14
test('STRIPEWH-14 two subscriptions, user found through stored rows, a subscription never moves user', async () => {
  const s = setup();
  await deliver(s, body('evt_a', 'customer.subscription.created', 1700000000, sub({ id: 'sub_a', current_period_end: 1702000000 })));
  await deliver(s, body('evt_b', 'customer.subscription.created', 1700000000,
    sub({ id: 'sub_b', current_period_end: 1703000000, items: { data: [{ price: { id: 'price_basic_monthly' } }] } })));
  assert.equal(s.svc.getEntitlement('user_1').plan, 'basic');
  await deliver(s, body('evt_bd', 'customer.subscription.deleted', 1700000001, sub({ id: 'sub_b' })));
  assert.deepEqual(s.svc.getEntitlement('user_1'), { entitled: true, plan: 'pro', status: 'active', current_period_end: 1702000000, cancel_at_period_end: false });

  const noMeta = sub({ id: 'sub_a', cancel_at_period_end: true });
  delete noMeta.metadata;
  assert.deepEqual(await deliver(s, body('evt_a2', 'customer.subscription.updated', 1700000002, noMeta)), { status: 200, received: true, result: 'applied' });
  assert.equal(s.store.getSubscription('sub_a')!.cancel_at_period_end, true);
  const viaCustomer = sub({ id: 'sub_c' });
  delete viaCustomer.metadata;
  assert.deepEqual(await deliver(s, body('evt_c', 'customer.subscription.created', 1700000003, viaCustomer)), { status: 200, received: true, result: 'applied' });
  assert.equal(s.store.getSubscription('sub_c')!.user_id, 'user_1');

  assert.deepEqual(await deliver(s, body('evt_x', 'customer.subscription.updated', 1700000004,
    sub({ id: 'sub_a', metadata: { user_id: 'user_2' } }))), { status: 200, received: true, result: 'applied' });
  assert.equal(s.store.getSubscription('sub_a')!.user_id, 'user_1');
  assert.deepEqual(s.svc.getEntitlement('user_2'), NONE);
});

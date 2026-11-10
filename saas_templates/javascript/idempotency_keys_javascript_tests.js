const { test } = require('node:test');
const assert = require('node:assert');
const {
  InMemoryStore,
  SqliteStore,
  OperationFailed,
  computeFingerprint,
  isRequired,
  handle,
  release,
  resolve,
  listUncertain,
  purgeExpired,
  problemResponse
} = require('./idempotency_keys_javascript.js');

let operationCallCount;

async function makeOperation(status = 200, body = { ok: true }) {
  operationCallCount++;
  return { status, body };
}

async function makeFailingOperation() {
  operationCallCount++;
  throw new OperationFailed('Operation failed');
}

/**
 * An operation that fails with an error whose outcome is unknown (a timeout after the provider may have acted).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-10). Touches nothing.
 */
async function makeTimeoutOperation() {
  operationCallCount++;
  throw new Error('provider timed out');
}

/** A settable clock in ms for deterministic expiry. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function makeClock(start = 1767225600000) {
  const clock = { t: start, now: () => clock.t };
  return clock;
}

/** Asserts a 409 outcome_unknown problem. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function assertOutcomeUnknown(result) {
  assert.strictEqual(result.status, 409);
  assert.strictEqual(result.content_type, 'application/problem+json');
  const body = JSON.parse(result.body);
  assert.ok(body.type.endsWith('/outcome_unknown'));
  assert.ok(body.title && body.detail);
}

function createConfig(store, overrides = {}) {
  return { store, ...overrides };
}

// IDEM-01
test('first call runs the operation once', async () => {
  const store = new InMemoryStore();
  operationCallCount = 0;

  const result = await handle('user1', 'key-1', 'POST', '/api/resource', { data: 'test' }, () => makeOperation(201, { id: 1 }), createConfig(store));

  assert.strictEqual(result.status, 201);
  assert.strictEqual(result.content_type, 'application/json');
  assert.deepStrictEqual(JSON.parse(result.body), { id: 1 });
  assert.strictEqual(operationCallCount, 1);
});

// IDEM-02
test('second identical call returns stored response and operation count stays at 1', async () => {
  const store = new InMemoryStore();
  operationCallCount = 0;

  await handle('user1', 'key-2', 'POST', '/api/resource', { data: 'test' }, () => makeOperation(201, { id: 2 }), createConfig(store));
  const result = await handle('user1', 'key-2', 'POST', '/api/resource', { data: 'test' }, () => makeOperation(201, { id: 999 }), createConfig(store));

  assert.strictEqual(result.status, 201);
  assert.deepStrictEqual(JSON.parse(result.body), { id: 2 });
  assert.strictEqual(operationCallCount, 1);
});

// IDEM-03
test('same key different body returns 422', async () => {
  const store = new InMemoryStore();
  operationCallCount = 0;

  await handle('user1', 'key-3', 'POST', '/api/resource', { data: 'first' }, () => makeOperation(201, { id: 3 }), createConfig(store));
  const result = await handle('user1', 'key-3', 'POST', '/api/resource', { data: 'second' }, () => makeOperation(201, { id: 999 }), createConfig(store));

  assert.strictEqual(result.status, 422);
  assert.strictEqual(result.content_type, 'application/problem+json');
  const body = JSON.parse(result.body);
  assert.ok(body.type.includes('unprocessable-content'));
  assert.strictEqual(operationCallCount, 1);
});

// IDEM-04
test('same key while first is in progress returns 409', async () => {
  const store = new InMemoryStore();
  operationCallCount = 0;

  let resolveFirst;
  const firstPromise = handle('user1', 'key-4', 'POST', '/api/resource', { data: 'test' }, () => new Promise((resolve) => {
    resolveFirst = () => resolve(makeOperation(201, { id: 4 }));
  }), createConfig(store));

  const secondResult = await handle('user1', 'key-4', 'POST', '/api/resource', { data: 'test' }, () => makeOperation(201, { id: 999 }), createConfig(store));

  assert.strictEqual(secondResult.status, 409);
  assert.strictEqual(secondResult.content_type, 'application/problem+json');
  const body = JSON.parse(secondResult.body);
  assert.ok(body.type.includes('conflict'));

  resolveFirst();
  await firstPromise;
  assert.strictEqual(operationCallCount, 1);
});

// IDEM-05
test('required operation with no key returns 400', async () => {
  const store = new InMemoryStore();
  operationCallCount = 0;

  const result = await handle('user1', null, 'POST', '/api/resource', { data: 'test' }, () => makeOperation(201, { id: 5 }), createConfig(store));

  assert.strictEqual(result.status, 400);
  assert.strictEqual(result.content_type, 'application/problem+json');
  const body = JSON.parse(result.body);
  assert.ok(body.type.includes('missing-idempotency-key'));
  assert.strictEqual(operationCallCount, 0);
});

// IDEM-06
test('same key under two different scopes runs twice independently', async () => {
  const store = new InMemoryStore();
  operationCallCount = 0;

  await handle('user1', 'shared-key', 'POST', '/api/resource', { data: 'user1' }, () => makeOperation(201, { id: 101 }), createConfig(store));
  await handle('user2', 'shared-key', 'POST', '/api/resource', { data: 'user2' }, () => makeOperation(201, { id: 102 }), createConfig(store));

  assert.strictEqual(operationCallCount, 2);
});

// IDEM-07
// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: an injected clock replaces a 10 ms sleep (deterministic), and the
// amended row adds the in_progress half below.
test('expired completed key runs the operation again', async () => {
  const store = new InMemoryStore();
  const clock = makeClock();
  operationCallCount = 0;

  const config = createConfig(store, { now: clock.now });
  await handle('user1', 'key-expired', 'POST', '/api/resource', { data: 'test' }, () => makeOperation(201, { id: 6 }), config);

  clock.t += 24 * 60 * 60 * 1000 - 1;
  const still = await handle('user1', 'key-expired', 'POST', '/api/resource', { data: 'test' }, () => makeOperation(201, { id: 7 }), config);
  assert.deepStrictEqual(JSON.parse(still.body), { id: 6 });
  assert.strictEqual(operationCallCount, 1);

  clock.t += 1;
  const result = await handle('user1', 'key-expired', 'POST', '/api/resource', { data: 'test' }, () => makeOperation(201, { id: 7 }), config);

  assert.strictEqual(result.status, 201);
  assert.deepStrictEqual(JSON.parse(result.body), { id: 7 });
  assert.strictEqual(operationCallCount, 2);
});

/**
 * IDEM-07 (second half): an in_progress record past expires_at (the process died mid-operation) is uncertain: a retry
 * gets 409 outcome_unknown, the operation does not run, purge_expired keeps it and list_uncertain shows it.
 * Run against both stores. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the stores only.
 */
// IDEM-07
test('in_progress key past expires_at gets 409 outcome_unknown and does not run', async () => {
  for (const store of [new InMemoryStore(), new SqliteStore(':memory:')]) {
    const clock = makeClock();
    const config = createConfig(store, { now: clock.now });
    operationCallCount = 0;
    // A claim whose operation never finished (the process was killed): the record stays in_progress.
    await store.claim('user1', 'key-crashed', computeFingerprint('POST', '/api/charge', { amount: 5 }), clock.t, clock.t + 24 * 60 * 60 * 1000);
    const during = await handle('user1', 'key-crashed', 'POST', '/api/charge', { amount: 5 }, () => makeOperation(201, { id: 1 }), config);
    assert.strictEqual(during.status, 409);
    assert.ok(!JSON.parse(during.body).type.endsWith('/outcome_unknown'));

    clock.t += 24 * 60 * 60 * 1000;
    await purgeExpired(config);
    const after = await handle('user1', 'key-crashed', 'POST', '/api/charge', { amount: 5 }, () => makeOperation(201, { id: 1 }), config);
    assertOutcomeUnknown(after);
    assert.strictEqual(operationCallCount, 0);
    const different = await handle('user1', 'key-crashed', 'POST', '/api/charge', { amount: 6 }, () => makeOperation(201, { id: 1 }), config);
    assert.strictEqual(different.status, 422);
    assert.deepStrictEqual((await listUncertain(10, config)).map(r => r.idem_key), ['key-crashed']);
    if (store.close) store.close();
  }
});

// IDEM-08
// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: only OperationFailed (a definite failure) frees the key now; the
// failing operation used to throw a plain Error, which under the amended spec leaves the key 'uncertain' (IDEM-10).
test('operation that throws OperationFailed frees the key: retry runs the operation', async () => {
  const store = new InMemoryStore();
  operationCallCount = 0;

  try {
    await handle('user1', 'key-error', 'POST', '/api/resource', { data: 'test' }, () => makeFailingOperation(), createConfig(store));
    assert.fail('Expected operation to throw');
  } catch (e) {
    assert.ok(e instanceof OperationFailed);
    assert.strictEqual(e.message, 'Operation failed');
  }

  assert.strictEqual(operationCallCount, 1);

  const result = await handle('user1', 'key-error', 'POST', '/api/resource', { data: 'test' }, () => makeOperation(201, { id: 8 }), createConfig(store));

  assert.strictEqual(result.status, 201);
  assert.deepStrictEqual(JSON.parse(result.body), { id: 8 });
  assert.strictEqual(operationCallCount, 2);
});

/**
 * IDEM-10: any other error leaves the key 'uncertain': the error is rethrown, a retry gets 409 outcome_unknown and the
 * operation count stays at 1 (also after the 24 h expiry); release() frees it, and then a retry runs the operation.
 * Run against both stores. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the stores only.
 */
// IDEM-10
test('any other error leaves the key uncertain until release()', async () => {
  for (const store of [new InMemoryStore(), new SqliteStore(':memory:')]) {
    const clock = makeClock();
    const config = createConfig(store, { now: clock.now });
    operationCallCount = 0;
    await assert.rejects(
      handle('user1', 'key-timeout', 'POST', '/api/charge', { amount: 5 }, () => makeTimeoutOperation(), config),
      /provider timed out/
    );
    assert.strictEqual((await store.get('user1', 'key-timeout')).status, 'uncertain');
    assertOutcomeUnknown(await handle('user1', 'key-timeout', 'POST', '/api/charge', { amount: 5 }, () => makeOperation(201, { id: 1 }), config));
    clock.t += 48 * 60 * 60 * 1000;
    await purgeExpired(config);
    assertOutcomeUnknown(await handle('user1', 'key-timeout', 'POST', '/api/charge', { amount: 5 }, () => makeOperation(201, { id: 1 }), config));
    assert.strictEqual(operationCallCount, 1);

    assert.strictEqual(await release('user2', 'key-timeout', config), false); // another scope's key is not this one
    assert.strictEqual(await release('user1', 'key-timeout', config), true);
    assert.strictEqual(await release('user1', 'key-timeout', config), false);
    const retried = await handle('user1', 'key-timeout', 'POST', '/api/charge', { amount: 5 }, () => makeOperation(201, { id: 2 }), config);
    assert.strictEqual(retried.status, 201);
    assert.deepStrictEqual(JSON.parse(retried.body), { id: 2 });
    assert.strictEqual(operationCallCount, 2);
    // release() on a completed key changes nothing
    assert.strictEqual(await release('user1', 'key-timeout', config), false);
    if (store.close) store.close();
  }
});

/**
 * IDEM-11: resolve() stores the reconciled response on an uncertain key (expires_at = now + 24 h); a retry returns it
 * without running the operation; a second resolve() or release() returns false; of two concurrent resolve/release
 * calls exactly one returns true. Run against both stores. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches the stores only.
 */
// IDEM-11
test('resolve() stores the reconciled response once', async () => {
  for (const store of [new InMemoryStore(), new SqliteStore(':memory:')]) {
    const clock = makeClock();
    const config = createConfig(store, { now: clock.now });
    operationCallCount = 0;
    await assert.rejects(handle('user1', 'key-r', 'POST', '/api/charge', { amount: 5 }, () => makeTimeoutOperation(), config));
    clock.t += 1000;
    assert.strictEqual(await resolve('user1', 'key-r', 201, { charge_id: 'ch_1' }, config), true);
    const rec = await store.get('user1', 'key-r');
    assert.strictEqual(rec.status, 'completed');
    assert.strictEqual(rec.expires_at, clock.t + 24 * 60 * 60 * 1000);
    const replay = await handle('user1', 'key-r', 'POST', '/api/charge', { amount: 5 }, () => makeOperation(201, { charge_id: 'ch_2' }), config);
    assert.strictEqual(replay.status, 201);
    assert.deepStrictEqual(JSON.parse(replay.body), { charge_id: 'ch_1' });
    assert.strictEqual(operationCallCount, 1);
    assert.strictEqual(await resolve('user1', 'key-r', 500, { other: true }, config), false);
    assert.strictEqual(await release('user1', 'key-r', config), false);
    assert.deepStrictEqual(JSON.parse((await store.get('user1', 'key-r')).response_body), { charge_id: 'ch_1' });

    await assert.rejects(handle('user1', 'key-race', 'POST', '/api/charge', { amount: 7 }, () => makeTimeoutOperation(), config));
    const outcomes = await Promise.all([
      resolve('user1', 'key-race', 201, { charge_id: 'ch_9' }, config),
      release('user1', 'key-race', config),
      resolve('user1', 'key-race', 201, { charge_id: 'ch_8' }, config)
    ]);
    assert.strictEqual(outcomes.filter(Boolean).length, 1);
    assert.deepStrictEqual(await listUncertain(10, config), []);
    if (store.close) store.close();
  }
});

// IDEM-09
test('error responses carry content_type application/problem+json and body with type title detail', async () => {
  const store = new InMemoryStore();
  operationCallCount = 0;

  const missingKeyResult = await handle('user1', null, 'POST', '/api/resource', { data: 'test' }, () => makeOperation(201, { id: 9 }), createConfig(store));
  assert.strictEqual(missingKeyResult.content_type, 'application/problem+json');
  const missingKeyBody = JSON.parse(missingKeyResult.body);
  assert.ok(missingKeyBody.type);
  assert.ok(missingKeyBody.title);
  assert.ok(missingKeyBody.detail);

  await handle('user1', 'key-err2', 'POST', '/api/resource', { data: 'first' }, () => makeOperation(201, { id: 9 }), createConfig(store));
  const mismatchResult = await handle('user1', 'key-err2', 'POST', '/api/resource', { data: 'second' }, () => makeOperation(201, { id: 999 }), createConfig(store));
  assert.strictEqual(mismatchResult.content_type, 'application/problem+json');
  const mismatchBody = JSON.parse(mismatchResult.body);
  assert.ok(mismatchBody.type);
  assert.ok(mismatchBody.title);
  assert.ok(mismatchBody.detail);

  let resolveFirst;
  const firstPromise = handle('user1', 'key-err3', 'POST', '/api/resource', { data: 'test' }, () => new Promise((resolve) => {
    resolveFirst = () => resolve(makeOperation(201, { id: 9 }));
  }), createConfig(store));
  const inProgressResult = await handle('user1', 'key-err3', 'POST', '/api/resource', { data: 'test' }, () => makeOperation(201, { id: 999 }), createConfig(store));
  assert.strictEqual(inProgressResult.content_type, 'application/problem+json');
  const inProgressBody = JSON.parse(inProgressResult.body);
  assert.ok(inProgressBody.type);
  assert.ok(inProgressBody.title);
  assert.ok(inProgressBody.detail);
  resolveFirst();
  await firstPromise;
});

test('isRequired returns true for POST and PATCH by default', () => {
  assert.strictEqual(isRequired('POST', '/api/resource'), true);
  assert.strictEqual(isRequired('PATCH', '/api/resource'), true);
  assert.strictEqual(isRequired('GET', '/api/resource'), false);
  assert.strictEqual(isRequired('PUT', '/api/resource'), false);
  assert.strictEqual(isRequired('DELETE', '/api/resource'), false);
});

test('isRequired respects custom config', () => {
  const config = { idempotentMethods: new Set(['POST', 'PUT']) };
  assert.strictEqual(isRequired('POST', '/api/resource', config), true);
  assert.strictEqual(isRequired('PUT', '/api/resource', config), true);
  assert.strictEqual(isRequired('PATCH', '/api/resource', config), false);
});

test('computeFingerprint produces consistent hashes', () => {
  const fp1 = computeFingerprint('POST', '/api/resource', { a: 1 });
  const fp2 = computeFingerprint('POST', '/api/resource', { a: 1 });
  const fp3 = computeFingerprint('POST', '/api/resource', { a: 2 });
  assert.strictEqual(fp1, fp2);
  assert.notStrictEqual(fp1, fp3);
  assert.strictEqual(fp1.length, 64);
});

test('SqliteStore works correctly', async () => {
  const store = new SqliteStore(':memory:');
  operationCallCount = 0;

  const result = await handle('user1', 'sqlite-key', 'POST', '/api/resource', { data: 'test' }, () => makeOperation(201, { id: 10 }), createConfig(store));
  assert.strictEqual(result.status, 201);
  assert.deepStrictEqual(JSON.parse(result.body), { id: 10 });
  assert.strictEqual(operationCallCount, 1);

  const cached = await handle('user1', 'sqlite-key', 'POST', '/api/resource', { data: 'test' }, () => makeOperation(201, { id: 999 }), createConfig(store));
  assert.strictEqual(cached.status, 201);
  assert.deepStrictEqual(JSON.parse(cached.body), { id: 10 });
  assert.strictEqual(operationCallCount, 1);

  store.close();
});

// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: an injected clock replaces a 10 ms sleep (deterministic).
test('purgeExpired removes expired completed records', async () => {
  const store = new InMemoryStore();
  const clock = makeClock();
  operationCallCount = 0;

  const shortTtlConfig = createConfig(store, { ttlMs: 1, now: clock.now });
  await handle('user1', 'key-purge', 'POST', '/api/resource', { data: 'test' }, () => makeOperation(201, { id: 11 }), shortTtlConfig);

  clock.t += 10;

  await purgeExpired(shortTtlConfig);
  assert.strictEqual(await store.get('user1', 'key-purge'), null);

  const result = await handle('user1', 'key-purge', 'POST', '/api/resource', { data: 'test' }, () => makeOperation(201, { id: 12 }), shortTtlConfig);
  assert.strictEqual(result.status, 201);
  assert.deepStrictEqual(JSON.parse(result.body), { id: 12 });
  assert.strictEqual(operationCallCount, 2);
});

test('non-idempotent method without key runs operation', async () => {
  const store = new InMemoryStore();
  operationCallCount = 0;

  const result = await handle('user1', null, 'GET', '/api/resource', null, () => makeOperation(200, { data: 'ok' }), createConfig(store));

  assert.strictEqual(result.status, 200);
  assert.deepStrictEqual(JSON.parse(result.body), { data: 'ok' });
  assert.strictEqual(operationCallCount, 1);
});
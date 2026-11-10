'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const {
  normalizeEmail, generateCode, createEmailCodeSignin, SqliteEmailCodeStore, EmailCodeError
} = require('./passwordless_email_code_signin_javascript.js');

/*
 * Tests for docs/specs/passwordless_email_code_signin.md (EMAILCODE-01..EMAILCODE-14) with the spec's TEST VECTORS.
 * The sender is a fake that records its calls (no network), time a settable clock and codes an injectable queue.
 * Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches an in-memory SQLite database only.
 */

const SECRET = '0123456789abcdef0123456789abcdef';
const T0 = 1699920000;
const ACCEPTED = { status: 202, sent: true, expires_in: 600 };
const INVALID = { error: 'invalid_code', status: 400 };
const LIMITED = { error: 'too_many_requests', status: 429 };

/**
 * A fake sender recording [to, code, expiresIn]; `answer` may be true, false or a function that throws.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function fakeSender() {
  const s = {
    calls: [],
    answer: true,
    async sendCode(to, code, expiresIn) {
      s.calls.push([to, code, expiresIn]);
      return typeof s.answer === 'function' ? s.answer() : s.answer;
    }
  };
  return s;
}

/**
 * A service with the spec's secret, a settable clock, a code queue (falls back to the default generator over a
 * deterministic byte stream), a recording revoke_unproven, and a store that counts account reads.
 * Out: {svc, store, sender, clock, codes, revoked, accountReads}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches an in-memory database.
 */
function setup(opts = {}) {
  const clock = { t: opts.start || T0 };
  const store = new SqliteEmailCodeStore();
  const env = { store, clock, codes: [], revoked: [], accountReads: 0, sender: fakeSender() };
  const find = store.findAccountByEmail.bind(store);
  store.findAccountByEmail = email => { env.accountReads++; return find(email); };
  let i = 0;
  const stream = n => {
    const out = [];
    for (let j = 0; j < n; j++, i++) out.push(crypto.createHash('sha256').update('bytes:' + Math.floor(i / 32)).digest()[i % 32]);
    return Buffer.from(out);
  };
  env.svc = createEmailCodeSignin({
    store, secret: SECRET, sender: env.sender, clock: () => clock.t, randomBytes: stream,
    generateCode: () => (env.codes.length ? env.codes.shift() : generateCode(stream)),
    revokeUnproven: opts.revoke || (id => { env.revoked.push(id); })
  });
  return env;
}

/** The last code the sender received. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
function lastCode(env) {
  return env.sender.calls[env.sender.calls.length - 1][1];
}

/** A 6-digit code different from c. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
function wrong(c) {
  return c === '111111' ? '222222' : '111111';
}

/** Inserts an account row directly. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
function addAccount(env, id, email, verifiedAt, status = 'active') {
  env.store.db.prepare('INSERT INTO accounts (id, email, email_verified_at, status, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(id, email, verifiedAt, status, 1);
}

/**
 * EMAILCODE-01: start answers 202 {sent: true, expires_in: 600} and the sender gets one 6-digit code; verify with
 * it answers 200 with new_account true and the account exists with email_verified_at set; a second sign-in for the
 * address gives the same account_id with new_account false; for a row that exists with email_verified_at null the
 * right code calls revoke_unproven once with its id and then sets email_verified_at, and an account made by verify
 * never calls it.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: EMAILCODE-01, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the sender is a fake: no network).
 */
// EMAILCODE-01
test('EMAILCODE-01 start sends one code; verify signs in and creates or finds the account; unproven rows are revoked', async () => {
  const env = setup();
  assert.deepStrictEqual(await env.svc.start('new@example.com', '203.0.113.7'), ACCEPTED);
  assert.strictEqual(env.sender.calls.length, 1);
  const [to, code, ttl] = env.sender.calls[0];
  assert.strictEqual(to, 'new@example.com');
  assert.match(code, /^[0-9]{6}$/);
  assert.strictEqual(ttl, 600);
  const r = await env.svc.verify('new@example.com', code, '203.0.113.7');
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.new_account, true);
  assert.strictEqual(r.email, 'new@example.com');
  assert.match(r.account_id, /^[0-9a-f]{32}$/);
  const row = env.store.db.prepare('SELECT * FROM accounts WHERE id = ?').get(r.account_id);
  assert.strictEqual(row.email_verified_at, T0);
  env.clock.t += 60;
  await env.svc.start('new@example.com', '203.0.113.7');
  assert.deepStrictEqual(await env.svc.verify('new@example.com', lastCode(env), '203.0.113.7'),
    { status: 200, account_id: r.account_id, email: 'new@example.com', new_account: false });
  assert.deepStrictEqual(env.revoked, []);
  // A row that exists unverified: revoke_unproven once, then verified.
  addAccount(env, 'acct_unproven', 'invited@example.com', null);
  await env.svc.start('invited@example.com', '203.0.113.7');
  assert.deepStrictEqual(await env.svc.verify('invited@example.com', lastCode(env), '203.0.113.7'),
    { status: 200, account_id: 'acct_unproven', email: 'invited@example.com', new_account: false });
  assert.deepStrictEqual(env.revoked, ['acct_unproven']);
  assert.strictEqual(env.store.findAccountByEmail('invited@example.com').email_verified_at, env.clock.t);
  // A revoke that raises leaves the row unverified: 500 processing_failed.
  const failing = setup({ revoke: () => { throw new Error('revocation failed'); } });
  addAccount(failing, 'acct_x', 'x@example.com', null);
  await failing.svc.start('x@example.com', '1.1.1.1');
  assert.deepStrictEqual(await failing.svc.verify('x@example.com', lastCode(failing), '1.1.1.1'), { error: 'processing_failed', status: 500 });
  assert.strictEqual(failing.store.findAccountByEmail('x@example.com').email_verified_at, null);
});

/**
 * EMAILCODE-02: storage: with the spec's secret, address and code the stored code_hash is the spec's value;
 * email_codes and rate_windows hold neither the address, the IP nor the code, and no plain SHA-256 of the code.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: EMAILCODE-02, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the sender is a fake: no network).
 */
// EMAILCODE-02
test('EMAILCODE-02 stored hashes are the spec values; no address, IP, code or plain SHA-256 is stored', async () => {
  const env = setup();
  assert.strictEqual(env.svc.emailHash('user@example.com'), '587522269e243312a5d6f20bcdc78dc97a3e644e2ad702cdb94ac9550c03b346');
  assert.strictEqual(env.svc.codeHash('user@example.com', '123456'), '761f222c89dc1744c480d21e141277cc9af815ee0e2a1d7489c9282594728b5b');
  assert.strictEqual(env.svc.ipHash('203.0.113.7'), 'e01c4eeb03c058165d49564dcaf561cf');
  env.codes.push('123456');
  assert.deepStrictEqual(await env.svc.start('user@example.com', '203.0.113.7'), ACCEPTED);
  const codes = env.store.db.prepare('SELECT * FROM email_codes').all().map(r => ({ ...r }));
  assert.deepStrictEqual(codes, [{
    email_hash: '587522269e243312a5d6f20bcdc78dc97a3e644e2ad702cdb94ac9550c03b346',
    code_hash: '761f222c89dc1744c480d21e141277cc9af815ee0e2a1d7489c9282594728b5b',
    expires_at: T0 + 600, attempts: 0, created_at: T0
  }]);
  const windows = env.store.db.prepare('SELECT key FROM rate_windows ORDER BY key').all().map(r => r.key);
  assert.deepStrictEqual(windows, [
    'start-email#587522269e243312a5d6f20bcdc78dc9', 'start-email-day#587522269e243312a5d6f20bcdc78dc9',
    'start-ip#e01c4eeb03c058165d49564dcaf561cf'
  ]);
  const dump = JSON.stringify([codes, env.store.db.prepare('SELECT * FROM rate_windows').all()]);
  for (const secretish of ['user@example.com', '203.0.113.7', '123456', crypto.createHash('sha256').update('123456').digest('hex')]) {
    assert.ok(!dump.includes(secretish), secretish);
  }
});

/**
 * EMAILCODE-03: single use: the right code a second time is 400 invalid_code.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: EMAILCODE-03, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the sender is a fake: no network).
 */
// EMAILCODE-03
test('EMAILCODE-03 the right code a second time is 400 invalid_code', async () => {
  const env = setup();
  await env.svc.start('a@example.com', '1.1.1.1');
  const code = lastCode(env);
  assert.strictEqual((await env.svc.verify('a@example.com', code, '1.1.1.1')).status, 200);
  assert.deepStrictEqual(await env.svc.verify('a@example.com', code, '1.1.1.1'), INVALID);
});

/**
 * EMAILCODE-04: expiry: the code is accepted 599 seconds after start and is 400 invalid_code at 600 seconds.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: EMAILCODE-04, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the sender is a fake: no network).
 */
// EMAILCODE-04
test('EMAILCODE-04 the code is accepted at 599 seconds and refused at 600', async () => {
  const env = setup();
  await env.svc.start('a@example.com', '1.1.1.1');
  const a = lastCode(env);
  await env.svc.start('b@example.com', '1.1.1.1');
  const b = lastCode(env);
  env.clock.t = T0 + 599;
  assert.strictEqual((await env.svc.verify('a@example.com', a, '1.1.1.1')).status, 200);
  env.clock.t = T0 + 600;
  assert.deepStrictEqual(await env.svc.verify('b@example.com', b, '1.1.1.1'), INVALID);
  assert.strictEqual(env.store.getCode(env.svc.emailHash('b@example.com')), null);
});

/**
 * EMAILCODE-05: five tries per code: after 5 wrong codes the right one is 400 invalid_code; after 4 wrong codes
 * the right one, the 5th try, is accepted.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: EMAILCODE-05, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the sender is a fake: no network).
 */
// EMAILCODE-05
test('EMAILCODE-05 five tries per code', async () => {
  const env = setup();
  await env.svc.start('a@example.com', '1.1.1.1');
  const a = lastCode(env);
  for (let i = 0; i < 5; i++) assert.deepStrictEqual(await env.svc.verify('a@example.com', wrong(a), '1.1.1.1'), INVALID);
  assert.strictEqual(env.store.getCode(env.svc.emailHash('a@example.com')), null);
  assert.deepStrictEqual(await env.svc.verify('a@example.com', a, '1.1.1.1'), INVALID);
  await env.svc.start('b@example.com', '1.1.1.1');
  const b = lastCode(env);
  for (let i = 0; i < 4; i++) assert.deepStrictEqual(await env.svc.verify('b@example.com', wrong(b), '1.1.1.1'), INVALID);
  assert.strictEqual((await env.svc.verify('b@example.com', b, '1.1.1.1')).status, 200);
});

/**
 * EMAILCODE-06: a new start replaces the code: the earlier code is 400 invalid_code, the new one is accepted, and
 * the count of tries starts again at 0.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: EMAILCODE-06, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the sender is a fake: no network).
 */
// EMAILCODE-06
test('EMAILCODE-06 a new start replaces the code and resets the tries', async () => {
  const env = setup();
  env.codes.push('111111', '222222');
  await env.svc.start('a@example.com', '1.1.1.1');
  for (let i = 0; i < 4; i++) assert.deepStrictEqual(await env.svc.verify('a@example.com', '999999', '1.1.1.1'), INVALID);
  await env.svc.start('a@example.com', '1.1.1.1');
  assert.strictEqual(env.store.getCode(env.svc.emailHash('a@example.com')).attempts, 0);
  assert.deepStrictEqual(await env.svc.verify('a@example.com', '111111', '1.1.1.1'), INVALID);
  for (let i = 0; i < 3; i++) assert.deepStrictEqual(await env.svc.verify('a@example.com', '999999', '1.1.1.1'), INVALID);
  assert.strictEqual((await env.svc.verify('a@example.com', '222222', '1.1.1.1')).status, 200);
});

/**
 * EMAILCODE-07: no enumeration: start gives the same answer, and the sender the same kind of call, for an address
 * with an account and for one without, and never reads accounts; verify gives the same 400 body for a wrong code,
 * an expired code, a used code and an address that never asked for one.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: EMAILCODE-07, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the sender is a fake: no network).
 */
// EMAILCODE-07
test('EMAILCODE-07 no enumeration: same start answer and email for known and unknown addresses; one 400 body', async () => {
  const env = setup();
  addAccount(env, 'acct_known', 'known@example.com', 5);
  const reads = env.accountReads;
  const known = await env.svc.start('known@example.com', '1.1.1.1');
  const unknown = await env.svc.start('unknown@example.com', '1.1.1.1');
  assert.deepStrictEqual(known, unknown);
  assert.strictEqual(env.accountReads, reads);
  assert.deepStrictEqual(env.sender.calls.map(([to, code, ttl]) => [to, /^[0-9]{6}$/.test(code), ttl]),
    [['known@example.com', true, 600], ['unknown@example.com', true, 600]]);
  const bodies = [];
  const k = env.sender.calls[0][1];
  bodies.push(await env.svc.verify('known@example.com', wrong(k), '1.1.1.1'));
  assert.strictEqual((await env.svc.verify('known@example.com', k, '1.1.1.1')).status, 200);
  bodies.push(await env.svc.verify('known@example.com', k, '1.1.1.1'));
  env.clock.t = T0 + 600;
  bodies.push(await env.svc.verify('unknown@example.com', env.sender.calls[1][1], '1.1.1.1'));
  bodies.push(await env.svc.verify('never@example.com', '123456', '1.1.1.1'));
  for (const b of bodies) assert.deepStrictEqual(b, INVALID);
});

/**
 * EMAILCODE-08: sends per address: the 6th start for one address in a clock hour is 429 too_many_requests and
 * sends nothing; in the next hour it works; the 11th in a clock day is 429 (a refused start still counts toward
 * the day).
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: EMAILCODE-08, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the sender is a fake: no network).
 */
// EMAILCODE-08
test('EMAILCODE-08 five starts per address per clock hour and ten per clock day', async () => {
  const env = setup();
  for (let i = 0; i < 5; i++) assert.deepStrictEqual(await env.svc.start('a@example.com', '10.0.0.' + i), ACCEPTED);
  assert.deepStrictEqual(await env.svc.start('a@example.com', '10.0.0.9'), LIMITED);
  assert.strictEqual(env.sender.calls.length, 5);
  env.clock.t = T0 + 3600;
  for (let i = 0; i < 4; i++) assert.deepStrictEqual(await env.svc.start('a@example.com', '10.0.1.' + i), ACCEPTED);
  assert.deepStrictEqual(await env.svc.start('a@example.com', '10.0.1.9'), LIMITED);
  assert.strictEqual(env.sender.calls.length, 9);
  env.clock.t = T0 + 7200;
  assert.deepStrictEqual(await env.svc.start('a@example.com', '10.0.2.1'), LIMITED);
  env.clock.t = 1700006400;
  assert.deepStrictEqual(await env.svc.start('a@example.com', '10.0.3.1'), ACCEPTED);
});

/**
 * EMAILCODE-09: sends per IP: the 21st start from one IP in a clock hour, each for another address, is 429
 * too_many_requests; another IP is not affected.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: EMAILCODE-09, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the sender is a fake: no network).
 */
// EMAILCODE-09
test('EMAILCODE-09 twenty starts per IP per clock hour; another IP is not affected', async () => {
  const env = setup();
  for (let i = 0; i < 20; i++) assert.deepStrictEqual(await env.svc.start(`u${i}@example.com`, '198.51.100.1'), ACCEPTED);
  assert.deepStrictEqual(await env.svc.start('u20@example.com', '198.51.100.1'), LIMITED);
  assert.strictEqual(env.sender.calls.length, 20);
  assert.deepStrictEqual(await env.svc.start('u20@example.com', '198.51.100.2'), ACCEPTED);
  env.clock.t = T0 + 3600;
  assert.deepStrictEqual(await env.svc.start('u21@example.com', '198.51.100.1'), ACCEPTED);
});

/**
 * EMAILCODE-10: tries per IP and per address: the 31st verify from one IP in a clock hour is 429
 * too_many_requests, with the right code too; the 11th verify for one address in a clock hour is 429 whatever IP
 * it comes from and however many new codes were sent.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: EMAILCODE-10, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the sender is a fake: no network).
 */
// EMAILCODE-10
test('EMAILCODE-10 thirty verifies per IP and ten per address per clock hour', async () => {
  const env = setup();
  await env.svc.start('target@example.com', '192.0.2.200');
  const code = lastCode(env);
  for (let i = 0; i < 30; i++) assert.deepStrictEqual(await env.svc.verify(`v${i}@example.com`, '123456', '192.0.2.1'), INVALID);
  assert.deepStrictEqual(await env.svc.verify('target@example.com', code, '192.0.2.1'), LIMITED);
  assert.strictEqual((await env.svc.verify('target@example.com', code, '192.0.2.2')).status, 200);

  const env2 = setup();
  for (let round = 0; round < 2; round++) {
    await env2.svc.start('b@example.com', '192.0.2.100');
    const c = lastCode(env2);
    for (let i = 0; i < 5; i++) assert.deepStrictEqual(await env2.svc.verify('b@example.com', wrong(c), `192.0.2.${round * 10 + i}`), INVALID);
  }
  await env2.svc.start('b@example.com', '192.0.2.100');
  assert.deepStrictEqual(await env2.svc.verify('b@example.com', lastCode(env2), '203.0.113.99'), LIMITED);
  env2.clock.t = T0 + 3600;
  await env2.svc.start('b@example.com', '192.0.2.100');
  assert.strictEqual((await env2.svc.verify('b@example.com', lastCode(env2), '203.0.113.99')).status, 200);
});

/**
 * EMAILCODE-11: input: " A@X.com " signs in a@x.com; a malformed address is 422 invalid_email at start and 400
 * invalid_code at verify; only space, tab, CR and LF are trimmed and only A-Z is lower-cased, so an address
 * followed by U+00A0, U+000B or U+0000, or one that starts with U+212A, is refused; "123 456" and "123-456" are
 * accepted as the code (each with its own fresh code); 5 digits, 7 digits, letters and six non-ASCII digits are
 * 400 invalid_code and spend no try of the code.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: EMAILCODE-11, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the sender is a fake: no network).
 */
// EMAILCODE-11
test('EMAILCODE-11 input normalisation for addresses and codes; malformed codes spend no try', async () => {
  assert.strictEqual(normalizeEmail(' A@X.com '), 'a@x.com');
  for (const bad of ['a@b', 'a b@x.com', 'a@x..com', '.a@x.com', 'a@x.com,b@y.com', '<a@x.com>',
    'a@x.com ', 'a@x.com\u000b', 'a@x.com\u0000', 'K@x.com', 42, null, undefined, '']) {
    assert.strictEqual(normalizeEmail(bad), null, String(bad));
  }
  const env = setup();
  env.codes.push('123456');
  assert.deepStrictEqual(await env.svc.start(' A@X.com ', '1.1.1.1'), ACCEPTED);
  assert.strictEqual(env.sender.calls[0][0], 'a@x.com');
  const r = await env.svc.verify(' A@X.com ', '123456', '1.1.1.1');
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.email, 'a@x.com');
  for (const bad of ['a@b', 'a@x.com ', 'a@x.com\u000b', 'a@x.com\u0000', 'K@x.com']) {
    assert.deepStrictEqual(await env.svc.start(bad, '1.1.1.1'), { error: 'invalid_email', status: 422 });
    assert.deepStrictEqual(await env.svc.verify(bad, '123456', '1.1.1.1'), INVALID);
  }
  for (const spelling of ['123 456', '123-456']) {
    const e = setup();
    e.codes.push('123456');
    await e.svc.start('c@example.com', '1.1.1.1');
    assert.strictEqual((await e.svc.verify('c@example.com', spelling, '1.1.1.1')).status, 200, spelling);
  }
  const e2 = setup();
  e2.codes.push('123456');
  await e2.svc.start('d@example.com', '1.1.1.1');
  for (const bad of ['12345', '1234567', 'abcdef', '١٢٣٤٥٦', '', undefined]) {
    assert.deepStrictEqual(await e2.svc.verify('d@example.com', bad, '1.1.1.1'), INVALID);
  }
  assert.strictEqual(e2.store.getCode(e2.svc.emailHash('d@example.com')).attempts, 0);
  assert.strictEqual((await e2.svc.verify('d@example.com', '123456', '1.1.1.1')).status, 200);
});

/**
 * EMAILCODE-12: a sender that returns false or raises makes start answer 503 send_failed and leaves no code for
 * the address; a secret under 32 bytes, or no sender, fails construction with not_configured.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: EMAILCODE-12, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the sender is a fake: no network).
 */
// EMAILCODE-12
test('EMAILCODE-12 a failed send is 503 and leaves no code; a short secret or no sender fails construction', async () => {
  for (const answer of [false, () => { throw new Error('smtp down'); }, undefined]) {
    const env = setup();
    env.sender.answer = answer;
    assert.deepStrictEqual(await env.svc.start('a@example.com', '1.1.1.1'), { error: 'send_failed', status: 503 });
    assert.strictEqual(env.store.getCode(env.svc.emailHash('a@example.com')), null);
  }
  const notConfigured = err => err instanceof EmailCodeError && err.code === 'not_configured';
  assert.throws(() => createEmailCodeSignin({ secret: SECRET.slice(0, 31), sender: fakeSender() }), notConfigured);
  assert.throws(() => createEmailCodeSignin({ secret: SECRET }), notConfigured);
  assert.throws(() => createEmailCodeSignin({ sender: fakeSender() }), notConfigured);
  assert.ok(createEmailCodeSignin({ secret: SECRET, sender: fakeSender() }));
});

/**
 * EMAILCODE-13: a suspended or closed account: the right code is 403 account_unavailable, and the code is used up.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: EMAILCODE-13, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the sender is a fake: no network).
 */
// EMAILCODE-13
test('EMAILCODE-13 suspended or closed accounts: the right code is 403 and is used up', async () => {
  for (const status of ['suspended', 'closed']) {
    const env = setup();
    addAccount(env, 'acct_' + status, status + '@example.com', 5, status);
    await env.svc.start(status + '@example.com', '1.1.1.1');
    const code = lastCode(env);
    assert.deepStrictEqual(await env.svc.verify(status + '@example.com', code, '1.1.1.1'), { error: 'account_unavailable', status: 403 });
    assert.strictEqual(env.store.getCode(env.svc.emailHash(status + '@example.com')), null);
    assert.deepStrictEqual(await env.svc.verify(status + '@example.com', code, '1.1.1.1'), INVALID);
  }
});

/**
 * EMAILCODE-14: a code sent to one address is 400 invalid_code for another address; an injected code "000042"
 * keeps its leading zeros and signs in; the default generator gives 6 digits 0-9 and, with the spec's injected
 * random bytes, the spec's codes.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: EMAILCODE-14, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the sender is a fake: no network).
 */
// EMAILCODE-14
test('EMAILCODE-14 codes are bound to their address; leading zeros kept; the default generator and its vector', async () => {
  const env = setup();
  env.codes.push('000042', '654321');
  await env.svc.start('one@example.com', '1.1.1.1');
  await env.svc.start('two@example.com', '1.1.1.1');
  assert.deepStrictEqual(await env.svc.verify('two@example.com', '000042', '1.1.1.1'), INVALID);
  assert.deepStrictEqual(await env.svc.verify('three@example.com', '000042', '1.1.1.1'), INVALID);
  assert.strictEqual((await env.svc.verify('one@example.com', '000042', '1.1.1.1')).status, 200);
  assert.strictEqual(env.sender.calls[0][1], '000042');
  const queue = [0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0xff, 0xf1, 0x3d, 0x7f, 0xff, 0xf1, 0x3d, 0x80, 0x00, 0x00, 0x00, 0x2a];
  const rnd = n => Buffer.from(queue.splice(0, n));
  assert.deepStrictEqual([generateCode(rnd), generateCode(rnd), generateCode(rnd)], ['483648', '999999', '000042']);
  assert.strictEqual(queue.length, 0);
  for (let i = 0; i < 50; i++) assert.match(generateCode(), /^[0-9]{6}$/);
});

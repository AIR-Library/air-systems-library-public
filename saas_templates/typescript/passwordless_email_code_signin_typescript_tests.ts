/**
 * Tests for passwordless_email_code_signin_typescript.ts: one test (or more) per EMAILCODE-01..14 row of
 * docs/specs/passwordless_email_code_signin.md, with the spec's fixed vectors. Offline: the sender and
 * revoke_unproven are recording fakes, the clock, the random bytes and the code generator are injected, the store is
 * in memory. Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'crypto';
import {
  EmailCodeSignin, InMemorySigninStore, normalizeEmail, SigninError,
} from './passwordless_email_code_signin_typescript.ts';

const SECRET = '0123456789abcdef0123456789abcdef';
const IP = '203.0.113.7';
const T0 = 1699920000;
const INVALID = { error: 'invalid_code', status: 400 };
const LIMITED = { error: 'too_many_requests', status: 429 };
const SENT = { status: 202, sent: true, expires_in: 600 };

/**
 * A service with a recording sender. In: overrides; `codes` is a queue the generator serves (then the real CODE).
 * Out: {svc, store, clock, sent, revoked, send}. send.mode: "ok" | "false" | "throw". 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
function setup(opts: { codes?: string[]; random?: (n: number) => Buffer; revokeThrows?: boolean } = {}) {
  const clock = { now: T0 };
  const sent: { to: string; code: string; ttl: number }[] = [];
  const revoked: string[] = [];
  const send = { mode: 'ok' };
  const store = new InMemorySigninStore();
  const codes = [...(opts.codes ?? [])];
  let svc: EmailCodeSignin;
  svc = new EmailCodeSignin({
    secret: SECRET,
    sender: {
      sendCode: async (to: string, code: string, ttl: number) => {
        if (send.mode === 'throw') throw new Error('smtp down');
        if (send.mode === 'false') return false;
        sent.push({ to, code, ttl });
        return true;
      },
    },
    revokeUnproven: (id: string) => {
      revoked.push(id);
      if (opts.revokeThrows) throw new Error('revoke failed');
    },
    store,
    clock: () => clock.now,
    randomBytes: opts.random,
    generateCode: codes.length || opts.codes ? () => (codes.length ? codes.shift()! : svc.generateCode()) : undefined,
  });
  return { svc, store, clock, sent, revoked, send };
}

/** The last code the sender got. Touches nothing. */
function lastCode(s: ReturnType<typeof setup>): string {
  return s.sent[s.sent.length - 1].code;
}

/** A code that differs from `code`. Touches nothing. */
function other(code: string): string {
  return code === '000000' ? '111111' : '000000';
}

/** A random_bytes fake serving the given bytes in order, whatever n is asked. Touches nothing. */
function queue(bytes: number[]): (n: number) => Buffer {
  const q = [...bytes];
  return (n: number) => Buffer.from(Array.from({ length: n }, () => {
    if (!q.length) throw new Error('random queue drained');
    return q.shift()!;
  }));
}

/**
 * EMAILCODE-01: start 202 and one 6-digit code; verify signs up then signs in; unproven rows are revoked.
 * In: the spec's vectors and fakes. Out: assertions only. Why: EMAILCODE-01 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// EMAILCODE-01
test('EMAILCODE-01 start 202 and one 6-digit code; verify signs up then signs in; unproven rows are revoked', async () => {
  const s = setup();
  assert.deepEqual(await s.svc.start('user@example.com', IP), SENT);
  assert.equal(s.sent.length, 1);
  assert.match(lastCode(s), /^[0-9]{6}$/);
  assert.equal(s.sent[0].to, 'user@example.com');
  assert.equal(s.sent[0].ttl, 600);
  const first = await s.svc.verify('user@example.com', lastCode(s), IP) as { account_id: string; new_account: boolean };
  assert.deepEqual(first, { status: 200, account_id: first.account_id, email: 'user@example.com', new_account: true });
  assert.match(first.account_id, /^[0-9a-f]{32}$/);
  assert.equal(s.store.accounts.get(first.account_id)!.email_verified_at, T0);
  s.clock.now += 60;
  await s.svc.start('user@example.com', IP);
  assert.deepEqual(await s.svc.verify('user@example.com', lastCode(s), IP),
    { status: 200, account_id: first.account_id, email: 'user@example.com', new_account: false });
  assert.deepEqual(s.revoked, []);

  s.store.accounts.set('acct_invited', { id: 'acct_invited', email: 'invited@example.com', email_verified_at: null, status: 'active', created_at: 1 });
  await s.svc.start('invited@example.com', IP);
  assert.deepEqual(await s.svc.verify('invited@example.com', lastCode(s), IP),
    { status: 200, account_id: 'acct_invited', email: 'invited@example.com', new_account: false });
  assert.deepEqual(s.revoked, ['acct_invited']);
  assert.equal(s.store.accounts.get('acct_invited')!.email_verified_at, s.clock.now);

  const r = setup({ revokeThrows: true });
  r.store.accounts.set('acct_x', { id: 'acct_x', email: 'x@example.com', email_verified_at: null, status: 'active', created_at: 1 });
  await r.svc.start('x@example.com', IP);
  assert.deepEqual(await r.svc.verify('x@example.com', lastCode(r), IP), { error: 'processing_failed', status: 500 });
  assert.equal(r.store.accounts.get('acct_x')!.email_verified_at, null);
});

/**
 * EMAILCODE-02: storage: the spec hashes and window keys; no address, IP, code or plain SHA-256 stored.
 * In: the spec's vectors and fakes. Out: assertions only. Why: EMAILCODE-02 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// EMAILCODE-02
test('EMAILCODE-02 storage: the spec hashes and window keys; no address, IP, code or plain SHA-256 stored', async () => {
  const s = setup({ codes: ['123456'] });
  assert.equal(s.svc.emailHash('user@example.com'), '587522269e243312a5d6f20bcdc78dc97a3e644e2ad702cdb94ac9550c03b346');
  assert.equal(s.svc.codeHash('user@example.com', '123456'), '761f222c89dc1744c480d21e141277cc9af815ee0e2a1d7489c9282594728b5b');
  assert.equal(s.svc.ipHash(IP), 'e01c4eeb03c058165d49564dcaf561cf');
  await s.svc.start('user@example.com', IP);
  const row = s.store.codes.get('587522269e243312a5d6f20bcdc78dc97a3e644e2ad702cdb94ac9550c03b346')!;
  assert.deepEqual(row, {
    email_hash: '587522269e243312a5d6f20bcdc78dc97a3e644e2ad702cdb94ac9550c03b346',
    code_hash: '761f222c89dc1744c480d21e141277cc9af815ee0e2a1d7489c9282594728b5b',
    expires_at: T0 + 600, attempts: 0, created_at: T0,
  });
  assert.deepEqual([...s.store.windows.values()].map((w) => w.key), [
    'start-ip#e01c4eeb03c058165d49564dcaf561cf',
    'start-email#587522269e243312a5d6f20bcdc78dc9',
    'start-email-day#587522269e243312a5d6f20bcdc78dc9',
  ]);
  const dump = JSON.stringify([...s.store.codes.values()]) + JSON.stringify([...s.store.windows.values()]);
  for (const secretText of ['user@example.com', IP, '123456', createHash('sha256').update('123456').digest('hex')]) {
    assert.ok(!dump.includes(secretText), secretText);
  }
});

/**
 * EMAILCODE-03: single use: the right code a second time is 400 invalid_code.
 * In: the spec's vectors and fakes. Out: assertions only. Why: EMAILCODE-03 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// EMAILCODE-03
test('EMAILCODE-03 single use: the right code a second time is 400 invalid_code', async () => {
  const s = setup();
  await s.svc.start('a@example.com', IP);
  assert.equal((await s.svc.verify('a@example.com', lastCode(s), IP)).status, 200);
  assert.deepEqual(await s.svc.verify('a@example.com', lastCode(s), IP), INVALID);
});

/**
 * EMAILCODE-04: expiry: accepted at 599 seconds, 400 at 600 seconds.
 * In: the spec's vectors and fakes. Out: assertions only. Why: EMAILCODE-04 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// EMAILCODE-04
test('EMAILCODE-04 expiry: accepted at 599 seconds, 400 at 600 seconds', async () => {
  const s = setup();
  await s.svc.start('a@example.com', IP);
  s.clock.now = T0 + 599;
  assert.equal((await s.svc.verify('a@example.com', lastCode(s), IP)).status, 200);
  const t = setup();
  await t.svc.start('a@example.com', IP);
  t.clock.now = T0 + 600;
  assert.deepEqual(await t.svc.verify('a@example.com', lastCode(t), IP), INVALID);
  assert.equal(t.store.codes.size, 0);
});

/**
 * EMAILCODE-05: five tries per code: 5 wrong kill it; the 5th try may still be the right one.
 * In: the spec's vectors and fakes. Out: assertions only. Why: EMAILCODE-05 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// EMAILCODE-05
test('EMAILCODE-05 five tries per code: 5 wrong kill it; the 5th try may still be the right one', async () => {
  const s = setup();
  await s.svc.start('a@example.com', IP);
  for (let i = 0; i < 5; i++) assert.deepEqual(await s.svc.verify('a@example.com', other(lastCode(s)), IP), INVALID);
  assert.equal(s.store.codes.size, 0);
  assert.deepEqual(await s.svc.verify('a@example.com', lastCode(s), IP), INVALID);
  const t = setup();
  await t.svc.start('a@example.com', IP);
  for (let i = 0; i < 4; i++) assert.deepEqual(await t.svc.verify('a@example.com', other(lastCode(t)), IP), INVALID);
  assert.equal((await t.svc.verify('a@example.com', lastCode(t), IP)).status, 200);
});

/**
 * EMAILCODE-06: a new start replaces the code and resets the tries.
 * In: the spec's vectors and fakes. Out: assertions only. Why: EMAILCODE-06 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// EMAILCODE-06
test('EMAILCODE-06 a new start replaces the code and resets the tries', async () => {
  const s = setup({ codes: ['111111', '222222'] });
  await s.svc.start('a@example.com', IP);
  for (let i = 0; i < 4; i++) await s.svc.verify('a@example.com', '999999', IP);
  await s.svc.start('a@example.com', IP);
  const row = [...s.store.codes.values()][0];
  assert.equal(row.attempts, 0);
  assert.deepEqual(await s.svc.verify('a@example.com', '111111', IP), INVALID);
  for (let i = 0; i < 3; i++) await s.svc.verify('a@example.com', '999999', IP);
  assert.equal((await s.svc.verify('a@example.com', '222222', IP)).status, 200);
});

/**
 * EMAILCODE-07: no enumeration: same start answer and sender call, no account read; one 400 body.
 * In: the spec's vectors and fakes. Out: assertions only. Why: EMAILCODE-07 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// EMAILCODE-07
test('EMAILCODE-07 no enumeration: same start answer and sender call, no account read; one 400 body', async () => {
  const s = setup();
  s.store.accounts.set('acct_1', { id: 'acct_1', email: 'known@example.com', email_verified_at: 1, status: 'active', created_at: 1 });
  const known = await s.svc.start('known@example.com', IP);
  const unknown = await s.svc.start('unknown@example.com', IP);
  assert.deepEqual(known, unknown);
  assert.deepEqual(known, SENT);
  assert.equal(s.store.accountReads, 0);
  assert.deepEqual(s.sent.map((m) => [m.to, m.code.length, m.ttl]), [['known@example.com', 6, 600], ['unknown@example.com', 6, 600]]);
  const bodies = [
    await s.svc.verify('known@example.com', other(s.sent[0].code), IP),
    await s.svc.verify('never@example.com', '123456', IP),
  ];
  assert.equal((await s.svc.verify('unknown@example.com', s.sent[1].code, IP)).status, 200);
  bodies.push(await s.svc.verify('unknown@example.com', s.sent[1].code, IP));
  await s.svc.start('late@example.com', IP);
  s.clock.now += 600;
  bodies.push(await s.svc.verify('late@example.com', lastCode(s), IP));
  for (const b of bodies) assert.deepEqual(b, INVALID);
});

/**
 * EMAILCODE-08: sends per address: 6th in an hour 429 and unsent; next hour works; 11th in a day 429.
 * In: the spec's vectors and fakes. Out: assertions only. Why: EMAILCODE-08 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// EMAILCODE-08
test('EMAILCODE-08 sends per address: 6th in an hour 429 and unsent; next hour works; 11th in a day 429', async () => {
  const s = setup();
  for (let i = 0; i < 5; i++) assert.deepEqual(await s.svc.start('a@example.com', IP), SENT);
  assert.deepEqual(await s.svc.start('a@example.com', IP), LIMITED);
  assert.equal(s.sent.length, 5);
  s.clock.now = T0 + 3600;
  for (let i = 0; i < 4; i++) assert.deepEqual(await s.svc.start('a@example.com', IP), SENT);
  assert.deepEqual(await s.svc.start('a@example.com', IP), LIMITED);
  assert.equal(s.sent.length, 9);
  s.clock.now = T0 + 86400;
  assert.deepEqual(await s.svc.start('a@example.com', IP), SENT);
});

/**
 * EMAILCODE-09: sends per IP: the 21st start from one IP in an hour is 429; another IP is not affected.
 * In: the spec's vectors and fakes. Out: assertions only. Why: EMAILCODE-09 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// EMAILCODE-09
test('EMAILCODE-09 sends per IP: the 21st start from one IP in an hour is 429; another IP is not affected', async () => {
  const s = setup();
  for (let i = 0; i < 20; i++) assert.deepEqual(await s.svc.start(`u${i}@example.com`, IP), SENT);
  assert.deepEqual(await s.svc.start('u20@example.com', IP), LIMITED);
  assert.deepEqual(await s.svc.start('u20@example.com', '198.51.100.9'), SENT);
  assert.equal(s.sent.length, 21);
});

/**
 * EMAILCODE-10: tries per IP (31st 429) and per address (11th 429 from any IP, new codes or not).
 * In: the spec's vectors and fakes. Out: assertions only. Why: EMAILCODE-10 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// EMAILCODE-10
test('EMAILCODE-10 tries per IP (31st 429) and per address (11th 429 from any IP, new codes or not)', async () => {
  const s = setup();
  await s.svc.start('a@example.com', '198.51.100.1');
  const code = lastCode(s);
  for (let i = 0; i < 30; i++) assert.deepEqual(await s.svc.verify(`v${i}@example.com`, '123456', IP), INVALID);
  assert.deepEqual(await s.svc.verify('a@example.com', code, IP), LIMITED);
  assert.equal(s.store.codes.size, 1);

  const t = setup();
  let n = 0;
  for (const tries of [4, 4, 2]) {
    await t.svc.start('b@example.com', '198.51.100.2');
    for (let i = 0; i < tries; i++) {
      assert.deepEqual(await t.svc.verify('b@example.com', other(lastCode(t)), `192.0.2.${n++}`), INVALID);
    }
  }
  assert.deepEqual(await t.svc.verify('b@example.com', lastCode(t), '192.0.2.200'), LIMITED);
  t.clock.now = T0 + 3600;
  await t.svc.start('b@example.com', '198.51.100.2');
  assert.equal((await t.svc.verify('b@example.com', lastCode(t), '192.0.2.201')).status, 200);
});

/**
 * EMAILCODE-11: input: trimming and lower-casing rules, bad addresses, spellings of the code, bad codes.
 * In: the spec's vectors and fakes. Out: assertions only. Why: EMAILCODE-11 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// EMAILCODE-11
test('EMAILCODE-11 input: trimming and lower-casing rules, bad addresses, spellings of the code, bad codes', async () => {
  assert.equal(normalizeEmail(' A@X.com '), 'a@x.com');
  for (const bad of ['a@b', 'a b@x.com', 'a@x..com', '.a@x.com', 'a@x.com,b@y.com', '<a@x.com>',
    'a@x.com ', 'a@x.com\u000b', 'a@x.com\u0000', 'K@x.com', '', 'a@', 42, null, undefined]) {
    assert.equal(normalizeEmail(bad), null, JSON.stringify(bad));
  }
  const s = setup();
  assert.deepEqual(await s.svc.start(' A@X.com ', IP), SENT);
  assert.equal(s.sent[0].to, 'a@x.com');
  const r = await s.svc.verify(' A@X.com ', lastCode(s), IP) as { email: string };
  assert.equal(r.email, 'a@x.com');
  for (const bad of ['a@b', 'a@x.com ', 'K@x.com']) {
    assert.deepEqual(await s.svc.start(bad, IP), { error: 'invalid_email', status: 422 });
    assert.deepEqual(await s.svc.verify(bad, '123456', IP), INVALID);
  }
  for (const spell of [(c: string) => c.slice(0, 3) + ' ' + c.slice(3), (c: string) => c.slice(0, 3) + '-' + c.slice(3)]) {
    const t = setup();
    await t.svc.start('c@example.com', IP);
    assert.equal((await t.svc.verify('c@example.com', spell(lastCode(t)), IP)).status, 200);
  }
  const u = setup();
  await u.svc.start('d@example.com', IP);
  for (const bad of ['12345', '1234567', 'abcdef', '١٢٣٤٥٦', '', undefined, 123456]) {
    assert.deepEqual(await u.svc.verify('d@example.com', bad, IP), INVALID);
  }
  assert.equal([...u.store.codes.values()][0].attempts, 0);
  assert.equal((await u.svc.verify('d@example.com', lastCode(u), IP)).status, 200);
});

/**
 * EMAILCODE-12: a failing sender is 503 send_failed with no code left; bad configuration fails construction.
 * In: the spec's vectors and fakes. Out: assertions only. Why: EMAILCODE-12 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// EMAILCODE-12
test('EMAILCODE-12 a failing sender is 503 send_failed with no code left; bad configuration fails construction', async () => {
  for (const mode of ['false', 'throw']) {
    const s = setup();
    s.send.mode = mode;
    assert.deepEqual(await s.svc.start('a@example.com', IP), { error: 'send_failed', status: 503 });
    assert.equal(s.store.codes.size, 0);
  }
  const notConfigured = (e: unknown) => e instanceof SigninError && e.code === 'not_configured';
  const sender = { sendCode: () => true };
  assert.throws(() => new EmailCodeSignin({ secret: SECRET.slice(0, 31), sender }), notConfigured);
  assert.throws(() => new EmailCodeSignin({ secret: Buffer.alloc(31), sender }), notConfigured);
  assert.throws(() => new EmailCodeSignin({ secret: SECRET, sender: undefined as any }), notConfigured);
  assert.ok(new EmailCodeSignin({ secret: Buffer.alloc(32), sender }));
});

/**
 * EMAILCODE-13: a suspended or closed account: the right code is 403 account_unavailable and used up.
 * In: the spec's vectors and fakes. Out: assertions only. Why: EMAILCODE-13 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// EMAILCODE-13
test('EMAILCODE-13 a suspended or closed account: the right code is 403 account_unavailable and used up', async () => {
  for (const status of ['suspended', 'closed'] as const) {
    const s = setup();
    s.store.accounts.set('acct', { id: 'acct', email: 'a@example.com', email_verified_at: 1, status, created_at: 1 });
    await s.svc.start('a@example.com', IP);
    assert.deepEqual(await s.svc.verify('a@example.com', lastCode(s), IP), { error: 'account_unavailable', status: 403 });
    assert.equal(s.store.codes.size, 0);
    assert.deepEqual(await s.svc.verify('a@example.com', lastCode(s), IP), INVALID);
  }
});

/**
 * EMAILCODE-14: a code is bound to its address; 000042 keeps its zeros; the CODE generator vectors.
 * In: the spec's vectors and fakes. Out: assertions only. Why: EMAILCODE-14 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// EMAILCODE-14
test('EMAILCODE-14 a code is bound to its address; 000042 keeps its zeros; the CODE generator vectors', async () => {
  const s = setup({ codes: ['000042', '777777'] });
  await s.svc.start('a@example.com', IP);
  await s.svc.start('b@example.com', IP);
  assert.deepEqual(await s.svc.verify('b@example.com', '000042', IP), INVALID);
  assert.equal(s.sent[0].code, '000042');
  assert.equal((await s.svc.verify('a@example.com', '000042', IP)).status, 200);
  const g = setup({ random: queue([0xff, 0xff, 0xff, 0xff, 0x80, 0, 0, 0, 0xff, 0xf1, 0x3d, 0x7f, 0xff, 0xf1, 0x3d, 0x80, 0, 0, 0, 0x2a]) });
  assert.deepEqual([g.svc.generateCode(), g.svc.generateCode(), g.svc.generateCode()], ['483648', '999999', '000042']);
  const d = setup();
  for (let i = 0; i < 50; i++) assert.match(d.svc.generateCode(), /^[0-9]{6}$/);
});

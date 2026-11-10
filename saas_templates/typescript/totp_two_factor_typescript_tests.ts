/**
 * Tests for totp_two_factor_typescript.ts: one test (or more) per TOTP-01..14 row of docs/specs/totp_two_factor.md,
 * with the spec's fixed vectors. Offline: the clock and the random bytes are injected; the store is in memory.
 * Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'crypto';
import {
  base32Decode, base32Encode, generateSecret, hotp, InMemoryTotpStore, open, otpauthUri, recoveryInput, seal,
  totpAt, TotpError, TotpTwoFactor,
} from './totp_two_factor_typescript.ts';

const K = Buffer.from('12345678901234567890', 'ascii');
const K_B32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const ENC_KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const REC_KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => 0x40 + i));
const NONCE = Buffer.from(Array.from({ length: 12 }, (_, i) => 0xa0 + i));
const SEALED_K = 'v1.oKGio6SlpqeoqaqroV0maQKFQOklPLSHVjWKjzfpA1TV+QA621cV0i7kP1B5d8k2owRGDhH/FzF0f662';

/**
 * A random_bytes fake that serves the given bytes in order, whatever n is asked, and then fresh CSPRNG bytes.
 * In: the bytes. Out: the function. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the CSPRNG once drained.
 */
function queue(bytes: number[]): (n: number) => Buffer {
  const q = [...bytes];
  return (n: number) => {
    const out: number[] = [];
    for (let i = 0; i < n; i++) out.push(q.length ? q.shift()! : randomBytes(1)[0]);
    return Buffer.from(out);
  };
}

/**
 * A service on a settable clock. In: the start time, random source and encryption key. Out: {svc, clock, store}.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
function setup(now = 1111111000, rnd?: (n: number) => Buffer, store = new InMemoryTotpStore(), encKey = ENC_KEY) {
  const clock = { now };
  const svc = new TotpTwoFactor({
    encryptionKey: encKey, recoveryHashKey: REC_KEY, issuer: 'Example App', store,
    clock: () => clock.now, randomBytes: rnd,
  });
  return { svc, clock, store };
}

/**
 * Enrolls and confirms a user at the current clock. In: the setup, user id. Out: {secret, codes}.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
function enroll(s: ReturnType<typeof setup>, user: string): { secret: string; codes: string[] } {
  const started = s.svc.enrollStart(user, user + '@example.com') as { secret: string };
  const confirmed = s.svc.enrollConfirm(user, totpAt(started.secret, s.clock.now)) as { recovery_codes: string[] };
  assert.equal(confirmed.recovery_codes.length, 8);
  return { secret: started.secret, codes: confirmed.recovery_codes };
}

/** A 6-digit code that matches none of the steps s-1..s+1 at `now`. Touches nothing. */
function wrongCode(secret: string, now: number): string {
  const near = [-30, 0, 30].map((d) => totpAt(secret, now + d));
  for (let i = 0; ; i++) {
    const c = String(i).padStart(6, '0');
    if (!near.includes(c)) return c;
  }
}

/** The number of failure rows the store holds for a user. Touches nothing. */
function failureRows(store: InMemoryTotpStore, user: string): number {
  return store.failures.filter((f) => f.user_id === user).length;
}

/**
 * TOTP-01: hotp RFC 4226 vectors, totp_at RFC 6238 vectors in 8 and 6 digits, 64-bit counter.
 * In: the spec's vectors and fakes. Out: assertions only. Why: TOTP-01 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// TOTP-01
test('TOTP-01 hotp RFC 4226 vectors, totp_at RFC 6238 vectors in 8 and 6 digits, 64-bit counter', () => {
  const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
  expected.forEach((code, c) => assert.equal(hotp(K, c), code));
  assert.equal(hotp(K, 4294967296), '999456');
  assert.notEqual(hotp(K, 4294967296), '755224');
  const table: [number, string, string][] = [
    [59, '94287082', '287082'], [1111111109, '07081804', '081804'], [1111111111, '14050471', '050471'],
    [1234567890, '89005924', '005924'], [2000000000, '69279037', '279037'], [20000000000, '65353130', '353130'],
  ];
  for (const [t, eight, six] of table) {
    assert.equal(totpAt(K_B32, t, 8), eight);
    assert.equal(totpAt(K_B32, t, 6), six);
    assert.equal(totpAt(K_B32, t), six);
  }
});

/**
 * TOTP-02: base32 vectors, lenient decode, invalid_base32, generate_secret.
 * In: the spec's vectors and fakes. Out: assertions only. Why: TOTP-02 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// TOTP-02
test('TOTP-02 base32 vectors, lenient decode, invalid_base32, generate_secret', () => {
  const vectors: [string, string][] = [['', ''], ['f', 'MY'], ['fo', 'MZXQ'], ['foo', 'MZXW6'], ['foob', 'MZXW6YQ'],
    ['fooba', 'MZXW6YTB'], ['foobar', 'MZXW6YTBOI']];
  for (const [plain, enc] of vectors) {
    assert.equal(base32Encode(Buffer.from(plain)), enc);
    if (enc) assert.equal(base32Decode(enc).toString(), plain);
  }
  assert.equal(base32Encode(K), K_B32);
  assert.equal(base32Decode('mzxw 6ytb-oi==').toString(), 'foobar');
  assert.equal(base32Decode('MZ').toString(), 'f');
  for (const bad of ['MZXW6YT1', '', 'M', 'MZX', 'MZXW6Y', '====', 'MZXW6YTé']) {
    assert.throws(() => base32Decode(bad), (e: unknown) => e instanceof TotpError && e.code === 'invalid_base32', bad);
  }
  const secret = generateSecret();
  assert.match(secret, /^[A-Z2-7]{32}$/);
  assert.equal(base32Decode(secret).length, 20);
});

/**
 * TOTP-03: enroll_start returns the secret and URI; the store holds only the sealed secret; a restart replaces it.
 * In: the spec's vectors and fakes. Out: assertions only. Why: TOTP-03 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// TOTP-03
test('TOTP-03 enroll_start returns the secret and URI; the store holds only the sealed secret; a restart replaces it', () => {
  assert.equal(otpauthUri(K_B32, 'Example App', 'alice@example.com'),
    'otpauth://totp/Example%20App%3Aalice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example%20App&algorithm=SHA1&digits=6&period=30');
  const s = setup(1111111000, queue([...K, ...NONCE]));
  const started = s.svc.enrollStart('user_1', 'alice@example.com');
  assert.deepEqual(started, {
    secret: K_B32,
    otpauth_uri: 'otpauth://totp/Example%20App%3Aalice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example%20App&algorithm=SHA1&digits=6&period=30',
  });
  const row = s.store.enrollments.get('user_1')!;
  assert.equal(row.secret_enc, SEALED_K);
  assert.equal(row.confirmed_at, null);
  assert.ok(!JSON.stringify([...s.store.enrollments.values()]).includes(K_B32));
  const again = s.svc.enrollStart('user_1', 'alice@example.com') as { secret: string };
  assert.notEqual(again.secret, K_B32);
  assert.notEqual(s.store.enrollments.get('user_1')!.secret_enc, SEALED_K);
  assert.equal(s.store.enrollments.size, 1);
  assert.equal(totpAt(again.secret, 1111111000).length, 6);
  assert.ok('recovery_codes' in (s.svc.enrollConfirm('user_1', totpAt(again.secret, 1111111000)) as object));
});

/**
 * TOTP-04: enroll_confirm: 8 spec recovery codes, keyed hashes only, confirming code refused, 409s.
 * In: the spec's vectors and fakes. Out: assertions only. Why: TOTP-04 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// TOTP-04
test('TOTP-04 enroll_confirm: 8 spec recovery codes, keyed hashes only, confirming code refused, 409s', () => {
  const stream = Array.from({ length: 400 }, (_, k) => (7 * k) % 256);
  const s = setup(1111111109, queue([...K, ...NONCE, ...stream]));
  assert.deepEqual(s.svc.enrollConfirm('user_1', '081804'), { error: 'enrollment_not_started', status: 409 });
  s.svc.enrollStart('user_1', 'alice@example.com');
  const out = s.svc.enrollConfirm('user_1', '081804') as { recovery_codes: string[] };
  assert.deepEqual(out.recovery_codes, [
    '29gq-y7en-w5ck', 't3ah-rz8f-px6d', 'mv4b-js29-gqy5', 'ckt3-ahrz-8fpx',
    '6dmv-4bjs-29gq', 'y7en-w5ck-t8fp', 'x6dm-v4bj-s29g', 'qy7e-nw5c-kt3a',
  ]);
  for (const c of out.recovery_codes) assert.match(c, /^[23456789abcdefghjkmnpqrstvwxyz]{4}-[23456789abcdefghjkmnpqrstvwxyz]{4}-[23456789abcdefghjkmnpqrstvwxyz]{4}$/);
  const stored = s.store.recovery.filter((r) => r.user_id === 'user_1');
  assert.equal(stored.length, 8);
  assert.equal(stored[0].code_hash, 'd9199ecad0b35d9e2f18857343d7fe79dd5f8425f1c460c88fe18f5c4b4a2645');
  const dump = JSON.stringify(s.store.recovery);
  for (const c of out.recovery_codes) {
    assert.ok(!dump.includes(c) && !dump.includes(recoveryInput(c)!));
  }
  assert.equal(s.store.enrollments.get('user_1')!.confirmed_at, 1111111109);
  assert.deepEqual(s.svc.verify('user_1', '081804'), { error: 'invalid_code', status: 401 });
  assert.deepEqual(s.svc.enrollConfirm('user_1', '081804'), { error: 'already_enrolled', status: 409 });
  assert.deepEqual(s.svc.enrollStart('user_1', 'alice@example.com'), { error: 'already_enrolled', status: 409 });
});

/**
 * TOTP-05: window: previous, current and next step accepted; two steps back and ahead refused.
 * In: the spec's vectors and fakes. Out: assertions only. Why: TOTP-05 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// TOTP-05
test('TOTP-05 window: previous, current and next step accepted; two steps back and ahead refused', () => {
  const s = setup(1111111000, queue([...K, ...NONCE]));
  s.svc.enrollStart('user_1', 'a');
  assert.ok('recovery_codes' in (s.svc.enrollConfirm('user_1', totpAt(K_B32, 1111111000)) as object));
  s.clock.now = 1111111109;
  assert.deepEqual(s.svc.verify('user_1', '150727'), { error: 'invalid_code', status: 401 });
  assert.deepEqual(s.svc.verify('user_1', '266759'), { error: 'invalid_code', status: 401 });
  for (const code of ['731029', '081804', '050471']) {
    assert.deepEqual(s.svc.verify('user_1', code), { ok: true, method: 'totp', recovery_codes_left: 8 });
  }
});

/**
 * TOTP-06: replay: a code once, no earlier step after a later one, the store claims each step once.
 * In: the spec's vectors and fakes. Out: assertions only. Why: TOTP-06 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// TOTP-06
test('TOTP-06 replay: a code once, no earlier step after a later one, the store claims each step once', () => {
  const s = setup(1111111000, queue([...K, ...NONCE]));
  s.svc.enrollStart('user_1', 'a');
  s.svc.enrollConfirm('user_1', totpAt(K_B32, 1111111000));
  s.clock.now = 1111111109;
  assert.equal((s.svc.verify('user_1', '081804') as { ok: boolean }).ok, true);
  assert.deepEqual(s.svc.verify('user_1', '081804'), { error: 'invalid_code', status: 401 });
  assert.deepEqual(s.svc.verify('user_1', '731029'), { error: 'invalid_code', status: 401 });
  assert.equal((s.svc.verify('user_1', '050471') as { ok: boolean }).ok, true);
  assert.equal(s.store.claimStep('user_1', 37037040), true);
  assert.equal(s.store.claimStep('user_1', 37037040), false);
  assert.equal(s.store.claimStep('user_1', 37037039), false);
});

/**
 * TOTP-07: input: spaces and dashes accepted; malformed codes are 401 invalid_code and one failure each.
 * In: the spec's vectors and fakes. Out: assertions only. Why: TOTP-07 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// TOTP-07
test('TOTP-07 input: spaces and dashes accepted; malformed codes are 401 invalid_code and one failure each', () => {
  for (const spelling of ['081 804', '081-804', '081804']) {
    const s = setup(1111111000, queue([...K, ...NONCE]));
    s.svc.enrollStart('u', 'a');
    s.svc.enrollConfirm('u', totpAt(K_B32, 1111111000));
    s.clock.now = 1111111109;
    assert.deepEqual(s.svc.verify('u', spelling), { ok: true, method: 'totp', recovery_codes_left: 8 }, spelling);
  }
  const bad: unknown[] = ['08180', '0818040', 'abcdef', '', undefined, null, '081804' + ' '.repeat(59),
    '1'.repeat(65), '٠٨١٨٠٤', 81804];
  bad.forEach((code, i) => {
    const s = setup(1111111000, queue([...K, ...NONCE]));
    const user = 'bad_' + i;
    s.svc.enrollStart(user, 'a');
    s.svc.enrollConfirm(user, totpAt(K_B32, 1111111000));
    s.clock.now = 1111111109;
    assert.deepEqual(s.svc.verify(user, code), { error: 'invalid_code', status: 401 }, String(code));
    assert.equal(s.store.enrollments.get(user)!.failed_since_success, 1);
    assert.equal(failureRows(s.store, user), 1);
  });
});

/**
 * TOTP-08: recovery codes: once each, any case and no dashes, not for another user, keyed hash.
 * In: the spec's vectors and fakes. Out: assertions only. Why: TOTP-08 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// TOTP-08
test('TOTP-08 recovery codes: once each, any case and no dashes, not for another user, keyed hash', () => {
  const s = setup();
  const a = enroll(s, 'user_a');
  enroll(s, 'user_b');
  assert.deepEqual(s.svc.verify('user_a', a.codes[0]), { ok: true, method: 'recovery_code', recovery_codes_left: 7 });
  assert.deepEqual(s.svc.verify('user_a', a.codes[0]), { error: 'invalid_code', status: 401 });
  assert.deepEqual(s.svc.verify('user_a', a.codes[1].toUpperCase()), { ok: true, method: 'recovery_code', recovery_codes_left: 6 });
  assert.deepEqual(s.svc.verify('user_a', a.codes[2].replace(/-/g, '')), { ok: true, method: 'recovery_code', recovery_codes_left: 5 });
  assert.deepEqual(s.svc.verify('user_b', a.codes[3]), { error: 'invalid_code', status: 401 });
  const hash = s.svc.recoveryHash('user_1', recoveryInput('K7MQ-2XPT-9HCW')!);
  assert.equal(hash, '5a93360f78c7f03de7336a625adf93bf238749d8da4aaf734271b327c52347a3');
  assert.notEqual(hash, createHash('sha256').update('k7mq2xpt9hcw').digest('hex'));
  const stored = s.store.recovery.filter((r) => r.user_id === 'user_a').map((r) => r.code_hash);
  assert.ok(stored.includes(s.svc.recoveryHash('user_a', recoveryInput(a.codes[4])!)));
  assert.ok(!stored.includes(createHash('sha256').update(recoveryInput(a.codes[4])!).digest('hex')));
});

/**
 * TOTP-09: lock: 5 failures in 900 s lock, retry_after, no failure added; ends at 900 s; try write 5 times.
 * In: the spec's vectors and fakes. Out: assertions only. Why: TOTP-09 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// TOTP-09
test('TOTP-09 lock: 5 failures in 900 s lock, retry_after, no failure added; ends at 900 s; try write 5 times', () => {
  const s = setup(1700000000 - 100);
  const { secret } = enroll(s, 'u');
  const t0 = 1700000000;
  for (let i = 0; i < 5; i++) {
    s.clock.now = t0 + 10 * i;
    assert.deepEqual(s.svc.verify('u', wrongCode(secret, s.clock.now)), { error: 'invalid_code', status: 401 });
  }
  s.clock.now = t0 + 50;
  assert.deepEqual(s.svc.verify('u', totpAt(secret, s.clock.now)), { error: 'locked', status: 429, retry_after: 850 });
  assert.equal(failureRows(s.store, 'u'), 5);
  assert.equal(s.store.enrollments.get('u')!.failed_since_success, 5);
  assert.deepEqual(s.svc.status('u'), { enrolled: true, locked_until: t0 + 900, recovery_required: false, recovery_codes_left: 8 });
  s.clock.now = t0 + 899;
  assert.deepEqual(s.svc.verify('u', totpAt(secret, s.clock.now)), { error: 'locked', status: 429, retry_after: 1 });
  s.clock.now = t0 + 900;
  assert.deepEqual(s.svc.verify('u', totpAt(secret, s.clock.now)), { ok: true, method: 'totp', recovery_codes_left: 8 });

  const fresh = new InMemoryTotpStore();
  for (let i = 0; i < 5; i++) assert.notEqual(fresh.tryInsert('x', 1000 + i), null);
  assert.equal(fresh.tryInsert('x', 1005), null);
});

/**
 * TOTP-10: an unreadable sealed secret is 503 secret_unreadable with no failure; a recovery code still works.
 * In: the spec's vectors and fakes. Out: assertions only. Why: TOTP-10 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// TOTP-10
test('TOTP-10 an unreadable sealed secret is 503 secret_unreadable with no failure; a recovery code still works', () => {
  const s = setup();
  const { secret, codes } = enroll(s, 'u');
  const otherKey = setup(s.clock.now, undefined, s.store, Buffer.alloc(32, 9));
  s.clock.now += 60;
  otherKey.clock.now = s.clock.now;
  assert.deepEqual(otherKey.svc.verify('u', totpAt(secret, s.clock.now)), { error: 'secret_unreadable', status: 503 });
  assert.equal(failureRows(s.store, 'u'), 0);
  assert.equal(s.store.enrollments.get('u')!.failed_since_success, 0);

  const row = s.store.enrollments.get('u')!;
  const i = 20;
  row.secret_enc = row.secret_enc.slice(0, i) + (row.secret_enc[i] === 'A' ? 'B' : 'A') + row.secret_enc.slice(i + 1);
  assert.deepEqual(s.svc.verify('u', totpAt(secret, s.clock.now)), { error: 'secret_unreadable', status: 503 });
  assert.equal(failureRows(s.store, 'u'), 0);
  assert.deepEqual(s.svc.verify('u', codes[0]), { ok: true, method: 'recovery_code', recovery_codes_left: 7 });
});

/**
 * TOTP-11: seal vector, open, wrong aad / key / byte, key sizes refused at construction.
 * In: the spec's vectors and fakes. Out: assertions only. Why: TOTP-11 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// TOTP-11
test('TOTP-11 seal vector, open, wrong aad / key / byte, key sizes refused at construction', () => {
  assert.equal(seal(ENC_KEY, NONCE, K_B32, 'totp:user_1'), SEALED_K);
  assert.equal(open(ENC_KEY, SEALED_K, 'totp:user_1'), K_B32);
  assert.equal(open(ENC_KEY, SEALED_K, 'totp:user_2'), null);
  assert.equal(open(Buffer.alloc(32, 1), SEALED_K, 'totp:user_1'), null);
  const changed = SEALED_K.slice(0, 30) + (SEALED_K[30] === 'A' ? 'B' : 'A') + SEALED_K.slice(31);
  assert.equal(open(ENC_KEY, changed, 'totp:user_1'), null);
  assert.equal(open(ENC_KEY, SEALED_K.slice(3), 'totp:user_1'), null);
  assert.equal(open(ENC_KEY, 'v1.!!!!', 'totp:user_1'), null);
  assert.equal(open(ENC_KEY, 'v1.' + Buffer.alloc(27).toString('base64'), 'totp:user_1'), null);
  const isInvalidKey = (e: unknown) => e instanceof TotpError && e.code === 'invalid_key';
  for (const n of [0, 16, 31, 33]) {
    assert.throws(() => new TotpTwoFactor({ encryptionKey: Buffer.alloc(n), recoveryHashKey: REC_KEY, issuer: 'x' }), isInvalidKey);
  }
  assert.throws(() => new TotpTwoFactor({ encryptionKey: ENC_KEY, recoveryHashKey: Buffer.alloc(31), issuer: 'x' }), isInvalidKey);
  assert.ok(new TotpTwoFactor({ encryptionKey: ENC_KEY, recoveryHashKey: Buffer.alloc(64), issuer: 'x' }));
});

/**
 * TOTP-12: disable with a valid code deletes everything; a wrong code is 401 and deletes nothing.
 * In: the spec's vectors and fakes. Out: assertions only. Why: TOTP-12 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// TOTP-12
test('TOTP-12 disable with a valid code deletes everything; a wrong code is 401 and deletes nothing', () => {
  const s = setup();
  const { secret } = enroll(s, 'u');
  s.clock.now += 60;
  assert.deepEqual(s.svc.disable('u', wrongCode(secret, s.clock.now)), { error: 'invalid_code', status: 401 });
  assert.ok(s.store.enrollments.has('u'));
  assert.equal(s.store.recovery.filter((r) => r.user_id === 'u').length, 8);
  assert.equal(failureRows(s.store, 'u'), 1);
  assert.deepEqual(s.svc.disable('u', totpAt(secret, s.clock.now)), { disabled: true });
  assert.ok(!s.store.enrollments.has('u'));
  assert.equal(s.store.recovery.filter((r) => r.user_id === 'u').length, 0);
  assert.equal(failureRows(s.store, 'u'), 0);
  assert.deepEqual(s.svc.verify('u', totpAt(secret, s.clock.now)), { error: 'not_enrolled', status: 409 });
  assert.ok('secret' in (s.svc.enrollStart('u', 'a') as object));
});

/**
 * TOTP-13: verify and disable before confirm are 409 not_enrolled; users never accept each other\'s codes.
 * In: the spec's vectors and fakes. Out: assertions only. Why: TOTP-13 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// TOTP-13
test('TOTP-13 verify and disable before confirm are 409 not_enrolled; users never accept each other\'s codes', () => {
  const s = setup();
  const started = s.svc.enrollStart('u', 'a') as { secret: string };
  const right = totpAt(started.secret, s.clock.now);
  assert.deepEqual(s.svc.verify('u', right), { error: 'not_enrolled', status: 409 });
  assert.deepEqual(s.svc.disable('u', right), { error: 'not_enrolled', status: 409 });
  assert.deepEqual(s.svc.verify('nobody', '123456'), { error: 'not_enrolled', status: 409 });
  const a = enroll(s, 'a');
  const b = enroll(s, 'b');
  s.clock.now += 60;
  const aCode = totpAt(a.secret, s.clock.now);
  const bCode = totpAt(b.secret, s.clock.now);
  assert.notEqual(aCode, bCode);
  assert.deepEqual(s.svc.verify('b', aCode), { error: 'invalid_code', status: 401 });
  assert.deepEqual(s.svc.verify('a', bCode), { error: 'invalid_code', status: 401 });
});

/**
 * TOTP-14: hard lock after 100 failures: recovery_required whatever the time, a recovery code clears it.
 * In: the spec's vectors and fakes. Out: assertions only. Why: TOTP-14 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// TOTP-14
test('TOTP-14 hard lock after 100 failures: recovery_required whatever the time, a recovery code clears it', () => {
  const s = setup(1700000000);
  const { secret, codes } = enroll(s, 'u');
  for (let w = 0; w < 20; w++) {
    s.clock.now += 900;
    for (let i = 0; i < 5; i++) {
      assert.deepEqual(s.svc.verify('u', wrongCode(secret, s.clock.now)), { error: 'invalid_code', status: 401 });
    }
  }
  assert.equal(s.store.enrollments.get('u')!.failed_since_success, 100);
  s.clock.now += 900;
  const rows = failureRows(s.store, 'u');
  assert.deepEqual(s.svc.verify('u', totpAt(secret, s.clock.now)), { error: 'recovery_required', status: 429 });
  assert.equal(failureRows(s.store, 'u'), rows);
  assert.equal(s.store.enrollments.get('u')!.failed_since_success, 100);
  assert.equal(s.svc.status('u').recovery_required, true);
  s.clock.now += 86400 * 30;
  assert.deepEqual(s.svc.verify('u', totpAt(secret, s.clock.now)), { error: 'recovery_required', status: 429 });
  assert.deepEqual(s.svc.verify('u', codes[0]), { ok: true, method: 'recovery_code', recovery_codes_left: 7 });
  assert.equal(s.store.enrollments.get('u')!.failed_since_success, 0);
  assert.deepEqual(s.svc.verify('u', totpAt(secret, s.clock.now)), { ok: true, method: 'totp', recovery_codes_left: 7 });
});

/**
 * TOTP-14: a success before the 100th failure starts the count again.
 * In: the spec's vectors and fakes. Out: assertions only. Why: TOTP-14 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// TOTP-14
test('TOTP-14 a success before the 100th failure starts the count again', () => {
  const s = setup(1700000000);
  const { secret } = enroll(s, 'u');
  for (let w = 0; w < 20; w++) {
    s.clock.now += 900;
    const n = w === 19 ? 4 : 5;
    for (let i = 0; i < n; i++) s.svc.verify('u', wrongCode(secret, s.clock.now));
  }
  assert.equal(s.store.enrollments.get('u')!.failed_since_success, 99);
  assert.deepEqual(s.svc.verify('u', totpAt(secret, s.clock.now)), { ok: true, method: 'totp', recovery_codes_left: 8 });
  assert.equal(s.store.enrollments.get('u')!.failed_since_success, 0);
  s.clock.now += 900;
  s.svc.verify('u', wrongCode(secret, s.clock.now));
  assert.equal(s.store.enrollments.get('u')!.failed_since_success, 1);
  s.clock.now += 30;
  assert.deepEqual(s.svc.verify('u', totpAt(secret, s.clock.now)), { ok: true, method: 'totp', recovery_codes_left: 8 });
});

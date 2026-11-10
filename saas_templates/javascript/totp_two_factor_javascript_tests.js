'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const {
  base32Encode, base32Decode, hotp, totpAt, otpauthUri, seal, open, recoveryCodeHash,
  SqliteTotpStore, TotpError, createTotpService
} = require('./totp_two_factor_javascript.js');

/*
 * Tests for docs/specs/totp_two_factor.md (TOTP-01..TOTP-14) with the spec's TEST VECTORS. Time comes from a
 * settable clock and random bytes from a queue, so every value is predictable. Why: Phase D wave 1, owner request
 * 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches an in-memory SQLite database only.
 */

const K = Buffer.from('12345678901234567890', 'ascii');
const KB32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const ENC_KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const REC_KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => 0x40 + i));
const NONCE = Buffer.from(Array.from({ length: 12 }, (_, i) => 0xa0 + i));
const SEALED_K = 'v1.oKGio6SlpqeoqaqroV0maQKFQOklPLSHVjWKjzfpA1TV+QA621cV0i7kP1B5d8k2owRGDhH/FzF0f662';
const SPEC_CODES = [
  '29gq-y7en-w5ck', 't3ah-rz8f-px6d', 'mv4b-js29-gqy5', 'ckt3-ahrz-8fpx',
  '6dmv-4bjs-29gq', 'y7en-w5ck-t8fp', 'x6dm-v4bj-s29g', 'qy7e-nw5c-kt3a'
];

/**
 * A random_bytes fake: serves the queued bytes in order whatever n is asked, then falls back to a counter so a
 * test that needs more never loops: byte i of SHA-256("fallback:" + i / 32), a deterministic stream that does
 * not cycle the way a small LCG does modulo 30. In: initial bytes. Out: {fn(n), push(bytes), drawn}.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function byteQueue(initial = []) {
  const q = Array.from(initial);
  const state = { drawn: 0, next: 0 };
  return {
    state,
    push(bytes) { q.push(...bytes); },
    fn(n) {
      const out = [];
      for (let i = 0; i < n; i++) {
        state.drawn++;
        if (q.length) { out.push(q.shift()); continue; }
        const i = state.next++;
        out.push(crypto.createHash('sha256').update('fallback:' + Math.floor(i / 32)).digest()[i % 32]);
      }
      return Buffer.from(out);
    }
  };
}

/**
 * A service with the spec's keys, a settable clock and a byte queue. In: start time, initial bytes, overrides.
 * Out: {svc, clock, rnd, store}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches an in-memory database.
 */
function setup(start = 1111111000, initial = [], overrides = {}) {
  const clock = { t: start };
  const rnd = byteQueue(initial);
  const store = overrides.store || new SqliteTotpStore();
  const svc = createTotpService({
    store, encryptionKey: ENC_KEY, recoveryHashKey: REC_KEY, issuer: 'Example App', clock: () => clock.t,
    randomBytes: n => rnd.fn(n), ...overrides
  });
  return { svc, clock, rnd, store };
}

/**
 * Enrolls and confirms a user at the current clock. Out: {secret, codes}.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
 */
function enroll(env, userId) {
  const { secret } = env.svc.enrollStart(userId, userId + '@example.com');
  const r = env.svc.enrollConfirm(userId, totpAt(secret, env.clock.t));
  assert.ok(r.recovery_codes, JSON.stringify(r));
  return { secret, codes: r.recovery_codes };
}

/**
 * A 6-digit code that matches none of the steps s-1, s, s+1 at time t. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches nothing.
 */
function wrongCode(secret, t) {
  const near = [t - 30, t, t + 30].map(x => totpAt(secret, x));
  for (let i = 0; ; i++) {
    const c = String(i).padStart(6, '0');
    if (!near.includes(c)) return c;
  }
}

/**
 * TOTP-01: hotp gives the RFC 4226 values for counters 0 to 9, and totp_at gives the RFC 6238 SHA-1 values in 8
 * and in 6 digits, T = 20000000000 included; a counter above 32 bits (4294967296) gives the spec's value, not the
 * value for 0.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: TOTP-01, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only.
 */
// TOTP-01
test('TOTP-01 hotp RFC 4226 values, totp_at RFC 6238 values in 8 and 6 digits, 64-bit counter', () => {
  const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
  for (let c = 0; c < 10; c++) assert.strictEqual(hotp(K, c), expected[c]);
  assert.strictEqual(hotp(K, 4294967296), '999456');
  const table = [
    [59, '94287082', '287082'], [1111111109, '07081804', '081804'], [1111111111, '14050471', '050471'],
    [1234567890, '89005924', '005924'], [2000000000, '69279037', '279037'], [20000000000, '65353130', '353130']
  ];
  for (const [t, eight, six] of table) {
    assert.strictEqual(totpAt(KB32, t, 8), eight);
    assert.strictEqual(totpAt(KB32, t, 6), six);
    assert.strictEqual(totpAt(KB32, t), six);
  }
});

/**
 * TOTP-02: base32: the RFC 4648 vectors encode without padding and decode back; decode ignores spaces, dashes, "="
 * and case; any other character, and a length of 1, 3 or 6 modulo 8, is invalid_base32; generate_secret is 32
 * characters that decode to 20 bytes.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: TOTP-02, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only.
 */
// TOTP-02
test('TOTP-02 base32 RFC 4648 vectors, lenient spelling, invalid characters and lengths, generate_secret', () => {
  const vectors = [['', ''], ['f', 'MY'], ['fo', 'MZXQ'], ['foo', 'MZXW6'], ['foob', 'MZXW6YQ'], ['fooba', 'MZXW6YTB'], ['foobar', 'MZXW6YTBOI']];
  for (const [plain, enc] of vectors) {
    assert.strictEqual(base32Encode(Buffer.from(plain)), enc);
    if (enc) assert.strictEqual(base32Decode(enc).toString(), plain);
  }
  assert.strictEqual(base32Encode(K), KB32);
  assert.strictEqual(base32Decode('mzxw 6ytb-oi==').toString(), 'foobar');
  assert.strictEqual(base32Decode('MZ').toString(), 'f');
  for (const bad of ['MZXW6YT1', '', 'M', 'MZX', 'MZXW6Y']) assert.deepStrictEqual(base32Decode(bad), { error: 'invalid_base32' });
  const { svc } = setup();
  const secret = svc.generateSecret();
  assert.strictEqual(secret.length, 32);
  assert.strictEqual(base32Decode(secret).length, 20);
});

/**
 * TOTP-03: enroll_start returns the secret and the exact otpauth URI; the store holds only the sealed secret (with
 * the injected random bytes: the spec's string), never the base32 text; a second enroll_start before confirming
 * replaces the secret.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: TOTP-03, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only.
 */
// TOTP-03
test('TOTP-03 enroll_start returns secret and URI, stores only the sealed secret, a second start replaces it', () => {
  const env = setup(1111111000, [...K, ...NONCE]);
  const r = env.svc.enrollStart('user_1', 'alice@example.com');
  assert.strictEqual(r.secret, KB32);
  assert.strictEqual(r.otpauth_uri,
    'otpauth://totp/Example%20App%3Aalice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example%20App&algorithm=SHA1&digits=6&period=30');
  assert.strictEqual(otpauthUri(KB32, 'Example App', 'alice@example.com'), r.otpauth_uri);
  const row = env.store.getEnrollment('user_1');
  assert.strictEqual(row.secret_enc, SEALED_K);
  assert.strictEqual(row.confirmed_at, null);
  assert.ok(!JSON.stringify(row).includes(KB32));
  const second = env.svc.enrollStart('user_1', 'alice@example.com');
  assert.notStrictEqual(second.secret, KB32);
  assert.notStrictEqual(env.store.getEnrollment('user_1').secret_enc, SEALED_K);
  assert.strictEqual(open(ENC_KEY, env.store.getEnrollment('user_1').secret_enc, 'totp:user_1'), second.secret);
  // The first secret no longer confirms.
  assert.deepStrictEqual(env.svc.enrollConfirm('user_1', totpAt(KB32, env.clock.t)), { error: 'invalid_code', status: 401 });
});

/**
 * TOTP-04: enroll_confirm with the current code returns 8 recovery codes shaped xxxx-xxxx-xxxx and stores only
 * their keyed hashes; the code that confirmed is then refused by verify; a second confirm is 409 already_enrolled,
 * a confirm with nothing started is 409 enrollment_not_started, enroll_start after confirming is 409
 * already_enrolled; with the spec's byte stream the 8 codes are the spec's 8 codes.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: TOTP-04, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only.
 */
// TOTP-04
test('TOTP-04 enroll_confirm gives the spec\'s 8 recovery codes, stores keyed hashes, and the 409 cases', () => {
  const env = setup(1111111000, [...K, ...NONCE]);
  assert.deepStrictEqual(env.svc.enrollConfirm('user_1', '123456'), { error: 'enrollment_not_started', status: 409 });
  env.svc.enrollStart('user_1', 'alice@example.com');
  const before = env.rnd.state.drawn;
  env.rnd.push(Array.from({ length: 200 }, (_, k) => (7 * k) % 256));
  const code = totpAt(KB32, env.clock.t);
  const r = env.svc.enrollConfirm('user_1', code);
  assert.deepStrictEqual(r, { recovery_codes: SPEC_CODES });
  assert.strictEqual(env.rnd.state.drawn - before, 101);
  for (const c of r.recovery_codes) assert.match(c, /^[23456789abcdefghjkmnpqrstvwxyz]{4}-[23456789abcdefghjkmnpqrstvwxyz]{4}-[23456789abcdefghjkmnpqrstvwxyz]{4}$/);
  const hashes = env.store.recoveryHashes('user_1');
  assert.strictEqual(hashes.length, 8);
  assert.strictEqual(hashes[0], 'd9199ecad0b35d9e2f18857343d7fe79dd5f8425f1c460c88fe18f5c4b4a2645');
  assert.ok(hashes.every(h => !SPEC_CODES.some(c => h.includes(c.replace(/-/g, '')))));
  assert.deepStrictEqual(env.svc.verify('user_1', code), { error: 'invalid_code', status: 401 });
  assert.deepStrictEqual(env.svc.enrollConfirm('user_1', code), { error: 'already_enrolled', status: 409 });
  assert.deepStrictEqual(env.svc.enrollStart('user_1', 'alice@example.com'), { error: 'already_enrolled', status: 409 });
});

/**
 * TOTP-05: verify accepts the code of the previous, the current and the next 30-second step, and refuses the codes
 * two steps back and two steps ahead with 401 invalid_code (the window vector).
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: TOTP-05, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only.
 */
// TOTP-05
test('TOTP-05 window: previous, current and next step accepted; two steps back and ahead refused', () => {
  const env = setup(1111111000, [...K, ...NONCE]);
  env.svc.enrollStart('user_1', 'a');
  assert.ok(env.svc.enrollConfirm('user_1', totpAt(KB32, 1111111000)).recovery_codes);
  env.clock.t = 1111111109;
  assert.deepStrictEqual(env.svc.verify('user_1', '150727'), { error: 'invalid_code', status: 401 });
  assert.deepStrictEqual(env.svc.verify('user_1', '266759'), { error: 'invalid_code', status: 401 });
  for (const code of ['731029', '081804', '050471']) {
    assert.deepStrictEqual(env.svc.verify('user_1', code), { ok: true, method: 'totp', recovery_codes_left: 8 });
  }
});

/**
 * TOTP-06: replay: an accepted code is 401 the second time; once a step is accepted the code of an earlier step is
 * 401 and the code of a later step is accepted; the store's claim succeeds once per step.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: TOTP-06, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only.
 */
// TOTP-06
test('TOTP-06 replay: an accepted code is refused again, earlier steps refused, later accepted; claim once per step', () => {
  const env = setup(1111111000, [...K, ...NONCE]);
  env.svc.enrollStart('user_1', 'a');
  env.svc.enrollConfirm('user_1', totpAt(KB32, 1111111000));
  env.clock.t = 1111111109;
  assert.strictEqual(env.svc.verify('user_1', '081804').ok, true);
  assert.deepStrictEqual(env.svc.verify('user_1', '081804'), { error: 'invalid_code', status: 401 });
  assert.deepStrictEqual(env.svc.verify('user_1', '731029'), { error: 'invalid_code', status: 401 });
  assert.strictEqual(env.svc.verify('user_1', '050471').ok, true);
  const step = env.store.getEnrollment('user_1').last_used_step;
  assert.strictEqual(step, 37037037);
  assert.strictEqual(env.store.claim('user_1', step + 1), 1);
  assert.strictEqual(env.store.claim('user_1', step + 1), 0);
});

/**
 * TOTP-07: input: "081 804" and "081-804" are accepted like "081804" (each spelling on its own fresh enrollment);
 * 5 digits, 7 digits, letters, an empty string, a missing code, a code over 64 characters and non-ASCII digits are
 * 401 invalid_code, never an exception, and each adds one failure (each tried on its own user, so the lock does
 * not answer first).
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: TOTP-07, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only.
 */
// TOTP-07
test('TOTP-07 spaced and dashed codes are accepted; malformed codes are 401 and add one failure each', () => {
  for (const spelling of ['081 804', '081-804', '081804']) {
    const env = setup(1111111000, [...K, ...NONCE]);
    env.svc.enrollStart('user_1', 'a');
    env.svc.enrollConfirm('user_1', totpAt(KB32, 1111111000));
    env.clock.t = 1111111109;
    assert.deepStrictEqual(env.svc.verify('user_1', spelling), { ok: true, method: 'totp', recovery_codes_left: 8 });
  }
  const env = setup(1111111000);
  const bad = ['12345', '1234567', 'abcdef', '', undefined, null, '1'.repeat(65), '٠٨١٨٠٤'];
  bad.forEach((code, i) => {
    const user = 'u' + i;
    enroll(env, user);
    const failuresBefore = env.store.failureCount(user);
    const fssBefore = env.store.getEnrollment(user).failed_since_success;
    assert.deepStrictEqual(env.svc.verify(user, code), { error: 'invalid_code', status: 401 });
    assert.strictEqual(env.store.failureCount(user), failuresBefore + 1);
    assert.strictEqual(env.store.getEnrollment(user).failed_since_success, fssBefore + 1);
  });
});

/**
 * TOTP-08: a recovery code signs in once (method "recovery_code", recovery_codes_left 7), typed in upper case and
 * without dashes too (each spelling with its own unused code); used again it is 401; user A's code is 401 for user
 * B; its stored hash is the spec's keyed hash, not a plain SHA-256.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: TOTP-08, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only.
 */
// TOTP-08
test('TOTP-08 recovery codes sign in once, in any case and without dashes; per user; keyed hash', () => {
  const env = setup(1111111000, [...K, ...NONCE]);
  env.svc.enrollStart('user_1', 'a');
  env.rnd.push(Array.from({ length: 200 }, (_, k) => (7 * k) % 256));
  env.svc.enrollConfirm('user_1', totpAt(KB32, 1111111000));
  assert.deepStrictEqual(env.svc.verify('user_1', SPEC_CODES[0]), { ok: true, method: 'recovery_code', recovery_codes_left: 7 });
  assert.deepStrictEqual(env.svc.verify('user_1', SPEC_CODES[0]), { error: 'invalid_code', status: 401 });
  assert.deepStrictEqual(env.svc.verify('user_1', SPEC_CODES[1].toUpperCase()), { ok: true, method: 'recovery_code', recovery_codes_left: 6 });
  assert.deepStrictEqual(env.svc.verify('user_1', SPEC_CODES[2].replace(/-/g, '')), { ok: true, method: 'recovery_code', recovery_codes_left: 5 });
  const other = enroll(env, 'user_2');
  assert.deepStrictEqual(env.svc.verify('user_2', SPEC_CODES[3]), { error: 'invalid_code', status: 401 });
  assert.deepStrictEqual(env.svc.verify('user_1', other.codes[0]), { error: 'invalid_code', status: 401 });
  assert.strictEqual(recoveryCodeHash(REC_KEY, 'user_1', 'K7MQ-2XPT-9HCW'), '5a93360f78c7f03de7336a625adf93bf238749d8da4aaf734271b327c52347a3');
  const plain = crypto.createHash('sha256').update('k7mq2xpt9hcw').digest('hex');
  assert.notStrictEqual(recoveryCodeHash(REC_KEY, 'user_1', 'K7MQ-2XPT-9HCW'), plain);
  assert.strictEqual(env.store.recoveryHashes('user_1')[0], 'd9199ecad0b35d9e2f18857343d7fe79dd5f8425f1c460c88fe18f5c4b4a2645');
});

/**
 * TOTP-09: lock: after 5 failures inside 900 seconds the next verify is 429 locked with retry_after, with a
 * correct code too, and adds no failure; 899 seconds after the oldest of the 5 it is still locked, at 900 seconds
 * a correct code is accepted; the store's try write succeeds 5 times inside one window and not a 6th.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: TOTP-09, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only.
 */
// TOTP-09
test('TOTP-09 lock after 5 failures in 900 s, even for a correct code; ends 900 s after the oldest; try write 5 times', () => {
  const env = setup(1111111000);
  const { secret } = enroll(env, 'user_1');
  env.clock.t = 1111112000;
  const t0 = env.clock.t;
  for (let i = 0; i < 5; i++) assert.deepStrictEqual(env.svc.verify('user_1', wrongCode(secret, t0)), { error: 'invalid_code', status: 401 });
  const failures = env.store.failureCount('user_1');
  assert.deepStrictEqual(env.svc.verify('user_1', totpAt(secret, t0)), { error: 'locked', status: 429, retry_after: 900 });
  assert.strictEqual(env.store.failureCount('user_1'), failures);
  assert.strictEqual(env.svc.status('user_1').locked_until, t0 + 900);
  env.clock.t = t0 + 899;
  assert.deepStrictEqual(env.svc.verify('user_1', totpAt(secret, env.clock.t)), { error: 'locked', status: 429, retry_after: 1 });
  env.clock.t = t0 + 900;
  assert.deepStrictEqual(env.svc.verify('user_1', totpAt(secret, env.clock.t)), { ok: true, method: 'totp', recovery_codes_left: 8 });
  assert.strictEqual(env.svc.status('user_1').locked_until, null);
  // The store's try write: 5 slots inside one window, not a 6th.
  const store = new SqliteTotpStore();
  const ids = [];
  for (let i = 0; i < 5; i++) ids.push(store.tryInsert('x', 5000));
  assert.ok(ids.every(id => Number.isInteger(id)));
  assert.strictEqual(store.tryInsert('x', 5000), null);
  assert.strictEqual(store.tryInsert('x', 5899), null);
  assert.ok(Number.isInteger(store.tryInsert('x', 5900)));
});

/**
 * TOTP-10: a sealed secret that cannot be opened (another encryption_key, or one changed character) makes verify
 * answer 503 secret_unreadable for a 6-digit code, never not_enrolled or invalid_code, and adds no failure; a
 * recovery code still signs in.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: TOTP-10, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only.
 */
// TOTP-10
test('TOTP-10 an unreadable sealed secret is 503 secret_unreadable with no failure; recovery codes still work', () => {
  const env = setup(1111111000);
  const { secret, codes } = enroll(env, 'user_1');
  env.clock.t += 60;
  const otherKey = Buffer.alloc(32, 7);
  const wrongKeySvc = createTotpService({
    store: env.store, encryptionKey: otherKey, recoveryHashKey: REC_KEY, issuer: 'Example App', clock: () => env.clock.t
  });
  const before = env.store.failureCount('user_1');
  assert.deepStrictEqual(wrongKeySvc.verify('user_1', totpAt(secret, env.clock.t)), { error: 'secret_unreadable', status: 503 });
  assert.strictEqual(env.store.failureCount('user_1'), before);
  assert.strictEqual(env.store.getEnrollment('user_1').failed_since_success, 0);
  assert.deepStrictEqual(wrongKeySvc.verify('user_1', codes[0]), { ok: true, method: 'recovery_code', recovery_codes_left: 7 });
  // One changed character in the stored sealed text.
  const row = env.store.getEnrollment('user_1');
  const i = row.secret_enc.length - 5;
  const changed = row.secret_enc.slice(0, i) + (row.secret_enc[i] === 'A' ? 'B' : 'A') + row.secret_enc.slice(i + 1);
  env.store.db.prepare('UPDATE totp_enrollments SET secret_enc = ? WHERE user_id = ?').run(changed, 'user_1');
  assert.deepStrictEqual(env.svc.verify('user_1', totpAt(secret, env.clock.t)), { error: 'secret_unreadable', status: 503 });
  assert.strictEqual(env.store.failureCount('user_1'), before);
  assert.deepStrictEqual(env.svc.verify('user_1', codes[1]), { ok: true, method: 'recovery_code', recovery_codes_left: 6 });
});

/**
 * TOTP-11: seal with the spec's key, nonce and aad gives the spec's string and open returns the secret; open with
 * another user's aad, another key or one changed character returns nothing; an encryption_key that is not 32
 * bytes, or a recovery_hash_key under 32 bytes, is refused at construction.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: TOTP-11, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only.
 */
// TOTP-11
test('TOTP-11 seal gives the spec string, open returns it; wrong aad, key or a changed character open nothing; key sizes', () => {
  assert.strictEqual(seal(ENC_KEY, NONCE, KB32, 'totp:user_1'), SEALED_K);
  assert.strictEqual(open(ENC_KEY, SEALED_K, 'totp:user_1'), KB32);
  assert.strictEqual(open(ENC_KEY, SEALED_K, 'totp:user_2'), null);
  assert.strictEqual(open(Buffer.alloc(32, 1), SEALED_K, 'totp:user_1'), null);
  for (let i = 3; i < SEALED_K.length; i += 7) {
    const c = SEALED_K[i] === 'A' ? 'B' : 'A';
    assert.strictEqual(open(ENC_KEY, SEALED_K.slice(0, i) + c + SEALED_K.slice(i + 1), 'totp:user_1'), null);
  }
  assert.strictEqual(open(ENC_KEY, SEALED_K.slice(3), 'totp:user_1'), null);
  assert.strictEqual(open(ENC_KEY, 'v1.' + Buffer.alloc(27).toString('base64'), 'totp:user_1'), null);
  assert.strictEqual(open(ENC_KEY, 'v1.!!!!', 'totp:user_1'), null);
  const isInvalidKey = err => err instanceof TotpError && err.code === 'invalid_key';
  assert.throws(() => createTotpService({ encryptionKey: Buffer.alloc(31), recoveryHashKey: REC_KEY, issuer: 'x' }), isInvalidKey);
  assert.throws(() => createTotpService({ encryptionKey: Buffer.alloc(33), recoveryHashKey: REC_KEY, issuer: 'x' }), isInvalidKey);
  assert.throws(() => createTotpService({ encryptionKey: ENC_KEY, recoveryHashKey: Buffer.alloc(31), issuer: 'x' }), isInvalidKey);
  assert.ok(createTotpService({ encryptionKey: ENC_KEY, recoveryHashKey: Buffer.alloc(64), issuer: 'x' }));
});

/**
 * TOTP-12: disable with a valid code deletes the enrollment, its recovery codes and its failures, and verify is
 * then 409 not_enrolled; disable with a wrong code is 401 and deletes nothing.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: TOTP-12, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only.
 */
// TOTP-12
test('TOTP-12 disable with a valid code deletes everything; with a wrong code deletes nothing', () => {
  const env = setup(1111111000);
  const { secret } = enroll(env, 'user_1');
  env.clock.t += 60;
  assert.deepStrictEqual(env.svc.disable('user_1', wrongCode(secret, env.clock.t)), { error: 'invalid_code', status: 401 });
  assert.ok(env.store.getEnrollment('user_1'));
  assert.strictEqual(env.store.recoveryCodesLeft('user_1'), 8);
  assert.strictEqual(env.store.failureCount('user_1'), 1);
  assert.deepStrictEqual(env.svc.disable('user_1', totpAt(secret, env.clock.t)), { disabled: true });
  assert.strictEqual(env.store.getEnrollment('user_1'), null);
  assert.strictEqual(env.store.recoveryCodesLeft('user_1'), 0);
  assert.strictEqual(env.store.recoveryHashes('user_1').length, 0);
  assert.strictEqual(env.store.failureCount('user_1'), 0);
  env.clock.t += 60;
  assert.deepStrictEqual(env.svc.verify('user_1', totpAt(secret, env.clock.t)), { error: 'not_enrolled', status: 409 });
  assert.ok(env.svc.enrollStart('user_1', 'a').secret);
});

/**
 * TOTP-13: verify and disable before enroll_confirm are 409 not_enrolled, with the right code too; two users with
 * different secrets never accept each other's codes.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: TOTP-13, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only.
 */
// TOTP-13
test('TOTP-13 verify and disable before confirm are 409 not_enrolled; users never accept each other\'s codes', () => {
  const env = setup(1111111000);
  const { secret } = env.svc.enrollStart('user_1', 'a');
  const right = totpAt(secret, env.clock.t);
  assert.deepStrictEqual(env.svc.verify('user_1', right), { error: 'not_enrolled', status: 409 });
  assert.deepStrictEqual(env.svc.disable('user_1', right), { error: 'not_enrolled', status: 409 });
  assert.deepStrictEqual(env.svc.verify('nobody', right), { error: 'not_enrolled', status: 409 });
  assert.strictEqual(env.svc.status('user_1').enrolled, false);
  env.svc.enrollConfirm('user_1', right);
  const b = enroll(env, 'user_2');
  assert.notStrictEqual(b.secret, secret);
  env.clock.t += 90;
  const codeA = totpAt(secret, env.clock.t);
  const codeB = totpAt(b.secret, env.clock.t);
  assert.notStrictEqual(codeA, codeB);
  assert.deepStrictEqual(env.svc.verify('user_2', codeA), { error: 'invalid_code', status: 401 });
  assert.deepStrictEqual(env.svc.verify('user_1', codeB), { error: 'invalid_code', status: 401 });
  assert.strictEqual(env.svc.verify('user_1', codeA).ok, true);
  assert.strictEqual(env.svc.verify('user_2', codeB).ok, true);
});

/**
 * TOTP-14: long-run guessing: after 100 failures with no success between them a correct 6-digit code is 429
 * recovery_required, however far the clock moves, and adds no failure; a recovery code then signs in, and after it
 * a correct 6-digit code is accepted again; a success before the 100th failure starts the count again.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: TOTP-14, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only.
 */
// TOTP-14
test('TOTP-14 after 100 failures in a row a correct code is 429 recovery_required until a recovery code signs in', () => {
  const env = setup(1111111000);
  const { secret, codes } = enroll(env, 'user_1');
  for (let w = 0; w < 20; w++) {
    env.clock.t += 900;
    for (let i = 0; i < 5; i++) assert.strictEqual(env.svc.verify('user_1', wrongCode(secret, env.clock.t)).status, 401);
  }
  assert.strictEqual(env.store.getEnrollment('user_1').failed_since_success, 100);
  env.clock.t += 900;
  const failures = env.store.failureCount('user_1');
  assert.deepStrictEqual(env.svc.verify('user_1', totpAt(secret, env.clock.t)), { error: 'recovery_required', status: 429 });
  assert.strictEqual(env.store.failureCount('user_1'), failures);
  assert.strictEqual(env.store.getEnrollment('user_1').failed_since_success, 100);
  assert.strictEqual(env.svc.status('user_1').recovery_required, true);
  env.clock.t += 10000000;
  assert.deepStrictEqual(env.svc.verify('user_1', totpAt(secret, env.clock.t)), { error: 'recovery_required', status: 429 });
  assert.deepStrictEqual(env.svc.verify('user_1', codes[0]), { ok: true, method: 'recovery_code', recovery_codes_left: 7 });
  assert.strictEqual(env.svc.status('user_1').recovery_required, false);
  env.clock.t += 60;
  assert.deepStrictEqual(env.svc.verify('user_1', totpAt(secret, env.clock.t)), { ok: true, method: 'totp', recovery_codes_left: 7 });

  // A success before the 100th failure starts the count again.
  const env2 = setup(1111111000);
  const two = enroll(env2, 'user_2');
  for (let w = 0; w < 20; w++) {
    env2.clock.t += 900;
    const n = w === 19 ? 4 : 5;
    for (let i = 0; i < n; i++) assert.strictEqual(env2.svc.verify('user_2', wrongCode(two.secret, env2.clock.t)).status, 401);
  }
  assert.strictEqual(env2.store.getEnrollment('user_2').failed_since_success, 99);
  assert.strictEqual(env2.svc.verify('user_2', totpAt(two.secret, env2.clock.t)).ok, true);
  assert.strictEqual(env2.store.getEnrollment('user_2').failed_since_success, 0);
  env2.clock.t += 900;
  assert.strictEqual(env2.svc.verify('user_2', wrongCode(two.secret, env2.clock.t)).status, 401);
  env2.clock.t += 60;
  assert.strictEqual(env2.svc.verify('user_2', totpAt(two.secret, env2.clock.t)).ok, true);
});

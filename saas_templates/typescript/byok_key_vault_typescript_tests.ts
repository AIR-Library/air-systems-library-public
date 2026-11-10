/**
 * Tests for byok_key_vault_typescript.ts: one test (or more) per VAULT-01..14 row of docs/specs/byok_key_vault.md,
 * with the spec's fixed vectors. Offline: the provider client is a fake, the clock and random bytes are injected,
 * the store is in memory. Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryVaultStore, KeyVault, VaultError, ProviderConfig } from './byok_key_vault_typescript.ts';

/** The spec's key, built from two pieces so no scanner reads it as a credential. */
const KEY = 'acme_' + 'k3y0123456789abcdefghWXYZ';
const K1 = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const K2 = Buffer.from(Array.from({ length: 32 }, (_, i) => 0x40 + i));
const PROVIDERS: Record<string, ProviderConfig> = { acme: { prefix: 'acme_', min_length: 24, max_length: 200 } };
const VECTOR_BYTES = [
  ...Array.from({ length: 32 }, (_, i) => 0x20 + i),
  ...Array.from({ length: 12 }, (_, i) => 0x60 + i),
  ...Array.from({ length: 12 }, (_, i) => 0x70 + i),
];
const CIPHERTEXT = 'YGFiY2RlZmdoaWprg/fAzqy7SCzJdVWPIX9FTko++mAiaT2vbM/uMNaLHZjhWoVBGl1vBtJurMStRQ==';
const WRAPPED = 'cHFyc3R1dnd4eXp7N6aYBJfsuhNsAxz5/W2f+J0G974wrnqNnbcDf3iKKAEOSVqlT/aJkU58qxAv2nPf';
const REWRAPPED = 'gIGCg4SFhoeIiYqLDX+c5AZRDKRAQ7oDXo+7DcjN++F5UtAjxrdC7+0oX0MOT3cH13mFkfvVnrrN/V6R';

/**
 * A random_bytes fake serving the given bytes in order, whatever n is asked, then CSPRNG bytes once drained.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the CSPRNG once drained.
 */
function queue(bytes: number[]): (n: number) => Buffer {
  const q = [...bytes];
  return (n: number) => {
    const out = Buffer.alloc(n);
    for (let i = 0; i < n; i++) out[i] = q.length ? q.shift()! : Math.floor(Math.random() * 256);
    return out;
  };
}

/**
 * A vault with a recording fake provider client. In: overrides. Out: {vault, store, calls, clock, answer}.
 * `answer.value` is what the fake returns ("throw" makes it raise). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only.
 */
function setup(opts: { random?: (n: number) => Buffer; store?: InMemoryVaultStore; keys?: Record<string, Buffer>;
                       active?: string; providers?: Record<string, ProviderConfig>; now?: number } = {}) {
  const calls: [string, string][] = [];
  const answer = { value: 'ok' as string };
  const clock = { now: opts.now ?? 1700000000 };
  const store = opts.store ?? new InMemoryVaultStore();
  const vault = new KeyVault({
    masterKeys: opts.keys ?? { k1: K1 }, activeKeyId: opts.active ?? 'k1', providers: opts.providers ?? PROVIDERS,
    providerClient: {
      check: async (provider: string, key: string) => {
        calls.push([provider, key]);
        if (answer.value === 'throw') throw new Error('network down');
        return answer.value;
      },
    },
    store, clock: () => clock.now, randomBytes: opts.random,
  });
  return { vault, store, calls, clock, answer };
}

/** Flips byte 20 of a base64 value (XOR 01) and encodes it again. Touches nothing. */
function flipByte20(b64: string): string {
  const raw = Buffer.from(b64, 'base64');
  raw[20] ^= 0x01;
  return raw.toString('base64');
}

/**
 * VAULT-01: save_key happy path: one check with the key, the row holds no key, the answer and audit row.
 * In: the spec's vectors and fakes. Out: assertions only. Why: VAULT-01 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// VAULT-01
test('VAULT-01 save_key happy path: one check with the key, the row holds no key, the answer and audit row', async () => {
  const s = setup();
  const out = await s.vault.saveKey('user_1', 'acme', KEY);
  assert.deepEqual(out, { provider: 'acme', hint: 'WXYZ', key_id: 'k1', created_at: 1700000000 });
  assert.deepEqual(s.calls, [['acme', KEY]]);
  const row = s.store.getRow('user_1', 'acme')!;
  assert.equal(row.key_id, 'k1');
  assert.equal(row.hint, 'WXYZ');
  assert.ok(row.wrapped_dek.length > 0 && row.ciphertext.length > 0);
  assert.ok(!JSON.stringify([...s.store.rows.values()]).includes(KEY));
  assert.ok(!JSON.stringify([...s.store.rows.values()]).includes(Buffer.from(KEY).toString('base64')));
  assert.deepEqual(s.vault.listAudit('user_1'), [{ at: 1700000000, action: 'key_saved', provider: 'acme', purpose: null, key_id: 'k1' }]);
});

/**
 * VAULT-02: known answer: the spec ciphertext and wrapped_dek; use_key returns the key.
 * In: the spec's vectors and fakes. Out: assertions only. Why: VAULT-02 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// VAULT-02
test('VAULT-02 known answer: the spec ciphertext and wrapped_dek; use_key returns the key', async () => {
  const s = setup({ random: queue(VECTOR_BYTES) });
  await s.vault.saveKey('user_1', 'acme', KEY);
  const row = s.store.getRow('user_1', 'acme')!;
  assert.equal(row.ciphertext, CIPHERTEXT);
  assert.equal(row.wrapped_dek, WRAPPED);
  assert.deepEqual(s.vault.useKey('user_1', 'acme', 'chat.completion'), { key: KEY });
});

/**
 * VAULT-03: unknown provider 404; malformed keys 400 invalid_key_format; no call, nothing stored.
 * In: the spec's vectors and fakes. Out: assertions only. Why: VAULT-03 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// VAULT-03
test('VAULT-03 unknown provider 404; malformed keys 400 invalid_key_format; no call, nothing stored', async () => {
  const s = setup();
  assert.deepEqual(await s.vault.saveKey('user_1', 'nope', KEY), { error: 'unknown_provider', status: 404 });
  const bad: unknown[] = [
    'beta_' + 'k3y0123456789abcdefghWXYZ', 'acme_' + 'short', 'acme_' + 'x'.repeat(196),
    'acme_' + 'k3y01234567 89abcdefghWXYZ', 'acme_' + 'k3y01234567\n89abcdefghWXYZ', 12345, null, undefined,
    KEY + ' ', KEY + '\u000b', KEY + '\u0000', 'acme_' + 'k3y0123456789abcdefghéXYZ',
  ];
  for (const key of bad) {
    assert.deepEqual(await s.vault.saveKey('user_1', 'acme', key), { error: 'invalid_key_format', status: 400 }, JSON.stringify(key));
  }
  assert.equal(s.calls.length, 0);
  assert.equal(s.store.rows.size, 0);
  assert.equal(s.store.audit.length, 0);
  assert.equal(s.store.windows.size, 0);
  const trimmed = await s.vault.saveKey('user_1', 'acme', ' \t' + KEY + '\r\n');
  assert.deepEqual(trimmed, { provider: 'acme', hint: 'WXYZ', key_id: 'k1', created_at: 1700000000 });
  assert.deepEqual(s.calls, [['acme', KEY]]);
  assert.equal((await s.vault.saveKey('user_1', 'acme', 'acme_' + 'x'.repeat(195))).hasOwnProperty('hint'), true);
});

/**
 * VAULT-04: provider rejected 400, unreachable / other / raised 502; nothing stored, the check counted.
 * In: the spec's vectors and fakes. Out: assertions only. Why: VAULT-04 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// VAULT-04
test('VAULT-04 provider rejected 400, unreachable / other / raised 502; nothing stored, the check counted', async () => {
  const s = setup();
  const cases: [string, string, number][] = [['rejected', 'key_rejected', 400], ['unreachable', 'provider_unreachable', 502],
    ['maybe', 'provider_unreachable', 502], ['throw', 'provider_unreachable', 502]];
  for (const [answer, error, status] of cases) {
    s.answer.value = answer;
    assert.deepEqual(await s.vault.saveKey('user_1', 'acme', KEY), { error, status });
  }
  assert.equal(s.calls.length, 4);
  assert.equal(s.store.rows.size, 0);
  assert.equal(s.store.audit.length, 0);
  assert.equal(s.store.windows.get(JSON.stringify(['user_1', 1699999200])), 4);
});

/**
 * VAULT-05: list_keys: fields, sorted by provider, no secret in its serialized form.
 * In: the spec's vectors and fakes. Out: assertions only. Why: VAULT-05 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// VAULT-05
test('VAULT-05 list_keys: fields, sorted by provider, no secret in its serialized form', async () => {
  const providers = { ...PROVIDERS, beta: { prefix: 'beta_', min_length: 24, max_length: 200 } };
  const s = setup({ providers });
  const betaKey = 'beta_' + 'Q9r8s7t6u5v4w3x2y1z0ABCD';
  await s.vault.saveKey('user_1', 'beta', betaKey);
  s.clock.now += 5;
  await s.vault.saveKey('user_1', 'acme', KEY);
  const list = s.vault.listKeys('user_1');
  assert.deepEqual(list, [
    { provider: 'acme', hint: 'WXYZ', key_id: 'k1', created_at: 1700000005, last_used_at: null },
    { provider: 'beta', hint: 'ABCD', key_id: 'k1', created_at: 1700000000, last_used_at: null },
  ]);
  const text = JSON.stringify(list);
  for (const row of s.store.rows.values()) {
    assert.ok(!text.includes(row.ciphertext) && !text.includes(row.wrapped_dek));
  }
  assert.ok(!text.includes(KEY) && !text.includes(betaKey) && !text.includes('ciphertext') && !text.includes('wrapped_dek'));
});

/**
 * VAULT-06: use_key: key, last_used_at, audit key_used; bad purpose 400; failed audit 500 with no key.
 * In: the spec's vectors and fakes. Out: assertions only. Why: VAULT-06 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// VAULT-06
test('VAULT-06 use_key: key, last_used_at, audit key_used; bad purpose 400; failed audit 500 with no key', async () => {
  const s = setup();
  await s.vault.saveKey('user_1', 'acme', KEY);
  s.clock.now = 1700000500;
  assert.deepEqual(s.vault.useKey('user_1', 'acme', 'chat:completion-1.v2_x'), { key: KEY });
  assert.equal(s.store.getRow('user_1', 'acme')!.last_used_at, 1700000500);
  assert.deepEqual(s.vault.listAudit('user_1')[1], { at: 1700000500, action: 'key_used', provider: 'acme', purpose: 'chat:completion-1.v2_x', key_id: 'k1' });
  const refusals: unknown[] = [];
  for (const purpose of ['', 'has space', 'semi;colon', 'slash/x', 'x'.repeat(101), undefined, 7]) {
    const r = s.vault.useKey('user_1', 'acme', purpose);
    assert.deepEqual(r, { error: 'invalid_purpose', status: 400 }, String(purpose));
    refusals.push(r);
  }
  s.store.failAuditWrites = true;
  s.clock.now = 1700000600;
  const failed = s.vault.useKey('user_1', 'acme', 'chat');
  assert.deepEqual(failed, { error: 'storage_failed', status: 500 });
  refusals.push(failed);
  assert.equal(s.store.getRow('user_1', 'acme')!.last_used_at, 1700000500);
  assert.equal(s.vault.listAudit('user_1').length, 2);
  assert.ok(!JSON.stringify(refusals).includes(KEY));
  assert.ok(!JSON.stringify(s.store.audit).includes(KEY));
});

/**
 * VAULT-07: isolation: another user sees nothing, cannot use or delete; A is untouched.
 * In: the spec's vectors and fakes. Out: assertions only. Why: VAULT-07 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// VAULT-07
test('VAULT-07 isolation: another user sees nothing, cannot use or delete; A is untouched', async () => {
  const s = setup();
  await s.vault.saveKey('user_a', 'acme', KEY);
  assert.deepEqual(s.vault.listKeys('user_b'), []);
  assert.deepEqual(s.vault.useKey('user_b', 'acme', 'chat'), { error: 'key_not_found', status: 404 });
  assert.deepEqual(s.vault.deleteKey('user_b', 'acme'), { deleted: false });
  assert.deepEqual(s.vault.useKey('user_a', 'acme', 'chat'), { key: KEY });
  assert.equal(s.vault.listKeys('user_a').length, 1);
});

/**
 * VAULT-08: moved rows, changed bytes, bad base64 and short values are 500 key_unreadable.
 * In: the spec's vectors and fakes. Out: assertions only. Why: VAULT-08 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// VAULT-08
test('VAULT-08 moved rows, changed bytes, bad base64 and short values are 500 key_unreadable', async () => {
  const providers = { ...PROVIDERS, beta: { prefix: 'acme_', min_length: 24, max_length: 200 } };
  const fresh = async () => {
    const s = setup({ providers });
    await s.vault.saveKey('user_a', 'acme', KEY);
    return s;
  };
  const unreadable = { error: 'key_unreadable', status: 500 };
  let s = await fresh();
  const row = s.store.getRow('user_a', 'acme')!;
  s.store.rows.set(s.store.key('user_b', 'acme'), { ...row, user_id: 'user_b' });
  assert.deepEqual(s.vault.useKey('user_b', 'acme', 'chat'), unreadable);
  s.store.rows.set(s.store.key('user_a', 'beta'), { ...row, provider: 'beta' });
  assert.deepEqual(s.vault.useKey('user_a', 'beta', 'chat'), unreadable);
  const edits: ((r: typeof row) => void)[] = [
    (r) => { r.ciphertext = flipByte20(r.ciphertext); },
    (r) => { r.wrapped_dek = flipByte20(r.wrapped_dek); },
    (r) => { r.ciphertext = '!!not base64!!'; },
    (r) => { r.wrapped_dek = 'not base64'; },
    (r) => { r.ciphertext = Buffer.alloc(27).toString('base64'); },
    (r) => { r.wrapped_dek = Buffer.alloc(10).toString('base64'); },
    (r) => { r.wrapped_dek = ''; },
  ];
  for (const edit of edits) {
    s = await fresh();
    const stored = s.store.rows.get(s.store.key('user_a', 'acme'))!;
    edit(stored);
    assert.deepEqual(s.vault.useKey('user_a', 'acme', 'chat'), unreadable);
  }
});

/**
 * VAULT-09: saving again replaces the key: one row, new DEK and nonces, new hint, new key returned.
 * In: the spec's vectors and fakes. Out: assertions only. Why: VAULT-09 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// VAULT-09
test('VAULT-09 saving again replaces the key: one row, new DEK and nonces, new hint, new key returned', async () => {
  const s = setup();
  await s.vault.saveKey('user_1', 'acme', KEY);
  const first = s.store.getRow('user_1', 'acme')!;
  const second = 'acme_' + 'n3wk3y0123456789abcdQRST';
  assert.equal((await s.vault.saveKey('user_1', 'acme', second) as { hint: string }).hint, 'QRST');
  assert.equal(s.store.rows.size, 1);
  const row = s.store.getRow('user_1', 'acme')!;
  assert.notEqual(row.ciphertext, first.ciphertext);
  assert.notEqual(row.wrapped_dek, first.wrapped_dek);
  const nonce = (b64: string) => Buffer.from(b64, 'base64').subarray(0, 12).toString('hex');
  assert.notEqual(nonce(row.ciphertext), nonce(first.ciphertext));
  assert.notEqual(nonce(row.wrapped_dek), nonce(first.wrapped_dek));
  assert.deepEqual(s.vault.useKey('user_1', 'acme', 'chat'), { key: second });
});

/**
 * VAULT-10: rotation: new saves under k2, rewrap re-wraps old rows (spec string), k1 can then leave.
 * In: the spec's vectors and fakes. Out: assertions only. Why: VAULT-10 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// VAULT-10
test('VAULT-10 rotation: new saves under k2, rewrap re-wraps old rows (spec string), k1 can then leave', async () => {
  const store = new InMemoryVaultStore();
  await setup({ store, random: queue(VECTOR_BYTES) }).vault.saveKey('user_1', 'acme', KEY);
  const both = setup({ store, keys: { k1: K1, k2: K2 }, active: 'k2' });
  const otherKey = 'acme_' + 'zzzz0123456789abcdefLMNO';
  assert.equal((await both.vault.saveKey('user_2', 'acme', otherKey) as { key_id: string }).key_id, 'k2');
  const rotator = setup({ store, keys: { k1: K1, k2: K2 }, active: 'k2', random: queue(Array.from({ length: 12 }, (_, i) => 0x80 + i)) });
  assert.deepEqual(rotator.vault.rewrap(), { rewrapped: 1, failed: 0 });
  const row = store.getRow('user_1', 'acme')!;
  assert.equal(row.key_id, 'k2');
  assert.equal(row.ciphertext, CIPHERTEXT);
  assert.equal(row.wrapped_dek, REWRAPPED);
  assert.equal(rotator.vault.listAudit('user_1').at(-1)!.action, 'key_rewrapped');
  const onlyK2 = setup({ store, keys: { k2: K2 }, active: 'k2' });
  assert.deepEqual(onlyK2.vault.useKey('user_1', 'acme', 'chat'), { key: KEY });
  assert.deepEqual(onlyK2.vault.useKey('user_2', 'acme', 'chat'), { key: otherKey });
  assert.deepEqual(onlyK2.vault.rewrap(), { rewrapped: 0, failed: 0 });
  const stale = store.getRow('user_1', 'acme')!;
  const audit = { user_id: 'user_1', provider: 'acme', action: 'key_rewrapped' as const, purpose: null, key_id: 'k2', at: 1 };
  assert.equal(store.rewrapRow('user_1', 'acme', WRAPPED, 'k2', 'x', audit), false);
  assert.equal(store.getRow('user_1', 'acme')!.wrapped_dek, stale.wrapped_dek);
});

/**
 * VAULT-11: unknown key id 503; bad master keys and provider configs fail construction.
 * In: the spec's vectors and fakes. Out: assertions only. Why: VAULT-11 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// VAULT-11
test('VAULT-11 unknown key id 503; bad master keys and provider configs fail construction', async () => {
  const store = new InMemoryVaultStore();
  const s = setup({ store, keys: { k1: K1, k2: K2 }, active: 'k2' });
  await s.vault.saveKey('user_1', 'acme', KEY);
  assert.deepEqual(setup({ store }).vault.useKey('user_1', 'acme', 'chat'), { error: 'key_unavailable', status: 503 });
  const bad = (code: string) => (e: unknown) => e instanceof VaultError && e.code === code;
  assert.throws(() => setup({ keys: { k1: Buffer.alloc(31) } }), bad('invalid_master_key'));
  assert.throws(() => setup({ keys: { k1: Buffer.alloc(33) } }), bad('invalid_master_key'));
  assert.throws(() => setup({ keys: { k1: K1 }, active: 'k9' }), bad('invalid_master_key'));
  assert.throws(() => setup({ keys: { 'bad id': K1 }, active: 'bad id' }), bad('invalid_master_key'));
  assert.throws(() => setup({ providers: { acme: { prefix: 'acme_', min_length: 20, max_length: 200 } } }), bad('invalid_provider_config'));
  assert.throws(() => setup({ providers: { acme: { prefix: 'acme_', min_length: 24, max_length: 5000 } } }), bad('invalid_provider_config'));
  assert.throws(() => setup({ providers: { Acme: { prefix: 'acme_', min_length: 24, max_length: 200 } } }), bad('invalid_provider_config'));
  assert.ok(setup({ providers: { acme: { prefix: 'acme_', min_length: 21, max_length: 200 } } }));
});

/**
 * VAULT-12: 10 provider checks per user per clock hour; 11th 429 with retry_after; next hour works.
 * In: the spec's vectors and fakes. Out: assertions only. Why: VAULT-12 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// VAULT-12
test('VAULT-12 10 provider checks per user per clock hour; 11th 429 with retry_after; next hour works', async () => {
  const s = setup({ now: 1699920000 });
  assert.deepEqual(await s.vault.saveKey('user_1', 'acme', 'acme_' + 'bad'), { error: 'invalid_key_format', status: 400 });
  for (let i = 0; i < 10; i++) {
    s.clock.now = 1699920000 + i * 60;
    assert.equal((await s.vault.saveKey('user_1', 'acme', KEY) as { hint: string }).hint, 'WXYZ');
  }
  s.clock.now = 1699920000 + 1000;
  assert.deepEqual(await s.vault.saveKey('user_1', 'acme', KEY), { error: 'rate_limited', status: 429, retry_after: 2600 });
  assert.equal(s.calls.length, 10);
  assert.equal((await s.vault.saveKey('user_2', 'acme', KEY) as { hint: string }).hint, 'WXYZ');
  s.clock.now = 1699923600;
  assert.equal((await s.vault.saveKey('user_1', 'acme', KEY) as { hint: string }).hint, 'WXYZ');
  const w = new InMemoryVaultStore();
  for (let i = 0; i < 10; i++) assert.equal(w.bumpSaveWindow('u', 1699920000), true);
  assert.equal(w.bumpSaveWindow('u', 1699920000), false);
  assert.equal(w.bumpSaveWindow('u', 1699923600), true);
});

/**
 * VAULT-13: delete_key removes the row and writes key_deleted; a second delete is false with no audit row.
 * In: the spec's vectors and fakes. Out: assertions only. Why: VAULT-13 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// VAULT-13
test('VAULT-13 delete_key removes the row and writes key_deleted; a second delete is false with no audit row', async () => {
  const s = setup();
  await s.vault.saveKey('user_1', 'acme', KEY);
  assert.deepEqual(s.vault.deleteKey('user_1', 'acme'), { deleted: true });
  assert.equal(s.store.rows.size, 0);
  assert.deepEqual(s.vault.listAudit('user_1').map((a) => a.action), ['key_saved', 'key_deleted']);
  assert.deepEqual(s.vault.deleteKey('user_1', 'acme'), { deleted: false });
  assert.equal(s.vault.listAudit('user_1').length, 2);
  assert.deepEqual(s.vault.useKey('user_1', 'acme', 'chat'), { error: 'key_not_found', status: 404 });
});

/**
 * VAULT-14: real randomness: the same key for two users gives different ciphertext, wrapped DEK and nonces.
 * In: the spec's vectors and fakes. Out: assertions only. Why: VAULT-14 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// VAULT-14
test('VAULT-14 real randomness: the same key for two users gives different ciphertext, wrapped DEK and nonces', async () => {
  const vault = new KeyVault({ masterKeys: { k1: K1 }, activeKeyId: 'k1', providers: PROVIDERS, providerClient: { check: () => 'ok' } });
  await vault.saveKey('user_a', 'acme', KEY);
  await vault.saveKey('user_b', 'acme', KEY);
  const a = vault.store.getRow('user_a', 'acme')!;
  const b = vault.store.getRow('user_b', 'acme')!;
  assert.notEqual(a.ciphertext, b.ciphertext);
  assert.notEqual(a.wrapped_dek, b.wrapped_dek);
  const nonce = (b64: string) => Buffer.from(b64, 'base64').subarray(0, 12).toString('hex');
  assert.notEqual(nonce(a.ciphertext), nonce(b.ciphertext));
  assert.notEqual(nonce(a.wrapped_dek), nonce(b.wrapped_dek));
  assert.deepEqual(vault.useKey('user_a', 'acme', 'x'), { key: KEY });
  assert.deepEqual(vault.useKey('user_b', 'acme', 'x'), { key: KEY });
});

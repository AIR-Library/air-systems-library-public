'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { createKeyVault, SqliteVaultStore, VaultError } = require('./byok_key_vault_javascript.js');

/*
 * Tests for docs/specs/byok_key_vault.md (VAULT-01..VAULT-14) with the spec's TEST VECTORS. The provider client is
 * a fake (no network), time is a settable clock and random bytes come from a queue. Why: Phase D wave 1, owner
 * request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches an in-memory SQLite database only.
 */

const KEY = 'acme_' + 'k3y0123456789abcdefghWXYZ';
const K1 = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const K2 = Buffer.from(Array.from({ length: 32 }, (_, i) => 0x40 + i));
const DEK_BYTES = Array.from({ length: 32 }, (_, i) => 0x20 + i);
const DATA_NONCE = Array.from({ length: 12 }, (_, i) => 0x60 + i);
const WRAP_NONCE = Array.from({ length: 12 }, (_, i) => 0x70 + i);
const SPEC_CIPHERTEXT = 'YGFiY2RlZmdoaWprg/fAzqy7SCzJdVWPIX9FTko++mAiaT2vbM/uMNaLHZjhWoVBGl1vBtJurMStRQ==';
const SPEC_WRAPPED = 'cHFyc3R1dnd4eXp7N6aYBJfsuhNsAxz5/W2f+J0G974wrnqNnbcDf3iKKAEOSVqlT/aJkU58qxAv2nPf';
const SPEC_REWRAPPED = 'gIGCg4SFhoeIiYqLDX+c5AZRDKRAQ7oDXo+7DcjN++F5UtAjxrdC7+0oX0MOT3cH13mFkfvVnrrN/V6R';
const PROVIDERS = {
  acme: { prefix: 'acme_', min_length: 24, max_length: 200 },
  beta: { prefix: 'beta_', min_length: 24, max_length: 200 }
};
const HOUR = 1699920000;

/**
 * A random_bytes fake: queued bytes in order, then a deterministic SHA-256 counter stream.
 * Out: {fn(n), push(bytes)}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function byteQueue(initial = []) {
  const q = Array.from(initial);
  let i = 0;
  return {
    push(bytes) { q.push(...bytes); },
    fn(n) {
      const out = [];
      for (let j = 0; j < n; j++) {
        if (q.length) { out.push(q.shift()); continue; }
        out.push(crypto.createHash('sha256').update('fallback:' + Math.floor(i / 32)).digest()[i % 32]);
        i++;
      }
      return Buffer.from(out);
    }
  };
}

/**
 * A fake provider client that records its calls and answers from `answer` (a value, or a function that may throw).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function fakeClient(answer = 'ok') {
  const client = {
    calls: [],
    answer,
    check(provider, key) {
      client.calls.push([provider, key]);
      return typeof client.answer === 'function' ? client.answer(provider, key) : client.answer;
    }
  };
  return client;
}

/**
 * A vault with the spec's configuration, a fake client, a settable clock and a byte queue.
 * Out: {vault, store, client, clock, rnd}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches an in-memory database.
 */
function setup(opts = {}) {
  const clock = { t: opts.start || HOUR + 100 };
  const rnd = byteQueue(opts.bytes || []);
  const store = opts.store || new SqliteVaultStore();
  const client = opts.client || fakeClient();
  const vault = createKeyVault({
    store, masterKeys: opts.masterKeys || { k1: K1 }, activeKeyId: opts.activeKeyId || 'k1', providers: PROVIDERS,
    providerClient: client, clock: () => clock.t, randomBytes: opts.realRandom ? undefined : n => rnd.fn(n)
  });
  return { vault, store, client, clock, rnd };
}

/** The row of the store, raw. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (read). */
function rawRows(store) {
  return store.db.prepare('SELECT * FROM provider_keys ORDER BY user_id, provider').all();
}

/** Audit rows of every user, raw. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (read). */
function rawAudit(store) {
  return store.db.prepare('SELECT * FROM provider_key_audit ORDER BY id').all();
}

/**
 * VAULT-01: save_key happy path: the provider check is called once with the key; the row holds key_id,
 * wrapped_dek, ciphertext and the hint "WXYZ" and nowhere the key; the answer is {provider, hint, key_id,
 * created_at}; an audit row key_saved exists.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: VAULT-01, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the provider client is a fake: no network).
 */
// VAULT-01
test('VAULT-01 save_key happy path: one check with the key, row holds no key, answer shape, key_saved audit', async () => {
  const env = setup();
  const r = await env.vault.saveKey('user_1', 'acme', KEY);
  assert.deepStrictEqual(r, { provider: 'acme', hint: 'WXYZ', key_id: 'k1', created_at: env.clock.t });
  assert.deepStrictEqual(env.client.calls, [['acme', KEY]]);
  const rows = rawRows(env.store);
  assert.strictEqual(rows.length, 1);
  assert.strictEqual(rows[0].key_id, 'k1');
  assert.strictEqual(rows[0].hint, 'WXYZ');
  assert.ok(rows[0].wrapped_dek.length > 0 && rows[0].ciphertext.length > 0);
  assert.ok(!JSON.stringify(rows).includes(KEY));
  assert.deepStrictEqual(env.vault.listAudit('user_1'), [{ at: env.clock.t, action: 'key_saved', provider: 'acme', purpose: null, key_id: 'k1' }]);
});

/**
 * VAULT-02: known answer: with master key k1, the injected random bytes and the key of the spec, the stored
 * ciphertext and wrapped_dek are exactly the spec's two strings, and use_key returns the key.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: VAULT-02, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the provider client is a fake: no network).
 */
// VAULT-02
test('VAULT-02 known answer: the spec ciphertext and wrapped_dek, and use_key returns the key', async () => {
  const env = setup({ bytes: [...DEK_BYTES, ...DATA_NONCE, ...WRAP_NONCE] });
  await env.vault.saveKey('user_1', 'acme', KEY);
  const row = env.store.getRow('user_1', 'acme');
  assert.strictEqual(row.ciphertext, SPEC_CIPHERTEXT);
  assert.strictEqual(row.wrapped_dek, SPEC_WRAPPED);
  assert.deepStrictEqual(env.vault.useKey('user_1', 'acme', 'chat.completion'), { key: KEY });
});

/**
 * VAULT-03: an unknown provider is 404 unknown_provider; a key with the wrong prefix, too short, too long, with a
 * space or a line break inside, or that is not text is 400 invalid_key_format; only leading and trailing space,
 * tab, CR and LF are trimmed first, so a key followed by U+00A0, U+000B or U+0000 is 400 invalid_key_format too;
 * in each refusal the provider client is not called and nothing is stored.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: VAULT-03, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the provider client is a fake: no network).
 */
// VAULT-03
test('VAULT-03 unknown provider and malformed keys are refused before the provider and before any write', async () => {
  const env = setup();
  assert.deepStrictEqual(await env.vault.saveKey('user_1', 'nope', KEY), { error: 'unknown_provider', status: 404 });
  const bad = [
    'beta_' + 'k3y0123456789abcdefghWXYZ', 'acme_' + 'short', 'acme_' + 'x'.repeat(196),
    'acme_' + 'k3y0123456789 abcdefghWXYZ', 'acme_' + 'k3y0123456789\nabcdefghWXYZ', 42, null, undefined,
    KEY + ' ', KEY + '\u000b', KEY + '\u0000'
  ];
  for (const key of bad) {
    assert.deepStrictEqual(await env.vault.saveKey('user_1', 'acme', key), { error: 'invalid_key_format', status: 400 });
  }
  assert.strictEqual(env.client.calls.length, 0);
  assert.strictEqual(rawRows(env.store).length, 0);
  assert.strictEqual(rawAudit(env.store).length, 0);
  // Only space, tab, CR and LF are trimmed: a padded key is saved trimmed.
  assert.strictEqual((await env.vault.saveKey('user_1', 'acme', ' \t\r\n' + KEY + '\n ')).hint, 'WXYZ');
  assert.deepStrictEqual(env.client.calls, [['acme', KEY]]);
  assert.strictEqual(env.vault.useKey('user_1', 'acme', 'p').key, KEY);
  // The 200-character maximum is inclusive.
  assert.strictEqual((await env.vault.saveKey('user_1', 'acme', 'acme_' + 'y'.repeat(195))).hint, 'yyyy');
});

/**
 * VAULT-04: the provider answers "rejected" -> 400 key_rejected; "unreachable", any other answer or a raised error
 * -> 502 provider_unreachable; no provider_keys row and no audit row is written (the check is still counted).
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: VAULT-04, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the provider client is a fake: no network).
 */
// VAULT-04
test('VAULT-04 rejected is 400 key_rejected; unreachable, other answers and errors are 502; nothing stored, check counted', async () => {
  const cases = [
    ['rejected', { error: 'key_rejected', status: 400 }],
    ['unreachable', { error: 'provider_unreachable', status: 502 }],
    ['OK', { error: 'provider_unreachable', status: 502 }],
    [undefined, { error: 'provider_unreachable', status: 502 }],
    [() => { throw new Error('network down'); }, { error: 'provider_unreachable', status: 502 }],
    [() => Promise.reject(new Error('timeout')), { error: 'provider_unreachable', status: 502 }]
  ];
  const env = setup();
  let n = 0;
  for (const [answer, expected] of cases) {
    env.client.answer = answer;
    const r = await env.vault.saveKey('user_1', 'acme', KEY);
    assert.deepStrictEqual(r, expected);
    assert.ok(!JSON.stringify(r).includes(KEY));
    n++;
    assert.strictEqual(env.store.windowCount('user_1', HOUR), n);
  }
  assert.strictEqual(rawRows(env.store).length, 0);
  assert.strictEqual(rawAudit(env.store).length, 0);
});

/**
 * VAULT-05: list_keys returns provider, hint, key_id, created_at and last_used_at, sorted by provider, and its
 * serialized form holds neither the key nor ciphertext nor wrapped_dek.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: VAULT-05, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the provider client is a fake: no network).
 */
// VAULT-05
test('VAULT-05 list_keys returns the public fields sorted by provider and never the key or ciphertext', async () => {
  const env = setup();
  await env.vault.saveKey('user_1', 'beta', 'beta_' + 'k3y0123456789abcdefghABCD');
  env.clock.t += 5;
  await env.vault.saveKey('user_1', 'acme', KEY);
  const list = env.vault.listKeys('user_1');
  assert.deepStrictEqual(list, [
    { provider: 'acme', hint: 'WXYZ', key_id: 'k1', created_at: HOUR + 105, last_used_at: null },
    { provider: 'beta', hint: 'ABCD', key_id: 'k1', created_at: HOUR + 100, last_used_at: null }
  ]);
  const dump = JSON.stringify(list);
  for (const row of rawRows(env.store)) {
    assert.ok(!dump.includes(row.ciphertext));
    assert.ok(!dump.includes(row.wrapped_dek));
  }
  assert.ok(!dump.includes(KEY));
});

/**
 * VAULT-06: use_key returns the key, sets last_used_at to the clock's time and writes an audit row key_used with
 * the purpose; an empty purpose, or one with a character outside [A-Za-z0-9_.:-], is 400 invalid_purpose; when the
 * audit write fails the answer is 500 storage_failed with no key; no audit row and no refusal ever holds the key.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: VAULT-06, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the provider client is a fake: no network).
 */
// VAULT-06
test('VAULT-06 use_key returns the key, records last_used_at and key_used; bad purposes; audit failure gives no key', async () => {
  const env = setup();
  await env.vault.saveKey('user_1', 'acme', KEY);
  env.clock.t += 42;
  assert.deepStrictEqual(env.vault.useKey('user_1', 'acme', 'chat:completion-v1.x_y'), { key: KEY });
  assert.strictEqual(env.store.getRow('user_1', 'acme').last_used_at, env.clock.t);
  assert.deepStrictEqual(env.vault.listAudit('user_1')[1], { at: env.clock.t, action: 'key_used', provider: 'acme', purpose: 'chat:completion-v1.x_y', key_id: 'k1' });
  for (const purpose of ['', 'has space', 'semi;colon', 'x'.repeat(101), 'é', null, 7]) {
    assert.deepStrictEqual(env.vault.useKey('user_1', 'acme', purpose), { error: 'invalid_purpose', status: 400 });
  }
  assert.deepStrictEqual(env.vault.useKey('user_1', 'acme', 'x'.repeat(100)), { key: KEY });

  /** A store whose audit write fails. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  class FailingAuditStore extends SqliteVaultStore {
    /** Throws for key_used rows (the audit write fails), else writes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    insertAudit(a) {
      if (a.action === 'key_used') throw new Error('disk full');
      super.insertAudit(a);
    }
  }
  const env2 = setup({ store: new FailingAuditStore() });
  await env2.vault.saveKey('user_1', 'acme', KEY);
  env2.clock.t += 10;
  const r = env2.vault.useKey('user_1', 'acme', 'chat');
  assert.deepStrictEqual(r, { error: 'storage_failed', status: 500 });
  assert.strictEqual(env2.store.getRow('user_1', 'acme').last_used_at, null);
  assert.ok(!JSON.stringify(rawAudit(env.store)).includes(KEY));
  assert.ok(!JSON.stringify(rawAudit(env2.store)).includes(KEY));
});

/**
 * VAULT-07: isolation: user B's list is empty, use_key for a provider only user A saved is 404 key_not_found and
 * delete_key is {deleted: false}; A's key is untouched.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: VAULT-07, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the provider client is a fake: no network).
 */
// VAULT-07
test('VAULT-07 isolation: user B sees nothing, cannot use or delete user A\'s key', async () => {
  const env = setup();
  await env.vault.saveKey('user_A', 'acme', KEY);
  assert.deepStrictEqual(env.vault.listKeys('user_B'), []);
  assert.deepStrictEqual(env.vault.useKey('user_B', 'acme', 'chat'), { error: 'key_not_found', status: 404 });
  assert.deepStrictEqual(env.vault.deleteKey('user_B', 'acme'), { deleted: false });
  assert.deepStrictEqual(env.vault.useKey('user_A', 'acme', 'chat'), { key: KEY });
  assert.strictEqual(env.vault.listKeys('user_A').length, 1);
});

/**
 * Decodes base64, XORs 01 into byte 20 and encodes again. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches nothing.
 */
function flipByte20(b64) {
  const raw = Buffer.from(b64, 'base64');
  raw[20] ^= 0x01;
  return raw.toString('base64');
}

/**
 * VAULT-08: a row moved to another user, a row moved to another provider, one changed byte of the DECODED
 * ciphertext and one of the decoded wrapped_dek (decode, XOR 01 into byte 20, encode again), and a stored value
 * that is not base64 or is too short each make use_key answer 500 key_unreadable, never an exception.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: VAULT-08, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the provider client is a fake: no network).
 */
// VAULT-08
test('VAULT-08 moved or damaged rows are 500 key_unreadable, never an exception', async () => {
  const cases = [
    ['moved to another user', s => s.db.prepare("UPDATE provider_keys SET user_id = 'user_2'").run(), 'user_2', 'acme'],
    ['moved to another provider', s => s.db.prepare("UPDATE provider_keys SET provider = 'beta'").run(), 'user_1', 'beta'],
    ['ciphertext byte', s => s.db.prepare('UPDATE provider_keys SET ciphertext = ?').run(flipByte20(s.getRow('user_1', 'acme').ciphertext)), 'user_1', 'acme'],
    ['wrapped_dek byte', s => s.db.prepare('UPDATE provider_keys SET wrapped_dek = ?').run(flipByte20(s.getRow('user_1', 'acme').wrapped_dek)), 'user_1', 'acme'],
    ['ciphertext not base64', s => s.db.prepare("UPDATE provider_keys SET ciphertext = '!!not base64!!'").run(), 'user_1', 'acme'],
    ['wrapped_dek not base64', s => s.db.prepare("UPDATE provider_keys SET wrapped_dek = 'abc'").run(), 'user_1', 'acme'],
    ['ciphertext too short', s => s.db.prepare('UPDATE provider_keys SET ciphertext = ?').run(Buffer.alloc(27, 1).toString('base64')), 'user_1', 'acme'],
    ['wrapped_dek too short', s => s.db.prepare('UPDATE provider_keys SET wrapped_dek = ?').run(Buffer.alloc(12, 1).toString('base64')), 'user_1', 'acme']
  ];
  for (const [name, damage, user, provider] of cases) {
    const env = setup();
    await env.vault.saveKey('user_1', 'acme', KEY);
    damage(env.store);
    assert.deepStrictEqual(env.vault.useKey(user, provider, 'chat'), { error: 'key_unreadable', status: 500 }, name);
  }
});

/**
 * VAULT-09: saving again for the same provider replaces the key: one row, a new DEK and new nonces, the new hint,
 * and use_key returns the new key.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: VAULT-09, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the provider client is a fake: no network).
 */
// VAULT-09
test('VAULT-09 saving again replaces the key: one row, new DEK and nonces, new hint, new key returned', async () => {
  const env = setup();
  await env.vault.saveKey('user_1', 'acme', KEY);
  const first = env.store.getRow('user_1', 'acme');
  env.vault.useKey('user_1', 'acme', 'chat');
  const KEY2 = 'acme_' + 'n3wk3y0123456789abcdefQRST';
  env.clock.t += 7;
  assert.deepStrictEqual(await env.vault.saveKey('user_1', 'acme', KEY2), { provider: 'acme', hint: 'QRST', key_id: 'k1', created_at: env.clock.t });
  const rows = rawRows(env.store);
  assert.strictEqual(rows.length, 1);
  assert.strictEqual(rows[0].hint, 'QRST');
  assert.strictEqual(rows[0].last_used_at, null);
  assert.notStrictEqual(rows[0].wrapped_dek, first.wrapped_dek);
  assert.notStrictEqual(rows[0].ciphertext, first.ciphertext);
  const nonce = b64 => Buffer.from(b64, 'base64').subarray(0, 12).toString('hex');
  assert.notStrictEqual(nonce(rows[0].ciphertext), nonce(first.ciphertext));
  assert.notStrictEqual(nonce(rows[0].wrapped_dek), nonce(first.wrapped_dek));
  const dek = (row, master) => {
    const raw = Buffer.from(row.wrapped_dek, 'base64');
    const d = crypto.createDecipheriv('aes-256-gcm', master, raw.subarray(0, 12), { authTagLength: 16 });
    d.setAAD(Buffer.from('byok:dek:k1:acme:user_1'));
    d.setAuthTag(raw.subarray(raw.length - 16));
    return Buffer.concat([d.update(raw.subarray(12, raw.length - 16)), d.final()]).toString('hex');
  };
  assert.notStrictEqual(dek(rows[0], K1), dek(first, K1));
  assert.deepStrictEqual(env.vault.useKey('user_1', 'acme', 'chat'), { key: KEY2 });
});

/**
 * VAULT-10: rotation: with k2 added and active a new save is wrapped under k2; rewrap() re-wraps the older rows
 * under k2, changes no ciphertext, returns {rewrapped: 1, failed: 0} and, with the injected nonce, stores the
 * spec's string; with k1 then removed from the keyring every key still opens; the store's rewrap write changes no
 * row when the row's wrapped_dek is no longer the one that was read.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: VAULT-10, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the provider client is a fake: no network).
 */
// VAULT-10
test('VAULT-10 rotation: new saves under k2, rewrap moves old rows to k2 with the spec string, k1 can then leave', async () => {
  const store = new SqliteVaultStore();
  const env1 = setup({ store, bytes: [...DEK_BYTES, ...DATA_NONCE, ...WRAP_NONCE] });
  await env1.vault.saveKey('user_1', 'acme', KEY);
  const env2 = setup({ store, masterKeys: { k1: K1, k2: K2 }, activeKeyId: 'k2' });
  const KEYB = 'acme_' + 'userb0123456789abcdefgLMNO';
  assert.strictEqual((await env2.vault.saveKey('user_2', 'acme', KEYB)).key_id, 'k2');
  env2.rnd.push(Array.from({ length: 12 }, (_, i) => 0x80 + i));
  assert.deepStrictEqual(env2.vault.rewrap(), { rewrapped: 1, failed: 0 });
  const row = store.getRow('user_1', 'acme');
  assert.strictEqual(row.key_id, 'k2');
  assert.strictEqual(row.ciphertext, SPEC_CIPHERTEXT);
  assert.strictEqual(row.wrapped_dek, SPEC_REWRAPPED);
  assert.strictEqual(env2.vault.listAudit('user_1').at(-1).action, 'key_rewrapped');
  assert.deepStrictEqual(env2.vault.rewrap(), { rewrapped: 0, failed: 0 });
  const env3 = setup({ store, masterKeys: { k2: K2 }, activeKeyId: 'k2' });
  assert.deepStrictEqual(env3.vault.useKey('user_1', 'acme', 'chat'), { key: KEY });
  assert.deepStrictEqual(env3.vault.useKey('user_2', 'acme', 'chat'), { key: KEYB });
  // The store's rewrap write changes no row when the wrapped_dek read is stale.
  assert.strictEqual(store.rewrapRow('user_1', 'acme', 'k1', 'xxxx', SPEC_WRAPPED, 1), 0);
  assert.strictEqual(store.getRow('user_1', 'acme').wrapped_dek, SPEC_REWRAPPED);
  // A row whose master key is gone counts as failed and is left unchanged.
  const env4 = setup({ store: new SqliteVaultStore() });
  await env4.vault.saveKey('user_1', 'acme', KEY);
  const env5 = setup({ store: env4.store, masterKeys: { k2: K2 }, activeKeyId: 'k2' });
  assert.deepStrictEqual(env5.vault.rewrap(), { rewrapped: 0, failed: 1 });
  assert.strictEqual(env4.store.getRow('user_1', 'acme').key_id, 'k1');
});

/**
 * VAULT-11: a row whose key_id is not in the keyring is 503 key_unavailable; a master key that is not 32 bytes, or
 * an active_key_id that is not in the keyring, fails construction; a provider whose min_length is under its
 * prefix's length + 16 fails construction with invalid_provider_config.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: VAULT-11, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the provider client is a fake: no network).
 */
// VAULT-11
test('VAULT-11 unknown key_id is 503; bad master keys and provider configs fail construction', async () => {
  const env = setup();
  await env.vault.saveKey('user_1', 'acme', KEY);
  const other = setup({ store: env.store, masterKeys: { k2: K2 }, activeKeyId: 'k2' });
  assert.deepStrictEqual(other.vault.useKey('user_1', 'acme', 'chat'), { error: 'key_unavailable', status: 503 });
  const base = { providers: PROVIDERS, providerClient: fakeClient() };
  const isCode = code => err => err instanceof VaultError && err.code === code;
  assert.throws(() => createKeyVault({ ...base, masterKeys: { k1: Buffer.alloc(31) }, activeKeyId: 'k1' }), isCode('invalid_master_key'));
  assert.throws(() => createKeyVault({ ...base, masterKeys: { k1: Buffer.alloc(33) }, activeKeyId: 'k1' }), isCode('invalid_master_key'));
  assert.throws(() => createKeyVault({ ...base, masterKeys: { k1: K1 }, activeKeyId: 'k2' }), isCode('invalid_master_key'));
  assert.throws(() => createKeyVault({ ...base, masterKeys: { 'bad id!': K1 }, activeKeyId: 'bad id!' }), isCode('invalid_master_key'));
  assert.throws(() => createKeyVault({
    masterKeys: { k1: K1 }, activeKeyId: 'k1', providerClient: fakeClient(),
    providers: { acme: { prefix: 'acme_', min_length: 20, max_length: 200 } }
  }), isCode('invalid_provider_config'));
  assert.ok(createKeyVault({
    masterKeys: { k1: K1 }, activeKeyId: 'k1', providerClient: fakeClient(),
    providers: { acme: { prefix: 'acme_', min_length: 21, max_length: 200 } }
  }));
});

/**
 * VAULT-12: at most 10 provider checks per user per clock hour: the 11th save_key is 429 rate_limited with
 * retry_after and calls no provider; another user is not affected; in the next hour it works again; a malformed
 * key does not count; the store's window write succeeds 10 times in one hour and not an 11th.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: VAULT-12, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the provider client is a fake: no network).
 */
// VAULT-12
test('VAULT-12 at most 10 provider checks per user per clock hour', async () => {
  const env = setup({ start: HOUR });
  for (let i = 0; i < 10; i++) {
    env.clock.t = HOUR + i;
    assert.strictEqual((await env.vault.saveKey('user_1', 'acme', KEY)).hint, 'WXYZ');
  }
  // A malformed key does not count, and is refused as malformed even when the window is full.
  assert.deepStrictEqual(await env.vault.saveKey('user_1', 'acme', 'acme_x'), { error: 'invalid_key_format', status: 400 });
  env.clock.t = HOUR + 600;
  const calls = env.client.calls.length;
  assert.deepStrictEqual(await env.vault.saveKey('user_1', 'acme', KEY), { error: 'rate_limited', status: 429, retry_after: 3000 });
  assert.strictEqual(env.client.calls.length, calls);
  assert.strictEqual((await env.vault.saveKey('user_2', 'acme', KEY)).hint, 'WXYZ');
  env.clock.t = HOUR + 3600;
  assert.strictEqual((await env.vault.saveKey('user_1', 'acme', KEY)).hint, 'WXYZ');
  // A malformed key in a fresh window adds nothing to the count.
  const env2 = setup({ start: HOUR });
  await env2.vault.saveKey('user_1', 'acme', 'nope');
  assert.strictEqual(env2.store.windowCount('user_1', HOUR), 0);
  // The store's window write: 10 times in one hour, not an 11th.
  const store = new SqliteVaultStore();
  for (let i = 0; i < 10; i++) assert.strictEqual(store.countCheck('u', HOUR), true);
  assert.strictEqual(store.countCheck('u', HOUR), false);
  assert.strictEqual(store.windowCount('u', HOUR), 10);
  assert.strictEqual(store.countCheck('u', HOUR + 3600), true);
});

/**
 * VAULT-13: delete_key removes the row and writes key_deleted; a second delete is {deleted: false} with no audit
 * row; use_key is then 404 key_not_found.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: VAULT-13, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the provider client is a fake: no network).
 */
// VAULT-13
test('VAULT-13 delete_key removes the row and audits once; a second delete is false; use_key then 404', async () => {
  const env = setup();
  await env.vault.saveKey('user_1', 'acme', KEY);
  env.clock.t += 3;
  assert.deepStrictEqual(env.vault.deleteKey('user_1', 'acme'), { deleted: true });
  assert.strictEqual(rawRows(env.store).length, 0);
  assert.deepStrictEqual(env.vault.listAudit('user_1').map(a => a.action), ['key_saved', 'key_deleted']);
  assert.deepStrictEqual(env.vault.listAudit('user_1')[1], { at: env.clock.t, action: 'key_deleted', provider: 'acme', purpose: null, key_id: 'k1' });
  assert.deepStrictEqual(env.vault.deleteKey('user_1', 'acme'), { deleted: false });
  assert.strictEqual(env.vault.listAudit('user_1').length, 2);
  assert.deepStrictEqual(env.vault.useKey('user_1', 'acme', 'chat'), { error: 'key_not_found', status: 404 });
});

/**
 * VAULT-13, a failing store: when the key_deleted audit write fails, deleteKey returns 500 storage_failed (not an
 * exception), the row stays (the transaction rolled back) and no key_deleted row exists; a later delete on a working
 * store succeeds.
 * In: none. Out: assertions. Why: VAULT-13, spec CONVENTIONS; review finding 4525101278.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: an in-memory SQLite database only.
 */
// VAULT-13
test('VAULT-13 delete_key with a failing store answers 500 storage_failed and keeps the row', async () => {
  /** A store whose key_deleted audit write fails. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  class FailingDeleteStore extends SqliteVaultStore {
    /** Throws for key_deleted rows while `failing`, else writes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    insertAudit(a) {
      if (this.failing && a.action === 'key_deleted') throw new Error('disk full');
      super.insertAudit(a);
    }
  }
  const store = new FailingDeleteStore();
  const env = setup({ store });
  await env.vault.saveKey('user_1', 'acme', KEY);
  store.failing = true;
  assert.deepStrictEqual(env.vault.deleteKey('user_1', 'acme'), { error: 'storage_failed', status: 500 });
  assert.strictEqual(rawRows(store).length, 1);
  assert.deepStrictEqual(env.vault.listAudit('user_1').map(a => a.action), ['key_saved']);
  store.failing = false;
  assert.deepStrictEqual(env.vault.deleteKey('user_1', 'acme'), { deleted: true });
});

/**
 * VAULT-10, a failing rewrap write: with two rows under k1 and the store's write failing for the first one, rewrap()
 * returns {rewrapped: 1, failed: 1}: the failure is counted, the first row is unchanged and the run still re-wraps
 * the second row (it does not stop at the first failure).
 * In: none. Out: assertions. Why: VAULT-10; review finding 4525101278. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: an in-memory SQLite database only.
 */
// VAULT-10
test('VAULT-10 rewrap counts a failed store write in failed and goes on with the next row', async () => {
  /** A store whose rewrap write fails for user_1. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
  class FailingRewrapStore extends SqliteVaultStore {
    /** Throws for user_1, else writes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database. */
    rewrapRow(userId, ...rest) {
      if (userId === 'user_1') throw new Error('disk full');
      return super.rewrapRow(userId, ...rest);
    }
  }
  const store = new FailingRewrapStore();
  const env1 = setup({ store });
  await env1.vault.saveKey('user_1', 'acme', KEY);
  await env1.vault.saveKey('user_2', 'acme', KEY);
  const before = store.getRow('user_1', 'acme');
  const env2 = setup({ store, masterKeys: { k1: K1, k2: K2 }, activeKeyId: 'k2' });
  assert.deepStrictEqual(env2.vault.rewrap(), { rewrapped: 1, failed: 1 });
  assert.deepStrictEqual(store.getRow('user_1', 'acme'), before);
  assert.strictEqual(store.getRow('user_2', 'acme').key_id, 'k2');
});

/**
 * VAULT-14: with real randomness, the same key saved for two users gives different ciphertext, different
 * wrapped_dek and different nonces.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: VAULT-14, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: an in-memory SQLite database only (the provider client is a fake: no network).
 */
// VAULT-14
test('VAULT-14 with real randomness two users\' copies of one key differ in ciphertext, wrapped_dek and nonces', async () => {
  const env = setup({ realRandom: true });
  await env.vault.saveKey('user_1', 'acme', KEY);
  await env.vault.saveKey('user_2', 'acme', KEY);
  const [a, b] = rawRows(env.store);
  assert.notStrictEqual(a.ciphertext, b.ciphertext);
  assert.notStrictEqual(a.wrapped_dek, b.wrapped_dek);
  const nonce = b64 => Buffer.from(b64, 'base64').subarray(0, 12).toString('hex');
  assert.notStrictEqual(nonce(a.ciphertext), nonce(b.ciphertext));
  assert.notStrictEqual(nonce(a.wrapped_dek), nonce(b.wrapped_dek));
  assert.notStrictEqual(nonce(a.ciphertext), nonce(a.wrapped_dek));
  assert.deepStrictEqual(env.vault.useKey('user_1', 'acme', 'chat'), { key: KEY });
  assert.deepStrictEqual(env.vault.useKey('user_2', 'acme', 'chat'), { key: KEY });
});

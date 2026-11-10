const test = require('node:test');
const assert = require('node:assert');
const {
  FeatureFlagClient,
  InMemoryFlagStore,
  SqlFlagStore,
  FeatureFlagError,
  stableBucket,
  SCHEMA_STATEMENTS
} = require('./feature_flags_javascript.js');

const RJ_ON = `[{"conditions":[],"variant":"on","value":true,"rollout":null}]`;
const RJ_ACME = `[{"conditions":[{"attribute":"email","operator":"ends_with","value":"@acme.com"}],"variant":"on","value":true,"rollout":null}]`;
const RJ_30 = `[{"conditions":[],"variant":"beta","value":true,"rollout":{"percentage":30}}]`;
const RJ_CHECKOUT = `[{"conditions":[],"variant":"beta","value":"new","rollout":{"percentage":30}},{"conditions":[{"attribute":"tier","operator":"equals","value":"pro"}],"variant":"pro","value":"pro-ui","rollout":null}]`;

function assertDetails(d, value, reason, variant, errorCode) {
  assert.strictEqual(d.value, value);
  assert.strictEqual(d.reason, reason);
  assert.strictEqual(d.variant, variant);
  assert.strictEqual(d.error_code, errorCode);
  assert.strictEqual(d.flag_key, d.flag_key);
}

// FLAG-01
test('S1 unknown_flag_returns_default', () => {
  const store = new InMemoryFlagStore();
  const client = new FeatureFlagClient(store);
  
  const d1 = client.getBooleanDetails('missing_flag', true, { targeting_key: 'alice' });
  assertDetails(d1, true, 'ERROR', null, 'FLAG_NOT_FOUND');
  
  const v1 = client.getStringValue('missing_flag', 'fallback', null);
  assert.strictEqual(v1, 'fallback');
});

// FLAG-02
test('S2 string_method_on_boolean_flag_is_type_mismatch', () => {
  const store = new InMemoryFlagStore();
  const client = new FeatureFlagClient(store, { clock: () => 1767225600 });
  
  client.setFlag('admin', 'bool_flag', 'boolean', 'true', true, '[]');
  
  const d1 = client.getStringDetails('bool_flag', 'fallback', {});
  assertDetails(d1, 'fallback', 'ERROR', null, 'TYPE_MISMATCH');
  
  const d2 = client.getBooleanDetails('bool_flag', false, {});
  assertDetails(d2, true, 'DEFAULT', null, null);
  
  const v1 = client.getNumberValue('bool_flag', 7, {});
  assert.strictEqual(v1, 7);
  
  client.setFlag('admin', 'bool_flag', 'boolean', 'true', false, '[]');
  
  const d3 = client.getStringDetails('bool_flag', 'fallback', {});
  assertDetails(d3, 'fallback', 'ERROR', null, 'TYPE_MISMATCH');
});

// FLAG-03
test('S3 disabled_flag_returns_caller_default', () => {
  const store = new InMemoryFlagStore();
  const client = new FeatureFlagClient(store, { clock: () => 1767225600 });
  
  client.setFlag('admin', 'off_flag', 'boolean', 'true', false, RJ_ON);
  
  const d1 = client.getBooleanDetails('off_flag', false, { targeting_key: 'alice' });
  assertDetails(d1, false, 'DISABLED', null, null);
  
  client.setFlag('admin', 'off_flag', 'boolean', 'true', true, RJ_ON);
  
  const d2 = client.getBooleanDetails('off_flag', false, { targeting_key: 'alice' });
  assertDetails(d2, true, 'TARGETING_MATCH', 'on', null);
  
  client.setFlag('admin', 'limit', 'number', '5', true, '[]');
  
  const v1 = client.getNumberValue('limit', 1, {});
  assert.strictEqual(v1, 5);
  
  client.setFlag('admin', 'limit', 'number', '5', false, '[]');
  
  const v2 = client.getNumberValue('limit', 1, {});
  assert.strictEqual(v2, 1);
});

// FLAG-04
test('S4 matching_rule_and_non_matching_rule', () => {
  const store = new InMemoryFlagStore();
  const client = new FeatureFlagClient(store, { clock: () => 1767225600 });
  
  client.setFlag('admin', 'acme_beta', 'boolean', 'false', true, RJ_ACME);
  
  const d1 = client.getBooleanDetails('acme_beta', false, { email: 'dev@acme.com' });
  assertDetails(d1, true, 'TARGETING_MATCH', 'on', null);
  
  const d2 = client.getBooleanDetails('acme_beta', true, { email: 'dev@other.com' });
  assertDetails(d2, false, 'DEFAULT', null, null);
  
  const d3 = client.getBooleanDetails('acme_beta', false, {});
  assertDetails(d3, false, 'DEFAULT', null, null);
});

// FLAG-05
test('S5 rollout_30_percent_deterministic_and_distributed', () => {
  const store = new InMemoryFlagStore();
  const client = new FeatureFlagClient(store, { clock: () => 1767225600 });
  
  client.setFlag('admin', 'rollout30', 'boolean', 'false', true, RJ_30);
  
  let count = 0;
  for (let i = 0; i < 10000; i++) {
    if (client.getBooleanValue('rollout30', false, { targeting_key: 'user-' + i })) {
      count++;
    }
  }
  assert.strictEqual(count, 2966);
  assert.ok(count >= 2500 && count <= 3500);
  
  const results = [];
  for (let i = 0; i < 5; i++) {
    results.push(client.getBooleanValue('rollout30', false, { targeting_key: 'user-42' }));
  }
  assert.ok(results.every(r => r === results[0]));
  
  const d1 = client.getBooleanDetails('rollout30', false, { targeting_key: 'user-135' });
  assertDetails(d1, true, 'SPLIT', 'beta', null);
  
  const d2 = client.getBooleanDetails('rollout30', false, { targeting_key: 'user-26' });
  assertDetails(d2, false, 'DEFAULT', null, null);
});

// FLAG-06
test('S6 user_outside_rollout_falls_through', () => {
  const store = new InMemoryFlagStore();
  const client = new FeatureFlagClient(store, { clock: () => 1767225600 });
  
  client.setFlag('admin', 'checkout_ui', 'string', '"classic"', true, RJ_CHECKOUT);
  
  const d1 = client.getStringDetails('checkout_ui', 'fallback', { targeting_key: 'bob', tier: 'pro' });
  assertDetails(d1, 'new', 'SPLIT', 'beta', null);
  
  const d2 = client.getStringDetails('checkout_ui', 'fallback', { targeting_key: 'carol', tier: 'pro' });
  assertDetails(d2, 'pro-ui', 'TARGETING_MATCH', 'pro', null);
  
  const d3 = client.getStringDetails('checkout_ui', 'fallback', { targeting_key: 'carol', tier: 'free' });
  assertDetails(d3, 'classic', 'DEFAULT', null, null);
  
  const d4 = client.getStringDetails('checkout_ui', 'fallback', { targeting_key: 'alice' });
  assertDetails(d4, 'classic', 'DEFAULT', null, null);
});

// FLAG-07
test('S7 corrupt_rules_returns_parse_error', () => {
  const badRules = [
    `[{"conditions": [`,
    `{"conditions":[]}`,
    `[{"conditions":[{"attribute":"email","operator":"starts_with","value":"@acme.com"}],"variant":"on","value":true,"rollout":null}]`,
    `[{"conditions":[],"variant":"beta","value":true,"rollout":{"percentage":101}}]`,
    `[{"conditions":[],"variant":"beta","value":true,"rollout":{"percentage":"30"}}]`,
    `[{"conditions":[],"variant":"on","value":true,"rollout":null},{"conditions":"oops"}]`,
    `NaN`,
    ``
  ];
  
  for (const bad of badRules) {
    const store = new InMemoryFlagStore();
    store.putFlag({
      key: 'corrupt_flag',
      type: 'boolean',
      default_value_json: 'true',
      enabled: true,
      rules_json: bad,
      updated_at: 1767225600,
      updated_by: 'import'
    });
    const client = new FeatureFlagClient(store);
    
    const d = client.getBooleanDetails('corrupt_flag', false, { targeting_key: 'alice' });
    assertDetails(d, false, 'ERROR', null, 'PARSE_ERROR');
  }
  
  const store2 = new InMemoryFlagStore();
  const client2 = new FeatureFlagClient(store2, { clock: () => 1767225600 });
  
  assert.throws(() => {
    client2.setFlag('admin', 'new_flag', 'boolean', 'false', true, `[{"conditions": [`);
  }, (err) => {
    assert.ok(err instanceof FeatureFlagError);
    assert.strictEqual(err.code, 'INVALID_RULES');
    assert.strictEqual(err.status, 400);
    return true;
  });
  
  const audits = store2.listAudit('new_flag');
  assert.strictEqual(audits.length, 0);
});

// FLAG-08
test('S8 set_flag_writes_audit_rows', () => {
  let clockVal = 1767225600;
  const store = new InMemoryFlagStore();
  const client = new FeatureFlagClient(store, { clock: () => clockVal });
  
  const e1 = client.setFlag('alice-admin', 'audit_flag', 'boolean', 'false', true, '[]');
  assert.strictEqual(e1.id, 1);
  assert.strictEqual(e1.flag_key, 'audit_flag');
  assert.strictEqual(e1.action, 'create');
  assert.strictEqual(e1.old_value, null);
  assert.strictEqual(e1.new_value, '{"type":"boolean","default_value":false,"enabled":true,"rules":[]}');
  assert.strictEqual(e1.actor_id, 'alice-admin');
  assert.strictEqual(e1.at, 1767225600);
  
  clockVal = 1767225660;
  const e2 = client.setFlag('bob-admin', 'audit_flag', 'boolean', 'true', false, '[]');
  assert.strictEqual(e2.id, 2);
  assert.strictEqual(e2.action, 'update');
  assert.strictEqual(e2.old_value, e1.new_value);
  assert.strictEqual(e2.new_value, '{"type":"boolean","default_value":true,"enabled":false,"rules":[]}');
  assert.strictEqual(e2.actor_id, 'bob-admin');
  assert.strictEqual(e2.at, 1767225660);
  
  const audits = store.listAudit('audit_flag');
  assert.strictEqual(audits.length, 2);
  assert.strictEqual(audits[0].id, 1);
  assert.strictEqual(audits[1].id, 2);
  assert.strictEqual(audits[0].new_value, audits[1].old_value);
  
  const otherAudits = store.listAudit('other');
  assert.strictEqual(otherAudits.length, 0);
  
  const flag = store.getFlag('audit_flag');
  assert.strictEqual(flag.updated_at, 1767225660);
  assert.strictEqual(flag.updated_by, 'bob-admin');
});

test('X1 bucket_vectors', () => {
  assert.strictEqual(stableBucket('checkout_ui', 'carol'), 94);
  assert.strictEqual(stableBucket('checkout_ui', 'bob'), 18);
  assert.strictEqual(stableBucket('checkout_ui', 'alice'), 88);
  assert.strictEqual(stableBucket('checkout_ui', 'jos\u00e9'), 45);
  assert.strictEqual(stableBucket('rollout30', 'user-0'), 24);
  assert.strictEqual(stableBucket('rollout30', 'user-3'), 98);
  assert.strictEqual(stableBucket('rollout30', 'user-26'), 30);
  assert.strictEqual(stableBucket('rollout30', 'user-135'), 29);
});

test('X2 rollout_boundaries', () => {
  const store = new InMemoryFlagStore();
  const client = new FeatureFlagClient(store, { clock: () => 1767225600 });
  
  client.setFlag('admin', 'pct_zero', 'boolean', 'false', true, `[{"conditions":[],"variant":"beta","value":true,"rollout":{"percentage":0}}]`);
  for (let i = 0; i < 100; i++) {
    const d = client.getBooleanDetails('pct_zero', false, { targeting_key: 'user-' + i });
    assertDetails(d, false, 'DEFAULT', null, null);
  }
  
  client.setFlag('admin', 'pct_hundred', 'boolean', 'false', true, `[{"conditions":[],"variant":"beta","value":true,"rollout":{"percentage":100}}]`);
  for (let i = 0; i < 100; i++) {
    const d = client.getBooleanDetails('pct_hundred', false, { targeting_key: 'user-' + i });
    assertDetails(d, true, 'SPLIT', 'beta', null);
  }
  
  const d1 = client.getBooleanDetails('pct_hundred', false, {});
  assertDetails(d1, false, 'DEFAULT', null, null);
  
  const d2 = client.getBooleanDetails('pct_hundred', false, { targeting_key: '' });
  assertDetails(d2, false, 'DEFAULT', null, null);
  
  const d3 = client.getBooleanDetails('pct_hundred', false, { targeting_key: 42 });
  assertDetails(d3, false, 'DEFAULT', null, null);
  
  client.setFlag('admin', 'rollout30', 'string', '"control"', true, 
    `[{"conditions":[],"variant":"a","value":"a","rollout":{"percentage":30}},{"conditions":[],"variant":"b","value":"b","rollout":{"percentage":60}}]`);
  
  const d4 = client.getStringDetails('rollout30', 'fallback', { targeting_key: 'user-135' });
  assertDetails(d4, 'a', 'SPLIT', 'a', null);
  
  const d5 = client.getStringDetails('rollout30', 'fallback', { targeting_key: 'user-26' });
  assertDetails(d5, 'b', 'SPLIT', 'b', null);
  
  const d6 = client.getStringDetails('rollout30', 'fallback', { targeting_key: 'user-3' });
  assertDetails(d6, 'control', 'DEFAULT', null, null);
});

test('X3 operators_each_isolated', () => {
  const store = new InMemoryFlagStore();
  const client = new FeatureFlagClient(store, { clock: () => 1767225600 });
  
  client.setFlag('admin', 'eq_flag', 'boolean', 'false', true, 
    `[{"conditions":[{"attribute":"tier","operator":"equals","value":"pro"}],"variant":"hit","value":true,"rollout":null}]`);
  assertDetails(client.getBooleanDetails('eq_flag', false, { tier: 'pro' }), true, 'TARGETING_MATCH', 'hit', null);
  assertDetails(client.getBooleanDetails('eq_flag', false, { tier: 'PRO' }), false, 'DEFAULT', null, null);
  assertDetails(client.getBooleanDetails('eq_flag', false, {}), false, 'DEFAULT', null, null);
  
  client.setFlag('admin', 'ne_flag', 'boolean', 'false', true,
    `[{"conditions":[{"attribute":"tier","operator":"not_equals","value":"free"}],"variant":"hit","value":true,"rollout":null}]`);
  assertDetails(client.getBooleanDetails('ne_flag', false, { tier: 'pro' }), true, 'TARGETING_MATCH', 'hit', null);
  assertDetails(client.getBooleanDetails('ne_flag', false, { tier: 'free' }), false, 'DEFAULT', null, null);
  assertDetails(client.getBooleanDetails('ne_flag', false, {}), false, 'DEFAULT', null, null);
  assertDetails(client.getBooleanDetails('ne_flag', false, { tier: null }), false, 'DEFAULT', null, null);
  
  client.setFlag('admin', 'in_flag', 'boolean', 'false', true,
    `[{"conditions":[{"attribute":"org_id","operator":"in_list","value":["org-1","org-2"]}],"variant":"hit","value":true,"rollout":null}]`);
  assertDetails(client.getBooleanDetails('in_flag', false, { org_id: 'org-2' }), true, 'TARGETING_MATCH', 'hit', null);
  assertDetails(client.getBooleanDetails('in_flag', false, { org_id: 'org-3' }), false, 'DEFAULT', null, null);
  
  client.setFlag('admin', 'ew_flag', 'boolean', 'false', true,
    `[{"conditions":[{"attribute":"email","operator":"ends_with","value":"@acme.com"}],"variant":"hit","value":true,"rollout":null}]`);
  assertDetails(client.getBooleanDetails('ew_flag', false, { email: 'ceo@acme.com' }), true, 'TARGETING_MATCH', 'hit', null);
  assertDetails(client.getBooleanDetails('ew_flag', false, { email: 'ceo@acme.com.evil.io' }), false, 'DEFAULT', null, null);
  assertDetails(client.getBooleanDetails('ew_flag', false, { email: 'CEO@ACME.COM' }), false, 'DEFAULT', null, null);
  
  client.setFlag('admin', 'num_eq_flag', 'boolean', 'false', true,
    `[{"conditions":[{"attribute":"seats","operator":"equals","value":3}],"variant":"hit","value":true,"rollout":null}]`);
  assertDetails(client.getBooleanDetails('num_eq_flag', false, { seats: 3 }), true, 'TARGETING_MATCH', 'hit', null);
  assertDetails(client.getBooleanDetails('num_eq_flag', false, { seats: 3.0 }), true, 'TARGETING_MATCH', 'hit', null);
  assertDetails(client.getBooleanDetails('num_eq_flag', false, { seats: '3' }), false, 'DEFAULT', null, null);
  assertDetails(client.getBooleanDetails('num_eq_flag', false, { seats: true }), false, 'DEFAULT', null, null);
  
  client.setFlag('admin', 'bool_eq_flag', 'boolean', 'false', true,
    `[{"conditions":[{"attribute":"beta","operator":"equals","value":true}],"variant":"hit","value":true,"rollout":null}]`);
  assertDetails(client.getBooleanDetails('bool_eq_flag', false, { beta: true }), true, 'TARGETING_MATCH', 'hit', null);
  assertDetails(client.getBooleanDetails('bool_eq_flag', false, { beta: 1 }), false, 'DEFAULT', null, null);
  assertDetails(client.getBooleanDetails('bool_eq_flag', false, { beta: 'true' }), false, 'DEFAULT', null, null);
});

test('X4 served_value_type_mismatch', () => {
  const store = new InMemoryFlagStore();
  const client = new FeatureFlagClient(store, { clock: () => 1767225600 });
  
  store.putFlag({
    key: 'bad_serve',
    type: 'boolean',
    default_value_json: 'false',
    enabled: true,
    rules_json: `[{"conditions":[],"variant":"bad","value":"yes","rollout":null}]`,
    updated_at: 1767225600,
    updated_by: 'import'
  });
  
  const d1 = client.getBooleanDetails('bad_serve', true, { targeting_key: 'alice' });
  assertDetails(d1, true, 'ERROR', null, 'TYPE_MISMATCH');
  
  store.putFlag({
    key: 'bad_default',
    type: 'boolean',
    default_value_json: '"oops"',
    enabled: true,
    rules_json: '[]',
    updated_at: 1767225600,
    updated_by: 'import'
  });
  
  const d2 = client.getBooleanDetails('bad_default', true, {});
  assertDetails(d2, true, 'ERROR', null, 'TYPE_MISMATCH');
  
  store.putFlag({
    key: 'bad_parse',
    type: 'boolean',
    default_value_json: 'nope',
    enabled: true,
    rules_json: '[]',
    updated_at: 1767225600,
    updated_by: 'import'
  });
  
  const d3 = client.getBooleanDetails('bad_parse', true, {});
  assertDetails(d3, true, 'ERROR', null, 'PARSE_ERROR');
  
  assert.throws(() => {
    client.setFlag('admin', 'valid_key', 'boolean', 'false', true, `[{"conditions":[],"variant":"bad","value":"yes","rollout":null}]`);
  }, (err) => {
    assert.ok(err instanceof FeatureFlagError);
    assert.strictEqual(err.code, 'INVALID_RULES');
    assert.strictEqual(err.status, 400);
    return true;
  });
});

test('X5 set_flag_validation_and_repair', () => {
  const store = new InMemoryFlagStore();
  const client = new FeatureFlagClient(store, { clock: () => 1767225600 });
  
  assert.throws(() => client.setFlag('', 'valid_key', 'boolean', 'false', true, '[]'), (err) => err.code === 'INVALID_ACTOR' && err.status === 400);
  assert.throws(() => client.setFlag('admin', 'bad:key', 'boolean', 'false', true, '[]'), (err) => err.code === 'INVALID_KEY' && err.status === 400);
  assert.throws(() => client.setFlag('admin', '', 'boolean', 'false', true, '[]'), (err) => err.code === 'INVALID_KEY' && err.status === 400);
  assert.throws(() => client.setFlag('admin', 'a'.repeat(129), 'boolean', 'false', true, '[]'), (err) => err.code === 'INVALID_KEY' && err.status === 400);
  assert.throws(() => client.setFlag('admin', 'valid_key', 'json', 'false', true, '[]'), (err) => err.code === 'INVALID_TYPE' && err.status === 400);
  assert.throws(() => client.setFlag('admin', 'valid_key', 'boolean', '"yes"', true, '[]'), (err) => err.code === 'INVALID_DEFAULT_VALUE' && err.status === 400);
  assert.throws(() => client.setFlag('admin', 'valid_key', 'number', 'NaN', true, '[]'), (err) => err.code === 'INVALID_DEFAULT_VALUE' && err.status === 400);
  assert.throws(() => client.setFlag('admin', 'valid_key', 'number', '1e999', true, '[]'), (err) => err.code === 'INVALID_DEFAULT_VALUE' && err.status === 400);
  assert.throws(() => client.setFlag('admin', 'valid_key', 'object', '[]', true, '[]'), (err) => err.code === 'INVALID_DEFAULT_VALUE' && err.status === 400);
  
  assert.strictEqual(store.listAudit('valid_key').length, 0);
  
  store.putFlag({
    key: 'repair_me',
    type: 'boolean',
    default_value_json: 'true',
    enabled: true,
    rules_json: `[{"conditions": [`,
    updated_at: 1767225600,
    updated_by: 'import'
  });
  
  const e = client.setFlag('fixer', 'repair_me', 'boolean', 'true', true, '[]');
  assert.strictEqual(e.action, 'update');
  assert.strictEqual(e.old_value, '{"type":"boolean","default_value":true,"enabled":true,"rules":[{"conditions": [}');
  
  const d = client.getBooleanDetails('repair_me', false, {});
  assertDetails(d, true, 'DEFAULT', null, null);
});

test('X6 store_failure_is_general', () => {
  class FailingStore {
    getFlag(key) { throw new Error('store down'); }
    putFlag(record) { throw new Error('store down'); }
    saveFlagAudited(record, actorId, at) { throw new Error('store down'); }
    listAudit(flagKey) { return []; }
  }
  
  const store = new FailingStore();
  const client = new FeatureFlagClient(store);
  
  const d1 = client.getBooleanDetails('any', true, {});
  assertDetails(d1, true, 'ERROR', null, 'GENERAL');
  
  assert.throws(() => {
    client.setFlag('admin', 'any', 'boolean', 'false', true, '[]');
  }, (err) => {
    assert.ok(err instanceof FeatureFlagError);
    assert.strictEqual(err.code, 'STORE_ERROR');
    assert.strictEqual(err.status, 500);
    return true;
  });
});

test('X7 sql_store_round_trip', () => {
  const { DatabaseSync } = require('node:sqlite');
  const db = new DatabaseSync(':memory:');
  const store = new SqlFlagStore(db);
  const client = new FeatureFlagClient(store, { clock: () => 1767225600 });
  
  const e1 = client.setFlag('alice-admin', 'audit_flag', 'boolean', 'false', true, '[]');
  assert.strictEqual(e1.id, 1);
  assert.strictEqual(e1.action, 'create');
  assert.strictEqual(e1.new_value, '{"type":"boolean","default_value":false,"enabled":true,"rules":[]}');
  
  const e2 = client.setFlag('bob-admin', 'audit_flag', 'boolean', 'true', false, '[]');
  assert.strictEqual(e2.id, 2);
  assert.strictEqual(e2.action, 'update');
  assert.strictEqual(e2.old_value, e1.new_value);
  
  const audits = store.listAudit('audit_flag');
  assert.strictEqual(audits.length, 2);
  
  const flag = store.getFlag('audit_flag');
  assert.strictEqual(flag.enabled, false);
  assert.strictEqual(typeof flag.enabled, 'boolean');
  
  client.setFlag('admin', 'checkout_ui', 'string', '"classic"', true, RJ_CHECKOUT);
  const d1 = client.getStringDetails('checkout_ui', 'fallback', { targeting_key: 'bob', tier: 'pro' });
  assertDetails(d1, 'new', 'SPLIT', 'beta', null);
  
  const d2 = client.getStringDetails('checkout_ui', 'fallback', { targeting_key: 'carol', tier: 'pro' });
  assertDetails(d2, 'pro-ui', 'TARGETING_MATCH', 'pro', null);
});
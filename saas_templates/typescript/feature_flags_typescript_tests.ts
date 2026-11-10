import { FeatureFlags, InMemoryFlagStore } from './feature_flags_typescript.ts';
import * as assert from 'assert';
import { test } from 'node:test';

// FLAG-01
test('unknown flag returns default with FLAG_NOT_FOUND', () => {
  const flags = new FeatureFlags();
  const result = flags.get_boolean_details('nonexistent', false, {});
  assert.strictEqual(result.value, false);
  assert.strictEqual(result.reason, 'ERROR');
  assert.strictEqual(result.error_code, 'FLAG_NOT_FOUND');
});

// FLAG-02
test('type mismatch returns default with TYPE_MISMATCH', () => {
  const flags = new FeatureFlags();
  flags.set_flag('admin', 'test_flag', 'boolean', true, true, []);
  const result = flags.get_string_details('test_flag', 'default', {});
  assert.strictEqual(result.value, 'default');
  assert.strictEqual(result.reason, 'ERROR');
  assert.strictEqual(result.error_code, 'TYPE_MISMATCH');
});

// FLAG-03
test('disabled flag returns default with DISABLED', () => {
  const flags = new FeatureFlags();
  flags.set_flag('admin', 'disabled_flag', 'boolean', true, false, []);
  const result = flags.get_boolean_details('disabled_flag', false, {});
  assert.strictEqual(result.value, false);
  assert.strictEqual(result.reason, 'DISABLED');
});

// FLAG-04
test('matching rule returns value with TARGETING_MATCH', () => {
  const flags = new FeatureFlags();
  const rules = [
    {
      conditions: [{ attribute: 'email', operator: 'ends_with', value: '@acme.com' }],
      variant: 'on',
      value: true,
      rollout: null
    }
  ];
  flags.set_flag('admin', 'email_flag', 'boolean', false, true, rules);
  const result = flags.get_boolean_details('email_flag', false, { email: 'user@acme.com' });
  assert.strictEqual(result.value, true);
  assert.strictEqual(result.variant, 'on');
  assert.strictEqual(result.reason, 'TARGETING_MATCH');
});

// FLAG-04
test('non-matching rule falls through to default', () => {
  const flags = new FeatureFlags();
  const rules = [
    {
      conditions: [{ attribute: 'email', operator: 'ends_with', value: '@acme.com' }],
      variant: 'on',
      value: true,
      rollout: null
    }
  ];
  flags.set_flag('admin', 'email_flag', 'boolean', false, true, rules);
  const result = flags.get_boolean_details('email_flag', false, { email: 'user@example.com' });
  assert.strictEqual(result.value, false);
  assert.strictEqual(result.reason, 'DEFAULT');
});

// FLAG-05
test('30% rollout is deterministic and within range', () => {
  const flags = new FeatureFlags();
  const rules = [
    {
      conditions: [],
      variant: 'beta',
      value: true,
      rollout: { percentage: 30 }
    }
  ];
  flags.set_flag('admin', 'rollout_flag', 'boolean', false, true, rules);

  const context1 = { targeting_key: 'user1' };
  const result1 = flags.get_boolean_details('rollout_flag', false, context1);
  const result2 = flags.get_boolean_details('rollout_flag', false, context1);
  assert.strictEqual(result1.value, result2.value);
  assert.strictEqual(result1.reason, result2.reason);

  let trueCount = 0;
  for (let i = 0; i < 10000; i++) {
    const context = { targeting_key: `user${i}` };
    const result = flags.get_boolean_details('rollout_flag', false, context);
    if (result.value === true) {
      trueCount++;
    }
  }
  const percentage = (trueCount / 10000) * 100;
  assert.ok(percentage >= 25 && percentage <= 35, `Rollout percentage ${percentage}% is outside expected range [25%, 35%]`);
});

// FLAG-06
test('user outside rollout falls through to next rule', () => {
  const flags = new FeatureFlags();
  const rules = [
    {
      conditions: [],
      variant: 'beta',
      value: true,
      rollout: { percentage: 30 }
    },
    {
      conditions: [],
      variant: 'fallback',
      value: false,
      rollout: null
    }
  ];
  flags.set_flag('admin', 'multi_rule_flag', 'boolean', true, true, rules);

  let foundOutside = false;
  for (let i = 0; i < 1000; i++) {
    const context = { targeting_key: `user${i}` };
    const result = flags.get_boolean_details('multi_rule_flag', true, context);
    if (result.value === false && result.variant === 'fallback' && result.reason === 'TARGETING_MATCH') {
      foundOutside = true;
      break;
    }
  }
  assert.ok(foundOutside, 'Should find a user outside the rollout who falls through to the next rule');
});

// FLAG-07
test('corrupt rules returns default with PARSE_ERROR', () => {
  const store = new InMemoryFlagStore();
  store.setFlag('corrupt_flag', {
    key: 'corrupt_flag',
    type: 'boolean',
    default_value: false,
    enabled: true,
    rules: 'not valid json {{{',
    updated_at: new Date().toISOString(),
    updated_by: 'admin'
  });
  const flags = new FeatureFlags(store);
  const result = flags.get_boolean_details('corrupt_flag', false, {});
  assert.strictEqual(result.value, false);
  assert.strictEqual(result.reason, 'ERROR');
  assert.strictEqual(result.error_code, 'PARSE_ERROR');
});

// FLAG-08
test('set_flag writes audit row with old and new values', () => {
  const store = new InMemoryFlagStore();
  const flags = new FeatureFlags(store);
  flags.set_flag('admin', 'audit_flag', 'boolean', false, true, []);
  flags.set_flag('admin', 'audit_flag', 'boolean', true, true, []);
  const audits = store.getAudits('audit_flag');
  assert.strictEqual(audits.length, 2);
  assert.strictEqual(audits[0].action, 'CREATE');
  assert.strictEqual(audits[0].old_value, null);
  assert.strictEqual(audits[0].new_value, false);
  assert.strictEqual(audits[1].action, 'UPDATE');
  assert.strictEqual(audits[1].old_value, false);
  assert.strictEqual(audits[1].new_value, true);
});
/**
 * FLAG-05: the bucket is the spec's stable_hash (first 8 bytes of SHA-256, unsigned big-endian) % 100,
 * the same in every language. In: a 30% rollout and known keys. Out: asserts the served value per key.
 * Expected buckets (computed independently with Python hashlib): "rollout_flag:user0" -> 84,
 * "rollout_flag:user1" -> 37, "rollout_flag:user2" -> 12. Why: the old float-based hash put user0 in
 * bucket 16 (served true) where every other language serves false. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory store only.
 */
// FLAG-05
test('rollout bucket matches the cross-language stable_hash', () => {
  const flags = new FeatureFlags();
  flags.set_flag('admin', 'rollout_flag', 'boolean', false, true,
    [{ conditions: [], variant: 'beta', value: true, rollout: { percentage: 30 } }]);
  const at = (k: string) => flags.get_boolean_details('rollout_flag', false, { targeting_key: k });
  assert.strictEqual(at('user0').value, false);
  assert.strictEqual(at('user0').reason, 'DEFAULT');
  assert.strictEqual(at('user1').value, false);
  assert.strictEqual(at('user2').value, true);
  assert.strictEqual(at('user2').reason, 'SPLIT');
  assert.strictEqual(at('user2').variant, 'beta');
});

<?php

require_once __DIR__ . '/feature_flags_php.php';

use Aoi\FeatureFlags\{
    FeatureFlagClient, FeatureFlagOptions, InMemoryFlagStore, SqlFlagStore,
    FlagStore, FlagRecord, FeatureFlagError, EvaluationDetails
};

const RJ_ON = '[{"conditions":[],"variant":"on","value":true,"rollout":null}]';
const RJ_ACME = '[{"conditions":[{"attribute":"email","operator":"ends_with","value":"@acme.com"}],"variant":"on","value":true,"rollout":null}]';
const RJ_30 = '[{"conditions":[],"variant":"beta","value":true,"rollout":{"percentage":30}}]';
const RJ_CHECKOUT = '[{"conditions":[],"variant":"beta","value":"new","rollout":{"percentage":30}},{"conditions":[{"attribute":"tier","operator":"equals","value":"pro"}],"variant":"pro","value":"pro-ui","rollout":null}]';

$T0 = 1767225600;
$T1 = $T0 + 60;
$failed = 0;

function assert_details(EvaluationDetails $d, mixed $exp_value, string $exp_reason, ?string $exp_variant, ?string $exp_error_code, string $test_name): void {
    global $failed;
    $ok = true;
    if ($d->value !== $exp_value) { echo "FAIL $test_name: value {$d->value} != $exp_value\n"; $ok = false; }
    if ($d->reason !== $exp_reason) { echo "FAIL $test_name: reason {$d->reason} != $exp_reason\n"; $ok = false; }
    if ($d->variant !== $exp_variant) { echo "FAIL $test_name: variant " . var_export($d->variant, true) . " != " . var_export($exp_variant, true) . "\n"; $ok = false; }
    if ($d->error_code !== $exp_error_code) { echo "FAIL $test_name: error_code " . var_export($d->error_code, true) . " != " . var_export($exp_error_code, true) . "\n"; $ok = false; }
    if (!$ok) $failed++;
}

function make_client(?\Closure $clock = null): FeatureFlagClient {
    $store = new InMemoryFlagStore();
    $opts = $clock ? new FeatureFlagOptions($clock) : null;
    return new FeatureFlagClient($store, $opts);
}

function make_client_with_store(FlagStore $store, ?\Closure $clock = null): FeatureFlagClient {
    $opts = $clock ? new FeatureFlagOptions($clock) : null;
    return new FeatureFlagClient($store, $opts);
}

// FLAG-01
function test_unknown_flag_returns_default(): void {
    global $failed;
    $client = make_client();
    $d = $client->get_boolean_details('missing_flag', true, ['targeting_key' => 'alice']);
    assert_details($d, true, 'ERROR', null, 'FLAG_NOT_FOUND', 'test_unknown_flag_returns_default');
    $v = $client->get_string_value('missing_flag', 'fallback', null);
    if ($v !== 'fallback') { echo "FAIL test_unknown_flag_returns_default: string value $v != fallback\n"; $failed++; }
}

// FLAG-02
function test_string_method_on_boolean_flag_is_type_mismatch(): void {
    global $failed, $T0;
    $clock = fn() => $T0;
    $client = make_client($clock);
    $client->set_flag('admin', 'bool_flag', 'boolean', 'true', true, '[]');
    $d = $client->get_string_details('bool_flag', 'fallback', []);
    assert_details($d, 'fallback', 'ERROR', null, 'TYPE_MISMATCH', 'test_string_method_on_boolean_flag_is_type_mismatch');
    $d2 = $client->get_boolean_details('bool_flag', false, []);
    assert_details($d2, true, 'DEFAULT', null, null, 'test_string_method_on_boolean_flag_is_type_mismatch_bool');
    $n = $client->get_number_value('bool_flag', 7, []);
    if ($n !== 7) { echo "FAIL test_string_method_on_boolean_flag_is_type_mismatch: number value $n != 7\n"; $failed++; }
    $client->set_flag('admin', 'bool_flag', 'boolean', 'true', false, '[]');
    $d3 = $client->get_string_details('bool_flag', 'fallback', []);
    assert_details($d3, 'fallback', 'ERROR', null, 'TYPE_MISMATCH', 'test_string_method_on_boolean_flag_is_type_mismatch_disabled');
}

// FLAG-03
function test_disabled_flag_returns_caller_default(): void {
    global $failed, $T0;
    $clock = fn() => $T0;
    $client = make_client($clock);
    $client->set_flag('admin', 'off_flag', 'boolean', 'true', false, RJ_ON);
    $d = $client->get_boolean_details('off_flag', false, ['targeting_key' => 'alice']);
    assert_details($d, false, 'DISABLED', null, null, 'test_disabled_flag_returns_caller_default');
    $client->set_flag('admin', 'off_flag', 'boolean', 'true', true, RJ_ON);
    $d2 = $client->get_boolean_details('off_flag', false, ['targeting_key' => 'alice']);
    assert_details($d2, true, 'TARGETING_MATCH', 'on', null, 'test_disabled_flag_returns_caller_default_enabled');
    $client->set_flag('admin', 'limit', 'number', '5', true, '[]');
    $n1 = $client->get_number_value('limit', 1, []);
    if ($n1 !== 5) { echo "FAIL test_disabled_flag_returns_caller_default: number enabled $n1 != 5\n"; $failed++; }
    $client->set_flag('admin', 'limit', 'number', '5', false, '[]');
    $n2 = $client->get_number_value('limit', 1, []);
    if ($n2 !== 1) { echo "FAIL test_disabled_flag_returns_caller_default: number disabled $n2 != 1\n"; $failed++; }
}

// FLAG-04
function test_matching_rule_and_non_matching_rule(): void {
    global $failed, $T0;
    $clock = fn() => $T0;
    $client = make_client($clock);
    $client->set_flag('admin', 'acme_beta', 'boolean', 'false', true, RJ_ACME);
    $d1 = $client->get_boolean_details('acme_beta', false, ['targeting_key' => 'u1', 'email' => 'dev@acme.com']);
    assert_details($d1, true, 'TARGETING_MATCH', 'on', null, 'test_matching_rule_and_non_matching_rule_match');
    $d2 = $client->get_boolean_details('acme_beta', true, ['targeting_key' => 'u2', 'email' => 'dev@other.com']);
    assert_details($d2, false, 'DEFAULT', null, null, 'test_matching_rule_and_non_matching_rule_nomatch');
    $d3 = $client->get_boolean_details('acme_beta', false, []);
    assert_details($d3, false, 'DEFAULT', null, null, 'test_matching_rule_and_non_matching_rule_empty');
}

// FLAG-05
function test_rollout_30_percent_deterministic_and_distributed(): void {
    global $failed, $T0;
    $clock = fn() => $T0;
    $client = make_client($clock);
    $client->set_flag('admin', 'rollout30', 'boolean', 'false', true, RJ_30);
    $count = 0;
    for ($i = 0; $i < 10000; $i++) {
        if ($client->get_boolean_value('rollout30', false, ['targeting_key' => "user-$i"])) {
            $count++;
        }
    }
    if ($count !== 2966) { echo "FAIL test_rollout_30_percent_deterministic_and_distributed: count $count != 2966\n"; $failed++; }
    if ($count < 2500 || $count > 3500) { echo "FAIL test_rollout_30_percent_deterministic_and_distributed: count $count not in 2500-3500\n"; $failed++; }
    $results = [];
    for ($i = 0; $i < 5; $i++) {
        $results[] = $client->get_boolean_value('rollout30', false, ['targeting_key' => 'user-42']);
    }
    if (count(array_unique($results)) !== 1) { echo "FAIL test_rollout_30_percent_deterministic_and_distributed: user-42 not consistent\n"; $failed++; }
    $d135 = $client->get_boolean_details('rollout30', false, ['targeting_key' => 'user-135']);
    assert_details($d135, true, 'SPLIT', 'beta', null, 'test_rollout_30_percent_deterministic_and_distributed_user135');
    $d26 = $client->get_boolean_details('rollout30', false, ['targeting_key' => 'user-26']);
    assert_details($d26, false, 'DEFAULT', null, null, 'test_rollout_30_percent_deterministic_and_distributed_user26');
}

// FLAG-06
function test_user_outside_rollout_falls_through(): void {
    global $failed, $T0;
    $clock = fn() => $T0;
    $client = make_client($clock);
    $client->set_flag('admin', 'checkout_ui', 'string', '"classic"', true, RJ_CHECKOUT);
    $d1 = $client->get_string_details('checkout_ui', 'fallback', ['targeting_key' => 'bob', 'tier' => 'pro']);
    assert_details($d1, 'new', 'SPLIT', 'beta', null, 'test_user_outside_rollout_falls_through_bob');
    $d2 = $client->get_string_details('checkout_ui', 'fallback', ['targeting_key' => 'carol', 'tier' => 'pro']);
    assert_details($d2, 'pro-ui', 'TARGETING_MATCH', 'pro', null, 'test_user_outside_rollout_falls_through_carol_pro');
    $d3 = $client->get_string_details('checkout_ui', 'fallback', ['targeting_key' => 'carol', 'tier' => 'free']);
    assert_details($d3, 'classic', 'DEFAULT', null, null, 'test_user_outside_rollout_falls_through_carol_free');
    $d4 = $client->get_string_details('checkout_ui', 'fallback', ['targeting_key' => 'alice']);
    assert_details($d4, 'classic', 'DEFAULT', null, null, 'test_user_outside_rollout_falls_through_alice');
}

// FLAG-07
function test_corrupt_rules_returns_parse_error(): void {
    global $failed, $T0;
    $bad_cases = [
        '[{"conditions": [',
        '{"conditions":[]}',
        '[{"conditions":[{"attribute":"email","operator":"starts_with","value":"@acme.com"}],"variant":"on","value":true,"rollout":null}]',
        '[{"conditions":[],"variant":"beta","value":true,"rollout":{"percentage":101}}]',
        '[{"conditions":[],"variant":"beta","value":true,"rollout":{"percentage":"30"}}]',
        '[{"conditions":[],"variant":"on","value":true,"rollout":null},{"conditions":"oops"}]',
        'NaN',
        ''
    ];
    foreach ($bad_cases as $bad) {
        $store = new InMemoryFlagStore();
        $store->put_flag(new FlagRecord('corrupt_flag', 'boolean', 'true', true, $bad, $T0, 'import'));
        $client = make_client_with_store($store);
        $d = $client->get_boolean_details('corrupt_flag', false, ['targeting_key' => 'alice']);
        assert_details($d, false, 'ERROR', null, 'PARSE_ERROR', 'test_corrupt_rules_returns_parse_error');
    }
    $client2 = make_client();
    try {
        $client2->set_flag('admin', 'new_flag', 'boolean', 'false', true, '[{"conditions": [');
        echo "FAIL test_corrupt_rules_returns_parse_error: set_flag should have thrown\n"; $failed++;
    } catch (FeatureFlagError $e) {
        if ($e->error_code !== 'INVALID_RULES' || $e->status !== 400) {
            echo "FAIL test_corrupt_rules_returns_parse_error: wrong error {$e->error_code} {$e->status}\n"; $failed++;
        }
    }
    $audit = $client2->store->list_audit('new_flag');
    if (count($audit) !== 0) { echo "FAIL test_corrupt_rules_returns_parse_error: audit not empty\n"; $failed++; }
}

// FLAG-08
function test_set_flag_writes_audit_rows(): void {
    global $failed, $T0, $T1;
    $store = new InMemoryFlagStore();
    $clock = fn() => $T0;
    $client = make_client_with_store($store, $clock);
    $e1 = $client->set_flag('alice-admin', 'audit_flag', 'boolean', 'false', true, '[]');
    if ($e1->id !== 1 || $e1->flag_key !== 'audit_flag' || $e1->action !== 'create' || $e1->old_value !== null || $e1->new_value !== '{"type":"boolean","default_value":false,"enabled":true,"rules":[]}' || $e1->actor_id !== 'alice-admin' || $e1->at !== $T0) {
        echo "FAIL test_set_flag_writes_audit_rows: e1 mismatch\n"; var_dump($e1); $failed++;
    }
    $clock2 = fn() => $T1;
    $client2 = make_client_with_store($store, $clock2);
    $e2 = $client2->set_flag('bob-admin', 'audit_flag', 'boolean', 'true', false, '[]');
    if ($e2->id !== 2 || $e2->action !== 'update' || $e2->old_value !== $e1->new_value || $e2->new_value !== '{"type":"boolean","default_value":true,"enabled":false,"rules":[]}' || $e2->actor_id !== 'bob-admin' || $e2->at !== $T1) {
        echo "FAIL test_set_flag_writes_audit_rows: e2 mismatch\n"; var_dump($e2); $failed++;
    }
    $audit = $store->list_audit('audit_flag');
    if (count($audit) !== 2 || $audit[0]->id !== 1 || $audit[1]->id !== 2) {
        echo "FAIL test_set_flag_writes_audit_rows: audit list mismatch\n"; $failed++;
    }
    $audit_other = $store->list_audit('other');
    if (count($audit_other) !== 0) { echo "FAIL test_set_flag_writes_audit_rows: other audit not empty\n"; $failed++; }
    $flag = $store->get_flag('audit_flag');
    if ($flag->updated_at !== $T1 || $flag->updated_by !== 'bob-admin') {
        echo "FAIL test_set_flag_writes_audit_rows: flag record not updated\n"; $failed++;
    }
}

function test_bucket_vectors(): void {
    global $failed;
    $vectors = [
        ['checkout_ui', 'carol', 94],
        ['checkout_ui', 'bob', 18],
        ['checkout_ui', 'alice', 88],
        ['checkout_ui', "jos\u{e9}", 45],
        ['rollout30', 'user-0', 24],
        ['rollout30', 'user-3', 98],
        ['rollout30', 'user-26', 30],
        ['rollout30', 'user-135', 29],
    ];
    foreach ($vectors as [$flag, $key, $exp]) {
        $got = FeatureFlagClient::stable_bucket($flag, $key);
        if ($got !== $exp) { echo "FAIL test_bucket_vectors: $flag:$key got $got exp $exp\n"; $failed++; }
    }
}

function test_rollout_boundaries(): void {
    global $failed, $T0;
    $clock = fn() => $T0;
    $client = make_client($clock);
    $client->set_flag('admin', 'pct_zero', 'boolean', 'false', true, '[{"conditions":[],"variant":"beta","value":true,"rollout":{"percentage":0}}]');
    for ($i = 0; $i < 100; $i++) {
        $v = $client->get_boolean_value('pct_zero', false, ['targeting_key' => "user-$i"]);
        if ($v !== false) { echo "FAIL test_rollout_boundaries: pct_zero user-$i got true\n"; $failed++; break; }
    }
    $client->set_flag('admin', 'pct_hundred', 'boolean', 'false', true, '[{"conditions":[],"variant":"beta","value":true,"rollout":{"percentage":100}}]');
    for ($i = 0; $i < 100; $i++) {
        $v = $client->get_boolean_value('pct_hundred', false, ['targeting_key' => "user-$i"]);
        if ($v !== true) { echo "FAIL test_rollout_boundaries: pct_hundred user-$i got false\n"; $failed++; break; }
    }
    $d1 = $client->get_boolean_details('pct_hundred', false, []);
    assert_details($d1, false, 'DEFAULT', null, null, 'test_rollout_boundaries_missing_tk');
    $d2 = $client->get_boolean_details('pct_hundred', false, ['targeting_key' => '']);
    assert_details($d2, false, 'DEFAULT', null, null, 'test_rollout_boundaries_empty_tk');
    $d3 = $client->get_boolean_details('pct_hundred', false, ['targeting_key' => 42]);
    assert_details($d3, false, 'DEFAULT', null, null, 'test_rollout_boundaries_numeric_tk');

    $client->set_flag('admin', 'rollout30', 'string', '"control"', true, '[{"conditions":[],"variant":"a","value":"a","rollout":{"percentage":30}},{"conditions":[],"variant":"b","value":"b","rollout":{"percentage":60}}]');
    $d135 = $client->get_string_details('rollout30', 'fallback', ['targeting_key' => 'user-135']);
    assert_details($d135, 'a', 'SPLIT', 'a', null, 'test_rollout_boundaries_user135');
    $d26 = $client->get_string_details('rollout30', 'fallback', ['targeting_key' => 'user-26']);
    assert_details($d26, 'b', 'SPLIT', 'b', null, 'test_rollout_boundaries_user26');
    $d3 = $client->get_string_details('rollout30', 'fallback', ['targeting_key' => 'user-3']);
    assert_details($d3, 'control', 'DEFAULT', null, null, 'test_rollout_boundaries_user3');
}

function test_operators_each_isolated(): void {
    global $failed, $T0;
    $clock = fn() => $T0;
    $client = make_client($clock);

    $client->set_flag('admin', 'eq_flag', 'boolean', 'false', true, '[{"conditions":[{"attribute":"tier","operator":"equals","value":"pro"}],"variant":"hit","value":true,"rollout":null}]');
    $d1 = $client->get_boolean_details('eq_flag', false, ['targeting_key' => 'u1', 'tier' => 'pro']);
    assert_details($d1, true, 'TARGETING_MATCH', 'hit', null, 'test_operators_each_isolated_equals_pro');
    $d2 = $client->get_boolean_details('eq_flag', false, ['targeting_key' => 'u2', 'tier' => 'PRO']);
    assert_details($d2, false, 'DEFAULT', null, null, 'test_operators_each_isolated_equals_PRO');
    $d3 = $client->get_boolean_details('eq_flag', false, ['targeting_key' => 'u3']);
    assert_details($d3, false, 'DEFAULT', null, null, 'test_operators_each_isolated_equals_missing');

    $client->set_flag('admin', 'ne_flag', 'boolean', 'false', true, '[{"conditions":[{"attribute":"tier","operator":"not_equals","value":"free"}],"variant":"hit","value":true,"rollout":null}]');
    $d4 = $client->get_boolean_details('ne_flag', false, ['targeting_key' => 'u1', 'tier' => 'pro']);
    assert_details($d4, true, 'TARGETING_MATCH', 'hit', null, 'test_operators_each_isolated_not_equals_pro');
    $d5 = $client->get_boolean_details('ne_flag', false, ['targeting_key' => 'u2', 'tier' => 'free']);
    assert_details($d5, false, 'DEFAULT', null, null, 'test_operators_each_isolated_not_equals_free');
    $d6 = $client->get_boolean_details('ne_flag', false, ['targeting_key' => 'u3']);
    assert_details($d6, false, 'DEFAULT', null, null, 'test_operators_each_isolated_not_equals_missing');
    $d7 = $client->get_boolean_details('ne_flag', false, ['targeting_key' => 'u4', 'tier' => null]);
    assert_details($d7, false, 'DEFAULT', null, null, 'test_operators_each_isolated_not_equals_null');

    $client->set_flag('admin', 'in_flag', 'boolean', 'false', true, '[{"conditions":[{"attribute":"org_id","operator":"in_list","value":["org-1","org-2"]}],"variant":"hit","value":true,"rollout":null}]');
    $d8 = $client->get_boolean_details('in_flag', false, ['targeting_key' => 'u1', 'org_id' => 'org-2']);
    assert_details($d8, true, 'TARGETING_MATCH', 'hit', null, 'test_operators_each_isolated_in_list_org2');
    $d9 = $client->get_boolean_details('in_flag', false, ['targeting_key' => 'u2', 'org_id' => 'org-3']);
    assert_details($d9, false, 'DEFAULT', null, null, 'test_operators_each_isolated_in_list_org3');

    $client->set_flag('admin', 'ew_flag', 'boolean', 'false', true, '[{"conditions":[{"attribute":"email","operator":"ends_with","value":"@acme.com"}],"variant":"hit","value":true,"rollout":null}]');
    $d10 = $client->get_boolean_details('ew_flag', false, ['targeting_key' => 'u1', 'email' => 'ceo@acme.com']);
    assert_details($d10, true, 'TARGETING_MATCH', 'hit', null, 'test_operators_each_isolated_ends_with_acme');
    $d11 = $client->get_boolean_details('ew_flag', false, ['targeting_key' => 'u2', 'email' => 'ceo@acme.com.evil.io']);
    assert_details($d11, false, 'DEFAULT', null, null, 'test_operators_each_isolated_ends_with_evil');
    $d12 = $client->get_boolean_details('ew_flag', false, ['targeting_key' => 'u3', 'email' => 'CEO@ACME.COM']);
    assert_details($d12, false, 'DEFAULT', null, null, 'test_operators_each_isolated_ends_with_case');

    $client->set_flag('admin', 'num_flag', 'boolean', 'false', true, '[{"conditions":[{"attribute":"seats","operator":"equals","value":3}],"variant":"hit","value":true,"rollout":null}]');
    $d13 = $client->get_boolean_details('num_flag', false, ['targeting_key' => 'u1', 'seats' => 3]);
    assert_details($d13, true, 'TARGETING_MATCH', 'hit', null, 'test_operators_each_isolated_equals_int3');
    $d14 = $client->get_boolean_details('num_flag', false, ['targeting_key' => 'u2', 'seats' => 3.0]);
    assert_details($d14, true, 'TARGETING_MATCH', 'hit', null, 'test_operators_each_isolated_equals_float3');
    $d15 = $client->get_boolean_details('num_flag', false, ['targeting_key' => 'u3', 'seats' => '3']);
    assert_details($d15, false, 'DEFAULT', null, null, 'test_operators_each_isolated_equals_string3');
    $d16 = $client->get_boolean_details('num_flag', false, ['targeting_key' => 'u4', 'seats' => true]);
    assert_details($d16, false, 'DEFAULT', null, null, 'test_operators_each_isolated_equals_true');

    $client->set_flag('admin', 'bool_flag2', 'boolean', 'false', true, '[{"conditions":[{"attribute":"beta","operator":"equals","value":true}],"variant":"hit","value":true,"rollout":null}]');
    $d17 = $client->get_boolean_details('bool_flag2', false, ['targeting_key' => 'u1', 'beta' => true]);
    assert_details($d17, true, 'TARGETING_MATCH', 'hit', null, 'test_operators_each_isolated_equals_bool_true');
    $d18 = $client->get_boolean_details('bool_flag2', false, ['targeting_key' => 'u2', 'beta' => 1]);
    assert_details($d18, false, 'DEFAULT', null, null, 'test_operators_each_isolated_equals_bool_1');
    $d19 = $client->get_boolean_details('bool_flag2', false, ['targeting_key' => 'u3', 'beta' => 'true']);
    assert_details($d19, false, 'DEFAULT', null, null, 'test_operators_each_isolated_equals_bool_string');
}

function test_served_value_type_mismatch(): void {
    global $failed, $T0;
    $store = new InMemoryFlagStore();
    $store->put_flag(new FlagRecord('bad_serve', 'boolean', 'false', true, '[{"conditions":[],"variant":"yes","value":"yes","rollout":null}]', $T0, 'import'));
    $client = make_client_with_store($store);
    $d = $client->get_boolean_details('bad_serve', false, ['targeting_key' => 'alice']);
    assert_details($d, false, 'ERROR', null, 'TYPE_MISMATCH', 'test_served_value_type_mismatch');
    $store2 = new InMemoryFlagStore();
    $store2->put_flag(new FlagRecord('bad_default', 'boolean', '"oops"', true, '[]', $T0, 'import'));
    $client2 = make_client_with_store($store2);
    $d2 = $client2->get_boolean_details('bad_default', false, ['targeting_key' => 'alice']);
    assert_details($d2, false, 'ERROR', null, 'TYPE_MISMATCH', 'test_served_value_type_mismatch_default');
    $store3 = new InMemoryFlagStore();
    $store3->put_flag(new FlagRecord('bad_json', 'boolean', 'nope', true, '[]', $T0, 'import'));
    $client3 = make_client_with_store($store3);
    $d3 = $client3->get_boolean_details('bad_json', false, ['targeting_key' => 'alice']);
    assert_details($d3, false, 'ERROR', null, 'PARSE_ERROR', 'test_served_value_type_mismatch_json');
    $client4 = make_client();
    try {
        $client4->set_flag('admin', 'bad_rule', 'boolean', 'false', true, '[{"conditions":[],"variant":"yes","value":"yes","rollout":null}]');
        echo "FAIL test_served_value_type_mismatch: set_flag should have thrown\n"; $failed++;
    } catch (FeatureFlagError $e) {
        if ($e->error_code !== 'INVALID_RULES' || $e->status !== 400) {
            echo "FAIL test_served_value_type_mismatch: wrong error {$e->error_code} {$e->status}\n"; $failed++;
        }
    }
}

function test_set_flag_validation_and_repair(): void {
    global $failed, $T0;
    $client = make_client();
    try {
        $client->set_flag('', 'valid_key', 'boolean', 'false', true, '[]');
        echo "FAIL test_set_flag_validation_and_repair: empty actor_id should have thrown\n"; $failed++;
    } catch (FeatureFlagError $e) {
        if ($e->error_code !== 'INVALID_ACTOR' || $e->status !== 400) {
            echo "FAIL test_set_flag_validation_and_repair: wrong error {$e->error_code} {$e->status}\n"; $failed++;
        }
    }
    try {
        $client->set_flag('admin', 'bad:key', 'boolean', 'false', true, '[]');
        echo "FAIL test_set_flag_validation_and_repair: bad key should have thrown\n"; $failed++;
    } catch (FeatureFlagError $e) {
        if ($e->error_code !== 'INVALID_KEY' || $e->status !== 400) {
            echo "FAIL test_set_flag_validation_and_repair: wrong error {$e->error_code} {$e->status}\n"; $failed++;
        }
    }
    try {
        $client->set_flag('admin', str_repeat('a', 129), 'boolean', 'false', true, '[]');
        echo "FAIL test_set_flag_validation_and_repair: long key should have thrown\n"; $failed++;
    } catch (FeatureFlagError $e) {
        if ($e->error_code !== 'INVALID_KEY' || $e->status !== 400) {
            echo "FAIL test_set_flag_validation_and_repair: wrong error {$e->error_code} {$e->status}\n"; $failed++;
        }
    }
    try {
        $client->set_flag('admin', 'valid_key', 'json', 'false', true, '[]');
        echo "FAIL test_set_flag_validation_and_repair: invalid type should have thrown\n"; $failed++;
    } catch (FeatureFlagError $e) {
        if ($e->error_code !== 'INVALID_TYPE' || $e->status !== 400) {
            echo "FAIL test_set_flag_validation_and_repair: wrong error {$e->error_code} {$e->status}\n"; $failed++;
        }
    }
    try {
        $client->set_flag('admin', 'valid_key', 'boolean', '"yes"', true, '[]');
        echo "FAIL test_set_flag_validation_and_repair: boolean with string should have thrown\n"; $failed++;
    } catch (FeatureFlagError $e) {
        if ($e->error_code !== 'INVALID_DEFAULT_VALUE' || $e->status !== 400) {
            echo "FAIL test_set_flag_validation_and_repair: wrong error {$e->error_code} {$e->status}\n"; $failed++;
        }
    }
    try {
        $client->set_flag('admin', 'valid_key', 'number', 'NaN', true, '[]');
        echo "FAIL test_set_flag_validation_and_repair: number with NaN should have thrown\n"; $failed++;
    } catch (FeatureFlagError $e) {
        if ($e->error_code !== 'INVALID_DEFAULT_VALUE' || $e->status !== 400) {
            echo "FAIL test_set_flag_validation_and_repair: wrong error {$e->error_code} {$e->status}\n"; $failed++;
        }
    }
    try {
        $client->set_flag('admin', 'valid_key', 'number', '1e999', true, '[]');
        echo "FAIL test_set_flag_validation_and_repair: number with 1e999 should have thrown\n"; $failed++;
    } catch (FeatureFlagError $e) {
        if ($e->error_code !== 'INVALID_DEFAULT_VALUE' || $e->status !== 400) {
            echo "FAIL test_set_flag_validation_and_repair: wrong error {$e->error_code} {$e->status}\n"; $failed++;
        }
    }
    try {
        $client->set_flag('admin', 'valid_key', 'object', '[]', true, '[]');
        echo "FAIL test_set_flag_validation_and_repair: object with array should have thrown\n"; $failed++;
    } catch (FeatureFlagError $e) {
        if ($e->error_code !== 'INVALID_DEFAULT_VALUE' || $e->status !== 400) {
            echo "FAIL test_set_flag_validation_and_repair: wrong error {$e->error_code} {$e->status}\n"; $failed++;
        }
    }
    $store = new InMemoryFlagStore();
    $store->put_flag(new FlagRecord('repair_me', 'boolean', 'true', true, '[{"conditions": [', $T0, 'import'));
    $client2 = make_client_with_store($store);
    $e = $client2->set_flag('fixer', 'repair_me', 'boolean', 'true', true, '[]');
    if ($e->id !== 1 || $e->action !== 'update' || $e->old_value !== '{"type":"boolean","default_value":true,"enabled":true,"rules":[{"conditions": [}' || $e->new_value !== '{"type":"boolean","default_value":true,"enabled":true,"rules":[]}' || $e->actor_id !== 'fixer' || $e->at !== $T0) {
        echo "FAIL test_set_flag_validation_and_repair: repair mismatch\n"; var_dump($e); $failed++;
    }
    $d = $client2->get_boolean_details('repair_me', false, ['targeting_key' => 'alice']);
    assert_details($d, true, 'DEFAULT', null, null, 'test_set_flag_validation_and_repair_repaired');
}

function test_store_failure_is_general(): void {
    global $failed;
    class FailingStore implements FlagStore {
        public function get_flag(string $key): ?FlagRecord {
            throw new \Exception('db down');
        }
        public function put_flag(FlagRecord $record): void {
            throw new \Exception('db down');
        }
        public function save_flag_audited(FlagRecord $record, string $actor_id, int $at): AuditEntry {
            throw new \Exception('db down');
        }
        public function list_audit(string $flag_key): array {
            throw new \Exception('db down');
        }
    }
    $store = new FailingStore();
    $client = make_client_with_store($store);
    $d = $client->get_boolean_details('any', true, []);
    assert_details($d, true, 'ERROR', null, 'GENERAL', 'test_store_failure_is_general_get');
    try {
        $client->set_flag('admin', 'any', 'boolean', 'false', true, '[]');
        echo "FAIL test_store_failure_is_general: set_flag should have thrown\n"; $failed++;
    } catch (FeatureFlagError $e) {
        if ($e->error_code !== 'STORE_ERROR' || $e->status !== 500) {
            echo "FAIL test_store_failure_is_general: wrong error {$e->error_code} {$e->status}\n"; $failed++;
        }
    }
}

exit($failed > 0 ? 1 : 0);
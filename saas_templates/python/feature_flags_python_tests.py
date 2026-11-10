import json
import sys
import threading
import time
# [2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP] FailingStore below annotates with Optional, List and
# AuditEntry, which were never imported: collection died with NameError on every Python version (annotations
# on a def are evaluated when the def runs). Test change only: the imports; no test or assertion changed.
from typing import List, Optional
from feature_flags_python import (
    FeatureFlagClient,
    InMemoryFlagStore,
    SqlFlagStore,
    FeatureFlagOptions,
    FeatureFlagError,
    stable_bucket,
    EvaluationDetails,
    FlagRecord,
    SCHEMA_STATEMENTS,
    REASON_STATIC,
    REASON_DEFAULT,
    REASON_TARGETING_MATCH,
    REASON_SPLIT,
    REASON_DISABLED,
    REASON_ERROR,
    ERROR_FLAG_NOT_FOUND,
    ERROR_TYPE_MISMATCH,
    ERROR_PARSE_ERROR,
    ERROR_GENERAL,
    FLAG_TYPE_BOOLEAN,
    FLAG_TYPE_STRING,
    FLAG_TYPE_NUMBER,
    FLAG_TYPE_OBJECT,
    AUDIT_ACTION_CREATE,
    AUDIT_ACTION_UPDATE,
    FlagStore,
    AuditEntry,
)

T0 = 1767225600
T1 = T0 + 60

RJ_ON = '[{"conditions":[],"variant":"on","value":true,"rollout":null}]'
RJ_ACME = '[{"conditions":[{"attribute":"email","operator":"ends_with","value":"@acme.com"}],"variant":"on","value":true,"rollout":null}]'
RJ_30 = '[{"conditions":[],"variant":"beta","value":true,"rollout":{"percentage":30}}]'
RJ_CHECKOUT = '[{"conditions":[],"variant":"beta","value":"new","rollout":{"percentage":30}},{"conditions":[{"attribute":"tier","operator":"equals","value":"pro"}],"variant":"pro","value":"pro-ui","rollout":null}]'

_failed = 0


def assert_equal(actual, expected, msg=""):
    global _failed
    if actual != expected:
        _failed += 1
        print(f"FAIL: {msg}: expected {expected!r}, got {actual!r}")
    else:
        print(f"OK: {msg}")


def assert_details(d: EvaluationDetails, value, reason, variant, error_code, msg=""):
    assert_equal(d.value, value, f"{msg} value")
    assert_equal(d.reason, reason, f"{msg} reason")
    assert_equal(d.variant, variant, f"{msg} variant")
    assert_equal(d.error_code, error_code, f"{msg} error_code")
    assert_equal(d.flag_key, d.flag_key, f"{msg} flag_key")


def test_unknown_flag_returns_default():
    store = InMemoryFlagStore()
    client = FeatureFlagClient(store)
    d = client.get_boolean_details("missing_flag", True, {"targeting_key": "alice"})
    assert_details(d, True, REASON_ERROR, None, ERROR_FLAG_NOT_FOUND, "unknown boolean")
    assert_equal(client.get_string_value("missing_flag", "fallback", None), "fallback", "unknown string")


def test_string_method_on_boolean_flag_is_type_mismatch():
    store = InMemoryFlagStore()
    client = FeatureFlagClient(store, FeatureFlagOptions(clock=lambda: T0))
    client.set_flag("admin", "bool_flag", FLAG_TYPE_BOOLEAN, "true", True, "[]")
    d = client.get_string_details("bool_flag", "fallback", {})
    assert_details(d, "fallback", REASON_ERROR, None, ERROR_TYPE_MISMATCH, "string on boolean")
    d = client.get_boolean_details("bool_flag", False, {})
    assert_details(d, True, REASON_DEFAULT, None, None, "boolean on boolean")
    assert_equal(client.get_number_value("bool_flag", 7, {}), 7, "number on boolean")
    client.set_flag("admin", "bool_flag", FLAG_TYPE_BOOLEAN, "true", False, "[]")
    d = client.get_string_details("bool_flag", "fallback", {})
    assert_details(d, "fallback", REASON_ERROR, None, ERROR_TYPE_MISMATCH, "string on disabled boolean")


def test_disabled_flag_returns_caller_default():
    store = InMemoryFlagStore()
    client = FeatureFlagClient(store, FeatureFlagOptions(clock=lambda: T0))
    client.set_flag("admin", "off_flag", FLAG_TYPE_BOOLEAN, "true", False, RJ_ON)
    d = client.get_boolean_details("off_flag", False, {"targeting_key": "alice"})
    assert_details(d, False, REASON_DISABLED, None, None, "disabled boolean")
    client.set_flag("admin", "off_flag", FLAG_TYPE_BOOLEAN, "true", True, RJ_ON)
    d = client.get_boolean_details("off_flag", False, {"targeting_key": "alice"})
    assert_details(d, True, REASON_TARGETING_MATCH, "on", None, "enabled boolean")
    client.set_flag("admin", "limit", FLAG_TYPE_NUMBER, "5", True, "[]")
    assert_equal(client.get_number_value("limit", 1, {}), 5, "number default enabled")
    client.set_flag("admin", "limit", FLAG_TYPE_NUMBER, "5", False, "[]")
    assert_equal(client.get_number_value("limit", 1, {}), 1, "number default disabled")


def test_matching_rule_and_non_matching_rule():
    store = InMemoryFlagStore()
    client = FeatureFlagClient(store, FeatureFlagOptions(clock=lambda: T0))
    client.set_flag("admin", "acme_beta", FLAG_TYPE_BOOLEAN, "false", True, RJ_ACME)
    d = client.get_boolean_details("acme_beta", False, {"email": "dev@acme.com"})
    assert_details(d, True, REASON_TARGETING_MATCH, "on", None, "matching email")
    d = client.get_boolean_details("acme_beta", True, {"email": "dev@other.com"})
    assert_details(d, False, REASON_DEFAULT, None, None, "non-matching email")
    d = client.get_boolean_details("acme_beta", False, {})
    assert_details(d, False, REASON_DEFAULT, None, None, "empty context")


def test_rollout_30_percent_deterministic_and_distributed():
    store = InMemoryFlagStore()
    client = FeatureFlagClient(store, FeatureFlagOptions(clock=lambda: T0))
    client.set_flag("admin", "rollout30", FLAG_TYPE_BOOLEAN, "false", True, RJ_30)
    count = 0
    for i in range(10000):
        if client.get_boolean_value("rollout30", False, {"targeting_key": f"user-{i}"}):
            count += 1
    assert_equal(count, 2966, "rollout 30% count")
    assert_equal(2500 <= count <= 3500, True, "rollout 30% range")
    results = [client.get_boolean_value("rollout30", False, {"targeting_key": "user-42"}) for _ in range(5)]
    assert_equal(all(r == results[0] for r in results), True, "deterministic user-42")
    d = client.get_boolean_details("rollout30", False, {"targeting_key": "user-135"})
    assert_details(d, True, REASON_SPLIT, "beta", None, "user-135 in rollout")
    d = client.get_boolean_details("rollout30", False, {"targeting_key": "user-26"})
    assert_details(d, False, REASON_DEFAULT, None, None, "user-26 outside rollout")


def test_user_outside_rollout_falls_through():
    store = InMemoryFlagStore()
    client = FeatureFlagClient(store, FeatureFlagOptions(clock=lambda: T0))
    client.set_flag("admin", "checkout_ui", FLAG_TYPE_STRING, '"classic"', True, RJ_CHECKOUT)
    d = client.get_string_details("checkout_ui", "fallback", {"targeting_key": "bob", "tier": "pro"})
    assert_details(d, "new", REASON_SPLIT, "beta", None, "bob in rollout")
    d = client.get_string_details("checkout_ui", "fallback", {"targeting_key": "carol", "tier": "pro"})
    assert_details(d, "pro-ui", REASON_TARGETING_MATCH, "pro", None, "carol pro tier")
    d = client.get_string_details("checkout_ui", "fallback", {"targeting_key": "carol", "tier": "free"})
    assert_details(d, "classic", REASON_DEFAULT, None, None, "carol free tier")
    d = client.get_string_details("checkout_ui", "fallback", {"targeting_key": "alice"})
    assert_details(d, "classic", REASON_DEFAULT, None, None, "alice no tier")


def test_corrupt_rules_json_returns_parse_error():
    store = InMemoryFlagStore()
    client = FeatureFlagClient(store)
    bad_cases = [
        '[{"conditions": [',
        '{"conditions":[]}',
        '[{"conditions":[{"attribute":"email","operator":"starts_with","value":"@acme.com"}],"variant":"on","value":true,"rollout":null}]',
        '[{"conditions":[],"variant":"beta","value":true,"rollout":{"percentage":101}}]',
        '[{"conditions":[],"variant":"beta","value":true,"rollout":{"percentage":"30"}}]',
        '[{"conditions":[],"variant":"on","value":true,"rollout":null},{"conditions":"oops"}]',
        'NaN',
        '',
    ]
    for i, bad in enumerate(bad_cases):
        store.put_flag(FlagRecord(key=f"corrupt_flag_{i}", type=FLAG_TYPE_BOOLEAN, default_value_json="true", enabled=True, rules_json=bad, updated_at=T0, updated_by="import"))
        d = client.get_boolean_details(f"corrupt_flag_{i}", False, {"targeting_key": "alice"})
        assert_details(d, False, REASON_ERROR, None, ERROR_PARSE_ERROR, f"corrupt case {i}")
    try:
        client.set_flag("admin", "new_flag", FLAG_TYPE_BOOLEAN, "false", True, '[{"conditions": [')
        assert_equal(False, True, "set_flag should have thrown INVALID_RULES")
    except FeatureFlagError as e:
        assert_equal(e.code, "INVALID_RULES", "INVALID_RULES code")
        assert_equal(e.status, 400, "INVALID_RULES status")
    assert_equal(len(store.list_audit("new_flag")), 0, "audit empty after failed set_flag")


def test_set_flag_writes_audit_rows():
    store = InMemoryFlagStore()
    clock = [T0]
    client = FeatureFlagClient(store, FeatureFlagOptions(clock=lambda: clock[0]))
    e1 = client.set_flag("alice-admin", "audit_flag", FLAG_TYPE_BOOLEAN, "false", True, "[]")
    assert_equal(e1.id, 1, "audit id 1")
    assert_equal(e1.flag_key, "audit_flag", "audit flag_key")
    assert_equal(e1.action, AUDIT_ACTION_CREATE, "audit action create")
    assert_equal(e1.old_value, None, "audit old_value null")
    assert_equal(e1.new_value, '{"type":"boolean","default_value":false,"enabled":true,"rules":[]}', "audit new_value")
    assert_equal(e1.actor_id, "alice-admin", "audit actor_id")
    assert_equal(e1.at, T0, "audit at T0")
    clock[0] = T1
    e2 = client.set_flag("bob-admin", "audit_flag", FLAG_TYPE_BOOLEAN, "true", False, "[]")
    assert_equal(e2.id, 2, "audit id 2")
    assert_equal(e2.action, AUDIT_ACTION_UPDATE, "audit action update")
    assert_equal(e2.old_value, e1.new_value, "audit old_value == prev new_value")
    assert_equal(e2.new_value, '{"type":"boolean","default_value":true,"enabled":false,"rules":[]}', "audit new_value 2")
    assert_equal(e2.actor_id, "bob-admin", "audit actor_id 2")
    assert_equal(e2.at, T1, "audit at T1")
    audits = store.list_audit("audit_flag")
    assert_equal(len(audits), 2, "audit count")
    assert_equal(audits[0].id, 1, "audit[0] id")
    assert_equal(audits[1].id, 2, "audit[1] id")
    assert_equal(store.list_audit("other"), [], "audit other empty")
    flag = store.get_flag("audit_flag")
    assert_equal(flag.updated_at, T1, "flag updated_at T1")
    assert_equal(flag.updated_by, "bob-admin", "flag updated_by bob-admin")


def test_bucket_vectors():
    assert_equal(stable_bucket("checkout_ui", "carol"), 94, "bucket carol")
    assert_equal(stable_bucket("checkout_ui", "bob"), 18, "bucket bob")
    assert_equal(stable_bucket("checkout_ui", "alice"), 88, "bucket alice")
    assert_equal(stable_bucket("checkout_ui", "jos\u00e9"), 45, "bucket jose")
    assert_equal(stable_bucket("rollout30", "user-0"), 24, "bucket user-0")
    assert_equal(stable_bucket("rollout30", "user-3"), 98, "bucket user-3")
    assert_equal(stable_bucket("rollout30", "user-26"), 30, "bucket user-26")
    assert_equal(stable_bucket("rollout30", "user-135"), 29, "bucket user-135")


def test_rollout_boundaries():
    store = InMemoryFlagStore()
    client = FeatureFlagClient(store, FeatureFlagOptions(clock=lambda: T0))
    client.set_flag("admin", "pct_zero", FLAG_TYPE_BOOLEAN, "false", True, '[{"conditions":[],"variant":"a","value":true,"rollout":{"percentage":0}}]')
    for i in range(100):
        assert_equal(client.get_boolean_value("pct_zero", False, {"targeting_key": f"user-{i}"}), False, f"pct_zero user-{i}")
    client.set_flag("admin", "pct_hundred", FLAG_TYPE_BOOLEAN, "false", True, '[{"conditions":[],"variant":"a","value":true,"rollout":{"percentage":100}}]')
    for i in range(100):
        d = client.get_boolean_details("pct_hundred", False, {"targeting_key": f"user-{i}"})
        assert_details(d, True, REASON_SPLIT, "a", None, f"pct_hundred user-{i}")
    for ctx in [{"targeting_key": ""}, {"targeting_key": 42}, {}]:
        d = client.get_boolean_details("pct_hundred", False, ctx)
        assert_details(d, False, REASON_DEFAULT, None, None, f"pct_hundred missing key {ctx}")
    client.set_flag("admin", "rollout30", FLAG_TYPE_STRING, '"control"', True,
        '[{"conditions":[],"variant":"a","value":"a","rollout":{"percentage":30}},{"conditions":[],"variant":"b","value":"b","rollout":{"percentage":60}}]')
    d = client.get_string_details("rollout30", "fallback", {"targeting_key": "user-135"})
    assert_details(d, "a", REASON_SPLIT, "a", None, "user-135 bucket 29 -> a")
    d = client.get_string_details("rollout30", "fallback", {"targeting_key": "user-26"})
    assert_details(d, "b", REASON_SPLIT, "b", None, "user-26 bucket 30 -> b")
    d = client.get_string_details("rollout30", "fallback", {"targeting_key": "user-3"})
    assert_details(d, "control", REASON_DEFAULT, None, None, "user-3 bucket 98 -> default")


def test_operators_each_isolated():
    store = InMemoryFlagStore()
    client = FeatureFlagClient(store, FeatureFlagOptions(clock=lambda: T0))
    client.set_flag("admin", "eq_flag", FLAG_TYPE_BOOLEAN, "false", True, '[{"conditions":[{"attribute":"tier","operator":"equals","value":"pro"}],"variant":"hit","value":true,"rollout":null}]')
    assert_details(client.get_boolean_details("eq_flag", False, {"tier": "pro"}), True, REASON_TARGETING_MATCH, "hit", None, "equals pro")
    assert_details(client.get_boolean_details("eq_flag", False, {"tier": "PRO"}), False, REASON_DEFAULT, None, None, "equals PRO")
    assert_details(client.get_boolean_details("eq_flag", False, {}), False, REASON_DEFAULT, None, None, "equals empty")
    client.set_flag("admin", "neq_flag", FLAG_TYPE_BOOLEAN, "false", True, '[{"conditions":[{"attribute":"tier","operator":"not_equals","value":"free"}],"variant":"hit","value":true,"rollout":null}]')
    assert_details(client.get_boolean_details("neq_flag", False, {"tier": "pro"}), True, REASON_TARGETING_MATCH, "hit", None, "not_equals pro")
    assert_details(client.get_boolean_details("neq_flag", False, {"tier": "free"}), False, REASON_DEFAULT, None, None, "not_equals free")
    assert_details(client.get_boolean_details("neq_flag", False, {}), False, REASON_DEFAULT, None, None, "not_equals empty")
    assert_details(client.get_boolean_details("neq_flag", False, {"tier": None}), False, REASON_DEFAULT, None, None, "not_equals null")
    client.set_flag("admin", "in_flag", FLAG_TYPE_BOOLEAN, "false", True, '[{"conditions":[{"attribute":"org_id","operator":"in_list","value":["org-1","org-2"]}],"variant":"hit","value":true,"rollout":null}]')
    assert_details(client.get_boolean_details("in_flag", False, {"org_id": "org-2"}), True, REASON_TARGETING_MATCH, "hit", None, "in_list org-2")
    assert_details(client.get_boolean_details("in_flag", False, {"org_id": "org-3"}), False, REASON_DEFAULT, None, None, "in_list org-3")
    client.set_flag("admin", "ew_flag", FLAG_TYPE_BOOLEAN, "false", True, '[{"conditions":[{"attribute":"email","operator":"ends_with","value":"@acme.com"}],"variant":"hit","value":true,"rollout":null}]')
    assert_details(client.get_boolean_details("ew_flag", False, {"email": "ceo@acme.com"}), True, REASON_TARGETING_MATCH, "hit", None, "ends_with acme")
    assert_details(client.get_boolean_details("ew_flag", False, {"email": "ceo@acme.com.evil.io"}), False, REASON_DEFAULT, None, None, "ends_with evil")
    assert_details(client.get_boolean_details("ew_flag", False, {"email": "CEO@ACME.COM"}), False, REASON_DEFAULT, None, None, "ends_with case")
    client.set_flag("admin", "eq_num_flag", FLAG_TYPE_BOOLEAN, "false", True, '[{"conditions":[{"attribute":"seats","operator":"equals","value":3}],"variant":"hit","value":true,"rollout":null}]')
    assert_details(client.get_boolean_details("eq_num_flag", False, {"seats": 3}), True, REASON_TARGETING_MATCH, "hit", None, "equals 3 int")
    assert_details(client.get_boolean_details("eq_num_flag", False, {"seats": 3.0}), True, REASON_TARGETING_MATCH, "hit", None, "equals 3.0")
    assert_details(client.get_boolean_details("eq_num_flag", False, {"seats": "3"}), False, REASON_DEFAULT, None, None, "equals string 3")
    assert_details(client.get_boolean_details("eq_num_flag", False, {"seats": True}), False, REASON_DEFAULT, None, None, "equals true")
    client.set_flag("admin", "eq_bool_flag", FLAG_TYPE_BOOLEAN, "false", True, '[{"conditions":[{"attribute":"beta","operator":"equals","value":true}],"variant":"hit","value":true,"rollout":null}]')
    assert_details(client.get_boolean_details("eq_bool_flag", False, {"beta": True}), True, REASON_TARGETING_MATCH, "hit", None, "equals true bool")
    assert_details(client.get_boolean_details("eq_bool_flag", False, {"beta": 1}), False, REASON_DEFAULT, None, None, "equals 1")
    assert_details(client.get_boolean_details("eq_bool_flag", False, {"beta": "true"}), False, REASON_DEFAULT, None, None, "equals string true")


def test_served_value_type_mismatch():
    store = InMemoryFlagStore()
    store.put_flag(FlagRecord(key="bad_serve", type=FLAG_TYPE_BOOLEAN, default_value_json="false", enabled=True, rules_json='[{"conditions":[],"variant":"bad","value":"yes","rollout":null}]', updated_at=T0, updated_by="import"))
    client = FeatureFlagClient(store)
    d = client.get_boolean_details("bad_serve", False, {"targeting_key": "alice"})
    assert_details(d, False, REASON_ERROR, None, ERROR_TYPE_MISMATCH, "served string on boolean")
    store.put_flag(FlagRecord(key="bad_default", type=FLAG_TYPE_BOOLEAN, default_value_json='"oops"', enabled=True, rules_json="[]", updated_at=T0, updated_by="import"))
    d = client.get_boolean_details("bad_default", False, {})
    assert_details(d, False, REASON_ERROR, None, ERROR_TYPE_MISMATCH, "bad default type")
    store.put_flag(FlagRecord(key="bad_parse", type=FLAG_TYPE_BOOLEAN, default_value_json="nope", enabled=True, rules_json="[]", updated_at=T0, updated_by="import"))
    d = client.get_boolean_details("bad_parse", False, {})
    assert_details(d, False, REASON_ERROR, None, ERROR_PARSE_ERROR, "bad default parse")
    try:
        client.set_flag("admin", "bad_rule", FLAG_TYPE_BOOLEAN, "false", True, '[{"conditions":[],"variant":"bad","value":"yes","rollout":null}]')
        assert_equal(False, True, "set_flag should throw INVALID_RULES")
    except FeatureFlagError as e:
        assert_equal(e.code, "INVALID_RULES", "INVALID_RULES on bad rule value")


def test_set_flag_validation_and_repair():
    store = InMemoryFlagStore()
    client = FeatureFlagClient(store, FeatureFlagOptions(clock=lambda: T0))
    cases = [
        ("", "valid", FLAG_TYPE_BOOLEAN, "false", True, "[]", "INVALID_ACTOR"),
        ("actor", "bad:key", FLAG_TYPE_BOOLEAN, "false", True, "[]", "INVALID_KEY"),
        ("actor", "x" * 129, FLAG_TYPE_BOOLEAN, "false", True, "[]", "INVALID_KEY"),
        ("actor", "valid", "json", "false", True, "[]", "INVALID_TYPE"),
        ("actor", "valid", FLAG_TYPE_BOOLEAN, '"yes"', True, "[]", "INVALID_DEFAULT_VALUE"),
        ("actor", "valid", FLAG_TYPE_NUMBER, "NaN", True, "[]", "INVALID_DEFAULT_VALUE"),
        ("actor", "valid", FLAG_TYPE_NUMBER, "1e999", True, "[]", "INVALID_DEFAULT_VALUE"),
        ("actor", "valid", FLAG_TYPE_OBJECT, "[]", True, "[]", "INVALID_DEFAULT_VALUE"),
    ]
    for actor, key, ftype, default, enabled, rules, expected_code in cases:
        try:
            client.set_flag(actor, key, ftype, default, enabled, rules)
            assert_equal(False, True, f"set_flag should throw {expected_code}")
        except FeatureFlagError as e:
            assert_equal(e.code, expected_code, f"{expected_code} code")
            assert_equal(e.status, 400, f"{expected_code} status")
    assert_equal(len(store.list_audit("valid_key")), 0, "audit empty after validation failures")
    store.put_flag(FlagRecord(key="repair_me", type=FLAG_TYPE_BOOLEAN, default_value_json="true", enabled=True, rules_json='[{"conditions": [', updated_at=T0, updated_by="import"))
    e = client.set_flag("fixer", "repair_me", FLAG_TYPE_BOOLEAN, "true", True, "[]")
    assert_equal(e.action, AUDIT_ACTION_UPDATE, "repair action update")
    assert_equal(e.old_value, '{"type":"boolean","default_value":true,"enabled":true,"rules":[{"conditions": [}', "repair old_value")
    d = client.get_boolean_details("repair_me", False, {})
    assert_details(d, True, REASON_DEFAULT, None, None, "repaired flag works")


class FailingStore(FlagStore):
    def get_flag(self, key: str) -> Optional[FlagRecord]:
        raise RuntimeError("store fail")
    def put_flag(self, record: FlagRecord) -> None:
        raise RuntimeError("store fail")
    def save_flag_audited(self, record: FlagRecord, actor_id: str, at: int) -> AuditEntry:
        raise RuntimeError("store fail")
    def list_audit(self, flag_key: str) -> List[AuditEntry]:
        raise RuntimeError("store fail")


def test_store_failure_is_general():
    store = FailingStore()
    client = FeatureFlagClient(store)
    d = client.get_boolean_details("any", True, {})
    assert_details(d, True, REASON_ERROR, None, ERROR_GENERAL, "get on failing store")
    try:
        client.set_flag("actor", "key", FLAG_TYPE_BOOLEAN, "false", True, "[]")
        assert_equal(False, True, "set_flag should throw STORE_ERROR")
    except FeatureFlagError as e:
        assert_equal(e.code, "STORE_ERROR", "STORE_ERROR code")
        assert_equal(e.status, 500, "STORE_ERROR status")


def test_sql_store_round_trip():
    store = SqlFlagStore(":memory:")
    clock = [T0]
    client = FeatureFlagClient(store, FeatureFlagOptions(clock=lambda: clock[0]))
    e1 = client.set_flag("alice-admin", "audit_flag", FLAG_TYPE_BOOLEAN, "false", True, "[]")
    assert_equal(e1.id, 1, "sql audit id 1")
    assert_equal(e1.action, AUDIT_ACTION_CREATE, "sql audit action create")
    clock[0] = T1
    e2 = client.set_flag("bob-admin", "audit_flag", FLAG_TYPE_BOOLEAN, "true", False, "[]")
    assert_equal(e2.id, 2, "sql audit id 2")
    assert_equal(e2.action, AUDIT_ACTION_UPDATE, "sql audit action update")
    audits = store.list_audit("audit_flag")
    assert_equal(len(audits), 2, "sql audit count")
    flag = store.get_flag("audit_flag")
    assert_equal(flag.enabled, False, "sql enabled bool")
    assert_equal(flag.updated_at, T1, "sql updated_at")
    assert_equal(flag.updated_by, "bob-admin", "sql updated_by")
    client.set_flag("admin", "checkout_ui", FLAG_TYPE_STRING, '"classic"', True, RJ_CHECKOUT)
    d = client.get_string_details("checkout_ui", "fallback", {"targeting_key": "bob", "tier": "pro"})
    assert_details(d, "new", REASON_SPLIT, "beta", None, "sql bob in rollout")
    d = client.get_string_details("checkout_ui", "fallback", {"targeting_key": "carol", "tier": "pro"})
    assert_details(d, "pro-ui", REASON_TARGETING_MATCH, "pro", None, "sql carol pro tier")


if __name__ == "__main__":
    test_unknown_flag_returns_default()
    test_string_method_on_boolean_flag_is_type_mismatch()
    test_disabled_flag_returns_caller_default()
    test_matching_rule_and_non_matching_rule()
    test_rollout_30_percent_deterministic_and_distributed()
    test_user_outside_rollout_falls_through()
    test_corrupt_rules_json_returns_parse_error()
    test_set_flag_writes_audit_rows()
    test_bucket_vectors()
    test_rollout_boundaries()
    test_operators_each_isolated()
    test_served_value_type_mismatch()
    test_set_flag_validation_and_repair()
    test_store_failure_is_general()
    test_sql_store_round_trip()
    if _failed:
        print(f"\n{_failed} TESTS FAILED")
        sys.exit(1)
    else:
        print("\nALL TESTS PASSED")
        sys.exit(0)
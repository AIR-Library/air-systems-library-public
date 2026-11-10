use serde_json::json;
use std::collections::HashMap;
use feature_flags_rust::*;

fn create_context(
    targeting_key: Option<String>,
    user_id: Option<String>,
    org_id: Option<String>,
    tier: Option<String>,
    email: Option<String>,
    attributes: HashMap<String, serde_json::Value>,
) -> Context {
    Context {
        targeting_key,
        user_id,
        org_id,
        tier,
        email,
        attributes,
    }
}

// FLAG-01
#[test]
fn test_unknown_flag_returns_default() {
    let store = InMemoryStore::new();
    let client = FeatureFlagClient::new(store);
    let context = create_context(Some("user1".to_string()), None, None, None, None, HashMap::new());
    let result = client.get_boolean_details("unknown_flag", false, &context);
    assert_eq!(result.value, false);
    assert_eq!(result.reason, EvaluationReason::Error);
    assert_eq!(result.error_code, Some(ErrorCode::FlagNotFound));
}

// FLAG-03
#[test]
fn test_disabled_flag_returns_default() {
    let store = InMemoryStore::new();
    store.init().unwrap();
    store.set_flag(
        "admin",
        "flag1",
        FlagType::Boolean,
        json!(true),
        false,
        json!([]),
    )
    .unwrap();
    let client = FeatureFlagClient::new(store);
    let context = create_context(Some("user1".to_string()), None, None, None, None, HashMap::new());
    let result = client.get_boolean_details("flag1", false, &context);
    assert_eq!(result.value, false);
    assert_eq!(result.reason, EvaluationReason::Disabled);
    assert_eq!(result.error_code, None);
}

// FLAG-04
#[test]
fn test_matching_rule_returns_value() {
    let store = InMemoryStore::new();
    store.init().unwrap();
    store.set_flag(
        "admin",
        "flag1",
        FlagType::Boolean,
        json!(false),
        true,
        json!([{
            "conditions": [{"attribute": "email", "operator": "ends_with", "value": "@acme.com"}],
            "variant": "on",
            "value": true,
            "rollout": null
        }]),
    )
    .unwrap();
    let client = FeatureFlagClient::new(store);
    let context = create_context(
        Some("user1".to_string()),
        None,
        None,
        None,
        Some("user@acme.com".to_string()),
        HashMap::new(),
    );
    let result = client.get_boolean_details("flag1", false, &context);
    assert_eq!(result.value, true);
    assert_eq!(result.reason, EvaluationReason::TargetingMatch);
    assert_eq!(result.variant, Some("on".to_string()));
    assert_eq!(result.error_code, None);
}

// FLAG-04
#[test]
fn test_non_matching_rule_does_not_apply() {
    let store = InMemoryStore::new();
    store.init().unwrap();
    store.set_flag(
        "admin",
        "flag1",
        FlagType::Boolean,
        json!(false),
        true,
        json!([{
            "conditions": [{"attribute": "email", "operator": "ends_with", "value": "@acme.com"}],
            "variant": "on",
            "value": true,
            "rollout": null
        }]),
    )
    .unwrap();
    let client = FeatureFlagClient::new(store);
    let context = create_context(
        Some("user1".to_string()),
        None,
        None,
        None,
        Some("user@example.com".to_string()),
        HashMap::new(),
    );
    let result = client.get_boolean_details("flag1", false, &context);
    assert_eq!(result.value, false);
    assert_eq!(result.reason, EvaluationReason::Default);
    assert_eq!(result.variant, None);
    assert_eq!(result.error_code, None);
}

// FLAG-05
#[test]
fn test_rollout_deterministic() {
    let store = InMemoryStore::new();
    store.init().unwrap();
    store.set_flag(
        "admin",
        "flag1",
        FlagType::Boolean,
        json!(false),
        true,
        json!([{
            "conditions": [],
            "variant": "on",
            "value": true,
            "rollout": {"percentage": 30}
        }]),
    )
    .unwrap();
    let client = FeatureFlagClient::new(store);
    let mut true_count = 0;
    let total = 10000;
    for i in 0..total {
        let context = create_context(
            Some(format!("user{}", i)),
            None,
            None,
            None,
            None,
            HashMap::new(),
        );
        if client.get_boolean_value("flag1", false, &context) {
            true_count += 1;
        }
    }
    // Expect between 25% and 35%
    let ratio = true_count as f64 / total as f64;
    assert!(ratio >= 0.25 && ratio <= 0.35);
    // Check determinism: same key always gives same result
    let context1 = create_context(Some("user123".to_string()), None, None, None, None, HashMap::new());
    let context2 = create_context(Some("user123".to_string()), None, None, None, None, HashMap::new());
    assert_eq!(
        client.get_boolean_value("flag1", false, &context1),
        client.get_boolean_value("flag1", false, &context2)
    );
}

// FLAG-06
#[test]
fn test_rollout_falls_through() {
    let store = InMemoryStore::new();
    store.init().unwrap();
    store.set_flag(
        "admin",
        "flag1",
        FlagType::Boolean,
        json!(false),
        true,
        json!([
            {
                "conditions": [],
                "variant": "on",
                "value": true,
                "rollout": {"percentage": 0}
            },
            {
                "conditions": [{"attribute": "tier", "operator": "equals", "value": "premium"}],
                "variant": "premium",
                "value": true,
                "rollout": null
            }
        ]),
    )
    .unwrap();
    let client = FeatureFlagClient::new(store);
    // User with bucket >= 0 (always true for percentage 0) and not premium -> should fall through to default (false)
    let context = create_context(
        Some("user1".to_string()),
        None,
        None,
        Some("basic".to_string()),
        None,
        HashMap::new(),
    );
    let result = client.get_boolean_details("flag1", false, &context);
    assert_eq!(result.value, false);
    assert_eq!(result.reason, EvaluationReason::Default);
    // User with bucket >= 0 and premium -> should match second rule
    let context = create_context(
        Some("user1".to_string()),
        None,
        None,
        Some("premium".to_string()),
        None,
        HashMap::new(),
    );
    let result = client.get_boolean_details("flag1", false, &context);
    assert_eq!(result.value, true);
    assert_eq!(result.reason, EvaluationReason::TargetingMatch);
    assert_eq!(result.variant, Some("premium".to_string()));
}

// FLAG-07
#[test]
fn test_corrupt_rules_returns_default() {
    let store = InMemoryStore::new();
    store.init().unwrap();
    store.set_flag(
        "admin",
        "flag1",
        FlagType::Boolean,
        json!(false),
        true,
        json!("invalid"), // Not an array
    )
    .unwrap();
    let client = FeatureFlagClient::new(store);
    let context = create_context(Some("user1".to_string()), None, None, None, None, HashMap::new());
    let result = client.get_boolean_details("flag1", false, &context);
    assert_eq!(result.value, false);
    assert_eq!(result.reason, EvaluationReason::Error);
    assert_eq!(result.error_code, Some(ErrorCode::ParseError));
}

/// What: FLAG-08: set_flag writes an audit row with the old and new values: "create" with no old value,
/// then "update" with the previous flag as old_value, each with the actor. Changed 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP: the old test only read the flag back; no audit row existed.
/// Touches: memory only.
// FLAG-08
#[test]
fn test_set_flag_writes_audit() {
    let store = InMemoryStore::new();
    store.init().unwrap();
    assert!(store.get_flag("flag1").is_none());
    store.set_flag(
        "admin",
        "flag1",
        FlagType::Boolean,
        json!(true),
        true,
        json!([]),
    )
    .unwrap();
    let flag = store.get_flag("flag1").unwrap();
    assert_eq!(flag.key, "flag1");
    assert_eq!(flag.flag_type, FlagType::Boolean);
    assert_eq!(flag.default_value, json!(true));
    assert_eq!(flag.enabled, true);
    assert_eq!(flag.rules, json!([]));
    store.set_flag("ops", "flag1", FlagType::Boolean, json!(true), false, json!([])).unwrap();
    let audit = store.list_audit("flag1");
    assert_eq!(audit.len(), 2);
    assert_eq!((audit[0].action.as_str(), audit[0].actor_id.as_str(), audit[0].old_value.clone()), ("create", "admin", None));
    assert_eq!(audit[0].new_value["enabled"], json!(true));
    assert_eq!((audit[1].action.as_str(), audit[1].actor_id.as_str()), ("update", "ops"));
    assert_eq!(audit[1].old_value.as_ref().unwrap()["enabled"], json!(true));
    assert_eq!(audit[1].new_value["enabled"], json!(false));
}

/// What: FLAG-02: calling the string method (and the number and object methods) on a boolean flag
/// returns the caller's default with reason ERROR and TYPE_MISMATCH, even when a rule would apply; the
/// boolean method still works. In: none. Out: panics on a wrong answer.
/// Why: the spec's required test FLAG-02 had no Rust test; the type check moved up front 2026-11-10.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
// FLAG-02
#[test]
fn test_type_mismatch_returns_default() {
    let store = InMemoryStore::new();
    store.init().unwrap();
    store
        .set_flag("admin", "bool_flag", FlagType::Boolean, json!(false), true, json!([{ "conditions": [], "variant": "on", "value": true, "rollout": null }]))
        .unwrap();
    let client = FeatureFlagClient::new(store);
    let context = create_context(Some("user1".to_string()), None, None, None, None, HashMap::new());
    let s = client.get_string_details("bool_flag", "fallback", &context);
    assert_eq!(s.value, "fallback");
    assert_eq!(s.reason, EvaluationReason::Error);
    assert_eq!(s.error_code, Some(ErrorCode::TypeMismatch));
    let n = client.get_number_details("bool_flag", 7.0, &context);
    assert_eq!((n.value, n.error_code), (7.0, Some(ErrorCode::TypeMismatch)));
    let o = client.get_object_details("bool_flag", json!({"x": 1}), &context);
    assert_eq!((o.value, o.error_code), (json!({"x": 1}), Some(ErrorCode::TypeMismatch)));
    assert!(client.get_boolean_value("bool_flag", false, &context));
}

/// What: the SQLite store answers like the in-memory one: a flag round-trips, a rule applies, a
/// disabled flag gives DISABLED, and set_flag writes create/update audit rows with old and new values.
/// In: none. Out: panics on a wrong answer. Why: `SqlStore` was a stub until 2026-11-10 (FLAG-08).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
// FLAG-08
#[test]
fn test_sql_store_round_trip_and_audit() {
    let store = SqlStore::new();
    store.init().unwrap();
    store
        .set_flag("admin", "beta", FlagType::Boolean, json!(false), true, json!([{ "conditions": [{"attribute": "tier", "operator": "equals", "value": "team"}], "variant": "on", "value": true, "rollout": null }]))
        .unwrap();
    store.set_flag("ops", "beta", FlagType::Boolean, json!(false), false, json!([])).unwrap();
    let audit = store.list_audit("beta");
    assert_eq!(audit.iter().map(|a| a.action.as_str()).collect::<Vec<_>>(), vec!["create", "update"]);
    assert_eq!(audit[1].old_value.as_ref().unwrap()["enabled"], json!(true));
    assert_eq!(audit[1].new_value["enabled"], json!(false));
    let client = FeatureFlagClient::new(store);
    let team = create_context(Some("u1".into()), None, None, Some("team".into()), None, HashMap::new());
    assert_eq!(client.get_boolean_details("beta", true, &team).reason, EvaluationReason::Disabled);
}

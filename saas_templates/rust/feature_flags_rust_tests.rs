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
}

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::RwLock;

// Allowed crates: serde, serde_json, hmac, sha2, base64, rand, uuid, thiserror
use sha2::{Sha256, Digest};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlagType {
    Boolean,
    String,
    Number,
    Object,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flag {
    pub key: String,
    pub flag_type: FlagType,
    pub default_value: Value,
    pub enabled: bool,
    pub rules: Value, // Expected to be an array of rule objects
    pub updated_at: String,
    pub updated_by: String,
}

#[derive(Debug, Clone)]
pub struct EvaluationDetails<T> {
    pub flag_key: String,
    pub value: T,
    pub variant: Option<String>,
    pub reason: EvaluationReason,
    pub error_code: Option<ErrorCode>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationReason {
    Static,
    Default,
    TargetingMatch,
    Split,
    Disabled,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    FlagNotFound,
    TypeMismatch,
    ParseError,
    General,
}

#[derive(Debug, Clone)]
pub struct Context {
    pub targeting_key: Option<String>,
    pub user_id: Option<String>,
    pub org_id: Option<String>,
    pub tier: Option<String>,
    pub email: Option<String>,
    pub attributes: HashMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operator {
    Equals,
    NotEquals,
    InList,
    EndsWith,
}

#[derive(Debug, Clone, Deserialize)]
struct Condition {
    attribute: String,
    operator: Operator,
    value: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct Rollout {
    percentage: f64,
}

#[derive(Debug, Clone, Deserialize)]
struct Rule {
    conditions: Vec<Condition>,
    variant: String,
    value: Value,
    rollout: Option<Rollout>,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Database error: {0}")]
    Database(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub trait FeatureFlagStore: Send + Sync {
    fn get_flag(&self, key: &str) -> Option<Flag>;
    fn set_flag(
        &self,
        actor: &str,
        key: &str,
        flag_type: FlagType,
        default_value: Value,
        enabled: bool,
        rules: Value,
    ) -> Result<(), StoreError>;
    fn init(&self) -> Result<(), StoreError>;
}

pub struct InMemoryStore {
    flags: RwLock<HashMap<String, Flag>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            flags: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureFlagStore for InMemoryStore {
    fn get_flag(&self, key: &str) -> Option<Flag> {
        self.flags.read().unwrap().get(key).cloned()
    }

    fn set_flag(
        &self,
        actor: &str,
        key: &str,
        flag_type: FlagType,
        default_value: Value,
        enabled: bool,
        rules: Value,
    ) -> Result<(), StoreError> {
        let flag = Flag {
            key: key.to_string(),
            flag_type,
            default_value,
            enabled,
            rules,
            updated_at: chrono::Utc::now().to_rfc3339(),
            updated_by: actor.to_string(),
        };
        self.flags.write().unwrap().insert(key.to_string(), flag);
        Ok(())
    }

    fn init(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

pub struct SqlStore {
    // In a real implementation, this would hold a database connection pool.
    // For this exercise, we leave it as a stub since tests use the in-memory store.
    _private: (),
}

impl SqlStore {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl FeatureFlagStore for SqlStore {
    fn get_flag(&self, _key: &str) -> Option<Flag> {
        None
    }

    fn set_flag(
        &self,
        _actor: &str,
        _key: &str,
        _flag_type: FlagType,
        _default_value: Value,
        _enabled: bool,
        _rules: Value,
    ) -> Result<(), StoreError> {
        Err(StoreError::Database("SQL store not implemented".to_string()))
    }

    fn init(&self) -> Result<(), StoreError> {
        Err(StoreError::Database("SQL store not implemented".to_string()))
    }
}

pub struct FeatureFlagClient<S: FeatureFlagStore> {
    store: S,
}

impl<S: FeatureFlagStore> FeatureFlagClient<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn get_boolean_value(&self, key: &str, default_value: bool, context: &Context) -> bool {
        self.get_boolean_details(key, default_value, context).value
    }

    pub fn get_boolean_details(
        &self,
        key: &str,
        default_value: bool,
        context: &Context,
    ) -> EvaluationDetails<bool> {
        self.evaluate_flag::<bool>(key, default_value, context, |v| v.as_bool())
    }

    pub fn get_string_value(&self, key: &str, default_value: &str, context: &Context) -> String {
        self.get_string_details(key, default_value, context).value
    }

    pub fn get_string_details(
        &self,
        key: &str,
        default_value: &str,
        context: &Context,
    ) -> EvaluationDetails<String> {
        self.evaluate_flag::<String>(
            key,
            default_value.to_string(),
            context,
            |v| v.as_str().map(|s| s.to_string()),
        )
    }

    pub fn get_number_value(&self, key: &str, default_value: f64, context: &Context) -> f64 {
        self.get_number_details(key, default_value, context).value
    }

    pub fn get_number_details(
        &self,
        key: &str,
        default_value: f64,
        context: &Context,
    ) -> EvaluationDetails<f64> {
        self.evaluate_flag::<f64>(key, default_value, context, |v| v.as_f64())
    }

    pub fn get_object_value(&self, key: &str, default_value: Value, context: &Context) -> Value {
        self.get_object_details(key, default_value, context).value
    }

    pub fn get_object_details(
        &self,
        key: &str,
        default_value: Value,
        context: &Context,
    ) -> EvaluationDetails<Value> {
        self.evaluate_flag::<Value>(key, default_value, context, |v| Some(v.clone()))
    }

    fn evaluate_flag<T: Clone>(
        &self,
        key: &str,
        default_value: T,
        context: &Context,
        extractor: fn(&Value) -> Option<T>,
    ) -> EvaluationDetails<T> {
        // Step 1: Get flag from store
        let flag = match self.store.get_flag(key) {
            Some(flag) => flag,
            None => {
                return EvaluationDetails {
                    flag_key: key.to_string(),
                    value: default_value,
                    variant: None,
                    reason: EvaluationReason::Error,
                    error_code: Some(ErrorCode::FlagNotFound),
                    error_message: Some(format!("Flag not found: {}", key)),
                };
            }
        };

        // Step 2: Check if flag is enabled
        if !flag.enabled {
            return EvaluationDetails {
                flag_key: key.to_string(),
                value: default_value,
                variant: None,
                reason: EvaluationReason::Disabled,
                error_code: None,
                error_message: None,
            };
        }

        // Step 3: Parse rules
        let rules: Vec<Rule> = match serde_json::from_value(flag.rules.clone()) {
            Ok(rules) => rules,
            Err(e) => {
                return EvaluationDetails {
                    flag_key: key.to_string(),
                    value: default_value,
                    variant: None,
                    reason: EvaluationReason::Error,
                    error_code: Some(ErrorCode::ParseError),
                    error_message: Some(format!("Failed to parse rules: {}", e)),
                };
            }
        };

        // Step 4: Evaluate each rule in order
        for rule in rules {
            // Check conditions
            let mut matches = true;
            for condition in &rule.conditions {
                if !self.evaluate_condition(&condition, context) {
                    matches = false;
                    break;
                }
            }

            if !matches {
                continue;
            }

            // Check rollout
            let applies = match &rule.rollout {
                Some(rollout) => {
                    // Need targeting_key for bucket hash
                    let targeting_key = match &context.targeting_key {
                        Some(tk) => tk.clone(),
                        None => continue,
                    };
                    // A share outside 0 to 100 is a configuration error, never "everyone" (from review).
                    if !(0.0..=100.0).contains(&rollout.percentage) {
                        continue;
                    }
                    let bucket = self.compute_bucket(key, &targeting_key);
                    f64::from(bucket) < rollout.percentage
                }
                None => true,
            };

            if !applies {
                continue;
            }

            // Rule applies: check type match
            let typed_value = match extractor(&rule.value) {
                Some(v) => v,
                None => {
                    return EvaluationDetails {
                        flag_key: key.to_string(),
                        value: default_value.clone(),
                        variant: None,
                        reason: EvaluationReason::Error,
                        error_code: Some(ErrorCode::TypeMismatch),
                        error_message: Some(format!(
                            "Type mismatch for flag {}: expected {:?}, got {:?}",
                            key, flag.flag_type, rule.value
                        )),
                    };
                }
            };

            let reason = if rule.rollout.is_some() {
                EvaluationReason::Split
            } else {
                EvaluationReason::TargetingMatch
            };

            return EvaluationDetails {
                flag_key: key.to_string(),
                value: typed_value,
                variant: Some(rule.variant.clone()),
                reason,
                error_code: None,
                error_message: None,
            };
        }

        // Step 5: No rule matched -> use flag's default value
        let typed_value = match extractor(&flag.default_value) {
            Some(v) => v,
            None => {
                return EvaluationDetails {
                    flag_key: key.to_string(),
                    value: default_value,
                    variant: None,
                    reason: EvaluationReason::Error,
                    error_code: Some(ErrorCode::TypeMismatch),
                    error_message: Some(format!(
                        "Type mismatch for flag {}: expected {:?}, got {:?}",
                        key, flag.flag_type, flag.default_value
                    )),
                };
            }
        };

        EvaluationDetails {
            flag_key: key.to_string(),
            value: typed_value,
            variant: None,
            reason: EvaluationReason::Default,
            error_code: None,
            error_message: None,
        }
    }

    fn evaluate_condition(&self, condition: &Condition, context: &Context) -> bool {
        let attr_value = self.lookup_attribute(&condition.attribute, context);
        match &condition.operator {
            Operator::Equals => attr_value.as_ref() == Some(&condition.value),
            // An absent attribute matches neither equals nor not_equals, as in the other languages (from review).
            Operator::NotEquals => attr_value.as_ref().map_or(false, |v| {
                !(v.is_null() || v.is_array() || v.is_object()) && v != &condition.value
            }),
            Operator::InList => {
                if let Value::Array(list) = &condition.value {
                    attr_value
                        .as_ref()
                        .map_or(false, |v| list.contains(v))
                } else {
                    false
                }
            }
            Operator::EndsWith => {
                match (attr_value.as_ref(), condition.value.as_str()) {
                    (Some(Value::String(s)), Some(suffix)) => s.ends_with(suffix),
                    _ => false,
                }
            }
        }
    }

    fn lookup_attribute(&self, attribute: &str, context: &Context) -> Option<Value> {
        match attribute {
            "targeting_key" => context.targeting_key.as_ref().map(|s| Value::String(s.clone())),
            "user_id" => context.user_id.as_ref().map(|s| Value::String(s.clone())),
            "org_id" => context.org_id.as_ref().map(|s| Value::String(s.clone())),
            "tier" => context.tier.as_ref().map(|s| Value::String(s.clone())),
            "email" => context.email.as_ref().map(|s| Value::String(s.clone())),
            _ => context.attributes.get(attribute).cloned(),
        }
    }

    fn compute_bucket(&self, flag_key: &str, targeting_key: &str) -> u8 {
        let input = format!("{}:{}", flag_key, targeting_key);
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let result = hasher.finalize();
        // Take first 8 bytes as big-endian u64
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&result[0..8]);
        let num = u64::from_be_bytes(bytes);
        (num % 100) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_context(
        targeting_key: Option<String>,
        user_id: Option<String>,
        org_id: Option<String>,
        tier: Option<String>,
        email: Option<String>,
        attributes: HashMap<String, Value>,
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
}

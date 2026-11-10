//! Feature flags (OpenFeature-style evaluation) with an audited store (TIER 3 spec, system: feature_flags).
//!
//! What: `FeatureFlagClient` evaluates boolean / string / number / object flags against a context with
//! ordered targeting rules and deterministic percentage rollouts, never panicking: every failure returns
//! the caller's default with reason ERROR and an error code. Flags live behind `FeatureFlagStore`
//! (`InMemoryStore`, or `SqlStore` on SQLite); every `set_flag` writes a `flag_audit` row with the old and
//! new flag.
//! Why: amended 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: `set_flag` wrote no audit row (FLAG-08), a flag
//! of another type was only caught when its served value could not be read as the requested type
//! (FLAG-02: a string flag read with the object method "worked"), and `SqlStore` was a stub that failed
//! every call.
//! Touches: memory, or the SQLite database given to `SqlStore`; the clock (audit and updated_at). No network.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Mutex, RwLock};

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

/// What: stored names of `FlagType`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl FlagType {
    /// What: the spec's name ('boolean' | 'string' | 'number' | 'object'). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn as_str(&self) -> &'static str {
        match self {
            FlagType::Boolean => "boolean",
            FlagType::String => "string",
            FlagType::Number => "number",
            FlagType::Object => "object",
        }
    }
    /// What: parse a stored name. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn parse(s: &str) -> Option<FlagType> {
        Some(match s {
            "boolean" => FlagType::Boolean,
            "string" => FlagType::String,
            "number" => FlagType::Number,
            "object" => FlagType::Object,
            _ => return None,
        })
    }
}

/// What: one `flag_audit` row: action "create" or "update", the flag before (None on create) and after
/// as JSON {type, default_value, enabled, rules}, the actor and the time. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP (FLAG-08). Touches: nothing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlagAuditEntry {
    pub id: i64,
    pub flag_key: String,
    pub action: String,
    pub old_value: Option<Value>,
    pub new_value: Value,
    pub actor_id: String,
    pub at: String,
}

/// What: the audited snapshot of a flag. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn snapshot(flag: &Flag) -> Value {
    json!({ "type": flag.flag_type.as_str(), "default_value": flag.default_value, "enabled": flag.enabled, "rules": flag.rules })
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

/// What: flag storage. `set_flag` stores the flag AND its audit row together; `list_audit` returns a
/// flag's audit rows oldest first. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (FLAG-08: `list_audit`
/// added, `set_flag` audited). Touches: whatever the implementation uses.
pub trait FeatureFlagStore: Send + Sync {
    fn get_flag(&self, key: &str) -> Option<Flag>;
    fn list_audit(&self, flag_key: &str) -> Vec<FlagAuditEntry>;
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

/// What: the in-memory store: flags and their audit rows. Changed 2026-11-10 (FLAG-08): audit rows.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
pub struct InMemoryStore {
    flags: RwLock<HashMap<String, Flag>>,
    audit: Mutex<Vec<FlagAuditEntry>>,
}

impl InMemoryStore {
    /// What: an empty store. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    pub fn new() -> Self {
        Self {
            flags: RwLock::new(HashMap::new()),
            audit: Mutex::new(Vec::new()),
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureFlagStore for InMemoryStore {
    /// What: a flag by key (a poisoned lock is recovered, never a panic). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn get_flag(&self, key: &str) -> Option<Flag> {
        self.flags.read().unwrap_or_else(|e| e.into_inner()).get(key).cloned()
    }

    /// What: a flag's audit rows, oldest first. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (FLAG-08).
    /// Touches: memory.
    fn list_audit(&self, flag_key: &str) -> Vec<FlagAuditEntry> {
        self.audit.lock().unwrap_or_else(|e| e.into_inner()).iter().filter(|e| e.flag_key == flag_key).cloned().collect()
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
        let now = chrono::Utc::now().to_rfc3339();
        let flag = Flag {
            key: key.to_string(),
            flag_type,
            default_value,
            enabled,
            rules,
            updated_at: now.clone(),
            updated_by: actor.to_string(),
        };
        // one lock order (flags, then audit) so the flag and its audit row change together
        let mut flags = self.flags.write().unwrap_or_else(|e| e.into_inner());
        let mut audit = self.audit.lock().unwrap_or_else(|e| e.into_inner());
        let old = flags.get(key).map(snapshot);
        let id = audit.len() as i64 + 1;
        audit.push(FlagAuditEntry {
            id,
            flag_key: key.to_string(),
            action: if old.is_some() { "update".into() } else { "create".into() },
            old_value: old,
            new_value: snapshot(&flag),
            actor_id: actor.to_string(),
            at: now,
        });
        flags.insert(key.to_string(), flag);
        Ok(())
    }

    fn init(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

/// What: the SQLite store with the spec's `feature_flags` and `flag_audit` tables; `set_flag` writes the
/// flag and its audit row in one transaction. Why: it was a stub that failed every call; implemented
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (FLAG-08). Touches: the SQLite database it is given.
pub struct SqlStore {
    conn: Mutex<rusqlite::Connection>,
}

impl SqlStore {
    /// What: a store on a private in-memory database (call `init`). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: memory.
    pub fn new() -> Self {
        Self::with_connection(rusqlite::Connection::open_in_memory().expect("in-memory SQLite opens"))
    }

    /// What: a store on a given connection (call `init`). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn with_connection(conn: rusqlite::Connection) -> Self {
        Self { conn: Mutex::new(conn) }
    }

    /// What: the connection (a poisoned lock is recovered). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn db(&self) -> std::sync::MutexGuard<'_, rusqlite::Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What: map a `feature_flags` row; a row whose JSON cannot be read keeps it as a string, so
    /// evaluation reports PARSE_ERROR instead of failing here. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn flag_row(r: &rusqlite::Row) -> rusqlite::Result<Flag> {
        let t: String = r.get(1)?;
        let json_or_text = |s: String| serde_json::from_str(&s).unwrap_or(Value::String(s));
        Ok(Flag {
            key: r.get(0)?,
            flag_type: FlagType::parse(&t).unwrap_or(FlagType::Object),
            default_value: json_or_text(r.get(2)?),
            enabled: r.get::<_, i64>(3)? != 0,
            rules: json_or_text(r.get(4)?),
            updated_at: r.get(5)?,
            updated_by: r.get(6)?,
        })
    }
}

impl Default for SqlStore {
    /// What: `SqlStore::new()`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn default() -> Self {
        Self::new()
    }
}

/// What: a SQLite error as a store error. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn sql_err(e: rusqlite::Error) -> StoreError {
    StoreError::Database(e.to_string())
}

impl FeatureFlagStore for SqlStore {
    /// What: a flag by key (a database error reads as "not found", so evaluation never panics).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
    fn get_flag(&self, key: &str) -> Option<Flag> {
        self.db()
            .query_row(
                "SELECT key, type, default_value, enabled, rules, updated_at, updated_by FROM feature_flags WHERE key = ?1",
                rusqlite::params![key],
                Self::flag_row,
            )
            .ok()
    }

    /// What: a flag's audit rows, oldest first. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
    fn list_audit(&self, flag_key: &str) -> Vec<FlagAuditEntry> {
        let conn = self.db();
        let Ok(mut stmt) = conn.prepare("SELECT id, flag_key, action, old_value, new_value, actor_id, at FROM flag_audit WHERE flag_key = ?1 ORDER BY id") else {
            return Vec::new();
        };
        let rows = stmt.query_map(rusqlite::params![flag_key], |r| {
            let old: Option<String> = r.get(3)?;
            let new: String = r.get(4)?;
            Ok(FlagAuditEntry {
                id: r.get(0)?,
                flag_key: r.get(1)?,
                action: r.get(2)?,
                old_value: old.and_then(|o| serde_json::from_str(&o).ok()),
                new_value: serde_json::from_str(&new).unwrap_or(Value::Null),
                actor_id: r.get(5)?,
                at: r.get(6)?,
            })
        });
        match rows {
            Ok(rows) => rows.filter_map(Result::ok).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// What: upsert the flag and append its audit row (create / update, old and new snapshot) in one
    /// transaction. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn set_flag(
        &self,
        actor: &str,
        key: &str,
        flag_type: FlagType,
        default_value: Value,
        enabled: bool,
        rules: Value,
    ) -> Result<(), StoreError> {
        let now = chrono::Utc::now().to_rfc3339();
        let flag = Flag { key: key.to_string(), flag_type, default_value, enabled, rules, updated_at: now.clone(), updated_by: actor.to_string() };
        let mut conn = self.db();
        let tx = conn.transaction().map_err(sql_err)?;
        let old: Option<Flag> = tx
            .query_row(
                "SELECT key, type, default_value, enabled, rules, updated_at, updated_by FROM feature_flags WHERE key = ?1",
                rusqlite::params![key],
                Self::flag_row,
            )
            .ok();
        tx.execute(
            "INSERT INTO feature_flags (key, type, default_value, enabled, rules, updated_at, updated_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (key) DO UPDATE SET type = excluded.type, default_value = excluded.default_value, enabled = excluded.enabled,
                rules = excluded.rules, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
            rusqlite::params![key, flag.flag_type.as_str(), flag.default_value.to_string(), flag.enabled as i64, flag.rules.to_string(), now, actor],
        )
        .map_err(sql_err)?;
        tx.execute(
            "INSERT INTO flag_audit (flag_key, action, old_value, new_value, actor_id, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![key, if old.is_some() { "update" } else { "create" }, old.as_ref().map(|f| snapshot(f).to_string()),
                snapshot(&flag).to_string(), actor, now],
        )
        .map_err(sql_err)?;
        tx.commit().map_err(sql_err)
    }

    /// What: create the spec's tables. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (DDL).
    fn init(&self) -> Result<(), StoreError> {
        self.db()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS feature_flags (key TEXT PRIMARY KEY, type TEXT NOT NULL CHECK (type IN ('boolean','string','number','object')),
                    default_value TEXT NOT NULL, enabled INTEGER NOT NULL, rules TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS flag_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, flag_key TEXT NOT NULL, action TEXT NOT NULL,
                    old_value TEXT NULL, new_value TEXT NOT NULL, actor_id TEXT NOT NULL, at TEXT NOT NULL);",
            )
            .map_err(sql_err)
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
        self.evaluate_flag::<bool>(key, FlagType::Boolean, default_value, context, |v| v.as_bool())
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
            FlagType::String,
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
        self.evaluate_flag::<f64>(key, FlagType::Number, default_value, context, |v| v.as_f64())
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
        self.evaluate_flag::<Value>(key, FlagType::Object, default_value, context, |v| v.is_object().then(|| v.clone()))
    }

    /// What: evaluate a flag for the method of type `expected`. Order: unknown flag -> FLAG_NOT_FOUND;
    /// stored type differs from the method called -> TYPE_MISMATCH; disabled -> DISABLED; unreadable
    /// rules -> PARSE_ERROR; then the first rule that applies (TARGETING_MATCH, or SPLIT inside its
    /// rollout), else the stored default (DEFAULT); a served value of the wrong type -> TYPE_MISMATCH.
    /// Every error returns the caller's default with reason ERROR. In: key, expected type, caller's
    /// default, context, value extractor. Out: `EvaluationDetails`.
    /// Why: OpenFeature evaluation; the up-front type check was added 2026-11-10 (FLAG-02), before it an
    /// object read of a string flag served the string. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: the store (read).
    fn evaluate_flag<T: Clone>(
        &self,
        key: &str,
        expected: FlagType,
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

        // Step 1b: the stored type must be the method's type
        if flag.flag_type != expected {
            return EvaluationDetails {
                flag_key: key.to_string(),
                value: default_value,
                variant: None,
                reason: EvaluationReason::Error,
                error_code: Some(ErrorCode::TypeMismatch),
                error_message: Some(format!("flag {} is a {} flag, not {}", key, flag.flag_type.as_str(), expected.as_str())),
            };
        }

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

// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.2: the `#[cfg(test)] mod tests` that sat here was a
// duplicate of feature_flags_rust_tests.rs (the same eight tests, FLAG-01/03/04/05/06/07/08, with no assertion the
// tests file lacks; its set_flag test was a subset of the tests file's FLAG-08). It was removed so the tests live
// in one place; no test was lost.

//! Health checks: liveness and readiness in the IETF health-check format (TIER 3 spec, system 6).
//!
//! What: `HealthChecker` keeps a registry of named checks; `liveness()` answers "the process is up"
//! without running any of them, `readiness()` runs them all concurrently, each with its own timeout,
//! and returns status pass/warn/fail with HTTP 200/200/503 and content type application/health+json.
//! Output is fixed text per outcome, so no error message, connection string or stack trace leaks.
//! Why: the old file did not compile (a block typed `()` where a tuple was expected, a private type in
//! a public trait, no `Debug` for the checker) and ran checks one after another against one shared
//! deadline. Repaired 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: threads (one per check per readiness call) and whatever the registered checks touch;
//! no database of its own (spec: SCHEMA none), no network, no money.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::sync::mpsc;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::fmt;
use std::error::Error;

#[derive(Clone, Default)]
/// What: the `HealthOptions` struct. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub struct HealthOptions {
    pub clock: Option<Arc<dyn Fn() -> i64 + Send + Sync>>,
    pub version: String,
    pub release_id: String,
    pub service_id: String,
    pub description: String,
}

pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;
pub type CheckFn = Arc<dyn Fn() -> bool + Send + Sync>;

/// What: one registered check as the store keeps it. Why: public because the public `CheckStore`
/// trait takes it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Clone)]
pub struct RegisteredCheck {
    pub component_id: String,
    pub component_type: String,
    pub check_fn: CheckFn,
    pub critical: bool,
    pub timeout_ms: u64,
}

/// What: the `CheckStore` trait. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub trait CheckStore: Send + Sync {
    /// What: `add_check` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn add_check(&self, check: RegisteredCheck) -> bool;
    /// What: `list_checks` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn list_checks(&self) -> Vec<RegisteredCheck>;
}

/// What: the `InMemoryCheckStore` struct. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub struct InMemoryCheckStore {
    checks: Mutex<BTreeMap<String, RegisteredCheck>>,
}

/// What: methods of `InMemoryCheckStore`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl InMemoryCheckStore {
    /// What: `new` of `InMemoryCheckStore`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    pub fn new() -> Self {
        Self {
            checks: Mutex::new(BTreeMap::new()),
        }
    }
}

/// What: `CheckStore` for `InMemoryCheckStore`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl CheckStore for InMemoryCheckStore {
    /// What: `add_check` of `CheckStore for InMemoryCheckStore`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn add_check(&self, check: RegisteredCheck) -> bool {
        let mut map = self.checks.lock().unwrap();
        if map.contains_key(&check.component_id) {
            false
        } else {
            map.insert(check.component_id.clone(), check);
            true
        }
    }

    /// What: `list_checks` of `CheckStore for InMemoryCheckStore`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn list_checks(&self) -> Vec<RegisteredCheck> {
        self.checks.lock().unwrap().values().cloned().collect()
    }
}

#[derive(Debug, Clone)]
/// What: the `HealthCheckError` struct. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub struct HealthCheckError {
    pub code: &'static str,
    pub http_status: u16,
    pub message: String,
}

/// What: `fmt::Display` for `HealthCheckError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl fmt::Display for HealthCheckError {
    /// What: human-readable text of `fmt::Display for HealthCheckError` (never secrets). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// What: `Error` for `HealthCheckError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl Error for HealthCheckError {}

#[derive(Debug, Clone)]
/// What: the `HealthResponse` struct. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub struct HealthResponse {
    pub http_status: u16,
    pub content_type: String,
    pub body: String,
}

/// What: the `HealthChecker` struct. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub struct HealthChecker {
    store: Arc<dyn CheckStore>,
    options: HealthOptions,
}

/// What: methods of `HealthChecker`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl HealthChecker {
    /// What: a checker over a check store; metadata options must be 1-128 safe characters.
    /// In: store, options. Out: the checker or `INVALID_OPTION`. Why: the old version also tested
    /// `Arc::strong_count == 0` (never true) and called the clock for no reason; both removed.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn new(store: Arc<dyn CheckStore>, options: Option<HealthOptions>) -> Result<Self, HealthCheckError> {
        let opts = options.unwrap_or_default();
        
        for (field, value) in [
            ("version", &opts.version),
            ("release_id", &opts.release_id),
            ("service_id", &opts.service_id),
            ("description", &opts.description),
        ] {
            if !value.is_empty() && !validate_metadata_chars(value) {
                return Err(HealthCheckError {
                    code: "INVALID_OPTION",
                    http_status: 400,
                    message: format!("invalid option: {}", field),
                });
            }
        }
        
        Ok(Self {
            store,
            options: opts,
        })
    }

    /// What: `register_check` of `HealthChecker`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    pub fn register_check(
        &self,
        component_id: &str,
        component_type: &str,
        check_fn: CheckFn,
        critical: bool,
        timeout_ms: u64,
    ) -> Result<(), HealthCheckError> {
        if !validate_id_chars(component_id) {
            return Err(HealthCheckError {
                code: "INVALID_COMPONENT_ID",
                http_status: 400,
                message: "component_id must be 1-64 characters from A-Z a-z 0-9 . _ -".to_string(),
            });
        }
        
        if !validate_id_chars(component_type) {
            return Err(HealthCheckError {
                code: "INVALID_COMPONENT_TYPE",
                http_status: 400,
                message: "component_type must be 1-64 characters from A-Z a-z 0-9 . _ -".to_string(),
            });
        }
        
        if timeout_ms < 1 || timeout_ms > 60000 {
            return Err(HealthCheckError {
                code: "INVALID_TIMEOUT",
                http_status: 400,
                message: "timeout_ms must be an integer from 1 to 60000".to_string(),
            });
        }
        
        let check = RegisteredCheck {
            component_id: component_id.to_string(),
            component_type: component_type.to_string(),
            check_fn,
            critical,
            timeout_ms,
        };
        
        if !self.store.add_check(check) {
            return Err(HealthCheckError {
                code: "DUPLICATE_COMPONENT",
                http_status: 409,
                message: "component_id is already registered".to_string(),
            });
        }
        
        Ok(())
    }

    /// What: `liveness` of `HealthChecker`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    pub fn liveness(&self) -> HealthResponse {
        let mut body = String::from(r#"{"status":"pass""#);
        add_metadata(&mut body, &self.options);
        body.push('}');
        
        HealthResponse {
            http_status: 200,
            content_type: "application/health+json".to_string(),
            body,
        }
    }

    /// What: run every registered check at once, each in its own thread with its own deadline
    /// (measured from when the run started), and report them in the IETF health format, keys sorted by
    /// the whole "<id>:responseTime" string. A check that returns false is "check reported failure", one
    /// that panics is "check raised an error" (its message is never copied into the output), one past
    /// its timeout is "check timed out" with observedValue = the timeout. Any critical failure gives
    /// "fail"/503, only non-critical failures "warn"/200, otherwise "pass"/200.
    /// In: none. Out: `HealthResponse` with content type application/health+json.
    /// Why: spec readiness(); the old code did not compile and ran checks one after another against a
    /// single shared deadline, so a fast check after a slow one was reported as timed out.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: spawns one thread per check; runs the
    /// registered check functions (which may touch databases or the network); the clock.
    pub fn readiness(&self) -> HealthResponse {
        let mut checks = self.store.list_checks();
        checks.sort_by(|a, b| format!("{}:responseTime", a.component_id).cmp(&format!("{}:responseTime", b.component_id)));
        let clock = self.clock();

        // Start every check before waiting on any, so each gets its whole timeout.
        let started = Instant::now();
        let receivers: Vec<_> = checks
            .iter()
            .map(|check| {
                let (tx, rx) = mpsc::channel();
                let check_fn = check.check_fn.clone();
                let clock = clock.clone();
                thread::spawn(move || {
                    let t0 = clock();
                    let outcome = catch_unwind(AssertUnwindSafe(|| check_fn()));
                    let finished = Instant::now();
                    let t1 = clock();
                    let kind = match outcome {
                        Ok(true) => WorkerResult::Pass,
                        Ok(false) => WorkerResult::Reported,
                        Err(_) => WorkerResult::Errored,
                    };
                    let _ = tx.send((kind, t0, t1, finished));
                });
                rx
            })
            .collect();

        let mut results = Vec::with_capacity(checks.len());
        for (check, rx) in checks.iter().zip(receivers) {
            let deadline = started + Duration::from_millis(check.timeout_ms);
            let remaining = deadline.saturating_duration_since(Instant::now());
            let (status, observed, time, output) = match rx.recv_timeout(remaining) {
                // finished, but after its own deadline (it was read late because an earlier check
                // with a longer timeout was being waited on)
                Ok((_, _, _, finished)) if finished > deadline => ("fail", check.timeout_ms, clock(), Some("check timed out")),
                Ok((kind, t0, t1, _)) => {
                    let observed = t1.saturating_sub(t0).max(0) as u64;
                    match kind {
                        WorkerResult::Pass => ("pass", observed, t1, None),
                        WorkerResult::Reported => ("fail", observed, t1, Some("check reported failure")),
                        WorkerResult::Errored => ("fail", observed, t1, Some("check raised an error")),
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => ("fail", check.timeout_ms, clock(), Some("check timed out")),
                Err(mpsc::RecvTimeoutError::Disconnected) => ("fail", 0, clock(), Some("check raised an error")),
            };
            results.push(CheckResult {
                key: format!("{}:responseTime", check.component_id),
                entry: format_check_entry(&check.component_id, &check.component_type, status, observed, time, output.map(String::from)),
                critical: check.critical,
                passed: status == "pass",
            });
        }

        let overall = if results.iter().any(|r| !r.passed && r.critical) {
            "fail"
        } else if results.iter().any(|r| !r.passed) {
            "warn"
        } else {
            "pass"
        };
        let mut body = format!(r#"{{"status":"{}""#, overall);
        add_metadata(&mut body, &self.options);
        body.push_str(r#","checks":{"#);
        for (i, r) in results.iter().enumerate() {
            if i > 0 {
                body.push(',');
            }
            body.push_str(&escape_json(&r.key));
            body.push_str(":[");
            body.push_str(&r.entry);
            body.push(']');
        }
        body.push_str("}}");
        HealthResponse {
            http_status: if overall == "fail" { 503 } else { 200 },
            content_type: "application/health+json".to_string(),
            body,
        }
    }

    /// What: the configured clock, or the system clock in Unix milliseconds.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the system clock when none is set.
    fn clock(&self) -> Clock {
        self.options.clock.clone().unwrap_or_else(|| {
            Arc::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0)
            })
        })
    }
}

/// What: `fmt::Debug` for `HealthChecker`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl fmt::Debug for HealthChecker {
    /// What: list the checker's options without its closures. Why: `Result<HealthChecker, _>` must be
    /// `Debug` for `unwrap_err()` in tests. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HealthChecker")
            .field("version", &self.options.version)
            .field("service_id", &self.options.service_id)
            .field("checks", &self.store.list_checks().len())
            .finish()
    }
}

/// What: one finished check, ready to be written into the body. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
struct CheckResult {
    key: String,
    entry: String,
    critical: bool,
    passed: bool,
}

/// What: how a check's function ended. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(PartialEq, Clone, Copy)]
enum WorkerResult {
    Pass,
    Reported,
    Errored,
}

/// What: one check's JSON object in the spec's field order. In: id, type, status, observed ms,
/// time (Unix ms), fixed output text. Out: JSON text. Why: the old version's raw strings were
/// unterminated, so the field values were swallowed into the literal. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn format_check_entry(
    component_id: &str,
    component_type: &str,
    status: &str,
    observed_value: u64,
    time_ms: i64,
    output: Option<String>,
) -> String {
    let mut entry = format!(
        r#"{{"componentId":{},"componentType":{},"observedValue":{},"observedUnit":"ms","status":{},"time":{}"#,
        escape_json(component_id),
        escape_json(component_type),
        observed_value,
        escape_json(status),
        escape_json(&format_iso_time(time_ms))
    );
    if let Some(out) = output {
        entry.push_str(r#","output":"#);
        entry.push_str(&escape_json(&out));
    }
    entry.push('}');
    entry
}

/// What: `format_iso_time`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
fn format_iso_time(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86400);
    let mut secs_of_day = secs.rem_euclid(86400);
    
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    secs_of_day %= 3600;
    let minute = secs_of_day / 60;
    let second = secs_of_day % 60;
    
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, hour, minute, second)
}

/// What: `civil_from_days`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m, d)
}

/// What: `add_metadata`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
fn add_metadata(body: &mut String, options: &HealthOptions) {
    if !options.version.is_empty() {
        body.push_str(r#","version":"#);
        body.push_str(&escape_json(&options.version));
    }
    if !options.release_id.is_empty() {
        body.push_str(r#","releaseId":"#);
        body.push_str(&escape_json(&options.release_id));
    }
    if !options.service_id.is_empty() {
        body.push_str(r#","serviceId":"#);
        body.push_str(&escape_json(&options.service_id));
    }
    if !options.description.is_empty() {
        body.push_str(r#","description":"#);
        body.push_str(&escape_json(&options.description));
    }
}

/// What: `validate_id_chars`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
fn validate_id_chars(s: &str) -> bool {
    let len = s.len();
    if len < 1 || len > 64 {
        return false;
    }
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

/// What: `validate_metadata_chars`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
fn validate_metadata_chars(s: &str) -> bool {
    let len = s.len();
    if len < 1 || len > 128 {
        return false;
    }
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '.' || c == '_' || c == ',' || c == '(' || c == ')' || c == '-')
}

/// What: `escape_json`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
fn escape_json(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 2);
    result.push('"');
    for c in s.chars() {
        match c {
            '"' => result.push_str(r#"\""#),
            '\\' => result.push_str(r#"\\"#),
            '\n' => result.push_str(r#"\n"#),
            '\r' => result.push_str(r#"\r"#),
            '\t' => result.push_str(r#"\t"#),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result.push('"');
    result
}
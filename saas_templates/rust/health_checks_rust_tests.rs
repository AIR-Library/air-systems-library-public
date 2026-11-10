//! Health checks tests (TIER 3 spec, system 6). Touches: threads and memory only.
mod health_checks_rust;

use health_checks_rust::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::Duration;

fn fixed_clock() -> Clock {
    Arc::new(|| 1767225600000)
}

fn make_checker() -> (Arc<InMemoryCheckStore>, HealthChecker) {
    let store = Arc::new(InMemoryCheckStore::new());
    let options = HealthOptions {
        clock: Some(fixed_clock()),
        ..Default::default()
    };
    let checker = HealthChecker::new(store.clone(), Some(options)).unwrap();
    (store, checker)
}

#[test]
fn test_all_checks_pass_returns_200_pass() {
    let (_, checker) = make_checker();
    checker.register_check("db", "datastore", Arc::new(|| true), true, 5000).unwrap();
    checker.register_check("cache", "component", Arc::new(|| true), false, 5000).unwrap();
    
    let resp = checker.readiness();
    assert_eq!(resp.http_status, 200);
    assert_eq!(resp.content_type, "application/health+json");
    let expected = r#"{"status":"pass","checks":{"cache:responseTime":[{"componentId":"cache","componentType":"component","observedValue":0,"observedUnit":"ms","status":"pass","time":"2026-01-01T00:00:00Z"}],"db:responseTime":[{"componentId":"db","componentType":"datastore","observedValue":0,"observedUnit":"ms","status":"pass","time":"2026-01-01T00:00:00Z"}]}}"#;
    assert_eq!(resp.body, expected);
}

#[test]
fn test_critical_check_fails_returns_503_fail() {
    let (_, checker) = make_checker();
    checker.register_check("db", "datastore", Arc::new(|| false), true, 5000).unwrap();
    checker.register_check("cache", "component", Arc::new(|| true), false, 5000).unwrap();
    
    let resp = checker.readiness();
    assert_eq!(resp.http_status, 503);
    assert_eq!(resp.content_type, "application/health+json");
    let expected = r#"{"status":"fail","checks":{"cache:responseTime":[{"componentId":"cache","componentType":"component","observedValue":0,"observedUnit":"ms","status":"pass","time":"2026-01-01T00:00:00Z"}],"db:responseTime":[{"componentId":"db","componentType":"datastore","observedValue":0,"observedUnit":"ms","status":"fail","time":"2026-01-01T00:00:00Z","output":"check reported failure"}]}}"#;
    assert_eq!(resp.body, expected);
}

#[test]
fn test_only_non_critical_fails_returns_200_warn() {
    let (_, checker) = make_checker();
    checker.register_check("db", "datastore", Arc::new(|| true), true, 5000).unwrap();
    checker.register_check("cache", "component", Arc::new(|| false), false, 5000).unwrap();
    
    let resp = checker.readiness();
    assert_eq!(resp.http_status, 200);
    assert_eq!(resp.content_type, "application/health+json");
    let expected = r#"{"status":"warn","checks":{"cache:responseTime":[{"componentId":"cache","componentType":"component","observedValue":0,"observedUnit":"ms","status":"fail","time":"2026-01-01T00:00:00Z","output":"check reported failure"}],"db:responseTime":[{"componentId":"db","componentType":"datastore","observedValue":0,"observedUnit":"ms","status":"pass","time":"2026-01-01T00:00:00Z"}]}}"#;
    assert_eq!(resp.body, expected);
}

#[test]
fn test_slow_check_past_timeout_fails_that_check() {
    let (_, checker) = make_checker();
    checker.register_check("fast", "component", Arc::new(|| true), false, 5000).unwrap();
    checker.register_check("slow", "component", Arc::new(|| {
        thread::sleep(Duration::from_millis(1000));
        true
    }), true, 100).unwrap();
    
    let resp = checker.readiness();
    assert_eq!(resp.http_status, 503);
    assert_eq!(resp.content_type, "application/health+json");
    let expected = r#"{"status":"fail","checks":{"fast:responseTime":[{"componentId":"fast","componentType":"component","observedValue":0,"observedUnit":"ms","status":"pass","time":"2026-01-01T00:00:00Z"}],"slow:responseTime":[{"componentId":"slow","componentType":"component","observedValue":100,"observedUnit":"ms","status":"fail","time":"2026-01-01T00:00:00Z","output":"check timed out"}]}}"#;
    assert_eq!(resp.body, expected);
}

#[test]
fn test_liveness_passes_when_dependency_would_fail() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();
    
    let (_, checker) = make_checker();
    checker.register_check("db", "datastore", Arc::new(move || {
        counter_clone.fetch_add(1, Ordering::SeqCst);
        panic!("db down");
    }), true, 5000).unwrap();
    
    let live = checker.liveness();
    assert_eq!(live.http_status, 200);
    assert_eq!(live.content_type, "application/health+json");
    assert_eq!(live.body, r#"{"status":"pass"}"#);
    assert_eq!(counter.load(Ordering::SeqCst), 0);
    
    let ready = checker.readiness();
    assert_eq!(ready.http_status, 503);
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[test]
fn test_output_contains_no_connection_string() {
    let (_, checker) = make_checker();
    let error_msg = "connect failed: postgres://admin:s3cret@db.internal:5432/app";
    checker.register_check("db", "datastore", Arc::new(move || {
        panic!("{}", error_msg);
    }), true, 5000).unwrap();
    
    let resp = checker.readiness();
    assert_eq!(resp.http_status, 503);
    assert!(!resp.body.contains("postgres://"));
    assert!(!resp.body.contains("s3cret"));
    assert!(!resp.body.contains("admin"));
    assert!(!resp.body.contains("5432"));
    let expected = r#"{"status":"fail","checks":{"db:responseTime":[{"componentId":"db","componentType":"datastore","observedValue":0,"observedUnit":"ms","status":"fail","time":"2026-01-01T00:00:00Z","output":"check raised an error"}]}}"#;
    assert_eq!(resp.body, expected);
    
    let err = checker.register_check("postgres://admin:s3cret@db", "datastore", Arc::new(|| true), true, 5000);
    assert!(err.is_err());
    let err = err.unwrap_err();
    assert_eq!(err.code, "INVALID_COMPONENT_ID");
    assert!(!err.message.contains("s3cret"));
}

#[test]
fn test_zero_checks_is_pass_with_empty_checks_object() {
    let (_, checker) = make_checker();
    let ready = checker.readiness();
    assert_eq!(ready.http_status, 200);
    assert_eq!(ready.body, r#"{"status":"pass","checks":{}}"#);
    
    let live = checker.liveness();
    assert_eq!(live.body, r#"{"status":"pass"}"#);
}

#[test]
fn test_metadata_in_fixed_order() {
    let store = Arc::new(InMemoryCheckStore::new());
    let options = HealthOptions {
        clock: Some(fixed_clock()),
        version: "1.2.2".to_string(),
        service_id: "billing-api".to_string(),
        description: "billing service".to_string(),
        ..Default::default()
    };
    let checker = HealthChecker::new(store, Some(options)).unwrap();
    
    let live = checker.liveness();
    assert_eq!(live.body, r#"{"status":"pass","version":"1.2.2","serviceId":"billing-api","description":"billing service"}"#);
    
    let ready = checker.readiness();
    assert_eq!(ready.body, r#"{"status":"pass","version":"1.2.2","serviceId":"billing-api","description":"billing service","checks":{}}"#);
    
    let bad_options = HealthOptions {
        clock: Some(fixed_clock()),
        version: "1.2.2/beta".to_string(),
        ..Default::default()
    };
    let err = HealthChecker::new(Arc::new(InMemoryCheckStore::new()), Some(bad_options));
    assert!(err.is_err());
    assert_eq!(err.unwrap_err().code, "INVALID_OPTION");
}

#[test]
fn test_checks_sorted_by_whole_key_ordinal() {
    let (_, checker) = make_checker();
    checker.register_check("a", "component", Arc::new(|| true), true, 5000).unwrap();
    checker.register_check("a-b", "component", Arc::new(|| true), true, 5000).unwrap();
    
    let resp = checker.readiness();
    let expected = r#"{"status":"pass","checks":{"a-b:responseTime":[{"componentId":"a-b","componentType":"component","observedValue":0,"observedUnit":"ms","status":"pass","time":"2026-01-01T00:00:00Z"}],"a:responseTime":[{"componentId":"a","componentType":"component","observedValue":0,"observedUnit":"ms","status":"pass","time":"2026-01-01T00:00:00Z"}]}}"#;
    assert_eq!(resp.body, expected);
}

#[test]
fn test_each_check_has_its_own_deadline() {
    let (_, checker) = make_checker();
    checker.register_check("alpha", "component", Arc::new(|| {
        thread::sleep(Duration::from_millis(600));
        true
    }), true, 5000).unwrap();
    checker.register_check("beta", "component", Arc::new(|| {
        thread::sleep(Duration::from_millis(300));
        true
    }), false, 100).unwrap();
    
    let resp = checker.readiness();
    assert_eq!(resp.http_status, 200);
    let expected = r#"{"status":"warn","checks":{"alpha:responseTime":[{"componentId":"alpha","componentType":"component","observedValue":0,"observedUnit":"ms","status":"pass","time":"2026-01-01T00:00:00Z"}],"beta:responseTime":[{"componentId":"beta","componentType":"component","observedValue":100,"observedUnit":"ms","status":"fail","time":"2026-01-01T00:00:00Z","output":"check timed out"}]}}"#;
    assert_eq!(resp.body, expected);
}

#[test]
fn test_invalid_registrations_are_rejected() {
    let (_, checker) = make_checker();
    
    let err = checker.register_check("", "datastore", Arc::new(|| true), true, 5000);
    assert_eq!(err.unwrap_err().code, "INVALID_COMPONENT_ID");
    
    let err = checker.register_check("db:main", "datastore", Arc::new(|| true), true, 5000);
    assert_eq!(err.unwrap_err().code, "INVALID_COMPONENT_ID");
    
    let long_id = "a".repeat(65);
    let err = checker.register_check(&long_id, "datastore", Arc::new(|| true), true, 5000);
    assert_eq!(err.unwrap_err().code, "INVALID_COMPONENT_ID");
    
    let err = checker.register_check("db", "", Arc::new(|| true), true, 5000);
    assert_eq!(err.unwrap_err().code, "INVALID_COMPONENT_TYPE");
    
    let err = checker.register_check("db", "datastore", Arc::new(|| true), true, 0);
    assert_eq!(err.unwrap_err().code, "INVALID_TIMEOUT");
    
    let err = checker.register_check("db", "datastore", Arc::new(|| true), true, 60001);
    assert_eq!(err.unwrap_err().code, "INVALID_TIMEOUT");
    
    checker.register_check("db", "datastore", Arc::new(|| true), true, 5000).unwrap();
    // Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): `unwrap_err()` consumed `err`, so the
    // second assertion could not compile; the error is unwrapped once and both fields are asserted.
    let err = checker.register_check("db", "datastore", Arc::new(|| true), true, 5000).unwrap_err();
    assert_eq!(err.code, "DUPLICATE_COMPONENT");
    assert_eq!(err.http_status, 409);
    
    let ready = checker.readiness();
    assert!(ready.body.contains(r#""db:responseTime""#));
}

#[test]
fn test_fast_check_after_slow_one_is_not_timed_out() {
    let (_, checker) = make_checker();
    checker.register_check("a", "component", Arc::new(|| {
        thread::sleep(Duration::from_millis(1000));
        true
    }), true, 5000).unwrap();
    
    for i in 1..=8 {
        let id = format!("b{}", i);
        checker.register_check(&id, "component", Arc::new(|| true), true, 100).unwrap();
    }
    
    let resp = checker.readiness();
    assert_eq!(resp.http_status, 200);
    
    let mut expected = String::from(r#"{"status":"pass","checks":{"#);
    let ids: Vec<String> = (1..=8).map(|i| format!("b{}", i)).collect();
    let mut all_ids = vec!["a".to_string()];
    all_ids.extend(ids);
    all_ids.sort_by(|a, b| {
        let ka = format!("{}:responseTime", a);
        let kb = format!("{}:responseTime", b);
        ka.cmp(&kb)
    });
    
    for (i, id) in all_ids.iter().enumerate() {
        if i > 0 {
            expected.push(',');
        }
        expected.push_str(&format!(r#""{}:responseTime":[{{"componentId":"{}","componentType":"component","observedValue":0,"observedUnit":"ms","status":"pass","time":"2026-01-01T00:00:00Z"}}]"#, id, id));
    }
    expected.push_str(r#"}}"#);
    
    assert_eq!(resp.body, expected);
}
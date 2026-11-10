//! Trial abuse prevention tests (GEMINI spec, template #3). Touches: in-memory SQLite only.
use super::*;
use chrono::{Duration, Utc};

#[test]
fn email_trial_history_pass() {
    let db = Database::new_in_memory().unwrap();
    let result = db.check_email_trial_history("new@example.com").unwrap();
    assert_eq!(result.decision, Decision::Pass);
}

#[test]
fn email_trial_history_challenge() {
    let db = Database::new_in_memory().unwrap();
    db.insert_trial_abuse_ledger(
        Some(1),
        Some("repeat@example.com"),
        None,
        None,
        None,
        None,
        None,
        None,
        Some("completed"),
    )
    .unwrap();
    let result = db.check_email_trial_history("repeat@example.com").unwrap();
    assert_eq!(result.decision, Decision::Challenge);
}

#[test]
fn email_trial_history_fail() {
    let db = Database::new_in_memory().unwrap();
    db.insert_trial_abuse_ledger(
        Some(1),
        Some("bad@example.com"),
        None,
        None,
        None,
        None,
        None,
        None,
        Some("completed"),
    )
    .unwrap();
    db.insert_trial_abuse_ledger(
        Some(2),
        Some("bad@example.com"),
        None,
        None,
        None,
        None,
        None,
        None,
        Some("completed"),
    )
    .unwrap();
    let result = db.check_email_trial_history("bad@example.com").unwrap();
    assert_eq!(result.decision, Decision::Fail);
}

#[test]
fn payment_method_history_pass() {
    let db = Database::new_in_memory().unwrap();
    let result = db.check_payment_method_history("pm_new").unwrap();
    assert_eq!(result.decision, Decision::Pass);
}

#[test]
fn payment_method_history_fail() {
    let db = Database::new_in_memory().unwrap();
    db.insert_trial_abuse_ledger(
        Some(1),
        None,
        Some("pm_reuse"),
        None,
        None,
        None,
        None,
        None,
        Some("completed"),
    )
    .unwrap();
    db.insert_trial_abuse_ledger(
        Some(2),
        None,
        Some("pm_reuse"),
        None,
        None,
        None,
        None,
        None,
        Some("completed"),
    )
    .unwrap();
    db.insert_trial_abuse_ledger(
        Some(3),
        None,
        Some("pm_reuse"),
        None,
        None,
        None,
        None,
        None,
        Some("completed"),
    )
    .unwrap();
    let result = db.check_payment_method_history("pm_reuse").unwrap();
    assert_eq!(result.decision, Decision::Fail);
}

#[test]
fn ip_signup_rate_limit_pass() {
    let db = Database::new_in_memory().unwrap();
    for _ in 0..4 {
        db.insert_signup("192.0.2.1").unwrap();
    }
    let result = db.check_ip_signup_rate_limit("192.0.2.1").unwrap();
    assert_eq!(result.decision, Decision::Pass);
}

#[test]
fn ip_signup_rate_limit_fail() {
    let db = Database::new_in_memory().unwrap();
    for _ in 0..10 {
        db.insert_signup("203.0.113.5").unwrap();
    }
    let result = db.check_ip_signup_rate_limit("203.0.113.5").unwrap();
    assert_eq!(result.decision, Decision::Fail);
}

#[test]
fn device_fingerprint_pass() {
    let db = Database::new_in_memory().unwrap();
    let device = DeviceInfo {
        user_agent: "UA".to_string(),
        screen_resolution: "1920x1080".to_string(),
        timezone: "UTC".to_string(),
        browser_language: "en-US".to_string(),
    };
    db.insert_device_fingerprint(1, &device).unwrap();
    let result = db.check_device_fingerprint(&device, Some(2)).unwrap();
    assert_eq!(result.decision, Decision::Pass);
}

#[test]
fn device_fingerprint_fail() {
    let db = Database::new_in_memory().unwrap();
    let device = DeviceInfo {
        user_agent: "UA".to_string(),
        screen_resolution: "1920x1080".to_string(),
        timezone: "UTC".to_string(),
        browser_language: "en-US".to_string(),
    };
    for i in 1..=6 {
        db.insert_device_fingerprint(i, &device).unwrap();
    }
    let result = db.check_device_fingerprint(&device, Some(7)).unwrap();
    assert_eq!(result.decision, Decision::Fail);
}

#[test]
fn trial_payment_timing_pass() {
    let db = Database::new_in_memory().unwrap();
    let trial_start = Utc::now() - Duration::days(10);
    db.insert_trial_abuse_ledger(
        Some(1),
        None,
        None,
        None,
        None,
        None,
        Some(&trial_start.to_rfc3339()),
        Some(&Utc::now().to_rfc3339()),
        Some("completed"),
    )
    .unwrap();
    let result = db.check_trial_payment_timing(1, 30).unwrap();
    assert_eq!(result.decision, Decision::Pass);
}

#[test]
fn trial_payment_timing_fail() {
    let db = Database::new_in_memory().unwrap();
    let trial_start = Utc::now() - Duration::days(120);
    db.insert_trial_abuse_ledger(
        Some(1),
        None,
        None,
        None,
        None,
        None,
        Some(&trial_start.to_rfc3339()),
        None,
        Some("completed"),
    )
    .unwrap();
    let result = db.check_trial_payment_timing(1, 30).unwrap();
    assert_eq!(result.decision, Decision::Fail);
}

#[test]
fn chargeback_history_pass() {
    let db = Database::new_in_memory().unwrap();
    let result = db.check_chargeback_history(1).unwrap();
    assert_eq!(result.decision, Decision::Pass);
}

#[test]
fn chargeback_history_fail() {
    let db = Database::new_in_memory().unwrap();
    // Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): nothing tied user 1 to customer
    // "cust_1", so no implementation could count these events for user 1 without inventing the link.
    // The link is now made explicitly; the event inserts are unwrapped instead of ignored.
    db.link_billing_customer(1, "cust_1").unwrap();
    db.insert_stripe_event("cust_1", "chargeback").unwrap();
    db.insert_stripe_event("cust_1", "chargeback").unwrap();
    db.insert_refund(1, "chargebacked").unwrap();
    let result = db.check_chargeback_history(1).unwrap();
    assert_eq!(result.decision, Decision::Fail);
}
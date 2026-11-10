//! Trial abuse prevention tests (GEMINI spec, template #3). Touches: in-memory SQLite only.
use super::*;
use chrono::{Duration, Utc};

// TRIAL-01
#[test]
fn email_trial_history_pass() {
    let db = Database::new_in_memory().unwrap();
    let result = db.check_email_trial_history("new@example.com").unwrap();
    assert_eq!(result.decision, Decision::Pass);
}

// TRIAL-02
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

// TRIAL-03
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

// TRIAL-04
#[test]
fn payment_method_history_pass() {
    let db = Database::new_in_memory().unwrap();
    let result = db.check_payment_method_history("pm_new").unwrap();
    assert_eq!(result.decision, Decision::Pass);
}

// TRIAL-05
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

// TRIAL-06
#[test]
fn ip_signup_rate_limit_pass() {
    let db = Database::new_in_memory().unwrap();
    for _ in 0..4 {
        db.insert_signup("192.0.2.1").unwrap();
    }
    let result = db.check_ip_signup_rate_limit("192.0.2.1").unwrap();
    assert_eq!(result.decision, Decision::Pass);
}

/// What: TRIAL-07: 10 signups from one IP -> FAIL, 429 too_many_signups_from_ip. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP:
/// the response assertion was added. Touches: in-memory SQLite.
// TRIAL-07
#[test]
fn ip_signup_rate_limit_fail() {
    let db = Database::new_in_memory().unwrap();
    for _ in 0..10 {
        db.insert_signup("203.0.113.5").unwrap();
    }
    let result = db.check_ip_signup_rate_limit("203.0.113.5").unwrap();
    assert_eq!(result.decision, Decision::Fail);
    let err = fail_response(&result).unwrap();
    assert_eq!((err.error.as_str(), err.code), ("too_many_signups_from_ip", 429));
}

/// What: TRIAL-08: one other user on the device -> PASS, and the device row is then written. Changed
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the row assertion was added (TRIAL-14 amendment). Touches: in-memory SQLite.
// TRIAL-08
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
    // 2026-11-10 amendment, session_012zDydZCZ4AChqhEZ4oVtaP: the row is written after a PASS
    assert_eq!(db.device_rows_for_user(2).unwrap(), 1);
}

/// What: TRIAL-09: six other users on the device -> FAIL (403 device_suspected_fraud) and no row is
/// written. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the response and no-row assertions were added. Touches: in-memory SQLite.
// TRIAL-09
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
    assert_eq!(fail_response(&result).unwrap().error, "device_suspected_fraud");
    // 2026-11-10 amendment, session_012zDydZCZ4AChqhEZ4oVtaP: a FAIL records no device row
    assert_eq!(db.device_rows_for_user(7).unwrap(), 0);
}

/// What: a database whose clock is `now`, with user 1 created (trial started) at `created`.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
fn timing_db(created: chrono::DateTime<Utc>, now: chrono::DateTime<Utc>) -> Database {
    let db = Database::new_in_memory().unwrap().with_clock(Box::new(move || now));
    db.insert_trial_abuse_ledger(Some(1), None, None, None, None, Some(&created.to_rfc3339()), Some(&created.to_rfc3339()), None, None).unwrap();
    db
}

/// What: TRIAL-10: a first payment 4 days (4 days 23 hours: floor is 4) after the 14-day trial ended,
/// and one during the trial, PASS. In: none. Out: panics on a wrong decision.
/// Why: changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the old test passed trial_days = 30 and
/// a payment already in the ledger, the rule the 2026-11-10 amendment replaced (days after trial_end =
/// created_at + trial_days, default 14). Touches: in-memory SQLite.
// TRIAL-10
#[test]
fn trial_payment_timing_pass() {
    let created = Utc::now() - Duration::days(100);
    let db = timing_db(created, created + Duration::days(14 + 4) + Duration::hours(23));
    assert_eq!(db.check_trial_payment_timing(1).unwrap().decision, Decision::Pass);
    // during the trial (days_after_trial is negative; floor toward negative infinity)
    let db = timing_db(created, created + Duration::days(13) + Duration::hours(12));
    let result = db.check_trial_payment_timing(1).unwrap();
    assert_eq!(result.decision, Decision::Pass);
    assert_eq!(result.rule_inputs["payment_delay"], -1);
}

/// What: TRIAL-11: a first payment 90 days after the trial ended, with no earlier payment, FAIL with
/// 403 trial_ended_no_payment_cannot_retry. In: none. Out: panics on a wrong decision.
/// Why: changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the old test used trial_days = 30 and
/// "more than 90 days since the trial started", the rule the amendment replaced. Touches: in-memory SQLite.
// TRIAL-11
#[test]
fn trial_payment_timing_fail() {
    let created = Utc::now() - Duration::days(200);
    let db = timing_db(created, created + Duration::days(14 + 90));
    let result = db.check_trial_payment_timing(1).unwrap();
    assert_eq!(result.decision, Decision::Fail);
    let err = fail_response(&result).unwrap();
    assert_eq!((err.error.as_str(), err.code), ("trial_ended_no_payment_cannot_retry", 403));
}

/// What: TRIAL-15: 5 and 89 days after the trial CHALLENGE; 90 days with an earlier payment CHALLENGE;
/// a configured trial length moves trial_end. In: none. Out: panics on a wrong decision.
/// Why: 2026-11-10 amendment (TRIAL-15). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
// TRIAL-15
#[test]
fn trial_payment_timing_boundaries() {
    let created = Utc::now() - Duration::days(200);
    for days in [5, 89] {
        let db = timing_db(created, created + Duration::days(14 + days));
        assert_eq!(db.check_trial_payment_timing(1).unwrap().decision, Decision::Challenge, "{} days", days);
    }
    let db = timing_db(created, created + Duration::days(14 + 90));
    db.insert_trial_abuse_ledger(Some(1), None, Some("pm_1"), None, None, None, None, Some(&(created + Duration::days(3)).to_rfc3339()), None).unwrap();
    assert_eq!(db.check_trial_payment_timing(1).unwrap().decision, Decision::Challenge);
    // trial_days is configuration: with a 30-day trial, day 34 is 4 days after it ended
    let db = timing_db(created, created + Duration::days(34)).with_trial_days(30);
    assert_eq!(db.check_trial_payment_timing(1).unwrap().decision, Decision::Pass);
}

/// What: TRIAL-14: 4 other users CHALLENGE (and the row is written); exactly 5 other users FAIL, even
/// when this user already has the device; a FAIL records no device row. In: none. Out: panics on a
/// wrong decision. Why: 2026-11-10 amendment (TRIAL-14). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: in-memory SQLite.
// TRIAL-14
#[test]
fn device_fingerprint_boundaries() {
    let db = Database::new_in_memory().unwrap();
    let device = DeviceInfo { user_agent: "UA".into(), screen_resolution: "1920x1080".into(), timezone: "UTC".into(), browser_language: "en-US".into() };
    for i in 1..=4 {
        db.insert_device_fingerprint(i, &device).unwrap();
    }
    assert_eq!(db.check_device_fingerprint(&device, Some(10)).unwrap().decision, Decision::Challenge);
    assert_eq!(db.device_rows_for_user(10).unwrap(), 1);
    // user 10 is now the 5th user: for user 11, 5 others -> FAIL, no row
    assert_eq!(db.check_device_fingerprint(&device, Some(11)).unwrap().decision, Decision::Fail);
    assert_eq!(db.device_rows_for_user(11).unwrap(), 0);
    // user 1 already has the device, but there are 4 others: known device PASS
    assert_eq!(db.check_device_fingerprint(&device, Some(1)).unwrap().decision, Decision::Pass);
    // one more other user: user 1 now sees exactly 5 others -> FAIL even though the device is known
    db.insert_device_fingerprint(5, &device).unwrap();
    let before = db.device_rows_for_user(1).unwrap();
    assert_eq!(db.check_device_fingerprint(&device, Some(1)).unwrap().decision, Decision::Fail);
    assert_eq!(db.device_rows_for_user(1).unwrap(), before);
}

/// What: TRIAL-09 through signup: on a device already used by 5 users, signup runs the device gate
/// before recording anything and is refused 403 device_suspected_fraud with no device, signup or
/// ledger row; a later signup from the same device is refused again. In: none. Out: panics on a wrong
/// answer. Why: 2026-11-10 amendment ("signup runs the gate before recording").
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
// TRIAL-09
#[test]
fn signup_runs_device_gate_before_recording() {
    let db = Database::new_in_memory().unwrap();
    let device = DeviceInfo { user_agent: "UA".into(), screen_resolution: "1920x1080".into(), timezone: "UTC".into(), browser_language: "en-US".into() };
    for i in 1..=5 {
        let gates = db.signup(i, &format!("u{}@example.com", i), &format!("198.51.100.{}", i), &device).unwrap().unwrap();
        assert_ne!(gates.device.decision, Decision::Fail);
    }
    for i in 6..=7 {
        let err = db.signup(i, &format!("u{}@example.com", i), "198.51.100.99", &device).unwrap().unwrap_err();
        assert_eq!((err.error.as_str(), err.code), ("device_suspected_fraud", 403));
        assert_eq!(db.device_rows_for_user(i).unwrap(), 0);
    }
    // nothing recorded for the refused signups: the IP still has no signups
    assert_eq!(db.check_ip_signup_rate_limit("198.51.100.99").unwrap().rule_inputs["count"], 0);
}

// TRIAL-12
#[test]
fn chargeback_history_pass() {
    let db = Database::new_in_memory().unwrap();
    let result = db.check_chargeback_history(1).unwrap();
    assert_eq!(result.decision, Decision::Pass);
}

// TRIAL-13
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
use chrono::{DateTime, Utc};
use notifications_rust::*;
use rusqlite::Connection;
use std::collections::HashMap;

/// Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the service's clock is pinned to 12:00 UTC.
/// With the wall clock, test_quiet_hours_skip (quiet hours 00:00-23:59) passed or failed depending on
/// the time of day the suite ran. Touches: memory only.
fn setup_service() -> NotificationService {
    let service = NotificationService::new_in_memory()
        .unwrap()
        .with_clock(Box::new(|| fixed_time(2026, 1, 15, 12, 0)));
    // Create a default user preference
    service
        .update_user_preferences(
            1,
            &UserNotificationPreferencesUpdate {
                do_not_disturb: Some(false),
                quiet_hours_start: Some("00:00".to_string()),
                quiet_hours_end: Some("00:00".to_string()),
                channels_enabled: Some(
                    [("email".to_string(), true), ("sms".to_string(), true), ("in_app".to_string(), true)]
                        .iter()
                        .cloned()
                        .collect(),
                ),
            },
        )
        .unwrap();
    service
}

#[test]
fn test_send_email_with_template_variables() {
    let service = setup_service();
    let mut vars = HashMap::new();
    vars.insert("app_name".to_string(), "TestApp".to_string());
    let resp = service
        .send_single_notification(1, "welcome_email", Some("email"), &vars, None)
        .unwrap();
    assert_eq!(resp.status, "sent");
    let log = service.track_message_status(&resp.message_id).unwrap();
    assert_eq!(log.channel, "email");
    assert_eq!(log.status, "sent");
}

#[test]
fn test_send_sms() {
    let service = setup_service();
    let mut vars = HashMap::new();
    vars.insert("days_left".to_string(), "5".to_string());
    let resp = service
        .send_single_notification(1, "trial_ending_soon", Some("sms"), &vars, None)
        .unwrap();
    assert_eq!(resp.status, "sent");
    let log = service.track_message_status(&resp.message_id).unwrap();
    assert_eq!(log.channel, "sms");
}

#[test]
fn test_send_in_app() {
    let service = setup_service();
    let mut vars = HashMap::new();
    vars.insert("workspace".to_string(), "Workspace1".to_string());
    let resp = service
        .send_single_notification(1, "user_invited", Some("in_app"), &vars, None)
        .unwrap();
    assert_eq!(resp.status, "sent");
    let log = service.track_message_status(&resp.message_id).unwrap();
    assert_eq!(log.channel, "in_app");
}

#[test]
fn test_batch_send_1000_notifications() {
    let service = setup_service();
    let mut requests = Vec::new();
    for i in 0..1000 {
        let mut vars = HashMap::new();
        vars.insert("days_left".to_string(), "3".to_string());
        requests.push(BatchRequest {
            user_id: 1,
            template_key: "trial_ending_soon".to_string(),
            channel: Some("sms".to_string()),
            vars,
            scheduled_at: None,
        });
    }
    let resp = service.send_batch_notifications(requests).unwrap();
    assert_eq!(resp.sent, 1000);
    assert_eq!(resp.failed, 0);
}

#[test]
fn test_quiet_hours_skip() {
    let service = setup_service();
    // Set quiet hours to cover all time
    service
        .update_user_preferences(
            1,
            &UserNotificationPreferencesUpdate {
                do_not_disturb: Some(false),
                quiet_hours_start: Some("00:00".to_string()),
                quiet_hours_end: Some("23:59".to_string()),
                channels_enabled: None,
            },
        )
        .unwrap();
    let mut vars = HashMap::new();
    vars.insert("days_left".to_string(), "2".to_string());
    let resp = service
        .send_single_notification(1, "trial_ending_soon", Some("sms"), &vars, None)
        .unwrap();
    assert_eq!(resp.status, "skipped");
}

#[test]
fn test_do_not_disturb_skip() {
    let service = setup_service();
    service
        .update_user_preferences(
            1,
            &UserNotificationPreferencesUpdate {
                do_not_disturb: Some(true),
                quiet_hours_start: None,
                quiet_hours_end: None,
                channels_enabled: None,
            },
        )
        .unwrap();
    let mut vars = HashMap::new();
    vars.insert("days_left".to_string(), "2".to_string());
    let resp = service
        .send_single_notification(1, "trial_ending_soon", Some("sms"), &vars, None)
        .unwrap();
    assert_eq!(resp.status, "skipped");
}

#[test]
fn test_track_opened() {
    let service = setup_service();
    let mut vars = HashMap::new();
    vars.insert("days_left".to_string(), "4".to_string());
    let resp = service
        .send_single_notification(1, "trial_ending_soon", Some("email"), &vars, None)
        .unwrap();
    assert_eq!(resp.status, "sent");
    service.mark_opened(&resp.message_id).unwrap();
    let log = service.track_message_status(&resp.message_id).unwrap();
    assert!(log.opened_at.is_some());
}

#[test]
fn test_retry_on_failure() {
    let service = setup_service();
    let mut vars = HashMap::new();
    vars.insert("days_left".to_string(), "3".to_string());
    vars.insert("simulate_fail".to_string(), "true".to_string());
    let resp = service
        .send_single_notification(1, "trial_ending_soon", Some("sms"), &vars, None)
        .unwrap();
    // Since simulate_fail is true, the first two attempts fail, third succeeds
    assert_eq!(resp.status, "sent");
    let log = service.track_message_status(&resp.message_id).unwrap();
    assert_eq!(log.status, "sent");
}

#[test]
fn test_unsubscribe_skips_future_emails() {
    let service = setup_service();
    service.unsubscribe_user(1).unwrap();
    let mut vars = HashMap::new();
    vars.insert("app_name".to_string(), "TestApp".to_string());
    let resp = service
        .send_single_notification(1, "welcome_email", Some("email"), &vars, None)
        .unwrap();
    assert_eq!(resp.status, "skipped");
}

#[test]
fn test_user_preferences_channels_enabled() {
    let service = setup_service();
    // Disable email, enable sms
    service
        .update_user_preferences(
            1,
            &UserNotificationPreferencesUpdate {
                do_not_disturb: None,
                quiet_hours_start: None,
                quiet_hours_end: None,
                channels_enabled: Some(
                    [("email".to_string(), false), ("sms".to_string(), true), ("in_app".to_string(), false)]
                        .iter()
                        .cloned()
                        .collect(),
                ),
            },
        )
        .unwrap();
    let mut vars = HashMap::new();
    vars.insert("days_left".to_string(), "2".to_string());
    // Channel is None, should auto-select sms
    let resp = service
        .send_single_notification(1, "trial_ending_soon", None, &vars, None)
        .unwrap();
    assert_eq!(resp.status, "sent");
    let log = service.track_message_status(&resp.message_id).unwrap();
    assert_eq!(log.channel, "sms");
}
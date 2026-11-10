use chrono::{DateTime, Utc};
use notifications_rust::*;
use rusqlite::Connection;
use std::collections::HashMap;

/// A 32-byte test-only unsubscribe secret (production reads it from configuration).
const SECRET: &[u8] = b"test-only-unsubscribe-secret-0123456789";

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

// NOTIF-01
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

// NOTIF-02
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

// NOTIF-03
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

// NOTIF-04
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

/// What: NOTIF-05: a send inside the user's quiet hours is not sent now; it is stored 'queued' with
/// scheduled_at = quiet_hours_end and delivered by deliver_due once quiet hours are over.
/// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the old test expected 'skipped' (the message
/// was dropped); the amended spec queues it until quiet_hours_end. Touches: memory only.
// NOTIF-05
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
    assert_eq!(resp.status, "queued");
    assert_eq!(service.track_message_status(&resp.message_id).unwrap().status, "queued");
    assert_eq!(service.deliver_due(fixed_time(2026, 1, 15, 23, 58)).unwrap().sent, 0, "still quiet");
    assert_eq!(service.deliver_due(fixed_time(2026, 1, 15, 23, 59)).unwrap().sent, 1, "due at quiet_hours_end");
    assert_eq!(service.track_message_status(&resp.message_id).unwrap().status, "sent");
}

/// What: NOTIF-05 and the Phase B.3 ruling: the quiet window is [start, end), so an email due exactly at
/// quiet_hours_end is sent and one a minute earlier is queued; quiet hours hold email and SMS only, so an
/// in-app message inside the window is stored at once (sent, not queued), also when deliver_due meets it.
/// In: none. Out: panics on a wrong answer. Why: Phase B.3 ruling (spec commit d4f4ed7).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
// NOTIF-05
#[test]
fn test_quiet_hours_window_end_and_in_app() {
    use std::cell::Cell;
    use std::rc::Rc;
    let at = Rc::new(Cell::new(fixed_time(2026, 1, 15, 7, 59)));
    let a = at.clone();
    let service = setup_service().with_clock(Box::new(move || a.get()));
    service
        .update_user_preferences(
            1,
            &UserNotificationPreferencesUpdate {
                do_not_disturb: Some(false),
                quiet_hours_start: Some("22:00".to_string()),
                quiet_hours_end: Some("08:00".to_string()),
                channels_enabled: None,
            },
        )
        .unwrap();
    let mut vars = HashMap::new();
    vars.insert("app_name".to_string(), "TestApp".to_string());
    let early = service.send_single_notification(1, "welcome_email", Some("email"), &vars, None).unwrap();
    assert_eq!(early.status, "queued");
    let in_app = service.send_single_notification(1, "welcome_email", Some("in_app"), &vars, None).unwrap();
    assert_eq!(in_app.status, "sent");
    assert_eq!(service.track_message_status(&in_app.message_id).unwrap().channel, "in_app");
    at.set(fixed_time(2026, 1, 15, 8, 0));
    let on_end = service.send_single_notification(1, "welcome_email", Some("email"), &vars, None).unwrap();
    assert_eq!(on_end.status, "sent");
    assert_eq!(service.deliver_due(fixed_time(2026, 1, 15, 8, 0)).unwrap().sent, 1, "the queued email is due at 08:00");
    // a scheduled in-app message that comes due inside quiet hours is delivered, not held
    at.set(fixed_time(2026, 1, 15, 21, 0));
    let later = service.send_single_notification(1, "welcome_email", Some("in_app"), &vars, Some(fixed_time(2026, 1, 15, 23, 0))).unwrap();
    assert_eq!(later.status, "queued");
    assert_eq!(service.deliver_due(fixed_time(2026, 1, 15, 23, 0)).unwrap().sent, 1);
    assert_eq!(service.track_message_status(&later.message_id).unwrap().status, "sent");
}

// NOTIF-06
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

// NOTIF-07
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

// NOTIF-08
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

// NOTIF-09
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

// NOTIF-10
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
/// What: a provider that records every accepted message in a shared list the test keeps.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, CodeRabbit review on PR 19. Touches: memory.
struct RecordingSender(std::rc::Rc<std::cell::RefCell<Vec<OutgoingMessage>>>);

/// What: `Sender` for the test provider: accept and record. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory.
impl Sender for RecordingSender {
    /// What: record the message and accept it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn send(&self, message: &OutgoingMessage) -> Result<(), String> {
        self.0.borrow_mut().push(message.clone());
        Ok(())
    }
}

/// Added 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP), CodeRabbit review on PR 19: a message scheduled
/// for later is queued, `deliver_due` does not send it early, and sends it (rendered, status `sent`)
/// once the clock reaches its time; a second run sends nothing again. Changed the same day for the
/// NOTIF-11/12 amendment: the service takes an unsubscribe secret and `deliver_due(now)` takes the time
/// and returns counts. Touches: memory only.
#[test]
fn test_scheduled_message_is_delivered_when_due() {
    let delivered = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let now = std::rc::Rc::new(std::cell::Cell::new(fixed_time(2026, 1, 15, 12, 0)));
    let clock = now.clone();
    let service = NotificationService::new(Connection::open_in_memory().unwrap(), Box::new(RecordingSender(delivered.clone())), SECRET)
        .unwrap()
        .with_sleeper(Box::new(|_| {}))
        .with_clock(Box::new(move || clock.get()));
    let mut vars = HashMap::new();
    vars.insert("app_name".to_string(), "TestApp".to_string());
    let at: DateTime<Utc> = fixed_time(2026, 1, 15, 14, 0);
    let resp = service.send_single_notification(1, "welcome_email", Some("email"), &vars, Some(at)).unwrap();
    assert_eq!(resp.status, "queued");
    assert!(delivered.borrow().is_empty());

    // Before its time: nothing is sent and it stays queued.
    assert_eq!(service.deliver_due(now.get()).unwrap().sent, 0);
    assert!(delivered.borrow().is_empty());
    assert_eq!(service.track_message_status(&resp.message_id).unwrap().status, "queued");

    // At its time: sent once, rendered with its vars, under the same message id.
    now.set(fixed_time(2026, 1, 15, 14, 0));
    assert_eq!(service.deliver_due(now.get()).unwrap().sent, 1);
    {
        let sent = delivered.borrow();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].message_id, resp.message_id);
        assert!(sent[0].body_text.contains("TestApp"));
        assert!(sent[0].body_text.contains("Unsubscribe"));
    }
    let tracked = service.track_message_status(&resp.message_id).unwrap();
    assert_eq!(tracked.status, "sent");
    assert!(tracked.sent_at.is_some());

    // Nothing is delivered twice.
    now.set(fixed_time(2026, 1, 15, 15, 0));
    assert_eq!(service.deliver_due(now.get()).unwrap().sent, 0);
    assert_eq!(delivered.borrow().len(), 1);
}

/// What: a service on its own in-memory database with the test secret, a recording sender and a
/// movable clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
fn recording_service(start: DateTime<Utc>) -> (NotificationService, std::rc::Rc<std::cell::RefCell<Vec<OutgoingMessage>>>, std::rc::Rc<std::cell::Cell<DateTime<Utc>>>) {
    let delivered = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let now = std::rc::Rc::new(std::cell::Cell::new(start));
    let clock = now.clone();
    let service = NotificationService::new(Connection::open_in_memory().unwrap(), Box::new(RecordingSender(delivered.clone())), SECRET)
        .unwrap()
        .with_sleeper(Box::new(|_| {}))
        .with_base_url("https://app.example.test")
        .with_clock(Box::new(move || clock.get()));
    (service, delivered, now)
}

/// What: NOTIF-02 / NOTIF-10 defaults: a user who set nothing has no quiet hours, do-not-disturb off and
/// channels {email: true, sms: false, in_app: true}; an SMS to them is skipped (channel_disabled) until
/// they turn SMS on, then it is sent. In: none. Out: panics on a wrong answer.
/// Why: 2026-11-10 amendment (NOTIF-02: SMS is opt-in). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory only.
// NOTIF-02
#[test]
fn test_default_preferences_sms_is_opt_in() {
    let (service, delivered, _) = recording_service(fixed_time(2026, 1, 15, 12, 0));
    let p = service.get_user_preferences(42).unwrap();
    assert_eq!((p.do_not_disturb, p.quiet_hours_start.clone(), p.quiet_hours_end.clone()), (false, None, None));
    assert_eq!(p.channels_enabled, default_channels());
    assert_eq!((p.channels_enabled["email"], p.channels_enabled["sms"], p.channels_enabled["in_app"]), (true, false, true));
    let vars: HashMap<String, String> = [("days_left".to_string(), "3".to_string())].into_iter().collect();
    assert_eq!(service.send_single_notification(42, "trial_ending_soon", Some("sms"), &vars, None).unwrap().status, "skipped");
    assert!(delivered.borrow().is_empty());
    service
        .update_user_preferences(42, &UserNotificationPreferencesUpdate {
            do_not_disturb: None,
            quiet_hours_start: None,
            quiet_hours_end: None,
            channels_enabled: Some([("sms".to_string(), true)].into_iter().collect()),
        })
        .unwrap();
    assert_eq!(service.send_single_notification(42, "trial_ending_soon", Some("sms"), &vars, None).unwrap().status, "sent");
    assert_eq!(delivered.borrow()[0].channel, "sms");
}

/// What: NOTIF-11: the email carries the signed unsubscribe link; GET with its token confirms and
/// changes nothing; POST sets channels_enabled.email = false (later emails are skipped); a missing,
/// short, non-hex, upper-case or altered token, another user's token, or an unknown channel all get
/// 403 invalid_unsubscribe_token and the user stays subscribed; a secret under 32 bytes is refused at
/// start. In: none. Out: panics on a wrong answer. Why: 2026-11-10 amendment (NOTIF-11).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
// NOTIF-11
#[test]
fn test_unsubscribe_link_is_signed_and_post_only() {
    assert!(NotificationService::new(Connection::open_in_memory().unwrap(), Box::new(FakeSender::default()), &[7u8; 31]).is_err());
    let (service, delivered, _) = recording_service(fixed_time(2026, 1, 15, 12, 0));
    let vars: HashMap<String, String> = [("app_name".to_string(), "TestApp".to_string())].into_iter().collect();
    service.send_single_notification(7, "welcome_email", Some("email"), &vars, None).unwrap();
    let token = service.unsubscribe_token(7, "email");
    assert_eq!(token.len(), 64);
    let link = format!("https://app.example.test/unsubscribe?user_id=7&channel=email&token={}", token);
    assert!(delivered.borrow()[0].body_text.contains(&link));

    let email_on = || service.get_user_preferences(7).unwrap().channels_enabled["email"];
    let refused = serde_json::json!({ "error": "invalid_unsubscribe_token" });
    let mut altered = token.clone().into_bytes();
    altered[10] = if altered[10] == b'0' { b'1' } else { b'0' };
    let altered = String::from_utf8(altered).unwrap();
    let other_user = service.unsubscribe_token(8, "email");
    for (channel, bad) in [
        ("email", None),
        ("email", Some("abc123")),
        ("email", Some(&"z".repeat(64)[..])),
        ("email", Some(&token.to_uppercase()[..])),
        ("email", Some(&altered[..])),
        ("email", Some(&other_user[..])),
        ("fax", Some(&token[..])),
    ] {
        for method in ["GET", "POST"] {
            assert_eq!(service.handle_unsubscribe(method, 7, channel, bad).unwrap(), (403, refused.clone()), "{} {:?} {:?}", method, channel, bad);
        }
    }
    assert!(email_on());
    let (status, body) = service.handle_unsubscribe("GET", 7, "email", Some(&token)).unwrap();
    assert_eq!((status, body["confirm"].as_bool()), (200, Some(true)));
    assert!(email_on(), "GET changes nothing");
    let (status, body) = service.handle_unsubscribe("POST", 7, "email", Some(&token)).unwrap();
    assert_eq!((status, body["unsubscribed"].as_bool()), (200, Some(true)));
    assert!(!email_on());
    assert_eq!(service.send_single_notification(7, "welcome_email", Some("email"), &vars, None).unwrap().status, "skipped");
}

/// What: NOTIF-12: a send 30 days ahead is queued and not sent now; deliver_due sends it once it is
/// due, exactly once (a second run sends nothing); a message whose user unsubscribed meanwhile is
/// skipped at delivery; a row stuck at 'sending' for over 300 s is re-queued and delivered, one stuck
/// for exactly 300 s is not. In: none. Out: panics on a wrong answer. Why: 2026-11-10 amendment
/// (NOTIF-12). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
// NOTIF-12
#[test]
fn test_scheduled_send_delivery_rules() {
    let t0 = fixed_time(2026, 1, 15, 12, 0);
    let (service, delivered, _) = recording_service(t0);
    let vars: HashMap<String, String> = [("app_name".to_string(), "TestApp".to_string())].into_iter().collect();
    let later = t0 + chrono::Duration::days(30);
    let a = service.send_single_notification(1, "welcome_email", Some("email"), &vars, Some(later)).unwrap();
    let b = service.send_single_notification(2, "welcome_email", Some("email"), &vars, Some(later)).unwrap();
    assert_eq!((a.status.as_str(), b.status.as_str()), ("queued", "queued"));
    assert_eq!(service.deliver_due(t0).unwrap(), DeliverCounts::default());
    assert!(delivered.borrow().is_empty());

    // user 2 unsubscribes through the signed link before the message is due
    let token = service.unsubscribe_token(2, "email");
    assert_eq!(service.handle_unsubscribe("POST", 2, "email", Some(&token)).unwrap().0, 200);

    let counts = service.deliver_due(later).unwrap();
    assert_eq!((counts.sent, counts.skipped), (1, 1));
    assert_eq!(service.track_message_status(&a.message_id).unwrap().status, "sent");
    assert_eq!(service.track_message_status(&b.message_id).unwrap().status, "skipped");
    assert_eq!(service.deliver_due(later + chrono::Duration::hours(1)).unwrap(), DeliverCounts::default());
    assert_eq!(delivered.borrow().len(), 1);
    assert_eq!(delivered.borrow()[0].message_id, a.message_id);

    // a worker crashed after claiming a row (its sender panicked mid-send): the row stays 'sending'
    // until its claim is over 300 s old, then it is re-queued and delivered
    let crashes = std::rc::Rc::new(std::cell::Cell::new(1));
    let sent = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let crashing = NotificationService::new(Connection::open_in_memory().unwrap(), Box::new(CrashOnceSender(crashes, sent.clone())), SECRET)
        .unwrap()
        .with_sleeper(Box::new(|_| {}))
        .with_clock(Box::new(move || t0));
    let c = crashing.send_single_notification(1, "welcome_email", Some("email"), &vars, Some(later)).unwrap();
    let crash = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| crashing.deliver_due(later)));
    assert!(crash.is_err());
    assert_eq!(crashing.track_message_status(&c.message_id).unwrap().status, "sending");
    assert_eq!(crashing.deliver_due(later + chrono::Duration::seconds(300)).unwrap(), DeliverCounts::default());
    assert_eq!(crashing.track_message_status(&c.message_id).unwrap().status, "sending");
    let counts = crashing.deliver_due(later + chrono::Duration::seconds(301)).unwrap();
    assert_eq!((counts.requeued, counts.sent), (1, 1));
    assert_eq!(crashing.track_message_status(&c.message_id).unwrap().status, "sent");
    assert_eq!(sent.borrow().len(), 1);
}

/// What: a provider that panics on its first `crashes` sends (a worker crash) and then records and
/// accepts. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-12). Touches: memory.
struct CrashOnceSender(std::rc::Rc<std::cell::Cell<u32>>, std::rc::Rc<std::cell::RefCell<Vec<OutgoingMessage>>>);

/// What: `Sender` for the crashing provider. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl Sender for CrashOnceSender {
    /// What: panic while crashes remain, else record and accept. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn send(&self, message: &OutgoingMessage) -> Result<(), String> {
        if self.0.get() > 0 {
            self.0.set(self.0.get() - 1);
            panic!("worker crashed mid-send");
        }
        self.1.borrow_mut().push(message.clone());
        Ok(())
    }
}

/// What: a service on a named shared-cache in-memory database, with a second connection to the same
/// database so a test can read stored columns the API does not return (status, scheduled_at), a
/// recording sender and a movable clock. In: a database name unique to the test, the start time.
/// Out: (service, reader connection, delivered messages, clock). Why: Phase B.2 tests (NOTIF-05/07) must
/// prove what is stored. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
fn shared_service(name: &str, start: DateTime<Utc>) -> (NotificationService, Connection, std::rc::Rc<std::cell::RefCell<Vec<OutgoingMessage>>>, std::rc::Rc<std::cell::Cell<DateTime<Utc>>>) {
    use rusqlite::OpenFlags;
    let uri = format!("file:{}?mode=memory&cache=shared", name);
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_URI;
    let main = Connection::open_with_flags(&uri, flags).unwrap();
    let reader = Connection::open_with_flags(&uri, flags).unwrap();
    let delivered = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let now = std::rc::Rc::new(std::cell::Cell::new(start));
    let clock = now.clone();
    let service = NotificationService::new(main, Box::new(RecordingSender(delivered.clone())), SECRET)
        .unwrap()
        .with_sleeper(Box::new(|_| {}))
        .with_clock(Box::new(move || clock.get()));
    (service, reader, delivered, now)
}

/// What: the stored (status, scheduled_at, opened_at) of a message, read through the second connection.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2). Touches: in-memory SQLite (read).
fn stored(reader: &Connection, id: &str) -> (String, Option<String>, Option<String>) {
    reader
        .query_row("SELECT status, scheduled_at, opened_at FROM notification_logs WHERE id = ?1", [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
}

/// What: NOTIF-05 (Phase B.2 wording): quiet hours are HH:MM in UTC and may cross midnight. With a
/// 22:00-08:00 window, a send at 23:00 is queued with scheduled_at = 08:00 the next day and one at 07:59
/// with 08:00 the same day; sends at 08:00 and 21:59 go out now. A message scheduled (outside quiet hours)
/// for 23:30 that deliver_due finds due at 23:30 is not sent: it goes back to 'queued' with scheduled_at =
/// 08:00 the next day (counted as deferred), and the 08:00 run sends it once. In: none. Out: panics on a
/// wrong answer. Why: Phase B.2 bug: deliver_due did not re-check quiet hours.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
// NOTIF-05
#[test]
fn test_quiet_hours_cross_midnight_and_deliver_due_requeues() {
    let (service, reader, delivered, now) = shared_service("notif05_b2", fixed_time(2026, 1, 15, 12, 0));
    service
        .update_user_preferences(
            1,
            &UserNotificationPreferencesUpdate {
                do_not_disturb: None,
                quiet_hours_start: Some("22:00".to_string()),
                quiet_hours_end: Some("08:00".to_string()),
                channels_enabled: None,
            },
        )
        .unwrap();
    let vars: HashMap<String, String> = [("app_name".to_string(), "TestApp".to_string())].into_iter().collect();
    let next_8 = "2026-01-16T08:00:00.000000Z".to_string();

    now.set(fixed_time(2026, 1, 15, 23, 0));
    let late = service.send_single_notification(1, "welcome_email", Some("email"), &vars, None).unwrap();
    assert_eq!(late.status, "queued");
    assert_eq!(stored(&reader, &late.message_id).1, Some(next_8.clone()));
    now.set(fixed_time(2026, 1, 16, 7, 59));
    let early = service.send_single_notification(1, "welcome_email", Some("email"), &vars, None).unwrap();
    assert_eq!(early.status, "queued");
    assert_eq!(stored(&reader, &early.message_id).1, Some(next_8.clone()));
    // both go out at quiet_hours_end
    let counts = service.deliver_due(fixed_time(2026, 1, 16, 8, 0)).unwrap();
    assert_eq!((counts.sent, counts.deferred), (2, 0));
    for (h, m) in [(8, 0), (21, 59)] {
        now.set(fixed_time(2026, 1, 16, h, m));
        let r = service.send_single_notification(1, "welcome_email", Some("email"), &vars, None).unwrap();
        assert_eq!(r.status, "sent", "{:02}:{:02} is outside quiet hours", h, m);
    }
    let sent_before = delivered.borrow().len();

    // scheduled at noon for 23:30 (no quiet hours apply to the scheduling itself)
    now.set(fixed_time(2026, 1, 16, 12, 0));
    let at = fixed_time(2026, 1, 16, 23, 30);
    let sched = service.send_single_notification(1, "welcome_email", Some("email"), &vars, Some(at)).unwrap();
    assert_eq!(sched.status, "queued");
    let counts = service.deliver_due(at).unwrap();
    assert_eq!((counts.sent, counts.deferred), (0, 1));
    let (status, scheduled_at, _) = stored(&reader, &sched.message_id);
    assert_eq!((status.as_str(), scheduled_at), ("queued", Some("2026-01-17T08:00:00.000000Z".to_string())));
    assert_eq!(delivered.borrow().len(), sent_before, "nothing sent inside quiet hours");
    assert_eq!(service.deliver_due(fixed_time(2026, 1, 17, 7, 59)).unwrap().sent, 0);
    let counts = service.deliver_due(fixed_time(2026, 1, 17, 8, 0)).unwrap();
    assert_eq!((counts.sent, counts.deferred), (1, 0));
    assert_eq!(stored(&reader, &sched.message_id).0, "sent");
    assert_eq!(delivered.borrow().iter().filter(|m| m.message_id == sched.message_id).count(), 1);
}

/// What: NOTIF-07 (Phase B.2 wording): GET /notifications/open/:message_id (`open_message`, this template
/// has no router) sets opened_at and status 'opened' the first time; a second call an hour later changes
/// nothing (opened_at keeps the first time); every call, an unknown id and a not-yet-sent (queued) message
/// included, answers 204, and the queued message is not marked opened. In: none. Out: panics on a wrong
/// answer. Why: NOTIF-07 now names the endpoint and its once-only rule. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
// NOTIF-07
#[test]
fn test_open_endpoint_sets_opened_once_and_answers_204() {
    let (service, reader, _, now) = shared_service("notif07_b2", fixed_time(2026, 1, 15, 12, 0));
    let vars: HashMap<String, String> = [("app_name".to_string(), "TestApp".to_string())].into_iter().collect();
    let sent = service.send_single_notification(1, "welcome_email", Some("email"), &vars, None).unwrap();
    assert_eq!(stored(&reader, &sent.message_id).0, "sent");
    now.set(fixed_time(2026, 1, 15, 12, 5));
    assert_eq!(service.open_message(&sent.message_id).unwrap(), 204);
    let first = stored(&reader, &sent.message_id);
    assert_eq!((first.0.as_str(), first.2.as_deref()), ("opened", Some("2026-01-15T12:05:00.000000Z")));
    now.set(fixed_time(2026, 1, 15, 13, 5));
    assert_eq!(service.open_message(&sent.message_id).unwrap(), 204);
    assert_eq!(stored(&reader, &sent.message_id), first, "a second open changes nothing");
    assert_eq!(service.track_message_status(&sent.message_id).unwrap().status, "opened");
    assert_eq!(service.open_message("no-such-message").unwrap(), 204);
    let queued = service.send_single_notification(1, "welcome_email", Some("email"), &vars, Some(fixed_time(2026, 2, 1, 0, 0))).unwrap();
    assert_eq!(service.open_message(&queued.message_id).unwrap(), 204);
    assert_eq!(stored(&reader, &queued.message_id).0, "queued");
    assert_eq!(stored(&reader, &queued.message_id).2, None);
}

/// What: a provider that refuses its first `fail_first` sends, then accepts; it counts every call.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, NOTIF-08). Touches: memory.
struct FlakySender {
    fail_first: u32,
    calls: std::rc::Rc<std::cell::Cell<u32>>,
}

/// What: `Sender` for the flaky provider. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl Sender for FlakySender {
    /// What: count the call; refuse while within `fail_first`, else accept. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn send(&self, _message: &OutgoingMessage) -> Result<(), String> {
        self.calls.set(self.calls.get() + 1);
        if self.calls.get() <= self.fail_first {
            return Err(format!("provider down (call {})", self.calls.get()));
        }
        Ok(())
    }
}

/// What: NOTIF-08 (Phase B.2 wording): a failed email is retried at most 3 times after the first attempt,
/// waiting 1 s, 2 s and 4 s. A sender that fails 3 times and recovers is called 4 times and the message
/// is 'sent'; one that fails 4 times is called exactly 4 times (never a 5th) and the message is 'failed'.
/// In: none. Out: panics on a wrong count or wait. Why: the spec now fixes the counting (it was 3 attempts
/// in all, 0.5 s / 1 s). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
// NOTIF-08
#[test]
fn test_retry_three_times_after_first_attempt() {
    for (fail_first, status) in [(3, "sent"), (4, "failed")] {
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let waits = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let record = waits.clone();
        let service = NotificationService::new(Connection::open_in_memory().unwrap(), Box::new(FlakySender { fail_first, calls: calls.clone() }), SECRET)
            .unwrap()
            .with_sleeper(Box::new(move |d| record.borrow_mut().push(d)))
            .with_clock(Box::new(|| fixed_time(2026, 1, 15, 12, 0)));
        let vars: HashMap<String, String> = [("app_name".to_string(), "TestApp".to_string())].into_iter().collect();
        let resp = service.send_single_notification(1, "welcome_email", Some("email"), &vars, None).unwrap();
        assert_eq!(resp.status, status, "{} failures", fail_first);
        assert_eq!(service.track_message_status(&resp.message_id).unwrap().status, status);
        assert_eq!(calls.get(), 4, "{} failures: the first attempt and 3 retries", fail_first);
        let secs: Vec<u64> = waits.borrow().iter().map(|d| d.as_secs()).collect();
        assert_eq!(secs, vec![1, 2, 4]);
    }
    assert_eq!(MAX_ATTEMPTS, 4);
}

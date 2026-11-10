//! Notifications: templated email, SMS and in-app messages with user preferences (TIER 2 spec,
//! system 2).
//!
//! What: `NotificationService` renders the spec's templates (`{variable}` substitution, one pass),
//! honours do-not-disturb, quiet hours, per-channel preferences and email unsubscribe, sends through an
//! injected `Sender` with up to 3 attempts and exponential backoff, and logs every message (sent,
//! queued, skipped or failed) so it can be tracked, opened and clicked.
//! Why: the old file did not compile (two `update_user_preferences`, `?` in a `bool` function, the
//! removed `NO_PARAMS`), used the local wall clock for quiet hours, faked failures from a template
//! variable inside production code, sent every email to a hard-coded address, and "unsubscribed" users
//! by turning on do-not-disturb for every channel. Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: the SQLite database it is given (in memory for tests); the network only through the
//! injected sender; no money.

use chrono::{DateTime, TimeZone, Timelike, Utc};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension, Result as SqlResult};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Duration;

/// The channels the service knows.
pub const CHANNELS: [&str; 3] = ["email", "sms", "in_app"];
/// Attempts per message before it is logged as failed (spec: "retry 3x").
pub const MAX_ATTEMPTS: u32 = 3;

/// What: create the spec's three tables (plus a `status` column on the log). In: a connection.
/// Out: `()` or a SQLite error. Why: executable schema. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: database (DDL).
pub fn init_db(conn: &Connection) -> SqlResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS notification_templates (
            key TEXT PRIMARY KEY, subject TEXT NOT NULL, body_text TEXT NOT NULL, body_html TEXT NOT NULL,
            channels_default TEXT NOT NULL, variables TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS notification_logs (
            id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, template_key TEXT NOT NULL, channel TEXT NOT NULL,
            vars_used TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL, scheduled_at TEXT NULL, sent_at TEXT NULL, opened_at TEXT NULL,
            clicked_at TEXT NULL, bounced INTEGER NOT NULL DEFAULT 0, error TEXT NULL);
         CREATE TABLE IF NOT EXISTS user_notification_preferences (
            user_id INTEGER PRIMARY KEY, do_not_disturb INTEGER NOT NULL, quiet_hours_start TEXT NOT NULL,
            quiet_hours_end TEXT NOT NULL, channels_enabled TEXT NOT NULL, unsubscribed INTEGER NOT NULL DEFAULT 0);",
    )
}

/// What: insert (or refresh) the spec's nine templates. In: a connection. Out: `()` or an error.
/// Why: "pre-defined, editable" templates. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: database (writes `notification_templates`).
pub fn load_default_templates(conn: &Connection) -> SqlResult<()> {
    let all = r#"["email","sms","in_app"]"#;
    let templates: [(&str, &str, &str, &str, &str); 9] = [
        ("welcome_email", "Welcome to {app_name}!", "Welcome to {app_name}! Here's your first step.", r#"["email","in_app"]"#, r#"["app_name"]"#),
        ("trial_starting", "Your trial is starting", "Your free trial is starting. You have {trial_days} days.", all, r#"["trial_days"]"#),
        ("trial_ending_soon", "Your trial ends soon", "Your trial ends in {days_left} days. Add payment method to continue.", all, r#"["days_left"]"#),
        ("subscription_changed", "Your plan changed", "Your plan changed from {old_tier} to {new_tier}. Effective {effective_date}.", all, r#"["old_tier","new_tier","effective_date"]"#),
        ("payment_failed", "Payment failed", "Payment failed for invoice {invoice_id}. {retry_date} retry, or update payment method.", all, r#"["invoice_id","retry_date"]"#),
        ("deployment_live", "Your deployment is live", "Your deployment {deployment_name} is now live at {url}.", all, r#"["deployment_name","url"]"#),
        ("user_invited", "You've been invited", "You've been invited to {workspace}. Click here to join.", all, r#"["workspace"]"#),
        ("invoice_ready", "Your invoice is ready", "Your invoice for {month} is ready. Download here.", r#"["email","in_app"]"#, r#"["month"]"#),
        ("admin_alert", "Admin alert", "{actor} performed {action} on {resource}.", r#"["email","in_app"]"#, r#"["actor","action","resource"]"#),
    ];
    for (key, subject, body_text, channels_default, variables) in templates {
        conn.execute(
            "INSERT OR REPLACE INTO notification_templates (key, subject, body_text, body_html, channels_default, variables)
             VALUES (?1, ?2, ?3, '', ?4, ?5)",
            params![key, subject, body_text, channels_default, variables],
        )?;
    }
    Ok(())
}

/// What: one template row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationTemplate {
    pub key: String,
    pub subject: String,
    pub body_text: String,
    pub body_html: String,
    pub channels_default: Vec<String>,
    pub variables: Vec<String>,
}

/// What: a user's stored preferences. Quiet hours are "HH:MM" in UTC; equal start and end mean no
/// quiet hours. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserNotificationPreferences {
    pub user_id: i64,
    pub do_not_disturb: bool,
    pub quiet_hours_start: String,
    pub quiet_hours_end: String,
    pub channels_enabled: HashMap<String, bool>,
    pub unsubscribed: bool,
}

/// What: a partial preferences update; `None` keeps the stored value. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserNotificationPreferencesUpdate {
    pub do_not_disturb: Option<bool>,
    pub quiet_hours_start: Option<String>,
    pub quiet_hours_end: Option<String>,
    pub channels_enabled: Option<HashMap<String, bool>>,
}

/// What: the send endpoint's response; `status` is sent, queued, skipped or failed.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendResponse {
    pub success: bool,
    pub message_id: String,
    pub status: String,
}

/// What: the batch endpoint's response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSendResponse {
    pub success: bool,
    pub sent: usize,
    pub failed: usize,
    pub message_ids: Vec<String>,
}

/// What: the track endpoint's response; `status` is the stored status, or `opened` once opened.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackResponse {
    pub message_id: String,
    pub user_id: i64,
    pub template_key: String,
    pub channel: String,
    pub status: String,
    pub sent_at: Option<DateTime<Utc>>,
    pub opened_at: Option<DateTime<Utc>>,
    pub clicked_at: Option<DateTime<Utc>>,
}

/// What: one item of a batch send. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone)]
pub struct BatchRequest {
    pub user_id: i64,
    pub template_key: String,
    pub channel: Option<String>,
    pub vars: HashMap<String, String>,
    pub scheduled_at: Option<DateTime<Utc>>,
}

/// What: a rendered message ready for a provider. The provider looks up the user's address itself;
/// the service never invents one. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq)]
pub struct OutgoingMessage {
    pub message_id: String,
    pub user_id: i64,
    pub channel: String,
    pub subject: String,
    pub body_text: String,
    pub body_html: String,
    pub vars: HashMap<String, String>,
}

/// What: the email/SMS/in-app provider (SMTP, an SMS gateway, a push service...). In: a message.
/// Out: `Ok` when the provider accepted it, `Err(reason)` otherwise. Why: external services sit behind a
/// trait so tests use a fake and never the network. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: the network, in a real implementation.
pub trait Sender {
    /// What: `send` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn send(&self, message: &OutgoingMessage) -> Result<(), String>;
}

/// What: an in-memory provider that records what it accepted. A message whose vars contain
/// `simulate_fail = "true"` is refused on its first two attempts and accepted on the third, so retries
/// can be tested. Why: test double (the old code faked failures inside the production path).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
#[derive(Default)]
pub struct FakeSender {
    pub delivered: RefCell<Vec<OutgoingMessage>>,
    attempts: RefCell<HashMap<String, u32>>,
}

/// What: `Sender` for `FakeSender`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl Sender for FakeSender {
    /// What: `send` of `Sender for FakeSender`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn send(&self, message: &OutgoingMessage) -> Result<(), String> {
        let mut attempts = self.attempts.borrow_mut();
        let n = attempts.entry(message.message_id.clone()).or_insert(0);
        *n += 1;
        if message.vars.get("simulate_fail").map(|v| v == "true").unwrap_or(false) && *n <= 2 {
            return Err(format!("simulated provider failure {}", n));
        }
        self.delivered.borrow_mut().push(message.clone());
        Ok(())
    }
}

/// What: the notification service. Why: the spec's endpoints as methods.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, sender, clock, sleeper.
pub struct NotificationService {
    conn: Connection,
    sender: Box<dyn Sender>,
    clock: Box<dyn Fn() -> DateTime<Utc>>,
    sleeper: Box<dyn Fn(Duration)>,
    backoff_base: Duration,
    unsubscribe_link: Box<dyn Fn(i64) -> String>,
}

/// What: a new random message id (32 hex chars). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: the OS random source.
fn new_message_id() -> String {
    let mut buf = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// What: parse "HH:MM" into minutes since midnight. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn parse_hhmm(s: &str) -> Option<u32> {
    let (h, m) = s.trim().split_once(':')?;
    let (h, m): (u32, u32) = (h.parse().ok()?, m.parse().ok()?);
    if h < 24 && m < 60 { Some(h * 60 + m) } else { None }
}

/// What: is `now` inside the [start, end) quiet window? A window may wrap midnight; equal or invalid
/// bounds mean no quiet hours. In: preferences, time. Out: bool. Why: spec "Quiet hours: check before
/// sending". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn in_quiet_hours(prefs: &UserNotificationPreferences, now: DateTime<Utc>) -> bool {
    let (Some(start), Some(end)) = (parse_hhmm(&prefs.quiet_hours_start), parse_hhmm(&prefs.quiet_hours_end)) else {
        return false;
    };
    let minute = now.hour() * 60 + now.minute();
    if start == end {
        false
    } else if start < end {
        minute >= start && minute < end
    } else {
        minute >= start || minute < end
    }
}

/// What: replace each `{name}` with its value in one pass, so a value containing `{other}` is never
/// expanded again; unknown placeholders stay. In: text, vars, whether to HTML-escape values.
/// Out: the rendered text. Why: spec templating, without injection. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn render(text: &str, vars: &HashMap<String, String>, html: bool) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after.find('}') {
            Some(close) if after[..close].chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && close > 0 => {
                let name = &after[..close];
                match vars.get(name) {
                    Some(v) if html => out.push_str(&escape_html(v)),
                    Some(v) => out.push_str(v),
                    None => {
                        out.push('{');
                        out.push_str(name);
                        out.push('}');
                    }
                }
                rest = &after[close + 1..];
            }
            _ => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// What: escape `& < > " '` for HTML. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

/// What: read an optional RFC 3339 column. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn parse_time(s: Option<String>) -> Option<DateTime<Utc>> {
    s.and_then(|s| DateTime::parse_from_rfc3339(&s).ok()).map(|d| d.with_timezone(&Utc))
}

/// What: methods of `NotificationService`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl NotificationService {
    /// What: a service on an in-memory SQLite database with a `FakeSender`, the system clock and no
    /// real sleeping between retries. Why: tests and demos. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
    pub fn new_in_memory() -> SqlResult<Self> {
        let svc = Self::new(Connection::open_in_memory()?, Box::new(FakeSender::default()))?;
        Ok(svc.with_sleeper(Box::new(|_| {})))
    }

    /// What: a production service: creates the tables and default templates, uses the system clock and
    /// real sleeps between retries. In: a connection and a provider. Out: the service.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (DDL and templates).
    pub fn new(conn: Connection, sender: Box<dyn Sender>) -> SqlResult<Self> {
        init_db(&conn)?;
        load_default_templates(&conn)?;
        Ok(Self {
            conn,
            sender,
            clock: Box::new(Utc::now),
            sleeper: Box::new(std::thread::sleep),
            backoff_base: Duration::from_millis(500),
            unsubscribe_link: Box::new(|_| "/notifications/unsubscribe".to_string()),
        })
    }

    /// What: replace the clock. Why: quiet hours must be testable at a fixed time of day.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> DateTime<Utc>>) -> Self {
        self.clock = clock;
        self
    }

    /// What: replace how the service waits between retries. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn with_sleeper(mut self, sleeper: Box<dyn Fn(Duration)>) -> Self {
        self.sleeper = sleeper;
        self
    }

    /// What: set how each email's unsubscribe link is built (it should carry a signed token in
    /// production). Why: spec "Include unsubscribe link in emails (legal requirement)".
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn with_unsubscribe_link(mut self, link: Box<dyn Fn(i64) -> String>) -> Self {
        self.unsubscribe_link = link;
        self
    }

    /// What: load a template. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
    fn load_template(&self, key: &str) -> SqlResult<NotificationTemplate> {
        self.conn.query_row(
            "SELECT key, subject, body_text, body_html, channels_default, variables FROM notification_templates WHERE key = ?1",
            params![key],
            |row| {
                let channels: String = row.get(4)?;
                let variables: String = row.get(5)?;
                Ok(NotificationTemplate {
                    key: row.get(0)?,
                    subject: row.get(1)?,
                    body_text: row.get(2)?,
                    body_html: row.get(3)?,
                    channels_default: serde_json::from_str(&channels).unwrap_or_default(),
                    variables: serde_json::from_str(&variables).unwrap_or_default(),
                })
            },
        )
    }

    /// What: a user's preferences, or the defaults (no DND, no quiet hours, every channel on).
    /// In: user id. Out: preferences. Why: spec "Get user preferences".
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
    pub fn get_user_preferences(&self, user_id: i64) -> SqlResult<UserNotificationPreferences> {
        let row = self
            .conn
            .query_row(
                "SELECT do_not_disturb, quiet_hours_start, quiet_hours_end, channels_enabled, unsubscribed
                 FROM user_notification_preferences WHERE user_id = ?1",
                params![user_id],
                |r| {
                    let channels: String = r.get(3)?;
                    Ok(UserNotificationPreferences {
                        user_id,
                        do_not_disturb: r.get::<_, i64>(0)? != 0,
                        quiet_hours_start: r.get(1)?,
                        quiet_hours_end: r.get(2)?,
                        channels_enabled: serde_json::from_str(&channels).unwrap_or_default(),
                        unsubscribed: r.get::<_, i64>(4)? != 0,
                    })
                },
            )
            .optional()?;
        Ok(row.unwrap_or_else(|| UserNotificationPreferences {
            user_id,
            do_not_disturb: false,
            quiet_hours_start: "00:00".into(),
            quiet_hours_end: "00:00".into(),
            channels_enabled: CHANNELS.iter().map(|c| (c.to_string(), true)).collect(),
            unsubscribed: false,
        }))
    }

    /// What: save the preferences. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn save_preferences(&self, p: &UserNotificationPreferences) -> SqlResult<()> {
        let channels = serde_json::to_string(&p.channels_enabled).unwrap_or_else(|_| "{}".into());
        self.conn.execute(
            "INSERT OR REPLACE INTO user_notification_preferences
                (user_id, do_not_disturb, quiet_hours_start, quiet_hours_end, channels_enabled, unsubscribed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![p.user_id, p.do_not_disturb as i64, p.quiet_hours_start, p.quiet_hours_end, channels, p.unsubscribed as i64],
        )?;
        Ok(())
    }

    /// What: apply a partial update; quiet hours must be "HH:MM" and channel names known.
    /// In: user id, update. Out: `()` or an error. Why: spec "Update user preferences".
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (write).
    pub fn update_user_preferences(&self, user_id: i64, update: &UserNotificationPreferencesUpdate) -> SqlResult<()> {
        let mut p = self.get_user_preferences(user_id)?;
        for t in [&update.quiet_hours_start, &update.quiet_hours_end].into_iter().flatten() {
            if parse_hhmm(t).is_none() {
                return Err(rusqlite::Error::InvalidParameterName(format!("quiet hours must be HH:MM, got {:?}", t)));
            }
        }
        if let Some(ch) = &update.channels_enabled {
            if let Some(bad) = ch.keys().find(|k| !CHANNELS.contains(&k.as_str())) {
                return Err(rusqlite::Error::InvalidParameterName(format!("unknown channel {:?}", bad)));
            }
        }
        if let Some(v) = update.do_not_disturb {
            p.do_not_disturb = v;
        }
        if let Some(v) = &update.quiet_hours_start {
            p.quiet_hours_start = v.trim().to_string();
        }
        if let Some(v) = &update.quiet_hours_end {
            p.quiet_hours_end = v.trim().to_string();
        }
        if let Some(ch) = &update.channels_enabled {
            for (k, v) in ch {
                p.channels_enabled.insert(k.clone(), *v);
            }
        }
        self.save_preferences(&p)
    }

    /// What: unsubscribe a user from email; SMS and in-app are untouched. In: user id. Out: `()`.
    /// Why: spec "user unsubscribed, future emails skipped" (the old code silenced every channel).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (write).
    pub fn unsubscribe_user(&self, user_id: i64) -> SqlResult<()> {
        let mut p = self.get_user_preferences(user_id)?;
        p.unsubscribed = true;
        self.save_preferences(&p)
    }

    /// What: write a log row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    #[allow(clippy::too_many_arguments)]
    fn log(&self, id: &str, user_id: i64, template_key: &str, channel: &str, vars: &HashMap<String, String>,
           status: &str, attempts: u32, scheduled_at: Option<DateTime<Utc>>, sent_at: Option<DateTime<Utc>>,
           error: Option<&str>) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO notification_logs (id, user_id, template_key, channel, vars_used, status, attempts, created_at,
                scheduled_at, sent_at, error) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![id, user_id, template_key, channel, serde_json::to_string(vars).unwrap_or_else(|_| "{}".into()),
                status, attempts, (self.clock)().to_rfc3339(), scheduled_at.map(|t| t.to_rfc3339()),
                sent_at.map(|t| t.to_rfc3339()), error],
        )?;
        Ok(())
    }

    /// What: send one templated notification. Order: unknown template or channel -> error;
    /// do-not-disturb -> skipped; quiet hours -> skipped; channel chosen (the requested one, or the
    /// template's first channel the user enabled) and skipped if disabled, or if it is email and the user
    /// unsubscribed; a future `scheduled_at` -> queued; otherwise up to 3 attempts with exponential
    /// backoff -> sent or failed. Every outcome is logged under the returned message id.
    /// In: user, template key, channel or `None`, vars, schedule. Out: `SendResponse`.
    /// Why: spec endpoint 1. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database, the sender (network in production), the clock, the sleeper.
    pub fn send_single_notification(
        &self,
        user_id: i64,
        template_key: &str,
        channel: Option<&str>,
        vars: &HashMap<String, String>,
        scheduled_at: Option<DateTime<Utc>>,
    ) -> SqlResult<SendResponse> {
        let template = self.load_template(template_key)?;
        if let Some(ch) = channel {
            if !CHANNELS.contains(&ch) {
                return Err(rusqlite::Error::InvalidParameterName(format!("unknown channel {:?}", ch)));
            }
        }
        let prefs = self.get_user_preferences(user_id)?;
        let message_id = new_message_id();
        let now = (self.clock)();
        let skip = |reason: &str, ch: &str| -> SqlResult<SendResponse> {
            self.log(&message_id, user_id, template_key, ch, vars, "skipped", 0, scheduled_at, None, Some(reason))?;
            Ok(SendResponse { success: false, message_id: message_id.clone(), status: "skipped".into() })
        };
        let requested = channel.unwrap_or("auto");
        if prefs.do_not_disturb {
            return skip("do_not_disturb", requested);
        }
        if scheduled_at.map(|t| t <= now).unwrap_or(true) && in_quiet_hours(&prefs, now) {
            return skip("quiet_hours", requested);
        }
        let enabled = |ch: &str| *prefs.channels_enabled.get(ch).unwrap_or(&true);
        let chosen = match channel {
            Some(ch) => ch.to_string(),
            None => match template.channels_default.iter().find(|c| enabled(c) && !(c.as_str() == "email" && prefs.unsubscribed)) {
                Some(c) => c.clone(),
                None => return skip("no_enabled_channel", "none"),
            },
        };
        if !enabled(&chosen) {
            return skip("channel_disabled", &chosen);
        }
        if chosen == "email" && prefs.unsubscribed {
            return skip("unsubscribed", &chosen);
        }
        if let Some(at) = scheduled_at {
            if at > now {
                self.log(&message_id, user_id, template_key, &chosen, vars, "queued", 0, scheduled_at, None, None)?;
                return Ok(SendResponse { success: true, message_id, status: "queued".into() });
            }
        }

        let mut body_text = render(&template.body_text, vars, false);
        let mut body_html = render(&template.body_html, vars, true);
        if chosen == "email" {
            let link = (self.unsubscribe_link)(user_id);
            body_text.push_str(&format!("\n\nUnsubscribe: {}", link));
            if !body_html.is_empty() {
                body_html.push_str(&format!("<p><a href=\"{}\">Unsubscribe</a></p>", escape_html(&link)));
            }
        }
        let message = OutgoingMessage {
            message_id: message_id.clone(),
            user_id,
            channel: chosen.clone(),
            subject: render(&template.subject, vars, false),
            body_text,
            body_html,
            vars: vars.clone(),
        };
        let mut last_error = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            match self.sender.send(&message) {
                Ok(()) => {
                    self.log(&message_id, user_id, template_key, &chosen, vars, "sent", attempt, scheduled_at, Some((self.clock)()), None)?;
                    return Ok(SendResponse { success: true, message_id, status: "sent".into() });
                }
                Err(e) => {
                    last_error = e;
                    if attempt < MAX_ATTEMPTS {
                        (self.sleeper)(self.backoff_base * 2u32.pow(attempt - 1));
                    }
                }
            }
        }
        self.log(&message_id, user_id, template_key, &chosen, vars, "failed", MAX_ATTEMPTS, scheduled_at, None, Some(&last_error))?;
        Ok(SendResponse { success: false, message_id, status: "failed".into() })
    }

    /// What: send many notifications; sent counts sent and queued, failed counts everything else.
    /// In: requests. Out: counts and ids in request order. Why: spec endpoint 2.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as `send_single_notification`.
    pub fn send_batch_notifications(&self, requests: Vec<BatchRequest>) -> SqlResult<BatchSendResponse> {
        let (mut sent, mut failed, mut message_ids) = (0, 0, Vec::with_capacity(requests.len()));
        let tx_started = self.conn.execute_batch("BEGIN").is_ok();
        for req in requests {
            let resp = self.send_single_notification(req.user_id, &req.template_key, req.channel.as_deref(), &req.vars, req.scheduled_at);
            match resp {
                Ok(r) => {
                    if r.status == "sent" || r.status == "queued" {
                        sent += 1;
                    } else {
                        failed += 1;
                    }
                    message_ids.push(r.message_id);
                }
                Err(_) => failed += 1,
            }
        }
        if tx_started {
            self.conn.execute_batch("COMMIT")?;
        }
        Ok(BatchSendResponse { success: failed == 0, sent, failed, message_ids })
    }

    /// What: a message's tracking record. In: message id. Out: `TrackResponse`, or
    /// `QueryReturnedNoRows`. Why: spec endpoint 3. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (read).
    pub fn track_message_status(&self, message_id: &str) -> SqlResult<TrackResponse> {
        self.conn.query_row(
            "SELECT id, user_id, template_key, channel, status, bounced, sent_at, opened_at, clicked_at
             FROM notification_logs WHERE id = ?1",
            params![message_id],
            |r| {
                let status: String = r.get(4)?;
                let bounced = r.get::<_, i64>(5)? != 0;
                let opened_at = parse_time(r.get(7)?);
                Ok(TrackResponse {
                    message_id: r.get(0)?,
                    user_id: r.get(1)?,
                    template_key: r.get(2)?,
                    channel: r.get(3)?,
                    status: if bounced { "bounced".into() } else if opened_at.is_some() { "opened".into() } else { status },
                    sent_at: parse_time(r.get(6)?),
                    opened_at,
                    clicked_at: parse_time(r.get(8)?),
                })
            },
        )
    }

    /// What: set a column to now, once, on a sent message. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (write).
    fn stamp(&self, message_id: &str, column: &str) -> SqlResult<()> {
        let sql = format!("UPDATE notification_logs SET {c} = COALESCE({c}, ?1) WHERE id = ?2 AND status = 'sent'", c = column);
        let n = self.conn.execute(&sql, params![(self.clock)().to_rfc3339(), message_id])?;
        if n == 0 { Err(rusqlite::Error::QueryReturnedNoRows) } else { Ok(()) }
    }

    /// What: mark a sent message opened (the tracking link was followed). Why: spec tracking.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (write).
    pub fn mark_opened(&self, message_id: &str) -> SqlResult<()> {
        self.stamp(message_id, "opened_at")
    }

    /// What: mark a sent message clicked; a click implies it was opened. Why: spec tracking.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (write).
    pub fn mark_clicked(&self, message_id: &str) -> SqlResult<()> {
        self.stamp(message_id, "clicked_at")?;
        self.stamp(message_id, "opened_at")
    }

    /// What: record a provider bounce for a sent message. Why: spec tracking ("bounced").
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (write).
    pub fn mark_bounced(&self, message_id: &str) -> SqlResult<()> {
        let n = self.conn.execute("UPDATE notification_logs SET bounced = 1 WHERE id = ?1 AND status = 'sent'", params![message_id])?;
        if n == 0 { Err(rusqlite::Error::QueryReturnedNoRows) } else { Ok(()) }
    }

    /// What: in-app messages for a user, newest last, ids only. Why: spec "In-app: store in
    /// notification_logs, fetch via /notifications endpoint". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (read).
    pub fn list_in_app(&self, user_id: i64) -> SqlResult<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT id FROM notification_logs WHERE user_id = ?1 AND channel = 'in_app' AND status = 'sent' ORDER BY rowid",
        )?;
        let ids = stmt.query_map(params![user_id], |r| r.get(0))?.collect::<SqlResult<Vec<String>>>()?;
        Ok(ids)
    }
}

/// What: a fixed UTC time, for clocks in tests and examples. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn fixed_time(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, mo, d, h, mi, 0).single().unwrap_or_else(Utc::now)
}

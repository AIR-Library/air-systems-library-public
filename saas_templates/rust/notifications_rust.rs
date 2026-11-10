//! Notifications: templated email, SMS and in-app messages with user preferences (TIER 2 spec,
//! system 2).
//!
//! What: `NotificationService` renders the spec's templates (`{variable}` substitution, one pass),
//! honours do-not-disturb, quiet hours, per-channel preferences and email unsubscribe, sends through an
//! injected `Sender` with up to 4 attempts (3 retries) and exponential backoff, and logs every message (sent,
//! queued, skipped or failed) so it can be tracked, opened and clicked. A message scheduled for later is
//! logged `queued`; the host must call `deliver_due` on a schedule (for example every minute from its
//! job runner or cron) to send the queued messages whose time has come (added for the CodeRabbit
//! review on PR 19, 2026-11-10: queued rows were never delivered).
//! Why: the old file did not compile (two `update_user_preferences`, `?` in a `bool` function, the
//! removed `NO_PARAMS`), used the local wall clock for quiet hours, faked failures from a template
//! variable inside production code, sent every email to a hard-coded address, and "unsubscribed" users
//! by turning on do-not-disturb for every channel. Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Amended 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-02/05/11/12): default preferences have no
//! quiet hours, do-not-disturb off and SMS off; email unsubscribe links carry an HMAC-SHA256 token (the
//! secret must be at least 32 bytes or the service refuses to start), GET on the link only confirms and
//! POST unsubscribes (channels_enabled[channel] = false); quiet hours queue the message until
//! quiet_hours_end; `deliver_due(now)` re-queues rows stuck at 'sending' for over 300 s, claims due rows
//! with a conditional update, re-checks preferences and finishes with a write conditional on its claim.
//! Amended 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, NOTIF-05/07/08): a failed send is
//! retried up to 3 times after the first attempt (4 attempts, waiting 1 s, 2 s and 4 s); `deliver_due`
//! re-checks quiet hours (HH:MM, UTC, may cross midnight) and puts a due message that falls inside them
//! back to 'queued' with scheduled_at = quiet_hours_end; `open_message` (GET /notifications/open/:id)
//! sets opened_at and status 'opened' the first time only and answers 204 either way.
//! Touches: the SQLite database it is given (in memory for tests); the network only through the
//! injected sender; no money.

use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, TimeZone, Timelike, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension, Result as SqlResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Duration;

/// The channels the service knows.
pub const CHANNELS: [&str; 3] = ["email", "sms", "in_app"];
/// Attempts per message before it is logged as failed: the first plus up to 3 retries (spec, amended
/// 2026-11-10 Phase B.2: "retry up to 3 times after the first attempt (at most 4 attempts)"; it was 3
/// attempts in all). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
pub const MAX_ATTEMPTS: u32 = 4;
/// The wait before the first retry; it doubles before each later one: 1 s, 2 s, 4 s (spec, Phase B.2;
/// it was 500 ms). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
pub const RETRY_BACKOFF_BASE: Duration = Duration::from_secs(1);
/// A row claimed ('sending') longer ago than this is taken to belong to a crashed worker (spec: 300 s).
pub const STALE_CLAIM_SECS: i64 = 300;
/// Shortest accepted unsubscribe secret, in bytes (spec: the service refuses to start below 32).
pub const MIN_UNSUBSCRIBE_SECRET_BYTES: usize = 32;

/// What: a time as stored: RFC 3339, UTC, microseconds, `Z`, fixed width, so text order is time order
/// and SQL can compare stored times as text. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// What: the default channel settings: email on, SMS off (opt-in: it costs money and marketing texts
/// need prior consent), in-app on. Why: 2026-11-10 amendment (NOTIF-02). 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn default_channels() -> HashMap<String, bool> {
    [("email", true), ("sms", false), ("in_app", true)].iter().map(|(c, on)| (c.to_string(), *on)).collect()
}

/// What: create the spec's three tables (the log has status, scheduled_at and claimed_at; quiet hours
/// are nullable). In: a connection. Out: `()` or a SQLite error. Why: executable schema; claimed_at and
/// nullable quiet hours added 2026-11-10 (NOTIF-05/12). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: database (DDL).
pub fn init_db(conn: &Connection) -> SqlResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS notification_templates (
            key TEXT PRIMARY KEY, subject TEXT NOT NULL, body_text TEXT NOT NULL, body_html TEXT NOT NULL,
            channels_default TEXT NOT NULL, variables TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS notification_logs (
            id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, template_key TEXT NOT NULL, channel TEXT NOT NULL,
            vars_used TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL, scheduled_at TEXT NULL, claimed_at TEXT NULL, sent_at TEXT NULL, opened_at TEXT NULL,
            clicked_at TEXT NULL, bounced INTEGER NOT NULL DEFAULT 0, error TEXT NULL);
         CREATE INDEX IF NOT EXISTS notification_logs_due ON notification_logs (status, scheduled_at);
         CREATE TABLE IF NOT EXISTS user_notification_preferences (
            user_id INTEGER PRIMARY KEY, do_not_disturb INTEGER NOT NULL, quiet_hours_start TEXT NULL,
            quiet_hours_end TEXT NULL, channels_enabled TEXT NOT NULL);",
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

/// What: a user's preferences. Quiet hours are "HH:MM" in UTC, `None` (the default) for none; equal
/// start and end also mean none. Changed 2026-11-10 (NOTIF-02/05): quiet hours are optional and the
/// separate `unsubscribed` flag is gone (unsubscribing turns the channel off).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserNotificationPreferences {
    pub user_id: i64,
    pub do_not_disturb: bool,
    pub quiet_hours_start: Option<String>,
    pub quiet_hours_end: Option<String>,
    pub channels_enabled: HashMap<String, bool>,
}

/// What: the outcome counts of one `deliver_due` run. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
/// (NOTIF-12). `deferred` (added 2026-11-10, Phase B.2, NOTIF-05) counts due messages put back to
/// 'queued' until quiet_hours_end because the user is in quiet hours now. Touches: nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliverCounts {
    pub requeued: usize,
    pub sent: usize,
    pub skipped: usize,
    pub failed: usize,
    pub deferred: usize,
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
    unsubscribe_secret: Vec<u8>,
    base_url: String,
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

/// What: is `now` inside the [start, end) quiet window? A window may wrap midnight; unset, equal or
/// invalid bounds mean no quiet hours. In: preferences, time. Out: bool. Why: spec "Quiet hours: check
/// before sending". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn in_quiet_hours(prefs: &UserNotificationPreferences, now: DateTime<Utc>) -> bool {
    let (Some(start), Some(end)) = (
        prefs.quiet_hours_start.as_deref().and_then(parse_hhmm),
        prefs.quiet_hours_end.as_deref().and_then(parse_hhmm),
    ) else {
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

/// What: the next time of day `end` ("HH:MM", UTC) after `now`: when a message queued in quiet hours
/// becomes due. In: time, end. Out: the instant, or `None` for an invalid end.
/// Why: 2026-11-10 amendment (NOTIF-05: queued with scheduled_at = quiet_hours_end).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn quiet_hours_end_after(now: DateTime<Utc>, end: &str) -> Option<DateTime<Utc>> {
    let minutes = parse_hhmm(end)?;
    let midnight = now.date_naive().and_hms_opt(0, 0, 0)?.and_utc();
    let today = midnight + ChronoDuration::minutes(minutes as i64);
    Some(if today > now { today } else { today + ChronoDuration::days(1) })
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

/// What: constant-time equality of two byte strings (unequal lengths are simply false).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-11). Touches: nothing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// What: methods of `NotificationService`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl NotificationService {
    /// What: a service on an in-memory SQLite database with a `FakeSender`, the system clock, no real
    /// sleeping between retries, and a fresh random 32-byte unsubscribe secret (never a hard-coded one).
    /// Why: tests and demos. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory, OS randomness.
    pub fn new_in_memory() -> SqlResult<Self> {
        let mut secret = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let svc = Self::new(Connection::open_in_memory()?, Box::new(FakeSender::default()), &secret)?;
        Ok(svc.with_sleeper(Box::new(|_| {})))
    }

    /// What: a production service: creates the tables and default templates, uses the system clock and
    /// real sleeps between retries. The unsubscribe secret comes from configuration and must be at least
    /// 32 bytes, or the service refuses to start (an empty key makes a forgeable HMAC).
    /// In: a connection, a provider, the unsubscribe secret. Out: the service or an error.
    /// Changed 2026-11-10 (NOTIF-11): the secret parameter. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (DDL and templates).
    pub fn new(conn: Connection, sender: Box<dyn Sender>, unsubscribe_secret: &[u8]) -> SqlResult<Self> {
        if unsubscribe_secret.len() < MIN_UNSUBSCRIBE_SECRET_BYTES {
            return Err(rusqlite::Error::InvalidParameterName("unsubscribe secret must be at least 32 bytes".into()));
        }
        init_db(&conn)?;
        load_default_templates(&conn)?;
        Ok(Self {
            conn,
            sender,
            clock: Box::new(Utc::now),
            sleeper: Box::new(std::thread::sleep),
            backoff_base: RETRY_BACKOFF_BASE,
            unsubscribe_secret: unsubscribe_secret.to_vec(),
            base_url: "https://app.example.com".to_string(),
        })
    }

    /// What: replace the clock. Why: quiet hours and schedules must be testable at a fixed time.
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

    /// What: set the public base URL of unsubscribe links (no trailing slash needed). Replaces the old
    /// free-form `with_unsubscribe_link` (2026-11-10, NOTIF-11: links must carry the signed token).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn with_base_url(mut self, base_url: &str) -> Self {
        self.base_url = base_url.trim_end_matches('/').to_string();
        self
    }

    /// What: the unsubscribe token: lowercase hex of HMAC-SHA256(secret, "unsubscribe:" + user_id + ":" +
    /// channel). In: user id, channel. Out: 64 hex characters. Why: 2026-11-10 amendment (NOTIF-11).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn unsubscribe_token(&self, user_id: i64, channel: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.unsubscribe_secret).expect("HMAC accepts any key length");
        mac.update(format!("unsubscribe:{}:{}", user_id, channel).as_bytes());
        mac.finalize().into_bytes().iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// What: the unsubscribe link `<base_url>/unsubscribe?user_id=<id>&channel=<channel>&token=<token>`.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-11). Touches: nothing.
    pub fn unsubscribe_link(&self, user_id: i64, channel: &str) -> String {
        format!("{}/unsubscribe?user_id={}&channel={}&token={}", self.base_url, user_id, channel, self.unsubscribe_token(user_id, channel))
    }

    /// What: the unsubscribe link's handler. A token that is missing or not exactly 64 characters of
    /// [0-9a-f], an unknown channel, or a token that does not match (constant-time comparison, no panic
    /// on unequal lengths) all get 403 {error: "invalid_unsubscribe_token"}, before any user lookup.
    /// Then GET only returns a confirmation and changes nothing (mail scanners follow links); POST sets
    /// channels_enabled[channel] = false; any other method is 405.
    /// In: HTTP method, user id, channel and token from the link. Out: (HTTP status, JSON body).
    /// Why: 2026-11-10 amendment (NOTIF-11): an unsigned link lets anyone unsubscribe anyone.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (preferences) on POST only.
    pub fn handle_unsubscribe(&self, method: &str, user_id: i64, channel: &str, token: Option<&str>) -> SqlResult<(u16, Value)> {
        let refused = (403, json!({ "error": "invalid_unsubscribe_token" }));
        let Some(token) = token else { return Ok(refused) };
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Ok(refused);
        }
        if !CHANNELS.contains(&channel) {
            return Ok(refused);
        }
        if !ct_eq(token.as_bytes(), self.unsubscribe_token(user_id, channel).as_bytes()) {
            return Ok(refused);
        }
        match method.to_ascii_uppercase().as_str() {
            "GET" => Ok((200, json!({ "confirm": true, "user_id": user_id, "channel": channel,
                "message": format!("Press the button to stop {} notifications.", channel) }))),
            "POST" => {
                let mut p = self.get_user_preferences(user_id)?;
                p.channels_enabled.insert(channel.to_string(), false);
                self.save_preferences(&p)?;
                Ok((200, json!({ "success": true, "channel": channel, "unsubscribed": true })))
            }
            _ => Ok((405, json!({ "error": "method_not_allowed" }))),
        }
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

    /// What: a user's preferences, or the defaults: do_not_disturb false, no quiet hours, channels
    /// {email: true, sms: false, in_app: true}; a channel missing from stored settings takes its default.
    /// In: user id. Out: preferences. Why: spec "Get user preferences"; defaults amended 2026-11-10
    /// (NOTIF-02: SMS is opt-in; NOTIF-05: no quiet hours). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (read).
    pub fn get_user_preferences(&self, user_id: i64) -> SqlResult<UserNotificationPreferences> {
        let row = self
            .conn
            .query_row(
                "SELECT do_not_disturb, quiet_hours_start, quiet_hours_end, channels_enabled
                 FROM user_notification_preferences WHERE user_id = ?1",
                params![user_id],
                |r| {
                    let stored: String = r.get(3)?;
                    let mut channels = default_channels();
                    let stored: HashMap<String, bool> = serde_json::from_str(&stored).unwrap_or_default();
                    channels.extend(stored);
                    Ok(UserNotificationPreferences {
                        user_id,
                        do_not_disturb: r.get::<_, i64>(0)? != 0,
                        quiet_hours_start: r.get(1)?,
                        quiet_hours_end: r.get(2)?,
                        channels_enabled: channels,
                    })
                },
            )
            .optional()?;
        Ok(row.unwrap_or_else(|| UserNotificationPreferences {
            user_id,
            do_not_disturb: false,
            quiet_hours_start: None,
            quiet_hours_end: None,
            channels_enabled: default_channels(),
        }))
    }

    /// What: save the preferences. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn save_preferences(&self, p: &UserNotificationPreferences) -> SqlResult<()> {
        let channels = serde_json::to_string(&p.channels_enabled).unwrap_or_else(|_| "{}".into());
        self.conn.execute(
            "INSERT OR REPLACE INTO user_notification_preferences
                (user_id, do_not_disturb, quiet_hours_start, quiet_hours_end, channels_enabled)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![p.user_id, p.do_not_disturb as i64, p.quiet_hours_start, p.quiet_hours_end, channels],
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
            p.quiet_hours_start = Some(v.trim().to_string());
        }
        if let Some(v) = &update.quiet_hours_end {
            p.quiet_hours_end = Some(v.trim().to_string());
        }
        if let Some(ch) = &update.channels_enabled {
            for (k, v) in ch {
                p.channels_enabled.insert(k.clone(), *v);
            }
        }
        self.save_preferences(&p)
    }

    /// What: unsubscribe a user from email (channels_enabled.email = false); SMS and in-app are
    /// untouched. The signed link (`handle_unsubscribe`) does the same for any channel. In: user id.
    /// Out: `()`. Why: spec "user unsubscribed, future emails skipped"; since 2026-11-10 (NOTIF-11) it
    /// turns the channel off instead of setting a separate flag. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (write).
    pub fn unsubscribe_user(&self, user_id: i64) -> SqlResult<()> {
        let mut p = self.get_user_preferences(user_id)?;
        p.channels_enabled.insert("email".to_string(), false);
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
                status, attempts, ts((self.clock)()), scheduled_at.map(ts), sent_at.map(ts), error],
        )?;
        Ok(())
    }

    /// What: the channel to use now, or why the message is skipped: do-not-disturb; the requested
    /// channel turned off; or ("auto") the template's first default channel the user has on, else
    /// "no_enabled_channel". In: preferences, requested channel ("auto" or a channel), template.
    /// Out: Ok(channel) or Err(reason). Why: shared by the immediate send and `deliver_due`, which
    /// re-checks preferences at delivery time (2026-11-10, NOTIF-12). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn choose_channel(prefs: &UserNotificationPreferences, requested: &str, template: &NotificationTemplate) -> Result<String, &'static str> {
        if prefs.do_not_disturb {
            return Err("do_not_disturb");
        }
        let enabled = |ch: &str| *prefs.channels_enabled.get(ch).unwrap_or(&false);
        if requested != "auto" {
            return if enabled(requested) { Ok(requested.to_string()) } else { Err("channel_disabled") };
        }
        template.channels_default.iter().find(|c| enabled(c)).cloned().ok_or("no_enabled_channel")
    }

    /// What: send one templated notification. Order: unknown template or channel -> error;
    /// do-not-disturb -> skipped; a future `scheduled_at`, or now inside the user's quiet hours ->
    /// stored 'queued' with scheduled_at (the requested time, or the next quiet_hours_end) for
    /// `deliver_due`; a disabled or unavailable channel -> skipped; otherwise up to 4 attempts (3 retries; changed 2026-11-10, Phase B.2) with
    /// exponential backoff -> sent or failed. Every outcome is logged under the returned message id.
    /// In: user, template key, channel or `None` (auto), vars, schedule. Out: `SendResponse`.
    /// Why: spec endpoint 1; quiet hours queue instead of dropping since the 2026-11-10 amendment
    /// (NOTIF-05). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
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
        let requested = channel.unwrap_or("auto");
        let skip = |reason: &str, ch: &str| -> SqlResult<SendResponse> {
            self.log(&message_id, user_id, template_key, ch, vars, "skipped", 0, scheduled_at, None, Some(reason))?;
            Ok(SendResponse { success: false, message_id: message_id.clone(), status: "skipped".into() })
        };
        if prefs.do_not_disturb {
            return skip("do_not_disturb", requested);
        }
        let mut due = scheduled_at.filter(|t| *t > now);
        if due.is_none() && in_quiet_hours(&prefs, now) {
            due = prefs.quiet_hours_end.as_deref().and_then(|end| quiet_hours_end_after(now, end));
        }
        if let Some(at) = due {
            self.log(&message_id, user_id, template_key, requested, vars, "queued", 0, Some(at), None, None)?;
            return Ok(SendResponse { success: true, message_id, status: "queued".into() });
        }
        let chosen = match Self::choose_channel(&prefs, requested, &template) {
            Ok(c) => c,
            Err(reason) => return skip(reason, requested),
        };
        let message = self.build_message(&template, &message_id, user_id, &chosen, vars);
        match self.send_with_retries(&message) {
            Ok(attempt) => {
                self.log(&message_id, user_id, template_key, &chosen, vars, "sent", attempt, scheduled_at, Some((self.clock)()), None)?;
                Ok(SendResponse { success: true, message_id, status: "sent".into() })
            }
            Err(last_error) => {
                self.log(&message_id, user_id, template_key, &chosen, vars, "failed", MAX_ATTEMPTS, scheduled_at, None, Some(&last_error))?;
                Ok(SendResponse { success: false, message_id, status: "failed".into() })
            }
        }
    }

    /// What: render a template into a provider message; email gets the signed unsubscribe link (text
    /// and HTML). In: template, message id, user, chosen channel, vars. Out: `OutgoingMessage`.
    /// Why: shared by `send_single_notification` and `deliver_due` so a queued message is rendered
    /// exactly like an immediate one (CodeRabbit review on PR 19); the link is signed since 2026-11-10
    /// (NOTIF-11). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn build_message(&self, template: &NotificationTemplate, message_id: &str, user_id: i64, channel: &str, vars: &HashMap<String, String>) -> OutgoingMessage {
        let mut body_text = render(&template.body_text, vars, false);
        let mut body_html = render(&template.body_html, vars, true);
        if channel == "email" {
            let link = self.unsubscribe_link(user_id, "email");
            body_text.push_str(&format!("\n\nUnsubscribe: {}", link));
            if !body_html.is_empty() {
                body_html.push_str(&format!("<p><a href=\"{}\">Unsubscribe</a></p>", escape_html(&link)));
            }
        }
        OutgoingMessage {
            message_id: message_id.to_string(),
            user_id,
            channel: channel.to_string(),
            subject: render(&template.subject, vars, false),
            body_text,
            body_html,
            vars: vars.clone(),
        }
    }

    /// What: hand a message to the sender up to `MAX_ATTEMPTS` (4) times: the first attempt and up to 3
    /// retries, waiting `backoff_base` (1 s), then 2 s, then 4 s before them; no wait after the last.
    /// In: the message. Out: `Ok(attempt that succeeded)` or `Err(last provider error)`. Why: the one retry
    /// loop for immediate and queued messages (moved out of `send_single_notification` for the CodeRabbit
    /// review on PR 19); counting changed 2026-11-10 (Phase B.2, NOTIF-08: 3 retries after the first
    /// attempt, as background jobs count; it made 3 attempts in all with 0.5 s / 1 s).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the sender (network in production), the sleeper.
    fn send_with_retries(&self, message: &OutgoingMessage) -> Result<u32, String> {
        let mut last_error = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            match self.sender.send(message) {
                Ok(()) => return Ok(attempt),
                Err(e) => {
                    last_error = e;
                    if attempt < MAX_ATTEMPTS {
                        (self.sleeper)(self.backoff_base * 2u32.pow(attempt - 1));
                    }
                }
            }
        }
        Err(last_error)
    }

    /// What: deliver the queued messages that are due at `now`, exactly once; the host calls this on a
    /// schedule (never an in-process timer, which a restart loses). In order:
    /// 1. 'sending' rows with claimed_at + 300 s < now go back to 'queued' (a crashed worker);
    /// 2. 'queued' rows with scheduled_at <= now, by scheduled_at then insertion order, are claimed one
    ///    by one: UPDATE ... SET status = 'sending', claimed_at = now WHERE id = ? AND status = 'queued'
    ///    (a row another worker claimed first is skipped);
    /// 3. preferences are checked NOW: channel off (an unsubscribe), no enabled channel, or
    ///    do-not-disturb -> 'skipped'; inside the user's quiet hours at `now` -> back to 'queued' with
    ///    scheduled_at = the next quiet_hours_end and claimed_at cleared (counted as `deferred`);
    /// 4. the final write is UPDATE ... WHERE id = ? AND status = 'sending' AND claimed_at = <this claim>.
    /// In: now. Out: counts {requeued, sent, skipped, failed, deferred}.
    /// Why: CodeRabbit review on PR 19 (queued rows were never delivered); steps 1-4 from the 2026-11-10
    /// amendment (NOTIF-12); the quiet-hours re-check from Phase B.2 (2026-11-10, NOTIF-05: a scheduled
    /// message that fell due inside quiet hours was sent anyway). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (notification_logs), the sender (network in production), the sleeper.
    pub fn deliver_due(&self, now: DateTime<Utc>) -> SqlResult<DeliverCounts> {
        let mut counts = DeliverCounts::default();
        let claim = ts(now);
        // 1. re-queue stale claims (compared as instants, not text)
        let stuck: Vec<(String, String)> = {
            let mut stmt = self.conn.prepare("SELECT id, claimed_at FROM notification_logs WHERE status = 'sending' ORDER BY rowid")?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get::<_, Option<String>>(1)?.unwrap_or_default())))?.collect::<SqlResult<Vec<_>>>()?;
            rows
        };
        for (id, claimed_at) in stuck {
            let stale = parse_time(Some(claimed_at.clone())).map_or(true, |c| c + ChronoDuration::seconds(STALE_CLAIM_SECS) < now);
            if stale {
                counts.requeued += self.conn.execute(
                    "UPDATE notification_logs SET status = 'queued', claimed_at = NULL WHERE id = ?1 AND status = 'sending' AND claimed_at IS ?2",
                    params![id, if claimed_at.is_empty() { None } else { Some(claimed_at) }],
                )?;
            }
        }
        // 2. claim due rows one by one
        let due: Vec<String> = {
            let mut stmt = self.conn.prepare(
                "SELECT id FROM notification_logs WHERE status = 'queued' AND scheduled_at IS NOT NULL AND scheduled_at <= ?1
                 ORDER BY scheduled_at, rowid",
            )?;
            let rows = stmt.query_map(params![claim], |r| r.get(0))?.collect::<SqlResult<Vec<String>>>()?;
            rows
        };
        for id in due {
            let claimed = self.conn.execute(
                "UPDATE notification_logs SET status = 'sending', claimed_at = ?2 WHERE id = ?1 AND status = 'queued'",
                params![id, claim],
            )?;
            if claimed != 1 {
                continue;
            }
            let (user_id, template_key, requested, vars_json): (i64, String, String, String) = self.conn.query_row(
                "SELECT user_id, template_key, channel, vars_used FROM notification_logs WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
            // 4. every outcome is written only if this claim still holds
            let finish = |status: &str, channel: &str, attempts: u32, sent_at: Option<DateTime<Utc>>, error: Option<&str>| -> SqlResult<usize> {
                self.conn.execute(
                    "UPDATE notification_logs SET status = ?2, channel = ?3, attempts = ?4, sent_at = ?5, error = ?6
                     WHERE id = ?1 AND status = 'sending' AND claimed_at = ?7",
                    params![id, status, channel, attempts, sent_at.map(ts), error, claim],
                )
            };
            let template = match self.load_template(&template_key) {
                Ok(t) => t,
                Err(e) => {
                    counts.failed += finish("failed", &requested, 0, None, Some(&format!("template: {}", e)))?;
                    continue;
                }
            };
            // 3. preferences as they are now
            let prefs = self.get_user_preferences(user_id)?;
            let channel = match Self::choose_channel(&prefs, &requested, &template) {
                Ok(c) => c,
                Err(reason) => {
                    counts.skipped += finish("skipped", &requested, 0, None, Some(reason))?;
                    continue;
                }
            };
            // 3b. quiet hours as they are now (Phase B.2, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
            if in_quiet_hours(&prefs, now) {
                if let Some(end) = prefs.quiet_hours_end.as_deref().and_then(|end| quiet_hours_end_after(now, end)) {
                    counts.deferred += self.conn.execute(
                        "UPDATE notification_logs SET status = 'queued', scheduled_at = ?2, claimed_at = NULL
                         WHERE id = ?1 AND status = 'sending' AND claimed_at = ?3",
                        params![id, ts(end), claim],
                    )?;
                    continue;
                }
            }
            let vars: HashMap<String, String> = serde_json::from_str(&vars_json).unwrap_or_default();
            let message = self.build_message(&template, &id, user_id, &channel, &vars);
            match self.send_with_retries(&message) {
                Ok(attempt) => counts.sent += finish("sent", &channel, attempt, Some((self.clock)()), None)?,
                Err(last_error) => counts.failed += finish("failed", &channel, MAX_ATTEMPTS, None, Some(&last_error))?,
            }
        }
        Ok(counts)
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

    /// What: set a column to now, once, on a delivered (sent or opened) message. In: message id, column.
    /// Out: `()`, or `QueryReturnedNoRows` for an unknown or undelivered message. Changed 2026-11-10 (Phase
    /// B.2): an opened message (status 'opened') still takes a click. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (write).
    fn stamp(&self, message_id: &str, column: &str) -> SqlResult<()> {
        let sql = format!("UPDATE notification_logs SET {c} = COALESCE({c}, ?1) WHERE id = ?2 AND status IN ('sent', 'opened')", c = column);
        let n = self.conn.execute(&sql, params![ts((self.clock)()), message_id])?;
        if n == 0 { Err(rusqlite::Error::QueryReturnedNoRows) } else { Ok(()) }
    }

    /// What: record the first opening of a sent message: opened_at = now and status 'opened', only while
    /// it is 'sent' and not yet opened, so a second opening changes nothing. In: message id. Out: how many
    /// rows changed (1 the first time, else 0). Why: NOTIF-07 (Phase B.2). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (write).
    fn record_open(&self, message_id: &str) -> SqlResult<usize> {
        self.conn.execute(
            "UPDATE notification_logs SET opened_at = ?1, status = 'opened' WHERE id = ?2 AND status = 'sent' AND opened_at IS NULL",
            params![ts((self.clock)()), message_id],
        )
    }

    /// What: GET /notifications/open/:message_id, the tracking pixel or link (this template has no router,
    /// so the host routes that path here). The first call on a sent message sets opened_at and status
    /// 'opened'; any later call, or an unknown or unsent id, changes nothing. In: message id. Out: the HTTP
    /// status, always 204 (so the answer never says whether an id exists or was opened before), or a
    /// database error. Why: NOTIF-07 (Phase B.2, 2026-11-10: the spec now names this endpoint).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (write).
    pub fn open_message(&self, message_id: &str) -> SqlResult<u16> {
        self.record_open(message_id)?;
        Ok(204)
    }

    /// What: mark a delivered message opened (the tracking link was followed): as `open_message`, but an
    /// unknown or undelivered message is `QueryReturnedNoRows`; a second call is `Ok` and changes nothing.
    /// Why: spec tracking; since 2026-11-10 (Phase B.2, NOTIF-07) it also sets status 'opened', once.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (write).
    pub fn mark_opened(&self, message_id: &str) -> SqlResult<()> {
        if self.record_open(message_id)? == 0 {
            let opened: Option<String> = self
                .conn
                .query_row("SELECT status FROM notification_logs WHERE id = ?1 AND status = 'opened'", params![message_id], |r| r.get(0))
                .optional()?;
            opened.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        }
        Ok(())
    }

    /// What: mark a delivered message clicked; a click implies it was opened. Why: spec tracking.
    /// Changed 2026-11-10 (Phase B.2): goes through `mark_opened`, so the status becomes 'opened'.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (write).
    pub fn mark_clicked(&self, message_id: &str) -> SqlResult<()> {
        self.stamp(message_id, "clicked_at")?;
        self.mark_opened(message_id)
    }

    /// What: record a provider bounce for a delivered (sent or opened) message. Why: spec tracking
    /// ("bounced"). Changed 2026-11-10 (Phase B.2): an opened message can still bounce later.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (write).
    pub fn mark_bounced(&self, message_id: &str) -> SqlResult<()> {
        let n = self.conn.execute("UPDATE notification_logs SET bounced = 1 WHERE id = ?1 AND status IN ('sent', 'opened')", params![message_id])?;
        if n == 0 { Err(rusqlite::Error::QueryReturnedNoRows) } else { Ok(()) }
    }

    /// What: in-app messages for a user, newest last, ids only. Why: spec "In-app: store in
    /// notification_logs, fetch via /notifications endpoint". Changed 2026-11-10 (Phase B.2): an opened
    /// message (status 'opened') is still listed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (read).
    pub fn list_in_app(&self, user_id: i64) -> SqlResult<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT id FROM notification_logs WHERE user_id = ?1 AND channel = 'in_app' AND status IN ('sent', 'opened') ORDER BY rowid",
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

# Repaired 2026-11-03: timezone-aware UTC times (datetime.utcnow is deprecated).
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: SQLite, SMTP and SMS (mocked in tests).
# Amended 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-02/05/11/12, spec amended after review on PR 19 and an
#   independent security review): default preferences have no quiet hours and SMS off; unsubscribe links carry
#   an HMAC-SHA256 token (secret >= 32 bytes from configuration, else the service refuses to start), GET only
#   confirms and POST unsubscribes; quiet hours and future sends are stored 'queued' with scheduled_at and sent
#   by deliver_due(now) (claim with a conditional update, re-check preferences, re-queue stale 'sending' rows),
#   never by an in-process timer; time comes from an injectable clock; senders and the retry sleep are
#   injectable so tests use no network and do not wait.
import hashlib
import hmac
import json
import os
import smtplib
import sqlite3
import threading
import time
from datetime import datetime, time as dtime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional, Tuple

# ---------- Database Setup ----------
DB_PATH = ":memory:"  # In-memory DB for simplicity; replace with file path as needed

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS notification_templates (
    key TEXT PRIMARY KEY,
    subject TEXT,
    body_text TEXT,
    body_html TEXT,
    channels_default TEXT, -- JSON array e.g. ["email","in_app"]
    variables TEXT          -- JSON array of variable names
);

CREATE TABLE IF NOT EXISTS notification_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    template_key TEXT,
    channel TEXT,
    vars_used TEXT,          -- JSON object
    sent_at TEXT,
    opened_at TEXT,
    clicked_at TEXT,
    bounced INTEGER DEFAULT 0,
    error TEXT,
    status TEXT,            -- queued, sending, sent, skipped, failed (plus opened, clicked tracking)
    attempt INTEGER DEFAULT 0,
    scheduled_at TEXT,      -- when a queued row is due (quiet hours end or a future send)
    claimed_at TEXT         -- when deliver_due claimed it ('sending')
);
CREATE INDEX IF NOT EXISTS idx_notification_logs_due ON notification_logs (status, scheduled_at, id);

CREATE TABLE IF NOT EXISTS user_notification_preferences (
    user_id INTEGER PRIMARY KEY,
    do_not_disturb INTEGER DEFAULT 0,
    quiet_hours_start TEXT,   -- "22:00" (UTC) or NULL
    quiet_hours_end TEXT,     -- "08:00" (UTC) or NULL
    channels_enabled TEXT     -- JSON object e.g. {"email":true,"sms":false,"in_app":true}
);
"""

DEFAULT_TEMPLATES = [
    {
        "key": "welcome_email",
        "subject": "Welcome to {app_name}!",
        "body_text": "Welcome to {app_name}! Here's your first step.",
        "body_html": "<p>Welcome to {app_name}! Here's your first step.</p>",
        "channels_default": json.dumps(["email", "in_app"]),
        "variables": json.dumps(["app_name"]),
    },
    {
        "key": "trial_starting",
        "subject": "Your trial is starting",
        "body_text": "Your free trial is starting. You have {trial_days} days.",
        "body_html": "<p>Your free trial is starting. You have {trial_days} days.</p>",
        "channels_default": json.dumps(["email", "in_app"]),
        "variables": json.dumps(["trial_days"]),
    },
    {
        "key": "trial_ending_soon",
        "subject": "Trial ending soon",
        "body_text": "Your trial ends in {days_left} days. Add payment method to continue.",
        "body_html": "<p>Your trial ends in {days_left} days. Add payment method to continue.</p>",
        "channels_default": json.dumps(["email", "in_app"]),
        "variables": json.dumps(["days_left"]),
    },
    {
        "key": "subscription_changed",
        "subject": "Subscription changed",
        "body_text": "Your plan changed from {old_tier} to {new_tier}. Effective {effective_date}.",
        "body_html": "<p>Your plan changed from {old_tier} to {new_tier}. Effective {effective_date}.</p>",
        "channels_default": json.dumps(["email", "in_app"]),
        "variables": json.dumps(["old_tier", "new_tier", "effective_date"]),
    },
    {
        "key": "payment_failed",
        "subject": "Payment failed",
        "body_text": "Payment failed for invoice {invoice_id}. {retry_date} retry, or update payment method.",
        "body_html": "<p>Payment failed for invoice {invoice_id}. {retry_date} retry, or update payment method.</p>",
        "channels_default": json.dumps(["email", "in_app"]),
        "variables": json.dumps(["invoice_id", "retry_date"]),
    },
    {
        "key": "deployment_live",
        "subject": "Deployment live",
        "body_text": "Your deployment {deployment_name} is now live at {url}.",
        "body_html": "<p>Your deployment {deployment_name} is now live at {url}.</p>",
        "channels_default": json.dumps(["email", "in_app"]),
        "variables": json.dumps(["deployment_name", "url"]),
    },
    {
        "key": "user_invited",
        "subject": "You are invited",
        "body_text": "You've been invited to {workspace}. Click here to join.",
        "body_html": "<p>You've been invited to {workspace}. Click here to join.</p>",
        "channels_default": json.dumps(["email", "in_app"]),
        "variables": json.dumps(["workspace"]),
    },
    {
        "key": "invoice_ready",
        "subject": "Invoice ready",
        "body_text": "Your invoice for {month} is ready. Download here.",
        "body_html": "<p>Your invoice for {month} is ready. Download here.</p>",
        "channels_default": json.dumps(["email", "in_app"]),
        "variables": json.dumps(["month"]),
    },
    {
        "key": "admin_alert",
        "subject": "Admin alert",
        "body_text": "{actor} performed {action} on {resource}.",
        "body_html": "<p>{actor} performed {action} on {resource}.</p>",
        "channels_default": json.dumps(["email", "sms", "in_app"]),
        "variables": json.dumps(["actor", "action", "resource"]),
    },
]

# ---------- Helper Functions ----------
CHANNELS = ("email", "sms", "in_app")
DEFAULT_CHANNELS_ENABLED = {"email": True, "sms": False, "in_app": True}
STALE_CLAIM_SECONDS = 300
# Email/SMS retries after the first attempt (4 attempts in all, waiting 1 s / 2 s / 4 s). NOTIF-08 as amended in
# Phase B.2, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP; the same counting as background jobs.
MAX_RETRIES = 3
MIN_SECRET_BYTES = 32
_HEX = frozenset("0123456789abcdef")


def _iso(dt: datetime) -> str:
    """An aware datetime as fixed-width UTC ISO-8601 ("2026-11-10T12:00:00.000000Z"), so stored times compare
    correctly as text. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 time (a trailing Z or no offset means UTC) to an aware datetime. Touches nothing."""
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _parse_time(t_str: str) -> dtime:
    return datetime.strptime(t_str, "%H:%M").time()

def _in_quiet_hours(start: Optional[str], end: Optional[str], now: dtime) -> bool:
    """True if `now` (UTC time of day) is inside [start, end), which may wrap midnight; False when either bound is
    unset (the default: no quiet hours, NOTIF-05 as amended 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)."""
    if not start or not end:
        return False
    start_t = _parse_time(start)
    end_t = _parse_time(end)
    if start_t == end_t:
        return False
    if start_t < end_t:
        return start_t <= now < end_t
    else:  # wraps midnight
        return now >= start_t or now < end_t


def _quiet_hours_end_after(now: datetime, end: str) -> datetime:
    """The next time of day `end` (UTC) after `now`: when a message queued in quiet hours is due.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-05). Touches nothing."""
    end_t = _parse_time(end)
    target = now.astimezone(timezone.utc).replace(hour=end_t.hour, minute=end_t.minute, second=0, microsecond=0)
    return target if target > now else target + timedelta(days=1)

def _render_template(text: str, variables: Dict[str, Any]) -> str:
    return text.format(**variables)

def _send_email(to_address: str, subject: str, body_text: str, body_html: str) -> None:
    # Simple SMTP send; replace with real credentials in production
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = "no-reply@example.com"
    msg['To'] = to_address

    part1 = MIMEText(body_text, 'plain')
    part2 = MIMEText(body_html, 'html')
    msg.attach(part1)
    msg.attach(part2)

    with smtplib.SMTP('localhost') as server:
        server.sendmail(msg['From'], [to_address], msg.as_string())

def _send_sms(to_number: str, body: str) -> None:
    # Placeholder for Twilio/AWS SNS integration
    # In production, raise exception on failure
    pass

# ---------- Core Service ----------
class NotificationService:
    def __init__(self, db_path: str = DB_PATH, unsubscribe_secret: Optional[Any] = None, clock=None,
                 email_sender=None, sms_sender=None, sleep=None, base_url: str = "https://example.com"):
        """Open the notification store.

        In: db_path; unsubscribe_secret (bytes or str; default the NOTIFICATIONS_UNSUBSCRIBE_SECRET environment
        variable), at least 32 bytes or ValueError: the service refuses to start (an empty key makes a forgeable
        HMAC); clock (aware UTC datetime; default the wall clock); email_sender(to, subject, text, html) and
        sms_sender(to, body) (default the module's _send_email/_send_sms, looked up at call time); sleep(seconds)
        for retry backoff (default time.sleep); base_url for unsubscribe links.
        Why: NOTIF-11/12 (spec amended 2026-11-10) and docs/specs/README.md (injectable clock and senders).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite (creates tables, seeds templates).
        """
        secret = unsubscribe_secret if unsubscribe_secret is not None else os.environ.get("NOTIFICATIONS_UNSUBSCRIBE_SECRET", "")
        secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        if len(secret_bytes) < MIN_SECRET_BYTES:
            raise ValueError("unsubscribe secret must be at least 32 bytes (set NOTIFICATIONS_UNSUBSCRIBE_SECRET)")
        self._unsubscribe_key = secret_bytes
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._email_sender = email_sender or (lambda *a: _send_email(*a))
        self._sms_sender = sms_sender or (lambda *a: _send_sms(*a))
        self._sleep = sleep or time.sleep
        self.base_url = base_url.rstrip("/")
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_db()
        self.lock = threading.Lock()

    def _init_db(self):
        cur = self.conn.cursor()
        cur.executescript(SCHEMA_SQL)
        # Insert default templates if not present
        for tmpl in DEFAULT_TEMPLATES:
            cur.execute(
                "INSERT OR IGNORE INTO notification_templates (key, subject, body_text, body_html, channels_default, variables) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    tmpl["key"],
                    tmpl["subject"],
                    tmpl["body_text"],
                    tmpl["body_html"],
                    tmpl["channels_default"],
                    tmpl["variables"],
                ),
            )
        self.conn.commit()

    # ---------- Preference Management ----------
    def get_user_preferences(self, user_id: int) -> Dict[str, Any]:
        """The user's preferences; a user who has set none gets (and stores) the defaults: do_not_disturb false,
        no quiet hours, channels {email: true, sms: false, in_app: true}.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] NOTIF-02/05 as amended: the defaults were quiet hours
        22:00-08:00 and SMS on (SMS is opt-in: it costs money and needs prior consent). Touches: SQLite."""
        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM user_notification_preferences WHERE user_id = ?", (user_id,)
        )
        row = cur.fetchone()
        if row:
            return {
                "user_id": user_id,
                "do_not_disturb": bool(row["do_not_disturb"]),
                "quiet_hours_start": row["quiet_hours_start"],
                "quiet_hours_end": row["quiet_hours_end"],
                "channels_enabled": json.loads(row["channels_enabled"]),
            }
        else:
            # Default preferences
            default = {
                "user_id": user_id,
                "do_not_disturb": False,
                "quiet_hours_start": None,
                "quiet_hours_end": None,
                "channels_enabled": dict(DEFAULT_CHANNELS_ENABLED),
            }
            cur.execute(
                "INSERT OR IGNORE INTO user_notification_preferences (user_id, do_not_disturb, quiet_hours_start, quiet_hours_end, channels_enabled) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    user_id,
                    int(default["do_not_disturb"]),
                    default["quiet_hours_start"],
                    default["quiet_hours_end"],
                    json.dumps(default["channels_enabled"]),
                ),
            )
            self.conn.commit()
            return default

    def update_user_preferences(self, user_id: int, updates: Dict[str, Any]) -> None:
        pref = self.get_user_preferences(user_id)
        pref.update(updates)
        cur = self.conn.cursor()
        cur.execute(
            "UPDATE user_notification_preferences SET do_not_disturb = ?, quiet_hours_start = ?, quiet_hours_end = ?, channels_enabled = ? "
            "WHERE user_id = ?",
            (
                int(pref["do_not_disturb"]),
                pref["quiet_hours_start"],
                pref["quiet_hours_end"],
                json.dumps(pref["channels_enabled"]),
                user_id,
            ),
        )
        self.conn.commit()

    # ---------- Unsubscribe links (NOTIF-11) ----------
    def unsubscribe_token(self, user_id: Any, channel: str) -> str:
        """Lowercase hex HMAC-SHA256(secret, "unsubscribe:" + user_id + ":" + channel). 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-11). Touches nothing."""
        message = f"unsubscribe:{user_id}:{channel}".encode("utf-8")
        return hmac.new(self._unsubscribe_key, message, hashlib.sha256).hexdigest()

    def unsubscribe_link(self, user_id: Any, channel: str) -> str:
        """<base_url>/unsubscribe?user_id=<id>&channel=<channel>&token=<token>. 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-11). Touches nothing."""
        return (f"{self.base_url}/unsubscribe?user_id={user_id}&channel={channel}"
                f"&token={self.unsubscribe_token(user_id, channel)}")

    def handle_unsubscribe(self, method: str, user_id: Any, channel: Any, token: Any) -> Dict[str, Any]:
        """The unsubscribe link's handler. Out: {status, body}.

        A token that is not exactly 64 chars of [0-9a-f], an unknown channel, or a token that does not match
        (constant-time compare) all get 403 {error: "invalid_unsubscribe_token"}, before any user lookup and
        without raising on unequal lengths. Then GET only returns a confirmation (changes nothing; mail scanners
        follow links) and POST sets channels_enabled[channel] = false. Other methods: 405.
        Why: NOTIF-11 (spec amended 2026-11-10: an unsigned link lets anyone unsubscribe anyone).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite (preferences) on POST only."""
        refused = {"status": 403, "body": {"error": "invalid_unsubscribe_token"}}
        if not isinstance(token, str) or len(token) != 64 or not set(token) <= _HEX:
            return refused
        if channel not in CHANNELS:
            return refused
        expected = self.unsubscribe_token(user_id, channel)
        if not hmac.compare_digest(token.encode("ascii"), expected.encode("ascii")):
            return refused
        verb = (method or "").upper()
        if verb == "GET":
            return {"status": 200, "body": {"confirm": True, "user_id": user_id, "channel": channel,
                                            "message": f"Press the button to stop {channel} notifications."}}
        if verb != "POST":
            return {"status": 405, "body": {"error": "method_not_allowed"}}
        pref = self.get_user_preferences(user_id)
        channels = dict(pref["channels_enabled"])
        channels[channel] = False
        self.update_user_preferences(user_id, {"channels_enabled": channels})
        return {"status": 200, "body": {"success": True, "channel": channel, "unsubscribed": True}}

    # ---------- Notification Sending ----------
    def _held_by_quiet_hours(self, pref: Dict[str, Any], channel: Optional[str], template_key: str) -> bool:
        """Whether quiet hours hold this message: only email and SMS are held; an in-app message is stored at once
        (it interrupts no one). The channel is the requested one, else the template's first enabled default; when
        that cannot be told (no template, no enabled channel) the message is held as before, and the later steps
        give their usual answer. In: preferences, the requested channel, the template key. Out: bool.
        Why: NOTIF-05 as amended in Phase B.3 (spec notifications.md, 2026-11-10). 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite (reads the template)."""
        held_channel = channel
        if not held_channel:
            tmpl = self._get_template(template_key)
            if tmpl is not None:
                held_channel, _reason = self._skip_reason(pref, None, tmpl)
        return held_channel != "in_app"

    def _skip_reason(self, pref: Dict[str, Any], channel: Optional[str], tmpl: sqlite3.Row) -> Tuple[Optional[str], Optional[str]]:
        """Pick the channel or the reason to skip. Out: (channel, None) or (None, "do_not_disturb" |
        "channel_disabled" | "no_enabled_channel"). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: shared by the
        immediate send and deliver_due, which re-checks preferences at delivery time (NOTIF-12). Touches nothing."""
        if pref["do_not_disturb"]:
            return None, "do_not_disturb"
        channels_enabled = pref["channels_enabled"]
        if channel:
            if not channels_enabled.get(channel, False):
                return None, "channel_disabled"
            return channel, None
        for ch in json.loads(tmpl["channels_default"]):
            if channels_enabled.get(ch, False):
                return ch, None
        return None, "no_enabled_channel"

    def _dispatch(self, user_id: int, tmpl: sqlite3.Row, channel: str, vars: Dict[str, Any]) -> Optional[str]:
        """Render and send one message: the first attempt plus up to MAX_RETRIES (3) retries, so at most 4
        attempts, waiting 1 s, 2 s and 4 s between them (via the injected sleep). Emails carry the signed
        unsubscribe link. In: user_id, the template row, the channel, the template vars. Out: None on success,
        else the last error text. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (factored out of
        send_notification; adds the unsubscribe link, NOTIF-11). Updated 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP: NOTIF-08 as amended in Phase B.2 (it made 3 attempts in all, waiting
        2 s and 4 s). Touches: the email / SMS sender (network in production)."""
        subject = _render_template(tmpl["subject"], vars)
        body_text = _render_template(tmpl["body_text"], vars)
        body_html = _render_template(tmpl["body_html"], vars)
        max_attempts = MAX_RETRIES + 1
        for attempt in range(1, max_attempts + 1):
            try:
                if channel == "email":
                    # In real implementation, retrieve user's email address
                    to_address = f"user{user_id}@example.com"
                    link = self.unsubscribe_link(user_id, "email")
                    self._email_sender(to_address, subject, f"{body_text}\n\nUnsubscribe: {link}",
                                       f'{body_html}<p><a href="{link}">Unsubscribe</a></p>')
                elif channel == "sms":
                    # Retrieve phone number placeholder
                    to_number = f"+100000000{user_id%10}"
                    self._sms_sender(to_number, body_text)
                elif channel == "in_app":
                    pass  # in-app is the stored log row itself
                else:
                    raise ValueError("Unsupported channel")
                return None
            except Exception as e:
                if attempt >= max_attempts:
                    return str(e) or e.__class__.__name__
                self._sleep(2 ** (attempt - 1))  # 1 s, 2 s, 4 s
        return "unreachable"

    def send_notification(
        self,
        user_id: int,
        template_key: str,
        channel: Optional[str] = None,
        vars: Optional[Dict[str, Any]] = None,
        scheduled_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /notifications/send. Out: {success, message_id, status 'sent'|'queued'|'skipped'|'failed'}.

        Do-not-disturb and disabled channels are logged 'skipped'. A send with scheduled_at in the future, or
        one that falls in the user's quiet hours, is stored 'queued' with scheduled_at (the requested time, or
        quiet_hours_end) and sent later by deliver_due(); nothing is held in memory.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] NOTIF-05/12 as amended: quiet hours and the clock use the
        injected clock, queued rows keep scheduled_at (they were dropped) and the channel (it was stored as
        "queued"), and future sends are honoured. Touches: SQLite, the senders.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.3 (NOTIF-05): quiet hours are [start, end), so a
        message sent exactly at quiet_hours_end goes out at once, and they hold email and SMS only: an in-app
        message is stored at once (see _held_by_quiet_hours)."""
        vars = vars or {}
        now = self.clock()
        pref = self.get_user_preferences(user_id)

        # Do Not Disturb check
        if pref["do_not_disturb"]:
            log_id = self._log(user_id, template_key, channel, vars, error="do_not_disturb", status="skipped")
            return {"success": True, "message_id": str(log_id), "status": "skipped"}

        # Scheduled for later, or quiet hours: queue for deliver_due
        due = _parse_iso(scheduled_at) if scheduled_at else None
        if due is None and _in_quiet_hours(pref["quiet_hours_start"], pref["quiet_hours_end"], now.astimezone(timezone.utc).time()):
            if self._held_by_quiet_hours(pref, channel, template_key):
                due = _quiet_hours_end_after(now, pref["quiet_hours_end"])
        if due is not None and due > now:
            if not self._get_template(template_key):
                return {"success": False, "error": "template_not_found"}
            log_id = self._log(user_id, template_key, channel, vars, error=None, status="queued",
                               scheduled_at=_iso(due), sent=False)
            return {"success": True, "message_id": str(log_id), "status": "queued"}

        # Resolve template
        tmpl = self._get_template(template_key)
        if not tmpl:
            return {"success": False, "error": "template_not_found"}

        chosen_channel, reason = self._skip_reason(pref, channel, tmpl)
        if reason:
            log_id = self._log(user_id, template_key, channel, vars, error=reason, status="skipped")
            return {"success": True, "message_id": str(log_id), "status": "skipped"}

        error = self._dispatch(user_id, tmpl, chosen_channel, vars)
        if error is None:
            log_id = self._log(user_id, template_key, chosen_channel, vars, error=None, status="sent", sent=True)
            return {"success": True, "message_id": str(log_id), "status": "sent"}
        log_id = self._log(user_id, template_key, chosen_channel, vars, error=error, status="failed",
                           attempt=MAX_RETRIES + 1)
        return {"success": False, "message_id": str(log_id), "status": "failed", "error": error}

    def deliver_due(self, now: Optional[datetime] = None) -> Dict[str, int]:
        """Send every queued message that is due, exactly once (call from a scheduled job, never a timer).

        In: now (default the clock). Out: {requeued, sent, skipped, failed}. In order:
        1. 'sending' rows with claimed_at + 300 s < now go back to 'queued' (a crashed worker);
        2. 'queued' rows with scheduled_at <= now, by scheduled_at then insertion order, are claimed one by one
           with UPDATE ... SET status='sending', claimed_at=now WHERE id=? AND status='queued' (a row another
           worker claimed first is skipped);
        3. preferences are checked NOW: unsubscribed, channel off or do-not-disturb -> 'skipped'; inside the
           user's quiet hours -> back to 'queued' with scheduled_at = quiet_hours_end (counted in "requeued");
        4. the final write is UPDATE ... WHERE id=? AND status='sending' AND claimed_at=<this claim>.
        Why: NOTIF-12 (spec amended 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: step 3's quiet-hours re-queue (NOTIF-05, Phase B.2;
        a due message used to be sent inside quiet hours). Phase B.3 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP):
        the re-queue applies to email and SMS only; an in-app message is stored at once.
        Touches: SQLite (notification_logs), the senders."""
        now = now or self.clock()
        now_s = _iso(now)
        counts = {"requeued": 0, "sent": 0, "skipped": 0, "failed": 0}
        stale = _iso(now - timedelta(seconds=STALE_CLAIM_SECONDS))
        cur = self.conn.execute(
            "UPDATE notification_logs SET status = 'queued', claimed_at = NULL "
            "WHERE status = 'sending' AND claimed_at < ?", (stale,))
        counts["requeued"] = cur.rowcount
        self.conn.commit()
        due_ids = [r["id"] for r in self.conn.execute(
            "SELECT id FROM notification_logs WHERE status = 'queued' AND scheduled_at IS NOT NULL "
            "AND scheduled_at <= ? ORDER BY scheduled_at, id", (now_s,)).fetchall()]
        for log_id in due_ids:
            claimed = self.conn.execute(
                "UPDATE notification_logs SET status = 'sending', claimed_at = ? WHERE id = ? AND status = 'queued'",
                (now_s, log_id)).rowcount
            self.conn.commit()
            if claimed != 1:
                continue
            row = self.conn.execute("SELECT * FROM notification_logs WHERE id = ?", (log_id,)).fetchone()
            tmpl = self._get_template(row["template_key"])
            vars = json.loads(row["vars_used"] or "{}")
            pref = self.get_user_preferences(row["user_id"])
            if tmpl is None:
                status, channel, error = "failed", row["channel"], "template_not_found"
            else:
                channel, reason = self._skip_reason(pref, row["channel"], tmpl)
                if reason:
                    status, channel, error = "skipped", row["channel"], reason
                elif channel != "in_app" and _in_quiet_hours(pref["quiet_hours_start"], pref["quiet_hours_end"],
                                                             now.astimezone(timezone.utc).time()):
                    self.conn.execute(
                        "UPDATE notification_logs SET status = 'queued', claimed_at = NULL, scheduled_at = ? "
                        "WHERE id = ? AND status = 'sending' AND claimed_at = ?",
                        (_iso(_quiet_hours_end_after(now, pref["quiet_hours_end"])), log_id, now_s))
                    self.conn.commit()
                    counts["requeued"] += 1
                    continue
                else:
                    error = self._dispatch(row["user_id"], tmpl, channel, vars)
                    status = "sent" if error is None else "failed"
            self.conn.execute(
                "UPDATE notification_logs SET status = ?, channel = ?, error = ?, sent_at = ? "
                "WHERE id = ? AND status = 'sending' AND claimed_at = ?",
                (status, channel, error, _iso(self.clock()) if status == "sent" else None, log_id, now_s))
            self.conn.commit()
            counts[status] += 1
        return counts

    def send_batch(self, notifications: List[Dict[str, Any]]) -> Dict[str, Any]:
        sent = 0
        failed = 0
        message_ids = []
        for notif in notifications:
            res = self.send_notification(
                user_id=notif["user_id"],
                template_key=notif["template_key"],
                channel=notif.get("channel"),
                vars=notif.get("vars", {}),
                scheduled_at=notif.get("scheduled_at"),
            )
            if res.get("success"):
                sent += 1
                if res.get("message_id"):
                    message_ids.append(res["message_id"])
            else:
                failed += 1
                if res.get("message_id"):
                    message_ids.append(res["message_id"])
        return {
            "success": True,
            "sent": sent,
            "failed": failed,
            "message_ids": message_ids,
        }

    # ---------- Tracking ----------
    def track_message(self, message_id: int) -> Dict[str, Any]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM notification_logs WHERE id = ?", (message_id,)
        )
        row = cur.fetchone()
        if not row:
            return {"error": "message_not_found"}
        return {
            "message_id": row["id"],
            "user_id": row["user_id"],
            "template_key": row["template_key"],
            "channel": row["channel"],
            "status": row["status"],
            "sent_at": row["sent_at"],
            "opened_at": row["opened_at"],
            "clicked_at": row["clicked_at"],
        }

    def record_click(self, message_id: int) -> Dict[str, Any]:
        """The tracked link was clicked: set clicked_at, and opened_at if unset, and mark the message 'opened'.

        In: message id. Out: the track_message() view, or {error: "message_not_found"}. Only a sent (or already
        opened) message changes. Why: NOTIF-07 ("message marked as opened when user clicks link"); nothing ever
        set opened_at. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite."""
        now = _iso(self.clock())
        self.conn.execute(
            "UPDATE notification_logs SET clicked_at = ?, opened_at = COALESCE(opened_at, ?), status = 'opened' "
            "WHERE id = ? AND status IN ('sent', 'opened')", (now, now, message_id))
        self.conn.commit()
        return self.track_message(message_id)

    def open_message(self, message_id: Any) -> Dict[str, Any]:
        """GET /notifications/open/:message_id: the tracking pixel or link says the message was opened.

        Sets opened_at (the clock) and status 'opened' the first time only, for a message that was sent; a
        second call, an unknown id or an id that is not a number changes nothing. In: message_id. Out:
        {status: 204, body: None} either way, so the answer never says whether the id exists.
        Why: NOTIF-07 as amended in Phase B.2 (2026-11-10): only a click (record_click) set opened_at.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite (notification_logs)."""
        try:
            mid = int(message_id)
        except (TypeError, ValueError):
            return {"status": 204, "body": None}
        self.conn.execute(
            "UPDATE notification_logs SET opened_at = ?, status = 'opened' "
            "WHERE id = ? AND opened_at IS NULL AND status = 'sent'", (_iso(self.clock()), mid))
        self.conn.commit()
        return {"status": 204, "body": None}

    # ---------- Internal Helpers ----------
    def _get_template(self, key: str) -> Optional[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM notification_templates WHERE key = ?", (key,)
        )
        return cur.fetchone()

    def _log(
        self,
        user_id: int,
        template_key: str,
        channel: Optional[str],
        vars_used: Dict[str, Any],
        error: Optional[str],
        status: str,
        attempt: int = 0,
        scheduled_at: Optional[str] = None,
        sent: bool = False,
    ) -> int:
        """Insert one notification_logs row. sent_at is set only for a sent message; scheduled_at is kept for a
        queued one. [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] NOTIF-12: scheduled_at was accepted and
        dropped, and sent_at was written for skipped and queued rows too. Touches: SQLite."""
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO notification_logs (user_id, template_key, channel, vars_used, sent_at, error, status, attempt, scheduled_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                user_id,
                template_key,
                channel,
                json.dumps(vars_used),
                _iso(self.clock()) if sent else None,
                error,
                status,
                attempt,
                scheduled_at,
            ),
        )
        self.conn.commit()
        return cur.lastrowid

    # ---------- API-like Endpoints ----------
    # These methods mimic the HTTP endpoints described in the spec.

    def api_send(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self.send_notification(
            user_id=payload["user_id"],
            template_key=payload["template_key"],
            channel=payload.get("channel"),
            vars=payload.get("vars", {}),
            scheduled_at=payload.get("scheduled_at"),
        )

    def api_send_batch(self, payload: List[Dict[str, Any]]) -> Dict[str, Any]:
        return self.send_batch(payload)

    def api_track(self, message_id: str) -> Dict[str, Any]:
        return self.track_message(int(message_id))

    def api_open(self, message_id: str) -> Dict[str, Any]:
        """GET /notifications/open/:message_id (this template has no router). In: the path's message_id.
        Out: {status: 204, body: None}. Why: NOTIF-07 (Phase B.2). 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite, through open_message()."""
        return self.open_message(message_id)

    def api_get_preferences(self, user_id: int) -> Dict[str, Any]:
        return self.get_user_preferences(user_id)

    def api_update_preferences(self, user_id: int, updates: Dict[str, Any]) -> Dict[str, Any]:
        self.update_user_preferences(user_id, updates)
        return {"success": True}

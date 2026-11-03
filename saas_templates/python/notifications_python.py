# Repaired 2026-11-03: timezone-aware UTC times (datetime.utcnow is deprecated).
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: SQLite, SMTP and SMS (mocked in tests).
import json
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
    status TEXT,            -- sent, queued, skipped, failed
    attempt INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS user_notification_preferences (
    user_id INTEGER PRIMARY KEY,
    do_not_disturb INTEGER DEFAULT 0,
    quiet_hours_start TEXT,   -- "22:00"
    quiet_hours_end TEXT,     -- "08:00"
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
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _parse_time(t_str: str) -> dtime:
    return datetime.strptime(t_str, "%H:%M").time()

def _in_quiet_hours(start: str, end: str, now: dtime) -> bool:
    start_t = _parse_time(start)
    end_t = _parse_time(end)
    if start_t < end_t:
        return start_t <= now < end_t
    else:  # wraps midnight
        return now >= start_t or now < end_t

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
    def __init__(self, db_path: str = DB_PATH):
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
                "quiet_hours_start": "22:00",
                "quiet_hours_end": "08:00",
                "channels_enabled": {"email": True, "sms": True, "in_app": True},
            }
            cur.execute(
                "INSERT INTO user_notification_preferences (user_id, do_not_disturb, quiet_hours_start, quiet_hours_end, channels_enabled) "
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

    # ---------- Notification Sending ----------
    def send_notification(
        self,
        user_id: int,
        template_key: str,
        channel: Optional[str] = None,
        vars: Optional[Dict[str, Any]] = None,
        scheduled_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        vars = vars or {}
        pref = self.get_user_preferences(user_id)

        # Do Not Disturb check
        if pref["do_not_disturb"]:
            self._log(
                user_id,
                template_key,
                "skipped",
                vars,
                error="do_not_disturb",
                status="skipped",
            )
            return {"success": True, "message_id": None, "status": "skipped"}

        # Quiet hours check
        now_time = datetime.now(timezone.utc).time()
        if _in_quiet_hours(
            pref["quiet_hours_start"], pref["quiet_hours_end"], now_time
        ):
            # Queue for end of quiet hours
            end_time = _parse_time(pref["quiet_hours_end"])
            today = datetime.now(timezone.utc).date()
            if pref["quiet_hours_start"] > pref["quiet_hours_end"]:  # wraps midnight
                # End is tomorrow
                target_dt = datetime.combine(today + timedelta(days=1), end_time)
            else:
                target_dt = datetime.combine(today, end_time)
            scheduled_iso = target_dt.isoformat() + "Z"
            self._log(
                user_id,
                template_key,
                "queued",
                vars,
                error=None,
                status="queued",
                scheduled_at=scheduled_iso,
            )
            return {"success": True, "message_id": None, "status": "queued"}

        # Resolve template
        tmpl = self._get_template(template_key)
        if not tmpl:
            return {"success": False, "error": "template_not_found"}

        # Determine channel
        channels_enabled = pref["channels_enabled"]
        if channel:
            if not channels_enabled.get(channel, False):
                self._log(
                    user_id,
                    template_key,
                    "skipped",
                    vars,
                    error="channel_disabled",
                    status="skipped",
                )
                return {"success": True, "message_id": None, "status": "skipped"}
            chosen_channel = channel
        else:
            default_channels = json.loads(tmpl["channels_default"])
            chosen_channel = None
            for ch in default_channels:
                if channels_enabled.get(ch, False):
                    chosen_channel = ch
                    break
            if not chosen_channel:
                self._log(
                    user_id,
                    template_key,
                    "skipped",
                    vars,
                    error="no_enabled_channel",
                    status="skipped",
                )
                return {"success": True, "message_id": None, "status": "skipped"}

        # Render content
        subject = _render_template(tmpl["subject"], vars)
        body_text = _render_template(tmpl["body_text"], vars)
        body_html = _render_template(tmpl["body_html"], vars)

        # Send with retry
        max_attempts = 3
        attempt = 0
        while attempt < max_attempts:
            try:
                if chosen_channel == "email":
                    # In real implementation, retrieve user's email address
                    to_address = f"user{user_id}@example.com"
                    _send_email(to_address, subject, body_text, body_html)
                elif chosen_channel == "sms":
                    # Retrieve phone number placeholder
                    to_number = f"+100000000{user_id%10}"
                    _send_sms(to_number, body_text)
                elif chosen_channel == "in_app":
                    # In-app just logs; no external send
                    pass
                else:
                    raise ValueError("Unsupported channel")
                # Success
                log_id = self._log(
                    user_id,
                    template_key,
                    chosen_channel,
                    vars,
                    error=None,
                    status="sent",
                )
                return {
                    "success": True,
                    "message_id": str(log_id),
                    "status": "sent",
                }
            except Exception as e:
                attempt += 1
                if attempt >= max_attempts:
                    log_id = self._log(
                        user_id,
                        template_key,
                        chosen_channel,
                        vars,
                        error=str(e),
                        status="failed",
                        attempt=attempt,
                    )
                    return {
                        "success": False,
                        "message_id": str(log_id),
                        "status": "failed",
                        "error": str(e),
                    }
                backoff = 2 ** attempt
                time.sleep(backoff)

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
        channel: str,
        vars_used: Dict[str, Any],
        error: Optional[str],
        status: str,
        attempt: int = 0,
        scheduled_at: Optional[str] = None,
    ) -> int:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO notification_logs (user_id, template_key, channel, vars_used, sent_at, error, status, attempt) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                user_id,
                template_key,
                channel,
                json.dumps(vars_used),
                _now_iso(),
                error,
                status,
                attempt,
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

    def api_get_preferences(self, user_id: int) -> Dict[str, Any]:
        return self.get_user_preferences(user_id)

    def api_update_preferences(self, user_id: int, updates: Dict[str, Any]) -> Dict[str, Any]:
        self.update_user_preferences(user_id, updates)
        return {"success": True}

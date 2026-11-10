# Tests updated with the fix 2026-11-03: timezone-aware UTC times (datetime.utcnow is deprecated).
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: SQLite, SMTP and SMS (mocked in tests).
# [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Rewritten for the amended spec (NOTIF-02/05/11/12): the service runs
#   on an injected clock (no test depends on the time of day any more; the old setUp had to dodge the default
#   22:00-08:00 quiet hours), takes an unsubscribe secret, and its retry sleep is a no-op here. Defaults are now no
#   quiet hours and SMS off. Each test keeps what it proved before; the new ones are NOTIF-11 and NOTIF-12.
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock
from notifications_python import NotificationService, _now_iso

SECRET = "s" * 32
T0 = datetime(2026, 11, 10, 12, 0, 0, tzinfo=timezone.utc)


class TestNotificationService(unittest.TestCase):
    def setUp(self):
        """A service on a fixed clock with a 32-byte secret and no retry sleep; user 1 has every channel on. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.now = [T0]
        self.service = NotificationService(unsubscribe_secret=SECRET, clock=lambda: self.now[0],
                                           sleep=lambda seconds: None)
        # Ensure a clean user
        self.user_id = 1
        self.service.update_user_preferences(self.user_id, {
            "do_not_disturb": False,
            "channels_enabled": {"email": True, "sms": True, "in_app": True}
        })

    def _last_log(self):
        """The newest notification_logs row. Touches: the test database (read)."""
        return self.service.conn.execute("SELECT * FROM notification_logs ORDER BY id DESC LIMIT 1").fetchone()

    # NOTIF-01
    @patch('notifications_python._send_email')
    def test_send_email_with_variables(self, mock_send_email):
        """An email renders its template variables.
        In: the test fixtures. Out: assertions. Why: NOTIF-01. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: fixed clock, body checked.
        Touches: in-memory SQLite only, mocked SMTP."""
        payload = {
            "user_id": self.user_id,
            "template_key": "welcome_email",
            "channel": "email",
            "vars": {"app_name": "TestApp"},
            "scheduled_at": None
        }
        resp = self.service.api_send(payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["status"], "sent")
        mock_send_email.assert_called_once()
        args = mock_send_email.call_args[0]
        self.assertIn("user1@example.com", args[0])
        self.assertIn("Welcome to TestApp!", args[1])
        self.assertIn("Welcome to TestApp! Here's your first step.", args[2])

    # NOTIF-02
    # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] SMS is opt-in under the amended defaults: the test first shows a
    # fresh user has SMS off, then turns it on for that user.
    @patch('notifications_python._send_sms')
    def test_send_sms(self, mock_send_sms):
        """An SMS is sent once the user has turned SMS on (it is off by default).
        In: the test fixtures. Out: assertions. Why: NOTIF-02. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: opt-in step added.
        Touches: in-memory SQLite only, mocked SMS."""
        fresh = 7
        self.assertEqual(self.service.get_user_preferences(fresh)["channels_enabled"],
                         {"email": True, "sms": False, "in_app": True})
        self.service.update_user_preferences(fresh, {"channels_enabled": {"email": True, "sms": True, "in_app": True}})
        payload = {
            "user_id": fresh,
            "template_key": "admin_alert",
            "channel": "sms",
            "vars": {"actor": "Alice", "action": "deleted", "resource": "file.txt"},
            "scheduled_at": None
        }
        resp = self.service.api_send(payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["status"], "sent")
        mock_send_sms.assert_called_once()
        args = mock_send_sms.call_args[0]
        self.assertIn("+1000000007", args[0])  # phone placeholder
        self.assertIn("Alice performed deleted on file.txt.", args[1])

    # NOTIF-02
    def test_default_preferences(self):
        """A user with no preferences: no quiet hours, do_not_disturb false, SMS off; an SMS is skipped.
        Why: NOTIF-02/05 defaults (amended 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches: the test database."""
        self.assertEqual(self.service.api_get_preferences(42), {
            "user_id": 42, "do_not_disturb": False, "quiet_hours_start": None, "quiet_hours_end": None,
            "channels_enabled": {"email": True, "sms": False, "in_app": True}})
        with patch('notifications_python._send_sms') as sms:
            resp = self.service.send_notification(42, "admin_alert", "sms", {"actor": "a", "action": "b", "resource": "c"})
        self.assertEqual(resp["status"], "skipped")
        sms.assert_not_called()

    # NOTIF-03
    def test_send_in_app(self):
        payload = {
            "user_id": self.user_id,
            "template_key": "invoice_ready",
            "channel": "in_app",
            "vars": {"month": "September"},
            "scheduled_at": None
        }
        resp = self.service.api_send(payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["status"], "sent")
        # Verify log entry exists with channel in_app
        log = self.service.track_message(int(resp["message_id"]))
        self.assertEqual(log["channel"], "in_app")
        self.assertEqual(log["status"], "sent")

    # NOTIF-04
    # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Now 1,000 messages (the row says "1000+"; it sent 10), and no
    # per-user quiet window is needed: the clock is fixed and the default has no quiet hours.
    def test_batch_send(self):
        """1,000 notifications in one batch are all sent.
        In: the test fixtures. Out: assertions. Why: NOTIF-04. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: 1,000 instead of 10; no quiet-hours workaround.
        Touches: in-memory SQLite only, mocked SMTP."""
        batch = []
        for i in range(1000):
            batch.append({
                "user_id": i+2,
                "template_key": "trial_ending_soon",
                "channel": "email",
                "vars": {"days_left": 5},
                "scheduled_at": None
            })
        with patch('notifications_python._send_email') as mock_email:
            mock_email.return_value = None
            resp = self.service.api_send_batch(batch)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["sent"], 1000)
        self.assertEqual(resp["failed"], 0)
        self.assertEqual(len(resp["message_ids"]), 1000)
        self.assertEqual(mock_email.call_count, 1000)

    # NOTIF-05
    # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Uses the injected clock (12:00 UTC inside 11:00-13:00) and checks
    # the amended rule: the message is queued with scheduled_at = quiet_hours_end and deliver_due sends it then.
    def test_quiet_hours_queue(self):
        """Inside quiet hours the message is queued until quiet_hours_end and deliver_due sends it then.
        In: the test fixtures. Out: assertions. Why: NOTIF-05. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: fixed clock, scheduled_at and delivery checked.
        Touches: in-memory SQLite only, mocked SMTP."""
        self.service.update_user_preferences(self.user_id, {
            "quiet_hours_start": "11:00",
            "quiet_hours_end": "13:00"
        })
        payload = {
            "user_id": self.user_id,
            "template_key": "welcome_email",
            "channel": "email",
            "vars": {"app_name": "QuietApp"},
            "scheduled_at": None
        }
        with patch('notifications_python._send_email') as mock_email:
            resp = self.service.api_send(payload)
            self.assertTrue(resp["success"])
            self.assertEqual(resp["status"], "queued")
            mock_email.assert_not_called()
            row = self._last_log()
            self.assertEqual(row["status"], "queued")
            self.assertEqual(row["scheduled_at"], "2026-11-10T13:00:00.000000Z")
            self.assertEqual(row["channel"], "email")
            self.assertEqual(self.service.deliver_due(T0 + timedelta(minutes=59))["sent"], 0)
            self.now[0] = T0 + timedelta(hours=1)
            self.assertEqual(self.service.deliver_due()["sent"], 1)
            mock_email.assert_called_once()
        self.assertEqual(self.service.track_message(int(resp["message_id"]))["status"], "sent")
        # a window that wraps midnight queues until the next morning
        self.service.update_user_preferences(self.user_id, {"quiet_hours_start": "22:00", "quiet_hours_end": "08:00"})
        self.now[0] = datetime(2026, 11, 10, 23, 30, tzinfo=timezone.utc)
        self.assertEqual(self.service.api_send(payload)["status"], "queued")
        self.assertEqual(self._last_log()["scheduled_at"], "2026-11-11T08:00:00.000000Z")

    # NOTIF-06
    def test_do_not_disturb_skip(self):
        """Do-not-disturb logs the message as skipped.
        In: the test fixtures. Out: assertions. Why: NOTIF-06. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: fixed clock.
        Touches: in-memory SQLite only."""
        self.service.update_user_preferences(self.user_id, {"do_not_disturb": True})
        payload = {
            "user_id": self.user_id,
            "template_key": "welcome_email",
            "channel": "email",
            "vars": {"app_name": "DNDApp"},
            "scheduled_at": None
        }
        resp = self.service.api_send(payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["status"], "skipped")
        # Verify log status skipped
        row = self._last_log()
        self.assertEqual(row["status"], "skipped")
        self.assertEqual(row["error"], "do_not_disturb")

    # NOTIF-08
    @patch('notifications_python._send_email')
    def test_retry_logic(self, mock_send_email):
        # First two attempts raise exception, third succeeds
        mock_send_email.side_effect = [Exception("SMTP error"), Exception("SMTP error"), None]
        payload = {
            "user_id": self.user_id,
            "template_key": "welcome_email",
            "channel": "email",
            "vars": {"app_name": "RetryApp"},
            "scheduled_at": None
        }
        resp = self.service.api_send(payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["status"], "sent")
        self.assertEqual(mock_send_email.call_count, 3)

    # NOTIF-08
    def test_retry_at_most_three_times_with_1_2_4_second_backoff(self):
        """A failed email is retried at most 3 times after the first attempt: 3 failures then success is sent
        after 4 attempts with waits of 1 s, 2 s and 4 s; 4 failures mark the message failed after 4 attempts,
        with no 5th. In: the test fixtures, a recording sleep. Out: assertions. Why: NOTIF-08 as amended in
        Phase B.2 (2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite, a
        mocked email sender."""
        waits = []
        self.service._sleep = waits.append
        payload = {"user_id": self.user_id, "template_key": "welcome_email", "channel": "email",
                   "vars": {"app_name": "RetryApp"}, "scheduled_at": None}
        with patch('notifications_python._send_email') as mock_email:
            mock_email.side_effect = [Exception("SMTP error")] * 3 + [None]
            resp = self.service.api_send(payload)
            self.assertEqual((resp["success"], resp["status"]), (True, "sent"))
            self.assertEqual(mock_email.call_count, 4)
            self.assertEqual(waits, [1, 2, 4])
        waits.clear()
        with patch('notifications_python._send_email') as mock_email:
            mock_email.side_effect = Exception("SMTP down")
            resp = self.service.api_send(payload)
            self.assertEqual((resp["success"], resp["status"]), (False, "failed"))
            self.assertEqual(mock_email.call_count, 4)
            self.assertEqual(waits, [1, 2, 4])
        row = self._last_log()
        self.assertEqual((row["status"], row["error"], row["attempt"]), ("failed", "SMTP down", 4))

    # NOTIF-09
    def test_unsubscribe_email(self):
        # User disables email channel
        """With email off, an email is skipped as channel_disabled.
        In: the test fixtures. Out: assertions. Why: NOTIF-09. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: fixed clock.
        Touches: in-memory SQLite only."""
        self.service.update_user_preferences(self.user_id, {
            "channels_enabled": {"email": False, "sms": True, "in_app": True}
        })
        payload = {
            "user_id": self.user_id,
            "template_key": "welcome_email",
            "channel": "email",
            "vars": {"app_name": "UnsubApp"},
            "scheduled_at": None
        }
        resp = self.service.api_send(payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["status"], "skipped")
        row = self._last_log()
        self.assertEqual(row["status"], "skipped")
        self.assertEqual(row["error"], "channel_disabled")

    # NOTIF-10
    def test_user_preferences_honored(self):
        # Disable sms, request sms channel
        """A disabled channel is honoured.
        In: the test fixtures. Out: assertions. Why: NOTIF-10. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: fixed clock.
        Touches: in-memory SQLite only."""
        self.service.update_user_preferences(self.user_id, {
            "channels_enabled": {"email": True, "sms": False, "in_app": True}
        })
        payload = {
            "user_id": self.user_id,
            "template_key": "admin_alert",
            "channel": "sms",
            "vars": {"actor": "Bob", "action": "created", "resource": "project"},
            "scheduled_at": None
        }
        resp = self.service.api_send(payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["status"], "skipped")
        row = self._last_log()
        self.assertEqual(row["status"], "skipped")
        self.assertEqual(row["error"], "channel_disabled")

    # NOTIF-07
    # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Now also clicks the tracked link and checks the message is marked
    # opened (the row says so; nothing set opened_at before).
    def test_track_message(self):
        """Tracking shows the sent message; clicking its link marks it opened.
        In: the test fixtures. Out: assertions. Why: NOTIF-07. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: record_click checked.
        Touches: in-memory SQLite only, mocked SMTP."""
        payload = {
            "user_id": self.user_id,
            "template_key": "welcome_email",
            "channel": "email",
            "vars": {"app_name": "TrackApp"},
            "scheduled_at": None
        }
        with patch('notifications_python._send_email'):
            resp = self.service.api_send(payload)
        track = self.service.api_track(resp["message_id"])
        self.assertEqual(track["message_id"], int(resp["message_id"]))
        self.assertEqual(track["user_id"], self.user_id)
        self.assertEqual(track["template_key"], "welcome_email")
        self.assertEqual(track["channel"], "email")
        self.assertEqual(track["status"], "sent")
        self.assertIsNotNone(track["sent_at"])
        self.assertIsNone(track["opened_at"])
        self.now[0] = T0 + timedelta(minutes=5)
        clicked = self.service.record_click(int(resp["message_id"]))
        self.assertEqual(clicked["status"], "opened")
        self.assertEqual(clicked["opened_at"], "2026-11-10T12:05:00.000000Z")
        self.assertEqual(clicked["clicked_at"], "2026-11-10T12:05:00.000000Z")

    # NOTIF-07
    def test_open_endpoint_marks_opened_once_and_answers_204(self):
        """GET /notifications/open/:message_id (api_open) sets opened_at and status 'opened' the first time; a
        second call changes nothing; every call, an unknown or malformed id included, answers 204.
        In: the test fixtures. Out: assertions. Why: NOTIF-07 as amended in Phase B.2 (2026-11-10).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite, mocked SMTP."""
        with patch('notifications_python._send_email'):
            resp = self.service.api_send({"user_id": self.user_id, "template_key": "welcome_email",
                                          "channel": "email", "vars": {"app_name": "OpenApp"}})
        mid = resp["message_id"]
        self.now[0] = T0 + timedelta(minutes=3)
        self.assertEqual(self.service.api_open(mid), {"status": 204, "body": None})
        track = self.service.api_track(mid)
        self.assertEqual((track["status"], track["opened_at"]), ("opened", "2026-11-10T12:03:00.000000Z"))
        self.now[0] = T0 + timedelta(minutes=9)
        self.assertEqual(self.service.api_open(mid), {"status": 204, "body": None})
        self.assertEqual(self.service.api_track(mid), track)
        self.assertEqual(self.service.api_open("999999"), {"status": 204, "body": None})
        self.assertEqual(self.service.api_open("not-a-number"), {"status": 204, "body": None})

    # NOTIF-05
    def test_deliver_due_requeues_a_due_message_inside_quiet_hours(self):
        """deliver_due step 3: a message that falls due inside the user's quiet hours (a window crossing
        midnight, in UTC) goes back to 'queued' with scheduled_at = quiet_hours_end and is sent then, once.
        In: the test fixtures. Out: assertions. Why: NOTIF-05 / deliver_due step 3 as amended in Phase B.2
        (2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite, mocked SMTP."""
        with patch('notifications_python._send_email') as mock_email:
            resp = self.service.api_send({"user_id": self.user_id, "template_key": "welcome_email",
                                          "channel": "email", "vars": {"app_name": "Night"},
                                          "scheduled_at": "2026-11-10T23:00:00Z"})
            self.assertEqual(resp["status"], "queued")
            self.service.update_user_preferences(self.user_id, {"quiet_hours_start": "22:00",
                                                                "quiet_hours_end": "08:00"})
            self.now[0] = datetime(2026, 11, 10, 23, 0, tzinfo=timezone.utc)
            self.assertEqual(self.service.deliver_due(), {"requeued": 1, "sent": 0, "skipped": 0, "failed": 0})
            mock_email.assert_not_called()
            row = self._last_log()
            self.assertEqual((row["status"], row["scheduled_at"], row["claimed_at"]),
                             ("queued", "2026-11-11T08:00:00.000000Z", None))
            self.now[0] = datetime(2026, 11, 11, 7, 59, tzinfo=timezone.utc)
            self.assertEqual(self.service.deliver_due()["sent"], 0)
            self.now[0] = datetime(2026, 11, 11, 8, 0, tzinfo=timezone.utc)
            self.assertEqual(self.service.deliver_due(), {"requeued": 0, "sent": 1, "skipped": 0, "failed": 0})
            self.assertEqual(self.service.deliver_due()["sent"], 0)
            mock_email.assert_called_once()

    # NOTIF-05
    def test_quiet_hours_window_is_start_inclusive_end_exclusive(self):
        """Quiet hours are [start, end): a message sent exactly at quiet_hours_end goes out at once, one sent exactly
        at quiet_hours_start is queued until the end, also for a window that crosses midnight.
        In: the test fixtures. Out: assertions. Why: NOTIF-05 as amended in Phase B.3 (notifications.md,
        2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite, mocked SMTP."""
        payload = {"user_id": self.user_id, "template_key": "welcome_email", "channel": "email",
                   "vars": {"app_name": "Edge"}, "scheduled_at": None}
        with patch('notifications_python._send_email') as mock_email:
            self.service.update_user_preferences(self.user_id, {"quiet_hours_start": "11:00",
                                                                "quiet_hours_end": "12:00"})
            self.assertEqual(self.service.api_send(payload)["status"], "sent")  # T0 is 12:00, the end
            self.assertEqual(mock_email.call_count, 1)
            self.service.update_user_preferences(self.user_id, {"quiet_hours_start": "12:00",
                                                                "quiet_hours_end": "13:00"})
            self.assertEqual(self.service.api_send(payload)["status"], "queued")  # 12:00 is the start
            self.assertEqual(self._last_log()["scheduled_at"], "2026-11-10T13:00:00.000000Z")
            self.service.update_user_preferences(self.user_id, {"quiet_hours_start": "22:00",
                                                                "quiet_hours_end": "08:00"})
            self.now[0] = datetime(2026, 11, 11, 8, 0, tzinfo=timezone.utc)
            self.assertEqual(self.service.api_send(payload)["status"], "sent")
            self.now[0] = datetime(2026, 11, 11, 7, 59, 59, tzinfo=timezone.utc)
            self.assertEqual(self.service.api_send(payload)["status"], "queued")
            self.assertEqual(mock_email.call_count, 2)

    # NOTIF-05
    def test_quiet_hours_hold_email_and_sms_only(self):
        """Inside quiet hours an in-app message is stored at once (status 'sent', channel in_app), whether it names
        the channel or takes it from the template; email and SMS are still queued; and deliver_due sends a due
        in-app message inside quiet hours instead of re-queueing it.
        In: the test fixtures. Out: assertions. Why: NOTIF-05 as amended in Phase B.3 (notifications.md,
        2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite, mocked senders."""
        self.service.update_user_preferences(self.user_id, {"quiet_hours_start": "11:00", "quiet_hours_end": "13:00"})
        with patch('notifications_python._send_email') as mock_email:
            resp = self.service.api_send({"user_id": self.user_id, "template_key": "invoice_ready",
                                          "channel": "in_app", "vars": {"month": "May"}, "scheduled_at": None})
            self.assertEqual(resp["status"], "sent")
            log = self.service.track_message(int(resp["message_id"]))
            self.assertEqual((log["channel"], log["status"]), ("in_app", "sent"))
            self.service.update_user_preferences(self.user_id, {"channels_enabled": {"email": False, "sms": False,
                                                                                      "in_app": True}})
            resp = self.service.api_send({"user_id": self.user_id, "template_key": "invoice_ready",
                                          "vars": {"month": "May"}, "scheduled_at": None})
            self.assertEqual(resp["status"], "sent")
            self.assertEqual(self._last_log()["channel"], "in_app")
            self.service.update_user_preferences(self.user_id, {"channels_enabled": {"email": True, "sms": True,
                                                                                      "in_app": True}})
            resp = self.service.api_send({"user_id": self.user_id, "template_key": "welcome_email",
                                          "channel": "email", "vars": {"app_name": "Q"}, "scheduled_at": None})
            self.assertEqual(resp["status"], "queued")
            mock_email.assert_not_called()
        with patch.object(self.service, "_sms_sender") as sms:
            resp = self.service.api_send({"user_id": self.user_id, "template_key": "invoice_ready",
                                          "channel": "sms", "vars": {"month": "May"}, "scheduled_at": None})
            self.assertEqual(resp["status"], "queued")
            sms.assert_not_called()
        # deliver_due: an in-app message that falls due inside quiet hours is stored, not re-queued.
        self.now[0] = datetime(2026, 11, 10, 10, 0, tzinfo=timezone.utc)
        queued = self.service.api_send({"user_id": self.user_id, "template_key": "invoice_ready",
                                        "channel": "in_app", "vars": {"month": "May"},
                                        "scheduled_at": "2026-11-10T11:30:00Z"})
        self.assertEqual(queued["status"], "queued")
        self.now[0] = datetime(2026, 11, 10, 11, 30, tzinfo=timezone.utc)
        counts = self.service.deliver_due()
        self.assertEqual((counts["sent"], counts["requeued"]), (1, 0))
        self.assertEqual(self.service.track_message(int(queued["message_id"]))["status"], "sent")

    # NOTIF-11
    def test_unsubscribe_link(self):
        """POST with a valid token turns the channel off; GET changes nothing; a missing, short, non-hex, altered or
        other-user/other-channel token and an unknown channel all get 403 invalid_unsubscribe_token and change
        nothing; the email carries the link; a short secret refuses to start.
        Why: NOTIF-11 (amended 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test db."""
        import hashlib
        import hmac
        token = self.service.unsubscribe_token(self.user_id, "email")
        self.assertEqual(token, hmac.new(SECRET.encode(), b"unsubscribe:1:email", hashlib.sha256).hexdigest())
        refused = {"status": 403, "body": {"error": "invalid_unsubscribe_token"}}
        altered = token[:-1] + ("0" if token[-1] != "0" else "1")
        bad = [(None, "email"), ("", "email"), (token[:63], "email"), (token.upper(), "email"),
               ("z" * 64, "email"), (altered, "email"), (self.service.unsubscribe_token(2, "email"), "email"),
               (self.service.unsubscribe_token(self.user_id, "sms"), "email"), (token, "fax"), (token + "0", "email")]
        for bad_token, channel in bad:
            self.assertEqual(self.service.handle_unsubscribe("POST", self.user_id, channel, bad_token), refused)
        get = self.service.handle_unsubscribe("GET", self.user_id, "email", token)
        self.assertEqual(get["status"], 200)
        self.assertTrue(self.service.get_user_preferences(self.user_id)["channels_enabled"]["email"])
        with patch('notifications_python._send_email') as mock_email:
            self.service.send_notification(self.user_id, "welcome_email", "email", {"app_name": "X"})
        self.assertIn(self.service.unsubscribe_link(self.user_id, "email"), mock_email.call_args[0][2])
        post = self.service.handle_unsubscribe("POST", self.user_id, "email", token)
        self.assertEqual(post["status"], 200)
        self.assertEqual(self.service.get_user_preferences(self.user_id)["channels_enabled"],
                         {"email": False, "sms": True, "in_app": True})
        for short in ("", "s" * 31, b"\x00" * 31):
            with self.assertRaises(ValueError):
                NotificationService(unsubscribe_secret=short)

    # NOTIF-12
    def test_scheduled_send_delivered_once_when_due(self):
        """A send 30 days ahead is queued, not sent; deliver_due sends it once due and a second run sends nothing;
        a user who unsubscribed meanwhile is skipped; a row stuck at 'sending' over 300 s is re-queued (and sent),
        one claimed 299 s ago is left alone. Why: NOTIF-12 (amended 2026-11-10).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test database."""
        later = (T0 + timedelta(days=30)).isoformat()
        self.service.update_user_preferences(2, {"channels_enabled": {"email": True, "sms": False, "in_app": True}})
        with patch('notifications_python._send_email') as mock_email:
            first = self.service.send_notification(self.user_id, "invoice_ready", "email", {"month": "Dec"}, later)
            second = self.service.send_notification(2, "invoice_ready", "email", {"month": "Dec"}, later)
            self.assertEqual((first["status"], second["status"]), ("queued", "queued"))
            self.assertEqual(self.service.deliver_due(), {"requeued": 0, "sent": 0, "skipped": 0, "failed": 0})
            mock_email.assert_not_called()
            token = self.service.unsubscribe_token(2, "email")
            self.assertEqual(self.service.handle_unsubscribe("POST", 2, "email", token)["status"], 200)
            self.now[0] = T0 + timedelta(days=30)
            self.assertEqual(self.service.deliver_due(), {"requeued": 0, "sent": 1, "skipped": 1, "failed": 0})
            self.assertEqual(self.service.deliver_due(), {"requeued": 0, "sent": 0, "skipped": 0, "failed": 0})
            self.assertEqual(mock_email.call_count, 1)
            self.assertEqual(mock_email.call_args[0][0], "user1@example.com")
        self.assertEqual(self.service.track_message(int(first["message_id"]))["status"], "sent")
        skipped = self.service.track_message(int(second["message_id"]))
        self.assertEqual(skipped["status"], "skipped")

        # stale claims: one 301 s old (re-queued and sent), one 299 s old (left at 'sending')
        conn = self.service.conn
        for claimed in (self.now[0] - timedelta(seconds=301), self.now[0] - timedelta(seconds=299)):
            conn.execute(
                "INSERT INTO notification_logs (user_id, template_key, channel, vars_used, status, scheduled_at, claimed_at) "
                "VALUES (?, 'invoice_ready', 'in_app', '{\"month\": \"Jan\"}', 'sending', ?, ?)",
                (self.user_id, claimed.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), claimed.strftime("%Y-%m-%dT%H:%M:%S.%fZ")))
        conn.commit()
        self.assertEqual(self.service.deliver_due(), {"requeued": 1, "sent": 1, "skipped": 0, "failed": 0})
        statuses = [r["status"] for r in conn.execute(
            "SELECT status FROM notification_logs WHERE template_key = 'invoice_ready' AND channel = 'in_app' ORDER BY id")]
        self.assertEqual(statuses, ["sent", "sending"])


if __name__ == '__main__':
    unittest.main()

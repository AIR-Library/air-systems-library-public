# Tests updated with the fix 2026-11-03: timezone-aware UTC times (datetime.utcnow is deprecated).
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: SQLite, SMTP and SMS (mocked in tests).
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock
from notifications_python import NotificationService, _now_iso

class TestNotificationService(unittest.TestCase):
    def setUp(self):
        self.service = NotificationService()
        # Ensure a clean user
        self.user_id = 1
        # A quiet window that never covers the moment the tests run. It was a fixed 22:00 to 08:00 UTC, so the suite
        # failed whenever it ran at night, which turned main red on 2026-11-04 at 05:56 UTC. 2026-11-05, session f3daac6e.
        now = datetime.now(timezone.utc)
        self.service.update_user_preferences(self.user_id, {
            "do_not_disturb": False,
            "quiet_hours_start": (now + timedelta(hours=2)).strftime("%H:%M"),
            "quiet_hours_end": (now + timedelta(hours=3)).strftime("%H:%M"),
            "channels_enabled": {"email": True, "sms": True, "in_app": True}
        })

    @patch('notifications_python._send_email')
    def test_send_email_with_variables(self, mock_send_email):
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

    @patch('notifications_python._send_sms')
    def test_send_sms(self, mock_send_sms):
        payload = {
            "user_id": self.user_id,
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
        self.assertIn("+1000000001", args[0])  # phone placeholder
        self.assertIn("Alice performed deleted on file.txt.", args[1])

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

    def test_batch_send(self):
        batch = []
        for i in range(10):
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
        self.assertEqual(resp["sent"], 10)
        self.assertEqual(resp["failed"], 0)
        self.assertEqual(len(resp["message_ids"]), 10)

    def test_quiet_hours_queue(self):
        # Set quiet hours to include current UTC time
        now = datetime.utcnow()
        start = (now - timedelta(hours=1)).strftime("%H:%M")
        end = (now + timedelta(hours=1)).strftime("%H:%M")
        self.service.update_user_preferences(self.user_id, {
            "quiet_hours_start": start,
            "quiet_hours_end": end
        })
        payload = {
            "user_id": self.user_id,
            "template_key": "welcome_email",
            "channel": "email",
            "vars": {"app_name": "QuietApp"},
            "scheduled_at": None
        }
        resp = self.service.api_send(payload)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["status"], "queued")
        # Verify log status queued
        cur = self.service.conn.cursor()
        cur.execute("SELECT status FROM notification_logs ORDER BY id DESC LIMIT 1")
        status = cur.fetchone()["status"]
        self.assertEqual(status, "queued")

    def test_do_not_disturb_skip(self):
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
        cur = self.service.conn.cursor()
        cur.execute("SELECT status, error FROM notification_logs ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        self.assertEqual(row["status"], "skipped")
        self.assertEqual(row["error"], "do_not_disturb")

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

    def test_unsubscribe_email(self):
        # User disables email channel
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
        cur = self.service.conn.cursor()
        cur.execute("SELECT status, error FROM notification_logs ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        self.assertEqual(row["status"], "skipped")
        self.assertEqual(row["error"], "channel_disabled")

    def test_user_preferences_honored(self):
        # Disable sms, request sms channel
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
        cur = self.service.conn.cursor()
        cur.execute("SELECT status, error FROM notification_logs ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        self.assertEqual(row["status"], "skipped")
        self.assertEqual(row["error"], "channel_disabled")

    def test_track_message(self):
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

if __name__ == '__main__':
    unittest.main()

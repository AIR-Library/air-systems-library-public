# Notifications (Email + Sms + In-App)

Reference contract for `saas_templates/<lang>/notifications_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# NOTIF-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `NOTIF-01` | Send email with template variables |
| `NOTIF-02` | Send SMS |
| `NOTIF-03` | Send in-app (stores in DB) |
| `NOTIF-04` | Batch send 1000+ notifications |
| `NOTIF-05` | Quiet hours: a send inside the user's window (UTC, may cross midnight) is not sent now; it is queued with scheduled_at = quiet_hours_end |
| `NOTIF-06` | Do-not-disturb: skip if enabled |
| `NOTIF-07` | Track: GET /notifications/open/:message_id sets opened_at and status 'opened' once; a second call changes nothing |
| `NOTIF-08` | Retry: a failed email is retried at most 3 times (4 attempts, 1 s / 2 s / 4 s) and succeeds when the sender recovers; a 4th failure marks it failed |
| `NOTIF-09` | Unsubscribe: user unsubscribed, future emails skipped |
| `NOTIF-10` | User preferences honored: channels_enabled respected |
| `NOTIF-11` | Unsubscribe link: POST with a valid token sets channels_enabled[channel] false; GET changes nothing; a missing, short, non-hex or altered token, or an unknown channel, gets 403 invalid_unsubscribe_token and the user stays subscribed |
| `NOTIF-12` | Scheduled send: a send 30 days ahead is not sent now; deliver_due sends it once due, exactly once (a second deliver_due sends nothing); a user who unsubscribed meanwhile is skipped; a row stuck at 'sending' over 300 s is re-queued |

## Contract

```text
PURPOSE:
Send notifications via template system. Support email, SMS, in-app.
User preferences: quiet hours, do-not-disturb, channel per notification type.
Track: sent, opened, clicked, bounced.

SCHEMA:
notification_templates (key, subject, body_text, body_html, channels_default, variables)
notification_logs (id, user_id, template_key, channel, vars_used, status, scheduled_at NULL, claimed_at NULL,
                   sent_at, opened_at, clicked_at, bounced, error)
- status: 'queued' | 'sending' | 'sent' | 'skipped' | 'failed' (plus 'opened', 'clicked', 'bounced' tracking)
user_notification_preferences (user_id, do_not_disturb, quiet_hours_start, quiet_hours_end, channels_enabled [JSON])

TEMPLATES (pre-defined, editable):
- welcome_email: "Welcome to {app_name}! Here's your first step."
- trial_starting: "Your free trial is starting. You have {trial_days} days."
- trial_ending_soon: "Your trial ends in {days_left} days. Add payment method to continue."
- subscription_changed: "Your plan changed from {old_tier} to {new_tier}. Effective {effective_date}."
- payment_failed: "Payment failed for invoice {invoice_id}. {retry_date} retry, or update payment method."
- deployment_live: "Your deployment {deployment_name} is now live at {url}."
- user_invited: "You've been invited to {workspace}. Click here to join."
- invoice_ready: "Your invoice for {month} is ready. Download here."
- admin_alert: "{actor} performed {action} on {resource}."

ENDPOINTS:

1. Send single notification
   POST /notifications/send
   {
     user_id: 123,
     template_key: 'trial_ending_soon',
     channel: 'email',  // or 'sms' or 'in_app' or null (auto-select based on user preference)
     vars: {
       days_left: 3
     },
     scheduled_at: null  // or ISO 8601 for later delivery
   }
   Response: { success: true, message_id: '...', status: 'sent'|'queued'|'failed' }

2. Send batch
   POST /notifications/send-batch
   [
     { user_id: 123, template_key: 'low_credits_alert', ... },
     { user_id: 456, template_key: 'low_credits_alert', ... }
   ]
   Response: { success: true, sent: 450, failed: 2, message_ids: [...] }

3. Track message status
   GET /notifications/track/:message_id
   Response: { message_id, user_id, template_key, channel, status: 'sent'|'bounced'|'opened', sent_at, opened_at, clicked_at }

4. Get user preferences
   GET /users/:user_id/notification-preferences
   Response: { user_id, do_not_disturb: false, quiet_hours_start: null, quiet_hours_end: null, channels_enabled: { email: true, sms: false, in_app: true } }

5. Update user preferences
   PUT /users/:user_id/notification-preferences
   { do_not_disturb: false, channels_enabled: { email: true, sms: false } }
   Response: { success: true }

IMPLEMENTATION:
- Email: Use SMTP or third-party (Sendgrid, AWS SES)
- SMS: Use Twilio or AWS SNS
- In-app: Store in notification_logs, fetch via /notifications endpoint
- Quiet hours: Check before sending; in quiet hours the message is stored 'queued' with scheduled_at =
  quiet_hours_end and sent by deliver_due (below)
- Do-not-disturb: Skip sending if enabled, log as 'skipped'
- Templating: Simple variable substitution {variable_name} → value
- Retry: Email/SMS failures retry up to 3 times after the first attempt (at most 4 attempts), waiting 1 s,
  2 s and 4 s, the same counting as background jobs. Amended 2026-11-10 (Phase B.2: one answer in every language).
- Quiet hours are "HH:MM" in UTC, and a window may cross midnight (22:00-08:00). The template stores no time
  zone; a deployment that keeps one converts to UTC before comparing. The window is [start, end): a message
  due exactly at quiet_hours_end is sent. Quiet hours hold email and SMS only; an in-app message is stored at
  once (it interrupts no one). Amended 2026-11-10 (Phase B.3).
- Opening: GET /notifications/open/:message_id records that a message was opened (the tracking pixel or
  link): it sets opened_at and status 'opened' the first time only and answers 204 either way (NOTIF-07).
- Unsubscribe: Include unsubscribe link in emails (legal requirement). The link is
  <base_url>/unsubscribe?user_id=<id>&channel=<channel>&token=<token> with
  token = lowercase hex of HMAC-SHA256(secret, "unsubscribe:" + user_id + ":" + channel), the secret
  coming from configuration (never hard-coded). The unsubscribe handler recomputes the token and compares
  it in constant time; a missing or wrong token is refused (403) and changes nothing. An unsigned link lets
  anyone unsubscribe anyone. Amended 2026-11-10 after review on PR 19.
  - The service refuses to start with a secret shorter than 32 bytes (an empty key makes a forgeable HMAC).
  - A token that is not exactly 64 characters of [0-9a-f], an unknown channel, or a mismatch all get the same
    403 {error: "invalid_unsubscribe_token"}, before any user lookup. (Comparing unequal lengths must not
    throw: Node's timingSafeEqual does, which would be a 500.)
  - GET on the link only shows a confirmation; the change happens on POST, so a mail scanner that follows
    links cannot unsubscribe anyone (RFC 8058 one-click uses POST). Success sets channels_enabled[channel]
    = false.
- Default preferences for a user who has set none: do_not_disturb false, no quiet hours, channels_enabled
  {email: true, sms: false, in_app: true}. SMS is opt-in: it costs money per message and marketing texts
  need the recipient's prior consent in many countries, so it is never on until the user turns it on.
- Scheduled sends (scheduled_at in the future) are stored as 'queued' with their scheduled_at and sent by
  deliver_due(now), never by an in-process timer (lost on restart). deliver_due(now), in order:
  1. 'sending' rows with claimed_at + 300 s < now go back to 'queued' (a crashed worker);
  2. 'queued' rows with scheduled_at <= now, by scheduled_at then insertion order, are claimed one by one:
     UPDATE ... SET status = 'sending', claimed_at = now WHERE id = ? AND status = 'queued' (a row another
     worker claimed first is skipped);
  3. preferences are checked NOW, not when the message was queued: unsubscribed, channel off or
     do-not-disturb -> 'skipped'; inside the user's quiet hours -> back to 'queued' with scheduled_at =
     quiet_hours_end;
  4. the final write is UPDATE ... WHERE id = ? AND status = 'sending' AND claimed_at = <this claim>.
  That sends each message exactly once when no worker crashes, and at least once after a crash. A single
  send must finish in under 300 s. Amended 2026-11-10 after an independent security review.

TESTS:
- **NOTIF-01** Send email with template variables
- **NOTIF-02** Send SMS
- **NOTIF-03** Send in-app (stores in DB)
- **NOTIF-04** Batch send 1000+ notifications
- **NOTIF-05** Quiet hours: a send inside the user's window (UTC, may cross midnight) is not sent now; it is queued with scheduled_at = quiet_hours_end
- **NOTIF-06** Do-not-disturb: skip if enabled
- **NOTIF-07** Track: GET /notifications/open/:message_id sets opened_at and status 'opened' once; a second call changes nothing
- **NOTIF-08** Retry: a failed email is retried at most 3 times (4 attempts, 1 s / 2 s / 4 s) and succeeds when the sender recovers; a 4th failure marks it failed
- **NOTIF-09** Unsubscribe: user unsubscribed, future emails skipped
- **NOTIF-10** User preferences honored: channels_enabled respected
- **NOTIF-11** Unsubscribe link: POST with a valid token sets channels_enabled[channel] false; GET changes nothing; a missing, short, non-hex or altered token, or an unknown channel, gets 403 invalid_unsubscribe_token and the user stays subscribed
- **NOTIF-12** Scheduled send: a send 30 days ahead is not sent now; deliver_due sends it once due, exactly once (a second deliver_due sends nothing); a user who unsubscribed meanwhile is skipped; a row stuck at 'sending' over 300 s is re-queued
```

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
| `NOTIF-05` | Quiet hours: skip if in range |
| `NOTIF-06` | Do-not-disturb: skip if enabled |
| `NOTIF-07` | Track: message marked as opened when user clicks link |
| `NOTIF-08` | Retry: failed email retries and eventually succeeds |
| `NOTIF-09` | Unsubscribe: user unsubscribed, future emails skipped |
| `NOTIF-10` | User preferences honored: channels_enabled respected |
| `NOTIF-11` | Unsubscribe link: a valid token unsubscribes; a missing or altered token is refused (403) and the user stays subscribed |
| `NOTIF-12` | Scheduled send: a send 30 days ahead is not sent now; deliver_due sends it once due, exactly once |

## Contract

```text
PURPOSE:
Send notifications via template system. Support email, SMS, in-app.
User preferences: quiet hours, do-not-disturb, channel per notification type.
Track: sent, opened, clicked, bounced.

SCHEMA:
notification_templates (key, subject, body_text, body_html, channels_default, variables)
notification_logs (id, user_id, template_key, channel, vars_used, sent_at, opened_at, clicked_at, bounced, error)
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
- Quiet hours: Check before sending, queue for quiet_hours_end if in quiet hours
- Do-not-disturb: Skip sending if enabled, log as 'skipped'
- Templating: Simple variable substitution {variable_name} → value
- Retry: Email/SMS failures retry 3x with exponential backoff
- Unsubscribe: Include unsubscribe link in emails (legal requirement). The link is
  <base_url>/unsubscribe?user_id=<id>&channel=<channel>&token=<token> with
  token = lowercase hex of HMAC-SHA256(secret, "unsubscribe:" + user_id + ":" + channel), the secret
  coming from configuration (never hard-coded). The unsubscribe handler recomputes the token and compares
  it in constant time; a missing or wrong token is refused (403) and changes nothing. An unsigned link lets
  anyone unsubscribe anyone. Amended 2026-11-10 after review on PR 19.
- Default preferences for a user who has set none: do_not_disturb false, no quiet hours, channels_enabled
  {email: true, sms: false, in_app: true}. SMS is opt-in: it costs money per message and marketing texts
  need the recipient's prior consent in many countries, so it is never on until the user turns it on.
- Scheduled sends (scheduled_at in the future) are stored as 'queued' with their scheduled_at and sent by
  deliver_due(now), never by an in-process timer (lost on restart). deliver_due claims each due row
  ('queued' -> 'sending' with a conditional update, so two workers cannot both send it) and returns a row
  left at 'sending' for more than 5 minutes (a crashed worker) to 'queued'.

TESTS:
- **NOTIF-01** Send email with template variables
- **NOTIF-02** Send SMS
- **NOTIF-03** Send in-app (stores in DB)
- **NOTIF-04** Batch send 1000+ notifications
- **NOTIF-05** Quiet hours: skip if in range
- **NOTIF-06** Do-not-disturb: skip if enabled
- **NOTIF-07** Track: message marked as opened when user clicks link
- **NOTIF-08** Retry: failed email retries and eventually succeeds
- **NOTIF-09** Unsubscribe: user unsubscribed, future emails skipped
- **NOTIF-10** User preferences honored: channels_enabled respected
- **NOTIF-11** Unsubscribe link: a valid token unsubscribes; a missing or altered token is refused (403) and the user stays subscribed
- **NOTIF-12** Scheduled send: a send 30 days ahead is not sent now; deliver_due sends it once due, exactly once
```

// Package notifications is the AOI Systems Library notifications template: templated email, SMS
// and in-app messages with per-user preferences (do-not-disturb, quiet hours, channels), retries
// with exponential backoff, a queue for quiet hours and scheduled sends, signed unsubscribe links,
// and open/click tracking.
//
// Repair 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP). The suite ran and failed: users
// without preferences got quiet hours 22:00-08:00 checked against the wall clock, so at night every
// send was "queued" and the results depended on the time of day; quiet hours logged the message as
// skipped and returned an invented "queued-<nanos>" id that could not be tracked; a successful send
// panicked on sendErr.Error(); SendRequest had no JSON tags, so HTTP sends lost user_id and
// template_key; GET/PUT preferences panicked on a bad slice; a partial preferences update reset
// every other field (and stored channels_enabled as JSON null, disabling all channels);
// unsubscribes lived only in process memory; and the batch ran 50 goroutines over the pool.
// This version follows TIER_2_MASTER_SPEC_6SYSTEMS.txt system 2 and the passing Python template:
// skip checks (do-not-disturb, disabled channel, unsubscribed) first, then quiet hours queue the
// message for quiet_hours_end, ProcessQueued delivers due messages, the batch runs in request order,
// message ids are random (not guessable row numbers), template variables are HTML-escaped in the HTML
// body, unsubscribes are stored in the database and the unsubscribe link carries an HMAC token.
//
// Phase B, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-02/05/11/12, amended): default preferences
// have no quiet hours and SMS off (opt-in); the unsubscribe token binds user AND channel
// (HMAC-SHA256(secret, "unsubscribe:<user_id>:<channel>"), lowercase hex), the secret must be at least 32
// bytes or the service will not start, a malformed, wrong or unknown-channel token gets one 403
// invalid_unsubscribe_token before any user lookup, GET only confirms and POST unsubscribes; queued and
// scheduled messages are delivered by DeliverDue(now) in the spec's four steps (re-queue stale 'sending'
// claims, claim due rows with a conditional update, re-check preferences, conditional final write).
// Touches: SQL database; network through the EmailProvider and SMSProvider the host supplies.
package notifications

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// Channel is a delivery channel.
type Channel string

// Channels.
const (
	ChannelEmail Channel = "email"
	ChannelSMS   Channel = "sms"
	ChannelInApp Channel = "in_app"
)

// Status is a message's delivery state.
type Status string

// Message states.
const (
	StatusSent    Status = "sent"
	StatusQueued  Status = "queued"
	StatusSending Status = "sending" // claimed by DeliverDue (added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
	StatusFailed  Status = "failed"
	StatusBounced Status = "bounced"
	StatusOpened  Status = "opened"
	StatusClicked Status = "clicked"
	StatusSkipped Status = "skipped"
)

// Template is a notification template; {name} placeholders are replaced by vars.
type Template struct {
	Key             string
	Subject         string
	BodyText        string
	BodyHTML        string
	ChannelsDefault []Channel
	Variables       []string
}

// NotificationLog is one notification_logs row.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: MessageID (the public id) added.
type NotificationLog struct {
	ID          int64
	MessageID   string
	UserID      int64
	TemplateKey string
	Channel     Channel
	VarsUsed    string
	SentAt      *time.Time
	OpenedAt    *time.Time
	ClickedAt   *time.Time
	Bounced     bool
	Error       string
	Status      Status
}

// UserPreferences is kept for API compatibility; PreferencesResponse is what the service returns.
type UserPreferences struct {
	UserID          int64
	DoNotDisturb    bool
	QuietHoursStart string
	QuietHoursEnd   string
	ChannelsEnabled map[string]bool
}

// SendRequest is one notification to send.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: JSON tags (HTTP sends lost every field).
type SendRequest struct {
	UserID      int64                  `json:"user_id"`
	TemplateKey string                 `json:"template_key"`
	Channel     *Channel               `json:"channel"` // nil: the template's first channel the user has enabled
	Vars        map[string]interface{} `json:"vars"`
	ScheduledAt *time.Time             `json:"scheduled_at"` // future: queued until then
}

// SendResponse is the result of one send.
type SendResponse struct {
	Success   bool   `json:"success"`
	MessageID string `json:"message_id"`
	Status    Status `json:"status"`
	Error     string `json:"error,omitempty"`
}

// BatchSendResponse is the result of a batch; MessageIDs follow the request order.
type BatchSendResponse struct {
	Success    bool     `json:"success"`
	Sent       int      `json:"sent"`
	Failed     int      `json:"failed"`
	MessageIDs []string `json:"message_ids"`
}

// TrackResponse is a message's tracking state.
type TrackResponse struct {
	MessageID   string     `json:"message_id"`
	UserID      int64      `json:"user_id"`
	TemplateKey string     `json:"template_key"`
	Channel     Channel    `json:"channel"`
	Status      Status     `json:"status"`
	SentAt      *time.Time `json:"sent_at"`
	OpenedAt    *time.Time `json:"opened_at"`
	ClickedAt   *time.Time `json:"clicked_at"`
}

// PreferencesResponse is a user's notification preferences. Quiet hours are nil (JSON null) when unset.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: quiet hours are pointers, since the spec's
// default is "no quiet hours" (null), not 22:00-08:00.
type PreferencesResponse struct {
	UserID          int64           `json:"user_id"`
	DoNotDisturb    bool            `json:"do_not_disturb"`
	QuietHoursStart *string         `json:"quiet_hours_start"`
	QuietHoursEnd   *string         `json:"quiet_hours_end"`
	ChannelsEnabled map[string]bool `json:"channels_enabled"`
}

// UpdatePreferencesRequest is a partial update: nil fields and absent channels keep their value; an
// empty quiet-hours string clears it.
type UpdatePreferencesRequest struct {
	DoNotDisturb    *bool           `json:"do_not_disturb"`
	QuietHoursStart *string         `json:"quiet_hours_start"`
	QuietHoursEnd   *string         `json:"quiet_hours_end"`
	ChannelsEnabled map[string]bool `json:"channels_enabled"`
}

// ---------------------------------------------------------------------------
// Providers (interfaces; tests use fakes, production plugs in SMTP/SES/Twilio)
// ---------------------------------------------------------------------------

// EmailProvider delivers one email.
type EmailProvider interface {
	Send(ctx context.Context, to, subject, bodyText, bodyHTML string) error
}

// SMSProvider delivers one SMS.
type SMSProvider interface {
	Send(ctx context.Context, to, body string) error
}

// NullEmailProvider accepts every email and sends nothing (tests, local development).
type NullEmailProvider struct{}

// Send does nothing and succeeds.
func (NullEmailProvider) Send(ctx context.Context, to, subject, bodyText, bodyHTML string) error {
	return nil
}

// NullSMSProvider accepts every SMS and sends nothing (tests, local development).
type NullSMSProvider struct{}

// Send does nothing and succeeds.
func (NullSMSProvider) Send(ctx context.Context, to, body string) error {
	return nil
}

// ContactResolver returns where to reach a user. Added 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP: addresses used to be invented inline. Touches: the host's user store.
type ContactResolver interface {
	Contact(ctx context.Context, userID int64) (email, phone string, err error)
}

// PlaceholderContacts returns user<id>@example.invalid and an empty phone. It exists so the template
// runs out of the box with the Null providers; replace it (Service.Contacts) with a lookup in your
// user store before using a real provider. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
type PlaceholderContacts struct{}

// Contact returns the placeholder address. Touches: nothing.
func (PlaceholderContacts) Contact(_ context.Context, userID int64) (string, string, error) {
	return fmt.Sprintf("user%d@example.invalid", userID), fmt.Sprintf("+1555%07d", userID%10000000), nil
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// Service sends and tracks notifications.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: injectable clock and sleep,
// contact resolver, unsubscribe secret; unsubscribes moved to the database.
type Service struct {
	db        *sql.DB
	templates map[string]Template
	email     EmailProvider
	sms       SMSProvider
	Contacts  ContactResolver
	// UnsubscribeSecret signs unsubscribe links (at least 32 bytes, from configuration).
	UnsubscribeSecret []byte
	// BaseURL prefixes the unsubscribe link in emails.
	BaseURL string
	now     func() time.Time
	sleep   func(time.Duration)
}

// MinUnsubscribeSecretBytes is the shortest unsubscribe secret the service accepts (spec: an empty or short
// key makes a forgeable HMAC). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
const MinUnsubscribeSecretBytes = 32

// NewService builds a service whose unsubscribe secret comes from NOTIFICATIONS_UNSUBSCRIBE_SECRET.
// Inputs: database, email and SMS providers (nil = Null providers). Output: the service with the built-in
// templates, or an error when the secret is missing or shorter than 32 bytes (the service refuses to
// start). Call InitDB before use.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-11): it fell back to a random per-process
// secret, which silently broke every link on restart. Touches: the environment.
func NewService(db *sql.DB, email EmailProvider, sms SMSProvider) (*Service, error) {
	return NewServiceWithSecret(db, email, sms, []byte(os.Getenv("NOTIFICATIONS_UNSUBSCRIBE_SECRET")))
}

// NewServiceWithSecret is NewService with the unsubscribe secret passed in (at least 32 bytes).
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing until used.
func NewServiceWithSecret(db *sql.DB, email EmailProvider, sms SMSProvider, secret []byte) (*Service, error) {
	if len(secret) < MinUnsubscribeSecretBytes {
		return nil, fmt.Errorf("notifications: the unsubscribe secret must be at least %d bytes", MinUnsubscribeSecretBytes)
	}
	if email == nil {
		email = NullEmailProvider{}
	}
	if sms == nil {
		sms = NullSMSProvider{}
	}
	s := &Service{
		db: db, templates: make(map[string]Template), email: email, sms: sms,
		Contacts: PlaceholderContacts{}, UnsubscribeSecret: append([]byte(nil), secret...), BaseURL: os.Getenv("NOTIFICATIONS_BASE_URL"),
		now: time.Now, sleep: time.Sleep,
	}
	s.seedTemplates()
	return s, nil
}

// SetClock replaces the clock used for quiet hours, scheduling and timestamps (tests freeze it so
// results never depend on the time of day). Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

func (s *Service) seedTemplates() {
	defaults := []Template{
		{Key: "welcome_email", Subject: "Welcome to {app_name}!", BodyText: "Welcome to {app_name}! Here's your first step.", BodyHTML: "<p>Welcome to {app_name}! Here's your first step.</p>", ChannelsDefault: []Channel{ChannelEmail}, Variables: []string{"app_name"}},
		{Key: "trial_starting", Subject: "Your free trial is starting", BodyText: "Your free trial is starting. You have {trial_days} days.", BodyHTML: "<p>Your free trial is starting. You have {trial_days} days.</p>", ChannelsDefault: []Channel{ChannelEmail}, Variables: []string{"trial_days"}},
		{Key: "trial_ending_soon", Subject: "Your trial ends in {days_left} days", BodyText: "Your trial ends in {days_left} days. Add payment method to continue.", BodyHTML: "<p>Your trial ends in {days_left} days. Add payment method to continue.</p>", ChannelsDefault: []Channel{ChannelEmail, ChannelSMS}, Variables: []string{"days_left"}},
		{Key: "subscription_changed", Subject: "Your plan changed", BodyText: "Your plan changed from {old_tier} to {new_tier}. Effective {effective_date}.", BodyHTML: "<p>Your plan changed from {old_tier} to {new_tier}. Effective {effective_date}.</p>", ChannelsDefault: []Channel{ChannelEmail}, Variables: []string{"old_tier", "new_tier", "effective_date"}},
		{Key: "payment_failed", Subject: "Payment failed", BodyText: "Payment failed for invoice {invoice_id}. {retry_date} retry, or update payment method.", BodyHTML: "<p>Payment failed for invoice {invoice_id}. {retry_date} retry, or update payment method.</p>", ChannelsDefault: []Channel{ChannelEmail, ChannelSMS}, Variables: []string{"invoice_id", "retry_date"}},
		{Key: "deployment_live", Subject: "Deployment live", BodyText: "Your deployment {deployment_name} is now live at {url}.", BodyHTML: "<p>Your deployment {deployment_name} is now live at {url}.</p>", ChannelsDefault: []Channel{ChannelEmail, ChannelInApp}, Variables: []string{"deployment_name", "url"}},
		{Key: "user_invited", Subject: "You've been invited", BodyText: "You've been invited to {workspace}. Click here to join.", BodyHTML: "<p>You've been invited to {workspace}. <a href=\"#\">Click here to join</a>.</p>", ChannelsDefault: []Channel{ChannelEmail}, Variables: []string{"workspace"}},
		{Key: "invoice_ready", Subject: "Your invoice is ready", BodyText: "Your invoice for {month} is ready. Download here.", BodyHTML: "<p>Your invoice for {month} is ready. <a href=\"#\">Download here</a>.</p>", ChannelsDefault: []Channel{ChannelEmail}, Variables: []string{"month"}},
		{Key: "admin_alert", Subject: "Admin alert", BodyText: "{actor} performed {action} on {resource}.", BodyHTML: "<p>{actor} performed {action} on {resource}.</p>", ChannelsDefault: []Channel{ChannelInApp}, Variables: []string{"actor", "action", "resource"}},
	}
	for _, t := range defaults {
		s.templates[t.Key] = t
	}
}

// ---------------------------------------------------------------------------
// Database schema
// ---------------------------------------------------------------------------

const schemaSQL = `
CREATE TABLE IF NOT EXISTS notification_templates (
	key TEXT PRIMARY KEY,
	subject TEXT,
	body_text TEXT,
	body_html TEXT,
	channels_default TEXT,
	variables TEXT
);
CREATE TABLE IF NOT EXISTS notification_logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	message_id TEXT NOT NULL UNIQUE,
	user_id INTEGER NOT NULL,
	template_key TEXT NOT NULL,
	channel TEXT NOT NULL,
	vars_used TEXT,
	scheduled_at DATETIME,
	claimed_at DATETIME,
	sent_at DATETIME,
	opened_at DATETIME,
	clicked_at DATETIME,
	bounced INTEGER NOT NULL DEFAULT 0,
	attempts INTEGER NOT NULL DEFAULT 0,
	error TEXT,
	status TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notification_logs_user ON notification_logs(user_id, channel);
CREATE INDEX IF NOT EXISTS idx_notification_logs_status ON notification_logs(status);
CREATE TABLE IF NOT EXISTS user_notification_preferences (
	user_id INTEGER PRIMARY KEY,
	do_not_disturb INTEGER NOT NULL DEFAULT 0,
	quiet_hours_start TEXT NULL,
	quiet_hours_end TEXT NULL,
	channels_enabled TEXT NOT NULL DEFAULT '{"email":true,"sms":false,"in_app":true}'
);
CREATE TABLE IF NOT EXISTS notification_unsubscribes (
	user_id INTEGER NOT NULL,
	channel TEXT NOT NULL,
	created_at DATETIME NOT NULL,
	PRIMARY KEY (user_id, channel)
);
`

// InitDB creates the tables. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (message_id,
// scheduled_at, attempts, notification_unsubscribes; then claimed_at, and preference defaults of no
// quiet hours and SMS off, NOTIF-02/12). Touches: database.
func (s *Service) InitDB(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schemaSQL)
	return err
}

// ---------------------------------------------------------------------------
// Templating
// ---------------------------------------------------------------------------

var varRe = regexp.MustCompile(`\{(\w+)\}`)

// renderTemplate replaces {name} with vars[name]; escapeHTML escapes each value for the HTML body.
// Unknown placeholders are left as written. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP
// (values were inserted into HTML unescaped). Touches: nothing.
func renderTemplate(text string, vars map[string]interface{}, escapeHTML bool) string {
	return varRe.ReplaceAllStringFunc(text, func(m string) string {
		if v, ok := vars[m[1:len(m)-1]]; ok {
			out := fmt.Sprintf("%v", v)
			if escapeHTML {
				out = html.EscapeString(out)
			}
			return out
		}
		return m
	})
}

// newMessageID returns a random 128-bit hex id, so message ids cannot be enumerated through the
// public track/opened/clicked endpoints. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
func newMessageID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("notifications: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------------------
// Preferences
// ---------------------------------------------------------------------------

// defaultPreferences are used for a user with no stored row: do_not_disturb false, no quiet hours,
// channels {email: true, sms: false, in_app: true}. SMS is opt-in: it costs money per message and
// marketing texts need prior consent in many countries.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-02/05, amended): the defaults were quiet
// hours 22:00-08:00 and SMS on.
func defaultPreferences(userID int64) *PreferencesResponse {
	return &PreferencesResponse{UserID: userID,
		ChannelsEnabled: map[string]bool{"email": true, "sms": false, "in_app": true}}
}

// GetPreferences returns a user's preferences, or the defaults when none are stored.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (nullable quiet hours). Touches: database.
func (s *Service) GetPreferences(ctx context.Context, userID int64) (*PreferencesResponse, error) {
	var dnd int
	var qStart, qEnd sql.NullString
	var chJSON string
	err := s.db.QueryRowContext(ctx,
		"SELECT do_not_disturb, quiet_hours_start, quiet_hours_end, channels_enabled FROM user_notification_preferences WHERE user_id = ?",
		userID).Scan(&dnd, &qStart, &qEnd, &chJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return defaultPreferences(userID), nil
	}
	if err != nil {
		return nil, err
	}
	p := defaultPreferences(userID)
	p.DoNotDisturb = dnd != 0
	if qStart.Valid && qStart.String != "" {
		v := qStart.String
		p.QuietHoursStart = &v
	}
	if qEnd.Valid && qEnd.String != "" {
		v := qEnd.String
		p.QuietHoursEnd = &v
	}
	stored := map[string]bool{}
	if err := json.Unmarshal([]byte(chJSON), &stored); err == nil {
		for k, v := range stored {
			p.ChannelsEnabled[k] = v
		}
	}
	return p, nil
}

// deref returns *p, or "" for nil. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

var hhmm = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)

// UpdatePreferences applies a partial update on top of the stored (or default) preferences.
// Output: an error for malformed quiet hours or unknown channels. Changed 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP: unset fields used to be reset to defaults; quiet hours may be cleared
// with "" and are stored as NULL when unset. Touches: database.
func (s *Service) UpdatePreferences(ctx context.Context, userID int64, req *UpdatePreferencesRequest) error {
	p, err := s.GetPreferences(ctx, userID)
	if err != nil {
		return err
	}
	if req.DoNotDisturb != nil {
		p.DoNotDisturb = *req.DoNotDisturb
	}
	if req.QuietHoursStart != nil {
		if *req.QuietHoursStart != "" && !hhmm.MatchString(*req.QuietHoursStart) {
			return fmt.Errorf("quiet_hours_start must be HH:MM")
		}
		p.QuietHoursStart = req.QuietHoursStart
	}
	if req.QuietHoursEnd != nil {
		if *req.QuietHoursEnd != "" && !hhmm.MatchString(*req.QuietHoursEnd) {
			return fmt.Errorf("quiet_hours_end must be HH:MM")
		}
		p.QuietHoursEnd = req.QuietHoursEnd
	}
	for k, v := range req.ChannelsEnabled {
		switch Channel(k) {
		case ChannelEmail, ChannelSMS, ChannelInApp:
			p.ChannelsEnabled[k] = v
		default:
			return fmt.Errorf("unknown channel %q", k)
		}
	}
	chJSON, _ := json.Marshal(p.ChannelsEnabled)
	dnd := 0
	if p.DoNotDisturb {
		dnd = 1
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO user_notification_preferences (user_id, do_not_disturb, quiet_hours_start, quiet_hours_end, channels_enabled)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(user_id) DO UPDATE SET
			do_not_disturb = excluded.do_not_disturb,
			quiet_hours_start = excluded.quiet_hours_start,
			quiet_hours_end = excluded.quiet_hours_end,
			channels_enabled = excluded.channels_enabled`,
		userID, dnd, nullIfEmpty(deref(p.QuietHoursStart)), nullIfEmpty(deref(p.QuietHoursEnd)), string(chJSON))
	return err
}

// nullIfEmpty maps "" to SQL NULL. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
func nullIfEmpty(v string) interface{} {
	if v == "" {
		return nil
	}
	return v
}

// ---------------------------------------------------------------------------
// Quiet hours
// ---------------------------------------------------------------------------

// quietHoursEnd reports whether now falls in [start, end) (wrapping midnight when start > end, as in
// 22:00-08:00) and, if so, the next moment the window ends. start and end are "HH:MM" in UTC and now is
// compared in UTC, whatever its location; the release time is returned in UTC. Equal start and end mean no
// quiet hours. In: now, start, end. Out: (release, true) inside the window, (zero, false) outside it.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (returns the release time so the message is
// queued, per the spec). Changed again the same day (Phase B.2, NOTIF-05): quiet hours are UTC; they were
// compared in now's own location, so the answer depended on the server's time zone. Touches: nothing.
func quietHoursEnd(now time.Time, start, end string) (time.Time, bool) {
	if !hhmm.MatchString(start) || !hhmm.MatchString(end) || start == end {
		return time.Time{}, false
	}
	now = now.UTC()
	nowHM := now.Format("15:04")
	in := false
	if start < end {
		in = nowHM >= start && nowHM < end
	} else {
		in = nowHM >= start || nowHM < end
	}
	if !in {
		return time.Time{}, false
	}
	h, _ := strconv.Atoi(end[:2])
	m, _ := strconv.Atoi(end[3:])
	release := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
	if !release.After(now) {
		release = release.AddDate(0, 0, 1)
	}
	return release, true
}

// quietHoursHold reports whether quiet hours hold a message on this channel: email and SMS only. An in-app
// message interrupts no one and is stored at once. In: channel. Out: bool. Why: Phase B.3 ruling (commit
// d4f4ed7, notifications spec IMPLEMENTATION: "Quiet hours hold email and SMS only"); in-app messages used to
// be queued too. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
func quietHoursHold(ch Channel) bool { return ch == ChannelEmail || ch == ChannelSMS }

// ---------------------------------------------------------------------------
// Send
// ---------------------------------------------------------------------------

// isUnsubscribed reports whether the user unsubscribed from channel. Added 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
func (s *Service) isUnsubscribed(ctx context.Context, userID int64, ch Channel) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM notification_unsubscribes WHERE user_id = ? AND channel = ?", userID, string(ch)).Scan(&n)
	return n > 0, err
}

// insertLog writes a notification_logs row and returns its public message id.
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
func (s *Service) insertLog(ctx context.Context, req *SendRequest, ch Channel, status Status, scheduledAt, sentAt *time.Time, attempts int, errMsg string) (string, error) {
	varsJSON, _ := json.Marshal(req.Vars)
	id := newMessageID()
	var errVal interface{}
	if errMsg != "" {
		errVal = errMsg
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO notification_logs (message_id, user_id, template_key, channel, vars_used, scheduled_at, sent_at, attempts, error, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, req.UserID, req.TemplateKey, string(ch), string(varsJSON), timeOrNil(scheduledAt), timeOrNil(sentAt), attempts, errVal, string(status))
	return id, err
}

func timeOrNil(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return t.UTC()
}

// Send sends (or skips, or queues) one notification and logs it. Order: template and channel
// resolution; skipped if do-not-disturb, the channel is disabled or the user unsubscribed from it;
// queued if scheduled_at is in the future or the user is in quiet hours (UTC; released at
// quiet_hours_end); otherwise delivered with up to 3 retries after the first attempt (4 attempts, waiting
// 1 s, 2 s, 4 s; Phase B.2, NOTIF-08). Output:
// SendResponse with the log's message id; an error only for bad input or storage failure.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Changed again the same day (Phase B.3, commit
// d4f4ed7): quiet hours hold email and SMS only (quietHoursHold); an in-app message is stored at once.
// Touches: database, providers (network).
func (s *Service) Send(ctx context.Context, req *SendRequest) (*SendResponse, error) {
	tmpl, ok := s.templates[req.TemplateKey]
	if !ok {
		return &SendResponse{Success: false, Status: StatusFailed, Error: "template_not_found"}, fmt.Errorf("template %q not found", req.TemplateKey)
	}
	if req.UserID <= 0 {
		return &SendResponse{Success: false, Status: StatusFailed, Error: "invalid_user_id"}, fmt.Errorf("user_id must be positive")
	}
	prefs, err := s.GetPreferences(ctx, req.UserID)
	if err != nil {
		return nil, err
	}
	var channel Channel
	if req.Channel != nil {
		channel = *req.Channel
		if channel != ChannelEmail && channel != ChannelSMS && channel != ChannelInApp {
			return &SendResponse{Success: false, Status: StatusFailed, Error: "invalid_channel"}, fmt.Errorf("unknown channel %q", channel)
		}
	} else {
		for _, ch := range tmpl.ChannelsDefault {
			if prefs.ChannelsEnabled[string(ch)] {
				channel = ch
				break
			}
		}
		if channel == "" {
			channel = tmpl.ChannelsDefault[0]
		}
	}
	skip := func(reason string) (*SendResponse, error) {
		id, err := s.insertLog(ctx, req, channel, StatusSkipped, nil, nil, 0, reason)
		if err != nil {
			return nil, err
		}
		return &SendResponse{Success: true, MessageID: id, Status: StatusSkipped}, nil
	}
	if prefs.DoNotDisturb {
		return skip("do_not_disturb")
	}
	if !prefs.ChannelsEnabled[string(channel)] {
		return skip("channel_disabled")
	}
	if unsub, err := s.isUnsubscribed(ctx, req.UserID, channel); err != nil {
		return nil, err
	} else if unsub {
		return skip("unsubscribed")
	}
	now := s.now()
	var releaseAt *time.Time
	if req.ScheduledAt != nil && req.ScheduledAt.After(now) {
		t := *req.ScheduledAt
		releaseAt = &t
	} else if end, quiet := quietHoursEnd(now, deref(prefs.QuietHoursStart), deref(prefs.QuietHoursEnd)); quiet && quietHoursHold(channel) {
		releaseAt = &end
	}
	if releaseAt != nil {
		id, err := s.insertLog(ctx, req, channel, StatusQueued, releaseAt, nil, 0, "")
		if err != nil {
			return nil, err
		}
		return &SendResponse{Success: true, MessageID: id, Status: StatusQueued}, nil
	}
	attempts, sendErr := s.deliver(ctx, tmpl, req, channel)
	if sendErr != nil {
		id, err := s.insertLog(ctx, req, channel, StatusFailed, nil, nil, attempts, sendErr.Error())
		if err != nil {
			return nil, err
		}
		return &SendResponse{Success: false, MessageID: id, Status: StatusFailed, Error: "delivery_failed"}, nil
	}
	sent := s.now()
	id, err := s.insertLog(ctx, req, channel, StatusSent, nil, &sent, attempts, "")
	if err != nil {
		return nil, err
	}
	return &SendResponse{Success: true, MessageID: id, Status: StatusSent}, nil
}

// deliver renders the template and hands it to the channel's provider. A failure is retried up to 3 times
// after the first attempt (at most 4 attempts), waiting 1 s, 2 s and 4 s, the same counting as background
// jobs; a 4th failure is returned and the caller marks the message failed. In-app messages are delivered by
// being logged. In: the template, the request and the channel. Output: the number of attempts and the last
// error. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Changed the same day (Phase B.2,
// NOTIF-08): it made 3 attempts in all, waiting 100 ms and 200 ms. Touches: providers (network), the sleep
// function.
func (s *Service) deliver(ctx context.Context, tmpl Template, req *SendRequest, ch Channel) (int, error) {
	if ch == ChannelInApp {
		return 0, nil
	}
	email, phone, err := s.Contacts.Contact(ctx, req.UserID)
	if err != nil {
		return 0, fmt.Errorf("no contact for user: %w", err)
	}
	subject := renderTemplate(tmpl.Subject, req.Vars, false)
	bodyText := renderTemplate(tmpl.BodyText, req.Vars, false)
	bodyHTML := renderTemplate(tmpl.BodyHTML, req.Vars, true)
	var send func() error
	switch ch {
	case ChannelEmail:
		if email == "" {
			return 0, errors.New("no email address on file")
		}
		link := s.UnsubscribeURL(req.UserID, ChannelEmail)
		bodyText += "\n\nUnsubscribe: " + link
		bodyHTML += fmt.Sprintf("<p><a href=\"%s\">Unsubscribe</a></p>", html.EscapeString(link))
		send = func() error { return s.email.Send(ctx, email, subject, bodyText, bodyHTML) }
	case ChannelSMS:
		if phone == "" {
			return 0, errors.New("no phone number on file")
		}
		send = func() error { return s.sms.Send(ctx, phone, bodyText) }
	}
	var lastErr error
	for attempt := 1; attempt <= MaxDeliveryAttempts; attempt++ {
		if lastErr = send(); lastErr == nil {
			return attempt, nil
		}
		if attempt < MaxDeliveryAttempts {
			s.sleep(time.Duration(1<<uint(attempt-1)) * time.Second) // 1 s, 2 s, 4 s
		}
	}
	return MaxDeliveryAttempts, lastErr
}

// MaxDeliveryAttempts is the first attempt plus up to 3 retries (spec: retry up to 3 times, at most 4
// attempts, waiting 1 s, 2 s and 4 s). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2,
// NOTIF-08). Touches nothing.
const MaxDeliveryAttempts = 4

// ClaimTimeout is how long a 'sending' claim may last before DeliverDue re-queues it (spec: a single send
// must finish in under 300 s). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
const ClaimTimeout = 300 * time.Second

// DeliverDue sends queued messages that are due, in the spec's four steps (NOTIF-12):
//  1. 'sending' rows claimed more than 300 s before now go back to 'queued' (a crashed worker);
//  2. 'queued' rows with scheduled_at <= now, by scheduled_at then insertion order, are claimed one by
//     one with UPDATE ... SET status = 'sending', claimed_at = now WHERE id = ? AND status = 'queued'
//     (a row another worker claimed first is skipped);
//  3. preferences are checked NOW, not when the message was queued: unsubscribed, channel off or
//     do-not-disturb -> 'skipped'; inside the user's quiet hours (UTC) -> back to 'queued' with
//     scheduled_at = quiet_hours_end (reviewed against the Phase B.2 wording, 2026-11-10,
//     session_012zDydZCZ4AChqhEZ4oVtaP: it already did this; the comparison is now in UTC);
//  4. the final write is UPDATE ... WHERE id = ? AND status = 'sending' AND claimed_at = <this claim>.
//
// Each message is sent exactly once when no worker crashes, at least once after a crash. No in-process
// timers: a scheduler or cron calls DeliverDue. In: the time to deliver for. Out: how many were sent.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (replaces ProcessQueued, which read and updated rows
// without a claim, so two workers could send the same message). Changed the same day (Phase B.3, commit
// d4f4ed7): only email and SMS go back to 'queued' inside quiet hours. Touches: database, providers (network).
func (s *Service) DeliverDue(ctx context.Context, now time.Time) (int, error) {
	now = now.UTC()
	// Step 1: re-queue stale claims.
	stale, err := s.db.QueryContext(ctx, `SELECT id, claimed_at FROM notification_logs WHERE status = ?`, string(StatusSending))
	if err != nil {
		return 0, err
	}
	type claim struct {
		id int64
		at time.Time
	}
	var stuck []claim
	for stale.Next() {
		var c claim
		var at sql.NullTime
		if err := stale.Scan(&c.id, &at); err != nil {
			stale.Close()
			return 0, err
		}
		if !at.Valid || at.Time.Add(ClaimTimeout).Before(now) {
			c.at = at.Time
			stuck = append(stuck, c)
		}
	}
	if err := stale.Close(); err != nil {
		return 0, err
	}
	for _, c := range stuck {
		if _, err := s.db.ExecContext(ctx, `UPDATE notification_logs SET status = ?, claimed_at = NULL
			WHERE id = ? AND status = ? AND (claimed_at = ? OR claimed_at IS NULL)`,
			string(StatusQueued), c.id, string(StatusSending), c.at); err != nil {
			return 0, err
		}
	}

	// Step 2: the due rows, by scheduled_at then insertion order.
	type queued struct {
		id        int64
		messageID string
		req       SendRequest
		channel   Channel
		release   sql.NullTime
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, message_id, user_id, template_key, channel, vars_used, scheduled_at
		FROM notification_logs WHERE status = ?`, string(StatusQueued))
	if err != nil {
		return 0, err
	}
	var due []queued
	for rows.Next() {
		var q queued
		var vars sql.NullString
		if err := rows.Scan(&q.id, &q.messageID, &q.req.UserID, &q.req.TemplateKey, &q.channel, &vars, &q.release); err != nil {
			rows.Close()
			return 0, err
		}
		if vars.Valid {
			_ = json.Unmarshal([]byte(vars.String), &q.req.Vars)
		}
		if !q.release.Valid || !q.release.Time.After(now) {
			due = append(due, q)
		}
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	sort.SliceStable(due, func(i, j int) bool {
		ti, tj := due[i].release.Time, due[j].release.Time
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return due[i].id < due[j].id
	})

	sentCount := 0
	for _, q := range due {
		claimedAt := now
		res, err := s.db.ExecContext(ctx, `UPDATE notification_logs SET status = ?, claimed_at = ? WHERE id = ? AND status = ?`,
			string(StatusSending), claimedAt, q.id, string(StatusQueued))
		if err != nil {
			return sentCount, err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			continue // another worker claimed it first
		}
		// Step 4's conditional write, used by every outcome below.
		final := func(status Status, sentAt, release interface{}, attempts int, errMsg string) error {
			var e interface{}
			if errMsg != "" {
				e = errMsg
			}
			claimed := interface{}(nil)
			if status == StatusSending {
				claimed = claimedAt
			}
			_, err := s.db.ExecContext(ctx, `UPDATE notification_logs SET status = ?, sent_at = ?, scheduled_at = ?, attempts = ?, error = ?, claimed_at = ?
				WHERE id = ? AND status = ? AND claimed_at = ?`,
				string(status), sentAt, release, attempts, e, claimed, q.id, string(StatusSending), claimedAt)
			return err
		}
		release := interface{}(nil)
		if q.release.Valid {
			release = q.release.Time.UTC()
		}
		// Step 3: preferences as they are now.
		tmpl, ok := s.templates[q.req.TemplateKey]
		prefs, err := s.GetPreferences(ctx, q.req.UserID)
		if err != nil {
			return sentCount, err
		}
		unsub, err := s.isUnsubscribed(ctx, q.req.UserID, q.channel)
		if err != nil {
			return sentCount, err
		}
		switch {
		case !ok:
			err = final(StatusFailed, nil, release, 0, "template_not_found")
		case unsub:
			err = final(StatusSkipped, nil, release, 0, "unsubscribed")
		case !prefs.ChannelsEnabled[string(q.channel)]:
			err = final(StatusSkipped, nil, release, 0, "channel_disabled")
		case prefs.DoNotDisturb:
			err = final(StatusSkipped, nil, release, 0, "do_not_disturb")
		default:
			if end, quiet := quietHoursEnd(now, deref(prefs.QuietHoursStart), deref(prefs.QuietHoursEnd)); quiet && quietHoursHold(q.channel) {
				_, err = s.db.ExecContext(ctx, `UPDATE notification_logs SET status = ?, scheduled_at = ?, claimed_at = NULL
					WHERE id = ? AND status = ? AND claimed_at = ?`, string(StatusQueued), end.UTC(), q.id, string(StatusSending), claimedAt)
				break
			}
			attempts, sendErr := s.deliver(ctx, tmpl, &q.req, q.channel)
			if sendErr != nil {
				err = final(StatusFailed, nil, release, attempts, sendErr.Error())
			} else {
				err = final(StatusSent, s.now().UTC(), release, attempts, "")
				sentCount++
			}
		}
		if err != nil {
			return sentCount, err
		}
	}
	return sentCount, nil
}

// ProcessQueued is DeliverDue at the service clock's time. Changed 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP: kept for callers of the earlier API. Touches: as DeliverDue.
func (s *Service) ProcessQueued(ctx context.Context) (int, error) {
	return s.DeliverDue(ctx, s.now())
}

// ---------------------------------------------------------------------------
// Batch send
// ---------------------------------------------------------------------------

// SendBatch sends each request in order; message_ids follow the request order. A request counts
// as sent when Send succeeded (delivered, queued or skipped by preference) and failed otherwise.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: 50 concurrent goroutines over the
// connection pool lost 980 of 1000 messages on an in-memory database and returned ids in random order.
// Touches: database, providers (network).
func (s *Service) SendBatch(ctx context.Context, reqs []SendRequest) (*BatchSendResponse, error) {
	resp := &BatchSendResponse{Success: true, MessageIDs: make([]string, 0, len(reqs))}
	for i := range reqs {
		r, err := s.Send(ctx, &reqs[i])
		if r != nil && r.MessageID != "" {
			resp.MessageIDs = append(resp.MessageIDs, r.MessageID)
		}
		if err != nil || r == nil || !r.Success {
			resp.Failed++
			continue
		}
		resp.Sent++
	}
	return resp, nil
}

// ---------------------------------------------------------------------------
// Track
// ---------------------------------------------------------------------------

// Track returns a message's tracking state. Output: sql.ErrNoRows for an unknown id.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (random message ids). Touches: database.
func (s *Service) Track(ctx context.Context, messageID string) (*TrackResponse, error) {
	var tr TrackResponse
	var channel, status string
	var sentAt, openedAt, clickedAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT message_id, user_id, template_key, channel, sent_at, opened_at, clicked_at, status
		 FROM notification_logs WHERE message_id = ?`, messageID).
		Scan(&tr.MessageID, &tr.UserID, &tr.TemplateKey, &channel, &sentAt, &openedAt, &clickedAt, &status)
	if err != nil {
		return nil, err
	}
	tr.Channel, tr.Status = Channel(channel), Status(status)
	tr.SentAt, tr.OpenedAt, tr.ClickedAt = nullTimePtr(sentAt), nullTimePtr(openedAt), nullTimePtr(clickedAt)
	return &tr, nil
}

func nullTimePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

// OpenMessage records that a delivered message was opened (GET /notifications/open/:message_id, the
// tracking pixel or link). The first time only, it sets opened_at = now and status 'opened'; a second call,
// an already clicked message (a click records the open), an undelivered message or an unknown id changes
// nothing. In: the public message id. Out: whether this call recorded the open, or a database error.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, NOTIF-07). Touches: database.
func (s *Service) OpenMessage(ctx context.Context, messageID string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE notification_logs SET opened_at = ?, status = 'opened'
		 WHERE message_id = ? AND opened_at IS NULL AND status = 'sent'`, s.now().UTC(), messageID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// MarkOpened records the first open of a delivered message, as OpenMessage, for the older
// /notifications/opened/{id} route. Output: nil once the message is recorded as opened (by this call or an
// earlier one), sql.ErrNoRows if no delivered message has that id. Changed 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP. Changed again the same day (Phase B.2, NOTIF-07): it now records the open
// once only, through OpenMessage (it rewrote the status on every call). Touches: database.
func (s *Service) MarkOpened(ctx context.Context, messageID string) error {
	if _, err := s.OpenMessage(ctx, messageID); err != nil {
		return err
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_logs
		WHERE message_id = ? AND status IN ('sent','opened','clicked')`, messageID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// MarkClicked records a click (a click implies an open). Output: sql.ErrNoRows if no delivered
// message has that id. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
func (s *Service) MarkClicked(ctx context.Context, messageID string) error {
	now := s.now().UTC()
	res, err := s.db.ExecContext(ctx,
		`UPDATE notification_logs SET clicked_at = COALESCE(clicked_at, ?), opened_at = COALESCE(opened_at, ?), status = 'clicked'
		 WHERE message_id = ? AND status IN ('sent','opened','clicked')`, now, now, messageID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ---------------------------------------------------------------------------
// Unsubscribe
// ---------------------------------------------------------------------------

// Unsubscribe stops future messages to the user on channel: channels_enabled[channel] = false, and a row
// in notification_unsubscribes. In: user id and channel. Out: an error for an unknown channel.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-09/11): per channel (email only before), and
// it now sets channels_enabled[channel] = false as the spec says. Touches: database.
func (s *Service) Unsubscribe(ctx context.Context, userID int64, ch Channel) error {
	if !validChannel(string(ch)) {
		return fmt.Errorf("unknown channel %q", ch)
	}
	if err := s.UpdatePreferences(ctx, userID, &UpdatePreferencesRequest{ChannelsEnabled: map[string]bool{string(ch): false}}); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO notification_unsubscribes (user_id, channel, created_at) VALUES (?, ?, ?)`,
		userID, string(ch), s.now().UTC())
	return err
}

// validChannel reports a known channel. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
func validChannel(ch string) bool {
	return ch == string(ChannelEmail) || ch == string(ChannelSMS) || ch == string(ChannelInApp)
}

// UnsubscribeToken is the lowercase hex HMAC-SHA256(UnsubscribeSecret, "unsubscribe:<user_id>:<channel>").
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-11): the token bound only the user, so an
// email link could unsubscribe the user from SMS too. Touches: nothing.
func (s *Service) UnsubscribeToken(userID int64, ch Channel) string {
	mac := hmac.New(sha256.New, s.UnsubscribeSecret)
	mac.Write([]byte("unsubscribe:" + strconv.FormatInt(userID, 10) + ":" + string(ch)))
	return hex.EncodeToString(mac.Sum(nil))
}

// UnsubscribeURL is the signed link put in every email:
// <base_url>/unsubscribe?user_id=<id>&channel=<channel>&token=<token>.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (the spec's query form, with the channel). Touches: nothing.
func (s *Service) UnsubscribeURL(userID int64, ch Channel) string {
	q := url.Values{}
	q.Set("user_id", strconv.FormatInt(userID, 10))
	q.Set("channel", string(ch))
	q.Set("token", s.UnsubscribeToken(userID, ch))
	return s.BaseURL + "/unsubscribe?" + q.Encode()
}

// isLowerHex64 reports exactly 64 characters of [0-9a-f]. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
func isLowerHex64(t string) bool {
	if len(t) != 64 {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// VerifyUnsubscribe checks an unsubscribe link's parameters without touching any user: the token must be
// 64 lowercase hex characters, the channel known, the user id a positive integer and the token equal (in
// constant time, on equal-length inputs) to the HMAC for that user and channel. Out: the user and channel,
// or ok=false for every kind of failure. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-11).
// Touches nothing.
func (s *Service) VerifyUnsubscribe(userIDParam, channelParam, token string) (int64, Channel, bool) {
	if !isLowerHex64(token) || !validChannel(channelParam) {
		return 0, "", false
	}
	userID, err := strconv.ParseInt(userIDParam, 10, 64)
	if err != nil || userID <= 0 {
		return 0, "", false
	}
	ch := Channel(channelParam)
	if !hmac.Equal([]byte(token), []byte(s.UnsubscribeToken(userID, ch))) {
		return 0, "", false
	}
	return userID, ch, true
}

// ---------------------------------------------------------------------------
// In-app notifications fetch
// ---------------------------------------------------------------------------

// GetInAppNotifications lists a user's delivered in-app notifications, newest first.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: skipped/queued rows are excluded and
// NULL error columns no longer break the scan. Touches: database.
func (s *Service) GetInAppNotifications(ctx context.Context, userID int64) ([]NotificationLog, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, message_id, user_id, template_key, channel, vars_used, sent_at, opened_at, clicked_at, bounced, error, status
		 FROM notification_logs WHERE user_id = ? AND channel = 'in_app' AND status IN ('sent','opened','clicked')
		 ORDER BY id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	logs := []NotificationLog{}
	for rows.Next() {
		var l NotificationLog
		var vars, errStr sql.NullString
		var sentAt, openedAt, clickedAt sql.NullTime
		var bounced int
		if err := rows.Scan(&l.ID, &l.MessageID, &l.UserID, &l.TemplateKey, &l.Channel, &vars, &sentAt, &openedAt, &clickedAt, &bounced, &errStr, &l.Status); err != nil {
			return nil, err
		}
		l.VarsUsed, l.Error, l.Bounced = vars.String, errStr.String, bounced != 0
		l.SentAt, l.OpenedAt, l.ClickedAt = nullTimePtr(sentAt), nullTimePtr(openedAt), nullTimePtr(clickedAt)
		logs = append(logs, l)
	}
	return logs, rows.Err()
}

// ---------------------------------------------------------------------------
// HTTP handlers. Mount these behind the host app's authentication: the user ids in paths and
// bodies are client-supplied, so the host must check the caller may act for that user.
// ---------------------------------------------------------------------------

// writeJSON writes body as JSON with status. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP:
// error bodies were assembled by string concatenation and broke on quotes. Touches: response.
func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code string, err error) {
	if err != nil && status >= 500 {
		log.Printf("notifications: %s: %v", code, err)
	}
	writeJSON(w, status, map[string]interface{}{"success": false, "error": code})
}

// HandleSend serves POST /notifications/send. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
func (s *Service) HandleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", nil)
		return
	}
	var req SendRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", nil)
		return
	}
	resp, err := s.Send(r.Context(), &req)
	if err != nil {
		if resp != nil && resp.Error != "" {
			writeError(w, http.StatusBadRequest, resp.Error, nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// HandleSendBatch serves POST /notifications/send-batch (at most 10,000 items).
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
func (s *Service) HandleSendBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", nil)
		return
	}
	var reqs []SendRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<20)).Decode(&reqs); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", nil)
		return
	}
	if len(reqs) > 10000 {
		writeError(w, http.StatusRequestEntityTooLarge, "batch_too_large", nil)
		return
	}
	resp, err := s.SendBatch(r.Context(), reqs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// lastSegment returns the path segment after prefix (empty if there is none or more follow).
func lastSegment(path, prefix string) string {
	rest := strings.TrimPrefix(path, prefix)
	if rest == path || rest == "" || strings.Contains(rest, "/") {
		return ""
	}
	return rest
}

// HandleTrack serves GET /notifications/track/{message_id}. Changed 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP.
func (s *Service) HandleTrack(w http.ResponseWriter, r *http.Request) {
	id := lastSegment(r.URL.Path, "/notifications/track/")
	resp, err := s.Track(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) || id == "" {
		writeError(w, http.StatusNotFound, "not_found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// HandleUnsubscribe serves /unsubscribe?user_id=&channel=&token=. Every bad link (missing, short,
// non-hex or altered token, unknown channel, bad user id) gets the same 403
// {error: "invalid_unsubscribe_token"} before any user lookup. GET only shows a confirmation and changes
// nothing (mail scanners follow links); POST unsubscribes (RFC 8058 one-click uses POST).
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-11): GET unsubscribed, the token was per user
// only, and errors differed by kind. Touches: database (POST only).
func (s *Service) HandleUnsubscribe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", nil)
		return
	}
	q := r.URL.Query()
	userID, ch, ok := s.VerifyUnsubscribe(q.Get("user_id"), q.Get("channel"), q.Get("token"))
	if !ok {
		writeError(w, http.StatusForbidden, "invalid_unsubscribe_token", nil)
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]interface{}{"confirm": true, "channel": ch,
			"message": "Send this form (POST) to unsubscribe."})
		return
	}
	if err := s.Unsubscribe(r.Context(), userID, ch); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "channel": ch})
}

// handleMark serves the opened/clicked tracking endpoints. Added 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP (one implementation for both).
func (s *Service) handleMark(prefix string, mark func(context.Context, string) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := mark(r.Context(), lastSegment(r.URL.Path, prefix))
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "not_found", nil)
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"success": true})
	}
}

// HandleOpen serves GET /notifications/open/{message_id}: it records the first open (OpenMessage) and answers
// 204 No Content whether or not this call changed anything, so the reply never says whether the id exists.
// Any other method is 405; a database failure is 500. In: the request. Out: the response.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, NOTIF-07). Touches: database.
func (s *Service) HandleOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", nil)
		return
	}
	if _, err := s.OpenMessage(r.Context(), lastSegment(r.URL.Path, "/notifications/open/")); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleMarkOpened serves /notifications/opened/{message_id}.
func (s *Service) HandleMarkOpened(w http.ResponseWriter, r *http.Request) {
	s.handleMark("/notifications/opened/", s.MarkOpened)(w, r)
}

// HandleMarkClicked serves /notifications/clicked/{message_id}.
func (s *Service) HandleMarkClicked(w http.ResponseWriter, r *http.Request) {
	s.handleMark("/notifications/clicked/", s.MarkClicked)(w, r)
}

// RegisterRoutes mounts the API on mux. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP; the
// same day (Phase B.2, NOTIF-07) GET /notifications/open/{message_id} was added. Touches: mux only.
func (s *Service) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/notifications/open/", s.HandleOpen)
	mux.HandleFunc("/notifications/send", s.HandleSend)
	mux.HandleFunc("/notifications/send-batch", s.HandleSendBatch)
	mux.HandleFunc("/notifications/track/", s.HandleTrack)
	mux.HandleFunc("/users/", s.handleUsers)
	mux.HandleFunc("/unsubscribe", s.HandleUnsubscribe)
	mux.HandleFunc("/notifications/opened/", s.HandleMarkOpened)
	mux.HandleFunc("/notifications/clicked/", s.HandleMarkClicked)
}

// handleUsers serves GET and PUT /users/{user_id}/notification-preferences.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the user id was sliced out with
// indexes that panicked (slice bounds out of range [9:8]). Touches: database.
func (s *Service) handleUsers(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "users" || parts[2] != "notification-preferences" {
		writeError(w, http.StatusNotFound, "not_found", nil)
		return
	}
	userID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || userID <= 0 {
		writeError(w, http.StatusBadRequest, "bad_user_id", nil)
		return
	}
	switch r.Method {
	case http.MethodGet:
		resp, err := s.GetPreferences(r.Context(), userID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPut:
		var req UpdatePreferencesRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", nil)
			return
		}
		if err := s.UpdatePreferences(r.Context(), userID, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid_preferences", "message": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"success": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", nil)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// NewInMemoryDB opens an in-memory SQLite database limited to one connection (each new
// connection to ":memory:" would be a separate, empty database). Changed 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func NewInMemoryDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// NewServiceWithDB builds a service with Null providers (secret from NOTIFICATIONS_UNSUBSCRIBE_SECRET)
// and creates its tables. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: NewService can refuse.
func NewServiceWithDB(db *sql.DB) (*Service, error) {
	s, err := NewService(db, nil, nil)
	if err != nil {
		return nil, err
	}
	if err := s.InitDB(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

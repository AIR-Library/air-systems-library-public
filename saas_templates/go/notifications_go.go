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
	"os"
	"regexp"
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

// PreferencesResponse is a user's notification preferences.
type PreferencesResponse struct {
	UserID          int64           `json:"user_id"`
	DoNotDisturb    bool            `json:"do_not_disturb"`
	QuietHoursStart string          `json:"quiet_hours_start"`
	QuietHoursEnd   string          `json:"quiet_hours_end"`
	ChannelsEnabled map[string]bool `json:"channels_enabled"`
}

// UpdatePreferencesRequest is a partial update: nil fields and absent channels keep their value.
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
	// UnsubscribeSecret signs unsubscribe links (NOTIFICATIONS_UNSUBSCRIBE_SECRET, else random per
	// process, which invalidates links on restart: set it in production).
	UnsubscribeSecret []byte
	// BaseURL prefixes the unsubscribe link in emails.
	BaseURL string
	now     func() time.Time
	sleep   func(time.Duration)
}

// NewService builds a service. Inputs: database, email and SMS providers (nil = Null providers).
// Output: the service with the built-in templates. Call InitDB before use.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing until used.
func NewService(db *sql.DB, email EmailProvider, sms SMSProvider) *Service {
	if email == nil {
		email = NullEmailProvider{}
	}
	if sms == nil {
		sms = NullSMSProvider{}
	}
	secret := []byte(os.Getenv("NOTIFICATIONS_UNSUBSCRIBE_SECRET"))
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			panic("notifications: crypto/rand failed: " + err.Error())
		}
	}
	s := &Service{
		db: db, templates: make(map[string]Template), email: email, sms: sms,
		Contacts: PlaceholderContacts{}, UnsubscribeSecret: secret, BaseURL: os.Getenv("NOTIFICATIONS_BASE_URL"),
		now: time.Now, sleep: time.Sleep,
	}
	s.seedTemplates()
	return s
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
	quiet_hours_start TEXT NOT NULL DEFAULT '22:00',
	quiet_hours_end TEXT NOT NULL DEFAULT '08:00',
	channels_enabled TEXT NOT NULL DEFAULT '{"email":true,"sms":true,"in_app":true}'
);
CREATE TABLE IF NOT EXISTS notification_unsubscribes (
	user_id INTEGER NOT NULL,
	channel TEXT NOT NULL,
	created_at DATETIME NOT NULL,
	PRIMARY KEY (user_id, channel)
);
`

// InitDB creates the tables. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (message_id,
// scheduled_at, attempts, notification_unsubscribes). Touches: database.
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

// defaultPreferences are used for a user with no stored row: quiet hours 22:00-08:00 and every
// channel on (as the passing PHP template; SMS is only ever sent to a number the ContactResolver
// returns, i.e. one the user gave). Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (SMS
// was off, so an explicit SMS send to a new user was skipped).
func defaultPreferences(userID int64) *PreferencesResponse {
	return &PreferencesResponse{UserID: userID, QuietHoursStart: "22:00", QuietHoursEnd: "08:00",
		ChannelsEnabled: map[string]bool{"email": true, "sms": true, "in_app": true}}
}

// GetPreferences returns a user's preferences, or the defaults (quiet hours 22:00-08:00, every
// channel on) when none are stored. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: database.
func (s *Service) GetPreferences(ctx context.Context, userID int64) (*PreferencesResponse, error) {
	var dnd int
	var qStart, qEnd, chJSON string
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
	p.DoNotDisturb, p.QuietHoursStart, p.QuietHoursEnd = dnd != 0, qStart, qEnd
	stored := map[string]bool{}
	if err := json.Unmarshal([]byte(chJSON), &stored); err == nil {
		for k, v := range stored {
			p.ChannelsEnabled[k] = v
		}
	}
	return p, nil
}

var hhmm = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)

// UpdatePreferences applies a partial update on top of the stored (or default) preferences.
// Output: an error for malformed quiet hours or unknown channels. Changed 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP: unset fields used to be reset to defaults. Touches: database.
func (s *Service) UpdatePreferences(ctx context.Context, userID int64, req *UpdatePreferencesRequest) error {
	p, err := s.GetPreferences(ctx, userID)
	if err != nil {
		return err
	}
	if req.DoNotDisturb != nil {
		p.DoNotDisturb = *req.DoNotDisturb
	}
	if req.QuietHoursStart != nil {
		if !hhmm.MatchString(*req.QuietHoursStart) {
			return fmt.Errorf("quiet_hours_start must be HH:MM")
		}
		p.QuietHoursStart = *req.QuietHoursStart
	}
	if req.QuietHoursEnd != nil {
		if !hhmm.MatchString(*req.QuietHoursEnd) {
			return fmt.Errorf("quiet_hours_end must be HH:MM")
		}
		p.QuietHoursEnd = *req.QuietHoursEnd
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
		userID, dnd, p.QuietHoursStart, p.QuietHoursEnd, string(chJSON))
	return err
}

// ---------------------------------------------------------------------------
// Quiet hours
// ---------------------------------------------------------------------------

// quietHoursEnd reports whether now falls in [start, end) (wrapping midnight when start > end) and,
// if so, the next moment the window ends, in now's location. Equal start and end mean no quiet
// hours. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (returns the release time so
// the message is queued, per the spec). Touches: nothing.
func quietHoursEnd(now time.Time, start, end string) (time.Time, bool) {
	if !hhmm.MatchString(start) || !hhmm.MatchString(end) || start == end {
		return time.Time{}, false
	}
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
// queued if scheduled_at is in the future or the user is in quiet hours (released at
// quiet_hours_end); otherwise delivered with up to 3 attempts and exponential backoff. Output:
// SendResponse with the log's message id; an error only for bad input or storage failure.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, providers (network).
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
	} else if end, quiet := quietHoursEnd(now, prefs.QuietHoursStart, prefs.QuietHoursEnd); quiet {
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

// deliver renders the template and hands it to the channel's provider, retrying failures up to 3
// attempts with backoff 100 ms, 200 ms. In-app messages are delivered by being logged. Output: the
// number of attempts and the last error. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: providers (network).
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
		link := s.UnsubscribeURL(req.UserID)
		bodyText += "\n\nUnsubscribe: " + link
		bodyHTML += fmt.Sprintf("<p><a href=\"%s\">Unsubscribe</a></p>", html.EscapeString(link))
		send = func() error { return s.email.Send(ctx, email, subject, bodyText, bodyHTML) }
	case ChannelSMS:
		if phone == "" {
			return 0, errors.New("no phone number on file")
		}
		send = func() error { return s.sms.Send(ctx, phone, bodyText) }
	}
	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if lastErr = send(); lastErr == nil {
			return attempt, nil
		}
		if attempt < maxAttempts {
			s.sleep(time.Duration(1<<uint(attempt-1)) * 100 * time.Millisecond)
		}
	}
	return maxAttempts, lastErr
}

// ProcessQueued delivers queued messages whose release time has passed, in queue order, updating
// each row in place (same message id). Do-not-disturb, disabled channels and unsubscribes are
// checked again; a message still inside the user's quiet hours is pushed to their end. Output: how
// many messages were sent. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: queued messages
// had no way out of the queue. Touches: database, providers (network).
func (s *Service) ProcessQueued(ctx context.Context) (int, error) {
	type queued struct {
		messageID string
		req       SendRequest
		channel   Channel
		release   sql.NullTime
	}
	rows, err := s.db.QueryContext(ctx, `SELECT message_id, user_id, template_key, channel, vars_used, scheduled_at
		FROM notification_logs WHERE status = ? ORDER BY id`, string(StatusQueued))
	if err != nil {
		return 0, err
	}
	var due []queued
	now := s.now()
	for rows.Next() {
		var q queued
		var vars sql.NullString
		if err := rows.Scan(&q.messageID, &q.req.UserID, &q.req.TemplateKey, &q.channel, &vars, &q.release); err != nil {
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
	sentCount := 0
	for _, q := range due {
		update := func(status Status, sentAt, release interface{}, attempts int, errMsg string) error {
			var e interface{}
			if errMsg != "" {
				e = errMsg
			}
			_, err := s.db.ExecContext(ctx, `UPDATE notification_logs SET status = ?, sent_at = ?, scheduled_at = ?, attempts = ?, error = ?
				WHERE message_id = ? AND status = ?`, string(status), sentAt, release, attempts, e, q.messageID, string(StatusQueued))
			return err
		}
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
			err = update(StatusFailed, nil, q.release.Time, 0, "template_not_found")
		case prefs.DoNotDisturb:
			err = update(StatusSkipped, nil, q.release.Time, 0, "do_not_disturb")
		case !prefs.ChannelsEnabled[string(q.channel)]:
			err = update(StatusSkipped, nil, q.release.Time, 0, "channel_disabled")
		case unsub:
			err = update(StatusSkipped, nil, q.release.Time, 0, "unsubscribed")
		default:
			if end, quiet := quietHoursEnd(now, prefs.QuietHoursStart, prefs.QuietHoursEnd); quiet {
				_, err = s.db.ExecContext(ctx, `UPDATE notification_logs SET scheduled_at = ? WHERE message_id = ?`, end.UTC(), q.messageID)
				break
			}
			attempts, sendErr := s.deliver(ctx, tmpl, &q.req, q.channel)
			if sendErr != nil {
				err = update(StatusFailed, nil, q.release.Time, attempts, sendErr.Error())
			} else {
				err = update(StatusSent, s.now().UTC(), q.release.Time, attempts, "")
				sentCount++
			}
		}
		if err != nil {
			return sentCount, err
		}
	}
	return sentCount, nil
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

// MarkOpened records the first open of a delivered message (status opened unless already clicked).
// Output: sql.ErrNoRows if no delivered message has that id. Changed 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
func (s *Service) MarkOpened(ctx context.Context, messageID string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE notification_logs SET opened_at = COALESCE(opened_at, ?),
			status = CASE WHEN status = 'clicked' THEN status ELSE 'opened' END
		 WHERE message_id = ? AND status IN ('sent','opened','clicked')`, s.now().UTC(), messageID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
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

// Unsubscribe stops future emails to the user (stored in notification_unsubscribes).
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (was an in-memory map). Touches: database.
func (s *Service) Unsubscribe(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO notification_unsubscribes (user_id, channel, created_at) VALUES (?, ?, ?)`,
		userID, string(ChannelEmail), s.now().UTC())
	return err
}

// UnsubscribeToken is HMAC-SHA256(UnsubscribeSecret, "unsubscribe:<user_id>") in hex.
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
func (s *Service) UnsubscribeToken(userID int64) string {
	mac := hmac.New(sha256.New, s.UnsubscribeSecret)
	mac.Write([]byte("unsubscribe:" + strconv.FormatInt(userID, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

// UnsubscribeURL is the signed link put in every email. Added 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
func (s *Service) UnsubscribeURL(userID int64) string {
	return fmt.Sprintf("%s/unsubscribe/%d?token=%s", s.BaseURL, userID, s.UnsubscribeToken(userID))
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

// HandleUnsubscribe serves /unsubscribe/{user_id}?token=...; the token must be the HMAC from the
// email link (compared in constant time). Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP:
// anyone could unsubscribe any user id. Touches: database.
func (s *Service) HandleUnsubscribe(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(lastSegment(r.URL.Path, "/unsubscribe/"), 10, 64)
	if err != nil || userID <= 0 {
		writeError(w, http.StatusBadRequest, "bad_user_id", nil)
		return
	}
	if !hmac.Equal([]byte(r.URL.Query().Get("token")), []byte(s.UnsubscribeToken(userID))) {
		writeError(w, http.StatusForbidden, "invalid_token", nil)
		return
	}
	if err := s.Unsubscribe(r.Context(), userID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
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

// HandleMarkOpened serves /notifications/opened/{message_id}.
func (s *Service) HandleMarkOpened(w http.ResponseWriter, r *http.Request) {
	s.handleMark("/notifications/opened/", s.MarkOpened)(w, r)
}

// HandleMarkClicked serves /notifications/clicked/{message_id}.
func (s *Service) HandleMarkClicked(w http.ResponseWriter, r *http.Request) {
	s.handleMark("/notifications/clicked/", s.MarkClicked)(w, r)
}

// RegisterRoutes mounts the API on mux. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
func (s *Service) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/notifications/send", s.HandleSend)
	mux.HandleFunc("/notifications/send-batch", s.HandleSendBatch)
	mux.HandleFunc("/notifications/track/", s.HandleTrack)
	mux.HandleFunc("/users/", s.handleUsers)
	mux.HandleFunc("/unsubscribe/", s.HandleUnsubscribe)
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

// NewServiceWithDB builds a service with Null providers and creates its tables.
func NewServiceWithDB(db *sql.DB) (*Service, error) {
	s := NewService(db, nil, nil)
	if err := s.InitDB(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

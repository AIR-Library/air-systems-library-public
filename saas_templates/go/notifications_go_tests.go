package notifications

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

type failingEmailProvider struct {
	mu       sync.Mutex
	failures int
	calls    int
}

func (f *failingEmailProvider) Send(ctx context.Context, to, subject, bodyText, bodyHTML string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failures {
		return fmt.Errorf("simulated failure %d", f.calls)
	}
	return nil
}

// testNoon is the fixed instant the service clock reads in tests: midday, outside the default
// 22:00-08:00 quiet hours. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: with the wall
// clock every send was "queued" whenever the suite ran at night (it failed at 04:25).
// Changed the same day (Phase B.2, NOTIF-05): noon UTC, not local noon, because quiet hours are now UTC.
func testNoon() time.Time { return time.Date(2026, time.January, 15, 12, 0, 0, 0, time.UTC) }

// testSecret is a 32-byte unsubscribe secret for tests. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP:
// the service now refuses a missing or short secret.
var testSecret = []byte("test-unsubscribe-secret-32-bytes!")

func setupService(t *testing.T) (*Service, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1) // every new connection to :memory: would be a separate, empty database
	s, err := NewServiceWithSecret(db, NullEmailProvider{}, NullSMSProvider{}, testSecret)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	s.SetClock(testNoon)
	if err := s.InitDB(context.Background()); err != nil {
		t.Fatalf("init db: %v", err)
	}
	return s, db
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// NOTIF-01
func TestSendEmailWithTemplateVariables(t *testing.T) {
	s, _ := setupService(t)
	ctx := context.Background()

	resp, err := s.Send(ctx, &SendRequest{
		UserID:      123,
		TemplateKey: "trial_ending_soon",
		Channel:     ptrChannel(ChannelEmail),
		Vars:        map[string]interface{}{"days_left": 3},
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected success, got %+v", resp)
	}
	if resp.Status != StatusSent {
		t.Errorf("expected status sent, got %s", resp.Status)
	}
	if resp.MessageID == "" {
		t.Error("expected non-empty message_id")
	}

	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: prove the variables were substituted in what the provider
	// received, and that the email carries the channel-bound unsubscribe link.
	rec := &recordingEmail{}
	s.email = rec
	if _, err := s.Send(ctx, &SendRequest{UserID: 123, TemplateKey: "trial_ending_soon", Channel: ptrChannel(ChannelEmail),
		Vars: map[string]interface{}{"days_left": 3}}); err != nil {
		t.Fatal(err)
	}
	if rec.subject != "Your trial ends in 3 days" || !strings.Contains(rec.text, "Your trial ends in 3 days.") ||
		strings.Contains(rec.text, "{days_left}") || !strings.Contains(rec.text, "channel=email") {
		t.Errorf("unexpected email: subject %q, text %q", rec.subject, rec.text)
	}
}

// recordingEmail keeps the last email it was given. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
type recordingEmail struct{ subject, text string }

func (r *recordingEmail) Send(_ context.Context, _, subject, bodyText, _ string) error {
	r.subject, r.text = subject, bodyText
	return nil
}

// NOTIF-02
func TestSendSMS(t *testing.T) {
	s, _ := setupService(t)
	ctx := context.Background()

	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-02, amended): SMS is opt-in, off by default, so
	// the user turns it on first; before that an SMS is skipped.
	if r, _ := s.Send(ctx, &SendRequest{UserID: 456, TemplateKey: "trial_ending_soon", Channel: ptrChannel(ChannelSMS),
		Vars: map[string]interface{}{"days_left": 5}}); r == nil || r.Status != StatusSkipped {
		t.Fatalf("SMS to a user who never enabled it must be skipped, got %+v", r)
	}
	if err := s.UpdatePreferences(ctx, 456, &UpdatePreferencesRequest{ChannelsEnabled: map[string]bool{"sms": true}}); err != nil {
		t.Fatalf("enable sms: %v", err)
	}

	resp, err := s.Send(ctx, &SendRequest{
		UserID:      456,
		TemplateKey: "trial_ending_soon",
		Channel:     ptrChannel(ChannelSMS),
		Vars:        map[string]interface{}{"days_left": 5},
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected success, got %+v", resp)
	}
	if resp.Status != StatusSent {
		t.Errorf("expected status sent, got %s", resp.Status)
	}
}

// NOTIF-03
func TestSendInApp(t *testing.T) {
	s, _ := setupService(t)
	ctx := context.Background()

	resp, err := s.Send(ctx, &SendRequest{
		UserID:      789,
		TemplateKey: "admin_alert",
		Channel:     ptrChannel(ChannelInApp),
		Vars:        map[string]interface{}{"actor": "admin", "action": "deleted", "resource": "user_42"},
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected success, got %+v", resp)
	}
	if resp.Status != StatusSent {
		t.Errorf("expected status sent, got %s", resp.Status)
	}

	// Verify stored in DB
	logs, err := s.GetInAppNotifications(ctx, 789)
	if err != nil {
		t.Fatalf("get in-app: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 in-app notification, got %d", len(logs))
	}
	if logs[0].TemplateKey != "admin_alert" {
		t.Errorf("expected template admin_alert, got %s", logs[0].TemplateKey)
	}
}

// NOTIF-04
func TestBatchSend1000(t *testing.T) {
	s, _ := setupService(t)
	ctx := context.Background()

	reqs := make([]SendRequest, 1000)
	for i := range reqs {
		reqs[i] = SendRequest{
			UserID:      int64(i + 1),
			TemplateKey: "welcome_email",
			Channel:     ptrChannel(ChannelInApp),
			Vars:        map[string]interface{}{"app_name": "TestApp"},
		}
	}

	resp, err := s.SendBatch(ctx, reqs)
	if err != nil {
		t.Fatalf("batch send: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected success, got %+v", resp)
	}
	if resp.Sent != 1000 {
		t.Errorf("expected 1000 sent, got %d", resp.Sent)
	}
	if resp.Failed != 0 {
		t.Errorf("expected 0 failed, got %d", resp.Failed)
	}
	if len(resp.MessageIDs) != 1000 {
		t.Errorf("expected 1000 message_ids, got %d", len(resp.MessageIDs))
	}
}

// NOTIF-05
// TestQuietHoursSkip proves a send inside the user's quiet hours is not sent now but queued with
// scheduled_at = quiet_hours_end, and DeliverDue sends it then. Input: none; output: test failures.
// Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, NOTIF-05 as amended): quiet hours are
// UTC, so the expected release time is compared in UTC (it used the clock's own location). Touches: in-memory SQLite.
func TestQuietHoursSkip(t *testing.T) {
	s, _ := setupService(t)
	ctx := context.Background()

	// Set quiet hours to cover the service's current time
	now := s.now()
	start := now.Add(-1 * time.Hour).Format("15:04")
	end := now.Add(1 * time.Hour).Format("15:04")

	err := s.UpdatePreferences(ctx, 100, &UpdatePreferencesRequest{
		QuietHoursStart: &start,
		QuietHoursEnd:   &end,
	})
	if err != nil {
		t.Fatalf("update prefs: %v", err)
	}

	resp, err := s.Send(ctx, &SendRequest{
		UserID:      100,
		TemplateKey: "welcome_email",
		Channel:     ptrChannel(ChannelEmail),
		Vars:        map[string]interface{}{"app_name": "TestApp"},
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if resp.Status != StatusQueued {
		t.Errorf("expected status queued (quiet hours), got %s", resp.Status)
	}

	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-05, amended): the message waits with
	// scheduled_at = quiet_hours_end and DeliverDue sends it then, not before.
	var scheduled time.Time
	if err := s.db.QueryRow(`SELECT scheduled_at FROM notification_logs WHERE message_id = ?`, resp.MessageID).Scan(&scheduled); err != nil {
		t.Fatalf("scheduled_at: %v", err)
	}
	if want := now.UTC().Add(time.Hour); !scheduled.Equal(want) {
		t.Errorf("expected scheduled_at at quiet_hours_end %s UTC (%v), got %v", end, want, scheduled)
	}
	if n, _ := s.DeliverDue(ctx, now.Add(30*time.Minute)); n != 0 {
		t.Errorf("nothing may be sent inside quiet hours")
	}
	if n, _ := s.DeliverDue(ctx, now.Add(time.Hour)); n != 1 {
		t.Errorf("expected the message to be sent when quiet hours end, sent %d", n)
	}
}

// NOTIF-06
func TestDoNotDisturbSkip(t *testing.T) {
	s, _ := setupService(t)
	ctx := context.Background()

	dnd := true
	err := s.UpdatePreferences(ctx, 200, &UpdatePreferencesRequest{
		DoNotDisturb: &dnd,
	})
	if err != nil {
		t.Fatalf("update prefs: %v", err)
	}

	resp, err := s.Send(ctx, &SendRequest{
		UserID:      200,
		TemplateKey: "welcome_email",
		Channel:     ptrChannel(ChannelEmail),
		Vars:        map[string]interface{}{"app_name": "TestApp"},
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if resp.Status != StatusSkipped {
		t.Errorf("expected status skipped (DND), got %s", resp.Status)
	}
}

// NOTIF-07
// TestTrackMessageOpened proves the older MarkOpened path records an open. The GET
// /notifications/open/:message_id rules are proven by TestOpenEndpointRecordsOnce. Doc block added
// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2). Touches: in-memory SQLite.
func TestTrackMessageOpened(t *testing.T) {
	s, _ := setupService(t)
	ctx := context.Background()

	resp, err := s.Send(ctx, &SendRequest{
		UserID:      300,
		TemplateKey: "welcome_email",
		Channel:     ptrChannel(ChannelInApp),
		Vars:        map[string]interface{}{"app_name": "TestApp"},
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if resp.MessageID == "" {
		t.Fatal("expected message_id")
	}

	// Mark as opened
	if err := s.MarkOpened(ctx, resp.MessageID); err != nil {
		t.Fatalf("mark opened: %v", err)
	}

	// Track
	tr, err := s.Track(ctx, resp.MessageID)
	if err != nil {
		t.Fatalf("track: %v", err)
	}
	if tr.Status != StatusOpened {
		t.Errorf("expected status opened, got %s", tr.Status)
	}
	if tr.OpenedAt == nil {
		t.Error("expected opened_at to be set")
	}
}

// NOTIF-08
// TestRetryFailedEmail proves NOTIF-08 as amended: a failed email is retried at most 3 times after the first
// attempt (4 attempts in all), waiting 1 s, 2 s and 4 s; it is sent when the sender recovers on the 4th
// attempt, and a 4th failure marks it failed with no 5th attempt. Input: none; output: test failures.
// Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): it expected 3 attempts in all (2
// failures + 1 success); the spec now counts 3 retries, so the sender fails 3 times and succeeds on the 4th,
// and the waits are checked. Touches: in-memory SQLite.
func TestRetryFailedEmail(t *testing.T) {
	run := func(failures int) (*SendResponse, *failingEmailProvider, []time.Duration, *Service) {
		t.Helper()
		db, err := sql.Open("sqlite3", ":memory:")
		if err != nil {
			t.Fatalf("open db: %v", err)
		}
		db.SetMaxOpenConns(1) // every new connection to :memory: would be a separate, empty database
		provider := &failingEmailProvider{failures: failures}
		s, err := NewServiceWithSecret(db, provider, NullSMSProvider{}, testSecret)
		if err != nil {
			t.Fatalf("new service: %v", err)
		}
		var waits []time.Duration
		s.sleep = func(d time.Duration) { waits = append(waits, d) } // recorded, not waited for
		s.SetClock(testNoon)
		if err := s.InitDB(context.Background()); err != nil {
			t.Fatalf("init db: %v", err)
		}
		resp, err := s.Send(context.Background(), &SendRequest{
			UserID:      400,
			TemplateKey: "welcome_email",
			Channel:     ptrChannel(ChannelEmail),
			Vars:        map[string]interface{}{"app_name": "TestApp"},
		})
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		return resp, provider, waits, s
	}
	wantWaits := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}

	resp, provider, waits, _ := run(3)
	if resp.Status != StatusSent {
		t.Errorf("expected status sent after 3 retries, got %s", resp.Status)
	}
	if provider.calls != 4 {
		t.Errorf("expected 4 calls (3 failures + 1 success), got %d", provider.calls)
	}
	if fmt.Sprint(waits) != fmt.Sprint(wantWaits) {
		t.Errorf("expected waits %v, got %v", wantWaits, waits)
	}

	resp, provider, waits, s := run(4)
	if resp.Status != StatusFailed {
		t.Errorf("a 4th failure must mark the message failed, got %s", resp.Status)
	}
	if provider.calls != 4 {
		t.Errorf("expected exactly 4 attempts, got %d", provider.calls)
	}
	if fmt.Sprint(waits) != fmt.Sprint(wantWaits) {
		t.Errorf("expected waits %v, got %v", wantWaits, waits)
	}
	var status string
	var attempts int
	if err := s.db.QueryRow(`SELECT status, attempts FROM notification_logs WHERE message_id = ?`, resp.MessageID).Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || attempts != 4 {
		t.Errorf("expected the row failed after 4 attempts, got %s after %d", status, attempts)
	}
}

// TestQuietHoursCrossMidnightUTC proves NOTIF-05 as amended: quiet hours are HH:MM in UTC and may cross
// midnight. With 22:00-08:00, a send at 23:30 UTC and one at 03:00 UTC (given on a clock in another time
// zone) are queued with scheduled_at = 08:00 UTC; 08:00 and 21:59 UTC are sent now. DeliverDue re-queues a
// due message inside the window with scheduled_at = quiet_hours_end (step 3). Input: none; output: test
// failures. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2). Touches: in-memory SQLite.
// NOTIF-05
func TestQuietHoursCrossMidnightUTC(t *testing.T) {
	s, _ := setupService(t)
	ctx := context.Background()
	start, end := "22:00", "08:00"
	if err := s.UpdatePreferences(ctx, 150, &UpdatePreferencesRequest{QuietHoursStart: &start, QuietHoursEnd: &end}); err != nil {
		t.Fatalf("update prefs: %v", err)
	}
	tokyo := time.FixedZone("UTC+9", 9*3600)
	day := time.Date(2026, time.March, 3, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		now     time.Time
		queued  bool
		release time.Time
	}{
		{day.Add(23*time.Hour + 30*time.Minute), true, day.Add(32 * time.Hour)},
		{day.Add(3 * time.Hour).In(tokyo), true, day.Add(8 * time.Hour)}, // 12:00 in Tokyo is 03:00 UTC
		{day.Add(8 * time.Hour), false, time.Time{}},
		{day.Add(21*time.Hour + 59*time.Minute).In(tokyo), false, time.Time{}},
	}
	for _, c := range cases {
		now := c.now
		s.SetClock(func() time.Time { return now })
		resp, err := s.Send(ctx, &SendRequest{UserID: 150, TemplateKey: "welcome_email", Channel: ptrChannel(ChannelInApp),
			Vars: map[string]interface{}{"app_name": "TestApp"}})
		if err != nil {
			t.Fatalf("send at %v: %v", now, err)
		}
		if c.queued {
			var scheduled time.Time
			if err := s.db.QueryRow(`SELECT scheduled_at FROM notification_logs WHERE message_id = ?`, resp.MessageID).Scan(&scheduled); err != nil {
				t.Fatal(err)
			}
			if resp.Status != StatusQueued || !scheduled.Equal(c.release) {
				t.Errorf("at %v UTC: expected queued until %v, got %s until %v", now.UTC(), c.release, resp.Status, scheduled)
			}
		} else if resp.Status != StatusSent {
			t.Errorf("at %v UTC: expected sent, got %s", now.UTC(), resp.Status)
		}
	}

	// DeliverDue step 3: a message due at 21:00 UTC, delivered at 23:00 UTC, is inside the window: it goes
	// back to 'queued' with scheduled_at = 08:00 UTC the next day and is sent then.
	s.SetClock(func() time.Time { return day.Add(12 * time.Hour) })
	due := day.Add(21 * time.Hour)
	resp, err := s.Send(ctx, &SendRequest{UserID: 150, TemplateKey: "welcome_email", Channel: ptrChannel(ChannelInApp),
		Vars: map[string]interface{}{"app_name": "TestApp"}, ScheduledAt: &due})
	if err != nil || resp.Status != StatusQueued {
		t.Fatalf("scheduled send: %v %+v", err, resp)
	}
	if n, err := s.DeliverDue(ctx, day.Add(23*time.Hour)); err != nil || n != 0 {
		t.Fatalf("inside quiet hours DeliverDue must send nothing, sent %d (%v)", n, err)
	}
	var status string
	var scheduled time.Time
	if err := s.db.QueryRow(`SELECT status, scheduled_at FROM notification_logs WHERE message_id = ?`, resp.MessageID).Scan(&status, &scheduled); err != nil {
		t.Fatal(err)
	}
	if status != "queued" || !scheduled.Equal(day.Add(32*time.Hour)) {
		t.Errorf("expected re-queued until 08:00 UTC, got %s until %v", status, scheduled)
	}
}

// TestOpenEndpointRecordsOnce proves NOTIF-07 as amended: GET /notifications/open/:message_id sets opened_at
// and status 'opened' the first time and answers 204; a second call answers 204 and changes nothing; an
// unknown id answers 204 too; a non-GET is 405. Input: none; output: test failures.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2). Touches: in-memory SQLite, a local test server.
// NOTIF-07
func TestOpenEndpointRecordsOnce(t *testing.T) {
	s, _ := setupService(t)
	ctx := context.Background()
	resp, err := s.Send(ctx, &SendRequest{UserID: 310, TemplateKey: "welcome_email", Channel: ptrChannel(ChannelEmail),
		Vars: map[string]interface{}{"app_name": "TestApp"}})
	if err != nil || resp.Status != StatusSent {
		t.Fatalf("send: %v %+v", err, resp)
	}
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	server := httptest.NewServer(mux)
	defer server.Close()
	get := func(id string) int {
		t.Helper()
		r, err := http.Get(server.URL + "/notifications/open/" + id)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}

	first := time.Date(2026, time.January, 15, 12, 5, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return first })
	if code := get(resp.MessageID); code != http.StatusNoContent {
		t.Fatalf("first open: expected 204, got %d", code)
	}
	tr, err := s.Track(ctx, resp.MessageID)
	if err != nil || tr.Status != StatusOpened || tr.OpenedAt == nil || !tr.OpenedAt.Equal(first) {
		t.Fatalf("first open must set opened_at and status opened: %+v (%v)", tr, err)
	}

	s.SetClock(func() time.Time { return first.Add(time.Hour) })
	if code := get(resp.MessageID); code != http.StatusNoContent {
		t.Fatalf("second open: expected 204, got %d", code)
	}
	tr2, _ := s.Track(ctx, resp.MessageID)
	if tr2.Status != StatusOpened || tr2.OpenedAt == nil || !tr2.OpenedAt.Equal(first) {
		t.Errorf("a second open must change nothing: %+v", tr2)
	}
	if changed, err := s.OpenMessage(ctx, resp.MessageID); err != nil || changed {
		t.Errorf("OpenMessage on an opened message must change nothing: %v %v", changed, err)
	}

	if code := get("no-such-message"); code != http.StatusNoContent {
		t.Errorf("unknown id: expected 204, got %d", code)
	}
	r, err := http.Post(server.URL+"/notifications/open/"+resp.MessageID, "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: expected 405, got %d", r.StatusCode)
	}
}

// NOTIF-09
func TestUnsubscribeSkipsEmail(t *testing.T) {
	s, _ := setupService(t)
	ctx := context.Background()

	// Unsubscribe user
	if err := s.Unsubscribe(ctx, 500, ChannelEmail); err != nil {
		t.Fatalf("unsubscribe: %v", err)
	}

	resp, err := s.Send(ctx, &SendRequest{
		UserID:      500,
		TemplateKey: "welcome_email",
		Channel:     ptrChannel(ChannelEmail),
		Vars:        map[string]interface{}{"app_name": "TestApp"},
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if resp.Status != StatusSkipped {
		t.Errorf("expected status skipped (unsubscribed), got %s", resp.Status)
	}
}

// NOTIF-10
func TestUserPreferencesChannelsEnabled(t *testing.T) {
	s, _ := setupService(t)
	ctx := context.Background()

	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the spec's defaults for a user with no preferences.
	def, err := s.GetPreferences(ctx, 601)
	if err != nil || def.DoNotDisturb || def.QuietHoursStart != nil || def.QuietHoursEnd != nil ||
		!def.ChannelsEnabled["email"] || def.ChannelsEnabled["sms"] || !def.ChannelsEnabled["in_app"] {
		t.Fatalf("unexpected default preferences: %+v (%v)", def, err)
	}

	// Disable email channel
	err = s.UpdatePreferences(ctx, 600, &UpdatePreferencesRequest{
		ChannelsEnabled: map[string]bool{"email": false, "sms": false, "in_app": true},
	})
	if err != nil {
		t.Fatalf("update prefs: %v", err)
	}

	// Try to send email - should be skipped
	resp, err := s.Send(ctx, &SendRequest{
		UserID:      600,
		TemplateKey: "welcome_email",
		Channel:     ptrChannel(ChannelEmail),
		Vars:        map[string]interface{}{"app_name": "TestApp"},
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if resp.Status != StatusSkipped {
		t.Errorf("expected status skipped (channel disabled), got %s", resp.Status)
	}

	// In-app should work
	resp2, err := s.Send(ctx, &SendRequest{
		UserID:      600,
		TemplateKey: "admin_alert",
		Channel:     ptrChannel(ChannelInApp),
		Vars:        map[string]interface{}{"actor": "a", "action": "b", "resource": "c"},
	})
	if err != nil {
		t.Fatalf("send in-app: %v", err)
	}
	if resp2.Status != StatusSent {
		t.Errorf("expected in-app sent, got %s", resp2.Status)
	}
}

// ---------------------------------------------------------------------------
// HTTP endpoint tests
// ---------------------------------------------------------------------------

func TestHTTPSend(t *testing.T) {
	s, _ := setupService(t)
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	body := `{"user_id":1,"template_key":"welcome_email","channel":"in_app","vars":{"app_name":"Test"}}`
	resp, err := http.Post(server.URL+"/notifications/send", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	var sr SendResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !sr.Success {
		t.Errorf("expected success")
	}
}

func TestHTTPTrack(t *testing.T) {
	s, _ := setupService(t)
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	// Send first
	body := `{"user_id":1,"template_key":"welcome_email","channel":"in_app","vars":{"app_name":"Test"}}`
	resp, _ := http.Post(server.URL+"/notifications/send", "application/json", strings.NewReader(body))
	var sr SendResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	resp.Body.Close()

	// Track
	trResp, err := http.Get(server.URL + "/notifications/track/" + sr.MessageID)
	if err != nil {
		t.Fatalf("get track: %v", err)
	}
	defer trResp.Body.Close()
	if trResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", trResp.StatusCode)
	}
	var tr TrackResponse
	if err := json.NewDecoder(trResp.Body).Decode(&tr); err != nil {
		t.Fatalf("decode track: %v", err)
	}
	if tr.MessageID != sr.MessageID {
		t.Errorf("message_id mismatch")
	}
}

func TestHTTPPreferences(t *testing.T) {
	s, _ := setupService(t)
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	// Get
	resp, err := http.Get(server.URL + "/users/1/notification-preferences")
	if err != nil {
		t.Fatalf("get prefs: %v", err)
	}
	defer resp.Body.Close()
	var pr PreferencesResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		t.Fatalf("decode prefs: %v", err)
	}
	if pr.UserID != 1 {
		t.Errorf("expected user_id 1, got %d", pr.UserID)
	}

	// Update
	body := `{"do_not_disturb":true,"channels_enabled":{"email":true,"sms":false,"in_app":true}}`
	req, _ := http.NewRequest(http.MethodPut, server.URL+"/users/1/notification-preferences", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	updResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put prefs: %v", err)
	}
	defer updResp.Body.Close()
	if updResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", updResp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func ptrChannel(c Channel) *Channel {
	return &c
}
// TestUnsubscribeLink proves NOTIF-11: the emailed link's token binds user and channel; GET only confirms;
// POST sets channels_enabled[channel] = false; a missing, short, non-hex, uppercase or altered token, a
// token for another channel or user, or an unknown channel all get 403 invalid_unsubscribe_token and the
// user stays subscribed; and a secret under 32 bytes stops the service from starting.
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite, a test HTTP server.
// NOTIF-11
func TestUnsubscribeLink(t *testing.T) {
	s, _ := setupService(t)
	ctx := context.Background()
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	if _, err := NewServiceWithSecret(nil, nil, nil, []byte("short")); err == nil {
		t.Fatal("a secret under 32 bytes must be refused")
	}
	s.BaseURL = server.URL
	link := s.UnsubscribeURL(42, ChannelEmail)
	u, _ := url.Parse(link)
	token := u.Query().Get("token")
	if len(token) != 64 || strings.ToLower(token) != token {
		t.Fatalf("token must be 64 lowercase hex characters: %q", token)
	}

	emailOn := func() bool {
		p, _ := s.GetPreferences(ctx, 42)
		return p.ChannelsEnabled["email"]
	}
	call := func(method, rawQuery string) (int, map[string]interface{}) {
		req, _ := http.NewRequest(method, server.URL+"/unsubscribe?"+rawQuery, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		defer resp.Body.Close()
		var body map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body
	}
	q := func(user, channel, tok string) string {
		v := url.Values{}
		v.Set("user_id", user)
		v.Set("channel", channel)
		if tok != "" {
			v.Set("token", tok)
		}
		return v.Encode()
	}
	altered := token[:63] + map[bool]string{true: "0", false: "1"}[token[63] != '0']
	bad := map[string]string{
		"missing token":       q("42", "email", ""),
		"short token":         q("42", "email", token[:63]),
		"non-hex token":       q("42", "email", strings.Repeat("z", 64)),
		"uppercase token":     q("42", "email", strings.ToUpper(token)),
		"altered token":       q("42", "email", altered),
		"other channel":       q("42", "sms", token),
		"other user":          q("43", "email", token),
		"unknown channel":     q("42", "fax", token),
	}
	for name, query := range bad {
		code, body := call(http.MethodPost, query)
		if code != http.StatusForbidden || body["error"] != "invalid_unsubscribe_token" {
			t.Errorf("%s: expected 403 invalid_unsubscribe_token, got %d %v", name, code, body)
		}
	}
	if !emailOn() {
		t.Fatal("a refused link must leave the user subscribed")
	}
	if code, _ := call(http.MethodGet, u.RawQuery); code != http.StatusOK || !emailOn() {
		t.Fatalf("GET must only confirm (code %d), and the user must stay subscribed", code)
	}
	if code, body := call(http.MethodPost, u.RawQuery); code != http.StatusOK || body["success"] != true {
		t.Fatalf("POST with the valid link: %d %v", code, body)
	}
	if emailOn() {
		t.Fatal("POST must set channels_enabled.email = false")
	}
	if p, _ := s.GetPreferences(ctx, 42); !p.ChannelsEnabled["in_app"] {
		t.Fatal("unsubscribing from email must not touch other channels")
	}
}

// TestScheduledSendDeliverDue proves NOTIF-12: a send 30 days ahead is queued, not sent; DeliverDue sends
// it once due and exactly once; a user who unsubscribed meanwhile is skipped; a row stuck at 'sending'
// for over 300 s is re-queued and sent, one claimed less than 300 s ago is left alone.
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
// NOTIF-12
func TestScheduledSendDeliverDue(t *testing.T) {
	s, db := setupService(t)
	ctx := context.Background()
	counter := &failingEmailProvider{}
	s.email = counter
	now := testNoon()
	later := now.Add(30 * 24 * time.Hour)

	send := func(user int64) *SendResponse {
		r, err := s.Send(ctx, &SendRequest{UserID: user, TemplateKey: "welcome_email", Channel: ptrChannel(ChannelEmail),
			Vars: map[string]interface{}{"app_name": "App"}, ScheduledAt: &later})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	a, b := send(1), send(2)
	if a.Status != StatusQueued || counter.calls != 0 {
		t.Fatalf("a send 30 days ahead must be queued, not sent: %+v, %d calls", a, counter.calls)
	}
	if n, _ := s.DeliverDue(ctx, now); n != 0 {
		t.Fatalf("nothing is due yet")
	}
	if err := s.Unsubscribe(ctx, 2, ChannelEmail); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DeliverDue(ctx, later); n != 1 || err != nil || counter.calls != 1 {
		t.Fatalf("expected exactly one send when due, got %d (%v), %d calls", n, err, counter.calls)
	}
	if n, _ := s.DeliverDue(ctx, later.Add(time.Minute)); n != 0 || counter.calls != 1 {
		t.Fatalf("a second DeliverDue must send nothing")
	}
	if tr, _ := s.Track(ctx, a.MessageID); tr.Status != StatusSent {
		t.Fatalf("user 1: expected sent, got %s", tr.Status)
	}
	if tr, _ := s.Track(ctx, b.MessageID); tr.Status != StatusSkipped {
		t.Fatalf("user 2 unsubscribed meanwhile: expected skipped, got %s", tr.Status)
	}

	// A crashed worker's claim: stuck at 'sending'.
	c := send(3)
	claimed := later.Add(-10 * time.Second).UTC()
	if _, err := db.Exec(`UPDATE notification_logs SET status = 'sending', claimed_at = ? WHERE message_id = ?`, claimed, c.MessageID); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.DeliverDue(ctx, claimed.Add(299*time.Second)); n != 0 {
		t.Fatalf("a claim under 300 s old must be left alone")
	}
	if n, _ := s.DeliverDue(ctx, claimed.Add(301*time.Second)); n != 1 || counter.calls != 2 {
		t.Fatalf("a claim over 300 s old must be re-queued and sent, sent %d", n)
	}
}

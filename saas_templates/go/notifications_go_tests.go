package notifications

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
func testNoon() time.Time { return time.Date(2026, time.January, 15, 12, 0, 0, 0, time.Local) }

func setupService(t *testing.T) (*Service, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1) // every new connection to :memory: would be a separate, empty database
	s := NewService(db, NullEmailProvider{}, NullSMSProvider{})
	s.SetClock(testNoon)
	if err := s.InitDB(context.Background()); err != nil {
		t.Fatalf("init db: %v", err)
	}
	return s, db
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
}

func TestSendSMS(t *testing.T) {
	s, _ := setupService(t)
	ctx := context.Background()

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
}

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

func TestRetryFailedEmail(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1) // every new connection to :memory: would be a separate, empty database
	provider := &failingEmailProvider{failures: 2}
	s := NewService(db, provider, NullSMSProvider{})
	s.SetClock(testNoon) // outside the default quiet hours, whatever the time of day
	if err := s.InitDB(context.Background()); err != nil {
		t.Fatalf("init db: %v", err)
	}
	ctx := context.Background()

	resp, err := s.Send(ctx, &SendRequest{
		UserID:      400,
		TemplateKey: "welcome_email",
		Channel:     ptrChannel(ChannelEmail),
		Vars:        map[string]interface{}{"app_name": "TestApp"},
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if resp.Status != StatusSent {
		t.Errorf("expected status sent after retries, got %s", resp.Status)
	}
	if provider.calls != 3 {
		t.Errorf("expected 3 calls (2 failures + 1 success), got %d", provider.calls)
	}
}

func TestUnsubscribeSkipsEmail(t *testing.T) {
	s, _ := setupService(t)
	ctx := context.Background()

	// Unsubscribe user
	if err := s.Unsubscribe(ctx, 500); err != nil {
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

func TestUserPreferencesChannelsEnabled(t *testing.T) {
	s, _ := setupService(t)
	ctx := context.Background()

	// Disable email channel
	err := s.UpdatePreferences(ctx, 600, &UpdatePreferencesRequest{
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
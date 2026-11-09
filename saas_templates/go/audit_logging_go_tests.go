package auditlogging

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditLogger_HappyPath(t *testing.T) {
	logger, err := NewAuditLogger(":memory:")
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	req := LogMutationRequest{
		ActorID:      strPtr("123"),
		ActorType:    "user",
		Action:       "subscription_changed",
		ResourceType: "subscription",
		ResourceID:   "456",
		OldValue:     json.RawMessage(`{"tier": "team", "billing_date": "2026-10-15"}`),
		NewValue:     json.RawMessage(`{"tier": "enterprise", "billing_date": "2026-10-15"}`),
		WhyChainID:   strPtr("wc_789"),
	}

	logID, err := logger.LogMutation(ctx, req)
	if err != nil {
		t.Fatalf("LogMutation failed: %v", err)
	}
	if logID == "" {
		t.Fatal("expected non-empty log ID")
	}

	queryReq := QueryLogsRequest{
		ActorID:      strPtr("123"),
		ResourceType: strPtr("subscription"),
		Limit:        10,
		Offset:       0,
	}
	resp, err := logger.QueryLogs(ctx, queryReq)
	if err != nil {
		t.Fatalf("QueryLogs failed: %v", err)
	}

	if resp.Total != 1 {
		t.Errorf("expected total=1, got %d", resp.Total)
	}
	if len(resp.Logs) != 1 {
		t.Errorf("expected 1 log, got %d", len(resp.Logs))
	}
	if resp.Logs[0].ID != logID {
		t.Errorf("log ID mismatch: got %s, want %s", resp.Logs[0].ID, logID)
	}
	if resp.Logs[0].Action != "subscription_changed" {
		t.Errorf("action mismatch: got %s", resp.Logs[0].Action)
	}
	if resp.Logs[0].ActorID == nil || *resp.Logs[0].ActorID != "123" {
		t.Errorf("actor_id mismatch: got %v", resp.Logs[0].ActorID)
	}
}

func TestAuditLogger_Replay_DivergenceDetection(t *testing.T) {
	logger, err := NewAuditLogger(":memory:")
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	req1 := LogMutationRequest{
		ActorID:      strPtr("123"),
		ActorType:    "user",
		Action:       "user_created",
		ResourceType: "user",
		ResourceID:   "user_001",
		OldValue:     json.RawMessage(`null`),
		NewValue:     json.RawMessage(`{"name": "Alice", "email": "alice@example.com"}`),
	}
	logID1, err := logger.LogMutation(ctx, req1)
	if err != nil {
		t.Fatalf("LogMutation 1 failed: %v", err)
	}

	req2 := LogMutationRequest{
		ActorID:      strPtr("123"),
		ActorType:    "user",
		Action:       "user_updated",
		ResourceType: "user",
		ResourceID:   "user_001",
		OldValue:     json.RawMessage(`{"name": "Alice", "email": "alice@example.com"}`),
		NewValue:     json.RawMessage(`{"name": "Alice Smith", "email": "alice@example.com"}`),
	}
	_, err = logger.LogMutation(ctx, req2)
	if err != nil {
		t.Fatalf("LogMutation 2 failed: %v", err)
	}

	replay1, err := logger.Replay(ctx, logID1)
	if err != nil {
		t.Fatalf("Replay failed: %v", err)
	}

	if !replay1.HasDiverged {
		t.Error("expected HasDiverged=true for log with later mutations")
	}
	if replay1.LogID != logID1 {
		t.Errorf("replay log ID mismatch: got %s", replay1.LogID)
	}

	var state map[string]any
	json.Unmarshal(replay1.ResourceStateAtTime, &state)
	if state["name"] != "Alice" {
		t.Errorf("resource state at time mismatch: got %v", state)
	}

	replay2, err := logger.Replay(ctx, logID1)
	if err != nil {
		t.Fatalf("Replay 2 failed: %v", err)
	}
	if !replay2.HasDiverged {
		t.Error("expected HasDiverged=true on second replay")
	}
}

func TestAuditLogger_Filtering(t *testing.T) {
	logger, err := NewAuditLogger(":memory:")
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	logs := []LogMutationRequest{
		{ActorID: strPtr("1"), ActorType: "user", Action: "user_created", ResourceType: "user", ResourceID: "u1", NewValue: json.RawMessage(`{}`)},
		{ActorID: strPtr("1"), ActorType: "user", Action: "user_suspended", ResourceType: "user", ResourceID: "u2", NewValue: json.RawMessage(`{}`)},
		{ActorID: strPtr("2"), ActorType: "user", Action: "user_created", ResourceType: "user", ResourceID: "u3", NewValue: json.RawMessage(`{}`)},
		{ActorID: strPtr("1"), ActorType: "service", Action: "deployment_created", ResourceType: "deployment", ResourceID: "d1", NewValue: json.RawMessage(`{}`)},
	}

	for _, l := range logs {
		_, err := logger.LogMutation(ctx, l)
		if err != nil {
			t.Fatalf("LogMutation failed: %v", err)
		}
	}

	tests := []struct {
		name       string
		req        QueryLogsRequest
		wantCount  int
		wantAction string
	}{
		{
			name:      "filter by actor_id",
			req:       QueryLogsRequest{ActorID: strPtr("1"), Limit: 10},
			wantCount: 3,
		},
		{
			name:      "filter by action wildcard user_*",
			req:       QueryLogsRequest{Action: strPtr("user_*"), Limit: 10},
			wantCount: 3,
		},
		{
			name:      "filter by resource_type",
			req:       QueryLogsRequest{ResourceType: strPtr("user"), Limit: 10},
			wantCount: 3,
		},
		{
			name:      "combined actor_id + action + resource_type",
			req:       QueryLogsRequest{ActorID: strPtr("1"), Action: strPtr("user_*"), ResourceType: strPtr("user"), Limit: 10},
			wantCount: 2,
		},
		{
			name:      "actor_id=2 only",
			req:       QueryLogsRequest{ActorID: strPtr("2"), Limit: 10},
			wantCount: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := logger.QueryLogs(ctx, tc.req)
			if err != nil {
				t.Fatalf("QueryLogs failed: %v", err)
			}
			if resp.Total != tc.wantCount {
				t.Errorf("total=%d, want %d", resp.Total, tc.wantCount)
			}
			if len(resp.Logs) != tc.wantCount {
				t.Errorf("logs count=%d, want %d", len(resp.Logs), tc.wantCount)
			}
			if tc.wantAction != "" {
				for _, log := range resp.Logs {
					if log.Action != tc.wantAction {
						t.Errorf("unexpected action %s", log.Action)
					}
				}
			}
		})
	}
}

func TestAuditLogger_Pagination(t *testing.T) {
	logger, err := NewAuditLogger(":memory:")
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	for i := 0; i < 25; i++ {
		req := LogMutationRequest{
			ActorID:      strPtr("1"),
			ActorType:    "user",
			Action:       "test_action",
			ResourceType: "resource",
			ResourceID:   string(rune('a' + i)),
			NewValue:     json.RawMessage(`{}`),
		}
		_, err := logger.LogMutation(ctx, req)
		if err != nil {
			t.Fatalf("LogMutation %d failed: %v", i, err)
		}
	}

	page1, err := logger.QueryLogs(ctx, QueryLogsRequest{Limit: 10, Offset: 0})
	if err != nil {
		t.Fatalf("page 1 failed: %v", err)
	}
	if len(page1.Logs) != 10 {
		t.Errorf("page 1: expected 10 logs, got %d", len(page1.Logs))
	}
	if !page1.HasMore {
		t.Error("page 1 should have more")
	}

	page2, err := logger.QueryLogs(ctx, QueryLogsRequest{Limit: 10, Offset: 10})
	if err != nil {
		t.Fatalf("page 2 failed: %v", err)
	}
	if len(page2.Logs) != 10 {
		t.Errorf("page 2: expected 10 logs, got %d", len(page2.Logs))
	}
	if !page2.HasMore {
		t.Error("page 2 should have more")
	}

	page3, err := logger.QueryLogs(ctx, QueryLogsRequest{Limit: 10, Offset: 20})
	if err != nil {
		t.Fatalf("page 3 failed: %v", err)
	}
	if len(page3.Logs) != 5 {
		t.Errorf("page 3: expected 5 logs, got %d", len(page3.Logs))
	}
	if page3.HasMore {
		t.Error("page 3 should not have more")
	}

	if page3.Total != 25 {
		t.Errorf("total=%d, want 25", page3.Total)
	}

	allIDs := make(map[string]bool)
	for _, log := range page1.Logs {
		allIDs[log.ID] = true
	}
	for _, log := range page2.Logs {
		if allIDs[log.ID] {
			t.Error("duplicate log ID across pages")
		}
		allIDs[log.ID] = true
	}
	for _, log := range page3.Logs {
		if allIDs[log.ID] {
			t.Error("duplicate log ID across pages")
		}
	}
}

func TestAuditLogger_Performance_1MLogs(t *testing.T) {
	logger, err := NewAuditLogger(":memory:")
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	const numLogs = 100000
	start := time.Now()
	for i := 0; i < numLogs; i++ {
		req := LogMutationRequest{
			ActorID:      strPtr("perf_user"),
			ActorType:    "user",
			Action:       "perf_action",
			ResourceType: "perf_resource",
			ResourceID:   string(rune(i % 1000)),
			NewValue:     json.RawMessage(`{"data": "test"}`),
		}
		_, err := logger.LogMutation(ctx, req)
		if err != nil {
			t.Fatalf("LogMutation %d failed: %v", i, err)
		}
	}
	insertDuration := time.Since(start)
	t.Logf("Inserted %d logs in %v", numLogs, insertDuration)

	queryStart := time.Now()
	resp, err := logger.QueryLogs(ctx, QueryLogsRequest{
		ActorID:      strPtr("perf_user"),
		Action:       strPtr("perf_action"),
		ResourceType: strPtr("perf_resource"),
		Limit:        100,
		Offset:       0,
	})
	queryDuration := time.Since(queryStart)

	if err != nil {
		t.Fatalf("QueryLogs failed: %v", err)
	}
	if resp.Total != numLogs {
		t.Errorf("total=%d, want %d", resp.Total, numLogs)
	}
	if len(resp.Logs) != 100 {
		t.Errorf("returned %d logs, want 100", len(resp.Logs))
	}

	t.Logf("Query took %v (limit 100)", queryDuration)
	if queryDuration > 100*time.Millisecond {
		t.Errorf("query took %v, expected <100ms", queryDuration)
	}
}

func TestAuditLogger_Immutability(t *testing.T) {
	logger, err := NewAuditLogger(":memory:")
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	req := LogMutationRequest{
		ActorID:      strPtr("1"),
		ActorType:    "user",
		Action:       "test",
		ResourceType: "resource",
		ResourceID:   "r1",
		NewValue:     json.RawMessage(`{}`),
	}
	logID, err := logger.LogMutation(ctx, req)
	if err != nil {
		t.Fatalf("LogMutation failed: %v", err)
	}

	_, err = logger.db.ExecContext(ctx, "UPDATE audit_log SET action = 'hacked' WHERE id = ?", logID)
	if err == nil {
		t.Error("expected UPDATE to fail, but it succeeded")
	}
}

func TestAuditLogger_WildcardAction(t *testing.T) {
	logger, err := NewAuditLogger(":memory:")
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	actions := []string{"user_created", "user_suspended", "user_updated", "user_deleted", "admin_action"}
	for _, action := range actions {
		req := LogMutationRequest{
			ActorID:      strPtr("1"),
			ActorType:    "user",
			Action:       action,
			ResourceType: "user",
			ResourceID:   "u1",
			NewValue:     json.RawMessage(`{}`),
		}
		_, err := logger.LogMutation(ctx, req)
		if err != nil {
			t.Fatalf("LogMutation %s failed: %v", action, err)
		}
	}

	resp, err := logger.QueryLogs(ctx, QueryLogsRequest{
		Action:       strPtr("user_*"),
		ResourceType: strPtr("user"),
		Limit:        100,
	})
	if err != nil {
		t.Fatalf("QueryLogs failed: %v", err)
	}

	if resp.Total != 4 {
		t.Errorf("wildcard user_* matched %d logs, want 4", resp.Total)
	}
	for _, log := range resp.Logs {
		if !strings.HasPrefix(log.Action, "user_") {
			t.Errorf("log action %s does not match user_*", log.Action)
		}
	}
}

func TestAuditLogger_Search(t *testing.T) {
	logger, err := NewAuditLogger(":memory:")
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	logs := []LogMutationRequest{
		{ActorID: strPtr("1"), ActorType: "user", Action: "user_created", ResourceType: "user", ResourceID: "u1", NewValue: json.RawMessage(`{"email": "alice@example.com"}`)},
		{ActorID: strPtr("1"), ActorType: "user", Action: "user_updated", ResourceType: "user", ResourceID: "u2", NewValue: json.RawMessage(`{"email": "bob@example.com"}`)},
		{ActorID: strPtr("2"), ActorType: "service", Action: "deployment_created", ResourceType: "deployment", ResourceID: "d1", NewValue: json.RawMessage(`{"name": "prod"}`)},
	}
	for _, l := range logs {
		_, err := logger.LogMutation(ctx, l)
		if err != nil {
			t.Fatalf("LogMutation failed: %v", err)
		}
	}

	searchTests := []struct {
		name      string
		req       SearchRequest
		wantCount int
	}{
		{"search email", SearchRequest{Query: "alice", Limit: 10}, 1},
		{"search wildcard", SearchRequest{Query: "exam*", Limit: 10}, 2},
		{"search resource_type filter", SearchRequest{Query: "prod", ResourceType: strPtr("deployment"), Limit: 10}, 1},
		{"search no results", SearchRequest{Query: "nonexistent", Limit: 10}, 0},
	}

	for _, tc := range searchTests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := logger.Search(ctx, tc.req)
			if err != nil {
				t.Fatalf("Search failed: %v", err)
			}
			if len(resp.Results) != tc.wantCount {
				t.Errorf("got %d results, want %d", len(resp.Results), tc.wantCount)
			}
		})
	}
}

func TestAuditLogger_Replay_NotFound(t *testing.T) {
	logger, err := NewAuditLogger(":memory:")
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	_, err = logger.Replay(ctx, "nonexistent_id")
	if err == nil {
		t.Error("expected error for nonexistent log")
	}
	if !errors.Is(err, ErrLogNotFound) {
		t.Errorf("expected ErrLogNotFound, got %v", err)
	}
}

func TestAuditLogger_InvalidActorType(t *testing.T) {
	logger, err := NewAuditLogger(":memory:")
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	req := LogMutationRequest{
		ActorID:      strPtr("1"),
		ActorType:    "invalid_type",
		Action:       "test",
		ResourceType: "resource",
		ResourceID:   "r1",
		NewValue:     json.RawMessage(`{}`),
	}
	_, err = logger.LogMutation(ctx, req)
	if err == nil {
		t.Error("expected error for invalid actor_type")
	}
	if !errors.Is(err, ErrInvalidActorType) {
		t.Errorf("expected ErrInvalidActorType, got %v", err)
	}
}

func strPtr(s string) *string {
	return &s
}

// A literal _ in a wildcard filter matches only "_": "user_*" must not match "userXcreated".
func TestAuditLogger_ActionWildcardUnderscoreIsLiteral(t *testing.T) {
	logger, err := NewAuditLogger(":memory:")
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}
	defer logger.Close()
	ctx := context.Background()

	for _, action := range []string{"user_created", "userXcreated"} {
		_, err := logger.LogMutation(ctx, LogMutationRequest{
			ActorID: strPtr("1"), ActorType: "user", Action: action,
			ResourceType: "user", ResourceID: "u1", NewValue: json.RawMessage(`{}`),
		})
		if err != nil {
			t.Fatalf("LogMutation %s failed: %v", action, err)
		}
	}

	resp, err := logger.QueryLogs(ctx, QueryLogsRequest{Action: strPtr("user_*"), Limit: 10})
	if err != nil {
		t.Fatalf("QueryLogs failed: %v", err)
	}
	if resp.Total != 1 || len(resp.Logs) != 1 || resp.Logs[0].Action != "user_created" {
		t.Errorf("user_* matched %d logs, want only user_created", resp.Total)
	}

	// Search escapes the same way: "r_c" is found in user_created only (CodeRabbit, PR 18).
	found, err := logger.Search(ctx, SearchRequest{Query: "r_c", Limit: 10})
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(found.Results) != 1 || found.Results[0].Action != "user_created" {
		t.Errorf("search r_c found %d logs, want only user_created", len(found.Results))
	}
}

// A database written by the previous version (variable-width RFC3339Nano times) is upgraded when it is opened, so a
// range ending at a row's exact instant still includes it (Codex review on PR 18, 2026-11-09, session 04ec72ff).
func TestAuditLogger_UpgradesOldTimestamps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open old db: %v", err)
	}
	_, err = old.Exec(`CREATE TABLE audit_log (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, actor_id TEXT,
		actor_type TEXT NOT NULL, action TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT NOT NULL,
		old_value TEXT, new_value TEXT, why_chain_id TEXT, metadata TEXT);
		INSERT INTO audit_log VALUES ('log_a', '2026-11-01T12:00:00.123Z', '1', 'user', 'a', 'user', 'u1', 'null', '{}', NULL, 'null');
		INSERT INTO audit_log VALUES ('log_b', '2026-11-01T12:00:05Z', '1', 'user', 'b', 'user', 'u1', 'null', '{}', NULL, 'null');`)
	old.Close()
	if err != nil {
		t.Fatalf("write old rows: %v", err)
	}

	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger on the old db failed: %v", err)
	}
	defer logger.Close()

	to := time.Date(2026, 11, 1, 12, 0, 0, 123_000_000, time.UTC)
	resp, err := logger.QueryLogs(context.Background(), QueryLogsRequest{DateTo: &to, Limit: 10})
	if err != nil {
		t.Fatalf("QueryLogs failed: %v", err)
	}
	if resp.Total != 1 || resp.Logs[0].ID != "log_a" {
		t.Fatalf("a range ending at log_a's instant returned %d logs, want log_a", resp.Total)
	}
	if got := resp.Logs[0].Timestamp; got != "2026-11-01T12:00:00.123000000Z" {
		t.Errorf("old time not rewritten to the fixed form: %s", got)
	}
	all, _ := logger.QueryLogs(context.Background(), QueryLogsRequest{Limit: 10})
	if all.Total != 2 || all.Logs[0].Timestamp != "2026-11-01T12:00:05.000000000Z" {
		t.Errorf("a whole-second old time was not rewritten: %+v", all.Logs)
	}
}

// A database that already has the update trigger and still holds old-format times opens and is upgraded; the trigger
// is back afterwards, so the log stays immutable (CodeRabbit review on PR 18, 2026-11-09, session 04ec72ff).
func TestAuditLogger_UpgradesOldTimestampsUnderTheTrigger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old-with-trigger.db")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open old db: %v", err)
	}
	_, err = old.Exec(`CREATE TABLE audit_log (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, actor_id TEXT,
		actor_type TEXT NOT NULL, action TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT NOT NULL,
		old_value TEXT, new_value TEXT, why_chain_id TEXT, metadata TEXT);
		INSERT INTO audit_log VALUES ('log_a', '2026-11-01T12:00:00.5Z', '1', 'user', 'a', 'user', 'u1', 'null', '{}', NULL, 'null');
		CREATE TRIGGER audit_log_immutable_update BEFORE UPDATE ON audit_log
		BEGIN SELECT RAISE(ABORT, 'audit log is immutable'); END;`)
	old.Close()
	if err != nil {
		t.Fatalf("write old db: %v", err)
	}

	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger on a db with the trigger failed: %v", err)
	}
	defer logger.Close()
	all, _ := logger.QueryLogs(context.Background(), QueryLogsRequest{Limit: 10})
	if all.Total != 1 || all.Logs[0].Timestamp != "2026-11-01T12:00:00.500000000Z" {
		t.Fatalf("old time not rewritten under the trigger: %+v", all.Logs)
	}
	if _, err := logger.db.Exec(`UPDATE audit_log SET action = 'x'`); err == nil {
		t.Error("the update trigger is gone after the upgrade; the log must stay immutable")
	}
}

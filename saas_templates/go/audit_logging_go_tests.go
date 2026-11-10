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

// AUDIT-01
func TestAuditLogger_HappyPath(t *testing.T) {
	logger, err := NewAuditLogger(":memory:")
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: a non-'user' entry names its data subject (AUDIT-10).
	req := LogMutationRequest{
		ActorID:       strPtr("123"),
		ActorType:     "user",
		SubjectUserID: strPtr("789"),
		Action:        "subscription_changed",
		ResourceType:  "subscription",
		ResourceID:    "456",
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
	resp, err := logger.QueryLogs(ctx, admin, queryReq)
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
	if got := resp.Logs[0]; got.ResourceID == nil || *got.ResourceID != "456" || !strings.Contains(string(got.NewValue), "enterprise") ||
		got.WhyChainID == nil || *got.WhyChainID != "wc_789" || got.PersonalErased {
		t.Errorf("the entry read back differs: %+v", got)
	}
	// The event row itself holds no actor or resource data; they live in audit_personal.
	var resID, oldV sql.NullString
	if err := logger.db.QueryRow(`SELECT resource_id, old_value FROM audit_log WHERE id = ?`, logID).Scan(&resID, &oldV); err != nil || resID.Valid || oldV.Valid {
		t.Errorf("audit_log kept personal fields: %v %v (%v)", resID, oldV, err)
	}
}

// AUDIT-02
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
	logID2, err := logger.LogMutation(ctx, req2)
	if err != nil {
		t.Fatalf("LogMutation 2 failed: %v", err)
	}

	replay1, err := logger.Replay(ctx, admin, logID1)
	if err != nil {
		t.Fatalf("Replay failed: %v", err)
	}

	if replay1.HasDiverged == nil || !*replay1.HasDiverged {
		t.Error("expected HasDiverged=true for log with later mutations")
	}
	if replay1.LogID != logID1 {
		t.Errorf("replay log ID mismatch: got %s", replay1.LogID)
	}

	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: resource_state_at_time is the entry's old_value, as the
	// spec says ({...old_value}) and the Python template returns; Go returned new_value. So the state at the
	// creation is null, and the state at the update (logID2) is Alice; the latest entry has not diverged.
	if string(replay1.ResourceStateAtTime) != "null" {
		t.Errorf("state at creation should be null, got %s", replay1.ResourceStateAtTime)
	}
	replay2, err := logger.Replay(ctx, admin, logID2)
	if err != nil {
		t.Fatalf("Replay 2 failed: %v", err)
	}
	var state map[string]any
	json.Unmarshal(replay2.ResourceStateAtTime, &state)
	if state["name"] != "Alice" {
		t.Errorf("resource state at time mismatch: got %v", state)
	}
	if replay2.HasDiverged == nil || *replay2.HasDiverged {
		t.Error("expected HasDiverged=false for the latest entry")
	}
}

// AUDIT-03
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
		// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 follow-up): a service entry names its service in
		// ActorService; ActorID is no longer taken as the service name (it was ActorID "1").
		{ActorService: strPtr("1"), ActorType: "service", SubjectUserID: strPtr("none"), Action: "deployment_created", ResourceType: "deployment", ResourceID: "d1", NewValue: json.RawMessage(`{}`)},
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
		// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: actor_id resolves through audit_subjects to USER actors
		// (spec, amended); the service entry whose actor id is also "1" is a different actor, matched by its
		// service name only when no user "1" exists. So user 1 has 2 entries, not 3.
		{
			name:      "filter by actor_id",
			req:       QueryLogsRequest{ActorID: strPtr("1"), Limit: 10},
			wantCount: 2,
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
			resp, err := logger.QueryLogs(ctx, admin, tc.req)
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

// AUDIT-04
func TestAuditLogger_Pagination(t *testing.T) {
	logger, err := NewAuditLogger(":memory:")
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	for i := 0; i < 25; i++ {
		req := LogMutationRequest{
			ActorID:       strPtr("1"),
			ActorType:     "user",
			SubjectUserID: strPtr("none"),
			Action:        "test_action",
			ResourceType:  "resource",
			ResourceID:   string(rune('a' + i)),
			NewValue:     json.RawMessage(`{}`),
		}
		_, err := logger.LogMutation(ctx, req)
		if err != nil {
			t.Fatalf("LogMutation %d failed: %v", i, err)
		}
	}

	page1, err := logger.QueryLogs(ctx, admin, QueryLogsRequest{Limit: 10, Offset: 0})
	if err != nil {
		t.Fatalf("page 1 failed: %v", err)
	}
	if len(page1.Logs) != 10 {
		t.Errorf("page 1: expected 10 logs, got %d", len(page1.Logs))
	}
	if !page1.HasMore {
		t.Error("page 1 should have more")
	}

	page2, err := logger.QueryLogs(ctx, admin, QueryLogsRequest{Limit: 10, Offset: 10})
	if err != nil {
		t.Fatalf("page 2 failed: %v", err)
	}
	if len(page2.Logs) != 10 {
		t.Errorf("page 2: expected 10 logs, got %d", len(page2.Logs))
	}
	if !page2.HasMore {
		t.Error("page 2 should have more")
	}

	page3, err := logger.QueryLogs(ctx, admin, QueryLogsRequest{Limit: 10, Offset: 20})
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

// TestAuditLogger_Performance_1MLogs proves AUDIT-05: with 1,000,000 entries (100 actors, 10,000 each) an
// actor_id + action + resource_type query returns its page in under 100 ms (the contract budget).
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: it seeded 100,000 entries (the row says 1M+); the rows
// are now generated inside SQLite in the current three-table layout, as the Python test does, so seeding
// takes seconds. The budget is unchanged.
// AUDIT-05
func TestAuditLogger_Performance_1MLogs(t *testing.T) {
	logger, err := NewAuditLogger(":memory:")
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}
	defer logger.Close()
	ctx := context.Background()

	const numLogs, actors = 1_000_000, 100
	start := time.Now()
	for _, stmt := range []string{
		`BEGIN`,
		`WITH RECURSIVE a(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM a WHERE i < 99)
		 INSERT INTO audit_subjects (subject_ref, user_id, created_at)
		 SELECT printf('ref_%03d', i), 'perf_actor_' || i, '2026-01-01T00:00:00.000000000Z' FROM a`,
		`WITH RECURSIVE s(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM s WHERE i < 999999)
		 INSERT INTO audit_log (id, timestamp, actor_type, action, resource_type, resource_id, personal_roles, metadata)
		 SELECT printf('id_%07d', i), strftime('%Y-%m-%dT%H:%M:%S', 1767225600 + i, 'unixepoch') || '.000000000Z',
			'user', 'perf_action', 'perf_resource', 'res_' || i, 'actor', '{}' FROM s`,
		`INSERT INTO audit_personal (log_id, subject_ref, role, data)
		 SELECT id, printf('ref_%03d', rowid % 100), 'actor',
			'{"actor_id":"perf_actor_' || (rowid % 100) || '","ip":null,"user_agent":null,"request_id":null}' FROM audit_log`,
		`COMMIT`,
	} {
		if _, err := logger.db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	t.Logf("Seeded %d logs in %v", numLogs, time.Since(start))

	queryStart := time.Now()
	resp, err := logger.QueryLogs(ctx, admin, QueryLogsRequest{
		ActorID:      strPtr("perf_actor_7"),
		Action:       strPtr("perf_action"),
		ResourceType: strPtr("perf_resource"),
		Limit:        100,
		Offset:       0,
	})
	queryDuration := time.Since(queryStart)

	if err != nil {
		t.Fatalf("QueryLogs failed: %v", err)
	}
	if resp.Total != numLogs/actors {
		t.Errorf("total=%d, want %d", resp.Total, numLogs/actors)
	}
	if len(resp.Logs) != 100 || resp.Logs[0].ActorID == nil || *resp.Logs[0].ActorID != "perf_actor_7" {
		t.Errorf("returned %d logs, want 100 by perf_actor_7", len(resp.Logs))
	}

	t.Logf("Query took %v (limit 100)", queryDuration)
	if queryDuration > 100*time.Millisecond {
		t.Errorf("query took %v, expected <100ms", queryDuration)
	}
}

// AUDIT-06
func TestAuditLogger_Immutability(t *testing.T) {
	logger, err := NewAuditLogger(":memory:")
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	req := LogMutationRequest{
		ActorID:       strPtr("1"),
		ActorType:     "user",
		SubjectUserID: strPtr("none"),
		Action:        "test",
		ResourceType:  "resource",
		ResourceID:    "r1",
		NewValue:      json.RawMessage(`{}`),
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

// AUDIT-07
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

	resp, err := logger.QueryLogs(ctx, admin, QueryLogsRequest{
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
		// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 follow-up): the service is named in ActorService
		// (it was ActorID "2", which no longer stands in for it).
		{ActorService: strPtr("2"), ActorType: "service", SubjectUserID: strPtr("none"), Action: "deployment_created", ResourceType: "deployment", ResourceID: "d1", NewValue: json.RawMessage(`{"name": "prod"}`)},
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
			resp, err := logger.Search(ctx, admin, tc.req)
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

	_, err = logger.Replay(ctx, admin, "nonexistent_id")
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

// admin is the verified admin caller every read needs (AUDIT-10). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
var admin = Caller{ID: "admin-1", IsAdmin: true}

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

	resp, err := logger.QueryLogs(ctx, admin, QueryLogsRequest{Action: strPtr("user_*"), Limit: 10})
	if err != nil {
		t.Fatalf("QueryLogs failed: %v", err)
	}
	if resp.Total != 1 || len(resp.Logs) != 1 || resp.Logs[0].Action != "user_created" {
		t.Errorf("user_* matched %d logs, want only user_created", resp.Total)
	}

	// Search escapes the same way: "r_c" is found in user_created only (CodeRabbit, PR 18).
	found, err := logger.Search(ctx, admin, SearchRequest{Query: "r_c", Limit: 10})
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
	resp, err := logger.QueryLogs(context.Background(), admin, QueryLogsRequest{DateTo: &to, Limit: 10})
	if err != nil {
		t.Fatalf("QueryLogs failed: %v", err)
	}
	if resp.Total != 1 || resp.Logs[0].ID != "log_a" {
		t.Fatalf("a range ending at log_a's instant returned %d logs, want log_a", resp.Total)
	}
	if got := resp.Logs[0].Timestamp; got != "2026-11-01T12:00:00.123000000Z" {
		t.Errorf("old time not rewritten to the fixed form: %s", got)
	}
	all, _ := logger.QueryLogs(context.Background(), admin, QueryLogsRequest{Limit: 10})
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
	all, _ := logger.QueryLogs(context.Background(), admin, QueryLogsRequest{Limit: 10})
	if all.Total != 1 || all.Logs[0].Timestamp != "2026-11-01T12:00:00.500000000Z" {
		t.Fatalf("old time not rewritten under the trigger: %+v", all.Logs)
	}
	if _, err := logger.db.Exec(`UPDATE audit_log SET action = 'x'`); err == nil {
		t.Error("the update trigger is gone after the upgrade; the log must stay immutable")
	}
}

// clockStepping returns a clock starting at t0 that moves one second per call, so entries never tie.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
func clockStepping(t0 time.Time) (func() time.Time, *time.Time) {
	now := t0
	return func() time.Time {
		now = now.Add(time.Second)
		return now
	}, &now
}

// allRowsText dumps every retained row of the three audit tables as text. Added 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-08/09).
func allRowsText(t *testing.T, logger *AuditLogger) string {
	t.Helper()
	var b strings.Builder
	for _, table := range []string{"audit_log", "audit_personal", "audit_subjects"} {
		rows, err := logger.db.Query("SELECT * FROM " + table)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]sql.NullString, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			for _, v := range vals {
				b.WriteString(v.String + "|")
			}
			b.WriteString("\n")
		}
		rows.Close()
	}
	return b.String()
}

// auditLogRows returns every audit_log row, in insertion order, as text.
func auditLogRows(t *testing.T, logger *AuditLogger) []string {
	t.Helper()
	rows, err := logger.db.Query(`SELECT id, timestamp, actor_type, IFNULL(actor_service, '~'), action, resource_type,
		IFNULL(resource_id, '~'), IFNULL(old_value, '~'), IFNULL(new_value, '~'), IFNULL(why_chain_id, '~'), personal_roles, metadata
		FROM audit_log ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		v := make([]string, 12)
		p := make([]any, 12)
		for i := range v {
			p[i] = &v[i]
		}
		if err := rows.Scan(p...); err != nil {
			t.Fatal(err)
		}
		out = append(out, strings.Join(v, "|"))
	}
	return out
}

// TestAuditLogger_EraseSubject proves AUDIT-08: after erase_subject no retained row of audit_log,
// audit_personal or audit_subjects holds the user's id, email or IP; every earlier audit_log row is unchanged
// and exactly one 'audit_subject_erased' row is added (personal_roles '', metadata {erased_rows}); reads show
// the user's entries with personal_erased true, an actor_id filter for the user finds nothing, search finds
// nothing and replay says erased; another user's entries and an admin's own actor row are kept.
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
// AUDIT-08
func TestAuditLogger_EraseSubject(t *testing.T) {
	clock, _ := clockStepping(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	logger, err := NewAuditLoggerWithOptions(":memory:", Options{Now: clock, RetentionDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	ctx := context.Background()
	const uid, email, ip = "987654321", "erase.me@example.test", "203.0.113.77"

	own, err := logger.LogMutation(ctx, LogMutationRequest{ActorID: strPtr(uid), ActorType: "user", Action: "user_profile_updated",
		ResourceType: "user", ResourceID: uid, OldValue: json.RawMessage(`{"email":"a@x.test"}`),
		NewValue: json.RawMessage(`{"email":"` + email + `"}`), WhyChainID: strPtr("wc_1"), IP: strPtr(ip),
		UserAgent: strPtr("UA"), RequestID: strPtr("r1")})
	if err != nil {
		t.Fatal(err)
	}
	byAdmin, err := logger.LogMutation(ctx, LogMutationRequest{ActorID: strPtr("5"), ActorType: "user", SubjectUserID: strPtr(uid),
		Action: "subscription_changed", ResourceType: "subscription", ResourceID: "sub_1",
		OldValue: json.RawMessage(`{"tier":"solo","email":"` + email + `"}`), NewValue: json.RawMessage(`{"tier":"team"}`), IP: strPtr("198.51.100.5")})
	if err != nil {
		t.Fatal(err)
	}
	viaKey, err := logger.LogMutation(ctx, LogMutationRequest{ActorID: strPtr("key_1"), ActorType: "api_key", ActorUserID: strPtr(uid),
		SubjectUserID: strPtr("none"), Action: "deployment_created", ResourceType: "deployment", ResourceID: "dep_1",
		NewValue: json.RawMessage(`{"name":"site"}`), IP: strPtr(ip)})
	if err != nil {
		t.Fatal(err)
	}
	other, err := logger.LogMutation(ctx, LogMutationRequest{ActorID: strPtr("6"), ActorType: "user", Action: "user_created",
		ResourceType: "user", ResourceID: "6", NewValue: json.RawMessage(`{"email":"keep@x.test"}`), IP: strPtr("192.0.2.6")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(allRowsText(t, logger), email) {
		t.Fatal("the email should be stored before the erasure")
	}
	before := auditLogRows(t, logger)

	erased, err := logger.EraseSubject(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if erased != 4 { // own: actor + subject, byAdmin: subject, viaKey: actor
		t.Fatalf("erased_rows = %d, want 4", erased)
	}
	text := allRowsText(t, logger)
	for _, needle := range []string{uid, email, ip} {
		if strings.Contains(text, needle) {
			t.Errorf("a retained row still holds %q", needle)
		}
	}
	after := auditLogRows(t, logger)
	if len(after) != len(before)+1 {
		t.Fatalf("expected exactly one added audit_log row, got %d -> %d", len(before), len(after))
	}
	for i := range before {
		if before[i] != after[i] {
			t.Errorf("audit_log row %d changed:\n%s\n%s", i, before[i], after[i])
		}
	}
	added := strings.Split(after[len(after)-1], "|")
	if added[2] != "service" || added[4] != "audit_subject_erased" || added[5] != "user" || added[6] != "~" ||
		added[10] != "" || added[11] != `{"erased_rows":4}` {
		t.Errorf("unexpected erasure entry: %v", added)
	}

	resp, err := logger.QueryLogs(ctx, admin, QueryLogsRequest{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]LogEntry{}
	for _, l := range resp.Logs {
		byID[l.ID] = l
	}
	for _, id := range []string{own, byAdmin, viaKey} {
		if !byID[id].PersonalErased {
			t.Errorf("entry %s should show personal_erased", id)
		}
	}
	if string(byID[own].NewValue) != "null" || byID[own].IP != nil || byID[own].ActorID != nil {
		t.Errorf("erased fields should read as null: %+v", byID[own])
	}
	if a := byID[byAdmin].ActorID; a == nil || *a != "5" {
		t.Errorf("the admin's own actor row must stay: %v", a)
	}
	if byID[other].PersonalErased || !strings.Contains(string(byID[other].NewValue), "keep@x.test") {
		t.Errorf("another user's entry must keep its data: %+v", byID[other])
	}
	if r, _ := logger.QueryLogs(ctx, admin, QueryLogsRequest{ActorID: strPtr(uid)}); r.Total != 0 {
		t.Errorf("an actor_id filter for the erased user found %d entries", r.Total)
	}
	if r, _ := logger.Search(ctx, admin, SearchRequest{Query: email}); len(r.Results) != 0 {
		t.Errorf("search still finds the erased email")
	}
	rp, err := logger.Replay(ctx, admin, own)
	if err != nil || !rp.Erased || rp.HasDiverged != nil || string(rp.ResourceStateAtTime) != "null" {
		t.Errorf("replay of an erased entry: %+v (%v)", rp, err)
	}
}

// TestAuditLogger_ApplyRetention proves AUDIT-09: entries older than the retention period (30 days here) lose
// their personal rows, newer ones keep them, no audit_log row is removed, and a subject left with no rows goes.
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
// AUDIT-09
func TestAuditLogger_ApplyRetention(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock, now := clockStepping(t0)
	logger, err := NewAuditLoggerWithOptions(":memory:", Options{Now: clock, RetentionDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	ctx := context.Background()
	oldID, _ := logger.LogMutation(ctx, LogMutationRequest{ActorID: strPtr("11"), ActorType: "user", Action: "user_created",
		ResourceType: "user", ResourceID: "11", NewValue: json.RawMessage(`{"email":"old@x.test"}`), IP: strPtr("192.0.2.11")})
	*now = t0.Add(40 * 24 * time.Hour)
	newID, _ := logger.LogMutation(ctx, LogMutationRequest{ActorID: strPtr("12"), ActorType: "user", Action: "user_created",
		ResourceType: "user", ResourceID: "12", NewValue: json.RawMessage(`{"email":"new@x.test"}`), IP: strPtr("192.0.2.12")})
	before := len(auditLogRows(t, logger))

	erased, err := logger.ApplyRetention(ctx, t0.Add(41*24*time.Hour))
	if err != nil || erased != 2 {
		t.Fatalf("erased_rows = %d (%v), want 2", erased, err)
	}
	if got := len(auditLogRows(t, logger)); got != before {
		t.Fatalf("retention removed audit_log rows: %d -> %d", before, got)
	}
	text := allRowsText(t, logger)
	if strings.Contains(text, "192.0.2.11") || strings.Contains(text, "old@x.test") || !strings.Contains(text, "192.0.2.12") {
		t.Errorf("retention erased the wrong rows")
	}
	resp, _ := logger.QueryLogs(ctx, admin, QueryLogsRequest{Limit: 10})
	for _, l := range resp.Logs {
		switch l.ID {
		case oldID:
			if !l.PersonalErased {
				t.Errorf("the old entry should show personal_erased")
			}
		case newID:
			if l.PersonalErased || !strings.Contains(string(l.NewValue), "new@x.test") {
				t.Errorf("the new entry should keep its data: %+v", l)
			}
		}
	}
	var users []string
	rows, _ := logger.db.Query(`SELECT user_id FROM audit_subjects`)
	for rows.Next() {
		var u string
		rows.Scan(&u)
		users = append(users, u)
	}
	rows.Close()
	if len(users) != 1 || users[0] != "12" {
		t.Errorf("subjects left: %v, want [12]", users)
	}
}

// TestAuditLogger_Refusals proves AUDIT-10: log() refuses a non-'user' entry without subject_user_id (400
// subject_required), a metadata key other than feature_flag / erased_rows (400 metadata_key_not_allowed), an
// api_key entry without actor_user_id (400 actor_user_required) and a 'user' entry with a different subject
// (400 subject_mismatch), writing nothing; and every read by a non-admin caller gets 403 admin_only.
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Extended the same day (Phase B.2, audit spec
// "Refusals by log()"): an unknown actor_type is 400 invalid_actor_type, a 'user' actor without actor_id is 400
// actor_required, and a 'service' actor with no service name is 400 actor_service_required. Extended again the
// same day (Phase B.2 follow-up): a 'service' actor with an actor_id but no actor_service is also 400
// actor_service_required (actor_id is no longer used as the service name). Touches: in-memory SQLite.
// AUDIT-10
func TestAuditLogger_Refusals(t *testing.T) {
	logger, err := NewAuditLogger(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	ctx := context.Background()
	base := func() LogMutationRequest {
		return LogMutationRequest{ActorID: strPtr("1"), ActorType: "user", Action: "x_changed", ResourceType: "subscription",
			ResourceID: "1", OldValue: json.RawMessage(`{}`), NewValue: json.RawMessage(`{}`)}
	}
	cases := []struct {
		code string
		edit func(r *LogMutationRequest)
	}{
		{"subject_required", func(r *LogMutationRequest) {}},
		{"metadata_key_not_allowed", func(r *LogMutationRequest) {
			r.SubjectUserID, r.Metadata = strPtr("none"), json.RawMessage(`{"ip":"1.2.3.4"}`)
		}},
		{"actor_user_required", func(r *LogMutationRequest) { r.SubjectUserID, r.ActorType = strPtr("none"), "api_key" }},
		{"subject_mismatch", func(r *LogMutationRequest) { r.ResourceType, r.SubjectUserID = "user", strPtr("2") }},
		// Phase B.2, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the three actor refusals.
		{"invalid_actor_type", func(r *LogMutationRequest) { r.SubjectUserID, r.ActorType = strPtr("none"), "robot" }},
		{"actor_required", func(r *LogMutationRequest) { r.SubjectUserID, r.ActorID = strPtr("none"), nil }},
		{"actor_required", func(r *LogMutationRequest) { r.SubjectUserID, r.ActorID = strPtr("none"), strPtr("") }},
		{"actor_service_required", func(r *LogMutationRequest) {
			r.SubjectUserID, r.ActorType, r.ActorID = strPtr("none"), "service", nil
		}},
		{"actor_service_required", func(r *LogMutationRequest) {
			r.SubjectUserID, r.ActorType, r.ActorID, r.ActorService = strPtr("none"), "service", nil, strPtr("")
		}},
		// Phase B.2 follow-up, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: an actor_id does not stand in for
		// actor_service (the base request carries ActorID "1"; the fallback used it as the service name).
		{"actor_service_required", func(r *LogMutationRequest) { r.SubjectUserID, r.ActorType = strPtr("none"), "service" }},
		{"actor_service_required", func(r *LogMutationRequest) {
			r.SubjectUserID, r.ActorType, r.ActorID = strPtr("none"), "service", strPtr("billing-worker")
		}},
	}
	for _, c := range cases {
		r := base()
		c.edit(&r)
		_, err := logger.LogMutation(ctx, r)
		var ae *AuditError
		if !errors.As(err, &ae) || ae.Status != 400 || ae.Code != c.code {
			t.Errorf("expected 400 %s, got %v", c.code, err)
		}
	}
	if n := len(auditLogRows(t, logger)); n != 0 {
		t.Fatalf("a refused entry wrote %d rows", n)
	}
	var subjects int
	logger.db.QueryRow(`SELECT COUNT(*) FROM audit_subjects`).Scan(&subjects)
	if subjects != 0 {
		t.Fatalf("a refused entry wrote %d subjects", subjects)
	}
	ok := base()
	ok.SubjectUserID, ok.Metadata = strPtr("none"), json.RawMessage(`{"feature_flag":"beta"}`)
	id, err := logger.LogMutation(ctx, ok)
	if err != nil {
		t.Fatalf("an allowed metadata key was refused: %v", err)
	}
	for _, caller := range []Caller{{}, {ID: "1"}, {ID: "1", IsAdmin: false}} {
		reads := []error{}
		_, e1 := logger.QueryLogs(ctx, caller, QueryLogsRequest{})
		_, e2 := logger.Replay(ctx, caller, id)
		_, e3 := logger.Search(ctx, caller, SearchRequest{Query: "x"})
		reads = append(reads, e1, e2, e3)
		for i, e := range reads {
			var ae *AuditError
			if !errors.As(e, &ae) || ae.Status != 403 || ae.Code != "admin_only" {
				t.Errorf("read %d by %+v: expected 403 admin_only, got %v", i, caller, e)
			}
		}
	}
}

// TestAuditLogger_ReplayErasedReflectsSubjectRow proves the Phase B.2 audit amendment for replay: "erased"
// reflects the entry's OWN 'subject' row. Before any erasure every replay answers "erased": false (present in
// the JSON); erasing the admin who acted leaves the entry's subject row, so it stays false with its state;
// erasing the subject makes it true with state and has_diverged null; an entry with subject 'none' stays false.
// Input: none; output: test failures. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
// AUDIT-08
func TestAuditLogger_ReplayErasedReflectsSubjectRow(t *testing.T) {
	logger, err := NewAuditLogger(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	ctx := context.Background()
	byAdmin, err := logger.LogMutation(ctx, LogMutationRequest{ActorID: strPtr("adm"), ActorType: "user", SubjectUserID: strPtr("cust"),
		Action: "subscription_changed", ResourceType: "subscription", ResourceID: "sub_9",
		OldValue: json.RawMessage(`{"tier":"solo"}`), NewValue: json.RawMessage(`{"tier":"team"}`)})
	if err != nil {
		t.Fatal(err)
	}
	noSubject, err := logger.LogMutation(ctx, LogMutationRequest{ActorID: strPtr("adm"), ActorType: "user", SubjectUserID: strPtr("none"),
		Action: "deployment_created", ResourceType: "deployment", ResourceID: "dep_9", NewValue: json.RawMessage(`{"name":"x"}`)})
	if err != nil {
		t.Fatal(err)
	}
	replay := func(id string) (ReplayResponse, map[string]json.RawMessage) {
		t.Helper()
		rp, err := logger.Replay(ctx, admin, id)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(rp)
		m := map[string]json.RawMessage{}
		_ = json.Unmarshal(raw, &m)
		return rp, m
	}
	rp, m := replay(byAdmin)
	if rp.Erased || string(m["erased"]) != "false" || string(rp.ResourceStateAtTime) != `{"tier":"solo"}` {
		t.Fatalf("before erasure: want erased false in the JSON and the state, got %s %+v", m["erased"], rp)
	}
	if _, err := logger.EraseSubject(ctx, "adm"); err != nil {
		t.Fatal(err)
	}
	if rp, _ := replay(byAdmin); rp.Erased || rp.HasDiverged == nil || string(rp.ResourceStateAtTime) != `{"tier":"solo"}` {
		t.Fatalf("erasing the actor must not erase the entry's subject row: %+v", rp)
	}
	if _, err := logger.EraseSubject(ctx, "cust"); err != nil {
		t.Fatal(err)
	}
	rp, m = replay(byAdmin)
	if !rp.Erased || string(m["erased"]) != "true" || rp.HasDiverged != nil || string(rp.ResourceStateAtTime) != "null" {
		t.Fatalf("after erasing the subject: want erased true, state and has_diverged null, got %+v", rp)
	}
	if rp, m := replay(noSubject); rp.Erased || string(m["erased"]) != "false" {
		t.Fatalf("an entry with no subject is never erased: %+v", rp)
	}
}

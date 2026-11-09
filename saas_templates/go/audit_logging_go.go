package auditlogging

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrLogNotFound      = errors.New("audit log not found")
	ErrImmutableLog     = errors.New("audit log is immutable; updates not allowed")
	ErrInvalidActorType = errors.New("actor_type must be 'user', 'service', or 'api_key'")
)

type AuditLogger struct {
	db         *sql.DB
	insertStmt *sql.Stmt
}

// tsLayout is fixed width (always nine fraction digits, always UTC), so timestamps compare correctly as text.
// time.RFC3339Nano drops trailing zeros, which made ".1Z" sort after ".12Z" and broke "later" in Replay.
const tsLayout = "2006-01-02T15:04:05.000000000Z"

func formatTS(t time.Time) string { return t.UTC().Format(tsLayout) }

// likeEscaper escapes LIKE's own wildcards and its escape character, for use with ESCAPE '\'.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

type LogMutationRequest struct {
	ActorID      *string         `json:"actor_id"`
	ActorType    string          `json:"actor_type"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	OldValue     json.RawMessage `json:"old_value"`
	NewValue     json.RawMessage `json:"new_value"`
	WhyChainID   *string         `json:"why_chain_id,omitempty"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
}

type LogEntry struct {
	ID           string          `json:"id"`
	Timestamp    string          `json:"timestamp"`
	ActorID      *string         `json:"actor_id"`
	ActorType    string          `json:"actor_type"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	OldValue     json.RawMessage `json:"old_value"`
	NewValue     json.RawMessage `json:"new_value"`
	WhyChainID   *string         `json:"why_chain_id,omitempty"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
}

type QueryLogsRequest struct {
	ActorID      *string
	Action       *string
	ResourceType *string
	ResourceID   *string
	DateFrom     *time.Time
	DateTo       *time.Time
	Limit        int
	Offset       int
}

type QueryLogsResponse struct {
	Logs    []LogEntry `json:"logs"`
	Total   int        `json:"total"`
	HasMore bool       `json:"has_more"`
}

type ReplayResponse struct {
	LogID               string          `json:"log_id"`
	Timestamp           string          `json:"timestamp"`
	ResourceStateAtTime json.RawMessage `json:"resource_state_at_time"`
	HasDiverged         bool            `json:"has_diverged"`
}

type SearchRequest struct {
	Query        string
	ResourceType *string
	Limit        int
}

type SearchResponse struct {
	Results []LogEntry `json:"results"`
}

func NewAuditLogger(dbPath string) (*AuditLogger, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if dbPath == ":memory:" {
		// Every new connection to ":memory:" opens its own empty database, so the pool must keep exactly one.
		db.SetMaxOpenConns(1)
	}

	if err := initSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	insertStmt, err := db.Prepare(`
		INSERT INTO audit_log (id, timestamp, actor_id, actor_type, action, resource_type, resource_id, old_value, new_value, why_chain_id, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("prepare insert: %w", err)
	}

	return &AuditLogger{db: db, insertStmt: insertStmt}, nil
}

func initSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS audit_log (
		id TEXT PRIMARY KEY,
		timestamp TEXT NOT NULL,
		actor_id TEXT,
		actor_type TEXT NOT NULL,
		action TEXT NOT NULL,
		resource_type TEXT NOT NULL,
		resource_id TEXT NOT NULL,
		old_value TEXT,
		new_value TEXT,
		why_chain_id TEXT,
		metadata TEXT
	);

	-- Upgrade (2026-11-09): rows from the previous version used variable-width RFC3339Nano times, which sort
	-- wrongly against the fixed nine-digit form now written (".123Z" sorted after ".123000000Z"). Rewritten once,
	-- here, before the immutability triggers below exist; every UTC time of 30 characters is already fixed.
	UPDATE audit_log SET timestamp =
		CASE WHEN instr(timestamp, '.') = 0
			THEN substr(timestamp, 1, 19) || '.000000000Z'
			ELSE substr(timestamp, 1, 20) || substr(substr(timestamp, 21, length(timestamp) - 21) || '000000000', 1, 9) || 'Z'
		END
	WHERE length(timestamp) <> 30 AND timestamp LIKE '____-__-__T__:__:__%Z';

	CREATE INDEX IF NOT EXISTS idx_audit_log_actor_action_resource_time 
	ON audit_log(actor_id, action, resource_type, timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_log_resource_time 
	ON audit_log(resource_type, resource_id, timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp 
	ON audit_log(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_log_action 
	ON audit_log(action);

	CREATE TRIGGER IF NOT EXISTS audit_log_immutable_update
	BEFORE UPDATE ON audit_log
	BEGIN
		SELECT RAISE(ABORT, 'audit log is immutable');
	END;

	CREATE TRIGGER IF NOT EXISTS audit_log_immutable_delete
	BEFORE DELETE ON audit_log
	BEGIN
		SELECT RAISE(ABORT, 'audit log is immutable');
	END;
	`
	_, err := db.Exec(schema)
	return err
}

func (a *AuditLogger) Close() error {
	if a.insertStmt != nil {
		a.insertStmt.Close()
	}
	return a.db.Close()
}

func (a *AuditLogger) LogMutation(ctx context.Context, req LogMutationRequest) (string, error) {
	if req.ActorType != "user" && req.ActorType != "service" && req.ActorType != "api_key" {
		return "", ErrInvalidActorType
	}

	id := generateID()
	timestamp := formatTS(time.Now())

	oldVal := string(req.OldValue)
	if oldVal == "" {
		oldVal = "null"
	}
	newVal := string(req.NewValue)
	if newVal == "" {
		newVal = "null"
	}
	meta := string(req.Metadata)
	if meta == "" {
		meta = "null"
	}

	_, err := a.insertStmt.ExecContext(ctx,
		id, timestamp, req.ActorID, req.ActorType, req.Action,
		req.ResourceType, req.ResourceID, oldVal, newVal, req.WhyChainID, meta,
	)
	if err != nil {
		return "", fmt.Errorf("insert log: %w", err)
	}

	return id, nil
}

func (a *AuditLogger) QueryLogs(ctx context.Context, req QueryLogsRequest) (QueryLogsResponse, error) {
	whereClauses := []string{}
	args := []any{}

	if req.ActorID != nil {
		whereClauses = append(whereClauses, "actor_id = ?")
		args = append(args, *req.ActorID)
	}
	if req.Action != nil {
		actionPattern := *req.Action
		if strings.Contains(actionPattern, "*") {
			// Only * is a wildcard: a literal %, _ or \ in an action name must match itself, not any text.
			actionPattern = likeEscaper.Replace(actionPattern)
			actionPattern = strings.ReplaceAll(actionPattern, "*", "%")
			whereClauses = append(whereClauses, `action LIKE ? ESCAPE '\'`)
		} else {
			whereClauses = append(whereClauses, "action = ?")
		}
		args = append(args, actionPattern)
	}
	if req.ResourceType != nil {
		whereClauses = append(whereClauses, "resource_type = ?")
		args = append(args, *req.ResourceType)
	}
	if req.ResourceID != nil {
		whereClauses = append(whereClauses, "resource_id = ?")
		args = append(args, *req.ResourceID)
	}
	if req.DateFrom != nil {
		whereClauses = append(whereClauses, "timestamp >= ?")
		args = append(args, formatTS(*req.DateFrom))
	}
	if req.DateTo != nil {
		whereClauses = append(whereClauses, "timestamp <= ?")
		args = append(args, formatTS(*req.DateTo))
	}

	whereSQL := ""
	if len(whereClauses) > 0 {
		whereSQL = "WHERE " + strings.Join(whereClauses, " AND ")
	}

	countQuery := "SELECT COUNT(*) FROM audit_log " + whereSQL
	var total int
	err := a.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return QueryLogsResponse{}, fmt.Errorf("count logs: %w", err)
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := req.Offset
	if offset < 0 {
		offset = 0
	}

	selectQuery := fmt.Sprintf(`
		SELECT id, timestamp, actor_id, actor_type, action, resource_type, resource_id, old_value, new_value, why_chain_id, metadata
		FROM audit_log
		%s
		ORDER BY timestamp DESC, rowid DESC
		LIMIT ? OFFSET ?
	`, whereSQL)

	args = append(args, limit, offset)
	rows, err := a.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return QueryLogsResponse{}, fmt.Errorf("query logs: %w", err)
	}
	defer rows.Close()

	logs := make([]LogEntry, 0, limit)
	for rows.Next() {
		var entry LogEntry
		var actorID, whyChainID sql.NullString
		var oldVal, newVal, meta string
		err := rows.Scan(
			&entry.ID, &entry.Timestamp, &actorID, &entry.ActorType,
			&entry.Action, &entry.ResourceType, &entry.ResourceID,
			&oldVal, &newVal, &whyChainID, &meta,
		)
		if err != nil {
			return QueryLogsResponse{}, fmt.Errorf("scan log: %w", err)
		}
		if actorID.Valid {
			entry.ActorID = &actorID.String
		}
		if whyChainID.Valid {
			entry.WhyChainID = &whyChainID.String
		}
		entry.OldValue = json.RawMessage(oldVal)
		entry.NewValue = json.RawMessage(newVal)
		entry.Metadata = json.RawMessage(meta)
		logs = append(logs, entry)
	}

	hasMore := (offset + len(logs)) < total
	return QueryLogsResponse{Logs: logs, Total: total, HasMore: hasMore}, nil
}

func (a *AuditLogger) Replay(ctx context.Context, logID string) (ReplayResponse, error) {
	query := `
		SELECT id, timestamp, old_value, new_value, resource_type, resource_id
		FROM audit_log
		WHERE id = ?
	`
	var entry struct {
		ID           string
		Timestamp    string
		OldValue     string
		NewValue     string
		ResourceType string
		ResourceID   string
	}
	err := a.db.QueryRowContext(ctx, query, logID).Scan(
		&entry.ID, &entry.Timestamp, &entry.OldValue, &entry.NewValue,
		&entry.ResourceType, &entry.ResourceID,
	)
	if err == sql.ErrNoRows {
		return ReplayResponse{}, ErrLogNotFound
	}
	if err != nil {
		return ReplayResponse{}, fmt.Errorf("query log: %w", err)
	}

	// "Later" is a later timestamp, or the same timestamp written after this entry (higher rowid). Ids are random,
	// so they cannot break a tie. The same fix as the Rust template (2026-11-05, session f3daac6e).
	divergedQuery := `
		SELECT COUNT(*) FROM audit_log
		WHERE resource_type = ? AND resource_id = ?
		  AND (timestamp > ? OR (timestamp = ? AND rowid > (SELECT rowid FROM audit_log WHERE id = ?)))
	`
	var laterCount int
	err = a.db.QueryRowContext(ctx, divergedQuery, entry.ResourceType, entry.ResourceID, entry.Timestamp, entry.Timestamp, entry.ID).Scan(&laterCount)
	if err != nil {
		return ReplayResponse{}, fmt.Errorf("check divergence: %w", err)
	}

	return ReplayResponse{
		LogID:               entry.ID,
		Timestamp:           entry.Timestamp,
		ResourceStateAtTime: json.RawMessage(entry.NewValue),
		HasDiverged:         laterCount > 0,
	}, nil
}

func (a *AuditLogger) Search(ctx context.Context, req SearchRequest) (SearchResponse, error) {
	if req.Query == "" {
		return SearchResponse{Results: []LogEntry{}}, nil
	}

	searchPattern := "%" + strings.ReplaceAll(likeEscaper.Replace(req.Query), "*", "%") + "%"
	whereClauses := []string{
		`(action LIKE ? ESCAPE '\' OR resource_type LIKE ? ESCAPE '\' OR resource_id LIKE ? ESCAPE '\' OR old_value LIKE ? ESCAPE '\' OR new_value LIKE ? ESCAPE '\')`,
	}
	args := []any{searchPattern, searchPattern, searchPattern, searchPattern, searchPattern}

	if req.ResourceType != nil {
		whereClauses = append(whereClauses, "resource_type = ?")
		args = append(args, *req.ResourceType)
	}

	whereSQL := "WHERE " + strings.Join(whereClauses, " AND ")

	limit := req.Limit
	if limit <= 0 {
		limit = 50
	}

	query := fmt.Sprintf(`
		SELECT id, timestamp, actor_id, actor_type, action, resource_type, resource_id, old_value, new_value, why_chain_id, metadata
		FROM audit_log
		%s
		ORDER BY timestamp DESC, rowid DESC
		LIMIT ?
	`, whereSQL)

	args = append(args, limit)
	rows, err := a.db.QueryContext(ctx, query, args...)
	if err != nil {
		return SearchResponse{}, fmt.Errorf("search logs: %w", err)
	}
	defer rows.Close()

	results := make([]LogEntry, 0, limit)
	for rows.Next() {
		var entry LogEntry
		var actorID, whyChainID sql.NullString
		var oldVal, newVal, meta string
		err := rows.Scan(
			&entry.ID, &entry.Timestamp, &actorID, &entry.ActorType,
			&entry.Action, &entry.ResourceType, &entry.ResourceID,
			&oldVal, &newVal, &whyChainID, &meta,
		)
		if err != nil {
			return SearchResponse{}, fmt.Errorf("scan log: %w", err)
		}
		if actorID.Valid {
			entry.ActorID = &actorID.String
		}
		if whyChainID.Valid {
			entry.WhyChainID = &whyChainID.String
		}
		entry.OldValue = json.RawMessage(oldVal)
		entry.NewValue = json.RawMessage(newVal)
		entry.Metadata = json.RawMessage(meta)
		results = append(results, entry)
	}

	return SearchResponse{Results: results}, nil
}

func generateID() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	return "log_" + hex.EncodeToString(bytes)
}

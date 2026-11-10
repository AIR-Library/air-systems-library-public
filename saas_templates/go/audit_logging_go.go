// Package auditlogging is the AOI Systems Library audit-log template: every mutation is logged append-only,
// queried, replayed and searched by admins, and a person's data can be erased without rewriting an event.
//
// Phase B rebuild, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, for the amended spec (AUDIT-08/09/10,
// docs/specs/audit_logging.md, amended after review on PR 19 and an independent security review), following
// the Python template:
//   - audit_log keeps events only. For an entry with a data subject, resource_id, old_value, new_value and
//     why_chain_id live in its 'subject' row of audit_personal; the acting user's id, ip, user_agent and
//     request_id live in its 'actor' row (actor_type 'user', or 'api_key' under actor_user_id). Both point at
//     audit_subjects through a RANDOM subject_ref, so deleting those rows leaves nothing that leads back.
//   - LogMutation requires subject_user_id (a user id or 'none') for every resource_type except 'user', allows
//     only the metadata keys feature_flag / erased_rows, requires actor_user_id for an api_key actor, and writes
//     the subject, the entry and its personal rows in ONE transaction.
//   - EraseSubject and ApplyRetention delete personal and subject rows only, never an audit_log row;
//     EraseSubject adds exactly one 'audit_subject_erased' entry.
//   - Reads (query, replay, search) are for admins only (403) and show personal_erased after erasure.
//   - Time comes from an injectable clock; ties are broken by insertion order (rowid).
//   - A database written by the previous version is migrated once when opened (see migrateLegacy).
//
// Touches: SQLite only.
package auditlogging

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrLogNotFound      = errors.New("audit log not found")
	ErrImmutableLog     = errors.New("audit log is immutable; updates not allowed")
	ErrInvalidActorType = errors.New("actor_type must be 'user', 'service', or 'api_key'")
)

// AuditError is a refusal with the HTTP status and error code the spec names (400 subject_required,
// metadata_key_not_allowed, actor_user_required, subject_mismatch, invalid_actor_type, actor_required,
// actor_service_required; 403 admin_only; 404 log_not_found). Unwrap returns the matching sentinel where one
// exists. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-10); actor_required and
// actor_service_required added the same day (Phase B.2, audit spec "Refusals by log()").
type AuditError struct {
	Status  int
	Code    string
	Message string
	wrapped error
}

func (e *AuditError) Error() string { return e.Code + ": " + e.Message }
func (e *AuditError) Unwrap() error { return e.wrapped }

func auditErr(status int, code, msg string) *AuditError {
	return &AuditError{Status: status, Code: code, Message: msg}
}

// Caller is the verified caller of a read. Only IsAdmin true may read (AUDIT-10).
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
type Caller struct {
	ID      string
	IsAdmin bool
}

// Options configures NewAuditLoggerWithOptions. Now is the clock (nil = time.Now); RetentionDays is the
// period ApplyRetention keeps personal data for (0 = 365). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
type Options struct {
	Now           func() time.Time
	RetentionDays int
}

// DefaultRetentionDays is used when Options.RetentionDays is 0. The right period depends on the purpose and
// the legal obligations that apply; this is configuration, not a recommendation.
const DefaultRetentionDays = 365

// eraserService names the audit system itself as the actor of the entries it writes.
const eraserService = "audit"

var allowedMetadataKeys = map[string]bool{"feature_flag": true, "erased_rows": true}

type AuditLogger struct {
	db            *sql.DB
	now           func() time.Time
	retentionDays int
	mu            sync.Mutex
}

// tsLayout is fixed width (always nine fraction digits, always UTC), so timestamps compare correctly as text.
// time.RFC3339Nano drops trailing zeros, which made ".1Z" sort after ".12Z" and broke "later" in Replay.
const tsLayout = "2006-01-02T15:04:05.000000000Z"

// formatTS writes t in UTC with the fixed nine-digit layout, so stored times compare correctly as text. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
func formatTS(t time.Time) string { return t.UTC().Format(tsLayout) }

// likeEscaper escapes LIKE's own wildcards and its escape character, for use with ESCAPE '\'.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// LogMutationRequest is one mutation to log.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-08/10): SubjectUserID (a user id or "none";
// required unless ResourceType is "user"), ActorUserID (an api_key's owner, required for api_key actors),
// ActorService, and the request's IP, UserAgent and RequestID, which are personal data and go to the 'actor'
// row, never to metadata. ResourceID "" means none.
type LogMutationRequest struct {
	ActorID       *string         `json:"actor_id"`
	ActorType     string          `json:"actor_type"`
	ActorUserID   *string         `json:"actor_user_id,omitempty"`
	ActorService  *string         `json:"actor_service,omitempty"`
	SubjectUserID *string         `json:"subject_user_id,omitempty"`
	Action        string          `json:"action"`
	ResourceType  string          `json:"resource_type"`
	ResourceID    string          `json:"resource_id"`
	OldValue      json.RawMessage `json:"old_value"`
	NewValue      json.RawMessage `json:"new_value"`
	WhyChainID    *string         `json:"why_chain_id,omitempty"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
	IP            *string         `json:"ip,omitempty"`
	UserAgent     *string         `json:"user_agent,omitempty"`
	RequestID     *string         `json:"request_id,omitempty"`
}

// LogEntry is the read shape of one entry: the event joined with its personal rows. Personal fields are
// nil once erased, and PersonalErased is then true. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
type LogEntry struct {
	ID             string          `json:"id"`
	Timestamp      string          `json:"timestamp"`
	ActorID        *string         `json:"actor_id"`
	ActorType      string          `json:"actor_type"`
	ActorService   *string         `json:"actor_service"`
	IP             *string         `json:"ip"`
	UserAgent      *string         `json:"user_agent"`
	RequestID      *string         `json:"request_id"`
	Action         string          `json:"action"`
	ResourceType   string          `json:"resource_type"`
	ResourceID     *string         `json:"resource_id"`
	OldValue       json.RawMessage `json:"old_value"`
	NewValue       json.RawMessage `json:"new_value"`
	WhyChainID     *string         `json:"why_chain_id"`
	Metadata       json.RawMessage `json:"metadata"`
	PersonalErased bool            `json:"personal_erased"`
}

type QueryLogsRequest struct {
	ActorID      *string
	Action       *string
	ResourceType *string
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

// ReplayResponse is the state an entry recorded. Erased reflects the entry's own 'subject' row: true when the
// entry was written with one and it is gone (the state and HasDiverged are then null), false otherwise, and
// it is always in the JSON. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP; the same day (Phase B.2,
// audit spec) "erased" stopped being omitted when false, so every replay answers it. Touches nothing.
type ReplayResponse struct {
	LogID               string          `json:"log_id"`
	Timestamp           string          `json:"timestamp"`
	Erased              bool            `json:"erased"`
	ResourceStateAtTime json.RawMessage `json:"resource_state_at_time"`
	HasDiverged         *bool           `json:"has_diverged"`
}

type SearchRequest struct {
	Query        string
	ResourceType *string
	Limit        int
}

type SearchResponse struct {
	Results []LogEntry `json:"results"`
}

// NewAuditLogger opens dbPath with the wall clock and the default retention. See NewAuditLoggerWithOptions.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database file.
func NewAuditLogger(dbPath string) (*AuditLogger, error) {
	return NewAuditLoggerWithOptions(dbPath, Options{})
}

// NewAuditLoggerWithOptions opens the SQLite database at dbPath (":memory:" keeps one connection), creates or
// migrates the schema. Out: the logger or an error. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the database file.
func NewAuditLoggerWithOptions(dbPath string, opts Options) (*AuditLogger, error) {
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
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	days := opts.RetentionDays
	if days <= 0 {
		days = DefaultRetentionDays
	}
	return &AuditLogger{db: db, now: now, retentionDays: days}, nil
}

const schemaTables = `
CREATE TABLE IF NOT EXISTS audit_subjects (
	subject_ref TEXT PRIMARY KEY,
	user_id TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_personal (
	log_id TEXT NOT NULL,
	subject_ref TEXT NOT NULL REFERENCES audit_subjects (subject_ref),
	role TEXT NOT NULL CHECK (role IN ('actor', 'subject')),
	data TEXT NOT NULL,
	PRIMARY KEY (log_id, role)
);
`

const auditLogTable = `
CREATE TABLE IF NOT EXISTS %s (
	id TEXT PRIMARY KEY,
	timestamp TEXT NOT NULL,
	actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'service', 'api_key')),
	actor_service TEXT,
	action TEXT NOT NULL,
	resource_type TEXT NOT NULL,
	resource_id TEXT,
	old_value TEXT,
	new_value TEXT,
	why_chain_id TEXT,
	personal_roles TEXT NOT NULL DEFAULT '',
	metadata TEXT NOT NULL DEFAULT '{}'
);
`

const schemaIndexesAndTriggers = `
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log (action, resource_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log (resource_type, resource_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_service ON audit_log (actor_service);
-- covers the per-entry step of an actor_id query (id -> action, resource_type, timestamp) without reading rows
CREATE INDEX IF NOT EXISTS idx_audit_log_id_filters ON audit_log (id, action, resource_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_personal_subject ON audit_personal (subject_ref, role, log_id);
CREATE TRIGGER IF NOT EXISTS audit_log_immutable_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is immutable'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_immutable_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is immutable'); END;
CREATE TRIGGER IF NOT EXISTS audit_personal_immutable_update BEFORE UPDATE ON audit_personal
BEGIN SELECT RAISE(ABORT, 'audit personal rows are immutable'); END;
`

// fixedTS rewrites an old variable-width RFC3339 time in column col to the fixed nine-digit form (SQL).
const fixedTS = `CASE WHEN length(timestamp) = 30 OR timestamp NOT LIKE '____-__-__T__:__:__%Z' THEN timestamp
	WHEN instr(timestamp, '.') = 0 THEN substr(timestamp, 1, 19) || '.000000000Z'
	ELSE substr(timestamp, 1, 20) || substr(substr(timestamp, 21, length(timestamp) - 21) || '000000000', 1, 9) || 'Z' END`

// initSchema creates the three tables, indexes and immutability triggers, migrating a database written by
// the previous version first. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
func initSchema(db *sql.DB) error {
	if _, err := db.Exec(schemaTables); err != nil {
		return err
	}
	legacy, err := hasColumn(db, "audit_log", "actor_id")
	if err != nil {
		return err
	}
	if legacy {
		if err := migrateLegacy(db); err != nil {
			return fmt.Errorf("migrate the previous schema: %w", err)
		}
	}
	if _, err := db.Exec(fmt.Sprintf(auditLogTable, "audit_log")); err != nil {
		return err
	}
	_, err = db.Exec(schemaIndexesAndTriggers)
	return err
}

// hasColumn reports whether table has column. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
func hasColumn(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// migrateLegacy moves a previous-version audit_log (actor_id in the event row, variable-width times) to the
// current layout in ONE transaction, with the old triggers dropped and recreated afterwards by initSchema:
// every row is copied in insertion order with its time rewritten to the fixed form; a user or api_key actor
// becomes an 'actor' row in audit_personal under a random subject_ref; a service actor's id becomes
// actor_service. Legacy rows had no subject_user_id, so they are kept as subject 'none' (their resource
// fields stay in audit_log). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (it replaces the 2026-11-09
// in-place time rewrite, which this version folds in). Touches: the database.
func migrateLegacy(db *sql.DB) error {
	ref := `lower(hex(randomblob(16)))`
	stmts := []string{
		`BEGIN`,
		`DROP TRIGGER IF EXISTS audit_log_immutable_update`,
		`DROP TRIGGER IF EXISTS audit_log_immutable_delete`,
		fmt.Sprintf(auditLogTable, "audit_log_v2"),
		`INSERT INTO audit_log_v2 (id, timestamp, actor_type, actor_service, action, resource_type, resource_id,
			old_value, new_value, why_chain_id, personal_roles, metadata)
		 SELECT id, ` + fixedTS + `, actor_type,
			CASE WHEN actor_type = 'service' THEN actor_id END, action, resource_type, NULLIF(resource_id, ''),
			NULLIF(old_value, 'null'), NULLIF(new_value, 'null'), why_chain_id,
			CASE WHEN actor_type IN ('user', 'api_key') AND actor_id IS NOT NULL THEN 'actor' ELSE '' END,
			CASE WHEN metadata IS NULL OR metadata = 'null' THEN '{}' ELSE metadata END
		 FROM audit_log ORDER BY rowid`,
		`INSERT OR IGNORE INTO audit_subjects (subject_ref, user_id, created_at)
		 SELECT ` + ref + `, actor_id, '` + formatTS(time.Now()) + `' FROM
			(SELECT DISTINCT actor_id FROM audit_log WHERE actor_type IN ('user', 'api_key') AND actor_id IS NOT NULL)`,
		`INSERT INTO audit_personal (log_id, subject_ref, role, data)
		 SELECT a.id, s.subject_ref, 'actor', json_object('actor_id', a.actor_id, 'ip', NULL, 'user_agent', NULL, 'request_id', NULL)
		 FROM audit_log a JOIN audit_subjects s ON s.user_id = a.actor_id
		 WHERE a.actor_type IN ('user', 'api_key') AND a.actor_id IS NOT NULL`,
		`DROP TABLE audit_log`,
		`ALTER TABLE audit_log_v2 RENAME TO audit_log`,
		`COMMIT`,
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		return err
	}
	defer conn.Close()
	for _, st := range stmts {
		if _, err := conn.ExecContext(context.Background(), st); err != nil {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
			return err
		}
	}
	return nil
}

// Close releases the database. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
func (a *AuditLogger) Close() error {
	return a.db.Close()
}

// rawOrNull returns the JSON text of v for storage, or nil (SQL NULL) for an empty or JSON null value.
func rawOrNull(v json.RawMessage) interface{} {
	t := strings.TrimSpace(string(v))
	if t == "" || t == "null" {
		return nil
	}
	return t
}

// jsonOrNull returns v, or the JSON literal null for an empty value.
func jsonOrNull(v json.RawMessage) json.RawMessage {
	if t := strings.TrimSpace(string(v)); t != "" {
		return json.RawMessage(t)
	}
	return json.RawMessage("null")
}

// subjectRef finds or creates the user's random subject_ref (insert-if-absent on user_id) inside tx.
// 128 random bits, never derived from the user id. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: audit_subjects.
func subjectRef(ctx context.Context, tx *sql.Tx, userID, now string) (string, error) {
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO audit_subjects (subject_ref, user_id, created_at) VALUES (?, ?, ?)`,
		randomHex(16), userID, now); err != nil {
		return "", err
	}
	var ref string
	err := tx.QueryRowContext(ctx, `SELECT subject_ref FROM audit_subjects WHERE user_id = ?`, userID).Scan(&ref)
	return ref, err
}

// LogMutation appends one entry (POST /audit/log, an internal service-authenticated call: the actor is the
// verified caller, never taken from a client body).
//
// In: LogMutationRequest. Out: the new log id, or an *AuditError 400: invalid_actor_type (actor_type not
// user/service/api_key), actor_required (a 'user' actor without ActorID), actor_service_required (a 'service'
// actor with neither ActorService nor ActorID, which names the service when ActorService is absent),
// metadata_key_not_allowed, subject_required, subject_mismatch, actor_user_required (an api_key without
// ActorUserID). Nothing is written on a refusal.
// Writes in ONE transaction: the subject(s) in audit_subjects, the audit_log event (resource fields only when
// the subject is 'none'), the 'subject' row {resource_id, old_value, new_value, why_chain_id} and the 'actor'
// row {actor_id, ip, user_agent, request_id} for user and api_key actors.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-01/08/10, amended). Changed again the same day
// (Phase B.2, audit spec "Refusals by log()"): a user actor without actor_id is actor_required (it was
// actor_user_required, the api_key code), and a service actor with no name is refused with
// actor_service_required (it was written with a NULL actor_service). Touches: the database.
func (a *AuditLogger) LogMutation(ctx context.Context, req LogMutationRequest) (string, error) {
	if req.ActorType != "user" && req.ActorType != "service" && req.ActorType != "api_key" {
		return "", &AuditError{Status: 400, Code: "invalid_actor_type", Message: ErrInvalidActorType.Error(), wrapped: ErrInvalidActorType}
	}
	metadata := map[string]json.RawMessage{}
	if m := rawOrNull(req.Metadata); m != nil {
		if err := json.Unmarshal([]byte(m.(string)), &metadata); err != nil {
			return "", auditErr(400, "invalid_metadata", "metadata must be a JSON object")
		}
	}
	var bad []string
	for k := range metadata {
		if !allowedMetadataKeys[k] {
			bad = append(bad, k)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return "", auditErr(400, "metadata_key_not_allowed", "metadata keys not allowed: "+strings.Join(bad, ", "))
	}
	var subject string // "" = no data subject
	if req.ResourceType == "user" {
		if req.ResourceID == "" {
			return "", auditErr(400, "subject_required", "a 'user' entry needs its resource_id")
		}
		subject = req.ResourceID
		if req.SubjectUserID != nil && *req.SubjectUserID != subject {
			return "", auditErr(400, "subject_mismatch", "subject_user_id differs from the user resource_id")
		}
	} else {
		if req.SubjectUserID == nil || *req.SubjectUserID == "" {
			return "", auditErr(400, "subject_required", "subject_user_id (a user id or 'none') is required")
		}
		if *req.SubjectUserID != "none" {
			subject = *req.SubjectUserID
		}
	}
	var actorOwner string
	switch req.ActorType {
	case "user":
		if req.ActorID == nil || *req.ActorID == "" {
			return "", auditErr(400, "actor_required", "a user actor needs actor_id")
		}
		actorOwner = *req.ActorID
	case "api_key":
		if req.ActorUserID == nil || *req.ActorUserID == "" {
			return "", auditErr(400, "actor_user_required", "an api_key entry needs actor_user_id (the key's owner)")
		}
		actorOwner = *req.ActorUserID
	}
	var service interface{}
	if req.ActorType == "service" {
		switch {
		case req.ActorService != nil && *req.ActorService != "":
			service = *req.ActorService
		case req.ActorID != nil && *req.ActorID != "":
			service = *req.ActorID
		default:
			return "", auditErr(400, "actor_service_required", "a service actor needs actor_service")
		}
	}
	var roles []string
	if actorOwner != "" {
		roles = append(roles, "actor")
	}
	if subject != "" {
		roles = append(roles, "subject")
	}
	metaJSON, _ := json.Marshal(metadata)
	var resourceID interface{}
	if req.ResourceID != "" {
		resourceID = req.ResourceID
	}

	id := generateID()
	now := formatTS(a.now())
	a.mu.Lock()
	defer a.mu.Unlock()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	inLog := subject == ""
	pick := func(v interface{}) interface{} {
		if inLog {
			return v
		}
		return nil
	}
	var why interface{}
	if req.WhyChainID != nil {
		why = *req.WhyChainID
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log (id, timestamp, actor_type, actor_service, action, resource_type,
		resource_id, old_value, new_value, why_chain_id, personal_roles, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, now, req.ActorType, service, req.Action, req.ResourceType, pick(resourceID), pick(rawOrNull(req.OldValue)),
		pick(rawOrNull(req.NewValue)), pick(why), strings.Join(roles, ","), string(metaJSON)); err != nil {
		return "", fmt.Errorf("insert log: %w", err)
	}
	if actorOwner != "" {
		ref, err := subjectRef(ctx, tx, actorOwner, now)
		if err != nil {
			return "", err
		}
		data, _ := json.Marshal(map[string]*string{"actor_id": req.ActorID, "ip": req.IP, "user_agent": req.UserAgent, "request_id": req.RequestID})
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_personal (log_id, subject_ref, role, data) VALUES (?, ?, 'actor', ?)`,
			id, ref, string(data)); err != nil {
			return "", err
		}
	}
	if subject != "" {
		ref, err := subjectRef(ctx, tx, subject, now)
		if err != nil {
			return "", err
		}
		data, _ := json.Marshal(map[string]interface{}{"resource_id": resourceID, "old_value": jsonOrNull(req.OldValue),
			"new_value": jsonOrNull(req.NewValue), "why_chain_id": why})
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_personal (log_id, subject_ref, role, data) VALUES (?, ?, 'subject', ?)`,
			id, ref, string(data)); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return id, nil
}

// EraseSubject erases a data subject: it deletes every audit_personal row with the user's subject_ref, then the
// audit_subjects row, and adds exactly one 'audit_subject_erased' entry (actor_type 'service', resource_type
// 'user', no resource_id, personal_roles '', metadata {erased_rows}), all in one transaction. No audit_log row
// is updated or deleted. In: the user id. Out: the number of personal rows erased.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-08); data_export_compliance calls it LAST.
// Touches: the database.
func (a *AuditLogger) EraseSubject(ctx context.Context, userID string) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var ref string
	var erased int64
	err = tx.QueryRowContext(ctx, `SELECT subject_ref FROM audit_subjects WHERE user_id = ?`, userID).Scan(&ref)
	switch {
	case err == nil:
		res, err := tx.ExecContext(ctx, `DELETE FROM audit_personal WHERE subject_ref = ?`, ref)
		if err != nil {
			return 0, err
		}
		erased, _ = res.RowsAffected()
		if _, err := tx.ExecContext(ctx, `DELETE FROM audit_subjects WHERE subject_ref = ?`, ref); err != nil {
			return 0, err
		}
	case !errors.Is(err, sql.ErrNoRows):
		return 0, err
	}
	meta, _ := json.Marshal(map[string]int64{"erased_rows": erased})
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log (id, timestamp, actor_type, actor_service, action, resource_type,
		resource_id, old_value, new_value, why_chain_id, personal_roles, metadata)
		VALUES (?, ?, 'service', ?, 'audit_subject_erased', 'user', NULL, NULL, NULL, NULL, '', ?)`,
		generateID(), formatTS(a.now()), eraserService, string(meta)); err != nil {
		return 0, err
	}
	return erased, tx.Commit()
}

// ApplyRetention erases the personal data of entries older than the retention period (their audit_personal
// rows) and any audit_subjects row left with none. audit_log rows stay. In: now. Out: rows erased.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-09). Touches: the database.
func (a *AuditLogger) ApplyRetention(ctx context.Context, now time.Time) (int64, error) {
	cutoff := formatTS(now.AddDate(0, 0, -a.retentionDays))
	a.mu.Lock()
	defer a.mu.Unlock()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM audit_personal WHERE log_id IN (SELECT id FROM audit_log WHERE timestamp < ?)`, cutoff)
	if err != nil {
		return 0, err
	}
	erased, _ := res.RowsAffected()
	if _, err := tx.ExecContext(ctx, `DELETE FROM audit_subjects WHERE subject_ref NOT IN (SELECT DISTINCT subject_ref FROM audit_personal)`); err != nil {
		return 0, err
	}
	return erased, tx.Commit()
}

// requireAdmin refuses every caller but an admin (AUDIT-10). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
func requireAdmin(c Caller) error {
	if !c.IsAdmin {
		return auditErr(403, "admin_only", "audit reads are for admins only")
	}
	return nil
}

// row is one audit_log row as stored.
type row struct {
	id, ts, actorType, action, resourceType, roles, metadata string
	service, resourceID, oldValue, newValue, why            sql.NullString
}

const rowColumns = `l.id, l.timestamp, l.actor_type, l.actor_service, l.action, l.resource_type, l.resource_id,
	l.old_value, l.new_value, l.why_chain_id, l.personal_roles, l.metadata`

func scanRows(rows *sql.Rows) ([]row, error) {
	defer rows.Close()
	var out []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.ts, &r.actorType, &r.service, &r.action, &r.resourceType, &r.resourceID,
			&r.oldValue, &r.newValue, &r.why, &r.roles, &r.metadata); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func nsPtr(s sql.NullString) *string {
	if !s.Valid {
		return nil
	}
	v := s.String
	return &v
}

func nsJSON(s sql.NullString) json.RawMessage {
	if !s.Valid || s.String == "" {
		return json.RawMessage("null")
	}
	return json.RawMessage(s.String)
}

// present turns stored rows into LogEntry values, joining their personal rows; an entry whose personal rows
// are gone shows those fields as nil and PersonalErased true. Added 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read).
func (a *AuditLogger) present(ctx context.Context, rows []row) ([]LogEntry, error) {
	personal := map[string]map[string]json.RawMessage{} // log_id+"/"+role -> data
	for start := 0; start < len(rows); start += 500 {
		end := start + 500
		if end > len(rows) {
			end = len(rows)
		}
		args := make([]interface{}, 0, end-start)
		for _, r := range rows[start:end] {
			args = append(args, r.id)
		}
		q := `SELECT log_id, role, data FROM audit_personal WHERE log_id IN (?` + strings.Repeat(",?", len(args)-1) + `)`
		pr, err := a.db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		for pr.Next() {
			var logID, role, data string
			if err := pr.Scan(&logID, &role, &data); err != nil {
				pr.Close()
				return nil, err
			}
			m := map[string]json.RawMessage{}
			_ = json.Unmarshal([]byte(data), &m)
			personal[logID+"/"+role] = m
		}
		if err := pr.Close(); err != nil {
			return nil, err
		}
	}
	str := func(v json.RawMessage) *string {
		var s *string
		_ = json.Unmarshal(v, &s)
		return s
	}
	out := make([]LogEntry, 0, len(rows))
	for _, r := range rows {
		e := LogEntry{ID: r.id, Timestamp: r.ts, ActorType: r.actorType, ActorService: nsPtr(r.service), Action: r.action,
			ResourceType: r.resourceType, Metadata: json.RawMessage(r.metadata), OldValue: json.RawMessage("null"), NewValue: json.RawMessage("null")}
		roles := strings.Split(r.roles, ",")
		hasSubject := false
		for _, role := range roles {
			if role == "" {
				continue
			}
			if _, ok := personal[r.id+"/"+role]; !ok {
				e.PersonalErased = true
			}
			if role == "subject" {
				hasSubject = true
			}
		}
		if actor, ok := personal[r.id+"/actor"]; ok {
			e.ActorID, e.IP, e.UserAgent, e.RequestID = str(actor["actor_id"]), str(actor["ip"]), str(actor["user_agent"]), str(actor["request_id"])
		} else if r.actorType == "service" {
			e.ActorID = nsPtr(r.service)
		}
		if hasSubject {
			if sub, ok := personal[r.id+"/subject"]; ok {
				e.ResourceID, e.WhyChainID = str(sub["resource_id"]), str(sub["why_chain_id"])
				e.OldValue, e.NewValue = jsonOrNull(sub["old_value"]), jsonOrNull(sub["new_value"])
			}
		} else {
			e.ResourceID, e.WhyChainID = nsPtr(r.resourceID), nsPtr(r.why)
			e.OldValue, e.NewValue = nsJSON(r.oldValue), nsJSON(r.newValue)
		}
		out = append(out, e)
	}
	return out, nil
}

// QueryLogs (GET /audit/logs, admins only: 403 otherwise) filters by actor, action (only * is a wildcard; a
// literal _ or % matches itself), resource type and time window; newest first, ties in reverse insertion
// order (limit 1-1000, default 100). Out: the page, total and has_more. actor_id resolves through audit_subjects and the 'actor' rows of
// audit_personal, so an erased actor matches nothing; a service actor matches by its name.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-03/04/05/07/08/10). Touches: the database (read).
func (a *AuditLogger) QueryLogs(ctx context.Context, caller Caller, req QueryLogsRequest) (QueryLogsResponse, error) {
	if err := requireAdmin(caller); err != nil {
		return QueryLogsResponse{}, err
	}
	source := "audit_log l"
	var where []string
	var args []interface{}
	if req.ActorID != nil {
		var ref string
		err := a.db.QueryRowContext(ctx, `SELECT subject_ref FROM audit_subjects WHERE user_id = ?`, *req.ActorID).Scan(&ref)
		switch {
		case err == nil:
			// CROSS JOIN makes SQLite walk the actor's personal rows first; both steps use indexes (AUDIT-05).
			source = "audit_personal p CROSS JOIN audit_log l ON l.id = p.log_id"
			where = append(where, "p.subject_ref = ? AND p.role = 'actor'")
			args = append(args, ref)
		case errors.Is(err, sql.ErrNoRows):
			where = append(where, "l.actor_type = 'service' AND l.actor_service = ?")
			args = append(args, *req.ActorID)
		default:
			return QueryLogsResponse{}, err
		}
	}
	if req.Action != nil {
		if strings.Contains(*req.Action, "*") {
			where = append(where, `l.action LIKE ? ESCAPE '\'`)
			args = append(args, strings.ReplaceAll(likeEscaper.Replace(*req.Action), "*", "%"))
		} else {
			where = append(where, "l.action = ?")
			args = append(args, *req.Action)
		}
	}
	if req.ResourceType != nil {
		where = append(where, "l.resource_type = ?")
		args = append(args, *req.ResourceType)
	}
	if req.DateFrom != nil {
		where = append(where, "l.timestamp >= ?")
		args = append(args, formatTS(*req.DateFrom))
	}
	if req.DateTo != nil {
		where = append(where, "l.timestamp <= ?")
		args = append(args, formatTS(*req.DateTo))
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}
	limit, offset := req.Limit, req.Offset
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 { // one page is fetched with an IN list of its ids
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	// Step 1 reads only indexes: the page's ids, in order, with the total counted in the same pass (AUDIT-05:
	// sorting 10,000 full rows of a 1M-row log took most of the 100 ms budget).
	ids, err := a.db.QueryContext(ctx, "SELECT l.id, COUNT(*) OVER () FROM "+source+whereSQL+
		" ORDER BY l.timestamp DESC, l.rowid DESC LIMIT ? OFFSET ?", append(args, limit, offset)...)
	if err != nil {
		return QueryLogsResponse{}, fmt.Errorf("query logs: %w", err)
	}
	var page []interface{}
	total := -1
	for ids.Next() {
		var id string
		if err := ids.Scan(&id, &total); err != nil {
			ids.Close()
			return QueryLogsResponse{}, err
		}
		page = append(page, id)
	}
	if err := ids.Close(); err != nil {
		return QueryLogsResponse{}, err
	}
	if total < 0 { // an empty page: count separately
		if err := a.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+source+whereSQL, args...).Scan(&total); err != nil {
			return QueryLogsResponse{}, fmt.Errorf("count logs: %w", err)
		}
	}
	// Step 2 reads the page's rows.
	var rows []row
	if len(page) > 0 {
		rs, err := a.db.QueryContext(ctx, "SELECT "+rowColumns+" FROM audit_log l WHERE l.id IN (?"+strings.Repeat(",?", len(page)-1)+
			") ORDER BY l.timestamp DESC, l.rowid DESC", page...)
		if err != nil {
			return QueryLogsResponse{}, fmt.Errorf("query logs: %w", err)
		}
		if rows, err = scanRows(rs); err != nil {
			return QueryLogsResponse{}, err
		}
	}
	logs, err := a.present(ctx, rows)
	if err != nil {
		return QueryLogsResponse{}, err
	}
	return QueryLogsResponse{Logs: logs, Total: total, HasMore: offset+len(logs) < total}, nil
}

// Replay (GET /audit/replay/:log_id, admins only) returns the entry's old_value as the resource state at that
// time and whether the state diverged since: the latest entry for the same resource left a different
// new_value. For an entry whose subject rows are gone it returns {erased: true, state null, has_diverged
// null}. *AuditError 404 (wrapping ErrLogNotFound) for an unknown id.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-02/08, as the Python template: the state is the
// old_value the spec names, and divergence compares the latest new_value). Touches: the database (read).
func (a *AuditLogger) Replay(ctx context.Context, caller Caller, logID string) (ReplayResponse, error) {
	if err := requireAdmin(caller); err != nil {
		return ReplayResponse{}, err
	}
	rs, err := a.db.QueryContext(ctx, "SELECT "+rowColumns+" FROM audit_log l WHERE l.id = ?", logID)
	if err != nil {
		return ReplayResponse{}, err
	}
	rows, err := scanRows(rs)
	if err != nil {
		return ReplayResponse{}, err
	}
	if len(rows) == 0 {
		return ReplayResponse{}, &AuditError{Status: 404, Code: "log_not_found", Message: "log " + logID + " not found", wrapped: ErrLogNotFound}
	}
	entries, err := a.present(ctx, rows)
	if err != nil {
		return ReplayResponse{}, err
	}
	e, r := entries[0], rows[0]
	hasSubject := strings.Contains(r.roles, "subject")
	if hasSubject {
		var n int
		if err := a.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_personal WHERE log_id = ? AND role = 'subject'`, logID).Scan(&n); err != nil {
			return ReplayResponse{}, err
		}
		if n == 0 {
			return ReplayResponse{LogID: logID, Timestamp: r.ts, Erased: true, ResourceStateAtTime: json.RawMessage("null")}, nil
		}
	}
	var latestID string
	var latestNew json.RawMessage
	if hasSubject {
		var ref, data string
		err = a.db.QueryRowContext(ctx, `SELECT subject_ref FROM audit_personal WHERE log_id = ? AND role = 'subject'`, logID).Scan(&ref)
		if err != nil {
			return ReplayResponse{}, err
		}
		err = a.db.QueryRowContext(ctx, `SELECT l.id, p.data FROM audit_personal p JOIN audit_log l ON l.id = p.log_id
			WHERE p.subject_ref = ? AND p.role = 'subject' AND l.resource_type = ? AND json_extract(p.data, '$.resource_id') IS ?
			ORDER BY l.timestamp DESC, l.rowid DESC LIMIT 1`, ref, r.resourceType, e.ResourceID).Scan(&latestID, &data)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return ReplayResponse{}, err
		}
		m := map[string]json.RawMessage{}
		_ = json.Unmarshal([]byte(data), &m)
		latestNew = jsonOrNull(m["new_value"])
	} else {
		var nv sql.NullString
		err = a.db.QueryRowContext(ctx, `SELECT id, new_value FROM audit_log WHERE resource_type = ? AND resource_id IS ?
			ORDER BY timestamp DESC, rowid DESC LIMIT 1`, r.resourceType, nsPtr(r.resourceID)).Scan(&latestID, &nv)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return ReplayResponse{}, err
		}
		latestNew = nsJSON(nv)
	}
	diverged := latestID != "" && latestID != logID && !jsonEqual(latestNew, e.NewValue)
	return ReplayResponse{LogID: logID, Timestamp: r.ts, ResourceStateAtTime: e.OldValue, HasDiverged: &diverged}, nil
}

// jsonEqual compares two JSON values by meaning, not by spelling.
func jsonEqual(x, y json.RawMessage) bool {
	var a, b interface{}
	if json.Unmarshal(x, &a) != nil || json.Unmarshal(y, &b) != nil {
		return string(x) == string(y)
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

// Search (GET /audit/search, admins only) returns entries whose action, resource type, values or metadata
// contain the query (only * is a wildcard), newest first. Values of an entry with a subject are searched in
// its 'subject' row, so erased data no longer matches.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-08/10). Touches: the database (read).
func (a *AuditLogger) Search(ctx context.Context, caller Caller, req SearchRequest) (SearchResponse, error) {
	if err := requireAdmin(caller); err != nil {
		return SearchResponse{}, err
	}
	if req.Query == "" {
		return SearchResponse{Results: []LogEntry{}}, nil
	}
	term := "%" + strings.ReplaceAll(likeEscaper.Replace(req.Query), "*", "%") + "%"
	like := ` LIKE ? ESCAPE '\'`
	q := "SELECT " + rowColumns + " FROM audit_log l WHERE (l.action" + like + " OR l.resource_type" + like +
		" OR l.resource_id" + like + " OR l.old_value" + like + " OR l.new_value" + like + " OR l.metadata" + like +
		" OR l.id IN (SELECT log_id FROM audit_personal WHERE role = 'subject' AND data" + like + "))"
	args := []interface{}{term, term, term, term, term, term, term}
	if req.ResourceType != nil {
		q += " AND l.resource_type = ?"
		args = append(args, *req.ResourceType)
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 50
	}
	q += " ORDER BY l.timestamp DESC, l.rowid DESC LIMIT ?"
	rs, err := a.db.QueryContext(ctx, q, append(args, limit)...)
	if err != nil {
		return SearchResponse{}, fmt.Errorf("search logs: %w", err)
	}
	rows, err := scanRows(rs)
	if err != nil {
		return SearchResponse{}, err
	}
	results, err := a.present(ctx, rows)
	return SearchResponse{Results: results}, err
}

// randomHex returns n random bytes in hex. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("auditlogging: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// generateID returns "log_" and 16 random bytes in hex. Touches: the system random source. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
func generateID() string {
	return "log_" + randomHex(16)
}

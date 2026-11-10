// Package idempotencykeys makes POST/PATCH safe to retry (IETF draft-ietf-httpapi-idempotency-key-header-07):
// the same request with the same key runs once, per scope.
//
// Phase B, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec IDEM-07/08/10/11, amended): records gain the
// status 'uncertain'. An operation error wrapping ErrOperationFailed frees the key; any other error (or a
// panic) marks it 'uncertain', and a retry gets 409 outcome_unknown without running, until the operator
// functions Release or Resolve settle it (each one conditional write). Only 'completed' records expire;
// an 'in_progress' record past expires_at is treated as uncertain. Before this, every error deleted the
// key (a timeout after the provider charged could charge twice) and in-progress records expired too.
// Touches: the injected store (memory or SQL).
package idempotencykeys

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ErrOperationFailed is the definite-failure signal: an operation returns an error wrapping it (checked
// with errors.Is) when it did nothing, e.g. a validation error or a provider decline. The key is then
// freed so a retry runs again (IDEM-08). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
var ErrOperationFailed = errors.New("operation failed")

// UncertainRecord is one row of the reconciliation work list (ListUncertain).
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
type UncertainRecord struct {
	Scope     string
	IdemKey   string
	CreatedAt int64
}

type IdempotencyError struct {
	Code    string
	Status  int
	Message string
}

func (e *IdempotencyError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

type HttpResponse struct {
	Status      int
	ContentType string
	Body        string
}

type OperationResult struct {
	Status int
	Body   string
}

type IdempotencyRecord struct {
	Scope              string
	IdemKey            string
	RequestFingerprint string
	Status             string
	ResponseStatus     *int
	ResponseBody       *string
	CreatedAt          int64
	ExpiresAt          int64
}

// Store keeps idempotency_records. Every method is one atomic step. TryClaim inserts a new in_progress
// record when the key is absent or holds a 'completed' record past expires_at, and never replaces an
// in_progress or uncertain one. Complete, Delete and MarkUncertain change only the in_progress record of
// that claim (createdAt). Release deletes, and Resolve completes, a record that is 'uncertain' or
// 'in_progress' past expires_at, in one conditional write, and report whether they did. ListUncertain
// lists those records oldest first (ties in insertion order). PurgeExpired deletes only expired
// 'completed' records.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-07/10/11): MarkUncertain, Release, Resolve
// and ListUncertain added; expiry limited to completed records.
type Store interface {
	TryClaim(rec IdempotencyRecord, now int64) (bool, error)
	Get(scope, idemKey string) (*IdempotencyRecord, error)
	Complete(scope, idemKey string, createdAt int64, responseStatus int, responseBody string) error
	Delete(scope, idemKey string, createdAt int64) error
	MarkUncertain(scope, idemKey string, createdAt int64) error
	Release(scope, idemKey string, now int64) (bool, error)
	Resolve(scope, idemKey string, now int64, responseStatus int, responseBody string, expiresAt int64) (bool, error)
	ListUncertain(now int64, limit int) ([]UncertainRecord, error)
	PurgeExpired(now int64) (int64, error)
}

type IdempotencyOptions struct {
	Clock           func() int64
	TtlSeconds      int64
	RequiredMethods []string
}

type IdempotencyService struct {
	store Store
	opts  IdempotencyOptions
}

func NewIdempotencyService(store Store, opts IdempotencyOptions) (*IdempotencyService, error) {
	if opts.TtlSeconds < 0 {
		return nil, &IdempotencyError{Code: "INVALID_OPTIONS", Status: 500, Message: "ttl_seconds must be >= 0"}
	}
	if opts.Clock == nil {
		opts.Clock = func() int64 { return time.Now().Unix() }
	}
	if opts.TtlSeconds == 0 {
		opts.TtlSeconds = 86400
	}
	if opts.RequiredMethods == nil {
		opts.RequiredMethods = []string{"POST", "PATCH"}
	}
	for i, m := range opts.RequiredMethods {
		opts.RequiredMethods[i] = asciiUpper(m)
	}
	return &IdempotencyService{store: store, opts: opts}, nil
}

// Handle runs operation at most once per (scope, key) and replays its stored response.
//
// In: scope (the authenticated client/user id, never request input), the Idempotency-Key, method, path,
// body and the operation. Out: the response, or an error from the store or the operation (re-raised).
// Check order (spec): missing key -> 400; different fingerprint -> 422 (even while the first is in
// progress); same fingerprint in progress -> 409; uncertain (or in_progress past expires_at) -> 409
// outcome_unknown, not run; completed -> the stored response; an expired completed record counts as absent.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-07, IDEM-10). Touches: the store.
func (s *IdempotencyService) Handle(scope, idempotencyKey, method, path, body string, operation func() (OperationResult, error)) (HttpResponse, error) {
	m := asciiUpper(method)
	if !s.IsRequired(m, path) {
		r, err := operation()
		if err != nil {
			return HttpResponse{}, err
		}
		if !checkResult(r) {
			return HttpResponse{}, &IdempotencyError{Code: "INVALID_OPERATION_RESULT", Status: 500, Message: "invalid operation result"}
		}
		return HttpResponse{Status: r.Status, ContentType: "application/json", Body: r.Body}, nil
	}
	if scope == "" {
		return HttpResponse{}, &IdempotencyError{Code: "SCOPE_REQUIRED", Status: 500, Message: "scope is required"}
	}
	if idempotencyKey == "" {
		return problemResponse(400, "IDEMPOTENCY_KEY_MISSING"), nil
	}
	if !validKey(idempotencyKey) {
		return problemResponse(400, "IDEMPOTENCY_KEY_INVALID"), nil
	}
	fp := computeFingerprint(m, path, body)
	now := s.opts.Clock()
	rec := IdempotencyRecord{
		Scope:              scope,
		IdemKey:            idempotencyKey,
		RequestFingerprint: fp,
		Status:             "in_progress",
		CreatedAt:          now,
		ExpiresAt:          now + s.opts.TtlSeconds,
	}
	for i := 0; i < 2; i++ {
		claimed, err := s.store.TryClaim(rec, now)
		if err != nil {
			return HttpResponse{}, err
		}
		if claimed {
			return s.runClaimed(rec, operation)
		}
		ex, err := s.store.Get(scope, idempotencyKey)
		if err != nil {
			return HttpResponse{}, err
		}
		if ex == nil || (ex.Status == "completed" && ex.ExpiresAt <= now) {
			continue // freed or expired between the claim and the read: claim again
		}
		if ex.RequestFingerprint != fp {
			return problemResponse(422, "IDEMPOTENCY_KEY_REUSED"), nil
		}
		switch {
		case ex.Status == "uncertain", ex.Status == "in_progress" && ex.ExpiresAt <= now:
			return problemResponse(409, "OUTCOME_UNKNOWN"), nil
		case ex.Status == "in_progress":
			return problemResponse(409, "REQUEST_IN_PROGRESS"), nil
		}
		return HttpResponse{Status: *ex.ResponseStatus, ContentType: "application/json", Body: *ex.ResponseBody}, nil
	}
	return problemResponse(409, "REQUEST_IN_PROGRESS"), nil
}

// runClaimed runs the operation for a record this call claimed and settles the record: a result ->
// 'completed'; an error wrapping ErrOperationFailed -> the record is deleted (IDEM-08); any other error
// or a panic -> 'uncertain' (IDEM-10), since the work may have happened. Errors and panics are re-raised.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: every error and panic used to delete the record.
// Touches: the store.
func (s *IdempotencyService) runClaimed(rec IdempotencyRecord, operation func() (OperationResult, error)) (HttpResponse, error) {
	settled := false
	defer func() {
		if !settled {
			if r := recover(); r != nil {
				_ = s.store.MarkUncertain(rec.Scope, rec.IdemKey, rec.CreatedAt)
				panic(r)
			}
		}
	}()
	r, err := operation()
	settled = true
	if err != nil {
		if errors.Is(err, ErrOperationFailed) {
			if derr := s.store.Delete(rec.Scope, rec.IdemKey, rec.CreatedAt); derr != nil {
				return HttpResponse{}, errors.Join(err, derr)
			}
			return HttpResponse{}, err
		}
		if merr := s.store.MarkUncertain(rec.Scope, rec.IdemKey, rec.CreatedAt); merr != nil {
			return HttpResponse{}, errors.Join(err, merr)
		}
		return HttpResponse{}, err
	}
	if !checkResult(r) {
		_ = s.store.MarkUncertain(rec.Scope, rec.IdemKey, rec.CreatedAt)
		return HttpResponse{}, &IdempotencyError{Code: "INVALID_OPERATION_RESULT", Status: 500, Message: "invalid operation result"}
	}
	err = s.store.Complete(rec.Scope, rec.IdemKey, rec.CreatedAt, r.Status, r.Body)
	if err != nil {
		return HttpResponse{}, err
	}
	return HttpResponse{Status: r.Status, ContentType: "application/json", Body: r.Body}, nil
}

// Release frees an 'uncertain' key (or an in_progress one past expires_at) once reconciliation shows the
// first attempt did nothing, so a retry runs the operation. Operator/reconciliation function: never an
// API route; scope is the stored record's scope (from ListUncertain), never request input.
// In: scope and key. Out: true if this call freed it; false (nothing changed) for any other state.
// One conditional write, so of two concurrent calls exactly one returns true.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-10, IDEM-11). Touches: the store.
func (s *IdempotencyService) Release(scope, idempotencyKey string) (bool, error) {
	return s.store.Release(scope, idempotencyKey, s.opts.Clock())
}

// Resolve stores the outcome reconciliation found for an 'uncertain' key (or an in_progress one past
// expires_at) as 'completed', with expires_at = now + the TTL (24 h by default), so a retry gets that
// stored response without running. Operator/reconciliation function, as Release.
// In: scope, key, the response status (100-599) and body. Out: true if this call resolved it; false
// (nothing changed) for any other state. One conditional write.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-11). Touches: the store.
func (s *IdempotencyService) Resolve(scope, idempotencyKey string, status int, body string) (bool, error) {
	if !checkResult(OperationResult{Status: status, Body: body}) {
		return false, &IdempotencyError{Code: "INVALID_OPERATION_RESULT", Status: 500, Message: "invalid response"}
	}
	now := s.opts.Clock()
	return s.store.Resolve(scope, idempotencyKey, now, status, body, now+s.opts.TtlSeconds)
}

// ListUncertain returns up to limit records awaiting reconciliation ('uncertain', or in_progress past
// expires_at), oldest first. Operator function, never an API route.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store (read).
func (s *IdempotencyService) ListUncertain(limit int) ([]UncertainRecord, error) {
	return s.store.ListUncertain(s.opts.Clock(), limit)
}

func (s *IdempotencyService) IsRequired(method, path string) bool {
	m := asciiUpper(method)
	for _, rm := range s.opts.RequiredMethods {
		if rm == m {
			return true
		}
	}
	return false
}

// PurgeExpired deletes expired 'completed' records; uncertain and in_progress records are kept.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
func (s *IdempotencyService) PurgeExpired() (int64, error) {
	return s.store.PurgeExpired(s.opts.Clock())
}

func ComputeFingerprint(method, path, body string) string {
	return computeFingerprint(method, path, body)
}

func computeFingerprint(m, p, b string) string {
	data := asciiUpper(m) + " " + p + "\n" + b
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

func validKey(k string) bool {
	if len(k) < 1 || len(k) > 255 {
		return false
	}
	for _, c := range []byte(k) {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

func checkResult(r OperationResult) bool {
	if r.Status < 100 || r.Status > 599 {
		return false
	}
	return r.Body != ""
}

func problemResponse(status int, code string) HttpResponse {
	var body string
	switch code {
	case "IDEMPOTENCY_KEY_MISSING":
		body = `{"type":"https://developer.example.com/problems/idempotency-key-missing","title":"Idempotency-Key is missing","detail":"This operation requires an Idempotency-Key request header."}`
	case "IDEMPOTENCY_KEY_INVALID":
		body = `{"type":"https://developer.example.com/problems/idempotency-key-invalid","title":"Idempotency-Key is invalid","detail":"An Idempotency-Key must be 1 to 255 printable ASCII characters."}`
	case "IDEMPOTENCY_KEY_REUSED":
		body = `{"type":"https://developer.example.com/problems/idempotency-key-reused","title":"Idempotency-Key is already used","detail":"This Idempotency-Key was already used with a different request payload."}`
	case "REQUEST_IN_PROGRESS":
		body = `{"type":"https://developer.example.com/problems/idempotency-request-outstanding","title":"A request is outstanding for this Idempotency-Key","detail":"A request with the same Idempotency-Key is still being processed. Retry later."}`
	case "OUTCOME_UNKNOWN": // added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-07, IDEM-10); same body as Python
		body = `{"type":"https://developer.example.com/problems/outcome_unknown","title":"Outcome unknown","detail":"The first request with this Idempotency-Key ended without a known outcome; it will not be run again until it is reconciled."}`
	}
	return HttpResponse{Status: status, ContentType: "application/problem+json", Body: body}
}

// InMemoryStore is the Store for tests and single-process use. seq keeps insertion order for
// ListUncertain ties. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (uncertain state).
type InMemoryStore struct {
	mu   sync.Mutex
	rows map[string]*IdempotencyRecord
	seqs map[string]int64
	seq  int64
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		rows: make(map[string]*IdempotencyRecord),
		seqs: make(map[string]int64),
	}
}

func (s *InMemoryStore) key(scope, idemKey string) string {
	return scope + "\x00" + idemKey
}

// awaitsReconciliation reports whether a record is 'uncertain' or an in_progress record past expires_at.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func awaitsReconciliation(rec *IdempotencyRecord, now int64) bool {
	return rec.Status == "uncertain" || (rec.Status == "in_progress" && rec.ExpiresAt <= now)
}

// TryClaim inserts rec unless a record exists that is not an expired completed one.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: only completed records expire. Touches: memory.
func (s *InMemoryStore) TryClaim(rec IdempotencyRecord, now int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.key(rec.Scope, rec.IdemKey)
	if ex, ok := s.rows[k]; ok && !(ex.Status == "completed" && ex.ExpiresAt <= now) {
		return false, nil
	}
	cp := rec
	s.rows[k] = &cp
	s.seq++
	s.seqs[k] = s.seq
	return true, nil
}

// Get returns a copy of the record, or nil. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: a copy,
// so a caller never reads a record another goroutine is changing. Touches: memory.
func (s *InMemoryStore) Get(scope, idemKey string) (*IdempotencyRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.rows[s.key(scope, idemKey)]; ok {
		cp := *rec
		return &cp, nil
	}
	return nil, nil
}

func (s *InMemoryStore) Complete(scope, idemKey string, createdAt int64, responseStatus int, responseBody string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ex, ok := s.rows[s.key(scope, idemKey)]
	if !ok || ex.CreatedAt != createdAt || ex.Status != "in_progress" {
		return nil
	}
	ex.Status = "completed"
	ex.ResponseStatus = &responseStatus
	ex.ResponseBody = &responseBody
	return nil
}

func (s *InMemoryStore) Delete(scope, idemKey string, createdAt int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.key(scope, idemKey)
	ex, ok := s.rows[k]
	if !ok || ex.CreatedAt != createdAt || ex.Status != "in_progress" {
		return nil
	}
	delete(s.rows, k)
	delete(s.seqs, k)
	return nil
}

// MarkUncertain sets the claim's in_progress record to 'uncertain'.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-10). Touches: memory.
func (s *InMemoryStore) MarkUncertain(scope, idemKey string, createdAt int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ex, ok := s.rows[s.key(scope, idemKey)]
	if ok && ex.CreatedAt == createdAt && ex.Status == "in_progress" {
		ex.Status = "uncertain"
	}
	return nil
}

// Release deletes a record awaiting reconciliation; false for anything else.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (s *InMemoryStore) Release(scope, idemKey string, now int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.key(scope, idemKey)
	ex, ok := s.rows[k]
	if !ok || !awaitsReconciliation(ex, now) {
		return false, nil
	}
	delete(s.rows, k)
	delete(s.seqs, k)
	return true, nil
}

// Resolve completes a record awaiting reconciliation with the given response; false for anything else.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (s *InMemoryStore) Resolve(scope, idemKey string, now int64, responseStatus int, responseBody string, expiresAt int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ex, ok := s.rows[s.key(scope, idemKey)]
	if !ok || !awaitsReconciliation(ex, now) {
		return false, nil
	}
	ex.Status = "completed"
	ex.ResponseStatus = &responseStatus
	ex.ResponseBody = &responseBody
	ex.ExpiresAt = expiresAt
	return true, nil
}

// ListUncertain lists records awaiting reconciliation by created_at, then insertion order.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory (read).
func (s *InMemoryStore) ListUncertain(now int64, limit int) ([]UncertainRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	type row struct {
		r   UncertainRecord
		seq int64
	}
	var rows []row
	for k, rec := range s.rows {
		if awaitsReconciliation(rec, now) {
			rows = append(rows, row{UncertainRecord{rec.Scope, rec.IdemKey, rec.CreatedAt}, s.seqs[k]})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].r.CreatedAt != rows[j].r.CreatedAt {
			return rows[i].r.CreatedAt < rows[j].r.CreatedAt
		}
		return rows[i].seq < rows[j].seq
	})
	out := []UncertainRecord{}
	for _, r := range rows {
		if limit > 0 && len(out) == limit {
			break
		}
		out = append(out, r.r)
	}
	return out, nil
}

// PurgeExpired deletes expired completed records. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP:
// uncertain and in_progress records are kept. Touches: memory.
func (s *InMemoryStore) PurgeExpired(now int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int64
	for k, rec := range s.rows {
		if rec.Status == "completed" && rec.ExpiresAt <= now {
			delete(s.rows, k)
			delete(s.seqs, k)
			count++
		}
	}
	return count, nil
}

type SqlStore struct {
	db *sql.DB
}

func NewSqlStore(db *sql.DB) *SqlStore {
	return &SqlStore{db: db}
}

func (s *SqlStore) Migrate() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS idempotency_records (scope TEXT NOT NULL, idem_key TEXT NOT NULL, request_fingerprint TEXT NOT NULL, status TEXT NOT NULL CHECK (status IN ('in_progress', 'completed', 'uncertain')), response_status INTEGER NULL, response_body TEXT NULL, created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL, PRIMARY KEY (scope, idem_key))`)
	if err != nil {
		return &IdempotencyError{Code: "STORE_ERROR", Status: 500, Message: err.Error()}
	}
	_, err = s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_idempotency_records_expires_at ON idempotency_records (expires_at)`)
	if err != nil {
		return &IdempotencyError{Code: "STORE_ERROR", Status: 500, Message: err.Error()}
	}
	return nil
}

func (s *SqlStore) TryClaim(rec IdempotencyRecord, now int64) (bool, error) {
	res, err := s.db.Exec(`INSERT INTO idempotency_records (scope, idem_key, request_fingerprint, status, response_status, response_body, created_at, expires_at) VALUES (?, ?, ?, 'in_progress', NULL, NULL, ?, ?) ON CONFLICT (scope, idem_key) DO UPDATE SET request_fingerprint = excluded.request_fingerprint, status = 'in_progress', response_status = NULL, response_body = NULL, created_at = excluded.created_at, expires_at = excluded.expires_at WHERE idempotency_records.status = 'completed' AND idempotency_records.expires_at <= ?`,
		rec.Scope, rec.IdemKey, rec.RequestFingerprint, rec.CreatedAt, rec.ExpiresAt, now)
	if err != nil {
		return false, &IdempotencyError{Code: "STORE_ERROR", Status: 500, Message: err.Error()}
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, &IdempotencyError{Code: "STORE_ERROR", Status: 500, Message: err.Error()}
	}
	return affected == 1, nil
}

func (s *SqlStore) Get(scope, idemKey string) (*IdempotencyRecord, error) {
	row := s.db.QueryRow(`SELECT scope, idem_key, request_fingerprint, status, response_status, response_body, created_at, expires_at FROM idempotency_records WHERE scope = ? AND idem_key = ?`, scope, idemKey)
	var rec IdempotencyRecord
	var responseStatus sql.NullInt64
	var responseBody sql.NullString
	err := row.Scan(&rec.Scope, &rec.IdemKey, &rec.RequestFingerprint, &rec.Status, &responseStatus, &responseBody, &rec.CreatedAt, &rec.ExpiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, &IdempotencyError{Code: "STORE_ERROR", Status: 500, Message: err.Error()}
	}
	if responseStatus.Valid {
		rs := int(responseStatus.Int64)
		rec.ResponseStatus = &rs
	}
	if responseBody.Valid {
		rb := responseBody.String
		rec.ResponseBody = &rb
	}
	return &rec, nil
}

func (s *SqlStore) Complete(scope, idemKey string, createdAt int64, responseStatus int, responseBody string) error {
	_, err := s.db.Exec(`UPDATE idempotency_records SET status = 'completed', response_status = ?, response_body = ? WHERE scope = ? AND idem_key = ? AND created_at = ? AND status = 'in_progress'`,
		responseStatus, responseBody, scope, idemKey, createdAt)
	if err != nil {
		return &IdempotencyError{Code: "STORE_ERROR", Status: 500, Message: err.Error()}
	}
	return nil
}

func (s *SqlStore) Delete(scope, idemKey string, createdAt int64) error {
	_, err := s.db.Exec(`DELETE FROM idempotency_records WHERE scope = ? AND idem_key = ? AND created_at = ? AND status = 'in_progress'`,
		scope, idemKey, createdAt)
	if err != nil {
		return &IdempotencyError{Code: "STORE_ERROR", Status: 500, Message: err.Error()}
	}
	return nil
}

// MarkUncertain sets the claim's in_progress row to 'uncertain' (one conditional UPDATE).
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-10). Touches: database.
func (s *SqlStore) MarkUncertain(scope, idemKey string, createdAt int64) error {
	_, err := s.db.Exec(`UPDATE idempotency_records SET status = 'uncertain' WHERE scope = ? AND idem_key = ? AND created_at = ? AND status = 'in_progress'`,
		scope, idemKey, createdAt)
	if err != nil {
		return &IdempotencyError{Code: "STORE_ERROR", Status: 500, Message: err.Error()}
	}
	return nil
}

// Release deletes a row awaiting reconciliation in ONE conditional DELETE; true if it did.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-10). Touches: database.
func (s *SqlStore) Release(scope, idemKey string, now int64) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM idempotency_records WHERE scope = ? AND idem_key = ? AND (status = 'uncertain' OR (status = 'in_progress' AND expires_at <= ?))`,
		scope, idemKey, now)
	return oneRow(res, err)
}

// Resolve completes a row awaiting reconciliation in ONE conditional UPDATE; true if it did.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-11). Touches: database.
func (s *SqlStore) Resolve(scope, idemKey string, now int64, responseStatus int, responseBody string, expiresAt int64) (bool, error) {
	res, err := s.db.Exec(`UPDATE idempotency_records SET status = 'completed', response_status = ?, response_body = ?, expires_at = ? WHERE scope = ? AND idem_key = ? AND (status = 'uncertain' OR (status = 'in_progress' AND expires_at <= ?))`,
		responseStatus, responseBody, expiresAt, scope, idemKey, now)
	return oneRow(res, err)
}

// ListUncertain lists rows awaiting reconciliation, oldest first (rowid breaks ties: insertion order).
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
func (s *SqlStore) ListUncertain(now int64, limit int) ([]UncertainRecord, error) {
	if limit <= 0 {
		limit = -1
	}
	rows, err := s.db.Query(`SELECT scope, idem_key, created_at FROM idempotency_records WHERE status = 'uncertain' OR (status = 'in_progress' AND expires_at <= ?) ORDER BY created_at, rowid LIMIT ?`, now, limit)
	if err != nil {
		return nil, &IdempotencyError{Code: "STORE_ERROR", Status: 500, Message: err.Error()}
	}
	defer rows.Close()
	out := []UncertainRecord{}
	for rows.Next() {
		var r UncertainRecord
		if err := rows.Scan(&r.Scope, &r.IdemKey, &r.CreatedAt); err != nil {
			return nil, &IdempotencyError{Code: "STORE_ERROR", Status: 500, Message: err.Error()}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// oneRow turns an Exec result into "exactly one row changed". Added 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func oneRow(res sql.Result, err error) (bool, error) {
	if err != nil {
		return false, &IdempotencyError{Code: "STORE_ERROR", Status: 500, Message: err.Error()}
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, &IdempotencyError{Code: "STORE_ERROR", Status: 500, Message: err.Error()}
	}
	return n == 1, nil
}

// PurgeExpired deletes expired completed rows only. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: database.
func (s *SqlStore) PurgeExpired(now int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM idempotency_records WHERE status = 'completed' AND expires_at <= ?`, now)
	if err != nil {
		return 0, &IdempotencyError{Code: "STORE_ERROR", Status: 500, Message: err.Error()}
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, &IdempotencyError{Code: "STORE_ERROR", Status: 500, Message: err.Error()}
	}
	return affected, nil
}
// Package compliance is the AOI Systems Library data-export and account-deletion template (GDPR / CCPA):
// a user exports their data as JSON or CSV through a signed 7-day link, and deletes their account through
// an emailed, single-use confirmation token, a 30-day grace period (none for a statutory request) and a
// cascade that ends by asking the audit system to erase the user's personal data.
//
// Phase B rewrite, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec EXPORT-05/09/12/13/14, amended after an
// independent security review). Before it: any non-empty string confirmed any deletion request, nobody
// checked whose request was confirmed or cancelled, every reason got 30 days, the cascade kept nothing
// apart (it deleted the user's audit trail), the export link was an unsigned URL and no email was sent.
// Now: the token is 32 random bytes kept only as its SHA-256, single use, 24 hours, bound to its deletion
// id and compared in constant time; confirm and cancel act only on the caller's own request (else
// ErrNotFound); statutory reasons have no grace and confirm runs the cascade at once; the cascade deletes
// the user's rows, logs 'user_deleted_cascade', then calls the injected AuditEraser LAST, all or nothing;
// export links are HMAC-signed and expire after 7 days. Touches: memory only; email and the audit system
// through injected interfaces.
package compliance

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Errors returned to the HTTP layer: ErrNotFound -> 404, ErrInvalidToken -> 400/403, the rest -> 400/409.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
var (
	ErrNotFound          = errors.New("not_found")
	ErrInvalidToken      = errors.New("invalid_confirmation_token")
	ErrInvalidReason     = errors.New("invalid_reason")
	ErrUnsupportedFormat = errors.New("unsupported_format")
	ErrNotPending        = errors.New("deletion_not_pending")
	ErrGraceElapsed      = errors.New("grace_period_elapsed")
	ErrLinkExpired       = errors.New("link_expired")
	ErrInvalidLink       = errors.New("invalid_link")
	ErrNotConfigured     = errors.New("not_configured")
)

const (
	exportLinkTTL = 7 * 24 * time.Hour
	gracePeriod   = 30 * 24 * time.Hour
	tokenTTL      = 24 * time.Hour
)

// Mailer sends the two emails this system needs (no network in tests: they pass a fake).
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-03, EXPORT-09). Touches: network in production.
type Mailer interface {
	SendExportReady(userID int, downloadURL string) error
	SendDeletionConfirmation(userID int, deletionID, token string) error
}

// AuditEraser is the audit system's erase_subject(user_id) (audit_logging.md), injected like the audit
// logger so tests pass a fake. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-13).
type AuditEraser interface {
	EraseSubject(userID int) error
}

// Options configures NewComplianceServiceWith. SigningKey signs export links (>= 32 bytes; a random key
// when empty). Now is the clock (nil = time.Now). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
type Options struct {
	Mailer     Mailer
	Eraser     AuditEraser
	SigningKey []byte
	Now        func() time.Time
	BaseURL    string
}

// ExportRequest represents a request to export a user's data. Content is the generated file.
type ExportRequest struct {
	ID             string
	UserID         int
	RequestedAt    time.Time
	Status         string // "pending", "completed", "failed"
	Format         string // "json" or "csv"
	FileURL        string
	CompletedAt    *time.Time
	ExpiresAt      *time.Time
	DataCategories []string
	EmailSent      bool
	Content        []byte
}

// DeletionRequest is one row of deletion_requests. UserID is nil once the deletion completed (EXPORT-13),
// so the row cannot re-identify erased audit entries. WillDeleteAt is requested_at + 30 days for
// user_requested / other and requested_at for a statutory reason. DeletedAt is set on completion.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: DeletedAt used to hold the scheduled time.
type DeletionRequest struct {
	ID           string
	UserID       *int
	RequestedAt  time.Time
	Status       string // "pending", "approved", "completed", "cancelled"
	Reason       string
	WillDeleteAt time.Time
	DeletedAt    *time.Time

	tokenHash    string
	tokenExpires time.Time
	tokenUsed    bool
}

// AuditLog records an action performed in the system. WhyChain holds the decision points.
type AuditLog struct {
	Action    string
	UserID    int
	Timestamp time.Time
	Details   string
	WhyChain  []string
}

// ComplianceService provides methods to handle export and deletion requests.
type ComplianceService struct {
	mu        sync.Mutex
	exports   map[string]*ExportRequest
	deletions map[string]*DeletionRequest
	order     []string // export and deletion ids in creation order, for listings
	auditLogs []AuditLog
	nowFunc   func() time.Time
	mailer    Mailer
	eraser    AuditEraser
	key       []byte
	baseURL   string
	// Simulated user data stores (the cascade deletes them)
	profiles     map[int]map[string]string
	sessions     map[int][]string
	apiKeys      map[int][]string
	activity     map[int][]string
	files        map[int][]string
	preferences  map[int]bool
	transactions map[int][]string
	// auditTrail is the audit system's view of the user: the cascade never touches it (EXPORT-08); only
	// the AuditEraser does.
	auditTrail map[int][]string
}

// NewComplianceService creates a service with a random signing key and no mailer or eraser: export and
// deletion then fail with ErrNotConfigured rather than pretend. Changed 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP.
func NewComplianceService() *ComplianceService {
	s, _ := NewComplianceServiceWith(Options{})
	return s
}

// NewComplianceServiceWith creates a service from Options. Out: the service, or an error for a signing
// key shorter than 32 bytes. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: crypto/rand.
func NewComplianceServiceWith(o Options) (*ComplianceService, error) {
	key := o.SigningKey
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
	} else if len(key) < 32 {
		return nil, errors.New("signing key must be at least 32 bytes")
	}
	base := o.BaseURL
	if base == "" {
		base = "https://files.example.com/exports/"
	}
	return &ComplianceService{
		exports:      make(map[string]*ExportRequest),
		deletions:    make(map[string]*DeletionRequest),
		nowFunc:      o.Now,
		mailer:       o.Mailer,
		eraser:       o.Eraser,
		key:          key,
		baseURL:      base,
		profiles:     make(map[int]map[string]string),
		sessions:     make(map[int][]string),
		apiKeys:      make(map[int][]string),
		activity:     make(map[int][]string),
		files:        make(map[int][]string),
		preferences:  make(map[int]bool),
		transactions: make(map[int][]string),
		auditTrail:   make(map[int][]string),
	}, nil
}

func (s *ComplianceService) now() time.Time {
	if s.nowFunc != nil {
		return s.nowFunc()
	}
	return time.Now()
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// log appends an audit entry; the caller holds s.mu.
func (s *ComplianceService) log(action string, userID int, details string, why ...string) {
	s.auditLogs = append(s.auditLogs, AuditLog{Action: action, UserID: userID, Timestamp: s.now(), Details: details, WhyChain: why})
}

// ---------- Export ----------

var exportCategories = []string{"profile", "sessions", "activity", "files", "preferences", "transactions", "audit_trail"}

// buildExport renders the user's data in every category as JSON or CSV (category,value rows). The caller
// holds s.mu. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-01/02: no file was generated).
func (s *ComplianceService) buildExport(userID int, format string) ([]byte, error) {
	data := map[string]interface{}{
		"profile":      s.profiles[userID],
		"sessions":     s.sessions[userID],
		"activity":     s.activity[userID],
		"files":        s.files[userID],
		"preferences":  map[string]bool{"enabled": s.preferences[userID]},
		"transactions": s.transactions[userID],
		"audit_trail":  s.auditTrail[userID],
	}
	if format == "json" {
		return json.Marshal(data)
	}
	var b strings.Builder
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"category", "value"})
	for _, cat := range exportCategories {
		switch v := data[cat].(type) {
		case []string:
			for _, item := range v {
				_ = w.Write([]string{cat, item})
			}
		case map[string]string:
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				_ = w.Write([]string{cat, k + "=" + v[k]})
			}
		case map[string]bool:
			_ = w.Write([]string{cat, "enabled=" + strconv.FormatBool(v["enabled"])})
		}
	}
	w.Flush()
	return []byte(b.String()), w.Error()
}

// sign is the HMAC-SHA256 of "<export id>.<expiry unix>" in hex.
func (s *ComplianceService) sign(id string, exp int64) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(id + "." + strconv.FormatInt(exp, 10)))
	return hex.EncodeToString(m.Sum(nil))
}

// RequestExport generates the caller's export, signs a 7-day download link and emails it.
//
// In: the verified caller's user id and the format ("json" or "csv"). Out: the completed request, or
// ErrUnsupportedFormat / ErrNotConfigured (no mailer) / the mailer's error (the request is then 'failed').
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-01..04): the file is really generated, the
// link is HMAC-signed and the email really sent. Touches: memory, the mailer.
func (s *ComplianceService) RequestExport(userID int, format string) (*ExportRequest, error) {
	if format != "json" && format != "csv" {
		return nil, ErrUnsupportedFormat
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mailer == nil {
		return nil, ErrNotConfigured
	}
	id, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	now := s.now()
	exp := now.Add(exportLinkTTL)
	content, err := s.buildExport(userID, format)
	if err != nil {
		return nil, err
	}
	req := &ExportRequest{
		ID: id, UserID: userID, RequestedAt: now, Status: "completed", Format: format, ExpiresAt: &exp,
		DataCategories: append([]string(nil), exportCategories...), Content: content,
		FileURL: fmt.Sprintf("%s%s?expires=%d&sig=%s", s.baseURL, id, exp.Unix(), s.sign(id, exp.Unix())),
	}
	completed := now
	req.CompletedAt = &completed
	s.exports[id] = req
	s.order = append(s.order, id)
	s.log("data_export_requested", userID, "format="+format, "format_valid", "export_generated", "link_signed")
	if err := s.mailer.SendExportReady(userID, req.FileURL); err != nil {
		req.Status = "failed"
		return req, err
	}
	req.EmailSent = true
	return req, nil
}

// Download serves an export file for a signed link: the signature is checked in constant time, then the
// expiry. In: the URL from the email. Out: the file, or ErrInvalidLink / ErrLinkExpired / ErrNotFound.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-04). Touches: memory (read).
func (s *ComplianceService) Download(link string) ([]byte, error) {
	u, err := url.Parse(link)
	if err != nil || !strings.HasPrefix(link, s.baseURL) {
		return nil, ErrInvalidLink
	}
	id := strings.TrimPrefix(u.Path, strings.TrimSuffix(mustPath(s.baseURL), "/")+"/")
	exp, err := strconv.ParseInt(u.Query().Get("expires"), 10, 64)
	if err != nil {
		return nil, ErrInvalidLink
	}
	if !hmac.Equal([]byte(u.Query().Get("sig")), []byte(s.sign(id, exp))) {
		return nil, ErrInvalidLink
	}
	if s.now().Unix() >= exp {
		return nil, ErrLinkExpired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.exports[id]
	if !ok || req.Status != "completed" {
		return nil, ErrNotFound
	}
	return req.Content, nil
}

func mustPath(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	return u.Path
}

// GetExportStatus returns the caller's export request; another user's is ErrNotFound.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: it returned any id to anyone. Touches: memory.
func (s *ComplianceService) GetExportStatus(callerUserID int, exportID string) (*ExportRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req, ok := s.exports[exportID]; ok && req.UserID == callerUserID {
		return req, nil
	}
	return nil, ErrNotFound
}

// ---------- Deletion ----------

// isStatutory reports a statutory erasure reason (no grace period). Added 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-12).
func isStatutory(reason string) bool {
	return reason == "gdpr_request" || reason == "gdpr_right_to_be_forgotten"
}

// RequestDeletion records the caller's deletion request and emails its confirmation token. Nothing is
// deleted until ConfirmDeletion.
//
// In: the verified caller's user id and the reason (user_requested, gdpr_request,
// gdpr_right_to_be_forgotten or other). Out: the pending request (WillDeleteAt = requested_at + 30 days,
// or requested_at for a statutory reason), or ErrInvalidReason / ErrNotConfigured / the mailer's error.
// The token is 32 random bytes; only its SHA-256 is kept, valid 24 h, bound to this request.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-05, 09, 12, 14). Touches: memory, mailer.
func (s *ComplianceService) RequestDeletion(userID int, reason string) (*DeletionRequest, error) {
	switch reason {
	case "user_requested", "gdpr_request", "gdpr_right_to_be_forgotten", "other":
	default:
		return nil, ErrInvalidReason
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mailer == nil {
		return nil, ErrNotConfigured
	}
	id, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	token, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	now := s.now()
	will := now.Add(gracePeriod)
	if isStatutory(reason) {
		will = now
	}
	uid := userID
	req := &DeletionRequest{
		ID: id, UserID: &uid, RequestedAt: now, Status: "pending", Reason: reason, WillDeleteAt: will,
		tokenHash: sha256Hex(token), tokenExpires: now.Add(tokenTTL),
	}
	if err := s.mailer.SendDeletionConfirmation(userID, id, token); err != nil {
		return nil, err
	}
	s.deletions[id] = req
	s.order = append(s.order, id)
	s.log("deletion_requested", userID, "reason="+reason, "reason_valid", "grace_period", "confirmation_sent")
	return req, nil
}

// ownDeletion returns the caller's own request or ErrNotFound; the caller holds s.mu.
func (s *ComplianceService) ownDeletion(callerUserID int, deletionID string) (*DeletionRequest, error) {
	req, ok := s.deletions[deletionID]
	if !ok || req.UserID == nil || *req.UserID != callerUserID {
		return nil, ErrNotFound
	}
	return req, nil
}

// ConfirmDeletion confirms the caller's own deletion request with the emailed token.
//
// In: the verified caller's user id, the deletion id and the token. Out: the request with WillDeleteAt
// as deletion_scheduled_for; for a statutory reason the cascade has already run (status 'completed',
// DeletedAt = now). Errors: ErrNotFound (no such request, or another user's), ErrNotPending,
// ErrInvalidToken (wrong, reused or older than 24 h; compared in constant time).
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-09, 12, 14): any non-empty token used to be
// accepted for any request, and the token was written to the audit log. Touches: memory, the eraser.
func (s *ComplianceService) ConfirmDeletion(callerUserID int, deletionID, token string) (*DeletionRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, err := s.ownDeletion(callerUserID, deletionID)
	if err != nil {
		return nil, err
	}
	if req.Status != "pending" {
		return nil, ErrNotPending
	}
	if req.tokenUsed || !s.now().Before(req.tokenExpires) ||
		subtle.ConstantTimeCompare([]byte(sha256Hex(token)), []byte(req.tokenHash)) != 1 {
		return nil, ErrInvalidToken
	}
	req.tokenUsed = true
	req.Status = "approved"
	s.log("deletion_confirmed", callerUserID, "deletion_id="+deletionID, "token_valid", "owner_matches")
	if isStatutory(req.Reason) {
		if err := s.cascade(req); err != nil {
			return nil, err
		}
	}
	return req, nil
}

// CancelDeletion cancels the caller's own pending or approved request before WillDeleteAt.
// Out: the request, or ErrNotFound (another user's too), ErrNotPending or ErrGraceElapsed.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-06, 14): anyone could cancel any request.
// Touches: memory.
func (s *ComplianceService) CancelDeletion(callerUserID int, deletionID string) (*DeletionRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, err := s.ownDeletion(callerUserID, deletionID)
	if err != nil {
		return nil, err
	}
	if req.Status != "pending" && req.Status != "approved" {
		return nil, ErrNotPending
	}
	if !s.now().Before(req.WillDeleteAt) {
		return nil, ErrGraceElapsed
	}
	req.Status = "cancelled"
	s.log("deletion_cancelled", callerUserID, "deletion_id="+deletionID, "owner_matches", "within_grace")
	return req, nil
}

// PerformDueDeletions runs the cascade for every approved request whose WillDeleteAt has passed (the
// scheduled job). Out: how many completed, or the first error. Added 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory, the eraser.
func (s *ComplianceService) PerformDueDeletions() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, id := range s.order {
		req, ok := s.deletions[id]
		if !ok || req.Status != "approved" || s.now().Before(req.WillDeleteAt) {
			continue
		}
		if err := s.cascade(req); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// PerformDeletionNow runs the cascade for one approved request whose WillDeleteAt has passed.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: uses the cascade below. Touches: memory, eraser.
func (s *ComplianceService) PerformDeletionNow(deletionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.deletions[deletionID]
	if !ok {
		return ErrNotFound
	}
	if req.Status != "approved" {
		return errors.New("deletion not approved")
	}
	if s.now().Before(req.WillDeleteAt) {
		return errors.New("deletion time not reached")
	}
	return s.cascade(req)
}

// cascade deletes the user, all or nothing, in the spec's order: (1) delete the user's rows (profile,
// sessions, API keys, activity, files, preferences, transactions, and their export requests and files),
// never the audit trail; (2) log 'user_deleted_cascade' with the user as subject; (3) call the audit
// eraser's EraseSubject(user_id) LAST. If the eraser fails, everything is put back and the error returned.
// On success the request is 'completed', DeletedAt = now and UserID = nil; nothing logs the user after.
// The caller holds s.mu. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-07, 08, 13).
// Touches: memory, the audit eraser.
func (s *ComplianceService) cascade(req *DeletionRequest) error {
	if s.eraser == nil {
		return ErrNotConfigured
	}
	uid := *req.UserID
	type snapshot struct {
		profile                                         map[string]string
		sessions, apiKeys, activity, files, transactions []string
		pref, hadPref                                    bool
		exports                                          map[string]*ExportRequest
		logs                                             int
	}
	snap := snapshot{profile: s.profiles[uid], sessions: s.sessions[uid], apiKeys: s.apiKeys[uid], activity: s.activity[uid],
		files: s.files[uid], transactions: s.transactions[uid], exports: map[string]*ExportRequest{}, logs: len(s.auditLogs)}
	snap.pref, snap.hadPref = s.preferences[uid]
	for id, e := range s.exports {
		if e.UserID == uid {
			snap.exports[id] = e
		}
	}
	counts := map[string]int{"sessions": len(snap.sessions), "api_keys": len(snap.apiKeys), "activity": len(snap.activity),
		"files": len(snap.files), "transactions": len(snap.transactions), "exports": len(snap.exports)}

	delete(s.profiles, uid)
	delete(s.sessions, uid)
	delete(s.apiKeys, uid)
	delete(s.activity, uid)
	delete(s.files, uid)
	delete(s.preferences, uid)
	delete(s.transactions, uid)
	for id := range snap.exports {
		delete(s.exports, id)
	}
	detail, _ := json.Marshal(counts)
	s.log("user_deleted_cascade", uid, string(detail), "approved", "grace_elapsed", "rows_deleted")

	if err := s.eraser.EraseSubject(uid); err != nil {
		if snap.profile != nil {
			s.profiles[uid] = snap.profile
		}
		restore := func(m map[int][]string, v []string) {
			if v != nil {
				m[uid] = v
			}
		}
		restore(s.sessions, snap.sessions)
		restore(s.apiKeys, snap.apiKeys)
		restore(s.activity, snap.activity)
		restore(s.files, snap.files)
		restore(s.transactions, snap.transactions)
		if snap.hadPref {
			s.preferences[uid] = snap.pref
		}
		for id, e := range snap.exports {
			s.exports[id] = e
		}
		s.auditLogs = s.auditLogs[:snap.logs]
		return fmt.Errorf("audit erasure failed, deletion rolled back: %w", err)
	}
	now := s.now()
	req.Status = "completed"
	req.DeletedAt = &now
	req.UserID = nil
	return nil
}

// ListExports returns export requests (admin listing), optionally filtered, in creation order. The
// HTTP layer restricts it to admins (permissions_rbac require_admin). Changed 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP: creation order instead of map order. Touches: memory (read).
func (s *ComplianceService) ListExports(userID *int, status *string) []*ExportRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*ExportRequest
	for _, id := range s.order {
		r, ok := s.exports[id]
		if !ok || (userID != nil && r.UserID != *userID) || (status != nil && r.Status != *status) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// ListDeletions returns deletion requests (admin listing), optionally filtered, in creation order; a
// completed request no longer matches a user filter (its user id is gone). Changed 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory (read).
func (s *ComplianceService) ListDeletions(userID *int, status *string) []*DeletionRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*DeletionRequest
	for _, id := range s.order {
		r, ok := s.deletions[id]
		if !ok || (userID != nil && (r.UserID == nil || *r.UserID != *userID)) || (status != nil && r.Status != *status) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// GetAuditLogs returns a copy of all audit logs.
func (s *ComplianceService) GetAuditLogs() []AuditLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	cpy := make([]AuditLog, len(s.auditLogs))
	copy(cpy, s.auditLogs)
	return cpy
}

// ---------- Simulated user data helpers (used by tests) ----------

// SetProfile stores profile fields for a user. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
func (s *ComplianceService) SetProfile(userID int, fields map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.profiles[userID] = fields
}

// AddSession records a session for a user.
func (s *ComplianceService) AddSession(userID int, sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[userID] = append(s.sessions[userID], sessionID)
}

// AddAPIKey records an API key for a user. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-07).
func (s *ComplianceService) AddAPIKey(userID int, keyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKeys[userID] = append(s.apiKeys[userID], keyID)
}

// AddActivity records an activity entry for a user. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
func (s *ComplianceService) AddActivity(userID int, entry string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activity[userID] = append(s.activity[userID], entry)
}

// AddFile records a file for a user.
func (s *ComplianceService) AddFile(userID int, fileName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[userID] = append(s.files[userID], fileName)
}

// SetPreference sets a boolean preference for a user.
func (s *ComplianceService) SetPreference(userID int, value bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preferences[userID] = value
}

// AddTransaction records a transaction for a user.
func (s *ComplianceService) AddTransaction(userID int, txnID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.transactions[userID] = append(s.transactions[userID], txnID)
}

// AddAuditTrailEntry records an audit trail entry for a user.
func (s *ComplianceService) AddAuditTrailEntry(userID int, entry string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditTrail[userID] = append(s.auditTrail[userID], entry)
}

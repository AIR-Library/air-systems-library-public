// Package api_keys is the AOI Systems Library template for API keys and service accounts: scoped
// keys (sk_live_/sk_test_), bcrypt-hashed at rest, per-key hourly rate limits, revocation, rotation
// with a 24-hour grace period, expiry, per-endpoint usage logging and an admin audit listing.
//
// Repair 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): the suite did not compile (rand and
// strconv not imported, APIKey.ScopesJSON and CreateAPIKeyResponse.Name missing), its tests needed a
// live PostgreSQL and Redis on localhost, rotation selected nine columns into ten targets and wrote a
// column that did not exist, unknown endpoints needed no scope at all, and usage was logged from a
// goroutine the stats query raced. This version runs on SQLite (modernc.org/sqlite, pure Go), puts
// the rate-limit counter behind the RateLimiter interface (MemoryRateLimiter here; a Redis INCR +
// EXPIRE adapter satisfies the same interface in production), finds a key by an indexed public
// prefix and then verifies the bcrypt hash, denies endpoints that map to no scope unless the key
// holds "*", and keeps one key id across rotation. Behaviour follows the passing JavaScript template
// and TIER_2_MASTER_SPEC_6SYSTEMS.txt, system 5.
// Touches: SQLite database (api_keys, api_key_usage), the OS random source; no network.
package api_keys

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// APIKeysDDL is the SQLite schema for API keys and their usage log. Timestamps are Unix
// nanoseconds (UTC) so range queries compare integers. key_prefix is the public, indexed first part
// of the random secret used to find the row; the full key is only ever stored as a bcrypt hash.
// previous_* hold the pre-rotation key during its grace period.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (was PostgreSQL DDL). Touches: database.
const APIKeysDDL = `
CREATE TABLE IF NOT EXISTS api_keys (
	id TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL,
	name TEXT NOT NULL,
	key_prefix TEXT NOT NULL,
	key_secret_hash TEXT NOT NULL,
	previous_key_prefix TEXT,
	previous_key_secret_hash TEXT,
	grace_period_ends_at INTEGER,
	scopes TEXT NOT NULL,
	rate_limit INTEGER NOT NULL,
	expires_at INTEGER,
	created_at INTEGER NOT NULL,
	last_used_at INTEGER,
	revoked_at INTEGER,
	is_active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_previous_prefix ON api_keys(previous_key_prefix);

CREATE TABLE IF NOT EXISTS api_key_usage (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	api_key_id TEXT NOT NULL REFERENCES api_keys(id),
	endpoint TEXT NOT NULL,
	method TEXT NOT NULL,
	status INTEGER NOT NULL,
	timestamp INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_api_key_usage_api_key_id ON api_key_usage(api_key_id, timestamp);
`

// GracePeriod is how long a rotated-out key keeps working (spec: 24h).
const GracePeriod = 24 * time.Hour

// prefixLen is the number of characters of the random part stored in clear as the lookup prefix.
// 12 base64url characters (72 bits) of a 43-character (256-bit) secret are public; the rest stays
// secret and the whole key is bcrypt-verified.
const prefixLen = 12

// APIError is a failure with the HTTP status a handler should return (401 invalid/revoked/expired,
// 403 insufficient scope, 404 not found, 409 conflict, 429 rate limited, 400 bad input).
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
type APIError struct {
	Status  int
	Code    string
	Message string
}

// Error returns the message. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
func (e *APIError) Error() string { return e.Message }

func apiErr(status int, code, msg string) *APIError {
	return &APIError{Status: status, Code: code, Message: msg}
}

// RateLimiter counts requests per key in fixed windows. Incr adds one to bucket and returns the new
// count; the bucket may be forgotten after ttl. A Redis adapter is INCR bucket, then EXPIRE bucket ttl
// when the count is 1 (spec: "Redis counter (key_id:2026-09-24T10:00:00)").
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: replaces the hard *redis.Client
// dependency so tests need no Redis server. Touches: whatever store the implementation uses.
type RateLimiter interface {
	Incr(ctx context.Context, bucket string, ttl time.Duration) (int64, error)
}

// MemoryRateLimiter is an in-process RateLimiter for tests and single-instance deployments.
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory only.
type MemoryRateLimiter struct {
	mu      sync.Mutex
	counts  map[string]int64
	expires map[string]time.Time
	now     func() time.Time
}

// NewMemoryRateLimiter returns an empty in-memory limiter using the wall clock for bucket expiry.
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory only.
func NewMemoryRateLimiter() *MemoryRateLimiter {
	return &MemoryRateLimiter{counts: map[string]int64{}, expires: map[string]time.Time{}, now: time.Now}
}

// Incr adds one to bucket and returns the count, dropping the bucket first if its ttl has passed.
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory only.
func (m *MemoryRateLimiter) Incr(_ context.Context, bucket string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if exp, ok := m.expires[bucket]; ok && !now.Before(exp) {
		delete(m.counts, bucket)
		delete(m.expires, bucket)
	}
	m.counts[bucket]++
	if m.counts[bucket] == 1 {
		m.expires[bucket] = now.Add(ttl)
	}
	return m.counts[bucket], nil
}

// Service handles API key operations.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: a RateLimiter replaces *redis.Client,
// and an injectable clock makes tests deterministic. Touches: database, rate limiter.
type Service struct {
	db         *sql.DB
	limiter    RateLimiter
	mode       string // "live" or "test": selects the sk_live_ / sk_test_ prefix
	now        func() time.Time
	BcryptCost int // bcrypt work factor for key hashes (default bcrypt.DefaultCost)
}

// NewService creates the service. Inputs: an open database with APIKeysDDL applied, a RateLimiter
// and the mode ("test" gives sk_test_ keys, anything else sk_live_). Output: the service.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (limiter instead of Redis client).
// Touches: nothing until a method is called.
func NewService(db *sql.DB, limiter RateLimiter, mode string) *Service {
	return &Service{db: db, limiter: limiter, mode: mode, now: time.Now, BcryptCost: bcrypt.DefaultCost}
}

// SetClock replaces the service clock (tests freeze time so hourly windows and expiry are
// deterministic). Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// CreateAPIKeyRequest represents the request to create an API key.
type CreateAPIKeyRequest struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresAt *string  `json:"expires_at,omitempty"` // RFC3339, or YYYY-MM-DD meaning the end of that UTC day
	RateLimit int      `json:"rate_limit"`           // requests per hour
}

// CreateAPIKeyResponse is returned once at creation; Key is never retrievable again.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: Name added (the tests read it; it is
// not secret).
type CreateAPIKeyResponse struct {
	APIKeyID  string     `json:"api_key_id"`
	Name      string     `json:"name"`
	Key       string     `json:"key"` // Only shown once
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RateLimit int        `json:"rate_limit"`
}

// ListAPIKeysResponse represents the response from listing API keys.
type ListAPIKeysResponse struct {
	Keys []APIKeyItem `json:"keys"`
}

// APIKeyItem is a key in list responses. It never carries the key or its hash.
type APIKeyItem struct {
	APIKeyID   string     `json:"api_key_id"`
	UserID     int64      `json:"user_id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RateLimit  int        `json:"rate_limit"`
	IsActive   bool       `json:"is_active"`
}

// RevokeAPIKeyResponse represents the response from revoking an API key.
type RevokeAPIKeyResponse struct {
	Success   bool      `json:"success"`
	RevokedAt time.Time `json:"revoked_at"`
}

// RotateAPIKeyResponse represents the response from rotating an API key.
type RotateAPIKeyResponse struct {
	NewKey            string    `json:"new_key"`
	OldKeyRevokedAt   time.Time `json:"old_key_revoked_at"`
	GracePeriodEndsAt time.Time `json:"grace_period_ends_at"`
}

// GetAPIKeyUsageStatsResponse represents the response from getting API key usage stats.
type GetAPIKeyUsageStatsResponse struct {
	APIKeyID           string           `json:"api_key_id"`
	TotalRequests      int64            `json:"total_requests"`
	RequestsByEndpoint map[string]int64 `json:"requests_by_endpoint"`
	RateLimitHits      int64            `json:"rate_limit_hits"`
	Errors             map[string]int64 `json:"errors"`
}

// ListAPIKeysForAdminResponse represents the response from admin listing API keys.
type ListAPIKeysForAdminResponse struct {
	Keys  []APIKeyItem `json:"keys"`
	Total int64        `json:"total"`
}

// APIKey is the authenticated key returned by ValidateAPIKey. It carries no secret material.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the hash is no longer exposed.
type APIKey struct {
	ID         string
	UserID     int64
	Name       string
	Scopes     []string
	RateLimit  int
	ExpiresAt  *time.Time
	CreatedAt  time.Time
	LastUsedAt *time.Time
	IsActive   bool
}

var scopeRe = regexp.MustCompile(`^(\*|[a-z][a-z_]*:[a-z][a-z_]*)$`)

// newID returns a random RFC 4122 version-4 UUID string. Added 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP (replaces github.com/google/uuid). Touches: OS random source.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// newSecret creates a key "sk_<mode>_<43 base64url chars>" and returns it with its lookup prefix
// and bcrypt hash. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (one place for the
// create and rotate paths). Touches: OS random source.
func (s *Service) newSecret() (key, prefix, hash string, err error) {
	kind := "sk_live_"
	if s.mode == "test" {
		kind = "sk_test_"
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return "", "", "", err
	}
	body := base64.RawURLEncoding.EncodeToString(random)
	key = kind + body
	h, err := bcrypt.GenerateFromPassword([]byte(key), s.BcryptCost)
	if err != nil {
		return "", "", "", err
	}
	return key, body[:prefixLen], string(h), nil
}

// keyPrefix extracts the lookup prefix from a presented key, or "" if the key is malformed.
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
func keyPrefix(key string) string {
	var body string
	switch {
	case strings.HasPrefix(key, "sk_live_"):
		body = key[len("sk_live_"):]
	case strings.HasPrefix(key, "sk_test_"):
		body = key[len("sk_test_"):]
	default:
		return ""
	}
	if len(body) < prefixLen+8 {
		return ""
	}
	return body[:prefixLen]
}

func nsToTime(ns sql.NullInt64) *time.Time {
	if !ns.Valid {
		return nil
	}
	t := time.Unix(0, ns.Int64).UTC()
	return &t
}

func timeToNS(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return t.UTC().UnixNano()
}

// parseExpiry accepts RFC3339 or YYYY-MM-DD (the key then works through the end of that UTC day).
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (the spec's example is '2026-12-31').
func parseExpiry(v string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC(), nil
	}
	d, err := time.Parse("2006-01-02", v)
	if err != nil {
		return time.Time{}, err
	}
	return d.AddDate(0, 0, 1).UTC(), nil
}

// CreateAPIKey creates a key for userID. Inputs: name, scopes (each "*" or "<verb>:<resource>"),
// optional expires_at, rate_limit > 0. Output: the response holding the only copy of the key.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (SQLite, prefix lookup, scope
// validation). Touches: database, OS random source.
func (s *Service) CreateAPIKey(ctx context.Context, userID int64, req CreateAPIKeyRequest) (*CreateAPIKeyResponse, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 255 {
		return nil, apiErr(400, "invalid_name", "name is required (max 255 characters)")
	}
	if req.RateLimit <= 0 {
		return nil, apiErr(400, "invalid_rate_limit", "rate_limit must be positive")
	}
	if len(req.Scopes) == 0 {
		return nil, apiErr(400, "invalid_scopes", "at least one scope required")
	}
	for _, sc := range req.Scopes {
		if !scopeRe.MatchString(sc) {
			return nil, apiErr(400, "invalid_scopes", fmt.Sprintf("invalid scope %q", sc))
		}
	}
	var expiresAt *time.Time
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := parseExpiry(*req.ExpiresAt)
		if err != nil {
			return nil, apiErr(400, "invalid_expires_at", "expires_at must be RFC3339 or YYYY-MM-DD")
		}
		expiresAt = &t
	}
	key, prefix, hash, err := s.newSecret()
	if err != nil {
		return nil, err
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	scopes, _ := json.Marshal(req.Scopes)
	now := s.now().UTC()
	if _, err = s.db.ExecContext(ctx, `
		INSERT INTO api_keys (id, user_id, name, key_prefix, key_secret_hash, scopes, rate_limit, expires_at, created_at, is_active)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
		id, userID, name, prefix, hash, string(scopes), req.RateLimit, timeToNS(expiresAt), now.UnixNano()); err != nil {
		return nil, err
	}
	return &CreateAPIKeyResponse{APIKeyID: id, Name: name, Key: key, CreatedAt: now, ExpiresAt: expiresAt, RateLimit: req.RateLimit}, nil
}

const itemColumns = `id, user_id, name, scopes, created_at, last_used_at, expires_at, rate_limit, is_active`

// scanItems reads APIKeyItem rows selected with itemColumns. Added 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP (shared by the user and admin listings). Touches: database rows.
func scanItems(rows *sql.Rows) ([]APIKeyItem, error) {
	keys := []APIKeyItem{}
	for rows.Next() {
		var k APIKeyItem
		var scopes string
		var created int64
		var lastUsed, expires sql.NullInt64
		var active int
		if err := rows.Scan(&k.APIKeyID, &k.UserID, &k.Name, &scopes, &created, &lastUsed, &expires, &k.RateLimit, &active); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(scopes), &k.Scopes); err != nil {
			return nil, err
		}
		k.CreatedAt = time.Unix(0, created).UTC()
		k.LastUsedAt = nsToTime(lastUsed)
		k.ExpiresAt = nsToTime(expires)
		k.IsActive = active == 1
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// ListAPIKeys lists a user's keys, newest first, masked (no key, no hash).
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
func (s *Service) ListAPIKeys(ctx context.Context, userID int64) (*ListAPIKeysResponse, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+itemColumns+` FROM api_keys WHERE user_id = ? ORDER BY created_at DESC, rowid DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys, err := scanItems(rows)
	if err != nil {
		return nil, err
	}
	return &ListAPIKeysResponse{Keys: keys}, nil
}

// RevokeAPIKey deactivates a key at once, including any rotated-out key still in its grace period.
// The HTTP layer must check that the caller owns the key (or is an admin) before calling it.
// Output: success and revoked_at; 404 if the key does not exist.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
func (s *Service) RevokeAPIKey(ctx context.Context, apiKeyID string) (*RevokeAPIKeyResponse, error) {
	now := s.now().UTC()
	res, err := s.db.ExecContext(ctx, `
		UPDATE api_keys SET is_active = 0, revoked_at = COALESCE(revoked_at, ?),
			previous_key_prefix = NULL, previous_key_secret_hash = NULL, grace_period_ends_at = NULL
		WHERE id = ?`, now.UnixNano(), apiKeyID)
	if err != nil {
		return nil, err
	}
	if n, err := res.RowsAffected(); err != nil {
		return nil, err
	} else if n == 0 {
		return nil, apiErr(404, "not_found", "api key not found")
	}
	return &RevokeAPIKeyResponse{Success: true, RevokedAt: now}, nil
}

// RotateAPIKey issues a new secret for the same key id; the old secret keeps working until
// grace_period_ends_at (24h). A revoked key cannot be rotated, and a key still inside a grace period
// cannot be rotated again (409), so a second rotation never cuts the first one's grace short.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (the old code scanned nine columns
// into ten targets and updated a missing updated_at column). Touches: database, OS random source.
func (s *Service) RotateAPIKey(ctx context.Context, apiKeyID string) (*RotateAPIKeyResponse, error) {
	now := s.now().UTC()
	var active int
	var prefix, hash string
	var grace sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT is_active, key_prefix, key_secret_hash, grace_period_ends_at FROM api_keys WHERE id = ?`,
		apiKeyID).Scan(&active, &prefix, &hash, &grace)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apiErr(404, "not_found", "api key not found")
	}
	if err != nil {
		return nil, err
	}
	if active != 1 {
		return nil, apiErr(409, "key_inactive", "api key is not active")
	}
	if grace.Valid && now.UnixNano() < grace.Int64 {
		return nil, apiErr(409, "rotation_in_progress", "the previous rotation is still in its grace period")
	}
	newKey, newPrefix, newHash, err := s.newSecret()
	if err != nil {
		return nil, err
	}
	graceEnds := now.Add(GracePeriod)
	// Compare-and-swap on the current hash so two concurrent rotations cannot both win.
	res, err := s.db.ExecContext(ctx, `
		UPDATE api_keys SET key_prefix = ?, key_secret_hash = ?, previous_key_prefix = ?,
			previous_key_secret_hash = ?, grace_period_ends_at = ?
		WHERE id = ? AND key_secret_hash = ? AND is_active = 1`,
		newPrefix, newHash, prefix, hash, graceEnds.UnixNano(), apiKeyID, hash)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, apiErr(409, "rotation_conflict", "api key changed during rotation")
	}
	return &RotateAPIKeyResponse{NewKey: newKey, OldKeyRevokedAt: now, GracePeriodEndsAt: graceEnds}, nil
}

// ValidateAPIKey authenticates a presented key for one request and logs it to api_key_usage.
// Inputs: the key (from "Authorization: Bearer"), the endpoint path and HTTP method. Output: the key,
// or an *APIError: 401 invalid/revoked/expired, 403 insufficient scope, 429 rate limited. Order:
// find by prefix + bcrypt verify (current secret, or the pre-rotation secret inside its grace
// period), active, expiry, scope, hourly rate limit; then usage is logged synchronously and
// last_used_at updated. Endpoints that map to no scope are denied unless the key holds "*".
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, rate limiter.
func (s *Service) ValidateAPIKey(ctx context.Context, key string, endpoint, method string) (*APIKey, error) {
	now := s.now().UTC()
	prefix := keyPrefix(key)
	if prefix == "" {
		return nil, apiErr(401, "invalid_api_key", "invalid api key")
	}
	type candidate struct {
		k            APIKey
		hash         string
		previousHash sql.NullString
		previousLive bool
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, name, scopes, rate_limit, expires_at, created_at, last_used_at, is_active,
			key_prefix, key_secret_hash, previous_key_prefix, previous_key_secret_hash, grace_period_ends_at
		FROM api_keys WHERE key_prefix = ? OR previous_key_prefix = ?`, prefix, prefix)
	if err != nil {
		return nil, err
	}
	var cands []candidate
	for rows.Next() {
		var c candidate
		var scopes, curPrefix string
		var expires, lastUsed, grace sql.NullInt64
		var created int64
		var active int
		var prevPrefix sql.NullString
		if err := rows.Scan(&c.k.ID, &c.k.UserID, &c.k.Name, &scopes, &c.k.RateLimit, &expires, &created, &lastUsed, &active,
			&curPrefix, &c.hash, &prevPrefix, &c.previousHash, &grace); err != nil {
			rows.Close()
			return nil, err
		}
		if err := json.Unmarshal([]byte(scopes), &c.k.Scopes); err != nil {
			rows.Close()
			return nil, err
		}
		c.k.ExpiresAt, c.k.LastUsedAt = nsToTime(expires), nsToTime(lastUsed)
		c.k.CreatedAt = time.Unix(0, created).UTC()
		c.k.IsActive = active == 1
		if curPrefix != prefix {
			c.hash = "" // only the previous secret can match this row
		}
		c.previousLive = prevPrefix.Valid && prevPrefix.String == prefix && grace.Valid && now.UnixNano() < grace.Int64
		cands = append(cands, c)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	var found *APIKey
	for i := range cands {
		c := &cands[i]
		if c.hash != "" && bcrypt.CompareHashAndPassword([]byte(c.hash), []byte(key)) == nil {
			found = &c.k
			break
		}
		if c.previousLive && c.previousHash.Valid &&
			bcrypt.CompareHashAndPassword([]byte(c.previousHash.String), []byte(key)) == nil {
			found = &c.k
			break
		}
	}
	if found == nil {
		return nil, apiErr(401, "invalid_api_key", "invalid api key")
	}
	if !found.IsActive {
		s.logUsage(ctx, found.ID, endpoint, method, 401, now)
		return nil, apiErr(401, "api_key_revoked", "api key revoked")
	}
	if found.ExpiresAt != nil && !now.Before(*found.ExpiresAt) {
		s.logUsage(ctx, found.ID, endpoint, method, 401, now)
		return nil, apiErr(401, "api_key_expired", "api key expired")
	}
	if !hasScope(found.Scopes, endpointMethodToScope(endpoint, method)) {
		s.logUsage(ctx, found.ID, endpoint, method, 403, now)
		return nil, apiErr(403, "insufficient_scope", "insufficient scope")
	}
	bucket := "rate_limit:" + found.ID + ":" + now.Truncate(time.Hour).Format(time.RFC3339)
	count, err := s.limiter.Incr(ctx, bucket, 2*time.Hour)
	if err != nil {
		return nil, err
	}
	if count > int64(found.RateLimit) {
		s.logUsage(ctx, found.ID, endpoint, method, 429, now)
		return nil, apiErr(429, "rate_limited", "rate limit exceeded")
	}
	if err := s.logUsage(ctx, found.ID, endpoint, method, 200, now); err != nil {
		return nil, err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE api_keys SET last_used_at = ? WHERE id = ?`, now.UnixNano(), found.ID); err != nil {
		return nil, err
	}
	found.LastUsedAt = &now
	return found, nil
}

// logUsage writes one api_key_usage row (spec: every API call logged with the key used).
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: synchronous, so stats never race it.
// Touches: database.
func (s *Service) logUsage(ctx context.Context, keyID, endpoint, method string, status int, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO api_key_usage (api_key_id, endpoint, method, status, timestamp) VALUES (?, ?, ?, ?, ?)`,
		keyID, endpoint, strings.ToUpper(method), status, at.UnixNano())
	return err
}

// hasScope reports whether scopes grant need; an empty need (unmapped endpoint) needs "*".
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: unmapped endpoints used to be allowed
// for every key. Touches: nothing.
func hasScope(scopes []string, need string) bool {
	for _, sc := range scopes {
		if sc == "*" || (need != "" && sc == need) {
			return true
		}
	}
	return false
}

// endpointMethodToScope maps a request to the scope it needs (spec's scope table), using the first
// path segment so /users/42 maps like /users. Output: the scope, or "" when the request is not
// covered (callers then require "*"). Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: nothing.
func endpointMethodToScope(endpoint, method string) string {
	path := strings.TrimPrefix(endpoint, "/api")
	seg := "/" + strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)[0]
	method = strings.ToUpper(method)
	read := method == "GET" || method == "HEAD"
	write := method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE"
	switch seg {
	case "/users", "/deployments":
		if read {
			return "read:" + seg[1:]
		}
		if write {
			return "write:" + seg[1:]
		}
	case "/invoices":
		if read {
			return "read:invoices"
		}
	case "/subscriptions", "/billing":
		if write {
			return "write:billing"
		}
	case "/webhooks":
		if method == "POST" || method == "DELETE" {
			return "webhook:manage"
		}
	}
	return ""
}

// GetAPIKeyUsageStats summarises api_key_usage for a key between from and to (inclusive): total
// requests, requests by "<endpoint> <METHOD>", 429 count and error counts by status.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (SQLite; the errors map no longer
// shadows the errors package). Touches: database.
func (s *Service) GetAPIKeyUsageStats(ctx context.Context, apiKeyID string, from, to time.Time) (*GetAPIKeyUsageStatsResponse, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT endpoint, method, status, COUNT(*) FROM api_key_usage
		WHERE api_key_id = ? AND timestamp >= ? AND timestamp <= ?
		GROUP BY endpoint, method, status`, apiKeyID, from.UTC().UnixNano(), to.UTC().UnixNano())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := &GetAPIKeyUsageStatsResponse{APIKeyID: apiKeyID, RequestsByEndpoint: map[string]int64{}, Errors: map[string]int64{}}
	for rows.Next() {
		var endpoint, method string
		var status int
		var n int64
		if err := rows.Scan(&endpoint, &method, &status, &n); err != nil {
			return nil, err
		}
		out.TotalRequests += n
		out.RequestsByEndpoint[endpoint+" "+method] += n
		if status == 429 {
			out.RateLimitHits += n
		}
		if status >= 400 {
			out.Errors[strconv.Itoa(status)] += n
		}
	}
	return out, rows.Err()
}

// ListAPIKeysForAdmin lists every key (optionally one user's, optionally "active"/"inactive"),
// newest first, masked. The HTTP layer must restrict it to admins.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
func (s *Service) ListAPIKeysForAdmin(ctx context.Context, userID *int64, status string) (*ListAPIKeysForAdminResponse, error) {
	query := `SELECT ` + itemColumns + ` FROM api_keys WHERE 1=1`
	var args []interface{}
	if userID != nil {
		query += " AND user_id = ?"
		args = append(args, *userID)
	}
	switch status {
	case "":
	case "active":
		query += " AND is_active = 1"
	case "inactive":
		query += " AND is_active = 0"
	default:
		return nil, apiErr(400, "invalid_status", "status must be active or inactive")
	}
	query += " ORDER BY created_at DESC, rowid DESC"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys, err := scanItems(rows)
	if err != nil {
		return nil, err
	}
	return &ListAPIKeysForAdminResponse{Keys: keys, Total: int64(len(keys))}, nil
}

package quotasratelimit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"
)

type Tier string

const (
	TierSolo       Tier = "solo"
	TierTeam       Tier = "team"
	TierEnterprise Tier = "enterprise"
)

// QuotaError is a rejected check: Status is the HTTP status the spec names for it (429 quota or rate
// limit, 413 storage, 403 feature gate), Code the error string, Details the body fields.
// Status added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (QUOTA-02/04/06/08/10 name the status;
// Go returned only the code). Touches nothing.
type QuotaError struct {
	Status  int
	Code    string
	Message string
	Details map[string]interface{}
}

func (e *QuotaError) Error() string {
	return e.Message
}

var (
	ErrQuotaExceeded      = errors.New("quota_exceeded")
	ErrStorageQuotaExceeded = errors.New("storage_quota_exceeded")
	ErrRateLimitExceeded  = errors.New("rate_limit_exceeded")
	ErrIPRateLimitExceeded = errors.New("ip_rate_limit_exceeded")
	// ErrFeatureNotAvailable carries the spec's one name for the feature-gate refusal. Renamed 2026-11-10,
	// session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, quotas spec: "feature_not_available_in_tier" in every
	// language; was "feature_not_available"). Touches nothing.
	ErrFeatureNotAvailable = errors.New("feature_not_available_in_tier")
)

// Config configures a Limiter. Now is the injectable clock (nil = time.Now), added 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP, so months and rate windows never depend on the time of day in
// tests (spec README "Deterministic"). Touches nothing.
type Config struct {
	DB  *sql.DB
	Now func() time.Time
}

type Limiter struct {
	db  *sql.DB
	now func() time.Time
	mu  sync.RWMutex

	userRateLimits map[string]*rateWindow
	ipRateLimits   map[string]*rateWindow
}

type rateWindow struct {
	requests []time.Time
	mu       sync.Mutex
}

var apiCallLimits = map[Tier]int64{
	TierSolo:       1000,
	TierTeam:       10000,
	TierEnterprise: -1,
}

var storageLimits = map[Tier]int64{
	TierSolo:       1_000_000_000,
	TierTeam:       100_000_000_000,
	TierEnterprise: -1,
}

var featureGates = map[string][]Tier{
	"feature_a": {TierTeam, TierEnterprise},
	"feature_b": {TierEnterprise},
	"feature_c": {TierSolo, TierTeam, TierEnterprise},
}

const (
	rateLimitPerUserWindow = time.Minute
	rateLimitPerUserMax    = 100
	rateLimitPerIPWindow   = time.Second
	rateLimitPerIPMax      = 10
)

// NewLimiter builds a Limiter on cfg.DB (required) and creates its tables. Out: the limiter or an
// error. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: takes the injectable clock cfg.Now.
// Touches: database (CREATE TABLE IF NOT EXISTS).
func NewLimiter(cfg Config) (*Limiter, error) {
	if cfg.DB == nil {
		return nil, errors.New("database connection required")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	l := &Limiter{
		db:             cfg.DB,
		now:            now,
		userRateLimits: make(map[string]*rateWindow),
		ipRateLimits:   make(map[string]*rateWindow),
	}
	if err := l.initSchema(context.Background()); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Limiter) initSchema(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS usage_metrics (
			user_id TEXT NOT NULL,
			month TEXT NOT NULL,
			call_count INTEGER NOT NULL DEFAULT 0,
			storage_bytes INTEGER NOT NULL DEFAULT 0,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, month)
		)`,
		`CREATE TABLE IF NOT EXISTS api_calls (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id TEXT NOT NULL,
			ip TEXT NOT NULL,
			endpoint TEXT NOT NULL,
			timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			status_code INTEGER NOT NULL,
			response_time_ms INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_api_calls_user_time ON api_calls(user_id, timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_api_calls_ip_time ON api_calls(ip, timestamp)`,
	}
	for _, q := range queries {
		if _, err := l.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("schema init failed: %w", err)
		}
	}
	return nil
}

// currentMonth is the clock's month as "YYYY-MM" (UTC). Changed 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP: reads the injectable clock. Touches nothing.
func (l *Limiter) currentMonth() string {
	return l.now().UTC().Format("2006-01")
}

// CheckAPIQuota decides api_call_quota for one request. In: user id and tier. Out: PASS, or a 429
// QuotaError {quota_exceeded, usage, limit, reset_date = the 1st of next month}; -1 is unlimited
// (QUOTA-13). Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: Status 429, clock-based month and
// reset_date. Touches: database (reads usage_metrics).
func (l *Limiter) CheckAPIQuota(ctx context.Context, userID string, tier Tier) (bool, *QuotaError, error) {
	limit, ok := apiCallLimits[tier]
	if !ok {
		return false, nil, fmt.Errorf("unknown tier: %s", tier)
	}
	if limit == -1 {
		return true, nil, nil
	}

	month := l.currentMonth()
	var currentUsage int64
	err := l.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(call_count), 0) FROM usage_metrics WHERE user_id = ? AND month = ?`,
		userID, month).Scan(&currentUsage)
	if err != nil && err != sql.ErrNoRows {
		return false, nil, fmt.Errorf("query usage: %w", err)
	}

	if currentUsage+1 > limit {
		now := l.now().UTC()
		resetDate := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02")
		return false, &QuotaError{
			Status:  429,
			Code:    "quota_exceeded",
			Message: "API call quota exceeded",
			Details: map[string]interface{}{
				"usage":      currentUsage,
				"limit":      limit,
				"reset_date": resetDate,
			},
		}, nil
	}
	return true, nil, nil
}

func (l *Limiter) IncrementAPIUsage(ctx context.Context, userID string) error {
	month := l.currentMonth()
	_, err := l.db.ExecContext(ctx, `
		INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
		VALUES (?, ?, 1, 0, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id, month) DO UPDATE SET
			call_count = call_count + 1,
			updated_at = CURRENT_TIMESTAMP
	`, userID, month)
	return err
}

// CheckStorageQuota decides storage_quota for an upload. In: user id, tier, incoming size. Out: PASS,
// or a 413 QuotaError {storage_quota_exceeded, usage, limit}; -1 is unlimited (QUOTA-13).
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: Status 413. Touches: database (reads).
func (l *Limiter) CheckStorageQuota(ctx context.Context, userID string, tier Tier, incomingFileSize int64) (bool, *QuotaError, error) {
	limit, ok := storageLimits[tier]
	if !ok {
		return false, nil, fmt.Errorf("unknown tier: %s", tier)
	}
	if limit == -1 {
		return true, nil, nil
	}

	var currentUsage int64
	err := l.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(storage_bytes), 0) FROM usage_metrics WHERE user_id = ?`,
		userID).Scan(&currentUsage)
	if err != nil && err != sql.ErrNoRows {
		return false, nil, fmt.Errorf("query storage: %w", err)
	}

	if currentUsage+incomingFileSize > limit {
		return false, &QuotaError{
			Status:  413,
			Code:    "storage_quota_exceeded",
			Message: "Storage quota exceeded",
			Details: map[string]interface{}{
				"usage": currentUsage,
				"limit": limit,
			},
		}, nil
	}
	return true, nil, nil
}

func (l *Limiter) IncrementStorageUsage(ctx context.Context, userID string, bytes int64) error {
	month := l.currentMonth()
	_, err := l.db.ExecContext(ctx, `
		INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
		VALUES (?, ?, 0, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id, month) DO UPDATE SET
			storage_bytes = storage_bytes + ?,
			updated_at = CURRENT_TIMESTAMP
	`, userID, month, bytes, bytes)
	return err
}

func (l *Limiter) getUserWindow(userID string) *rateWindow {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.userRateLimits[userID]
	if !ok {
		w = &rateWindow{requests: make([]time.Time, 0, rateLimitPerUserMax+1)}
		l.userRateLimits[userID] = w
	}
	return w
}

func (l *Limiter) getIPWindow(ip string) *rateWindow {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.ipRateLimits[ip]
	if !ok {
		w = &rateWindow{requests: make([]time.Time, 0, rateLimitPerIPMax+1)}
		l.ipRateLimits[ip] = w
	}
	return w
}

// checkAndRecord is a sliding-window counter: it drops requests older than window, refuses when limit
// remain, else records now. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: now comes from the
// limiter's injectable clock. Touches nothing.
func (w *rateWindow) checkAndRecord(now time.Time, limit int, window time.Duration) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	cutoff := now.Add(-window)
	valid := w.requests[:0]
	for _, t := range w.requests {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	w.requests = valid
	if len(w.requests) >= limit {
		return false
	}
	w.requests = append(w.requests, now)
	return true
}

// CheckRateLimitPerUser allows fewer than 100 requests per user per sliding minute; else a 429
// QuotaError {rate_limit_exceeded, reset_seconds 60}. Changed 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP: Status 429 and the injectable clock. Touches: memory only.
func (l *Limiter) CheckRateLimitPerUser(userID string) (bool, *QuotaError) {
	w := l.getUserWindow(userID)
	ok := w.checkAndRecord(l.now(), rateLimitPerUserMax, rateLimitPerUserWindow)
	if !ok {
		return false, &QuotaError{
			Status:  429,
			Code:    "rate_limit_exceeded",
			Message: "Rate limit exceeded (100 requests per minute)",
			Details: map[string]interface{}{
				"reset_seconds": 60,
			},
		}
	}
	return true, nil
}

// CheckRateLimitPerIP allows fewer than 10 requests per IP per sliding second; else a 429 QuotaError
// {ip_rate_limit_exceeded, reset_seconds 1}. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP:
// Status 429 and the injectable clock. Touches: memory only.
func (l *Limiter) CheckRateLimitPerIP(ip string) (bool, *QuotaError) {
	w := l.getIPWindow(ip)
	ok := w.checkAndRecord(l.now(), rateLimitPerIPMax, rateLimitPerIPWindow)
	if !ok {
		return false, &QuotaError{
			Status:  429,
			Code:    "ip_rate_limit_exceeded",
			Message: "IP rate limit exceeded (10 requests per second)",
			Details: map[string]interface{}{
				"reset_seconds": 1,
			},
		}
	}
	return true, nil
}

// CheckFeatureGate allows a feature when the tier is in its allowed list; else a 403 QuotaError
// {feature_not_available_in_tier, tier, minimum_tier, upgrade_url}. Inputs: the user id, the user's tier and
// the feature name. Output: (true, nil, nil) when allowed, (false, refusal, nil) when not, and an error for an
// unknown feature. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: Status 403; later the same day
// (Phase B.2, quotas spec amendment) the code became "feature_not_available_in_tier", one name in every
// language. Touches nothing.
func (l *Limiter) CheckFeatureGate(ctx context.Context, userID string, tier Tier, feature string) (bool, *QuotaError, error) {
	allowedTiers, ok := featureGates[feature]
	if !ok {
		return false, nil, fmt.Errorf("unknown feature: %s", feature)
	}

	allowed := false
	for _, t := range allowedTiers {
		if t == tier {
			allowed = true
			break
		}
	}

	if !allowed {
		minTier := "team"
		if feature == "feature_b" {
			minTier = "enterprise"
		}
		return false, &QuotaError{
			Status:  403,
			Code:    "feature_not_available_in_tier",
			Message: "Feature not available in current tier",
			Details: map[string]interface{}{
				"tier":          string(tier),
				"minimum_tier":  minTier,
				"upgrade_url":   "/upgrade",
			},
		}, nil
	}
	return true, nil, nil
}

func (l *Limiter) LogAPICall(ctx context.Context, userID, ip, endpoint string, statusCode, responseTimeMs int) error {
	_, err := l.db.ExecContext(ctx, `
		INSERT INTO api_calls (user_id, ip, endpoint, timestamp, status_code, response_time_ms)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
	`, userID, ip, endpoint, statusCode, responseTimeMs)
	return err
}

// HandleMonthRollover starts a new month: API call counts of past months are dropped (QUOTA-11), but
// each user's stored bytes are carried into the new month's row, because storage is what the user
// still holds, not a monthly allowance (spec storage_quota: SUM(bytes) of the user's files).
// In: a context. Out: an error from the database. One transaction.
// Why: until 2026-11-10 the rollover deleted past rows outright, so every user's storage usage fell
// to zero on the 1st of each month and the storage quota stopped working. Changed 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (usage_metrics).
func (l *Limiter) HandleMonthRollover(ctx context.Context) error {
	newMonth := l.currentMonth()
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
		SELECT user_id, ?, 0, SUM(storage_bytes), CURRENT_TIMESTAMP FROM usage_metrics
		WHERE month != ? GROUP BY user_id HAVING SUM(storage_bytes) != 0
		ON CONFLICT(user_id, month) DO UPDATE SET
			storage_bytes = storage_bytes + excluded.storage_bytes,
			updated_at = CURRENT_TIMESTAMP
	`, newMonth, newMonth); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM usage_metrics WHERE month != ?`, newMonth); err != nil {
		return err
	}
	return tx.Commit()
}

func (l *Limiter) HandleTierUpgrade(ctx context.Context, userID string, newTier Tier) error {
	if _, ok := apiCallLimits[newTier]; !ok {
		return fmt.Errorf("unknown tier: %s", newTier)
	}
	return nil
}

func (l *Limiter) GetCurrentUsage(ctx context.Context, userID string) (callCount, storageBytes int64, err error) {
	month := l.currentMonth()
	err = l.db.QueryRowContext(ctx,
		`SELECT COALESCE(call_count, 0), COALESCE(storage_bytes, 0) FROM usage_metrics WHERE user_id = ? AND month = ?`,
		userID, month).Scan(&callCount, &storageBytes)
	if err == sql.ErrNoRows {
		return 0, 0, nil
	}
	return
}
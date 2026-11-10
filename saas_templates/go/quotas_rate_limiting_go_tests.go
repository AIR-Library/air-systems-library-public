package quotasratelimit

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: one connection, because every new connection to
	// :memory: is a separate, empty database (spec README "Storage behind an interface").
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

func newTestLimiter(t *testing.T) *Limiter {
	t.Helper()
	db := setupTestDB(t)
	l, err := NewLimiter(Config{DB: db})
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}
	return l
}

// QUOTA-01
func TestAPIQuotaPASS(t *testing.T) {
	l := newTestLimiter(t)
	ctx := context.Background()

	ok, qerr, err := l.CheckAPIQuota(ctx, "user1", TierSolo)
	if err != nil {
		t.Fatalf("CheckAPIQuota error: %v", err)
	}
	if !ok {
		t.Fatalf("expected PASS, got FAIL: %v", qerr)
	}

	if err := l.IncrementAPIUsage(ctx, "user1"); err != nil {
		t.Fatalf("IncrementAPIUsage: %v", err)
	}

	callCount, _, err := l.GetCurrentUsage(ctx, "user1")
	if err != nil {
		t.Fatalf("GetCurrentUsage: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("expected call_count=1, got %d", callCount)
	}
}

// QUOTA-02
func TestAPIQuotaFAIL(t *testing.T) {
	l := newTestLimiter(t)
	ctx := context.Background()

	for i := 0; i < 1000; i++ {
		if err := l.IncrementAPIUsage(ctx, "user2"); err != nil {
			t.Fatalf("IncrementAPIUsage: %v", err)
		}
	}

	ok, qerr, err := l.CheckAPIQuota(ctx, "user2", TierSolo)
	if err != nil {
		t.Fatalf("CheckAPIQuota error: %v", err)
	}
	if ok {
		t.Fatalf("expected FAIL, got PASS")
	}
	if qerr == nil || qerr.Code != "quota_exceeded" || qerr.Status != 429 {
		t.Fatalf("expected 429 quota_exceeded error, got %+v", qerr)
	}
	if qerr.Details["limit"] != int64(1000) {
		t.Fatalf("expected limit 1000, got %v", qerr.Details["limit"])
	}
}

// QUOTA-03
func TestStorageQuotaPASS(t *testing.T) {
	l := newTestLimiter(t)
	ctx := context.Background()

	ok, qerr, err := l.CheckStorageQuota(ctx, "user3", TierSolo, 100)
	if err != nil {
		t.Fatalf("CheckStorageQuota error: %v", err)
	}
	if !ok {
		t.Fatalf("expected PASS, got FAIL: %v", qerr)
	}

	if err := l.IncrementStorageUsage(ctx, "user3", 100); err != nil {
		t.Fatalf("IncrementStorageUsage: %v", err)
	}

	_, storage, err := l.GetCurrentUsage(ctx, "user3")
	if err != nil {
		t.Fatalf("GetCurrentUsage: %v", err)
	}
	if storage != 100 {
		t.Fatalf("expected storage=100, got %d", storage)
	}
}

// QUOTA-04
func TestStorageQuotaFAIL(t *testing.T) {
	l := newTestLimiter(t)
	ctx := context.Background()

	if err := l.IncrementStorageUsage(ctx, "user4", 1_000_000_000); err != nil {
		t.Fatalf("IncrementStorageUsage: %v", err)
	}

	ok, qerr, err := l.CheckStorageQuota(ctx, "user4", TierSolo, 1)
	if err != nil {
		t.Fatalf("CheckStorageQuota error: %v", err)
	}
	if ok {
		t.Fatalf("expected FAIL, got PASS")
	}
	if qerr == nil || qerr.Code != "storage_quota_exceeded" || qerr.Status != 413 {
		t.Fatalf("expected storage_quota_exceeded error, got %v", qerr)
	}
}

// QUOTA-05
func TestRateLimitPerUserPASS(t *testing.T) {
	l := newTestLimiter(t)

	for i := 0; i < 99; i++ {
		ok, qerr := l.CheckRateLimitPerUser("user5")
		if !ok {
			t.Fatalf("request %d: expected PASS, got FAIL: %v", i, qerr)
		}
	}
}

// QUOTA-06
func TestRateLimitPerUserFAIL(t *testing.T) {
	l := newTestLimiter(t)

	for i := 0; i < 100; i++ {
		ok, _ := l.CheckRateLimitPerUser("user6")
		if !ok && i < 99 {
			t.Fatalf("request %d: unexpected FAIL", i)
		}
	}

	ok, qerr := l.CheckRateLimitPerUser("user6")
	if ok {
		t.Fatalf("expected FAIL on 101st request, got PASS")
	}
	if qerr == nil || qerr.Code != "rate_limit_exceeded" || qerr.Status != 429 {
		t.Fatalf("expected rate_limit_exceeded error, got %v", qerr)
	}
	if qerr.Details["reset_seconds"] != 60 {
		t.Fatalf("expected reset_seconds=60, got %v", qerr.Details["reset_seconds"])
	}
}

// QUOTA-07
func TestRateLimitPerIPPASS(t *testing.T) {
	l := newTestLimiter(t)

	for i := 0; i < 9; i++ {
		ok, qerr := l.CheckRateLimitPerIP("192.168.1.1")
		if !ok {
			t.Fatalf("request %d: expected PASS, got FAIL: %v", i, qerr)
		}
	}
}

// QUOTA-08
func TestRateLimitPerIPFAIL(t *testing.T) {
	l := newTestLimiter(t)

	for i := 0; i < 10; i++ {
		ok, _ := l.CheckRateLimitPerIP("192.168.1.2")
		if !ok && i < 9 {
			t.Fatalf("request %d: unexpected FAIL", i)
		}
	}

	ok, qerr := l.CheckRateLimitPerIP("192.168.1.2")
	if ok {
		t.Fatalf("expected FAIL on 11th request, got PASS")
	}
	if qerr == nil || qerr.Code != "ip_rate_limit_exceeded" || qerr.Status != 429 {
		t.Fatalf("expected ip_rate_limit_exceeded error, got %v", qerr)
	}
	if qerr.Details["reset_seconds"] != 1 {
		t.Fatalf("expected reset_seconds=1, got %v", qerr.Details["reset_seconds"])
	}
}

// QUOTA-09
func TestFeatureGatePASS(t *testing.T) {
	l := newTestLimiter(t)
	ctx := context.Background()

	tests := []struct {
		tier    Tier
		feature string
	}{
		{TierSolo, "feature_c"},
		{TierTeam, "feature_a"},
		{TierTeam, "feature_c"},
		{TierEnterprise, "feature_a"},
		{TierEnterprise, "feature_b"},
		{TierEnterprise, "feature_c"},
	}

	for _, tc := range tests {
		ok, qerr, err := l.CheckFeatureGate(ctx, "user7", tc.tier, tc.feature)
		if err != nil {
			t.Fatalf("CheckFeatureGate error: %v", err)
		}
		if !ok {
			t.Fatalf("tier=%s feature=%s: expected PASS, got FAIL: %v", tc.tier, tc.feature, qerr)
		}
	}
}

// QUOTA-10
// TestFeatureGateFAIL proves a tier below a feature's minimum gets 403 with the spec's body: error
// "feature_not_available_in_tier", tier, minimum_tier and upgrade_url. Input: none; output: test failures.
// Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): the quotas spec now names the refusal
// "feature_not_available_in_tier" in every language, so the expected code changed from "feature_not_available";
// the tier field is now asserted too. Touches an in-memory SQLite database only.
func TestFeatureGateFAIL(t *testing.T) {
	l := newTestLimiter(t)
	ctx := context.Background()

	tests := []struct {
		tier        Tier
		feature     string
		minTier     string
	}{
		{TierSolo, "feature_a", "team"},
		{TierSolo, "feature_b", "enterprise"},
		{TierTeam, "feature_b", "enterprise"},
	}

	for _, tc := range tests {
		ok, qerr, err := l.CheckFeatureGate(ctx, "user8", tc.tier, tc.feature)
		if err != nil {
			t.Fatalf("CheckFeatureGate error: %v", err)
		}
		if ok {
			t.Fatalf("tier=%s feature=%s: expected FAIL, got PASS", tc.tier, tc.feature)
		}
		if qerr == nil || qerr.Code != "feature_not_available_in_tier" || qerr.Status != 403 {
			t.Fatalf("expected 403 feature_not_available_in_tier, got %v", qerr)
		}
		if qerr.Details["tier"] != string(tc.tier) {
			t.Fatalf("expected tier=%s, got %v", tc.tier, qerr.Details["tier"])
		}
		if qerr.Details["minimum_tier"] != tc.minTier {
			t.Fatalf("expected minimum_tier=%s, got %v", tc.minTier, qerr.Details["minimum_tier"])
		}
		if qerr.Details["upgrade_url"] != "/upgrade" {
			t.Fatalf("expected upgrade_url=/upgrade, got %v", qerr.Details["upgrade_url"])
		}
	}
}

// QUOTA-11
func TestMonthRollover(t *testing.T) {
	l := newTestLimiter(t)
	ctx := context.Background()

	// user9's usage is moved into a past month; user10's stays in this one. 2026-11-05, session f3daac6e: this test
	// used to expect this month's usage to vanish, which is the opposite of a rollover.
	for _, user := range []string{"user9", "user10"} {
		if err := l.IncrementAPIUsage(ctx, user); err != nil {
			t.Fatalf("IncrementAPIUsage: %v", err)
		}
	}
	if _, err := l.db.ExecContext(ctx, `UPDATE usage_metrics SET month = '2000-01' WHERE user_id = ?`, "user9"); err != nil {
		t.Fatalf("move usage to a past month: %v", err)
	}

	if err := l.HandleMonthRollover(ctx); err != nil {
		t.Fatalf("HandleMonthRollover: %v", err)
	}

	var pastRows int
	if err := l.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM usage_metrics WHERE month = '2000-01'`).Scan(&pastRows); err != nil {
		t.Fatalf("count past rows: %v", err)
	}
	if pastRows != 0 {
		t.Fatalf("expected past months to be deleted, found %d rows", pastRows)
	}
	callCount, _, err := l.GetCurrentUsage(ctx, "user10")
	if err != nil {
		t.Fatalf("GetCurrentUsage after rollover: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("expected this month's call_count to survive a rollover, got %d", callCount)
	}
}

// QUOTA-12
func TestTierUpgrade(t *testing.T) {
	l := newTestLimiter(t)
	ctx := context.Background()

	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the user first uses up the solo quota, so the PASS
	// after the upgrade proves the new limit applies at once (QUOTA-12); before, usage was zero and
	// solo would have passed too.
	for i := 0; i < 1000; i++ {
		if err := l.IncrementAPIUsage(ctx, "user10"); err != nil {
			t.Fatalf("IncrementAPIUsage: %v", err)
		}
	}
	if ok, _, _ := l.CheckAPIQuota(ctx, "user10", TierSolo); ok {
		t.Fatalf("expected the solo quota to be used up before the upgrade")
	}
	if err := l.HandleTierUpgrade(ctx, "user10", TierTeam); err != nil {
		t.Fatalf("HandleTierUpgrade to team: %v", err)
	}

	ok, qerr, err := l.CheckAPIQuota(ctx, "user10", TierTeam)
	if err != nil {
		t.Fatalf("CheckAPIQuota after upgrade: %v", err)
	}
	if !ok {
		t.Fatalf("expected PASS after upgrade to team, got FAIL: %v", qerr)
	}

	if err := l.HandleTierUpgrade(ctx, "user10", TierEnterprise); err != nil {
		t.Fatalf("HandleTierUpgrade to enterprise: %v", err)
	}

	ok, qerr, err = l.CheckAPIQuota(ctx, "user10", TierEnterprise)
	if err != nil {
		t.Fatalf("CheckAPIQuota after upgrade to enterprise: %v", err)
	}
	if !ok {
		t.Fatalf("expected PASS after upgrade to enterprise, got FAIL: %v", qerr)
	}
}

// QUOTA-13
func TestEnterpriseUnlimitedAPI(t *testing.T) {
	l := newTestLimiter(t)
	ctx := context.Background()

	for i := 0; i < 10000; i++ {
		if err := l.IncrementAPIUsage(ctx, "user11"); err != nil {
			t.Fatalf("IncrementAPIUsage: %v", err)
		}
	}

	ok, qerr, err := l.CheckAPIQuota(ctx, "user11", TierEnterprise)
	if err != nil {
		t.Fatalf("CheckAPIQuota: %v", err)
	}
	if !ok {
		t.Fatalf("expected PASS for enterprise unlimited, got FAIL: %v", qerr)
	}
}

// QUOTA-13
func TestEnterpriseUnlimitedStorage(t *testing.T) {
	l := newTestLimiter(t)
	ctx := context.Background()

	ok, qerr, err := l.CheckStorageQuota(ctx, "user12", TierEnterprise, 1_000_000_000_000)
	if err != nil {
		t.Fatalf("CheckStorageQuota: %v", err)
	}
	if !ok {
		t.Fatalf("expected PASS for enterprise unlimited storage, got FAIL: %v", qerr)
	}
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: QUOTA-13 says the upload is stored; record it and
	// check again past the team limit.
	if err := l.IncrementStorageUsage(ctx, "user12", 1_000_000_000_000); err != nil {
		t.Fatalf("IncrementStorageUsage: %v", err)
	}
	_, stored, err := l.GetCurrentUsage(ctx, "user12")
	if err != nil || stored != 1_000_000_000_000 {
		t.Fatalf("expected 1e12 bytes stored, got %d (%v)", stored, err)
	}
	if ok, qerr, err := l.CheckStorageQuota(ctx, "user12", TierEnterprise, 1); err != nil || !ok {
		t.Fatalf("expected PASS past every other tier's storage limit, got %v %v", qerr, err)
	}
}

func TestLogAPICall(t *testing.T) {
	l := newTestLimiter(t)
	ctx := context.Background()

	if err := l.LogAPICall(ctx, "user13", "10.0.0.1", "/api/test", 200, 42); err != nil {
		t.Fatalf("LogAPICall: %v", err)
	}

	var count int
	err := l.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_calls WHERE user_id = ?`, "user13").Scan(&count)
	if err != nil {
		t.Fatalf("query api_calls: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 api_call record, got %d", count)
	}
}

// TestRateLimitWindowExpiry: a full per-user window frees up once the minute has passed.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the injectable clock replaces a 60 s sleep
// (spec README: time comes from an injectable clock); the window and the assertion are unchanged.
func TestRateLimitWindowExpiry(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	l, err := NewLimiter(Config{DB: setupTestDB(t), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}

	for i := 0; i < 100; i++ {
		ok, _ := l.CheckRateLimitPerUser("user14")
		if !ok {
			t.Fatalf("request %d: unexpected FAIL", i)
		}
	}
	if ok, _ := l.CheckRateLimitPerUser("user14"); ok {
		t.Fatalf("expected FAIL inside the window")
	}

	now = now.Add(time.Minute + 100*time.Millisecond)

	ok, qerr := l.CheckRateLimitPerUser("user14")
	if !ok {
		t.Fatalf("expected PASS after window expiry, got FAIL: %v", qerr)
	}
}

// TestIPRateLimitWindowExpiry: a full per-IP window frees up once the second has passed.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the injectable clock replaces a 1 s sleep.
func TestIPRateLimitWindowExpiry(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	l, err := NewLimiter(Config{DB: setupTestDB(t), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}

	for i := 0; i < 10; i++ {
		ok, _ := l.CheckRateLimitPerIP("10.0.0.2")
		if !ok {
			t.Fatalf("request %d: unexpected FAIL", i)
		}
	}
	if ok, _ := l.CheckRateLimitPerIP("10.0.0.2"); ok {
		t.Fatalf("expected FAIL inside the window")
	}

	now = now.Add(time.Second + 100*time.Millisecond)

	ok, qerr := l.CheckRateLimitPerIP("10.0.0.2")
	if !ok {
		t.Fatalf("expected PASS after window expiry, got FAIL: %v", qerr)
	}
}

func TestUnknownTier(t *testing.T) {
	l := newTestLimiter(t)
	ctx := context.Background()

	_, _, err := l.CheckAPIQuota(ctx, "user15", "unknown")
	if err == nil {
		t.Fatalf("expected error for unknown tier")
	}
}

func TestUnknownFeature(t *testing.T) {
	l := newTestLimiter(t)
	ctx := context.Background()

	_, _, err := l.CheckFeatureGate(ctx, "user16", TierSolo, "unknown_feature")
	if err == nil {
		t.Fatalf("expected error for unknown feature")
	}
}
// TestMonthRolloverKeepsStorage proves a rollover resets API call counts but keeps the bytes a user
// still stores, so the storage quota still applies in the new month. Why: HandleMonthRollover deleted
// past rows outright and so zeroed storage every month (found 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
// Touches: in-memory SQLite.
func TestMonthRolloverKeepsStorage(t *testing.T) {
	now := time.Date(2026, 10, 31, 23, 0, 0, 0, time.UTC)
	l, err := NewLimiter(Config{DB: setupTestDB(t), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}
	ctx := context.Background()
	if err := l.IncrementStorageUsage(ctx, "u", 999_999_999); err != nil {
		t.Fatal(err)
	}
	if err := l.IncrementAPIUsage(ctx, "u"); err != nil {
		t.Fatal(err)
	}
	now = time.Date(2026, 11, 1, 0, 0, 1, 0, time.UTC)
	if err := l.HandleMonthRollover(ctx); err != nil {
		t.Fatalf("rollover: %v", err)
	}
	calls, stored, err := l.GetCurrentUsage(ctx, "u")
	if err != nil || calls != 0 || stored != 999_999_999 {
		t.Fatalf("after rollover want calls=0 stored=999999999, got %d %d (%v)", calls, stored, err)
	}
	if ok, qerr, _ := l.CheckStorageQuota(ctx, "u", TierSolo, 2); ok || qerr.Status != 413 {
		t.Fatalf("storage quota must still apply after a rollover, got ok=%v %+v", ok, qerr)
	}
}

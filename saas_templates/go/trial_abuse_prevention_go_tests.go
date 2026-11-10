package trialabuse

import (
	"context"
	"errors"
	"testing"
	"time"
)

func setupTestDB(t *testing.T) *TrialAbusePrevention {
	t.Helper()
	tap, err := NewTrialAbusePrevention(":memory:")
	if err != nil {
		t.Fatalf("NewTrialAbusePrevention: %v", err)
	}
	t.Cleanup(func() { tap.Close() })
	return tap
}

// TRIAL-01
func TestEmailTrialHistory_Pass_NewEmail(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()

	result := tap.CheckEmailTrialHistory(ctx, "new@example.com")

	if result.Decision != DecisionPass {
		t.Errorf("expected PASS, got %s: %s", result.Decision, result.Reason)
	}
	if result.Code != 200 {
		t.Errorf("expected code 200, got %d", result.Code)
	}
}

// TRIAL-02
func TestEmailTrialHistory_Challenge_OnePriorTrial(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	_, err := tap.db.ExecContext(ctx,
		`INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, subscription_status, created_at)
		 VALUES (?, ?, ?, ?, ?, 'completed', ?)`,
		"user1", "test@example.com", "1.2.3.4", now, now, now)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	result := tap.CheckEmailTrialHistory(ctx, "test@example.com")

	if result.Decision != DecisionChallenge {
		t.Errorf("expected CHALLENGE, got %s: %s", result.Decision, result.Reason)
	}
	if result.Code != 200 {
		t.Errorf("expected code 200, got %d", result.Code)
	}
	if result.Meta["prior_count"] != int64(1) {
		t.Errorf("expected prior_count 1, got %v", result.Meta["prior_count"])
	}
}

// TRIAL-03
func TestEmailTrialHistory_Fail_TwoPriorTrials(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	for i := 0; i < 2; i++ {
		_, err := tap.db.ExecContext(ctx,
			`INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, subscription_status, created_at)
			 VALUES (?, ?, ?, ?, ?, 'completed', ?)`,
			"user"+string(rune('1'+i)), "test@example.com", "1.2.3.4", now, now, now)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	result := tap.CheckEmailTrialHistory(ctx, "test@example.com")

	if result.Decision != DecisionFail {
		t.Errorf("expected FAIL, got %s: %s", result.Decision, result.Reason)
	}
	if result.Code != 409 {
		t.Errorf("expected code 409, got %d", result.Code)
	}
}

// TRIAL-04
func TestPaymentMethodHistory_Pass_NewCard(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()

	result := tap.CheckPaymentMethodHistory(ctx, "pm_new_card")

	if result.Decision != DecisionPass {
		t.Errorf("expected PASS, got %s: %s", result.Decision, result.Reason)
	}
	if result.Code != 200 {
		t.Errorf("expected code 200, got %d", result.Code)
	}
}

// TRIAL-05
func TestPaymentMethodHistory_Fail_ThreePriorUses(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		_, err := tap.db.ExecContext(ctx,
			`INSERT INTO trial_abuse_ledger (user_id, email, ip, stripe_payment_method_id, signup_date, trial_started_at, subscription_status, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, 'completed', ?)`,
			"user"+string(rune('1'+i)), "email"+string(rune('1'+i))+"@example.com", "1.2.3.4", "pm_shared", now, now, now)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	result := tap.CheckPaymentMethodHistory(ctx, "pm_shared")

	if result.Decision != DecisionFail {
		t.Errorf("expected FAIL, got %s: %s", result.Decision, result.Reason)
	}
	if result.Code != 403 {
		t.Errorf("expected code 403, got %d", result.Code)
	}
	if result.Meta["prior_count"] != int64(3) {
		t.Errorf("expected prior_count 3, got %v", result.Meta["prior_count"])
	}
}

// TRIAL-06
func TestIPSignupRateLimit_Pass_UnderLimit(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	for i := 0; i < 4; i++ {
		_, err := tap.db.ExecContext(ctx,
			`INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, created_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			"user"+string(rune('1'+i)), "email"+string(rune('1'+i))+"@example.com", "192.168.1.1", now, now, now)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	result := tap.CheckIPSignupRateLimit(ctx, "192.168.1.1")

	if result.Decision != DecisionPass {
		t.Errorf("expected PASS, got %s: %s", result.Decision, result.Reason)
	}
	if result.Code != 200 {
		t.Errorf("expected code 200, got %d", result.Code)
	}
	if result.Meta["count"] != int64(4) {
		t.Errorf("expected count 4, got %v", result.Meta["count"])
	}
}

// TRIAL-07
func TestIPSignupRateLimit_Fail_OverLimit(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		_, err := tap.db.ExecContext(ctx,
			`INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, created_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			"user"+string(rune('1'+i)), "email"+string(rune('1'+i))+"@example.com", "10.0.0.1", now, now, now)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	result := tap.CheckIPSignupRateLimit(ctx, "10.0.0.1")

	if result.Decision != DecisionFail {
		t.Errorf("expected FAIL, got %s: %s", result.Decision, result.Reason)
	}
	if result.Code != 429 {
		t.Errorf("expected code 429, got %d", result.Code)
	}
	if result.Meta["retry_after"] != 86400 {
		t.Errorf("expected retry_after 86400, got %v", result.Meta["retry_after"])
	}
}

// TRIAL-08
func TestDeviceFingerprint_Pass_NewDevice(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()

	device := DeviceInfo{
		UserAgent:        "Mozilla/5.0",
		ScreenResolution: "1920x1080",
		Timezone:         "UTC",
		BrowserLanguage:  "en-US",
	}
	deviceHash := tap.HashDevice(device)

	result := tap.CheckDeviceFingerprint(ctx, "user1", deviceHash)

	if result.Decision != DecisionPass {
		t.Errorf("expected PASS, got %s: %s", result.Decision, result.Reason)
	}
	if result.Code != 200 {
		t.Errorf("expected code 200, got %d", result.Code)
	}
}

// TRIAL-09
func TestDeviceFingerprint_Fail_SharedByManyUsers(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()

	device := DeviceInfo{
		UserAgent:        "Mozilla/5.0",
		ScreenResolution: "1920x1080",
		Timezone:         "UTC",
		BrowserLanguage:  "en-US",
	}
	deviceHash := tap.HashDevice(device)

	now := time.Now().UTC()
	for i := 0; i < 6; i++ {
		_, err := tap.db.ExecContext(ctx,
			`INSERT INTO device_fingerprints (user_id, device_hash, user_agent, screen_resolution, timezone, created_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			"user"+string(rune('1'+i)), deviceHash, device.UserAgent, device.ScreenResolution, device.Timezone, now)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	result := tap.CheckDeviceFingerprint(ctx, "new_user", deviceHash)

	if result.Decision != DecisionFail {
		t.Errorf("expected FAIL, got %s: %s", result.Decision, result.Reason)
	}
	if result.Code != 403 {
		t.Errorf("expected code 403, got %d", result.Code)
	}
	if result.Meta["matching_users"] != int64(6) {
		t.Errorf("expected matching_users 6, got %v", result.Meta["matching_users"])
	}
}

// timingAt plants a user whose trial started at start (with an optional earlier payment) on a service
// whose clock reads now, and returns the payment-timing gate with the default 14-day trial.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (TRIAL-10/11/15 as amended). Touches: in-memory SQLite.
func timingAt(t *testing.T, start, now time.Time, earlierPayment bool) GateResult {
	t.Helper()
	tap := setupTestDB(t)
	tap.SetClock(func() time.Time { return now })
	var paid any
	if earlierPayment {
		paid = start.Add(24 * time.Hour)
	}
	if _, err := tap.db.ExecContext(context.Background(),
		`INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, payment_added_date, subscription_status, created_at)
		 VALUES ('u', 'u@example.com', '1.2.3.4', ?, ?, ?, 'trial', ?)`, start, start, paid, start); err != nil {
		t.Fatalf("insert: %v", err)
	}
	return tap.CheckTrialPaymentTiming(context.Background(), "u", 0)
}

// Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the amended TRIAL-10 is a FIRST payment 4 days
// after the trial ended (and one during the trial), judged with the payment date = now; the old test
// planted an already-added payment and checked days since the trial start.
// TRIAL-10
func TestTrialPaymentTiming_Pass_PaymentWithinWindow(t *testing.T) {
	start := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	trialEnd := start.Add(14 * 24 * time.Hour)
	for name, now := range map[string]time.Time{
		"4 days after the trial":   trialEnd.Add(4*24*time.Hour + 23*time.Hour),
		"during the trial":         start.Add(3 * 24 * time.Hour),
		"one second before the end": trialEnd.Add(-time.Second),
	} {
		result := timingAt(t, start, now, false)
		if result.Decision != DecisionPass || result.Code != 200 {
			t.Errorf("%s: expected PASS, got %s (%v)", name, result.Decision, result.Meta)
		}
	}
	if r := timingAt(t, start, trialEnd.Add(-time.Second), false); r.Meta["days_after_trial"] != int64(-1) {
		t.Errorf("days_after_trial must floor toward negative infinity: 1 s before the end is -1, got %v", r.Meta["days_after_trial"])
	}
}

// Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the amended TRIAL-11 is a FIRST payment 90 days
// after the trial ended with no earlier payment -> FAIL 403.
// TRIAL-11
func TestTrialPaymentTiming_Fail_TrialEndedNoPaymentRetryAfter90Days(t *testing.T) {
	start := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	result := timingAt(t, start, start.Add((14+90)*24*time.Hour), false)
	if result.Decision != DecisionFail {
		t.Errorf("expected FAIL, got %s: %s", result.Decision, result.Reason)
	}
	if result.Code != 403 {
		t.Errorf("expected code 403, got %d", result.Code)
	}
	if result.Meta["days_after_trial"] != int64(90) || result.Meta["earlier_payment"] != false {
		t.Errorf("unexpected meta %v", result.Meta)
	}
}

// TestTrialPaymentTiming_Boundaries proves TRIAL-15: 5 and 89 days after the trial are CHALLENGE, and 90
// days WITH an earlier payment is CHALLENGE, not FAIL. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// TRIAL-15
func TestTrialPaymentTiming_Boundaries(t *testing.T) {
	start := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	trialEnd := start.Add(14 * 24 * time.Hour)
	for _, c := range []struct {
		days    int
		earlier bool
		want    Decision
	}{{5, false, DecisionChallenge}, {89, false, DecisionChallenge}, {90, true, DecisionChallenge}, {90, false, DecisionFail}} {
		r := timingAt(t, start, trialEnd.Add(time.Duration(c.days)*24*time.Hour), c.earlier)
		if r.Decision != c.want {
			t.Errorf("%d days after, earlier payment %v: expected %s, got %s", c.days, c.earlier, c.want, r.Decision)
		}
	}
}

// TRIAL-12
func TestChargebackHistory_Pass_NoChargebacks(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()

	result := tap.CheckChargebackHistory(ctx, "user_no_cb", "cus_123")

	if result.Decision != DecisionPass {
		t.Errorf("expected PASS, got %s: %s", result.Decision, result.Reason)
	}
	if result.Code != 200 {
		t.Errorf("expected code 200, got %d", result.Code)
	}
}

// TRIAL-13
func TestChargebackHistory_Fail_TwoPlusChargebacks(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()

	userID := "user_cb_fail"
	now := time.Now().UTC()
	for i := 0; i < 2; i++ {
		_, err := tap.db.ExecContext(ctx,
			`INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, subscription_status, chargeback_count, created_at)
			 VALUES (?, ?, ?, ?, ?, 'chargebacked', 1, ?)`,
			userID, "test@example.com", "1.2.3.4", now, now, now)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	result := tap.CheckChargebackHistory(ctx, userID, "cus_123")

	if result.Decision != DecisionFail {
		t.Errorf("expected FAIL, got %s: %s", result.Decision, result.Reason)
	}
	if result.Code != 403 {
		t.Errorf("expected code 403, got %d", result.Code)
	}
	if result.Meta["chargebacks"] != int64(2) {
		t.Errorf("expected chargebacks 2, got %v", result.Meta["chargebacks"])
	}
}

func TestOnSignup_NewUserAllowed(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()

	input := SignupInput{
		Email: "newuser@example.com",
		Password: "password123",
		IP: "192.168.1.100",
		Device: DeviceInfo{
			UserAgent:        "Mozilla/5.0",
			ScreenResolution: "1920x1080",
			Timezone:         "America/New_York",
			BrowserLanguage:  "en-US",
		},
	}

	userID, emailGate, ipGate, err := tap.OnSignup(ctx, input)
	if err != nil {
		t.Fatalf("OnSignup error: %v", err)
	}
	if userID == "" {
		t.Fatal("expected userID")
	}
	if emailGate.Decision != DecisionPass {
		t.Errorf("email gate: expected PASS, got %s", emailGate.Decision)
	}
	if ipGate.Decision != DecisionPass {
		t.Errorf("ip gate: expected PASS, got %s", ipGate.Decision)
	}
}

func TestOnSignup_EmailChallenge_Flagged(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	_, err := tap.db.ExecContext(ctx,
		`INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, subscription_status, created_at)
		 VALUES (?, ?, ?, ?, ?, 'completed', ?)`,
		"user1", "existing@example.com", "1.2.3.4", now, now, now)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	input := SignupInput{
		Email: "existing@example.com",
		Password: "password123",
		IP: "192.168.1.100",
		Device: DeviceInfo{
			UserAgent:        "Mozilla/5.0",
			ScreenResolution: "1920x1080",
			Timezone:         "America/New_York",
			BrowserLanguage:  "en-US",
		},
	}

	userID, emailGate, ipGate, err := tap.OnSignup(ctx, input)
	if err != nil {
		t.Fatalf("OnSignup error: %v", err)
	}
	if userID == "" {
		t.Fatal("expected userID")
	}
	if emailGate.Decision != DecisionChallenge {
		t.Errorf("email gate: expected CHALLENGE, got %s", emailGate.Decision)
	}
	if ipGate.Decision != DecisionPass {
		t.Errorf("ip gate: expected PASS, got %s", ipGate.Decision)
	}
}

func TestOnSignup_IPFail_Rejected(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		_, err := tap.db.ExecContext(ctx,
			`INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, created_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			"user"+string(rune('1'+i)), "email"+string(rune('1'+i))+"@example.com", "10.0.0.50", now, now, now)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	input := SignupInput{
		Email: "new@example.com",
		Password: "password123",
		IP: "10.0.0.50",
		Device: DeviceInfo{
			UserAgent:        "Mozilla/5.0",
			ScreenResolution: "1920x1080",
			Timezone:         "UTC",
			BrowserLanguage:  "en-US",
		},
	}

	_, _, _, err := tap.OnSignup(ctx, input)
	if err == nil {
		t.Fatal("expected error for IP rate limit fail")
	}
}

func TestOnSubscriptionCreated_Success(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()

	userID := "user_sub_success"
	now := time.Now().UTC()
	trialStart := now.Add(-5 * 24 * time.Hour)
	_, err := tap.db.ExecContext(ctx,
		`INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, subscription_status, created_at)
		 VALUES (?, ?, ?, ?, ?, 'trial', ?)`,
		userID, "test@example.com", "1.2.3.4", trialStart, trialStart, now)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	input := PaymentInput{
		UserID:                userID,
		StripePaymentMethodID: "pm_new",
		StripeCustomerID:      "cus_123",
	}

	paymentGate, timingGate, chargebackGate, err := tap.OnSubscriptionCreated(ctx, input, 14)
	if err != nil {
		t.Fatalf("OnSubscriptionCreated error: %v", err)
	}
	if paymentGate.Decision != DecisionPass {
		t.Errorf("payment gate: expected PASS, got %s", paymentGate.Decision)
	}
	if timingGate.Decision != DecisionPass {
		t.Errorf("timing gate: expected PASS, got %s", timingGate.Decision)
	}
	if chargebackGate.Decision != DecisionPass {
		t.Errorf("chargeback gate: expected PASS, got %s", chargebackGate.Decision)
	}
}

func TestOnSubscriptionCreated_PaymentFail_Rejected(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()

	userID := "user_sub_fail"
	now := time.Now().UTC()
	trialStart := now.Add(-5 * 24 * time.Hour)
	for i := 0; i < 3; i++ {
		_, err := tap.db.ExecContext(ctx,
			`INSERT INTO trial_abuse_ledger (user_id, email, ip, stripe_payment_method_id, signup_date, trial_started_at, subscription_status, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, 'completed', ?)`,
			"user"+string(rune('1'+i)), "email"+string(rune('1'+i))+"@example.com", "1.2.3.4", "pm_shared", now, now, now)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	_, err := tap.db.ExecContext(ctx,
		`INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, subscription_status, created_at)
		 VALUES (?, ?, ?, ?, ?, 'trial', ?)`,
		userID, "test@example.com", "1.2.3.4", trialStart, trialStart, now)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	input := PaymentInput{
		UserID:                userID,
		StripePaymentMethodID: "pm_shared",
		StripeCustomerID:      "cus_123",
	}

	_, _, _, err = tap.OnSubscriptionCreated(ctx, input, 14)
	if err == nil {
		t.Fatal("expected error for payment method reuse")
	}
}

func TestHashDevice_Deterministic(t *testing.T) {
	tap := setupTestDB(t)

	device := DeviceInfo{
		UserAgent:        "Mozilla/5.0",
		ScreenResolution: "1920x1080",
		Timezone:         "UTC",
		BrowserLanguage:  "en-US",
	}

	hash1 := tap.HashDevice(device)
	hash2 := tap.HashDevice(device)

	if hash1 != hash2 {
		t.Errorf("HashDevice not deterministic: %s != %s", hash1, hash2)
	}
	if len(hash1) != 64 {
		t.Errorf("expected 64 char hex string, got %d", len(hash1))
	}
}

// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the amended spec makes 5 other users a FAIL even
// on the user's own device (TRIAL-14), so this test now uses 4 other users, where the user's own device
// still PASSes (an unknown user there gets CHALLENGE, see TestDeviceFingerprint_Boundaries).
func TestDeviceFingerprint_KnownDevice_Pass(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()

	device := DeviceInfo{
		UserAgent:        "Mozilla/5.0",
		ScreenResolution: "1920x1080",
		Timezone:         "UTC",
		BrowserLanguage:  "en-US",
	}
	deviceHash := tap.HashDevice(device)

	now := time.Now().UTC()
	_, err := tap.db.ExecContext(ctx,
		`INSERT INTO device_fingerprints (user_id, device_hash, user_agent, screen_resolution, timezone, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"user1", deviceHash, device.UserAgent, device.ScreenResolution, device.Timezone, now)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Add 4 other users with same device
	for i := 2; i <= 5; i++ {
		_, err := tap.db.ExecContext(ctx,
			`INSERT INTO device_fingerprints (user_id, device_hash, user_agent, screen_resolution, timezone, created_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			"user"+string(rune('0'+i)), deviceHash, device.UserAgent, device.ScreenResolution, device.Timezone, now)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	// user1 should still PASS because it's their known device
	result := tap.CheckDeviceFingerprint(ctx, "user1", deviceHash)

	if result.Decision != DecisionPass {
		t.Errorf("expected PASS for known device, got %s: %s", result.Decision, result.Reason)
	}
	if result.Code != 200 {
		t.Errorf("expected code 200, got %d", result.Code)
	}
	if result.Meta["is_known_device"] != true || result.Meta["matching_users"] != int64(4) {
		t.Errorf("expected is_known_device true and 4 other users, got %v", result.Meta)
	}
}

// TestDeviceFingerprint_Boundaries proves TRIAL-14: 4 other users -> CHALLENGE for a new user; exactly 5
// -> FAIL, even for a user who already has the device; a FAIL records no device row, at signup or later.
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
// TRIAL-14
func TestDeviceFingerprint_Boundaries(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()
	device := DeviceInfo{UserAgent: "Farm/1.0", ScreenResolution: "800x600", Timezone: "UTC", BrowserLanguage: "en"}
	hash := tap.HashDevice(device)
	rows := func() int {
		var n int
		_ = tap.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM device_fingerprints WHERE device_hash = ?`, hash).Scan(&n)
		return n
	}
	// Signups through the real flow: the first 2 PASS, the next 3 CHALLENGE, and each records the device.
	var users []string
	for i := 0; i < 5; i++ {
		id, _, _, err := tap.OnSignup(ctx, SignupInput{Email: string(rune('a'+i)) + "@example.com", IP: "10.0.0." + string(rune('1'+i)), Device: device})
		if err != nil {
			t.Fatalf("signup %d: %v", i, err)
		}
		users = append(users, id)
		if i == 3 {
			if r := tap.CheckDeviceFingerprint(ctx, "", hash); r.Decision != DecisionChallenge || r.Meta["matching_users"] != int64(4) {
				t.Fatalf("4 other users: expected CHALLENGE, got %s %v", r.Decision, r.Meta)
			}
		}
	}
	if rows() != 5 {
		t.Fatalf("expected 5 device rows, got %d", rows())
	}
	// Exactly 5 others: FAIL for a new user, and the sixth signup is refused with no row written.
	if r := tap.CheckDeviceFingerprint(ctx, "", hash); r.Decision != DecisionFail || r.Code != 403 {
		t.Fatalf("5 other users: expected FAIL 403, got %s %d", r.Decision, r.Code)
	}
	_, _, _, err := tap.OnSignup(ctx, SignupInput{Email: "f@example.com", IP: "10.0.1.1", Device: device})
	var ge *GateError
	if !errors.As(err, &ge) || ge.ErrorCode != "device_suspected_fraud" || ge.Result.Code != 403 {
		t.Fatalf("sixth signup: expected device_suspected_fraud, got %v", err)
	}
	if rows() != 5 {
		t.Fatalf("a FAIL must record no device row; rows %d", rows())
	}
	var ledger int
	_ = tap.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM trial_abuse_ledger WHERE email = 'f@example.com'`).Scan(&ledger)
	if ledger != 0 {
		t.Fatalf("a FAIL must record no ledger row")
	}
	// A user who already has the device, with 5 other users on it: FAIL all the same.
	if _, err := tap.db.ExecContext(ctx, `INSERT INTO device_fingerprints (user_id, device_hash, user_agent, screen_resolution, timezone, created_at) VALUES ('extra', ?, '', '', '', ?)`, hash, time.Now()); err != nil {
		t.Fatal(err)
	}
	if r := tap.CheckDeviceFingerprint(ctx, users[0], hash); r.Decision != DecisionFail || r.Meta["is_known_device"] != true {
		t.Fatalf("own device with 5 others: expected FAIL, got %s %v", r.Decision, r.Meta)
	}
	// CheckAndRecordDevice on a FAIL writes nothing for a new user.
	before := rows()
	if r, err := tap.CheckAndRecordDevice(ctx, "newcomer", device); err != nil || r.Decision != DecisionFail {
		t.Fatalf("CheckAndRecordDevice: %v %v", r.Decision, err)
	}
	if rows() != before {
		t.Fatalf("CheckAndRecordDevice recorded a device after a FAIL")
	}
}

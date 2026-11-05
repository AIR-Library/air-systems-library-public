package trialabuse

import (
	"context"
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

func TestTrialPaymentTiming_Pass_PaymentWithinWindow(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()

	userID := "user_timing_pass"
	now := time.Now().UTC()
	trialStart := now.Add(-5 * 24 * time.Hour)
	paymentAdded := now.Add(-2 * 24 * time.Hour)

	_, err := tap.db.ExecContext(ctx,
		`INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, payment_added_date, subscription_status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, 'completed', ?)`,
		userID, "test@example.com", "1.2.3.4", trialStart, trialStart, paymentAdded, now)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	result := tap.CheckTrialPaymentTiming(ctx, userID, 14)

	if result.Decision != DecisionPass {
		t.Errorf("expected PASS, got %s: %s", result.Decision, result.Reason)
	}
	if result.Code != 200 {
		t.Errorf("expected code 200, got %d", result.Code)
	}
}

func TestTrialPaymentTiming_Fail_TrialEndedNoPaymentRetryAfter90Days(t *testing.T) {
	tap := setupTestDB(t)
	ctx := context.Background()

	userID := "user_timing_fail"
	now := time.Now().UTC()
	trialStart := now.Add(-120 * 24 * time.Hour)

	_, err := tap.db.ExecContext(ctx,
		`INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, subscription_status, created_at)
		 VALUES (?, ?, ?, ?, ?, 'trial', ?)`,
		userID, "test@example.com", "1.2.3.4", trialStart, trialStart, now)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	result := tap.CheckTrialPaymentTiming(ctx, userID, 14)

	if result.Decision != DecisionFail {
		t.Errorf("expected FAIL, got %s: %s", result.Decision, result.Reason)
	}
	if result.Code != 403 {
		t.Errorf("expected code 403, got %d", result.Code)
	}
	if !result.Meta["trial_ended"].(bool) {
		t.Errorf("expected trial_ended true")
	}
	if result.Meta["payment_added"] != false {
		t.Errorf("expected payment_added false")
	}
}

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

	// Add 5 other users with same device
	for i := 2; i <= 6; i++ {
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
	if result.Meta["is_known_device"] != true {
		t.Errorf("expected is_known_device true")
	}
}

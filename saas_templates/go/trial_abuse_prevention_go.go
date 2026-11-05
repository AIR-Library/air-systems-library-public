package trialabuse

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Decision string

const (
	DecisionPass     Decision = "PASS"
	DecisionChallenge Decision = "CHALLENGE"
	DecisionFail     Decision = "FAIL"
)

type GateResult struct {
	Gate     string
	Decision Decision
	Reason   string
	Code     int
	Meta     map[string]any
}

type TrialAbuseLedger struct {
	ID                       int64
	UserID                   string
	Email                    string
	StripePaymentMethodID    sql.NullString
	IP                       string
	DeviceFingerprint        string
	SignupDate               time.Time
	TrialStartedAt           time.Time
	PaymentAddedDate         sql.NullTime
	SubscriptionStatus       string
	ChargebackCount          int
	RefundCount              int
	GateFlags                map[string]string
	AlertReason              sql.NullString
	CreatedAt                time.Time
}

type DeviceFingerprint struct {
	ID               int64
	UserID           string
	DeviceHash       string
	UserAgent        string
	ScreenResolution string
	Timezone         string
	CreatedAt        time.Time
}

type GateDecisionRecord struct {
	ID           int64
	UserID       string
	GateName     string
	Decision     string
	RuleInputs   map[string]any
	RuleOutputs  map[string]any
	CreatedAt    time.Time
}

type DeviceInfo struct {
	UserAgent        string
	ScreenResolution string
	Timezone         string
	BrowserLanguage  string
}

type SignupInput struct {
	Email           string
	Password        string
	IP              string
	Device          DeviceInfo
}

type PaymentInput struct {
	UserID                   string
	StripePaymentMethodID    string
	StripeCustomerID         string
}

type TrialAbusePrevention struct {
	db *sql.DB
}

func NewTrialAbusePrevention(dbPath string) (*TrialAbusePrevention, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	tap := &TrialAbusePrevention{db: db}
	if err := tap.initSchema(context.Background()); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return tap, nil
}

func (tap *TrialAbusePrevention) Close() error {
	return tap.db.Close()
}

func (tap *TrialAbusePrevention) initSchema(ctx context.Context) error {
	schema := `
	CREATE TABLE IF NOT EXISTS trial_abuse_ledger (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL,
		email TEXT NOT NULL,
		stripe_payment_method_id TEXT,
		ip TEXT NOT NULL,
		device_fingerprint TEXT,
		signup_date DATETIME NOT NULL,
		trial_started_at DATETIME NOT NULL,
		payment_added_date DATETIME,
		subscription_status TEXT DEFAULT 'trial',
		chargeback_count INTEGER DEFAULT 0,
		refund_count INTEGER DEFAULT 0,
		gate_flags TEXT DEFAULT '{}',
		alert_reason TEXT,
		created_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_ledger_email ON trial_abuse_ledger(email);
	CREATE INDEX IF NOT EXISTS idx_ledger_payment ON trial_abuse_ledger(stripe_payment_method_id);
	CREATE INDEX IF NOT EXISTS idx_ledger_ip ON trial_abuse_ledger(ip);

	CREATE TABLE IF NOT EXISTS device_fingerprints (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL,
		device_hash TEXT NOT NULL,
		user_agent TEXT NOT NULL,
		screen_resolution TEXT NOT NULL,
		timezone TEXT NOT NULL,
		created_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_device_hash ON device_fingerprints(device_hash);
	CREATE INDEX IF NOT EXISTS idx_device_user ON device_fingerprints(user_id);

	CREATE TABLE IF NOT EXISTS gate_decisions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL,
		gate_name TEXT NOT NULL,
		decision TEXT NOT NULL,
		rule_inputs TEXT NOT NULL,
		rule_outputs TEXT NOT NULL,
		created_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_gate_user ON gate_decisions(user_id);
	`
	_, err := tap.db.ExecContext(ctx, schema)
	return err
}

func (tap *TrialAbusePrevention) HashDevice(device DeviceInfo) string {
	data := device.UserAgent + "|" + device.ScreenResolution + "|" + device.Timezone + "|" + device.BrowserLanguage
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (tap *TrialAbusePrevention) logGateDecision(ctx context.Context, userID, gateName string, decision Decision, inputs, outputs map[string]any) error {
	inputsJSON, _ := json.Marshal(inputs)
	outputsJSON, _ := json.Marshal(outputs)
	_, err := tap.db.ExecContext(ctx,
		`INSERT INTO gate_decisions (user_id, gate_name, decision, rule_inputs, rule_outputs, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		userID, gateName, string(decision), string(inputsJSON), string(outputsJSON), time.Now().UTC())
	return err
}

func (tap *TrialAbusePrevention) CheckEmailTrialHistory(ctx context.Context, email string) GateResult {
	var count int
	err := tap.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM trial_abuse_ledger WHERE email = ? AND subscription_status IN ('completed', 'chargebacked')`,
		email).Scan(&count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return GateResult{Gate: "email_trial_history", Decision: DecisionFail, Reason: "database error", Code: 500}
	}

	var decision Decision
	var code int
	var reason string
	switch {
	case count == 0:
		decision = DecisionPass
		code = 200
		reason = "no prior trials"
	case count == 1:
		decision = DecisionChallenge
		code = 200
		reason = "one prior trial, flagged"
	default:
		decision = DecisionFail
		code = 409
		reason = "email has trial history"
	}

	return GateResult{
		Gate:     "email_trial_history",
		Decision: decision,
		Reason:   reason,
		Code:     code,
		Meta:     map[string]any{"email": email, "prior_count": int64(count)},
	}
}

func (tap *TrialAbusePrevention) CheckPaymentMethodHistory(ctx context.Context, paymentMethodID string) GateResult {
	var count int
	err := tap.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM trial_abuse_ledger WHERE stripe_payment_method_id = ? AND subscription_status IN ('completed', 'chargebacked')`,
		paymentMethodID).Scan(&count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return GateResult{Gate: "payment_method_history", Decision: DecisionFail, Reason: "database error", Code: 500}
	}

	var decision Decision
	var code int
	var reason string
	switch {
	case count < 2:
		decision = DecisionPass
		code = 200
		reason = "payment method used less than 2 times"
	case count == 2:
		decision = DecisionChallenge
		code = 200
		reason = "payment method used 2 times, flagged"
	default:
		decision = DecisionFail
		code = 403
		reason = "payment method used for multiple trials"
	}

	return GateResult{
		Gate:     "payment_method_history",
		Decision: decision,
		Reason:   reason,
		Code:     code,
		Meta:     map[string]any{"payment_method_id": paymentMethodID, "prior_count": int64(count)},
	}
}

func (tap *TrialAbusePrevention) CheckIPSignupRateLimit(ctx context.Context, ip string) GateResult {
	var count int
	err := tap.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM trial_abuse_ledger WHERE ip = ? AND signup_date > ?`,
		ip, time.Now().UTC().Add(-24*time.Hour)).Scan(&count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return GateResult{Gate: "ip_signup_rate_limit", Decision: DecisionFail, Reason: "database error", Code: 500}
	}

	var decision Decision
	var code int
	var reason string
	switch {
	case count < 5:
		decision = DecisionPass
		code = 200
		reason = "under rate limit"
	case count < 10:
		decision = DecisionChallenge
		code = 200
		reason = "rate limit warning, require CAPTCHA"
	default:
		decision = DecisionFail
		code = 429
		reason = "too many signups from IP"
	}

	return GateResult{
		Gate:     "ip_signup_rate_limit",
		Decision: decision,
		Reason:   reason,
		Code:     code,
		Meta:     map[string]any{"ip": ip, "count": int64(count), "limit": 5, "retry_after": 86400},
	}
}

func (tap *TrialAbusePrevention) CheckDeviceFingerprint(ctx context.Context, userID, deviceHash string) GateResult {
	var count int
	err := tap.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT user_id) FROM device_fingerprints WHERE device_hash = ?`,
		deviceHash).Scan(&count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return GateResult{Gate: "device_fingerprint", Decision: DecisionFail, Reason: "database error", Code: 500}
	}

	// Check if device matches user's known devices
	var knownCount int
	err = tap.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM device_fingerprints WHERE user_id = ? AND device_hash = ?`,
		userID, deviceHash).Scan(&knownCount)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return GateResult{Gate: "device_fingerprint", Decision: DecisionFail, Reason: "database error", Code: 500}
	}

	var decision Decision
	var code int
	var reason string
	isKnownDevice := knownCount > 0
	switch {
	case count < 2 || isKnownDevice:
		decision = DecisionPass
		code = 200
		reason = "device not suspicious"
	case count <= 5:
		decision = DecisionChallenge
		code = 200
		reason = "device shared by multiple users, send verification email"
	default:
		decision = DecisionFail
		code = 403
		reason = "device suspected fraud"
	}

	return GateResult{
		Gate:     "device_fingerprint",
		Decision: decision,
		Reason:   reason,
		Code:     code,
		Meta:     map[string]any{"device_hash": deviceHash, "matching_users": int64(count), "is_known_device": isKnownDevice},
	}
}

func (tap *TrialAbusePrevention) CheckTrialPaymentTiming(ctx context.Context, userID string, trialDays int) GateResult {
	var ledger TrialAbuseLedger
	err := tap.db.QueryRowContext(ctx,
		`SELECT user_id, trial_started_at, payment_added_date, subscription_status FROM trial_abuse_ledger WHERE user_id = ? ORDER BY created_at DESC LIMIT 1`,
		userID).Scan(&ledger.UserID, &ledger.TrialStartedAt, &ledger.PaymentAddedDate, &ledger.SubscriptionStatus)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GateResult{Gate: "trial_payment_timing", Decision: DecisionPass, Reason: "no trial record found", Code: 200}
		}
		return GateResult{Gate: "trial_payment_timing", Decision: DecisionFail, Reason: "database error", Code: 500}
	}

	now := time.Now().UTC()
	daysElapsed := int(now.Sub(ledger.TrialStartedAt).Hours() / 24)

	var decision Decision
	var code int
	var reason string

	trialEnded := daysElapsed > trialDays
	paymentAdded := ledger.PaymentAddedDate.Valid
	paymentDelay := 0
	if paymentAdded {
		paymentDelay = int(ledger.PaymentAddedDate.Time.Sub(ledger.TrialStartedAt).Hours() / 24)
	}

	switch {
	case !trialEnded && paymentAdded && paymentDelay >= 0:
		decision = DecisionPass
		code = 200
		reason = "payment added within trial window"
	case trialEnded && paymentAdded && paymentDelay > trialDays && paymentDelay <= trialDays+30:
		decision = DecisionChallenge
		code = 200
		reason = "late payment entry"
	case trialEnded && !paymentAdded && daysElapsed > trialDays+90:
		decision = DecisionFail
		code = 403
		reason = "trial ended, no payment, cannot retry after 90 days"
	default:
		decision = DecisionPass
		code = 200
		reason = "within acceptable timing"
	}

	return GateResult{
		Gate:     "trial_payment_timing",
		Decision: decision,
		Reason:   reason,
		Code:     code,
		Meta:     map[string]any{"days_elapsed": daysElapsed, "payment_delay": paymentDelay, "trial_ended": trialEnded, "payment_added": paymentAdded},
	}
}

func (tap *TrialAbusePrevention) CheckChargebackHistory(ctx context.Context, userID, stripeCustomerID string) GateResult {
	var totalChargebacks int
	err := tap.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(chargeback_count), 0) FROM trial_abuse_ledger WHERE user_id = ?`,
		userID).Scan(&totalChargebacks)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return GateResult{Gate: "chargeback_history", Decision: DecisionFail, Reason: "database error", Code: 500}
	}

	var decision Decision
	var code int
	var reason string
	switch {
	case totalChargebacks == 0:
		decision = DecisionPass
		code = 200
		reason = "no chargebacks"
	case totalChargebacks == 1:
		decision = DecisionChallenge
		code = 200
		reason = "one chargeback, flagged"
	default:
		decision = DecisionFail
		code = 403
		reason = "chargeback history requires prepayment"
	}

	return GateResult{
		Gate:     "chargeback_history",
		Decision: decision,
		Reason:   reason,
		Code:     code,
		Meta:     map[string]any{"chargebacks": int64(totalChargebacks), "stripe_customer_id": stripeCustomerID},
	}
}

func (tap *TrialAbusePrevention) OnSignup(ctx context.Context, input SignupInput) (string, GateResult, GateResult, error) {
	emailGate := tap.CheckEmailTrialHistory(ctx, input.Email)
	if emailGate.Decision == DecisionFail {
		return "", emailGate, GateResult{}, errors.New(emailGate.Reason)
	}

	ipGate := tap.CheckIPSignupRateLimit(ctx, input.IP)
	if ipGate.Decision == DecisionFail {
		return "", emailGate, ipGate, errors.New(ipGate.Reason)
	}

	userID := fmt.Sprintf("user_%d", time.Now().UnixNano())

	deviceHash := tap.HashDevice(input.Device)

	gateFlags := map[string]string{
		"email": emailGate.Decision.String(),
		"ip":    ipGate.Decision.String(),
	}
	gateFlagsJSON, _ := json.Marshal(gateFlags)

	now := time.Now().UTC()
	result, err := tap.db.ExecContext(ctx,
		`INSERT INTO trial_abuse_ledger (user_id, email, ip, device_fingerprint, signup_date, trial_started_at, subscription_status, gate_flags, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, 'trial', ?, ?)`,
		userID, input.Email, input.IP, deviceHash, now, now, string(gateFlagsJSON), now)
	if err != nil {
		return "", emailGate, ipGate, fmt.Errorf("insert ledger: %w", err)
	}

	ledgerID, _ := result.LastInsertId()

	_, err = tap.db.ExecContext(ctx,
		`INSERT INTO device_fingerprints (user_id, device_hash, user_agent, screen_resolution, timezone, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		userID, deviceHash, input.Device.UserAgent, input.Device.ScreenResolution, input.Device.Timezone, now)
	if err != nil {
		return "", emailGate, ipGate, fmt.Errorf("insert device fingerprint: %w", err)
	}

	tap.logGateDecision(ctx, userID, "email_trial_history", emailGate.Decision, emailGate.Meta, map[string]any{"user_id": userID, "ledger_id": ledgerID})
	tap.logGateDecision(ctx, userID, "ip_signup_rate_limit", ipGate.Decision, ipGate.Meta, map[string]any{"user_id": userID, "ledger_id": ledgerID})

	if emailGate.Decision == DecisionChallenge || ipGate.Decision == DecisionChallenge {
		challengeFlags := map[string]string{}
		if emailGate.Decision == DecisionChallenge {
			challengeFlags["email_trial_attempt_2+"] = "true"
		}
		if ipGate.Decision == DecisionChallenge {
			challengeFlags["captcha_required"] = "true"
		}
		challengeFlagsJSON, _ := json.Marshal(challengeFlags)
		tap.db.ExecContext(ctx, `UPDATE trial_abuse_ledger SET gate_flags = ? WHERE id = ?`, string(challengeFlagsJSON), ledgerID)
	}

	return userID, emailGate, ipGate, nil
}

func (tap *TrialAbusePrevention) OnSubscriptionCreated(ctx context.Context, input PaymentInput, trialDays int) (GateResult, GateResult, GateResult, error) {
	paymentGate := tap.CheckPaymentMethodHistory(ctx, input.StripePaymentMethodID)
	timingGate := tap.CheckTrialPaymentTiming(ctx, input.UserID, trialDays)
	chargebackGate := tap.CheckChargebackHistory(ctx, input.UserID, input.StripeCustomerID)

	if paymentGate.Decision == DecisionFail {
		return paymentGate, timingGate, chargebackGate, errors.New(paymentGate.Reason)
	}
	if timingGate.Decision == DecisionFail {
		return paymentGate, timingGate, chargebackGate, errors.New(timingGate.Reason)
	}
	if chargebackGate.Decision == DecisionFail {
		return paymentGate, timingGate, chargebackGate, errors.New(chargebackGate.Reason)
	}

	now := time.Now().UTC()
	gateFlags := map[string]string{
		"payment":    paymentGate.Decision.String(),
		"timing":     timingGate.Decision.String(),
		"chargeback": chargebackGate.Decision.String(),
	}
	gateFlagsJSON, _ := json.Marshal(gateFlags)

	_, err := tap.db.ExecContext(ctx,
		`UPDATE trial_abuse_ledger SET 
			stripe_payment_method_id = ?,
			payment_added_date = ?,
			subscription_status = 'completed',
			gate_flags = ?,
			created_at = ?
		 WHERE user_id = ?`,
		input.StripePaymentMethodID, now, string(gateFlagsJSON), now, input.UserID)
	if err != nil {
		return paymentGate, timingGate, chargebackGate, fmt.Errorf("update ledger: %w", err)
	}

	tap.logGateDecision(ctx, input.UserID, "payment_method_history", paymentGate.Decision, paymentGate.Meta, map[string]any{"payment_method_id": input.StripePaymentMethodID})
	tap.logGateDecision(ctx, input.UserID, "trial_payment_timing", timingGate.Decision, timingGate.Meta, map[string]any{})
	tap.logGateDecision(ctx, input.UserID, "chargeback_history", chargebackGate.Decision, chargebackGate.Meta, map[string]any{})

	return paymentGate, timingGate, chargebackGate, nil
}

func (d Decision) String() string {
	return string(d)
}

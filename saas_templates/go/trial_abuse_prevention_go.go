// Package trialabuse is the AOI Systems Library trial-abuse template: six gates (email history,
// payment-method history, IP signup rate, device fingerprint, payment timing, chargebacks) run at signup
// and at subscription creation, each logged to gate_decisions.
//
// Phase B, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (TRIAL-09/10/11/14/15, amended): the device gate
// counts OTHER users on the device and decides FAIL >= 5, PASS < 2, PASS for the user's own device, else
// CHALLENGE, and signup runs it BEFORE recording the device (recording first meant a device farm never
// failed); payment timing is days after the trial END, floored toward negative infinity: PASS < 5, FAIL >= 90
// with no earlier payment, else CHALLENGE. Time comes from an injectable clock. Touches: SQLite.
package trialabuse

import (
	"context"
	"crypto/rand"
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

// TrialAbusePrevention runs the gates. TrialDays is the default trial length (14) used when a caller
// passes trialDays <= 0. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: injectable clock and
// configurable trial length. Touches: SQLite.
type TrialAbusePrevention struct {
	db        *sql.DB
	now       func() time.Time
	TrialDays int
}

// GateError is a gate FAIL that stops signup or subscription creation: ErrorCode is the spec's error
// ("email_has_trial_history" 409, "too_many_signups_from_ip" 429, "device_suspected_fraud" 403,
// "payment_method_used_for_multiple_trials" 403, "trial_ended_no_payment_cannot_retry" 403,
// "chargeback_history_requires_prepayment" 403) and Result the gate's decision.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: callers could not tell which gate failed.
type GateError struct {
	ErrorCode string
	Result    GateResult
}

// Error returns the spec error code.
func (e *GateError) Error() string { return e.ErrorCode }

// NewTrialAbusePrevention opens dbPath (":memory:" for tests, kept on one connection so every call sees
// the same database) and creates the tables. Out: the service or an error.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: one connection for :memory:, clock and TrialDays
// defaults. Touches: SQLite.
func NewTrialAbusePrevention(dbPath string) (*TrialAbusePrevention, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if dbPath == ":memory:" {
		db.SetMaxOpenConns(1)
	}
	tap := &TrialAbusePrevention{db: db, now: func() time.Time { return time.Now().UTC() }, TrialDays: 14}
	if err := tap.initSchema(context.Background()); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return tap, nil
}

// SetClock replaces the clock (tests fix "now"). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
func (tap *TrialAbusePrevention) SetClock(now func() time.Time) { tap.now = now }

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
		userID, gateName, string(decision), string(inputsJSON), string(outputsJSON), tap.now().UTC())
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
		ip, tap.now().UTC().Add(-24*time.Hour)).Scan(&count)
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

// CheckDeviceFingerprint decides gate 4 without writing anything.
//
// In: the user id ("" for a user not created yet: every user on the device then counts) and the device
// hash. Out: the GateResult; Meta has matching_users (OTHER users on the device) and is_known_device.
// Decision, in this order: FAIL (403 device_suspected_fraud) if matching_users >= 5; PASS if < 2; PASS if
// this user already has a row for the device; CHALLENGE otherwise.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (TRIAL-09, TRIAL-14): it counted the user too,
// PASSed any known device even at 5+ others, and its CHALLENGE range (<= 5) overlapped FAIL.
// Touches: SQLite (read).
func (tap *TrialAbusePrevention) CheckDeviceFingerprint(ctx context.Context, userID, deviceHash string) GateResult {
	var uid any
	if userID != "" {
		uid = userID
	}
	var count int
	err := tap.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT user_id) FROM device_fingerprints WHERE device_hash = ? AND (? IS NULL OR user_id != ?)`,
		deviceHash, uid, uid).Scan(&count)
	if err != nil {
		return GateResult{Gate: "device_fingerprint", Decision: DecisionFail, Reason: "database error", Code: 500}
	}
	isKnownDevice := false
	if userID != "" {
		var knownCount int
		if err := tap.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM device_fingerprints WHERE user_id = ? AND device_hash = ?`,
			userID, deviceHash).Scan(&knownCount); err != nil {
			return GateResult{Gate: "device_fingerprint", Decision: DecisionFail, Reason: "database error", Code: 500}
		}
		isKnownDevice = knownCount > 0
	}

	decision, code, reason := DecisionChallenge, 200, "device shared by other users, send verification email"
	switch {
	case count >= 5:
		decision, code, reason = DecisionFail, 403, "device suspected fraud"
	case count < 2:
		decision, reason = DecisionPass, "device not suspicious"
	case isKnownDevice:
		decision, reason = DecisionPass, "the user's own device"
	}
	return GateResult{
		Gate:     "device_fingerprint",
		Decision: decision,
		Reason:   reason,
		Code:     code,
		Meta:     map[string]any{"device_hash": deviceHash, "matching_users": int64(count), "is_known_device": isKnownDevice},
	}
}

// CheckAndRecordDevice runs gate 4 for an existing user and, only after a PASS or CHALLENGE, records the
// device row (once per user and device). A FAIL records nothing.
// In: user id and the device. Out: the GateResult. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
// (TRIAL-14: "the device row is written AFTER the decision, and only for PASS or CHALLENGE").
// Touches: SQLite (device_fingerprints, gate_decisions).
func (tap *TrialAbusePrevention) CheckAndRecordDevice(ctx context.Context, userID string, device DeviceInfo) (GateResult, error) {
	deviceHash := tap.HashDevice(device)
	gate := tap.CheckDeviceFingerprint(ctx, userID, deviceHash)
	_ = tap.logGateDecision(ctx, userID, "device_fingerprint", gate.Decision, gate.Meta, map[string]any{})
	if gate.Code == 500 {
		return gate, errors.New(gate.Reason)
	}
	if gate.Decision == DecisionFail {
		return gate, nil
	}
	return gate, tap.recordDevice(ctx, tap.db, userID, deviceHash, device)
}

// recordDevice inserts the user's device row unless it exists. Added 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite (device_fingerprints).
func (tap *TrialAbusePrevention) recordDevice(ctx context.Context, ex execer, userID, deviceHash string, device DeviceInfo) error {
	_, err := ex.ExecContext(ctx,
		`INSERT INTO device_fingerprints (user_id, device_hash, user_agent, screen_resolution, timezone, created_at)
		 SELECT ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM device_fingerprints WHERE user_id = ? AND device_hash = ?)`,
		userID, deviceHash, device.UserAgent, device.ScreenResolution, device.Timezone, tap.now().UTC(), userID, deviceHash)
	return err
}

// execer is *sql.DB or *sql.Tx. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// CheckTrialPaymentTiming decides gate 5 as a payment method is added (the payment date is now).
//
// In: the user id and the trial length in days (<= 0 means TrialDays, default 14). Out: the GateResult;
// Meta has days_after_trial, earlier_payment and trial_days.
// trial_end = the user's first trial start + trial_days; days_after_trial = floor((now - trial_end) / 1 day),
// rounding toward negative infinity; earlier_payment = the ledger already has a payment_added_date for the
// user. PASS if days_after_trial < 5; FAIL (403 trial_ended_no_payment_cannot_retry) if >= 90 and no earlier
// payment; CHALLENGE otherwise. A user with no ledger row FAILs closed (user_not_found), as in Python.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (TRIAL-10/11/15): it counted days since the trial
// START, truncated, with windows of its own, and PASSed a user it could not find. Touches: SQLite (read).
func (tap *TrialAbusePrevention) CheckTrialPaymentTiming(ctx context.Context, userID string, trialDays int) GateResult {
	if trialDays <= 0 {
		trialDays = tap.TrialDays
	}
	var started sql.NullString
	var payments int
	err := tap.db.QueryRowContext(ctx,
		`SELECT MIN(trial_started_at), COUNT(payment_added_date) FROM trial_abuse_ledger WHERE user_id = ?`,
		userID).Scan(&started, &payments)
	if err != nil {
		return GateResult{Gate: "trial_payment_timing", Decision: DecisionFail, Reason: "database error", Code: 500}
	}
	if !started.Valid {
		return GateResult{Gate: "trial_payment_timing", Decision: DecisionFail, Reason: "user_not_found", Code: 403,
			Meta: map[string]any{"trial_days": trialDays}}
	}
	start, err := parseDBTime(started.String)
	if err != nil {
		return GateResult{Gate: "trial_payment_timing", Decision: DecisionFail, Reason: "bad trial start", Code: 500}
	}
	trialEnd := start.Add(time.Duration(trialDays) * 24 * time.Hour)
	daysAfterTrial := floorDays(tap.now().Sub(trialEnd))
	earlierPayment := payments > 0

	decision, code, reason := DecisionChallenge, 200, "late payment entry"
	switch {
	case daysAfterTrial < 5:
		decision, reason = DecisionPass, "payment within 5 days of the trial end"
	case daysAfterTrial >= 90 && !earlierPayment:
		decision, code, reason = DecisionFail, 403, "trial ended, no payment, cannot retry after 90 days"
	}
	return GateResult{
		Gate:     "trial_payment_timing",
		Decision: decision,
		Reason:   reason,
		Code:     code,
		Meta:     map[string]any{"days_after_trial": daysAfterTrial, "earlier_payment": earlierPayment, "trial_days": trialDays},
	}
}

// floorDays is d in whole days rounded toward negative infinity (-1 s is day -1, not 0).
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec: floor, not truncation). Touches nothing.
func floorDays(d time.Duration) int64 {
	day := int64(24 * time.Hour)
	n := int64(d)
	q := n / day
	if n%day != 0 && n < 0 {
		q--
	}
	return q
}

// parseDBTime reads a timestamp the SQLite driver stored from a time.Time.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func parseDBTime(v string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02 15:04:05.999999999 -0700 MST", "2006-01-02 15:04:05.999999999 -0700 -0700",
		time.RFC3339Nano, "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05.999999999", "2006-01-02T15:04:05.999999999"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognised time %q", v)
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

// OnSignup runs the signup gates, then records the signup and the device.
//
// In: email, password (not stored here), the server-observed IP and the device. Out: the new user id and
// the email and IP gate results, or a *GateError: email 409 email_has_trial_history, IP 429
// too_many_signups_from_ip, device 403 device_suspected_fraud. Every gate runs BEFORE anything is recorded,
// so a FAIL records no ledger or device row; the ledger row and the device row are written in one
// transaction.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (TRIAL-09/14): the device gate now runs here, before
// the device is recorded (it used to be recorded unchecked, so a device farm never failed); user ids are
// random, not the clock's nanoseconds; challenge flags are merged into gate_flags instead of replacing them.
// Touches: SQLite (trial_abuse_ledger, device_fingerprints, gate_decisions); crypto/rand.
func (tap *TrialAbusePrevention) OnSignup(ctx context.Context, input SignupInput) (string, GateResult, GateResult, error) {
	emailGate := tap.CheckEmailTrialHistory(ctx, input.Email)
	if emailGate.Decision == DecisionFail {
		return "", emailGate, GateResult{}, &GateError{ErrorCode: "email_has_trial_history", Result: emailGate}
	}
	ipGate := tap.CheckIPSignupRateLimit(ctx, input.IP)
	if ipGate.Decision == DecisionFail {
		return "", emailGate, ipGate, &GateError{ErrorCode: "too_many_signups_from_ip", Result: ipGate}
	}
	deviceHash := tap.HashDevice(input.Device)
	deviceGate := tap.CheckDeviceFingerprint(ctx, "", deviceHash)
	if deviceGate.Decision == DecisionFail {
		_ = tap.logGateDecision(ctx, "", "device_fingerprint", deviceGate.Decision, deviceGate.Meta, map[string]any{})
		return "", emailGate, ipGate, &GateError{ErrorCode: "device_suspected_fraud", Result: deviceGate}
	}

	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		return "", emailGate, ipGate, err
	}
	userID := "user_" + hex.EncodeToString(idBytes)

	gateFlags := map[string]string{
		"email":  emailGate.Decision.String(),
		"ip":     ipGate.Decision.String(),
		"device": deviceGate.Decision.String(),
	}
	if emailGate.Decision == DecisionChallenge {
		gateFlags["email_trial_attempt_2+"] = "true"
	}
	if ipGate.Decision == DecisionChallenge {
		gateFlags["captcha_required"] = "true"
	}
	gateFlagsJSON, _ := json.Marshal(gateFlags)

	now := tap.now().UTC()
	tx, err := tap.db.BeginTx(ctx, nil)
	if err != nil {
		return "", emailGate, ipGate, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx,
		`INSERT INTO trial_abuse_ledger (user_id, email, ip, device_fingerprint, signup_date, trial_started_at, subscription_status, gate_flags, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, 'trial', ?, ?)`,
		userID, input.Email, input.IP, deviceHash, now, now, string(gateFlagsJSON), now)
	if err != nil {
		return "", emailGate, ipGate, fmt.Errorf("insert ledger: %w", err)
	}
	ledgerID, _ := result.LastInsertId()
	if err := tap.recordDevice(ctx, tx, userID, deviceHash, input.Device); err != nil {
		return "", emailGate, ipGate, fmt.Errorf("insert device fingerprint: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", emailGate, ipGate, err
	}

	_ = tap.logGateDecision(ctx, userID, "email_trial_history", emailGate.Decision, emailGate.Meta, map[string]any{"user_id": userID, "ledger_id": ledgerID})
	_ = tap.logGateDecision(ctx, userID, "ip_signup_rate_limit", ipGate.Decision, ipGate.Meta, map[string]any{"user_id": userID, "ledger_id": ledgerID})
	_ = tap.logGateDecision(ctx, userID, "device_fingerprint", deviceGate.Decision, deviceGate.Meta, map[string]any{"user_id": userID, "ledger_id": ledgerID})
	return userID, emailGate, ipGate, nil
}

// OnSubscriptionCreated runs the payment gates and records the payment on the user's ledger.
// In: the user id (verified caller), payment method and customer, and the trial length (<= 0 = default).
// Out: the three gate results, or a *GateError (403) for the first FAIL.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: typed errors, the gate flags are merged (they were
// replaced) and created_at is no longer overwritten. Touches: SQLite.
func (tap *TrialAbusePrevention) OnSubscriptionCreated(ctx context.Context, input PaymentInput, trialDays int) (GateResult, GateResult, GateResult, error) {
	paymentGate := tap.CheckPaymentMethodHistory(ctx, input.StripePaymentMethodID)
	timingGate := tap.CheckTrialPaymentTiming(ctx, input.UserID, trialDays)
	chargebackGate := tap.CheckChargebackHistory(ctx, input.UserID, input.StripeCustomerID)

	if paymentGate.Decision == DecisionFail {
		return paymentGate, timingGate, chargebackGate, &GateError{ErrorCode: "payment_method_used_for_multiple_trials", Result: paymentGate}
	}
	if timingGate.Decision == DecisionFail {
		return paymentGate, timingGate, chargebackGate, &GateError{ErrorCode: "trial_ended_no_payment_cannot_retry", Result: timingGate}
	}
	if chargebackGate.Decision == DecisionFail {
		return paymentGate, timingGate, chargebackGate, &GateError{ErrorCode: "chargeback_history_requires_prepayment", Result: chargebackGate}
	}

	now := tap.now().UTC()
	flags := map[string]string{}
	var existing sql.NullString
	_ = tap.db.QueryRowContext(ctx, `SELECT gate_flags FROM trial_abuse_ledger WHERE user_id = ? ORDER BY id DESC LIMIT 1`, input.UserID).Scan(&existing)
	if existing.Valid {
		_ = json.Unmarshal([]byte(existing.String), &flags)
	}
	flags["payment"] = paymentGate.Decision.String()
	flags["timing"] = timingGate.Decision.String()
	flags["chargeback"] = chargebackGate.Decision.String()
	if timingGate.Decision == DecisionChallenge {
		flags["late_payment_entry"] = "true"
	}
	gateFlagsJSON, _ := json.Marshal(flags)

	_, err := tap.db.ExecContext(ctx,
		`UPDATE trial_abuse_ledger SET 
			stripe_payment_method_id = ?,
			payment_added_date = ?,
			subscription_status = 'completed',
			gate_flags = ?
		 WHERE user_id = ?`,
		input.StripePaymentMethodID, now, string(gateFlagsJSON), input.UserID)
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

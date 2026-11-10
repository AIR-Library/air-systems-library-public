// Package billing is the AOI Systems Library billing template: Stripe subscriptions (create, change
// plan with proration), a refund queue (queued, never auto-executed), and an idempotent, signature-
// verified Stripe webhook handler, recorded in SQL tables with an audit log.
//
// Repair 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): the suite did not compile against
// any stripe-go release (stripe.Client, stripe.GetClient, invoice.Invoice and
// subscription.Subscription do not exist; v76 names the item params SubscriptionItemsParams). Stripe
// now sits behind the StripeAPI interface: StripeClient is the real adapter on stripe-go v76's
// client.API, and the tests use an in-memory fake. Also repaired, to match the spec
// (GEMINI_DISPATCH_MASTER_SPEC.txt, template #4) and the passing Python template: webhook signatures
// are always verified (an unset STRIPE_WEBHOOK_SECRET used to skip verification, so anyone could
// post "invoice paid"), with Stripe's 5-minute timestamp tolerance against replays; each webhook is
// applied in one transaction together with its idempotency row, and a storage failure returns an
// error so Stripe retries instead of the event being marked processed and lost; refunds cannot
// exceed what is left of the invoice; a subscription update with an unknown price no longer blanks
// the tier. Touches: SQL database, network and money (Stripe API, through StripeAPI only).
package billing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/stripe/stripe-go/v76"
	stripeclient "github.com/stripe/stripe-go/v76/client"
)

// PriceID maps a tier to its Stripe price ID. The defaults are placeholders; set
// STRIPE_PRICE_SOLO / STRIPE_PRICE_TEAM / STRIPE_PRICE_ENTERPRISE to your account's price ids.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (environment overrides).
var PriceID = map[string]string{
	"solo":       envOr("STRIPE_PRICE_SOLO", "price_1UIsolo"),
	"team":       envOr("STRIPE_PRICE_TEAM", "price_1UIteam"),
	"enterprise": envOr("STRIPE_PRICE_ENTERPRISE", "price_1UIent"),
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// WebhookTolerance is how old a webhook signature timestamp may be (Stripe's default, 5 minutes).
const WebhookTolerance = 5 * time.Minute

// StripeAPI is the part of Stripe this template calls. CreateSubscription subscribes a customer to
// a price; RetrieveSubscription reads a subscription with its items; UpdateSubscription sends
// stripe.subscriptions.update with the given params and returns the proration credit in cents
// (positive = credit to the customer).
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Changed the same day (Phase B, BILL-03):
// retrieve and update are separate calls, so ChangePlan itself picks the existing item id and refuses
// a subscription without exactly one item before any update, and a test can see the exact params.
// Touches: network, money.
type StripeAPI interface {
	CreateSubscription(ctx context.Context, customerID, priceID string) (*stripe.Subscription, error)
	RetrieveSubscription(ctx context.Context, subscriptionID string) (*stripe.Subscription, error)
	UpdateSubscription(ctx context.Context, subscriptionID string, params *stripe.SubscriptionParams) (prorationCredit int64, err error)
}

// StripeClient is the production StripeAPI on stripe-go v76.
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: network (api.stripe.com), money.
type StripeClient struct {
	api *stripeclient.API
}

// NewStripeClient returns a StripeClient for a secret key. Added 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing until called.
func NewStripeClient(secretKey string) *StripeClient {
	return &StripeClient{api: stripeclient.New(secretKey, nil)}
}

// CreateSubscription calls stripe.subscriptions.create({customer, items: [{price}]}).
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: network, money.
func (c *StripeClient) CreateSubscription(ctx context.Context, customerID, priceID string) (*stripe.Subscription, error) {
	params := &stripe.SubscriptionParams{
		Customer: stripe.String(customerID),
		Items:    []*stripe.SubscriptionItemsParams{{Price: stripe.String(priceID)}},
	}
	params.Context = ctx
	return c.api.Subscriptions.New(params)
}

// RetrieveSubscription calls stripe.subscriptions.retrieve(id); the result carries its items.
// In: the Stripe subscription id. Out: the subscription or Stripe's error.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (BILL-03). Touches: network.
func (c *StripeClient) RetrieveSubscription(ctx context.Context, subscriptionID string) (*stripe.Subscription, error) {
	get := &stripe.SubscriptionParams{}
	get.Context = ctx
	return c.api.Subscriptions.Get(subscriptionID, get)
}

// UpdateSubscription calls stripe.subscriptions.update(id, params), then reads the upcoming invoice
// and returns the credit from its negative proration lines (0 if the preview fails: the plan has
// already changed, the preview is informational only).
// In: the Stripe subscription id and the update params. Out: the proration credit in cents.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (BILL-03). Touches: network, money.
func (c *StripeClient) UpdateSubscription(ctx context.Context, subscriptionID string, params *stripe.SubscriptionParams) (int64, error) {
	params.Context = ctx
	if _, err := c.api.Subscriptions.Update(subscriptionID, params); err != nil {
		return 0, err
	}
	up := &stripe.InvoiceUpcomingParams{Subscription: stripe.String(subscriptionID)}
	up.Context = ctx
	inv, err := c.api.Invoices.Upcoming(up)
	if err != nil {
		return 0, nil
	}
	var credit int64
	if inv.Lines != nil {
		for _, l := range inv.Lines.Data {
			if l.Proration && l.Amount < 0 {
				credit -= l.Amount
			}
		}
	}
	return credit, nil
}

// BillingService handles subscriptions, invoices, refunds, and webhooks.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: StripeAPI instead of *stripe.Client.
type BillingService struct {
	db     *sql.DB
	stripe StripeAPI
	now    func() time.Time
	// WebhookSecret overrides STRIPE_WEBHOOK_SECRET (read at call time when empty).
	WebhookSecret string
}

// NewBillingService builds the service with the real Stripe client from STRIPE_SECRET_KEY.
// Output: error if the key is unset. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: environment only.
func NewBillingService(db *sql.DB) (*BillingService, error) {
	key := os.Getenv("STRIPE_SECRET_KEY")
	if key == "" {
		return nil, fmt.Errorf("STRIPE_SECRET_KEY not set")
	}
	return NewBillingServiceWithClient(db, NewStripeClient(key)), nil
}

// NewBillingServiceWithClient injects any StripeAPI (a fake in tests).
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
func NewBillingServiceWithClient(db *sql.DB, client StripeAPI) *BillingService {
	return &BillingService{db: db, stripe: client, now: time.Now}
}

// Schema is the executable DDL for all billing tables.
const Schema = `
CREATE TABLE IF NOT EXISTS subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  stripe_subscription_id TEXT UNIQUE NOT NULL,
  customer_id TEXT NOT NULL,
  tier TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  cancelled_at TEXT
);
CREATE TABLE IF NOT EXISTS invoices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  stripe_invoice_id TEXT UNIQUE NOT NULL,
  customer_id TEXT NOT NULL,
  amount INTEGER NOT NULL,
  status TEXT NOT NULL,
  paid_at TEXT
);
CREATE TABLE IF NOT EXISTS refunds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  invoice_id TEXT NOT NULL,
  amount INTEGER NOT NULL,
  status TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  executed_at TEXT
);
CREATE TABLE IF NOT EXISTS events (
  stripe_event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  processed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action TEXT NOT NULL,
  customer_id TEXT,
  detail TEXT,
  created_at TEXT NOT NULL
);
`

// Migrate applies the schema.
func (s *BillingService) Migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, Schema)
	return err
}

// nowUTC returns the current time as UTC ISO 8601 (spec: "Timestamps: UTC, ISO 8601").
func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

// execer is satisfied by *sql.DB and *sql.Tx.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

// audit writes one audit_log row through db or the caller's transaction. Output: the error (it
// used to be dropped). Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
func audit(ctx context.Context, ex execer, action, customerID string, detail map[string]interface{}) error {
	var d interface{}
	if detail != nil {
		b, _ := json.Marshal(detail)
		d = string(b)
	}
	_, err := ex.ExecContext(ctx, "INSERT INTO audit_log (action, customer_id, detail, created_at) VALUES (?,?,?,?)",
		action, customerID, d, nowUTC())
	return err
}

// CreateSubscription subscribes customerID to tier through Stripe and records it.
// Output: {success, subscription_id, tier, status:"active", next_billing_date}; 400 invalid_tier.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: Stripe (money), database.
func (s *BillingService) CreateSubscription(ctx context.Context, customerID, tier string) (map[string]interface{}, error) {
	price, ok := PriceID[tier]
	if !ok {
		return nil, &APIError{Code: "invalid_tier", Message: "unknown tier: " + tier, Status: http.StatusBadRequest}
	}
	if strings.TrimSpace(customerID) == "" {
		return nil, &APIError{Code: "invalid_customer", Message: "customer_id required", Status: http.StatusBadRequest}
	}
	sub, err := s.stripe.CreateSubscription(ctx, customerID, price)
	if err != nil {
		return nil, &APIError{Code: "stripe_error", Message: "Stripe rejected the subscription", Status: http.StatusBadGateway}
	}
	created := nowUTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO subscriptions (stripe_subscription_id, customer_id, tier, status, created_at, updated_at)
		 VALUES (?,?,?,?,?,?)`, sub.ID, customerID, tier, "active", created, created); err != nil {
		return nil, err
	}
	if err = audit(ctx, tx, "subscription_created", customerID, map[string]interface{}{"tier": tier, "stripe_sub_id": sub.ID}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	next := time.Now().UTC().AddDate(0, 1, 0)
	if sub.CurrentPeriodEnd > 0 {
		next = time.Unix(sub.CurrentPeriodEnd, 0).UTC()
	}
	return map[string]interface{}{
		"success":           true,
		"subscription_id":   sub.ID,
		"tier":              tier,
		"status":            "active",
		"next_billing_date": next.Format(time.RFC3339),
	}, nil
}

// ChangePlan moves a subscription (Stripe id or local id) to newTier through Stripe, then records
// it. Order (spec flow 2, amended 2026-11-10): unknown tier -> 400 invalid_tier; unknown subscription ->
// 404 not_found; stripe.subscriptions.retrieve, and not exactly one item -> 409
// subscription_item_ambiguous; only then stripe.subscriptions.update with
// {items: [{id: current_item_id, price}], proration_behavior: "create_prorations"}, so Stripe swaps the
// price instead of adding a second item that would bill both plans.
// Output: {success, subscription_id, old_tier, new_tier, effective_date, proration_credit}.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (BILL-03). Touches: Stripe (money), database.
func (s *BillingService) ChangePlan(ctx context.Context, subscriptionID, newTier string) (map[string]interface{}, error) {
	price, ok := PriceID[newTier]
	if !ok {
		return nil, &APIError{Code: "invalid_tier", Message: "unknown tier: " + newTier, Status: http.StatusBadRequest}
	}
	var oldTier, stripeSubID, customerID string
	err := s.db.QueryRowContext(ctx,
		"SELECT tier, stripe_subscription_id, customer_id FROM subscriptions WHERE stripe_subscription_id=? OR CAST(id AS TEXT)=?",
		subscriptionID, subscriptionID).Scan(&oldTier, &stripeSubID, &customerID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &APIError{Code: "not_found", Message: "subscription not found", Status: http.StatusNotFound}
	}
	if err != nil {
		return nil, err
	}
	current, err := s.stripe.RetrieveSubscription(ctx, stripeSubID)
	if err != nil {
		return nil, &APIError{Code: "stripe_error", Message: "Stripe could not read the subscription", Status: http.StatusBadGateway}
	}
	if current == nil || current.Items == nil || len(current.Items.Data) != 1 || current.Items.Data[0] == nil {
		return nil, &APIError{Code: "subscription_item_ambiguous",
			Message: "the subscription does not have exactly one item", Status: http.StatusConflict}
	}
	credit, err := s.stripe.UpdateSubscription(ctx, stripeSubID, &stripe.SubscriptionParams{
		Items:             []*stripe.SubscriptionItemsParams{{ID: stripe.String(current.Items.Data[0].ID), Price: stripe.String(price)}},
		ProrationBehavior: stripe.String("create_prorations"),
	})
	if err != nil {
		return nil, &APIError{Code: "stripe_error", Message: "Stripe rejected the plan change", Status: http.StatusBadGateway}
	}
	updated := nowUTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE subscriptions SET tier=?, updated_at=? WHERE stripe_subscription_id=?",
		newTier, updated, stripeSubID); err != nil {
		return nil, err
	}
	if err = audit(ctx, tx, "plan_changed", customerID, map[string]interface{}{
		"subscription_id": stripeSubID, "old_tier": oldTier, "new_tier": newTier, "proration_credits": credit}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"success":          true,
		"subscription_id":  subscriptionID,
		"old_tier":         oldTier,
		"new_tier":         newTier,
		"effective_date":   updated,
		"proration_credit": credit,
	}, nil
}

// QueueRefund queues (never executes) a refund for a succeeded invoice. Checks: amount > 0 and
// amount plus refunds already queued or executed <= invoice amount. Output: {success, refund_id,
// status:"queued", amount, reason}; 404 not_found, 400 invalid_amount / invalid_invoice_status /
// refund_exceeds_invoice. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (positive
// amounts, cumulative limit, one transaction). Touches: database.
func (s *BillingService) QueueRefund(ctx context.Context, invoiceID string, amount int64, reason, createdBy string) (map[string]interface{}, error) {
	if amount <= 0 {
		return nil, &APIError{Code: "invalid_amount", Message: "amount must be positive", Status: http.StatusBadRequest}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var status, customerID string
	var invAmount int64
	err = tx.QueryRowContext(ctx, "SELECT status, amount, customer_id FROM invoices WHERE stripe_invoice_id=?", invoiceID).
		Scan(&status, &invAmount, &customerID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &APIError{Code: "not_found", Message: "invoice not found", Status: http.StatusNotFound}
	}
	if err != nil {
		return nil, err
	}
	if status != "succeeded" {
		return nil, &APIError{Code: "invalid_invoice_status", Message: "invoice not succeeded", Status: http.StatusBadRequest}
	}
	var already int64
	if err = tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(amount),0) FROM refunds WHERE invoice_id=? AND status IN ('queued','executed')",
		invoiceID).Scan(&already); err != nil {
		return nil, err
	}
	if amount+already > invAmount {
		return nil, &APIError{Code: "refund_exceeds_invoice", Message: "refund exceeds invoice amount", Status: http.StatusBadRequest}
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO refunds (invoice_id, amount, status, reason, created_by, created_at) VALUES (?,?,?,?,?,?)`,
		invoiceID, amount, "queued", reason, createdBy, nowUTC())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	if err = audit(ctx, tx, "refund_queued", customerID, map[string]interface{}{"invoice_id": invoiceID, "amount": amount, "reason": reason}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true, "refund_id": id, "status": "queued", "amount": amount, "reason": reason}, nil
}

// HandleStripeWebhook verifies the Stripe-Signature header, then applies the event exactly once:
// the events row (idempotency) and the event's changes commit in one transaction. Output:
// {received:true}; 500 missing_webhook_secret when no secret is configured, 403 invalid_signature,
// 400 invalid_payload, or a storage error (Stripe then retries).
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
func (s *BillingService) HandleStripeWebhook(ctx context.Context, payload []byte, sigHeader string) (map[string]interface{}, error) {
	secret := s.WebhookSecret
	if secret == "" {
		secret = os.Getenv("STRIPE_WEBHOOK_SECRET")
	}
	if secret == "" {
		return nil, &APIError{Code: "missing_webhook_secret", Message: "webhook secret not configured", Status: http.StatusInternalServerError}
	}
	if !verifySignature(payload, sigHeader, secret, s.now()) {
		return nil, &APIError{Code: "invalid_signature", Message: "invalid webhook signature", Status: http.StatusForbidden}
	}
	var event stripe.Event
	if err := json.Unmarshal(payload, &event); err != nil || event.ID == "" || event.Data == nil {
		return nil, &APIError{Code: "invalid_payload", Message: "bad payload", Status: http.StatusBadRequest}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO events (stripe_event_id, event_type, processed_at) VALUES (?,?,?)",
		event.ID, string(event.Type), nowUTC())
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return map[string]interface{}{"received": true}, nil // already processed
	}
	switch event.Type {
	case "invoice.payment_succeeded":
		err = handlePaymentSucceeded(ctx, tx, event.Data.Raw)
	case "invoice.payment_failed":
		err = handlePaymentFailed(ctx, tx, event.Data.Raw)
	case "customer.subscription.updated":
		err = handleSubscriptionUpdated(ctx, tx, event.Data.Raw)
	case "customer.subscription.deleted":
		err = handleSubscriptionDeleted(ctx, tx, event.Data.Raw)
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return map[string]interface{}{"received": true}, nil
}

func customerOf(c *stripe.Customer) string {
	if c == nil {
		return ""
	}
	return c.ID
}

// handlePaymentSucceeded records the invoice as succeeded and audits it. Changed 2026-11-10,
// session session_012zDydZCZ4AChqhEZ4oVtaP (stripe.Invoice; errors returned). Touches: database.
func handlePaymentSucceeded(ctx context.Context, tx *sql.Tx, raw json.RawMessage) error {
	var inv stripe.Invoice
	if err := json.Unmarshal(raw, &inv); err != nil {
		return &APIError{Code: "invalid_payload", Message: "bad invoice object", Status: http.StatusBadRequest}
	}
	customer := customerOf(inv.Customer)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO invoices (stripe_invoice_id, customer_id, amount, status, paid_at) VALUES (?,?,?,?,?)
		 ON CONFLICT(stripe_invoice_id) DO UPDATE SET amount=excluded.amount, status=excluded.status, paid_at=excluded.paid_at`,
		inv.ID, customer, inv.AmountPaid, "succeeded", nowUTC()); err != nil {
		return err
	}
	return audit(ctx, tx, "payment_succeeded", customer, map[string]interface{}{"invoice_id": inv.ID, "amount": inv.AmountPaid})
}

// handlePaymentFailed marks the invoice's subscription (or, without one, the customer's open
// subscriptions) past_due. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
func handlePaymentFailed(ctx context.Context, tx *sql.Tx, raw json.RawMessage) error {
	var inv stripe.Invoice
	if err := json.Unmarshal(raw, &inv); err != nil {
		return &APIError{Code: "invalid_payload", Message: "bad invoice object", Status: http.StatusBadRequest}
	}
	customer := customerOf(inv.Customer)
	var err error
	if inv.Subscription != nil && inv.Subscription.ID != "" {
		_, err = tx.ExecContext(ctx, "UPDATE subscriptions SET status='past_due', updated_at=? WHERE stripe_subscription_id=? AND status NOT IN ('cancelled','past_due')",
			nowUTC(), inv.Subscription.ID)
	} else {
		_, err = tx.ExecContext(ctx, "UPDATE subscriptions SET status='past_due', updated_at=? WHERE customer_id=? AND status NOT IN ('cancelled','past_due')",
			nowUTC(), customer)
	}
	if err != nil {
		return err
	}
	return audit(ctx, tx, "payment_failed", customer, map[string]interface{}{"invoice_id": inv.ID, "reason": "payment_failed"})
}

// tierFromSubscription returns the tier of the first item: its price lookup_key when that is a
// known tier, else the tier whose configured price id matches, else "" (unknown).
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
func tierFromSubscription(sub *stripe.Subscription) string {
	if sub.Items == nil || len(sub.Items.Data) == 0 || sub.Items.Data[0] == nil || sub.Items.Data[0].Price == nil {
		return ""
	}
	p := sub.Items.Data[0].Price
	if _, ok := PriceID[p.LookupKey]; ok {
		return p.LookupKey
	}
	for tier, id := range PriceID {
		if id == p.ID && p.ID != "" {
			return tier
		}
	}
	return ""
}

// handleSubscriptionUpdated sets tier (items[0].price.lookup_key) and status. An unknown price
// keeps the stored tier. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
func handleSubscriptionUpdated(ctx context.Context, tx *sql.Tx, raw json.RawMessage) error {
	var sub stripe.Subscription
	if err := json.Unmarshal(raw, &sub); err != nil {
		return &APIError{Code: "invalid_payload", Message: "bad subscription object", Status: http.StatusBadRequest}
	}
	var oldTier string
	err := tx.QueryRowContext(ctx, "SELECT tier FROM subscriptions WHERE stripe_subscription_id=?", sub.ID).Scan(&oldTier)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // not one of ours
	}
	if err != nil {
		return err
	}
	tier := tierFromSubscription(&sub)
	if tier == "" {
		tier = oldTier
	}
	if _, err := tx.ExecContext(ctx, "UPDATE subscriptions SET tier=?, status=?, updated_at=? WHERE stripe_subscription_id=?",
		tier, string(sub.Status), nowUTC(), sub.ID); err != nil {
		return err
	}
	return audit(ctx, tx, "subscription_updated", customerOf(sub.Customer), map[string]interface{}{"old_tier": oldTier, "new_tier": tier})
}

// handleSubscriptionDeleted marks the subscription cancelled. Changed 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
func handleSubscriptionDeleted(ctx context.Context, tx *sql.Tx, raw json.RawMessage) error {
	var sub stripe.Subscription
	if err := json.Unmarshal(raw, &sub); err != nil {
		return &APIError{Code: "invalid_payload", Message: "bad subscription object", Status: http.StatusBadRequest}
	}
	now := nowUTC()
	if _, err := tx.ExecContext(ctx, "UPDATE subscriptions SET status='cancelled', cancelled_at=?, updated_at=? WHERE stripe_subscription_id=?",
		now, now, sub.ID); err != nil {
		return err
	}
	return audit(ctx, tx, "subscription_cancelled", customerOf(sub.Customer), nil)
}

// verifySignature checks a Stripe-Signature header ("t=<unix>,v1=<hex>[,v1=...]"): some v1 must be
// HMAC-SHA256(secret, "<t>.<payload>"), compared in constant time, and t must be within
// WebhookTolerance of now. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (several v1
// values, timestamp tolerance). Touches: nothing.
func verifySignature(payload []byte, sigHeader, secret string, now time.Time) bool {
	var timestamp string
	var sigs [][]byte
	for _, p := range strings.Split(sigHeader, ",") {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			timestamp = kv[1]
		case "v1":
			if b, err := hex.DecodeString(kv[1]); err == nil {
				sigs = append(sigs, b)
			}
		}
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || len(sigs) == 0 {
		return false
	}
	if age := now.Sub(time.Unix(ts, 0)); age > WebhookTolerance || age < -WebhookTolerance {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(payload)
	expected := mac.Sum(nil)
	ok := false
	for _, sig := range sigs {
		if hmac.Equal(expected, sig) {
			ok = true
		}
	}
	return ok
}

// APIError is a structured error with a JSON code and HTTP status.
type APIError struct {
	Code    string
	Message string
	Status  int
}

func (e *APIError) Error() string { return e.Code + ": " + e.Message }

// WriteJSON writes a response body as JSON.
func WriteJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ErrorJSON renders an APIError in the spec's {error, message} shape.
func ErrorJSON(e *APIError) map[string]interface{} {
	return map[string]interface{}{"error": e.Code, "message": e.Message}
}

// AmountFromCents parses a string amount into int64 cents; ok is false for anything that is not
// a whole number. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (a parse error used to
// read as 0). Touches: nothing.
func AmountFromCents(s string) (int64, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n, err == nil
}

package billing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stripe/stripe-go/v76"
	_ "github.com/mattn/go-sqlite3"
)

// fakeStripe is the in-memory StripeAPI the tests use: it records calls and never touches the
// network. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (the tests called
// stripe.GetClient(), which does not exist in any stripe-go release).
type fakeStripe struct {
	created []string // "customer|price"
	changed []string // "subscription|item id|price|proration_behavior" (one per update call)
	updates int
	items   map[string][]string // subscription id -> its item ids; a missing id has one item "si_<id>"
	credit  int64
}

// CreateSubscription records the call and returns a subscription with a sequential fake id.
func (f *fakeStripe) CreateSubscription(_ context.Context, customerID, priceID string) (*stripe.Subscription, error) {
	f.created = append(f.created, customerID+"|"+priceID)
	return &stripe.Subscription{ID: fmt.Sprintf("sub_fake_%d", len(f.created)), Status: "active"}, nil
}

// RetrieveSubscription returns the subscription with its configured items (default: one item,
// "si_<subscription id>"). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (BILL-03). Touches nothing.
func (f *fakeStripe) RetrieveSubscription(_ context.Context, subscriptionID string) (*stripe.Subscription, error) {
	ids, ok := f.items[subscriptionID]
	if !ok {
		ids = []string{"si_" + subscriptionID}
	}
	list := &stripe.SubscriptionItemList{}
	for _, id := range ids {
		list.Data = append(list.Data, &stripe.SubscriptionItem{ID: id})
	}
	return &stripe.Subscription{ID: subscriptionID, Items: list}, nil
}

// UpdateSubscription records every item it is sent as "subscription|item id|price|proration" and
// returns the configured proration credit. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: was
// ChangeSubscriptionPrice, which hid the item id from the test. Touches nothing.
func (f *fakeStripe) UpdateSubscription(_ context.Context, subscriptionID string, params *stripe.SubscriptionParams) (int64, error) {
	f.updates++
	proration := ""
	if params.ProrationBehavior != nil {
		proration = *params.ProrationBehavior
	}
	for _, it := range params.Items {
		id, price := "", ""
		if it.ID != nil {
			id = *it.ID
		}
		if it.Price != nil {
			price = *it.Price
		}
		f.changed = append(f.changed, subscriptionID+"|"+id+"|"+price+"|"+proration)
	}
	return f.credit, nil
}

// signed configures a webhook secret for this test and returns a valid Stripe-Signature header for
// payload. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the spec requires every webhook
// to be verified with STRIPE_WEBHOOK_SECRET before processing, so unsigned calls are now rejected.
func signed(t *testing.T, payload []byte) string {
	t.Helper()
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_unit")
	return sign(payload, "whsec_unit")
}

func newTestService(t *testing.T) *BillingService {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1) // every new connection to :memory: would be a separate, empty database
	svc := NewBillingServiceWithClient(db, &fakeStripe{credit: 250})
	if err := svc.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return svc
}

// BILL-01
func TestCreateSubscriptionHappyPath(t *testing.T) {
	svc := newTestService(t)
	stripe.Key = "sk_test_dummy"
	ctx := context.Background()
	res, err := svc.CreateSubscription(ctx, "cus_123", "solo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res["success"] != true {
		t.Fatalf("expected success true, got %v", res["success"])
	}
	if res["tier"] != "solo" || res["status"] != "active" {
		t.Fatalf("unexpected fields: %v", res)
	}
	var count int
	if err := svc.db.QueryRow("SELECT COUNT(*) FROM subscriptions WHERE customer_id='cus_123'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 subscription row, got %d", count)
	}
	if f := svc.stripe.(*fakeStripe); len(f.created) != 1 || f.created[0] != "cus_123|"+PriceID["solo"] {
		t.Fatalf("expected one Stripe create for cus_123 at the solo price, got %v", f.created)
	}
}

// BILL-02
func TestCreateSubscriptionInvalidTier(t *testing.T) {
	svc := newTestService(t)
	_, err := svc.CreateSubscription(context.Background(), "cus_123", "platinum")
	if err == nil {
		t.Fatal("expected error for invalid tier")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected APIError, got %T", err)
	}
	if apiErr.Code != "invalid_tier" || apiErr.Status != http.StatusBadRequest {
		t.Fatalf("wrong error: %+v", apiErr)
	}
}

// BILL-03
func TestChangePlanHappyPath(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	created := nowUTC()
	_, err := svc.db.ExecContext(ctx,
		`INSERT INTO subscriptions (stripe_subscription_id, customer_id, tier, status, created_at, updated_at)
		 VALUES ('sub_abc','cus_123','solo','active',?,?)`, created, created)
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.ChangePlan(ctx, "sub_abc", "team")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res["old_tier"] != "solo" || res["new_tier"] != "team" {
		t.Fatalf("unexpected tiers: %v", res)
	}
	var tier string
	if err := svc.db.QueryRow("SELECT tier FROM subscriptions WHERE stripe_subscription_id='sub_abc'").Scan(&tier); err != nil {
		t.Fatal(err)
	}
	if tier != "team" {
		t.Fatalf("expected tier team, got %s", tier)
	}
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: BILL-03 (amended) requires the existing item's id
	// with the new price, so Stripe swaps the price instead of adding a second item.
	want := "sub_abc|si_sub_abc|" + PriceID["team"] + "|create_prorations"
	if f := svc.stripe.(*fakeStripe); f.updates != 1 || len(f.changed) != 1 || f.changed[0] != want {
		t.Fatalf("expected one Stripe update %q, got %v", want, f.changed)
	}
	if res["proration_credit"] != int64(250) {
		t.Fatalf("expected the proration credit from Stripe (250), got %v", res["proration_credit"])
	}

	// Unknown tier: 400 invalid_tier, and Stripe is never updated.
	_, err = svc.ChangePlan(ctx, "sub_abc", "platinum")
	if e, ok := err.(*APIError); !ok || e.Status != http.StatusBadRequest || e.Code != "invalid_tier" {
		t.Fatalf("unknown tier: want 400 invalid_tier, got %v", err)
	}
	// Not exactly one item (none, or two): 409 subscription_item_ambiguous, and Stripe is never updated.
	f := svc.stripe.(*fakeStripe)
	for _, items := range [][]string{{}, {"si_1", "si_2"}} {
		f.items = map[string][]string{"sub_abc": items}
		_, err = svc.ChangePlan(ctx, "sub_abc", "enterprise")
		if e, ok := err.(*APIError); !ok || e.Status != http.StatusConflict || e.Code != "subscription_item_ambiguous" {
			t.Fatalf("items %v: want 409 subscription_item_ambiguous, got %v", items, err)
		}
	}
	if f.updates != 1 {
		t.Fatalf("a refused change must not reach stripe.subscriptions.update; updates=%d", f.updates)
	}
	if err := svc.db.QueryRow("SELECT tier FROM subscriptions WHERE stripe_subscription_id='sub_abc'").Scan(&tier); err != nil || tier != "team" {
		t.Fatalf("a refused change must not touch the tier; got %s (%v)", tier, err)
	}
}

// BILL-04
func TestQueueRefundHappyPath(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	_, err := svc.db.ExecContext(ctx,
		`INSERT INTO invoices (stripe_invoice_id, customer_id, amount, status, paid_at)
		 VALUES ('in_1','cus_123',10000,'succeeded',?)`, nowUTC())
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.QueueRefund(ctx, "in_1", 5000, "duplicate", "admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res["status"] != "queued" || res["amount"] != int64(5000) {
		t.Fatalf("unexpected refund: %v", res)
	}
	var status string
	if err := svc.db.QueryRow("SELECT status FROM refunds WHERE invoice_id='in_1'").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "queued" {
		t.Fatalf("expected queued, got %s", status)
	}
}

// BILL-05
func TestQueueRefundExceedsInvoice(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	_, err := svc.db.ExecContext(ctx,
		`INSERT INTO invoices (stripe_invoice_id, customer_id, amount, status, paid_at)
		 VALUES ('in_2','cus_123',1000,'succeeded',?)`, nowUTC())
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.QueueRefund(ctx, "in_2", 2000, "too much", "admin")
	if err == nil {
		t.Fatal("expected error")
	}
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.Code != "refund_exceeds_invoice" || apiErr.Status != http.StatusBadRequest {
		t.Fatalf("wrong error: %+v", err)
	}
}

func buildEvent(t *testing.T, id, typ string, raw interface{}) []byte {
	t.Helper()
	rawBytes, _ := json.Marshal(raw)
	event := stripe.Event{
		ID:   id,
		Type: stripe.EventType(typ),
		Data: &stripe.EventData{Raw: rawBytes},
	}
	b, _ := json.Marshal(event)
	return b
}

// BILL-06
func TestHandleWebhookPaymentSucceeded(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	inv := stripe.Invoice{ID: "in_100", Customer: &stripe.Customer{ID: "cus_9"}, AmountPaid: 999}
	payload := buildEvent(t, "evt_1", "invoice.payment_succeeded", inv)
	res, err := svc.HandleStripeWebhook(ctx, payload, signed(t, payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res["received"] != true {
		t.Fatalf("expected received true: %v", res)
	}
	var status string
	if err := svc.db.QueryRow("SELECT status FROM invoices WHERE stripe_invoice_id='in_100'").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "succeeded" {
		t.Fatalf("expected succeeded, got %s", status)
	}
	var auditCount int
	if err := svc.db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='payment_succeeded'").Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("expected 1 audit row, got %d", auditCount)
	}
}

// BILL-07
func TestHandleWebhookDuplicateEvent(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	inv := stripe.Invoice{ID: "in_200", Customer: &stripe.Customer{ID: "cus_9"}, AmountPaid: 500}
	payload := buildEvent(t, "evt_dup", "invoice.payment_succeeded", inv)
	sig := signed(t, payload)
	if _, err := svc.HandleStripeWebhook(ctx, payload, sig); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.HandleStripeWebhook(ctx, payload, sig); err != nil {
		t.Fatal(err)
	}
	var auditCount int
	if err := svc.db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='payment_succeeded'").Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("idempotency failed, got %d audit rows", auditCount)
	}
}

// BILL-08
func TestHandleWebhookSubscriptionUpdated(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	created := nowUTC()
	_, err := svc.db.ExecContext(ctx,
		`INSERT INTO subscriptions (stripe_subscription_id, customer_id, tier, status, created_at, updated_at)
		 VALUES ('sub_upd','cus_9','solo','active',?,?)`, created, created)
	if err != nil {
		t.Fatal(err)
	}
	sub := stripe.Subscription{
		ID:       "sub_upd",
		Customer: &stripe.Customer{ID: "cus_9"},
		Status:   "active",
		Items:    &stripe.SubscriptionItemList{Data: []*stripe.SubscriptionItem{{Price: &stripe.Price{LookupKey: "team"}}}},
	}
	payload := buildEvent(t, "evt_upd", "customer.subscription.updated", sub)
	if _, err := svc.HandleStripeWebhook(ctx, payload, signed(t, payload)); err != nil {
		t.Fatal(err)
	}
	var tier, status string
	if err := svc.db.QueryRow("SELECT tier, status FROM subscriptions WHERE stripe_subscription_id='sub_upd'").Scan(&tier, &status); err != nil {
		t.Fatal(err)
	}
	if tier != "team" || status != "active" {
		t.Fatalf("expected team/active, got %s/%s", tier, status)
	}
}

// TestWebhookInvalidSignature proves BILL-09: a bad Stripe-Signature is 400 invalid_signature.
// In: none. Out: test failures. Why: Phase B.3 ruling (commit d4f4ed7): BILL-09 answers 400, Stripe's documented
// answer and the same as stripe_webhook_entitlements; the assertion expected 403 before. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test database.
// BILL-09
func TestWebhookInvalidSignature(t *testing.T) {
	svc := newTestService(t)
	os.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
	defer os.Unsetenv("STRIPE_WEBHOOK_SECRET")
	inv := stripe.Invoice{ID: "in_300", Customer: &stripe.Customer{ID: "cus_9"}, AmountPaid: 100}
	payload := buildEvent(t, "evt_sig", "invoice.payment_succeeded", inv)
	_, err := svc.HandleStripeWebhook(context.Background(), payload, "t=123,v1=deadbeef")
	if err == nil {
		t.Fatal("expected signature error")
	}
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.Code != "invalid_signature" || apiErr.Status != http.StatusBadRequest {
		t.Fatalf("wrong error: %+v", err)
	}
}

// BILL-10
func TestWebhookResponseTime(t *testing.T) {
	svc := newTestService(t)
	inv := stripe.Invoice{ID: "in_400", Customer: &stripe.Customer{ID: "cus_9"}, AmountPaid: 100}
	payload := buildEvent(t, "evt_fast", "invoice.payment_succeeded", inv)
	sig := signed(t, payload)
	start := time.Now()
	res, err := svc.HandleStripeWebhook(context.Background(), payload, sig)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if res["received"] != true {
		t.Fatalf("expected received true: %v", res)
	}
	if elapsed >= 3*time.Second {
		t.Fatalf("webhook took too long: %v", elapsed)
	}
}

// sign builds a valid Stripe v1 signature for tests.
func sign(payload []byte, secret string) string {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(payload)
	return fmt.Sprintf("t=%s,v1=%x", ts, mac.Sum(nil))
}

func TestWebhookValidSignature(t *testing.T) {
	svc := newTestService(t)
	os.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_ok")
	defer os.Unsetenv("STRIPE_WEBHOOK_SECRET")
	inv := stripe.Invoice{ID: "in_500", Customer: &stripe.Customer{ID: "cus_9"}, AmountPaid: 100}
	payload := buildEvent(t, "evt_ok", "invoice.payment_succeeded", inv)
	sig := sign(payload, "whsec_ok")
	res, err := svc.HandleStripeWebhook(context.Background(), payload, sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res["received"] != true {
		t.Fatalf("expected received true: %v", res)
	}
}

// TestHTTPHandler exercises the JSON response contract end-to-end.
func TestHTTPHandler(t *testing.T) {
	svc := newTestService(t)
	os.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_http")
	defer os.Unsetenv("STRIPE_WEBHOOK_SECRET")
	inv := stripe.Invoice{ID: "in_600", Customer: &stripe.Customer{ID: "cus_9"}, AmountPaid: 100}
	payload := buildEvent(t, "evt_http", "invoice.payment_succeeded", inv)
	sig := sign(payload, "whsec_http")

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0)
		buf := make([]byte, 1<<20)
		n, _ := r.Body.Read(buf)
		body = append(body, buf[:n]...)
		res, err := svc.HandleStripeWebhook(r.Context(), body, r.Header.Get("Stripe-Signature"))
		if err != nil {
			var apiErr *APIError
			if ok := asAPIError(err, &apiErr); ok {
				WriteJSON(w, apiErr.Status, ErrorJSON(apiErr))
				return
			}
			WriteJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "internal", "message": err.Error()})
			return
		}
		WriteJSON(w, http.StatusOK, res)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/webhook", stringsReader(payload))
	req.Header.Set("Stripe-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["received"] != true {
		t.Fatalf("expected received true: %v", out)
	}
}

func asAPIError(err error, target **APIError) bool {
	if e, ok := err.(*APIError); ok {
		*target = e
		return true
	}
	return false
}

func stringsReader(b []byte) *stringsReaderType { return &stringsReaderType{b: b} }

type stringsReaderType struct {
	b   []byte
	pos int
}

func (r *stringsReaderType) Read(p []byte) (int, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF // the io.Reader contract: a custom "EOF" error makes net/http abort the request
	}
	n := copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}
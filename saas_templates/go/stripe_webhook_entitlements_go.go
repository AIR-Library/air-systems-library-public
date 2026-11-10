// Package stripeentitlements receives Stripe's webhook, proves it came from Stripe, applies every event once
// and in order, and keeps one answer per user: what they are entitled to now
// (docs/specs/stripe_webhook_entitlements.md).
//
// The signature is checked before the body is parsed; the event id is claimed and the event applied in one
// transaction, so a failure that a retry can fix is undone and answered 500. The webhook is the only writer of
// entitlements: no function takes a plan, status or period end from a caller.
//
// Why: Phase D wave 1, owner request 2026-11-10 (spec STRIPEWH-01 to STRIPEWH-14).
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the injected store (memory here; a SQL store follows the spec's schema), the injected Stripe client
// (network in production, a fake in tests), the application's user lookup and the clock. It decides access to
// paid plans (money) but moves none.
package stripeentitlements

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Tolerance is the largest allowed distance in seconds between the signed timestamp and now.
// Why: STRIPEWH-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
const Tolerance = 300

// EventRow is one stripe_events row.
// Why: STRIPEWH-08 (claim). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type EventRow struct {
	EventID    string
	Type       string
	Created    int64
	ReceivedAt int64
	Result     string
}

// SubRow is one entitlement_subscriptions row.
// Why: spec SCHEMA. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type SubRow struct {
	SubscriptionID    string
	UserID            string
	CustomerID        *string
	PriceID           *string
	Plan              *string
	Status            string
	CurrentPeriodEnd  int64
	CancelAtPeriodEnd bool
	EventAt           int64
	EventRank         int64
	UpdatedAt         int64
}

// Tx is the work of one webhook delivery inside one transaction.
// ClaimEvent inserts the event row and reports false when the id is already there (a duplicate-key insert).
// Why: steps 7-9 are one transaction. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database or memory.
type Tx interface {
	ClaimEvent(ev EventRow) (bool, error)
	SetEventResult(eventID, result string) error
	GetSub(subscriptionID string) (*SubRow, error)
	SubsByCustomer(customerID string) ([]SubRow, error)
	PutSub(row SubRow) error
}

// Store runs a transaction (undone when fn returns an error) and reads a user's rows.
// Why: STRIPEWH-13 (undo on error), get_entitlement. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the database or memory.
type Store interface {
	InTx(fn func(tx Tx) error) error
	SubsByUser(userID string) ([]SubRow, error)
}

// MemoryStore is the in-memory Store the tests use. InTx holds the lock and restores a snapshot on error.
// Why: README "storage behind an interface". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
type MemoryStore struct {
	mu     sync.Mutex
	events map[string]EventRow
	subs   map[string]SubRow
}

// NewMemoryStore returns an empty store.
// In: none. Out: store. Why: tests. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{events: map[string]EventRow{}, subs: map[string]SubRow{}}
}

// memTx is the in-memory transaction view; the store's lock is held while it is used.
// Why: InTx. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
type memTx struct{ m *MemoryStore }

// InTx runs fn atomically; an error or a panic restores the maps as they were.
// In: fn. Out: fn's error. Why: STRIPEWH-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) InTx(fn func(tx Tx) error) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ev := make(map[string]EventRow, len(m.events))
	for k, v := range m.events {
		ev[k] = v
	}
	subs := make(map[string]SubRow, len(m.subs))
	for k, v := range m.subs {
		subs[k] = v
	}
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("transaction panicked")
		}
		if err != nil {
			m.events, m.subs = ev, subs
		}
	}()
	return fn(memTx{m})
}

// SubsByUser lists the user's rows.
// In: user. Out: rows. Why: get_entitlement. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) SubsByUser(userID string) ([]SubRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []SubRow{}
	for _, r := range m.subs {
		if r.UserID == userID {
			out = append(out, r)
		}
	}
	return out, nil
}

// ClaimEvent inserts the event row unless its id exists.
// In: row. Out: inserted. Why: CLAIM. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (t memTx) ClaimEvent(ev EventRow) (bool, error) {
	if _, ok := t.m.events[ev.EventID]; ok {
		return false, nil
	}
	t.m.events[ev.EventID] = ev
	return true, nil
}

// SetEventResult stores the result in the event's row.
// In: id, result. Out: error. Why: step 8. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (t memTx) SetEventResult(eventID, result string) error {
	ev := t.m.events[eventID]
	ev.Result = result
	t.m.events[eventID] = ev
	return nil
}

// GetSub returns a copy of the row, or nil.
// In: subscription id. Out: row. Why: SUBSCRIPTION b. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (t memTx) GetSub(id string) (*SubRow, error) {
	if r, ok := t.m.subs[id]; ok {
		return &r, nil
	}
	return nil, nil
}

// SubsByCustomer lists the rows with that customer id.
// In: customer id. Out: rows. Why: SUBSCRIPTION c. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (t memTx) SubsByCustomer(customerID string) ([]SubRow, error) {
	out := []SubRow{}
	for _, r := range t.m.subs {
		if r.CustomerID != nil && *r.CustomerID == customerID {
			out = append(out, r)
		}
	}
	return out, nil
}

// PutSub writes the row.
// In: row. Out: error. Why: SUBSCRIPTION g. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (t memTx) PutSub(row SubRow) error {
	t.m.subs[row.SubscriptionID] = row
	return nil
}

// StripeClient fetches a subscription object as Stripe holds it now.
// Why: STRIPEWH-09, STRIPEWH-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: network (the real one).
type StripeClient interface {
	RetrieveSubscription(subscriptionID string) (map[string]any, error)
}

// Config is the injected configuration.
// Why: spec CONFIGURATION. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type Config struct {
	WebhookSecret      string
	PricePlans         map[string]string
	StripeClient       StripeClient
	UserExists         func(userID string) bool
	PeriodGraceSeconds int64
	Store              Store
	Clock              func() int64
}

// Service handles the webhook and answers get_entitlement.
// Why: STRIPEWH-01 to -14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: see the package comment.
type Service struct {
	cfg Config
}

// New builds the service. A short secret is not refused here: every call then answers 503.
// In: config. Out: service. Why: STRIPEWH-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func New(cfg Config) *Service {
	if cfg.Store == nil {
		cfg.Store = NewMemoryStore()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() int64 { return time.Now().Unix() }
	}
	if cfg.UserExists == nil {
		cfg.UserExists = func(string) bool { return false }
	}
	return &Service{cfg: cfg}
}

// Refusal is a returned refusal {error, status}.
// Why: spec CONVENTIONS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type Refusal struct {
	Error  string `json:"error"`
	Status int    `json:"status"`
}

// Result is handle_webhook's answer: {status: 200, received: true, result} or {status, error}.
// Why: spec handle_webhook. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type Result struct {
	Status   int    `json:"status"`
	Received bool   `json:"received,omitempty"`
	Result   string `json:"result,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Entitlement is get_entitlement's answer; Status is the subscription's status in Stripe's spelling.
// Why: STRIPEWH-07, -10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type Entitlement struct {
	Entitled          bool    `json:"entitled"`
	Plan              *string `json:"plan"`
	Status            string  `json:"status"`
	CurrentPeriodEnd  *int64  `json:"current_period_end"`
	CancelAtPeriodEnd bool    `json:"cancel_at_period_end"`
}

var (
	evtIDRe = regexp.MustCompile(`^evt_[A-Za-z0-9_]{1,200}$`)
	subIDRe = regexp.MustCompile(`^sub_[A-Za-z0-9_]{1,200}$`)
	statRe  = regexp.MustCompile(`^[a-z_]{1,32}$`)
	tRe     = regexp.MustCompile(`^[0-9]{1,12}$`)
	v1Re    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// hmacHex is lower-case hex of HMAC-SHA256(key = UTF-8 of secret, message = t + "." + payload).
// In: secret, t as written, payload. Out: hex. Why: STRIPEWH-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func hmacHex(secret, t string, payload []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(t + "."))
	m.Write(payload)
	return hex.EncodeToString(m.Sum(nil))
}

// SignPayload builds a Stripe-Signature header for tests and test-mode clients.
// In: raw body, secret (whole text, "whsec_" included), timestamp. Out: "t=...,v1=...".
// Why: STRIPEWH-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func SignPayload(payload []byte, secret string, timestamp int64) string {
	t := strconv.FormatInt(timestamp, 10)
	return "t=" + t + ",v1=" + hmacHex(secret, t, payload)
}

// VerifySignature checks the header against the raw body: exactly one t of 1-12 digits, any v1 of 64 lower-case
// hex characters, every candidate compared in constant time, then the 300-second tolerance.
// In: raw body, header, secret, now. Out: the signed timestamp, or 503 webhook_not_configured,
// 400 missing_signature, 400 invalid_signature, 400 timestamp_out_of_tolerance.
// Why: STRIPEWH-02 to -05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func VerifySignature(payload []byte, header, secret string, now int64) (int64, *Refusal) {
	if len(secret) < 16 {
		return 0, &Refusal{Error: "webhook_not_configured", Status: 503}
	}
	if header == "" {
		return 0, &Refusal{Error: "missing_signature", Status: 400}
	}
	invalid := &Refusal{Error: "invalid_signature", Status: 400}
	if len(header) > 4096 {
		return 0, invalid
	}
	tVals, cands := []string{}, []string{}
	for _, el := range strings.Split(header, ",") {
		el = strings.Trim(el, " ")
		eq := strings.IndexByte(el, '=')
		if eq < 0 {
			continue
		}
		name, val := el[:eq], el[eq+1:]
		switch name {
		case "t":
			tVals = append(tVals, val)
		case "v1":
			if v1Re.MatchString(val) {
				cands = append(cands, val)
			}
		}
	}
	if len(tVals) != 1 || !tRe.MatchString(tVals[0]) || len(cands) == 0 {
		return 0, invalid
	}
	expected := []byte(hmacHex(secret, tVals[0], payload))
	hit := false
	for _, c := range cands {
		if hmac.Equal(expected, []byte(c)) {
			hit = true
		}
	}
	if !hit {
		return 0, invalid
	}
	ts, _ := strconv.ParseInt(tVals[0], 10, 64)
	if d := now - ts; d > Tolerance || d < -Tolerance {
		return 0, &Refusal{Error: "timestamp_out_of_tolerance", Status: 400}
	}
	return ts, nil
}

// asTime is TIME: a number (never a bool, text or null) that is finite, whole and 0..99999999999. The webhook
// body gives json.Number (UseNumber); an object from the injected Stripe client may hold float64 (encoding/json's
// default) or a Go integer, and those are numbers too.
// In: decoded value. Out: seconds, ok. Why: STRIPEWH-06, -11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func asTime(v any) (int64, bool) {
	var f float64
	switch n := v.(type) {
	case json.Number:
		p, err := strconv.ParseFloat(string(n), 64)
		if err != nil {
			return 0, false
		}
		f = p
	case float64:
		f = n
	case int64:
		f = float64(n)
	case int:
		f = float64(n)
	default:
		return 0, false
	}
	if math.IsInf(f, 0) || math.IsNaN(f) || f != math.Floor(f) || f < 0 || f > 99999999999 {
		return 0, false
	}
	return int64(f), true
}

// get walks nested objects by key and returns the value, or nil.
// In: value, keys. Out: value. Why: reading event fields. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func get(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

// text returns v as a string when it is one.
// In: value. Out: text, ok. Why: reading event fields. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func text(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// holdsNonFinite reports whether a decoded JSON value (UseNumber: numbers are json.Number) holds, anywhere inside
// it, a number that is not finite as a float64 (1e400: strconv answers ±Inf with ErrRange).
// In: the decoded value. Out: true when one is found. Why: spec db20a03 (Phase B.4): a body holding any
// non-finite number, not only in a TIME field, is 400 invalid_payload as a whole. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func holdsNonFinite(v any) bool {
	switch x := v.(type) {
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		return err != nil || math.IsInf(f, 0) || math.IsNaN(f)
	case float64:
		return math.IsInf(x, 0) || math.IsNaN(x)
	case map[string]any:
		for _, item := range x {
			if holdsNonFinite(item) {
				return true
			}
		}
	case []any:
		for _, item := range x {
			if holdsNonFinite(item) {
				return true
			}
		}
	}
	return false
}

// parseEvent is step 6: strict UTF-8 without a BOM, one JSON value, and the id, type, created and data.object
// rules.
// In: raw body. Out: event object, ok. Why: STRIPEWH-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec db20a03, Phase B.4): a body holding a non-finite
// number anywhere (holdsNonFinite: 1e400 outside created too) is refused; before, only a non-finite created was.
func parseEvent(payload []byte) (map[string]any, bool) {
	if !utf8.Valid(payload) || bytes.HasPrefix(payload, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	ev, ok := v.(map[string]any)
	if !ok || holdsNonFinite(ev) {
		return nil, false
	}
	id, ok := text(ev["id"])
	if !ok || !evtIDRe.MatchString(id) {
		return nil, false
	}
	typ, ok := text(ev["type"])
	if !ok || len(typ) < 1 || len(typ) > 100 {
		return nil, false
	}
	for i := 0; i < len(typ); i++ {
		if typ[i] < 0x20 || typ[i] > 0x7e {
			return nil, false
		}
	}
	if _, ok := asTime(ev["created"]); !ok {
		return nil, false
	}
	if _, ok := get(ev, "data", "object").(map[string]any); !ok {
		return nil, false
	}
	return ev, true
}

// HandleWebhook verifies, parses, claims and applies one delivery.
// In: raw body, Stripe-Signature header ("" when missing). Out: 200 {received, result: applied | duplicate |
// stale | ignored}, or a refusal: 503 webhook_not_configured, 400 missing_signature / invalid_signature /
// timestamp_out_of_tolerance / invalid_payload, 500 processing_failed (nothing kept, so Stripe retries).
// Why: STRIPEWH-01 to -14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the store, the Stripe client (network), user_exists, the clock.
func (s *Service) HandleWebhook(payload []byte, header string) Result {
	now := s.cfg.Clock()
	if _, ref := VerifySignature(payload, header, s.cfg.WebhookSecret, now); ref != nil {
		return Result{Status: ref.Status, Error: ref.Error}
	}
	ev, ok := parseEvent(payload)
	if !ok {
		return Result{Status: 400, Error: "invalid_payload"}
	}
	id, _ := text(ev["id"])
	typ, _ := text(ev["type"])
	created, _ := asTime(ev["created"])
	result := ""
	err := s.cfg.Store.InTx(func(tx Tx) error {
		claimed, err := tx.ClaimEvent(EventRow{EventID: id, Type: typ, Created: created, ReceivedAt: now})
		if err != nil {
			return err
		}
		if !claimed {
			result = "duplicate"
			return nil
		}
		r, err := s.apply(tx, typ, created, get(ev, "data", "object").(map[string]any), now)
		if err != nil {
			return err
		}
		result = r
		return tx.SetEventResult(id, r)
	})
	if err != nil {
		return Result{Status: 500, Error: "processing_failed"}
	}
	return Result{Status: 200, Received: true, Result: result}
}

// apply is APPLY(event): it dispatches by type.
// In: tx, type, created, data.object, now. Out: result, or an error that undoes the transaction.
// Why: STRIPEWH-07 to -14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the Stripe client.
func (s *Service) apply(tx Tx, typ string, created int64, obj map[string]any, now int64) (string, error) {
	hint, _ := text(get(obj, "metadata", "user_id"))
	switch typ {
	case "customer.subscription.created":
		return s.subscription(tx, obj, hint, 0, created, now, false)
	case "customer.subscription.updated":
		return s.subscription(tx, obj, hint, 1, created, now, false)
	case "customer.subscription.deleted":
		return s.subscription(tx, obj, hint, 2, created, now, false)
	case "checkout.session.completed":
		mode, _ := text(obj["mode"])
		subID, ok := text(obj["subscription"])
		if mode != "subscription" || !ok || !subIDRe.MatchString(subID) {
			return "ignored", nil
		}
		row, err := tx.GetSub(subID)
		if err != nil {
			return "", err
		}
		if row != nil && (row.EventAt > created || (row.EventAt == created && row.EventRank > 1)) {
			return "stale", nil
		}
		sub, err := s.retrieve(subID)
		if err != nil {
			return "", err
		}
		h, ok := text(obj["client_reference_id"])
		if !ok || h == "" {
			h, _ = text(get(obj, "metadata", "user_id"))
		}
		return s.subscription(tx, sub, h, 1, created, now, true)
	default:
		return "ignored", nil
	}
}

// retrieve calls the Stripe client; a nil client, an error or a panic is an error.
// In: subscription id. Out: object or error. Why: STRIPEWH-09, -13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the Stripe client (network).
func (s *Service) retrieve(id string) (sub map[string]any, err error) {
	defer func() {
		if recover() != nil {
			sub, err = nil, errors.New("stripe client panicked")
		}
	}()
	if s.cfg.StripeClient == nil {
		return nil, errors.New("no stripe client")
	}
	sub, err = s.cfg.StripeClient.RetrieveSubscription(id)
	if err == nil && sub == nil {
		err = errors.New("empty subscription")
	}
	return sub, err
}

// priceOf returns items.data[0].price.id when it is text.
// In: subscription object. Out: price id, ok. Why: SUBSCRIPTION b. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func priceOf(sub map[string]any) (string, bool) {
	items, ok := get(sub, "items", "data").([]any)
	if !ok || len(items) == 0 {
		return "", false
	}
	return text(get(items[0], "price", "id"))
}

// periodEnd is rule e: the top-level TIME, else the largest item TIME, else the stored value.
// In: object, stored value. Out: seconds. Why: STRIPEWH-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func periodEnd(sub map[string]any, stored int64) int64 {
	if t, ok := asTime(sub["current_period_end"]); ok {
		return t
	}
	best, found := int64(0), false
	if items, ok := get(sub, "items", "data").([]any); ok {
		for _, it := range items {
			if t, ok := asTime(get(it, "current_period_end")); ok && (!found || t > best) {
				best, found = t, true
			}
		}
	}
	if found {
		return best
	}
	return stored
}

// subscription is SUBSCRIPTION(sub, hint, rank): rules a to g.
// In: tx, object, user hint, rank, event created, now, whether the object was just fetched.
// Out: "applied" | "ignored" | "stale", or an error (a Stripe client failure) that undoes the transaction.
// Why: STRIPEWH-07, -09 to -14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the Stripe client.
func (s *Service) subscription(tx Tx, sub map[string]any, hint string, rank, eventAt, now int64, fetched bool) (string, error) {
	id, ok := text(sub["id"])
	if !ok || !subIDRe.MatchString(id) {
		return "ignored", nil
	}
	row, err := tx.GetSub(id)
	if err != nil {
		return "", err
	}
	for {
		price, hasPrice := priceOf(sub)
		var priceID, plan *string
		if row == nil {
			p, known := s.cfg.PricePlans[price]
			if !hasPrice || !known {
				return "ignored", nil
			}
			priceID, plan = strPtr(price), strPtr(p)
		} else if p, known := s.cfg.PricePlans[price]; hasPrice && known {
			priceID, plan = strPtr(price), strPtr(p)
		} else if !hasPrice || (row.PriceID != nil && *row.PriceID == price) {
			priceID, plan = row.PriceID, row.Plan
		} else {
			priceID, plan = strPtr(price), nil
		}
		customer, hasCustomer := text(sub["customer"])
		user := ""
		if row != nil {
			user = row.UserID
		} else if hint != "" && s.cfg.UserExists(hint) {
			user = hint
		} else if hasCustomer {
			rows, err := tx.SubsByCustomer(customer)
			if err != nil {
				return "", err
			}
			for i, r := range rows {
				if i == 0 {
					user = r.UserID
				} else if r.UserID != user {
					user = ""
					break
				}
			}
		}
		if user == "" {
			return "ignored", nil
		}
		if row != nil {
			if eventAt < row.EventAt || (eventAt == row.EventAt && rank < row.EventRank) {
				return "stale", nil
			}
			if rank <= 1 && eventAt == row.EventAt && rank == row.EventRank && !fetched {
				sub, err = s.retrieve(id)
				if err != nil {
					return "", err
				}
				// Rules b and c run again on the fetched object (loop), so the row ends with Stripe's current
				// price and plan: ruling of commit fed6e7b, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
				fetched = true
				continue
			}
		}
		stored := int64(0)
		if row != nil {
			stored = row.CurrentPeriodEnd
		}
		cpe := periodEnd(sub, stored)
		status := "canceled"
		if rank != 2 {
			st, ok := text(sub["status"])
			if !ok || !statRe.MatchString(st) {
				return "ignored", nil
			}
			status = st
		}
		var cust *string
		if hasCustomer {
			cust = strPtr(customer)
		}
		cancel, _ := sub["cancel_at_period_end"].(bool)
		err = tx.PutSub(SubRow{SubscriptionID: id, UserID: user, CustomerID: cust, PriceID: priceID, Plan: plan,
			Status: status, CurrentPeriodEnd: cpe, CancelAtPeriodEnd: cancel, EventAt: eventAt, EventRank: rank, UpdatedAt: now})
		if err != nil {
			return "", err
		}
		return "applied", nil
	}
}

// strPtr returns a pointer to a copy of s.
// In: text. Out: pointer. Why: nullable columns. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func strPtr(s string) *string { return &s }

// GetEntitlement answers what the user is entitled to now, computed from the clock at every call.
// In: verified user id. Out: the entitlement, or 500 storage_failed.
// Why: STRIPEWH-07, -10, -14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store (read), the clock.
func (s *Service) GetEntitlement(userID string) (Entitlement, *Refusal) {
	rows, err := s.cfg.Store.SubsByUser(userID)
	if err != nil {
		return Entitlement{}, &Refusal{Error: "storage_failed", Status: 500}
	}
	if len(rows) == 0 {
		return Entitlement{Status: "none"}, nil
	}
	now := s.cfg.Clock()
	entitling := []SubRow{}
	for _, r := range rows {
		if r.Plan != nil && (r.Status == "active" || r.Status == "trialing") && r.CurrentPeriodEnd+s.cfg.PeriodGraceSeconds > now {
			entitling = append(entitling, r)
		}
	}
	if len(entitling) > 0 {
		sort.Slice(entitling, func(i, j int) bool {
			a, b := entitling[i], entitling[j]
			if a.CurrentPeriodEnd != b.CurrentPeriodEnd {
				return a.CurrentPeriodEnd > b.CurrentPeriodEnd
			}
			if a.EventAt != b.EventAt {
				return a.EventAt > b.EventAt
			}
			return a.SubscriptionID > b.SubscriptionID
		})
		r := entitling[0]
		cpe := r.CurrentPeriodEnd
		return Entitlement{Entitled: true, Plan: strPtr(*r.Plan), Status: r.Status, CurrentPeriodEnd: &cpe,
			CancelAtPeriodEnd: r.CancelAtPeriodEnd}, nil
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].EventAt != rows[j].EventAt {
			return rows[i].EventAt > rows[j].EventAt
		}
		return rows[i].SubscriptionID > rows[j].SubscriptionID
	})
	r := rows[0]
	cpe := r.CurrentPeriodEnd
	return Entitlement{Entitled: false, Status: r.Status, CurrentPeriodEnd: &cpe, CancelAtPeriodEnd: r.CancelAtPeriodEnd}, nil
}

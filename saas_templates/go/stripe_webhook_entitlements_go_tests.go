package stripeentitlements

// Tests for stripe_webhook_entitlements_go.go against docs/specs/stripe_webhook_entitlements.md.
// Phase D wave 1, owner request 2026-11-10. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: memory only (in-memory store, fake Stripe client, fixed clock); no network.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// secret is the spec's signing secret, built from two pieces.
// Why: STRIPEWH-01 vector. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
var secret = "whsec_" + "test_secret_for_vectors"

// specBody is the spec's 317-byte body.
// Why: STRIPEWH-01 vector. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
var specBody = []byte(`{"id":"evt_test_0001","type":"customer.subscription.updated","created":1700000000,` +
	`"data":{"object":{"id":"sub_test_0001","customer":"cus_test_0001","status":"active",` +
	`"current_period_end":1702592000,"cancel_at_period_end":false,` +
	`"metadata":{"user_id":"user_1"},"items":{"data":[{"price":{"id":"price_pro_monthly"}}]}}}}`)

// fakeStripe answers RetrieveSubscription from subs, or with err; it records the ids asked for.
// Why: no network in tests. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
type fakeStripe struct {
	subs  map[string]map[string]any
	err   error
	calls []string
}

// RetrieveSubscription records the call and answers.
// In: id. Out: object, error. Why: fake. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (f *fakeStripe) RetrieveSubscription(id string) (map[string]any, error) {
	f.calls = append(f.calls, id)
	if f.err != nil {
		return nil, f.err
	}
	return f.subs[id], nil
}

// srig is one service with its store, client and settable clock.
// Why: helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type srig struct {
	svc    *Service
	store  *MemoryStore
	client *fakeStripe
	now    int64
}

// newSRig builds a service with the spec's configuration; users user_1, user_2 and user_9 exist.
// In: grace seconds. Out: rig. Why: helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func newSRig(grace int64) *srig {
	r := &srig{store: NewMemoryStore(), client: &fakeStripe{subs: map[string]map[string]any{}}, now: 1700000000}
	users := map[string]bool{"user_1": true, "user_2": true, "user_9": true}
	r.svc = New(Config{WebhookSecret: secret, PricePlans: map[string]string{"price_pro_monthly": "pro", "price_team": "team"},
		StripeClient: r.client, UserExists: func(u string) bool { return users[u] }, PeriodGraceSeconds: grace,
		Store: r.store, Clock: func() int64 { return r.now }})
	return r
}

// subObj builds a subscription object.
// In: id, user (metadata, "" for none), status, price ("" for none), period end (0 for none). Out: object.
// Why: helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func subObj(id, user, status, price string, cpe int64) map[string]any {
	o := map[string]any{"id": id, "customer": "cus_" + id[4:], "status": status, "cancel_at_period_end": false}
	if user != "" {
		o["metadata"] = map[string]any{"user_id": user}
	}
	if price != "" {
		o["items"] = map[string]any{"data": []any{map[string]any{"price": map[string]any{"id": price}}}}
	}
	if cpe != 0 {
		o["current_period_end"] = cpe
	}
	return o
}

// event serialises an event; created is written as given (a number or raw JSON text).
// In: id, type, created, data.object. Out: body. Why: helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func event(id, typ string, created any, obj any) []byte {
	c, _ := json.Marshal(created)
	if raw, ok := created.(string); ok && strings.HasPrefix(raw, "raw:") {
		c = []byte(raw[4:])
	}
	o, _ := json.Marshal(obj)
	return []byte(`{"id":"` + id + `","type":"` + typ + `","created":` + string(c) + `,"data":{"object":` + string(o) + `}}`)
}

// send signs body at the rig's time and delivers it.
// In: body. Out: result. Why: helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (r *srig) send(body []byte) Result {
	return r.svc.HandleWebhook(body, SignPayload(body, secret, r.now))
}

// ent returns the user's entitlement.
// In: user. Out: entitlement. Why: helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (r *srig) ent(user string) Entitlement {
	e, _ := r.svc.GetEntitlement(user)
	return e
}

// js renders a value as JSON for compact comparisons.
// In: value. Out: JSON text. Why: helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func js(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

const noneAnswer = `{"entitled":false,"plan":null,"status":"none","current_period_end":null,"cancel_at_period_end":false}`

// TestStripeWH01SignedVector proves the header vector, the applied answer and the entitlement.
// STRIPEWH-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestStripeWH01SignedVector(t *testing.T) {
	sum := sha256.Sum256(specBody)
	if len(specBody) != 317 || hex.EncodeToString(sum[:]) != "f2e8a2d52e46e4642dde0390c9def15047ff2178a8d33a9928698aca132cbe88" {
		t.Fatalf("body vector: %d bytes", len(specBody))
	}
	h := SignPayload(specBody, secret, 1700000000)
	if h != "t=1700000000,v1=5bca2d8b83d83f9a52f3b25714245817b15ae87b9e73abcca2c7a514977a8ae5" {
		t.Fatalf("header = %s", h)
	}
	r := newSRig(0)
	if got := r.svc.HandleWebhook(specBody, h); got != (Result{Status: 200, Received: true, Result: "applied"}) {
		t.Fatalf("handle = %+v", got)
	}
	want := `{"entitled":true,"plan":"pro","status":"active","current_period_end":1702592000,"cancel_at_period_end":false}`
	if got := js(r.ent("user_1")); got != want {
		t.Fatalf("entitlement = %s", got)
	}
}

// TestStripeWH02InvalidSignatures proves each bad header is 400 invalid_signature with nothing stored.
// STRIPEWH-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestStripeWH02InvalidSignatures(t *testing.T) {
	good := SignPayload(specBody, secret, 1700000000)
	v1 := good[strings.Index(good, "v1=")+3:]
	changed := append([]byte{}, specBody...)
	changed[10] ^= 0x01
	cases := []struct {
		body   []byte
		header string
	}{
		{specBody, SignPayload(specBody, "whsec_"+"another_secret_value", 1700000000)},
		{changed, good},
		{specBody, "t=1700000001,v1=" + v1},
		{specBody, "t=1700000000"},
		{specBody, "t=1700000000,v1=" + strings.ToUpper(v1)},
		{specBody, "t=1700000000,v1=" + v1[:63]},
		{specBody, "t=1700000000,v0=" + v1},
		{specBody, "t=1700000000,t=1700000000,v1=" + v1},
	}
	for i, c := range cases {
		r := newSRig(0)
		if got := r.svc.HandleWebhook(c.body, c.header); got != (Result{Status: 400, Error: "invalid_signature"}) {
			t.Fatalf("case %d = %+v", i, got)
		}
		if len(r.store.events) != 0 || len(r.store.subs) != 0 {
			t.Fatalf("case %d stored something", i)
		}
	}
}

// TestStripeWH03MissingHeaderAndShortSecret proves missing_signature and 503 webhook_not_configured.
// STRIPEWH-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestStripeWH03MissingHeaderAndShortSecret(t *testing.T) {
	r := newSRig(0)
	if got := r.svc.HandleWebhook(specBody, ""); got != (Result{Status: 400, Error: "missing_signature"}) {
		t.Fatalf("missing = %+v", got)
	}
	short := "whsec_" + "short1234"
	s := New(Config{WebhookSecret: short, Clock: func() int64 { return 1700000000 }})
	for _, h := range []string{SignPayload(specBody, short, 1700000000), "", "garbage", SignPayload(specBody, secret, 1700000000)} {
		if got := s.HandleWebhook(specBody, h); got != (Result{Status: 503, Error: "webhook_not_configured"}) {
			t.Fatalf("short secret, header %q = %+v", h, got)
		}
	}
}

// TestStripeWH04Tolerance proves 300 seconds either way is accepted and 301 is refused.
// STRIPEWH-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestStripeWH04Tolerance(t *testing.T) {
	h := SignPayload(specBody, secret, 1700000000)
	for _, c := range []struct {
		now  int64
		want Result
	}{
		{1700000300, Result{Status: 200, Received: true, Result: "applied"}},
		{1700000301, Result{Status: 400, Error: "timestamp_out_of_tolerance"}},
		{1699999700, Result{Status: 200, Received: true, Result: "applied"}},
		{1699999699, Result{Status: 400, Error: "timestamp_out_of_tolerance"}},
	} {
		r := newSRig(0)
		r.now = c.now
		if got := r.svc.HandleWebhook(specBody, h); got != c.want {
			t.Fatalf("now %d = %+v", c.now, got)
		}
	}
}

// TestStripeWH05TwoV1Values proves a header is accepted when its second v1 is right, with v0 and spaces.
// STRIPEWH-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestStripeWH05TwoV1Values(t *testing.T) {
	good := SignPayload(specBody, secret, 1700000000)
	v1 := good[strings.Index(good, "v1=")+3:]
	h := "t=1700000000, v1=" + strings.Repeat("0", 64) + ", v0=" + strings.Repeat("a", 64) + ", v1=" + v1
	r := newSRig(0)
	if got := r.svc.HandleWebhook(specBody, h); got.Result != "applied" {
		t.Fatalf("two v1 = %+v", got)
	}
}

// TestStripeWH06InvalidPayloads proves bodies that are signed but malformed are 400 and never recorded.
// STRIPEWH-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestStripeWH06InvalidPayloads(t *testing.T) {
	obj := subObj("sub_a1", "user_1", "active", "price_pro_monthly", 1702592000)
	o, _ := json.Marshal(obj)
	bodies := [][]byte{
		[]byte("not json"),
		[]byte(`[1,2]`),
		[]byte(`{"type":"customer.subscription.created","created":1700000000,"data":{"object":` + string(o) + `}}`),
		[]byte(`{"id":"xyz_1","type":"customer.subscription.created","created":1700000000,"data":{"object":` + string(o) + `}}`),
		[]byte(`{"id":"evt_1","created":1700000000,"data":{"object":` + string(o) + `}}`),
		[]byte(`{"id":"evt_1","type":"customer.subscription.created","data":{"object":` + string(o) + `}}`),
		[]byte(`{"id":"evt_1","type":"customer.subscription.created","created":1700000000,"data":{}}`),
		[]byte("\xEF\xBB\xBF" + string(event("evt_1", "customer.subscription.created", 1700000000, obj))),
		event("evt_1", "customer.subscription.created", true, obj),
		event("evt_1", "customer.subscription.created", "1700000000", obj),
		event("evt_1", "customer.subscription.created", "raw:1700000000.5", obj),
		event("evt_1", "customer.subscription.created", "raw:-1", obj),
		event("evt_1", "customer.subscription.created", "raw:100000000000", obj),
		event("evt_1", "customer.subscription.created", "raw:1e400", obj),
	}
	for i, b := range bodies {
		r := newSRig(0)
		if got := r.send(b); got != (Result{Status: 400, Error: "invalid_payload"}) {
			t.Fatalf("body %d = %+v", i, got)
		}
		if len(r.store.events) != 0 {
			t.Fatalf("body %d was recorded", i)
		}
	}
	r := newSRig(0)
	if got := r.send(event("evt_1", "customer.subscription.created", "raw:1700000000.0", obj)); got.Result != "applied" {
		t.Fatalf("1700000000.0 = %+v", got)
	}
	if r.store.events["evt_1"].Created != 1700000000 {
		t.Fatal("created not read as 1700000000")
	}
}

// TestStripeWH06NonFiniteNumberAnywhere proves the db20a03 amendment of STRIPEWH-06 (Phase B.4): a correctly
// signed, otherwise valid body holding "x": 1e400 (a non-finite number outside any TIME field), at the top level or
// inside data.object, is 400 invalid_payload and no event is recorded; the same body without it is applied.
// In: none. Out: test failures. Why: STRIPEWH-06 as amended by db20a03. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
// STRIPEWH-06
func TestStripeWH06NonFiniteNumberAnywhere(t *testing.T) {
	good := event("evt_inf", "customer.subscription.created", 1700000000, subObj("sub_inf", "user_1", "active", "price_pro_monthly", 1702592000))
	top := append([]byte(`{"x":1e400,`), good[1:]...)
	nested := bytes.Replace(good, []byte(`"object":{`), []byte(`"object":{"x":1e400,`), 1)
	if bytes.Equal(nested, good) {
		t.Fatal("the nested body is unchanged")
	}
	for name, b := range map[string][]byte{"top level": top, "in data.object": nested} {
		r := newSRig(0)
		if got := r.send(b); got != (Result{Status: 400, Error: "invalid_payload"}) {
			t.Fatalf("1e400 %s = %+v", name, got)
		}
		if len(r.store.events) != 0 {
			t.Fatalf("1e400 %s was recorded", name)
		}
	}
	if got := newSRig(0).send(good); got.Status != 200 || got.Result != "applied" {
		t.Fatalf("the same body without it = %+v", got)
	}
}

// TestStripeWH07Created proves a created event entitles its user and leaves another user's answer alone.
// STRIPEWH-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestStripeWH07Created(t *testing.T) {
	r := newSRig(0)
	r.send(event("evt_u2", "customer.subscription.created", 1699999000, subObj("sub_u2", "user_2", "trialing", "price_team", 1701000000)))
	other := js(r.ent("user_2"))
	if got := js(r.ent("user_1")); got != noneAnswer {
		t.Fatalf("before = %s", got)
	}
	if got := r.send(event("evt_c1", "customer.subscription.created", 1700000000, subObj("sub_c1", "user_1", "active", "price_pro_monthly", 1702592000))); got.Result != "applied" {
		t.Fatalf("created = %+v", got)
	}
	want := `{"entitled":true,"plan":"pro","status":"active","current_period_end":1702592000,"cancel_at_period_end":false}`
	if got := js(r.ent("user_1")); got != want {
		t.Fatalf("after = %s", got)
	}
	if js(r.ent("user_2")) != other {
		t.Fatal("another user's answer changed")
	}
}

// TestStripeWH08Duplicate proves the same event id twice is 200 duplicate and changes nothing.
// STRIPEWH-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestStripeWH08Duplicate(t *testing.T) {
	r := newSRig(0)
	r.send(specBody)
	before := r.store.subs["sub_test_0001"]
	r.now += 10
	if got := r.svc.HandleWebhook(specBody, SignPayload(specBody, secret, r.now)); got != (Result{Status: 200, Received: true, Result: "duplicate"}) {
		t.Fatalf("second = %+v", got)
	}
	if js(r.store.subs["sub_test_0001"]) != js(before) {
		t.Fatal("the row changed")
	}
}

// TestStripeWH09OutOfOrder proves stale events, rank order at equal times, and the fetch on a tie.
// STRIPEWH-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestStripeWH09OutOfOrder(t *testing.T) {
	r := newSRig(0)
	r.send(event("evt_a", "customer.subscription.updated", 200, subObj("sub_o1", "user_1", "active", "price_pro_monthly", 1702592000)))
	row := js(r.store.subs["sub_o1"])
	if got := r.send(event("evt_b", "customer.subscription.updated", 100, subObj("sub_o1", "user_1", "past_due", "price_pro_monthly", 1702592000))); got.Result != "stale" {
		t.Fatalf("older = %+v", got)
	}
	if got := r.send(event("evt_c", "customer.subscription.created", 200, subObj("sub_o1", "user_1", "incomplete", "price_pro_monthly", 1702592000))); got.Result != "stale" {
		t.Fatalf("created at the same time = %+v", got)
	}
	if js(r.store.subs["sub_o1"]) != row || len(r.client.calls) != 0 {
		t.Fatal("a stale event changed the row or called Stripe")
	}
	if got := r.send(event("evt_d", "customer.subscription.deleted", 200, subObj("sub_o1", "user_1", "active", "price_pro_monthly", 1702592000))); got.Result != "applied" {
		t.Fatalf("deleted at the same time = %+v", got)
	}
	if r.store.subs["sub_o1"].Status != "canceled" || r.store.subs["sub_o1"].EventRank != 2 {
		t.Fatalf("row = %+v", r.store.subs["sub_o1"])
	}
	r.send(event("evt_e", "customer.subscription.updated", 300, subObj("sub_o2", "user_1", "active", "price_pro_monthly", 1702592000)))
	r.client.subs["sub_o2"] = subObj("sub_o2", "user_1", "trialing", "price_team", 1703000000)
	if got := r.send(event("evt_f", "customer.subscription.updated", 300, subObj("sub_o2", "user_1", "past_due", "price_pro_monthly", 1702592000))); got.Result != "applied" {
		t.Fatalf("tie = %+v", got)
	}
	got := r.store.subs["sub_o2"]
	if len(r.client.calls) != 1 || r.client.calls[0] != "sub_o2" || got.Status != "trialing" || got.CurrentPeriodEnd != 1703000000 || *got.Plan != "team" {
		t.Fatalf("after the fetch: %+v calls %v", got, r.client.calls)
	}
}

// TestStripeWH10EndsAtOnce proves non-paying statuses and a passed period end stop entitlement, and the grace.
// STRIPEWH-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestStripeWH10EndsAtOnce(t *testing.T) {
	for i, st := range []string{"past_due", "unpaid", "canceled"} {
		r := newSRig(0)
		r.send(event("evt_1", "customer.subscription.created", 100, subObj("sub_s1", "user_1", "active", "price_pro_monthly", 1702592000)))
		if !r.ent("user_1").Entitled {
			t.Fatal("not entitled when active")
		}
		r.send(event("evt_2", "customer.subscription.updated", 200, subObj("sub_s1", "user_1", st, "price_pro_monthly", 1702592000)))
		if e := r.ent("user_1"); e.Entitled || e.Status != st || e.Plan != nil {
			t.Fatalf("case %d: %s", i, js(e))
		}
	}
	r := newSRig(0)
	r.send(event("evt_1", "customer.subscription.created", 100, subObj("sub_s1", "user_1", "active", "price_pro_monthly", r.now)))
	if r.ent("user_1").Entitled {
		t.Fatal("entitled when current_period_end == now")
	}
	r.now--
	if !r.ent("user_1").Entitled {
		t.Fatal("not entitled one second before the period end")
	}
	g := newSRig(60)
	g.send(event("evt_1", "customer.subscription.created", 100, subObj("sub_s1", "user_1", "active", "price_pro_monthly", g.now)))
	g.now += 59
	if !g.ent("user_1").Entitled {
		t.Fatal("grace 60: not entitled 59 seconds after the end")
	}
	g.now++
	if g.ent("user_1").Entitled {
		t.Fatal("grace 60: entitled 60 seconds after the end")
	}
}

// TestStripeWH11PeriodEnd proves the top-level value, the largest item value and keeping the stored value.
// STRIPEWH-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestStripeWH11PeriodEnd(t *testing.T) {
	r := newSRig(0)
	r.send(event("evt_1", "customer.subscription.created", 100, subObj("sub_p1", "user_1", "active", "price_pro_monthly", 1702592000)))
	if r.store.subs["sub_p1"].CurrentPeriodEnd != 1702592000 {
		t.Fatal("top-level period end")
	}
	o := subObj("sub_p1", "user_1", "active", "", 0)
	o["items"] = map[string]any{"data": []any{
		map[string]any{"price": map[string]any{"id": "price_pro_monthly"}, "current_period_end": 1703000000},
		map[string]any{"price": map[string]any{"id": "price_pro_monthly"}, "current_period_end": 1704000000},
	}}
	r.send(event("evt_2", "customer.subscription.updated", 200, o))
	if r.store.subs["sub_p1"].CurrentPeriodEnd != 1704000000 {
		t.Fatalf("items period end = %d", r.store.subs["sub_p1"].CurrentPeriodEnd)
	}
	r.send(event("evt_3", "customer.subscription.updated", 300, subObj("sub_p1", "user_1", "active", "price_pro_monthly", 0)))
	if r.store.subs["sub_p1"].CurrentPeriodEnd != 1704000000 {
		t.Fatal("an event without a period end overwrote it")
	}
}

// TestStripeWH12Ignored proves the ignored cases are recorded with no change, and the stored-row exceptions.
// STRIPEWH-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestStripeWH12Ignored(t *testing.T) {
	r := newSRig(0)
	cases := map[string][]byte{
		"evt_i1": event("evt_i1", "customer.subscription.created", 100, subObj("sub_i1", "user_1", "active", "price_unknown", 1702592000)),
		"evt_i2": event("evt_i2", "customer.subscription.created", 100, subObj("sub_i2", "ghost", "active", "price_pro_monthly", 1702592000)),
		"evt_i3": event("evt_i3", "invoice.paid", 100, map[string]any{"id": "in_1"}),
		"evt_i4": event("evt_i4", "customer.subscription.created", 100, subObj("sub_bad-id", "user_1", "active", "price_pro_monthly", 1702592000)),
	}
	for id, b := range cases {
		if got := r.send(b); got != (Result{Status: 200, Received: true, Result: "ignored"}) {
			t.Fatalf("%s = %+v", id, got)
		}
		if ev, ok := r.store.events[id]; !ok || ev.Result != "ignored" {
			t.Fatalf("%s not recorded", id)
		}
	}
	if len(r.store.subs) != 0 || js(r.ent("user_1")) != noneAnswer {
		t.Fatal("an ignored event changed entitlements")
	}
	r.svc.cfg.PricePlans["price_old"] = "legacy"
	r.send(event("evt_1", "customer.subscription.created", 100, subObj("sub_k1", "user_1", "active", "price_old", 1702592000)))
	delete(r.svc.cfg.PricePlans, "price_old")
	if !r.ent("user_1").Entitled || *r.ent("user_1").Plan != "legacy" {
		t.Fatal("a price taken off sale stopped serving its buyer")
	}
	if got := r.send(event("evt_2", "customer.subscription.deleted", 200, subObj("sub_k1", "user_1", "active", "price_old", 1702592000))); got.Result != "applied" {
		t.Fatalf("deleted with an old price = %+v", got)
	}
	if r.store.subs["sub_k1"].Status != "canceled" {
		t.Fatal("deleted not applied")
	}
	r.send(event("evt_3", "customer.subscription.created", 100, subObj("sub_k2", "user_2", "active", "price_pro_monthly", 1702592000)))
	if got := r.send(event("evt_4", "customer.subscription.updated", 200, subObj("sub_k2", "user_2", "active", "price_unknown", 1702592000))); got.Result != "applied" {
		t.Fatalf("move to unknown price = %+v", got)
	}
	if e := r.ent("user_2"); e.Entitled || r.store.subs["sub_k2"].Plan != nil || *r.store.subs["sub_k2"].PriceID != "price_unknown" {
		t.Fatalf("after the move: %s", js(e))
	}
}

// TestStripeWH13CheckoutSession proves the fetch by id, client_reference_id, and the 500 that keeps nothing.
// STRIPEWH-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestStripeWH13CheckoutSession(t *testing.T) {
	r := newSRig(0)
	session := map[string]any{"id": "cs_1", "mode": "subscription", "subscription": "sub_chk_1", "client_reference_id": "user_9"}
	body := event("evt_chk", "checkout.session.completed", 100, session)
	r.client.err = errors.New("stripe down")
	if got := r.send(body); got != (Result{Status: 500, Error: "processing_failed"}) {
		t.Fatalf("raising client = %+v", got)
	}
	if _, ok := r.store.events["evt_chk"]; ok || len(r.store.subs) != 0 {
		t.Fatal("the failed delivery was kept")
	}
	r.client.err = nil
	r.client.subs["sub_chk_1"] = subObj("sub_chk_1", "", "active", "price_pro_monthly", 1702592000)
	if got := r.send(body); got.Result != "applied" {
		t.Fatalf("redelivery = %+v", got)
	}
	if len(r.client.calls) != 2 || r.client.calls[1] != "sub_chk_1" {
		t.Fatalf("calls = %v", r.client.calls)
	}
	if e := r.ent("user_9"); !e.Entitled || *e.Plan != "pro" {
		t.Fatalf("user_9 = %s", js(e))
	}
}

// TestStripeWH14TwoSubscriptionsAndUserLookup proves two subscriptions, user lookup without metadata, and that
// no event moves a subscription to another user.
// STRIPEWH-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestStripeWH14TwoSubscriptionsAndUserLookup(t *testing.T) {
	r := newSRig(0)
	r.send(event("evt_1", "customer.subscription.created", 100, subObj("sub_m1", "user_1", "active", "price_pro_monthly", 2000000000)))
	r.send(event("evt_2", "customer.subscription.created", 100, subObj("sub_m2", "user_1", "active", "price_team", 1900000000)))
	if *r.ent("user_1").Plan != "pro" {
		t.Fatal("the later period end does not decide")
	}
	r.send(event("evt_3", "customer.subscription.deleted", 200, subObj("sub_m1", "user_1", "canceled", "price_pro_monthly", 2000000000)))
	if e := r.ent("user_1"); !e.Entitled || *e.Plan != "team" {
		t.Fatalf("after ending one: %s", js(e))
	}
	if got := r.send(event("evt_4", "customer.subscription.updated", 300, subObj("sub_m2", "", "active", "price_team", 1950000000))); got.Result != "applied" ||
		r.store.subs["sub_m2"].CurrentPeriodEnd != 1950000000 {
		t.Fatalf("no metadata, stored subscription = %+v", got)
	}
	o := subObj("sub_m3", "", "active", "price_pro_monthly", 2100000000)
	o["customer"] = "cus_m2"
	if got := r.send(event("evt_5", "customer.subscription.created", 400, o)); got.Result != "applied" || r.store.subs["sub_m3"].UserID != "user_1" {
		t.Fatalf("no metadata, customer id = %+v", got)
	}
	r.send(event("evt_6", "customer.subscription.updated", 500, subObj("sub_m2", "user_2", "active", "price_team", 1960000000)))
	if r.store.subs["sub_m2"].UserID != "user_1" || r.ent("user_2").Entitled {
		t.Fatal("an event moved a subscription to another user")
	}
}

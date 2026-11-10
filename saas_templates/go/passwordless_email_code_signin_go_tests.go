package passwordless

// Tests for passwordless_email_code_signin_go.go against docs/specs/passwordless_email_code_signin.md.
// Phase D wave 1, owner request 2026-11-10. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: memory only (in-memory store, fake sender, fixed clock); no network.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// fakeSender records every SendCode call; fail makes it return false, err makes it return an error.
// Why: tests need no network (README). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
type fakeSender struct {
	calls []sentCall
	fail  bool
	err   error
}

// sentCall is one recorded SendCode call.
// Why: EMAILCODE-01, -07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type sentCall struct {
	to, code string
	ttl      int
}

// SendCode records the call and answers as configured.
// In: to, code, ttl. Out: ok, error. Why: fake sender. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (f *fakeSender) SendCode(to, code string, ttl int) (bool, error) {
	f.calls = append(f.calls, sentCall{to, code, ttl})
	if f.err != nil {
		return false, f.err
	}
	return !f.fail, nil
}

// lastCode returns the code of the latest send.
// In: none. Out: code. Why: test helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func (f *fakeSender) lastCode() string { return f.calls[len(f.calls)-1].code }

// rig is one service with its store, sender and a settable clock.
// Why: test helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type rig struct {
	svc    *Service
	store  *MemoryStore
	sender *fakeSender
	now    int64
}

// newRig builds a service with the spec's secret; code, when not "", is what generate_code returns.
// In: code. Out: rig. Why: test helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func newRig(t *testing.T, code string) *rig {
	r := &rig{store: NewMemoryStore(), sender: &fakeSender{}, now: 1699920000}
	cfg := Config{Secret: []byte("0123456789abcdef0123456789abcdef"), Sender: r.sender, Store: r.store,
		Clock: func() int64 { return r.now }}
	if code != "" {
		cfg.GenerateCode = func() string { return code }
	}
	svc, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.svc = svc
	return r
}

// queue serves the given bytes in order, whatever n is asked.
// In: bytes. Out: random_bytes func. Why: EMAILCODE-14 vectors. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: memory.
func queue(b []byte) func(int) []byte {
	return func(n int) []byte {
		out := b[:n]
		b = b[n:]
		return out
	}
}

// TestEmailCode01SignInAndSignUp proves start/verify, account creation, a second sign-in and revoke_unproven.
// EMAILCODE-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestEmailCode01SignInAndSignUp(t *testing.T) {
	r := newRig(t, "")
	revoked := []string{}
	r.svc.cfg.RevokeUnproven = func(id string) error { revoked = append(revoked, id); return nil }
	if got := r.svc.Start("user@example.com", "203.0.113.7"); got != (StartResult{Status: 202, Sent: true, ExpiresIn: 600}) {
		t.Fatalf("start = %+v", got)
	}
	if len(r.sender.calls) != 1 || !regexp.MustCompile(`^[0-9]{6}$`).MatchString(r.sender.lastCode()) ||
		r.sender.calls[0].to != "user@example.com" || r.sender.calls[0].ttl != 600 {
		t.Fatalf("sender calls = %+v", r.sender.calls)
	}
	v := r.svc.Verify("user@example.com", r.sender.lastCode(), "203.0.113.7")
	if v.Status != 200 || !v.NewAccount || v.Email != "user@example.com" || len(v.AccountID) != 32 {
		t.Fatalf("verify = %+v", v)
	}
	acc, _ := r.store.FindAccountByEmail("user@example.com")
	if acc == nil || acc.ID != v.AccountID || acc.EmailVerifiedAt == nil || *acc.EmailVerifiedAt != r.now || acc.Status != "active" {
		t.Fatalf("account = %+v", acc)
	}
	r.svc.Start("user@example.com", "203.0.113.7")
	v2 := r.svc.Verify("user@example.com", r.sender.lastCode(), "203.0.113.7")
	if v2.Status != 200 || v2.NewAccount || v2.AccountID != v.AccountID {
		t.Fatalf("second verify = %+v", v2)
	}
	if len(revoked) != 0 {
		t.Fatalf("an account made by verify called revoke_unproven: %v", revoked)
	}
	_ = r.store.InsertAccountIfAbsent(Account{ID: "invited_1", Email: "inv@example.com", Status: "active", CreatedAt: 1})
	r.svc.Start("inv@example.com", "203.0.113.7")
	v3 := r.svc.Verify("inv@example.com", r.sender.lastCode(), "203.0.113.7")
	if v3.Status != 200 || v3.AccountID != "invited_1" || v3.NewAccount {
		t.Fatalf("verify unproven = %+v", v3)
	}
	if len(revoked) != 1 || revoked[0] != "invited_1" {
		t.Fatalf("revoke_unproven calls = %v", revoked)
	}
	acc, _ = r.store.FindAccountByEmail("inv@example.com")
	if acc.EmailVerifiedAt == nil || *acc.EmailVerifiedAt != r.now {
		t.Fatalf("email_verified_at not set: %+v", acc)
	}
}

// TestEmailCode01VerifyReplyJSONShapes marshals verify's two answers: a returning user's reply carries
// "new_account": false (it was dropped by omitempty), a new user's carries true, and a refusal is exactly
// {status, error}. In: none. Out: test failures. Why: review finding 4525344132 (spec verify: {status: 200,
// account_id, email, new_account}; a refusal is {error, status}). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: memory only.
// EMAILCODE-01
func TestEmailCode01VerifyReplyJSONShapes(t *testing.T) {
	r := newRig(t, "")
	r.svc.Start("back@example.com", "203.0.113.7")
	first := r.svc.Verify("back@example.com", r.sender.lastCode(), "203.0.113.7")
	r.svc.Start("back@example.com", "203.0.113.7")
	again := r.svc.Verify("back@example.com", r.sender.lastCode(), "203.0.113.7")
	refused := r.svc.Verify("back@example.com", "12345", "203.0.113.7")
	shapes := map[string]VerifyResult{"new": first, "returning": again, "refused": refused}
	want := map[string]map[string]any{
		"new":       {"status": float64(200), "account_id": first.AccountID, "email": "back@example.com", "new_account": true},
		"returning": {"status": float64(200), "account_id": first.AccountID, "email": "back@example.com", "new_account": false},
		"refused":   {"status": float64(400), "error": "invalid_code"},
	}
	for name, result := range shapes {
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("%s: unmarshal %s: %v", name, raw, err)
		}
		if len(got) != len(want[name]) {
			t.Fatalf("%s: JSON %s, want the keys of %v", name, raw, want[name])
		}
		for k, v := range want[name] {
			if got[k] != v {
				t.Fatalf("%s: JSON %s, want %s = %v", name, raw, k, v)
			}
		}
	}
}

// TestEmailCode01RevokeFailureLeavesRowUnverified proves a raising revoke_unproven is 500 and verifies nothing.
// EMAILCODE-01 (verify step 7). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestEmailCode01RevokeFailureLeavesRowUnverified(t *testing.T) {
	r := newRig(t, "123456")
	r.svc.cfg.RevokeUnproven = func(string) error { return errors.New("down") }
	_ = r.store.InsertAccountIfAbsent(Account{ID: "invited_1", Email: "inv@example.com", Status: "active", CreatedAt: 1})
	r.svc.Start("inv@example.com", "1.2.3.4")
	if v := r.svc.Verify("inv@example.com", "123456", "1.2.3.4"); v != (VerifyResult{Status: 500, Error: "processing_failed"}) {
		t.Fatalf("verify = %+v", v)
	}
	acc, _ := r.store.FindAccountByEmail("inv@example.com")
	if acc.EmailVerifiedAt != nil {
		t.Fatal("row was verified although revoke_unproven failed")
	}
}

// TestEmailCode02StorageHoldsOnlyKeyedHashes proves the stored code_hash vector and that nothing plain is kept.
// EMAILCODE-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestEmailCode02StorageHoldsOnlyKeyedHashes(t *testing.T) {
	r := newRig(t, "123456")
	if h := r.svc.EmailHash("user@example.com"); h != "587522269e243312a5d6f20bcdc78dc97a3e644e2ad702cdb94ac9550c03b346" {
		t.Fatalf("email_hash = %s", h)
	}
	if h := r.svc.IPHash("203.0.113.7"); h != "e01c4eeb03c058165d49564dcaf561cf" {
		t.Fatalf("ip_hash = %s", h)
	}
	if got := r.svc.Start("user@example.com", "203.0.113.7"); got.Status != 202 {
		t.Fatalf("start = %+v", got)
	}
	row := r.store.codes["587522269e243312a5d6f20bcdc78dc97a3e644e2ad702cdb94ac9550c03b346"]
	if row == nil || row.CodeHash != "761f222c89dc1744c480d21e141277cc9af815ee0e2a1d7489c9282594728b5b" ||
		row.ExpiresAt != r.now+600 || row.Attempts != 0 || row.CreatedAt != r.now {
		t.Fatalf("code row = %+v", row)
	}
	keys := r.store.windowKeys()
	want := []string{"start-email#587522269e243312a5d6f20bcdc78dc9", "start-email-day#587522269e243312a5d6f20bcdc78dc9",
		"start-ip#e01c4eeb03c058165d49564dcaf561cf"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("rate_windows keys = %v", keys)
	}
	plain := sha256.Sum256([]byte("123456"))
	all := strings.Join(keys, "|")
	for k, v := range r.store.codes {
		all += "|" + k + "|" + v.CodeHash
	}
	for _, bad := range []string{"user@example.com", "203.0.113.7", "123456", hex.EncodeToString(plain[:])} {
		if strings.Contains(all, bad) {
			t.Fatalf("storage holds %q", bad)
		}
	}
}

// TestEmailCode03SingleUse proves the right code a second time is 400 invalid_code.
// EMAILCODE-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestEmailCode03SingleUse(t *testing.T) {
	r := newRig(t, "123456")
	r.svc.Start("a@x.com", "1.1.1.1")
	if v := r.svc.Verify("a@x.com", "123456", "1.1.1.1"); v.Status != 200 {
		t.Fatalf("first = %+v", v)
	}
	if v := r.svc.Verify("a@x.com", "123456", "1.1.1.1"); v != (VerifyResult{Status: 400, Error: "invalid_code"}) {
		t.Fatalf("second = %+v", v)
	}
}

// TestEmailCode04Expiry proves the code works 599 seconds after start and not at 600.
// EMAILCODE-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestEmailCode04Expiry(t *testing.T) {
	r := newRig(t, "123456")
	r.svc.Start("a@x.com", "1.1.1.1")
	r.now += 599
	if v := r.svc.Verify("a@x.com", "123456", "1.1.1.1"); v.Status != 200 {
		t.Fatalf("at 599 = %+v", v)
	}
	r2 := newRig(t, "123456")
	r2.svc.Start("a@x.com", "1.1.1.1")
	r2.now += 600
	if v := r2.svc.Verify("a@x.com", "123456", "1.1.1.1"); v != (VerifyResult{Status: 400, Error: "invalid_code"}) {
		t.Fatalf("at 600 = %+v", v)
	}
}

// TestEmailCode05FiveTriesPerCode proves 5 wrong codes kill the code and the 5th try may be the right one.
// EMAILCODE-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestEmailCode05FiveTriesPerCode(t *testing.T) {
	r := newRig(t, "123456")
	r.svc.Start("a@x.com", "1.1.1.1")
	for i := 0; i < 5; i++ {
		if v := r.svc.Verify("a@x.com", "654321", "1.1.1.1"); v.Error != "invalid_code" {
			t.Fatalf("wrong %d = %+v", i, v)
		}
	}
	if v := r.svc.Verify("a@x.com", "123456", "1.1.1.1"); v != (VerifyResult{Status: 400, Error: "invalid_code"}) {
		t.Fatalf("right after 5 wrong = %+v", v)
	}
	r2 := newRig(t, "123456")
	r2.svc.Start("a@x.com", "1.1.1.1")
	for i := 0; i < 4; i++ {
		r2.svc.Verify("a@x.com", "654321", "1.1.1.1")
	}
	if v := r2.svc.Verify("a@x.com", "123456", "1.1.1.1"); v.Status != 200 {
		t.Fatalf("right as 5th try = %+v", v)
	}
}

// TestEmailCode06NewStartReplacesCode proves a new start kills the old code and resets the tries.
// EMAILCODE-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestEmailCode06NewStartReplacesCode(t *testing.T) {
	r := newRig(t, "111111")
	r.svc.Start("a@x.com", "1.1.1.1")
	for i := 0; i < 4; i++ {
		r.svc.Verify("a@x.com", "999999", "1.1.1.1")
	}
	r.svc.cfg.GenerateCode = func() string { return "222222" }
	r.svc.Start("a@x.com", "1.1.1.1")
	if v := r.svc.Verify("a@x.com", "111111", "1.1.1.1"); v != (VerifyResult{Status: 400, Error: "invalid_code"}) {
		t.Fatalf("old code = %+v", v)
	}
	for i := 0; i < 3; i++ {
		r.svc.Verify("a@x.com", "999999", "1.1.1.1")
	}
	if v := r.svc.Verify("a@x.com", "222222", "1.1.1.1"); v.Status != 200 {
		t.Fatalf("new code as its 5th try = %+v", v)
	}
}

// TestEmailCode07NoEnumeration proves start and verify answer alike for known and unknown addresses.
// EMAILCODE-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestEmailCode07NoEnumeration(t *testing.T) {
	r := newRig(t, "")
	_ = r.store.InsertAccountIfAbsent(Account{ID: "known", Email: "known@x.com", Status: "active", CreatedAt: 1})
	readsBefore := r.store.accountReads
	a := r.svc.Start("known@x.com", "1.1.1.1")
	b := r.svc.Start("unknown@x.com", "1.1.1.1")
	if a != b || a.Status != 202 {
		t.Fatalf("start answers differ: %+v %+v", a, b)
	}
	if r.store.accountReads != readsBefore {
		t.Fatal("start read accounts")
	}
	re := regexp.MustCompile(`^[0-9]{6}$`)
	if len(r.sender.calls) != 2 || !re.MatchString(r.sender.calls[0].code) || !re.MatchString(r.sender.calls[1].code) ||
		r.sender.calls[0].ttl != r.sender.calls[1].ttl {
		t.Fatalf("sender calls differ: %+v", r.sender.calls)
	}
	want := VerifyResult{Status: 400, Error: "invalid_code"}
	code := r.sender.calls[1].code
	wrong := "000000"
	if code == wrong {
		wrong = "000001"
	}
	answers := []VerifyResult{r.svc.Verify("unknown@x.com", wrong, "1.1.1.1")}
	if v := r.svc.Verify("unknown@x.com", code, "1.1.1.1"); v.Status != 200 {
		t.Fatalf("right code = %+v", v)
	}
	answers = append(answers, r.svc.Verify("unknown@x.com", code, "1.1.1.1"))
	r.svc.Start("known@x.com", "1.1.1.1")
	r.now += 600
	answers = append(answers, r.svc.Verify("known@x.com", r.sender.lastCode(), "1.1.1.1"))
	answers = append(answers, r.svc.Verify("never@x.com", "123456", "1.1.1.1"))
	for i, v := range answers {
		if v != want {
			t.Fatalf("answer %d = %+v", i, v)
		}
	}
}

// TestEmailCode08SendsPerAddress proves 5 starts per address per clock hour and 10 per clock day.
// EMAILCODE-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestEmailCode08SendsPerAddress(t *testing.T) {
	r := newRig(t, "123456")
	for i := 1; i <= 5; i++ {
		if got := r.svc.Start("a@x.com", "1.1.1.1"); got.Status != 202 {
			t.Fatalf("start %d = %+v", i, got)
		}
	}
	sent := len(r.sender.calls)
	if got := r.svc.Start("a@x.com", "1.1.1.1"); got != (StartResult{Status: 429, Error: "too_many_requests"}) {
		t.Fatalf("6th = %+v", got)
	}
	if len(r.sender.calls) != sent {
		t.Fatal("a refused start sent a code")
	}
	r.now = 1699923600
	for i := 1; i <= 4; i++ {
		if got := r.svc.Start("a@x.com", "1.1.1.1"); got.Status != 202 {
			t.Fatalf("next hour start %d = %+v", i, got)
		}
	}
	if got := r.svc.Start("a@x.com", "1.1.1.1"); got != (StartResult{Status: 429, Error: "too_many_requests"}) {
		t.Fatalf("11th in the day = %+v", got)
	}
}

// TestEmailCode09SendsPerIP proves 20 starts per IP per clock hour, and another IP is not affected.
// EMAILCODE-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestEmailCode09SendsPerIP(t *testing.T) {
	r := newRig(t, "123456")
	for i := 1; i <= 20; i++ {
		if got := r.svc.Start("u"+itoa(int64(i))+"@x.com", "9.9.9.9"); got.Status != 202 {
			t.Fatalf("start %d = %+v", i, got)
		}
	}
	if got := r.svc.Start("u21@x.com", "9.9.9.9"); got != (StartResult{Status: 429, Error: "too_many_requests"}) {
		t.Fatalf("21st = %+v", got)
	}
	if got := r.svc.Start("u21@x.com", "8.8.8.8"); got.Status != 202 {
		t.Fatalf("other ip = %+v", got)
	}
}

// TestEmailCode10TriesPerIPAndAddress proves 30 verifies per IP and 10 per address per clock hour.
// EMAILCODE-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestEmailCode10TriesPerIPAndAddress(t *testing.T) {
	r := newRig(t, "123456")
	r.svc.Start("target@x.com", "5.5.5.5")
	for i := 1; i <= 30; i++ {
		if v := r.svc.Verify("u"+itoa(int64(i))+"@x.com", "123456", "9.9.9.9"); v.Error != "invalid_code" {
			t.Fatalf("verify %d = %+v", i, v)
		}
	}
	if v := r.svc.Verify("target@x.com", "123456", "9.9.9.9"); v != (VerifyResult{Status: 429, Error: "too_many_requests"}) {
		t.Fatalf("31st from the ip = %+v", v)
	}
	r2 := newRig(t, "123456")
	r2.svc.Start("a@x.com", "5.5.5.5")
	for i := 1; i <= 5; i++ {
		r2.svc.Verify("a@x.com", "654321", "10.0.0."+itoa(int64(i)))
	}
	r2.svc.Start("a@x.com", "5.5.5.5")
	for i := 6; i <= 10; i++ {
		r2.svc.Verify("a@x.com", "654321", "10.0.0."+itoa(int64(i)))
	}
	r2.svc.Start("a@x.com", "5.5.5.5")
	if v := r2.svc.Verify("a@x.com", "123456", "10.0.1.1"); v != (VerifyResult{Status: 429, Error: "too_many_requests"}) {
		t.Fatalf("11th for the address = %+v", v)
	}
}

// TestEmailCode11Input proves address trimming and lower-casing rules and the code spellings.
// EMAILCODE-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestEmailCode11Input(t *testing.T) {
	r := newRig(t, "123456")
	r.svc.Start(" A@X.com ", "1.1.1.1")
	if r.sender.calls[0].to != "a@x.com" {
		t.Fatalf("sent to %q", r.sender.calls[0].to)
	}
	if v := r.svc.Verify(" A@X.com ", "123456", "1.1.1.1"); v.Status != 200 || v.Email != "a@x.com" {
		t.Fatalf("verify = %+v", v)
	}
	if e, ok := NormalizeEmail(" A@X.com "); !ok || e != "a@x.com" {
		t.Fatalf("normalize = %q", e)
	}
	bad := []string{"a@b", "a b@x.com", "a@x..com", ".a@x.com", "a@x.com,b@y.com", "<a@x.com>",
		"a@x.com ", "a@x.com\u000b", "a@x.com\u0000", "K@x.com"}
	for _, b := range bad {
		if _, ok := NormalizeEmail(b); ok {
			t.Fatalf("normalize accepted %q", b)
		}
		if got := r.svc.Start(b, "1.1.1.1"); got != (StartResult{Status: 422, Error: "invalid_email"}) {
			t.Fatalf("start(%q) = %+v", b, got)
		}
	}
	if v := r.svc.Verify("a@b", "123456", "1.1.1.1"); v != (VerifyResult{Status: 400, Error: "invalid_code"}) {
		t.Fatalf("verify malformed = %+v", v)
	}
	for _, spelled := range []string{"123 456", "123-456"} {
		r2 := newRig(t, "123456")
		r2.svc.Start("a@x.com", "1.1.1.1")
		if v := r2.svc.Verify("a@x.com", spelled, "1.1.1.1"); v.Status != 200 {
			t.Fatalf("verify %q = %+v", spelled, v)
		}
	}
	r3 := newRig(t, "123456")
	r3.svc.Start("a@x.com", "1.1.1.1")
	for _, c := range []string{"12345", "1234567", "abcdef", "١٢٣٤٥٦"} {
		if v := r3.svc.Verify("a@x.com", c, "1.1.1.1"); v != (VerifyResult{Status: 400, Error: "invalid_code"}) {
			t.Fatalf("verify %q = %+v", c, v)
		}
	}
	if row := r3.store.codes[r3.svc.EmailHash("a@x.com")]; row == nil || row.Attempts != 0 {
		t.Fatalf("malformed codes spent a try: %+v", row)
	}
}

// TestEmailCode12SendFailureAndConfig proves send_failed leaves no code, and construction fails closed.
// EMAILCODE-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestEmailCode12SendFailureAndConfig(t *testing.T) {
	r := newRig(t, "123456")
	r.sender.fail = true
	if got := r.svc.Start("a@x.com", "1.1.1.1"); got != (StartResult{Status: 503, Error: "send_failed"}) {
		t.Fatalf("false sender = %+v", got)
	}
	if len(r.store.codes) != 0 {
		t.Fatal("a code was left after send_failed")
	}
	r.sender.fail, r.sender.err = false, errors.New("smtp down")
	if got := r.svc.Start("a@x.com", "1.1.1.1"); got != (StartResult{Status: 503, Error: "send_failed"}) {
		t.Fatalf("raising sender = %+v", got)
	}
	if len(r.store.codes) != 0 {
		t.Fatal("a code was left after a raising sender")
	}
	_, err := New(Config{Secret: []byte(strings.Repeat("k", 31)), Sender: &fakeSender{}})
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Code != "not_configured" {
		t.Fatalf("short secret: %v", err)
	}
	_, err = New(Config{Secret: []byte(strings.Repeat("k", 32))})
	if !errors.As(err, &ce) || ce.Code != "not_configured" {
		t.Fatalf("no sender: %v", err)
	}
}

// TestEmailCode13SuspendedOrClosed proves the right code is 403 account_unavailable and is used up.
// EMAILCODE-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestEmailCode13SuspendedOrClosed(t *testing.T) {
	for _, status := range []string{"suspended", "closed"} {
		r := newRig(t, "123456")
		at := int64(5)
		_ = r.store.InsertAccountIfAbsent(Account{ID: "acc", Email: "a@x.com", EmailVerifiedAt: &at, Status: status, CreatedAt: 1})
		r.svc.Start("a@x.com", "1.1.1.1")
		if v := r.svc.Verify("a@x.com", "123456", "1.1.1.1"); v != (VerifyResult{Status: 403, Error: "account_unavailable"}) {
			t.Fatalf("%s = %+v", status, v)
		}
		if v := r.svc.Verify("a@x.com", "123456", "1.1.1.1"); v != (VerifyResult{Status: 400, Error: "invalid_code"}) {
			t.Fatalf("%s code not used up: %+v", status, v)
		}
	}
}

// TestEmailCode14CodeBindingAndGenerator proves a code is bound to its address, keeps leading zeros, and the
// generator gives the spec's codes.
// EMAILCODE-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory, the OS random source.
func TestEmailCode14CodeBindingAndGenerator(t *testing.T) {
	r := newRig(t, "000042")
	r.svc.Start("a@x.com", "1.1.1.1")
	if v := r.svc.Verify("b@x.com", "000042", "1.1.1.1"); v != (VerifyResult{Status: 400, Error: "invalid_code"}) {
		t.Fatalf("other address = %+v", v)
	}
	if r.sender.lastCode() != "000042" {
		t.Fatalf("sent %q", r.sender.lastCode())
	}
	if v := r.svc.Verify("a@x.com", "000042", "1.1.1.1"); v.Status != 200 {
		t.Fatalf("leading zeros = %+v", v)
	}
	q := queue([]byte{0xff, 0xff, 0xff, 0xff, 0x80, 0, 0, 0, 0xff, 0xf1, 0x3d, 0x7f, 0xff, 0xf1, 0x3d, 0x80, 0, 0, 0, 0x2a})
	for _, want := range []string{"483648", "999999", "000042"} {
		if got := GenerateCode(q); got != want {
			t.Fatalf("code = %s, want %s", got, want)
		}
	}
	re := regexp.MustCompile(`^[0-9]{6}$`)
	for i := 0; i < 50; i++ {
		if c := GenerateCode(cryptoRandom); !re.MatchString(c) {
			t.Fatalf("default code %q", c)
		}
	}
	r2 := newRig(t, "")
	r2.svc.Start("c@x.com", "1.1.1.1")
	if !re.MatchString(r2.sender.lastCode()) {
		t.Fatalf("service default code %q", r2.sender.lastCode())
	}
}

package totp

// Tests for totp_two_factor_go.go against docs/specs/totp_two_factor.md.
// Phase D wave 1, owner request 2026-11-10. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: memory only (in-memory store, injected clock and bytes); no network.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// kBytes is the RFC 4226 / 6238 test key "12345678901234567890".
// Why: TOTP-01 vectors. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
var kBytes = []byte("12345678901234567890")

// seq returns the bytes from..to inclusive.
// In: bounds. Out: bytes. Why: key and nonce vectors. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func seq(from, to byte) []byte {
	out := []byte{}
	for b := int(from); b <= int(to); b++ {
		out = append(out, byte(b))
	}
	return out
}

// source serves prefix first, then next() one byte at a time, whatever n is asked; it counts bytes served.
// Why: TOTP-03, TOTP-04 byte streams. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
type source struct {
	prefix []byte
	next   func() byte
	served int
}

// bytes serves n bytes.
// In: n. Out: bytes. Why: injected random_bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (s *source) bytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		if len(s.prefix) > 0 {
			out[i], s.prefix = s.prefix[0], s.prefix[1:]
		} else {
			out[i] = s.next()
		}
		s.served++
	}
	return out
}

// cryptoByte draws one byte from the OS.
// In: none. Out: byte. Why: unpredictable recovery codes in tests that do not check them. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the OS random source.
func cryptoByte() byte {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return b[0]
}

// trig is one service with its store, settable clock and byte source.
// Why: test helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type trig struct {
	svc   *Service
	store *MemoryStore
	now   int64
	src   *source
}

// newTrig builds a service with the spec's keys over store; the source serves K and the a0..ab nonce first.
// In: store. Out: rig. Why: helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func newTrig(t *testing.T, store *MemoryStore) *trig {
	r := &trig{store: store, now: 1111111000}
	r.src = &source{prefix: append(append([]byte{}, kBytes...), seq(0xa0, 0xab)...), next: cryptoByte}
	svc, err := New(Config{EncryptionKey: seq(0, 0x1f), RecoveryHashKey: seq(0x40, 0x5f), Issuer: "Example App",
		Store: store, Clock: func() int64 { return r.now }, RandomBytes: r.src.bytes})
	if err != nil {
		t.Fatal(err)
	}
	r.svc = svc
	return r
}

// code returns the 6-digit code of secret K at time at.
// In: time. Out: code. Why: helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func code(at int64) string {
	c, _ := TotpAt(Base32Encode(kBytes), at, 6)
	return c
}

// wrong returns a 6-digit code that no step of the window at time at accepts.
// In: time. Out: code. Why: failures. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func wrong(at int64) string {
	for _, c := range []string{"000000", "111111", "222222", "333333"} {
		if c != code(at-30) && c != code(at) && c != code(at+30) {
			return c
		}
	}
	return "444444"
}

// enrolled starts and confirms user with secret K at the rig's time and returns the recovery codes.
// In: rig, user. Out: codes. Why: helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func enrolled(t *testing.T, r *trig, user string) []string {
	if len(r.src.prefix) == 0 {
		r.src.prefix = append(append([]byte{}, kBytes...), seq(0xa0, 0xab)...)
	}
	if _, ref := r.svc.EnrollStart(user, user+"@example.com"); ref != nil {
		t.Fatalf("enroll_start: %+v", ref)
	}
	codes, ref := r.svc.EnrollConfirm(user, code(r.now))
	if ref != nil {
		t.Fatalf("enroll_confirm: %+v", ref)
	}
	return codes
}

// failures counts the user's failure rows.
// In: store, user. Out: count. Why: "adds no failure" checks. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: memory.
func failures(s *MemoryStore, user string) int {
	ts, _ := s.FailureTimes(user)
	return len(ts)
}

// TestTotp01HotpAndTotpVectors proves the RFC 4226 and RFC 6238 values, the 64-bit counter included.
// TOTP-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func TestTotp01HotpAndTotpVectors(t *testing.T) {
	want := strings.Fields("755224 287082 359152 969429 338314 254676 287922 162583 399871 520489")
	for c, w := range want {
		if got := Hotp(kBytes, uint64(c), 6); got != w {
			t.Fatalf("hotp(%d) = %s, want %s", c, got, w)
		}
	}
	if got := Hotp(kBytes, 4294967296, 6); got != "999456" {
		t.Fatalf("hotp(2^32) = %s", got)
	}
	table := []struct {
		at     int64
		d8, d6 string
	}{
		{59, "94287082", "287082"}, {1111111109, "07081804", "081804"}, {1111111111, "14050471", "050471"},
		{1234567890, "89005924", "005924"}, {2000000000, "69279037", "279037"}, {20000000000, "65353130", "353130"},
	}
	sec := Base32Encode(kBytes)
	for _, row := range table {
		g8, _ := TotpAt(sec, row.at, 8)
		g6, _ := TotpAt(sec, row.at, 6)
		if g8 != row.d8 || g6 != row.d6 {
			t.Fatalf("totp_at(%d) = %s %s", row.at, g8, g6)
		}
	}
}

// TestTotp02Base32 proves the RFC 4648 vectors, the decode rules and generate_secret.
// TOTP-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the OS random source.
func TestTotp02Base32(t *testing.T) {
	if Base32Encode(kBytes) != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" {
		t.Fatal("base32(K)")
	}
	vec := [][2]string{{"", ""}, {"f", "MY"}, {"fo", "MZXQ"}, {"foo", "MZXW6"}, {"foob", "MZXW6YQ"}, {"fooba", "MZXW6YTB"}, {"foobar", "MZXW6YTBOI"}}
	for _, v := range vec {
		if got := Base32Encode([]byte(v[0])); got != v[1] {
			t.Fatalf("encode(%q) = %s", v[0], got)
		}
		if v[1] != "" {
			if got, err := Base32Decode(v[1]); err != nil || string(got) != v[0] {
				t.Fatalf("decode(%s) = %q %v", v[1], got, err)
			}
		}
	}
	if got, err := Base32Decode("mzxw 6ytb-oi=="); err != nil || string(got) != "foobar" {
		t.Fatalf("lenient decode = %q %v", got, err)
	}
	if got, err := Base32Decode("MZ"); err != nil || string(got) != "f" {
		t.Fatalf("MZ = %q %v", got, err)
	}
	for _, bad := range []string{"MZXW6YT1", "", "M", "MZX", "MZXW6Y"} {
		if _, err := Base32Decode(bad); !errors.Is(err, ErrInvalidBase32) {
			t.Fatalf("decode(%q) err = %v", bad, err)
		}
	}
	svc, _ := New(Config{EncryptionKey: seq(0, 0x1f), RecoveryHashKey: seq(0x40, 0x5f)})
	s := svc.GenerateSecret()
	b, err := Base32Decode(s)
	if len(s) != 32 || err != nil || len(b) != 20 {
		t.Fatalf("generate_secret = %q", s)
	}
}

// TestTotp03EnrollStart proves the secret, the URI, the stored sealed string and replacement before confirm.
// TOTP-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestTotp03EnrollStart(t *testing.T) {
	r := newTrig(t, NewMemoryStore())
	res, ref := r.svc.EnrollStart("user_1", "alice@example.com")
	if ref != nil || res.Secret != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" ||
		res.OtpauthURI != "otpauth://totp/Example%20App%3Aalice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example%20App&algorithm=SHA1&digits=6&period=30" {
		t.Fatalf("enroll_start = %+v %+v", res, ref)
	}
	e := r.store.enrolls["user_1"]
	if e.SecretEnc != "v1.oKGio6SlpqeoqaqroV0maQKFQOklPLSHVjWKjzfpA1TV+QA621cV0i7kP1B5d8k2owRGDhH/FzF0f662" ||
		e.ConfirmedAt != nil || e.LastUsedStep != 0 || e.FailedSinceSuccess != 0 || e.CreatedAt != r.now {
		t.Fatalf("row = %+v", e)
	}
	if strings.Contains(e.SecretEnc, res.Secret) {
		t.Fatal("the store holds the base32 secret")
	}
	res2, _ := r.svc.EnrollStart("user_1", "alice@example.com")
	if res2.Secret == res.Secret || r.store.enrolls["user_1"].SecretEnc == e.SecretEnc {
		t.Fatal("a second enroll_start did not replace the secret")
	}
	if _, ref := r.svc.EnrollConfirm("user_1", code(r.now)); ref == nil || ref.Error != "invalid_code" {
		t.Fatalf("the replaced secret still confirms: %+v", ref)
	}
}

// TestTotp04EnrollConfirm proves the recovery codes (the spec's byte stream), their keyed hashes and the 409s.
// TOTP-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestTotp04EnrollConfirm(t *testing.T) {
	r := newTrig(t, NewMemoryStore())
	k := 0
	r.src.next = func() byte { b := byte((7 * k) % 256); k++; return b }
	if _, ref := r.svc.EnrollConfirm("user_1", code(r.now)); ref == nil || *ref != (Refusal{Error: "enrollment_not_started", Status: 409}) {
		t.Fatalf("nothing started = %+v", ref)
	}
	r.svc.EnrollStart("user_1", "alice@example.com")
	before := r.src.served
	codes, ref := r.svc.EnrollConfirm("user_1", code(r.now))
	if ref != nil {
		t.Fatal(ref)
	}
	want := strings.Fields("29gq-y7en-w5ck t3ah-rz8f-px6d mv4b-js29-gqy5 ckt3-ahrz-8fpx 6dmv-4bjs-29gq y7en-w5ck-t8fp x6dm-v4bj-s29g qy7e-nw5c-kt3a")
	if strings.Join(codes, " ") != strings.Join(want, " ") {
		t.Fatalf("codes = %v", codes)
	}
	if r.src.served-before != 101 {
		t.Fatalf("bytes drawn = %d", r.src.served-before)
	}
	re := regexp.MustCompile(`^[23456789abcdefghjkmnpqrstvwxyz]{4}-[23456789abcdefghjkmnpqrstvwxyz]{4}-[23456789abcdefghjkmnpqrstvwxyz]{4}$`)
	for _, c := range codes {
		if !re.MatchString(c) {
			t.Fatalf("code shape %q", c)
		}
	}
	if len(r.store.recovery) != 8 || r.store.recovery[0].hash != "d9199ecad0b35d9e2f18857343d7fe79dd5f8425f1c460c88fe18f5c4b4a2645" {
		t.Fatalf("stored hashes = %+v", r.store.recovery)
	}
	for i, row := range r.store.recovery {
		n, _ := recoveryInput(codes[i])
		if row.hash != r.svc.RecoveryHash("user_1", n) || strings.Contains(row.hash, n) {
			t.Fatalf("row %d is not the keyed hash", i)
		}
	}
	if _, ref := r.svc.Verify("user_1", code(r.now)); ref == nil || *ref != (Refusal{Error: "invalid_code", Status: 401}) {
		t.Fatalf("confirming code reused = %+v", ref)
	}
	if _, ref := r.svc.EnrollConfirm("user_1", code(r.now)); ref == nil || *ref != (Refusal{Error: "already_enrolled", Status: 409}) {
		t.Fatalf("second confirm = %+v", ref)
	}
	if _, ref := r.svc.EnrollStart("user_1", "x"); ref == nil || *ref != (Refusal{Error: "already_enrolled", Status: 409}) {
		t.Fatalf("enroll_start after confirm = %+v", ref)
	}
}

// TestTotp05Window proves one step of drift each way and no more (the window vector, refusals first).
// TOTP-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestTotp05Window(t *testing.T) {
	r := newTrig(t, NewMemoryStore())
	enrolled(t, r, "user_1")
	r.now = 1111111109
	for _, c := range []string{"150727", "266759"} {
		if _, ref := r.svc.Verify("user_1", c); ref == nil || *ref != (Refusal{Error: "invalid_code", Status: 401}) {
			t.Fatalf("%s = %+v", c, ref)
		}
	}
	for _, c := range []string{"731029", "081804", "050471"} {
		if res, ref := r.svc.Verify("user_1", c); ref != nil || res.Method != "totp" {
			t.Fatalf("%s = %+v", c, ref)
		}
	}
}

// TestTotp06Replay proves an accepted code and an earlier step are refused, a later step is accepted, and the
// store's claim succeeds once per step.
// TOTP-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestTotp06Replay(t *testing.T) {
	r := newTrig(t, NewMemoryStore())
	enrolled(t, r, "user_1")
	r.now = 1111111109
	if _, ref := r.svc.Verify("user_1", "081804"); ref != nil {
		t.Fatal(ref)
	}
	if _, ref := r.svc.Verify("user_1", "081804"); ref == nil || ref.Status != 401 {
		t.Fatalf("replay = %+v", ref)
	}
	if _, ref := r.svc.Verify("user_1", "731029"); ref == nil || ref.Status != 401 {
		t.Fatalf("earlier step = %+v", ref)
	}
	if _, ref := r.svc.Verify("user_1", "050471"); ref != nil {
		t.Fatalf("later step = %+v", ref)
	}
	if ok, _ := r.store.Claim("user_1", 37037040); !ok {
		t.Fatal("first claim refused")
	}
	if ok, _ := r.store.Claim("user_1", 37037040); ok {
		t.Fatal("second claim of the same step succeeded")
	}
}

// TestTotp07Input proves the accepted spellings and that malformed codes are 401 with one failure each.
// TOTP-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestTotp07Input(t *testing.T) {
	for _, spelled := range []string{"081804", "081 804", "081-804"} {
		r := newTrig(t, NewMemoryStore())
		enrolled(t, r, "user_1")
		r.now = 1111111109
		if _, ref := r.svc.Verify("user_1", spelled); ref != nil {
			t.Fatalf("%q = %+v", spelled, ref)
		}
	}
	bad := []string{"08180", "0818045", "abcdef", "", strings.Repeat("0", 65), "٠٨١٨٠٤"}
	for i, c := range bad {
		r := newTrig(t, NewMemoryStore())
		user := "u" + itoa(int64(i))
		enrolled(t, r, user)
		r.now = 1111111109
		if _, ref := r.svc.Verify(user, c); ref == nil || *ref != (Refusal{Error: "invalid_code", Status: 401}) {
			t.Fatalf("%q = %+v", c, ref)
		}
		if failures(r.store, user) != 1 || r.store.enrolls[user].FailedSinceSuccess != 1 {
			t.Fatalf("%q did not add exactly one failure", c)
		}
	}
}

// TestTotp08RecoveryCodes proves single use, spellings, per-user binding and the keyed hash vector.
// TOTP-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestTotp08RecoveryCodes(t *testing.T) {
	r := newTrig(t, NewMemoryStore())
	codes := enrolled(t, r, "user_a")
	res, ref := r.svc.Verify("user_a", codes[0])
	if ref != nil || *res != (VerifyResult{OK: true, Method: "recovery_code", RecoveryCodesLeft: 7}) {
		t.Fatalf("recovery = %+v %+v", res, ref)
	}
	if _, ref := r.svc.Verify("user_a", codes[0]); ref == nil || ref.Status != 401 {
		t.Fatalf("reused = %+v", ref)
	}
	if res, ref := r.svc.Verify("user_a", strings.ToUpper(codes[1])); ref != nil || res.RecoveryCodesLeft != 6 {
		t.Fatalf("upper case = %+v", ref)
	}
	if res, ref := r.svc.Verify("user_a", strings.ReplaceAll(codes[2], "-", "")); ref != nil || res.RecoveryCodesLeft != 5 {
		t.Fatalf("no dashes = %+v", ref)
	}
	enrolled(t, r, "user_b")
	if _, ref := r.svc.Verify("user_b", codes[3]); ref == nil || ref.Status != 401 {
		t.Fatalf("A's code for B = %+v", ref)
	}
	if h := r.svc.RecoveryHash("user_1", "k7mq2xpt9hcw"); h != "5a93360f78c7f03de7336a625adf93bf238749d8da4aaf734271b327c52347a3" {
		t.Fatalf("code_hash = %s", h)
	}
	n, _ := recoveryInput("K7MQ-2XPT-9HCW")
	plain := sha256.Sum256([]byte(n))
	if n != "k7mq2xpt9hcw" || hex.EncodeToString(plain[:]) == r.svc.RecoveryHash("user_1", n) {
		t.Fatal("recovery hash is a plain SHA-256")
	}
}

// TestTotp09Lock proves the 5-in-900-seconds lock, retry_after, its end, and the store's try write.
// TOTP-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestTotp09Lock(t *testing.T) {
	r := newTrig(t, NewMemoryStore())
	enrolled(t, r, "user_1")
	r.now = 1111112000
	for i := 0; i < 5; i++ {
		r.svc.Verify("user_1", wrong(r.now))
	}
	if _, ref := r.svc.Verify("user_1", code(r.now)); ref == nil || *ref != (Refusal{Error: "locked", Status: 429, RetryAfter: 900}) {
		t.Fatalf("6th = %+v", ref)
	}
	if failures(r.store, "user_1") != 5 {
		t.Fatal("the locked answer added a failure")
	}
	r.now += 899
	if _, ref := r.svc.Verify("user_1", code(r.now)); ref == nil || *ref != (Refusal{Error: "locked", Status: 429, RetryAfter: 1}) {
		t.Fatalf("at 899 = %+v", ref)
	}
	st, _ := r.svc.Status("user_1")
	if st.LockedUntil == nil || *st.LockedUntil != 1111112900 {
		t.Fatalf("status = %+v", st)
	}
	r.now++
	if _, ref := r.svc.Verify("user_1", code(r.now)); ref != nil {
		t.Fatalf("at 900 = %+v", ref)
	}
	s := NewMemoryStore()
	for i := 0; i < 5; i++ {
		if _, ok, _ := s.Try("u", 1000); !ok {
			t.Fatalf("try %d refused", i)
		}
	}
	if _, ok, _ := s.Try("u", 1000); ok {
		t.Fatal("6th try write succeeded")
	}
}

// TestTotp10SecretUnreadable proves 503 for a sealed secret that does not open, no failure, and recovery works.
// TOTP-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestTotp10SecretUnreadable(t *testing.T) {
	store := NewMemoryStore()
	r := newTrig(t, store)
	codes := enrolled(t, r, "user_1")
	r.now = 1111111109
	other, _ := New(Config{EncryptionKey: seq(0x60, 0x7f), RecoveryHashKey: seq(0x40, 0x5f), Store: store,
		Clock: func() int64 { return r.now }})
	if _, ref := other.Verify("user_1", code(r.now)); ref == nil || *ref != (Refusal{Error: "secret_unreadable", Status: 503}) {
		t.Fatalf("other key = %+v", ref)
	}
	if failures(store, "user_1") != 0 || store.enrolls["user_1"].FailedSinceSuccess != 0 {
		t.Fatal("503 added a failure")
	}
	if res, ref := other.Verify("user_1", codes[0]); ref != nil || res.Method != "recovery_code" {
		t.Fatalf("recovery with other key = %+v", ref)
	}
	enc := []byte(store.enrolls["user_1"].SecretEnc)
	if enc[10] == 'A' {
		enc[10] = 'B'
	} else {
		enc[10] = 'A'
	}
	store.enrolls["user_1"].SecretEnc = string(enc)
	if _, ref := r.svc.Verify("user_1", code(r.now)); ref == nil || *ref != (Refusal{Error: "secret_unreadable", Status: 503}) {
		t.Fatalf("changed character = %+v", ref)
	}
	if failures(store, "user_1") != 0 {
		t.Fatal("503 added a failure")
	}
	if res, ref := r.svc.Verify("user_1", codes[1]); ref != nil || res.Method != "recovery_code" {
		t.Fatalf("recovery = %+v", ref)
	}
}

// TestTotp11SealOpenAndKeys proves the seal vector, open's refusals and the key-size checks.
// TOTP-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func TestTotp11SealOpenAndKeys(t *testing.T) {
	key := seq(0, 0x1f)
	want := "v1.oKGio6SlpqeoqaqroV0maQKFQOklPLSHVjWKjzfpA1TV+QA621cV0i7kP1B5d8k2owRGDhH/FzF0f662"
	s, err := Seal(key, seq(0xa0, 0xab), []byte(Base32Encode(kBytes)), "totp:user_1")
	if err != nil || s != want {
		t.Fatalf("seal = %s %v", s, err)
	}
	if pt, ok := Open(key, s, "totp:user_1"); !ok || string(pt) != Base32Encode(kBytes) {
		t.Fatal("open")
	}
	changed := []byte(s)
	changed[20] ^= 0x01
	for i, c := range []struct {
		key []byte
		s   string
		aad string
	}{{key, s, "totp:user_2"}, {seq(1, 0x20), s, "totp:user_1"}, {key, string(changed), "totp:user_1"},
		{key, s[3:], "totp:user_1"}, {key, "v1.@@@", "totp:user_1"}, {key, "v1.AAAA", "totp:user_1"}} {
		if _, ok := Open(c.key, c.s, c.aad); ok {
			t.Fatalf("case %d opened", i)
		}
	}
	var ce *ConfigError
	for _, cfg := range []Config{{EncryptionKey: key[:31], RecoveryHashKey: seq(0x40, 0x5f)},
		{EncryptionKey: append(key, 0), RecoveryHashKey: seq(0x40, 0x5f)}, {EncryptionKey: key, RecoveryHashKey: seq(0x40, 0x5e)}} {
		if _, err := New(cfg); !errors.As(err, &ce) || ce.Code != "invalid_key" {
			t.Fatalf("construction: %v", err)
		}
	}
}

// TestTotp12Disable proves disable deletes everything with a valid code and nothing with a wrong one.
// TOTP-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestTotp12Disable(t *testing.T) {
	r := newTrig(t, NewMemoryStore())
	enrolled(t, r, "user_1")
	r.now = 1111111109
	if d, ref := r.svc.Disable("user_1", wrong(r.now)); d || ref == nil || *ref != (Refusal{Error: "invalid_code", Status: 401}) {
		t.Fatalf("wrong = %v %+v", d, ref)
	}
	if r.store.enrolls["user_1"] == nil || len(r.store.recovery) != 8 {
		t.Fatal("a wrong code deleted something")
	}
	if d, ref := r.svc.Disable("user_1", code(r.now)); !d || ref != nil {
		t.Fatalf("disable = %v %+v", d, ref)
	}
	if r.store.enrolls["user_1"] != nil || len(r.store.recovery) != 0 || failures(r.store, "user_1") != 0 {
		t.Fatal("disable left rows")
	}
	if _, ref := r.svc.Verify("user_1", code(r.now+30)); ref == nil || *ref != (Refusal{Error: "not_enrolled", Status: 409}) {
		t.Fatalf("verify after disable = %+v", ref)
	}
}

// TestTotp13NotEnrolledAndIsolation proves 409 before confirm and that two users' codes never cross.
// TOTP-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestTotp13NotEnrolledAndIsolation(t *testing.T) {
	r := newTrig(t, NewMemoryStore())
	r.svc.EnrollStart("user_1", "x")
	if _, ref := r.svc.Verify("user_1", code(r.now)); ref == nil || *ref != (Refusal{Error: "not_enrolled", Status: 409}) {
		t.Fatalf("verify = %+v", ref)
	}
	if _, ref := r.svc.Disable("user_1", code(r.now)); ref == nil || *ref != (Refusal{Error: "not_enrolled", Status: 409}) {
		t.Fatalf("disable = %+v", ref)
	}
	r.svc.EnrollConfirm("user_1", code(r.now))
	r.src.prefix = append(append([]byte{}, []byte("abcdefghijklmnopqrst")...), seq(0xb0, 0xbb)...)
	r.svc.EnrollStart("user_2", "y")
	secB := Base32Encode([]byte("abcdefghijklmnopqrst"))
	cb, _ := TotpAt(secB, r.now, 6)
	if _, ref := r.svc.EnrollConfirm("user_2", cb); ref != nil {
		t.Fatal(ref)
	}
	r.now = 1111111109
	cb2, _ := TotpAt(secB, r.now+30, 6)
	if cb2 == code(r.now) || cb2 == code(r.now+30) || cb2 == code(r.now-30) {
		t.Fatal("the two fixed secrets collide at this time; pick another time")
	}
	if _, ref := r.svc.Verify("user_2", code(r.now+30)); ref == nil || ref.Status != 401 {
		t.Fatalf("A's code for B = %+v", ref)
	}
	if _, ref := r.svc.Verify("user_1", cb2); ref == nil || ref.Status != 401 {
		t.Fatalf("B's code for A = %+v", ref)
	}
}

// TestTotp14HardLock proves recovery_required after 100 failures, its end by a recovery code, and the reset.
// TOTP-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestTotp14HardLock(t *testing.T) {
	r := newTrig(t, NewMemoryStore())
	codes := enrolled(t, r, "user_1")
	r.now = 1111200000
	for w := 0; w < 20; w++ {
		for i := 0; i < 5; i++ {
			if _, ref := r.svc.Verify("user_1", wrong(r.now)); ref == nil || ref.Error != "invalid_code" {
				t.Fatalf("window %d try %d = %+v", w, i, ref)
			}
		}
		r.now += 900
	}
	if r.store.enrolls["user_1"].FailedSinceSuccess != 100 {
		t.Fatalf("failed_since_success = %d", r.store.enrolls["user_1"].FailedSinceSuccess)
	}
	if _, ref := r.svc.Verify("user_1", code(r.now)); ref == nil || *ref != (Refusal{Error: "recovery_required", Status: 429}) {
		t.Fatalf("after 100 = %+v", ref)
	}
	r.now += 10000000
	if _, ref := r.svc.Verify("user_1", code(r.now)); ref == nil || *ref != (Refusal{Error: "recovery_required", Status: 429}) {
		t.Fatalf("much later = %+v", ref)
	}
	if r.store.enrolls["user_1"].FailedSinceSuccess != 100 {
		t.Fatal("recovery_required added a failure")
	}
	if st, _ := r.svc.Status("user_1"); !st.RecoveryRequired {
		t.Fatal("status.recovery_required")
	}
	if res, ref := r.svc.Verify("user_1", codes[0]); ref != nil || res.Method != "recovery_code" {
		t.Fatalf("recovery = %+v", ref)
	}
	if res, ref := r.svc.Verify("user_1", code(r.now)); ref != nil || res.Method != "totp" {
		t.Fatalf("totp after recovery = %+v", ref)
	}
	r2 := newTrig(t, NewMemoryStore())
	enrolled(t, r2, "user_1")
	r2.now = 1111200000
	for n := 0; n < 99; n++ {
		r2.svc.Verify("user_1", wrong(r2.now))
		if n%5 == 4 {
			r2.now += 900
		}
	}
	r2.now += 900
	if _, ref := r2.svc.Verify("user_1", code(r2.now)); ref != nil {
		t.Fatalf("success at 99 = %+v", ref)
	}
	if r2.store.enrolls["user_1"].FailedSinceSuccess != 0 {
		t.Fatal("a success did not reset the count")
	}
	r2.svc.Verify("user_1", wrong(r2.now))
	r2.now += 60
	if _, ref := r2.svc.Verify("user_1", code(r2.now)); ref != nil {
		t.Fatalf("after reset = %+v", ref)
	}
}

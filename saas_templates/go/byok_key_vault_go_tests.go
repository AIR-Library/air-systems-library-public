package byokvault

// Tests for byok_key_vault_go.go against docs/specs/byok_key_vault.md.
// Phase D wave 1, owner request 2026-11-10. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: memory only (in-memory store, fake provider client, fixed clock); no network.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// testKey is the spec's key, built from two pieces so no scanner reads it as a credential.
// Why: VAULT-02 vector. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
var testKey = "acme_" + "k3y0123456789abcdefghWXYZ"

// fakeClient records checks and answers with ans or err.
// Why: no network in tests. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
type fakeClient struct {
	calls []string
	ans   string
	err   error
}

// Check records the call and answers as configured.
// In: provider, key. Out: answer, error. Why: fake. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (f *fakeClient) Check(provider, key string) (string, error) {
	f.calls = append(f.calls, provider+"|"+key)
	return f.ans, f.err
}

// seq returns the bytes from..to inclusive.
// In: bounds. Out: bytes. Why: vectors. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func seq(from, to byte) []byte {
	out := []byte{}
	for b := int(from); b <= int(to); b++ {
		out = append(out, byte(b))
	}
	return out
}

// queue serves bytes in order, whatever n is asked.
// In: bytes. Out: random_bytes. Why: vectors. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func queue(b []byte) func(int) []byte {
	return func(n int) []byte {
		out := b[:n]
		b = b[n:]
		return out
	}
}

// specRandom is the byte stream of the spec's save_key vector.
// In: none. Out: random_bytes. Why: VAULT-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func specRandom() func(int) []byte {
	b := append(append(seq(0x20, 0x3f), seq(0x60, 0x6b)...), seq(0x70, 0x7b)...)
	return queue(b)
}

// vrig is one vault with its store, client and settable clock.
// Why: test helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type vrig struct {
	v      *Vault
	store  *MemoryStore
	client *fakeClient
	now    int64
}

// providers returns acme and beta, each with the spec's bounds.
// In: none. Out: providers. Why: VAULT-08 needs a second provider. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func providers() map[string]Provider {
	return map[string]Provider{"acme": {Prefix: "acme_", MinLength: 24, MaxLength: 200},
		"beta": {Prefix: "beta_", MinLength: 24, MaxLength: 200}}
}

// newVRig builds a vault over store with master keys keys and active id; rnd nil means the CSPRNG.
// In: store, keys, active, random. Out: rig. Why: helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: memory.
func newVRig(t *testing.T, store *MemoryStore, keys map[string][]byte, active string, rnd func(int) []byte) *vrig {
	r := &vrig{store: store, client: &fakeClient{ans: "ok"}, now: 1699920000}
	v, err := New(Config{MasterKeys: keys, ActiveKeyID: active, Providers: providers(), ProviderClient: r.client,
		Store: store, Clock: func() int64 { return r.now }, RandomBytes: rnd})
	if err != nil {
		t.Fatal(err)
	}
	r.v = v
	return r
}

// k1 and k2 are the spec's master keys.
// Why: VAULT-02, VAULT-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
var k1, k2 = seq(0x00, 0x1f), seq(0x40, 0x5f)

// TestVault01SaveHappyPath proves the check is called once, the row holds no key and the audit row exists.
// VAULT-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestVault01SaveHappyPath(t *testing.T) {
	r := newVRig(t, NewMemoryStore(), map[string][]byte{"k1": k1}, "k1", nil)
	got, ref := r.v.SaveKey("user_1", "acme", testKey)
	if ref != nil || *got != (SavedKey{Provider: "acme", Hint: "WXYZ", KeyID: "k1", CreatedAt: r.now}) {
		t.Fatalf("save = %+v %+v", got, ref)
	}
	if len(r.client.calls) != 1 || r.client.calls[0] != "acme|"+testKey {
		t.Fatalf("checks = %v", r.client.calls)
	}
	row := r.store.keys[rowKey("user_1", "acme")]
	if row == nil || row.KeyID != "k1" || row.Hint != "WXYZ" || row.WrappedDEK == "" || row.Ciphertext == "" {
		t.Fatalf("row = %+v", row)
	}
	blob, _ := json.Marshal(row)
	if strings.Contains(string(blob), testKey) || strings.Contains(string(blob), "k3y0123456789") {
		t.Fatal("the row holds the key")
	}
	audit, _ := r.v.ListAudit("user_1")
	if len(audit) != 1 || audit[0].Action != "key_saved" || audit[0].Provider != "acme" || audit[0].KeyID != "k1" || audit[0].At != r.now {
		t.Fatalf("audit = %+v", audit)
	}
}

// TestVault02KnownAnswer proves the stored ciphertext and wrapped_dek are the spec's strings.
// VAULT-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestVault02KnownAnswer(t *testing.T) {
	r := newVRig(t, NewMemoryStore(), map[string][]byte{"k1": k1}, "k1", specRandom())
	if _, ref := r.v.SaveKey("user_1", "acme", testKey); ref != nil {
		t.Fatal(ref)
	}
	row := r.store.keys[rowKey("user_1", "acme")]
	if row.Ciphertext != "YGFiY2RlZmdoaWprg/fAzqy7SCzJdVWPIX9FTko++mAiaT2vbM/uMNaLHZjhWoVBGl1vBtJurMStRQ==" {
		t.Fatalf("ciphertext = %s", row.Ciphertext)
	}
	if row.WrappedDEK != "cHFyc3R1dnd4eXp7N6aYBJfsuhNsAxz5/W2f+J0G974wrnqNnbcDf3iKKAEOSVqlT/aJkU58qxAv2nPf" {
		t.Fatalf("wrapped_dek = %s", row.WrappedDEK)
	}
	if k, ref := r.v.UseKey("user_1", "acme", "chat"); ref != nil || k != testKey {
		t.Fatalf("use = %q %+v", k, ref)
	}
}

// TestVault03InvalidFormat proves unknown providers and malformed keys are refused before any check or write.
// VAULT-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestVault03InvalidFormat(t *testing.T) {
	r := newVRig(t, NewMemoryStore(), map[string][]byte{"k1": k1}, "k1", nil)
	if _, ref := r.v.SaveKey("user_1", "nope", testKey); ref == nil || *ref != (Refusal{Error: "unknown_provider", Status: 404}) {
		t.Fatalf("unknown provider = %+v", ref)
	}
	bad := []string{
		"beta_" + "k3y0123456789abcdefghWXYZ",
		"acme_" + "short",
		"acme_" + strings.Repeat("x", 196),
		"acme_" + "k3y0123456 789abcdefghWXYZ",
		"acme_" + "k3y0123456\n789abcdefghWXYZ",
		testKey + " ",
		testKey + "\u000b",
		testKey + "\u0000",
	}
	for _, k := range bad {
		if _, ref := r.v.SaveKey("user_1", "acme", k); ref == nil || *ref != (Refusal{Error: "invalid_key_format", Status: 400}) {
			t.Fatalf("SaveKey(%q) = %+v", k, ref)
		}
	}
	if len(r.client.calls) != 0 || len(r.store.keys) != 0 || len(r.store.audit) != 0 || len(r.store.windows) != 0 {
		t.Fatal("a refusal called the provider or stored something")
	}
	if got, ref := r.v.SaveKey("user_1", "acme", " \t"+testKey+"\r\n"); ref != nil || got.Hint != "WXYZ" {
		t.Fatalf("trimmed key = %+v %+v", got, ref)
	}
	if r.client.calls[0] != "acme|"+testKey {
		t.Fatalf("checked %q", r.client.calls[0])
	}
}

// TestVault04ProviderAnswers proves rejected is 400, unreachable/other/error is 502, and nothing is stored.
// VAULT-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestVault04ProviderAnswers(t *testing.T) {
	r := newVRig(t, NewMemoryStore(), map[string][]byte{"k1": k1}, "k1", nil)
	cases := []struct {
		ans  string
		err  error
		want Refusal
	}{
		{"rejected", nil, Refusal{Error: "key_rejected", Status: 400}},
		{"unreachable", nil, Refusal{Error: "provider_unreachable", Status: 502}},
		{"maybe", nil, Refusal{Error: "provider_unreachable", Status: 502}},
		{"ok", errors.New("timeout"), Refusal{Error: "provider_unreachable", Status: 502}},
	}
	for i, c := range cases {
		r.client.ans, r.client.err = c.ans, c.err
		if _, ref := r.v.SaveKey("user_1", "acme", testKey); ref == nil || *ref != c.want {
			t.Fatalf("case %d = %+v", i, ref)
		}
		if len(r.store.keys) != 0 || len(r.store.audit) != 0 {
			t.Fatalf("case %d stored something", i)
		}
	}
	if r.store.windows["user_1\x00"+itoa(1699920000)] != 4 {
		t.Fatalf("checks counted = %d", r.store.windows["user_1\x00"+itoa(1699920000)])
	}
}

// TestVault05ListKeys proves list_keys' fields and order, and that its JSON holds no secret material.
// VAULT-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestVault05ListKeys(t *testing.T) {
	r := newVRig(t, NewMemoryStore(), map[string][]byte{"k1": k1}, "k1", nil)
	r.v.SaveKey("user_1", "beta", "beta_"+"k3y0123456789abcdefghABCD")
	r.v.SaveKey("user_1", "acme", testKey)
	list, ref := r.v.ListKeys("user_1")
	if ref != nil || len(list) != 2 || list[0].Provider != "acme" || list[1].Provider != "beta" ||
		list[0].Hint != "WXYZ" || list[1].Hint != "ABCD" || list[0].KeyID != "k1" || list[0].CreatedAt != r.now || list[0].LastUsedAt != nil {
		t.Fatalf("list = %+v", list)
	}
	blob, _ := json.Marshal(list)
	s := string(blob)
	for _, bad := range []string{testKey, r.store.keys[rowKey("user_1", "acme")].Ciphertext, r.store.keys[rowKey("user_1", "acme")].WrappedDEK, "ciphertext", "wrapped"} {
		if strings.Contains(s, bad) {
			t.Fatalf("list JSON holds %q", bad)
		}
	}
	for _, f := range []string{`"provider"`, `"hint"`, `"key_id"`, `"created_at"`, `"last_used_at"`} {
		if !strings.Contains(s, f) {
			t.Fatalf("list JSON lacks %s: %s", f, s)
		}
	}
}

// TestVault06UseKey proves use_key's audit, last_used_at, purpose check and the audit-failure answer.
// VAULT-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestVault06UseKey(t *testing.T) {
	r := newVRig(t, NewMemoryStore(), map[string][]byte{"k1": k1}, "k1", nil)
	r.v.SaveKey("user_1", "acme", testKey)
	r.now += 50
	k, ref := r.v.UseKey("user_1", "acme", "chat.completion:v1")
	if ref != nil || k != testKey {
		t.Fatalf("use = %+v", ref)
	}
	if lu := r.store.keys[rowKey("user_1", "acme")].LastUsedAt; lu == nil || *lu != r.now {
		t.Fatalf("last_used_at = %v", lu)
	}
	audit, _ := r.v.ListAudit("user_1")
	if len(audit) != 2 || audit[1].Action != "key_used" || audit[1].Purpose == nil || *audit[1].Purpose != "chat.completion:v1" || audit[1].At != r.now {
		t.Fatalf("audit = %+v", audit)
	}
	for _, p := range []string{"", "bad purpose", "x/y", strings.Repeat("a", 101)} {
		if _, ref := r.v.UseKey("user_1", "acme", p); ref == nil || *ref != (Refusal{Error: "invalid_purpose", Status: 400}) {
			t.Fatalf("purpose %q = %+v", p, ref)
		}
	}
	r.store.failAudit = true
	r.now += 10
	k, ref = r.v.UseKey("user_1", "acme", "chat")
	if k != "" || ref == nil || *ref != (Refusal{Error: "storage_failed", Status: 500}) {
		t.Fatalf("audit failure = %q %+v", k, ref)
	}
	if lu := r.store.keys[rowKey("user_1", "acme")].LastUsedAt; *lu != r.now-10 {
		t.Fatal("last_used_at changed although the audit write failed")
	}
	r.store.failAudit = false
	blob, _ := json.Marshal(r.store.audit)
	refBlob, _ := json.Marshal(ref)
	if strings.Contains(string(blob), testKey) || strings.Contains(string(refBlob), testKey) {
		t.Fatal("an audit row or a refusal holds the key")
	}
}

// TestVault07Isolation proves user B sees nothing of user A's key.
// VAULT-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestVault07Isolation(t *testing.T) {
	r := newVRig(t, NewMemoryStore(), map[string][]byte{"k1": k1}, "k1", nil)
	r.v.SaveKey("user_a", "acme", testKey)
	if list, _ := r.v.ListKeys("user_b"); len(list) != 0 {
		t.Fatalf("B list = %+v", list)
	}
	if _, ref := r.v.UseKey("user_b", "acme", "chat"); ref == nil || *ref != (Refusal{Error: "key_not_found", Status: 404}) {
		t.Fatalf("B use = %+v", ref)
	}
	if d, ref := r.v.DeleteKey("user_b", "acme"); d || ref != nil {
		t.Fatalf("B delete = %v %+v", d, ref)
	}
	if k, ref := r.v.UseKey("user_a", "acme", "chat"); ref != nil || k != testKey {
		t.Fatalf("A use = %+v", ref)
	}
}

// flip decodes base64, XORs 01 into byte 20 and encodes again.
// In: base64 text. Out: base64 text. Why: VAULT-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func flip(s string) string {
	b, _ := base64.StdEncoding.DecodeString(s)
	b[20] ^= 0x01
	return base64.StdEncoding.EncodeToString(b)
}

// TestVault08TamperedRows proves moved, edited, non-base64 and short rows are 500 key_unreadable.
// VAULT-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestVault08TamperedRows(t *testing.T) {
	r := newVRig(t, NewMemoryStore(), map[string][]byte{"k1": k1}, "k1", nil)
	r.v.SaveKey("user_1", "acme", testKey)
	orig := *r.store.keys[rowKey("user_1", "acme")]
	want := Refusal{Error: "key_unreadable", Status: 500}
	moved := orig
	moved.UserID = "user_2"
	r.store.keys[rowKey("user_2", "acme")] = &moved
	if _, ref := r.v.UseKey("user_2", "acme", "chat"); ref == nil || *ref != want {
		t.Fatalf("moved to another user = %+v", ref)
	}
	moved2 := orig
	moved2.Provider = "beta"
	r.store.keys[rowKey("user_1", "beta")] = &moved2
	if _, ref := r.v.UseKey("user_1", "beta", "chat"); ref == nil || *ref != want {
		t.Fatalf("moved to another provider = %+v", ref)
	}
	edits := []func(*KeyRow){
		func(k *KeyRow) { k.Ciphertext = flip(k.Ciphertext) },
		func(k *KeyRow) { k.WrappedDEK = flip(k.WrappedDEK) },
		func(k *KeyRow) { k.Ciphertext = "not base64!!" },
		func(k *KeyRow) { k.WrappedDEK = "%%%%" },
		func(k *KeyRow) { k.Ciphertext = base64.StdEncoding.EncodeToString(make([]byte, 27)) },
		func(k *KeyRow) { k.WrappedDEK = base64.StdEncoding.EncodeToString([]byte("short")) },
	}
	for i, e := range edits {
		row := orig
		e(&row)
		r.store.keys[rowKey("user_1", "acme")] = &row
		if _, ref := r.v.UseKey("user_1", "acme", "chat"); ref == nil || *ref != want {
			t.Fatalf("edit %d = %+v", i, ref)
		}
	}
}

// TestVault09SaveAgainReplaces proves a second save replaces the row with a new DEK and nonces.
// VAULT-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestVault09SaveAgainReplaces(t *testing.T) {
	r := newVRig(t, NewMemoryStore(), map[string][]byte{"k1": k1}, "k1", nil)
	r.v.SaveKey("user_1", "acme", testKey)
	first := *r.store.keys[rowKey("user_1", "acme")]
	second := "acme_" + "n3wKey0123456789abcdefLMNO"
	got, ref := r.v.SaveKey("user_1", "acme", second)
	if ref != nil || got.Hint != "LMNO" {
		t.Fatalf("second save = %+v %+v", got, ref)
	}
	if len(r.store.keys) != 1 {
		t.Fatalf("rows = %d", len(r.store.keys))
	}
	row := r.store.keys[rowKey("user_1", "acme")]
	a, _ := base64.StdEncoding.DecodeString(first.Ciphertext)
	b, _ := base64.StdEncoding.DecodeString(row.Ciphertext)
	c, _ := base64.StdEncoding.DecodeString(first.WrappedDEK)
	d, _ := base64.StdEncoding.DecodeString(row.WrappedDEK)
	if string(a[:12]) == string(b[:12]) || string(c[:12]) == string(d[:12]) || row.Hint != "LMNO" {
		t.Fatal("nonces were reused")
	}
	dekA, _ := gcmOpen(k1, first.WrappedDEK, dekAAD("k1", "acme", "user_1"))
	dekB, _ := gcmOpen(k1, row.WrappedDEK, dekAAD("k1", "acme", "user_1"))
	if string(dekA) == string(dekB) {
		t.Fatal("the DEK was reused")
	}
	if k, _ := r.v.UseKey("user_1", "acme", "chat"); k != second {
		t.Fatalf("use = %q", k)
	}
}

// TestVault10Rotation proves rewrap under k2, the spec's rewrapped string, and the stale-write guard.
// VAULT-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestVault10Rotation(t *testing.T) {
	store := NewMemoryStore()
	r1 := newVRig(t, store, map[string][]byte{"k1": k1}, "k1", specRandom())
	r1.v.SaveKey("user_1", "acme", testKey)
	ct := store.keys[rowKey("user_1", "acme")].Ciphertext
	both := map[string][]byte{"k1": k1, "k2": k2}
	r2 := newVRig(t, store, both, "k2", nil)
	if got, ref := r2.v.SaveKey("user_2", "acme", testKey); ref != nil || got.KeyID != "k2" {
		t.Fatalf("new save = %+v %+v", got, ref)
	}
	r3 := newVRig(t, store, both, "k2", queue(seq(0x80, 0x8b)))
	res, ref := r3.v.Rewrap()
	if ref != nil || res != (RewrapResult{Rewrapped: 1, Failed: 0}) {
		t.Fatalf("rewrap = %+v %+v", res, ref)
	}
	row := store.keys[rowKey("user_1", "acme")]
	if row.KeyID != "k2" || row.Ciphertext != ct ||
		row.WrappedDEK != "gIGCg4SFhoeIiYqLDX+c5AZRDKRAQ7oDXo+7DcjN++F5UtAjxrdC7+0oX0MOT3cH13mFkfvVnrrN/V6R" {
		t.Fatalf("row = %+v", row)
	}
	audit, _ := r3.v.ListAudit("user_1")
	if audit[len(audit)-1].Action != "key_rewrapped" || audit[len(audit)-1].KeyID != "k2" {
		t.Fatalf("audit = %+v", audit)
	}
	r4 := newVRig(t, store, map[string][]byte{"k2": k2}, "k2", nil)
	for _, u := range []string{"user_1", "user_2"} {
		if k, ref := r4.v.UseKey(u, "acme", "chat"); ref != nil || k != testKey {
			t.Fatalf("%s after k1 removed = %+v", u, ref)
		}
	}
	changed, err := store.Rewrap("user_1", "acme", "k2", "x", "stale-wrapped-dek", AuditRow{UserID: "user_1", Action: "key_rewrapped"})
	if err != nil || changed {
		t.Fatalf("stale rewrap changed a row: %v %v", changed, err)
	}
	if store.keys[rowKey("user_1", "acme")].WrappedDEK == "x" {
		t.Fatal("stale rewrap wrote")
	}
}

// TestVault11KeyringAndConfig proves 503 key_unavailable and the construction failures.
// VAULT-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestVault11KeyringAndConfig(t *testing.T) {
	store := NewMemoryStore()
	r := newVRig(t, store, map[string][]byte{"k1": k1}, "k1", nil)
	r.v.SaveKey("user_1", "acme", testKey)
	r2 := newVRig(t, store, map[string][]byte{"k2": k2}, "k2", nil)
	if _, ref := r2.v.UseKey("user_1", "acme", "chat"); ref == nil || *ref != (Refusal{Error: "key_unavailable", Status: 503}) {
		t.Fatalf("missing master key = %+v", ref)
	}
	var ce *ConfigError
	_, err := New(Config{MasterKeys: map[string][]byte{"k1": k1[:31]}, ActiveKeyID: "k1", Providers: providers()})
	if !errors.As(err, &ce) || ce.Code != "invalid_master_key" {
		t.Fatalf("31-byte key: %v", err)
	}
	_, err = New(Config{MasterKeys: map[string][]byte{"k1": k1}, ActiveKeyID: "k9", Providers: providers()})
	if !errors.As(err, &ce) || ce.Code != "invalid_master_key" {
		t.Fatalf("unknown active id: %v", err)
	}
	_, err = New(Config{MasterKeys: map[string][]byte{"k1": k1}, ActiveKeyID: "k1",
		Providers: map[string]Provider{"acme": {Prefix: "acme_", MinLength: 20, MaxLength: 200}}})
	if !errors.As(err, &ce) || ce.Code != "invalid_provider_config" {
		t.Fatalf("min_length 20: %v", err)
	}
}

// TestVault12HourlyCheckLimit proves 10 provider checks per user per clock hour and the store's window write.
// VAULT-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestVault12HourlyCheckLimit(t *testing.T) {
	r := newVRig(t, NewMemoryStore(), map[string][]byte{"k1": k1}, "k1", nil)
	if _, ref := r.v.SaveKey("user_1", "acme", "acme_bad"); ref == nil || ref.Error != "invalid_key_format" {
		t.Fatalf("malformed = %+v", ref)
	}
	for i := 1; i <= 10; i++ {
		if _, ref := r.v.SaveKey("user_1", "acme", testKey); ref != nil {
			t.Fatalf("save %d = %+v", i, ref)
		}
	}
	r.now += 100
	calls := len(r.client.calls)
	if _, ref := r.v.SaveKey("user_1", "acme", testKey); ref == nil || *ref != (Refusal{Error: "rate_limited", Status: 429, RetryAfter: 3500}) {
		t.Fatalf("11th = %+v", ref)
	}
	if len(r.client.calls) != calls {
		t.Fatal("a refused save called the provider")
	}
	if _, ref := r.v.SaveKey("user_2", "acme", testKey); ref != nil {
		t.Fatalf("other user = %+v", ref)
	}
	r.now = 1699923600
	if _, ref := r.v.SaveKey("user_1", "acme", testKey); ref != nil {
		t.Fatalf("next hour = %+v", ref)
	}
	s := NewMemoryStore()
	for i := 1; i <= 10; i++ {
		if ok, _ := s.BumpSaveWindow("u", 1699920000); !ok {
			t.Fatalf("window write %d refused", i)
		}
	}
	if ok, _ := s.BumpSaveWindow("u", 1699920000); ok {
		t.Fatal("11th window write succeeded")
	}
}

// TestVault13Delete proves delete_key, its audit row, a second delete and use after delete.
// VAULT-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func TestVault13Delete(t *testing.T) {
	r := newVRig(t, NewMemoryStore(), map[string][]byte{"k1": k1}, "k1", nil)
	r.v.SaveKey("user_1", "acme", testKey)
	if d, ref := r.v.DeleteKey("user_1", "acme"); !d || ref != nil {
		t.Fatalf("delete = %v %+v", d, ref)
	}
	if len(r.store.keys) != 0 {
		t.Fatal("row left")
	}
	audit, _ := r.v.ListAudit("user_1")
	if len(audit) != 2 || audit[1].Action != "key_deleted" {
		t.Fatalf("audit = %+v", audit)
	}
	if d, _ := r.v.DeleteKey("user_1", "acme"); d {
		t.Fatal("second delete = true")
	}
	if audit, _ = r.v.ListAudit("user_1"); len(audit) != 2 {
		t.Fatalf("second delete wrote audit: %+v", audit)
	}
	if _, ref := r.v.UseKey("user_1", "acme", "chat"); ref == nil || *ref != (Refusal{Error: "key_not_found", Status: 404}) {
		t.Fatalf("use after delete = %+v", ref)
	}
}

// TestVault14RealRandomness proves two users' saves of the same key share no ciphertext, DEK wrap or nonce.
// VAULT-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory, the OS random source.
func TestVault14RealRandomness(t *testing.T) {
	r := newVRig(t, NewMemoryStore(), map[string][]byte{"k1": k1}, "k1", nil)
	r.v.SaveKey("user_a", "acme", testKey)
	r.v.SaveKey("user_b", "acme", testKey)
	a, b := r.store.keys[rowKey("user_a", "acme")], r.store.keys[rowKey("user_b", "acme")]
	if a.Ciphertext == b.Ciphertext || a.WrappedDEK == b.WrappedDEK {
		t.Fatal("same ciphertext or wrapped_dek")
	}
	ca, _ := base64.StdEncoding.DecodeString(a.Ciphertext)
	cb, _ := base64.StdEncoding.DecodeString(b.Ciphertext)
	wa, _ := base64.StdEncoding.DecodeString(a.WrappedDEK)
	wb, _ := base64.StdEncoding.DecodeString(b.WrappedDEK)
	if string(ca[:12]) == string(cb[:12]) || string(wa[:12]) == string(wb[:12]) || string(ca[:12]) == string(wa[:12]) {
		t.Fatal("a nonce repeated")
	}
}

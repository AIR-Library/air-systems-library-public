// Package byokvault stores users' own provider API keys ("bring your own key") with AES-256-GCM envelope
// encryption (docs/specs/byok_key_vault.md).
//
// Each stored key gets its own 32-byte data key (DEK); only the DEK is wrapped by a master key. The aad binds a
// row to its user, provider and master key id, so a moved or edited row no longer opens. A key is shown again
// only as a 4-character hint, opened only for the user who saved it, and every use is audited in the same
// transaction that marks it used.
//
// Why: Phase D wave 1, owner request 2026-11-10 (spec VAULT-01 to VAULT-14).
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the injected store (memory here; a SQL store follows the spec's schema), the injected provider
// client (network in production, a fake in tests), the clock and the CSPRNG. No money.
package byokvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// SavesPerHour is SAVES_PER_HOUR: provider checks per user per clock hour.
// Why: VAULT-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
const SavesPerHour = 10

// ConfigError is a construction failure: invalid_master_key or invalid_provider_config (fail closed).
// Why: VAULT-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type ConfigError struct{ Code string }

// Error returns the code; it never holds a key.
// In: none. Out: code. Why: VAULT-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func (e *ConfigError) Error() string { return e.Code }

// Provider is one provider's key format: prefix and length bounds.
// Why: VAULT-03, VAULT-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type Provider struct {
	Prefix    string
	MinLength int
	MaxLength int
}

// ProviderClient checks a key with its provider: "ok", "rejected" or "unreachable", or an error.
// Why: VAULT-01, VAULT-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: network (the real one).
type ProviderClient interface {
	Check(provider, key string) (string, error)
}

// KeyRow is one provider_keys row. It never holds the plain key.
// Why: VAULT-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type KeyRow struct {
	UserID     string
	Provider   string
	KeyID      string
	WrappedDEK string
	Ciphertext string
	Hint       string
	CreatedAt  int64
	LastUsedAt *int64
}

// AuditRow is one provider_key_audit row; Purpose is nil except for key_used.
// Why: VAULT-01, -06, -13, -10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type AuditRow struct {
	ID       int64   `json:"-"`
	UserID   string  `json:"-"`
	At       int64   `json:"at"`
	Action   string  `json:"action"`
	Provider string  `json:"provider"`
	Purpose  *string `json:"purpose"`
	KeyID    string  `json:"key_id"`
}

// Store keeps provider_keys, provider_key_audit and provider_key_save_windows. Every method is one atomic
// step (one statement or one transaction).
//
// BumpSaveWindow is the conditional insert-or-add-1-while-under-10 and reports whether it changed a row.
// SaveKey replaces the user's row for the provider and adds the audit row, in one transaction. MarkUsed sets
// last_used_at and adds the key_used audit row in one transaction. DeleteKey deletes the row and adds the audit
// row, reporting whether a row existed. Rewrap updates key_id and wrapped_dek only while the row still holds
// wrappedRead, adding the audit row when it changed one. RowsNotUnder lists rows whose key_id is not keyID, in
// (user_id, provider) byte order.
// Why: VAULT-01 to -13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database or memory.
type Store interface {
	BumpSaveWindow(userID string, windowStart int64) (bool, error)
	SaveKey(row KeyRow, audit AuditRow) error
	GetKey(userID, provider string) (*KeyRow, error)
	MarkUsed(userID, provider string, now int64, audit AuditRow) error
	DeleteKey(userID, provider string, audit AuditRow) (bool, error)
	ListKeys(userID string) ([]KeyRow, error)
	RowsNotUnder(keyID string) ([]KeyRow, error)
	Rewrap(userID, provider, newKeyID, newWrapped, wrappedRead string, audit AuditRow) (bool, error)
	ListAudit(userID string) ([]AuditRow, error)
}

// MemoryStore is the in-memory Store the tests use. failAudit makes the next audited write fail without
// changing anything (VAULT-06).
// Why: README "storage behind an interface". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
type MemoryStore struct {
	mu        sync.Mutex
	keys      map[string]*KeyRow
	audit     []AuditRow
	windows   map[string]int64
	nextID    int64
	failAudit bool
}

// NewMemoryStore returns an empty MemoryStore.
// In: none. Out: store. Why: tests. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{keys: map[string]*KeyRow{}, windows: map[string]int64{}}
}

// rowKey joins user and provider into one map key (NUL never appears in either).
// In: user, provider. Out: key. Why: PRIMARY KEY (user_id, provider). 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func rowKey(u, p string) string { return u + "\x00" + p }

// addAudit appends an audit row with the next ascending id; the caller holds the lock.
// In: row. Out: error when failAudit is set. Why: VAULT-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: memory.
func (m *MemoryStore) addAudit(a AuditRow) error {
	if m.failAudit {
		return errors.New("audit write failed")
	}
	m.nextID++
	a.ID = m.nextID
	m.audit = append(m.audit, a)
	return nil
}

// BumpSaveWindow inserts (user, window, 1) or adds 1 while the count is under 10.
// In: user, window start. Out: whether a row changed. Why: VAULT-12. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) BumpSaveWindow(userID string, windowStart int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := userID + "\x00" + itoa(windowStart)
	if m.windows[k] >= SavesPerHour {
		return false, nil
	}
	m.windows[k]++
	return true, nil
}

// SaveKey replaces the row and adds the audit row, both or neither.
// In: row, audit. Out: error. Why: save_key step 5. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) SaveKey(row KeyRow, audit AuditRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.addAudit(audit); err != nil {
		return err
	}
	r := row
	m.keys[rowKey(row.UserID, row.Provider)] = &r
	return nil
}

// GetKey returns a copy of the row, or nil.
// In: user, provider. Out: row. Why: use_key. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) GetKey(userID, provider string) (*KeyRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.keys[rowKey(userID, provider)]; ok {
		c := *r
		return &c, nil
	}
	return nil, nil
}

// MarkUsed sets last_used_at and adds the key_used audit row, both or neither.
// In: user, provider, now, audit. Out: error. Why: VAULT-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: memory.
func (m *MemoryStore) MarkUsed(userID, provider string, now int64, audit AuditRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.keys[rowKey(userID, provider)]
	if !ok {
		return errors.New("row gone")
	}
	if err := m.addAudit(audit); err != nil {
		return err
	}
	t := now
	r.LastUsedAt = &t
	return nil
}

// DeleteKey deletes the row and adds the audit row when a row existed.
// In: user, provider, audit. Out: whether a row was deleted. Why: VAULT-13. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) DeleteKey(userID, provider string, audit AuditRow) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := rowKey(userID, provider)
	if _, ok := m.keys[k]; !ok {
		return false, nil
	}
	if err := m.addAudit(audit); err != nil {
		return false, err
	}
	delete(m.keys, k)
	return true, nil
}

// sortedRows returns copies of rows matching keep, ordered by (user_id, provider) bytes; the caller holds the lock.
// In: filter. Out: rows. Why: list_keys, rewrap order. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) sortedRows(keep func(*KeyRow) bool) []KeyRow {
	out := []KeyRow{}
	for _, r := range m.keys {
		if keep(r) {
			out = append(out, *r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UserID != out[j].UserID {
			return out[i].UserID < out[j].UserID
		}
		return out[i].Provider < out[j].Provider
	})
	return out
}

// ListKeys returns the user's rows sorted by provider.
// In: user. Out: rows. Why: VAULT-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) ListKeys(userID string) ([]KeyRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sortedRows(func(r *KeyRow) bool { return r.UserID == userID }), nil
}

// RowsNotUnder lists rows whose key_id is not keyID, in (user_id, provider) order.
// In: active key id. Out: rows. Why: VAULT-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) RowsNotUnder(keyID string) ([]KeyRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sortedRows(func(r *KeyRow) bool { return r.KeyID != keyID }), nil
}

// Rewrap updates key_id and wrapped_dek only while the row still holds wrappedRead, with its audit row.
// In: user, provider, new key id, new wrapped DEK, the wrapped DEK read, audit. Out: whether a row changed.
// Why: VAULT-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) Rewrap(userID, provider, newKeyID, newWrapped, wrappedRead string, audit AuditRow) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.keys[rowKey(userID, provider)]
	if !ok || r.WrappedDEK != wrappedRead {
		return false, nil
	}
	if err := m.addAudit(audit); err != nil {
		return false, err
	}
	r.KeyID, r.WrappedDEK = newKeyID, newWrapped
	return true, nil
}

// ListAudit returns the user's audit rows, oldest first.
// In: user. Out: rows. Why: list_audit. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) ListAudit(userID string) ([]AuditRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []AuditRow{}
	for _, a := range m.audit {
		if a.UserID == userID {
			out = append(out, a)
		}
	}
	return out, nil
}

// Config is the injected configuration.
// Why: spec CONFIGURATION. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type Config struct {
	MasterKeys     map[string][]byte
	ActiveKeyID    string
	Providers      map[string]Provider
	ProviderClient ProviderClient
	Store          Store
	Clock          func() int64
	RandomBytes    func(n int) []byte
}

// Vault runs save_key, list_keys, use_key, delete_key, rewrap and list_audit.
// Why: VAULT-01 to -14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: see the package comment.
type Vault struct {
	cfg Config
}

// Refusal is a returned refusal {error, status} plus retry_after for rate_limited. It never holds a key.
// Why: spec CONVENTIONS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type Refusal struct {
	Error      string `json:"error"`
	Status     int    `json:"status"`
	RetryAfter int64  `json:"retry_after,omitempty"`
}

// SavedKey is save_key's answer.
// Why: VAULT-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type SavedKey struct {
	Provider  string `json:"provider"`
	Hint      string `json:"hint"`
	KeyID     string `json:"key_id"`
	CreatedAt int64  `json:"created_at"`
}

// KeyInfo is one list_keys item: never the key, ciphertext or wrapped DEK.
// Why: VAULT-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type KeyInfo struct {
	Provider   string `json:"provider"`
	Hint       string `json:"hint"`
	KeyID      string `json:"key_id"`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt *int64 `json:"last_used_at"`
}

// RewrapResult is rewrap's answer.
// Why: VAULT-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type RewrapResult struct {
	Rewrapped int `json:"rewrapped"`
	Failed    int `json:"failed"`
}

var (
	keyIDRe      = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	providerIDRe = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	purposeRe    = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,100}$`)
)

// New checks the keyring and the providers and builds the vault (fail closed).
// In: config. Out: vault, or *ConfigError invalid_master_key / invalid_provider_config.
// Why: VAULT-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func New(cfg Config) (*Vault, error) {
	if len(cfg.MasterKeys) == 0 {
		return nil, &ConfigError{Code: "invalid_master_key"}
	}
	keys := map[string][]byte{}
	for id, k := range cfg.MasterKeys {
		if !keyIDRe.MatchString(id) || len(k) != 32 {
			return nil, &ConfigError{Code: "invalid_master_key"}
		}
		keys[id] = append([]byte(nil), k...)
	}
	if _, ok := keys[cfg.ActiveKeyID]; !ok {
		return nil, &ConfigError{Code: "invalid_master_key"}
	}
	cfg.MasterKeys = keys
	for id, p := range cfg.Providers {
		if !providerIDRe.MatchString(id) || p.MinLength < 20 || p.MinLength > p.MaxLength || p.MaxLength > 4096 ||
			p.MinLength < utf8.RuneCountInString(p.Prefix)+16 {
			return nil, &ConfigError{Code: "invalid_provider_config"}
		}
	}
	if cfg.Store == nil {
		cfg.Store = NewMemoryStore()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() int64 { return time.Now().Unix() }
	}
	if cfg.RandomBytes == nil {
		cfg.RandomBytes = func(n int) []byte {
			b := make([]byte, n)
			if _, err := rand.Read(b); err != nil {
				panic("crypto/rand unavailable")
			}
			return b
		}
	}
	return &Vault{cfg: cfg}, nil
}

// gcmSeal is AES-256-GCM: nonce + ciphertext + 16-byte tag.
// In: 32-byte key, 12-byte nonce, plaintext, aad text. Out: bytes. Why: ENVELOPE. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func gcmSeal(key, nonce, plaintext []byte, aad string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), nonce...)
	return g.Seal(out, nonce, plaintext, []byte(aad)), nil
}

// gcmOpen decodes base64 and opens nonce + ciphertext + tag; any fault (bad base64, under 28 bytes, a tag that
// fails) is ok=false, never a panic.
// In: key, base64 text, aad text. Out: plaintext, ok. Why: VAULT-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func gcmOpen(key []byte, b64, aad string) ([]byte, bool) {
	raw, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || len(raw) < 28 || len(key) != 32 {
		return nil, false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false
	}
	pt, err := g.Open(nil, raw[:12], raw[12:], []byte(aad))
	if err != nil {
		return nil, false
	}
	return pt, true
}

// dataAAD and dekAAD are the two aad texts of the ENVELOPE.
// In: ids. Out: aad. Why: binds a row to user, provider and master key. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func dataAAD(provider, user string) string { return "byok:data:" + provider + ":" + user }

// dekAAD: see dataAAD.
// In: key id, provider, user. Out: aad. Why: ENVELOPE. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func dekAAD(keyID, provider, user string) string {
	return "byok:dek:" + keyID + ":" + provider + ":" + user
}

// draw reads exactly n random bytes (a short answer from an injected source is an error, never a short nonce).
// In: n. Out: bytes, ok. Why: every nonce is 12 fresh bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the random source.
func (v *Vault) draw(n int) ([]byte, bool) {
	b := v.cfg.RandomBytes(n)
	return b, len(b) == n
}

// SaveKey checks, encrypts and stores a user's key for a provider, replacing the earlier one.
// In: verified user id, provider, key. Out: SavedKey, or a Refusal: 404 unknown_provider, 400 invalid_key_format,
// 429 rate_limited, 400 key_rejected, 502 provider_unreachable, 500 storage_failed.
// Why: VAULT-01 to -04, -09, -12, -14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the store, the provider client (network), the clock, the random source.
func (v *Vault) SaveKey(userID, provider, key string) (*SavedKey, *Refusal) {
	p, ok := v.cfg.Providers[provider]
	if !ok {
		return nil, &Refusal{Error: "unknown_provider", Status: 404}
	}
	k := strings.Trim(key, " \t\r\n")
	n := utf8.RuneCountInString(k)
	if !strings.HasPrefix(k, p.Prefix) || n < p.MinLength || n > p.MaxLength {
		return nil, &Refusal{Error: "invalid_key_format", Status: 400}
	}
	for i := 0; i < len(k); i++ {
		if k[i] < 0x21 || k[i] > 0x7e {
			return nil, &Refusal{Error: "invalid_key_format", Status: 400}
		}
	}
	now := v.cfg.Clock()
	w := now - (now % 3600)
	changed, err := v.cfg.Store.BumpSaveWindow(userID, w)
	if err != nil {
		return nil, &Refusal{Error: "storage_failed", Status: 500}
	}
	if !changed {
		return nil, &Refusal{Error: "rate_limited", Status: 429, RetryAfter: w + 3600 - now}
	}
	switch v.check(provider, k) {
	case "ok":
	case "rejected":
		return nil, &Refusal{Error: "key_rejected", Status: 400}
	default:
		return nil, &Refusal{Error: "provider_unreachable", Status: 502}
	}
	dek, ok1 := v.draw(32)
	dataNonce, ok2 := v.draw(12)
	wrapNonce, ok3 := v.draw(12)
	if !ok1 || !ok2 || !ok3 {
		return nil, &Refusal{Error: "storage_failed", Status: 500}
	}
	ct, err1 := gcmSeal(dek, dataNonce, []byte(k), dataAAD(provider, userID))
	wd, err2 := gcmSeal(v.cfg.MasterKeys[v.cfg.ActiveKeyID], wrapNonce, dek, dekAAD(v.cfg.ActiveKeyID, provider, userID))
	if err1 != nil || err2 != nil {
		return nil, &Refusal{Error: "storage_failed", Status: 500}
	}
	hint := k[len(k)-4:]
	row := KeyRow{UserID: userID, Provider: provider, KeyID: v.cfg.ActiveKeyID,
		WrappedDEK: base64.StdEncoding.EncodeToString(wd), Ciphertext: base64.StdEncoding.EncodeToString(ct),
		Hint: hint, CreatedAt: now}
	if err := v.cfg.Store.SaveKey(row, AuditRow{UserID: userID, At: now, Action: "key_saved", Provider: provider,
		KeyID: v.cfg.ActiveKeyID}); err != nil {
		return nil, &Refusal{Error: "storage_failed", Status: 500}
	}
	return &SavedKey{Provider: provider, Hint: hint, KeyID: v.cfg.ActiveKeyID, CreatedAt: now}, nil
}

// check calls the provider client and maps an error, a panic or an unknown answer to "unreachable".
// In: provider, key. Out: "ok", "rejected" or "unreachable". Why: VAULT-04. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the provider client (network).
func (v *Vault) check(provider, key string) (out string) {
	defer func() {
		if recover() != nil {
			out = "unreachable"
		}
	}()
	if v.cfg.ProviderClient == nil {
		return "unreachable"
	}
	ans, err := v.cfg.ProviderClient.Check(provider, key)
	if err != nil || (ans != "ok" && ans != "rejected") {
		return "unreachable"
	}
	return ans
}

// ListKeys returns the user's keys as hints, sorted by provider.
// In: verified user id. Out: items, or 500 storage_failed. Why: VAULT-05. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
func (v *Vault) ListKeys(userID string) ([]KeyInfo, *Refusal) {
	rows, err := v.cfg.Store.ListKeys(userID)
	if err != nil {
		return nil, &Refusal{Error: "storage_failed", Status: 500}
	}
	out := []KeyInfo{}
	for _, r := range rows {
		out = append(out, KeyInfo{Provider: r.Provider, Hint: r.Hint, KeyID: r.KeyID, CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt})
	}
	return out, nil
}

// UseKey opens the user's key for a server-side provider call and records the use first.
// In: verified user id, provider, purpose. Out: the key, or a Refusal: 400 invalid_purpose, 404 key_not_found,
// 503 key_unavailable, 500 key_unreadable, 500 storage_failed.
// Why: VAULT-02, -06, -07, -08, -11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the store, the clock.
func (v *Vault) UseKey(userID, provider, purpose string) (string, *Refusal) {
	if !purposeRe.MatchString(purpose) {
		return "", &Refusal{Error: "invalid_purpose", Status: 400}
	}
	row, err := v.cfg.Store.GetKey(userID, provider)
	if err != nil {
		return "", &Refusal{Error: "storage_failed", Status: 500}
	}
	if row == nil {
		return "", &Refusal{Error: "key_not_found", Status: 404}
	}
	mk, ok := v.cfg.MasterKeys[row.KeyID]
	if !ok {
		return "", &Refusal{Error: "key_unavailable", Status: 503}
	}
	dek, ok := gcmOpen(mk, row.WrappedDEK, dekAAD(row.KeyID, provider, userID))
	if !ok || len(dek) != 32 {
		return "", &Refusal{Error: "key_unreadable", Status: 500}
	}
	pt, ok := gcmOpen(dek, row.Ciphertext, dataAAD(provider, userID))
	if !ok {
		return "", &Refusal{Error: "key_unreadable", Status: 500}
	}
	now := v.cfg.Clock()
	p := purpose
	if err := v.cfg.Store.MarkUsed(userID, provider, now, AuditRow{UserID: userID, At: now, Action: "key_used",
		Provider: provider, Purpose: &p, KeyID: row.KeyID}); err != nil {
		return "", &Refusal{Error: "storage_failed", Status: 500}
	}
	return string(pt), nil
}

// DeleteKey removes the user's key for a provider and audits it; no row is {deleted: false} with no audit.
// In: verified user id, provider. Out: deleted, or 500 storage_failed. Why: VAULT-07, VAULT-13. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the clock.
func (v *Vault) DeleteKey(userID, provider string) (bool, *Refusal) {
	row, err := v.cfg.Store.GetKey(userID, provider)
	if err != nil {
		return false, &Refusal{Error: "storage_failed", Status: 500}
	}
	if row == nil {
		return false, nil
	}
	deleted, err := v.cfg.Store.DeleteKey(userID, provider, AuditRow{UserID: userID, At: v.cfg.Clock(),
		Action: "key_deleted", Provider: provider, KeyID: row.KeyID})
	if err != nil {
		return false, &Refusal{Error: "storage_failed", Status: 500}
	}
	return deleted, nil
}

// Rewrap re-wraps every row not under the active master key; OPERATOR ONLY, never reachable from a request.
// In: none. Out: {rewrapped, failed}, or 500 storage_failed. Why: VAULT-10. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the clock, the random source.
func (v *Vault) Rewrap() (RewrapResult, *Refusal) {
	res := RewrapResult{}
	rows, err := v.cfg.Store.RowsNotUnder(v.cfg.ActiveKeyID)
	if err != nil {
		return res, &Refusal{Error: "storage_failed", Status: 500}
	}
	active := v.cfg.ActiveKeyID
	for _, r := range rows {
		mk, ok := v.cfg.MasterKeys[r.KeyID]
		if !ok {
			res.Failed++
			continue
		}
		dek, ok := gcmOpen(mk, r.WrappedDEK, dekAAD(r.KeyID, r.Provider, r.UserID))
		if !ok || len(dek) != 32 {
			res.Failed++
			continue
		}
		nonce, ok := v.draw(12)
		if !ok {
			res.Failed++
			continue
		}
		wd, err := gcmSeal(v.cfg.MasterKeys[active], nonce, dek, dekAAD(active, r.Provider, r.UserID))
		if err != nil {
			res.Failed++
			continue
		}
		changed, err := v.cfg.Store.Rewrap(r.UserID, r.Provider, active, base64.StdEncoding.EncodeToString(wd), r.WrappedDEK,
			AuditRow{UserID: r.UserID, At: v.cfg.Clock(), Action: "key_rewrapped", Provider: r.Provider, KeyID: active})
		if err != nil {
			return res, &Refusal{Error: "storage_failed", Status: 500}
		}
		if changed {
			res.Rewrapped++
		}
	}
	return res, nil
}

// ListAudit returns the user's audit rows, oldest first.
// In: verified user id. Out: rows, or 500 storage_failed. Why: list_audit. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
func (v *Vault) ListAudit(userID string) ([]AuditRow, *Refusal) {
	rows, err := v.cfg.Store.ListAudit(userID)
	if err != nil {
		return nil, &Refusal{Error: "storage_failed", Status: 500}
	}
	return rows, nil
}

// itoa formats a non-negative or negative 64-bit integer in decimal.
// In: n. Out: text. Why: window keys. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	var b [20]byte
	i := len(b)
	for n != 0 {
		d := n % 10
		if d < 0 {
			d = -d
		}
		i--
		b[i] = byte('0' + d)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// Package passwordless signs a person in, and up, with a 6-digit code sent by email
// (docs/specs/passwordless_email_code_signin.md).
//
// One code per address at a time, valid 600 seconds, usable once, 5 tries. start answers the same for a known
// and an unknown address and never reads accounts. Codes, addresses and IPs used as keys are stored only as
// HMAC-SHA256 under the server's secret. Every try is counted by a conditional write before the compare.
//
// Why: Phase D wave 1, owner request 2026-11-10 (spec EMAILCODE-01 to EMAILCODE-14).
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the injected store (memory here; a SQL store follows the spec's schema), the injected email sender
// (network in production, a fake in tests), the clock and the CSPRNG. No money.
package passwordless

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"
)

// Limits and lifetimes from the spec's CONFIGURATION section.
// Why: EMAILCODE-04, -05, -08, -09, -10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
const (
	CodeTTL            = 600
	CodeAttempts       = 5
	StartPerEmailHour  = 5
	StartPerEmailDay   = 10
	StartPerIPHour     = 20
	VerifyPerIPHour    = 30
	VerifyPerEmailHour = 10
)

// ConfigError is the construction failure "not_configured" (fail closed).
// In: Code. Out: Error() text. Why: EMAILCODE-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type ConfigError struct{ Code string }

// Error returns the error code; it never holds the secret.
// In: none. Out: the code. Why: EMAILCODE-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func (e *ConfigError) Error() string { return e.Code }

// Account is one row of the accounts table (auth_system's users).
// Why: EMAILCODE-01, -13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type Account struct {
	ID              string
	Email           string
	EmailVerifiedAt *int64
	Status          string
	CreatedAt       int64
}

// CodeRow is one row of email_codes: only hashes, never the address or the code.
// Why: EMAILCODE-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type CodeRow struct {
	EmailHash string
	CodeHash  string
	ExpiresAt int64
	Attempts  int
	CreatedAt int64
}

// Store holds accounts, email_codes and rate_windows. Every method is one atomic step.
//
// Bump inserts (key, windowStart, 1) or adds 1 and returns the count after it. PutCode replaces the row of
// emailHash. DeleteCodeIf deletes the row only when it still holds codeHash and reports the rows deleted.
// TryCode is the conditional "attempts = attempts + 1 WHERE attempts < 5 AND expires_at > now" and returns the
// stored hash and the new attempts, or ok=false when no row changed. DeleteDeadCode deletes the row when it is
// expired or used up. DeleteExhaustedCode deletes the row when attempts >= 5. FindAccountByEmail reads an
// account, InsertAccountIfAbsent inserts unless the email exists, MarkVerified sets email_verified_at.
// Why: EMAILCODE-02 to -10 (no read-then-write). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the database (a SQL implementation) or memory.
type Store interface {
	Bump(key string, windowStart int64) (int64, error)
	PutCode(row CodeRow) error
	DeleteCodeIf(emailHash, codeHash string) (int64, error)
	TryCode(emailHash string, now int64) (storedHash string, attempts int, ok bool, err error)
	DeleteDeadCode(emailHash string, now int64) error
	DeleteExhaustedCode(emailHash string) error
	FindAccountByEmail(email string) (*Account, error)
	InsertAccountIfAbsent(acc Account) error
	MarkVerified(id string, at int64) error
}

// MemoryStore is the in-memory Store the tests use; one mutex makes each method atomic.
// accountReads counts FindAccountByEmail calls so a test can prove start never reads accounts.
// Why: EMAILCODE-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
type MemoryStore struct {
	mu           sync.Mutex
	accounts     []*Account
	codes        map[string]*CodeRow
	windows      map[string]int64
	accountReads int
}

// NewMemoryStore returns an empty MemoryStore.
// In: none. Out: the store. Why: README "storage behind an interface". 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{codes: map[string]*CodeRow{}, windows: map[string]int64{}}
}

// Bump adds 1 to the window (key, windowStart) and returns the count after it, in one locked step.
// In: key, window start. Out: count. Why: BUMP. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) Bump(key string, windowStart int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key + "\x00" + itoa(windowStart)
	m.windows[k]++
	return m.windows[k], nil
}

// PutCode writes the code row, replacing an earlier one for the same email hash.
// In: row. Out: error. Why: start step 4. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) PutCode(row CodeRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := row
	m.codes[row.EmailHash] = &r
	return nil
}

// DeleteCodeIf deletes the row of emailHash only while it holds codeHash. Out: rows deleted (0 or 1).
// Why: start step 5, verify step 6. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) DeleteCodeIf(emailHash, codeHash string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.codes[emailHash]
	if !ok || r.CodeHash != codeHash {
		return 0, nil
	}
	delete(m.codes, emailHash)
	return 1, nil
}

// TryCode counts one try: attempts + 1 while attempts < 5 and the code has not expired.
// In: email hash, now. Out: stored hash, new attempts, whether a row changed. Why: verify step 4 (EMAILCODE-05).
// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) TryCode(emailHash string, now int64) (string, int, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.codes[emailHash]
	if !ok || r.Attempts >= CodeAttempts || r.ExpiresAt <= now {
		return "", 0, false, nil
	}
	r.Attempts++
	return r.CodeHash, r.Attempts, true, nil
}

// DeleteDeadCode deletes the row when it is expired (expires_at <= now) or used up (attempts >= 5).
// In: email hash, now. Out: error. Why: verify step 4. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: memory.
func (m *MemoryStore) DeleteDeadCode(emailHash string, now int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.codes[emailHash]; ok && (r.Attempts >= CodeAttempts || r.ExpiresAt <= now) {
		delete(m.codes, emailHash)
	}
	return nil
}

// DeleteExhaustedCode deletes the row when its attempts reached 5.
// In: email hash. Out: error. Why: verify step 5. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) DeleteExhaustedCode(emailHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.codes[emailHash]; ok && r.Attempts >= CodeAttempts {
		delete(m.codes, emailHash)
	}
	return nil
}

// FindAccountByEmail returns a copy of the account with that email, or nil, and counts the read.
// In: normalised email. Out: account or nil. Why: verify step 7, EMAILCODE-07. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) FindAccountByEmail(email string) (*Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accountReads++
	for _, a := range m.accounts {
		if a.Email == email {
			c := *a
			return &c, nil
		}
	}
	return nil, nil
}

// InsertAccountIfAbsent inserts the account unless a row with its email exists (UNIQUE email).
// In: account. Out: error. Why: verify step 7. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) InsertAccountIfAbsent(acc Account) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.accounts {
		if a.Email == acc.Email {
			return nil
		}
	}
	c := acc
	m.accounts = append(m.accounts, &c)
	return nil
}

// MarkVerified sets email_verified_at on the account id.
// In: id, time. Out: error. Why: verify step 7. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) MarkVerified(id string, at int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.accounts {
		if a.ID == id {
			t := at
			a.EmailVerifiedAt = &t
		}
	}
	return nil
}

// windowKeys lists the rate_windows keys (test helper for EMAILCODE-02), sorted.
// In: none. Out: keys without their window start. Why: EMAILCODE-02. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory (read).
func (m *MemoryStore) windowKeys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []string{}
	for k := range m.windows {
		out = append(out, k[:strings.IndexByte(k, 0)])
	}
	sort.Strings(out)
	return out
}

// Sender sends a code by email. It returns false or an error when the mail did not go out.
// Why: EMAILCODE-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: network (the real one).
type Sender interface {
	SendCode(to, code string, expiresInSeconds int) (bool, error)
}

// Config is the injected configuration. Secret (at least 32 bytes) and Sender are required; Clock,
// RandomBytes, GenerateCode and RevokeUnproven have defaults.
// Why: spec CONFIGURATION. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type Config struct {
	Secret         []byte
	Sender         Sender
	Store          Store
	Clock          func() int64
	RandomBytes    func(n int) []byte
	GenerateCode   func() string
	RevokeUnproven func(accountID string) error
}

// Service runs start and verify.
// Why: EMAILCODE-01 to -14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: see the package comment.
type Service struct {
	cfg Config
}

// StartResult is start's answer: 202 {sent, expires_in} or a refusal {error, status}.
// Why: spec start. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type StartResult struct {
	Status    int    `json:"status"`
	Sent      bool   `json:"sent,omitempty"`
	ExpiresIn int    `json:"expires_in,omitempty"`
	Error     string `json:"error,omitempty"`
}

// VerifyResult is verify's answer: 200 {account_id, email, new_account} or a refusal {error, status}.
// Why: spec verify. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type VerifyResult struct {
	Status     int    `json:"status"`
	AccountID  string `json:"account_id,omitempty"`
	Email      string `json:"email,omitempty"`
	NewAccount bool   `json:"new_account,omitempty"`
	Error      string `json:"error,omitempty"`
}

// cryptoRandom reads n bytes from the system CSPRNG; it panics only when the OS has no randomness.
// In: n. Out: bytes. Why: default random_bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the OS random source.
func cryptoRandom(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable")
	}
	return b
}

// New builds the service. A secret under 32 bytes or no sender fails with not_configured (fail closed).
// In: config. Out: service or *ConfigError. Why: EMAILCODE-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func New(cfg Config) (*Service, error) {
	if len(cfg.Secret) < 32 || cfg.Sender == nil {
		return nil, &ConfigError{Code: "not_configured"}
	}
	if cfg.Store == nil {
		cfg.Store = NewMemoryStore()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() int64 { return time.Now().Unix() }
	}
	if cfg.RandomBytes == nil {
		cfg.RandomBytes = cryptoRandom
	}
	if cfg.GenerateCode == nil {
		rb := cfg.RandomBytes
		cfg.GenerateCode = func() string { return GenerateCode(rb) }
	}
	if cfg.RevokeUnproven == nil {
		cfg.RevokeUnproven = func(string) error { return nil }
	}
	k := make([]byte, len(cfg.Secret))
	copy(k, cfg.Secret)
	cfg.Secret = k
	return &Service{cfg: cfg}, nil
}

// GenerateCode is CODE: an unsigned big-endian 32-bit draw, redrawn when >= 4294000000, mod 1000000 with
// 6 digits (leading zeros kept), so every code is equally likely.
// In: random_bytes. Out: 6 digits. Why: EMAILCODE-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the random source.
func GenerateCode(randomBytes func(int) []byte) string {
	for {
		b := randomBytes(4)
		if len(b) < 4 {
			continue
		}
		n := uint64(binary.BigEndian.Uint32(b[:4]))
		if n >= 4294000000 {
			continue
		}
		s := itoa(int64(n % 1000000))
		return strings.Repeat("0", 6-len(s)) + s
	}
}

// NormalizeEmail trims space, tab, CR and LF at both ends, maps A-Z to a-z and checks the shape
// [a-z0-9][a-z0-9._%+=-]*@[a-z0-9-]+(\.[a-z0-9-]+)+ with 3 to 254 characters.
// In: raw text. Out: the address and true, or "" and false. Why: EMAILCODE-11. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func NormalizeEmail(raw string) (string, bool) {
	s := strings.Trim(raw, " \t\r\n")
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	s = string(b)
	if len(s) < 3 || len(s) > 254 {
		return "", false
	}
	at := strings.IndexByte(s, '@')
	if at < 1 || strings.IndexByte(s[at+1:], '@') >= 0 {
		return "", false
	}
	local, domain := s[:at], s[at+1:]
	if !isAlnum(local[0]) {
		return "", false
	}
	for i := 1; i < len(local); i++ {
		c := local[i]
		if !isAlnum(c) && !strings.ContainsRune("._%+=-", rune(c)) {
			return "", false
		}
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, l := range labels {
		if l == "" {
			return "", false
		}
		for i := 0; i < len(l); i++ {
			if !isAlnum(l[i]) && l[i] != '-' {
				return "", false
			}
		}
	}
	return s, true
}

// isAlnum reports whether c is a-z or 0-9 (the text is already ASCII lower case).
// In: byte. Out: bool. Why: NormalizeEmail. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func isAlnum(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') }

// HmacHex is lower-case hex of HMAC-SHA256(secret, UTF-8 of text).
// In: text. Out: 64 hex characters. Why: spec HELPERS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func (s *Service) HmacHex(text string) string {
	m := hmac.New(sha256.New, s.cfg.Secret)
	m.Write([]byte(text))
	return hex.EncodeToString(m.Sum(nil))
}

// EmailHash is hmac_hex("email:" + email).
// In: normalised email. Out: hex. Why: EMAILCODE-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func (s *Service) EmailHash(email string) string { return s.HmacHex("email:" + email) }

// CodeHash is hmac_hex("code:" + email_hash(email) + ":" + code).
// In: email, code. Out: hex. Why: EMAILCODE-02, -14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func (s *Service) CodeHash(email, code string) string {
	return s.HmacHex("code:" + s.EmailHash(email) + ":" + code)
}

// IPHash is the first 32 characters of hmac_hex("ip:" + ip).
// In: ip. Out: 32 hex characters. Why: EMAILCODE-02, -09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func (s *Service) IPHash(ip string) string { return s.HmacHex("ip:" + ip)[:32] }

// ek is the first 32 characters of email_hash(email): the rate-window key part for an address.
// In: email. Out: 32 hex characters. Why: EMAILCODE-08, -10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func (s *Service) ek(email string) string { return s.EmailHash(email)[:32] }

// bump is BUMP: one atomic count in the window of span seconds that holds now.
// In: key, span. Out: the count after it. Why: EMAILCODE-08 to -10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the store.
func (s *Service) bump(key string, span int64) (int64, error) {
	now := s.cfg.Clock()
	return s.cfg.Store.Bump(key, now-(now%span))
}

// Start sends a fresh code to the address. It never reads accounts.
// In: raw email, client ip ("" means "unknown"). Out: 202 {sent, expires_in}, 422 invalid_email,
// 429 too_many_requests, 503 send_failed, or 500 processing_failed when the store fails.
// Why: EMAILCODE-01, -07, -08, -09, -12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the store, the sender (network), the clock, the random source.
func (s *Service) Start(email, ip string) StartResult {
	e, ok := NormalizeEmail(email)
	if !ok {
		return StartResult{Status: 422, Error: "invalid_email"}
	}
	if ip == "" {
		ip = "unknown"
	}
	n, err := s.bump("start-ip#"+s.IPHash(ip), 3600)
	if err != nil {
		return StartResult{Status: 500, Error: "processing_failed"}
	}
	if n > StartPerIPHour {
		return StartResult{Status: 429, Error: "too_many_requests"}
	}
	h, err1 := s.bump("start-email#"+s.ek(e), 3600)
	d, err2 := s.bump("start-email-day#"+s.ek(e), 86400)
	if err1 != nil || err2 != nil {
		return StartResult{Status: 500, Error: "processing_failed"}
	}
	if h > StartPerEmailHour || d > StartPerEmailDay {
		return StartResult{Status: 429, Error: "too_many_requests"}
	}
	code := s.cfg.GenerateCode()
	now := s.cfg.Clock()
	eh, ch := s.EmailHash(e), s.CodeHash(e, code)
	if err := s.cfg.Store.PutCode(CodeRow{EmailHash: eh, CodeHash: ch, ExpiresAt: now + CodeTTL, CreatedAt: now}); err != nil {
		return StartResult{Status: 500, Error: "processing_failed"}
	}
	if !s.send(e, code) {
		_, _ = s.cfg.Store.DeleteCodeIf(eh, ch)
		return StartResult{Status: 503, Error: "send_failed"}
	}
	return StartResult{Status: 202, Sent: true, ExpiresIn: CodeTTL}
}

// send calls the sender and turns false, an error or a panic into false.
// In: email, code. Out: whether the mail went out. Why: EMAILCODE-12. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the sender (network).
func (s *Service) send(e, code string) (sent bool) {
	defer func() {
		if recover() != nil {
			sent = false
		}
	}()
	ok, err := s.cfg.Sender.SendCode(e, code, CodeTTL)
	return err == nil && ok
}

// normalizeCode removes ASCII spaces and "-" and checks for exactly 6 digits 0-9.
// In: code text. Out: the 6 digits and true, or false. Why: EMAILCODE-11. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func normalizeCode(code string) (string, bool) {
	c := strings.NewReplacer(" ", "", "-", "").Replace(code)
	if len(c) != 6 {
		return "", false
	}
	for i := 0; i < 6; i++ {
		if c[i] < '0' || c[i] > '9' {
			return "", false
		}
	}
	return c, true
}

// Verify checks the code for the address and returns the account, making it on first sign-in.
// In: raw email, code, client ip ("" means "unknown"). Out: 200 {account_id, email, new_account},
// 400 invalid_code, 403 account_unavailable, 429 too_many_requests or 500 processing_failed.
// Why: EMAILCODE-01, -03 to -07, -10, -11, -13, -14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the store, revoke_unproven, the clock, the random source.
func (s *Service) Verify(email, code, ip string) VerifyResult {
	invalid := VerifyResult{Status: 400, Error: "invalid_code"}
	failed := VerifyResult{Status: 500, Error: "processing_failed"}
	if ip == "" {
		ip = "unknown"
	}
	n, err := s.bump("verify-ip#"+s.IPHash(ip), 3600)
	if err != nil {
		return failed
	}
	if n > VerifyPerIPHour {
		return VerifyResult{Status: 429, Error: "too_many_requests"}
	}
	e, okE := NormalizeEmail(email)
	c, okC := normalizeCode(code)
	if !okE || !okC {
		return invalid
	}
	n, err = s.bump("verify-email#"+s.ek(e), 3600)
	if err != nil {
		return failed
	}
	if n > VerifyPerEmailHour {
		return VerifyResult{Status: 429, Error: "too_many_requests"}
	}
	now := s.cfg.Clock()
	eh := s.EmailHash(e)
	given := s.CodeHash(e, c)
	stored, attempts, ok, err := s.cfg.Store.TryCode(eh, now)
	if err != nil {
		return failed
	}
	if !ok {
		_ = s.cfg.Store.DeleteDeadCode(eh, now)
		subtle.ConstantTimeCompare([]byte(given), []byte(strings.Repeat("0", 64)))
		return invalid
	}
	if subtle.ConstantTimeCompare([]byte(given), []byte(stored)) != 1 {
		if attempts >= CodeAttempts {
			_ = s.cfg.Store.DeleteExhaustedCode(eh)
		}
		return invalid
	}
	deleted, err := s.cfg.Store.DeleteCodeIf(eh, stored)
	if err != nil {
		return failed
	}
	if deleted != 1 {
		return invalid
	}
	id := hex.EncodeToString(s.cfg.RandomBytes(16))
	if err := s.cfg.Store.InsertAccountIfAbsent(Account{ID: id, Email: e, EmailVerifiedAt: &now, Status: "active", CreatedAt: now}); err != nil {
		return failed
	}
	acc, err := s.cfg.Store.FindAccountByEmail(e)
	if err != nil || acc == nil {
		return failed
	}
	newAccount := acc.ID == id
	if acc.EmailVerifiedAt == nil {
		if !s.revoke(acc.ID) {
			return failed
		}
		if err := s.cfg.Store.MarkVerified(acc.ID, now); err != nil {
			return failed
		}
	}
	if acc.Status != "active" {
		return VerifyResult{Status: 403, Error: "account_unavailable"}
	}
	return VerifyResult{Status: 200, AccountID: acc.ID, Email: e, NewAccount: newAccount}
}

// revoke calls revoke_unproven and turns an error or a panic into false.
// In: account id. Out: whether it succeeded. Why: EMAILCODE-01 (verify step 7). 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: whatever the application's revoke_unproven touches.
func (s *Service) revoke(id string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return s.cfg.RevokeUnproven(id) == nil
}

// itoa formats a signed 64-bit integer in decimal.
// In: n. Out: text. Why: keys and codes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
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

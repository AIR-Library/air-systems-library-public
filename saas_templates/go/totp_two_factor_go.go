// Package totp is a second sign-in factor from an authenticator app (docs/specs/totp_two_factor.md): RFC 6238
// codes with one step of drift each way, a replay guard, an attempt lock counted before any code is looked at,
// a hard lock after 100 failures, and one-time recovery codes stored only as keyed hashes.
//
// Why: Phase D wave 1, owner request 2026-11-10 (spec TOTP-01 to TOTP-14).
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the injected store (memory here; a SQL store follows the spec's schema), the clock and the CSPRNG.
// No network, no money.
package totp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Constants from the spec's CONFIGURATION.
// Why: TOTP-05, -09, -14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
const (
	Step             = 30
	Digits           = 6
	LockFailures     = 5
	LockSeconds      = 900
	HardLockFailures = 100
	RecoveryCodes    = 8
	RecoveryAlphabet = "23456789abcdefghjkmnpqrstvwxyz"
)

// ErrInvalidBase32 is base32_decode's error.
// Why: TOTP-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
var ErrInvalidBase32 = errors.New("invalid_base32")

// ConfigError is the construction failure invalid_key (fail closed).
// Why: TOTP-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type ConfigError struct{ Code string }

// Error returns the code; it never holds a key.
// In: none. Out: code. Why: TOTP-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func (e *ConfigError) Error() string { return e.Code }

const b32alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// Base32Encode is RFC 4648 base32, upper case, without "=" padding.
// In: bytes. Out: text. Why: TOTP-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func Base32Encode(b []byte) string {
	var sb strings.Builder
	var buf uint64
	bits := 0
	for _, c := range b {
		buf = buf<<8 | uint64(c)
		bits += 8
		for bits >= 5 {
			sb.WriteByte(b32alphabet[(buf>>(bits-5))&31])
			bits -= 5
		}
	}
	if bits > 0 {
		sb.WriteByte(b32alphabet[(buf<<(5-bits))&31])
	}
	return sb.String()
}

// Base32Decode removes ASCII spaces, "-" and "=", upper-cases a-z, checks every character and the length
// (1, 3 or 6 modulo 8 is invalid), and decodes 5 bits per character, dropping leftover bits.
// In: text. Out: bytes or ErrInvalidBase32. Why: TOTP-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func Base32Decode(s string) ([]byte, error) {
	vals := []byte{}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '-' || c == '=' {
			continue
		}
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		idx := strings.IndexByte(b32alphabet, c)
		if idx < 0 {
			return nil, ErrInvalidBase32
		}
		vals = append(vals, byte(idx))
	}
	if len(vals) == 0 {
		return nil, ErrInvalidBase32
	}
	if m := len(vals) % 8; m == 1 || m == 3 || m == 6 {
		return nil, ErrInvalidBase32
	}
	out := []byte{}
	var buf uint64
	bits := 0
	for _, v := range vals {
		buf = buf<<5 | uint64(v)
		bits += 5
		if bits >= 8 {
			out = append(out, byte(buf>>(bits-8)))
			bits -= 8
		}
	}
	return out, nil
}

// Hotp is RFC 4226: HMAC-SHA1 over the 8-byte big-endian counter, dynamic truncation, mod 10^digits.
// In: key, 64-bit counter, digits. Out: zero-padded code. Why: TOTP-01. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func Hotp(key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	mac := m.Sum(nil)
	o := mac[19] & 0x0f
	v := binary.BigEndian.Uint32(mac[o:o+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	s := itoa(int64(v % mod))
	return strings.Repeat("0", digits-len(s)) + s
}

// TotpAt is hotp(base32_decode(secret), floor(unix_time / 30), digits).
// In: base32 secret, unix time, digits. Out: code or ErrInvalidBase32. Why: TOTP-01. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func TotpAt(secret string, unixTime int64, digits int) (string, error) {
	k, err := Base32Decode(secret)
	if err != nil {
		return "", err
	}
	return Hotp(k, uint64(unixTime/Step), digits), nil
}

// pct percent-encodes every UTF-8 byte outside [A-Za-z0-9._~-] with upper-case hex.
// In: text. Out: text. Why: otpauth_uri. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func pct(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || strings.IndexByte("._~-", c) >= 0 {
			sb.WriteByte(c)
		} else {
			sb.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return sb.String()
}

// OtpauthURI builds the Key URI that authenticator apps read.
// In: secret, issuer, account label. Out: URI. Why: TOTP-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func OtpauthURI(secret, issuer, label string) string {
	return "otpauth://totp/" + pct(issuer+":"+label) + "?secret=" + secret + "&issuer=" + pct(issuer) +
		"&algorithm=SHA1&digits=6&period=30"
}

// Seal is "v1." + base64(nonce + AES-256-GCM ciphertext + tag) with the aad's UTF-8.
// In: 32-byte key, 12-byte nonce, plaintext, aad. Out: text or error. Why: TOTP-11. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func Seal(key, nonce, plaintext []byte, aad string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(nonce) != 12 {
		return "", errors.New("nonce must be 12 bytes")
	}
	out := g.Seal(append([]byte(nil), nonce...), nonce, plaintext, []byte(aad))
	return "v1." + base64.StdEncoding.EncodeToString(out), nil
}

// Open reverses Seal; a missing prefix, bad base64, fewer than 28 bytes or a failed tag gives ok=false.
// In: key, sealed text, aad. Out: plaintext, ok. Why: TOTP-10, TOTP-11. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func Open(key []byte, sealed, aad string) ([]byte, bool) {
	if !strings.HasPrefix(sealed, "v1.") || len(key) != 32 {
		return nil, false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(sealed[3:])
	if err != nil || len(raw) < 28 {
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

// Enrollment is one totp_enrollments row.
// Why: spec SCHEMA. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type Enrollment struct {
	UserID             string
	SecretEnc          string
	ConfirmedAt        *int64
	LastUsedStep       int64
	FailedSinceSuccess int64
	CreatedAt          int64
}

// Store keeps totp_enrollments, totp_recovery_codes and totp_failures. Every method is one atomic step.
//
// StartEnrollment writes the row unless a confirmed one exists (false then). Confirm is the conditional
// confirm of enroll_confirm step 7. Claim is CLAIM(step). Try is TRY: it inserts a failure row only while the
// user has fewer than 5 rows with at > now - 900, and returns the slot id. DeleteSlot deletes one slot row.
// AddFailure adds 1 to failed_since_success. ResetFailures sets it to 0. FailureTimes lists the user's failure
// times, newest first. UseRecoveryCode is the conditional used_at write. DeleteUser removes the enrollment,
// the recovery codes and the failures.
// Why: TOTP-03 to -14 (no read-then-write). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the database or memory.
type Store interface {
	GetEnrollment(userID string) (*Enrollment, error)
	StartEnrollment(e Enrollment) (bool, error)
	Confirm(userID string, now, step int64, secretEncRead string) (bool, error)
	Claim(userID string, step int64) (bool, error)
	Try(userID string, now int64) (slot int64, ok bool, err error)
	DeleteSlot(slot int64) error
	AddFailure(userID string) error
	ResetFailures(userID string) error
	FailureTimes(userID string) ([]int64, error)
	AddRecoveryCodes(userID string, hashes []string, now int64) error
	UseRecoveryCode(userID, hash string, now int64) (bool, error)
	RecoveryCodesLeft(userID string) (int, error)
	DeleteUser(userID string) error
}

// recoveryRow is one totp_recovery_codes row.
// Why: spec SCHEMA. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type recoveryRow struct {
	userID, hash string
	createdAt    int64
	usedAt       *int64
}

// failureRow is one totp_failures row.
// Why: spec SCHEMA. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type failureRow struct {
	id     int64
	userID string
	at     int64
}

// MemoryStore is the in-memory Store the tests use; one mutex makes each method atomic.
// Why: README "storage behind an interface". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
type MemoryStore struct {
	mu       sync.Mutex
	enrolls  map[string]*Enrollment
	recovery []*recoveryRow
	failures []failureRow
	nextID   int64
}

// NewMemoryStore returns an empty store.
// In: none. Out: store. Why: tests. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func NewMemoryStore() *MemoryStore { return &MemoryStore{enrolls: map[string]*Enrollment{}} }

// GetEnrollment returns a copy of the row, or nil.
// In: user. Out: row. Why: every flow. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) GetEnrollment(userID string) (*Enrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.enrolls[userID]; ok {
		c := *e
		return &c, nil
	}
	return nil, nil
}

// StartEnrollment writes the row, replacing an unconfirmed one; a confirmed row is kept and false returned.
// In: row. Out: written. Why: enroll_start steps 1-2. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) StartEnrollment(e Enrollment) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.enrolls[e.UserID]; ok && old.ConfirmedAt != nil {
		return false, nil
	}
	c := e
	m.enrolls[e.UserID] = &c
	return true, nil
}

// Confirm sets confirmed_at, last_used_step and failed_since_success = 0 while the row is unconfirmed and
// still holds secretEncRead.
// In: user, now, step, sealed secret read. Out: changed. Why: enroll_confirm step 7. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) Confirm(userID string, now, step int64, secretEncRead string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.enrolls[userID]
	if !ok || e.ConfirmedAt != nil || e.SecretEnc != secretEncRead {
		return false, nil
	}
	t := now
	e.ConfirmedAt, e.LastUsedStep, e.FailedSinceSuccess = &t, step, 0
	return true, nil
}

// Claim sets last_used_step = step and failed_since_success = 0 while confirmed and last_used_step < step.
// In: user, step. Out: changed. Why: TOTP-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) Claim(userID string, step int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.enrolls[userID]
	if !ok || e.ConfirmedAt == nil || e.LastUsedStep >= step {
		return false, nil
	}
	e.LastUsedStep, e.FailedSinceSuccess = step, 0
	return true, nil
}

// Try inserts a failure row (the slot) only while the user has fewer than 5 rows with at > now - 900.
// In: user, now. Out: slot id, ok. Why: TOTP-09 (TRY). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) Try(userID string, now int64) (int64, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, f := range m.failures {
		if f.userID == userID && f.at > now-LockSeconds {
			n++
		}
	}
	if n >= LockFailures {
		return 0, false, nil
	}
	m.nextID++
	m.failures = append(m.failures, failureRow{id: m.nextID, userID: userID, at: now})
	return m.nextID, true, nil
}

// DeleteSlot deletes the failure row with that id, and only it.
// In: slot id. Out: error. Why: answers that are not a FAILURE. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: memory.
func (m *MemoryStore) DeleteSlot(slot int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, f := range m.failures {
		if f.id == slot {
			m.failures = append(m.failures[:i], m.failures[i+1:]...)
			break
		}
	}
	return nil
}

// AddFailure adds 1 to failed_since_success.
// In: user. Out: error. Why: FAILURE. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) AddFailure(userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.enrolls[userID]; ok {
		e.FailedSinceSuccess++
	}
	return nil
}

// ResetFailures sets failed_since_success = 0.
// In: user. Out: error. Why: a recovery-code success (TOTP-14). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: memory.
func (m *MemoryStore) ResetFailures(userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.enrolls[userID]; ok {
		e.FailedSinceSuccess = 0
	}
	return nil
}

// FailureTimes lists the user's failure times, newest first (ties: later insert first).
// In: user. Out: times. Why: LOCKED retry_after. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) FailureTimes(userID string) ([]int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := []failureRow{}
	for _, f := range m.failures {
		if f.userID == userID {
			rows = append(rows, f)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].at != rows[j].at {
			return rows[i].at > rows[j].at
		}
		return rows[i].id > rows[j].id
	})
	out := make([]int64, len(rows))
	for i, r := range rows {
		out[i] = r.at
	}
	return out, nil
}

// AddRecoveryCodes stores the codes' hashes.
// In: user, hashes, now. Out: error. Why: TOTP-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) AddRecoveryCodes(userID string, hashes []string, now int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, h := range hashes {
		m.recovery = append(m.recovery, &recoveryRow{userID: userID, hash: h, createdAt: now})
	}
	return nil
}

// UseRecoveryCode sets used_at on the user's unused row with that hash.
// In: user, hash, now. Out: changed. Why: TOTP-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) UseRecoveryCode(userID, hash string, now int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.recovery {
		if r.userID == userID && r.hash == hash && r.usedAt == nil {
			t := now
			r.usedAt = &t
			return true, nil
		}
	}
	return false, nil
}

// RecoveryCodesLeft counts the user's unused recovery codes.
// In: user. Out: count. Why: recovery_codes_left. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) RecoveryCodesLeft(userID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, r := range m.recovery {
		if r.userID == userID && r.usedAt == nil {
			n++
		}
	}
	return n, nil
}

// DeleteUser removes the user's enrollment, recovery codes and failures.
// In: user. Out: error. Why: TOTP-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (m *MemoryStore) DeleteUser(userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.enrolls, userID)
	rec := m.recovery[:0]
	for _, r := range m.recovery {
		if r.userID != userID {
			rec = append(rec, r)
		}
	}
	m.recovery = rec
	fs := m.failures[:0]
	for _, f := range m.failures {
		if f.userID != userID {
			fs = append(fs, f)
		}
	}
	m.failures = fs
	return nil
}

// Config is the injected configuration.
// Why: spec CONFIGURATION. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type Config struct {
	EncryptionKey   []byte
	RecoveryHashKey []byte
	Issuer          string
	Store           Store
	Clock           func() int64
	RandomBytes     func(n int) []byte
}

// Service runs enroll_start, enroll_confirm, verify, disable and status.
// Why: TOTP-03 to -14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: see the package comment.
type Service struct {
	cfg Config
}

// Refusal is a returned refusal {error, status} plus retry_after for locked. It never holds a code or key.
// Why: spec CONVENTIONS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type Refusal struct {
	Error      string `json:"error"`
	Status     int    `json:"status"`
	RetryAfter int64  `json:"retry_after,omitempty"`
}

// StartResult is enroll_start's answer.
// Why: TOTP-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type StartResult struct {
	Secret     string `json:"secret"`
	OtpauthURI string `json:"otpauth_uri"`
}

// VerifyResult is verify's ok answer.
// Why: TOTP-05 to -08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type VerifyResult struct {
	OK                bool   `json:"ok"`
	Method            string `json:"method"`
	RecoveryCodesLeft int    `json:"recovery_codes_left"`
}

// StatusResult is status's answer.
// Why: spec status. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type StatusResult struct {
	Enrolled          bool   `json:"enrolled"`
	LockedUntil       *int64 `json:"locked_until"`
	RecoveryRequired  bool   `json:"recovery_required"`
	RecoveryCodesLeft int    `json:"recovery_codes_left"`
}

// New checks the keys and builds the service: encryption_key exactly 32 bytes, recovery_hash_key at least 32.
// In: config. Out: service or *ConfigError invalid_key. Why: TOTP-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func New(cfg Config) (*Service, error) {
	if len(cfg.EncryptionKey) != 32 || len(cfg.RecoveryHashKey) < 32 {
		return nil, &ConfigError{Code: "invalid_key"}
	}
	cfg.EncryptionKey = append([]byte(nil), cfg.EncryptionKey...)
	cfg.RecoveryHashKey = append([]byte(nil), cfg.RecoveryHashKey...)
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
	return &Service{cfg: cfg}, nil
}

// GenerateSecret is base32_encode(random_bytes(20)): 32 characters.
// In: none. Out: secret. Why: TOTP-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the random source.
func (s *Service) GenerateSecret() string { return Base32Encode(s.cfg.RandomBytes(20)) }

// RecoveryHash is lower-case hex of HMAC-SHA256(recovery_hash_key, "recovery:" + user + ":" + normalised code).
// In: user, code in RECOVERY INPUT form. Out: hex. Why: TOTP-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func (s *Service) RecoveryHash(userID, normalized string) string {
	m := hmac.New(sha256.New, s.cfg.RecoveryHashKey)
	m.Write([]byte("recovery:" + userID + ":" + normalized))
	return hex.EncodeToString(m.Sum(nil))
}

// aad is "totp:" + user_id.
// In: user. Out: aad. Why: binds a sealed secret to its user. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func aad(userID string) string { return "totp:" + userID }

// totpInput removes ASCII spaces and "-" and requires exactly 6 digits 0-9; over 64 characters is never one.
// In: code. Out: digits, ok. Why: TOTP-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func totpInput(code string) (string, bool) {
	if utf8.RuneCountInString(code) > 64 {
		return "", false
	}
	c := strings.NewReplacer(" ", "", "-", "").Replace(code)
	if len(c) != Digits {
		return "", false
	}
	for i := 0; i < len(c); i++ {
		if c[i] < '0' || c[i] > '9' {
			return "", false
		}
	}
	return c, true
}

// recoveryInput maps A-Z to a-z, removes ASCII spaces and "-", and requires 12 RECOVERY ALPHABET symbols.
// In: code. Out: normalised code, ok. Why: TOTP-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func recoveryInput(code string) (string, bool) {
	if utf8.RuneCountInString(code) > 64 {
		return "", false
	}
	b := []byte{}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if c == ' ' || c == '-' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b = append(b, c)
	}
	if len(b) != 12 {
		return "", false
	}
	for _, c := range b {
		if strings.IndexByte(RecoveryAlphabet, c) < 0 {
			return "", false
		}
	}
	return string(b), true
}

// match is MATCH: compares the codes of steps s-1, s, s+1 in constant time, all of them, and returns the
// largest equal step.
// In: key, digits, now. Out: step, found. Why: TOTP-05, TOTP-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func match(key []byte, input string, now int64) (int64, bool) {
	s := now / Step
	best, found := int64(-1), 0
	for d := int64(-1); d <= 1; d++ {
		st := s + d
		if st < 0 {
			continue
		}
		eq := subtle.ConstantTimeCompare([]byte(Hotp(key, uint64(st), Digits)), []byte(input))
		if eq == 1 {
			best = st
		}
		found |= eq
	}
	return best, found == 1
}

// drawRecoveryCodes makes 8 distinct codes, one random byte per symbol, redrawing bytes >= 240.
// In: none. Out: codes shown as xxxx-xxxx-xxxx. Why: TOTP-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the random source.
func (s *Service) drawRecoveryCodes() []string {
	codes := []string{}
	seen := map[string]bool{}
	for len(codes) < RecoveryCodes {
		sym := make([]byte, 0, 12)
		for len(sym) < 12 {
			b := s.cfg.RandomBytes(1)
			if len(b) < 1 || b[0] >= 240 {
				continue
			}
			sym = append(sym, RecoveryAlphabet[int(b[0])%30])
		}
		c := string(sym[0:4]) + "-" + string(sym[4:8]) + "-" + string(sym[8:12])
		if seen[c] {
			continue
		}
		seen[c] = true
		codes = append(codes, c)
	}
	return codes
}

// lockedRefusal is 429 locked with retry_after from the 5th most recent failure.
// In: user, now. Out: refusal. Why: TOTP-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
func (s *Service) lockedRefusal(userID string, now int64) *Refusal {
	times, err := s.cfg.Store.FailureTimes(userID)
	if err != nil || len(times) < LockFailures {
		return &Refusal{Error: "locked", Status: 429, RetryAfter: 1}
	}
	return &Refusal{Error: "locked", Status: 429, RetryAfter: times[LockFailures-1] + LockSeconds - now}
}

// failure keeps the slot row as the failure and adds 1 to failed_since_success.
// In: user. Out: 401 invalid_code. Why: FAILURE. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
func (s *Service) failure(userID string) *Refusal {
	_ = s.cfg.Store.AddFailure(userID)
	return &Refusal{Error: "invalid_code", Status: 401}
}

// EnrollStart starts (or restarts, before confirming) an enrollment and returns the secret once.
// In: verified user id, account label. Out: {secret, otpauth_uri}, or 409 already_enrolled / 500 storage_failed.
// Why: TOTP-03, TOTP-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the random source.
func (s *Service) EnrollStart(userID, label string) (*StartResult, *Refusal) {
	e, err := s.cfg.Store.GetEnrollment(userID)
	if err != nil {
		return nil, &Refusal{Error: "storage_failed", Status: 500}
	}
	if e != nil && e.ConfirmedAt != nil {
		return nil, &Refusal{Error: "already_enrolled", Status: 409}
	}
	secret := s.GenerateSecret()
	sealed, err := Seal(s.cfg.EncryptionKey, s.cfg.RandomBytes(12), []byte(secret), aad(userID))
	if err != nil {
		return nil, &Refusal{Error: "storage_failed", Status: 500}
	}
	ok, err := s.cfg.Store.StartEnrollment(Enrollment{UserID: userID, SecretEnc: sealed, CreatedAt: s.cfg.Clock()})
	if err != nil {
		return nil, &Refusal{Error: "storage_failed", Status: 500}
	}
	if !ok {
		return nil, &Refusal{Error: "already_enrolled", Status: 409}
	}
	return &StartResult{Secret: secret, OtpauthURI: OtpauthURI(secret, s.cfg.Issuer, label)}, nil
}

// EnrollConfirm confirms the enrollment with a current code and returns the 8 recovery codes once.
// In: verified user id, code. Out: codes, or 409 enrollment_not_started / already_enrolled, 429 locked,
// 401 invalid_code, 503 secret_unreadable, 500 storage_failed.
// Why: TOTP-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the clock, the random source.
func (s *Service) EnrollConfirm(userID, code string) ([]string, *Refusal) {
	now := s.cfg.Clock()
	e, err := s.cfg.Store.GetEnrollment(userID)
	if err != nil {
		return nil, &Refusal{Error: "storage_failed", Status: 500}
	}
	if e == nil {
		return nil, &Refusal{Error: "enrollment_not_started", Status: 409}
	}
	if e.ConfirmedAt != nil {
		return nil, &Refusal{Error: "already_enrolled", Status: 409}
	}
	slot, ok, err := s.cfg.Store.Try(userID, now)
	if err != nil {
		return nil, &Refusal{Error: "storage_failed", Status: 500}
	}
	if !ok {
		return nil, s.lockedRefusal(userID, now)
	}
	input, ok := totpInput(code)
	if !ok {
		return nil, s.failure(userID)
	}
	secret, ok := Open(s.cfg.EncryptionKey, e.SecretEnc, aad(userID))
	if !ok {
		_ = s.cfg.Store.DeleteSlot(slot)
		return nil, &Refusal{Error: "secret_unreadable", Status: 503}
	}
	key, err := Base32Decode(string(secret))
	if err != nil {
		_ = s.cfg.Store.DeleteSlot(slot)
		return nil, &Refusal{Error: "secret_unreadable", Status: 503}
	}
	step, found := match(key, input, now)
	if !found {
		return nil, s.failure(userID)
	}
	changed, err := s.cfg.Store.Confirm(userID, now, step, e.SecretEnc)
	if err != nil {
		_ = s.cfg.Store.DeleteSlot(slot)
		return nil, &Refusal{Error: "storage_failed", Status: 500}
	}
	if !changed {
		cur, _ := s.cfg.Store.GetEnrollment(userID)
		if cur != nil && cur.ConfirmedAt != nil {
			_ = s.cfg.Store.DeleteSlot(slot)
			return nil, &Refusal{Error: "already_enrolled", Status: 409}
		}
		return nil, s.failure(userID)
	}
	codes := s.drawRecoveryCodes()
	hashes := make([]string, len(codes))
	for i, c := range codes {
		n, _ := recoveryInput(c)
		hashes[i] = s.RecoveryHash(userID, n)
	}
	if err := s.cfg.Store.AddRecoveryCodes(userID, hashes, now); err != nil {
		_ = s.cfg.Store.DeleteSlot(slot)
		return nil, &Refusal{Error: "storage_failed", Status: 500}
	}
	_ = s.cfg.Store.DeleteSlot(slot)
	return codes, nil
}

// check runs steps 1 to 5 of verify and is shared by Verify and Disable.
// In: user, code. Out: method on success, or the refusal. Why: TOTP-05 to -14. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the clock.
func (s *Service) check(userID, code string) (string, *Refusal) {
	now := s.cfg.Clock()
	e, err := s.cfg.Store.GetEnrollment(userID)
	if err != nil {
		return "", &Refusal{Error: "storage_failed", Status: 500}
	}
	if e == nil || e.ConfirmedAt == nil {
		return "", &Refusal{Error: "not_enrolled", Status: 409}
	}
	slot, ok, err := s.cfg.Store.Try(userID, now)
	if err != nil {
		return "", &Refusal{Error: "storage_failed", Status: 500}
	}
	if !ok {
		return "", s.lockedRefusal(userID, now)
	}
	if input, ok := totpInput(code); ok {
		if e.FailedSinceSuccess >= HardLockFailures {
			_ = s.cfg.Store.DeleteSlot(slot)
			return "", &Refusal{Error: "recovery_required", Status: 429}
		}
		secret, ok := Open(s.cfg.EncryptionKey, e.SecretEnc, aad(userID))
		key, err := Base32Decode(string(secret))
		if !ok || err != nil {
			_ = s.cfg.Store.DeleteSlot(slot)
			return "", &Refusal{Error: "secret_unreadable", Status: 503}
		}
		step, found := match(key, input, now)
		if !found || step <= e.LastUsedStep {
			return "", s.failure(userID)
		}
		claimed, err := s.cfg.Store.Claim(userID, step)
		if err != nil {
			_ = s.cfg.Store.DeleteSlot(slot)
			return "", &Refusal{Error: "storage_failed", Status: 500}
		}
		if !claimed {
			return "", s.failure(userID)
		}
		_ = s.cfg.Store.DeleteSlot(slot)
		return "totp", nil
	}
	if n, ok := recoveryInput(code); ok {
		used, err := s.cfg.Store.UseRecoveryCode(userID, s.RecoveryHash(userID, n), now)
		if err != nil {
			_ = s.cfg.Store.DeleteSlot(slot)
			return "", &Refusal{Error: "storage_failed", Status: 500}
		}
		if !used {
			return "", s.failure(userID)
		}
		_ = s.cfg.Store.ResetFailures(userID)
		_ = s.cfg.Store.DeleteSlot(slot)
		return "recovery_code", nil
	}
	return "", s.failure(userID)
}

// Verify checks a 6-digit code or a recovery code for an enrolled user.
// In: verified user id, code ("" when missing). Out: {ok, method, recovery_codes_left}, or 409 not_enrolled,
// 429 locked / recovery_required, 401 invalid_code, 503 secret_unreadable, 500 storage_failed.
// Why: TOTP-05 to -10, -13, -14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the clock.
func (s *Service) Verify(userID, code string) (*VerifyResult, *Refusal) {
	method, ref := s.check(userID, code)
	if ref != nil {
		return nil, ref
	}
	left, _ := s.cfg.Store.RecoveryCodesLeft(userID)
	return &VerifyResult{OK: true, Method: method, RecoveryCodesLeft: left}, nil
}

// Disable checks the code like verify and then deletes the enrollment, recovery codes and failures.
// In: verified user id, code. Out: disabled, or verify's refusals. Why: TOTP-12, TOTP-13. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the clock.
func (s *Service) Disable(userID, code string) (bool, *Refusal) {
	if _, ref := s.check(userID, code); ref != nil {
		return false, ref
	}
	if err := s.cfg.Store.DeleteUser(userID); err != nil {
		return false, &Refusal{Error: "storage_failed", Status: 500}
	}
	return true, nil
}

// Status reports enrollment, lock and recovery state; reading it changes nothing.
// In: verified user id. Out: status, or 500 storage_failed. Why: spec status (auth_system's MFA check).
// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store (read), the clock.
func (s *Service) Status(userID string) (*StatusResult, *Refusal) {
	now := s.cfg.Clock()
	e, err := s.cfg.Store.GetEnrollment(userID)
	if err != nil {
		return nil, &Refusal{Error: "storage_failed", Status: 500}
	}
	out := &StatusResult{}
	if e != nil && e.ConfirmedAt != nil {
		out.Enrolled = true
		out.RecoveryRequired = e.FailedSinceSuccess >= HardLockFailures
	}
	times, _ := s.cfg.Store.FailureTimes(userID)
	n := 0
	for _, t := range times {
		if t > now-LockSeconds {
			n++
		}
	}
	if n >= LockFailures {
		u := times[LockFailures-1] + LockSeconds
		out.LockedUntil = &u
	}
	out.RecoveryCodesLeft, _ = s.cfg.Store.RecoveryCodesLeft(userID)
	return out, nil
}

// itoa formats a 64-bit integer in decimal.
// In: n. Out: text. Why: codes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
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

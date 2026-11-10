// Package screening finds secrets (API keys, tokens, private keys, passwords in URLs and in assignments) and
// personal data (email addresses, phone numbers, card numbers, IP addresses, US social security numbers) in a
// text before it is stored, logged or shared, and either refuses the text or replaces each match with a marker
// (docs/specs/secret_pii_screening.md).
//
// Matching follows the spec's MATCHING procedure exactly. Go's regexp is an RE2 engine with leftmost-first
// semantics, so the leftmost match at or after pos is the smallest start p at which the regex, anchored at p,
// matches, and the match there is the same. find_all therefore tries the anchored regex only at starts that can
// begin a match and that pass the detector's start-only guard (a guard that reads only the character before
// m rejects every match at that start, so skipping it changes nothing). This keeps each scan linear for the
// spec's hostile inputs.
//
// Why: Phase D wave 1, owner request 2026-11-10 (spec SCREEN-01 to SCREEN-14).
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing outside memory: no database, files, network or money. It never logs the text, a matched value
// or the hash key.
package screening

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// DefaultMaxBytes is max_bytes when none is given.
// Why: spec new_screener. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
const DefaultMaxBytes = 1048576

// ConfigError is the construction failure invalid_hash_key (fail closed).
// Why: SCREEN-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type ConfigError struct{ Code string }

// Error returns the code; it never holds the key.
// In: none. Out: code. Why: SCREEN-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func (e *ConfigError) Error() string { return e.Code }

// Finding is one match: its category, label, code-point span, masked preview and keyed hash. It never holds the
// matched value.
// Why: spec scan_text. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type Finding struct {
	Category  string  `json:"category"`
	Label     string  `json:"label"`
	Start     int     `json:"start"`
	End       int     `json:"end"`
	Preview   string  `json:"preview"`
	ValueHash *string `json:"value_hash"`
	Encoded   bool    `json:"encoded"`
}

// Result is screen_text's answer: {ok: true, status: 200, text, findings} or a refusal {ok: false, error,
// status, findings?}. A refusal never carries text.
// Why: spec CONVENTIONS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type Result struct {
	OK       bool      `json:"ok"`
	Status   int       `json:"status"`
	Error    string    `json:"error,omitempty"`
	Text     *string   `json:"text,omitempty"`
	Findings []Finding `json:"findings"`
}

// Screener holds the hash key and the size limit.
// Why: spec new_screener. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type Screener struct {
	hashKey  []byte
	maxBytes int
}

// NewScreener builds a screener. hashKey nil means no key (every value_hash null); a key under 32 bytes fails
// with invalid_hash_key. maxBytes <= 0 means DefaultMaxBytes.
// In: hash key, max bytes. Out: screener or *ConfigError. Why: SCREEN-12, SCREEN-14. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func NewScreener(hashKey []byte, maxBytes int) (*Screener, error) {
	if hashKey != nil && len(hashKey) < 32 {
		return nil, &ConfigError{Code: "invalid_hash_key"}
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	var k []byte
	if hashKey != nil {
		k = append([]byte(nil), hashKey...)
	}
	return &Screener{hashKey: k, maxBytes: maxBytes}, nil
}

// cand is one detector candidate, in byte offsets.
// Why: COMBINING. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type cand struct{ s, e, det int }

// detector is one entry of the DETECTORS table.
// Why: spec DETECTORS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type detector struct {
	num   int
	label string
	cat   string
	find  func(text, lower string) []cand
}

// isW is W = [A-Za-z0-9_].
// In: byte. Out: bool. Why: guards. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func isW(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

// isDigit is 0-9 only.
// In: byte. Out: bool. Why: guards and checks. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// isHex is 0-9, a-f, A-F.
// In: byte. Out: bool. Why: IPv6 and escapes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func isHex(c byte) bool { return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') }

// isLetter is A-Z a-z.
// In: byte. Out: bool. Why: URL scheme. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// before returns the byte before position p, or -1 for none. A byte >= 0x80 stands for a non-ASCII character,
// which is in none of the guards' ASCII sets.
// In: text, p. Out: byte or -1. Why: guards. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func before(s string, p int) int {
	if p == 0 {
		return -1
	}
	return int(s[p-1])
}

// after returns the byte at position e (just after a match), or -1 at the end.
// In: text, e. Out: byte or -1. Why: guards. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func after(s string, e int) int {
	if e >= len(s) {
		return -1
	}
	return int(s[e])
}

// notW reports "none, or a character outside W".
// In: byte or -1. Out: bool. Why: guards. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func notW(c int) bool { return c < 0 || !isW(byte(c)) }

// anchored compiles a core regex anchored at the start of the slice it is run on.
// In: core regex. Out: compiled regex. Why: MATCHING (leftmost match = smallest anchored start). 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func anchored(core string) *regexp.Regexp { return regexp.MustCompile(`^(?:` + core + `)`) }

// findRx is find_all for a regex detector. start(p) must be false only where no accepted match can start at p;
// accept judges a match m (absolute indices, group 1 included) and returns the span and the next pos.
// In: text, regex, start filter, accept. Out: candidates. Why: MATCHING. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func findRx(s string, re *regexp.Regexp, start func(p int) bool, accept func(m []int) (cs, ce, next int, ok bool)) []cand {
	out := []cand{}
	pos := 0
	for pos < len(s) {
		var m []int
		for p := pos; p < len(s); p++ {
			if !start(p) {
				continue
			}
			if loc := re.FindStringSubmatchIndex(s[p:]); loc != nil {
				for i := range loc {
					if loc[i] >= 0 {
						loc[i] += p
					}
				}
				m = loc
				break
			}
		}
		if m == nil {
			break
		}
		if cs, ce, next, ok := accept(m); ok {
			out = append(out, cand{s: cs, e: ce})
			pos = next
		} else {
			pos = m[0] + 1
		}
	}
	return out
}

// whole accepts the whole match when ok, with pos = the end of m.
// In: match, ok. Out: accept's values. Why: most detectors. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func whole(m []int, ok bool) (int, int, int, bool) { return m[0], m[1], m[1], ok }

// group1 accepts capture group 1 when ok, with pos = the end of m.
// In: match, ok. Out: accept's values. Why: detectors 11 and 12 ("span: group 1"). 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func group1(m []int, ok bool) (int, int, int, bool) { return m[2], m[3], m[1], ok }

const pemHeader = `-----BEGIN (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----`

var (
	rePem1     = anchored(pemHeader + `(?:\r?\nProc-Type: 4,ENCRYPTED\r?\nDEK-Info: [A-Z0-9-]{1,32},[0-9A-Fa-f]{1,64}\r?\n)?[^-]*-----END (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----`)
	rePemHead  = anchored(pemHeader)
	reOpenAI   = anchored(`sk-[A-Za-z0-9_-]{15,499}[A-Za-z0-9_]`)
	reStripe   = anchored(`[spr]k_(?:live|test)_[A-Za-z0-9]{16,500}`)
	reAWS      = anchored(`A[KS]IA[0-9A-Z]{16}`)
	reGitHub   = anchored(`gh[pousr]_[A-Za-z0-9]{20,500}|github_pat_[A-Za-z0-9_]{20,500}`)
	reSlack    = anchored(`xox[abprs]-[A-Za-z0-9-]{9,499}[A-Za-z0-9]`)
	reGoogle   = anchored(`AIza[0-9A-Za-z_-]{35}`)
	reWhsec    = anchored(`whsec_[A-Za-z0-9+/=]{16,500}`)
	reBearer   = anchored(`[Bb][Ee][Aa][Rr][Ee][Rr][ \t]+([A-Za-z0-9._~+/=-]{10,})`)
	reURL      = anchored(`[A-Za-z][A-Za-z0-9+.-]{0,30}://[^/ \t\r\n:@]*:([^@ \t\r\n/]+)@`)
	reGeneric  = anchored(`(?:api[_-]?key|apikey|secret(?:[_-]?key)?|password|passwd|pwd|access[_-]?key|auth[_-]?token|private[_-]?key|credentials?|token)(?:\\?["'])?[ \t]*(?::=|=>|[:=])[ \t]*(?:\\?["'])?`)
	reEmail    = anchored(`[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}`)
	rePhone    = anchored(`(?:\+?1[-. ]?)?\(?[0-9]{3}\)?[-. ][0-9]{3}[-. ][0-9]{4}|\+[1-9][0-9]{7,14}`)
	reCard     = anchored(`[0-9](?:[ -]?[0-9]){12,18}`)
	reSSN      = anchored(`[0-9]{3}-[0-9]{2}-[0-9]{4}`)
	reIPv4     = anchored(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`)
	reIPv6     = anchored(`[0-9A-Fa-f:]{2,39}`)
	cardPrefix = regexp.MustCompile(`^(?:4|5[1-5]|2(?:22[1-9]|2[3-9][0-9]|[3-6][0-9][0-9]|7[01][0-9]|720)|3[47]|6(?:011|5[0-9][0-9]|4[4-9][0-9])|3(?:0[0-5]|[68][0-9])|35[0-9][0-9])`)
)

// placeholders is the PLACEHOLDERS list.
// Why: detectors 12 and 13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
var placeholders = map[string]bool{}

// init fills placeholders from the spec's list.
// In: none. Out: none. Why: PLACEHOLDERS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory.
func init() {
	for _, p := range strings.Fields("changeme change_me your_key_here your-key-here xxx xxxx xxxxx redacted todo example " +
		"placeholder secret password insert_key_here none null n/a na <your-password> <your-key> fillmein") {
		placeholders[p] = true
	}
}

// asciiLower maps A-Z to a-z and changes no other byte, so positions stay the same.
// In: text. Out: text. Why: CONVENTIONS ("ASCII lower case"). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// hasDigit reports whether s holds 0-9.
// In: text. Out: bool. Why: checks. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func hasDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			return true
		}
	}
	return false
}

// camelHumps counts places where a-z is directly followed by A-Z.
// In: text. Out: count. Why: detector 11 check, looks_like_secret. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func camelHumps(s string) int {
	n := 0
	for i := 0; i+1 < len(s); i++ {
		if s[i] >= 'a' && s[i] <= 'z' && s[i+1] >= 'A' && s[i+1] <= 'Z' {
			n++
		}
	}
	return n
}

// looksLikeSecret: a digit 0-9; or a character below U+0080 outside [A-Za-z0-9]; or 2 a-z/A-Z humps.
// In: text. Out: bool. Why: detector 13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func looksLikeSecret(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if isDigit(c) || (c < 0x80 && (!isW(c) || c == '_')) {
			return true
		}
	}
	return camelHumps(v) >= 2
}

// isName is NAME: a letter A-Z a-z or "_" followed by letters, digits 0-9 and "_".
// In: text. Out: bool. Why: REFERENCE. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func isName(s string) bool {
	if s == "" || !(isLetter(s[0]) || s[0] == '_') {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isW(s[i]) {
			return false
		}
	}
	return true
}

// allNames reports whether every part of s split at "." is a NAME.
// In: text. Out: bool. Why: REFERENCE. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func allNames(s string) bool {
	for _, p := range strings.Split(s, ".") {
		if !isName(p) {
			return false
		}
	}
	return true
}

// isReference is REFERENCE(V): a variable, template or mask; a call or index on a dotted name; or a dotted
// name without digits.
// In: V. Out: bool. Why: detector 13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func isReference(v string) bool {
	if v != "" && strings.IndexByte("$<{%*", v[0]) >= 0 {
		return true
	}
	if i := strings.IndexAny(v, "(["); i >= 0 && allNames(v[:i]) {
		return true
	}
	return strings.IndexByte(v, '.') >= 0 && !hasDigit(v) && allNames(v)
}

// findPemTruncated is detector 2: a private key block cut off before its END line, found by hand.
// In: text. Out: candidates. Why: SCREEN-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func findPemTruncated(s string) []cand {
	out := []cand{}
	n := len(s)
	pos := 0
	for pos < n {
		i := strings.Index(s[pos:], "-----BEGIN ")
		if i < 0 {
			break
		}
		hs := pos + i
		loc := rePemHead.FindStringIndex(s[hs:])
		if loc == nil {
			pos = hs + 1
			continue
		}
		p, count, end := hs+loc[1], 0, -1
		for {
			q := p
			for q < n {
				c := s[q]
				if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '>' || c == '-' {
					q++
				} else if strings.HasPrefix(s[q:], `\n`) {
					q += 2
				} else if strings.HasPrefix(s[q:], `\r\n`) {
					q += 4
				} else {
					break
				}
			}
			r := q
			for r < n && ((isW(s[r]) && s[r] != '_') || s[r] == '+' || s[r] == '/' || s[r] == '=') {
				r++
			}
			if r-q < 16 {
				break
			}
			count, end, p = count+(r-q), r, r
		}
		if count >= 60 {
			out = append(out, cand{s: hs, e: end})
			pos = end
		} else {
			pos = hs + 1
		}
	}
	return out
}

// isS is S = [A-Za-z0-9_-] (detector 10).
// In: byte. Out: bool. Why: jwt. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func isS(c byte) bool { return isW(c) || c == '-' }

// runEnd returns the end of the run of S characters that starts at i.
// In: text, i. Out: end. Why: jwt. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func runEnd(s string, i int) int {
	for i < len(s) && isS(s[i]) {
		i++
	}
	return i
}

// findJWT is detector 10: three dot-separated runs of S starting with "eyJ", found by hand so it is linear.
// In: text. Out: candidates. Why: SCREEN-02, SCREEN-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func findJWT(s string) []cand {
	out := []cand{}
	pos := 0
	for pos < len(s) {
		k := strings.Index(s[pos:], "eyJ")
		if k < 0 {
			break
		}
		i := pos + k
		if !notW(before(s, i)) {
			pos = i + 1
			continue
		}
		j := runEnd(s, i)
		pos = j
		if j-i < 8 || j >= len(s) || s[j] != '.' {
			continue
		}
		k2 := runEnd(s, j+1)
		if k2-(j+1) < 5 || k2 >= len(s) || s[k2] != '.' {
			continue
		}
		e := runEnd(s, k2+1)
		if e-(k2+1) < 5 {
			continue
		}
		out = append(out, cand{s: i, e: e})
		pos = e
	}
	return out
}

// genericValueEnds is detector 13's value rule as a lookup table, built once per text from right to left:
// ends[p] is where a value starting at p ends. A value stops at space, tab, LF, CR, FF, VT, ' " ; or at a
// backslash whose next character is one of those blanks or quotes (a backslash at the very end is taken).
// In: text. Out: table of len(text)+1 ends. Why: SCREEN-14 ("token=$" * 28571 is quadratic when each value is
// scanned on its own; spec note of commit fed6e7b: compute where each value ends once). 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing (memory).
func genericValueEnds(s string) []int32 {
	stop := func(c byte) bool {
		return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' || c == '\'' || c == '"'
	}
	ends := make([]int32, len(s)+1)
	ends[len(s)] = int32(len(s))
	for p := len(s) - 1; p >= 0; p-- {
		c := s[p]
		if stop(c) || c == ';' || (c == '\\' && p+1 < len(s) && stop(s[p+1])) {
			ends[p] = int32(p)
		} else {
			ends[p] = ends[p+1]
		}
	}
	return ends
}

// atLeastRunes reports whether s holds at least n code points, reading no further than it must.
// In: text, n. Out: bool. Why: detector 13's 8-character check in constant time (SCREEN-14). 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func atLeastRunes(s string, n int) bool {
	for range s {
		n--
		if n <= 0 {
			return true
		}
	}
	return n <= 0
}

// runBefore counts the [a-z0-9_.-] characters just before p in lower, stopping at 41.
// In: lower text, p. Out: count. Why: detector 13 guard. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func runBefore(lower string, p int) int {
	n := 0
	for k := p - 1; k >= 0 && n <= 40; k-- {
		c := lower[k]
		if (c >= 'a' && c <= 'z') || isDigit(c) || c == '_' || c == '.' || c == '-' {
			n++
		} else {
			break
		}
	}
	return n
}

// cardSpan is detector 16's span rule: the longest prefix of m with 13-19 digits, a card-like grouping, a valid
// end, a card network prefix and a Luhn check.
// In: text, match. Out: span end, ok. Why: SCREEN-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func cardSpan(s string, m []int) (int, bool) {
	sub := s[m[0]:m[1]]
	digits := make([]byte, 0, 19)
	for i := 0; i < len(sub); i++ {
		if isDigit(sub[i]) {
			digits = append(digits, sub[i])
		}
	}
	if !cardPrefix.Match(digits) {
		return 0, false
	}
	for e := len(sub); e > 0; e-- {
		if e == len(sub) {
			if !notW(after(s, m[1])) {
				continue
			}
		} else if sub[e] != ' ' && sub[e] != '-' {
			continue
		}
		pre := sub[:e]
		groups := strings.FieldsFunc(pre, func(r rune) bool { return r == ' ' || r == '-' })
		d := strings.Join(groups, "")
		if len(d) < 13 || len(d) > 19 {
			continue
		}
		okGroups := true
		for _, g := range groups[:len(groups)-1] {
			if len(g) < 4 {
				okGroups = false
				break
			}
		}
		if okGroups && luhn(d) {
			return m[0] + e, true
		}
	}
	return 0, false
}

// luhn is the Luhn check over a digit string.
// In: digits. Out: valid. Why: SCREEN-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func luhn(d string) bool {
	sum := 0
	for i := len(d) - 1; i >= 0; i-- {
		v := int(d[i] - '0')
		if (len(d)-1-i)%2 == 1 {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
	}
	return sum%10 == 0
}

// ssnOK is detector 17's check.
// In: "ddd-dd-dddd". Out: possible. Why: SCREEN-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func ssnOK(v string) bool {
	a, b, c := v[0:3], v[4:6], v[7:11]
	return a != "000" && a != "666" && a[0] != '9' && b != "00" && c != "0000"
}

// ipv4OK is detector 18's check: no number over 255 or with a leading zero, and a public host address.
// In: dotted text. Out: public. Why: SCREEN-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func ipv4OK(v string) bool {
	parts := strings.Split(v, ".")
	n := make([]int, 4)
	for i, p := range parts {
		if len(p) > 1 && p[0] == '0' {
			return false
		}
		x, _ := strconv.Atoi(p)
		if x > 255 {
			return false
		}
		n[i] = x
	}
	if n[0] == 0 || n[0] == 10 || n[0] == 127 || n[0] >= 224 {
		return false
	}
	if (n[0] == 169 && n[1] == 254) || (n[0] == 172 && n[1] >= 16 && n[1] <= 31) || (n[0] == 192 && n[1] == 168) {
		return false
	}
	return n[3] != 0
}

// hexGroups reports whether every part of s split at ":" is 1 to 4 hex digits; "" has no groups.
// In: text. Out: group count, ok. Why: IPv6 check. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func hexGroups(s string) (int, bool) {
	if s == "" {
		return 0, true
	}
	parts := strings.Split(s, ":")
	for _, p := range parts {
		if len(p) < 1 || len(p) > 4 {
			return 0, false
		}
		for i := 0; i < len(p); i++ {
			if !isHex(p[i]) {
				return 0, false
			}
		}
	}
	return len(parts), true
}

// ipv6OK is detector 19's check: at most one "::", never ":::", 8 groups (or at most 7 around "::"), and a
// first group from 0x2000 to 0x3fff (global addresses only).
// In: text. Out: global. Why: SCREEN-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func ipv6OK(v string) bool {
	if strings.Contains(v, ":::") || strings.Count(v, "::") > 1 {
		return false
	}
	first := "0"
	if i := strings.Index(v, "::"); i >= 0 {
		l, ok1 := hexGroups(v[:i])
		r, ok2 := hexGroups(v[i+2:])
		if !ok1 || !ok2 || l+r > 7 {
			return false
		}
		if i > 0 {
			first = strings.Split(v[:i], ":")[0]
		}
	} else {
		g, ok := hexGroups(v)
		if !ok || g != 8 {
			return false
		}
		first = strings.Split(v, ":")[0]
	}
	x, err := strconv.ParseUint(first, 16, 32)
	return err == nil && x >= 0x2000 && x <= 0x3fff
}

// emailGuard is detector 14's guard after the match: after is not W, and m is not the user part of a URL.
// In: text, match. Out: passes. Why: SCREEN-04, SCREEN-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func emailGuard(s string, m []int) bool {
	if !notW(after(s, m[1])) {
		return false
	}
	for k := m[0] - 1; k >= 0; k-- {
		c := s[k]
		if c == '/' || c == '@' || c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			return !(k >= 2 && s[k-2:k+1] == "://")
		}
	}
	return true
}

// detectors is the DETECTORS table, in priority order.
// Why: spec DETECTORS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
var detectors = []detector{
	{1, "pem_private_key", "secret", func(s, _ string) []cand {
		return findRx(s, rePem1, func(p int) bool { return s[p] == '-' && strings.HasPrefix(s[p:], "-----BEGIN ") },
			func(m []int) (int, int, int, bool) { return whole(m, true) })
	}},
	{2, "pem_private_key", "secret", func(s, _ string) []cand { return findPemTruncated(s) }},
	{3, "openai_style_api_key", "secret", func(s, _ string) []cand {
		return findRx(s, reOpenAI, func(p int) bool { return s[p] == 's' && strings.HasPrefix(s[p:], "sk-") && notW(before(s, p)) },
			func(m []int) (int, int, int, bool) { return whole(m, hasDigit(s[m[0]:m[1]])) })
	}},
	{4, "stripe_style_api_key", "secret", func(s, _ string) []cand {
		return findRx(s, reStripe, func(p int) bool {
			return (s[p] == 's' || s[p] == 'p' || s[p] == 'r') && strings.HasPrefix(s[p+1:], "k_") && notW(before(s, p))
		}, func(m []int) (int, int, int, bool) { return whole(m, notW(after(s, m[1]))) })
	}},
	{5, "aws_access_key_id", "secret", func(s, _ string) []cand {
		return findRx(s, reAWS, func(p int) bool { return s[p] == 'A' && notW(before(s, p)) },
			func(m []int) (int, int, int, bool) { return whole(m, notW(after(s, m[1]))) })
	}},
	{6, "github_token", "secret", func(s, _ string) []cand {
		return findRx(s, reGitHub, func(p int) bool { return s[p] == 'g' && notW(before(s, p)) },
			func(m []int) (int, int, int, bool) { return whole(m, notW(after(s, m[1]))) })
	}},
	{7, "slack_token", "secret", func(s, _ string) []cand {
		return findRx(s, reSlack, func(p int) bool { return s[p] == 'x' && strings.HasPrefix(s[p:], "xox") && notW(before(s, p)) },
			func(m []int) (int, int, int, bool) { return whole(m, notW(after(s, m[1]))) })
	}},
	{8, "google_api_key", "secret", func(s, _ string) []cand {
		return findRx(s, reGoogle, func(p int) bool { return s[p] == 'A' && strings.HasPrefix(s[p:], "AIza") && notW(before(s, p)) },
			func(m []int) (int, int, int, bool) {
				a := after(s, m[1])
				return whole(m, notW(a) && a != '-')
			})
	}},
	{9, "webhook_signing_secret", "secret", func(s, _ string) []cand {
		return findRx(s, reWhsec, func(p int) bool { return s[p] == 'w' && strings.HasPrefix(s[p:], "whsec_") && notW(before(s, p)) },
			func(m []int) (int, int, int, bool) { return whole(m, true) })
	}},
	{10, "jwt", "secret", func(s, _ string) []cand { return findJWT(s) }},
	{11, "bearer_token", "secret", func(s, lower string) []cand {
		return findRx(s, reBearer, func(p int) bool {
			return (s[p] == 'b' || s[p] == 'B') && strings.HasPrefix(lower[p:], "bearer") && notW(before(s, p))
		}, func(m []int) (int, int, int, bool) {
			g := s[m[2]:m[3]]
			return group1(m, hasDigit(g) || camelHumps(g) >= 2)
		})
	}},
	{12, "url_credentials", "secret", func(s, _ string) []cand {
		return findRx(s, reURL, func(p int) bool {
			if !isLetter(s[p]) {
				return false
			}
			lim := p + 32
			if lim > len(s) {
				lim = len(s)
			}
			c := strings.IndexByte(s[p+1:lim], ':')
			return c >= 0 && strings.HasPrefix(s[p+1+c:], "://")
		}, func(m []int) (int, int, int, bool) {
			g := s[m[2]:m[3]]
			return group1(m, !strings.HasPrefix(g, "[REDACTED:") && !placeholders[asciiLower(g)])
		})
	}},
	{13, "generic_key_value_assignment", "secret", func(s, lower string) []cand {
		var ends []int32
		return findRx(lower, reGeneric, func(p int) bool {
			return strings.IndexByte("aspct", lower[p]) >= 0 && runBefore(lower, p) <= 40
		}, func(m []int) (int, int, int, bool) {
			vs := m[1]
			// The "[REDACTED:" test runs before the value is measured (spec IMPLEMENTATION RULES): none of its
			// characters ends a value, so the value starts with it exactly when the text at vs does.
			if strings.HasPrefix(s[vs:], "[REDACTED:") {
				return 0, 0, 0, false
			}
			if ends == nil {
				ends = genericValueEnds(s)
			}
			ve := int(ends[vs])
			val := s[vs:ve]
			if !atLeastRunes(val, 8) {
				return 0, 0, 0, false
			}
			v := strings.TrimRight(val, ".,;:!?")
			// Instant refusals first (spec note, commit fed6e7b): a value starting with $ < { % * is a REFERENCE,
			// and only a short value can be a PLACEHOLDER. Every check here refuses, so their order changes no
			// answer, only the time.
			if v != "" && strings.IndexByte("$<{%*", v[0]) >= 0 {
				return 0, 0, 0, false
			}
			if len(v) <= 32 && placeholders[asciiLower(v)] {
				return 0, 0, 0, false
			}
			if isReference(v) || !looksLikeSecret(v) {
				return 0, 0, 0, false
			}
			return vs, ve, ve, true
		})
	}},
	{14, "email_address", "pii", func(s, _ string) []cand {
		return findRx(s, reEmail, func(p int) bool {
			c := s[p]
			if !(isW(c) || c == '.' || c == '%' || c == '+' || c == '-') || !notW(before(s, p)) {
				return false
			}
			lim := p + 65
			if lim > len(s) {
				lim = len(s)
			}
			return strings.IndexByte(s[p+1:lim], '@') >= 0
		}, func(m []int) (int, int, int, bool) { return whole(m, emailGuard(s, m)) })
	}},
	{15, "phone_number", "pii", func(s, _ string) []cand {
		return findRx(s, rePhone, func(p int) bool {
			b := before(s, p)
			return (isDigit(s[p]) || s[p] == '+' || s[p] == '(') && !(b >= 0 && isDigit(byte(b)))
		}, func(m []int) (int, int, int, bool) {
			a := after(s, m[1])
			return whole(m, !(a >= 0 && isDigit(byte(a))))
		})
	}},
	{16, "credit_card_number", "pii", func(s, _ string) []cand {
		return findRx(s, reCard, func(p int) bool { return isDigit(s[p]) && notW(before(s, p)) },
			func(m []int) (int, int, int, bool) {
				e, ok := cardSpan(s, m)
				return m[0], e, e, ok
			})
	}},
	{17, "ssn", "pii", func(s, _ string) []cand {
		return findRx(s, reSSN, func(p int) bool { return isDigit(s[p]) && notW(before(s, p)) && before(s, p) != '-' },
			func(m []int) (int, int, int, bool) {
				a := after(s, m[1])
				return whole(m, notW(a) && a != '-' && ssnOK(s[m[0]:m[1]]))
			})
	}},
	{18, "ip_address", "pii", func(s, _ string) []cand {
		return findRx(s, reIPv4, func(p int) bool { return isDigit(s[p]) && notW(before(s, p)) && before(s, p) != '.' },
			func(m []int) (int, int, int, bool) {
				a := after(s, m[1])
				dotDigit := a == '.' && m[1]+1 < len(s) && isDigit(s[m[1]+1])
				return whole(m, notW(a) && !dotDigit && ipv4OK(s[m[0]:m[1]]))
			})
	}},
	{19, "ip_address", "pii", func(s, _ string) []cand {
		return findRx(s, reIPv6, func(p int) bool {
			b := before(s, p)
			return (isHex(s[p]) || s[p] == ':') && (b < 0 || !(isW(byte(b)) || b == ':' || b == '.'))
		}, func(m []int) (int, int, int, bool) {
			a := after(s, m[1])
			return whole(m, (a < 0 || !(isW(byte(a)) || a == ':')) && ipv6OK(s[m[0]:m[1]]))
		})
	}},
}

// Mask is mask(value): "*" per code point under 16; otherwise the first 2, "*" for the middle, the last 2.
// In: value. Out: preview. Why: SCREEN-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func Mask(v string) string {
	r := []rune(v)
	if len(r) < 16 {
		return strings.Repeat("*", len(r))
	}
	return string(r[:2]) + strings.Repeat("*", len(r)-4) + string(r[len(r)-2:])
}

// valueHash is lower-case hex of HMAC-SHA256(hash_key, UTF-8 of the value), or nil without a key.
// In: value. Out: hash or nil. Why: SCREEN-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func (sc *Screener) valueHash(v string) *string {
	if sc.hashKey == nil {
		return nil
	}
	m := hmac.New(sha256.New, sc.hashKey)
	m.Write([]byte(v))
	h := hex.EncodeToString(m.Sum(nil))
	return &h
}

// span is a finding's byte span, kept beside it for redaction.
// Why: redact_text. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type span struct{ s, e int }

// scan runs the selected detectors, combines their candidates and builds the findings with code-point spans.
// In: text, categories. Out: findings and their byte spans, ordered by start. Why: scan_text. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func (sc *Screener) scan(text string, cats map[string]bool) ([]Finding, []span) {
	lower := asciiLower(text)
	all := []cand{}
	for _, d := range detectors {
		if !cats[d.cat] {
			continue
		}
		for _, c := range d.find(text, lower) {
			c.det = d.num
			all = append(all, c)
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.s != b.s {
			return a.s < b.s
		}
		if a.e-a.s != b.e-b.s {
			return a.e-a.s > b.e-b.s
		}
		return a.det < b.det
	})
	findings, spans := []Finding{}, []span{}
	lastEnd, bytePos, cpPos := 0, 0, 0
	toCP := func(b int) int {
		cpPos += utf8.RuneCountInString(text[bytePos:b])
		bytePos = b
		return cpPos
	}
	for _, c := range all {
		if c.s < lastEnd {
			continue
		}
		lastEnd = c.e
		d := detectors[c.det-1]
		v := text[c.s:c.e]
		start := toCP(c.s)
		end := toCP(c.e)
		findings = append(findings, Finding{Category: d.cat, Label: d.label, Start: start, End: end, Preview: Mask(v),
			ValueHash: sc.valueHash(v)})
		spans = append(spans, span{c.s, c.e})
	}
	return findings, spans
}

// catSet checks categories: nil means ["secret", "pii"]; empty or anything else is invalid.
// In: categories. Out: set, ok. Why: SCREEN-14 (invalid_categories). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func catSet(categories []string) (map[string]bool, bool) {
	if categories == nil {
		return map[string]bool{"secret": true, "pii": true}, true
	}
	if len(categories) == 0 {
		return nil, false
	}
	set := map[string]bool{}
	for _, c := range categories {
		if c != "secret" && c != "pii" {
			return nil, false
		}
		set[c] = true
	}
	return set, true
}

// ScanText is scan_text: the findings of the detectors in categories (nil = both), ordered by start.
// In: text, categories. Out: findings (nil for invalid categories). Why: SCREEN-02 to -08, -11. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func (sc *Screener) ScanText(text string, categories []string) []Finding {
	cats, ok := catSet(categories)
	if !ok {
		return nil
	}
	f, _ := sc.scan(text, cats)
	return f
}

// redact replaces each span with "[REDACTED:" + label + "]" in one left-to-right pass.
// In: text, findings, spans. Out: text. Why: redact_text (SCREEN-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func redact(text string, f []Finding, sp []span) string {
	var b strings.Builder
	last := 0
	for i, x := range sp {
		b.WriteString(text[last:x.s])
		b.WriteString("[REDACTED:" + f[i].Label + "]")
		last = x.e
	}
	b.WriteString(text[last:])
	return b.String()
}

// RedactText is redact_text(text, findings): spans are code points, as findings carry them; findings with
// start -1 are skipped.
// In: text, findings ordered by start. Out: text. Why: spec redact_text. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func RedactText(text string, findings []Finding) string {
	byteAt := make([]int, 0, len(text)+1)
	for i := range text {
		byteAt = append(byteAt, i)
	}
	byteAt = append(byteAt, len(text))
	f, sp := []Finding{}, []span{}
	for _, x := range findings {
		if x.Start < 0 || x.Start > x.End || x.End >= len(byteAt) {
			continue
		}
		f = append(f, x)
		sp = append(sp, span{byteAt[x.Start], byteAt[x.End]})
	}
	return redact(text, f, sp)
}

// ResolveEscapes is resolve_escapes: up to 8 left-to-right passes that replace JSON escapes; unresolved is true
// when an escape is left after the 8th pass.
// In: text. Out: text, unresolved. Why: SCREEN-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func ResolveEscapes(text string) (string, bool) {
	for i := 0; i < 8 && hasEscape(text); i++ {
		text = escapePass(text)
	}
	return text, hasEscape(text)
}

// hex4 parses 4 hex digits at s[i:i+4].
// In: text, i. Out: value, ok. Why: \uXXXX. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func hex4(s string, i int) (rune, bool) {
	if i+4 > len(s) {
		return 0, false
	}
	var v rune
	for k := i; k < i+4; k++ {
		c := s[k]
		if !isHex(c) {
			return 0, false
		}
		d, _ := strconv.ParseUint(string(c), 16, 8)
		v = v*16 + rune(d)
	}
	return v, true
}

// hasEscape reports whether the text holds an ESCAPE: \uXXXX or a backslash before one of " \ / b f n r t.
// In: text. Out: bool. Why: ESCAPES. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func hasEscape(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] != '\\' {
			continue
		}
		c := s[i+1]
		if strings.IndexByte(`"\/bfnrt`, c) >= 0 {
			return true
		}
		if c == 'u' {
			if _, ok := hex4(s, i+2); ok {
				return true
			}
		}
	}
	return false
}

// escapePass is one left-to-right pass of ESCAPES; surrogate pairs combine, lone surrogates become U+FFFD.
// In: text. Out: text. Why: ESCAPES. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func escapePass(s string) string {
	var b strings.Builder
	simple := map[byte]string{'"': `"`, '\\': `\`, '/': "/", 'b': "\b", 'f': "\f", 'n': "\n", 'r': "\r", 't': "\t"}
	for i := 0; i < len(s); {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		c := s[i+1]
		if r, ok := simple[c]; ok {
			b.WriteString(r)
			i += 2
			continue
		}
		if c == 'u' {
			if v, ok := hex4(s, i+2); ok {
				if v >= 0xD800 && v <= 0xDBFF && i+12 <= len(s) && s[i+6] == '\\' && s[i+7] == 'u' {
					if lo, ok2 := hex4(s, i+8); ok2 && lo >= 0xDC00 && lo <= 0xDFFF {
						b.WriteRune(0x10000 + (v-0xD800)<<10 + (lo - 0xDC00))
						i += 12
						continue
					}
				}
				if v >= 0xD800 && v <= 0xDFFF {
					v = 0xFFFD
				}
				b.WriteRune(v)
				i += 6
				continue
			}
		}
		b.WriteByte('\\')
		i++
	}
	return b.String()
}

// refusal builds {ok: false, error, status, findings}.
// In: code, status, findings. Out: result. Why: spec CONVENTIONS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func refusal(code string, status int, f []Finding) Result {
	if f == nil {
		f = []Finding{}
	}
	return Result{OK: false, Status: status, Error: code, Findings: f}
}

// unknownPos marks findings as having no position in the text (start -1, end -1), optionally encoded.
// In: findings, encoded. Out: copies. Why: steps 8 and 9. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func unknownPos(f []Finding, encoded bool) []Finding {
	out := make([]Finding, len(f))
	for i, x := range f {
		x.Start, x.End = -1, -1
		if encoded {
			x.Encoded = true
		}
		out[i] = x
	}
	return out
}

// ScreenText is screen_text: it refuses or strips secrets and personal data, in the spec's step order. mode ""
// means "reject" and categories nil means ["secret", "pii"]. Anything raised inside is 500 screening_failed.
// In: text, mode ("reject" | "strip"), categories. Out: Result.
// Why: SCREEN-01, -09, -10, -13, -14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func (sc *Screener) ScreenText(text, mode string, categories []string) (res Result) {
	defer func() {
		if recover() != nil {
			res = refusal("screening_failed", 500, nil)
		}
	}()
	if !utf8.ValidString(text) {
		return refusal("invalid_text", 400, nil)
	}
	if mode == "" {
		mode = "reject"
	}
	if mode != "reject" && mode != "strip" {
		return refusal("invalid_mode", 400, nil)
	}
	cats, ok := catSet(categories)
	if !ok {
		return refusal("invalid_categories", 400, nil)
	}
	if len(text) > sc.maxBytes {
		return refusal("text_too_large", 413, nil)
	}
	f, sp := sc.scan(text, cats)
	if mode == "reject" && len(f) > 0 {
		return refusal("secrets_or_pii_detected", 422, f)
	}
	out := text
	if len(f) > 0 {
		out = redact(text, f, sp)
		if f2, _ := sc.scan(out, cats); len(f2) > 0 {
			return refusal("secrets_or_pii_detected", 422, append(append([]Finding{}, f...), unknownPos(f2, false)...))
		}
	}
	if strings.IndexByte(out, '\\') >= 0 {
		r, unresolved := ResolveEscapes(out)
		h := []Finding{}
		if r != out {
			hf, _ := sc.scan(r, cats)
			h = unknownPos(hf, true)
		}
		if unresolved {
			h = append(h, Finding{Category: "secret", Label: "unresolved_escape", Start: -1, End: -1, Preview: "***", Encoded: true})
		}
		if len(h) > 0 {
			return refusal("secrets_or_pii_detected", 422, append(append([]Finding{}, f...), h...))
		}
	}
	return Result{OK: true, Status: 200, Text: &out, Findings: f}
}

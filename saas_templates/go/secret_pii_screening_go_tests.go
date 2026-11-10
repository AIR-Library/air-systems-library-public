package screening

// Tests for secret_pii_screening_go.go against docs/specs/secret_pii_screening.md, with every TEST VECTOR.
// Key-shaped values are built from two or more pieces at run time so no repository scanner reads them as real.
// Phase D wave 1, owner request 2026-11-10. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: memory only; no network.

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The spec's key-shaped vectors, each joined from pieces.
// Why: TEST VECTORS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
var (
	K1 = "sk-" + "abcdEFGH12345678ijklMNOP"
	K2 = "sk_" + "live_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
	K3 = "pk_" + "test_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
	K4 = "AKIA" + "IOSFODNN7EXAMPLE"
	K5 = "ghp_" + "16C7e42F292c6912E7710c838347Ae178B4a"
	K6 = "github_pat_" + "11ABCDEFG0abcdefghij_KLMNOPQRSTUVWXYZ0123456789"
	K7 = "xoxb-" + "1234567890-abcdefghijklmnopqrstuvwx"
	K8 = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
	K9 = "whsec_" + "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
	J  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0" + "." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	B  = "-----BEGIN RSA " + "PRIVATE KEY-----"
	E  = "-----END RSA " + "PRIVATE KEY-----"
	L1 = "MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumga0R2LiajO16aI4Uxa2b9nb"
	L2 = "AKELFOxNOFICTIONALKEYMATERIALFORTESTINGPURPOSESONLY1234567890AB"
	P1 = B + "\n" + L1 + "\n" + L2 + "\n" + E
	P2 = B + "\n" + "Proc-Type: 4,ENCRYPTED\n" + "DEK-Info: AES-256-CBC,A1B2C3D4E5F60718293A4B5C6D7E8F90\n" + "\n" + L1 + "\n" + E
	P3 = B + "\n" + "api_key=looksLikeASecretButItsJustPemBase64Content\n" + E
	P4 = B + "\n" + L1 + "\n" + L2 + " (cut"
	G  = "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----" + "\nVersion: GnuPG v2\n\n" + L1 + "\n" + L2 + "\n=AbCd\n" + "-----END PGP " + "PRIVATE KEY BLOCK-----"
	T  = "Contact jane@example.com or call 555-123-4567 for help."
)

// vec is one scan vector: the text and its findings as "label start-end", joined by ", " ("" for nothing).
// Why: TEST VECTORS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type vec struct{ text, want string }

// rep repeats s n times.
// In: s, n. Out: text. Why: vectors written with "*". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func rep(s string, n int) string { return strings.Repeat(s, n) }

// clean are the four SCREEN-01 texts.
// Why: SCREEN-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
var clean = []string{
	"User: let's plan the export feature.\nAssistant: I built the CSV export button and will add a progress bar.\n",
	"def get_cache_key(user_id):\n    return f'user:{user_id}'\n\nclass TokenBucket:\n    def __init__(self, capacity):\n        self.capacity = capacity\n",
	"Please reset your password before the next login.",
	"version 1.2.3.4.5 released at 12:30:45 on 2026-11-10, build 20261110123045, order 1234567890",
}

var vectors = map[string][]vec{
	"SCREEN-02": {
		{"here is my key: " + K1, "openai_style_api_key 16-43"},
		{"STRIPE_KEY=" + K2, "stripe_style_api_key 11-43"},
		{K3 + " used in the demo", "stripe_style_api_key 0-32"},
		{"AWS_ACCESS_KEY_ID=" + K4, "aws_access_key_id 18-38"},
		{"token: " + K5, "github_token 7-47"},
		{"use " + K6 + " now", "github_token 4-62"},
		{K7, "slack_token 0-40"},
		{"key=" + K8 + "&x=1", "google_api_key 4-43"},
		{"secret " + K9 + ".", "webhook_signing_secret 7-45"},
		{"Authorization token captured: " + J, "jwt 30-162"},
		{"ASIA" + "IOSFODNN7EXAMPLE", "aws_access_key_id 0-20"},
		{"task-" + "abcdEFGH12345678ijklMNOP", ""},
		{"X" + K4, ""},
		{K2 + "_x", ""},
		{"class sk-spinner-three-bounce is used", ""},
	},
	"SCREEN-03": {
		{"a " + P1 + " b", "pem_private_key 2-192"},
		{P2, "pem_private_key 0-205"},
		{P3, "pem_private_key 0-112"},
		{"api_key=looksLikeASecretButItsJustPemBase64Content", "generic_key_value_assignment 8-50"},
		{"x " + P4, "pem_private_key 2-162"},
		{"-" + B + "\n-" + L1 + "\n-" + L2 + "\n-" + E, "pem_private_key 1-163"},
		{"> " + B + "\n> " + L1 + "\n> " + L2 + "\n> " + E, "pem_private_key 2-198"},
		{G, "pem_private_key 0-227"},
		{B + "\n" + rep("A", 30) + `\n` + rep("A", 30), "pem_private_key 0-94"},
		{B + "\n" + rep("A", 29) + `\n` + rep("A", 30), ""},
		{B + "\n" + rep("A", 59), ""},
		{"Look for the line " + B + " in the file.", ""},
	},
	"SCREEN-04": {
		{"curl -H 'Authorization: Bearer abc123DEF456ghi789JKL'", "bearer_token 31-52"},
		{"authorization: BEARER abc123DEF456ghi789JKL", "bearer_token 22-43"},
		{"Bearer authentication is required", ""},
		{"Bearer " + J, "jwt 7-139"},
		{"postgres://app:S3cr3t-Pa55@db.internal:5432/app", "url_credentials 15-26"},
		{"ssh://git:hunter2secret@host/repo", "url_credentials 10-23"},
		{"https://user:password@example.com/", ""},
		{"https://jane@example.com/x", ""},
		{"redis://:Sup3rS3cretValue@cache.example.com:6379/0", "url_credentials 9-25"},
		{"http://localhost:8080/@foo and https://example.com/a:b@c", ""},
		{"Our API uses Bearer authentication.", ""},
		{"Send the header with bearer token-based auth", ""},
	},
	"SCREEN-05": {
		{"DB_PASSWORD=Sup3rS3cretValue!\n", "generic_key_value_assignment 12-29"},
		{"internal_api_key: \"zx91-nq7f-88ab-lorem\"", "generic_key_value_assignment 19-39"},
		{"{\"password\": \"hunter2hunter2\"}", "generic_key_value_assignment 14-28"},
		{`{\"password\":\"hunter2hunter2\"}`, "generic_key_value_assignment 16-30"},
		{"db_password: CorrectHorseBatteryStaple", "generic_key_value_assignment 13-38"},
		{"the db_password: CorrectHorseBatteryStaple9 I mentioned", "generic_key_value_assignment 17-43"},
		{`password: DOMAIN\Administrator1`, "generic_key_value_assignment 10-31"},
		{"API_KEY = 'Zx91Nq7f88ab'", "generic_key_value_assignment 11-23"},
		{"token=abc12345;next", "generic_key_value_assignment 6-14"},
		{"password: p\u00e4ssw\u00f6rd123", "generic_key_value_assignment 10-21"},
		{rep("a", 40) + "token=abc12345def", "generic_key_value_assignment 46-57"},
		{rep("a", 41) + "token=abc12345def", ""},
		{"API_KEY=your_key_here", ""},
		{"password: changeme", ""},
		{"pwd=abc123", ""},
		{"Secret: whatever the team decides", ""},
		{"password: WordPress", ""},
		{"My favorite crypto token: Ethereum has been volatile", ""},
		{"class TokenBucket:", ""},
		{"Please reset your password before the next login.", ""},
		{"secrets: abc12345def", ""},
		{"password: gr\u00f6\u00dferes", ""},
		{"password: [REDACTED:generic_key_value_assignment]", ""},
		{"'password' => 'Sup3rS3cretValue!',", "generic_key_value_assignment 15-32"},
		{"password := \"Sup3rS3cretValue!\"", "generic_key_value_assignment 13-30"},
		{"password: hunter2!", "generic_key_value_assignment 10-18"},
		{"password: P@ss(w0rd)1x", "generic_key_value_assignment 10-22"},
		{"token: ab12.cd34.ef56gh78", "generic_key_value_assignment 7-25"},
		{"\u0130 token=abc12345", "generic_key_value_assignment 8-16"},
		{"The password: required.", ""},
		{"token: optional,", ""},
		{"password: changeme.", ""},
		{"password: undefined,", ""},
		{"password = os.getenv(\"DB_PASSWORD\")", ""},
		{"api_key = os.environ[\"API_KEY\"]", ""},
		{"secret_key = settings.SECRET_KEY", ""},
		{"apiKey: process.env.STRIPE_KEY,", ""},
		{"token = getAccessTokenSilently();", ""},
		{"password: req.body.password,", ""},
		{"API_KEY=$API_KEY", ""},
		{"token=${TOKEN}", ""},
		{"api_key: <YOUR_API_KEY>", ""},
		{"Password: ********", ""},
		{"token: Optional[str] = None", ""},
		{"password = models.CharField(max_length=128)", ""},
		{"to\u212aen=abc12345def", ""},
		{"password: abcdefgh\u0663", ""},
	},
	"SCREEN-06": {
		{T, "email_address 8-24, phone_number 33-45"},
		{"<jane.doe+tag@mail.example.co.uk>", "email_address 1-32"},
		{"see https://example.com/contact?email=jane@example.com", "email_address 38-54"},
		{"call (555) 123-4567 now", "phone_number 5-19"},
		{"+1 555-123-4567", "phone_number 0-15"},
		{"reach me at +442071838750.", "phone_number 12-25"},
		{"SSN 123-45-6789", "ssn 4-15"},
		{"order 5551234567 shipped", ""},
		{"jane@example.com_backup", ""},
		{"user@localhost and a@b", ""},
		{"SSN 000-12-3456, 666-12-3456, 900-12-3456, 123-00-4567, 123-45-0000", ""},
	},
	"SCREEN-07": {
		{"card 4242 4242 4242 4242 exp 12/27", "credit_card_number 5-24"},
		{"5555-5555-5555-4444", "credit_card_number 0-19"},
		{"378282246310005", "credit_card_number 0-15"},
		{"card 4242 4242 4242 4242 123", "credit_card_number 5-24"},
		{"4242 4242 4242 4242 1234 5678", "credit_card_number 0-19"},
		{"4242 4242 4242 4241", ""},
		{"1234 5678 1234 5670", ""},
		{"ts 1700000000000 ms", ""},
		{"42424242424242424242424", ""},
		{"x4242424242424242", ""},
		{"4242424242424242x", ""},
		{"3782 822463 10005", "credit_card_number 0-17"},
		{"card 4222 2222 2222 2 end", "credit_card_number 5-21"},
		{"2 2 6 14 8 15 20 6 13", ""},
		{"4 8 15 16 23 42 4 8 15 16 23 42 108", ""},
	},
	"SCREEN-08": {
		{"client 203.0.113.7 connected", "ip_address 7-18"},
		{"from 198.51.100.24.", "ip_address 5-18"},
		{"addr 2001:db8::8a2e:370:7334 ok", "ip_address 5-28"},
		{"[2001:0db8:0000:0000:0000:ff00:0042:8329]", "ip_address 1-40"},
		{"8.8.8.8 and 172.32.0.1 and 2606:4700:4700::1111", "ip_address 0-7, ip_address 12-22, ip_address 27-47"},
		{"127.0.0.1 10.0.0.5 192.168.1.1 172.16.0.1 169.254.1.1 0.0.0.0 224.0.0.1 255.255.255.255", ""},
		{"999.1.1.1 and 256.1.1.1 and 08.8.8.8", ""},
		{"1.2.3.4.5 and v8.8.8.8", ""},
		{"12:30:45 and aa:bb:cc:dd:ee:ff", ""},
		{"::1 and fe80::1 and fc00::1", ""},
		{"db::add(x) and dead::beef", ""},
		{"Version=1.0.0.0, Culture=neutral", ""},
	},
	"SCREEN-11": {
		{"\u00e9\U0001F600 a@b.co", "email_address 3-9"},
		{"token=" + K1, "openai_style_api_key 6-33"},
		{"Bearer " + K1, "openai_style_api_key 7-34"},
	},
}

// specKey is hash_key = the 32 bytes 00 01 ... 1f.
// In: none. Out: key. Why: SCREEN-09, -10, -12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func specKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

// newSc builds a screener with the spec's key.
// In: none. Out: screener. Why: helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func newSc(t *testing.T) *Screener {
	sc, err := NewScreener(specKey(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

// summary renders findings as "label start-end, ...".
// In: findings. Out: text. Why: helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func summary(f []Finding) string {
	parts := []string{}
	for _, x := range f {
		parts = append(parts, x.Label+" "+strconv.Itoa(x.Start)+"-"+strconv.Itoa(x.End))
	}
	return strings.Join(parts, ", ")
}

// checkVectors asserts every vector of one id with scan_text, and that no character is in two findings.
// In: id. Out: none. Why: SCREEN-02 to -08, -11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func checkVectors(t *testing.T, id string) {
	t.Helper()
	sc := newSc(t)
	for _, v := range vectors[id] {
		f := sc.ScanText(v.text, nil)
		if got := summary(f); got != v.want {
			t.Errorf("%s %q: got %q, want %q", id, v.text, got, v.want)
		}
		for i := 1; i < len(f); i++ {
			if f[i].Start < f[i-1].End {
				t.Errorf("%s %q: findings overlap", id, v.text)
			}
		}
		for _, x := range f {
			if x.Encoded || x.ValueHash == nil || len(*x.ValueHash) != 64 {
				t.Errorf("%s %q: finding fields %+v", id, v.text, x)
			}
		}
	}
}

// TestScreen01CleanTexts proves the four clean texts pass unchanged with no findings in both modes.
// SCREEN-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func TestScreen01CleanTexts(t *testing.T) {
	sc := newSc(t)
	for _, text := range clean {
		for _, mode := range []string{"reject", "strip"} {
			r := sc.ScreenText(text, mode, nil)
			if !r.OK || r.Status != 200 || r.Text == nil || *r.Text != text || len(r.Findings) != 0 {
				t.Fatalf("%s %q: %+v", mode, text, r)
			}
		}
	}
}

// TestScreen02KeyShapes proves every key shape and the four near-misses.
// SCREEN-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func TestScreen02KeyShapes(t *testing.T) { checkVectors(t, "SCREEN-02") }

// TestScreen03PrivateKeyBlocks proves whole blocks, cut-off blocks (quoted, diffed, escaped) and the misses.
// SCREEN-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func TestScreen03PrivateKeyBlocks(t *testing.T) { checkVectors(t, "SCREEN-03") }

// TestScreen04BearerAndURL proves bearer tokens and URL passwords, and the prose and placeholder misses.
// SCREEN-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func TestScreen04BearerAndURL(t *testing.T) { checkVectors(t, "SCREEN-04") }

// TestScreen05KeyValue proves key = value secrets in every form, and every placeholder, reference and miss.
// SCREEN-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func TestScreen05KeyValue(t *testing.T) { checkVectors(t, "SCREEN-05") }

// TestScreen06EmailPhoneSSN proves addresses, phone numbers and SSNs, and their misses.
// SCREEN-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func TestScreen06EmailPhoneSSN(t *testing.T) { checkVectors(t, "SCREEN-06") }

// TestScreen07Cards proves card prefixes, Luhn, separators and the misses.
// SCREEN-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func TestScreen07Cards(t *testing.T) { checkVectors(t, "SCREEN-07") }

// TestScreen08IPAddresses proves public IPv4, global IPv6 and every non-public or non-address miss.
// SCREEN-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func TestScreen08IPAddresses(t *testing.T) { checkVectors(t, "SCREEN-08") }

// TestScreen09RejectMode proves the 422 refusal carries findings but neither the text nor a matched value,
// and that categories ["secret"] lets the same text through.
// SCREEN-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func TestScreen09RejectMode(t *testing.T) {
	sc := newSc(t)
	r := sc.ScreenText(T, "reject", nil)
	if r.OK || r.Status != 422 || r.Error != "secrets_or_pii_detected" || r.Text != nil || summary(r.Findings) != "email_address 8-24, phone_number 33-45" {
		t.Fatalf("reject = %+v", r)
	}
	if r2 := sc.ScreenText(T, "", nil); r2.Status != 422 {
		t.Fatalf("default mode = %+v", r2)
	}
	blob, _ := json.Marshal(r)
	for _, bad := range []string{T, "jane@example.com", "555-123-4567", `"text"`} {
		if strings.Contains(string(blob), bad) {
			t.Fatalf("the refusal holds %q: %s", bad, blob)
		}
	}
	ok := sc.ScreenText(T, "reject", []string{"secret"})
	if !ok.OK || ok.Status != 200 || *ok.Text != T || len(ok.Findings) != 0 {
		t.Fatalf("secret only = %+v", ok)
	}
}

// TestScreen10StripMode proves the markers, that everything else is unchanged, that every stripped vector
// screens clean, and the 422 for a match that only shows once its neighbour is gone.
// SCREEN-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func TestScreen10StripMode(t *testing.T) {
	sc := newSc(t)
	r := sc.ScreenText(T, "strip", nil)
	want := "Contact [REDACTED:email_address] or call [REDACTED:phone_number] for help."
	if !r.OK || r.Status != 200 || *r.Text != want || summary(r.Findings) != "email_address 8-24, phone_number 33-45" {
		t.Fatalf("strip = %+v", r)
	}
	for id, list := range vectors {
		for _, v := range list {
			if v.want == "" {
				continue
			}
			s := sc.ScreenText(v.text, "strip", nil)
			if !s.OK {
				t.Fatalf("%s strip %q = %+v", id, v.text, s)
			}
			again := sc.ScreenText(*s.Text, "reject", nil)
			if !again.OK || len(again.Findings) != 0 {
				t.Fatalf("%s re-screen of %q = %+v", id, *s.Text, again)
			}
			if got := RedactText(v.text, s.Findings); got != *s.Text {
				t.Fatalf("%s redact_text differs: %q", id, got)
			}
		}
	}
	n := sc.ScreenText("jane@example.com555-123-4567", "strip", nil)
	if n.OK || n.Status != 422 || n.Text != nil || len(n.Findings) != 2 || summary(n.Findings) != "phone_number 16-28, email_address -1--1" {
		t.Fatalf("neighbour = %+v", n)
	}
}

// TestScreen11Overlaps proves the earliest start, then the longest span, then the earlier detector wins, and
// that positions count code points.
// SCREEN-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func TestScreen11Overlaps(t *testing.T) {
	checkVectors(t, "SCREEN-11")
	sc := newSc(t)
	if got := summary(sc.ScanText(P3, nil)); got != "pem_private_key 0-112" {
		t.Fatalf("earliest start: %s", got)
	}
	if got := summary(sc.ScanText("a "+P1+" b", nil)); got != "pem_private_key 2-192" {
		t.Fatalf("longest span: %s", got)
	}
	if got := summary(sc.ScanText("Bearer "+J, nil)); got != "jwt 7-139" {
		t.Fatalf("earlier detector: %s", got)
	}
}

// TestScreen12MaskAndHash proves mask, the keyed value_hash vectors, null without a key, and the key check.
// SCREEN-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func TestScreen12MaskAndHash(t *testing.T) {
	if Mask(rep("a", 15)) != rep("*", 15) || Mask("abcdefghijklmnop") != "ab************op" || Mask(K1) != "sk"+rep("*", 23)+"OP" {
		t.Fatal("mask")
	}
	sc := newSc(t)
	r := sc.ScreenText(T, "strip", []string{"pii"})
	if !r.OK || len(r.Findings) != 2 {
		t.Fatalf("strip pii = %+v", r)
	}
	want := `[{"category":"pii","label":"email_address","start":8,"end":24,"preview":"ja************om","value_hash":"9487588974759d303d5d44401791a603ad85fda9276d43f7436077d709d9da10","encoded":false},` +
		`{"category":"pii","label":"phone_number","start":33,"end":45,"preview":"************","value_hash":"ee171612a2f4984e73ec9377b4d10f2b76125f5adf8e4315f12e77ebb2cd41c3","encoded":false}]`
	if blob, _ := json.Marshal(r.Findings); string(blob) != want {
		t.Fatalf("findings = %s", blob)
	}
	nokey, _ := NewScreener(nil, 0)
	for _, f := range nokey.ScanText(T, nil) {
		if f.ValueHash != nil {
			t.Fatal("value_hash without a key")
		}
	}
	_, err := NewScreener(specKey()[:31], 0)
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Code != "invalid_hash_key" {
		t.Fatalf("short key: %v", err)
	}
}

// TestScreen13HiddenEscapes proves vectors E1 to E8 in both modes.
// SCREEN-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func TestScreen13HiddenEscapes(t *testing.T) {
	sc := newSc(t)
	e1 := `{"note": "sk\u002d` + "abcdEFGH12345678ijklMNOP" + `"}`
	e2 := `{"outer": "{\"k\": \"sk\\u002d` + "abcdEFGH12345678ijklMNOP" + `\"}"}`
	e3 := `{"msg": "the escape \u00e9 prints an e-acute and \n is a newline"}`
	e4 := `{"contact": "jane\u0040example.com"}`
	e5 := `{"emoji": "\ud83d\ude00 ok", "path": "C:\\Users\\name\\notes.txt"}`
	e6 := `{"key": "` + strings.ReplaceAll(P1, "\n", `\n`) + `"}`
	e7 := `{"key": "` + strings.ReplaceAll(P2, "\n", `\n`) + `"}`
	e8 := rep(`\`, 600) + "n"
	encoded := func(label string) string { return label + " -1--1 encoded" }
	describe := func(r Result) string {
		if r.OK {
			return "ok " + summary(r.Findings)
		}
		parts := []string{}
		for _, f := range r.Findings {
			s := f.Label + " " + strconv.Itoa(f.Start) + "-" + strconv.Itoa(f.End)
			if f.Encoded {
				s += " encoded"
			}
			parts = append(parts, s)
		}
		return strconv.Itoa(r.Status) + " " + strings.Join(parts, ", ")
	}
	cases := []struct {
		text, reject, strip string
	}{
		{e1, "422 " + encoded("openai_style_api_key"), "422 " + encoded("openai_style_api_key")},
		{e2, "422 " + encoded("openai_style_api_key"), "422 " + encoded("openai_style_api_key")},
		{e3, "ok ", "ok "},
		{e4, "422 " + encoded("email_address"), "422 " + encoded("email_address")},
		{e5, "ok ", "ok "},
		{e6, "422 pem_private_key 9-202", "ok pem_private_key 9-202"},
		{e7, "422 " + encoded("pem_private_key"), "422 " + encoded("pem_private_key")},
		{e8, "422 " + encoded("unresolved_escape"), "422 " + encoded("unresolved_escape")},
	}
	for i, c := range cases {
		rj := sc.ScreenText(c.text, "reject", nil)
		st := sc.ScreenText(c.text, "strip", nil)
		if describe(rj) != c.reject || describe(st) != c.strip {
			t.Fatalf("E%d: reject %q strip %q", i+1, describe(rj), describe(st))
		}
		if rj.OK && *rj.Text != c.text {
			t.Fatalf("E%d text changed", i+1)
		}
		if !rj.OK && rj.Error != "secrets_or_pii_detected" {
			t.Fatalf("E%d error %q", i+1, rj.Error)
		}
	}
	if st := sc.ScreenText(e6, "strip", nil); *st.Text != `{"key": "[REDACTED:pem_private_key]"}` {
		t.Fatalf("E6 strip text = %q", *st.Text)
	}
	if r := sc.ScreenText(e8, "reject", nil); r.Findings[0].Category != "secret" || r.Findings[0].Preview != "***" || r.Findings[0].ValueHash != nil {
		t.Fatalf("E8 finding = %+v", r.Findings[0])
	}
}

// TestScreen14InputChecksAndHostileInputs proves the 400/413 answers come before any scan and that each
// hostile 200,000-character input is screened in strip mode in under 2 seconds.
// SCREEN-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func TestScreen14InputChecksAndHostileInputs(t *testing.T) {
	sc := newSc(t)
	if r := sc.ScreenText("x", "mask", nil); r.Status != 400 || r.Error != "invalid_mode" || r.OK {
		t.Fatalf("mode = %+v", r)
	}
	for _, cats := range [][]string{{}, {"secret", "keys"}} {
		if r := sc.ScreenText("x", "reject", cats); r.Status != 400 || r.Error != "invalid_categories" {
			t.Fatalf("categories %v = %+v", cats, r)
		}
	}
	small, _ := NewScreener(specKey(), 9)
	if r := small.ScreenText(rep("\u00e9", 5), "reject", nil); r.Status != 413 || r.Error != "text_too_large" {
		t.Fatalf("9 bytes = %+v", r)
	}
	if r := small.ScreenText(T, "mask", nil); r.Error != "invalid_mode" {
		t.Fatalf("mode is checked before size: %+v", r)
	}
	ten, _ := NewScreener(specKey(), 10)
	if r := ten.ScreenText(rep("\u00e9", 5), "reject", nil); !r.OK {
		t.Fatalf("10 bytes = %+v", r)
	}
	if r := sc.ScreenText("ab\xffcd", "reject", nil); r.Status != 400 || r.Error != "invalid_text" {
		t.Fatalf("byte FF = %+v", r)
	}
	hostile := []string{
		rep("a.", 100000), rep("-----BEGIN "+"PRIVATE KEY-----", 7400), rep("1234-", 40000), rep("eyJ", 66666),
		rep("xeyJ-", 40000), rep("xsk-", 50000), "password" + rep(" ", 199990), rep("token=[REDACTED:", 12500), rep("token=$", 28571),
		rep("a://b:", 33000), rep("ab:", 66000), rep("1.1.", 50000), rep(`\n`, 100000), B + rep("\n", 199969),
		B + rep("\n"+rep("A", 64), 3000),
	}
	for i, h := range hostile {
		start := time.Now()
		r := sc.ScreenText(h, "strip", nil)
		if d := time.Since(start); d >= 2*time.Second {
			t.Fatalf("hostile %d took %v", i, d)
		}
		if r.Status != 200 && r.Status != 422 {
			t.Fatalf("hostile %d = %d %s", i, r.Status, r.Error)
		}
	}
}

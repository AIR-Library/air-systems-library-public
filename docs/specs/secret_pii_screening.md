# Secret & PII Screening (Detect, Refuse or Redact)

Reference contract for `saas_templates/<lang>/secret_pii_screening_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# SCREEN-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `SCREEN-01` | ordinary prose and code with no secret in it (the four clean texts in TEST VECTORS) -> {ok: true}, the text unchanged, findings [] in both modes |
| `SCREEN-02` | every key shape is found with its label and its exact span, and the four near-misses are not (vectors SCREEN-02) |
| `SCREEN-03` | a private key block is one finding that covers the whole block, with its encrypted header too; a line inside it is not reported on its own; a block cut off before its END line is found, also when it is quoted with "> " or removed in a diff, and only with 60 key characters after the header; a header with no key after it is not (vectors SCREEN-03) |
| `SCREEN-04` | a bearer token and a password inside a URL (with or without a user name) are found, and only the token or the password is the span; the word Bearer in prose, also before a full stop or a hyphenated word, a placeholder password and a URL with no password are not (vectors SCREEN-04) |
| `SCREEN-05` | key = value secrets are found in env, YAML, JSON, escaped-JSON, => and := form and in mid sentence; placeholders, values under 8 characters, plain words, a word that ends a sentence, a reference to a secret (a variable, a template, a call, a dotted name) and already redacted values are not; only A-Z is lower-cased and only 0-9 are digits (vectors SCREEN-05) |
| `SCREEN-06` | email addresses, phone numbers and social security numbers are found; a bare 10-digit number, an address followed by an underscore and an SSN with an impossible area are not (vectors SCREEN-06) |
| `SCREEN-07` | a card number needs a card network's prefix and a valid Luhn check, is found with spaces or dashes and when a short number follows it; a Luhn-valid number with no card prefix and a row of small numbers are not found (vectors SCREEN-07) |
| `SCREEN-08` | public IPv4 and global IPv6 addresses are found; private, loopback, link-local and multicast addresses, octets over 255, dotted version numbers, an address that ends in .0, clock times and MAC addresses are not (vectors SCREEN-08) |
| `SCREEN-09` | reject mode: a text with findings is {ok: false, error: "secrets_or_pii_detected", status: 422} with the findings, and the whole result holds neither the text nor any matched value; with categories ["secret"] the same text is ok with findings [] |
| `SCREEN-10` | strip mode: every finding is replaced by a [REDACTED:...] marker that names its label, and every other character is unchanged; screening that output again, in reject mode, is ok with no findings; a match that only appears once its neighbour is redacted makes strip answer 422 instead of returning the text |
| `SCREEN-11` | overlaps: the earliest start wins, then the longest span, then the earlier detector, so no character is in two findings; start and end count code points (a text with a 2-byte and a 4-byte character before the match) |
| `SCREEN-12` | mask shows nothing of a value under 16 characters and only 2 + 2 characters of a longer one; value_hash is HMAC-SHA256 with the configured key (the spec's value) and null without a key; a key under 32 bytes is refused at construction |
| `SCREEN-13` | a secret hidden behind JSON escapes, one or two layers deep, is refused in BOTH modes with encoded: true; text that only mentions an escape is accepted; strip still succeeds when the direct redaction already removed the secret; escapes left after 8 passes are refused (vectors E1-E8) |
| `SCREEN-14` | an unknown mode is 400 invalid_mode, an empty or unknown category list is 400 invalid_categories and a text over max_bytes is 413 text_too_large, all before any scan; each hostile 200,000-character input in the spec is screened in under 2 seconds |

## Contract

```text
Source: OWASP Logging Cheat Sheet and OWASP Secrets Management Cheat Sheet (rules applied, text not reproduced).
The detectors, guards and limits come from a screening module that ran in production, and from its tests.

PURPOSE:
  Find secrets (API keys, tokens, private keys, passwords in URLs and in assignments) and personal data (email
  addresses, phone numbers, card numbers, IP addresses, US social security numbers) in a text BEFORE it is
  stored, logged or shared, and either refuse the text or replace each match with a marker.

SCHEMA:
  None: the system stores nothing. A caller may store a result's findings as they are (they hold no matched value).

CONVENTIONS:
  - Names are snake_case here; each language spells them its own way (screenText, ScreenText).
  - A refusal is a RETURNED value {ok: false, error, status}, never an unhandled exception. `status` is the HTTP
    status a route serves it with. A refusal never carries `text`.
  - `start` and `end` count Unicode code points from 0; `end` is exclusive. Regex engines report offsets in their
    own unit (bytes in Go, PHP and Rust; UTF-16 units in JavaScript, Java and C#): convert before returning.
  - "ASCII lower case" maps A-Z to a-z and changes no other character, so positions stay the same. Never the
    language's own lower-case function: those also change characters outside ASCII.
  - "Missing" is the language's own absent value where the parameter can carry one (None, null, undefined, nil
    pointer, Option::None); otherwise the empty text. "Not text" is tested only where the language lets a caller
    pass another type; do not widen a parameter to an untyped value for it.

ENDPOINTS / FUNCTIONS:
  new_screener(hash_key = none, max_bytes = 1048576) -> screener
      hash_key is the server's secret for value_hash. Shorter than 32 bytes -> construction fails with
      invalid_hash_key and no screener exists (fail closed). No key -> every value_hash is null.
  screen_text(text, mode = "reject", categories = ["secret", "pii"]) -> result
      The entry point. Steps in this order; the first that answers ends the call.
      1. text is not text, or is not well-formed Unicode (an unpaired surrogate in a UTF-16 string, invalid
         UTF-8 in a byte string)                  -> {ok: false, error: "invalid_text", status: 400}
      2. mode is neither "reject" nor "strip"     -> {ok: false, error: "invalid_mode", status: 400}
      3. categories is empty, or holds anything but "secret" and "pii"
                                                  -> {ok: false, error: "invalid_categories", status: 400}
      4. UTF-8 length of text > max_bytes         -> {ok: false, error: "text_too_large", status: 413}
      5. F = scan_text(text, categories)
      6. mode "reject" and F is not empty         -> {ok: false, error: "secrets_or_pii_detected", status: 422, findings: F}
      7. out = redact_text(text, F)               (out is text when F is empty)
      8. mode "strip" and F is not empty: F2 = scan_text(out, categories). F2 is not empty (a match that only
         shows once its neighbour is gone: a guard looks at the character next to a match, and redaction
         changed it)
                                                  -> {ok: false, error: "secrets_or_pii_detected", status: 422,
                                                      findings: F followed by F2 with start: -1, end: -1}
         Strip never returns a text that reject would refuse.
      9. HIDDEN CHECK, only when out contains a backslash. R = resolve_escapes(out). H = scan_text(R.text,
         categories) when R.text differs from out, each finding changed to encoded: true, start: -1, end: -1.
         When R.unresolved, H also gets {category: "secret", label: "unresolved_escape", start: -1, end: -1,
         preview: "***", value_hash: null, encoded: true}, whatever the categories (what it hides is unknown).
         H not empty -> {ok: false, error: "secrets_or_pii_detected", status: 422, findings: F followed by H},
         in BOTH modes: what an escape hides has no position in the text, so it cannot be cut out, and storing
         the text would store the secret.
      10. -> {ok: true, status: 200, text: out, findings: F}
  scan_text(text, categories = ["secret", "pii"]) -> [finding], ordered by start
      Only the detectors whose category is in categories take part, so a personal-data match can never hide
      a secret that overlaps it when only secrets are asked for.
      finding = {category: "secret" | "pii", label, start, end, preview, value_hash, encoded: false}
      preview = mask(matched text). value_hash = lower-case hex of HMAC-SHA256(hash_key, UTF-8 of the matched
      text), or null without a key.
  redact_text(text, findings) -> the text with each finding's span replaced by "[REDACTED:" + label + "]",
      built in ONE left-to-right pass (never by rebuilding the whole string once per finding).
  mask(value) -> n = its number of code points. n < 16: "*" repeated n times. Otherwise its first 2 characters,
      "*" repeated n - 4 times, its last 2 characters.
  resolve_escapes(text) -> {text, unresolved}      (see ESCAPES)

MATCHING (the same procedure in every language):
  Core regexes use only literal characters, \r \n \t, escaped punctuation, [classes] with explicit ASCII ranges,
  ? * + {m,n} {m,} with counts of at most 500, (?:...), at most one capture group, and |. They never use \b \w \d \s,
  look-around, back-references or flags, and never a group repeated without an upper count ((?:...)* or
  (?:...)+): java.util.regex recurses once per round and PCRE counts each round against its limits. So a
  backtracking engine and an RE2-style engine (Go, Rust) return the same leftmost match. Compile them with no flags: no ignore-case, no multiline, no Unicode classes.
  find_all(detector, text): pos = 0, then repeat: m = the leftmost match of the core regex starting at or after
  pos; none -> stop. When the detector's guard and check accept m, m is a candidate (its span is m, or capture
  group 1 where the detector says "span: group 1") and pos = the end of m. Otherwise pos = the start of m + 1.
  "before" is the character just before m and "after" the character just after m. At either end of the text
  there is none, and none passes every guard. W = [A-Za-z0-9_]. "not W" = none, or a character outside W.

DETECTORS (the number is the priority when two candidates have the same span):
   1 pem_private_key (secret)
       regex: -----BEGIN (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----(?:\r?\nProc-Type: 4,ENCRYPTED\r?\nDEK-Info: [A-Z0-9-]{1,32},[0-9A-Fa-f]{1,64}\r?\n)?[^-]*-----END (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----
   2 pem_private_key (secret): a block cut off before its END line. Found by hand, like detector 10: a regex
       that repeats a group here overflows the stack of java.util.regex at about 2,000 characters and hits
       PCRE's limits in PHP.
       header regex: -----BEGIN (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----
       pos = 0, then repeat: h = the leftmost header match at or after pos; none -> stop.
       p = the end of h, count = 0, end = none. Then repeat:
         q = p. Move q forward while the text at q is a space, a tab, CR, LF, ">" or "-" (1 character each),
         the two characters backslash n, or the four characters backslash r backslash n. (">" and "-" are
         there for a key quoted in a mail or removed in a diff.)
         r = the end of the run of [A-Za-z0-9+/=] characters that starts at q.
         r - q < 16 -> leave this loop. Otherwise count = count + (r - q), end = r, p = r.
       count >= 60 -> a candidate: the span is the start of h to end, and pos = end.
       Otherwise pos = the start of h + 1.
       Only the characters of the runs are counted, never the n or r of an escaped line break.
   3 openai_style_api_key (secret)
       regex: sk-[A-Za-z0-9_-]{15,499}[A-Za-z0-9_]        guard: before is not W
       check: the match holds a digit 0-9   (without it every hyphenated CSS class that starts with sk- is a key)
   4 stripe_style_api_key (secret)
       regex: [spr]k_(?:live|test)_[A-Za-z0-9]{16,500}        guard: before is not W, after is not W
   5 aws_access_key_id (secret)
       regex: A[KS]IA[0-9A-Z]{16}        guard: before is not W, after is not W
   6 github_token (secret)
       regex: gh[pousr]_[A-Za-z0-9]{20,500}|github_pat_[A-Za-z0-9_]{20,500}
       guard: before is not W, after is not W
   7 slack_token (secret)
       regex: xox[abprs]-[A-Za-z0-9-]{9,499}[A-Za-z0-9]        guard: before is not W, after is not W
   8 google_api_key (secret)
       regex: AIza[0-9A-Za-z_-]{35}        guard: before is not W, after is not W and is not "-"
   9 webhook_signing_secret (secret)
       regex: whsec_[A-Za-z0-9+/=]{16,500}        guard: before is not W
  10 jwt (secret): found by hand, so it is linear for any input. S = [A-Za-z0-9_-]. pos = 0, then repeat: i = the
       next "eyJ" at or after pos; none -> stop. before is in W -> pos = i + 1. Otherwise j = the end of the run
       of S characters that starts at i, and pos = j. It is a candidate when j - i >= 8, the character at j is
       ".", a run of at least 5 S characters follows, then ".", then a run of at least 5 S characters ending at
       e: the span is i to e and pos = e.
  11 bearer_token (secret)
       regex: [Bb][Ee][Aa][Rr][Ee][Rr][ \t]+([A-Za-z0-9._~+/=-]{10,})
       span: group 1        guard: before is not W
       check: group 1 holds a digit 0-9, or at least 2 places where a letter a-z is directly followed by a
         letter A-Z. (Not looks_like_secret: the class itself holds . ~ + / = -, so the full stop of a
         sentence would make any word a token.)
  12 url_credentials (secret): the password of scheme://user:password@host (the user may be empty)
       regex: [A-Za-z][A-Za-z0-9+.-]{0,30}://[^/ \t\r\n:@]*:([^@ \t\r\n/]+)@
       span: group 1        check: group 1 does not start with "[REDACTED:" and its ASCII lower case is not a PLACEHOLDER
  13 generic_key_value_assignment (secret): matched on LOWER, the ASCII lower case of the text
       regex: (?:api[_-]?key|apikey|secret(?:[_-]?key)?|password|passwd|pwd|access[_-]?key|auth[_-]?token|private[_-]?key|credentials?|token)(?:\\?["'])?[ \t]*(?::=|=>|[:=])[ \t]*(?:\\?["'])?
       guard: the run of [a-z0-9_.-] characters just before m in LOWER is at most 40 long
       value: starts at the end of m and takes characters of the ORIGINAL text until one of: space, tab, LF, CR,
         FF, VT, ' " ; or a backslash whose next character is one of space, tab, LF, CR, FF, VT, ' "
         (a backslash at the very end of the text is taken)
       check, in this order: the value does not start with "[REDACTED:" (test this first, before measuring the
         value); it has at least 8 code points; then V = the value without the characters . , ; : ! ? at its
         end (they end a sentence; the span still covers them): the ASCII lower case of V is not a
         PLACEHOLDER, V is not a REFERENCE (below), and looks_like_secret(V)
       span: the value. After a candidate pos = the end of the value; otherwise pos = the start of m + 1.
  14 email_address (pii)
       regex: [A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}
       guard: before is not W, after is not W, and the match is not the user part of a URL: let k be the nearest
         position before m that holds "/", "@", space, tab, CR or LF; the guard fails when the three characters
         ending at k are "://"
  15 phone_number (pii)
       regex: (?:\+?1[-. ]?)?\(?[0-9]{3}\)?[-. ][0-9]{3}[-. ][0-9]{4}|\+[1-9][0-9]{7,14}
       guard: before is not a digit 0-9, after is not a digit 0-9
  16 credit_card_number (pii)
       regex: [0-9](?:[ -]?[0-9]){12,18}        guard: before is not W
       span: the LONGEST prefix of m that (a) holds 13 to 19 digits, (b) ends at the end of m with after not W, or
         ends just before a space or "-" inside m, (c) is grouped like a card: split the prefix at its spaces
         and "-"; every group but the last has at least 4 digits, and (d) whose digits start with a card network
         prefix (CARD PREFIX below) and pass the Luhn check. No such prefix -> not a candidate. pos = the end
         of the prefix. (Test the CARD PREFIX once, first: it is the same for every prefix of m.)
  17 ssn (pii)
       regex: [0-9]{3}-[0-9]{2}-[0-9]{4}        guard: before is not W and not "-", after is not W and not "-"
       check: the first group is not 000, not 666 and does not start with 9; the second is not 00; the third is not 0000
  18 ip_address (pii): IPv4
       regex: [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}
       guard: before is not W and not "."; after is not W; and not (after is "." and the character after that is a digit)
       check: no number is over 255 or has a leading zero ("0" alone is fine), and the address is public: the first
         number is not 0, 10 or 127 and is under 224, the address is not in 169.254.x.x, 172.16-31.x.x or
         192.168.x.x, and the last number is not 0 (x.y.z.0 is a network or a version, not a host)
  19 ip_address (pii): IPv6
       regex: [0-9A-Fa-f:]{2,39}
       guard: before is none or not one of W, ":" and "."; after is none or not one of W and ":"
       check: "::" appears at most once and ":::" never. With "::": the groups left and right of it, split on ":",
         are at most 7 in all. Without: exactly 8 groups. Every group is 1 to 4 hex digits. The first group (0 when
         the text starts with "::") is between 0x2000 and 0x3fff: only global addresses count.

  COMBINING: collect every detector's candidates; sort by start ascending, then longer span first, then detector
  number ascending; walk the list and keep a candidate when its start >= the end of the last one kept.

  looks_like_secret(v): v has a digit 0-9; or a character below U+0080 that is not in [A-Za-z0-9]; or at least 2
    places where a letter a-z is directly followed by a letter A-Z. (A character at or above U+0080 passes none
    of the three tests.)
  REFERENCE(V): V says where a secret comes from and is not one. A NAME is a letter A-Z a-z or "_" followed by
    any number of letters, digits 0-9 and "_". V is a REFERENCE when:
      it starts with one of $ < { % *  (a variable, a template, a mask); or
      it holds a "(" or a "[", and what stands before the first of them, split at ".", is NAMEs only
        (a call or an index: os.getenv( , Optional[ ); or
      it holds a ".", holds no digit 0-9, and split at "." is NAMEs only  (a dotted name: settings.SECRET_KEY).
    Written as loops, not as a regex (see MATCHING). A real secret of one of these shapes is missed: about 1 in
    10 random 16-character passwords. That is the price of not refusing ordinary code.
  PLACEHOLDERS: changeme change_me your_key_here your-key-here xxx xxxx xxxxx redacted todo example placeholder
    secret password insert_key_here none null n/a na <your-password> <your-key> fillmein
  CARD PREFIX, on the digits: ^(?:4|5[1-5]|2(?:22[1-9]|2[3-9][0-9]|[3-6][0-9][0-9]|7[01][0-9]|720)|3[47]|6(?:011|5[0-9][0-9]|4[4-9][0-9])|3(?:0[0-5]|[68][0-9])|35[0-9][0-9])
  Luhn: from the last digit leftwards, double every second digit (subtract 9 when over 9); the sum is a multiple of 10.

ESCAPES:
  An ESCAPE is \uXXXX (X a hex digit, either case) or a backslash followed by one of " \ / b f n r t.
  One pass, left to right, replaces every ESCAPE: \uXXXX by the character U+XXXX; a high surrogate (D800-DBFF)
  directly followed by a low surrogate escape (DC00-DFFF) by the one character the pair encodes; any other
  surrogate by U+FFFD; \" \\ \/ by " \ /; \b \f \n \r \t by U+0008 U+000C U+000A U+000D U+0009. A backslash
  followed by anything else stays. resolve_escapes repeats the pass while the text holds an ESCAPE, at most 8
  times. unresolved = the text still holds an ESCAPE after the 8th pass.

IMPLEMENTATION -- RULES:
  - Screen DECODED values where you can (each string of a parsed JSON body, each form field), not the serialized
    document. The hidden check is the safety net for text that arrives already serialized.
  - "reject" is the default mode: silent stripping hides the loss from the person who sent the text.
  - Fail closed: anything raised inside a detector or the hidden check (an engine limit, a stack overflow, any
    exception) is {ok: false, error: "screening_failed", status: 500}, in both modes: never "nothing found" and
    never an unhandled exception. Java: catch StackOverflowError too.
  - Never log the text, a matched value or the hash key. Logs may carry labels, counts and positions.
  - Every regex above is bounded or delimited so the scan is linear in the text length. Keep it that way:
    detectors 2, 10 and 13 are procedures on purpose, and detector 13's "[REDACTED:" test comes before the
    value scan.
  - Test files and fixtures build key-shaped values from two or more string pieces at run time, exactly as the
    vectors below are written with "+", so a repository secret scanner never blocks a commit.
  - The system finds what its detectors describe and nothing else. It is one layer, not a guarantee.

PRIMITIVES (standard library unless a package is named):
  regex            Python re | JavaScript, TypeScript RegExp (no u, no i flag) | Java java.util.regex | C#
                   System.Text.RegularExpressions (RegexOptions.CultureInvariant) | PHP preg_* (no u, no i
                   modifier) | Go regexp | Rust regex crate (already on the runner's list)
  HMAC-SHA256      Python hmac + hashlib | JavaScript, TypeScript node:crypto createHmac | Java javax.crypto.Mac
                   "HmacSHA256" | C# System.Security.Cryptography.HMACSHA256 | PHP hash_hmac | Go crypto/hmac +
                   crypto/sha256 | Rust hmac + sha2 crates (on the runner's list)
  code points      PHP: preg_match_all('/./us') or iconv_strlen (do not require mbstring) | C#: count UTF-16 units
                   that are not low surrogates | Go utf8.RuneCountInString | Rust chars().count()
  well-formed text Python: text.encode("utf-8") raises | JavaScript, TypeScript text.isWellFormed() | Java, C#:
                   a loop that pairs surrogates | PHP preg_match('//u', text) === 1 | Go utf8.ValidString |
                   Rust: a &str is always well-formed

TEST VECTORS (every language asserts these exact results). "+" joins pieces; * repeats a string. In a string,
\n is a line feed, \\ one backslash, \" a double quote, \u00e9 and \U0001F600 those code points. "a-b" after
a label is start-end.
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
  SCREEN-01, all four -> nothing, in both modes:
    "User: let's plan the export feature.\nAssistant: I built the CSV export button and will add a progress bar.\n"
    "def get_cache_key(user_id):\n    return f'user:{user_id}'\n\nclass TokenBucket:\n    def __init__(self, capacity):\n        self.capacity = capacity\n"
    "Please reset your password before the next login."
    "version 1.2.3.4.5 released at 12:30:45 on 2026-11-10, build 20261110123045, order 1234567890"
  SCREEN-02:
    "here is my key: " + K1  ->  openai_style_api_key 16-43
    "STRIPE_KEY=" + K2  ->  stripe_style_api_key 11-43
    K3 + " used in the demo"  ->  stripe_style_api_key 0-32
    "AWS_ACCESS_KEY_ID=" + K4  ->  aws_access_key_id 18-38
    "token: " + K5  ->  github_token 7-47
    "use " + K6 + " now"  ->  github_token 4-62
    K7  ->  slack_token 0-40
    "key=" + K8 + "&x=1"  ->  google_api_key 4-43
    "secret " + K9 + "."  ->  webhook_signing_secret 7-45
    "Authorization token captured: " + J  ->  jwt 30-162
    "ASIA" + "IOSFODNN7EXAMPLE"  ->  aws_access_key_id 0-20
    "task-" + "abcdEFGH12345678ijklMNOP"  ->  nothing
    "X" + K4  ->  nothing
    K2 + "_x"  ->  nothing
    "class sk-spinner-three-bounce is used"  ->  nothing
  SCREEN-03:
    "a " + P1 + " b"  ->  pem_private_key 2-192
    P2  ->  pem_private_key 0-205
    P3  ->  pem_private_key 0-112
    "api_key=looksLikeASecretButItsJustPemBase64Content"  ->  generic_key_value_assignment 8-50
    "x " + P4  ->  pem_private_key 2-162
    "-" + B + "\n-" + L1 + "\n-" + L2 + "\n-" + E  ->  pem_private_key 1-163
    "> " + B + "\n> " + L1 + "\n> " + L2 + "\n> " + E  ->  pem_private_key 2-198
    G  ->  pem_private_key 0-227
    B + "\n" + "A" * 30 + "\\n" + "A" * 30  ->  pem_private_key 0-94
    B + "\n" + "A" * 29 + "\\n" + "A" * 30  ->  nothing
    B + "\n" + "A" * 59  ->  nothing
    "Look for the line " + B + " in the file."  ->  nothing
  SCREEN-04:
    "curl -H 'Authorization: Bearer abc123DEF456ghi789JKL'"  ->  bearer_token 31-52
    "authorization: BEARER abc123DEF456ghi789JKL"  ->  bearer_token 22-43
    "Bearer authentication is required"  ->  nothing
    "Bearer " + J  ->  jwt 7-139
    "postgres://app:S3cr3t-Pa55@db.internal:5432/app"  ->  url_credentials 15-26
    "ssh://git:hunter2secret@host/repo"  ->  url_credentials 10-23
    "https://user:password@example.com/"  ->  nothing
    "https://jane@example.com/x"  ->  nothing
    "redis://:Sup3rS3cretValue@cache.example.com:6379/0"  ->  url_credentials 9-25
    "http://localhost:8080/@foo and https://example.com/a:b@c"  ->  nothing
    "Our API uses Bearer authentication."  ->  nothing
    "Send the header with bearer token-based auth"  ->  nothing
  SCREEN-05:
    "DB_PASSWORD=Sup3rS3cretValue!\n"  ->  generic_key_value_assignment 12-29
    "internal_api_key: \"zx91-nq7f-88ab-lorem\""  ->  generic_key_value_assignment 19-39
    "{\"password\": \"hunter2hunter2\"}"  ->  generic_key_value_assignment 14-28
    "{\\\"password\\\":\\\"hunter2hunter2\\\"}"  ->  generic_key_value_assignment 16-30
    "db_password: CorrectHorseBatteryStaple"  ->  generic_key_value_assignment 13-38
    "the db_password: CorrectHorseBatteryStaple9 I mentioned"  ->  generic_key_value_assignment 17-43
    "password: DOMAIN\\Administrator1"  ->  generic_key_value_assignment 10-31
    "API_KEY = 'Zx91Nq7f88ab'"  ->  generic_key_value_assignment 11-23
    "token=abc12345;next"  ->  generic_key_value_assignment 6-14
    "password: p\u00e4ssw\u00f6rd123"  ->  generic_key_value_assignment 10-21
    "a" * 40 + "token=abc12345def"  ->  generic_key_value_assignment 46-57
    "a" * 41 + "token=abc12345def"  ->  nothing
    "API_KEY=your_key_here"  ->  nothing
    "password: changeme"  ->  nothing
    "pwd=abc123"  ->  nothing
    "Secret: whatever the team decides"  ->  nothing
    "password: WordPress"  ->  nothing
    "My favorite crypto token: Ethereum has been volatile"  ->  nothing
    "class TokenBucket:"  ->  nothing
    "Please reset your password before the next login."  ->  nothing
    "secrets: abc12345def"  ->  nothing
    "password: gr\u00f6\u00dferes"  ->  nothing
    "password: [REDACTED:generic_key_value_assignment]"  ->  nothing
    "'password' => 'Sup3rS3cretValue!',"  ->  generic_key_value_assignment 15-32
    "password := \"Sup3rS3cretValue!\""  ->  generic_key_value_assignment 13-30
    "password: hunter2!"  ->  generic_key_value_assignment 10-18
    "password: P@ss(w0rd)1x"  ->  generic_key_value_assignment 10-22
    "token: ab12.cd34.ef56gh78"  ->  generic_key_value_assignment 7-25
    "\u0130 token=abc12345"  ->  generic_key_value_assignment 8-16
    "The password: required."  ->  nothing
    "token: optional,"  ->  nothing
    "password: changeme."  ->  nothing
    "password: undefined,"  ->  nothing
    "password = os.getenv(\"DB_PASSWORD\")"  ->  nothing
    "api_key = os.environ[\"API_KEY\"]"  ->  nothing
    "secret_key = settings.SECRET_KEY"  ->  nothing
    "apiKey: process.env.STRIPE_KEY,"  ->  nothing
    "token = getAccessTokenSilently();"  ->  nothing
    "password: req.body.password,"  ->  nothing
    "API_KEY=$API_KEY"  ->  nothing
    "token=${TOKEN}"  ->  nothing
    "api_key: <YOUR_API_KEY>"  ->  nothing
    "Password: ********"  ->  nothing
    "token: Optional[str] = None"  ->  nothing
    "password = models.CharField(max_length=128)"  ->  nothing
    "to\u212aen=abc12345def"  ->  nothing
    "password: abcdefgh\u0663"  ->  nothing
  SCREEN-06:
    "Contact jane@example.com or call 555-123-4567 for help."  ->  email_address 8-24, phone_number 33-45
    "<jane.doe+tag@mail.example.co.uk>"  ->  email_address 1-32
    "see https://example.com/contact?email=jane@example.com"  ->  email_address 38-54
    "call (555) 123-4567 now"  ->  phone_number 5-19
    "+1 555-123-4567"  ->  phone_number 0-15
    "reach me at +442071838750."  ->  phone_number 12-25
    "SSN 123-45-6789"  ->  ssn 4-15
    "order 5551234567 shipped"  ->  nothing
    "jane@example.com_backup"  ->  nothing
    "user@localhost and a@b"  ->  nothing
    "SSN 000-12-3456, 666-12-3456, 900-12-3456, 123-00-4567, 123-45-0000"  ->  nothing
  SCREEN-07:
    "card 4242 4242 4242 4242 exp 12/27"  ->  credit_card_number 5-24
    "5555-5555-5555-4444"  ->  credit_card_number 0-19
    "378282246310005"  ->  credit_card_number 0-15
    "card 4242 4242 4242 4242 123"  ->  credit_card_number 5-24
    "4242 4242 4242 4242 1234 5678"  ->  credit_card_number 0-19
    "4242 4242 4242 4241"  ->  nothing
    "1234 5678 1234 5670"  ->  nothing
    "ts 1700000000000 ms"  ->  nothing
    "42424242424242424242424"  ->  nothing
    "x4242424242424242"  ->  nothing
    "4242424242424242x"  ->  nothing
    "3782 822463 10005"  ->  credit_card_number 0-17
    "card 4222 2222 2222 2 end"  ->  credit_card_number 5-21
    "2 2 6 14 8 15 20 6 13"  ->  nothing
    "4 8 15 16 23 42 4 8 15 16 23 42 108"  ->  nothing
  SCREEN-08:
    "client 203.0.113.7 connected"  ->  ip_address 7-18
    "from 198.51.100.24."  ->  ip_address 5-18
    "addr 2001:db8::8a2e:370:7334 ok"  ->  ip_address 5-28
    "[2001:0db8:0000:0000:0000:ff00:0042:8329]"  ->  ip_address 1-40
    "8.8.8.8 and 172.32.0.1 and 2606:4700:4700::1111"  ->  ip_address 0-7, ip_address 12-22, ip_address 27-47
    "127.0.0.1 10.0.0.5 192.168.1.1 172.16.0.1 169.254.1.1 0.0.0.0 224.0.0.1 255.255.255.255"  ->  nothing
    "999.1.1.1 and 256.1.1.1 and 08.8.8.8"  ->  nothing
    "1.2.3.4.5 and v8.8.8.8"  ->  nothing
    "12:30:45 and aa:bb:cc:dd:ee:ff"  ->  nothing
    "::1 and fe80::1 and fc00::1"  ->  nothing
    "db::add(x) and dead::beef"  ->  nothing
    "Version=1.0.0.0, Culture=neutral"  ->  nothing
  SCREEN-09, SCREEN-10 and SCREEN-12, with hash_key = the 32 bytes 00 01 02 ... 1f and
  T = "Contact jane@example.com or call 555-123-4567 for help.":
    reject -> {ok: false, error: "secrets_or_pii_detected", status: 422, findings: the two below}; no `text`
    reject with categories ["secret"] -> {ok: true, status: 200, text: T, findings: []}
    strip with categories ["pii"] -> the strip answer below
      {"category": "pii", "label": "email_address", "start": 8, "end": 24, "preview": "ja************om", "value_hash": "9487588974759d303d5d44401791a603ad85fda9276d43f7436077d709d9da10", "encoded": false}
      {"category": "pii", "label": "phone_number", "start": 33, "end": 45, "preview": "************", "value_hash": "ee171612a2f4984e73ec9377b4d10f2b76125f5adf8e4315f12e77ebb2cd41c3", "encoded": false}
    strip  -> {ok: true, status: 200, text: "Contact [REDACTED:email_address] or call [REDACTED:phone_number] for help.",
               findings: the same two}
    mask("a" * 15) = "*" * 15; mask("abcdefghijklmnop") = "ab************op"; mask(K1) = "sk" + "*" * 23 + "OP"
    SCREEN-10 also strips every vector above that has a finding and screens the output again: ok, findings [].
    "jane@example.com555-123-4567" in strip mode -> 422 secrets_or_pii_detected, findings phone_number 16-28
    and then email_address with start -1, end -1 (the address only becomes a match once the number is gone).
  SCREEN-11:
    "\u00e9\U0001F600 a@b.co"  ->  email_address 3-9
    "token=" + K1  ->  openai_style_api_key 6-33
    "Bearer " + K1  ->  openai_style_api_key 7-34
  SCREEN-13, the texts as their exact characters (not string literals); "encoded" = encoded: true, start -1, end -1:
    E1 = {"note": "sk\u002dabcdEFGH12345678ijklMNOP"}
        reject: 422, openai_style_api_key encoded
        strip: 422, openai_style_api_key encoded
    E2 = {"outer": "{\"k\": \"sk\\u002dabcdEFGH12345678ijklMNOP\"}"}
        reject: 422, openai_style_api_key encoded
        strip: 422, openai_style_api_key encoded
    E3 = {"msg": "the escape \u00e9 prints an e-acute and \n is a newline"}
        reject: ok, findings [], text unchanged
        strip: ok, findings [], text unchanged
    E4 = {"contact": "jane\u0040example.com"}
        reject: 422, email_address encoded
        strip: 422, email_address encoded
    E5 = {"emoji": "\ud83d\ude00 ok", "path": "C:\\Users\\name\\notes.txt"}
        reject: ok, findings [], text unchanged
        strip: ok, findings [], text unchanged
    E6 = {"key": "<P1 with each line feed written as the two characters \n>"}
        reject: 422, pem_private_key 9-202
        strip: ok, text {"key": "[REDACTED:pem_private_key]"}
    E7 = {"key": "<P2 with each line feed written as the two characters \n>"}
        reject: 422, pem_private_key encoded
        strip: 422, pem_private_key encoded
    E8 = 600 backslashes followed by the letter n
        reject: 422, unresolved_escape encoded
        strip: 422, unresolved_escape encoded
  Note (2026-11-10, found by the Python and TypeScript implementers): detector 13 followed literally is
  quadratic on "token=$" * 28571 (18 s). Compute where each value ends once (a lookup table) and run the
  instant refusals first; the answers must not change, only the time. That input is now in SCREEN-14.
  SCREEN-14: screen_text("x", "mask") -> 400 invalid_mode. categories [] and ["secret", "keys"] -> 400
    invalid_categories. With max_bytes = 9, "\u00e9" * 5 (10 bytes) -> 413
    text_too_large; with max_bytes = 10 it is ok. Each of these, in strip mode, returns in under 2 seconds:
    "a." * 100000, ("-----BEGIN " + "PRIVATE KEY-----") * 7400, "1234-" * 40000, "eyJ" * 66666, "xeyJ-" * 40000,
    "xsk-" * 50000, "password" + " " * 199990, "token=[REDACTED:" * 12500, "token=$" * 28571, "a://b:" * 33000, "ab:" * 66000,
    "1.1." * 50000, "\\n" * 100000, B + "\n" * 199969, B + ("\n" + "A" * 64) * 3000
    Extra, not a required id (a Rust &str cannot hold such a text): where the language can build it, an
    unpaired surrogate (JavaScript, TypeScript, Java, C#, Python) or the byte FF (PHP, Go) is 400 invalid_text.

TESTS:
  - **SCREEN-01** ordinary prose and code with no secret in it (the four clean texts in TEST VECTORS) -> {ok: true}, the text unchanged, findings [] in both modes
  - **SCREEN-02** every key shape is found with its label and its exact span, and the four near-misses are not (vectors SCREEN-02)
  - **SCREEN-03** a private key block is one finding that covers the whole block, with its encrypted header too; a line inside it is not reported on its own; a block cut off before its END line is found, also when it is quoted with "> " or removed in a diff, and only with 60 key characters after the header; a header with no key after it is not (vectors SCREEN-03)
  - **SCREEN-04** a bearer token and a password inside a URL (with or without a user name) are found, and only the token or the password is the span; the word Bearer in prose, also before a full stop or a hyphenated word, a placeholder password and a URL with no password are not (vectors SCREEN-04)
  - **SCREEN-05** key = value secrets are found in env, YAML, JSON, escaped-JSON, => and := form and in mid sentence; placeholders, values under 8 characters, plain words, a word that ends a sentence, a reference to a secret (a variable, a template, a call, a dotted name) and already redacted values are not; only A-Z is lower-cased and only 0-9 are digits (vectors SCREEN-05)
  - **SCREEN-06** email addresses, phone numbers and social security numbers are found; a bare 10-digit number, an address followed by an underscore and an SSN with an impossible area are not (vectors SCREEN-06)
  - **SCREEN-07** a card number needs a card network's prefix and a valid Luhn check, is found with spaces or dashes and when a short number follows it; a Luhn-valid number with no card prefix and a row of small numbers are not found (vectors SCREEN-07)
  - **SCREEN-08** public IPv4 and global IPv6 addresses are found; private, loopback, link-local and multicast addresses, octets over 255, dotted version numbers, an address that ends in .0, clock times and MAC addresses are not (vectors SCREEN-08)
  - **SCREEN-09** reject mode: a text with findings is {ok: false, error: "secrets_or_pii_detected", status: 422} with the findings, and the whole result holds neither the text nor any matched value; with categories ["secret"] the same text is ok with findings []
  - **SCREEN-10** strip mode: every finding is replaced by a [REDACTED:...] marker that names its label, and every other character is unchanged; screening that output again, in reject mode, is ok with no findings; a match that only appears once its neighbour is redacted makes strip answer 422 instead of returning the text
  - **SCREEN-11** overlaps: the earliest start wins, then the longest span, then the earlier detector, so no character is in two findings; start and end count code points (a text with a 2-byte and a 4-byte character before the match)
  - **SCREEN-12** mask shows nothing of a value under 16 characters and only 2 + 2 characters of a longer one; value_hash is HMAC-SHA256 with the configured key (the spec's value) and null without a key; a key under 32 bytes is refused at construction
  - **SCREEN-13** a secret hidden behind JSON escapes, one or two layers deep, is refused in BOTH modes with encoded: true; text that only mentions an escape is accepted; strip still succeeds when the direct redaction already removed the secret; escapes left after 8 passes are refused (vectors E1-E8)
  - **SCREEN-14** an unknown mode is 400 invalid_mode, an empty or unknown category list is 400 invalid_categories and a text over max_bytes is 413 text_too_large, all before any scan; each hostile 200,000-character input in the spec is screened in under 2 seconds
```

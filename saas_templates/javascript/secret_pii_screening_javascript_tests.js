'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { newScreener, ScreeningError, mask, resolveEscapes } = require('./secret_pii_screening_javascript.js');

/*
 * Tests for docs/specs/secret_pii_screening.md (SCREEN-01..SCREEN-14), using the spec's TEST VECTORS verbatim.
 * Key-shaped values are built from two or more pieces at run time, exactly as the spec writes them with "+", so a
 * repository secret scanner never blocks a commit. Why: Phase D wave 1, owner request 2026-11-10.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
 */

const K1 = 'sk-' + 'abcdEFGH12345678ijklMNOP';
const K2 = 'sk_' + 'live_' + 'A1b2C3d4E5f6G7h8I9j0K1l2';
const K3 = 'pk_' + 'test_' + 'A1b2C3d4E5f6G7h8I9j0K1l2';
const K4 = 'AKIA' + 'IOSFODNN7EXAMPLE';
const K5 = 'ghp_' + '16C7e42F292c6912E7710c838347Ae178B4a';
const K6 = 'github_pat_' + '11ABCDEFG0abcdefghij_KLMNOPQRSTUVWXYZ0123456789';
const K7 = 'xoxb-' + '1234567890-abcdefghijklmnopqrstuvwx';
const K8 = 'AIza' + 'SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q';
const K9 = 'whsec_' + 'MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw';
const J = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' + '.' + 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0' + '.' +
  'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
const B = '-----BEGIN RSA ' + 'PRIVATE KEY-----';
const E = '-----END RSA ' + 'PRIVATE KEY-----';
const L1 = 'MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumga0R2LiajO16aI4Uxa2b9nb';
const L2 = 'AKELFOxNOFICTIONALKEYMATERIALFORTESTINGPURPOSESONLY1234567890AB';
const P1 = B + '\n' + L1 + '\n' + L2 + '\n' + E;
const P2 = B + '\n' + 'Proc-Type: 4,ENCRYPTED\n' + 'DEK-Info: AES-256-CBC,A1B2C3D4E5F60718293A4B5C6D7E8F90\n' + '\n' + L1 + '\n' + E;
const P3 = B + '\n' + 'api_key=looksLikeASecretButItsJustPemBase64Content\n' + E;
const P4 = B + '\n' + L1 + '\n' + L2 + ' (cut';
const G = '-----BEGIN PGP ' + 'PRIVATE KEY BLOCK-----' + '\nVersion: GnuPG v2\n\n' + L1 + '\n' + L2 + '\n=AbCd\n' +
  '-----END PGP ' + 'PRIVATE KEY BLOCK-----';
const HASH_KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const T = 'Contact jane@example.com or call 555-123-4567 for help.';

const CLEAN = [
  "User: let's plan the export feature.\nAssistant: I built the CSV export button and will add a progress bar.\n",
  "def get_cache_key(user_id):\n    return f'user:{user_id}'\n\nclass TokenBucket:\n    def __init__(self, capacity):\n        self.capacity = capacity\n",
  'Please reset your password before the next login.',
  'version 1.2.3.4.5 released at 12:30:45 on 2026-11-10, build 20261110123045, order 1234567890'
];

const V02 = [
  ['here is my key: ' + K1, [['openai_style_api_key', 16, 43]]],
  ['STRIPE_KEY=' + K2, [['stripe_style_api_key', 11, 43]]],
  [K3 + ' used in the demo', [['stripe_style_api_key', 0, 32]]],
  ['AWS_ACCESS_KEY_ID=' + K4, [['aws_access_key_id', 18, 38]]],
  ['token: ' + K5, [['github_token', 7, 47]]],
  ['use ' + K6 + ' now', [['github_token', 4, 62]]],
  [K7, [['slack_token', 0, 40]]],
  ['key=' + K8 + '&x=1', [['google_api_key', 4, 43]]],
  ['secret ' + K9 + '.', [['webhook_signing_secret', 7, 45]]],
  ['Authorization token captured: ' + J, [['jwt', 30, 162]]],
  ['ASIA' + 'IOSFODNN7EXAMPLE', [['aws_access_key_id', 0, 20]]],
  ['task-' + 'abcdEFGH12345678ijklMNOP', []],
  ['X' + K4, []],
  [K2 + '_x', []],
  ['class sk-spinner-three-bounce is used', []]
];

const V03 = [
  ['a ' + P1 + ' b', [['pem_private_key', 2, 192]]],
  [P2, [['pem_private_key', 0, 205]]],
  [P3, [['pem_private_key', 0, 112]]],
  ['api_key=looksLikeASecretButItsJustPemBase64Content', [['generic_key_value_assignment', 8, 50]]],
  ['x ' + P4, [['pem_private_key', 2, 162]]],
  ['-' + B + '\n-' + L1 + '\n-' + L2 + '\n-' + E, [['pem_private_key', 1, 163]]],
  ['> ' + B + '\n> ' + L1 + '\n> ' + L2 + '\n> ' + E, [['pem_private_key', 2, 198]]],
  [G, [['pem_private_key', 0, 227]]],
  [B + '\n' + 'A'.repeat(30) + '\\n' + 'A'.repeat(30), [['pem_private_key', 0, 94]]],
  [B + '\n' + 'A'.repeat(29) + '\\n' + 'A'.repeat(30), []],
  [B + '\n' + 'A'.repeat(59), []],
  ['Look for the line ' + B + ' in the file.', []]
];

const V04 = [
  ["curl -H 'Authorization: Bearer abc123DEF456ghi789JKL'", [['bearer_token', 31, 52]]],
  ['authorization: BEARER abc123DEF456ghi789JKL', [['bearer_token', 22, 43]]],
  ['Bearer authentication is required', []],
  ['Bearer ' + J, [['jwt', 7, 139]]],
  ['postgres://app:' + 'S3cr3t-Pa55@db.internal:5432/app', [['url_credentials', 15, 26]]],
  ['ssh://git:' + 'hunter2secret@host/repo', [['url_credentials', 10, 23]]],
  ['https://user:password@example.com/', []],
  ['https://jane@example.com/x', []],
  ['redis://:' + 'Sup3rS3cretValue@cache.example.com:6379/0', [['url_credentials', 9, 25]]],
  ['http://localhost:8080/@foo and https://example.com/a:b@c', []],
  ['Our API uses Bearer authentication.', []],
  ['Send the header with bearer token-based auth', []]
];

const GK = 'generic_key_value_assignment';
const V05 = [
  ['DB_PASSWORD=Sup3rS3cretValue!\n', [[GK, 12, 29]]],
  ['internal_api_key: "zx91-nq7f-88ab-lorem"', [[GK, 19, 39]]],
  ['{"password": "hunter2hunter2"}', [[GK, 14, 28]]],
  ['{\\"password\\":\\"hunter2hunter2\\"}', [[GK, 16, 30]]],
  ['db_password: CorrectHorseBatteryStaple', [[GK, 13, 38]]],
  ['the db_password: CorrectHorseBatteryStaple9 I mentioned', [[GK, 17, 43]]],
  ['password: DOMAIN\\Administrator1', [[GK, 10, 31]]],
  ["API_KEY = 'Zx91Nq7f88ab'", [[GK, 11, 23]]],
  ['token=abc12345;next', [[GK, 6, 14]]],
  ['password: p\u00e4ssw\u00f6rd123', [[GK, 10, 21]]],
  ['a'.repeat(40) + 'token=abc12345def', [[GK, 46, 57]]],
  ['a'.repeat(41) + 'token=abc12345def', []],
  ['API_KEY=your_key_here', []],
  ['password: changeme', []],
  ['pwd=abc123', []],
  ['Secret: whatever the team decides', []],
  ['password: WordPress', []],
  ['My favorite crypto token: Ethereum has been volatile', []],
  ['class TokenBucket:', []],
  ['Please reset your password before the next login.', []],
  ['secrets: abc12345def', []],
  ['password: gr\u00f6\u00dferes', []],
  ['password: [REDACTED:generic_key_value_assignment]', []],
  ["'password' => 'Sup3rS3cretValue!',", [[GK, 15, 32]]],
  ['password := "Sup3rS3cretValue!"', [[GK, 13, 30]]],
  ['password: hunter2!', [[GK, 10, 18]]],
  ['password: P@ss(w0rd)1x', [[GK, 10, 22]]],
  ['token: ab12.cd34.ef56gh78', [[GK, 7, 25]]],
  ['\u0130 token=abc12345', [[GK, 8, 16]]],
  ['The password: required.', []],
  ['token: optional,', []],
  ['password: changeme.', []],
  ['password: undefined,', []],
  ['password = os.getenv("DB_PASSWORD")', []],
  ['api_key = os.environ["API_KEY"]', []],
  ['secret_key = settings.SECRET_KEY', []],
  ['apiKey: process.env.STRIPE_KEY,', []],
  ['token = getAccessTokenSilently();', []],
  ['password: req.body.password,', []],
  ['API_KEY=$API_KEY', []],
  ['token=${TOKEN}', []],
  ['api_key: <YOUR_API_KEY>', []],
  ['Password: ********', []],
  ['token: Optional[str] = None', []],
  ['password = models.CharField(max_length=128)', []],
  ['to\u212aen=abc12345def', []],
  ['password: abcdefgh\u0663', []]
];

const V06 = [
  ['Contact jane@example.com or call 555-123-4567 for help.', [['email_address', 8, 24], ['phone_number', 33, 45]]],
  ['<jane.doe+tag@mail.example.co.uk>', [['email_address', 1, 32]]],
  ['see https://example.com/contact?email=jane@example.com', [['email_address', 38, 54]]],
  ['call (555) 123-4567 now', [['phone_number', 5, 19]]],
  ['+1 555-123-4567', [['phone_number', 0, 15]]],
  ['reach me at +442071838750.', [['phone_number', 12, 25]]],
  ['SSN 123-45-6789', [['ssn', 4, 15]]],
  ['order 5551234567 shipped', []],
  ['jane@example.com_backup', []],
  ['user@localhost and a@b', []],
  ['SSN 000-12-3456, 666-12-3456, 900-12-3456, 123-00-4567, 123-45-0000', []]
];

const CC = 'credit_card_number';
const V07 = [
  ['card 4242 4242 4242 4242 exp 12/27', [[CC, 5, 24]]],
  ['5555-5555-5555-4444', [[CC, 0, 19]]],
  ['378282246310005', [[CC, 0, 15]]],
  ['card 4242 4242 4242 4242 123', [[CC, 5, 24]]],
  ['4242 4242 4242 4242 1234 5678', [[CC, 0, 19]]],
  ['4242 4242 4242 4241', []],
  ['1234 5678 1234 5670', []],
  ['ts 1700000000000 ms', []],
  ['42424242424242424242424', []],
  ['x4242424242424242', []],
  ['4242424242424242x', []],
  ['3782 822463 10005', [[CC, 0, 17]]],
  ['card 4222 2222 2222 2 end', [[CC, 5, 21]]],
  ['2 2 6 14 8 15 20 6 13', []],
  ['4 8 15 16 23 42 4 8 15 16 23 42 108', []]
];

const IP = 'ip_address';
const V08 = [
  ['client 203.0.113.7 connected', [[IP, 7, 18]]],
  ['from 198.51.100.24.', [[IP, 5, 18]]],
  ['addr 2001:db8::8a2e:370:7334 ok', [[IP, 5, 28]]],
  ['[2001:0db8:0000:0000:0000:ff00:0042:8329]', [[IP, 1, 40]]],
  ['8.8.8.8 and 172.32.0.1 and 2606:4700:4700::1111', [[IP, 0, 7], [IP, 12, 22], [IP, 27, 47]]],
  ['127.0.0.1 10.0.0.5 192.168.1.1 172.16.0.1 169.254.1.1 0.0.0.0 224.0.0.1 255.255.255.255', []],
  ['999.1.1.1 and 256.1.1.1 and 08.8.8.8', []],
  ['1.2.3.4.5 and v8.8.8.8', []],
  ['12:30:45 and aa:bb:cc:dd:ee:ff', []],
  ['::1 and fe80::1 and fc00::1', []],
  ['db::add(x) and dead::beef', []],
  ['Version=1.0.0.0, Culture=neutral', []]
];

const V11 = [
  ['\u00e9\u{1F600} a@b.co', [['email_address', 3, 9]]],
  ['token=' + K1, [['openai_style_api_key', 6, 33]]],
  ['Bearer ' + K1, [['openai_style_api_key', 7, 34]]]
];

/**
 * Asserts scan_text(text) gives exactly the expected [label, start, end] list (category checked by label family).
 * In: screener, text, expected. Out: nothing (throws on mismatch). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches nothing.
 */
function assertScan(s, text, expected) {
  const got = s.scanText(text).map(f => [f.label, f.start, f.end]);
  assert.deepStrictEqual(got, expected, `scan of ${JSON.stringify(text.slice(0, 60))}`);
}

/**
 * Asserts every vector of a group, and that each finding's category matches its detector.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function assertGroup(vectors) {
  const s = newScreener();
  const pii = new Set(['email_address', 'phone_number', 'credit_card_number', 'ssn', 'ip_address']);
  for (const [text, expected] of vectors) {
    assertScan(s, text, expected);
    for (const f of s.scanText(text)) assert.strictEqual(f.category, pii.has(f.label) ? 'pii' : 'secret');
  }
}

/**
 * Builds the expected redaction of text from [label, start, end] code point spans, by hand, for comparison.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function expectedRedaction(text, spans) {
  const cps = Array.from(text);
  let out = '';
  let last = 0;
  for (const [label, s, e] of spans) {
    out += cps.slice(last, s).join('') + '[REDACTED:' + label + ']';
    last = e;
  }
  return out + cps.slice(last).join('');
}

/**
 * SCREEN-01: ordinary prose and code with no secret in it (the four clean texts in TEST VECTORS) -> {ok: true},
 * the text unchanged, findings [] in both modes.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: SCREEN-01, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only.
 */
// SCREEN-01
test('SCREEN-01 clean prose and code pass unchanged with no findings in both modes', () => {
  const s = newScreener();
  for (const text of CLEAN) {
    for (const mode of ['reject', 'strip']) {
      assert.deepStrictEqual(s.screenText(text, mode), { ok: true, status: 200, text, findings: [] });
    }
  }
});

/**
 * SCREEN-02: every key shape is found with its label and its exact span, and the four near-misses are not (vectors
 * SCREEN-02).
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: SCREEN-02, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only.
 */
// SCREEN-02
test('SCREEN-02 every key shape is found with its label and exact span; near-misses are not', () => {
  assertGroup(V02);
});

/**
 * SCREEN-03: a private key block is one finding that covers the whole block, with its encrypted header too; a line
 * inside it is not reported on its own; a block cut off before its END line is found, also when it is quoted with
 * "> " or removed in a diff, and only with 60 key characters after the header; a header with no key after it is
 * not (vectors SCREEN-03).
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: SCREEN-03, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only.
 */
// SCREEN-03
test('SCREEN-03 private key blocks: whole block, encrypted header, cut-off, quoted and diffed blocks', () => {
  assertGroup(V03);
});

/**
 * SCREEN-04: a bearer token and a password inside a URL (with or without a user name) are found, and only the
 * token or the password is the span; the word Bearer in prose, also before a full stop or a hyphenated word, a
 * placeholder password and a URL with no password are not (vectors SCREEN-04).
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: SCREEN-04, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only.
 */
// SCREEN-04
test('SCREEN-04 bearer tokens and URL passwords are found; prose, placeholders and no-password URLs are not', () => {
  assertGroup(V04);
});

/**
 * SCREEN-05: key = value secrets are found in env, YAML, JSON, escaped-JSON, => and := form and in mid sentence;
 * placeholders, values under 8 characters, plain words, a word that ends a sentence, a reference to a secret (a
 * variable, a template, a call, a dotted name) and already redacted values are not; only A-Z is lower-cased and
 * only 0-9 are digits (vectors SCREEN-05).
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: SCREEN-05, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only.
 */
// SCREEN-05
test('SCREEN-05 key = value secrets in every form; placeholders, short values, words and references are not', () => {
  assertGroup(V05);
});

/**
 * SCREEN-06: email addresses, phone numbers and social security numbers are found; a bare 10-digit number, an
 * address followed by an underscore and an SSN with an impossible area are not (vectors SCREEN-06).
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: SCREEN-06, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only.
 */
// SCREEN-06
test('SCREEN-06 emails, phones and SSNs are found; bare numbers, underscored addresses, bad SSNs are not', () => {
  assertGroup(V06);
});

/**
 * SCREEN-07: a card number needs a card network's prefix and a valid Luhn check, is found with spaces or dashes
 * and when a short number follows it; a Luhn-valid number with no card prefix and a row of small numbers are not
 * found (vectors SCREEN-07).
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: SCREEN-07, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only.
 */
// SCREEN-07
test('SCREEN-07 cards need a network prefix, a Luhn pass and card grouping', () => {
  assertGroup(V07);
});

/**
 * SCREEN-08: public IPv4 and global IPv6 addresses are found; private, loopback, link-local and multicast
 * addresses, octets over 255, dotted version numbers, an address that ends in .0, clock times and MAC addresses
 * are not (vectors SCREEN-08).
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: SCREEN-08, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only.
 */
// SCREEN-08
test('SCREEN-08 public IPv4 and global IPv6 are found; private, invalid, versions, times and MACs are not', () => {
  assertGroup(V08);
});

/**
 * SCREEN-09: reject mode: a text with findings is {ok: false, error: "secrets_or_pii_detected", status: 422} with
 * the findings, and the whole result holds neither the text nor any matched value; with categories ["secret"] the
 * same text is ok with findings [].
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: SCREEN-09, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only.
 */
// SCREEN-09
test('SCREEN-09 reject mode refuses with findings and holds neither the text nor a matched value', () => {
  const s = newScreener(HASH_KEY);
  const r = s.screenText(T);
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.error, 'secrets_or_pii_detected');
  assert.strictEqual(r.status, 422);
  assert.ok(!('text' in r));
  assert.deepStrictEqual(r.findings.map(f => [f.label, f.start, f.end]), [['email_address', 8, 24], ['phone_number', 33, 45]]);
  const dump = JSON.stringify(r);
  assert.ok(!dump.includes('jane@example.com'));
  assert.ok(!dump.includes('555-123-4567'));
  assert.ok(!dump.includes(T));
  assert.deepStrictEqual(s.screenText(T, 'reject', ['secret']), { ok: true, status: 200, text: T, findings: [] });
});

/**
 * SCREEN-10: strip mode: every finding is replaced by a [REDACTED:...] marker that names its label, and every
 * other character is unchanged; screening that output again, in reject mode, is ok with no findings; a match that
 * only appears once its neighbour is redacted makes strip answer 422 instead of returning the text.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: SCREEN-10, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only.
 */
// SCREEN-10
test('SCREEN-10 strip replaces each finding with its marker, leaves the rest, and the output screens clean', () => {
  const s = newScreener(HASH_KEY);
  const expectedFindings = [
    { category: 'pii', label: 'email_address', start: 8, end: 24, preview: 'ja************om', value_hash: '9487588974759d303d5d44401791a603ad85fda9276d43f7436077d709d9da10', encoded: false },
    { category: 'pii', label: 'phone_number', start: 33, end: 45, preview: '************', value_hash: 'ee171612a2f4984e73ec9377b4d10f2b76125f5adf8e4315f12e77ebb2cd41c3', encoded: false }
  ];
  const stripped = 'Contact [REDACTED:email_address] or call [REDACTED:phone_number] for help.';
  assert.deepStrictEqual(s.screenText(T, 'strip'), { ok: true, status: 200, text: stripped, findings: expectedFindings });
  assert.deepStrictEqual(s.screenText(T, 'strip', ['pii']), { ok: true, status: 200, text: stripped, findings: expectedFindings });

  const all = [V02, V03, V04, V05, V06, V07, V08, V11].flat().filter(([, exp]) => exp.length > 0);
  assert.ok(all.length > 60);
  for (const [text, expected] of all) {
    const r = s.screenText(text, 'strip');
    assert.strictEqual(r.ok, true, `strip of ${JSON.stringify(text.slice(0, 60))}: ${r.error}`);
    assert.strictEqual(r.text, expectedRedaction(text, expected));
    assert.deepStrictEqual(s.screenText(r.text, 'reject'), { ok: true, status: 200, text: r.text, findings: [] });
  }

  const r = s.screenText('jane@example.com555-123-4567', 'strip');
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.status, 422);
  assert.strictEqual(r.error, 'secrets_or_pii_detected');
  assert.ok(!('text' in r));
  assert.deepStrictEqual(r.findings.map(f => [f.label, f.start, f.end]), [['phone_number', 16, 28], ['email_address', -1, -1]]);
});

/**
 * SCREEN-11: overlaps: the earliest start wins, then the longest span, then the earlier detector, so no character
 * is in two findings; start and end count code points (a text with a 2-byte and a 4-byte character before the
 * match).
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: SCREEN-11, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only.
 */
// SCREEN-11
test('SCREEN-11 overlaps resolve by start, length, detector; offsets count code points', () => {
  assertGroup(V11);
  const s = newScreener();
  const r = s.screenText('\u00e9\u{1F600} a@b.co', 'strip');
  assert.strictEqual(r.text, '\u00e9\u{1F600} [REDACTED:email_address]');
});

/**
 * SCREEN-12: mask shows nothing of a value under 16 characters and only 2 + 2 characters of a longer one;
 * value_hash is HMAC-SHA256 with the configured key (the spec's value) and null without a key; a key under 32
 * bytes is refused at construction.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: SCREEN-12, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only.
 */
// SCREEN-12
test('SCREEN-12 mask, value_hash with and without key, short key refused', () => {
  assert.strictEqual(mask('a'.repeat(15)), '*'.repeat(15));
  assert.strictEqual(mask('abcdefghijklmnop'), 'ab************op');
  assert.strictEqual(mask(K1), 'sk' + '*'.repeat(23) + 'OP');
  const keyed = newScreener(HASH_KEY).scanText(T);
  assert.deepStrictEqual(keyed.map(f => f.value_hash), [
    '9487588974759d303d5d44401791a603ad85fda9276d43f7436077d709d9da10',
    'ee171612a2f4984e73ec9377b4d10f2b76125f5adf8e4315f12e77ebb2cd41c3'
  ]);
  assert.deepStrictEqual(keyed.map(f => f.preview), ['ja************om', '************']);
  assert.deepStrictEqual(newScreener().scanText(T).map(f => f.value_hash), [null, null]);
  assert.throws(() => newScreener(HASH_KEY.subarray(0, 31)), err => err instanceof ScreeningError && err.code === 'invalid_hash_key');
});

/**
 * Asserts a result is the 422 refusal whose findings are exactly the given labels, all encoded with no position.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function assertEncoded(r, labels) {
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.status, 422);
  assert.strictEqual(r.error, 'secrets_or_pii_detected');
  assert.ok(!('text' in r));
  assert.deepStrictEqual(r.findings.map(f => [f.label, f.start, f.end, f.encoded]), labels.map(l => [l, -1, -1, true]));
}

/**
 * SCREEN-13: a secret hidden behind JSON escapes, one or two layers deep, is refused in BOTH modes with encoded:
 * true; text that only mentions an escape is accepted; strip still succeeds when the direct redaction already
 * removed the secret; escapes left after 8 passes are refused (vectors E1-E8).
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: SCREEN-13, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only.
 */
// SCREEN-13
test('SCREEN-13 secrets behind JSON escapes are refused in both modes; mentions of escapes are not', () => {
  const s = newScreener();
  const E1 = String.raw`{"note": "sk\u002d` + 'abcdEFGH12345678ijklMNOP"}';
  const E2 = String.raw`{"outer": "{\"k\": \"sk\\u002d` + String.raw`abcdEFGH12345678ijklMNOP\"}"}`;
  const E3 = String.raw`{"msg": "the escape \u00e9 prints an e-acute and \n is a newline"}`;
  const E4 = String.raw`{"contact": "jane\u0040example.com"}`;
  const E5 = String.raw`{"emoji": "\ud83d\ude00 ok", "path": "C:\\Users\\name\\notes.txt"}`;
  const E6 = '{"key": "' + P1.split('\n').join('\\n') + '"}';
  const E7 = '{"key": "' + P2.split('\n').join('\\n') + '"}';
  const E8 = '\\'.repeat(600) + 'n';
  for (const mode of ['reject', 'strip']) {
    assertEncoded(s.screenText(E1, mode), ['openai_style_api_key']);
    assertEncoded(s.screenText(E2, mode), ['openai_style_api_key']);
    assert.deepStrictEqual(s.screenText(E3, mode), { ok: true, status: 200, text: E3, findings: [] });
    assertEncoded(s.screenText(E4, mode), ['email_address']);
    assert.deepStrictEqual(s.screenText(E5, mode), { ok: true, status: 200, text: E5, findings: [] });
    assertEncoded(s.screenText(E7, mode), ['pem_private_key']);
    assertEncoded(s.screenText(E8, mode), ['unresolved_escape']);
  }
  const r6 = s.screenText(E6, 'reject');
  assert.strictEqual(r6.status, 422);
  assert.deepStrictEqual(r6.findings.map(f => [f.label, f.start, f.end, f.encoded]), [['pem_private_key', 9, 202, false]]);
  const s6 = s.screenText(E6, 'strip');
  assert.strictEqual(s6.ok, true);
  assert.strictEqual(s6.text, '{"key": "[REDACTED:pem_private_key]"}');
  const unresolved = s.screenText(E8).findings[0];
  assert.deepStrictEqual(unresolved, { category: 'secret', label: 'unresolved_escape', start: -1, end: -1, preview: '***', value_hash: null, encoded: true });
  assert.deepStrictEqual(resolveEscapes(String.raw`\ud83d\ude00\ud83d \"\/\b\f\n\r\t\q\\`),
    { text: '\u{1F600}\ufffd "/\b\f\n\r\t\\q\\', unresolved: false });
});

/**
 * SCREEN-14: an unknown mode is 400 invalid_mode, an empty or unknown category list is 400 invalid_categories and
 * a text over max_bytes is 413 text_too_large, all before any scan; each hostile 200,000-character input in the
 * spec is screened in under 2 seconds.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: SCREEN-14, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only.
 */
// SCREEN-14
test('SCREEN-14 bad mode, bad categories and oversize text are refused before any scan; hostile inputs are fast', () => {
  const s = newScreener();
  assert.deepStrictEqual(s.screenText('x', 'mask'), { ok: false, error: 'invalid_mode', status: 400 });
  assert.deepStrictEqual(s.screenText('x', 'reject', []), { ok: false, error: 'invalid_categories', status: 400 });
  assert.deepStrictEqual(s.screenText('x', 'reject', ['secret', 'keys']), { ok: false, error: 'invalid_categories', status: 400 });
  const accent5 = '\u00e9'.repeat(5);
  assert.deepStrictEqual(newScreener(null, 9).screenText(accent5), { ok: false, error: 'text_too_large', status: 413 });
  assert.deepStrictEqual(newScreener(null, 10).screenText(accent5), { ok: true, status: 200, text: accent5, findings: [] });
  // An oversized secret-bearing text is refused as too large, not scanned (step 4 runs before step 5).
  assert.deepStrictEqual(newScreener(null, 10).screenText('token: ' + K1), { ok: false, error: 'text_too_large', status: 413 });
  // Extra, not a required id: an unpaired surrogate is invalid_text.
  assert.deepStrictEqual(s.screenText('a\ud800b'), { ok: false, error: 'invalid_text', status: 400 });
  assert.deepStrictEqual(s.screenText(42), { ok: false, error: 'invalid_text', status: 400 });

  const hostile = [
    'a.'.repeat(100000), ('-----BEGIN ' + 'PRIVATE KEY-----').repeat(7400), '1234-'.repeat(40000), 'eyJ'.repeat(66666),
    'xeyJ-'.repeat(40000), 'xsk-'.repeat(50000), 'password' + ' '.repeat(199990), 'token=[REDACTED:'.repeat(12500),
    'a://b:'.repeat(33000), 'ab:'.repeat(66000), '1.1.'.repeat(50000), '\\n'.repeat(100000), B + '\n'.repeat(199969),
    B + ('\n' + 'A'.repeat(64)).repeat(3000),
    // Lead ruling fed6e7b (2026-11-10): detector 13 followed literally is quadratic on this one.
    'token=$'.repeat(28571)
  ];
  assert.strictEqual('token=$'.repeat(28571).length, 199997);
  for (const text of hostile) {
    const t0 = process.hrtime.bigint();
    const r = s.screenText(text, 'strip');
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    assert.ok(ms < 2000, `hostile input took ${ms} ms`);
    assert.notStrictEqual(r.error, 'screening_failed');
  }
});

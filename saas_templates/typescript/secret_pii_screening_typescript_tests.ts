/**
 * Tests for secret_pii_screening_typescript.ts: one test (or more) per SCREEN-01..14 row of
 * docs/specs/secret_pii_screening.md, asserting the spec's TEST VECTORS exactly. Every key-shaped value is built
 * from two or more pieces at run time, as the spec writes them, so a repository secret scanner never blocks a commit.
 * Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Finding, mask, newScreener, resolveEscapes, ScreenError, Screener } from './secret_pii_screening_typescript.ts';

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
const G = '-----BEGIN PGP ' + 'PRIVATE KEY BLOCK-----' + '\nVersion: GnuPG v2\n\n' + L1 + '\n' + L2 + '\n=AbCd\n' + '-----END PGP ' +
  'PRIVATE KEY BLOCK-----';
const HASH_KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const T = 'Contact jane@example.com or call 555-123-4567 for help.';

type Span = [string, number, number];
const screener = new Screener();

/** [label, start, end] of each finding (both categories). Touches nothing. */
function spans(text: string, s: Screener = screener): Span[] {
  return s.scanText(text).map((f) => [f.label, f.start, f.end] as Span);
}

/** Asserts a table of vectors: text -> exact spans. Touches nothing. */
function check(vectors: [string, Span[]][]): void {
  for (const [text, expected] of vectors) assert.deepEqual(spans(text), expected, JSON.stringify(text.slice(0, 80)));
}

const V02: [string, Span[]][] = [
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
  ['class sk-spinner-three-bounce is used', []],
];
const V03: [string, Span[]][] = [
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
  ['Look for the line ' + B + ' in the file.', []],
];
const V04: [string, Span[]][] = [
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
  ['Send the header with bearer token-based auth', []],
];
const KV = 'generic_key_value_assignment';
const V05: [string, Span[]][] = [
  ['DB_PASSWORD=' + 'Sup3rS3cretValue!\n', [[KV, 12, 29]]],
  ['internal_api_key: "' + 'zx91-nq7f-88ab-lorem"', [[KV, 19, 39]]],
  ['{"password": "' + 'hunter2hunter2"}', [[KV, 14, 28]]],
  ['{\\"password\\":\\"' + 'hunter2hunter2\\"}', [[KV, 16, 30]]],
  ['db_password: ' + 'CorrectHorseBatteryStaple', [[KV, 13, 38]]],
  ['the db_password: ' + 'CorrectHorseBatteryStaple9 I mentioned', [[KV, 17, 43]]],
  ['password: ' + 'DOMAIN\\Administrator1', [[KV, 10, 31]]],
  ["API_KEY = '" + "Zx91Nq7f88ab'", [[KV, 11, 23]]],
  ['token=' + 'abc12345;next', [[KV, 6, 14]]],
  ['password: ' + 'p\u00e4ssw\u00f6rd123', [[KV, 10, 21]]],
  ['a'.repeat(40) + 'token=' + 'abc12345def', [[KV, 46, 57]]],
  ['a'.repeat(41) + 'token=' + 'abc12345def', []],
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
  ["'password' => '" + "Sup3rS3cretValue!',", [[KV, 15, 32]]],
  ['password := "' + 'Sup3rS3cretValue!"', [[KV, 13, 30]]],
  ['password: ' + 'hunter2!', [[KV, 10, 18]]],
  ['password: ' + 'P@ss(w0rd)1x', [[KV, 10, 22]]],
  ['token: ' + 'ab12.cd34.ef56gh78', [[KV, 7, 25]]],
  ['\u0130 token=' + 'abc12345', [[KV, 8, 16]]],
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
  ['password: abcdefgh\u0663', []],
];
const V06: [string, Span[]][] = [
  [T, [['email_address', 8, 24], ['phone_number', 33, 45]]],
  ['<jane.doe+tag@mail.example.co.uk>', [['email_address', 1, 32]]],
  ['see https://example.com/contact?email=jane@example.com', [['email_address', 38, 54]]],
  ['call (555) 123-4567 now', [['phone_number', 5, 19]]],
  ['+1 555-123-4567', [['phone_number', 0, 15]]],
  ['reach me at +442071838750.', [['phone_number', 12, 25]]],
  ['SSN 123-45-6789', [['ssn', 4, 15]]],
  ['order 5551234567 shipped', []],
  ['jane@example.com_backup', []],
  ['user@localhost and a@b', []],
  ['SSN 000-12-3456, 666-12-3456, 900-12-3456, 123-00-4567, 123-45-0000', []],
];
const CC = 'credit_card_number';
const V07: [string, Span[]][] = [
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
  ['4 8 15 16 23 42 4 8 15 16 23 42 108', []],
];
const IP = 'ip_address';
const V08: [string, Span[]][] = [
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
  ['Version=1.0.0.0, Culture=neutral', []],
];

/**
 * SCREEN-01: the four clean texts are ok, unchanged, with no findings, in both modes.
 * In: the spec's vectors and fakes. Out: assertions only. Why: SCREEN-01 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// SCREEN-01
test('SCREEN-01 the four clean texts are ok, unchanged, with no findings, in both modes', () => {
  const clean = [
    "User: let's plan the export feature.\nAssistant: I built the CSV export button and will add a progress bar.\n",
    "def get_cache_key(user_id):\n    return f'user:{user_id}'\n\nclass TokenBucket:\n    def __init__(self, capacity):\n        self.capacity = capacity\n",
    'Please reset your password before the next login.',
    'version 1.2.3.4.5 released at 12:30:45 on 2026-11-10, build 20261110123045, order 1234567890',
  ];
  for (const text of clean) {
    for (const mode of ['reject', 'strip']) {
      assert.deepEqual(screener.screenText(text, mode), { ok: true, status: 200, text, findings: [] });
    }
  }
});

/**
 * SCREEN-02: every key shape with its label and exact span; the near-misses are not found.
 * In: the spec's vectors and fakes. Out: assertions only. Why: SCREEN-02 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// SCREEN-02
test('SCREEN-02 every key shape with its label and exact span; the near-misses are not found', () => check(V02));

/**
 * SCREEN-03: private key blocks: whole block, encrypted header, cut-off blocks, quoted and diff forms.
 * In: the spec's vectors and fakes. Out: assertions only. Why: SCREEN-03 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// SCREEN-03
test('SCREEN-03 private key blocks: whole block, encrypted header, cut-off blocks, quoted and diff forms', () => check(V03));

/**
 * SCREEN-04: bearer tokens and URL passwords: only the token or password is the span.
 * In: the spec's vectors and fakes. Out: assertions only. Why: SCREEN-04 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// SCREEN-04
test('SCREEN-04 bearer tokens and URL passwords: only the token or password is the span', () => check(V04));

/**
 * SCREEN-05: key = value secrets in every form; placeholders, references and plain words are not.
 * In: the spec's vectors and fakes. Out: assertions only. Why: SCREEN-05 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// SCREEN-05
test('SCREEN-05 key = value secrets in every form; placeholders, references and plain words are not', () => check(V05));

/**
 * SCREEN-06: emails, phone numbers and SSNs; the near-misses are not found.
 * In: the spec's vectors and fakes. Out: assertions only. Why: SCREEN-06 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// SCREEN-06
test('SCREEN-06 emails, phone numbers and SSNs; the near-misses are not found', () => check(V06));

/**
 * SCREEN-07: card numbers need a network prefix and Luhn; groupings and following numbers.
 * In: the spec's vectors and fakes. Out: assertions only. Why: SCREEN-07 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// SCREEN-07
test('SCREEN-07 card numbers need a network prefix and Luhn; groupings and following numbers', () => check(V07));

/**
 * SCREEN-08: public IPv4 and global IPv6 only.
 * In: the spec's vectors and fakes. Out: assertions only. Why: SCREEN-08 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// SCREEN-08
test('SCREEN-08 public IPv4 and global IPv6 only', () => check(V08));

/**
 * SCREEN-09: reject mode: 422 with the findings and neither the text nor a value; ["secret"] is ok.
 * In: the spec's vectors and fakes. Out: assertions only. Why: SCREEN-09 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// SCREEN-09
test('SCREEN-09 reject mode: 422 with the findings and neither the text nor a value; ["secret"] is ok', () => {
  const s = new Screener(HASH_KEY);
  const out = s.screenText(T);
  assert.deepEqual(out, { ok: false, error: 'secrets_or_pii_detected', status: 422, findings: [
    { category: 'pii', label: 'email_address', start: 8, end: 24, preview: 'ja************om', value_hash: '9487588974759d303d5d44401791a603ad85fda9276d43f7436077d709d9da10', encoded: false },
    { category: 'pii', label: 'phone_number', start: 33, end: 45, preview: '************', value_hash: 'ee171612a2f4984e73ec9377b4d10f2b76125f5adf8e4315f12e77ebb2cd41c3', encoded: false },
  ] });
  const dump = JSON.stringify(out);
  assert.ok(!('text' in out));
  for (const secret of [T, 'jane@example.com', '555-123-4567']) assert.ok(!dump.includes(secret));
  assert.deepEqual(s.screenText(T, 'reject', ['secret']), { ok: true, status: 200, text: T, findings: [] });
  const keyRefusal = s.screenText('my key ' + K1, 'reject');
  assert.ok(!JSON.stringify(keyRefusal).includes(K1));
});

/**
 * SCREEN-10: strip mode: markers name the label, everything else unchanged, the output screens clean.
 * In: the spec's vectors and fakes. Out: assertions only. Why: SCREEN-10 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// SCREEN-10
test('SCREEN-10 strip mode: markers name the label, everything else unchanged, the output screens clean', () => {
  const s = new Screener(HASH_KEY);
  const out = s.screenText(T, 'strip');
  assert.deepEqual(out, {
    ok: true, status: 200, text: 'Contact [REDACTED:email_address] or call [REDACTED:phone_number] for help.',
    findings: (s.screenText(T) as { findings: Finding[] }).findings,
  });
  const pii = s.screenText(T, 'strip', ['pii']) as { text: string };
  assert.equal(pii.text, 'Contact [REDACTED:email_address] or call [REDACTED:phone_number] for help.');
  for (const [text, expected] of [...V02, ...V03, ...V04, ...V05, ...V06, ...V07, ...V08]) {
    if (!expected.length) continue;
    const stripped = screener.screenText(text, 'strip');
    assert.equal(stripped.ok, true, JSON.stringify(text.slice(0, 60)));
    const redacted = (stripped as { text: string }).text;
    for (const [label] of expected) assert.ok(redacted.includes('[REDACTED:' + label + ']'));
    assert.deepEqual(screener.screenText(redacted, 'reject'), { ok: true, status: 200, text: redacted, findings: [] });
  }
  assert.equal((screener.screenText('a ' + P1 + ' b', 'strip') as { text: string }).text, 'a [REDACTED:pem_private_key] b');
  const late = screener.screenText('jane@example.com555-123-4567', 'strip') as { ok: boolean; status: number; error: string; findings: Finding[] };
  assert.deepEqual([late.ok, late.status, late.error], [false, 422, 'secrets_or_pii_detected']);
  assert.deepEqual(late.findings.map((f) => [f.label, f.start, f.end]), [['phone_number', 16, 28], ['email_address', -1, -1]]);
  assert.ok(!('text' in late));
});

/**
 * SCREEN-11: overlaps: earliest start, longest span, earlier detector; code point positions.
 * In: the spec's vectors and fakes. Out: assertions only. Why: SCREEN-11 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// SCREEN-11
test('SCREEN-11 overlaps: earliest start, longest span, earlier detector; code point positions', () => {
  check([
    ['\u00e9\u{1F600} a@b.co', [['email_address', 3, 9]]],
    ['token=' + K1, [['openai_style_api_key', 6, 33]]],
    ['Bearer ' + K1, [['openai_style_api_key', 7, 34]]],
  ]);
  const out = screener.screenText('\u00e9\u{1F600} a@b.co', 'strip') as { text: string };
  assert.equal(out.text, '\u00e9\u{1F600} [REDACTED:email_address]');
  for (const [text] of [...V02, ...V03, ...V05]) {
    const found = screener.scanText(text);
    for (let i = 1; i < found.length; i++) assert.ok(found[i].start >= found[i - 1].end);
  }
});

/**
 * SCREEN-12: mask, value_hash with the configured key (null without), short keys refused.
 * In: the spec's vectors and fakes. Out: assertions only. Why: SCREEN-12 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// SCREEN-12
test('SCREEN-12 mask, value_hash with the configured key (null without), short keys refused', () => {
  assert.equal(mask('a'.repeat(15)), '*'.repeat(15));
  assert.equal(mask('abcdefghijklmnop'), 'ab************op');
  assert.equal(mask(K1), 'sk' + '*'.repeat(23) + 'OP');
  assert.equal(mask('\u{1F600}'.repeat(16)), '\u{1F600}\u{1F600}' + '*'.repeat(12) + '\u{1F600}\u{1F600}');
  const keyed = new Screener(HASH_KEY).scanText(T);
  assert.equal(keyed[0].value_hash, '9487588974759d303d5d44401791a603ad85fda9276d43f7436077d709d9da10');
  assert.equal(keyed[1].value_hash, 'ee171612a2f4984e73ec9377b4d10f2b76125f5adf8e4315f12e77ebb2cd41c3');
  assert.deepEqual(screener.scanText(T).map((f) => f.value_hash), [null, null]);
  assert.throws(() => new Screener(Buffer.alloc(31)), (e: unknown) => e instanceof ScreenError && e.code === 'invalid_hash_key');
  assert.throws(() => newScreener('short key'), (e: unknown) => e instanceof ScreenError && e.code === 'invalid_hash_key');
  assert.ok(newScreener(HASH_KEY));
});

/**
 * SCREEN-13: secrets behind JSON escapes are refused in both modes; escape mentions pass; E1-E8.
 * In: the spec's vectors and fakes. Out: assertions only. Why: SCREEN-13 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// SCREEN-13
test('SCREEN-13 secrets behind JSON escapes are refused in both modes; escape mentions pass; E1-E8', () => {
  const encoded = (label: string) => ({ label, start: -1, end: -1, encoded: true });
  const pick = (r: any) => (r.findings ?? []).map((f: Finding) => ({ label: f.label, start: f.start, end: f.end, encoded: f.encoded }));
  const P1e = P1.replace(/\n/g, '\\n');
  const P2e = P2.replace(/\n/g, '\\n');
  const vectors: [string, string, unknown, unknown][] = [
    ['E1', '{"note": "sk\\u002d' + 'abcdEFGH12345678ijklMNOP"}', [encoded('openai_style_api_key')], [encoded('openai_style_api_key')]],
    ['E2', '{"outer": "{\\"k\\": \\"sk\\\\u002d' + 'abcdEFGH12345678ijklMNOP\\"}"}', [encoded('openai_style_api_key')], [encoded('openai_style_api_key')]],
    ['E3', '{"msg": "the escape \\u00e9 prints an e-acute and \\n is a newline"}', 'ok', 'ok'],
    ['E4', '{"contact": "jane\\u0040example.com"}', [encoded('email_address')], [encoded('email_address')]],
    ['E5', '{"emoji": "\\ud83d\\ude00 ok", "path": "C:\\\\Users\\\\name\\\\notes.txt"}', 'ok', 'ok'],
    ['E6', '{"key": "' + P1e + '"}', [{ label: 'pem_private_key', start: 9, end: 202, encoded: false }], '{"key": "[REDACTED:pem_private_key]"}'],
    ['E7', '{"key": "' + P2e + '"}', [encoded('pem_private_key')], [encoded('pem_private_key')]],
    ['E8', '\\'.repeat(600) + 'n', [encoded('unresolved_escape')], [encoded('unresolved_escape')]],
  ];
  for (const [name, text, reject, strip] of vectors) {
    for (const [mode, want] of [['reject', reject], ['strip', strip]] as [string, unknown][]) {
      const r = screener.screenText(text, mode) as any;
      if (want === 'ok') {
        assert.deepEqual(r, { ok: true, status: 200, text, findings: [] }, name + ' ' + mode);
      } else if (typeof want === 'string') {
        assert.deepEqual(r, { ok: true, status: 200, text: want, findings: r.findings }, name + ' ' + mode);
        assert.equal(r.findings[0].label, 'pem_private_key');
      } else {
        assert.deepEqual([r.ok, r.status, r.error], [false, 422, 'secrets_or_pii_detected'], name + ' ' + mode);
        assert.deepEqual(pick(r), want, name + ' ' + mode);
        assert.ok(!('text' in r));
      }
    }
  }
  const e8 = screener.screenText('\\'.repeat(600) + 'n') as any;
  assert.deepEqual(e8.findings[0], { category: 'secret', label: 'unresolved_escape', start: -1, end: -1, preview: '***', value_hash: null, encoded: true });
  assert.deepEqual(resolveEscapes('a\\u0041\\"b'), { text: 'aA"b', unresolved: false });
  assert.deepEqual(resolveEscapes('\\ud800x'), { text: '\ufffdx', unresolved: false });
});

/**
 * SCREEN-14: bad mode, bad categories and too-large text refused before any scan; hostile inputs under 2 s.
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the spec's new hostile input "token=$" * 28571 (200,000
 * characters, quadratic for a value scan that is not table-driven) is in the list, so its speed is proven.
 * In: the spec's vectors and fakes. Out: assertions only. Why: SCREEN-14 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// SCREEN-14
test('SCREEN-14 bad mode, bad categories and too-large text refused before any scan; hostile inputs under 2 s', () => {
  assert.deepEqual(screener.screenText('x', 'mask'), { ok: false, error: 'invalid_mode', status: 400 });
  assert.deepEqual(screener.screenText('x', 'reject', []), { ok: false, error: 'invalid_categories', status: 400 });
  assert.deepEqual(screener.screenText('x', 'reject', ['secret', 'keys']), { ok: false, error: 'invalid_categories', status: 400 });
  assert.deepEqual(screener.screenText(K1, 'mask'), { ok: false, error: 'invalid_mode', status: 400 });
  const nine = new Screener(null, 9);
  assert.deepEqual(nine.screenText('\u00e9'.repeat(5)), { ok: false, error: 'text_too_large', status: 413 });
  assert.deepEqual(nine.screenText(K1), { ok: false, error: 'text_too_large', status: 413 });
  assert.deepEqual(new Screener(null, 10).screenText('\u00e9'.repeat(5)), { ok: true, status: 200, text: '\u00e9'.repeat(5), findings: [] });
  assert.deepEqual(screener.screenText('a\ud800b'), { ok: false, error: 'invalid_text', status: 400 });
  assert.deepEqual(screener.screenText(42 as unknown as string), { ok: false, error: 'invalid_text', status: 400 });
  const hostile = [
    'a.'.repeat(100000), ('-----BEGIN ' + 'PRIVATE KEY-----').repeat(7400), '1234-'.repeat(40000), 'eyJ'.repeat(66666),
    'xeyJ-'.repeat(40000), 'xsk-'.repeat(50000), 'password' + ' '.repeat(199990), 'token=[REDACTED:'.repeat(12500),
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: added when the spec listed it (detector 13 was quadratic on it).
    'token=$'.repeat(28571),
    'a://b:'.repeat(33000), 'ab:'.repeat(66000), '1.1.'.repeat(50000), '\\n'.repeat(100000), B + '\n'.repeat(199969),
    B + ('\n' + 'A'.repeat(64)).repeat(3000),
  ];
  for (const text of hostile) {
    const t0 = process.hrtime.bigint();
    const r = screener.screenText(text, 'strip');
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    assert.ok(ms < 2000, `${JSON.stringify(text.slice(0, 20))} took ${ms} ms`);
    assert.notEqual(r.status, 500);
  }
});

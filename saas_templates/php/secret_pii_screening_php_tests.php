<?php
/**
 * Secret & PII screening tests (docs/specs/secret_pii_screening.md, SCREEN-01..14).
 *
 * Self-running script: each test_* function asserts the spec's fixed vectors exactly; the script exits 1 on
 * any failure. Key-shaped values are built from two or more pieces at run time (spec IMPLEMENTATION RULES), so
 * a repository secret scanner never sees a whole key in this file.
 *
 * Why: Phase D wave 1, owner request 2026-11-10. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only (no database, files, network or money).
 */

declare(strict_types=1);

require_once __DIR__ . '/secret_pii_screening_php.php';

use SecretPiiScreening\Screener;
use SecretPiiScreening\ScreeningError;
use function SecretPiiScreening\mask;
use function SecretPiiScreening\new_screener;
use function SecretPiiScreening\resolve_escapes;

$GLOBALS['FAILS'] = 0;

/**
 * Assert two values are identical. In: expected, actual, label. Out: none; counts and prints a failure.
 * Why: test helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: stdout.
 */
function eq($expected, $actual, string $msg): void
{
    if ($expected !== $actual) {
        $GLOBALS['FAILS']++;
        echo "  FAIL $msg\n    expected: " . var_export($expected, true) . "\n    actual:   " . var_export($actual, true) . "\n";
    }
}

/**
 * The spec's key pieces (TEST VECTORS), joined at run time. In: a name. Out: the value.
 * Why: SCREEN-02..13 vectors. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function V(string $name): string
{
    $L1 = 'MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumga0R2LiajO16aI4Uxa2b9nb';
    $L2 = 'AKELFOxNOFICTIONALKEYMATERIALFORTESTINGPURPOSESONLY1234567890AB';
    $B = '-----BEGIN RSA ' . 'PRIVATE KEY-----';
    $E = '-----END RSA ' . 'PRIVATE KEY-----';
    $v = [
        'K1' => 'sk-' . 'abcdEFGH12345678ijklMNOP',
        'K2' => 'sk_' . 'live_' . 'A1b2C3d4E5f6G7h8I9j0K1l2',
        'K3' => 'pk_' . 'test_' . 'A1b2C3d4E5f6G7h8I9j0K1l2',
        'K4' => 'AKIA' . 'IOSFODNN7EXAMPLE',
        'K5' => 'ghp_' . '16C7e42F292c6912E7710c838347Ae178B4a',
        'K6' => 'github_pat_' . '11ABCDEFG0abcdefghij_KLMNOPQRSTUVWXYZ0123456789',
        'K7' => 'xoxb-' . '1234567890-abcdefghijklmnopqrstuvwx',
        'K8' => 'AIza' . 'SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q',
        'K9' => 'whsec_' . 'MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
        'J' => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' . '.' . 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0' . '.' . 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
        'B' => $B, 'E' => $E, 'L1' => $L1, 'L2' => $L2,
        'P1' => $B . "\n" . $L1 . "\n" . $L2 . "\n" . $E,
        'P2' => $B . "\n" . "Proc-Type: 4,ENCRYPTED\n" . "DEK-Info: AES-256-CBC,A1B2C3D4E5F60718293A4B5C6D7E8F90\n" . "\n" . $L1 . "\n" . $E,
        'P3' => $B . "\n" . "api_key=looksLikeASecretButItsJustPemBase64Content\n" . $E,
        'P4' => $B . "\n" . $L1 . "\n" . $L2 . ' (cut',
        'G' => '-----BEGIN PGP ' . "PRIVATE KEY BLOCK-----" . "\nVersion: GnuPG v2\n\n" . $L1 . "\n" . $L2 . "\n=AbCd\n" . '-----END PGP ' . 'PRIVATE KEY BLOCK-----',
    ];
    return $v[$name];
}

/**
 * Findings of scan_text as "label start-end" strings. In: screener, text, categories. Out: list of strings.
 * Why: compact exact assertions. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function spans(Screener $s, string $text, array $cats = ['secret', 'pii']): array
{
    return array_map(static fn(array $f): string => $f['label'] . ' ' . $f['start'] . '-' . $f['end'], $s->scanText($text, $cats));
}

/**
 * Assert a table of [text, expected spans]. In: screener, vectors, test name. Out: none.
 * Why: the spec's vector tables. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: stdout.
 */
function table(Screener $s, array $vectors, string $name): void
{
    foreach ($vectors as $i => [$text, $want]) {
        eq($want, spans($s, $text), "$name vector $i");
    }
}

/** The SCREEN-02 table. Out: [[text, spans]]. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
function vectors02(): array
{
    return [
        ['here is my key: ' . V('K1'), ['openai_style_api_key 16-43']],
        ['STRIPE_KEY=' . V('K2'), ['stripe_style_api_key 11-43']],
        [V('K3') . ' used in the demo', ['stripe_style_api_key 0-32']],
        ['AWS_ACCESS_KEY_ID=' . V('K4'), ['aws_access_key_id 18-38']],
        ['token: ' . V('K5'), ['github_token 7-47']],
        ['use ' . V('K6') . ' now', ['github_token 4-62']],
        [V('K7'), ['slack_token 0-40']],
        ['key=' . V('K8') . '&x=1', ['google_api_key 4-43']],
        ['secret ' . V('K9') . '.', ['webhook_signing_secret 7-45']],
        ['Authorization token captured: ' . V('J'), ['jwt 30-162']],
        ['ASIA' . 'IOSFODNN7EXAMPLE', ['aws_access_key_id 0-20']],
        ['task-' . 'abcdEFGH12345678ijklMNOP', []],
        ['X' . V('K4'), []],
        [V('K2') . '_x', []],
        ['class sk-spinner-three-bounce is used', []],
    ];
}

/** The SCREEN-03 table. Out: [[text, spans]]. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
function vectors03(): array
{
    $B = V('B');
    return [
        ['a ' . V('P1') . ' b', ['pem_private_key 2-192']],
        [V('P2'), ['pem_private_key 0-205']],
        [V('P3'), ['pem_private_key 0-112']],
        ['api_key=looksLikeASecretButItsJustPemBase64Content', ['generic_key_value_assignment 8-50']],
        ['x ' . V('P4'), ['pem_private_key 2-162']],
        ['-' . $B . "\n-" . V('L1') . "\n-" . V('L2') . "\n-" . V('E'), ['pem_private_key 1-163']],
        ['> ' . $B . "\n> " . V('L1') . "\n> " . V('L2') . "\n> " . V('E'), ['pem_private_key 2-198']],
        [V('G'), ['pem_private_key 0-227']],
        [$B . "\n" . str_repeat('A', 30) . "\\n" . str_repeat('A', 30), ['pem_private_key 0-94']],
        [$B . "\n" . str_repeat('A', 29) . "\\n" . str_repeat('A', 30), []],
        [$B . "\n" . str_repeat('A', 59), []],
        ['Look for the line ' . $B . ' in the file.', []],
    ];
}

/** The SCREEN-04 table. Out: [[text, spans]]. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
function vectors04(): array
{
    return [
        ["curl -H 'Authorization: Bearer abc123DEF456ghi789JKL'", ['bearer_token 31-52']],
        ['authorization: BEARER abc123DEF456ghi789JKL', ['bearer_token 22-43']],
        ['Bearer authentication is required', []],
        ['Bearer ' . V('J'), ['jwt 7-139']],
        ['postgres://app:S3cr3t-Pa55@db.internal:5432/app', ['url_credentials 15-26']],
        ['ssh://git:hunter2secret@host/repo', ['url_credentials 10-23']],
        ['https://user:password@example.com/', []],
        ['https://jane@example.com/x', []],
        ['redis://:Sup3rS3cretValue@cache.example.com:6379/0', ['url_credentials 9-25']],
        ['http://localhost:8080/@foo and https://example.com/a:b@c', []],
        ['Our API uses Bearer authentication.', []],
        ['Send the header with bearer token-based auth', []],
    ];
}

/** The SCREEN-05 table. Out: [[text, spans]]. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
function vectors05(): array
{
    $g = 'generic_key_value_assignment ';
    return [
        ["DB_PASSWORD=Sup3rS3cretValue!\n", [$g . '12-29']],
        ["internal_api_key: \"zx91-nq7f-88ab-lorem\"", [$g . '19-39']],
        ["{\"password\": \"hunter2hunter2\"}", [$g . '14-28']],
        ["{\\\"password\\\":\\\"hunter2hunter2\\\"}", [$g . '16-30']],
        ['db_password: CorrectHorseBatteryStaple', [$g . '13-38']],
        ['the db_password: CorrectHorseBatteryStaple9 I mentioned', [$g . '17-43']],
        ["password: DOMAIN\\Administrator1", [$g . '10-31']],
        ["API_KEY = 'Zx91Nq7f88ab'", [$g . '11-23']],
        ['token=abc12345;next', [$g . '6-14']],
        ["password: p\u{e4}ssw\u{f6}rd123", [$g . '10-21']],
        [str_repeat('a', 40) . 'token=abc12345def', [$g . '46-57']],
        [str_repeat('a', 41) . 'token=abc12345def', []],
        ['API_KEY=your_key_here', []],
        ['password: changeme', []],
        ['pwd=abc123', []],
        ['Secret: whatever the team decides', []],
        ['password: WordPress', []],
        ['My favorite crypto token: Ethereum has been volatile', []],
        ['class TokenBucket:', []],
        ['Please reset your password before the next login.', []],
        ['secrets: abc12345def', []],
        ["password: gr\u{f6}\u{df}eres", []],
        ['password: [REDACTED:generic_key_value_assignment]', []],
        ["'password' => 'Sup3rS3cretValue!',", [$g . '15-32']],
        ["password := \"Sup3rS3cretValue!\"", [$g . '13-30']],
        ['password: hunter2!', [$g . '10-18']],
        ['password: P@ss(w0rd)1x', [$g . '10-22']],
        ['token: ab12.cd34.ef56gh78', [$g . '7-25']],
        ["\u{130} token=abc12345", [$g . '8-16']],
        ['The password: required.', []],
        ['token: optional,', []],
        ['password: changeme.', []],
        ['password: undefined,', []],
        ["password = os.getenv(\"DB_PASSWORD\")", []],
        ["api_key = os.environ[\"API_KEY\"]", []],
        ['secret_key = settings.SECRET_KEY', []],
        ['apiKey: process.env.STRIPE_KEY,', []],
        ['token = getAccessTokenSilently();', []],
        ['password: req.body.password,', []],
        ["API_KEY=\$API_KEY", []],
        ["token=\${TOKEN}", []],
        ['api_key: <YOUR_API_KEY>', []],
        ['Password: ********', []],
        ['token: Optional[str] = None', []],
        ['password = models.CharField(max_length=128)', []],
        ["to\u{212a}en=abc12345def", []],
        ["password: abcdefgh\u{663}", []],
    ];
}

/** The SCREEN-06 table. Out: [[text, spans]]. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
function vectors06(): array
{
    return [
        ['Contact jane@example.com or call 555-123-4567 for help.', ['email_address 8-24', 'phone_number 33-45']],
        ['<jane.doe+tag@mail.example.co.uk>', ['email_address 1-32']],
        ['see https://example.com/contact?email=jane@example.com', ['email_address 38-54']],
        ['call (555) 123-4567 now', ['phone_number 5-19']],
        ['+1 555-123-4567', ['phone_number 0-15']],
        ['reach me at +442071838750.', ['phone_number 12-25']],
        ['SSN 123-45-6789', ['ssn 4-15']],
        ['order 5551234567 shipped', []],
        ['jane@example.com_backup', []],
        ['user@localhost and a@b', []],
        ['SSN 000-12-3456, 666-12-3456, 900-12-3456, 123-00-4567, 123-45-0000', []],
    ];
}

/** The SCREEN-07 table. Out: [[text, spans]]. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
function vectors07(): array
{
    $c = 'credit_card_number ';
    return [
        ['card 4242 4242 4242 4242 exp 12/27', [$c . '5-24']],
        ['5555-5555-5555-4444', [$c . '0-19']],
        ['378282246310005', [$c . '0-15']],
        ['card 4242 4242 4242 4242 123', [$c . '5-24']],
        ['4242 4242 4242 4242 1234 5678', [$c . '0-19']],
        ['4242 4242 4242 4241', []],
        ['1234 5678 1234 5670', []],
        ['ts 1700000000000 ms', []],
        ['42424242424242424242424', []],
        ['x4242424242424242', []],
        ['4242424242424242x', []],
        ['3782 822463 10005', [$c . '0-17']],
        ['card 4222 2222 2222 2 end', [$c . '5-21']],
        ['2 2 6 14 8 15 20 6 13', []],
        ['4 8 15 16 23 42 4 8 15 16 23 42 108', []],
    ];
}

/** The SCREEN-08 table. Out: [[text, spans]]. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
function vectors08(): array
{
    return [
        ['client 203.0.113.7 connected', ['ip_address 7-18']],
        ['from 198.51.100.24.', ['ip_address 5-18']],
        ['addr 2001:db8::8a2e:370:7334 ok', ['ip_address 5-28']],
        ['[2001:0db8:0000:0000:0000:ff00:0042:8329]', ['ip_address 1-40']],
        ['8.8.8.8 and 172.32.0.1 and 2606:4700:4700::1111', ['ip_address 0-7', 'ip_address 12-22', 'ip_address 27-47']],
        ['127.0.0.1 10.0.0.5 192.168.1.1 172.16.0.1 169.254.1.1 0.0.0.0 224.0.0.1 255.255.255.255', []],
        ['999.1.1.1 and 256.1.1.1 and 08.8.8.8', []],
        ['1.2.3.4.5 and v8.8.8.8', []],
        ['12:30:45 and aa:bb:cc:dd:ee:ff', []],
        ['::1 and fe80::1 and fc00::1', []],
        ['db::add(x) and dead::beef', []],
        ['Version=1.0.0.0, Culture=neutral', []],
    ];
}

/** The 32-byte hash key 00 01 .. 1f of SCREEN-09/10/12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function hashKey(): string
{
    return implode('', array_map('chr', range(0, 31)));
}

const T = 'Contact jane@example.com or call 555-123-4567 for help.';

/** The two findings of T with the spec's hash key. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function tFindings(): array
{
    return [
        ['category' => 'pii', 'label' => 'email_address', 'start' => 8, 'end' => 24, 'preview' => 'ja************om', 'value_hash' => '9487588974759d303d5d44401791a603ad85fda9276d43f7436077d709d9da10', 'encoded' => false],
        ['category' => 'pii', 'label' => 'phone_number', 'start' => 33, 'end' => 45, 'preview' => '************', 'value_hash' => 'ee171612a2f4984e73ec9377b4d10f2b76125f5adf8e4315f12e77ebb2cd41c3', 'encoded' => false],
    ];
}

// SCREEN-01
/**
 * SCREEN-01: the four clean texts are ok, unchanged, with no findings, in both modes.
 * Why: SCREEN-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
 */
function test_screen01_clean_texts_pass_unchanged(): void
{
    $s = new_screener();
    $clean = [
        "User: let's plan the export feature.\nAssistant: I built the CSV export button and will add a progress bar.\n",
        "def get_cache_key(user_id):\n    return f'user:{user_id}'\n\nclass TokenBucket:\n    def __init__(self, capacity):\n        self.capacity = capacity\n",
        'Please reset your password before the next login.',
        'version 1.2.3.4.5 released at 12:30:45 on 2026-11-10, build 20261110123045, order 1234567890',
    ];
    foreach ($clean as $i => $text) {
        foreach (['reject', 'strip'] as $mode) {
            eq(['ok' => true, 'status' => 200, 'text' => $text, 'findings' => []], $s->screenText($text, $mode), "clean $i $mode");
        }
    }
}

// SCREEN-02
/** SCREEN-02: every key shape with its label and exact span; the four near-misses are not found. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_screen02_key_shapes(): void
{
    table(new_screener(), vectors02(), 'SCREEN-02');
}

// SCREEN-03
/** SCREEN-03: private key blocks, encrypted, cut off, quoted, diffed; bare header not. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_screen03_private_key_blocks(): void
{
    table(new_screener(), vectors03(), 'SCREEN-03');
}

// SCREEN-04
/** SCREEN-04: bearer tokens and URL passwords; prose and placeholders not. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_screen04_bearer_and_url_credentials(): void
{
    table(new_screener(), vectors04(), 'SCREEN-04');
}

// SCREEN-05
/** SCREEN-05: key = value assignments in every form; placeholders, references and plain words not. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_screen05_key_value_assignments(): void
{
    table(new_screener(), vectors05(), 'SCREEN-05');
}

// SCREEN-06
/** SCREEN-06: emails, phones and SSNs; near-misses not. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_screen06_email_phone_ssn(): void
{
    table(new_screener(), vectors06(), 'SCREEN-06');
}

// SCREEN-07
/** SCREEN-07: card numbers need a network prefix, Luhn and card grouping. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_screen07_card_numbers(): void
{
    table(new_screener(), vectors07(), 'SCREEN-07');
}

// SCREEN-08
/** SCREEN-08: public IPv4 and global IPv6 only. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_screen08_ip_addresses(): void
{
    table(new_screener(), vectors08(), 'SCREEN-08');
}

// SCREEN-09
/**
 * SCREEN-09: reject answers 422 with the findings and holds neither the text nor a matched value; with
 * categories ["secret"] the same text is ok. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
 */
function test_screen09_reject_mode(): void
{
    $s = new_screener(hashKey());
    $r = $s->screenText(T);
    eq(['ok' => false, 'error' => 'secrets_or_pii_detected', 'status' => 422, 'findings' => tFindings()], $r, 'reject T');
    $json = json_encode($r);
    eq(false, strpos($json, 'jane@example.com'), 'no email in the result');
    eq(false, strpos($json, '555-123-4567'), 'no phone in the result');
    eq(false, strpos($json, 'Contact'), 'no text in the result');
    eq(['ok' => true, 'status' => 200, 'text' => T, 'findings' => []], $s->screenText(T, 'reject', ['secret']), 'secret only');
}

// SCREEN-10
/**
 * SCREEN-10: strip replaces each finding by its marker and nothing else; the output screens clean; a match
 * that only appears once its neighbour is gone makes strip answer 422. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
 */
function test_screen10_strip_mode(): void
{
    $s = new_screener(hashKey());
    eq(['ok' => true, 'status' => 200, 'text' => 'Contact [REDACTED:email_address] or call [REDACTED:phone_number] for help.', 'findings' => tFindings()], $s->screenText(T, 'strip'), 'strip T');
    eq(['ok' => true, 'status' => 200, 'text' => 'Contact [REDACTED:email_address] or call [REDACTED:phone_number] for help.', 'findings' => tFindings()], $s->screenText(T, 'strip', ['pii']), 'strip T pii');
    eq('Contact [REDACTED:email_address] or call [REDACTED:phone_number] for help.', $s->redactText(T, tFindings()), 'redact_text');
    $count = 0;
    foreach ([vectors02(), vectors03(), vectors04(), vectors05(), vectors06(), vectors07(), vectors08()] as $table) {
        foreach ($table as $i => [$text, $want]) {
            if ($want === []) {
                continue;
            }
            $r = $s->screenText($text, 'strip');
            eq(true, $r['ok'], "strip vector ok: $i " . json_encode($want));
            if (!$r['ok']) {
                continue;
            }
            // Everything outside the findings is unchanged: rebuild by hand from the findings.
            $chars = preg_split('//u', $text, -1, PREG_SPLIT_NO_EMPTY);
            $expected = '';
            $at = 0;
            foreach ($r['findings'] as $f) {
                $expected .= implode('', array_slice($chars, $at, $f['start'] - $at)) . '[REDACTED:' . $f['label'] . ']';
                $at = $f['end'];
            }
            $expected .= implode('', array_slice($chars, $at));
            eq($expected, $r['text'], "strip text $i");
            eq(['ok' => true, 'status' => 200, 'text' => $r['text'], 'findings' => []], $s->screenText($r['text'], 'reject'), "rescreen $i");
            $count++;
        }
    }
    eq(true, $count >= 60, 'every vector with a finding was stripped');
    $r = $s->screenText('jane@example.com555-123-4567', 'strip');
    eq(false, $r['ok'], 'neighbour match ok');
    eq(422, $r['status'], 'neighbour match status');
    eq('secrets_or_pii_detected', $r['error'], 'neighbour match error');
    eq(false, isset($r['text']), 'no text in the refusal');
    eq([['phone_number', 16, 28], ['email_address', -1, -1]], array_map(static fn($f) => [$f['label'], $f['start'], $f['end']], $r['findings']), 'neighbour findings');
}

// SCREEN-11
/** SCREEN-11: earliest start, then longest, then lower detector; offsets in code points. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_screen11_overlaps_and_code_points(): void
{
    $s = new_screener();
    eq(['email_address 3-9'], spans($s, "\u{e9}\u{1F600} a@b.co"), 'code points');
    eq(['openai_style_api_key 6-33'], spans($s, 'token=' . V('K1')), 'key beats assignment');
    eq(['openai_style_api_key 7-34'], spans($s, 'Bearer ' . V('K1')), 'key beats bearer');
}

// SCREEN-12
/**
 * SCREEN-12: mask, value_hash with and without a key, a short key refused at construction.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
 */
function test_screen12_mask_hash_and_key(): void
{
    eq(str_repeat('*', 15), mask(str_repeat('a', 15)), 'mask 15');
    eq('ab************op', mask('abcdefghijklmnop'), 'mask 16');
    eq('sk' . str_repeat('*', 23) . 'OP', mask(V('K1')), 'mask K1');
    $f = (new Screener(hashKey()))->scanText(T);
    eq('9487588974759d303d5d44401791a603ad85fda9276d43f7436077d709d9da10', $f[0]['value_hash'], 'hash email');
    eq('ee171612a2f4984e73ec9377b4d10f2b76125f5adf8e4315f12e77ebb2cd41c3', $f[1]['value_hash'], 'hash phone');
    $f = (new Screener())->scanText(T);
    eq([null, null], [$f[0]['value_hash'], $f[1]['value_hash']], 'no key, no hash');
    $code = null;
    try {
        new_screener(substr(hashKey(), 0, 31));
    } catch (ScreeningError $e) {
        $code = $e->getErrorCode();
    }
    eq('invalid_hash_key', $code, 'short key refused');
}

// SCREEN-13
/**
 * SCREEN-13: E1-E8, the texts as their exact characters (nowdoc), in both modes.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
 */
function test_screen13_hidden_behind_escapes(): void
{
    $s = new_screener();
    $sk = 'sk' . '\u002d' . 'abcdEFGH12345678ijklMNOP';
    $E1 = '{"note": "' . $sk . '"}';
    $E2 = '{"outer": "{\"k\": \"sk\\\\u002d' . 'abcdEFGH12345678ijklMNOP\"}"}';
    $E3 = <<<'TXT'
{"msg": "the escape \u00e9 prints an e-acute and \n is a newline"}
TXT;
    $E4 = <<<'TXT'
{"contact": "jane\u0040example.com"}
TXT;
    $E5 = <<<'TXT'
{"emoji": "\ud83d\ude00 ok", "path": "C:\\Users\\name\\notes.txt"}
TXT;
    $E6 = '{"key": "' . str_replace("\n", '\n', V('P1')) . '"}';
    $E7 = '{"key": "' . str_replace("\n", '\n', V('P2')) . '"}';
    $E8 = str_repeat('\\', 600) . 'n';
    eq('{"outer": "{\"k\": \"sk\\\\u002dabcdEFGH12345678ijklMNOP\"}"}', $E2, 'E2 characters');
    eq(1, substr_count($E2, '\\\\'), 'E2 holds one doubled backslash');
    $enc = static fn(array $r): array => array_map(static fn($f) => [$f['label'], $f['start'], $f['end'], $f['encoded']], $r['findings'] ?? []);
    foreach (['reject', 'strip'] as $mode) {
        foreach (['E1' => $E1, 'E2' => $E2] as $n => $t) {
            $r = $s->screenText($t, $mode);
            eq([false, 422], [$r['ok'], $r['status']], "$n $mode");
            eq([['openai_style_api_key', -1, -1, true]], $enc($r), "$n $mode findings");
        }
        foreach (['E3' => $E3, 'E5' => $E5] as $n => $t) {
            eq(['ok' => true, 'status' => 200, 'text' => $t, 'findings' => []], $s->screenText($t, $mode), "$n $mode");
        }
        $r = $s->screenText($E4, $mode);
        eq([false, 422, [['email_address', -1, -1, true]]], [$r['ok'], $r['status'], $enc($r)], "E4 $mode");
        $r = $s->screenText($E7, $mode);
        eq([false, 422, [['pem_private_key', -1, -1, true]]], [$r['ok'], $r['status'], $enc($r)], "E7 $mode");
        $r = $s->screenText($E8, $mode);
        eq([false, 422, [['unresolved_escape', -1, -1, true]]], [$r['ok'], $r['status'], $enc($r)], "E8 $mode");
        eq(['category' => 'secret', 'label' => 'unresolved_escape', 'start' => -1, 'end' => -1, 'preview' => '***', 'value_hash' => null, 'encoded' => true], $r['findings'][0] ?? null, "E8 $mode finding");
    }
    $r = $s->screenText($E6, 'reject');
    eq([false, 422, [['pem_private_key', 9, 202, false]]], [$r['ok'], $r['status'], $enc($r)], 'E6 reject');
    $r = $s->screenText($E6, 'strip');
    eq(['ok' => true, 'status' => 200, 'text' => '{"key": "[REDACTED:pem_private_key]"}'], ['ok' => $r['ok'], 'status' => $r['status'], 'text' => $r['text'] ?? null], 'E6 strip');
    eq(['text' => "\u{e9}\n", 'unresolved' => false], resolve_escapes('\u00e9\n'), 'resolve_escapes one pass');
    eq(['text' => "\u{1F600}\u{FFFD}", 'unresolved' => false], resolve_escapes('\ud83d\ude00\udc00'), 'surrogates');
}

// SCREEN-14
/**
 * SCREEN-14: invalid_mode, invalid_categories and text_too_large before any scan; every hostile 200,000
 * character input screened (strip) in under 2 seconds. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * "token=$" * 28571 added 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP) with the spec note that detector 13 stays linear.
 * Touches: memory, the clock (timing only).
 */
function test_screen14_limits_and_hostile_inputs(): void
{
    $s = new_screener();
    eq(['ok' => false, 'error' => 'invalid_mode', 'status' => 400], $s->screenText('x', 'mask'), 'mode');
    eq(['ok' => false, 'error' => 'invalid_categories', 'status' => 400], $s->screenText('x', 'reject', []), 'empty categories');
    eq(['ok' => false, 'error' => 'invalid_categories', 'status' => 400], $s->screenText('x', 'reject', ['secret', 'keys']), 'unknown category');
    $e5 = str_repeat("\u{e9}", 5);
    eq(['ok' => false, 'error' => 'text_too_large', 'status' => 413], new_screener(null, 9)->screenText($e5), 'too large');
    eq(['ok' => true, 'status' => 200, 'text' => $e5, 'findings' => []], new_screener(null, 10)->screenText($e5), 'fits');
    // Extra (not a required id): the byte FF is not well-formed UTF-8.
    eq(['ok' => false, 'error' => 'invalid_text', 'status' => 400], $s->screenText("a\xFFb"), 'invalid utf-8');
    // The size check comes before any scan: a secret in an oversized text is still 413.
    eq(413, new_screener(null, 10)->screenText('token=' . V('K1'))['status'], 'size before scan');
    $B = V('B');
    $hostile = [
        str_repeat('a.', 100000),
        str_repeat('-----BEGIN ' . 'PRIVATE KEY-----', 7400),
        str_repeat('1234-', 40000),
        str_repeat('eyJ', 66666),
        str_repeat('xeyJ-', 40000),
        str_repeat('xsk-', 50000),
        'password' . str_repeat(' ', 199990),
        str_repeat('token=[REDACTED:', 12500),
        str_repeat('token=$', 28571),
        str_repeat('a://b:', 33000),
        str_repeat('ab:', 66000),
        str_repeat('1.1.', 50000),
        str_repeat('\\n', 100000),
        $B . str_repeat("\n", 199969),
        $B . str_repeat("\n" . str_repeat('A', 64), 3000),
    ];
    foreach ($hostile as $i => $text) {
        $t0 = hrtime(true);
        $r = $s->screenText($text, 'strip');
        $ms = (hrtime(true) - $t0) / 1e6;
        eq(true, $ms < 2000, "hostile $i took {$ms} ms");
        eq(true, $r['status'] !== 500, "hostile $i did not fail the engine");
    }
}

$tests = array_filter(get_defined_functions()['user'], static fn(string $f): bool => str_starts_with($f, 'test_'));
foreach ($tests as $t) {
    $before = $GLOBALS['FAILS'];
    try {
        $t();
    } catch (Throwable $e) {
        $GLOBALS['FAILS']++;
        echo "  EXCEPTION in $t: " . get_class($e) . ' ' . $e->getMessage() . "\n";
    }
    echo ($GLOBALS['FAILS'] === $before ? 'PASS ' : 'FAIL ') . $t . "\n";
}
echo $GLOBALS['FAILS'] === 0 ? "All tests passed\n" : "{$GLOBALS['FAILS']} assertion(s) failed\n";
exit($GLOBALS['FAILS'] === 0 ? 0 : 1);

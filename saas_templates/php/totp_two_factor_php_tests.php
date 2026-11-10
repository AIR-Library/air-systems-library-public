<?php
/**
 * TOTP two-factor tests (docs/specs/totp_two_factor.md, TOTP-01..14).
 *
 * Self-running script on an in-memory SQLite store, with an injected clock and an injected byte source (a
 * queue for the spec's vectors, a deterministic hash stream elsewhere), so nothing depends on the time of day
 * or on chance. Exits 1 on any failure.
 *
 * Why: Phase D wave 1, owner request 2026-11-10. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory and in-memory SQLite only (no files, network or money).
 */

declare(strict_types=1);

require_once __DIR__ . '/totp_two_factor_php.php';

use TotpTwoFactor\SqlTotpStore;
use TotpTwoFactor\TotpError;
use TotpTwoFactor\TotpService;
use function TotpTwoFactor\base32_decode;
use function TotpTwoFactor\base32_encode;
use function TotpTwoFactor\hotp;
use function TotpTwoFactor\open;
use function TotpTwoFactor\otpauth_uri;
use function TotpTwoFactor\seal;
use function TotpTwoFactor\totp_at;

$GLOBALS['FAILS'] = 0;

/**
 * Assert identity. In: expected, actual, label. Out: none; prints and counts a failure.
 * Why: test helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: stdout.
 */
function eq($expected, $actual, string $msg): void
{
    if ($expected !== $actual) {
        $GLOBALS['FAILS']++;
        echo "  FAIL $msg\n    expected: " . var_export($expected, true) . "\n    actual:   " . var_export($actual, true) . "\n";
    }
}

const K = '12345678901234567890';
const SEALED = 'v1.oKGio6SlpqeoqaqroV0maQKFQOklPLSHVjWKjzfpA1TV+QA621cV0i7kP1B5d8k2owRGDhH/FzF0f662';

/** The spec's encryption_key 00..1f. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
function encKey(): string
{
    return implode('', array_map('chr', range(0x00, 0x1f)));
}

/** The spec's recovery_hash_key 40..5f. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
function recKey(): string
{
    return implode('', array_map('chr', range(0x40, 0x5f)));
}

/**
 * A mutable test clock. Why: injected clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
final class TestClock
{
    public int $now;

    /** In: start time. Out: the clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    public function __construct(int $now)
    {
        $this->now = $now;
    }
}

/**
 * A byte source: first the queued bytes in order whatever n is asked, then a deterministic SHA-256 stream.
 * Why: the spec's queue rule. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
final class ByteQueue
{
    public string $queue;
    public int $served = 0;
    private int $counter = 0;
    private string $seed;

    /** In: queued bytes, a seed for the stream after them. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    public function __construct(string $queue = '', string $seed = 'seed')
    {
        $this->queue = $queue;
        $this->seed = $seed;
    }

    /** In: n. Out: n bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    public function take(int $n): string
    {
        $out = '';
        while (strlen($out) < $n) {
            if ($this->queue !== '') {
                $out .= $this->queue[0];
                $this->queue = substr($this->queue, 1);
            } else {
                $out .= hash('sha256', $this->seed . ':' . $this->counter++, true)[0];
            }
            $this->served++;
        }
        return $out;
    }
}

/**
 * A fresh world: in-memory SQLite, store, clock, byte source and service with issuer "Example App".
 * In: start time, queued bytes, seed, encryption key. Out: [service, store, clock, bytes, pdo].
 * Why: every test starts clean. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
 */
function world(int $now = 1_111_111_000, string $queue = '', string $seed = 'seed', ?PDO $pdo = null): array
{
    $pdo ??= new PDO('sqlite::memory:');
    $store = new SqlTotpStore($pdo);
    $store->migrate();
    $clock = new TestClock($now);
    $bytes = new ByteQueue($queue, $seed);
    $svc = new TotpService($store, encKey(), recKey(), 'Example App', static fn(): int => $clock->now, [$bytes, 'take']);
    return [$svc, $store, $clock, $bytes, $pdo];
}

/**
 * Enroll and confirm a user at the clock's time. In: service, clock, user. Out: [secret, recovery codes].
 * Why: setup for the verify tests. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
 */
function enrolled(TotpService $svc, TestClock $clock, string $user): array
{
    $secret = $svc->enrollStart($user, $user . '@example.com')['secret'];
    $r = $svc->enrollConfirm($user, totp_at($secret, $clock->now));
    return [$secret, $r['recovery_codes']];
}

/**
 * A 6-digit code that matches none of the three window steps. In: secret, now. Out: the code.
 * Why: wrong codes that are certainly wrong. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function wrongCode(string $secret, int $now): string
{
    $window = [totp_at($secret, $now - 30), totp_at($secret, $now), totp_at($secret, $now + 30)];
    for ($i = 0; ; $i++) {
        $c = str_pad((string)$i, 6, '0', STR_PAD_LEFT);
        if (!in_array($c, $window, true)) {
            return $c;
        }
    }
}

// TOTP-01
/** TOTP-01: RFC 4226 and RFC 6238 vectors; a counter above 32 bits. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_totp01_rfc_vectors(): void
{
    $want = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
    foreach ($want as $c => $code) {
        eq($code, hotp(K, $c), "hotp $c");
    }
    eq('999456', hotp(K, 4294967296), 'hotp 2^32');
    $s = base32_encode(K);
    $rows = [[59, '94287082', '287082'], [1111111109, '07081804', '081804'], [1111111111, '14050471', '050471'],
        [1234567890, '89005924', '005924'], [2000000000, '69279037', '279037'], [20000000000, '65353130', '353130']];
    foreach ($rows as [$t, $eight, $six]) {
        eq($eight, totp_at($s, $t, 8), "totp_at $t 8");
        eq($six, totp_at($s, $t, 6), "totp_at $t 6");
    }
}

// TOTP-02
/** TOTP-02: base32 vectors, lenient decode, invalid inputs, generate_secret. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_totp02_base32(): void
{
    $vec = ['' => '', 'f' => 'MY', 'fo' => 'MZXQ', 'foo' => 'MZXW6', 'foob' => 'MZXW6YQ', 'fooba' => 'MZXW6YTB', 'foobar' => 'MZXW6YTBOI'];
    foreach ($vec as $plain => $enc) {
        eq($enc, base32_encode((string)$plain), "encode '$plain'");
        if ($enc !== '') {
            eq((string)$plain, base32_decode($enc), "decode $enc");
        }
    }
    eq('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', base32_encode(K), 'encode K');
    eq('foobar', base32_decode('mzxw 6ytb-oi=='), 'lenient decode');
    eq('f', base32_decode('MZ'), 'MZ');
    foreach (['MZXW6YT1', '', 'M', 'MZX', 'MZXW6Y'] as $bad) {
        $code = null;
        try {
            base32_decode($bad);
        } catch (TotpError $e) {
            $code = $e->getErrorCode();
        }
        eq('invalid_base32', $code, "invalid '$bad'");
    }
    [$svc] = world();
    $g = $svc->generateSecret();
    eq(32, strlen($g), 'generate_secret length');
    eq(20, strlen(base32_decode($g)), 'generate_secret bytes');
}

// TOTP-03
/**
 * TOTP-03: enroll_start returns the secret and exact URI; only the sealed secret (the spec's string) is
 * stored; a second enroll_start before confirming replaces it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 */
function test_totp03_enroll_start(): void
{
    $nonce = implode('', array_map('chr', range(0xa0, 0xab)));
    [$svc, $store] = world(1_111_111_000, K . $nonce);
    $r = $svc->enrollStart('user_1', 'alice@example.com');
    eq(['secret' => 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 'otpauth_uri' => 'otpauth://totp/Example%20App%3Aalice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example%20App&algorithm=SHA1&digits=6&period=30'], $r, 'enroll_start answer');
    eq('otpauth://totp/Example%20App%3Aalice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example%20App&algorithm=SHA1&digits=6&period=30', otpauth_uri(base32_encode(K), 'Example App', 'alice@example.com'), 'otpauth_uri');
    $rows = $store->rows('totp_enrollments', 'user_1');
    eq(1, count($rows), 'one row');
    eq(SEALED, $rows[0]['secret_enc'], 'sealed secret is the spec string');
    eq(false, strpos(json_encode($rows), 'GEZDGNBVGY3TQOJQ'), 'no base32 text stored');
    eq(null, $rows[0]['confirmed_at'], 'unconfirmed');
    $r2 = $svc->enrollStart('user_1', 'alice@example.com');
    $rows2 = $store->rows('totp_enrollments', 'user_1');
    eq(1, count($rows2), 'still one row');
    eq(true, $r2['secret'] !== $r['secret'] && $rows2[0]['secret_enc'] !== SEALED, 'second enroll_start replaced the secret');
}

/** The spec's queue for TOTP-04: K, the nonce, then (7k) mod 256. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function confirmQueue(): string
{
    $q = K . implode('', array_map('chr', range(0xa0, 0xab)));
    for ($k = 0; $k < 400; $k++) {
        $q .= chr((7 * $k) % 256);
    }
    return $q;
}

// TOTP-04
/**
 * TOTP-04: confirm returns the spec's 8 codes (101 bytes drawn) and stores only keyed hashes; the confirming
 * code is then refused; the 409 answers. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
 */
function test_totp04_enroll_confirm(): void
{
    [$svc, $store, $clock, $bytes] = world(1_111_111_109, confirmQueue());
    eq(['error' => 'enrollment_not_started', 'status' => 409], $svc->enrollConfirm('user_1', '081804'), 'nothing started');
    $svc->enrollStart('user_1', 'alice@example.com');
    eq(32, $bytes->served, '32 bytes for enroll_start');
    $r = $svc->enrollConfirm('user_1', '081804');
    $want = ['29gq-y7en-w5ck', 't3ah-rz8f-px6d', 'mv4b-js29-gqy5', 'ckt3-ahrz-8fpx', '6dmv-4bjs-29gq', 'y7en-w5ck-t8fp', 'x6dm-v4bj-s29g', 'qy7e-nw5c-kt3a'];
    eq(['recovery_codes' => $want], $r, 'the spec codes');
    eq(32 + 101, $bytes->served, '101 bytes drawn for the codes');
    foreach ($r['recovery_codes'] as $c) {
        eq(1, preg_match('/^[23456789abcdefghjkmnpqrstvwxyz]{4}-[23456789abcdefghjkmnpqrstvwxyz]{4}-[23456789abcdefghjkmnpqrstvwxyz]{4}$/', $c), "shape $c");
    }
    $stored = array_column($store->rows('totp_recovery_codes', 'user_1'), 'code_hash');
    eq(8, count($stored), '8 hashes');
    eq('d9199ecad0b35d9e2f18857343d7fe79dd5f8425f1c460c88fe18f5c4b4a2645', $stored[0], 'first hash');
    eq(array_map(static fn($c) => $svc->codeHash('user_1', str_replace('-', '', $c)), $want), $stored, 'keyed hashes only');
    eq(false, strpos(json_encode($store->rows('totp_recovery_codes', 'user_1')), '29gq'), 'no plain code stored');
    eq(['error' => 'invalid_code', 'status' => 401], $svc->verify('user_1', '081804'), 'confirming code refused');
    eq(['error' => 'already_enrolled', 'status' => 409], $svc->enrollConfirm('user_1', '081804'), 'second confirm');
    eq(['error' => 'already_enrolled', 'status' => 409], $svc->enrollStart('user_1', 'alice@example.com'), 'enroll_start after confirm');
}

// TOTP-05
/** TOTP-05: the window vector; the two refusals are checked first. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_totp05_window(): void
{
    [$svc, , $clock] = world(1_111_111_000, K . str_repeat("\xa0", 12));
    $secret = $svc->enrollStart('user_1', 'a')['secret'];
    eq(base32_encode(K), $secret, 'secret is K');
    eq(true, isset($svc->enrollConfirm('user_1', totp_at($secret, 1_111_111_000))['recovery_codes']), 'confirmed');
    $clock->now = 1_111_111_109;
    eq(['error' => 'invalid_code', 'status' => 401], $svc->verify('user_1', '150727'), 'two steps back');
    eq(['error' => 'invalid_code', 'status' => 401], $svc->verify('user_1', '266759'), 'two steps ahead');
    foreach (['731029', '081804', '050471'] as $c) {
        eq(['ok' => true, 'method' => 'totp', 'recovery_codes_left' => 8], $svc->verify('user_1', $c), "accept $c");
    }
}

// TOTP-06
/** TOTP-06: replay refusal and the store's claim once per step. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_totp06_replay(): void
{
    [$svc, $store, $clock] = world(1_111_111_000);
    [$secret] = enrolled($svc, $clock, 'u');
    $clock->now = 1_111_112_000;
    $code = totp_at($secret, $clock->now);
    eq(true, $svc->verify('u', $code)['ok'] ?? false, 'first use');
    eq(['error' => 'invalid_code', 'status' => 401], $svc->verify('u', $code), 'replayed');
    eq(['error' => 'invalid_code', 'status' => 401], $svc->verify('u', totp_at($secret, $clock->now - 30)), 'earlier step after a later one');
    eq(true, $svc->verify('u', totp_at($secret, $clock->now + 30))['ok'] ?? false, 'later step accepted');
    $step = intdiv($clock->now, 30) + 5;
    eq([true, false], [$store->claim('u', $step), $store->claim('u', $step)], 'claim once per step');
}

// TOTP-07
/**
 * TOTP-07: spaced and dashed spellings are accepted; malformed inputs are 401 and each adds exactly one
 * failure, each on its own user. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
 */
function test_totp07_input_forms(): void
{
    foreach (['081 804', '081-804', '081804'] as $i => $spelling) {
        [$svc, , $clock] = world(1_111_111_000, K . str_repeat("\x01", 12));
        $svc->enrollStart('u', 'a');
        $svc->enrollConfirm('u', totp_at(base32_encode(K), 1_111_111_000));
        $clock->now = 1_111_111_109;
        eq(['ok' => true, 'method' => 'totp', 'recovery_codes_left' => 8], $svc->verify('u', $spelling), "spelling $i");
    }
    [$svc, $store, $clock] = world(1_111_111_000);
    $bad = ['12345', '1234567', 'abcdef', '', null, '081804' . str_repeat(' ', 59), "\u{0660}\u{0668}\u{0661}\u{0668}\u{0660}\u{0664}", "\u{FF10}\u{FF18}\u{FF11}\u{FF18}\u{FF10}\u{FF14}"];
    foreach ($bad as $i => $code) {
        $user = "bad_$i";
        [$secret] = enrolled($svc, $clock, $user);
        $clock->now += 60;
        if ($i === 5) {
            eq(65, strlen($code), 'over 64 characters');
            $code = totp_at($secret, $clock->now) . str_repeat(' ', 59);
        }
        try {
            $r = $svc->verify($user, $code);
        } catch (Throwable $e) {
            $r = 'exception ' . get_class($e);
        }
        eq(['error' => 'invalid_code', 'status' => 401], $r, "bad input $i");
        eq(1, count($store->rows('totp_failures', $user)), "one failure row $i");
        eq(1, (int)$store->rows('totp_enrollments', $user)[0]['failed_since_success'], "failed_since_success $i");
    }
}

// TOTP-08
/**
 * TOTP-08: recovery codes sign in once, in any case and without dashes; never for another user; the stored
 * hash is the spec's keyed hash. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
 */
function test_totp08_recovery_codes(): void
{
    [$svc, $store, $clock] = world(1_111_111_000, '', 'a');
    [, $codes] = enrolled($svc, $clock, 'user_a');
    [, $codesB] = enrolled($svc, $clock, 'user_b');
    eq(['ok' => true, 'method' => 'recovery_code', 'recovery_codes_left' => 7], $svc->verify('user_a', $codes[0]), 'first use');
    eq(['error' => 'invalid_code', 'status' => 401], $svc->verify('user_a', $codes[0]), 'used again');
    eq(['ok' => true, 'method' => 'recovery_code', 'recovery_codes_left' => 6], $svc->verify('user_a', strtoupper($codes[1])), 'upper case');
    eq(['ok' => true, 'method' => 'recovery_code', 'recovery_codes_left' => 5], $svc->verify('user_a', str_replace('-', '', $codes[2])), 'no dashes');
    eq(['error' => 'invalid_code', 'status' => 401], $svc->verify('user_b', $codes[3]), "A's code for B");
    eq(8, $store->recoveryLeft('user_b'), 'B unchanged');
    $h = $svc->codeHash('user_1', 'k7mq2xpt9hcw');
    eq('5a93360f78c7f03de7336a625adf93bf238749d8da4aaf734271b327c52347a3', $h, 'spec code_hash');
    eq(true, $h !== hash('sha256', 'k7mq2xpt9hcw') && $h !== hash('sha256', 'K7MQ-2XPT-9HCW'), 'not a plain sha256');
    $stored = array_column($store->rows('totp_recovery_codes', 'user_a'), 'code_hash');
    eq($svc->codeHash('user_a', str_replace('-', '', $codes[0])), $stored[0], 'stored keyed hash');
}

// TOTP-09
/**
 * TOTP-09: 5 failures inside 900 s lock the user (correct code too, no failure added); 899 s after the oldest
 * still locked, at 900 s a correct code is accepted; the store's try write succeeds 5 times, not a 6th.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
 */
function test_totp09_lock(): void
{
    [$svc, $store, $clock] = world(1_111_000_000);
    [$secret] = enrolled($svc, $clock, 'u');
    $t0 = 1_111_100_000;
    for ($i = 0; $i < 5; $i++) {
        $clock->now = $t0 + 10 * $i;
        eq(['error' => 'invalid_code', 'status' => 401], $svc->verify('u', wrongCode($secret, $clock->now)), "failure $i");
    }
    eq(['error' => 'locked', 'status' => 429, 'retry_after' => 860], $svc->verify('u', totp_at($secret, $clock->now)), 'locked with a correct code');
    eq(5, count($store->rows('totp_failures', 'u')), 'no failure added');
    eq(5, (int)$store->rows('totp_enrollments', 'u')[0]['failed_since_success'], 'count unchanged');
    eq($t0 + 900, $svc->status('u')['locked_until'], 'status locked_until');
    $clock->now = $t0 + 899;
    eq(['error' => 'locked', 'status' => 429, 'retry_after' => 1], $svc->verify('u', totp_at($secret, $clock->now)), '899 s');
    $clock->now = $t0 + 900;
    eq(['ok' => true, 'method' => 'totp', 'recovery_codes_left' => 8], $svc->verify('u', totp_at($secret, $clock->now)), '900 s');
    $got = [];
    for ($i = 0; $i < 6; $i++) {
        $got[] = $store->tryWrite('other', 5000) !== null;
    }
    eq([true, true, true, true, true, false], $got, 'try write 5 times, not a 6th');
}

// TOTP-10
/**
 * TOTP-10: a sealed secret that cannot be opened (another key, one changed character) is 503
 * secret_unreadable for a 6-digit code, adds no failure, and a recovery code still signs in.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
 */
function test_totp10_secret_unreadable(): void
{
    [$svc, $store, $clock, , $pdo] = world(1_111_111_000);
    [$secret, $codes] = enrolled($svc, $clock, 'u');
    $clock->now += 300;
    $other = new TotpService($store, str_repeat("\x07", 32), recKey(), 'Example App', static fn(): int => $clock->now);
    eq(['error' => 'secret_unreadable', 'status' => 503], $other->verify('u', totp_at($secret, $clock->now)), 'another key');
    eq([0, 0], [count($store->rows('totp_failures', 'u')), (int)$store->rows('totp_enrollments', 'u')[0]['failed_since_success']], 'no failure added');
    eq(['ok' => true, 'method' => 'recovery_code', 'recovery_codes_left' => 7], $other->verify('u', $codes[0]), 'recovery code with another key');
    $enc = $store->rows('totp_enrollments', 'u')[0]['secret_enc'];
    $pos = 10;
    $changed = substr($enc, 0, $pos) . ($enc[$pos] === 'A' ? 'B' : 'A') . substr($enc, $pos + 1);
    $pdo->prepare('UPDATE totp_enrollments SET secret_enc = ? WHERE user_id = ?')->execute([$changed, 'u']);
    $clock->now += 300;
    eq(['error' => 'secret_unreadable', 'status' => 503], $svc->verify('u', totp_at($secret, $clock->now)), 'one changed character');
    eq(0, count($store->rows('totp_failures', 'u')), 'still no failure');
    eq(['ok' => true, 'method' => 'recovery_code', 'recovery_codes_left' => 6], $svc->verify('u', $codes[1]), 'recovery code still works');
}

// TOTP-11
/** TOTP-11: seal/open vectors and key sizes at construction. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_totp11_seal_open_and_keys(): void
{
    $nonce = implode('', array_map('chr', range(0xa0, 0xab)));
    $secret = base32_encode(K);
    eq(SEALED, seal(encKey(), $nonce, $secret, 'totp:user_1'), 'seal vector');
    eq($secret, open(encKey(), SEALED, 'totp:user_1'), 'open');
    eq(null, open(encKey(), SEALED, 'totp:user_2'), "another user's aad");
    eq(null, open(str_repeat("\x01", 32), SEALED, 'totp:user_1'), 'another key');
    eq(null, open(encKey(), substr(SEALED, 0, 20) . 'A' . substr(SEALED, 21), 'totp:user_1'), 'one changed character');
    eq(null, open(encKey(), substr(SEALED, 3), 'totp:user_1'), 'no prefix');
    eq(null, open(encKey(), 'v1.' . base64_encode(str_repeat('x', 27)), 'totp:user_1'), 'too short');
    eq(null, open(encKey(), 'v1.***', 'totp:user_1'), 'bad base64');
    $store = new SqlTotpStore(new PDO('sqlite::memory:'));
    foreach ([[str_repeat('k', 31), recKey()], [str_repeat('k', 33), recKey()], [encKey(), str_repeat('r', 31)]] as $i => [$ek, $rk]) {
        $code = null;
        try {
            new TotpService($store, $ek, $rk, 'Example App');
        } catch (TotpError $e) {
            $code = $e->getErrorCode();
        }
        eq('invalid_key', $code, "bad key $i");
    }
}

// TOTP-12
/**
 * TOTP-12: disable with a wrong code deletes nothing; with a valid code deletes the enrollment, codes and
 * failures, and verify is then 409. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
 */
function test_totp12_disable(): void
{
    [$svc, $store, $clock] = world(1_111_111_000);
    [$secret] = enrolled($svc, $clock, 'u');
    $clock->now += 120;
    eq(['error' => 'invalid_code', 'status' => 401], $svc->disable('u', wrongCode($secret, $clock->now)), 'wrong code');
    eq([1, 8, 1], [count($store->rows('totp_enrollments', 'u')), count($store->rows('totp_recovery_codes', 'u')), count($store->rows('totp_failures', 'u'))], 'nothing deleted');
    eq(['disabled' => true], $svc->disable('u', totp_at($secret, $clock->now)), 'disabled');
    eq([0, 0, 0], [count($store->rows('totp_enrollments', 'u')), count($store->rows('totp_recovery_codes', 'u')), count($store->rows('totp_failures', 'u'))], 'all deleted');
    eq(['error' => 'not_enrolled', 'status' => 409], $svc->verify('u', totp_at($secret, $clock->now + 30)), 'not enrolled after');
}

// TOTP-13
/** TOTP-13: not_enrolled before confirm; users never accept each other's codes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_totp13_not_enrolled_and_isolation(): void
{
    [$svc, , $clock] = world(1_111_111_000, '', 'iso');
    $secret = $svc->enrollStart('u', 'a')['secret'];
    $code = totp_at($secret, $clock->now);
    eq(['error' => 'not_enrolled', 'status' => 409], $svc->verify('u', $code), 'verify before confirm');
    eq(['error' => 'not_enrolled', 'status' => 409], $svc->disable('u', $code), 'disable before confirm');
    eq(['error' => 'not_enrolled', 'status' => 409], $svc->verify('nobody', $code), 'no row');
    $svc->enrollConfirm('u', $code);
    [$secretB] = enrolled($svc, $clock, 'v');
    eq(true, $secret !== $secretB, 'different secrets');
    $clock->now += 300;
    $a = totp_at($secret, $clock->now);
    $b = totp_at($secretB, $clock->now);
    eq(true, $a !== $b, 'different codes at this time');
    eq(['error' => 'invalid_code', 'status' => 401], $svc->verify('v', $a), "A's code for B");
    eq(['error' => 'invalid_code', 'status' => 401], $svc->verify('u', $b), "B's code for A");
    eq(true, $svc->verify('u', $a)['ok'] ?? false, "A's own code");
}

// TOTP-14
/**
 * TOTP-14: after 100 failures with no success a correct code is 429 recovery_required however far the clock
 * moves, adding no failure; a recovery code signs in and resets the count; a success before the 100th failure
 * starts the count again. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
 */
function test_totp14_hard_lock(): void
{
    [$svc, $store, $clock] = world(1_000_000_000);
    [$secret, $codes] = enrolled($svc, $clock, 'u');
    for ($w = 0; $w < 20; $w++) {
        $clock->now += 900;
        for ($i = 0; $i < 5; $i++) {
            eq(['error' => 'invalid_code', 'status' => 401], $svc->verify('u', wrongCode($secret, $clock->now)), "window $w failure $i");
        }
    }
    eq(100, (int)$store->rows('totp_enrollments', 'u')[0]['failed_since_success'], '100 failures');
    $clock->now += 900;
    $failRows = count($store->rows('totp_failures', 'u'));
    eq(['error' => 'recovery_required', 'status' => 429], $svc->verify('u', totp_at($secret, $clock->now)), 'recovery required');
    eq($failRows, count($store->rows('totp_failures', 'u')), 'no failure row added');
    eq(100, (int)$store->rows('totp_enrollments', 'u')[0]['failed_since_success'], 'count unchanged');
    eq(true, $svc->status('u')['recovery_required'], 'status recovery_required');
    $clock->now += 10_000_000;
    eq(['error' => 'recovery_required', 'status' => 429], $svc->verify('u', totp_at($secret, $clock->now)), 'still, much later');
    eq(['ok' => true, 'method' => 'recovery_code', 'recovery_codes_left' => 7], $svc->verify('u', $codes[0]), 'recovery code');
    eq(0, (int)$store->rows('totp_enrollments', 'u')[0]['failed_since_success'], 'count reset');
    $clock->now += 60;
    eq(['ok' => true, 'method' => 'totp', 'recovery_codes_left' => 7], $svc->verify('u', totp_at($secret, $clock->now)), 'totp again');

    [$svc2, $store2, $clock2] = world(1_000_000_000);
    [$s2] = enrolled($svc2, $clock2, 'w');
    $n = 0;
    while ($n < 99) {
        $clock2->now += 900;
        for ($i = 0; $i < 5 && $n < 99; $i++, $n++) {
            $svc2->verify('w', wrongCode($s2, $clock2->now));
        }
    }
    eq(99, (int)$store2->rows('totp_enrollments', 'w')[0]['failed_since_success'], '99 failures');
    $clock2->now += 900;
    eq(true, $svc2->verify('w', totp_at($s2, $clock2->now))['ok'] ?? false, 'success before the 100th');
    eq(0, (int)$store2->rows('totp_enrollments', 'w')[0]['failed_since_success'], 'count starts again');
    $clock2->now += 60;
    $svc2->verify('w', wrongCode($s2, $clock2->now));
    eq(1, (int)$store2->rows('totp_enrollments', 'w')[0]['failed_since_success'], 'one failure after');
    $clock2->now += 60;
    eq(true, $svc2->verify('w', totp_at($s2, $clock2->now))['ok'] ?? false, 'not recovery_required');
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

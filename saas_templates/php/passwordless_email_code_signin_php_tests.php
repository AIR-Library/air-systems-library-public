<?php
/**
 * Passwordless email-code sign-in tests (docs/specs/passwordless_email_code_signin.md, EMAILCODE-01..14).
 *
 * Self-running script on in-memory SQLite, a fake sender that records its calls (no network), a fake
 * revoke_unproven hook, an injected clock and injected codes or bytes. Exits 1 on any failure.
 *
 * Why: Phase D wave 1, owner request 2026-11-10. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory and in-memory SQLite only.
 */

declare(strict_types=1);

require_once __DIR__ . '/passwordless_email_code_signin_php.php';

use PasswordlessEmailCodeSignin\AccountStore;
use PasswordlessEmailCodeSignin\EmailCodeSignin;
use PasswordlessEmailCodeSignin\SigninError;
use PasswordlessEmailCodeSignin\SqlAccountStore;
use PasswordlessEmailCodeSignin\SqlCodeStore;
use function PasswordlessEmailCodeSignin\normalize_email;

$GLOBALS['FAILS'] = 0;

/**
 * Assert identity. In: expected, actual, label. Out: none. Why: test helper. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: stdout.
 */
function eq($expected, $actual, string $msg): void
{
    if ($expected !== $actual) {
        $GLOBALS['FAILS']++;
        echo "  FAIL $msg\n    expected: " . var_export($expected, true) . "\n    actual:   " . var_export($actual, true) . "\n";
    }
}

const SECRET = '0123456789abcdef0123456789abcdef';
const T0 = 1_699_920_000;
const OK202 = ['status' => 202, 'sent' => true, 'expires_in' => 600];
const INVALID = ['error' => 'invalid_code', 'status' => 400];
const LIMITED = ['error' => 'too_many_requests', 'status' => 429];

/** Fake sender. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
final class FakeSender
{
    public array $calls = [];
    public string $mode = 'ok';

    /** Records (to, code, expires_in); answers per mode. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    public function __invoke(string $to, string $code, int $expires): bool
    {
        $this->calls[] = [$to, $code, $expires];
        if ($this->mode === 'throw') {
            throw new RuntimeException('smtp down');
        }
        return $this->mode === 'ok';
    }

    /** The last code sent. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    public function last(): string
    {
        return end($this->calls)[1];
    }
}

/** Account store spy: counts calls, delegates to SQL. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
final class SpyAccounts implements AccountStore
{
    public int $calls = 0;

    /** In: the real store. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    public function __construct(private SqlAccountStore $inner)
    {
    }

    /** Counted. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    public function findByEmail(string $email): ?array
    {
        $this->calls++;
        return $this->inner->findByEmail($email);
    }

    /** Counted. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    public function insertVerifiedIfAbsent(string $id, string $email, int $now): void
    {
        $this->calls++;
        $this->inner->insertVerifiedIfAbsent($id, $email, $now);
    }

    /** Counted. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    public function markVerified(string $id, int $now): void
    {
        $this->calls++;
        $this->inner->markVerified($id, $now);
    }
}

/** Mutable clock and code queue. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
final class Ctx
{
    public int $now = T0;
    public array $codes = [];
    public array $revoked = [];
    public bool $revokeFails = false;
}

/**
 * A fresh world. Codes come from $ctx->codes when queued, else the default generator.
 * Out: [service, code store, spy accounts, sender, ctx, pdo]. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: in-memory SQLite.
 */
function world(): array
{
    $pdo = new PDO('sqlite::memory:');
    $codes = new SqlCodeStore($pdo);
    $codes->migrate();
    $acc = new SqlAccountStore($pdo);
    $acc->migrate();
    $spy = new SpyAccounts($acc);
    $sender = new FakeSender();
    $ctx = new Ctx();
    $svc = null;
    $svc = new EmailCodeSignin($codes, $spy, SECRET, $sender,
        static function (string $id) use ($ctx): void {
            $ctx->revoked[] = $id;
            if ($ctx->revokeFails) {
                throw new RuntimeException('revoke failed');
            }
        },
        static fn(): int => $ctx->now, null,
        static function () use ($ctx, &$svc): string {
            return $ctx->codes !== [] ? array_shift($ctx->codes) : $svc->defaultCode();
        });
    return [$svc, $codes, $spy, $sender, $ctx, $pdo];
}

/** All rows of a table. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite (read). */
function rows(PDO $pdo, string $t): array
{
    return $pdo->query("SELECT * FROM $t ORDER BY rowid")->fetchAll(PDO::FETCH_ASSOC);
}

/** Start and return the code sent. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
function startCode(EmailCodeSignin $svc, FakeSender $s, string $email, string $ip = '198.51.100.1'): string
{
    eq(OK202, $svc->start($email, $ip), "start $email");
    return $s->last();
}

// EMAILCODE-01
/** EMAILCODE-01: the happy path, the second sign-in, and revoke_unproven. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_emailcode01_happy_path(): void
{
    [$svc, , $spy, $sender, $ctx, $pdo] = world();
    eq(OK202, $svc->start('user@example.com', '203.0.113.7'), 'start');
    eq(1, count($sender->calls), 'one send');
    eq(1, preg_match('/^[0-9]{6}$/D', $sender->calls[0][1]), '6-digit code');
    eq(['user@example.com', 600], [$sender->calls[0][0], $sender->calls[0][2]], 'sent to the address');
    $r = $svc->verify('user@example.com', $sender->calls[0][1], '203.0.113.7');
    eq(200, $r['status'], 'verify 200');
    eq(true, $r['new_account'], 'new account');
    $acc = rows($pdo, 'accounts');
    eq([[$r['account_id'], 'user@example.com', T0, 'active']], array_map(static fn($a) => [$a['id'], $a['email'], (int)$a['email_verified_at'], $a['status']], $acc), 'account row');
    eq(32, strlen($r['account_id']), '32 hex characters');
    $ctx->now += 100;
    $r2 = $svc->verify('user@example.com', startCode($svc, $sender, 'user@example.com'), '203.0.113.7');
    eq(['status' => 200, 'account_id' => $r['account_id'], 'email' => 'user@example.com', 'new_account' => false], $r2, 'second sign-in');
    eq([], $ctx->revoked, 'verify-made account never revoked');
    $pdo->exec("INSERT INTO accounts (id, email, email_verified_at, status, created_at) VALUES ('acc_invited', 'invited@example.com', NULL, 'active', 1)");
    $r3 = $svc->verify('invited@example.com', startCode($svc, $sender, 'invited@example.com'), '203.0.113.7');
    eq(['status' => 200, 'account_id' => 'acc_invited', 'email' => 'invited@example.com', 'new_account' => false], $r3, 'unverified row signs in');
    eq(['acc_invited'], $ctx->revoked, 'revoke_unproven once with its id');
    eq($ctx->now, (int)$pdo->query("SELECT email_verified_at FROM accounts WHERE id = 'acc_invited'")->fetchColumn(), 'then verified');
    // If revoke_unproven raises, the row stays unverified and the answer is 500.
    $pdo->exec("INSERT INTO accounts (id, email, email_verified_at, status, created_at) VALUES ('acc_two', 'two@example.com', NULL, 'active', 1)");
    $ctx->revokeFails = true;
    eq(['error' => 'processing_failed', 'status' => 500], $svc->verify('two@example.com', startCode($svc, $sender, 'two@example.com'), '203.0.113.7'), 'revoke raises');
    eq(null, $pdo->query("SELECT email_verified_at FROM accounts WHERE id = 'acc_two'")->fetchColumn(), 'left unverified');
}

// EMAILCODE-02
/** EMAILCODE-02: the stored hashes and keys are the spec's; nothing in clear. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_emailcode02_storage(): void
{
    [$svc, , , , $ctx, $pdo] = world();
    eq('587522269e243312a5d6f20bcdc78dc97a3e644e2ad702cdb94ac9550c03b346', $svc->emailHash('user@example.com'), 'email_hash');
    eq('761f222c89dc1744c480d21e141277cc9af815ee0e2a1d7489c9282594728b5b', $svc->codeHash('user@example.com', '123456'), 'code_hash');
    eq('e01c4eeb03c058165d49564dcaf561cf', $svc->ipHash('203.0.113.7'), 'ip_hash');
    $ctx->codes = ['123456'];
    $svc->start('user@example.com', '203.0.113.7');
    $codes = rows($pdo, 'email_codes');
    eq([['587522269e243312a5d6f20bcdc78dc97a3e644e2ad702cdb94ac9550c03b346', '761f222c89dc1744c480d21e141277cc9af815ee0e2a1d7489c9282594728b5b', T0 + 600, 0]],
        array_map(static fn($r) => [$r['email_hash'], $r['code_hash'], (int)$r['expires_at'], (int)$r['attempts']], $codes), 'email_codes row');
    eq(['start-ip#e01c4eeb03c058165d49564dcaf561cf', 'start-email#587522269e243312a5d6f20bcdc78dc9', 'start-email-day#587522269e243312a5d6f20bcdc78dc9'],
        array_column(rows($pdo, 'rate_windows'), 'key'), 'rate_windows keys');
    $all = json_encode([$codes, rows($pdo, 'rate_windows')]);
    foreach (['user@example.com', '203.0.113.7', '123456', hash('sha256', '123456')] as $plain) {
        eq(false, strpos($all, $plain), "no $plain in storage");
    }
}

// EMAILCODE-03
/** EMAILCODE-03: single use. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
function test_emailcode03_single_use(): void
{
    [$svc, , , $sender] = world();
    $code = startCode($svc, $sender, 'a@x.com');
    eq(200, $svc->verify('a@x.com', $code, '1.1.1.1')['status'], 'first');
    eq(INVALID, $svc->verify('a@x.com', $code, '1.1.1.1'), 'second');
}

// EMAILCODE-04
/** EMAILCODE-04: 599 s accepted, 600 s refused. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
function test_emailcode04_expiry(): void
{
    [$svc, , , $sender, $ctx] = world();
    $a = startCode($svc, $sender, 'a@x.com');
    $b = startCode($svc, $sender, 'b@x.com');
    $ctx->now = T0 + 599;
    eq(200, $svc->verify('a@x.com', $a, '1.1.1.1')['status'], '599 s');
    $ctx->now = T0 + 600;
    eq(INVALID, $svc->verify('b@x.com', $b, '1.1.1.1'), '600 s');
}

/** A wrong code for a known right one. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
function wrong(string $code): string
{
    return str_pad((string)(((int)$code + 1) % 1000000), 6, '0', STR_PAD_LEFT);
}

// EMAILCODE-05
/** EMAILCODE-05: five tries per code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
function test_emailcode05_five_tries(): void
{
    [$svc, , , $sender] = world();
    $code = startCode($svc, $sender, 'a@x.com');
    for ($i = 0; $i < 5; $i++) {
        eq(INVALID, $svc->verify('a@x.com', wrong($code), '1.1.1.1'), "wrong $i");
    }
    eq(INVALID, $svc->verify('a@x.com', $code, '1.1.1.1'), 'right after 5 wrong');
    $code = startCode($svc, $sender, 'b@x.com');
    for ($i = 0; $i < 4; $i++) {
        $svc->verify('b@x.com', wrong($code), '1.1.1.1');
    }
    eq(200, $svc->verify('b@x.com', $code, '1.1.1.1')['status'], 'right as the 5th try');
}

// EMAILCODE-06
/** EMAILCODE-06: a new start replaces the code and resets the tries. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_emailcode06_new_start_replaces(): void
{
    [$svc, , , $sender, $ctx, $pdo] = world();
    $ctx->codes = ['111111', '222222'];
    $first = startCode($svc, $sender, 'a@x.com');
    for ($i = 0; $i < 4; $i++) {
        $svc->verify('a@x.com', wrong($first), '1.1.1.1');
    }
    eq(4, (int)rows($pdo, 'email_codes')[0]['attempts'], '4 tries on the first code');
    $second = startCode($svc, $sender, 'a@x.com');
    eq(0, (int)rows($pdo, 'email_codes')[0]['attempts'], 'tries start again at 0');
    eq(INVALID, $svc->verify('a@x.com', $first, '1.1.1.1'), 'earlier code');
    for ($i = 0; $i < 3; $i++) {
        $svc->verify('a@x.com', wrong($second), '1.1.1.1');
    }
    eq(200, $svc->verify('a@x.com', $second, '1.1.1.1')['status'] ?? null, 'new code accepted as its 5th try');
}

// EMAILCODE-07
/** EMAILCODE-07: no enumeration. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
function test_emailcode07_no_enumeration(): void
{
    [$svc, , $spy, $sender, $ctx, $pdo] = world();
    $pdo->exec("INSERT INTO accounts (id, email, email_verified_at, status, created_at) VALUES ('acc_1', 'known@x.com', 1, 'active', 1)");
    $before = $spy->calls;
    $known = $svc->start('known@x.com', '1.1.1.1');
    $unknown = $svc->start('unknown@x.com', '1.1.1.1');
    eq([OK202, OK202], [$known, $unknown], 'same answer');
    eq($before, $spy->calls, 'start never reads accounts');
    eq([['known@x.com', 1, 600], ['unknown@x.com', 1, 600]], array_map(static fn($c) => [$c[0], preg_match('/^[0-9]{6}$/D', $c[1]), $c[2]], $sender->calls), 'same kind of send');
    $knownCode = $sender->calls[0][1];
    $wrongBody = $svc->verify('known@x.com', wrong($knownCode), '1.1.1.1');
    $usedCode = $sender->calls[1][1];
    $svc->verify('unknown@x.com', $usedCode, '1.1.1.1');
    $usedBody = $svc->verify('unknown@x.com', $usedCode, '1.1.1.1');
    $neverBody = $svc->verify('never@x.com', '123456', '1.1.1.1');
    $ctx->now += 600;
    $expiredBody = $svc->verify('known@x.com', $knownCode, '1.1.1.1');
    eq([INVALID, INVALID, INVALID, INVALID], [$wrongBody, $expiredBody, $usedBody, $neverBody], 'same 400 body');
}

// EMAILCODE-08
/** EMAILCODE-08: sends per address, per hour and per day. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
function test_emailcode08_sends_per_address(): void
{
    [$svc, , , $sender, $ctx] = world();
    for ($i = 1; $i <= 5; $i++) {
        eq(OK202, $svc->start('a@x.com', '1.1.1.1'), "hour 1 start $i");
    }
    eq(LIMITED, $svc->start('a@x.com', '1.1.1.1'), '6th in the hour');
    eq(5, count($sender->calls), 'the 6th sent nothing');
    $ctx->now = 1_699_923_600;
    for ($i = 1; $i <= 4; $i++) {
        eq(OK202, $svc->start('a@x.com', '1.1.1.1'), "hour 2 start $i");
    }
    eq(LIMITED, $svc->start('a@x.com', '1.1.1.1'), '11th in the day');
    eq(9, count($sender->calls), 'nothing sent for it');
    $ctx->now = 1_700_006_400;
    eq(OK202, $svc->start('a@x.com', '1.1.1.1'), 'next day');
}

// EMAILCODE-09
/** EMAILCODE-09: sends per IP. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
function test_emailcode09_sends_per_ip(): void
{
    [$svc] = world();
    for ($i = 1; $i <= 20; $i++) {
        eq(OK202, $svc->start("u$i@x.com", '9.9.9.9'), "start $i");
    }
    eq(LIMITED, $svc->start('u21@x.com', '9.9.9.9'), '21st from the IP');
    eq(OK202, $svc->start('u21@x.com', '8.8.8.8'), 'another IP');
}

// EMAILCODE-10
/** EMAILCODE-10: tries per IP and per address. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
function test_emailcode10_tries(): void
{
    [$svc, , , $sender] = world();
    for ($i = 1; $i <= 30; $i++) {
        eq(INVALID, $svc->verify("n$i@x.com", '123456', '7.7.7.7'), "verify $i");
    }
    $code = startCode($svc, $sender, 'z@x.com', '6.6.6.6');
    eq(LIMITED, $svc->verify('z@x.com', $code, '7.7.7.7'), '31st from the IP, right code');
    $n = 0;
    foreach ([4, 4, 2] as $tries) {
        $code = startCode($svc, $sender, 'y@x.com', '6.6.6.6');
        for ($i = 0; $i < $tries; $i++) {
            $n++;
            eq(INVALID, $svc->verify('y@x.com', wrong($code), "10.0.0.$n"), "address try $n");
        }
    }
    eq(LIMITED, $svc->verify('y@x.com', $code, '10.0.1.1'), '11th for the address, right code, new IP');
}

// EMAILCODE-11
/** EMAILCODE-11: input forms. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
function test_emailcode11_input(): void
{
    eq('a@x.com', normalize_email(' A@X.com '), 'normalize');
    foreach (['a@b', 'a b@x.com', 'a@x..com', '.a@x.com', 'a@x.com,b@y.com', '<a@x.com>', "a@x.com\u{a0}", "a@x.com\x0B", "a@x.com\x00", "\u{212a}@x.com", null, ''] as $i => $bad) {
        eq(null, normalize_email($bad), "normalize bad $i");
    }
    [$svc, , , $sender, $ctx, $pdo] = world();
    $code = startCode($svc, $sender, ' A@X.com ');
    eq('a@x.com', $sender->calls[0][0], 'sent to the normalized address');
    eq(['status' => 200, 'email' => 'a@x.com'], array_intersect_key($svc->verify(' A@X.com ', $code, '1.1.1.1'), ['status' => 1, 'email' => 1]), 'signs in a@x.com');
    foreach (["a@x.com\u{a0}", "a@x.com\x0B", "a@x.com\x00", "\u{212a}@x.com", 'a@b'] as $i => $bad) {
        eq(['error' => 'invalid_email', 'status' => 422], $svc->start($bad, '1.1.1.1'), "start bad $i");
        eq(INVALID, $svc->verify($bad, '123456', '1.1.1.1'), "verify bad $i");
    }
    foreach (['123 456', '123-456'] as $spelling) {
        $ctx->codes = ['123456'];
        startCode($svc, $sender, 'b@x.com', '2.2.2.2');
        eq(200, $svc->verify('b@x.com', $spelling, '2.2.2.2')['status'] ?? null, "spelling $spelling");
    }
    $ctx->codes = ['123456'];
    startCode($svc, $sender, 'c@x.com', '3.3.3.3');
    foreach (['12345', '1234567', 'abcdef', "\u{661}\u{662}\u{663}\u{664}\u{665}\u{666}", null] as $i => $bad) {
        eq(INVALID, $svc->verify('c@x.com', $bad, '3.3.3.3'), "bad code $i");
    }
    eq(0, (int)$pdo->query('SELECT attempts FROM email_codes')->fetchColumn(), 'no try spent');
    eq(200, $svc->verify('c@x.com', '123456', '3.3.3.3')['status'] ?? null, 'the code still works');
}

// EMAILCODE-12
/** EMAILCODE-12: send failures and configuration. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
function test_emailcode12_send_failed_and_config(): void
{
    foreach (['false', 'throw'] as $mode) {
        [$svc, , , $sender, , $pdo] = world();
        $sender->mode = $mode;
        eq(['error' => 'send_failed', 'status' => 503], $svc->start('a@x.com', '1.1.1.1'), "sender $mode");
        eq([], rows($pdo, 'email_codes'), "no code left ($mode)");
    }
    $pdo = new PDO('sqlite::memory:');
    $cases = ['short secret' => [str_repeat('s', 31), new FakeSender()], 'no sender' => [SECRET, null]];
    foreach ($cases as $name => [$secret, $sender]) {
        $code = null;
        try {
            new EmailCodeSignin(new SqlCodeStore($pdo), new SqlAccountStore($pdo), $secret, $sender);
        } catch (SigninError $e) {
            $code = $e->getErrorCode();
        }
        eq('not_configured', $code, $name);
    }
}

// EMAILCODE-13
/** EMAILCODE-13: suspended and closed accounts. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
function test_emailcode13_unavailable_account(): void
{
    [$svc, , , $sender, , $pdo] = world();
    foreach (['suspended', 'closed'] as $status) {
        $email = "$status@x.com";
        $pdo->prepare("INSERT INTO accounts (id, email, email_verified_at, status, created_at) VALUES (?, ?, 1, ?, 1)")->execute(["acc_$status", $email, $status]);
        $code = startCode($svc, $sender, $email);
        eq(['error' => 'account_unavailable', 'status' => 403], $svc->verify($email, $code, '1.1.1.1'), $status);
        eq(INVALID, $svc->verify($email, $code, '1.1.1.1'), "$status code used up");
    }
    eq([], rows($pdo, 'email_codes'), 'no code left');
}

// EMAILCODE-14
/** EMAILCODE-14: codes bound to the address; leading zeros; the generator vectors. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_emailcode14_codes(): void
{
    [$svc, , , $sender, $ctx] = world();
    $ctx->codes = ['111111', '222222'];
    startCode($svc, $sender, 'a@x.com');
    startCode($svc, $sender, 'b@x.com');
    eq(INVALID, $svc->verify('b@x.com', '111111', '1.1.1.1'), "a's code for b");
    $ctx->codes = ['000042'];
    eq('000042', startCode($svc, $sender, 'z@x.com'), 'leading zeros sent');
    eq(200, $svc->verify('z@x.com', '000042', '1.1.1.1')['status'] ?? null, '000042 signs in');
    $queue = hex2bin('ffffffff' . '80000000' . 'fff13d7f' . 'fff13d80' . '0000002a');
    $bytes = static function (int $n) use (&$queue): string {
        $out = substr($queue, 0, $n);
        $queue = substr($queue, $n);
        return $out;
    };
    $pdo = new PDO('sqlite::memory:');
    $gen = new EmailCodeSignin(new SqlCodeStore($pdo), new SqlAccountStore($pdo), SECRET, new FakeSender(), null, null, $bytes);
    eq(['483648', '999999', '000042'], [$gen->defaultCode(), $gen->defaultCode(), $gen->defaultCode()], 'generator vectors');
    eq('', $queue, 'every byte drawn');
    $real = new EmailCodeSignin(new SqlCodeStore($pdo), new SqlAccountStore($pdo), SECRET, new FakeSender());
    for ($i = 0; $i < 50; $i++) {
        eq(1, preg_match('/^[0-9]{6}$/D', $real->defaultCode()), 'default generator 6 digits');
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

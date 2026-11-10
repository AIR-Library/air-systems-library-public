<?php
/**
 * BYOK key vault tests (docs/specs/byok_key_vault.md, VAULT-01..14).
 *
 * Self-running script on an in-memory SQLite store with a fake provider client (no network), an injected
 * clock and an injected byte queue for the known-answer vectors. Exits 1 on any failure. The test key is
 * built from two pieces at run time.
 *
 * Why: Phase D wave 1, owner request 2026-11-10. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory and in-memory SQLite only.
 */

declare(strict_types=1);

require_once __DIR__ . '/byok_key_vault_php.php';

use ByokKeyVault\KeyVault;
use ByokKeyVault\ProviderClient;
use ByokKeyVault\SqlVaultStore;
use ByokKeyVault\VaultError;

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

/** The spec's key, from two pieces. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
function theKey(): string
{
    return 'acme_' . 'k3y0123456789abcdefghWXYZ';
}

const CIPHERTEXT = 'YGFiY2RlZmdoaWprg/fAzqy7SCzJdVWPIX9FTko++mAiaT2vbM/uMNaLHZjhWoVBGl1vBtJurMStRQ==';
const WRAPPED = 'cHFyc3R1dnd4eXp7N6aYBJfsuhNsAxz5/W2f+J0G974wrnqNnbcDf3iKKAEOSVqlT/aJkU58qxAv2nPf';
const REWRAPPED = 'gIGCg4SFhoeIiYqLDX+c5AZRDKRAQ7oDXo+7DcjN++F5UtAjxrdC7+0oX0MOT3cH13mFkfvVnrrN/V6R';

/** n bytes start, start+1, ... 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
function seq(int $start, int $n): string
{
    return implode('', array_map('chr', range($start, $start + $n - 1)));
}

/**
 * Fake provider client: answers a fixed value (or throws) and records each call.
 * Why: no network in tests. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
final class FakeProvider implements ProviderClient
{
    public array $calls = [];
    public $answer = 'ok';

    /** Records the call; throws when the answer is 'throw'. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    public function check(string $provider, string $key)
    {
        $this->calls[] = [$provider, $key];
        if ($this->answer === 'throw') {
            throw new RuntimeException('provider down');
        }
        return $this->answer;
    }
}

/** Mutable clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
final class Clock
{
    public int $now = 1_699_920_000;
}

/**
 * Byte queue: serves queued bytes first, then the CSPRNG. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the CSPRNG once the queue is empty.
 */
final class Bytes
{
    public string $q = '';

    /** In: n. Out: n bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    public function take(int $n): string
    {
        $out = substr($this->q, 0, $n);
        $this->q = substr($this->q, strlen($out));
        return $out . ($n > strlen($out) ? random_bytes($n - strlen($out)) : '');
    }
}

/** The spec's providers. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
function providers(): array
{
    return ['acme' => ['prefix' => 'acme_', 'min_length' => 24, 'max_length' => 200], 'beta' => ['prefix' => 'beta_', 'min_length' => 24, 'max_length' => 200]];
}

/**
 * A fresh vault on in-memory SQLite with keyring {k1}. Out: [vault, store, provider, clock, bytes].
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
 */
function world(?array $keys = null, string $active = 'k1', ?SqlVaultStore $store = null, ?Clock $clock = null, ?Bytes $bytes = null, ?FakeProvider $p = null): array
{
    if ($store === null) {
        $store = new SqlVaultStore(new PDO('sqlite::memory:'));
        $store->migrate();
    }
    $clock ??= new Clock();
    $bytes ??= new Bytes();
    $p ??= new FakeProvider();
    $vault = new KeyVault($store, $keys ?? ['k1' => seq(0x00, 32)], $active, providers(), $p, static fn(): int => $clock->now, [$bytes, 'take']);
    return [$vault, $store, $p, $clock, $bytes];
}

/** All rows of a table. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite (read). */
function rows(SqlVaultStore $s, string $table): array
{
    return $s->db->query("SELECT * FROM $table ORDER BY rowid")->fetchAll(PDO::FETCH_ASSOC);
}

// VAULT-01
/** VAULT-01: the happy path. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
function test_vault01_save_happy_path(): void
{
    [$v, $s, $p, $c] = world();
    $r = $v->saveKey('user_1', 'acme', theKey());
    eq(['provider' => 'acme', 'hint' => 'WXYZ', 'key_id' => 'k1', 'created_at' => $c->now], $r, 'answer');
    eq([['acme', theKey()]], $p->calls, 'provider checked once with the key');
    $row = rows($s, 'provider_keys');
    eq(1, count($row), 'one row');
    eq(['user_1', 'acme', 'k1', 'WXYZ'], [$row[0]['user_id'], $row[0]['provider'], $row[0]['key_id'], $row[0]['hint']], 'row fields');
    eq(true, $row[0]['wrapped_dek'] !== '' && $row[0]['ciphertext'] !== '', 'envelope stored');
    eq(false, strpos(json_encode([rows($s, 'provider_keys'), rows($s, 'provider_key_audit')]), 'k3y0123456789'), 'key stored nowhere');
    eq([['at' => $c->now, 'action' => 'key_saved', 'provider' => 'acme', 'purpose' => null, 'key_id' => 'k1']], $v->listAudit('user_1'), 'audit key_saved');
}

// VAULT-02
/** VAULT-02: known answer. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
function test_vault02_known_answer(): void
{
    $bytes = new Bytes();
    $bytes->q = seq(0x20, 32) . seq(0x60, 12) . seq(0x70, 12);
    [$v, $s] = world(null, 'k1', null, null, $bytes);
    $v->saveKey('user_1', 'acme', theKey());
    $row = rows($s, 'provider_keys')[0];
    eq(CIPHERTEXT, $row['ciphertext'], 'ciphertext');
    eq(WRAPPED, $row['wrapped_dek'], 'wrapped_dek');
    eq(['key' => theKey()], $v->useKey('user_1', 'acme', 'chat.completion'), 'use_key');
}

// VAULT-03
/**
 * VAULT-03: unknown provider and every malformed key are refused with no provider call and nothing stored.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
 */
function test_vault03_validation(): void
{
    [$v, $s, $p] = world();
    eq(['error' => 'unknown_provider', 'status' => 404], $v->saveKey('user_1', 'nope', theKey()), 'unknown provider');
    $k = theKey();
    $bad = [
        'wrong prefix' => 'beta_' . substr($k, 5),
        'too short' => 'acme_' . 'k3y0123456789abcde',
        'too long' => 'acme_' . str_repeat('x', 196),
        'space inside' => 'acme_' . 'k3y0123456 789abcdefghWXYZ',
        'line break inside' => "acme_k3y0123456\n789abcdefghWXYZ",
        'missing' => null,
        'nbsp after' => $k . "\u{a0}",
        'VT after' => $k . "\x0B",
        'NUL after' => $k . "\x00",
    ];
    foreach ($bad as $name => $key) {
        eq(['error' => 'invalid_key_format', 'status' => 400], $v->saveKey('user_1', 'acme', $key), $name);
    }
    eq([23, 201], [strlen($bad['too short']), strlen($bad['too long'])], 'length vectors are min - 1 and max + 1');
    eq([], $p->calls, 'provider never called');
    eq([[], [], []], [rows($s, 'provider_keys'), rows($s, 'provider_key_audit'), rows($s, 'provider_key_save_windows')], 'nothing stored');
    // Leading and trailing space, tab, CR and LF are trimmed: the same key padded is accepted as the key.
    eq('WXYZ', $v->saveKey('user_1', 'acme', " \t\r\n" . $k . "\r\n\t ")['hint'] ?? null, 'trimmed key accepted');
    eq([['acme', $k]], $p->calls, 'the trimmed key is checked');
}

// VAULT-04
/**
 * VAULT-04: rejected -> 400 key_rejected; unreachable, other answers and a raised error -> 502; nothing written
 * but the check is counted. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
 */
function test_vault04_provider_answers(): void
{
    [$v, $s, $p] = world();
    $cases = ['rejected' => ['error' => 'key_rejected', 'status' => 400], 'unreachable' => ['error' => 'provider_unreachable', 'status' => 502],
        'maybe' => ['error' => 'provider_unreachable', 'status' => 502], 'throw' => ['error' => 'provider_unreachable', 'status' => 502]];
    foreach ($cases as $answer => $want) {
        $p->answer = $answer;
        eq($want, $v->saveKey('user_1', 'acme', theKey()), "answer $answer");
    }
    $p->answer = 42;
    eq(['error' => 'provider_unreachable', 'status' => 502], $v->saveKey('user_1', 'acme', theKey()), 'non-text answer');
    eq([[], []], [rows($s, 'provider_keys'), rows($s, 'provider_key_audit')], 'nothing written');
    eq(5, (int)rows($s, 'provider_key_save_windows')[0]['count'], 'every check counted');
}

// VAULT-05
/** VAULT-05: list_keys fields, order and no secrets. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
function test_vault05_list_keys(): void
{
    [$v, $s, , $c] = world();
    $v->saveKey('user_1', 'beta', 'beta_' . 'zzzz0123456789abcdefgh1234');
    $c->now += 5;
    $v->saveKey('user_1', 'acme', theKey());
    $list = $v->listKeys('user_1');
    eq([
        ['provider' => 'acme', 'hint' => 'WXYZ', 'key_id' => 'k1', 'created_at' => 1_699_920_005, 'last_used_at' => null],
        ['provider' => 'beta', 'hint' => '1234', 'key_id' => 'k1', 'created_at' => 1_699_920_000, 'last_used_at' => null],
    ], $list, 'list');
    $json = json_encode($list);
    foreach (rows($s, 'provider_keys') as $r) {
        eq(false, strpos($json, $r['ciphertext']), 'no ciphertext');
        eq(false, strpos($json, $r['wrapped_dek']), 'no wrapped_dek');
    }
    eq(false, strpos($json, 'k3y0123456789'), 'no key');
}

// VAULT-06
/**
 * VAULT-06: use_key returns the key, sets last_used_at, audits key_used with the purpose; bad purposes are
 * 400; a failing audit write is 500 storage_failed with no key. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: SQLite (a trigger makes the audit insert fail).
 */
function test_vault06_use_key(): void
{
    [$v, $s, , $c] = world();
    $v->saveKey('user_1', 'acme', theKey());
    $c->now += 77;
    eq(['key' => theKey()], $v->useKey('user_1', 'acme', 'chat:v1.completion_x-1'), 'use');
    eq($c->now, $v->listKeys('user_1')[0]['last_used_at'], 'last_used_at');
    eq(['at' => $c->now, 'action' => 'key_used', 'provider' => 'acme', 'purpose' => 'chat:v1.completion_x-1', 'key_id' => 'k1'], $v->listAudit('user_1')[1], 'audit key_used');
    foreach (['', 'has space', 'semi;colon', "caf\u{e9}", str_repeat('a', 101), null] as $i => $bad) {
        eq(['error' => 'invalid_purpose', 'status' => 400], $v->useKey('user_1', 'acme', $bad), "bad purpose $i");
    }
    $s->db->exec("CREATE TRIGGER fail_audit BEFORE INSERT ON provider_key_audit WHEN NEW.action = 'key_used' BEGIN SELECT RAISE(ABORT, 'audit down'); END");
    $before = $v->listKeys('user_1')[0]['last_used_at'];
    $c->now += 10;
    eq(['error' => 'storage_failed', 'status' => 500], $v->useKey('user_1', 'acme', 'chat'), 'audit write fails');
    eq($before, $v->listKeys('user_1')[0]['last_used_at'], 'last_used_at rolled back');
    eq(false, strpos(json_encode(rows($s, 'provider_key_audit')), 'k3y0123456789'), 'no audit row holds the key');
}

// VAULT-07
/** VAULT-07: isolation between users. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
function test_vault07_isolation(): void
{
    [$v] = world();
    $v->saveKey('user_a', 'acme', theKey());
    eq([], $v->listKeys('user_b'), 'B list empty');
    eq(['error' => 'key_not_found', 'status' => 404], $v->useKey('user_b', 'acme', 'chat'), 'B use');
    eq(['deleted' => false], $v->deleteKey('user_b', 'acme'), 'B delete');
    eq(['key' => theKey()], $v->useKey('user_a', 'acme', 'chat'), 'A untouched');
}

// VAULT-08
/**
 * VAULT-08: moved rows, one changed decoded byte, non-base64 and too-short values are 500 key_unreadable,
 * never an exception. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
 */
function test_vault08_tampering(): void
{
    $flip = static function (string $b64): string {
        $raw = base64_decode($b64);
        $raw[20] = chr(ord($raw[20]) ^ 0x01);
        return base64_encode($raw);
    };
    $cases = [
        'moved to another user' => static fn(PDO $db) => $db->exec("UPDATE provider_keys SET user_id = 'user_2'"),
        'moved to another provider' => static fn(PDO $db) => $db->exec("UPDATE provider_keys SET provider = 'beta'"),
        'ciphertext byte 20' => static fn(PDO $db) => $db->prepare('UPDATE provider_keys SET ciphertext = ?')->execute([$flip($db->query('SELECT ciphertext FROM provider_keys')->fetchColumn())]),
        'wrapped_dek byte 20' => static fn(PDO $db) => $db->prepare('UPDATE provider_keys SET wrapped_dek = ?')->execute([$flip($db->query('SELECT wrapped_dek FROM provider_keys')->fetchColumn())]),
        'ciphertext not base64' => static fn(PDO $db) => $db->exec("UPDATE provider_keys SET ciphertext = '***not base64***'"),
        'wrapped_dek not base64' => static fn(PDO $db) => $db->exec("UPDATE provider_keys SET wrapped_dek = '%%%'"),
        'ciphertext too short' => static fn(PDO $db) => $db->prepare('UPDATE provider_keys SET ciphertext = ?')->execute([base64_encode(str_repeat('a', 27))]),
        'wrapped_dek too short' => static fn(PDO $db) => $db->prepare('UPDATE provider_keys SET wrapped_dek = ?')->execute([base64_encode(str_repeat('a', 10))]),
    ];
    foreach ($cases as $name => $tamper) {
        [$v, $s] = world();
        $v->saveKey('user_1', 'acme', theKey());
        $tamper($s->db);
        $user = $name === 'moved to another user' ? 'user_2' : 'user_1';
        $provider = $name === 'moved to another provider' ? 'beta' : 'acme';
        try {
            $r = $v->useKey($user, $provider, 'chat');
        } catch (Throwable $e) {
            $r = 'exception ' . get_class($e);
        }
        eq(['error' => 'key_unreadable', 'status' => 500], $r, $name);
    }
}

// VAULT-09
/** VAULT-09: saving again replaces the key. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
function test_vault09_replace(): void
{
    [$v, $s] = world();
    $v->saveKey('user_1', 'acme', theKey());
    $old = rows($s, 'provider_keys')[0];
    $new = 'acme_' . 'n3wKey0123456789abcdefQRST';
    eq('QRST', $v->saveKey('user_1', 'acme', $new)['hint'] ?? null, 'new hint');
    $rows = rows($s, 'provider_keys');
    eq(1, count($rows), 'one row');
    eq(true, $rows[0]['ciphertext'] !== $old['ciphertext'] && $rows[0]['wrapped_dek'] !== $old['wrapped_dek'], 'new envelope');
    eq(true, substr(base64_decode($rows[0]['ciphertext']), 0, 12) !== substr(base64_decode($old['ciphertext']), 0, 12), 'new data nonce');
    eq(true, substr(base64_decode($rows[0]['wrapped_dek']), 0, 12) !== substr(base64_decode($old['wrapped_dek']), 0, 12), 'new wrap nonce');
    eq('QRST', $rows[0]['hint'], 'stored hint');
    eq(['key' => $new], $v->useKey('user_1', 'acme', 'chat'), 'new key returned');
}

// VAULT-10
/**
 * VAULT-10: rotation to k2, rewrap() with the spec's nonce, k1 removed afterwards, and the store's
 * conditional rewrap write. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
 */
function test_vault10_rotation(): void
{
    $bytes = new Bytes();
    $bytes->q = seq(0x20, 32) . seq(0x60, 12) . seq(0x70, 12);
    [$v1, $s, $p, $c] = world(null, 'k1', null, null, $bytes);
    $v1->saveKey('user_1', 'acme', theKey());
    $keys = ['k1' => seq(0x00, 32), 'k2' => seq(0x40, 32)];
    [$v2] = world($keys, 'k2', $s, $c, $bytes, $p);
    $v2->saveKey('user_2', 'acme', theKey());
    eq('k2', $s->getRow('user_2', 'acme')['key_id'], 'new save under k2');
    $bytes->q = seq(0x80, 12);
    eq(['rewrapped' => 1, 'failed' => 0], $v2->rewrap(), 'rewrap');
    $row = $s->getRow('user_1', 'acme');
    eq(['k2', CIPHERTEXT, REWRAPPED], [$row['key_id'], $row['ciphertext'], $row['wrapped_dek']], 'rewrapped row');
    eq('key_rewrapped', $v2->listAudit('user_1')[1]['action'] ?? null, 'audit key_rewrapped');
    [$v3] = world(['k2' => seq(0x40, 32)], 'k2', $s, $c, $bytes, $p);
    eq(['key' => theKey()], $v3->useKey('user_1', 'acme', 'chat'), 'user_1 opens without k1');
    eq(['key' => theKey()], $v3->useKey('user_2', 'acme', 'chat'), 'user_2 opens without k1');
    eq(false, $s->rewrapRow('user_1', 'acme', 'k2', 'whatever', 'not-the-one-read', $c->now), 'stale rewrap write changes nothing');
    eq(REWRAPPED, $s->getRow('user_1', 'acme')['wrapped_dek'], 'row unchanged');
}

// VAULT-10
/**
 * VAULT-10, a failing row: three rows under k1; with k2 active, a trigger makes the middle row's rewrap write fail
 * as a database error would. rewrap() returns {rewrapped: 2, failed: 1}; the first and third rows are under k2 and
 * open; the middle row is unchanged under k1. Then a random source that is short for the middle row's nonce: again
 * {rewrapped: 2, failed: 1}. In: none. Out: assertions. Why: review finding 4525344188 (a per-row error left
 * rewrap() as an unhandled exception with no count). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: in-memory SQLite.
 */
function test_vault10_rewrap_counts_a_failing_row(): void
{
    $users = ['user_1', 'user_2', 'user_3'];
    $keys = ['k1' => seq(0x00, 32), 'k2' => seq(0x40, 32)];
    [$v1, $s, $p, $c] = world();
    foreach ($users as $u) {
        $v1->saveKey($u, 'acme', theKey());
    }
    $before = $s->getRow('user_2', 'acme');
    $s->db->exec("CREATE TRIGGER fail_user_2 BEFORE UPDATE OF wrapped_dek ON provider_keys WHEN NEW.user_id = 'user_2'
        BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END");
    [$v2] = world($keys, 'k2', $s, $c, null, $p);
    eq(['rewrapped' => 2, 'failed' => 1], $v2->rewrap(), 'a failing store write is counted');
    eq(['k2', 'k1', 'k2'], array_map(static fn(string $u): string => (string)$s->getRow($u, 'acme')['key_id'], $users), 'key ids');
    eq($before, $s->getRow('user_2', 'acme'), 'the failing row is unchanged');
    foreach ($users as $u) {
        eq(['key' => theKey()], $v2->useKey($u, 'acme', 'chat'), "$u opens");
    }

    [$w1, $s2, $p2, $c2] = world();
    foreach ($users as $u) {
        $w1->saveKey($u, 'acme', theKey());
    }
    $calls = 0;
    $short = static function (int $n) use (&$calls): string {
        $calls++;
        return random_bytes($calls === 2 ? $n - 1 : $n);
    };
    $w2 = new KeyVault($s2, $keys, 'k2', providers(), $p2, static fn(): int => $c2->now, $short);
    eq(['rewrapped' => 2, 'failed' => 1], $w2->rewrap(), 'a short nonce is counted');
    eq(['k2', 'k1', 'k2'], array_map(static fn(string $u): string => (string)$s2->getRow($u, 'acme')['key_id'], $users), 'key ids after a short nonce');
}

// VAULT-11
/** VAULT-11: key_unavailable and construction refusals. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
function test_vault11_config(): void
{
    [$v, $s, $p, $c] = world(['k1' => seq(0x00, 32), 'k2' => seq(0x40, 32)], 'k2');
    $v->saveKey('user_1', 'acme', theKey());
    [$only1] = world(['k1' => seq(0x00, 32)], 'k1', $s, $c, null, $p);
    eq(['error' => 'key_unavailable', 'status' => 503], $only1->useKey('user_1', 'acme', 'chat'), 'key id not in keyring');
    $store = new SqlVaultStore(new PDO('sqlite::memory:'));
    $bad = [
        'short master key' => [['k1' => str_repeat('a', 31)], 'k1', providers(), 'invalid_master_key'],
        'long master key' => [['k1' => str_repeat('a', 33)], 'k1', providers(), 'invalid_master_key'],
        'active not in keyring' => [['k1' => seq(0, 32)], 'k9', providers(), 'invalid_master_key'],
        'malformed key id' => [['k 1' => seq(0, 32)], 'k 1', providers(), 'invalid_master_key'],
        'min under prefix + 16' => [['k1' => seq(0, 32)], 'k1', ['acme' => ['prefix' => 'acme_', 'min_length' => 20, 'max_length' => 200]], 'invalid_provider_config'],
        'bad provider id' => [['k1' => seq(0, 32)], 'k1', ['Acme' => ['prefix' => 'acme_', 'min_length' => 24, 'max_length' => 200]], 'invalid_provider_config'],
    ];
    foreach ($bad as $name => [$keys, $active, $prov, $want]) {
        $code = null;
        try {
            new KeyVault($store, $keys, $active, $prov, new FakeProvider());
        } catch (VaultError $e) {
            $code = $e->getErrorCode();
        }
        eq($want, $code, $name);
    }
}

// VAULT-12
/**
 * VAULT-12: 10 checks per user per clock hour; the 11th is 429 with retry_after and no provider call; other
 * users unaffected; the next hour works; malformed keys do not count; the store's window write.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
 */
function test_vault12_rate_limit(): void
{
    [$v, $s, $p, $c] = world();
    $c->now = 1_699_920_000;
    $v->saveKey('user_1', 'acme', 'acme_short');
    for ($i = 0; $i < 10; $i++) {
        eq('WXYZ', $v->saveKey('user_1', 'acme', theKey())['hint'] ?? null, "save $i");
        $c->now += 60;
    }
    $calls = count($p->calls);
    eq(['error' => 'rate_limited', 'status' => 429, 'retry_after' => 1_699_923_600 - $c->now], $v->saveKey('user_1', 'acme', theKey()), '11th');
    eq($calls, count($p->calls), 'no provider call');
    eq('WXYZ', $v->saveKey('user_2', 'acme', theKey())['hint'] ?? null, 'other user');
    $c->now = 1_699_923_600;
    eq('WXYZ', $v->saveKey('user_1', 'acme', theKey())['hint'] ?? null, 'next hour');
    $got = [];
    for ($i = 0; $i < 11; $i++) {
        $got[] = $s->countCheck('user_9', 1_699_920_000);
    }
    eq(array_merge(array_fill(0, 10, true), [false]), $got, 'store window write 10 times, not an 11th');
}

// VAULT-13
/** VAULT-13: delete_key. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
function test_vault13_delete(): void
{
    [$v, $s, , $c] = world();
    $v->saveKey('user_1', 'acme', theKey());
    $c->now += 3;
    eq(['deleted' => true], $v->deleteKey('user_1', 'acme'), 'delete');
    eq([], rows($s, 'provider_keys'), 'row removed');
    eq(['at' => $c->now, 'action' => 'key_deleted', 'provider' => 'acme', 'purpose' => null, 'key_id' => 'k1'], $v->listAudit('user_1')[1] ?? null, 'audit key_deleted');
    eq(['deleted' => false], $v->deleteKey('user_1', 'acme'), 'second delete');
    eq(2, count($v->listAudit('user_1')), 'no audit row for the second delete');
    eq(['error' => 'key_not_found', 'status' => 404], $v->useKey('user_1', 'acme', 'chat'), 'use after delete');
}

// VAULT-14
/** VAULT-14: real randomness gives different envelopes per user. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_vault14_real_randomness(): void
{
    $store = new SqlVaultStore(new PDO('sqlite::memory:'));
    $store->migrate();
    $v = new KeyVault($store, ['k1' => seq(0, 32)], 'k1', providers(), new FakeProvider());
    $v->saveKey('user_a', 'acme', theKey());
    $v->saveKey('user_b', 'acme', theKey());
    $a = $store->getRow('user_a', 'acme');
    $b = $store->getRow('user_b', 'acme');
    eq(true, $a['ciphertext'] !== $b['ciphertext'], 'ciphertext differs');
    eq(true, $a['wrapped_dek'] !== $b['wrapped_dek'], 'wrapped_dek differs');
    eq(true, substr(base64_decode($a['ciphertext']), 0, 12) !== substr(base64_decode($b['ciphertext']), 0, 12), 'data nonces differ');
    eq(true, substr(base64_decode($a['wrapped_dek']), 0, 12) !== substr(base64_decode($b['wrapped_dek']), 0, 12), 'wrap nonces differ');
    eq([['key' => theKey()], ['key' => theKey()]], [$v->useKey('user_a', 'acme', 'x'), $v->useKey('user_b', 'acme', 'x')], 'both open');
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

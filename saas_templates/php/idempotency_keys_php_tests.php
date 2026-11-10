<?php
/**
 * Idempotency keys tests (idempotency_keys.md, IDEM-01..11).
 *
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: every test now runs twice, on the in-memory store
 * and on the SQL store (SQLite in memory), with a fixed clock; tests were added for the amended IDEM-07,
 * IDEM-08, IDEM-10 and IDEM-11, and two old tests that asserted the replaced behaviour were corrected (see
 * the comments on them). Touches: memory and in-memory SQLite only.
 */
declare(strict_types=1);

require_once 'idempotency_keys_php.php';

/** The fixed test time; tests move it by assigning $GLOBALS['NOW']. */
$GLOBALS['NOW'] = 1_800_000_000;

/**
 * Install a fresh default service on the given store kind ('memory' or 'sql') with the fixed clock.
 * Output: the store. Touches: memory or a new in-memory SQLite database.
 */
function resetGlobals(string $kind = 'memory'): IdempotencyStorage
{
    $GLOBALS['NOW'] = 1_800_000_000;
    if ($kind === 'sql') {
        $pdo = new PDO('sqlite::memory:');
        $storage = new SqlIdempotencyStorage($pdo);
        $storage->migrate();
    } else {
        $storage = new InMemoryStorage();
    }
    $GLOBALS['IDEMPOTENCY_SERVICE'] = new IdempotencyService($storage, static fn(): int => $GLOBALS['NOW']);
    return $storage;
}

function expectTrue(bool $condition, string $message = ''): void {
    if (!$condition) {
        throw new Exception("Assertion failed: $message");
    }
}

function expectEquals($expected, $actual, string $message = ''): void {
    if ($expected !== $actual) {
        throw new Exception("Assertion failed: $message. Expected: " . var_export($expected, true) . ", Actual: " . var_export($actual, true));
    }
}

/** The last path segment of a problem response's type, e.g. "outcome_unknown". Touches: nothing. */
function problem_type(array $result): string
{
    $type = (string)(json_decode($result['body'], true)['type'] ?? '');
    return substr($type, strrpos($type, '/') + 1);
}

// IDEM-01
function test_first_call_runs_operation_once(string $kind) {
    resetGlobals($kind);
    $called = 0;
    $operation = function() use (&$called) {
        $called++;
        return ['status' => 200, 'body' => ['result' => 'success']];
    };
    $result = handle('user1', 'key1', 'POST', '/resource', '{}', $operation);
    expectTrue($called === 1, 'Operation should be called once');
    expectEquals(200, $result['status'], 'Status should be 200');
    expectEquals('application/json', $result['content_type'], 'Content type should be application/json');
    $body = json_decode($result['body'], true);
    expectEquals(['result' => 'success'], $body, 'Body should be success');
}

// IDEM-02
function test_second_identical_call_returns_stored_response(string $kind) {
    resetGlobals($kind);
    $called = 0;
    $operation = function() use (&$called) {
        $called++;
        return ['status' => 201, 'body' => ['result' => 'success', 'n' => $called]];
    };
    $result1 = handle('user1', 'key1', 'POST', '/resource', '{}', $operation);
    $GLOBALS['NOW'] += 3600;
    $result2 = handle('user1', 'key1', 'POST', '/resource', '{}', $operation);
    expectTrue($called === 1, 'Operation should be called only once');
    expectEquals(201, $result1['status'], 'First status should be 201');
    expectEquals(201, $result2['status'], 'Second status is the stored 201');
    expectEquals($result1['body'], $result2['body'], 'Bodies should be identical');
}

// IDEM-03
function test_same_key_different_body_returns_422(string $kind) {
    resetGlobals($kind);
    $called = 0;
    $operation = function() use (&$called) {
        $called++;
        return ['status' => 200, 'body' => ['result' => 'success']];
    };
    handle('user1', 'key1', 'POST', '/resource', '{"a":1}', $operation);
    $result = handle('user1', 'key1', 'POST', '/resource', '{"a":2}', $operation);
    expectTrue($called === 1, 'Operation should be called only once');
    expectEquals(422, $result['status'], 'Status should be 422');
    expectEquals('application/problem+json', $result['content_type'], 'Content type should be application/problem+json');
    $body = json_decode($result['body'], true);
    expectEquals('https://example.com/problems/payload-mismatch', $body['type'], 'Type should be payload-mismatch');
}

// IDEM-04
function test_same_key_in_progress_returns_409(string $kind) {
    $storage = resetGlobals($kind);
    $now = $GLOBALS['NOW'];
    // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the fingerprint was built with '\n' in single
    // quotes (a backslash and an n, not a newline), so it never matched the request; with the spec's check
    // order (422 before 409) that test would have got 422. It now uses the real fingerprint.
    $fingerprint = compute_fingerprint('POST', '/resource', '{}');
    $storage->claim('user1', 'key1', $fingerprint, $now, $now + IDEMPOTENCY_TTL);
    $called = 0;
    $operation = function() use (&$called) {
        $called++;
        return ['status' => 200, 'body' => ['result' => 'success']];
    };
    $result = handle('user1', 'key1', 'POST', '/resource', '{}', $operation);
    expectEquals(409, $result['status'], 'Status should be 409');
    expectEquals('application/problem+json', $result['content_type'], 'Content type should be application/problem+json');
    expectEquals('conflict', problem_type($result), 'Type should be conflict');
    expectEquals(0, $called, 'The operation does not run while the first is in progress');
    // A different payload while the first is still in progress is 422, not 409 (spec check order).
    $other = handle('user1', 'key1', 'POST', '/resource', '{"x":1}', $operation);
    expectEquals(422, $other['status'], 'Different fingerprint wins over in-progress');
}

// IDEM-05
function test_required_operation_no_key_returns_400(string $kind) {
    resetGlobals($kind);
    $called = 0;
    $operation = function() use (&$called) {
        $called++;
        return ['status' => 200, 'body' => ['result' => 'should not be called']];
    };
    $result = handle('user1', '', 'POST', '/resource', '{}', $operation);
    expectEquals(400, $result['status'], 'Status should be 400');
    expectEquals('application/problem+json', $result['content_type'], 'Content type should be application/problem+json');
    $body = json_decode($result['body'], true);
    expectEquals('https://example.com/problems/missing-idempotency-key', $body['type'], 'Type should be missing-idempotency-key');
    expectEquals(0, $called, 'The operation does not run without a key');
    expectEquals(400, handle('user1', '', 'PATCH', '/resource', '{}', $operation)['status'], 'PATCH also requires a key');
    expectEquals(200, handle('user1', '', 'GET', '/resource', '', $operation)['status'], 'GET does not');
}

// IDEM-06
function test_same_key_different_scope_runs_twice(string $kind) {
    resetGlobals($kind);
    $called = 0;
    $operation = function() use (&$called) {
        $called++;
        return ['status' => 200, 'body' => ['result' => 'success']];
    };
    handle('user1', 'key1', 'POST', '/resource', '{}', $operation);
    handle('user2', 'key1', 'POST', '/resource', '{}', $operation);
    expectTrue($called === 2, 'Operation should be called twice for different scopes');
}

// IDEM-07
function test_expired_key_runs_operation_again(string $kind) {
    $storage = resetGlobals($kind);
    $called = 0;
    $operation = function() use (&$called) {
        $called++;
        return ['status' => 200, 'body' => ['result' => 'fresh']];
    };
    $now = $GLOBALS['NOW'];
    $fingerprint = compute_fingerprint('POST', '/resource', '{}');
    $storage->insertRecord('user1', 'key1', $fingerprint, 'completed', 200, json_encode(['result' => 'stale']), $now - 90000, $now - 10);
    $result = handle('user1', 'key1', 'POST', '/resource', '{}', $operation);
    expectTrue($called === 1, 'Operation should be called once (the expired record should be treated as absent)');
    expectEquals(200, $result['status'], 'Status should be 200');
    expectEquals('application/json', $result['content_type'], 'Content type should be application/json');
    expectEquals(['result' => 'fresh'], json_decode($result['body'], true), 'The fresh response, not the stale one');
    // Its replacement is stored: a retry gets it without a second run.
    handle('user1', 'key1', 'POST', '/resource', '{}', $operation);
    expectEquals(1, $called, 'The replacement record is served');
}

/**
 * IDEM-07, second half: an in_progress record past expires_at (a killed process) is uncertain: 409
 * outcome_unknown, the operation does not run, purge_expired keeps it, and it is on the work list.
 * Why: amended spec. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test store.
 */
// IDEM-07
function test_in_progress_past_expiry_is_outcome_unknown(string $kind) {
    $storage = resetGlobals($kind);
    $now = $GLOBALS['NOW'];
    $fingerprint = compute_fingerprint('POST', '/charge', '{"amount":5}');
    $storage->claim('user1', 'crashed', $fingerprint, $now, $now + IDEMPOTENCY_TTL);
    $GLOBALS['NOW'] = $now + IDEMPOTENCY_TTL + 1;
    $called = 0;
    $operation = function() use (&$called) {
        $called++;
        return ['status' => 200, 'body' => []];
    };
    $result = handle('user1', 'crashed', 'POST', '/charge', '{"amount":5}', $operation);
    expectEquals([409, 'outcome_unknown', 'application/problem+json'], [$result['status'], problem_type($result), $result['content_type']], 'expired in_progress -> outcome_unknown');
    expectEquals(0, $called, 'The operation does not run');
    purge_expired();
    expectEquals(409, handle('user1', 'crashed', 'POST', '/charge', '{"amount":5}', $operation)['status'], 'purge keeps it');
    expectEquals([['scope' => 'user1', 'idem_key' => 'crashed', 'created_at' => $now]], list_uncertain(10), 'listed for reconciliation');
    expectEquals(0, $called, 'Still not run');
}

/**
 * IDEM-08: an operation that throws OperationFailedException did nothing, so the key is freed and a retry
 * with the same key runs the operation.
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: it threw a plain Exception and expected the key to
 * be freed; under the amended spec a plain error leaves the key 'uncertain' (IDEM-10), so the definite
 * failure is now OperationFailedException.
 */
// IDEM-08
function test_operation_that_raises_frees_the_key(string $kind) {
    resetGlobals($kind);
    $called = 0;
    $operation = function() use (&$called) {
        $called++;
        if ($called === 1) {
            throw new OperationFailedException('card declined');
        }
        return ['status' => 200, 'body' => ['result' => 'success']];
    };
    $threw = false;
    try {
        handle('user1', 'key1', 'POST', '/resource', '{}', $operation);
    } catch (OperationFailedException $e) {
        $threw = true;
    }
    expectTrue($threw, 'First call re-throws OperationFailedException');
    $result = handle('user1', 'key1', 'POST', '/resource', '{}', $operation);
    expectTrue($called === 2, 'Operation should be called twice');
    expectEquals(200, $result['status'], 'Status should be 200');
    expectEquals('application/json', $result['content_type'], 'Content type should be application/json');
}

// IDEM-09
function test_error_responses_have_correct_content_type_and_body(string $kind) {
    resetGlobals($kind);
    $check = function (array $result, int $status) {
        expectEquals($status, $result['status'], "status $status");
        expectEquals('application/problem+json', $result['content_type'], "$status content type should be application/problem+json");
        $body = json_decode($result['body'], true);
        foreach (['type', 'title', 'detail'] as $field) {
            expectTrue(isset($body[$field]) && is_string($body[$field]) && $body[$field] !== '', "$status body has $field");
        }
    };
    $ok = fn() => ['status' => 200, 'body' => []];
    $check(handle('user1', '', 'POST', '/resource', '{}', $ok), 400);

    $storage = resetGlobals($kind);
    $now = $GLOBALS['NOW'];
    $storage->claim('user1', 'key1', compute_fingerprint('POST', '/resource', '{}'), $now, $now + IDEMPOTENCY_TTL);
    $check(handle('user1', 'key1', 'POST', '/resource', '{}', $ok), 409);

    resetGlobals($kind);
    handle('user1', 'key1', 'POST', '/resource', '{"a":1}', $ok);
    $check(handle('user1', 'key1', 'POST', '/resource', '{"a":2}', $ok), 422);

    resetGlobals($kind);
    try {
        handle('user1', 'key2', 'POST', '/resource', '{}', function () { throw new RuntimeException('timeout'); });
    } catch (RuntimeException $e) {
    }
    $check(handle('user1', 'key2', 'POST', '/resource', '{}', $ok), 409);
}

/**
 * IDEM-10: any other error leaves the key 'uncertain'. The error is re-thrown; a retry gets 409
 * outcome_unknown and does not run; purge keeps it; after release() a retry runs it. release() on a key that
 * is not uncertain returns false.
 * Why: amended spec. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test store.
 */
// IDEM-10
function test_other_error_leaves_key_uncertain_until_release(string $kind) {
    resetGlobals($kind);
    $called = 0;
    $operation = function() use (&$called) {
        $called++;
        if ($called === 1) {
            throw new RuntimeException('provider timeout after the charge was sent');
        }
        return ['status' => 200, 'body' => ['charged' => true]];
    };
    $threw = false;
    try {
        handle('user1', 'pay', 'POST', '/charge', '{}', $operation);
    } catch (RuntimeException $e) {
        $threw = !($e instanceof OperationFailedException);
    }
    expectTrue($threw, 'The other error is re-thrown');
    $retry = handle('user1', 'pay', 'POST', '/charge', '{}', $operation);
    expectEquals([409, 'outcome_unknown'], [$retry['status'], problem_type($retry)], 'Retry gets outcome_unknown');
    expectEquals(1, $called, 'The operation count stays at 1');
    $GLOBALS['NOW'] += 10 * IDEMPOTENCY_TTL;
    purge_expired();
    expectEquals(409, handle('user1', 'pay', 'POST', '/charge', '{}', $operation)['status'], 'An uncertain key never expires');
    expectEquals(1, $called, 'Still 1');
    expectEquals(false, release('user2', 'pay'), 'Another scope cannot release it');
    expectEquals(true, release('user1', 'pay'), 'release() frees it');
    expectEquals(false, release('user1', 'pay'), 'A second release() is false');
    $result = handle('user1', 'pay', 'POST', '/charge', '{}', $operation);
    expectEquals(200, $result['status'], 'After release a retry runs');
    expectEquals(2, $called, 'Run again once');
    expectEquals(false, release('user1', 'pay'), 'release() of a completed key is false');
}

/**
 * IDEM-11: resolve() on an 'uncertain' key stores the given response as completed (expires 24h later); a
 * retry returns it without running; a second resolve() or a release() returns false and changes nothing.
 * Why: amended spec. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test store.
 */
// IDEM-11
function test_resolve_stores_outcome_once(string $kind) {
    $storage = resetGlobals($kind);
    $called = 0;
    $operation = function() use (&$called) {
        $called++;
        throw new RuntimeException('connection reset');
    };
    try {
        handle('user1', 'pay', 'POST', '/charge', '{}', $operation);
    } catch (RuntimeException $e) {
    }
    expectEquals(true, resolve('user1', 'pay', 201, ['charge_id' => 'ch_1']), 'resolve() stores the outcome');
    expectEquals(false, resolve('user1', 'pay', 500, ['charge_id' => 'ch_2']), 'A second resolve() is false');
    expectEquals(false, release('user1', 'pay'), 'release() after resolve() is false');
    $retry = handle('user1', 'pay', 'POST', '/charge', '{}', $operation);
    expectEquals([201, 'application/json', ['charge_id' => 'ch_1']], [$retry['status'], $retry['content_type'], json_decode($retry['body'], true)], 'Retry returns the resolved response');
    expectEquals(1, $called, 'without running the operation');
    expectEquals($GLOBALS['NOW'] + IDEMPOTENCY_TTL, $storage->get('user1', 'pay')['expires_at'], 'expires_at = now + 24h');
    expectEquals([], list_uncertain(10), 'No longer on the work list');
}

/**
 * Exactly one of two calls wins release()/resolve(): two services on ONE SQLite file race on the same
 * uncertain key; the conditional write lets only the first succeed. Why: amended spec ("ONE conditional
 * write"). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: a temporary SQLite file, deleted after.
 */
function test_release_and_resolve_win_once_across_connections(string $kind) {
    if ($kind !== 'sql') {
        return;
    }
    $file = tempnam(sys_get_temp_dir(), 'idem');
    try {
        $a = new SqlIdempotencyStorage(new PDO('sqlite:' . $file));
        $a->migrate();
        $b = new SqlIdempotencyStorage(new PDO('sqlite:' . $file));
        $clock = static fn(): int => 1_800_000_000;
        $svcA = new IdempotencyService($a, $clock);
        $svcB = new IdempotencyService($b, $clock);
        foreach (['k1', 'k2'] as $key) {
            $a->insertRecord('user1', $key, 'fp', 'uncertain', null, null, 1_799_999_000, 1_800_086_400);
        }
        expectEquals([true, false], [$svcA->release('user1', 'k1'), $svcB->release('user1', 'k1')], 'one release wins');
        expectEquals([true, false], [$svcB->resolve('user1', 'k2', 200, []), $svcA->resolve('user1', 'k2', 500, [])], 'one resolve wins');
        expectEquals(200, $a->get('user1', 'k2')['response_status'], 'the winner stored its response');
    } finally {
        @unlink($file);
    }
}

$tests = [
    'test_first_call_runs_operation_once',
    'test_second_identical_call_returns_stored_response',
    'test_same_key_different_body_returns_422',
    'test_same_key_in_progress_returns_409',
    'test_required_operation_no_key_returns_400',
    'test_same_key_different_scope_runs_twice',
    'test_expired_key_runs_operation_again',
    'test_in_progress_past_expiry_is_outcome_unknown',
    'test_operation_that_raises_frees_the_key',
    'test_error_responses_have_correct_content_type_and_body',
    'test_other_error_leaves_key_uncertain_until_release',
    'test_resolve_stores_outcome_once',
    'test_release_and_resolve_win_once_across_connections',
];

$failed = [];
foreach (['memory', 'sql'] as $kind) {
    foreach ($tests as $test) {
        try {
            $test($kind);
            echo "PASS: $test [$kind]\n";
        } catch (Throwable $e) {
            echo "FAIL: $test [$kind] - {$e->getMessage()}\n";
            $failed[] = "$test [$kind]";
        }
    }
}

if (!empty($failed)) {
    echo "Failed tests: " . implode(', ', $failed) . "\n";
    exit(1);
}
echo "All tests passed\n";
exit(0);

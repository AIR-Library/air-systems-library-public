<?php
require_once 'health_checks_php.php';

function assert_equal($a, $b, $msg = '')
{
    if ($a !== $b) {
        echo "FAIL: $msg\n";
        exit(1);
    }
}

function assert_contains($needle, $haystack, $msg = '')
{
    if (strpos($haystack, $needle) === false) {
        echo "FAIL: $msg\n";
        exit(1);
    }
}

function assert_not_contains($needle, $haystack, $msg = '')
{
    if (strpos($haystack, $needle) !== false) {
        echo "FAIL: $msg\n";
        exit(1);
    }
}

// HEALTH-01
function test_all_checks_pass()
{
    CheckRegistry::reset();

    $check_pass = function () {
        return ['status' => 'pass'];
    };

    CheckRegistry::register('db', 'database', $check_pass, true, 100);
    CheckRegistry::register('cache', 'cache', $check_pass, false, 100);

    $resp = readiness();
    assert_equal($resp['http_status'], 200, 'All pass: status code');
    $body = json_decode($resp['body'], true);
    assert_equal($body['status'], 'pass', 'All pass: overall status');
    assert_equal($resp['content_type'], 'application/health+json', 'All pass: content type');
}

// HEALTH-02
function test_critical_check_fails()
{
    CheckRegistry::reset();

    $check_fail = function () {
        return ['status' => 'fail'];
    };

    CheckRegistry::register('db', 'database', $check_fail, true, 100);

    $resp = readiness();
    assert_equal($resp['http_status'], 503, 'Critical fail: status code');
    $body = json_decode($resp['body'], true);
    assert_equal($body['status'], 'fail', 'Critical fail: overall status');
}

// HEALTH-03
function test_noncritical_check_fails()
{
    CheckRegistry::reset();

    $check_fail = function () {
        return ['status' => 'fail'];
    };

    CheckRegistry::register('cache', 'cache', $check_fail, false, 100);

    $resp = readiness();
    assert_equal($resp['http_status'], 200, 'Noncritical fail: status code');
    $body = json_decode($resp['body'], true);
    assert_equal($body['status'], 'warn', 'Noncritical fail: overall status');
}

// HEALTH-04
function test_slow_check_exceeds_timeout()
{
    CheckRegistry::reset();

    $check_slow = function () {
        usleep(200000); // 200 ms
        return ['status' => 'pass'];
    };

    CheckRegistry::register('slow', 'service', $check_slow, false, 100); // 100 ms timeout

    $resp = readiness();
    assert_equal($resp['http_status'], 200, 'Slow check timeout: status code');
    $body = json_decode($resp['body'], true);
    assert_equal($body['status'], 'warn', 'Slow check timeout: overall status');

    // The checks map uses the spec's "<componentId>:<componentType>" key and a list of results
    // (health_checks.md; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
    $checkResult = $body['checks']['slow:service'][0];
    assert_equal($checkResult['status'], 'fail', 'Slow check timeout: check status');
}

// HEALTH-05
function test_liveness_stays_pass()
{
    CheckRegistry::reset();

    $check_fail = function () {
        return ['status' => 'fail'];
    };

    CheckRegistry::register('db', 'database', $check_fail, true, 100);

    $resp = liveness();
    assert_equal($resp['http_status'], 200, 'Liveness: status code');
    $body = json_decode($resp['body'], true);
    assert_equal($body['status'], 'pass', 'Liveness: overall status');
}

// HEALTH-06
function test_no_connection_string_in_output()
{
    CheckRegistry::reset();

    $check_pass = function () {
        return ['status' => 'pass'];
    };

    CheckRegistry::register('db', 'database', $check_pass, true, 100);

    $resp = readiness();
    assert_not_contains('connection string', $resp['body'], 'Output contains connection string');
}

/**
 * HEALTH-06 with a real leak attempt: a failing check throws an error whose message carries a database
 * URL with a password; neither the URL nor the password may appear in the readiness or liveness output.
 * Why: the original HEALTH-06 test only looked for the words "connection string". 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// HEALTH-06
function test_failing_check_error_does_not_leak_connection_string()
{
    CheckRegistry::reset();
    CheckRegistry::register('db', 'database', function () {
        throw new RuntimeException('could not connect to postgres://app:s3cretPw@db.internal:5432/prod');
    }, true, 100);
    $resp = readiness();
    assert_equal($resp['http_status'], 503, 'Leak test: critical failure is 503');
    assert_not_contains('postgres://', $resp['body'], 'Readiness leaked the connection URL');
    assert_not_contains('s3cretPw', $resp['body'], 'Readiness leaked the password');
    assert_not_contains('postgres://', liveness()['body'], 'Liveness leaked the connection URL');
}

test_all_checks_pass();
test_critical_check_fails();
test_noncritical_check_fails();
test_slow_check_exceeds_timeout();
test_liveness_stays_pass();
test_no_connection_string_in_output();
test_failing_check_error_does_not_leak_connection_string();

echo "All tests passed.\n";
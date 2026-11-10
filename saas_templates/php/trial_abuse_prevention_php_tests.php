<?php

declare(strict_types=1);

require_once __DIR__ . '/trial_abuse_prevention_php.php';

use TrialAbusePrevention\TrialAbusePrevention;
use TrialAbusePrevention\GateResult;

/**
 * Minimal test harness.
 */
final class TestRunner
{
    private int $passed = 0;
    private int $failed = 0;
    private array $failures = [];

    public function assert(bool $condition, string $message): void
    {
        if ($condition) {
            $this->passed++;
            echo "  ✓ {$message}\n";
        } else {
            $this->failed++;
            $this->failures[] = $message;
            echo "  ✗ {$message}\n";
        }
    }

    public function assertSame(mixed $expected, mixed $actual, string $message): void
    {
        $this->assert($expected === $actual, $message . " (expected " . var_export($expected, true) . ", got " . var_export($actual, true) . ")");
    }

    public function summary(): void
    {
        echo "\n";
        echo str_repeat('=', 60) . "\n";
        echo "Results: {$this->passed} passed, {$this->failed} failed\n";
        if ($this->failures !== []) {
            echo "Failures:\n";
            foreach ($this->failures as $f) {
                echo "  - {$f}\n";
            }
        }
        echo str_repeat('=', 60) . "\n";
        exit($this->failed > 0 ? 1 : 0);
    }
}

function makeDb(): PDO
{
    $pdo = new PDO('sqlite::memory:');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    TrialAbusePrevention::migrate($pdo);
    return $pdo;
}

function makeService(PDO $db, ?string $now = null): TrialAbusePrevention
{
    return new TrialAbusePrevention($db, $now);
}

$runner = new TestRunner();

// ---------------------------------------------------------------------------
// Gate 1: email_trial_history
// ---------------------------------------------------------------------------
echo "Gate 1: email_trial_history\n";

// PASS: new email
// TRIAL-01
$db = makeDb();
$svc = makeService($db);
$result = $svc->checkEmailTrialHistory('new@example.com');
$runner->assertSame('PASS', $result->decision, 'email_trial_history PASS → new email allowed');

// CHALLENGE: same email after 1 completed trial
// TRIAL-02
$db = makeDb();
$svc = makeService($db);
$svc->createLedgerEntry('usr_1', 'repeat@example.com', ['subscription_status' => 'completed']);
$result = $svc->checkEmailTrialHistory('repeat@example.com');
$runner->assertSame('CHALLENGE', $result->decision, 'email_trial_history CHALLENGE → same email after 1 trial, flagged');

// FAIL: same email after 2 completed trials
// TRIAL-03
$db = makeDb();
$svc = makeService($db);
$svc->createLedgerEntry('usr_1', 'abuse@example.com', ['subscription_status' => 'completed']);
$svc->createLedgerEntry('usr_2', 'abuse@example.com', ['subscription_status' => 'completed']);
$result = $svc->checkEmailTrialHistory('abuse@example.com');
$runner->assertSame('FAIL', $result->decision, 'email_trial_history FAIL → same email after 2 trials, rejected');

// ---------------------------------------------------------------------------
// Gate 2: payment_method_history
// ---------------------------------------------------------------------------
echo "\nGate 2: payment_method_history\n";

// PASS: new card
// TRIAL-04
$db = makeDb();
$svc = makeService($db);
$result = $svc->checkPaymentMethodHistory('pm_new_card');
$runner->assertSame('PASS', $result->decision, 'payment_method_history PASS → new card allowed');

// FAIL: same card after 3 completed trials
// TRIAL-05
$db = makeDb();
$svc = makeService($db);
$svc->createLedgerEntry('usr_1', 'a@x.com', ['stripe_payment_method_id' => 'pm_reuse', 'subscription_status' => 'completed']);
$svc->createLedgerEntry('usr_2', 'b@x.com', ['stripe_payment_method_id' => 'pm_reuse', 'subscription_status' => 'completed']);
$svc->createLedgerEntry('usr_3', 'c@x.com', ['stripe_payment_method_id' => 'pm_reuse', 'subscription_status' => 'completed']);
$result = $svc->checkPaymentMethodHistory('pm_reuse');
$runner->assertSame('FAIL', $result->decision, 'payment_method_history FAIL → same card after 3 trials, rejected');

// ---------------------------------------------------------------------------
// Gate 3: ip_signup_rate_limit
// ---------------------------------------------------------------------------
echo "\nGate 3: ip_signup_rate_limit\n";

// PASS: < 5 signups from IP
// TRIAL-06
$db = makeDb();
$svc = makeService($db, '2025-01-15 12:00:00');
for ($i = 0; $i < 3; $i++) {
    $svc->createSignup("usr_ip_{$i}", "ip{$i}@x.com", '10.0.0.1', '2025-01-15 10:00:00');
}
$result = $svc->checkIpSignupRateLimit('10.0.0.1');
$runner->assertSame('PASS', $result->decision, 'ip_signup_rate_limit PASS → < 5 signups from IP, allowed');

// FAIL: 10+ signups from IP
// TRIAL-07
$db = makeDb();
$svc = makeService($db, '2025-01-15 12:00:00');
for ($i = 0; $i < 10; $i++) {
    $svc->createSignup("usr_ip_{$i}", "ip{$i}@x.com", '10.0.0.2', '2025-01-15 10:00:00');
}
$result = $svc->checkIpSignupRateLimit('10.0.0.2');
$runner->assertSame('FAIL', $result->decision, 'ip_signup_rate_limit FAIL → 10+ signups from IP, rejected 429');

// ---------------------------------------------------------------------------
// Gate 4: device_fingerprint
// ---------------------------------------------------------------------------
echo "\nGate 4: device_fingerprint\n";

// PASS: device < 2 users
// TRIAL-08
$db = makeDb();
$svc = makeService($db);
$device = ['user_agent' => 'Mozilla/5.0', 'screen_resolution' => '1920x1080', 'timezone' => 'UTC', 'browser_language' => 'en'];
$hash = TrialAbusePrevention::computeDeviceHash($device);
$svc->recordDeviceFingerprint('usr_dev_1', $device, $hash);
$result = $svc->checkDeviceFingerprint($device);
$runner->assertSame('PASS', $result->decision, 'device_fingerprint PASS → device < 2 users, allowed');

// FAIL: device used by 5 or more other users (6 here, checked before the new user exists)
// TRIAL-09
$db = makeDb();
$svc = makeService($db);
$device = ['user_agent' => 'Mozilla/5.0', 'screen_resolution' => '1920x1080', 'timezone' => 'UTC', 'browser_language' => 'en'];
$hash = TrialAbusePrevention::computeDeviceHash($device);
for ($i = 1; $i <= 6; $i++) {
    $svc->recordDeviceFingerprint("usr_dev_{$i}", $device, $hash);
}
$result = $svc->checkDeviceFingerprint($device);
$runner->assertSame('FAIL', $result->decision, 'device_fingerprint FAIL → device > 5 users, rejected');
$result = $svc->checkDeviceFingerprint($device, 'usr_dev_new');
$runner->assertSame([6, 'FAIL'], [$result->ruleInputs['matching_users'], $result->decision], 'device_fingerprint FAIL → 6 other users for a new user');

// TRIAL-14: boundaries (amended 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). The count is of OTHER users.
// TRIAL-14
$db = makeDb();
$svc = makeService($db);
for ($i = 1; $i <= 4; $i++) {
    $svc->recordDeviceFingerprint("usr_b_{$i}", $device, $hash);
}
$result = $svc->checkDeviceFingerprint($device, 'usr_new');
$runner->assertSame([4, 'CHALLENGE'], [$result->ruleInputs['matching_users'], $result->decision], 'device_fingerprint → 4 other users CHALLENGE');
$result = $svc->checkDeviceFingerprint($device, 'usr_b_1');
$runner->assertSame([3, 'PASS'], [$result->ruleInputs['matching_users'], $result->decision], 'device_fingerprint → the user\'s own device with 3 others PASS (the user is not counted)');
$svc->recordDeviceFingerprint('usr_b_5', $device, $hash);
$result = $svc->checkDeviceFingerprint($device, 'usr_b_1');
$runner->assertSame([4, 'PASS'], [$result->ruleInputs['matching_users'], $result->decision], 'device_fingerprint → own device, 4 others PASS');
$svc->recordDeviceFingerprint('usr_b_6', $device, $hash);
$result = $svc->checkDeviceFingerprint($device, 'usr_b_1');
$runner->assertSame([5, 'FAIL'], [$result->ruleInputs['matching_users'], $result->decision], 'device_fingerprint → exactly 5 others FAIL even though this user already has the device');
$rowsBefore = (int) $db->query('SELECT COUNT(*) FROM device_fingerprints')->fetchColumn();
$result = $svc->checkAndRecordDevice($device, 'usr_new_2');
$runner->assertSame('FAIL', $result->decision, 'checkAndRecordDevice FAIL for a 7th user');
$runner->assertSame($rowsBefore, (int) $db->query('SELECT COUNT(*) FROM device_fingerprints')->fetchColumn(), 'a FAIL records no device row');
$other = ['user_agent' => 'Other/1.0', 'screen_resolution' => '800x600', 'timezone' => 'UTC', 'browser_language' => 'de'];
$result = $svc->checkAndRecordDevice($other, 'usr_new_2');
$runner->assertSame('PASS', $result->decision, 'a fresh device PASSes');
$runner->assertSame(1, (int) $db->query("SELECT COUNT(*) FROM device_fingerprints WHERE user_id = 'usr_new_2'")->fetchColumn(), 'and is recorded after the decision');

// TRIAL-09 / TRIAL-14 through signup: the gate runs before the device is recorded, so a device with 5
// other users is refused with no user and no device row; 1 other user signs up and is recorded.
// TRIAL-09
$db = makeDb();
$svc = makeService($db, '2025-01-15 12:00:00');
for ($i = 1; $i <= 5; $i++) {
    $svc->recordDeviceFingerprint("usr_farm_{$i}", $device, $hash);
}
$response = $svc->signup('farm6@example.com', 'password123', '10.9.9.9', $device);
$runner->assertSame([403, 'device_suspected_fraud'], [$response['status'], $response['body']['error'] ?? null], 'signup → 403 device_suspected_fraud with 5 other users on the device');
$runner->assertSame(0, (int) $db->query('SELECT COUNT(*) FROM users')->fetchColumn(), 'no user created');
$runner->assertSame(5, (int) $db->query('SELECT COUNT(*) FROM device_fingerprints')->fetchColumn(), 'no device row recorded on FAIL');
$db = makeDb();
$svc = makeService($db, '2025-01-15 12:00:00');
$svc->recordDeviceFingerprint('usr_one', $device, $hash);
$response = $svc->signup('second@example.com', 'password123', '10.9.9.8', $device);
$runner->assertSame(200, $response['status'], 'signup with 1 other user on the device → 200');
$runner->assertSame(2, (int) $db->query('SELECT COUNT(DISTINCT user_id) FROM device_fingerprints')->fetchColumn(), 'the new user\'s device is recorded after the PASS');

// ---------------------------------------------------------------------------
// Gate 5: trial_payment_timing
// ---------------------------------------------------------------------------
echo "\nGate 5: trial_payment_timing\n";

// PASS: payment during the trial (days_after_trial = -9), and a first payment 4 days after it ended
// TRIAL-10
$db = makeDb();
$svc = makeService($db, '2025-01-20 12:00:00');
$svc->createUser('usr_timing_1', 'timing@x.com', 'pass', ['created_at' => '2025-01-15 12:00:00', 'trial_days' => 14]);
$svc->createLedgerEntry('usr_timing_1', 'timing@x.com', ['payment_added_date' => '2025-01-18 12:00:00']);
$result = $svc->checkTrialPaymentTiming('usr_timing_1');
$runner->assertSame('PASS', $result->decision, 'trial_payment_timing PASS → payment within trial window, allowed');
$db = makeDb();
$svc = makeService($db, '2025-01-19 12:00:00'); // trial 01-01 12:00 + 14 days = 01-15 12:00; +4 days
$svc->createUser('usr_timing_4', 't4@x.com', 'pass', ['created_at' => '2025-01-01 12:00:00', 'trial_days' => 14]);
$svc->createLedgerEntry('usr_timing_4', 't4@x.com', ['payment_added_date' => null]);
$result = $svc->checkTrialPaymentTiming('usr_timing_4');
$runner->assertSame([4, 'PASS'], [$result->ruleInputs['days_after_trial'], $result->decision], 'trial_payment_timing PASS → first payment 4 days after the trial ended');

// FAIL: first payment 90+ days after the trial ended, no earlier payment
// TRIAL-11
$db = makeDb();
$svc = makeService($db, '2025-05-01 12:00:00');
$svc->createUser('usr_timing_2', 'timing2@x.com', 'pass', ['created_at' => '2025-01-01 12:00:00', 'trial_days' => 14]);
$svc->createLedgerEntry('usr_timing_2', 'timing2@x.com', ['payment_added_date' => null]);
$result = $svc->checkTrialPaymentTiming('usr_timing_2');
$runner->assertSame('FAIL', $result->decision, 'trial_payment_timing FAIL → trial ended, no payment, trying to re-add, rejected');
$db = makeDb();
$svc = makeService($db, '2025-04-15 12:00:00'); // exactly 90 days after the trial ended (01-15 12:00)
$svc->createUser('usr_timing_90', 't90@x.com', 'pass', ['created_at' => '2025-01-01 12:00:00', 'trial_days' => 14]);
$svc->createLedgerEntry('usr_timing_90', 't90@x.com', ['payment_added_date' => null]);
$result = $svc->checkTrialPaymentTiming('usr_timing_90');
$runner->assertSame([90, 'FAIL'], [$result->ruleInputs['days_after_trial'], $result->decision], 'trial_payment_timing FAIL → first payment exactly 90 days after the trial');

// TRIAL-15: boundaries (amended 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): 5 and 89 days CHALLENGE, 90 days with an earlier payment
// CHALLENGE; floor rounds toward negative infinity; trial_days is configuration.
// TRIAL-15
$timing = function (string $now, ?string $earlierPayment, int $trialDays = 14) {
    $db = makeDb();
    $svc = makeService($db, $now);
    $svc->createUser('usr_t', 't@x.com', 'pass', ['created_at' => '2025-01-01 12:00:00', 'trial_days' => $trialDays]);
    $svc->createLedgerEntry('usr_t', 't@x.com', ['payment_added_date' => $earlierPayment]);
    $r = $svc->checkTrialPaymentTiming('usr_t');
    return [$r->ruleInputs['days_after_trial'], $r->decision];
};
$runner->assertSame([5, 'CHALLENGE'], $timing('2025-01-20 12:00:00', null), 'trial_payment_timing → 5 days after the trial CHALLENGE');
$runner->assertSame([4, 'PASS'], $timing('2025-01-20 11:59:59', null), 'trial_payment_timing → one second short of 5 days is still 4 (floor) PASS');
$runner->assertSame([89, 'CHALLENGE'], $timing('2025-04-14 12:00:00', null), 'trial_payment_timing → 89 days CHALLENGE');
$runner->assertSame([90, 'CHALLENGE'], $timing('2025-04-15 12:00:00', '2025-01-10 12:00:00'), 'trial_payment_timing → 90 days with an earlier payment CHALLENGE');
$runner->assertSame([-1, 'PASS'], $timing('2025-01-15 00:00:00', null), 'trial_payment_timing → half a day before the trial ends is -1 (floor toward negative infinity)');
$runner->assertSame([60, 'CHALLENGE'], $timing('2025-04-15 12:00:00', null, 44), 'trial_payment_timing → trial_days is per configuration (44 days: 60 days after)');
$db = makeDb();
$svc = new TrialAbusePrevention($db, '2025-01-01 12:00:00', 30);
TrialAbusePrevention::migrate($db);
$svc->signup('conf@example.com', 'password123', '10.1.1.1');
$runner->assertSame(30, (int) $db->query("SELECT trial_days FROM users WHERE email = 'conf@example.com'")->fetchColumn(), 'signup stores the configured trial_days');

// ---------------------------------------------------------------------------
// Gate 6: chargeback_history
// ---------------------------------------------------------------------------
echo "\nGate 6: chargeback_history\n";

// PASS: no chargebacks
// TRIAL-12
$db = makeDb();
$svc = makeService($db);
$svc->createUser('usr_cb_1', 'cb@x.com', 'pass', ['stripe_customer_id' => 'cus_1']);
$result = $svc->checkChargebackHistory('usr_cb_1');
$runner->assertSame('PASS', $result->decision, 'chargeback_history PASS → no chargebacks, allowed');

// FAIL: 2+ chargebacks
// TRIAL-13
$db = makeDb();
$svc = makeService($db);
$svc->createUser('usr_cb_2', 'cb2@x.com', 'pass', ['stripe_customer_id' => 'cus_2']);
$svc->createStripeEvent('cus_2', 'chargeback.created');
$svc->createStripeEvent('cus_2', 'chargeback.updated');
$result = $svc->checkChargebackHistory('usr_cb_2');
$runner->assertSame('FAIL', $result->decision, 'chargeback_history FAIL → 2+ chargebacks, requires prepayment');

// ---------------------------------------------------------------------------
// Integration: signup flow
// ---------------------------------------------------------------------------
echo "\nIntegration: signup flow\n";

// Successful signup with new email and low IP count
$db = makeDb();
$svc = makeService($db, '2025-01-15 12:00:00');
$response = $svc->signup('fresh@example.com', 'password123', '192.168.1.1');
$runner->assertSame(200, $response['status'], 'signup → 200 for new email');
$runner->assertSame(true, $response['body']['success'], 'signup → success true');
$runner->assert(isset($response['body']['user_id']), 'signup → user_id present');

// Signup rejected: email has 2 prior trials
$db = makeDb();
$svc = makeService($db, '2025-01-15 12:00:00');
$svc->createLedgerEntry('usr_old_1', 'blocked@example.com', ['subscription_status' => 'completed']);
$svc->createLedgerEntry('usr_old_2', 'blocked@example.com', ['subscription_status' => 'completed']);
$response = $svc->signup('blocked@example.com', 'password123', '192.168.1.2');
$runner->assertSame(409, $response['status'], 'signup → 409 for email with 2 prior trials');
$runner->assertSame('email_has_trial_history', $response['body']['error'], 'signup → error email_has_trial_history');

// Signup rejected: IP rate limited
$db = makeDb();
$svc = makeService($db, '2025-01-15 12:00:00');
for ($i = 0; $i < 10; $i++) {
    $svc->createSignup("usr_ip_{$i}", "ip{$i}@x.com", '10.0.0.99', '2025-01-15 10:00:00');
}
$response = $svc->signup('newip@example.com', 'password123', '10.0.0.99');
$runner->assertSame(429, $response['status'], 'signup → 429 for IP with 10+ signups');
$runner->assertSame('too_many_signups_from_ip', $response['body']['error'], 'signup → error too_many_signups_from_ip');
$runner->assertSame(86400, $response['body']['retry_after'], 'signup → retry_after 86400');

// ---------------------------------------------------------------------------
// Integration: payment flow
// ---------------------------------------------------------------------------
echo "\nIntegration: payment flow\n";

// Successful payment
$db = makeDb();
$svc = makeService($db, '2025-01-20 12:00:00');
$svc->createUser('usr_pay_1', 'pay@x.com', 'pass', ['created_at' => '2025-01-15 12:00:00', 'trial_days' => 14, 'stripe_customer_id' => 'cus_pay']);
$svc->createLedgerEntry('usr_pay_1', 'pay@x.com', ['payment_added_date' => null]);
$response = $svc->subscriptionCreated('usr_pay_1', 'pm_new');
$runner->assertSame(200, $response['status'], 'payment → 200 for valid payment');
$runner->assertSame(true, $response['body']['success'], 'payment → success true');

// Payment rejected: payment method used 3+ times
$db = makeDb();
$svc = makeService($db, '2025-01-20 12:00:00');
$svc->createUser('usr_pay_2', 'pay2@x.com', 'pass', ['created_at' => '2025-01-15 12:00:00', 'trial_days' => 14, 'stripe_customer_id' => 'cus_pay2']);
$svc->createLedgerEntry('usr_pay_2', 'pay2@x.com', ['payment_added_date' => null]);
$svc->createLedgerEntry('usr_other_1', 'o1@x.com', ['stripe_payment_method_id' => 'pm_bad', 'subscription_status' => 'completed']);
$svc->createLedgerEntry('usr_other_2', 'o2@x.com', ['stripe_payment_method_id' => 'pm_bad', 'subscription_status' => 'completed']);
$svc->createLedgerEntry('usr_other_3', 'o3@x.com', ['stripe_payment_method_id' => 'pm_bad', 'subscription_status' => 'completed']);
$response = $svc->subscriptionCreated('usr_pay_2', 'pm_bad');
$runner->assertSame(403, $response['status'], 'payment → 403 for payment method used 3+ times');
$runner->assertSame('payment_method_used_for_multiple_trials', $response['body']['error'], 'payment → error payment_method_used_for_multiple_trials');

// Payment rejected: trial ended, no payment, 90+ days
$db = makeDb();
$svc = makeService($db, '2025-05-01 12:00:00');
$svc->createUser('usr_pay_3', 'pay3@x.com', 'pass', ['created_at' => '2025-01-01 12:00:00', 'trial_days' => 14, 'stripe_customer_id' => 'cus_pay3']);
$svc->createLedgerEntry('usr_pay_3', 'pay3@x.com', ['payment_added_date' => null]);
$response = $svc->subscriptionCreated('usr_pay_3', 'pm_new3');
$runner->assertSame(403, $response['status'], 'payment → 403 for trial ended no payment 90+ days');
$runner->assertSame('trial_ended_no_payment_cannot_retry', $response['body']['error'], 'payment → error trial_ended_no_payment_cannot_retry');

// Payment rejected: 2+ chargebacks
$db = makeDb();
$svc = makeService($db, '2025-01-20 12:00:00');
$svc->createUser('usr_pay_4', 'pay4@x.com', 'pass', ['created_at' => '2025-01-15 12:00:00', 'trial_days' => 14, 'stripe_customer_id' => 'cus_pay4']);
$svc->createLedgerEntry('usr_pay_4', 'pay4@x.com', ['payment_added_date' => null]);
$svc->createStripeEvent('cus_pay4', 'chargeback.created');
$svc->createStripeEvent('cus_pay4', 'chargeback.updated');
$response = $svc->subscriptionCreated('usr_pay_4', 'pm_new4');
$runner->assertSame(403, $response['status'], 'payment → 403 for 2+ chargebacks');
$runner->assertSame('chargeback_history_requires_prepayment', $response['body']['error'], 'payment → error chargeback_history_requires_prepayment');

// ---------------------------------------------------------------------------
// Gate decision logging
// ---------------------------------------------------------------------------
echo "\nGate decision logging\n";

$db = makeDb();
$svc = makeService($db);
$svc->checkEmailTrialHistory('log@example.com');
$stmt = $db->query('SELECT COUNT(*) FROM gate_decisions WHERE gate_name = "email_trial_history"');
$count = (int) $stmt->fetchColumn();
$runner->assertSame(1, $count, 'gate_decisions → email_trial_history logged');

$runner->summary();
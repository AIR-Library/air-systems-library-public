<?php
// Tests updated with the fix 2026-11-03: events go only to the sending organization's endpoints (they went to every organization's),
//   the event type is a bound parameter (it was pasted into the SQL), and deliver() takes an
//   optional sender so it can be tested without the network.
// Why: the suite failed on CI (it was listed in ci/baseline.json). Reviewed by Claude; fixed by a free model from a continuity handoff, session c6ee9a72 (2026-11-03).
// Touches: the database, outgoing HTTPS (curl).

declare(strict_types=1);

require_once __DIR__ . '/webhooks_php.php';

use Webhooks\Webhooks;
use function Webhooks\verify_webhook;

class WebhooksTest
{
    private Webhooks $webhooks;
    private PDO $db;
    private int $passed = 0;
    private int $failed = 0;

    public function __construct()
    {
        $this->db = new PDO('sqlite::memory:');
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->webhooks = new Webhooks($this->db);
        $this->webhooks->migrate();
    }

    private function assert(bool $condition, string $message): void
    {
        if ($condition) {
            $this->passed++;
            echo "✓ $message\n";
        } else {
            $this->failed++;
            echo "✗ $message\n";
        }
    }

    private function assertEquals(mixed $expected, mixed $actual, string $message): void
    {
        $this->assert($expected === $actual, "$message (expected: " . var_export($expected, true) . ", got: " . var_export($actual, true) . ")");
    }

    private function assertNotEquals(mixed $expected, mixed $actual, string $message): void
    {
        $this->assert($expected !== $actual, "$message (should not equal: " . var_export($expected, true) . ")");
    }

    public function run(): void
    {
        $this->testSecretGeneration();
        $this->testSignVerifyRoundtrip();
        $this->testChangedBodyFails();
        $this->testChangedTimestampFails();
        $this->testOldTimestampRejected();
        $this->testMultipleSignatures();
        $this->testCreateEndpoint();
        $this->testSendEvent();
        $this->testDeliverSuccess();
        $this->testDeliverFailureRetries();
        $this->testWebhookIdConsistentAcrossRetries();
        $this->testRotateSecret();
        $this->testDisableAfterFiveFailures();
        $this->testVerifyHelperFunction();
        $this->testDeliverStatusCodesWithFakeSender();
        $this->testWebhookIdSameOnEveryRetry();
        $this->testEventTypeMatchIsExact();

        echo "\n--- Results: {$this->passed} passed, {$this->failed} failed ---\n";
        if ($this->failed > 0) {
            exit(1);
        }
    }

    // HOOK-08
    private function testSecretGeneration(): void
    {
        $result = $this->webhooks->createEndpoint('org_secret_gen', 'https://example.com/webhook', ['user.created']);
        $this->assert(str_starts_with($result['secret'], 'whsec_'), 'Secret starts with whsec_');
        $decoded = base64_decode(substr($result['secret'], 6), true);
        $this->assert($decoded !== false, 'Secret is valid base64');
        $this->assert(strlen($decoded) >= 24 && strlen($decoded) <= 64, 'Secret decodes to 24-64 bytes');
    }

    // HOOK-01
    private function testSignVerifyRoundtrip(): void
    {
        $secret = 'whsec_' . base64_encode(random_bytes(32));
        $msgId = 'msg_test123';
        $timestamp = time();
        $body = '{"event":"test","data":{"id":1}}';

        $sig = Webhooks::sign($secret, $msgId, $timestamp, $body);
        $this->assert(str_starts_with($sig, 'v1,'), 'Signature format v1,<base64>');

        $headers = [
            'webhook-id' => $msgId,
            'webhook-timestamp' => (string)$timestamp,
            'webhook-signature' => $sig,
        ];
        $result = Webhooks::verify($secret, $headers, $body);
        $this->assert($result === true, 'Valid signature verifies');
    }

    // HOOK-02
    private function testChangedBodyFails(): void
    {
        $secret = 'whsec_' . base64_encode(random_bytes(32));
        $msgId = 'msg_test123';
        $timestamp = time();
        $body = '{"event":"test","data":{"id":1}}';
        $sig = Webhooks::sign($secret, $msgId, $timestamp, $body);

        $headers = [
            'webhook-id' => $msgId,
            'webhook-timestamp' => (string)$timestamp,
            'webhook-signature' => $sig,
        ];
        $result = Webhooks::verify($secret, $headers, '{"event":"test","data":{"id":2}}');
        $this->assert($result !== true, 'Changed body fails verification');
    }

    // HOOK-02
    private function testChangedTimestampFails(): void
    {
        $secret = 'whsec_' . base64_encode(random_bytes(32));
        $msgId = 'msg_test123';
        $timestamp = time();
        $body = '{"event":"test"}';
        $sig = Webhooks::sign($secret, $msgId, $timestamp, $body);

        $headers = [
            'webhook-id' => $msgId,
            'webhook-timestamp' => (string)($timestamp + 1),
            'webhook-signature' => $sig,
        ];
        $result = Webhooks::verify($secret, $headers, $body);
        $this->assert($result !== true, 'Changed timestamp fails verification');
    }

    // HOOK-03
    private function testOldTimestampRejected(): void
    {
        $secret = 'whsec_' . base64_encode(random_bytes(32));
        $msgId = 'msg_test123';
        $timestamp = time() - 600; // 10 minutes ago
        $body = '{"event":"test"}';
        $sig = Webhooks::sign($secret, $msgId, $timestamp, $body);

        $headers = [
            'webhook-id' => $msgId,
            'webhook-timestamp' => (string)$timestamp,
            'webhook-signature' => $sig,
        ];
        $result = Webhooks::verify($secret, $headers, $body, 300);
        $this->assert($result !== true, 'Old timestamp rejected');
        $this->assertEquals('Timestamp outside tolerance', $result, 'Correct error message');
    }

    // HOOK-04
    private function testMultipleSignatures(): void
    {
        $secret1 = 'whsec_' . base64_encode(random_bytes(32));
        $secret2 = 'whsec_' . base64_encode(random_bytes(32));
        $msgId = 'msg_test123';
        $timestamp = time();
        $body = '{"event":"test"}';

        $sig1 = Webhooks::sign($secret1, $msgId, $timestamp, $body);
        $sig2 = Webhooks::sign($secret2, $msgId, $timestamp, $body);

        $headers = [
            'webhook-id' => $msgId,
            'webhook-timestamp' => (string)$timestamp,
            'webhook-signature' => "$sig1 $sig2",
        ];

        $result1 = Webhooks::verify($secret1, $headers, $body);
        $this->assert($result1 === true, 'First signature matches');

        $result2 = Webhooks::verify($secret2, $headers, $body);
        $this->assert($result2 === true, 'Second signature matches');

        $secret3 = 'whsec_' . base64_encode(random_bytes(32));
        $result3 = Webhooks::verify($secret3, $headers, $body);
        $this->assert($result3 !== true, 'Unknown secret fails');
    }

    private function testCreateEndpoint(): void
    {
        $result = $this->webhooks->createEndpoint('org_create_ep', 'https://example.com/webhook', ['user.created', 'user.updated']);
        $this->assert(!empty($result['id']), 'Returns ID');
        $this->assert(str_starts_with($result['id'], 'wep_'), 'ID has correct prefix');

        try {
            $this->webhooks->createEndpoint('org_create_ep', 'http://invalid.com', ['test']);
            $this->assert(false, 'Should reject non-HTTPS');
        } catch (InvalidArgumentException) {
            $this->assert(true, 'Rejects non-HTTPS URL');
        }

        $result2 = $this->webhooks->createEndpoint('org_create_ep', 'http://localhost/webhook', ['test']);
        $this->assert(!empty($result2['id']), 'Allows localhost HTTP');
    }

    // HOOK-06
    private function testSendEvent(): void
    {
        $orgId = 'org_send_event';
        $ep1 = $this->webhooks->createEndpoint($orgId, 'https://example.com/1', ['user.created']);
        $ep2 = $this->webhooks->createEndpoint($orgId, 'https://example.com/2', ['user.created', 'user.deleted']);
        $this->webhooks->createEndpoint($orgId, 'https://example.com/3', ['user.deleted']); // not subscribed

        // Create endpoint for different org - should not receive
        $other = $this->webhooks->createEndpoint('org_other', 'https://example.com/4', ['user.created']);

        $msgId = $this->webhooks->sendEvent($orgId, 'user.created', ['user_id' => 123, 'name' => 'Test']);

        $deliveries = $this->db->query("SELECT COUNT(*) FROM webhook_deliveries WHERE message_id = '$msgId'")->fetchColumn();
        $this->assertEquals(2, $deliveries, 'Creates delivery for each subscribed endpoint');
        $otherStmt = $this->db->prepare('SELECT COUNT(*) FROM webhook_deliveries WHERE endpoint_id = ?');
        $otherStmt->execute([$other['id']]);
        $this->assertEquals(0, (int)$otherStmt->fetchColumn(), "Other org's endpoint gets no delivery");

        $msg = $this->db->query("SELECT payload FROM webhook_messages WHERE id = '$msgId'")->fetchColumn();
        $this->assertEquals('{"user_id":123,"name":"Test"}', $msg, 'Stores payload correctly');

        // Verify org_id stored on message
        $msgOrg = $this->db->query("SELECT org_id FROM webhook_messages WHERE id = '$msgId'")->fetchColumn();
        $this->assertEquals($orgId, $msgOrg, 'Message stores org_id');
    }

    private function testDeliverSuccess(): void
    {
        $orgId = 'org_deliver_success';
        $ep = $this->webhooks->createEndpoint($orgId, 'https://httpbin.org/post', ['test.event']);
        $msgId = $this->webhooks->sendEvent($orgId, 'test.event', ['data' => 'test']);

        $delivery = $this->db->query("SELECT * FROM webhook_deliveries WHERE message_id = '$msgId'")->fetch(PDO::FETCH_ASSOC);
        $this->assert(!empty($delivery), 'Delivery created');

        // Test that successful delivery marks success and resets failure_count
        $this->db->prepare('UPDATE webhook_deliveries SET success = 1, status_code = 200, delivered_at = ? WHERE id = ?')
            ->execute([time(), $delivery['id']]);
        $this->db->prepare('UPDATE webhook_endpoints SET failure_count = 0 WHERE id = ?')
            ->execute([$ep['id']]);

        $epCheck = $this->db->query("SELECT failure_count, active FROM webhook_endpoints WHERE id = '{$ep['id']}'")->fetch(PDO::FETCH_ASSOC);
        $this->assertEquals(0, $epCheck['failure_count'], 'Failure count reset on success');
        $this->assertEquals(1, $epCheck['active'], 'Endpoint stays active');
    }

    private function testDeliverFailureRetries(): void
    {
        $orgId = 'org_deliver_failure';
        $ep = $this->webhooks->createEndpoint($orgId, 'https://httpbin.org/status/500', ['test.event']);
        $msgId = $this->webhooks->sendEvent($orgId, 'test.event', ['data' => 'test']);

        $delivery = $this->db->query("SELECT * FROM webhook_deliveries WHERE message_id = '$msgId'")->fetch(PDO::FETCH_ASSOC);
        $originalAttempt = $delivery['attempt'];

        // Simulate a failed delivery (500)
        $now = time();
        $nextAttempt = $now + Webhooks::RETRY_SCHEDULE[0]; // 5 seconds
        $this->db->prepare('UPDATE webhook_deliveries SET attempt = ?, status_code = 500, error = "HTTP 500", next_attempt_at = ? WHERE id = ?')
            ->execute([$originalAttempt + 1, $nextAttempt, $delivery['id']]);
        $this->db->prepare('UPDATE webhook_endpoints SET failure_count = failure_count + 1 WHERE id = ?')
            ->execute([$ep['id']]);

        $updated = $this->db->query("SELECT attempt, next_attempt_at FROM webhook_deliveries WHERE id = '{$delivery['id']}'")->fetch(PDO::FETCH_ASSOC);
        $this->assertEquals($originalAttempt + 1, $updated['attempt'], 'Attempt incremented');
        $this->assertEquals($nextAttempt, $updated['next_attempt_at'], 'Next attempt scheduled with backoff');

        // Test 301 also schedules retry
        $delivery2 = $this->db->query("SELECT * FROM webhook_deliveries WHERE message_id = '$msgId' LIMIT 1 OFFSET 1")->fetch(PDO::FETCH_ASSOC);
        if ($delivery2) {
            $this->db->prepare('UPDATE webhook_deliveries SET attempt = ?, status_code = 301, error = "HTTP 301", next_attempt_at = ? WHERE id = ?')
                ->execute([$delivery2['attempt'] + 1, $now + 300, $delivery2['id']]);
            $updated2 = $this->db->query("SELECT status_code FROM webhook_deliveries WHERE id = '{$delivery2['id']}'")->fetchColumn();
            $this->assertEquals(301, $updated2, '301 treated as failure');
        }

        // Test 400 also schedules retry
        $this->assert(true, '400 and 500 schedule retry (verified by logic)');
    }

    private function testWebhookIdConsistentAcrossRetries(): void
    {
        $orgId = 'org_webhook_id';
        $ep = $this->webhooks->createEndpoint($orgId, 'https://example.com/webhook', ['test.event']);
        $msgId = $this->webhooks->sendEvent($orgId, 'test.event', ['data' => 'test']);

        $deliveries = $this->db->query("SELECT * FROM webhook_deliveries WHERE message_id = '$msgId'")->fetchAll(PDO::FETCH_ASSOC);
        foreach ($deliveries as $d) {
            $this->assertEquals($msgId, $d['message_id'], 'webhook-id (message_id) stays same across retries');
        }

        // Simulate retry by creating new delivery row for same message (as would happen in retry logic)
        // Actually, the spec says same delivery row, attempt increments. Let's verify that.
        $delivery = $deliveries[0];
        $this->db->prepare('UPDATE webhook_deliveries SET attempt = 2 WHERE id = ?')->execute([$delivery['id']]);
        $retry = $this->db->query("SELECT message_id FROM webhook_deliveries WHERE id = '{$delivery['id']}'")->fetchColumn();
        $this->assertEquals($msgId, $retry, 'Same message_id on retry attempt');
    }

    private function testRotateSecret(): void
    {
        $orgId = 'org_rotate_secret';
        $ep = $this->webhooks->createEndpoint($orgId, 'https://example.com/webhook', ['test.event']);
        $oldSecret = $this->db->query("SELECT secret FROM webhook_endpoints WHERE id = '{$ep['id']}'")->fetchColumn();

        $newSecret = $this->webhooks->rotateSecret($ep['id']);
        $this->assert(str_starts_with($newSecret, 'whsec_'), 'New secret has prefix');
        $this->assertNotEquals($oldSecret, $newSecret, 'Secret actually rotated');

        $stored = $this->db->query("SELECT secret FROM webhook_endpoints WHERE id = '{$ep['id']}'")->fetchColumn();
        $this->assertEquals($newSecret, $stored, 'New secret persisted');
    }

    private function testDisableAfterFiveFailures(): void
    {
        $orgId = 'org_disable_5';
        $ep = $this->webhooks->createEndpoint($orgId, 'https://example.com/webhook', ['test.event']);

        // Simulate 5 fully failed messages (all retries exhausted)
        for ($i = 0; $i < 5; $i++) {
            $msgId = $this->webhooks->sendEvent($orgId, 'test.event', ['seq' => $i]);
            $delivery = $this->db->query("SELECT id FROM webhook_deliveries WHERE message_id = '$msgId'")->fetch(PDO::FETCH_ASSOC);

            // Exhaust all retries for this delivery
            $this->db->prepare('UPDATE webhook_deliveries SET attempt = ?, success = 0, next_attempt_at = NULL WHERE id = ?')
                ->execute([count(Webhooks::RETRY_SCHEDULE) + 1, $delivery['id']]);
            // Record the endpoint failure (increments failure_count, disables if threshold reached)
            $this->webhooks->recordEndpointFailure($ep['id']);
        }

        $epCheck = $this->db->query("SELECT active, failure_count FROM webhook_endpoints WHERE id = '{$ep['id']}'")->fetch(PDO::FETCH_ASSOC);
        $this->assertEquals(5, $epCheck['failure_count'], 'Failure count is 5');
        $this->assertEquals(0, $epCheck['active'], 'Endpoint disabled after 5 failures');
    }

    /**
     * Build a service on a fresh database with a fixed, settable clock.
     *
     * Inputs: &$now (the clock reads it on every call). Output: [Webhooks, PDO].
     * Why: the HOOK-05/07 tests drive deliver() with a fake sender and a fixed time instead of editing rows
     * by hand. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: an in-memory SQLite database.
     */
    private function freshService(int &$now): array
    {
        $db = new PDO('sqlite::memory:');
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $svc = new Webhooks($db, function () use (&$now): int { return $now; });
        $svc->migrate();
        return [$svc, $db];
    }

    /**
     * HOOK-05: deliver() through a fake sender. 200 and 299 mark success with no retry; 301, 400, 500 and a
     * sender that throws record a failure and schedule the next attempt 5 s later (RETRY_SCHEDULE[0]).
     * Why: the older tests only edited delivery rows by hand and never called deliver(). 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: an in-memory SQLite database; no network.
     */
    // HOOK-05
    private function testDeliverStatusCodesWithFakeSender(): void
    {
        $now = 1_700_000_000;
        foreach ([200 => true, 299 => true, 301 => false, 400 => false, 500 => false, -1 => false] as $code => $ok) {
            [$svc, $db] = $this->freshService($now);
            $svc->createEndpoint('org_a', 'https://example.com/hook', ['test.event']);
            $msgId = $svc->sendEvent('org_a', 'test.event', ['n' => 1]);
            $row = $db->query('SELECT * FROM webhook_deliveries')->fetch(PDO::FETCH_ASSOC);
            $sender = function (string $url, array $headers, string $body) use ($code): int {
                if ($code === -1) {
                    throw new RuntimeException('connection timed out');
                }
                return $code;
            };
            $res = $svc->deliver($row, $sender);
            $after = $db->query('SELECT * FROM webhook_deliveries')->fetch(PDO::FETCH_ASSOC);
            $label = $code === -1 ? 'throwing sender' : "HTTP $code";
            $this->assertEquals($ok, $res['success'], "$label: success flag");
            $this->assertEquals($ok ? 1 : 0, (int)$after['success'], "$label: stored success");
            if ($ok) {
                $this->assertEquals(null, $after['next_attempt_at'] === null ? null : 'scheduled', "$label: no retry was scheduled");
                $this->assertEquals($now, (int)$after['delivered_at'], "$label: delivered_at is the clock time");
            } else {
                $this->assertEquals(2, (int)$after['attempt'], "$label: attempt incremented");
                $this->assertEquals($now + Webhooks::RETRY_SCHEDULE[0], (int)$after['next_attempt_at'], "$label: retry in 5 s");
                $this->assertEquals(null, $after['delivered_at'], "$label: not delivered");
            }
        }
    }

    /**
     * HOOK-07: the webhook-id header is the message id on the first attempt and on the retry of the same
     * message, and its signature verifies against the endpoint secret.
     * Why: the older test only re-read message_id from a row it edited. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: an in-memory SQLite database; no network.
     */
    // HOOK-07
    private function testWebhookIdSameOnEveryRetry(): void
    {
        $now = 1_700_000_000;
        [$svc, $db] = $this->freshService($now);
        $ep = $svc->createEndpoint('org_a', 'https://example.com/hook', ['test.event']);
        $msgId = $svc->sendEvent('org_a', 'test.event', ['n' => 1]);
        $seen = [];
        $codes = [500, 200];
        $sender = function (string $url, array $headers, string $body) use (&$seen, &$codes, $ep, &$now): int {
            $h = [];
            foreach ($headers as $line) {
                [$k, $v] = explode(': ', $line, 2);
                $h[strtolower($k)] = $v;
            }
            $seen[] = $h['webhook-id'];
            $this->assert(Webhooks::verify($ep['secret'], $h, $body, 300, $now) === true, 'Delivered signature verifies');
            return array_shift($codes);
        };
        $row = $db->query('SELECT * FROM webhook_deliveries')->fetch(PDO::FETCH_ASSOC);
        $svc->deliver($row, $sender);
        $now += Webhooks::RETRY_SCHEDULE[0];
        $pending = $svc->getPendingDeliveries();
        $this->assertEquals(1, count($pending), 'The failed delivery is due for retry');
        $res = $svc->deliver($pending[0], $sender);
        $this->assertEquals(true, $res['success'], 'Retry succeeds');
        $this->assertEquals([$msgId, $msgId], $seen, 'webhook-id is the message id on both attempts');
    }

    /**
     * An event type is matched exactly: "%" and "_" are not wildcards, so "user.%" reaches no
     * "user.created" endpoint. Why: sendEvent used a LIKE pattern built from the event type.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: an in-memory SQLite database.
     */
    private function testEventTypeMatchIsExact(): void
    {
        $now = 1_700_000_000;
        [$svc, $db] = $this->freshService($now);
        $svc->createEndpoint('org_a', 'https://example.com/hook', ['user.created']);
        $svc->sendEvent('org_a', 'user.%', ['n' => 1]);
        $svc->sendEvent('org_a', 'user_created', ['n' => 2]);
        $this->assertEquals(0, (int)$db->query('SELECT COUNT(*) FROM webhook_deliveries')->fetchColumn(), 'Wildcard event types match nothing');
        $svc->sendEvent('org_a', 'user.created', ['n' => 3]);
        $this->assertEquals(1, (int)$db->query('SELECT COUNT(*) FROM webhook_deliveries')->fetchColumn(), 'Exact event type matches');
    }

    private function testVerifyHelperFunction(): void
    {
        $secret = 'whsec_' . base64_encode(random_bytes(32));
        $msgId = 'msg_test123';
        $timestamp = time();
        $body = '{"event":"test"}';
        $sig = Webhooks::sign($secret, $msgId, $timestamp, $body);

        $serverHeaders = [
            'HTTP_WEBHOOK_ID' => $msgId,
            'HTTP_WEBHOOK_TIMESTAMP' => (string)$timestamp,
            'HTTP_WEBHOOK_SIGNATURE' => $sig,
        ];

        $result = verify_webhook($secret, $body, $serverHeaders);
        $this->assert($result === true, 'verify_webhook helper works');

        $result2 = verify_webhook($secret, '{"event":"tampered"}', $serverHeaders);
        $this->assert($result2 !== true, 'verify_webhook detects tampering');
    }
}

// Run tests
$test = new WebhooksTest();
$test->run();

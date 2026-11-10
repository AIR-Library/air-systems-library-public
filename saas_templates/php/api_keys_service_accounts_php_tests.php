<?php
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the service runs on a fixed, settable clock (UTC) with bcrypt cost 4 so
//   KEYS-04 can make the spec's 1001 requests; revoke, rotate and usage stats pass the verified caller and the
//   admin list an admin caller; each changed test says what changed. Touches: in-memory SQLite only.

require_once 'api_keys_service_accounts_php.php';

class ApiKeyServiceTest {
    private PDO $pdo;
    private InMemoryRateLimiter $rateLimiter;
    private ApiKeyService $service;
    private int $now = 0;

    /** Fresh database, a fixed clock (2026-06-01 10:00:00 UTC) and bcrypt cost 4. */
    public function setUp(): void {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->rateLimiter = new InMemoryRateLimiter();
        $this->now = gmmktime(10, 0, 0, 6, 1, 2026);
        $this->service = new ApiKeyService($this->pdo, $this->rateLimiter, fn(): int => $this->now, 4);
    }

    public function run(): void {
        $tests = [
            'testCreateKeyWithScopes',
            'testUseKeySuccess',
            'testRevokeKey',
            'testRateLimitExceeded',
            'testScopeCheckFailure',
            'testRotateKeyGracePeriod',
            'testExpiredKey',
            'testUsageStats',
            'testAdminAudit',
            'testManagementCallsActOnlyOnOwnKeys'
        ];

        $passed = 0;
        $failed = 0;

        foreach ($tests as $test) {
            $this->setUp();
            try {
                $this->$test();
                echo "✓ {$test} passed\n";
                $passed++;
            } catch (Throwable $e) {
                echo "✗ {$test} failed: " . $e->getMessage() . "\n";
                echo $e->getTraceAsString() . "\n";
                $failed++;
            }
        }

        echo "\nTotal: " . ($passed + $failed) . " | Passed: {$passed} | Failed: {$failed}\n";
        exit($failed > 0 ? 1 : 0);
    }

    private function assert(bool $condition, string $message = 'Assertion failed'): void {
        if (!$condition) {
            throw new Exception($message);
        }
    }

    // KEYS-01
    public function testCreateKeyWithScopes(): void {
        $res = $this->service->createApiKey(1, 'My Integration', ['read:deployments', 'write:webhooks'], '2026-12-31', 1000);
        
        $this->assert(isset($res['api_key_id']), 'Should return api_key_id');
        $this->assert(strpos($res['key'], 'sk_live_') === 0, 'Should start with sk_live_');
        $this->assert($res['rate_limit'] === 1000, 'Should match rate limit');
        $this->assert($res['expires_at'] === '2026-12-31', 'Should match expires_at');
        $listed = $this->service->listApiKeys(1)['keys'];
        $this->assert(count($listed) === 1 && $listed[0]['scopes'] === ['read:deployments', 'write:webhooks'], 'Scopes are stored');
        $this->assert(!array_key_exists('key', $listed[0]), 'The key is never listed');
        $stored = $this->pdo->query('SELECT key_secret_hash FROM api_keys')->fetchColumn();
        $this->assert(strpos($res['key'], (string)$stored) === false && str_starts_with((string)$stored, '$2y$'), 'Only a bcrypt hash is stored');
    }

    // KEYS-02
    public function testUseKeySuccess(): void {
        $res = $this->service->createApiKey(1, 'My Integration', ['read:deployments'], null, 1000);
        $rawKey = $res['key'];

        $auth = $this->service->authenticateAndValidate($rawKey, 'GET', '/deployments');
        $this->assert($auth['valid'] === true, 'Authentication should succeed');
        $this->assert($auth['user_id'] === 1, 'User ID should match');
    }

    // KEYS-03
    public function testRevokeKey(): void {
        $res = $this->service->createApiKey(1, 'My Integration', ['read:deployments'], null, 1000);
        $rawKey = $res['key'];
        $keyId = $res['api_key_id'];

        $revokeRes = $this->service->revokeApiKey(1, $keyId);
        $this->assert($revokeRes['success'] === true, 'Revocation should succeed');

        $auth = $this->service->authenticateAndValidate($rawKey, 'GET', '/deployments');
        $this->assert($auth['valid'] === false, 'Authentication should fail after revocation');
        $this->assert($auth['status'] === 401, 'Status should be 401');
    }

    // KEYS-04
    /**
     * KEYS-04. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the row is "1001st request in hour returns 429"; the test used
     * a limit of 3. It now uses the default limit (1000) and makes 1001 requests in one hour; the next hour
     * the key works again.
     */
    public function testRateLimitExceeded(): void {
        $res = $this->service->createApiKey(1, 'My Integration', ['read:deployments']);
        $rawKey = $res['key'];
        $this->assert($res['rate_limit'] === 1000, 'Default limit is 1000/hour');

        for ($i = 1; $i <= 1000; $i++) {
            $auth = $this->service->authenticateAndValidate($rawKey, 'GET', '/deployments');
            if ($auth['valid'] !== true) {
                $this->assert(false, "Request {$i} should succeed");
            }
        }

        $auth = $this->service->authenticateAndValidate($rawKey, 'GET', '/deployments');
        $this->assert($auth['valid'] === false, '1001st request should be rate limited');
        $this->assert($auth['status'] === 429, 'Status should be 429');
        $stats = $this->service->getApiKeyUsageStats(1, $res['api_key_id'], '2026-06-01 00:00:00', '2026-06-02 00:00:00');
        $this->assert($stats['rate_limit_hits'] === 1 && $stats['total_requests'] === 1001, 'The 429 is logged');

        $this->now += 3600;
        $this->assert($this->service->authenticateAndValidate($rawKey, 'GET', '/deployments')['valid'] === true, 'A new hour resets the count');
    }

    // KEYS-05
    public function testScopeCheckFailure(): void {
        $res = $this->service->createApiKey(1, 'My Integration', ['read:deployments'], null, 1000);
        $rawKey = $res['key'];

        $auth = $this->service->authenticateAndValidate($rawKey, 'POST', '/deployments');
        $this->assert($auth['valid'] === false, 'Should fail scope check');
        $this->assert($auth['status'] === 403, 'Status should be 403');
    }

    // KEYS-06
    public function testRotateKeyGracePeriod(): void {
        $res = $this->service->createApiKey(1, 'My Integration', ['read:deployments'], null, 1000);
        $oldKey = $res['key'];
        $oldKeyId = $res['api_key_id'];

        $rotation = $this->service->rotateApiKey(1, $oldKeyId);
        $newKey = $rotation['new_key'];

        $authOld = $this->service->authenticateAndValidate($oldKey, 'GET', '/deployments');
        $this->assert($authOld['valid'] === true, 'Old key should still work during grace period');

        $authNew = $this->service->authenticateAndValidate($newKey, 'GET', '/deployments');
        $this->assert($authNew['valid'] === true, 'New key should work immediately');

        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the clock moves past the 24 h grace period (the test edited the row).
        $this->now += 86400 + 1;

        $authOldExpired = $this->service->authenticateAndValidate($oldKey, 'GET', '/deployments');
        $this->assert($authOldExpired['valid'] === false, 'Old key should fail after grace period expires');
        $this->assert($authOldExpired['status'] === 401, 'Old key gets 401 after the grace period');
        $this->assert($this->service->authenticateAndValidate($newKey, 'GET', '/deployments')['valid'] === true, 'New key still works');
    }

    // KEYS-07
    public function testExpiredKey(): void {
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: expires_at is one hour after the fixed clock, then the clock passes it.
        $res = $this->service->createApiKey(1, 'My Integration', ['read:deployments'], gmdate('Y-m-d H:i:s', $this->now + 3600), 1000);
        $rawKey = $res['key'];
        $this->assert($this->service->authenticateAndValidate($rawKey, 'GET', '/deployments')['valid'] === true, 'Works before expires_at');
        $this->now += 3600;

        $auth = $this->service->authenticateAndValidate($rawKey, 'GET', '/deployments');
        $this->assert($auth['valid'] === false, 'Expired key should fail authentication');
        $this->assert($auth['status'] === 401, 'Status should be 401');
    }

    // KEYS-08
    public function testUsageStats(): void {
        $res = $this->service->createApiKey(1, 'My Integration', ['read:deployments', 'write:billing'], null, 1000);
        $rawKey = $res['key'];
        $keyId = $res['api_key_id'];

        $this->service->authenticateAndValidate($rawKey, 'GET', '/deployments');
        $this->service->authenticateAndValidate($rawKey, 'POST', '/billing');
        $this->service->authenticateAndValidate($rawKey, 'DELETE', '/deployments'); // 403

        $from = gmdate('Y-m-d H:i:s', $this->now - 3600);
        $to = gmdate('Y-m-d H:i:s', $this->now + 3600);

        $stats = $this->service->getApiKeyUsageStats(1, $keyId, $from, $to);

        $this->assert($stats['total_requests'] === 3, 'Should record 3 requests');
        $this->assert($stats['requests_by_endpoint']['GET /deployments'] === 1, 'Should record 1 GET /deployments');
        $this->assert($stats['requests_by_endpoint']['POST /billing'] === 1, 'Should record 1 POST /billing');
        $this->assert($stats['errors']['403'] === 1, 'Should record 1 403 error');
    }

    // KEYS-09
    public function testAdminAudit(): void {
        $this->service->createApiKey(1, 'Key 1', ['*'], null, 1000);
        $this->service->createApiKey(1, 'Key 2', ['read:users'], null, 1000);
        $this->service->createApiKey(2, 'Key 3', ['write:users'], null, 1000);

        $admin = ['user_id' => 99, 'is_admin' => true];
        $auditAll = $this->service->adminListAllKeys($admin);
        $this->assert($auditAll['total'] === 3, 'Admin should see all 3 keys');
        $this->assert(!array_key_exists('key_secret_hash', $auditAll['keys'][0]), 'No hash in the admin list');

        $auditUser1 = $this->service->adminListAllKeys($admin, 1);
        $this->assert($auditUser1['total'] === 2, 'Admin should see 2 keys for user 1');

        $auditActive = $this->service->adminListAllKeys($admin, null, 'active');
        $this->assert($auditActive['total'] === 3, 'All keys should be active');

        $denied = $this->service->adminListAllKeys(['user_id' => 1, 'is_admin' => false]);
        $this->assert(($denied['status'] ?? null) === 403, 'A non-admin cannot list every key');
    }

    /**
     * Revoke, rotate and usage stats act only on the verified caller's own keys: another user's key id gets
     * not_found and nothing changes. Why: identity from the verified caller (common rules); anyone could revoke
     * any key by id. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
     */
    public function testManagementCallsActOnlyOnOwnKeys(): void {
        $res = $this->service->createApiKey(1, 'Owner key', ['read:deployments']);
        $id = $res['api_key_id'];
        $this->assert(($this->service->revokeApiKey(2, $id)['status'] ?? null) === 404, 'Another user cannot revoke it');
        $this->assert(($this->service->getApiKeyUsageStats(2, $id, '2026-01-01', '2027-01-01')['status'] ?? null) === 404, 'Another user cannot read its usage');
        try {
            $this->service->rotateApiKey(2, $id);
            $this->assert(false, 'Another user cannot rotate it');
        } catch (Exception $e) {
            $this->assert($e->getCode() === 404, 'Rotate by another user is 404');
        }
        $this->assert($this->service->authenticateAndValidate($res['key'], 'GET', '/deployments')['valid'] === true, 'The key still works');
        $this->assert(count($this->service->listApiKeys(1)['keys']) === 1, 'No rotated copy was created');
    }
}

$testRunner = new ApiKeyServiceTest();
$testRunner->run();
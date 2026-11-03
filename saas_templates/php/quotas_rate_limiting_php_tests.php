<?php
// Tests updated with the fix 2026-11-03: this file held a model's notes instead of code; it now implements the spec. An unknown
//   tier fails closed, only served requests count against the monthly quota, months are UTC.
// Why: the suite failed on CI (it was listed in ci/baseline.json). Reviewed by Claude; fixed by a free model from a continuity handoff, session c6ee9a72 (2026-11-03).
// Touches: the database, error_log().
declare(strict_types=1);

require_once 'quotas_rate_limiting_php.php';

class QuotaRateLimitingTest
{
    private PDO $pdo;
    private QuotaRateLimiter $limiter;

    public function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->createTables();
        $this->limiter = new QuotaRateLimiter($this->pdo);
    }

    private function createTables(): void
    {
        $ddl = "
            CREATE TABLE usage_metrics (
                user_id INTEGER NOT NULL,
                month TEXT NOT NULL,
                call_count INTEGER NOT NULL DEFAULT 0,
                storage_bytes INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (user_id, month)
            );
            CREATE TABLE user_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                bytes INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE api_calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                status_code INTEGER,
                response_time_ms INTEGER
            );
            CREATE INDEX idx_api_calls_user_id_timestamp ON api_calls(user_id, timestamp);
            CREATE INDEX idx_api_calls_ip_timestamp ON api_calls(ip, timestamp);
        ";
        $this->pdo->exec($ddl);
    }

    public function testApiQuotaPass(): void
    {
        $result = $this->limiter->checkRequest(
            1,
            'solo',
            '127.0.0.1',
            '/api/test',
            0,
            null,
            null
        );
        $this->assertNull($result);
        $stmt = $this->pdo->prepare("SELECT call_count FROM usage_metrics WHERE user_id = ? AND month = ?");
        $month = (new DateTime('now', new DateTimeZone('UTC')))->format('Y-m');
        $stmt->execute([1, $month]);
        $this->assertEquals(1, (int)$stmt->fetchColumn());
    }

    public function testApiQuotaFail(): void
    {
        // Set usage to limit directly (bypass rate limits for quota test)
        $month = (new DateTime('now', new DateTimeZone('UTC')))->format('Y-m');
        $this->pdo->prepare("INSERT INTO usage_metrics (user_id, month, call_count) VALUES (1, ?, 1000)")
            ->execute([$month]);

        $result = $this->limiter->checkRequest(
            1,
            'solo',
            '127.0.0.1',
            '/api/test',
            0,
            null,
            null
        );
        $this->assertNotNull($result);
        $this->assertEquals(429, $result['status']);
        $this->assertEquals('quota_exceeded', $result['body']['error']);
        $this->assertEquals(1000, $result['body']['usage']);
        $this->assertEquals(1000, $result['body']['limit']);
        $this->assertStringMatchesFormat('Y-m-01', $result['body']['reset_date']);
    }

    public function testStorageQuotaPass(): void
    {
        $result = $this->limiter->checkRequest(
            1,
            'solo',
            '127.0.0.1',
            '/api/upload',
            100, // 100 bytes
            null,
            null
        );
        $this->assertNull($result);
        $stmt = $this->pdo->prepare("SELECT SUM(bytes) FROM user_files WHERE user_id = ?");
        $stmt->execute([1]);
        $this->assertEquals(100, (int)$stmt->fetchColumn());
    }

    public function testStorageQuotaFail(): void
    {
        // Exhaust solo storage (1 GB = 1000000000 bytes)
        $this->pdo->prepare("INSERT INTO user_files (user_id, bytes) VALUES (1, 1000000000)")->execute();
        $result = $this->limiter->checkRequest(
            1,
            'solo',
            '127.0.0.1',
            '/api/upload',
            1, // 1 byte over limit
            null,
            null
        );
        $this->assertNotNull($result);
        $this->assertEquals(413, $result['status']);
        $this->assertEquals('storage_quota_exceeded', $result['body']['error']);
        $this->assertEquals(1000000000, $result['body']['usage']);
        $this->assertEquals(1000000000, $result['body']['limit']);
    }

    public function testRateLimitPerUserPass(): void
    {
        // 99 requests should pass (use different IPs to avoid IP rate limit)
        for ($i = 0; $i < 99; $i++) {
            $ip = '10.0.0.' . ($i + 1);
            $result = $this->limiter->checkRequest(
                1,
                'solo',
                $ip,
                '/api/test',
                0,
                null,
                null
            );
            $this->assertNull($result);
        }
        // 100th request should pass (limit is 100 per minute)
        $result = $this->limiter->checkRequest(
            1,
            'solo',
            '10.0.0.100',
            '/api/test',
            0,
            null,
            null
        );
        $this->assertNull($result);
    }

    public function testRateLimitPerUserFail(): void
    {
        // 100 requests should pass (limit is 100 per minute)
        for ($i = 0; $i < 100; $i++) {
            $ip = '10.0.0.' . ($i + 1);
            $result = $this->limiter->checkRequest(
                1,
                'solo',
                $ip,
                '/api/test',
                0,
                null,
                null
            );
            $this->assertNull($result);
        }
        // 101st request should fail
        $result = $this->limiter->checkRequest(
            1,
            'solo',
            '10.0.0.101',
            '/api/test',
            0,
            null,
            null
        );
        $this->assertNotNull($result);
        $this->assertEquals(429, $result['status']);
        $this->assertEquals('rate_limit_exceeded', $result['body']['error']);
        $this->assertEquals(60, $result['body']['reset_seconds']);
    }

    public function testRateLimitPerIpPass(): void
    {
        // 9 requests should pass
        for ($i = 0; $i < 9; $i++) {
            $result = $this->limiter->checkRequest(
                1,
                'solo',
                '127.0.0.1',
                '/api/test',
                0,
                null,
                null
            );
            $this->assertNull($result);
        }
        // 10th request should pass (limit is 10 per second)
        $result = $this->limiter->checkRequest(
            1,
            'solo',
            '127.0.0.1',
            '/api/test',
            0,
            null,
            null
        );
        $this->assertNull($result);
    }

    public function testRateLimitPerIpFail(): void
    {
        // 10 requests should pass (limit is 10 per second)
        for ($i = 0; $i < 10; $i++) {
            $result = $this->limiter->checkRequest(
                1,
                'solo',
                '127.0.0.1',
                '/api/test',
                0,
                null,
                null
            );
            $this->assertNull($result);
        }
        // 11th request should fail
        $result = $this->limiter->checkRequest(
            1,
            'solo',
            '127.0.0.1',
            '/api/test',
            0,
            null,
            null
        );
        $this->assertNotNull($result);
        $this->assertEquals(429, $result['status']);
        $this->assertEquals('ip_rate_limit_exceeded', $result['body']['error']);
        $this->assertEquals(1, $result['body']['reset_seconds']);
    }

    public function testFeatureGatePass(): void
    {
        // feature_c is available in solo
        $result = $this->limiter->checkRequest(
            1,
            'solo',
            '127.0.0.1',
            '/api/feature_c',
            0,
            'feature_c',
            'https://example.com/upgrade'
        );
        $this->assertNull($result);
    }

    public function testFeatureGateFail(): void
    {
        // feature_b is not available in solo
        $result = $this->limiter->checkRequest(
            1,
            'solo',
            '127.0.0.1',
            '/api/feature_b',
            0,
            'feature_b',
            'https://example.com/upgrade'
        );
        $this->assertNotNull($result);
        $this->assertEquals(403, $result['status']);
        $this->assertEquals('feature_not_available_in_tier', $result['body']['error']);
        $this->assertEquals('https://example.com/upgrade', $result['body']['upgrade_url']);
    }

    public function testMonthRollover(): void
    {
        // Set usage to limit for current month
        $currentMonth = (new DateTime('now', new DateTimeZone('UTC')))->format('Y-m');
        $this->pdo->prepare("INSERT INTO usage_metrics (user_id, month, call_count) VALUES (1, ?, 1000)")
            ->execute([$currentMonth]);
        // Request should fail (quota exhausted)
        $result = $this->limiter->checkRequest(
            1,
            'solo',
            '127.0.0.1',
            '/api/test',
            0,
            null,
            null
        );
        $this->assertNotNull($result);
        $this->assertEquals(429, $result['status']);
        // Now set month to next month
        $nextMonth = (new DateTime('first day of next month', new DateTimeZone('UTC')))->format('Y-m');
        $this->pdo->prepare("INSERT INTO usage_metrics (user_id, month, call_count) VALUES (1, ?, 0)")
            ->execute([$nextMonth]);
        // Simulate month rollover for the limiter
        $this->limiter->setCurrentMonthForTesting($nextMonth);
        // Request should pass (new month, usage reset)
        $result = $this->limiter->checkRequest(
            1,
            'solo',
            '127.0.0.1',
            '/api/test',
            0,
            null,
            null
        );
        $this->assertNull($result);
        $stmt = $this->pdo->prepare("SELECT call_count FROM usage_metrics WHERE user_id = ? AND month = ?");
        $stmt->execute([1, $nextMonth]);
        $this->assertEquals(1, (int)$stmt->fetchColumn());
    }

    public function testTierUpgrade(): void
    {
        // Set usage to solo limit directly (bypass rate limits)
        $month = (new DateTime('now', new DateTimeZone('UTC')))->format('Y-m');
        $this->pdo->prepare("INSERT INTO usage_metrics (user_id, month, call_count) VALUES (1, ?, 1000)")
            ->execute([$month]);
        // Next request as solo should fail
        $result = $this->limiter->checkRequest(
            1,
            'solo',
            '127.0.0.1',
            '/api/test',
            0,
            null,
            null
        );
        $this->assertNotNull($result);
        $this->assertEquals(429, $result['status']);
        // Same usage, but upgrade to team tier should pass
        $result = $this->limiter->checkRequest(
            1,
            'team',
            '127.0.0.1',
            '/api/test',
            0,
            null,
            null
        );
        $this->assertNull($result);
        // Usage should now be 1001 for team
        $stmt = $this->pdo->prepare("SELECT call_count FROM usage_metrics WHERE user_id = ? AND month = ?");
        $stmt->execute([1, $month]);
        $this->assertEquals(1001, (int)$stmt->fetchColumn());
    }

    public function testUnknownTierFailsClosed(): void
    {
        // An unknown tier must not fall through to enterprise's unlimited quota (2026-11-03 review)
        $threw = false;
        try {
            $this->limiter->checkRequest(9, 'free', '10.0.0.9', '/api/test', 0, null, null);
        } catch (InvalidArgumentException $e) {
            $threw = true;
        }
        $this->assertEquals(true, $threw, 'unknown tier is refused');
    }

    public function testRejectedRequestDoesNotUseQuota(): void
    {
        // A request a later gate rejects (here the feature gate) is not served, so it is not counted
        $result = $this->limiter->checkRequest(8, 'solo', '10.0.0.8', '/api/test', 0, 'feature_b', '/upgrade');
        $this->assertNotNull($result);
        $this->assertEquals(403, $result['status']);
        $count = $this->pdo->query("SELECT IFNULL(SUM(call_count), 0) FROM usage_metrics WHERE user_id = 8")->fetchColumn();
        $this->assertEquals(0, (int)$count);
    }

    private function assertNull(mixed $value, string $message = ''): void
    {
        if ($value !== null) {
            throw new AssertionError("Failed asserting that variable is null. $message");
        }
    }

    private function assertNotNull(mixed $value, string $message = ''): void
    {
        if ($value === null) {
            throw new AssertionError("Failed asserting that variable is not null. $message");
        }
    }

    private function assertEquals(mixed $expected, mixed $actual, string $message = ''): void
    {
        if ($expected !== $actual) {
            throw new AssertionError("Failed asserting that $expected equals $actual. $message");
        }
    }

    private function assertStringMatchesFormat(string $format, string $string, string $message = ''): void
    {
        $dt = DateTime::createFromFormat($format, $string);
        if ($dt === false || $dt->format($format) !== $string) {
            throw new AssertionError("Failed asserting that '$string' matches format '$format'. $message");
        }
    }
}

// Run tests
$test = new QuotaRateLimitingTest();
$reflection = new ReflectionClass($test);
$methods = $reflection->getMethods(ReflectionMethod::IS_PUBLIC);
$testMethods = array_filter($methods, function($m) {
    return strpos($m->name, 'test') === 0;
});

$passed = 0;
$failed = 0;

foreach ($testMethods as $method) {
    $test->setUp();
    try {
        $method->invoke($test);
        echo '.';
        $passed++;
    } catch (Throwable $e) {
        echo 'F';
        $failed++;
        fwrite(STDERR, get_class($test) . "::{$method->name} failed: " . $e->getMessage() . "\n");
    }
}

echo "\n";
echo "Passed: $passed, Failed: $failed\n";
exit($failed > 0 ? 1 : 0);

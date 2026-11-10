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
    /** Fixed test time (2026-11-10 12:00:00 UTC); the limiter reads it through its injected clock. */
    private int $now = 0;

    /**
     * Fresh in-memory database and a limiter on a fixed clock, so the per-second and per-minute windows never
     * straddle a real second boundary (it used the wall clock; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
     */
    public function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->createTables();
        $this->now = gmmktime(12, 0, 0, 11, 10, 2026);
        $this->limiter = new QuotaRateLimiter($this->pdo, fn(): int => $this->now);
    }

    /**
     * QUOTA-13: enterprise's -1 limits are unlimited. A 5 TB upload is stored, and API calls past every other
     * tier's monthly limit (team 10,000) never get 429 from the quota; the usage still counts.
     * Why: amended spec. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory database.
     */
    // QUOTA-13
    public function testEnterpriseMinusOneIsUnlimited(): void
    {
        $huge = 5 * 1000 * 1000 * 1000 * 1000;
        $result = $this->limiter->checkRequest(7, 'enterprise', '10.0.7.1', '/upload', $huge, null, null);
        $this->assertNull($result, 'a 5 TB enterprise upload passes');
        $this->assertEquals($huge, (int)$this->pdo->query("SELECT SUM(bytes) FROM user_files WHERE user_id = 7")->fetchColumn());
        $this->pdo->prepare("UPDATE usage_metrics SET call_count = 10001 WHERE user_id = 7 AND month = ?")
            ->execute([gmdate('Y-m', $this->now)]);
        for ($i = 0; $i < 3; $i++) {
            $this->now += 2; // stay clear of the per-second IP limit; the quota is what is under test
            $result = $this->limiter->checkRequest(7, 'enterprise', '10.0.7.1', '/api/test', 0, null, null);
            $this->assertNull($result, 'enterprise call past every other tier\'s limit passes');
        }
        $this->assertEquals(10004, (int)$this->pdo->query("SELECT call_count FROM usage_metrics WHERE user_id = 7")->fetchColumn());
        // The same usage on team is rejected, so the pass above is the -1 rule, not a broken check.
        $result = $this->limiter->checkRequest(7, 'team', '10.0.7.2', '/api/test', 0, null, null);
        $this->assertEquals(429, $result['status']);
        $this->assertEquals(10000, $result['body']['limit']);
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

    // QUOTA-01
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
        $month = gmdate('Y-m', $this->now); // the limiter's clock month (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
        $stmt->execute([1, $month]);
        $this->assertEquals(1, (int)$stmt->fetchColumn());
    }

    // QUOTA-02
    public function testApiQuotaFail(): void
    {
        // Set usage to limit directly (bypass rate limits for quota test)
        $month = gmdate('Y-m', $this->now); // the limiter's clock month (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
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

    // QUOTA-03
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

    // QUOTA-04
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

    // QUOTA-05
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

    // QUOTA-06
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

    // QUOTA-07
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

    // QUOTA-08
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

    // QUOTA-09
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

    // QUOTA-10
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

    // QUOTA-11
    public function testMonthRollover(): void
    {
        // Set usage to limit for current month (the limiter's clock month; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
        $currentMonth = gmdate('Y-m', $this->now);
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
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the clock moves into the next month instead of overriding the month and
        // pre-seeding a zero row, so the rollover itself (a new month starts at zero usage) is what is tested.
        $this->now = gmmktime(0, 0, 5, 12, 1, 2026);
        $nextMonth = gmdate('Y-m', $this->now);
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

    // QUOTA-12
    public function testTierUpgrade(): void
    {
        // Set usage to solo limit directly (bypass rate limits)
        $month = gmdate('Y-m', $this->now); // the limiter's clock month (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
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

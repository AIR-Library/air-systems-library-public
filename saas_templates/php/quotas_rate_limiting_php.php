<?php
// Repaired 2026-11-03: this file held a model's notes instead of code; it now implements the spec. An unknown
//   tier fails closed, only served requests count against the monthly quota, months are UTC.
// Why: the suite failed on CI (it was listed in ci/baseline.json). Reviewed by Claude; fixed by a free model from a continuity handoff, session c6ee9a72 (2026-11-03).
// Touches: the database, error_log().
// Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): -1 is the unlimited limit in every quota (QUOTA-13), and
//   time comes from an injectable clock (rate-limit windows, api_calls timestamps, the current month).
declare(strict_types=1);

class QuotaRateLimiter
{
    private PDO $db;
    private ?string $currentMonthOverride = null;
    /** Limit value that means "unlimited" in every quota (quotas_rate_limiting.md, QUOTA-13). */
    public const UNLIMITED = -1;
    /** @var Closure(): int */
    private Closure $clock;

    /**
     * Inputs: $db (shared connection), $clock (optional fn(): int unix seconds; default time()).
     * Why: deterministic tests; the per-second IP window used SQLite's datetime('now') and could straddle a
     * second boundary. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database connection settings.
     */
    public function __construct(PDO $db, ?Closure $clock = null)
    {
        $this->db = $db;
        $this->clock = $clock ?? static fn(): int => time();
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    public static function setupSchema(PDO $db): void
    {
        $db->exec("
            CREATE TABLE IF NOT EXISTS usage_metrics (
                user_id INTEGER NOT NULL,
                month TEXT NOT NULL,
                call_count INTEGER NOT NULL DEFAULT 0,
                storage_bytes INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (user_id, month)
            );
            CREATE TABLE IF NOT EXISTS user_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                bytes INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS api_calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                status_code INTEGER,
                response_time_ms INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_api_calls_user_id_timestamp ON api_calls(user_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_api_calls_ip_timestamp ON api_calls(ip, timestamp);
        ");
    }

    public function setCurrentMonthForTesting(?string $month): void
    {
        $this->currentMonthOverride = $month;
    }

    public function checkRequest(
        int $user_id,
        string $tier,
        string $ip,
        string $endpoint,
        int $file_size = 0,
        ?string $feature = null,
        ?string $upgrade_url = null
    ): ?array {
        // 1. rate_limit_per_user
        if (!$this->checkRateLimitPerUser($user_id)) {
            return [
                'status' => 429,
                'body' => [
                    'error' => 'rate_limit_exceeded',
                    'reset_seconds' => 60
                ]
            ];
        }

        // 2. rate_limit_per_ip
        if (!$this->checkRateLimitPerIp($ip)) {
            return [
                'status' => 429,
                'body' => [
                    'error' => 'ip_rate_limit_exceeded',
                    'reset_seconds' => 1
                ]
            ];
        }

        // 3. api_call_quota
        $apiQuotaResult = $this->checkApiCallQuota($user_id, $tier);
        if ($apiQuotaResult !== true) {
            return [
                'status' => 429,
                'body' => $apiQuotaResult
            ];
        }

        // 4. storage_quota
        $storageQuotaResult = $this->checkStorageQuota($user_id, $tier, $file_size);
        if ($storageQuotaResult !== true) {
            return [
                'status' => 413,
                'body' => $storageQuotaResult
            ];
        }

        // 5. feature_gate
        if ($feature !== null) {
            $featureGateResult = $this->checkFeatureGate($user_id, $tier, $feature, $upgrade_url);
            if ($featureGateResult !== true) {
                return [
                    'status' => 403,
                    'body' => $featureGateResult
                ];
            }
        }

        // All checks passed - log the API call, and only now count it against the monthly quota
        // (a request a later gate rejects was not served, so it must not use up quota)
        $this->logApiCall($user_id, $ip, $endpoint);
        $this->incrementApiCallUsage($user_id, $this->getCurrentMonth(), 1);

        // Store file if upload size provided
        if ($file_size > 0) {
            $stmt = $this->db->prepare("INSERT INTO user_files (user_id, bytes) VALUES (?, ?)");
            $stmt->execute([$user_id, $file_size]);
        }

        return null;
    }

    /** rate_limit_per_user: PASS if fewer than 100 calls in the last 60 s by the clock (QUOTA-05/06; clock 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). */
    private function checkRateLimitPerUser(int $user_id): bool
    {
        $stmt = $this->db->prepare(
            "SELECT COUNT(*) FROM api_calls WHERE user_id = ? AND timestamp > ?"
        );
        $stmt->execute([$user_id, $this->ts(($this->clock)() - 60)]);
        $count = (int)$stmt->fetchColumn();

        $this->whyChain('rate_limit_per_user', [
            'user_id' => $user_id,
            'current_usage' => $count,
            'limit' => 100
        ]);

        return $count < 100;
    }

    /** rate_limit_per_ip: PASS if fewer than 10 calls in the last 1 s by the clock (QUOTA-07/08; clock 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). */
    private function checkRateLimitPerIp(string $ip): bool
    {
        $stmt = $this->db->prepare(
            "SELECT COUNT(*) FROM api_calls WHERE ip = ? AND timestamp > ?"
        );
        $stmt->execute([$ip, $this->ts(($this->clock)() - 1)]);
        $count = (int)$stmt->fetchColumn();

        $this->whyChain('rate_limit_per_ip', [
            'ip' => $ip,
            'current_usage' => $count,
            'limit' => 10
        ]);

        return $count < 10;
    }

    /** api_call_quota: PASS if the limit is -1 (unlimited) or usage + 1 <= limit, else the 429 body (QUOTA-01/02/13, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). */
    private function checkApiCallQuota(int $user_id, string $tier): bool|array
    {
        $month = $this->getCurrentMonth();
        $currentUsage = $this->getCurrentApiCallUsage($user_id, $month);
        $limit = $this->getQuotaLimit($tier, 'api_call');

        if ($limit === self::UNLIMITED) { // -1 = unlimited (QUOTA-13)
            $passed = true;
            $limitForDisplay = $limit;
        } else {
            $passed = ($currentUsage + 1) <= $limit;
            $limitForDisplay = $limit;
        }

        $this->whyChain('api_quota_check', [
            'user_id' => $user_id,
            'tier' => $tier,
            'current_usage' => $currentUsage,
            'limit' => $limitForDisplay
        ]);

        if (!$passed) {
            $resetDate = $this->getResetDate($month);
            return [
                'error' => 'quota_exceeded',
                'usage' => $currentUsage,
                'limit' => $limitForDisplay,
                'reset_date' => $resetDate
            ];
        }

        return true;
    }

    /** storage_quota: PASS if the limit is -1 (unlimited) or stored + incoming <= limit, else the 413 body (QUOTA-03/04/13, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). */
    private function checkStorageQuota(int $user_id, string $tier, int $file_size): bool|array
    {
        $currentStorage = $this->getCurrentStorageUsage($user_id);
        $limit = $this->getQuotaLimit($tier, 'storage');

        if ($limit === self::UNLIMITED) { // -1 = unlimited (QUOTA-13)
            $passed = true;
            $limitForDisplay = $limit;
        } else {
            $passed = ($currentStorage + $file_size) <= $limit;
            $limitForDisplay = $limit;
        }

        $this->whyChain('storage_quota_check', [
            'user_id' => $user_id,
            'tier' => $tier,
            'current_usage' => $currentStorage,
            'limit' => $limitForDisplay
        ]);

        if (!$passed) {
            return [
                'error' => 'storage_quota_exceeded',
                'usage' => $currentStorage,
                'limit' => $limitForDisplay
            ];
        }

        return true;
    }

    private function checkFeatureGate(int $user_id, string $tier, string $feature, ?string $upgrade_url): bool|array
    {
        $features = [
            'feature_a' => ['team', 'enterprise'],
            'feature_b' => ['enterprise'],
            'feature_c' => ['solo', 'team', 'enterprise']
        ];

        $allowedTiers = $features[$feature] ?? [];
        $passed = in_array($tier, $allowedTiers, true);

        $this->whyChain('feature_gate', [
            'user_id' => $user_id,
            'feature' => $feature,
            'tier' => $tier,
            'allowed_tiers' => implode(',', $allowedTiers)
        ]);

        if (!$passed) {
            return [
                'error' => 'feature_not_available_in_tier',
                'upgrade_url' => $upgrade_url ?? ''
            ];
        }

        return true;
    }

    /** Record a served call in api_calls with the clock's UTC time (was SQLite's datetime('now'), 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: the database. */
    private function logApiCall(int $user_id, string $ip, string $endpoint): void
    {
        $stmt = $this->db->prepare(
            "INSERT INTO api_calls (user_id, ip, endpoint, timestamp) VALUES (?, ?, ?, ?)"
        );
        $stmt->execute([$user_id, $ip, $endpoint, $this->ts(($this->clock)())]);
    }

    /** Format unix seconds as the UTC 'Y-m-d H:i:s' text stored in api_calls.timestamp. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    private function ts(int $unix): string
    {
        return gmdate('Y-m-d H:i:s', $unix);
    }

    private function whyChain(string $gate, array $context): void
    {
        $parts = [];
        foreach ($context as $key => $value) {
            $parts[] = sprintf('%s=%s', $key, is_string($value) ? $value : (string)$value);
        }
        error_log('why_chain: gate=' . $gate . ', ' . implode(', ', $parts));
    }

    /**
     * Limit for a tier and quota type ('api_call' or 'storage'). Output: the limit, or UNLIMITED (-1).
     * Throws InvalidArgumentException for an unknown tier (fail closed). Why: QUOTA-13 makes -1 the unlimited
     * value in every quota (it was null). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private function getQuotaLimit(string $tier, string $type): int
    {
        $limits = [
            'solo' => [
                'api_call' => 1000,
                'storage' => 1000000000 // 1 GB
            ],
            'team' => [
                'api_call' => 10000,
                'storage' => 100000000000 // 100 GB
            ],
            'enterprise' => [
                'api_call' => self::UNLIMITED,
                'storage' => self::UNLIMITED
            ]
        ];

        if (!array_key_exists($tier, $limits)) {
            // Fail closed: an unknown tier must not fall through to enterprise's unlimited quota
            throw new InvalidArgumentException("unknown tier: $tier");
        }
        return $limits[$tier][$type];
    }

    private function getCurrentApiCallUsage(int $user_id, string $month): int
    {
        $stmt = $this->db->prepare(
            "SELECT IFNULL(SUM(call_count), 0) FROM usage_metrics WHERE user_id = ? AND month = ?"
        );
        $stmt->execute([$user_id, $month]);
        return (int)$stmt->fetchColumn();
    }

    private function getCurrentStorageUsage(int $user_id): int
    {
        $stmt = $this->db->prepare(
            "SELECT IFNULL(SUM(bytes), 0) FROM user_files WHERE user_id = ?"
        );
        $stmt->execute([$user_id]);
        return (int)$stmt->fetchColumn();
    }

    /** 'Y-m' of the clock (UTC), unless overridden for tests. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private function getCurrentMonth(): string
    {
        return $this->currentMonthOverride ?? gmdate('Y-m', ($this->clock)());
    }

    private function getResetDate(string $month): string
    {
        $dt = DateTime::createFromFormat('Y-m', $month);
        $dt->modify('first day of next month');
        return $dt->format('Y-m-d');
    }

    private function incrementApiCallUsage(int $user_id, string $month, int $increment): void
    {
        // Try to update first
        $stmt = $this->db->prepare(
            "UPDATE usage_metrics SET call_count = call_count + ?, updated_at = datetime('now') WHERE user_id = ? AND month = ?"
        );
        $stmt->execute([$increment, $user_id, $month]);
        if ($stmt->rowCount() === 0) {
            $stmt = $this->db->prepare(
                "INSERT INTO usage_metrics (user_id, month, call_count, updated_at) VALUES (?, ?, ?, datetime('now'))"
            );
            $stmt->execute([$user_id, $month, $increment]);
        }
    }
}

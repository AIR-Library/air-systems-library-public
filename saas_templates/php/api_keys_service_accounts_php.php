<?php
/**
 * API keys and service accounts (api_keys_service_accounts.md): scoped keys, per-key hourly rate limits,
 * rotation with a 24 h grace period, usage stats and an admin audit list.
 *
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: management calls take the VERIFIED caller (revoke, rotate and
 * usage stats act only on the caller's own keys, else not_found; the admin list needs an admin caller, else
 * 403); time comes from an injectable clock (UTC) instead of date()/time() in the server's zone; the rate
 * limiter's hour window uses that clock; the bcrypt cost is configurable.
 * Touches: the database (api_keys, api_key_usage) and the rate limiter's store.
 */

interface RateLimiterInterface {
    /** True when the key already made $limitPerHour requests in the UTC hour of $now (then a hit is recorded). */
    public function isRateLimited(string $apiKeyId, int $limitPerHour, int $now): bool;
    public function recordHit(string $apiKeyId): void;
    public function getRateLimitHits(string $apiKeyId): int;
}

class InMemoryRateLimiter implements RateLimiterInterface {
    private array $requests = [];
    private array $hits = [];

    public function isRateLimited(string $apiKeyId, int $limitPerHour, int $now): bool {
        $hourKey = gmdate('Y-m-d\TH:00:00', $now);
        $key = "{$apiKeyId}:{$hourKey}";

        if (!isset($this->requests[$key])) {
            $this->requests[$key] = 0;
        }

        if ($this->requests[$key] >= $limitPerHour) {
            $this->recordHit($apiKeyId);
            return true;
        }

        $this->requests[$key]++;
        return false;
    }

    public function recordHit(string $apiKeyId): void {
        if (!isset($this->hits[$apiKeyId])) {
            $this->hits[$apiKeyId] = 0;
        }
        $this->hits[$apiKeyId]++;
    }

    public function getRateLimitHits(string $apiKeyId): int {
        return $this->hits[$apiKeyId] ?? 0;
    }
}

class ApiKeyService {
    private PDO $pdo;
    private RateLimiterInterface $rateLimiter;
    /** @var Closure(): int */
    private Closure $clock;
    private int $bcryptCost;

    /**
     * Inputs: $pdo, $rateLimiter, $clock (fn(): int unix seconds; default time()), $bcryptCost (password_hash
     * cost, default 10; tests lower it so 1001 requests run quickly). Creates the tables.
     * Why: deterministic time (common rules). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (DDL).
     */
    public function __construct(PDO $pdo, RateLimiterInterface $rateLimiter, ?Closure $clock = null, int $bcryptCost = 10) {
        $this->pdo = $pdo;
        $this->rateLimiter = $rateLimiter;
        $this->clock = $clock ?? static fn(): int => time();
        $this->bcryptCost = $bcryptCost;
        $this->initializeDatabase();
    }

    /** UTC 'Y-m-d H:i:s' for unix seconds (default now from the clock). Touches: nothing. */
    private function ts(?int $unix = null): string {
        return gmdate('Y-m-d H:i:s', $unix ?? ($this->clock)());
    }

    /** UTC ISO 8601 'Y-m-d\TH:i:s\Z'. Touches: nothing. */
    private function iso(int $unix): string {
        return gmdate('Y-m-d\TH:i:s\Z', $unix);
    }

    /**
     * The key row when it belongs to $callerUserId, else null (a missing key and another user's key look the
     * same). Why: management calls act only on the caller's own keys. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (read).
     */
    private function ownedKey(int $callerUserId, int $apiKeyId): ?array {
        $stmt = $this->pdo->prepare('SELECT * FROM api_keys WHERE id = :id AND user_id = :uid');
        $stmt->execute([':id' => $apiKeyId, ':uid' => $callerUserId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    private function initializeDatabase(): void {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name VARCHAR(255) NOT NULL,
                key_secret_hash VARCHAR(255) NOT NULL,
                scopes TEXT NOT NULL,
                rate_limit INTEGER NOT NULL DEFAULT 1000,
                expires_at DATETIME NULL,
                created_at DATETIME NOT NULL,
                last_used_at DATETIME NULL,
                is_active TINYINT NOT NULL DEFAULT 1,
                grace_expires_at DATETIME NULL
            );
        ");

        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS api_key_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key_id INTEGER NOT NULL,
                endpoint VARCHAR(255) NOT NULL,
                method VARCHAR(10) NOT NULL,
                status INTEGER NOT NULL,
                timestamp DATETIME NOT NULL,
                FOREIGN KEY (api_key_id) REFERENCES api_keys(id)
            );
        ");
    }

    public function createApiKey(int $userId, string $name, array $scopes, ?string $expiresAt = null, int $rateLimit = 1000, string $env = 'live'): array {
        $secret = bin2hex(random_bytes(24));
        $hash = password_hash($secret, PASSWORD_BCRYPT, ['cost' => $this->bcryptCost]);
        $createdAt = $this->ts();

        $stmt = $this->pdo->prepare("
            INSERT INTO api_keys (user_id, name, key_secret_hash, scopes, rate_limit, expires_at, created_at, is_active)
            VALUES (:user_id, :name, :hash, :scopes, :rate_limit, :expires_at, :created_at, 1)
        ");

        $stmt->execute([
            ':user_id' => $userId,
            ':name' => $name,
            ':hash' => $hash,
            ':scopes' => json_encode($scopes),
            ':rate_limit' => $rateLimit,
            ':expires_at' => $expiresAt,
            ':created_at' => $createdAt
        ]);

        $id = $this->pdo->lastInsertId();
        $rawKey = "sk_{$env}_{$id}_{$secret}";

        return [
            'api_key_id' => (int)$id,
            'key' => $rawKey,
            'created_at' => $createdAt,
            'expires_at' => $expiresAt,
            'rate_limit' => $rateLimit
        ];
    }

    public function listApiKeys(int $userId): array {
        $stmt = $this->pdo->prepare("
            SELECT id, name, scopes, created_at, last_used_at, rate_limit, is_active 
            FROM api_keys 
            WHERE user_id = :user_id
        ");
        $stmt->execute([':user_id' => $userId]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $keys = [];
        foreach ($rows as $row) {
            $keys[] = [
                'api_key_id' => (int)$row['id'],
                'name' => $row['name'],
                'scopes' => json_decode($row['scopes'], true),
                'created_at' => $row['created_at'],
                'last_used_at' => $row['last_used_at'],
                'rate_limit' => (int)$row['rate_limit'],
                'is_active' => (bool)$row['is_active']
            ];
        }

        return ['keys' => $keys];
    }

    /**
     * DELETE /api-keys/:id for the verified caller's own key: the key stops working at once (no grace).
     * Output: {success: true, revoked_at} or {success: false, error: 'not_found', status: 404} for a missing
     * key or another user's. Why: anyone could revoke any key by id (changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
     * Touches: the database.
     */
    public function revokeApiKey(int $callerUserId, int $apiKeyId): array {
        if ($this->ownedKey($callerUserId, $apiKeyId) === null) {
            return ['success' => false, 'error' => 'not_found', 'status' => 404];
        }
        $stmt = $this->pdo->prepare("
            UPDATE api_keys 
            SET is_active = 0, grace_expires_at = NULL 
            WHERE id = :id AND user_id = :uid
        ");
        $stmt->execute([':id' => $apiKeyId, ':uid' => $callerUserId]);

        return [
            'success' => true,
            'revoked_at' => $this->iso(($this->clock)())
        ];
    }

    /**
     * POST /api-keys/:id/rotate for the verified caller's own key: a new key with the same scopes, limit and
     * expiry; the old one keeps working for 24 h. Output: {new_key, old_key_revoked_at, grace_period_ends_at}.
     * Throws Exception(404) for a missing key or another user's. Why: anyone could rotate any key (changed
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: the database.
     */
    public function rotateApiKey(int $callerUserId, int $apiKeyId): array {
        $oldKey = $this->ownedKey($callerUserId, $apiKeyId);

        if (!$oldKey) {
            throw new Exception("API Key not found", 404);
        }

        $newKeyData = $this->createApiKey(
            (int)$oldKey['user_id'],
            $oldKey['name'] . ' (Rotated)',
            json_decode($oldKey['scopes'], true),
            $oldKey['expires_at'],
            (int)$oldKey['rate_limit']
        );

        $now = ($this->clock)();
        $gracePeriodEndsAt = $this->ts($now + 86400); // 24 hours grace period

        $updateStmt = $this->pdo->prepare("
            UPDATE api_keys 
            SET is_active = 0, grace_expires_at = :grace_expires_at 
            WHERE id = :id
        ");
        $updateStmt->execute([
            ':grace_expires_at' => $gracePeriodEndsAt,
            ':id' => $apiKeyId
        ]);

        return [
            'new_key' => $newKeyData['key'],
            'old_key_revoked_at' => $this->iso($now),
            'grace_period_ends_at' => $this->iso($now + 86400)
        ];
    }

    public function authenticateAndValidate(string $rawKey, string $method, string $endpoint): array {
        if (!preg_match('/^sk_(live|test)_(\d+)_(.+)$/', $rawKey, $matches)) {
            return ['valid' => false, 'error' => 'Invalid key format', 'status' => 401];
        }

        $id = (int)$matches[2];
        $secret = $matches[3];

        $stmt = $this->pdo->prepare("SELECT * FROM api_keys WHERE id = :id");
        $stmt->execute([':id' => $id]);
        $key = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$key) {
            return ['valid' => false, 'error' => 'Key not found', 'status' => 401];
        }

        if (!password_verify($secret, $key['key_secret_hash'])) {
            return ['valid' => false, 'error' => 'Invalid credentials', 'status' => 401];
        }

        $now = ($this->clock)();
        $isActive = (bool)$key['is_active'];
        $expiresAt = $key['expires_at'] ? (new DateTimeImmutable($key['expires_at'], new DateTimeZone('UTC')))->getTimestamp() : null;
        $graceExpiresAt = $key['grace_expires_at'] ? (new DateTimeImmutable($key['grace_expires_at'], new DateTimeZone('UTC')))->getTimestamp() : null;

        $isValid = false;
        if ($isActive) {
            if ($expiresAt === null || $expiresAt > $now) {
                $isValid = true;
            }
        } else {
            if ($graceExpiresAt !== null && $graceExpiresAt > $now) {
                $isValid = true;
            }
        }

        if (!$isValid) {
            $this->logUsage($id, $endpoint, $method, 401);
            return ['valid' => false, 'error' => 'Key expired or inactive', 'status' => 401];
        }

        $scopes = json_decode($key['scopes'], true);
        $requiredScope = $this->getRequiredScope($method, $endpoint);

        if (!in_array('*', $scopes) && !in_array($requiredScope, $scopes)) {
            $this->logUsage($id, $endpoint, $method, 403);
            return ['valid' => false, 'error' => 'Insufficient permissions', 'status' => 403];
        }

        if ($this->rateLimiter->isRateLimited((string)$id, (int)$key['rate_limit'], $now)) {
            $this->logUsage($id, $endpoint, $method, 429);
            return ['valid' => false, 'error' => 'Rate limit exceeded', 'status' => 429];
        }

        $this->logUsage($id, $endpoint, $method, 200);

        $updateStmt = $this->pdo->prepare("UPDATE api_keys SET last_used_at = :last_used_at WHERE id = :id");
        $updateStmt->execute([
            ':last_used_at' => $this->ts($now),
            ':id' => $id
        ]);

        return [
            'valid' => true,
            'api_key_id' => $id,
            'user_id' => (int)$key['user_id']
        ];
    }

    public function logUsage(int $apiKeyId, string $endpoint, string $method, int $status): void {
        $stmt = $this->pdo->prepare("
            INSERT INTO api_key_usage (api_key_id, endpoint, method, status, timestamp)
            VALUES (:api_key_id, :endpoint, :method, :status, :timestamp)
        ");
        $stmt->execute([
            ':api_key_id' => $apiKeyId,
            ':endpoint' => $endpoint,
            ':method' => $method,
            ':status' => $status,
            ':timestamp' => $this->ts()
        ]);
    }

    /**
     * GET /api-keys/:id/usage for the verified caller's own key: requests in [from, to] counted per
     * "METHOD /endpoint", rate-limit hits and errors by status. Output: the spec's stats, or {error:
     * 'not_found', status: 404} for a missing key or another user's.
     * Why: anyone could read any key's usage (changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: the database (read).
     */
    public function getApiKeyUsageStats(int $callerUserId, int $apiKeyId, string $from, string $to): array {
        if ($this->ownedKey($callerUserId, $apiKeyId) === null) {
            return ['error' => 'not_found', 'status' => 404];
        }
        $stmt = $this->pdo->prepare("
            SELECT endpoint, method, status 
            FROM api_key_usage 
            WHERE api_key_id = :api_key_id 
              AND timestamp >= :from_date 
              AND timestamp <= :to_date
        ");
        $stmt->execute([
            ':api_key_id' => $apiKeyId,
            ':from_date' => $from,
            ':to_date' => $to
        ]);
        $usages = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $totalRequests = count($usages);
        $requestsByEndpoint = [];
        $rateLimitHits = 0;
        $errors = [];

        foreach ($usages as $usage) {
            $endpointKey = "{$usage['method']} {$usage['endpoint']}";
            if (!isset($requestsByEndpoint[$endpointKey])) {
                $requestsByEndpoint[$endpointKey] = 0;
            }
            $requestsByEndpoint[$endpointKey]++;

            $status = (int)$usage['status'];
            if ($status === 429) {
                $rateLimitHits++;
            }

            if ($status >= 400) {
                $statusStr = (string)$status;
                if (!isset($errors[$statusStr])) {
                    $errors[$statusStr] = 0;
                }
                $errors[$statusStr]++;
            }
        }

        return [
            'api_key_id' => $apiKeyId,
            'total_requests' => $totalRequests,
            'requests_by_endpoint' => $requestsByEndpoint,
            'rate_limit_hits' => $rateLimitHits,
            'errors' => $errors
        ];
    }

    /**
     * GET /admin/api-keys: every key (never its secret or hash), filtered by user and status. $caller is the
     * verified caller; only {is_admin: true} may list (else {error: 'forbidden', status: 403}).
     * Why: KEYS-09; the admin gate is 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (anyone could list every key).
     * Touches: the database (read).
     */
    public function adminListAllKeys(array $caller, ?int $userId = null, ?string $status = null): array {
        if (($caller['is_admin'] ?? false) !== true) {
            return ['error' => 'forbidden', 'status' => 403];
        }
        $query = "SELECT * FROM api_keys WHERE 1=1";
        $params = [];

        if ($userId !== null) {
            $query .= " AND user_id = :user_id";
            $params[':user_id'] = $userId;
        }

        if ($status !== null) {
            if ($status === 'active') {
                $query .= " AND is_active = 1 AND (expires_at IS NULL OR expires_at > :now)";
                $params[':now'] = $this->ts();
            } elseif ($status === 'inactive') {
                $query .= " AND (is_active = 0 AND (grace_expires_at IS NULL OR grace_expires_at <= :now))";
                $params[':now'] = $this->ts();
            }
        }

        $stmt = $this->pdo->prepare($query);
        $stmt->execute($params);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $keys = [];
        foreach ($rows as $row) {
            $keys[] = [
                'api_key_id' => (int)$row['id'],
                'user_id' => (int)$row['user_id'],
                'name' => $row['name'],
                'scopes' => json_decode($row['scopes'], true),
                'created_at' => $row['created_at'],
                'last_used_at' => $row['last_used_at'],
                'rate_limit' => (int)$row['rate_limit'],
                'is_active' => (bool)$row['is_active']
            ];
        }

        return [
            'keys' => $keys,
            'total' => count($keys)
        ];
    }

    private function getRequiredScope(string $method, string $endpoint): string {
        $method = strtoupper($method);
        $endpoint = '/' . ltrim($endpoint, '/');

        if (preg_match('#^/users#', $endpoint)) {
            return ($method === 'GET') ? 'read:users' : 'write:users';
        }
        if (preg_match('#^/deployments#', $endpoint)) {
            return ($method === 'GET') ? 'read:deployments' : 'write:deployments';
        }
        if (preg_match('#^/invoices#', $endpoint)) {
            return 'read:invoices';
        }
        if (preg_match('#^/subscriptions#', $endpoint) || preg_match('#^/billing#', $endpoint)) {
            return 'write:billing';
        }
        if (preg_match('#^/webhooks#', $endpoint)) {
            return 'webhook:manage';
        }

        return 'unknown';
    }
}
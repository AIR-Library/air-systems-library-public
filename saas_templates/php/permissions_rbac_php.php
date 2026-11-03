<?php
// Repaired 2026-11-03: foreign keys are switched on, so cascades really delete; one audit row per cascade.
// Why: the suite failed on CI (it was listed in ci/baseline.json). Reviewed by Claude; fixed by a free model from a continuity handoff, session c6ee9a72 (2026-11-03).
// Touches: the database only.
declare(strict_types=1);

class Database
{
    private PDO $pdo;

    public function __construct(string $dsn = 'sqlite::memory:')
    {
        $this->pdo = new PDO($dsn);
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->exec('PRAGMA foreign_keys = ON');
        $this->migrate();
    }

    public function getConnection(): PDO
    {
        return $this->pdo;
    }

    private function migrate(): void
    {
        $sql = <<<SQL
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    tier TEXT NOT NULL CHECK(tier IN ('public','member','admin','owner'))
);

CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    key TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    path TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL
);

CREATE TABLE deployments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    FOREIGN KEY(org_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE TABLE dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment_id INTEGER NOT NULL,
    record TEXT NOT NULL,
    FOREIGN KEY(deployment_id) REFERENCES deployments(id) ON DELETE CASCADE
);

CREATE TABLE theme_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment_id INTEGER NOT NULL,
    config TEXT NOT NULL,
    FOREIGN KEY(deployment_id) REFERENCES deployments(id) ON DELETE CASCADE
);

CREATE TABLE deployment_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment_id INTEGER NOT NULL,
    log TEXT NOT NULL,
    FOREIGN KEY(deployment_id) REFERENCES deployments(id) ON DELETE CASCADE
);

CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    endpoint TEXT NOT NULL,
    required_tier TEXT NOT NULL,
    user_tier TEXT,
    decision TEXT NOT NULL CHECK(decision IN ('PASS','FAIL')),
    timestamp TEXT NOT NULL
);
SQL;
        $this->pdo->exec($sql);
    }
}

class User
{
    public int $id;
    public string $username;
    public string $tier;

    public function __construct(int $id, string $username, string $tier)
    {
        $this->id = $id;
        $this->username = $username;
        $this->tier = $tier;
    }
}

class AuditLog
{
    private PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function log(?int $userId, string $endpoint, string $requiredTier, string $userTier, string $decision): void
    {
        $stmt = $this->pdo->prepare('INSERT INTO audit_logs (user_id, endpoint, required_tier, user_tier, decision, timestamp) VALUES (:user_id, :endpoint, :required_tier, :user_tier, :decision, :timestamp)');
        $stmt->execute([
            ':user_id' => $userId,
            ':endpoint' => $endpoint,
            ':required_tier' => $requiredTier,
            ':user_tier' => $userTier,
            ':decision' => $decision,
            ':timestamp' => (new DateTime('now', new DateTimeZone('UTC')))->format(DateTime::ATOM),
        ]);
    }
}

class RBACMiddleware
{
    private PDO $pdo;
    private AuditLog $audit;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
        $this->audit = new AuditLog($pdo);
    }

    private function tierHierarchy(string $tier): int
    {
        return match ($tier) {
            'public' => 0,
            'member' => 1,
            'admin' => 2,
            'owner' => 3,
            default => -1,
        };
    }

    private function checkTier(string $requiredTier, ?User $currentUser, string $endpoint): array
    {
        $userTier = $currentUser ? $currentUser->tier : 'public';
        $decision = $this->tierHierarchy($userTier) >= $this->tierHierarchy($requiredTier) ? 'PASS' : 'FAIL';
        $this->audit->log($currentUser ? $currentUser->id : null, $endpoint, $requiredTier, $userTier, $decision);

        if ($decision === 'FAIL') {
            $error = $requiredTier === 'owner' ? 'owner_only' : ($requiredTier === 'admin' ? 'admin_only' : 'permission_denied');
            return ['error' => $error, 'code' => 403];
        }
        return ['ok' => true];
    }

    public function requireOwner(callable $handler, ?User $currentUser, string $endpoint): array
    {
        $check = $this->checkTier('owner', $currentUser, $endpoint);
        if (isset($check['error'])) {
            return $check;
        }
        return $handler();
    }

    public function requireAdmin(callable $handler, ?User $currentUser, string $endpoint): array
    {
        $check = $this->checkTier('admin', $currentUser, $endpoint);
        if (isset($check['error'])) {
            return $check;
        }
        return $handler();
    }

    public function requireAuthenticated(callable $handler, ?User $currentUser, string $endpoint): array
    {
        if ($currentUser === null) {
            $this->audit->log(null, $endpoint, 'authenticated', 'public', 'FAIL');
            return ['error' => 'authentication_required', 'code' => 401];
        }
        $this->audit->log($currentUser->id, $endpoint, 'authenticated', $currentUser->tier, 'PASS');
        return $handler();
    }
}

class CascadeDelete
{
    private PDO $pdo;
    private AuditLog $audit;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
        $this->audit = new AuditLog($pdo);
    }

    public function deleteUser(int $userId): array
    {
        try {
            $this->pdo->beginTransaction();

            // Count related items
            $counts = [
                'sessions' => $this->countRows('sessions', ['user_id' => $userId]),
                'keys' => $this->countRows('api_keys', ['user_id' => $userId]),
                'files' => $this->countRows('files', ['user_id' => $userId]),
            ];

            // Delete user (cascade will delete related rows)
            $stmt = $this->pdo->prepare('DELETE FROM users WHERE id = :id');
            $stmt->execute([':id' => $userId]);

            $this->pdo->commit();

            $this->audit->log($userId, 'user_deleted_cascade', 'owner', 'owner', 'PASS');
            // For simplicity, we skip storing deleted_items in audit_log

            return ['ok' => true];
        } catch (Exception $e) {
            $this->pdo->rollBack();
            return ['error' => 'cascade_error', 'code' => 500];
        }
    }

    public function deleteDeployment(int $deploymentId): array
    {
        try {
            $this->pdo->beginTransaction();

            // Count related items
            $counts = [
                'dns' => $this->countRows('dns_records', ['deployment_id' => $deploymentId]),
                'themes' => $this->countRows('theme_configs', ['deployment_id' => $deploymentId]),
                'logs' => $this->countRows('deployment_logs', ['deployment_id' => $deploymentId]),
            ];

            // Delete deployment (cascade will delete related rows)
            $stmt = $this->pdo->prepare('DELETE FROM deployments WHERE id = :id');
            $stmt->execute([':id' => $deploymentId]);

            $this->pdo->commit();

            $this->audit->log(null, 'deployment_deleted_cascade', 'owner', 'owner', 'PASS');
            return ['ok' => true];
        } catch (Exception $e) {
            $this->pdo->rollBack();
            return ['error' => 'cascade_error', 'code' => 500];
        }
    }

    public function deleteOrganization(int $orgId): array
    {
        try {
            $this->pdo->beginTransaction();

            // Count related items
            $counts = [
                'deployments' => $this->countRows('deployments', ['org_id' => $orgId]),
            ];

            // Delete organization (cascade will delete deployments and their cascades)
            $stmt = $this->pdo->prepare('DELETE FROM organizations WHERE id = :id');
            $stmt->execute([':id' => $orgId]);

            $this->pdo->commit();

            $this->audit->log(null, 'org_deleted_cascade', 'owner', 'owner', 'PASS');
            return ['ok' => true];
        } catch (Exception $e) {
            $this->pdo->rollBack();
            return ['error' => 'cascade_error', 'code' => 500];
        }
    }

    private function countRows(string $table, array $conditions): int
    {
        $sql = "SELECT COUNT(*) FROM {$table} WHERE ";
        $parts = [];
        $params = [];
        foreach ($conditions as $col => $val) {
            $parts[] = "{$col} = :{$col}";
            $params[":{$col}"] = $val;
        }
        $sql .= implode(' AND ', $parts);
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return (int)$stmt->fetchColumn();
    }
}

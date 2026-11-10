<?php
// Repaired 2026-11-03: foreign keys are switched on, so cascades really delete; one audit row per cascade.
// Why: the suite failed on CI (it was listed in ci/baseline.json). Reviewed by Claude; fixed by a free model from a continuity handoff, session c6ee9a72 (2026-11-03).
// Touches: the database only.
// Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): delete_organization follows amended RBAC-06 (caller must be an
//   owner member of that org, else 404; deletes its deployments, org API keys, invitations and memberships; never a
//   user account, session or personal API key); cascades write deleted_items inside their transaction.
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

CREATE TABLE organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL
);

-- org_id NULL = a personal key that belongs to its user; set = an org key (RBAC-06)
CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    org_id INTEGER,
    key TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(org_id) REFERENCES organizations(id)
);

-- memberships (org_id, user_id, role) as in organizations_teams.md
CREATE TABLE memberships (
    org_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('owner','admin','member')),
    PRIMARY KEY(org_id, user_id),
    FOREIGN KEY(org_id) REFERENCES organizations(id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE invitations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    FOREIGN KEY(org_id) REFERENCES organizations(id)
);

CREATE TABLE files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    path TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
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
    details TEXT,
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

    /**
     * Append one audit row. Inputs: actor user id (null = anonymous), endpoint or action name, required tier,
     * the caller's tier, PASS/FAIL, and optional $details (JSON-encoded; cascades put {resource_id,
     * deleted_items} here). Output: none. Why: $details added for the cascade logs' deleted_items
     * (RBAC-04/05/06). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function log(?int $userId, string $endpoint, string $requiredTier, string $userTier, string $decision, ?array $details = null): void
    {
        $stmt = $this->pdo->prepare('INSERT INTO audit_logs (user_id, endpoint, required_tier, user_tier, decision, details, timestamp) VALUES (:user_id, :endpoint, :required_tier, :user_tier, :decision, :details, :timestamp)');
        $stmt->execute([
            ':user_id' => $userId,
            ':endpoint' => $endpoint,
            ':required_tier' => $requiredTier,
            ':user_tier' => $userTier,
            ':decision' => $decision,
            ':details' => $details === null ? null : json_encode($details),
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

            // Logged inside the transaction with its deleted_items (it was logged after commit, without them;
            // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
            $this->audit->log($userId, 'user_deleted_cascade', 'owner', 'owner', 'PASS', ['user_id' => $userId, 'deleted_items' => $counts]);
            $this->pdo->commit();

            return ['ok' => true, 'deleted_items' => $counts];
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

            $this->audit->log(null, 'deployment_deleted_cascade', 'owner', 'owner', 'PASS', ['deployment_id' => $deploymentId, 'deleted_items' => $counts]);
            $this->pdo->commit();
            return ['ok' => true, 'deleted_items' => $counts];
        } catch (Exception $e) {
            $this->pdo->rollBack();
            return ['error' => 'cascade_error', 'code' => 500];
        }
    }

    /**
     * Delete an organization (amended RBAC-06).
     *
     * Inputs: $caller (the verified current user; null = anonymous) and $orgId. Output: {ok: true,
     * deleted_items: {deployments, api_keys, invitations, memberships}}, {error: 'not_found', code: 404} when
     * the caller's membership row for this org is not role 'owner' (a global admin or owner tier is not
     * enough, and a missing org looks the same), or {error: 'cascade_error', code: 500} after a rollback.
     * In one transaction: the org's deployments (their DNS, theme configs and logs cascade), API keys whose
     * org_id is this org, ALL its invitations and membership rows, then the org, then the audit row
     * org_deleted_cascade with deleted_items. Never a user account, a session or a personal API key (no
     * org_id); a member's memberships in other orgs are untouched.
     * Why: RBAC-06 as amended 2026-11-10 (it had no gate and deleted only the org row and its deployments).
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function deleteOrganization(?User $caller, int $orgId): array
    {
        if ($caller === null) {
            return ['error' => 'not_found', 'code' => 404];
        }
        try {
            $this->pdo->beginTransaction();

            $stmt = $this->pdo->prepare('SELECT role FROM memberships WHERE org_id = :org AND user_id = :user');
            $stmt->execute([':org' => $orgId, ':user' => $caller->id]);
            if ($stmt->fetchColumn() !== 'owner') {
                $this->pdo->rollBack();
                $this->audit->log($caller->id, 'org_delete', 'org_owner', $caller->tier, 'FAIL', ['org_id' => $orgId]);
                return ['error' => 'not_found', 'code' => 404];
            }

            $counts = [
                'deployments' => $this->countRows('deployments', ['org_id' => $orgId]),
                'api_keys' => $this->countRows('api_keys', ['org_id' => $orgId]),
                'invitations' => $this->countRows('invitations', ['org_id' => $orgId]),
                'memberships' => $this->countRows('memberships', ['org_id' => $orgId]),
            ];

            // Deployments first (DNS records, theme configs and logs go with them by ON DELETE CASCADE).
            $this->pdo->prepare('DELETE FROM deployments WHERE org_id = :id')->execute([':id' => $orgId]);
            $this->pdo->prepare('DELETE FROM api_keys WHERE org_id = :id')->execute([':id' => $orgId]);
            $this->pdo->prepare('DELETE FROM invitations WHERE org_id = :id')->execute([':id' => $orgId]);
            $this->pdo->prepare('DELETE FROM memberships WHERE org_id = :id')->execute([':id' => $orgId]);
            $this->pdo->prepare('DELETE FROM organizations WHERE id = :id')->execute([':id' => $orgId]);

            $this->audit->log($caller->id, 'org_deleted_cascade', 'org_owner', 'owner', 'PASS', ['org_id' => $orgId, 'deleted_items' => $counts]);
            $this->pdo->commit();
            return ['ok' => true, 'deleted_items' => $counts];
        } catch (Exception $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            return ['error' => 'cascade_error', 'code' => 500];
        }
    }

    /**
     * COUNT(*) of $table rows matching every column = value in $conditions. Table and column names come only
     * from this class's own literals, never from callers' input; values are bound parameters.
     * Touches: the database (read). Documented 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     */
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

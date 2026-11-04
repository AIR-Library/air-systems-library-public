<?php
// Tests updated with the fix 2026-11-03: foreign keys are switched on, so cascades really delete; one audit row per cascade.
// Why: the suite failed on CI (it was listed in ci/baseline.json). Reviewed by Claude; fixed by a free model from a continuity handoff, session c6ee9a72 (2026-11-03).
// Touches: the database only.
declare(strict_types=1);

require_once __DIR__ . '/permissions_rbac_php.php';

use PHPUnit\Framework\TestCase;

final class PermissionsRBACTest extends TestCase
{
    private Database $db;
    private PDO $pdo;
    private RBACMiddleware $middleware;
    private CascadeDelete $cascade;

    protected function setUp(): void
    {
        $this->db = new Database();
        $this->pdo = $this->db->getConnection();
        $this->middleware = new RBACMiddleware($this->pdo);
        $this->cascade = new CascadeDelete($this->pdo);
        $this->seedData();
    }

    private function seedData(): void
    {
        $users = [
            ['username' => 'owner', 'tier' => 'owner'],
            ['username' => 'admin', 'tier' => 'admin'],
            ['username' => 'member', 'tier' => 'member'],
            ['username' => 'public', 'tier' => 'public'],
        ];
        foreach ($users as $u) {
            $stmt = $this->pdo->prepare('INSERT INTO users (username, tier) VALUES (:username, :tier)');
            $stmt->execute([':username' => $u['username'], ':tier' => $u['tier']]);
        }

        // Create organization and deployment
        $this->pdo->exec("INSERT INTO organizations (name) VALUES ('Org1')");
        $orgId = $this->pdo->lastInsertId();
        $this->pdo->exec("INSERT INTO deployments (org_id, name) VALUES ({$orgId}, 'Deploy1')");
        $deployId = $this->pdo->lastInsertId();

        // Add related records
        $this->pdo->exec("INSERT INTO dns_records (deployment_id, record) VALUES ({$deployId}, 'dns1')");
        $this->pdo->exec("INSERT INTO theme_configs (deployment_id, config) VALUES ({$deployId}, 'theme1')");
        $this->pdo->exec("INSERT INTO deployment_logs (deployment_id, log) VALUES ({$deployId}, 'log1')");

        // Add user related records
        $userId = $this->pdo->query("SELECT id FROM users WHERE username='owner'")->fetchColumn();
        $this->pdo->exec("INSERT INTO sessions (user_id, token) VALUES ({$userId}, 'sess1')");
        $this->pdo->exec("INSERT INTO api_keys (user_id, key) VALUES ({$userId}, 'key1')");
        $this->pdo->exec("INSERT INTO files (user_id, path) VALUES ({$userId}, '/file1')");
    }

    private function getUser(string $username): User
    {
        $stmt = $this->pdo->prepare('SELECT id, username, tier FROM users WHERE username = :username');
        $stmt->execute([':username' => $username]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return new User((int)$row['id'], $row['username'], $row['tier']);
    }

    public function testRequireOwnerNonOwner(): void
    {
        $user = $this->getUser('admin');
        $response = $this->middleware->requireOwner(fn() => ['ok' => true], $user, 'admin_create_user');
        $this->assertEquals(403, $response['code']);
        $this->assertEquals('owner_only', $response['error']);
    }

    public function testRequireAdminMember(): void
    {
        $user = $this->getUser('member');
        $response = $this->middleware->requireAdmin(fn() => ['ok' => true], $user, 'admin_list_customers');
        $this->assertEquals(403, $response['code']);
        $this->assertEquals('admin_only', $response['error']);
    }

    public function testRequireAuthenticatedPublic(): void
    {
        $response = $this->middleware->requireAuthenticated(fn() => ['ok' => true], null, 'public_signup');
        $this->assertEquals(401, $response['code']);
        $this->assertEquals('authentication_required', $response['error']);
    }

    public function testCascadeDeleteUser(): void
    {
        $user = $this->getUser('owner');
        $result = $this->cascade->deleteUser($user->id);
        $this->assertTrue($result['ok']);

        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM users WHERE id = :id');
        $stmt->execute([':id' => $user->id]);
        $this->assertEquals(0, $stmt->fetchColumn());

        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM sessions WHERE user_id = :id');
        $stmt->execute([':id' => $user->id]);
        $this->assertEquals(0, $stmt->fetchColumn());
    }

    public function testCascadeDeleteDeployment(): void
    {
        $deployId = $this->pdo->query("SELECT id FROM deployments")->fetchColumn();
        $result = $this->cascade->deleteDeployment((int)$deployId);
        $this->assertTrue($result['ok']);

        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM deployments WHERE id = :id');
        $stmt->execute([':id' => $deployId]);
        $this->assertEquals(0, $stmt->fetchColumn());
    }

    public function testCascadeDeleteOrganization(): void
    {
        $orgId = $this->pdo->query("SELECT id FROM organizations")->fetchColumn();
        $result = $this->cascade->deleteOrganization((int)$orgId);
        $this->assertTrue($result['ok']);

        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM organizations WHERE id = :id');
        $stmt->execute([':id' => $orgId]);
        $this->assertEquals(0, $stmt->fetchColumn());
    }

    public function testCascadeOnErrorRollback(): void
    {
        // Create a trigger that prevents session deletion to force rollback
        $this->pdo->exec("CREATE TRIGGER prevent_session_delete BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT, 'cannot delete sessions'); END;");

        // Attempt to delete user; should rollback
        $user = $this->getUser('owner');
        // Verify user has sessions
        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM sessions WHERE user_id = :id');
        $stmt->execute([':id' => $user->id]);
        $this->assertEquals(1, $stmt->fetchColumn());

        // Attempt to delete user; should rollback due to trigger
        $result = $this->cascade->deleteUser($user->id);
        $this->assertEquals(500, $result['code']);
        $this->assertEquals('cascade_error', $result['error']);

        // Verify user still exists
        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM users WHERE id = :id');
        $stmt->execute([':id' => $user->id]);
        $this->assertEquals(1, $stmt->fetchColumn());

        // Verify sessions still exist
        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM sessions WHERE user_id = :id');
        $stmt->execute([':id' => $user->id]);
        $this->assertEquals(1, $stmt->fetchColumn());

        // Clean up trigger
        $this->pdo->exec("DROP TRIGGER prevent_session_delete");
    }

    public function testPermissionAuditLogged(): void
    {
        $user = $this->getUser('member');
        $this->middleware->requireAdmin(fn() => ['ok' => true], $user, 'admin_action');

        $stmt = $this->pdo->prepare('SELECT * FROM audit_logs WHERE endpoint = :endpoint ORDER BY id DESC LIMIT 1');
        $stmt->execute([':endpoint' => 'admin_action']);
        $log = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertNotEmpty($log);
        $this->assertEquals('member', $log['user_tier']);
        $this->assertEquals('admin', $log['required_tier']);
        $this->assertEquals('FAIL', $log['decision']);
    }

    public function testTierHierarchy(): void
    {
        $owner = $this->getUser('owner');
        $admin = $this->getUser('admin');
        $member = $this->getUser('member');

        // Owner can perform admin action
        $res = $this->middleware->requireAdmin(fn() => ['ok' => true], $owner, 'admin_action');
        $this->assertTrue($res['ok']);

        // Admin cannot perform owner action
        $res = $this->middleware->requireOwner(fn() => ['ok' => true], $admin, 'owner_action');
        $this->assertEquals(403, $res['code']);
        $this->assertEquals('owner_only', $res['error']);

        // Member cannot perform admin action
        $res = $this->middleware->requireAdmin(fn() => ['ok' => true], $member, 'admin_action');
        $this->assertEquals(403, $res['code']);
        $this->assertEquals('admin_only', $res['error']);
    }

    public function testPermissionCheckResponseTime(): void
    {
        $user = $this->getUser('admin');
        $start = microtime(true);
        $this->middleware->requireAdmin(fn() => ['ok' => true], $user, 'admin_action');
        $duration = microtime(true) - $start;
        $this->assertLessThan(0.01, $duration);
    }
}
?>

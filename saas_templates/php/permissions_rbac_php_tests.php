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

    // RBAC-01
    public function testRequireOwnerNonOwner(): void
    {
        $user = $this->getUser('admin');
        $response = $this->middleware->requireOwner(fn() => ['ok' => true], $user, 'admin_create_user');
        $this->assertEquals(403, $response['code']);
        $this->assertEquals('owner_only', $response['error']);
    }

    // RBAC-02
    public function testRequireAdminMember(): void
    {
        $user = $this->getUser('member');
        $response = $this->middleware->requireAdmin(fn() => ['ok' => true], $user, 'admin_list_customers');
        $this->assertEquals(403, $response['code']);
        $this->assertEquals('admin_only', $response['error']);
    }

    // RBAC-03
    public function testRequireAuthenticatedPublic(): void
    {
        $response = $this->middleware->requireAuthenticated(fn() => ['ok' => true], null, 'public_signup');
        $this->assertEquals(401, $response['code']);
        $this->assertEquals('authentication_required', $response['error']);
    }

    // RBAC-04
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
        $this->assertEquals(0, $this->pdo->query("SELECT COUNT(*) FROM api_keys WHERE user_id = {$user->id}")->fetchColumn());
        $this->assertEquals(0, $this->pdo->query("SELECT COUNT(*) FROM files WHERE user_id = {$user->id}")->fetchColumn());
        $this->assertSame(['sessions' => 1, 'keys' => 1, 'files' => 1], $result['deleted_items']);
    }

    // RBAC-05
    public function testCascadeDeleteDeployment(): void
    {
        $deployId = $this->pdo->query("SELECT id FROM deployments")->fetchColumn();
        $result = $this->cascade->deleteDeployment((int)$deployId);
        $this->assertTrue($result['ok']);

        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM deployments WHERE id = :id');
        $stmt->execute([':id' => $deployId]);
        $this->assertEquals(0, $stmt->fetchColumn());
        foreach (['dns_records', 'theme_configs', 'deployment_logs'] as $table) {
            $this->assertEquals(0, $this->pdo->query("SELECT COUNT(*) FROM $table")->fetchColumn(), "$table emptied");
        }
    }

    /**
     * RBAC-06 as amended. Org1 (owner: 'owner'; members 'admin' and 'member') and Org2 (owner 'admin', who is
     * also an Org1 member). Org2's owner gets 404 deleting Org1, as do a plain member and an anonymous caller;
     * Org1's owner deletes it: its deployment (and DNS/theme/log rows), org API key, invitations and
     * memberships go; every user account, session and personal API key stays, and the admin's Org2
     * membership, Org2 key and Org2 itself are untouched.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: deleteOrganization now takes the caller and the test proves the gate
     * and what is kept (it only checked that the org row was gone).
     */
    // RBAC-06
    public function testCascadeDeleteOrganization(): void
    {
        $orgId = (int)$this->pdo->query("SELECT id FROM organizations WHERE name = 'Org1'")->fetchColumn();
        $owner = $this->getUser('owner');
        $admin = $this->getUser('admin');
        $member = $this->getUser('member');
        $this->pdo->exec("INSERT INTO organizations (name) VALUES ('Org2')");
        $org2 = (int)$this->pdo->lastInsertId();
        $ins = $this->pdo->prepare('INSERT INTO memberships (org_id, user_id, role) VALUES (?, ?, ?)');
        $ins->execute([$orgId, $owner->id, 'owner']);
        $ins->execute([$orgId, $admin->id, 'admin']);
        $ins->execute([$orgId, $member->id, 'member']);
        $ins->execute([$org2, $admin->id, 'owner']);
        $key = $this->pdo->prepare('INSERT INTO api_keys (user_id, org_id, key) VALUES (?, ?, ?)');
        $key->execute([$owner->id, $orgId, 'org1-key']);
        $key->execute([$admin->id, null, 'admin-personal']);
        $key->execute([$admin->id, $org2, 'org2-key']);
        $this->pdo->exec("INSERT INTO sessions (user_id, token) VALUES ({$admin->id}, 'admin-sess')");
        $inv = $this->pdo->prepare('INSERT INTO invitations (org_id, email, token_hash) VALUES (?, ?, ?)');
        $inv->execute([$orgId, 'a@example.com', 'h1']);
        $inv->execute([$orgId, 'b@example.com', 'h2']);
        $inv->execute([$org2, 'c@example.com', 'h3']);
        $count = fn(string $sql) => (int)$this->pdo->query($sql)->fetchColumn();
        $before = $count('SELECT COUNT(*) FROM users');

        foreach ([$admin, $member, null] as $who) {
            $this->assertSame(['error' => 'not_found', 'code' => 404], $this->cascade->deleteOrganization($who, $orgId));
        }
        $this->assertSame(['error' => 'not_found', 'code' => 404], $this->cascade->deleteOrganization($owner, 999));
        $this->assertSame(1, $count("SELECT COUNT(*) FROM organizations WHERE id = $orgId"));

        $result = $this->cascade->deleteOrganization($owner, $orgId);
        $this->assertTrue($result['ok']);
        $this->assertSame(['deployments' => 1, 'api_keys' => 1, 'invitations' => 2, 'memberships' => 3], $result['deleted_items']);

        $this->assertSame(0, $count("SELECT COUNT(*) FROM organizations WHERE id = $orgId"));
        $this->assertSame(0, $count("SELECT COUNT(*) FROM deployments WHERE org_id = $orgId"));
        $this->assertSame(0, $count('SELECT COUNT(*) FROM dns_records') + $count('SELECT COUNT(*) FROM theme_configs') + $count('SELECT COUNT(*) FROM deployment_logs'));
        $this->assertSame(0, $count("SELECT COUNT(*) FROM api_keys WHERE org_id = $orgId"));
        $this->assertSame(0, $count("SELECT COUNT(*) FROM invitations WHERE org_id = $orgId"));
        $this->assertSame(0, $count("SELECT COUNT(*) FROM memberships WHERE org_id = $orgId"));
        // Kept: every account, sessions, personal keys, and everything of Org2.
        $this->assertSame($before, $count('SELECT COUNT(*) FROM users'));
        $this->assertSame(2, $count('SELECT COUNT(*) FROM sessions'));
        $this->assertSame(['admin-personal', 'key1', 'org2-key'], $this->pdo->query('SELECT key FROM api_keys ORDER BY key')->fetchAll(PDO::FETCH_COLUMN));
        $this->assertSame('owner', $this->pdo->query("SELECT role FROM memberships WHERE org_id = $org2 AND user_id = {$admin->id}")->fetchColumn());
        $this->assertSame(1, $count("SELECT COUNT(*) FROM invitations WHERE org_id = $org2"));
        $details = json_decode((string)$this->pdo->query("SELECT details FROM audit_logs WHERE endpoint = 'org_deleted_cascade'")->fetchColumn(), true);
        $this->assertSame(['org_id' => $orgId, 'deleted_items' => $result['deleted_items']], $details);
    }

    // RBAC-07
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

    // RBAC-08
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

    // RBAC-09
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

    // RBAC-10
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

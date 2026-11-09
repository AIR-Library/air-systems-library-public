<?php
declare(strict_types=1);

require_once 'admin_system_php.php';

use PHPUnit\Framework\TestCase;

final class AdminSystemTest extends TestCase
{
    private AdminSystem $admin;
    private PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->admin = new AdminSystem($this->pdo);

        // Seed users
        $now = (new DateTime('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare('INSERT INTO users (email, name, tier, status, created_at, updated_at) VALUES (:email, :name, :tier, :status, :created_at, :updated_at)');
        $stmt->execute([':email' => 'owner@example.com', ':name' => 'Owner', ':tier' => 'owner', ':status' => 'active', ':created_at' => $now, ':updated_at' => $now]);
        $stmt->execute([':email' => 'admin@example.com', ':name' => 'Admin', ':tier' => 'admin', ':status' => 'active', ':created_at' => $now, ':updated_at' => $now]);
        $stmt->execute([':email' => 'user@example.com', ':name' => 'User', ':tier' => 'user', ':status' => 'active', ':created_at' => $now, ':updated_at' => $now]);

        // Seed customers (with created_at and updated_at for new schema)
        $stmt = $this->pdo->prepare('INSERT INTO customers (email, name, tier, signup_date, invoice_count, status, created_at, updated_at) VALUES (:email, :name, :tier, :signup_date, :invoice_count, :status, :created_at, :updated_at)');
        $stmt->execute([':email' => 'cust1@example.com', ':name' => 'Customer One', ':tier' => 'user', ':signup_date' => $now, ':invoice_count' => 5, ':status' => 'active', ':created_at' => $now, ':updated_at' => $now]);
        $stmt->execute([':email' => 'cust2@example.com', ':name' => 'Customer Two', ':tier' => 'admin', ':signup_date' => $now, ':invoice_count' => 3, ':status' => 'active', ':created_at' => $now, ':updated_at' => $now]);

        // Seed deployments
        $stmt = $this->pdo->prepare('INSERT INTO deployments (customer_id, domain, tier, status, theme_id, created_at, updated_at) VALUES (:customer_id, :domain, :tier, :status, :theme_id, :created_at, :updated_at)');
        $stmt->execute([':customer_id' => 1, ':domain' => 'example.com', ':tier' => 'user', ':status' => 'draft', ':theme_id' => 1, ':created_at' => $now, ':updated_at' => $now]);

        // Set current user to owner for tests
        $stmt = $this->pdo->query('SELECT id FROM users WHERE tier = \'owner\'');
        $owner_id = (int)$stmt->fetchColumn();
        $this->admin->setCurrentUser($owner_id);
    }

    public function testCreateUserHappyPath(): void
    {
        $response = $this->admin->createUser([
            'csrf_token' => $this->admin->csrfToken(),
            'email' => 'newuser@example.com',
            'name' => 'New User',
            'tier' => 'user',
            'notify' => true,
        ]);
        $this->assertTrue($response['success']);
        $this->assertEquals('newuser@example.com', $response['email']);
        $this->assertEquals('user', $response['tier']);
    }

    public function testCreateUserDuplicateEmail(): void
    {
        $response = $this->admin->createUser([
            'csrf_token' => $this->admin->csrfToken(),
            'email' => 'user@example.com',
            'name' => 'Duplicate',
            'tier' => 'user',
            'notify' => false,
        ]);
        $this->assertEquals('email_exists', $response['error']);
    }

    public function testCreateUserNonOwner(): void
    {
        // Switch to admin
        $stmt = $this->pdo->query('SELECT id FROM users WHERE tier = "admin"');
        $admin_id = (int)$stmt->fetchColumn();
        $this->admin->setCurrentUser($admin_id);

        $response = $this->admin->createUser([
            'csrf_token' => $this->admin->csrfToken(),
            'email' => 'another@example.com',
            'name' => 'Another',
            'tier' => 'user',
            'notify' => false,
        ]);
        $this->assertEquals('owner_only', $response['error']);
    }

    public function testResetPasswordHappyPath(): void
    {
        $stmt = $this->pdo->query('SELECT id FROM users WHERE email = "user@example.com"');
        $user_id = (int)$stmt->fetchColumn();

        $response = $this->admin->resetPassword([
            'csrf_token' => $this->admin->csrfToken(),
            'user_id' => $user_id,
        ]);
        $this->assertTrue($response['success']);
        $this->assertEquals('reset_email_sent', $response['status']);
    }

    public function testResetPasswordOwnAccount(): void
    {
        $stmt = $this->pdo->query('SELECT id FROM users WHERE tier = \'owner\'');
        $owner_id = (int)$stmt->fetchColumn();

        $response = $this->admin->resetPassword([
            'csrf_token' => $this->admin->csrfToken(),
            'user_id' => $owner_id,
        ]);
        $this->assertEquals('cannot_reset_own_password', $response['error']);
    }

    public function testChangeRoleHappyPath(): void
    {
        $stmt = $this->pdo->query('SELECT id FROM users WHERE email = "user@example.com"');
        $user_id = (int)$stmt->fetchColumn();

        $response = $this->admin->changeRole([
            'csrf_token' => $this->admin->csrfToken(),
            'user_id' => $user_id,
            'new_tier' => 'admin',
        ]);
        $this->assertTrue($response['success']);
        $this->assertEquals('admin', $response['new_tier']);
    }

    public function testChangeRoleLastOwner(): void
    {
        // Make owner the only owner
        $current_owner_id = $this->admin->getCurrentUserId();
        $stmt = $this->pdo->prepare('UPDATE users SET tier = \'user\' WHERE tier = \'owner\' AND id != :id');
        $stmt->execute([':id' => $current_owner_id]);

        $stmt = $this->pdo->query('SELECT id FROM users WHERE tier = \'owner\'');
        $owner_id = (int)$stmt->fetchColumn();

        $response = $this->admin->changeRole([
            'csrf_token' => $this->admin->csrfToken(),
            'user_id' => $owner_id,
            'new_tier' => 'admin',
        ]);
        $this->assertEquals('cannot_demote_last_owner', $response['error']);
    }

    public function testSuspendUserHappyPath(): void
    {
        $stmt = $this->pdo->query('SELECT id FROM users WHERE email = "user@example.com"');
        $user_id = (int)$stmt->fetchColumn();

        $response = $this->admin->suspendUser([
            'csrf_token' => $this->admin->csrfToken(),
            'user_id' => $user_id,
            'reason' => 'Violation',
        ]);
        $this->assertTrue($response['success']);
        $this->assertTrue($response['suspended']);
    }

    public function testSuspendOwnAccount(): void
    {
        $stmt = $this->pdo->query('SELECT id FROM users WHERE tier = \'owner\'');
        $owner_id = (int)$stmt->fetchColumn();

        $response = $this->admin->suspendUser([
            'csrf_token' => $this->admin->csrfToken(),
            'user_id' => $owner_id,
            'reason' => 'Self suspend',
        ]);
        $this->assertEquals('cannot_suspend_yourself', $response['error']);
    }

    public function testCustomersListPagination(): void
    {
        $response = $this->admin->listCustomers(1, 1);
        $this->assertCount(1, $response);
        $this->assertArrayHasKey('customer_id', $response[0]);
    }

    public function testCustomersDetail(): void
    {
        $response = $this->admin->getCustomer(1);
        $this->assertArrayHasKey('customer_id', $response);
        $this->assertArrayHasKey('subscription_status', $response);
    }

    public function testChangePlan(): void
    {
        $response = $this->admin->changePlan([
            'csrf_token' => $this->admin->csrfToken(),
            'customer_id' => 1,
            'new_tier' => 'admin',
        ]);
        $this->assertTrue($response['success']);
        $this->assertEquals('admin', $response['new_tier']);
    }

    public function testQueueRefund(): void
    {
        $response = $this->admin->queueRefund([
            'csrf_token' => $this->admin->csrfToken(),
            'invoice_id' => 123,
            'amount' => 50.00,
            'reason' => 'Overcharge',
        ]);
        $this->assertTrue($response['success']);
        $this->assertEquals('queued', $response['status']);
    }

    public function testCreateDeployment(): void
    {
        $response = $this->admin->createDeployment([
            'csrf_token' => $this->admin->csrfToken(),
            'customer_id' => 1,
            'domain' => 'newdomain.com',
            'tier' => 'user',
            'theme_id' => 2,
        ]);
        $this->assertTrue($response['success']);
        $this->assertEquals('newdomain.com', $response['domain']);
    }

    public function testPublishDeployment(): void
    {
        // Create a new deployment to publish
        $this->admin->createDeployment([
            'csrf_token' => $this->admin->csrfToken(),
            'customer_id' => 1,
            'domain' => 'publish.com',
            'tier' => 'user',
            'theme_id' => 3,
        ]);
        $stmt = $this->pdo->query('SELECT id FROM deployments WHERE domain = "publish.com"');
        $deployment_id = (int)$stmt->fetchColumn();

        $response = $this->admin->publishDeployment([
            'csrf_token' => $this->admin->csrfToken(),
            'deployment_id' => $deployment_id,
        ]);
        $this->assertTrue($response['success']);
        $this->assertEquals('live', $response['status']);
    }

    public function testGovernanceApprove(): void
    {
        // Create a governance action
        $now = (new DateTime('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare('INSERT INTO governance_actions (action_type, actor_id, target_resource_id, reason, submitted_at) VALUES (:action_type, :actor_id, :target_resource_id, :reason, :submitted_at)');
        $stmt->execute([':action_type' => 'delete_user', ':actor_id' => $this->admin->getCurrentUserId(), ':target_resource_id' => 2, ':reason' => 'Violation', ':submitted_at' => $now]);

        $stmt = $this->pdo->query('SELECT id FROM governance_actions ORDER BY submitted_at DESC LIMIT 1');
        $action_id = (int)$stmt->fetchColumn();

        $response = $this->admin->decideGovernanceAction($action_id, 'approve', ['csrf_token' => $this->admin->csrfToken()]);
        $this->assertTrue($response['success']);
        $this->assertEquals('approved', $response['status']);
    }

    public function testGovernanceReject(): void
    {
        // Create a governance action
        $now = (new DateTime('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare('INSERT INTO governance_actions (action_type, actor_id, target_resource_id, reason, submitted_at) VALUES (:action_type, :actor_id, :target_resource_id, :reason, :submitted_at)');
        $stmt->execute([':action_type' => 'delete_user', ':actor_id' => $this->admin->getCurrentUserId(), ':target_resource_id' => 3, ':reason' => 'Violation', ':submitted_at' => $now]);

        $stmt = $this->pdo->query('SELECT id FROM governance_actions ORDER BY submitted_at DESC LIMIT 1');
        $action_id = (int)$stmt->fetchColumn();

        $response = $this->admin->decideGovernanceAction($action_id, 'reject', ['csrf_token' => $this->admin->csrfToken(), 'reason' => 'Insufficient evidence']);
        $this->assertTrue($response['success']);
        $this->assertEquals('rejected', $response['status']);
    }

    public function testAuditLogSearch(): void
    {
        // Perform some actions to generate logs
        $this->admin->createUser([
            'csrf_token' => $this->admin->csrfToken(),
            'email' => 'audituser@example.com',
            'name' => 'Audit User',
            'tier' => 'user',
            'notify' => false,
        ]);

        $filters = [
            'action_type' => 'user_created',
            'limit' => 10,
            'offset' => 0,
        ];
        $logs = $this->admin->searchAuditLog($filters);
        $this->assertNotEmpty($logs);
        $this->assertEquals('user_created', $logs[0]['action']);
    }

    public function testCsrfTokenSurvivesANewRequest(): void
    {
        // The page and the POST that submits it are separate requests, so separate AdminSystem objects.
        $page = new AdminSystem($this->pdo);
        $post = new AdminSystem($this->pdo, $page->csrfToken());
        $this->assertSame($page->csrfToken(), $post->csrfToken());

        $stranger = new AdminSystem($this->pdo);
        $this->assertNotSame($page->csrfToken(), $stranger->csrfToken());
    }
}

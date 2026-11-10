<?php
declare(strict_types=1);

require_once 'admin_system_php.php';

use PHPUnit\Framework\TestCase;

/**
 * Fake Stripe for change_plan: records every call, returns a subscription with the configured item ids.
 * Why: ADMIN-12 as amended. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing (no network).
 */
final class FakeAdminStripe implements AdminStripeGateway
{
    /** @var list<array> */
    public array $calls = [];
    /** @param list<string> $itemIds */
    public function __construct(public array $itemIds = ['si_current'])
    {
    }
    public function retrieveSubscription(string $subscriptionId): object
    {
        $this->calls[] = ['retrieve', $subscriptionId];
        $sub = new stdClass();
        $sub->items = new stdClass();
        $sub->items->data = array_map(static fn(string $id): object => (object)['id' => $id], $this->itemIds);
        return $sub;
    }
    public function updateSubscription(string $subscriptionId, array $params): object
    {
        $this->calls[] = ['update', $subscriptionId, $params];
        return (object)['id' => $subscriptionId, 'current_period_end' => 1798761600];
    }
}

final class AdminSystemTest extends TestCase
{
    private AdminSystem $admin;
    private PDO $pdo;
    /** @var list<array{0: string, 1: string, 2: string}> e-mails the fake sender received */
    private array $mail = [];
    private FakeAdminStripe $stripe;
    private bool $canPublish = true;

    /**
     * Fresh database, a fake e-mail sender, a fake Stripe and a settable SafetyFlags.can_publish.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the service now takes these as injected dependencies.
     */
    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->mail = [];
        $this->stripe = new FakeAdminStripe();
        $this->canPublish = true;
        $this->admin = new AdminSystem($this->pdo, null, [
            'mailer' => function (string $to, string $subject, string $body): void { $this->mail[] = [$to, $subject, $body]; },
            'stripe' => $this->stripe,
            'can_publish' => fn(int $deploymentId): bool => $this->canPublish,
        ]);

        // Seed users
        $now = (new DateTime('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare('INSERT INTO users (email, name, tier, status, created_at, updated_at) VALUES (:email, :name, :tier, :status, :created_at, :updated_at)');
        $stmt->execute([':email' => 'owner@example.com', ':name' => 'Owner', ':tier' => 'owner', ':status' => 'active', ':created_at' => $now, ':updated_at' => $now]);
        $stmt->execute([':email' => 'admin@example.com', ':name' => 'Admin', ':tier' => 'admin', ':status' => 'active', ':created_at' => $now, ':updated_at' => $now]);
        $stmt->execute([':email' => 'user@example.com', ':name' => 'User', ':tier' => 'user', ':status' => 'active', ':created_at' => $now, ':updated_at' => $now]);

        // Seed customers (with created_at and updated_at for new schema)
        // Customers carry a plan tier and a Stripe subscription (they were seeded with user roles as tiers).
        $stmt = $this->pdo->prepare('INSERT INTO customers (email, name, tier, signup_date, invoice_count, status, stripe_subscription_id, created_at, updated_at) VALUES (:email, :name, :tier, :signup_date, :invoice_count, :status, :sub, :created_at, :updated_at)');
        $stmt->execute([':email' => 'cust1@example.com', ':name' => 'Customer One', ':tier' => 'solo', ':signup_date' => $now, ':invoice_count' => 5, ':status' => 'active', ':sub' => 'sub_cust1', ':created_at' => $now, ':updated_at' => $now]);
        $stmt->execute([':email' => 'cust2@example.com', ':name' => 'Customer Two', ':tier' => 'team', ':signup_date' => $now, ':invoice_count' => 3, ':status' => 'active', ':sub' => 'sub_cust2', ':created_at' => $now, ':updated_at' => $now]);

        // Seed deployments
        $stmt = $this->pdo->prepare('INSERT INTO deployments (customer_id, domain, tier, status, theme_id, created_at, updated_at) VALUES (:customer_id, :domain, :tier, :status, :theme_id, :created_at, :updated_at)');
        $stmt->execute([':customer_id' => 1, ':domain' => 'example.com', ':tier' => 'user', ':status' => 'draft', ':theme_id' => 1, ':created_at' => $now, ':updated_at' => $now]);

        // Set current user to owner for tests
        $stmt = $this->pdo->query('SELECT id FROM users WHERE tier = \'owner\'');
        $owner_id = (int)$stmt->fetchColumn();
        $this->admin->setCurrentUser($owner_id);
    }

    // ADMIN-01
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
        $this->assertEquals('active', $this->pdo->query("SELECT status FROM users WHERE email = 'newuser@example.com'")->fetchColumn());
        $this->assertCount(1, $this->mail, 'invite sent');
        $this->assertSame('newuser@example.com', $this->mail[0][0]);
    }

    // ADMIN-02
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

    // ADMIN-03
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

    // ADMIN-04
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
        // The e-mail is sent; its token is stored only as a hash and never written to the audit log.
        $this->assertCount(1, $this->mail);
        $this->assertSame('user@example.com', $this->mail[0][0]);
        $this->assertSame(1, preg_match('/token=([0-9a-f]{64})/', $this->mail[0][2], $m));
        $this->assertSame(hash('sha256', $m[1]), $this->pdo->query('SELECT token_hash FROM password_resets')->fetchColumn());
        $auditText = implode(' ', array_map('strval', $this->pdo->query('SELECT COALESCE(old_value, \'\') || COALESCE(new_value, \'\') FROM audit_logs')->fetchAll(PDO::FETCH_COLUMN)));
        $this->assertStringNotContainsString($m[1], $auditText);
    }

    // ADMIN-05
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

    // ADMIN-06
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
        $this->assertEquals('admin', $this->pdo->query("SELECT tier FROM users WHERE id = $user_id")->fetchColumn());
        $row = $this->pdo->query("SELECT actor_id, old_value, new_value FROM audit_logs WHERE action = 'role_changed'")->fetch(PDO::FETCH_ASSOC);
        $this->assertSame([(int)$this->admin->getCurrentUserId(), '{"tier":"user"}', '{"tier":"admin"}'], [(int)$row['actor_id'], $row['old_value'], $row['new_value']]);
    }

    // ADMIN-07
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

    // ADMIN-08
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
        $this->assertEquals('suspended', $this->pdo->query("SELECT status FROM users WHERE id = $user_id")->fetchColumn());
        // A suspended user can no longer act as the caller.
        $this->expectException(RuntimeException::class);
        $this->admin->setCurrentUser($user_id);
    }

    // ADMIN-09
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

    // ADMIN-10
    public function testCustomersListPagination(): void
    {
        $response = $this->admin->listCustomers(1, 1);
        $this->assertCount(1, $response);
        $this->assertArrayHasKey('customer_id', $response[0]);
        // Page 2 holds the other customer; both pages have every listed field.
        $page2 = $this->admin->listCustomers(2, 1);
        $this->assertCount(1, $page2);
        $this->assertNotEquals($response[0]['customer_id'], $page2[0]['customer_id']);
        foreach ([$response[0], $page2[0]] as $row) {
            $this->assertSame(['customer_id', 'email', 'name', 'tier', 'signup_date', 'invoice_count', 'status'], array_keys($row));
        }
        $this->assertSame([], $this->admin->listCustomers(3, 1));
    }

    // ADMIN-11
    public function testCustomersDetail(): void
    {
        $response = $this->admin->getCustomer(1);
        $this->assertArrayHasKey('customer_id', $response);
        $this->assertArrayHasKey('subscription_status', $response);
        $this->assertSame(['customer_id', 'email', 'name', 'tier', 'subscription_status', 'payment_method', 'address', 'notes'], array_keys($response));
    }

    /**
     * ADMIN-12 as amended: change_plan retrieves the subscription and updates the existing item id with the
     * new price (one item, prorations), then records the tier and audit_log plan_changed.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: it changed a customer to the user role 'admin' and never reached Stripe.
     */
    // ADMIN-12
    public function testChangePlan(): void
    {
        $response = $this->admin->changePlan([
            'csrf_token' => $this->admin->csrfToken(),
            'customer_id' => 1,
            'new_tier' => 'team',
        ]);
        $this->assertTrue($response['success']);
        $this->assertEquals('team', $response['new_tier']);
        $this->assertEquals('solo', $response['old_tier']);
        $this->assertSame([
            ['retrieve', 'sub_cust1'],
            ['update', 'sub_cust1', ['items' => [['id' => 'si_current', 'price' => AdminSystem::PRICE_IDS['team']]], 'proration_behavior' => 'create_prorations']],
        ], $this->stripe->calls);
        $this->assertEquals('team', $this->pdo->query('SELECT tier FROM customers WHERE id = 1')->fetchColumn());
        $row = $this->pdo->query("SELECT resource_id, old_value, new_value FROM audit_logs WHERE action = 'plan_changed'")->fetch(PDO::FETCH_ASSOC);
        $this->assertSame(['1', '{"tier":"solo"}', '{"tier":"team"}'], [(string)$row['resource_id'], $row['old_value'], $row['new_value']]);
    }

    /**
     * ADMIN-12 refusals: an unknown tier (or a user role) is invalid_tier before Stripe is called; a
     * subscription with two items is subscription_item_ambiguous after the retrieve and before any update.
     * Why: amended ADMIN-12 / BILL-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory database; fake Stripe.
     */
    // ADMIN-12
    public function testChangePlanRefusesBeforeAnyUpdate(): void
    {
        foreach (['admin', 'platinum'] as $tier) {
            $r = $this->admin->changePlan(['csrf_token' => $this->admin->csrfToken(), 'customer_id' => 1, 'new_tier' => $tier]);
            $this->assertSame('invalid_tier', $r['error']);
        }
        $this->assertSame([], $this->stripe->calls);
        $this->stripe->itemIds = ['si_a', 'si_b'];
        $r = $this->admin->changePlan(['csrf_token' => $this->admin->csrfToken(), 'customer_id' => 1, 'new_tier' => 'team']);
        $this->assertSame(['subscription_item_ambiguous', 409], [$r['error'], $r['status']]);
        $this->assertSame([['retrieve', 'sub_cust1']], $this->stripe->calls);
        $this->assertEquals('solo', $this->pdo->query('SELECT tier FROM customers WHERE id = 1')->fetchColumn());
    }

    // ADMIN-13
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
        $row = $this->pdo->query('SELECT invoice_id, amount, status, created_by FROM refunds WHERE id = ' . (int)$response['refund_id'])->fetch(PDO::FETCH_ASSOC);
        $this->assertSame([123, 50.0, 'queued', $this->admin->getCurrentUserId()], [(int)$row['invoice_id'], (float)$row['amount'], $row['status'], (int)$row['created_by']]);
    }

    // ADMIN-14
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
        $this->assertEquals('draft', $this->pdo->query('SELECT status FROM deployments WHERE id = ' . (int)$response['deployment_id'])->fetchColumn());
        // "config initialized"
        $config = $this->pdo->query('SELECT theme_id, tier FROM deployment_configs WHERE deployment_id = ' . (int)$response['deployment_id'])->fetch(PDO::FETCH_ASSOC);
        $this->assertSame([2, 'user'], [(int)$config['theme_id'], $config['tier']]);
    }

    // ADMIN-15
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
        $publish = fn() => $this->admin->publishDeployment(['csrf_token' => $this->admin->csrfToken(), 'deployment_id' => $deployment_id]);

        // Double gate, changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the SafetyFlags.can_publish gate and domain_verified are
        // now checked (they were not), so the test turns each on before the publish succeeds.
        $this->canPublish = false;
        $this->assertSame('publish_not_allowed', $publish()['error']);
        $this->canPublish = true;
        $this->assertSame('domain_not_verified', $publish()['error']);
        $this->assertEquals('draft', $this->pdo->query("SELECT status FROM deployments WHERE id = $deployment_id")->fetchColumn());
        $this->pdo->exec("UPDATE deployments SET domain_verified = 1 WHERE id = $deployment_id");

        $response = $publish();
        $this->assertTrue($response['success']);
        $this->assertEquals('live', $response['status']);
        $this->assertEquals('live', $this->pdo->query("SELECT status FROM deployments WHERE id = $deployment_id")->fetchColumn());
        // The owner half of the gate: an admin cannot publish.
        $this->pdo->exec("UPDATE deployments SET status = 'draft' WHERE id = $deployment_id");
        $this->admin->setCurrentUser((int)$this->pdo->query("SELECT id FROM users WHERE tier = 'admin'")->fetchColumn());
        $this->assertSame('owner_only', $publish()['error']);
    }

    // ADMIN-16
    public function testGovernanceApprove(): void
    {
        // Create a governance action
        $now = (new DateTime('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare('INSERT INTO governance_actions (action_type, actor_id, target_resource_id, reason, submitted_at) VALUES (:action_type, :actor_id, :target_resource_id, :reason, :submitted_at)');
        // Target user 3 (user@example.com); it targeted 2, the admin. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP because
        // approval now really executes the action, so the test names the user whose status it checks.
        $stmt->execute([':action_type' => 'suspend_user', ':actor_id' => $this->admin->getCurrentUserId(), ':target_resource_id' => 3, ':reason' => 'Violation', ':submitted_at' => $now]);

        $stmt = $this->pdo->query('SELECT id FROM governance_actions ORDER BY submitted_at DESC LIMIT 1');
        $action_id = (int)$stmt->fetchColumn();

        $response = $this->admin->decideGovernanceAction($action_id, 'approve', ['csrf_token' => $this->admin->csrfToken()]);
        $this->assertTrue($response['success']);
        $this->assertEquals('approved', $response['status']);
        // "action executed"
        $this->assertEquals('suspended', $this->pdo->query('SELECT status FROM users WHERE id = 3')->fetchColumn());
        $this->assertEquals('approved', $this->pdo->query("SELECT status FROM governance_actions WHERE id = $action_id")->fetchColumn());
        // An action type that cannot be executed stays pending.
        $stmt = $this->pdo->prepare('INSERT INTO governance_actions (action_type, actor_id, target_resource_id, reason, submitted_at) VALUES (?, ?, ?, ?, ?)');
        $stmt->execute(['launch_rockets', $this->admin->getCurrentUserId(), 1, 'x', $now]);
        $other = (int)$this->pdo->lastInsertId();
        $this->assertSame('unsupported_action_type', $this->admin->decideGovernanceAction($other, 'approve', ['csrf_token' => $this->admin->csrfToken()])['error']);
        $this->assertEquals('pending', $this->pdo->query("SELECT status FROM governance_actions WHERE id = $other")->fetchColumn());
    }

    // ADMIN-17
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
        // "reason logged", and the action did not run
        $this->assertEquals('Insufficient evidence', $this->pdo->query("SELECT reason FROM audit_logs WHERE action = 'action_rejected'")->fetchColumn());
        $this->assertEquals('Insufficient evidence', $this->pdo->query("SELECT rejection_reason FROM governance_actions WHERE id = $action_id")->fetchColumn());
        $this->assertEquals('active', $this->pdo->query('SELECT status FROM users WHERE id = 3')->fetchColumn());
    }

    // ADMIN-18
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
        // Filters really filter, and limit/offset page through the results.
        foreach (['a1@example.com', 'a2@example.com'] as $email) {
            $this->admin->createUser(['csrf_token' => $this->admin->csrfToken(), 'email' => $email, 'name' => 'A', 'tier' => 'user', 'notify' => false]);
        }
        $this->admin->suspendUser(['csrf_token' => $this->admin->csrfToken(), 'user_id' => 3, 'reason' => 'x']);
        $all = $this->admin->searchAuditLog(['action_type' => 'user_created']);
        $this->assertCount(3, $all);
        $this->assertSame(['user_created'], array_values(array_unique(array_column($all, 'action'))));
        $page1 = $this->admin->searchAuditLog(['action_type' => 'user_created', 'limit' => 2, 'offset' => 0]);
        $page2 = $this->admin->searchAuditLog(['action_type' => 'user_created', 'limit' => 2, 'offset' => 2]);
        $this->assertCount(2, $page1);
        $this->assertCount(1, $page2);
        $this->assertSame(array_column($all, 'resource_id'), array_merge(array_column($page1, 'resource_id'), array_column($page2, 'resource_id')));
        $byResource = $this->admin->searchAuditLog(['resource_id' => 3]);
        $this->assertSame(['user_suspended'], array_column($byResource, 'action'));
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

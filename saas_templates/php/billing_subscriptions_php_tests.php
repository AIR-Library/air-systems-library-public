<?php
declare(strict_types=1);

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

// The composer autoloader (phpunit, stripe-php) is loaded by the runner's bootstrap, as in every
// other PHP suite; a vendor/ folder next to this file does not exist (the cause of the failure).
require_once __DIR__ . '/billing_subscriptions_php.php';

/**
 * Billing & Subscriptions tests (spec template #4, ten required tests).
 *
 * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. The setup could not run:
 * $this->createMock() inside the static setUpBeforeClass, self::$pdo never assigned, and the
 * Stripe client's magic `subscriptions` property cannot be mocked (Stripe\Subscriptions does not
 * exist). Stripe is now the StripeGateway interface, mocked with the same once()/with()
 * expectations; each test gets a fresh in-memory database (the tests insert the same ids, which
 * collided in one shared database); webhooks carry a real Stripe signature made with the test
 * secret (the old "dummy signature" called Webhook::constructEvent, which throws on it).
 * Touches: an in-memory SQLite database only; no network.
 */
class BillingSystemTest extends TestCase
{
    private static PDO $pdo;
    /** @var StripeGateway&MockObject */
    private StripeGateway $stripeMock;

    protected function setUp(): void
    {
        putenv('STRIPE_SECRET_KEY=test_secret');
        putenv('STRIPE_WEBHOOK_SECRET=test_webhook_secret');
        putenv('DB_DSN=sqlite::memory:');
        putenv('DB_USER=');
        putenv('DB_PASS=');

        // Initialize BillingSystem (creates a fresh in-memory DB)
        BillingSystem::init();
        self::$pdo = BillingSystem::pdo();

        // Replace Stripe with a mock of the gateway interface
        $this->stripeMock = $this->createMock(StripeGateway::class);
        BillingSystem::$stripe = $this->stripeMock;
    }

    /**
     * A valid Stripe-Signature header for $payload (t=..., v1=HMAC-SHA256 of "t.payload").
     */
    private function sign(string $payload, string $secret = 'test_webhook_secret'): string
    {
        $t = time();
        return 't=' . $t . ',v1=' . hash_hmac('sha256', $t . '.' . $payload, $secret);
    }

    // BILL-01
    public function testCreateSubscriptionHappyPath()
    {
        $customerId = 'cus_test';
        $tier = 'solo';

        $stripeSub = new stdClass();
        $stripeSub->id = 'sub_test';
        $stripeSub->current_period_end = time() + 30 * 24 * 60 * 60;

        $this->stripeMock->expects($this->once())
            ->method('createSubscription')
            ->with([
                'customer' => $customerId,
                'items' => [['price' => BillingSystem::PRICE_IDS[$tier]]],
            ])
            ->willReturn($stripeSub);

        $result = BillingSystem::createSubscription($customerId, $tier);
        $this->assertTrue($result['success']);
        $this->assertEquals('sub_test', $result['subscription_id']);

        // Verify DB record
        $stmt = self::$pdo->prepare('SELECT * FROM subscriptions WHERE stripe_subscription_id = :id');
        $stmt->execute([':id' => 'sub_test']);
        $row = $stmt->fetch();
        $this->assertNotFalse($row);
        $this->assertEquals($customerId, $row['customer_id']);
        $this->assertEquals($tier, $row['tier']);
        $this->assertEquals('active', $row['status']);
    }

    // BILL-02
    public function testCreateSubscriptionInvalidTier()
    {
        $this->stripeMock->expects($this->never())->method('createSubscription');
        $result = BillingSystem::createSubscription('cus_test', 'invalid');
        $this->assertArrayHasKey('error', $result);
        $this->assertEquals('invalid_tier', $result['error']);
    }

    // BILL-03
    public function testChangePlanHappyPath()
    {
        // Insert existing subscription
        $stmt = self::$pdo->prepare('INSERT INTO subscriptions (stripe_subscription_id, customer_id, tier, status, created_at, updated_at) VALUES (:id, :cust, :tier, :status, :created, :updated)');
        $stmt->execute([
            ':id' => 'sub_test',
            ':cust' => 'cus_test',
            ':tier' => 'solo',
            ':status' => 'active',
            ':created' => (new DateTime('now', new DateTimeZone('UTC')))->format(DateTime::ATOM),
            ':updated' => (new DateTime('now', new DateTimeZone('UTC')))->format(DateTime::ATOM),
        ]);

        $newTier = 'team';
        $stripeSub = new stdClass();
        $stripeSub->id = 'sub_test';
        $stripeSub->current_period_end = time() + 30 * 24 * 60 * 60;
        $stripeSub->plan = new stdClass();
        $stripeSub->plan->nickname = 'Team Plan';
        $stripeSub->proration_details = [];

        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: BILL-03 as amended. The subscription is retrieved first, and the
        // update names the existing item id with the new price (a bare {price} adds a second item).
        $this->stripeMock->expects($this->once())
            ->method('retrieveSubscription')
            ->with('sub_test')
            ->willReturn(self::remoteSubscription(['si_current']));
        $this->stripeMock->expects($this->once())
            ->method('updateSubscription')
            ->with('sub_test', [
                'items' => [['id' => 'si_current', 'price' => BillingSystem::PRICE_IDS[$newTier]]],
                'proration_behavior' => 'create_prorations',
            ])
            ->willReturn($stripeSub);

        $stripeSub->proration_details = [['amount' => -1250], ['amount' => 300]];
        $result = BillingSystem::changePlan('sub_test', $newTier);
        $this->assertTrue($result['success']);
        $this->assertEquals('team', $result['new_tier']);
        $this->assertEquals('solo', $result['old_tier']);
        $this->assertSame(-950, $result['proration_credit']);
        $audit = json_decode((string)self::$pdo->query("SELECT data FROM audit_logs WHERE action = 'plan_changed'")->fetchColumn(), true);
        $this->assertSame(['subscription_id' => 'sub_test', 'old_tier' => 'solo', 'new_tier' => 'team', 'proration_credits' => -950], $audit);

        // Verify DB update
        $stmt = self::$pdo->prepare('SELECT tier FROM subscriptions WHERE stripe_subscription_id = :id');
        $stmt->execute([':id' => 'sub_test']);
        $row = $stmt->fetch();
        $this->assertEquals($newTier, $row['tier']);
    }

    /**
     * A fake retrieved subscription with the given item ids.
     * Why: BILL-03 tests. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static function remoteSubscription(array $itemIds): object
    {
        $sub = new stdClass();
        $sub->id = 'sub_test';
        $sub->items = new stdClass();
        $sub->items->data = array_map(static function (string $id): object {
            $item = new stdClass();
            $item->id = $id;
            return $item;
        }, $itemIds);
        return $sub;
    }

    /**
     * BILL-03 refusals: an unknown tier is invalid_tier before Stripe is touched, and a subscription with zero
     * or two items is subscription_item_ambiguous (409) after the retrieve and before any update; the tier
     * in our record is unchanged. Why: amended BILL-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: an in-memory SQLite database; Stripe is a mock.
     */
    // BILL-03
    public function testChangePlanRefusesUnknownTierAndAmbiguousItems()
    {
        $now = (new DateTime('now', new DateTimeZone('UTC')))->format(DateTime::ATOM);
        self::$pdo->prepare('INSERT INTO subscriptions (stripe_subscription_id, customer_id, tier, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
            ->execute(['sub_test', 'cus_test', 'solo', 'active', $now, $now]);
        $this->stripeMock->expects($this->never())->method('updateSubscription');
        $this->stripeMock->expects($this->exactly(2))
            ->method('retrieveSubscription')
            ->with('sub_test')
            ->willReturnOnConsecutiveCalls(self::remoteSubscription([]), self::remoteSubscription(['si_a', 'si_b']));

        $this->assertEquals('invalid_tier', BillingSystem::changePlan('sub_test', 'platinum')['error']);
        foreach (['zero items', 'two items'] as $case) {
            $result = BillingSystem::changePlan('sub_test', 'team');
            $this->assertEquals('subscription_item_ambiguous', $result['error'], $case);
            $this->assertEquals(409, $result['status'], $case);
        }
        $this->assertEquals('solo', self::$pdo->query("SELECT tier FROM subscriptions WHERE stripe_subscription_id = 'sub_test'")->fetchColumn());
        $this->assertEquals(0, (int)self::$pdo->query("SELECT COUNT(*) FROM audit_logs WHERE action = 'plan_changed'")->fetchColumn());
    }

    // BILL-04
    public function testQueueRefundHappyPath()
    {
        // Insert invoice
        $stmt = self::$pdo->prepare('INSERT INTO invoices (stripe_invoice_id, customer_id, amount, status, paid_at) VALUES (:id, :cust, :amount, :status, :paid)');
        $stmt->execute([
            ':id' => 'inv_test',
            ':cust' => 'cus_test',
            ':amount' => 1000,
            ':status' => 'succeeded',
            ':paid' => (new DateTime('now', new DateTimeZone('UTC')))->format(DateTime::ATOM),
        ]);

        $result = BillingSystem::queueRefund('inv_test', 500, 'duplicate charge', 'admin');
        $this->assertTrue($result['success']);
        $this->assertEquals(500, $result['amount']);
        $this->assertEquals('queued', $result['status']);

        // Verify DB record
        $stmt = self::$pdo->prepare('SELECT * FROM refunds WHERE id = :id');
        $stmt->execute([':id' => $result['refund_id']]);
        $row = $stmt->fetch();
        $this->assertNotFalse($row);
        $this->assertEquals('inv_test', $row['invoice_id']);
        $this->assertEquals(500, $row['amount']);
        $this->assertEquals('queued', $row['status']);
    }

    // BILL-05
    public function testQueueRefundAmountExceedsInvoice()
    {
        // Insert invoice
        $stmt = self::$pdo->prepare('INSERT INTO invoices (stripe_invoice_id, customer_id, amount, status, paid_at) VALUES (:id, :cust, :amount, :status, :paid)');
        $stmt->execute([
            ':id' => 'inv_test',
            ':cust' => 'cus_test',
            ':amount' => 1000,
            ':status' => 'succeeded',
            ':paid' => (new DateTime('now', new DateTimeZone('UTC')))->format(DateTime::ATOM),
        ]);

        $result = BillingSystem::queueRefund('inv_test', 1500, 'overcharge', 'admin');
        $this->assertArrayHasKey('error', $result);
        $this->assertEquals('refund_exceeds_invoice', $result['error']);

        // Partial refunds add up: 600 fits, a second 600 would exceed the 1000 invoice
        $this->assertTrue(BillingSystem::queueRefund('inv_test', 600, 'partial', 'admin')['success']);
        $result = BillingSystem::queueRefund('inv_test', 600, 'partial again', 'admin');
        $this->assertEquals('refund_exceeds_invoice', $result['error']);
    }

    // BILL-06
    public function testHandleWebhookPaymentSucceeded()
    {
        $payload = json_encode([
            'id' => 'evt_test',
            'type' => 'invoice.payment_succeeded',
            'data' => [
                'object' => [
                    'id' => 'inv_test',
                    'customer' => 'cus_test',
                    'amount' => 1000,
                    'created' => time(),
                ],
            ],
        ]);

        $sigHeader = $this->sign($payload); // was a "dummy signature" that constructEvent rejects

        $result = BillingSystem::handleStripeWebhook($payload, ['Stripe-Signature' => $sigHeader]);
        $this->assertTrue($result['received']);

        // Verify invoice inserted
        $stmt = self::$pdo->prepare('SELECT * FROM invoices WHERE stripe_invoice_id = :id');
        $stmt->execute([':id' => 'inv_test']);
        $row = $stmt->fetch();
        $this->assertNotFalse($row);
        $this->assertEquals('succeeded', $row['status']);
        // "audit logged"
        $audit = json_decode((string)self::$pdo->query("SELECT data FROM audit_logs WHERE action = 'payment_succeeded'")->fetchColumn(), true);
        $this->assertSame('inv_test', $audit['invoice_id']);
    }

    // BILL-07
    public function testHandleWebhookDuplicateEvent()
    {
        $payload = json_encode([
            'id' => 'evt_dup',
            'type' => 'invoice.payment_succeeded',
            'data' => [
                'object' => [
                    'id' => 'inv_dup',
                    'customer' => 'cus_test',
                    'amount' => 1000,
                    'created' => time(),
                ],
            ],
        ]);

        $sigHeader = $this->sign($payload); // was a "dummy signature" that constructEvent rejects

        // First call
        $result1 = BillingSystem::handleStripeWebhook($payload, ['Stripe-Signature' => $sigHeader]);
        $this->assertTrue($result1['received']);

        // Second call
        $result2 = BillingSystem::handleStripeWebhook($payload, ['Stripe-Signature' => $sigHeader]);
        $this->assertTrue($result2['received']);

        // Verify only one invoice record
        $stmt = self::$pdo->prepare('SELECT COUNT(*) as cnt FROM invoices WHERE stripe_invoice_id = :id');
        $stmt->execute([':id' => 'inv_dup']);
        $row = $stmt->fetch();
        $this->assertEquals(1, $row['cnt']);

        // ...and the event's effects (its audit entry) happened once
        $cnt = self::$pdo->query("SELECT COUNT(*) FROM audit_logs WHERE action = 'payment_succeeded'")->fetchColumn();
        $this->assertEquals(1, $cnt);
    }

    // BILL-08
    public function testHandleWebhookSubscriptionUpdated()
    {
        // Insert subscription
        $stmt = self::$pdo->prepare('INSERT INTO subscriptions (stripe_subscription_id, customer_id, tier, status, created_at, updated_at) VALUES (:id, :cust, :tier, :status, :created, :updated)');
        $stmt->execute([
            ':id' => 'sub_test',
            ':cust' => 'cus_test',
            ':tier' => 'solo',
            ':status' => 'active',
            ':created' => (new DateTime('now', new DateTimeZone('UTC')))->format(DateTime::ATOM),
            ':updated' => (new DateTime('now', new DateTimeZone('UTC')))->format(DateTime::ATOM),
        ]);

        $payload = json_encode([
            'id' => 'evt_sub_update',
            'type' => 'customer.subscription.updated',
            'data' => [
                'object' => [
                    'id' => 'sub_test',
                    'customer' => 'cus_test',
                    // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: was 'active' (no change), so "status changed" was untested.
                    'status' => 'past_due',
                    'items' => [
                        'data' => [
                            [
                                'price' => [
                                    'id' => BillingSystem::PRICE_IDS['team'],
                                ],
                            ],
                        ],
                    ],
                    'previous_attributes' => [
                        'plan' => [
                            'nickname' => 'Solo Plan',
                        ],
                    ],
                ],
            ],
        ]);

        $sigHeader = $this->sign($payload); // was a "dummy signature" that constructEvent rejects

        $result = BillingSystem::handleStripeWebhook($payload, ['Stripe-Signature' => $sigHeader]);
        $this->assertTrue($result['received']);

        // Verify tier updated
        $stmt = self::$pdo->prepare('SELECT tier, status FROM subscriptions WHERE stripe_subscription_id = :id');
        $stmt->execute([':id' => 'sub_test']);
        $row = $stmt->fetch();
        $this->assertEquals('team', $row['tier']);
        $this->assertEquals('past_due', $row['status']);
    }

    // BILL-09
    public function testWebhookSignatureInvalid()
    {
        $payload = json_encode(['id' => 'evt_invalid']);
        $result = BillingSystem::handleStripeWebhook($payload, ['Stripe-Signature' => 'invalid_sig']);
        $this->assertArrayHasKey('error', $result);
        $this->assertEquals('invalid_signature', $result['error']);

        // A well-formed signature made with the wrong secret is rejected too
        $result = BillingSystem::handleStripeWebhook($payload, ['Stripe-Signature' => $this->sign($payload, 'wrong_secret')]);
        $this->assertEquals('invalid_signature', $result['error']);
        $cnt = self::$pdo->query('SELECT COUNT(*) FROM events')->fetchColumn();
        $this->assertEquals(0, $cnt);
    }

    // BILL-10
    public function testWebhookResponseTime()
    {
        $payload = json_encode([
            'id' => 'evt_time',
            'type' => 'invoice.payment_succeeded',
            'data' => [
                'object' => [
                    'id' => 'inv_time',
                    'customer' => 'cus_test',
                    'amount' => 1000,
                    'created' => time(),
                ],
            ],
        ]);

        $sigHeader = $this->sign($payload); // was a "dummy signature" that constructEvent rejects

        $start = microtime(true);
        $result = BillingSystem::handleStripeWebhook($payload, ['Stripe-Signature' => $sigHeader]);
        $duration = microtime(true) - $start;

        $this->assertTrue($result['received']);
        $this->assertLessThan(3, $duration);
    }
}

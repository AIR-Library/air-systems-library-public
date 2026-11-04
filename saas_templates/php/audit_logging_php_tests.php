<?php
// Tests updated with the fix 2026-11-03: audit rows are append-only: they can no longer be edited or deleted.
// Why: the suite failed on CI (it was listed in ci/baseline.json). Reviewed by Claude; fixed by a free model from a continuity handoff, session c6ee9a72 (2026-11-03).
// Touches: the database only.
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once 'audit_logging_php.php';

final class AuditLoggerTest extends TestCase
{
    private PDO $pdo;
    private AuditLogger $logger;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->logger = new AuditLogger($this->pdo);
    }

    public function testHappyPath(): void
    {
        $log = $this->logger->logMutation([
            'actor_id' => 123,
            'actor_type' => 'user',
            'action' => 'subscription_changed',
            'resource_type' => 'subscription',
            'resource_id' => '456',
            'old_value' => ['tier' => 'team'],
            'new_value' => ['tier' => 'enterprise'],
            'why_chain_id' => 'wc_789',
            'metadata' => ['ip' => '1.2.3.4'],
        ]);
        $this->assertTrue($log['success']);
        $logs = $this->logger->queryLogs(['actor_id' => 123, 'action' => 'subscription_changed']);
        $this->assertCount(1, $logs['logs']);
        $this->assertEquals('subscription_changed', $logs['logs'][0]['action']);
    }

    public function testReplayNoDivergence(): void
    {
        $resource_id = 'res_1';
        $this->pdo->exec("INSERT INTO resources (id, type, state) VALUES ('$resource_id', 'subscription', '{\"tier\":\"team\"}')");
        $log = $this->logger->logMutation([
            'actor_id' => 1,
            'actor_type' => 'user',
            'action' => 'subscription_changed',
            'resource_type' => 'subscription',
            'resource_id' => $resource_id,
            'old_value' => ['tier' => 'team'],
            'new_value' => ['tier' => 'enterprise'],
        ]);
        $replay = $this->logger->replay($log['log_id']);
        $this->assertFalse($replay['has_diverged']);
        $this->assertEquals(['tier' => 'team'], $replay['resource_state_at_time']);
    }

    public function testReplayWithDivergence(): void
    {
        $resource_id = 'res_2';
        $this->pdo->exec("INSERT INTO resources (id, type, state) VALUES ('$resource_id', 'subscription', '{\"tier\":\"team\"}')");
        $log = $this->logger->logMutation([
            'actor_id' => 2,
            'actor_type' => 'user',
            'action' => 'subscription_changed',
            'resource_type' => 'subscription',
            'resource_id' => $resource_id,
            'old_value' => ['tier' => 'team'],
            'new_value' => ['tier' => 'enterprise'],
        ]);
        // Diverge
        $this->pdo->exec("UPDATE resources SET state = '{\"tier\":\"gold\"}' WHERE id = '$resource_id'");
        $replay = $this->logger->replay($log['log_id']);
        $this->assertTrue($replay['has_diverged']);
    }

    public function testFiltering(): void
    {
        $this->logger->logMutation([
            'actor_id' => 10,
            'actor_type' => 'user',
            'action' => 'user_created',
            'resource_type' => 'user',
            'resource_id' => 'u1',
            'old_value' => null,
            'new_value' => ['name' => 'Alice'],
        ]);
        $this->logger->logMutation([
            'actor_id' => 10,
            'actor_type' => 'user',
            'action' => 'user_suspended',
            'resource_type' => 'user',
            'resource_id' => 'u1',
            'old_value' => ['status' => 'active'],
            'new_value' => ['status' => 'suspended'],
        ]);
        $this->logger->logMutation([
            'actor_id' => 20,
            'actor_type' => 'user',
            'action' => 'user_created',
            'resource_type' => 'user',
            'resource_id' => 'u2',
            'old_value' => null,
            'new_value' => ['name' => 'Bob'],
        ]);
        $logs = $this->logger->queryLogs([
            'actor_id' => 10,
            'action' => 'user_*',
            'resource_type' => 'user',
        ]);
        $this->assertCount(2, $logs['logs']);
    }

    public function testPagination(): void
    {
        for ($i = 0; $i < 150; $i++) {
            $this->logger->logMutation([
                'actor_id' => 1,
                'actor_type' => 'user',
                'action' => 'action_' . $i,
                'resource_type' => 'resource',
                'resource_id' => (string)$i,
                'old_value' => null,
                'new_value' => null,
            ]);
        }
        $page1 = $this->logger->queryLogs(['limit' => 100, 'offset' => 0]);
        $this->assertCount(100, $page1['logs']);
        $this->assertTrue($page1['has_more']);
        $page2 = $this->logger->queryLogs(['limit' => 100, 'offset' => 100]);
        $this->assertCount(50, $page2['logs']);
        $this->assertFalse($page2['has_more']);
    }

    public function testImmutability(): void
    {
        $log = $this->logger->logMutation([
            'actor_id' => 3,
            'actor_type' => 'user',
            'action' => 'test_action',
            'resource_type' => 'test',
            'resource_id' => 't1',
            'old_value' => null,
            'new_value' => null,
        ]);
        $this->expectException(PDOException::class);
        $this->pdo->exec("UPDATE audit_log SET action = 'modified' WHERE id = '{$log['log_id']}'");
    }

    public function testWildcardAction(): void
    {
        $this->logger->logMutation([
            'actor_id' => 4,
            'actor_type' => 'user',
            'action' => 'user_created',
            'resource_type' => 'user',
            'resource_id' => 'u3',
            'old_value' => null,
            'new_value' => null,
        ]);
        $this->logger->logMutation([
            'actor_id' => 4,
            'actor_type' => 'user',
            'action' => 'user_suspended',
            'resource_type' => 'user',
            'resource_id' => 'u3',
            'old_value' => null,
            'new_value' => null,
        ]);
        $this->logger->logMutation([
            'actor_id' => 4,
            'actor_type' => 'user',
            'action' => 'billing_changed',
            'resource_type' => 'subscription',
            'resource_id' => 's1',
            'old_value' => null,
            'new_value' => null,
        ]);
        $logs = $this->logger->queryLogs(['action' => 'user_*']);
        $this->assertCount(2, $logs['logs']);
    }

    public function testSearch(): void
    {
        $this->logger->logMutation([
            'actor_id' => 5,
            'actor_type' => 'user',
            'action' => 'user_created',
            'resource_type' => 'user',
            'resource_id' => 'u4',
            'old_value' => null,
            'new_value' => null,
        ]);
        $this->logger->logMutation([
            'actor_id' => 5,
            'actor_type' => 'user',
            'action' => 'user_updated',
            'resource_type' => 'user',
            'resource_id' => 'u4',
            'old_value' => null,
            'new_value' => null,
        ]);
        $search = $this->logger->search('created', 'user', 10);
        $this->assertCount(1, $search['results']);
        $this->assertEquals('user_created', $search['results'][0]['action']);
    }
}

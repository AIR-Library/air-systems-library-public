<?php
// Tests updated with the fix 2026-11-03: audit rows are append-only: they can no longer be edited or deleted.
// Why: the suite failed on CI (it was listed in ci/baseline.json). Reviewed by Claude; fixed by a free model from a continuity handoff, session c6ee9a72 (2026-11-03).
// Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP) for the amended spec: every read passes a verified admin
//   caller; entries about a resource other than a user name their subject_user_id (or 'none'); the clock is
//   injected (1 s per call, so order is fixed); metadata no longer carries an ip; replay divergence is read from
//   later log entries (the 'resources' side table is gone); AUDIT-05 (1M rows), AUDIT-08, AUDIT-09 and AUDIT-10
//   are new. Each changed test says what changed.
// Touches: an in-memory SQLite database only.
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once 'audit_logging_php.php';

final class AuditLoggerTest extends TestCase
{
    private const ADMIN = ['user_id' => 'admin-1', 'is_admin' => true];
    private PDO $pdo;
    private AuditLogger $logger;
    private DateTimeImmutable $now;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->now = new DateTimeImmutable('2026-01-01T00:00:00Z');
        $this->logger = new AuditLogger($this->pdo, function (): DateTimeImmutable {
            $this->now = $this->now->modify('+1 second');
            return $this->now;
        }, 30);
    }

    /** Every retained row of the three audit tables as text (AUDIT-08). */
    private function allRowsText(): string
    {
        $text = [];
        foreach (['audit_log', 'audit_personal', 'audit_subjects'] as $table) {
            foreach ($this->pdo->query("SELECT * FROM $table")->fetchAll(PDO::FETCH_NUM) as $row) {
                $text[] = json_encode(array_map('strval', array_map(fn($v) => $v ?? '', $row)));
            }
        }
        return implode("\n", $text);
    }

    /** Assert that $call throws AuditException with the given status and code. */
    private function assertRefused(callable $call, int $status, string $code): void
    {
        try {
            $call();
            $this->fail("expected $status $code");
        } catch (AuditException $e) {
            $this->assertSame([$status, $code], [$e->status, $e->errorCode]);
        }
    }

    /**
     * AUDIT-01. Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): subject_user_id names the subscription's
     * owner, the ip moved from metadata (now refused) to the request field, and the query is an admin's.
     */
    // AUDIT-01
    public function testHappyPath(): void
    {
        $log = $this->logger->logMutation([
            'actor_id' => 123,
            'actor_type' => 'user',
            'subject_user_id' => 789,
            'action' => 'subscription_changed',
            'resource_type' => 'subscription',
            'resource_id' => '456',
            'old_value' => ['tier' => 'team'],
            'new_value' => ['tier' => 'enterprise'],
            'why_chain_id' => 'wc_789',
            'ip' => '1.2.3.4',
        ]);
        $this->assertTrue($log['success']);
        $logs = $this->logger->queryLogs(['actor_id' => 123, 'action' => 'subscription_changed'], self::ADMIN);
        $this->assertCount(1, $logs['logs']);
        $entry = $logs['logs'][0];
        $this->assertEquals('subscription_changed', $entry['action']);
        $this->assertSame(['123', '456', ['tier' => 'team'], ['tier' => 'enterprise'], 'wc_789', '1.2.3.4', false],
            [$entry['actor_id'], $entry['resource_id'], $entry['old_value'], $entry['new_value'], $entry['why_chain_id'], $entry['ip'], $entry['personal_erased']]);
        // The event row itself holds none of it: it lives in the personal rows.
        $raw = $this->pdo->query('SELECT resource_id, old_value, new_value, why_chain_id, personal_roles FROM audit_log')->fetch(PDO::FETCH_ASSOC);
        $this->assertSame(['resource_id' => null, 'old_value' => null, 'new_value' => null, 'why_chain_id' => null, 'personal_roles' => 'actor,subject'], $raw);
    }

    /**
     * AUDIT-02, no divergence: the entry is the latest for its resource. Changed 2026-11-10
     * (session_012zDydZCZ4AChqhEZ4oVtaP): divergence is read from later log entries, not a 'resources' table.
     */
    // AUDIT-02
    public function testReplayNoDivergence(): void
    {
        $log = $this->logger->logMutation([
            'actor_id' => 1,
            'actor_type' => 'user',
            'subject_user_id' => 'none',
            'action' => 'subscription_changed',
            'resource_type' => 'subscription',
            'resource_id' => 'res_1',
            'old_value' => ['tier' => 'team'],
            'new_value' => ['tier' => 'enterprise'],
        ]);
        $replay = $this->logger->replay($log['log_id'], self::ADMIN);
        $this->assertFalse($replay['has_diverged']);
        $this->assertEquals(['tier' => 'team'], $replay['resource_state_at_time']);
    }

    /** AUDIT-02, divergence: a later entry changed the same resource (subject and no-subject entries). */
    // AUDIT-02
    public function testReplayWithDivergence(): void
    {
        foreach (['none', '77'] as $subject) {
            $base = ['actor_id' => 2, 'actor_type' => 'user', 'subject_user_id' => $subject, 'action' => 'subscription_changed', 'resource_type' => 'subscription', 'resource_id' => "res_$subject"];
            $first = $this->logger->logMutation($base + ['old_value' => ['tier' => 'team'], 'new_value' => ['tier' => 'enterprise']]);
            $this->logger->logMutation($base + ['old_value' => ['tier' => 'enterprise'], 'new_value' => ['tier' => 'gold']]);
            $replay = $this->logger->replay($first['log_id'], self::ADMIN);
            $this->assertTrue($replay['has_diverged'], "subject $subject");
            $this->assertEquals(['tier' => 'team'], $replay['resource_state_at_time']);
        }
        $this->assertRefused(fn() => $this->logger->replay('missing', self::ADMIN), 404, 'log_not_found');
    }

    // AUDIT-03
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
        $this->logger->logMutation([
            'actor_id' => 10,
            'actor_type' => 'user',
            'subject_user_id' => 'none',
            'action' => 'user_flagged',
            'resource_type' => 'report',
            'resource_id' => 'r1',
        ]);
        $logs = $this->logger->queryLogs([
            'actor_id' => 10,
            'action' => 'user_*',
            'resource_type' => 'user',
        ], self::ADMIN);
        $this->assertCount(2, $logs['logs']);
        $this->assertSame(['user_suspended', 'user_created'], array_column($logs['logs'], 'action'), 'newest first');
        $this->assertSame(2, $logs['total']);
    }

    // AUDIT-04
    public function testPagination(): void
    {
        for ($i = 0; $i < 150; $i++) {
            $this->logger->logMutation([
                'actor_id' => 1,
                'actor_type' => 'user',
                'subject_user_id' => 'none',
                'action' => 'action_' . $i,
                'resource_type' => 'resource',
                'resource_id' => (string)$i,
                'old_value' => null,
                'new_value' => null,
            ]);
        }
        $page1 = $this->logger->queryLogs(['limit' => 100, 'offset' => 0], self::ADMIN);
        $this->assertCount(100, $page1['logs']);
        $this->assertTrue($page1['has_more']);
        $this->assertSame(150, $page1['total']);
        $page2 = $this->logger->queryLogs(['limit' => 100, 'offset' => 100], self::ADMIN);
        $this->assertCount(50, $page2['logs']);
        $this->assertFalse($page2['has_more']);
        $ids = array_merge(array_column($page1['logs'], 'resource_id'), array_column($page2['logs'], 'resource_id'));
        $this->assertSame(array_map('strval', range(149, 0)), $ids, 'the pages cover every entry once, newest first');
    }

    /**
     * AUDIT-05: 1,000,000 entries by 100 actors (10,000 each), seeded straight into the tables in one statement
     * per table; an admin's actor_id + action query returns in under 100 ms (the budget is contract).
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the PHP suite had no performance test.
     */
    // AUDIT-05
    public function testPerformanceOneMillionLogs(): void
    {
        $this->pdo->exec('PRAGMA synchronous = OFF');
        $this->pdo->exec('PRAGMA journal_mode = MEMORY');
        $this->pdo->beginTransaction();
        $this->pdo->exec("WITH RECURSIVE a(n) AS (SELECT 0 UNION ALL SELECT n + 1 FROM a WHERE n < 99)
            INSERT INTO audit_subjects (subject_ref, user_id, created_at) SELECT printf('ref_%03d', n), 'perf_actor_' || n, '2026-01-01' FROM a");
        $this->pdo->exec("WITH RECURSIVE s(n) AS (SELECT 0 UNION ALL SELECT n + 1 FROM s WHERE n < 999999)
            INSERT INTO audit_log (id, timestamp, actor_type, action, resource_type, resource_id, personal_roles, metadata)
            SELECT printf('id_%07d', n), printf('2026-01-01T%02d:%02d:%02d.%06dZ', (n / 3600) % 24, (n / 60) % 60, n % 60, n),
                   'user', CASE WHEN n % 2 = 0 THEN 'perf_action' ELSE 'other_action' END, 'perf_resource', 'res_' || n, 'actor', '{}' FROM s");
        $this->pdo->exec("WITH RECURSIVE s(n) AS (SELECT 0 UNION ALL SELECT n + 1 FROM s WHERE n < 999999)
            INSERT INTO audit_personal (log_id, subject_ref, role, data)
            SELECT printf('id_%07d', n), printf('ref_%03d', n % 100), 'actor',
                   json_object('actor_id', 'perf_actor_' || (n % 100), 'ip', NULL, 'user_agent', NULL, 'request_id', NULL) FROM s");
        $this->pdo->commit();
        $this->assertSame(1000000, (int)$this->pdo->query('SELECT COUNT(*) FROM audit_log')->fetchColumn());

        $start = microtime(true);
        $res = $this->logger->queryLogs(['actor_id' => 'perf_actor_7', 'action' => 'perf_action', 'limit' => 100], self::ADMIN);
        $ms = (microtime(true) - $start) * 1000;
        fwrite(STDERR, '  (audit query over 1M rows: ' . round($ms, 2) . " ms)\n");
        $this->assertSame(0, $res['total'], 'actor 7 only has odd-numbered entries, all other_action');
        $start = microtime(true);
        $res = $this->logger->queryLogs(['actor_id' => 'perf_actor_8', 'action' => 'perf_action', 'resource_type' => 'perf_resource', 'limit' => 100], self::ADMIN);
        $ms2 = (microtime(true) - $start) * 1000;
        fwrite(STDERR, '  (audit query over 1M rows: ' . round($ms2, 2) . " ms)\n");
        $this->assertSame(10000, $res['total']);
        $this->assertCount(100, $res['logs']);
        $this->assertSame('perf_actor_8', $res['logs'][0]['actor_id']);
        $this->assertLessThan(100.0, $ms, "query took {$ms} ms");
        $this->assertLessThan(100.0, $ms2, "query took {$ms2} ms");
    }

    // AUDIT-06
    public function testImmutability(): void
    {
        $log = $this->logger->logMutation([
            'actor_id' => 3,
            'actor_type' => 'user',
            'subject_user_id' => 3,
            'action' => 'test_action',
            'resource_type' => 'test',
            'resource_id' => 't1',
            'old_value' => null,
            'new_value' => null,
        ]);
        foreach ([
            "UPDATE audit_log SET action = 'modified' WHERE id = '{$log['log_id']}'",
            "DELETE FROM audit_log WHERE id = '{$log['log_id']}'",
            "UPDATE audit_personal SET data = '{}' WHERE log_id = '{$log['log_id']}'",
        ] as $sql) {
            try {
                $this->pdo->exec($sql);
                $this->fail("allowed: $sql");
            } catch (PDOException $e) {
                $this->assertStringContainsString('immutable', $e->getMessage());
            }
        }
        $this->assertSame('test_action', $this->pdo->query('SELECT action FROM audit_log')->fetchColumn());
    }

    /**
     * AUDIT-07. Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): adds an action that only matched because
     * '_' was a LIKE wildcard ('userXcreated'); it must not match 'user_*'.
     */
    // AUDIT-07
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
            'subject_user_id' => 4,
            'action' => 'billing_changed',
            'resource_type' => 'subscription',
            'resource_id' => 's1',
            'old_value' => null,
            'new_value' => null,
        ]);
        $this->logger->logMutation(['actor_id' => 4, 'actor_type' => 'user', 'action' => 'userXcreated', 'resource_type' => 'user', 'resource_id' => 'u3']);
        $logs = $this->logger->queryLogs(['action' => 'user_*'], self::ADMIN);
        $this->assertCount(2, $logs['logs']);
        $this->assertSame(['user_suspended', 'user_created'], array_column($logs['logs'], 'action'));
    }

    /** Search finds entries by action (admins only). */
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
        $search = $this->logger->search('created', 'user', 10, self::ADMIN);
        $this->assertCount(1, $search['results']);
        $this->assertEquals('user_created', $search['results'][0]['action']);
        $this->assertCount(0, $this->logger->search('%', 'user', 10, self::ADMIN)['results'], '% in the query is literal');
    }

    /**
     * AUDIT-08: after erase_subject(user) no retained row of the three tables holds the user's id, email or IP;
     * every earlier audit_log row is unchanged and exactly one row is added ('audit_subject_erased', personal_roles
     * '', metadata {erased_rows}); queries show the user's entries with personal_erased true, an actor_id filter
     * for the user finds nothing, and replay reports erased. Distinctive values: id 987654321, email
     * erase.me@example.test, IP 203.0.113.77. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     */
    // AUDIT-08
    public function testEraseSubjectLeavesNothingThatIdentifiesTheUser(): void
    {
        $uid = 987654321;
        $email = 'erase.me@example.test';
        $ip = '203.0.113.77';
        $own = $this->logger->logMutation(['actor_id' => $uid, 'actor_type' => 'user', 'action' => 'user_profile_updated', 'resource_type' => 'user', 'resource_id' => $uid,
            'old_value' => ['email' => 'a@x.test'], 'new_value' => ['email' => $email], 'why_chain_id' => 'wc_1', 'ip' => $ip, 'user_agent' => 'UA', 'request_id' => 'r1']);
        $byAdmin = $this->logger->logMutation(['actor_id' => 5, 'actor_type' => 'user', 'subject_user_id' => $uid, 'action' => 'subscription_changed', 'resource_type' => 'subscription',
            'resource_id' => 'sub_1', 'old_value' => ['tier' => 'solo', 'email' => $email], 'new_value' => ['tier' => 'team'], 'ip' => '198.51.100.5']);
        $viaKey = $this->logger->logMutation(['actor_id' => 'key_1', 'actor_type' => 'api_key', 'actor_user_id' => $uid, 'subject_user_id' => 'none', 'action' => 'deployment_created',
            'resource_type' => 'deployment', 'resource_id' => 'dep_1', 'new_value' => ['region' => 'eu'], 'ip' => $ip]);
        $other = $this->logger->logMutation(['actor_id' => 6, 'actor_type' => 'user', 'action' => 'user_created', 'resource_type' => 'user', 'resource_id' => 6, 'new_value' => ['email' => 'keep@example.test'], 'ip' => '192.0.2.9']);
        $this->assertSame(2, $this->logger->queryLogs(['actor_id' => $uid], self::ADMIN)['total'], 'two entries acted by the user (own, via key)');
        $before = $this->pdo->query('SELECT * FROM audit_log ORDER BY rowid')->fetchAll(PDO::FETCH_ASSOC);
        $text = $this->allRowsText();
        foreach ([(string)$uid, $email, $ip] as $needle) {
            $this->assertStringContainsString($needle, $text, "seeded: $needle");
        }

        $this->assertSame(['erased_rows' => 4], $this->logger->eraseSubject($uid));

        $text = $this->allRowsText();
        foreach ([(string)$uid, $email, $ip] as $needle) {
            $this->assertStringNotContainsString($needle, $text, "erased: $needle");
        }
        $after = $this->pdo->query('SELECT * FROM audit_log ORDER BY rowid')->fetchAll(PDO::FETCH_ASSOC);
        $this->assertSame($before, array_slice($after, 0, count($before)), 'earlier rows unchanged');
        $this->assertCount(count($before) + 1, $after, 'exactly one row added');
        $added = end($after);
        $this->assertSame(['audit_subject_erased', 'service', 'user', null, '', '{"erased_rows":4}'],
            [$added['action'], $added['actor_type'], $added['resource_type'], $added['resource_id'], $added['personal_roles'], $added['metadata']]);

        $this->assertSame(0, $this->logger->queryLogs(['actor_id' => $uid], self::ADMIN)['total'], 'actor filter finds nothing');
        $byId = [];
        foreach ($this->logger->queryLogs([], self::ADMIN)['logs'] as $entry) {
            $byId[$entry['id']] = $entry;
        }
        foreach ([$own['log_id'], $byAdmin['log_id'], $viaKey['log_id']] as $id) {
            $this->assertTrue($byId[$id]['personal_erased'], "$id shows personal_erased");
        }
        $this->assertNull($byId[$own['log_id']]['ip']);
        $this->assertNull($byId[$byAdmin['log_id']]['old_value']);
        $this->assertSame('5', $byId[$byAdmin['log_id']]['actor_id'], "the admin's own actor row is kept");
        $this->assertFalse($byId[$other['log_id']]['personal_erased']);
        $this->assertSame('192.0.2.9', $byId[$other['log_id']]['ip'], "another user's data is kept");
        $this->assertSame(['log_id' => $own['log_id'], 'timestamp' => $before[0]['timestamp'], 'erased' => true, 'resource_state_at_time' => null, 'has_diverged' => null],
            $this->logger->replay($own['log_id'], self::ADMIN));
        $this->assertCount(0, $this->logger->search('erase.me', null, 50, self::ADMIN)['results']);
        $this->assertSame(['erased_rows' => 0], $this->logger->eraseSubject($uid), 'a second erasure finds nothing');
    }

    /**
     * AUDIT-09: apply_retention (30 days here) erases the personal data of older entries and drops subjects
     * left without personal rows; newer entries keep theirs; no audit_log row is removed.
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     */
    // AUDIT-09
    public function testApplyRetention(): void
    {
        $old = $this->logger->logMutation(['actor_id' => 41, 'actor_type' => 'user', 'action' => 'user_login', 'resource_type' => 'user', 'resource_id' => 41, 'ip' => '203.0.113.41']);
        $this->now = $this->now->modify('+40 days');
        $new = $this->logger->logMutation(['actor_id' => 42, 'actor_type' => 'user', 'action' => 'user_login', 'resource_type' => 'user', 'resource_id' => 42, 'ip' => '203.0.113.42']);
        $count = (int)$this->pdo->query('SELECT COUNT(*) FROM audit_log')->fetchColumn();

        $this->assertSame(['erased_rows' => 2], $this->logger->applyRetention($this->now));

        $this->assertSame($count, (int)$this->pdo->query('SELECT COUNT(*) FROM audit_log')->fetchColumn(), 'no audit_log row removed');
        $logs = [];
        foreach ($this->logger->queryLogs([], self::ADMIN)['logs'] as $e) {
            $logs[$e['id']] = $e;
        }
        $this->assertTrue($logs[$old['log_id']]['personal_erased']);
        $this->assertNull($logs[$old['log_id']]['ip']);
        $this->assertFalse($logs[$new['log_id']]['personal_erased']);
        $this->assertSame('203.0.113.42', $logs[$new['log_id']]['ip']);
        $this->assertSame(['42'], $this->pdo->query('SELECT user_id FROM audit_subjects')->fetchAll(PDO::FETCH_COLUMN), 'subject 41 dropped');
        $this->assertSame(['erased_rows' => 0], $this->logger->applyRetention($this->now));
    }

    /**
     * AUDIT-10: logMutation refuses a non-'user' entry without subject_user_id (400 subject_required), a metadata
     * key other than feature_flag / erased_rows (400 metadata_key_not_allowed), an api_key entry without
     * actor_user_id (400 actor_user_required) and a 'user' entry with another subject (400 subject_mismatch);
     * nothing is written; reads by a non-admin caller get 403. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     */
    // AUDIT-10
    public function testRefusals(): void
    {
        $base = ['actor_id' => 1, 'actor_type' => 'user', 'action' => 'subscription_changed', 'resource_type' => 'subscription', 'resource_id' => 's1'];
        $this->assertRefused(fn() => $this->logger->logMutation($base), 400, 'subject_required');
        $this->assertRefused(fn() => $this->logger->logMutation($base + ['subject_user_id' => '']), 400, 'subject_required');
        $this->assertRefused(fn() => $this->logger->logMutation($base + ['subject_user_id' => 'none', 'metadata' => ['ip' => '1.2.3.4']]), 400, 'metadata_key_not_allowed');
        $this->assertRefused(fn() => $this->logger->logMutation(['actor_id' => 'key_9', 'actor_type' => 'api_key'] + $base + ['subject_user_id' => 'none']), 400, 'actor_user_required');
        $this->assertRefused(fn() => $this->logger->logMutation(['actor_id' => 1, 'actor_type' => 'user', 'action' => 'user_updated', 'resource_type' => 'user', 'resource_id' => 7, 'subject_user_id' => 8]), 400, 'subject_mismatch');
        $this->assertRefused(fn() => $this->logger->logMutation(['actor_type' => 'robot'] + $base + ['subject_user_id' => 'none']), 400, 'invalid_actor_type');
        $this->assertSame(0, (int)$this->pdo->query('SELECT COUNT(*) FROM audit_log')->fetchColumn(), 'nothing written');
        $this->assertTrue($this->logger->logMutation($base + ['subject_user_id' => 'none', 'metadata' => ['feature_flag' => 'new_ui']])['success']);

        $logId = (string)$this->pdo->query('SELECT id FROM audit_log')->fetchColumn();
        foreach ([null, [], ['user_id' => 1, 'is_admin' => false], ['user_id' => 1, 'is_admin' => 'true']] as $caller) {
            $this->assertRefused(fn() => $this->logger->queryLogs([], $caller), 403, 'admin_only');
            $this->assertRefused(fn() => $this->logger->replay($logId, $caller), 403, 'admin_only');
            $this->assertRefused(fn() => $this->logger->search('subscription', null, 10, $caller), 403, 'admin_only');
        }
    }
}

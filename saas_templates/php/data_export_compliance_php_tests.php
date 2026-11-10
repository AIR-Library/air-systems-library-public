<?php
/**
 * Data Export & Compliance tests (TIER 2 spec, system 3: eleven required tests).
 *
 * Converted 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP, from a top-level script whose
 * checks the runner could not count (0 tests) and which never loaded the implementation
 * (`Class "Compliance\Database" not found`). Every check of the script is kept, in the test named
 * after the spec line it proves; each test builds its own state instead of relying on the
 * previous block. One check changed meaning: the script expected the account to be deleted the
 * moment deletion was confirmed, which contradicts the spec's 30-day grace period (and the
 * script's own cancel test); the cascade is now checked after the grace period ends.
 *
 * Touches: an in-memory SQLite database, in-memory storage and mail. No network, no files.
 */

declare(strict_types=1);

use Compliance\ComplianceException;
use Compliance\ComplianceService;
use Compliance\Database;
use Compliance\InMemoryMailer;
use Compliance\InMemoryObjectStorage;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/data_export_compliance_php.php';

final class DataExportComplianceTest extends TestCase
{
    private PDO $db;
    private InMemoryMailer $mailer;
    private InMemoryObjectStorage $storage;
    private ComplianceService $service;
    private DateTimeImmutable $now;

    /** Fresh database, fakes and a controllable clock for every test. */
    protected function setUp(): void
    {
        $this->now = new DateTimeImmutable('2026-03-01T12:00:00Z');
        $this->db = Database::create();
        $this->mailer = new InMemoryMailer();
        $this->storage = new InMemoryObjectStorage();
        $this->service = new ComplianceService(
            $this->db,
            $this->mailer,
            $this->storage,
            null,
            fn (): DateTimeImmutable => $this->now
        );
    }

    /** A user with one row in every data category (as the script's seedUser()). */
    private function seedUser(): int
    {
        $db = $this->db;
        $stmt = $db->prepare('INSERT INTO users (email, name, created_at, tier, status) VALUES (:email, :name, :created_at, :tier, :status)');
        $stmt->execute([
            ':email' => 'user@example.com',
            ':name' => 'John Doe',
            ':created_at' => (new DateTimeImmutable())->format(DateTimeImmutable::ATOM),
            ':tier' => 'premium',
            ':status' => 'active',
        ]);
        $userId = (int) $db->lastInsertId();

        $stmt = $db->prepare('INSERT INTO sessions (user_id, ip, device, started_at) VALUES (:uid, :ip, :device, :started_at)');
        $stmt->execute([':uid' => $userId, ':ip' => '127.0.0.1', ':device' => 'Chrome', ':started_at' => (new DateTimeImmutable('-10 days'))->format(DateTimeImmutable::ATOM)]);

        $stmt = $db->prepare('INSERT INTO activities (user_id, type, details, performed_at) VALUES (:uid, :type, :details, :performed_at)');
        $stmt->execute([':uid' => $userId, ':type' => 'login', ':details' => null, ':performed_at' => (new DateTimeImmutable('-9 days'))->format(DateTimeImmutable::ATOM)]);

        $stmt = $db->prepare('INSERT INTO files (user_id, filename, size, uploaded_at) VALUES (:uid, :filename, :size, :uploaded_at)');
        $stmt->execute([':uid' => $userId, ':filename' => 'report.pdf', ':size' => 123456, ':uploaded_at' => (new DateTimeImmutable('-8 days'))->format(DateTimeImmutable::ATOM)]);

        $stmt = $db->prepare('INSERT INTO preferences (user_id, key, value) VALUES (:uid, :key, :value)');
        $stmt->execute([':uid' => $userId, ':key' => 'theme', ':value' => 'dark']);

        $stmt = $db->prepare('INSERT INTO transactions (user_id, amount, currency, type, created_at) VALUES (:uid, :amount, :currency, :type, :created_at)');
        $stmt->execute([':uid' => $userId, ':amount' => 49.99, ':currency' => 'USD', ':type' => 'invoice', ':created_at' => (new DateTimeImmutable('-7 days'))->format(DateTimeImmutable::ATOM)]);

        return $userId;
    }

    /** Rows of $table for $userId (users: by id). */
    private function countFor(string $table, int $userId): int
    {
        $column = $table === 'users' ? 'id' : 'user_id';
        $stmt = $this->db->prepare("SELECT COUNT(*) FROM {$table} WHERE {$column} = :uid");
        $stmt->execute([':uid' => $userId]);
        return (int) $stmt->fetchColumn();
    }

    /** Request deletion and return [deletion_id, token from the emailed link]. */
    private function requestDeletionAndToken(int $userId, string $reason): array
    {
        $resp = $this->service->requestDeletion($userId, $reason);
        $body = $this->mailer->sent[count($this->mailer->sent) - 1]['body'];
        $this->assertSame(1, preg_match('/token=([a-f0-9]{32})/', $body, $m));
        return [$resp['deletion_id'], $m[1]];
    }

    /** Spec: Export: JSON and CSV formats both work (JSON). Script test 1. */
    public function testExportJsonFormat(): void
    {
        $userId = $this->seedUser();
        $response = $this->service->requestExport($userId, 'json');
        $this->assertTrue($response['success']);
        $this->assertSame('pending', $response['status']);

        // The job runs inline, so the export is completed now
        $status = $this->service->getExportStatus($response['export_id']);
        $this->assertSame('completed', $status['status']);
        $this->assertNotEmpty($status['file_url']);
        $this->assertNotEmpty($status['expires_at']);
        $this->assertStringContainsString('.json', $status['file_url']);

        $content = $this->storage->download($status['file_url'], $this->now);
        $this->assertIsString($content);
        $this->assertSame('user@example.com', json_decode($content, true)['profile']['email']);
    }

    /** Spec: Export: JSON and CSV formats both work (CSV). Script test 2. */
    public function testExportCsvFormat(): void
    {
        $userId = $this->seedUser();
        $responseCsv = $this->service->requestExport($userId, 'csv');
        $statusCsv = $this->service->getExportStatus($responseCsv['export_id']);
        $this->assertSame('completed', $statusCsv['status']);
        $this->assertStringContainsString('.csv', $statusCsv['file_url']);
        $this->assertCount(1, $this->mailer->sent);

        $csv = $this->storage->download($statusCsv['file_url'], $this->now);
        $this->assertIsString($csv);
        $this->assertStringContainsString("profile\nid,email,name,created_at,tier,status\n", $csv);
        $this->assertStringContainsString('user@example.com', $csv);

        $this->expectException(ComplianceException::class);
        $this->service->requestExport($userId, 'xml');
    }

    /** Spec: Export: All data categories included (profile, activity, files, etc). */
    public function testExportIncludesAllDataCategories(): void
    {
        $userId = $this->seedUser();
        $status = $this->service->getExportStatus($this->service->requestExport($userId, 'json')['export_id']);
        $data = json_decode((string) $this->storage->download($status['file_url'], $this->now), true);

        foreach (['profile', 'sessions', 'activities', 'files', 'preferences', 'transactions', 'audit_trail'] as $section) {
            $this->assertArrayHasKey($section, $data);
        }
        $this->assertSame('127.0.0.1', $data['sessions'][0]['ip']);
        $this->assertSame('login', $data['activities'][0]['type']);
        $this->assertSame(['filename' => 'report.pdf', 'size' => 123456], array_intersect_key($data['files'][0], ['filename' => 1, 'size' => 1]));
        $this->assertSame('dark', $data['preferences'][0]['value']);
        $this->assertEquals(49.99, $data['transactions'][0]['amount']);
        $this->assertContains('data_export_requested', array_column($data['audit_trail'], 'action'));
    }

    /** Spec: Export: Email sent with download link. Script test 1 (email part). */
    public function testExportEmailSentWithDownloadLink(): void
    {
        $userId = $this->seedUser();
        $status = $this->service->getExportStatus($this->service->requestExport($userId, 'json')['export_id']);

        $this->assertCount(1, $this->mailer->sent);
        $email = $this->mailer->sent[0];
        $this->assertSame($userId, $email['user_id']);
        $this->assertStringContainsString('data export', $email['subject']);
        $this->assertStringContainsString($status['file_url'], $email['body']);
    }

    /** Spec: Export: Signed URL works, expires after 7 days (and is download-only). */
    public function testSignedUrlWorksAndExpiresAfterSevenDays(): void
    {
        $userId = $this->seedUser();
        $status = $this->service->getExportStatus($this->service->requestExport($userId, 'json')['export_id']);
        $url = $status['file_url'];

        $this->assertEquals($this->now->modify('+7 days'), new DateTimeImmutable($status['expires_at']));
        $this->assertNotNull($this->storage->download($url, $this->now));
        $this->assertNotNull($this->storage->download($url, $this->now->modify('+7 days')));
        $this->assertNull($this->storage->download($url, $this->now->modify('+7 days +1 second')));
        $this->assertNull($this->storage->download($url, $this->now, 'PUT'));
        $this->assertNull($this->storage->download(preg_replace('/signature=[0-9a-f]/', 'signature=x', $url), $this->now));
        $this->assertNull($this->storage->download(preg_replace('/expires=\d+/', 'expires=9999999999', $url), $this->now));
    }

    /** Spec: Deletion: User confirmed via email token. Script tests 3 and 4 (confirmation part). */
    public function testDeletionConfirmedViaEmailToken(): void
    {
        $userId = $this->seedUser();
        $delResp = $this->service->requestDeletion($userId, 'gdpr_right_to_be_forgotten');
        $this->assertTrue($delResp['success']);
        $deletionId = $delResp['deletion_id'];
        $this->assertStringContainsString('T', $delResp['will_delete_at']);
        $this->assertCount(1, $this->mailer->sent);
        $confirmEmail = $this->mailer->sent[0];
        $this->assertStringContainsString('Confirm your account deletion', $confirmEmail['subject']);
        preg_match('/token=([a-f0-9]{32})/', $confirmEmail['body'], $matches);
        $this->assertNotEmpty($matches[1]);
        $token = $matches[1];

        // A wrong token is refused and the request stays pending
        try {
            $this->service->confirmDeletion($deletionId, str_repeat('0', 32));
            $this->fail('wrong token accepted');
        } catch (ComplianceException $e) {
            $this->assertSame('invalid_token', $e->errorCode);
        }

        $confirmResp = $this->service->confirmDeletion($deletionId, $token);
        $this->assertTrue($confirmResp['success']);
        $this->assertStringContainsString('T', $confirmResp['deletion_scheduled_for']);

        // The token works once
        $this->expectException(ComplianceException::class);
        $this->service->confirmDeletion($deletionId, $token);
    }

    /** Spec: Deletion: 30-day grace period enforced. */
    public function testDeletionGracePeriodEnforced(): void
    {
        $userId = $this->seedUser();
        [$deletionId, $token] = $this->requestDeletionAndToken($userId, 'user_requested');
        $confirm = $this->service->confirmDeletion($deletionId, $token);
        $this->assertEquals($this->now->modify('+30 days'), new DateTimeImmutable($confirm['deletion_scheduled_for']));

        // Nothing is deleted on confirmation or during the grace period
        $this->assertSame(1, $this->countFor('users', $userId));
        $this->now = $this->now->modify('+30 days -1 second');
        $this->assertSame(0, $this->service->processDueDeletions());
        $this->assertSame(1, $this->countFor('users', $userId));

        // Deleted once the period is over
        $this->now = $this->now->modify('+1 second');
        $this->assertSame(1, $this->service->processDueDeletions());
        $this->assertSame(0, $this->countFor('users', $userId));
    }

    /** Spec: Deletion: User can cancel within grace period. Script test 5. */
    public function testUserCanCancelWithinGracePeriod(): void
    {
        $userId2 = $this->seedUser();
        [$delId2, $token2] = $this->requestDeletionAndToken($userId2, 'user_requested');
        $this->service->confirmDeletion($delId2, $token2);
        $cancelResp = $this->service->cancelDeletion($delId2);
        $this->assertTrue($cancelResp['success']);
        $this->assertSame('cancelled', $cancelResp['status']);

        // User still exists, also after the grace period would have ended
        $this->now = $this->now->modify('+31 days');
        $this->assertSame(0, $this->service->processDueDeletions());
        $this->assertSame(1, $this->countFor('users', $userId2));

        // After the grace period a confirmed deletion can no longer be cancelled
        $userId3 = $this->seedUser();
        [$delId3, $token3] = $this->requestDeletionAndToken($userId3, 'other');
        $this->service->confirmDeletion($delId3, $token3);
        $this->now = $this->now->modify('+30 days');
        try {
            $this->service->cancelDeletion($delId3);
            $this->fail('cancel after the grace period accepted');
        } catch (ComplianceException $e) {
            $this->assertSame('grace_period_elapsed', $e->errorCode);
        }
    }

    /** Spec: Deletion: Cascade delete works (sessions, api_keys, etc deleted). Script test 4. */
    public function testCascadeDeleteRemovesUserData(): void
    {
        $userId = $this->seedUser();
        $other = $this->seedUser();
        $export = $this->service->getExportStatus($this->service->requestExport($userId, 'json')['export_id']);
        [$deletionId, $token] = $this->requestDeletionAndToken($userId, 'gdpr_right_to_be_forgotten');
        $this->service->confirmDeletion($deletionId, $token);
        $this->now = $this->now->modify('+30 days');
        $this->service->processDueDeletions();

        // Verify cascade delete (sessions, files, etc removed)
        $this->assertSame(0, $this->countFor('sessions', $userId));
        $this->assertSame(0, $this->countFor('files', $userId));
        $this->assertSame(0, $this->countFor('users', $userId));
        foreach (['activities', 'preferences', 'transactions', 'export_requests'] as $table) {
            $this->assertSame(0, $this->countFor($table, $userId), $table);
        }
        // The stored export file (personal data) is gone too
        $this->assertNull($this->storage->download($export['file_url'], $this->now->modify('-1 day')));
        // Another user's data is untouched
        $this->assertSame(1, $this->countFor('users', $other));
        $this->assertSame(1, $this->countFor('sessions', $other));
    }

    /** Spec: Deletion: Audit log preserved (not deleted with user). Script test 4 (audit part). */
    public function testAuditLogPreservedAfterDeletion(): void
    {
        $userId = $this->seedUser();
        [$deletionId, $token] = $this->requestDeletionAndToken($userId, 'gdpr_request');
        $this->service->confirmDeletion($deletionId, $token);
        $this->now = $this->now->modify('+30 days');
        $this->service->processDueDeletions();

        $this->assertSame(0, $this->countFor('users', $userId));
        $this->assertGreaterThan(0, $this->countFor('audit_log', $userId));
    }

    /** Spec: Admin: Can see all export/deletion requests (exports). Script test 6. */
    public function testAdminCanListExportRequests(): void
    {
        $a = $this->seedUser();
        $b = $this->seedUser();
        $this->service->requestExport($a, 'json');
        $this->service->requestExport($b, 'csv');

        $adminList = $this->service->listExports(['status' => 'completed']);
        $this->assertGreaterThanOrEqual(2, $adminList['total']);
        $this->assertSame(2, $adminList['total']);
        foreach ($adminList['exports'] as $exp) {
            $this->assertContains($exp['status'], ['completed', 'failed', 'pending']);
            $this->assertArrayNotHasKey('file_url', $exp); // download links are not shown to admins
        }
        $this->assertSame(1, $this->service->listExports(['user_id' => $b])['total']);
    }

    /** Spec: Admin: Can see all export/deletion requests (deletions). Script test 7. */
    public function testAdminCanListDeletionRequests(): void
    {
        $userId = $this->seedUser();
        [$deletionId, $token] = $this->requestDeletionAndToken($userId, 'user_requested');
        $this->service->confirmDeletion($deletionId, $token);
        $this->seedUser();
        $this->now = $this->now->modify('+30 days');
        $this->service->processDueDeletions();

        $adminDelList = $this->service->listDeletions(['status' => 'completed']);
        $this->assertGreaterThanOrEqual(1, $adminDelList['total']);
        foreach ($adminDelList['deletions'] as $del) {
            $this->assertContains($del['status'], ['completed', 'cancelled', 'approved', 'pending']);
            $this->assertArrayNotHasKey('confirmation_token_hash', $del);
        }
    }

    /** Spec: Audit: All requests logged with why_chain support. Script test 8. */
    public function testAllRequestsAuditLoggedWithWhyChain(): void
    {
        $userId = $this->seedUser();
        $this->service->requestExport($userId, 'json', 'why_export_1');
        [$deletionId, $token] = $this->requestDeletionAndToken($userId, 'gdpr_request');
        $this->service->confirmDeletion($deletionId, $token);
        $this->service->cancelDeletion($deletionId);
        [$deletionId2, $token2] = $this->requestDeletionAndToken($userId, 'gdpr_request');
        $this->service->confirmDeletion($deletionId2, $token2);
        $this->now = $this->now->modify('+30 days');
        $this->service->processDueDeletions();

        $auditRows = $this->db->query('SELECT * FROM audit_log')->fetchAll(PDO::FETCH_ASSOC);
        $actions = array_column($auditRows, 'action');
        $this->assertContains('data_export_requested', $actions);
        $this->assertContains('deletion_requested', $actions);
        $this->assertContains('deletion_confirmed', $actions);
        $this->assertTrue(in_array('deletion_completed', $actions, true) || in_array('deletion_cancelled', $actions, true));
        $this->assertContains('deletion_completed', $actions);
        $this->assertContains('deletion_cancelled', $actions);
        $this->assertContains('why_export_1', array_column($auditRows, 'why_chain'));
        // No token or download link ever reaches the audit log
        $this->assertStringNotContainsString($token, json_encode($auditRows));
        $this->assertStringNotContainsString('signature=', json_encode($auditRows));
    }
}

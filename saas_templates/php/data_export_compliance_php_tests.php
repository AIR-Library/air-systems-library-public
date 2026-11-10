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
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP for the amended spec (EXPORT-05/12/13/14): confirm, cancel and export
 * status take the authenticated user; tokens are 64 hex characters; statutory reasons are deleted when
 * confirmed; the cascade ends with the audit eraser (a fake records each call); tests EXPORT-12/13/14 added.
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

/**
 * Fake audit eraser: records each eraseSubject() call with what the database looked like at that moment
 * (users rows of the subject, the last audit_log row), so EXPORT-13 can check the order; can be told to fail.
 * Why: EXPORT-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the test database.
 */
final class RecordingAuditEraser implements Compliance\AuditEraser
{
    /** @var list<array{user_id: int, user_rows: int, last_audit: array|false}> */
    public array $calls = [];
    public bool $fail = false;
    public function __construct(private PDO $db)
    {
    }
    public function eraseSubject(int $userId): void
    {
        $users = $this->db->prepare('SELECT COUNT(*) FROM users WHERE id = ?');
        $users->execute([$userId]);
        $this->calls[] = [
            'user_id' => $userId,
            'user_rows' => (int) $users->fetchColumn(),
            'last_audit' => $this->db->query('SELECT id, user_id, action FROM audit_log ORDER BY id DESC LIMIT 1')->fetch(PDO::FETCH_ASSOC),
        ];
        if ($this->fail) {
            throw new RuntimeException('audit system unavailable');
        }
    }
}

final class DataExportComplianceTest extends TestCase
{
    private RecordingAuditEraser $eraser;
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
        $this->eraser = new RecordingAuditEraser($this->db);
        $this->service = new ComplianceService(
            $this->db,
            $this->mailer,
            $this->storage,
            null,
            fn (): DateTimeImmutable => $this->now,
            'https://app.example.com',
            $this->eraser
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
        $this->assertSame(1, preg_match('/token=([a-f0-9]{64})/', $body, $m));
        return [$resp['deletion_id'], $m[1]];
    }

    /** Spec: Export: JSON and CSV formats both work (JSON). Script test 1. */
    // EXPORT-01
    public function testExportJsonFormat(): void
    {
        $userId = $this->seedUser();
        $response = $this->service->requestExport($userId, 'json');
        $this->assertTrue($response['success']);
        $this->assertSame('pending', $response['status']);

        // The job runs inline, so the export is completed now
        $status = $this->service->getExportStatus($response['export_id'], $userId);
        $this->assertSame('completed', $status['status']);
        $this->assertNotEmpty($status['file_url']);
        $this->assertNotEmpty($status['expires_at']);
        $this->assertStringContainsString('.json', $status['file_url']);

        $content = $this->storage->download($status['file_url'], $this->now);
        $this->assertIsString($content);
        $this->assertSame('user@example.com', json_decode($content, true)['profile']['email']);
    }

    /** Spec: Export: JSON and CSV formats both work (CSV). Script test 2. */
    // EXPORT-01
    public function testExportCsvFormat(): void
    {
        $userId = $this->seedUser();
        $responseCsv = $this->service->requestExport($userId, 'csv');
        $statusCsv = $this->service->getExportStatus($responseCsv['export_id'], $userId);
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
    // EXPORT-02
    public function testExportIncludesAllDataCategories(): void
    {
        $userId = $this->seedUser();
        $status = $this->service->getExportStatus($this->service->requestExport($userId, 'json')['export_id'], $userId);
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
    // EXPORT-03
    public function testExportEmailSentWithDownloadLink(): void
    {
        $userId = $this->seedUser();
        $status = $this->service->getExportStatus($this->service->requestExport($userId, 'json')['export_id'], $userId);

        $this->assertCount(1, $this->mailer->sent);
        $email = $this->mailer->sent[0];
        $this->assertSame($userId, $email['user_id']);
        $this->assertStringContainsString('data export', $email['subject']);
        $this->assertStringContainsString($status['file_url'], $email['body']);
    }

    /** Spec: Export: Signed URL works, expires after 7 days (and is download-only). */
    // EXPORT-04
    public function testSignedUrlWorksAndExpiresAfterSevenDays(): void
    {
        $userId = $this->seedUser();
        $status = $this->service->getExportStatus($this->service->requestExport($userId, 'json')['export_id'], $userId);
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
    // EXPORT-09
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
        preg_match('/token=([a-f0-9]{64})/', $confirmEmail['body'], $matches);
        $this->assertNotEmpty($matches[1]);
        $token = $matches[1];

        // A wrong token is refused and the request stays pending
        try {
            $this->service->confirmDeletion($userId, $deletionId, str_repeat('0', 64));
            $this->fail('wrong token accepted');
        } catch (ComplianceException $e) {
            $this->assertSame('invalid_token', $e->errorCode);
        }

        $confirmResp = $this->service->confirmDeletion($userId, $deletionId, $token);
        $this->assertTrue($confirmResp['success']);
        $this->assertStringContainsString('T', $confirmResp['deletion_scheduled_for']);

        // The token works once
        $this->expectException(ComplianceException::class);
        $this->service->confirmDeletion($userId, $deletionId, $token);
    }

    /** Spec: Deletion: 30-day grace period enforced. */
    // EXPORT-05
    public function testDeletionGracePeriodEnforced(): void
    {
        $userId = $this->seedUser();
        $requestedAt = $this->now;
        $request = $this->service->requestDeletion($userId, 'user_requested');
        $this->assertEquals($requestedAt->modify('+30 days'), new DateTimeImmutable($request['will_delete_at']), 'will_delete_at = requested_at + 30 days');
        $body = $this->mailer->sent[count($this->mailer->sent) - 1]['body'];
        preg_match('/token=([a-f0-9]{64})/', $body, $m);
        [$deletionId, $token] = [$request['deletion_id'], $m[1]];
        // Confirmed 3 hours later: still requested_at + 30 days (amended EXPORT-05, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
        $this->now = $this->now->modify('+3 hours');
        $confirm = $this->service->confirmDeletion($userId, $deletionId, $token);
        $this->assertEquals($requestedAt->modify('+30 days'), new DateTimeImmutable($confirm['deletion_scheduled_for']));
        $this->assertSame('approved', $confirm['status']);
        $this->now = $requestedAt;

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
    // EXPORT-06
    public function testUserCanCancelWithinGracePeriod(): void
    {
        $userId2 = $this->seedUser();
        [$delId2, $token2] = $this->requestDeletionAndToken($userId2, 'user_requested');
        $this->service->confirmDeletion($userId2, $delId2, $token2);
        $cancelResp = $this->service->cancelDeletion($userId2, $delId2);
        $this->assertTrue($cancelResp['success']);
        $this->assertSame('cancelled', $cancelResp['status']);

        // User still exists, also after the grace period would have ended
        $this->now = $this->now->modify('+31 days');
        $this->assertSame(0, $this->service->processDueDeletions());
        $this->assertSame(1, $this->countFor('users', $userId2));

        // After the grace period a confirmed deletion can no longer be cancelled
        $userId3 = $this->seedUser();
        [$delId3, $token3] = $this->requestDeletionAndToken($userId3, 'other');
        $this->service->confirmDeletion($userId3, $delId3, $token3);
        $this->now = $this->now->modify('+30 days');
        try {
            $this->service->cancelDeletion($userId3, $delId3);
            $this->fail('cancel after the grace period accepted');
        } catch (ComplianceException $e) {
            $this->assertSame('grace_period_elapsed', $e->errorCode);
        }
    }

    /** Spec: Deletion: Cascade delete works (sessions, api_keys, etc deleted). Script test 4. */
    // EXPORT-07
    public function testCascadeDeleteRemovesUserData(): void
    {
        $userId = $this->seedUser();
        $other = $this->seedUser();
        $export = $this->service->getExportStatus($this->service->requestExport($userId, 'json')['export_id'], $userId);
        [$deletionId, $token] = $this->requestDeletionAndToken($userId, 'gdpr_right_to_be_forgotten');
        $this->service->confirmDeletion($userId, $deletionId, $token);
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
    // EXPORT-08
    public function testAuditLogPreservedAfterDeletion(): void
    {
        $userId = $this->seedUser();
        [$deletionId, $token] = $this->requestDeletionAndToken($userId, 'gdpr_request');
        $this->service->confirmDeletion($userId, $deletionId, $token);
        $this->now = $this->now->modify('+30 days');
        $this->service->processDueDeletions();

        $this->assertSame(0, $this->countFor('users', $userId));
        $this->assertGreaterThan(0, $this->countFor('audit_log', $userId));
    }

    /** Spec: Admin: Can see all export/deletion requests (exports). Script test 6. */
    // EXPORT-10
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
    // EXPORT-10
    public function testAdminCanListDeletionRequests(): void
    {
        $userId = $this->seedUser();
        [$deletionId, $token] = $this->requestDeletionAndToken($userId, 'user_requested');
        $this->service->confirmDeletion($userId, $deletionId, $token);
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
    // EXPORT-11
    public function testAllRequestsAuditLoggedWithWhyChain(): void
    {
        $userId = $this->seedUser();
        $this->service->requestExport($userId, 'json', 'why_export_1');
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the cancelled request is user_requested (a confirmed gdpr_request is
        // now deleted at once, so it could not be cancelled), and the cascade's entry is user_deleted_cascade.
        [$deletionId, $token] = $this->requestDeletionAndToken($userId, 'user_requested');
        $this->service->confirmDeletion($userId, $deletionId, $token);
        $this->service->cancelDeletion($userId, $deletionId);
        [$deletionId2, $token2] = $this->requestDeletionAndToken($userId, 'gdpr_request');
        $this->service->confirmDeletion($userId, $deletionId2, $token2);
        $this->now = $this->now->modify('+30 days');
        $this->service->processDueDeletions();

        $auditRows = $this->db->query('SELECT * FROM audit_log')->fetchAll(PDO::FETCH_ASSOC);
        $actions = array_column($auditRows, 'action');
        $this->assertContains('data_export_requested', $actions);
        $this->assertContains('deletion_requested', $actions);
        $this->assertContains('deletion_confirmed', $actions);
        $this->assertContains('user_deleted_cascade', $actions);
        $this->assertContains('deletion_cancelled', $actions);
        $this->assertContains('why_export_1', array_column($auditRows, 'why_chain'));
        // No token or download link ever reaches the audit log
        $this->assertStringNotContainsString($token, json_encode($auditRows));
        $this->assertStringNotContainsString('signature=', json_encode($auditRows));
    }

    /**
     * EXPORT-12: a statutory request (gdpr_request, gdpr_right_to_be_forgotten) is not held for 30 days:
     * will_delete_at = requested_at, and confirm() runs the cascade before it returns (status 'completed',
     * deleted_at = deletion_scheduled_for = now). Why: amended spec. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: in-memory SQLite, fakes.
     */
    // EXPORT-12
    public function testStatutoryDeletionIsNotHeld(): void
    {
        foreach (['gdpr_request', 'gdpr_right_to_be_forgotten'] as $reason) {
            $userId = $this->seedUser();
            $requestedAt = $this->now;
            $request = $this->service->requestDeletion($userId, $reason);
            $this->assertEquals($requestedAt, new DateTimeImmutable($request['will_delete_at']), "$reason: will_delete_at = requested_at");
            preg_match('/token=([a-f0-9]{64})/', $this->mailer->sent[count($this->mailer->sent) - 1]['body'], $m);
            $this->now = $this->now->modify('+2 hours');
            $confirm = $this->service->confirmDeletion($userId, $request['deletion_id'], $m[1]);
            $this->assertSame('completed', $confirm['status']);
            $this->assertEquals($this->now, new DateTimeImmutable($confirm['deletion_scheduled_for']));
            $this->assertSame(0, $this->countFor('users', $userId), "$reason: deleted before confirm() returned");
            $row = $this->db->query("SELECT status, deleted_at, scheduled_at FROM deletion_requests WHERE id = '{$request['deletion_id']}'")->fetch(PDO::FETCH_ASSOC);
            $this->assertSame('completed', $row['status']);
            $this->assertSame($row['scheduled_at'], $row['deleted_at']);
            $this->assertEquals($this->now, new DateTimeImmutable($row['deleted_at']));
        }
        $this->assertSame(0, $this->service->processDueDeletions());
    }

    /**
     * EXPORT-13: cascade order. When the eraser is called the user's rows are already gone and the last audit
     * entry is 'user_deleted_cascade' for that user; nothing is logged after it; deletion_requests.user_id is
     * NULL (on every request row of the user). Without an eraser, or when it fails, nothing is deleted.
     * Why: amended spec (independent security review). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
     */
    // EXPORT-13
    public function testCascadeOrderEndsWithAuditEraser(): void
    {
        $userId = $this->seedUser();
        [$cancelled, $t0] = $this->requestDeletionAndToken($userId, 'user_requested');
        $this->service->cancelDeletion($userId, $cancelled);
        [$deletionId, $token] = $this->requestDeletionAndToken($userId, 'user_requested');
        $this->service->confirmDeletion($userId, $deletionId, $token);
        $this->now = $this->now->modify('+30 days');
        $lastBefore = (int) $this->db->query('SELECT MAX(id) FROM audit_log')->fetchColumn();
        $this->assertSame(1, $this->service->processDueDeletions());

        $this->assertCount(1, $this->eraser->calls);
        $call = $this->eraser->calls[0];
        $this->assertSame($userId, $call['user_id']);
        $this->assertSame(0, $call['user_rows'], 'user rows deleted before the eraser runs');
        $this->assertSame(['user_id' => $userId, 'action' => 'user_deleted_cascade'], ['user_id' => (int) $call['last_audit']['user_id'], 'action' => $call['last_audit']['action']]);
        $this->assertGreaterThan($lastBefore, (int) $call['last_audit']['id']);
        $this->assertSame((int) $call['last_audit']['id'], (int) $this->db->query('SELECT MAX(id) FROM audit_log')->fetchColumn(), 'nothing logged after the eraser');
        $this->assertSame(0, (int) $this->db->query("SELECT COUNT(*) FROM deletion_requests WHERE user_id = $userId")->fetchColumn(), 'deletion_requests.user_id is NULL');
        $this->assertNull($this->db->query("SELECT user_id FROM deletion_requests WHERE id = '$deletionId'")->fetchColumn());
        $this->assertSame('completed', $this->db->query("SELECT status FROM deletion_requests WHERE id = '$deletionId'")->fetchColumn());

        // A failing eraser rolls the whole cascade back.
        $other = $this->seedUser();
        [$d2, $t2] = $this->requestDeletionAndToken($other, 'gdpr_request');
        $this->eraser->fail = true;
        try {
            $this->service->confirmDeletion($other, $d2, $t2);
            $this->fail('cascade with a failing eraser completed');
        } catch (RuntimeException $e) {
            $this->assertSame('audit system unavailable', $e->getMessage());
        }
        $this->assertSame(1, $this->countFor('users', $other));
        $this->assertSame(1, $this->countFor('sessions', $other));
        $this->assertSame((string) $other, (string) $this->db->query("SELECT user_id FROM deletion_requests WHERE id = '$d2'")->fetchColumn());
        $this->assertSame(0, (int) $this->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'user_deleted_cascade' AND user_id = $other")->fetchColumn());

        // No eraser configured: fails closed.
        $bare = new ComplianceService($this->db, $this->mailer, $this->storage, null, fn (): DateTimeImmutable => $this->now);
        $third = $this->seedUser();
        $req = $bare->requestDeletion($third, 'gdpr_request');
        preg_match('/token=([a-f0-9]{64})/', $this->mailer->sent[count($this->mailer->sent) - 1]['body'], $m);
        try {
            $bare->confirmDeletion($third, $req['deletion_id'], $m[1]);
            $this->fail('deletion completed without an audit eraser');
        } catch (ComplianceException $e) {
            $this->assertSame('audit_eraser_not_configured', $e->errorCode);
        }
        $this->assertSame(1, $this->countFor('users', $third));
    }

    /**
     * EXPORT-14: nothing is deleted before confirm (even past 30 days); a wrong, reused or expired (over 24h)
     * token is refused; another user's request is not_found for confirm and cancel (and another user's export
     * for status). Why: amended spec. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
     */
    // EXPORT-14
    public function testConfirmationTokenRulesAndOwnership(): void
    {
        $userId = $this->seedUser();
        $intruder = $this->seedUser();
        [$deletionId, $token] = $this->requestDeletionAndToken($userId, 'user_requested');
        $this->assertSame(64, strlen($token));
        $this->assertSame(hash('sha256', $token), $this->db->query("SELECT confirmation_token_hash FROM deletion_requests WHERE id = '$deletionId'")->fetchColumn());
        $this->assertStringNotContainsString($token, json_encode($this->db->query('SELECT * FROM deletion_requests')->fetchAll(PDO::FETCH_ASSOC)));

        $this->now = $this->now->modify('+40 days');
        $this->assertSame(0, $this->service->processDueDeletions(), 'nothing deleted before confirm');
        $this->assertSame(1, $this->countFor('users', $userId));
        $this->now = $this->now->modify('-40 days');

        $refused = function (callable $call, string $code): void {
            try {
                $call();
                $this->fail("expected $code");
            } catch (ComplianceException $e) {
                $this->assertSame($code, $e->errorCode);
            }
        };
        $refused(fn () => $this->service->confirmDeletion($intruder, $deletionId, $token), 'not_found');
        $refused(fn () => $this->service->cancelDeletion($intruder, $deletionId), 'not_found');
        $refused(fn () => $this->service->confirmDeletion($userId, $deletionId, strrev($token)), 'invalid_token');
        $refused(fn () => $this->service->confirmDeletion($userId, $deletionId, ''), 'invalid_token');
        $this->assertSame('pending', $this->db->query("SELECT status FROM deletion_requests WHERE id = '$deletionId'")->fetchColumn());

        // Expired: just over 24 hours after the request.
        [$late, $lateToken] = $this->requestDeletionAndToken($userId, 'user_requested');
        $this->now = $this->now->modify('+24 hours');
        $refused(fn () => $this->service->confirmDeletion($userId, $late, $lateToken), 'token_expired');
        $this->now = $this->now->modify('-24 hours');

        // The right token works once; a reuse is refused.
        $this->service->confirmDeletion($userId, $deletionId, $token);
        $refused(fn () => $this->service->confirmDeletion($userId, $deletionId, $token), 'not_pending');

        // Another user's export status is not found either.
        $export = $this->service->requestExport($userId, 'json');
        $refused(fn () => $this->service->getExportStatus($export['export_id'], $intruder), 'not_found');
    }
}

<?php
// Tests updated with the fix 2026-11-03: a test mode captures e-mail and SMS instead of sending them, so the tests need neither
//   runkit nor a mail server.
// Why: the suite failed on CI (it was listed in ci/baseline.json). Reviewed by Claude; fixed by a free model from a continuity handoff, session c6ee9a72 (2026-11-03).
// Touches: the database, mail() and the SMS API (not in test mode).
declare(strict_types=1);

require_once __DIR__ . '/notifications_php.php';

use PHPUnit\Framework\TestCase;
use NotificationSystem\NotificationService;
use function NotificationSystem\seedTemplates;
use function NotificationSystem\runMigrations;

final class NotificationServiceTest extends TestCase
{
    private PDO $pdo;
    private NotificationService $service;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->service = new NotificationService($this->pdo, [], []);
        $this->service->enableTestMode();
        seedTemplates($this->pdo);
    }

    public function testSendEmailWithTemplateVariables(): void
    {
        $payload = [
            'user_id' => 1,
            'template_key' => 'trial_ending_soon',
            'channel' => 'email',
            'vars' => ['days_left' => 3],
            'scheduled_at' => null
        ];
        $result = $this->service->endpointSend($payload);
        $this->assertTrue($result['success']);
        $this->assertEquals('sent', $result['status']);
        $this->assertNotNull($result['message_id']);

        $emailData = $this->service->getLastEmailData();
        $this->assertStringContainsString('3', $emailData['message']);
        $this->assertStringContainsString('Trial ending soon', $emailData['subject']);
    }

    public function testSendSms(): void
    {
        $payload = [
            'user_id' => 2,
            'template_key' => 'welcome_email',
            'channel' => 'sms',
            'vars' => ['app_name' => 'TestApp'],
            'scheduled_at' => null
        ];
        $result = $this->service->endpointSend($payload);
        $this->assertTrue($result['success']);
        $this->assertEquals('sent', $result['status']);

        $smsData = $this->service->getLastSmsData();
        $this->assertStringContainsString('TestApp', $smsData['body']);
    }

    public function testSendInAppStoresInDb(): void
    {
        $payload = [
            'user_id' => 3,
            'template_key' => 'admin_alert',
            'channel' => 'in_app',
            'vars' => ['actor' => 'Alice', 'action' => 'delete', 'resource' => 'file.txt'],
            'scheduled_at' => null
        ];
        $result = $this->service->endpointSend($payload);
        $this->assertTrue($result['success']);
        $this->assertEquals('sent', $result['status']);

        $stmt = $this->pdo->prepare('SELECT * FROM notification_logs WHERE id = :id');
        $stmt->execute([':id' => $result['message_id']]);
        $log = $stmt->fetch(PDO::FETCH_ASSOC);
        $this->assertEquals('sent', $log['status']);
        $this->assertEquals('in_app', $log['channel']);
    }

    public function testBatchSendLargeNumber(): void
    {
        $batch = [];
        for ($i = 1; $i <= 50; $i++) {
            $batch[] = [
                'user_id' => $i,
                'template_key' => 'welcome_email',
                'channel' => 'email',
                'vars' => ['app_name' => 'App' . $i],
                'scheduled_at' => null
            ];
        }
        $result = $this->service->endpointSendBatch($batch);
        $this->assertTrue($result['success']);
        $this->assertEquals(50, $result['sent']);
        $this->assertEquals(0, $result['failed']);
        $this->assertCount(50, $result['message_ids']);
    }

    public function testQuietHoursSkipAndQueue(): void
    {
        $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $start = $now->modify('-1 hour')->format('H:i');
        $end = $now->modify('+2 hours')->format('H:i');

        $prefStmt = $this->pdo->prepare('INSERT INTO user_notification_preferences (user_id, do_not_disturb, quiet_hours_start, quiet_hours_end, channels_enabled) VALUES (100, 0, :start, :end, :ch)');
        $prefStmt->execute([
            ':start' => $start,
            ':end'   => $end,
            ':ch'    => json_encode(['email'=>true,'sms'=>true,'in_app'=>true])
        ]);

        $payload = [
            'user_id' => 100,
            'template_key' => 'welcome_email',
            'channel' => 'email',
            'vars' => ['app_name' => 'QuietApp'],
            'scheduled_at' => null
        ];
        $result = $this->service->endpointSend($payload);
        $this->assertEquals('queued', $result['status']);
        $this->assertNotNull($result['message_id']);

        // Verify scheduled_at stored
        $stmt = $this->pdo->prepare('SELECT sent_at FROM notification_logs WHERE id = :id');
        $stmt->execute([':id' => $result['message_id']]);
        $sentAt = $stmt->fetchColumn();
        $this->assertNotNull($sentAt);
    }

    public function testDoNotDisturbSkips(): void
    {
        $prefStmt = $this->pdo->prepare('INSERT INTO user_notification_preferences (user_id, do_not_disturb, channels_enabled) VALUES (200, 1, :ch)');
        $prefStmt->execute([':ch' => json_encode(['email'=>true,'sms'=>true,'in_app'=>true])]);

        $payload = [
            'user_id' => 200,
            'template_key' => 'welcome_email',
            'channel' => 'email',
            'vars' => ['app_name' => 'DNDApp'],
            'scheduled_at' => null
        ];
        $result = $this->service->endpointSend($payload);
        $this->assertEquals('skipped', $result['status']);
        $this->assertNull($result['message_id']);
    }

    public function testTrackMessageStatusUpdates(): void
    {
        $payload = [
            'user_id' => 5,
            'template_key' => 'welcome_email',
            'channel' => 'email',
            'vars' => ['app_name' => 'TrackApp'],
            'scheduled_at' => null
        ];
        $sendRes = $this->service->endpointSend($payload);
        $msgId = $sendRes['message_id'];
        $track = $this->service->endpointTrack((string)$msgId);
        $this->assertEquals('sent', $track['status']);
        $this->assertNotNull($track['sent_at']);
        $this->assertEquals(5, $track['user_id']);
        $this->assertEquals('welcome_email', $track['template_key']);
    }

    public function testRetryOnFailure(): void
    {
        $service = new class($this->pdo) extends NotificationService {
            private int $attempt = 0;
            protected function sendEmail(int $userId, string $subject, string $textBody, string $htmlBody): void
            {
                $this->attempt++;
                if ($this->attempt < 3) {
                    throw new Exception('SMTP error');
                }
                // Third attempt succeeds - store data but don't throw
                $this->lastEmailData = [
                    'to' => "user{$userId}@example.com",
                    'subject' => $subject,
                    'message' => $htmlBody,
                    'headers' => 'test'
                ];
            }
        };
        $service->enableTestMode();
        seedTemplates($this->pdo);

        $payload = [
            'user_id' => 6,
            'template_key' => 'welcome_email',
            'channel' => 'email',
            'vars' => ['app_name' => 'RetryApp'],
            'scheduled_at' => null
        ];
        $result = $service->endpointSend($payload);
        $this->assertTrue($result['success']);
        $this->assertEquals('sent', $result['status']);
    }

    public function testUnsubscribeLinkIncludedInEmail(): void
    {
        $payload = [
            'user_id' => 7,
            'template_key' => 'welcome_email',
            'channel' => 'email',
            'vars' => ['app_name' => 'UnsubApp'],
            'scheduled_at' => null
        ];
        $result = $this->service->endpointSend($payload);
        $this->assertTrue($result['success']);

        $emailData = $this->service->getLastEmailData();
        $this->assertStringContainsString('unsubscribe', strtolower($emailData['message']));
        $this->assertStringContainsString('example.com/unsubscribe', $emailData['message']);
        $this->assertStringContainsString('uid=7', $emailData['message']);
    }

    public function testUserPreferencesHonored(): void
    {
        // Disable SMS for user
        $prefStmt = $this->pdo->prepare('INSERT INTO user_notification_preferences (user_id, do_not_disturb, channels_enabled) VALUES (300, 0, :ch)');
        $prefStmt->execute([':ch' => json_encode(['email'=>true,'sms'=>false,'in_app'=>true])]);

        $payload = [
            'user_id' => 300,
            'template_key' => 'welcome_email',
            'channel' => 'sms',
            'vars' => ['app_name' => 'PrefApp'],
            'scheduled_at' => null
        ];
        $result = $this->service->endpointSend($payload);
        $this->assertEquals('skipped', $result['status']);
        $this->assertNull($result['message_id']);
    }
}
?>

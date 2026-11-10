<?php
// Tests updated with the fix 2026-11-03: a test mode captures e-mail and SMS instead of sending them, so the tests need neither
//   runkit nor a mail server.
// Why: the suite failed on CI (it was listed in ci/baseline.json). Reviewed by Claude; fixed by a free model from a continuity handoff, session c6ee9a72 (2026-11-03).
// Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): a fixed clock, an unsubscribe secret and a no-op retry
//   sleep are injected; tests follow the amended NOTIF-02/05/11/12 and NOTIF-07/09 now prove their rows (see the
//   comments on each changed test).
// Changed again 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP, Phase B.2): NOTIF-08 counts retries after the first
//   attempt (4 attempts, 1 s / 2 s / 4 s; the test expected 3 attempts); deliverDue reports `deferred`, so the
//   NOTIF-12 result arrays carry deferred => 0; NOTIF-05 and NOTIF-07 gained the quiet-hours re-queue in
//   deliverDue and the open endpoint.
// Touches: an in-memory SQLite database; no mail() or SMS API (test mode).
declare(strict_types=1);

require_once __DIR__ . '/notifications_php.php';

use PHPUnit\Framework\TestCase;
use NotificationSystem\NotificationService;
use function NotificationSystem\seedTemplates;
use function NotificationSystem\runMigrations;

final class NotificationServiceTest extends TestCase
{
    private const SECRET = 'test-unsubscribe-secret-0123456789abcdef';
    private PDO $pdo;
    private NotificationService $service;
    private DateTimeImmutable $now;
    /** @var list<int> backoff sleeps requested by the service, in microseconds */
    private array $sleeps = [];

    /** A service on the shared test database with the fixed clock, the test secret and a recording sleep. */
    private function makeService(): NotificationService
    {
        $service = new NotificationService(
            $this->pdo,
            [],
            [],
            self::SECRET,
            fn(): DateTimeImmutable => $this->now,
            'https://example.com',
            function (int $us): void { $this->sleeps[] = $us; }
        );
        $service->enableTestMode();
        return $service;
    }

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->now = new DateTimeImmutable('2026-11-10 12:00:00', new DateTimeZone('UTC'));
        $this->sleeps = [];
        $this->service = $this->makeService();
        seedTemplates($this->pdo);
    }

    private function logRow(string|int $id): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM notification_logs WHERE id = :id');
        $stmt->execute([':id' => $id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    // NOTIF-01
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
        $this->assertStringContainsString('Your trial ends in 3 days.', $emailData['message']);
        $this->assertStringNotContainsString('{days_left}', $emailData['message']);
        $this->assertStringContainsString('Trial ending soon', $emailData['subject']);
    }

    /**
     * NOTIF-02: SMS. Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): SMS is off by default (amended
     * spec), so the user turns it on first; with the default preferences the SMS is skipped.
     */
    // NOTIF-02
    public function testSendSms(): void
    {
        $payload = [
            'user_id' => 2,
            'template_key' => 'welcome_email',
            'channel' => 'sms',
            'vars' => ['app_name' => 'TestApp'],
            'scheduled_at' => null
        ];
        $this->assertSame(['email' => true, 'sms' => false, 'in_app' => true], $this->service->getUserPreferences(2)['channels_enabled']);
        $this->assertNull($this->service->getUserPreferences(2)['quiet_hours_start']);
        $this->assertFalse($this->service->getUserPreferences(2)['do_not_disturb']);
        $this->assertEquals('skipped', $this->service->endpointSend($payload)['status'], 'SMS is opt-in');
        $this->assertSame([], $this->service->getLastSmsData());

        $this->assertTrue($this->service->endpointUpdatePreferences(2, 2, ['channels_enabled' => ['sms' => true]])['success']);
        $result = $this->service->endpointSend($payload);
        $this->assertTrue($result['success']);
        $this->assertEquals('sent', $result['status']);

        $smsData = $this->service->getLastSmsData();
        $this->assertStringContainsString('TestApp', $smsData['body']);
    }

    // NOTIF-03
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

        $log = $this->logRow($result['message_id']);
        $this->assertEquals('sent', $log['status']);
        $this->assertEquals('in_app', $log['channel']);
        $this->assertSame(['actor' => 'Alice', 'action' => 'delete', 'resource' => 'file.txt'], json_decode($log['vars_used'], true));
    }

    /**
     * NOTIF-04: batch of 1000+. Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): it sent 50; the row
     * says 1000+.
     */
    // NOTIF-04
    public function testBatchSendLargeNumber(): void
    {
        $batch = [];
        for ($i = 1; $i <= 1000; $i++) {
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
        $this->assertEquals(1000, $result['sent']);
        $this->assertEquals(0, $result['failed']);
        $this->assertCount(1000, $result['message_ids']);
        $this->assertSame(1000, (int)$this->pdo->query("SELECT COUNT(*) FROM notification_logs WHERE status = 'sent'")->fetchColumn());
    }

    /**
     * NOTIF-05: in quiet hours the message is not sent now; it is queued with scheduled_at = quiet_hours_end
     * and deliverDue sends it then. Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): a fixed clock (the
     * window was built from the wall clock), and scheduled_at instead of sent_at (amended spec).
     */
    // NOTIF-05
    public function testQuietHoursSkipAndQueue(): void
    {
        $prefStmt = $this->pdo->prepare('INSERT INTO user_notification_preferences (user_id, do_not_disturb, quiet_hours_start, quiet_hours_end, channels_enabled) VALUES (100, 0, :start, :end, :ch)');
        $prefStmt->execute([
            ':start' => '11:00',
            ':end'   => '14:00',
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
        $this->assertSame([], $this->service->getLastEmailData(), 'nothing sent in quiet hours');

        $log = $this->logRow($result['message_id']);
        $this->assertSame('2026-11-10 14:00:00', $log['scheduled_at']);
        $this->assertNull($log['sent_at']);

        $this->assertSame(0, $this->service->deliverDue(new DateTimeImmutable('2026-11-10 13:59:59', new DateTimeZone('UTC')))['sent']);
        $this->assertSame(1, $this->service->deliverDue(new DateTimeImmutable('2026-11-10 14:00:00', new DateTimeZone('UTC')))['sent']);
        $this->assertSame('sent', $this->logRow($result['message_id'])['status']);

        // Quiet hours that wrap midnight queue until the next morning.
        $this->service->updateUserPreferences(100, ['quiet_hours_start' => '22:00', 'quiet_hours_end' => '07:00']);
        $this->now = new DateTimeImmutable('2026-11-10 23:30:00', new DateTimeZone('UTC'));
        $late = $this->service->endpointSend($payload);
        $this->assertSame('2026-11-11 07:00:00', $this->logRow($late['message_id'])['scheduled_at']);
        // Outside quiet hours it is sent at once.
        $this->now = new DateTimeImmutable('2026-11-10 08:00:00', new DateTimeZone('UTC'));
        $this->assertSame('sent', $this->service->endpointSend($payload)['status']);
    }

    /**
     * NOTIF-05, deliver_due step 3 (Phase B.2): a scheduled message that falls due inside the user's quiet hours
     * (22:00-07:00 UTC, across midnight) is not sent; deliverDue puts it back to 'queued' with scheduled_at =
     * quiet_hours_end and sends it then. Quiet hours must be "HH:MM" (else 400 invalid_quiet_hours, nothing changed).
     * Input: the fixed clock. Output: assertions only. Why: the amended spec. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory SQLite database; e-mail is captured (test mode).
     */
    // NOTIF-05
    public function testDeliverDueRequeuesInsideQuietHours(): void
    {
        $utc = new DateTimeZone('UTC');
        $msg = $this->service->endpointSend(['user_id' => 300, 'template_key' => 'welcome_email', 'channel' => 'email', 'vars' => ['app_name' => 'Night'], 'scheduled_at' => '2026-11-10T23:30:00Z']);
        $this->assertSame('queued', $msg['status']);
        $this->assertTrue($this->service->updateUserPreferences(300, ['quiet_hours_start' => '22:00', 'quiet_hours_end' => '07:00'])['success']);

        $this->assertSame(['requeued' => 0, 'sent' => 0, 'skipped' => 0, 'failed' => 0, 'deferred' => 1], $this->service->deliverDue(new DateTimeImmutable('2026-11-10 23:30:00', $utc)));
        $row = $this->logRow($msg['message_id']);
        $this->assertSame(['queued', '2026-11-11 07:00:00', null, null], [$row['status'], $row['scheduled_at'], $row['claimed_at'], $row['sent_at']]);
        $this->assertSame([], $this->service->getLastEmailData(), 'nothing sent inside quiet hours');
        $this->assertSame(0, $this->service->deliverDue(new DateTimeImmutable('2026-11-11 06:59:59', $utc))['sent']);
        $this->assertSame(['requeued' => 0, 'sent' => 1, 'skipped' => 0, 'failed' => 0, 'deferred' => 0], $this->service->deliverDue(new DateTimeImmutable('2026-11-11 07:00:00', $utc)));
        $this->assertSame('sent', $this->logRow($msg['message_id'])['status']);

        foreach (['7:00', '24:00', '07:60', '07:00:00', 'soon', ''] as $bad) {
            $this->assertSame(['success' => false, 'error' => 'invalid_quiet_hours', 'status' => 400], $this->service->updateUserPreferences(300, ['quiet_hours_end' => $bad]), $bad);
        }
        $this->assertSame('07:00', $this->service->getUserPreferences(300)['quiet_hours_end'], 'unchanged');
        $this->assertTrue($this->service->updateUserPreferences(300, ['quiet_hours_start' => null, 'quiet_hours_end' => null])['success'], 'null clears');
    }

    // NOTIF-06
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
        $this->assertSame([], $this->service->getLastEmailData());
        $this->assertSame('do_not_disturb', $this->pdo->query("SELECT error FROM notification_logs WHERE user_id = 200")->fetchColumn());
    }

    /**
     * NOTIF-07: a click on a link in a sent message marks it opened. Changed 2026-11-10
     * (session_012zDydZCZ4AChqhEZ4oVtaP): the test only read back 'sent'; recordClick() is new.
     */
    // NOTIF-07
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
        $this->assertNull($track['opened_at']);

        $this->now = $this->now->modify('+10 minutes');
        $clicked = $this->service->recordClick((string)$msgId);
        $this->assertSame('opened', $clicked['status']);
        $this->assertSame('2026-11-10 12:10:00', $clicked['opened_at']);
        $this->assertSame('2026-11-10 12:10:00', $clicked['clicked_at']);
        $this->assertSame('opened', $this->service->endpointTrack((string)$msgId)['status']);
        $this->assertArrayHasKey('error', $this->service->recordClick('999999'));
    }

    /**
     * NOTIF-07 as amended (Phase B.2): GET /notifications/open/:message_id sets opened_at and status 'opened' the
     * first time only and answers 204 either way; a second call, an unknown id and a message not yet sent change
     * nothing. Input: the fixed clock. Output: assertions only. Why: the amended spec. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory SQLite database.
     */
    // NOTIF-07
    public function testOpenEndpointRecordsTheFirstOpenOnly(): void
    {
        $sent = $this->service->endpointSend(['user_id' => 7, 'template_key' => 'welcome_email', 'channel' => 'email', 'vars' => ['app_name' => 'Open'], 'scheduled_at' => null]);
        $this->assertSame('sent', $sent['status']);
        $this->now = $this->now->modify('+5 minutes');
        $this->assertSame(['status' => 204], $this->service->endpointOpen((string)$sent['message_id']));
        $first = $this->logRow($sent['message_id']);
        $this->assertSame(['opened', '2026-11-10 12:05:00'], [$first['status'], $first['opened_at']]);
        $this->now = $this->now->modify('+1 hour');
        $this->assertSame(['status' => 204], $this->service->endpointOpen((string)$sent['message_id']));
        $this->assertSame($first, $this->logRow($sent['message_id']), 'a second open changes nothing');
        $this->assertSame(['status' => 204], $this->service->endpointOpen('999999'), 'unknown id: 204 as well');

        $queued = $this->service->endpointSend(['user_id' => 7, 'template_key' => 'welcome_email', 'channel' => 'email', 'vars' => [], 'scheduled_at' => '2026-12-01T00:00:00Z']);
        $this->assertSame(['status' => 204], $this->service->endpointOpen((string)$queued['message_id']));
        $this->assertSame(['queued', null], [$this->logRow($queued['message_id'])['status'], $this->logRow($queued['message_id'])['opened_at']], 'an unsent message is not opened');
    }

    /**
     * NOTIF-08: a failing email is retried with backoff and succeeds when the sender recovers. Changed 2026-11-10
     * (session_012zDydZCZ4AChqhEZ4oVtaP): the service is built with the injected secret and sleep (the
     * backoff really slept 1.5 s), and the backoff steps are asserted. Changed again the same day (Phase B.2,
     * amended NOTIF-08: up to 3 retries AFTER the first attempt): the sender fails three times and the fourth
     * attempt succeeds, after waits of 1 s, 2 s and 4 s (the test expected success on the third attempt after
     * 1 s and 2 s, which was the old 3-attempts-in-total count). testRetryGivesUpAfterFourAttempts proves the end.
     */
    // NOTIF-08
    public function testRetryOnFailure(): void
    {
        $sleeps = &$this->sleeps;
        $service = new class($this->pdo, [], [], self::SECRET, fn(): DateTimeImmutable => $this->now, 'https://example.com', function (int $us) use (&$sleeps): void { $sleeps[] = $us; }) extends NotificationService {
            public int $attempt = 0;
            protected function sendEmail(int $userId, string $subject, string $textBody, string $htmlBody): void
            {
                $this->attempt++;
                if ($this->attempt < 4) {
                    throw new Exception('SMTP error');
                }
                // Fourth attempt (the third retry) succeeds - store data but don't throw
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
        $this->assertSame(4, $service->attempt);
        $this->assertSame([1000000, 2000000, 4000000], $this->sleeps, 'exponential backoff 1 s, 2 s, 4 s');
    }

    /**
     * NOTIF-08, the end of the retries (Phase B.2): a sender that never recovers is tried 4 times (the first attempt
     * and 3 retries, waiting 1 s, 2 s, 4 s) and the message is marked 'failed'. Input: a sender that always
     * throws. Output: assertions only. Why: the amended spec ("a 4th failure marks it failed"). 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory SQLite database.
     */
    // NOTIF-08
    public function testRetryGivesUpAfterFourAttempts(): void
    {
        $sleeps = &$this->sleeps;
        $service = new class($this->pdo, [], [], self::SECRET, fn(): DateTimeImmutable => $this->now, 'https://example.com', function (int $us) use (&$sleeps): void { $sleeps[] = $us; }) extends NotificationService {
            public int $attempt = 0;
            protected function sendEmail(int $userId, string $subject, string $textBody, string $htmlBody): void
            {
                $this->attempt++;
                throw new Exception('SMTP down');
            }
        };
        $service->enableTestMode();
        $result = $service->endpointSend(['user_id' => 8, 'template_key' => 'welcome_email', 'channel' => 'email', 'vars' => ['app_name' => 'Down'], 'scheduled_at' => null]);
        $this->assertSame([false, 'failed', 'SMTP down'], [$result['success'], $result['status'], $result['error']]);
        $this->assertSame(4, $service->attempt, 'the first attempt and 3 retries');
        $this->assertSame([1000000, 2000000, 4000000], $this->sleeps);
        $this->assertSame('failed', $this->logRow($result['message_id'])['status']);
        $this->assertSame(3, NotificationService::MAX_RETRIES);
    }

    /**
     * NOTIF-09: an email carries the signed unsubscribe link; after the user unsubscribes through it, future
     * emails are skipped. Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the link is now signed
     * (user_id, channel, token; it was ?uid=&tid=), and the test proves the "future emails skipped" half.
     */
    // NOTIF-09
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
        $token = hash_hmac('sha256', 'unsubscribe:7:email', self::SECRET);
        $this->assertStringContainsString('user_id=7&amp;channel=email&amp;token=' . $token, $emailData['message']);

        parse_str((string)parse_url($emailData['unsubscribe_url'], PHP_URL_QUERY), $q);
        $this->assertSame(200, $this->service->handleUnsubscribe('POST', $q['user_id'], $q['channel'], $q['token'])['status']);
        $again = $this->service->endpointSend($payload);
        $this->assertEquals('skipped', $again['status'], 'future emails are skipped');
        $this->assertTrue($this->service->getUserPreferences(7)['channels_enabled']['in_app'], 'other channels untouched');
    }

    // NOTIF-10
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
        $payload['channel'] = 'in_app';
        $this->assertEquals('sent', $this->service->endpointSend($payload)['status'], 'an enabled channel still sends');
        // Preferences are the caller's own: another user cannot read or change them.
        $this->assertSame(403, $this->service->endpointUpdatePreferences(301, 300, ['channels_enabled' => ['sms' => true]])['code']);
        $this->assertSame(403, $this->service->endpointGetPreferences(301, 300)['code']);
        $this->assertFalse($this->service->getUserPreferences(300)['channels_enabled']['sms']);
    }

    /**
     * NOTIF-11: POST with a valid token sets channels_enabled[channel] false; GET changes nothing; a missing,
     * short, non-hex, uppercase or altered token, a token for another user or channel, or an unknown channel
     * gets 403 invalid_unsubscribe_token and the user stays subscribed; a secret under 32 bytes is refused at
     * start. Why: amended spec. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
     */
    // NOTIF-11
    public function testSignedUnsubscribeLink(): void
    {
        $valid = $this->service->unsubscribeToken(42, 'email');
        $this->assertSame(hash_hmac('sha256', 'unsubscribe:42:email', self::SECRET), $valid);
        $this->assertSame(1, preg_match('/^[0-9a-f]{64}$/', $valid));

        $get = $this->service->handleUnsubscribe('GET', '42', 'email', $valid);
        $this->assertSame(200, $get['status']);
        $this->assertTrue($get['body']['confirm']);
        $this->assertTrue($this->service->getUserPreferences(42)['channels_enabled']['email'], 'GET changes nothing');

        $altered = substr($valid, 0, -1) . ($valid[63] === '0' ? '1' : '0');
        $bad = [
            ['42', 'email', null],
            ['42', 'email', ''],
            ['42', 'email', substr($valid, 0, 63)],
            ['42', 'email', $valid . '0'],
            ['42', 'email', str_repeat('g', 64)],
            ['42', 'email', strtoupper($valid)],
            ['42', 'email', $altered],
            ['43', 'email', $valid],
            ['42', 'sms', $valid],
            ['42', 'fax', hash_hmac('sha256', 'unsubscribe:42:fax', self::SECRET)],
            ['42abc', 'email', $valid],
        ];
        foreach ($bad as [$uid, $channel, $token]) {
            $r = $this->service->handleUnsubscribe('POST', $uid, $channel, $token);
            $this->assertSame([403, ['error' => 'invalid_unsubscribe_token']], [$r['status'], $r['body']], "refused: $uid/$channel/" . var_export($token, true));
        }
        $this->assertTrue($this->service->getUserPreferences(42)['channels_enabled']['email'], 'still subscribed after refused attempts');
        $this->assertSame(0, (int)$this->pdo->query('SELECT COUNT(*) FROM user_notification_preferences WHERE user_id = 43')->fetchColumn(), 'no user lookup for a refused token');

        $post = $this->service->handleUnsubscribe('POST', '42', 'email', $valid);
        $this->assertSame(200, $post['status']);
        $this->assertFalse($this->service->getUserPreferences(42)['channels_enabled']['email']);
        $this->assertSame(405, $this->service->handleUnsubscribe('DELETE', '42', 'email', $valid)['status']);

        foreach (['', 'short-secret', str_repeat('x', 31)] as $weak) {
            try {
                new NotificationService($this->pdo, [], [], $weak);
                $this->fail('a secret under 32 bytes was accepted');
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('32 bytes', $e->getMessage());
            }
        }
    }

    /**
     * NOTIF-12: a send 30 days ahead is queued, not sent; deliverDue sends it once due, exactly once; a user
     * who unsubscribed meanwhile is skipped; a row stuck at 'sending' over 300 s is re-queued (and one under
     * 300 s is left alone). Why: amended spec. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
     */
    // NOTIF-12
    // deliverDue's result carries `deferred` (quiet hours, NOTIF-05) since 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
    // (Phase B.2); each expected array below gained deferred => 0 and nothing else changed.
    public function testScheduledSendDeliveredOnceByDeliverDue(): void
    {
        $utc = new DateTimeZone('UTC');
        $due = '2026-12-10T12:00:00Z';
        $a = $this->service->endpointSend(['user_id' => 50, 'template_key' => 'welcome_email', 'channel' => 'email', 'vars' => ['app_name' => 'Later'], 'scheduled_at' => $due]);
        $b = $this->service->endpointSend(['user_id' => 51, 'template_key' => 'welcome_email', 'channel' => 'email', 'vars' => ['app_name' => 'Later'], 'scheduled_at' => $due]);
        $this->assertSame(['queued', 'queued'], [$a['status'], $b['status']]);
        $this->assertSame([], $this->service->getLastEmailData(), 'not sent now');
        $this->assertSame(['requeued' => 0, 'sent' => 0, 'skipped' => 0, 'failed' => 0, 'deferred' => 0], $this->service->deliverDue());

        // User 51 unsubscribes meanwhile.
        $this->service->handleUnsubscribe('POST', '51', 'email', $this->service->unsubscribeToken(51, 'email'));

        $at = new DateTimeImmutable('2026-12-10 12:00:00', $utc);
        $this->assertSame(['requeued' => 0, 'sent' => 1, 'skipped' => 1, 'failed' => 0, 'deferred' => 0], $this->service->deliverDue($at));
        $this->assertSame('sent', $this->logRow($a['message_id'])['status']);
        $this->assertSame(['skipped', 'channel_disabled'], [$this->logRow($b['message_id'])['status'], $this->logRow($b['message_id'])['error']]);
        $this->assertSame(['requeued' => 0, 'sent' => 0, 'skipped' => 0, 'failed' => 0, 'deferred' => 0], $this->service->deliverDue($at->modify('+1 hour')), 'exactly once');

        // A crashed worker's claim: re-queued after 300 s, not before.
        $c = $this->service->endpointSend(['user_id' => 52, 'template_key' => 'welcome_email', 'channel' => 'in_app', 'vars' => [], 'scheduled_at' => $due]);
        $this->pdo->prepare("UPDATE notification_logs SET status = 'sending', claimed_at = :t WHERE id = :id")->execute([':t' => '2026-12-10 12:00:00', ':id' => $c['message_id']]);
        $this->assertSame(['requeued' => 0, 'sent' => 0, 'skipped' => 0, 'failed' => 0, 'deferred' => 0], $this->service->deliverDue(new DateTimeImmutable('2026-12-10 12:05:00', $utc)));
        $this->assertSame('sending', $this->logRow($c['message_id'])['status']);
        $this->assertSame(['requeued' => 1, 'sent' => 1, 'skipped' => 0, 'failed' => 0, 'deferred' => 0], $this->service->deliverDue(new DateTimeImmutable('2026-12-10 12:05:01', $utc)));
        $this->assertSame('sent', $this->logRow($c['message_id'])['status']);
    }
}
?>

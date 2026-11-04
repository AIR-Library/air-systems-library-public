<?php
// Repaired 2026-11-03: a test mode captures e-mail and SMS instead of sending them, so the tests need neither
//   runkit nor a mail server.
// Why: the suite failed on CI (it was listed in ci/baseline.json). Reviewed by Claude; fixed by a free model from a continuity handoff, session c6ee9a72 (2026-11-03).
// Touches: the database, mail() and the SMS API (not in test mode).
declare(strict_types=1);

namespace NotificationSystem;

use PDO;
use PDOException;
use Exception;

/**
 * Database migration: creates required tables.
 */
function runMigrations(PDO $pdo): void
{
    $sql = <<<SQL
CREATE TABLE IF NOT EXISTS notification_templates (
    `key` VARCHAR(100) PRIMARY KEY,
    subject VARCHAR(255),
    body_text TEXT,
    body_html TEXT,
    channels_default VARCHAR(20),
    variables JSON
);

CREATE TABLE IF NOT EXISTS notification_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    template_key VARCHAR(100) NOT NULL,
    channel VARCHAR(20) NOT NULL,
    vars_used JSON,
    sent_at DATETIME,
    opened_at DATETIME,
    clicked_at DATETIME,
    bounced INTEGER DEFAULT 0,
    error TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'queued'
);

CREATE TABLE IF NOT EXISTS user_notification_preferences (
    user_id INTEGER PRIMARY KEY,
    do_not_disturb INTEGER DEFAULT 0,
    quiet_hours_start TIME,
    quiet_hours_end TIME,
    channels_enabled JSON
);
SQL;
    $pdo->exec($sql);
}

/**
 * Simple templating engine: replaces {var} with value.
 */
function renderTemplate(string $template, array $variables): string
{
    foreach ($variables as $key => $value) {
        $template = str_replace('{' . $key . '}', (string)$value, $template);
    }
    return $template;
}

/**
 * Notification Service handling send, batch, tracking, preferences.
 */
class NotificationService
{
    private PDO $pdo;
    private array $emailConfig;
    private array $smsConfig;
    private int $maxRetries = 3;
    protected array $lastEmailData = [];
    protected array $lastSmsData = [];
    protected bool $testMode = false;

    public function __construct(PDO $pdo, array $emailConfig = [], array $smsConfig = [])
    {
        $this->pdo = $pdo;
        $this->emailConfig = $emailConfig;
        $this->smsConfig = $smsConfig;
        runMigrations($this->pdo);
    }

    public function enableTestMode(): void
    {
        $this->testMode = true;
    }

    public function getLastEmailData(): array
    {
        return $this->lastEmailData;
    }

    public function getLastSmsData(): array
    {
        return $this->lastSmsData;
    }

    /**
     * Send a single notification.
     */
    public function sendNotification(
        int $userId,
        string $templateKey,
        ?string $channel,
        array $vars = [],
        ?string $scheduledAt = null
    ): array {
        // Load template
        $stmt = $this->pdo->prepare('SELECT * FROM notification_templates WHERE `key` = :key');
        $stmt->execute([':key' => $templateKey]);
        $template = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$template) {
            return ['success' => false, 'error' => 'Template not found'];
        }

        // Load user preferences
        $pref = $this->getUserPreferences($userId);
        if ($pref['do_not_disturb']) {
            $this->logSkipped($userId, $templateKey, $channel ?? $template['channels_default'], $vars, 'do_not_disturb');
            return ['success' => true, 'message_id' => null, 'status' => 'skipped'];
        }

        // Quiet hours handling
        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $quietStart = $pref['quiet_hours_start'] ? \DateTimeImmutable::createFromFormat('H:i', $pref['quiet_hours_start'], new \DateTimeZone('UTC')) : null;
        $quietEnd   = $pref['quiet_hours_end']   ? \DateTimeImmutable::createFromFormat('H:i', $pref['quiet_hours_end'],   new \DateTimeZone('UTC')) : null;
        $inQuiet = false;
        if ($quietStart && $quietEnd) {
            $nowTime = (int)$now->format('Hi');
            $start   = (int)$quietStart->format('Hi');
            $end     = (int)$quietEnd->format('Hi');
            if ($start < $end) {
                $inQuiet = $nowTime >= $start && $nowTime < $end;
            } else { // wraps midnight
                $inQuiet = $nowTime >= $start || $nowTime < $end;
            }
        }
        if ($inQuiet) {
            // Queue for end of quiet hours
            $queueTime = $quietEnd ? $quietEnd->format('H:i:s') : '08:00:00';
            $scheduledAt = (new \DateTimeImmutable('today ' . $queueTime, new \DateTimeZone('UTC')))->format('c');
        }

        // Determine channel
        $selectedChannel = $channel ?? $template['channels_default'];
        $enabledChannels = $pref['channels_enabled'] ?? [];
        if (isset($enabledChannels[$selectedChannel]) && $enabledChannels[$selectedChannel] === false) {
            $this->logSkipped($userId, $templateKey, $selectedChannel, $vars, 'channel_disabled');
            return ['success' => true, 'message_id' => null, 'status' => 'skipped'];
        }

        // Render content
        $subject = $template['subject'] ? renderTemplate($template['subject'], $vars) : '';
        $bodyText = $template['body_text'] ? renderTemplate($template['body_text'], $vars) : '';
        $bodyHtml = $template['body_html'] ? renderTemplate($template['body_html'], $vars) : '';

        // Insert log entry (status queued)
        $logStmt = $this->pdo->prepare('INSERT INTO notification_logs (user_id, template_key, channel, vars_used, status) VALUES (:uid, :tk, :ch, :vars, :st)');
        $logStmt->execute([
            ':uid'   => $userId,
            ':tk'    => $templateKey,
            ':ch'    => $selectedChannel,
            ':vars'  => json_encode($vars),
            ':st'    => $scheduledAt ? 'queued' : 'pending'
        ]);
        $messageId = (int)$this->pdo->lastInsertId();

        // If scheduled for future, just return queued
        if ($scheduledAt) {
            $update = $this->pdo->prepare('UPDATE notification_logs SET sent_at = :sa, status = :st WHERE id = :id');
            $update->execute([
                ':sa' => $scheduledAt,
                ':st' => 'queued',
                ':id' => $messageId
            ]);
            return ['success' => true, 'message_id' => (string)$messageId, 'status' => 'queued'];
        }

        // Attempt to send with retries
        $attempt = 0;
        $sent = false;
        $errorMsg = null;
        while ($attempt < $this->maxRetries && !$sent) {
            try {
                switch ($selectedChannel) {
                    case 'email':
                        $this->sendEmail($userId, $subject, $bodyText, $bodyHtml);
                        break;
                    case 'sms':
                        $this->sendSms($userId, $bodyText);
                        break;
                    case 'in_app':
                        // In-app just stored; consider sent
                        break;
                    default:
                        throw new Exception('Unsupported channel');
                }
                $sent = true;
            } catch (Exception $e) {
                $attempt++;
                $errorMsg = $e->getMessage();
                if ($attempt < $this->maxRetries) {
                    usleep((int)pow(2, $attempt) * 500000); // exponential backoff
                }
            }
        }

        // Update log
        $status = $sent ? 'sent' : 'failed';
        $update = $this->pdo->prepare('UPDATE notification_logs SET sent_at = :sa, status = :st, error = :err, bounced = :bounced WHERE id = :id');
        $update->execute([
            ':sa' => (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s'),
            ':st' => $status,
            ':err'=> $errorMsg,
            ':bounced' => $sent ? 0 : 1,
            ':id' => $messageId
        ]);

        return [
            'success' => $sent,
            'message_id' => (string)$messageId,
            'status' => $sent ? 'sent' : 'failed',
            'error' => $errorMsg
        ];
    }

    /**
     * Send batch notifications.
     */
    public function sendBatch(array $notifications): array
    {
        $sent = 0;
        $failed = 0;
        $ids = [];

        foreach ($notifications as $n) {
            $res = $this->sendNotification(
                $n['user_id'],
                $n['template_key'],
                $n['channel'] ?? null,
                $n['vars'] ?? [],
                $n['scheduled_at'] ?? null
            );
            if (isset($res['message_id']) && $res['message_id'] !== null) {
                $ids[] = $res['message_id'];
            }
            if ($res['status'] === 'sent') {
                $sent++;
            } else {
                $failed++;
            }
        }

        return [
            'success' => true,
            'sent' => $sent,
            'failed' => $failed,
            'message_ids' => $ids
        ];
    }

    /**
     * Track message status.
     */
    public function trackMessage(string $messageId): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM notification_logs WHERE id = :id');
        $stmt->execute([':id' => $messageId]);
        $log = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$log) {
            return ['error' => 'Message not found'];
        }

        return [
            'message_id'   => $log['id'],
            'user_id'      => $log['user_id'],
            'template_key' => $log['template_key'],
            'channel'      => $log['channel'],
            'status'       => $log['status'],
            'sent_at'      => $log['sent_at'],
            'opened_at'    => $log['opened_at'],
            'clicked_at'   => $log['clicked_at'],
            'bounced'      => (bool)$log['bounced'],
            'error'        => $log['error']
        ];
    }

    /**
     * Get user preferences.
     */
    public function getUserPreferences(int $userId): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM user_notification_preferences WHERE user_id = :uid');
        $stmt->execute([':uid' => $userId]);
        $pref = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$pref) {
            // Default preferences
            $default = [
                'user_id' => $userId,
                'do_not_disturb' => false,
                'quiet_hours_start' => null,
                'quiet_hours_end' => null,
                'channels_enabled' => json_encode(['email' => true, 'sms' => true, 'in_app' => true])
            ];
            $ins = $this->pdo->prepare('INSERT INTO user_notification_preferences (user_id, do_not_disturb, quiet_hours_start, quiet_hours_end, channels_enabled) VALUES (:uid, 0, NULL, NULL, :ch)');
            $ins->execute([':uid' => $userId, ':ch' => $default['channels_enabled']]);
            $pref = $default;
        }

        return [
            'user_id' => $userId,
            'do_not_disturb' => (bool)$pref['do_not_disturb'],
            'quiet_hours_start' => $pref['quiet_hours_start'],
            'quiet_hours_end' => $pref['quiet_hours_end'],
            'channels_enabled' => json_decode($pref['channels_enabled'], true)
        ];
    }

    /**
     * Update user preferences.
     */
    public function updateUserPreferences(int $userId, array $updates): array
    {
        $fields = [];
        $params = [':uid' => $userId];
        if (isset($updates['do_not_disturb'])) {
            $fields[] = 'do_not_disturb = :dnd';
            $params[':dnd'] = $updates['do_not_disturb'] ? 1 : 0;
        }
        if (isset($updates['quiet_hours_start'])) {
            $fields[] = 'quiet_hours_start = :qhs';
            $params[':qhs'] = $updates['quiet_hours_start'];
        }
        if (isset($updates['quiet_hours_end'])) {
            $fields[] = 'quiet_hours_end = :qhe';
            $params[':qhe'] = $updates['quiet_hours_end'];
        }
        if (isset($updates['channels_enabled'])) {
            $fields[] = 'channels_enabled = :ch';
            $params[':ch'] = json_encode($updates['channels_enabled']);
        }
        if (empty($fields)) {
            return ['success' => false, 'error' => 'No fields to update'];
        }
        $sql = 'UPDATE user_notification_preferences SET ' . implode(', ', $fields) . ' WHERE user_id = :uid';
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return ['success' => true];
    }

    /**
     * Internal: log a skipped notification.
     */
    private function logSkipped(int $userId, string $templateKey, string $channel, array $vars, string $reason): void
    {
        $stmt = $this->pdo->prepare('INSERT INTO notification_logs (user_id, template_key, channel, vars_used, status, error) VALUES (:uid, :tk, :ch, :vars, :st, :err)');
        $stmt->execute([
            ':uid'   => $userId,
            ':tk'    => $templateKey,
            ':ch'    => $channel,
            ':vars'  => json_encode($vars),
            ':st'    => 'skipped',
            ':err'   => $reason
        ]);
    }

    /**
     * Internal: send email via PHP's mail() (placeholder for real SMTP).
     */
    protected function sendEmail(int $userId, string $subject, string $textBody, string $htmlBody): void
    {
        // Retrieve user email from a hypothetical users table (not defined). For demo, use placeholder.
        $to = "user{$userId}@example.com";
        $headers = "From: no-reply@example.com\r\n";
        $headers .= "MIME-Version: 1.0\r\n";
        $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
        // Append unsubscribe link
        $unsubscribeLink = "https://example.com/unsubscribe?uid={$userId}&tid=" . urlencode($subject);
        $htmlBody .= "<br><br><a href=\"{$unsubscribeLink}\">Unsubscribe</a>";
        $message = $htmlBody ?: nl2br($textBody);

        $this->lastEmailData = [
            'to' => $to,
            'subject' => $subject,
            'message' => $message,
            'headers' => $headers
        ];

        if ($this->testMode) {
            return;
        }

        $sent = mail($to, $subject, $message, $headers);
        if (!$sent) {
            throw new Exception('Email sending failed');
        }
    }

    /**
     * Internal: send SMS via Twilio REST API (simplified).
     */
    protected function sendSms(int $userId, string $text): void
    {
        // Retrieve user phone from a hypothetical users table. Placeholder:
        $to = "+1555000" . str_pad((string)$userId, 4, '0', STR_PAD_LEFT);
        $accountSid = $this->smsConfig['account_sid'] ?? '';
        $authToken  = $this->smsConfig['auth_token'] ?? '';
        $from       = $this->smsConfig['from'] ?? '';
        $url = "https://api.twilio.com/2010-04-01/Accounts/{$accountSid}/Messages.json";

        $postFields = http_build_query([
            'To'   => $to,
            'From' => $from,
            'Body' => $text
        ]);

        $this->lastSmsData = [
            'to' => $to,
            'from' => $from,
            'body' => $text,
            'url' => $url
        ];

        if ($this->testMode) {
            return;
        }

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_USERPWD, $accountSid . ':' . $authToken);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postFields);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $result = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if (curl_errno($ch) || $httpCode >= 400) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new Exception('SMS sending failed: ' . ($err ?: $result));
        }
        curl_close($ch);
    }

    /**
     * Public API entry points (simulating HTTP endpoints).
     */
    public function endpointSend(array $payload): array
    {
        return $this->sendNotification(
            $payload['user_id'],
            $payload['template_key'],
            $payload['channel'] ?? null,
            $payload['vars'] ?? [],
            $payload['scheduled_at'] ?? null
        );
    }

    public function endpointSendBatch(array $payload): array
    {
        return $this->sendBatch($payload);
    }

    public function endpointTrack(string $messageId): array
    {
        return $this->trackMessage($messageId);
    }

    public function endpointGetPreferences(int $userId): array
    {
        return $this->getUserPreferences($userId);
    }

    public function endpointUpdatePreferences(int $userId, array $payload): array
    {
        return $this->updateUserPreferences($userId, $payload);
    }
}

/**
 * Helper to seed default templates.
 */
function seedTemplates(PDO $pdo): void
{
    $templates = [
        [
            'key' => 'welcome_email',
            'subject' => 'Welcome to {app_name}!',
            'body_text' => 'Welcome to {app_name}! Here\'s your first step.',
            'body_html' => '<p>Welcome to {app_name}! Here\'s your first step.</p>',
            'channels_default' => 'email',
            'variables' => json_encode(['app_name'])
        ],
        [
            'key' => 'trial_starting',
            'subject' => 'Your trial is starting',
            'body_text' => 'Your free trial is starting. You have {trial_days} days.',
            'body_html' => '<p>Your free trial is starting. You have {trial_days} days.</p>',
            'channels_default' => 'email',
            'variables' => json_encode(['trial_days'])
        ],
        [
            'key' => 'trial_ending_soon',
            'subject' => 'Trial ending soon',
            'body_text' => 'Your trial ends in {days_left} days. Add payment method to continue.',
            'body_html' => '<p>Your trial ends in {days_left} days. Add payment method to continue.</p>',
            'channels_default' => 'email',
            'variables' => json_encode(['days_left'])
        ],
        [
            'key' => 'subscription_changed',
            'subject' => 'Subscription changed',
            'body_text' => 'Your plan changed from {old_tier} to {new_tier}. Effective {effective_date}.',
            'body_html' => '<p>Your plan changed from {old_tier} to {new_tier}. Effective {effective_date}.</p>',
            'channels_default' => 'email',
            'variables' => json_encode(['old_tier','new_tier','effective_date'])
        ],
        [
            'key' => 'payment_failed',
            'subject' => 'Payment failed',
            'body_text' => 'Payment failed for invoice {invoice_id}. {retry_date} retry, or update payment method.',
            'body_html' => '<p>Payment failed for invoice {invoice_id}. {retry_date} retry, or update payment method.</p>',
            'channels_default' => 'email',
            'variables' => json_encode(['invoice_id','retry_date'])
        ],
        [
            'key' => 'deployment_live',
            'subject' => 'Deployment live',
            'body_text' => 'Your deployment {deployment_name} is now live at {url}.',
            'body_html' => '<p>Your deployment {deployment_name} is now live at <a href="{url}">{url}</a>.</p>',
            'channels_default' => 'email',
            'variables' => json_encode(['deployment_name','url'])
        ],
        [
            'key' => 'user_invited',
            'subject' => 'You\'ve been invited',
            'body_text' => 'You\'ve been invited to {workspace}. Click here to join.',
            'body_html' => '<p>You\'ve been invited to {workspace}. <a href="#">Click here to join</a>.</p>',
            'channels_default' => 'email',
            'variables' => json_encode(['workspace'])
        ],
        [
            'key' => 'invoice_ready',
            'subject' => 'Invoice ready',
            'body_text' => 'Your invoice for {month} is ready. Download here.',
            'body_html' => '<p>Your invoice for {month} is ready. <a href="#">Download here</a>.</p>',
            'channels_default' => 'email',
            'variables' => json_encode(['month'])
        ],
        [
            'key' => 'admin_alert',
            'subject' => 'Admin alert',
            'body_text' => '{actor} performed {action} on {resource}.',
            'body_html' => '<p>{actor} performed {action} on {resource}.</p>',
            'channels_default' => 'email',
            'variables' => json_encode(['actor','action','resource'])
        ]
    ];

    $stmt = $pdo->prepare('INSERT OR IGNORE INTO notification_templates (`key`, subject, body_text, body_html, channels_default, variables) VALUES (:key, :subject, :body_text, :body_html, :channels_default, :variables)');
    foreach ($templates as $t) {
        $stmt->execute([
            ':key' => $t['key'],
            ':subject' => $t['subject'],
            ':body_text' => $t['body_text'],
            ':body_html' => $t['body_html'],
            ':channels_default' => $t['channels_default'],
            ':variables' => $t['variables']
        ]);
    }
}

// Example bootstrap (not executed in tests)
if (php_sapi_name() === 'cli' && isset($argv[1]) && $argv[1] === 'init') {
    $pdo = new PDO('sqlite:' . __DIR__ . '/notifications.db');
    $service = new NotificationService($pdo);
    seedTemplates($pdo);
    echo "Database initialized.\n";
}
?>

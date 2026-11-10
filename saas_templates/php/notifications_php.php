<?php
// Repaired 2026-11-03: a test mode captures e-mail and SMS instead of sending them, so the tests need neither
//   runkit nor a mail server.
// Why: the suite failed on CI (it was listed in ci/baseline.json). Reviewed by Claude; fixed by a free model from a continuity handoff, session c6ee9a72 (2026-11-03).
// Touches: the database, mail() and the SMS API (not in test mode).
// Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): see NotificationService (NOTIF-02/05/11/12 amendments).
declare(strict_types=1);

namespace NotificationSystem;

use PDO;
use PDOException;
use Exception;

/**
 * Database migration: creates required tables. notification_logs has status ('queued' | 'sending' | 'sent' |
 * 'skipped' | 'failed' | 'opened'), scheduled_at and claimed_at for deliverDue (added 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP, NOTIF-12). Touches: the database (DDL).
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
    status VARCHAR(20) NOT NULL DEFAULT 'queued',
    scheduled_at DATETIME NULL,
    claimed_at DATETIME NULL
);
CREATE INDEX IF NOT EXISTS idx_notification_logs_due ON notification_logs (status, scheduled_at);

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
 * Notification Service handling send, batch, scheduled delivery, tracking, preferences and unsubscribe.
 *
 * Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, for the amended spec (NOTIF-02/05/11/12):
 *  - default preferences: no quiet hours, do_not_disturb false, channels {email true, sms false, in_app true}
 *    (SMS was on by default; it is opt-in);
 *  - unsubscribe links carry token = lowercase hex HMAC-SHA256(secret, "unsubscribe:" + user_id + ":" + channel);
 *    the service refuses to start with a secret under 32 bytes; a malformed, wrong or unknown-channel token
 *    gets the same 403 invalid_unsubscribe_token before any user lookup; GET only confirms, POST unsubscribes
 *    (the old link was unsigned: anyone could unsubscribe anyone);
 *  - quiet hours and future sends are stored 'queued' with scheduled_at (quiet hours: the next quiet_hours_end;
 *    the old code wrote the time into sent_at) and delivered by deliverDue(now) in the spec's four steps;
 *  - the clock, the retry sleep and the senders are injectable; tracking records opens and clicks.
 *
 * Touches: the database (notification_* tables), e-mail via mail() and the Twilio SMS API (not in test mode).
 */
class NotificationService
{
    public const CHANNELS = ['email', 'sms', 'in_app'];
    public const DEFAULT_CHANNELS = ['email' => true, 'sms' => false, 'in_app' => true];
    /** A 'sending' row claimed longer ago than this is re-queued (a crashed worker). */
    public const CLAIM_TIMEOUT_SECONDS = 300;

    private PDO $pdo;
    private array $emailConfig;
    private array $smsConfig;
    private int $maxRetries = 3;
    protected array $lastEmailData = [];
    protected array $lastSmsData = [];
    protected bool $testMode = false;
    private string $unsubscribeSecret;
    private string $baseUrl;
    /** @var \Closure(): \DateTimeImmutable */
    private \Closure $clock;
    /** @var \Closure(int): void retry backoff sleep, in microseconds */
    private \Closure $sleeper;

    /**
     * Inputs: $pdo (shared connection; tables are created), e-mail and SMS settings, $unsubscribeSecret (at
     * least 32 bytes; default the NOTIFICATIONS_UNSUBSCRIBE_SECRET environment variable), $clock (fn():
     * DateTimeImmutable, default now in UTC), $baseUrl for unsubscribe links, $sleeper (fn(int microseconds),
     * default usleep) for retry backoff.
     * Throws InvalidArgumentException when the secret is shorter than 32 bytes: an empty or short key makes a
     * forgeable HMAC (NOTIF-11). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (DDL).
     */
    public function __construct(
        PDO $pdo,
        array $emailConfig = [],
        array $smsConfig = [],
        ?string $unsubscribeSecret = null,
        ?\Closure $clock = null,
        string $baseUrl = 'https://example.com',
        ?\Closure $sleeper = null
    ) {
        $secret = $unsubscribeSecret ?? (string)getenv('NOTIFICATIONS_UNSUBSCRIBE_SECRET');
        if (strlen($secret) < 32) {
            throw new \InvalidArgumentException('The unsubscribe secret must be at least 32 bytes (set NOTIFICATIONS_UNSUBSCRIBE_SECRET)');
        }
        $this->pdo = $pdo;
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->emailConfig = $emailConfig;
        $this->smsConfig = $smsConfig;
        $this->unsubscribeSecret = $secret;
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->clock = $clock ?? static fn(): \DateTimeImmutable => new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $this->sleeper = $sleeper ?? static function (int $microseconds): void { usleep($microseconds); };
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

    /** Now from the injected clock, in UTC. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    private function now(): \DateTimeImmutable
    {
        return ($this->clock)()->setTimezone(new \DateTimeZone('UTC'));
    }

    /** 'Y-m-d H:i:s' UTC text, the format of every time column here. Touches: nothing. */
    private static function ts(\DateTimeImmutable $t): string
    {
        return $t->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s');
    }

    /**
     * Send a single notification (POST /notifications/send).
     *
     * Inputs: user id (the caller must be authorised to notify this user), template key, channel or null
     * (the template's default), template variables, scheduled_at (ISO 8601) or null. Output: {success,
     * message_id, status 'sent'|'queued'|'skipped'|'failed'}. Order: do-not-disturb or a disabled channel ->
     * 'skipped' (logged); a future scheduled_at or the user's quiet hours -> 'queued' with scheduled_at (the
     * given time, or the next quiet_hours_end) for deliverDue(); else sent now with retries.
     * Why: NOTIF-01..06/10, quiet hours amended 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP).
     * Touches: the database; e-mail / SMS through the senders.
     */
    public function sendNotification(
        int $userId,
        string $templateKey,
        ?string $channel,
        array $vars = [],
        ?string $scheduledAt = null
    ): array {
        $template = $this->loadTemplate($templateKey);
        if (!$template) {
            return ['success' => false, 'error' => 'Template not found'];
        }
        $selectedChannel = $channel ?? $template['channels_default'];
        $pref = $this->getUserPreferences($userId);
        $skip = $this->skipReason($pref, $selectedChannel);
        if ($skip !== null) {
            $this->logSkipped($userId, $templateKey, $selectedChannel, $vars, $skip);
            return ['success' => true, 'message_id' => null, 'status' => 'skipped'];
        }

        $now = $this->now();
        $queueAt = null;
        if ($scheduledAt !== null && $scheduledAt !== '') {
            $at = new \DateTimeImmutable($scheduledAt, new \DateTimeZone('UTC'));
            if ($at > $now) {
                $queueAt = $at;
            }
        }
        if ($queueAt === null) {
            $queueAt = $this->quietHoursEnd($pref, $now);
        }

        $logStmt = $this->pdo->prepare('INSERT INTO notification_logs (user_id, template_key, channel, vars_used, status, scheduled_at) VALUES (:uid, :tk, :ch, :vars, :st, :sched)');
        $logStmt->execute([
            ':uid' => $userId,
            ':tk' => $templateKey,
            ':ch' => $selectedChannel,
            ':vars' => json_encode($vars),
            ':st' => $queueAt !== null ? 'queued' : 'sending',
            ':sched' => $queueAt !== null ? self::ts($queueAt) : null,
        ]);
        $messageId = (int)$this->pdo->lastInsertId();
        if ($queueAt !== null) {
            return ['success' => true, 'message_id' => (string)$messageId, 'status' => 'queued'];
        }

        $error = $this->dispatch($userId, $template, $selectedChannel, $vars);
        $sent = $error === null;
        $this->pdo->prepare('UPDATE notification_logs SET sent_at = :sa, status = :st, error = :err, bounced = :bounced WHERE id = :id')
            ->execute([':sa' => self::ts($this->now()), ':st' => $sent ? 'sent' : 'failed', ':err' => $error, ':bounced' => $sent ? 0 : 1, ':id' => $messageId]);

        return ['success' => $sent, 'message_id' => (string)$messageId, 'status' => $sent ? 'sent' : 'failed', 'error' => $error];
    }

    /**
     * deliver_due(now): send queued messages that are due, in the spec's four steps.
     * 1. 'sending' rows claimed more than 300 s ago go back to 'queued' (a crashed worker);
     * 2. due 'queued' rows (scheduled_at <= now), by scheduled_at then insertion order, are claimed one by one
     *    with UPDATE ... SET status = 'sending', claimed_at = now WHERE id = ? AND status = 'queued' (a row
     *    another worker claimed first is skipped);
     * 3. preferences are checked NOW: do-not-disturb or the channel switched off (e.g. unsubscribed) ->
     *    'skipped';
     * 4. the final write is conditional on the same claim (status 'sending' and this claimed_at).
     * Input: now (default the clock). Output: {requeued, sent, skipped, failed}. No in-process timers.
     * Why: NOTIF-12 (amended 2026-11-10 after an independent security review). session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database; e-mail / SMS through the senders.
     */
    public function deliverDue(?\DateTimeImmutable $now = null): array
    {
        $now = ($now ?? $this->now())->setTimezone(new \DateTimeZone('UTC'));
        $nowText = self::ts($now);
        $requeue = $this->pdo->prepare("UPDATE notification_logs SET status = 'queued', claimed_at = NULL WHERE status = 'sending' AND claimed_at IS NOT NULL AND claimed_at < :cutoff");
        $requeue->execute([':cutoff' => self::ts($now->modify('-' . self::CLAIM_TIMEOUT_SECONDS . ' seconds'))]);
        $result = ['requeued' => $requeue->rowCount(), 'sent' => 0, 'skipped' => 0, 'failed' => 0];

        $due = $this->pdo->prepare("SELECT id FROM notification_logs WHERE status = 'queued' AND scheduled_at IS NOT NULL AND scheduled_at <= :now ORDER BY scheduled_at ASC, id ASC");
        $due->execute([':now' => $nowText]);
        $claim = $this->pdo->prepare("UPDATE notification_logs SET status = 'sending', claimed_at = :now WHERE id = :id AND status = 'queued'");
        $final = $this->pdo->prepare("UPDATE notification_logs SET status = :st, sent_at = :sa, error = :err, bounced = :bounced WHERE id = :id AND status = 'sending' AND claimed_at = :claimed");
        foreach ($due->fetchAll(PDO::FETCH_COLUMN) as $id) {
            $claim->execute([':now' => $nowText, ':id' => $id]);
            if ($claim->rowCount() !== 1) {
                continue; // another worker claimed it first
            }
            $row = $this->pdo->query('SELECT * FROM notification_logs WHERE id = ' . (int)$id)->fetch(PDO::FETCH_ASSOC);
            $template = $this->loadTemplate((string)$row['template_key']);
            $skip = $template ? $this->skipReason($this->getUserPreferences((int)$row['user_id']), (string)$row['channel']) : 'template_missing';
            if ($skip !== null) {
                $final->execute([':st' => 'skipped', ':sa' => null, ':err' => $skip, ':bounced' => 0, ':id' => $id, ':claimed' => $nowText]);
                $result['skipped'] += $final->rowCount();
                continue;
            }
            $vars = json_decode((string)$row['vars_used'], true) ?: [];
            $error = $this->dispatch((int)$row['user_id'], $template, (string)$row['channel'], $vars);
            $final->execute([
                ':st' => $error === null ? 'sent' : 'failed',
                ':sa' => self::ts($this->now()),
                ':err' => $error,
                ':bounced' => $error === null ? 0 : 1,
                ':id' => $id,
                ':claimed' => $nowText,
            ]);
            $result[$error === null ? 'sent' : 'failed'] += $final->rowCount();
        }
        return $result;
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
     * Record that the user clicked a link in a sent message: clicked_at = now, opened_at = now if not yet
     * set, status 'opened' (a click proves the message was opened). Output: the tracked message, or
     * {error} for an unknown or unsent message.
     * Why: NOTIF-07 ("message marked as opened when user clicks link") had no implementation.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function recordClick(string $messageId): array
    {
        $now = self::ts($this->now());
        $stmt = $this->pdo->prepare("UPDATE notification_logs SET clicked_at = :now, opened_at = COALESCE(opened_at, :now2), status = 'opened' WHERE id = :id AND status IN ('sent', 'opened')");
        $stmt->execute([':now' => $now, ':now2' => $now, ':id' => $messageId]);
        if ($stmt->rowCount() !== 1) {
            return ['error' => 'Message not found'];
        }
        return $this->trackMessage($messageId);
    }

    /**
     * Get user preferences; a user who has set none gets the defaults (no quiet hours, do_not_disturb false,
     * channels {email true, sms false, in_app true}), stored on first read.
     * Why: NOTIF-02 as amended: SMS is opt-in (it was on by default). 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function getUserPreferences(int $userId): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM user_notification_preferences WHERE user_id = :uid');
        $stmt->execute([':uid' => $userId]);
        $pref = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$pref) {
            $pref = [
                'user_id' => $userId,
                'do_not_disturb' => 0,
                'quiet_hours_start' => null,
                'quiet_hours_end' => null,
                'channels_enabled' => json_encode(self::DEFAULT_CHANNELS),
            ];
            $ins = $this->pdo->prepare('INSERT OR IGNORE INTO user_notification_preferences (user_id, do_not_disturb, quiet_hours_start, quiet_hours_end, channels_enabled) VALUES (:uid, 0, NULL, NULL, :ch)');
            $ins->execute([':uid' => $userId, ':ch' => $pref['channels_enabled']]);
        }
        $channels = json_decode((string)($pref['channels_enabled'] ?? ''), true);
        return [
            'user_id' => $userId,
            'do_not_disturb' => (bool)$pref['do_not_disturb'],
            'quiet_hours_start' => $pref['quiet_hours_start'],
            'quiet_hours_end' => $pref['quiet_hours_end'],
            'channels_enabled' => (is_array($channels) ? $channels : []) + self::DEFAULT_CHANNELS,
        ];
    }

    /**
     * Update user preferences. channels_enabled is merged into the stored map (only known channels, booleans).
     * Output: {success} or {success: false, error}.
     * Why: it updated nothing for a user without a stored row, and replaced the whole channel map.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function updateUserPreferences(int $userId, array $updates): array
    {
        $current = $this->getUserPreferences($userId); // makes sure the row exists
        $fields = [];
        $params = [':uid' => $userId];
        if (array_key_exists('do_not_disturb', $updates)) {
            $fields[] = 'do_not_disturb = :dnd';
            $params[':dnd'] = $updates['do_not_disturb'] ? 1 : 0;
        }
        if (array_key_exists('quiet_hours_start', $updates)) {
            $fields[] = 'quiet_hours_start = :qhs';
            $params[':qhs'] = $updates['quiet_hours_start'];
        }
        if (array_key_exists('quiet_hours_end', $updates)) {
            $fields[] = 'quiet_hours_end = :qhe';
            $params[':qhe'] = $updates['quiet_hours_end'];
        }
        if (isset($updates['channels_enabled']) && is_array($updates['channels_enabled'])) {
            $channels = $current['channels_enabled'];
            foreach ($updates['channels_enabled'] as $ch => $on) {
                if (in_array($ch, self::CHANNELS, true)) {
                    $channels[$ch] = (bool)$on;
                }
            }
            $fields[] = 'channels_enabled = :ch';
            $params[':ch'] = json_encode($channels);
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
     * Unsubscribe token: lowercase hex HMAC-SHA256(secret, "unsubscribe:" + user_id + ":" + channel).
     * Why: NOTIF-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public function unsubscribeToken(int|string $userId, string $channel): string
    {
        return hash_hmac('sha256', 'unsubscribe:' . $userId . ':' . $channel, $this->unsubscribeSecret);
    }

    /**
     * The signed unsubscribe link <base_url>/unsubscribe?user_id=<id>&channel=<channel>&token=<token>.
     * Why: NOTIF-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public function unsubscribeUrl(int $userId, string $channel): string
    {
        return $this->baseUrl . '/unsubscribe?' . http_build_query(['user_id' => $userId, 'channel' => $channel, 'token' => $this->unsubscribeToken($userId, $channel)]);
    }

    /**
     * The unsubscribe link's handler. Inputs: HTTP method and the link's user_id, channel and token. Output:
     * {status, body}. A token that is not exactly 64 characters of [0-9a-f], an unknown channel, a user id
     * that is not digits, or a token that does not match (hash_equals, which never throws on unequal lengths)
     * all get 403 {error: "invalid_unsubscribe_token"} before any user lookup. GET only returns a confirmation
     * (mail scanners follow links); POST sets channels_enabled[channel] = false; other methods 405.
     * Why: NOTIF-11 (amended 2026-11-10: an unsigned link let anyone unsubscribe anyone).
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database on POST only.
     */
    public function handleUnsubscribe(string $method, mixed $userId, mixed $channel, mixed $token): array
    {
        $refused = ['status' => 403, 'body' => ['error' => 'invalid_unsubscribe_token']];
        if (!is_string($token) || !preg_match('/^[0-9a-f]{64}$/D', $token)) {
            return $refused;
        }
        if (!is_string($channel) || !in_array($channel, self::CHANNELS, true)) {
            return $refused;
        }
        $userText = is_int($userId) ? (string)$userId : (is_string($userId) ? $userId : '');
        if (!preg_match('/^[0-9]{1,18}$/D', $userText)) {
            return $refused;
        }
        if (!hash_equals($this->unsubscribeToken($userText, $channel), $token)) {
            return $refused;
        }
        $verb = strtoupper($method);
        if ($verb === 'GET') {
            return ['status' => 200, 'body' => ['confirm' => true, 'user_id' => (int)$userText, 'channel' => $channel, 'message' => "Press the button to stop {$channel} notifications."]];
        }
        if ($verb !== 'POST') {
            return ['status' => 405, 'body' => ['error' => 'method_not_allowed']];
        }
        $this->updateUserPreferences((int)$userText, ['channels_enabled' => [$channel => false]]);
        return ['status' => 200, 'body' => ['success' => true, 'channel' => $channel, 'unsubscribed' => true]];
    }

    /** The template row, or null. Touches: the database (read). */
    private function loadTemplate(string $templateKey): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM notification_templates WHERE `key` = :key');
        $stmt->execute([':key' => $templateKey]);
        $t = $stmt->fetch(PDO::FETCH_ASSOC);
        return $t ?: null;
    }

    /**
     * Why a message to this user on this channel must be skipped: 'do_not_disturb', 'channel_disabled'
     * (switched off or unsubscribed; a channel the map does not list counts as off) or null to send.
     * Shared by the immediate send and deliverDue (which re-checks at delivery time, NOTIF-12).
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private function skipReason(array $pref, string $channel): ?string
    {
        if ($pref['do_not_disturb']) {
            return 'do_not_disturb';
        }
        if (!in_array($channel, self::CHANNELS, true) || empty($pref['channels_enabled'][$channel])) {
            return 'channel_disabled';
        }
        return null;
    }

    /**
     * The next quiet_hours_end (UTC) when $now is inside the user's quiet hours, else null. Quiet hours may
     * wrap midnight (22:00-07:00). Why: amended spec (queue with scheduled_at = quiet_hours_end).
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private function quietHoursEnd(array $pref, \DateTimeImmutable $now): ?\DateTimeImmutable
    {
        $start = $pref['quiet_hours_start'];
        $end = $pref['quiet_hours_end'];
        if (!$start || !$end || !preg_match('/^(\d{2}):(\d{2})/', (string)$start, $s) || !preg_match('/^(\d{2}):(\d{2})/', (string)$end, $e)) {
            return null;
        }
        $nowMin = (int)$now->format('H') * 60 + (int)$now->format('i');
        $startMin = (int)$s[1] * 60 + (int)$s[2];
        $endMin = (int)$e[1] * 60 + (int)$e[2];
        if ($startMin === $endMin) {
            return null;
        }
        $inQuiet = $startMin < $endMin ? ($nowMin >= $startMin && $nowMin < $endMin) : ($nowMin >= $startMin || $nowMin < $endMin);
        if (!$inQuiet) {
            return null;
        }
        $candidate = $now->setTime((int)$e[1], (int)$e[2], 0);
        return $candidate > $now ? $candidate : $candidate->modify('+1 day');
    }

    /**
     * Render and send one message, up to $maxRetries attempts with exponential backoff (1 s, 2 s through the
     * injected sleeper). Output: null on success, else the last error text. Emails carry the signed
     * unsubscribe link. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (factored out of sendNotification so
     * deliverDue uses it too). Touches: e-mail / SMS through sendEmail / sendSms.
     */
    private function dispatch(int $userId, array $template, string $channel, array $vars): ?string
    {
        $subject = $template['subject'] ? renderTemplate($template['subject'], $vars) : '';
        $bodyText = $template['body_text'] ? renderTemplate($template['body_text'], $vars) : '';
        $bodyHtml = $template['body_html'] ? renderTemplate($template['body_html'], $vars) : '';
        $errorMsg = null;
        for ($attempt = 1; $attempt <= $this->maxRetries; $attempt++) {
            try {
                switch ($channel) {
                    case 'email':
                        $this->sendEmail($userId, $subject, $bodyText, $bodyHtml);
                        break;
                    case 'sms':
                        $this->sendSms($userId, $bodyText);
                        break;
                    case 'in_app':
                        break; // the stored log row is the in-app message
                    default:
                        throw new Exception('Unsupported channel');
                }
                return null;
            } catch (Exception $e) {
                $errorMsg = $e->getMessage();
                if ($attempt < $this->maxRetries) {
                    ($this->sleeper)((int)pow(2, $attempt - 1) * 1000000);
                }
            }
        }
        return $errorMsg;
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
     * Internal: send email via PHP's mail() (placeholder for real SMTP). The body ends with the signed
     * unsubscribe link (changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the old link carried only the
     * user id and the subject, so anyone could unsubscribe anyone). Touches: e-mail (not in test mode).
     */
    protected function sendEmail(int $userId, string $subject, string $textBody, string $htmlBody): void
    {
        // Retrieve user email from a hypothetical users table (not defined). For demo, use placeholder.
        $to = "user{$userId}@example.com";
        $headers = "From: no-reply@example.com\r\n";
        $headers .= "MIME-Version: 1.0\r\n";
        $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
        $unsubscribeLink = $this->unsubscribeUrl($userId, 'email');
        $message = ($htmlBody ?: nl2br(htmlspecialchars($textBody)))
            . '<br><br><a href="' . htmlspecialchars($unsubscribeLink, ENT_QUOTES) . '">Unsubscribe</a>';

        $this->lastEmailData = [
            'to' => $to,
            'subject' => $subject,
            'message' => $message,
            'headers' => $headers,
            'unsubscribe_url' => $unsubscribeLink,
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

    /**
     * GET /users/:user_id/notification-preferences. $callerUserId is the verified session user (never a
     * request field); another user's preferences are 403. Why: identity from the verified caller (common
     * rules). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function endpointGetPreferences(int $callerUserId, int $userId): array
    {
        if ($callerUserId !== $userId) {
            return ['error' => 'forbidden', 'code' => 403];
        }
        return $this->getUserPreferences($userId);
    }

    /**
     * PUT /users/:user_id/notification-preferences, for the verified caller's own preferences only (403
     * otherwise). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function endpointUpdatePreferences(int $callerUserId, int $userId, array $payload): array
    {
        if ($callerUserId !== $userId) {
            return ['error' => 'forbidden', 'code' => 403];
        }
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

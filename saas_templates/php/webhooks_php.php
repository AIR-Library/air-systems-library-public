<?php
// Repaired 2026-11-03: events go only to the sending organization's endpoints (they went to every organization's),
//   the event type is a bound parameter (it was pasted into the SQL), and deliver() takes an
//   optional sender so it can be tested without the network.
// Why: the suite failed on CI (it was listed in ci/baseline.json). Reviewed by Claude; fixed by a free model from a continuity handoff, session c6ee9a72 (2026-11-03).
// Touches: the database, outgoing HTTPS (curl).
// Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): injectable clock, exact event-type match (no LIKE
//   wildcards), digits-only timestamps in verify(), pending deliveries tie-broken by insertion order.

declare(strict_types=1);

namespace Webhooks;

use PDO;
use RuntimeException;
use InvalidArgumentException;

/**
 * Webhooks - Signed Outbound Delivery (Standard Webhooks spec)
 */
final class Webhooks
{
    private PDO $db;
    /** @var \Closure(): int */
    private \Closure $clock;
    private const SECRET_PREFIX = 'whsec_';
    private const SECRET_BYTES_MIN = 24;
    private const SECRET_BYTES_MAX = 64;
    private const MAX_FAILURES_BEFORE_DISABLE = 5;
    public const RETRY_SCHEDULE = [5, 300, 1800, 7200, 18000, 36000, 36000]; // seconds

    /**
     * Build the service on a PDO connection.
     *
     * Inputs: $db (shared connection; error mode set to exceptions), $clock (optional; returns unix seconds,
     * default time()). Output: none.
     * Why: the common rules require an injectable clock where the spec involves time (retry schedule,
     * delivered_at). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database connection settings.
     */
    public function __construct(PDO $db, ?\Closure $clock = null)
    {
        $this->db = $db;
        $this->clock = $clock ?? static fn(): int => time();
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    /**
     * Initialize database schema
     */
    public function migrate(): void
    {
        $sql = <<<SQL
CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    event_types TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    failure_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS webhook_messages (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 1,
    status_code INTEGER,
    success INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    next_attempt_at INTEGER,
    delivered_at INTEGER,
    FOREIGN KEY (message_id) REFERENCES webhook_messages(id),
    FOREIGN KEY (endpoint_id) REFERENCES webhook_endpoints(id)
);

CREATE INDEX IF NOT EXISTS idx_deliveries_pending ON webhook_deliveries(next_attempt_at) WHERE success = 0 AND next_attempt_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_endpoints_org ON webhook_endpoints(org_id);
CREATE INDEX IF NOT EXISTS idx_messages_event ON webhook_messages(event_type);
CREATE INDEX IF NOT EXISTS idx_messages_org ON webhook_messages(org_id);
SQL;
        $this->db->exec($sql);
    }

    /**
     * Create a new webhook endpoint
     * @return array{id: string, secret: string}
     */
    public function createEndpoint(string $orgId, string $url, array $eventTypes): array
    {
        if (!preg_match('#^https://#', $url) && !preg_match('#^http://localhost#', $url)) {
            throw new InvalidArgumentException('URL must be https:// (http://localhost allowed for dev)');
        }
        if (empty($eventTypes)) {
            throw new InvalidArgumentException('event_types cannot be empty');
        }

        $id = 'wep_' . bin2hex(random_bytes(16));
        $secret = self::SECRET_PREFIX . base64_encode(random_bytes(32));
        $now = ($this->clock)();

        $stmt = $this->db->prepare(
            'INSERT INTO webhook_endpoints (id, org_id, url, secret, event_types, active, failure_count, created_at)
             VALUES (?, ?, ?, ?, ?, 1, 0, ?)'
        );
        $stmt->execute([$id, $orgId, $url, $secret, json_encode($eventTypes), $now]);

        return ['id' => $id, 'secret' => $secret];
    }

    /**
     * Send an event to all subscribed endpoints of the given org.
     *
     * Inputs: $orgId (the verified caller's org), $eventType, $payload. Output: the new message id "msg_...".
     * Creates one webhook_messages row and one pending delivery per ACTIVE endpoint of THAT org whose
     * event_types JSON array contains $eventType exactly (json_each equality, so "%" or "_" in an event type
     * are not LIKE wildcards). Why: HOOK-06; the LIKE match let "user.%" reach every "user.*" endpoint
     * (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: the database (one transaction).
     */
    public function sendEvent(string $orgId, string $eventType, array $payload): string
    {
        $messageId = 'msg_' . bin2hex(random_bytes(16));
        $now = ($this->clock)();
        $payloadJson = json_encode($payload, JSON_THROW_ON_ERROR);

        $this->db->beginTransaction();
        try {
            $stmt = $this->db->prepare(
                'INSERT INTO webhook_messages (id, org_id, event_type, payload, created_at) VALUES (?, ?, ?, ?, ?)'
            );
            $stmt->execute([$messageId, $orgId, $eventType, $payloadJson, $now]);

            $endpoints = $this->db->prepare(
                "SELECT id FROM webhook_endpoints
                 WHERE active = 1
                 AND org_id = ?
                 AND EXISTS (SELECT 1 FROM json_each(webhook_endpoints.event_types) je WHERE je.value = ?)
                 ORDER BY rowid"
            );
            $endpoints->execute([$orgId, $eventType]);
            $endpointIds = $endpoints->fetchAll(PDO::FETCH_COLUMN);

            $deliveryStmt = $this->db->prepare(
                'INSERT INTO webhook_deliveries (id, message_id, endpoint_id, attempt, next_attempt_at)
                 VALUES (?, ?, ?, 1, ?)'
            );
            foreach ($endpointIds as $endpointId) {
                $deliveryId = 'dlv_' . bin2hex(random_bytes(16));
                $deliveryStmt->execute([$deliveryId, $messageId, $endpointId, $now]);
            }

            $this->db->commit();
        } catch (\Throwable $e) {
            $this->db->rollBack();
            throw $e;
        }

        return $messageId;
    }

    /**
     * Generate signature for a message
     */
    public static function sign(string $secret, string $msgId, int $timestamp, string $body): string
    {
        $key = base64_decode(substr($secret, strlen(self::SECRET_PREFIX)), true);
        if ($key === false) {
            throw new InvalidArgumentException('Invalid secret format');
        }
        $signedContent = $msgId . '.' . $timestamp . '.' . $body;
        $signature = hash_hmac('sha256', $signedContent, $key, true);
        return 'v1,' . base64_encode($signature);
    }

    /**
     * Deliver a single webhook delivery.
     *
     * Inputs: $delivery (a row with id and attempt), $sender (injectable fn(url, headers, body): int status;
     * null uses curl). Output: {success, status_code, error}. 200-299 marks success; any other status, a
     * thrown sender or a timeout records the status and schedules the next attempt from RETRY_SCHEDULE;
     * the webhook-id header is always the message id, so it is the same on every retry (HOOK-05, HOOK-07).
     * Time comes from the injected clock (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
     * Touches: the database, outgoing HTTPS when no sender is given.
     * @param ?callable $sender Function(string $url, array $headers, string $body): int
     * @return array{success: bool, status_code: int|null, error: string|null}
     */
    public function deliver(array $delivery, ?callable $sender = null): array
    {
        $stmt = $this->db->prepare(
            'SELECT wm.id as msg_id, wm.payload, wm.created_at, we.url, we.secret, we.id as endpoint_id
             FROM webhook_deliveries wd
             JOIN webhook_messages wm ON wd.message_id = wm.id
             JOIN webhook_endpoints we ON wd.endpoint_id = we.id
             WHERE wd.id = ?'
        );
        $stmt->execute([$delivery['id']]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            throw new RuntimeException('Delivery not found');
        }

        $timestamp = ($this->clock)();
        $signature = self::sign($row['secret'], $row['msg_id'], $timestamp, $row['payload']);

        $headers = [
            'Content-Type: application/json',
            'webhook-id: ' . $row['msg_id'],
            'webhook-timestamp: ' . $timestamp,
            'webhook-signature: ' . $signature,
        ];

        $statusCode = 0;
        $curlError = '';
        $success = false;

        if ($sender !== null) {
            try {
                $statusCode = $sender($row['url'], $headers, $row['payload']);
                $success = $statusCode >= 200 && $statusCode < 300;
                $curlError = $success ? '' : "HTTP $statusCode";
            } catch (\Throwable $e) {
                $success = false;
                $statusCode = 0;
                $curlError = $e->getMessage();
            }
        } else {
            $ch = curl_init($row['url']);
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $row['payload'],
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 10,
                CURLOPT_SSL_VERIFYPEER => true,
            ]);

            $response = curl_exec($ch);
            $statusCode = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $curlError = curl_error($ch);
            curl_close($ch);

            $success = $statusCode >= 200 && $statusCode < 300 && $curlError === '';
            $curlError = $success ? null : ($curlError ?: "HTTP $statusCode");
        }

        $now = ($this->clock)();

        $this->db->beginTransaction();
        try {
            if ($success) {
                $this->db->prepare(
                    'UPDATE webhook_deliveries SET success = 1, status_code = ?, delivered_at = ?, error = NULL, next_attempt_at = NULL WHERE id = ?'
                )->execute([$statusCode, $now, $delivery['id']]);
                $this->db->prepare(
                    'UPDATE webhook_endpoints SET failure_count = 0 WHERE id = ?'
                )->execute([$row['endpoint_id']]);
            } else {
                // Attempt n failed: the next one (n + 1) waits RETRY_SCHEDULE[n - 1], so the first retry is
                // after 5 s (spec: 5s, 5m, 30m, 2h, 5h, 10h, 10h). It used RETRY_SCHEDULE[n] and skipped the 5 s
                // step (fixed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
                $failedAttempt = (int)$delivery['attempt'];
                $attempt = $failedAttempt + 1;
                $nextAttempt = null;
                if ($failedAttempt >= 1 && $failedAttempt <= count(self::RETRY_SCHEDULE)) {
                    $nextAttempt = $now + self::RETRY_SCHEDULE[$failedAttempt - 1];
                }
                $this->db->prepare(
                    'UPDATE webhook_deliveries SET attempt = ?, status_code = ?, error = ?, next_attempt_at = ? WHERE id = ?'
                )->execute([$attempt, $statusCode, $curlError, $nextAttempt, $delivery['id']]);

                if ($nextAttempt === null) {
                    $this->recordEndpointFailure($row['endpoint_id']);
                }
            }
            $this->db->commit();
        } catch (\Throwable $e) {
            $this->db->rollBack();
            throw $e;
        }

        return ['success' => $success, 'status_code' => $statusCode, 'error' => $curlError];
    }

    /**
     * Record a delivery exhaustion for an endpoint (increment failure count, disable if threshold reached)
     */
    public function recordEndpointFailure(string $endpointId): void
    {
        $this->db->prepare(
            'UPDATE webhook_endpoints SET failure_count = failure_count + 1 WHERE id = ?'
        )->execute([$endpointId]);

        $epStmt = $this->db->prepare('SELECT failure_count, active FROM webhook_endpoints WHERE id = ?');
        $epStmt->execute([$endpointId]);
        $row = $epStmt->fetch(PDO::FETCH_ASSOC);
        if ($row && $row['failure_count'] >= self::MAX_FAILURES_BEFORE_DISABLE && $row['active'] == 1) {
            $this->db->prepare('UPDATE webhook_endpoints SET active = 0 WHERE id = ?')
                ->execute([$endpointId]);
        }
    }

    /**
     * Verify a webhook signature (receiver side).
     *
     * Inputs: $secret ("whsec_..."), $headers (webhook-id, webhook-timestamp, webhook-signature), the raw body,
     * $toleranceSeconds (default 300) and $now (optional unix seconds, default time(), so tests are
     * deterministic). Output: true, or an error string. The timestamp must be all digits and within the
     * tolerance; every space-separated "v1,<sig>" is compared in constant time (hash_equals).
     * Why: HOOK-01..04; $now added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     * @return true|string true on success, error message on failure
     */
    public static function verify(string $secret, array $headers, string $rawBody, int $toleranceSeconds = 300, ?int $now = null): bool|string
    {
        $msgId = $headers['webhook-id'] ?? '';
        $timestampHeader = $headers['webhook-timestamp'] ?? '';
        $signatureHeader = $headers['webhook-signature'] ?? '';

        if (!$msgId || !$timestampHeader || !$signatureHeader) {
            return 'Missing required headers';
        }

        if (!preg_match('/^\d{1,12}$/', (string)$timestampHeader)) {
            return 'Invalid timestamp';
        }
        $timestamp = (int)$timestampHeader;
        $now = $now ?? time();
        if (abs($now - $timestamp) > $toleranceSeconds) {
            return 'Timestamp outside tolerance';
        }

        $signatures = array_map('trim', explode(' ', $signatureHeader));
        $expected = self::sign($secret, $msgId, $timestamp, $rawBody);

        foreach ($signatures as $sig) {
            if (hash_equals($expected, $sig)) {
                return true;
            }
        }

        return 'No matching signature';
    }

    /**
     * Rotate the secret for an endpoint
     */
    public function rotateSecret(string $endpointId): string
    {
        $newSecret = self::SECRET_PREFIX . base64_encode(random_bytes(32));
        $stmt = $this->db->prepare('UPDATE webhook_endpoints SET secret = ? WHERE id = ?');
        $stmt->execute([$newSecret, $endpointId]);
        if ($stmt->rowCount() === 0) {
            throw new RuntimeException('Endpoint not found');
        }
        return $newSecret;
    }

    /**
     * Get pending deliveries ready for retry, oldest due first, ties in insertion order (tie-break and the
     * injected clock added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: the database (read).
     * @return array<int, array{id: string, message_id: string, endpoint_id: string, attempt: int}>
     */
    public function getPendingDeliveries(int $limit = 100): array
    {
        $now = ($this->clock)();
        $stmt = $this->db->prepare(
            'SELECT id, message_id, endpoint_id, attempt
             FROM webhook_deliveries
             WHERE success = 0 AND next_attempt_at IS NOT NULL AND next_attempt_at <= ?
             ORDER BY next_attempt_at ASC, rowid ASC
             LIMIT ?'
        );
        $stmt->execute([$now, $limit]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}

/**
 * Convenience function for receiver-side verification from raw $_SERVER/$_POST
 */
function verify_webhook(string $secret, string $rawBody, array $serverHeaders = [], int $tolerance = 300): bool|string
{
    $headers = [];
    foreach ($serverHeaders as $key => $value) {
        $lower = strtolower($key);
        if ($lower === 'http_webhook_id') $headers['webhook-id'] = $value;
        elseif ($lower === 'http_webhook_timestamp') $headers['webhook-timestamp'] = $value;
        elseif ($lower === 'http_webhook_signature') $headers['webhook-signature'] = $value;
    }
    return Webhooks::verify($secret, $headers, $rawBody, $tolerance);
}

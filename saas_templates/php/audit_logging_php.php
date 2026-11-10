<?php
// Repaired 2026-11-03: audit rows are append-only: they can no longer be edited or deleted.
// Why: the suite failed on CI (it was listed in ci/baseline.json). Reviewed by Claude; fixed by a free model from a continuity handoff, session c6ee9a72 (2026-11-03).
// Rebuilt 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, for the amended spec (AUDIT-08/09/10; docs/specs/audit_logging.md,
//   amended after review on PR 19 and an independent security review):
//   - audit_log keeps events only. For an entry with a data subject, resource_id, old_value, new_value and
//     why_chain_id live in its 'subject' row of audit_personal; the acting user's id, ip, user_agent and request_id
//     live in its 'actor' row. Both point at audit_subjects by a RANDOM subject_ref, so deleting that row and the
//     personal rows leaves nothing in the log that leads back to the person. (actor_id, ip and the snapshots were
//     columns of audit_log, and metadata accepted anything, so an IP outlived any erasure.)
//   - logMutation() requires subject_user_id (a user id or 'none') for every resource_type except 'user', allows only
//     the metadata keys feature_flag / erased_rows, requires actor_user_id for an api_key actor, and writes the
//     subject, the entry and its personal rows in ONE transaction.
//   - eraseSubject() and applyRetention() delete personal and subject rows only, never an audit_log row;
//     eraseSubject() adds exactly one 'audit_subject_erased' entry.
//   - Reads (query, replay, search) are for admins only (403 otherwise) and show personal_erased after erasure.
//   - Time comes from an injectable clock; ties are broken by insertion order (rowid); '_' in a wildcard is literal.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, one answer in every language): logMutation() refuses
//   a 'user' actor without actor_id (actor_required) and a 'service' actor without actor_service
//   (actor_service_required; it fell back to actor_id); replay() always says whether the entry's subject row is
//   erased; AuditLogger implements Compliance\AuditEraser (data_export_compliance), so the deletion cascade takes the
//   logger as it is, with no adapter. The interface is declared below in its own namespace block, so the rest of
//   this file sits in the global namespace block.
// Touches: the database only.
declare(strict_types=1);

namespace Compliance {
    if (!\interface_exists(AuditEraser::class, false)) {
        /**
         * The audit system's erasure entry point as data_export_compliance_php.php declares it: erase_subject(user_id)
         * -> {erased_rows: int}. Declared here too, identically, so AuditLogger can implement it whichever file loads
         * first; keep the two declarations the same.
         * Why: Phase B.2 bug "AuditLogger::eraseSubject returns an array while the AuditEraser interface returns void;
         * make the two fit without an adapter". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing by itself.
         */
        interface AuditEraser
        {
            /**
             * Erase the personal audit data of $userId. Output: {erased_rows: int}. Throws on failure.
             * Touches: the audit system's tables.
             */
            public function eraseSubject(int|string $userId): array;
        }
    }
}

namespace {

/**
 * A refused audit call: HTTP-style status and error code (400 subject_required, subject_mismatch,
 * metadata_key_not_allowed, actor_user_required, actor_required, actor_service_required, invalid_actor_type;
 * 403 admin_only; 404 log_not_found). actor_required and actor_service_required are 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2).
 * Why: AUDIT-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
final class AuditException extends RuntimeException
{
    public function __construct(public readonly int $status, public readonly string $errorCode, string $message = '')
    {
        parent::__construct($message !== '' ? $message : $errorCode, $status);
    }
}

/**
 * The audit log (audit_logging.md): append-only events, personal data beside them, erasure and retention, admin
 * reads. Implements Compliance\AuditEraser, so data_export_compliance's deletion cascade calls eraseSubject() on it
 * directly (since 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, Phase B.2). Touches: the database only.
 */
class AuditLogger implements \Compliance\AuditEraser
{
    public const ACTOR_TYPES = ['user', 'service', 'api_key'];
    public const ALLOWED_METADATA_KEYS = ['feature_flag', 'erased_rows'];
    public const DEFAULT_RETENTION_DAYS = 365;
    private const ERASER_SERVICE = 'audit';

    private PDO $pdo;
    /** @var Closure(): DateTimeImmutable */
    private Closure $clock;
    private int $retentionDays;

    /**
     * Inputs: $pdo (one shared connection), $clock (fn(): DateTimeImmutable; default now in UTC), $retentionDays
     * (configuration for applyRetention(); default 365). Creates the tables, indexes and immutability triggers.
     * Why: injectable clock and retention (AUDIT-09). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (DDL).
     */
    public function __construct(PDO $pdo, ?Closure $clock = null, int $retentionDays = self::DEFAULT_RETENTION_DAYS)
    {
        $this->pdo = $pdo;
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->clock = $clock ?? static fn(): DateTimeImmutable => new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $this->retentionDays = $retentionDays;
        $this->initializeSchema();
    }

    /**
     * The three audit tables (spec SCHEMA), their indexes and the triggers that refuse UPDATE / DELETE on
     * audit_log and UPDATE on audit_personal. Touches: the database (DDL).
     */
    private function initializeSchema(): void
    {
        $sql = <<<SQL
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'service', 'api_key')),
    actor_service TEXT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    old_value TEXT,
    new_value TEXT,
    why_chain_id TEXT,
    personal_roles TEXT NOT NULL DEFAULT '',
    metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log (action, resource_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp);
-- Covering index for the actor_id join: id lookups that also check action / resource_type / timestamp
-- without reading the row (AUDIT-05's 100 ms budget at 1M rows).
CREATE INDEX IF NOT EXISTS idx_audit_log_id_filters ON audit_log (id, action, resource_type, timestamp);
CREATE TABLE IF NOT EXISTS audit_subjects (
    subject_ref TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_personal (
    log_id TEXT NOT NULL REFERENCES audit_log (id),
    subject_ref TEXT NOT NULL REFERENCES audit_subjects (subject_ref),
    role TEXT NOT NULL CHECK (role IN ('actor', 'subject')),
    data TEXT NOT NULL,
    PRIMARY KEY (log_id, role)
);
CREATE INDEX IF NOT EXISTS idx_audit_personal_subject ON audit_personal (subject_ref, role, log_id);
CREATE TRIGGER IF NOT EXISTS prevent_audit_log_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'Audit log is immutable'); END;
CREATE TRIGGER IF NOT EXISTS prevent_audit_log_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'Audit log is immutable'); END;
CREATE TRIGGER IF NOT EXISTS prevent_audit_personal_update BEFORE UPDATE ON audit_personal
BEGIN SELECT RAISE(ABORT, 'Audit personal rows are immutable'); END;
SQL;
        $this->pdo->exec($sql);
    }

    /** Fixed-width UTC ISO 8601 with microseconds, so stored times compare as text. Touches: nothing. */
    private static function iso(DateTimeImmutable $t): string
    {
        return $t->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.u\Z');
    }

    /** A random UUID v4 (log ids). Touches: nothing. */
    private function generateUuid(): string
    {
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    /** Run $work in a transaction, or inside the caller's if one is open. Touches: the database. */
    private function inTransaction(callable $work): mixed
    {
        if ($this->pdo->inTransaction()) {
            return $work();
        }
        $this->pdo->beginTransaction();
        try {
            $result = $work();
            $this->pdo->commit();
            return $result;
        } catch (Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /**
     * Find or create the user's subject_ref (insert-if-absent on user_id): 128 random bits, never derived
     * from the user id. Called inside the caller's transaction. Touches: audit_subjects.
     */
    private function subjectRef(string $userId, string $now): string
    {
        $this->pdo->prepare('INSERT OR IGNORE INTO audit_subjects (subject_ref, user_id, created_at) VALUES (?, ?, ?)')
            ->execute([bin2hex(random_bytes(16)), $userId, $now]);
        $stmt = $this->pdo->prepare('SELECT subject_ref FROM audit_subjects WHERE user_id = ?');
        $stmt->execute([$userId]);
        return (string)$stmt->fetchColumn();
    }

    /**
     * POST /audit/log: an internal, service-authenticated call; actor_id is the verified caller's.
     *
     * Input keys: actor_id, actor_type ('user'|'service'|'api_key'), actor_user_id (an api key's owner),
     * actor_service (a service's name; default actor_id), action, resource_type, resource_id, old_value,
     * new_value, why_chain_id, metadata (only feature_flag / erased_rows), subject_user_id (required unless
     * resource_type is 'user': a user id or 'none'), ip, user_agent, request_id.
     * Output: {success: true, log_id}. Throws AuditException 400: invalid_actor_type, metadata_key_not_allowed,
     * subject_required, subject_mismatch, actor_required ('user' without actor_id), actor_service_required
     * ('service' without actor_service), actor_user_required ('api_key' without actor_user_id).
     * Writes in ONE transaction: the subject(s), the audit_log event (resource fields only when the subject is
     * 'none'), the 'subject' row {resource_id, old_value, new_value, why_chain_id} and the 'actor' row
     * {actor_id, ip, user_agent, request_id} (user / api_key actors).
     * Why: AUDIT-01/10 as amended 2026-11-10 (personal data beside the log so it can be erased).
     * session_012zDydZCZ4AChqhEZ4oVtaP. The same day (Phase B.2) a 'user' actor without actor_id became actor_required
     * (it was actor_user_required) and a 'service' actor must name actor_service (it fell back to actor_id).
     * Touches: the database.
     */
    public function logMutation(array $data): array
    {
        $actorType = $data['actor_type'] ?? null;
        if (!in_array($actorType, self::ACTOR_TYPES, true)) {
            throw new AuditException(400, 'invalid_actor_type', 'actor_type must be user, service or api_key');
        }
        $metadata = $data['metadata'] ?? [];
        if (!is_array($metadata)) {
            throw new AuditException(400, 'metadata_key_not_allowed', 'metadata must be an object');
        }
        $badKeys = array_diff(array_map('strval', array_keys($metadata)), self::ALLOWED_METADATA_KEYS);
        if ($badKeys !== []) {
            throw new AuditException(400, 'metadata_key_not_allowed', 'metadata keys not allowed: ' . implode(', ', $badKeys));
        }
        $resourceType = (string)($data['resource_type'] ?? '');
        $resourceId = $data['resource_id'] ?? null;
        $subjectUserId = $data['subject_user_id'] ?? null;
        if ($resourceType === 'user') {
            if ($resourceId === null || (string)$resourceId === '') {
                throw new AuditException(400, 'subject_required', "a 'user' entry needs its resource_id");
            }
            $subject = (string)$resourceId;
            if ($subjectUserId !== null && (string)$subjectUserId !== $subject) {
                throw new AuditException(400, 'subject_mismatch', 'subject_user_id differs from the user resource_id');
            }
        } else {
            if ($subjectUserId === null || (string)$subjectUserId === '') {
                throw new AuditException(400, 'subject_required', "subject_user_id (a user id or 'none') is required");
            }
            $subject = (string)$subjectUserId === 'none' ? null : (string)$subjectUserId;
        }
        $actorId = $data['actor_id'] ?? null;
        $actorOwner = null;
        if ($actorType === 'user') {
            if ($actorId === null || (string)$actorId === '') {
                throw new AuditException(400, 'actor_required', 'a user actor needs actor_id');
            }
            $actorOwner = (string)$actorId;
        } elseif ($actorType === 'api_key') {
            $owner = $data['actor_user_id'] ?? null;
            if ($owner === null || (string)$owner === '') {
                throw new AuditException(400, 'actor_user_required', "an api_key entry needs actor_user_id (the key's owner)");
            }
            $actorOwner = (string)$owner;
        }
        $serviceName = null;
        if ($actorType === 'service') {
            $serviceName = (string)($data['actor_service'] ?? '');
            if ($serviceName === '') {
                throw new AuditException(400, 'actor_service_required', "a service actor needs actor_service (the service's name)");
            }
        }

        $logId = $this->generateUuid();
        $now = self::iso(($this->clock)());
        $roles = [];
        if ($actorOwner !== null) {
            $roles[] = 'actor';
        }
        if ($subject !== null) {
            $roles[] = 'subject';
        }
        $oldValue = $data['old_value'] ?? null;
        $newValue = $data['new_value'] ?? null;
        $whyChain = $data['why_chain_id'] ?? null;
        $inLog = $subject === null; // resource fields stay in audit_log only for an entry with no data subject
        $subjectData = [
            'resource_id' => $resourceId === null ? null : (string)$resourceId,
            'old_value' => $oldValue,
            'new_value' => $newValue,
            'why_chain_id' => $whyChain,
        ];
        ksort($metadata);

        $this->inTransaction(function () use ($logId, $now, $actorType, $serviceName, $data, $resourceType, $inLog, $subjectData, $oldValue, $newValue, $whyChain, $roles, $metadata, $actorOwner, $actorId, $subject): void {
            $this->pdo->prepare(
                'INSERT INTO audit_log (id, timestamp, actor_type, actor_service, action, resource_type, resource_id, old_value, new_value, why_chain_id, personal_roles, metadata)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
            )->execute([
                $logId, $now, $actorType, $serviceName, (string)$data['action'], $resourceType,
                $inLog ? $subjectData['resource_id'] : null,
                $inLog && $oldValue !== null ? json_encode($oldValue) : null,
                $inLog && $newValue !== null ? json_encode($newValue) : null,
                $inLog ? $whyChain : null,
                implode(',', $roles),
                json_encode((object)$metadata),
            ]);
            $personal = $this->pdo->prepare('INSERT INTO audit_personal (log_id, subject_ref, role, data) VALUES (?, ?, ?, ?)');
            if ($actorOwner !== null) {
                $personal->execute([$logId, $this->subjectRef($actorOwner, $now), 'actor', json_encode([
                    'actor_id' => $actorId === null ? null : (string)$actorId,
                    'ip' => $data['ip'] ?? null,
                    'user_agent' => $data['user_agent'] ?? null,
                    'request_id' => $data['request_id'] ?? null,
                ])]);
            }
            if ($subject !== null) {
                $personal->execute([$logId, $this->subjectRef($subject, $now), 'subject', json_encode($subjectData)]);
            }
        });
        return ['success' => true, 'log_id' => $logId];
    }

    /**
     * Erase a data subject: delete every audit_personal row with the user's subject_ref, then the
     * audit_subjects row, in one transaction, and add exactly one 'audit_subject_erased' entry (actor_type
     * 'service', resource_type 'user', no resource_id, personal_roles '', metadata {erased_rows}). No audit_log
     * row is updated or deleted. Input: user id. Output: {erased_rows}.
     * Why: AUDIT-08 (amended 2026-11-10); data_export_compliance calls it LAST in its cascade.
     * session_012zDydZCZ4AChqhEZ4oVtaP. It implements Compliance\AuditEraser::eraseSubject() since the same day
     * (Phase B.2), so the cascade calls it with no adapter; erased_rows = the audit_personal rows deleted.
     * Touches: the database.
     */
    public function eraseSubject(int|string $userId): array
    {
        return $this->inTransaction(function () use ($userId): array {
            $stmt = $this->pdo->prepare('SELECT subject_ref FROM audit_subjects WHERE user_id = ?');
            $stmt->execute([(string)$userId]);
            $ref = $stmt->fetchColumn();
            $erased = 0;
            if ($ref !== false) {
                $del = $this->pdo->prepare('DELETE FROM audit_personal WHERE subject_ref = ?');
                $del->execute([$ref]);
                $erased = $del->rowCount();
                $this->pdo->prepare('DELETE FROM audit_subjects WHERE subject_ref = ?')->execute([$ref]);
            }
            $this->pdo->prepare(
                "INSERT INTO audit_log (id, timestamp, actor_type, actor_service, action, resource_type, resource_id, old_value, new_value, why_chain_id, personal_roles, metadata)
                 VALUES (?, ?, 'service', ?, 'audit_subject_erased', 'user', NULL, NULL, NULL, NULL, '', ?)"
            )->execute([$this->generateUuid(), self::iso(($this->clock)()), self::ERASER_SERVICE, json_encode(['erased_rows' => $erased])]);
            return ['erased_rows' => $erased];
        });
    }

    /**
     * Erase the personal data of entries older than the retention period, and any audit_subjects row left with
     * no personal rows. audit_log rows stay. Input: now (default the clock). Output: {erased_rows}.
     * Why: AUDIT-09 (amended 2026-11-10). session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function applyRetention(?DateTimeImmutable $now = null): array
    {
        $cutoff = self::iso(($now ?? ($this->clock)())->modify('-' . $this->retentionDays . ' days'));
        return $this->inTransaction(function () use ($cutoff): array {
            $del = $this->pdo->prepare('DELETE FROM audit_personal WHERE log_id IN (SELECT id FROM audit_log WHERE timestamp < ?)');
            $del->execute([$cutoff]);
            $this->pdo->exec('DELETE FROM audit_subjects WHERE subject_ref NOT IN (SELECT DISTINCT subject_ref FROM audit_personal)');
            return ['erased_rows' => $del->rowCount()];
        });
    }

    /** Reads are for admins only: the verified caller must carry is_admin === true. Throws 403 admin_only. */
    private function requireAdmin(?array $caller): void
    {
        if (!is_array($caller) || ($caller['is_admin'] ?? false) !== true) {
            throw new AuditException(403, 'admin_only', 'audit reads are for admins only');
        }
    }

    /** Escape LIKE wildcards (\, %, _) for use with ESCAPE '\'. Touches: nothing. */
    private static function likeEscape(string $text): string
    {
        return str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $text);
    }

    /**
     * Turn audit_log rows into the read shape, joining their personal rows; an entry whose declared personal
     * rows are gone shows those fields as null and personal_erased true. Touches: the database (read).
     */
    private function present(array $rows): array
    {
        $personal = [];
        foreach (array_chunk(array_column($rows, 'id'), 500) as $chunk) {
            $stmt = $this->pdo->prepare('SELECT log_id, role, data FROM audit_personal WHERE log_id IN (' . implode(',', array_fill(0, count($chunk), '?')) . ')');
            $stmt->execute($chunk);
            foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $p) {
                $personal[$p['log_id'] . '|' . $p['role']] = json_decode($p['data'], true);
            }
        }
        $out = [];
        foreach ($rows as $row) {
            $roles = array_values(array_filter(explode(',', (string)$row['personal_roles'])));
            $actor = $personal[$row['id'] . '|actor'] ?? null;
            $subject = $personal[$row['id'] . '|subject'] ?? null;
            $erased = false;
            foreach ($roles as $role) {
                if (!isset($personal[$row['id'] . '|' . $role])) {
                    $erased = true;
                }
            }
            if (in_array('subject', $roles, true)) {
                $resource = $subject ?? ['resource_id' => null, 'old_value' => null, 'new_value' => null, 'why_chain_id' => null];
            } else {
                $resource = [
                    'resource_id' => $row['resource_id'],
                    'old_value' => $row['old_value'] !== null ? json_decode($row['old_value'], true) : null,
                    'new_value' => $row['new_value'] !== null ? json_decode($row['new_value'], true) : null,
                    'why_chain_id' => $row['why_chain_id'],
                ];
            }
            $out[] = [
                'id' => $row['id'],
                'timestamp' => $row['timestamp'],
                'actor_id' => $actor['actor_id'] ?? ($row['actor_type'] === 'service' ? $row['actor_service'] : null),
                'actor_type' => $row['actor_type'],
                'actor_service' => $row['actor_service'],
                'ip' => $actor['ip'] ?? null,
                'user_agent' => $actor['user_agent'] ?? null,
                'request_id' => $actor['request_id'] ?? null,
                'action' => $row['action'],
                'resource_type' => $row['resource_type'],
                'resource_id' => $resource['resource_id'],
                'old_value' => $resource['old_value'],
                'new_value' => $resource['new_value'],
                'why_chain_id' => $resource['why_chain_id'],
                'metadata' => json_decode((string)$row['metadata'], true) ?: [],
                'personal_erased' => $erased,
            ];
        }
        return $out;
    }

    /**
     * GET /audit/logs (admins only; AuditException 403 otherwise).
     *
     * Inputs: $filters {actor_id, action (with '*' wildcards), resource_type, date_from, date_to, limit (100),
     * offset (0)} and the verified $caller {is_admin}. Output: {logs, total, has_more}, newest first, ties in
     * reverse insertion order. actor_id resolves through audit_subjects and the 'actor' rows of audit_personal,
     * so an erased actor matches nothing; a service actor matches by its name. '_' and '%' in a pattern are
     * literal. Why: AUDIT-03/04/07/08/10 as amended. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (read).
     */
    public function queryLogs(array $filters, ?array $caller = null): array
    {
        $this->requireAdmin($caller);
        $from = 'audit_log l';
        $where = [];
        $params = [];
        if (isset($filters['actor_id'])) {
            $stmt = $this->pdo->prepare('SELECT subject_ref FROM audit_subjects WHERE user_id = ?');
            $stmt->execute([(string)$filters['actor_id']]);
            $ref = $stmt->fetchColumn();
            if ($ref !== false) {
                // CROSS JOIN fixes SQLite's join order: start from the actor's personal rows (index on
                // subject_ref, role), not from a large action range of audit_log (AUDIT-05 budget).
                $from = 'audit_personal p CROSS JOIN audit_log l ON l.id = p.log_id';
                $where[] = "p.subject_ref = ? AND p.role = 'actor'";
                $params[] = $ref;
            } else {
                $where[] = "l.actor_type = 'service' AND l.actor_service = ?";
                $params[] = (string)$filters['actor_id'];
            }
        }
        if (isset($filters['action'])) {
            $action = (string)$filters['action'];
            if (str_contains($action, '*')) {
                $where[] = "l.action LIKE ? ESCAPE '\\'";
                $params[] = str_replace('*', '%', self::likeEscape($action));
            } else {
                $where[] = 'l.action = ?';
                $params[] = $action;
            }
        }
        if (isset($filters['resource_type'])) {
            $where[] = 'l.resource_type = ?';
            $params[] = (string)$filters['resource_type'];
        }
        if (isset($filters['date_from'])) {
            $where[] = 'l.timestamp >= ?';
            $params[] = (string)$filters['date_from'];
        }
        if (isset($filters['date_to'])) {
            $where[] = 'l.timestamp <= ?';
            $params[] = (string)$filters['date_to'];
        }
        $limit = max(0, (int)($filters['limit'] ?? 100));
        $offset = max(0, (int)($filters['offset'] ?? 0));
        $whereSql = $where ? ' WHERE ' . implode(' AND ', $where) : '';

        $count = $this->pdo->prepare("SELECT COUNT(*) FROM {$from}{$whereSql}");
        $count->execute($params);
        $total = (int)$count->fetchColumn();
        // Two steps: the page's ids from the (covering) indexes, then those rows, in page order.
        $stmt = $this->pdo->prepare("SELECT l.id FROM {$from}{$whereSql} ORDER BY l.timestamp DESC, l.rowid DESC LIMIT ? OFFSET ?");
        foreach (array_values($params) as $i => $v) {
            $stmt->bindValue($i + 1, $v, PDO::PARAM_STR);
        }
        $stmt->bindValue(count($params) + 1, $limit, PDO::PARAM_INT);
        $stmt->bindValue(count($params) + 2, $offset, PDO::PARAM_INT);
        $stmt->execute();
        $ids = $stmt->fetchAll(PDO::FETCH_COLUMN);
        $rows = [];
        if ($ids !== []) {
            $fetch = $this->pdo->prepare('SELECT * FROM audit_log WHERE id IN (' . implode(',', array_fill(0, count($ids), '?')) . ')');
            $fetch->execute($ids);
            $byId = [];
            foreach ($fetch->fetchAll(PDO::FETCH_ASSOC) as $row) {
                $byId[$row['id']] = $row;
            }
            foreach ($ids as $id) {
                $rows[] = $byId[$id];
            }
        }
        $logs = $this->present($rows);
        return ['logs' => $logs, 'total' => $total, 'has_more' => ($offset + count($logs)) < $total];
    }

    /**
     * GET /audit/replay/:log_id (admins only). Output: {log_id, timestamp, resource_state_at_time (the entry's
     * old_value), has_diverged (a later entry for the same resource left a different new_value)}; for an entry
     * whose subject rows are gone: {log_id, timestamp, erased: true, resource_state_at_time: null,
     * has_diverged: null}. AuditException 404 log_not_found.
     * Why: AUDIT-02/08 as amended; divergence is read from the log itself (it compared a side table
     * 'resources' that nothing kept up to date). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (read).
     */
    public function replay(string $log_id, ?array $caller = null): array
    {
        $this->requireAdmin($caller);
        $stmt = $this->pdo->prepare('SELECT * FROM audit_log WHERE id = ?');
        $stmt->execute([$log_id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            throw new AuditException(404, 'log_not_found', 'Log not found');
        }
        $entry = $this->present([$row])[0];
        $hasSubject = in_array('subject', explode(',', (string)$row['personal_roles']), true);
        if ($hasSubject) {
            // erased reflects the entry's own subject row only (an erased actor row does not hide the snapshots).
            $subjectGone = $this->pdo->prepare("SELECT COUNT(*) FROM audit_personal WHERE log_id = ? AND role = 'subject'");
            $subjectGone->execute([$log_id]);
            if ((int)$subjectGone->fetchColumn() === 0) {
                return ['log_id' => $log_id, 'timestamp' => $row['timestamp'], 'erased' => true, 'resource_state_at_time' => null, 'has_diverged' => null];
            }
        }
        if ($hasSubject) {
            $ref = $this->pdo->prepare("SELECT subject_ref FROM audit_personal WHERE log_id = ? AND role = 'subject'");
            $ref->execute([$log_id]);
            $latest = $this->pdo->prepare(
                "SELECT l.id, p.data FROM audit_personal p JOIN audit_log l ON l.id = p.log_id
                 WHERE p.subject_ref = ? AND p.role = 'subject' AND l.resource_type = ? AND json_extract(p.data, '$.resource_id') IS ?
                 ORDER BY l.timestamp DESC, l.rowid DESC LIMIT 1"
            );
            $latest->execute([$ref->fetchColumn(), $row['resource_type'], $entry['resource_id']]);
            $last = $latest->fetch(PDO::FETCH_ASSOC);
            $latestNew = $last ? (json_decode($last['data'], true)['new_value'] ?? null) : null;
        } else {
            $latest = $this->pdo->prepare('SELECT id, new_value FROM audit_log WHERE resource_type = ? AND resource_id IS ? ORDER BY timestamp DESC, rowid DESC LIMIT 1');
            $latest->execute([$row['resource_type'], $row['resource_id']]);
            $last = $latest->fetch(PDO::FETCH_ASSOC);
            $latestNew = $last && $last['new_value'] !== null ? json_decode($last['new_value'], true) : null;
        }
        $hasDiverged = (bool)($last && $last['id'] !== $log_id && $latestNew !== $entry['new_value']);
        return ['log_id' => $log_id, 'timestamp' => $row['timestamp'], 'erased' => false, 'resource_state_at_time' => $entry['old_value'], 'has_diverged' => $hasDiverged];
    }

    /**
     * GET /audit/search (admins only): entries whose action, resource type, values or metadata contain $q
     * (literally; LIKE wildcards in $q are escaped), newest first. Output: {results} in the queryLogs() shape.
     * Values of an entry with a subject are searched in its 'subject' row, so erased data no longer matches.
     * Why: AUDIT-08/10 as amended. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read).
     */
    public function search(string $q, ?string $resource_type = null, int $limit = 50, ?array $caller = null): array
    {
        $this->requireAdmin($caller);
        $term = '%' . self::likeEscape($q) . '%';
        $sql = "SELECT l.* FROM audit_log l WHERE (l.action LIKE :q ESCAPE '\\' OR l.resource_type LIKE :q ESCAPE '\\'
                OR l.old_value LIKE :q ESCAPE '\\' OR l.new_value LIKE :q ESCAPE '\\' OR l.metadata LIKE :q ESCAPE '\\'
                OR l.id IN (SELECT log_id FROM audit_personal WHERE role = 'subject' AND data LIKE :q ESCAPE '\\'))";
        if ($resource_type !== null) {
            $sql .= ' AND l.resource_type = :rt';
        }
        $sql .= ' ORDER BY l.timestamp DESC, l.rowid DESC LIMIT :limit';
        $stmt = $this->pdo->prepare($sql);
        $stmt->bindValue(':q', $term, PDO::PARAM_STR);
        if ($resource_type !== null) {
            $stmt->bindValue(':rt', $resource_type, PDO::PARAM_STR);
        }
        $stmt->bindValue(':limit', max(0, $limit), PDO::PARAM_INT);
        $stmt->execute();
        return ['results' => $this->present($stmt->fetchAll(PDO::FETCH_ASSOC))];
    }
}
}

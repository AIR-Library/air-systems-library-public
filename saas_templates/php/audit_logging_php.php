<?php
// Repaired 2026-11-03: audit rows are append-only: they can no longer be edited or deleted.
// Why: the suite failed on CI (it was listed in ci/baseline.json). Reviewed by Claude; fixed by a free model from a continuity handoff, session c6ee9a72 (2026-11-03).
// Touches: the database only.
declare(strict_types=1);

class AuditLogger
{
    private PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
        $this->initializeSchema();
    }

    private function initializeSchema(): void
    {
        $sql = <<<SQL
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    actor_id INTEGER,
    actor_type TEXT CHECK(actor_type IN ('user','service','api_key')),
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    why_chain_id TEXT,
    metadata TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor_action_resource_timestamp
    ON audit_log(actor_id, action, resource_type, timestamp);
CREATE TABLE IF NOT EXISTS resources (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    state TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS prevent_audit_log_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'Audit log is immutable');
END;
CREATE TRIGGER IF NOT EXISTS prevent_audit_log_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'Audit log is immutable');
END;
SQL;
        $this->pdo->exec($sql);
    }

    public function logMutation(array $data): array
    {
        $id = $this->generateUuid();
        $timestamp = (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format(DateTime::ATOM);
        $stmt = $this->pdo->prepare(
            'INSERT INTO audit_log (id, timestamp, actor_id, actor_type, action, resource_type, resource_id, old_value, new_value, why_chain_id, metadata)
             VALUES (:id, :timestamp, :actor_id, :actor_type, :action, :resource_type, :resource_id, :old_value, :new_value, :why_chain_id, :metadata)'
        );
        $stmt->execute([
            ':id' => $id,
            ':timestamp' => $timestamp,
            ':actor_id' => $data['actor_id'] ?? null,
            ':actor_type' => $data['actor_type'] ?? null,
            ':action' => $data['action'],
            ':resource_type' => $data['resource_type'],
            ':resource_id' => $data['resource_id'],
            ':old_value' => json_encode($data['old_value'] ?? null),
            ':new_value' => json_encode($data['new_value'] ?? null),
            ':why_chain_id' => $data['why_chain_id'] ?? null,
            ':metadata' => json_encode($data['metadata'] ?? null),
        ]);
        return ['success' => true, 'log_id' => $id];
    }

    public function queryLogs(array $filters): array
    {
        $sql = 'SELECT id, timestamp, actor_id, action, resource_type, resource_id, old_value, new_value, why_chain_id FROM audit_log WHERE 1=1';
        $params = [];
        if (isset($filters['actor_id'])) {
            $sql .= ' AND actor_id = :actor_id';
            $params[':actor_id'] = $filters['actor_id'];
        }
        if (isset($filters['action'])) {
            $action = $filters['action'];
            if (strpos($action, '*') !== false) {
                $action = str_replace('*', '%', $action);
                $sql .= ' AND action LIKE :action';
            } else {
                $sql .= ' AND action = :action';
            }
            $params[':action'] = $action;
        }
        if (isset($filters['resource_type'])) {
            $sql .= ' AND resource_type = :resource_type';
            $params[':resource_type'] = $filters['resource_type'];
        }
        if (isset($filters['date_from'])) {
            $sql .= ' AND timestamp >= :date_from';
            $params[':date_from'] = $filters['date_from'];
        }
        if (isset($filters['date_to'])) {
            $sql .= ' AND timestamp <= :date_to';
            $params[':date_to'] = $filters['date_to'];
        }
        $sql .= ' ORDER BY timestamp DESC';
        $limit = $filters['limit'] ?? 100;
        $offset = $filters['offset'] ?? 0;
        $sql .= ' LIMIT :limit OFFSET :offset';
        $params[':limit'] = $limit;
        $params[':offset'] = $offset;

        $stmt = $this->pdo->prepare($sql);
        foreach ($params as $k => $v) {
            if ($k === ':limit' || $k === ':offset') {
                $stmt->bindValue($k, (int)$v, PDO::PARAM_INT);
            } else {
                $stmt->bindValue($k, $v, PDO::PARAM_STR);
            }
        }
        $stmt->execute();
        $logs = [];
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $row['old_value'] = json_decode($row['old_value'], true);
            $row['new_value'] = json_decode($row['new_value'], true);
            $logs[] = $row;
        }
        $countSql = 'SELECT COUNT(*) FROM audit_log WHERE 1=1';
        if (isset($filters['actor_id'])) {
            $countSql .= ' AND actor_id = :actor_id';
        }
        if (isset($filters['action'])) {
            $action = $filters['action'];
            if (strpos($action, '*') !== false) {
                $action = str_replace('*', '%', $action);
                $countSql .= ' AND action LIKE :action';
            } else {
                $countSql .= ' AND action = :action';
            }
        }
        if (isset($filters['resource_type'])) {
            $countSql .= ' AND resource_type = :resource_type';
        }
        if (isset($filters['date_from'])) {
            $countSql .= ' AND timestamp >= :date_from';
        }
        if (isset($filters['date_to'])) {
            $countSql .= ' AND timestamp <= :date_to';
        }
        $countStmt = $this->pdo->prepare($countSql);
        foreach ($params as $k => $v) {
            if ($k !== ':limit' && $k !== ':offset') {
                $countStmt->bindValue($k, $v, PDO::PARAM_STR);
            }
        }
        $countStmt->execute();
        $total = (int)$countStmt->fetchColumn();
        $has_more = ($offset + $limit) < $total;
        return ['logs' => $logs, 'total' => $total, 'has_more' => $has_more];
    }

    public function replay(string $log_id): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM audit_log WHERE id = :id');
        $stmt->execute([':id' => $log_id]);
        $log = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$log) {
            throw new InvalidArgumentException("Log not found");
        }
        $resource_id = $log['resource_id'];
        $resource_type = $log['resource_type'];
        $resourceStmt = $this->pdo->prepare('SELECT state FROM resources WHERE id = :id AND type = :type');
        $resourceStmt->execute([':id' => $resource_id, ':type' => $resource_type]);
        $resource = $resourceStmt->fetch(PDO::FETCH_ASSOC);
        $current_state = $resource ? json_decode($resource['state'], true) : null;
        $old_value = json_decode($log['old_value'], true);
        $has_diverged = $current_state !== $old_value;
        return [
            'log_id' => $log_id,
            'timestamp' => $log['timestamp'],
            'resource_state_at_time' => $old_value,
            'has_diverged' => $has_diverged,
        ];
    }

    public function search(string $q, string $resource_type, int $limit = 50): array
    {
        $sql = 'SELECT id, timestamp, actor_id, action, resource_type, resource_id, old_value, new_value, why_chain_id
                FROM audit_log
                WHERE (action LIKE :q OR resource_type LIKE :q)
                  AND resource_type = :resource_type
                ORDER BY timestamp DESC
                LIMIT :limit';
        $stmt = $this->pdo->prepare($sql);
        $like = '%' . $q . '%';
        $stmt->bindValue(':q', $like, PDO::PARAM_STR);
        $stmt->bindValue(':resource_type', $resource_type, PDO::PARAM_STR);
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        $results = [];
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $row['old_value'] = json_decode($row['old_value'], true);
            $row['new_value'] = json_decode($row['new_value'], true);
            $results[] = $row;
        }
        return ['results' => $results];
    }

    private function generateUuid(): string
    {
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }
}

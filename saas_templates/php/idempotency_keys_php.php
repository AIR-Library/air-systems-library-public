<?php
/**
 * Idempotency keys (idempotency_keys.md; IETF draft-ietf-httpapi-idempotency-key-header-07).
 *
 * What it does: makes POST/PATCH safe to retry. handle() runs an operation at most once per
 * (scope, Idempotency-Key) and serves the stored response to identical retries; release(), resolve() and
 * list_uncertain() let an operator settle a key whose first attempt ended without a known outcome.
 *
 * Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, for the amended spec (IDEM-07/08/10/11):
 *  - status gains 'uncertain'. An operation that throws OperationFailedException did nothing: its key is
 *    freed and a retry runs. ANY other error leaves the key 'uncertain': a retry gets 409 outcome_unknown and
 *    does not run until release() or resolve() settles it (it used to delete the key on every error, so a
 *    timeout after a charge let the retry charge twice).
 *  - only 'completed' records expire; an 'in_progress' record past expires_at (a killed process) is treated
 *    as 'uncertain' everywhere and a claim never replaces it (expired in_progress keys used to be reclaimed).
 *  - check order is missing key -> 400, different fingerprint -> 422 (even while in progress), in progress
 *    -> 409, uncertain -> 409 outcome_unknown, completed -> stored response (409 used to win over 422).
 *  - release() and resolve() are each ONE conditional write, so of two concurrent calls exactly one is true.
 *  - time comes from an injectable clock; the SQL store creates its own table.
 *
 * Inputs/outputs: see each function. Touches: the idempotency store (memory or a SQL database through PDO)
 * and whatever the caller's operation touches (often money). release()/resolve()/list_uncertain() are
 * operator functions: never route them to API clients.
 */

declare(strict_types=1);

/**
 * Raised by an operation to report a DEFINITE failure (it did nothing: a validation error, a provider
 * decline). handle() frees the key and re-throws it, so a retry with the same key runs again (IDEM-08).
 * Why: amended spec names this type for PHP. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
class OperationFailedException extends RuntimeException
{
}

/**
 * Storage for idempotency records. Every write is a single conditional operation so two processes cannot
 * both win. Records are arrays {scope, idem_key, request_fingerprint, status, response_status,
 * response_body, created_at, expires_at} with unix-second times.
 * Why: amended IDEM-07..11 need conditional claim/complete/release/resolve. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the backing store.
 */
interface IdempotencyStorage
{
    /** Insert an in_progress record, or replace an EXPIRED COMPLETED one; false when any other record holds the key. */
    public function claim(string $scope, string $idemKey, string $fingerprint, int $now, int $expiresAt): bool;

    /** The record, or null. No expiry filtering: the caller interprets status and expires_at. */
    public function get(string $scope, string $idemKey): ?array;

    /** in_progress -> completed with the response and a new expires_at. */
    public function complete(string $scope, string $idemKey, int $status, string $body, int $expiresAt): bool;

    /** Delete the record only while it is in_progress (OperationFailed). */
    public function deleteInProgress(string $scope, string $idemKey): bool;

    /** in_progress -> uncertain (any other error). */
    public function markUncertain(string $scope, string $idemKey): bool;

    /** Delete an uncertain record (or an in_progress one past expires_at); true only for the caller that did it. */
    public function release(string $scope, string $idemKey, int $now): bool;

    /** Uncertain (or in_progress past expires_at) -> completed with the response; true only for the caller that did it. */
    public function resolve(string $scope, string $idemKey, int $status, string $body, int $expiresAt, int $now): bool;

    /** Uncertain records (and in_progress ones past expires_at), oldest first: [{scope, idem_key, created_at}]. */
    public function listUncertain(int $now, int $limit): array;

    /** Delete completed records whose expires_at has passed; uncertain and in_progress records are kept. */
    public function purgeExpired(int $now): void;

    /** Insert a record as given (test and migration helper). */
    public function insertRecord(string $scope, string $idemKey, string $fingerprint, string $status, ?int $responseStatus, ?string $responseBody, int $createdAt, int $expiresAt): void;
}

/**
 * In-memory store (one process). Insertion order is kept for list_uncertain ties.
 * Why: tests and single-process use. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
final class InMemoryStorage implements IdempotencyStorage
{
    /** @var array<string, array> */
    private array $records = [];

    /** Map key for (scope, key); the scope's length prefix keeps "a|b"+"c" apart from "a"+"b|c". */
    private static function k(string $scope, string $idemKey): string
    {
        return strlen($scope) . ':' . $scope . '|' . $idemKey;
    }

    /** 'uncertain', or 'in_progress' past expires_at (a killed process), per the amended spec. */
    private static function isUncertain(array $r, int $now): bool
    {
        return $r['status'] === 'uncertain' || ($r['status'] === 'in_progress' && $r['expires_at'] <= $now);
    }

    public function claim(string $scope, string $idemKey, string $fingerprint, int $now, int $expiresAt): bool
    {
        $k = self::k($scope, $idemKey);
        if (isset($this->records[$k])) {
            $r = $this->records[$k];
            if (!($r['status'] === 'completed' && $r['expires_at'] <= $now)) {
                return false;
            }
            unset($this->records[$k]);
        }
        $this->insertRecord($scope, $idemKey, $fingerprint, 'in_progress', null, null, $now, $expiresAt);
        return true;
    }

    public function get(string $scope, string $idemKey): ?array
    {
        return $this->records[self::k($scope, $idemKey)] ?? null;
    }

    public function complete(string $scope, string $idemKey, int $status, string $body, int $expiresAt): bool
    {
        $k = self::k($scope, $idemKey);
        if (($this->records[$k]['status'] ?? null) !== 'in_progress') {
            return false;
        }
        $this->records[$k] = ['status' => 'completed', 'response_status' => $status, 'response_body' => $body, 'expires_at' => $expiresAt] + $this->records[$k];
        return true;
    }

    public function deleteInProgress(string $scope, string $idemKey): bool
    {
        $k = self::k($scope, $idemKey);
        if (($this->records[$k]['status'] ?? null) !== 'in_progress') {
            return false;
        }
        unset($this->records[$k]);
        return true;
    }

    public function markUncertain(string $scope, string $idemKey): bool
    {
        $k = self::k($scope, $idemKey);
        if (($this->records[$k]['status'] ?? null) !== 'in_progress') {
            return false;
        }
        $this->records[$k]['status'] = 'uncertain';
        return true;
    }

    public function release(string $scope, string $idemKey, int $now): bool
    {
        $k = self::k($scope, $idemKey);
        if (!isset($this->records[$k]) || !self::isUncertain($this->records[$k], $now)) {
            return false;
        }
        unset($this->records[$k]);
        return true;
    }

    public function resolve(string $scope, string $idemKey, int $status, string $body, int $expiresAt, int $now): bool
    {
        $k = self::k($scope, $idemKey);
        if (!isset($this->records[$k]) || !self::isUncertain($this->records[$k], $now)) {
            return false;
        }
        $this->records[$k] = ['status' => 'completed', 'response_status' => $status, 'response_body' => $body, 'expires_at' => $expiresAt] + $this->records[$k];
        return true;
    }

    public function listUncertain(int $now, int $limit): array
    {
        $rows = [];
        foreach ($this->records as $r) {
            if (self::isUncertain($r, $now)) {
                $rows[] = ['scope' => $r['scope'], 'idem_key' => $r['idem_key'], 'created_at' => $r['created_at']];
            }
        }
        usort($rows, static fn(array $a, array $b): int => $a['created_at'] <=> $b['created_at']); // stable: ties keep insertion order
        return array_slice($rows, 0, max(0, $limit));
    }

    public function purgeExpired(int $now): void
    {
        foreach ($this->records as $k => $r) {
            if ($r['status'] === 'completed' && $r['expires_at'] <= $now) {
                unset($this->records[$k]);
            }
        }
    }

    public function insertRecord(string $scope, string $idemKey, string $fingerprint, string $status, ?int $responseStatus, ?string $responseBody, int $createdAt, int $expiresAt): void
    {
        $this->records[self::k($scope, $idemKey)] = [
            'scope' => $scope,
            'idem_key' => $idemKey,
            'request_fingerprint' => $fingerprint,
            'status' => $status,
            'response_status' => $responseStatus,
            'response_body' => $responseBody,
            'created_at' => $createdAt,
            'expires_at' => $expiresAt,
        ];
    }
}

/**
 * SQL store on PDO (SQLite 3.24+ upsert syntax; PostgreSQL accepts the same statements). Every write is one
 * statement with its condition in the WHERE clause; rowCount() tells the caller whether it won.
 * Why: the amended spec's "ONE conditional write" rule for claim, release and resolve. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (table idempotency_records).
 */
final class SqlIdempotencyStorage implements IdempotencyStorage
{
    /** Schema from the spec, status constrained to the three values. */
    public const SCHEMA = <<<SQL
CREATE TABLE IF NOT EXISTS idempotency_records (
    scope TEXT NOT NULL,
    idem_key TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('in_progress', 'completed', 'uncertain')),
    response_status INTEGER NULL,
    response_body TEXT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (scope, idem_key)
)
SQL;

    /** "Uncertain" in SQL: status uncertain, or in_progress past expires_at. */
    private const UNCERTAIN = "(status = 'uncertain' OR (status = 'in_progress' AND expires_at <= :now))";

    /** Input: the shared connection (error mode set to exceptions). Touches: the connection settings. */
    public function __construct(private \PDO $pdo)
    {
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    }

    /** Create the table if it is missing. Touches: the database (DDL). */
    public function migrate(): void
    {
        $this->pdo->exec(self::SCHEMA);
    }

    public function claim(string $scope, string $idemKey, string $fingerprint, int $now, int $expiresAt): bool
    {
        $stmt = $this->pdo->prepare(
            "INSERT INTO idempotency_records (scope, idem_key, request_fingerprint, status, response_status, response_body, created_at, expires_at)
             VALUES (:scope, :key, :fp, 'in_progress', NULL, NULL, :now, :exp)
             ON CONFLICT (scope, idem_key) DO UPDATE SET
                 request_fingerprint = excluded.request_fingerprint, status = 'in_progress', response_status = NULL,
                 response_body = NULL, created_at = excluded.created_at, expires_at = excluded.expires_at
             WHERE idempotency_records.status = 'completed' AND idempotency_records.expires_at <= excluded.created_at"
        );
        $stmt->execute([':scope' => $scope, ':key' => $idemKey, ':fp' => $fingerprint, ':now' => $now, ':exp' => $expiresAt]);
        return $stmt->rowCount() === 1;
    }

    public function get(string $scope, string $idemKey): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM idempotency_records WHERE scope = ? AND idem_key = ?');
        $stmt->execute([$scope, $idemKey]);
        $r = $stmt->fetch(\PDO::FETCH_ASSOC);
        if (!$r) {
            return null;
        }
        foreach (['created_at', 'expires_at'] as $f) {
            $r[$f] = (int)$r[$f];
        }
        $r['response_status'] = $r['response_status'] === null ? null : (int)$r['response_status'];
        return $r;
    }

    public function complete(string $scope, string $idemKey, int $status, string $body, int $expiresAt): bool
    {
        $stmt = $this->pdo->prepare(
            "UPDATE idempotency_records SET status = 'completed', response_status = ?, response_body = ?, expires_at = ?
             WHERE scope = ? AND idem_key = ? AND status = 'in_progress'"
        );
        $stmt->execute([$status, $body, $expiresAt, $scope, $idemKey]);
        return $stmt->rowCount() === 1;
    }

    public function deleteInProgress(string $scope, string $idemKey): bool
    {
        $stmt = $this->pdo->prepare("DELETE FROM idempotency_records WHERE scope = ? AND idem_key = ? AND status = 'in_progress'");
        $stmt->execute([$scope, $idemKey]);
        return $stmt->rowCount() === 1;
    }

    public function markUncertain(string $scope, string $idemKey): bool
    {
        $stmt = $this->pdo->prepare("UPDATE idempotency_records SET status = 'uncertain' WHERE scope = ? AND idem_key = ? AND status = 'in_progress'");
        $stmt->execute([$scope, $idemKey]);
        return $stmt->rowCount() === 1;
    }

    public function release(string $scope, string $idemKey, int $now): bool
    {
        $stmt = $this->pdo->prepare('DELETE FROM idempotency_records WHERE scope = :scope AND idem_key = :key AND ' . self::UNCERTAIN);
        $stmt->execute([':scope' => $scope, ':key' => $idemKey, ':now' => $now]);
        return $stmt->rowCount() === 1;
    }

    public function resolve(string $scope, string $idemKey, int $status, string $body, int $expiresAt, int $now): bool
    {
        $stmt = $this->pdo->prepare(
            "UPDATE idempotency_records SET status = 'completed', response_status = :status, response_body = :body, expires_at = :exp
             WHERE scope = :scope AND idem_key = :key AND " . self::UNCERTAIN
        );
        $stmt->execute([':status' => $status, ':body' => $body, ':exp' => $expiresAt, ':scope' => $scope, ':key' => $idemKey, ':now' => $now]);
        return $stmt->rowCount() === 1;
    }

    public function listUncertain(int $now, int $limit): array
    {
        $stmt = $this->pdo->prepare('SELECT scope, idem_key, created_at FROM idempotency_records WHERE ' . self::UNCERTAIN . ' ORDER BY created_at ASC, rowid ASC LIMIT :limit');
        $stmt->bindValue(':now', $now, \PDO::PARAM_INT);
        $stmt->bindValue(':limit', max(0, $limit), \PDO::PARAM_INT);
        $stmt->execute();
        return array_map(static fn(array $r): array => ['scope' => $r['scope'], 'idem_key' => $r['idem_key'], 'created_at' => (int)$r['created_at']], $stmt->fetchAll(\PDO::FETCH_ASSOC));
    }

    public function purgeExpired(int $now): void
    {
        $stmt = $this->pdo->prepare("DELETE FROM idempotency_records WHERE status = 'completed' AND expires_at <= ?");
        $stmt->execute([$now]);
    }

    public function insertRecord(string $scope, string $idemKey, string $fingerprint, string $status, ?int $responseStatus, ?string $responseBody, int $createdAt, int $expiresAt): void
    {
        $stmt = $this->pdo->prepare('INSERT INTO idempotency_records (scope, idem_key, request_fingerprint, status, response_status, response_body, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
        $stmt->execute([$scope, $idemKey, $fingerprint, $status, $responseStatus, $responseBody, $createdAt, $expiresAt]);
    }
}

/**
 * The idempotency service: handle() for API requests, release()/resolve()/listUncertain() for operators.
 * Why: one object holds the store, clock and the required-method rule (they were globals with time()).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store and the caller's operation.
 */
final class IdempotencyService
{
    public const TTL = 86400;
    private const PROBLEM_BASE = 'https://example.com/problems/';

    /** @var Closure(): int */
    private Closure $clock;

    /**
     * @param IdempotencyStorage $storage         Shared by every request.
     * @param Closure|null       $clock           fn(): int unix seconds; default time().
     * @param list<string>       $requiredMethods Methods that need a key (is_required); default POST, PATCH.
     */
    public function __construct(private IdempotencyStorage $storage, ?Closure $clock = null, private array $requiredMethods = ['POST', 'PATCH'])
    {
        $this->clock = $clock ?? static fn(): int => time();
    }

    /** is_required(method, path): true for the configured methods (POST and PATCH by default). Touches: nothing. */
    public function isRequired(string $method, string $path): bool
    {
        return in_array(strtoupper($method), $this->requiredMethods, true);
    }

    /** SHA-256 of (method + " " + path + "\n" + body), lowercase hex. Touches: nothing. */
    public static function fingerprint(string $method, string $path, string $body): string
    {
        return hash('sha256', $method . ' ' . $path . "\n" . $body);
    }

    /**
     * Run $operation at most once per (scope, key).
     *
     * Inputs: $scope = the AUTHENTICATED client/user id (never a request field); the Idempotency-Key value;
     * method, path and raw body (fingerprint); $operation fn(): {status, body}. Output: {status,
     * content_type, body}: the operation's response or the stored one as application/json, or a problem
     * (application/problem+json {type, title, detail}): 400 missing key, 422 key reused with another payload,
     * 409 request in progress, 409 outcome_unknown. OperationFailedException frees the key and is re-thrown;
     * any other Throwable marks the key 'uncertain' and is re-thrown.
     * Why: IDEM-01..10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store; the operation.
     */
    public function handle(string $scope, string $idempotencyKey, string $method, string $path, string $body, callable $operation): array
    {
        if (!$this->isRequired($method, $path)) {
            return self::json($operation());
        }
        if ($idempotencyKey === '') {
            return self::problem(400, 'missing-idempotency-key', 'Missing Idempotency Key', 'The Idempotency-Key header is required for this operation.');
        }
        $fingerprint = self::fingerprint($method, $path, $body);

        for ($attempt = 0; $attempt < 2; $attempt++) {
            $now = ($this->clock)();
            $record = $this->storage->get($scope, $idempotencyKey);
            if ($record !== null && !($record['status'] === 'completed' && $record['expires_at'] <= $now)) {
                return $this->answerFromRecord($record, $fingerprint, $now);
            }
            if ($this->storage->claim($scope, $idempotencyKey, $fingerprint, $now, $now + self::TTL)) {
                return $this->run($scope, $idempotencyKey, $operation);
            }
            // Lost the claim to a concurrent request: read its record and answer from it.
        }
        return self::problem(409, 'conflict', 'Conflict', 'An operation with this idempotency key is already in progress.');
    }

    /**
     * Operator: free an 'uncertain' key (or an in_progress one past expires_at) once reconciliation shows the
     * first attempt did nothing. Output: true when this call freed it; false (nothing changed) otherwise.
     * $scope is the stored record's scope from listUncertain(), never request input.
     * Why: IDEM-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store (one conditional delete).
     */
    public function release(string $scope, string $idempotencyKey): bool
    {
        return $this->storage->release($scope, $idempotencyKey, ($this->clock)());
    }

    /**
     * Operator: store the outcome reconciliation found for an 'uncertain' key as 'completed' with
     * expires_at = now + 24h. Output: true when this call stored it; false (nothing changed) otherwise.
     * Why: IDEM-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store (one conditional update).
     * @param mixed $body The response body (JSON-encoded like an operation's body).
     */
    public function resolve(string $scope, string $idempotencyKey, int $status, mixed $body): bool
    {
        $now = ($this->clock)();
        return $this->storage->resolve($scope, $idempotencyKey, $status, (string)json_encode($body), $now + self::TTL, $now);
    }

    /**
     * Operator: the reconciliation work list, oldest first: [{scope, idem_key, created_at}].
     * Why: amended spec. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store (read).
     */
    public function listUncertain(int $limit = 100): array
    {
        return $this->storage->listUncertain(($this->clock)(), $limit);
    }

    /** Delete expired 'completed' records; uncertain and in_progress ones are kept. Touches: the store. */
    public function purgeExpired(): void
    {
        $this->storage->purgeExpired(($this->clock)());
    }

    /** Answer a retry from an existing (non-expired-completed) record, in the spec's check order. */
    private function answerFromRecord(array $record, string $fingerprint, int $now): array
    {
        if (!hash_equals((string)$record['request_fingerprint'], $fingerprint)) {
            return self::problem(422, 'payload-mismatch', 'Payload Mismatch', 'The request payload does not match the original request for this idempotency key.');
        }
        if ($record['status'] === 'in_progress' && $record['expires_at'] > $now) {
            return self::problem(409, 'conflict', 'Conflict', 'An operation with this idempotency key is already in progress.');
        }
        if ($record['status'] !== 'completed') { // uncertain, or in_progress past expires_at
            return self::problem(409, 'outcome_unknown', 'Outcome unknown', 'The first request with this Idempotency-Key ended without a known outcome; it will not be run again until it is reconciled.');
        }
        return ['status' => (int)$record['response_status'], 'content_type' => 'application/json', 'body' => (string)$record['response_body']];
    }

    /** Run the claimed operation and record its outcome (completed / freed / uncertain). */
    private function run(string $scope, string $idempotencyKey, callable $operation): array
    {
        try {
            $result = $operation();
            if (!is_array($result) || !isset($result['status']) || !is_int($result['status'])) {
                throw new UnexpectedValueException('operation must return {status: int, body}');
            }
        } catch (OperationFailedException $e) {
            $this->storage->deleteInProgress($scope, $idempotencyKey);
            throw $e;
        } catch (Throwable $e) {
            $this->storage->markUncertain($scope, $idempotencyKey);
            throw $e;
        }
        $responseBody = (string)json_encode($result['body'] ?? null);
        $this->storage->complete($scope, $idempotencyKey, $result['status'], $responseBody, ($this->clock)() + self::TTL);
        return ['status' => $result['status'], 'content_type' => 'application/json', 'body' => $responseBody];
    }

    /** An operation result {status, body} as an application/json response. Touches: nothing. */
    private static function json(array $result): array
    {
        return ['status' => (int)$result['status'], 'content_type' => 'application/json', 'body' => (string)json_encode($result['body'] ?? null)];
    }

    /** An RFC 7807 application/problem+json response {type, title, detail} (IDEM-09). Touches: nothing. */
    private static function problem(int $status, string $type, string $title, string $detail): array
    {
        return [
            'status' => $status,
            'content_type' => 'application/problem+json',
            'body' => (string)json_encode(['type' => self::PROBLEM_BASE . $type, 'title' => $title, 'detail' => $detail], JSON_UNESCAPED_SLASHES),
        ];
    }
}

const IDEMPOTENCY_TTL = IdempotencyService::TTL;

/** The process-wide default service used by the spec-named functions below (in-memory store). */
$GLOBALS['IDEMPOTENCY_SERVICE'] = new IdempotencyService(new InMemoryStorage());

/** Spec function is_required(method, path) on the default service. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function is_required(string $method, string $path): bool
{
    return $GLOBALS['IDEMPOTENCY_SERVICE']->isRequired($method, $path);
}

/** Spec fingerprint: SHA-256 of method + " " + path + "\n" + body. Touches: nothing. */
function compute_fingerprint(string $method, string $path, string $body): string
{
    return IdempotencyService::fingerprint($method, $path, $body);
}

/** Spec function handle(...) on the default service; see IdempotencyService::handle(). */
function handle(string $scope, string $idempotencyKey, string $method, string $path, string $body, callable $operation): array
{
    return $GLOBALS['IDEMPOTENCY_SERVICE']->handle($scope, $idempotencyKey, $method, $path, $body, $operation);
}

/** Operator function release(scope, key) on the default service; never an API route. */
function release(string $scope, string $idempotencyKey): bool
{
    return $GLOBALS['IDEMPOTENCY_SERVICE']->release($scope, $idempotencyKey);
}

/** Operator function resolve(scope, key, status, body) on the default service; never an API route. */
function resolve(string $scope, string $idempotencyKey, int $status, mixed $body): bool
{
    return $GLOBALS['IDEMPOTENCY_SERVICE']->resolve($scope, $idempotencyKey, $status, $body);
}

/** Operator function list_uncertain(limit) on the default service; never an API route. */
function list_uncertain(int $limit = 100): array
{
    return $GLOBALS['IDEMPOTENCY_SERVICE']->listUncertain($limit);
}

/** Spec function purge_expired() on the default service. */
function purge_expired(): void
{
    $GLOBALS['IDEMPOTENCY_SERVICE']->purgeExpired();
}

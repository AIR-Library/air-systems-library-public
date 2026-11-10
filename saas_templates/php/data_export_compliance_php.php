<?php
/**
 * Data Export & Compliance (TIER 2, system 3): GDPR/CCPA data export and account deletion with
 * a 30-day grace period, on PDO SQLite.
 *
 * What it does: a user asks for an export (JSON or CSV); a job gathers every data category,
 * stores the file, and emails a signed, download-only link that expires after 7 days. A user asks
 * for deletion; an emailed one-time token confirms it; the cascade delete runs only when
 * processDueDeletions() finds the 30-day grace period over, and the user can cancel until then.
 * The audit log (and the deletion request itself, as the compliance record) is kept.
 *
 * Inputs/outputs: ComplianceService methods take ids and options and return the spec's response
 * arrays; failures throw ComplianceException with a machine-readable code.
 *
 * Why (repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP): the suite failed with
 * `Class "Compliance\Database" not found` (its tests never loaded this file) and had no test the
 * runner could count. Behind that: confirming a deletion deleted the account at once (no grace
 * period at all), the cascade deleted the deletion request it then tried to mark completed, the
 * export files (personal data) were never deleted, "signed" URLs carried the literal signature
 * "mocked" and could not be checked or expire, the confirmation token was stored in plain text,
 * the CSV export broke on the profile section and allowed spreadsheet formula injection, and
 * email, storage and the database were static singletons with no interface to swap.
 *
 * Touches: the database (users and related tables, export_requests, deletion_requests,
 * audit_log), object storage (export files) and email, each behind an interface; the in-memory
 * implementations here touch no network or files. No money.
 */

declare(strict_types=1);

namespace Compliance;

use Closure;
use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;
use PDO;
use RuntimeException;
use Throwable;

/**
 * A compliance request that cannot be carried out; $errorCode is the API's error string.
 *
 * Why: callers need a code to map to HTTP 400/403/404 without parsing messages. 2026-11-10,
 * session session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
class ComplianceException extends RuntimeException
{
    /**
     * @param string $errorCode e.g. invalid_format, not_found, invalid_token, grace_period_elapsed
     * @param string $message   Human-readable text (no secrets).
     *
     * Why: dependencies are injected instead of static singletons. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing (stores dependencies; the default signing key comes from random_bytes).
     */
    public function __construct(public readonly string $errorCode, string $message)
    {
        parent::__construct($message);
    }
}

/**
 * Creates a migrated PDO connection.
 *
 * Why: replaces the static in-memory singleton so each caller (and each test) owns its own
 * database. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
 */
final class Database
{
    /**
     * Open a connection and create the tables if they do not exist.
     *
     * @param string      $dsn  PDO DSN; default an in-memory SQLite database.
     * @param string|null $user Database user (not used by SQLite).
     * @param string|null $pass Database password (not used by SQLite).
     * @return PDO With exceptions on errors and associative fetches.
     *
     * Why: replaces the static in-memory Database singleton. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (connect and DDL).
     */
    public static function create(string $dsn = 'sqlite::memory:', ?string $user = null, ?string $pass = null): PDO
    {
        $pdo = new PDO($dsn, $user, $pass);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        self::migrate($pdo);
        return $pdo;
    }

    /**
     * Create the schema. deletion_requests and audit_log have no foreign key to users: they
     * must outlive the account they record.
     *
     * Why: deletion_requests no longer references users, so the record survives the cascade. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (DDL).
     */
    public static function migrate(PDO $pdo): void
    {
        $pdo->exec(<<<SQL
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    tier TEXT NOT NULL,
    status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    ip TEXT NOT NULL,
    device TEXT NOT NULL,
    started_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS activities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    type TEXT NOT NULL,
    details TEXT,
    performed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    filename TEXT NOT NULL,
    size INTEGER NOT NULL,
    uploaded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS preferences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    key TEXT NOT NULL,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    amount REAL NOT NULL,
    currency TEXT NOT NULL,
    type TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    details TEXT,
    why_chain TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log (user_id);
CREATE TABLE IF NOT EXISTS export_requests (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    requested_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'failed')),
    format TEXT NOT NULL CHECK (format IN ('json', 'csv')),
    storage_key TEXT,
    file_url TEXT,
    completed_at TEXT,
    expires_at TEXT
);
CREATE TABLE IF NOT EXISTS deletion_requests (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    requested_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'completed', 'cancelled')),
    reason TEXT NOT NULL,
    confirmation_token_hash TEXT,
    scheduled_at TEXT,
    deleted_at TEXT
);
SQL);
    }
}

/**
 * Sends email (SMTP, SES, ...). Implement it for your provider.
 *
 * Why: the spec emails download and confirmation links; tests need a fake. 2026-11-10,
 * session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the network in real implementations.
 */
interface Mailer
{
    /**
     * @param int    $userId  Recipient (your implementation looks up the address).
     * @param string $subject Subject line.
     * @param string $body    Plain-text body (contains one-time links: do not log it).
     *
     * Why: email sits behind the Mailer interface. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: email (network) in real mailers; memory in InMemoryMailer.
     */
    public function send(int $userId, string $subject, string $body): void;
}

/**
 * Mailer that keeps messages in memory (tests, local runs).
 *
 * Why: replaces the static EmailService. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches memory only.
 */
final class InMemoryMailer implements Mailer
{
    /** @var list<array{user_id: int, subject: string, body: string}> */
    public array $sent = [];

    /**
     * Records the message.
     *
     * Why: email sits behind the Mailer interface. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: email (network) in real mailers; memory in InMemoryMailer.
     */
    public function send(int $userId, string $subject, string $body): void
    {
        $this->sent[] = ['user_id' => $userId, 'subject' => $subject, 'body' => $body];
    }
}

/**
 * Encrypted object storage with signed, download-only, expiring URLs (S3 in production:
 * server-side encryption on, and a presigned GET URL).
 *
 * Why: the spec stores exports in S3 behind 7-day signed URLs; tests need a fake. 2026-11-10,
 * session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the network in real implementations.
 */
interface ObjectStorage
{
    /**
     * Store $content under $key (overwrites).
     *
     * Why: storage sits behind ObjectStorage. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: object storage (network) in real implementations; memory in the in-memory one.
     */
    public function put(string $key, string $content): void;

    /**
     * Remove $key; no error when absent.
     *
     * Why: the cascade must remove stored export files (personal data). 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: object storage (network) in real implementations; memory in the in-memory one.
     */
    public function delete(string $key): void;

    /**
     * A URL that allows only downloading $key until $expiresAt.
     *
     * Why: links were "signed" with the literal text "mocked". 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing (computes an HMAC).
     */
    public function signedDownloadUrl(string $key, DateTimeImmutable $expiresAt): string;
}

/**
 * ObjectStorage in memory, with real HMAC-SHA256 signed URLs that can be checked and expire.
 *
 * Why: the old mock signed nothing ("signature=mocked"). 2026-11-10, session
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
 */
final class InMemoryObjectStorage implements ObjectStorage
{
    private const BASE_URL = 'https://storage.invalid/';

    /** @var array<string, string> */
    private array $objects = [];
    private string $signingKey;

    /**
     * @param string|null $signingKey Secret for URL signatures; default 32 random bytes.
     *
     * Why: dependencies are injected instead of static singletons. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing (stores dependencies; the default signing key comes from random_bytes).
     */
    public function __construct(?string $signingKey = null)
    {
        $this->signingKey = $signingKey ?? random_bytes(32);
    }

    /**
     * Implements the interface method of the same name.
     *
     * Why: storage sits behind ObjectStorage. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: object storage (network) in real implementations; memory in the in-memory one.
     */
    public function put(string $key, string $content): void
    {
        $this->objects[$key] = $content;
    }

    /**
     * Implements the interface method of the same name.
     *
     * Why: the cascade must remove stored export files (personal data). 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: object storage (network) in real implementations; memory in the in-memory one.
     */
    public function delete(string $key): void
    {
        unset($this->objects[$key]);
    }

    /**
     * Whether $key is stored.
     *
     * Why: lets callers check that a file was removed. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    public function has(string $key): bool
    {
        return isset($this->objects[$key]);
    }

    /**
     * Implements the interface method of the same name.
     *
     * Why: links were "signed" with the literal text "mocked". 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing (computes an HMAC).
     */
    public function signedDownloadUrl(string $key, DateTimeImmutable $expiresAt): string
    {
        $expires = $expiresAt->getTimestamp();
        return self::BASE_URL . rawurlencode($key) . '?expires=' . $expires . '&signature=' . $this->sign('GET', $key, $expires);
    }

    /**
     * Download through a signed URL: the content, or null when the signature is wrong, the
     * method is not GET, the link has expired or the object is gone.
     *
     * @param string            $url    The signed URL.
     * @param DateTimeImmutable $now    The time of the request.
     * @param string            $method HTTP method (only GET is ever allowed).
     *
     * Why: a signed link must be checkable: right signature, GET only, not expired (hash_equals). 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    public function download(string $url, DateTimeImmutable $now, string $method = 'GET'): ?string
    {
        if (!str_starts_with($url, self::BASE_URL)) {
            return null;
        }
        $path = (string) parse_url($url, PHP_URL_PATH);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        $key = rawurldecode(ltrim($path, '/'));
        $expires = $query['expires'] ?? '';
        $signature = $query['signature'] ?? '';
        if (!is_string($expires) || !ctype_digit($expires) || !is_string($signature)) {
            return null;
        }
        if (!hash_equals($this->sign($method, $key, (int) $expires), $signature)) {
            return null;
        }
        if ($method !== 'GET' || $now->getTimestamp() > (int) $expires) {
            return null;
        }
        return $this->objects[$key] ?? null;
    }

    /**
     * HMAC over method, key and expiry.
     *
     * Why: one HMAC-SHA256 over method, key and expiry. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private function sign(string $method, string $key, int $expires): string
    {
        return hash_hmac('sha256', $method . "\n" . $key . "\n" . $expires, $this->signingKey);
    }
}

/**
 * Runs background work (the Background Jobs system in production).
 *
 * Why: the spec makes export generation a background job. 2026-11-10, session
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches whatever the job touches.
 */
interface JobDispatcher
{
    /**
     * Run or enqueue $job.
     *
     * Why: the export runs as a background job. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: whatever the job touches.
     */
    public function dispatch(callable $job): void;
}

/**
 * JobDispatcher that runs the job immediately (tests, small deployments).
 *
 * Why: replaces the static JobQueue. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches whatever the job touches.
 */
final class InlineJobDispatcher implements JobDispatcher
{
    /**
     * Implements the interface method of the same name.
     *
     * Why: the export runs as a background job. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: whatever the job touches.
     */
    public function dispatch(callable $job): void
    {
        $job();
    }
}

/**
 * Writes the compliance audit trail. Rows are never deleted by the cascade.
 *
 * Why: the spec logs every export and deletion request, with an optional why_chain id.
 * 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
 */
final class AuditLog
{
    /**
     * @param PDO     $pdo   Connection with the audit_log table.
     * @param Closure $clock Returns now.
     *
     * Why: dependencies are injected instead of static singletons. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing (stores dependencies; the default signing key comes from random_bytes).
     */
    public function __construct(private PDO $pdo, private Closure $clock)
    {
    }

    /**
     * @param int|null    $userId   Subject user.
     * @param string      $action   e.g. data_export_requested.
     * @param array       $details  JSON-encoded; never put tokens or URLs here.
     * @param string|null $whyChain Reasoning-chain id linking the request to its cause.
     *
     * Why: the spec audits every request, with why_chain support. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (INSERT into audit_log).
     */
    public function record(?int $userId, string $action, array $details = [], ?string $whyChain = null): void
    {
        $this->pdo->prepare(
            'INSERT INTO audit_log (user_id, action, details, why_chain, created_at)
             VALUES (:user_id, :action, :details, :why_chain, :created_at)'
        )->execute([
            ':user_id' => $userId,
            ':action' => $action,
            ':details' => json_encode($details, JSON_UNESCAPED_SLASHES),
            ':why_chain' => $whyChain,
            ':created_at' => ComplianceService::format(($this->clock)()),
        ]);
    }
}

/**
 * The compliance service (export, deletion, admin lists).
 *
 * Authorization belongs to the caller: pass the *authenticated* user's id (never one taken
 * from the request body), and expose listExports/listDeletions only to admins.
 *
 * Why: see the file header. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches the database, storage and email.
 */
final class ComplianceService
{
    public const EXPORT_LINK_TTL = '+7 days';
    public const GRACE_PERIOD = '+30 days';
    public const DELETION_REASONS = ['user_requested', 'gdpr_request', 'gdpr_right_to_be_forgotten', 'other'];

    /** Tables holding the user's data, removed by the cascade (audit_log is kept). */
    private const USER_TABLES = ['sessions', 'activities', 'files', 'preferences', 'transactions', 'export_requests'];

    private Closure $clock;
    private JobDispatcher $jobs;
    private AuditLog $audit;

    /**
     * @param PDO                $pdo            Migrated connection (Database::create()).
     * @param Mailer             $mailer         Email sender.
     * @param ObjectStorage      $storage        Export file storage.
     * @param JobDispatcher|null $jobs           Default: run inline.
     * @param Closure|null       $clock          Returns now; default the system clock (UTC).
     * @param string             $appBaseUrl     Base of the emailed confirmation link.
     *
     * Why: dependencies are injected instead of static singletons. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing (stores dependencies; the default signing key comes from random_bytes).
     */
    public function __construct(
        private PDO $pdo,
        private Mailer $mailer,
        private ObjectStorage $storage,
        ?JobDispatcher $jobs = null,
        ?Closure $clock = null,
        private string $appBaseUrl = 'https://app.example.com',
    ) {
        $this->jobs = $jobs ?? new InlineJobDispatcher();
        $this->clock = $clock ?? static fn (): DateTimeImmutable => new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $this->audit = new AuditLog($pdo, $this->clock);
    }

    // ---------- EXPORT ----------

    /**
     * Request a data export (POST /compliance/export). The file is built by a background job.
     *
     * @param int         $userId   The authenticated user.
     * @param string      $format   json | csv.
     * @param string|null $whyChain Optional why-chain id for the audit entry.
     * @return array {success: true, export_id, status: 'pending', will_email_at}
     * @throws ComplianceException invalid_format | user_not_found
     *
     * Why: the export ran through static singletons; now validated and injected. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database, the job dispatcher and the audit log.
     */
    public function requestExport(int $userId, string $format, ?string $whyChain = null): array
    {
        if (!in_array($format, ['json', 'csv'], true)) {
            throw new ComplianceException('invalid_format', 'Format must be json or csv');
        }
        $this->requireUser($userId);
        $exportId = self::uuid();
        $now = $this->now();
        $this->pdo->prepare(
            "INSERT INTO export_requests (id, user_id, requested_at, status, format)
             VALUES (:id, :user_id, :requested_at, 'pending', :format)"
        )->execute([':id' => $exportId, ':user_id' => $userId, ':requested_at' => self::format($now), ':format' => $format]);
        $this->audit->record($userId, 'data_export_requested', ['format' => $format, 'export_id' => $exportId], $whyChain);

        $this->jobs->dispatch(fn () => $this->processExport($exportId));

        return [
            'success' => true,
            'export_id' => $exportId,
            'status' => 'pending',
            'will_email_at' => self::format($now->modify('+5 minutes')),
        ];
    }

    /**
     * The export job: gather, store, sign a 7-day link, email it. On failure the request is
     * marked failed and the error code (not the data) is audited.
     *
     * @param string $exportId A pending export request.
     *
     * Why: real signed links, a CSV that handles the profile section, failures audited without data. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database, object storage and email.
     */
    public function processExport(string $exportId): void
    {
        $stmt = $this->pdo->prepare("SELECT * FROM export_requests WHERE id = :id AND status = 'pending'");
        $stmt->execute([':id' => $exportId]);
        $request = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($request === false) {
            return;
        }
        $userId = (int) $request['user_id'];
        try {
            $data = $this->gatherUserData($userId);
            $content = $request['format'] === 'json'
                ? json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)
                : self::toCsv($data);
            $key = "exports/{$exportId}.{$request['format']}";
            $this->storage->put($key, $content);
            $now = $this->now();
            $expiresAt = $now->modify(self::EXPORT_LINK_TTL);
            $url = $this->storage->signedDownloadUrl($key, $expiresAt);

            $this->pdo->prepare(
                "UPDATE export_requests SET status = 'completed', storage_key = :key, file_url = :url,
                        completed_at = :completed_at, expires_at = :expires_at WHERE id = :id"
            )->execute([
                ':key' => $key,
                ':url' => $url,
                ':completed_at' => self::format($now),
                ':expires_at' => self::format($expiresAt),
                ':id' => $exportId,
            ]);
            $this->mailer->send(
                $userId,
                'Your data export is ready',
                "Your data export is ready. Download it here (the link expires in 7 days):\n{$url}\n"
            );
        } catch (Throwable $e) {
            $this->pdo->prepare("UPDATE export_requests SET status = 'failed' WHERE id = :id")->execute([':id' => $exportId]);
            $this->audit->record($userId, 'data_export_failed', ['export_id' => $exportId, 'error' => get_class($e)]);
        }
    }

    /**
     * Export status (GET /compliance/exports/:export_id).
     *
     * @param string   $exportId
     * @param int|null $userId The authenticated user; when given, another user's export is
     *                         reported as not found.
     * @return array {export_id, status, file_url, expires_at, requested_at}
     * @throws ComplianceException not_found
     *
     * Why: optional ownership check so a route cannot show another user's export. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read).
     */
    public function getExportStatus(string $exportId, ?int $userId = null): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM export_requests WHERE id = :id');
        $stmt->execute([':id' => $exportId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false || ($userId !== null && (int) $row['user_id'] !== $userId)) {
            throw new ComplianceException('not_found', 'Export not found');
        }
        return [
            'export_id' => $row['id'],
            'status' => $row['status'],
            'file_url' => $row['file_url'],
            'expires_at' => $row['expires_at'],
            'requested_at' => $row['requested_at'],
        ];
    }

    // ---------- DELETION ----------

    /**
     * Request account deletion (POST /compliance/delete): emails a one-time confirmation link.
     * Only a hash of the token is stored.
     *
     * @param int         $userId   The authenticated user.
     * @param string      $reason   One of DELETION_REASONS.
     * @param string|null $whyChain Optional why-chain id for the audit entry.
     * @return array {success: true, deletion_id, status: 'pending', will_delete_at}
     * @throws ComplianceException invalid_reason | user_not_found
     *
     * Why: the confirmation token was stored in plain text; only its SHA-256 is stored now. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database, email and the audit log.
     */
    public function requestDeletion(int $userId, string $reason, ?string $whyChain = null): array
    {
        if (!in_array($reason, self::DELETION_REASONS, true)) {
            throw new ComplianceException('invalid_reason', 'Unknown deletion reason');
        }
        $this->requireUser($userId);
        $deletionId = self::uuid();
        $token = bin2hex(random_bytes(16));
        $now = $this->now();
        $this->pdo->prepare(
            "INSERT INTO deletion_requests (id, user_id, requested_at, status, reason, confirmation_token_hash)
             VALUES (:id, :user_id, :requested_at, 'pending', :reason, :token_hash)"
        )->execute([
            ':id' => $deletionId,
            ':user_id' => $userId,
            ':requested_at' => self::format($now),
            ':reason' => $reason,
            ':token_hash' => hash('sha256', $token),
        ]);
        $this->audit->record($userId, 'deletion_requested', ['reason' => $reason, 'deletion_id' => $deletionId], $whyChain);

        $link = rtrim($this->appBaseUrl, '/') . "/compliance/delete/{$deletionId}/confirm?token={$token}";
        $this->mailer->send(
            $userId,
            'Confirm your account deletion',
            "Please confirm your account deletion with the link below. Your account is deleted 30 days "
            . "after you confirm, and you can cancel until then.\n{$link}\n\nIf you did not ask for this, ignore this email.\n"
        );

        return [
            'success' => true,
            'deletion_id' => $deletionId,
            'status' => 'pending',
            'will_delete_at' => self::format($now->modify(self::GRACE_PERIOD)),
        ];
    }

    /**
     * Confirm deletion with the emailed token (POST /compliance/delete/:id/confirm). Starts the
     * 30-day grace period; the token works once.
     *
     * @return array {success: true, deletion_scheduled_for}
     * @throws ComplianceException not_found | not_pending | invalid_token
     *
     * Why: confirming deleted the account at once (no grace period); the token is now single-use and compared in constant time. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database and the audit log.
     */
    public function confirmDeletion(string $deletionId, string $token): array
    {
        $row = $this->getDeletion($deletionId);
        if ($row['status'] !== 'pending' || $row['confirmation_token_hash'] === null) {
            throw new ComplianceException('not_pending', 'Deletion request is not awaiting confirmation');
        }
        if (!hash_equals($row['confirmation_token_hash'], hash('sha256', $token))) {
            throw new ComplianceException('invalid_token', 'Invalid confirmation token');
        }
        $scheduledAt = self::format($this->now()->modify(self::GRACE_PERIOD));
        $stmt = $this->pdo->prepare(
            "UPDATE deletion_requests SET status = 'approved', scheduled_at = :scheduled_at, confirmation_token_hash = NULL
             WHERE id = :id AND status = 'pending'"
        );
        $stmt->execute([':scheduled_at' => $scheduledAt, ':id' => $deletionId]);
        if ($stmt->rowCount() !== 1) {
            throw new ComplianceException('not_pending', 'Deletion request is not awaiting confirmation');
        }
        $this->audit->record((int) $row['user_id'], 'deletion_confirmed', ['deletion_id' => $deletionId]);

        return ['success' => true, 'deletion_scheduled_for' => $scheduledAt];
    }

    /**
     * Cancel a pending or confirmed deletion within the grace period (DELETE /compliance/delete/:id).
     *
     * @param string   $deletionId
     * @param int|null $userId The authenticated user; when given, another user's request is
     *                         reported as not found.
     * @return array {success: true, status: 'cancelled'}
     * @throws ComplianceException not_found | not_cancellable | grace_period_elapsed
     *
     * Why: cancelling must stop at the end of the grace period. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database and the audit log.
     */
    public function cancelDeletion(string $deletionId, ?int $userId = null): array
    {
        $row = $this->getDeletion($deletionId);
        if ($userId !== null && (int) $row['user_id'] !== $userId) {
            throw new ComplianceException('not_found', 'Deletion request not found');
        }
        if (!in_array($row['status'], ['pending', 'approved'], true)) {
            throw new ComplianceException('not_cancellable', 'Deletion can no longer be cancelled');
        }
        $now = self::format($this->now());
        if ($row['status'] === 'approved' && $row['scheduled_at'] <= $now) {
            throw new ComplianceException('grace_period_elapsed', 'The grace period has ended');
        }
        $stmt = $this->pdo->prepare(
            "UPDATE deletion_requests SET status = 'cancelled', confirmation_token_hash = NULL
             WHERE id = :id AND status IN ('pending', 'approved')"
        );
        $stmt->execute([':id' => $deletionId]);
        if ($stmt->rowCount() !== 1) {
            throw new ComplianceException('not_cancellable', 'Deletion can no longer be cancelled');
        }
        $this->audit->record((int) $row['user_id'], 'deletion_cancelled', ['deletion_id' => $deletionId]);
        return ['success' => true, 'status' => 'cancelled'];
    }

    /**
     * Run every confirmed deletion whose grace period is over (call it from a scheduled job).
     * Each runs in its own transaction: the user's rows in USER_TABLES and the user row are
     * deleted, stored export files are removed, the request becomes 'completed'; audit_log and
     * the deletion request stay.
     *
     * @return int Number of accounts deleted.
     *
     * Why: the grace period needs a worker that deletes only when it is over. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database and object storage (deletes personal data).
     */
    public function processDueDeletions(): int
    {
        $stmt = $this->pdo->prepare(
            "SELECT id, user_id FROM deletion_requests WHERE status = 'approved' AND scheduled_at <= :now ORDER BY rowid"
        );
        $stmt->execute([':now' => self::format($this->now())]);
        $done = 0;
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $this->executeDeletion($row['id'], (int) $row['user_id']);
            $done++;
        }
        return $done;
    }

    /**
     * The cascade for one request (see processDueDeletions).
     *
     * Why: the old cascade deleted the deletion request it then marked completed, and left export files behind. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database and object storage (deletes personal data).
     */
    private function executeDeletion(string $deletionId, int $userId): void
    {
        $keys = $this->pdo->prepare('SELECT storage_key FROM export_requests WHERE user_id = :uid AND storage_key IS NOT NULL');
        $keys->execute([':uid' => $userId]);
        $storageKeys = $keys->fetchAll(PDO::FETCH_COLUMN);

        $this->pdo->beginTransaction();
        try {
            foreach (self::USER_TABLES as $table) {
                $this->pdo->prepare("DELETE FROM {$table} WHERE user_id = :uid")->execute([':uid' => $userId]);
            }
            $this->pdo->prepare('DELETE FROM users WHERE id = :uid')->execute([':uid' => $userId]);
            $this->pdo->prepare(
                "UPDATE deletion_requests SET status = 'completed', deleted_at = :now WHERE id = :id"
            )->execute([':now' => self::format($this->now()), ':id' => $deletionId]);
            $this->audit->record($userId, 'deletion_completed', ['deletion_id' => $deletionId]);
            $this->pdo->commit();
        } catch (Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
        foreach ($storageKeys as $key) {
            $this->storage->delete((string) $key);
        }
    }

    // ---------- ADMIN (expose to admins only) ----------

    /**
     * All export requests (GET /admin/compliance/exports), oldest first; signed URLs omitted.
     *
     * @param array $filters {user_id?: int, status?: string}
     * @return array {exports: list<array>, total: int}
     *
     * Why: the admin list showed live download links; it no longer does. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read).
     */
    public function listExports(array $filters = []): array
    {
        $rows = $this->listRequests(
            'SELECT id AS export_id, user_id, requested_at, status, format, completed_at, expires_at FROM export_requests',
            $filters
        );
        return ['exports' => $rows, 'total' => count($rows)];
    }

    /**
     * All deletion requests (GET /admin/compliance/deletions), oldest first; token hashes omitted.
     *
     * @param array $filters {user_id?: int, status?: string}
     * @return array {deletions: list<array>, total: int}
     *
     * Why: the admin list showed confirmation tokens; it no longer does. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read).
     */
    public function listDeletions(array $filters = []): array
    {
        $rows = $this->listRequests(
            'SELECT id AS deletion_id, user_id, requested_at, status, reason, scheduled_at, deleted_at FROM deletion_requests',
            $filters
        );
        return ['deletions' => $rows, 'total' => count($rows)];
    }

    /**
     * Shared filter logic of the admin lists (bound parameters only).
     *
     * Why: one bound-parameter filter for both admin lists. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read).
     */
    private function listRequests(string $select, array $filters): array
    {
        $where = [];
        $params = [];
        if (isset($filters['user_id'])) {
            $where[] = 'user_id = :user_id';
            $params[':user_id'] = (int) $filters['user_id'];
        }
        if (isset($filters['status'])) {
            $where[] = 'status = :status';
            $params[':status'] = (string) $filters['status'];
        }
        $sql = $select . ($where ? ' WHERE ' . implode(' AND ', $where) : '') . ' ORDER BY rowid';
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // ---------- HELPERS ----------

    /**
     * UTC ISO 8601 (sorts as text).
     *
     * Why: one timestamp format (UTC ISO 8601) that sorts as text. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public static function format(DateTimeImmutable $time): string
    {
        return $time->setTimezone(new DateTimeZone('UTC'))->format(DateTimeInterface::ATOM);
    }

    /**
     * Now from the clock.
     *
     * Why: the clock is injectable so the 30-day and 7-day periods are testable. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private function now(): DateTimeImmutable
    {
        return ($this->clock)();
    }

    /**
     * @throws ComplianceException user_not_found
     *
     * Why: requests for a user that does not exist are refused. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read).
     */
    private function requireUser(int $userId): void
    {
        $stmt = $this->pdo->prepare('SELECT 1 FROM users WHERE id = :id');
        $stmt->execute([':id' => $userId]);
        if ($stmt->fetchColumn() === false) {
            throw new ComplianceException('user_not_found', 'User not found');
        }
    }

    /**
     * @throws ComplianceException not_found
     *
     * Why: shared lookup for confirm/cancel. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read).
     */
    private function getDeletion(string $deletionId): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM deletion_requests WHERE id = :id');
        $stmt->execute([':id' => $deletionId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            throw new ComplianceException('not_found', 'Deletion request not found');
        }
        return $row;
    }

    /**
     * A random UUID v4.
     *
     * Why: ids must not be guessable (random_bytes). 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static function uuid(): string
    {
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    /**
     * Every data category of the spec: profile, sessions (IPs, devices), activity, files
     * (names and sizes, not contents), preferences, transactions and the audit trail.
     *
     * Why: the profile section broke the CSV writer; every spec category is gathered. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read).
     */
    private function gatherUserData(int $userId): array
    {
        $queries = [
            'profile' => 'SELECT id, email, name, created_at, tier, status FROM users WHERE id = :uid',
            'sessions' => 'SELECT ip, device, started_at FROM sessions WHERE user_id = :uid ORDER BY id',
            'activities' => 'SELECT type, details, performed_at FROM activities WHERE user_id = :uid ORDER BY id',
            'files' => 'SELECT filename, size, uploaded_at FROM files WHERE user_id = :uid ORDER BY id',
            'preferences' => 'SELECT key, value FROM preferences WHERE user_id = :uid ORDER BY id',
            'transactions' => 'SELECT amount, currency, type, created_at FROM transactions WHERE user_id = :uid ORDER BY id',
            'audit_trail' => 'SELECT action, details, why_chain, created_at FROM audit_log WHERE user_id = :uid ORDER BY id',
        ];
        $data = [];
        foreach ($queries as $section => $sql) {
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute([':uid' => $userId]);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $data[$section] = $section === 'profile' ? ($rows[0] ?? []) : $rows;
        }
        return $data;
    }

    /**
     * CSV with one titled section per category (RFC 4180 quoting). Text cells starting with
     * = + - @ or a control character get a leading apostrophe so spreadsheets do not run them
     * as formulas.
     *
     * Why: the old writer failed on the profile section and allowed formula injection. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    private static function toCsv(array $data): string
    {
        $out = fopen('php://memory', 'w+');
        foreach ($data as $section => $records) {
            $rows = $section === 'profile' ? ($records === [] ? [] : [$records]) : $records;
            fputcsv($out, [$section], ',', '"', '');
            if ($rows !== []) {
                fputcsv($out, array_keys($rows[0]), ',', '"', '');
                foreach ($rows as $row) {
                    $cells = array_map(static function (mixed $v): string {
                        $v = (string) $v;
                        return ($v !== '' && !is_numeric($v) && preg_match('/^[=+\-@\t\r]/', $v)) ? "'" . $v : $v;
                    }, array_values($row));
                    fputcsv($out, $cells, ',', '"', '');
                }
            }
            fwrite($out, "\n");
        }
        rewind($out);
        $csv = (string) stream_get_contents($out);
        fclose($out);
        return $csv;
    }
}

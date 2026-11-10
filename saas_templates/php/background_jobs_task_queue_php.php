<?php
/**
 * Background Jobs & Task Queue (TIER 2, system 4): a database-backed job queue on PDO SQLite.
 *
 * What it does: enqueues jobs, lets a worker claim and run them, tracks progress ("X/Y") and
 * results, retries failed jobs with exponential backoff (1s, 2s, 4s, ...), honours scheduled_at,
 * cancels jobs that have not started, and creates a new job when a failed one is retried by hand.
 *
 * Inputs/outputs: PHP arrays in, PHP arrays out (the shapes in the spec's six endpoints);
 * handleRequest() maps the HTTP endpoints onto them and returns status, headers and a JSON body.
 *
 * Why (repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP): the suite failed with
 * `Class "JobQueue" not found` because its tests never loaded this file, and behind that the code
 * could not run on SQLite at all: MySQL-only SQL (NOW(), SQL_CALC_FOUND_ROWS, FOR UPDATE, ENUM),
 * a global class that redeclared PHP's own InvalidArgumentException (a fatal error), `use PDO;` in
 * the global namespace (a warning), params decoded twice (a TypeError), the schema only as a
 * global constant while the tests read JobQueue::DATABASE_SCHEMA, failures that never set status
 * 'failed', a final progress of "0/0", the handler run inside one long transaction (so progress was
 * never visible while it ran), no atomic claim (two workers could run one job), and a manual retry
 * that left the original's automatic retry pending (the task could run twice).
 *
 * Touches: the database (tables jobs and job_runs). No network, no files, no money. The demo task
 * handlers only simulate work; register real ones with registerTaskHandler().
 */

declare(strict_types=1);

/**
 * Raised when a job id does not exist (HTTP 404).
 *
 * Why: the old file declared a global `InvalidArgumentException`, which redeclares PHP's built-in
 * class and is a fatal error; the 404 case now has its own name. 2026-11-10, session
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
class JobNotFoundException extends RuntimeException
{
}

/**
 * Thrown by a task handler to mark an attempt as failed, so the queue records the error and
 * schedules a retry with backoff (or fails the job for good when attempts are used up).
 *
 * Why: the demo handlers returned normally even when every item failed, so no job ever failed.
 * 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
class TaskFailedException extends RuntimeException
{
}

/**
 * The job queue: lifecycle, worker, retries, progress and results.
 *
 * Retry policy (JOBS-03/04 as amended 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): `max_retries` counts retries AFTER
 * the first attempt, so a job runs at most max_retries + 1 times (max_retries 3 -> 4 runs). When attempt
 * n fails and a retry is left, retry n is scheduled: status goes back to 'enqueued', retry_count = n and
 * next_retry_at = failed_at + 2^(n-1) seconds (1s, 2s, 4s, ...); the worker skips the job until then.
 * When attempt max_retries + 1 fails, status is 'failed' with retry_count = max_retries and
 * next_retry_at null. (It used to treat max_retries as the number of attempts and kept a waiting job in
 * 'failed'.) A manual retry (retryJob) of a failed job creates a new job with a fresh set of retries.
 *
 * Why: see the file header. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the database.
 */
class JobQueue
{
    /** Job statuses from the spec. */
    public const STATUSES = ['enqueued', 'running', 'completed', 'failed', 'cancelled'];

    /** Largest page listJobs() returns. */
    public const MAX_LIST_LIMIT = 100;

    /**
     * SQLite DDL for the queue (run it once with PDO::exec). Times are UTC ISO 8601 strings
     * with microseconds, so they sort and compare as text.
     */
    public const DATABASE_SCHEMA = <<<SQL
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    task_type TEXT NOT NULL,
    params TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'enqueued'
        CHECK (status IN ('enqueued', 'running', 'completed', 'failed', 'cancelled')),
    created_at TEXT NOT NULL,
    started_at TEXT NULL,
    completed_at TEXT NULL,
    progress TEXT NOT NULL DEFAULT '0/0',
    result TEXT NULL,
    error TEXT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 3,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_retry_at TEXT NULL,
    scheduled_at TEXT NULL,
    retry_of TEXT NULL,
    retried_as TEXT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_status_type ON jobs (status, task_type);
CREATE TABLE IF NOT EXISTS job_runs (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    started_at TEXT NOT NULL,
    completed_at TEXT NULL,
    result TEXT NULL
);
CREATE INDEX IF NOT EXISTS idx_job_runs_job ON job_runs (job_id);
SQL;

    private PDO $pdo;

    /** @var array<string, callable(array, callable(int, int): void): array> */
    private array $taskHandlers = [];

    /** @var Closure(): DateTimeImmutable */
    private Closure $clock;

    /**
     * Create a queue over an existing PDO connection (the schema must already exist).
     *
     * @param PDO          $pdo   Connection holding the jobs and job_runs tables.
     * @param Closure|null $clock Returns "now"; defaults to the system clock. Tests and
     *                            simulations pass a fixed clock to stay deterministic.
     *
     * Why: the clock is injectable so backoff and scheduling can be tested without sleeping.
     * 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database setting only.
     */
    public function __construct(PDO $pdo, ?Closure $clock = null)
    {
        $this->pdo = $pdo;
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->clock = $clock ?? static fn (): DateTimeImmutable => new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $this->registerDemoHandlers();
    }

    /**
     * Register (or replace) the handler for a task type.
     *
     * @param string   $taskType Name used in enqueue()['task_type'].
     * @param callable $handler  fn(array $params, callable $progress): array. Call
     *                           $progress($done, $total) as work proceeds; return the result
     *                           array; throw (e.g. TaskFailedException) to fail the attempt.
     *
     * Why: real tasks (Notifications, Webhooks, Data Export) plug in here instead of the demo
     * handlers. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
     */
    public function registerTaskHandler(string $taskType, callable $handler): void
    {
        if ($taskType === '') {
            throw new InvalidArgumentException('task_type must not be empty');
        }
        $this->taskHandlers[$taskType] = $handler;
    }

    /**
     * Enqueue a job (POST /jobs/enqueue).
     *
     * @param array $data {task_type: string, params: array, scheduled_at?: string, max_retries?: int}
     * @return array {success: true, job_id: string, status: 'enqueued'}
     * @throws InvalidArgumentException on a missing/unknown task_type, non-array params, a bad
     *                                  scheduled_at or a negative max_retries.
     *
     * Why: rewritten for SQLite; validates input before writing. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (one INSERT).
     */
    public function enqueue(array $data): array
    {
        $taskType = $data['task_type'] ?? null;
        if (!is_string($taskType) || $taskType === '') {
            throw new InvalidArgumentException('task_type is required and must be a string');
        }
        if (!isset($this->taskHandlers[$taskType])) {
            throw new InvalidArgumentException(sprintf('Unknown task type: %s', $taskType));
        }
        if (!isset($data['params']) || !is_array($data['params'])) {
            throw new InvalidArgumentException('params is required and must be an object');
        }
        $maxRetries = $data['max_retries'] ?? 3;
        if (!is_int($maxRetries) || $maxRetries < 0) {
            throw new InvalidArgumentException('max_retries must be a non-negative integer');
        }
        $scheduledAt = null;
        if (isset($data['scheduled_at'])) {
            $scheduledAt = $this->formatTime($this->parseTime($data['scheduled_at'], 'scheduled_at'));
        }

        $jobId = self::uuid();
        $stmt = $this->pdo->prepare(
            "INSERT INTO jobs (id, task_type, params, status, created_at, max_retries, scheduled_at)
             VALUES (:id, :task_type, :params, 'enqueued', :created_at, :max_retries, :scheduled_at)"
        );
        $stmt->execute([
            ':id' => $jobId,
            ':task_type' => $taskType,
            ':params' => json_encode($data['params'], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            ':created_at' => $this->formatTime($this->now()),
            ':max_retries' => $maxRetries,
            ':scheduled_at' => $scheduledAt,
        ]);

        return ['success' => true, 'job_id' => $jobId, 'status' => 'enqueued'];
    }

    /**
     * Job status and details (GET /jobs/:job_id).
     *
     * @param string $jobId
     * @return array {job_id, task_type, status, progress, created_at, started_at, completed_at,
     *               result, error, retry_count, max_retries, next_retry_at, scheduled_at}
     * @throws JobNotFoundException
     *
     * Why: now also returns retry_count, max_retries and error, which the retry tests read.
     * 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (read).
     */
    public function getStatus(string $jobId): array
    {
        $job = $this->getJob($jobId);
        return [
            'job_id' => $job['id'],
            'task_type' => $job['task_type'],
            'status' => $job['status'],
            'progress' => $job['progress'],
            'created_at' => $job['created_at'],
            'started_at' => $job['started_at'],
            'completed_at' => $job['completed_at'],
            'result' => $job['result'] !== null ? json_decode($job['result'], true) : null,
            'error' => $job['error'],
            'retry_count' => (int) $job['retry_count'],
            'max_retries' => (int) $job['max_retries'],
            'next_retry_at' => $job['next_retry_at'],
            'scheduled_at' => $job['scheduled_at'],
        ];
    }

    /**
     * List jobs, oldest first (GET /jobs?status=&task_type=&limit=&offset=).
     *
     * @param array $filters {status?: string, task_type?: string, limit?: int (1..100, default 50), offset?: int}
     * @return array {jobs: list<array>, total: int} where total counts every match, not just the page.
     * @throws InvalidArgumentException on an unknown status.
     *
     * Why: replaced MySQL's SQL_CALC_FOUND_ROWS/FOUND_ROWS with COUNT(*); orders by insertion
     * (rowid) so ties are deterministic. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches the database (read).
     */
    public function listJobs(array $filters = []): array
    {
        $where = [];
        $params = [];
        if (isset($filters['status'])) {
            if (!in_array($filters['status'], self::STATUSES, true)) {
                throw new InvalidArgumentException('Unknown status filter');
            }
            $where[] = 'status = :status';
            $params[':status'] = $filters['status'];
        }
        if (isset($filters['task_type'])) {
            $where[] = 'task_type = :task_type';
            $params[':task_type'] = (string) $filters['task_type'];
        }
        $whereClause = $where ? 'WHERE ' . implode(' AND ', $where) : '';

        $count = $this->pdo->prepare("SELECT COUNT(*) FROM jobs $whereClause");
        $count->execute($params);
        $total = (int) $count->fetchColumn();

        $limit = max(1, min(self::MAX_LIST_LIMIT, (int) ($filters['limit'] ?? 50)));
        $offset = max(0, (int) ($filters['offset'] ?? 0));
        $stmt = $this->pdo->prepare(
            "SELECT id, task_type, status, progress, created_at, started_at, completed_at, result,
                    error, retry_count, max_retries, next_retry_at, scheduled_at
             FROM jobs $whereClause ORDER BY rowid ASC LIMIT :limit OFFSET :offset"
        );
        foreach ($params as $name => $value) {
            $stmt->bindValue($name, $value);
        }
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

        $jobs = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $row['job_id'] = $row['id'];
            $row['result'] = $row['result'] !== null ? json_decode($row['result'], true) : null;
            $jobs[] = $row;
        }
        return ['jobs' => $jobs, 'total' => $total];
    }

    /**
     * Cancel a job that has not started (DELETE /jobs/:job_id).
     *
     * @param string $jobId
     * @return array {success: true, status: 'cancelled'}
     * @throws JobNotFoundException
     * @throws InvalidArgumentException when the job is not 'enqueued' (running, finished, failed).
     *
     * Why: the status check and the update are now one conditional UPDATE, so a worker cannot
     * claim the job between them. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches the database.
     */
    public function cancelJob(string $jobId): array
    {
        $stmt = $this->pdo->prepare("UPDATE jobs SET status = 'cancelled' WHERE id = :id AND status = 'enqueued'");
        $stmt->execute([':id' => $jobId]);
        if ($stmt->rowCount() !== 1) {
            $this->getJob($jobId); // 404 if it does not exist
            throw new InvalidArgumentException('Job can only be cancelled before it starts');
        }
        return ['success' => true, 'status' => 'cancelled'];
    }

    /**
     * Retry a failed job by hand (POST /jobs/:job_id/retry): creates a new enqueued job with the
     * same task, params and max_retries and a fresh set of retries (retry_count 0; it used to carry the
     * old count over, which no longer fits "retry_count counts this job's retries", 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP),
     * and clears the original's next_retry_at so the task cannot run twice. A job can be retried by hand once.
     *
     * @param string $jobId
     * @return array {success: true, new_job_id: string, status: 'enqueued'}
     * @throws JobNotFoundException
     * @throws InvalidArgumentException when the job is not 'failed' or was already retried.
     *
     * Why: the old version left the original's automatic retry pending (double execution) and
     * refused to retry a job that had used up its attempts, which is when a manual retry is
     * needed. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database
     * (one transaction: UPDATE original, INSERT new job).
     */
    public function retryJob(string $jobId): array
    {
        $job = $this->getJob($jobId);
        if ($job['status'] !== 'failed') {
            throw new InvalidArgumentException('Only failed jobs can be retried');
        }

        $newJobId = self::uuid();
        $this->pdo->beginTransaction();
        try {
            $mark = $this->pdo->prepare(
                "UPDATE jobs SET retried_as = :new_id, next_retry_at = NULL
                 WHERE id = :id AND status = 'failed' AND retried_as IS NULL"
            );
            $mark->execute([':new_id' => $newJobId, ':id' => $jobId]);
            if ($mark->rowCount() !== 1) {
                throw new InvalidArgumentException('Job was already retried or is no longer failed');
            }
            $insert = $this->pdo->prepare(
                "INSERT INTO jobs (id, task_type, params, status, created_at, max_retries, retry_count, retry_of)
                 VALUES (:id, :task_type, :params, 'enqueued', :created_at, :max_retries, :retry_count, :retry_of)"
            );
            $insert->execute([
                ':id' => $newJobId,
                ':task_type' => $job['task_type'],
                ':params' => $job['params'],
                ':created_at' => $this->formatTime($this->now()),
                ':max_retries' => (int) $job['max_retries'],
                ':retry_count' => 0,
                ':retry_of' => $jobId,
            ]);
            $this->pdo->commit();
        } catch (Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }

        return ['success' => true, 'new_job_id' => $newJobId, 'status' => 'enqueued'];
    }

    /**
     * Results of a completed job (GET /jobs/:job_id/results).
     *
     * @param string $jobId
     * @return array {job_id, status: 'completed', result: array, completed_at}
     * @throws JobNotFoundException
     * @throws InvalidArgumentException when the job has not completed.
     *
     * Why: unchanged contract; reads the SQLite row. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (read).
     */
    public function getResults(string $jobId): array
    {
        $job = $this->getJob($jobId);
        if ($job['status'] !== 'completed') {
            throw new InvalidArgumentException('Results are only available for completed jobs');
        }
        return [
            'job_id' => $job['id'],
            'status' => $job['status'],
            'result' => $job['result'] !== null ? json_decode($job['result'], true) : null,
            'completed_at' => $job['completed_at'],
        ];
    }

    /**
     * Run one enqueued job now (the worker's step for a known job id). A job whose scheduled_at
     * is still in the future is left untouched.
     *
     * @param string $jobId
     * @return void Status, progress, result or error are written to the job row.
     * @throws JobNotFoundException
     * @throws InvalidArgumentException when the job is not 'enqueued'.
     *
     * Why: the job is claimed with one conditional UPDATE (enqueued -> running) so two workers
     * can never run it twice, and the handler runs outside a transaction so progress is visible
     * while it runs. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. A job waiting for a
     * retry's backoff (next_retry_at in the future) is left alone too (JOBS-03 as amended, same day).
     * Touches the database and whatever the task handler touches.
     */
    public function processJob(string $jobId): void
    {
        $job = $this->getJob($jobId);
        if ($job['status'] !== 'enqueued') {
            throw new InvalidArgumentException('Job is not enqueued');
        }
        $now = $this->now();
        if ($job['scheduled_at'] !== null && $this->parseTime($job['scheduled_at'], 'scheduled_at') > $now) {
            return; // not due yet
        }
        if ($job['next_retry_at'] !== null && $this->parseTime($job['next_retry_at'], 'next_retry_at') > $now) {
            return; // waiting for its retry's backoff (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
        }
        if ($this->claim($jobId, 'enqueued', $now)) {
            $this->execute($jobId);
        }
    }

    /**
     * The worker loop's step: run every job that is due, oldest first: enqueued jobs whose
     * scheduled_at has passed (or is empty) and whose next_retry_at (a scheduled retry) has passed
     * (or is empty). Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: a job waiting for a retry is now 'enqueued'.
     *
     * @param int $limit Most jobs to run in this call.
     * @return list<string> Ids of the jobs this call ran.
     *
     * Why: the old file had no automatic retry at all although the spec requires one.
     * 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database and the task
     * handlers.
     */
    public function runDueJobs(int $limit = 10): array
    {
        $now = $this->now();
        $nowText = $this->formatTime($now);
        // A job waiting for a retry is 'enqueued' with next_retry_at in the future and is skipped until
        // then (JOBS-03 as amended, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
        $stmt = $this->pdo->prepare(
            "SELECT id, status FROM jobs
             WHERE status = 'enqueued' AND (scheduled_at IS NULL OR scheduled_at <= :now1)
               AND (next_retry_at IS NULL OR next_retry_at <= :now2)
             ORDER BY rowid ASC LIMIT :limit"
        );
        $stmt->bindValue(':now1', $nowText);
        $stmt->bindValue(':now2', $nowText);
        $stmt->bindValue(':limit', max(1, $limit), PDO::PARAM_INT);
        $stmt->execute();
        $ran = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            if ($this->claim($row['id'], $row['status'], $now)) {
                $this->execute($row['id']);
                $ran[] = $row['id'];
            }
        }
        return $ran;
    }

    /**
     * Atomically move a due 'enqueued' job (scheduled_at and next_retry_at passed or empty) to 'running'.
     *
     * @return bool True when this caller won the claim.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the 'failed' branch is gone (a waiting retry is 'enqueued').
     *
     * Why: replaces MySQL's SELECT ... FOR UPDATE, which SQLite does not have. 2026-11-10,
     * session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
     */
    private function claim(string $jobId, string $fromStatus, DateTimeImmutable $now): bool
    {
        $nowText = $this->formatTime($now);
        if ($fromStatus !== 'enqueued') {
            return false;
        }
        $stmt = $this->pdo->prepare(
            "UPDATE jobs SET status = 'running', started_at = :now, next_retry_at = NULL, error = NULL
             WHERE id = :id AND status = 'enqueued' AND (scheduled_at IS NULL OR scheduled_at <= :now2)
               AND (next_retry_at IS NULL OR next_retry_at <= :now3)"
        );
        $stmt->execute([':now' => $nowText, ':now2' => $nowText, ':now3' => $nowText, ':id' => $jobId]);
        return $stmt->rowCount() === 1;
    }

    /**
     * Run a claimed ('running') job's handler and record the outcome and a job_runs row.
     *
     * On success: status 'completed', result and completed_at set. On failure: see recordFailure()
     * (retry n scheduled as 'enqueued' while retries are left, else 'failed').
     *
     * Why: see processJob(). 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches the database and the task handler.
     */
    private function execute(string $jobId): void
    {
        $job = $this->getJob($jobId);
        $runId = self::uuid();
        $this->pdo->prepare(
            "INSERT INTO job_runs (id, job_id, status, started_at) VALUES (:id, :job_id, 'running', :started_at)"
        )->execute([':id' => $runId, ':job_id' => $jobId, ':started_at' => $this->formatTime($this->now())]);

        try {
            $params = json_decode($job['params'], true, 512, JSON_THROW_ON_ERROR);
            $handler = $this->taskHandlers[$job['task_type']] ?? null;
            if ($handler === null) {
                throw new TaskFailedException(sprintf('No handler registered for task type %s', $job['task_type']));
            }
            $result = $handler(is_array($params) ? $params : [], function (int $done, int $total) use ($jobId): void {
                $this->updateProgress($jobId, $done, $total);
            });
            if (!is_array($result)) {
                throw new TaskFailedException('Task handler must return an array');
            }
        } catch (Throwable $e) {
            $this->recordFailure($jobId, $runId, $e);
            return;
        }

        $now = $this->formatTime($this->now());
        $resultJson = json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $this->pdo->beginTransaction();
        try {
            $this->pdo->prepare(
                "UPDATE jobs SET status = 'completed', completed_at = :now, result = :result,
                        attempts = attempts + 1, next_retry_at = NULL
                 WHERE id = :id AND status = 'running'"
            )->execute([':now' => $now, ':result' => $resultJson, ':id' => $jobId]);
            $this->pdo->prepare(
                "UPDATE job_runs SET status = 'completed', completed_at = :now, result = :result WHERE id = :id"
            )->execute([':now' => $now, ':result' => $resultJson, ':id' => $runId]);
            $this->pdo->commit();
        } catch (Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /**
     * Record a failed attempt (JOBS-03/04 as amended).
     *
     * Inputs: job id, run id, the error. Output: none. Attempt n = attempts + 1 just failed. If
     * n <= max_retries, retry n is scheduled: status 'enqueued', retry_count = n,
     * next_retry_at = now + 2^(n-1) seconds. Otherwise (attempt max_retries + 1 failed): status 'failed',
     * retry_count = max_retries, next_retry_at null, completed_at now.
     * Why: failures used to be swallowed into status 'enqueued' with a MySQL-only update; then max_retries
     * counted attempts and a waiting job was 'failed' (changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
     * Touches the database.
     */
    private function recordFailure(string $jobId, string $runId, Throwable $error): void
    {
        $job = $this->getJob($jobId);
        $attempts = (int) $job['attempts'] + 1;
        $maxRetries = (int) $job['max_retries'];
        $now = $this->now();
        $retryLeft = $attempts <= $maxRetries;
        $retryCount = $retryLeft ? $attempts : $maxRetries;
        $nextRetryAt = $retryLeft
            ? $this->formatTime($now->modify(sprintf('+%d seconds', 2 ** ($attempts - 1))))
            : null;
        $message = substr($error->getMessage(), 0, 1000);

        $this->pdo->beginTransaction();
        try {
            $this->pdo->prepare(
                "UPDATE jobs SET status = :status, attempts = :attempts, retry_count = :retry_count,
                        error = :error, next_retry_at = :next_retry_at, completed_at = :completed_at
                 WHERE id = :id"
            )->execute([
                ':status' => $retryLeft ? 'enqueued' : 'failed',
                ':attempts' => $attempts,
                ':retry_count' => $retryCount,
                ':error' => $message,
                ':next_retry_at' => $nextRetryAt,
                ':completed_at' => $retryLeft ? null : $this->formatTime($now),
                ':id' => $jobId,
            ]);
            $this->pdo->prepare(
                "UPDATE job_runs SET status = 'failed', completed_at = :now, result = :result WHERE id = :id"
            )->execute([
                ':now' => $this->formatTime($now),
                ':result' => json_encode(['error' => $message]),
                ':id' => $runId,
            ]);
            $this->pdo->commit();
        } catch (Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /**
     * Write "done/total" to the job's progress (its own statement, visible at once).
     *
     * Why: progress is the spec's real-time "345/500". 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
     */
    private function updateProgress(string $jobId, int $done, int $total): void
    {
        $this->pdo->prepare('UPDATE jobs SET progress = :progress WHERE id = :id')
            ->execute([':progress' => sprintf('%d/%d', $done, $total), ':id' => $jobId]);
    }

    /**
     * Load a job row (params left as the stored JSON text).
     *
     * @throws JobNotFoundException
     *
     * Why: the old version decoded params here and again in processJob (a TypeError).
     * 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (read).
     */
    private function getJob(string $jobId): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM jobs WHERE id = :id');
        $stmt->execute([':id' => $jobId]);
        $job = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($job === false) {
            throw new JobNotFoundException('Job not found');
        }
        return $job;
    }

    /**
     * The current time from the injected clock, in UTC.
     *
     * Why: one place for time, so tests can fix it. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
     */
    private function now(): DateTimeImmutable
    {
        return ($this->clock)()->setTimezone(new DateTimeZone('UTC'));
    }

    /**
     * Format a time as UTC ISO 8601 with microseconds (sorts correctly as text).
     *
     * Why: stored times must compare as text in SQL. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
     */
    private function formatTime(DateTimeImmutable $time): string
    {
        return $time->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.u\Z');
    }

    /**
     * Parse a client-supplied time (a string without a zone is read in PHP's default zone).
     *
     * @throws InvalidArgumentException when it is not a valid date/time.
     *
     * Why: scheduled_at used to be stored unchecked. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
     */
    private function parseTime(mixed $value, string $field): DateTimeImmutable
    {
        if (!is_string($value) || $value === '') {
            throw new InvalidArgumentException(sprintf('%s must be a date/time string', $field));
        }
        try {
            return new DateTimeImmutable($value);
        } catch (Exception) {
            throw new InvalidArgumentException(sprintf('%s is not a valid date/time', $field));
        }
    }

    /**
     * A random UUID v4 (random_bytes, a CSPRNG).
     *
     * Why: job ids must not be guessable. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches nothing.
     */
    private static function uuid(): string
    {
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    /**
     * Register the built-in demo handlers. They only simulate work so the queue can be run and
     * tested on its own; `params.failure_points` (item indexes) makes chosen items fail. An
     * attempt in which every item fails throws TaskFailedException. Replace them with real
     * handlers (Notifications, Webhooks, Data Export, ...) via registerTaskHandler().
     *
     * Why: the old handlers slept on every item and never failed a job. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing (no email, HTTP or deletion happens).
     */
    private function registerDemoHandlers(): void
    {
        $this->taskHandlers['send_bulk_email'] = static function (array $params, callable $progress): array {
            [$ok, $errors] = self::simulateItems($params, 'total', 10, $progress,
                static fn (int $i): array => ['user_id' => 1000 + $i, 'error' => 'email_bounced']);
            return ['task_type' => 'send_bulk_email', 'sent' => $ok, 'failed' => count($errors), 'skipped' => 0, 'errors' => $errors];
        };
        $this->taskHandlers['webhook_retry'] = static function (array $params, callable $progress): array {
            [$ok, $errors] = self::simulateItems($params, 'total', 10, $progress,
                static fn (int $i): array => ['webhook_id' => 'wh_' . (2000 + $i), 'error' => 'timeout']);
            return ['task_type' => 'webhook_retry', 'success' => $ok, 'failed' => count($errors), 'errors' => $errors];
        };
        $this->taskHandlers['export_generate'] = static function (array $params, callable $progress): array {
            [$ok] = self::simulateItems($params, 'total', 1000, $progress,
                static fn (int $i): array => ['row' => $i, 'error' => 'unreadable']);
            return ['task_type' => 'export_generate', 'format' => (string) ($params['format'] ?? 'csv'), 'rows' => $ok, 'size_bytes' => $ok * 100];
        };
        $this->taskHandlers['daily_report_generate'] = function (array $params, callable $progress): array {
            [$ok] = self::simulateItems($params, 'metrics', 50, $progress,
                static fn (int $i): array => ['metric' => $i, 'error' => 'unavailable']);
            return ['task_type' => 'daily_report_generate', 'date' => $this->now()->format('Y-m-d'), 'metrics_processed' => $ok, 'data_points' => $ok * 10];
        };
        $this->taskHandlers['cleanup_old_sessions'] = static function (array $params, callable $progress): array {
            [$ok] = self::simulateItems($params, 'session_count', 1000, $progress,
                static fn (int $i): array => ['session' => $i, 'error' => 'locked']);
            return ['task_type' => 'cleanup_old_sessions', 'deleted_sessions' => $ok];
        };
        $this->taskHandlers['delete_user_cascade'] = static function (array $params, callable $progress): array {
            [$ok] = self::simulateItems($params, 'total_items', 6, $progress,
                static fn (int $i): array => ['item' => $i, 'error' => 'locked']);
            return ['task_type' => 'delete_user_cascade', 'user_id' => (int) ($params['user_id'] ?? 0), 'total_deleted' => $ok];
        };
    }

    /**
     * Shared loop of the demo handlers: walks $params[$countKey] items, reports progress after
     * each, and collects an error for every index listed in params.failure_points.
     *
     * @return array{0: int, 1: list<array>} [items that succeeded, error entries]
     * @throws TaskFailedException when there were items and every one failed.
     *
     * Why: one rule for "the attempt failed" across the demo handlers. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
     */
    private static function simulateItems(array $params, string $countKey, int $default, callable $progress, callable $errorFor): array
    {
        $total = max(0, (int) ($params[$countKey] ?? $default));
        $failurePoints = array_flip(array_map('intval', (array) ($params['failure_points'] ?? [])));
        $ok = 0;
        $errors = [];
        for ($i = 0; $i < $total; $i++) {
            if (isset($failurePoints[$i])) {
                $errors[] = $errorFor($i);
            } else {
                $ok++;
            }
            $progress($i + 1, $total);
        }
        if ($total > 0 && $ok === 0) {
            throw new TaskFailedException(sprintf('All %d items failed', $total));
        }
        return [$ok, $errors];
    }
}

/**
 * Route an HTTP request to the queue (the spec's six endpoints).
 *
 * @param JobQueue $jobQueue The queue to use (the caller owns the connection).
 * @param string   $method   HTTP method.
 * @param string   $uri      Path with optional query string.
 * @param string   $body     Raw request body (JSON for POST /jobs/enqueue).
 * @return array{status: int, headers: array<string, string>, body: string}
 *
 * Mount this behind your authentication: the spec's job endpoints carry no owner, so only
 * trusted (admin or internal) callers should reach them.
 *
 * Why: the old router opened a MySQL connection with a hard-coded root/empty-password default
 * and fell through to a 500 on bad JSON. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches the database through the queue.
 */
function handleJobsRequest(JobQueue $jobQueue, string $method, string $uri, string $body): array
{
    $path = parse_url($uri, PHP_URL_PATH) ?: '/';
    parse_str((string) parse_url($uri, PHP_URL_QUERY), $query);
    $json = static fn (int $status, array $payload): array => [
        'status' => $status,
        'headers' => ['Content-Type' => 'application/json'],
        'body' => json_encode($payload, JSON_UNESCAPED_SLASHES),
    ];

    try {
        if ($method === 'POST' && $path === '/jobs/enqueue') {
            $data = json_decode($body, true);
            if (!is_array($data)) {
                throw new InvalidArgumentException('Body must be a JSON object');
            }
            return $json(200, $jobQueue->enqueue($data));
        }
        if ($method === 'POST' && preg_match('#^/jobs/([^/]+)/retry$#', $path, $m)) {
            return $json(200, $jobQueue->retryJob($m[1]));
        }
        if ($method === 'GET' && preg_match('#^/jobs/([^/]+)/results$#', $path, $m)) {
            return $json(200, $jobQueue->getResults($m[1]));
        }
        if ($method === 'GET' && $path === '/jobs') {
            $filters = array_intersect_key($query, array_flip(['status', 'task_type', 'limit', 'offset']));
            return $json(200, $jobQueue->listJobs($filters));
        }
        if ($method === 'GET' && preg_match('#^/jobs/([^/]+)$#', $path, $m)) {
            return $json(200, $jobQueue->getStatus($m[1]));
        }
        if ($method === 'DELETE' && preg_match('#^/jobs/([^/]+)$#', $path, $m)) {
            return $json(200, $jobQueue->cancelJob($m[1]));
        }
        return $json(404, ['success' => false, 'error' => 'not_found']);
    } catch (JobNotFoundException) {
        return $json(404, ['success' => false, 'error' => 'job_not_found']);
    } catch (InvalidArgumentException $e) {
        return $json(400, ['success' => false, 'error' => $e->getMessage()]);
    } catch (Throwable) {
        return $json(500, ['success' => false, 'error' => 'internal_error']);
    }
}

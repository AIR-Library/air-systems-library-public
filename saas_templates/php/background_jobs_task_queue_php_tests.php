<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

// Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the suite never loaded the
// implementation (Class "JobQueue" not found). Test changes are listed where they were made.
require_once __DIR__ . '/background_jobs_task_queue_php.php';

/**
 * Test suite for Background Jobs & Task Queue implementation.
 *
 * Touches: an in-memory SQLite database only.
 */
final class BackgroundJobsTaskQueueTest extends TestCase
{
    private PDO $pdo;
    private JobQueue $jobQueue;

    protected function setUp(): void
    {
        // Use in-memory SQLite for testing
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->exec(JobQueue::DATABASE_SCHEMA);
        $this->jobQueue = new JobQueue($this->pdo);
    }

    public function testEnqueueJobWorkerPicksItUpStatusBecomesRunning(): void
    {
        $data = [
            'task_type' => 'send_bulk_email',
            'params' => ['total' => 5, 'failure_points' => []],
            'max_retries' => 3
        ];
        $response = $this->jobQueue->enqueue($data);
        $this->assertTrue($response['success']);
        $this->assertEquals('enqueued', $response['status']);
        $jobId = $response['job_id'];

        // Simulate worker picking up the job
        $this->jobQueue->processJob($jobId);

        $status = $this->jobQueue->getStatus($jobId);
        $this->assertEquals('completed', $status['status']);
        $this->assertEquals('5/5', $status['progress']);
    }

    public function testJobCompletesStatusBecomesCompletedResultsAvailable(): void
    {
        $data = [
            'task_type' => 'export_generate',
            'params' => ['total' => 10, 'format' => 'csv'],
            'max_retries' => 2
        ];
        $response = $this->jobQueue->enqueue($data);
        $jobId = $response['job_id'];

        $this->jobQueue->processJob($jobId);

        $status = $this->jobQueue->getStatus($jobId);
        $this->assertEquals('completed', $status['status']);
        $this->assertEquals('10/10', $status['progress']);

        $results = $this->jobQueue->getResults($jobId);
        $this->assertEquals('completed', $results['status']);
        $this->assertIsArray($results['result']); // was $this->IsArray(...), a constraint factory that asserted nothing
        $this->assertArrayHasKey('task_type', $results['result']);
        $this->assertEquals('export_generate', $results['result']['task_type']);
    }

    public function testJobFailsAutoRetriesWithExponentialBackoff(): void
    {
        $data = [
            'task_type' => 'webhook_retry',
            'params' => ['total' => 2, 'failure_points' => [0, 1]], // All fail
            'max_retries' => 2
        ];
        $response = $this->jobQueue->enqueue($data);
        $jobId = $response['job_id'];

        // First attempt
        // The spec's backoff is 1s, 2s, 4s, ...: the first retry is due exactly 1s after the
        // failure, so next_retry_at must lie between (before + 1s) and (after + 1s). The old
        // assertion (> now + 1s, taken after the call) required a first delay above 1s, which
        // contradicts the spec.
        $before = new DateTimeImmutable();
        $this->jobQueue->processJob($jobId);
        $after = new DateTimeImmutable();
        $status = $this->jobQueue->getStatus($jobId);
        $this->assertEquals('failed', $status['status']);
        $this->assertEquals(1, $status['retry_count']);
        $this->assertNotNull($status['next_retry_at']);
        $this->assertGreaterThanOrEqual($before->modify('+1 second'), new DateTimeImmutable($status['next_retry_at']));
        $this->assertLessThanOrEqual($after->modify('+1 second'), new DateTimeImmutable($status['next_retry_at']));

        // Wait for backoff (simulate by setting time)
        // In real test, we'd wait or mock time; here we force retry via retryJob
        $retryResponse = $this->jobQueue->retryJob($jobId);
        $this->assertTrue($retryResponse['success']);
        $this->assertEquals('enqueued', $retryResponse['status']);
        $retryJobId = $retryResponse['new_job_id'];

        // Second attempt: the delay doubles to 2s (same bracketing as above)
        $before = new DateTimeImmutable();
        $this->jobQueue->processJob($retryJobId);
        $after = new DateTimeImmutable();
        $status = $this->jobQueue->getStatus($retryJobId);
        $this->assertEquals('failed', $status['status']);
        $this->assertEquals(2, $status['retry_count']);
        $this->assertNotNull($status['next_retry_at']);
        $this->assertGreaterThanOrEqual($before->modify('+2 seconds'), new DateTimeImmutable($status['next_retry_at']));
        $this->assertLessThanOrEqual($after->modify('+2 seconds'), new DateTimeImmutable($status['next_retry_at']));

        // The manual retry superseded the original's pending automatic retry (no double run)
        $this->assertNull($this->jobQueue->getStatus($jobId)['next_retry_at']);
    }

    public function testJobExceedsMaxRetriesStatusBecomesFailed(): void
    {
        $data = [
            'task_type' => 'cleanup_old_sessions',
            'params' => ['session_count' => 1, 'failure_points' => [0]],
            'max_retries' => 1
        ];
        $response = $this->jobQueue->enqueue($data);
        $jobId = $response['job_id'];

        // First attempt (will fail)
        $this->jobQueue->processJob($jobId);
        $status = $this->jobQueue->getStatus($jobId);
        $this->assertEquals('failed', $status['status']);
        $this->assertEquals(1, $status['retry_count']);
        $this->assertEquals(1, $status['max_retries']);
        $this->assertNull($status['next_retry_at']); // No more retries
    }

    public function testUserCancelsBeforeJobStartsStatusBecomesCancelled(): void
    {
        $data = [
            'task_type' => 'daily_report_generate',
            'params' => ['metrics' => 5],
            'max_retries' => 3
        ];
        $response = $this->jobQueue->enqueue($data);
        $jobId = $response['job_id'];

        $response = $this->jobQueue->cancelJob($jobId);
        $this->assertTrue($response['success']);
        $this->assertEquals('cancelled', $response['status']);

        $status = $this->jobQueue->getStatus($jobId);
        $this->assertEquals('cancelled', $status['status']);
    }

    public function testProgressTrackingUpdatesInRealTime(): void
    {
        $data = [
            'task_type' => 'send_bulk_email',
            'params' => ['total' => 100, 'failure_points' => []],
            'max_retries' => 3
        ];
        $response = $this->jobQueue->enqueue($data);
        $jobId = $response['job_id'];

        // We cannot test real-time updates without a worker, but we can verify
        // that the progress field gets updated during processing by checking
        // the internal state via a mock or by checking after processing.
        // Instead, we test that the progress field is updated by the handler.
        // We'll test the handler directly via a job that reports progress.
        // Since we don't expose progress mid-job in the API, we test the
        // final progress after completion.
        $this->jobQueue->processJob($jobId);
        $status = $this->jobQueue->getStatus($jobId);
        $this->assertEquals('100/100', $status['progress']);
    }

    public function testScheduledJobsOnlyRunAfterScheduledAtTime(): void
    {
        $pastTime = (new DateTimeImmutable())->modify('-1 hour')->format('Y-m-d H:i:s');
        $futureTime = (new DateTimeImmutable())->modify('+1 hour')->format('Y-m-d H:i:s');

        // Past scheduled job should run immediately
        $dataPast = [
            'task_type' => 'send_bulk_email',
            'params' => ['total' => 1],
            'scheduled_at' => $pastTime
        ];
        $responsePast = $this->jobQueue->enqueue($dataPast);
        $this->jobQueue->processJob($responsePast['job_id']); // was ['jobId']: enqueue returns job_id (spec)
        $statusPast = $this->jobQueue->getStatus($responsePast['job_id']);
        $this->assertEquals('completed', $statusPast['status']);

        // Future scheduled job should not run yet
        $dataFuture = [
            'task_type' => 'send_bulk_email',
            'params' => ['total' => 1],
            'scheduled_at' => $futureTime
        ];
        $responseFuture = $this->jobQueue->enqueue($dataFuture);
        $this->jobQueue->processJob($responseFuture['job_id']);
        $statusFuture = $this->jobQueue->getStatus($responseFuture['job_id']);
        $this->assertEquals('enqueued', $statusFuture['status']); // Still enqueued
        $this->assertNull($statusFuture['started_at']);
    }

    public function testBulkJobProcessedWithoutBlockingRequest(): void
    {
        // We test that enqueue returns quickly regardless of job size
        $start = microtime(true);
        $data = [
            'task_type' => 'delete_user_cascade',
            'params' => ['total_items' => 10000],
            'max_retries' => 1
        ];
        $response = $this->jobQueue->enqueue($data);
        $end = microtime(true);
        $this->assertTrue($response['success']);
        $this->assertLessThan(0.1, $end - $start); // Enqueue should be fast (was `- start`, an undefined constant)

        // Job should be enqueued, not yet processed
        $status = $this->jobQueue->getStatus($response['job_id']);
        $this->assertEquals('enqueued', $status['status']);
    }

    public function testResultsAvailableAfterCompletion(): void
    {
        $data = [
            'task_type' => 'send_bulk_email',
            'params' => [
                'total' => 3,
                'failure_points' => [1] // Second item fails
            ],
            'max_retries' => 3
        ];
        $response = $this->jobQueue->enqueue($data);
        $jobId = $response['job_id'];

        $this->jobQueue->processJob($jobId);
        $results = $this->jobQueue->getResults($jobId);

        $this->assertEquals('completed', $results['status']);
        $this->assertIsArray($results['result']);
        $this->assertEquals('send_bulk_email', $results['result']['task_type']);
        $this->assertEquals(2, $results['result']['sent']);
        $this->assertEquals(1, $results['result']['failed']);
        $this->assertEquals(0, $results['result']['skipped']);
        $this->assertCount(1, $results['result']['errors']);
        $this->assertEquals('email_bounced', $results['result']['errors'][0]['error']);
        $this->assertIsInt($results['result']['errors'][0]['user_id']);
        $this->assertNotNull($results['completed_at']);
    }

    public function testListJobsFilterByStatusAndTaskType(): void
    {
        // Enqueue various jobs
        $this->jobQueue->enqueue([
            'task_type' => 'send_bulk_email',
            'params' => ['total' => 1]
        ]);
        $this->jobQueue->enqueue([
            'task_type' => 'webhook_retry',
            'params' => ['total' => 1]
        ]);
        $this->jobQueue->enqueue([
            'task_type' => 'send_bulk_email',
            'params' => ['total' => 1]
        ]);

        // List all
        $all = $this->jobQueue->listJobs();
        $this->assertEquals(3, $all['total']);

        // Filter by status enqueued
        $enqueued = $this->jobQueue->listJobs(['status' => 'enqueued']);
        $this->assertEquals(3, $enqueued['total']);

        // Filter by task_type
        $emails = $this->jobQueue->listJobs(['task_type' => 'send_bulk_email']);
        $this->assertEquals(2, $emails['total']);

        // Filter by both
        $emailEnqueued = $this->jobQueue->listJobs([
            'status' => 'enqueued',
            'task_type' => 'send_bulk_email'
        ]);
        $this->assertEquals(2, $emailEnqueued['total']);

        // Process one email job
        $emailJob = $this->jobQueue->listJobs(['task_type' => 'send_bulk_email', 'limit' => 1])['jobs'][0];
        $this->jobQueue->processJob($emailJob['id']);

        // Now list running (should be 0 as it completed quickly)
        $running = $this->jobQueue->listJobs(['status' => 'running']);
        $this->assertEquals(0, $running['total']);

        // List completed
        $completed = $this->jobQueue->listJobs(['status' => 'completed']);
        $this->assertEquals(1, $completed['total']);
    }

    public function testDeleteJobThatIsAlreadyRunningReturnsError(): void
    {
        $data = [
            'task_type' => 'send_bulk_email',
            'params' => ['total' => 5],
            'max_retries' => 3
        ];
        $response = $this->jobQueue->enqueue($data);
        $jobId = $response['job_id'];

        // Mark as running manually to simulate (through the test's own handle on the same
        // connection; JobQueue's $pdo is private, so `$this->jobQueue->pdo` could never work)
        $this->pdo->prepare(
            "UPDATE jobs SET status = 'running' WHERE id = :id"
        )->execute([':id' => $jobId]);

        $this->expectException(InvalidArgumentException::class);
        $this->jobQueue->cancelJob($jobId);
    }

    public function testRetryJobThatIsNotFailedReturnsError(): void
    {
        $data = [
            'task_type' => 'send_bulk_email',
            'params' => ['total' => 1],
            'max_retries' => 3
        ];
        $response = $this->jobQueue->enqueue($data);
        $jobId = $response['job_id'];

        $this->expectException(InvalidArgumentException::class);
        $this->jobQueue->retryJob($jobId);
    }

    public function testGetResultsForNonCompletedJobReturnsError(): void
    {
        $data = [
            'task_type' => 'send_bulk_email',
            'params' => ['total' => 1],
            'max_retries' => 3
        ];
        $response = $this->jobQueue->enqueue($data);
        $jobId = $response['job_id']; // was ['jobId']: enqueue returns job_id (spec)

        $this->expectException(InvalidArgumentException::class);
        $this->jobQueue->getResults($jobId);
    }

    /**
     * Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): the spec's "auto-retries with
     * exponential backoff" was only exercised through a manual retry. With a controllable clock,
     * the worker must leave a failed job alone until next_retry_at, then run it again by itself,
     * and fail it for good once its attempts are used up.
     */
    public function testWorkerAutoRetriesFailedJobAfterBackoff(): void
    {
        $now = new DateTimeImmutable('2026-01-01T00:00:00Z');
        $queue = new JobQueue($this->pdo, function () use (&$now): DateTimeImmutable {
            return $now;
        });
        $jobId = $queue->enqueue([
            'task_type' => 'webhook_retry',
            'params' => ['total' => 1, 'failure_points' => [0]],
            'max_retries' => 2,
        ])['job_id'];

        $this->assertSame([$jobId], $queue->runDueJobs());
        $status = $queue->getStatus($jobId);
        $this->assertEquals('failed', $status['status']);
        $this->assertEquals(1, $status['retry_count']);
        $this->assertEquals(new DateTimeImmutable('2026-01-01T00:00:01Z'), new DateTimeImmutable($status['next_retry_at']));

        $now = $now->modify('+500 milliseconds');
        $this->assertSame([], $queue->runDueJobs()); // backoff not elapsed

        $now = $now->modify('+500 milliseconds');
        $this->assertSame([$jobId], $queue->runDueJobs()); // automatic retry
        $status = $queue->getStatus($jobId);
        $this->assertEquals('failed', $status['status']);
        $this->assertEquals(2, $status['retry_count']);
        $this->assertNull($status['next_retry_at']); // attempts used up

        $now = $now->modify('+1 hour');
        $this->assertSame([], $queue->runDueJobs());
    }
}

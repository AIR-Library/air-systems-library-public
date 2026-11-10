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

    // JOBS-01
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

        // "status becomes running": a handler reads its own job's status while the worker runs it.
        $seen = null;
        $this->jobQueue->registerTaskHandler('probe', function (array $params, callable $progress) use (&$seen, &$probeId): array {
            $seen = $this->jobQueue->getStatus($probeId);
            return ['ok' => true];
        });
        $probeId = $this->jobQueue->enqueue(['task_type' => 'probe', 'params' => []])['job_id'];
        $this->assertSame([$probeId], $this->jobQueue->runDueJobs());
        $this->assertEquals('running', $seen['status']);
        $this->assertNotNull($seen['started_at']);
    }

    // JOBS-02
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

    /**
     * A queue on a settable fixed clock, plus a handler 'always_fails' that counts its runs and throws.
     * Why: the JOBS-03/04 tests drive the worker through backoff without sleeping. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * @return array{0: JobQueue, 1: Closure(string): void} the queue and a function that sets the clock
     */
    private function clockedQueue(int &$runs): array
    {
        $now = new DateTimeImmutable('2026-01-01T00:00:00Z');
        $queue = new JobQueue($this->pdo, function () use (&$now): DateTimeImmutable {
            return $now;
        });
        $queue->registerTaskHandler('always_fails', function (array $params, callable $progress) use (&$runs): array {
            $runs++;
            throw new TaskFailedException('boom');
        });
        $set = function (string $at) use (&$now): void {
            $now = new DateTimeImmutable($at);
        };
        return [$queue, $set];
    }

    /**
     * JOBS-03 as amended: a failing job is retried by the worker on its own: retry 1 after 1s, retry 2 after a
     * further 2s, retry 3 after 4s; while it waits its status is 'enqueued', retry_count = n, and the worker
     * skips it until next_retry_at.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the old test expected status 'failed' while waiting and drove the
     * second attempt through a manual retry; the amended spec keeps a waiting job 'enqueued'.
     */
    // JOBS-03
    public function testJobFailsAutoRetriesWithExponentialBackoff(): void
    {
        $runs = 0;
        [$queue, $setClock] = $this->clockedQueue($runs);
        $jobId = $queue->enqueue(['task_type' => 'always_fails', 'params' => [], 'max_retries' => 3])['job_id'];

        $expect = [
            // [run at, retry_count after, next_retry_at after]
            ['2026-01-01T00:00:00Z', 1, '2026-01-01T00:00:01Z'],
            ['2026-01-01T00:00:01Z', 2, '2026-01-01T00:00:03Z'],
            ['2026-01-01T00:00:03Z', 3, '2026-01-01T00:00:07Z'],
        ];
        foreach ($expect as $i => [$at, $retryCount, $nextAt]) {
            $setClock($at);
            $this->assertSame([$jobId], $queue->runDueJobs(), "attempt " . ($i + 1) . " runs at $at");
            $status = $queue->getStatus($jobId);
            $this->assertEquals('enqueued', $status['status']);
            $this->assertEquals($retryCount, $status['retry_count']);
            $this->assertEquals(new DateTimeImmutable($nextAt), new DateTimeImmutable($status['next_retry_at']));
            // Just before the backoff ends the worker leaves it alone, and processJob does too.
            $setClock((new DateTimeImmutable($nextAt))->modify('-1 millisecond')->format('Y-m-d\TH:i:s.uP'));
            $this->assertSame([], $queue->runDueJobs());
            $queue->processJob($jobId);
            $this->assertEquals('enqueued', $queue->getStatus($jobId)['status']);
        }
        $this->assertSame(3, $runs);
    }

    /**
     * JOBS-04 as amended: with max_retries = 3 the job runs 4 times (the first attempt plus 3 retries), then
     * status 'failed', retry_count = 3, next_retry_at null, and the worker never runs it again. max_retries 0
     * means one run and no retry.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: max_retries used to count attempts (max_retries 1 = no retry).
     */
    // JOBS-04
    public function testJobExceedsMaxRetriesStatusBecomesFailed(): void
    {
        $runs = 0;
        [$queue, $setClock] = $this->clockedQueue($runs);
        $jobId = $queue->enqueue(['task_type' => 'always_fails', 'params' => [], 'max_retries' => 3])['job_id'];
        foreach (['00:00:00', '00:00:01', '00:00:03', '00:00:07'] as $at) {
            $setClock("2026-01-01T{$at}Z");
            $this->assertSame([$jobId], $queue->runDueJobs());
        }
        $this->assertSame(4, $runs);
        $status = $queue->getStatus($jobId);
        $this->assertEquals('failed', $status['status']);
        $this->assertEquals(3, $status['retry_count']);
        $this->assertEquals(3, $status['max_retries']);
        $this->assertNull($status['next_retry_at']); // No more retries
        $setClock('2026-01-02T00:00:00Z');
        $this->assertSame([], $queue->runDueJobs());
        $this->assertSame(4, $runs);

        $runs = 0;
        $once = $queue->enqueue(['task_type' => 'always_fails', 'params' => [], 'max_retries' => 0])['job_id'];
        $this->assertSame([$once], $queue->runDueJobs());
        $status = $queue->getStatus($once);
        $this->assertSame(['failed', 0, null], [$status['status'], $status['retry_count'], $status['next_retry_at']]);
        $this->assertSame(1, $runs);
    }

    /**
     * A failed job (retries used up) can be retried by hand once: a new enqueued job with the same task and
     * a fresh retry_count; the original keeps no pending retry. Why: the manual-retry part of the old
     * backoff test, kept as its own test (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: in-memory SQLite.
     */
    public function testManualRetryOfFailedJobCreatesFreshJob(): void
    {
        $runs = 0;
        [$queue, $setClock] = $this->clockedQueue($runs);
        $jobId = $queue->enqueue(['task_type' => 'always_fails', 'params' => [], 'max_retries' => 0])['job_id'];
        $queue->runDueJobs();
        $retry = $queue->retryJob($jobId);
        $this->assertSame('enqueued', $retry['status']);
        $new = $queue->getStatus($retry['new_job_id']);
        $this->assertSame(['enqueued', 0, 0], [$new['status'], $new['retry_count'], $new['max_retries']]);
        $this->assertNull($queue->getStatus($jobId)['next_retry_at']);
        $this->expectException(InvalidArgumentException::class);
        $queue->retryJob($jobId); // only once
    }

    // JOBS-05
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

    // JOBS-06
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

        // Real time: a handler that reports 45/100 sees that progress through getStatus while it runs.
        $midRun = null;
        $this->jobQueue->registerTaskHandler('progress_probe', function (array $params, callable $progress) use (&$midRun, &$probeId): array {
            $progress(45, 100);
            $midRun = $this->jobQueue->getStatus($probeId)['progress'];
            $progress(100, 100);
            return ['ok' => true];
        });
        $probeId = $this->jobQueue->enqueue(['task_type' => 'progress_probe', 'params' => []])['job_id'];
        $this->jobQueue->processJob($probeId);
        $this->assertSame('45/100', $midRun);
    }

    // JOBS-07
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

    // JOBS-08
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

        // The worker then processes all 10,000 items (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the
        // test never ran the bulk job).
        $this->assertSame([$response['job_id']], $this->jobQueue->runDueJobs());
        $status = $this->jobQueue->getStatus($response['job_id']);
        $this->assertEquals('completed', $status['status']);
        $this->assertEquals('10000/10000', $status['progress']);
        $this->assertSame(10000, $this->jobQueue->getResults($response['job_id'])['result']['total_deleted']);
    }

    // JOBS-09
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
     * the worker must leave a waiting job alone until next_retry_at, then run it again by itself,
     * and fail it for good once its retries are used up. Changed later the same day for the
     * amended JOBS-03/04: max_retries 2 means 3 runs, a waiting job is 'enqueued', and the final
     * retry_count is max_retries.
     */
    // JOBS-03
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
        $this->assertEquals('enqueued', $status['status']);
        $this->assertEquals(1, $status['retry_count']);
        $this->assertEquals(new DateTimeImmutable('2026-01-01T00:00:01Z'), new DateTimeImmutable($status['next_retry_at']));

        $now = $now->modify('+500 milliseconds');
        $this->assertSame([], $queue->runDueJobs()); // backoff not elapsed

        $now = $now->modify('+500 milliseconds');
        $this->assertSame([$jobId], $queue->runDueJobs()); // automatic retry 1
        $status = $queue->getStatus($jobId);
        $this->assertEquals('enqueued', $status['status']);
        $this->assertEquals(2, $status['retry_count']);
        $this->assertEquals(new DateTimeImmutable('2026-01-01T00:00:03Z'), new DateTimeImmutable($status['next_retry_at']));

        $now = $now->modify('+2 seconds');
        $this->assertSame([$jobId], $queue->runDueJobs()); // automatic retry 2, the last
        $status = $queue->getStatus($jobId);
        $this->assertEquals('failed', $status['status']);
        $this->assertEquals(2, $status['retry_count']);
        $this->assertNull($status['next_retry_at']); // retries used up

        $now = $now->modify('+1 hour');
        $this->assertSame([], $queue->runDueJobs());
    }
}

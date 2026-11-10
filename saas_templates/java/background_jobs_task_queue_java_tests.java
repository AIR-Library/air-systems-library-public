package com.saas.jobs;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.*;

import java.sql.*;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for BackgroundJobsTaskQueue.
 * Covers all spec-required test cases.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class BackgroundJobsTaskQueueTests {

    private static Connection connection;
    private static BackgroundJobsTaskQueue queue;
    private static ObjectMapper objectMapper;

    @BeforeAll
    static void setup() throws Exception {
        // Use in-memory H2 database for testing
        connection = DriverManager.getConnection("jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1", "sa", "");
        objectMapper = new ObjectMapper();
        queue = new BackgroundJobsTaskQueue(connection, 2, 50);
        queue.start();
    }

    @AfterAll
    static void teardown() {
        if (queue != null) {
            queue.stop();
        }
        if (connection != null) {
            try {
                connection.close();
            } catch (SQLException e) {
                // Ignore
            }
        }
    }

    @BeforeEach
    void cleanDatabase() throws Exception {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("DELETE FROM job_runs");
            stmt.execute("DELETE FROM jobs");
        }
    }

    /**
     * Test 1: Enqueue job, worker picks it up, status becomes running
     */
    @Test
    @Order(1)
    void testEnqueueAndWorkerPicksUp() throws Exception {
        ObjectNode params = objectMapper.createObjectNode();
        params.put("template_key", "test_template");

        Map<String, Object> enqueueResponse = queue.enqueueJob("send_bulk_email", params, null, 3);
        assertTrue((Boolean) enqueueResponse.get("success"));
        String jobId = (String) enqueueResponse.get("job_id");
        assertEquals("enqueued", enqueueResponse.get("status"));

        // Wait for job to be picked up and start running
        Thread.sleep(200);

        Map<String, Object> status = queue.getJobStatus(jobId);
        String jobStatus = (String) status.get("status");
        // Job should be running or completed (fast test job)
        assertTrue("running".equals(jobStatus) || "completed".equals(jobStatus),
                "Expected running or completed, got: " + jobStatus);
    }

    /**
     * Test 2: Job completes, status becomes completed, results available
     */
    // JOBS-02
    @Test
    @Order(2)
    void testJobCompletesWithResults() throws Exception {
        ObjectNode params = objectMapper.createObjectNode();
        params.put("report_type", "metrics");

        Map<String, Object> enqueueResponse = queue.enqueueJob("daily_report_generate", params, null, 3);
        String jobId = (String) enqueueResponse.get("job_id");

        // Wait for completion
        waitForJobCompletion(jobId, 5000);

        Map<String, Object> status = queue.getJobStatus(jobId);
        assertEquals("completed", status.get("status"));

        Map<String, Object> results = queue.getJobResults(jobId);
        assertEquals("completed", results.get("status"));
        assertNotNull(results.get("result"));
        assertNotNull(results.get("completed_at"));
    }

    /**
     * Test 3: Job fails, auto-retries with exponential backoff
     */
    @Test
    @Order(3)
    void testJobFailsAndRetriesWithBackoff() throws Exception {
        // Register a failing task handler
        queue.registerTaskHandler("test_failing_task", (context, job) -> {
            if (job.retryCount < 2) {
                context.markFailed("Simulated failure");
            } else {
                context.setResult(Map.of("success", true));
                context.markCompleted();
            }
        });

        ObjectNode params = objectMapper.createObjectNode();
        Map<String, Object> enqueueResponse = queue.enqueueJob("test_failing_task", params, null, 3);
        String jobId = (String) enqueueResponse.get("job_id");

        // Wait for retries to happen (backoff: 1s + 2s = 3s + processing time)
        waitForJobCompletion(jobId, 10000);

        Map<String, Object> status = queue.getJobStatus(jobId);
        // After 2 failures, it should succeed on 3rd attempt
        assertEquals("completed", status.get("status"));
        assertTrue((Integer) status.get("retry_count") >= 2);
    }

    /**
     * Test 4: Job exceeds max_retries, status becomes failed
     */
    @Test
    @Order(4)
    void testJobExceedsMaxRetries() throws Exception {
        // Register a always-failing task handler
        queue.registerTaskHandler("test_always_fails", (context, job) -> {
            context.markFailed("Always fails");
        });

        ObjectNode params = objectMapper.createObjectNode();
        Map<String, Object> enqueueResponse = queue.enqueueJob("test_always_fails", params, null, 2);
        String jobId = (String) enqueueResponse.get("job_id");

        // Wait for all retries to be exhausted
        // Backoff: 1s, 2s = 3s total
        waitForJobCompletion(jobId, 10000);

        Map<String, Object> status = queue.getJobStatus(jobId);
        assertEquals("failed", status.get("status"));
        assertEquals(2, (Integer) status.get("retry_count"));
        assertNotNull(status.get("error"));
    }

    /**
     * Test 5: User cancels before job starts, status becomes cancelled
     */
    // JOBS-05
    @Test
    @Order(5)
    void testCancelJobBeforeStart() throws Exception {
        // Use a scheduled job in the future so it won't be picked up immediately
        Instant futureTime = Instant.now().plusSeconds(10);
        ObjectNode params = objectMapper.createObjectNode();
        params.put("template_key", "test");

        Map<String, Object> enqueueResponse = queue.enqueueJob("send_bulk_email", params, futureTime, 3);
        String jobId = (String) enqueueResponse.get("job_id");

        // Cancel immediately
        Map<String, Object> cancelResponse = queue.cancelJob(jobId);
        assertTrue((Boolean) cancelResponse.get("success"));
        assertEquals("cancelled", cancelResponse.get("status"));

        // Verify status
        Map<String, Object> status = queue.getJobStatus(jobId);
        assertEquals("cancelled", status.get("status"));
    }

    /**
     * Test 6: Progress tracking (45/100 updates in real-time)
     */
    @Test
    @Order(6)
    void testProgressTracking() throws Exception {
        // Register a task that updates progress
        queue.registerTaskHandler("test_progress_task", (context, job) -> {
            int total = 100;
            for (int i = 1; i <= total; i++) {
                context.updateProgress(i + "/" + total);
                try {
                    Thread.sleep(5); // Small delay to simulate work
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            context.setResult(Map.of("processed", total));
            context.markCompleted();
        });

        ObjectNode params = objectMapper.createObjectNode();
        Map<String, Object> enqueueResponse = queue.enqueueJob("test_progress_task", params, null, 3);
        String jobId = (String) enqueueResponse.get("job_id");

        // Wait a bit and check progress
        Thread.sleep(100);
        Map<String, Object> status = queue.getJobStatus(jobId);
        String progress = (String) status.get("progress");
        assertNotNull(progress);
        // Progress should be in format "X/Y"
        assertTrue(progress.matches("\\d+/\\d+"), "Progress should be in X/Y format, got: " + progress);

        // Wait for completion
        waitForJobCompletion(jobId, 5000);
        status = queue.getJobStatus(jobId);
        assertEquals("completed", status.get("status"));
        assertEquals("100/100", status.get("progress"));
    }

    /**
     * Test 7: Scheduled jobs: only run after scheduled_at time
     */
    @Test
    @Order(7)
    void testScheduledJobsRunAfterScheduledAt() throws Exception {
        // Schedule job 1 second in the future
        Instant scheduledTime = Instant.now().plusSeconds(1);
        ObjectNode params = objectMapper.createObjectNode();
        params.put("report_type", "test");

        Map<String, Object> enqueueResponse = queue.enqueueJob("daily_report_generate", params, scheduledTime, 3);
        String jobId = (String) enqueueResponse.get("job_id");

        // Immediately check - should still be enqueued
        Thread.sleep(100);
        Map<String, Object> status = queue.getJobStatus(jobId);
        assertEquals("enqueued", status.get("status"));

        // Wait for scheduled time to pass
        Thread.sleep(1500);
        status = queue.getJobStatus(jobId);
        assertEquals("completed", status.get("status"));
    }

    /**
     * Test 8: Bulk job: 10,000 items processed without blocking request
     */
    @Test
    @Order(8)
    void testBulkJobProcessesWithoutBlocking() throws Exception {
        long startTime = System.currentTimeMillis();

        ObjectNode params = objectMapper.createObjectNode();
        params.put("template_key", "bulk_test");

        // Enqueue should return quickly
        Map<String, Object> enqueueResponse = queue.enqueueJob("send_bulk_email", params, null, 3);
        long enqueueTime = System.currentTimeMillis() - startTime;

        // Enqueue should be fast (< 100ms)
        assertTrue(enqueueTime < 100, "Enqueue took too long: " + enqueueTime + "ms");

        String jobId = (String) enqueueResponse.get("job_id");

        // Wait for completion
        waitForJobCompletion(jobId, 10000);

        Map<String, Object> status = queue.getJobStatus(jobId);
        assertEquals("completed", status.get("status"));
    }

    /**
     * Test 9: Results available after completion
     */
    // JOBS-09
    @Test
    @Order(9)
    void testResultsAvailableAfterCompletion() throws Exception {
        ObjectNode params = objectMapper.createObjectNode();
        params.put("export_type", "csv");

        Map<String, Object> enqueueResponse = queue.enqueueJob("export_generate", params, null, 3);
        String jobId = (String) enqueueResponse.get("job_id");

        // Wait for completion
        waitForJobCompletion(jobId, 5000);

        Map<String, Object> results = queue.getJobResults(jobId);
        assertEquals("completed", results.get("status"));
        assertNotNull(results.get("result"));
        assertNotNull(results.get("completed_at"));

        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) results.get("result");
        assertNotNull(result.get("export_type"));
        assertNotNull(result.get("records_exported"));
    }

    /**
     * Test: List jobs with filters
     */
    @Test
    @Order(10)
    void testListJobsWithFilters() throws Exception {
        // Enqueue several jobs
        for (int i = 0; i < 5; i++) {
            ObjectNode params = objectMapper.createObjectNode();
            params.put("template_key", "test_" + i);
            queue.enqueueJob("send_bulk_email", params, null, 3);
        }

        // List all jobs
        Map<String, Object> allJobs = queue.listJobs(null, null, 10);
        assertTrue((Integer) allJobs.get("total") >= 5);

        // List by task type
        Map<String, Object> filteredJobs = queue.listJobs(null, "send_bulk_email", 10);
        assertTrue((Integer) filteredJobs.get("total") >= 5);

        // List by status
        Map<String, Object> enqueuedJobs = queue.listJobs("enqueued", null, 10);
        assertNotNull(enqueuedJobs.get("jobs"));
    }

    /**
     * Test: Retry failed job creates new job
     */
    @Test
    @Order(11)
    void testRetryFailedJob() throws Exception {
        // Create a job that will fail
        queue.registerTaskHandler("test_retry_task", (context, job) -> {
            context.markFailed("Test failure");
        });

        ObjectNode params = objectMapper.createObjectNode();
        Map<String, Object> enqueueResponse = queue.enqueueJob("test_retry_task", params, null, 1);
        String jobId = (String) enqueueResponse.get("job_id");

        // Wait for it to fail
        waitForJobCompletion(jobId, 5000);

        Map<String, Object> status = queue.getJobStatus(jobId);
        assertEquals("failed", status.get("status"));

        // Retry the job
        Map<String, Object> retryResponse = queue.retryJob(jobId);
        assertTrue((Boolean) retryResponse.get("success"));
        assertNotNull(retryResponse.get("new_job_id"));
        assertEquals("enqueued", retryResponse.get("status"));

        String newJobId = (String) retryResponse.get("new_job_id");
        assertNotEquals(jobId, newJobId);
    }

    /**
     * Test: Cancel job that is already running should fail
     */
    @Test
    @Order(12)
    void testCancelRunningJobFails() throws Exception {
        // Register a slow task
        queue.registerTaskHandler("test_slow_task", (context, job) -> {
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            context.setResult(Map.of("done", true));
            context.markCompleted();
        });

        ObjectNode params = objectMapper.createObjectNode();
        Map<String, Object> enqueueResponse = queue.enqueueJob("test_slow_task", params, null, 3);
        String jobId = (String) enqueueResponse.get("job_id");

        // Wait for it to start running
        Thread.sleep(200);

        Map<String, Object> status = queue.getJobStatus(jobId);
        if ("running".equals(status.get("status"))) {
            // Try to cancel - should fail
            assertThrows(BackgroundJobsTaskQueue.JobNotCancellableException.class,
                    () -> queue.cancelJob(jobId));
        }

        // Wait for completion
        waitForJobCompletion(jobId, 10000);
    }

    /**
     * Test: Get job status for non-existent job throws exception
     */
    @Test
    @Order(13)
    void testGetNonExistentJob() {
        assertThrows(BackgroundJobsTaskQueue.JobNotFoundException.class,
                () -> queue.getJobStatus("non-existent-job-id"));
    }

    /**
     * Test: Get results for non-completed job throws exception
     */
    @Test
    @Order(14)
    void testGetResultsForNonCompletedJob() throws Exception {
        // Schedule job in future
        Instant futureTime = Instant.now().plusSeconds(10);
        ObjectNode params = objectMapper.createObjectNode();
        Map<String, Object> enqueueResponse = queue.enqueueJob("daily_report_generate", params, futureTime, 3);
        String jobId = (String) enqueueResponse.get("job_id");

        // Try to get results - should fail
        assertThrows(BackgroundJobsTaskQueue.JobNotCompletedException.class,
                () -> queue.getJobResults(jobId));
    }

    /**
     * Test: Webhook retry task
     */
    @Test
    @Order(15)
    void testWebhookRetryTask() throws Exception {
        ObjectNode params = objectMapper.createObjectNode();
        com.fasterxml.jackson.databind.node.ArrayNode webhookArray = objectMapper.createArrayNode();
        for (int i = 0; i < 10; i++) {
            ObjectNode webhook = objectMapper.createObjectNode();
            webhook.put("id", "wh_" + i);
            webhook.put("url", "https://example.com/webhook");
            webhookArray.add(webhook);
        }
        params.set("webhooks", webhookArray);

        Map<String, Object> enqueueResponse = queue.enqueueJob("webhook_retry", params, null, 3);
        String jobId = (String) enqueueResponse.get("job_id");

        waitForJobCompletion(jobId, 5000);

        Map<String, Object> results = queue.getJobResults(jobId);
        assertEquals("completed", results.get("status"));
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) results.get("result");
        assertNotNull(result.get("succeeded"));
        assertNotNull(result.get("failed"));
    }

    /**
     * Test: Delete user cascade task
     */
    @Test
    @Order(16)
    void testDeleteUserCascade() throws Exception {
        ObjectNode params = objectMapper.createObjectNode();
        params.put("user_id", "user_123");

        Map<String, Object> enqueueResponse = queue.enqueueJob("delete_user_cascade", params, null, 3);
        String jobId = (String) enqueueResponse.get("job_id");

        waitForJobCompletion(jobId, 5000);

        Map<String, Object> results = queue.getJobResults(jobId);
        assertEquals("completed", results.get("status"));
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) results.get("result");
        assertEquals("user_123", result.get("user_id"));
        assertEquals(true, result.get("deleted"));
    }

    /**
     * Test: Cleanup old sessions task
     */
    @Test
    @Order(17)
    void testCleanupOldSessions() throws Exception {
        ObjectNode params = objectMapper.createObjectNode();
        params.put("days_old", 30);

        Map<String, Object> enqueueResponse = queue.enqueueJob("cleanup_old_sessions", params, null, 3);
        String jobId = (String) enqueueResponse.get("job_id");

        waitForJobCompletion(jobId, 5000);

        Map<String, Object> results = queue.getJobResults(jobId);
        assertEquals("completed", results.get("status"));
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) results.get("result");
        assertEquals(30, result.get("days_old"));
        assertNotNull(result.get("sessions_deleted"));
    }

    // ==================== Deterministic worker tests (2026-11-10) ====================

    /** A clock tests move by hand. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    static final class MutableClock extends java.time.Clock {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");

        @Override public java.time.ZoneId getZone() { return java.time.ZoneOffset.UTC; }

        @Override public java.time.Clock withZone(java.time.ZoneId zone) { return this; }

        @Override public Instant instant() { return now; }
    }

    /**
     * A queue on its own private database and a test clock, never started: the test runs the worker step itself with
     * runReadyJobsOnce(), so nothing depends on sleeps or thread timing. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: a private in-memory H2 database.
     */
    private static BackgroundJobsTaskQueue deterministicQueue(MutableClock clock) throws SQLException {
        Connection c = DriverManager.getConnection(
                "jdbc:h2:mem:jobs_det_" + java.util.UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1", "sa", "");
        return new BackgroundJobsTaskQueue(c, 1, 50, clock);
    }

    /**
     * JOBS-01: an enqueued job is picked up by the worker and its status is 'running' while its handler runs.
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (the older test accepted "running or completed").
     */
    // JOBS-01
    @Test
    @Order(20)
    void testWorkerPicksUpJobAndStatusIsRunning() throws Exception {
        MutableClock clock = new MutableClock();
        BackgroundJobsTaskQueue q = deterministicQueue(clock);
        java.util.List<Object> seen = new java.util.ArrayList<>();
        q.registerTaskHandler("observe", (context, job) -> {
            seen.add(q.getJobStatus(job.id).get("status"));
            context.markCompleted();
        });
        String jobId = (String) q.enqueueJob("observe", objectMapper.createObjectNode(), null, 3).get("job_id");
        assertEquals("enqueued", q.getJobStatus(jobId).get("status"));
        assertEquals(1, q.runReadyJobsOnce());
        assertEquals(java.util.List.of("running"), seen);
        assertEquals("completed", q.getJobStatus(jobId).get("status"));
    }

    /**
     * JOBS-03: a failing job is retried with exponential backoff: retry 1 waits 1 s, retry 2 waits 2 s, status
     * 'enqueued' and retry_count = n while it waits, and the worker skips it until next_retry_at.
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec amendment; the older test only waited 10 s).
     */
    // JOBS-03
    @Test
    @Order(21)
    void testRetryBackoffOneThenTwoSeconds() throws Exception {
        MutableClock clock = new MutableClock();
        BackgroundJobsTaskQueue q = deterministicQueue(clock);
        AtomicRuns runs = new AtomicRuns();
        q.registerTaskHandler("flaky", (context, job) -> {
            if (runs.next() < 3) context.markFailed("boom"); else context.markCompleted();
        });
        String jobId = (String) q.enqueueJob("flaky", objectMapper.createObjectNode(), null, 3).get("job_id");
        Instant t0 = clock.now;

        assertEquals(1, q.runReadyJobsOnce());                       // attempt 1 fails
        Map<String, Object> st = q.getJobStatus(jobId);
        assertEquals("enqueued", st.get("status"));
        assertEquals(1, st.get("retry_count"));
        assertEquals(t0.plusSeconds(1).toString(), st.get("next_retry_at"));
        clock.now = t0.plusMillis(999);
        assertEquals(0, q.runReadyJobsOnce(), "skipped until next_retry_at");
        clock.now = t0.plusSeconds(1);

        assertEquals(1, q.runReadyJobsOnce());                       // retry 1 fails
        st = q.getJobStatus(jobId);
        assertEquals("enqueued", st.get("status"));
        assertEquals(2, st.get("retry_count"));
        assertEquals(t0.plusSeconds(3).toString(), st.get("next_retry_at"));
        clock.now = t0.plusSeconds(2);
        assertEquals(0, q.runReadyJobsOnce(), "retry 2 waits 2 s");
        clock.now = t0.plusSeconds(3);

        assertEquals(1, q.runReadyJobsOnce());                       // retry 2 succeeds
        st = q.getJobStatus(jobId);
        assertEquals("completed", st.get("status"));
        assertEquals(2, st.get("retry_count"));
        assertEquals(3, runs.count());
    }

    /**
     * JOBS-04: with max_retries = 3 an always-failing job runs 4 times (1 + 3 retries), then status 'failed' with
     * retry_count = 3, and it is never run again. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec amendment).
     */
    // JOBS-04
    @Test
    @Order(22)
    void testMaxRetriesThreeRunsFourTimesThenFailed() throws Exception {
        MutableClock clock = new MutableClock();
        BackgroundJobsTaskQueue q = deterministicQueue(clock);
        AtomicRuns runs = new AtomicRuns();
        q.registerTaskHandler("always_fails", (context, job) -> {
            runs.next();
            context.markFailed("always");
        });
        String jobId = (String) q.enqueueJob("always_fails", objectMapper.createObjectNode(), null, 3).get("job_id");
        for (int i = 0; i < 10; i++) {
            q.runReadyJobsOnce();
            clock.now = clock.now.plusSeconds(60);
        }
        Map<String, Object> st = q.getJobStatus(jobId);
        assertEquals(4, runs.count());
        assertEquals("failed", st.get("status"));
        assertEquals(3, st.get("retry_count"));
        assertNotNull(st.get("error"));
    }

    /**
     * JOBS-06: progress written by a running job is visible to a status read while the job is still running
     * (45/100), and ends at 100/100. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (the older test read progress
     * after a 100 ms sleep, which depends on thread timing).
     */
    // JOBS-06
    @Test
    @Order(23)
    void testProgressVisibleWhileRunning() throws Exception {
        MutableClock clock = new MutableClock();
        BackgroundJobsTaskQueue q = deterministicQueue(clock);
        java.util.List<Object> midway = new java.util.ArrayList<>();
        q.registerTaskHandler("progress", (context, job) -> {
            for (int i = 1; i <= 100; i++) {
                context.updateProgress(i + "/100");
                if (i == 45) {
                    Map<String, Object> st = q.getJobStatus(job.id);
                    midway.add(st.get("status") + " " + st.get("progress"));
                }
            }
            context.markCompleted();
        });
        String jobId = (String) q.enqueueJob("progress", objectMapper.createObjectNode(), null, 3).get("job_id");
        q.runReadyJobsOnce();
        assertEquals(java.util.List.of("running 45/100"), midway);
        assertEquals("100/100", q.getJobStatus(jobId).get("progress"));
    }

    /**
     * JOBS-07: a job scheduled for later is not run before scheduled_at and is run once it has passed.
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (deterministic; the older test slept 1.5 s).
     */
    // JOBS-07
    @Test
    @Order(24)
    void testScheduledJobWaitsForScheduledAt() throws Exception {
        MutableClock clock = new MutableClock();
        BackgroundJobsTaskQueue q = deterministicQueue(clock);
        String jobId = (String) q.enqueueJob("daily_report_generate", objectMapper.createObjectNode(),
                clock.now.plusSeconds(60), 3).get("job_id");
        assertEquals(0, q.runReadyJobsOnce());
        clock.now = clock.now.plusSeconds(59);
        assertEquals(0, q.runReadyJobsOnce());
        assertEquals("enqueued", q.getJobStatus(jobId).get("status"));
        clock.now = clock.now.plusSeconds(1);
        assertEquals(1, q.runReadyJobsOnce());
        assertEquals("completed", q.getJobStatus(jobId).get("status"));
    }

    /**
     * JOBS-08: enqueueing a 10,000-item job returns at once without running it (the request is not blocked), and
     * the worker then processes all 10,000 items. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (the older test
     * timed send_bulk_email, which processes however many users the stub returns, not 10,000).
     */
    // JOBS-08
    @Test
    @Order(25)
    void testTenThousandItemsProcessedWithoutBlockingEnqueue() throws Exception {
        MutableClock clock = new MutableClock();
        BackgroundJobsTaskQueue q = deterministicQueue(clock);
        AtomicRuns items = new AtomicRuns();
        q.registerTaskHandler("bulk", (context, job) -> {
            for (int i = 0; i < 10_000; i++) {
                items.next();
                if ((i + 1) % 1000 == 0) context.updateProgress((i + 1) + "/10000");
            }
            context.setResult(Map.of("processed", 10_000));
            context.markCompleted();
        });
        Map<String, Object> resp = q.enqueueJob("bulk", objectMapper.createObjectNode(), null, 3);
        assertEquals("enqueued", resp.get("status"));
        assertEquals(0, items.count(), "enqueue must not run the job");
        q.runReadyJobsOnce();
        assertEquals(10_000, items.count());
        String jobId = (String) resp.get("job_id");
        assertEquals("completed", q.getJobStatus(jobId).get("status"));
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) q.getJobResults(jobId).get("result");
        assertEquals(10_000, result.get("processed"));
    }

    /** A counter for handler runs. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static final class AtomicRuns {
        private final java.util.concurrent.atomic.AtomicInteger n = new java.util.concurrent.atomic.AtomicInteger();

        int next() { return n.incrementAndGet(); }

        int count() { return n.get(); }
    }

    // ==================== Helper Methods ====================

    private void waitForJobCompletion(String jobId, long timeoutMs) throws InterruptedException {
        long startTime = System.currentTimeMillis();
        while (System.currentTimeMillis() - startTime < timeoutMs) {
            Map<String, Object> status = queue.getJobStatus(jobId);
            String jobStatus = (String) status.get("status");
            if ("completed".equals(jobStatus) || "failed".equals(jobStatus) || "cancelled".equals(jobStatus)) {
                return;
            }
            Thread.sleep(50);
        }
        fail("Job " + jobId + " did not complete within " + timeoutMs + "ms");
    }
}

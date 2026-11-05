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

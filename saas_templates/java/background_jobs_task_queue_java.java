package com.saas.jobs;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.sql.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Background Jobs & Task Queue module.
 * Database-backed queue with polling worker, exponential backoff retries,
 * atomic status transitions, progress tracking, and scheduled execution.
 */
public class BackgroundJobsTaskQueue implements AutoCloseable {

    private final Connection connection;
    private final ObjectMapper objectMapper;
    private final ExecutorService workerPool;
    private final ScheduledExecutorService scheduler;
    private final AtomicBoolean running;
    private final Map<String, BiConsumer<JobContext, Job>> taskHandlers;
    private final long pollIntervalMs;
    private final long scheduleCheckIntervalMs;
    private final int workerCount;
    private final int maxBatchSize;
    /** Source of "now" for every timestamp, retry and schedule decision (spec: injectable clock). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private final java.time.Clock clock;

    private static final String DDL = """
            CREATE TABLE IF NOT EXISTS jobs (
                id VARCHAR(36) PRIMARY KEY,
                task_type VARCHAR(128) NOT NULL,
                params TEXT,
                status VARCHAR(32) NOT NULL DEFAULT 'enqueued',
                created_at TIMESTAMP NOT NULL,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                progress VARCHAR(64),
                result TEXT,
                error TEXT,
                retry_count INT NOT NULL DEFAULT 0,
                max_retries INT NOT NULL DEFAULT 3,
                next_retry_at TIMESTAMP,
                scheduled_at TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS job_runs (
                id VARCHAR(36) PRIMARY KEY,
                job_id VARCHAR(36) NOT NULL,
                status VARCHAR(32) NOT NULL,
                started_at TIMESTAMP NOT NULL,
                completed_at TIMESTAMP,
                result TEXT,
                FOREIGN KEY (job_id) REFERENCES jobs(id)
            );

            CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
            CREATE INDEX IF NOT EXISTS idx_jobs_task_type ON jobs(task_type);
            CREATE INDEX IF NOT EXISTS idx_jobs_next_retry ON jobs(next_retry_at);
            CREATE INDEX IF NOT EXISTS idx_jobs_scheduled ON jobs(scheduled_at);
            """;

    public BackgroundJobsTaskQueue(Connection connection, int workerCount, long pollIntervalMs) {
        this(connection, workerCount, pollIntervalMs, java.time.Clock.systemUTC());
    }

    /**
     * Queue on an injectable clock. In: connection, worker count, poll interval, clock. Why: JOBS-03/04/07 must be
     * testable without sleeping (spec rule "Deterministic"); 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (creates the schema), no threads until start().
     */
    public BackgroundJobsTaskQueue(Connection connection, int workerCount, long pollIntervalMs, java.time.Clock clock) {
        this.clock = clock;
        this.connection = connection;
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        this.workerPool = Executors.newFixedThreadPool(workerCount);
        this.scheduler = Executors.newScheduledThreadPool(2);
        this.running = new AtomicBoolean(false);
        this.taskHandlers = new ConcurrentHashMap<>();
        this.pollIntervalMs = pollIntervalMs;
        this.scheduleCheckIntervalMs = Math.max(100, pollIntervalMs / 2);
        this.workerCount = workerCount;
        this.maxBatchSize = workerCount * 2;
        initializeSchema();
        registerDefaultHandlers();
    }

    private void initializeSchema() {
        try (Statement stmt = connection.createStatement()) {
            for (String sql : DDL.split(";")) {
                String trimmed = sql.trim();
                if (!trimmed.isEmpty()) {
                    stmt.execute(trimmed);
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to initialize job schema", e);
        }
    }

    private void registerDefaultHandlers() {
        taskHandlers.put("send_bulk_email", this::handleSendBulkEmail);
        taskHandlers.put("webhook_retry", this::handleWebhookRetry);
        taskHandlers.put("export_generate", this::handleExportGenerate);
        taskHandlers.put("daily_report_generate", this::handleDailyReportGenerate);
        taskHandlers.put("delete_user_cascade", this::handleDeleteUserCascade);
        taskHandlers.put("cleanup_old_sessions", this::handleCleanupOldSessions);
        taskHandlers.put("sync_stripe_invoices", this::handleSyncStripeInvoices);
        taskHandlers.put("generate_deployment_archive", this::handleGenerateDeploymentArchive);
    }

    /**
     * Register a custom task handler.
     */
    public void registerTaskHandler(String taskType, BiConsumer<JobContext, Job> handler) {
        taskHandlers.put(taskType, handler);
    }

    /**
     * Start the worker pool and scheduler.
     */
    public void start() {
        if (running.compareAndSet(false, true)) {
            for (int i = 0; i < workerCount; i++) {
                workerPool.submit(this::workerLoop);
            }
            scheduler.scheduleAtFixedRate(this::processScheduledJobs, 0, scheduleCheckIntervalMs, TimeUnit.MILLISECONDS);
        }
    }

    /**
     * Stop the worker pool and scheduler gracefully.
     */
    public void stop() {
        if (running.compareAndSet(true, false)) {
            scheduler.shutdown();
            workerPool.shutdown();
            try {
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
                if (!workerPool.awaitTermination(10, TimeUnit.SECONDS)) {
                    workerPool.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                scheduler.shutdownNow();
                workerPool.shutdownNow();
            }
        }
    }

    @Override
    public void close() {
        stop();
    }

    /**
     * Enqueue a new job.
     * POST /jobs/enqueue
     */
    public Map<String, Object> enqueueJob(String taskType, JsonNode params, Instant scheduledAt, int maxRetries) {
        String jobId = UUID.randomUUID().toString();
        Instant now = clock.instant();
        String paramsJson = params != null ? params.toString() : "{}";

        try (PreparedStatement ps = connection.prepareStatement(
                "INSERT INTO jobs (id, task_type, params, status, created_at, max_retries, scheduled_at) VALUES (?, ?, ?, 'enqueued', ?, ?, ?)")) {
            ps.setString(1, jobId);
            ps.setString(2, taskType);
            ps.setString(3, paramsJson);
            ps.setTimestamp(4, Timestamp.from(now));
            ps.setInt(5, maxRetries);
            if (scheduledAt != null) {
                ps.setTimestamp(6, Timestamp.from(scheduledAt));
            } else {
                ps.setNull(6, Types.TIMESTAMP);
            }
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to enqueue job", e);
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", true);
        response.put("job_id", jobId);
        response.put("status", "enqueued");
        return response;
    }

    /**
     * Get job status.
     * GET /jobs/:job_id
     */
    public Map<String, Object> getJobStatus(String jobId) {
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT id, task_type, status, progress, created_at, started_at, completed_at, result, error, retry_count, max_retries, next_retry_at, scheduled_at FROM jobs WHERE id = ?")) {
            ps.setString(1, jobId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return mapJobToStatusResponse(rs);
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to get job status", e);
        }
        throw new JobNotFoundException(jobId);
    }

    /**
     * List jobs with optional filters.
     * GET /jobs?status=running&task_type=send_bulk_email&limit=10
     */
    public Map<String, Object> listJobs(String status, String taskType, int limit) {
        StringBuilder sql = new StringBuilder("SELECT id, task_type, status, progress, created_at, started_at, completed_at, result, error, retry_count, max_retries, next_retry_at, scheduled_at FROM jobs WHERE 1=1");
        List<Object> params = new ArrayList<>();

        if (status != null && !status.isEmpty()) {
            sql.append(" AND status = ?");
            params.add(status);
        }
        if (taskType != null && !taskType.isEmpty()) {
            sql.append(" AND task_type = ?");
            params.add(taskType);
        }
        sql.append(" ORDER BY created_at DESC LIMIT ?");
        params.add(limit);

        List<Map<String, Object>> jobs = new ArrayList<>();
        int total = 0;

        try {
            // Get total count
            StringBuilder countSql = new StringBuilder("SELECT COUNT(*) FROM jobs WHERE 1=1");
            List<Object> countParams = new ArrayList<>();
            if (status != null && !status.isEmpty()) {
                countSql.append(" AND status = ?");
                countParams.add(status);
            }
            if (taskType != null && !taskType.isEmpty()) {
                countSql.append(" AND task_type = ?");
                countParams.add(taskType);
            }
            try (PreparedStatement ps = connection.prepareStatement(countSql.toString())) {
                for (int i = 0; i < countParams.size(); i++) {
                    ps.setObject(i + 1, countParams.get(i));
                }
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        total = rs.getInt(1);
                    }
                }
            }

            // Get jobs
            try (PreparedStatement ps = connection.prepareStatement(sql.toString())) {
                for (int i = 0; i < params.size(); i++) {
                    ps.setObject(i + 1, params.get(i));
                }
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        jobs.add(mapJobToListItem(rs));
                    }
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to list jobs", e);
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("jobs", jobs);
        response.put("total", total);
        return response;
    }

    /**
     * Cancel a job (only if not started).
     * DELETE /jobs/:job_id
     */
    public Map<String, Object> cancelJob(String jobId) {
        try (PreparedStatement ps = connection.prepareStatement(
                "UPDATE jobs SET status = 'cancelled', completed_at = ? WHERE id = ? AND status = 'enqueued'")) {
            ps.setTimestamp(1, Timestamp.from(clock.instant()));
            ps.setString(2, jobId);
            int updated = ps.executeUpdate();
            if (updated > 0) {
                Map<String, Object> response = new LinkedHashMap<>();
                response.put("success", true);
                response.put("status", "cancelled");
                return response;
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to cancel job", e);
        }
        throw new JobNotCancellableException(jobId);
    }

    /**
     * Retry a failed job.
     * POST /jobs/:job_id/retry
     */
    public Map<String, Object> retryJob(String jobId) {
        Job originalJob;
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT id, task_type, params, status, max_retries FROM jobs WHERE id = ?")) {
            ps.setString(1, jobId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    throw new JobNotFoundException(jobId);
                }
                originalJob = new Job(
                        rs.getString("id"),
                        rs.getString("task_type"),
                        rs.getString("params"),
                        rs.getString("status"),
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        0,
                        rs.getInt("max_retries"),
                        null,
                        null
                );
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to get job for retry", e);
        }

        if (!"failed".equals(originalJob.status)) {
            throw new JobNotRetryableException(jobId, originalJob.status);
        }

        String newJobId = UUID.randomUUID().toString();
        Instant now = clock.instant();

        try (PreparedStatement ps = connection.prepareStatement(
                "INSERT INTO jobs (id, task_type, params, status, created_at, max_retries) VALUES (?, ?, ?, 'enqueued', ?, ?)")) {
            ps.setString(1, newJobId);
            ps.setString(2, originalJob.taskType);
            ps.setString(3, originalJob.params);
            ps.setTimestamp(4, Timestamp.from(now));
            ps.setInt(5, originalJob.maxRetries);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to create retry job", e);
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", true);
        response.put("new_job_id", newJobId);
        response.put("status", "enqueued");
        return response;
    }

    /**
     * Get job results (when completed).
     * GET /jobs/:job_id/results
     */
    public Map<String, Object> getJobResults(String jobId) {
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT id, task_type, status, result, completed_at FROM jobs WHERE id = ?")) {
            ps.setString(1, jobId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String status = rs.getString("status");
                    if (!"completed".equals(status) && !"failed".equals(status)) {
                        throw new JobNotCompletedException(jobId, status);
                    }
                    Map<String, Object> response = new LinkedHashMap<>();
                    response.put("job_id", jobId);
                    response.put("status", status);

                    String resultJson = rs.getString("result");
                    if (resultJson != null && !resultJson.isEmpty()) {
                        try {
                            Map<String, Object> resultMap = objectMapper.readValue(resultJson, new TypeReference<Map<String, Object>>() {});
                            Map<String, Object> result = new LinkedHashMap<>();
                            result.put("task_type", rs.getString("task_type"));
                            result.putAll(resultMap);
                            response.put("result", result);
                        } catch (JsonProcessingException e) {
                            response.put("result", resultJson);
                        }
                    } else {
                        response.put("result", null);
                    }

                    Timestamp completedAt = rs.getTimestamp("completed_at");
                    response.put("completed_at", completedAt != null ? completedAt.toInstant().toString() : null);
                    return response;
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to get job results", e);
        }
        throw new JobNotFoundException(jobId);
    }

    // ==================== Worker Logic ====================

    /**
     * Runs, on the calling thread, every job that is ready now (enqueued, scheduled_at and next_retry_at passed),
     * oldest first, one batch. In: none. Out: how many jobs were attempted. Why: a deterministic worker step for tests
     * and for deployments that drive the queue from their own scheduler instead of start(); 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database, whatever the task handlers touch.
     */
    public int runReadyJobsOnce() {
        List<Job> jobs = fetchReadyJobs();
        for (Job job : jobs) {
            executeJob(job);
        }
        return jobs.size();
    }

    private void workerLoop() {
        while (running.get()) {
            try {
                List<Job> jobs = fetchReadyJobs();
                for (Job job : jobs) {
                    if (!running.get()) break;
                    executeJob(job);
                }
                if (jobs.isEmpty()) {
                    Thread.sleep(pollIntervalMs);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                if (running.get()) {
                    try {
                        Thread.sleep(pollIntervalMs);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }
    }

    private List<Job> fetchReadyJobs() {
        List<Job> jobs = new ArrayList<>();
        Instant now = clock.instant();
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT id, task_type, params, status, created_at, started_at, completed_at, progress, result, error, retry_count, max_retries, next_retry_at, scheduled_at " +
                "FROM jobs WHERE status = 'enqueued' AND (scheduled_at IS NULL OR scheduled_at <= ?) AND (next_retry_at IS NULL OR next_retry_at <= ?) " +
                "ORDER BY created_at ASC LIMIT ?")) {
            ps.setTimestamp(1, Timestamp.from(now));
            ps.setTimestamp(2, Timestamp.from(now));
            ps.setInt(3, maxBatchSize);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    jobs.add(mapResultSetToJob(rs));
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to fetch ready jobs", e);
        }
        return jobs;
    }

    private void executeJob(Job job) {
        // Atomically transition to running
        if (!transitionToRunning(job.id)) {
            return; // Someone else got it or it was cancelled
        }

        String runId = UUID.randomUUID().toString();
        Instant startedAt = clock.instant();

        // Create job run record
        try (PreparedStatement ps = connection.prepareStatement(
                "INSERT INTO job_runs (id, job_id, status, started_at) VALUES (?, ?, 'running', ?)")) {
            ps.setString(1, runId);
            ps.setString(2, job.id);
            ps.setTimestamp(3, Timestamp.from(startedAt));
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to create job run", e);
        }

        JobContext context = new JobContext(job, this);
        BiConsumer<JobContext, Job> handler = taskHandlers.get(job.taskType);

        if (handler == null) {
            handleJobFailure(job, runId, new Exception("Unknown task type: " + job.taskType));
            return;
        }

        try {
            handler.accept(context, job);
            // If job completed successfully
            if ("completed".equals(context.getStatus())) {
                completeJob(job, runId, context.getResult(), null);
            } else if ("failed".equals(context.getStatus())) {
                handleJobFailure(job, runId, new Exception(context.getError() != null ? context.getError() : "Task failed"));
            } else {
                // Default: treat as completed
                completeJob(job, runId, context.getResult(), null);
            }
        } catch (Exception e) {
            handleJobFailure(job, runId, e);
        }
    }

    private boolean transitionToRunning(String jobId) {
        try (PreparedStatement ps = connection.prepareStatement(
                "UPDATE jobs SET status = 'running', started_at = ? WHERE id = ? AND status = 'enqueued'")) {
            ps.setTimestamp(1, Timestamp.from(clock.instant()));
            ps.setString(2, jobId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new RuntimeException("Failed to transition job to running", e);
        }
    }

    private void completeJob(Job job, String runId, Map<String, Object> result, String error) {
        Instant completedAt = clock.instant();
        String resultJson = result != null ? toJson(result) : null;

        try (PreparedStatement ps = connection.prepareStatement(
                "UPDATE jobs SET status = 'completed', completed_at = ?, result = ?, error = ? WHERE id = ?")) {
            ps.setTimestamp(1, Timestamp.from(completedAt));
            ps.setString(2, resultJson);
            ps.setString(3, error);
            ps.setString(4, job.id);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to complete job", e);
        }

        try (PreparedStatement ps = connection.prepareStatement(
                "UPDATE job_runs SET status = 'completed', completed_at = ?, result = ? WHERE id = ?")) {
            ps.setTimestamp(1, Timestamp.from(completedAt));
            ps.setString(2, resultJson);
            ps.setString(3, runId);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to complete job run", e);
        }
    }

    /**
     * After a failed attempt: retry n = retry_count + 1 waits 2^(n-1) s (status 'enqueued', next_retry_at = now + delay,
     * retry_count = n) while n <= max_retries; when attempt max_retries + 1 fails, status 'failed' with
     * retry_count = max_retries (JOBS-03/04 as amended 2026-11-10). Documented 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP; now on the injected clock. Touches: the database.
     */
    private void handleJobFailure(Job job, String runId, Exception e) {
        Instant now = clock.instant();
        int newRetryCount = job.retryCount + 1;
        String errorMessage = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();

        if (newRetryCount <= job.maxRetries) {
            // Schedule retry with exponential backoff: 1s, 2s, 4s, 8s, ...
            long backoffSeconds = (long) Math.pow(2, newRetryCount - 1);
            Instant nextRetryAt = now.plusSeconds(backoffSeconds);

            try (PreparedStatement ps = connection.prepareStatement(
                    "UPDATE jobs SET status = 'enqueued', retry_count = ?, next_retry_at = ?, error = ? WHERE id = ?")) {
                ps.setInt(1, newRetryCount);
                ps.setTimestamp(2, Timestamp.from(nextRetryAt));
                ps.setString(3, errorMessage);
                ps.setString(4, job.id);
                ps.executeUpdate();
            } catch (SQLException e2) {
                throw new RuntimeException("Failed to schedule retry", e2);
            }

            try (PreparedStatement ps = connection.prepareStatement(
                    "UPDATE job_runs SET status = 'failed', completed_at = ?, result = ? WHERE id = ?")) {
                ps.setTimestamp(1, Timestamp.from(now));
                ps.setString(2, toJson(Map.of("error", errorMessage)));
                ps.setString(3, runId);
                ps.executeUpdate();
            } catch (SQLException e2) {
                throw new RuntimeException("Failed to update job run", e2);
            }
        } else {
            // Max retries exceeded - set retry_count to maxRetries (not newRetryCount)
            try (PreparedStatement ps = connection.prepareStatement(
                    "UPDATE jobs SET status = 'failed', completed_at = ?, retry_count = ?, error = ? WHERE id = ?")) {
                ps.setTimestamp(1, Timestamp.from(now));
                ps.setInt(2, job.maxRetries);
                ps.setString(3, errorMessage);
                ps.setString(4, job.id);
                ps.executeUpdate();
            } catch (SQLException e2) {
                throw new RuntimeException("Failed to mark job as failed", e2);
            }

            try (PreparedStatement ps = connection.prepareStatement(
                    "UPDATE job_runs SET status = 'failed', completed_at = ?, result = ? WHERE id = ?")) {
                ps.setTimestamp(1, Timestamp.from(now));
                ps.setString(2, toJson(Map.of("error", errorMessage, "retries_exhausted", true)));
                ps.setString(3, runId);
                ps.executeUpdate();
            } catch (SQLException e2) {
                throw new RuntimeException("Failed to update job run", e2);
            }
        }
    }

    private void processScheduledJobs() {
        // Scheduled jobs are handled by the main poll loop via the scheduled_at check
        // This method can be used for additional scheduling logic if needed
    }

    // ==================== Task Handlers ====================

    private void handleSendBulkEmail(JobContext context, Job job) {
        try {
            JsonNode params = job.params != null ? objectMapper.readTree(job.params) : objectMapper.createObjectNode();
            JsonNode filter = params.has("filter") ? params.get("filter") : null;
            String templateKey = params.has("template_key") ? params.get("template_key").asText() : "default";

            // Simulate fetching users matching filter
            List<Map<String, Object>> users = fetchUsersByFilter(filter);
            int total = users.size();
            int sent = 0;
            int failed = 0;
            int skipped = 0;
            List<Map<String, Object>> errors = new ArrayList<>();

            for (int i = 0; i < total; i++) {
                if (context.isCancelled()) {
                    break;
                }
                Map<String, Object> user = users.get(i);
                try {
                    // Simulate sending email
                    boolean success = sendEmail(templateKey, user);
                    if (success) {
                        sent++;
                    } else {
                        failed++;
                        errors.add(Map.of("user_id", user.get("id"), "error", "email_bounced"));
                    }
                } catch (Exception e) {
                    failed++;
                    errors.add(Map.of("user_id", user.get("id"), "error", e.getMessage()));
                }

                // Update progress periodically
                if ((i + 1) % 10 == 0 || i == total - 1) {
                    context.updateProgress((i + 1) + "/" + total);
                }
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("sent", sent);
            result.put("failed", failed);
            result.put("skipped", skipped);
            if (!errors.isEmpty()) {
                result.put("errors", errors);
            }
            context.setResult(result);
            context.markCompleted();

        } catch (Exception e) {
            context.markFailed(e.getMessage());
        }
    }

    private void handleWebhookRetry(JobContext context, Job job) {
        try {
            JsonNode params = job.params != null ? objectMapper.readTree(job.params) : objectMapper.createObjectNode();
            JsonNode webhooks = params.has("webhooks") ? params.get("webhooks") : null;

            if (webhooks == null || !webhooks.isArray()) {
                context.markFailed("No webhooks specified for retry");
                return;
            }

            int total = webhooks.size();
            int succeeded = 0;
            int failed = 0;
            List<Map<String, Object>> errors = new ArrayList<>();

            for (int i = 0; i < total; i++) {
                if (context.isCancelled()) break;
                JsonNode webhook = webhooks.get(i);
                try {
                    boolean success = deliverWebhook(webhook);
                    if (success) {
                        succeeded++;
                    } else {
                        failed++;
                        errors.add(Map.of("webhook_id", webhook.has("id") ? webhook.get("id").asText() : "unknown", "error", "delivery_failed"));
                    }
                } catch (Exception e) {
                    failed++;
                    errors.add(Map.of("webhook_id", webhook.has("id") ? webhook.get("id").asText() : "unknown", "error", e.getMessage()));
                }

                if ((i + 1) % 10 == 0 || i == total - 1) {
                    context.updateProgress((i + 1) + "/" + total);
                }
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("succeeded", succeeded);
            result.put("failed", failed);
            if (!errors.isEmpty()) {
                result.put("errors", errors);
            }
            context.setResult(result);
            context.markCompleted();

        } catch (Exception e) {
            context.markFailed(e.getMessage());
        }
    }

    private void handleExportGenerate(JobContext context, Job job) {
        try {
            JsonNode params = job.params != null ? objectMapper.readTree(job.params) : objectMapper.createObjectNode();
            String exportType = params.has("export_type") ? params.get("export_type").asText() : "csv";
            JsonNode filter = params.has("filter") ? params.get("filter") : null;

            List<Map<String, Object>> records = fetchRecordsForExport(filter);
            int total = records.size();
            int processed = 0;

            for (int i = 0; i < total; i++) {
                if (context.isCancelled()) break;
                // Simulate processing each record
                processed++;
                if ((i + 1) % 50 == 0 || i == total - 1) {
                    context.updateProgress((i + 1) + "/" + total);
                }
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("export_type", exportType);
            result.put("records_exported", processed);
            result.put("file_size_bytes", processed * 100); // Simulated
            context.setResult(result);
            context.markCompleted();

        } catch (Exception e) {
            context.markFailed(e.getMessage());
        }
    }

    private void handleDailyReportGenerate(JobContext context, Job job) {
        try {
            JsonNode params = job.params != null ? objectMapper.readTree(job.params) : objectMapper.createObjectNode();
            String reportType = params.has("report_type") ? params.get("report_type").asText() : "metrics";

            // Simulate aggregating metrics
            Map<String, Object> metrics = new LinkedHashMap<>();
            metrics.put("total_users", 10000);
            metrics.put("active_users", 5000);
            metrics.put("new_signups", 150);
            metrics.put("revenue", 25000.00);
            metrics.put("api_calls", 1000000);
            metrics.put("error_rate", 0.002);

            context.updateProgress("1/1");
            context.setResult(metrics);
            context.markCompleted();

        } catch (Exception e) {
            context.markFailed(e.getMessage());
        }
    }

    private void handleDeleteUserCascade(JobContext context, Job job) {
        try {
            JsonNode params = job.params != null ? objectMapper.readTree(job.params) : objectMapper.createObjectNode();
            String userId = params.has("user_id") ? params.get("user_id").asText() : null;

            if (userId == null) {
                context.markFailed("user_id is required");
                return;
            }

            // Simulate cascading deletion
            context.updateProgress("1/5");
            deleteUserData(userId, "sessions");
            context.updateProgress("2/5");
            deleteUserData(userId, "notifications");
            context.updateProgress("3/5");
            deleteUserData(userId, "webhooks");
            context.updateProgress("4/5");
            deleteUserData(userId, "exports");
            context.updateProgress("5/5");
            deleteUserData(userId, "user");

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("user_id", userId);
            result.put("deleted", true);
            result.put("tables_affected", List.of("sessions", "notifications", "webhooks", "exports", "user"));
            context.setResult(result);
            context.markCompleted();

        } catch (Exception e) {
            context.markFailed(e.getMessage());
        }
    }

    private void handleCleanupOldSessions(JobContext context, Job job) {
        try {
            JsonNode params = job.params != null ? objectMapper.readTree(job.params) : objectMapper.createObjectNode();
            int daysOld = params.has("days_old") ? params.get("days_old").asInt() : 30;

            // Simulate deleting old sessions
            int deleted = 100; // Simulated count
            context.updateProgress("1/1");

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("days_old", daysOld);
            result.put("sessions_deleted", deleted);
            context.setResult(result);
            context.markCompleted();

        } catch (Exception e) {
            context.markFailed(e.getMessage());
        }
    }

    private void handleSyncStripeInvoices(JobContext context, Job job) {
        try {
            JsonNode params = job.params != null ? objectMapper.readTree(job.params) : objectMapper.createObjectNode();

            // Simulate syncing invoices
            int synced = 50;
            int failed = 0;
            context.updateProgress("1/1");

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("invoices_synced", synced);
            result.put("invoices_failed", failed);
            context.setResult(result);
            context.markCompleted();

        } catch (Exception e) {
            context.markFailed(e.getMessage());
        }
    }

    private void handleGenerateDeploymentArchive(JobContext context, Job job) {
        try {
            JsonNode params = job.params != null ? objectMapper.readTree(job.params) : objectMapper.createObjectNode();
            String version = params.has("version") ? params.get("version").asText() : "latest";

            // Simulate generating archive
            context.updateProgress("1/3");
            Thread.sleep(100);
            context.updateProgress("2/3");
            Thread.sleep(100);
            context.updateProgress("3/3");

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("version", version);
            result.put("archive_size_bytes", 1024 * 1024);
            result.put("files_included", 100);
            context.setResult(result);
            context.markCompleted();

        } catch (Exception e) {
            context.markFailed(e.getMessage());
        }
    }

    // ==================== Helper Methods ====================

    private List<Map<String, Object>> fetchUsersByFilter(JsonNode filter) {
        // Simulate fetching users
        List<Map<String, Object>> users = new ArrayList<>();
        for (int i = 1; i <= 100; i++) {
            Map<String, Object> user = new LinkedHashMap<>();
            user.put("id", i);
            user.put("email", "user" + i + "@example.com");
            users.add(user);
        }
        return users;
    }

    private boolean sendEmail(String templateKey, Map<String, Object> user) {
        // Simulate email sending - 98% success rate
        return new Random().nextInt(100) < 98;
    }

    private boolean deliverWebhook(JsonNode webhook) {
        // Simulate webhook delivery - 95% success rate
        return new Random().nextInt(100) < 95;
    }

    private List<Map<String, Object>> fetchRecordsForExport(JsonNode filter) {
        List<Map<String, Object>> records = new ArrayList<>();
        for (int i = 1; i <= 500; i++) {
            Map<String, Object> record = new LinkedHashMap<>();
            record.put("id", i);
            record.put("data", "record_data_" + i);
            records.add(record);
        }
        return records;
    }

    private void deleteUserData(String userId, String table) {
        // Simulate deletion
    }

    private Map<String, Object> mapJobToStatusResponse(ResultSet rs) throws SQLException {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("job_id", rs.getString("id"));
        response.put("task_type", rs.getString("task_type"));
        response.put("status", rs.getString("status"));
        response.put("progress", rs.getString("progress"));

        Timestamp createdAt = rs.getTimestamp("created_at");
        response.put("created_at", createdAt != null ? createdAt.toInstant().toString() : null);

        Timestamp startedAt = rs.getTimestamp("started_at");
        response.put("started_at", startedAt != null ? startedAt.toInstant().toString() : null);

        Timestamp completedAt = rs.getTimestamp("completed_at");
        response.put("completed_at", completedAt != null ? completedAt.toInstant().toString() : null);

        String resultJson = rs.getString("result");
        if (resultJson != null && !resultJson.isEmpty()) {
            try {
                Map<String, Object> resultMap = objectMapper.readValue(resultJson, new TypeReference<Map<String, Object>>() {});
                response.put("result", resultMap);
            } catch (JsonProcessingException e) {
                response.put("result", resultJson);
            }
        } else {
            response.put("result", null);
        }

        response.put("error", rs.getString("error"));
        response.put("retry_count", rs.getInt("retry_count"));
        response.put("max_retries", rs.getInt("max_retries"));

        Timestamp nextRetryAt = rs.getTimestamp("next_retry_at");
        response.put("next_retry_at", nextRetryAt != null ? nextRetryAt.toInstant().toString() : null);

        Timestamp scheduledAt = rs.getTimestamp("scheduled_at");
        response.put("scheduled_at", scheduledAt != null ? scheduledAt.toInstant().toString() : null);

        return response;
    }

    private Map<String, Object> mapJobToListItem(ResultSet rs) throws SQLException {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("job_id", rs.getString("id"));
        item.put("task_type", rs.getString("task_type"));
        item.put("status", rs.getString("status"));
        item.put("progress", rs.getString("progress"));

        Timestamp createdAt = rs.getTimestamp("created_at");
        item.put("created_at", createdAt != null ? createdAt.toInstant().toString() : null);

        Timestamp startedAt = rs.getTimestamp("started_at");
        item.put("started_at", startedAt != null ? startedAt.toInstant().toString() : null);

        Timestamp completedAt = rs.getTimestamp("completed_at");
        item.put("completed_at", completedAt != null ? completedAt.toInstant().toString() : null);

        item.put("retry_count", rs.getInt("retry_count"));
        item.put("max_retries", rs.getInt("max_retries"));

        return item;
    }

    private Job mapResultSetToJob(ResultSet rs) throws SQLException {
        return new Job(
                rs.getString("id"),
                rs.getString("task_type"),
                rs.getString("params"),
                rs.getString("status"),
                rs.getTimestamp("created_at") != null ? rs.getTimestamp("created_at").toInstant() : null,
                rs.getTimestamp("started_at") != null ? rs.getTimestamp("started_at").toInstant() : null,
                rs.getTimestamp("completed_at") != null ? rs.getTimestamp("completed_at").toInstant() : null,
                rs.getString("progress"),
                rs.getString("result"),
                rs.getString("error"),
                rs.getInt("retry_count"),
                rs.getInt("max_retries"),
                rs.getTimestamp("next_retry_at") != null ? rs.getTimestamp("next_retry_at").toInstant() : null,
                rs.getTimestamp("scheduled_at") != null ? rs.getTimestamp("scheduled_at").toInstant() : null
        );
    }

    private String toJson(Object obj) {
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            return "{}";
        }
    }

    // ==================== Inner Classes ====================

    public static class Job {
        public final String id;
        public final String taskType;
        public final String params;
        public final String status;
        public final Instant createdAt;
        public final Instant startedAt;
        public final Instant completedAt;
        public final String progress;
        public final String result;
        public final String error;
        public final int retryCount;
        public final int maxRetries;
        public final Instant nextRetryAt;
        public final Instant scheduledAt;

        public Job(String id, String taskType, String params, String status, Instant createdAt,
                   Instant startedAt, Instant completedAt, String progress, String result,
                   String error, int retryCount, int maxRetries, Instant nextRetryAt, Instant scheduledAt) {
            this.id = id;
            this.taskType = taskType;
            this.params = params;
            this.status = status;
            this.createdAt = createdAt;
            this.startedAt = startedAt;
            this.completedAt = completedAt;
            this.progress = progress;
            this.result = result;
            this.error = error;
            this.retryCount = retryCount;
            this.maxRetries = maxRetries;
            this.nextRetryAt = nextRetryAt;
            this.scheduledAt = scheduledAt;
        }
    }

    public static class JobContext {
        private final Job job;
        private final BackgroundJobsTaskQueue queue;
        private final AtomicBoolean cancelled;
        private volatile String status;
        private volatile Map<String, Object> result;
        private volatile String error;
        private volatile String progress;

        public JobContext(Job job, BackgroundJobsTaskQueue queue) {
            this.job = job;
            this.queue = queue;
            this.cancelled = new AtomicBoolean(false);
            this.status = "running";
        }

        public Job getJob() {
            return job;
        }

        public boolean isCancelled() {
            return cancelled.get();
        }

        public void cancel() {
            cancelled.set(true);
        }

        public void updateProgress(String progress) {
            this.progress = progress;
            try (PreparedStatement ps = queue.connection.prepareStatement(
                    "UPDATE jobs SET progress = ? WHERE id = ?")) {
                ps.setString(1, progress);
                ps.setString(2, job.id);
                ps.executeUpdate();
            } catch (SQLException e) {
                // Log but don't fail the job on progress update failure
            }
        }

        public void setResult(Map<String, Object> result) {
            this.result = result;
        }

        public void markCompleted() {
            this.status = "completed";
        }

        public void markFailed(String error) {
            this.status = "failed";
            this.error = error;
        }

        public String getStatus() {
            return status;
        }

        public Map<String, Object> getResult() {
            return result;
        }

        public String getError() {
            return error;
        }
    }

    // ==================== Exceptions ====================

    public static class JobNotFoundException extends RuntimeException {
        public JobNotFoundException(String jobId) {
            super("Job not found: " + jobId);
        }
    }

    public static class JobNotCancellableException extends RuntimeException {
        public JobNotCancellableException(String jobId) {
            super("Job cannot be cancelled (not in enqueued state): " + jobId);
        }
    }

    public static class JobNotRetryableException extends RuntimeException {
        public JobNotRetryableException(String jobId, String status) {
            super("Job cannot be retried (status: " + status + "): " + jobId);
        }
    }

    public static class JobNotCompletedException extends RuntimeException {
        public JobNotCompletedException(String jobId, String status) {
            super("Job not completed (status: " + status + "): " + jobId);
        }
    }
}

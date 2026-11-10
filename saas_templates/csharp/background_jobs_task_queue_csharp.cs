// Background jobs & task queue template (TIER_2_MASTER_SPEC system 4): enqueue, status, list, cancel, retry and
// results over a database-backed queue polled by a hosted worker, with exponential-backoff retries.
// Repaired 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP). The suite failed to compile (tests lacked the
// Microsoft.Data.Sqlite using); behind that: Migrate() ran with no migrations (no tables in a real database), the retry
// count of a finally-failed job was never saved, webhook_retry could not fail, a job's progress was empty while
// running, and claiming/cancelling a job was not atomic. Jobs are now claimed and cancelled with one conditional
// UPDATE each, every attempt is recorded in job_runs, and webhook delivery goes through IWebhookSender, whose HTTP
// implementation refuses non-HTTPS and internal targets before any network call.
// 2026-11-10 (same session, CodeRabbit review on PR 19): a job interrupted by host shutdown goes back to enqueued
// without using a retry, and the webhook sender never follows redirects (a 3xx is a failed attempt).
// Touches: the jobs database (jobs, job_runs), outbound HTTPS for webhook_retry (production sender only).
#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace BackgroundJobs
{
    // -------------------------------------------------------------------------
    // Data models & EF Core context
    // -------------------------------------------------------------------------
    public enum JobStatus
    {
        Enqueued,
        Running,
        Completed,
        Failed,
        Cancelled
    }

    /// <summary>Implements the interface member of the same name; see the class summary. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    /// <summary>A queued task (spec schema jobs). Progress is "done/total", "0/0" from the moment a job is claimed. Updated 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Pure data.</summary>
    public class Job
    {
        [Key]
        public Guid Id { get; set; }

        [Required]
        public string TaskType { get; set; } = null!;

        [Required]
        public string ParamsJson { get; set; } = "{}";

        [Required]
        public JobStatus Status { get; set; } = JobStatus.Enqueued;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? StartedAt { get; set; }
        public DateTime? CompletedAt { get; set; }

        public string? Progress { get; set; } // e.g. "45/100"; "0/0" from the moment a job is claimed

        public string? ResultJson { get; set; }

        public string? Error { get; set; }

        public int RetryCount { get; set; } = 0;

        public int MaxRetries { get; set; } = 3;

        public DateTime? NextRetryAt { get; set; }

        public DateTime? ScheduledAt { get; set; }
    }

    /// <summary>Implements the interface member of the same name; see the class summary. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    /// <summary>One attempt at a job (spec schema job_runs), now with the attempt's error. Updated 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Pure data.</summary>
    public class JobRun
    {
        [Key]
        public Guid Id { get; set; }

        [Required]
        public Guid JobId { get; set; }

        [ForeignKey(nameof(JobId))]
        public Job Job { get; set; } = null!;

        [Required]
        public JobStatus Status { get; set; }

        public DateTime StartedAt { get; set; } = DateTime.UtcNow;
        public DateTime? CompletedAt { get; set; }

        public string? ResultJson { get; set; }

        public string? Error { get; set; }
    }

    /// <summary>Implements the interface member of the same name; see the class summary. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    /// <summary>EF Core context for jobs and job_runs (SQLite-compatible mapping). Updated 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (job_runs.error). Touches: the jobs database.</summary>
    public class JobsDbContext : DbContext
    {
        public DbSet<Job> Jobs => Set<Job>();
        public DbSet<JobRun> JobRuns => Set<JobRun>();

        public JobsDbContext(DbContextOptions<JobsDbContext> options) : base(options) { }

        /// <summary>Maps the entities to their tables and indexes. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the EF model only.</summary>
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // DDL equivalent (SQLite compatible)
            modelBuilder.Entity<Job>(entity =>
            {
                entity.ToTable("jobs");
                entity.Property(e => e.Id).HasColumnName("id");
                entity.Property(e => e.TaskType).HasColumnName("task_type");
                entity.Property(e => e.ParamsJson).HasColumnName("params");
                entity.Property(e => e.Status).HasColumnName("status")
                      .HasConversion<string>();
                entity.Property(e => e.CreatedAt).HasColumnName("created_at");
                entity.Property(e => e.StartedAt).HasColumnName("started_at");
                entity.Property(e => e.CompletedAt).HasColumnName("completed_at");
                entity.Property(e => e.Progress).HasColumnName("progress");
                entity.Property(e => e.ResultJson).HasColumnName("result");
                entity.Property(e => e.Error).HasColumnName("error");
                entity.Property(e => e.RetryCount).HasColumnName("retry_count");
                entity.Property(e => e.MaxRetries).HasColumnName("max_retries");
                entity.Property(e => e.NextRetryAt).HasColumnName("next_retry_at");
                entity.Property(e => e.ScheduledAt).HasColumnName("scheduled_at");
            });

            modelBuilder.Entity<JobRun>(entity =>
            {
                entity.ToTable("job_runs");
                entity.Property(e => e.Id).HasColumnName("id");
                entity.Property(e => e.JobId).HasColumnName("job_id");
                entity.Property(e => e.Status).HasColumnName("status")
                      .HasConversion<string>();
                entity.Property(e => e.StartedAt).HasColumnName("started_at");
                entity.Property(e => e.CompletedAt).HasColumnName("completed_at");
                entity.Property(e => e.ResultJson).HasColumnName("result");
                entity.Property(e => e.Error).HasColumnName("error");
            });
        }
    }

    // -------------------------------------------------------------------------
    // Repository
    // -------------------------------------------------------------------------
    /// <summary>
    /// Data access for jobs. Every status change is one conditional UPDATE (spec: "Status changes are atomic"), so two
    /// workers cannot both claim a job and a cancel cannot race a start. Changed 2026-11-10 (session
    /// session_012zDydZCZ4AChqhEZ4oVtaP): ClaimAsync, RecordFailureAsync and run records added; cancel made atomic.
    /// RequeueInterruptedAsync added the same day (CodeRabbit review on PR 19): a job interrupted by shutdown goes back
    /// to enqueued without using a retry. Touches: jobs, job_runs.
    /// </summary>
    public interface IJobRepository
    {
        Task<Job> EnqueueAsync(string taskType, object parameters, DateTime? scheduledAt, int maxRetries);
        Task<Job?> GetAsync(Guid jobId);
        Task<List<Job>> ListAsync(string? status, string? taskType, int limit);
        Task<bool> CancelAsync(Guid jobId);
        Task<Job?> RetryAsync(Guid jobId);
        Task UpdateProgressAsync(Guid jobId, string progress);
        Task<bool> ClaimAsync(Guid jobId, DateTime now);
        Task MarkCompletedAsync(Guid jobId, object result);
        Task<JobStatus> RecordFailureAsync(Guid jobId, string error, DateTime now);
        Task<bool> RequeueInterruptedAsync(Guid jobId, DateTime now);
    }

    /// <summary>EF Core implementation of <see cref="IJobRepository"/>. Touches: jobs, job_runs.</summary>
    public class JobRepository : IJobRepository
    {
        private readonly JobsDbContext _db;

        public JobRepository(JobsDbContext db) => _db = db;

        /// <summary>Stores a new enqueued job. Inputs: task type, params (serialised to JSON), optional run-at time, retry budget. Touches: jobs.</summary>
        public async Task<Job> EnqueueAsync(string taskType, object parameters, DateTime? scheduledAt, int maxRetries)
        {
            var job = new Job
            {
                Id = Guid.NewGuid(),
                TaskType = taskType,
                ParamsJson = JsonSerializer.Serialize(parameters ?? new { }),
                Status = JobStatus.Enqueued,
                CreatedAt = DateTime.UtcNow,
                ScheduledAt = scheduledAt?.ToUniversalTime(),
                MaxRetries = maxRetries
            };
            _db.Jobs.Add(job);
            await _db.SaveChangesAsync();
            return job;
        }

        /// <summary>Reads one job without tracking, so a status read always reflects the database. Touches: jobs (read).</summary>
        public Task<Job?> GetAsync(Guid jobId) => _db.Jobs.AsNoTracking().FirstOrDefaultAsync(j => j.Id == jobId);

        /// <summary>Lists jobs, newest first, optionally by status and task type. Touches: jobs (read).</summary>
        public async Task<List<Job>> ListAsync(string? status, string? taskType, int limit)
        {
            var query = _db.Jobs.AsNoTracking().AsQueryable();
            if (!string.IsNullOrEmpty(status) && Enum.TryParse<JobStatus>(status, true, out var st))
                query = query.Where(j => j.Status == st);
            if (!string.IsNullOrEmpty(taskType))
                query = query.Where(j => j.TaskType == taskType);
            return await query.OrderByDescending(j => j.CreatedAt).Take(limit).ToListAsync();
        }

        /// <summary>
        /// Cancels a job only while it is still enqueued (spec: "only if not started"), in one conditional UPDATE so a
        /// worker that claims it at the same moment cannot also run it. Output: true when cancelled. Touches: jobs.
        /// </summary>
        public async Task<bool> CancelAsync(Guid jobId)
        {
            var changed = await _db.Jobs
                .Where(j => j.Id == jobId && j.Status == JobStatus.Enqueued)
                .ExecuteUpdateAsync(u => u.SetProperty(j => j.Status, JobStatus.Cancelled));
            return changed == 1;
        }

        /// <summary>Creates a fresh enqueued copy of a failed job (spec endpoint 5). Output: the new job, or null when the job is missing or not failed. Touches: jobs.</summary>
        public async Task<Job?> RetryAsync(Guid jobId)
        {
            var oldJob = await _db.Jobs.AsNoTracking().FirstOrDefaultAsync(j => j.Id == jobId);
            if (oldJob == null || oldJob.Status != JobStatus.Failed) return null;

            var newJob = new Job
            {
                Id = Guid.NewGuid(),
                TaskType = oldJob.TaskType,
                ParamsJson = oldJob.ParamsJson,
                Status = JobStatus.Enqueued,
                CreatedAt = DateTime.UtcNow,
                MaxRetries = oldJob.MaxRetries,
                ScheduledAt = null
            };
            _db.Jobs.Add(newJob);
            await _db.SaveChangesAsync();
            return newJob;
        }

        /// <summary>Sets a running job's "done/total" progress. Touches: jobs.</summary>
        public Task UpdateProgressAsync(Guid jobId, string progress) =>
            _db.Jobs.Where(j => j.Id == jobId && j.Status == JobStatus.Running)
                .ExecuteUpdateAsync(u => u.SetProperty(j => j.Progress, progress));

        /// <summary>
        /// Atomically moves an enqueued job to running (status, started_at, progress "0/0") and opens a job_runs row.
        /// Output: false when another worker or a cancel got there first. Added 2026-11-10 (session
        /// session_012zDydZCZ4AChqhEZ4oVtaP). Touches: jobs, job_runs.
        /// </summary>
        public async Task<bool> ClaimAsync(Guid jobId, DateTime now)
        {
            var claimed = await _db.Jobs
                .Where(j => j.Id == jobId && j.Status == JobStatus.Enqueued)
                .ExecuteUpdateAsync(u => u
                    .SetProperty(j => j.Status, JobStatus.Running)
                    .SetProperty(j => j.StartedAt, now)
                    .SetProperty(j => j.Progress, "0/0"));
            if (claimed != 1) return false;
            _db.JobRuns.Add(new JobRun { Id = Guid.NewGuid(), JobId = jobId, Status = JobStatus.Running, StartedAt = now });
            await _db.SaveChangesAsync();
            return true;
        }

        /// <summary>Marks a running job completed with its result and closes its open run. Touches: jobs, job_runs.</summary>
        public async Task MarkCompletedAsync(Guid jobId, object result)
        {
            var now = DateTime.UtcNow;
            var json = JsonSerializer.Serialize(result);
            await _db.Jobs.Where(j => j.Id == jobId && j.Status == JobStatus.Running)
                .ExecuteUpdateAsync(u => u
                    .SetProperty(j => j.Status, JobStatus.Completed)
                    .SetProperty(j => j.CompletedAt, now)
                    .SetProperty(j => j.ResultJson, json));
            await CloseRunAsync(jobId, JobStatus.Completed, json, null, now);
        }

        /// <summary>
        /// Records a failed attempt: retry_count + 1; past max_retries the job is failed for good, otherwise it is
        /// re-enqueued with next_retry_at = now + 2^(retry_count-1) seconds (1s, 2s, 4s, ...; spec "Exponential
        /// backoff"). Output: the job's new status. Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): the
        /// old code saved the final failure without its retry count. Touches: jobs, job_runs.
        /// </summary>
        public async Task<JobStatus> RecordFailureAsync(Guid jobId, string error, DateTime now)
        {
            var job = await _db.Jobs.FirstOrDefaultAsync(j => j.Id == jobId);
            if (job == null) return JobStatus.Failed;
            job.RetryCount++;
            job.Error = error;
            if (job.RetryCount > job.MaxRetries)
            {
                job.Status = JobStatus.Failed;
                job.CompletedAt = now;
                job.NextRetryAt = null;
            }
            else
            {
                job.Status = JobStatus.Enqueued;
                job.NextRetryAt = now.AddSeconds(Math.Pow(2, job.RetryCount - 1));
            }
            await _db.SaveChangesAsync();
            await CloseRunAsync(jobId, JobStatus.Failed, null, error, now);
            return job.Status;
        }

        /// <summary>Error text written on a job_runs row closed because the worker stopped mid-attempt.</summary>
        public const string InterruptedError = "interrupted: the worker stopped during this attempt; the job was re-enqueued without using a retry";

        /// <summary>
        /// Puts a job that was running when the host stopped back in the queue: one conditional UPDATE (only while it is
        /// still running) sets status enqueued, clears started_at, progress and next_retry_at so the next worker picks it
        /// up at once, and leaves retry_count unchanged (a shutdown is not a failed attempt). The open job_runs row is
        /// closed as cancelled with <see cref="InterruptedError"/>. Every database call uses CancellationToken.None,
        /// because the caller's token is already cancelled when this runs. Inputs: the job id and the time to record.
        /// Output: true when the job was re-enqueued. Why: CodeRabbit review on PR 19, a job interrupted by shutdown
        /// stayed "running" forever (the worker only picks enqueued jobs) with its run left open. Added 2026-11-10,
        /// session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: jobs, job_runs.
        /// </summary>
        public async Task<bool> RequeueInterruptedAsync(Guid jobId, DateTime now)
        {
            var requeued = await _db.Jobs
                .Where(j => j.Id == jobId && j.Status == JobStatus.Running)
                .ExecuteUpdateAsync(u => u
                    .SetProperty(j => j.Status, JobStatus.Enqueued)
                    .SetProperty(j => j.StartedAt, (DateTime?)null)
                    .SetProperty(j => j.Progress, (string?)null)
                    .SetProperty(j => j.NextRetryAt, (DateTime?)null), CancellationToken.None);
            await CloseRunAsync(jobId, JobStatus.Cancelled, null, InterruptedError, now);
            return requeued == 1;
        }

        /// <summary>Closes the job's open job_runs row with an outcome. Touches: job_runs.</summary>
        private async Task CloseRunAsync(Guid jobId, JobStatus status, string? resultJson, string? error, DateTime now)
        {
            var run = await _db.JobRuns
                .Where(r => r.JobId == jobId && r.CompletedAt == null)
                .OrderByDescending(r => r.StartedAt)
                .FirstOrDefaultAsync();
            if (run == null) return;
            run.Status = status;
            run.CompletedAt = now;
            run.ResultJson = resultJson;
            run.Error = error;
            await _db.SaveChangesAsync();
        }
    }

    // -------------------------------------------------------------------------
    // Webhook delivery (used by webhook_retry)
    // -------------------------------------------------------------------------
    /// <summary>
    /// Delivers one webhook. Production: <see cref="HttpWebhookSender"/>; a test may substitute a fake. Added 2026-11-10
    /// (session session_012zDydZCZ4AChqhEZ4oVtaP) so webhook_retry does real work instead of always succeeding.
    /// Touches: the network in production implementations.
    /// </summary>
    public interface IWebhookSender
    {
        Task SendAsync(string url, string payloadJson, CancellationToken ct);
    }

    /// <summary>
    /// Posts webhooks over HTTPS. Before any network call it refuses (ArgumentException) a target that is not an
    /// absolute https URL, a single-label or reserved host name (localhost, *.local, *.internal, *.invalid, *.test,
    /// *.example), or a literal loopback, private, link-local or unspecified IP, so a job's parameters cannot aim the
    /// server at itself or its network (SSRF). A non-2xx answer throws, which makes the job retry. Added 2026-11-10
    /// (session session_012zDydZCZ4AChqhEZ4oVtaP). Touches: outbound HTTPS. Note: host names are not resolved here;
    /// deployments should also restrict egress at the network layer, because DNS can point a public name inward.
    /// Redirects are never followed (CodeRabbit review on PR 19, 2026-11-10, same session): the check above only sees
    /// the first URL, so a public https host answering 302 to an internal address would otherwise bypass it. The
    /// sender builds its own HttpClient, turns AllowAutoRedirect off on the handler it is given (through any
    /// DelegatingHandler chain), and treats a 3xx answer as a failed attempt. There is deliberately no constructor that
    /// takes a ready-made HttpClient, whose redirect setting could not be checked.
    /// </summary>
    public class HttpWebhookSender : IWebhookSender
    {
        private static readonly string[] ReservedSuffixes = { ".localhost", ".local", ".internal", ".invalid", ".test", ".example" };
        /// <summary>Time limit of one delivery attempt when none is given.</summary>
        public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(10);
        private readonly HttpClient _http;

        /// <summary>
        /// Production sender: a SocketsHttpHandler with redirects off and a <see cref="DefaultTimeout"/> per attempt.
        /// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review on PR 19), replacing the
        /// HttpClient constructor. Touches: nothing until a send.
        /// </summary>
        public HttpWebhookSender() : this(new SocketsHttpHandler { AllowAutoRedirect = false }, DefaultTimeout) { }

        /// <summary>
        /// Sender over a given handler (a custom transport, or a stub in tests). Inputs: the handler, which must not
        /// have sent a request yet, and the per-attempt timeout. It switches AllowAutoRedirect off on the innermost
        /// SocketsHttpHandler or HttpClientHandler, so no handler passed here can follow a redirect on its own. Added
        /// 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review on PR 19). Touches: the handler's
        /// settings.
        /// </summary>
        public HttpWebhookSender(HttpMessageHandler handler, TimeSpan timeout)
        {
            DisableRedirects(handler ?? throw new ArgumentNullException(nameof(handler)));
            _http = new HttpClient(handler) { Timeout = timeout };
        }

        /// <summary>
        /// Validates the target (see the class summary), then POSTs the JSON payload. Throws on refusal, on a 3xx
        /// answer (redirects are not followed, so an internal Location is never reached) and on any other non-2xx
        /// answer. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review on PR 19: 3xx is a
        /// failure). Touches: network.
        /// </summary>
        public async Task SendAsync(string url, string payloadJson, CancellationToken ct)
        {
            var target = ValidateTarget(url);
            using var content = new StringContent(payloadJson ?? "{}", Encoding.UTF8, "application/json");
            using var response = await _http.PostAsync(target, content, ct);
            var code = (int)response.StatusCode;
            if (code >= 300 && code < 400)
                throw new HttpRequestException($"Webhook endpoint answered a redirect ({code}); redirects are not followed");
            if (!response.IsSuccessStatusCode)
                throw new HttpRequestException($"Webhook endpoint answered {code}");
        }

        /// <summary>
        /// Walks a DelegatingHandler chain to its innermost handler and turns AllowAutoRedirect off when it is a
        /// SocketsHttpHandler or HttpClientHandler (other handlers do not follow redirects by themselves; SendAsync also
        /// refuses any 3xx). Input: the handler. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit
        /// review on PR 19). Touches: the handler's settings.
        /// </summary>
        private static void DisableRedirects(HttpMessageHandler handler)
        {
            var current = handler;
            while (current is DelegatingHandler delegating && delegating.InnerHandler != null)
                current = delegating.InnerHandler;
            if (current is SocketsHttpHandler sockets) sockets.AllowAutoRedirect = false;
            else if (current is HttpClientHandler client) client.AllowAutoRedirect = false;
        }

        /// <summary>Returns the parsed URL when it is an allowed webhook target; throws ArgumentException otherwise. Pure.</summary>
        public static Uri ValidateTarget(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
                throw new ArgumentException("Webhook URL must be an absolute https URL");
            var host = uri.IdnHost.TrimEnd('.').ToLowerInvariant();
            if (IPAddress.TryParse(host.Trim('[', ']'), out var ip))
            {
                if (IsInternal(ip)) throw new ArgumentException("Webhook URL must not target an internal address");
                return uri;
            }
            if (!host.Contains('.') || host == "localhost" || ReservedSuffixes.Any(s => host.EndsWith(s, StringComparison.Ordinal)))
                throw new ArgumentException("Webhook URL must name a public host");
            return uri;
        }

        /// <summary>True for loopback, private (RFC 1918 / ULA), link-local, CGNAT and unspecified addresses. Pure.</summary>
        private static bool IsInternal(IPAddress ip)
        {
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return true;
            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || (ip.GetAddressBytes()[0] & 0xFE) == 0xFC;
            var b = ip.GetAddressBytes();
            return b[0] == 10 || b[0] == 0 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);
        }
    }

    // -------------------------------------------------------------------------
    // Job handlers
    // -------------------------------------------------------------------------
    /// <summary>
    /// One task type. ExecuteAsync does the work, reports progress through the repository and returns the result to
    /// store; throwing makes the job retry. Changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): handlers
    /// return their result instead of writing the job row, so completion is recorded in one place.
    /// </summary>
    public interface IJobHandler
    {
        Task<object> ExecuteAsync(Job job, IJobRepository repo, CancellationToken ct);
    }

    /// <summary>
    /// send_bulk_email: walks the recipients in batches, reporting "sent/total" progress. This template simulates
    /// sending (no SMTP); a real one calls the Notifications system per recipient. Touches: jobs (progress).
    /// </summary>
    public class SendBulkEmailHandler : IJobHandler
    {
        /// <summary>Runs this task for one job and returns its result; throws to make the job retry. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: see the class summary.</summary>
        public async Task<object> ExecuteAsync(Job job, IJobRepository repo, CancellationToken ct)
        {
            const int total = 500;
            int sent = 0;
            await repo.UpdateProgressAsync(job.Id, $"0/{total}");
            for (int i = 1; i <= total; i++)
            {
                ct.ThrowIfCancellationRequested();
                sent++;
                if (i % 25 == 0)
                {
                    await Task.Delay(100, ct); // one simulated batch
                    await repo.UpdateProgressAsync(job.Id, $"{i}/{total}");
                }
            }
            return new { task_type = job.TaskType, sent, failed = 0, skipped = 0, errors = Array.Empty<object>() };
        }
    }

    /// <summary>
    /// webhook_retry: re-delivers a webhook (params: url, payload) through <see cref="IWebhookSender"/>. A refused or
    /// failed delivery throws, so the queue retries it with backoff. Rewritten 2026-11-10 (session
    /// session_012zDydZCZ4AChqhEZ4oVtaP): it used to report success without sending anything. Touches: the network
    /// through the sender.
    /// </summary>
    public class WebhookRetryHandler : IJobHandler
    {
        private readonly IWebhookSender _sender;

        public WebhookRetryHandler(IWebhookSender sender) => _sender = sender;

        /// <summary>Runs this task for one job and returns its result; throws to make the job retry. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: see the class summary.</summary>
        public async Task<object> ExecuteAsync(Job job, IJobRepository repo, CancellationToken ct)
        {
            using var doc = JsonDocument.Parse(job.ParamsJson);
            var url = doc.RootElement.TryGetProperty("url", out var u) && u.ValueKind == JsonValueKind.String ? u.GetString() : null;
            if (string.IsNullOrWhiteSpace(url)) throw new ArgumentException("webhook_retry needs a url");
            var payload = doc.RootElement.TryGetProperty("payload", out var p) ? p.GetRawText() : "{}";
            await repo.UpdateProgressAsync(job.Id, "0/1");
            await _sender.SendAsync(url, payload, ct);
            await repo.UpdateProgressAsync(job.Id, "1/1");
            return new { task_type = job.TaskType, delivered = true };
        }
    }

    /// <summary>export_generate: simulated export build (a real one calls the Data Export system). Touches: jobs (progress).</summary>
    public class ExportGenerateHandler : IJobHandler
    {
        /// <summary>Runs this task for one job and returns its result; throws to make the job retry. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: see the class summary.</summary>
        public async Task<object> ExecuteAsync(Job job, IJobRepository repo, CancellationToken ct)
        {
            await repo.UpdateProgressAsync(job.Id, "0/1");
            await Task.Delay(500, ct);
            await repo.UpdateProgressAsync(job.Id, "1/1");
            return new { task_type = job.TaskType, export_id = job.Id };
        }
    }

    /// <summary>daily_report_generate: simulated metrics aggregation. Touches: jobs (progress).</summary>
    public class DailyReportHandler : IJobHandler
    {
        /// <summary>Runs this task for one job and returns its result; throws to make the job retry. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: see the class summary.</summary>
        public async Task<object> ExecuteAsync(Job job, IJobRepository repo, CancellationToken ct)
        {
            await repo.UpdateProgressAsync(job.Id, "0/1");
            await Task.Delay(300, ct);
            await repo.UpdateProgressAsync(job.Id, "1/1");
            return new { task_type = job.TaskType, report_id = job.Id };
        }
    }

    /// <summary>cleanup_old_sessions: simulated deletion of sessions older than 30 days. Touches: jobs (progress).</summary>
    public class CleanupOldSessionsHandler : IJobHandler
    {
        /// <summary>Runs this task for one job and returns its result; throws to make the job retry. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: see the class summary.</summary>
        public async Task<object> ExecuteAsync(Job job, IJobRepository repo, CancellationToken ct)
        {
            await repo.UpdateProgressAsync(job.Id, "0/1");
            await Task.Delay(150, ct);
            await repo.UpdateProgressAsync(job.Id, "1/1");
            return new { task_type = job.TaskType, cleaned = true };
        }
    }

    /// <summary>delete_user_cascade: simulated cascade (a real one calls the Data Export deletion). Touches: jobs (progress).</summary>
    public class DeleteUserCascadeHandler : IJobHandler
    {
        /// <summary>Runs this task for one job and returns its result; throws to make the job retry. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: see the class summary.</summary>
        public async Task<object> ExecuteAsync(Job job, IJobRepository repo, CancellationToken ct)
        {
            await repo.UpdateProgressAsync(job.Id, "0/1");
            await Task.Delay(400, ct);
            await repo.UpdateProgressAsync(job.Id, "1/1");
            return new { task_type = job.TaskType, deleted = true };
        }
    }

    /// <summary>Maps a task type to its handler. Unknown types are refused at enqueue time. Touches: nothing.</summary>
    public class JobDispatcher
    {
        public static readonly IReadOnlyDictionary<string, Type> Handlers = new Dictionary<string, Type>
        {
            { "send_bulk_email", typeof(SendBulkEmailHandler) },
            { "webhook_retry", typeof(WebhookRetryHandler) },
            { "export_generate", typeof(ExportGenerateHandler) },
            { "daily_report_generate", typeof(DailyReportHandler) },
            { "cleanup_old_sessions", typeof(CleanupOldSessionsHandler) },
            { "delete_user_cascade", typeof(DeleteUserCascadeHandler) }
        };

        /// <summary>True when a handler exists for the task type. Pure.</summary>
        public static bool IsKnown(string? taskType) => taskType != null && Handlers.ContainsKey(taskType);

        /// <summary>Resolves the handler for a task type from the given scope, or null. Touches: nothing.</summary>
        public IJobHandler? Resolve(IServiceProvider scope, string taskType) =>
            Handlers.TryGetValue(taskType, out var type) ? (IJobHandler?)scope.GetService(type) : null;
    }

    // -------------------------------------------------------------------------
    // Background worker
    // -------------------------------------------------------------------------
    /// <summary>
    /// The worker: every <see cref="PollInterval"/> it takes due jobs (enqueued, scheduled_at and next_retry_at
    /// passed) oldest first, claims each atomically and runs it; a thrown exception is a failed attempt (see
    /// RecordFailureAsync). Changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): atomic claim, one place
    /// records the outcome, the retry count is always saved, a failing poll is logged instead of stopping the worker.
    /// Touches: jobs, job_runs, and whatever the handlers touch.
    /// </summary>
    public class JobProcessor : BackgroundService
    {
        public static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(500);
        private readonly IServiceProvider _sp;
        private readonly ILogger<JobProcessor> _logger;

        public JobProcessor(IServiceProvider sp, ILogger<JobProcessor> logger)
        {
            _sp = sp;
            _logger = logger;
        }

        /// <summary>Polls until the host stops. Touches: see the class summary.</summary>
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await ProcessPendingJobs(stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Job poll failed");
                }
                await Task.Delay(PollInterval, stoppingToken);
            }
        }

        /// <summary>
        /// Runs one poll: up to 5 due jobs, oldest first. Input: the host's stopping token. Output: none; throws
        /// OperationCanceledException when the host stops, after re-enqueueing the job that was running (see
        /// <see cref="IJobRepository.RequeueInterruptedAsync"/>). Internal (was private) so a test can run one poll
        /// deterministically. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review on PR 19).
        /// Touches: jobs, job_runs, and whatever the handlers touch.
        /// </summary>
        internal async Task ProcessPendingJobs(CancellationToken ct)
        {
            List<Guid> due;
            using (var scope = _sp.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<JobsDbContext>();
                var now = DateTime.UtcNow;
                due = await db.Jobs
                    .AsNoTracking()
                    .Where(j => j.Status == JobStatus.Enqueued &&
                                (j.ScheduledAt == null || j.ScheduledAt <= now) &&
                                (j.NextRetryAt == null || j.NextRetryAt <= now))
                    .OrderBy(j => j.CreatedAt)
                    .Select(j => j.Id)
                    .Take(5)
                    .ToListAsync(ct);
            }

            foreach (var jobId in due)
            {
                ct.ThrowIfCancellationRequested();
                using var scope = _sp.CreateScope();
                var repo = scope.ServiceProvider.GetRequiredService<IJobRepository>();
                if (!await repo.ClaimAsync(jobId, DateTime.UtcNow)) continue; // cancelled or taken meanwhile
                var job = await repo.GetAsync(jobId);
                if (job == null) continue;
                try
                {
                    var handler = scope.ServiceProvider.GetRequiredService<JobDispatcher>().Resolve(scope.ServiceProvider, job.TaskType)
                        ?? throw new InvalidOperationException($"No handler for task type {job.TaskType}");
                    var result = await handler.ExecuteAsync(job, repo, ct);
                    await repo.MarkCompletedAsync(job.Id, result);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    // The host is stopping: hand the job back to the queue (no retry used) before giving up, or it would
                    // stay "running" forever. CodeRabbit review on PR 19; 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
                    try
                    {
                        await repo.RequeueInterruptedAsync(job.Id, DateTime.UtcNow);
                    }
                    // Only database failures are caught (ExecuteUpdate raises the provider's DbException, SaveChanges a
                    // DbUpdateException); the cancellation is rethrown either way. Narrowed from a catch-all for code
                    // scanning on PR 19, 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
                    catch (System.Data.Common.DbException requeueError)
                    {
                        _logger.LogError(requeueError, "Job {JobId} was interrupted and could not be re-enqueued", job.Id);
                    }
                    catch (DbUpdateException requeueError)
                    {
                        _logger.LogError(requeueError, "Job {JobId} was interrupted and could not be re-enqueued", job.Id);
                    }
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Job {JobId} ({TaskType}) attempt failed: {Error}", job.Id, job.TaskType, ex.Message);
                    await repo.RecordFailureAsync(job.Id, ex.Message, DateTime.UtcNow);
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // API endpoints (minimal API)
    // -------------------------------------------------------------------------
    /// <summary>
    /// Service registration and the six HTTP endpoints of the spec. Changed 2026-11-10 (session
    /// session_012zDydZCZ4AChqhEZ4oVtaP): EnsureCreated instead of Migrate (this template ships no migrations, so
    /// Migrate created no tables), endpoints mapped on the WebApplication, enqueue validates its input.
    /// Touches: the jobs database; the network through IWebhookSender.
    /// </summary>
    public class Startup
    {
        /// <summary>Most retries a job may ask for.</summary>
        public const int MaxRetriesLimit = 10;

        /// <summary>
        /// Registers the database (SQLite file jobs.db), repository, handlers, webhook sender and worker. The webhook
        /// sender is built with redirects off (a 3xx is a failed attempt), so a public host cannot redirect a delivery
        /// past the SSRF check to an internal address; changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP
        /// (CodeRabbit review on PR 19). Touches: nothing until resolved.
        /// </summary>
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<JobsDbContext>(opt => opt.UseSqlite("Data Source=jobs.db"));
            services.AddScoped<IJobRepository, JobRepository>();
            services.AddSingleton<JobDispatcher>();
            services.AddSingleton<IWebhookSender>(_ => new HttpWebhookSender(new SocketsHttpHandler { AllowAutoRedirect = false }, HttpWebhookSender.DefaultTimeout));
            services.AddTransient<SendBulkEmailHandler>();
            services.AddTransient<WebhookRetryHandler>();
            services.AddTransient<ExportGenerateHandler>();
            services.AddTransient<DailyReportHandler>();
            services.AddTransient<CleanupOldSessionsHandler>();
            services.AddTransient<DeleteUserCascadeHandler>();
            services.AddHostedService<JobProcessor>();
            services.AddLogging();
        }

        /// <summary>Creates the schema if missing and maps the endpoints. Touches: the jobs database.</summary>
        public void Configure(WebApplication app)
        {
            using (var scope = app.Services.CreateScope())
            {
                scope.ServiceProvider.GetRequiredService<JobsDbContext>().Database.EnsureCreated();
            }

            // 1. Enqueue job
            app.MapPost("/jobs/enqueue", async (HttpContext http, IJobRepository repo) =>
            {
                EnqueueRequest? payload;
                try
                {
                    payload = await JsonSerializer.DeserializeAsync<EnqueueRequest>(http.Request.Body);
                }
                catch (JsonException)
                {
                    return Results.BadRequest(new { success = false, error = "invalid_payload" });
                }
                if (payload == null || !JobDispatcher.IsKnown(payload.TaskType))
                    return Results.BadRequest(new { success = false, error = "unknown_task_type" });
                var maxRetries = payload.MaxRetries ?? 3;
                if (maxRetries < 0 || maxRetries > MaxRetriesLimit)
                    return Results.BadRequest(new { success = false, error = "invalid_max_retries" });

                object parameters = payload.Params.HasValue ? payload.Params.Value : new { };
                var job = await repo.EnqueueAsync(payload.TaskType, parameters, payload.ScheduledAt, maxRetries);
                return Results.Ok(new { success = true, job_id = job.Id, status = job.Status.ToString().ToLowerInvariant() });
            });

            // 2. Get job status
            app.MapGet("/jobs/{jobId:guid}", async (Guid jobId, IJobRepository repo) =>
            {
                var job = await repo.GetAsync(jobId);
                if (job == null) return Results.NotFound();
                return Results.Ok(new
                {
                    job_id = job.Id,
                    task_type = job.TaskType,
                    status = job.Status.ToString().ToLowerInvariant(),
                    progress = job.Progress,
                    created_at = job.CreatedAt,
                    started_at = job.StartedAt,
                    result = ParseJson(job.ResultJson),
                    error = job.Error,
                    retry_count = job.RetryCount,
                    next_retry_at = job.NextRetryAt
                });
            });

            // 3. List jobs
            app.MapGet("/jobs", async (HttpRequest req, IJobRepository repo) =>
            {
                int limit = 10;
                if (int.TryParse(req.Query["limit"], out var l)) limit = Math.Clamp(l, 1, 100);
                var jobs = await repo.ListAsync(req.Query["status"], req.Query["task_type"], limit);
                var list = jobs.Select(j => new
                {
                    job_id = j.Id,
                    task_type = j.TaskType,
                    status = j.Status.ToString().ToLowerInvariant(),
                    created_at = j.CreatedAt
                });
                return Results.Ok(new { jobs = list, total = jobs.Count });
            });

            // 4. Cancel job
            app.MapDelete("/jobs/{jobId:guid}", async (Guid jobId, IJobRepository repo) =>
            {
                if (!await repo.CancelAsync(jobId)) return Results.BadRequest(new { success = false, error = "cannot_cancel" });
                return Results.Ok(new { success = true, status = "cancelled" });
            });

            // 5. Retry failed job
            app.MapPost("/jobs/{jobId:guid}/retry", async (Guid jobId, IJobRepository repo) =>
            {
                var newJob = await repo.RetryAsync(jobId);
                if (newJob == null) return Results.BadRequest(new { success = false, error = "retry_not_possible" });
                return Results.Ok(new { success = true, new_job_id = newJob.Id, status = newJob.Status.ToString().ToLowerInvariant() });
            });

            // 6. Get results
            app.MapGet("/jobs/{jobId:guid}/results", async (Guid jobId, IJobRepository repo) =>
            {
                var job = await repo.GetAsync(jobId);
                if (job == null) return Results.NotFound();
                if (job.Status != JobStatus.Completed) return Results.BadRequest(new { error = "job_not_completed" });
                return Results.Ok(new
                {
                    job_id = job.Id,
                    status = job.Status.ToString().ToLowerInvariant(),
                    result = ParseJson(job.ResultJson),
                    completed_at = job.CompletedAt
                });
            });
        }

        /// <summary>Parses stored JSON into a JsonElement for the response (null when absent). Pure.</summary>
        private static JsonElement? ParseJson(string? json)
        {
            if (json == null) return null;
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.Clone();
        }
    }

    // -------------------------------------------------------------------------
    // DTOs
    // -------------------------------------------------------------------------
    /// <summary>Body of POST /jobs/enqueue. Pure data.</summary>
    public class EnqueueRequest
    {
        [JsonPropertyName("task_type")]
        public string TaskType { get; set; } = null!;

        [JsonPropertyName("params")]
        public JsonElement? Params { get; set; }

        [JsonPropertyName("scheduled_at")]
        public DateTime? ScheduledAt { get; set; }

        [JsonPropertyName("max_retries")]
        public int? MaxRetries { get; set; }
    }

    // -------------------------------------------------------------------------
    // Program entry point
    // -------------------------------------------------------------------------
    /// <summary>Builds and runs the web host: services, schema, endpoints, worker. Touches: see Startup.</summary>
    public class Program
    {
        /// <summary>Entry point: builds the host from Startup and runs it. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: see Startup.</summary>
        public static async Task Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            var startup = new Startup();
            startup.ConfigureServices(builder.Services);
            var app = builder.Build();
            startup.Configure(app);
            await app.RunAsync();
        }
    }
}

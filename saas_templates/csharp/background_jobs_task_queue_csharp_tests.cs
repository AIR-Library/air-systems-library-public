using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using BackgroundJobs;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

public class BackgroundJobsTests : IClassFixture<WebApplicationFactory<BackgroundJobs.Program>>
{
    private readonly WebApplicationFactory<BackgroundJobs.Program> _factory;

    // Keeps this test's shared in-memory database alive for the life of the test.
    private readonly SqliteConnection _keepAlive;

    /// <summary>
    /// Points WebApplicationFactory at a content root. It otherwise looks for a solution (.sln) above the test binaries,
    /// which a single-assembly build (app and tests compiled together, as the library's runner does) does not have, and
    /// every test failed with "Solution root could not be located". WebApplicationFactory reads the documented
    /// ASPNETCORE_TEST_CONTENTROOT_&lt;ASSEMBLY&gt; setting first. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: this process's environment.
    /// </summary>
    static BackgroundJobsTests()
    {
        var assembly = typeof(BackgroundJobs.Program).Assembly.GetName().Name!.ToUpperInvariant().Replace(".", "_");
        Environment.SetEnvironmentVariable($"ASPNETCORE_TEST_CONTENTROOT_{assembly}", AppContext.BaseDirectory);
    }

    public BackgroundJobsTests(WebApplicationFactory<BackgroundJobs.Program> factory)
    {
        // One named, shared-cache in-memory database per test. The original opened a new ":memory:" connection inside
        // the options callback, which runs once per scope, so every request and the worker each saw a different,
        // empty database ("no such table"). Separate connections to one shared-cache database are also safe to use
        // from the request threads and the worker at once, which a single shared connection is not.
        // 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
        var connectionString = $"DataSource=file:jobs_{Guid.NewGuid():N}?mode=memory&cache=shared";
        _keepAlive = new SqliteConnection(connectionString);
        _keepAlive.Open();

        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                // Replace SQLite file DB with in‑memory SQLite for isolation
                var descriptor = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<JobsDbContext>));
                if (descriptor != null) services.Remove(descriptor);
                services.AddDbContext<JobsDbContext>(options =>
                {
                    options.UseSqlite(connectionString);
                });
                // Ensure DB is created
                var sp = services.BuildServiceProvider();
                using var scope = sp.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<JobsDbContext>();
                db.Database.EnsureCreated();
            });
        });
    }

    private async Task<Guid> EnqueueJobAsync(string taskType, object parameters, DateTime? scheduledAt = null, int maxRetries = 3)
    {
        var client = _factory.CreateClient();
        var payload = new
        {
            task_type = taskType,
            @params = parameters,
            scheduled_at = scheduledAt,
            max_retries = maxRetries
        };
        var response = await client.PostAsJsonAsync("/jobs/enqueue", payload);
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        var jobId = json.GetProperty("job_id").GetGuid();
        return jobId;
    }

    private async Task<JobStatus> GetJobStatusAsync(Guid jobId)
    {
        var client = _factory.CreateClient();
        var resp = await client.GetAsync($"/jobs/{jobId}");
        resp.EnsureSuccessStatusCode();
        var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
        var statusStr = json.GetProperty("status").GetString()!;
        return Enum.Parse<JobStatus>(statusStr, true);
    }

    private async Task<object?> GetJobResultAsync(Guid jobId)
    {
        var client = _factory.CreateClient();
        var resp = await client.GetAsync($"/jobs/{jobId}/results");
        if (resp.StatusCode == HttpStatusCode.BadRequest) return null;
        resp.EnsureSuccessStatusCode();
        var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
        return json.GetProperty("result");
    }

    private async Task WaitForStatusAsync(Guid jobId, JobStatus desired, TimeSpan timeout)
    {
        var start = DateTime.UtcNow;
        while (DateTime.UtcNow - start < timeout)
        {
            var status = await GetJobStatusAsync(jobId);
            if (status == desired) return;
            await Task.Delay(200);
        }
        throw new TimeoutException($"Job {jobId} did not reach status {desired} in time");
    }

    // JOBS-01
    // JOBS-02
    // JOBS-09
    [Fact]
    public async Task Enqueue_Job_Runs_To_Completion()
    {
        var jobId = await EnqueueJobAsync("send_bulk_email", new { template_key = "test", filter = new { } });
        await WaitForStatusAsync(jobId, JobStatus.Running, TimeSpan.FromSeconds(5));
        await WaitForStatusAsync(jobId, JobStatus.Completed, TimeSpan.FromSeconds(30));
        var result = await GetJobResultAsync(jobId);
        Assert.NotNull(result);
    }

    // JOBS-03
    [Fact]
    public async Task Job_Fails_And_Retries_With_Exponential_Backoff()
    {
        // Use a task type that throws to simulate failure
        var jobId = await EnqueueJobAsync("webhook_retry", new { url = "http://invalid" }, maxRetries: 2);
        await WaitForStatusAsync(jobId, JobStatus.Failed, TimeSpan.FromSeconds(30));

        // Verify retry count via DB inspection
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<JobsDbContext>();
        var job = await db.Jobs.FindAsync(jobId);
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (JOBS-03/04 amendment): retry_count counts retries only,
        // so after the first try and 2 retries it is 2 (was asserted as 3, counting the first try too).
        Assert.Equal(2, job!.RetryCount);
        Assert.Equal(JobStatus.Failed, job.Status);
    }

    // JOBS-04
    [Fact]
    public async Task Job_Exceeds_Max_Retries_And_Fails()
    {
        var jobId = await EnqueueJobAsync("webhook_retry", new { url = "http://invalid" }, maxRetries: 1);
        await WaitForStatusAsync(jobId, JobStatus.Failed, TimeSpan.FromSeconds(30));

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<JobsDbContext>();
        var job = await db.Jobs.FindAsync(jobId);
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (JOBS-04 amendment): failed with retry_count = max_retries
        // (was asserted as 2 = max_retries + 1).
        Assert.Equal(1, job!.RetryCount);
        Assert.Equal(JobStatus.Failed, job.Status);
        Assert.Equal(2, await db.JobRuns.CountAsync(r => r.JobId == jobId)); // the first try and one retry
    }

    // JOBS-05
    [Fact]
    public async Task User_Cancels_Before_Start()
    {
        var future = DateTime.UtcNow.AddMinutes(5);
        var jobId = await EnqueueJobAsync("daily_report_generate", new { }, scheduledAt: future);
        var client = _factory.CreateClient();
        var delResp = await client.DeleteAsync($"/jobs/{jobId}");
        delResp.EnsureSuccessStatusCode();

        var status = await GetJobStatusAsync(jobId);
        Assert.Equal(JobStatus.Cancelled, status);
    }

    // JOBS-06
    [Fact]
    public async Task Progress_Tracking_Updates()
    {
        var jobId = await EnqueueJobAsync("send_bulk_email", new { template_key = "test", filter = new { } });
        await WaitForStatusAsync(jobId, JobStatus.Running, TimeSpan.FromSeconds(5));

        var client = _factory.CreateClient();
        var resp = await client.GetAsync($"/jobs/{jobId}");
        resp.EnsureSuccessStatusCode();
        var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
        var progress = json.GetProperty("progress").GetString();
        Assert.Matches(@"^\d+/\d+$", progress);
    }

    // JOBS-07
    [Fact]
    public async Task Scheduled_Jobs_Run_After_Scheduled_Time()
    {
        var scheduled = DateTime.UtcNow.AddSeconds(3);
        var jobId = await EnqueueJobAsync("cleanup_old_sessions", new { }, scheduledAt: scheduled);
        var statusBefore = await GetJobStatusAsync(jobId);
        Assert.Equal(JobStatus.Enqueued, statusBefore);

        await WaitForStatusAsync(jobId, JobStatus.Completed, TimeSpan.FromSeconds(15));
        var finalStatus = await GetJobStatusAsync(jobId);
        Assert.Equal(JobStatus.Completed, finalStatus);
    }

    // JOBS-08
    [Fact]
    public async Task Bulk_Job_Does_Not_Block_Request()
    {
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: JOBS-08 names 10,000 items; the job now walks 10,000 and
        // the test checks all were processed (before, the handler always walked 500).
        var start = DateTime.UtcNow;
        var jobId = await EnqueueJobAsync("send_bulk_email", new { template_key = "test", filter = new { }, count = 10_000 });
        var elapsed = DateTime.UtcNow - start;
        Assert.True(elapsed.TotalSeconds < 1, "Enqueue request should be fast");
        await WaitForStatusAsync(jobId, JobStatus.Completed, TimeSpan.FromSeconds(30));
        var result = (JsonElement)(await GetJobResultAsync(jobId))!;
        Assert.Equal(10_000, result.GetProperty("sent").GetInt32());
    }

    [Fact]
    public async Task Retry_Failed_Job_Endpoint_Creates_New_Job()
    {
        var jobId = await EnqueueJobAsync("webhook_retry", new { url = "http://invalid" }, maxRetries: 0);
        await WaitForStatusAsync(jobId, JobStatus.Failed, TimeSpan.FromSeconds(30));

        var client = _factory.CreateClient();
        var resp = await client.PostAsync($"/jobs/{jobId}/retry", null);
        resp.EnsureSuccessStatusCode();
        var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
        var newJobId = json.GetProperty("new_job_id").GetGuid();

        // The new job's status as created, from the retry response. Reading it with a second request raced the worker,
        // which may claim the new job in between (2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP).
        var newStatus = Enum.Parse<JobStatus>(json.GetProperty("status").GetString()!, true);
        Assert.Equal(JobStatus.Enqueued, newStatus);
        Assert.NotEqual(jobId, newJobId);
        await GetJobStatusAsync(newJobId); // the new job exists and is readable
    }
}
/// <summary>
/// Deterministic tests of the worker and the webhook sender without a web host. Added 2026-11-10, session
/// session_012zDydZCZ4AChqhEZ4oVtaP, for the CodeRabbit review on PR 19: (1) a job interrupted by host shutdown must go
/// back to enqueued without using a retry, with its run closed; (2) the webhook sender must never follow a redirect.
/// Touches: a private in-memory SQLite database and in-process stub HTTP handlers; no network, no sleeps.
/// </summary>
public class JobWorkerShutdownAndRedirectTests
{
    /// <summary>A webhook sender that simulates the host stopping mid-delivery: it cancels the worker's token, then
    /// throws as a cancelled HTTP call would. Touches: the given token source.</summary>
    private sealed class StopHostDuringSend : IWebhookSender
    {
        private readonly CancellationTokenSource _stop;
        public StopHostDuringSend(CancellationTokenSource stop) => _stop = stop;

        public Task SendAsync(string url, string payloadJson, CancellationToken ct)
        {
            _stop.Cancel();
            ct.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }
    }

    /// <summary>A terminal handler that answers every request with one fixed response and counts the requests. Pure.</summary>
    private sealed class FixedAnswerHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly string _location;
        public int Requests;

        public FixedAnswerHandler(HttpStatusCode status, string location = null)
        {
            _status = status;
            _location = location;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Requests);
            var response = new HttpResponseMessage(_status) { RequestMessage = request };
            if (_location != null) response.Headers.Location = new Uri(_location);
            return Task.FromResult(response);
        }
    }

    /// <summary>A pass-through DelegatingHandler, to prove the sender reaches the innermost handler. Pure.</summary>
    private sealed class PassThroughHandler : DelegatingHandler { }

    /// <summary>A webhook sender that always fails and counts its calls (a failed attempt). No network. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private sealed class AlwaysFailingSender : IWebhookSender
    {
        public int Calls;
        public Task SendAsync(string url, string payloadJson, CancellationToken ct)
        {
            Interlocked.Increment(ref Calls);
            throw new HttpRequestException("receiver answered 500");
        }
    }

    /// <summary>
    /// A worker over a private in-memory database with the given sender and clock, and one enqueued webhook_retry job
    /// with <paramref name="maxRetries"/>. Out: the provider (dispose it), the worker and the job id. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
    /// </summary>
    private static async Task<(ServiceProvider Provider, SqliteConnection KeepAlive, JobProcessor Worker, Guid JobId)> WorkerWithJob(
        IWebhookSender sender, Func<DateTime> clock, int maxRetries)
    {
        var connectionString = $"DataSource=file:jobs_retry_{Guid.NewGuid():N}?mode=memory&cache=shared";
        var keepAlive = new SqliteConnection(connectionString);
        keepAlive.Open();
        var services = new ServiceCollection();
        services.AddDbContext<JobsDbContext>(o => o.UseSqlite(connectionString));
        services.AddScoped<IJobRepository, JobRepository>();
        services.AddSingleton<JobDispatcher>();
        services.AddSingleton(sender);
        services.AddTransient<WebhookRetryHandler>();
        var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<JobsDbContext>().Database.EnsureCreated();
        var job = await scope.ServiceProvider.GetRequiredService<IJobRepository>()
            .EnqueueAsync("webhook_retry", new { url = "https://hooks.example.com/deliver" }, null, maxRetries);
        return (provider, keepAlive, new JobProcessor(provider, NullLogger<JobProcessor>.Instance, clock), job.Id);
    }

    /// <summary>Reads a job outside the worker's scope. Touches: in-memory SQLite.</summary>
    private static async Task<Job> ReadJob(ServiceProvider provider, Guid jobId)
    {
        using var scope = provider.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<JobsDbContext>().Jobs.AsNoTracking().SingleAsync(j => j.Id == jobId);
    }

    /// <summary>
    /// JOBS-03: after a failed attempt the job waits 'enqueued' with retry_count 1 and next_retry_at = failure + 1 s;
    /// the worker skips it before then; retry 2 waits 2 s. Deterministic: the worker's clock is moved by hand.
    /// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec amendment). Touches: in-memory SQLite.
    /// </summary>
    // JOBS-03
    [Fact]
    public async Task Failed_Attempt_Waits_1s_Then_2s_And_Counts_Retries()
    {
        var now = new DateTime(2026, 11, 10, 12, 0, 0, DateTimeKind.Utc);
        var sender = new AlwaysFailingSender();
        var (provider, keepAlive, worker, jobId) = await WorkerWithJob(sender, () => now, 3);
        using var _p = provider;
        using var _k = keepAlive;

        await worker.ProcessPendingJobs(CancellationToken.None);
        var job = await ReadJob(provider, jobId);
        Assert.Equal(1, sender.Calls);
        Assert.Equal(JobStatus.Enqueued, job.Status);
        Assert.Equal(1, job.RetryCount);
        Assert.Equal(now.AddSeconds(1), job.NextRetryAt);

        now = now.AddMilliseconds(999);
        await worker.ProcessPendingJobs(CancellationToken.None);
        Assert.Equal(1, sender.Calls); // not due yet: skipped

        now = now.AddMilliseconds(1);
        await worker.ProcessPendingJobs(CancellationToken.None);
        job = await ReadJob(provider, jobId);
        Assert.Equal(2, sender.Calls);
        Assert.Equal(2, job.RetryCount);
        Assert.Equal(now.AddSeconds(2), job.NextRetryAt);
        Assert.Equal(JobStatus.Enqueued, job.Status);
    }

    /// <summary>
    /// JOBS-04: with max_retries = 3 the job runs 4 times (waits 1 s, 2 s, 4 s), then is 'failed' with retry_count 3,
    /// no next_retry_at, and never runs again. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec amendment).
    /// Touches: in-memory SQLite.
    /// </summary>
    // JOBS-04
    [Fact]
    public async Task Max_Retries_3_Runs_4_Times_Then_Failed_With_RetryCount_3()
    {
        var now = new DateTime(2026, 11, 10, 12, 0, 0, DateTimeKind.Utc);
        var sender = new AlwaysFailingSender();
        var (provider, keepAlive, worker, jobId) = await WorkerWithJob(sender, () => now, 3);
        using var _p = provider;
        using var _k = keepAlive;

        foreach (var wait in new[] { 0, 1, 2, 4 })
        {
            now = now.AddSeconds(wait);
            await worker.ProcessPendingJobs(CancellationToken.None);
        }

        var job = await ReadJob(provider, jobId);
        Assert.Equal(4, sender.Calls);
        Assert.Equal(JobStatus.Failed, job.Status);
        Assert.Equal(3, job.RetryCount);
        Assert.Null(job.NextRetryAt);

        now = now.AddHours(1);
        await worker.ProcessPendingJobs(CancellationToken.None);
        Assert.Equal(4, sender.Calls);
        using var scope = provider.CreateScope();
        Assert.Equal(4, await scope.ServiceProvider.GetRequiredService<JobsDbContext>().JobRuns.CountAsync(r => r.JobId == jobId));
    }

    [Fact]
    public async Task Job_Interrupted_By_Shutdown_Is_Requeued_Without_Using_A_Retry()
    {
        var connectionString = $"DataSource=file:jobs_shutdown_{Guid.NewGuid():N}?mode=memory&cache=shared";
        using var keepAlive = new SqliteConnection(connectionString);
        keepAlive.Open();
        using var stop = new CancellationTokenSource();

        var services = new ServiceCollection();
        services.AddDbContext<JobsDbContext>(o => o.UseSqlite(connectionString));
        services.AddScoped<IJobRepository, JobRepository>();
        services.AddSingleton<JobDispatcher>();
        services.AddSingleton<IWebhookSender>(new StopHostDuringSend(stop));
        services.AddTransient<WebhookRetryHandler>();
        using var provider = services.BuildServiceProvider();

        Guid jobId;
        using (var scope = provider.CreateScope())
        {
            scope.ServiceProvider.GetRequiredService<JobsDbContext>().Database.EnsureCreated();
            var job = await scope.ServiceProvider.GetRequiredService<IJobRepository>()
                .EnqueueAsync("webhook_retry", new { url = "https://hooks.example.com/deliver" }, null, 3);
            jobId = job.Id;
        }

        var processor = new JobProcessor(provider, NullLogger<JobProcessor>.Instance);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => processor.ProcessPendingJobs(stop.Token));

        using (var scope = provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<JobsDbContext>();
            var job = await db.Jobs.AsNoTracking().SingleAsync(j => j.Id == jobId);
            Assert.Equal(JobStatus.Enqueued, job.Status);   // not stuck in Running
            Assert.Equal(0, job.RetryCount);                 // a shutdown is not a failed attempt
            Assert.Null(job.NextRetryAt);                    // due again at once
            Assert.Null(job.StartedAt);

            var run = Assert.Single(await db.JobRuns.AsNoTracking().Where(r => r.JobId == jobId).ToListAsync());
            Assert.NotNull(run.CompletedAt);                 // the attempt's run is closed, not left open
            Assert.Equal(JobStatus.Cancelled, run.Status);
            Assert.Equal(JobRepository.InterruptedError, run.Error);
        }
    }

    [Fact]
    public async Task Webhook_Redirect_Is_A_Failed_Attempt_And_Is_Not_Followed()
    {
        var handler = new FixedAnswerHandler(HttpStatusCode.Found, "https://127.0.0.1/admin");
        var sender = new HttpWebhookSender(handler, TimeSpan.FromSeconds(5));

        var error = await Assert.ThrowsAsync<HttpRequestException>(
            () => sender.SendAsync("https://hooks.example.com/deliver", "{}", CancellationToken.None));
        Assert.Contains("redirect", error.Message);
        Assert.Equal(1, handler.Requests); // only the validated public URL was requested
    }

    [Fact]
    public void Webhook_Sender_Turns_Off_Automatic_Redirects_On_The_Innermost_Handler()
    {
        var sockets = new SocketsHttpHandler();
        Assert.True(sockets.AllowAutoRedirect); // the .NET default this guards against
        _ = new HttpWebhookSender(new PassThroughHandler { InnerHandler = sockets }, TimeSpan.FromSeconds(5));
        Assert.False(sockets.AllowAutoRedirect);

        var classic = new HttpClientHandler();
        _ = new HttpWebhookSender(classic, TimeSpan.FromSeconds(5));
        Assert.False(classic.AllowAutoRedirect);
    }
}

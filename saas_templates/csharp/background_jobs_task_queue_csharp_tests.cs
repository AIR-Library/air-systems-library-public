using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using BackgroundJobs;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
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

    [Fact]
    public async Task Enqueue_Job_Runs_To_Completion()
    {
        var jobId = await EnqueueJobAsync("send_bulk_email", new { template_key = "test", filter = new { } });
        await WaitForStatusAsync(jobId, JobStatus.Running, TimeSpan.FromSeconds(5));
        await WaitForStatusAsync(jobId, JobStatus.Completed, TimeSpan.FromSeconds(30));
        var result = await GetJobResultAsync(jobId);
        Assert.NotNull(result);
    }

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
        Assert.Equal(3, job!.RetryCount); // initial try + 2 retries
        Assert.Equal(JobStatus.Failed, job.Status);
    }

    [Fact]
    public async Task Job_Exceeds_Max_Retries_And_Fails()
    {
        var jobId = await EnqueueJobAsync("webhook_retry", new { url = "http://invalid" }, maxRetries: 1);
        await WaitForStatusAsync(jobId, JobStatus.Failed, TimeSpan.FromSeconds(30));

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<JobsDbContext>();
        var job = await db.Jobs.FindAsync(jobId);
        Assert.Equal(2, job!.RetryCount); // initial + 1 retry
        Assert.Equal(JobStatus.Failed, job.Status);
    }

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

    [Fact]
    public async Task Bulk_Job_Does_Not_Block_Request()
    {
        var start = DateTime.UtcNow;
        var jobId = await EnqueueJobAsync("send_bulk_email", new { template_key = "test", filter = new { } });
        var elapsed = DateTime.UtcNow - start;
        Assert.True(elapsed.TotalSeconds < 1, "Enqueue request should be fast");
        await WaitForStatusAsync(jobId, JobStatus.Completed, TimeSpan.FromSeconds(30));
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
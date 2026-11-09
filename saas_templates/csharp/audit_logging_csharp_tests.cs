using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AuditLogging;
using Microsoft.Data.Sqlite;
using Xunit;

public class AuditLoggingTests : IDisposable
{
    private readonly AuditLogRepository _repo;
    private readonly DbConnection _connection;

    public AuditLoggingTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
        _repo = new AuditLogRepository(_connection);
    }

    public void Dispose()
    {
        _repo.Dispose();
        _connection.Dispose();
    }

    private async Task<string> LogSampleAsync(long? actorId = 123, string action = "user_created", string resourceType = "user", string resourceId = "456")
    {
        var entry = new AuditLogEntry
        {
            ActorId = actorId,
            ActorType = ActorType.User,
            Action = action,
            ResourceType = resourceType,
            ResourceId = resourceId,
            OldValue = JsonSerializer.Deserialize<JsonElement>("{\"tier\":\"team\"}"),
            NewValue = JsonSerializer.Deserialize<JsonElement>("{\"tier\":\"enterprise\"}"),
            WhyChainId = "wc_789"
        };
        return await _repo.LogMutationAsync(entry);
    }

    [Fact]
    public async Task HappyPath_LogAndQuery()
    {
        var logId = await LogSampleAsync();
        var result = await _repo.QueryLogsAsync(actorId: 123, action: "user_*", resourceType: "user");
        Assert.Single(result.Logs);
        var log = result.Logs.First();
        Assert.Equal(logId, log.Id);
        Assert.Equal("user_created", log.Action);
        Assert.Equal("user", log.ResourceType);
        Assert.Equal("456", log.ResourceId);
    }

    [Fact]
    public async Task Replay_DivergenceDetection()
    {
        var firstLogId = await LogSampleAsync();
        // mutate same resource again
        await LogSampleAsync(action: "user_suspended");
        var replay = await _repo.ReplayAsync(firstLogId);
        Assert.Equal(firstLogId, replay.LogId);
        Assert.True(replay.HasDiverged);
        Assert.Equal("{\"tier\":\"team\"}", replay.ResourceStateAtTime.Value.GetRawText());
    }

    [Fact]
    public async Task Filtering_ActorActionResource()
    {
        await LogSampleAsync(action: "user_created");
        await LogSampleAsync(action: "user_suspended");
        await LogSampleAsync(action: "billing_changed", resourceType: "subscription");
        var result = await _repo.QueryLogsAsync(actorId: 123, action: "user_*", resourceType: "user");
        Assert.Equal(2, result.Total);
        Assert.All(result.Logs, l => Assert.StartsWith("user_", l.Action));
    }

    [Fact]
    public async Task Pagination_LimitOffset()
    {
        for (int i = 0; i < 150; i++)
        {
            await LogSampleAsync(action: $"action_{i}");
        }
        var firstPage = await _repo.QueryLogsAsync(limit: 100, offset: 0);
        var secondPage = await _repo.QueryLogsAsync(limit: 100, offset: 100);
        Assert.Equal(100, firstPage.Logs.Count());
        Assert.Equal(50, secondPage.Logs.Count());
        Assert.True(firstPage.HasMore);
        Assert.False(secondPage.HasMore);
    }

    [Fact]
    public async Task Immutability_UpdateFails()
    {
        var logId = await LogSampleAsync();
        var ex = await Assert.ThrowsAsync<SqliteException>(async () =>
        {
            var cmd = _connection.CreateCommand();
            cmd.CommandText = "UPDATE audit_log SET action = 'hacked' WHERE id = @id;";
            cmd.Parameters.Add(new SqliteParameter("@id", logId));
            await cmd.ExecuteNonQueryAsync();
        });
        Assert.Contains("cannot", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Wildcard_ActionMatches()
    {
        await LogSampleAsync(action: "user_created");
        await LogSampleAsync(action: "user_suspended");
        await LogSampleAsync(action: "billing_changed");
        var result = await _repo.QueryLogsAsync(action: "user_*");
        Assert.Equal(2, result.Total);
    }

    [Fact]
    public async Task Search_FullText()
    {
        await LogSampleAsync(action: "subscription_changed");
        await LogSampleAsync(action: "user_created");
        var results = await _repo.SearchAsync("subscription");
        Assert.Single(results);
        Assert.Equal("subscription_changed", results.First().Action);
    }
}

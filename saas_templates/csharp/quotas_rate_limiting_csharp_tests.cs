using System;
using System.Threading.Tasks;
using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Caching.Memory;
using QuotasRateLimiting;
using Xunit;

namespace QuotasRateLimitingTests
{
    public class QuotaServiceTests : IDisposable
    {
        private readonly SqliteConnection _conn;
        private readonly QuotaService _service;
        private readonly IMemoryCache _cache;

        public QuotaServiceTests()
        {
            _conn = new SqliteConnection("Data Source=:memory:");
            _conn.Open();
            _conn.Execute(QuotaService.SchemaSql);
            _cache = new MemoryCache(new MemoryCacheOptions());
            _service = new QuotaService(_conn, _cache);
        }

        public void Dispose()
        {
            _conn.Dispose();
            _cache.Dispose();
        }

        private async Task<User> CreateUserAsync(Tier tier)
        {
            var user = new User { Id = Guid.NewGuid(), Tier = tier };
            await _conn.ExecuteAsync("INSERT INTO users (id, tier) VALUES (@Id, @Tier)",
                new { Id = user.Id.ToString(), Tier = tier.ToString() });
            return user;
        }

        [Fact]
        public async Task ApiQuota_Pass()
        {
            var user = await CreateUserAsync(Tier.Solo);
            var (success, _) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/test");
            Assert.True(success);
            var usage = await _conn.QuerySingleAsync<int>(
                "SELECT call_count FROM usage_metrics WHERE user_id = @Id AND month = @Month",
                new { Id = user.Id.ToString(), Month = DateTime.UtcNow.ToString("yyyy-MM") });
            Assert.Equal(1, usage);
        }

        [Fact]
        public async Task ApiQuota_Fail()
        {
            var user = await CreateUserAsync(Tier.Solo);
            // Prepopulate usage to limit
            await _conn.ExecuteAsync(@"
INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
VALUES (@UserId, @Month, @Calls, 0, @Now);
", new { UserId = user.Id.ToString(), Month = DateTime.UtcNow.ToString("yyyy-MM"), Calls = 1000, Now = DateTime.UtcNow.ToString("o") });

            var (success, json) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/test");
            Assert.False(success);
            Assert.Contains("\"error\":\"quota_exceeded\"", json);
        }

        [Fact]
        public async Task StorageQuota_Pass()
        {
            var user = await CreateUserAsync(Tier.Solo);
            var (success, _) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/upload", incomingFileSize: 500_000_000);
            Assert.True(success);
            var storage = await _conn.QuerySingleAsync<long>(
                "SELECT storage_bytes FROM usage_metrics WHERE user_id = @Id AND month = @Month",
                new { Id = user.Id.ToString(), Month = DateTime.UtcNow.ToString("yyyy-MM") });
            Assert.Equal(500_000_000L, storage);
        }

        [Fact]
        public async Task StorageQuota_Fail()
        {
            var user = await CreateUserAsync(Tier.Solo);
            // Prepopulate near limit
            await _conn.ExecuteAsync(@"
INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
VALUES (@UserId, @Month, 0, @Used, @Now);
", new { UserId = user.Id.ToString(), Month = DateTime.UtcNow.ToString("yyyy-MM"), Used = 900_000_000L, Now = DateTime.UtcNow.ToString("o") });

            var (success, json) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/upload", incomingFileSize: 200_000_000);
            Assert.False(success);
            Assert.Contains("\"error\":\"storage_quota_exceeded\"", json);
        }

        [Fact]
        public async Task RateLimitPerUser_Pass()
        {
            var user = await CreateUserAsync(Tier.Team);
            for (int i = 0; i < 99; i++)
            {
                // Use a unique IP per call to avoid hitting the per-IP rate limit (10/sec)
                var ip = $"10.0.0.{i + 1}";
                var (success, _) = await _service.ProcessApiCallAsync(user, ip, "/test");
                Assert.True(success);
            }
        }

        [Fact]
        public async Task RateLimitPerUser_Fail()
        {
            var user = await CreateUserAsync(Tier.Team);
            for (int i = 0; i < 100; i++)
            {
                // Use a unique IP per call to avoid hitting the per-IP rate limit (10/sec)
                var ip = $"10.0.1.{i + 1}";
                var (success, _) = await _service.ProcessApiCallAsync(user, ip, "/test");
                Assert.True(success);
            }
            // 101st call should be rejected by per-user rate limit
            var (fail, json) = await _service.ProcessApiCallAsync(user, "10.0.1.101", "/test");
            Assert.False(fail);
            Assert.Contains("\"error\":\"rate_limit_exceeded\"", json);
        }

        [Fact]
        public async Task RateLimitPerIp_Pass()
        {
            var user = await CreateUserAsync(Tier.Team);
            for (int i = 0; i < 9; i++)
            {
                var (success, _) = await _service.ProcessApiCallAsync(user, "5.6.7.8", "/test");
                Assert.True(success);
            }
        }

        [Fact]
        public async Task RateLimitPerIp_Fail()
        {
            var user = await CreateUserAsync(Tier.Team);
            for (int i = 0; i < 10; i++)
            {
                var (success, _) = await _service.ProcessApiCallAsync(user, "5.6.7.8", "/test");
                Assert.True(success);
            }
            var (fail, json) = await _service.ProcessApiCallAsync(user, "5.6.7.8", "/test");
            Assert.False(fail);
            Assert.Contains("\"error\":\"ip_rate_limit_exceeded\"", json);
        }

        [Fact]
        public async Task FeatureGate_Pass()
        {
            var user = await CreateUserAsync(Tier.Team);
            var (success, _) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/feature", feature: "feature_a");
            Assert.True(success);
        }

        [Fact]
        public async Task FeatureGate_Fail()
        {
            var user = await CreateUserAsync(Tier.Solo);
            var (success, json) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/feature", feature: "feature_a");
            Assert.False(success);
            Assert.Contains("\"error\":\"feature_not_available_in_tier\"", json);
        }

        [Fact]
        public async Task MonthRollover_ResetsUsage()
        {
            var user = await CreateUserAsync(Tier.Solo);
            // Simulate usage in previous month
            var prevMonth = DateTime.UtcNow.AddMonths(-1).ToString("yyyy-MM");
            await _conn.ExecuteAsync(@"
INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
VALUES (@UserId, @Month, 500, 0, @Now);
", new { UserId = user.Id.ToString(), Month = prevMonth, Now = DateTime.UtcNow.ToString("o") });

            // Ensure current month has no record
            var (success, _) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/test");
            Assert.True(success);
            var currentUsage = await _conn.QuerySingleAsync<int>(
                "SELECT call_count FROM usage_metrics WHERE user_id = @Id AND month = @Month",
                new { Id = user.Id.ToString(), Month = DateTime.UtcNow.ToString("yyyy-MM") });
            Assert.Equal(1, currentUsage);
        }

        [Fact]
        public async Task TierUpgrade_UpdatesLimitsImmediately()
        {
            var user = await CreateUserAsync(Tier.Solo);
            // Fill solo quota
            await _conn.ExecuteAsync(@"
INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
VALUES (@UserId, @Month, 1000, 0, @Now);
", new { UserId = user.Id.ToString(), Month = DateTime.UtcNow.ToString("yyyy-MM"), Now = DateTime.UtcNow.ToString("o") });

            // Upgrade to Team
            await _service.UpgradeTierAsync(user, Tier.Team);

            // Now should succeed because team limit is higher
            var (success, _) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/test");
            Assert.True(success);
        }
    }
}

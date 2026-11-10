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

        /// <summary>
        /// The test clock. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the service reads this instead of the
        /// wall clock, so the 1-second IP window and the month never depend on how fast the test runs or the date.
        /// </summary>
        private DateTime _now = new DateTime(2026, 11, 10, 12, 0, 0, DateTimeKind.Utc);

        public QuotaServiceTests()
        {
            _conn = new SqliteConnection("Data Source=:memory:");
            _conn.Open();
            _conn.Execute(QuotaService.SchemaSql);
            _cache = new MemoryCache(new MemoryCacheOptions());
            _service = new QuotaService(_conn, _cache, () => _now);
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

        // QUOTA-01
        [Fact]
        public async Task ApiQuota_Pass()
        {
            var user = await CreateUserAsync(Tier.Solo);
            var (success, _, _) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/test");
            Assert.True(success);
            var usage = await _conn.QuerySingleAsync<int>(
                "SELECT call_count FROM usage_metrics WHERE user_id = @Id AND month = @Month",
                new { Id = user.Id.ToString(), Month = _now.ToString("yyyy-MM") });
            Assert.Equal(1, usage);
        }

        // QUOTA-02
        [Fact]
        public async Task ApiQuota_Fail()
        {
            var user = await CreateUserAsync(Tier.Solo);
            // Prepopulate usage to limit
            await _conn.ExecuteAsync(@"
INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
VALUES (@UserId, @Month, @Calls, 0, @Now);
", new { UserId = user.Id.ToString(), Month = _now.ToString("yyyy-MM"), Calls = 1000, Now = _now.ToString("o") });

            var (success, status, json) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/test");
            Assert.False(success);
            Assert.Contains("\"error\":\"quota_exceeded\"", json);
            Assert.Equal(429, status);
        }

        // QUOTA-03
        [Fact]
        public async Task StorageQuota_Pass()
        {
            var user = await CreateUserAsync(Tier.Solo);
            var (success, _, _) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/upload", incomingFileSize: 500_000_000);
            Assert.True(success);
            var storage = await _conn.QuerySingleAsync<long>(
                "SELECT storage_bytes FROM usage_metrics WHERE user_id = @Id AND month = @Month",
                new { Id = user.Id.ToString(), Month = _now.ToString("yyyy-MM") });
            Assert.Equal(500_000_000L, storage);
        }

        // QUOTA-04
        [Fact]
        public async Task StorageQuota_Fail()
        {
            var user = await CreateUserAsync(Tier.Solo);
            // Prepopulate near limit
            await _conn.ExecuteAsync(@"
INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
VALUES (@UserId, @Month, 0, @Used, @Now);
", new { UserId = user.Id.ToString(), Month = _now.ToString("yyyy-MM"), Used = 900_000_000L, Now = _now.ToString("o") });

            var (success, status, json) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/upload", incomingFileSize: 200_000_000);
            Assert.False(success);
            Assert.Contains("\"error\":\"storage_quota_exceeded\"", json);
            Assert.Equal(413, status);
        }

        // QUOTA-05
        [Fact]
        public async Task RateLimitPerUser_Pass()
        {
            var user = await CreateUserAsync(Tier.Team);
            for (int i = 0; i < 99; i++)
            {
                // Use a unique IP per call to avoid hitting the per-IP rate limit (10/sec)
                var ip = $"10.0.0.{i + 1}";
                var (success, _, _) = await _service.ProcessApiCallAsync(user, ip, "/test");
                Assert.True(success);
            }
        }

        // QUOTA-06
        [Fact]
        public async Task RateLimitPerUser_Fail()
        {
            var user = await CreateUserAsync(Tier.Team);
            for (int i = 0; i < 100; i++)
            {
                // Use a unique IP per call to avoid hitting the per-IP rate limit (10/sec)
                var ip = $"10.0.1.{i + 1}";
                var (success, _, _) = await _service.ProcessApiCallAsync(user, ip, "/test");
                Assert.True(success);
            }
            // 101st call should be rejected by per-user rate limit
            var (fail, status, json) = await _service.ProcessApiCallAsync(user, "10.0.1.101", "/test");
            Assert.False(fail);
            Assert.Contains("\"error\":\"rate_limit_exceeded\"", json);
            Assert.Equal(429, status);
        }

        // QUOTA-07
        [Fact]
        public async Task RateLimitPerIp_Pass()
        {
            var user = await CreateUserAsync(Tier.Team);
            for (int i = 0; i < 9; i++)
            {
                var (success, _, _) = await _service.ProcessApiCallAsync(user, "5.6.7.8", "/test");
                Assert.True(success);
            }
        }

        // QUOTA-08
        [Fact]
        public async Task RateLimitPerIp_Fail()
        {
            var user = await CreateUserAsync(Tier.Team);
            for (int i = 0; i < 10; i++)
            {
                var (success, _, _) = await _service.ProcessApiCallAsync(user, "5.6.7.8", "/test");
                Assert.True(success);
            }
            var (fail, status, json) = await _service.ProcessApiCallAsync(user, "5.6.7.8", "/test");
            Assert.False(fail);
            Assert.Contains("\"error\":\"ip_rate_limit_exceeded\"", json);
            Assert.Equal(429, status);

            // the next second is a new window (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the counter used to never reset)
            _now = _now.AddSeconds(1);
            var (again, _, _) = await _service.ProcessApiCallAsync(user, "5.6.7.8", "/test");
            Assert.True(again);
        }

        // QUOTA-09
        [Fact]
        public async Task FeatureGate_Pass()
        {
            var user = await CreateUserAsync(Tier.Team);
            var (success, _, _) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/feature", feature: "feature_a");
            Assert.True(success);
        }

        /// <summary>
        /// QUOTA-10: a solo user asking for feature_a (team and up) gets 403 {error: "feature_not_available_in_tier",
        /// tier: "solo", minimum_tier: "team", upgrade_url}. In: nothing. Out: asserts. Changed 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2: the spec now names this exact body in every language; the tier
        /// field is now asserted too). Touches: the test's in-memory database.
        /// </summary>
        // QUOTA-10
        [Fact]
        public async Task FeatureGate_Fail()
        {
            var user = await CreateUserAsync(Tier.Solo);
            var (success, status, json) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/feature", feature: "feature_a");
            Assert.False(success);
            Assert.Contains("\"error\":\"feature_not_available_in_tier\"", json);
            Assert.Equal(403, status);
            Assert.Contains("\"upgrade_url\":", json);
            Assert.Contains("\"minimum_tier\":\"team\"", json);
            Assert.Contains("\"tier\":\"solo\"", json);
        }

        // QUOTA-11
        [Fact]
        public async Task MonthRollover_ResetsUsage()
        {
            var user = await CreateUserAsync(Tier.Solo);
            // Simulate usage in previous month
            var prevMonth = _now.AddMonths(-1).ToString("yyyy-MM");
            await _conn.ExecuteAsync(@"
INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
VALUES (@UserId, @Month, 500, 0, @Now);
", new { UserId = user.Id.ToString(), Month = prevMonth, Now = _now.ToString("o") });

            // Ensure current month has no record
            var (success, _, _) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/test");
            Assert.True(success);
            var currentUsage = await _conn.QuerySingleAsync<int>(
                "SELECT call_count FROM usage_metrics WHERE user_id = @Id AND month = @Month",
                new { Id = user.Id.ToString(), Month = _now.ToString("yyyy-MM") });
            Assert.Equal(1, currentUsage);
        }

        // QUOTA-12
        [Fact]
        public async Task TierUpgrade_UpdatesLimitsImmediately()
        {
            var user = await CreateUserAsync(Tier.Solo);
            // Fill solo quota
            await _conn.ExecuteAsync(@"
INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
VALUES (@UserId, @Month, 1000, 0, @Now);
", new { UserId = user.Id.ToString(), Month = _now.ToString("yyyy-MM"), Now = _now.ToString("o") });

            // Upgrade to Team
            await _service.UpgradeTierAsync(user, Tier.Team);

            // Now should succeed because team limit is higher
            var (success, _, _) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/test");
            Assert.True(success);
        }

        /// <summary>
        /// QUOTA-11, with the clock: a full month is refused, and the first call of the next month passes with
        /// call_count 1. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (the other rollover test seeds a past
        /// month; this one crosses the boundary). Touches: in-memory SQLite.
        /// </summary>
        // QUOTA-11
        [Fact]
        public async Task MonthRollover_ClockCrossesMonth_QuotaStartsAgain()
        {
            _now = new DateTime(2026, 11, 30, 23, 59, 59, DateTimeKind.Utc);
            var user = await CreateUserAsync(Tier.Solo);
            await _conn.ExecuteAsync(@"
INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
VALUES (@UserId, '2026-11', 1000, 0, @Now);", new { UserId = user.Id.ToString(), Now = _now.ToString("o") });
            var (refused, status, json) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/test");
            Assert.False(refused);
            Assert.Equal(429, status);
            Assert.Contains("\"reset_date\":\"2026-12-01\"", json);

            _now = _now.AddSeconds(1);
            var (passed, _, _) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/test");
            Assert.True(passed);
            Assert.Equal(1, await _conn.QuerySingleAsync<int>(
                "SELECT call_count FROM usage_metrics WHERE user_id = @Id AND month = '2026-12'", new { Id = user.Id.ToString() }));
        }

        /// <summary>
        /// Storage is the user's total, not this month's: 900 MB stored last month plus 200 MB now is over solo's
        /// 1 GB, and a refused upload records nothing. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (before, a
        /// new month reset storage to 0). Touches: in-memory SQLite.
        /// </summary>
        [Fact]
        public async Task StorageQuota_CountsEveryMonth_AndRefusalRecordsNothing()
        {
            var user = await CreateUserAsync(Tier.Solo);
            await _conn.ExecuteAsync(@"
INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
VALUES (@UserId, @Month, 3, 900000000, @Now);", new { UserId = user.Id.ToString(), Month = _now.AddMonths(-1).ToString("yyyy-MM"), Now = _now.ToString("o") });

            var (success, status, _) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/upload", incomingFileSize: 200_000_000);
            Assert.False(success);
            Assert.Equal(413, status);
            Assert.Equal(0, await _conn.QuerySingleAsync<int>(
                "SELECT COUNT(*) FROM usage_metrics WHERE user_id = @Id AND month = @Month",
                new { Id = user.Id.ToString(), Month = _now.ToString("yyyy-MM") }));
            Assert.Equal(0, await _conn.QuerySingleAsync<int>("SELECT COUNT(*) FROM api_calls WHERE user_id = @Id", new { Id = user.Id.ToString() }));
        }

        /// <summary>
        /// QUOTA-13: -1 is unlimited. An enterprise upload far past every other tier's storage limit is stored, and an
        /// enterprise user already past team's 10,000 calls this month is never refused by the quota.
        /// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec amendment). Touches: in-memory SQLite.
        /// </summary>
        // QUOTA-13
        [Fact]
        public async Task Unlimited_Enterprise_StorageAndApiCalls()
        {
            Assert.Equal(-1, Limits.ApiCallLimits[Tier.Enterprise]);
            Assert.Equal(-1, Limits.StorageLimits[Tier.Enterprise]);
            var user = await CreateUserAsync(Tier.Enterprise);
            await _conn.ExecuteAsync(@"
INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
VALUES (@UserId, @Month, 250000, 0, @Now);", new { UserId = user.Id.ToString(), Month = _now.ToString("yyyy-MM"), Now = _now.ToString("o") });

            var (uploaded, status, _) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/upload", incomingFileSize: 500_000_000_000L);
            Assert.True(uploaded);
            Assert.Equal(200, status);
            for (var i = 0; i < 5; i++)
            {
                _now = _now.AddSeconds(1);
                var (ok, code, _) = await _service.ProcessApiCallAsync(user, "1.2.3.4", "/test");
                Assert.True(ok);
                Assert.Equal(200, code);
            }
            var row = await _conn.QuerySingleAsync<(long Calls, long Bytes)>(
                "SELECT call_count AS Calls, storage_bytes AS Bytes FROM usage_metrics WHERE user_id = @Id AND month = @Month",
                new { Id = user.Id.ToString(), Month = _now.ToString("yyyy-MM") });
            Assert.Equal(250006, row.Calls);
            Assert.Equal(500_000_000_000L, row.Bytes);
        }
    }
}

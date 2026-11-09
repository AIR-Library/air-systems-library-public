using System;
using System.Collections.Generic;
using System.Data;
using System.Text.Json;
using System.Threading.Tasks;
using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Caching.Memory;

namespace QuotasRateLimiting
{
    public enum Tier
    {
        Solo,
        Team,
        Enterprise
    }

    public class User
    {
        public Guid Id { get; set; }
        public Tier Tier { get; set; }
    }

    public static class Limits
    {
        public static readonly Dictionary<Tier, int> ApiCallLimits = new()
        {
            { Tier.Solo, 1000 },
            { Tier.Team, 10000 },
            { Tier.Enterprise, int.MaxValue } // unlimited
        };

        public static readonly Dictionary<Tier, long> StorageLimits = new()
        {
            { Tier.Solo, 1_000_000_000L },          // 1 GB
            { Tier.Team, 100_000_000_000L },        // 100 GB
            { Tier.Enterprise, long.MaxValue }     // unlimited
        };
    }

    public class QuotaService
    {
        private readonly IDbConnection _db;
        private readonly IMemoryCache _cache;
        private readonly JsonSerializerOptions _jsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

        // Feature gate definition
        private static readonly Dictionary<string, Tier[]> FeatureGate = new()
        {
            { "feature_a", new[] { Tier.Team, Tier.Enterprise } },
            { "feature_b", new[] { Tier.Enterprise } },
            { "feature_c", new[] { Tier.Solo, Tier.Team, Tier.Enterprise } }
        };

        public QuotaService(IDbConnection db, IMemoryCache cache)
        {
            _db = db;
            _cache = cache;
        }

        // DDL for required tables
        public static readonly string SchemaSql = @"
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    tier TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS usage_metrics (
    user_id TEXT NOT NULL,
    month TEXT NOT NULL,
    call_count INTEGER NOT NULL DEFAULT 0,
    storage_bytes INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, month)
);
CREATE TABLE IF NOT EXISTS api_calls (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    ip TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    response_time_ms INTEGER NOT NULL
);
";

        private void WhyChain(string gate, Guid userId, params object[] args)
        {
            // Simple console logging for audit trail
            Console.WriteLine($"[WhyChain] gate={gate}, user_id={userId}, args={string.Join(",", args)}");
        }

        private string CurrentMonth => DateTime.UtcNow.ToString("yyyy-MM");

        public async Task<(bool Success, string JsonResponse)> ProcessApiCallAsync(
            User user,
            string ip,
            string endpoint,
            long incomingFileSize = 0,
            string feature = null)
        {
            // 1. Rate limit per IP (10 req/sec)
            var ipKey = $"rl_ip:{ip}";
            var ipCount = _cache.GetOrCreate(ipKey, entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(1);
                return 0;
            });
            if (ipCount >= 10)
            {
                var err = new { error = "ip_rate_limit_exceeded", reset_seconds = 1 };
                return (false, JsonSerializer.Serialize(err, _jsonOptions));
            }
            _cache.Set(ipKey, ipCount + 1);

            // 2. Rate limit per user (100 req/min)
            var userKey = $"rl_user:{user.Id}";
            var userCount = _cache.GetOrCreate(userKey, entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1);
                return 0;
            });
            if (userCount >= 100)
            {
                var err = new { error = "rate_limit_exceeded", reset_seconds = 60 };
                return (false, JsonSerializer.Serialize(err, _jsonOptions));
            }
            _cache.Set(userKey, userCount + 1);

            // 3. API quota
            var apiQuotaLimit = Limits.ApiCallLimits[user.Tier];
            if (apiQuotaLimit != int.MaxValue)
            {
                var usage = await _db.QueryFirstOrDefaultAsync<int?>(
                    "SELECT call_count FROM usage_metrics WHERE user_id = @UserId AND month = @Month",
                    new { UserId = user.Id.ToString(), Month = CurrentMonth });

                int currentUsage = usage ?? 0;
                WhyChain("api_quota_check", user.Id, user.Tier, currentUsage, apiQuotaLimit);
                if (currentUsage + 1 > apiQuotaLimit)
                {
                    var resetDate = new DateTime(DateTime.UtcNow.Year, DateTime.UtcNow.Month, 1).AddMonths(1);
                    var err = new
                    {
                        error = "quota_exceeded",
                        usage = currentUsage,
                        limit = apiQuotaLimit,
                        reset_date = resetDate.ToString("yyyy-MM-dd")
                    };
                    return (false, JsonSerializer.Serialize(err, _jsonOptions));
                }

                // Increment usage
                await _db.ExecuteAsync(@"
INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
VALUES (@UserId, @Month, 1, 0, @Now)
ON CONFLICT(user_id, month) DO UPDATE SET
    call_count = call_count + 1,
    updated_at = @Now;
", new { UserId = user.Id.ToString(), Month = CurrentMonth, Now = DateTime.UtcNow.ToString("o") });
            }

            // 4. Storage quota (if file upload)
            if (incomingFileSize > 0)
            {
                var storageLimit = Limits.StorageLimits[user.Tier];
                if (storageLimit != long.MaxValue)
                {
                    var storage = await _db.QueryFirstOrDefaultAsync<long?>(
                        "SELECT storage_bytes FROM usage_metrics WHERE user_id = @UserId AND month = @Month",
                        new { UserId = user.Id.ToString(), Month = CurrentMonth });

                    long currentStorage = storage ?? 0;
                    WhyChain("storage_quota_check", user.Id, user.Tier, currentStorage, storageLimit);
                    if (currentStorage + incomingFileSize > storageLimit)
                    {
                        var err = new
                        {
                            error = "storage_quota_exceeded",
                            usage = currentStorage,
                            limit = storageLimit
                        };
                        return (false, JsonSerializer.Serialize(err, _jsonOptions));
                    }

                    // Increment storage usage
                    await _db.ExecuteAsync(@"
INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
VALUES (@UserId, @Month, 0, @IncSize, @Now)
ON CONFLICT(user_id, month) DO UPDATE SET
    storage_bytes = storage_bytes + @IncSize,
    updated_at = @Now;
", new { UserId = user.Id.ToString(), Month = CurrentMonth, IncSize = incomingFileSize, Now = DateTime.UtcNow.ToString("o") });
                }
            }

            // 5. Feature gate (if applicable)
            if (!string.IsNullOrEmpty(feature))
            {
                if (!FeatureGate.TryGetValue(feature, out var allowedTiers))
                {
                    var err = new { error = "unknown_feature", feature };
                    return (false, JsonSerializer.Serialize(err, _jsonOptions));
                }

                WhyChain("feature_gate", user.Id, feature, user.Tier, string.Join("|", allowedTiers));
                if (Array.IndexOf(allowedTiers, user.Tier) < 0)
                {
                    var err = new
                    {
                        error = "feature_not_available_in_tier",
                        upgrade_url = $"https://example.com/upgrade?target={allowedTiers[0]}"
                    };
                    return (false, JsonSerializer.Serialize(err, _jsonOptions));
                }
            }

            // Log successful API call
            await _db.ExecuteAsync(@"
INSERT INTO api_calls (id, user_id, ip, endpoint, timestamp, status_code, response_time_ms)
VALUES (@Id, @UserId, @Ip, @Endpoint, @Timestamp, @Status, @RespTime);
", new
            {
                Id = Guid.NewGuid().ToString(),
                UserId = user.Id.ToString(),
                Ip = ip,
                Endpoint = endpoint,
                Timestamp = DateTime.UtcNow.ToString("o"),
                Status = 200,
                RespTime = 0
            });

            var success = new { success = true };
            return (true, JsonSerializer.Serialize(success, _jsonOptions));
        }

        // Helper to reset usage for month rollover (used in tests)
        public async Task ResetMonthAsync(string month)
        {
            await _db.ExecuteAsync("DELETE FROM usage_metrics WHERE month <> @Month", new { Month = month });
        }

        // Helper to upgrade tier (used in tests)
        public async Task UpgradeTierAsync(User user, Tier newTier)
        {
            user.Tier = newTier;
            await _db.ExecuteAsync("UPDATE users SET tier = @Tier WHERE id = @Id", new { Tier = newTier.ToString(), Id = user.Id.ToString() });
        }
    }
}

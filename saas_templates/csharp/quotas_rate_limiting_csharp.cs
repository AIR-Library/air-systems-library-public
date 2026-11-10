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

    /// <summary>
    /// Per-tier quotas. -1 means unlimited, in every quota (QUOTA-13, spec amended 2026-11-10).
    /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: enterprise was int.MaxValue / long.MaxValue, a sentinel
    /// the spec does not use. Touches nothing.
    /// </summary>
    public static class Limits
    {
        /// <summary>The value that means "no limit".</summary>
        public const long Unlimited = -1;

        public static readonly Dictionary<Tier, long> ApiCallLimits = new()
        {
            { Tier.Solo, 1000 },
            { Tier.Team, 10000 },
            { Tier.Enterprise, Unlimited }
        };

        public static readonly Dictionary<Tier, long> StorageLimits = new()
        {
            { Tier.Solo, 1_000_000_000L },          // 1 GB
            { Tier.Team, 100_000_000_000L },        // 100 GB
            { Tier.Enterprise, Unlimited }
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

        private readonly Func<DateTime> _clock;

        /// <summary>
        /// Builds the service. In: the database (usage_metrics, api_calls), the cache that holds rate-limit counters,
        /// and an optional clock returning UTC now (default DateTime.UtcNow).
        /// Why the clock: the per-IP (1 s) and per-user (1 min) windows and the month boundary are tested by moving
        /// time, never by racing the wall clock (docs/specs/README.md "Deterministic"). 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing on construction.
        /// </summary>
        public QuotaService(IDbConnection db, IMemoryCache cache, Func<DateTime> clock = null)
        {
            _db = db;
            _cache = cache;
            _clock = clock ?? (() => DateTime.UtcNow);
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

        /// <summary>
        /// Counts one request in a fixed rate-limit window and says whether it is allowed.
        /// In: the counter name, the window start and length, and the limit. Out: true when fewer than
        /// <paramref name="limit"/> requests were already counted in this window (the request is then counted).
        /// Why: before 2026-11-10 the counter was re-Set without an expiry after the first request, so it never reset
        /// and an IP was blocked for good after its 10th request ever. The window is now part of the key and expires
        /// at the window's end. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory cache.
        /// </summary>
        private bool TryCountInWindow(string name, DateTime windowStart, TimeSpan window, int limit)
        {
            var key = $"{name}:{windowStart.Ticks}";
            var count = _cache.TryGetValue(key, out int existing) ? existing : 0;
            if (count >= limit)
                return false;
            _cache.Set(key, count + 1, new DateTimeOffset(windowStart + window + window, TimeSpan.Zero));
            return true;
        }

        /// <summary>
        /// Runs every quota check for one API request, in this order: per-IP rate limit (10/s, 429
        /// ip_rate_limit_exceeded), per-user rate limit (100/min, 429 rate_limit_exceeded), feature gate (403
        /// feature_not_available_in_tier with upgrade_url, tier and minimum_tier), API call quota for the month (429
        /// quota_exceeded with usage, limit, reset_date), storage quota for the user's total storage (413
        /// storage_quota_exceeded). A limit of -1 is unlimited (QUOTA-13). Only when every check passes are the month's
        /// call_count and storage_bytes increased and the call logged to api_calls.
        /// In: the verified user, the client IP, the endpoint, the incoming upload size (0 for none), an optional feature.
        /// Out: (Success, Status, JsonResponse) where Status is the HTTP status (200 on success).
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: -1 unlimited; the HTTP status is returned; storage is
        /// the user's total over every month (spec "SUM(bytes) ... WHERE user_id = ?"; before, a new month reset it);
        /// nothing is recorded for a rejected request (before, a feature-gate or storage rejection still counted the
        /// call, and an upload rejected by the feature gate still counted its bytes); time from the injected clock.
        /// Touches: usage_metrics and api_calls (database), the rate-limit cache.
        /// </summary>
        public async Task<(bool Success, int Status, string JsonResponse)> ProcessApiCallAsync(
            User user,
            string ip,
            string endpoint,
            long incomingFileSize = 0,
            string feature = null)
        {
            var now = _clock();
            var month = now.ToString("yyyy-MM");

            // 1. Rate limit per IP (10 req/sec)
            var second = new DateTime(now.Ticks - now.Ticks % TimeSpan.TicksPerSecond, DateTimeKind.Utc);
            if (!TryCountInWindow($"rl_ip:{ip}", second, TimeSpan.FromSeconds(1), 10))
                return (false, 429, JsonSerializer.Serialize(new { error = "ip_rate_limit_exceeded", reset_seconds = 1 }, _jsonOptions));

            // 2. Rate limit per user (100 req/min)
            var minute = new DateTime(now.Ticks - now.Ticks % TimeSpan.TicksPerMinute, DateTimeKind.Utc);
            if (!TryCountInWindow($"rl_user:{user.Id}", minute, TimeSpan.FromMinutes(1), 100))
                return (false, 429, JsonSerializer.Serialize(new { error = "rate_limit_exceeded", reset_seconds = 60 }, _jsonOptions));

            // 3. Feature gate (if applicable)
            if (!string.IsNullOrEmpty(feature))
            {
                if (!FeatureGate.TryGetValue(feature, out var allowedTiers))
                    return (false, 403, JsonSerializer.Serialize(new { error = "unknown_feature", feature }, _jsonOptions));

                WhyChain("feature_gate", user.Id, feature, user.Tier, string.Join("|", allowedTiers));
                if (Array.IndexOf(allowedTiers, user.Tier) < 0)
                {
                    var err = new
                    {
                        error = "feature_not_available_in_tier",
                        tier = user.Tier.ToString().ToLowerInvariant(),
                        minimum_tier = allowedTiers[0].ToString().ToLowerInvariant(),
                        upgrade_url = $"https://example.com/upgrade?target={allowedTiers[0]}"
                    };
                    return (false, 403, JsonSerializer.Serialize(err, _jsonOptions));
                }
            }

            // 4. API quota for this month
            var apiQuotaLimit = Limits.ApiCallLimits[user.Tier];
            var currentUsage = await _db.QueryFirstOrDefaultAsync<long?>(
                "SELECT call_count FROM usage_metrics WHERE user_id = @UserId AND month = @Month",
                new { UserId = user.Id.ToString(), Month = month }) ?? 0;
            WhyChain("api_quota_check", user.Id, user.Tier, currentUsage, apiQuotaLimit);
            if (apiQuotaLimit != Limits.Unlimited && currentUsage + 1 > apiQuotaLimit)
            {
                var resetDate = new DateTime(now.Year, now.Month, 1).AddMonths(1);
                var err = new
                {
                    error = "quota_exceeded",
                    usage = currentUsage,
                    limit = apiQuotaLimit,
                    reset_date = resetDate.ToString("yyyy-MM-dd")
                };
                return (false, 429, JsonSerializer.Serialize(err, _jsonOptions));
            }

            // 5. Storage quota over everything the user has stored (if file upload)
            if (incomingFileSize > 0)
            {
                var storageLimit = Limits.StorageLimits[user.Tier];
                var currentStorage = await _db.QueryFirstOrDefaultAsync<long?>(
                    "SELECT SUM(storage_bytes) FROM usage_metrics WHERE user_id = @UserId",
                    new { UserId = user.Id.ToString() }) ?? 0;
                WhyChain("storage_quota_check", user.Id, user.Tier, currentStorage, storageLimit);
                if (storageLimit != Limits.Unlimited && currentStorage + incomingFileSize > storageLimit)
                {
                    var err = new
                    {
                        error = "storage_quota_exceeded",
                        usage = currentStorage,
                        limit = storageLimit
                    };
                    return (false, 413, JsonSerializer.Serialize(err, _jsonOptions));
                }
            }

            // Every check passed: count the call (and the stored bytes) for this month
            await _db.ExecuteAsync(@"
INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
VALUES (@UserId, @Month, 1, @IncSize, @Now)
ON CONFLICT(user_id, month) DO UPDATE SET
    call_count = call_count + 1,
    storage_bytes = storage_bytes + @IncSize,
    updated_at = @Now;
", new { UserId = user.Id.ToString(), Month = month, IncSize = Math.Max(0, incomingFileSize), Now = now.ToString("o") });

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
                Timestamp = now.ToString("o"),
                Status = 200,
                RespTime = 0
            });

            var success = new { success = true };
            return (true, 200, JsonSerializer.Serialize(success, _jsonOptions));
        }

        /// <summary>
        /// Clears the API call counts of every month other than <paramref name="month"/>. A new month needs no reset
        /// (its row starts at 0); this only tidies old counters. Storage bytes are kept: storage is the user's total.
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: it deleted the rows, which also dropped the storage
        /// they recorded. Touches: usage_metrics.
        /// </summary>
        public async Task ResetMonthAsync(string month)
        {
            await _db.ExecuteAsync("UPDATE usage_metrics SET call_count = 0 WHERE month <> @Month", new { Month = month });
        }

        // Helper to upgrade tier (used in tests)
        public async Task UpgradeTierAsync(User user, Tier newTier)
        {
            user.Tier = newTier;
            await _db.ExecuteAsync("UPDATE users SET tier = @Tier WHERE id = @Id", new { Tier = newTier.ToString(), Id = user.Id.ToString() });
        }
    }
}

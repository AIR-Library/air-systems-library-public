using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Net.Http;
using BCrypt.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

#nullable enable

namespace SaaSLibrary.ApiKeys
{
    public class ApiKeysService
    {
        private readonly ApiKeysDbContext _dbContext;
        private readonly IConnectionMultiplexer _redis;
        private readonly ILogger<ApiKeysService> _logger;

        public ApiKeysService(ApiKeysDbContext dbContext, IConnectionMultiplexer redis, ILogger<ApiKeysService> logger)
        {
            _dbContext = dbContext;
            _redis = redis;
            _logger = logger;
        }

        public async Task<ApiKeyResponse> CreateApiKeyAsync(Guid userId, CreateApiKeyRequest request)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));
            if (string.IsNullOrWhiteSpace(request.Name)) throw new ArgumentException("Name is required", nameof(request.Name));
            if (request.Scopes == null || request.Scopes.Count == 0) throw new ArgumentException("At least one scope is required", nameof(request.Scopes));
            if (request.RateLimit <= 0) throw new ArgumentException("Rate limit must be positive", nameof(request.RateLimit));

            var keyParts = GenerateApiKey();
            var apiKey = new ApiKey
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                Name = request.Name,
                KeyPrefix = keyParts.Prefix,
                KeySecretHash = BCrypt.Net.BCrypt.HashPassword(keyParts.FullKey),
                ScopesJson = JsonSerializer.Serialize(request.Scopes),
                RateLimit = request.RateLimit,
                ExpiresAt = request.ExpiresAt,
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };

            _dbContext.ApiKeys.Add(apiKey);
            await _dbContext.SaveChangesAsync();

            return new ApiKeyResponse
            {
                ApiKeyId = apiKey.Id.ToString(),
                Key = keyParts.FullKey,
                CreatedAt = apiKey.CreatedAt,
                ExpiresAt = apiKey.ExpiresAt,
                RateLimit = apiKey.RateLimit
            };
        }

        public async Task<ListApiKeysResponse> ListApiKeysAsync(Guid userId)
        {
            var keys = await _dbContext.ApiKeys
                .Where(k => k.UserId == userId)
                .Select(k => new ApiKeySummary
                {
                    ApiKeyId = k.Id.ToString(),
                    Name = k.Name,
                    Scopes = JsonSerializer.Deserialize<List<string>>(k.ScopesJson)!,
                    CreatedAt = k.CreatedAt,
                    LastUsedAt = k.LastUsedAt,
                    RateLimit = k.RateLimit,
                    IsActive = k.IsActive
                })
                .ToListAsync();

            return new ListApiKeysResponse { Keys = keys };
        }

        public async Task<RevokeApiKeyResponse> RevokeApiKeyAsync(Guid userId, Guid apiKeyId)
        {
            var apiKey = await _dbContext.ApiKeys
                .FirstOrDefaultAsync(k => k.Id == apiKeyId && k.UserId == userId);

            if (apiKey == null)
                throw new KeyNotFoundException($"API key {apiKeyId} not found for user {userId}");

            apiKey.IsActive = false;
            await _dbContext.SaveChangesAsync();

            return new RevokeApiKeyResponse
            {
                Success = true,
                RevokedAt = DateTime.UtcNow
            };
        }

        public async Task<RotateApiKeyResponse> RotateApiKeyAsync(Guid userId, Guid apiKeyId)
        {
            var apiKey = await _dbContext.ApiKeys
                .FirstOrDefaultAsync(k => k.Id == apiKeyId && k.UserId == userId);

            if (apiKey == null)
                throw new KeyNotFoundException($"API key {apiKeyId} not found for user {userId}");

            // Rotation keeps the row active and swaps its secret, so a revoked key would hand back a secret
            // that never validates. Revoked stays revoked: the caller creates a new key instead.
            if (!apiKey.IsActive)
                throw new InvalidOperationException($"API key {apiKeyId} is revoked and cannot be rotated");

            var oldKeyRevokedAt = DateTime.UtcNow;
            var gracePeriodEndsAt = oldKeyRevokedAt.AddHours(24);

            apiKey.PreviousKeyPrefix = apiKey.KeyPrefix;
            apiKey.PreviousKeySecretHash = apiKey.KeySecretHash;
            apiKey.PreviousKeyRevokedAt = oldKeyRevokedAt;
            apiKey.GracePeriodEndsAt = gracePeriodEndsAt;

            var newKeyParts = GenerateApiKey();
            apiKey.KeyPrefix = newKeyParts.Prefix;
            apiKey.KeySecretHash = BCrypt.Net.BCrypt.HashPassword(newKeyParts.FullKey);
            apiKey.LastUsedAt = null;

            await _dbContext.SaveChangesAsync();

            return new RotateApiKeyResponse
            {
                NewKey = newKeyParts.FullKey,
                OldKeyRevokedAt = oldKeyRevokedAt,
                GracePeriodEndsAt = gracePeriodEndsAt
            };
        }

        public async Task<ApiKeyValidationResult> ValidateApiKeyAsync(string key, string endpoint, HttpMethod method)
        {
            if (string.IsNullOrWhiteSpace(key))
                return new ApiKeyValidationResult { IsValid = false, ErrorMessage = "Missing API key", StatusCode = System.Net.HttpStatusCode.Unauthorized };

            if (!key.StartsWith("sk_live_"))
                return new ApiKeyValidationResult { IsValid = false, ErrorMessage = "Invalid API key format", StatusCode = System.Net.HttpStatusCode.Unauthorized };

            if (key.Length < 16) // "sk_live_" (8) + at least 8 char prefix
                return new ApiKeyValidationResult { IsValid = false, ErrorMessage = "API key too short", StatusCode = System.Net.HttpStatusCode.Unauthorized };

            var prefix = key.Substring(8, 8);
            var apiKey = await _dbContext.ApiKeys
                .AsNoTracking()
                .FirstOrDefaultAsync(k => k.KeyPrefix == prefix && k.IsActive);

            if (apiKey == null)
            {
                apiKey = await _dbContext.ApiKeys
                    .AsNoTracking()
                    .FirstOrDefaultAsync(k => k.PreviousKeyPrefix == prefix && k.IsActive && k.GracePeriodEndsAt.HasValue && k.GracePeriodEndsAt.Value > DateTime.UtcNow);
            }

            if (apiKey == null)
                return new ApiKeyValidationResult { IsValid = false, ErrorMessage = "Invalid API key", StatusCode = System.Net.HttpStatusCode.Unauthorized };

            string secretHash = apiKey.KeySecretHash;
            if (apiKey.PreviousKeyPrefix == prefix && apiKey.GracePeriodEndsAt.HasValue && apiKey.GracePeriodEndsAt.Value > DateTime.UtcNow)
            {
                secretHash = apiKey.PreviousKeySecretHash!;
            }
            else if (apiKey.KeyPrefix != prefix)
            {
                return new ApiKeyValidationResult { IsValid = false, ErrorMessage = "Invalid API key", StatusCode = System.Net.HttpStatusCode.Unauthorized };
            }

            if (!BCrypt.Net.BCrypt.Verify(key, secretHash))
                return new ApiKeyValidationResult { IsValid = false, ErrorMessage = "Invalid API key", StatusCode = System.Net.HttpStatusCode.Unauthorized };

            if (apiKey.ExpiresAt.HasValue && apiKey.ExpiresAt.Value < DateTime.UtcNow)
                return new ApiKeyValidationResult { IsValid = false, ErrorMessage = "API key expired", StatusCode = System.Net.HttpStatusCode.Unauthorized };

            var scopes = JsonSerializer.Deserialize<List<string>>(apiKey.ScopesJson)!;
            // A key needs the exact scope for the route. There is no wildcard: keys are not checked for their scopes
            // when created, so a "*" would let any key holder grant itself everything.
            var requiredScope = GetRequiredScope(endpoint, method);
            if (!scopes.Contains(requiredScope))
                return new ApiKeyValidationResult { IsValid = false, ErrorMessage = "Insufficient scope", StatusCode = System.Net.HttpStatusCode.Forbidden };

            var redisDb = _redis.GetDatabase();
            var redisKey = $"rate_limit:{apiKey.Id}:{DateTime.UtcNow:yyyy-MM-dd HH}";
            long current = await redisDb.StringIncrementAsync(redisKey);
            if (current == 1)
                await redisDb.KeyExpireAsync(redisKey, TimeSpan.FromHours(2));

            if (current > apiKey.RateLimit)
                return new ApiKeyValidationResult { IsValid = false, ErrorMessage = "Rate limit exceeded", StatusCode = (System.Net.HttpStatusCode)429 };

            var trackedKey = await _dbContext.ApiKeys.FindAsync(apiKey.Id);
            if (trackedKey != null)
            {
                trackedKey.LastUsedAt = DateTime.UtcNow;
                await _dbContext.SaveChangesAsync();
            }

            return new ApiKeyValidationResult { IsValid = true };
        }

        public async Task LogApiKeyUsageAsync(Guid apiKeyId, string endpoint, HttpMethod method, int statusCode)
        {
            var usage = new ApiKeyUsage
            {
                Id = Guid.NewGuid(),
                ApiKeyId = apiKeyId,
                Endpoint = endpoint,
                Method = method.ToString(),
                Status = statusCode,
                Timestamp = DateTime.UtcNow
            };

            _dbContext.ApiKeyUsages.Add(usage);
            await _dbContext.SaveChangesAsync();
        }

        public async Task<ApiKeyUsageResponse> GetApiKeyUsageAsync(Guid userId, Guid apiKeyId, DateTime? from, DateTime? to)
        {
            var apiKey = await _dbContext.ApiKeys
                .FirstOrDefaultAsync(k => k.Id == apiKeyId && k.UserId == userId);

            if (apiKey == null)
                throw new KeyNotFoundException($"API key {apiKeyId} not found for user {userId}");

            var query = _dbContext.ApiKeyUsages
                .Where(u => u.ApiKeyId == apiKeyId);

            if (from.HasValue)
                query = query.Where(u => u.Timestamp >= from.Value);
            if (to.HasValue)
                query = query.Where(u => u.Timestamp <= to.Value);

            var usages = await query.ToListAsync();

            var totalRequests = usages.LongCount();
            var requestsByEndpoint = usages
                .GroupBy(u => $"{u.Method} {u.Endpoint}")
                .ToDictionary(g => g.Key, g => (long)g.Count());
            var rateLimitHits = usages.Count(u => u.Status == 429);
            var errors = usages
                .Where(u => u.Status >= 400)
                .GroupBy(u => u.Status.ToString())
                .ToDictionary(g => g.Key, g => (long)g.Count());

            return new ApiKeyUsageResponse
            {
                ApiKeyId = apiKeyId.ToString(),
                TotalRequests = totalRequests,
                RequestsByEndpoint = requestsByEndpoint,
                RateLimitHits = rateLimitHits,
                Errors = errors
            };
        }

        public async Task<AdminListApiKeysResponse> AdminListApiKeysAsync(Guid? userId, string status)
        {
            var query = _dbContext.ApiKeys.AsQueryable();

            if (userId.HasValue)
                query = query.Where(k => k.UserId == userId.Value);

            if (!string.IsNullOrWhiteSpace(status))
            {
                var isActive = status.Equals("active", StringComparison.OrdinalIgnoreCase);
                query = query.Where(k => k.IsActive == isActive);
            }

            var keys = await query
                .Select(k => new ApiKeySummary
                {
                    ApiKeyId = k.Id.ToString(),
                    Name = k.Name,
                    Scopes = JsonSerializer.Deserialize<List<string>>(k.ScopesJson)!,
                    CreatedAt = k.CreatedAt,
                    LastUsedAt = k.LastUsedAt,
                    RateLimit = k.RateLimit,
                    IsActive = k.IsActive
                })
                .ToListAsync();

            return new AdminListApiKeysResponse
            {
                Keys = keys,
                Total = keys.Count
            };
        }

        private static (string FullKey, string Prefix) GenerateApiKey()
        {
            var randomBytes = RandomNumberGenerator.GetBytes(24);
            var base64Url = Base64UrlEncode(randomBytes);
            var fullKey = $"sk_live_{base64Url}";
            var prefix = base64Url.Substring(0, 8);
            return (fullKey, prefix);
        }

        private static string Base64UrlEncode(byte[] input)
        {
            var base64 = Convert.ToBase64String(input);
            base64 = base64.TrimEnd('=');
            base64 = base64.Replace('+', '-').Replace('/', '_');
            return base64;
        }

        private static string GetRequiredScope(string endpoint, HttpMethod method)
        {
            // Normalize endpoint: remove leading/trailing slashes, convert to lowercase
            var normalizedEndpoint = endpoint.TrimStart('/').TrimEnd('/').ToLowerInvariant();
            var methodLower = method.Method.ToLowerInvariant();

            var segments = normalizedEndpoint.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (segments.Length == 0) return "*";

            var knownResources = new HashSet<string> { "users", "deployments", "invoices", "webhooks", "subscriptions", "billing" };
            var resource = segments.FirstOrDefault(s => knownResources.Contains(s)) ?? segments[0];

            return (resource, methodLower) switch
            {
                ("users", "get") => "read:users",
                ("users", "post") => "write:users",
                ("users", "put") => "write:users",
                ("users", "patch") => "write:users",
                ("deployments", "get") => "read:deployments",
                ("deployments", "post") => "write:deployments",
                ("deployments", "put") => "write:deployments",
                ("deployments", "patch") => "write:deployments",
                ("invoices", "get") => "read:invoices",
                ("subscriptions", "post") => "write:billing",
                ("billing", "put") => "write:billing",
                ("billing", "patch") => "write:billing",
                ("webhooks", "post") => "webhook:manage",
                ("webhooks", "delete") => "webhook:manage",
                _ => $"{methodLower}:{resource}"
            };
        }
    }

    public class ApiKeysDbContext : DbContext
    {
        public ApiKeysDbContext(DbContextOptions<ApiKeysDbContext> options) : base(options) { }

        public DbSet<ApiKey> ApiKeys => Set<ApiKey>();
        public DbSet<ApiKeyUsage> ApiKeyUsages => Set<ApiKeyUsage>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<ApiKey>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Id).ValueGeneratedNever();
                entity.Property(e => e.UserId).IsRequired();
                entity.Property(e => e.Name).IsRequired().HasMaxLength(255);
                entity.Property(e => e.KeyPrefix).IsRequired().HasMaxLength(8);
                entity.Property(e => e.KeySecretHash).IsRequired().HasMaxLength(255);
                entity.Property(e => e.ScopesJson).IsRequired();
                entity.Property(e => e.RateLimit).IsRequired();
                entity.Property(e => e.ExpiresAt);
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("CURRENT_TIMESTAMP");
                entity.Property(e => e.LastUsedAt);
                entity.Property(e => e.IsActive).HasDefaultValue(true);
                entity.Property(e => e.PreviousKeyPrefix).HasMaxLength(8);
                entity.Property(e => e.PreviousKeySecretHash).HasMaxLength(255);
                entity.Property(e => e.PreviousKeyRevokedAt);
                entity.Property(e => e.GracePeriodEndsAt);
                entity.HasIndex(e => e.UserId);
                entity.HasIndex(e => e.KeyPrefix);
                entity.HasIndex(e => e.PreviousKeyPrefix);
                entity.HasIndex(e => e.IsActive);
            });

            modelBuilder.Entity<ApiKeyUsage>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Id).ValueGeneratedNever();
                entity.Property(e => e.ApiKeyId).IsRequired();
                entity.Property(e => e.Endpoint).IsRequired().HasMaxLength(255);
                entity.Property(e => e.Method).IsRequired().HasMaxLength(10);
                entity.Property(e => e.Status).IsRequired();
                entity.Property(e => e.Timestamp).HasDefaultValueSql("CURRENT_TIMESTAMP");
                entity.HasIndex(e => e.ApiKeyId);
                entity.HasIndex(e => e.Timestamp);
            });
        }
    }

    public class ApiKey
    {
        public Guid Id { get; set; }
        public Guid UserId { get; set; }
        public string Name { get; set; } = default!;
        public string KeyPrefix { get; set; } = default!;
        public string KeySecretHash { get; set; } = default!;
        public string ScopesJson { get; set; } = default!;
        public int RateLimit { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? LastUsedAt { get; set; }
        public bool IsActive { get; set; }
        public string? PreviousKeyPrefix { get; set; }
        public string? PreviousKeySecretHash { get; set; }
        public DateTime? PreviousKeyRevokedAt { get; set; }
        public DateTime? GracePeriodEndsAt { get; set; }
    }

    public class ApiKeyUsage
    {
        public Guid Id { get; set; }
        public Guid ApiKeyId { get; set; }
        public string Endpoint { get; set; } = default!;
        public string Method { get; set; } = default!;
        public int Status { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class CreateApiKeyRequest
    {
        [Required]
        public string Name { get; set; } = default!;
        [Required]
        public List<string> Scopes { get; set; } = default!;
        public DateTime? ExpiresAt { get; set; }
        [Required]
        public int RateLimit { get; set; }
    }

    public class ApiKeyResponse
    {
        public string ApiKeyId { get; set; } = default!;
        public string Key { get; set; } = default!;
        public DateTime CreatedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public int RateLimit { get; set; }
    }

    public class ListApiKeysResponse
    {
        public List<ApiKeySummary> Keys { get; set; } = default!;
    }

    public class ApiKeySummary
    {
        public string ApiKeyId { get; set; } = default!;
        public string Name { get; set; } = default!;
        public List<string> Scopes { get; set; } = default!;
        public DateTime CreatedAt { get; set; }
        public DateTime? LastUsedAt { get; set; }
        public int RateLimit { get; set; }
        public bool IsActive { get; set; }
    }

    public class RevokeApiKeyResponse
    {
        public bool Success { get; set; }
        public DateTime RevokedAt { get; set; }
    }

    public class RotateApiKeyResponse
    {
        public string NewKey { get; set; } = default!;
        public DateTime OldKeyRevokedAt { get; set; }
        public DateTime GracePeriodEndsAt { get; set; }
    }

    public class ApiKeyUsageResponse
    {
        public string ApiKeyId { get; set; } = default!;
        public long TotalRequests { get; set; }
        public Dictionary<string, long> RequestsByEndpoint { get; set; } = default!;
        public long RateLimitHits { get; set; }
        public Dictionary<string, long> Errors { get; set; } = default!;
    }

    public class AdminListApiKeysResponse
    {
        public List<ApiKeySummary> Keys { get; set; } = default!;
        public long Total { get; set; }
    }

    public class ApiKeyValidationResult
    {
        public bool IsValid { get; set; }
        public string? ErrorMessage { get; set; }
        public System.Net.HttpStatusCode? StatusCode { get; set; }
    }

    public static class Schema
    {
        public static string CreateTables => @"
            CREATE TABLE api_keys (
                id UUID PRIMARY KEY,
                user_id UUID NOT NULL,
                name VARCHAR(255) NOT NULL,
                key_prefix VARCHAR(8) NOT NULL,
                key_secret_hash VARCHAR(255) NOT NULL,
                scopes_json TEXT NOT NULL,
                rate_limit INTEGER NOT NULL,
                expires_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP WITH TIME ZONE,
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                previous_key_prefix VARCHAR(8),
                previous_key_secret_hash VARCHAR(255),
                previous_key_revoked_at TIMESTAMP WITH TIME ZONE,
                grace_period_ends_at TIMESTAMP WITH TIME ZONE
            );

            CREATE TABLE api_key_usage (
                id UUID PRIMARY KEY,
                api_key_id UUID NOT NULL REFERENCES api_keys(id),
                endpoint VARCHAR(255) NOT NULL,
                method VARCHAR(10) NOT NULL,
                status INTEGER NOT NULL,
                timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IX_api_keys_user_id ON api_keys(user_id);
            CREATE INDEX IX_api_keys_key_prefix ON api_keys(key_prefix);
            CREATE INDEX IX_api_keys_previous_key_prefix ON api_keys(previous_key_prefix);
            CREATE INDEX IX_api_keys_is_active ON api_keys(is_active);
            CREATE INDEX IX_api_key_usage_api_key_id ON api_key_usage(api_key_id);
            CREATE INDEX IX_api_key_usage_timestamp ON api_key_usage(timestamp);
        ";
    }
}

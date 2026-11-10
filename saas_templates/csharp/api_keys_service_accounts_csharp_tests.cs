using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using BCrypt.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using StackExchange.Redis;
using Xunit;
using SaaSLibrary.ApiKeys;

namespace SaaSLibrary.ApiKeys.Tests
{
    public class ApiKeysServiceTests : IDisposable
    {
        private readonly ApiKeysDbContext _dbName;
        private readonly Mock<IConnectionMultiplexer> _redisMock;
        private readonly Mock<IDatabase> _redisDatabaseMock;
        private readonly Mock<ILogger<ApiKeysService>> _loggerMock;
        private readonly ApiKeysService _service;
        private readonly Guid _testUserId = Guid.NewGuid();

        public ApiKeysServiceTests()
        {
            var options = new DbContextOptionsBuilder<ApiKeysDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;
            _dbName = new ApiKeysDbContext(options);

            _redisMock = new Mock<IConnectionMultiplexer>();
            _redisDatabaseMock = new Mock<IDatabase>();
            _redisMock.Setup(r => r.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(_redisDatabaseMock.Object);

            _loggerMock = new Mock<ILogger<ApiKeysService>>();

            _service = new ApiKeysService(_dbName, _redisMock.Object, _loggerMock.Object);
        }

        public void Dispose()
        {
            _dbName.Dispose();
        }

        // KEYS-01
        [Fact]
        public async Task CreateApiKey_WithValidRequest_ReturnsApiKeyResponse()
        {
            // Arrange
            var request = new CreateApiKeyRequest
            {
                Name = "Test Key",
                Scopes = new List<string> { "read:deployments", "write:webhooks" },
                ExpiresAt = DateTime.UtcNow.AddYears(1),
                RateLimit = 1000
            };

            // Act
            var result = await _service.CreateApiKeyAsync(_testUserId, request);

            // Assert
            Assert.NotNull(result);
            Assert.NotNull(result.ApiKeyId);
            Assert.NotNull(result.Key);
            Assert.StartsWith("sk_live_", result.Key);
            Assert.Equal(request.RateLimit, result.RateLimit);
            Assert.Equal(request.ExpiresAt, result.ExpiresAt);
            Assert.Equal(DateTime.UtcNow.Date, result.CreatedAt.Date); // Created today

            // Verify in database
            var apiKey = await _dbName.ApiKeys.FindAsync(Guid.Parse(result.ApiKeyId));
            Assert.NotNull(apiKey);
            Assert.Equal(_testUserId, apiKey.UserId);
            Assert.Equal(request.Name, apiKey.Name);
            Assert.True(BCrypt.Net.BCrypt.Verify(result.Key, apiKey.KeySecretHash));
            Assert.Equal(request.Scopes.Count, JsonSerializer.Deserialize<List<string>>(apiKey.ScopesJson)!.Count);
            Assert.Equal(request.RateLimit, apiKey.RateLimit);
            Assert.Equal(request.ExpiresAt, apiKey.ExpiresAt);
            Assert.True(apiKey.IsActive);
        }

        [Fact]
        public async Task CreateApiKey_WithNullRequest_ThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => 
                _service.CreateApiKeyAsync(_testUserId, null!));
        }

        [Fact]
        public async Task CreateApiKey_WithEmptyName_ThrowsArgumentException()
        {
            var request = new CreateApiKeyRequest
            {
                Name = "",
                Scopes = new List<string> { "read:deployments" },
                RateLimit = 1000
            };

            await Assert.ThrowsAsync<ArgumentException>(() => 
                _service.CreateApiKeyAsync(_testUserId, request));
        }

        [Fact]
        public async Task CreateApiKey_WithEmptyScopes_ThrowsArgumentException()
        {
            var request = new CreateApiKeyRequest
            {
                Name = "Test",
                Scopes = new List<string>(),
                RateLimit = 1000
            };

            await Assert.ThrowsAsync<ArgumentException>(() => 
                _service.CreateApiKeyAsync(_testUserId, request));
        }

        [Fact]
        public async Task CreateApiKey_WithNonPositiveRateLimit_ThrowsArgumentException()
        {
            var request = new CreateApiKeyRequest
            {
                Name = "Test",
                Scopes = new List<string> { "read:deployments" },
                RateLimit = 0
            };

            await Assert.ThrowsAsync<ArgumentException>(() => 
                _service.CreateApiKeyAsync(_testUserId, request));
        }

        [Fact]
        public async Task ListApiKeys_ForUserWithKeys_ReturnsMaskedKeys()
        {
            // Arrange
            await CreateTestApiKeyInDb("Key 1", new List<string> { "read:deployments" });
            await CreateTestApiKeyInDb("Key 2", new List<string> { "write:deployments" });

            // Act
            var result = await _service.ListApiKeysAsync(_testUserId);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(2, result.Keys.Count);
            Assert.All(result.Keys, k =>
            {
                Assert.NotNull(k.ApiKeyId);
                Assert.DoesNotContain("sk_live_", k.ApiKeyId); // ID is GUID, not key
                Assert.Contains(k.Name, new[] { "Key 1", "Key 2" });
                Assert.NotEmpty(k.Scopes);
                Assert.Equal(1000, k.RateLimit); // Default from test helper
                Assert.True(k.IsActive);
            });
        }

        [Fact]
        public async Task ListApiKeys_ForUserWithNoKeys_ReturnsEmptyList()
        {
            // Act
            var result = await _service.ListApiKeysAsync(_testUserId);

            // Assert
            Assert.NotNull(result);
            Assert.Empty(result.Keys);
        }

        [Fact]
        public async Task RevokeApiKey_ExistingKeyForUser_SetsIsActiveFalse()
        {
            // Arrange
            var apiKey = await CreateTestApiKeyInDb("To Revoke", new List<string> { "read:deployments" });

            // Act
            var result = await _service.RevokeApiKeyAsync(_testUserId, apiKey.Id);

            // Assert
            Assert.True(result.Success);
            Assert.Equal(DateTime.UtcNow.Date, result.RevokedAt.Date);

            var updatedKey = await _dbName.ApiKeys.FindAsync(apiKey.Id);
            Assert.False(updatedKey.IsActive);
        }

        [Fact]
        public async Task RevokeApiKey_NonExistingKeyForUser_ThrowsKeyNotFoundException()
        {
            // Act & Assert
            await Assert.ThrowsAsync<KeyNotFoundException>(() => 
                _service.RevokeApiKeyAsync(_testUserId, Guid.NewGuid()));
        }

        [Fact]
        public async Task RevokeApiKey_KeyBelongingToOtherUser_ThrowsKeyNotFoundException()
        {
            // Arrange
            var otherUserId = Guid.NewGuid();
            var apiKey = await CreateTestApiKeyInDb("Other User Key", new List<string> { "read:deployments" }, otherUserId);

            // Act & Assert
            await Assert.ThrowsAsync<KeyNotFoundException>(() => 
                _service.RevokeApiKeyAsync(_testUserId, apiKey.Id));
        }

        [Fact]
        public async Task RotateApiKey_ExistingKeyForUser_ReturnsNewKeyAndRevokesOld()
        {
            // Arrange
            var originalKey = await CreateTestApiKeyInDb("To Rotate", new List<string> { "read:deployments" });
            var originalPrefix = originalKey.KeyPrefix;

            // Act
            var result = await _service.RotateApiKeyAsync(_testUserId, originalKey.Id);

            // Assert
            Assert.NotNull(result);
            Assert.NotNull(result.NewKey);
            Assert.StartsWith("sk_live_", result.NewKey);
            Assert.Equal(DateTime.UtcNow.Date, result.OldKeyRevokedAt.Date);
            Assert.Equal(DateTime.UtcNow.AddHours(24).Date, result.GracePeriodEndsAt.Date);

            // Verify old key material moved to previous fields, new key in current fields
            var rotatedKey = await _dbName.ApiKeys.FindAsync(originalKey.Id);
            Assert.True(rotatedKey.IsActive); // Key record stays active
            Assert.Equal(originalPrefix, rotatedKey.PreviousKeyPrefix); // Old prefix preserved
            Assert.NotNull(rotatedKey.PreviousKeySecretHash); // Old hash preserved
            Assert.NotNull(rotatedKey.PreviousKeyRevokedAt);
            Assert.NotNull(rotatedKey.GracePeriodEndsAt);
            Assert.NotEqual(originalPrefix, rotatedKey.KeyPrefix); // New prefix generated
            Assert.True(BCrypt.Net.BCrypt.Verify(result.NewKey, rotatedKey.KeySecretHash)); // New key matches new hash
            Assert.Equal(rotatedKey.KeyPrefix, result.NewKey.Substring(8, 8)); // New key prefix matches stored prefix
        }

        [Fact]
        public async Task RotateApiKey_RevokedKey_ThrowsAndReturnsNoSecret()
        {
            var apiKey = await CreateTestApiKeyInDb("Revoked", new List<string> { "read:deployments" });
            await _service.RevokeApiKeyAsync(_testUserId, apiKey.Id);

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                _service.RotateApiKeyAsync(_testUserId, apiKey.Id));
        }

        [Fact]
        public async Task RotateApiKey_NonExistingKeyForUser_ThrowsKeyNotFoundException()
        {
            // Act & Assert
            await Assert.ThrowsAsync<KeyNotFoundException>(() => 
                _service.RotateApiKeyAsync(_testUserId, Guid.NewGuid()));
        }

        [Fact]
        public async Task RotateApiKey_KeyBelongingToOtherUser_ThrowsKeyNotFoundException()
        {
            // Arrange
            var otherUserId = Guid.NewGuid();
            var apiKey = await CreateTestApiKeyInDb("Other User Key", new List<string> { "read:deployments" }, otherUserId);

            // Act & Assert
            await Assert.ThrowsAsync<KeyNotFoundException>(() => 
                _service.RotateApiKeyAsync(_testUserId, apiKey.Id));
        }

        [Fact]
        public async Task RotateApiKey_TwiceInsideGracePeriod_Throws()
        {
            // A second rotation would overwrite the first key's grace period (CodeRabbit, PR 18).
            var apiKey = await CreateTestApiKeyInDb("Twice", new List<string> { "read:deployments" });
            await _service.RotateApiKeyAsync(_testUserId, apiKey.Id);

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                _service.RotateApiKeyAsync(_testUserId, apiKey.Id));
        }

        [Fact]
        public async Task ValidateApiKey_ResourceIsFirstSegmentAfterVersion()
        {
            // read:users opens /api/v1/users, not /internal/users (CodeRabbit, PR 18).
            var created = await _service.CreateApiKeyAsync(_testUserId,
                new CreateApiKeyRequest { Name = "Scopes", Scopes = new List<string> { "read:users" }, RateLimit = 1000 });
            _redisDatabaseMock.Setup(r => r.StringIncrementAsync(It.IsAny<RedisKey>(), It.IsAny<long>(), It.IsAny<CommandFlags>()))
                .ReturnsAsync(1L);

            Assert.True((await _service.ValidateApiKeyAsync(created.Key, "/api/v1/users", HttpMethod.Get)).IsValid);
            Assert.False((await _service.ValidateApiKeyAsync(created.Key, "/internal/users", HttpMethod.Get)).IsValid);
            Assert.False((await _service.ValidateApiKeyAsync(created.Key, "/users", HttpMethod.Delete)).IsValid);
        }

        [Fact]
        public async Task ValidateApiKey_ValidKeyAndScope_ReturnsValid()
        {
            // Arrange
            var createRequest = new CreateApiKeyRequest
            {
                Name = "Validation Test",
                Scopes = new List<string> { "read:deployments" },
                RateLimit = 1000
            };
            var createResult = await _service.CreateApiKeyAsync(_testUserId, createRequest);
            var validKey = createResult.Key;

            // Mock Redis to allow the request
            _redisDatabaseMock.Setup(r => r.StringIncrementAsync(It.IsAny<RedisKey>(), It.IsAny<long>(), It.IsAny<CommandFlags>()))
                .ReturnsAsync(1L);

            // Act
            var result = await _service.ValidateApiKeyAsync(validKey, "/deployments", HttpMethod.Get);

            // Assert
            Assert.True(result.IsValid);
            Assert.Null(result.ErrorMessage);
            Assert.Null(result.StatusCode);
        }

        [Fact]
        public async Task ValidateApiKey_NullKey_ReturnsInvalidWithUnauthorized()
        {
            // Act
            var result = await _service.ValidateApiKeyAsync(null!, "/deployments", HttpMethod.Get);

            // Assert
            Assert.False(result.IsValid);
            Assert.Equal("Missing API key", result.ErrorMessage);
            Assert.Equal(HttpStatusCode.Unauthorized, result.StatusCode);
        }

        [Fact]
        public async Task ValidateApiKey_InvalidFormatKey_ReturnsInvalidWithUnauthorized()
        {
            // Act
            var result = await _service.ValidateApiKeyAsync("invalid_key", "/deployments", HttpMethod.Get);

            // Assert
            Assert.False(result.IsValid);
            Assert.Equal("Invalid API key format", result.ErrorMessage);
            Assert.Equal(HttpStatusCode.Unauthorized, result.StatusCode);
        }

        [Fact]
        public async Task ValidateApiKey_TooShortKey_ReturnsInvalidWithUnauthorized()
        {
            // Act
            var result = await _service.ValidateApiKeyAsync("sk_live_123", "/deployments", HttpMethod.Get);

            // Assert
            Assert.False(result.IsValid);
            Assert.Equal("API key too short", result.ErrorMessage);
            Assert.Equal(HttpStatusCode.Unauthorized, result.StatusCode);
        }

        [Fact]
        public async Task ValidateApiKey_ValidKeyButWrongPrefix_ReturnsInvalidWithUnauthorized()
        {
            // Arrange
            var apiKey = await CreateTestApiKeyInDb("Valid Key", new List<string> { "read:deployments" });
            // Use a different prefix that doesn't exist in DB
            var wrongKey = $"sk_live_{apiKey.KeyPrefix.Substring(0, 4)}xxxxxxxxxxxxxxxx"; // Still 8 chars prefix but different

            // Act
            var result = await _service.ValidateApiKeyAsync(wrongKey, "/deployments", HttpMethod.Get);

            // Assert
            Assert.False(result.IsValid);
            Assert.Equal("Invalid API key", result.ErrorMessage);
            Assert.Equal(HttpStatusCode.Unauthorized, result.StatusCode);
        }

        [Fact]
        public async Task ValidateApiKey_ValidKeyButFailedBcryptVerify_ReturnsInvalidWithUnauthorized()
        {
            // Arrange
            var apiKey = await CreateTestApiKeyInDb("Valid Key", new List<string> { "read:deployments" });
            // Create a key that has the correct prefix but wrong secret (will fail bcrypt)
            var wrongKey = $"sk_live_{apiKey.KeyPrefix}wrongsecrethere123"; // Same prefix, different rest

            // Act
            var result = await _service.ValidateApiKeyAsync(wrongKey, "/deployments", HttpMethod.Get);

            // Assert
            Assert.False(result.IsValid);
            Assert.Equal("Invalid API key", result.ErrorMessage);
            Assert.Equal(HttpStatusCode.Unauthorized, result.StatusCode);
        }

        // KEYS-07
        [Fact]
        public async Task ValidateApiKey_ExpiredKey_ReturnsInvalidWithUnauthorized()
        {
            // Arrange
            var expiredDate = DateTime.UtcNow.AddDays(-1);
            var createRequest = new CreateApiKeyRequest
            {
                Name = "Expired Key Test",
                Scopes = new List<string> { "read:deployments" },
                RateLimit = 1000,
                ExpiresAt = expiredDate
            };
            var createResult = await _service.CreateApiKeyAsync(_testUserId, createRequest);
            var expiredKey = createResult.Key;

            // Mock Redis to allow the request
            _redisDatabaseMock.Setup(r => r.StringIncrementAsync(It.IsAny<RedisKey>(), It.IsAny<long>(), It.IsAny<CommandFlags>()))
                .ReturnsAsync(1L);

            // Act
            var result = await _service.ValidateApiKeyAsync(expiredKey, "/deployments", HttpMethod.Get);

            // Assert
            Assert.False(result.IsValid);
            Assert.Equal("API key expired", result.ErrorMessage);
            Assert.Equal(HttpStatusCode.Unauthorized, result.StatusCode);
        }

        // KEYS-05
        [Fact]
        public async Task ValidateApiKey_ValidKeyButInsufficientScope_ReturnsInvalidWithForbidden()
        {
            // Arrange
            var createRequest = new CreateApiKeyRequest
            {
                Name = "Scope Test",
                Scopes = new List<string> { "read:deployments" }, // Only read
                RateLimit = 1000
            };
            var createResult = await _service.CreateApiKeyAsync(_testUserId, createRequest);
            var key = createResult.Key;

            // Mock Redis to allow the request
            _redisDatabaseMock.Setup(r => r.StringIncrementAsync(It.IsAny<RedisKey>(), It.IsAny<long>(), It.IsAny<CommandFlags>()))
                .ReturnsAsync(1L);

            // Act - POST requires write:deployments
            var result = await _service.ValidateApiKeyAsync(key, "/deployments", HttpMethod.Post); // Requires write

            // Assert
            Assert.False(result.IsValid);
            Assert.Equal("Insufficient scope", result.ErrorMessage);
            Assert.Equal(HttpStatusCode.Forbidden, result.StatusCode);
        }

        [Fact]
        public async Task ValidateApiKey_ValidKeyButRateLimitExceeded_ReturnsInvalidWith429()
        {
            // Arrange
            var createRequest = new CreateApiKeyRequest
            {
                Name = "Rate Limit Test",
                Scopes = new List<string> { "read:deployments" },
                RateLimit = 2 // Very low for testing
            };
            var createResult = await _service.CreateApiKeyAsync(_testUserId, createRequest);
            var key = createResult.Key;

            // Mock Redis to return increasing counts
            _redisDatabaseMock.SetupSequence(r => r.StringIncrementAsync(It.IsAny<RedisKey>(), It.IsAny<long>(), It.IsAny<CommandFlags>()))
                .ReturnsAsync(1L)
                .ReturnsAsync(2L)
                .ReturnsAsync(3L); // Third call exceeds limit of 2

            // Act
            var result1 = await _service.ValidateApiKeyAsync(key, "/deployments", HttpMethod.Get);
            var result2 = await _service.ValidateApiKeyAsync(key, "/deployments", HttpMethod.Get);
            var result3 = await _service.ValidateApiKeyAsync(key, "/deployments", HttpMethod.Get);

            // Assert
            Assert.True(result1.IsValid);
            Assert.True(result2.IsValid);
            Assert.False(result3.IsValid);
            Assert.Equal("Rate limit exceeded", result3.ErrorMessage);
            Assert.Equal((HttpStatusCode)429, result3.StatusCode);
        }

        [Fact]
        public async Task ValidateApiKey_ValidKey_UpdatesLastUsedAt()
        {
            // Arrange
            var createRequest = new CreateApiKeyRequest
            {
                Name = "Last Used Test",
                Scopes = new List<string> { "read:deployments" },
                RateLimit = 1000
            };
            var createResult = await _service.CreateApiKeyAsync(_testUserId, createRequest);
            var key = createResult.Key;

            // Mock Redis to allow the request
            _redisDatabaseMock.Setup(r => r.StringIncrementAsync(It.IsAny<RedisKey>(), It.IsAny<long>(), It.IsAny<CommandFlags>()))
                .ReturnsAsync(1L);

            // Act
            await _service.ValidateApiKeyAsync(key, "/deployments", HttpMethod.Get);

            // Assert
            var apiKey = await _dbName.ApiKeys.FindAsync(Guid.Parse(createResult.ApiKeyId));
            Assert.NotNull(apiKey.LastUsedAt);
            Assert.InRange(apiKey.LastUsedAt.Value, DateTime.UtcNow.AddSeconds(-5), DateTime.UtcNow.AddSeconds(5));
        }

        [Fact]
        public async Task LogApiKeyUsageAsync_AddsUsageRecord()
        {
            // Arrange
            var apiKey = await CreateTestApiKeyInDb("Usage Test", new List<string> { "read:deployments" });

            // Act
            await _service.LogApiKeyUsageAsync(apiKey.Id, "/deployments", HttpMethod.Get, 200);

            // Assert
            var usage = await _dbName.ApiKeyUsages.FirstOrDefaultAsync();
            Assert.NotNull(usage);
            Assert.Equal(apiKey.Id, usage.ApiKeyId);
            Assert.Equal("/deployments", usage.Endpoint);
            Assert.Equal("GET", usage.Method);
            Assert.Equal(200, usage.Status);
        }

        // KEYS-08
        [Fact]
        public async Task GetApiKeyUsageAsync_ForExistingKey_ReturnsUsageStats()
        {
            // Arrange
            var apiKey = await CreateTestApiKeyInDb("Usage Stats Test", new List<string> { "read:deployments" });
            await _service.LogApiKeyUsageAsync(apiKey.Id, "/deployments", HttpMethod.Get, 200);
            await _service.LogApiKeyUsageAsync(apiKey.Id, "/deployments", HttpMethod.Get, 200);
            await _service.LogApiKeyUsageAsync(apiKey.Id, "/webhooks", HttpMethod.Post, 200);
            await _service.LogApiKeyUsageAsync(apiKey.Id, "/webhooks", HttpMethod.Post, 429); // Rate limit hit
            await _service.LogApiKeyUsageAsync(apiKey.Id, "/nonexistent", HttpMethod.Get, 404);

            // Act
            var result = await _service.GetApiKeyUsageAsync(_testUserId, apiKey.Id, null, null);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(apiKey.Id.ToString(), result.ApiKeyId);
            Assert.Equal(5, result.TotalRequests);
            Assert.Equal(2, result.RequestsByEndpoint["GET /deployments"]);
            Assert.Equal(2, result.RequestsByEndpoint["POST /webhooks"]);
            Assert.Equal(1, result.RequestsByEndpoint["GET /nonexistent"]);
            Assert.Equal(1, result.RateLimitHits); // One 429
            Assert.Equal(1, result.Errors["404"]); // One 404
            Assert.DoesNotContain("200", result.Errors.Keys); // Successes not in errors
        }

        [Fact]
        public async Task GetApiKeyUsageAsync_WithDateRange_FiltersByTimestamp()
        {
            // Arrange
            var apiKey = await CreateTestApiKeyInDb("Date Range Test", new List<string> { "read:deployments" });
            var now = DateTime.UtcNow;
            var yesterday = now.AddDays(-1);

            await _service.LogApiKeyUsageAsync(apiKey.Id, "/deployments", HttpMethod.Get, 200); // Now
            await _service.LogApiKeyUsageAsync(apiKey.Id, "/deployments", HttpMethod.Get, 200); // Now
            _dbName.ApiKeyUsages.Add(new ApiKeyUsage
            {
                Id = Guid.NewGuid(),
                ApiKeyId = apiKey.Id,
                Endpoint = "/deployments",
                Method = "GET",
                Status = 200,
                Timestamp = yesterday
            });
            await _dbName.SaveChangesAsync();

            // Act
            var result = await _service.GetApiKeyUsageAsync(_testUserId, apiKey.Id, yesterday.AddHours(1), now.AddHours(1));

            // Assert
            Assert.Equal(2, result.TotalRequests); // Only the two from 'now', not yesterday's
        }

        [Fact]
        public async Task GetApiKeyUsageAsync_NonExistingKeyForUser_ThrowsKeyNotFoundException()
        {
            // Act & Assert
            await Assert.ThrowsAsync<KeyNotFoundException>(() => 
                _service.GetApiKeyUsageAsync(_testUserId, Guid.NewGuid(), null, null));
        }

        [Fact]
        public async Task GetApiKeyUsageAsync_KeyBelongingToOtherUser_ThrowsKeyNotFoundException()
        {
            // Arrange
            var otherUserId = Guid.NewGuid();
            var apiKey = await CreateTestApiKeyInDb("Other User Key", new List<string> { "read:deployments" }, otherUserId);

            // Act & Assert
            await Assert.ThrowsAsync<KeyNotFoundException>(() => 
                _service.GetApiKeyUsageAsync(_testUserId, apiKey.Id, null, null));
        }

        /// <summary>
        /// An authenticated caller with the given roles. In: the user id and roles. Out: the principal. Why: the admin
        /// list now checks its caller itself (Phase B.2). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Pure.
        /// </summary>
        private static ClaimsPrincipal Caller(Guid userId, params string[] roles) =>
            new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim(ClaimTypes.NameIdentifier, userId.ToString()) }.Concat(roles.Select(r => new Claim(ClaimTypes.Role, r))),
                authenticationType: "test"));

        /// <summary>An authenticated admin. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Pure.</summary>
        private static ClaimsPrincipal AdminCaller() => Caller(Guid.NewGuid(), "admin");

        /// <summary>
        /// KEYS-09 (Phase B.2 bug fix): AdminListApiKeysAsync refuses a non-admin caller itself, not only at the route:
        /// a signed-in user without the admin role, an anonymous identity and no caller at all each get 403
        /// admin_only; an admin sees every user's keys. In: nothing. Out: asserts. Added 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory database.
        /// </summary>
        // KEYS-09
        [Fact]
        public async Task AdminListApiKeysAsync_NonAdminCaller_Forbidden()
        {
            await CreateTestApiKeyInDb("Someone Else's Key", new List<string> { "read:deployments" }, Guid.NewGuid());
            foreach (var caller in new ClaimsPrincipal[] { Caller(_testUserId), Caller(_testUserId, "user"), new ClaimsPrincipal(new ClaimsIdentity()), null })
            {
                var ex = await Assert.ThrowsAsync<ApiKeysForbiddenException>(() => _service.AdminListApiKeysAsync(caller, null, null));
                Assert.Equal(403, ex.StatusCode);
                Assert.Equal("admin_only", ex.Code);
            }
            Assert.Equal(1, (await _service.AdminListApiKeysAsync(AdminCaller(), null, null)).Total);
        }

        // KEYS-09
        [Fact]
        public async Task AdminListApiKeysAsync_NoFilters_ReturnsAllKeys()
        {
            // Arrange
            var user1Id = Guid.NewGuid();
            var user2Id = Guid.NewGuid();
            await CreateTestApiKeyInDb("User1 Key", new List<string> { "read:deployments" }, user1Id);
            await CreateTestApiKeyInDb("User1 Key 2", new List<string> { "write:deployments" }, user1Id);
            await CreateTestApiKeyInDb("User2 Key", new List<string> { "read:webhooks" }, user2Id);

            // Act
            var result = await _service.AdminListApiKeysAsync(AdminCaller(), null, null);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(3, result.Keys.Count);
            Assert.Equal(3, result.Total);
        }

        [Fact]
        public async Task AdminListApiKeysAsync_WithUserIdFilter_ReturnsOnlyUsersKeys()
        {
            // Arrange
            var user1Id = Guid.NewGuid();
            var user2Id = Guid.NewGuid();
            await CreateTestApiKeyInDb("User1 Key", new List<string> { "read:deployments" }, user1Id);
            await CreateTestApiKeyInDb("User2 Key", new List<string> { "read:webhooks" }, user2Id);

            // Act
            var result = await _service.AdminListApiKeysAsync(AdminCaller(), user1Id, null);

            // Assert
            Assert.NotNull(result);
            Assert.Single(result.Keys);
            Assert.Equal(1, result.Total);
            Assert.Contains(result.Keys, k => k.Name == "User1 Key");
        }

        [Fact]
        public async Task AdminListApiKeysAsync_WithStatusActiveFilter_ReturnsOnlyActiveKeys()
        {
            // Arrange
            var activeKey = await CreateTestApiKeyInDb("Active Key", new List<string> { "read:deployments" });
            var revokedKey = await CreateTestApiKeyInDb("Revoked Key", new List<string> { "read:deployments" });
            await _service.RevokeApiKeyAsync(_testUserId, revokedKey.Id);

            // Act
            var result = await _service.AdminListApiKeysAsync(AdminCaller(), null, "active");

            // Assert
            Assert.NotNull(result);
            Assert.Single(result.Keys);
            Assert.Equal(1, result.Total);
            Assert.Contains(result.Keys, k => k.Name == "Active Key");
            Assert.DoesNotContain(result.Keys, k => k.Name == "Revoked Key");
        }

        [Fact]
        public async Task AdminListApiKeysAsync_WithStatusInactiveFilter_ReturnsOnlyInactiveKeys()
        {
            // Arrange
            var activeKey = await CreateTestApiKeyInDb("Active Key", new List<string> { "read:deployments" });
            var revokedKey = await CreateTestApiKeyInDb("Revoked Key", new List<string> { "read:deployments" });
            await _service.RevokeApiKeyAsync(_testUserId, revokedKey.Id);

            // Act
            var result = await _service.AdminListApiKeysAsync(AdminCaller(), null, "inactive");

            // Assert
            Assert.NotNull(result);
            Assert.Single(result.Keys);
            Assert.Equal(1, result.Total);
            Assert.Contains(result.Keys, k => k.Name == "Revoked Key");
            Assert.DoesNotContain(result.Keys, k => k.Name == "Active Key");
        }

        /// <summary>
        /// KEYS-02: a request carrying "Authorization: Bearer &lt;key&gt;" succeeds; no header or another scheme is 401.
        /// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (no test covered the header). Touches: in-memory EF, mocked Redis.
        /// </summary>
        // KEYS-02
        [Fact]
        public async Task AuthorizationHeader_BearerKey_Succeeds()
        {
            var created = await _service.CreateApiKeyAsync(_testUserId,
                new CreateApiKeyRequest { Name = "Header", Scopes = new List<string> { "read:deployments" }, RateLimit = 1000 });
            _redisDatabaseMock.Setup(r => r.StringIncrementAsync(It.IsAny<RedisKey>(), It.IsAny<long>(), It.IsAny<CommandFlags>()))
                .ReturnsAsync(1L);

            var ok = await _service.ValidateAuthorizationHeaderAsync("Bearer " + created.Key, "/api/deployments", HttpMethod.Get);
            Assert.True(ok.IsValid);

            var missing = await _service.ValidateAuthorizationHeaderAsync(null, "/api/deployments", HttpMethod.Get);
            Assert.False(missing.IsValid);
            Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);

            var basic = await _service.ValidateAuthorizationHeaderAsync("Basic " + created.Key, "/api/deployments", HttpMethod.Get);
            Assert.False(basic.IsValid);
            Assert.Equal(HttpStatusCode.Unauthorized, basic.StatusCode);
        }

        /// <summary>
        /// KEYS-03: a key that worked is refused with 401 once revoked. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
        /// (the revoke test only checked the is_active flag, not a later request). Touches: in-memory EF, mocked Redis.
        /// </summary>
        // KEYS-03
        [Fact]
        public async Task RevokedKey_SubsequentRequest_Returns401()
        {
            var created = await _service.CreateApiKeyAsync(_testUserId,
                new CreateApiKeyRequest { Name = "Revoke me", Scopes = new List<string> { "read:deployments" }, RateLimit = 1000 });
            _redisDatabaseMock.Setup(r => r.StringIncrementAsync(It.IsAny<RedisKey>(), It.IsAny<long>(), It.IsAny<CommandFlags>()))
                .ReturnsAsync(1L);
            Assert.True((await _service.ValidateAuthorizationHeaderAsync("Bearer " + created.Key, "/deployments", HttpMethod.Get)).IsValid);

            await _service.RevokeApiKeyAsync(_testUserId, Guid.Parse(created.ApiKeyId));

            var after = await _service.ValidateAuthorizationHeaderAsync("Bearer " + created.Key, "/deployments", HttpMethod.Get);
            Assert.False(after.IsValid);
            Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
        }

        /// <summary>
        /// KEYS-04: with rate_limit 1000, the 1000th request in the hour passes and the 1001st is 429, and the hit is
        /// counted in usage stats. Redis is mocked to report the hour's counter at 1000 and then 1001 (running 1001
        /// bcrypt checks would take minutes). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory EF, mocked Redis.
        /// </summary>
        // KEYS-04
        [Fact]
        public async Task RateLimit_1001stRequestInHour_Returns429()
        {
            var created = await _service.CreateApiKeyAsync(_testUserId,
                new CreateApiKeyRequest { Name = "Limit", Scopes = new List<string> { "read:deployments" }, RateLimit = 1000 });
            _redisDatabaseMock.SetupSequence(r => r.StringIncrementAsync(It.IsAny<RedisKey>(), It.IsAny<long>(), It.IsAny<CommandFlags>()))
                .ReturnsAsync(1000L)
                .ReturnsAsync(1001L);

            var thousandth = await _service.ValidateApiKeyAsync(created.Key, "/deployments", HttpMethod.Get);
            var next = await _service.ValidateApiKeyAsync(created.Key, "/deployments", HttpMethod.Get);

            Assert.True(thousandth.IsValid);
            Assert.False(next.IsValid);
            Assert.Equal((HttpStatusCode)429, next.StatusCode);
            var stats = await _service.GetApiKeyUsageAsync(_testUserId, Guid.Parse(created.ApiKeyId), null, null);
            Assert.Equal(1, stats.RateLimitHits);
        }

        /// <summary>
        /// KEYS-06: after rotation the new key works at once and the old key keeps working until the 24 h grace period
        /// ends, then gets 401. Uses the injectable clock. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (the rotate
        /// test never used either key). Touches: in-memory EF, mocked Redis.
        /// </summary>
        // KEYS-06
        [Fact]
        public async Task Rotate_NewKeyWorks_OldKeyStopsAfterGracePeriod()
        {
            var now = new DateTime(2026, 11, 10, 12, 0, 0, DateTimeKind.Utc);
            var service = new ApiKeysService(_dbName, _redisMock.Object, _loggerMock.Object, () => now);
            _redisDatabaseMock.Setup(r => r.StringIncrementAsync(It.IsAny<RedisKey>(), It.IsAny<long>(), It.IsAny<CommandFlags>()))
                .ReturnsAsync(1L);
            var created = await service.CreateApiKeyAsync(_testUserId,
                new CreateApiKeyRequest { Name = "Rotate", Scopes = new List<string> { "read:deployments" }, RateLimit = 1000 });

            var rotated = await service.RotateApiKeyAsync(_testUserId, Guid.Parse(created.ApiKeyId));
            Assert.Equal(now.AddHours(24), rotated.GracePeriodEndsAt);
            Assert.True((await service.ValidateApiKeyAsync(rotated.NewKey, "/deployments", HttpMethod.Get)).IsValid);
            Assert.True((await service.ValidateApiKeyAsync(created.Key, "/deployments", HttpMethod.Get)).IsValid);

            now = now.AddHours(23).AddMinutes(59);
            Assert.True((await service.ValidateApiKeyAsync(created.Key, "/deployments", HttpMethod.Get)).IsValid);

            now = now.AddMinutes(2);
            var old = await service.ValidateApiKeyAsync(created.Key, "/deployments", HttpMethod.Get);
            Assert.False(old.IsValid);
            Assert.Equal(HttpStatusCode.Unauthorized, old.StatusCode);
            Assert.True((await service.ValidateApiKeyAsync(rotated.NewKey, "/deployments", HttpMethod.Get)).IsValid);
        }

        // Helper methods
        private async Task<ApiKey> CreateTestApiKeyInDb(string name, List<string> scopes, Guid? userId = null, DateTime? expiresAt = null)
        {
            // Generate a unique key for each test key to avoid collisions
            var keyParts = GenerateTestApiKey();
            var apiKey = new ApiKey
            {
                Id = Guid.NewGuid(),
                UserId = userId ?? _testUserId,
                Name = name,
                KeyPrefix = keyParts.Prefix,
                KeySecretHash = BCrypt.Net.BCrypt.HashPassword(keyParts.FullKey),
                ScopesJson = JsonSerializer.Serialize(scopes),
                RateLimit = 1000,
                ExpiresAt = expiresAt,
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                PreviousKeyPrefix = null,
                PreviousKeySecretHash = null,
                PreviousKeyRevokedAt = null,
                GracePeriodEndsAt = null
            };

            _dbName.ApiKeys.Add(apiKey);
            await _dbName.SaveChangesAsync();
            return apiKey;
        }

        private static (string FullKey, string Prefix) GenerateTestApiKey()
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
    }
}

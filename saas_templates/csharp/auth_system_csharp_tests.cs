// Tests for the auth template. Changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): `BCrypt.HashPassword`
// resolved to the BCrypt namespace (compile error) and is BCrypt.Net.BCrypt.HashPassword; a loop variable named
// `result` clashed with the outer `result` (compile error) and is `signup`; the OAuth tests passed a state ("state123")
// that nothing had issued, which a correct callback must refuse (spec gate state_valid), and now obtain one from
// CreateOAuthStateAsync; VerifyEmail_HappyPath re-read the user through the context that still tracked the old
// instance and now reads through a fresh one. Three tests were added for verify_access_token and the login lock.
// Touches: EF InMemory databases and an in-memory cache only.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthSystem;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using OtpNet;
using Xunit;

namespace AuthSystemTests
{
    public class AuthServiceTests
    {
        private readonly DbContextOptions<AuthDbContext> _dbOptions;
        private readonly Mock<IEmailSender> _emailSenderMock;
        private readonly Mock<IOAuthProvider> _oauthProviderMock;
        private readonly IMemoryCache _cache;
        private readonly string _jwtSecret = "this_is_a_very_secret_key_for_jwt_signing_that_is_long_enough";

        public AuthServiceTests()
        {
            _dbOptions = new DbContextOptionsBuilder<AuthDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;
            _emailSenderMock = new Mock<IEmailSender>();
            _oauthProviderMock = new Mock<IOAuthProvider>();
            _cache = new MemoryCache(new MemoryCacheOptions());
        }

        private AuthDbContext CreateDb() => new AuthDbContext(_dbOptions);
        private AuthService CreateService() => new AuthService(CreateDb(), _emailSenderMock.Object, _oauthProviderMock.Object, _cache, _jwtSecret);

        // AUTH-01
        [Fact]
        public async Task Signup_HappyPath_CreatesUserAndSendsEmail()
        {
            var service = CreateService();
            var result = await service.SignupAsync("test@example.com", "ThisIsAVeryLongPassword123!", "Test User");
            Assert.Equal("pending_verification", ((dynamic)result).status);
            Assert.Equal("test@example.com", ((dynamic)result).email);
            _emailSenderMock.Verify(es => es.SendVerificationEmailAsync("test@example.com", It.IsAny<string>()), Times.Once);
            // the row exists and is unverified (AUTH-01 "user created"; added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
            using var db = CreateDb();
            Assert.Equal("unverified", (await db.Users.SingleAsync(u => u.Email == "test@example.com")).Status);
        }

        // AUTH-02
        [Fact]
        public async Task Signup_DuplicateEmail_ReturnsError()
        {
            using var db = CreateDb();
            db.Users.Add(new User { Email = "test@example.com", PasswordHash = BCrypt.Net.BCrypt.HashPassword("password"), Status = "verified" });
            await db.SaveChangesAsync();

            var service = CreateService();
            var result = await service.SignupAsync("test@example.com", "ThisIsAVeryLongPassword123!", "Test User");
            Assert.Equal("email_already_exists", ((dynamic)result).error);
        }

        // AUTH-03
        [Fact]
        public async Task Signup_WeakPassword_TooShort_ReturnsError()
        {
            var service = CreateService();
            var result = await service.SignupAsync("test@example.com", "short", "Test User");
            Assert.Equal("password_rejected", ((dynamic)result).error);
            Assert.Equal("too_short", ((dynamic)result).reason);

            // Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-03 amendment): checks run too_short, too_long,
            // blocklisted and the first failure wins; "password123" is on the blocklist but is too_short first.
            Assert.Equal("too_short", ((dynamic)await service.SignupAsync("a@example.com", "password123", "A")).reason);
            Assert.Equal("too_long", ((dynamic)await service.SignupAsync("b@example.com", new string('x', 65), "B")).reason);
            Assert.Equal("too_short", ((dynamic)await service.SignupAsync("c@example.com", string.Concat(Enumerable.Repeat("\U0001F600", 8)), "C")).reason);
            var own = await service.SignupAsync("long.address.user@example.com", "long.address.user@example.com", "D");
            Assert.Equal("password_rejected", ((dynamic)own).error);
            Assert.Equal("blocklisted", ((dynamic)own).reason);
            using var db = CreateDb();
            Assert.False(await db.Users.AnyAsync(), "a rejected password creates no user");
        }

        // AUTH-04
        [Fact]
        public async Task Signup_IPRateLimit_Exceeded_ReturnsError()
        {
            var service = CreateService();
            for (int i = 0; i < 5; i++)
            {
                var signup = await service.SignupAsync($"user{i}@example.com", "ThisIsAVeryLongPassword123!", "Test User");
                if (i < 4)
                    Assert.Equal("pending_verification", ((dynamic)signup).status);
            }

            var result = await service.SignupAsync("blocked@example.com", "ThisIsAVeryLongPassword123!", "Test User");
            Assert.Equal("too_many_signups_from_ip", ((dynamic)result).error);
        }

        // AUTH-05
        [Fact]
        public async Task VerifyEmail_HappyPath_VerifiesUser()
        {
            using var db = CreateDb();
            var user = new User { Email = "test@example.com", PasswordHash = BCrypt.Net.BCrypt.HashPassword("password"), Status = "unverified" };
            db.Users.Add(user);
            await db.SaveChangesAsync();

            var code = "123456";
            db.VerificationCodes.Add(new VerificationCode
            {
                UserId = user.Id,
                Code = code,
                Type = "email",
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddMinutes(15)
            });
            await db.SaveChangesAsync();

            var service = CreateService();
            var result = await service.VerifyEmailAsync("test@example.com", code);
            Assert.Equal("verified", ((dynamic)result).status);
            Assert.Equal(user.Id, ((dynamic)result).user_id);

            // Read through a fresh context: `db` still tracks the pre-verification instance, so FindAsync on it
            // would return that stale object without querying (2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP).
            using var freshDb = CreateDb();
            var updatedUser = await freshDb.Users.FindAsync(user.Id);
            Assert.NotNull(updatedUser.EmailVerifiedAt);
        }

        // AUTH-06
        [Fact]
        public async Task VerifyEmail_ExpiredCode_ReturnsError()
        {
            using var db = CreateDb();
            var user = new User { Email = "test@example.com", PasswordHash = BCrypt.Net.BCrypt.HashPassword("password"), Status = "unverified" };
            db.Users.Add(user);
            await db.SaveChangesAsync();

            var code = "123456";
            db.VerificationCodes.Add(new VerificationCode
            {
                UserId = user.Id,
                Code = code,
                Type = "email",
                CreatedAt = DateTime.UtcNow.AddMinutes(-20),
                ExpiresAt = DateTime.UtcNow.AddMinutes(-5)
            });
            await db.SaveChangesAsync();

            var service = CreateService();
            var result = await service.VerifyEmailAsync("test@example.com", code);
            Assert.Equal("code_expired", ((dynamic)result).error);
        }

        // AUTH-07
        [Fact]
        public async Task Login_NoMFA_ReturnsToken()
        {
            using var db = CreateDb();
            var user = new User { Email = "test@example.com", PasswordHash = BCrypt.Net.BCrypt.HashPassword("ThisIsAVeryLongPassword123!"), Status = "verified" };
            db.Users.Add(user);
            await db.SaveChangesAsync();

            var service = CreateService();
            var result = await service.LoginAsync("test@example.com", "ThisIsAVeryLongPassword123!", "device1", "127.0.0.1");
            Assert.Equal("authenticated", ((dynamic)result).status);
            Assert.NotNull(((dynamic)result).token);
            Assert.Equal(user.Id, ((dynamic)result).user.id);
        }

        // AUTH-08
        [Fact]
        public async Task Login_WithMFAEnabled_ReturnsMFARequired()
        {
            using var db = CreateDb();
            var user = new User
            {
                Email = "test@example.com",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("ThisIsAVeryLongPassword123!"),
                Status = "verified",
                MfaEnabled = true,
                MfaSecret = "JBSWY3DPEHPK3PXP" // Base32 for "HELLOWORLD"
            };
            db.Users.Add(user);
            await db.SaveChangesAsync();

            var service = CreateService();
            var result = await service.LoginAsync("test@example.com", "ThisIsAVeryLongPassword123!", "device1", "127.0.0.1");
            Assert.Equal("mfa_required", ((dynamic)result).status);
            Assert.NotNull(((dynamic)result).challenge_id);
        }

        // AUTH-09
        [Fact]
        public async Task Login_InvalidPassword_ReturnsError()
        {
            using var db = CreateDb();
            var user = new User { Email = "test@example.com", PasswordHash = BCrypt.Net.BCrypt.HashPassword("ThisIsAVeryLongPassword123!"), Status = "verified" };
            db.Users.Add(user);
            await db.SaveChangesAsync();

            var service = CreateService();
            var result = await service.LoginAsync("test@example.com", "WrongPassword", "device1", "127.0.0.1");
            Assert.Equal("invalid_credentials", ((dynamic)result).error);
        }

        // AUTH-10
        [Fact]
        public async Task OAuthCallback_NewUser_CreatesUserAndLinksProvider()
        {
            _oauthProviderMock.Setup(o => o.GetEmailFromCodeAsync("google", "code")).ReturnsAsync("newuser@example.com");
            _oauthProviderMock.Setup(o => o.IsEmailVerifiedAsync("google", "code")).ReturnsAsync(true);

            var service = CreateService();
            var state = await service.CreateOAuthStateAsync();
            var result = await service.OAuthCallbackAsync("google", "code", state);
            Assert.Equal("authenticated", ((dynamic)result).status);
            Assert.Equal("newuser@example.com", ((dynamic)result).user.email);
            Assert.Equal("verified", ((dynamic)result).user.status.ToString());

            using var db = CreateDb();
            var user = await db.Users.FirstOrDefaultAsync(u => u.Email == "newuser@example.com");
            Assert.NotNull(user);
            Assert.Equal("verified", user.Status);
        }

        // AUTH-11
        [Fact]
        public async Task OAuthCallback_ExistingUser_LinksProvider()
        {
            using var db = CreateDb();
            var user = new User { Email = "existing@example.com", PasswordHash = BCrypt.Net.BCrypt.HashPassword("password"), Status = "verified" };
            db.Users.Add(user);
            await db.SaveChangesAsync();

            _oauthProviderMock.Setup(o => o.GetEmailFromCodeAsync("google", "code")).ReturnsAsync("existing@example.com");
            _oauthProviderMock.Setup(o => o.IsEmailVerifiedAsync("google", "code")).ReturnsAsync(true);

            var service = CreateService();
            var state = await service.CreateOAuthStateAsync();
            var result = await service.OAuthCallbackAsync("google", "code", state);
            Assert.Equal("authenticated", ((dynamic)result).status);
            Assert.Equal(user.Id, ((dynamic)result).user.id);
        }

        // AUTH-12
        [Fact]
        public async Task MfaChallenge_ValidCode_ReturnsToken()
        {
            using var db = CreateDb();
            var user = new User
            {
                Email = "test@example.com",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("ThisIsAVeryLongPassword123!"),
                Status = "verified",
                MfaEnabled = true,
                MfaSecret = "JBSWY3DPEHPK3PXP"
            };
            db.Users.Add(user);
            await db.SaveChangesAsync();

            var totp = new Totp(Base32Encoding.ToBytes(user.MfaSecret));
            var code = totp.ComputeTotp();

            var challengeId = Guid.NewGuid().ToString();
            db.VerificationCodes.Add(new VerificationCode
            {
                UserId = user.Id,
                Code = challengeId,
                Type = "mfa",
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddMinutes(5)
            });
            await db.SaveChangesAsync();

            var service = CreateService();
            var result = await service.MfaChallengeAsync(challengeId, code);
            Assert.Equal("authenticated", ((dynamic)result).status);
            Assert.NotNull(((dynamic)result).token);
        }

        // AUTH-13
        [Fact]
        public async Task MfaChallenge_InvalidCode_ReturnsError()
        {
            using var db = CreateDb();
            var user = new User
            {
                Email = "test@example.com",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("ThisIsAVeryLongPassword123!"),
                Status = "verified",
                MfaEnabled = true,
                MfaSecret = "JBSWY3DPEHPK3PXP"
            };
            db.Users.Add(user);
            await db.SaveChangesAsync();

            var challengeId = Guid.NewGuid().ToString();
            db.VerificationCodes.Add(new VerificationCode
            {
                UserId = user.Id,
                Code = challengeId,
                Type = "mfa",
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddMinutes(5)
            });
            await db.SaveChangesAsync();

            var service = CreateService();
            var result = await service.MfaChallengeAsync(challengeId, "000000");
            Assert.Equal("invalid_code", ((dynamic)result).error);
        }

        // AUTH-14
        [Fact]
        public async Task TokenRefresh_HappyPath_IssuesNewToken()
        {
            using var db = CreateDb();
            var user = new User { Email = "test@example.com", PasswordHash = BCrypt.Net.BCrypt.HashPassword("password"), Status = "verified", Tier = "premium" };
            db.Users.Add(user);
            await db.SaveChangesAsync();

            var refreshToken = Guid.NewGuid().ToString();
            db.Sessions.Add(new Session
            {
                UserId = user.Id,
                RefreshTokenHash = AuthService.HashRefreshToken(refreshToken), // only the hash is stored (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(7),
                Ip = "127.0.0.1",
                DeviceId = "device1"
            });
            await db.SaveChangesAsync();

            var service = CreateService();
            var result = await service.TokenRefreshAsync(refreshToken);
            Assert.Equal("ok", ((dynamic)result).status);
            Assert.NotNull(((dynamic)result).token);
        }

        // AUTH-15
        [Fact]
        public async Task TokenRefresh_BannedUser_ReturnsError()
        {
            using var db = CreateDb();
            var user = new User { Email = "test@example.com", PasswordHash = BCrypt.Net.BCrypt.HashPassword("password"), Status = "banned" };
            db.Users.Add(user);
            await db.SaveChangesAsync();

            var refreshToken = Guid.NewGuid().ToString();
            db.Sessions.Add(new Session
            {
                UserId = user.Id,
                RefreshTokenHash = AuthService.HashRefreshToken(refreshToken), // only the hash is stored (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(7),
                Ip = "127.0.0.1",
                DeviceId = "device1"
            });
            await db.SaveChangesAsync();

            var service = CreateService();
            var result = await service.TokenRefreshAsync(refreshToken);
            Assert.Equal("user_banned", ((dynamic)result).error);
        }
    
        /// <summary>
        /// Flow 7 (verify_access_token) happy path: a token from login verifies and names the same user. Added
        /// 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP) with the flow itself. Touches: the in-memory database.
        /// </summary>
        [Fact]
        public async Task VerifyAccessToken_ValidToken_ReturnsUser()
        {
            using var db = CreateDb();
            var user = new User { Email = "test@example.com", PasswordHash = BCrypt.Net.BCrypt.HashPassword("ThisIsAVeryLongPassword123!"), Status = "verified" };
            db.Users.Add(user);
            await db.SaveChangesAsync();

            var service = CreateService();
            var login = await service.LoginAsync("test@example.com", "ThisIsAVeryLongPassword123!", "device1", "127.0.0.1");
            var result = await service.VerifyAccessTokenAsync((string)((dynamic)login).token);
            Assert.Equal("ok", ((dynamic)result).status);
            Assert.Equal(user.Id, ((dynamic)result).user.id);
        }

        /// <summary>
        /// Flow 7 rejects an unsigned ("alg":"none") token and a token signed with another key (RFC 8725 3.1: the
        /// header's algorithm is never trusted). Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP).
        /// </summary>
        [Fact]
        public async Task VerifyAccessToken_ForgedOrUnsigned_ReturnsInvalidToken()
        {
            using var db = CreateDb();
            var user = new User { Email = "test@example.com", PasswordHash = BCrypt.Net.BCrypt.HashPassword("ThisIsAVeryLongPassword123!"), Status = "verified" };
            db.Users.Add(user);
            await db.SaveChangesAsync();

            static string B64(string json) => Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            var exp = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds();
            var payload = B64($"{{\"user_id\":\"{user.Id}\",\"tier\":\"free\",\"exp\":{exp}}}");
            var unsigned = B64("{\"alg\":\"none\",\"typ\":\"JWT\"}") + "." + payload + ".";

            var otherKeyService = new AuthService(CreateDb(), _emailSenderMock.Object, _oauthProviderMock.Object, _cache, "a_completely_different_secret_key_that_is_also_long_enough");
            var login = await otherKeyService.LoginAsync("test@example.com", "ThisIsAVeryLongPassword123!", "device1", "127.0.0.1");
            var forged = (string)((dynamic)login).token;

            var service = CreateService();
            Assert.Equal("invalid_token", ((dynamic)await service.VerifyAccessTokenAsync(unsigned)).error);
            Assert.Equal("invalid_token", ((dynamic)await service.VerifyAccessTokenAsync(forged)).error);
        }

        /// <summary>
        /// Login locks an ip+email pair after 5 failed attempts in 15 minutes (spec rate_limit gate), even when the 6th
        /// attempt has the right password. Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): failures were
        /// counted but never checked.
        /// </summary>
        [Fact]
        public async Task Login_FiveFailures_LocksFurtherAttempts()
        {
            using var db = CreateDb();
            db.Users.Add(new User { Email = "test@example.com", PasswordHash = BCrypt.Net.BCrypt.HashPassword("ThisIsAVeryLongPassword123!"), Status = "verified" });
            await db.SaveChangesAsync();

            var service = CreateService();
            for (int i = 0; i < 5; i++)
                Assert.Equal("invalid_credentials", ((dynamic)await service.LoginAsync("test@example.com", "WrongPassword", "device1", "10.0.0.1")).error);
            var locked = await service.LoginAsync("test@example.com", "ThisIsAVeryLongPassword123!", "device1", "10.0.0.1");
            Assert.Equal("too_many_attempts", ((dynamic)locked).error);
        }
}
}
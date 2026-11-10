// Tests for the auth template. Changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): `BCrypt.HashPassword`
// resolved to the BCrypt namespace (compile error) and is BCrypt.Net.BCrypt.HashPassword; a loop variable named
// `result` clashed with the outer `result` (compile error) and is `signup`; the OAuth tests passed a state ("state123")
// that nothing had issued, which a correct callback must refuse (spec gate state_valid), and now obtain one from
// CreateOAuthStateAsync; VerifyEmail_HappyPath re-read the user through the context that still tracked the old
// instance and now reads through a fresh one. Three tests were added for verify_access_token and the login lock.
// Phase B.2 (2026-11-10, same session): verification codes, MFA challenge ids and OAuth states are seeded as their
// SHA-256 (CodeHash; the Code column is gone), the OAuth mocks answer the single ExchangeCodeAsync call that replaced
// GetEmailFromCodeAsync + IsEmailVerifiedAsync, and AUTH-16 tests were added.
// spec d270fa3 (2026-11-10, same session: keyed HMAC for stored secrets): the service takes a fixed test HMAC key,
// rows are seeded as HMAC-SHA256(TestSecretKey, value) through Hash() (they used AuthService's static plain SHA-256),
// AUTH-16 asserts the stored value is not the plain SHA-256, and a test proves the service refuses to start without
// a 32-byte key.
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
        /// <summary>Fixed 32+ byte HMAC key for stored secrets (spec d270fa3: tests pass a fixed test key). 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private const string TestSecretKey = "test-secret-key-0123456789abcdef-auth";

        /// <summary>
        /// The value the service stores for a secret: lower-case hex HMAC-SHA256(TestSecretKey, value). In: the secret.
        /// Out: 64 hex characters. Why: spec d270fa3: keyed HMAC for stored secrets; the tests called the service's
        /// static plain SHA-256 (AuthService.HashSecret) until 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// Touches: nothing.
        /// </summary>
        private static string Hash(string value) => Convert.ToHexString(System.Security.Cryptography.HMACSHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(TestSecretKey), System.Text.Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

        /// <summary>
        /// Plain, unkeyed SHA-256 hex of a secret, which the service must no longer store. In: the secret. Out: 64 hex
        /// characters. Why: spec d270fa3: keyed HMAC for stored secrets (AUTH-16 asserts the stored value is not this).
        /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
        /// </summary>
        private static string PlainSha256(string value) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

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
        /// <summary>A service on a fresh context with the test JWT secret and, since spec d270fa3 (2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP), the fixed TestSecretKey. Touches: the in-memory database and cache.</summary>
        private AuthService CreateService() => new AuthService(CreateDb(), _emailSenderMock.Object, _oauthProviderMock.Object, _cache, _jwtSecret, TestSecretKey);

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
                CodeHash = Hash(code), // stored only as its hash (AUTH-16, 2026-11-10)
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
                CodeHash = Hash(code), // stored only as its hash (AUTH-16, 2026-11-10)
                Type = "email",
                CreatedAt = DateTime.UtcNow.AddMinutes(-20),
                ExpiresAt = DateTime.UtcNow.AddMinutes(-5)
            });
            await db.SaveChangesAsync();

            var service = CreateService();
            var result = await service.VerifyEmailAsync("test@example.com", code);
            Assert.Equal("code_expired", ((dynamic)result).error);
        }

        /// <summary>
        /// Auth spec flow 2 "Attempts" (Phase B.3 ruling): 4 wrong codes leave the code usable; the 5th wrong code
        /// invalidates it, so the right code is then code_invalid and the user stays unverified; a new code
        /// (as signup sends) works. A second user with 4 wrong tries then the right one is verified. In: nothing.
        /// Out: asserts. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory database.
        /// </summary>
        [Fact]
        public async Task VerifyEmail_FiveWrongCodes_InvalidateTheCode()
        {
            using var db = CreateDb();
            var user = new User { Email = "guess@example.com", PasswordHash = BCrypt.Net.BCrypt.HashPassword("password"), Status = "unverified" };
            var other = new User { Email = "four@example.com", PasswordHash = BCrypt.Net.BCrypt.HashPassword("password"), Status = "unverified" };
            db.Users.AddRange(user, other);
            await db.SaveChangesAsync();
            foreach (var u in new[] { user, other })
                db.VerificationCodes.Add(new VerificationCode
                {
                    UserId = u.Id, CodeHash = Hash("123456"), Type = "email",
                    CreatedAt = DateTime.UtcNow, ExpiresAt = DateTime.UtcNow.AddMinutes(15)
                });
            await db.SaveChangesAsync();

            for (var i = 0; i < 4; i++)
                Assert.Equal("code_invalid", ((dynamic)await CreateService().VerifyEmailAsync("four@example.com", "00000" + i)).error);
            Assert.Equal("verified", ((dynamic)await CreateService().VerifyEmailAsync("four@example.com", "123456")).status);

            for (var i = 0; i < 5; i++)
                Assert.Equal("code_invalid", ((dynamic)await CreateService().VerifyEmailAsync("guess@example.com", "00000" + i)).error);
            Assert.Equal("code_invalid", ((dynamic)await CreateService().VerifyEmailAsync("guess@example.com", "123456")).error);
            Assert.Equal("code_invalid", ((dynamic)await CreateService().VerifyEmailAsync("guess@example.com", "123456")).error);
            using (var check = CreateDb())
            {
                Assert.Null((await check.Users.FindAsync(user.Id)).EmailVerifiedAt);
                Assert.Empty(check.VerificationCodes.Where(v => v.UserId == user.Id));
            }

            // a new code is sent: it works
            using (var resend = CreateDb())
            {
                resend.VerificationCodes.Add(new VerificationCode
                {
                    UserId = user.Id, CodeHash = Hash("654321"), Type = "email",
                    CreatedAt = DateTime.UtcNow, ExpiresAt = DateTime.UtcNow.AddMinutes(15)
                });
                await resend.SaveChangesAsync();
            }
            Assert.Equal("verified", ((dynamic)await CreateService().VerifyEmailAsync("guess@example.com", "654321")).status);
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
            // one exchange of the code through the injected client (Phase B.2, 2026-11-10; was two calls with the same code)
            _oauthProviderMock.Setup(o => o.ExchangeCodeAsync("google", "code"))
                .ReturnsAsync(new OAuthIdentity { ProviderUserId = "g-1", Email = "newuser@example.com", EmailVerified = true });

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

            // one exchange of the code through the injected client (Phase B.2, 2026-11-10; was two calls with the same code)
            _oauthProviderMock.Setup(o => o.ExchangeCodeAsync("google", "code"))
                .ReturnsAsync(new OAuthIdentity { ProviderUserId = "g-2", Email = "existing@example.com", EmailVerified = true });

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
                CodeHash = Hash(challengeId), // stored only as its hash (Phase B.2, 2026-11-10)
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
                CodeHash = Hash(challengeId), // stored only as its hash (Phase B.2, 2026-11-10)
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
                RefreshTokenHash = Hash(refreshToken), // only the hash is stored (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
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
                RefreshTokenHash = Hash(refreshToken), // only the hash is stored (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
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

            var otherKeyService = new AuthService(CreateDb(), _emailSenderMock.Object, _oauthProviderMock.Object, _cache, "a_completely_different_secret_key_that_is_also_long_enough", TestSecretKey);
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

        /// <summary>
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec d270fa3: keyed HMAC for stored secrets): each
        /// stored value must equal HMAC-SHA256(TestSecretKey, value) and must not equal its plain SHA-256.
        /// AUTH-16: login returns a refresh_token that token_refresh accepts; the sessions table holds only its SHA-256
        /// (no stored column equals the token); and the signup verification code is stored only as its SHA-256 (the
        /// code emailed to the user is not in the table, and it still verifies). In: nothing. Out: asserts. Added
        /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2). Touches: the in-memory database and cache.
        /// </summary>
        // AUTH-16
        [Fact]
        public async Task Login_RefreshTokenAccepted_OnlyHashesAtRest()
        {
            string emailedCode = null;
            _emailSenderMock.Setup(e => e.SendVerificationEmailAsync("hash@example.com", It.IsAny<string>()))
                .Callback<string, string>((_, c) => emailedCode = c).Returns(Task.CompletedTask);
            var service = CreateService();
            Assert.Equal("pending_verification", ((dynamic)await service.SignupAsync("hash@example.com", "a long passphrase nobody guesses", "Hash")).status);
            Assert.NotNull(emailedCode);
            using (var db = CreateDb())
            {
                var stored = await db.VerificationCodes.SingleAsync(v => v.Type == "email");
                Assert.Equal(Hash(emailedCode), stored.CodeHash);
                Assert.NotEqual(PlainSha256(emailedCode), stored.CodeHash); // spec d270fa3 (2026-11-10): keyed, not plain
                Assert.NotEqual(emailedCode, stored.CodeHash);
                Assert.Equal(64, stored.CodeHash.Length);
            }
            Assert.Equal("verified", ((dynamic)await CreateService().VerifyEmailAsync("hash@example.com", emailedCode)).status);

            var login = await CreateService().LoginAsync("hash@example.com", "a long passphrase nobody guesses", "device1", "127.0.0.1");
            Assert.Equal("authenticated", ((dynamic)login).status);
            string refreshToken = ((dynamic)login).refresh_token;
            Assert.False(string.IsNullOrEmpty(refreshToken));

            using (var db = CreateDb())
            {
                var session = await db.Sessions.AsNoTracking().SingleAsync();
                Assert.Equal(Hash(refreshToken), session.RefreshTokenHash);
                Assert.NotEqual(PlainSha256(refreshToken), session.RefreshTokenHash); // spec d270fa3 (2026-11-10)
                Assert.Null(session.RefreshToken); // not mapped: a database read never hands out the token
                Assert.DoesNotContain(refreshToken, new[] { session.RefreshTokenHash, session.Ip, session.DeviceId });
            }

            var refreshed = await CreateService().TokenRefreshAsync(refreshToken);
            Assert.Equal("ok", ((dynamic)refreshed).status);
            Assert.Equal("ok", ((dynamic)await CreateService().VerifyAccessTokenAsync((string)((dynamic)refreshed).token)).status);
            // the stored hash itself is not a usable refresh token
            using (var db = CreateDb())
                Assert.Equal("invalid_token", ((dynamic)await CreateService().TokenRefreshAsync((await db.Sessions.SingleAsync()).RefreshTokenHash)).error);
        }

        /// <summary>
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec d270fa3): the challenge id and state hashes must
        /// equal HMAC-SHA256(TestSecretKey, value), not the plain SHA-256.
        /// AUTH-16 (with "Secrets at rest"): MFA verify and the OAuth callback also return a refresh_token that
        /// token_refresh accepts; the MFA challenge id and the OAuth state are stored only as their SHA-256; the OAuth
        /// state is single use and expires after 10 minutes; the callback exchanges the provider's code exactly once
        /// through the injected client and takes the identity from that exchange, never from the code (a code the
        /// provider refuses signs nobody in). In: nothing. Out: asserts. Added 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2). Touches: the in-memory database and cache.
        /// </summary>
        // AUTH-16
        [Fact]
        public async Task MfaAndOAuth_ReturnRefreshToken_StateAndChallengeHashed_StateSingleUseAndExpiring()
        {
            using (var db = CreateDb())
            {
                db.Users.Add(new User { Email = "mfa@example.com", PasswordHash = BCrypt.Net.BCrypt.HashPassword("a long passphrase nobody guesses"), Status = "verified", MfaEnabled = true, MfaSecret = "JBSWY3DPEHPK3PXP" });
                await db.SaveChangesAsync();
            }
            var mfaLogin = await CreateService().LoginAsync("mfa@example.com", "a long passphrase nobody guesses", "device1", "127.0.0.1");
            string challengeId = ((dynamic)mfaLogin).challenge_id;
            using (var db = CreateDb())
            {
                var row = await db.VerificationCodes.SingleAsync(v => v.Type == "mfa");
                Assert.Equal(Hash(challengeId), row.CodeHash);
                Assert.NotEqual(PlainSha256(challengeId), row.CodeHash); // spec d270fa3 (2026-11-10)
                Assert.Equal("invalid_challenge", ((dynamic)await CreateService().MfaChallengeAsync(row.CodeHash, "000000")).error);
            }
            var mfa = await CreateService().MfaChallengeAsync(challengeId, new Totp(Base32Encoding.ToBytes("JBSWY3DPEHPK3PXP")).ComputeTotp());
            Assert.Equal("authenticated", ((dynamic)mfa).status);
            Assert.Equal("ok", ((dynamic)await CreateService().TokenRefreshAsync((string)((dynamic)mfa).refresh_token)).status);

            _oauthProviderMock.Setup(o => o.ExchangeCodeAsync("google", "good-code"))
                .ReturnsAsync(new OAuthIdentity { ProviderUserId = "g-9", Email = "oauth@example.com", EmailVerified = true });
            _oauthProviderMock.Setup(o => o.ExchangeCodeAsync("google", "refused-code")).ReturnsAsync((OAuthIdentity)null);

            var service = CreateService();
            var state = await service.CreateOAuthStateAsync();
            using (var db = CreateDb())
            {
                var row = await db.VerificationCodes.SingleAsync(v => v.Type == "oauth_state");
                Assert.Equal(Hash(state), row.CodeHash);
                Assert.NotEqual(PlainSha256(state), row.CodeHash); // spec d270fa3 (2026-11-10)
                Assert.NotEqual(state, row.CodeHash);
                Assert.InRange(row.ExpiresAt - row.CreatedAt, TimeSpan.FromMinutes(10) - TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(10) + TimeSpan.FromSeconds(1));
            }
            var oauth = await service.OAuthCallbackAsync("google", "good-code", state);
            Assert.Equal("authenticated", ((dynamic)oauth).status);
            Assert.Equal("oauth@example.com", ((dynamic)oauth).user.email);
            Assert.Equal("ok", ((dynamic)await CreateService().TokenRefreshAsync((string)((dynamic)oauth).refresh_token)).status);
            _oauthProviderMock.Verify(o => o.ExchangeCodeAsync("google", "good-code"), Times.Once);

            // single use: the same state again is refused before the provider is asked
            Assert.Equal("invalid_state", ((dynamic)await CreateService().OAuthCallbackAsync("google", "good-code", state)).error);
            _oauthProviderMock.Verify(o => o.ExchangeCodeAsync("google", "good-code"), Times.Once);

            // a code the provider refuses signs nobody in (the code is never an identity)
            var state2 = await CreateService().CreateOAuthStateAsync();
            Assert.Equal("oauth_exchange_failed", ((dynamic)await CreateService().OAuthCallbackAsync("google", "refused-code", state2)).error);

            // expired: a state older than 10 minutes is refused
            var state3 = await CreateService().CreateOAuthStateAsync();
            using (var db = CreateDb())
            {
                var row = await db.VerificationCodes.SingleAsync(v => v.Type == "oauth_state" && v.CodeHash == Hash(state3));
                row.ExpiresAt = DateTime.UtcNow.AddSeconds(-1);
                await db.SaveChangesAsync();
            }
            Assert.Equal("invalid_state", ((dynamic)await CreateService().OAuthCallbackAsync("google", "good-code", state3)).error);
            _oauthProviderMock.Verify(o => o.ExchangeCodeAsync("google", "good-code"), Times.Once);
        }

        /// <summary>
        /// AUTH-16: the service refuses to start without a 32-byte HMAC key: the constructor throws ArgumentException
        /// for an empty or 31-byte secretKey, and for a null one when AUTH_SECRET_KEY is unset or 31 bytes; a 32-byte
        /// AUTH_SECRET_KEY starts it and keys the stored hash. In: nothing. Out: asserts. Why: spec d270fa3: keyed HMAC
        /// for stored secrets ("the service refuses to start without it"). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// Touches: the AUTH_SECRET_KEY environment variable (restored afterwards), the in-memory database and cache.
        /// </summary>
        // AUTH-16
        [Fact]
        public void Constructor_WithoutA32ByteSecretKey_RefusesToStart()
        {
            AuthService Make(string key) => new AuthService(CreateDb(), _emailSenderMock.Object, _oauthProviderMock.Object, _cache, _jwtSecret, key);
            var saved = Environment.GetEnvironmentVariable("AUTH_SECRET_KEY");
            try
            {
                Environment.SetEnvironmentVariable("AUTH_SECRET_KEY", null);
                Assert.Contains("AUTH_SECRET_KEY", Assert.Throws<ArgumentException>(() => Make(null)).Message);
                Assert.Throws<ArgumentException>(() => Make(""));
                Assert.Throws<ArgumentException>(() => Make(new string('k', 31)));
                Environment.SetEnvironmentVariable("AUTH_SECRET_KEY", new string('k', 31));
                Assert.Throws<ArgumentException>(() => Make(null));
                Environment.SetEnvironmentVariable("AUTH_SECRET_KEY", TestSecretKey);
                var fromEnv = Make(null);
                Assert.Equal(Hash("123456"), fromEnv.HashSecret("123456"));
                Assert.NotEqual(PlainSha256("123456"), fromEnv.HashSecret("123456"));
            }
            finally
            {
                Environment.SetEnvironmentVariable("AUTH_SECRET_KEY", saved);
            }
        }
}
}
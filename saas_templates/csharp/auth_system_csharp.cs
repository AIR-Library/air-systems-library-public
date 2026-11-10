// Auth system template (GEMINI_DISPATCH_MASTER_SPEC template #1): signup, email verification, login with optional
// TOTP MFA, OAuth callback, refresh and access-token verification, over EF Core, with bcrypt, HS256 JWTs and an
// in-memory rate-limit cache. Repaired 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP); see AuthService.
// Touches: the auth database, the email sender and OAuth provider interfaces, the cache, stdout (why chain).
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using OtpNet;

namespace AuthSystem
{
    public class AuthDbContext : DbContext
    {
        public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) { }

        public DbSet<User> Users { get; set; }
        public DbSet<Session> Sessions { get; set; }
        public DbSet<VerificationCode> VerificationCodes { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Email).IsRequired().HasMaxLength(255);
                entity.HasIndex(e => e.Email).IsUnique();
                entity.Property(e => e.PasswordHash).IsRequired();
                entity.Property(e => e.Tier).IsRequired().HasDefaultValue("free");
                entity.Property(e => e.Status).IsRequired().HasDefaultValue("unverified");
                entity.Property(e => e.EmailVerifiedAt);
                entity.Property(e => e.MfaSecret);
                entity.Property(e => e.MfaEnabled).HasDefaultValue(false);
            });

            modelBuilder.Entity<Session>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.RefreshToken).IsRequired().HasMaxLength(255);
                entity.HasIndex(e => e.RefreshToken).IsUnique();
                entity.Property(e => e.CreatedAt).IsRequired();
                entity.Property(e => e.ExpiresAt).IsRequired();
                entity.Property(e => e.Ip).IsRequired().HasMaxLength(45);
                entity.Property(e => e.DeviceId).IsRequired().HasMaxLength(255);
                entity.HasOne(e => e.User).WithMany().HasForeignKey(e => e.UserId);
            });

            modelBuilder.Entity<VerificationCode>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Code).IsRequired().HasMaxLength(255);
                entity.Property(e => e.CreatedAt).IsRequired();
                entity.Property(e => e.ExpiresAt).IsRequired();
                entity.Property(e => e.Type).IsRequired().HasMaxLength(20);
                entity.HasOne(e => e.User).WithMany().HasForeignKey(e => e.UserId);
            });

            modelBuilder.Entity<AuditLog>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Timestamp).IsRequired();
                entity.Property(e => e.Action).IsRequired().HasMaxLength(100);
                entity.Property(e => e.ResourceType).IsRequired().HasMaxLength(50);
                entity.Property(e => e.ResourceId).HasMaxLength(255);
                entity.Property(e => e.OldValue).HasMaxLength(1024);
                entity.Property(e => e.NewValue).HasMaxLength(1024);
                entity.Property(e => e.ActorId);
            });
        }
    }

    /// <summary>
    /// A user account. Tier and Status default to "free" and "unverified" in C# as well as in the schema: a database
    /// default is never applied by providers that do not run DDL (EF InMemory), so a user created without them failed
    /// its required-column check (2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP). Pure data.
    /// </summary>
    public class User
    {
        public int Id { get; set; }
        public string Email { get; set; }
        public string PasswordHash { get; set; }
        public string Tier { get; set; } = "free";
        public string Status { get; set; } = "unverified";
        public DateTime? EmailVerifiedAt { get; set; }
        public string MfaSecret { get; set; }
        public bool MfaEnabled { get; set; }
    }

    public class Session
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public string RefreshToken { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public string Ip { get; set; }
        public string DeviceId { get; set; }
        public User User { get; set; }
    }

    /// <summary>
    /// A one-time code: an email code, an MFA challenge or an OAuth state. UserId is null for an OAuth state, which
    /// exists before any user is known (2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP). Pure data.
    /// </summary>
    public class VerificationCode
    {
        public int Id { get; set; }
        public int? UserId { get; set; }
        public string Code { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public string Type { get; set; }
        public User User { get; set; }
    }

    public class AuditLog
    {
        public int Id { get; set; }
        public DateTime Timestamp { get; set; }
        public int? ActorId { get; set; }
        public string Action { get; set; }
        public string ResourceType { get; set; }
        public string ResourceId { get; set; }
        public string OldValue { get; set; }
        public string NewValue { get; set; }
    }

    public interface IEmailSender
    {
        Task SendVerificationEmailAsync(string email, string code);
    }

    public interface IOAuthProvider
    {
        Task<string> GetEmailFromCodeAsync(string provider, string code);
        Task<bool> IsEmailVerifiedAsync(string provider, string code);
    }

    /// <summary>
    /// The seven auth flows of GEMINI_DISPATCH_MASTER_SPEC template #1: signup, verify_email, login, oauth_callback,
    /// mfa_challenge, token_refresh and verify_access_token, each gated, audit-logged and why-chain-logged.
    /// Repaired 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP). The suite did not compile: BCrypt was called
    /// through its namespace (BCrypt.HashPassword instead of BCrypt.Net.BCrypt.HashPassword) and IMemoryCache has no
    /// SetAsync. While repairing it: login now requires status 'verified' (as the Go template does) and enforces the
    /// spec's 5-failures-per-15-minutes lock; verify_email sets status 'verified' and compares codes in constant time;
    /// verification codes come from a CSPRNG; the OAuth state is issued here (<see cref="CreateOAuthStateAsync"/>),
    /// single-use and expiring; MFA accepts one 30-second step of drift and locks a challenge after 5 wrong codes;
    /// JWTs are HS256 with user_id and tier; and the missing flow 7, <see cref="VerifyAccessTokenAsync"/>, was added.
    /// Touches: the auth database (users, sessions, verification_codes, audit_log), the in-memory rate-limit cache,
    /// the email sender and OAuth provider interfaces (network in production, fakes in tests), and stdout (why chain,
    /// never secrets).
    /// </summary>
    public class AuthService
    {
        /// <summary>Spec: rate_limit_ip_24h, 5 signups per IP per 24 hours.</summary>
        public const int MaxSignupsPerIpPerDay = 5;
        /// <summary>Spec: 5 failed logins per 15 minutes per ip/user.</summary>
        public const int MaxFailedLoginsPer15Min = 5;
        /// <summary>Wrong TOTP codes allowed on one MFA challenge before it is destroyed.</summary>
        public const int MaxMfaAttemptsPerChallenge = 5;
        /// <summary>Access-token lifetime in seconds (15 minutes).</summary>
        public const int AccessTokenSeconds = 900;
        /// <summary>Bucket used when a caller does not pass the client IP to <see cref="SignupAsync"/>: all such signups share one limit (fail closed).</summary>
        public const string UnknownIp = "unknown";

        private readonly AuthDbContext _db;
        private readonly IEmailSender _emailSender;
        private readonly IOAuthProvider _oauthProvider;
        private readonly IMemoryCache _cache;
        private readonly byte[] _jwtKey;
        private static readonly object CounterGate = new object();
        private readonly string _serviceName = "MyService";
        private readonly HashSet<string> _commonPasswords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "password", "123456", "12345678", "qwerty", "abc123", "monkey", "letmein", "dragon", "baseball", "iloveyou",
            "trustno1", "sunshine", "master", "welcome", "password1", "superman", "princess", "1234567", "123456789",
            "123123", "football", "!@#$%^&*", "charlie", "aa123456", "donald", "jordan123", "harley", "ranger", "daniel",
            "starwars", "klaster", "1q2w3e4r", "131313", "freedom", "whatever", "qazwsx", "trustno1", "654321", "27653328",
            "iamthebest", "fuckyou", "superman1", "princess1", "1qaz2wsx", "qweasdzxc", "password123", "michael", "football1",
            "superman123", "123qwe", "cocacola", "samsung", "android", "foobar", "access14", "asdfghjkl", "zxcvbnm", "111111"
        };

        /// <summary>
        /// Creates the service. Inputs: the database context, email sender, OAuth provider, a cache for rate limits and
        /// the JWT signing secret (from configuration, never hard-coded; at least 32 bytes because HS256 needs a 256-bit
        /// key). Throws ArgumentException on a short secret. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
        /// Touches: nothing until a flow runs.
        /// </summary>
        public AuthService(AuthDbContext db, IEmailSender emailSender, IOAuthProvider oauthProvider, IMemoryCache cache, string jwtSecret)
        {
            _db = db ?? throw new ArgumentNullException(nameof(db));
            _emailSender = emailSender ?? throw new ArgumentNullException(nameof(emailSender));
            _oauthProvider = oauthProvider ?? throw new ArgumentNullException(nameof(oauthProvider));
            _cache = cache ?? throw new ArgumentNullException(nameof(cache));
            if (string.IsNullOrEmpty(jwtSecret) || Encoding.UTF8.GetByteCount(jwtSecret) < 32)
                throw new ArgumentException("The JWT secret must be at least 32 bytes (HS256 needs a 256-bit key).", nameof(jwtSecret));
            _jwtKey = Encoding.UTF8.GetBytes(jwtSecret);
        }

        /// <summary>
        /// Flow 1, signup. Gates: rate_limit_ip_24h (5), email_unique, password_strength (NIST SP 800-63B-4: 15-64
        /// characters, blocklist, not the email/name/service name, no composition rules). Creates an 'unverified' user
        /// with a bcrypt hash and emails a 6-digit code valid 15 minutes. Inputs: email, password, name and the client IP
        /// (optional; omitted IPs share the <see cref="UnknownIp"/> bucket). Output: {status:"pending_verification",
        /// email, message} or {error}. Repaired 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): BCrypt.Net.BCrypt,
        /// cache Set instead of the non-existent SetAsync, email normalised before the uniqueness check, CSPRNG code.
        /// Touches: users, verification_codes, audit_log, the cache, the email sender (network in production).
        /// </summary>
        public async Task<object> SignupAsync(string email, string password, string name, string clientIp = null)
        {
            var ip = string.IsNullOrWhiteSpace(clientIp) ? UnknownIp : clientIp;
            var normalizedEmail = (email ?? string.Empty).Trim().ToLowerInvariant();
            var rateLimitKey = $"signup_ip:{ip}";
            if (ReadCounter(rateLimitKey) >= MaxSignupsPerIpPerDay)
                return new { error = "too_many_signups_from_ip" };

            if (normalizedEmail.Length == 0 || !normalizedEmail.Contains('@'))
                return new { error = "invalid_email" };

            if (await _db.Users.AnyAsync(u => u.Email == normalizedEmail))
                return new { error = "email_already_exists" };

            var passwordResult = ValidatePassword(password ?? string.Empty, normalizedEmail, name);
            if (!passwordResult.Success)
                return new { error = "password_rejected", reason = passwordResult.Reason };

            IncrementCounter(rateLimitKey, TimeSpan.FromHours(24));

            var user = new User
            {
                Email = normalizedEmail,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(password),
                Tier = "free",
                Status = "unverified"
            };
            _db.Users.Add(user);
            await _db.SaveChangesAsync();

            var code = GenerateVerificationCode();
            _db.VerificationCodes.Add(new VerificationCode
            {
                UserId = user.Id,
                Code = code,
                Type = "email",
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddMinutes(15)
            });
            await _db.SaveChangesAsync();

            await _emailSender.SendVerificationEmailAsync(normalizedEmail, code);
            await LogAuditAsync(user.Id, "user_created", "user", user.Id.ToString(), null, $"{{email:{normalizedEmail}}}");
            await LogWhyChainAsync("signup", new[] { "email_unique", "password_strength", "rate_limit_ip_24h" });

            return new { status = "pending_verification", email = normalizedEmail, message = "check email" };
        }

        /// <summary>
        /// Flow 2, verify_email. Gates: user_unverified (email_verified_at is null), code_valid (matches, compared in
        /// constant time; not expired). Marks email_verified_at and status 'verified' and deletes the code. Inputs:
        /// email, code. Output: {status:"verified", user_id, message} or {error: invalid_request | code_invalid |
        /// code_expired}. Repaired 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): sets status so login accepts
        /// the user, constant-time comparison, wrong vs expired codes reported apart. Touches: users,
        /// verification_codes, audit_log.
        /// </summary>
        public async Task<object> VerifyEmailAsync(string email, string code)
        {
            var normalizedEmail = (email ?? string.Empty).Trim().ToLowerInvariant();
            var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == normalizedEmail);
            if (user == null || user.EmailVerifiedAt.HasValue)
                return new { error = "invalid_request" };

            var candidates = await _db.VerificationCodes
                .Where(v => v.UserId == user.Id && v.Type == "email")
                .ToListAsync();
            var verification = candidates.FirstOrDefault(v => SecretEquals(v.Code, code));
            if (verification == null)
                return new { error = "code_invalid" };
            if (verification.ExpiresAt <= DateTime.UtcNow)
                return new { error = "code_expired" };

            user.EmailVerifiedAt = DateTime.UtcNow;
            user.Status = "verified";
            _db.VerificationCodes.Remove(verification);
            await _db.SaveChangesAsync();

            await LogAuditAsync(user.Id, "email_verified", "user", user.Id.ToString(), null, null);
            await LogWhyChainAsync("verify_email", new[] { "code_valid", "user_unverified" });

            return new { status = "verified", user_id = user.Id, message = "ready to login" };
        }

        /// <summary>
        /// Flow 3, login. Gates: rate_limit (5 failures per 15 minutes per ip+email, checked first so a locked pair
        /// cannot keep guessing), user_exists_and_verified (status 'verified', as in the Go template),
        /// password_correct (bcrypt), mfa_gate. With MFA on, returns {status:"mfa_required", challenge_id} (a random
        /// id valid 5 minutes); otherwise creates a session and returns {status:"authenticated", session_id, token,
        /// expires_in, user}. Every failure answers invalid_credentials, so accounts cannot be enumerated.
        /// Repaired 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): BCrypt.Net.BCrypt.Verify, the lock is now
        /// enforced (failures used to be counted and never checked), status gate. Touches: users, sessions,
        /// verification_codes, audit_log, the cache.
        /// </summary>
        public async Task<object> LoginAsync(string email, string password, string deviceId, string ip)
        {
            var normalizedEmail = (email ?? string.Empty).Trim().ToLowerInvariant();
            var rateLimitKey = $"login_failed:{ip}:{normalizedEmail}";
            if (ReadCounter(rateLimitKey) >= MaxFailedLoginsPer15Min)
            {
                await LogWhyChainAsync("login", new[] { "rate_limit" });
                return new { error = "too_many_attempts" };
            }

            var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == normalizedEmail);
            if (user == null || user.Status != "verified" || string.IsNullOrEmpty(user.PasswordHash) ||
                !BCrypt.Net.BCrypt.Verify(password ?? string.Empty, user.PasswordHash))
            {
                IncrementCounter(rateLimitKey, TimeSpan.FromMinutes(15));
                await LogWhyChainAsync("login", new[] { "user_exists", "password_correct" });
                return new { error = "invalid_credentials" };
            }

            _cache.Remove(rateLimitKey);

            if (user.MfaEnabled)
            {
                var challengeId = GenerateOpaqueToken();
                _db.VerificationCodes.Add(new VerificationCode
                {
                    UserId = user.Id,
                    Code = challengeId,
                    Type = "mfa",
                    CreatedAt = DateTime.UtcNow,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(5)
                });
                await _db.SaveChangesAsync();
                await LogWhyChainAsync("login", new[] { "user_exists", "password_correct", "mfa_gate", "rate_limit" });
                return new { status = "mfa_required", challenge_id = challengeId };
            }

            var session = await CreateSessionAsync(user.Id, ip, deviceId);
            var token = GenerateJwtToken(user.Id, user.Tier);
            await LogAuditAsync(user.Id, "session_created", "session", session.Id.ToString(), null, $"{{ip:{ip},device_id:{deviceId}}}");
            await LogWhyChainAsync("login", new[] { "user_exists", "password_correct", "mfa_gate", "rate_limit" });

            return Authenticated(session, token, user);
        }

        /// <summary>
        /// Issues an OAuth <c>state</c> value for the authorize redirect: 32 random bytes, stored for 10 minutes and
        /// consumed by <see cref="OAuthCallbackAsync"/> (spec gate state_valid: CSRF protection). Output: the state
        /// string, to be put in the redirect and bound to the browser session by the caller. Added 2026-11-10
        /// (session session_012zDydZCZ4AChqhEZ4oVtaP): the callback checked a state that nothing could create.
        /// Touches: verification_codes.
        /// </summary>
        public async Task<string> CreateOAuthStateAsync()
        {
            var state = GenerateOpaqueToken();
            _db.VerificationCodes.Add(new VerificationCode
            {
                UserId = null,
                Code = state,
                Type = "oauth_state",
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddMinutes(10)
            });
            await _db.SaveChangesAsync();
            return state;
        }

        /// <summary>
        /// Flow 4, oauth_callback. Gates: state_valid (issued by <see cref="CreateOAuthStateAsync"/>, unexpired,
        /// single use), email_verified_by_provider. A new email creates a 'verified' user with an unusable random
        /// password; an existing email is linked. Inputs: provider, authorization code, state. Output:
        /// {status:"authenticated", session_id, token, expires_in, user:{id,email,tier,status}} or {error}.
        /// Repaired 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): BCrypt.Net.BCrypt, the state is consumed
        /// before the provider is asked (a replayed state fails even if the provider call does), suspended/banned
        /// users are refused, the audit actor is the user. Touches: users, sessions, verification_codes, audit_log, the
        /// OAuth provider (network in production).
        /// </summary>
        public async Task<object> OAuthCallbackAsync(string provider, string code, string state)
        {
            if (string.IsNullOrEmpty(state))
                return new { error = "invalid_state" };
            var stateVerification = await _db.VerificationCodes
                .FirstOrDefaultAsync(v => v.Type == "oauth_state" && v.Code == state && v.ExpiresAt > DateTime.UtcNow);
            if (stateVerification == null)
                return new { error = "invalid_state" };
            _db.VerificationCodes.Remove(stateVerification);
            await _db.SaveChangesAsync();

            var email = await _oauthProvider.GetEmailFromCodeAsync(provider, code);
            var isVerified = await _oauthProvider.IsEmailVerifiedAsync(provider, code);
            if (!isVerified || string.IsNullOrWhiteSpace(email))
                return new { error = "email_not_verified_by_provider" };

            var normalizedEmail = email.Trim().ToLowerInvariant();
            var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == normalizedEmail);
            if (user == null)
            {
                user = new User
                {
                    Email = normalizedEmail,
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword(GenerateOpaqueToken()),
                    Tier = "free",
                    Status = "verified",
                    EmailVerifiedAt = DateTime.UtcNow
                };
                _db.Users.Add(user);
                await _db.SaveChangesAsync();
            }
            else if (user.Status == "suspended" || user.Status == "banned")
            {
                return new { error = "user_banned" };
            }

            var session = await CreateSessionAsync(user.Id, "oauth", provider ?? "oauth");
            var token = GenerateJwtToken(user.Id, user.Tier);
            await LogAuditAsync(user.Id, "oauth_login", "oauth_provider", provider, null, $"{{user_id:{user.Id},session_id:{session.Id}}}");
            await LogWhyChainAsync("oauth_callback", new[] { "state_valid", "email_verified" });

            return Authenticated(session, token, user);
        }

        /// <summary>
        /// Flow 5, mfa_challenge. Gates: challenge_exists_and_valid (unexpired), code_correct (TOTP, one 30-second step
        /// of drift either way). After <see cref="MaxMfaAttemptsPerChallenge"/> wrong codes the challenge is deleted,
        /// so a 6-digit code cannot be brute-forced. Inputs: challenge id, code. Output: {status:"authenticated", ...}
        /// or {error: invalid_challenge | invalid_code}. Repaired 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP):
        /// drift window narrowed from ±2 steps, attempt limit added. Touches: users, sessions, verification_codes,
        /// audit_log, the cache.
        /// </summary>
        public async Task<object> MfaChallengeAsync(string challengeId, string totpCode)
        {
            var challenge = await _db.VerificationCodes
                .FirstOrDefaultAsync(v => v.Type == "mfa" && v.Code == challengeId && v.ExpiresAt > DateTime.UtcNow);
            if (challenge == null || challenge.UserId == null)
                return new { error = "invalid_challenge" };

            var user = await _db.Users.FindAsync(challenge.UserId.Value);
            if (user == null || !user.MfaEnabled || string.IsNullOrEmpty(user.MfaSecret))
                return new { error = "invalid_challenge" };

            var totp = new Totp(Base32Encoding.ToBytes(user.MfaSecret));
            var verified = !string.IsNullOrEmpty(totpCode) &&
                           totp.VerifyTotp(totpCode, out _, new VerificationWindow(1, 1));
            if (!verified)
            {
                var attemptsKey = $"mfa_attempts:{challenge.Id}";
                if (IncrementCounter(attemptsKey, TimeSpan.FromMinutes(5)) >= MaxMfaAttemptsPerChallenge)
                {
                    _db.VerificationCodes.Remove(challenge);
                    await _db.SaveChangesAsync();
                    _cache.Remove(attemptsKey);
                }
                return new { error = "invalid_code" };
            }

            _db.VerificationCodes.Remove(challenge);
            await _db.SaveChangesAsync();

            var session = await CreateSessionAsync(user.Id, "mfa", "mfa");
            var token = GenerateJwtToken(user.Id, user.Tier);
            await LogAuditAsync(user.Id, "mfa_verified", "user", user.Id.ToString(), null, null);
            await LogWhyChainAsync("mfa_challenge", new[] { "challenge_valid", "code_correct" });

            return Authenticated(session, token, user);
        }

        /// <summary>
        /// Flow 6, token_refresh. Gates: token_valid (a stored, unexpired refresh token), user_not_banned (status not
        /// 'suspended'/'banned'). Issues a new access token. Input: the refresh token. Output: {status:"ok", token,
        /// expires_in} or {error: invalid_token | user_banned}. Updated 2026-11-10 (session
        /// session_012zDydZCZ4AChqhEZ4oVtaP): audit resource id is the session. Touches: sessions, users, audit_log.
        /// </summary>
        public async Task<object> TokenRefreshAsync(string refreshToken)
        {
            if (string.IsNullOrEmpty(refreshToken))
                return new { error = "invalid_token" };
            var session = await _db.Sessions
                .Include(s => s.User)
                .FirstOrDefaultAsync(s => s.RefreshToken == refreshToken && s.ExpiresAt > DateTime.UtcNow);
            if (session == null || session.User == null)
                return new { error = "invalid_token" };

            if (session.User.Status == "suspended" || session.User.Status == "banned")
            {
                await LogWhyChainAsync("token_refresh", new[] { "token_valid", "user_active" });
                return new { error = "user_banned" };
            }

            var newToken = GenerateJwtToken(session.User.Id, session.User.Tier);
            await LogAuditAsync(session.User.Id, "token_refreshed", "session", session.Id.ToString(), null, null);
            await LogWhyChainAsync("token_refresh", new[] { "token_valid", "user_active" });

            return new { status = "ok", token = newToken, expires_in = AccessTokenSeconds };
        }

        /// <summary>
        /// Flow 7, verify_access_token: what every authenticated request calls. Gates: signature_valid (HS256 only,
        /// passed explicitly as ValidAlgorithms; the header's alg is never trusted and "none" is rejected, RFC 8725
        /// 3.1), not_expired (no clock skew), user_exists_and_active. Read-only. Input: the access token. Output:
        /// {status:"ok", user:{id,email,tier}} or {error: invalid_token | token_expired | user_banned}. Added
        /// 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): the spec requires it and the other languages have it;
        /// without it the library issued tokens nothing checked. Touches: users (read).
        /// </summary>
        public async Task<object> VerifyAccessTokenAsync(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                return new { error = "invalid_token" };

            var parameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(_jwtKey),
                ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 },
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ClockSkew = TimeSpan.Zero
            };

            ClaimsPrincipal principal;
            try
            {
                var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
                principal = handler.ValidateToken(token, parameters, out _);
            }
            catch (SecurityTokenExpiredException)
            {
                await LogWhyChainAsync("verify_access_token", new[] { "signature_valid", "not_expired" });
                return new { error = "token_expired" };
            }
            catch (Exception ex) when (ex is SecurityTokenException || ex is ArgumentException)
            {
                await LogWhyChainAsync("verify_access_token", new[] { "signature_valid" });
                return new { error = "invalid_token" };
            }

            if (!int.TryParse(principal.FindFirst("user_id")?.Value, out var userId))
                return new { error = "invalid_token" };
            var user = await _db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == userId);
            if (user == null)
                return new { error = "invalid_token" };
            if (user.Status == "suspended" || user.Status == "banned")
            {
                await LogWhyChainAsync("verify_access_token", new[] { "signature_valid", "not_expired", "user_active" });
                return new { error = "user_banned" };
            }

            await LogWhyChainAsync("verify_access_token", new[] { "signature_valid", "not_expired", "user_active" });
            return new { status = "ok", user = new { id = user.Id, email = user.Email, tier = user.Tier } };
        }

        /// <summary>The shared "authenticated" response of login, OAuth and MFA. Pure. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static object Authenticated(Session session, string token, User user) => new
        {
            status = "authenticated",
            session_id = session.Id,
            refresh_token = session.RefreshToken,
            token,
            expires_in = AccessTokenSeconds,
            user = new { id = user.Id, email = user.Email, tier = user.Tier, status = user.Status }
        };

        /// <summary>Reads a rate-limit counter (0 when absent or expired). Touches: the cache. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private int ReadCounter(string key) =>
            _cache.TryGetValue(key, out CounterEntry entry) && entry.ExpiresAt > DateTimeOffset.UtcNow ? entry.Count : 0;

        /// <summary>
        /// Adds one to a rate-limit counter whose window starts at the first hit and does not slide. Returns the new
        /// count. Replaces the non-existent IMemoryCache.SetAsync (compile error). 2026-11-10, session
        /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the cache.
        /// </summary>
        private int IncrementCounter(string key, TimeSpan window)
        {
            lock (CounterGate)
            {
                if (!_cache.TryGetValue(key, out CounterEntry entry) || entry.ExpiresAt <= DateTimeOffset.UtcNow)
                    entry = new CounterEntry { ExpiresAt = DateTimeOffset.UtcNow.Add(window) };
                entry.Count++;
                _cache.Set(key, entry, entry.ExpiresAt);
                return entry.Count;
            }
        }

        /// <summary>A rate-limit counter and the fixed end of its window. Pure data.</summary>
        private sealed class CounterEntry
        {
            public int Count { get; set; }
            public DateTimeOffset ExpiresAt { get; set; }
        }

        /// <summary>Creates a session with a random refresh token valid 7 days. Touches: sessions.</summary>
        private async Task<Session> CreateSessionAsync(int userId, string ip, string deviceId)
        {
            var session = new Session
            {
                UserId = userId,
                RefreshToken = GenerateOpaqueToken(),
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(7),
                Ip = ip ?? string.Empty,
                DeviceId = deviceId ?? string.Empty
            };
            _db.Sessions.Add(session);
            await _db.SaveChangesAsync();
            return session;
        }

        /// <summary>
        /// Signs a 15-minute HS256 access token with user_id and tier (spec: "JWT: sign with HS256, include user_id and
        /// tier"). Updated 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): explicit "HS256" and a user_id claim,
        /// which <see cref="VerifyAccessTokenAsync"/> reads. Pure (uses the clock).
        /// </summary>
        private string GenerateJwtToken(int userId, string tier)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
                    new Claim("user_id", userId.ToString()),
                    new Claim("tier", tier ?? "free")
                }),
                Expires = DateTime.UtcNow.AddSeconds(AccessTokenSeconds),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(_jwtKey), SecurityAlgorithms.HmacSha256)
            };
            return tokenHandler.WriteToken(tokenHandler.CreateToken(tokenDescriptor));
        }

        /// <summary>32 random bytes from the OS CSPRNG, URL-safe base64. Used for refresh tokens, MFA challenge ids and OAuth states. Pure.</summary>
        private static string GenerateOpaqueToken() =>
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        /// <summary>
        /// A 6-digit email code from the OS CSPRNG. Updated 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): was
        /// System.Random, which is predictable, and its upper bound excluded 999999. Pure.
        /// </summary>
        private static string GenerateVerificationCode() => RandomNumberGenerator.GetInt32(100000, 1000000).ToString();

        /// <summary>Constant-time string comparison (CryptographicOperations.FixedTimeEquals); false when either is null. Pure.</summary>
        private static bool SecretEquals(string expected, string provided)
        {
            if (expected == null || provided == null) return false;
            return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(provided));
        }

        /// <summary>
        /// NIST SP 800-63B-4 password check: 15 to 64 characters, not on the bundled blocklist, not the user's email,
        /// name or the service name. No composition rules. Output: (true, null) or (false, reason). Pure.
        /// </summary>
        private (bool Success, string Reason) ValidatePassword(string password, string email, string name)
        {
            if (password.Length < 15) return (false, "too_short");
            if (password.Length > 64) return (false, "too_long");
            if (_commonPasswords.Contains(password)) return (false, "blocklisted");
            if (password.Equals(email, StringComparison.OrdinalIgnoreCase)) return (false, "blocklisted");
            if (!string.IsNullOrEmpty(name) && password.Equals(name, StringComparison.OrdinalIgnoreCase)) return (false, "blocklisted");
            if (password.Equals(_serviceName, StringComparison.OrdinalIgnoreCase)) return (false, "blocklisted");
            return (true, null);
        }

        /// <summary>Writes one audit_log row. Never receives passwords, codes or tokens. Touches: audit_log.</summary>
        private Task LogAuditAsync(int? actorId, string action, string resourceType, string resourceId, string oldValue, string newValue)
        {
            _db.AuditLogs.Add(new AuditLog
            {
                Timestamp = DateTime.UtcNow,
                ActorId = actorId,
                Action = action,
                ResourceType = resourceType,
                ResourceId = resourceId,
                OldValue = oldValue,
                NewValue = newValue
            });
            return _db.SaveChangesAsync();
        }

        /// <summary>Writes the why chain (flow and decision points, never secrets) to stdout; a real system sends it to a structured logger.</summary>
        private Task LogWhyChainAsync(string flow, string[] decisionPoints)
        {
            Console.WriteLine($"WHY_CHAIN: flow={flow}, decision_points=[{string.Join(",", decisionPoints)}]");
            return Task.CompletedTask;
        }
    }
}

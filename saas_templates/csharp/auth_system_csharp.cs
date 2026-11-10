// Auth system template (GEMINI_DISPATCH_MASTER_SPEC template #1): signup, email verification, login with optional
// TOTP MFA, OAuth callback, refresh and access-token verification, over EF Core, with bcrypt, HS256 JWTs and an
// in-memory rate-limit cache. Repaired 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP); see AuthService.
// Phase B.2 (2026-11-10, same session): every secret at rest is a SHA-256 (an HMAC-SHA256 since d270fa3) (refresh tokens, email codes, MFA challenge
// ids, OAuth states) and the OAuth callback exchanges the provider's code once through IOAuthProvider.ExchangeCodeAsync.
// spec d270fa3 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: keyed HMAC for stored secrets): those hashes are now
// HMAC-SHA256 under a server key (constructor secretKey, else the AUTH_SECRET_KEY environment variable, at least 32
// bytes; the constructor refuses to start without it), not a plain SHA-256. Touches also: the process environment.
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
                entity.Property(e => e.RefreshTokenHash).IsRequired().HasMaxLength(64);
                entity.HasIndex(e => e.RefreshTokenHash).IsUnique();
                entity.Ignore(e => e.RefreshToken);
                entity.Property(e => e.CreatedAt).IsRequired();
                entity.Property(e => e.ExpiresAt).IsRequired();
                entity.Property(e => e.Ip).IsRequired().HasMaxLength(45);
                entity.Property(e => e.DeviceId).IsRequired().HasMaxLength(255);
                entity.HasOne(e => e.User).WithMany().HasForeignKey(e => e.UserId);
            });

            modelBuilder.Entity<VerificationCode>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.CodeHash).IsRequired().HasMaxLength(64);
                entity.HasIndex(e => new { e.Type, e.CodeHash });
                entity.Property(e => e.CreatedAt).IsRequired();
                entity.Property(e => e.ExpiresAt).IsRequired();
                entity.Property(e => e.Type).IsRequired().HasMaxLength(20);
                // Attempts is a concurrency token (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, review finding
                // 4525101240): EF then writes "SET Attempts = k + 1 WHERE Id = ? AND Attempts = k", ONE conditional
                // write that fails (DbUpdateConcurrencyException) when another request counted a try first, so
                // concurrent wrong codes can no longer all write the same k + 1. Touches: the model only.
                entity.Property(e => e.Attempts).IsConcurrencyToken();
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

    /// <summary>
    /// A login session. The refresh token is stored only as its HMAC-SHA256 (lower-case hex) in RefreshTokenHash; the raw
    /// token exists only in memory (RefreshToken, not mapped) when the session is created, to be handed to the client
    /// once. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the raw token was stored and looked up as is (a
    /// database leak handed out every session; docs/specs/README.md "Secure by default"). Pure data.
    /// </summary>
    public class Session
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public string RefreshTokenHash { get; set; }
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
    /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, auth spec "Secrets at rest", AUTH-16): the value
    /// is stored only as CodeHash, the lower-case hex HMAC-SHA256 (AUTH_SECRET_KEY, spec d270fa3) of the code (<see cref="AuthService.HashSecret"/>); the
    /// column was Code, holding the code itself, so a database read handed out usable codes and OAuth states.
    /// </summary>
    public class VerificationCode
    {
        public int Id { get; set; }
        public int? UserId { get; set; }

        /// <summary>HMAC-SHA256 (lower-case hex) of the email code, MFA challenge id or OAuth state; never the value itself.</summary>
        public string CodeHash { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public string Type { get; set; }
        public User User { get; set; }

        /// <summary>
        /// Wrong email codes tried against this user's current code (verify_email only). At
        /// <see cref="AuthService.MaxEmailCodeAttempts"/> the code is deleted, so even the right code is code_invalid until
        /// a new code is sent (a new row starts at 0). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.3,
        /// auth spec flow 2 "Attempts"). Pure data.
        /// </summary>
        public int Attempts { get; set; }
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

    /// <summary>
    /// Who the OAuth provider says signed in, from its token endpoint and user-info response: the provider's own user
    /// id, the email and whether the provider verified it. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase
    /// B.2, AUTH-16). Pure data.
    /// </summary>
    public class OAuthIdentity
    {
        public string ProviderUserId { get; set; }
        public string Email { get; set; }
        public bool EmailVerified { get; set; }
    }

    /// <summary>
    /// The injected OAuth provider client. ExchangeCodeAsync redeems the authorization code at the provider's token
    /// endpoint (server to server, with the client secret) and reads the signed-in identity; it returns null when the
    /// provider refuses the code. The code is never an identity by itself, and it is exchanged once: providers accept
    /// an authorization code a single time. In: the provider name and the code. Out: the identity or null. Changed
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, auth spec "Secrets at rest"): replaces
    /// GetEmailFromCodeAsync + IsEmailVerifiedAsync, which redeemed the same single-use code twice. Touches: the
    /// provider (network) in production.
    /// </summary>
    public interface IOAuthProvider
    {
        Task<OAuthIdentity> ExchangeCodeAsync(string provider, string code);
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
        /// <summary>Wrong email verification codes for one user before the current code is invalidated (Phase B.3, 2026-11-10).</summary>
        public const int MaxEmailCodeAttempts = 5;
        /// <summary>resend_verification requests accepted per email per hour (AUTH-18, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).</summary>
        public const int MaxResendsPerHour = 3;
        /// <summary>Life of a resent verification code in minutes (AUTH-18, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).</summary>
        public const int ResendCodeMinutes = 10;
        /// <summary>Access-token lifetime in seconds (15 minutes).</summary>
        public const int AccessTokenSeconds = 900;
        /// <summary>Bucket used when a caller does not pass the client IP to <see cref="SignupAsync"/>: all such signups share one limit (fail closed).</summary>
        public const string UnknownIp = "unknown";

        private readonly AuthDbContext _db;
        private readonly IEmailSender _emailSender;
        private readonly IOAuthProvider _oauthProvider;
        private readonly IMemoryCache _cache;
        private readonly byte[] _jwtKey;
        /// <summary>HMAC key for stored secrets (spec d270fa3, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).</summary>
        private readonly byte[] _secretKey;
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
        /// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets. secretKey (from
        /// configuration like the JWT secret; null means the AUTH_SECRET_KEY environment variable) keys the
        /// HMAC-SHA256 every stored secret is kept as. Throws ArgumentException when it is missing or shorter than 32
        /// bytes, so the service refuses to start without it. Touches also: the process environment (read).
        /// </summary>
        public AuthService(AuthDbContext db, IEmailSender emailSender, IOAuthProvider oauthProvider, IMemoryCache cache, string jwtSecret, string secretKey)
        {
            secretKey ??= Environment.GetEnvironmentVariable("AUTH_SECRET_KEY");
            if (string.IsNullOrEmpty(secretKey) || Encoding.UTF8.GetByteCount(secretKey) < 32)
                throw new ArgumentException("AUTH_SECRET_KEY must be set and at least 32 bytes.", nameof(secretKey));
            _secretKey = Encoding.UTF8.GetBytes(secretKey);
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
        /// Changed the same day (Phase B.2, AUTH-16): the code is stored only as its HMAC-SHA256.
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
                CodeHash = HashSecret(code), // only the hash is stored (AUTH-16, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
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
        /// the user, constant-time comparison, wrong vs expired codes reported apart. Changed the same day (Phase B.2,
        /// AUTH-16): the stored value is the code's HMAC-SHA256, compared in constant time with the hash of the code given.
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.3, flow 2 "Attempts"): a wrong code adds one to
        /// the attempts of the user's current code(s); the 5th wrong code deletes them, so further tries, even with the
        /// right code, get code_invalid until a new code is sent (a 6-digit code must not be guessable by retrying).
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (review finding 4525101240, CWE-307): every try is
        /// COUNTED FIRST, in one conditional database write per code (<see cref="TryCountEmailCodeAttemptAsync"/>),
        /// and the code is compared only when that write succeeded, as Go, JavaScript and TypeScript do. Before, the
        /// count was read, compared and written back as an absolute value, so N concurrent wrong guesses all wrote
        /// Attempts + 1 and a batch cost one attempt. A code with 5 counted tries is spent: it is never compared again
        /// and a wrong 5th try deletes it. The right code on a counted 5th try still verifies; an expired code on a
        /// counted try is code_expired (the try counts, as in Go). Answers are unchanged (AUTH-17).
        /// Touches: users, verification_codes, audit_log.
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
            var providedHash = code == null ? null : HashSecret(code);
            // Review finding 4525101240 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): count the try in the database
            // first; compare only a code whose conditional increment succeeded.
            VerificationCode verification = null;
            foreach (var current in candidates)
            {
                if (!await TryCountEmailCodeAttemptAsync(current))
                    continue; // spent (5 counted tries), or deleted meanwhile: never compared
                if (SecretEquals(current.CodeHash, providedHash))
                {
                    verification = current;
                    break;
                }
                if (current.Attempts >= MaxEmailCodeAttempts)
                    await RemoveSpentEmailCodeAsync(current);
            }
            if (verification == null)
                return new { error = "code_invalid" };
            if (verification.ExpiresAt <= DateTime.UtcNow)
                return new { error = "code_expired" };

            user.EmailVerifiedAt = DateTime.UtcNow;
            user.Status = "verified";
            _db.VerificationCodes.Remove(verification);
            for (var round = 0; ; round++)
            {
                try
                {
                    await _db.SaveChangesAsync();
                    break;
                }
                catch (DbUpdateConcurrencyException) when (round < MaxEmailCodeAttempts)
                {
                    // A racing wrong guess counted a try on this row after ours. Our try was counted and matched, so
                    // finish: reload the row (it may be gone) and delete it again; the user's update is still pending.
                    var entry = _db.Entry(verification);
                    await entry.ReloadAsync();
                    if (entry.State != EntityState.Detached) _db.VerificationCodes.Remove(verification);
                }
            }

            await LogAuditAsync(user.Id, "email_verified", "user", user.Id.ToString(), null, null);
            await LogWhyChainAsync("verify_email", new[] { "code_valid", "user_unverified" });

            return new { status = "verified", user_id = user.Id, message = "ready to login" };
        }

        /// <summary>
        /// Flow 2b, resend_verification. At most <see cref="MaxResendsPerHour"/> requests per email per hour are accepted
        /// (the check and the count are one step under the counter lock, so concurrent requests cannot pass it); a 4th
        /// within the hour is {error: "too_many_requests"} (the spec's 429) and sends nothing. For an unverified user it
        /// deletes the user's email codes, stores a new 6-digit code (Attempts 0, its HMAC-SHA256, valid
        /// <see cref="ResendCodeMinutes"/> minutes) and emails it. An unknown or already verified email gets the same
        /// {status: "sent"} (the spec's 202) and nothing is sent, so the answer never says whether an account exists;
        /// those requests count toward the limit too. In: the email (trimmed and lower-cased, as signup stores it).
        /// Out: {status: "sent"} or {error: "too_many_requests"}. Why: AUTH-18 (auth spec flow 2b, commit 0eb5a4e):
        /// after 5 wrong codes (AUTH-17) nothing could issue a new code, so anyone who knew an email could block its
        /// verification. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// Touches: users (read), verification_codes, audit_log, the cache, the email sender (network in production).
        /// </summary>
        public async Task<object> ResendVerificationAsync(string email)
        {
            var normalizedEmail = (email ?? string.Empty).Trim().ToLowerInvariant();
            if (!TryTakeCounter($"resend_email:{normalizedEmail}", MaxResendsPerHour, TimeSpan.FromHours(1)))
            {
                await LogWhyChainAsync("resend_verification", new[] { "rate_limit_email_1h:failed" });
                return new { error = "too_many_requests" };
            }
            var sent = new { status = "sent" };
            var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == normalizedEmail);
            if (user == null || user.EmailVerifiedAt.HasValue)
            {
                // Unknown or already verified: the same answer as a real resend, and no email (no account enumeration).
                await LogWhyChainAsync("resend_verification", new[] { "rate_limit_email_1h", "user_unverified:failed" });
                return sent;
            }
            var old = await _db.VerificationCodes.Where(v => v.UserId == user.Id && v.Type == "email").ToListAsync();
            _db.VerificationCodes.RemoveRange(old);
            var code = GenerateVerificationCode();
            _db.VerificationCodes.Add(new VerificationCode
            {
                UserId = user.Id,
                CodeHash = HashSecret(code),
                Type = "email",
                Attempts = 0,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddMinutes(ResendCodeMinutes)
            });
            await _db.SaveChangesAsync();

            await _emailSender.SendVerificationEmailAsync(normalizedEmail, code);
            await LogAuditAsync(user.Id, "verification_resent", "user", user.Id.ToString(), null, null);
            await LogWhyChainAsync("resend_verification", new[] { "rate_limit_email_1h", "user_unverified" });
            return sent;
        }

        /// <summary>
        /// Counts one try against an email code in ONE conditional database write: Attempts is a concurrency token, so
        /// EF writes "SET Attempts = k + 1 WHERE Id = ? AND Attempts = k" with k read below 5. When another request
        /// counted first the write changes no row (DbUpdateConcurrencyException): the row is re-read from the database
        /// and the count is tried again from the new value. Attempts only grow, so this loop ends within 5 rounds.
        /// In: the tracked code row. Out: true when this try was counted (the caller may compare the code); false when
        /// the code is spent (5 counted tries) or was deleted.
        /// Why: review finding 4525101240 (CWE-307: concurrent wrong guesses all wrote the same Attempts + 1); auth
        /// spec flow 2 "Attempts", AUTH-17. EF InMemory, which the tests use, has no ExecuteUpdateAsync, so the
        /// conditional write is EF's own concurrency check. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// Touches: verification_codes.
        /// </summary>
        private async Task<bool> TryCountEmailCodeAttemptAsync(VerificationCode row)
        {
            var entry = _db.Entry(row);
            for (var round = 0; round <= MaxEmailCodeAttempts; round++)
            {
                if (row.Attempts >= MaxEmailCodeAttempts) return false;
                row.Attempts++;
                try
                {
                    await _db.SaveChangesAsync();
                    return true;
                }
                catch (DbUpdateConcurrencyException)
                {
                    await entry.ReloadAsync();
                    if (entry.State == EntityState.Detached) return false;
                }
            }
            return false;
        }

        /// <summary>
        /// Deletes an email code that has 5 counted tries (it is spent). Another request may have deleted it first;
        /// that is the same outcome, so a concurrency failure only detaches the row.
        /// In: the tracked code row. Out: nothing. Why: review finding 4525101240; auth spec flow 2 "Attempts" (a spent
        /// code is gone until a new code is sent). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// Touches: verification_codes.
        /// </summary>
        private async Task RemoveSpentEmailCodeAsync(VerificationCode row)
        {
            _db.VerificationCodes.Remove(row);
            try
            {
                await _db.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                _db.Entry(row).State = EntityState.Detached;
            }
        }

        /// <summary>
        /// Flow 3, login. Gates: rate_limit (5 failures per 15 minutes per ip+email, checked first so a locked pair
        /// cannot keep guessing), user_exists_and_verified (status 'verified', as in the Go template),
        /// password_correct (bcrypt), mfa_gate. With MFA on, returns {status:"mfa_required", challenge_id} (a random
        /// id valid 5 minutes, stored only as its HMAC-SHA256); otherwise creates a session and returns {status:
        /// "authenticated", session_id, token, refresh_token, expires_in, user} (AUTH-16: the refresh_token is the
        /// value token_refresh takes). Every failure answers invalid_credentials, so accounts cannot be enumerated.
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): the challenge id is hashed at rest. The
        /// challenge id alone is not a credential (the TOTP code is still needed), but it is a bearer handle to a
        /// half-finished login, so it is kept like the other secrets.
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
                    CodeHash = HashSecret(challengeId),
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
        /// Changed the same day (Phase B.2, auth spec "Secrets at rest"): only the state's HMAC-SHA256 is stored.
        /// Touches: verification_codes.
        /// </summary>
        public async Task<string> CreateOAuthStateAsync()
        {
            var state = GenerateOpaqueToken();
            _db.VerificationCodes.Add(new VerificationCode
            {
                UserId = null,
                CodeHash = HashSecret(state),
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
        /// users are refused, the audit actor is the user. Changed the same day (Phase B.2, AUTH-16 and "Secrets at
        /// rest"): the state is looked up by its HMAC-SHA256 (single use, 10 minutes); the code is exchanged ONCE through
        /// the injected client (<see cref="IOAuthProvider.ExchangeCodeAsync"/>), never treated as an identity, and a
        /// refused exchange is {error: "oauth_exchange_failed"}; the answer carries refresh_token.
        /// Touches: users, sessions, verification_codes, audit_log, the OAuth provider (network in production).
        /// </summary>
        public async Task<object> OAuthCallbackAsync(string provider, string code, string state)
        {
            if (string.IsNullOrEmpty(state))
                return new { error = "invalid_state" };
            var stateHash = HashSecret(state);
            var stateVerification = await _db.VerificationCodes
                .FirstOrDefaultAsync(v => v.Type == "oauth_state" && v.CodeHash == stateHash && v.ExpiresAt > DateTime.UtcNow);
            if (stateVerification == null)
                return new { error = "invalid_state" };
            _db.VerificationCodes.Remove(stateVerification);
            await _db.SaveChangesAsync();

            if (string.IsNullOrEmpty(code))
                return new { error = "oauth_exchange_failed" };
            var identity = await _oauthProvider.ExchangeCodeAsync(provider, code);
            if (identity == null)
                return new { error = "oauth_exchange_failed" };
            if (!identity.EmailVerified || string.IsNullOrWhiteSpace(identity.Email))
                return new { error = "email_not_verified_by_provider" };

            var normalizedEmail = identity.Email.Trim().ToLowerInvariant();
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
        /// drift window narrowed from ±2 steps, attempt limit added. Changed the same day (Phase B.2, AUTH-16): the
        /// challenge is found by its id's HMAC-SHA256, and the answer carries refresh_token. Touches: users, sessions,
        /// verification_codes, audit_log, the cache.
        /// </summary>
        public async Task<object> MfaChallengeAsync(string challengeId, string totpCode)
        {
            if (string.IsNullOrEmpty(challengeId))
                return new { error = "invalid_challenge" };
            var challengeHash = HashSecret(challengeId);
            var challenge = await _db.VerificationCodes
                .FirstOrDefaultAsync(v => v.Type == "mfa" && v.CodeHash == challengeHash && v.ExpiresAt > DateTime.UtcNow);
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
            // looked up by the token's HMAC-SHA256: equal hashes leak nothing about the token (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
            var hash = HashRefreshToken(refreshToken);
            var session = await _db.Sessions
                .Include(s => s.User)
                .FirstOrDefaultAsync(s => s.RefreshTokenHash == hash && s.ExpiresAt > DateTime.UtcNow);
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

        /// <summary>
        /// The shared "authenticated" response of login, OAuth and MFA: status, session_id, refresh_token (the raw
        /// token, handed out this once; token_refresh takes it), token, expires_in and the user. Pure. 2026-11-10,
        /// session session_012zDydZCZ4AChqhEZ4oVtaP (AUTH-16: every flow that creates a session returns refresh_token).
        /// </summary>
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

        /// <summary>
        /// Adds one to a rate-limit counter only while it is below max, in one step under the counter lock, so
        /// concurrent callers cannot pass the limit. The window starts at the first hit and does not slide.
        /// In: the key, the max and the window. Out: true when the hit was counted (allowed); false when the window was
        /// already at max (refused, not counted). Why: AUTH-18 (3 resends per email per hour). 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the cache.
        /// </summary>
        private bool TryTakeCounter(string key, int max, TimeSpan window)
        {
            lock (CounterGate)
            {
                if (!_cache.TryGetValue(key, out CounterEntry entry) || entry.ExpiresAt <= DateTimeOffset.UtcNow)
                    entry = new CounterEntry { ExpiresAt = DateTimeOffset.UtcNow.Add(window) };
                if (entry.Count >= max) return false;
                entry.Count++;
                _cache.Set(key, entry, entry.ExpiresAt);
                return true;
            }
        }

        /// <summary>A rate-limit counter and the fixed end of its window. Pure data.</summary>
        private sealed class CounterEntry
        {
            public int Count { get; set; }
            public DateTimeOffset ExpiresAt { get; set; }
        }

        /// <summary>
        /// HMAC-SHA256 of a refresh token under the service key, as lower-case hex: what the sessions table stores and
        /// is searched by. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Pure. Same as <see cref="HashSecret"/>.
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec d270fa3: keyed HMAC for stored secrets): an
        /// instance method now, since the hash is keyed; it was a static plain SHA-256.
        /// </summary>
        public string HashRefreshToken(string refreshToken) => HashSecret(refreshToken);

        /// <summary>
        /// HMAC-SHA256(secretKey, secret) as lower-case hex for a secret (refresh token, email code, MFA challenge id,
        /// OAuth state): the only form in which any of them is stored (auth spec "Secrets at rest", AUTH-16). In: the
        /// secret. Out: 64 hex characters. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2).
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec d270fa3: keyed HMAC for stored secrets): it was a
        /// static plain SHA-256, which a leaked table of 6-digit codes gives up to brute force. Pure.
        /// </summary>
        public string HashSecret(string secret) =>
            Convert.ToHexString(HMACSHA256.HashData(_secretKey, Encoding.UTF8.GetBytes(secret))).ToLowerInvariant();

        /// <summary>
        /// Creates a session with a random refresh token valid 7 days; only its hash is stored, the raw token is on the
        /// returned object for the response. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: sessions.
        /// </summary>
        private async Task<Session> CreateSessionAsync(int userId, string ip, string deviceId)
        {
            var raw = GenerateOpaqueToken();
            var session = new Session
            {
                UserId = userId,
                RefreshToken = raw,
                RefreshTokenHash = HashRefreshToken(raw),
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
        /// Checks run too_short, too_long, blocklisted and the first failure wins (AUTH-03, spec amended 2026-11-10).
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: length counts Unicode characters (runes), not UTF-16
        /// code units, so eight emoji are 8 characters (too_short), not 16.
        /// </summary>
        private (bool Success, string Reason) ValidatePassword(string password, string email, string name)
        {
            var length = password.EnumerateRunes().Count();
            if (length < 15) return (false, "too_short");
            if (length > 64) return (false, "too_long");
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

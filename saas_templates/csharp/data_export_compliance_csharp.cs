// Data export & compliance template (TIER_2_MASTER_SPEC system 3, GDPR/CCPA): a user exports their data as JSON or
// CSV (built in the background, stored, offered through a 7-day signed download link and emailed), requests account
// deletion (30-day grace period, confirmed through an emailed token, cancellable), and admins list both kinds of
// request. Every request and outcome is written to audit_logs, which the cascade delete keeps.
//
// Rewritten 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP). The suite did not compile: the context had no
// AuditLogs set, Channel and the test's Startup/Program did not exist, and the controllers talked to SQL Server on
// localhost through System.Data.SqlClient. Behind that: every request ran as one hard-coded user id, the admin
// endpoints had no authorisation, anyone could read or cancel anyone's request by id, the "confirmation token" was
// base64 of the deletion id (forgeable), the cascade built SQL from table names at run time, and the queue completed
// its own writer before the first item so nothing was ever processed.
// Now: EF Core (SQLite when ConnectionStrings:Compliance is set, otherwise an in-memory database for development);
// identity only from a verified HS256 bearer token (Auth:JwtSecret, the auth template's token format, "sub" = user id,
// "role" = admin for admin endpoints); owners only on their own requests; confirmation tokens are 32 random bytes
// stored as SHA-256 and compared in constant time; downloads are HMAC-signed URLs checked in constant time with an
// expiry; user data, file storage and email sit behind IUserDataStore, IExportStorage and IComplianceMailer, with
// in-memory development implementations so a fresh copy runs and its tests make no network calls.
// 2026-11-10 (same session, CodeRabbit review on PR 19): a completed deletion also deletes the user's export files and
// export_requests rows first (a failed cleanup leaves the deletion approved, to be retried), and a download link is
// refused once its export request or file is gone, so a deleted user's unexpired link no longer works.
// 2026-11-10 (same session, spec amendment EXPORT-05/12/13/14): a statutory reason (gdpr_request,
// gdpr_right_to_be_forgotten) has no grace period and confirm() runs the cascade at once; the confirmation token
// expires after 24 h; the cascade logs 'user_deleted_cascade' then calls the injected audit eraser's erase_subject LAST,
// and deletion_requests.user_id is set NULL on completion; time comes from ComplianceClock.
// Touches: the compliance database; the user data store (reads, and deletes on a completed deletion); export storage;
// email (through IComplianceMailer: network in production).
#nullable enable
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using STJ = System.Text.Json.Serialization;

namespace ComplianceModule
{
    #region DTOs (snake_case on the wire, for System.Text.Json and Newtonsoft alike)

    /// <summary>Body of POST /compliance/export: format "json" or "csv". Pure data.</summary>
    public class ExportRequestDto
    {
        [Required, JsonProperty("format"), STJ.JsonPropertyName("format")]
        public string Format { get; set; } = "";
    }

    /// <summary>Body of POST /compliance/delete: one of the spec's reasons. Pure data.</summary>
    public class DeletionRequestDto
    {
        [Required, JsonProperty("reason"), STJ.JsonPropertyName("reason")]
        public string Reason { get; set; } = "";
    }

    /// <summary>Body of POST /compliance/delete/{id}/confirm: the token from the confirmation email. Pure data.</summary>
    public class ConfirmDeletionDto
    {
        [Required, JsonProperty("confirmation_token"), STJ.JsonPropertyName("confirmation_token")]
        public string ConfirmationToken { get; set; } = "";
    }

    /// <summary>Answer to an export request. Pure data.</summary>
    public class ExportResponse
    {
        [JsonProperty("success"), STJ.JsonPropertyName("success")] public bool Success { get; set; }
        [JsonProperty("export_id"), STJ.JsonPropertyName("export_id")] public string? ExportId { get; set; }
        [JsonProperty("status"), STJ.JsonPropertyName("status")] public string? Status { get; set; }
        [JsonProperty("format"), STJ.JsonPropertyName("format")] public string? Format { get; set; }
        [JsonProperty("will_email_at"), STJ.JsonPropertyName("will_email_at")] public string? WillEmailAt { get; set; }
    }

    /// <summary>Answer to GET /compliance/exports/{id}. Pure data.</summary>
    public class ExportStatusResponse
    {
        [JsonProperty("export_id"), STJ.JsonPropertyName("export_id")] public string? ExportId { get; set; }
        [JsonProperty("status"), STJ.JsonPropertyName("status")] public string? Status { get; set; }
        [JsonProperty("file_url"), STJ.JsonPropertyName("file_url")] public string? FileUrl { get; set; }
        [JsonProperty("expires_at"), STJ.JsonPropertyName("expires_at")] public string? ExpiresAt { get; set; }
        [JsonProperty("requested_at"), STJ.JsonPropertyName("requested_at")] public string? RequestedAt { get; set; }
    }

    /// <summary>Answer to a deletion request. Pure data.</summary>
    public class DeletionResponse
    {
        [JsonProperty("success"), STJ.JsonPropertyName("success")] public bool Success { get; set; }
        [JsonProperty("deletion_id"), STJ.JsonPropertyName("deletion_id")] public string? DeletionId { get; set; }
        [JsonProperty("status"), STJ.JsonPropertyName("status")] public string? Status { get; set; }
        [JsonProperty("will_delete_at"), STJ.JsonPropertyName("will_delete_at")] public string? WillDeleteAt { get; set; }
    }

    /// <summary>Answer to a deletion confirmation. Pure data.</summary>
    public class DeletionConfirmationResponse
    {
        [JsonProperty("success"), STJ.JsonPropertyName("success")] public bool Success { get; set; }
        [JsonProperty("deletion_scheduled_for"), STJ.JsonPropertyName("deletion_scheduled_for")] public string? DeletionScheduledFor { get; set; }

        /// <summary>The deletion's status after confirm: 'approved' (grace period running) or, for a statutory reason, 'completed'. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        [JsonProperty("status"), STJ.JsonPropertyName("status")] public string? Status { get; set; }
    }

    /// <summary>Admin list of export requests. Pure data.</summary>
    public class AdminExportResponse
    {
        [JsonProperty("exports"), STJ.JsonPropertyName("exports")] public List<ExportRequest> Exports { get; set; } = new();
        [JsonProperty("total"), STJ.JsonPropertyName("total")] public int Total { get; set; }
    }

    /// <summary>Admin list of deletion requests. Pure data.</summary>
    public class AdminDeletionResponse
    {
        [JsonProperty("deletions"), STJ.JsonPropertyName("deletions")] public List<DeletionRequest> Deletions { get; set; } = new();
        [JsonProperty("total"), STJ.JsonPropertyName("total")] public int Total { get; set; }
    }

    #endregion

    #region Entities and DbContext

    /// <summary>
    /// export_requests row. Status: pending, completed, failed. StorageKey is internal and never serialised.
    /// Sequence orders lists by insertion. Pure data.
    /// </summary>
    public class ExportRequest
    {
        [JsonProperty("id"), STJ.JsonPropertyName("id")] public Guid Id { get; set; }
        [JsonProperty("user_id"), STJ.JsonPropertyName("user_id")] public Guid UserId { get; set; }
        [JsonProperty("requested_at"), STJ.JsonPropertyName("requested_at")] public DateTime RequestedAt { get; set; }
        [JsonProperty("status"), STJ.JsonPropertyName("status")] public string Status { get; set; } = "pending";
        [JsonProperty("format"), STJ.JsonPropertyName("format")] public string Format { get; set; } = "json";
        [JsonProperty("file_url"), STJ.JsonPropertyName("file_url")] public string? FileUrl { get; set; }
        [JsonProperty("completed_at"), STJ.JsonPropertyName("completed_at")] public DateTime? CompletedAt { get; set; }
        [JsonProperty("expires_at"), STJ.JsonPropertyName("expires_at")] public DateTime? ExpiresAt { get; set; }
        [JsonIgnore, STJ.JsonIgnore] public string? StorageKey { get; set; }
        [JsonIgnore, STJ.JsonIgnore] public long Sequence { get; set; }
    }

    /// <summary>
    /// deletion_requests row. Status: pending (awaiting email confirmation), approved (confirmed, waiting out the grace
    /// period), cancelled, completed, failed. The confirmation token is stored only as its SHA-256 hash, valid until
    /// TokenExpiresAt (24 h), and never serialised. UserId is set NULL when the deletion completes (EXPORT-13), so the
    /// row cannot re-identify erased audit entries. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: nullable
    /// UserId, TokenExpiresAt. Pure data.
    /// </summary>
    public class DeletionRequest
    {
        [JsonProperty("id"), STJ.JsonPropertyName("id")] public Guid Id { get; set; }
        [JsonProperty("user_id"), STJ.JsonPropertyName("user_id")] public Guid? UserId { get; set; }
        [JsonProperty("requested_at"), STJ.JsonPropertyName("requested_at")] public DateTime RequestedAt { get; set; }
        [JsonProperty("status"), STJ.JsonPropertyName("status")] public string Status { get; set; } = "pending";
        [JsonProperty("reason"), STJ.JsonPropertyName("reason")] public string Reason { get; set; } = "";
        [JsonProperty("scheduled_for"), STJ.JsonPropertyName("scheduled_for")] public DateTime ScheduledFor { get; set; }
        [JsonProperty("confirmed_at"), STJ.JsonPropertyName("confirmed_at")] public DateTime? ConfirmedAt { get; set; }
        [JsonProperty("deleted_at"), STJ.JsonPropertyName("deleted_at")] public DateTime? DeletedAt { get; set; }
        [JsonIgnore, STJ.JsonIgnore] public byte[]? ConfirmationTokenHash { get; set; }
        [JsonIgnore, STJ.JsonIgnore] public DateTime? TokenExpiresAt { get; set; }
        [JsonIgnore, STJ.JsonIgnore] public long Sequence { get; set; }
    }

    /// <summary>
    /// audit_logs row: kept when a user is deleted (legal requirement, EXPORT-08). When the user's deletion completes,
    /// the audit eraser removes the link to the person: UserId becomes Guid.Empty, ActorId null, PersonalErased true;
    /// the event itself stays. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-13). Pure data.
    /// </summary>
    public class AuditLog
    {
        public Guid Id { get; set; }
        public Guid UserId { get; set; }
        public bool PersonalErased { get; set; }
        public Guid? ActorId { get; set; }
        public string Action { get; set; } = "";
        public string Details { get; set; } = "{}";
        public DateTime Timestamp { get; set; }
        public long Sequence { get; set; }
    }

    /// <summary>
    /// EF Core context for the compliance tables. Rewritten 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): adds
    /// the AuditLogs set the code used, drops SQL Server-only defaults (NEWID, GETUTCDATE) so it runs on SQLite and
    /// in memory. Touches: the compliance database.
    /// </summary>
    public class ComplianceDbContext : DbContext
    {
        public ComplianceDbContext(DbContextOptions<ComplianceDbContext> options) : base(options) { }

        public DbSet<ExportRequest> ExportRequests => Set<ExportRequest>();
        public DbSet<DeletionRequest> DeletionRequests => Set<DeletionRequest>();
        public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

        /// <summary>Maps the entities to their tables and indexes. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the EF model only.</summary>
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<ExportRequest>(entity =>
            {
                entity.ToTable("export_requests");
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Status).HasMaxLength(20).IsRequired();
                entity.Property(e => e.Format).HasMaxLength(10).IsRequired();
                entity.HasIndex(e => e.UserId);
            });
            modelBuilder.Entity<DeletionRequest>(entity =>
            {
                entity.ToTable("deletion_requests");
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Status).HasMaxLength(20).IsRequired();
                entity.Property(e => e.Reason).HasMaxLength(50).IsRequired();
                entity.HasIndex(e => e.UserId);
            });
            modelBuilder.Entity<AuditLog>(entity =>
            {
                entity.ToTable("audit_logs");
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Action).HasMaxLength(100).IsRequired();
                entity.HasIndex(e => e.UserId);
            });
        }
    }

    #endregion

    #region External services (interfaces and development implementations)

    /// <summary>
    /// Everything this system reads about a user and the cascade delete. Implement it over your own tables (users,
    /// sessions, activity, files, preferences, transactions, api_keys); never over audit_logs, which must survive.
    /// Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP) in place of raw SQL built from table names and of
    /// hard-coded sample data. Touches: your user data.
    /// </summary>
    public interface IUserDataStore
    {
        /// <summary>The user's email address, or null when the user does not exist.</summary>
        Task<string?> GetEmailAsync(Guid userId, CancellationToken ct);

        /// <summary>The export document: profile, sessions, activity, files (metadata only), preferences, transactions.</summary>
        Task<JObject> CollectAsync(Guid userId, CancellationToken ct);

        /// <summary>Deletes every row that belongs to the user, except audit logs.</summary>
        Task DeleteUserAsync(Guid userId, CancellationToken ct);
    }

    /// <summary>
    /// Development / test implementation of <see cref="IUserDataStore"/>: users seeded in memory with
    /// <see cref="Seed"/>. Not for production. Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP).
    /// Touches: process memory.
    /// </summary>
    public class InMemoryUserDataStore : IUserDataStore
    {
        private readonly ConcurrentDictionary<Guid, JObject> _users = new();

        /// <summary>Stores a user's data document; it must contain profile.email. Touches: process memory.</summary>
        public void Seed(Guid userId, JObject data) => _users[userId] = (JObject)data.DeepClone();

        /// <summary>True while the user's data exists. Touches: process memory.</summary>
        public bool Exists(Guid userId) => _users.ContainsKey(userId);

        /// <summary>Implements the interface member of the same name; see the class summary. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public Task<string?> GetEmailAsync(Guid userId, CancellationToken ct) =>
            Task.FromResult(_users.TryGetValue(userId, out var d) ? (string?)d.SelectToken("profile.email")?.ToString() : null);

        /// <summary>Implements the interface member of the same name; see the class summary. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public Task<JObject> CollectAsync(Guid userId, CancellationToken ct) =>
            _users.TryGetValue(userId, out var d)
                ? Task.FromResult((JObject)d.DeepClone())
                : Task.FromException<JObject>(new KeyNotFoundException("User not found"));

        /// <summary>Implements the interface member of the same name; see the class summary. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public Task DeleteUserAsync(Guid userId, CancellationToken ct)
        {
            _users.TryRemove(userId, out _);
            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Where export files live and how download links are made. Production: S3 with server-side encryption and a
    /// presigned GET URL limited to 7 days (download only). Added 2026-11-10 (session
    /// session_012zDydZCZ4AChqhEZ4oVtaP). DeleteAsync added the same day (CodeRabbit review on PR 19) so an account
    /// deletion removes the user's export files. Touches: file storage.
    /// </summary>
    public interface IExportStorage
    {
        Task PutAsync(string key, byte[] content, string contentType, CancellationToken ct);
        Task<(byte[] Content, string ContentType)?> GetAsync(string key, CancellationToken ct);

        /// <summary>
        /// Deletes the file stored under the key; a key that holds nothing is not an error (idempotent, so a retried
        /// deletion can run it again). Throws when the storage cannot delete it, which keeps the account deletion
        /// retryable. Production (S3): DeleteObject, after which the object's presigned URLs answer 404. Added
        /// 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review on PR 19). Touches: file storage.
        /// </summary>
        Task DeleteAsync(string key, CancellationToken ct);
        string CreateDownloadUrl(string key, DateTimeOffset expiresAt);
        bool VerifyDownload(string key, long expiresUnix, string? signature, DateTimeOffset now);
    }

    /// <summary>
    /// Development storage: files in memory, served by GET /compliance/downloads/{key}. Links are
    /// HMAC-SHA256(key, "storageKey:expires") with the key from Compliance:DownloadSigningKey (at least 32 bytes) or a
    /// random per-process key; they are checked in constant time and refused after their expiry. Added 2026-11-10
    /// (session session_012zDydZCZ4AChqhEZ4oVtaP) in place of a fake S3 URL with "Signature=sig". Touches: process
    /// memory.
    /// </summary>
    public class InMemoryExportStorage : IExportStorage
    {
        private readonly ConcurrentDictionary<string, (byte[], string)> _files = new();
        private readonly byte[] _signingKey;
        private readonly string _baseUrl;

        public InMemoryExportStorage(IConfiguration config)
        {
            var key = config["Compliance:DownloadSigningKey"];
            if (!string.IsNullOrEmpty(key) && Encoding.UTF8.GetByteCount(key) < 32)
                throw new ArgumentException("Compliance:DownloadSigningKey must be at least 32 bytes");
            _signingKey = string.IsNullOrEmpty(key) ? RandomNumberGenerator.GetBytes(32) : Encoding.UTF8.GetBytes(key);
            _baseUrl = config["App:BaseUrl"] ?? "";
        }

        /// <summary>Implements the interface member of the same name; see the class summary. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public Task PutAsync(string key, byte[] content, string contentType, CancellationToken ct)
        {
            _files[key] = (content, contentType);
            return Task.CompletedTask;
        }

        /// <summary>Implements the interface member of the same name; see the class summary. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public Task<(byte[] Content, string ContentType)?> GetAsync(string key, CancellationToken ct) =>
            Task.FromResult(_files.TryGetValue(key, out var f) ? ((byte[], string)?)f : null);

        /// <summary>
        /// Removes the file under the key from memory; a missing key is a no-op. Input: the storage key. Added
        /// 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review on PR 19: a deleted user's export
        /// stayed downloadable). Touches: process memory.
        /// </summary>
        public Task DeleteAsync(string key, CancellationToken ct)
        {
            _files.TryRemove(key, out _);
            return Task.CompletedTask;
        }

        /// <summary>Implements the interface member of the same name; see the class summary. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public string CreateDownloadUrl(string key, DateTimeOffset expiresAt)
        {
            var exp = expiresAt.ToUnixTimeSeconds();
            // Keys are built from GUIDs and a whitelisted extension ("exports/{user}/{id}.csv"), so they are URL-safe as they
            // are; escaping the slashes would change the key the download route sees and break the signature.
            return $"{_baseUrl}/compliance/downloads/{key}?expires={exp}&signature={Sign(key, exp)}";
        }

        /// <summary>Implements the interface member of the same name; see the class summary. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public bool VerifyDownload(string key, long expiresUnix, string? signature, DateTimeOffset now)
        {
            if (string.IsNullOrEmpty(signature) || now.ToUnixTimeSeconds() > expiresUnix) return false;
            var expected = Encoding.ASCII.GetBytes(Sign(key, expiresUnix));
            var provided = Encoding.ASCII.GetBytes(signature);
            return expected.Length == provided.Length && CryptographicOperations.FixedTimeEquals(expected, provided);
        }

        /// <summary>base64url HMAC-SHA256 of "key:expires". Pure.</summary>
        private string Sign(string key, long expires)
        {
            using var hmac = new HMACSHA256(_signingKey);
            var mac = hmac.ComputeHash(Encoding.UTF8.GetBytes($"{key}:{expires}"));
            return Convert.ToBase64String(mac).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
    }

    /// <summary>The two emails this system sends. Production: your mail provider. Touches: email (network).</summary>
    public interface IComplianceMailer
    {
        Task SendExportReadyAsync(string email, string downloadUrl, CancellationToken ct);
        Task SendDeletionConfirmationAsync(string email, Guid deletionId, string confirmationToken, CancellationToken ct);
    }

    /// <summary>One email captured by <see cref="DevelopmentComplianceMailer"/>. Pure data.</summary>
    public record CapturedComplianceEmail(string To, string Kind, string Secret, Guid? DeletionId);

    /// <summary>
    /// Development / test mailer: keeps emails in memory (the link or token included, so tests can follow them) and
    /// logs only that one was sent, never the address or the secret. Not for production. Added 2026-11-10 (session
    /// session_012zDydZCZ4AChqhEZ4oVtaP). Touches: process memory.
    /// </summary>
    public class DevelopmentComplianceMailer : IComplianceMailer
    {
        private readonly List<CapturedComplianceEmail> _sent = new();
        private readonly ILogger<DevelopmentComplianceMailer> _logger;

        public DevelopmentComplianceMailer(ILogger<DevelopmentComplianceMailer> logger) => _logger = logger;

        /// <summary>A snapshot of the captured emails in send order. Touches: process memory.</summary>
        public IReadOnlyList<CapturedComplianceEmail> Sent { get { lock (_sent) return _sent.ToList(); } }

        /// <summary>Implements the interface member of the same name; see the class summary. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public Task SendExportReadyAsync(string email, string downloadUrl, CancellationToken ct)
        {
            lock (_sent) _sent.Add(new CapturedComplianceEmail(email, "export_ready", downloadUrl, null));
            _logger.LogInformation("Development mailer captured an export-ready email");
            return Task.CompletedTask;
        }

        /// <summary>Implements the interface member of the same name; see the class summary. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public Task SendDeletionConfirmationAsync(string email, Guid deletionId, string confirmationToken, CancellationToken ct)
        {
            lock (_sent) _sent.Add(new CapturedComplianceEmail(email, "deletion_confirmation", confirmationToken, deletionId));
            _logger.LogInformation("Development mailer captured a deletion confirmation email");
            return Task.CompletedTask;
        }
    }

    #endregion

    /// <summary>
    /// The audit system's erase_subject(user_id), injected like the audit logger (EXPORT-13). The deletion cascade calls
    /// it LAST, after the user's rows are deleted and 'user_deleted_cascade' is logged. Production wires it to the audit
    /// logging system's erase_subject; an implementation may stage its changes in the compliance unit of work (saved
    /// with the deletion) or call the audit system. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    public interface IAuditEraser
    {
        Task EraseSubjectAsync(Guid userId, CancellationToken ct);
    }

    /// <summary>
    /// Default <see cref="IAuditEraser"/> for this template's own audit_logs: every row of the user (saved, and staged
    /// in this unit of work) keeps its event but loses the link to the person (UserId Guid.Empty, ActorId null,
    /// PersonalErased true). Changes are staged on the scoped context and saved with the deletion (one SaveChanges).
    /// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: audit_logs (staged updates).
    /// </summary>
    public class LocalAuditEraser : IAuditEraser
    {
        private readonly ComplianceDbContext _db;

        public LocalAuditEraser(ComplianceDbContext db) => _db = db;

        /// <summary>Stages the erasure of the user's link in every audit row. Touches: audit_logs.</summary>
        public async Task EraseSubjectAsync(Guid userId, CancellationToken ct)
        {
            var saved = await _db.AuditLogs.Where(a => a.UserId == userId || a.ActorId == userId).ToListAsync(ct);
            foreach (var row in saved.Concat(_db.AuditLogs.Local.Where(a => a.UserId == userId || a.ActorId == userId)).Distinct().ToList())
            {
                if (row.UserId == userId) row.UserId = Guid.Empty;
                if (row.ActorId == userId) row.ActorId = null;
                row.PersonalErased = true;
            }
        }
    }

    /// <summary>The clock the compliance services read (UTC); tests move it. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public class ComplianceClock
    {
        public Func<DateTime> Now { get; set; } = () => DateTime.UtcNow;
    }

    #region Core services

    /// <summary>Writes audit_logs rows (added to the caller's unit of work; the caller saves). Touches: audit_logs.</summary>
    public static class Audit
    {
        private static long _sequence;

        /// <summary>Next value of the process-wide sequence that breaks ties between rows written in the same tick
        /// (insertion order). Static on purpose: services are created per request, so a per-instance counter would
        /// restart at 1 for every request. Moved into this static helper 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP,
        /// for code scanning ("static field written by instance method", PR 19). Touches: memory only.</summary>
        private static long NextSequence() => Interlocked.Increment(ref _sequence);

        /// <summary>Adds an audit row for a user, with the acting user and JSON details. Touches: audit_logs.</summary>
        public static void Add(ComplianceDbContext db, Guid userId, Guid? actorId, string action, object details) =>
            db.AuditLogs.Add(new AuditLog
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                ActorId = actorId,
                Action = action,
                Details = JsonConvert.SerializeObject(details),
                Timestamp = DateTime.UtcNow,
                Sequence = NextSequence()
            });
    }

    /// <summary>Outcome of a service call: a value, or an error code with its HTTP status. Pure data.</summary>
    public record ServiceResult<T>(T? Value, string? Error = null, int StatusCode = 200)
    {
        public bool Ok => Error == null;
    }

    /// <summary>
    /// Export and deletion requests for the signed-in user, and the admin lists. Callers pass the authenticated user
    /// id; a request belonging to someone else answers not_found, as if it did not exist. Added 2026-11-10 (session
    /// session_012zDydZCZ4AChqhEZ4oVtaP). Touches: the compliance database, the user data store (read), the mailer.
    /// </summary>
    public class ComplianceService
    {
        public static readonly string[] Formats = { "json", "csv" };
        public static readonly string[] Reasons = { "user_requested", "gdpr_request", "gdpr_right_to_be_forgotten", "other" };
        public static readonly TimeSpan GracePeriod = TimeSpan.FromDays(30);

        /// <summary>Reasons that are a statutory erasure request: no grace period (EXPORT-12).</summary>
        public static readonly string[] StatutoryReasons = { "gdpr_request", "gdpr_right_to_be_forgotten" };

        /// <summary>How long a deletion confirmation token works.</summary>
        public static readonly TimeSpan ConfirmationTokenLifetime = TimeSpan.FromHours(24);
        private static long _sequence;

        /// <summary>Next value of the process-wide sequence that breaks ties between rows written in the same tick
        /// (insertion order). Static on purpose: services are created per request, so a per-instance counter would
        /// restart at 1 for every request. Moved into this static helper 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP,
        /// for code scanning ("static field written by instance method", PR 19). Touches: memory only.</summary>
        private static long NextSequence() => Interlocked.Increment(ref _sequence);

        private readonly ComplianceDbContext _db;
        private readonly IUserDataStore _users;
        private readonly IComplianceMailer _mailer;
        private readonly ExportProcessor _processor;
        private readonly ComplianceClock _clock;

        /// <summary>
        /// In: the database, the user data store, the mailer, the processor (runs a statutory deletion's cascade at
        /// confirm) and the clock. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: processor and clock. Touches nothing.
        /// </summary>
        public ComplianceService(ComplianceDbContext db, IUserDataStore users, IComplianceMailer mailer, ExportProcessor processor, ComplianceClock clock)
        {
            _db = db;
            _users = users;
            _mailer = mailer;
            _processor = processor;
            _clock = clock;
        }

        /// <summary>
        /// Endpoint 1: records a pending export for the user (built later by <see cref="ExportProcessor"/>) and audits
        /// data_export_requested. Output: export id, status pending, the format and an estimated email time.
        /// Touches: export_requests, audit_logs.
        /// </summary>
        public async Task<ServiceResult<ExportResponse>> RequestExportAsync(Guid userId, string? format, CancellationToken ct)
        {
            var fmt = format?.ToLowerInvariant();
            if (fmt == null || !Formats.Contains(fmt)) return new(null, "invalid_format", 400);
            var now = DateTime.UtcNow;
            var export = new ExportRequest
            {
                Id = Guid.NewGuid(), UserId = userId, RequestedAt = now, Status = "pending", Format = fmt,
                Sequence = NextSequence()
            };
            _db.ExportRequests.Add(export);
            Audit.Add(_db, userId, userId, "data_export_requested", new { export_id = export.Id, format = fmt });
            await _db.SaveChangesAsync(ct);
            return new(new ExportResponse
            {
                Success = true, ExportId = export.Id.ToString(), Status = export.Status, Format = fmt,
                WillEmailAt = Iso(now.AddMinutes(5))
            });
        }

        /// <summary>Endpoint 2: the status of one of the user's exports (admins may read any). Touches: export_requests (read).</summary>
        public async Task<ServiceResult<ExportStatusResponse>> GetExportAsync(Guid userId, bool isAdmin, Guid exportId, CancellationToken ct)
        {
            var e = await _db.ExportRequests.AsNoTracking().FirstOrDefaultAsync(x => x.Id == exportId, ct);
            if (e == null || (e.UserId != userId && !isAdmin)) return new(null, "not_found", 404);
            return new(new ExportStatusResponse
            {
                ExportId = e.Id.ToString(), Status = e.Status, FileUrl = e.FileUrl,
                ExpiresAt = e.ExpiresAt.HasValue ? Iso(e.ExpiresAt.Value) : null, RequestedAt = Iso(e.RequestedAt)
            });
        }

        /// <summary>
        /// Endpoint 3: records a pending deletion, emails a one-time confirmation token (32 random bytes; only its
        /// SHA-256 is stored, valid 24 h, bound to this deletion id) and audits deletion_requested. will_delete_at =
        /// requested_at + 30 days for user_requested / other (EXPORT-05), = requested_at for gdpr_request /
        /// gdpr_right_to_be_forgotten (EXPORT-12: no grace period). Only one open deletion per user. Nothing is deleted
        /// before confirm. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (statutory reasons, token expiry, clock).
        /// Touches: deletion_requests, audit_logs, the mailer.
        /// </summary>
        public async Task<ServiceResult<DeletionResponse>> RequestDeletionAsync(Guid userId, string? reason, CancellationToken ct)
        {
            if (reason == null || !Reasons.Contains(reason)) return new(null, "invalid_reason", 400);
            var open = await _db.DeletionRequests.AnyAsync(d => d.UserId == userId && (d.Status == "pending" || d.Status == "approved"), ct);
            if (open) return new(null, "deletion_already_requested", 409);
            var email = await _users.GetEmailAsync(userId, ct);
            if (email == null) return new(null, "user_not_found", 404);

            var now = _clock.Now();
            var token = Base64Url(RandomNumberGenerator.GetBytes(32));
            var deletion = new DeletionRequest
            {
                Id = Guid.NewGuid(), UserId = userId, RequestedAt = now, Status = "pending", Reason = reason,
                ScheduledFor = StatutoryReasons.Contains(reason) ? now : now.Add(GracePeriod),
                ConfirmationTokenHash = SHA256.HashData(Encoding.UTF8.GetBytes(token)),
                TokenExpiresAt = now.Add(ConfirmationTokenLifetime),
                Sequence = NextSequence()
            };
            _db.DeletionRequests.Add(deletion);
            Audit.Add(_db, userId, userId, "deletion_requested", new { deletion_id = deletion.Id, reason });
            await _db.SaveChangesAsync(ct);
            await _mailer.SendDeletionConfirmationAsync(email, deletion.Id, token, ct);
            return new(new DeletionResponse
            {
                Success = true, DeletionId = deletion.Id.ToString(), Status = deletion.Status, WillDeleteAt = Iso(deletion.ScheduledFor)
            });
        }

        /// <summary>
        /// True while a deletion request has not run or been cancelled: status 'pending' (awaiting confirm) or
        /// 'approved' (confirmed, waiting out the grace period). Input: the request. Output: bool. Pure. Why: the spec's
        /// "a cancelled request gets 409 deletion_not_pending" (EXPORT-15); a failed cascade is also no longer pending.
        /// (A completed request is answered 404 before this is asked.) Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        private static bool StillPending(DeletionRequest d) => d.Status == "pending" || d.Status == "approved";

        /// <summary>
        /// Endpoint 4 (EXPORT-09/14/15): the owner confirms with the emailed token. Inputs: the caller, the deletion id
        /// and the token. Output: the confirmation, or an error. Another user's request (or none) is 404 not_found, and
        /// so is a completed one, to every caller (it has no owner: user_id is NULL, EXPORT-13; spec clarified in
        /// 3abb340); a cancelled (or failed) request is 409 deletion_not_pending, checked before the token; a wrong,
        /// reused (the request is already approved and its hash cleared) or expired (over 24 h) token gets the one
        /// answer 400 invalid_confirmation_token, so the reply never says which, and changes nothing. The comparison is
        /// constant-time over the SHA-256 hashes; the token is cleared on use (single use). For a statutory reason
        /// confirm() runs the cascade before returning: deletion_scheduled_for = deleted_at = now and status
        /// 'completed' (if the export cleanup fails it stays 'approved' and the worker retries). Otherwise the
        /// deletion runs after the grace period.
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (expiry, statutory cascade, clock; Phase B.2 /
        /// EXPORT-15: the error codes invalid_confirmation_token and deletion_not_pending, and a reused token is 400,
        /// not 409). Touches: deletion_requests, audit_logs; for a statutory reason everything the cascade touches.
        /// </summary>
        public async Task<ServiceResult<DeletionConfirmationResponse>> ConfirmDeletionAsync(Guid userId, Guid deletionId, string? token, CancellationToken ct)
        {
            var d = await _db.DeletionRequests.FirstOrDefaultAsync(x => x.Id == deletionId, ct);
            if (d == null || d.UserId != userId || d.Status == "completed") return new(null, "not_found", 404);
            if (!StillPending(d)) return new(null, "deletion_not_pending", 409);
            var now = _clock.Now();
            var provided = SHA256.HashData(Encoding.UTF8.GetBytes(token ?? ""));
            var matches = d.Status == "pending" && d.ConfirmationTokenHash != null && CryptographicOperations.FixedTimeEquals(d.ConfirmationTokenHash, provided);
            if (!matches || d.TokenExpiresAt == null || now > d.TokenExpiresAt.Value)
            {
                Audit.Add(_db, userId, userId, "deletion_confirmation_rejected", new { deletion_id = d.Id, expired = matches });
                await _db.SaveChangesAsync(ct);
                return new(null, "invalid_confirmation_token", 400);
            }
            d.Status = "approved";
            d.ConfirmedAt = now;
            d.ConfirmationTokenHash = null; // single use
            d.TokenExpiresAt = null;
            var statutory = StatutoryReasons.Contains(d.Reason);
            if (statutory) d.ScheduledFor = now;
            Audit.Add(_db, userId, userId, "deletion_confirmed", new { deletion_id = d.Id });
            await _db.SaveChangesAsync(ct);
            if (statutory)
                await _processor.RunCascadeAsync(d, now, ct);
            return new(new DeletionConfirmationResponse { Success = true, DeletionScheduledFor = Iso(d.ScheduledFor), Status = d.Status });
        }

        /// <summary>
        /// Endpoint 5: the owner cancels a pending or approved deletion before it runs. Inputs: the caller and the
        /// deletion id. Output: {success, status:'cancelled'} or an error: anyone else's request (or none) is 404
        /// not_found, and so is a completed one, to every caller (EXPORT-13/15, spec clarified in 3abb340); a cancelled
        /// (or failed) one is 409 deletion_not_pending.
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 / EXPORT-15: the code was cannot_cancel).
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.3 ruling, endpoint 5): once will_delete_at
        /// (ScheduledFor) has been reached by the injected clock, the deletion is due (the worker runs rows with
        /// scheduled_for &lt;= now) and cancelling is 409 grace_period_over; the row is left as it was.
        /// Touches: deletion_requests, audit_logs.
        /// </summary>
        public async Task<ServiceResult<object>> CancelDeletionAsync(Guid userId, Guid deletionId, CancellationToken ct)
        {
            var d = await _db.DeletionRequests.FirstOrDefaultAsync(x => x.Id == deletionId, ct);
            if (d == null || d.UserId != userId || d.Status == "completed") return new(null, "not_found", 404);
            if (!StillPending(d)) return new(null, "deletion_not_pending", 409);
            if (_clock.Now() >= d.ScheduledFor) return new(null, "grace_period_over", 409); // Phase B.3, 2026-11-10
            d.Status = "cancelled";
            d.ConfirmationTokenHash = null;
            d.TokenExpiresAt = null;
            Audit.Add(_db, userId, userId, "deletion_cancelled", new { deletion_id = d.Id });
            await _db.SaveChangesAsync(ct);
            return new(new { success = true, status = "cancelled" });
        }

        /// <summary>Endpoint 6 (admin): export requests, optionally by user and status, in request order (at most 500). Touches: export_requests (read).</summary>
        public async Task<AdminExportResponse> ListExportsAsync(Guid? userId, string? status, CancellationToken ct)
        {
            var q = _db.ExportRequests.AsNoTracking().AsQueryable();
            if (userId.HasValue) q = q.Where(e => e.UserId == userId.Value);
            if (!string.IsNullOrEmpty(status)) q = q.Where(e => e.Status == status);
            var total = await q.CountAsync(ct);
            var items = await q.OrderBy(e => e.RequestedAt).ThenBy(e => e.Sequence).Take(500).ToListAsync(ct);
            return new AdminExportResponse { Exports = items, Total = total };
        }

        /// <summary>Endpoint 7 (admin): deletion requests, optionally by status, in request order (at most 500). Touches: deletion_requests (read).</summary>
        public async Task<AdminDeletionResponse> ListDeletionsAsync(string? status, CancellationToken ct)
        {
            var q = _db.DeletionRequests.AsNoTracking().AsQueryable();
            if (!string.IsNullOrEmpty(status)) q = q.Where(d => d.Status == status);
            var total = await q.CountAsync(ct);
            var items = await q.OrderBy(d => d.RequestedAt).ThenBy(d => d.Sequence).Take(500).ToListAsync(ct);
            return new AdminDeletionResponse { Deletions = items, Total = total };
        }

        /// <summary>ISO 8601 UTC text. Pure.</summary>
        public static string Iso(DateTime value) => DateTime.SpecifyKind(value, DateTimeKind.Utc).ToString("o", CultureInfo.InvariantCulture);

        /// <summary>URL-safe base64 without padding. Pure.</summary>
        public static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>
    /// Builds pending exports and runs due deletions. Exports: collect the user's data, write JSON or CSV, store it,
    /// make a 7-day download link, email it, mark completed (or failed). Deletions: approved requests whose 30-day
    /// grace period has passed are cascaded through <see cref="IUserDataStore.DeleteUserAsync"/>; audit_logs are kept.
    /// Since 2026-11-10 (CodeRabbit review on PR 19) the user's export files and export_requests rows go first.
    /// Called by <see cref="ComplianceWorker"/> and directly by tests. Added 2026-11-10 (session
    /// session_012zDydZCZ4AChqhEZ4oVtaP). Touches: the compliance database, the user data store, storage, the mailer.
    /// </summary>
    public class ExportProcessor
    {
        public static readonly TimeSpan LinkLifetime = TimeSpan.FromDays(7);
        private readonly ComplianceDbContext _db;
        private readonly IUserDataStore _users;
        private readonly IExportStorage _storage;
        private readonly IComplianceMailer _mailer;
        private readonly ILogger<ExportProcessor> _logger;
        private readonly IAuditEraser _auditEraser;

        /// <summary>
        /// In: the database, the user data store, export storage, the mailer, a logger and the audit eraser (default:
        /// <see cref="LocalAuditEraser"/> over the same context). Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP:
        /// the audit eraser (EXPORT-13). Touches nothing.
        /// </summary>
        public ExportProcessor(ComplianceDbContext db, IUserDataStore users, IExportStorage storage, IComplianceMailer mailer, ILogger<ExportProcessor> logger,
            IAuditEraser? auditEraser = null)
        {
            _db = db;
            _users = users;
            _storage = storage;
            _mailer = mailer;
            _logger = logger;
            _auditEraser = auditEraser ?? new LocalAuditEraser(db);
        }

        /// <summary>Builds every pending export, oldest first. Output: how many were processed. Touches: see the class summary.</summary>
        public async Task<int> ProcessPendingExportsAsync(CancellationToken ct)
        {
            var pending = await _db.ExportRequests.Where(e => e.Status == "pending")
                .OrderBy(e => e.RequestedAt).ThenBy(e => e.Sequence).Take(20).ToListAsync(ct);
            foreach (var export in pending)
            {
                try
                {
                    var data = await _users.CollectAsync(export.UserId, ct);
                    var (bytes, contentType) = export.Format == "csv"
                        ? (Encoding.UTF8.GetBytes(ToCsv(data)), "text/csv")
                        : (Encoding.UTF8.GetBytes(data.ToString(Formatting.Indented)), "application/json");
                    var key = StorageKeyFor(export);
                    await _storage.PutAsync(key, bytes, contentType, ct);
                    var completedAt = DateTime.UtcNow;
                    var expiresAt = completedAt.Add(LinkLifetime);
                    var url = _storage.CreateDownloadUrl(key, new DateTimeOffset(expiresAt, TimeSpan.Zero));
                    var email = await _users.GetEmailAsync(export.UserId, ct) ?? throw new InvalidOperationException("User has no email address");
                    await _mailer.SendExportReadyAsync(email, url, ct);

                    export.Status = "completed";
                    export.StorageKey = key;
                    export.FileUrl = url;
                    export.CompletedAt = completedAt;
                    export.ExpiresAt = expiresAt;
                    Audit.Add(_db, export.UserId, null, "data_export_completed", new { export_id = export.Id, format = export.Format });
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogError("Export {ExportId} failed: {Error}", export.Id, ex.GetType().Name);
                    export.Status = "failed";
                    Audit.Add(_db, export.UserId, null, "data_export_failed", new { export_id = export.Id, error = ex.GetType().Name });
                }
                await _db.SaveChangesAsync(ct);
            }
            return pending.Count;
        }

        /// <summary>
        /// The storage key of an export's file: "exports/{user}/{export id}.{format}". Derived, not read from
        /// StorageKey, because an export that failed after its file was stored (for example at the email step) has no
        /// StorageKey but does have a file. Input: the export request. Output: the key. Added 2026-11-10, session
        /// session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review on PR 19). Pure.
        /// </summary>
        public static string StorageKeyFor(ExportRequest export) => $"exports/{export.UserId}/{export.Id}.{export.Format}";

        /// <summary>
        /// Runs every approved deletion whose time has come at <paramref name="now"/> (after the grace period; at once for a
        /// statutory reason), oldest first, through <see cref="RunCascadeAsync"/>. Input: the time to judge by. Output:
        /// how many due deletions were attempted. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit
        /// review on PR 19, and EXPORT-13: the cascade moved to RunCascadeAsync). Touches: see RunCascadeAsync.
        /// </summary>
        public async Task<int> ProcessDueDeletionsAsync(DateTime now, CancellationToken ct)
        {
            var due = await _db.DeletionRequests.Where(d => d.Status == "approved" && d.ScheduledFor <= now)
                .OrderBy(d => d.ScheduledFor).ThenBy(d => d.Sequence).ToListAsync(ct);
            foreach (var deletion in due)
                await RunCascadeAsync(deletion, now, ct);
            return due.Count;
        }

        /// <summary>
        /// The deletion cascade of one approved request (EXPORT-07/08/13), in order:
        /// (0) the user's export files are deleted from storage and their export_requests rows staged for removal; if
        ///     storage fails, the deletion stays 'approved' (audited deletion_export_cleanup_failed) and is retried;
        /// (1) the user's rows are deleted through <see cref="IUserDataStore.DeleteUserAsync"/> (never the audit tables);
        /// (2) 'user_deleted_cascade' is logged with the user as subject;
        /// (3) the audit eraser's erase_subject(user_id) is called LAST;
        /// then the request is 'completed' with deleted_at = now and user_id NULL, and every database change of the
        /// cascade is saved in one SaveChanges. Nothing is logged for the user after step 3. A failure in (1)-(3) marks
        /// the request 'failed' (audited). Input: the tracked request, the time. Written 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP (an independent security review found nothing erased the user's audit
        /// personal data, and 'deletion_completed' was logged for the user after the cascade). Touches: export storage,
        /// export_requests, the user data store, audit_logs, deletion_requests, the audit eraser.
        /// </summary>
        public async Task RunCascadeAsync(DeletionRequest deletion, DateTime now, CancellationToken ct)
        {
            if (deletion.Status != "approved" || deletion.UserId is not Guid userId) return;
            try
            {
                await DeleteExportsOfAsync(userId, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError("Deletion {DeletionId}: export cleanup failed, will retry: {Error}", deletion.Id, ex.GetType().Name);
                foreach (var entry in _db.ChangeTracker.Entries<ExportRequest>().Where(e => e.State == EntityState.Deleted).ToList())
                    entry.State = EntityState.Unchanged;
                Audit.Add(_db, userId, null, "deletion_export_cleanup_failed", new { deletion_id = deletion.Id, error = ex.GetType().Name });
                await _db.SaveChangesAsync(ct);
                return; // still "approved": the next pass retries it
            }
            try
            {
                await _users.DeleteUserAsync(userId, ct);
                Audit.Add(_db, userId, null, "user_deleted_cascade", new { deletion_id = deletion.Id });
                await _auditEraser.EraseSubjectAsync(userId, ct);
                deletion.Status = "completed";
                deletion.DeletedAt = now;
                deletion.UserId = null;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError("Deletion {DeletionId} failed: {Error}", deletion.Id, ex.GetType().Name);
                deletion.Status = "failed";
                Audit.Add(_db, userId, null, "deletion_failed", new { deletion_id = deletion.Id, error = ex.GetType().Name });
            }
            await _db.SaveChangesAsync(ct);
        }

        /// <summary>
        /// Deletes every export file of the user from storage, then stages the removal of their export_requests rows
        /// (saved with the deletion's outcome). Storage deletes are idempotent, so a retry after a partial failure is
        /// safe; rows are removed only once every file is gone. Input: the user id. Throws when storage fails. Added
        /// 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review on PR 19). Touches: export storage,
        /// export_requests.
        /// </summary>
        private async Task DeleteExportsOfAsync(Guid userId, CancellationToken ct)
        {
            var exports = await _db.ExportRequests.Where(e => e.UserId == userId).ToListAsync(ct);
            foreach (var export in exports)
            {
                await _storage.DeleteAsync(StorageKeyFor(export), ct);
                if (!string.IsNullOrEmpty(export.StorageKey) && export.StorageKey != StorageKeyFor(export))
                    await _storage.DeleteAsync(export.StorageKey, ct);
            }
            _db.ExportRequests.RemoveRange(exports);
        }

        /// <summary>
        /// Flattens the export document to CSV rows "section,path,value". Every field is quoted with inner quotes
        /// doubled, and a value starting with =, +, - or @ is prefixed with ' so a spreadsheet does not run it as a
        /// formula (CSV injection). Pure.
        /// </summary>
        public static string ToCsv(JObject data)
        {
            var sb = new StringBuilder("section,path,value\n");
            foreach (var leaf in data.Descendants().OfType<JValue>())
            {
                var path = leaf.Path;
                var section = path.Split('.', '[')[0];
                sb.Append(Cell(section)).Append(',').Append(Cell(path)).Append(',').Append(Cell(leaf.ToString(CultureInfo.InvariantCulture))).Append('\n');
            }
            return sb.ToString();
        }

        /// <summary>One CSV cell, quoted and formula-safe. Pure.</summary>
        private static string Cell(string value)
        {
            if (value.Length > 0 && "=+-@".Contains(value[0])) value = "'" + value;
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        }
    }

    /// <summary>
    /// Hosted worker: every <see cref="Interval"/> builds pending exports and runs due deletions in a fresh scope.
    /// Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP), replacing a queue that never ran. Touches: see
    /// <see cref="ExportProcessor"/>.
    /// </summary>
    public class ComplianceWorker : BackgroundService
    {
        public static readonly TimeSpan Interval = TimeSpan.FromSeconds(2);
        private readonly IServiceProvider _sp;
        private readonly ILogger<ComplianceWorker> _logger;

        public ComplianceWorker(IServiceProvider sp, ILogger<ComplianceWorker> logger)
        {
            _sp = sp;
            _logger = logger;
        }

        /// <summary>The worker loop: one pass, then wait, until the host stops; a failing pass is logged, not fatal. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: see the class summary.</summary>
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    using var scope = _sp.CreateScope();
                    var processor = scope.ServiceProvider.GetRequiredService<ExportProcessor>();
                    await processor.ProcessPendingExportsAsync(stoppingToken);
                    await processor.ProcessDueDeletionsAsync(scope.ServiceProvider.GetRequiredService<ComplianceClock>().Now(), stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Compliance worker pass failed");
                }
                await Task.Delay(Interval, stoppingToken);
            }
        }
    }

    #endregion

    #region Authentication

    /// <summary>
    /// Bearer authentication for this template: an HS256 JWT signed with Auth:JwtSecret (the auth system's token
    /// format). "sub" (or "user_id") must be a GUID user id; role "admin" grants the admin endpoints. The algorithm is
    /// fixed (ValidAlgorithms = HS256; "none" and header-chosen algorithms are refused), the lifetime is checked with
    /// no clock skew, and without a configured secret (at least 32 bytes) every request is anonymous: fail closed.
    /// Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP), replacing a hard-coded user id. Touches: the
    /// request headers and configuration (read).
    /// </summary>
    public class BearerTokenHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public const string Scheme = "Bearer";
        private readonly IConfiguration _config;

        public BearerTokenHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, IConfiguration config)
            : base(options, logger, encoder) => _config = config;

        /// <summary>Authenticates the request from its bearer token, or reports no result / failure. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: request headers, configuration (read).</summary>
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var header = Request.Headers.Authorization.ToString();
            if (!header.StartsWith("Bearer ", StringComparison.Ordinal)) return Task.FromResult(AuthenticateResult.NoResult());
            var secret = _config["Auth:JwtSecret"];
            if (string.IsNullOrEmpty(secret) || Encoding.UTF8.GetByteCount(secret) < 32)
                return Task.FromResult(AuthenticateResult.Fail("Authentication is not configured"));
            try
            {
                var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
                var principal = handler.ValidateToken(header.Substring(7).Trim(), new TokenValidationParameters
                {
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
                    ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 },
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ClockSkew = TimeSpan.Zero,
                    RoleClaimType = "role",
                    NameClaimType = "sub"
                }, out _);
                var id = principal.FindFirst("sub")?.Value ?? principal.FindFirst("user_id")?.Value;
                if (!Guid.TryParse(id, out _)) return Task.FromResult(AuthenticateResult.Fail("Token has no user id"));
                return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme)));
            }
            catch (Exception ex) when (ex is SecurityTokenException || ex is ArgumentException)
            {
                return Task.FromResult(AuthenticateResult.Fail("Invalid token"));
            }
        }
    }

    /// <summary>Reads the authenticated user's id from the verified token. Pure.</summary>
    public static class CurrentUser
    {
        /// <summary>The authenticated user id ("sub", else "user_id"). 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Pure.</summary>
        public static Guid Id(ClaimsPrincipal user) =>
            Guid.Parse(user.FindFirst("sub")?.Value ?? user.FindFirst("user_id")!.Value);

        /// <summary>True when the verified token carries role admin. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Pure.</summary>
        public static bool IsAdmin(ClaimsPrincipal user) => user.IsInRole("admin");
    }

    #endregion

    #region Startup and Program

    /// <summary>
    /// Service registration and the seven endpoints of the spec plus the signed download. Users' endpoints need an
    /// authenticated user; /admin endpoints need role admin. Development implementations of IUserDataStore,
    /// IExportStorage and IComplianceMailer are registered only when none was registered before (register yours
    /// first). Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP). Touches: see the file header.
    /// </summary>
    public class Startup
    {
        private readonly IConfiguration _config;

        public Startup(IConfiguration config) => _config = config;

        /// <summary>Registers the database, gateways/stores, services, worker and auth as described on the class. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing until resolved.</summary>
        public void ConfigureServices(IServiceCollection services)
        {
            var cs = _config.GetConnectionString("Compliance");
            if (string.IsNullOrEmpty(cs))
            {
                var name = "compliance-" + Guid.NewGuid().ToString("N");
                services.AddDbContext<ComplianceDbContext>(o => o.UseInMemoryDatabase(name));
            }
            else
            {
                services.AddDbContext<ComplianceDbContext>(o => o.UseSqlite(cs));
            }

            if (!services.Any(d => d.ServiceType == typeof(IUserDataStore)))
            {
                services.AddSingleton<InMemoryUserDataStore>();
                services.AddSingleton<IUserDataStore>(sp => sp.GetRequiredService<InMemoryUserDataStore>());
            }
            if (!services.Any(d => d.ServiceType == typeof(IExportStorage)))
                services.AddSingleton<IExportStorage, InMemoryExportStorage>();
            if (!services.Any(d => d.ServiceType == typeof(IComplianceMailer)))
            {
                services.AddSingleton<DevelopmentComplianceMailer>();
                services.AddSingleton<IComplianceMailer>(sp => sp.GetRequiredService<DevelopmentComplianceMailer>());
            }

            if (!services.Any(d => d.ServiceType == typeof(IAuditEraser)))
                services.AddScoped<IAuditEraser, LocalAuditEraser>();
            services.AddSingleton<ComplianceClock>();
            services.AddScoped<ComplianceService>();
            services.AddScoped<ExportProcessor>();
            services.AddHostedService<ComplianceWorker>();

            services.AddAuthentication(BearerTokenHandler.Scheme)
                .AddScheme<AuthenticationSchemeOptions, BearerTokenHandler>(BearerTokenHandler.Scheme, _ => { });
            services.AddAuthorization(o =>
            {
                o.AddPolicy("user", p => p.RequireAuthenticatedUser());
                o.AddPolicy("admin", p => p.RequireAuthenticatedUser().RequireRole("admin"));
            });
        }

        /// <summary>Creates the schema if missing, adds authentication/authorisation and maps the endpoints. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP; the download now also requires the completed export request and its file to exist (CodeRabbit review on PR 19). Touches: the database, export storage.</summary>
        public void Configure(WebApplication app)
        {
            using (var scope = app.Services.CreateScope())
                scope.ServiceProvider.GetRequiredService<ComplianceDbContext>().Database.EnsureCreated();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapPost("/compliance/export", async (ExportRequestDto dto, ClaimsPrincipal user, ComplianceService svc, CancellationToken ct) =>
                ToResult(await svc.RequestExportAsync(CurrentUser.Id(user), dto?.Format, ct))).RequireAuthorization("user");

            app.MapGet("/compliance/exports/{exportId:guid}", async (Guid exportId, ClaimsPrincipal user, ComplianceService svc, CancellationToken ct) =>
                ToResult(await svc.GetExportAsync(CurrentUser.Id(user), CurrentUser.IsAdmin(user), exportId, ct))).RequireAuthorization("user");

            app.MapPost("/compliance/delete", async (DeletionRequestDto dto, ClaimsPrincipal user, ComplianceService svc, CancellationToken ct) =>
                ToResult(await svc.RequestDeletionAsync(CurrentUser.Id(user), dto?.Reason, ct))).RequireAuthorization("user");

            app.MapPost("/compliance/delete/{deletionId:guid}/confirm", async (Guid deletionId, ConfirmDeletionDto dto, ClaimsPrincipal user, ComplianceService svc, CancellationToken ct) =>
                ToResult(await svc.ConfirmDeletionAsync(CurrentUser.Id(user), deletionId, dto?.ConfirmationToken, ct))).RequireAuthorization("user");

            app.MapDelete("/compliance/delete/{deletionId:guid}", async (Guid deletionId, ClaimsPrincipal user, ComplianceService svc, CancellationToken ct) =>
                ToResult(await svc.CancelDeletionAsync(CurrentUser.Id(user), deletionId, ct))).RequireAuthorization("user");

            app.MapGet("/admin/compliance/exports", async (Guid? user_id, string? status, ComplianceService svc, CancellationToken ct) =>
                Results.Json(await svc.ListExportsAsync(user_id, status, ct))).RequireAuthorization("admin");

            app.MapGet("/admin/compliance/deletions", async (string? status, ComplianceService svc, CancellationToken ct) =>
                Results.Json(await svc.ListDeletionsAsync(status, ct))).RequireAuthorization("admin");

            // The signed link is the credential (it is emailed to the owner), so this endpoint needs no session. A valid
            // signature is not enough: the completed export request must still exist and so must its file, so a link of a
            // deleted account (whose exports were removed) answers 404. Changed 2026-11-10, session
            // session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review on PR 19). Touches: export_requests (read), export storage.
            app.MapGet("/compliance/downloads/{**key}", async (string key, long expires, string? signature, IExportStorage storage, ComplianceDbContext db, CancellationToken ct) =>
            {
                if (!storage.VerifyDownload(key, expires, signature, DateTimeOffset.UtcNow)) return Results.StatusCode(403);
                var requestExists = await db.ExportRequests.AsNoTracking().AnyAsync(e => e.StorageKey == key && e.Status == "completed", ct);
                if (!requestExists) return Results.NotFound();
                var file = await storage.GetAsync(key, ct);
                return file == null ? Results.NotFound() : Results.File(file.Value.Content, file.Value.ContentType);
            });
        }

        /// <summary>Maps a service result to JSON with its status code. Pure.</summary>
        private static IResult ToResult<T>(ServiceResult<T> r) =>
            r.Ok ? Results.Json(r.Value) : Results.Json(new { success = false, error = r.Error }, statusCode: r.StatusCode);
    }

    /// <summary>Builds and runs the web host. Touches: see Startup.</summary>
    public class Program
    {
        /// <summary>Entry point: builds the host from Startup and runs it. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: see Startup.</summary>
        public static async Task Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            var startup = new Startup(builder.Configuration);
            startup.ConfigureServices(builder.Services);
            var app = builder.Build();
            startup.Configure(app);
            await app.RunAsync();
        }
    }

    #endregion
}

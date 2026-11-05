using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data;
using System.Data.Common;
using System.Data.SqlClient;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace ComplianceModule
{
    public class ExportRequestDto
    {
        [Required]
        public string Format { get; set; }
    }

    public class DeletionRequestDto
    {
        [Required]
        public string Reason { get; set; }
    }

    public class ConfirmDeletionDto
    {
        [Required]
        public string ConfirmationToken { get; set; }
    }

    public class ExportResponse
    {
        public bool Success { get; set; }
        public string ExportId { get; set; }
        public string Status { get; set; }
        public string WillEmailAt { get; set; }
    }

    public class ExportStatusResponse
    {
        public string ExportId { get; set; }
        public string Status { get; set; }
        public string FileUrl { get; set; }
        public string ExpiresAt { get; set; }
        public string RequestedAt { get; set; }
    }

    public class DeletionResponse
    {
        public bool Success { get; set; }
        public string DeletionId { get; set; }
        public string Status { get; set; }
        public string WillDeleteAt { get; set; }
    }

    public class DeletionConfirmationResponse
    {
        public bool Success { get; set; }
        public string DeletionScheduledFor { get; set; }
    }

    public class AdminExportResponse
    {
        public List<ExportRequest> Exports { get; set; }
        public int Total { get; set; }
    }

    public class AdminDeletionResponse
    {
        public List<DeletionRequest> Deletions { get; set; }
        public int Total { get; set; }
    }

    public class ExportRequest
    {
        public Guid Id { get; set; }
        public Guid UserId { get; set; }
        public DateTime RequestedAt { get; set; }
        public string Status { get; set; }
        public string Format { get; set; }
        public string FileUrl { get; set; }
        public DateTime? CompletedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
    }

    public class DeletionRequest
    {
        public Guid Id { get; set; }
        public Guid UserId { get; set; }
        public DateTime RequestedAt { get; set; }
        public string Status { get; set; }
        public string Reason { get; set; }
        public DateTime? DeletedAt { get; set; }
    }

    public class ComplianceDbContext : DbContext
    {
        public ComplianceDbContext(DbContextOptions<ComplianceDbContext> options) : base(options) { }

        public DbSet<ExportRequest> ExportRequests { get; set; }
        public DbSet<DeletionRequest> DeletionRequests { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<ExportRequest>(entity =>
            {
                entity.ToTable("export_requests");
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Id).HasDefaultValueSql("NEWID()");
                entity.Property(e => e.UserId).IsRequired();
                entity.Property(e => e.RequestedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.Status).HasMaxLength(20).IsRequired();
                entity.Property(e => e.Format).HasMaxLength(10).IsRequired();
                entity.Property(e => e.FileUrl).HasColumnType("nvarchar(max)");
                entity.Property(e => e.CompletedAt);
                entity.Property(e => e.ExpiresAt);
            });

            modelBuilder.Entity<DeletionRequest>(entity =>
            {
                entity.ToTable("deletion_requests");
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Id).HasDefaultValueSql("NEWID()");
                entity.Property(e => e.UserId).IsRequired();
                entity.Property(e => e.RequestedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.Status).HasMaxLength(20).IsRequired();
                entity.Property(e => e.Reason).HasMaxLength(50).IsRequired();
                entity.Property(e => e.DeletedAt);
            });
        }
    }

    public interface IExportService
    {
        Task<string> GenerateExportAsync(Guid userId, string format, CancellationToken cancellationToken);
        Task<string> UploadToS3Async(string filePath, string contentType);
        Task<string> GenerateSignedUrlAsync(string s3Key);
        Task SendEmailAsync(string userEmail, string downloadLink);
    }

    public class ExportService : IExportService
    {
        private readonly ILogger<ExportService> _logger;
        private readonly IConfiguration _configuration;
        private readonly IAuditService _auditService;

        public ExportService(ILogger<ExportService> logger, IConfiguration configuration, IAuditService auditService)
        {
            _logger = logger;
            _configuration = configuration;
            _auditService = auditService;
        }

        public async Task<string> GenerateExportAsync(Guid userId, string format, CancellationToken cancellationToken)
        {
            var userData = await FetchUserDataAsync(userId, cancellationToken);
            string filePath;

            if (format.Equals("json", StringComparison.OrdinalIgnoreCase))
            {
                filePath = Path.GetTempFileName() + ".json";
                await File.WriteAllTextAsync(filePath, JsonConvert.SerializeObject(userData, Formatting.Indented), cancellationToken);
            }
            else if (format.Equals("csv", StringComparison.OrdinalIgnoreCase))
            {
                filePath = Path.GetTempFileName() + ".csv";
                var csv = ConvertToCsv(userData);
                await File.WriteAllTextAsync(filePath, csv, cancellationToken);
            }
            else
            {
                throw new ArgumentException("Invalid format specified");
            }

            return filePath;
        }

        public async Task<string> UploadToS3Async(string filePath, string contentType)
        {
            // Simulate S3 upload - in reality would use AWS SDK
            var fileName = Path.GetFileName(filePath);
            var s3Key = $"exports/{Guid.NewGuid()}/{fileName}";
            _logger.LogInformation("Simulated S3 upload: {S3Key}", s3Key);
            await Task.Delay(100); // Simulate network delay
            return s3Key;
        }

        public async Task<string> GenerateSignedUrlAsync(string s3Key)
        {
            // Simulate signed URL generation - in reality would use AWS SDK
            var expires = DateTime.UtcNow.AddDays(7);
            var url = $"https://s3.amazonaws.com/bucket/{s3Key}?Expires={((DateTimeOffset)expires).ToUnixTimeSeconds()}&Signature=sig";
            return url;
        }

        public async Task SendEmailAsync(string userEmail, string downloadLink)
        {
            // An address is personal data and a download link is a secret, so neither goes into the log.
            // Code scanning alert cs/exposure-of-sensitive-information, 2026-11-05, session f3daac6e.
            _logger.LogInformation("Simulated export email sent");
            await Task.CompletedTask;
        }

        private async Task<JObject> FetchUserDataAsync(Guid userId, CancellationToken cancellationToken)
        {
            // In reality would query multiple services/databases
            await Task.Delay(50, cancellationToken); // Simulate DB call
            return new JObject
            {
                ["profile"] = new JObject
                {
                    ["id"] = userId.ToString(),
                    ["email"] = "user@example.com",
                    ["name"] = "John Doe",
                    ["created_at"] = DateTime.Utcnow.AddYears(-2).ToString("o"),
                    ["tier"] = "premium",
                    ["status"] = "active"
                },
                ["sessions"] = new JArray
                {
                    new JObject { ["ip"] = "192.168.1.1", ["device_info"] = "Chrome on Windows", ["login_at"] = DateTime.Utcnow.AddHours(-1).ToString("o") }
                },
                ["activity"] = new JArray
                {
                    new JObject { ["action"] = "login", ["timestamp"] = DateTime.Utcnow.AddHours(-2).ToString("o") }
                },
                ["files"] = new JArray
                {
                    new JObject { ["id"] = Guid.NewGuid(), ["name"] = "document.pdf", ["size"] = 1024 }
                },
                ["preferences"] = new JObject
                {
                    ["notifications"] = true,
                    ["theme"] = "dark",
                    ["language"] = "en"
                },
                ["transactions"] = new JArray
                {
                    new JObject { ["id"] = Guid.NewGuid(), ["amount"] = 99.99, ["date"] = DateTime.Utcnow.AddDays(-10).ToString("o") }
                },
                ["audit_trail"] = new JArray
                {
                    new JObject { ["action"] = "profile_update", ["timestamp"] = DateTime.Utcnow.AddDays(-5).ToString("o") }
                }
            };
        }

        private string ConvertToCsv(JObject data)
        {
            var sb = new StringBuilder();
            sb.AppendLine("section,key,value");
            FlattenJson(data, "", sb);
            return sb.ToString();
        }

        private void FlattenJson(JToken token, string parentPath, StringBuilder sb)
        {
            switch (token.Type)
            {
                case JTokenType.Object:
                    foreach (var prop in token.Children<JProperty>())
                    {
                        var newPath = string.IsNullOrEmpty(parentPath) ? prop.Name : $"{parentPath}.{prop.Name}";
                        FlattenJson(prop.Value, newPath, sb);
                    }
                    break;
                case JTokenType.Array:
                    var index = 0;
                    foreach (var item in token.Children())
                    {
                        var newPath = $"{parentPath}[{index}]";
                        FlattenJson(item, newPath, sb);
                        index++;
                    }
                    break;
                default:
                    sb.AppendLine($"\"{parentPath}\",\"{token.Path}\",\"{token.ToString()}\"");
                    break;
            }
        }
    }

    public interface IDeletionService
    {
        Task<DeletionRequest> RequestDeletionAsync(Guid userId, string reason, string confirmationToken, CancellationToken cancellationToken);
        Task ConfirmDeletionAsync(Guid deletionId, string confirmationToken, CancellationToken cancellationToken);
        Task CancelDeletionAsync(Guid deletionId, CancellationToken cancellationToken);
        Task ProcessScheduledDeletionsAsync(CancellationToken cancellationToken);
    }

    public class DeletionService : IDeletionService
    {
        private readonly ComplianceDbContext _dbContext;
        private readonly ILogger<DeletionService> _logger;
        private readonly IAuditService _auditService;
        private readonly IUserService _userService;
        private readonly IEncryptionService _encryptionService;

        public DeletionService(ComplianceDbContext dbContext, ILogger<DeletionService> logger, IAuditService auditService, IUserService userService, IEncryptionService encryptionService)
        {
            _dbContext = dbContext;
            _logger = logger;
            _auditService = auditService;
            _userService = userService;
            _encryptionService = encryptionService;
        }

        public async Task<DeletionRequest> RequestDeletionAsync(Guid userId, string reason, string confirmationToken, CancellationToken cancellationToken)
        {
            var deletionId = Guid.NewGuid();
            var requestedAt = DateTime.UtcNow;
            var willDeleteAt = requestedAt.AddDays(30); // 30-day grace period

            var deletionRequest = new DeletionRequest
            {
                Id = deletionId,
                UserId = userId,
                RequestedAt = requestedAt,
                Status = "pending",
                Reason = reason
            };

            _dbContext.DeletionRequests.Add(deletionRequest);
            await _dbContext.SaveChangesAsync(cancellationToken);

            await _auditService.LogAsync(userId, "deletion_requested", new { reason, deletion_id = deletionId.ToString() }, cancellationToken);

            // Send confirmation email with token
            var user = await _userService.GetUserByIdAsync(userId, cancellationToken);
            var token = _encryptionService.EncryptToken(deletionId, userId, requestedAt);
            await _userService.SendDeletionConfirmationEmailAsync(user.Email, token, cancellationToken);

            return deletionRequest;
        }

        public async Task ConfirmDeletionAsync(Guid deletionId, string confirmationToken, CancellationToken cancellationToken)
        {
            var deletionRequest = await _dbContext.DeletionRequests.FindAsync(new object[] { deletionId }, cancellationToken);
            if (deletionRequest == null)
                throw new KeyNotFoundException("Deletion request not found");

            if (deletionRequest.Status != "pending")
                throw new InvalidOperationException("Deletion request is not pending");

            var userId = deletionRequest.UserId;
            var requestedAt = deletionRequest.RequestedAt;

            if (!_encryptionService.ValidateToken(confirmationToken, deletionId, userId, requestedAt))
                throw new SecurityTokenException("Invalid confirmation token");

            deletionRequest.Status = "approved";
            await _dbContext.SaveChangesAsync(cancellationToken);

            await _auditService.LogAsync(userId, "deletion_confirmed", new { deletion_id = deletionId.ToString() }, cancellationToken);
        }

        public async Task CancelDeletionAsync(Guid deletionId, CancellationToken cancellationToken)
        {
            var deletionRequest = await _dbContext.DeletionRequests.FindAsync(new object[] { deletionId }, cancellationToken);
            if (deletionRequest == null)
                throw new KeyNotFoundException("Deletion request not found");

            if (deletionRequest.Status != "pending" && deletionRequest.Status != "approved")
                throw new InvalidOperationException("Deletion request cannot be cancelled");

            deletionRequest.Status = "cancelled";
            await _dbContext.SaveChangesAsync(cancellationToken);

            await _auditService.LogAsync(deletionRequest.UserId, "deletion_cancelled", new { deletion_id = deletionId.ToString() }, cancellationToken);
        }

        public async Task ProcessScheduledDeletionsAsync(CancellationToken cancellationToken)
        {
            var now = DateTime.UtcNow;
            var deletionsToProcess = await _dbContext.DeletionRequests
                .Where(d => d.Status == "approved" && d.RequestedAt.AddDays(30) <= now)
                .ToListAsync(cancellationToken);

            foreach (var deletion in deletionsToProcess)
            {
                try
                {
                    await CascadeDeleteUserAsync(deletion.UserId, cancellationToken);
                    deletion.Status = "completed";
                    deletion.DeletedAt = now;
                    await _auditService.LogAsync(deletion.UserId, "deletion_completed", new { deletion_id = deletion.Id.ToString() }, cancellationToken);
                }
                catch (Exception ex)
                {
                    deletion.Status = "failed";
                    await _auditService.LogAsync(deletion.UserId, "deletion_failed", new { deletion_id = deletion.Id.ToString(), error = ex.Message }, cancellationToken);
                    _logger.LogError(ex, "Failed to process deletion {DeletionId}", deletion.Id);
                }
            }

            await _dbContext.SaveChangesAsync(cancellationToken);
        }

        private async Task CascadeDeleteUserAsync(Guid userId, CancellationToken cancellationToken)
        {
            // Delete from all tables where user_id = X, except audit_log
            var tables = new[] { "sessions", "activity", "files", "preferences", "transactions", "api_keys" };
            foreach (var table in tables)
            {
                var sql = $"DELETE FROM {table} WHERE user_id = @UserId";
                await _dbContext.Database.ExecuteSqlRawAsync(sql, new SqlParameter("@UserId", userId), cancellationToken);
            }

            // Delete the user record itself
            var userSql = "DELETE FROM users WHERE id = @UserId";
            await _dbContext.Database.ExecuteSqlRawAsync(userSql, new SqlParameter("@UserId", userId), cancellationToken);
        }
    }

    public interface IAuditService
    {
        Task LogAsync(Guid userId, string action, object details, CancellationToken cancellationToken);
    }

    public class AuditService : IAuditService
    {
        private readonly ComplianceDbContext _dbContext;
        private readonly ILogger<AuditService> _logger;

        public AuditService(ComplianceDbContext dbContext, ILogger<AuditService> logger)
        {
            _dbContext = dbContext;
            _logger = logger;
        }

        public async Task LogAsync(Guid userId, string action, object details, CancellationToken cancellationToken)
        {
            var auditEntry = new AuditLog
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                Action = action,
                Details = JsonConvert.SerializeObject(details),
                Timestamp = DateTime.UtcNow
            };

            _dbContext.AuditLogs.Add(auditEntry);
            await _dbContext.SaveChangesAsync(cancellationToken);
            _logger.LogInformation("Audit logged: User {UserId} - {Action}", userId, action);
        }
    }

    public class AuditLog
    {
        public Guid Id { get; set; }
        public Guid UserId { get; set; }
        public string Action { get; set; }
        public string Details { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public interface IUserService
    {
        Task<User> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken);
        Task SendDeletionConfirmationEmailAsync(string email, string token, CancellationToken cancellationToken);
    }

    public class UserService : IUserService
    {
        private readonly ILogger<UserService> _logger;
        private readonly IConfiguration _configuration;

        public UserService(ILogger<UserService> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        public async Task<User> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken)
        {
            // Simulate DB call
            await Task.Delay(10);
            return new User
            {
                Id = userId,
                Email = "user@example.com",
                Name = "John Doe"
            };
        }

        public async Task SendDeletionConfirmationEmailAsync(string email, string token, CancellationToken cancellationToken)
        {
            var confirmationLink = $"{_configuration["App:BaseUrl"]}/compliance/delete/confirm?token={token}";
            // The link carries the confirmation token, so it stays out of the log, and so does the address.
            // Code scanning alert cs/exposure-of-sensitive-information, 2026-11-05, session f3daac6e.
            _logger.LogInformation("Simulated deletion confirmation email sent");
            await Task.CompletedTask;
        }
    }

    public class User
    {
        public Guid Id { get; set; }
        public string Email { get; set; }
        public string Name { get; set; }
    }

    public interface IEncryptionService
    {
        string EncryptToken(Guid deletionId, Guid userId, DateTime requestedAt);
        bool ValidateToken(string token, Guid deletionId, Guid userId, DateTime requestedAt);
    }

    public class EncryptionService : IEncryptionService
    {
        private readonly IConfiguration _configuration;

        public EncryptionService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string EncryptToken(Guid deletionId, Guid userId, DateTime requestedAt)
        {
            var data = $"{deletionId}|{userId}|{requestedAt.ToString("o")}";
            // In reality would use proper encryption (e.g., AES)
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(data));
        }

        public bool ValidateToken(string token, Guid deletionId, Guid userId, DateTime requestedAt)
        {
            try
            {
                var data = Encoding.UTF8.GetString(Convert.FromBase64String(token));
                var parts = data.Split('|');
                if (parts.Length != 3) return false;

                var tokenDeletionId = Guid.Parse(parts[0]);
                var tokenUserId = Guid.Parse(parts[1]);
                var tokenRequestedAt = DateTime.Parse(parts[2], null, DateTimeStyles.RoundtripKind);

                return tokenDeletionId == deletionId &&
                       tokenUserId == userId &&
                       Math.Abs((tokenRequestedAt - requestedAt).TotalSeconds) < 1; // Allow 1 second skew
            }
            catch
            {
                return false;
            }
        }
    }

    public interface IBackgroundJobQueue
    {
        void QueueBackgroundWorkItem(Func<CancellationToken, Task> workItem);
    }

    public class BackgroundJobQueue : IBackgroundJobQueue, IHostedService
    {
        private readonly Channel<Func<CancellationToken, Task>> _queue = Channel.CreateUnbounded<Func<CancellationToken, Task>>();
        private readonly ILogger<BackgroundJobQueue> _logger;
        private CancellationTokenSource _cts;

        public BackgroundJobQueue(ILogger<BackgroundJobQueue> logger)
        {
            _logger = logger;
        }

        public void QueueBackgroundWorkItem(Func<CancellationToken, Task> workItem)
        {
            if (_queue.Writer.TryComplete())
                return;
            _queue.Writer.WriteAsync(workItem).GetAwaiter().GetResult();
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _ = Task.Run(() => ProcessQueueAsync(_cts.Token));
            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _cts.Cancel();
            return Task.CompletedTask;
        }

        private async Task ProcessQueueAsync(CancellationToken cancellationToken)
        {
            await foreach (var workItem in _queue.Reader.ReadAllAsync(cancellationToken))
            {
                try
                {
                    await workItem(cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in background work item");
                }
            }
        }
    }

    [ApiController]
    [Route("compliance")]
    public class ComplianceController : ControllerBase
    {
        private readonly IExportService _exportService;
        private readonly IDeletionService _deletionService;
        private readonly IBackgroundJobQueue _backgroundJobQueue;
        private readonly ILogger<ComplianceController> _logger;

        public ComplianceController(IExportService exportService, IDeletionService deletionService, IBackgroundJobQueue backgroundJobQueue, ILogger<ComplianceController> logger)
        {
            _exportService = exportService;
            _deletionService = deletionService;
            _backgroundJobQueue = backgroundJobQueue;
            _logger = logger;
        }

        [HttpPost("export")]
        public async Task<IActionResult> RequestExport([FromBody] ExportRequestDto dto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var userId = GetCurrentUserId();
            if (userId == Guid.Empty)
                return Unauthorized();

            var exportId = Guid.NewGuid();
            var requestedAt = DateTime.UtcNow;
            var willEmailAt = requestedAt.AddMinutes(5); // Simulate processing time

            // Record export request
            using (var connection = new SqlConnection(GetConnectionString()))
            {
                await connection.OpenAsync();
                using (var command = new SqlCommand(
                    "INSERT INTO export_requests (id, user_id, requested_at, status, format) VALUES (@Id, @UserId, @RequestedAt, @Status, @Format)", connection))
                {
                    command.Parameters.AddWithValue("@Id", exportId);
                    command.Parameters.AddWithValue("@UserId", userId);
                    command.Parameters.AddWithValue("@RequestedAt", requestedAt);
                    command.Parameters.AddWithValue("@Status", "pending");
                    command.Parameters.AddWithValue("@Format", dto.Format);
                    await command.ExecuteNonQueryAsync();
                }
            }

            // Queue background job for export processing
            _backgroundJobQueue.QueueBackgroundWorkItem(async (token) =>
            {
                try
                {
                    // Generate export file
                    var filePath = await _exportService.GenerateExportAsync(userId, dto.Format, token);
                    
                    // Upload to S3
                    var s3Key = await _exportService.UploadToS3Async(filePath, $"text/{dto.Format}");
                    
                    // Generate signed URL
                    var fileUrl = await _exportService.GenerateSignedUrlAsync(s3Key);
                    
                    // Send email
                    var user = await GetUserAsync(userId, token);
                    await _exportService.SendEmailAsync(user.Email, fileUrl);
                    
                    // Update export request as completed
                    var completedAt = DateTime.UtcNow;
                    var expiresAt = completedAt.AddDays(7);
                    using (var connection = new SqlConnection(GetConnectionString()))
                    {
                        await connection.OpenAsync();
                        using (var command = new SqlCommand(
                            "UPDATE export_requests SET status = @Status, file_url = @FileUrl, completed_at = @CompletedAt, expires_at = @ExpiresAt WHERE id = @Id", connection))
                        {
                            command.Parameters.AddWithValue("@Status", "completed");
                            command.Parameters.AddWithValue("@FileUrl", fileUrl);
                            command.Parameters.AddWithValue("@CompletedAt", completedAt);
                            command.Parameters.AddWithValue("@ExpiresAt", expiresAt);
                            command.Parameters.AddWithValue("@Id", exportId);
                            await command.ExecuteNonQueryAsync();
                        }
                    }
                    
                    // Log audit
                    await LogAuditAsync(userId, "data_export_completed", new { export_id = exportId.ToString(), format = dto.Format }, token);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Export processing failed for user {UserId}", userId);
                    
                    // Update export request as failed
                    using (var connection = new SqlConnection(GetConnectionString()))
                    {
                        await connection.OpenAsync();
                        using (var command = new SqlCommand(
                            "UPDATE export_requests SET status = @Status WHERE id = @Id", connection))
                        {
                            command.Parameters.AddWithValue("@Status", "failed");
                            command.Parameters.AddWithValue("@Id", exportId);
                            await command.ExecuteNonQueryAsync();
                        }
                    }
                    
                    // Log audit failure
                    await LogAuditAsync(userId, "data_export_failed", new { export_id = exportId.ToString(), error = ex.Message }, token);
                }
                finally
                {
                    // Clean up temp file if exists
                    // (In reality would track filePath from generation step)
                }
            });

            return Ok(new ExportResponse
            {
                Success = true,
                ExportId = exportId.ToString(),
                Status = "pending",
                WillEmailAt = willEmailAt.ToString("o")
            });
        }

        [HttpGet("exports/{exportId}")]
        public async Task<IActionResult> GetExportStatus(Guid exportId)
        {
            using (var connection = new SqlConnection(GetConnectionString()))
            {
                await connection.OpenAsync();
                using (var command = new SqlCommand(
                    "SELECT id, user_id, requested_at, status, format, file_url, completed_at, expires_at FROM export_requests WHERE id = @Id", connection))
                {
                    command.Parameters.AddWithValue("@Id", exportId);
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (!await reader.ReadAsync())
                            return NotFound();

                        var status = reader.GetString(reader.GetOrdinal("status"));
                        var fileUrl = reader.IsDBNull(reader.GetOrdinal("file_url")) ? null : reader.GetString(reader.GetOrdinal("file_url"));
                        var expiresAt = reader.IsDBNull(reader.GetOrdinal("expires_at")) ? (DateTime?)null : reader.GetDateTime(reader.GetOrdinal("expires_at"));
                        var requestedAt = reader.GetDateTime(reader.GetOrdinal("requested_at"));
                        var completedAt = reader.IsDBNull(reader.GetOrdinal("completed_at")) ? (DateTime?)null : reader.GetDateTime(reader.GetOrdinal("completed_at"));

                        return Ok(new ExportStatusResponse
                        {
                            ExportId = exportId.ToString(),
                            Status = status,
                            FileUrl = fileUrl,
                            ExpiresAt = expiresAt?.ToString("o"),
                            RequestedAt = requestedAt.ToString("o")
                        });
                    }
                }
            }
        }

        [HttpPost("delete")]
        public async Task<IActionResult> RequestDeletion([FromBody] DeletionRequestDto dto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var userId = GetCurrentUserId();
            if (userId == Guid.Empty)
                return Unauthorized();

            // Generate confirmation token
            var confirmationToken = Guid.NewGuid().ToString(); // In reality would be encrypted token
            
            var deletionRequest = await _deletionService.RequestDeletionAsync(userId, dto.Reason, confirmationToken, HttpContext.RequestAborted);
            
            var willDeleteAt = deletionRequest.RequestedAt.AddDays(30);
            
            return Ok(new DeletionResponse
            {
                Success = true,
                DeletionId = deletionRequest.Id.ToString(),
                Status = deletionRequest.Status,
                WillDeleteAt = willDeleteAt.ToString("o")
            });
        }

        [HttpPost("delete/{deletionId}/confirm")]
        public async Task<IActionResult> ConfirmDeletion(Guid deletionId, [FromBody] ConfirmDeletionDto dto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            await _deletionService.ConfirmDeletionAsync(deletionId, dto.ConfirmationToken, HttpContext.RequestAborted);
            
            // Get the deletion request to return scheduled time
            var deletionRequest = await GetDeletionRequestAsync(deletionId, HttpContext.RequestAborted);
            var willDeleteAt = deletionRequest.RequestedAt.AddDays(30);
            
            return Ok(new DeletionConfirmationResponse
            {
                Success = true,
                DeletionScheduledFor = willDeleteAt.ToString("o")
            });
        }

        [HttpDelete("delete/{deletionId}")]
        public async Task<IActionResult> CancelDeletion(Guid deletionId)
        {
            await _deletionService.CancelDeletionAsync(deletionId, HttpContext.RequestAborted);
            return Ok(new { success = true, status = "cancelled" });
        }

        private Guid GetCurrentUserId()
        {
            // In reality would extract from JWT token or session
            // For simulation, return a fixed user ID
            return Guid.Parse("11111111-1111-1111-1111-111111111111");
        }

        private async Task<User> GetUserAsync(Guid userId, CancellationToken cancellationToken)
        {
            // In reality would call user service
            return new User { Id = userId, Email = "user@example.com", Name = "John Doe" };
        }

        private async Task<DeletionRequest> GetDeletionRequestAsync(Guid deletionId, CancellationToken cancellationToken)
        {
            using (var connection = new SqlConnection(GetConnectionString()))
            {
                await connection.OpenAsync();
                using (var command = new SqlCommand(
                    "SELECT id, user_id, requested_at, status, reason FROM deletion_requests WHERE id = @Id", connection))
                {
                    command.Parameters.AddWithValue("@Id", deletionId);
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (!await reader.ReadAsync())
                            throw new KeyNotFoundException("Deletion request not found");

                        return new DeletionRequest
                        {
                            Id = reader.GetGuid(reader.GetOrdinal("id")),
                            UserId = reader.GetGuid(reader.GetOrdinal("user_id")),
                            RequestedAt = reader.GetDateTime(reader.GetOrdinal("requested_at")),
                            Status = reader.GetString(reader.GetOrdinal("status")),
                            Reason = reader.GetString(reader.GetOrdinal("reason"))
                        };
                    }
                }
            }
        }

        private async Task LogAuditAsync(Guid userId, string action, object details, CancellationToken cancellationToken)
        {
            // In reality would use audit service
            await Task.CompletedTask;
        }

        private string GetConnectionString()
        {
            // In reality would get from configuration
            return "Server=localhost;Database=ComplianceDb;Trusted_Connection=True;";
        }
    }

    [ApiController]
    [Route("admin/compliance")]
    public class AdminComplianceController : ControllerBase
    {
        private readonly ILogger<AdminComplianceController> _logger;

        public AdminComplianceController(ILogger<AdminComplianceController> logger)
        {
            _logger = logger;
        }

        [HttpGet("exports")]
        public async Task<IActionResult> ListExports([FromQuery] Guid? userId, [FromQuery] string status)
        {
            var whereConditions = new List<string>();
            var parameters = new List<SqlParameter>();

            if (userId.HasValue)
            {
                whereConditions.Add("user_id = @UserId");
                parameters.Add(new SqlParameter("@UserId", userId.Value));
            }

            if (!string.IsNullOrEmpty(status))
            {
                whereConditions.Add("status = @Status");
                parameters.Add(new SqlParameter("@Status", status));
            }

            var whereClause = whereConditions.Any() ? "WHERE " + string.Join(" AND ", whereConditions) : "";

            var sql = $"SELECT id, user_id, requested_at, status, format, file_url, completed_at, expires_at FROM export_requests {whereClause}";
            
            var exports = new List<ExportRequest>();
            
            using (var connection = new SqlConnection(GetConnectionString()))
            {
                await connection.OpenAsync();
                using (var command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddRange(parameters.ToArray());
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        while (await reader.ReadAsync())
                        {
                            exports.Add(new ExportRequest
                            {
                                Id = reader.GetGuid(reader.GetOrdinal("id")),
                                UserId = reader.GetGuid(reader.GetOrdinal("user_id")),
                                RequestedAt = reader.GetDateTime(reader.GetOrdinal("requested_at")),
                                Status = reader.GetString(reader.GetOrdinal("status")),
                                Format = reader.GetString(reader.GetOrdinal("format")),
                                FileUrl = reader.IsDBNull(reader.GetOrdinal("file_url")) ? null : reader.GetString(reader.GetOrdinal("file_url")),
                                CompletedAt = reader.IsDBNull(reader.GetOrdinal("completed_at")) ? (DateTime?)null : reader.GetDateTime(reader.GetOrdinal("completed_at")),
                                ExpiresAt = reader.IsDBNull(reader.GetOrdinal("expires_at")) ? (DateTime?)null : reader.GetDateTime(reader.GetOrdinal("expires_at"))
                            });
                        }
                    }
                }
            }

            return Ok(new AdminExportResponse
            {
                Exports = exports,
                Total = exports.Count
            });
        }

        [HttpGet("deletions")]
        public async Task<IActionResult> ListDeletions([FromQuery] string status)
        {
            var whereConditions = new List<string>();
            var parameters = new List<SqlParameter>();

            if (!string.IsNullOrEmpty(status))
            {
                whereConditions.Add("status = @Status");
                parameters.Add(new SqlParameter("@Status", status));
            }

            var whereClause = whereConditions.Any() ? "WHERE " + string.Join(" AND ", whereConditions) : "";

            var sql = $"SELECT id, user_id, requested_at, status, reason, deleted_at FROM deletion_requests {whereClause}";
            
            var deletions = new List<DeletionRequest>();
            
            using (var connection = new SqlConnection(GetConnectionString()))
            {
                await connection.OpenAsync();
                using (var command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddRange(parameters.ToArray());
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        while (await reader.ReadAsync())
                        {
                            deletions.Add(new DeletionRequest
                            {
                                Id = reader.GetGuid(reader.GetOrdinal("id")),
                                UserId = reader.GetGuid(reader.GetOrdinal("user_id")),
                                RequestedAt = reader.GetDateTime(reader.GetOrdinal("requested_at")),
                                Status = reader.GetString(reader.GetOrdinal("status")),
                                Reason = reader.GetString(reader.GetOrdinal("reason")),
                                DeletedAt = reader.IsDBNull(reader.GetOrdinal("deleted_at")) ? (DateTime?)null : reader.GetDateTime(reader.GetOrdinal("deleted_at"))
                            });
                        }
                    }
                }
            }

            return Ok(new AdminDeletionResponse
            {
                Deletions = deletions,
                Total = deletions.Count
            });
        }

        private string GetConnectionString()
        {
            return "Server=localhost;Database=ComplianceDb;Trusted_Connection=True;";
        }
    }
}
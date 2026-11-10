// HTTP tests for the data export & compliance template. Changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP):
// the API now takes the user from a verified bearer token and keeps /admin for admins (the spec says "admin only"), so
// each test signs in as its own fresh user (minted with the test secret below) and the admin tests use an admin token;
// the background worker is removed from the test host so a new export stays "pending" until a test processes it
// on purpose; and RequestExport_JsonAndCsvFormatsBothWork compared the status with the format although the test above
// it requires "pending" for the same request (it now checks status pending and the echoed format). New tests cover
// anonymous and non-admin access, other users' requests, the emailed confirmation token, the built export and its
// signed link, and the cascade after the grace period. Touches: an in-process test server; no network.
using System;
using System.Collections.Generic;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ComplianceModule;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace ComplianceModule.Tests
{
    public class CustomWebApplicationFactory<TStartup> : WebApplicationFactory<TStartup> where TStartup : class
    {
        /// <summary>The token signing secret of the test host (a test value, not a real secret).</summary>
        public const string JwtSecret = "compliance-tests-signing-secret-0123456789abcdef";

        /// <summary>
        /// Points WebApplicationFactory at a content root. It otherwise looks for a solution (.sln) above the test
        /// binaries, which a single-assembly build (app and tests compiled together, as the library's runner does) does
        /// not have. WebApplicationFactory reads the documented ASPNETCORE_TEST_CONTENTROOT_&lt;ASSEMBLY&gt; setting
        /// first. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: this process's environment.
        /// </summary>
        static CustomWebApplicationFactory()
        {
            var assembly = typeof(TStartup).Assembly.GetName().Name!.ToUpperInvariant().Replace(".", "_");
            Environment.SetEnvironmentVariable($"ASPNETCORE_TEST_CONTENTROOT_{assembly}", AppContext.BaseDirectory);
        }

        /// <summary>
        /// An HS256 bearer token for a user (role "admin" for an admin), valid 15 minutes, signed with
        /// <see cref="JwtSecret"/>. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Pure.
        /// </summary>
        public static string Token(Guid userId, string role = null)
        {
            var claims = new List<Claim> { new Claim("sub", userId.ToString()) };
            if (role != null) claims.Add(new Claim("role", role));
            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(handler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(15),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtSecret)), SecurityAlgorithms.HmacSha256)
            }));
        }

        protected override IHost CreateHost(IHostBuilder builder)
        {
            builder.ConfigureAppConfiguration(config =>
                config.AddInMemoryCollection(new Dictionary<string, string> { ["Auth:JwtSecret"] = JwtSecret }));
            builder.ConfigureServices(services =>
            {
                // No background worker in tests: exports stay "pending" until a test runs ExportProcessor itself.
                var worker = services.SingleOrDefault(d => d.ImplementationType == typeof(ComplianceWorker));
                if (worker != null)
                    services.Remove(worker);

                // Remove the existing DbContext registration
                var descriptor = services.SingleOrDefault(
                    d => d.ServiceType == typeof(DbContextOptions<ComplianceDbContext>));
                if (descriptor != null)
                    services.Remove(descriptor);

                // Add DbContext using an in-memory database for testing
                services.AddDbContext<ComplianceDbContext>(options =>
                {
                    options.UseInMemoryDatabase("ComplianceTestDb");
                });

                // Build the service provider
                var serviceProvider = services.BuildServiceProvider();

                // Create a scope to obtain a reference to the database
                using (var scope = serviceProvider.CreateScope())
                {
                    var scopedServices = scope.ServiceProvider;
                    var db = scopedServices.GetRequiredService<ComplianceDbContext>();
                    try
                    {
                        // Ensure the database is created
                        db.Database.EnsureCreated();
                    }
                    catch (Exception ex)
                    {
                        throw new Exception("An error occurred seeding the database with test messages. Error: " + ex.Message);
                    }
                }
            });

            return base.CreateHost(builder);
        }
    }

    public class ComplianceApiTests : IClassFixture<CustomWebApplicationFactory<ComplianceModule.Startup>>
    {
        private readonly HttpClient _client;
        private readonly HttpClient _adminClient;
        private readonly Guid _userId = Guid.NewGuid();
        private readonly CustomWebApplicationFactory<ComplianceModule.Startup> _factory;

        public ComplianceApiTests(CustomWebApplicationFactory<ComplianceModule.Startup> factory)
        {
            _factory = factory;
            // Each test is its own signed-in user, seeded in the development user store.
            _client = factory.CreateClient();
            _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", CustomWebApplicationFactory<ComplianceModule.Startup>.Token(_userId));
            _adminClient = factory.CreateClient();
            _adminClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", CustomWebApplicationFactory<ComplianceModule.Startup>.Token(Guid.NewGuid(), "admin"));
            factory.Services.GetRequiredService<InMemoryUserDataStore>().Seed(_userId, SampleUser(_userId));
        }

        /// <summary>A user's data document with every category the spec lists. Pure.</summary>
        private static JObject SampleUser(Guid id) => new JObject
        {
            ["profile"] = new JObject { ["id"] = id.ToString(), ["email"] = $"{id:N}@example.test", ["name"] = "Test User", ["tier"] = "team", ["status"] = "active" },
            ["sessions"] = new JArray(new JObject { ["ip"] = "203.0.113.7", ["device_info"] = "Firefox on Linux" }),
            ["activity"] = new JArray(new JObject { ["action"] = "login" }),
            ["files"] = new JArray(new JObject { ["name"] = "report.pdf", ["size"] = 2048 }),
            ["preferences"] = new JObject { ["theme"] = "dark", ["language"] = "en" },
            ["transactions"] = new JArray(new JObject { ["amount"] = 19.99, ["note"] = "=HYPERLINK(\"x\")" }),
            ["audit_trail"] = new JArray(new JObject { ["action"] = "profile_update" })
        };

        [Fact]
        public async Task RequestExport_ReturnsPendingStatus()
        {
            // Arrange
            var request = new ExportRequestDto { Format = "json" };
            using var content = new StringContent(JsonConvert.SerializeObject(request), Encoding.UTF8, "application/json");

            // Act
            var response = await _client.PostAsync("/compliance/export", content);

            // Assert
            response.EnsureSuccessStatusCode();
            var responseString = await response.Content.ReadAsStringAsync();
            var exportResponse = JsonConvert.DeserializeObject<ExportResponse>(responseString);
            
            Assert.True(exportResponse.Success);
            Assert.Equal("pending", exportResponse.Status);
            Assert.NotNull(exportResponse.ExportId);
            Assert.NotNull(exportResponse.WillEmailAt);
        }

        // EXPORT-01
        [Fact]
        public async Task RequestExport_JsonAndCsvFormatsBothWork()
        {
            // Test JSON
            var jsonRequest = new ExportRequestDto { Format = "json" };
            using var jsonContent = new StringContent(JsonConvert.SerializeObject(jsonRequest), Encoding.UTF8, "application/json");
            var jsonResponse = await _client.PostAsync("/compliance/export", jsonContent);
            jsonResponse.EnsureSuccessStatusCode();
            var jsonResponseString = await jsonResponse.Content.ReadAsStringAsync();
            var jsonExportResponse = JsonConvert.DeserializeObject<ExportResponse>(jsonResponseString);
            Assert.Equal("pending", jsonExportResponse.Status);
            Assert.Equal("json", jsonExportResponse.Format);

            // Test CSV
            var csvRequest = new ExportRequestDto { Format = "csv" };
            using var csvContent = new StringContent(JsonConvert.SerializeObject(csvRequest), Encoding.UTF8, "application/json");
            var csvResponse = await _client.PostAsync("/compliance/export", csvContent);
            csvResponse.EnsureSuccessStatusCode();
            var csvResponseString = await csvResponse.Content.ReadAsStringAsync();
            var csvExportResponse = JsonConvert.DeserializeObject<ExportResponse>(csvResponseString);
            Assert.Equal("pending", csvExportResponse.Status);
            Assert.Equal("csv", csvExportResponse.Format);

            // both files are built and download in their format (added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP:
            // the test only checked the requests were accepted)
            using (var scope = _factory.Services.CreateScope())
                await scope.ServiceProvider.GetRequiredService<ExportProcessor>().ProcessPendingExportsAsync(CancellationToken.None);
            var anonymous = _factory.CreateClient();
            var jsonFile = await anonymous.GetStringAsync((await Status(jsonExportResponse.ExportId)).FileUrl);
            Assert.Equal($"{_userId:N}@example.test", (string)JObject.Parse(jsonFile).SelectToken("profile.email"));
            var csvFile = await anonymous.GetStringAsync((await Status(csvExportResponse.ExportId)).FileUrl);
            Assert.StartsWith("section,path,value\n", csvFile);
            Assert.Contains("\"profile\",\"profile.email\"", csvFile);
        }

        /// <summary>GET /compliance/exports/{id} as the test user. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private async Task<ExportStatusResponse> Status(string exportId)
        {
            var r = await _client.GetAsync($"/compliance/exports/{exportId}");
            r.EnsureSuccessStatusCode();
            return JsonConvert.DeserializeObject<ExportStatusResponse>(await r.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task GetExportStatus_ReturnsCorrectStatus()
        {
            // First request an export
            var exportRequest = new ExportRequestDto { Format = "json" };
            using var exportContent = new StringContent(JsonConvert.SerializeObject(exportRequest), Encoding.UTF8, "application/json");
            var exportResponse = await _client.PostAsync("/compliance/export", exportContent);
            exportResponse.EnsureSuccessStatusCode();
            var exportResponseString = await exportResponse.Content.ReadAsStringAsync();
            var exportResponseObj = JsonConvert.DeserializeObject<ExportResponse>(exportResponseString);
            var exportId = exportResponseObj.ExportId;

            // Then check its status
            var statusResponse = await _client.GetAsync($"/compliance/exports/{exportId}");
            statusResponse.EnsureSuccessStatusCode();
            var statusResponseString = await statusResponse.Content.ReadAsStringAsync();
            var statusResponseObj = JsonConvert.DeserializeObject<ExportStatusResponse>(statusResponseString);
            
            Assert.Equal(exportId, statusResponseObj.ExportId);
            Assert.Equal("pending", statusResponseObj.Status);
        }

        // EXPORT-05
        [Fact]
        public async Task RequestDeletion_ReturnsPendingStatusWithGracePeriod()
        {
            // Arrange
            // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-05/12 amendment): the 30-day grace period is for
            // user_requested / other; gdpr_request now has none (see Deletion_StatutoryReason_HasNoGracePeriod).
            var request = new DeletionRequestDto { Reason = "user_requested" };
            using var content = new StringContent(JsonConvert.SerializeObject(request), Encoding.UTF8, "application/json");

            // Act
            var response = await _client.PostAsync("/compliance/delete", content);

            // Assert
            response.EnsureSuccessStatusCode();
            var responseString = await response.Content.ReadAsStringAsync();
            var deletionResponse = JsonConvert.DeserializeObject<DeletionResponse>(responseString);
            
            Assert.True(deletionResponse.Success);
            Assert.Equal("pending", deletionResponse.Status);
            Assert.NotNull(deletionResponse.DeletionId);
            Assert.NotNull(deletionResponse.WillDeleteAt);
            
            // Verify will_delete_at is approximately 30 days from now
            var willDeleteAt = DateTime.Parse(deletionResponse.WillDeleteAt, null, System.Globalization.DateTimeStyles.RoundtripKind);
            var now = DateTime.UtcNow;
            Assert.InRange(willDeleteAt.Subtract(now).TotalDays, 29, 31);
            using var scope = _factory.Services.CreateScope();
            var row = await scope.ServiceProvider.GetRequiredService<ComplianceDbContext>().DeletionRequests.AsNoTracking()
                .SingleAsync(d => d.Id == Guid.Parse(deletionResponse.DeletionId));
            Assert.Equal(row.RequestedAt.AddDays(30), row.ScheduledFor); // exactly requested_at + 30 days
        }

        // EXPORT-06
        [Fact]
        public async Task DeletionCanBeCancelledWithinGracePeriod()
        {
            // Request deletion
            var request = new DeletionRequestDto { Reason = "user_requested" };
            using var requestContent = new StringContent(JsonConvert.SerializeObject(request), Encoding.UTF8, "application/json");
            var requestResponse = await _client.PostAsync("/compliance/delete", requestContent);
            requestResponse.EnsureSuccessStatusCode();
            var requestResponseString = await requestResponse.Content.ReadAsStringAsync();
            var requestResponseObj = JsonConvert.DeserializeObject<DeletionResponse>(requestResponseString);
            var deletionId = requestResponseObj.DeletionId;

            // Cancel deletion
            var cancelResponse = await _client.DeleteAsync($"/compliance/delete/{deletionId}");
            cancelResponse.EnsureSuccessStatusCode();
            var cancelResponseString = await cancelResponse.Content.ReadAsStringAsync();
            var cancelResponseObj = JsonConvert.DeserializeObject<dynamic>(cancelResponseString);
            
            Assert.True((bool)cancelResponseObj.success);
            Assert.Equal("cancelled", (string)cancelResponseObj.status);
        }

        [Fact]
        public async Task DeletionRequiresConfirmationToken()
        {
            // Request deletion
            var request = new DeletionRequestDto { Reason = "gdpr_right_to_be_forgotten" };
            using var requestContent = new StringContent(JsonConvert.SerializeObject(request), Encoding.UTF8, "application/json");
            var requestResponse = await _client.PostAsync("/compliance/delete", requestContent);
            requestResponse.EnsureSuccessStatusCode();
            var requestResponseString = await requestResponse.Content.ReadAsStringAsync();
            var requestResponseObj = JsonConvert.DeserializeObject<DeletionResponse>(requestResponseString);
            var deletionId = requestResponseObj.DeletionId;

            // Attempt to confirm with invalid token
            var confirmRequest = new ConfirmDeletionDto { ConfirmationToken = "invalid_token" };
            using var confirmContent = new StringContent(JsonConvert.SerializeObject(confirmRequest), Encoding.UTF8, "application/json");
            var confirmResponse = await _client.PostAsync($"/compliance/delete/{deletionId}/confirm", confirmContent);
            Assert.Equal(HttpStatusCode.BadRequest, confirmResponse.StatusCode); // Or Unauthorized, depending on implementation

            // Confirm with valid token would require token generation logic - skipped for brevity
            // In a real test we would generate a valid token using the same encryption as the service
        }

        // EXPORT-10
        [Fact]
        public async Task AdminCanListExportRequests()
        {
            // Create a couple of export requests
            await CreateTestExportRequest("json");
            await CreateTestExportRequest("csv");

            // Request admin endpoint
            var response = await _adminClient.GetAsync("/admin/compliance/exports");
            response.EnsureSuccessStatusCode();
            var responseString = await response.Content.ReadAsStringAsync();
            var adminResponse = JsonConvert.DeserializeObject<AdminExportResponse>(responseString);
            
            Assert.True(adminResponse.Total >= 2);
            Assert.Contains(adminResponse.Exports, e => e.Format == "json");
            Assert.Contains(adminResponse.Exports, e => e.Format == "csv");
        }

        // EXPORT-10
        [Fact]
        public async Task AdminCanListDeletionRequestsByStatus()
        {
            // Create a pending deletion request
            await CreateTestDeletionRequest("pending", "user_requested");
            
            // Request admin endpoint for pending deletions
            var response = await _adminClient.GetAsync("/admin/compliance/deletions?status=pending");
            response.EnsureSuccessStatusCode();
            var responseString = await response.Content.ReadAsStringAsync();
            var adminResponse = JsonConvert.DeserializeObject<AdminDeletionResponse>(responseString);
            
            Assert.True(adminResponse.Total >= 1);
            Assert.All(adminResponse.Deletions, d => Assert.Equal("pending", d.Status));
        }

        /// <summary>No token: 401. A user's token on an admin endpoint: 403. Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP).</summary>
        [Fact]
        public async Task AnonymousAndNonAdminCallersAreRefused()
        {
            var anonymous = _factory.CreateClient();
            using var content = new StringContent(JsonConvert.SerializeObject(new ExportRequestDto { Format = "json" }), Encoding.UTF8, "application/json");
            Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsync("/compliance/export", content)).StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/admin/compliance/exports")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await _client.GetAsync("/admin/compliance/exports")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await _client.GetAsync("/admin/compliance/deletions")).StatusCode);
        }

        /// <summary>Another user can neither read an export nor cancel a deletion by id (404, as if absent). Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP).</summary>
        [Fact]
        public async Task OtherUsersCannotReadOrCancelMyRequests()
        {
            var export = await PostAs<ExportResponse>(_client, "/compliance/export", new ExportRequestDto { Format = "csv" });
            var deletion = await PostAs<DeletionResponse>(_client, "/compliance/delete", new DeletionRequestDto { Reason = "other" });

            var stranger = _factory.CreateClient();
            stranger.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", CustomWebApplicationFactory<ComplianceModule.Startup>.Token(Guid.NewGuid()));
            Assert.Equal(HttpStatusCode.NotFound, (await stranger.GetAsync($"/compliance/exports/{export.ExportId}")).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await stranger.DeleteAsync($"/compliance/delete/{deletion.DeletionId}")).StatusCode);
        }

        /// <summary>
        /// The emailed token confirms the deletion (once); after the 30-day grace period the cascade removes the user's
        /// data and the audit log survives. Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP).
        /// </summary>
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-12/13 amendment): reason user_requested (a gdpr
        // reason has no grace period now); the audit rows are found by id after the deletion, because erase_subject
        // removes their link to the user; 'user_deleted_cascade' is logged instead of 'deletion_completed'.
        // EXPORT-08
        // EXPORT-09
        [Fact]
        public async Task ConfirmedDeletionCascadesAfterGracePeriodAndKeepsAudit()
        {
            var deletion = await PostAs<DeletionResponse>(_client, "/compliance/delete", new DeletionRequestDto { Reason = "user_requested" });
            var mailer = _factory.Services.GetRequiredService<DevelopmentComplianceMailer>();
            var token = mailer.Sent.Last(m => m.DeletionId == Guid.Parse(deletion.DeletionId)).Secret;

            var confirm = await PostAs<DeletionConfirmationResponse>(_client, $"/compliance/delete/{deletion.DeletionId}/confirm", new ConfirmDeletionDto { ConfirmationToken = token });
            Assert.True(confirm.Success);
            using var againContent = new StringContent(JsonConvert.SerializeObject(new ConfirmDeletionDto { ConfirmationToken = token }), Encoding.UTF8, "application/json");
            var again = await _client.PostAsync($"/compliance/delete/{deletion.DeletionId}/confirm", againContent);
            Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);

            var store = _factory.Services.GetRequiredService<InMemoryUserDataStore>();
            using var scope = _factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ComplianceDbContext>();
            var auditIds = await db.AuditLogs.Where(a => a.UserId == _userId).Select(a => a.Id).ToListAsync();
            var processor = scope.ServiceProvider.GetRequiredService<ExportProcessor>();
            Assert.Equal(0, await processor.ProcessDueDeletionsAsync(DateTime.UtcNow.AddDays(29), CancellationToken.None));
            Assert.True(store.Exists(_userId));
            await processor.ProcessDueDeletionsAsync(DateTime.UtcNow.AddDays(31), CancellationToken.None);
            Assert.False(store.Exists(_userId));

            // EXPORT-08: every earlier audit row is still there, no longer linked to the user
            var kept = await db.AuditLogs.AsNoTracking().Where(a => auditIds.Contains(a.Id)).ToListAsync();
            Assert.Equal(auditIds.Count, kept.Count);
            Assert.All(kept, a => Assert.True(a.PersonalErased && a.UserId == Guid.Empty));
            var actions = kept.Select(a => a.Action).ToList();
            Assert.Contains("deletion_requested", actions);
            Assert.Contains("deletion_confirmed", actions);
            Assert.Contains(await db.AuditLogs.AsNoTracking().ToListAsync(), a => a.Action == "user_deleted_cascade" && a.Details.Contains(deletion.DeletionId));
        }

        /// <summary>
        /// A processed export is completed with a 7-day signed link that downloads a file holding every data category,
        /// CSV-formula-safe; a tampered or expired link is refused. Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP).
        /// </summary>
        // EXPORT-02
        // EXPORT-03
        // EXPORT-04
        [Fact]
        public async Task ProcessedExportHasWorkingSignedLink()
        {
            var export = await PostAs<ExportResponse>(_client, "/compliance/export", new ExportRequestDto { Format = "csv" });
            using (var scope = _factory.Services.CreateScope())
                await scope.ServiceProvider.GetRequiredService<ExportProcessor>().ProcessPendingExportsAsync(CancellationToken.None);

            var status = JsonConvert.DeserializeObject<ExportStatusResponse>(await (await _client.GetAsync($"/compliance/exports/{export.ExportId}")).Content.ReadAsStringAsync());
            Assert.Equal("completed", status.Status);
            Assert.InRange(DateTime.Parse(status.ExpiresAt, null, System.Globalization.DateTimeStyles.RoundtripKind).Subtract(DateTime.UtcNow).TotalDays, 6.9, 7.1);
            // EXPORT-03: the link was emailed to the user (assert added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
            Assert.Contains(_factory.Services.GetRequiredService<DevelopmentComplianceMailer>().Sent,
                m => m.Kind == "export_ready" && m.To == $"{_userId:N}@example.test" && m.Secret == status.FileUrl);

            var anonymous = _factory.CreateClient();
            var file = await anonymous.GetStringAsync(status.FileUrl);
            foreach (var section in new[] { "profile", "sessions", "activity", "files", "preferences", "transactions", "audit_trail" })
                Assert.Contains($"\"{section}\"", file);
            Assert.Contains("\"'=HYPERLINK", file);

            var tampered = status.FileUrl.Replace("signature=", "signature=x");
            Assert.Equal(HttpStatusCode.Forbidden, (await anonymous.GetAsync(tampered)).StatusCode);
            var expired = System.Text.RegularExpressions.Regex.Replace(status.FileUrl, "expires=\\d+", "expires=1");
            Assert.Equal(HttpStatusCode.Forbidden, (await anonymous.GetAsync(expired)).StatusCode);
        }

        /// <summary>
        /// EXPORT-07 / EXPORT-08: after the grace period the deletion removes the user's export files and export
        /// requests, so the export link that worked before is refused (404) and storage no longer holds the file; the
        /// audit log survives. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review on PR 19:
        /// a deleted user's unexpired signed link still downloaded the export). Touches: the in-process test server.
        /// </summary>
        // EXPORT-07
        [Fact]
        public async Task DeletedUsersExportLinkIsRefusedAndFileIsGone()
        {
            var export = await PostAs<ExportResponse>(_client, "/compliance/export", new ExportRequestDto { Format = "json" });
            using (var scope = _factory.Services.CreateScope())
                await scope.ServiceProvider.GetRequiredService<ExportProcessor>().ProcessPendingExportsAsync(CancellationToken.None);
            var status = JsonConvert.DeserializeObject<ExportStatusResponse>(await (await _client.GetAsync($"/compliance/exports/{export.ExportId}")).Content.ReadAsStringAsync());
            Assert.Equal("completed", status.Status);
            var anonymous = _factory.CreateClient();
            Assert.Equal(HttpStatusCode.OK, (await anonymous.GetAsync(status.FileUrl)).StatusCode); // the link works before

            var deletionId = await ConfirmDeletionAsync();
            using (var scope = _factory.Services.CreateScope())
                await scope.ServiceProvider.GetRequiredService<ExportProcessor>().ProcessDueDeletionsAsync(DateTime.UtcNow.AddDays(31), CancellationToken.None);

            Assert.Equal(HttpStatusCode.NotFound, (await anonymous.GetAsync(status.FileUrl)).StatusCode); // same, unexpired link
            var key = $"exports/{_userId}/{export.ExportId}.json";
            Assert.Null(await _factory.Services.GetRequiredService<IExportStorage>().GetAsync(key, CancellationToken.None));
            using (var scope = _factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<ComplianceDbContext>();
                Assert.False(await db.ExportRequests.AnyAsync(e => e.UserId == _userId));
                // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-13): the request's user_id is NULL once
                // completed and the audit rows lose their link to the user, so both are found by the export/deletion id.
                var completed = await db.DeletionRequests.SingleAsync(d => d.Id == deletionId);
                Assert.Equal("completed", completed.Status);
                Assert.Null(completed.UserId);
                var actions = (await db.AuditLogs.AsNoTracking().ToListAsync())
                    .Where(a => a.Details.Contains(export.ExportId) || a.Details.Contains(deletionId.ToString())).Select(a => a.Action).ToList();
                Assert.Contains("data_export_requested", actions);
                Assert.Contains("data_export_completed", actions);
                Assert.Contains("user_deleted_cascade", actions);
                Assert.False(await db.AuditLogs.AnyAsync(a => a.UserId == _userId));
            }
        }

        /// <summary>
        /// When the export files cannot be deleted, the account deletion is not marked completed: it stays approved
        /// (the user's data untouched) and the next pass, with working storage, completes it. Added 2026-11-10, session
        /// session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review on PR 19). Touches: the in-process test server.
        /// </summary>
        [Fact]
        public async Task DeletionStaysRetryableWhenExportCleanupFails()
        {
            await PostAs<ExportResponse>(_client, "/compliance/export", new ExportRequestDto { Format = "csv" });
            var deletionId = await ConfirmDeletionAsync();
            var store = _factory.Services.GetRequiredService<InMemoryUserDataStore>();
            var later = DateTime.UtcNow.AddDays(31);

            using (var scope = _factory.Services.CreateScope())
            {
                var sp = scope.ServiceProvider;
                var broken = new ExportProcessor(sp.GetRequiredService<ComplianceDbContext>(), sp.GetRequiredService<IUserDataStore>(),
                    new StorageThatCannotDelete(sp.GetRequiredService<IExportStorage>()), sp.GetRequiredService<IComplianceMailer>(),
                    NullLogger<ExportProcessor>.Instance);
                await broken.ProcessDueDeletionsAsync(later, CancellationToken.None);
                var db = sp.GetRequiredService<ComplianceDbContext>();
                Assert.Equal("approved", (await db.DeletionRequests.AsNoTracking().SingleAsync(d => d.UserId == _userId)).Status);
                Assert.True(await db.ExportRequests.AnyAsync(e => e.UserId == _userId));
                Assert.Contains("deletion_export_cleanup_failed", await db.AuditLogs.Where(a => a.UserId == _userId).Select(a => a.Action).ToListAsync());
            }
            Assert.True(store.Exists(_userId));

            using (var scope = _factory.Services.CreateScope())
            {
                await scope.ServiceProvider.GetRequiredService<ExportProcessor>().ProcessDueDeletionsAsync(later, CancellationToken.None);
                var db = scope.ServiceProvider.GetRequiredService<ComplianceDbContext>();
                // by id: user_id is NULL once completed (EXPORT-13; changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
                Assert.Equal("completed", (await db.DeletionRequests.AsNoTracking().SingleAsync(d => d.Id == deletionId)).Status);
                Assert.False(await db.ExportRequests.AnyAsync(e => e.UserId == _userId));
            }
            Assert.False(store.Exists(_userId));
        }

        /// <summary>Export storage whose delete always fails; everything else goes to the real storage. Test double.</summary>
        private sealed class StorageThatCannotDelete : IExportStorage
        {
            private readonly IExportStorage _inner;
            public StorageThatCannotDelete(IExportStorage inner) => _inner = inner;
            public Task PutAsync(string key, byte[] content, string contentType, CancellationToken ct) => _inner.PutAsync(key, content, contentType, ct);
            public Task<(byte[] Content, string ContentType)?> GetAsync(string key, CancellationToken ct) => _inner.GetAsync(key, ct);
            public Task DeleteAsync(string key, CancellationToken ct) => throw new System.IO.IOException("storage unavailable");
            public string CreateDownloadUrl(string key, DateTimeOffset expiresAt) => _inner.CreateDownloadUrl(key, expiresAt);
            public bool VerifyDownload(string key, long expiresUnix, string signature, DateTimeOffset now) => _inner.VerifyDownload(key, expiresUnix, signature, now);
        }

        /// <summary>
        /// Requests this test user's deletion (user_requested: 30-day grace) and confirms it with the emailed token.
        /// Out: the deletion id. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: was gdpr_request, which now runs
        /// the cascade at confirm (EXPORT-12); returns the id because user_id is NULL after completion.
        /// </summary>
        private async Task<Guid> ConfirmDeletionAsync()
        {
            var deletion = await PostAs<DeletionResponse>(_client, "/compliance/delete", new DeletionRequestDto { Reason = "user_requested" });
            var token = _factory.Services.GetRequiredService<DevelopmentComplianceMailer>().Sent.Last(m => m.DeletionId == Guid.Parse(deletion.DeletionId)).Secret;
            var confirm = await PostAs<DeletionConfirmationResponse>(_client, $"/compliance/delete/{deletion.DeletionId}/confirm", new ConfirmDeletionDto { ConfirmationToken = token });
            Assert.True(confirm.Success);
            return Guid.Parse(deletion.DeletionId);
        }

        /// <summary>The emailed confirmation token of a deletion. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private string TokenOf(string deletionId) =>
            _factory.Services.GetRequiredService<DevelopmentComplianceMailer>().Sent.Last(m => m.DeletionId == Guid.Parse(deletionId)).Secret;

        /// <summary>POSTs a confirm with a token and returns the raw response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private async Task<HttpResponseMessage> Confirm(HttpClient client, string deletionId, string token)
        {
            using var content = new StringContent(JsonConvert.SerializeObject(new ConfirmDeletionDto { ConfirmationToken = token }), Encoding.UTF8, "application/json");
            return await client.PostAsync($"/compliance/delete/{deletionId}/confirm", content);
        }

        /// <summary>
        /// EXPORT-12: a gdpr_request or gdpr_right_to_be_forgotten deletion is not held for 30 days: will_delete_at =
        /// requested_at, nothing is deleted before confirm, and confirm runs the cascade before it returns (status
        /// completed, deleted_at = deletion_scheduled_for = now). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        // EXPORT-12
        [Fact]
        public async Task Deletion_StatutoryReason_HasNoGracePeriod()
        {
            foreach (var reason in new[] { "gdpr_request", "gdpr_right_to_be_forgotten" })
            {
                var userId = Guid.NewGuid();
                _factory.Services.GetRequiredService<InMemoryUserDataStore>().Seed(userId, SampleUser(userId));
                var client = _factory.CreateClient();
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", CustomWebApplicationFactory<ComplianceModule.Startup>.Token(userId));

                var deletion = await PostAs<DeletionResponse>(client, "/compliance/delete", new DeletionRequestDto { Reason = reason });
                using (var scope = _factory.Services.CreateScope())
                {
                    var row = await scope.ServiceProvider.GetRequiredService<ComplianceDbContext>().DeletionRequests.AsNoTracking().SingleAsync(d => d.Id == Guid.Parse(deletion.DeletionId));
                    Assert.Equal(row.RequestedAt, row.ScheduledFor);
                    Assert.Equal(ComplianceService.Iso(row.RequestedAt), deletion.WillDeleteAt);
                    // nothing is deleted before confirm, even when the worker runs
                    await scope.ServiceProvider.GetRequiredService<ExportProcessor>().ProcessDueDeletionsAsync(DateTime.UtcNow.AddDays(400), CancellationToken.None);
                }
                Assert.True(_factory.Services.GetRequiredService<InMemoryUserDataStore>().Exists(userId));

                var confirmResponse = await Confirm(client, deletion.DeletionId, TokenOf(deletion.DeletionId));
                confirmResponse.EnsureSuccessStatusCode();
                var confirm = JsonConvert.DeserializeObject<DeletionConfirmationResponse>(await confirmResponse.Content.ReadAsStringAsync());
                Assert.Equal("completed", confirm.Status);
                Assert.False(_factory.Services.GetRequiredService<InMemoryUserDataStore>().Exists(userId));
                using (var scope = _factory.Services.CreateScope())
                {
                    var row = await scope.ServiceProvider.GetRequiredService<ComplianceDbContext>().DeletionRequests.AsNoTracking().SingleAsync(d => d.Id == Guid.Parse(deletion.DeletionId));
                    Assert.Equal(row.ScheduledFor, row.DeletedAt);
                    Assert.Equal(ComplianceService.Iso(row.ScheduledFor), confirm.DeletionScheduledFor);
                    Assert.Null(row.UserId);
                }
            }
        }

        /// <summary>
        /// EXPORT-13: the cascade deletes the user's rows, logs 'user_deleted_cascade', then calls the audit eraser's
        /// erase_subject(user_id) LAST, and nothing is logged for the user after it; deletion_requests.user_id is NULL
        /// once completed. A recording eraser checks the state at the moment it is called. Added 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        // EXPORT-13
        [Fact]
        public async Task DeletionCascade_Order_EraseSubjectLast()
        {
            var deletionId = await ConfirmDeletionAsync();
            using var scope = _factory.Services.CreateScope();
            var sp = scope.ServiceProvider;
            var db = sp.GetRequiredService<ComplianceDbContext>();
            var store = sp.GetRequiredService<InMemoryUserDataStore>();
            var eraser = new RecordingEraser(db, store);
            var processor = new ExportProcessor(db, sp.GetRequiredService<IUserDataStore>(), sp.GetRequiredService<IExportStorage>(),
                sp.GetRequiredService<IComplianceMailer>(), NullLogger<ExportProcessor>.Instance, eraser);

            await processor.ProcessDueDeletionsAsync(DateTime.UtcNow.AddDays(31), CancellationToken.None);

            Assert.Equal(new[] { _userId }, eraser.Calls);
            Assert.False(eraser.UserExistedAtCall, "the user's rows are deleted before erase_subject");
            Assert.True(eraser.CascadeLoggedAtCall, "'user_deleted_cascade' is logged before erase_subject");
            var rows = await db.AuditLogs.AsNoTracking().ToListAsync();
            Assert.Equal(eraser.AuditRowsAtCall, rows.Count); // nothing logged after erase_subject
            Assert.DoesNotContain(rows, a => a.UserId == _userId || a.ActorId == _userId);
            var completed = await db.DeletionRequests.AsNoTracking().SingleAsync(d => d.Id == deletionId);
            Assert.Equal("completed", completed.Status);
            Assert.Null(completed.UserId);
        }

        /// <summary>An audit eraser that records what was true when it was called, then erases like the default one. Test double.</summary>
        private sealed class RecordingEraser : IAuditEraser
        {
            private readonly ComplianceDbContext _db;
            private readonly InMemoryUserDataStore _store;
            public readonly List<Guid> Calls = new();
            public bool UserExistedAtCall;
            public bool CascadeLoggedAtCall;
            public int AuditRowsAtCall;

            public RecordingEraser(ComplianceDbContext db, InMemoryUserDataStore store) { _db = db; _store = store; }

            public async Task EraseSubjectAsync(Guid userId, CancellationToken ct)
            {
                Calls.Add(userId);
                UserExistedAtCall = _store.Exists(userId);
                CascadeLoggedAtCall = _db.AuditLogs.Local.Any(a => a.UserId == userId && a.Action == "user_deleted_cascade");
                AuditRowsAtCall = await _db.AuditLogs.CountAsync(ct) + _db.AuditLogs.Local.Count(a => _db.Entry(a).State == EntityState.Added);
                await new LocalAuditEraser(_db).EraseSubjectAsync(userId, ct);
            }
        }

        /// <summary>
        /// EXPORT-14: nothing is deleted before confirm; a wrong token is refused (400) and changes nothing; a token over
        /// 24 h old is refused (400); a reused token is refused (409, already confirmed); another user's request is 404 for
        /// confirm and cancel. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Moves the shared clock and restores it.
        /// </summary>
        // EXPORT-14
        [Fact]
        public async Task DeletionConfirmation_WrongReusedExpiredForeign_AllRefused()
        {
            var store = _factory.Services.GetRequiredService<InMemoryUserDataStore>();
            var deletion = await PostAs<DeletionResponse>(_client, "/compliance/delete", new DeletionRequestDto { Reason = "user_requested" });
            var token = TokenOf(deletion.DeletionId);
            Assert.True(store.Exists(_userId));

            Assert.Equal(HttpStatusCode.BadRequest, (await Confirm(_client, deletion.DeletionId, token.Substring(0, token.Length - 1) + (token.EndsWith("A") ? "B" : "A"))).StatusCode);

            var stranger = _factory.CreateClient();
            stranger.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", CustomWebApplicationFactory<ComplianceModule.Startup>.Token(Guid.NewGuid()));
            Assert.Equal(HttpStatusCode.NotFound, (await Confirm(stranger, deletion.DeletionId, token)).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await stranger.DeleteAsync($"/compliance/delete/{deletion.DeletionId}")).StatusCode);

            var clock = _factory.Services.GetRequiredService<ComplianceClock>();
            var original = clock.Now;
            try
            {
                clock.Now = () => DateTime.UtcNow.AddHours(24).AddMinutes(1);
                Assert.Equal(HttpStatusCode.BadRequest, (await Confirm(_client, deletion.DeletionId, token)).StatusCode);
            }
            finally
            {
                clock.Now = original;
            }
            Assert.True(store.Exists(_userId)); // nothing deleted by any refused attempt

            (await Confirm(_client, deletion.DeletionId, token)).EnsureSuccessStatusCode();
            Assert.Equal(HttpStatusCode.Conflict, (await Confirm(_client, deletion.DeletionId, token)).StatusCode);
            Assert.True(store.Exists(_userId)); // approved, waiting out the grace period
        }

        /// <summary>
        /// EXPORT-11: every export and deletion request is audited with its reason (action, the acting user and the
        /// details: format, reason, request id). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        // EXPORT-11
        [Fact]
        public async Task AllRequestsAreAudited()
        {
            var export = await PostAs<ExportResponse>(_client, "/compliance/export", new ExportRequestDto { Format = "json" });
            var deletion = await PostAs<DeletionResponse>(_client, "/compliance/delete", new DeletionRequestDto { Reason = "other" });
            await _client.DeleteAsync($"/compliance/delete/{deletion.DeletionId}");
            using var scope = _factory.Services.CreateScope();
            var rows = await scope.ServiceProvider.GetRequiredService<ComplianceDbContext>().AuditLogs.AsNoTracking()
                .Where(a => a.UserId == _userId).OrderBy(a => a.Sequence).ToListAsync();
            Assert.Equal(new[] { "data_export_requested", "deletion_requested", "deletion_cancelled" }, rows.Select(a => a.Action).ToArray());
            Assert.All(rows, a => Assert.Equal(_userId, a.ActorId));
            Assert.Contains(export.ExportId, rows[0].Details);
            Assert.Contains("\"reason\":\"other\"", rows[1].Details);
        }

        /// <summary>POSTs a JSON body, requires success and reads the answer. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static async Task<T> PostAs<T>(HttpClient client, string url, object body)
        {
            using var content = new StringContent(JsonConvert.SerializeObject(body), Encoding.UTF8, "application/json");
            var response = await client.PostAsync(url, content);
            response.EnsureSuccessStatusCode();
            return JsonConvert.DeserializeObject<T>(await response.Content.ReadAsStringAsync());
        }

        private async Task CreateTestExportRequest(string format)
        {
            var request = new ExportRequestDto { Format = format };
            using var content = new StringContent(JsonConvert.SerializeObject(request), Encoding.UTF8, "application/json");
            await _client.PostAsync("/compliance/export", content);
        }

        private async Task CreateTestDeletionRequest(string status, string reason)
        {
            // This would require bypassing the API to directly insert for status setup
            // For simplicity, we'll use the API which always creates pending
            var request = new DeletionRequestDto { Reason = reason };
            using var content = new StringContent(JsonConvert.SerializeObject(request), Encoding.UTF8, "application/json");
            await _client.PostAsync("/compliance/delete", content);
            
            // To test non-pending statuses, we would need to directly update the DB
            // This is omitted for brevity but would be needed for full coverage
        }
    }
}
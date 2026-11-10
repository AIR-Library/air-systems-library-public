// HTTP tests for the notifications template. Changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): responses
// were read as `dynamic`, which System.Text.Json materialises as a JsonElement, so every `result.success` threw at run
// time whatever the server answered; they are read as JsonElement now with the same assertions. `channel = null` in an
// anonymous type does not compile and is `(string?)null` (still "auto-select"). The content-root setting and the wait
// in TrackMessageStatus are explained where they are. Touches: an in-process test server; no network.
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using System.Linq;
using System.Threading;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Notifications;

namespace NotificationsTests
{
    public class NotificationApiTests : IClassFixture<WebApplicationFactory<Program>>
    {
        private readonly HttpClient _client;
        private readonly WebApplicationFactory<Program> _app;

        /// <summary>
        /// Points WebApplicationFactory at a content root. It otherwise looks for a solution (.sln) above the test
        /// binaries, which a single-assembly build (app and tests compiled together, as the library's runner does) does
        /// not have, so every test failed before sending a request. WebApplicationFactory reads the documented
        /// ASPNETCORE_TEST_CONTENTROOT_&lt;ASSEMBLY&gt; setting first. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
        /// Touches: this process's environment.
        /// </summary>
        static NotificationApiTests()
        {
            var assembly = typeof(Program).Assembly.GetName().Name!.ToUpperInvariant().Replace(".", "_");
            Environment.SetEnvironmentVariable($"ASPNETCORE_TEST_CONTENTROOT_{assembly}", AppContext.BaseDirectory);
        }

        /// <summary>The unsubscribe secret the test host is configured with (a test value, 32+ bytes).</summary>
        internal const string TestSecret = "test-unsubscribe-secret-0123456789abcdef";

        /// <summary>
        /// Builds the test host. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the service now refuses to start
        /// without a 32-byte unsubscribe secret (NOTIF-11), so the host is given one.
        /// </summary>
        public NotificationApiTests(WebApplicationFactory<Program> factory)
        {
            _app = factory.WithWebHostBuilder(builder => builder.UseSetting("Notifications:UnsubscribeSecret", TestSecret));
            _client = _app.CreateClient();
        }

        /// <summary>GET /notifications/track/{id} as JSON. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test server.</summary>
        private async Task<JsonElement> Track(string messageId)
        {
            var resp = await _client.GetAsync($"/notifications/track/{messageId}");
            resp.EnsureSuccessStatusCode();
            return await resp.Content.ReadFromJsonAsync<JsonElement>();
        }

        /// <summary>Polls the track endpoint (up to 10 s) until the message leaves 'queued'/'sending'. Touches: the test server.</summary>
        private async Task<JsonElement> WaitDelivered(string messageId)
        {
            JsonElement t;
            var deadline = DateTime.UtcNow.AddSeconds(10);
            do
            {
                t = await Track(messageId);
                var status = t.GetProperty("status").GetString();
                if (status != "queued" && status != "sending") break;
                await Task.Delay(50);
            } while (DateTime.UtcNow < deadline);
            return t;
        }

        // NOTIF-01
        [Fact]
        public async Task SendEmailWithTemplateVariables()
        {
            var payload = new
            {
                user_id = 1,
                template_key = "welcome_email",
                channel = "email",
                vars = new Dictionary<string, string> { { "app_name", "TestApp" } },
                scheduled_at = (DateTime?)null
            };
            var response = await _client.PostAsJsonAsync("/notifications/send", payload);
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.True(result.GetProperty("success").GetBoolean());
            Assert.Equal("queued", result.GetProperty("status").GetString());
            // the delivered email carries the variable (asserts added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
            Assert.Equal("sent", (await WaitDelivered(result.GetProperty("message_id").GetString()!)).GetProperty("status").GetString());
            var email = _app.Services.GetRequiredService<DevelopmentOutbox>().Messages.Single(m => m.UserId == 1 && m.Channel == "email");
            Assert.Equal("Welcome to TestApp!", email.Subject);
            Assert.Contains("Welcome to TestApp! Here's your first step.", email.Body);
            Assert.DoesNotContain("{app_name}", email.Body);
        }

        // NOTIF-02
        [Fact]
        public async Task SendSms()
        {
            var payload = new
            {
                user_id = 2,
                template_key = "trial_ending_soon",
                channel = "sms",
                vars = new Dictionary<string, string> { { "days_left", "3" } },
                scheduled_at = (DateTime?)null
            };
            // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-02 amendment): SMS is off by default, so a send
            // before opting in is skipped, and the user enables SMS first.
            var before = await (await _client.PostAsJsonAsync("/notifications/send", payload)).Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal("skipped", before.GetProperty("status").GetString());
            (await _client.PutAsJsonAsync("/users/2/notification-preferences",
                new { channels_enabled = new Dictionary<string, bool> { { "sms", true } } })).EnsureSuccessStatusCode();

            var response = await _client.PostAsJsonAsync("/notifications/send", payload);
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.True(result.GetProperty("success").GetBoolean());
            Assert.Equal("queued", result.GetProperty("status").GetString());
            var tracked = await WaitDelivered(result.GetProperty("message_id").GetString()!);
            Assert.Equal("sms", tracked.GetProperty("channel").GetString());
            Assert.Equal("sent", tracked.GetProperty("status").GetString());
            Assert.Contains(_app.Services.GetRequiredService<DevelopmentOutbox>().Messages,
                m => m.Channel == "sms" && m.UserId == 2 && m.Body.Contains("3 days"));
        }

        // NOTIF-03
        [Fact]
        public async Task SendInAppStoresInDb()
        {
            var payload = new
            {
                user_id = 3,
                template_key = "admin_alert",
                channel = "in_app",
                vars = new Dictionary<string, string> { { "actor", "system" }, { "action", "restart" }, { "resource", "server" } },
                scheduled_at = (DateTime?)null
            };
            var response = await _client.PostAsJsonAsync("/notifications/send", payload);
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.True(result.GetProperty("success").GetBoolean());
            // stored in notification_logs (asserts added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
            var stored = await Track(result.GetProperty("message_id").GetString()!);
            Assert.Equal("in_app", stored.GetProperty("channel").GetString());
            Assert.Equal(3, stored.GetProperty("user_id").GetInt64());
        }

        // NOTIF-04
        [Fact]
        public async Task BatchSendMany()
        {
            var batch = new List<object>();
            // 1,000 items (NOTIF-04 says 1000+; it was 20. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
            for (int i = 0; i < 1000; i++)
            {
                batch.Add(new
                {
                    user_id = 100 + i,
                    template_key = "payment_failed",
                    channel = "email",
                    vars = new Dictionary<string, string> { { "invoice_id", $"INV{i}" }, { "retry_date", DateTime.UtcNow.AddDays(1).ToString("yyyy-MM-dd") } },
                    scheduled_at = (DateTime?)null
                });
            }
            var response = await _client.PostAsJsonAsync("/notifications/send-batch", batch);
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.True(result.GetProperty("success").GetBoolean());
            Assert.Equal(1000, result.GetProperty("sent").GetInt32());
            Assert.Equal(1000, result.GetProperty("message_ids").GetArrayLength());
        }

        // NOTIF-05
        [Fact]
        public async Task QuietHoursSkip()
        {
            // Set quiet hours to now +/- 1 hour
            var now = DateTime.UtcNow;
            var start = now.AddHours(-1).TimeOfDay;
            var end = now.AddHours(1).TimeOfDay;
            // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the test never set quiet hours (the API does take them,
            // "HH:mm" UTC), so "queued" proved nothing. Quiet hours now span the current time, and the message must wait
            // for their end instead of being sent.
            var prefPayload = new
            {
                do_not_disturb = false,
                quiet_hours_start = start.ToString(@"hh\:mm"),
                quiet_hours_end = end.ToString(@"hh\:mm"),
                channels_enabled = new Dictionary<string, bool> { { "email", true } }
            };
            var prefResponse = await _client.PutAsJsonAsync($"/users/999/notification-preferences", prefPayload);
            prefResponse.EnsureSuccessStatusCode();
            var sendPayload = new
            {
                user_id = 999,
                template_key = "welcome_email",
                channel = "email",
                vars = new Dictionary<string, string> { { "app_name", "QuietApp" } },
                scheduled_at = (DateTime?)null
            };
            var response = await _client.PostAsJsonAsync("/notifications/send", sendPayload);
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.True(result.GetProperty("success").GetBoolean());
            // Status should be queued because quiet hours cause delay
            Assert.Equal("queued", result.GetProperty("status").GetString());
            var tracked = await Track(result.GetProperty("message_id").GetString()!);
            Assert.True(tracked.GetProperty("scheduled_at").GetDateTime() > now.AddMinutes(30), "held until the quiet hours end");
            Assert.Equal("queued", tracked.GetProperty("status").GetString());
        }

        // NOTIF-06
        [Fact]
        public async Task DoNotDisturbSkips()
        {
            var prefPayload = new
            {
                do_not_disturb = true,
                channels_enabled = new Dictionary<string, bool> { { "email", true } }
            };
            var prefResponse = await _client.PutAsJsonAsync($"/users/555/notification-preferences", prefPayload);
            prefResponse.EnsureSuccessStatusCode();

            var sendPayload = new
            {
                user_id = 555,
                template_key = "welcome_email",
                channel = "email",
                vars = new Dictionary<string, string> { { "app_name", "DNDApp" } },
                scheduled_at = (DateTime?)null
            };
            var response = await _client.PostAsJsonAsync("/notifications/send", sendPayload);
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.True(result.GetProperty("success").GetBoolean());
            Assert.Equal("skipped", result.GetProperty("status").GetString());
        }

        // NOTIF-07
        [Fact]
        public async Task TrackMessageStatus()
        {
            var sendPayload = new
            {
                user_id = 777,
                template_key = "welcome_email",
                channel = "email",
                vars = new Dictionary<string, string> { { "app_name", "TrackApp" } },
                scheduled_at = (DateTime?)null
            };
            var sendResp = await _client.PostAsJsonAsync("/notifications/send", sendPayload);
            sendResp.EnsureSuccessStatusCode();
            var sendResult = await sendResp.Content.ReadFromJsonAsync<JsonElement>();
            var messageId = sendResult.GetProperty("message_id").GetString();

            // Simulate opening by updating the log directly (since click tracking endpoint not defined)
            // In real system, a click would hit a tracking endpoint that updates OpenedAt.
            // For test, we fetch the log via track endpoint and verify status.
            // Delivery happens in the background after the "queued" answer, so wait (up to 10 s) for the message to
            // leave the queue before checking it was sent; reading it once at once raced the delivery worker
            // (2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP).
            JsonElement trackResult = default;
            var deadline = DateTime.UtcNow.AddSeconds(10);
            do
            {
                var trackResp = await _client.GetAsync($"/notifications/track/{messageId}");
                trackResp.EnsureSuccessStatusCode();
                trackResult = await trackResp.Content.ReadFromJsonAsync<JsonElement>();
                if (trackResult.GetProperty("status").GetString() != "queued") break;
                await Task.Delay(50);
            } while (DateTime.UtcNow < deadline);
            Assert.Equal("sent", trackResult.GetProperty("status").GetString());

            // the user clicks the link in the message: it is marked opened (NOTIF-07; added 2026-11-10,
            // session_012zDydZCZ4AChqhEZ4oVtaP: nothing could mark a message opened before)
            // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, spec "Opening"): the answer is 204 every
            // time (it was asserted only as a success, and an unknown id as 404); a second call changes nothing.
            Assert.Equal(HttpStatusCode.NoContent, (await _client.GetAsync($"/notifications/open/{messageId}")).StatusCode);
            var opened = await Track(messageId!);
            Assert.Equal("opened", opened.GetProperty("status").GetString());
            Assert.Equal(JsonValueKind.String, opened.GetProperty("opened_at").ValueKind);
            var firstOpenedAt = opened.GetProperty("opened_at").GetString();
            await Task.Delay(20);
            Assert.Equal(HttpStatusCode.NoContent, (await _client.GetAsync($"/notifications/open/{messageId}")).StatusCode);
            var again = await Track(messageId!);
            Assert.Equal("opened", again.GetProperty("status").GetString());
            Assert.Equal(firstOpenedAt, again.GetProperty("opened_at").GetString());
            Assert.Equal(HttpStatusCode.NoContent, (await _client.GetAsync($"/notifications/open/{Guid.NewGuid()}")).StatusCode);
        }

        [Fact]
        public async Task UnsubscribePreventsFutureEmails()
        {
            // Simulate unsubscribe by setting do_not_disturb via preferences
            var prefPayload = new
            {
                do_not_disturb = true,
                channels_enabled = new Dictionary<string, bool> { { "email", false } }
            };
            var prefResponse = await _client.PutAsJsonAsync($"/users/888/notification-preferences", prefPayload);
            prefResponse.EnsureSuccessStatusCode();

            var sendPayload = new
            {
                user_id = 888,
                template_key = "welcome_email",
                channel = "email",
                vars = new Dictionary<string, string> { { "app_name", "UnsubApp" } },
                scheduled_at = (DateTime?)null
            };
            var response = await _client.PostAsJsonAsync("/notifications/send", sendPayload);
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.True(result.GetProperty("success").GetBoolean());
            Assert.Equal("skipped", result.GetProperty("status").GetString());
        }

        // NOTIF-10
        [Fact]
        public async Task UserPreferencesHonored()
        {
            var prefPayload = new
            {
                do_not_disturb = false,
                channels_enabled = new Dictionary<string, bool> { { "email", false }, { "sms", true }, { "in_app", true } }
            };
            var prefResponse = await _client.PutAsJsonAsync($"/users/7777/notification-preferences", prefPayload);
            prefResponse.EnsureSuccessStatusCode();

            var sendPayload = new
            {
                user_id = 7777,
                template_key = "welcome_email",
                channel = (string?)null, // auto-select
                vars = new Dictionary<string, string> { { "app_name", "PrefApp" } },
                scheduled_at = (DateTime?)null
            };
            var response = await _client.PostAsJsonAsync("/notifications/send", sendPayload);
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.True(result.GetProperty("success").GetBoolean());
            // Since email disabled, should fallback to sms (first enabled)
            Assert.Equal("queued", result.GetProperty("status").GetString());
            Assert.Equal("sms", (await Track(result.GetProperty("message_id").GetString()!)).GetProperty("channel").GetString());
        }
    
        /// <summary>
        /// The unsubscribe link in a delivered email works only as issued: the same token for another user is refused,
        /// the genuine link turns email off, and the next email to that user is skipped (spec: "Unsubscribe: user
        /// unsubscribed, future emails skipped"). Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP) with the
        /// signed links. Touches: the in-process server and its development outbox.
        /// </summary>
        // NOTIF-09
        [Fact]
        public async Task UnsubscribeLink_IsSignedAndStopsFutureEmails()
        {
            const long userId = 4242;
            var send = new { user_id = userId, template_key = "welcome_email", channel = "email",
                vars = new Dictionary<string, string> { { "app_name", "LinkApp" } }, scheduled_at = (DateTime?)null };
            (await _client.PostAsJsonAsync("/notifications/send", send)).EnsureSuccessStatusCode();

            var outbox = _app.Services.GetRequiredService<DevelopmentOutbox>();
            OutboxMessage? email = null;
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (email == null && DateTime.UtcNow < deadline)
            {
                email = outbox.Messages.LastOrDefault(m => m.UserId == userId && m.Channel == "email");
                if (email == null) await Task.Delay(50);
            }
            Assert.NotNull(email);
            var match = System.Text.RegularExpressions.Regex.Match(email!.Body, "token=([A-Za-z0-9_-]+)");
            Assert.True(match.Success);
            var token = match.Groups[1].Value;

            // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-11 amendment): the link is /unsubscribe, a bad
            // token is 403, GET only confirms and POST unsubscribes.
            var forged = await _client.PostAsync($"/unsubscribe?user_id={userId + 1}&channel=email&token={token}", null);
            Assert.Equal(HttpStatusCode.Forbidden, forged.StatusCode);
            var confirm = await _client.GetAsync($"/unsubscribe?user_id={userId}&channel=email&token={token}");
            confirm.EnsureSuccessStatusCode();
            var genuine = await _client.PostAsync($"/unsubscribe?user_id={userId}&channel=email&token={token}", null);
            genuine.EnsureSuccessStatusCode();

            var again = await _client.PostAsJsonAsync("/notifications/send", send);
            var result = await again.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal("skipped", result.GetProperty("status").GetString());
        }

        /// <summary>
        /// NOTIF-11: POST with a valid token turns the channel off; GET changes nothing; a missing, short, non-hex
        /// (upper-case), altered or foreign token, or an unknown channel, is 403 invalid_unsubscribe_token and the user
        /// stays subscribed. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec amendment). Touches: the test server.
        /// </summary>
        // NOTIF-11
        [Fact]
        public async Task UnsubscribeLink_PostOnly_AndEveryBadTokenIs403()
        {
            const long userId = 5150;
            var tokens = new UnsubscribeTokens(TestSecret);
            var token = tokens.Create(userId, "email");
            Assert.Matches("^[0-9a-f]{64}$", token);
            var altered = (token[0] == 'a' ? "b" : "a") + token.Substring(1);
            var bad = new[]
            {
                $"/unsubscribe?user_id={userId}&channel=email",
                $"/unsubscribe?user_id={userId}&channel=email&token={token.Substring(0, 63)}",
                $"/unsubscribe?user_id={userId}&channel=email&token={token.ToUpperInvariant()}",
                $"/unsubscribe?user_id={userId}&channel=email&token={new string('z', 64)}",
                $"/unsubscribe?user_id={userId}&channel=email&token={altered}",
                $"/unsubscribe?user_id={userId}&channel=fax&token={token}",
                $"/unsubscribe?user_id={userId + 1}&channel=email&token={token}",
                $"/unsubscribe?user_id=abc&channel=email&token={token}",
            };
            foreach (var url in bad)
            {
                foreach (var response in new[] { await _client.PostAsync(url, null), await _client.GetAsync(url) })
                {
                    Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
                    var body = await response.Content.ReadFromJsonAsync<JsonElement>();
                    Assert.Equal("invalid_unsubscribe_token", body.GetProperty("error").GetString());
                }
            }

            async Task<bool> EmailOn()
            {
                var prefs = await _client.GetFromJsonAsync<JsonElement>($"/users/{userId}/notification-preferences");
                return prefs.GetProperty("channels_enabled").GetProperty("email").GetBoolean();
            }
            Assert.True(await EmailOn());
            (await _client.GetAsync($"/unsubscribe?user_id={userId}&channel=email&token={token}")).EnsureSuccessStatusCode();
            Assert.True(await EmailOn()); // GET only confirms
            (await _client.PostAsync($"/unsubscribe?user_id={userId}&channel=email&token={token}", null)).EnsureSuccessStatusCode();
            Assert.False(await EmailOn());
        }
}

    /// <summary>
    /// Deterministic tests of deliver_due, quiet hours and retries: the service and worker over a private in-memory
    /// database, the development outbox, and a clock moved by hand (no background worker, no sleeps). Added 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-05/08/12 amendments). Touches: process memory only.
    /// </summary>
    public class DeliverDueTests
    {
        /// <summary>An email gateway that fails its first <c>failures</c> sends, then delivers to the outbox. No network.</summary>
        private sealed class FlakyEmail : IEmailGateway
        {
            private readonly DevelopmentOutbox _outbox;
            public int Failures;
            public int Calls;
            public FlakyEmail(DevelopmentOutbox outbox, int failures) { _outbox = outbox; Failures = failures; }

            public Task SendEmailAsync(long userId, string subject, string htmlBody, string textBody, CancellationToken ct)
            {
                Calls++;
                if (Failures-- > 0) throw new InvalidOperationException("smtp 451 try again later");
                return _outbox.SendEmailAsync(userId, subject, htmlBody, textBody, ct);
            }
        }

        /// <summary>The service provider, clock, outbox and worker for one test. Touches: process memory.</summary>
        private static (ServiceProvider Sp, NotificationClock Clock, DevelopmentOutbox Outbox, DeliveryWorker Worker) Build(Func<DevelopmentOutbox, IEmailGateway>? email = null)
        {
            var services = new ServiceCollection();
            var name = "notif-" + Guid.NewGuid().ToString("N");
            services.AddDbContext<NotificationDbContext>(o => o.UseInMemoryDatabase(name));
            services.AddSingleton<IConfiguration>(new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["Notifications:PublicBaseUrl"] = "https://app.example" }).Build());
            var outbox = new DevelopmentOutbox();
            services.AddSingleton(outbox);
            services.AddSingleton<IEmailGateway>(email?.Invoke(outbox) ?? outbox);
            services.AddSingleton<ISmsGateway>(outbox);
            services.AddSingleton(new UnsubscribeTokens(NotificationApiTests.TestSecret));
            var clock = new NotificationClock();
            var t = new DateTime(2026, 11, 10, 23, 0, 0, DateTimeKind.Utc);
            clock.Now = () => t;
            services.AddSingleton(clock);
            services.AddSingleton<DeliverySignal>();
            services.AddScoped<NotificationService>();
            var sp = services.BuildServiceProvider();
            using (var scope = sp.CreateScope())
                scope.ServiceProvider.GetRequiredService<NotificationDbContext>().Database.EnsureCreated();
            var worker = new DeliveryWorker(sp, sp.GetRequiredService<DeliverySignal>(), NullLogger<DeliveryWorker>.Instance, clock);
            return (sp, clock, outbox, worker);
        }

        private static async Task<T> InScope<T>(ServiceProvider sp, Func<NotificationService, NotificationDbContext, Task<T>> work)
        {
            using var scope = sp.CreateScope();
            return await work(scope.ServiceProvider.GetRequiredService<NotificationService>(), scope.ServiceProvider.GetRequiredService<NotificationDbContext>());
        }

        private static Task<NotificationLog> Log(ServiceProvider sp, string id) =>
            InScope(sp, (_, db) => db.NotificationLogs.AsNoTracking().SingleAsync(l => l.Id == Guid.Parse(id)));

        private static readonly Dictionary<string, string> AppVars = new() { ["app_name"] = "Acme" };

        /// <summary>
        /// NOTIF-05: inside quiet hours (22:00-07:00, now 23:00) an email is queued with scheduled_at = the next 07:00 and
        /// not sent before; deliver_due at 07:00 sends it. In-app is not held. Defaults: email and in_app on, SMS off.
        /// </summary>
        // NOTIF-05
        [Fact]
        public async Task QuietHours_QueueUntilEnd_ThenDeliverDueSends()
        {
            var (sp, clock, outbox, worker) = Build();
            using var _ = sp;
            var now = clock.Now();
            var defaults = await InScope(sp, (svc, _) => svc.GetPreferencesAsync(1));
            Assert.False(defaults.DoNotDisturb);
            Assert.Null(defaults.QuietHoursStart);
            Assert.Equal(new Dictionary<string, bool> { ["email"] = true, ["sms"] = false, ["in_app"] = true }, defaults.ChannelsEnabled);

            Assert.Null(await InScope(sp, (svc, _) => svc.UpdatePreferencesAsync(1, new UpdatePrefRequest { QuietHoursStart = "22:00", QuietHoursEnd = "07:00" })));
            var r = await InScope(sp, (svc, _) => svc.SendAsync(1, "welcome_email", "email", AppVars, null));
            Assert.Equal("queued", r.Status);
            Assert.Equal(new DateTime(2026, 11, 11, 7, 0, 0, DateTimeKind.Utc), (await Log(sp, r.MessageId!)).ScheduledAt);

            Assert.Equal(0, await worker.DeliverDueAsync(now.AddHours(7).AddMinutes(59).AddSeconds(59), CancellationToken.None));
            Assert.Empty(outbox.Messages);
            Assert.Equal(1, await worker.DeliverDueAsync(new DateTime(2026, 11, 11, 7, 0, 0, DateTimeKind.Utc), CancellationToken.None));
            Assert.Equal("sent", (await Log(sp, r.MessageId!)).Status);
            Assert.Contains("Acme", outbox.Messages.Single().Body);
        }

        /// <summary>
        /// NOTIF-08: an email whose gateway fails twice is retried after 1 s and 2 s and then sent (3 attempts); a gateway
        /// that never works is retried 3 times (after 1 s, 2 s and 4 s) and ends 'failed' after the 4th attempt.
        /// Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2: the spec now counts up to 3 retries after the
        /// first attempt, at most 4 attempts; this test asserted 'failed' after 3). Touches: process memory only.
        /// </summary>
        // NOTIF-08
        [Fact]
        public async Task Retry_FailedEmail_RetriesWithBackoff_AndEventuallySucceeds()
        {
            FlakyEmail? flaky = null;
            var (sp, clock, outbox, worker) = Build(o => flaky = new FlakyEmail(o, 2));
            using var _ = sp;
            var t0 = clock.Now();
            var r = await InScope(sp, (svc, _) => svc.SendAsync(7, "welcome_email", "email", AppVars, null));

            Assert.Equal(0, await worker.DeliverDueAsync(t0, CancellationToken.None));
            var log = await Log(sp, r.MessageId!);
            Assert.Equal(("queued", 1, t0.AddSeconds(1)), (log.Status, log.Attempts, log.NextAttemptAt!.Value));
            Assert.Equal(0, await worker.DeliverDueAsync(t0.AddMilliseconds(999), CancellationToken.None)); // waiting
            Assert.Equal(1, flaky!.Calls);
            Assert.Equal(0, await worker.DeliverDueAsync(t0.AddSeconds(1), CancellationToken.None));
            Assert.Equal(t0.AddSeconds(3), (await Log(sp, r.MessageId!)).NextAttemptAt);
            Assert.Equal(1, await worker.DeliverDueAsync(t0.AddSeconds(3), CancellationToken.None));
            Assert.Equal("sent", (await Log(sp, r.MessageId!)).Status);
            Assert.Equal(3, flaky.Calls);
            Assert.Single(outbox.Messages);

            flaky.Failures = 10;
            var doomed = await InScope(sp, (svc, _) => svc.SendAsync(8, "welcome_email", "email", AppVars, null));
            foreach (var at in new[] { 0, 1, 3 })
                await worker.DeliverDueAsync(t0.AddSeconds(10 + at), CancellationToken.None);
            // after 3 failed attempts the 3rd retry waits 4 s (2026-11-10, Phase B.2: this was asserted 'failed')
            var third = await Log(sp, doomed.MessageId!);
            Assert.Equal(("queued", 3, t0.AddSeconds(17)), (third.Status, third.Attempts, third.NextAttemptAt!.Value));
            Assert.Equal(0, await worker.DeliverDueAsync(t0.AddSeconds(16.999), CancellationToken.None)); // still waiting
            Assert.Equal(3, (await Log(sp, doomed.MessageId!)).Attempts);
            await worker.DeliverDueAsync(t0.AddSeconds(17), CancellationToken.None);
            var failed = await Log(sp, doomed.MessageId!);
            Assert.Equal(("failed", 4), (failed.Status, failed.Attempts));
            Assert.Equal(DeliveryWorker.MaxAttempts, failed.Attempts);
        }

        /// <summary>
        /// NOTIF-08 (Phase B.2 amendment): a gateway that fails three times is retried after 1 s, 2 s and 4 s and the 4th
        /// attempt succeeds: the message is 'sent' after exactly 4 calls. In: nothing. Out: asserts. Added 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory only.
        /// </summary>
        // NOTIF-08
        [Fact]
        public async Task Retry_ThreeFailures_FourthAttemptSucceeds()
        {
            FlakyEmail? flaky = null;
            var (sp, clock, outbox, worker) = Build(o => flaky = new FlakyEmail(o, 3));
            using var _ = sp;
            var t0 = clock.Now();
            var r = await InScope(sp, (svc, _) => svc.SendAsync(9, "welcome_email", "email", AppVars, null));
            await worker.DeliverDueAsync(t0, CancellationToken.None);
            Assert.Equal(t0.AddSeconds(1), (await Log(sp, r.MessageId!)).NextAttemptAt);
            await worker.DeliverDueAsync(t0.AddSeconds(1), CancellationToken.None);
            Assert.Equal(t0.AddSeconds(3), (await Log(sp, r.MessageId!)).NextAttemptAt);
            await worker.DeliverDueAsync(t0.AddSeconds(3), CancellationToken.None);
            Assert.Equal(t0.AddSeconds(7), (await Log(sp, r.MessageId!)).NextAttemptAt);
            Assert.Equal(1, await worker.DeliverDueAsync(t0.AddSeconds(7), CancellationToken.None));
            var log = await Log(sp, r.MessageId!);
            Assert.Equal(("sent", 3), (log.Status, log.Attempts)); // three failed attempts counted, the 4th sent it
            Assert.Equal(4, flaky!.Calls);
            Assert.Single(outbox.Messages);
        }

        /// <summary>
        /// NOTIF-05 (Phase B.2 amendment, deliver_due step 3): a message queued for 12:00 whose user then sets quiet hours
        /// 11:00-13:00 (UTC, same day) is not sent at 12:00 but goes back to 'queued' with scheduled_at = 13:00, and is
        /// sent then. A window crossing midnight (22:00-07:00) holds a message due at 02:00 until 07:00 the same morning.
        /// In: nothing. Out: asserts. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory only.
        /// </summary>
        // NOTIF-05
        [Fact]
        public async Task QuietHours_DeliverDueRequeuesUntilQuietHoursEnd()
        {
            var (sp, _, outbox, worker) = Build();
            using var __ = sp;
            var noon = new DateTime(2026, 11, 11, 12, 0, 0, DateTimeKind.Utc);
            var r = await InScope(sp, (svc, _) => svc.SendAsync(31, "welcome_email", "email", AppVars, noon));
            Assert.Equal(noon, (await Log(sp, r.MessageId!)).ScheduledAt);
            Assert.Null(await InScope(sp, (svc, _) => svc.UpdatePreferencesAsync(31, new UpdatePrefRequest { QuietHoursStart = "11:00", QuietHoursEnd = "13:00" })));

            Assert.Equal(0, await worker.DeliverDueAsync(noon, CancellationToken.None));
            var held = await Log(sp, r.MessageId!);
            Assert.Equal(("queued", noon.AddHours(1)), (held.Status, held.ScheduledAt));
            Assert.Null(held.ClaimedAt);
            Assert.Empty(outbox.Messages);
            Assert.Equal(0, await worker.DeliverDueAsync(noon.AddMinutes(59), CancellationToken.None));
            Assert.Equal(1, await worker.DeliverDueAsync(noon.AddHours(1), CancellationToken.None));
            Assert.Equal("sent", (await Log(sp, r.MessageId!)).Status);

            var twoAm = new DateTime(2026, 11, 12, 2, 0, 0, DateTimeKind.Utc);
            var night = await InScope(sp, (svc, _) => svc.SendAsync(32, "welcome_email", "email", AppVars, twoAm));
            Assert.Null(await InScope(sp, (svc, _) => svc.UpdatePreferencesAsync(32, new UpdatePrefRequest { QuietHoursStart = "22:00", QuietHoursEnd = "07:00" })));
            Assert.Equal(0, await worker.DeliverDueAsync(twoAm, CancellationToken.None));
            Assert.Equal(new DateTime(2026, 11, 12, 7, 0, 0, DateTimeKind.Utc), (await Log(sp, night.MessageId!)).ScheduledAt);
            Assert.Equal(1, await worker.DeliverDueAsync(new DateTime(2026, 11, 12, 7, 0, 0, DateTimeKind.Utc), CancellationToken.None));
            Assert.Equal(2, outbox.Messages.Count);
        }

        /// <summary>
        /// NOTIF-12: a send 30 days ahead is not sent now; deliver_due sends it once due, exactly once (a second pass sends
        /// nothing); a user who unsubscribed meanwhile is skipped; a row stuck at 'sending' over 300 s is re-queued and
        /// sent, one stuck less long is left alone.
        /// </summary>
        // NOTIF-12
        [Fact]
        public async Task ScheduledSend_DeliverDue_ExactlyOnce_SkipsUnsubscribed_RequeuesStale()
        {
            var (sp, clock, outbox, worker) = Build();
            using var _ = sp;
            var t0 = clock.Now();
            var later = t0.AddDays(30);
            var kept = await InScope(sp, (svc, _) => svc.SendAsync(21, "welcome_email", "email", AppVars, later));
            var unsub = await InScope(sp, (svc, _) => svc.SendAsync(22, "welcome_email", "email", AppVars, later));
            Assert.Equal("queued", kept.Status);
            Assert.Equal(later, (await Log(sp, kept.MessageId!)).ScheduledAt);

            Assert.Equal(0, await worker.DeliverDueAsync(t0, CancellationToken.None));
            Assert.Equal(0, await worker.DeliverDueAsync(later.AddSeconds(-1), CancellationToken.None));
            Assert.Empty(outbox.Messages);

            // user 22 unsubscribes through the signed link before the send is due
            var token = sp.GetRequiredService<UnsubscribeTokens>().Create(22, "email");
            Assert.True(await InScope(sp, (svc, _) => svc.UnsubscribeAsync(22, "email", token)));

            Assert.Equal(1, await worker.DeliverDueAsync(later, CancellationToken.None));
            Assert.Equal(0, await worker.DeliverDueAsync(later, CancellationToken.None));
            Assert.Equal("sent", (await Log(sp, kept.MessageId!)).Status);
            var skipped = await Log(sp, unsub.MessageId!);
            Assert.Equal(("skipped", "channel_disabled"), (skipped.Status, skipped.Error));
            Assert.Single(outbox.Messages);
            Assert.Equal(21, outbox.Messages[0].UserId);

            // a worker crashed after claiming a message: stuck at 'sending'
            var stuck = await InScope(sp, (svc, _) => svc.SendAsync(23, "welcome_email", "email", AppVars, null));
            var claimedAt = later.AddMinutes(1);
            await InScope(sp, async (_, db) =>
            {
                var row = await db.NotificationLogs.SingleAsync(l => l.Id == Guid.Parse(stuck.MessageId!));
                row.Status = "sending";
                row.ClaimedAt = claimedAt;
                return await db.SaveChangesAsync();
            });
            Assert.Equal(0, await worker.DeliverDueAsync(claimedAt.AddSeconds(300), CancellationToken.None));
            Assert.Equal("sending", (await Log(sp, stuck.MessageId!)).Status);
            Assert.Equal(1, await worker.DeliverDueAsync(claimedAt.AddSeconds(301), CancellationToken.None));
            Assert.Equal("sent", (await Log(sp, stuck.MessageId!)).Status);
            Assert.Equal(2, outbox.Messages.Count);
        }
    }
}
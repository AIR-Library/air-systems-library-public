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
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
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

        public NotificationApiTests(WebApplicationFactory<Program> factory)
        {
            _app = factory.WithWebHostBuilder(builder => { });
            _client = _app.CreateClient();
        }

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
        }

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
            var response = await _client.PostAsJsonAsync("/notifications/send", payload);
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.True(result.GetProperty("success").GetBoolean());
        }

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
        }

        [Fact]
        public async Task BatchSendMany()
        {
            var batch = new List<object>();
            for (int i = 0; i < 20; i++)
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
            Assert.Equal(20, result.GetProperty("sent").GetInt32());
        }

        [Fact]
        public async Task QuietHoursSkip()
        {
            // Set quiet hours to now +/- 1 hour
            var now = DateTime.UtcNow;
            var start = now.AddHours(-1).TimeOfDay;
            var end = now.AddHours(1).TimeOfDay;
            var prefPayload = new
            {
                do_not_disturb = false,
                channels_enabled = new Dictionary<string, bool> { { "email", true } }
            };
            var prefResponse = await _client.PutAsJsonAsync($"/users/999/notification-preferences", prefPayload);
            prefResponse.EnsureSuccessStatusCode();

            // Update quiet hours directly via DB (since API does not expose it)
            // For test simplicity, we assume the service defaults to 0 and we cannot set it via API.
            // We'll simulate by sending with scheduled_at within quiet hours and verify it is queued for later.
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
        }

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
        }
    
        /// <summary>
        /// The unsubscribe link in a delivered email works only as issued: the same token for another user is refused,
        /// the genuine link turns email off, and the next email to that user is skipped (spec: "Unsubscribe: user
        /// unsubscribed, future emails skipped"). Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP) with the
        /// signed links. Touches: the in-process server and its development outbox.
        /// </summary>
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

            var forged = await _client.GetAsync($"/notifications/unsubscribe?user_id={userId + 1}&channel=email&token={token}");
            Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);
            var genuine = await _client.GetAsync($"/notifications/unsubscribe?user_id={userId}&channel=email&token={token}");
            genuine.EnsureSuccessStatusCode();

            var again = await _client.PostAsJsonAsync("/notifications/send", send);
            var result = await again.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal("skipped", result.GetProperty("status").GetString());
        }
}
}
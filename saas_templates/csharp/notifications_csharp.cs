// Notifications template (TIER_2_MASTER_SPEC system 2): email, SMS and in-app notifications from templates, with
// do-not-disturb, quiet hours, per-channel preferences, retries with backoff, tracking and signed unsubscribe links.
// Repaired 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP). The suite failed to compile because it needed the
// Twilio package (not available, and it carried a hard-coded account SID and auth token). Behind that: request JSON
// never bound (snake_case fields, PascalCase properties); default preferences put every user in quiet hours forever
// (start == end read as an all-day range); background sends used the request's DbContext after it was disposed;
// channel preference updates were written to a throw-away copy; a message was logged "sent" before anything was
// sent; emails went to invented addresses (user{id}@example.com) over plain SMTP; template variables were put into
// HTML unescaped; and the unsubscribe link was an unsigned user id anyone could forge.
// Now: delivery goes through IEmailGateway / ISmsGateway (SMTP adapter included; SMS adapters such as Twilio or SNS
// plug in behind the interface; a development outbox is used when none is configured), addresses come from
// IRecipientDirectory, a hosted worker delivers due messages from the database with 3 attempts and exponential
// backoff, and unsubscribe links carry an HMAC that is checked in constant time.
// Touches: the notifications database; SMTP / SMS providers (network) when configured; nothing else.
#nullable enable
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Notifications
{
    #region Data Models and DbContext

    /// <summary>A notification template (spec schema notification_templates). Variables lists the placeholders it accepts. Pure data.</summary>
    public class NotificationTemplate
    {
        [Key]
        public string Key { get; set; } = null!;
        public string Subject { get; set; } = null!;
        public string BodyText { get; set; } = null!;
        public string BodyHtml { get; set; } = null!;
        public string ChannelsDefault { get; set; } = null!; // comma separated e.g. "email,sms"
        public string Variables { get; set; } = null!; // comma separated list of allowed vars
    }

    /// <summary>
    /// One notification (spec schema notification_logs) and its delivery state. Status: queued, sent, failed, skipped,
    /// opened, bounced. SentAt is set only when a provider accepted the message; ScheduledFor and NextAttemptAt drive
    /// the delivery worker. Changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): status started as "sent"
    /// before anything was sent. Pure data.
    /// </summary>
    public class NotificationLog
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();
        public long UserId { get; set; }
        public string TemplateKey { get; set; } = null!;
        public string Channel { get; set; } = null!; // email, sms, in_app
        public string VarsUsed { get; set; } = null!; // JSON
        public DateTime CreatedAt { get; set; }
        public DateTime ScheduledFor { get; set; }
        public DateTime? SentAt { get; set; }
        public DateTime? OpenedAt { get; set; }
        public DateTime? ClickedAt { get; set; }
        public bool Bounced { get; set; }
        public string? Error { get; set; }
        public int Attempts { get; set; }
        public DateTime? NextAttemptAt { get; set; }
        public long Sequence { get; set; }
        public string Status { get; set; } = "queued";
    }

    /// <summary>
    /// A user's notification preferences (spec schema user_notification_preferences). Quiet hours are UTC times of day;
    /// null, or start equal to end, means none. ChannelsEnabled is a copy: assign a new dictionary to change it.
    /// Changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): nullable quiet hours (0:00-0:00 meant "always
    /// quiet"), and the dictionary is no longer mapped by EF. Pure data.
    /// </summary>
    public class UserNotificationPreference
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long UserId { get; set; }
        public bool DoNotDisturb { get; set; }
        public TimeSpan? QuietHoursStart { get; set; }
        public TimeSpan? QuietHoursEnd { get; set; }
        public string ChannelsEnabledJson { get; set; } = "{}"; // {"email":true,"sms":false,"in_app":true}

        [NotMapped]
        public Dictionary<string, bool> ChannelsEnabled
        {
            get => JsonSerializer.Deserialize<Dictionary<string, bool>>(ChannelsEnabledJson) ?? new();
            set => ChannelsEnabledJson = JsonSerializer.Serialize(value);
        }
    }

    /// <summary>EF Core context with the nine seeded templates of the spec. Touches: the notifications database.</summary>
    public class NotificationDbContext : DbContext
    {
        public NotificationDbContext(DbContextOptions<NotificationDbContext> options) : base(options) { }

        public DbSet<NotificationTemplate> NotificationTemplates => Set<NotificationTemplate>();
        public DbSet<NotificationLog> NotificationLogs => Set<NotificationLog>();
        public DbSet<UserNotificationPreference> UserNotificationPreferences => Set<UserNotificationPreference>();

        /// <summary>Maps the entities to their tables and indexes. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the EF model only.</summary>
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // Seed templates
            modelBuilder.Entity<NotificationTemplate>().HasData(
                new NotificationTemplate
                {
                    Key = "welcome_email",
                    Subject = "Welcome to {app_name}!",
                    BodyText = "Welcome to {app_name}! Here's your first step.",
                    BodyHtml = "<p>Welcome to {app_name}! Here's your first step.</p>",
                    ChannelsDefault = "email",
                    Variables = "app_name"
                },
                new NotificationTemplate
                {
                    Key = "trial_starting",
                    Subject = "Your trial is starting",
                    BodyText = "Your free trial is starting. You have {trial_days} days.",
                    BodyHtml = "<p>Your free trial is starting. You have {trial_days} days.</p>",
                    ChannelsDefault = "email,in_app",
                    Variables = "trial_days"
                },
                new NotificationTemplate
                {
                    Key = "trial_ending_soon",
                    Subject = "Trial ending soon",
                    BodyText = "Your trial ends in {days_left} days. Add payment method to continue.",
                    BodyHtml = "<p>Your trial ends in {days_left} days. Add payment method to continue.</p>",
                    ChannelsDefault = "email,in_app",
                    Variables = "days_left"
                },
                new NotificationTemplate
                {
                    Key = "subscription_changed",
                    Subject = "Subscription changed",
                    BodyText = "Your plan changed from {old_tier} to {new_tier}. Effective {effective_date}.",
                    BodyHtml = "<p>Your plan changed from {old_tier} to {new_tier}. Effective {effective_date}.</p>",
                    ChannelsDefault = "email",
                    Variables = "old_tier,new_tier,effective_date"
                },
                new NotificationTemplate
                {
                    Key = "payment_failed",
                    Subject = "Payment failed",
                    BodyText = "Payment failed for invoice {invoice_id}. {retry_date} retry, or update payment method.",
                    BodyHtml = "<p>Payment failed for invoice {invoice_id}. {retry_date} retry, or update payment method.</p>",
                    ChannelsDefault = "email,in_app",
                    Variables = "invoice_id,retry_date"
                },
                new NotificationTemplate
                {
                    Key = "deployment_live",
                    Subject = "Deployment live",
                    BodyText = "Your deployment {deployment_name} is now live at {url}.",
                    BodyHtml = "<p>Your deployment {deployment_name} is now live at {url}.</p>",
                    ChannelsDefault = "email,in_app",
                    Variables = "deployment_name,url"
                },
                new NotificationTemplate
                {
                    Key = "user_invited",
                    Subject = "You are invited",
                    BodyText = "You've been invited to {workspace}. Click here to join.",
                    BodyHtml = "<p>You've been invited to {workspace}. <a href=\"{join_url}\">Click here to join</a>.</p>",
                    ChannelsDefault = "email,in_app",
                    Variables = "workspace,join_url"
                },
                new NotificationTemplate
                {
                    Key = "invoice_ready",
                    Subject = "Invoice ready",
                    BodyText = "Your invoice for {month} is ready. Download here.",
                    BodyHtml = "<p>Your invoice for {month} is ready. <a href=\"{download_url}\">Download here</a>.</p>",
                    ChannelsDefault = "email,in_app",
                    Variables = "month,download_url"
                },
                new NotificationTemplate
                {
                    Key = "admin_alert",
                    Subject = "Admin alert",
                    BodyText = "{actor} performed {action} on {resource}.",
                    BodyHtml = "<p>{actor} performed {action} on {resource}.</p>",
                    ChannelsDefault = "email",
                    Variables = "actor,action,resource"
                }
            );
        }
    }

    #endregion

    #region Delivery gateways

    /// <summary>
    /// Resolves where a user's notifications go. Implement it over your users table; the core service never invents
    /// addresses. Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP). Touches: your user store.
    /// </summary>
    public interface IRecipientDirectory
    {
        Task<string?> GetEmailAsync(long userId, CancellationToken ct);
        Task<string?> GetPhoneAsync(long userId, CancellationToken ct);
    }

    /// <summary>
    /// Sends one email. Production: <see cref="SmtpEmailGateway"/> (or SendGrid/SES behind the same interface);
    /// development and tests: <see cref="DevelopmentOutbox"/>. Throwing marks the attempt failed (it is retried).
    /// Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP). Touches: the network in production.
    /// </summary>
    public interface IEmailGateway
    {
        Task SendEmailAsync(long userId, string subject, string htmlBody, string textBody, CancellationToken ct);
    }

    /// <summary>
    /// Sends one SMS. Put Twilio, AWS SNS or another provider behind it; <see cref="DevelopmentOutbox"/> is used when
    /// none is registered. Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP) in place of the direct Twilio
    /// calls (the package is not available here, and the code held hard-coded credentials). Touches: the network in
    /// production.
    /// </summary>
    public interface ISmsGateway
    {
        Task SendSmsAsync(long userId, string text, CancellationToken ct);
    }

    /// <summary>One message captured by <see cref="DevelopmentOutbox"/>. Pure data.</summary>
    public record OutboxMessage(string Channel, long UserId, string? Subject, string Body);

    /// <summary>
    /// Development / test gateway: keeps sent emails and SMS in memory instead of contacting a provider, so a fresh
    /// copy of the template runs without credentials and tests make no network calls. Never use it in production: the
    /// messages go nowhere. Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP). Touches: process memory.
    /// </summary>
    public class DevelopmentOutbox : IEmailGateway, ISmsGateway
    {
        private readonly List<OutboxMessage> _messages = new();

        /// <summary>A snapshot of the captured messages, in send order. Touches: process memory.</summary>
        public IReadOnlyList<OutboxMessage> Messages { get { lock (_messages) return _messages.ToList(); } }

        /// <summary>Implements the interface member of the same name; see the class summary. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public Task SendEmailAsync(long userId, string subject, string htmlBody, string textBody, CancellationToken ct)
        {
            lock (_messages) _messages.Add(new OutboxMessage("email", userId, subject, htmlBody));
            return Task.CompletedTask;
        }

        /// <summary>Implements the interface member of the same name; see the class summary. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public Task SendSmsAsync(long userId, string text, CancellationToken ct)
        {
            lock (_messages) _messages.Add(new OutboxMessage("sms", userId, null, text));
            return Task.CompletedTask;
        }
    }

    /// <summary>SMTP settings, read from the "Smtp" configuration section (never hard-coded). Pure data.</summary>
    public class SmtpOptions
    {
        public string Host { get; set; } = "";
        public int Port { get; set; } = 587;
        public string? User { get; set; }
        public string? Password { get; set; }
        public string From { get; set; } = "";
    }

    /// <summary>
    /// Email over SMTP with TLS (EnableSsl), credentials from configuration and the address from
    /// <see cref="IRecipientDirectory"/>; a user without an address fails the attempt. Rewritten 2026-11-10 (session
    /// session_012zDydZCZ4AChqhEZ4oVtaP): it sent unencrypted to localhost and to an invented address. Touches: the
    /// network (SMTP).
    /// </summary>
    public class SmtpEmailGateway : IEmailGateway
    {
        private readonly SmtpOptions _options;
        private readonly IRecipientDirectory _directory;

        public SmtpEmailGateway(SmtpOptions options, IRecipientDirectory directory)
        {
            _options = options;
            _directory = directory;
        }

        /// <summary>Implements the interface member of the same name; see the class summary. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public async Task SendEmailAsync(long userId, string subject, string htmlBody, string textBody, CancellationToken ct)
        {
            var to = await _directory.GetEmailAsync(userId, ct)
                ?? throw new InvalidOperationException("No email address for this user");
            using var client = new SmtpClient(_options.Host, _options.Port) { EnableSsl = true, Timeout = 10000 };
            if (!string.IsNullOrEmpty(_options.User))
                client.Credentials = new NetworkCredential(_options.User, _options.Password);
            using var mail = new MailMessage(_options.From, to) { Subject = subject, Body = htmlBody, IsBodyHtml = true };
            mail.AlternateViews.Add(AlternateView.CreateAlternateViewFromString(textBody, Encoding.UTF8, "text/plain"));
            await client.SendMailAsync(mail, ct);
        }
    }

    /// <summary>
    /// Builds and checks unsubscribe tokens: base64url(HMAC-SHA256(secret, "userId:channel")), compared with
    /// CryptographicOperations.FixedTimeEquals, so a link only works for the user and channel it was issued for.
    /// The secret comes from Notifications:UnsubscribeSecret (at least 32 bytes); without it a random per-process
    /// secret is used (development: links stop working after a restart). Added 2026-11-10 (session
    /// session_012zDydZCZ4AChqhEZ4oVtaP): the old link was ?user=&lt;id&gt;, which anyone could forge. Pure.
    /// </summary>
    public class UnsubscribeTokens
    {
        private readonly byte[] _key;

        public UnsubscribeTokens(string? secret)
        {
            if (!string.IsNullOrEmpty(secret) && Encoding.UTF8.GetByteCount(secret) < 32)
                throw new ArgumentException("Notifications:UnsubscribeSecret must be at least 32 bytes");
            _key = string.IsNullOrEmpty(secret) ? RandomNumberGenerator.GetBytes(32) : Encoding.UTF8.GetBytes(secret);
        }

        /// <summary>The token for a user and channel. Pure.</summary>
        public string Create(long userId, string channel)
        {
            using var hmac = new HMACSHA256(_key);
            var mac = hmac.ComputeHash(Encoding.UTF8.GetBytes($"{userId}:{channel}"));
            return Convert.ToBase64String(mac).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        /// <summary>True when the token was issued for this user and channel (constant-time comparison). Pure.</summary>
        public bool Verify(long userId, string channel, string? token)
        {
            if (string.IsNullOrEmpty(token)) return false;
            var expected = Encoding.ASCII.GetBytes(Create(userId, channel));
            var provided = Encoding.ASCII.GetBytes(token);
            return expected.Length == provided.Length && CryptographicOperations.FixedTimeEquals(expected, provided);
        }
    }

    /// <summary>Wakes the delivery worker when a message is queued, so it need not wait for its next poll. Touches: process memory.</summary>
    public class DeliverySignal
    {
        private readonly SemaphoreSlim _signal = new(0);

        /// <summary>Wakes the worker (at most one pending wake-up). 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.</summary>
        public void Notify() { if (_signal.CurrentCount == 0) _signal.Release(); }

        /// <summary>Waits for a wake-up or the timeout. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.</summary>
        public Task<bool> WaitAsync(TimeSpan timeout, CancellationToken ct) => _signal.WaitAsync(timeout, ct);
    }

    #endregion

    #region Services

    /// <summary>Result of one send request. Pure data.</summary>
    public record SendResult(bool Success, string? MessageId, string Status, string? Error);

    /// <summary>
    /// Accepts notifications and manages preferences (spec endpoints 1-5). It decides and records; the
    /// <see cref="DeliveryWorker"/> delivers. Rewritten 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP); see the
    /// file header. Touches: the notifications database.
    /// </summary>
    public class NotificationService
    {
        public static readonly string[] Channels = { "email", "sms", "in_app" };
        public const int MaxBatchSize = 5000;
        private static long _sequence;

        /// <summary>Next value of the process-wide sequence that breaks ties between rows written in the same tick
        /// (insertion order). Static on purpose: services are created per request, so a per-instance counter would
        /// restart at 1 for every request. Moved into this static helper 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP,
        /// for code scanning ("static field written by instance method", PR 19). Touches: memory only.</summary>
        private static long NextSequence() => Interlocked.Increment(ref _sequence);

        private readonly NotificationDbContext _db;
        private readonly DeliverySignal _signal;
        private readonly UnsubscribeTokens _tokens;

        public NotificationService(NotificationDbContext db, DeliverySignal signal, UnsubscribeTokens tokens)
        {
            _db = db;
            _signal = signal;
            _tokens = tokens;
        }

        /// <summary>The preferences a user without a stored row gets: every channel on, no quiet hours, DND off. Pure.</summary>
        private static UserNotificationPreference Defaults(long userId) => new()
        {
            UserId = userId,
            ChannelsEnabled = Channels.ToDictionary(c => c, _ => true)
        };

        /// <summary>
        /// True when <paramref name="now"/> (UTC) falls in the user's quiet hours; ranges may cross midnight; no range,
        /// or start == end, is never quiet. Fixed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP). Pure.
        /// </summary>
        public static bool IsInQuietHours(UserNotificationPreference pref, DateTime now)
        {
            if (pref.QuietHoursStart is not TimeSpan start || pref.QuietHoursEnd is not TimeSpan end || start == end) return false;
            var t = now.TimeOfDay;
            return start < end ? t >= start && t < end : t >= start || t < end;
        }

        /// <summary>
        /// Picks the channel: an explicitly requested channel must be enabled (otherwise null: the user opted out);
        /// with none requested, the template's default channels in order, then email, sms, in_app, first enabled wins.
        /// Pure.
        /// </summary>
        private static string? ChooseChannel(string? requested, NotificationTemplate template, Dictionary<string, bool> enabled)
        {
            bool On(string c) => enabled.TryGetValue(c, out var v) && v;
            if (requested != null) return On(requested) ? requested : null;
            var order = template.ChannelsDefault.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Concat(Channels).Distinct();
            return order.FirstOrDefault(On);
        }

        /// <summary>
        /// Spec endpoint 1. Validates the user id, template and channel; records a skipped message when do-not-disturb is
        /// on or the chosen channel is disabled; otherwise queues it for now, for scheduled_at, or for the end of quiet
        /// hours, whichever is latest. Only the template's declared variables are kept. Output: success, message id and
        /// status queued / skipped, or success false with an error code. Touches: notification_logs, preferences (read).
        /// </summary>
        public async Task<SendResult> SendAsync(long userId, string? templateKey, string? channel,
            Dictionary<string, string>? vars, DateTime? scheduledAt)
        {
            if (userId <= 0) return new SendResult(false, null, "failed", "invalid_user_id");
            if (channel != null && !Channels.Contains(channel)) return new SendResult(false, null, "failed", "invalid_channel");
            var template = templateKey == null ? null : await _db.NotificationTemplates.FirstOrDefaultAsync(t => t.Key == templateKey);
            if (template == null) return new SendResult(false, null, "failed", "template_not_found");

            var allowed = template.Variables.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var kept = (vars ?? new()).Where(kv => allowed.Contains(kv.Key)).ToDictionary(kv => kv.Key, kv => kv.Value);

            var pref = await _db.UserNotificationPreferences.AsNoTracking().FirstOrDefaultAsync(p => p.UserId == userId) ?? Defaults(userId);
            var now = DateTime.UtcNow;
            var selected = pref.DoNotDisturb ? null : ChooseChannel(channel, template, pref.ChannelsEnabled);

            var log = new NotificationLog
            {
                UserId = userId,
                TemplateKey = template.Key,
                Channel = selected ?? channel ?? "none",
                VarsUsed = JsonSerializer.Serialize(kept),
                CreatedAt = now,
                ScheduledFor = now,
                Sequence = NextSequence()
            };

            if (selected == null)
            {
                log.Status = "skipped";
                log.Error = pref.DoNotDisturb ? "do_not_disturb" : "channel_disabled";
            }
            else
            {
                var due = scheduledAt.HasValue ? DateTime.SpecifyKind(scheduledAt.Value, DateTimeKind.Utc) : now;
                if (due < now) due = now;
                if (selected != "in_app" && IsInQuietHours(pref, due))
                {
                    var end = due.Date.Add(pref.QuietHoursEnd!.Value);
                    if (end <= due) end = end.AddDays(1);
                    due = end;
                }
                log.ScheduledFor = due;
                log.Status = "queued";
            }

            _db.NotificationLogs.Add(log);
            await _db.SaveChangesAsync();
            if (log.Status == "queued") _signal.Notify();
            return new SendResult(true, log.Id.ToString(), log.Status, null);
        }

        /// <summary>
        /// Spec endpoint 2: sends each item in order (up to <see cref="MaxBatchSize"/>). Output: sent (accepted for
        /// delivery), skipped, failed (rejected) and the message ids in input order (null for a rejected item).
        /// Touches: notification_logs.
        /// </summary>
        public async Task<(int Sent, int Skipped, int Failed, List<string?> MessageIds)> SendBatchAsync(IReadOnlyList<SendRequest> batch)
        {
            int sent = 0, skipped = 0, failed = 0;
            var ids = new List<string?>();
            foreach (var item in batch)
            {
                var r = await SendAsync(item.UserId, item.TemplateKey, item.Channel, item.Vars, item.ScheduledAt);
                if (!r.Success) failed++;
                else if (r.Status == "skipped") skipped++;
                else sent++;
                ids.Add(r.MessageId);
            }
            return (sent, skipped, failed, ids);
        }

        /// <summary>Spec endpoint 3: one message's log. Touches: notification_logs (read).</summary>
        public Task<NotificationLog?> TrackAsync(Guid messageId) =>
            _db.NotificationLogs.AsNoTracking().FirstOrDefaultAsync(l => l.Id == messageId);

        /// <summary>Spec endpoint 4: the stored preferences, or the defaults when none are stored. Touches: preferences (read).</summary>
        public async Task<UserNotificationPreference> GetPreferencesAsync(long userId) =>
            await _db.UserNotificationPreferences.AsNoTracking().FirstOrDefaultAsync(p => p.UserId == userId) ?? Defaults(userId);

        /// <summary>
        /// Spec endpoint 5: updates do-not-disturb, quiet hours ("HH:mm", UTC) and channels (merged over the current
        /// ones; unknown channel names are refused). Output: null on success, or an error code. Fixed 2026-11-10
        /// (session session_012zDydZCZ4AChqhEZ4oVtaP): channel changes were written to a copy and lost. Touches:
        /// preferences.
        /// </summary>
        public async Task<string?> UpdatePreferencesAsync(long userId, UpdatePrefRequest request)
        {
            if (userId <= 0) return "invalid_user_id";
            if (request.ChannelsEnabled != null && request.ChannelsEnabled.Keys.Any(k => !Channels.Contains(k))) return "invalid_channel";
            TimeSpan? start = null, end = null;
            if (request.QuietHoursStart != null && !TryParseTime(request.QuietHoursStart, out start)) return "invalid_quiet_hours";
            if (request.QuietHoursEnd != null && !TryParseTime(request.QuietHoursEnd, out end)) return "invalid_quiet_hours";

            var pref = await _db.UserNotificationPreferences.FirstOrDefaultAsync(p => p.UserId == userId);
            if (pref == null)
            {
                pref = Defaults(userId);
                _db.UserNotificationPreferences.Add(pref);
            }
            if (request.DoNotDisturb.HasValue) pref.DoNotDisturb = request.DoNotDisturb.Value;
            if (request.QuietHoursStart != null) pref.QuietHoursStart = start;
            if (request.QuietHoursEnd != null) pref.QuietHoursEnd = end;
            if (request.ChannelsEnabled != null)
            {
                var channels = pref.ChannelsEnabled;
                foreach (var kv in request.ChannelsEnabled) channels[kv.Key] = kv.Value;
                pref.ChannelsEnabled = channels;
            }
            await _db.SaveChangesAsync();
            return null;
        }

        /// <summary>
        /// Turns one channel off for a user when the signed token matches (spec: unsubscribe; future messages on that
        /// channel are skipped). Output: true when applied. Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP).
        /// Touches: preferences.
        /// </summary>
        public async Task<bool> UnsubscribeAsync(long userId, string channel, string? token)
        {
            if (!Channels.Contains(channel) || !_tokens.Verify(userId, channel, token)) return false;
            return await UpdatePreferencesAsync(userId, new UpdatePrefRequest { ChannelsEnabled = new() { [channel] = false } }) == null;
        }

        /// <summary>Parses "HH:mm" (00:00-23:59). Pure.</summary>
        private static bool TryParseTime(string text, out TimeSpan? value)
        {
            value = null;
            if (!TimeSpan.TryParseExact(text, @"hh\:mm", System.Globalization.CultureInfo.InvariantCulture, out var t)) return false;
            value = t;
            return true;
        }
    }

    /// <summary>
    /// Delivers due messages: every 200 ms (or at once when signalled) it takes queued messages whose time has come,
    /// oldest first, renders them (variables HTML-encoded in the HTML body; an email gets its signed unsubscribe link)
    /// and hands them to the channel's gateway. In-app messages are delivered by being stored. A failed attempt is
    /// retried after 1 s, then 2 s; the third failure marks the message failed with the error (spec: "retry 3x with
    /// exponential backoff"). Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP), replacing in-memory
    /// closures that used a disposed DbContext. Touches: notification_logs, the gateways (network in production).
    /// </summary>
    public class DeliveryWorker : BackgroundService
    {
        public const int MaxAttempts = 3;
        private readonly IServiceProvider _sp;
        private readonly DeliverySignal _signal;
        private readonly ILogger<DeliveryWorker> _logger;

        public DeliveryWorker(IServiceProvider sp, DeliverySignal signal, ILogger<DeliveryWorker> logger)
        {
            _sp = sp;
            _signal = signal;
            _logger = logger;
        }

        /// <summary>The worker loop: one pass, then wait, until the host stops; a failing pass is logged, not fatal. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: see the class summary.</summary>
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await DeliverDueAsync(stoppingToken);
                    await _signal.WaitAsync(TimeSpan.FromMilliseconds(200), stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Notification delivery poll failed");
                    await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
                }
            }
        }

        /// <summary>One pass over due messages (at most 100). Touches: see the class summary.</summary>
        public async Task DeliverDueAsync(CancellationToken ct)
        {
            using var scope = _sp.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<NotificationDbContext>();
            var now = DateTime.UtcNow;
            var due = await db.NotificationLogs
                .Where(l => l.Status == "queued" && l.ScheduledFor <= now && (l.NextAttemptAt == null || l.NextAttemptAt <= now))
                .OrderBy(l => l.ScheduledFor).ThenBy(l => l.Sequence)
                .Take(100)
                .ToListAsync(ct);
            foreach (var log in due)
            {
                try
                {
                    await DeliverAsync(scope.ServiceProvider, db, log, ct);
                    log.Status = "sent";
                    log.SentAt = DateTime.UtcNow;
                    log.Error = null;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    log.Attempts++;
                    log.Error = ex.Message;
                    if (log.Attempts >= MaxAttempts) log.Status = "failed";
                    else log.NextAttemptAt = DateTime.UtcNow.AddSeconds(Math.Pow(2, log.Attempts - 1));
                    _logger.LogWarning("Notification {MessageId} attempt {Attempt} failed", log.Id, log.Attempts);
                }
                await db.SaveChangesAsync(ct);
            }
        }

        /// <summary>Renders and hands one message to its gateway; throws on failure. Touches: the gateways.</summary>
        private static async Task DeliverAsync(IServiceProvider sp, NotificationDbContext db, NotificationLog log, CancellationToken ct)
        {
            if (log.Channel == "in_app") return; // stored in notification_logs; the app reads it from there
            var template = await db.NotificationTemplates.AsNoTracking().FirstAsync(t => t.Key == log.TemplateKey, ct);
            var vars = JsonSerializer.Deserialize<Dictionary<string, string>>(log.VarsUsed) ?? new();
            var subject = Render(template.Subject, vars, html: false);
            var text = Render(template.BodyText, vars, html: false);
            if (log.Channel == "email")
            {
                var tokens = sp.GetRequiredService<UnsubscribeTokens>();
                var baseUrl = sp.GetRequiredService<IConfiguration>()["Notifications:PublicBaseUrl"] ?? "";
                var link = $"{baseUrl}/notifications/unsubscribe?user_id={log.UserId}&channel=email&token={tokens.Create(log.UserId, "email")}";
                var html = Render(template.BodyHtml, vars, html: true) + $"<p><a href=\"{WebUtility.HtmlEncode(link)}\">Unsubscribe</a></p>";
                await sp.GetRequiredService<IEmailGateway>().SendEmailAsync(log.UserId, subject, html, text + "\n\nUnsubscribe: " + link, ct);
            }
            else if (log.Channel == "sms")
            {
                await sp.GetRequiredService<ISmsGateway>().SendSmsAsync(log.UserId, text, ct);
            }
            else
            {
                throw new InvalidOperationException($"Unsupported channel {log.Channel}");
            }
        }

        /// <summary>Replaces {name} placeholders; values are HTML-encoded when rendering HTML. Pure.</summary>
        public static string Render(string template, Dictionary<string, string> vars, bool html)
        {
            var result = template;
            foreach (var kv in vars)
                result = result.Replace("{" + kv.Key + "}", html ? WebUtility.HtmlEncode(kv.Value) : kv.Value);
            return result;
        }
    }

    #endregion

    #region API Setup

    /// <summary>
    /// Service registration and endpoints. Database: SQLite when ConnectionStrings:Notifications is set, otherwise an
    /// in-memory database (development only: it is lost on restart). Gateways: SMTP when Smtp:Host is set, otherwise
    /// the development outbox; SMS: register your provider's ISmsGateway before calling this, otherwise the
    /// development outbox. Rewritten 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP). Touches: see the file
    /// header. Note: these endpoints take the user id from the route and have no authentication of their own; put
    /// them behind your auth middleware and check the caller may act for that user.
    /// </summary>
    public class Startup
    {
        private readonly IConfiguration _config;

        public Startup(IConfiguration config) => _config = config;

        /// <summary>Registers the database, gateways/stores, services, worker and auth as described on the class. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing until resolved.</summary>
        public void ConfigureServices(IServiceCollection services)
        {
            var cs = _config.GetConnectionString("Notifications");
            if (string.IsNullOrEmpty(cs))
            {
                // One in-memory store per host: a fixed name would be shared by every host in the process, and one
                // host's worker would deliver another host's messages.
                var name = "notifications-" + Guid.NewGuid().ToString("N");
                services.AddDbContext<NotificationDbContext>(opt => opt.UseInMemoryDatabase(name));
            }
            else
                services.AddDbContext<NotificationDbContext>(opt => opt.UseSqlite(cs));

            services.AddSingleton<DevelopmentOutbox>();
            var smtp = _config.GetSection("Smtp").Get<SmtpOptions>();
            if (smtp != null && !string.IsNullOrEmpty(smtp.Host))
            {
                services.AddSingleton(smtp);
                services.AddSingleton<IEmailGateway, SmtpEmailGateway>();
            }
            else
            {
                services.AddSingleton<IEmailGateway>(sp => sp.GetRequiredService<DevelopmentOutbox>());
            }
            services.TryAddSingletonSms();
            services.AddSingleton(new UnsubscribeTokens(_config["Notifications:UnsubscribeSecret"]));
            services.AddSingleton<DeliverySignal>();
            services.AddScoped<NotificationService>();
            services.AddHostedService<DeliveryWorker>();
        }

        /// <summary>Creates the schema (and seeds templates) and maps the endpoints. Touches: the notifications database.</summary>
        public void Configure(WebApplication app)
        {
            using (var scope = app.Services.CreateScope())
                scope.ServiceProvider.GetRequiredService<NotificationDbContext>().Database.EnsureCreated();

            app.MapPost("/notifications/send", async (HttpContext context, NotificationService service) =>
            {
                var payload = await ReadJson<SendRequest>(context);
                if (payload == null) return Results.BadRequest(new { success = false, error = "invalid_payload" });
                var r = await service.SendAsync(payload.UserId, payload.TemplateKey, payload.Channel, payload.Vars, payload.ScheduledAt);
                if (!r.Success) return Results.BadRequest(new { success = false, status = r.Status, error = r.Error });
                return Results.Ok(new { success = true, message_id = r.MessageId, status = r.Status });
            });

            app.MapPost("/notifications/send-batch", async (HttpContext context, NotificationService service) =>
            {
                var batch = await ReadJson<List<SendRequest>>(context);
                if (batch == null) return Results.BadRequest(new { success = false, error = "invalid_payload" });
                if (batch.Count > NotificationService.MaxBatchSize) return Results.BadRequest(new { success = false, error = "batch_too_large" });
                var (sent, skipped, failed, ids) = await service.SendBatchAsync(batch);
                return Results.Ok(new { success = true, sent, skipped, failed, message_ids = ids });
            });

            app.MapGet("/notifications/track/{messageId:guid}", async (Guid messageId, NotificationService service) =>
            {
                var log = await service.TrackAsync(messageId);
                if (log == null) return Results.NotFound();
                return Results.Ok(new
                {
                    message_id = log.Id,
                    user_id = log.UserId,
                    template_key = log.TemplateKey,
                    channel = log.Channel,
                    status = log.Status,
                    sent_at = log.SentAt,
                    opened_at = log.OpenedAt,
                    clicked_at = log.ClickedAt,
                    bounced = log.Bounced,
                    error = log.Error
                });
            });

            app.MapGet("/users/{userId:long}/notification-preferences", async (long userId, NotificationService service) =>
            {
                var pref = await service.GetPreferencesAsync(userId);
                return Results.Ok(new
                {
                    user_id = pref.UserId,
                    do_not_disturb = pref.DoNotDisturb,
                    quiet_hours_start = pref.QuietHoursStart?.ToString(@"hh\:mm"),
                    quiet_hours_end = pref.QuietHoursEnd?.ToString(@"hh\:mm"),
                    channels_enabled = pref.ChannelsEnabled
                });
            });

            app.MapPut("/users/{userId:long}/notification-preferences", async (long userId, HttpContext context, NotificationService service) =>
            {
                var payload = await ReadJson<UpdatePrefRequest>(context);
                if (payload == null) return Results.BadRequest(new { success = false, error = "invalid_payload" });
                var error = await service.UpdatePreferencesAsync(userId, payload);
                return error == null ? Results.Ok(new { success = true }) : Results.BadRequest(new { success = false, error });
            });

            app.MapGet("/notifications/unsubscribe", async (long user_id, string channel, string? token, NotificationService service) =>
                await service.UnsubscribeAsync(user_id, channel, token)
                    ? Results.Ok(new { success = true })
                    : Results.BadRequest(new { success = false, error = "invalid_unsubscribe_link" }));
        }

        /// <summary>Reads a JSON body, or null when it is missing or malformed. Touches: the request body.</summary>
        private static async Task<T?> ReadJson<T>(HttpContext context) where T : class
        {
            try { return await JsonSerializer.DeserializeAsync<T>(context.Request.Body); }
            catch (JsonException) { return null; }
        }
    }

    /// <summary>Registration helper: the development outbox serves SMS unless an ISmsGateway was registered first.</summary>
    public static class SmsRegistration
    {
        /// <summary>Registers the development outbox as ISmsGateway unless one is registered already. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the service collection.</summary>
        public static void TryAddSingletonSms(this IServiceCollection services)
        {
            if (services.Any(d => d.ServiceType == typeof(ISmsGateway))) return;
            services.AddSingleton<ISmsGateway>(sp => sp.GetRequiredService<DevelopmentOutbox>());
        }
    }

    /// <summary>
    /// Body of a send request and of each batch item, in the spec's snake_case field names. Changed 2026-11-10 (session
    /// session_012zDydZCZ4AChqhEZ4oVtaP): without the names nothing bound and every request had user 0 and no template.
    /// Pure data.
    /// </summary>
    public class SendRequest
    {
        [JsonPropertyName("user_id")] public long UserId { get; set; }
        [JsonPropertyName("template_key")] public string? TemplateKey { get; set; }
        [JsonPropertyName("channel")] public string? Channel { get; set; }
        [JsonPropertyName("vars")] public Dictionary<string, string>? Vars { get; set; }
        [JsonPropertyName("scheduled_at")] public DateTime? ScheduledAt { get; set; }
    }

    /// <summary>Body of a preferences update; quiet hours are "HH:mm" UTC. Pure data.</summary>
    public class UpdatePrefRequest
    {
        [JsonPropertyName("do_not_disturb")] public bool? DoNotDisturb { get; set; }
        [JsonPropertyName("quiet_hours_start")] public string? QuietHoursStart { get; set; }
        [JsonPropertyName("quiet_hours_end")] public string? QuietHoursEnd { get; set; }
        [JsonPropertyName("channels_enabled")] public Dictionary<string, bool>? ChannelsEnabled { get; set; }
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

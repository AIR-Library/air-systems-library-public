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
// IRecipientDirectory, a hosted worker delivers due messages from the database with up to 3 retries after the first
// attempt (4 attempts; 1 s / 2 s / 4 s; Phase B.2, 2026-11-10), and unsubscribe links carry an HMAC that is checked in
// constant time.
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
    /// One notification (spec schema notification_logs) and its delivery state. Status: queued, sending, sent, failed,
    /// skipped, opened, bounced. SentAt is set only when a provider accepted the message; ScheduledAt and NextAttemptAt
    /// drive deliver_due; ClaimedAt is when a worker claimed it ('sending'). Status and ClaimedAt are concurrency tokens,
    /// so every write is conditional on the values read (the spec's "UPDATE ... WHERE status = 'queued'" claim and
    /// "WHERE status = 'sending' AND claimed_at = &lt;this claim&gt;" final write).
    /// Changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): status started as "sent" before anything was sent.
    /// Changed again 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-12): ScheduledFor renamed ScheduledAt (spec
    /// column scheduled_at), ClaimedAt added. Pure data.
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
        public DateTime ScheduledAt { get; set; }
        public DateTime? ClaimedAt { get; set; }
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
            // Conditional writes for deliver_due (NOTIF-12; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
            modelBuilder.Entity<NotificationLog>().Property(l => l.Status).IsConcurrencyToken();
            modelBuilder.Entity<NotificationLog>().Property(l => l.ClaimedAt).IsConcurrencyToken();

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
    /// Builds and checks unsubscribe tokens (NOTIF-11, amended 2026-11-10): token = lower-case hex of
    /// HMAC-SHA256(secret, "unsubscribe:" + user_id + ":" + channel). The secret comes from configuration
    /// (Notifications:UnsubscribeSecret) and must be at least 32 bytes, or the service refuses to start (an empty key
    /// makes a forgeable HMAC). Verify refuses, the same way and before any user lookup, a token that is not exactly
    /// 64 characters of [0-9a-f], an unknown channel and a mismatch; the comparison is constant-time and never throws.
    /// Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: it was base64url over "userId:channel" and fell back to a
    /// random per-process secret. Pure.
    /// </summary>
    public class UnsubscribeTokens
    {
        private readonly byte[] _key;

        /// <summary>Throws ArgumentException for a missing secret or one shorter than 32 bytes (UTF-8).</summary>
        public UnsubscribeTokens(string? secret)
        {
            if (string.IsNullOrEmpty(secret) || Encoding.UTF8.GetByteCount(secret) < 32)
                throw new ArgumentException("Notifications:UnsubscribeSecret must be set and at least 32 bytes");
            _key = Encoding.UTF8.GetBytes(secret);
        }

        /// <summary>The token for a user and channel: 64 lower-case hex characters. Pure.</summary>
        public string Create(long userId, string channel)
        {
            using var hmac = new HMACSHA256(_key);
            var mac = hmac.ComputeHash(Encoding.UTF8.GetBytes($"unsubscribe:{userId}:{channel}"));
            return Convert.ToHexString(mac).ToLowerInvariant();
        }

        /// <summary>True when the token is well-formed, the channel is known and the token was issued for them. Pure.</summary>
        public bool Verify(long userId, string? channel, string? token)
        {
            if (token == null || token.Length != 64 || !token.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                return false;
            if (channel == null || !NotificationService.Channels.Contains(channel))
                return false;
            var expected = Encoding.ASCII.GetBytes(Create(userId, channel));
            return CryptographicOperations.FixedTimeEquals(expected, Encoding.ASCII.GetBytes(token));
        }
    }

    /// <summary>
    /// The clock the service and worker read (UTC). Tests replace <see cref="Now"/> to move time. Added 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-05/08/12 are tested at exact times). Touches nothing.
    /// </summary>
    public class NotificationClock
    {
        public Func<DateTime> Now { get; set; } = () => DateTime.UtcNow;
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
        private readonly NotificationClock _clock;

        /// <summary>
        /// In: the database, the worker's wake-up signal, the unsubscribe token service and the clock.
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the clock. Touches nothing.
        /// </summary>
        public NotificationService(NotificationDbContext db, DeliverySignal signal, UnsubscribeTokens tokens, NotificationClock clock)
        {
            _db = db;
            _signal = signal;
            _tokens = tokens;
            _clock = clock;
        }

        /// <summary>
        /// The preferences a user without a stored row gets: do_not_disturb false, no quiet hours, channels
        /// {email: true, sms: false, in_app: true}. SMS is opt-in (it costs money and needs prior consent).
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-02 amendment): every channel was on. Pure.
        /// </summary>
        public static UserNotificationPreference Defaults(long userId) => new()
        {
            UserId = userId,
            ChannelsEnabled = new Dictionary<string, bool> { ["email"] = true, ["sms"] = false, ["in_app"] = true }
        };

        /// <summary>True when the preferences allow this channel now: not do-not-disturb and the channel is on. Pure.</summary>
        public static bool Allows(UserNotificationPreference pref, string channel) =>
            !pref.DoNotDisturb && pref.ChannelsEnabled.TryGetValue(channel, out var on) && on;

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
        /// The first moment at or after <paramref name="at"/> (UTC) that is the user's quiet_hours_end: today's end time,
        /// or tomorrow's when today's has passed (a window crossing midnight, 22:00-07:00, ends the next morning). In:
        /// the preferences (with quiet hours set) and a time inside them. Out: scheduled_at for a held message. Pure.
        /// Why: NOTIF-05 and deliver_due step 3 both hold a message until quiet_hours_end. Added 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2; was inline in SendAsync).
        /// </summary>
        public static DateTime QuietHoursEndAfter(UserNotificationPreference pref, DateTime at)
        {
            var end = at.Date.Add(pref.QuietHoursEnd!.Value);
            if (end <= at) end = end.AddDays(1);
            return DateTime.SpecifyKind(end, DateTimeKind.Utc);
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
        /// on or the chosen channel is disabled; otherwise queues it ('queued' with scheduled_at) for now, for
        /// scheduled_at, or, inside quiet hours, for quiet_hours_end (NOTIF-05), whichever is latest; deliver_due sends
        /// it (NOTIF-12). Time comes from the injected clock (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Only the template's declared variables are kept. Output: success, message id and
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
            var now = _clock.Now();
            var selected = pref.DoNotDisturb ? null : ChooseChannel(channel, template, pref.ChannelsEnabled);

            var log = new NotificationLog
            {
                UserId = userId,
                TemplateKey = template.Key,
                Channel = selected ?? channel ?? "none",
                VarsUsed = JsonSerializer.Serialize(kept),
                CreatedAt = now,
                ScheduledAt = now,
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
                    due = QuietHoursEndAfter(pref, due);
                log.ScheduledAt = due;
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
        /// The unsubscribe link's POST (NOTIF-11): when the token is valid for this user and channel (checked first,
        /// before any user lookup; see <see cref="UnsubscribeTokens.Verify"/>), sets channels_enabled[channel] = false.
        /// Out: true when applied; false (nothing changed) for a missing, malformed, altered or foreign token or an
        /// unknown channel. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: hex HMAC token, GET no longer changes
        /// anything (see <see cref="CheckUnsubscribeLink"/>). Touches: preferences.
        /// </summary>
        public async Task<bool> UnsubscribeAsync(long userId, string? channel, string? token)
        {
            if (!_tokens.Verify(userId, channel, token)) return false;
            return await UpdatePreferencesAsync(userId, new UpdatePrefRequest { ChannelsEnabled = new() { [channel!] = false } }) == null;
        }

        /// <summary>
        /// The unsubscribe link's GET: only says whether the link is valid, so a mail scanner that follows links changes
        /// nothing (RFC 8058 one-click uses POST). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Pure.
        /// </summary>
        public bool CheckUnsubscribeLink(long userId, string? channel, string? token) => _tokens.Verify(userId, channel, token);

        /// <summary>
        /// Tracking (NOTIF-07): GET /notifications/open/:message_id, the tracking pixel or link of a delivered message.
        /// The first time only it sets opened_at and status 'opened'; a later call changes nothing. In: the message id (a
        /// random GUID, so it cannot be guessed). Out: true when this call recorded the opening; false for an unknown or
        /// undelivered message or one already opened (the route answers 204 either way). Added 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP (there was no tracking write at all). Changed the same day (Phase B.2,
        /// spec "Opening"): once only, and clicked_at is no longer set by an open. Touches: notification_logs.
        /// </summary>
        public async Task<bool> MarkOpenedAsync(Guid messageId)
        {
            var log = await _db.NotificationLogs.FirstOrDefaultAsync(l => l.Id == messageId);
            if (log == null || log.SentAt == null || log.OpenedAt != null) return false;
            log.OpenedAt = _clock.Now();
            log.Status = "opened";
            try
            {
                await _db.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                return false;
            }
            return true;
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
    /// Delivers due messages: every 200 ms (or at once when signalled) it runs <see cref="DeliverDueAsync(DateTime, CancellationToken)"/>
    /// with the clock's time. Rendering: variables HTML-encoded in the HTML body; an email gets its signed unsubscribe
    /// link. In-app messages are delivered by being stored. A failed attempt is retried after 1 s, 2 s, then 4 s; the
    /// fourth failure marks the message failed (spec, amended in Phase B.2: up to 3 retries after the first attempt,
    /// at most 4 attempts; MaxAttempts was 3 until 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Added 2026-11-10 (session
    /// session_012zDydZCZ4AChqhEZ4oVtaP), replacing in-memory closures that used a disposed DbContext; deliver_due's
    /// four steps added the same day (NOTIF-12). Touches: notification_logs, preferences (read), the gateways.
    /// </summary>
    public class DeliveryWorker : BackgroundService
    {
        /// <summary>The first attempt plus up to 3 retries (NOTIF-08, Phase B.2 2026-11-10; was 3 attempts).</summary>
        public const int MaxAttempts = 4;

        /// <summary>A 'sending' row claimed longer ago than this is re-queued (a crashed worker).</summary>
        public static readonly TimeSpan ClaimTimeout = TimeSpan.FromSeconds(300);

        private readonly IServiceProvider _sp;
        private readonly DeliverySignal _signal;
        private readonly ILogger<DeliveryWorker> _logger;
        private readonly NotificationClock _clock;

        /// <summary>In: the service provider, the wake-up signal, a logger and the clock. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the clock.</summary>
        public DeliveryWorker(IServiceProvider sp, DeliverySignal signal, ILogger<DeliveryWorker> logger, NotificationClock clock)
        {
            _sp = sp;
            _signal = signal;
            _logger = logger;
            _clock = clock;
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

        /// <summary>One pass at the clock's time. Touches: see the class summary.</summary>
        public Task<int> DeliverDueAsync(CancellationToken ct) => DeliverDueAsync(_clock.Now(), ct);

        /// <summary>
        /// deliver_due(now), the spec's four steps (NOTIF-12, amended 2026-11-10):
        /// 1. 'sending' rows with claimed_at + 300 s &lt; now go back to 'queued' (a crashed worker);
        /// 2. 'queued' rows with scheduled_at &lt;= now (and any retry wait over), by scheduled_at then insertion order, at
        ///    most 100, are claimed one by one with a conditional write (status 'queued' -&gt; 'sending', claimed_at = now);
        ///    a row another worker claimed first is skipped;
        /// 3. preferences are read NOW: do-not-disturb or the channel turned off (unsubscribed) -&gt; 'skipped'; inside the
        ///    user's quiet hours (email and SMS; in-app is never held, as in send) -&gt; back to 'queued' with
        ///    scheduled_at = quiet_hours_end (added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, Phase B.2);
        /// 4. the outcome (sent / retry later / failed / skipped) is written conditionally on status 'sending' and this
        ///    claimed_at, so a row re-queued meanwhile is not overwritten.
        /// In: the time to judge "due" by. Out: how many messages were sent in this pass.
        /// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: notification_logs, preferences, the gateways.
        /// </summary>
        public async Task<int> DeliverDueAsync(DateTime now, CancellationToken ct)
        {
            using var scope = _sp.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<NotificationDbContext>();

            // 1. re-queue stale claims
            var staleBefore = now - ClaimTimeout;
            var stale = await db.NotificationLogs
                .Where(l => l.Status == "sending" && l.ClaimedAt != null && l.ClaimedAt < staleBefore)
                .ToListAsync(ct);
            foreach (var log in stale)
            {
                log.Status = "queued";
                log.ClaimedAt = null;
                await TrySaveAsync(db, ct);
            }

            // 2. due rows, oldest first
            var dueIds = await db.NotificationLogs
                .Where(l => l.Status == "queued" && l.ScheduledAt <= now && (l.NextAttemptAt == null || l.NextAttemptAt <= now))
                .OrderBy(l => l.ScheduledAt).ThenBy(l => l.Sequence)
                .Select(l => l.Id)
                .Take(100)
                .ToListAsync(ct);

            var sent = 0;
            foreach (var id in dueIds)
            {
                db.ChangeTracker.Clear();
                var log = await db.NotificationLogs.FirstOrDefaultAsync(l => l.Id == id && l.Status == "queued", ct);
                if (log == null) continue;
                log.Status = "sending";
                log.ClaimedAt = now;
                if (!await TrySaveAsync(db, ct)) continue; // another worker claimed it first

                // 3. preferences as they are now
                var pref = await db.UserNotificationPreferences.AsNoTracking().FirstOrDefaultAsync(p => p.UserId == log.UserId, ct)
                    ?? NotificationService.Defaults(log.UserId);
                if (!NotificationService.Allows(pref, log.Channel))
                {
                    log.Status = "skipped";
                    log.Error = pref.DoNotDisturb ? "do_not_disturb" : "channel_disabled";
                }
                else if (log.Channel != "in_app" && NotificationService.IsInQuietHours(pref, now))
                {
                    log.Status = "queued";
                    log.ClaimedAt = null;
                    log.ScheduledAt = NotificationService.QuietHoursEndAfter(pref, now);
                }
                else
                {
                    try
                    {
                        await DeliverAsync(scope.ServiceProvider, db, log, ct);
                        log.Status = "sent";
                        log.SentAt = now;
                        log.Error = null;
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        log.Attempts++;
                        log.Error = ex.Message;
                        if (log.Attempts >= MaxAttempts)
                        {
                            log.Status = "failed";
                        }
                        else
                        {
                            log.Status = "queued";
                            log.ClaimedAt = null;
                            log.NextAttemptAt = now.AddSeconds(Math.Pow(2, log.Attempts - 1));
                        }
                        _logger.LogWarning("Notification {MessageId} attempt {Attempt} failed", log.Id, log.Attempts);
                    }
                }

                // 4. conditional final write (original status 'sending' and this claimed_at)
                if (await TrySaveAsync(db, ct) && log.Status == "sent") sent++;
            }
            return sent;
        }

        /// <summary>
        /// SaveChanges as a conditional write: false when the row changed since it was read (another worker claimed or
        /// re-queued it). Only DbUpdateConcurrencyException is caught. Touches: the database.
        /// </summary>
        private async Task<bool> TrySaveAsync(NotificationDbContext db, CancellationToken ct)
        {
            try
            {
                await db.SaveChangesAsync(ct);
                return true;
            }
            catch (DbUpdateConcurrencyException)
            {
                db.ChangeTracker.Clear();
                return false;
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
                var link = $"{baseUrl}/unsubscribe?user_id={log.UserId}&channel=email&token={tokens.Create(log.UserId, "email")}";
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
            // Built on first use from the host's final configuration; Configure resolves it at start-up, so a missing or
            // short secret stops the service from starting (NOTIF-11; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
            services.AddSingleton(sp => new UnsubscribeTokens(sp.GetRequiredService<IConfiguration>()["Notifications:UnsubscribeSecret"]));
            services.AddSingleton<NotificationClock>();
            services.AddSingleton<DeliverySignal>();
            services.AddScoped<NotificationService>();
            services.AddHostedService<DeliveryWorker>();
        }

        /// <summary>Creates the schema (and seeds templates) and maps the endpoints. Touches: the notifications database.</summary>
        public void Configure(WebApplication app)
        {
            // refuse to start without a usable unsubscribe secret (throws ArgumentException)
            app.Services.GetRequiredService<UnsubscribeTokens>();
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
                    scheduled_at = log.ScheduledAt,
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

            // Unsubscribe link (NOTIF-11; changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): GET only confirms, POST
            // unsubscribes; any bad link is the same 403 invalid_unsubscribe_token. Query values are read as strings so
            // a malformed user id is also that 403, not a binding error.
            app.MapGet("/unsubscribe", (HttpContext context, NotificationService service) =>
            {
                var (ok, userId, channel, token) = ReadLink(context);
                return ok && service.CheckUnsubscribeLink(userId, channel, token)
                    ? Results.Ok(new { confirm = true, user_id = userId, channel, message = "POST to this link to unsubscribe" })
                    : Results.Json(new { error = "invalid_unsubscribe_token" }, statusCode: 403);
            });
            app.MapPost("/unsubscribe", async (HttpContext context, NotificationService service) =>
            {
                var (ok, userId, channel, token) = ReadLink(context);
                return ok && await service.UnsubscribeAsync(userId, channel, token)
                    ? Results.Ok(new { success = true })
                    : Results.Json(new { error = "invalid_unsubscribe_token" }, statusCode: 403);
            });

            // Tracking (NOTIF-07): the tracking pixel or link marks a message opened the first time; the answer is 204
            // either way, so the URL says nothing about the message. Changed 2026-11-10, session
            // session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, spec "Opening": was 200, and 404 for an unknown message).
            // Touches: notification_logs.
            app.MapGet("/notifications/open/{messageId:guid}", async (Guid messageId, NotificationService service) =>
            {
                await service.MarkOpenedAsync(messageId);
                return Results.NoContent();
            });
        }

        /// <summary>The unsubscribe link's user_id, channel and token from the query; ok false when user_id is not a number. Pure.</summary>
        private static (bool Ok, long UserId, string? Channel, string? Token) ReadLink(HttpContext context)
        {
            var q = context.Request.Query;
            var ok = long.TryParse(q["user_id"].ToString(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var userId);
            return (ok, userId, q["channel"].ToString(), q["token"].ToString());
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

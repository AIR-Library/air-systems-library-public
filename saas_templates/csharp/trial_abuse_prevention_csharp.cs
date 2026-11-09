using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace TrialAbusePrevention
{
    public enum GateDecision { Pass, Challenge, Fail }

    public class GateCheckResult
    {
        public GateDecision Decision { get; set; }
        public string Reason { get; set; }
        public int? RetryAfterSeconds { get; set; }
        public string ChallengeType { get; set; } // For CHALLENGE: "captcha" or "email_confirm"
    }

    public class TrialAbusePreventionService
    {
        private readonly TrialAbusePreventionDbContext _context;
        private readonly ILogger<TrialAbusePreventionService> _logger;
        private const int TrialDays = 14; // Example trial duration, should be configurable

        public TrialAbusePreventionService(TrialAbusePreventionDbContext context, ILogger<TrialAbusePreventionService> logger)
        {
            _context = context;
            _logger = logger;
        }

        /// <summary>
        /// Gate: counts completed or charged-back trials for this e-mail. Output: Pass/Challenge/Fail with a reason.
        /// The log line carries no e-mail address (personal data). Touches: reads the ledger. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
        public async Task<GateCheckResult> CheckEmailTrialHistory(string email)
        {
            var priorCount = await _context.TrialAbuseLedgers
                .CountAsync(l => l.Email == email &&
                                 (l.SubscriptionStatus == "completed" || l.SubscriptionStatus == "chargebacked"));

            GateDecision decision;
            if (priorCount == 0) decision = GateDecision.Pass;
            else if (priorCount == 1) decision = GateDecision.Challenge;
            else decision = GateDecision.Fail;

            var reason = $"Email {email} has {priorCount} prior trial(s)";
            // The address stays out of the log: it is personal data, and the count and decision are what an operator needs.
            // Code scanning alert cs/exposure-of-sensitive-information, 2026-11-05, session f3daac6e.
            _logger.LogInformation("Gate check: email_trial_history, prior_count={PriorCount}, decision={Decision}",
                priorCount, decision);

            return new GateCheckResult { Decision = decision, Reason = reason };
        }

        /// <summary>
        /// Gate: counts prior completed or charged-back trials on this payment method. Touches: reads the ledger. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
        public async Task<GateCheckResult> CheckPaymentMethodHistory(string stripePaymentMethodId)
        {
            var priorCount = await _context.TrialAbuseLedgers
                .CountAsync(l => l.StripePaymentMethodId == stripePaymentMethodId &&
                                 (l.SubscriptionStatus == "completed" || l.SubscriptionStatus == "chargebacked"));

            GateDecision decision;
            if (priorCount < 2) decision = GateDecision.Pass;
            else if (priorCount == 2) decision = GateDecision.Challenge;
            else decision = GateDecision.Fail;

            var reason = $"Payment method {stripePaymentMethodId} used in {priorCount} prior trial(s)";
            _logger.LogInformation("Gate check: payment_method_history, payment_id={PaymentId}, prior_count={PriorCount}, decision={Decision}",
                stripePaymentMethodId, priorCount, decision);

            return new GateCheckResult { Decision = decision, Reason = reason };
        }

        /// <summary>
        /// Gate: counts signups from this IP in the last 24 hours. Touches: reads signups. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
        public async Task<GateCheckResult> CheckIpSignupRateLimit(string ip)
        {
            var count = await _context.Signups
                .CountAsync(s => s.Ip == ip &&
                                 s.CreatedAt >= DateTime.UtcNow.AddHours(-24));

            GateDecision decision;
            if (count < 5) decision = GateDecision.Pass;
            else if (count < 10) decision = GateDecision.Challenge;
            else decision = GateDecision.Fail;

            var reason = $"IP {ip} has {count} signup(s) in last 24 hours";
            _logger.LogInformation("Gate check: ip_signup_rate_limit, ip={Ip}, count={Count}, decision={Decision}",
                ip, count, decision);

            return new GateCheckResult
            {
                Decision = decision,
                Reason = reason,
                RetryAfterSeconds = decision == GateDecision.Fail ? 86400 : (int?)null
            };
        }

        /// <summary>
        /// Gate: hashes the device traits and counts other users on the same device. Touches: reads fingerprints. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
        public async Task<GateCheckResult> CheckDeviceFingerprint(string userAgent, string screenResolution, string timezone, string browserLanguage, string userId = null)
        {
            var device = $"{userAgent}|{screenResolution}|{timezone}|{browserLanguage}";
            var deviceHash = ComputeSha256Hash(device);

            var matchingUsers = await _context.DeviceFingerprints
                .Where(df => df.DeviceHash == deviceHash)
                .Select(df => df.UserId)
                .Distinct()
                .CountAsync();

            bool matchesKnownDevice = false;
            if (!string.IsNullOrEmpty(userId))
            {
                matchesKnownDevice = await _context.DeviceFingerprints
                    .AnyAsync(df => df.DeviceHash == deviceHash && df.UserId == userId);
            }

            GateDecision decision;
            if (matchingUsers < 2 || matchesKnownDevice) decision = GateDecision.Pass;
            else if (matchingUsers <= 5) decision = GateDecision.Challenge;
            else decision = GateDecision.Fail;

            var reason = $"Device hash {deviceHash} matches {matchingUsers} user(s)";
            _logger.LogInformation("Gate check: device_fingerprint, device_hash={DeviceHash}, matching_users={MatchingUsers}, decision={Decision}",
                deviceHash, matchingUsers, decision);

            return new GateCheckResult { Decision = decision, Reason = reason };
        }

        /// <summary>
        /// Gate: compares when payment was added with the trial window. Fail for an unknown user. Touches: reads users and ledger. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
        public async Task<GateCheckResult> CheckTrialPaymentTiming(string userId)
        {
            var user = await _context.Users.FindAsync(userId);
            if (user == null)
            {
                var notFoundReason = $"User {userId} not found";
                _logger.LogWarning("Gate check: trial_payment_timing, user_id={UserId}, reason={Reason}", userId, notFoundReason);
                return new GateCheckResult { Decision = GateDecision.Fail, Reason = notFoundReason };
            }

            var trialStartDate = user.CreatedAt;
            var now = DateTime.UtcNow;
            var daysElapsed = (now - trialStartDate).Days;
            var paymentAddedDate = await _context.TrialAbuseLedgers
                .Where(l => l.UserId == userId)
                .Select(l => l.PaymentAddedDate)
                .OrderByDescending(d => d)
                .FirstOrDefaultAsync();

            GateDecision decision;
            if (daysElapsed < TrialDays + 5 && paymentAddedDate.HasValue && paymentAddedDate.Value > trialStartDate)
                decision = GateDecision.Pass;
            else if (daysElapsed > TrialDays + 30 && paymentAddedDate.HasValue && paymentAddedDate.Value > trialStartDate.AddDays(TrialDays))
                decision = GateDecision.Challenge;
            else if (daysElapsed > TrialDays && !paymentAddedDate.HasValue && now > trialStartDate.AddDays(TrialDays + 90))
                decision = GateDecision.Fail;
            else
                decision = GateDecision.Pass; // Default to pass if none of the above conditions match

            var reason = $"Trial started {daysElapsed} days ago, payment added { (paymentAddedDate.HasValue ? ((now - paymentAddedDate.Value).Days.ToString() + " days ago") : "never") }";
            _logger.LogInformation("Gate check: trial_payment_timing, user_id={UserId}, trial_duration={TrialDuration}, payment_delay={PaymentDelay}, decision={Decision}",
                userId, daysElapsed, paymentAddedDate.HasValue ? (now - paymentAddedDate.Value).Days : (int?)null, decision);

            return new GateCheckResult { Decision = decision, Reason = reason };
        }

        /// <summary>
        /// Gate: counts Stripe chargeback events and charged-back refunds for the user. Touches: reads events and refunds. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
        public async Task<GateCheckResult> CheckChargebackHistory(string stripeCustomerId, string userId)
        {
            var stripeChargebacks = await _context.StripeEvents
                .CountAsync(e => e.Customer == stripeCustomerId &&
                                 e.Type.Contains("chargeback"));

            var refundChargebacks = await _context.Refunds
                .CountAsync(r => r.UserId == userId &&
                                 r.Status == "chargebacked");

            var totalChargebacks = stripeChargebacks + refundChargebacks;

            GateDecision decision;
            if (totalChargebacks == 0) decision = GateDecision.Pass;
            else if (totalChargebacks == 1) decision = GateDecision.Challenge;
            else decision = GateDecision.Fail;

            var reason = $"User {userId} has {totalChargebacks} chargeback(s)";
            _logger.LogInformation("Gate check: chargeback_history, user_id={UserId}, chargebacks={Chargebacks}, decision={Decision}",
                userId, totalChargebacks, decision);

            return new GateCheckResult { Decision = decision, Reason = reason };
        }

        /// <summary>
        /// Appends a trial ledger entry. Touches: inserts one row. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
        public async Task LogAbuseEntry(TrialAbuseLedger entry)
        {
            _context.TrialAbuseLedgers.Add(entry);
            await _context.SaveChangesAsync();
        }

        /// <summary>
        /// Records one gate decision. Touches: inserts one row. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
        public async Task LogGateDecision(GateDecisionLog log)
        {
            _context.GateDecisionLogs.Add(log);
            await _context.SaveChangesAsync();
        }

        /// <summary>
        /// Lower-case hex SHA-256 of the UTF-8 input (device fingerprints). Pure. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
        public static string ComputeSha256Hash(string input)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var bytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(input));
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }
    }

    public class TrialAbusePreventionDbContext : DbContext
    {
        public TrialAbusePreventionDbContext(DbContextOptions<TrialAbusePreventionDbContext> options) : base(options) { }

        public DbSet<TrialAbuseLedger> TrialAbuseLedgers { get; set; }
        public DbSet<DeviceFingerprint> DeviceFingerprints { get; set; }
        public DbSet<GateDecisionLog> GateDecisionLogs { get; set; }
        public DbSet<Signup> Signups { get; set; }
        public DbSet<StripeEvent> StripeEvents { get; set; }
        public DbSet<Refund> Refunds { get; set; }
        public DbSet<User> Users { get; set; }

        /// <summary>
        /// Maps the trial-abuse entities; AbuseFlags stays text (comma-separated flags, not JSON). Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<TrialAbuseLedger>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Email).IsRequired().HasMaxLength(255);
                entity.Property(e => e.StripePaymentMethodId).HasMaxLength(255);
                entity.Property(e => e.Ip).IsRequired();
                entity.Property(e => e.DeviceFingerprint).HasMaxLength(64); // SHA256 hash
                entity.Property(e => e.GateFlags).HasColumnType("jsonb");
            });

            modelBuilder.Entity<DeviceFingerprint>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.DeviceHash).IsRequired().HasMaxLength(64);
                entity.Property(e => e.UserAgent).IsRequired();
                entity.Property(e => e.ScreenResolution).IsRequired();
                entity.Property(e => e.Timezone).IsRequired();
                entity.Property(e => e.BrowserLanguage).IsRequired();
            });

            modelBuilder.Entity<GateDecisionLog>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.GateName).IsRequired().HasMaxLength(50);
                entity.Property(e => e.Decision).IsRequired().HasMaxLength(10);
                entity.Property(e => e.RuleInputs).HasColumnType("jsonb");
                entity.Property(e => e.RuleOutputs).HasColumnType("jsonb");
            });

            modelBuilder.Entity<Signup>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Ip).IsRequired();
                entity.Property(e => e.CreatedAt).IsRequired();
            });

            modelBuilder.Entity<StripeEvent>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Customer).IsRequired();
                entity.Property(e => e.Type).IsRequired();
            });

            modelBuilder.Entity<Refund>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.UserId).IsRequired();
                entity.Property(e => e.Status).IsRequired().HasMaxLength(50);
            });

            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.CreatedAt).IsRequired();
                entity.Property(e => e.AbuseFlags).HasColumnType("text");   // comma-separated flags, not JSON
            });
        }
    }

    public class TrialAbuseLedger
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string Email { get; set; }
        public string StripePaymentMethodId { get; set; }
        public string Ip { get; set; }
        public string DeviceFingerprint { get; set; }
        public DateTime SignupDate { get; set; }
        public DateTime TrialStartedAt { get; set; }
        public DateTime? PaymentAddedDate { get; set; }
        public string SubscriptionStatus { get; set; }
        public int ChargebackCount { get; set; }
        public int RefundCount { get; set; }
        public string GateFlags { get; set; } // JSON
        public string AlertReason { get; set; }
        public DateTime CreatedAt { get; set; }
    }

    public class DeviceFingerprint
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string DeviceHash { get; set; }
        public string UserAgent { get; set; }
        public string ScreenResolution { get; set; }
        public string Timezone { get; set; }
        public string BrowserLanguage { get; set; }
        public DateTime CreatedAt { get; set; }
    }

    public class GateDecisionLog
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string GateName { get; set; }
        public string Decision { get; set; } // Pass, Challenge, Fail
        public string RuleInputs { get; set; } // JSON
        public string RuleOutputs { get; set; } // JSON
        public DateTime CreatedAt { get; set; }
    }

    public class Signup
    {
        public int Id { get; set; }
        public string Ip { get; set; }
        public DateTime CreatedAt { get; set; }
    }

    public class StripeEvent
    {
        public int Id { get; set; }
        public string Customer { get; set; }
        public string Type { get; set; }
        public DateTime CreatedAt { get; set; }
    }

    public class Refund
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string Status { get; set; }
        public DateTime CreatedAt { get; set; }
    }

    public class User
    {
        public string Id { get; set; }
        public DateTime CreatedAt { get; set; }
        public string AbuseFlags { get; set; } // Comma-separated flags
    }

    public static class TrialAbusePreventionSchema
    {
        /// <summary>
        /// The plain SQL that creates the ledger, fingerprint and decision tables with their indexes. Pure. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
        public static string GetCreateTablesSql()
        {
            return @"
CREATE TABLE IF NOT EXISTS trial_abuse_ledger (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    stripe_payment_method_id VARCHAR(255),
    ip INET NOT NULL,
    device_fingerprint VARCHAR(64),
    signup_date TIMESTAMP WITH TIME ZONE NOT NULL,
    trial_started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    payment_added_date TIMESTAMP WITH TIME ZONE,
    subscription_status VARCHAR(50),
    chargeback_count INTEGER DEFAULT 0,
    refund_count INTEGER DEFAULT 0,
    gate_flags JSONB,
    alert_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS device_fingerprints (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    device_hash VARCHAR(64) NOT NULL,
    user_agent TEXT NOT NULL,
    screen_resolution VARCHAR(50) NOT NULL,
    timezone VARCHAR(50) NOT NULL,
    browser_language VARCHAR(10) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS gate_decisions (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    gate_name VARCHAR(50) NOT NULL,
    decision VARCHAR(10) NOT NULL,
    rule_inputs JSONB,
    rule_outputs JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_trial_abuse_ledger_email ON trial_abuse_ledger(email);
CREATE INDEX IF NOT EXISTS idx_trial_abuse_ledger_stripe_payment_method_id ON trial_abuse_ledger(stripe_payment_method_id);
CREATE INDEX IF NOT EXISTS idx_signups_ip_created_at ON signups(ip, created_at);
CREATE INDEX IF NOT EXISTS idx_device_fingerprints_device_hash ON device_fingerprints(device_hash);
CREATE INDEX IF NOT EXISTS idx_gate_decisions_user_id ON gate_decisions(user_id);
";
        }
    }
}

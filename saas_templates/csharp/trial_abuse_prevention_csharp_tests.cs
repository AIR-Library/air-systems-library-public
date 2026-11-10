using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using TrialAbusePrevention;
using Xunit;

namespace TrialAbusePreventionTests
{
    public class TrialAbusePreventionTests : IDisposable
    {
        private readonly DbContextOptions<TrialAbusePreventionDbContext> _options;
        private readonly TrialAbusePreventionDbContext _context;
        private TrialAbusePreventionService _service;
        private readonly ILogger<TrialAbusePreventionService> _logger = Mock.Of<ILogger<TrialAbusePreventionService>>();

        public TrialAbusePreventionTests()
        {
            _options = new DbContextOptionsBuilder<TrialAbusePreventionDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            _context = new TrialAbusePreventionDbContext(_options);
            _context.Database.EnsureCreated();
            _service = new TrialAbusePreventionService(_context, _logger, () => _now);
        }

        /// <summary>The service's clock (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): tests set it to exact boundaries.</summary>
        private DateTime _now = DateTime.UtcNow;

        /// <summary>Adds a user whose trial (14 days) ended exactly <paramref name="daysAfterTrial"/> days before _now. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private async Task<string> UserWithTrialEndedDaysAgo(string userId, double daysAfterTrial, DateTime? earlierPayment = null)
        {
            _context.Users.Add(new User { Id = userId, CreatedAt = _now.AddDays(-14 - daysAfterTrial) });
            if (earlierPayment.HasValue)
                _context.TrialAbuseLedgers.Add(new TrialAbuseLedger
                {
                    UserId = userId, Email = userId + "@example.com", Ip = "1.2.3.4",
                    SignupDate = _now.AddDays(-14 - daysAfterTrial), TrialStartedAt = _now.AddDays(-14 - daysAfterTrial),
                    PaymentAddedDate = earlierPayment, SubscriptionStatus = "active"
                });
            await _context.SaveChangesAsync();
            return userId;
        }

        /// <summary>Gives <paramref name="count"/> distinct users the test device. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private async Task SeedDevice(int count, string prefix = "user")
        {
            var deviceHash = TrialAbusePreventionService.ComputeSha256Hash("TestAgent|1920x1080|UTC|en-US");
            for (int i = 0; i < count; i++)
                _context.DeviceFingerprints.Add(new DeviceFingerprint
                {
                    UserId = $"{prefix}{i}", DeviceHash = deviceHash, UserAgent = "TestAgent",
                    ScreenResolution = "1920x1080", Timezone = "UTC", BrowserLanguage = "en-US"
                });
            await _context.SaveChangesAsync();
        }

        public void Dispose()
        {
            _context.Dispose();
        }

        // TRIAL-01
        [Fact]
        public async Task EmailTrialHistory_Pass_NewEmailAllowed()
        {
            // Arrange
            var email = "new@example.com";

            // Act
            var result = await _service.CheckEmailTrialHistory(email);

            // Assert
            Assert.Equal(GateDecision.Pass, result.Decision);
            Assert.Contains("0 prior trial", result.Reason);
        }

        // TRIAL-02
        [Fact]
        public async Task EmailTrialHistory_Challenge_SameEmailAfterOneTrialFlagged()
        {
            // Arrange
            var email = "existing@example.com";
            _context.TrialAbuseLedgers.Add(new TrialAbuseLedger
            {
                UserId = "user1",
                Email = email,
                Ip = "192.168.1.1",
                SubscriptionStatus = "completed",
                SignupDate = DateTime.UtcNow.AddDays(-30),
                TrialStartedAt = DateTime.UtcNow.AddDays(-30),
                CreatedAt = DateTime.UtcNow.AddDays(-30)
            });
            await _context.SaveChangesAsync();

            // Act
            var result = await _service.CheckEmailTrialHistory(email);

            // Assert
            Assert.Equal(GateDecision.Challenge, result.Decision);
            Assert.Contains("1 prior trial", result.Reason);
        }

        // TRIAL-03
        [Fact]
        public async Task EmailTrialHistory_Fail_SameEmailAfterTwoTrialsRejected()
        {
            // Arrange
            var email = "abuser@example.com";
            _context.TrialAbuseLedgers.AddRange(
                new TrialAbuseLedger 
                { 
                    UserId = "user1", 
                    Email = email, 
                    Ip = "192.168.1.1", 
                    SubscriptionStatus = "completed", 
                    SignupDate = DateTime.UtcNow.AddDays(-60), 
                    TrialStartedAt = DateTime.UtcNow.AddDays(-60),
                    CreatedAt = DateTime.UtcNow.AddDays(-60)
                },
                new TrialAbuseLedger 
                { 
                    UserId = "user2", 
                    Email = email, 
                    Ip = "192.168.1.2", 
                    SubscriptionStatus = "chargebacked", 
                    SignupDate = DateTime.UtcNow.AddDays(-30), 
                    TrialStartedAt = DateTime.UtcNow.AddDays(-30),
                    CreatedAt = DateTime.UtcNow.AddDays(-30)
                }
            );
            await _context.SaveChangesAsync();

            // Act
            var result = await _service.CheckEmailTrialHistory(email);

            // Assert
            Assert.Equal(GateDecision.Fail, result.Decision);
            Assert.Contains("2 prior trial", result.Reason);
        }

        // TRIAL-04
        [Fact]
        public async Task PaymentMethodHistory_Pass_NewCardAllowed()
        {
            // Arrange
            var paymentId = "pm_new_123";

            // Act
            var result = await _service.CheckPaymentMethodHistory(paymentId);

            // Assert
            Assert.Equal(GateDecision.Pass, result.Decision);
            Assert.Contains("0 prior trial", result.Reason);
        }

        // TRIAL-05
        [Fact]
        public async Task PaymentMethodHistory_Fail_SameCardAfterThreeTrialsRejected()
        {
            // Arrange
            var paymentId = "pm_abused_123";
            _context.TrialAbuseLedgers.AddRange(
                new TrialAbuseLedger 
                { 
                    UserId = "user1", 
                    Email = "user1@example.com", 
                    Ip = "192.168.1.1", 
                    StripePaymentMethodId = paymentId, 
                    SubscriptionStatus = "completed", 
                    SignupDate = DateTime.UtcNow.AddDays(-60), 
                    TrialStartedAt = DateTime.UtcNow.AddDays(-60),
                    CreatedAt = DateTime.UtcNow.AddDays(-60)
                },
                new TrialAbuseLedger 
                { 
                    UserId = "user2", 
                    Email = "user2@example.com", 
                    Ip = "192.168.1.2", 
                    StripePaymentMethodId = paymentId, 
                    SubscriptionStatus = "completed", 
                    SignupDate = DateTime.UtcNow.AddDays(-45), 
                    TrialStartedAt = DateTime.UtcNow.AddDays(-45),
                    CreatedAt = DateTime.UtcNow.AddDays(-45)
                },
                new TrialAbuseLedger 
                { 
                    UserId = "user3", 
                    Email = "user3@example.com", 
                    Ip = "192.168.1.3", 
                    StripePaymentMethodId = paymentId, 
                    SubscriptionStatus = "chargebacked", 
                    SignupDate = DateTime.UtcNow.AddDays(-30), 
                    TrialStartedAt = DateTime.UtcNow.AddDays(-30),
                    CreatedAt = DateTime.UtcNow.AddDays(-30)
                }
            );
            await _context.SaveChangesAsync();

            // Act
            var result = await _service.CheckPaymentMethodHistory(paymentId);

            // Assert
            Assert.Equal(GateDecision.Fail, result.Decision);
            Assert.Contains("3 prior trial", result.Reason);
        }

        // TRIAL-06
        [Fact]
        public async Task IpSignupRateLimit_Pass_LessThanFiveSignupsFromIpAllowed()
        {
            // Arrange
            var ip = "192.168.1.1";
            for (int i = 0; i < 4; i++)
            {
                _context.Signups.Add(new Signup { Ip = ip, CreatedAt = DateTime.UtcNow.AddHours(-12) });
            }
            await _context.SaveChangesAsync();

            // Act
            var result = await _service.CheckIpSignupRateLimit(ip);

            // Assert
            Assert.Equal(GateDecision.Pass, result.Decision);
            Assert.Contains("4 signup", result.Reason);
            Assert.Null(result.RetryAfterSeconds);
        }

        // TRIAL-07
        [Fact]
        public async Task IpSignupRateLimit_Fail_TenOrMoreSignupsFromIpRejected429()
        {
            // Arrange
            var ip = "10.0.0.1";
            for (int i = 0; i < 10; i++)
            {
                _context.Signups.Add(new Signup { Ip = ip, CreatedAt = DateTime.UtcNow.AddHours(-12) });
            }
            await _context.SaveChangesAsync();

            // Act
            var result = await _service.CheckIpSignupRateLimit(ip);

            // Assert
            Assert.Equal(GateDecision.Fail, result.Decision);
            Assert.Contains("10 signup", result.Reason);
            Assert.Equal(86400, result.RetryAfterSeconds);
        }

        // TRIAL-08
        [Fact]
        public async Task DeviceFingerprint_Pass_DeviceLessThanTwoUsersAllowed()
        {
            // Arrange
            var userAgent = "TestAgent";
            var screenResolution = "1920x1080";
            var timezone = "UTC";
            var browserLanguage = "en-US";

            // Act
            var result = await _service.CheckDeviceFingerprint(userAgent, screenResolution, timezone, browserLanguage);

            // Assert
            Assert.Equal(GateDecision.Pass, result.Decision);
            Assert.Contains("0 user", result.Reason);

            // one other user is still < 2: PASS, and the new user's device row is written after the decision
            // (added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
            await SeedDevice(1);
            var withUser = await _service.CheckDeviceFingerprint(userAgent, screenResolution, timezone, browserLanguage, "new_user");
            Assert.Equal(GateDecision.Pass, withUser.Decision);
            Assert.Equal(1, await _context.DeviceFingerprints.CountAsync(d => d.UserId == "new_user"));
        }

        // TRIAL-09
        [Fact]
        public async Task DeviceFingerprint_Fail_DeviceMoreThanFiveUsersRejected()
        {
            // Arrange
            var userAgent = "TestAgent";
            var screenResolution = "1920x1080";
            var timezone = "UTC";
            var browserLanguage = "en-US";
            var device = $"{userAgent}|{screenResolution}|{timezone}|{browserLanguage}";
            var deviceHash = TrialAbusePreventionService.ComputeSha256Hash(device);

            for (int i = 0; i < 6; i++)
            {
                _context.DeviceFingerprints.Add(new DeviceFingerprint
                {
                    UserId = $"user{i}",
                    DeviceHash = deviceHash,
                    UserAgent = userAgent,
                    ScreenResolution = screenResolution,
                    Timezone = timezone,
                    BrowserLanguage = browserLanguage
                });
            }
            await _context.SaveChangesAsync();

            // Act
            var result = await _service.CheckDeviceFingerprint(userAgent, screenResolution, timezone, browserLanguage);

            // Assert
            Assert.Equal(GateDecision.Fail, result.Decision);
            Assert.Contains("6 user", result.Reason);

            // a user who already has the device is still refused at 5+ OTHER users (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
            var known = await _service.CheckDeviceFingerprint(userAgent, screenResolution, timezone, browserLanguage, "user0");
            Assert.Equal(GateDecision.Fail, known.Decision);
            Assert.Contains("5 user", known.Reason);
        }

        /// <summary>
        /// TRIAL-14: 4 other users -> CHALLENGE (and the row is written); exactly 5 other users -> FAIL, even for a user
        /// who already has the device, and a FAIL writes no device row. Added 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP (spec amendment). Touches: in-memory EF.
        /// </summary>
        // TRIAL-14
        [Fact]
        public async Task DeviceFingerprint_Boundaries_FourChallengeFiveFail()
        {
            await SeedDevice(4);
            var four = await _service.CheckDeviceFingerprint("TestAgent", "1920x1080", "UTC", "en-US", "newcomer");
            Assert.Equal(GateDecision.Challenge, four.Decision);
            Assert.Equal(1, await _context.DeviceFingerprints.CountAsync(d => d.UserId == "newcomer"));

            // newcomer now has the device and sees 4 others: known device -> PASS, no duplicate row
            var again = await _service.CheckDeviceFingerprint("TestAgent", "1920x1080", "UTC", "en-US", "newcomer");
            Assert.Equal(GateDecision.Pass, again.Decision);
            Assert.Equal(1, await _context.DeviceFingerprints.CountAsync(d => d.UserId == "newcomer"));

            // a sixth user sees exactly 5 others: FAIL and no row
            var fifth = await _service.CheckDeviceFingerprint("TestAgent", "1920x1080", "UTC", "en-US", "sixth");
            Assert.Equal(GateDecision.Fail, fifth.Decision);
            Assert.Equal(0, await _context.DeviceFingerprints.CountAsync(d => d.UserId == "sixth"));

            // exactly 5 others for a user who already has the device: still FAIL
            await SeedDevice(1, "extra");
            var knownAtFive = await _service.CheckDeviceFingerprint("TestAgent", "1920x1080", "UTC", "en-US", "newcomer");
            Assert.Equal(GateDecision.Fail, knownAtFive.Decision);
        }

        /// <summary>
        /// TRIAL-10: a first payment 4 days after the trial ended passes, and so does one during the trial.
        /// Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec amendment): the old test passed a user 5 days into
        /// the trial with a payment already on the ledger, under the old rules.
        /// </summary>
        // TRIAL-10
        [Fact]
        public async Task TrialPaymentTiming_Pass_PaymentWithinTrialWindowAllowed()
        {
            var late = await UserWithTrialEndedDaysAgo("user_four_days", 4);
            var result = await _service.CheckTrialPaymentTiming(late);
            Assert.Equal(GateDecision.Pass, result.Decision);
            Assert.Contains("days_after_trial=4", result.Reason);

            var during = await UserWithTrialEndedDaysAgo("user_in_trial", -9);
            var inTrial = await _service.CheckTrialPaymentTiming(during);
            Assert.Equal(GateDecision.Pass, inTrial.Decision);
            Assert.Contains("days_after_trial=-9", inTrial.Reason);

            // floor, not truncation: half a day before the trial ends is day -1, not 0
            var halfDay = await UserWithTrialEndedDaysAgo("user_half_day", -0.5);
            Assert.Contains("days_after_trial=-1", (await _service.CheckTrialPaymentTiming(halfDay)).Reason);
        }

        /// <summary>
        /// TRIAL-11: a first payment 90 days after the trial ended, with no earlier payment, is refused.
        /// Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec amendment; exact boundary via the clock).
        /// </summary>
        // TRIAL-11
        [Fact]
        public async Task TrialPaymentTiming_Fail_TrialEndedNoPaymentTryingToRejectAfter90Days()
        {
            var userId = await UserWithTrialEndedDaysAgo("user_timing_fail", 90);

            var result = await _service.CheckTrialPaymentTiming(userId);

            Assert.Equal(GateDecision.Fail, result.Decision);
            Assert.Contains("days_after_trial=90", result.Reason);
            Assert.Contains("earlier_payment=false", result.Reason);
        }

        /// <summary>
        /// TRIAL-15: 5 and 89 days after the trial are CHALLENGE; 90 days with an earlier payment is CHALLENGE; and the
        /// trial length is configuration (a 30-day trial moves every boundary). Added 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP (spec amendment). Touches: in-memory EF.
        /// </summary>
        // TRIAL-15
        [Fact]
        public async Task TrialPaymentTiming_Boundaries_Challenge()
        {
            Assert.Equal(GateDecision.Challenge, (await _service.CheckTrialPaymentTiming(await UserWithTrialEndedDaysAgo("d5", 5))).Decision);
            Assert.Equal(GateDecision.Challenge, (await _service.CheckTrialPaymentTiming(await UserWithTrialEndedDaysAgo("d89", 89))).Decision);
            var paidBefore = await UserWithTrialEndedDaysAgo("d90paid", 90, _now.AddDays(-100));
            var result = await _service.CheckTrialPaymentTiming(paidBefore);
            Assert.Equal(GateDecision.Challenge, result.Decision);
            Assert.Contains("earlier_payment=true", result.Reason);

            var thirtyDayTrials = new TrialAbusePreventionService(_context, _logger, () => _now, trialDays: 30);
            _context.Users.Add(new User { Id = "t30", CreatedAt = _now.AddDays(-34) });
            await _context.SaveChangesAsync();
            Assert.Equal(GateDecision.Pass, (await thirtyDayTrials.CheckTrialPaymentTiming("t30")).Decision);
        }

        // TRIAL-12
        [Fact]
        public async Task ChargebackHistory_Pass_NoChargebacksAllowed()
        {
            // Arrange
            var userId = "user_cb_pass";
            var stripeCustomerId = "cus_pass_123";

            // Act
            var result = await _service.CheckChargebackHistory(stripeCustomerId, userId);

            // Assert
            Assert.Equal(GateDecision.Pass, result.Decision);
            Assert.Contains("0 chargeback", result.Reason);
        }

        // TRIAL-13
        [Fact]
        public async Task ChargebackHistory_Fail_TwoOrMoreChargebacksRequiresPrepayment()
        {
            // Arrange
            var userId = "user_cb_fail";
            var stripeCustomerId = "cus_fail_123";
            _context.StripeEvents.AddRange(
                new StripeEvent { Customer = stripeCustomerId, Type = "chargeback.created", CreatedAt = DateTime.UtcNow.AddDays(-60) },
                new StripeEvent { Customer = stripeCustomerId, Type = "chargeback.created", CreatedAt = DateTime.UtcNow.AddDays(-30) }
            );
            await _context.SaveChangesAsync();

            // Act
            var result = await _service.CheckChargebackHistory(stripeCustomerId, userId);

            // Assert
            Assert.Equal(GateDecision.Fail, result.Decision);
            Assert.Contains("2 chargeback", result.Reason);
        }

        [Fact]
        public async Task LogAbuseEntry_CreatesEntryInLedger()
        {
            // Arrange
            var entry = new TrialAbuseLedger
            {
                UserId = "user_log",
                Email = "log@example.com",
                Ip = "1.2.3.4",
                SignupDate = DateTime.UtcNow,
                TrialStartedAt = DateTime.UtcNow,
                SubscriptionStatus = "completed"
            };

            // Act
            await _service.LogAbuseEntry(entry);
            var ledgerEntry = await _context.TrialAbuseLedgers.FirstOrDefaultAsync(l => l.UserId == "user_log");

            // Assert
            Assert.NotNull(ledgerEntry);
            Assert.Equal("log@example.com", ledgerEntry.Email);
        }

        [Fact]
        public async Task LogGateDecision_CreatesEntryInGateDecisions()
        {
            // Arrange
            var log = new GateDecisionLog
            {
                UserId = "user_gate",
                GateName = "email_trial_history",
                Decision = "Pass",
                RuleInputs = "{\"email\":\"test@example.com\"}",
                RuleOutputs = "{\"prior_count\":0}"
            };

            // Act
            await _service.LogGateDecision(log);
            var gateLog = await _context.GateDecisionLogs.FirstOrDefaultAsync(l => l.UserId == "user_gate");

            // Assert
            Assert.NotNull(gateLog);
            Assert.Equal("email_trial_history", gateLog.GateName);
            Assert.Equal("Pass", gateLog.Decision);
        }
    }
}

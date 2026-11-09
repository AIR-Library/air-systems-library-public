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
        private TrialAbusePreventionDbContext _context;
        private TrialAbusePreventionService _service;
        private readonly ILogger<TrialAbusePreventionService> _logger = Mock.Of<ILogger<TrialAbusePreventionService>>();

        public TrialAbusePreventionTests()
        {
            _options = new DbContextOptionsBuilder<TrialAbusePreventionDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            _context = new TrialAbusePreventionDbContext(_options);
            _context.Database.EnsureCreated();
            _service = new TrialAbusePreventionService(_context, _logger);
        }

        public void Dispose()
        {
            _context.Dispose();
        }

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
        }

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
        }

        [Fact]
        public async Task TrialPaymentTiming_Pass_PaymentWithinTrialWindowAllowed()
        {
            // Arrange
            var userId = "user_timing_pass";
            var user = new User { Id = userId, CreatedAt = DateTime.UtcNow.AddDays(-5) };
            _context.Users.Add(user);
            _context.TrialAbuseLedgers.Add(new TrialAbuseLedger
            {
                UserId = userId,
                Email = "test@example.com",
                Ip = "1.2.3.4",
                SignupDate = DateTime.UtcNow.AddDays(-5),
                TrialStartedAt = DateTime.UtcNow.AddDays(-5),
                PaymentAddedDate = DateTime.UtcNow.AddDays(-3),
                SubscriptionStatus = "completed"
            });
            await _context.SaveChangesAsync();

            // Act
            var result = await _service.CheckTrialPaymentTiming(userId);

            // Assert
            Assert.Equal(GateDecision.Pass, result.Decision);
            Assert.Contains("5 days ago", result.Reason);
        }

        [Fact]
        public async Task TrialPaymentTiming_Fail_TrialEndedNoPaymentTryingToRejectAfter90Days()
        {
            // Arrange
            var userId = "user_timing_fail";
            var user = new User { Id = userId, CreatedAt = DateTime.UtcNow.AddDays(-120) };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            // Act
            var result = await _service.CheckTrialPaymentTiming(userId);

            // Assert
            Assert.Equal(GateDecision.Fail, result.Decision);
            Assert.Contains("120 days ago", result.Reason);
            Assert.Contains("never", result.Reason);
        }

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

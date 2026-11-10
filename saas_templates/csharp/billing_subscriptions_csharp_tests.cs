// Tests for the billing template. Changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): they built
// Stripe.net objects (Stripe.Subscription with long timestamps, Stripe.Invoice.AmountRefunded) that do not exist in
// Stripe.net 44 and could not compile, and "simulated a valid signature" by blanking STRIPE_WEBHOOK_SECRET, i.e. by
// switching verification off. They now fake IStripeService with local types and sign every webhook payload with a
// test secret exactly as Stripe does, so signature verification is exercised, not bypassed. Same ten tests, same
// assertions. Touches: in-memory databases only; no network.
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using BillingSubscriptions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace BillingSubscriptionsTests
{
    public class BillingServiceTests
    {
        private BillingContext GetInMemoryContext()
        {
            var options = new DbContextOptionsBuilder<BillingContext>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options;
            var context = new BillingContext(options);
            context.Database.EnsureCreated();
            return context;
        }

        private ILogger<BillingService> GetLogger()
        {
            var mock = new Mock<ILogger<BillingService>>();
            return mock.Object;
        }

        // Helper to create a mock StripeService
        private Mock<IStripeService> GetMockStripeService()
        {
            return new Mock<IStripeService>();
        }

        /// <summary>The webhook signing secret every test service uses (a test value, not a real secret).</summary>
        private const string WebhookSecret = "whsec_test_secret";

        /// <summary>Builds the service under test with the test webhook secret. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private BillingService NewService(BillingContext ctx, IStripeService stripe, ILogger<BillingService> logger) =>
            new BillingService(ctx, stripe, logger, WebhookSecret);

        /// <summary>
        /// Signs a payload the way Stripe does: "t=&lt;unix&gt;,v1=hex(HMAC-SHA256(secret, t + "." + payload))".
        /// 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Pure (reads the clock).
        /// </summary>
        private static string Sign(string payload, string secret = WebhookSecret)
        {
            var t = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
            var sig = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes($"{t}.{payload}"))).ToLowerInvariant();
            return $"t={t},v1={sig}";
        }

        /// <summary>A Stripe event body ({id, type, data: {object}}) in Stripe's JSON field names. Pure.</summary>
        private static string EventJson(string id, string type, object dataObject) =>
            JsonSerializer.Serialize(new { id, type, data = new { @object = dataObject } });

        /// <summary>An invoice.payment_succeeded data object. Pure.</summary>
        private static object PaidInvoice(string id, string customer, long amountPaid) => new
        {
            id,
            customer,
            amount_paid = amountPaid,
            status_transitions = new { paid_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
        };

        // BILL-01
        [Fact]
        public async Task CreateSubscription_HappyPath()
        {
            var ctx = GetInMemoryContext();
            var logger = GetLogger();
            var stripeMock = GetMockStripeService();

            var stripeSub = new StripeSubscriptionInfo
            {
                Id = "sub_123",
                CurrentPeriodEnd = DateTime.UtcNow.AddMonths(1)
            };
            stripeMock.Setup(s => s.CreateSubscriptionAsync("cust_1", It.IsAny<string>()))
                .ReturnsAsync(stripeSub);

            var service = NewService(ctx, stripeMock.Object, logger);
            var response = await service.CreateSubscriptionAsync("cust_1", "solo");

            Assert.True(response.Success);
            var data = Assert.IsType<CreateSubscriptionResult>(response.Data);
            Assert.Equal("sub_123", data.SubscriptionId);
            Assert.Equal("solo", data.Tier);
            Assert.Equal("active", data.Status);
            Assert.NotNull(data.NextBillingDate);

            var dbSub = await ctx.Subscriptions.FirstOrDefaultAsync(s => s.StripeSubscriptionId == "sub_123");
            Assert.NotNull(dbSub);
            Assert.Equal("solo", dbSub.Tier);
        }

        // BILL-02
        [Fact]
        public async Task CreateSubscription_InvalidTier()
        {
            var ctx = GetInMemoryContext();
            var logger = GetLogger();
            var stripeMock = GetMockStripeService();

            var service = NewService(ctx, stripeMock.Object, logger);
            var response = await service.CreateSubscriptionAsync("cust_1", "invalid_tier");

            Assert.False(response.Success);
            Assert.Equal("invalid_tier", response.Error.Code);
            Assert.Equal(400, response.Status);
        }

        // BILL-03
        [Fact]
        public async Task ChangePlan_HappyPath()
        {
            var ctx = GetInMemoryContext();
            var logger = GetLogger();
            var stripeMock = GetMockStripeService();

            // Seed subscription
            var sub = new Subscription
            {
                StripeSubscriptionId = "sub_123",
                CustomerId = "cust_1",
                Tier = "solo",
                Status = "active",
                CreatedAt = DateTime.UtcNow
            };
            ctx.Subscriptions.Add(sub);
            await ctx.SaveChangesAsync();

            var stripeSub = new StripeSubscriptionInfo
            {
                Id = "sub_123",
                CurrentPeriodStart = DateTime.UtcNow,
                ProrationCredit = 0
            };
            // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (BILL-03 amendment): the service retrieves the
            // subscription, then updates its one existing item (id si_1) with the new price and create_prorations.
            stripeMock.Setup(s => s.RetrieveSubscriptionAsync("sub_123"))
                .ReturnsAsync(new StripeSubscriptionInfo { Id = "sub_123", ItemIds = new List<string> { "si_1" } });
            stripeMock.Setup(s => s.UpdateSubscriptionAsync("sub_123", "si_1", It.IsAny<string>(), "create_prorations"))
                .ReturnsAsync(stripeSub);

            var service = NewService(ctx, stripeMock.Object, logger);
            var response = await service.ChangePlanAsync("sub_123", "team");

            Assert.True(response.Success);
            stripeMock.Verify(s => s.UpdateSubscriptionAsync("sub_123", "si_1", "price_1UI_team", "create_prorations"), Times.Once);
            var data = Assert.IsType<ChangePlanResult>(response.Data);
            Assert.Equal("sub_123", data.SubscriptionId);
            Assert.Equal("solo", data.OldTier);
            Assert.Equal("team", data.NewTier);
            Assert.NotNull(data.EffectiveDate);
            Assert.Equal(0, data.ProrationCredit);

            var dbSub = await ctx.Subscriptions.FirstAsync(s => s.StripeSubscriptionId == "sub_123");
            Assert.Equal("team", dbSub.Tier);
            Assert.Contains(await ctx.AuditLogs.ToListAsync(), a => a.Action == "plan_changed");
        }

        /// <summary>
        /// BILL-03 refusals: an unknown tier is 400 invalid_tier, and a subscription with no item or with two items is
        /// 409 subscription_item_ambiguous; in every case Stripe is never asked to update and the row keeps its tier.
        /// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec amendment). Touches: in-memory database, mocked Stripe.
        /// </summary>
        // BILL-03
        [Fact]
        public async Task ChangePlan_UnknownTierOrNotExactlyOneItem_RefusedBeforeUpdate()
        {
            var ctx = GetInMemoryContext();
            ctx.Subscriptions.Add(new Subscription { StripeSubscriptionId = "sub_9", CustomerId = "cust_1", Tier = "solo", Status = "active", CreatedAt = DateTime.UtcNow });
            await ctx.SaveChangesAsync();
            var stripeMock = GetMockStripeService();
            var service = NewService(ctx, stripeMock.Object, GetLogger());

            var badTier = await service.ChangePlanAsync("sub_9", "platinum");
            Assert.Equal("invalid_tier", badTier.Error.Code);
            Assert.Equal(400, badTier.Status);
            stripeMock.Verify(s => s.RetrieveSubscriptionAsync(It.IsAny<string>()), Times.Never);

            foreach (var items in new[] { new List<string>(), new List<string> { "si_a", "si_b" } })
            {
                stripeMock.Setup(s => s.RetrieveSubscriptionAsync("sub_9"))
                    .ReturnsAsync(new StripeSubscriptionInfo { Id = "sub_9", ItemIds = items });
                var ambiguous = await service.ChangePlanAsync("sub_9", "team");
                Assert.False(ambiguous.Success);
                Assert.Equal("subscription_item_ambiguous", ambiguous.Error.Code);
                Assert.Equal(409, ambiguous.Status);
            }

            stripeMock.Verify(s => s.UpdateSubscriptionAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
            Assert.Equal("solo", (await ctx.Subscriptions.FirstAsync(s => s.StripeSubscriptionId == "sub_9")).Tier);
        }

        // BILL-04
        [Fact]
        public async Task QueueRefund_HappyPath()
        {
            var ctx = GetInMemoryContext();
            var logger = GetLogger();
            var stripeMock = GetMockStripeService();

            var stripeInvoice = new StripeInvoiceInfo
            {
                Id = "in_123",
                AmountPaid = 5000,
                Status = "paid"
            };
            stripeMock.Setup(s => s.RetrieveInvoiceAsync("in_123"))
                .ReturnsAsync(stripeInvoice);

            var service = NewService(ctx, stripeMock.Object, logger);
            var response = await service.QueueRefundAsync("in_123", 3000, "Customer request", "admin_user");

            Assert.True(response.Success);
            var data = Assert.IsType<QueueRefundResult>(response.Data);
            Assert.Equal("queued", data.Status);
            Assert.Equal(3000, data.Amount);
            Assert.Equal("Customer request", data.Reason);
            Assert.True(data.RefundId > 0);

            var dbRefund = await ctx.Refunds.FirstAsync(r => r.Id == data.RefundId);
            Assert.Equal("queued", dbRefund.Status);
            Assert.Equal(3000, dbRefund.Amount);
        }

        // BILL-05
        [Fact]
        public async Task QueueRefund_AmountExceedsInvoice()
        {
            var ctx = GetInMemoryContext();
            var logger = GetLogger();
            var stripeMock = GetMockStripeService();

            var stripeInvoice = new StripeInvoiceInfo
            {
                Id = "in_123",
                AmountPaid = 2000,
                Status = "paid"
            };
            stripeMock.Setup(s => s.RetrieveInvoiceAsync("in_123"))
                .ReturnsAsync(stripeInvoice);

            var service = NewService(ctx, stripeMock.Object, logger);
            var response = await service.QueueRefundAsync("in_123", 3000, "Too much", "admin_user");

            Assert.False(response.Success);
            Assert.Equal("refund_exceeds_invoice", response.Error.Code);
        }

        // BILL-06
        [Fact]
        public async Task HandleWebhook_PaymentSucceeded()
        {
            var ctx = GetInMemoryContext();
            var logger = GetLogger();
            var stripeMock = GetMockStripeService();

            var service = NewService(ctx, stripeMock.Object, logger);

            var json = EventJson("evt_1", "invoice.payment_succeeded", PaidInvoice("in_123", "cust_1", 5000));

            var response = await service.HandleStripeWebhookAsync(json, Sign(json));
            Assert.True(response.Success);
            var webhookResp = Assert.IsType<WebhookResponse>(response.Data);
            Assert.True(webhookResp.Received);

            var dbInvoice = await ctx.Invoices.FirstAsync(i => i.StripeInvoiceId == "in_123");
            Assert.Equal("succeeded", dbInvoice.Status);
            Assert.Equal(5000, dbInvoice.Amount);
            // BILL-06 says "audit logged" (assert added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
            Assert.Contains(await ctx.AuditLogs.ToListAsync(), a => a.Action == "payment_succeeded");
        }

        // BILL-07
        [Fact]
        public async Task HandleWebhook_DuplicateEvent_Idempotent()
        {
            var ctx = GetInMemoryContext();
            var logger = GetLogger();
            var stripeMock = GetMockStripeService();

            var service = NewService(ctx, stripeMock.Object, logger);

            var json = EventJson("evt_dup", "invoice.payment_succeeded", PaidInvoice("in_123", "cust_1", 5000));

            // First call
            var first = await service.HandleStripeWebhookAsync(json, Sign(json));
            Assert.True(first.Success);

            // Second call (duplicate)
            var second = await service.HandleStripeWebhookAsync(json, Sign(json));
            Assert.True(second.Success);
            var webhookResp = Assert.IsType<WebhookResponse>(second.Data);
            Assert.True(webhookResp.Received);

            // Ensure only one invoice record
            var invoices = await ctx.Invoices.ToListAsync();
            Assert.Single(invoices);
        }

        // BILL-08
        [Fact]
        public async Task HandleWebhook_SubscriptionUpdated()
        {
            var ctx = GetInMemoryContext();
            var logger = GetLogger();
            var stripeMock = GetMockStripeService();

            // Seed existing subscription
            ctx.Subscriptions.Add(new Subscription
            {
                StripeSubscriptionId = "sub_123",
                CustomerId = "cust_1",
                Tier = "solo",
                Status = "past_due", // was "active", so the test could not see the status change BILL-08 names (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
                CreatedAt = DateTime.UtcNow
            });
            await ctx.SaveChangesAsync();

            var service = NewService(ctx, stripeMock.Object, logger);

            var json = EventJson("evt_upd", "customer.subscription.updated", new
            {
                id = "sub_123",
                customer = "cust_1",
                status = "active",
                items = new { data = new[] { new { price = new { lookup_key = "team" } } } }
            });

            var response = await service.HandleStripeWebhookAsync(json, Sign(json));
            Assert.True(response.Success);

            var sub = await ctx.Subscriptions.FirstAsync(s => s.StripeSubscriptionId == "sub_123");
            Assert.Equal("team", sub.Tier);
            Assert.Equal("active", sub.Status);
        }

        /// <summary>
        /// BILL-09: a webhook with a bad Stripe-Signature is refused with 400 invalid_signature. In: nothing. Out:
        /// asserts. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.3 ruling: 400, Stripe's documented
        /// answer and the same as stripe_webhook_entitlements; this asserted 403). Touches: the in-memory database.
        /// </summary>
        // BILL-09
        [Fact]
        public async Task HandleWebhook_InvalidSignature()
        {
            var ctx = GetInMemoryContext();
            var logger = GetLogger();
            var stripeMock = GetMockStripeService();

            var service = NewService(ctx, stripeMock.Object, logger);

            var response = await service.HandleStripeWebhookAsync("{}", "invalid_signature");
            Assert.False(response.Success);
            Assert.Equal("invalid_signature", response.Error.Code);
            Assert.Equal(400, response.Status); // Phase B.3 (2026-11-10): was 403
        }

        // BILL-10
        [Fact]
        public async Task Webhook_ResponseTime_UnderThreeSeconds()
        {
            var ctx = GetInMemoryContext();
            var logger = GetLogger();
            var stripeMock = GetMockStripeService();

            var service = NewService(ctx, stripeMock.Object, logger);

            var json = EventJson("evt_time", "invoice.payment_succeeded", PaidInvoice("in_123", "cust_1", 1000));

            var start = DateTime.UtcNow;
            var response = await service.HandleStripeWebhookAsync(json, Sign(json));
            var elapsed = DateTime.UtcNow - start;

            Assert.True(response.Success);
            Assert.True(Assert.IsType<WebhookResponse>(response.Data).Received);
            Assert.True(elapsed.TotalSeconds < 3, $"Elapsed {elapsed.TotalSeconds}s exceeds 3 seconds");
        }
    
        /// <summary>
        /// A well-formed Stripe-Signature made with another secret, and a genuine one replayed after the 5-minute
        /// tolerance, are both refused, and nothing is recorded. Added 2026-11-10 (session
        /// session_012zDydZCZ4AChqhEZ4oVtaP) with the constant-time verifier.
        /// </summary>
        [Fact]
        public async Task HandleWebhook_WrongSecretOrStaleTimestamp_Rejected()
        {
            var ctx = GetInMemoryContext();
            var json = EventJson("evt_forged", "invoice.payment_succeeded", PaidInvoice("in_9", "cust_1", 5000));
            var service = NewService(ctx, GetMockStripeService().Object, GetLogger());

            var forged = await service.HandleStripeWebhookAsync(json, Sign(json, "whsec_someone_else"));
            Assert.Equal("invalid_signature", forged.Error.Code);
            Assert.Equal(400, forged.Status); // BILL-09, Phase B.3 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)

            var later = new BillingService(ctx, GetMockStripeService().Object, GetLogger(), WebhookSecret,
                () => DateTimeOffset.UtcNow.AddMinutes(10));
            var stale = await later.HandleStripeWebhookAsync(json, Sign(json));
            Assert.Equal("invalid_signature", stale.Error.Code);
            Assert.Equal(400, stale.Status); // BILL-09, Phase B.3 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)

            Assert.Empty(await ctx.Events.ToListAsync());
            Assert.Empty(await ctx.Invoices.ToListAsync());
        }

        /// <summary>
        /// Two refunds that each fit the invoice but together exceed it: the second is refused. Added 2026-11-10
        /// (session session_012zDydZCZ4AChqhEZ4oVtaP) with the cumulative check.
        /// </summary>
        [Fact]
        public async Task QueueRefund_CumulativeRefundsCannotExceedInvoice()
        {
            var ctx = GetInMemoryContext();
            var stripeMock = GetMockStripeService();
            stripeMock.Setup(s => s.RetrieveInvoiceAsync("in_123"))
                .ReturnsAsync(new StripeInvoiceInfo { Id = "in_123", AmountPaid = 5000, Status = "paid" });
            var service = NewService(ctx, stripeMock.Object, GetLogger());

            Assert.True((await service.QueueRefundAsync("in_123", 3000, "first", "admin_user")).Success);
            var second = await service.QueueRefundAsync("in_123", 3000, "second", "admin_user");
            Assert.False(second.Success);
            Assert.Equal("refund_exceeds_invoice", second.Error.Code);
        }
}
}
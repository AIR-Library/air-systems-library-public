// Billing & subscriptions template (GEMINI_DISPATCH_MASTER_SPEC template #4): create_subscription, change_plan,
// queue_refund and handle_stripe_webhook over EF Core, with Stripe behind IStripeService.
// Repaired 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): the suite had 17 compile errors because the
// Stripe.net types (Stripe.Subscription, Stripe.Invoice) were returned where the local entities were expected, and
// webhook verification could only be "tested" by blanking the secret. Stripe now sits behind an interface that speaks
// local types (StripeSubscriptionInfo, StripeInvoiceInfo); StripeService is the only Stripe.net adapter; webhooks are
// verified with Stripe's v1 HMAC-SHA256 scheme in constant time and an empty secret is refused.
// Touches: the billing database, Stripe's API (network, money) through StripeService only.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace BillingSubscriptions
{
    // ---------- Database Models ----------
    public class Subscription
    {
        public int Id { get; set; }
        public string StripeSubscriptionId { get; set; }
        public string CustomerId { get; set; }
        public string Tier { get; set; }
        public string Status { get; set; } // active, suspended, cancelled, past_due
        public DateTime CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
        public DateTime? CancelledAt { get; set; }
    }

    public class Invoice
    {
        public int Id { get; set; }
        public string StripeInvoiceId { get; set; }
        public string CustomerId { get; set; }
        public long Amount { get; set; } // amount in cents
        public string Status { get; set; } // succeeded, failed, pending
        public DateTime? PaidAt { get; set; }
    }

    public class Refund
    {
        public int Id { get; set; }
        public string InvoiceId { get; set; }
        public long Amount { get; set; }
        public string Status { get; set; } // queued, processed
        public string Reason { get; set; }
        public string CreatedBy { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? ExecutedAt { get; set; }
    }

    public class EventRecord
    {
        public int Id { get; set; }
        public string StripeEventId { get; set; }
        public string EventType { get; set; }
        public DateTime ProcessedAt { get; set; }
    }

    public class AuditLog
    {
        public int Id { get; set; }
        public string Action { get; set; }
        public string Details { get; set; }
        public DateTime LoggedAt { get; set; }
    }

    // ---------- DbContext ----------
    public class BillingContext : DbContext
    {
        public DbSet<Subscription> Subscriptions => Set<Subscription>();
        public DbSet<Invoice> Invoices => Set<Invoice>();
        public DbSet<Refund> Refunds => Set<Refund>();
        public DbSet<EventRecord> Events => Set<EventRecord>();
        public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

        public BillingContext(DbContextOptions<BillingContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Subscription>()
                .HasIndex(s => s.StripeSubscriptionId)
                .IsUnique();

            modelBuilder.Entity<Invoice>()
                .HasIndex(i => i.StripeInvoiceId)
                .IsUnique();

            modelBuilder.Entity<EventRecord>()
                .HasIndex(e => e.StripeEventId)
                .IsUnique();

            // DDL for reference (executed via EnsureCreated if needed)
            // CREATE TABLE subscriptions (...);
            // CREATE TABLE invoices (...);
            // CREATE TABLE refunds (...);
            // CREATE TABLE events (...);
            // CREATE TABLE audit_logs (...);
        }
    }

    // ---------- Stripe Wrapper ----------
    /// <summary>
    /// What the billing service needs from Stripe about a subscription, in local types so the service and its tests do
    /// not depend on Stripe.net's model. ProrationCredit is in cents (the credit for unused time on the old plan).
    /// Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP). Pure data.
    /// </summary>
    public class StripeSubscriptionInfo
    {
        public string Id { get; set; }
        public string Status { get; set; }
        public DateTime CurrentPeriodStart { get; set; }
        public DateTime CurrentPeriodEnd { get; set; }
        public long ProrationCredit { get; set; }
    }

    /// <summary>
    /// What the billing service needs from Stripe about an invoice. AmountPaid is in cents; Status is Stripe's
    /// ("paid", "open", ...). Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP). Pure data.
    /// </summary>
    public class StripeInvoiceInfo
    {
        public string Id { get; set; }
        public string CustomerId { get; set; }
        public long AmountPaid { get; set; }
        public string Status { get; set; }
    }

    /// <summary>
    /// A payment provider refused or failed a call. Implementations of <see cref="IStripeService"/> report provider
    /// failures with this type, so billing answers "stripe_error" for those and lets any other exception (a bug)
    /// surface instead of hiding it as a provider error. In: a message and the provider's own exception. Added
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, for code scanning ("generic catch clause", PR 19). Touches nothing.
    /// </summary>
    public class PaymentProviderException : Exception
    {
        /// <summary>Creates the exception with the provider's message and, if any, its original exception.</summary>
        public PaymentProviderException(string message, Exception inner = null) : base(message, inner) { }
    }

    /// <summary>
    /// The Stripe calls billing makes. Production uses <see cref="StripeService"/>; tests use a fake, so no test touches
    /// the network. Changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP) to return local types (it returned
    /// Stripe.net types typed as the local entities, which did not compile). Touches: Stripe (network, money) in
    /// production implementations. Provider failures are thrown as <see cref="PaymentProviderException"/>.
    /// </summary>
    public interface IStripeService
    {
        Task<StripeSubscriptionInfo> CreateSubscriptionAsync(string customerId, string priceId);
        Task<StripeSubscriptionInfo> UpdateSubscriptionAsync(string subscriptionId, string newPriceId);
        Task<StripeInvoiceInfo> RetrieveInvoiceAsync(string invoiceId);
    }

    /// <summary>
    /// Stripe.net adapter for <see cref="IStripeService"/>. Reads the API key from STRIPE_SECRET_KEY (never hard-coded).
    /// Rewritten 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): maps Stripe objects to local types; a plan change
    /// now replaces the existing subscription item (passing only a price added a second item, billing both plans) and
    /// reports the proration credit from the latest invoice's proration lines. Touches: Stripe's API (network, money).
    /// </summary>
    public class StripeService : IStripeService
    {
        private readonly Stripe.StripeClient _client;

        /// <summary>Creates the adapter from STRIPE_SECRET_KEY; throws when it is not set. Touches: environment.</summary>
        public StripeService()
        {
            var secretKey = Environment.GetEnvironmentVariable("STRIPE_SECRET_KEY");
            if (string.IsNullOrWhiteSpace(secretKey))
                throw new InvalidOperationException("STRIPE_SECRET_KEY not set");
            _client = new Stripe.StripeClient(secretKey);
        }

        /// <summary>stripe.subscriptions.create with one price. Output: the new subscription. Touches: Stripe (money).</summary>
        public async Task<StripeSubscriptionInfo> CreateSubscriptionAsync(string customerId, string priceId)
        {
            var options = new Stripe.SubscriptionCreateOptions
            {
                Customer = customerId,
                Items = new List<Stripe.SubscriptionItemOptions> { new Stripe.SubscriptionItemOptions { Price = priceId } }
            };
            try
            {
                var stripeSub = await new Stripe.SubscriptionService(_client).CreateAsync(options);
                return Map(stripeSub, 0);
            }
            catch (Stripe.StripeException e)
            {
                throw new PaymentProviderException(e.Message, e);
            }
        }

        /// <summary>
        /// stripe.subscriptions.update replacing the current item's price, with prorations. Output: the updated
        /// subscription and the proration credit in cents. Touches: Stripe (money).
        /// </summary>
        public async Task<StripeSubscriptionInfo> UpdateSubscriptionAsync(string subscriptionId, string newPriceId)
        {
            var service = new Stripe.SubscriptionService(_client);
            Stripe.Subscription current;
            try
            {
                current = await service.GetAsync(subscriptionId);
            }
            catch (Stripe.StripeException e)
            {
                throw new PaymentProviderException(e.Message, e);
            }
            var itemId = current.Items?.Data?.FirstOrDefault()?.Id
                ?? throw new PaymentProviderException("Subscription has no item to change");
            var options = new Stripe.SubscriptionUpdateOptions
            {
                Items = new List<Stripe.SubscriptionItemOptions> { new Stripe.SubscriptionItemOptions { Id = itemId, Price = newPriceId } },
                ProrationBehavior = "always_invoice",
                Expand = new List<string> { "latest_invoice" }
            };
            Stripe.Subscription stripeSub;
            try
            {
                stripeSub = await service.UpdateAsync(subscriptionId, options);
            }
            catch (Stripe.StripeException e)
            {
                throw new PaymentProviderException(e.Message, e);
            }
            var credit = stripeSub.LatestInvoice?.Lines?.Data?
                .Where(l => l.Proration && l.Amount < 0)
                .Sum(l => -l.Amount) ?? 0;
            return Map(stripeSub, credit);
        }

        /// <summary>stripe.invoices.retrieve. Output: the invoice. Touches: Stripe (network).</summary>
        public async Task<StripeInvoiceInfo> RetrieveInvoiceAsync(string invoiceId)
        {
            Stripe.Invoice invoice;
            try
            {
                invoice = await new Stripe.InvoiceService(_client).GetAsync(invoiceId);
            }
            catch (Stripe.StripeException e)
            {
                throw new PaymentProviderException(e.Message, e);
            }
            return invoice == null ? null : new StripeInvoiceInfo
            {
                Id = invoice.Id,
                CustomerId = invoice.CustomerId,
                AmountPaid = invoice.AmountPaid,
                Status = invoice.Status
            };
        }

        /// <summary>Maps a Stripe.net subscription to the local type. Pure.</summary>
        private static StripeSubscriptionInfo Map(Stripe.Subscription s, long prorationCredit) => new StripeSubscriptionInfo
        {
            Id = s.Id,
            Status = s.Status,
            CurrentPeriodStart = s.CurrentPeriodStart,
            CurrentPeriodEnd = s.CurrentPeriodEnd,
            ProrationCredit = prorationCredit
        };
    }

    // ---------- Response DTOs ----------
    public class ApiResponse
    {
        public bool Success { get; set; }
        public object Data { get; set; }
        public ApiError Error { get; set; }
    }

    public class ApiError
    {
        public string Code { get; set; }
        public string Message { get; set; }
    }

    public class CreateSubscriptionResult
    {
        public string SubscriptionId { get; set; }
        public string Tier { get; set; }
        public string Status { get; set; }
        public string NextBillingDate { get; set; }
    }

    public class ChangePlanResult
    {
        public string SubscriptionId { get; set; }
        public string OldTier { get; set; }
        public string NewTier { get; set; }
        public string EffectiveDate { get; set; }
        public long ProrationCredit { get; set; }
    }

    public class QueueRefundResult
    {
        public int RefundId { get; set; }
        public string Status { get; set; }
        public long Amount { get; set; }
        public string Reason { get; set; }
    }

    public class WebhookResponse
    {
        public bool Received { get; set; } = true;
    }

    // ---------- Billing Service ----------
    /// <summary>
    /// The four billing flows. Every mutation and its audit row are saved together. Repaired 2026-11-10 (session
    /// session_012zDydZCZ4AChqhEZ4oVtaP); see the file header. Touches: the billing database (subscriptions, invoices,
    /// refunds, events, audit_logs) and Stripe through <see cref="IStripeService"/> (network, money).
    /// </summary>
    public class BillingService
    {
        /// <summary>How old a webhook signature timestamp may be (Stripe's default tolerance).</summary>
        public static readonly TimeSpan WebhookTolerance = TimeSpan.FromMinutes(5);

        private readonly BillingContext _db;
        private readonly IStripeService _stripe;
        private readonly ILogger<BillingService> _logger;
        private readonly Func<DateTimeOffset> _clock;
        private readonly Dictionary<string, string> _priceIds = new Dictionary<string, string>
        {
            { "solo", "price_1UI_solo" },
            { "team", "price_1UI_team" },
            { "enterprise", "price_1UI_enterprise" }
        };
        private readonly byte[] _webhookSecret;

        /// <summary>
        /// Creates the service. Inputs: the database, the Stripe gateway, a logger, the webhook signing secret (null
        /// reads STRIPE_WEBHOOK_SECRET) and an optional clock for the signature tolerance check. Throws when the secret
        /// is missing or empty: an empty secret used to switch signature checking off. Changed 2026-11-10 (session
        /// session_012zDydZCZ4AChqhEZ4oVtaP). Touches: environment (read).
        /// </summary>
        public BillingService(BillingContext db, IStripeService stripe, ILogger<BillingService> logger,
            string webhookSecret = null, Func<DateTimeOffset> clock = null)
        {
            _db = db ?? throw new ArgumentNullException(nameof(db));
            _stripe = stripe ?? throw new ArgumentNullException(nameof(stripe));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            var secret = webhookSecret ?? Environment.GetEnvironmentVariable("STRIPE_WEBHOOK_SECRET");
            if (string.IsNullOrEmpty(secret))
                throw new InvalidOperationException("STRIPE_WEBHOOK_SECRET not set");
            _webhookSecret = Encoding.UTF8.GetBytes(secret);
            _clock = clock ?? (() => DateTimeOffset.UtcNow);
        }

        // ---------- Helper ----------
        /// <summary>
        /// Adds an audit row to the current unit of work; the caller's SaveChangesAsync writes it together with the
        /// change it records. Changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): it used to save on its own,
        /// synchronously, so a change and its audit row could be split. Touches: audit_logs.
        /// </summary>
        private void LogAudit(string action, object details)
        {
            _db.AuditLogs.Add(new AuditLog
            {
                Action = action,
                Details = JsonSerializer.Serialize(details),
                LoggedAt = DateTime.UtcNow
            });
        }

        /// <summary>A failed response with an error code and message. Pure.</summary>
        private static ApiResponse Fail(string code, string message) =>
            new ApiResponse { Success = false, Error = new ApiError { Code = code, Message = message } };

        // ---------- 1. create_subscription ----------
        /// <summary>
        /// Flow 1: creates the Stripe subscription for the tier's price, stores it as 'active' and audits it. Inputs:
        /// customer id, tier (solo/team/enterprise). Output: {subscription_id, tier, status, next_billing_date (ISO 8601
        /// UTC)} or invalid_tier / stripe_error (the Stripe message is logged, not returned). Touches: Stripe (money),
        /// subscriptions, audit_logs.
        /// </summary>
        public async Task<ApiResponse> CreateSubscriptionAsync(string customerId, string tier)
        {
            if (tier == null || !_priceIds.TryGetValue(tier, out var priceId))
                return Fail("invalid_tier", "Tier not recognized");
            if (string.IsNullOrWhiteSpace(customerId))
                return Fail("invalid_customer", "Customer id is required");

            StripeSubscriptionInfo stripeSub;
            try
            {
                stripeSub = await _stripe.CreateSubscriptionAsync(customerId, priceId);
            }
            catch (PaymentProviderException ex)
            {
                _logger.LogError(ex, "Error creating subscription");
                return Fail("stripe_error", "The payment provider rejected the request");
            }

            _db.Subscriptions.Add(new Subscription
            {
                StripeSubscriptionId = stripeSub.Id,
                CustomerId = customerId,
                Tier = tier,
                Status = "active",
                CreatedAt = DateTime.UtcNow
            });
            LogAudit("subscription_created", new { customer_id = customerId, tier, stripe_sub_id = stripeSub.Id });
            await _db.SaveChangesAsync();

            return new ApiResponse
            {
                Success = true,
                Data = new CreateSubscriptionResult
                {
                    SubscriptionId = stripeSub.Id,
                    Tier = tier,
                    Status = "active",
                    NextBillingDate = Iso(stripeSub.CurrentPeriodEnd)
                }
            };
        }

        // ---------- 2. change_plan ----------
        /// <summary>
        /// Flow 2: moves a stored subscription to a new tier in Stripe (with proration), updates the row and audits old
        /// tier, new tier and the proration credit. Inputs: Stripe subscription id, new tier. Output: {subscription_id,
        /// old_tier, new_tier, effective_date, proration_credit (cents)} or invalid_tier / not_found / stripe_error.
        /// Touches: Stripe (money), subscriptions, audit_logs.
        /// </summary>
        public async Task<ApiResponse> ChangePlanAsync(string subscriptionId, string newTier)
        {
            if (newTier == null || !_priceIds.TryGetValue(newTier, out var newPriceId))
                return Fail("invalid_tier", "Tier not recognized");

            var subscription = await _db.Subscriptions.FirstOrDefaultAsync(s => s.StripeSubscriptionId == subscriptionId);
            if (subscription == null)
                return Fail("not_found", "Subscription not found");

            StripeSubscriptionInfo stripeSub;
            try
            {
                stripeSub = await _stripe.UpdateSubscriptionAsync(subscriptionId, newPriceId);
            }
            catch (PaymentProviderException ex)
            {
                _logger.LogError(ex, "Error changing plan");
                return Fail("stripe_error", "The payment provider rejected the request");
            }

            var oldTier = subscription.Tier;
            subscription.Tier = newTier;
            subscription.UpdatedAt = DateTime.UtcNow;
            LogAudit("plan_changed", new { subscription_id = subscriptionId, old_tier = oldTier, new_tier = newTier, proration_credits = stripeSub.ProrationCredit });
            await _db.SaveChangesAsync();

            return new ApiResponse
            {
                Success = true,
                Data = new ChangePlanResult
                {
                    SubscriptionId = subscriptionId,
                    OldTier = oldTier,
                    NewTier = newTier,
                    EffectiveDate = Iso(stripeSub.CurrentPeriodStart),
                    ProrationCredit = stripeSub.ProrationCredit
                }
            };
        }

        // ---------- 3. queue_refund ----------
        /// <summary>
        /// Flow 3: queues (never executes) a refund. Checks: the amount is positive, the invoice exists and is paid,
        /// and this refund plus every refund already queued or processed for the invoice does not exceed what was paid
        /// (so repeated requests cannot refund more than the invoice). Inputs: invoice id, amount (cents), reason, the
        /// acting admin's id (from the authenticated session, not the request body). Output: {refund_id, status:
        /// "queued", amount, reason} or invalid_amount / invalid_invoice / refund_exceeds_invoice. Changed 2026-11-10
        /// (session session_012zDydZCZ4AChqhEZ4oVtaP): cumulative check added. Touches: Stripe (read), refunds,
        /// audit_logs.
        /// </summary>
        public async Task<ApiResponse> QueueRefundAsync(string invoiceId, long amount, string reason, string createdBy)
        {
            if (amount <= 0)
                return Fail("invalid_amount", "Refund amount must be positive");

            var stripeInvoice = await _stripe.RetrieveInvoiceAsync(invoiceId);
            if (stripeInvoice == null || stripeInvoice.Status != "paid")
                return Fail("invalid_invoice", "Invoice not found or not succeeded");

            var alreadyRefunded = await _db.Refunds
                .Where(r => r.InvoiceId == invoiceId && (r.Status == "queued" || r.Status == "processed"))
                .SumAsync(r => (long?)r.Amount) ?? 0;
            if (amount + alreadyRefunded > stripeInvoice.AmountPaid)
                return Fail("refund_exceeds_invoice", "Refund amount exceeds invoice total");

            var refund = new Refund
            {
                InvoiceId = invoiceId,
                Amount = amount,
                Reason = reason,
                Status = "queued",
                CreatedBy = createdBy,
                CreatedAt = DateTime.UtcNow
            };
            _db.Refunds.Add(refund);
            LogAudit("refund_queued", new { invoice_id = invoiceId, amount, reason, created_by = createdBy });
            await _db.SaveChangesAsync();

            return new ApiResponse
            {
                Success = true,
                Data = new QueueRefundResult { RefundId = refund.Id, Status = "queued", Amount = amount, Reason = reason }
            };
        }

        // ---------- 4. handle_stripe_webhook ----------
        /// <summary>
        /// Flow 4: verifies the Stripe-Signature header, then applies the event once. Handles
        /// invoice.payment_succeeded, invoice.payment_failed, customer.subscription.updated and
        /// customer.subscription.deleted; other types are recorded and audited. The event id, the changes and the audit
        /// row are saved in one SaveChanges, so a failure leaves the event unrecorded and Stripe's retry can apply it;
        /// a duplicate (already recorded, or lost on the unique index in a race) is acknowledged without changes.
        /// Inputs: the raw request body and the Stripe-Signature header. Output: {received: true} or invalid_signature /
        /// invalid_payload. Rewritten 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): own constant-time
        /// verification and JSON parsing instead of Stripe.net's typed event objects. Touches: events, invoices,
        /// subscriptions, audit_logs.
        /// </summary>
        public async Task<ApiResponse> HandleStripeWebhookAsync(string jsonPayload, string stripeSignatureHeader)
        {
            if (!VerifySignature(jsonPayload, stripeSignatureHeader))
                return Fail("invalid_signature", "Webhook signature verification failed");

            JsonElement root, obj;
            string eventId, eventType;
            try
            {
                root = JsonDocument.Parse(jsonPayload).RootElement;
                eventId = root.GetProperty("id").GetString();
                eventType = root.GetProperty("type").GetString();
                obj = root.GetProperty("data").GetProperty("object");
            }
            catch (Exception ex) when (ex is JsonException || ex is KeyNotFoundException || ex is InvalidOperationException)
            {
                return Fail("invalid_payload", "Webhook payload is not a Stripe event");
            }
            if (string.IsNullOrEmpty(eventId) || string.IsNullOrEmpty(eventType))
                return Fail("invalid_payload", "Webhook payload is not a Stripe event");

            if (await _db.Events.AnyAsync(e => e.StripeEventId == eventId))
                return new ApiResponse { Success = true, Data = new WebhookResponse() };

            _db.Events.Add(new EventRecord { StripeEventId = eventId, EventType = eventType, ProcessedAt = DateTime.UtcNow });

            switch (eventType)
            {
                case "invoice.payment_succeeded":
                    {
                        var invoiceId = Str(obj, "id");
                        var customerId = Str(obj, "customer");
                        var amount = Long(obj, "amount_paid") ?? 0;
                        var paidAtUnix = obj.TryGetProperty("status_transitions", out var st) ? Long(st, "paid_at") : null;
                        var paidAt = paidAtUnix.HasValue ? DateTimeOffset.FromUnixTimeSeconds(paidAtUnix.Value).UtcDateTime : DateTime.UtcNow;

                        var dbInvoice = await _db.Invoices.FirstOrDefaultAsync(i => i.StripeInvoiceId == invoiceId);
                        if (dbInvoice == null)
                        {
                            dbInvoice = new Invoice { StripeInvoiceId = invoiceId };
                            _db.Invoices.Add(dbInvoice);
                        }
                        dbInvoice.CustomerId = customerId;
                        dbInvoice.Amount = amount;
                        dbInvoice.Status = "succeeded";
                        dbInvoice.PaidAt = paidAt;
                        LogAudit("payment_succeeded", new { customer_id = customerId, invoice_id = invoiceId, amount });
                        break;
                    }
                case "invoice.payment_failed":
                    {
                        var subscriptionId = Str(obj, "subscription");
                        var subscription = subscriptionId == null ? null
                            : await _db.Subscriptions.FirstOrDefaultAsync(s => s.StripeSubscriptionId == subscriptionId);
                        if (subscription != null && subscription.Status != "past_due")
                        {
                            subscription.Status = "past_due";
                            subscription.UpdatedAt = DateTime.UtcNow;
                        }
                        var reason = obj.TryGetProperty("last_finalization_error", out var err) && err.ValueKind == JsonValueKind.Object
                            ? Str(err, "message") : "payment_failed";
                        LogAudit("payment_failed", new { customer_id = Str(obj, "customer"), invoice_id = Str(obj, "id"), reason });
                        break;
                    }
                case "customer.subscription.updated":
                    {
                        var subscription = await FindSubscription(Str(obj, "id"));
                        if (subscription != null)
                        {
                            var oldTier = subscription.Tier;
                            var lookupKey = FirstItemLookupKey(obj);
                            // Only a known tier is accepted, so an unrelated price cannot set an arbitrary tier.
                            var newTier = lookupKey != null && _priceIds.ContainsKey(lookupKey) ? lookupKey : oldTier;
                            subscription.Tier = newTier;
                            subscription.Status = Str(obj, "status") ?? subscription.Status;
                            subscription.UpdatedAt = DateTime.UtcNow;
                            LogAudit("subscription_updated", new { customer_id = Str(obj, "customer"), old_tier = oldTier, new_tier = newTier });
                        }
                        break;
                    }
                case "customer.subscription.deleted":
                    {
                        var subscription = await FindSubscription(Str(obj, "id"));
                        if (subscription != null)
                        {
                            subscription.Status = "cancelled";
                            subscription.CancelledAt = DateTime.UtcNow;
                            subscription.UpdatedAt = DateTime.UtcNow;
                            LogAudit("subscription_cancelled", new { customer_id = Str(obj, "customer") });
                        }
                        break;
                    }
                default:
                    LogAudit("unhandled_event", new { event_type = eventType });
                    break;
            }

            try
            {
                await _db.SaveChangesAsync();
            }
            catch (DbUpdateException)
            {
                // A concurrent delivery of the same event may have won the unique index: then acknowledge it as a
                // duplicate; any other failure propagates so Stripe retries the delivery.
                if (!await IsRecordedElsewhere(eventId)) throw;
            }
            return new ApiResponse { Success = true, Data = new WebhookResponse() };
        }

        /// <summary>
        /// Stripe v1 signature check: header "t=&lt;unix&gt;,v1=&lt;hex&gt;[,v1=...]"; expected = HMAC-SHA256(secret,
        /// "&lt;t&gt;.&lt;payload&gt;"); any v1 must match in constant time (CryptographicOperations.FixedTimeEquals) and
        /// t must be within <see cref="WebhookTolerance"/> of now. Inputs: raw payload, header. Output: true when
        /// genuine. Added 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP). Pure (reads the clock).
        /// </summary>
        public bool VerifySignature(string payload, string header)
        {
            if (payload == null || string.IsNullOrEmpty(header)) return false;
            long? timestamp = null;
            var signatures = new List<string>();
            foreach (var part in header.Split(','))
            {
                var kv = part.Split('=', 2);
                if (kv.Length != 2) continue;
                var key = kv[0].Trim();
                if (key == "t" && long.TryParse(kv[1].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var t)) timestamp = t;
                else if (key == "v1") signatures.Add(kv[1].Trim());
            }
            if (timestamp == null || signatures.Count == 0) return false;
            var age = _clock() - DateTimeOffset.FromUnixTimeSeconds(timestamp.Value);
            if (age.Duration() > WebhookTolerance) return false;

            byte[] expected;
            using (var hmac = new HMACSHA256(_webhookSecret))
                expected = hmac.ComputeHash(Encoding.UTF8.GetBytes($"{timestamp.Value}.{payload}"));
            var match = false;
            foreach (var sig in signatures)
            {
                byte[] provided;
                try { provided = Convert.FromHexString(sig); }
                catch (FormatException) { continue; }
                if (provided.Length == expected.Length && CryptographicOperations.FixedTimeEquals(expected, provided)) match = true;
            }
            return match;
        }

        /// <summary>Finds a stored subscription by Stripe id (null when absent or id is null). Touches: subscriptions (read).</summary>
        private Task<Subscription> FindSubscription(string stripeSubscriptionId) =>
            stripeSubscriptionId == null ? Task.FromResult<Subscription>(null)
                : _db.Subscriptions.FirstOrDefaultAsync(s => s.StripeSubscriptionId == stripeSubscriptionId);

        /// <summary>True when another delivery already stored this event id. Touches: events (read, fresh context state).</summary>
        private async Task<bool> IsRecordedElsewhere(string eventId)
        {
            foreach (var entry in _db.ChangeTracker.Entries().ToList()) entry.State = EntityState.Detached;
            return await _db.Events.AnyAsync(e => e.StripeEventId == eventId);
        }

        /// <summary>items.data[0].price.lookup_key of a Stripe subscription object, or null. Pure.</summary>
        private static string FirstItemLookupKey(JsonElement sub)
        {
            if (!sub.TryGetProperty("items", out var items) || !items.TryGetProperty("data", out var data) ||
                data.ValueKind != JsonValueKind.Array || data.GetArrayLength() == 0) return null;
            var first = data[0];
            return first.TryGetProperty("price", out var price) && price.ValueKind == JsonValueKind.Object ? Str(price, "lookup_key") : null;
        }

        /// <summary>A string property, or null when missing or not a string. Pure.</summary>
        private static string Str(JsonElement e, string name) =>
            e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

        /// <summary>An integer property, or null when missing or not a number. Pure.</summary>
        private static long? Long(JsonElement e, string name) =>
            e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var n) ? n : null;

        /// <summary>ISO 8601 UTC ("o") text for a timestamp. Pure.</summary>
        private static string Iso(DateTime value) => DateTime.SpecifyKind(value, DateTimeKind.Utc).ToString("o", CultureInfo.InvariantCulture);
    }
}

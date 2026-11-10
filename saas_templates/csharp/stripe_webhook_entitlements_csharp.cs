// Stripe webhook entitlements template (docs/specs/stripe_webhook_entitlements.md): verifies Stripe's webhook
// signature (Stripe-Signature "t=...,v1=<hex HMAC-SHA256>", 300-second tolerance) BEFORE reading the body, applies
// each event exactly once (a CLAIM insert on stripe_events) and in order (event_at, then the rank created < updated <
// deleted; a tie of one kind asks Stripe), and keeps one answer per user: what they are entitled to right now. The
// webhook is the only writer of that answer.
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1, owner request 2026-11-10).
// Touches: stripe_events and entitlement_subscriptions behind IEntitlementStore (process memory in
// InMemoryEntitlementStore); the injected Stripe client (the network, in production; tests pass a fake). Money: it
// decides access to paid plans, never charges. Never logs the secret, the signature header or the payload.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AOI.StripeWebhookEntitlements
{
    /// <summary>
    /// Stripe's subscription lookup: retrieve_subscription(id) -> a subscription object (a JSON object), or throws.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the network in production.
    /// </summary>
    public interface IStripeSubscriptionClient
    {
        /// <summary>The subscription as Stripe holds it now. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        JsonElement RetrieveSubscription(string subscriptionId);
    }

    /// <summary>
    /// A webhook (or signature) answer: Status is the HTTP status; on 200, Received is true and Result is applied |
    /// duplicate | stale | ignored; otherwise Error. Timestamp is set by a verify_signature that passed. Pure data.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    public sealed class WebhookResult
    {
        public int Status { get; set; } = 200;
        public string Error { get; set; }
        public bool Ok => Error == null;
        public bool Received { get; set; }
        public string Result { get; set; }
        public long? Timestamp { get; set; }

        /// <summary>A refusal. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public static WebhookResult Fail(int status, string error) => new WebhookResult { Status = status, Error = error };
    }

    /// <summary>get_entitlement's answer; Status is the subscription's status in Stripe's spelling, or "none". Pure data. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public sealed class Entitlement
    {
        public bool Entitled { get; set; }
        public string Plan { get; set; }
        public string Status { get; set; }
        public long? CurrentPeriodEnd { get; set; }
        public bool CancelAtPeriodEnd { get; set; }
    }

    /// <summary>One row of entitlement_subscriptions. Pure data. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public sealed class SubscriptionRow
    {
        public string StripeSubscriptionId { get; set; }
        public string UserId { get; set; }
        public string StripeCustomerId { get; set; }
        public string PriceId { get; set; }
        public string Plan { get; set; }
        public string Status { get; set; }
        public long CurrentPeriodEnd { get; set; }
        public bool CancelAtPeriodEnd { get; set; }
        public long EventAt { get; set; }
        public int EventRank { get; set; }
        public long UpdatedAt { get; set; }

        /// <summary>A copy. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public SubscriptionRow Copy() => (SubscriptionRow)MemberwiseClone();
    }

    /// <summary>One row of stripe_events. Pure data. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public sealed class StripeEventRow
    {
        public string EventId { get; set; }
        public string Type { get; set; }
        public long Created { get; set; }
        public long ReceivedAt { get; set; }
        public string Result { get; set; }

        /// <summary>A copy. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public StripeEventRow Copy() => (StripeEventRow)MemberwiseClone();
    }

    /// <summary>
    /// The two tables. InTransaction runs steps 7-9 as one transaction: an exception undoes every change made inside it
    /// and propagates. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
    /// </summary>
    public interface IEntitlementStore
    {
        /// <summary>Runs <paramref name="work"/> as one transaction. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        T InTransaction<T>(Func<T> work);

        /// <summary>CLAIM: inserts the event; false when the id is already there (an insert that fails on the key). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        bool InsertEvent(StripeEventRow row);

        /// <summary>Stores the event's result. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        void SetEventResult(string eventId, string result);

        /// <summary>The event row (a copy), or null. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        StripeEventRow GetEvent(string eventId);

        /// <summary>The subscription row (a copy), or null. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        SubscriptionRow GetSubscription(string subscriptionId);

        /// <summary>The rows with this customer id (copies). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        List<SubscriptionRow> RowsForCustomer(string customerId);

        /// <summary>The user's rows (copies). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        List<SubscriptionRow> RowsForUser(string userId);

        /// <summary>Writes (inserts or replaces) a subscription row. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        void PutSubscription(SubscriptionRow row);
    }

    /// <summary>
    /// IEntitlementStore in process memory behind one (re-entrant) lock; a transaction snapshots both tables and
    /// restores them when the work throws. FailNextWrite makes the next PutSubscription throw (a store failure).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    public sealed class InMemoryEntitlementStore : IEntitlementStore
    {
        private readonly object _lock = new object();
        private Dictionary<string, StripeEventRow> _events = new Dictionary<string, StripeEventRow>(StringComparer.Ordinal);
        private Dictionary<string, SubscriptionRow> _subs = new Dictionary<string, SubscriptionRow>(StringComparer.Ordinal);

        /// <summary>Test hook: the next PutSubscription throws. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public bool FailNextWrite { get; set; }

        /// <summary>Test hook: how many events are recorded. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public int EventCount { get { lock (_lock) return _events.Count; } }

        /// <summary>Test hook: every subscription row (copies). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public List<SubscriptionRow> AllSubscriptions() { lock (_lock) return _subs.Values.Select(s => s.Copy()).ToList(); }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public T InTransaction<T>(Func<T> work)
        {
            lock (_lock)
            {
                var events = _events.ToDictionary(kv => kv.Key, kv => kv.Value.Copy(), StringComparer.Ordinal);
                var subs = _subs.ToDictionary(kv => kv.Key, kv => kv.Value.Copy(), StringComparer.Ordinal);
                try
                {
                    return work();
                }
                catch
                {
                    _events = events;
                    _subs = subs;
                    throw;
                }
            }
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public bool InsertEvent(StripeEventRow row)
        {
            lock (_lock)
            {
                if (_events.ContainsKey(row.EventId)) return false;
                _events[row.EventId] = row.Copy();
                return true;
            }
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public void SetEventResult(string eventId, string result)
        {
            lock (_lock) if (_events.TryGetValue(eventId, out var e)) e.Result = result;
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public StripeEventRow GetEvent(string eventId)
        {
            lock (_lock) return _events.TryGetValue(eventId, out var e) ? e.Copy() : null;
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public SubscriptionRow GetSubscription(string subscriptionId)
        {
            lock (_lock) return subscriptionId != null && _subs.TryGetValue(subscriptionId, out var s) ? s.Copy() : null;
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public List<SubscriptionRow> RowsForCustomer(string customerId)
        {
            lock (_lock) return _subs.Values.Where(s => customerId != null && s.StripeCustomerId == customerId).Select(s => s.Copy()).ToList();
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public List<SubscriptionRow> RowsForUser(string userId)
        {
            lock (_lock) return _subs.Values.Where(s => s.UserId == userId).Select(s => s.Copy()).ToList();
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public void PutSubscription(SubscriptionRow row)
        {
            lock (_lock)
            {
                if (FailNextWrite) { FailNextWrite = false; throw new InvalidOperationException("store write failed"); }
                _subs[row.StripeSubscriptionId] = row.Copy();
            }
        }
    }

    /// <summary>
    /// The webhook receiver and entitlement reader: sign_payload, verify_signature, handle_webhook, get_entitlement.
    /// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1, owner request 2026-11-10). Touches: the
    /// store and the Stripe client.
    /// </summary>
    public sealed class StripeWebhookEntitlements
    {
        public const int Tolerance = 300;
        private const long MaxTime = 99999999999L;
        private static readonly Regex EventIdShape = new Regex("^evt_[A-Za-z0-9_]{1,200}$", RegexOptions.CultureInvariant);
        private static readonly Regex SubIdShape = new Regex("^sub_[A-Za-z0-9_]{1,200}$", RegexOptions.CultureInvariant);

        private readonly IEntitlementStore _store;
        private readonly string _webhookSecret;
        private readonly Dictionary<string, string> _pricePlans;
        private readonly IStripeSubscriptionClient _stripe;
        private readonly Func<string, bool> _userExists;
        private readonly long _grace;
        private readonly Func<long> _clock;

        /// <summary>
        /// Builds the receiver. In: the store, webhook_secret, price_plans {price_id: plan}, the Stripe client,
        /// user_exists(user_id), period_grace_seconds (default 0) and the clock (Unix seconds). A secret under 16 bytes
        /// is not refused here: every call answers 503 webhook_not_configured (STRIPEWH-03). 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
        /// </summary>
        public StripeWebhookEntitlements(IEntitlementStore store, string webhookSecret, IDictionary<string, string> pricePlans,
            IStripeSubscriptionClient stripe, Func<string, bool> userExists, long periodGraceSeconds = 0, Func<long> clock = null)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _webhookSecret = webhookSecret;
            _pricePlans = (pricePlans ?? new Dictionary<string, string>()).ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);
            _stripe = stripe;
            _userExists = userExists ?? (_ => false);
            _grace = periodGraceSeconds;
            _clock = clock ?? (() => DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        }

        // ------------------------------------------------------------------ signature

        /// <summary>
        /// sign_payload: "t=" + timestamp + ",v1=" + lower-case hex HMAC-SHA256(key = UTF-8 of the whole secret, message =
        /// the timestamp's digits + "." + payload). In: the raw payload bytes, the secret, the timestamp. Out: the header.
        /// Why: STRIPEWH-01. Pure.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        public static string SignPayload(byte[] payload, string secret, long timestamp) =>
            "t=" + timestamp + ",v1=" + Hex(Mac(secret, timestamp.ToString(), payload));

        /// <summary>sign_payload over the UTF-8 of a text payload. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public static string SignPayload(string payload, string secret, long timestamp) => SignPayload(Encoding.UTF8.GetBytes(payload), secret, timestamp);

        /// <summary>
        /// verify_signature, steps 1-5: 503 webhook_not_configured (secret under 16 bytes); 400 missing_signature;
        /// 400 invalid_signature (over 4096 bytes, not exactly one t of 1-12 digits, no 64-hex v1, no candidate equal
        /// in constant time, every candidate compared); 400 timestamp_out_of_tolerance (|now - t| over 300). In: the raw
        /// payload, the header, the secret, now. Out: {ok, timestamp} or the refusal. Why: STRIPEWH-02..05. 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP. Pure.
        /// </summary>
        public static WebhookResult VerifySignature(byte[] payload, string header, string secret, long now)
        {
            if (secret == null || Encoding.UTF8.GetByteCount(secret) < 16) return WebhookResult.Fail(503, "webhook_not_configured");
            if (string.IsNullOrEmpty(header)) return WebhookResult.Fail(400, "missing_signature");
            if (Encoding.UTF8.GetByteCount(header) > 4096) return WebhookResult.Fail(400, "invalid_signature");
            var ts = new List<string>();
            var candidates = new List<string>();
            foreach (var element in header.Split(','))
            {
                var e = element.Trim(' ');
                var eq = e.IndexOf('=');
                if (eq < 0) continue;
                var name = e.Substring(0, eq);
                var value = e.Substring(eq + 1);
                if (name == "t") ts.Add(value);
                else if (name == "v1" && value.Length == 64 && value.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) candidates.Add(value);
            }
            if (ts.Count != 1 || ts[0].Length < 1 || ts[0].Length > 12 || !ts[0].All(c => c >= '0' && c <= '9'))
                return WebhookResult.Fail(400, "invalid_signature");
            if (candidates.Count == 0) return WebhookResult.Fail(400, "invalid_signature");
            var expected = Encoding.ASCII.GetBytes(Hex(Mac(secret, ts[0], payload ?? Array.Empty<byte>())));
            var match = false;
            foreach (var c in candidates) match |= CryptographicOperations.FixedTimeEquals(expected, Encoding.ASCII.GetBytes(c));
            if (!match) return WebhookResult.Fail(400, "invalid_signature");
            var t = long.Parse(ts[0]);
            if (Math.Abs(now - t) > Tolerance) return WebhookResult.Fail(400, "timestamp_out_of_tolerance");
            return new WebhookResult { Timestamp = t };
        }

        // ------------------------------------------------------------------ webhook

        /// <summary>handle_webhook over the UTF-8 of a text payload (tests and string-bodied hosts). Touches: see the byte overload. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public WebhookResult HandleWebhook(string payload, string header) =>
            HandleWebhook(payload == null ? null : Encoding.UTF8.GetBytes(payload), header);

        /// <summary>
        /// handle_webhook: verify (steps 1-5), then parse (step 6: strict UTF-8, no BOM, a JSON object with an evt_ id, a
        /// printable type, a TIME created and an object data.object; else 400 invalid_payload), then CLAIM, APPLY and
        /// store the result as one transaction (step 9: any error undoes it all, 500 processing_failed). In: the RAW body
        /// bytes and the Stripe-Signature header. Out: 200 {received, result} or the refusal. Why: STRIPEWH-01..14.
        /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the Stripe client.
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec db20a03, Phase B.4): a body holding a non-finite
        /// number anywhere (HoldsNonFinite: 1e400 outside created too) is 400 invalid_payload; before, only a non-finite
        /// created was.
        /// </summary>
        public WebhookResult HandleWebhook(byte[] payload, string header)
        {
            // A null body is an empty body: its signature then fails like any other (400), never a crash.
            // Code-quality review on PR 22, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
            payload ??= Array.Empty<byte>();
            var now = _clock();
            var verified = VerifySignature(payload, header, _webhookSecret, now);
            if (!verified.Ok) return verified;

            JsonDocument doc;
            try
            {
                if (payload.Length >= 3 && payload[0] == 0xEF && payload[1] == 0xBB && payload[2] == 0xBF) return WebhookResult.Fail(400, "invalid_payload");
                var text = new UTF8Encoding(false, true).GetString(payload);
                doc = JsonDocument.Parse(text);
            }
            catch (Exception)
            {
                return WebhookResult.Fail(400, "invalid_payload");
            }
            using (doc)
            {
                var root = doc.RootElement;
                // Phase B.4 (spec db20a03, 2026-11-10): a non-finite number anywhere makes the whole body invalid.
                if (root.ValueKind != JsonValueKind.Object || HoldsNonFinite(root)) return WebhookResult.Fail(400, "invalid_payload");
                var id = Str(root, "id");
                var type = Str(root, "type");
                var created = Time(Prop(root, "created"));
                var data = Prop(root, "data");
                var obj = data is JsonElement d && d.ValueKind == JsonValueKind.Object ? Prop(d, "object") : null;
                if (id == null || !EventIdShape.IsMatch(id) || type == null || type.Length < 1 || type.Length > 100 ||
                    type.Any(c => c < ' ' || c > '~') || created == null || obj?.ValueKind != JsonValueKind.Object)
                    return WebhookResult.Fail(400, "invalid_payload");
                // Both were checked just above; non-null locals make that explicit inside the transaction (code-quality
                // review on PR 22, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
                var createdAt = created.Value;
                var objElement = obj.Value;
                try
                {
                    var result = _store.InTransaction(() =>
                    {
                        if (!_store.InsertEvent(new StripeEventRow { EventId = id, Type = type, Created = createdAt, ReceivedAt = now }))
                            return "duplicate";
                        var applied = Apply(type, createdAt, objElement, now);
                        _store.SetEventResult(id, applied);
                        return applied;
                    });
                    return new WebhookResult { Received = true, Result = result };
                }
                catch (Exception)
                {
                    return WebhookResult.Fail(500, "processing_failed");
                }
            }
        }

        /// <summary>
        /// get_entitlement: among the user's ENTITLING rows (a plan, status active or trialing, current_period_end +
        /// grace &gt; now) the greatest period end, event_at, then subscription id; else the latest row, not entitled; else
        /// the "none" answer. Computed from the clock at every call. Why: STRIPEWH-07, 10, 14. 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store (read).
        /// </summary>
        public Entitlement GetEntitlement(string userId)
        {
            var now = _clock();
            var rows = _store.RowsForUser(userId);
            var entitling = rows.Where(r => r.Plan != null && (r.Status == "active" || r.Status == "trialing") && r.CurrentPeriodEnd + _grace > now)
                .OrderByDescending(r => r.CurrentPeriodEnd).ThenByDescending(r => r.EventAt)
                .ThenByDescending(r => r.StripeSubscriptionId, StringComparer.Ordinal).FirstOrDefault();
            if (entitling != null)
                return new Entitlement { Entitled = true, Plan = entitling.Plan, Status = entitling.Status, CurrentPeriodEnd = entitling.CurrentPeriodEnd, CancelAtPeriodEnd = entitling.CancelAtPeriodEnd };
            var latest = rows.OrderByDescending(r => r.EventAt).ThenByDescending(r => r.StripeSubscriptionId, StringComparer.Ordinal).FirstOrDefault();
            if (latest != null)
                return new Entitlement { Entitled = false, Plan = null, Status = latest.Status, CurrentPeriodEnd = latest.CurrentPeriodEnd, CancelAtPeriodEnd = latest.CancelAtPeriodEnd };
            return new Entitlement { Entitled = false, Plan = null, Status = "none", CurrentPeriodEnd = null, CancelAtPeriodEnd = false };
        }

        // ------------------------------------------------------------------ APPLY

        /// <summary>APPLY(event) by type. Out: applied | stale | ignored. Throws on a client or store error. Touches: store, client. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private string Apply(string type, long created, JsonElement obj, long now)
        {
            switch (type)
            {
                case "customer.subscription.created": return Subscription(obj, MetadataUser(obj), 0, created, now, fetched: false);
                case "customer.subscription.updated": return Subscription(obj, MetadataUser(obj), 1, created, now, fetched: false);
                case "customer.subscription.deleted": return Subscription(obj, MetadataUser(obj), 2, created, now, fetched: false);
                case "checkout.session.completed":
                {
                    var subId = Str(obj, "subscription");
                    if (Str(obj, "mode") != "subscription" || subId == null || !SubIdShape.IsMatch(subId)) return "ignored";
                    var row = _store.GetSubscription(subId);
                    if (row != null && Compare(row.EventAt, row.EventRank, created, 1) > 0) return "stale";
                    var sub = Fetch(subId);
                    var reference = Str(obj, "client_reference_id");
                    var hint = !string.IsNullOrEmpty(reference) ? reference : MetadataUser(obj);
                    return Subscription(sub, hint, 1, created, now, fetched: true);
                }
                default:
                    return "ignored";
            }
        }

        /// <summary>
        /// SUBSCRIPTION(sub, hint, rank), rules a-g: the id shape; the price and plan (an unknown price never creates a
        /// row; a stored row keeps or loses its plan); the user (the row's, else a verified hint, else one user of the
        /// customer's rows); stale or tie (a tie of rank 0 or 1 fetches the subscription and continues with it); the
        /// period end (top level, else the largest item, else the stored one); the status; the write. Touches: store, client.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        private string Subscription(JsonElement sub, string hint, int rank, long eventAt, long now, bool fetched)
        {
            var subId = Str(sub, "id");
            if (subId == null || !SubIdShape.IsMatch(subId)) return "ignored";
            var row = _store.GetSubscription(subId);
            if (row == null)
            {
                var price = PriceId(sub);
                if (price == null || !_pricePlans.ContainsKey(price)) return "ignored";
            }
            string userId;
            if (row != null) userId = row.UserId;
            else if (!string.IsNullOrEmpty(hint) && _userExists(hint)) userId = hint;
            else
            {
                var customer = Str(sub, "customer");
                var owners = customer == null ? new List<string>() : _store.RowsForCustomer(customer).Select(r => r.UserId).Distinct().ToList();
                if (owners.Count != 1) return "ignored";
                userId = owners[0];
            }
            if (row != null)
            {
                var cmp = Compare(eventAt, rank, row.EventAt, row.EventRank);
                if (cmp < 0) return "stale";
                if (cmp == 0 && rank <= 1 && !fetched) sub = Fetch(subId);
            }
            // rule b runs on the object being written: after a tie fetch that is the fetched subscription, so the row gets
            // Stripe's current price and plan (spec fed6e7b, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
            var (priceId, plan) = PriceAndPlan(sub, row);
            long periodEnd = Time(Prop(sub, "current_period_end")) ?? ItemsPeriodEnd(sub) ?? row?.CurrentPeriodEnd ?? 0;
            string status;
            if (rank == 2) status = "canceled";
            else
            {
                status = Str(sub, "status");
                if (status == null || status.Length < 1 || status.Length > 32 || !status.All(c => (c >= 'a' && c <= 'z') || c == '_')) return "ignored";
            }
            _store.PutSubscription(new SubscriptionRow
            {
                StripeSubscriptionId = subId, UserId = userId, StripeCustomerId = Str(sub, "customer"), PriceId = priceId, Plan = plan,
                Status = status, CurrentPeriodEnd = periodEnd, CancelAtPeriodEnd = Prop(sub, "cancel_at_period_end")?.ValueKind == JsonValueKind.True,
                EventAt = eventAt, EventRank = rank, UpdatedAt = now,
            });
            return "applied";
        }

        /// <summary>Rule b's price and plan for a write. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private (string PriceId, string Plan) PriceAndPlan(JsonElement sub, SubscriptionRow row)
        {
            var price = PriceId(sub);
            if (price != null && _pricePlans.TryGetValue(price, out var plan)) return (price, plan);
            if (row != null && (price == null || price == row.PriceId)) return (row.PriceId, row.Plan);
            return (price, null);
        }

        /// <summary>stripe_client.retrieve_subscription; a non-object answer counts as an error. Throws. Touches: the client. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private JsonElement Fetch(string subId)
        {
            if (_stripe == null) throw new InvalidOperationException("no Stripe client");
            var sub = _stripe.RetrieveSubscription(subId);
            if (sub.ValueKind != JsonValueKind.Object) throw new InvalidOperationException("not a subscription object");
            return sub;
        }

        // ------------------------------------------------------------------ JSON helpers (pure)

        /// <summary>(a1, r1) compared with (a2, r2), event_at first. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static int Compare(long a1, int r1, long a2, int r2) => a1 != a2 ? a1.CompareTo(a2) : r1.CompareTo(r2);

        /// <summary>A property of an object, or null. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static JsonElement? Prop(JsonElement obj, string name) =>
            obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(name, out var v) ? v : (JsonElement?)null;

        /// <summary>A property that is a JSON string, or null. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static string Str(JsonElement obj, string name)
        {
            var v = Prop(obj, name);
            return v?.ValueKind == JsonValueKind.String ? v.Value.GetString() : null;
        }

        /// <summary>
        /// Whether a JSON value holds, anywhere inside it, a number that is not finite as a double (1e400 reads as
        /// infinity, or does not read at all). In: a parsed element (JsonDocument caps the depth at 64). Out: true when
        /// one is found. Why: spec db20a03 (Phase B.4): a body holding any non-finite number, not only in a TIME field,
        /// is 400 invalid_payload as a whole, because some parsers refuse it while parsing.
        /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Pure.
        /// </summary>
        private static bool HoldsNonFinite(JsonElement e)
        {
            switch (e.ValueKind)
            {
                case JsonValueKind.Number:
                    return !e.TryGetDouble(out var d) || !double.IsFinite(d);
                case JsonValueKind.Object:
                    foreach (var p in e.EnumerateObject())
                        if (HoldsNonFinite(p.Value)) return true;
                    return false;
                case JsonValueKind.Array:
                    foreach (var item in e.EnumerateArray())
                        if (HoldsNonFinite(item)) return true;
                    return false;
                default:
                    return false;
            }
        }

        /// <summary>
        /// TIME: a JSON number (never true, a text or null) whose value is finite, whole and in 0..99999999999. Out: the
        /// value or null. Why: STRIPEWH-06. Pure.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        private static long? Time(JsonElement? e)
        {
            if (e?.ValueKind != JsonValueKind.Number) return null;
            if (!e.Value.TryGetDouble(out var d) || !double.IsFinite(d) || d != Math.Floor(d) || d < 0 || d > MaxTime) return null;
            return (long)d;
        }

        /// <summary>metadata.user_id when it is a string. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static string MetadataUser(JsonElement obj) => Prop(obj, "metadata") is JsonElement m ? Str(m, "user_id") : null;

        /// <summary>items.data as a list of elements (empty when absent). Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static List<JsonElement> Items(JsonElement sub)
        {
            var items = Prop(sub, "items");
            var data = items is JsonElement i ? Prop(i, "data") : null;
            return data?.ValueKind == JsonValueKind.Array ? data.Value.EnumerateArray().ToList() : new List<JsonElement>();
        }

        /// <summary>items.data[0].price.id when it is a string. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static string PriceId(JsonElement sub)
        {
            var items = Items(sub);
            if (items.Count == 0) return null;
            return Prop(items[0], "price") is JsonElement p ? Str(p, "id") : null;
        }

        /// <summary>The largest items.data[].current_period_end that is a TIME, or null. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static long? ItemsPeriodEnd(JsonElement sub)
        {
            long? best = null;
            foreach (var item in Items(sub))
            {
                var t = Time(Prop(item, "current_period_end"));
                if (t != null && (best == null || t > best)) best = t;
            }
            return best;
        }

        /// <summary>HMAC-SHA256(UTF-8 of secret, UTF-8 of (t + ".") followed by the payload bytes). Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static byte[] Mac(string secret, string t, byte[] payload)
        {
            var prefix = Encoding.UTF8.GetBytes(t + ".");
            var msg = new byte[prefix.Length + payload.Length];
            Buffer.BlockCopy(prefix, 0, msg, 0, prefix.Length);
            Buffer.BlockCopy(payload, 0, msg, prefix.Length, payload.Length);
            return HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), msg);
        }

        /// <summary>Lower-case hex of bytes. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AOI.Webhooks
{
    // ---------- Store Interfaces ----------
    public interface IStore
    {
        Endpoint AddEndpoint(string orgId, string url, IEnumerable<string> eventTypes);
        Endpoint GetEndpoint(string endpointId);
        IEnumerable<Endpoint> GetActiveEndpoints(string orgId, string eventType);
        void UpdateEndpoint(Endpoint endpoint);

        Message AddMessage(string orgId, string eventType, string payload);
        Message GetMessage(string messageId);

        Delivery AddDelivery(string messageId, string endpointId);
        Delivery GetDelivery(int deliveryId);
        IEnumerable<Delivery> GetPendingDeliveries(DateTimeOffset now);
        void UpdateDelivery(Delivery delivery);
    }

    // ---------- In‑Memory Store ----------
    public class InMemoryStore : IStore
    {
        private readonly Dictionary<string, Endpoint> _endpoints = new();
        private readonly Dictionary<string, Message> _messages = new();
        private readonly Dictionary<int, Delivery> _deliveries = new();
        private int _deliverySeq = 1;

        public Endpoint AddEndpoint(string orgId, string url, IEnumerable<string> eventTypes)
        {
            var secretBytes = new byte[32];
            RandomNumberGenerator.Fill(secretBytes);
            var secret = "whsec_" + Convert.ToBase64String(secretBytes);
            var ep = new Endpoint
            {
                Id = Guid.NewGuid().ToString(),
                OrgId = orgId,
                Url = url,
                Secret = secret,
                EventTypes = new HashSet<string>(eventTypes),
                Active = true,
                FailureCount = 0,
                CreatedAt = DateTimeOffset.UtcNow
            };
            _endpoints[ep.Id] = ep;
            return ep;
        }

        public Endpoint GetEndpoint(string endpointId) => _endpoints[endpointId];

        public IEnumerable<Endpoint> GetActiveEndpoints(string orgId, string eventType) =>
            _endpoints.Values.Where(e => e.Active && e.OrgId == orgId && e.EventTypes.Contains(eventType));

        public void UpdateEndpoint(Endpoint endpoint) => _endpoints[endpoint.Id] = endpoint;

        public Message AddMessage(string orgId, string eventType, string payload)
        {
            var msg = new Message
            {
                Id = "msg_" + Guid.NewGuid().ToString("N"),
                OrgId = orgId,
                EventType = eventType,
                Payload = payload,
                CreatedAt = DateTimeOffset.UtcNow
            };
            _messages[msg.Id] = msg;
            return msg;
        }

        public Message GetMessage(string messageId) => _messages[messageId];

        public Delivery AddDelivery(string messageId, string endpointId)
        {
            var del = new Delivery
            {
                Id = _deliverySeq++,
                MessageId = messageId,
                EndpointId = endpointId,
                Attempt = 0,
                Success = false
            };
            _deliveries[del.Id] = del;
            return del;
        }

        public Delivery GetDelivery(int deliveryId) => _deliveries[deliveryId];

        /// <summary>
        /// Deliveries still due: not successful, not given up on (<see cref="Delivery.RetriesExhausted"/>), and
        /// with no next attempt or a next attempt at or before <paramref name="now"/>. In insertion order.
        /// Why: a delivery whose last scheduled retry failed must stop being sent (webhooks spec: retry
        /// schedule 5s..10h, then the message has fully failed). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// Touches: in-memory store only.
        /// </summary>
        public IEnumerable<Delivery> GetPendingDeliveries(DateTimeOffset now) =>
            _deliveries.Values.OrderBy(d => d.Id)
                .Where(d => !d.Success && !d.RetriesExhausted && (d.NextAttemptAt == null || d.NextAttemptAt <= now));

        public void UpdateDelivery(Delivery delivery) => _deliveries[delivery.Id] = delivery;
    }

    // ---------- Data Models ----------
    public class Endpoint
    {
        public string Id { get; set; }
        public string OrgId { get; set; }
        public string Url { get; set; }
        public string Secret { get; set; }
        public HashSet<string> EventTypes { get; set; }
        public bool Active { get; set; }
        public int FailureCount { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
    }

    public class Message
    {
        public string Id { get; set; }
        public string OrgId { get; set; }
        public string EventType { get; set; }
        public string Payload { get; set; } // raw JSON string
        public DateTimeOffset CreatedAt { get; set; }
    }

    public class Delivery
    {
        public int Id { get; set; }
        public string MessageId { get; set; }
        public string EndpointId { get; set; }
        public int Attempt { get; set; }
        public int? StatusCode { get; set; }
        public bool Success { get; set; }
        public string Error { get; set; }
        public DateTimeOffset? NextAttemptAt { get; set; }
        public DateTimeOffset? DeliveredAt { get; set; }

        /// <summary>
        /// True once the last attempt in the retry schedule failed: the message has fully failed for this
        /// endpoint and is never sent again. Stored as error = "retries_exhausted" in a SQL store.
        /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (webhooks spec retry rule). Touches nothing.
        /// </summary>
        public bool RetriesExhausted => Error == WebhookService.RetriesExhaustedError;
    }

    // ---------- Core Service ----------
    public static class WebhookService
    {
        // shared store for the whole process
        public static IStore Store { get; } = new InMemoryStore();

        private static readonly TimeSpan[] Backoff = new[]
        {
            TimeSpan.FromSeconds(5),
            TimeSpan.FromMinutes(5),
            TimeSpan.FromMinutes(30),
            TimeSpan.FromHours(2),
            TimeSpan.FromHours(5),
            TimeSpan.FromHours(10),
            TimeSpan.FromHours(10)
        };

        // Create endpoint and generate secret
        public static Endpoint CreateEndpoint(string orgId, string url, IEnumerable<string> eventTypes)
        {
            if (!url.StartsWith("https://") && !(url.StartsWith("http://localhost")))
                throw new ArgumentException("URL must be https:// or http://localhost for dev");
            return Store.AddEndpoint(orgId, url, eventTypes);
        }

        // Send event – creates message and pending deliveries
        public static Message SendEvent(string orgId, string eventType, JsonElement payload)
        {
            var payloadStr = payload.GetRawText();
            var msg = Store.AddMessage(orgId, eventType, payloadStr);
            var endpoints = Store.GetActiveEndpoints(orgId, eventType);
            foreach (var ep in endpoints)
            {
                Store.AddDelivery(msg.Id, ep.Id);
            }
            return msg;
        }

        // Sign according to spec
        public static string Sign(string secret, string msgId, long timestamp, string payload)
        {
            if (!secret.StartsWith("whsec_"))
                throw new ArgumentException("Invalid secret format");
            var keyB64 = secret.Substring("whsec_".Length);
            var key = Convert.FromBase64String(keyB64);
            var content = $"{msgId}.{timestamp}.{payload}";
            using var hmac = new HMACSHA256(key);
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(content));
            var sig = Convert.ToBase64String(hash);
            return $"v1,{sig}";
        }

        /// <summary>
        /// Receiver-side check of a Standard Webhooks request.
        /// In: the endpoint secret ("whsec_..."), the request headers (webhook-id, webhook-timestamp,
        /// webhook-signature), the raw body, and the tolerance in seconds (default 300).
        /// Out: true when the timestamp is within the tolerance and ANY of the space-separated "v1,&lt;base64&gt;"
        /// signatures matches; false otherwise. Never throws on a malformed header: an entry without a comma or
        /// with a version other than "v1" is skipped (before 2026-11-10 such an entry threw IndexOutOfRange).
        /// Signatures are compared with CryptographicOperations.FixedTimeEquals (HOOK-01..04).
        /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing (pure computation, reads the clock).
        /// </summary>
        public static bool Verify(string secret, IDictionary<string, string> headers, string rawBody, int toleranceSeconds = 300)
        {
            if (headers == null || rawBody == null ||
                !headers.TryGetValue("webhook-id", out var msgId) ||
                !headers.TryGetValue("webhook-timestamp", out var tsStr) ||
                !headers.TryGetValue("webhook-signature", out var sigHeader) ||
                msgId == null || sigHeader == null)
                return false;

            if (!long.TryParse(tsStr, out var timestamp))
                return false;

            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (Math.Abs(now - timestamp) > toleranceSeconds)
                return false;

            // expected format is "v1,<base64>"
            var expectedBytes = Encoding.UTF8.GetBytes(Sign(secret, msgId, timestamp, rawBody).Substring(3));
            var matched = false;
            foreach (var sig in sigHeader.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                var comma = sig.IndexOf(',');
                if (comma < 0 || sig.Substring(0, comma) != "v1")
                    continue;
                var providedBytes = Encoding.UTF8.GetBytes(sig.Substring(comma + 1));
                if (CryptographicOperations.FixedTimeEquals(expectedBytes, providedBytes))
                    matched = true;
            }
            return matched;
        }

        /// <summary>The error text that marks a delivery whose retries are all used up.</summary>
        public const string RetriesExhaustedError = "retries_exhausted";

        /// <summary>
        /// Sends one attempt of a delivery through the injectable sender.
        /// In: the delivery, and sender(url, headers, body) =&gt; (statusCode, responseBody).
        /// Out: none; the delivery row records attempt, status_code, success and next_attempt_at.
        /// Headers: webhook-id (the message id, the same on every retry: HOOK-07), webhook-timestamp,
        /// webhook-signature and Content-Type: application/json. 200-299 is success; anything else, or a
        /// sender that throws, is a failure (HOOK-05) and schedules the next attempt after 5s, 5m, 30m, 2h, 5h,
        /// 10h, 10h. When the last of those retries fails the message has fully failed for this endpoint: no
        /// further attempt (error "retries_exhausted"), and the endpoint's failure_count (consecutive
        /// fully-failed messages) goes up; at 5 the endpoint is disabled. A success resets failure_count.
        /// Why: before 2026-11-10 every failed attempt counted toward disabling, so one message's retries could
        /// disable an endpoint, and retries never stopped; the spec counts fully-failed messages.
        /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: network through the sender, the store.
        /// </summary>
        public static void Deliver(Delivery delivery,
            Func<string, Dictionary<string, string>, string, (int statusCode, string responseBody)> sender)
        {
            var endpoint = Store.GetEndpoint(delivery.EndpointId);
            var message = Store.GetMessage(delivery.MessageId);
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var signature = Sign(endpoint.Secret, message.Id, timestamp, message.Payload);
            var headers = new Dictionary<string, string>
            {
                { "webhook-id", message.Id },
                { "webhook-timestamp", timestamp.ToString() },
                { "webhook-signature", signature },
                { "Content-Type", "application/json" }
            };

            (int statusCode, string _) result;
            string error = null;
            try
            {
                result = sender(endpoint.Url, headers, message.Payload);
            }
            catch (Exception ex)
            {
                // a sender that raises or times out is a failed attempt, never an unhandled error
                result = (0, null);
                error = ex.GetType().Name;
            }

            delivery.Attempt += 1;
            delivery.StatusCode = result.statusCode;
            delivery.Success = result.statusCode >= 200 && result.statusCode <= 299;
            delivery.DeliveredAt = DateTimeOffset.UtcNow;

            if (!delivery.Success)
            {
                if (delivery.Attempt > Backoff.Length)
                {
                    // the last scheduled retry failed: the message has fully failed for this endpoint
                    delivery.NextAttemptAt = null;
                    delivery.Error = RetriesExhaustedError;
                    endpoint.FailureCount += 1;
                    if (endpoint.FailureCount >= 5)
                        endpoint.Active = false;
                    Store.UpdateEndpoint(endpoint);
                }
                else
                {
                    delivery.Error = error ?? ("http_" + result.statusCode);
                    delivery.NextAttemptAt = DateTimeOffset.UtcNow.Add(Backoff[delivery.Attempt - 1]);
                }
            }
            else
            {
                delivery.Error = null;
                delivery.NextAttemptAt = null;
                endpoint.FailureCount = 0;
                Store.UpdateEndpoint(endpoint);
            }

            Store.UpdateDelivery(delivery);
        }

        // Rotate secret for an endpoint
        public static string RotateSecret(string endpointId)
        {
            var endpoint = Store.GetEndpoint(endpointId);
            var secretBytes = new byte[32];
            RandomNumberGenerator.Fill(secretBytes);
            var newSecret = "whsec_" + Convert.ToBase64String(secretBytes);
            endpoint.Secret = newSecret;
            Store.UpdateEndpoint(endpoint);
            return newSecret;
        }
    }
}
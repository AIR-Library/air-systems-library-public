// Tests for the Stripe webhook entitlements template (docs/specs/stripe_webhook_entitlements.md,
// STRIPEWH-01..STRIPEWH-14), with the spec's fixed vector. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
// (Phase D wave 1, owner request 2026-11-10). Offline: a fake Stripe client, an injected clock, the in-memory store.
// Touches: process memory only. The secret is built from pieces at run time.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AOI.StripeWebhookEntitlements;

/// <summary>The STRIPEWH-01..STRIPEWH-14 tests, run by Main (a console harness). Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.</summary>
public static class StripeWebhookEntitlementsTests
{
    private static int _failures;
    private static int _checks;

    /// <summary>Runs every test and returns 1 when any check failed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the console.</summary>
    public static int Main()
    {
        TestVector();
        TestInvalidSignatures();
        TestMissingHeaderAndUnconfigured();
        TestTolerance();
        TestTwoV1Values();
        TestInvalidPayloads();
        TestNonFiniteNumberAnywhere();
        TestCreatedGrantsEntitlement();
        TestDuplicate();
        TestOutOfOrder();
        TestEntitlementEnds();
        TestPeriodEnd();
        TestIgnored();
        TestCheckoutSession();
        TestTwoSubscriptionsAndUserLookup();
        Console.WriteLine($"\n=== Results: {_checks} checks, {_failures} failures ===");
        return _failures > 0 ? 1 : 0;
    }

    /// <summary>Counts one check; prints FAIL with the message when it is false. Touches: the console. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static void Check(bool condition, string message)
    {
        _checks++;
        if (!condition) { _failures++; Console.WriteLine("FAIL: " + message); }
    }

    /// <summary>Counts one equality check; prints both values on failure. Touches: the console. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static void Eq<T>(T expected, T actual, string message)
    {
        _checks++;
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            _failures++;
            Console.WriteLine($"FAIL: {message} -- expected <{expected}>, got <{actual}>");
        }
    }

    private static readonly string Secret = "whsec_" + "test_secret_for_vectors";
    private const string Body =
        "{\"id\":\"evt_test_0001\",\"type\":\"customer.subscription.updated\",\"created\":1700000000," +
        "\"data\":{\"object\":{\"id\":\"sub_test_0001\",\"customer\":\"cus_test_0001\",\"status\":\"active\"," +
        "\"current_period_end\":1702592000,\"cancel_at_period_end\":false," +
        "\"metadata\":{\"user_id\":\"user_1\"},\"items\":{\"data\":[{\"price\":{\"id\":\"price_pro_monthly\"}}]}}}}";

    /// <summary>A Stripe client that serves queued subscription objects (JSON) and records ids; Throw makes it raise. No network. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private sealed class FakeStripe : IStripeSubscriptionClient
    {
        public List<string> Calls = new List<string>();
        public Dictionary<string, string> Objects = new Dictionary<string, string>();
        public bool Throw;
        /// <summary>Records the id; serves the queued object or throws when Throw is set. Touches: process memory. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public JsonElement RetrieveSubscription(string subscriptionId)
        {
            Calls.Add(subscriptionId);
            if (Throw) throw new InvalidOperationException("stripe unavailable");
            return JsonDocument.Parse(Objects[subscriptionId]).RootElement.Clone();
        }
    }

    /// <summary>The receiver under test with its store, Stripe fake and clock. Touches: process memory. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private sealed class Rig
    {
        public InMemoryEntitlementStore Store = new InMemoryEntitlementStore();
        public FakeStripe Stripe = new FakeStripe();
        public long Now = 1700000000;
        public StripeWebhookEntitlements Sys;
        /// <summary>A receiver over a fresh store with the Stripe fake and the movable clock. Touches: process memory. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public Rig(long grace = 0, string secret = null, Dictionary<string, string> plans = null)
        {
            Sys = Build(grace, secret, plans);
        }
        /// <summary>A receiver over this rig's store with another grace, secret or price list. Touches: process memory. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public StripeWebhookEntitlements Build(long grace = 0, string secret = null, Dictionary<string, string> plans = null) =>
            new StripeWebhookEntitlements(Store, secret ?? Secret, plans ?? new Dictionary<string, string> { ["price_pro_monthly"] = "pro", ["price_team"] = "team" },
                Stripe, u => u == "user_1" || u == "user_2" || u == "user_3", grace, () => Now);

        /// <summary>Signs a body at the current clock and handles it. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public WebhookResult Send(string body) => Sys.HandleWebhook(body, StripeWebhookEntitlements.SignPayload(body, Secret, Now));
    }

    /// <summary>A subscription object as JSON. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static string Sub(string id, string status = "active", string price = "price_pro_monthly", long? cpe = 1702592000,
        string user = "user_1", string customer = "cus_1", bool cancel = false, string items = null)
    {
        var parts = new List<string> { $"\"id\":\"{id}\"", $"\"customer\":\"{customer}\"", $"\"status\":\"{status}\"" };
        if (cpe != null) parts.Add($"\"current_period_end\":{cpe}");
        parts.Add($"\"cancel_at_period_end\":{(cancel ? "true" : "false")}");
        if (user != null) parts.Add($"\"metadata\":{{\"user_id\":\"{user}\"}}");
        parts.Add(items ?? (price == null ? "\"items\":{\"data\":[]}" : $"\"items\":{{\"data\":[{{\"price\":{{\"id\":\"{price}\"}}}}]}}"));
        return "{" + string.Join(",", parts) + "}";
    }

    /// <summary>An event body as JSON. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static string Evt(string id, string type, long created, string obj) =>
        $"{{\"id\":\"{id}\",\"type\":\"{type}\",\"created\":{created},\"data\":{{\"object\":{obj}}}}}";

    /// <summary>The JSON form of an entitlement, to compare answers whole. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static string Show(Entitlement e) => JsonSerializer.Serialize(e);

    /// <summary>
    /// The spec's vector: the body's SHA-256, sign_payload's header, handle_webhook 200 applied at 1700000000, and the
    /// entitlement answer. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // STRIPEWH-01
    public static void TestVector()
    {
        var bytes = Encoding.UTF8.GetBytes(Body);
        Eq(317, bytes.Length, "the body is 317 bytes");
        Eq("f2e8a2d52e46e4642dde0390c9def15047ff2178a8d33a9928698aca132cbe88", Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), "body SHA-256");
        var header = StripeWebhookEntitlements.SignPayload(bytes, Secret, 1700000000);
        Eq("t=1700000000,v1=5bca2d8b83d83f9a52f3b25714245817b15ae87b9e73abcca2c7a514977a8ae5", header, "sign_payload");
        var rig = new Rig();
        var r = rig.Sys.HandleWebhook(bytes, header);
        Eq((200, true, "applied"), (r.Status, r.Received, r.Result), "handle_webhook");
        var e = rig.Sys.GetEntitlement("user_1");
        Eq((true, "pro", "active", (long?)1702592000, false), (e.Entitled, e.Plan, e.Status, e.CurrentPeriodEnd, e.CancelAtPeriodEnd), "get_entitlement");
        Eq("applied", rig.Store.GetEvent("evt_test_0001").Result, "the event row holds its result");
    }

    /// <summary>
    /// 400 invalid_signature, nothing stored, for another secret, a changed body byte, a changed t, no v1, a v1 that is
    /// not 64 lower-case hex, only a v0, and two t elements. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    /// </summary>
    // STRIPEWH-02
    public static void TestInvalidSignatures()
    {
        var rig = new Rig();
        var good = StripeWebhookEntitlements.SignPayload(Body, Secret, 1700000000);
        var v1 = good.Substring(good.IndexOf("v1=") + 3);
        var other = StripeWebhookEntitlements.SignPayload(Body, "whsec_" + "another_secret_value", 1700000000);
        var changedBody = Body.Replace("\"active\"", "\"activf\"");
        var cases = new List<(string Name, string Body, string Header)>
        {
            ("another secret", Body, other),
            ("one changed byte of the body", changedBody, good),
            ("a changed t", Body, "t=1700000001,v1=" + v1),
            ("no v1", Body, "t=1700000000"),
            ("v1 upper case", Body, "t=1700000000,v1=" + v1.ToUpperInvariant()),
            ("v1 too short", Body, "t=1700000000,v1=" + v1.Substring(1)),
            ("only v0", Body, "t=1700000000,v0=" + v1),
            ("two t elements", Body, "t=1700000000,t=1700000000,v1=" + v1),
            ("t not digits", Body, "t=17000000x0,v1=" + v1),
            ("over 4096 bytes", Body, good + "," + new string('x', 4100)),
        };
        foreach (var (name, body, header) in cases)
        {
            var r = rig.Sys.HandleWebhook(body, header);
            Eq((400, "invalid_signature"), (r.Status, r.Error), name);
        }
        Eq(0, rig.Store.EventCount, "no event recorded");
        Eq(0, rig.Store.AllSubscriptions().Count, "no row");
    }

    /// <summary>
    /// A missing or empty header is 400 missing_signature; a secret under 16 bytes is 503 webhook_not_configured for
    /// every call, whatever its signature. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // STRIPEWH-03
    public static void TestMissingHeaderAndUnconfigured()
    {
        var rig = new Rig();
        foreach (var h in new[] { null, "" })
        {
            var r = rig.Sys.HandleWebhook(Body, h);
            Eq((400, "missing_signature"), (r.Status, r.Error), "header " + (h == null ? "missing" : "empty"));
        }
        var shortSecret = "whsec_" + "short";
        var weak = new Rig(secret: shortSecret);
        foreach (var h in new[] { StripeWebhookEntitlements.SignPayload(Body, shortSecret, 1700000000), null, "garbage", StripeWebhookEntitlements.SignPayload(Body, Secret, 1700000000) })
        {
            var r = weak.Sys.HandleWebhook(Body, h);
            Eq((503, "webhook_not_configured"), (r.Status, r.Error), "short secret");
        }
        Eq(0, weak.Store.EventCount, "nothing recorded");
        Eq(503, StripeWebhookEntitlements.VerifySignature(Encoding.UTF8.GetBytes(Body), "t=1", "123456789012345", 0).Status, "15 bytes is too short");
        Eq(400, StripeWebhookEntitlements.VerifySignature(Encoding.UTF8.GetBytes(Body), "t=1", "1234567890123456", 0).Status, "16 bytes is configured");
    }

    /// <summary>
    /// Tolerance with a fresh store each time: 300 s old accepted, 301 s old refused, 300 s ahead accepted, 301 s ahead
    /// refused (timestamp_out_of_tolerance). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // STRIPEWH-04
    public static void TestTolerance()
    {
        var header = StripeWebhookEntitlements.SignPayload(Body, Secret, 1700000000);
        foreach (var (now, ok) in new[] { (1700000300L, true), (1700000301L, false), (1699999700L, true), (1699999699L, false) })
        {
            var rig = new Rig { Now = now };
            var r = rig.Sys.HandleWebhook(Body, header);
            if (ok) Eq((200, "applied"), (r.Status, r.Result), $"now {now} accepted");
            else Eq((400, "timestamp_out_of_tolerance"), (r.Status, r.Error), $"now {now} refused");
        }
    }

    /// <summary>
    /// A header with two v1 values is accepted when the second is right, also with a v0 element and spaces after the
    /// commas. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // STRIPEWH-05
    public static void TestTwoV1Values()
    {
        var good = StripeWebhookEntitlements.SignPayload(Body, Secret, 1700000000);
        var v1 = good.Substring(good.IndexOf("v1=") + 3);
        var wrong = new string('0', 64);
        var rig = new Rig();
        var r = rig.Sys.HandleWebhook(Body, "t=1700000000, v1=" + wrong + ", v0=" + wrong + ", v1=" + v1);
        Eq((200, "applied"), (r.Status, r.Result), "the second v1 is right");
        var rig2 = new Rig();
        Eq(200, rig2.Sys.HandleWebhook(Body, "t=1700000000,v1=" + wrong + ",v1=" + v1).Status, "without spaces too");
    }

    /// <summary>
    /// Correctly signed bodies that are not JSON, not an object, or lack an evt_ id, a type, a whole-number created or
    /// data.object are 400 invalid_payload and not recorded; created true, "1700000000", 1700000000.5, -1, 100000000000
    /// and 1e400 too; created 1700000000.0 is accepted. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    /// </summary>
    // STRIPEWH-06
    public static void TestInvalidPayloads()
    {
        var rig = new Rig();
        var obj = Sub("sub_p1");
        var serial = 0;
        // A signed-body template with this created value and a fresh event id. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        string WithCreated(string c) => $"{{\"id\":\"evt_p_{serial++}\",\"type\":\"customer.subscription.updated\",\"created\":{c},\"data\":{{\"object\":{obj}}}}}";
        var bad = new List<(string Name, string Body)>
        {
            ("not JSON", "this is not json"),
            ("not an object", "[1,2,3]"),
            ("no evt_ id", Evt("abc_1", "customer.subscription.updated", 1700000000, obj)),
            ("no id", $"{{\"type\":\"customer.subscription.updated\",\"created\":1700000000,\"data\":{{\"object\":{obj}}}}}"),
            ("no type", $"{{\"id\":\"evt_nt\",\"created\":1700000000,\"data\":{{\"object\":{obj}}}}}"),
            ("no created", $"{{\"id\":\"evt_nc\",\"type\":\"x\",\"data\":{{\"object\":{obj}}}}}"),
            ("no data.object", "{\"id\":\"evt_nd\",\"type\":\"x\",\"created\":1700000000,\"data\":{}}"),
            ("data.object not an object", "{\"id\":\"evt_no\",\"type\":\"x\",\"created\":1700000000,\"data\":{\"object\":\"sub\"}}"),
            ("created true", WithCreated("true")),
            ("created a text", WithCreated("\"1700000000\"")),
            ("created 1700000000.5", WithCreated("1700000000.5")),
            ("created -1", WithCreated("-1")),
            ("created 100000000000", WithCreated("100000000000")),
            ("created 1e400", WithCreated("1e400")),
            ("created null", WithCreated("null")),
            ("a byte-order mark", "﻿" + Evt("evt_bom", "customer.subscription.updated", 1700000000, obj)),
        };
        foreach (var (name, body) in bad)
        {
            var r = rig.Send(body);
            Eq((400, "invalid_payload"), (r.Status, r.Error), name);
        }
        Eq(0, rig.Store.EventCount, "no id recorded");
        var whole = rig.Send(WithCreated("1700000000.0").Replace("evt_p_", "evt_whole_"));
        Eq((200, "applied"), (whole.Status, whole.Result), "created 1700000000.0 is accepted");
        Eq(1, rig.Store.EventCount, "that one is recorded");
        var invalidUtf8 = Encoding.UTF8.GetBytes(Evt("evt_u8", "x", 1700000000, obj)).Concat(new byte[] { 0xFF }).ToArray();
        var u = rig.Sys.HandleWebhook(invalidUtf8, StripeWebhookEntitlements.SignPayload(invalidUtf8, Secret, rig.Now));
        Eq((400, "invalid_payload"), (u.Status, u.Error), "invalid UTF-8");
    }

    /// <summary>
    /// STRIPEWH-06 (spec db20a03, Phase B.4): a correctly signed, otherwise valid body holding "x": 1e400 (a non-finite
    /// number outside any TIME field), at the top level or inside data.object, is 400 invalid_payload and no event is
    /// recorded; the same body without it is applied. In: none. Out: throws on a wrong answer. Why: STRIPEWH-06 as
    /// amended by db20a03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    /// </summary>
    // STRIPEWH-06
    public static void TestNonFiniteNumberAnywhere()
    {
        var rig = new Rig();
        var good = Evt("evt_inf", "customer.subscription.created", 1700000000, Sub("sub_inf"));
        var nested = good.Replace("\"object\":{", "\"object\":{\"x\":1e400,");
        Eq(true, nested != good, "the nested body differs");
        foreach (var (name, body) in new[] { ("top level", "{\"x\":1e400," + good.Substring(1)), ("in data.object", nested) })
        {
            var r = rig.Send(body);
            Eq((400, "invalid_payload"), (r.Status, r.Error), "1e400 " + name);
        }
        Eq(0, rig.Store.EventCount, "no event recorded");
        var ok = rig.Send(good);
        Eq((200, "applied"), (ok.Status, ok.Result), "the same body without it is applied");
    }

    /// <summary>
    /// customer.subscription.created (active, known price, metadata.user_id) gives the entitled answer; before it the
    /// user's answer is "none"; another user's answer is unchanged. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: process memory.
    /// </summary>
    // STRIPEWH-07
    public static void TestCreatedGrantsEntitlement()
    {
        var rig = new Rig();
        Eq(Show(new Entitlement { Entitled = false, Plan = null, Status = "none", CurrentPeriodEnd = null, CancelAtPeriodEnd = false }), Show(rig.Sys.GetEntitlement("user_1")), "the none answer");
        rig.Send(Evt("evt_u2", "customer.subscription.created", 1699990000, Sub("sub_u2", price: "price_team", user: "user_2", customer: "cus_2")));
        var other = Show(rig.Sys.GetEntitlement("user_2"));
        var r = rig.Send(Evt("evt_c1", "customer.subscription.created", 1700000000, Sub("sub_c1", cpe: 1702592000, cancel: true)));
        Eq("applied", r.Result, "applied");
        var e = rig.Sys.GetEntitlement("user_1");
        Eq((true, "pro", "active", (long?)1702592000, true), (e.Entitled, e.Plan, e.Status, e.CurrentPeriodEnd, e.CancelAtPeriodEnd), "entitled");
        Eq(other, Show(rig.Sys.GetEntitlement("user_2")), "another user's answer is unchanged");
        Check(rig.Sys.GetEntitlement("user_2").Entitled, "user_2 still has team");
    }

    /// <summary>The same event id twice: the second is 200 duplicate and the row is unchanged. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.</summary>
    // STRIPEWH-08
    public static void TestDuplicate()
    {
        var rig = new Rig();
        Eq("applied", rig.Sys.HandleWebhook(Body, StripeWebhookEntitlements.SignPayload(Body, Secret, rig.Now)).Result, "first delivery");
        var before = JsonSerializer.Serialize(rig.Store.AllSubscriptions());
        rig.Now += 100;
        var second = rig.Sys.HandleWebhook(Body, StripeWebhookEntitlements.SignPayload(Body, Secret, rig.Now));
        Eq((200, true, "duplicate"), (second.Status, second.Received, second.Result), "second delivery");
        Eq(before, JsonSerializer.Serialize(rig.Store.AllSubscriptions()), "row unchanged");
        Eq(1, rig.Store.EventCount, "one event row");
    }

    /// <summary>
    /// Out of order: after created-at-200, an event at 100 is stale; at an equal time a created event does not overwrite
    /// an updated one, a deleted one overwrites both; a second updated event at the stored time fetches the subscription
    /// and the row ends with the fetched state, its price and plan included (rule d as ruled in fed6e7b). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // STRIPEWH-09
    public static void TestOutOfOrder()
    {
        var rig = new Rig();
        Eq("applied", rig.Send(Evt("evt_o1", "customer.subscription.updated", 200, Sub("sub_o", cpe: 1800000000))).Result, "updated at 200");
        Eq("stale", rig.Send(Evt("evt_o2", "customer.subscription.updated", 100, Sub("sub_o", status: "canceled"))).Result, "updated at 100 is stale");
        Eq("stale", rig.Send(Evt("evt_o3", "customer.subscription.created", 200, Sub("sub_o", status: "incomplete"))).Result, "created at 200 does not overwrite updated at 200");
        Eq("active", rig.Store.AllSubscriptions().Single().Status, "unchanged");
        Eq(0, rig.Stripe.Calls.Count, "no fetch yet");

        rig.Stripe.Objects["sub_o"] = Sub("sub_o", status: "past_due", cpe: 1800000500, price: "price_team");
        Eq("applied", rig.Send(Evt("evt_o4", "customer.subscription.updated", 200, Sub("sub_o", status: "active"))).Result, "a second updated at 200");
        Eq("sub_o", string.Join(",", rig.Stripe.Calls), "it fetched the subscription");
        var row = rig.Store.AllSubscriptions().Single();
        Eq(("past_due", 1800000500L), (row.Status, row.CurrentPeriodEnd), "the row has the fetched state");
        // spec fed6e7b (rule d): rule b runs again on the fetched object, so the row has Stripe's current price and plan
        Eq(("price_team", "team"), (row.PriceId, row.Plan), "price and plan re-derived from the fetched subscription");

        Eq("applied", rig.Send(Evt("evt_o5", "customer.subscription.deleted", 200, Sub("sub_o", status: "active"))).Result, "deleted at 200 overwrites");
        Eq("canceled", rig.Store.AllSubscriptions().Single().Status, "canceled");
        Eq("stale", rig.Send(Evt("evt_o6", "customer.subscription.updated", 200, Sub("sub_o"))).Result, "updated at 200 after deleted");
        Eq("stale", rig.Send(Evt("evt_o7", "customer.subscription.created", 200, Sub("sub_o"))).Result, "created at 200 after deleted");
        Eq(1, rig.Stripe.Calls.Count, "no further fetch");
        Eq("canceled", rig.Store.AllSubscriptions().Single().Status, "still canceled");
    }

    /// <summary>
    /// The entitlement ends at once for past_due, unpaid and canceled, and for active when current_period_end &lt;= now
    /// (equal: not entitled; one second later: entitled); with period_grace_seconds 60 it lasts 60 s longer. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // STRIPEWH-10
    public static void TestEntitlementEnds()
    {
        var created = 1699990000L;
        foreach (var status in new[] { "past_due", "unpaid", "canceled" })
        {
            var rig = new Rig();
            rig.Send(Evt("evt_a", "customer.subscription.created", created, Sub("sub_e", cpe: 1800000000)));
            Check(rig.Sys.GetEntitlement("user_1").Entitled, "entitled before");
            rig.Send(Evt("evt_b", "customer.subscription.updated", created + 1, Sub("sub_e", status: status, cpe: 1800000000)));
            var e = rig.Sys.GetEntitlement("user_1");
            Eq((false, (string)null, status), (e.Entitled, e.Plan, e.Status), status + " ends it at once");
        }
        var rig2 = new Rig();
        rig2.Send(Evt("evt_t", "customer.subscription.created", created, Sub("sub_t", status: "trialing", cpe: 1700000001)));
        Check(rig2.Sys.GetEntitlement("user_1").Entitled, "trialing, period end one second after now: entitled");
        rig2.Now = 1700000001;
        Check(!rig2.Sys.GetEntitlement("user_1").Entitled, "period end equal to now: not entitled");
        Eq("trialing", rig2.Sys.GetEntitlement("user_1").Status, "the answer keeps the status");
        var graced = rig2.Build(grace: 60);
        Check(graced.GetEntitlement("user_1").Entitled, "with 60 s of grace still entitled");
        rig2.Now = 1700000060;
        Check(graced.GetEntitlement("user_1").Entitled, "59 s after the period end");
        rig2.Now = 1700000061;
        Check(!graced.GetEntitlement("user_1").Entitled, "60 s after the period end");
    }

    /// <summary>
    /// The period end is the top-level current_period_end, else the largest items.data[].current_period_end; an event
    /// with neither keeps the stored period end. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // STRIPEWH-11
    public static void TestPeriodEnd()
    {
        var rig = new Rig();
        rig.Send(Evt("evt_p1", "customer.subscription.created", 100, Sub("sub_p", cpe: 1800000000)));
        Eq(1800000000L, rig.Store.AllSubscriptions().Single().CurrentPeriodEnd, "top level");
        var items = "\"items\":{\"data\":[{\"price\":{\"id\":\"price_pro_monthly\"},\"current_period_end\":1810000000},{\"price\":{\"id\":\"x\"},\"current_period_end\":1820000000},{\"current_period_end\":\"1900000000\"}]}";
        rig.Send(Evt("evt_p2", "customer.subscription.updated", 200, Sub("sub_p", cpe: null, items: items)));
        Eq(1820000000L, rig.Store.AllSubscriptions().Single().CurrentPeriodEnd, "the largest item's");
        Eq("pro", rig.Store.AllSubscriptions().Single().Plan, "price from items.data[0]");
        rig.Send(Evt("evt_p3", "customer.subscription.updated", 300, Sub("sub_p", status: "past_due", cpe: null)));
        var row = rig.Store.AllSubscriptions().Single();
        Eq((1820000000L, "past_due"), (row.CurrentPeriodEnd, row.Status), "neither: the stored period end is kept");
        var both = "\"items\":{\"data\":[{\"price\":{\"id\":\"price_pro_monthly\"},\"current_period_end\":1999999999}]}";
        rig.Send(Evt("evt_p4", "customer.subscription.updated", 400, Sub("sub_p", cpe: 1830000000, items: both)));
        Eq(1830000000L, rig.Store.AllSubscriptions().Single().CurrentPeriodEnd, "the top level wins over items");
    }

    /// <summary>
    /// 200 ignored, with no change and the event id recorded, for an unknown price on a new subscription, a user that
    /// does not exist, an unhandled type and a malformed subscription id; a deleted event for a stored subscription whose
    /// price left price_plans is applied; an updated event to a price outside price_plans is applied and ends the
    /// entitlement. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // STRIPEWH-12
    public static void TestIgnored()
    {
        var rig = new Rig();
        var cases = new List<(string Id, string Body)>
        {
            ("evt_i1", Evt("evt_i1", "customer.subscription.created", 100, Sub("sub_i1", price: "price_unknown"))),
            ("evt_i2", Evt("evt_i2", "customer.subscription.created", 100, Sub("sub_i2", user: "ghost", customer: "cus_ghost"))),
            ("evt_i3", Evt("evt_i3", "invoice.paid", 100, "{\"id\":\"in_1\"}")),
            ("evt_i4", Evt("evt_i4", "customer.subscription.created", 100, Sub("sub-bad!"))),
            ("evt_i5", Evt("evt_i5", "customer.subscription.created", 100, Sub("sub_i5", price: null))),
        };
        foreach (var (id, body) in cases)
        {
            var r = rig.Send(body);
            Eq((200, "ignored"), (r.Status, r.Result), id);
            Eq("ignored", rig.Store.GetEvent(id)?.Result, id + " is recorded");
        }
        Eq(0, rig.Store.AllSubscriptions().Count, "no row");
        Eq("none", rig.Sys.GetEntitlement("user_1").Status, "no entitlement");

        rig.Send(Evt("evt_k1", "customer.subscription.created", 100, Sub("sub_k", price: "price_team", cpe: 1800000000)));
        Check(rig.Sys.GetEntitlement("user_1").Entitled, "team granted");
        var moved = rig.Send(Evt("evt_k2", "customer.subscription.updated", 200, Sub("sub_k", price: "price_gone", cpe: 1800000000)));
        Eq("applied", moved.Result, "an updated event to an unknown price is applied");
        var e = rig.Sys.GetEntitlement("user_1");
        Eq((false, "active"), (e.Entitled, e.Status), "the user is no longer entitled");
        Eq("price_gone", rig.Store.AllSubscriptions().Single().PriceId, "the row records the new price");

        var rig2 = new Rig();
        rig2.Send(Evt("evt_d1", "customer.subscription.created", 100, Sub("sub_d", price: "price_team", cpe: 1800000000)));
        var noPlans = rig2.Build(plans: new Dictionary<string, string> { ["price_pro_monthly"] = "pro" });
        var del = noPlans.HandleWebhook(Evt("evt_d2", "customer.subscription.deleted", 200, Sub("sub_d", price: "price_team")),
            StripeWebhookEntitlements.SignPayload(Evt("evt_d2", "customer.subscription.deleted", 200, Sub("sub_d", price: "price_team")), Secret, rig2.Now));
        Eq("applied", del.Result, "deleted is applied though its price left price_plans");
        var row = rig2.Store.AllSubscriptions().Single();
        Eq(("canceled", "team"), (row.Status, row.Plan), "canceled; the row kept its plan");
        Check(!noPlans.GetEntitlement("user_1").Entitled, "not entitled");
    }

    /// <summary>
    /// checkout.session.completed fetches the subscription by the session's id and takes client_reference_id as the
    /// user; when the client raises the answer is 500 processing_failed, the id is not recorded, and the same event
    /// delivered again is applied. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // STRIPEWH-13
    public static void TestCheckoutSession()
    {
        var rig = new Rig();
        rig.Stripe.Objects["sub_cs"] = Sub("sub_cs", user: null, customer: "cus_cs", cpe: 1800000000);
        var session = "{\"id\":\"cs_1\",\"mode\":\"subscription\",\"subscription\":\"sub_cs\",\"client_reference_id\":\"user_3\",\"metadata\":{\"user_id\":\"user_2\"}}";
        var body = Evt("evt_cs", "checkout.session.completed", 1700000000, session);
        rig.Stripe.Throw = true;
        var failed = rig.Send(body);
        Eq((500, "processing_failed"), (failed.Status, failed.Error), "the client raises");
        Eq(null, rig.Store.GetEvent("evt_cs"), "the event id is not recorded");
        Eq(0, rig.Store.AllSubscriptions().Count, "nothing written");
        rig.Stripe.Throw = false;
        var again = rig.Send(body);
        Eq((200, "applied"), (again.Status, again.Result), "delivered again: applied");
        Eq("sub_cs,sub_cs", string.Join(",", rig.Stripe.Calls), "fetched by the session's subscription id");
        Eq("user_3", rig.Store.AllSubscriptions().Single().UserId, "the user is client_reference_id");
        Check(rig.Sys.GetEntitlement("user_3").Entitled, "user_3 is entitled");
        Check(!rig.Sys.GetEntitlement("user_2").Entitled, "metadata.user_id was not used");

        var payment = Evt("evt_pay", "checkout.session.completed", 1700000000, "{\"id\":\"cs_2\",\"mode\":\"payment\",\"subscription\":null}");
        Eq("ignored", rig.Send(payment).Result, "a payment-mode session is ignored");
        var store = new Rig();
        store.Store.FailNextWrite = true;
        var storeFail = store.Send(Body);
        Eq((500, "processing_failed"), (storeFail.Status, storeFail.Error), "a store failure is 500 too");
        Eq(0, store.Store.EventCount, "and the event is not recorded");
    }

    /// <summary>
    /// One user with two subscriptions: ending one leaves the other's entitlement; an event without metadata finds its
    /// user through the stored subscription or the customer id; an event naming another user never moves a
    /// subscription. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    // STRIPEWH-14
    public static void TestTwoSubscriptionsAndUserLookup()
    {
        var rig = new Rig();
        rig.Send(Evt("evt_s1", "customer.subscription.created", 100, Sub("sub_one", price: "price_team", cpe: 1800000000, customer: "cus_x")));
        rig.Send(Evt("evt_s2", "customer.subscription.created", 101, Sub("sub_two", price: "price_pro_monthly", cpe: 1900000000, customer: "cus_x")));
        Eq("pro", rig.Sys.GetEntitlement("user_1").Plan, "the later period end wins");
        rig.Send(Evt("evt_s3", "customer.subscription.deleted", 200, Sub("sub_two", user: null, customer: "cus_x")));
        var e = rig.Sys.GetEntitlement("user_1");
        Eq((true, "team", (long?)1800000000), (e.Entitled, e.Plan, e.CurrentPeriodEnd), "ending one leaves the other");

        Eq("applied", rig.Send(Evt("evt_s4", "customer.subscription.updated", 300, Sub("sub_one", price: "price_team", user: null, customer: "cus_x", cancel: true))).Result, "no metadata: the stored row's user");
        Eq(("user_1", true), (rig.Store.GetSubscription("sub_one").UserId, rig.Store.GetSubscription("sub_one").CancelAtPeriodEnd), "same user");
        Eq("applied", rig.Send(Evt("evt_s5", "customer.subscription.created", 400, Sub("sub_three", user: null, customer: "cus_x"))).Result, "no metadata, new subscription: the customer's user");
        Eq("user_1", rig.Store.GetSubscription("sub_three").UserId, "found through the customer id");
        Eq("applied", rig.Send(Evt("evt_s6", "customer.subscription.updated", 500, Sub("sub_one", price: "price_team", user: "user_2", customer: "cus_x"))).Result, "an event naming another user");
        Eq("user_1", rig.Store.GetSubscription("sub_one").UserId, "never moves the subscription");
        Check(!rig.Sys.GetEntitlement("user_2").Entitled, "user_2 gains nothing");
        Eq("ignored", rig.Send(Evt("evt_s7", "customer.subscription.created", 600, Sub("sub_four", user: null, customer: "cus_unknown"))).Result, "no metadata and an unknown customer");
    }
}

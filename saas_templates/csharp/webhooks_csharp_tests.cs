using System;
using System.Collections.Generic;
using System.Text.Json;
using AOI.Webhooks;

public static class Tests
{
    private static int _failures = 0;

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            Console.WriteLine("FAIL: " + message);
            _failures++;
        }
    }

    // 1. sign then verify round‑trip
    // HOOK-01
    public static void TestSignVerifyRoundTrip()
    {
        var ep = WebhookService.CreateEndpoint("org1", "https://example.com/hook", new[] { "order.created" });
        var payload = JsonDocument.Parse("{\"id\":123}").RootElement;
        var msg = WebhookService.SendEvent("org1", "order.created", payload);
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var sig = WebhookService.Sign(ep.Secret, msg.Id, timestamp, msg.Payload);
        var headers = new Dictionary<string, string>
        {
            { "webhook-id", msg.Id },
            { "webhook-timestamp", timestamp.ToString() },
            { "webhook-signature", sig }
        };
        var ok = WebhookService.Verify(ep.Secret, headers, msg.Payload);
        Assert(ok, "Sign/Verify round‑trip should succeed");
    }

    // 2. changed body fails verify
    // HOOK-02
    public static void TestChangedBodyFails()
    {
        var ep = WebhookService.CreateEndpoint("org2", "https://example.com/hook2", new[] { "order.updated" });
        var payload = JsonDocument.Parse("{\"status\":\"new\"}").RootElement;
        var msg = WebhookService.SendEvent("org2", "order.updated", payload);
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var sig = WebhookService.Sign(ep.Secret, msg.Id, timestamp, msg.Payload);
        var headers = new Dictionary<string, string>
        {
            { "webhook-id", msg.Id },
            { "webhook-timestamp", timestamp.ToString() },
            { "webhook-signature", sig }
        };
        var alteredBody = "{\"status\":\"old\"}";
        var ok = WebhookService.Verify(ep.Secret, headers, alteredBody);
        Assert(!ok, "Verification must fail when body is altered");
    }

    // 3. changed timestamp fails verify
    // HOOK-02
    public static void TestChangedTimestampFails()
    {
        var ep = WebhookService.CreateEndpoint("org3", "https://example.com/hook3", new[] { "order.deleted" });
        var payload = JsonDocument.Parse("{\"id\":9}").RootElement;
        var msg = WebhookService.SendEvent("org3", "order.deleted", payload);
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var sig = WebhookService.Sign(ep.Secret, msg.Id, timestamp, msg.Payload);
        var badTs = timestamp + 1000; // different timestamp
        var headers = new Dictionary<string, string>
        {
            { "webhook-id", msg.Id },
            { "webhook-timestamp", badTs.ToString() },
            { "webhook-signature", sig }
        };
        var ok = WebhookService.Verify(ep.Secret, headers, msg.Payload);
        Assert(!ok, "Verification must fail when timestamp is altered");
    }

    // 4. timestamp older than tolerance rejected
    // HOOK-03
    public static void TestTimestampTolerance()
    {
        var ep = WebhookService.CreateEndpoint("org4", "https://example.com/hook4", new[] { "order.created" });
        var payload = JsonDocument.Parse("{\"id\":1}").RootElement;
        var msg = WebhookService.SendEvent("org4", "order.created", payload);
        var oldTs = DateTimeOffset.UtcNow.AddSeconds(-400).ToUnixTimeSeconds(); // tolerance 300
        var sig = WebhookService.Sign(ep.Secret, msg.Id, oldTs, msg.Payload);
        var headers = new Dictionary<string, string>
        {
            { "webhook-id", msg.Id },
            { "webhook-timestamp", oldTs.ToString() },
            { "webhook-signature", sig }
        };
        var ok = WebhookService.Verify(ep.Secret, headers, msg.Payload);
        Assert(!ok, "Verification must reject timestamps outside tolerance");
    }

    // 5. multiple signatures – one matches
    // HOOK-04
    public static void TestMultipleSignatures()
    {
        var ep = WebhookService.CreateEndpoint("org5", "https://example.com/hook5", new[] { "order.created" });
        var payload = JsonDocument.Parse("{\"id\":2}").RootElement;
        var msg = WebhookService.SendEvent("org5", "order.created", payload);
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var goodSig = WebhookService.Sign(ep.Secret, msg.Id, ts, msg.Payload);
        var bogusSig = "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        var combined = $"{goodSig} {bogusSig}";
        var headers = new Dictionary<string, string>
        {
            { "webhook-id", msg.Id },
            { "webhook-timestamp", ts.ToString() },
            { "webhook-signature", combined }
        };
        var ok = WebhookService.Verify(ep.Secret, headers, msg.Payload);
        Assert(ok, "Verification should succeed when at least one signature matches");
        // a malformed entry (no "v1," prefix) is skipped, never an exception (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
        headers["webhook-signature"] = "garbage " + goodSig;
        Assert(WebhookService.Verify(ep.Secret, headers, msg.Payload), "a malformed entry before a good one is skipped");
        headers["webhook-signature"] = "garbage";
        Assert(!WebhookService.Verify(ep.Secret, headers, msg.Payload), "only malformed entries fail without throwing");
    }

    // 6. delivery success/failure handling
    // HOOK-05
    public static void TestDeliverySuccessAndRetry()
    {
        var ep = WebhookService.CreateEndpoint("org6", "https://example.com/hook6", new[] { "order.created" });
        var payload = JsonDocument.Parse("{\"id\":3}").RootElement;
        var msg = WebhookService.SendEvent("org6", "order.created", payload);
        var delivery = WebhookService.Store.GetPendingDeliveries(DateTimeOffset.UtcNow).First();

        // success case (200)
        WebhookService.Deliver(delivery, (url, hdr, body) => (200, "ok"));
        var d1 = WebhookService.Store.GetDelivery(delivery.Id);
        Assert(d1.Success && d1.StatusCode == 200, "200 response should mark delivery as success");

        // failure case (301) – create a new delivery for same message
        var delivery2 = WebhookService.Store.AddDelivery(msg.Id, ep.Id);
        WebhookService.Deliver(delivery2, (url, hdr, body) => (301, "moved"));
        var d2 = WebhookService.Store.GetDelivery(delivery2.Id);
        Assert(!d2.Success && d2.StatusCode == 301 && d2.NextAttemptAt != null,
            "301 response should schedule a retry");

        // 299 is still success; 400 and 500 schedule a retry (HOOK-05 names all of these; added 2026-11-10,
        // session_012zDydZCZ4AChqhEZ4oVtaP, because the test only covered 200 and 301)
        var d299 = WebhookService.Store.AddDelivery(msg.Id, ep.Id);
        WebhookService.Deliver(d299, (url, hdr, body) => (299, "ok"));
        Assert(WebhookService.Store.GetDelivery(d299.Id).Success, "299 response should mark delivery as success");
        foreach (var code in new[] { 400, 500 })
        {
            var d = WebhookService.Store.AddDelivery(msg.Id, ep.Id);
            WebhookService.Deliver(d, (url, hdr, body) => (code, "no"));
            var got = WebhookService.Store.GetDelivery(d.Id);
            Assert(!got.Success && got.StatusCode == code && got.NextAttemptAt != null,
                $"{code} response should schedule a retry");
        }
    }

    // 7. org isolation
    // HOOK-06
    public static void TestOrgIsolation()
    {
        var epA = WebhookService.CreateEndpoint("orgA", "https://example.com/hookA", new[] { "order.created" });
        var epB = WebhookService.CreateEndpoint("orgB", "https://example.com/hookB", new[] { "order.created" });
        var payload = JsonDocument.Parse("{\"id\":4}").RootElement;
        WebhookService.SendEvent("orgA", "order.created", payload);
        var pending = WebhookService.Store.GetPendingDeliveries(DateTimeOffset.UtcNow);
        var forB = pending.Any(d => d.EndpointId == epB.Id);
        Assert(!forB, "Endpoint of orgB must not receive events from orgA");
        Assert(pending.Any(d => d.EndpointId == epA.Id), "Endpoint of orgA must get the event");
    }

    // 8. webhook‑id identical across retries
    // HOOK-07
    public static void TestWebhookIdAcrossRetries()
    {
        var ep = WebhookService.CreateEndpoint("org8", "https://example.com/hook8", new[] { "order.created" });
        var payload = JsonDocument.Parse("{\"id\":5}").RootElement;
        var msg = WebhookService.SendEvent("org8", "order.created", payload);
        var delivery = WebhookService.Store.AddDelivery(msg.Id, ep.Id);
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: compare the webhook-id HEADER each attempt sent,
        // not only the stored message id, so the test proves what the receiver sees.
        var sentIds = new List<string>();
        // first attempt fails
        WebhookService.Deliver(delivery, (url, hdr, body) => { sentIds.Add(hdr["webhook-id"]); return (500, "error"); });
        var first = WebhookService.Store.GetDelivery(delivery.Id);
        // second attempt (retry)
        WebhookService.Deliver(first, (url, hdr, body) => { sentIds.Add(hdr["webhook-id"]); return (200, "ok"); });
        var second = WebhookService.Store.GetDelivery(first.Id);
        Assert(first.MessageId == second.MessageId, "webhook-id must stay the same across retries");
        Assert(sentIds.Count == 2 && sentIds[0] == msg.Id && sentIds[1] == msg.Id,
            "the webhook-id header must be the message id on every attempt");
    }

    /// <summary>
    /// The retry schedule ends and only fully-failed messages count toward disabling an endpoint.
    /// In/out: none; asserts on the shared store. Why: webhooks spec "Retry with exponential backoff: after 5s,
    /// 5m, 30m, 2h, 5h, 10h, 10h. Disable an endpoint after 5 consecutive fully-failed messages"; before
    /// 2026-11-10 the C# version retried forever and disabled after 5 failed attempts of any message.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory webhook store only.
    /// </summary>
    public static void TestEndpointDisabledAfterFiveFullyFailedMessages()
    {
        var ep = WebhookService.CreateEndpoint("org10", "https://example.com/hook10", new[] { "order.created" });
        var payload = JsonDocument.Parse("{\"id\":10}").RootElement;
        for (var m = 1; m <= 5; m++)
        {
            var msg = WebhookService.SendEvent("org10", "order.created", payload);
            var d = WebhookService.Store.AddDelivery(msg.Id, ep.Id);
            for (var attempt = 1; attempt <= 8; attempt++)
            {
                WebhookService.Deliver(d, (url, hdr, body) => (500, "error"));
                d = WebhookService.Store.GetDelivery(d.Id);
                if (attempt < 8)
                    Assert(d.NextAttemptAt != null && !d.RetriesExhausted, $"attempt {attempt} must schedule a retry");
                if (m == 1 && attempt == 7)
                    Assert(WebhookService.Store.GetEndpoint(ep.Id).Active, "retries of one message must not disable the endpoint");
            }
            Assert(d.RetriesExhausted && d.NextAttemptAt == null, "after the 7th retry fails the message has fully failed");
            Assert(!WebhookService.Store.GetPendingDeliveries(DateTimeOffset.UtcNow.AddDays(30)).Any(x => x.Id == d.Id),
                "a fully-failed delivery is never pending again");
            Assert(WebhookService.Store.GetEndpoint(ep.Id).Active == (m < 5), $"endpoint active after {m} fully-failed messages");
        }
    }

    // 9. secret format and length
    // HOOK-08
    public static void TestSecretGeneration()
    {
        var ep = WebhookService.CreateEndpoint("org9", "https://example.com/hook9", new[] { "order.created" });
        Assert(ep.Secret.StartsWith("whsec_"), "Secret must start with whsec_");
        var b64 = ep.Secret.Substring("whsec_".Length);
        var bytes = Convert.FromBase64String(b64);
        Assert(bytes.Length >= 24 && bytes.Length <= 64,
            $"Secret bytes length must be 24‑64, got {bytes.Length}");
    }

    // ---------- Runner ----------
    public static int Main()
    {
        var tests = new Action[]
        {
            TestSignVerifyRoundTrip,
            TestChangedBodyFails,
            TestChangedTimestampFails,
            TestTimestampTolerance,
            TestMultipleSignatures,
            TestDeliverySuccessAndRetry,
            TestOrgIsolation,
            TestWebhookIdAcrossRetries,
            TestSecretGeneration,
            TestEndpointDisabledAfterFiveFullyFailedMessages
        };

        foreach (var t in tests)
        {
            try
            {
                t();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"EXCEPTION in {t.Method.Name}: {ex}");
                _failures++;
            }
        }

        if (_failures == 0)
        {
            Console.WriteLine("ALL TESTS PASSED");
            return 0;
        }
        else
        {
            Console.WriteLine($"{_failures} TEST(S) FAILED");
            return 1;
        }
    }
}
import java.util.*;
import java.time.Instant;
import java.util.Base64;

public class webhooks_java_tests {
    public static void main(String[] args) {
        try {
            testSignVerifyRoundTrip();
            testChangedBodyFailsVerify();
            testChangedTimestampFailsVerify();
            testTimestampOlderThanTolerance();
            testSpaceSeparatedSignatures();
            testDeliverySuccessAndRetry();
            testWebhookIdAcrossRetries();
            testEventForOrgANeverReachesOrgB();
            testGeneratedSecretFormat();
            System.out.println("All tests passed");
        } catch (Throwable e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    /* ---------- Test Helpers ---------- */

    /**
     * Fails the test with msg unless cond holds. Why: the tests used Java `assert`, which the runner never enables
     * (no -ea), so no assertion ran; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static void check(boolean cond, String msg) {
        if (!cond) {
            throw new AssertionError(msg);
        }
    }

    private static Webhooks createWebhooksWithFakeSender() {
        Webhooks.InMemoryStorage storage = new Webhooks.InMemoryStorage();
        Webhooks.Sender fakeSender = new Webhooks.Sender() {
            @Override
            public int send(String url, Map<String, String> headers, String body) throws Exception {
                return 200;
            }
        };
        return new Webhooks(storage, fakeSender);
    }

    /* ---------- Tests ---------- */

    // HOOK-01
    private static void testSignVerifyRoundTrip() {
        Webhooks webhooks = createWebhooksWithFakeSender();
        Map<String, String> ep = webhooks.createEndpoint("org1", "https://example.com/webhook", Arrays.asList("order.created"));
        String secret = ep.get("secret");
        String msgId = "msg_abcdef";
        long ts = Instant.now().getEpochSecond();
        String body = "{\"order_id\":123}";
        String signature = webhooks.sign(secret, msgId, ts, body);
        Map<String, String> headers = new HashMap<>();
        headers.put("webhook-id", msgId);
        headers.put("webhook-timestamp", Long.toString(ts));
        headers.put("webhook-signature", signature);
        boolean ok = webhooks.verify(secret, headers, body, 300);
        check(ok, "Sign/verify round-trip failed");
    }

    // HOOK-02
    private static void testChangedBodyFailsVerify() {
        Webhooks webhooks = createWebhooksWithFakeSender();
        Map<String, String> ep = webhooks.createEndpoint("org1", "https://example.com/webhook", Arrays.asList("order.created"));
        String secret = ep.get("secret");
        String msgId = "msg_abcdef";
        long ts = Instant.now().getEpochSecond();
        String body = "{\"order_id\":123}";
        String signature = webhooks.sign(secret, msgId, ts, body);
        Map<String, String> headers = new HashMap<>();
        headers.put("webhook-id", msgId);
        headers.put("webhook-timestamp", Long.toString(ts));
        headers.put("webhook-signature", signature);
        boolean ok = webhooks.verify(secret, headers, body + "x", 300);
        check(!ok, "Changed body should fail verification");
    }

    // HOOK-02
    private static void testChangedTimestampFailsVerify() {
        Webhooks webhooks = createWebhooksWithFakeSender();
        Map<String, String> ep = webhooks.createEndpoint("org1", "https://example.com/webhook", Arrays.asList("order.created"));
        String secret = ep.get("secret");
        String msgId = "msg_abcdef";
        long ts = Instant.now().getEpochSecond();
        String body = "{\"order_id\":123}";
        String signature = webhooks.sign(secret, msgId, ts, body);
        Map<String, String> headers = new HashMap<>();
        headers.put("webhook-id", msgId);
        headers.put("webhook-timestamp", Long.toString(ts + 1000));
        headers.put("webhook-signature", signature);
        boolean ok = webhooks.verify(secret, headers, body, 300);
        check(!ok, "Changed timestamp should fail verification");
    }

    // HOOK-03
    private static void testTimestampOlderThanTolerance() {
        Webhooks webhooks = createWebhooksWithFakeSender();
        Map<String, String> ep = webhooks.createEndpoint("org1", "https://example.com/webhook", Arrays.asList("order.created"));
        String secret = ep.get("secret");
        String msgId = "msg_abcdef";
        long ts = Instant.now().getEpochSecond() - 1000;
        String body = "{\"order_id\":123}";
        String signature = webhooks.sign(secret, msgId, ts, body);
        Map<String, String> headers = new HashMap<>();
        headers.put("webhook-id", msgId);
        headers.put("webhook-timestamp", Long.toString(ts));
        headers.put("webhook-signature", signature);
        boolean ok = webhooks.verify(secret, headers, body, 300);
        check(!ok, "Timestamp older than tolerance should fail");
    }

    // HOOK-04
    private static void testSpaceSeparatedSignatures() {
        Webhooks webhooks = createWebhooksWithFakeSender();
        Map<String, String> ep1 = webhooks.createEndpoint("org1", "https://example.com/webhook1", Arrays.asList("order.created"));
        Map<String, String> ep2 = webhooks.createEndpoint("org1", "https://example.com/webhook2", Arrays.asList("order.created"));
        String secret1 = ep1.get("secret");
        String secret2 = ep2.get("secret");
        String msgId = "msg_abcdef";
        long ts = Instant.now().getEpochSecond();
        String body = "{\"order_id\":123}";
        String sig1 = webhooks.sign(secret1, msgId, ts, body);
        String sig2 = webhooks.sign(secret2, msgId, ts, body);
        Map<String, String> headers = new HashMap<>();
        headers.put("webhook-id", msgId);
        headers.put("webhook-timestamp", Long.toString(ts));
        headers.put("webhook-signature", sig1 + " " + sig2);
        boolean ok = webhooks.verify(secret1, headers, body, 300);
        check(ok, "Should accept if any signature matches");
    }

    // HOOK-05
    private static void testDeliverySuccessAndRetry() {
        Webhooks.InMemoryStorage storage = new Webhooks.InMemoryStorage();
        Webhooks.Sender fakeSender = new Webhooks.Sender() {
            private int callCount = 0;
            @Override
            public int send(String url, Map<String, String> headers, String body) throws Exception {
                callCount++;
                if (callCount == 1) return 400;
                if (callCount == 2) return 301;
                if (callCount == 3) return 500;
                return 200;
            }
        };
        Webhooks webhooks = new Webhooks(storage, fakeSender);
        Map<String, String> ep = webhooks.createEndpoint("org1", "https://example.com/webhook", Arrays.asList("order.created"));
        String msgId = webhooks.sendEvent("org1", "order.created", "{\"order_id\":123}");
        List<Webhooks.WebhookDelivery> deliveries = storage.listDeliveriesByMessage(msgId);
        check(deliveries.size() == 1, "One delivery should be created");
        Webhooks.WebhookDelivery delivery = deliveries.get(0);

        // First attempt: 400 -> failure, retry scheduled
        webhooks.deliver(delivery);
        check(!delivery.success, "First attempt (400) should fail");
        check(delivery.statusCode == 400, "Status code should be 400");
        check(delivery.nextAttemptAt != null, "Next attempt should be scheduled");

        // Second attempt: 301 -> failure, retry scheduled
        webhooks.deliver(delivery);
        check(!delivery.success, "Second attempt (301) should fail");
        check(delivery.statusCode == 301, "Status code should be 301");
        check(delivery.nextAttemptAt != null, "Next attempt should be scheduled");

        // Third attempt: 500 -> failure, retry scheduled
        webhooks.deliver(delivery);
        check(!delivery.success, "Third attempt (500) should fail");
        check(delivery.statusCode == 500, "Status code should be 500");
        check(delivery.nextAttemptAt != null, "Next attempt should be scheduled");

        // Fourth attempt: 200 -> success
        webhooks.deliver(delivery);
        check(delivery.success, "Fourth attempt (200) should succeed");
        check(delivery.statusCode == 200, "Status code should be 200");
        check(delivery.deliveredAt != null, "DeliveredAt should be set");
    }

    /**
     * HOOK-07: the webhook-id HEADER the receiver sees is the same message id on every retry of one message.
     * In/out: none; fails by throwing. Why: the earlier version only compared the delivery row's own id, which
     * never proved the header; rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only
     * (a recording fake sender, no network).
     */
    // HOOK-07
    private static void testWebhookIdAcrossRetries() {
        Webhooks.InMemoryStorage storage = new Webhooks.InMemoryStorage();
        List<String> seenIds = new ArrayList<>();
        int[] statuses = {500, 503, 200};
        Webhooks.Sender recording = (url, headers, body) -> {
            seenIds.add(headers.get("webhook-id"));
            return statuses[seenIds.size() - 1];
        };
        long[] now = {1_700_000_000L};
        Webhooks webhooks = new Webhooks(storage, recording, () -> now[0]);
        webhooks.createEndpoint("org1", "https://example.com/webhook", Arrays.asList("order.created"));
        String msgId = webhooks.sendEvent("org1", "order.created", "{\"order_id\":123}");
        Webhooks.WebhookDelivery delivery = storage.listDeliveriesByMessage(msgId).get(0);
        for (int i = 0; i < 3; i++) {
            webhooks.deliver(delivery);
            now[0] += 3600;
        }
        check(seenIds.size() == 3, "three attempts expected, got " + seenIds.size());
        for (String id : seenIds) {
            check(msgId.equals(id), "webhook-id must be the message id on every attempt, got " + id);
        }
        check(delivery.success, "third attempt (200) should succeed");
    }

    /**
     * HOOK-06: an event sent for org A creates no delivery for org B's endpoint subscribed to the same event type,
     * and org B's own event creates no delivery for org A. In/out: none; fails by throwing.
     * Why: spec amendment 2026-09-26 (events used to fan out to every tenant); added 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    // HOOK-06
    private static void testEventForOrgANeverReachesOrgB() {
        Webhooks.InMemoryStorage storage = new Webhooks.InMemoryStorage();
        Webhooks webhooks = new Webhooks(storage, (u, h, b) -> 200, () -> 1_700_000_000L);
        String epA = webhooks.createEndpoint("orgA", "https://a.example.com/hook", Arrays.asList("order.created")).get("id");
        String epB = webhooks.createEndpoint("orgB", "https://b.example.com/hook", Arrays.asList("order.created")).get("id");
        String msgA = webhooks.sendEvent("orgA", "order.created", "{}");
        List<Webhooks.WebhookDelivery> forA = storage.listDeliveriesByMessage(msgA);
        check(forA.size() == 1, "org A's event must create exactly one delivery, got " + forA.size());
        check(forA.get(0).endpointId.equals(epA), "org A's event must go to org A's endpoint only");
        String msgB = webhooks.sendEvent("orgB", "order.created", "{}");
        List<Webhooks.WebhookDelivery> forB = storage.listDeliveriesByMessage(msgB);
        check(forB.size() == 1 && forB.get(0).endpointId.equals(epB), "org B's event must go to org B's endpoint only");
    }

    // HOOK-08
    private static void testGeneratedSecretFormat() {
        Webhooks webhooks = createWebhooksWithFakeSender();
        Map<String, String> ep = webhooks.createEndpoint("org1", "https://example.com/webhook", Arrays.asList("order.created"));
        String secret = ep.get("secret");
        check(secret.startsWith("whsec_"), "Secret should start with whsec_");
        String b64 = secret.substring(6);
        byte[] decoded = Base64.getDecoder().decode(b64);
        check(decoded.length >= 24 && decoded.length <= 64, "Secret length should be 24-64 bytes, got " + decoded.length);
    }
}
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
            testSqlStorageRoundTrip();
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
    /**
     * SQLStorage keeps everything the in-memory store keeps: endpoints (with event types, secret rotation, failure count),
     * messages, and deliveries with their attempt, status, retry time and outcome, read back from the database by a
     * fresh lookup; listings are scoped by org and in insertion order, so org1's event never reaches org2 (HOOK-06).
     * Runs on in-memory H2 (the runner ships no SQLite driver; the store's SQL is portable to SQLite).
     * In/out: none; fails by throwing. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (java bug list: SQLStorage was a
     * stub that silently stored nothing). Touches: an in-memory H2 database only (fake sender, no network).
     */
    // HOOK-06
    private static void testSqlStorageRoundTrip() throws Exception {
        try (java.sql.Connection conn = java.sql.DriverManager.getConnection(
                "jdbc:h2:mem:webhooks_" + UUID.randomUUID().toString().replace("-", ""))) {
            Webhooks.SQLStorage storage = new Webhooks.SQLStorage(conn).createTables();
            int[] statuses = {500, 200};
            int[] calls = {0};
            Webhooks.Sender sender = (url, headers, body) -> statuses[calls[0]++];
            long[] now = {1_700_000_000L};
            Webhooks webhooks = new Webhooks(storage, sender, () -> now[0]);

            Map<String, String> a1 = webhooks.createEndpoint("org1", "https://a1.example.com/hook", Arrays.asList("order.created", "order.paid"));
            Map<String, String> a2 = webhooks.createEndpoint("org1", "https://a2.example.com/hook", Arrays.asList("order.created"));
            Map<String, String> b1 = webhooks.createEndpoint("org2", "https://b1.example.com/hook", Arrays.asList("order.created"));
            Webhooks.WebhookEndpoint stored = storage.getEndpoint(a1.get("id"));
            check(stored != null && "org1".equals(stored.orgId) && stored.secret.equals(a1.get("secret")), "endpoint read back");
            check(stored.eventTypes.equals(new HashSet<>(Arrays.asList("order.created", "order.paid"))), "event types read back");
            check(stored.active && stored.failureCount == 0 && stored.createdAt == now[0], "endpoint fields read back");

            String msgId = webhooks.sendEvent("org1", "order.created", "{\"order_id\":7}");
            Webhooks.WebhookMessage msg = storage.getMessage(msgId);
            check(msg != null && "org1".equals(msg.orgId) && "{\"order_id\":7}".equals(msg.payload), "message read back");
            List<Webhooks.WebhookDelivery> ds = storage.listDeliveriesByMessage(msgId);
            check(ds.size() == 2, "one delivery per org1 endpoint, none for org2: " + ds.size());
            check(ds.get(0).endpointId.equals(a1.get("id")) && ds.get(1).endpointId.equals(a2.get("id")), "insertion order");
            for (Webhooks.WebhookDelivery d : ds) {
                check(!d.endpointId.equals(b1.get("id")), "org1's event reached org2");
            }

            // First attempt fails: the stored row shows the status and the next attempt.
            webhooks.deliver(storage.getDelivery(ds.get(0).id));
            Webhooks.WebhookDelivery after = storage.getDelivery(ds.get(0).id);
            check(!after.success && after.statusCode == 500 && after.attempt == 2, "failed attempt stored");
            check(after.nextAttemptAt != null && after.nextAttemptAt == now[0] + 5, "retry time stored");
            check("HTTP 500".equals(after.error) && after.deliveredAt == null, "error stored");

            // The retry succeeds: the stored row shows it.
            now[0] += 5;
            webhooks.deliver(after);
            Webhooks.WebhookDelivery done = storage.getDelivery(ds.get(0).id);
            check(done.success && done.statusCode == 200 && done.deliveredAt == now[0], "success stored");
            check(done.nextAttemptAt == null && done.error == null, "retry cleared");

            // Rotation and disabling persist.
            String newSecret = webhooks.rotateSecret(a2.get("id"));
            check(storage.getEndpoint(a2.get("id")).secret.equals(newSecret), "rotated secret stored");
            Webhooks.WebhookEndpoint off = storage.getEndpoint(a2.get("id"));
            off.active = false;
            off.failureCount = 5;
            storage.updateEndpoint(off);
            check(storage.getEndpoint(a2.get("id")).failureCount == 5, "failure count stored");
            check(storage.listActiveEndpoints("org1", "order.created").size() == 1, "inactive endpoint not listed");
            check(storage.listActiveEndpoints("org2", "order.paid").isEmpty(), "event type filter");
            check(storage.getEndpoint("ep_missing") == null && storage.getMessage("msg_missing") == null
                    && storage.getDelivery("missing") == null, "unknown ids are null");
        }
    }
}

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.time.*;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.Base64;

public class Webhooks {

    /* ---------- Data Models ---------- */

    public static class WebhookEndpoint {
        public final String id;
        public final String orgId;
        public final String url;
        public String secret;
        public final Set<String> eventTypes;
        public boolean active;
        public int failureCount;
        public final long createdAt;

        public WebhookEndpoint(String id, String orgId, String url, String secret, Set<String> eventTypes, boolean active, int failureCount, long createdAt) {
            this.id = id;
            this.orgId = orgId;
            this.url = url;
            this.secret = secret;
            this.eventTypes = eventTypes;
            this.active = active;
            this.failureCount = failureCount;
            this.createdAt = createdAt;
        }
    }

    /**
     * One event sent for one org (webhook_messages row). Its id is the webhook-id header on every attempt.
     *
     * <p>2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: gained orgId (HOOK-06, spec "send_event(org_id, ...)"),
     * so a message can only fan out to its own org's endpoints. Touches: memory only.
     */
    public static class WebhookMessage {
        public final String id;
        public final String orgId;
        public final String eventType;
        public final String payload;
        public final long createdAt;

        public WebhookMessage(String id, String orgId, String eventType, String payload, long createdAt) {
            this.id = id;
            this.orgId = orgId;
            this.eventType = eventType;
            this.payload = payload;
            this.createdAt = createdAt;
        }
    }

    public static class WebhookDelivery {
        public final String id;
        public final String messageId;
        public final String endpointId;
        public int attempt;
        public Integer statusCode;
        public boolean success;
        public String error;
        public Long nextAttemptAt;
        public Long deliveredAt;

        public WebhookDelivery(String id, String messageId, String endpointId, int attempt) {
            this.id = id;
            this.messageId = messageId;
            this.endpointId = endpointId;
            this.attempt = attempt;
            this.success = false;
            this.statusCode = null;
            this.error = null;
            this.nextAttemptAt = null;
            this.deliveredAt = null;
        }
    }

    /* ---------- Storage Interface ---------- */

    public interface Storage {
        void createEndpoint(WebhookEndpoint endpoint);
        WebhookEndpoint getEndpoint(String id);
        /**
         * Active endpoints of ONE org subscribed to eventType, in creation order.
         * In: orgId, eventType. Out: matching endpoints. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP:
         * now scoped by org (HOOK-06; before, every tenant's endpoint got every event). Touches: the store.
         */
        List<WebhookEndpoint> listActiveEndpoints(String orgId, String eventType);
        void updateEndpoint(WebhookEndpoint endpoint);

        void createMessage(WebhookMessage message);
        WebhookMessage getMessage(String id);

        void createDelivery(WebhookDelivery delivery);
        WebhookDelivery getDelivery(String id);
        void updateDelivery(WebhookDelivery delivery);
        List<WebhookDelivery> listDeliveriesByMessage(String messageId);
    }

    /* ---------- In-Memory Store ---------- */

    public static class InMemoryStorage implements Storage {
        // LinkedHashMap (synchronized) keeps insertion order, so lists are deterministic (spec: ties by insertion order).
        private final Map<String, WebhookEndpoint> endpoints = Collections.synchronizedMap(new LinkedHashMap<>());
        private final Map<String, WebhookMessage> messages = Collections.synchronizedMap(new LinkedHashMap<>());
        private final Map<String, WebhookDelivery> deliveries = Collections.synchronizedMap(new LinkedHashMap<>());

        @Override
        public void createEndpoint(WebhookEndpoint endpoint) {
            endpoints.put(endpoint.id, endpoint);
        }

        @Override
        public WebhookEndpoint getEndpoint(String id) {
            return endpoints.get(id);
        }

        @Override
        public synchronized List<WebhookEndpoint> listActiveEndpoints(String orgId, String eventType) {
            List<WebhookEndpoint> result = new ArrayList<>();
            for (WebhookEndpoint ep : new ArrayList<>(endpoints.values())) {
                if (ep.active && ep.orgId.equals(orgId) && ep.eventTypes.contains(eventType)) {
                    result.add(ep);
                }
            }
            return result;
        }

        @Override
        public void updateEndpoint(WebhookEndpoint endpoint) {
            endpoints.put(endpoint.id, endpoint);
        }

        @Override
        public void createMessage(WebhookMessage message) {
            messages.put(message.id, message);
        }

        @Override
        public WebhookMessage getMessage(String id) {
            return messages.get(id);
        }

        @Override
        public void createDelivery(WebhookDelivery delivery) {
            deliveries.put(delivery.id, delivery);
        }

        @Override
        public WebhookDelivery getDelivery(String id) {
            return deliveries.get(id);
        }

        @Override
        public void updateDelivery(WebhookDelivery delivery) {
            deliveries.put(delivery.id, delivery);
        }

        @Override
        public synchronized List<WebhookDelivery> listDeliveriesByMessage(String messageId) {
            List<WebhookDelivery> result = new ArrayList<>();
            for (WebhookDelivery d : new ArrayList<>(deliveries.values())) {
                if (d.messageId.equals(messageId)) {
                    result.add(d);
                }
            }
            return result;
        }
    }

    /* ---------- SQL Store (Skeleton) ---------- */

    public static class SQLStorage implements Storage {
        private final Connection conn;

        public SQLStorage(Connection conn) {
            this.conn = conn;
        }

        @Override
        public void createEndpoint(WebhookEndpoint endpoint) {
        }

        @Override
        public WebhookEndpoint getEndpoint(String id) {
            return null;
        }

        @Override
        public List<WebhookEndpoint> listActiveEndpoints(String orgId, String eventType) {
            return Collections.emptyList();
        }

        @Override
        public void updateEndpoint(WebhookEndpoint endpoint) {
        }

        @Override
        public void createMessage(WebhookMessage message) {
        }

        @Override
        public WebhookMessage getMessage(String id) {
            return null;
        }

        @Override
        public void createDelivery(WebhookDelivery delivery) {
        }

        @Override
        public WebhookDelivery getDelivery(String id) {
            return null;
        }

        @Override
        public void updateDelivery(WebhookDelivery delivery) {
        }

        @Override
        public List<WebhookDelivery> listDeliveriesByMessage(String messageId) {
            return Collections.emptyList();
        }
    }

    /* ---------- Sender Interface ---------- */

    public interface Sender {
        int send(String url, Map<String, String> headers, String body) throws Exception;
    }

    /* ---------- Webhooks Core ---------- */

    private final Storage storage;
    private final Sender sender;
    private final SecureRandom random = new SecureRandom();
    private final Base64.Encoder base64Encoder = Base64.getEncoder().withoutPadding();
    private final Base64.Decoder base64Decoder = Base64.getDecoder();

    private final long[] backoffDelays = new long[]{5, 300, 1800, 7200, 18000, 36000, 36000};
    private final java.util.function.LongSupplier clock;

    /** Real clock (epoch seconds). */
    public Webhooks(Storage storage, Sender sender) {
        this(storage, sender, () -> Instant.now().getEpochSecond());
    }

    /**
     * Webhooks with an injectable clock.
     * In: storage, sender (the only way out to the network), clock returning unix seconds.
     * Why: spec "Deterministic: time comes from an injectable clock"; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: nothing until called.
     */
    public Webhooks(Storage storage, Sender sender, java.util.function.LongSupplier clock) {
        this.storage = storage;
        this.sender = sender;
        this.clock = clock;
    }

    /* ---------- Public API ---------- */

    public Map<String, String> createEndpoint(String orgId, String url, List<String> eventTypes) {
        if (!url.startsWith("https://") && !url.startsWith("http://localhost")) {
            throw new IllegalArgumentException("URL must be https:// or http://localhost");
        }
        String id = "ep_" + randomHex(8);
        String secret = generateSecret();
        Set<String> eventSet = new HashSet<>(eventTypes);
        long now = clock.getAsLong();
        WebhookEndpoint ep = new WebhookEndpoint(id, orgId, url, secret, eventSet, true, 0, now);
        storage.createEndpoint(ep);
        Map<String, String> result = new HashMap<>();
        result.put("id", id);
        result.put("secret", secret);
        return result;
    }

    /**
     * send_event: creates ONE message for orgId and a pending delivery for every active endpoint OF THAT ORG
     * subscribed to eventType.
     * In: orgId, eventType, payload (raw JSON body). Out: the message id ("msg_" + 16 random bytes in hex).
     * Why: HOOK-06 / spec amendment 2026-09-26 (an org's events never reach another org's endpoints);
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store only (no network; deliver() sends).
     */
    public String sendEvent(String orgId, String eventType, String payload) {
        if (orgId == null || orgId.isEmpty()) {
            throw new IllegalArgumentException("org_id is required");
        }
        String msgId = "msg_" + randomHex(16);
        long now = clock.getAsLong();
        WebhookMessage msg = new WebhookMessage(msgId, orgId, eventType, payload, now);
        storage.createMessage(msg);

        List<WebhookEndpoint> endpoints = storage.listActiveEndpoints(orgId, eventType);
        for (WebhookEndpoint ep : endpoints) {
            String deliveryId = msgId + "_" + ep.id;
            WebhookDelivery delivery = new WebhookDelivery(deliveryId, msgId, ep.id, 1);
            storage.createDelivery(delivery);
        }
        return msgId;
    }

    public String sign(String secret, String msgId, long timestamp, String body) {
        try {
            String keyB64 = secret.startsWith("whsec_") ? secret.substring(6) : secret;
            byte[] keyBytes = base64Decoder.decode(keyB64);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(keySpec);
            String data = msgId + "." + timestamp + "." + body;
            byte[] sig = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            String b64 = base64Encoder.encodeToString(sig);
            return "v1," + b64;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * deliver: POSTs the message to the endpoint through the injected sender, records the status, and on any
     * non-2xx (or a sender that throws) schedules the next attempt on the 5s, 5m, 30m, 2h, 5h, 10h, 10h ladder.
     * In: the delivery. Out: none (the delivery row is updated). The webhook-id header is the MESSAGE id on every
     * attempt (HOOK-07). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: uses the injected clock; a success resets
     * the endpoint's consecutive-failure count and only a fully-failed message (all retries spent) counts toward
     * disabling it (spec: "Disable an endpoint after 5 consecutive fully-failed messages"). Touches: network via
     * the sender, the store.
     */
    public void deliver(WebhookDelivery delivery) {
        try {
            WebhookMessage msg = storage.getMessage(delivery.messageId);
            WebhookEndpoint ep = storage.getEndpoint(delivery.endpointId);
            if (msg == null || ep == null) {
                return;
            }
            long timestamp = clock.getAsLong();
            String signature = sign(ep.secret, msg.id, timestamp, msg.payload);
            Map<String, String> headers = new HashMap<>();
            headers.put("webhook-id", msg.id);
            headers.put("webhook-timestamp", Long.toString(timestamp));
            headers.put("webhook-signature", signature);
            headers.put("Content-Type", "application/json");
            int status = sender.send(ep.url, headers, msg.payload);
            delivery.statusCode = status;
            if (status >= 200 && status <= 299) {
                delivery.success = true;
                delivery.deliveredAt = timestamp;
                delivery.nextAttemptAt = null;
                delivery.error = null;
                ep.failureCount = 0;
                storage.updateEndpoint(ep);
            } else {
                delivery.success = false;
                delivery.error = "HTTP " + status;
                scheduleRetry(delivery);
            }
            storage.updateDelivery(delivery);
        } catch (Exception e) {
            delivery.success = false;
            delivery.error = e.getMessage();
            scheduleRetry(delivery);
            storage.updateDelivery(delivery);
        }
    }

    public boolean verify(String secret, Map<String, String> headers, String rawBody, long toleranceSeconds) {
        try {
            String msgId = headers.get("webhook-id");
            String tsStr = headers.get("webhook-timestamp");
            String sigHeader = headers.get("webhook-signature");
            if (msgId == null || tsStr == null || sigHeader == null) {
                return false;
            }
            long ts = Long.parseLong(tsStr.trim());
            long now = clock.getAsLong();
            if (Math.abs(now - ts) > toleranceSeconds) {
                return false;
            }
            String keyB64 = secret.startsWith("whsec_") ? secret.substring(6) : secret;
            byte[] keyBytes = base64Decoder.decode(keyB64);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(keySpec);
            String data = msgId + "." + ts + "." + rawBody;
            byte[] expectedSig = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            String expectedB64 = base64Encoder.encodeToString(expectedSig);

            String[] sigParts = sigHeader.split(" ");
            for (String part : sigParts) {
                String[] kv = part.split(",", 2);
                if (kv.length != 2) continue;
                String scheme = kv[0];
                String sig = kv[1];
                if (!"v1".equals(scheme)) continue;
                if (constantTimeEquals(expectedB64, sig)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    public String rotateSecret(String endpointId) {
        WebhookEndpoint ep = storage.getEndpoint(endpointId);
        if (ep == null) {
            throw new IllegalArgumentException("Endpoint not found");
        }
        String newSecret = generateSecret();
        ep.secret = newSecret;
        storage.updateEndpoint(ep);
        return newSecret;
    }

    /* ---------- Helpers ---------- */

    private String generateSecret() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return "whsec_" + base64Encoder.encodeToString(bytes);
    }

    /**
     * After a failed attempt: schedule retry n (n = attempts so far) after backoffDelays[n-1]; when all seven retries
     * are spent the message is fully failed (nextAttemptAt null) and the endpoint's consecutive-failure count goes up,
     * disabling it at 5. In: the delivery. Out: none. Why: spec retry ladder and "5 consecutive fully-failed messages";
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (before, every failed ATTEMPT counted, so one bad message disabled
     * an endpoint). Touches: the store.
     */
    private void scheduleRetry(WebhookDelivery delivery) {
        int failedAttempt = delivery.attempt;
        if (failedAttempt <= backoffDelays.length) {
            delivery.attempt = failedAttempt + 1;
            delivery.nextAttemptAt = clock.getAsLong() + backoffDelays[failedAttempt - 1];
            return;
        }
        delivery.nextAttemptAt = null;
        WebhookEndpoint ep = storage.getEndpoint(delivery.endpointId);
        if (ep != null) {
            ep.failureCount += 1;
            if (ep.failureCount >= 5) {
                ep.active = false;
            }
            storage.updateEndpoint(ep);
        }
    }

    private boolean constantTimeEquals(String a, String b) {
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(aBytes, bBytes);
    }

    private String randomHex(int byteLength) {
        byte[] bytes = new byte[byteLength];
        random.nextBytes(bytes);
        StringBuilder sb = new StringBuilder(byteLength * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
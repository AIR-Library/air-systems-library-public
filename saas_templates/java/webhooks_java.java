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

    /* ---------- SQL Store ---------- */

    /**
     * Storage on a JDBC database, following the spec's schema (webhook_endpoints, webhook_messages,
     * webhook_deliveries). The SQL is plain and portable: it runs on SQLite and on H2 (the test runs it on in-memory H2,
     * because the runner's Java toolchain ships the H2 driver and no SQLite driver). event_types is stored as a JSON
     * array; booleans as 0/1; times as unix seconds. A seq column keeps insertion order for listings (spec: ties are
     * broken by insertion order). Methods are synchronized, so one store shared by every thread stays consistent.
     *
     * <p>In: an open Connection (the caller owns it; every call uses it, so every thread shares one database).
     * Out: the Storage interface. Why: java bug list (Phase B.2, 2026-11-10): SQLStorage was a stub whose writes did
     * nothing and whose reads returned nothing, silently losing every webhook. Written 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database behind the connection. A SQLException is rethrown as
     * IllegalStateException, never swallowed.
     */
    public static class SQLStorage implements Storage {
        private static final com.fasterxml.jackson.databind.ObjectMapper JSON = new com.fasterxml.jackson.databind.ObjectMapper();
        private final Connection conn;

        /** Uses conn for every call. In: an open connection. Touches: nothing until called. */
        public SQLStorage(Connection conn) {
            this.conn = Objects.requireNonNull(conn, "conn");
        }

        /**
         * Creates the three tables if they are missing (run as a migration in production). Out: this store.
         * Touches: the database (DDL).
         */
        public synchronized SQLStorage createTables() {
            try (Statement st = conn.createStatement()) {
                st.execute("CREATE TABLE IF NOT EXISTS webhook_endpoints (id VARCHAR(64) PRIMARY KEY, seq BIGINT NOT NULL, "
                        + "org_id VARCHAR(255) NOT NULL, url VARCHAR(2048) NOT NULL, secret VARCHAR(255) NOT NULL, "
                        + "event_types VARCHAR(8000) NOT NULL, active INTEGER NOT NULL, failure_count INTEGER NOT NULL, "
                        + "created_at BIGINT NOT NULL)");
                st.execute("CREATE TABLE IF NOT EXISTS webhook_messages (id VARCHAR(64) PRIMARY KEY, org_id VARCHAR(255) NOT NULL, "
                        + "event_type VARCHAR(255) NOT NULL, payload CLOB NOT NULL, created_at BIGINT NOT NULL)");
                st.execute("CREATE TABLE IF NOT EXISTS webhook_deliveries (id VARCHAR(160) PRIMARY KEY, seq BIGINT NOT NULL, "
                        + "message_id VARCHAR(64) NOT NULL, endpoint_id VARCHAR(64) NOT NULL, attempt INTEGER NOT NULL, "
                        + "status_code INTEGER, success INTEGER NOT NULL, error VARCHAR(2000), next_attempt_at BIGINT, "
                        + "delivered_at BIGINT)");
                st.execute("CREATE INDEX IF NOT EXISTS webhook_endpoints_org ON webhook_endpoints (org_id, active)");
                st.execute("CREATE INDEX IF NOT EXISTS webhook_deliveries_message ON webhook_deliveries (message_id)");
            } catch (SQLException e) {
                throw new IllegalStateException("webhooks: could not create tables", e);
            }
            return this;
        }

        /** Next insertion-order number for a table (only called inside a synchronized method). Touches: reads the DB. */
        private long nextSeq(String table) throws SQLException {
            try (Statement st = conn.createStatement();
                 ResultSet rs = st.executeQuery("SELECT COALESCE(MAX(seq), 0) + 1 FROM " + table)) {
                rs.next();
                return rs.getLong(1);
            }
        }

        private static String toJson(Set<String> eventTypes) {
            try {
                return JSON.writeValueAsString(new TreeSet<>(eventTypes));
            } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
                throw new IllegalStateException(e);
            }
        }

        private static Set<String> eventTypesFrom(String json) {
            try {
                return new HashSet<>(Arrays.asList(JSON.readValue(json, String[].class)));
            } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
                throw new IllegalStateException("webhooks: bad event_types in the store", e);
            }
        }

        private static WebhookEndpoint endpointFrom(ResultSet rs) throws SQLException {
            return new WebhookEndpoint(rs.getString("id"), rs.getString("org_id"), rs.getString("url"), rs.getString("secret"),
                    eventTypesFrom(rs.getString("event_types")), rs.getInt("active") != 0, rs.getInt("failure_count"),
                    rs.getLong("created_at"));
        }

        private static Long longOrNull(ResultSet rs, String col) throws SQLException {
            long v = rs.getLong(col);
            return rs.wasNull() ? null : v;
        }

        private static WebhookDelivery deliveryFrom(ResultSet rs) throws SQLException {
            WebhookDelivery d = new WebhookDelivery(rs.getString("id"), rs.getString("message_id"),
                    rs.getString("endpoint_id"), rs.getInt("attempt"));
            int code = rs.getInt("status_code");
            d.statusCode = rs.wasNull() ? null : code;
            d.success = rs.getInt("success") != 0;
            d.error = rs.getString("error");
            d.nextAttemptAt = longOrNull(rs, "next_attempt_at");
            d.deliveredAt = longOrNull(rs, "delivered_at");
            return d;
        }

        private static void setLongOrNull(PreparedStatement ps, int i, Long v) throws SQLException {
            if (v == null) ps.setNull(i, Types.BIGINT); else ps.setLong(i, v);
        }

        /** Inserts an endpoint. Touches: the database. */
        @Override
        public synchronized void createEndpoint(WebhookEndpoint endpoint) {
            try (PreparedStatement ps = conn.prepareStatement("INSERT INTO webhook_endpoints "
                    + "(id, seq, org_id, url, secret, event_types, active, failure_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
                ps.setString(1, endpoint.id);
                ps.setLong(2, nextSeq("webhook_endpoints"));
                ps.setString(3, endpoint.orgId);
                ps.setString(4, endpoint.url);
                ps.setString(5, endpoint.secret);
                ps.setString(6, toJson(endpoint.eventTypes));
                ps.setInt(7, endpoint.active ? 1 : 0);
                ps.setInt(8, endpoint.failureCount);
                ps.setLong(9, endpoint.createdAt);
                ps.executeUpdate();
            } catch (SQLException e) {
                throw new IllegalStateException("webhooks: createEndpoint failed", e);
            }
        }

        /** The endpoint, or null. Touches: reads the database. */
        @Override
        public synchronized WebhookEndpoint getEndpoint(String id) {
            try (PreparedStatement ps = conn.prepareStatement("SELECT * FROM webhook_endpoints WHERE id = ?")) {
                ps.setString(1, id);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? endpointFrom(rs) : null;
                }
            } catch (SQLException e) {
                throw new IllegalStateException("webhooks: getEndpoint failed", e);
            }
        }

        /** Active endpoints of orgId subscribed to eventType, in insertion order (HOOK-06). Touches: reads the database. */
        @Override
        public synchronized List<WebhookEndpoint> listActiveEndpoints(String orgId, String eventType) {
            List<WebhookEndpoint> result = new ArrayList<>();
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT * FROM webhook_endpoints WHERE org_id = ? AND active = 1 ORDER BY seq")) {
                ps.setString(1, orgId);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        WebhookEndpoint ep = endpointFrom(rs);
                        if (ep.eventTypes.contains(eventType)) result.add(ep);
                    }
                }
            } catch (SQLException e) {
                throw new IllegalStateException("webhooks: listActiveEndpoints failed", e);
            }
            return result;
        }

        /** Saves an endpoint's secret, event types, active flag and failure count. Touches: the database. */
        @Override
        public synchronized void updateEndpoint(WebhookEndpoint endpoint) {
            try (PreparedStatement ps = conn.prepareStatement("UPDATE webhook_endpoints SET url = ?, secret = ?, "
                    + "event_types = ?, active = ?, failure_count = ? WHERE id = ?")) {
                ps.setString(1, endpoint.url);
                ps.setString(2, endpoint.secret);
                ps.setString(3, toJson(endpoint.eventTypes));
                ps.setInt(4, endpoint.active ? 1 : 0);
                ps.setInt(5, endpoint.failureCount);
                ps.setString(6, endpoint.id);
                ps.executeUpdate();
            } catch (SQLException e) {
                throw new IllegalStateException("webhooks: updateEndpoint failed", e);
            }
        }

        /** Inserts a message. Touches: the database. */
        @Override
        public synchronized void createMessage(WebhookMessage message) {
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO webhook_messages (id, org_id, event_type, payload, created_at) VALUES (?, ?, ?, ?, ?)")) {
                ps.setString(1, message.id);
                ps.setString(2, message.orgId);
                ps.setString(3, message.eventType);
                ps.setString(4, message.payload);
                ps.setLong(5, message.createdAt);
                ps.executeUpdate();
            } catch (SQLException e) {
                throw new IllegalStateException("webhooks: createMessage failed", e);
            }
        }

        /** The message, or null. Touches: reads the database. */
        @Override
        public synchronized WebhookMessage getMessage(String id) {
            try (PreparedStatement ps = conn.prepareStatement("SELECT * FROM webhook_messages WHERE id = ?")) {
                ps.setString(1, id);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) return null;
                    return new WebhookMessage(rs.getString("id"), rs.getString("org_id"), rs.getString("event_type"),
                            rs.getString("payload"), rs.getLong("created_at"));
                }
            } catch (SQLException e) {
                throw new IllegalStateException("webhooks: getMessage failed", e);
            }
        }

        /** Inserts a delivery. Touches: the database. */
        @Override
        public synchronized void createDelivery(WebhookDelivery delivery) {
            try (PreparedStatement ps = conn.prepareStatement("INSERT INTO webhook_deliveries (id, seq, message_id, "
                    + "endpoint_id, attempt, status_code, success, error, next_attempt_at, delivered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
                ps.setString(1, delivery.id);
                ps.setLong(2, nextSeq("webhook_deliveries"));
                ps.setString(3, delivery.messageId);
                ps.setString(4, delivery.endpointId);
                ps.setInt(5, delivery.attempt);
                if (delivery.statusCode == null) ps.setNull(6, Types.INTEGER); else ps.setInt(6, delivery.statusCode);
                ps.setInt(7, delivery.success ? 1 : 0);
                ps.setString(8, delivery.error);
                setLongOrNull(ps, 9, delivery.nextAttemptAt);
                setLongOrNull(ps, 10, delivery.deliveredAt);
                ps.executeUpdate();
            } catch (SQLException e) {
                throw new IllegalStateException("webhooks: createDelivery failed", e);
            }
        }

        /** The delivery, or null. Touches: reads the database. */
        @Override
        public synchronized WebhookDelivery getDelivery(String id) {
            try (PreparedStatement ps = conn.prepareStatement("SELECT * FROM webhook_deliveries WHERE id = ?")) {
                ps.setString(1, id);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? deliveryFrom(rs) : null;
                }
            } catch (SQLException e) {
                throw new IllegalStateException("webhooks: getDelivery failed", e);
            }
        }

        /** Saves a delivery's attempt, status, outcome and times. Touches: the database. */
        @Override
        public synchronized void updateDelivery(WebhookDelivery delivery) {
            try (PreparedStatement ps = conn.prepareStatement("UPDATE webhook_deliveries SET attempt = ?, status_code = ?, "
                    + "success = ?, error = ?, next_attempt_at = ?, delivered_at = ? WHERE id = ?")) {
                ps.setInt(1, delivery.attempt);
                if (delivery.statusCode == null) ps.setNull(2, Types.INTEGER); else ps.setInt(2, delivery.statusCode);
                ps.setInt(3, delivery.success ? 1 : 0);
                ps.setString(4, delivery.error);
                setLongOrNull(ps, 5, delivery.nextAttemptAt);
                setLongOrNull(ps, 6, delivery.deliveredAt);
                ps.setString(7, delivery.id);
                ps.executeUpdate();
            } catch (SQLException e) {
                throw new IllegalStateException("webhooks: updateDelivery failed", e);
            }
        }

        /** A message's deliveries in insertion order. Touches: reads the database. */
        @Override
        public synchronized List<WebhookDelivery> listDeliveriesByMessage(String messageId) {
            List<WebhookDelivery> result = new ArrayList<>();
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT * FROM webhook_deliveries WHERE message_id = ? ORDER BY seq")) {
                ps.setString(1, messageId);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) result.add(deliveryFrom(rs));
                }
            } catch (SQLException e) {
                throw new IllegalStateException("webhooks: listDeliveriesByMessage failed", e);
            }
            return result;
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
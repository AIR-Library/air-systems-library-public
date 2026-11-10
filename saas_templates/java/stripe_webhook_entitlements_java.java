import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Stripe webhook entitlements (spec docs/specs/stripe_webhook_entitlements.md): receives Stripe's webhook, verifies
 * the Stripe-Signature header (HMAC-SHA256, 300 s tolerance) BEFORE parsing, applies every event exactly once and in
 * order (created, then rank created &lt; updated &lt; deleted; an unorderable tie asks Stripe), and keeps one answer per
 * user: what they are entitled to right now. The webhook is the only writer of that answer.
 *
 * In: the raw request body and the Stripe-Signature header. Out: result maps with "status"; never an unhandled
 * exception. Why: Phase D wave 1, owner request 2026-11-10 (STRIPEWH-01 to STRIPEWH-14).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the injected Store (database; memory in tests), the injected Stripe client (network in production, a fake
 * in tests). It decides paid access (money-adjacent) but moves no money. Never logs the secret, the header or the payload.
 */
public final class StripeWebhookEntitlements {
    public static final long TOLERANCE = 300;
    private static final Pattern EVT_ID = Pattern.compile("evt_[A-Za-z0-9_]{1,200}");
    private static final Pattern SUB_ID = Pattern.compile("sub_[A-Za-z0-9_]{1,200}");
    private static final Pattern STATUS = Pattern.compile("[a-z_]{1,32}");
    private static final ObjectMapper JSON = JsonMapper.builder()
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();

    /** The injected Stripe client: retrieve_subscription(id) -> a subscription object, or raises. Touches: network. */
    public interface StripeClient {
        /** In: a subscription id. Out: Stripe's current subscription object; raises on failure. Touches: network (real client). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        JsonNode retrieveSubscription(String subscriptionId) throws Exception;
    }

    /** A stripe_events row. result is null until the event is applied. */
    public record EventRow(String eventId, String type, long created, long receivedAt, String result) {}

    /** An entitlement_subscriptions row. plan null entitles nobody. */
    public record SubRow(String subscriptionId, String userId, String customerId, String priceId, String plan,
                         String status, long currentPeriodEnd, boolean cancelAtPeriodEnd, long eventAt, int eventRank,
                         long updatedAt) {}

    /**
     * Storage for stripe_events and entitlement_subscriptions. claimEvent is an insert that fails on a duplicate key;
     * transaction() runs its body all-or-nothing. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (memory in tests).
     */
    public interface Store {
        /** CLAIM: inserts the stripe_events row. Out: false when the id is already there (duplicate key). Touches: the database. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        boolean claimEvent(String eventId, String type, long created, long receivedAt);

        /** Stores APPLY's result in the event's row. Touches: the database. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        void setEventResult(String eventId, String result);

        /** The event row, or null. Touches: reads the database. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        EventRow getEvent(String eventId);

        /** The entitlement_subscriptions row, or null. Touches: reads the database. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        SubRow getSub(String subscriptionId);

        /** Inserts or replaces the row for its subscription id. Touches: the database. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        void putSub(SubRow row);

        /** The user's rows. Touches: reads the database. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        List<SubRow> subsForUser(String userId);

        /** The rows with this stripe_customer_id. Touches: reads the database. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        List<SubRow> subsForCustomer(String customerId);

        /** Runs body; when it throws, every change it made is undone and the exception is rethrown. */
        <T> T transaction(Supplier<T> body);
    }

    /**
     * In-memory Store: synchronized, with a snapshot/restore transaction. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: memory only.
     */
    public static final class InMemoryStore implements Store {
        private LinkedHashMap<String, EventRow> events = new LinkedHashMap<>();
        private LinkedHashMap<String, SubRow> subs = new LinkedHashMap<>();

        @Override
        public synchronized boolean claimEvent(String eventId, String type, long created, long receivedAt) {
            if (events.containsKey(eventId)) return false;
            events.put(eventId, new EventRow(eventId, type, created, receivedAt, null));
            return true;
        }

        @Override
        public synchronized void setEventResult(String eventId, String result) {
            EventRow e = events.get(eventId);
            if (e != null) events.put(eventId, new EventRow(e.eventId(), e.type(), e.created(), e.receivedAt(), result));
        }

        @Override
        public synchronized EventRow getEvent(String eventId) {
            return events.get(eventId);
        }

        /** Every event row (for inspection). */
        public synchronized int eventCount() {
            return events.size();
        }

        @Override
        public synchronized SubRow getSub(String subscriptionId) {
            return subs.get(subscriptionId);
        }

        @Override
        public synchronized void putSub(SubRow row) {
            subs.put(row.subscriptionId(), row);
        }

        @Override
        public synchronized List<SubRow> subsForUser(String userId) {
            List<SubRow> out = new ArrayList<>();
            for (SubRow r : subs.values()) if (r.userId().equals(userId)) out.add(r);
            return out;
        }

        @Override
        public synchronized List<SubRow> subsForCustomer(String customerId) {
            List<SubRow> out = new ArrayList<>();
            for (SubRow r : subs.values()) if (customerId != null && customerId.equals(r.customerId())) out.add(r);
            return out;
        }

        @Override
        public synchronized <T> T transaction(Supplier<T> body) {
            LinkedHashMap<String, EventRow> e0 = new LinkedHashMap<>(events);
            LinkedHashMap<String, SubRow> s0 = new LinkedHashMap<>(subs);
            try {
                return body.get();
            } catch (RuntimeException ex) {
                events = e0;
                subs = s0;
                throw ex;
            }
        }
    }

    /** Wraps an error raised while applying, so the transaction undoes every change. */
    private static final class ApplyFailed extends RuntimeException {
        ApplyFailed(Throwable cause) {
            super("apply failed", cause);
        }
    }

    private final Store store;
    private final String webhookSecret;
    private final Map<String, String> pricePlans;
    private final StripeClient stripe;
    private final Predicate<String> userExists;
    private final long periodGraceSeconds;
    private final LongSupplier clock;

    /**
     * In: store, webhook_secret, price_plans {price_id: plan}, Stripe client, user_exists, period_grace_seconds and
     * clock (Unix seconds). Out: the service. A secret under 16 bytes is not refused here: every call then answers 503
     * webhook_not_configured (STRIPEWH-03). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    public StripeWebhookEntitlements(Store store, String webhookSecret, Map<String, String> pricePlans, StripeClient stripe,
                                     Predicate<String> userExists, long periodGraceSeconds, LongSupplier clock) {
        this.store = store;
        this.webhookSecret = webhookSecret;
        this.pricePlans = new LinkedHashMap<>(pricePlans);
        this.stripe = stripe;
        this.userExists = userExists;
        this.periodGraceSeconds = periodGraceSeconds;
        this.clock = clock;
    }

    // ------------------------------------------------------------------------------------------------ signature
    /** In: two byte arrays. Out: a followed by b. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /** Lower-case hex HMAC-SHA256(key = UTF-8 of secret, message = t + "." + payload). */
    private static String hmacHex(String secret, String t, byte[] payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] d = mac.doFinal(concat((t + ".").getBytes(StandardCharsets.US_ASCII), payload));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("hmac unavailable");
        }
    }

    /**
     * sign_payload(payload, secret, timestamp) -> "t=" + timestamp + ",v1=" + hex. The whole secret text is the key.
     * STRIPEWH-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public static String signPayload(byte[] payload, String secret, long timestamp) {
        return "t=" + timestamp + ",v1=" + hmacHex(secret, Long.toString(timestamp), payload);
    }

    /** sign_payload for a payload given as text (its UTF-8 bytes). */
    public static String signPayload(String payload, String secret, long timestamp) {
        return signPayload(payload.getBytes(StandardCharsets.UTF_8), secret, timestamp);
    }

    /** A refusal. In: HTTP status, error code. Out: {status, error}. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static Map<String, Object> refuse(int status, String error) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", status);
        m.put("error", error);
        return m;
    }

    /** In: a v1 value. Out: true for exactly 64 characters of [0-9a-f]. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean isHex64(String v) {
        if (v.length() != 64) return false;
        for (int i = 0; i < 64; i++) {
            char c = v.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        }
        return true;
    }

    /** In: a header element. Out: it without leading and trailing ASCII spaces. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static String trimSpaces(String s) {
        int a = 0, b = s.length();
        while (a < b && s.charAt(a) == ' ') a++;
        while (b > a && s.charAt(b - 1) == ' ') b--;
        return s.substring(a, b);
    }

    /**
     * verify_signature(payload, header, secret, now) -> {status 200, ok: true, timestamp}, or 503
     * webhook_not_configured / 400 missing_signature / 400 invalid_signature / 400 timestamp_out_of_tolerance, in
     * the spec's order. Every v1 candidate is compared in constant time with no early exit. STRIPEWH-02..05.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public static Map<String, Object> verifySignature(byte[] payload, String header, String secret, long now) {
        if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < 16) return refuse(503, "webhook_not_configured");
        if (header == null || header.isEmpty()) return refuse(400, "missing_signature");
        if (header.getBytes(StandardCharsets.UTF_8).length > 4096) return refuse(400, "invalid_signature");
        String t = null;
        int tCount = 0;
        List<String> candidates = new ArrayList<>();
        for (String raw : header.split(",", -1)) {
            String el = trimSpaces(raw);
            int eq = el.indexOf('=');
            if (eq < 0) continue;
            String name = el.substring(0, eq), value = el.substring(eq + 1);
            if (name.equals("t")) {
                tCount++;
                t = value;
            } else if (name.equals("v1") && isHex64(value)) {
                candidates.add(value);
            }
        }
        if (tCount != 1 || !t.matches("[0-9]{1,12}")) return refuse(400, "invalid_signature");
        if (candidates.isEmpty()) return refuse(400, "invalid_signature");
        byte[] expected = hmacHex(secret, t, payload == null ? new byte[0] : payload).getBytes(StandardCharsets.US_ASCII);
        boolean any = false;
        for (String c : candidates) {
            any |= MessageDigest.isEqual(expected, c.getBytes(StandardCharsets.US_ASCII));
        }
        if (!any) return refuse(400, "invalid_signature");
        long ts = Long.parseLong(t);
        if (Math.abs(now - ts) > TOLERANCE) return refuse(400, "timestamp_out_of_tolerance");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", 200);
        m.put("ok", true);
        m.put("timestamp", ts);
        return m;
    }

    // ------------------------------------------------------------------------------------------------ parsing
    /**
     * TIME: a JSON number (never a boolean, text or null) whose value is a whole number from 0 to 99999999999.
     * 1700000000.0 counts; 1700000000.5, -1, 1e400 and 100000000000 do not. Out: the value, or null.
     */
    static Long time(JsonNode n) {
        if (n == null || !n.isNumber()) return null;
        BigDecimal v;
        if (n.isIntegralNumber()) {
            v = new BigDecimal(n.bigIntegerValue());
        } else if (n.isBigDecimal()) {
            v = n.decimalValue();
        } else {
            double d = n.doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d) || d != Math.floor(d)) return null;
            v = BigDecimal.valueOf(d);
        }
        if (v.signum() < 0 || v.compareTo(BigDecimal.valueOf(99999999999L)) > 0) return null;
        try {
            return v.toBigIntegerExact().longValueExact();
        } catch (ArithmeticException e) {
            return null;
        }
    }

    /** In: a JSON node. Out: its text, or null when it is not a JSON string. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static String text(JsonNode n) {
        return n != null && n.isTextual() ? n.textValue() : null;
    }

    /** In: a node and a path of object keys. Out: the node there, or null. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static JsonNode at(JsonNode n, String... path) {
        JsonNode c = n;
        for (String p : path) {
            if (c == null || !c.isObject()) return null;
            c = c.get(p);
        }
        return c;
    }

    /**
     * Whether a parsed JSON value holds, anywhere inside it, a number that is not finite as a double (Jackson reads
     * 1e400 as Infinity; a huge integer literal becomes a BigInteger whose double value is Infinity). Walks with an
     * explicit stack, so a deep body cannot overflow the call stack.
     * In: the parsed node. Out: true when one is found. Why: spec db20a03 (Phase B.4): a body holding any non-finite
     * number, not only in a TIME field, is 400 invalid_payload as a whole. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    static boolean holdsNonFinite(JsonNode root) {
        java.util.ArrayDeque<JsonNode> todo = new java.util.ArrayDeque<>();
        if (root != null) todo.push(root);
        while (!todo.isEmpty()) {
            JsonNode n = todo.pop();
            if (n.isNumber()) {
                if (!Double.isFinite(n.doubleValue())) return true;
            } else if (n.isContainerNode()) {
                n.elements().forEachRemaining(todo::push);
            }
        }
        return false;
    }

    /** Parses the body: strict UTF-8, no BOM, one JSON value. Out: the node, or null for anything the parser raises. */
    private static JsonNode parse(byte[] payload) {
        if (payload == null) return null;
        if (payload.length >= 3 && (payload[0] & 0xff) == 0xEF && (payload[1] & 0xff) == 0xBB && (payload[2] & 0xff) == 0xBF) return null;
        try {
            String s = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(payload)).toString();
            return JSON.readTree(s);
        } catch (CharacterCodingException e) {
            return null;
        } catch (Exception | StackOverflowError e) {
            return null;
        }
    }

    /** In: the event type. Out: true for 1 to 100 characters U+0020-U+007E. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean validType(String t) {
        if (t == null || t.isEmpty() || t.length() > 100) return false;
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c < 0x20 || c > 0x7e) return false;
        }
        return true;
    }

    // ------------------------------------------------------------------------------------------------ webhook
    /** handle_webhook with a text body (its UTF-8 bytes). */
    public Map<String, Object> handleWebhook(String payload, String header) {
        return handleWebhook(payload == null ? null : payload.getBytes(StandardCharsets.UTF_8), header);
    }

    /**
     * handle_webhook(payload, header) -> {status 200, received: true, result: applied | duplicate | stale | ignored}.
     * Verifies first, then parses (400 invalid_payload), then CLAIM + APPLY + result in one transaction; any error
     * while applying undoes it all and answers 500 processing_failed (Stripe retries). STRIPEWH-01..14.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the Stripe client.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec db20a03, Phase B.4): a body holding a non-finite number
     * anywhere (holdsNonFinite: 1e400 outside created too) is 400 invalid_payload; before, only a non-finite created was.
     */
    public Map<String, Object> handleWebhook(byte[] payload, String header) {
        long now = clock.getAsLong();
        Map<String, Object> v = verifySignature(payload, header, webhookSecret, now);
        if (!Integer.valueOf(200).equals(v.get("status"))) return v;
        JsonNode ev = parse(payload);
        if (ev == null || !ev.isObject() || holdsNonFinite(ev)) return refuse(400, "invalid_payload");
        String id = text(ev.get("id"));
        String type = text(ev.get("type"));
        Long created = time(ev.get("created"));
        JsonNode obj = at(ev, "data", "object");
        if (id == null || !EVT_ID.matcher(id).matches() || !validType(type) || created == null || obj == null || !obj.isObject()) {
            return refuse(400, "invalid_payload");
        }
        try {
            String result = store.transaction(() -> {
                if (!store.claimEvent(id, type, created, now)) return "duplicate";
                String r = apply(type, created, obj, now);
                store.setEventResult(id, r);
                return r;
            });
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("status", 200);
            m.put("received", true);
            m.put("result", result);
            return m;
        } catch (RuntimeException e) {
            return refuse(500, "processing_failed");
        }
    }

    /** Retrieves a subscription through the injected client. In: its id. Out: the object; a raise becomes ApplyFailed (500, undone). Touches: the Stripe client (network). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private JsonNode fetch(String subId) {
        try {
            JsonNode n = stripe.retrieveSubscription(subId);
            if (n == null) throw new IllegalStateException("no subscription object");
            return n;
        } catch (Exception e) {
            throw new ApplyFailed(e);
        }
    }

    /** APPLY(event) by type. Out: the result text. Errors propagate (the caller's transaction undoes them). */
    private String apply(String type, long created, JsonNode obj, long now) {
        switch (type) {
            case "customer.subscription.created":
                return subscription(obj, text(at(obj, "metadata", "user_id")), 0, created, now, false);
            case "customer.subscription.updated":
                return subscription(obj, text(at(obj, "metadata", "user_id")), 1, created, now, false);
            case "customer.subscription.deleted":
                return subscription(obj, text(at(obj, "metadata", "user_id")), 2, created, now, false);
            case "checkout.session.completed": {
                String subId = text(obj.get("subscription"));
                if (!"subscription".equals(text(obj.get("mode"))) || subId == null || !SUB_ID.matcher(subId).matches()) {
                    return "ignored";
                }
                SubRow row = store.getSub(subId);
                if (row != null && compare(row.eventAt(), row.eventRank(), created, 1) > 0) return "stale";
                JsonNode sub = fetch(subId);
                String hint = text(obj.get("client_reference_id"));
                if (hint == null || hint.isEmpty()) hint = text(at(obj, "metadata", "user_id"));
                return subscription(sub, hint, 1, created, now, true);
            }
            default:
                return "ignored";
        }
    }

    /** Orders (event_at, rank) pairs, event_at first. In: two pairs. Out: <0, 0, >0. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static int compare(long atA, int rankA, long atB, int rankB) {
        if (atA != atB) return Long.compare(atA, atB);
        return Integer.compare(rankA, rankB);
    }

    /** sub.items.data[0].price.id, or null. */
    private static String priceOf(JsonNode sub) {
        JsonNode data = at(sub, "items", "data");
        if (data == null || !data.isArray() || data.size() == 0) return null;
        return text(at(data.get(0), "price", "id"));
    }

    /**
     * SUBSCRIPTION(sub, hint, rank) rules a-g of the spec. fetched is true when the object was just retrieved from
     * Stripe (checkout.session.completed), so an equal (event_at, rank) does not fetch a second time.
     * Out: "applied" | "stale" | "ignored". Touches: the store, the Stripe client.
     */
    private String subscription(JsonNode sub, String hint, int rank, long eventAt, long now, boolean fetched) {
        String subId = text(at(sub, "id"));
        if (subId == null || !SUB_ID.matcher(subId).matches()) return "ignored";
        SubRow row = store.getSub(subId);
        String priceId = priceOf(sub);
        if (row == null && (priceId == null || !pricePlans.containsKey(priceId))) return "ignored";
        String user;
        if (row != null) {
            user = row.userId();
        } else if (hint != null && !hint.isEmpty() && userExists.test(hint)) {
            user = hint;
        } else {
            String customer = text(sub.get("customer"));
            List<SubRow> byCustomer = customer == null ? List.of() : store.subsForCustomer(customer);
            String only = null;
            boolean same = !byCustomer.isEmpty();
            for (SubRow r : byCustomer) {
                if (only == null) only = r.userId();
                else if (!only.equals(r.userId())) same = false;
            }
            if (!same) return "ignored";
            user = only;
        }
        if (row != null) {
            int c = compare(eventAt, rank, row.eventAt(), row.eventRank());
            if (c < 0) return "stale";
            if (c == 0 && rank <= 1 && !fetched) {
                sub = fetch(subId);
                priceId = priceOf(sub);
            }
        }
        String plan;
        if (row == null) {
            plan = pricePlans.get(priceId);
        } else if (priceId != null && pricePlans.containsKey(priceId)) {
            plan = pricePlans.get(priceId);
        } else if (priceId == null || priceId.equals(row.priceId())) {
            priceId = row.priceId();
            plan = row.plan();
        } else {
            plan = null;
        }
        Long cpe = time(sub.get("current_period_end"));
        if (cpe == null) {
            JsonNode data = at(sub, "items", "data");
            if (data != null && data.isArray()) {
                for (JsonNode item : data) {
                    Long t = time(at(item, "current_period_end"));
                    if (t != null && (cpe == null || t > cpe)) cpe = t;
                }
            }
        }
        if (cpe == null) cpe = row != null ? row.currentPeriodEnd() : 0L;
        String status;
        if (rank == 2) {
            status = "canceled";
        } else {
            status = text(sub.get("status"));
            if (status == null || !STATUS.matcher(status).matches()) return "ignored";
        }
        JsonNode cap = sub.get("cancel_at_period_end");
        boolean cancel = cap != null && cap.isBoolean() && cap.booleanValue();
        store.putSub(new SubRow(subId, user, text(sub.get("customer")), priceId, plan, status, cpe, cancel, eventAt, rank, now));
        return "applied";
    }

    // ------------------------------------------------------------------------------------------------ entitlement
    /** ENTITLING(row): a plan, status active or trialing, and current_period_end + grace > now. In: row, now. Out: true/false. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private boolean entitling(SubRow r, long now) {
        return r.plan() != null && ("active".equals(r.status()) || "trialing".equals(r.status()))
                && r.currentPeriodEnd() + periodGraceSeconds > now;
    }

    /**
     * get_entitlement(user_id) -> {entitled, plan, status, current_period_end, cancel_at_period_end}, computed from the
     * clock at every call: the best entitling row, else the latest row (not entitled), else the "none" answer.
     * STRIPEWH-07, 10, 14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the store.
     */
    public Map<String, Object> getEntitlement(String userId) {
        long now = clock.getAsLong();
        List<SubRow> rows = store.subsForUser(userId);
        SubRow best = null;
        for (SubRow r : rows) {
            if (!entitling(r, now)) continue;
            if (best == null || r.currentPeriodEnd() > best.currentPeriodEnd()
                    || (r.currentPeriodEnd() == best.currentPeriodEnd() && (r.eventAt() > best.eventAt()
                    || (r.eventAt() == best.eventAt() && r.subscriptionId().compareTo(best.subscriptionId()) > 0)))) {
                best = r;
            }
        }
        Map<String, Object> m = new LinkedHashMap<>();
        if (best != null) {
            m.put("entitled", true);
            m.put("plan", best.plan());
            m.put("status", best.status());
            m.put("current_period_end", best.currentPeriodEnd());
            m.put("cancel_at_period_end", best.cancelAtPeriodEnd());
            return m;
        }
        SubRow latest = null;
        for (SubRow r : rows) {
            if (latest == null || r.eventAt() > latest.eventAt()
                    || (r.eventAt() == latest.eventAt() && r.subscriptionId().compareTo(latest.subscriptionId()) > 0)) {
                latest = r;
            }
        }
        m.put("entitled", false);
        m.put("plan", null);
        m.put("status", latest == null ? "none" : latest.status());
        m.put("current_period_end", latest == null ? null : latest.currentPeriodEnd());
        m.put("cancel_at_period_end", latest != null && latest.cancelAtPeriodEnd());
        return m;
    }
}

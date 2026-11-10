import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Tests for StripeWebhookEntitlements (spec docs/specs/stripe_webhook_entitlements.md, STRIPEWH-01 to STRIPEWH-14),
 * with a fake Stripe client (no network) and an injected clock. Run through main(); a failed check exits 1.
 * Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only (no database, files, network or money).
 */
public class stripe_webhook_entitlements_java_tests {

    static final String SECRET = "whsec_" + "test_secret_for_vectors";
    static final String BODY = "{\"id\":\"evt_test_0001\",\"type\":\"customer.subscription.updated\",\"created\":1700000000,"
            + "\"data\":{\"object\":{\"id\":\"sub_test_0001\",\"customer\":\"cus_test_0001\",\"status\":\"active\","
            + "\"current_period_end\":1702592000,\"cancel_at_period_end\":false,"
            + "\"metadata\":{\"user_id\":\"user_1\"},\"items\":{\"data\":[{\"price\":{\"id\":\"price_pro_monthly\"}}]}}}}";
    static final ObjectMapper JSON = new ObjectMapper();

    /** Runs every test. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only. */
    public static void main(String[] args) {
        try {
            testVector();
            testInvalidSignatures();
            testMissingHeaderAndShortSecret();
            testTolerance();
            testTwoV1Values();
            testInvalidPayloads();
            testCreatedGrants();
            testDuplicate();
            testOutOfOrder();
            testEntitlementEnds();
            testPeriodEnd();
            testIgnored();
            testCheckoutSession();
            testTwoSubscriptionsAndUserLookup();
            System.out.println("All tests passed");
        } catch (Throwable e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    // ------------------------------------------------------------------------------------------------ helpers
    /** Fails with msg unless cond holds. */
    static void check(boolean cond, String msg) {
        if (!cond) throw new AssertionError(msg);
    }

    /** A fake Stripe client: answers from a map of subscription JSON, records calls, raises when raise is set. */
    static final class FakeStripe implements StripeWebhookEntitlements.StripeClient {
        final Map<String, String> subs = new HashMap<>();
        final List<String> calls = new ArrayList<>();
        boolean raise = false;

        @Override
        public JsonNode retrieveSubscription(String id) throws Exception {
            calls.add(id);
            if (raise) throw new java.io.IOException("stripe unreachable");
            return JSON.readTree(subs.get(id));
        }
    }

    /** Test fixture: store, fakes, clock and service. Touches: memory only. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static final class Fx {
        final StripeWebhookEntitlements.InMemoryStore store = new StripeWebhookEntitlements.InMemoryStore();
        final FakeStripe stripe = new FakeStripe();
        long now = 1700000000L;
        final StripeWebhookEntitlements svc;

        Fx() {
            this(0, SECRET);
        }

        Fx(long grace, String secret) {
            Map<String, String> plans = new HashMap<>();
            plans.put("price_pro_monthly", "pro");
            plans.put("price_team_monthly", "team");
            Set<String> users = Set.of("user_1", "user_2", "user_3");
            svc = new StripeWebhookEntitlements(store, secret, plans, stripe, users::contains, grace, () -> now);
        }

        /** Signs body at the current time and delivers it. */
        Map<String, Object> deliver(String body) {
            return svc.handleWebhook(body, StripeWebhookEntitlements.signPayload(body, SECRET, now));
        }
    }

    /** A subscription object. userId null leaves out metadata; price null leaves out items; cpe null leaves it out. */
    static String sub(String id, String customer, String status, Long cpe, boolean cancel, String userId, String price) {
        StringBuilder sb = new StringBuilder("{\"id\":\"" + id + "\",\"customer\":\"" + customer + "\",\"status\":\"" + status + "\"");
        if (cpe != null) sb.append(",\"current_period_end\":").append(cpe);
        sb.append(",\"cancel_at_period_end\":").append(cancel);
        if (userId != null) sb.append(",\"metadata\":{\"user_id\":\"").append(userId).append("\"}");
        if (price != null) sb.append(",\"items\":{\"data\":[{\"price\":{\"id\":\"").append(price).append("\"}}]}");
        return sb.append("}").toString();
    }

    /** Test helper: an event body with id, type, created (raw JSON) and data.object. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static String event(String id, String type, String created, String object) {
        return "{\"id\":\"" + id + "\",\"type\":\"" + type + "\",\"created\":" + created + ",\"data\":{\"object\":" + object + "}}";
    }

    /** Test helper: true for {status 200, received: true, result: want}. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static boolean result(Map<String, Object> r, String want) {
        return Integer.valueOf(200).equals(r.get("status")) && Boolean.TRUE.equals(r.get("received")) && want.equals(r.get("result"));
    }

    /** Test helper: true for a refusal with this status and error. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static boolean refusal(Map<String, Object> r, int status, String error) {
        return Integer.valueOf(status).equals(r.get("status")) && error.equals(r.get("error"));
    }

    /** Test helper: an expected get_entitlement answer. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static Map<String, Object> ent(boolean entitled, String plan, String status, Long cpe, boolean cancel) {
        Map<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("entitled", entitled);
        m.put("plan", plan);
        m.put("status", status);
        m.put("current_period_end", cpe);
        m.put("cancel_at_period_end", cancel);
        return m;
    }

    static final Map<String, Object> NONE = ent(false, null, "none", null, false);

    // ------------------------------------------------------------------------------------------------ tests
    // STRIPEWH-01
    /** The spec's body, header, applied answer and entitlement. */
    static void testVector() throws Exception {
        byte[] b = BODY.getBytes(StandardCharsets.UTF_8);
        check(b.length == 317, "317 bytes, got " + b.length);
        StringBuilder h = new StringBuilder();
        for (byte x : MessageDigest.getInstance("SHA-256").digest(b)) h.append(String.format("%02x", x & 0xff));
        check(h.toString().equals("f2e8a2d52e46e4642dde0390c9def15047ff2178a8d33a9928698aca132cbe88"), "body sha256");
        String header = StripeWebhookEntitlements.signPayload(b, SECRET, 1700000000L);
        check(header.equals("t=1700000000,v1=5bca2d8b83d83f9a52f3b25714245817b15ae87b9e73abcca2c7a514977a8ae5"), "header " + header);
        Fx fx = new Fx();
        check(result(fx.svc.handleWebhook(b, header), "applied"), "applied");
        check(fx.svc.getEntitlement("user_1").equals(ent(true, "pro", "active", 1702592000L, false)), "entitlement " + fx.svc.getEntitlement("user_1"));
    }

    // STRIPEWH-02
    /** Every bad signature is 400 invalid_signature and stores nothing. */
    static void testInvalidSignatures() {
        Fx fx = new Fx();
        String good = StripeWebhookEntitlements.signPayload(BODY, SECRET, fx.now);
        String v1 = good.substring(good.indexOf("v1=") + 3);
        String changed = BODY.replace("user_1", "user_2");
        String[][] cases = {
            {BODY, StripeWebhookEntitlements.signPayload(BODY, "whsec_" + "another_secret_value", fx.now)},
            {changed, good},
            {BODY, "t=" + (fx.now + 1) + ",v1=" + v1},
            {BODY, "t=" + fx.now},
            {BODY, "t=" + fx.now + ",v1=" + v1.toUpperCase()},
            {BODY, "t=" + fx.now + ",v1=" + v1.substring(1)},
            {BODY, "t=" + fx.now + ",v0=" + v1},
            {BODY, "t=" + fx.now + ",t=" + fx.now + ",v1=" + v1},
            {BODY, "t=abc,v1=" + v1},
            {BODY, "x".repeat(4097)}};
        for (String[] c : cases) {
            check(refusal(fx.svc.handleWebhook(c[0], c[1]), 400, "invalid_signature"), "invalid_signature for " + c[1]);
        }
        check(fx.store.eventCount() == 0 && fx.store.getSub("sub_test_0001") == null, "nothing stored");
    }

    // STRIPEWH-03
    /** A missing or empty header is 400 missing_signature; a short secret is 503 for every call. */
    static void testMissingHeaderAndShortSecret() {
        Fx fx = new Fx();
        check(refusal(fx.svc.handleWebhook(BODY, null), 400, "missing_signature"), "null header");
        check(refusal(fx.svc.handleWebhook(BODY, ""), 400, "missing_signature"), "empty header");
        String shortSecret = "whsec_" + "short";
        Fx s = new Fx(0, shortSecret);
        check(refusal(s.svc.handleWebhook(BODY, StripeWebhookEntitlements.signPayload(BODY, shortSecret, s.now)), 503, "webhook_not_configured"), "short secret, good signature");
        check(refusal(s.svc.handleWebhook(BODY, null), 503, "webhook_not_configured"), "short secret, no header");
        check(refusal(s.svc.handleWebhook(BODY, "t=1,v1=00"), 503, "webhook_not_configured"), "short secret, bad header");
        check(s.store.eventCount() == 0, "nothing stored");
    }

    // STRIPEWH-04
    /** 300 s old accepted; 301 s old and 301 s ahead refused (the spec's four clocks). */
    static void testTolerance() {
        String header = StripeWebhookEntitlements.signPayload(BODY, SECRET, 1700000000L);
        long[][] cases = {{1700000300L, 1}, {1700000301L, 0}, {1699999700L, 1}, {1699999699L, 0}};
        for (long[] c : cases) {
            Fx fx = new Fx();
            fx.now = c[0];
            Map<String, Object> r = fx.svc.handleWebhook(BODY, header);
            if (c[1] == 1) check(result(r, "applied"), "accepted at " + c[0] + " " + r);
            else check(refusal(r, 400, "timestamp_out_of_tolerance"), "refused at " + c[0] + " " + r);
        }
    }

    // STRIPEWH-05
    /** Two v1 values: accepted when the second is right, with a v0 element and spaces after the commas. */
    static void testTwoV1Values() {
        Fx fx = new Fx();
        String good = StripeWebhookEntitlements.signPayload(BODY, SECRET, fx.now);
        String v1 = good.substring(good.indexOf("v1=") + 3);
        String header = "t=" + fx.now + ", v0=" + "0".repeat(64) + ", v1=" + "a".repeat(64) + ", v1=" + v1;
        check(result(fx.svc.handleWebhook(BODY, header), "applied"), "second v1 accepted");
    }

    // STRIPEWH-06
    /** Signed bodies that are not valid events are 400 invalid_payload and their id is not recorded. */
    static void testInvalidPayloads() {
        Fx fx = new Fx();
        String obj = sub("sub_a", "cus_a", "active", 1702592000L, false, "user_1", "price_pro_monthly");
        String[] bad = {
            "not json",
            "[1,2]",
            "{\"id\":\"evt_1\"} trailing",
            event("xyz_1", "customer.subscription.updated", "1700000000", obj),
            "{\"type\":\"customer.subscription.updated\",\"created\":1700000000,\"data\":{\"object\":" + obj + "}}",
            "{\"id\":\"evt_2\",\"created\":1700000000,\"data\":{\"object\":" + obj + "}}",
            event("evt_3", "customer.subscription.updated", "true", obj),
            event("evt_4", "customer.subscription.updated", "\"1700000000\"", obj),
            event("evt_5", "customer.subscription.updated", "1700000000.5", obj),
            event("evt_6", "customer.subscription.updated", "-1", obj),
            event("evt_7", "customer.subscription.updated", "100000000000", obj),
            event("evt_8", "customer.subscription.updated", "1e400", obj),
            "{\"id\":\"evt_9\",\"type\":\"customer.subscription.updated\",\"created\":1700000000}",
            event("evt_10", "customer.subscription.updated", "1700000000", "[]"),
            "﻿" + event("evt_11", "customer.subscription.updated", "1700000000", obj)};
        for (String b : bad) check(refusal(fx.deliver(b), 400, "invalid_payload"), "invalid_payload for " + b);
        byte[] badUtf8 = event("evt_12", "x", "1700000000", "{}").replace("x", "ÿ").getBytes(StandardCharsets.ISO_8859_1);
        check(refusal(fx.svc.handleWebhook(badUtf8, StripeWebhookEntitlements.signPayload(badUtf8, SECRET, fx.now)), 400, "invalid_payload"), "invalid UTF-8");
        check(fx.store.eventCount() == 0, "no id recorded");
        check(result(fx.deliver(event("evt_ok", "customer.subscription.updated", "1700000000.0", obj)), "applied"), "created 1700000000.0 accepted");
        check(fx.store.getEvent("evt_ok").created() == 1700000000L, "created stored as a whole number");
    }

    // STRIPEWH-07
    /** A created event with an active, known price grants; before it the answer is "none"; other users unchanged. */
    static void testCreatedGrants() {
        Fx fx = new Fx();
        check(fx.svc.getEntitlement("user_1").equals(NONE), "none before");
        fx.deliver(event("evt_o", "customer.subscription.created", "1699999000", sub("sub_o", "cus_o", "active", 1702000000L, false, "user_2", "price_team_monthly")));
        Map<String, Object> other = fx.svc.getEntitlement("user_2");
        check(result(fx.deliver(event("evt_c", "customer.subscription.created", "1700000000",
                sub("sub_c", "cus_c", "active", 1702592000L, true, "user_1", "price_pro_monthly"))), "applied"), "applied");
        check(fx.svc.getEntitlement("user_1").equals(ent(true, "pro", "active", 1702592000L, true)), "granted " + fx.svc.getEntitlement("user_1"));
        check(fx.svc.getEntitlement("user_2").equals(other) && Boolean.TRUE.equals(other.get("entitled")), "other user unchanged");
        check(fx.svc.getEntitlement("user_3").equals(NONE), "a third user stays none");
    }

    // STRIPEWH-08
    /** The same event id twice: duplicate, the row unchanged. */
    static void testDuplicate() {
        Fx fx = new Fx();
        check(result(fx.deliver(BODY), "applied"), "first");
        StripeWebhookEntitlements.SubRow r = fx.store.getSub("sub_test_0001");
        fx.now += 10;
        check(result(fx.deliver(BODY), "duplicate"), "second is duplicate");
        check(fx.store.getSub("sub_test_0001").equals(r), "row unchanged");
    }

    // STRIPEWH-09
    /** Older events are stale; at equal created, created < updated < deleted; an equal updated pair fetches from Stripe. */
    static void testOutOfOrder() {
        Fx fx = new Fx();
        String a = sub("sub_9", "cus_9", "active", 1702592000L, false, "user_1", "price_pro_monthly");
        check(result(fx.deliver(event("evt_200", "customer.subscription.updated", "200", a)), "applied"), "created 200");
        check(result(fx.deliver(event("evt_100", "customer.subscription.updated", "100", sub("sub_9", "cus_9", "past_due", 1702592000L, false, "user_1", "price_pro_monthly"))), "stale"), "created 100 is stale");
        check(fx.store.getSub("sub_9").status().equals("active") && fx.store.getSub("sub_9").eventAt() == 200, "nothing changed");
        check(result(fx.deliver(event("evt_c200", "customer.subscription.created", "200", sub("sub_9", "cus_9", "incomplete", 1702592000L, false, "user_1", "price_pro_monthly"))), "stale"),
                "a created event does not overwrite an updated one of the same second");
        check(fx.stripe.calls.isEmpty(), "no fetch for a lower rank");
        fx.stripe.subs.put("sub_9", sub("sub_9", "cus_9", "trialing", 1703000000L, true, "user_1", "price_team_monthly"));
        check(result(fx.deliver(event("evt_u200", "customer.subscription.updated", "200", sub("sub_9", "cus_9", "past_due", 1702592000L, false, "user_1", "price_pro_monthly"))), "applied"), "equal updated");
        check(fx.stripe.calls.equals(List.of("sub_9")), "fetched through the client");
        StripeWebhookEntitlements.SubRow r = fx.store.getSub("sub_9");
        check(r.status().equals("trialing") && r.currentPeriodEnd() == 1703000000L && r.cancelAtPeriodEnd() && "team".equals(r.plan()), "fetched state " + r);
        check(result(fx.deliver(event("evt_d200", "customer.subscription.deleted", "200", sub("sub_9", "cus_9", "active", 1703000000L, false, "user_1", "price_team_monthly"))), "applied"), "deleted overwrites");
        check(fx.store.getSub("sub_9").status().equals("canceled") && fx.store.getSub("sub_9").eventRank() == 2, "canceled");
        check(result(fx.deliver(event("evt_c200b", "customer.subscription.created", "200", a)), "stale")
                && result(fx.deliver(event("evt_u200b", "customer.subscription.updated", "200", a)), "stale"), "deleted beats created and updated");
        check(fx.stripe.calls.size() == 1, "no further fetch");
    }

    // STRIPEWH-10
    /** past_due, unpaid and canceled end access at once; the period end decides for active; the grace extends it. */
    static void testEntitlementEnds() {
        for (String st : new String[] {"past_due", "unpaid", "canceled"}) {
            Fx fx = new Fx();
            fx.deliver(event("evt_a", "customer.subscription.created", "100", sub("sub_x", "cus_x", "active", 1702592000L, false, "user_1", "price_pro_monthly")));
            check(Boolean.TRUE.equals(fx.svc.getEntitlement("user_1").get("entitled")), "entitled first");
            fx.deliver(event("evt_b", "customer.subscription.updated", "200", sub("sub_x", "cus_x", st, 1702592000L, false, "user_1", "price_pro_monthly")));
            Map<String, Object> e = fx.svc.getEntitlement("user_1");
            check(e.equals(ent(false, null, st, 1702592000L, false)), st + " ends access " + e);
        }
        Fx fx = new Fx();
        fx.deliver(event("evt_a", "customer.subscription.created", "100", sub("sub_x", "cus_x", "active", fx.now, false, "user_1", "price_pro_monthly")));
        check(Boolean.FALSE.equals(fx.svc.getEntitlement("user_1").get("entitled")), "period end == now: not entitled");
        fx.deliver(event("evt_b", "customer.subscription.updated", "200", sub("sub_x", "cus_x", "active", fx.now + 1, false, "user_1", "price_pro_monthly")));
        check(Boolean.TRUE.equals(fx.svc.getEntitlement("user_1").get("entitled")), "period end one second ahead: entitled");
        fx.now += 1;
        check(Boolean.FALSE.equals(fx.svc.getEntitlement("user_1").get("entitled")), "computed from the clock at every call");
        Fx g = new Fx(60, SECRET);
        long end = g.now;
        g.deliver(event("evt_a", "customer.subscription.created", "100", sub("sub_x", "cus_x", "active", end, false, "user_1", "price_pro_monthly")));
        g.now = end + 59;
        check(Boolean.TRUE.equals(g.svc.getEntitlement("user_1").get("entitled")), "grace: 59 s after the end");
        g.now = end + 60;
        check(Boolean.FALSE.equals(g.svc.getEntitlement("user_1").get("entitled")), "grace: 60 s after the end");
    }

    // STRIPEWH-11
    /** The top-level period end, else the largest item period end; neither keeps the stored value. */
    static void testPeriodEnd() {
        Fx fx = new Fx();
        String itemsOnly = "{\"id\":\"sub_p\",\"customer\":\"cus_p\",\"status\":\"active\",\"metadata\":{\"user_id\":\"user_1\"},"
                + "\"items\":{\"data\":[{\"price\":{\"id\":\"price_pro_monthly\"},\"current_period_end\":1702000000},"
                + "{\"price\":{\"id\":\"price_team_monthly\"},\"current_period_end\":1703000000}]}}";
        fx.deliver(event("evt_1", "customer.subscription.created", "100", itemsOnly));
        check(fx.store.getSub("sub_p").currentPeriodEnd() == 1703000000L, "largest item period end");
        fx.deliver(event("evt_2", "customer.subscription.updated", "200", sub("sub_p", "cus_p", "active", 1704000000L, false, "user_1", "price_pro_monthly")));
        check(fx.store.getSub("sub_p").currentPeriodEnd() == 1704000000L, "top-level period end");
        fx.deliver(event("evt_3", "customer.subscription.updated", "300", sub("sub_p", "cus_p", "active", null, true, "user_1", "price_pro_monthly")));
        StripeWebhookEntitlements.SubRow r = fx.store.getSub("sub_p");
        check(r.currentPeriodEnd() == 1704000000L && r.cancelAtPeriodEnd() && r.eventAt() == 300, "neither keeps the stored period end");
    }

    // STRIPEWH-12
    /** ignored cases (ids still recorded); a deleted or a price-change event for a stored row still applies. */
    static void testIgnored() {
        Fx fx = new Fx();
        String[][] cases = {
            {"evt_i1", "customer.subscription.created", sub("sub_i1", "cus_i", "active", 1702592000L, false, "user_1", "price_unknown")},
            {"evt_i2", "customer.subscription.created", sub("sub_i2", "cus_i", "active", 1702592000L, false, "ghost", "price_pro_monthly")},
            {"evt_i3", "invoice.paid", sub("sub_i3", "cus_i", "active", 1702592000L, false, "user_1", "price_pro_monthly")},
            {"evt_i4", "customer.subscription.created", sub("sub-bad!", "cus_i", "active", 1702592000L, false, "user_1", "price_pro_monthly")}};
        for (String[] c : cases) {
            check(result(fx.deliver(event(c[0], c[1], "100", c[2])), "ignored"), "ignored " + c[0]);
            check(fx.store.getEvent(c[0]) != null && "ignored".equals(fx.store.getEvent(c[0]).result()), "recorded " + c[0]);
        }
        check(fx.svc.getEntitlement("user_1").equals(NONE) && fx.svc.getEntitlement("ghost").equals(NONE), "no entitlement change");
        fx.deliver(event("evt_g", "customer.subscription.created", "100", sub("sub_g", "cus_g", "active", 1702592000L, false, "user_1", "price_pro_monthly")));
        Fx gone = new Fx();
        gone.store.putSub(fx.store.getSub("sub_g"));
        StripeWebhookEntitlements noPlans = new StripeWebhookEntitlements(gone.store, SECRET, Map.of(), gone.stripe, u -> true, 0, () -> gone.now);
        String del = event("evt_del", "customer.subscription.deleted", "200", sub("sub_g", "cus_g", "active", 1702592000L, false, "user_1", "price_pro_monthly"));
        check(result(noPlans.handleWebhook(del, StripeWebhookEntitlements.signPayload(del, SECRET, gone.now)), "applied"), "deleted applies when the price left price_plans");
        check(gone.store.getSub("sub_g").status().equals("canceled"), "canceled");
        check(result(fx.deliver(event("evt_mv", "customer.subscription.updated", "200", sub("sub_g", "cus_g", "active", 1702592000L, false, "user_1", "price_unknown"))), "applied"), "moved to an unknown price");
        StripeWebhookEntitlements.SubRow r = fx.store.getSub("sub_g");
        check("price_unknown".equals(r.priceId()) && r.plan() == null, "price kept, plan null");
        check(Boolean.FALSE.equals(fx.svc.getEntitlement("user_1").get("entitled")), "no longer entitled");
    }

    // STRIPEWH-13
    /** checkout.session.completed fetches the subscription; a raising client is 500, unrecorded, and a retry applies. */
    static void testCheckoutSession() {
        Fx fx = new Fx();
        fx.stripe.subs.put("sub_ck", sub("sub_ck", "cus_ck", "active", 1702592000L, false, null, "price_pro_monthly"));
        String session = "{\"id\":\"cs_1\",\"mode\":\"subscription\",\"subscription\":\"sub_ck\",\"client_reference_id\":\"user_2\"}";
        String body = event("evt_ck", "checkout.session.completed", "100", session);
        fx.stripe.raise = true;
        check(refusal(fx.deliver(body), 500, "processing_failed"), "client raises -> 500");
        check(fx.store.getEvent("evt_ck") == null && fx.store.getSub("sub_ck") == null, "event id not recorded, nothing written");
        fx.stripe.raise = false;
        check(result(fx.deliver(body), "applied"), "the same event delivered again applies");
        check(fx.stripe.calls.equals(List.of("sub_ck", "sub_ck")), "fetched by the session's subscription id, once per delivery");
        check(fx.store.getSub("sub_ck").userId().equals("user_2"), "user is client_reference_id");
        check(fx.svc.getEntitlement("user_2").equals(ent(true, "pro", "active", 1702592000L, false)), "entitled");
        check(result(fx.deliver(event("evt_pay", "checkout.session.completed", "100", "{\"mode\":\"payment\",\"subscription\":\"sub_ck\"}")), "ignored"), "payment mode ignored");
        check(result(fx.deliver(event("evt_old", "checkout.session.completed", "50", session)), "stale") && fx.stripe.calls.size() == 2, "older checkout: stale without a fetch");
    }

    // STRIPEWH-14
    /** Two subscriptions for one user; user lookup through the stored row or the customer; a row never moves users. */
    static void testTwoSubscriptionsAndUserLookup() {
        Fx fx = new Fx();
        fx.deliver(event("evt_1", "customer.subscription.created", "100", sub("sub_one", "cus_u1", "active", 1702000000L, false, "user_1", "price_pro_monthly")));
        fx.deliver(event("evt_2", "customer.subscription.created", "110", sub("sub_two", "cus_u1", "active", 1701000000L, false, "user_1", "price_team_monthly")));
        check(fx.svc.getEntitlement("user_1").equals(ent(true, "pro", "active", 1702000000L, false)), "greatest period end wins");
        check(result(fx.deliver(event("evt_3", "customer.subscription.deleted", "200", sub("sub_one", "cus_u1", "active", 1702000000L, false, null, "price_pro_monthly"))), "applied"),
                "deleted without metadata finds the user through the stored subscription");
        check(fx.svc.getEntitlement("user_1").equals(ent(true, "team", "active", 1701000000L, false)), "the other subscription still entitles");
        check(result(fx.deliver(event("evt_4", "customer.subscription.created", "300", sub("sub_three", "cus_u1", "active", 1705000000L, false, null, "price_pro_monthly"))), "applied"),
                "a new subscription without metadata finds its user through the customer id");
        check(fx.store.getSub("sub_three").userId().equals("user_1"), "user from the customer");
        check(result(fx.deliver(event("evt_5", "customer.subscription.updated", "400", sub("sub_two", "cus_u1", "active", 1701000000L, false, "user_2", "price_team_monthly"))), "applied"), "names another user");
        check(fx.store.getSub("sub_two").userId().equals("user_1") && fx.svc.getEntitlement("user_2").equals(NONE), "the subscription never moves");
        fx.deliver(event("evt_6", "customer.subscription.created", "500", sub("sub_four", "cus_shared", "active", 1705000000L, false, "user_2", "price_pro_monthly")));
        fx.store.putSub(new StripeWebhookEntitlements.SubRow("sub_five", "user_3", "cus_shared", "price_pro_monthly", "pro", "active", 1705000000L, false, 500, 0, fx.now));
        check(result(fx.deliver(event("evt_7", "customer.subscription.created", "600", sub("sub_six", "cus_shared", "active", 1705000000L, false, null, "price_pro_monthly"))), "ignored"),
                "a customer shared by two users finds no user");
    }
}

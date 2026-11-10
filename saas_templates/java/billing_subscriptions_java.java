package com.saas.billing;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.stripe.exception.SignatureVerificationException;
import com.stripe.exception.StripeException;
import com.stripe.model.Subscription;
import com.stripe.model.SubscriptionItem;
import com.stripe.net.RequestOptions;
import com.stripe.net.Webhook;
import com.stripe.param.SubscriptionCreateParams;
import com.stripe.param.SubscriptionUpdateParams;

import java.sql.*;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Billing and subscriptions on Stripe (spec: GEMINI_DISPATCH_MASTER_SPEC, template #4): create a subscription,
 * change plan with a proration credit, queue a refund (never executed automatically), and process Stripe webhooks
 * once each (signature verified, idempotent by Stripe event id).
 *
 * Stripe sits behind {@link StripeGateway}: {@link StripeSdkGateway} calls the real API with stripe-java;
 * {@link InMemoryStripeGateway} is a deterministic fake for tests and local runs (no network). The webhook
 * signature check is local HMAC work (stripe-java's Webhook.Signature, a constant-time comparison) and needs no
 * network. Secrets come from configuration (environment variable, else JVM system property), never from code.
 *
 * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. It did not compile against stripe-java 28.1.0
 * (addItems, a static Subscription.update and Webhook.constructEvent returning JsonObject do not exist). Also fixed:
 * the webhook secret was read only from the environment; "ON DUPLICATE KEY UPDATE" is MySQL-only; a
 * subscription.updated event without a lookup key wiped the tier to null and the event's items list was read in
 * a shape real Stripe events do not have; refunds could add up to more than the invoice; the processed-event
 * record and its effects were not one transaction; Stripe.apiKey was set globally at class load.
 * Touches: the database (subscriptions, invoices, refunds, events, audit_log); Stripe's API (money) through
 * StripeSdkGateway only.
 */
public class BillingService {

    private static final DateTimeFormatter ISO_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);

    /** Stripe price id per tier. Override with STRIPE_PRICE_SOLO / _TEAM / _ENTERPRISE; placeholders otherwise. */
    public static final Map<String, String> PRICE_IDS;
    /** Monthly list price per tier in cents (spec: Solo $9.99, Team $19.99, Enterprise $99), for proration. */
    public static final Map<String, Long> TIER_PRICE_CENTS;

    static {
        Map<String, String> prices = new HashMap<>();
        prices.put("solo", config("STRIPE_PRICE_SOLO", "price_1UI_solo_placeholder"));
        prices.put("team", config("STRIPE_PRICE_TEAM", "price_1UI_team_placeholder"));
        prices.put("enterprise", config("STRIPE_PRICE_ENTERPRISE", "price_1UI_enterprise_placeholder"));
        PRICE_IDS = Collections.unmodifiableMap(prices);

        Map<String, Long> cents = new HashMap<>();
        cents.put("solo", 999L);
        cents.put("team", 1999L);
        cents.put("enterprise", 9900L);
        TIER_PRICE_CENTS = Collections.unmodifiableMap(cents);
    }

    /** Seconds of clock skew accepted on a webhook signature timestamp (Stripe's default). */
    private static final long WEBHOOK_TOLERANCE_SECONDS = 300;

    private final Connection connection;
    private final StripeGateway stripe;
    private final String webhookSecret;
    private final Clock clock;

    /**
     * Production constructor: real Stripe (key from STRIPE_SECRET_KEY), webhook secret from
     * STRIPE_WEBHOOK_SECRET, system UTC clock. Each setting is read from the environment, else from a JVM system
     * property of the same name.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the webhook secret was read from the
     * environment only, and the API key was set on the global Stripe.apiKey. Touches: nothing until called.
     */
    public BillingService(Connection connection) {
        this(connection, new StripeSdkGateway(config("STRIPE_SECRET_KEY", null)),
                config("STRIPE_WEBHOOK_SECRET", null), Clock.systemUTC());
    }

    /**
     * Full constructor: any StripeGateway (real or InMemoryStripeGateway), the webhook signing secret and a clock.
     * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP so tests run without network or wall-clock
     * dependence. Touches: nothing until called.
     */
    public BillingService(Connection connection, StripeGateway stripe, String webhookSecret, Clock clock) {
        this.connection = Objects.requireNonNull(connection, "connection");
        this.stripe = Objects.requireNonNull(stripe, "stripe");
        this.webhookSecret = webhookSecret;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Reads a setting from the environment, else from a JVM system property, else the default.
     * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process environment (read only).
     */
    static String config(String name, String defaultValue) {
        String value = System.getenv(name);
        if (value == null || value.isEmpty()) value = System.getProperty(name);
        return (value == null || value.isEmpty()) ? defaultValue : value;
    }

    /**
     * Creates the five tables (H2 and MySQL compatible).
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: dropped MySQL-only "ON UPDATE
     * CURRENT_TIMESTAMP" (updated_at is set by every UPDATE here). Touches: the database.
     */
    public static void initializeSchema(Connection conn) throws SQLException {
        String ddl = "CREATE TABLE IF NOT EXISTS subscriptions (\n" +
                "    id BIGINT AUTO_INCREMENT PRIMARY KEY,\n" +
                "    stripe_subscription_id VARCHAR(255) UNIQUE NOT NULL,\n" +
                "    customer_id VARCHAR(255) NOT NULL,\n" +
                "    tier VARCHAR(50) NOT NULL,\n" +
                "    status VARCHAR(50) NOT NULL DEFAULT 'active',\n" +
                "    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,\n" +
                "    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,\n" +
                "    cancelled_at TIMESTAMP NULL\n" +
                ");\n" +
                "CREATE TABLE IF NOT EXISTS invoices (\n" +
                "    id BIGINT AUTO_INCREMENT PRIMARY KEY,\n" +
                "    stripe_invoice_id VARCHAR(255) UNIQUE NOT NULL,\n" +
                "    customer_id VARCHAR(255) NOT NULL,\n" +
                "    amount BIGINT NOT NULL,\n" +
                "    status VARCHAR(50) NOT NULL,\n" +
                "    paid_at TIMESTAMP NULL\n" +
                ");\n" +
                "CREATE TABLE IF NOT EXISTS refunds (\n" +
                "    id BIGINT AUTO_INCREMENT PRIMARY KEY,\n" +
                "    invoice_id BIGINT NOT NULL,\n" +
                "    amount BIGINT NOT NULL,\n" +
                "    status VARCHAR(50) NOT NULL DEFAULT 'queued',\n" +
                "    reason VARCHAR(255) NOT NULL,\n" +
                "    created_by VARCHAR(255) NOT NULL,\n" +
                "    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,\n" +
                "    executed_at TIMESTAMP NULL,\n" +
                "    FOREIGN KEY (invoice_id) REFERENCES invoices(id)\n" +
                ");\n" +
                "CREATE TABLE IF NOT EXISTS events (\n" +
                "    id BIGINT AUTO_INCREMENT PRIMARY KEY,\n" +
                "    stripe_event_id VARCHAR(255) UNIQUE NOT NULL,\n" +
                "    event_type VARCHAR(255) NOT NULL,\n" +
                "    processed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP\n" +
                ");\n" +
                "CREATE TABLE IF NOT EXISTS audit_log (\n" +
                "    id BIGINT AUTO_INCREMENT PRIMARY KEY,\n" +
                "    action VARCHAR(255) NOT NULL,\n" +
                "    customer_id VARCHAR(255),\n" +
                "    subscription_id VARCHAR(255),\n" +
                "    invoice_id VARCHAR(255),\n" +
                "    tier VARCHAR(50),\n" +
                "    old_tier VARCHAR(50),\n" +
                "    new_tier VARCHAR(50),\n" +
                "    amount BIGINT,\n" +
                "    reason VARCHAR(255),\n" +
                "    proration_credits BIGINT,\n" +
                "    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP\n" +
                ");";

        try (Statement stmt = conn.createStatement()) {
            for (String sql : ddl.split(";")) {
                if (!sql.trim().isEmpty()) {
                    stmt.execute(sql.trim());
                }
            }
        }
    }

    /**
     * Flow 1: create a subscription for a Stripe customer on a tier.
     * Input: Stripe customer id, tier (solo|team|enterprise). Output: {success, subscription_id, tier, status,
     * next_billing_date} or {error: invalid_tier|stripe_error|db_error, message}.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: Stripe goes through the gateway; times come
     * from the clock. Touches: Stripe (creates a billable subscription), the database.
     */
    public JsonObject createSubscription(String customerId, String tier) {
        if (tier == null || !PRICE_IDS.containsKey(tier)) {
            return errorResponse("invalid_tier", "Invalid tier: " + tier);
        }
        if (customerId == null || customerId.isEmpty()) {
            return errorResponse("invalid_customer", "customer_id is required");
        }

        try {
            StripeSubscription subscription = stripe.createSubscription(customerId, PRICE_IDS.get(tier));

            String sql = "INSERT INTO subscriptions (stripe_subscription_id, customer_id, tier, status, created_at, updated_at) VALUES (?, ?, ?, 'active', ?, ?)";
            Timestamp now = now();
            try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
                pstmt.setString(1, subscription.id);
                pstmt.setString(2, customerId);
                pstmt.setString(3, tier);
                pstmt.setTimestamp(4, now);
                pstmt.setTimestamp(5, now);
                pstmt.executeUpdate();
            }

            logAudit("subscription_created", customerId, subscription.id, null, tier, null, null, null, null, null);

            JsonObject response = new JsonObject();
            response.addProperty("success", true);
            response.addProperty("subscription_id", subscription.id);
            response.addProperty("tier", tier);
            response.addProperty("status", "active");
            response.addProperty("next_billing_date",
                    ISO_FORMATTER.format(Instant.ofEpochSecond(subscription.currentPeriodEnd)));
            return response;

        } catch (StripeException e) {
            return errorResponse("stripe_error", e.getMessage());
        } catch (SQLException e) {
            return errorResponse("db_error", e.getMessage());
        }
    }

    /**
     * Flow 2: move a subscription to another tier. Stripe prorates; the response reports the credit for the
     * unused part of the current period at the old tier's price.
     * Input: Stripe subscription id, new tier. Output: {success, subscription_id, old_tier, new_tier,
     * effective_date, proration_credit (cents)} or {error: invalid_tier (400) | not_found |
     * subscription_item_ambiguous (409) | stripe_error | db_error}.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the Stripe update did not compile and the
     * credit was always 0. Amended the same day (BILL-03, spec flow 2): the subscription is retrieved first, one
     * that does not have exactly one item is refused with subscription_item_ambiguous before any update, and the
     * update names that item's id with the new price and proration_behavior create_prorations (a bare price ADDS a
     * second item and bills both plans). Touches: Stripe (changes what the customer is billed), the database.
     */
    public JsonObject changePlan(String subscriptionId, String newTier) {
        if (newTier == null || !PRICE_IDS.containsKey(newTier)) {
            return errorResponse("invalid_tier", "Invalid tier: " + newTier);
        }

        try {
            String oldTier;
            String customerId;
            String sql = "SELECT tier, customer_id FROM subscriptions WHERE stripe_subscription_id = ?";
            try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
                pstmt.setString(1, subscriptionId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (!rs.next()) {
                        return errorResponse("not_found", "Subscription not found");
                    }
                    oldTier = rs.getString("tier");
                    customerId = rs.getString("customer_id");
                }
            }

            StripeSubscription current = stripe.retrieveSubscription(subscriptionId);
            if (current.itemIds.size() != 1) {
                return errorResponse("subscription_item_ambiguous",
                        "Subscription has " + current.itemIds.size() + " items; expected exactly one");
            }
            StripeSubscription updated = stripe.updateSubscriptionItem(subscriptionId, current.itemIds.get(0), PRICE_IDS.get(newTier));
            Instant now = clock.instant();
            long prorationCredit = prorationCredit(oldTier, updated, now);

            String updateSql = "UPDATE subscriptions SET tier = ?, updated_at = ? WHERE stripe_subscription_id = ?";
            try (PreparedStatement pstmt = connection.prepareStatement(updateSql)) {
                pstmt.setString(1, newTier);
                pstmt.setTimestamp(2, Timestamp.from(now));
                pstmt.setString(3, subscriptionId);
                pstmt.executeUpdate();
            }

            logAudit("plan_changed", customerId, subscriptionId, null, null, oldTier, newTier, null, null, prorationCredit);

            JsonObject response = new JsonObject();
            response.addProperty("success", true);
            response.addProperty("subscription_id", subscriptionId);
            response.addProperty("old_tier", oldTier);
            response.addProperty("new_tier", newTier);
            response.addProperty("effective_date", ISO_FORMATTER.format(now));
            response.addProperty("proration_credit", prorationCredit);
            return response;

        } catch (StripeException e) {
            return errorResponse("stripe_error", e.getMessage());
        } catch (SQLException e) {
            return errorResponse("db_error", e.getMessage());
        }
    }

    /**
     * Credit in cents for the unused part of the current period at the old tier's price:
     * floor(price * remaining / period). 0 when the period is unknown or over.
     * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (spec: "proration calculated"). Pure.
     */
    static long prorationCredit(String oldTier, StripeSubscription period, Instant now) {
        Long price = TIER_PRICE_CENTS.get(oldTier);
        if (price == null || period == null) return 0;
        long length = period.currentPeriodEnd - period.currentPeriodStart;
        long remaining = period.currentPeriodEnd - now.getEpochSecond();
        if (length <= 0 || remaining <= 0) return 0;
        remaining = Math.min(remaining, length);
        return Math.floorDiv(price * remaining, length);
    }

    /**
     * Flow 3: queue a refund for a paid invoice. Refunds are only queued here, never sent to Stripe.
     * Input: Stripe invoice id, amount in cents (> 0), reason, createdBy (the authenticated admin's id, taken
     * from the server-side session, never from the request body). Output: {success, refund_id, status: queued,
     * amount, reason} or {error: invalid_amount|not_found|invalid_invoice_status|refund_exceeds_invoice|db_error}.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: refunds already queued or executed for the
     * invoice now count against its amount (two refunds could add up to more than was paid); non-positive
     * amounts are rejected. Touches: the database (money owed back to a customer).
     */
    public JsonObject queueRefund(String invoiceId, long amount, String reason, String createdBy) {
        if (amount <= 0) {
            return errorResponse("invalid_amount", "Refund amount must be positive");
        }
        try {
            long invoiceDbId;
            long invoiceAmount;
            String invoiceStatus;
            String sql = "SELECT id, amount, status FROM invoices WHERE stripe_invoice_id = ?";
            try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
                pstmt.setString(1, invoiceId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (!rs.next()) {
                        return errorResponse("not_found", "Invoice not found");
                    }
                    invoiceDbId = rs.getLong("id");
                    invoiceAmount = rs.getLong("amount");
                    invoiceStatus = rs.getString("status");
                }
            }

            if (!"succeeded".equals(invoiceStatus)) {
                return errorResponse("invalid_invoice_status", "Invoice is not in succeeded status");
            }

            long alreadyRefunded = 0;
            String sumSql = "SELECT COALESCE(SUM(amount), 0) FROM refunds WHERE invoice_id = ? AND status <> 'failed'";
            try (PreparedStatement pstmt = connection.prepareStatement(sumSql)) {
                pstmt.setLong(1, invoiceDbId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) alreadyRefunded = rs.getLong(1);
                }
            }
            if (amount > invoiceAmount - alreadyRefunded) {
                return errorResponse("refund_exceeds_invoice", "Refund amount exceeds invoice amount");
            }

            String insertSql = "INSERT INTO refunds (invoice_id, amount, reason, status, created_by, created_at) VALUES (?, ?, ?, 'queued', ?, ?)";
            long refundId = 0;
            try (PreparedStatement pstmt = connection.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                pstmt.setLong(1, invoiceDbId);
                pstmt.setLong(2, amount);
                pstmt.setString(3, reason);
                pstmt.setString(4, createdBy);
                pstmt.setTimestamp(5, now());
                pstmt.executeUpdate();
                try (ResultSet keys = pstmt.getGeneratedKeys()) {
                    if (keys.next()) {
                        refundId = keys.getLong(1);
                    }
                }
            }

            logAudit("refund_queued", null, null, invoiceId, null, null, null, amount, reason, null);

            JsonObject response = new JsonObject();
            response.addProperty("success", true);
            response.addProperty("refund_id", refundId);
            response.addProperty("status", "queued");
            response.addProperty("amount", amount);
            response.addProperty("reason", reason);
            return response;

        } catch (SQLException e) {
            return errorResponse("db_error", e.getMessage());
        }
    }

    /**
     * Flow 4: process one Stripe webhook. The Stripe-Signature header is verified (HMAC-SHA256, constant-time
     * compare, 300 s tolerance on this service's clock) before anything is parsed. An event id already in the
     * events table is acknowledged and not processed again. The event's effects and its events row are written
     * in one transaction, so a failure leaves nothing half-applied and Stripe's retry processes it cleanly.
     * Input: raw request body, Stripe-Signature header. Output: {received: true} (plus duplicate: true for a
     * replay) or {error: config_error|invalid_signature|invalid_payload|db_error, message}.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: Webhook.constructEvent returns an Event,
     * not a JsonObject (compile error); the secret now also comes from a system property; one transaction.
     * Touches: the database.
     */
    public JsonObject handleStripeWebhook(String payload, String signature) {
        if (webhookSecret == null || webhookSecret.isEmpty()) {
            return errorResponse("config_error", "Webhook secret not configured");
        }
        if (payload == null || signature == null) {
            return errorResponse("invalid_signature", "Invalid webhook signature");
        }

        try {
            Webhook.Signature.verifyHeader(payload, signature, webhookSecret, WEBHOOK_TOLERANCE_SECONDS, clock);
        } catch (SignatureVerificationException e) {
            return errorResponse("invalid_signature", "Invalid webhook signature");
        }

        String eventId;
        String eventType;
        JsonObject event;
        try {
            event = JsonParser.parseString(payload).getAsJsonObject();
            eventId = event.get("id").getAsString();
            eventType = event.get("type").getAsString();
        } catch (RuntimeException e) {
            return errorResponse("invalid_payload", "Webhook payload is not a Stripe event");
        }

        boolean previousAutoCommit = true;
        try {
            previousAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);

            String checkSql = "SELECT id FROM events WHERE stripe_event_id = ?";
            try (PreparedStatement pstmt = connection.prepareStatement(checkSql)) {
                pstmt.setString(1, eventId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) {
                        connection.rollback();
                        JsonObject response = new JsonObject();
                        response.addProperty("received", true);
                        response.addProperty("duplicate", true);
                        return response;
                    }
                }
            }

            // Claim the event first: a concurrent delivery of the same id fails on the UNIQUE key and rolls back.
            String insertEventSql = "INSERT INTO events (stripe_event_id, event_type, processed_at) VALUES (?, ?, ?)";
            try (PreparedStatement pstmt = connection.prepareStatement(insertEventSql)) {
                pstmt.setString(1, eventId);
                pstmt.setString(2, eventType);
                pstmt.setTimestamp(3, now());
                pstmt.executeUpdate();
            }

            if ("invoice.payment_succeeded".equals(eventType)) {
                processPaymentSucceeded(event);
            } else if ("invoice.payment_failed".equals(eventType)) {
                processPaymentFailed(event);
            } else if ("customer.subscription.updated".equals(eventType)) {
                processSubscriptionUpdated(event);
            } else if ("customer.subscription.deleted".equals(eventType)) {
                processSubscriptionDeleted(event);
            }

            connection.commit();
        } catch (SQLException | RuntimeException e) {
            try {
                connection.rollback();
            } catch (SQLException ignored) {
                // the original error is the one to report
            }
            return errorResponse(e instanceof SQLException ? "db_error" : "invalid_payload", e.getMessage());
        } finally {
            try {
                connection.setAutoCommit(previousAutoCommit);
            } catch (SQLException ignored) {
                // connection unusable; the caller will see it on next use
            }
        }

        JsonObject response = new JsonObject();
        response.addProperty("received", true);
        return response;
    }

    /**
     * invoice.payment_succeeded: upserts the invoice as succeeded with amount_paid and paid_at, and audits it.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: update-then-insert instead of MySQL-only
     * ON DUPLICATE KEY UPDATE. Touches: the database (caller's transaction).
     */
    private void processPaymentSucceeded(JsonObject event) throws SQLException {
        JsonObject invoiceObj = event.getAsJsonObject("data").getAsJsonObject("object");
        String stripeInvoiceId = invoiceObj.get("id").getAsString();
        String customerId = invoiceObj.get("customer").getAsString();
        long amount = invoiceObj.get("amount_paid").getAsLong();
        Timestamp paidAt = now();

        String update = "UPDATE invoices SET status = 'succeeded', amount = ?, paid_at = ? WHERE stripe_invoice_id = ?";
        int updated;
        try (PreparedStatement pstmt = connection.prepareStatement(update)) {
            pstmt.setLong(1, amount);
            pstmt.setTimestamp(2, paidAt);
            pstmt.setString(3, stripeInvoiceId);
            updated = pstmt.executeUpdate();
        }
        if (updated == 0) {
            String insert = "INSERT INTO invoices (stripe_invoice_id, customer_id, amount, status, paid_at) VALUES (?, ?, ?, 'succeeded', ?)";
            try (PreparedStatement pstmt = connection.prepareStatement(insert)) {
                pstmt.setString(1, stripeInvoiceId);
                pstmt.setString(2, customerId);
                pstmt.setLong(3, amount);
                pstmt.setTimestamp(4, paidAt);
                pstmt.executeUpdate();
            }
        }

        logAudit("payment_succeeded", customerId, null, stripeInvoiceId, null, null, null, amount, null, null);
    }

    /**
     * invoice.payment_failed: marks the invoice's subscription (or, if the event names none, the customer's
     * live subscriptions) past_due, and audits the failure reason.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: targets the invoice's subscription when
     * Stripe names it, instead of every subscription of the customer. Touches: the database.
     */
    private void processPaymentFailed(JsonObject event) throws SQLException {
        JsonObject invoiceObj = event.getAsJsonObject("data").getAsJsonObject("object");
        String stripeInvoiceId = invoiceObj.get("id").getAsString();
        String customerId = invoiceObj.get("customer").getAsString();
        String subscriptionId = stringOrNull(invoiceObj, "subscription");
        String reason = stringOrNull(invoiceObj, "failure_reason");
        if (reason == null) reason = "unknown";

        String sql = subscriptionId != null
                ? "UPDATE subscriptions SET status = 'past_due', updated_at = ? WHERE stripe_subscription_id = ? AND status NOT IN ('cancelled', 'past_due')"
                : "UPDATE subscriptions SET status = 'past_due', updated_at = ? WHERE customer_id = ? AND status NOT IN ('cancelled', 'past_due')";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setTimestamp(1, now());
            pstmt.setString(2, subscriptionId != null ? subscriptionId : customerId);
            pstmt.executeUpdate();
        }

        logAudit("payment_failed", customerId, subscriptionId, stripeInvoiceId, null, null, null, null, reason, null);
    }

    /**
     * customer.subscription.updated: sets status, and tier from items[0].price.lookup_key when that is a known
     * tier. Accepts Stripe's real shape (items: {data: [...]}) and a bare array.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: an event without a lookup key set the tier
     * to null (the column is NOT NULL, so the whole webhook failed); real Stripe item lists were not read.
     * Touches: the database.
     */
    private void processSubscriptionUpdated(JsonObject event) throws SQLException {
        JsonObject subObj = event.getAsJsonObject("data").getAsJsonObject("object");
        String stripeSubId = subObj.get("id").getAsString();
        String customerId = subObj.get("customer").getAsString();
        String status = subObj.get("status").getAsString();

        String newTier = null;
        JsonArray items = null;
        if (subObj.has("items")) {
            JsonElement el = subObj.get("items");
            if (el.isJsonArray()) {
                items = el.getAsJsonArray();
            } else if (el.isJsonObject() && el.getAsJsonObject().has("data")) {
                items = el.getAsJsonObject().getAsJsonArray("data");
            }
        }
        if (items != null && items.size() > 0) {
            JsonObject item = items.get(0).getAsJsonObject();
            if (item.has("price") && item.get("price").isJsonObject()) {
                String lookupKey = stringOrNull(item.getAsJsonObject("price"), "lookup_key");
                if (lookupKey != null && PRICE_IDS.containsKey(lookupKey)) {
                    newTier = lookupKey;
                }
            }
        }

        String oldTier = null;
        try (PreparedStatement pstmt = connection.prepareStatement(
                "SELECT tier FROM subscriptions WHERE stripe_subscription_id = ?")) {
            pstmt.setString(1, stripeSubId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    oldTier = rs.getString("tier");
                }
            }
        }
        if (newTier == null) newTier = oldTier;

        String updateSql = "UPDATE subscriptions SET tier = ?, status = ?, updated_at = ? WHERE stripe_subscription_id = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(updateSql)) {
            pstmt.setString(1, newTier);
            pstmt.setString(2, status);
            pstmt.setTimestamp(3, now());
            pstmt.setString(4, stripeSubId);
            pstmt.executeUpdate();
        }

        logAudit("subscription_updated", customerId, stripeSubId, null, null, oldTier, newTier, null, null, null);
    }

    /**
     * customer.subscription.deleted: marks the subscription cancelled with cancelled_at, and audits it.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: times from the clock. Touches: the database.
     */
    private void processSubscriptionDeleted(JsonObject event) throws SQLException {
        JsonObject subObj = event.getAsJsonObject("data").getAsJsonObject("object");
        String stripeSubId = subObj.get("id").getAsString();
        String customerId = subObj.get("customer").getAsString();

        String sql = "UPDATE subscriptions SET status = 'cancelled', cancelled_at = ?, updated_at = ? WHERE stripe_subscription_id = ?";
        Timestamp now = now();
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setTimestamp(1, now);
            pstmt.setTimestamp(2, now);
            pstmt.setString(3, stripeSubId);
            pstmt.executeUpdate();
        }

        logAudit("subscription_cancelled", customerId, stripeSubId, null, null, null, null, null, null, null);
    }

    /**
     * Appends one audit_log row. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: time from the
     * clock. Touches: the database.
     */
    private void logAudit(String action, String customerId, String subscriptionId, String invoiceId,
                          String tier, String oldTier, String newTier, Long amount, String reason, Long prorationCredits) throws SQLException {
        String sql = "INSERT INTO audit_log (action, customer_id, subscription_id, invoice_id, tier, old_tier, new_tier, amount, reason, proration_credits, created_at) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, action);
            pstmt.setString(2, customerId);
            pstmt.setString(3, subscriptionId);
            pstmt.setString(4, invoiceId);
            pstmt.setString(5, tier);
            pstmt.setString(6, oldTier);
            pstmt.setString(7, newTier);
            if (amount != null) pstmt.setLong(8, amount); else pstmt.setNull(8, Types.BIGINT);
            pstmt.setString(9, reason);
            if (prorationCredits != null) pstmt.setLong(10, prorationCredits); else pstmt.setNull(10, Types.BIGINT);
            pstmt.setTimestamp(11, now());
            pstmt.executeUpdate();
        }
    }

    /** Current time from the clock as a JDBC timestamp. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. */
    private Timestamp now() {
        return Timestamp.from(clock.instant());
    }

    /** A JSON member as a string, or null when absent or JSON null. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static String stringOrNull(JsonObject obj, String name) {
        JsonElement el = obj.get(name);
        return (el == null || el.isJsonNull()) ? null : el.getAsString();
    }

    /** {error, message} response. Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Pure. */
    private JsonObject errorResponse(String code, String message) {
        JsonObject response = new JsonObject();
        response.addProperty("error", code);
        response.addProperty("message", message);
        return response;
    }

    // ─── Stripe boundary ─────────────────────────────────────────────────────────────────────────────────

    /**
     * What this service needs from Stripe. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP so the
     * template runs and is tested without network (rule: external services behind an interface with a fake).
     */
    public interface StripeGateway {
        /** Creates a subscription for the customer on one price. Touches: Stripe (money). */
        StripeSubscription createSubscription(String customerId, String priceId) throws StripeException;

        /**
         * Reads a subscription with its item ids (stripe.subscriptions.retrieve). Added 2026-11-10,
         * session_012zDydZCZ4AChqhEZ4oVtaP (BILL-03). Touches: Stripe (read only).
         */
        StripeSubscription retrieveSubscription(String subscriptionId) throws StripeException;

        /**
         * stripe.subscriptions.update(subscriptionId, {items: [{id: itemId, price: priceId}],
         * proration_behavior: 'create_prorations'}): replaces the price of that one existing item.
         * Replaces changePrice 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (BILL-03). Touches: Stripe (money).
         */
        StripeSubscription updateSubscriptionItem(String subscriptionId, String itemId, String priceId) throws StripeException;
    }

    /**
     * The parts of a Stripe subscription this service uses: its id and current period (epoch seconds).
     * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
     */
    public static final class StripeSubscription {
        public final String id;
        public final long currentPeriodStart;
        public final long currentPeriodEnd;
        /** Ids of the subscription's items, in Stripe's order (added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, BILL-03). */
        public final List<String> itemIds;

        /** Value object; no side effects. */
        public StripeSubscription(String id, long currentPeriodStart, long currentPeriodEnd) {
            this(id, currentPeriodStart, currentPeriodEnd, List.of());
        }

        /** Value object with item ids; no side effects. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        public StripeSubscription(String id, long currentPeriodStart, long currentPeriodEnd, List<String> itemIds) {
            this.id = id;
            this.currentPeriodStart = currentPeriodStart;
            this.currentPeriodEnd = currentPeriodEnd;
            this.itemIds = List.copyOf(itemIds);
        }
    }

    /**
     * StripeGateway on the real Stripe API (stripe-java 28.1.0). The API key is passed per request, never stored
     * in the global Stripe.apiKey. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (replaces calls that
     * did not compile: addItems, static Subscription.update). Touches: network (api.stripe.com), money.
     */
    public static final class StripeSdkGateway implements StripeGateway {
        private final String apiKey;

        /** Gateway using apiKey (may be null: calls then fail with a clear error instead of a global key). */
        public StripeSdkGateway(String apiKey) {
            this.apiKey = apiKey;
        }

        /** Request options carrying the key; fails clearly when no key is configured. */
        private RequestOptions options() {
            if (apiKey == null || apiKey.isEmpty()) {
                throw new IllegalStateException("STRIPE_SECRET_KEY is not configured");
            }
            return RequestOptions.builder().setApiKey(apiKey).build();
        }

        /** Creates the subscription with one item at priceId. Touches: network, money. */
        @Override
        public StripeSubscription createSubscription(String customerId, String priceId) throws StripeException {
            SubscriptionCreateParams params = SubscriptionCreateParams.builder()
                    .setCustomer(customerId)
                    .addItem(SubscriptionCreateParams.Item.builder().setPrice(priceId).build())
                    .build();
            Subscription s = Subscription.create(params, options());
            return new StripeSubscription(s.getId(), orZero(s.getCurrentPeriodStart()), orZero(s.getCurrentPeriodEnd()));
        }

        /** stripe.subscriptions.retrieve with the item ids. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: network. */
        @Override
        public StripeSubscription retrieveSubscription(String subscriptionId) throws StripeException {
            Subscription s = Subscription.retrieve(subscriptionId, options());
            List<String> ids = new ArrayList<>();
            if (s.getItems() != null && s.getItems().getData() != null) {
                for (SubscriptionItem it : s.getItems().getData()) {
                    ids.add(it.getId());
                }
            }
            return new StripeSubscription(s.getId(), orZero(s.getCurrentPeriodStart()), orZero(s.getCurrentPeriodEnd()), ids);
        }

        /**
         * Updates the one named item to priceId with proration_behavior create_prorations; never sends a bare price.
         * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (BILL-03). Touches: network, money.
         */
        @Override
        public StripeSubscription updateSubscriptionItem(String subscriptionId, String itemId, String priceId) throws StripeException {
            if (itemId == null || itemId.isEmpty()) {
                throw new IllegalArgumentException("an existing item id is required (a bare price adds a second item)");
            }
            RequestOptions opts = options();
            SubscriptionUpdateParams params = SubscriptionUpdateParams.builder()
                    .addItem(SubscriptionUpdateParams.Item.builder().setId(itemId).setPrice(priceId).build())
                    .setProrationBehavior(SubscriptionUpdateParams.ProrationBehavior.CREATE_PRORATIONS)
                    .build();
            Subscription s = Subscription.retrieve(subscriptionId, opts).update(params, opts);
            return new StripeSubscription(s.getId(), orZero(s.getCurrentPeriodStart()), orZero(s.getCurrentPeriodEnd()), List.of(itemId));
        }

        /** Null-safe unboxing of Stripe's epoch-second fields. Pure. */
        private static long orZero(Long v) {
            return v == null ? 0L : v;
        }
    }

    /**
     * Deterministic in-memory StripeGateway for tests and local runs: ids sub_test_1, sub_test_2, ... and
     * 30-day periods starting at the clock's time; it records every call. Unknown subscriptions throw like
     * Stripe would. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    public static final class InMemoryStripeGateway implements StripeGateway {
        private final Clock clock;
        /** subscription id -> its items, each {item id, price id}, in order (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). */
        private final Map<String, List<String[]>> itemsBySubscription = new HashMap<>();
        private final Map<String, String> priceBySubscription = new HashMap<>();
        private final Map<String, long[]> periodBySubscription = new HashMap<>();
        private final List<String> calls = new ArrayList<>();
        private int next = 1;

        /** Fake on the given clock (period starts come from it). */
        public InMemoryStripeGateway(Clock clock) {
            this.clock = clock;
        }

        /** Creates sub_test_N with a 30-day period from now and records the call. Touches: memory only. */
        @Override
        public synchronized StripeSubscription createSubscription(String customerId, String priceId) {
            String id = "sub_test_" + next++;
            long start = clock.instant().getEpochSecond();
            long end = start + Duration.ofDays(30).getSeconds();
            priceBySubscription.put(id, priceId);
            periodBySubscription.put(id, new long[]{start, end});
            itemsBySubscription.put(id, new ArrayList<>(List.<String[]>of(new String[]{"si_" + id + "_1", priceId})));
            calls.add("create " + customerId + " " + priceId);
            return new StripeSubscription(id, start, end, List.of("si_" + id + "_1"));
        }

        /** Records an existing one-item subscription (item id "si_<id>_1") with its period. */
        public synchronized void addExisting(String subscriptionId, String priceId, long periodStart, long periodEnd) {
            addExistingItems(subscriptionId, List.of(priceId), periodStart, periodEnd);
        }

        /**
         * Records an existing subscription with one item per price (item ids "si_<id>_1", "si_<id>_2", ...), so tests can
         * build the multi-item case BILL-03 refuses. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
         */
        public synchronized void addExistingItems(String subscriptionId, List<String> priceIds, long periodStart, long periodEnd) {
            List<String[]> items = new ArrayList<>();
            for (int i = 0; i < priceIds.size(); i++) {
                items.add(new String[]{"si_" + subscriptionId + "_" + (i + 1), priceIds.get(i)});
            }
            itemsBySubscription.put(subscriptionId, items);
            priceBySubscription.put(subscriptionId, priceIds.isEmpty() ? null : priceIds.get(0));
            periodBySubscription.put(subscriptionId, new long[]{periodStart, periodEnd});
        }

        private static StripeException missing(String what) {
            return new com.stripe.exception.InvalidRequestException(what, null, null, "resource_missing", 404, null);
        }

        /** Returns a known subscription with its item ids and records "retrieve sub". Touches: memory only. */
        @Override
        public synchronized StripeSubscription retrieveSubscription(String subscriptionId) throws StripeException {
            long[] period = periodBySubscription.get(subscriptionId);
            if (period == null) {
                throw missing("No such subscription: " + subscriptionId);
            }
            calls.add("retrieve " + subscriptionId);
            List<String> ids = new ArrayList<>();
            for (String[] it : itemsBySubscription.getOrDefault(subscriptionId, List.of())) {
                ids.add(it[0]);
            }
            return new StripeSubscription(subscriptionId, period[0], period[1], ids);
        }

        /**
         * Sets the named EXISTING item's price and records "update sub item price"; an unknown subscription or item
         * throws, so a call without the right item id can never add a second item here. 2026-11-10,
         * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
         */
        @Override
        public synchronized StripeSubscription updateSubscriptionItem(String subscriptionId, String itemId, String priceId) throws StripeException {
            long[] period = periodBySubscription.get(subscriptionId);
            if (period == null) {
                throw missing("No such subscription: " + subscriptionId);
            }
            List<String[]> items = itemsBySubscription.getOrDefault(subscriptionId, new ArrayList<>());
            String[] target = null;
            for (String[] it : items) {
                if (it[0].equals(itemId)) target = it;
            }
            if (target == null) {
                throw missing("No such subscription item: " + itemId);
            }
            target[1] = priceId;
            priceBySubscription.put(subscriptionId, priceId);
            calls.add("update " + subscriptionId + " " + itemId + " " + priceId);
            List<String> ids = new ArrayList<>();
            for (String[] it : items) ids.add(it[0]);
            return new StripeSubscription(subscriptionId, period[0], period[1], ids);
        }

        /** Number of items on the subscription (0 if unknown). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        public synchronized int itemCount(String subscriptionId) {
            return itemsBySubscription.getOrDefault(subscriptionId, List.of()).size();
        }

        /** Price currently on the subscription, or null. */
        public synchronized String priceOf(String subscriptionId) {
            return priceBySubscription.get(subscriptionId);
        }

        /** Every call made, in order ("create cus price", "retrieve sub", "update sub item price"). */
        public synchronized List<String> calls() {
            return new ArrayList<>(calls);
        }
    }
}

package com.saas.billing;

import com.google.gson.JsonObject;
import com.stripe.Stripe;
import com.stripe.exception.StripeException;
import com.stripe.model.Subscription;
import com.stripe.net.Webhook;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Tests for BillingService, one per line of the spec's TESTS REQUIRED.
 *
 * Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP:
 *  - each test gets its own in-memory database. The shared "testdb" kept rows between tests, so the second test to
 *    insert inv_123, evt_123 or sub_123 failed on a UNIQUE key, depending on test order;
 *  - the settings are set before the service is built (it reads them at construction);
 *  - the happy paths the spec requires ("stripe call made, DB record created", "proration calculated", "invoice
 *    marked succeeded", "idempotency check prevents double-processing", "tier updated") now run against the
 *    in-memory Stripe gateway and correctly signed webhooks, after the original assertions, which all remain.
 */
public class BillingServiceTest {

    private static final String WEBHOOK_SECRET = "whsec_test_only";

    private Connection connection;
    private BillingService billingService;
    private Clock clock;
    private BillingService.InMemoryStripeGateway fakeStripe;
    private BillingService fakeBilling;

    /** Private database per test, default service and a fake-Stripe service. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the shared database made tests order-dependent. Touches: in-memory H2. */
    @BeforeEach
    void setUp() throws Exception {
        // Mock Stripe API key
        System.setProperty("STRIPE_SECRET_KEY", "sk_test_mock");
        System.setProperty("STRIPE_WEBHOOK_SECRET", "whsec_mock");

        // Use a private H2 in-memory database for each test
        connection = DriverManager.getConnection("jdbc:h2:mem:billing_" + UUID.randomUUID().toString().replace("-", ""), "sa", "");
        BillingService.initializeSchema(connection);
        billingService = new BillingService(connection);

        clock = Clock.fixed(Instant.parse("2026-01-15T12:00:00Z"), ZoneOffset.UTC);
        fakeStripe = new BillingService.InMemoryStripeGateway(clock);
        fakeBilling = new BillingService(connection, fakeStripe, WEBHOOK_SECRET, clock);
    }

    @org.junit.jupiter.api.AfterEach
    void tearDown() throws Exception {
        connection.close();
    }

    /** A Stripe-Signature header for payload, signed with WEBHOOK_SECRET at the test clock's time. */
    private String sign(String payload) throws Exception {
        String ts = String.valueOf(clock.instant().getEpochSecond());
        return "t=" + ts + ",v1=" + Webhook.Util.computeHmacSha256(WEBHOOK_SECRET, ts + "." + payload);
    }

    /** Number of rows matching a query with one string parameter. */
    private int count(String sql, String param) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, param);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }

    /** Invalid tier rejected; happy path calls Stripe (fake) and stores the row. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: happy path added (spec TESTS). */
    @Test
    void testCreateSubscriptionHappyPath() throws Exception {
        // Mock Stripe
        // Note: In a real test, we'd use a mock server or mock the Stripe SDK
        // For this test, we'll assume the Stripe call succeeds and returns a subscription
        // Since we can't easily mock the static Stripe SDK without PowerMock or similar,
        // we'll test the DB and response logic by mocking the Stripe call indirectly
        // or by using a test double. For simplicity, let's assume the Stripe call works
        // and focus on the DB and response.

        // Since we can't easily mock the static Stripe SDK, let's test the invalid tier case first
        // and then assume the happy path works if Stripe is configured correctly.
        // For a complete test, we'd need to mock the Stripe SDK.

        // Test invalid tier
        JsonObject response = billingService.createSubscription("cus_123", "invalid_tier");
        assertEquals("invalid_tier", response.get("error").getAsString());

        // Happy path through the in-memory Stripe gateway: Stripe called once, DB row created
        JsonObject created = fakeBilling.createSubscription("cus_123", "team");
        assertTrue(created.get("success").getAsBoolean());
        String subId = created.get("subscription_id").getAsString();
        assertEquals("team", created.get("tier").getAsString());
        assertEquals("active", created.get("status").getAsString());
        assertEquals("2026-02-14T12:00:00Z", created.get("next_billing_date").getAsString());
        assertEquals(1, fakeStripe.calls().size());
        assertEquals(BillingService.PRICE_IDS.get("team"), fakeStripe.priceOf(subId));
        assertEquals(1, count("SELECT COUNT(*) FROM subscriptions WHERE stripe_subscription_id = ? AND tier = 'team' AND status = 'active'", subId));
        assertEquals(1, count("SELECT COUNT(*) FROM audit_log WHERE subscription_id = ? AND action = 'subscription_created'", subId));
    }

    @Test
    void testCreateSubscriptionInvalidTier() {
        JsonObject response = billingService.createSubscription("cus_123", "invalid_tier");
        assertEquals("invalid_tier", response.get("error").getAsString());
    }

    /** Invalid tier rejected; happy path updates Stripe (fake) and computes the proration credit. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: happy path added. */
    @Test
    void testChangePlanHappyPath() throws Exception {
        // Setup: Create a subscription in DB
        String sql = "INSERT INTO subscriptions (stripe_subscription_id, customer_id, tier, status, created_at) VALUES (?, ?, ?, 'active', NOW())";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, "sub_123");
            pstmt.setString(2, "cus_123");
            pstmt.setString(3, "solo");
            pstmt.executeUpdate();
        }

        // Mock Stripe update
        // Since we can't easily mock the static Stripe SDK, we'll test the DB update logic
        // by assuming the Stripe call succeeds.

        // For a complete test, we'd need to mock the Stripe SDK.
        // Let's test the invalid tier case
        JsonObject response = billingService.changePlan("sub_123", "invalid_tier");
        assertEquals("invalid_tier", response.get("error").getAsString());

        // Happy path: Stripe updated, proration calculated. Period: 30 days, 10 days left at the test clock.
        long now = clock.instant().getEpochSecond();
        long day = 86_400L;
        fakeStripe.addExisting("sub_123", BillingService.PRICE_IDS.get("solo"), now - 20 * day, now + 10 * day);
        JsonObject changed = fakeBilling.changePlan("sub_123", "team");
        assertTrue(changed.get("success").getAsBoolean());
        assertEquals("solo", changed.get("old_tier").getAsString());
        assertEquals("team", changed.get("new_tier").getAsString());
        assertEquals(333L, changed.get("proration_credit").getAsLong()); // floor(999 * 10 / 30)
        assertEquals(BillingService.PRICE_IDS.get("team"), fakeStripe.priceOf("sub_123"));
        assertEquals(1, count("SELECT COUNT(*) FROM subscriptions WHERE stripe_subscription_id = ? AND tier = 'team'", "sub_123"));
    }

    /** A refund is queued and stored. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: asserts the stored row. */
    @Test
    void testQueueRefundHappyPath() throws Exception {
        // Setup: Create an invoice in DB
        String sql = "INSERT INTO invoices (stripe_invoice_id, customer_id, amount, status, paid_at) VALUES (?, ?, ?, 'succeeded', NOW())";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, "inv_123");
            pstmt.setString(2, "cus_123");
            pstmt.setLong(3, 10000); // $100.00
            pstmt.executeUpdate();
        }

        JsonObject response = billingService.queueRefund("inv_123", 5000, "Customer request", "admin");
        assertTrue(response.get("success").getAsBoolean());
        assertEquals("queued", response.get("status").getAsString());
        assertEquals(5000, response.get("amount").getAsLong());
        assertEquals(1, count("SELECT COUNT(*) FROM refunds WHERE status = 'queued' AND created_by = ?", "admin"));
    }

    /** Refunds may not exceed the invoice, alone or together. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: cumulative case added. */
    @Test
    void testQueueRefundExceedsInvoice() throws Exception {
        // Setup: Create an invoice in DB
        String sql = "INSERT INTO invoices (stripe_invoice_id, customer_id, amount, status, paid_at) VALUES (?, ?, ?, 'succeeded', NOW())";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, "inv_123");
            pstmt.setString(2, "cus_123");
            pstmt.setLong(3, 10000); // $100.00
            pstmt.executeUpdate();
        }

        JsonObject response = billingService.queueRefund("inv_123", 15000, "Customer request", "admin");
        assertEquals("refund_exceeds_invoice", response.get("error").getAsString());

        // Two refunds may not add up to more than the invoice either
        assertTrue(billingService.queueRefund("inv_123", 6000, "Customer request", "admin").get("success").getAsBoolean());
        assertEquals("refund_exceeds_invoice",
                billingService.queueRefund("inv_123", 6000, "Customer request", "admin").get("error").getAsString());
    }

    /** Bad signature refused; a signed event marks the invoice succeeded and audits it. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: signed case added. */
    @Test
    void testHandleWebhookPaymentSucceeded() throws Exception {
        // Create a valid webhook payload
        String payload = "{\n" +
                "  \"id\": \"evt_123\",\n" +
                "  \"type\": \"invoice.payment_succeeded\",\n" +
                "  \"data\": {\n" +
                "    \"object\": {\n" +
                "      \"id\": \"inv_123\",\n" +
                "      \"customer\": \"cus_123\",\n" +
                "      \"amount_paid\": 10000\n" +
                "    }\n" +
                "  }\n" +
                "}";

        // Mock webhook signature verification
        // Since Webhook.constructEvent is static, we need to mock it or use a real signature
        // For testing, we'll use a mock signature that passes verification
        // Note: In a real test, we'd generate a valid signature using the webhook secret

        // For simplicity, let's test the idempotency by processing the same event twice
        // First, we need to mock the webhook signature verification
        // Since we can't easily mock the static Webhook.constructEvent, we'll test the DB logic
        // by assuming the signature is valid.

        // Let's test the duplicate event case
        // First, insert the event into the events table
        String sql = "INSERT INTO events (stripe_event_id, event_type, processed_at) VALUES (?, ?, NOW())";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, "evt_123");
            pstmt.setString(2, "invoice.payment_succeeded");
            pstmt.executeUpdate();
        }

        // Now, process the same event again
        // Since we can't easily mock the webhook signature, we'll test the idempotency logic
        // by assuming the signature is valid and the event is already processed.

        // For a complete test, we'd need to mock the Webhook.constructEvent method.
        // Let's test the invalid signature case
        JsonObject response = billingService.handleStripeWebhook(payload, "invalid_signature");
        assertEquals("invalid_signature", response.get("error").getAsString());

        // A correctly signed, new event: invoice marked succeeded, audit logged
        String fresh = payload.replace("evt_123", "evt_124").replace("inv_123", "inv_124");
        JsonObject ok = fakeBilling.handleStripeWebhook(fresh, sign(fresh));
        assertTrue(ok.get("received").getAsBoolean());
        assertEquals(1, count("SELECT COUNT(*) FROM invoices WHERE stripe_invoice_id = ? AND status = 'succeeded' AND amount = 10000", "inv_124"));
        assertEquals(1, count("SELECT COUNT(*) FROM audit_log WHERE invoice_id = ? AND action = 'payment_succeeded'", "inv_124"));
        assertEquals(1, count("SELECT COUNT(*) FROM events WHERE stripe_event_id = ?", "evt_124"));
    }

    /** Bad signature refused; a signed replay is acknowledged and not reprocessed. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: signed case added. */
    @Test
    void testHandleWebhookDuplicateEvent() throws Exception {
        // Setup: Insert event into events table
        String sql = "INSERT INTO events (stripe_event_id, event_type, processed_at) VALUES (?, ?, NOW())";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, "evt_123");
            pstmt.setString(2, "invoice.payment_succeeded");
            pstmt.executeUpdate();
        }

        // Create a valid webhook payload
        String payload = "{\n" +
                "  \"id\": \"evt_123\",\n" +
                "  \"type\": \"invoice.payment_succeeded\",\n" +
                "  \"data\": {\n" +
                "    \"object\": {\n" +
                "      \"id\": \"inv_123\",\n" +
                "      \"customer\": \"cus_123\",\n" +
                "      \"amount_paid\": 10000\n" +
                "    }\n" +
                "  }\n" +
                "}";

        // Since we can't easily mock the webhook signature, we'll test the idempotency logic
        // by assuming the signature is valid and the event is already processed.
        // For a complete test, we'd need to mock the Webhook.constructEvent method.

        // Let's test the invalid signature case
        JsonObject response = billingService.handleStripeWebhook(payload, "invalid_signature");
        assertEquals("invalid_signature", response.get("error").getAsString());

        // Correctly signed replay of the already-processed event: acknowledged, not processed again
        JsonObject replay = fakeBilling.handleStripeWebhook(payload, sign(payload));
        assertTrue(replay.get("received").getAsBoolean());
        assertEquals(0, count("SELECT COUNT(*) FROM invoices WHERE stripe_invoice_id = ?", "inv_123"));
        assertEquals(1, count("SELECT COUNT(*) FROM events WHERE stripe_event_id = ?", "evt_123"));
    }

    /** Bad signature refused; a signed event updates tier and status. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: signed case added. */
    @Test
    void testHandleWebhookSubscriptionUpdated() throws Exception {
        // Create a valid webhook payload
        String payload = "{\n" +
                "  \"id\": \"evt_456\",\n" +
                "  \"type\": \"customer.subscription.updated\",\n" +
                "  \"data\": {\n" +
                "    \"object\": {\n" +
                "      \"id\": \"sub_123\",\n" +
                "      \"customer\": \"cus_123\",\n" +
                "      \"status\": \"active\",\n" +
                "      \"items\": [\n" +
                "        {\n" +
                "          \"price\": {\n" +
                "            \"lookup_key\": \"team\"\n" +
                "          }\n" +
                "        }\n" +
                "      ]\n" +
                "    }\n" +
                "  }\n" +
                "}";

        // Setup: Create a subscription in DB
        String sql = "INSERT INTO subscriptions (stripe_subscription_id, customer_id, tier, status, created_at) VALUES (?, ?, ?, 'active', NOW())";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, "sub_123");
            pstmt.setString(2, "cus_123");
            pstmt.setString(3, "solo");
            pstmt.executeUpdate();
        }

        // Since we can't easily mock the webhook signature, we'll test the invalid signature case
        JsonObject response = billingService.handleStripeWebhook(payload, "invalid_signature");
        assertEquals("invalid_signature", response.get("error").getAsString());

        // Correctly signed: tier updated to the lookup key, status set
        JsonObject ok = fakeBilling.handleStripeWebhook(payload, sign(payload));
        assertTrue(ok.get("received").getAsBoolean());
        assertEquals(1, count("SELECT COUNT(*) FROM subscriptions WHERE stripe_subscription_id = ? AND tier = 'team' AND status = 'active'", "sub_123"));
    }

    @Test
    void testWebhookSignatureInvalid() {
        String payload = "{}";
        JsonObject response = billingService.handleStripeWebhook(payload, "invalid_signature");
        assertEquals("invalid_signature", response.get("error").getAsString());
    }

    @Test
    void testWebhookResponseTime() {
        // Test that the response is returned quickly
        String payload = "{}";
        long startTime = System.currentTimeMillis();
        JsonObject response = billingService.handleStripeWebhook(payload, "invalid_signature");
        long endTime = System.currentTimeMillis();

        // Response should be returned quickly (less than 3 seconds)
        assertTrue(endTime - startTime < 3000);
        assertEquals("invalid_signature", response.get("error").getAsString());
    }
}
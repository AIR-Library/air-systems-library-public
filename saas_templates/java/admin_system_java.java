package com.example.admin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.stripe.exception.StripeException;
import com.stripe.model.Subscription;
import com.stripe.model.SubscriptionItem;
import com.stripe.net.RequestOptions;
import com.stripe.param.SubscriptionUpdateParams;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.*;
import java.util.regex.Pattern;

/*
 * Admin system (spec: GEMINI_DISPATCH_MASTER_SPEC, template #2): owner/admin management of users, customers,
 * deployments and governance approvals, every mutation audited, every POST CSRF-checked.
 *
 * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. The file did not compile (124 errors): it used
 * JPA, Spring Data, javax.servlet and bean validation, none of which this library's Java toolchain provides (Spring
 * Boot 3 with spring-jdbc and jakarta.servlet), and GovernanceAction had no accessors. It now runs on JdbcTemplate
 * with the same entity and repository names the tests use. Security fixes made on the way:
 *   - identity came from a client-sent X-User-Id header, always: it is now trusted only when the deployment
 *     names a trusted header set by its authentication proxy (admin.auth.trusted-user-header); otherwise every
 *     request is unauthenticated (401). Suspended or deleted users are never authenticated;
 *   - the current user lived in a ThreadLocal that was never cleared (it leaked to the next request on the same
 *     worker thread): it is now a request attribute;
 *   - the CSRF token was hard-coded ("secure-token") and compared with equals: it comes from configuration
 *     (admin.csrf.token), is compared in constant time, and with none configured every POST is refused;
 *   - audit details were built by string concatenation (JSON injection): they are serialized by Jackson;
 *   - refunds were never saved, unchecked against an invoice and kept as double: they are stored as DECIMAL after
 *     checking the invoice exists, belongs to the customer, succeeded and is not over-refunded;
 *   - change_plan set the global Stripe.apiKey and sent "price_id_for_<tier>": Stripe now sits behind
 *     AdminStripeGateway (real or in-memory, chosen by configuration), prices come from STRIPE_PRICE_<TIER>;
 *   - publish's safety flag was hard-coded true: SafetyFlags.canPublish comes from configuration, default false;
 *   - governance approval executed nothing and the audit-log search returned an empty list: both are real now.
 * Touches: the configured DataSource (H2 in tests), Stripe's API (money) only through StripeSdkAdminGateway,
 * outgoing email only through AdminMailer (in-memory by default).
 */

/**
 * Spring Boot entry point and wiring. Configuration (application properties or environment):
 * admin.auth.trusted-user-header (header your auth proxy sets with the signed-in user's id; unset = nobody is
 * authenticated), admin.csrf.token (required for POSTs), admin.stripe.gateway (stripe | in-memory, default
 * stripe), admin.safety.can-publish (default false), admin.app.base-url (links in emails).
 * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (see the file comment). Touches: nothing itself.
 */
@SpringBootApplication
public class AdminSystemApplication {

    /** Starts the admin service. Touches: network (HTTP listener), the database. */
    public static void main(String[] args) {
        SpringApplication.run(AdminSystemApplication.class, args);
    }

    /** UTC clock for every timestamp, replaceable in tests. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. */
    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    /**
     * CSRF check on every state-changing /admin request (spec: "Every POST: verify_csrf()"). Repaired 2026-11-10,
     * session session_012zDydZCZ4AChqhEZ4oVtaP: token from configuration, constant-time comparison.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.3, ADMIN-19 "the CSRF check included"): it now
     * runs second, after AuthFilter, so a suspended caller is refused with 403 account_suspended before the CSRF
     * check. In: the configured token. Out: the filter registration. Touches: nothing (reads the request).
     */
    @Bean
    FilterRegistrationBean<CsrfFilter> csrfFilter(@Value("${admin.csrf.token:}") String token) {
        FilterRegistrationBean<CsrfFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new CsrfFilter(token));
        registration.addUrlPatterns("/admin/*");
        registration.setOrder(2);
        return registration;
    }

    /**
     * Authentication: resolves the signed-in user from the trusted header, if one is configured.
     * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (replaces MockAuthFilter, which trusted any
     * client-sent X-User-Id). Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.3, ADMIN-19): first in
     * the chain, so a suspended caller is refused before any gate, the CSRF check included. In: the user repository
     * and the trusted header name. Out: the filter registration. Touches: reads the database.
     */
    @Bean
    FilterRegistrationBean<AuthFilter> authFilter(UserRepository users,
                                                  @Value("${admin.auth.trusted-user-header:}") String header) {
        FilterRegistrationBean<AuthFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new AuthFilter(users, header));
        registration.addUrlPatterns("/admin/*");
        registration.setOrder(1);
        return registration;
    }

    /**
     * The Stripe boundary: the real API ("stripe", the default) or the deterministic in-memory fake
     * ("in-memory", for tests and local runs). Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: Stripe's API (money) when "stripe".
     */
    @Bean
    AdminStripeGateway stripeGateway(@Value("${admin.stripe.gateway:stripe}") String mode) {
        if ("in-memory".equals(mode)) {
            return new InMemoryAdminStripeGateway();
        }
        return new StripeSdkAdminGateway(System.getenv("STRIPE_SECRET_KEY"));
    }

    /**
     * Outgoing email. This template ships only the in-memory outbox (no mail library is in its toolchain);
     * replace this bean with an SMTP or provider implementation in production.
     * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    @Bean
    AdminMailer adminMailer() {
        return new InMemoryAdminMailer();
    }

    /** SafetyFlags from configuration. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. */
    @Bean
    SafetyFlags safetyFlags(@Value("${admin.safety.can-publish:false}") boolean canPublish) {
        return new SafetyFlags(canPublish);
    }

    /** Programmatic transactions (no proxies on package-private services). Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. */
    @Bean
    TransactionTemplate transactionTemplate(PlatformTransactionManager tm) {
        return new TransactionTemplate(tm);
    }
}

/* ---------- SECURITY ---------- */

/**
 * Access to the authenticated user of the current request (a request attribute set by AuthFilter) and the
 * spec's two gates. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: request attribute instead of
 * a ThreadLocal that was never cleared. Touches: nothing.
 */
final class SecurityUtil {
    static final String ATTRIBUTE = "admin.currentUser";

    private SecurityUtil() {}

    /** The signed-in user, or 401 unauthenticated. */
    static User getCurrentUser() {
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        Object u = attrs == null ? null : attrs.getAttribute(ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
        if (!(u instanceof User)) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "unauthenticated");
        return (User) u;
    }

    /**
     * Spec gate owner_only: returns the owner, else 403 owner_only. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
     * (admin spec TIERS, Phase B.2): the staff role is lowercase 'owner' (it compared "OWNER"). Touches: nothing.
     */
    static User requireOwner() {
        User u = getCurrentUser();
        if (!Tiers.OWNER.equals(u.getTier())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "owner_only");
        }
        return u;
    }

    /**
     * Spec gate admin_or_owner: returns the user, else 403 admin_or_owner. Changed 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP (admin spec TIERS): lowercase roles 'owner' / 'admin'. Touches: nothing.
     */
    static User requireAdminOrOwner() {
        User u = getCurrentUser();
        if (!Tiers.OWNER.equals(u.getTier()) && !Tiers.ADMIN.equals(u.getTier())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "admin_or_owner");
        }
        return u;
    }

    /** Constant-time string comparison for secrets (MessageDigest.isEqual on UTF-8 bytes). */
    static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}

/**
 * The two things the admin spec calls "tier" (TIERS, amended 2026-11-10, Phase B.2): users.tier is the STAFF ROLE
 * ('owner' | 'admin' | 'user'); a customer's or deployment's tier is the PLAN ('solo' | 'team' | 'enterprise').
 * A plan where a role is expected, or the reverse, is 400 invalid_tier. Added 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP (roles were "OWNER"/"ADMIN"/"USER" and a deployment took any tier). Touches nothing.
 */
final class Tiers {
    static final String OWNER = "owner";
    static final String ADMIN = "admin";
    static final String USER = "user";
    static final Set<String> ROLES = Set.of(OWNER, ADMIN, USER);
    static final Set<String> PLANS = Set.of("solo", "team", "enterprise");

    private Tiers() {}
}

/**
 * Refuses any POST/PUT/PATCH/DELETE whose X-CSRF-Token header does not match the configured token (403
 * csrf_invalid). With no token configured, every such request is refused (fail closed).
 * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: was a hard-coded token compared with equals.
 * Touches: nothing (reads the request, writes the error response).
 */
class CsrfFilter extends OncePerRequestFilter {
    private static final String CSRF_HEADER = "X-CSRF-Token";
    private final String expectedToken;

    CsrfFilter(String expectedToken) {
        this.expectedToken = expectedToken;
    }

    /** Rejects a state-changing request without the configured token; passes everything else on. Touches: the response. */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String method = request.getMethod().toUpperCase(Locale.ROOT);
        boolean mutating = method.equals("POST") || method.equals("PUT") || method.equals("PATCH") || method.equals("DELETE");
        if (mutating) {
            String token = request.getHeader(CSRF_HEADER);
            if (expectedToken == null || expectedToken.isEmpty() || !SecurityUtil.constantTimeEquals(expectedToken, token)) {
                response.setStatus(HttpStatus.FORBIDDEN.value());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.getWriter().write("{\"error\":\"csrf_invalid\",\"message\":\"Invalid CSRF token\"}");
                return;
            }
        }
        filterChain.doFilter(request, response);
    }
}

/**
 * Authenticates the request from a header that the deployment's authentication proxy sets (and strips from
 * client requests) with the signed-in user's id. Only active users are accepted; a suspended user is refused right
 * here, before any gate, with 403 {error: "account_suspended"} (ADMIN-19). With no trusted header configured,
 * nobody is authenticated and every endpoint answers 401.
 * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (replaces MockAuthFilter). Changed the same day
 * (ADMIN-19, Phase B.2): a suspended caller got 401 unauthenticated. Touches: reads the database, writes the response.
 */
class AuthFilter extends OncePerRequestFilter {
    private final UserRepository users;
    private final String trustedHeader;

    AuthFilter(UserRepository users, String trustedHeader) {
        this.users = users;
        this.trustedHeader = trustedHeader;
    }

    /**
     * Sets the authenticated user (active only) from the trusted header, if configured; answers 403 account_suspended
     * for a suspended user without calling the rest of the chain, so nothing runs for them (ADMIN-19).
     * In: the request. Out: the request passed on, or the 403. Touches: reads the database, writes the response.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (trustedHeader != null && !trustedHeader.isEmpty()) {
            String uid = request.getHeader(trustedHeader);
            if (uid != null && uid.matches("\\d{1,18}")) {
                Optional<User> found = users.findById(Long.parseLong(uid));
                if (found.isPresent() && "suspended".equals(found.get().getStatus())) {
                    response.setStatus(HttpStatus.FORBIDDEN.value());
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    response.getWriter().write("{\"error\":\"account_suspended\",\"message\":\"account_suspended\"}");
                    return;
                }
                found.filter(u -> "active".equals(u.getStatus()))
                        .ifPresent(u -> request.setAttribute(SecurityUtil.ATTRIBUTE, u));
            }
        }
        chain.doFilter(request, response);
    }
}

/** The spec's SafetyFlags (second gate on publish). Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. */
class SafetyFlags {
    private final boolean canPublish;

    SafetyFlags(boolean canPublish) {
        this.canPublish = canPublish;
    }

    boolean canPublish() {
        return canPublish;
    }
}

/* ---------- EXTERNAL SERVICES ---------- */

/**
 * What the admin system needs from Stripe. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
 * Changed the same day (ADMIN-12, admin_system.md change_plan -> billing_subscriptions.md flow 2): the plan change is
 * three steps the caller orders itself, so the checks run before any update: the tier's price, the subscription's
 * item ids, then an update naming the one existing item. Touches: money.
 */
interface AdminStripeGateway {
    /** The Stripe price id of a plan tier, or null when the tier is unknown (the caller answers 400 invalid_tier). */
    String priceFor(String tier);

    /** stripe.subscriptions.retrieve: the subscription's item ids in order. Touches: Stripe (read only). */
    List<String> subscriptionItemIds(String subscriptionId) throws StripeException;

    /**
     * stripe.subscriptions.update(subscriptionId, {items: [{id: itemId, price: priceId}],
     * proration_behavior: 'create_prorations'}). Never a bare price: that adds a second item and bills both plans.
     * Touches: Stripe (money).
     */
    void updateSubscriptionItem(String subscriptionId, String itemId, String priceId) throws StripeException;
}

/**
 * AdminStripeGateway on the real API (stripe-java 28.1.0). The price for a tier comes from the environment
 * variable STRIPE_PRICE_<TIER>; a tier without one is unknown rather than guessed. The key is sent per request.
 * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP; split into retrieve / update-one-item the same day
 * (ADMIN-12). Touches: network (api.stripe.com), money.
 */
class StripeSdkAdminGateway implements AdminStripeGateway {
    private final String apiKey;

    StripeSdkAdminGateway(String apiKey) {
        this.apiKey = apiKey;
    }

    private RequestOptions options() {
        if (apiKey == null || apiKey.isEmpty()) {
            throw new IllegalStateException("STRIPE_SECRET_KEY is not configured");
        }
        return RequestOptions.builder().setApiKey(apiKey).build();
    }

    /** STRIPE_PRICE_<TIER> or null. Touches: reads the environment. */
    @Override
    public String priceFor(String tier) {
        if (tier == null) return null;
        String price = System.getenv("STRIPE_PRICE_" + tier.toUpperCase(Locale.ROOT));
        return price == null || price.isEmpty() ? null : price;
    }

    /** Retrieves the subscription's item ids. Touches: network. */
    @Override
    public List<String> subscriptionItemIds(String subscriptionId) throws StripeException {
        Subscription sub = Subscription.retrieve(subscriptionId, options());
        List<String> ids = new ArrayList<>();
        if (sub.getItems() != null && sub.getItems().getData() != null) {
            for (SubscriptionItem it : sub.getItems().getData()) ids.add(it.getId());
        }
        return ids;
    }

    /** Updates the one named item to priceId, creating prorations. Touches: network, money. */
    @Override
    public void updateSubscriptionItem(String subscriptionId, String itemId, String priceId) throws StripeException {
        if (itemId == null || itemId.isEmpty()) {
            throw new IllegalArgumentException("an existing item id is required");
        }
        RequestOptions opts = options();
        Subscription.retrieve(subscriptionId, opts).update(SubscriptionUpdateParams.builder()
                .addItem(SubscriptionUpdateParams.Item.builder().setId(itemId).setPrice(priceId).build())
                .setProrationBehavior(SubscriptionUpdateParams.ProrationBehavior.CREATE_PRORATIONS)
                .build(), opts);
    }
}

/**
 * In-memory AdminStripeGateway: plan tiers solo, team and enterprise with fake price ids; a subscription it has not
 * seen has one item "si_<id>_1"; it records "retrieve <sub>" and "update <sub> <item> <price>" and sends nothing.
 * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP; items and the update-one-item call added the same day
 * (ADMIN-12). Touches: memory only.
 */
class InMemoryAdminStripeGateway implements AdminStripeGateway {
    static final Map<String, String> PRICES = Map.of(
            "solo", "price_test_solo", "team", "price_test_team", "enterprise", "price_test_enterprise");
    private final List<String> calls = Collections.synchronizedList(new ArrayList<>());
    private final Map<String, List<String[]>> items = new HashMap<>();

    @Override
    public String priceFor(String tier) {
        return PRICES.get(tier);
    }

    /** Sets a subscription's items (one price per item); lets tests build a two-item subscription. */
    synchronized void setItems(String subscriptionId, List<String> priceIds) {
        List<String[]> list = new ArrayList<>();
        for (int i = 0; i < priceIds.size(); i++) {
            list.add(new String[]{"si_" + subscriptionId + "_" + (i + 1), priceIds.get(i)});
        }
        items.put(subscriptionId, list);
    }

    private List<String[]> itemsOf(String subscriptionId) {
        return items.computeIfAbsent(subscriptionId,
                id -> new ArrayList<>(List.<String[]>of(new String[]{"si_" + id + "_1", null})));
    }

    @Override
    public synchronized List<String> subscriptionItemIds(String subscriptionId) {
        calls.add("retrieve " + subscriptionId);
        List<String> ids = new ArrayList<>();
        for (String[] it : itemsOf(subscriptionId)) ids.add(it[0]);
        return ids;
    }

    /** Sets the named existing item's price; an unknown item throws (no item is ever added). */
    @Override
    public synchronized void updateSubscriptionItem(String subscriptionId, String itemId, String priceId) {
        for (String[] it : itemsOf(subscriptionId)) {
            if (it[0].equals(itemId)) {
                it[1] = priceId;
                calls.add("update " + subscriptionId + " " + itemId + " " + priceId);
                return;
            }
        }
        throw new IllegalArgumentException("No such subscription item: " + itemId);
    }

    synchronized int itemCount(String subscriptionId) {
        return itemsOf(subscriptionId).size();
    }

    List<String> calls() {
        synchronized (calls) {
            return new ArrayList<>(calls);
        }
    }
}

/** Outgoing email boundary. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: email in real implementations. */
interface AdminMailer {
    void send(String to, String subject, String body);
}

/**
 * In-memory outbox: keeps recipients and subjects only (bodies can hold reset links, which are secrets).
 * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
class InMemoryAdminMailer implements AdminMailer {
    private final List<String> sent = Collections.synchronizedList(new ArrayList<>());

    /** Records recipient and subject only. Touches: memory only. */
    @Override
    public void send(String to, String subject, String body) {
        sent.add(to + " | " + subject);
    }

    List<String> sent() {
        synchronized (sent) {
            return new ArrayList<>(sent);
        }
    }
}

/* ---------- SCHEMA ---------- */

/**
 * Creates the tables on startup (idempotent; H2 and MySQL). Repositories depend on it, so the schema exists
 * before any query. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: adds invoices (refunds are
 * checked against them), password_reset_tokens, deployment domain_verified/config/archived_at, customer
 * payment_method/address/notes, and audit_log old/new value and reason columns the spec's search returns; money is
 * DECIMAL. Touches: the database.
 */
@Component
class SchemaInitializer {
    SchemaInitializer(JdbcTemplate jdbc) {
        String[] statements = {
            "CREATE TABLE IF NOT EXISTS users (id BIGINT PRIMARY KEY AUTO_INCREMENT, email VARCHAR(255) UNIQUE NOT NULL, name VARCHAR(255) NOT NULL, tier VARCHAR(50) NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'active', password_hash VARCHAR(255), created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)",
            "CREATE TABLE IF NOT EXISTS password_reset_tokens (id BIGINT PRIMARY KEY AUTO_INCREMENT, user_id BIGINT NOT NULL, token_hash VARCHAR(64) NOT NULL UNIQUE, expires_at TIMESTAMP NOT NULL, used_at TIMESTAMP)",
            "CREATE TABLE IF NOT EXISTS customers (id BIGINT PRIMARY KEY AUTO_INCREMENT, email VARCHAR(255) NOT NULL, name VARCHAR(255) NOT NULL, tier VARCHAR(50) NOT NULL, signup_date DATE NOT NULL, invoice_count INT NOT NULL DEFAULT 0, status VARCHAR(20) NOT NULL DEFAULT 'active', stripe_subscription_id VARCHAR(255), payment_method VARCHAR(100), address VARCHAR(500), notes VARCHAR(2000))",
            "CREATE TABLE IF NOT EXISTS invoices (id BIGINT PRIMARY KEY AUTO_INCREMENT, customer_id BIGINT NOT NULL, amount DECIMAL(12,2) NOT NULL, status VARCHAR(20) NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)",
            "CREATE TABLE IF NOT EXISTS deployments (id BIGINT PRIMARY KEY AUTO_INCREMENT, customer_id BIGINT NOT NULL, domain VARCHAR(255) NOT NULL UNIQUE, tier VARCHAR(50) NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'draft', theme_id BIGINT, domain_verified BOOLEAN NOT NULL DEFAULT FALSE, config VARCHAR(2000), published_at TIMESTAMP, archived_at TIMESTAMP, suspend_reason VARCHAR(255))",
            "CREATE TABLE IF NOT EXISTS refunds (id BIGINT PRIMARY KEY AUTO_INCREMENT, invoice_id BIGINT NOT NULL, amount DECIMAL(12,2) NOT NULL, reason VARCHAR(255) NOT NULL, status VARCHAR(20) NOT NULL, created_by BIGINT NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)",
            "CREATE TABLE IF NOT EXISTS audit_log (id BIGINT PRIMARY KEY AUTO_INCREMENT, action VARCHAR(100) NOT NULL, actor_id BIGINT NOT NULL, resource_type VARCHAR(50), resource_id BIGINT, old_value VARCHAR(2000), new_value VARCHAR(2000), reason VARCHAR(500), created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)",
            "CREATE TABLE IF NOT EXISTS governance_actions (id BIGINT PRIMARY KEY AUTO_INCREMENT, action_type VARCHAR(100) NOT NULL, actor_id BIGINT NOT NULL, target_resource_id BIGINT, reason VARCHAR(255), submitted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, status VARCHAR(20) NOT NULL DEFAULT 'pending', approved_by BIGINT, approved_at TIMESTAMP, rejection_reason VARCHAR(255), execution_result VARCHAR(500), new_tier VARCHAR(20))"
        };
        for (String sql : statements) {
            jdbc.execute(sql);
        }
    }
}

/* ---------- ENTITIES ---------- */

/** An admin-console user (tier = staff role 'owner', 'admin' or 'user'; lowercase since 2026-11-10, Phase B.2). Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: plain class, no JPA. */
class User {
    private Long id;
    private String email;
    private String name;
    private String tier;
    private String status = "active";
    private Instant createdAt;

    public Long getId() { return id; }
    void setId(Long id) { this.id = id; }
    public String getEmail() { return email; }
    public void setEmail(String e) { this.email = e; }
    public String getName() { return name; }
    public void setName(String n) { this.name = n; }
    public String getTier() { return tier; }
    public void setTier(String t) { this.tier = t; }
    public String getStatus() { return status; }
    public void setStatus(String s) { this.status = s; }
    public Instant getCreatedAt() { return createdAt; }
    void setCreatedAt(Instant i) { this.createdAt = i; }
}

/** A paying customer. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: plain class; detail fields added. */
class Customer {
    private Long id;
    private String email;
    private String name;
    private String tier;
    private LocalDate signupDate;
    private int invoiceCount;
    private String status = "active";
    private String stripeSubscriptionId;
    private String paymentMethod;
    private String address;
    private String notes;

    public Long getId() { return id; }
    void setId(Long id) { this.id = id; }
    public String getEmail() { return email; }
    public void setEmail(String e) { this.email = e; }
    public String getName() { return name; }
    public void setName(String n) { this.name = n; }
    public String getTier() { return tier; }
    public void setTier(String t) { this.tier = t; }
    public LocalDate getSignupDate() { return signupDate; }
    public void setSignupDate(LocalDate d) { this.signupDate = d; }
    public int getInvoiceCount() { return invoiceCount; }
    public void setInvoiceCount(int c) { this.invoiceCount = c; }
    public String getStatus() { return status; }
    public void setStatus(String s) { this.status = s; }
    public String getStripeSubscriptionId() { return stripeSubscriptionId; }
    public void setStripeSubscriptionId(String s) { this.stripeSubscriptionId = s; }
    public String getPaymentMethod() { return paymentMethod; }
    public void setPaymentMethod(String p) { this.paymentMethod = p; }
    public String getAddress() { return address; }
    public void setAddress(String a) { this.address = a; }
    public String getNotes() { return notes; }
    public void setNotes(String n) { this.notes = n; }
}

/** A customer invoice (refunds are checked against it). Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. */
class Invoice {
    private Long id;
    private Long customerId;
    private BigDecimal amount;
    private String status;

    public Long getId() { return id; }
    void setId(Long id) { this.id = id; }
    public Long getCustomerId() { return customerId; }
    public void setCustomerId(Long c) { this.customerId = c; }
    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal a) { this.amount = a; }
    public String getStatus() { return status; }
    public void setStatus(String s) { this.status = s; }
}

/** A customer site. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: plain class; domainVerified, config, archivedAt added. */
class Deployment {
    private Long id;
    private Long customerId;
    private String domain;
    private String tier;
    private String status = "draft";
    private Long themeId;
    private boolean domainVerified;
    private String config;
    private Instant publishedAt;
    private Instant archivedAt;
    private String suspendReason;

    public Long getId() { return id; }
    void setId(Long id) { this.id = id; }
    public Long getCustomerId() { return customerId; }
    public void setCustomerId(Long c) { this.customerId = c; }
    public String getDomain() { return domain; }
    public void setDomain(String d) { this.domain = d; }
    public String getTier() { return tier; }
    public void setTier(String t) { this.tier = t; }
    public String getStatus() { return status; }
    public void setStatus(String s) { this.status = s; }
    public Long getThemeId() { return themeId; }
    public void setThemeId(Long t) { this.themeId = t; }
    public boolean isDomainVerified() { return domainVerified; }
    public void setDomainVerified(boolean v) { this.domainVerified = v; }
    public String getConfig() { return config; }
    public void setConfig(String c) { this.config = c; }
    public Instant getPublishedAt() { return publishedAt; }
    public void setPublishedAt(Instant i) { this.publishedAt = i; }
    public Instant getArchivedAt() { return archivedAt; }
    public void setArchivedAt(Instant i) { this.archivedAt = i; }
    public String getSuspendReason() { return suspendReason; }
    public void setSuspendReason(String r) { this.suspendReason = r; }
}

/** A queued refund (never executed here). Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: BigDecimal amount. */
class Refund {
    private Long id;
    private Long invoiceId;
    private BigDecimal amount;
    private String reason;
    private String status;
    private Long createdBy;
    private Instant createdAt;

    public Long getId() { return id; }
    void setId(Long id) { this.id = id; }
    public Long getInvoiceId() { return invoiceId; }
    public void setInvoiceId(Long i) { this.invoiceId = i; }
    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal a) { this.amount = a; }
    public String getReason() { return reason; }
    public void setReason(String r) { this.reason = r; }
    public String getStatus() { return status; }
    public void setStatus(String s) { this.status = s; }
    public Long getCreatedBy() { return createdBy; }
    public void setCreatedBy(Long b) { this.createdBy = b; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant i) { this.createdAt = i; }
}

/** One audit-log row. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: accessors and the spec's search fields. */
class AuditLog {
    private Long id;
    private String action;
    private Long actorId;
    private String resourceType;
    private Long resourceId;
    private String oldValue;
    private String newValue;
    private String reason;
    private Instant timestamp;

    public Long getId() { return id; }
    void setId(Long id) { this.id = id; }
    public String getAction() { return action; }
    public void setAction(String a) { this.action = a; }
    public Long getActorId() { return actorId; }
    public void setActorId(Long a) { this.actorId = a; }
    public String getResourceType() { return resourceType; }
    public void setResourceType(String r) { this.resourceType = r; }
    public Long getResourceId() { return resourceId; }
    public void setResourceId(Long r) { this.resourceId = r; }
    public String getOldValue() { return oldValue; }
    public void setOldValue(String v) { this.oldValue = v; }
    public String getNewValue() { return newValue; }
    public void setNewValue(String v) { this.newValue = v; }
    public String getReason() { return reason; }
    public void setReason(String r) { this.reason = r; }
    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant t) { this.timestamp = t; }
}

/**
 * A mutation waiting for an owner's approval. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: it had
 * no accessors at all (most of the compile errors).
 */
class GovernanceAction {
    private Long id;
    private String actionType;
    private Long actorId;
    private Long targetResourceId;
    private String reason;
    private Instant submittedAt;
    private String status = "pending";
    private Long approvedBy;
    private Instant approvedAt;
    private String rejectionReason;
    private String executionResult;
    private String newTier;

    public Long getId() { return id; }
    void setId(Long id) { this.id = id; }
    public String getActionType() { return actionType; }
    public void setActionType(String t) { this.actionType = t; }
    public Long getActorId() { return actorId; }
    public void setActorId(Long a) { this.actorId = a; }
    public Long getTargetResourceId() { return targetResourceId; }
    public void setTargetResourceId(Long t) { this.targetResourceId = t; }
    public String getReason() { return reason; }
    public void setReason(String r) { this.reason = r; }
    public Instant getSubmittedAt() { return submittedAt; }
    public void setSubmittedAt(Instant i) { this.submittedAt = i; }
    public String getStatus() { return status; }
    public void setStatus(String s) { this.status = s; }
    public Long getApprovedBy() { return approvedBy; }
    public void setApprovedBy(Long a) { this.approvedBy = a; }
    public Instant getApprovedAt() { return approvedAt; }
    public void setApprovedAt(Instant i) { this.approvedAt = i; }
    public String getRejectionReason() { return rejectionReason; }
    public void setRejectionReason(String r) { this.rejectionReason = r; }
    public String getExecutionResult() { return executionResult; }
    public void setExecutionResult(String r) { this.executionResult = r; }
    /**
     * The role a change_role action sets (null for other action types). Added 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.3, ADMIN-07: a governance-approved change_role). Touches: nothing.
     */
    public String getNewTier() { return newTier; }
    /** Sets the role a change_role action sets. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    public void setNewTier(String t) { this.newTier = t; }
}

/* ---------- REPOSITORIES (JdbcTemplate, parameterized SQL only) ---------- */

/** Shared JDBC helpers. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database. */
abstract class JdbcRepository {
    protected final JdbcTemplate jdbc;

    JdbcRepository(JdbcTemplate jdbc, SchemaInitializer schema) {
        this.jdbc = jdbc;
    }

    /** Runs an INSERT and returns the generated id. */
    protected long insert(String sql, Object... args) {
        KeyHolder keys = new GeneratedKeyHolder();
        jdbc.update(con -> {
            PreparedStatement ps = con.prepareStatement(sql, new String[]{"ID"});
            for (int i = 0; i < args.length; i++) ps.setObject(i + 1, args[i]);
            return ps;
        }, keys);
        return Objects.requireNonNull(keys.getKey(), "no generated id").longValue();
    }

    static Timestamp ts(Instant i) {
        return i == null ? null : Timestamp.from(i);
    }

    static Instant instant(ResultSet rs, String col) throws SQLException {
        Timestamp t = rs.getTimestamp(col);
        return t == null ? null : t.toInstant();
    }

    static Long longOrNull(ResultSet rs, String col) throws SQLException {
        long v = rs.getLong(col);
        return rs.wasNull() ? null : v;
    }
}

/** Users. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: JdbcTemplate instead of Spring Data JPA, same method names. */
@Repository
class UserRepository extends JdbcRepository {
    private static final RowMapper<User> MAPPER = (rs, n) -> {
        User u = new User();
        u.setId(rs.getLong("id"));
        u.setEmail(rs.getString("email"));
        u.setName(rs.getString("name"));
        u.setTier(rs.getString("tier"));
        u.setStatus(rs.getString("status"));
        u.setCreatedAt(instant(rs, "created_at"));
        return u;
    };
    private final Clock clock;

    UserRepository(JdbcTemplate jdbc, SchemaInitializer schema, Clock clock) {
        super(jdbc, schema);
        this.clock = clock;
    }

    /** Inserts (setting id and created_at on the object) or updates by id. */
    User save(User u) {
        if (u.getId() == null) {
            if (u.getCreatedAt() == null) u.setCreatedAt(clock.instant());
            u.setId(insert("INSERT INTO users (email, name, tier, status, created_at) VALUES (?, ?, ?, ?, ?)",
                    u.getEmail(), u.getName(), u.getTier(), u.getStatus(), ts(u.getCreatedAt())));
        } else {
            jdbc.update("UPDATE users SET email = ?, name = ?, tier = ?, status = ? WHERE id = ?",
                    u.getEmail(), u.getName(), u.getTier(), u.getStatus(), u.getId());
        }
        return u;
    }

    List<User> saveAll(Iterable<User> users) {
        List<User> out = new ArrayList<>();
        for (User u : users) out.add(save(u));
        return out;
    }

    List<User> findAll() {
        return jdbc.query("SELECT * FROM users ORDER BY id", MAPPER);
    }

    Optional<User> findById(Long id) {
        return jdbc.query("SELECT * FROM users WHERE id = ?", MAPPER, id).stream().findFirst();
    }

    Optional<User> findByEmail(String email) {
        return jdbc.query("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", MAPPER, email).stream().findFirst();
    }

    boolean existsByEmail(String email) {
        return findByEmail(email).isPresent();
    }

    List<User> findActiveOwners() {
        return jdbc.query("SELECT * FROM users WHERE tier = 'owner' AND status = 'active' ORDER BY id", MAPPER);
    }
}

/** Customers. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: JdbcTemplate, offset pagination. */
@Repository
class CustomerRepository extends JdbcRepository {
    private static final RowMapper<Customer> MAPPER = (rs, n) -> {
        Customer c = new Customer();
        c.setId(rs.getLong("id"));
        c.setEmail(rs.getString("email"));
        c.setName(rs.getString("name"));
        c.setTier(rs.getString("tier"));
        java.sql.Date d = rs.getDate("signup_date");
        c.setSignupDate(d == null ? null : d.toLocalDate());
        c.setInvoiceCount(rs.getInt("invoice_count"));
        c.setStatus(rs.getString("status"));
        c.setStripeSubscriptionId(rs.getString("stripe_subscription_id"));
        c.setPaymentMethod(rs.getString("payment_method"));
        c.setAddress(rs.getString("address"));
        c.setNotes(rs.getString("notes"));
        return c;
    };
    private final Clock clock;

    CustomerRepository(JdbcTemplate jdbc, SchemaInitializer schema, Clock clock) {
        super(jdbc, schema);
        this.clock = clock;
    }

    Customer save(Customer c) {
        if (c.getSignupDate() == null) c.setSignupDate(LocalDate.ofInstant(clock.instant(), java.time.ZoneOffset.UTC));
        if (c.getId() == null) {
            c.setId(insert("INSERT INTO customers (email, name, tier, signup_date, invoice_count, status, stripe_subscription_id, payment_method, address, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    c.getEmail(), c.getName(), c.getTier(), java.sql.Date.valueOf(c.getSignupDate()), c.getInvoiceCount(),
                    c.getStatus(), c.getStripeSubscriptionId(), c.getPaymentMethod(), c.getAddress(), c.getNotes()));
        } else {
            jdbc.update("UPDATE customers SET email = ?, name = ?, tier = ?, signup_date = ?, invoice_count = ?, status = ?, stripe_subscription_id = ?, payment_method = ?, address = ?, notes = ? WHERE id = ?",
                    c.getEmail(), c.getName(), c.getTier(), java.sql.Date.valueOf(c.getSignupDate()), c.getInvoiceCount(),
                    c.getStatus(), c.getStripeSubscriptionId(), c.getPaymentMethod(), c.getAddress(), c.getNotes(), c.getId());
        }
        return c;
    }

    Optional<Customer> findById(Long id) {
        return jdbc.query("SELECT * FROM customers WHERE id = ?", MAPPER, id).stream().findFirst();
    }

    boolean existsById(Long id) {
        return findById(id).isPresent();
    }

    List<Customer> findPage(int offset, int limit) {
        return jdbc.query("SELECT * FROM customers ORDER BY id LIMIT ? OFFSET ?", MAPPER, limit, offset);
    }
}

/** Invoices. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. */
@Repository
class InvoiceRepository extends JdbcRepository {
    private static final RowMapper<Invoice> MAPPER = (rs, n) -> {
        Invoice i = new Invoice();
        i.setId(rs.getLong("id"));
        i.setCustomerId(rs.getLong("customer_id"));
        i.setAmount(rs.getBigDecimal("amount"));
        i.setStatus(rs.getString("status"));
        return i;
    };

    InvoiceRepository(JdbcTemplate jdbc, SchemaInitializer schema) {
        super(jdbc, schema);
    }

    Invoice save(Invoice i) {
        if (i.getId() == null) {
            i.setId(insert("INSERT INTO invoices (customer_id, amount, status) VALUES (?, ?, ?)",
                    i.getCustomerId(), i.getAmount(), i.getStatus()));
        } else {
            jdbc.update("UPDATE invoices SET customer_id = ?, amount = ?, status = ? WHERE id = ?",
                    i.getCustomerId(), i.getAmount(), i.getStatus(), i.getId());
        }
        return i;
    }

    Optional<Invoice> findById(Long id) {
        return jdbc.query("SELECT * FROM invoices WHERE id = ?", MAPPER, id).stream().findFirst();
    }
}

/** Deployments. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: JdbcTemplate. */
@Repository
class DeploymentRepository extends JdbcRepository {
    private static final RowMapper<Deployment> MAPPER = (rs, n) -> {
        Deployment d = new Deployment();
        d.setId(rs.getLong("id"));
        d.setCustomerId(rs.getLong("customer_id"));
        d.setDomain(rs.getString("domain"));
        d.setTier(rs.getString("tier"));
        d.setStatus(rs.getString("status"));
        d.setThemeId(longOrNull(rs, "theme_id"));
        d.setDomainVerified(rs.getBoolean("domain_verified"));
        d.setConfig(rs.getString("config"));
        d.setPublishedAt(instant(rs, "published_at"));
        d.setArchivedAt(instant(rs, "archived_at"));
        d.setSuspendReason(rs.getString("suspend_reason"));
        return d;
    };

    DeploymentRepository(JdbcTemplate jdbc, SchemaInitializer schema) {
        super(jdbc, schema);
    }

    Deployment save(Deployment d) {
        if (d.getId() == null) {
            d.setId(insert("INSERT INTO deployments (customer_id, domain, tier, status, theme_id, domain_verified, config, published_at, archived_at, suspend_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    d.getCustomerId(), d.getDomain(), d.getTier(), d.getStatus(), d.getThemeId(), d.isDomainVerified(),
                    d.getConfig(), ts(d.getPublishedAt()), ts(d.getArchivedAt()), d.getSuspendReason()));
        } else {
            jdbc.update("UPDATE deployments SET customer_id = ?, domain = ?, tier = ?, status = ?, theme_id = ?, domain_verified = ?, config = ?, published_at = ?, archived_at = ?, suspend_reason = ? WHERE id = ?",
                    d.getCustomerId(), d.getDomain(), d.getTier(), d.getStatus(), d.getThemeId(), d.isDomainVerified(),
                    d.getConfig(), ts(d.getPublishedAt()), ts(d.getArchivedAt()), d.getSuspendReason(), d.getId());
        }
        return d;
    }

    Optional<Deployment> findById(Long id) {
        return jdbc.query("SELECT * FROM deployments WHERE id = ?", MAPPER, id).stream().findFirst();
    }

    boolean existsByDomain(String domain) {
        Integer n = jdbc.queryForObject("SELECT COUNT(*) FROM deployments WHERE LOWER(domain) = LOWER(?)", Integer.class, domain);
        return n != null && n > 0;
    }

    List<Deployment> findPage(int offset, int limit) {
        return jdbc.query("SELECT * FROM deployments ORDER BY id LIMIT ? OFFSET ?", MAPPER, limit, offset);
    }
}

/** Refunds. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: refunds were never stored. */
@Repository
class RefundRepository extends JdbcRepository {
    RefundRepository(JdbcTemplate jdbc, SchemaInitializer schema) {
        super(jdbc, schema);
    }

    Refund save(Refund r) {
        r.setId(insert("INSERT INTO refunds (invoice_id, amount, reason, status, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                r.getInvoiceId(), r.getAmount(), r.getReason(), r.getStatus(), r.getCreatedBy(), ts(r.getCreatedAt())));
        return r;
    }

    /** Sum of refunds for the invoice that are queued or executed (not failed). */
    BigDecimal sumOpenOrExecuted(Long invoiceId) {
        BigDecimal sum = jdbc.queryForObject(
                "SELECT COALESCE(SUM(amount), 0) FROM refunds WHERE invoice_id = ? AND status <> 'failed'",
                BigDecimal.class, invoiceId);
        return sum == null ? BigDecimal.ZERO : sum;
    }

    int countByStatus(String status) {
        Integer n = jdbc.queryForObject("SELECT COUNT(*) FROM refunds WHERE status = ?", Integer.class, status);
        return n == null ? 0 : n;
    }
}

/** Audit log. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: JdbcTemplate; search with filters. */
@Repository
class AuditLogRepository extends JdbcRepository {
    private static final RowMapper<AuditLog> MAPPER = (rs, n) -> {
        AuditLog a = new AuditLog();
        a.setId(rs.getLong("id"));
        a.setAction(rs.getString("action"));
        a.setActorId(rs.getLong("actor_id"));
        a.setResourceType(rs.getString("resource_type"));
        a.setResourceId(longOrNull(rs, "resource_id"));
        a.setOldValue(rs.getString("old_value"));
        a.setNewValue(rs.getString("new_value"));
        a.setReason(rs.getString("reason"));
        a.setTimestamp(instant(rs, "created_at"));
        return a;
    };

    AuditLogRepository(JdbcTemplate jdbc, SchemaInitializer schema) {
        super(jdbc, schema);
    }

    AuditLog save(AuditLog a) {
        a.setId(insert("INSERT INTO audit_log (action, actor_id, resource_type, resource_id, old_value, new_value, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                a.getAction(), a.getActorId(), a.getResourceType(), a.getResourceId(), a.getOldValue(),
                a.getNewValue(), a.getReason(), ts(a.getTimestamp())));
        return a;
    }

    /** Newest first (ties by id, newest first); every filter optional. */
    List<AuditLog> search(String action, Long resourceId, Instant from, Instant to, int limit, int offset) {
        StringBuilder sql = new StringBuilder("SELECT * FROM audit_log WHERE 1 = 1");
        List<Object> args = new ArrayList<>();
        if (action != null) { sql.append(" AND action = ?"); args.add(action); }
        if (resourceId != null) { sql.append(" AND resource_id = ?"); args.add(resourceId); }
        if (from != null) { sql.append(" AND created_at >= ?"); args.add(ts(from)); }
        if (to != null) { sql.append(" AND created_at <= ?"); args.add(ts(to)); }
        sql.append(" ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?");
        args.add(limit);
        args.add(offset);
        return jdbc.query(sql.toString(), MAPPER, args.toArray());
    }
}

/** Governance actions. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: JdbcTemplate. */
@Repository
class GovernanceActionRepository extends JdbcRepository {
    private static final RowMapper<GovernanceAction> MAPPER = (rs, n) -> {
        GovernanceAction g = new GovernanceAction();
        g.setId(rs.getLong("id"));
        g.setActionType(rs.getString("action_type"));
        g.setActorId(rs.getLong("actor_id"));
        g.setTargetResourceId(longOrNull(rs, "target_resource_id"));
        g.setReason(rs.getString("reason"));
        g.setSubmittedAt(instant(rs, "submitted_at"));
        g.setStatus(rs.getString("status"));
        g.setApprovedBy(longOrNull(rs, "approved_by"));
        g.setApprovedAt(instant(rs, "approved_at"));
        g.setRejectionReason(rs.getString("rejection_reason"));
        g.setExecutionResult(rs.getString("execution_result"));
        g.setNewTier(rs.getString("new_tier"));
        return g;
    };
    private final Clock clock;

    GovernanceActionRepository(JdbcTemplate jdbc, SchemaInitializer schema, Clock clock) {
        super(jdbc, schema);
        this.clock = clock;
    }

    GovernanceAction save(GovernanceAction g) {
        if (g.getId() == null) {
            if (g.getSubmittedAt() == null) g.setSubmittedAt(clock.instant());
            g.setId(insert("INSERT INTO governance_actions (action_type, actor_id, target_resource_id, reason, submitted_at, status, approved_by, approved_at, rejection_reason, execution_result, new_tier) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    g.getActionType(), g.getActorId(), g.getTargetResourceId(), g.getReason(), ts(g.getSubmittedAt()),
                    g.getStatus(), g.getApprovedBy(), ts(g.getApprovedAt()), g.getRejectionReason(), g.getExecutionResult(),
                    g.getNewTier()));
        } else {
            jdbc.update("UPDATE governance_actions SET status = ?, approved_by = ?, approved_at = ?, rejection_reason = ?, execution_result = ? WHERE id = ?",
                    g.getStatus(), g.getApprovedBy(), ts(g.getApprovedAt()), g.getRejectionReason(), g.getExecutionResult(), g.getId());
        }
        return g;
    }

    Optional<GovernanceAction> findById(Long id) {
        return jdbc.query("SELECT * FROM governance_actions WHERE id = ?", MAPPER, id).stream().findFirst();
    }

    /** Locks the row for the decision (no two owners decide the same action at once). */
    Optional<GovernanceAction> findByIdForUpdate(Long id) {
        return jdbc.query("SELECT * FROM governance_actions WHERE id = ? FOR UPDATE", MAPPER, id).stream().findFirst();
    }

    List<GovernanceAction> findByStatus(String status, int offset, int limit) {
        return jdbc.query("SELECT * FROM governance_actions WHERE status = ? ORDER BY submitted_at, id LIMIT ? OFFSET ?",
                MAPPER, status, limit, offset);
    }
}

/* ---------- SERVICES ---------- */

/**
 * Writes audit entries inside the caller's transaction (spec: "audit_log write before commit"). Values are
 * serialized as JSON by Jackson. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: string-built JSON
 * allowed injection. Touches: the database.
 */
@Service
class AuditService {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final AuditLogRepository auditRepo;
    private final Clock clock;

    AuditService(AuditLogRepository auditRepo, Clock clock) {
        this.auditRepo = auditRepo;
        this.clock = clock;
    }

    void log(String action, Long actorId, String resourceType, Long resourceId,
             Object oldValue, Object newValue, String reason) {
        AuditLog a = new AuditLog();
        a.setAction(action);
        a.setActorId(actorId);
        a.setResourceType(resourceType);
        a.setResourceId(resourceId);
        a.setOldValue(toJson(oldValue));
        a.setNewValue(toJson(newValue));
        a.setReason(reason);
        a.setTimestamp(clock.instant());
        auditRepo.save(a);
    }

    static String toJson(Object value) {
        if (value == null) return null;
        try {
            return JSON.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("unserializable audit value", e);
        }
    }

    List<AuditLog> search(String action, Long resourceId, Instant from, Instant to, int limit, int offset) {
        return auditRepo.search(action, resourceId, from, to, limit, offset);
    }
}

/**
 * Users domain: create, reset password, change role, suspend; each audited in the same transaction.
 * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: validation (email, name, role), the invite and
 * reset emails are really sent through AdminMailer, reset tokens are random and stored only as SHA-256 hashes, the
 * actor is passed in by the controller (from the authenticated request). Touches: the database, email.
 */
@Service
class UserService {
    /** Staff roles a user may hold (admin spec TIERS; lowercase since 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). */
    static final Set<String> VALID_TIERS = Tiers.ROLES;
    /**
     * An e-mail address: one "@", no spaces, and a domain of dot-separated labels with no empty label. Each label
     * excludes ".", so every "." in the domain can only be a separator and the match is linear. Changed 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP: the old pattern ([^@\\s]+\\.[^@\\s]+) could split the domain at any of
     * its dots, which code scanning flagged as a polynomial regular expression on user input (PR 19). Touches nothing.
     */
    private static final Pattern EMAIL = Pattern.compile("^[^@\\s]+@[^@\\s.]+(?:\\.[^@\\s.]+)+$");
    private static final SecureRandom RANDOM = new SecureRandom();

    private final UserRepository userRepo;
    private final AuditService audit;
    private final AdminMailer mailer;
    private final TransactionTemplate tx;
    private final JdbcTemplate jdbc;
    private final Clock clock;
    private final String baseUrl;

    UserService(UserRepository userRepo, AuditService audit, AdminMailer mailer, TransactionTemplate tx,
                JdbcTemplate jdbc, Clock clock, @Value("${admin.app.base-url:http://localhost:8080}") String baseUrl) {
        this.userRepo = userRepo;
        this.audit = audit;
        this.mailer = mailer;
        this.tx = tx;
        this.jdbc = jdbc;
        this.clock = clock;
        this.baseUrl = baseUrl;
    }

    /** Creates a user (409 email_exists; 400 invalid_email/invalid_name/invalid_tier) and sends the invite if asked. */
    User createUser(User actor, String email, String name, String tier, boolean notify) {
        String normalizedEmail = email == null ? null : email.trim().toLowerCase(Locale.ROOT);
        if (normalizedEmail == null || normalizedEmail.length() > 255 || !EMAIL.matcher(normalizedEmail).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_email");
        }
        String trimmedName = name == null ? "" : name.trim();
        if (trimmedName.isEmpty() || trimmedName.length() > 255) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_name");
        }
        if (tier == null || !VALID_TIERS.contains(tier)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_tier");
        }
        User created = tx.execute(status -> {
            if (userRepo.existsByEmail(normalizedEmail)) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "email_exists");
            }
            User u = new User();
            u.setEmail(normalizedEmail);
            u.setName(trimmedName);
            u.setTier(tier);
            userRepo.save(u);
            audit.log("user_created", actor.getId(), "user", u.getId(), null,
                    Map.of("email", normalizedEmail, "tier", tier), null);
            return u;
        });
        if (notify) {
            mailer.send(normalizedEmail, "You have been invited", "Sign in at " + baseUrl + " to get started.");
        }
        return created;
    }

    /** Issues a one-hour reset token and emails the link (400 cannot_reset_own_password / cannot_reset_last_owner). */
    void resetPassword(User actor, Long userId) {
        String token = randomToken();
        User target = tx.execute(status -> {
            User t = userRepo.findById(userId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "user_not_found"));
            if (t.getId().equals(actor.getId())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "cannot_reset_own_password");
            }
            if (isLastActiveOwner(t)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "cannot_reset_last_owner");
            }
            Instant now = clock.instant();
            jdbc.update("INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
                    t.getId(), sha256Hex(token), Timestamp.from(now.plus(Duration.ofHours(1))));
            audit.log("password_reset_initiated", actor.getId(), "user", t.getId(), null, null, null);
            return t;
        });
        mailer.send(target.getEmail(), "Reset your password", baseUrl + "/reset-password?token=" + token);
    }

    /**
     * Changes a user's role; returns the old role. The last active owner cannot be demoted.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.4 ruling af92d76, change_role "Order"): the gate
     * (owner_only, checked by the caller, and user_id != current_user_id) now runs before the checks, so an owner
     * changing their own role always gets 400 cannot_change_own_role, even as the last owner. It ran the last-owner
     * check first (answering cannot_demote_last_owner) and the tier check before both; the last-owner refusal is now
     * reached through a governance change_role (ADMIN-07).
     * In: the verified owner, the target id, the new tier. Out: the old tier, or ResponseStatusException 400
     * cannot_change_own_role | invalid_tier | cannot_demote_last_owner, 404 user_not_found.
     * Touches: the database (users, audit_logs).
     */
    String changeRole(User actor, Long userId, String newTier) {
        if (userId != null && userId.equals(actor.getId())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "cannot_change_own_role");
        }
        if (newTier == null || !VALID_TIERS.contains(newTier)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_tier");
        }
        return tx.execute(status -> {
            User target = userRepo.findById(userId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "user_not_found"));
            if (isLastActiveOwner(target) && !Tiers.OWNER.equals(newTier)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "cannot_demote_last_owner");
            }
            String oldTier = target.getTier();
            target.setTier(newTier);
            userRepo.save(target);
            audit.log("role_changed", actor.getId(), "user", target.getId(), oldTier, newTier, null);
            return oldTier;
        });
    }

    /** Suspends a user (400 cannot_suspend_yourself / cannot_suspend_last_owner; reason required). */
    void suspendUser(User actor, Long userId, String reason) {
        if (reason == null || reason.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "reason_required");
        }
        tx.executeWithoutResult(status -> {
            User target = userRepo.findById(userId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "user_not_found"));
            if (target.getId().equals(actor.getId())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "cannot_suspend_yourself");
            }
            if (isLastActiveOwner(target)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "cannot_suspend_last_owner");
            }
            String old = target.getStatus();
            target.setStatus("suspended");
            userRepo.save(target);
            audit.log("user_suspended", actor.getId(), "user", target.getId(), old, "suspended", reason);
        });
    }

    /** True when the user is the only active owner. */
    boolean isLastActiveOwner(User user) {
        if (!Tiers.OWNER.equals(user.getTier()) || !"active".equals(user.getStatus())) return false;
        List<User> owners = userRepo.findActiveOwners();
        return owners.size() == 1 && owners.get(0).getId().equals(user.getId());
    }

    private static String randomToken() {
        byte[] b = new byte[32];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    static String sha256Hex(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}

/**
 * Customers domain: list, detail, change plan (Stripe), queue refund.
 * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: Stripe through AdminStripeGateway; refunds are
 * checked against the customer's succeeded invoice, stored as DECIMAL and audited; old tier returned. Touches: the
 * database, Stripe (money).
 */
@Service
class CustomerService {
    private static final Pattern TIER = Pattern.compile("^[A-Za-z0-9_-]{1,50}$");
    private final CustomerRepository custRepo;
    private final InvoiceRepository invoiceRepo;
    private final RefundRepository refundRepo;
    private final AuditService audit;
    private final AdminStripeGateway stripe;
    private final TransactionTemplate tx;
    private final Clock clock;

    CustomerService(CustomerRepository custRepo, InvoiceRepository invoiceRepo, RefundRepository refundRepo,
                    AuditService audit, AdminStripeGateway stripe, TransactionTemplate tx, Clock clock) {
        this.custRepo = custRepo;
        this.invoiceRepo = invoiceRepo;
        this.refundRepo = refundRepo;
        this.audit = audit;
        this.stripe = stripe;
        this.tx = tx;
        this.clock = clock;
    }

    List<Customer> listCustomers(int offset, int limit) {
        return custRepo.findPage(offset, limit);
    }

    Customer getDetail(Long id) {
        return custRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "customer_not_found"));
    }

    /**
     * change_plan (owner only; the actor is the verified caller). Same rule as billing change_plan (flow 2):
     * unknown tier -> 400 invalid_tier; the subscription is retrieved and anything but exactly one item -> 409
     * subscription_item_ambiguous; both before any update. Then Stripe updates that item's price with prorations,
     * and only on success the DB tier and audit change. In: actor, customer id, new tier. Out: the old tier.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-12: the gateway used to pick the first item and,
     * with none, sent a bare price). Changed again the same day (admin spec TIERS, Phase B.2): only a plan
     * (solo/team/enterprise) is accepted, so a staff role such as 'owner' is 400 invalid_tier before any Stripe call.
     * Touches: Stripe (money), the database.
     */
    String changePlan(User actor, Long customerId, String newTier) {
        if (newTier == null || !TIER.matcher(newTier).matches() || !Tiers.PLANS.contains(newTier)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_tier");
        }
        String price = stripe.priceFor(newTier);
        if (price == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_tier");
        }
        Customer cust = getDetail(customerId);
        if (cust.getStripeSubscriptionId() == null || cust.getStripeSubscriptionId().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "no_subscription");
        }
        List<String> itemIds;
        try {
            itemIds = stripe.subscriptionItemIds(cust.getStripeSubscriptionId());
        } catch (StripeException | RuntimeException e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "stripe_error");
        }
        if (itemIds.size() != 1) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "subscription_item_ambiguous");
        }
        try {
            stripe.updateSubscriptionItem(cust.getStripeSubscriptionId(), itemIds.get(0), price);
        } catch (StripeException | RuntimeException e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "stripe_error");
        }
        return tx.execute(status -> {
            Customer c = getDetail(customerId);
            String oldTier = c.getTier();
            c.setTier(newTier);
            custRepo.save(c);
            audit.log("plan_changed", actor.getId(), "customer", c.getId(), oldTier, newTier, null);
            return oldTier;
        });
    }

    /** Queues a refund (never executes it). createdBy is the authenticated actor. */
    Refund queueRefund(User actor, Long customerId, Long invoiceId, BigDecimal amount, String reason) {
        if (amount == null || amount.signum() <= 0 || amount.scale() > 2) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_amount");
        }
        if (reason == null || reason.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "reason_required");
        }
        return tx.execute(status -> {
            Invoice inv = invoiceRepo.findById(invoiceId)
                    .filter(i -> i.getCustomerId().equals(customerId))
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "invoice_not_found"));
            if (!"succeeded".equals(inv.getStatus())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_invoice_status");
            }
            BigDecimal available = inv.getAmount().subtract(refundRepo.sumOpenOrExecuted(inv.getId()));
            if (amount.compareTo(available) > 0) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "refund_exceeds_invoice");
            }
            Refund r = new Refund();
            r.setInvoiceId(inv.getId());
            r.setAmount(amount);
            r.setReason(reason);
            r.setStatus("queued");
            r.setCreatedBy(actor.getId());
            r.setCreatedAt(clock.instant());
            refundRepo.save(r);
            audit.log("refund_queued", actor.getId(), "invoice", inv.getId(), null,
                    Map.of("refund_id", r.getId(), "amount", amount.toPlainString()), reason);
            return r;
        });
    }
}

/**
 * Deployments domain: create, publish (double gate), suspend, retire, list.
 * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: publish checks SafetyFlags (configuration, not a
 * hard-coded true), draft status, verified domain and a theme; create validates and initializes config; retire
 * records archived_at. Touches: the database.
 */
@Service
class DeploymentService {
    private static final Pattern DOMAIN = Pattern.compile("^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$");
    private final DeploymentRepository depRepo;
    private final CustomerRepository custRepo;
    private final AuditService audit;
    private final SafetyFlags safety;
    private final TransactionTemplate tx;
    private final Clock clock;

    DeploymentService(DeploymentRepository depRepo, CustomerRepository custRepo, AuditService audit,
                      SafetyFlags safety, TransactionTemplate tx, Clock clock) {
        this.depRepo = depRepo;
        this.custRepo = custRepo;
        this.audit = audit;
        this.safety = safety;
        this.tx = tx;
        this.clock = clock;
    }

    /**
     * Creates a draft deployment (domain_verified false) with its initial config. Theme ids are not validated here:
     * this template has no themes table. In: actor, customer id, domain, plan tier, theme id. Out: the deployment.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (admin spec TIERS, Phase B.2): the tier must be a plan
     * (solo/team/enterprise); a staff role or anything else is 400 invalid_tier (any non-blank value was accepted).
     * Touches: the database.
     */
    Deployment createDeployment(User actor, Long customerId, String domain, String tier, Long themeId) {
        String normalizedDomain = domain == null ? "" : domain.trim().toLowerCase(Locale.ROOT);
        if (!DOMAIN.matcher(normalizedDomain).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_domain");
        }
        if (tier == null || !Tiers.PLANS.contains(tier)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_tier");
        }
        if (themeId == null || themeId <= 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "theme_not_found");
        }
        return tx.execute(status -> {
            if (!custRepo.existsById(customerId)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "customer_not_found");
            }
            if (depRepo.existsByDomain(normalizedDomain)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "domain_exists");
            }
            Deployment d = new Deployment();
            d.setCustomerId(customerId);
            d.setDomain(normalizedDomain);
            d.setTier(tier);
            d.setThemeId(themeId);
            d.setConfig(AuditService.toJson(Map.of("theme_id", themeId, "tier", tier)));
            depRepo.save(d);
            audit.log("deployment_created", actor.getId(), "deployment", d.getId(), null,
                    Map.of("customer_id", customerId, "domain", normalizedDomain), null);
            return d;
        });
    }

    /** Publishes a draft (403 publish_not_allowed; 400 cannot_publish_non_draft / domain_not_verified / theme_not_set). */
    Deployment publish(User actor, Long deploymentId) {
        if (!safety.canPublish()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "publish_not_allowed");
        }
        return tx.execute(status -> {
            Deployment d = find(deploymentId);
            if (!"draft".equals(d.getStatus())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "cannot_publish_non_draft");
            }
            if (!d.isDomainVerified()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "domain_not_verified");
            }
            if (d.getThemeId() == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "theme_not_set");
            }
            d.setStatus("live");
            d.setPublishedAt(clock.instant());
            depRepo.save(d);
            audit.log("deployment_published", actor.getId(), "deployment", d.getId(), "draft", "live", null);
            return d;
        });
    }

    /** Suspends a deployment (reason required; archived ones cannot be suspended). */
    Deployment suspend(User actor, Long deploymentId, String reason) {
        if (reason == null || reason.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "reason_required");
        }
        return tx.execute(status -> {
            Deployment d = find(deploymentId);
            if ("archived".equals(d.getStatus())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "deployment_archived");
            }
            String old = d.getStatus();
            d.setStatus("suspended");
            d.setSuspendReason(reason);
            depRepo.save(d);
            audit.log("deployment_suspended", actor.getId(), "deployment", d.getId(), old, "suspended", reason);
            return d;
        });
    }

    /** Archives a deployment with archived_at. */
    Deployment retire(User actor, Long deploymentId) {
        return tx.execute(status -> {
            Deployment d = find(deploymentId);
            String old = d.getStatus();
            d.setStatus("archived");
            d.setArchivedAt(clock.instant());
            depRepo.save(d);
            audit.log("deployment_archived", actor.getId(), "deployment", d.getId(), old, "archived", null);
            return d;
        });
    }

    List<Deployment> listDeployments(int offset, int limit) {
        return depRepo.findPage(offset, limit);
    }

    private Deployment find(Long id) {
        return depRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "deployment_not_found"));
    }
}

/**
 * Governance: pending list, approve (executes the original action) and reject (reason required), audit search.
 * Supported action types: change_role (new_tier), suspend_user, delete_user (soft delete: status 'deleted'),
 * retire_deployment (change_role added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, Phase B.3 ADMIN-07). The
 * submitter cannot approve their own action, and the last active owner cannot be suspended or deleted.
 * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: approve executed nothing, reject did not require
 * a reason, the audit search was a placeholder. Touches: the database.
 */
@Service
class GovernanceService {
    private final GovernanceActionRepository gaRepo;
    private final UserRepository userRepo;
    private final DeploymentRepository depRepo;
    private final UserService userService;
    private final AuditService audit;
    private final TransactionTemplate tx;
    private final Clock clock;

    GovernanceService(GovernanceActionRepository gaRepo, UserRepository userRepo, DeploymentRepository depRepo,
                      UserService userService, AuditService audit, TransactionTemplate tx, Clock clock) {
        this.gaRepo = gaRepo;
        this.userRepo = userRepo;
        this.depRepo = depRepo;
        this.userService = userService;
        this.audit = audit;
        this.tx = tx;
        this.clock = clock;
    }

    List<GovernanceAction> pendingActions(int offset, int limit) {
        return gaRepo.findByStatus("pending", offset, limit);
    }

    /** Approves (and executes) or rejects a pending action; returns the new status. */
    String decide(User actor, Long actionId, String decision, String reason) {
        boolean approve = "approve".equalsIgnoreCase(decision);
        boolean reject = "reject".equalsIgnoreCase(decision);
        if (!approve && !reject) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_decision");
        }
        if (reject && (reason == null || reason.isBlank())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "reason_required");
        }
        return tx.execute(status -> {
            GovernanceAction ga = gaRepo.findByIdForUpdate(actionId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "action_not_found"));
            if (!"pending".equals(ga.getStatus())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "action_not_pending");
            }
            if (reject) {
                ga.setStatus("rejected");
                ga.setRejectionReason(reason);
                gaRepo.save(ga);
                audit.log("action_rejected", actor.getId(), "governance", ga.getId(), "pending", "rejected", reason);
                return "rejected";
            }
            if (actor.getId().equals(ga.getActorId())) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "cannot_approve_own_action");
            }
            String result = execute(actor, ga);
            ga.setStatus("approved");
            ga.setApprovedBy(actor.getId());
            ga.setApprovedAt(clock.instant());
            ga.setExecutionResult(result);
            gaRepo.save(ga);
            audit.log("action_approved", actor.getId(), "governance", ga.getId(), "pending", "approved", result);
            return "approved";
        });
    }

    /**
     * Runs the approved action inside the decision's transaction; returns a short result. Any refusal it throws
     * rolls the whole decision back, so the action stays pending.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.3, ADMIN-07): supports change_role (target user,
     * new_tier): 400 invalid_tier for anything but a staff role, 400 cannot_demote_last_owner when it would demote the
     * last active owner, otherwise the role changes and role_changed is audited. In: the approver and the action.
     * Out: the execution result. Touches: the database.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (review finding 4525101248; spec LAST OWNER, approver rule):
     * a change_role whose target is the approver ({@code actor}) is refused with 400 cannot_change_own_role, checked
     * AFTER the last-owner check, so the decision rolls back and the action stays pending, as in PHP and JavaScript.
     */
    private String execute(User actor, GovernanceAction ga) {
        Long target = ga.getTargetResourceId();
        switch (ga.getActionType() == null ? "" : ga.getActionType()) {
            case "change_role": {
                String newTier = ga.getNewTier();
                if (newTier == null || !UserService.VALID_TIERS.contains(newTier)) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_tier");
                }
                User u = userRepo.findById(target)
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "user_not_found"));
                if (userService.isLastActiveOwner(u) && !Tiers.OWNER.equals(newTier)) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "cannot_demote_last_owner");
                }
                if (u.getId().equals(actor.getId())) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "cannot_change_own_role");
                }
                String oldTier = u.getTier();
                u.setTier(newTier);
                userRepo.save(u);
                audit.log("role_changed", actor.getId(), "user", u.getId(), oldTier, newTier, null);
                return "user " + u.getId() + " " + oldTier + " -> " + newTier;
            }
            case "suspend_user":
            case "delete_user": {
                User u = userRepo.findById(target)
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "user_not_found"));
                if (userService.isLastActiveOwner(u)) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "cannot_remove_last_owner");
                }
                String newStatus = "delete_user".equals(ga.getActionType()) ? "deleted" : "suspended";
                u.setStatus(newStatus);
                userRepo.save(u);
                return "user " + u.getId() + " " + newStatus;
            }
            case "retire_deployment": {
                Deployment d = depRepo.findById(target)
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "deployment_not_found"));
                d.setStatus("archived");
                d.setArchivedAt(clock.instant());
                depRepo.save(d);
                return "deployment " + d.getId() + " archived";
            }
            default:
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "unsupported_action_type");
        }
    }

    List<AuditLog> searchAudit(String actionType, Long resourceId, Instant from, Instant to, int limit, int offset) {
        return audit.search(actionType, resourceId, from, to, limit, offset);
    }
}

/* ---------- CONTROLLERS ---------- */

/** Request-payload helpers that turn bad input into 400s. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. */
final class Payloads {
    private Payloads() {}

    static Map<String, Object> body(Map<String, Object> payload) {
        return payload == null ? Map.of() : payload;
    }

    static Long requireLong(Map<String, Object> p, String key) {
        Object v = body(p).get(key);
        if (v instanceof Number && ((Number) v).doubleValue() == Math.rint(((Number) v).doubleValue())) {
            return ((Number) v).longValue();
        }
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "missing_or_invalid_" + key);
    }

    static String optString(Map<String, Object> p, String key) {
        Object v = body(p).get(key);
        if (v == null) return null;
        if (v instanceof String) return (String) v;
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "missing_or_invalid_" + key);
    }

    static String requireString(Map<String, Object> p, String key) {
        String s = optString(p, key);
        if (s == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "missing_or_invalid_" + key);
        return s;
    }

    static BigDecimal requireMoney(Map<String, Object> p, String key) {
        Object v = body(p).get(key);
        if (v instanceof Number) return new BigDecimal(v.toString());
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "missing_or_invalid_" + key);
    }

    /** Ordered map that, unlike Map.of, accepts null values (JSON null). */
    static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    static String iso(Instant i) {
        return i == null ? null : i.toString();
    }

    static int clamp(int v, int min, int max) {
        return Math.max(min, Math.min(max, v));
    }
}

/** POST /admin/users/action. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: real old_tier, validated payload. */
@RestController
@RequestMapping("/admin/users")
class AdminUserController {
    private final UserService userService;

    AdminUserController(UserService userService) {
        this.userService = userService;
    }

    /** Owner-only user actions chosen by X-Action: create, reset_password, change_role, suspend. Input: JSON body. Output: the spec's response or {error, message}. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: actor from the authenticated request. Touches: the database, email. */
    @PostMapping("/action")
    public ResponseEntity<?> handle(@RequestHeader("X-Action") String action,
                                    @RequestBody(required = false) Map<String, Object> payload) {
        User actor = SecurityUtil.requireOwner();
        switch (action) {
            case "create": {
                User u = userService.createUser(actor, Payloads.requireString(payload, "email"),
                        Payloads.requireString(payload, "name"), Payloads.requireString(payload, "tier"),
                        Boolean.TRUE.equals(Payloads.body(payload).get("notify")));
                return ResponseEntity.ok(Payloads.map("success", true, "user_id", u.getId(), "email", u.getEmail(),
                        "tier", u.getTier(), "created_at", Payloads.iso(u.getCreatedAt())));
            }
            case "reset_password":
                userService.resetPassword(actor, Payloads.requireLong(payload, "user_id"));
                return ResponseEntity.ok(Payloads.map("success", true, "status", "reset_email_sent"));
            case "change_role": {
                Long uid = Payloads.requireLong(payload, "user_id");
                String newTier = Payloads.requireString(payload, "new_tier");
                String oldTier = userService.changeRole(actor, uid, newTier);
                return ResponseEntity.ok(Payloads.map("success", true, "user_id", uid, "old_tier", oldTier, "new_tier", newTier));
            }
            case "suspend": {
                Long uid = Payloads.requireLong(payload, "user_id");
                userService.suspendUser(actor, uid, Payloads.requireString(payload, "reason"));
                return ResponseEntity.ok(Payloads.map("success", true, "user_id", uid, "suspended", true));
            }
            default:
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "unknown_action");
        }
    }
}

/** /admin/customers. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: null-safe maps, real detail fields, refunds stored. */
@RestController
@RequestMapping("/admin/customers")
class AdminCustomerController {
    private final CustomerService custService;
    private final Clock clock;

    AdminCustomerController(CustomerService custService, Clock clock) {
        this.custService = custService;
        this.clock = clock;
    }

    /** Admin-or-owner customer list, page/size (size 1 to 100). Output: [{customer_id, email, name, tier, signup_date, invoice_count, status}]. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the database. */
    @GetMapping
    public ResponseEntity<?> list(@RequestParam(name = "page", defaultValue = "0") int page,
                                  @RequestParam(name = "size", defaultValue = "20") int size) {
        SecurityUtil.requireAdminOrOwner();
        int limit = Payloads.clamp(size, 1, 100);
        int offset = Math.max(0, page) * limit;
        List<Map<String, Object>> data = new ArrayList<>();
        for (Customer c : custService.listCustomers(offset, limit)) {
            data.add(Payloads.map("customer_id", c.getId(), "email", c.getEmail(), "name", c.getName(),
                    "tier", c.getTier(), "signup_date", c.getSignupDate() == null ? null : c.getSignupDate().toString(),
                    "invoice_count", c.getInvoiceCount(), "status", c.getStatus()));
        }
        return ResponseEntity.ok(data);
    }

    /** Admin-or-owner customer detail. Output: {customer_id, email, name, tier, subscription_status, payment_method, address, notes}. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: real fields instead of "placeholder". Touches: reads the database. */
    @GetMapping("/{customerId}")
    public ResponseEntity<?> detail(@PathVariable("customerId") Long customerId) {
        SecurityUtil.requireAdminOrOwner();
        Customer c = custService.getDetail(customerId);
        return ResponseEntity.ok(Payloads.map("customer_id", c.getId(), "email", c.getEmail(), "name", c.getName(),
                "tier", c.getTier(), "subscription_status", c.getStatus(), "payment_method", c.getPaymentMethod(),
                "address", c.getAddress(), "notes", c.getNotes()));
    }

    /** Owner-only customer actions by X-Action: change_plan (Stripe), queue_refund. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: refunds stored and checked, old_tier real. Touches: the database, Stripe (money). */
    @PostMapping("/{customerId}/action")
    public ResponseEntity<?> action(@PathVariable("customerId") Long customerId,
                                    @RequestHeader("X-Action") String action,
                                    @RequestBody(required = false) Map<String, Object> payload) {
        User actor = SecurityUtil.requireOwner();
        switch (action) {
            case "change_plan": {
                String newTier = Payloads.requireString(payload, "new_tier");
                String oldTier = custService.changePlan(actor, customerId, newTier);
                return ResponseEntity.ok(Payloads.map("success", true, "customer_id", customerId, "old_tier", oldTier,
                        "new_tier", newTier, "effective_date", clock.instant().toString()));
            }
            case "queue_refund": {
                Refund r = custService.queueRefund(actor, customerId, Payloads.requireLong(payload, "invoice_id"),
                        Payloads.requireMoney(payload, "amount"), Payloads.requireString(payload, "reason"));
                return ResponseEntity.ok(Payloads.map("success", true, "refund_id", r.getId(), "status", r.getStatus(),
                        "amount", r.getAmount()));
            }
            default:
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "unknown_action");
        }
    }
}

/** /admin/deployments. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: null-safe maps, actor passed down. */
@RestController
@RequestMapping("/admin/deployments")
class AdminDeploymentController {
    private final DeploymentService depService;

    AdminDeploymentController(DeploymentService depService) {
        this.depService = depService;
    }

    /** Admin-or-owner deployment list, page/size. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: null published_at no longer crashes Map.of. Touches: reads the database. */
    @GetMapping
    public ResponseEntity<?> list(@RequestParam(name = "page", defaultValue = "0") int page,
                                  @RequestParam(name = "size", defaultValue = "20") int size) {
        SecurityUtil.requireAdminOrOwner();
        int limit = Payloads.clamp(size, 1, 100);
        List<Map<String, Object>> data = new ArrayList<>();
        for (Deployment d : depService.listDeployments(Math.max(0, page) * limit, limit)) {
            data.add(Payloads.map("deployment_id", d.getId(), "customer_id", d.getCustomerId(), "domain", d.getDomain(),
                    "tier", d.getTier(), "status", d.getStatus(), "theme", d.getThemeId(),
                    "published_at", Payloads.iso(d.getPublishedAt())));
        }
        return ResponseEntity.ok(data);
    }

    /** Owner-only deployment actions by X-Action: create, publish (double gate), suspend, retire. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database. */
    @PostMapping("/action")
    public ResponseEntity<?> action(@RequestHeader("X-Action") String action,
                                    @RequestBody(required = false) Map<String, Object> payload) {
        User actor = SecurityUtil.requireOwner();
        switch (action) {
            case "create": {
                Deployment d = depService.createDeployment(actor, Payloads.requireLong(payload, "customer_id"),
                        Payloads.requireString(payload, "domain"), Payloads.requireString(payload, "tier"),
                        Payloads.requireLong(payload, "theme_id"));
                return ResponseEntity.ok(Payloads.map("success", true, "deployment_id", d.getId(), "domain", d.getDomain(),
                        "tier", d.getTier()));
            }
            case "publish": {
                Deployment d = depService.publish(actor, Payloads.requireLong(payload, "deployment_id"));
                return ResponseEntity.ok(Payloads.map("success", true, "deployment_id", d.getId(), "status", d.getStatus(),
                        "public_url", "https://" + d.getDomain()));
            }
            case "suspend": {
                Deployment d = depService.suspend(actor, Payloads.requireLong(payload, "deployment_id"),
                        Payloads.requireString(payload, "reason"));
                return ResponseEntity.ok(Payloads.map("success", true, "deployment_id", d.getId(), "status", d.getStatus()));
            }
            case "retire": {
                Deployment d = depService.retire(actor, Payloads.requireLong(payload, "deployment_id"));
                return ResponseEntity.ok(Payloads.map("success", true, "deployment_id", d.getId(), "status", d.getStatus()));
            }
            default:
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "unknown_action");
        }
    }
}

/** /admin/governance. Parameter names are explicit (templates are compiled without -parameters). Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: status from the decision; real audit search. */
@RestController
@RequestMapping("/admin/governance")
class AdminGovernanceController {
    private final GovernanceService govService;

    AdminGovernanceController(GovernanceService govService) {
        this.govService = govService;
    }

    /** Admin-or-owner list of pending governance actions, oldest first. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the database. */
    @GetMapping("/actions")
    public ResponseEntity<?> pending(@RequestParam(name = "page", defaultValue = "0") int page,
                                     @RequestParam(name = "size", defaultValue = "20") int size) {
        SecurityUtil.requireAdminOrOwner();
        int limit = Payloads.clamp(size, 1, 100);
        List<Map<String, Object>> data = new ArrayList<>();
        for (GovernanceAction a : govService.pendingActions(Math.max(0, page) * limit, limit)) {
            data.add(Payloads.map("action_id", a.getId(), "action_type", a.getActionType(), "actor", a.getActorId(),
                    "target_resource_id", a.getTargetResourceId(), "reason", a.getReason(),
                    "submitted_at", Payloads.iso(a.getSubmittedAt()), "status", a.getStatus()));
        }
        return ResponseEntity.ok(data);
    }

    /** Owner-only approve (executes) or reject (reason required) by X-Decide. Output: {success, action_id, status}. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: status comes from what happened. Touches: the database. */
    @PostMapping("/actions/{actionId}/decide")
    public ResponseEntity<?> decide(@PathVariable("actionId") Long actionId,
                                    @RequestHeader("X-Decide") String decide,
                                    @RequestBody(required = false) Map<String, Object> payload) {
        User actor = SecurityUtil.requireOwner();
        String status = govService.decide(actor, actionId, decide, Payloads.optString(payload, "reason"));
        return ResponseEntity.ok(Payloads.map("success", true, "action_id", actionId, "status", status));
    }

    /** Admin-or-owner audit search: action_type, resource_id, date_from/date_to (ISO-8601), limit (1 to 1000, default 100), offset. Newest first. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: returned an empty list. Touches: reads the database. */
    @GetMapping("/audit-log")
    public ResponseEntity<?> auditLog(@RequestParam(name = "action_type", required = false) String action_type,
                                      @RequestParam(name = "resource_id", required = false) Long resource_id,
                                      @RequestParam(name = "date_from", required = false) String date_from,
                                      @RequestParam(name = "date_to", required = false) String date_to,
                                      @RequestParam(name = "limit", defaultValue = "100") int limit,
                                      @RequestParam(name = "offset", defaultValue = "0") int offset) {
        SecurityUtil.requireAdminOrOwner();
        Instant from;
        Instant to;
        try {
            from = date_from == null ? null : Instant.parse(date_from);
            to = date_to == null ? null : Instant.parse(date_to);
        } catch (java.time.format.DateTimeParseException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_date_range");
        }
        List<Map<String, Object>> data = new ArrayList<>();
        for (AuditLog a : govService.searchAudit(action_type, resource_id, from, to,
                Payloads.clamp(limit, 1, 1000), Math.max(0, offset))) {
            data.add(Payloads.map("timestamp", Payloads.iso(a.getTimestamp()), "actor_id", a.getActorId(),
                    "action", a.getAction(), "resource_type", a.getResourceType(), "resource_id", a.getResourceId(),
                    "old_value", a.getOldValue(), "new_value", a.getNewValue(), "reason", a.getReason()));
        }
        return ResponseEntity.ok(data);
    }
}

/* ---------- ERRORS ---------- */

/**
 * Maps errors to the spec's {error, message} shape. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP:
 * adds missing headers and unreadable bodies (were 500s); internal details are not echoed back.
 */
@RestControllerAdvice
class GlobalExceptionHandler {
    /** {error, message} with the exception's status. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. */
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, Object>> handle(ResponseStatusException ex) {
        return new ResponseEntity<>(Payloads.map("error", ex.getReason(), "message", ex.getReason()), ex.getStatusCode());
    }

    /** 400 missing_header. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. */
    @ExceptionHandler(MissingRequestHeaderException.class)
    public ResponseEntity<Map<String, Object>> missingHeader(MissingRequestHeaderException ex) {
        return new ResponseEntity<>(Payloads.map("error", "missing_header", "message", ex.getHeaderName()), HttpStatus.BAD_REQUEST);
    }

    /** 400 invalid_json. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> unreadable(HttpMessageNotReadableException ex) {
        return new ResponseEntity<>(Payloads.map("error", "invalid_json", "message", "Request body is not valid JSON"), HttpStatus.BAD_REQUEST);
    }
}

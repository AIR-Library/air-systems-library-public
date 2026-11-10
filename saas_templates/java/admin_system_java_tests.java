package com.example.admin;

import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.*;
import org.springframework.test.web.servlet.*;
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: RequestPostProcessor lives in the .request
// sub-package; without this import the file could not compile against any implementation.
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.*;

/*
 * Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the test deployment's configuration. The
 * implementation no longer trusts a client-sent X-User-Id header, a hard-coded CSRF token, a hard-coded
 * "can publish" flag or a live Stripe key unless the deployment says so; these properties say so for this test
 * (identity header from the test's stand-in auth proxy, the CSRF token the requests send, the in-memory Stripe
 * gateway, publishing enabled).
 */
@SpringBootTest(properties = {
        "admin.auth.trusted-user-header=X-User-Id",
        "admin.csrf.token=secure-token",
        "admin.stripe.gateway=in-memory",
        "admin.safety.can-publish=true"
})
@AutoConfigureMockMvc
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AdminSystemTests {

    @Autowired private MockMvc mockMvc;
    @Autowired private UserRepository userRepo;
    @Autowired private CustomerRepository custRepo;
    @Autowired private DeploymentRepository depRepo;
    @Autowired private InvoiceRepository invoiceRepo;
    @Autowired private GovernanceActionRepository gaRepo;
    @Autowired private AdminStripeGateway stripeGateway;
    @Autowired private AdminMailer mailer;
    @Autowired private ObjectMapper mapper;

    private User owner;
    private User admin;
    private User regular;

    private static final String CSRF_HEADER = "X-CSRF-Token";
    private static final String CSRF_TOKEN = "secure-token";

    @BeforeAll
    void setupUsers() {
        owner = new User(); owner.setEmail("owner@example.com"); owner.setName("Owner"); owner.setTier("OWNER");
        admin = new User(); admin.setEmail("admin@example.com"); admin.setName("Admin"); admin.setTier("ADMIN");
        regular = new User(); regular.setEmail("user@example.com"); regular.setName("User"); regular.setTier("USER");
        userRepo.saveAll(List.of(owner, admin, regular));
    }

    /**
     * Audit rows for one action and resource, read through the audit-log endpoint as the owner.
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP so the rows that say "audit logged" can check it.
     * Touches: reads the test database.
     */
    private List<Map<String, Object>> auditRows(String action, Long resourceId) throws Exception {
        String body = mockMvc.perform(get("/admin/governance/audit-log")
                        .param("action_type", action)
                        .param("resource_id", String.valueOf(resourceId))
                        .with(auth(owner)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return mapper.readValue(body, mapper.getTypeFactory().constructCollectionType(List.class, Map.class));
    }

    private RequestPostProcessor auth(User u) {
        return request -> {
            request.addHeader("X-User-Id", u.getId().toString());
            request.addHeader(CSRF_HEADER, CSRF_TOKEN);
            return request;
        };
    }

    // ADMIN-01
    @Test
    void testCreateUserHappyPath() throws Exception {
        Map<String, Object> payload = Map.of(
                "email", "newuser@example.com",
                "name", "New User",
                "tier", "USER",
                "notify", true
        );
        mockMvc.perform(post("/admin/users/action")
                .header("X-Action", "create")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(payload))
                .with(auth(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.email").value("newuser@example.com"));
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the row says "invite sent"; the in-memory mailer shows it.
        Assertions.assertTrue(((InMemoryAdminMailer) mailer).sent().stream().anyMatch(m -> m.startsWith("newuser@example.com |")));
    }

    // ADMIN-02
    @Test
    void testCreateUserDuplicateEmail() throws Exception {
        Map<String, Object> payload = Map.of(
                "email", owner.getEmail(),
                "name", "Dup",
                "tier", "USER",
                "notify", false
        );
        mockMvc.perform(post("/admin/users/action")
                .header("X-Action", "create")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(payload))
                .with(auth(owner)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("email_exists"));
    }

    // ADMIN-03
    @Test
    void testCreateUserNonOwner() throws Exception {
        Map<String, Object> payload = Map.of(
                "email", "another@example.com",
                "name", "Another",
                "tier", "USER",
                "notify", false
        );
        mockMvc.perform(post("/admin/users/action")
                .header("X-Action", "create")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(payload))
                .with(auth(admin)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("owner_only"));
    }

    // ADMIN-04
    @Test
    void testResetPasswordHappyPath() throws Exception {
        Map<String, Object> payload = Map.of("user_id", regular.getId());
        mockMvc.perform(post("/admin/users/action")
                .header("X-Action", "reset_password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(payload))
                .with(auth(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("reset_email_sent"));
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the row says "email sent".
        Assertions.assertTrue(((InMemoryAdminMailer) mailer).sent().stream().anyMatch(m -> m.startsWith(regular.getEmail() + " |")));
    }

    // ADMIN-05
    @Test
    void testResetPasswordOwnAccount() throws Exception {
        Map<String, Object> payload = Map.of("user_id", owner.getId());
        mockMvc.perform(post("/admin/users/action")
                .header("X-Action", "reset_password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(payload))
                .with(auth(owner)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("cannot_reset_own_password"));
    }

    // ADMIN-06
    @Test
    void testChangeRoleHappyPath() throws Exception {
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: a user of its own, and the row's "role changed + audit
        // logged" checked (the stored tier and a role_changed audit row).
        User target = new User(); target.setEmail("role-target@example.com"); target.setName("Role"); target.setTier("USER");
        userRepo.save(target);
        Map<String, Object> payload = Map.of("user_id", target.getId(), "new_tier", "ADMIN");
        mockMvc.perform(post("/admin/users/action")
                .header("X-Action", "change_role")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(payload))
                .with(auth(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        Assertions.assertEquals("ADMIN", userRepo.findById(target.getId()).orElseThrow().getTier());
        Assertions.assertEquals(1, auditRows("role_changed", target.getId()).size());
    }

    // ADMIN-07
    @Test
    void testChangeRoleLastOwner() throws Exception {
        // Ensure only one owner exists
        userRepo.findAll().stream()
                .filter(u -> !"OWNER".equals(u.getTier()))
                .forEach(u -> u.setTier("USER"));
        userRepo.saveAll(userRepo.findAll());

        Map<String, Object> payload = Map.of("user_id", owner.getId(), "new_tier", "ADMIN");
        try {
            mockMvc.perform(post("/admin/users/action")
                    .header("X-Action", "change_role")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(mapper.writeValueAsString(payload))
                    .with(auth(owner)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("cannot_demote_last_owner"));
        } finally {
            // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: put the admin back, so tests that act as the admin do
            // not depend on running before this one (the setup above demotes every non-owner).
            User a = userRepo.findById(admin.getId()).orElseThrow();
            a.setTier("ADMIN");
            userRepo.save(a);
        }
    }

    // ADMIN-08
    @Test
    void testSuspendUserHappyPath() throws Exception {
        Map<String, Object> payload = Map.of("user_id", regular.getId(), "reason", "policy");
        mockMvc.perform(post("/admin/users/action")
                .header("X-Action", "suspend")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(payload))
                .with(auth(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.suspended").value(true));
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the row says "status changed".
        Assertions.assertEquals("suspended", userRepo.findById(regular.getId()).orElseThrow().getStatus());
        User r = userRepo.findById(regular.getId()).orElseThrow();
        r.setStatus("active");
        userRepo.save(r);
    }

    // ADMIN-09
    @Test
    void testSuspendOwnAccount() throws Exception {
        Map<String, Object> payload = Map.of("user_id", owner.getId(), "reason", "self");
        mockMvc.perform(post("/admin/users/action")
                .header("X-Action", "suspend")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(payload))
                .with(auth(owner)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("cannot_suspend_yourself"));
    }

    // ADMIN-10
    @Test
    void testCustomersListPagination() throws Exception {
        // create dummy customers
        for (int i = 0; i < 30; i++) {
            Customer c = new Customer();
            c.setEmail("c"+i+"@example.com");
            c.setName("Customer "+i);
            c.setTier("USER");
            c.setSignupDate(java.time.LocalDate.now());
            custRepo.save(c);
        }
        mockMvc.perform(get("/admin/customers")
                .param("page", "0")
                .param("size", "10")
                .with(auth(admin)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(10))
                // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: "all fields present" and a second page checked.
                .andExpect(jsonPath("$[0].customer_id").isNumber())
                .andExpect(jsonPath("$[0].email").isString())
                .andExpect(jsonPath("$[0].name").isString())
                .andExpect(jsonPath("$[0].tier").isString())
                .andExpect(jsonPath("$[0].signup_date").isString())
                .andExpect(jsonPath("$[0].invoice_count").isNumber())
                .andExpect(jsonPath("$[0].status").isString());
        String first = mockMvc.perform(get("/admin/customers").param("page", "0").param("size", "10").with(auth(owner)))
                .andReturn().getResponse().getContentAsString();
        String second = mockMvc.perform(get("/admin/customers").param("page", "1").param("size", "10").with(auth(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(10))
                .andReturn().getResponse().getContentAsString();
        Assertions.assertNotEquals(first, second, "page 1 must differ from page 0");
    }

    // ADMIN-11
    @Test
    void testCustomerDetailFields() throws Exception {
        Customer c = new Customer();
        c.setEmail("detail@example.com");
        c.setName("Detail");
        c.setTier("USER");
        c.setSignupDate(java.time.LocalDate.now());
        custRepo.save(c);
        mockMvc.perform(get("/admin/customers/"+c.getId())
                .with(auth(admin)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("detail@example.com"))
                .andExpect(jsonPath("$.name").value("Detail"))
                // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: every field the spec lists is in the answer.
                .andExpect(jsonPath("$.customer_id").value(c.getId()))
                .andExpect(jsonPath("$.tier").value("USER"))
                .andExpect(jsonPath("$.subscription_status").exists())
                .andExpect(jsonPath("$.payment_method").hasJsonPath())
                .andExpect(jsonPath("$.address").hasJsonPath())
                .andExpect(jsonPath("$.notes").hasJsonPath());
    }

    /**
     * ADMIN-12: change_plan retrieves the subscription and updates its ONE existing item to the new price (no second
     * item), returns old and new tier, and writes a plan_changed audit row; an unknown tier is 400 invalid_tier and a
     * two-item subscription is 409 subscription_item_ambiguous, neither reaching an update.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: spec amendment (billing flow 2 rule). The test used tier
     * "PRO", which no price exists for; it now moves solo -> team, the plan tiers the in-memory gateway prices.
     * Touches: the test database and the in-memory Stripe gateway.
     */
    // ADMIN-12
    @Test
    void testChangePlanStripeCalled() throws Exception {
        InMemoryAdminStripeGateway fake = (InMemoryAdminStripeGateway) stripeGateway;
        Customer c = new Customer();
        c.setEmail("stripe@example.com");
        c.setName("Stripe");
        c.setTier("solo");
        c.setSignupDate(java.time.LocalDate.now());
        c.setStripeSubscriptionId("sub_123");
        custRepo.save(c);
        mockMvc.perform(post("/admin/customers/"+c.getId()+"/action")
                .header("X-Action", "change_plan")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("new_tier", "team")))
                .with(auth(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.new_tier").value("team"))
                .andExpect(jsonPath("$.old_tier").value("solo"));
        Assertions.assertTrue(fake.calls().contains("retrieve sub_123"));
        Assertions.assertTrue(fake.calls().contains("update sub_123 si_sub_123_1 price_test_team"));
        Assertions.assertEquals(1, fake.itemCount("sub_123"), "no second item");
        Assertions.assertEquals(1, auditRows("plan_changed", c.getId()).size());

        // Unknown tier: 400 invalid_tier before any Stripe call.
        int before = fake.calls().size();
        mockMvc.perform(post("/admin/customers/"+c.getId()+"/action")
                .header("X-Action", "change_plan")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("new_tier", "PRO")))
                .with(auth(owner)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_tier"));
        Assertions.assertEquals(before, fake.calls().size());

        // Two items: 409 subscription_item_ambiguous after the retrieve, before any update.
        Customer two = new Customer();
        two.setEmail("two-items@example.com");
        two.setName("Two");
        two.setTier("solo");
        two.setSignupDate(java.time.LocalDate.now());
        two.setStripeSubscriptionId("sub_two_items");
        custRepo.save(two);
        fake.setItems("sub_two_items", List.of("price_test_solo", "price_addon"));
        mockMvc.perform(post("/admin/customers/"+two.getId()+"/action")
                .header("X-Action", "change_plan")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("new_tier", "team")))
                .with(auth(owner)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("subscription_item_ambiguous"));
        Assertions.assertTrue(fake.calls().stream().noneMatch(x -> x.startsWith("update sub_two_items")));
        Assertions.assertEquals("solo", custRepo.findById(two.getId()).orElseThrow().getTier());
    }

    // ADMIN-13
    @Test
    void testQueueRefundRecordCreated() throws Exception {
        // Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the spec checks that the invoice exists
        // and succeeded; the test refunded invoice 1001 of customer 1, neither of which it created, so a correct
        // implementation had to refuse it. It now creates the customer and a paid invoice first.
        Customer c = new Customer();
        c.setEmail("refund@example.com");
        c.setName("Refund");
        c.setTier("BASIC");
        c.setSignupDate(java.time.LocalDate.now());
        custRepo.save(c);
        Invoice inv = new Invoice();
        inv.setCustomerId(c.getId());
        inv.setAmount(new java.math.BigDecimal("100.00"));
        inv.setStatus("succeeded");
        invoiceRepo.save(inv);
        Map<String, Object> payload = Map.of(
                "invoice_id", inv.getId(),
                "amount", 49.99,
                "reason", "customer request"
        );
        mockMvc.perform(post("/admin/customers/" + c.getId() + "/action")
                .header("X-Action", "queue_refund")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(payload))
                .with(auth(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("queued"))
                .andExpect(jsonPath("$.refund_id").isNumber());
    }

    // ADMIN-14
    @Test
    void testCreateDeployment() throws Exception {
        Customer c = new Customer();
        c.setEmail("dep@example.com");
        c.setName("DepCust");
        c.setTier("BASIC");
        c.setSignupDate(java.time.LocalDate.now());
        custRepo.save(c);
        Map<String, Object> payload = Map.of(
                "customer_id", c.getId(),
                "domain", "example.com",
                "tier", "BASIC",
                "theme_id", 1
        );
        mockMvc.perform(post("/admin/deployments/action")
                .header("X-Action", "create")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(payload))
                .with(auth(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.domain").value("example.com"))
                .andExpect(jsonPath("$.deployment_id").isNumber());
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the row says "config initialized".
        Deployment created = depRepo.findPage(0, 10_000).stream().filter(d -> "example.com".equals(d.getDomain())).findFirst().orElseThrow();
        Assertions.assertNotNull(created.getConfig());
        Assertions.assertTrue(created.getConfig().contains("theme_id"));
        Assertions.assertEquals("draft", created.getStatus());
    }

    /** Publishing a ready draft makes it live. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the draft has a theme and a verified domain (spec checks). */
    // ADMIN-15
    @Test
    void testPublishDeploymentDoubleGate() throws Exception {
        // create deployment first
        Deployment d = new Deployment();
        d.setCustomerId(1L);
        d.setDomain("publish.com");
        d.setTier("BASIC");
        d.setStatus("draft");
        // Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the spec's publish check requires a
        // verified domain and a theme; the draft now has both.
        d.setThemeId(1L);
        d.setDomainVerified(true);
        depRepo.save(d);
        Map<String, Object> payload = Map.of("deployment_id", d.getId());
        mockMvc.perform(post("/admin/deployments/action")
                .header("X-Action", "publish")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(payload))
                .with(auth(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("live"));
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the gate is checked, so a draft without a verified domain
        // is refused and stays a draft.
        Deployment unverified = new Deployment();
        unverified.setCustomerId(1L);
        unverified.setDomain("unverified-publish.com");
        unverified.setTier("BASIC");
        unverified.setStatus("draft");
        unverified.setThemeId(1L);
        unverified.setDomainVerified(false);
        depRepo.save(unverified);
        mockMvc.perform(post("/admin/deployments/action")
                .header("X-Action", "publish")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("deployment_id", unverified.getId())))
                .with(auth(owner)))
                .andExpect(status().is4xxClientError());
        Assertions.assertEquals("draft", depRepo.findById(unverified.getId()).orElseThrow().getStatus());
    }

    /** Approving executes the action. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: saves the action, uses its id, asserts the execution. */
    // ADMIN-16
    @Test
    void testGovernanceApprove() throws Exception {
        // create a pending governance action
        // Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the action was never saved and the request
        // assumed id 1 existed; it is now saved and its real id used. It targets a user of its own, because
        // approving executes the action and must not remove a user other tests rely on.
        User target = new User(); target.setEmail("approve-target@example.com"); target.setName("Target"); target.setTier("USER");
        userRepo.save(target);
        GovernanceAction ga = new GovernanceAction();
        ga.setActionType("delete_user");
        ga.setActorId(admin.getId());
        ga.setTargetResourceId(target.getId());
        ga.setReason("cleanup");
        gaRepo.save(ga);
        mockMvc.perform(post("/admin/governance/actions/" + ga.getId() + "/decide")
                .header("X-Decide", "approve")
                .with(auth(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("approved"));
        // The original action was executed
        Assertions.assertEquals("deleted", userRepo.findById(target.getId()).orElseThrow().getStatus());
    }

    /** Rejecting records the reason and executes nothing. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: saves the action, uses its id. */
    // ADMIN-17
    @Test
    void testGovernanceReject() throws Exception {
        // create a pending governance action
        // Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: saved, and its real id used (it assumed id 2).
        User target = new User(); target.setEmail("reject-target@example.com"); target.setName("Target"); target.setTier("USER");
        userRepo.save(target);
        GovernanceAction ga = new GovernanceAction();
        ga.setActionType("delete_user");
        ga.setActorId(admin.getId());
        ga.setTargetResourceId(target.getId());
        ga.setReason("cleanup");
        gaRepo.save(ga);
        Map<String, Object> payload = Map.of("reason", "not needed");
        mockMvc.perform(post("/admin/governance/actions/" + ga.getId() + "/decide")
                .header("X-Decide", "reject")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(payload))
                .with(auth(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("rejected"));
        // Nothing was executed
        Assertions.assertEquals("active", userRepo.findById(target.getId()).orElseThrow().getStatus());
    }

    // ADMIN-18
    @Test
    void testAuditLogSearch() throws Exception {
        mockMvc.perform(get("/admin/governance/audit-log")
                .param("action_type", "user_created")
                .param("limit", "10")
                .with(auth(admin)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").isNumber());
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: "correct filters applied, pagination works" checked on rows
        // this test creates (three users created; the action filter and limit/offset pages).
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/admin/users/action")
                    .header("X-Action", "create")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(mapper.writeValueAsString(Map.of("email", "audit" + i + "@example.com", "name", "Audit " + i,
                            "tier", "USER", "notify", false)))
                    .with(auth(owner)))
                    .andExpect(status().isOk());
        }
        String all = mockMvc.perform(get("/admin/governance/audit-log").param("action_type", "user_created")
                        .param("limit", "1000").with(auth(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].action").value(org.hamcrest.Matchers.everyItem(org.hamcrest.Matchers.is("user_created"))))
                .andReturn().getResponse().getContentAsString();
        List<?> rows = mapper.readValue(all, List.class);
        Assertions.assertTrue(rows.size() >= 3);
        mockMvc.perform(get("/admin/governance/audit-log").param("action_type", "user_created")
                        .param("limit", "2").param("offset", "0").with(auth(owner)))
                .andExpect(jsonPath("$.length()").value(2));
        String page2 = mockMvc.perform(get("/admin/governance/audit-log").param("action_type", "user_created")
                        .param("limit", "2").param("offset", "2").with(auth(owner)))
                .andReturn().getResponse().getContentAsString();
        Assertions.assertEquals(Math.min(2, rows.size() - 2), mapper.readValue(page2, List.class).size());
    }
}
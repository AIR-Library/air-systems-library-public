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

    private RequestPostProcessor auth(User u) {
        return request -> {
            request.addHeader("X-User-Id", u.getId().toString());
            request.addHeader(CSRF_HEADER, CSRF_TOKEN);
            return request;
        };
    }

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
    }

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
    }

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

    @Test
    void testChangeRoleHappyPath() throws Exception {
        Map<String, Object> payload = Map.of("user_id", regular.getId(), "new_tier", "ADMIN");
        mockMvc.perform(post("/admin/users/action")
                .header("X-Action", "change_role")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(payload))
                .with(auth(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testChangeRoleLastOwner() throws Exception {
        // Ensure only one owner exists
        userRepo.findAll().stream()
                .filter(u -> !"OWNER".equals(u.getTier()))
                .forEach(u -> u.setTier("USER"));
        userRepo.saveAll(userRepo.findAll());

        Map<String, Object> payload = Map.of("user_id", owner.getId(), "new_tier", "ADMIN");
        mockMvc.perform(post("/admin/users/action")
                .header("X-Action", "change_role")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(payload))
                .with(auth(owner)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("cannot_demote_last_owner"));
    }

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
    }

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
                .andExpect(jsonPath("$.length()").value(10));
    }

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
                .andExpect(jsonPath("$.name").value("Detail"));
    }

    /** change_plan updates Stripe and returns old and new tier. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: asserts the (in-memory) Stripe call and old_tier. */
    @Test
    void testChangePlanStripeCalled() throws Exception {
        Customer c = new Customer();
        c.setEmail("stripe@example.com");
        c.setName("Stripe");
        c.setTier("BASIC");
        c.setSignupDate(java.time.LocalDate.now());
        c.setStripeSubscriptionId("sub_123");
        custRepo.save(c);
        Map<String, Object> payload = Map.of("new_tier", "PRO");
        mockMvc.perform(post("/admin/customers/"+c.getId()+"/action")
                .header("X-Action", "change_plan")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(payload))
                .with(auth(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.new_tier").value("PRO"))
                .andExpect(jsonPath("$.old_tier").value("BASIC"));
        // The Stripe subscription update was called (in-memory gateway, no network)
        Assertions.assertTrue(((InMemoryAdminStripeGateway) stripeGateway).calls().contains("sub_123 PRO"));
    }

    /** A refund against a paid invoice is queued. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: creates the customer and invoice it refunds. */
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
                .andExpect(jsonPath("$.status").value("queued"));
    }

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
                .andExpect(jsonPath("$.domain").value("example.com"));
    }

    /** Publishing a ready draft makes it live. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the draft has a theme and a verified domain (spec checks). */
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
    }

    /** Approving executes the action. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: saves the action, uses its id, asserts the execution. */
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

    @Test
    void testAuditLogSearch() throws Exception {
        mockMvc.perform(get("/admin/governance/audit-log")
                .param("action_type", "user_created")
                .param("limit", "10")
                .with(auth(admin)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").isNumber());
    }
}
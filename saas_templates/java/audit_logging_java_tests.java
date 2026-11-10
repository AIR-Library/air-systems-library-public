package com.saas.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.NullNode;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.function.Executable;
import org.mockito.junit.jupiter.MockitoExtension;

import java.sql.*;
import java.time.Instant;
import java.time.LocalDate;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for AuditLoggingService, one or more tests per spec id (AUDIT-01..10).
 *
 * Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP for the amended spec: entries are logged through LogRequest
 * (actor, data subject, request details), reads take a verified Caller and are admin-only, personal data lives in
 * audit_personal under a random subject_ref, and erase_subject / apply_retention are tested. Every earlier case (happy
 * path, replay and divergence, filters, pagination, the 1M-row 100 ms budget, immutability, wildcard, search, date
 * range, validation, metadata, creation replay) is kept with the same expectations where the spec did not change
 * them. The metadata test used to store ip/user_agent/request_id in metadata; the amended spec refuses those keys
 * (they would outlive erasure), so it now stores feature_flag and checks the refusal. Touches: in-memory H2 only.
 */
@ExtendWith(MockitoExtension.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuditLoggingServiceTest {

    private static Connection connection;
    private static AuditLoggingService service;
    private static final ObjectMapper om = new ObjectMapper();
    private static final AuditLoggingService.Caller ADMIN = AuditLoggingService.Caller.admin("admin-1");
    private static final AuditLoggingService.Caller MEMBER = AuditLoggingService.Caller.user("member-1");

    @BeforeAll
    static void setup() throws Exception {
        // Use H2 in-memory database for tests
        connection = DriverManager.getConnection("jdbc:h2:mem:audit_test;DB_CLOSE_DELAY=-1", "sa", "");
        service = new AuditLoggingService(connection);
    }

    @AfterAll
    static void teardown() throws Exception {
        if (service != null) service.close();
    }

    @BeforeEach
    void cleanTable() throws Exception {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("DELETE FROM audit_personal");
            stmt.execute("DELETE FROM audit_subjects");
            stmt.execute("DELETE FROM audit_log");
        }
    }

    /** A user acting on a resource of their own (resource_type 'user': the subject is the resource). */
    private static Map<String, Object> userEvent(String actor, String action, String userId, Object oldV, Object newV)
            throws SQLException {
        return service.log(AuditLoggingService.LogRequest.byUser(actor, action, "user", userId)
                .values(AuditLoggingService.toJsonNode(oldV), AuditLoggingService.toJsonNode(newV)));
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> logsOf(Map<String, Object> result) {
        return (List<Map<String, Object>>) result.get("logs");
    }

    private static AuditLoggingService.AuditException refused(Executable call) {
        return assertThrows(AuditLoggingService.AuditException.class, call);
    }

    // AUDIT-01
    @Test
    @Order(1)
    void testHappyPath_logAndQuery() throws Exception {
        Map<String, Object> oldVal = new LinkedHashMap<>();
        oldVal.put("tier", "team");
        oldVal.put("billing_date", "2026-10-15");
        Map<String, Object> newVal = new LinkedHashMap<>();
        newVal.put("tier", "enterprise");
        newVal.put("billing_date", "2026-10-15");

        Map<String, Object> response = service.log(AuditLoggingService.LogRequest
                .byUser("123", "subscription_changed", "subscription", "456")
                .subject("789")
                .values(AuditLoggingService.toJsonNode(oldVal), AuditLoggingService.toJsonNode(newVal))
                .why("wc_789"));
        assertTrue((Boolean) response.get("success"));
        assertNotNull(response.get("log_id"));

        Map<String, Object> queryResult = service.queryLogs(ADMIN, "123", "subscription_changed", "subscription", 100, 0, null, null);
        assertEquals(1, (Long) queryResult.get("total"));
        List<Map<String, Object>> logs = logsOf(queryResult);
        assertEquals(1, logs.size());
        Map<String, Object> log = logs.get(0);
        assertEquals("123", log.get("actor_id"));
        assertEquals("subscription_changed", log.get("action"));
        assertEquals("subscription", log.get("resource_type"));
        assertEquals("456", log.get("resource_id"));
        assertEquals("wc_789", log.get("why_chain_id"));
        assertEquals("actor,subject", log.get("personal_roles"));
        assertEquals(false, log.get("personal_erased"));
        assertEquals("team", ((JsonNode) log.get("old_value")).get("tier").asText());
        assertEquals("enterprise", ((JsonNode) log.get("new_value")).get("tier").asText());

        // The event row itself holds none of it: the snapshots and ids live in audit_personal.
        try (Statement st = connection.createStatement();
             ResultSet rs = st.executeQuery("SELECT resource_id, old_value, new_value, why_chain_id FROM audit_log")) {
            assertTrue(rs.next());
            for (int c = 1; c <= 4; c++) assertNull(rs.getString(c));
        }
    }

    // AUDIT-02
    @Test
    @Order(2)
    void testReplay_noDivergence() throws Exception {
        String logId = (String) userEvent("1", "user_suspended", "u_001",
                Map.of("status", "active"), Map.of("status", "suspended")).get("log_id");

        Map<String, Object> replay = service.replay(ADMIN, logId);
        assertEquals(logId, replay.get("log_id"));
        assertNotNull(replay.get("timestamp"));
        assertEquals(false, replay.get("has_diverged"));
        assertEquals("active", ((JsonNode) replay.get("resource_state_at_time")).get("status").asText());
    }

    // AUDIT-02
    @Test
    @Order(3)
    void testReplay_divergenceDetected() throws Exception {
        String logId1 = (String) userEvent("1", "user_created", "u_002",
                Map.of("status", "none"), Map.of("status", "active")).get("log_id");
        userEvent("1", "user_suspended", "u_002", Map.of("status", "active"), Map.of("status", "suspended"));
        assertEquals(true, service.replay(ADMIN, logId1).get("has_diverged"));

        // The same for a resource that belongs to no person (snapshots kept in audit_log).
        String dep = (String) service.log(AuditLoggingService.LogRequest.byService("deployer", "deployment_updated", "deployment", "d_1")
                .subject("none").values(AuditLoggingService.toJsonNode(Map.of("v", 1)), AuditLoggingService.toJsonNode(Map.of("v", 2)))).get("log_id");
        assertEquals(false, service.replay(ADMIN, dep).get("has_diverged"));
        service.log(AuditLoggingService.LogRequest.byService("deployer", "deployment_updated", "deployment", "d_1")
                .subject("none").values(AuditLoggingService.toJsonNode(Map.of("v", 2)), AuditLoggingService.toJsonNode(Map.of("v", 3))));
        assertEquals(true, service.replay(ADMIN, dep).get("has_diverged"));
    }

    @Test
    @Order(3)
    void testReplay_divergenceAfterAnUnchangedEntry() throws Exception {
        // Values A, A, B: the first A has diverged, though the entry right after it is the same (CodeRabbit, PR 18).
        Map<String, Object> a = Map.of("status", "active");
        Map<String, Object> b = Map.of("status", "suspended");
        String first = (String) userEvent("1", "user_created", "u_aab", Map.of("status", "none"), a).get("log_id");
        userEvent("1", "user_touched", "u_aab", a, a);
        userEvent("1", "user_suspended", "u_aab", a, b);
        assertEquals(true, service.replay(ADMIN, first).get("has_diverged"));
    }

    @Test
    @Order(4)
    void testReplay_logNotFound() {
        assertThrows(NoSuchElementException.class, () -> service.replay(ADMIN, "99999"));
    }

    // AUDIT-03
    @Test
    @Order(5)
    void testFiltering_combinedFilters() throws Exception {
        userEvent("100", "user_created", "u_1", null, Map.of("name", "Alice"));
        userEvent("100", "user_suspended", "u_2", Map.of("status", "active"), Map.of("status", "suspended"));
        service.log(AuditLoggingService.LogRequest.byUser("200", "billing_changed", "subscription", "s_1").subject("u_9")
                .values(AuditLoggingService.toJsonNode(Map.of("tier", "basic")), AuditLoggingService.toJsonNode(Map.of("tier", "pro"))));
        userEvent("100", "user_created", "u_3", null, Map.of("name", "Bob"));
        service.log(AuditLoggingService.LogRequest.byUser("100", "billing_changed", "subscription", "s_2").subject("u_1"));

        Map<String, Object> result = service.queryLogs(ADMIN, "100", "user_*", "user", 100, 0, null, null);
        assertEquals(3, (Long) result.get("total"));
        for (Map<String, Object> log : logsOf(result)) {
            assertEquals("100", log.get("actor_id"));
            assertTrue(((String) log.get("action")).startsWith("user_"));
            assertEquals("user", log.get("resource_type"));
        }
        assertEquals(1, (Long) service.queryLogs(ADMIN, "200", null, null, 100, 0, null, null).get("total"));
        assertEquals(2, (Long) service.queryLogs(ADMIN, null, null, "subscription", 100, 0, null, null).get("total"));
        assertEquals(1, (Long) service.queryLogs(ADMIN, "100", "billing_changed", "subscription", 100, 0, null, null).get("total"));
    }

    // AUDIT-04
    @Test
    @Order(6)
    void testPagination() throws Exception {
        for (int i = 1; i <= 10; i++) {
            userEvent("actor_" + i, "user_created", "u_" + i, null, Map.of("seq", i));
        }
        Map<String, Object> page1 = service.queryLogs(ADMIN, null, null, null, 3, 0, null, null);
        assertEquals(10, (Long) page1.get("total"));
        assertEquals(true, page1.get("has_more"));
        assertEquals(3, logsOf(page1).size());
        assertEquals("u_1", logsOf(page1).get(0).get("resource_id"));

        Map<String, Object> page2 = service.queryLogs(ADMIN, null, null, null, 3, 3, null, null);
        assertEquals(true, page2.get("has_more"));
        assertEquals(3, logsOf(page2).size());
        assertEquals("u_4", logsOf(page2).get(0).get("resource_id"));

        Map<String, Object> page4 = service.queryLogs(ADMIN, null, null, null, 3, 9, null, null);
        assertEquals(false, page4.get("has_more"));
        assertEquals(1, logsOf(page4).size());

        Map<String, Object> all = service.queryLogs(ADMIN, null, null, null, 10, 0, null, null);
        assertEquals(false, all.get("has_more"));
        assertEquals(10, logsOf(all).size());
    }

    /**
     * AUDIT-05: 1,000,000 entries (each with an 'actor' personal row under one of 1,000 subjects); a query filtered by
     * actor_id + action + resource_type returns in under 100 ms. Rows are bulk-inserted by SQL in the amended schema.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the schema split (the budget is unchanged).
     */
    // AUDIT-05
    @Test
    @Order(7)
    void testPerformance_1MLogs() throws Exception {
        long start = System.currentTimeMillis();
        connection.setAutoCommit(false);
        try (PreparedStatement subj = connection.prepareStatement(
                "INSERT INTO audit_subjects (subject_ref, user_id, created_at) VALUES (?, ?, ?)")) {
            for (int a = 0; a < 1000; a++) {
                subj.setString(1, String.format("%032x", a));
                subj.setString(2, "actor_" + a);
                subj.setTimestamp(3, Timestamp.from(Instant.now()));
                subj.addBatch();
            }
            subj.executeBatch();
        }
        try (PreparedStatement log = connection.prepareStatement("""
                INSERT INTO audit_log (id, timestamp, actor_type, actor_service, action, resource_type, resource_id,
                                       old_value, new_value, why_chain_id, personal_roles, metadata)
                VALUES (?, ?, 'user', NULL, 'deployment_created', 'deployment', ?, '{}', ?, NULL, 'actor', NULL)""");
             PreparedStatement pers = connection.prepareStatement(
                "INSERT INTO audit_personal (log_id, subject_ref, role, data) VALUES (?, ?, 'actor', ?)")) {
            Instant base = Instant.now();
            for (long i = 1; i <= 1_000_000; i++) {
                int a = (int) (i % 1000);
                log.setLong(1, i);
                log.setTimestamp(2, Timestamp.from(base.minusSeconds(1_000_000 - i)));
                log.setString(3, "d_" + i);
                log.setString(4, "{\"seq\":" + i + "}");
                log.addBatch();
                pers.setLong(1, i);
                pers.setString(2, String.format("%032x", a));
                pers.setString(3, "{\"actor_id\":\"actor_" + a + "\",\"ip\":null,\"user_agent\":null,\"request_id\":null}");
                pers.addBatch();
                if (i % 10000 == 0) {
                    log.executeBatch();
                    pers.executeBatch();
                }
            }
            log.executeBatch();
            pers.executeBatch();
            connection.commit();
        } finally {
            connection.setAutoCommit(true);
        }
        System.out.println("[PERF] Inserted 1M logs in " + (System.currentTimeMillis() - start) + "ms");

        long queryStart = System.currentTimeMillis();
        Map<String, Object> result = service.queryLogs(ADMIN, "actor_500", "deployment_created", "deployment", 100, 0, null, null);
        long queryMs = System.currentTimeMillis() - queryStart;
        System.out.println("[PERF] Filtered query took " + queryMs + "ms, total=" + result.get("total"));

        assertTrue(queryMs < 100, "Query should complete in <100ms but took " + queryMs + "ms");
        assertEquals(1000L, result.get("total"));
        assertEquals("actor_500", logsOf(result).get(0).get("actor_id"));
    }

    // AUDIT-06
    @Test
    @Order(8)
    void testImmutability_updateThrows() throws Exception {
        String logId = (String) userEvent("1", "user_created", "u_imm", null, Map.of("x", 1)).get("log_id");
        assertThrows(UnsupportedOperationException.class, () -> service.updateLog(logId));
    }

    // AUDIT-06
    @Test
    @Order(9)
    void testImmutability_deleteThrows() throws Exception {
        String logId = (String) userEvent("1", "user_created", "u_del", null, Map.of("x", 1)).get("log_id");
        assertThrows(UnsupportedOperationException.class, () -> service.deleteLog(logId));
    }

    // AUDIT-07
    @Test
    @Order(10)
    void testWildcard_actionMatching() throws Exception {
        userEvent("1", "user_created", "u_1", null, Map.of("n", 1));
        userEvent("1", "user_suspended", "u_2", Map.of("s", "active"), Map.of("s", "suspended"));
        userEvent("1", "user_email_changed", "u_3", Map.of("e", "a@b.c"), Map.of("e", "x@y.z"));
        service.log(AuditLoggingService.LogRequest.byUser("1", "billing_changed", "subscription", "s_1").subject("u_1"));
        // "user_" is a literal prefix: "_" is not a LIKE wildcard here.
        userEvent("1", "userXcreated", "u_4", null, Map.of("n", 4));

        Map<String, Object> result = service.queryLogs(ADMIN, "1", "user_*", null, 100, 0, null, null);
        assertEquals(3, (Long) result.get("total"));
        Set<String> actions = new HashSet<>();
        for (Map<String, Object> log : logsOf(result)) actions.add((String) log.get("action"));
        assertEquals(Set.of("user_created", "user_suspended", "user_email_changed"), actions);
    }

    /**
     * AUDIT-08: erase_subject removes every trace of the user (id 987654321, email erase.me@example.test, IP
     * 203.0.113.77) from all retained rows of audit_log, audit_personal and audit_subjects; every earlier audit_log row
     * is unchanged; exactly one row is added ('audit_subject_erased', personal_roles '', metadata {erased_rows}); the
     * user's entries read back with personal_erased true; an actor_id filter for the user finds nothing; replay of an
     * erased entry says erased. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     */
    // AUDIT-08
    @Test
    @Order(19)
    void testEraseSubject() throws Exception {
        String uid = "987654321";
        String email = "erase.me@example.test";
        String ip = "203.0.113.77";
        // The user acts on their own account, from their IP.
        String own = (String) service.log(AuditLoggingService.LogRequest.byUser(uid, "user_email_changed", "user", uid)
                .request(ip, "Mozilla/5.0", "req_1")
                .values(AuditLoggingService.toJsonNode(Map.of("email", "old." + email)), AuditLoggingService.toJsonNode(Map.of("email", email)))
                .why("wc_" + uid)).get("log_id");
        // An admin acts on the user.
        String byAdmin = (String) service.log(AuditLoggingService.LogRequest.byUser("42", "user_suspended", "user", uid)
                .request("198.51.100.1", "AdminUA", "req_2")
                .values(AuditLoggingService.toJsonNode(Map.of("email", email, "status", "active")),
                        AuditLoggingService.toJsonNode(Map.of("email", email, "status", "suspended")))).get("log_id");
        // The user's subscription, and an API key the user owns.
        service.log(AuditLoggingService.LogRequest.byService("billing", "subscription_changed", "subscription", "sub_" + uid)
                .subject(uid).values(AuditLoggingService.toJsonNode(Map.of("tier", "team")), AuditLoggingService.toJsonNode(Map.of("tier", "pro"))));
        AuditLoggingService.LogRequest viaKey = AuditLoggingService.LogRequest.byUser("key_77", "deployment_created", "deployment", "d_9")
                .subject("none").request(ip, "curl", "req_3");
        viaKey.actorType = "api_key";
        viaKey.actorUserId = uid;
        service.log(viaKey);
        // Another user's entry must keep its personal data.
        String other = (String) userEvent("555", "user_created", "555", null, Map.of("email", "keep@example.test")).get("log_id");

        List<List<String>> logBefore = rows("SELECT * FROM audit_log ORDER BY id");
        Map<String, Object> erased = service.eraseSubject(uid);
        assertEquals(5, erased.get("erased_rows"));   // own: actor+subject, byAdmin: subject, subscription: subject, key: actor

        for (String table : List.of("audit_log", "audit_personal", "audit_subjects")) {
            for (List<String> row : rows("SELECT * FROM " + table)) {
                String joined = String.join("|", row);
                assertFalse(joined.contains(uid), table + " still holds the user id: " + joined);
                assertFalse(joined.contains(email), table + " still holds the email: " + joined);
                assertFalse(joined.contains(ip), table + " still holds the IP: " + joined);
            }
        }
        List<List<String>> logAfter = rows("SELECT * FROM audit_log ORDER BY id");
        assertEquals(logBefore.size() + 1, logAfter.size());
        assertEquals(logBefore, logAfter.subList(0, logBefore.size()), "earlier audit_log rows are unchanged");
        Map<String, Object> marker = logsOf(service.queryLogs(ADMIN, null, "audit_subject_erased", null, 10, 0, null, null)).get(0);
        assertEquals("", marker.get("personal_roles"));
        assertEquals("service", marker.get("actor_type"));
        assertEquals("user", marker.get("resource_type"));
        assertNull(marker.get("resource_id"));
        assertEquals(5, ((JsonNode) marker.get("metadata")).get("erased_rows").asInt());
        assertEquals(1, ((JsonNode) marker.get("metadata")).size());

        assertEquals(0L, service.queryLogs(ADMIN, uid, null, null, 100, 0, null, null).get("total"));
        Map<String, Map<String, Object>> byId = new HashMap<>();
        for (Map<String, Object> l : logsOf(service.queryLogs(ADMIN, null, null, null, 100, 0, null, null))) {
            byId.put((String) l.get("id"), l);
        }
        assertEquals(true, byId.get(own).get("personal_erased"));
        assertNull(byId.get(own).get("actor_id"));
        assertNull(byId.get(own).get("resource_id"));
        assertEquals(true, byId.get(byAdmin).get("personal_erased"));
        assertEquals("42", byId.get(byAdmin).get("actor_id"), "the admin's own actor row is not the user's data");
        assertEquals(false, byId.get(other).get("personal_erased"));
        assertEquals("555", byId.get(other).get("resource_id"));
        Map<String, Object> replay = service.replay(ADMIN, own);
        assertEquals(true, replay.get("erased"));
        assertNull(replay.get("resource_state_at_time"));
        assertNull(replay.get("has_diverged"));
        // The subject_ref was random, not derived from the id: nothing left to recompute.
        assertEquals(0, rows("SELECT * FROM audit_subjects WHERE user_id = '" + uid + "'").size());
    }

    /**
     * AUDIT-09: apply_retention erases the personal data of entries older than the retention period (and subjects left
     * with nothing), keeps it for newer entries, and removes no audit_log row. Added 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: a second service on the same in-memory database, with a test clock.
     */
    // AUDIT-09
    @Test
    @Order(20)
    void testApplyRetention() throws Exception {
        Instant t0 = Instant.parse("2025-01-01T00:00:00Z");
        Instant[] now = {t0};
        java.time.Clock clock = new java.time.Clock() {
            @Override public java.time.ZoneId getZone() { return java.time.ZoneOffset.UTC; }
            @Override public java.time.Clock withZone(java.time.ZoneId z) { return this; }
            @Override public Instant instant() { return now[0]; }
        };
        AuditLoggingService svc = new AuditLoggingService(connection, clock, java.time.Duration.ofDays(365));
        String oldEntry = (String) svc.log(AuditLoggingService.LogRequest.byUser("700", "user_created", "user", "700")
                .request("192.0.2.70", "UA", "r1").values(null, AuditLoggingService.toJsonNode(Map.of("email", "old@example.test")))).get("log_id");
        now[0] = t0.plus(java.time.Duration.ofDays(200));
        String newEntry = (String) svc.log(AuditLoggingService.LogRequest.byUser("701", "user_created", "user", "701")
                .values(null, AuditLoggingService.toJsonNode(Map.of("email", "new@example.test")))).get("log_id");
        int logRows = rows("SELECT * FROM audit_log").size();

        now[0] = t0.plus(java.time.Duration.ofDays(400));
        assertEquals(2, svc.applyRetention(now[0]).get("erased_rows"));   // actor + subject rows of the old entry
        assertEquals(logRows, rows("SELECT * FROM audit_log").size(), "no audit_log row is removed");
        Map<String, Map<String, Object>> byId = new HashMap<>();
        for (Map<String, Object> l : logsOf(svc.queryLogs(ADMIN, null, null, null, 100, 0, null, null))) {
            byId.put((String) l.get("id"), l);
        }
        assertEquals(true, byId.get(oldEntry).get("personal_erased"));
        assertEquals(false, byId.get(newEntry).get("personal_erased"));
        assertEquals("701", byId.get(newEntry).get("resource_id"));
        assertEquals(0, rows("SELECT * FROM audit_subjects WHERE user_id = '700'").size());
        assertEquals(1, rows("SELECT * FROM audit_subjects WHERE user_id = '701'").size());
    }

    /**
     * AUDIT-10: log() refuses a non-'user' entry without subject_user_id (400 subject_required), a metadata key other
     * than feature_flag / erased_rows (400 metadata_key_not_allowed), an api_key entry without actor_user_id (400
     * actor_user_required) and a 'user' entry whose subject contradicts it (400 subject_mismatch); query, replay and
     * search by a non-admin (or no) caller get 403. Nothing is written for a refused entry. Added 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP.
     */
    // AUDIT-10
    @Test
    @Order(21)
    void testRefusals() throws Exception {
        AuditLoggingService.AuditException e = refused(() -> service.log(
                AuditLoggingService.LogRequest.byUser("1", "billing_changed", "subscription", "s_1")));
        assertEquals(400, e.status());
        assertEquals("subject_required", e.code());
        e = refused(() -> service.log(AuditLoggingService.LogRequest.byUser("1", "billing_changed", "subscription", "s_1")
                .subject("none").meta(AuditLoggingService.toJsonNode(Map.of("ip", "192.0.2.1")))));
        assertEquals("metadata_key_not_allowed", e.code());
        AuditLoggingService.LogRequest key = AuditLoggingService.LogRequest.byUser("key_1", "deployment_created", "deployment", "d_1").subject("none");
        key.actorType = "api_key";
        e = refused(() -> service.log(key));
        assertEquals("actor_user_required", e.code());
        e = refused(() -> service.log(AuditLoggingService.LogRequest.byUser("1", "user_created", "user", "u_1").subject("u_2")));
        assertEquals("subject_mismatch", e.code());
        assertEquals(0, rows("SELECT * FROM audit_log").size());
        assertEquals(0, rows("SELECT * FROM audit_subjects").size());

        String id = (String) userEvent("1", "user_created", "u_1", null, Map.of("n", 1)).get("log_id");
        for (AuditLoggingService.Caller c : Arrays.asList(MEMBER, null)) {
            assertEquals(403, refused(() -> service.queryLogs(c, null, null, null, 10, 0, null, null)).status());
            assertEquals(403, refused(() -> service.replay(c, id)).status());
            assertEquals(403, refused(() -> service.search(c, "user", null, 10)).status());
        }
    }

    /**
     * AUDIT-10 (Phase B.2 amendment): log() refuses an actor_type other than user/service/api_key (400
     * invalid_actor_type), a 'user' actor without actor_id (400 actor_required) and a 'service' actor without
     * actor_service (400 actor_service_required, even when an actor_id is given: no fallback), writing nothing; erase_subject and apply_retention return erased_rows =
     * the audit_personal rows they deleted (0 when there is nothing); replay's "erased" is false while the entry's
     * subject row exists and true once it is gone. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: H2.
     */
    // AUDIT-10
    @Test
    @Order(22)
    void testActorRefusalsErasedRowsAndReplayErasedFlag() throws Exception {
        AuditLoggingService.LogRequest robot = AuditLoggingService.LogRequest.byUser("1", "user_created", "user", "u_1");
        robot.actorType = "robot";
        AuditLoggingService.AuditException e = refused(() -> service.log(robot));
        assertEquals(400, e.status());
        assertEquals("invalid_actor_type", e.code());
        e = refused(() -> service.log(AuditLoggingService.LogRequest.byUser(null, "user_created", "user", "u_1")));
        assertEquals(400, e.status());
        assertEquals("actor_required", e.code());
        e = refused(() -> service.log(AuditLoggingService.LogRequest.byService(null, "billing_changed", "subscription", "s_1").subject("none")));
        assertEquals(400, e.status());
        assertEquals("actor_service_required", e.code());
        // No fallback to actor_id as the service name (lead's spec clarification, 2026-11-10).
        AuditLoggingService.LogRequest withId = AuditLoggingService.LogRequest.byService(null, "billing_changed", "subscription", "s_1").subject("none");
        withId.actorId = "billing";
        assertEquals("actor_service_required", refused(() -> service.log(withId)).code());
        assertEquals(0, rows("SELECT * FROM audit_log").size());

        String live = (String) userEvent("7", "user_updated", "u_7", Map.of("n", 1), Map.of("n", 2)).get("log_id");
        Map<String, Object> before = service.replay(ADMIN, live);
        assertEquals(false, before.get("erased"));
        assertNotNull(before.get("resource_state_at_time"));
        // u_7 is both actor ("7" is another user) and subject: one subject row under u_7.
        assertEquals(1, service.eraseSubject("u_7").get("erased_rows"));
        assertEquals(0, service.eraseSubject("u_7").get("erased_rows"), "nothing left to erase");
        assertEquals(true, service.replay(ADMIN, live).get("erased"));
    }

    // ------------------------------------------------------------------
    // Additional: Search endpoint
    // ------------------------------------------------------------------

    @Test
    @Order(11)
    void testSearch() throws Exception {
        userEvent("1", "user_email_changed", "u_1", Map.of("email", "old@test.com"), Map.of("email", "new@test.com"));
        userEvent("2", "user_created", "u_2", null, Map.of("name", "Alice"));
        service.log(AuditLoggingService.LogRequest.byService("billing", "billing_changed", "subscription", "s_1").subject("none")
                .values(AuditLoggingService.toJsonNode(Map.of("tier", "basic")), AuditLoggingService.toJsonNode(Map.of("tier", "pro"))));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> results = (List<Map<String, Object>>) service.search(ADMIN, "email", null, 50).get("results");
        assertEquals(1, results.size());
        assertEquals("user_email_changed", results.get(0).get("action"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> results2 = (List<Map<String, Object>>) service.search(ADMIN, "user", "user", 50).get("results");
        assertEquals(2, results2.size());

        // A subject entry's resource_id is searchable although it lives in audit_personal.
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> byResource = (List<Map<String, Object>>) service.search(ADMIN, "u_2", null, 50).get("results");
        assertEquals(1, byResource.size());
    }

    // ------------------------------------------------------------------
    // Additional: Date range filtering
    // ------------------------------------------------------------------

    @Test
    @Order(12)
    void testDateRangeFiltering() throws Exception {
        String sql = """
            INSERT INTO audit_log (id, timestamp, actor_type, actor_service, action, resource_type, resource_id,
                                   old_value, new_value, why_chain_id, personal_roles, metadata)
            VALUES (?, ?, 'service', 'test', ?, 'deployment', ?, '{}', '{}', NULL, '', NULL)
            """;
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            Object[][] rows = {{1L, "2026-01-15T10:00:00Z", "deployment_created", "d_jan"},
                    {2L, "2026-06-15T10:00:00Z", "deployment_suspended", "d_jun"},
                    {3L, "2026-12-15T10:00:00Z", "deployment_created", "d_dec"}};
            for (Object[] r : rows) {
                ps.setLong(1, (Long) r[0]);
                ps.setTimestamp(2, Timestamp.from(Instant.parse((String) r[1])));
                ps.setString(3, (String) r[2]);
                ps.setString(4, (String) r[3]);
                ps.executeUpdate();
            }
        }
        assertEquals(2, (Long) service.queryLogs(ADMIN, null, null, null, 100, 0, "2026-01-01", "2026-06-30").get("total"));
        assertEquals(1, (Long) service.queryLogs(ADMIN, null, null, null, 100, 0, "2026-07-01", null).get("total"));
    }

    // ------------------------------------------------------------------
    // Additional: Validation errors
    // ------------------------------------------------------------------

    @Test
    @Order(13)
    void testValidation_missingActorType() {
        AuditLoggingService.LogRequest r = AuditLoggingService.LogRequest.byUser("1", "user_created", "user", "u_1");
        r.actorType = null;
        assertEquals("invalid_actor_type", refused(() -> service.log(r)).code());
    }

    @Test
    @Order(14)
    void testValidation_missingAction() {
        assertEquals("action_required", refused(() -> service.log(AuditLoggingService.LogRequest.byUser("1", null, "user", "u_1"))).code());
    }

    @Test
    @Order(15)
    void testValidation_missingResourceType() {
        assertEquals("resource_type_required", refused(() -> service.log(AuditLoggingService.LogRequest.byUser("1", "user_created", null, "u_1"))).code());
    }

    @Test
    @Order(16)
    void testValidation_missingResourceId() {
        assertEquals("resource_id_required", refused(() -> service.log(AuditLoggingService.LogRequest.byUser("1", "user_created", "user", null))).code());
    }

    // ------------------------------------------------------------------
    // Additional: Metadata storage
    // ------------------------------------------------------------------

    /**
     * Metadata is stored and read back. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: only feature_flag and
     * erased_rows are allowed now; the request details (ip, user_agent, request_id) go in the actor's personal row.
     */
    @Test
    @Order(17)
    void testMetadataStorage() throws Exception {
        service.log(AuditLoggingService.LogRequest.byUser("1", "billing_changed", "subscription", "s_meta").subject("1")
                .request("192.168.1.1", "TestAgent/1.0", "req_abc123")
                .values(AuditLoggingService.toJsonNode(Map.of("tier", "basic")), AuditLoggingService.toJsonNode(Map.of("tier", "pro")))
                .meta(AuditLoggingService.toJsonNode(Map.of("feature_flag", "new_billing"))));

        List<Map<String, Object>> logs = logsOf(service.queryLogs(ADMIN, null, null, null, 100, 0, null, null));
        assertEquals(1, logs.size());
        JsonNode storedMeta = (JsonNode) logs.get(0).get("metadata");
        assertEquals("new_billing", storedMeta.get("feature_flag").asText());
        assertEquals(1, storedMeta.size());
        List<List<String>> personal = rows("SELECT data FROM audit_personal WHERE role = 'actor'");
        assertTrue(personal.get(0).get(0).contains("192.168.1.1"));
        assertTrue(personal.get(0).get(0).contains("req_abc123"));
    }

    // ------------------------------------------------------------------
    // Additional: Replay with null old_value (creation event)
    // ------------------------------------------------------------------

    @Test
    @Order(18)
    void testReplay_creationEvent_nullOldValue() throws Exception {
        String logId = (String) userEvent("1", "user_created", "u_new", null, Map.of("name", "New User")).get("log_id");
        Map<String, Object> replay = service.replay(ADMIN, logId);
        assertEquals(false, replay.get("has_diverged"));
        JsonNode state = (JsonNode) replay.get("resource_state_at_time");
        assertTrue(state.isNull() || state.isMissingNode());
    }

    /** Every row of a query as strings (all columns), for the erasure scan. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static List<List<String>> rows(String sql) throws SQLException {
        List<List<String>> out = new ArrayList<>();
        try (Statement st = connection.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            int n = rs.getMetaData().getColumnCount();
            while (rs.next()) {
                List<String> row = new ArrayList<>();
                for (int c = 1; c <= n; c++) row.add(String.valueOf(rs.getString(c)));
                out.add(row);
            }
        }
        return out;
    }
}

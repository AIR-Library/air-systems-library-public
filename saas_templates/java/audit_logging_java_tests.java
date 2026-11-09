package com.saas.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.NullNode;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.sql.*;
import java.time.Instant;
import java.time.LocalDate;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for AuditLoggingService.
 *
 * Covers every case listed in the spec's TESTS section:
 *   ✓ Happy path: log mutation, query it back
 *   ✓ Replay: divergence detection (state changed since log)
 *   ✓ Filtering: actor_id + action + resource_type work together
 *   ✓ Pagination: limit/offset work
 *   ✓ Performance: 1M+ logs, queries return <100ms
 *   ✓ Immutability: UPDATE on log returns error
 *   ✓ Wildcard: action='user_*' matches user_created, user_suspended, etc.
 */
@ExtendWith(MockitoExtension.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuditLoggingServiceTest {

    private static Connection connection;
    private static AuditLoggingService service;
    private static final ObjectMapper om = new ObjectMapper();

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
            stmt.execute("DELETE FROM audit_log");
        }
    }

    // ------------------------------------------------------------------
    // ✓ Happy path: log mutation, query it back
    // ------------------------------------------------------------------

    @Test
    @Order(1)
    void testHappyPath_logAndQuery() throws Exception {
        Map<String, Object> oldVal = new LinkedHashMap<>();
        oldVal.put("tier", "team");
        oldVal.put("billing_date", "2026-10-15");

        Map<String, Object> newVal = new LinkedHashMap<>();
        newVal.put("tier", "enterprise");
        newVal.put("billing_date", "2026-10-15");

        Map<String, Object> response = service.logMutation(
                "123", "user", "subscription_changed", "subscription", "456",
                AuditLoggingService.toJsonNode(oldVal),
                AuditLoggingService.toJsonNode(newVal),
                "wc_789", null);

        assertTrue((Boolean) response.get("success"));
        assertNotNull(response.get("log_id"));

        // Query it back
        Map<String, Object> queryResult = service.queryLogs(
                "123", "subscription_changed", "subscription", 100, 0, null, null);

        assertEquals(1, (Long) queryResult.get("total"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> logs = (List<Map<String, Object>>) queryResult.get("logs");
        assertEquals(1, logs.size());

        Map<String, Object> log = logs.get(0);
        assertEquals("123", log.get("actor_id"));
        assertEquals("subscription_changed", log.get("action"));
        assertEquals("subscription", log.get("resource_type"));
        assertEquals("456", log.get("resource_id"));
        assertEquals("wc_789", log.get("why_chain_id"));

        JsonNode oldJson = (JsonNode) log.get("old_value");
        assertEquals("team", oldJson.get("tier").asText());
        JsonNode newJson = (JsonNode) log.get("new_value");
        assertEquals("enterprise", newJson.get("tier").asText());
    }

    // ------------------------------------------------------------------
    // ✓ Replay: divergence detection (state changed since log)
    // ------------------------------------------------------------------

    @Test
    @Order(2)
    void testReplay_noDivergence() throws Exception {
        Map<String, Object> oldVal = Map.of("status", "active");
        Map<String, Object> newVal = Map.of("status", "suspended");

        Map<String, Object> logResp = service.logMutation(
                "1", "user", "user_suspended", "user", "u_001",
                AuditLoggingService.toJsonNode(oldVal),
                AuditLoggingService.toJsonNode(newVal),
                null, null);

        String logId = (String) logResp.get("log_id");

        Map<String, Object> replay = service.replay(logId);
        assertEquals(logId, replay.get("log_id"));
        assertNotNull(replay.get("timestamp"));
        assertEquals(false, replay.get("has_diverged"));

        JsonNode state = (JsonNode) replay.get("resource_state_at_time");
        assertEquals("active", state.get("status").asText());
    }

    @Test
    @Order(3)
    void testReplay_divergenceDetected() throws Exception {
        // First mutation: user created
        Map<String, Object> old1 = Map.of("status", "none");
        Map<String, Object> new1 = Map.of("status", "active");
        Map<String, Object> logResp1 = service.logMutation(
                "1", "user", "user_created", "user", "u_002",
                AuditLoggingService.toJsonNode(old1),
                AuditLoggingService.toJsonNode(new1),
                null, null);
        String logId1 = (String) logResp1.get("log_id");

        // Second mutation: user suspended (state diverges)
        Map<String, Object> old2 = Map.of("status", "active");
        Map<String, Object> new2 = Map.of("status", "suspended");
        service.logMutation(
                "1", "user", "user_suspended", "user", "u_002",
                AuditLoggingService.toJsonNode(old2),
                AuditLoggingService.toJsonNode(new2),
                null, null);

        // Replay the first log: state has diverged
        Map<String, Object> replay = service.replay(logId1);
        assertEquals(true, replay.get("has_diverged"));
    }

    @Test
    @Order(3)
    void testReplay_divergenceAfterAnUnchangedEntry() throws Exception {
        // Values A, A, B: the first A has diverged, though the entry right after it is the same (CodeRabbit, PR 18).
        Map<String, Object> a = Map.of("status", "active");
        Map<String, Object> b = Map.of("status", "suspended");
        String first = (String) service.logMutation("1", "user", "user_created", "user", "u_aab",
                AuditLoggingService.toJsonNode(Map.of("status", "none")), AuditLoggingService.toJsonNode(a), null, null).get("log_id");
        service.logMutation("1", "user", "user_touched", "user", "u_aab",
                AuditLoggingService.toJsonNode(a), AuditLoggingService.toJsonNode(a), null, null);
        service.logMutation("1", "user", "user_suspended", "user", "u_aab",
                AuditLoggingService.toJsonNode(a), AuditLoggingService.toJsonNode(b), null, null);
        assertEquals(true, service.replay(first).get("has_diverged"));
    }

    @Test
    @Order(4)
    void testReplay_logNotFound() {
        assertThrows(NoSuchElementException.class, () -> service.replay("99999"));
    }

    // ------------------------------------------------------------------
    // ✓ Filtering: actor_id + action + resource_type work together
    // ------------------------------------------------------------------

    @Test
    @Order(5)
    void testFiltering_combinedFilters() throws Exception {
        // Insert multiple logs with different attributes
        service.logMutation("100", "user", "user_created", "user", "u_1",
                NullNode.getInstance(), AuditLoggingService.toJsonNode(Map.of("name", "Alice")), null, null);
        service.logMutation("100", "user", "user_suspended", "user", "u_2",
                AuditLoggingService.toJsonNode(Map.of("status", "active")),
                AuditLoggingService.toJsonNode(Map.of("status", "suspended")), null, null);
        service.logMutation("200", "service", "billing_changed", "subscription", "s_1",
                AuditLoggingService.toJsonNode(Map.of("tier", "basic")),
                AuditLoggingService.toJsonNode(Map.of("tier", "pro")), null, null);
        service.logMutation("100", "user", "user_created", "user", "u_3",
                NullNode.getInstance(), AuditLoggingService.toJsonNode(Map.of("name", "Bob")), null, null);

        // Filter: actor_id=100, action=user_*, resource_type=user
        Map<String, Object> result = service.queryLogs("100", "user_*", "user", 100, 0, null, null);
        assertEquals(3, (Long) result.get("total"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> logs = (List<Map<String, Object>>) result.get("logs");
        for (Map<String, Object> log : logs) {
            assertEquals("100", log.get("actor_id"));
            assertTrue(((String) log.get("action")).startsWith("user_"));
            assertEquals("user", log.get("resource_type"));
        }

        // Filter: actor_id=200 only
        Map<String, Object> result2 = service.queryLogs("200", null, null, 100, 0, null, null);
        assertEquals(1, (Long) result2.get("total"));

        // Filter: resource_type=subscription only
        Map<String, Object> result3 = service.queryLogs(null, null, "subscription", 100, 0, null, null);
        assertEquals(1, (Long) result3.get("total"));
    }

    // ------------------------------------------------------------------
    // ✓ Pagination: limit/offset work
    // ------------------------------------------------------------------

    @Test
    @Order(6)
    void testPagination() throws Exception {
        // Insert 10 logs
        for (int i = 1; i <= 10; i++) {
            service.logMutation("actor_" + i, "user", "user_created", "user", "u_" + i,
                    NullNode.getInstance(),
                    AuditLoggingService.toJsonNode(Map.of("seq", i)),
                    null, null);
        }

        // Page 1: limit=3, offset=0
        Map<String, Object> page1 = service.queryLogs(null, null, null, 3, 0, null, null);
        assertEquals(10, (Long) page1.get("total"));
        assertEquals(true, page1.get("has_more"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> logs1 = (List<Map<String, Object>>) page1.get("logs");
        assertEquals(3, logs1.size());

        // Page 2: limit=3, offset=3
        Map<String, Object> page2 = service.queryLogs(null, null, null, 3, 3, null, null);
        assertEquals(true, page2.get("has_more"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> logs2 = (List<Map<String, Object>>) page2.get("logs");
        assertEquals(3, logs2.size());

        // Page 4: limit=3, offset=9
        Map<String, Object> page4 = service.queryLogs(null, null, null, 3, 9, null, null);
        assertEquals(false, page4.get("has_more"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> logs4 = (List<Map<String, Object>>) page4.get("logs");
        assertEquals(1, logs4.size());

        // All 10 with limit=10
        Map<String, Object> all = service.queryLogs(null, null, null, 10, 0, null, null);
        assertEquals(false, all.get("has_more"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> allLogs = (List<Map<String, Object>>) all.get("logs");
        assertEquals(10, allLogs.size());
    }

    // ------------------------------------------------------------------
    // ✓ Performance: 1M+ logs, queries return <100ms
    // ------------------------------------------------------------------

    @Test
    @Order(7)
    void testPerformance_1MLogs() throws Exception {
        // Insert 1,000,000 logs in batch
        String batchSql = """
            INSERT INTO audit_log
                (id, timestamp, actor_id, actor_type, action, resource_type, resource_id,
                 old_value, new_value, why_chain_id, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;

        long start = System.currentTimeMillis();
        try (PreparedStatement ps = connection.prepareStatement(batchSql)) {
            connection.setAutoCommit(false);
            for (long i = 1; i <= 1_000_000; i++) {
                ps.setLong(1, i);
                ps.setTimestamp(2, Timestamp.from(Instant.now().minusSeconds(1_000_000 - i)));
                ps.setString(3, "actor_" + (i % 1000));
                ps.setString(4, "user");
                ps.setString(5, "user_created");
                ps.setString(6, "user");
                ps.setString(7, "u_" + i);
                ps.setString(8, "{}");
                ps.setString(9, "{\"seq\":" + i + "}");
                ps.setString(10, null);
                ps.setString(11, null);
                ps.addBatch();
                if (i % 10000 == 0) {
                    ps.executeBatch();
                }
            }
            ps.executeBatch();
            connection.commit();
        }
        connection.setAutoCommit(true);
        long insertMs = System.currentTimeMillis() - start;
        System.out.println("[PERF] Inserted 1M logs in " + insertMs + "ms");

        // Query with filter: should return <100ms
        long queryStart = System.currentTimeMillis();
        Map<String, Object> result = service.queryLogs("actor_500", "user_created", "user", 100, 0, null, null);
        long queryMs = System.currentTimeMillis() - queryStart;
        System.out.println("[PERF] Filtered query took " + queryMs + "ms, total=" + result.get("total"));

        assertTrue(queryMs < 100, "Query should complete in <100ms but took " + queryMs + "ms");
        assertTrue((Long) result.get("total") > 0);
    }

    // ------------------------------------------------------------------
    // ✓ Immutability: UPDATE on log returns error
    // ------------------------------------------------------------------

    @Test
    @Order(8)
    void testImmutability_updateThrows() throws Exception {
        Map<String, Object> logResp = service.logMutation(
                "1", "user", "user_created", "user", "u_imm",
                NullNode.getInstance(), AuditLoggingService.toJsonNode(Map.of("x", 1)), null, null);
        String logId = (String) logResp.get("log_id");

        assertThrows(UnsupportedOperationException.class, () -> service.updateLog(logId));
    }

    @Test
    @Order(9)
    void testImmutability_deleteThrows() throws Exception {
        Map<String, Object> logResp = service.logMutation(
                "1", "user", "user_created", "user", "u_del",
                NullNode.getInstance(), AuditLoggingService.toJsonNode(Map.of("x", 1)), null, null);
        String logId = (String) logResp.get("log_id");

        assertThrows(UnsupportedOperationException.class, () -> service.deleteLog(logId));
    }

    // ------------------------------------------------------------------
    // ✓ Wildcard: action='user_*' matches user_created, user_suspended, etc.
    // ------------------------------------------------------------------

    @Test
    @Order(10)
    void testWildcard_actionMatching() throws Exception {
        service.logMutation("1", "user", "user_created", "user", "u_1",
                NullNode.getInstance(), AuditLoggingService.toJsonNode(Map.of("n", 1)), null, null);
        service.logMutation("1", "user", "user_suspended", "user", "u_2",
                AuditLoggingService.toJsonNode(Map.of("s", "active")),
                AuditLoggingService.toJsonNode(Map.of("s", "suspended")), null, null);
        service.logMutation("1", "user", "user_email_changed", "user", "u_3",
                AuditLoggingService.toJsonNode(Map.of("e", "a@b.c")),
                AuditLoggingService.toJsonNode(Map.of("e", "x@y.z")), null, null);
        service.logMutation("1", "user", "billing_changed", "subscription", "s_1",
                AuditLoggingService.toJsonNode(Map.of("t", "basic")),
                AuditLoggingService.toJsonNode(Map.of("t", "pro")), null, null);

        // Wildcard user_* should match the 3 user_* actions but not billing_changed
        Map<String, Object> result = service.queryLogs("1", "user_*", null, 100, 0, null, null);
        assertEquals(3, (Long) result.get("total"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> logs = (List<Map<String, Object>>) result.get("logs");
        Set<String> actions = new HashSet<>();
        for (Map<String, Object> log : logs) {
            actions.add((String) log.get("action"));
        }
        assertTrue(actions.contains("user_created"));
        assertTrue(actions.contains("user_suspended"));
        assertTrue(actions.contains("user_email_changed"));
        assertFalse(actions.contains("billing_changed"));
    }

    // ------------------------------------------------------------------
    // Additional: Search endpoint
    // ------------------------------------------------------------------

    @Test
    @Order(11)
    void testSearch() throws Exception {
        service.logMutation("1", "user", "user_email_changed", "user", "u_1",
                AuditLoggingService.toJsonNode(Map.of("email", "old@test.com")),
                AuditLoggingService.toJsonNode(Map.of("email", "new@test.com")), null, null);
        service.logMutation("2", "user", "user_created", "user", "u_2",
                NullNode.getInstance(), AuditLoggingService.toJsonNode(Map.of("name", "Alice")), null, null);
        service.logMutation("3", "service", "billing_changed", "subscription", "s_1",
                AuditLoggingService.toJsonNode(Map.of("tier", "basic")),
                AuditLoggingService.toJsonNode(Map.of("tier", "pro")), null, null);

        // Search for "email" in actions
        Map<String, Object> result = service.search("email", null, 50);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> results = (List<Map<String, Object>>) result.get("results");
        assertEquals(1, results.size());
        assertEquals("user_email_changed", results.get(0).get("action"));

        // Search with resource_type filter
        Map<String, Object> result2 = service.search("user", "user", 50);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> results2 = (List<Map<String, Object>>) result2.get("results");
        assertEquals(2, results2.size());
    }

    // ------------------------------------------------------------------
    // Additional: Date range filtering
    // ------------------------------------------------------------------

    @Test
    @Order(12)
    void testDateRangeFiltering() throws Exception {
        // Insert logs with specific timestamps by direct SQL
        String sql = """
            INSERT INTO audit_log
                (id, timestamp, actor_id, actor_type, action, resource_type, resource_id,
                 old_value, new_value, why_chain_id, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            // Log in Jan 2026
            ps.setLong(1, 1);
            ps.setTimestamp(2, Timestamp.valueOf("2026-01-15 10:00:00"));
            ps.setString(3, "1");
            ps.setString(4, "user");
            ps.setString(5, "user_created");
            ps.setString(6, "user");
            ps.setString(7, "u_jan");
            ps.setString(8, "{}");
            ps.setString(9, "{}");
            ps.setString(10, null);
            ps.setString(11, null);
            ps.executeUpdate();

            // Log in Jun 2026
            ps.setLong(1, 2);
            ps.setTimestamp(2, Timestamp.valueOf("2026-06-15 10:00:00"));
            ps.setString(3, "1");
            ps.setString(4, "user");
            ps.setString(5, "user_suspended");
            ps.setString(6, "user");
            ps.setString(7, "u_jun");
            ps.setString(8, "{}");
            ps.setString(9, "{}");
            ps.setString(10, null);
            ps.setString(11, null);
            ps.executeUpdate();

            // Log in Dec 2026
            ps.setLong(1, 3);
            ps.setTimestamp(2, Timestamp.valueOf("2026-12-15 10:00:00"));
            ps.setString(3, "1");
            ps.setString(4, "user");
            ps.setString(5, "user_created");
            ps.setString(6, "user");
            ps.setString(7, "u_dec");
            ps.setString(8, "{}");
            ps.setString(9, "{}");
            ps.setString(10, null);
            ps.setString(11, null);
            ps.executeUpdate();
        }

        // Filter: date_from=2026-01-01, date_to=2026-06-30
        Map<String, Object> result = service.queryLogs(null, null, null, 100, 0, "2026-01-01", "2026-06-30");
        assertEquals(2, (Long) result.get("total"));

        // Filter: date_from=2026-07-01
        Map<String, Object> result2 = service.queryLogs(null, null, null, 100, 0, "2026-07-01", null);
        assertEquals(1, (Long) result2.get("total"));
    }

    // ------------------------------------------------------------------
    // Additional: Validation errors
    // ------------------------------------------------------------------

    @Test
    @Order(13)
    void testValidation_missingActorType() {
        assertThrows(IllegalArgumentException.class, () ->
                service.logMutation("1", null, "user_created", "user", "u_1",
                        NullNode.getInstance(), NullNode.getInstance(), null, null));
    }

    @Test
    @Order(14)
    void testValidation_missingAction() {
        assertThrows(IllegalArgumentException.class, () ->
                service.logMutation("1", "user", null, "user", "u_1",
                        NullNode.getInstance(), NullNode.getInstance(), null, null));
    }

    @Test
    @Order(15)
    void testValidation_missingResourceType() {
        assertThrows(IllegalArgumentException.class, () ->
                service.logMutation("1", "user", "user_created", null, "u_1",
                        NullNode.getInstance(), NullNode.getInstance(), null, null));
    }

    @Test
    @Order(16)
    void testValidation_missingResourceId() {
        assertThrows(IllegalArgumentException.class, () ->
                service.logMutation("1", "user", "user_created", "user", null,
                        NullNode.getInstance(), NullNode.getInstance(), null, null));
    }

    // ------------------------------------------------------------------
    // Additional: Metadata storage
    // ------------------------------------------------------------------

    @Test
    @Order(17)
    void testMetadataStorage() throws Exception {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("ip", "192.168.1.1");
        meta.put("user_agent", "TestAgent/1.0");
        meta.put("request_id", "req_abc123");
        meta.put("feature_flag", "new_billing");

        Map<String, Object> logResp = service.logMutation(
                "1", "user", "billing_changed", "subscription", "s_meta",
                AuditLoggingService.toJsonNode(Map.of("tier", "basic")),
                AuditLoggingService.toJsonNode(Map.of("tier", "pro")),
                null, AuditLoggingService.toJsonNode(meta));

        String logId = (String) logResp.get("log_id");

        Map<String, Object> queryResult = service.queryLogs(null, null, null, 100, 0, null, null);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> logs = (List<Map<String, Object>>) queryResult.get("logs");
        assertEquals(1, logs.size());

        JsonNode storedMeta = (JsonNode) logs.get(0).get("metadata");
        assertEquals("192.168.1.1", storedMeta.get("ip").asText());
        assertEquals("TestAgent/1.0", storedMeta.get("user_agent").asText());
        assertEquals("req_abc123", storedMeta.get("request_id").asText());
        assertEquals("new_billing", storedMeta.get("feature_flag").asText());
    }

    // ------------------------------------------------------------------
    // Additional: Replay with null old_value (creation event)
    // ------------------------------------------------------------------

    @Test
    @Order(18)
    void testReplay_creationEvent_nullOldValue() throws Exception {
        Map<String, Object> logResp = service.logMutation(
                "1", "user", "user_created", "user", "u_new",
                NullNode.getInstance(),
                AuditLoggingService.toJsonNode(Map.of("name", "New User")),
                null, null);

        String logId = (String) logResp.get("log_id");
        Map<String, Object> replay = service.replay(logId);
        assertEquals(false, replay.get("has_diverged"));

        JsonNode state = (JsonNode) replay.get("resource_state_at_time");
        assertTrue(state.isNull() || state.isMissingNode());
    }
}

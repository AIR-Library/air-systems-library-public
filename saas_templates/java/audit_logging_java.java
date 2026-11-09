package com.saas.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.MissingNode;

import java.sql.*;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

/**
 * Immutable Audit Event Log with Replay capability.
 *
 * <p>Every mutation is logged immutably (append-only). Given a log entry, the
 * system can replay the resource state at that moment and detect whether the
 * state has diverged since.
 *
 * <p>Used by: GDPR compliance, SOC2, debugging, fraud detection, governance approval.
 */
public class AuditLoggingService implements AutoCloseable {

    private final Connection connection;
    private final ObjectMapper objectMapper;
    private final AtomicLong idSequence = new AtomicLong(0);

    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /**
     * Create a service backed by the given JDBC connection.
     * The schema is created (if not present) on construction.
     */
    public AuditLoggingService(Connection connection) throws SQLException {
        this.connection = connection;
        // Decimals are read as BigDecimal, so 0.100000000000000001 and ...002 stay different when Replay
        // compares values (as doubles they were equal; CodeRabbit, PR 18, 2026-11-09).
        this.objectMapper = new ObjectMapper()
                .enable(com.fasterxml.jackson.databind.DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);
        this.initializeSchema();
    }

    private void initializeSchema() throws SQLException {
        String ddl = """
            CREATE TABLE IF NOT EXISTS audit_log (
                id              BIGINT PRIMARY KEY,
                timestamp       TIMESTAMP WITH TIME ZONE NOT NULL,
                actor_id        VARCHAR(255),
                actor_type      VARCHAR(50) NOT NULL,
                action          VARCHAR(255) NOT NULL,
                resource_type   VARCHAR(255) NOT NULL,
                resource_id     VARCHAR(255) NOT NULL,
                old_value       TEXT,
                new_value       TEXT,
                why_chain_id    VARCHAR(255),
                metadata        TEXT
            );
            """;
        // Added 'id' as 5th column to fully cover ORDER BY timestamp, id
        String indexDdl = """
            CREATE INDEX IF NOT EXISTS idx_audit_log_query
                ON audit_log (actor_id, action, resource_type, timestamp, id);
            """;
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(ddl);
            stmt.execute(indexDdl);
        }
    }

    // ------------------------------------------------------------------
    // Endpoint 1: Log mutation (called BEFORE commit)
    // POST /audit/log
    // ------------------------------------------------------------------

    /**
     * Log a mutation. Returns a response map with {@code success} and {@code log_id}.
     *
     * @param actorId       user ID or null if system
     * @param actorType     'user' | 'service' | 'api_key'
     * @param action        e.g. 'subscription_changed'
     * @param resourceType  e.g. 'subscription'
     * @param resourceId    UUID or numeric ID
     * @param oldValue      snapshot before mutation (JSON)
     * @param newValue      snapshot after mutation (JSON)
     * @param whyChainId    link to why_chains table (optional)
     * @param metadata      extra context (optional)
     * @return response map: { success: true, log_id: "..." }
     */
    public Map<String, Object> logMutation(
            String actorId,
            String actorType,
            String action,
            String resourceType,
            String resourceId,
            JsonNode oldValue,
            JsonNode newValue,
            String whyChainId,
            JsonNode metadata) throws SQLException {

        if (actorType == null || actorType.isBlank()) {
            throw new IllegalArgumentException("actor_type is required");
        }
        if (action == null || action.isBlank()) {
            throw new IllegalArgumentException("action is required");
        }
        if (resourceType == null || resourceType.isBlank()) {
            throw new IllegalArgumentException("resource_type is required");
        }
        if (resourceId == null || resourceId.isBlank()) {
            throw new IllegalArgumentException("resource_id is required");
        }

        long id = idSequence.incrementAndGet();
        Instant now = Instant.now();

        String oldJson = toJsonString(oldValue);
        String newJson = toJsonString(newValue);
        String metaJson = toJsonString(metadata);

        String sql = """
            INSERT INTO audit_log
                (id, timestamp, actor_id, actor_type, action, resource_type, resource_id,
                 old_value, new_value, why_chain_id, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setLong(1, id);
            ps.setTimestamp(2, Timestamp.from(now));
            ps.setString(3, actorId);
            ps.setString(4, actorType);
            ps.setString(5, action);
            ps.setString(6, resourceType);
            ps.setString(7, resourceId);
            ps.setString(8, oldJson);
            ps.setString(9, newJson);
            ps.setString(10, whyChainId);
            ps.setString(11, metaJson);
            ps.executeUpdate();
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", true);
        response.put("log_id", String.valueOf(id));
        return response;
    }

    // ------------------------------------------------------------------
    // Endpoint 2: Query logs (filter + paginate)
    // GET /audit/logs?actor_id=...&action=...&resource_type=...&limit=...&offset=...&date_from=...&date_to=...
    // ------------------------------------------------------------------

    /**
     * Query audit logs with optional filters and pagination.
     *
     * @param actorId      filter by actor (null = no filter)
     * @param action       filter by action, supports wildcard suffix e.g. "user_*" (null = no filter)
     * @param resourceType filter by resource type (null = no filter)
     * @param limit        max rows to return (default 100)
     * @param offset       rows to skip (default 0)
     * @param dateFrom     inclusive lower bound, ISO date (null = no filter)
     * @param dateTo       inclusive upper bound, ISO date (null = no filter)
     * @return response map: { logs: [...], total: N, has_more: bool }
     */
    public Map<String, Object> queryLogs(
            String actorId,
            String action,
            String resourceType,
            int limit,
            int offset,
            String dateFrom,
            String dateTo) throws SQLException {

        if (limit <= 0) limit = 100;
        if (offset < 0) offset = 0;

        List<String> whereClauses = new ArrayList<>();
        List<Object> params = new ArrayList<>();

        if (actorId != null && !actorId.isBlank()) {
            whereClauses.add("actor_id = ?");
            params.add(actorId);
        }
        if (action != null && !action.isBlank()) {
            if (action.endsWith("*")) {
                String prefix = action.substring(0, action.length() - 1);
                whereClauses.add("action LIKE ?");
                params.add(prefix + "%");
            } else {
                whereClauses.add("action = ?");
                params.add(action);
            }
        }
        if (resourceType != null && !resourceType.isBlank()) {
            whereClauses.add("resource_type = ?");
            params.add(resourceType);
        }
        if (dateFrom != null && !dateFrom.isBlank()) {
            whereClauses.add("timestamp >= ?");
            params.add(Timestamp.valueOf(LocalDate.parse(dateFrom).atStartOfDay()));
        }
        if (dateTo != null && !dateTo.isBlank()) {
            whereClauses.add("timestamp < ?");
            params.add(Timestamp.valueOf(LocalDate.parse(dateTo).plusDays(1).atStartOfDay()));
        }

        String whereSql = whereClauses.isEmpty() ? "" : " WHERE " + String.join(" AND ", whereClauses);

        // Total matching rows, for has_more
        long total = 0;
        String countSql = "SELECT COUNT(*) FROM audit_log" + whereSql;
        try (PreparedStatement countPs = connection.prepareStatement(countSql)) {
            bindParams(countPs, params);
            try (ResultSet rs = countPs.executeQuery()) {
                if (rs.next()) {
                    total = rs.getLong(1);
                }
            }
        }

        // Then fetch the page of data
        String selectSql = """
            SELECT id, timestamp, actor_id, actor_type, action, resource_type, resource_id,
                   old_value, new_value, why_chain_id, metadata
            FROM audit_log
            """ + whereSql + " ORDER BY timestamp ASC, id ASC LIMIT ? OFFSET ?";

        List<Map<String, Object>> logs = new ArrayList<>();
        try (PreparedStatement ps = connection.prepareStatement(selectSql)) {
            bindParams(ps, params);
            int idx = params.size() + 1;
            ps.setInt(idx, limit);
            ps.setInt(idx + 1, offset);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    logs.add(mapRow(rs));
                }
            }
        }

        boolean hasMore = (offset + limit) < total;

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("logs", logs);
        response.put("total", total);
        response.put("has_more", hasMore);
        return response;
    }

    // ------------------------------------------------------------------
    // Endpoint 3: Replay (given log_id, what was state at that moment?)
    // GET /audit/replay/:log_id
    // ------------------------------------------------------------------

    /**
     * Replay the resource state at the time of the given log entry.
     *
     * @param logId the audit log ID
     * @return response map: { log_id, timestamp, resource_state_at_time, has_diverged }
     * @throws NoSuchElementException if the log entry does not exist
     */
    public Map<String, Object> replay(String logId) throws SQLException {
        long id;
        try {
            id = Long.parseLong(logId);
        } catch (NumberFormatException e) {
            throw new NoSuchElementException("Invalid log_id: " + logId);
        }

        String sql = """
            SELECT id, timestamp, actor_id, actor_type, action, resource_type, resource_id,
                   old_value, new_value, why_chain_id, metadata
            FROM audit_log WHERE id = ?
            """;

        Map<String, Object> logEntry;
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    throw new NoSuchElementException("Log entry not found: " + logId);
                }
                logEntry = mapRow(rs);
            }
        }

        // Determine divergence: has the resource state changed since this log?
        // Divergence = there exists a later log entry for the same resource
        // (same resource_type + resource_id) with a different new_value.
        JsonNode newValueNode = (JsonNode) logEntry.get("new_value");
        boolean hasDiverged = checkDivergence(id,
                (String) logEntry.get("resource_type"),
                (String) logEntry.get("resource_id"),
                newValueNode);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("log_id", logId);
        response.put("timestamp", logEntry.get("timestamp"));
        response.put("resource_state_at_time", logEntry.get("old_value"));
        response.put("has_diverged", hasDiverged);
        return response;
    }

    private boolean checkDivergence(long logId, String resourceType, String resourceId, JsonNode newValueJson)
            throws SQLException {
        String sql = """
            SELECT new_value FROM audit_log
            WHERE resource_type = ? AND resource_id = ? AND id > ?
            ORDER BY timestamp ASC, id ASC
            """;
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, resourceType);
            ps.setString(2, resourceId);
            ps.setLong(3, logId);
            try (ResultSet rs = ps.executeQuery()) {
                // Every later entry counts: A, A, B has diverged from the first A (CodeRabbit, PR 18).
                while (rs.next()) {
                    if (!Objects.equals(newValueJson, parseJson(rs.getString(1)))) {
                        return true;
                    }
                }
                return false;
            }
        }
    }

    // ------------------------------------------------------------------
    // Endpoint 4: Search (full-text over actions and resources)
    // GET /audit/search?q=...&resource_type=...&limit=...
    // ------------------------------------------------------------------

    /**
     * Full-text search over action and resource fields.
     *
     * @param query        search term (matched against action, resource_type, resource_id)
     * @param resourceType optional filter by resource type
     * @param limit        max results (default 50)
     * @return response map: { results: [...] }
     */
    public Map<String, Object> search(String query, String resourceType, int limit) throws SQLException {
        if (limit <= 0) limit = 50;

        List<String> whereClauses = new ArrayList<>();
        List<Object> params = new ArrayList<>();

        if (query != null && !query.isBlank()) {
            whereClauses.add("(action LIKE ? OR resource_type LIKE ? OR resource_id LIKE ?)");
            String like = "%" + query + "%";
            params.add(like);
            params.add(like);
            params.add(like);
        }
        if (resourceType != null && !resourceType.isBlank()) {
            whereClauses.add("resource_type = ?");
            params.add(resourceType);
        }

        String whereSql = whereClauses.isEmpty() ? "" : " WHERE " + String.join(" AND ", whereClauses);

        String sql = """
            SELECT id, timestamp, actor_id, actor_type, action, resource_type, resource_id,
                   old_value, new_value, why_chain_id, metadata
            FROM audit_log
            """ + whereSql + " ORDER BY timestamp DESC, id DESC LIMIT ?";

        List<Map<String, Object>> results = new ArrayList<>();
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            bindParams(ps, params);
            int idx = params.size() + 1;
            ps.setInt(idx, limit);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    results.add(mapRow(rs));
                }
            }
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("results", results);
        return response;
    }

    // ------------------------------------------------------------------
    // Immutability enforcement
    // ------------------------------------------------------------------

    /**
     * Attempt to update an audit log entry. This will always fail because the
     * table is append-only. In production, this would be enforced by database
     * permissions (no UPDATE/DELETE grants). Here we demonstrate the guard.
     *
     * @param logId the log entry ID
     * @throws UnsupportedOperationException always, to enforce immutability
     */
    public void updateLog(String logId) {
        throw new UnsupportedOperationException(
                "Audit log entries are immutable. UPDATE on log_id=" + logId + " is not permitted.");
    }

    /**
     * Attempt to delete an audit log entry. This will always fail.
     *
     * @param logId the log entry ID
     * @throws UnsupportedOperationException always, to enforce immutability
     */
    public void deleteLog(String logId) {
        throw new UnsupportedOperationException(
                "Audit log entries are immutable. DELETE on log_id=" + logId + " is not permitted.");
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private Map<String, Object> mapRow(ResultSet rs) throws SQLException {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("id", String.valueOf(rs.getLong("id")));
        row.put("timestamp", rs.getTimestamp("timestamp").toInstant().toString());
        row.put("actor_id", rs.getString("actor_id"));
        row.put("actor_type", rs.getString("actor_type"));
        row.put("action", rs.getString("action"));
        row.put("resource_type", rs.getString("resource_type"));
        row.put("resource_id", rs.getString("resource_id"));
        row.put("old_value", parseJson(rs.getString("old_value")));
        row.put("new_value", parseJson(rs.getString("new_value")));
        row.put("why_chain_id", rs.getString("why_chain_id"));
        row.put("metadata", parseJson(rs.getString("metadata")));
        return row;
    }

    private void bindParams(PreparedStatement ps, List<Object> params) throws SQLException {
        for (int i = 0; i < params.size(); i++) {
            Object p = params.get(i);
            if (p instanceof Timestamp ts) {
                ps.setTimestamp(i + 1, ts);
            } else if (p instanceof String s) {
                ps.setString(i + 1, s);
            } else if (p instanceof Integer i2) {
                ps.setInt(i + 1, i2);
            } else if (p instanceof Long l) {
                ps.setLong(i + 1, l);
            } else {
                ps.setObject(i + 1, p);
            }
        }
    }

    private String toJsonString(JsonNode node) {
        if (node == null || node instanceof MissingNode || node instanceof NullNode) {
            return null;
        }
        return node.toString();
    }

    private JsonNode parseJson(String json) {
        if (json == null || json.isBlank()) {
            return NullNode.getInstance();
        }
        try {
            return objectMapper.readTree(json);
        } catch (JsonProcessingException e) {
            return new TextNode(json);
        }
    }

    @Override
    public void close() throws SQLException {
        if (connection != null && !connection.isClosed()) {
            connection.close();
        }
    }

    // ------------------------------------------------------------------
    // Convenience: build a JsonNode from a Map (for callers)
    // ------------------------------------------------------------------

    public static JsonNode toJsonNode(Map<String, Object> map) {
        if (map == null) return NullNode.getInstance();
        ObjectMapper om = new ObjectMapper();
        return om.valueToTree(map);
    }

    public static JsonNode toJsonNode(Object obj) {
        if (obj == null) return NullNode.getInstance();
        ObjectMapper om = new ObjectMapper();
        return om.valueToTree(obj);
    }
}

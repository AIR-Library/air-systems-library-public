import java.sql.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class FeatureFlags {
    public interface Store {
        Flag getFlag(String key);
        void setFlag(Flag flag);
        List<Audit> getAudits();

        /**
         * Appends one flag_audit row. In: flag key, action, old and new value, actor id. Out: none.
         * Why: FLAG-08 "set_flag writes an audit row" for EVERY store (it used to be written for the in-memory store
         * only); 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store (database for SqlStore).
         */
        void addAudit(String flagKey, String action, String oldValue, String newValue, String actorId);
    }

    public static class Flag {
        public String key;
        public String type;
        public String defaultValue;
        public boolean enabled;
        public String rules;
        public long updatedAt;
        public String updatedBy;

        public Flag(String key, String type, String defaultValue, boolean enabled, String rules, long updatedAt, String updatedBy) {
            this.key = key;
            this.type = type;
            this.defaultValue = defaultValue;
            this.enabled = enabled;
            this.rules = rules;
            this.updatedAt = updatedAt;
            this.updatedBy = updatedBy;
        }
    }

    public static class Audit {
        public long id;
        public String flagKey;
        public String action;
        public String oldValue;
        public String newValue;
        public String actorId;
        public long at;

        public Audit(long id, String flagKey, String action, String oldValue, String newValue, String actorId, long at) {
            this.id = id;
            this.flagKey = flagKey;
            this.action = action;
            this.oldValue = oldValue;
            this.newValue = newValue;
            this.actorId = actorId;
            this.at = at;
        }
    }

    public static class InMemoryStore implements Store {
        private final Map<String, Flag> flags = new HashMap<>();
        private final List<Audit> audits = new ArrayList<>();
        private long auditId = 0;

        @Override
        public synchronized Flag getFlag(String key) {
            return flags.get(key);
        }

        @Override
        public synchronized void setFlag(Flag flag) {
            flags.put(flag.key, flag);
        }

        @Override
        public synchronized void addAudit(String flagKey, String action, String oldValue, String newValue, String actorId) {
            audits.add(new Audit(++auditId, flagKey, action, oldValue, newValue, actorId, System.currentTimeMillis()));
        }

        @Override
        public synchronized List<Audit> getAudits() {
            return new ArrayList<>(audits);
        }
    }

    public static class SqlStore implements Store {
        private final String jdbcUrl;

        public SqlStore(String jdbcUrl) {
            this.jdbcUrl = jdbcUrl;
        }

        @Override
        public Flag getFlag(String key) {
            try (Connection conn = DriverManager.getConnection(jdbcUrl)) {
                PreparedStatement stmt = conn.prepareStatement("SELECT * FROM feature_flags WHERE key = ?");
                stmt.setString(1, key);
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    return new Flag(
                        rs.getString("key"),
                        rs.getString("type"),
                        rs.getString("default_value"),
                        rs.getBoolean("enabled"),
                        rs.getString("rules"),
                        rs.getLong("updated_at"),
                        rs.getString("updated_by")
                    );
                }
            } catch (SQLException e) {
                // Return null on error
            }
            return null;
        }

        @Override
        public void setFlag(Flag flag) {
            try (Connection conn = DriverManager.getConnection(jdbcUrl)) {
                PreparedStatement stmt = conn.prepareStatement(
                    "INSERT OR REPLACE INTO feature_flags (key, type, default_value, enabled, rules, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?)"
                );
                stmt.setString(1, flag.key);
                stmt.setString(2, flag.type);
                stmt.setString(3, flag.defaultValue);
                stmt.setBoolean(4, flag.enabled);
                stmt.setString(5, flag.rules);
                stmt.setLong(6, flag.updatedAt);
                stmt.setString(7, flag.updatedBy);
                stmt.executeUpdate();
            } catch (SQLException e) {
                throw new IllegalStateException("could not save flag", e);
            }
        }

        /** See {@link Store#addAudit}. Parameterized INSERT into flag_audit; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database. */
        @Override
        public void addAudit(String flagKey, String action, String oldValue, String newValue, String actorId) {
            try (Connection conn = DriverManager.getConnection(jdbcUrl);
                 PreparedStatement stmt = conn.prepareStatement(
                     "INSERT INTO flag_audit (flag_key, action, old_value, new_value, actor_id, at) VALUES (?, ?, ?, ?, ?, ?)")) {
                stmt.setString(1, flagKey);
                stmt.setString(2, action);
                stmt.setString(3, oldValue);
                stmt.setString(4, newValue);
                stmt.setString(5, actorId);
                stmt.setLong(6, System.currentTimeMillis());
                stmt.executeUpdate();
            } catch (SQLException e) {
                throw new IllegalStateException("could not write flag audit", e);
            }
        }

        @Override
        public List<Audit> getAudits() {
            List<Audit> result = new ArrayList<>();
            try (Connection conn = DriverManager.getConnection(jdbcUrl)) {
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery("SELECT * FROM flag_audit");
                while (rs.next()) {
                    result.add(new Audit(
                        rs.getLong("id"),
                        rs.getString("flag_key"),
                        rs.getString("action"),
                        rs.getString("old_value"),
                        rs.getString("new_value"),
                        rs.getString("actor_id"),
                        rs.getLong("at")
                    ));
                }
            } catch (SQLException e) {
                // Return empty list on error
            }
            return result;
        }
    }

    private final Store store;

    public FeatureFlags(Store store) {
        this.store = store;
    }

    /**
     * Rollout bucket: the first 8 bytes of SHA-256(input) as an UNSIGNED big-endian integer, mod 100.
     * In: flag_key + ":" + targeting_key. Out: 0..99.
     * Why: FLAG-05 / spec "stable_hash is a FIXED algorithm ... and ONLY that". 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP: the old code took a SIGNED remainder (negative buckets, so a 30% rollout
     * served about 65%) and fell back to FNV-1a, which the spec forbids. Touches: nothing.
     */
    public static int stableHash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(input.getBytes(StandardCharsets.UTF_8));
            long value = 0;
            for (int i = 0; i < 8; i++) {
                value = (value << 8) | (hashBytes[i] & 0xFF);
            }
            return (int) Long.remainderUnsigned(value, 100);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required for stable rollout buckets", e);
        }
    }

    public static class EvaluationDetails {
        public String flagKey;
        public Object value;
        public String variant;
        public String reason;
        public String errorCode;
        public String errorMessage;

        public EvaluationDetails(String flagKey, Object value, String variant, String reason, String errorCode, String errorMessage) {
            this.flagKey = flagKey;
            this.value = value;
            this.variant = variant;
            this.reason = reason;
            this.errorCode = errorCode;
            this.errorMessage = errorMessage;
        }
    }

    /**
     * Evaluates a flag; never throws (OpenFeature). In: key, the caller's default, context, the method's type.
     * Out: details {value, variant, reason, error_code}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: strict rules
     * parsing (PARSE_ERROR), served-value type check (TYPE_MISMATCH), numeric rollout percentages, null context.
     * Touches: reads the store.
     */
    @SuppressWarnings("unchecked")
    private EvaluationDetails evaluate(String flagKey, Object defaultValue, Map<String, Object> context, String expectedType) {
        try {
            Flag flag = store.getFlag(flagKey);
            if (flag == null) {
                return new EvaluationDetails(flagKey, defaultValue, null, "ERROR", "FLAG_NOT_FOUND", "Flag not found");
            }

            if (!flag.enabled) {
                return new EvaluationDetails(flagKey, defaultValue, null, "DISABLED", null, null);
            }

            if (!flag.type.equals(expectedType)) {
                return new EvaluationDetails(flagKey, defaultValue, null, "ERROR", "TYPE_MISMATCH", "Type mismatch");
            }

            // Parse rules
            List<Map<String, Object>> rules = parseRules(flag.rules);
            if (context == null) {
                context = Collections.emptyMap();
            }
            if (rules == null) {
                return new EvaluationDetails(flagKey, defaultValue, null, "ERROR", "PARSE_ERROR", "Bad rules");
            }

            Object tk = context.get("targeting_key");
            if (tk == null) {
                tk = context.get("user_id");
            }
            String targetingKey = tk == null ? null : String.valueOf(tk);

            for (Map<String, Object> rule : rules) {
                List<Map<String, Object>> conditions = (List<Map<String, Object>>) rule.getOrDefault("conditions", new ArrayList<>());
                boolean allMatch = true;
                for (Map<String, Object> condition : conditions) {
                    String attribute = (String) condition.get("attribute");
                    String operator = (String) condition.get("operator");
                    Object value = condition.get("value");
                    Object contextValue = context.get(attribute);

                    if (!matchCondition(contextValue, operator, value)) {
                        allMatch = false;
                        break;
                    }
                }

                if (allMatch) {
                    Map<String, Object> rollout = (Map<String, Object>) rule.get("rollout");
                    if (rollout == null) {
                        // No rollout - serve value
                        if (!valueHasType(rule.get("value"), expectedType)) {
                            return new EvaluationDetails(flagKey, defaultValue, null, "ERROR", "TYPE_MISMATCH", "Served value has the wrong type");
                        }
                        return new EvaluationDetails(flagKey, rule.get("value"), (String) rule.get("variant"), "TARGETING_MATCH", null, null);
                    } else {
                        // Rollout
                        double percentage = ((Number) rollout.get("percentage")).doubleValue();
                        if (targetingKey != null) {
                            int bucket = stableHash(flagKey + ":" + targetingKey);
                            if (bucket < percentage) {
                                if (!valueHasType(rule.get("value"), expectedType)) {
                                    return new EvaluationDetails(flagKey, defaultValue, null, "ERROR", "TYPE_MISMATCH", "Served value has the wrong type");
                                }
                                return new EvaluationDetails(flagKey, rule.get("value"), (String) rule.get("variant"), "SPLIT", null, null);
                            }
                        }
                        // Does not apply, continue to next rule
                    }
                }
            }

            // No rule applied - return default
            return new EvaluationDetails(flagKey, parseValue(flag.defaultValue, expectedType), null, "DEFAULT", null, null);
        } catch (Exception e) {
            return new EvaluationDetails(flagKey, defaultValue, null, "ERROR", "GENERAL", e.getMessage());
        }
    }

    private boolean matchCondition(Object contextValue, String operator, Object ruleValue) {
        if (contextValue == null) {
            return false;
        }

        switch (operator) {
            case "equals":
                return contextValue.equals(ruleValue);
            case "not_equals":
                return !contextValue.equals(ruleValue);
            case "in_list":
                if (ruleValue instanceof List) {
                    return ((List<?>) ruleValue).contains(contextValue);
                }
                return false;
            case "ends_with":
                if (contextValue instanceof String && ruleValue instanceof String) {
                    return ((String) contextValue).endsWith((String) ruleValue);
                }
                return false;
            default:
                return false;
        }
    }

    private static final com.fasterxml.jackson.databind.ObjectMapper JSON = new com.fasterxml.jackson.databind.ObjectMapper();

    /**
     * Parses and validates the rules JSON (the one shape in the spec: a list of {conditions, variant, value, rollout}).
     * In: the stored rules text (null or blank = no rules). Out: the rules, or null when the text is not valid JSON or
     * not that shape (the caller then answers PARSE_ERROR). Why: FLAG-07; the hand-written parser it replaces accepted
     * "not valid json" as an empty rule list and could not read in_list values or escaped strings.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing (pure).
     */
    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> parseRules(String rulesJson) {
        if (rulesJson == null || rulesJson.trim().isEmpty()) {
            return new ArrayList<>();
        }
        try {
            Object parsed = JSON.readValue(rulesJson, Object.class);
            if (!(parsed instanceof List)) {
                return null;
            }
            List<Map<String, Object>> rules = new ArrayList<>();
            for (Object r : (List<Object>) parsed) {
                if (!(r instanceof Map)) {
                    return null;
                }
                Map<String, Object> rule = (Map<String, Object>) r;
                Object conds = rule.getOrDefault("conditions", new ArrayList<>());
                if (!(conds instanceof List)) {
                    return null;
                }
                for (Object c : (List<Object>) conds) {
                    if (!(c instanceof Map) || !(((Map<String, Object>) c).get("attribute") instanceof String)
                            || !(((Map<String, Object>) c).get("operator") instanceof String)) {
                        return null;
                    }
                }
                Object rollout = rule.get("rollout");
                if (rollout != null && !(rollout instanceof Map && ((Map<String, Object>) rollout).get("percentage") instanceof Number)) {
                    return null;
                }
                if (rule.get("variant") != null && !(rule.get("variant") instanceof String)) {
                    return null;
                }
                rules.add(rule);
            }
            return rules;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * True when a served rule value has the flag's declared type. In: value, type. Out: boolean.
     * Why: spec "A served value whose type is not the flag's type -> caller's default, TYPE_MISMATCH";
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static boolean valueHasType(Object value, String type) {
        switch (type) {
            case "boolean": return value instanceof Boolean;
            case "string": return value instanceof String;
            case "number": return value instanceof Number;
            case "object": return value instanceof Map || value instanceof List;
            default: return false;
        }
    }

    private Object parseValue(String value, String type) {
        if (value == null) return null;
        switch (type) {
            case "boolean":
                return Boolean.parseBoolean(value);
            case "string":
                return value;
            case "number":
                try {
                    return Double.parseDouble(value);
                } catch (NumberFormatException e) {
                    return 0;
                }
            case "object":
                return value; // Return as string representation
            default:
                return value;
        }
    }

    public boolean getBooleanValue(String flagKey, boolean defaultValue, Map<String, Object> context) {
        EvaluationDetails details = evaluate(flagKey, defaultValue, context, "boolean");
        if (details.value instanceof Boolean) {
            return (Boolean) details.value;
        }
        return defaultValue;
    }

    public String getStringValue(String flagKey, String defaultValue, Map<String, Object> context) {
        EvaluationDetails details = evaluate(flagKey, defaultValue, context, "string");
        if (details.value instanceof String) {
            return (String) details.value;
        }
        return defaultValue;
    }

    public double getNumberValue(String flagKey, double defaultValue, Map<String, Object> context) {
        EvaluationDetails details = evaluate(flagKey, defaultValue, context, "number");
        if (details.value instanceof Number) {
            return ((Number) details.value).doubleValue();
        }
        return defaultValue;
    }

    public Object getObjectValue(String flagKey, Object defaultValue, Map<String, Object> context) {
        EvaluationDetails details = evaluate(flagKey, defaultValue, context, "object");
        return details.value;
    }

    public EvaluationDetails getBooleanDetails(String flagKey, boolean defaultValue, Map<String, Object> context) {
        return evaluate(flagKey, defaultValue, context, "boolean");
    }

    public EvaluationDetails getStringDetails(String flagKey, String defaultValue, Map<String, Object> context) {
        return evaluate(flagKey, defaultValue, context, "string");
    }

    public EvaluationDetails getNumberDetails(String flagKey, double defaultValue, Map<String, Object> context) {
        return evaluate(flagKey, defaultValue, context, "number");
    }

    public EvaluationDetails getObjectDetails(String flagKey, Object defaultValue, Map<String, Object> context) {
        return evaluate(flagKey, defaultValue, context, "object");
    }

    /**
     * set_flag: stores the flag and writes one audit row with the old and new default value, for every store.
     * In: actor id, key, type, default value (text), enabled, rules JSON. Out: none.
     * Why: FLAG-08; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (audit used to be skipped for SqlStore).
     * Touches: the store (database for SqlStore).
     */
    public void setFlag(String actor, String key, String type, String defaultValue, boolean enabled, String rules) {
        Flag existing = store.getFlag(key);
        String oldValue = existing != null ? existing.defaultValue : null;
        
        Flag newFlag = new Flag(key, type, defaultValue, enabled, rules, System.currentTimeMillis(), actor);
        store.setFlag(newFlag);
        
        store.addAudit(key, "set", oldValue, defaultValue, actor);
    }
}
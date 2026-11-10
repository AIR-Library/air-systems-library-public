import java.util.*;

public class FeatureFlagsTests {
    private static int passed = 0;
    private static int failed = 0;

    /**
     * Fails the test with msg unless cond holds. Why: the tests used Java `assert`, which the runner never enables
     * (no -ea), so no assertion ran; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static void check(boolean cond, String msg) {
        if (!cond) {
            throw new AssertionError(msg);
        }
    }

    public static void main(String[] args) {
        testUnknownFlagReturnsDefault();
        testTypeMismatch();
        testDisabledFlag();
        testMatchingRule();
        testRolloutDeterministic();
        testRolloutFallsThrough();
        testCorruptRules();
        testSetFlagAudit();

        System.out.println("Passed: " + passed + ", Failed: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    // FLAG-01
    private static void testUnknownFlagReturnsDefault() {
        try {
            FeatureFlags.InMemoryStore store = new FeatureFlags.InMemoryStore();
            FeatureFlags ff = new FeatureFlags(store);
            Map<String, Object> context = new HashMap<>();
            context.put("targeting_key", "user1");
            
            boolean result = ff.getBooleanValue("nonexistent", true, context);
            FeatureFlags.EvaluationDetails details = ff.getBooleanDetails("nonexistent", true, context);
            
            check(result == true, "Expected default true");
            check(details.reason.equals("ERROR"), "Expected ERROR reason");
            check(details.errorCode.equals("FLAG_NOT_FOUND"), "Expected FLAG_NOT_FOUND");
            
            passed++;
        } catch (Throwable e) {
            failed++;
            System.out.println("testUnknownFlagReturnsDefault FAILED: " + e.getMessage());
        }
    }

    // FLAG-02
    private static void testTypeMismatch() {
        try {
            FeatureFlags.InMemoryStore store = new FeatureFlags.InMemoryStore();
            FeatureFlags ff = new FeatureFlags(store);
            
            // Set a boolean flag
            ff.setFlag("admin", "myflag", "boolean", "true", true, "[]");
            
            Map<String, Object> context = new HashMap<>();
            context.put("targeting_key", "user1");
            
            // Try to get as string
            String result = ff.getStringValue("myflag", "default", context);
            FeatureFlags.EvaluationDetails details = ff.getStringDetails("myflag", "default", context);
            
            check(result.equals("default"), "Expected default");
            check(details.reason.equals("ERROR"), "Expected ERROR reason");
            check(details.errorCode.equals("TYPE_MISMATCH"), "Expected TYPE_MISMATCH");
            
            passed++;
        } catch (Throwable e) {
            failed++;
            System.out.println("testTypeMismatch FAILED: " + e.getMessage());
        }
    }

    // FLAG-03
    private static void testDisabledFlag() {
        try {
            FeatureFlags.InMemoryStore store = new FeatureFlags.InMemoryStore();
            FeatureFlags ff = new FeatureFlags(store);
            
            // Set a disabled flag
            ff.setFlag("admin", "myflag", "boolean", "true", false, "[]");
            
            Map<String, Object> context = new HashMap<>();
            context.put("targeting_key", "user1");
            
            boolean result = ff.getBooleanValue("myflag", false, context);
            FeatureFlags.EvaluationDetails details = ff.getBooleanDetails("myflag", false, context);
            
            check(result == false, "Expected default false");
            check(details.reason.equals("DISABLED"), "Expected DISABLED reason");
            
            passed++;
        } catch (Throwable e) {
            failed++;
            System.out.println("testDisabledFlag FAILED: " + e.getMessage());
        }
    }

    // FLAG-04
    private static void testMatchingRule() {
        try {
            FeatureFlags.InMemoryStore store = new FeatureFlags.InMemoryStore();
            FeatureFlags ff = new FeatureFlags(store);
            
            // Rule that matches users with email ending in @acme.com
            String rules = "[{\"conditions\":[{\"attribute\":\"email\",\"operator\":\"ends_with\",\"value\":\"@acme.com\"}],\"variant\":\"on\",\"value\":true,\"rollout\":null}]";
            ff.setFlag("admin", "myflag", "boolean", "false", true, rules);
            
            Map<String, Object> context = new HashMap<>();
            context.put("targeting_key", "user1");
            context.put("email", "user@acme.com");
            
            boolean result = ff.getBooleanValue("myflag", false, context);
            FeatureFlags.EvaluationDetails details = ff.getBooleanDetails("myflag", false, context);
            
            check(result == true, "Expected true");
            check(details.reason.equals("TARGETING_MATCH"), "Expected TARGETING_MATCH");
            check(details.variant.equals("on"), "Expected variant 'on'");
            
            // Non-matching user
            Map<String, Object> context2 = new HashMap<>();
            context2.put("targeting_key", "user2");
            context2.put("email", "user@other.com");
            
            boolean result2 = ff.getBooleanValue("myflag", false, context2);
            check(result2 == false, "Expected default false for non-matching");
            
            passed++;
        } catch (Throwable e) {
            failed++;
            System.out.println("testMatchingRule FAILED: " + e.getMessage());
        }
    }

    // FLAG-05
    private static void testRolloutDeterministic() {
        try {
            FeatureFlags.InMemoryStore store = new FeatureFlags.InMemoryStore();
            FeatureFlags ff = new FeatureFlags(store);
            
            // 30% rollout
            String rules = "[{\"conditions\":[],\"variant\":\"beta\",\"value\":true,\"rollout\":{\"percentage\":30}}]";
            ff.setFlag("admin", "myflag", "boolean", "false", true, rules);
            
            // Same key gives same answer
            Map<String, Object> context1 = new HashMap<>();
            context1.put("targeting_key", "user1");
            boolean result1 = ff.getBooleanValue("myflag", false, context1);
            boolean result2 = ff.getBooleanValue("myflag", false, context1);
            check(result1 == result2, "Same key should give same result");
            
            // Count over 10,000 keys
            int trueCount = 0;
            for (int i = 0; i < 10000; i++) {
                Map<String, Object> context = new HashMap<>();
                context.put("targeting_key", "user" + i);
                if (ff.getBooleanValue("myflag", false, context)) {
                    trueCount++;
                }
            }
            
            double percentage = (double) trueCount / 10000 * 100;
            check(percentage >= 25 && percentage <= 35, "Expected 25-35%, got " + percentage + "%");
            
            passed++;
        } catch (Throwable e) {
            failed++;
            System.out.println("testRolloutDeterministic FAILED: " + e.getMessage());
        }
    }

    // FLAG-06
    private static void testRolloutFallsThrough() {
        try {
            FeatureFlags.InMemoryStore store = new FeatureFlags.InMemoryStore();
            FeatureFlags ff = new FeatureFlags(store);
            
            // First rule: 30% rollout, second rule: always true
            String rules = "[{\"conditions\":[],\"variant\":\"beta\",\"value\":true,\"rollout\":{\"percentage\":30}}," +
                          "{\"conditions\":[],\"variant\":\"always\",\"value\":true,\"rollout\":null}]";
            ff.setFlag("admin", "myflag", "boolean", "false", true, rules);
            
            // Find a key that falls through the first rule (bucket >= 30)
            String fallthroughKey = null;
            for (int i = 0; i < 1000; i++) {
                String key = "user" + i;
                Map<String, Object> context = new HashMap<>();
                context.put("targeting_key", key);
                int bucket = FeatureFlags.stableHash("myflag:" + key);
                if (bucket >= 30) {
                    fallthroughKey = key;
                    break;
                }
            }
            
            check(fallthroughKey != null, "Could not find a fallthrough key");
            
            Map<String, Object> context = new HashMap<>();
            context.put("targeting_key", fallthroughKey);
            FeatureFlags.EvaluationDetails details = ff.getBooleanDetails("myflag", false, context);
            
            // Should fall through to second rule
            check(details.reason.equals("TARGETING_MATCH"), "Expected TARGETING_MATCH from second rule");
            check(details.variant.equals("always"), "Expected variant 'always'");
            
            passed++;
        } catch (Throwable e) {
            failed++;
            System.out.println("testRolloutFallsThrough FAILED: " + e.getMessage());
        }
    }

    // FLAG-07
    private static void testCorruptRules() {
        try {
            FeatureFlags.InMemoryStore store = new FeatureFlags.InMemoryStore();
            FeatureFlags ff = new FeatureFlags(store);
            
            // Corrupt rules JSON
            ff.setFlag("admin", "myflag", "boolean", "true", true, "not valid json");
            
            Map<String, Object> context = new HashMap<>();
            context.put("targeting_key", "user1");
            
            boolean result = ff.getBooleanValue("myflag", false, context);
            FeatureFlags.EvaluationDetails details = ff.getBooleanDetails("myflag", false, context);
            
            check(result == false, "Expected default false");
            check(details.reason.equals("ERROR"), "Expected ERROR reason");
            check(details.errorCode.equals("PARSE_ERROR"), "Expected PARSE_ERROR");
            
            passed++;
        } catch (Throwable e) {
            failed++;
            System.out.println("testCorruptRules FAILED: " + e.getMessage());
        }
    }

    // FLAG-08
    private static void testSetFlagAudit() {
        try {
            FeatureFlags.InMemoryStore store = new FeatureFlags.InMemoryStore();
            FeatureFlags ff = new FeatureFlags(store);
            
            // Set flag initially
            ff.setFlag("admin", "myflag", "boolean", "true", true, "[]");
            
            // Update flag
            ff.setFlag("admin", "myflag", "boolean", "false", true, "[]");
            
            List<FeatureFlags.Audit> audits = store.getAudits();
            check(audits.size() == 2, "Expected 2 audit records, got " + audits.size());
            
            FeatureFlags.Audit first = audits.get(0);
            check(first.flagKey.equals("myflag"), "Expected flag key 'myflag'");
            check(first.action.equals("set"), "Expected action 'set'");
            check(first.oldValue == null, "Expected null old value for first set");
            check(first.newValue.equals("true"), "Expected new value 'true'");
            
            FeatureFlags.Audit second = audits.get(1);
            check(second.oldValue.equals("true"), "Expected old value 'true'");
            check(second.newValue.equals("false"), "Expected new value 'false'");
            
            passed++;
        } catch (Throwable e) {
            failed++;
            System.out.println("testSetFlagAudit FAILED: " + e.getMessage());
        }
    }
}
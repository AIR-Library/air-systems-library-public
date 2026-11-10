import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;
import java.util.concurrent.atomic.AtomicInteger;

public final class HealthCheckerTests {
    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        runTest("testAllChecksPassReturns200Pass", HealthCheckerTests::testAllChecksPassReturns200Pass);
        runTest("testCriticalCheckFailsReturns503Fail", HealthCheckerTests::testCriticalCheckFailsReturns503Fail);
        runTest("testOnlyNonCriticalFailsReturns200Warn", HealthCheckerTests::testOnlyNonCriticalFailsReturns200Warn);
        runTest("testSlowCheckPastTimeoutFailsThatCheck", HealthCheckerTests::testSlowCheckPastTimeoutFailsThatCheck);
        runTest("testLivenessPassesWhenDependencyWouldFail", HealthCheckerTests::testLivenessPassesWhenDependencyWouldFail);
        runTest("testOutputContainsNoConnectionString", HealthCheckerTests::testOutputContainsNoConnectionString);
        runTest("testZeroChecksIsPassWithEmptyChecksObject", HealthCheckerTests::testZeroChecksIsPassWithEmptyChecksObject);
        runTest("testMetadataInFixedOrder", HealthCheckerTests::testMetadataInFixedOrder);
        runTest("testChecksSortedByWholeKeyOrdinal", HealthCheckerTests::testChecksSortedByWholeKeyOrdinal);
        runTest("testEachCheckHasItsOwnDeadline", HealthCheckerTests::testEachCheckHasItsOwnDeadline);
        runTest("testInvalidRegistrationsAreRejected", HealthCheckerTests::testInvalidRegistrationsAreRejected);
        runTest("testFastCheckAfterSlowOneIsNotTimedOut", HealthCheckerTests::testFastCheckAfterSlowOneIsNotTimedOut);

        System.out.println("=== SUMMARY ===");
        System.out.println("Passed: " + passed);
        System.out.println("Failed: " + failed);
        System.exit(failed > 0 ? 1 : 0);
    }

    private static void runTest(String name, Runnable test) {
        try {
            test.run();
            passed++;
            System.out.println("PASS: " + name);
        } catch (AssertionError e) {
            failed++;
            System.out.println("FAIL: " + name + " - " + e.getMessage());
        } catch (Throwable e) {
            failed++;
            System.out.println("FAIL: " + name + " - " + e.getClass().getName() + ": " + e.getMessage());
        }
    }

    private static void assertEquals(String expected, String actual, String msg) {
        if (!expected.equals(actual)) throw new AssertionError(msg + " expected: " + expected + " actual: " + actual);
    }

    private static void assertEquals(int expected, int actual, String msg) {
        if (expected != actual) throw new AssertionError(msg + " expected: " + expected + " actual: " + actual);
    }

    private static void assertTrue(boolean condition, String msg) {
        if (!condition) throw new AssertionError(msg);
    }

    private static void assertFalse(boolean condition, String msg) {
        if (condition) throw new AssertionError(msg);
    }

    private static HealthChecker.InMemoryCheckStore newStore() {
        return new HealthChecker.InMemoryCheckStore();
    }

    private static HealthChecker newChecker(HealthChecker.CheckStore store, LongSupplier clock) {
        HealthChecker.HealthOptions opts = new HealthChecker.HealthOptions();
        opts.clock = clock;
        return new HealthChecker(store, opts);
    }

    private static final long FIXED_CLOCK_MS = 1767225600000L;
    private static final String FIXED_TIME = "2026-01-01T00:00:00Z";

    // HEALTH-01
    static void testAllChecksPassReturns200Pass() {
        HealthChecker.InMemoryCheckStore store = newStore();
        HealthChecker checker = newChecker(store, () -> FIXED_CLOCK_MS);
        checker.registerCheck("db", "datastore", () -> true, true, 5000);
        checker.registerCheck("cache", "component", () -> true, false, 5000);
        HealthChecker.HealthResponse resp = checker.readiness();
        assertEquals(200, resp.httpStatus(), "http_status");
        assertEquals("application/health+json", resp.contentType(), "content_type");
        String expected = "{\"status\":\"pass\",\"checks\":{\"cache:responseTime\":[{\"componentId\":\"cache\",\"componentType\":\"component\",\"observedValue\":0,\"observedUnit\":\"ms\",\"status\":\"pass\",\"time\":\"" + FIXED_TIME + "\"}],\"db:responseTime\":[{\"componentId\":\"db\",\"componentType\":\"datastore\",\"observedValue\":0,\"observedUnit\":\"ms\",\"status\":\"pass\",\"time\":\"" + FIXED_TIME + "\"}]}}";
        assertEquals(expected, resp.body(), "body");
    }

    // HEALTH-02
    static void testCriticalCheckFailsReturns503Fail() {
        HealthChecker.InMemoryCheckStore store = newStore();
        HealthChecker checker = newChecker(store, () -> FIXED_CLOCK_MS);
        checker.registerCheck("db", "datastore", () -> false, true, 5000);
        checker.registerCheck("cache", "component", () -> true, false, 5000);
        HealthChecker.HealthResponse resp = checker.readiness();
        assertEquals(503, resp.httpStatus(), "http_status");
        assertEquals("application/health+json", resp.contentType(), "content_type");
        String expected = "{\"status\":\"fail\",\"checks\":{\"cache:responseTime\":[{\"componentId\":\"cache\",\"componentType\":\"component\",\"observedValue\":0,\"observedUnit\":\"ms\",\"status\":\"pass\",\"time\":\"" + FIXED_TIME + "\"}],\"db:responseTime\":[{\"componentId\":\"db\",\"componentType\":\"datastore\",\"observedValue\":0,\"observedUnit\":\"ms\",\"status\":\"fail\",\"time\":\"" + FIXED_TIME + "\",\"output\":\"check reported failure\"}]}}";
        assertEquals(expected, resp.body(), "body");
    }

    // HEALTH-03
    static void testOnlyNonCriticalFailsReturns200Warn() {
        HealthChecker.InMemoryCheckStore store = newStore();
        HealthChecker checker = newChecker(store, () -> FIXED_CLOCK_MS);
        checker.registerCheck("db", "datastore", () -> true, true, 5000);
        checker.registerCheck("cache", "component", () -> false, false, 5000);
        HealthChecker.HealthResponse resp = checker.readiness();
        assertEquals(200, resp.httpStatus(), "http_status");
        assertEquals("application/health+json", resp.contentType(), "content_type");
        String expected = "{\"status\":\"warn\",\"checks\":{\"cache:responseTime\":[{\"componentId\":\"cache\",\"componentType\":\"component\",\"observedValue\":0,\"observedUnit\":\"ms\",\"status\":\"fail\",\"time\":\"" + FIXED_TIME + "\",\"output\":\"check reported failure\"}],\"db:responseTime\":[{\"componentId\":\"db\",\"componentType\":\"datastore\",\"observedValue\":0,\"observedUnit\":\"ms\",\"status\":\"pass\",\"time\":\"" + FIXED_TIME + "\"}]}}";
        assertEquals(expected, resp.body(), "body");
    }

    // HEALTH-04
    static void testSlowCheckPastTimeoutFailsThatCheck() {
        HealthChecker.InMemoryCheckStore store = newStore();
        HealthChecker checker = newChecker(store, () -> FIXED_CLOCK_MS);
        checker.registerCheck("fast", "component", () -> true, false, 5000);
        checker.registerCheck("slow", "component", () -> { Thread.sleep(1000); return true; }, true, 100);
        HealthChecker.HealthResponse resp = checker.readiness();
        assertEquals(503, resp.httpStatus(), "http_status");
        assertEquals("application/health+json", resp.contentType(), "content_type");
        String expected = "{\"status\":\"fail\",\"checks\":{\"fast:responseTime\":[{\"componentId\":\"fast\",\"componentType\":\"component\",\"observedValue\":0,\"observedUnit\":\"ms\",\"status\":\"pass\",\"time\":\"" + FIXED_TIME + "\"}],\"slow:responseTime\":[{\"componentId\":\"slow\",\"componentType\":\"component\",\"observedValue\":100,\"observedUnit\":\"ms\",\"status\":\"fail\",\"time\":\"" + FIXED_TIME + "\",\"output\":\"check timed out\"}]}}";
        assertEquals(expected, resp.body(), "body");
    }

    // HEALTH-05
    static void testLivenessPassesWhenDependencyWouldFail() {
        HealthChecker.InMemoryCheckStore store = newStore();
        AtomicInteger counter = new AtomicInteger(0);
        HealthChecker checker = newChecker(store, () -> FIXED_CLOCK_MS);
        checker.registerCheck("db", "datastore", () -> { counter.incrementAndGet(); throw new RuntimeException("fail"); }, true, 5000);
        HealthChecker.HealthResponse live = checker.liveness();
        assertEquals(200, live.httpStatus(), "liveness http_status");
        assertEquals("application/health+json", live.contentType(), "liveness content_type");
        assertEquals("{\"status\":\"pass\"}", live.body(), "liveness body");
        assertEquals(0, counter.get(), "counter before readiness");
        HealthChecker.HealthResponse ready = checker.readiness();
        assertEquals(503, ready.httpStatus(), "readiness http_status");
        assertEquals(1, counter.get(), "counter after readiness");
    }

    // HEALTH-06
    static void testOutputContainsNoConnectionString() {
        HealthChecker.InMemoryCheckStore store = newStore();
        HealthChecker checker = newChecker(store, () -> FIXED_CLOCK_MS);
        String dsn = "postgres://admin:s3cret@db.internal:5432/app";
        checker.registerCheck("db", "datastore", () -> { throw new RuntimeException("connect failed: " + dsn); }, true, 5000);
        HealthChecker.HealthResponse resp = checker.readiness();
        assertEquals(503, resp.httpStatus(), "http_status");
        String body = resp.body();
        assertEquals("{\"status\":\"fail\",\"checks\":{\"db:responseTime\":[{\"componentId\":\"db\",\"componentType\":\"datastore\",\"observedValue\":0,\"observedUnit\":\"ms\",\"status\":\"fail\",\"time\":\"" + FIXED_TIME + "\",\"output\":\"check raised an error\"}]}}", body, "body");
        assertFalse(body.contains("postgres://"), "no postgres:// in body");
        assertFalse(body.contains("s3cret"), "no s3cret in body");
        assertFalse(body.contains("admin"), "no admin in body");
        assertFalse(body.contains("5432"), "no 5432 in body");

        try {
            checker.registerCheck("postgres://admin:s3cret@db", "datastore", () -> true, true, 5000);
            throw new AssertionError("expected INVALID_COMPONENT_ID");
        } catch (HealthChecker.HealthCheckError e) {
            assertEquals("INVALID_COMPONENT_ID", e.getCode(), "error code");
            assertFalse(e.getMessage().contains("s3cret"), "error message no secret");
        }
    }

    static void testZeroChecksIsPassWithEmptyChecksObject() {
        HealthChecker.InMemoryCheckStore store = newStore();
        HealthChecker checker = newChecker(store, () -> FIXED_CLOCK_MS);
        HealthChecker.HealthResponse live = checker.liveness();
        assertEquals("{\"status\":\"pass\"}", live.body(), "liveness body");
        HealthChecker.HealthResponse ready = checker.readiness();
        assertEquals(200, ready.httpStatus(), "readiness http_status");
        assertEquals("{\"status\":\"pass\",\"checks\":{}}", ready.body(), "readiness body");
    }

    static void testMetadataInFixedOrder() {
        HealthChecker.InMemoryCheckStore store = newStore();
        HealthChecker.HealthOptions opts = new HealthChecker.HealthOptions();
        opts.clock = () -> FIXED_CLOCK_MS;
        opts.version = "1.2.2";
        opts.serviceId = "billing-api";
        opts.description = "billing service";
        HealthChecker checker = new HealthChecker(store, opts);
        HealthChecker.HealthResponse live = checker.liveness();
        String expectedLive = "{\"status\":\"pass\",\"version\":\"1.2.2\",\"serviceId\":\"billing-api\",\"description\":\"billing service\"}";
        assertEquals(expectedLive, live.body(), "liveness body");
        HealthChecker.HealthResponse ready = checker.readiness();
        String expectedReady = "{\"status\":\"pass\",\"version\":\"1.2.2\",\"serviceId\":\"billing-api\",\"description\":\"billing service\",\"checks\":{}}";
        assertEquals(expectedReady, ready.body(), "readiness body");

        try {
            HealthChecker.HealthOptions badOpts = new HealthChecker.HealthOptions();
            badOpts.clock = () -> FIXED_CLOCK_MS;
            badOpts.version = "1.2.2/beta";
            new HealthChecker(store, badOpts);
            throw new AssertionError("expected INVALID_OPTION");
        } catch (HealthChecker.HealthCheckError e) {
            assertEquals("INVALID_OPTION", e.getCode(), "error code");
        }
    }

    static void testChecksSortedByWholeKeyOrdinal() {
        HealthChecker.InMemoryCheckStore store = newStore();
        HealthChecker checker = newChecker(store, () -> FIXED_CLOCK_MS);
        checker.registerCheck("a", "component", () -> true, true, 5000);
        checker.registerCheck("a-b", "component", () -> true, true, 5000);
        HealthChecker.HealthResponse resp = checker.readiness();
        String expected = "{\"status\":\"pass\",\"checks\":{\"a-b:responseTime\":[{\"componentId\":\"a-b\",\"componentType\":\"component\",\"observedValue\":0,\"observedUnit\":\"ms\",\"status\":\"pass\",\"time\":\"" + FIXED_TIME + "\"}],\"a:responseTime\":[{\"componentId\":\"a\",\"componentType\":\"component\",\"observedValue\":0,\"observedUnit\":\"ms\",\"status\":\"pass\",\"time\":\"" + FIXED_TIME + "\"}]}}";
        assertEquals(expected, resp.body(), "body");
    }

    static void testEachCheckHasItsOwnDeadline() {
        HealthChecker.InMemoryCheckStore store = newStore();
        HealthChecker checker = newChecker(store, () -> FIXED_CLOCK_MS);
        checker.registerCheck("alpha", "component", () -> { Thread.sleep(600); return true; }, true, 5000);
        checker.registerCheck("beta", "component", () -> { Thread.sleep(300); return true; }, false, 100);
        HealthChecker.HealthResponse resp = checker.readiness();
        assertEquals(200, resp.httpStatus(), "http_status");
        String expected = "{\"status\":\"warn\",\"checks\":{\"alpha:responseTime\":[{\"componentId\":\"alpha\",\"componentType\":\"component\",\"observedValue\":0,\"observedUnit\":\"ms\",\"status\":\"pass\",\"time\":\"" + FIXED_TIME + "\"}],\"beta:responseTime\":[{\"componentId\":\"beta\",\"componentType\":\"component\",\"observedValue\":100,\"observedUnit\":\"ms\",\"status\":\"fail\",\"time\":\"" + FIXED_TIME + "\",\"output\":\"check timed out\"}]}}";
        assertEquals(expected, resp.body(), "body");
    }

    static void testInvalidRegistrationsAreRejected() {
        HealthChecker.InMemoryCheckStore store = newStore();
        HealthChecker checker = newChecker(store, () -> FIXED_CLOCK_MS);

        try { checker.registerCheck("", "type", () -> true, true, 5000); throw new AssertionError("expected INVALID_COMPONENT_ID"); }
        catch (HealthChecker.HealthCheckError e) { assertEquals("INVALID_COMPONENT_ID", e.getCode(), "empty id"); }

        try { checker.registerCheck("db:main", "type", () -> true, true, 5000); throw new AssertionError("expected INVALID_COMPONENT_ID"); }
        catch (HealthChecker.HealthCheckError e) { assertEquals("INVALID_COMPONENT_ID", e.getCode(), "colon id"); }

        try { checker.registerCheck("a".repeat(65), "type", () -> true, true, 5000); throw new AssertionError("expected INVALID_COMPONENT_ID"); }
        catch (HealthChecker.HealthCheckError e) { assertEquals("INVALID_COMPONENT_ID", e.getCode(), "long id"); }

        try { checker.registerCheck("valid", "", () -> true, true, 5000); throw new AssertionError("expected INVALID_COMPONENT_TYPE"); }
        catch (HealthChecker.HealthCheckError e) { assertEquals("INVALID_COMPONENT_TYPE", e.getCode(), "empty type"); }

        try { checker.registerCheck("valid", "type", () -> true, true, 0); throw new AssertionError("expected INVALID_TIMEOUT"); }
        catch (HealthChecker.HealthCheckError e) { assertEquals("INVALID_TIMEOUT", e.getCode(), "timeout 0"); }

        try { checker.registerCheck("valid", "type", () -> true, true, 60001); throw new AssertionError("expected INVALID_TIMEOUT"); }
        catch (HealthChecker.HealthCheckError e) { assertEquals("INVALID_TIMEOUT", e.getCode(), "timeout 60001"); }

        try { checker.registerCheck("valid", "type", null, true, 5000); throw new AssertionError("expected INVALID_CHECK_FN"); }
        catch (HealthChecker.HealthCheckError e) { assertEquals("INVALID_CHECK_FN", e.getCode(), "null check_fn"); }

        checker.registerCheck("db", "datastore", () -> true, true, 5000);
        try { checker.registerCheck("db", "datastore", () -> true, true, 5000); throw new AssertionError("expected DUPLICATE_COMPONENT"); }
        catch (HealthChecker.HealthCheckError e) { assertEquals("DUPLICATE_COMPONENT", e.getCode(), "duplicate"); assertEquals(409, e.getHttpStatus(), "http_status 409"); }

        HealthChecker.HealthResponse ready = checker.readiness();
        assertTrue(ready.body().contains("\"db:responseTime\""), "only first db registered");
        int count = 0;
        int idx = 0;
        while ((idx = ready.body().indexOf("db:responseTime", idx)) != -1) {
            count++;
            idx += "db:responseTime".length();
        }
        assertEquals(1, count, "no duplicate");
    }

    static void testFastCheckAfterSlowOneIsNotTimedOut() {
        HealthChecker.InMemoryCheckStore store = newStore();
        HealthChecker checker = newChecker(store, () -> FIXED_CLOCK_MS);
        checker.registerCheck("a", "component", () -> { Thread.sleep(1000); return true; }, true, 5000);
        for (int i = 1; i <= 8; i++) {
            final int n = i;
            checker.registerCheck("b" + n, "component", () -> true, true, 100);
        }
        HealthChecker.HealthResponse resp = checker.readiness();
        assertEquals(200, resp.httpStatus(), "http_status");
        StringBuilder expected = new StringBuilder("{\"status\":\"pass\",\"checks\":{");
        expected.append("\"a:responseTime\":[{\"componentId\":\"a\",\"componentType\":\"component\",\"observedValue\":0,\"observedUnit\":\"ms\",\"status\":\"pass\",\"time\":\"").append(FIXED_TIME).append("\"}]");
        for (int i = 1; i <= 8; i++) {
            expected.append(",\"b").append(i).append(":responseTime\":[{\"componentId\":\"b").append(i).append("\",\"componentType\":\"component\",\"observedValue\":0,\"observedUnit\":\"ms\",\"status\":\"pass\",\"time\":\"").append(FIXED_TIME).append("\"}]");
        }
        expected.append("}}");
        assertEquals(expected.toString(), resp.body(), "body");
    }
}
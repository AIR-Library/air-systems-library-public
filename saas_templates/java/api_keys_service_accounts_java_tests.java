import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import java.time.*;
import java.util.*;

public class ApiKeysServiceAccountsTests {

    private ApiKeysServiceAccounts.ApiKeyRepository keyRepo;
    private ApiKeysServiceAccounts.ApiKeyUsageRepository usageRepo;
    private ApiKeysServiceAccounts.RateLimiter rateLimiter;
    private ApiKeysServiceAccounts.ApiKeyService service;

    @BeforeEach
    public void setup() {
        keyRepo = new ApiKeysServiceAccounts.InMemoryApiKeyRepository();
        usageRepo = new ApiKeysServiceAccounts.InMemoryApiKeyUsageRepository();
        rateLimiter = new ApiKeysServiceAccounts.RateLimiter();
        service = new ApiKeysServiceAccounts.ApiKeyService(keyRepo, usageRepo, rateLimiter);
    }

    @Test
    public void testCreateKeyWithScopes() {
        List<String> scopes = Arrays.asList("read:deployments", "write:webhooks");
        Map<String, Object> resp = service.createKey(1L, "My Integration", scopes,
                LocalDateTime.now().plusDays(30), 1000);
        assertNotNull(resp.get("api_key_id"));
        assertNotNull(resp.get("key"));
        assertEquals(1000, resp.get("rate_limit"));
        // Key should be sk_live_ prefixed
        String key = (String) resp.get("key");
        assertTrue(key.startsWith("sk_live_"));
    }

    @Test
    public void testUseKeySuccess() {
        List<String> scopes = Arrays.asList("GET /deployments");
        Map<String, Object> create = service.createKey(1L, "Test", scopes,
                null, 1000);
        String key = (String) create.get("key");
        Map<String, Object> use = service.useKey(key, "/deployments", "GET", 200);
        assertEquals(200, use.get("status"));
    }

    @Test
    public void testRevokeKey() {
        List<String> scopes = Arrays.asList("GET /deployments");
        Map<String, Object> create = service.createKey(1L, "Test", scopes,
                null, 1000);
        long id = (long) create.get("api_key_id");
        String key = (String) create.get("key");
        service.revokeKey(id);
        Exception e = assertThrows(IllegalArgumentException.class,
                () -> service.useKey(key, "/deployments", "GET", 200));
        assertTrue(e.getMessage().contains("revoked"));
    }

    @Test
    public void testRateLimit() {
        List<String> scopes = Arrays.asList("GET /deployments");
        Map<String, Object> create = service.createKey(1L, "Test", scopes,
                null, 5);
        String key = (String) create.get("key");
        for (int i = 0; i < 5; i++) {
            service.useKey(key, "/deployments", "GET", 200);
        }
        Exception e = assertThrows(IllegalStateException.class,
                () -> service.useKey(key, "/deployments", "GET", 200));
        assertTrue(e.getMessage().contains("Rate limit exceeded"));
        // Verify rate limit hit was logged
        long keyId = (long) create.get("api_key_id");
        Map<String, Object> stats = service.getUsageStats(keyId,
                LocalDateTime.now().minusHours(1), LocalDateTime.now().plusHours(1));
        assertEquals(1, stats.get("rate_limit_hits"));
    }

    @Test
    public void testScopeCheck() {
        List<String> scopes = Arrays.asList("GET /deployments");
        Map<String, Object> create = service.createKey(1L, "Test", scopes,
                null, 1000);
        String key = (String) create.get("key");
        Exception e = assertThrows(IllegalArgumentException.class,
                () -> service.useKey(key, "/deployments", "POST", 200));
        assertTrue(e.getMessage().contains("Insufficient scope"));
    }

    @Test
    public void testRotateKey() {
        List<String> scopes = Arrays.asList("GET /deployments");
        Map<String, Object> create = service.createKey(1L, "Test", scopes,
                null, 1000);
        long id = (long) create.get("api_key_id");
        String oldKey = (String) create.get("key");
        Map<String, Object> rotate = service.rotateKey(id);
        String newKey = (String) rotate.get("new_key");
        // Old key still works within grace period
        service.useKey(oldKey, "/deployments", "GET", 200);
        // New key works
        service.useKey(newKey, "/deployments", "GET", 200);
        // Simulate grace period end
        ApiKeysServiceAccounts.ApiKey keyObj = keyRepo.findById(id).get();
        keyObj.gracePeriodEndsAt = LocalDateTime.now().minusSeconds(1);
        keyRepo.save(keyObj);
        Exception e = assertThrows(IllegalArgumentException.class,
                () -> service.useKey(oldKey, "/deployments", "GET", 200));
        assertTrue(e.getMessage().contains("revoked"));
        // New key still works after grace period
        service.useKey(newKey, "/deployments", "GET", 200);
    }

    @Test
    public void testExpiredKey() {
        List<String> scopes = Arrays.asList("GET /deployments");
        Map<String, Object> create = service.createKey(1L, "Test", scopes,
                LocalDateTime.now().minusDays(1), 1000);
        String key = (String) create.get("key");
        Exception e = assertThrows(IllegalArgumentException.class,
                () -> service.useKey(key, "/deployments", "GET", 200));
        assertTrue(e.getMessage().contains("expired"));
    }

    @Test
    public void testUsageStats() {
        List<String> scopes = Arrays.asList("GET /deployments", "POST /webhooks");
        Map<String, Object> create = service.createKey(1L, "Test", scopes,
                null, 1000);
        String key = (String) create.get("key");
        service.useKey(key, "/deployments", "GET", 200);
        service.useKey(key, "/deployments", "GET", 200);
        service.useKey(key, "/webhooks", "POST", 200);
        service.useKey(key, "/webhooks", "POST", 404);
        LocalDateTime from = LocalDateTime.now().minusDays(1);
        LocalDateTime to = LocalDateTime.now().plusDays(1);
        Map<String, Object> stats = service.getUsageStats((long) create.get("api_key_id"), from, to);
        assertEquals(4, stats.get("total_requests"));
        Map<String, Integer> byEndpoint = (Map<String, Integer>) stats.get("requests_by_endpoint");
        assertEquals(2, byEndpoint.get("GET /deployments"));
        assertEquals(2, byEndpoint.get("POST /webhooks"));
        Map<Integer, Integer> errors = (Map<Integer, Integer>) stats.get("errors");
        assertEquals(1, errors.get(404));
    }

    @Test
    public void testAdminAudit() {
        List<String> scopes = Arrays.asList("GET /deployments");
        service.createKey(1L, "Key1", scopes, null, 1000);
        service.createKey(2L, "Key2", scopes, null, 1000);
        // Admin audit with userId filter
        Map<String, Object> audit = service.listAllKeysForAudit(1L, true, true);
        assertEquals(1, audit.get("total"));
        List<Map<String, Object>> keys = (List<Map<String, Object>>) audit.get("keys");
        assertEquals(1L, keys.get(0).get("user_id"));
        // Admin audit without userId filter (all users)
        Map<String, Object> auditAll = service.listAllKeysForAudit(null, true, true);
        assertEquals(2, auditAll.get("total"));
        // Non-admin should fail
        Exception e = assertThrows(SecurityException.class,
                () -> service.listAllKeysForAudit(1L, true, false));
        assertTrue(e.getMessage().contains("Admin access required"));
    }

    @Test
    public void testRateLimitAtomicWithUsageLogging() {
        // Verify that rate-limited requests are logged with status 429
        List<String> scopes = Arrays.asList("GET /test");
        Map<String, Object> create = service.createKey(1L, "Test", scopes, null, 2);
        String key = (String) create.get("key");
        long keyId = (long) create.get("api_key_id");
        // Two successful requests
        service.useKey(key, "/test", "GET", 200);
        service.useKey(key, "/test", "GET", 200);
        // Third request hits rate limit
        assertThrows(IllegalStateException.class, () -> service.useKey(key, "/test", "GET", 200));
        // Check usage stats include the 429
        Map<String, Object> stats = service.getUsageStats(keyId,
                LocalDateTime.now().minusHours(1), LocalDateTime.now().plusHours(1));
        assertEquals(3, stats.get("total_requests"));
        assertEquals(1, stats.get("rate_limit_hits"));
        Map<Integer, Integer> errors = (Map<Integer, Integer>) stats.get("errors");
        assertEquals(1, errors.get(429));
    }

    @Test
    public void testWildcardScope() {
        List<String> scopes = Arrays.asList("*");
        Map<String, Object> create = service.createKey(1L, "Admin Key", scopes, null, 1000);
        String key = (String) create.get("key");
        // Should allow any action
        service.useKey(key, "/deployments", "GET", 200);
        service.useKey(key, "/deployments", "POST", 200);
        service.useKey(key, "/users", "DELETE", 200);
        service.useKey(key, "/billing", "PUT", 200);
    }
}

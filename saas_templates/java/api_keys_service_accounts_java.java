import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.stream.Collectors;
import java.security.SecureRandom;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import org.mindrot.jbcrypt.BCrypt;

/**
 * Database schema (DDL) for reference:
 *
 * CREATE TABLE api_keys (
 *   id BIGINT PRIMARY KEY,
 *   user_id BIGINT NOT NULL,
 *   name VARCHAR(255) NOT NULL,
 *   key_secret_hash VARCHAR(255) NOT NULL,
 *   scopes JSON NOT NULL,
 *   rate_limit INT NOT NULL,
 *   expires_at TIMESTAMP,
 *   created_at TIMESTAMP NOT NULL,
 *   last_used_at TIMESTAMP,
 *   is_active BOOLEAN NOT NULL,
 *   revoked_at TIMESTAMP,
 *   grace_period_ends_at TIMESTAMP
 * );
 *
 * CREATE TABLE api_key_usage (
 *   id BIGINT PRIMARY KEY,
 *   api_key_id BIGINT NOT NULL,
 *   endpoint VARCHAR(255) NOT NULL,
 *   method VARCHAR(10) NOT NULL,
 *   status INT NOT NULL,
 *   timestamp TIMESTAMP NOT NULL
 * );
 */
public class ApiKeysServiceAccounts {

    /* ---------- Models ---------- */
    public static class ApiKey {
        public long id;
        public long userId;
        public String name;
        public String keySecretHash;
        public List<String> scopes;
        public int rateLimit;
        public LocalDateTime expiresAt;
        public LocalDateTime createdAt;
        public LocalDateTime lastUsedAt;
        public boolean isActive;
        public LocalDateTime revokedAt;
        public LocalDateTime gracePeriodEndsAt;

        public ApiKey(long id, long userId, String name, String keySecretHash,
                      List<String> scopes, int rateLimit, LocalDateTime expiresAt,
                      LocalDateTime createdAt, boolean isActive) {
            this.id = id;
            this.userId = userId;
            this.name = name;
            this.keySecretHash = keySecretHash;
            this.scopes = scopes;
            this.rateLimit = rateLimit;
            this.expiresAt = expiresAt;
            this.createdAt = createdAt;
            this.isActive = isActive;
        }
    }

    public static class ApiKeyUsage {
        public long id;
        public long apiKeyId;
        public String endpoint;
        public String method;
        public int status;
        public LocalDateTime timestamp;

        public ApiKeyUsage(long id, long apiKeyId, String endpoint,
                           String method, int status, LocalDateTime timestamp) {
            this.id = id;
            this.apiKeyId = apiKeyId;
            this.endpoint = endpoint;
            this.method = method;
            this.status = status;
            this.timestamp = timestamp;
        }
    }

    /* ---------- Repository (In-Memory) ---------- */
    public interface ApiKeyRepository {
        ApiKey save(ApiKey key);
        Optional<ApiKey> findById(long id);
        Optional<ApiKey> findBySecret(String secret);
        List<ApiKey> findAll();
        List<ApiKey> findByUserIdAndStatus(long userId, Boolean isActive);
        void delete(long id);
    }

    public static class InMemoryApiKeyRepository implements ApiKeyRepository {
        private final Map<Long, ApiKey> store = new ConcurrentHashMap<>();
        private final AtomicLong idGen = new AtomicLong(1);

        @Override
        public ApiKey save(ApiKey key) {
            if (key.id == 0) {
                key.id = idGen.getAndIncrement();
            }
            store.put(key.id, key);
            return key;
        }

        @Override
        public Optional<ApiKey> findById(long id) {
            return Optional.ofNullable(store.get(id));
        }

        @Override
        public Optional<ApiKey> findBySecret(String secret) {
            // Every key is checked with bcrypt, which is slow. In production, put a key id in the secret
            // (sk_live_<id>_<random>) so one lookup finds the key.
            return store.values().stream()
                    .filter(k -> BCrypt.checkpw(secret, k.keySecretHash))
                    .findFirst();
        }

        @Override
        public List<ApiKey> findAll() {
            return new ArrayList<>(store.values());
        }

        @Override
        public List<ApiKey> findByUserIdAndStatus(long userId, Boolean isActive) {
            return store.values().stream()
                    .filter(k -> k.userId == userId && (isActive == null || k.isActive == isActive))
                    .collect(Collectors.toList());
        }

        @Override
        public void delete(long id) {
            store.remove(id);
        }
    }

    public interface ApiKeyUsageRepository {
        ApiKeyUsage save(ApiKeyUsage usage);
        List<ApiKeyUsage> findByApiKeyIdAndTimeRange(long apiKeyId,
                                                     LocalDateTime from,
                                                     LocalDateTime to);
        List<ApiKeyUsage> findByApiKeyId(long apiKeyId);

        /** Counts one call the rate limit refused. Refused calls are counted, not stored one by one, so a flood costs one
         *  counter per second and endpoint (2026-11-08, session f3daac6e, from review of PR 17). */
        default void countRejected(long apiKeyId, LocalDateTime at, String endpoint) {
        }

        /** Refused calls of one key in [from, to], per "METHOD /path". */
        default Map<String, Integer> rejectedByEndpoint(long apiKeyId, LocalDateTime from, LocalDateTime to) {
            return Map.of();
        }
    }

    public static class InMemoryApiKeyUsageRepository implements ApiKeyUsageRepository {
        /** How long refused-call counters are kept. Older ones are dropped, so the counters cannot grow forever. */
        public static final java.time.Duration REJECTED_RETENTION = java.time.Duration.ofDays(31);

        private record RejectedBucket(long apiKeyId, LocalDateTime second, String endpoint) {}

        private final ConcurrentHashMap<RejectedBucket, AtomicInteger> rejected = new ConcurrentHashMap<>();
        private volatile long lastPrune;   // epoch second of the last cleanup
        private final Map<Long, ApiKeyUsage> store = new ConcurrentHashMap<>();

        @Override
        public void countRejected(long apiKeyId, LocalDateTime at, String endpoint) {
            LocalDateTime second = at.truncatedTo(ChronoUnit.SECONDS);
            AtomicInteger counter = rejected.computeIfAbsent(new RejectedBucket(apiKeyId, second, endpoint), b -> new AtomicInteger());
            long nowSecond = second.toEpochSecond(java.time.ZoneOffset.UTC);
            if (counter.incrementAndGet() == 1 && nowSecond - lastPrune >= 60) {
                // At most once a minute: a scan per new counter would make a flood quadratic (review of PR 17).
                lastPrune = nowSecond;
                LocalDateTime cutoff = second.minus(REJECTED_RETENTION);
                rejected.keySet().removeIf(b -> b.second().isBefore(cutoff));
            }
        }

        @Override
        public Map<String, Integer> rejectedByEndpoint(long apiKeyId, LocalDateTime from, LocalDateTime to) {
            Map<String, Integer> out = new HashMap<>();
            LocalDateTime start = from.truncatedTo(ChronoUnit.SECONDS);
            rejected.forEach((b, n) -> {
                if (b.apiKeyId() == apiKeyId && !b.second().isBefore(start) && !b.second().isAfter(to)) {
                    out.merge(b.endpoint(), n.get(), Integer::sum);
                }
            });
            return out;
        }
        private final AtomicLong idGen = new AtomicLong(1);

        @Override
        public ApiKeyUsage save(ApiKeyUsage usage) {
            if (usage.id == 0) {
                usage.id = idGen.getAndIncrement();
            }
            store.put(usage.id, usage);
            return usage;
        }

        @Override
        public List<ApiKeyUsage> findByApiKeyIdAndTimeRange(long apiKeyId,
                                                           LocalDateTime from,
                                                           LocalDateTime to) {
            return store.values().stream()
                    .filter(u -> u.apiKeyId == apiKeyId &&
                            !u.timestamp.isBefore(from) &&
                            !u.timestamp.isAfter(to))
                    .collect(Collectors.toList());
        }

        @Override
        public List<ApiKeyUsage> findByApiKeyId(long apiKeyId) {
            return store.values().stream()
                    .filter(u -> u.apiKeyId == apiKeyId)
                    .collect(Collectors.toList());
        }
    }

    /* ---------- Rate Limiter ---------- */
    public static class RateLimiter {
        private final ConcurrentHashMap<String, AtomicInteger> counters = new ConcurrentHashMap<>();
        private final Duration window = Duration.ofHours(1);

        public boolean allow(String keyId, int limit) {
            String hourKey = keyId + ":" + LocalDateTime.now().truncatedTo(ChronoUnit.HOURS);
            AtomicInteger counter = counters.computeIfAbsent(hourKey, k -> new AtomicInteger(0));
            int current = counter.incrementAndGet();
            // Opportunistic cleanup of stale hour buckets (older than 2 hours)
            if (ThreadLocalRandom.current().nextInt(100) == 0) {
                cleanupStaleBuckets();
            }
            return current <= limit;
        }

        private void cleanupStaleBuckets() {
            LocalDateTime cutoff = LocalDateTime.now().minusHours(2);
            counters.entrySet().removeIf(entry -> {
                String[] parts = entry.getKey().split(":", 2);
                if (parts.length == 2) {
                    try {
                        LocalDateTime bucketTime = LocalDateTime.parse(parts[1]);
                        return bucketTime.isBefore(cutoff);
                    } catch (Exception e) {
                        return true; // Remove malformed keys
                    }
                }
                return true;
            });
        }

        // Package-private for testing only; not part of public API
        void resetForTesting() {
            counters.clear();
        }
    }

    /* ---------- Service ---------- */
    public static class ApiKeyService {
        private final ApiKeyRepository keyRepo;
        private final ApiKeyUsageRepository usageRepo;
        private final RateLimiter rateLimiter;
        private final ObjectMapper mapper = new ObjectMapper();
        private final SecureRandom random = new SecureRandom();

        public ApiKeyService(ApiKeyRepository keyRepo,
                             ApiKeyUsageRepository usageRepo,
                             RateLimiter rateLimiter) {
            this.keyRepo = keyRepo;
            this.usageRepo = usageRepo;
            this.rateLimiter = rateLimiter;
        }

        /* Create API key */
        public Map<String, Object> createKey(long userId, String name,
                                             List<String> scopes,
                                             LocalDateTime expiresAt,
                                             int rateLimit) {
            String secret = generateSecret();
            String hash = BCrypt.hashpw(secret, BCrypt.gensalt());
            ApiKey key = new ApiKey(0, userId, name, hash, scopes,
                    rateLimit, expiresAt, LocalDateTime.now(), true);
            keyRepo.save(key);
            Map<String, Object> resp = new HashMap<>();
            resp.put("api_key_id", key.id);
            resp.put("key", secret); // Only shown once per spec
            resp.put("created_at", key.createdAt.toString());
            resp.put("expires_at", key.expiresAt != null ? key.expiresAt.toString() : null);
            resp.put("rate_limit", key.rateLimit);
            return resp;
        }

        /* List API keys (masked) */
        public Map<String, Object> listKeys(long userId) {
            List<ApiKey> keys = keyRepo.findByUserIdAndStatus(userId, null);
            List<Map<String, Object>> list = keys.stream().map(k -> {
                Map<String, Object> m = new HashMap<>();
                m.put("api_key_id", k.id);
                m.put("name", k.name);
                m.put("scopes", k.scopes);
                m.put("created_at", k.createdAt.toString());
                m.put("last_used_at", k.lastUsedAt != null ? k.lastUsedAt.toString() : null);
                m.put("rate_limit", k.rateLimit);
                m.put("is_active", k.isActive);
                return m;
            }).collect(Collectors.toList());
            Map<String, Object> resp = new HashMap<>();
            resp.put("keys", list);
            return resp;
        }

        /* Revoke API key */
        public Map<String, Object> revokeKey(long apiKeyId) {
            ApiKey key = keyRepo.findById(apiKeyId)
                    .orElseThrow(() -> new IllegalArgumentException("Key not found"));
            key.isActive = false;
            key.revokedAt = LocalDateTime.now();
            keyRepo.save(key);
            Map<String, Object> resp = new HashMap<>();
            resp.put("success", true);
            resp.put("revoked_at", key.revokedAt.toString());
            return resp;
        }

        /* Rotate API key */
        public Map<String, Object> rotateKey(long apiKeyId) {
            ApiKey oldKey = keyRepo.findById(apiKeyId)
                    .orElseThrow(() -> new IllegalArgumentException("Key not found"));
            oldKey.isActive = false;
            oldKey.revokedAt = LocalDateTime.now();
            oldKey.gracePeriodEndsAt = oldKey.revokedAt.plusHours(24);
            keyRepo.save(oldKey);

            String secret = generateSecret();
            String hash = BCrypt.hashpw(secret, BCrypt.gensalt());
            ApiKey newKey = new ApiKey(0, oldKey.userId, oldKey.name + " (rotated)",
                    hash, oldKey.scopes, oldKey.rateLimit,
                    oldKey.expiresAt, LocalDateTime.now(), true);
            keyRepo.save(newKey);

            Map<String, Object> resp = new HashMap<>();
            resp.put("new_key", secret); // Only shown once per spec
            resp.put("old_key_revoked_at", oldKey.revokedAt.toString());
            resp.put("grace_period_ends_at", oldKey.gracePeriodEndsAt.toString());
            return resp;
        }

        /* Use API key (validate and log) - atomic rate-limit check + usage logging */
        public Map<String, Object> useKey(String secret, String endpoint,
                                          String method, int status) {
            ApiKey key = keyRepo.findBySecret(secret)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid key"));
            // Check active or grace period
            if (!key.isActive) {
                if (key.gracePeriodEndsAt == null || LocalDateTime.now().isAfter(key.gracePeriodEndsAt)) {
                    throw new IllegalArgumentException("Key revoked");
                }
            }
            // Check expiry
            if (key.expiresAt != null && LocalDateTime.now().isAfter(key.expiresAt)) {
                throw new IllegalArgumentException("Key expired");
            }
            // Check scope
            String action = method.toUpperCase() + " " + endpoint;
            if (!key.scopes.contains("*") && !key.scopes.contains(action)) {
                throw new IllegalArgumentException("Insufficient scope");
            }
            // Atomic rate-limit check and usage logging per key, on a lock object of this key's own: a lock on an interned
            // String can be taken by unrelated code anywhere in the process (code scanning, 2026-11-08, session f3daac6e, from review).
            synchronized (keyLocks.computeIfAbsent(key.id, id -> new Object())) {
                if (!rateLimiter.allow(String.valueOf(key.id), key.rateLimit)) {
                    // Rejected calls are counted per key, second and endpoint, not stored one by one: a flood of them
                    // would otherwise fill memory while being refused (2026-11-08, session f3daac6e, from review).
                    // Counted by the usage repository, so every service sharing it sees the same numbers.
                    usageRepo.countRejected(key.id, LocalDateTime.now(), method + " " + endpoint);
                    throw new IllegalStateException("Rate limit exceeded");
                }
                // Log usage
                ApiKeyUsage usage = new ApiKeyUsage(0, key.id, endpoint, method, status,
                        LocalDateTime.now());
                usageRepo.save(usage);
                key.lastUsedAt = LocalDateTime.now();
                keyRepo.save(key);
            }

            Map<String, Object> resp = new HashMap<>();
            resp.put("status", status);
            return resp;
        }

        /* Get usage stats */
        private final ConcurrentHashMap<Long, Object> keyLocks = new ConcurrentHashMap<>();

        public Map<String, Object> getUsageStats(long apiKeyId,
                                                 LocalDateTime from,
                                                 LocalDateTime to) {
            List<ApiKeyUsage> usages = usageRepo.findByApiKeyIdAndTimeRange(apiKeyId, from, to);
            int total = usages.size();
            Map<String, Integer> byEndpoint = new HashMap<>();
            Map<Integer, Integer> errors = new HashMap<>();
            int rateLimitHits = 0;
            for (Map.Entry<String, Integer> e : usageRepo.rejectedByEndpoint(apiKeyId, from, to).entrySet()) {
                int n = e.getValue();
                total += n;
                rateLimitHits += n;
                byEndpoint.merge(e.getKey(), n, Integer::sum);
                errors.merge(429, n, Integer::sum);
            }
            for (ApiKeyUsage u : usages) {
                String ep = u.method + " " + u.endpoint;
                byEndpoint.merge(ep, 1, Integer::sum);
                if (u.status >= 400) {
                    errors.merge(u.status, 1, Integer::sum);
                }
                if (u.status == 429) rateLimitHits++;
            }
            Map<String, Object> resp = new HashMap<>();
            resp.put("api_key_id", apiKeyId);
            resp.put("total_requests", total);
            resp.put("requests_by_endpoint", byEndpoint);
            resp.put("rate_limit_hits", rateLimitHits);
            resp.put("errors", errors);
            return resp;
        }

        /* Admin audit - requires isAdmin=true; null userId means all users */
        public Map<String, Object> listAllKeysForAudit(Long userId, Boolean isActive, boolean isAdmin) {
            if (!isAdmin) {
                throw new SecurityException("Admin access required");
            }
            List<ApiKey> keys;
            if (userId != null) {
                keys = keyRepo.findByUserIdAndStatus(userId, isActive);
            } else {
                keys = keyRepo.findAll().stream()
                        .filter(k -> isActive == null || k.isActive == isActive)
                        .collect(Collectors.toList());
            }
            List<Map<String, Object>> list = keys.stream().map(k -> {
                Map<String, Object> m = new HashMap<>();
                m.put("api_key_id", k.id);
                m.put("user_id", k.userId);
                m.put("name", k.name);
                m.put("scopes", k.scopes);
                m.put("created_at", k.createdAt.toString());
                m.put("expires_at", k.expiresAt != null ? k.expiresAt.toString() : null);
                m.put("is_active", k.isActive);
                return m;
            }).collect(Collectors.toList());
            Map<String, Object> resp = new HashMap<>();
            resp.put("keys", list);
            resp.put("total", list.size());
            return resp;
        }

        /* Helper: generate secret */
        private String generateSecret() {
            byte[] bytes = new byte[24];
            random.nextBytes(bytes);
            return "sk_live_" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        }
    }
}

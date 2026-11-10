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
        private final AtomicLong lastPrune = new AtomicLong();   // epoch second of the last cleanup
        private final Map<Long, ApiKeyUsage> store = new ConcurrentHashMap<>();

        @Override
        public void countRejected(long apiKeyId, LocalDateTime at, String endpoint) {
            LocalDateTime second = at.truncatedTo(ChronoUnit.SECONDS);
            AtomicInteger counter = rejected.computeIfAbsent(new RejectedBucket(apiKeyId, second, endpoint), b -> new AtomicInteger());
            long nowSecond = second.toEpochSecond(java.time.ZoneOffset.UTC);
            long last = lastPrune.get();
            // At most once a minute, and only by the caller that wins the compare-and-set: a scan per new counter would
            // make a flood quadratic, and racing callers would each scan (reviews of PR 17).
            if (counter.incrementAndGet() == 1 && nowSecond - last >= 60 && lastPrune.compareAndSet(last, nowSecond)) {
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
            return allow(keyId, limit, LocalDateTime.now());
        }

        /**
         * Counts one call in the key's current clock hour and says whether it is within the limit.
         * In: key id, limit per hour, the caller's "now". Out: true while count <= limit (the limit+1st call is refused).
         * Why: KEYS-04 with an injectable clock (spec rule "Deterministic"); 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
         * Touches: memory only.
         */
        public boolean allow(String keyId, int limit, LocalDateTime now) {
            String hourKey = keyId + ":" + now.truncatedTo(ChronoUnit.HOURS);
            AtomicInteger counter = counters.computeIfAbsent(hourKey, k -> new AtomicInteger(0));
            int current = counter.incrementAndGet();
            // Opportunistic cleanup of stale hour buckets (older than 2 hours)
            if (ThreadLocalRandom.current().nextInt(100) == 0) {
                cleanupStaleBuckets(now);
            }
            return current <= limit;
        }

        /** Drops hour buckets older than two hours before the caller's now (not the wall clock, so an injected clock
         *  never loses a live bucket); 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory. */
        private void cleanupStaleBuckets(LocalDateTime now) {
            LocalDateTime cutoff = now.minusHours(2);
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

    /**
     * A refused API call: HTTP status 401 (invalid, revoked or expired key), 403 (scope) or 429 (rate limit) and an
     * error code. In: status, code, message. Why: the spec answers 401/403/429, which plain IllegalArgument/IllegalState
     * exceptions could not say; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public static class ApiKeyException extends RuntimeException {
        private final int status;
        private final String error;

        public ApiKeyException(int status, String error, String message) {
            super(message);
            this.status = status;
            this.error = error;
        }

        public int getStatus() {
            return status;
        }

        public String getError() {
            return error;
        }
    }

    /* ---------- Service ---------- */
    public static class ApiKeyService {
        private final ApiKeyRepository keyRepo;
        private final ApiKeyUsageRepository usageRepo;
        private final RateLimiter rateLimiter;
        private final ObjectMapper mapper = new ObjectMapper();
        private final SecureRandom random = new SecureRandom();
        private final Clock clock;
        /** SHA-256(secret) -> key id for secrets already proven with bcrypt (see resolveKey). */
        private final ConcurrentHashMap<String, Long> verifiedSecrets = new ConcurrentHashMap<>();

        public ApiKeyService(ApiKeyRepository keyRepo,
                             ApiKeyUsageRepository usageRepo,
                             RateLimiter rateLimiter) {
            this(keyRepo, usageRepo, rateLimiter, Clock.systemUTC());
        }

        /**
         * Service with an injectable clock. In: repositories, rate limiter, clock. Why: spec "Deterministic: time comes
         * from an injectable clock" (KEYS-04/06/07); 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
         */
        public ApiKeyService(ApiKeyRepository keyRepo,
                             ApiKeyUsageRepository usageRepo,
                             RateLimiter rateLimiter,
                             Clock clock) {
            this.keyRepo = keyRepo;
            this.usageRepo = usageRepo;
            this.rateLimiter = rateLimiter;
            this.clock = clock;
        }

        private LocalDateTime now() {
            return LocalDateTime.now(clock);
        }

        /**
         * Finds the key a presented secret belongs to. The first use of a secret is checked with bcrypt against the
         * stored hashes; after that its SHA-256 digest maps straight to the key id, so a key's 1000 calls an hour do not
         * cost 1000 bcrypt runs. The digest of a 192-bit random secret reveals nothing usable, and only secrets that
         * already passed bcrypt are cached. Revocation and expiry are still read from the key on every call.
         * In: the secret. Out: the key, or empty. Why: KEYS-02/04; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
         * Touches: the key repository, memory.
         */
        private Optional<ApiKey> resolveKey(String secret) {
            if (secret == null || !secret.startsWith("sk_")) {
                return Optional.empty();
            }
            String digest = sha256Hex(secret);
            Long cached = verifiedSecrets.get(digest);
            if (cached != null) {
                Optional<ApiKey> k = keyRepo.findById(cached);
                if (k.isPresent()) {
                    return k;
                }
                verifiedSecrets.remove(digest);
            }
            Optional<ApiKey> found = keyRepo.findBySecret(secret);
            found.ifPresent(k -> verifiedSecrets.put(digest, k.id));
            return found;
        }

        private static String sha256Hex(String s) {
            try {
                byte[] d = java.security.MessageDigest.getInstance("SHA-256").digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                StringBuilder sb = new StringBuilder();
                for (byte b : d) sb.append(String.format("%02x", b));
                return sb.toString();
            } catch (java.security.NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }

        /**
         * Whether a key's scopes allow METHOD on endpoint, by the spec's scope list: read:X = GET /X, write:X = POST/PUT
         * /X, write:billing = POST /subscriptions and PUT /billing, webhook:manage = POST/DELETE /webhooks, * = all.
         * The resource is the endpoint's first path segment (a leading /api is ignored).
         * In: scopes, method, endpoint. Out: allowed. Why: KEYS-05 ("read:deployments can't write deployments"); the
         * old check compared literal "GET /x" strings, which no spec scope is. 2026-11-10,
         * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
         */
        static boolean scopeAllows(List<String> scopes, String method, String endpoint) {
            String m = method.toUpperCase(Locale.ROOT);
            String path = endpoint.startsWith("/api/") ? endpoint.substring(4) : endpoint;
            String[] segs = path.replaceAll("^/+", "").split("[/?]");
            String resource = segs.length > 0 ? segs[0] : "";
            for (String scope : scopes) {
                if ("*".equals(scope)) return true;
                if ("write:billing".equals(scope)
                        && (("POST".equals(m) && "subscriptions".equals(resource)) || ("PUT".equals(m) && "billing".equals(resource)))) {
                    return true;
                }
                if ("webhook:manage".equals(scope) && "webhooks".equals(resource)
                        && ("POST".equals(m) || "DELETE".equals(m))) {
                    return true;
                }
                if (scope.equals("read:" + resource) && "GET".equals(m)) return true;
                if (scope.equals("write:" + resource) && ("POST".equals(m) || "PUT".equals(m))) return true;
            }
            return false;
        }

        /* Create API key */
        public Map<String, Object> createKey(long userId, String name,
                                             List<String> scopes,
                                             LocalDateTime expiresAt,
                                             int rateLimit) {
            String secret = generateSecret();
            String hash = BCrypt.hashpw(secret, BCrypt.gensalt());
            ApiKey key = new ApiKey(0, userId, name, hash, scopes,
                    rateLimit, expiresAt, now(), true);
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
            key.revokedAt = now();
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
            oldKey.revokedAt = now();
            oldKey.gracePeriodEndsAt = oldKey.revokedAt.plusHours(24);
            keyRepo.save(oldKey);

            String secret = generateSecret();
            String hash = BCrypt.hashpw(secret, BCrypt.gensalt());
            ApiKey newKey = new ApiKey(0, oldKey.userId, oldKey.name + " (rotated)",
                    hash, oldKey.scopes, oldKey.rateLimit,
                    oldKey.expiresAt, now(), true);
            keyRepo.save(newKey);

            Map<String, Object> resp = new HashMap<>();
            resp.put("new_key", secret); // Only shown once per spec
            resp.put("old_key_revoked_at", oldKey.revokedAt.toString());
            resp.put("grace_period_ends_at", oldKey.gracePeriodEndsAt.toString());
            return resp;
        }

        /**
         * Use API key: the request's "Authorization: Bearer <key>" secret is checked, then active/grace period, expiry,
         * scope and the hourly rate limit; the call is logged to api_key_usage.
         * In: the bearer secret, endpoint, method, the status the handler answered. Out: {status}.
         * Throws ApiKeyException 401 invalid_api_key / api_key_revoked / api_key_expired, 403 insufficient_scope,
         * 429 rate_limited. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: typed 401/403/429 (KEYS-03/04/05/07), spec
         * scope names (KEYS-05), injected clock, refused 401/403 calls of a known key are logged too ("every API call
         * logged"). Touches: key and usage repositories.
         */
        public Map<String, Object> useKey(String secret, String endpoint,
                                          String method, int status) {
            ApiKey key = resolveKey(secret)
                    .orElseThrow(() -> new ApiKeyException(401, "invalid_api_key", "Invalid key"));
            LocalDateTime now = now();
            // Check active or grace period
            if (!key.isActive) {
                if (key.gracePeriodEndsAt == null || now.isAfter(key.gracePeriodEndsAt)) {
                    usageRepo.save(new ApiKeyUsage(0, key.id, endpoint, method, 401, now));
                    throw new ApiKeyException(401, "api_key_revoked", "Key revoked");
                }
            }
            // Check expiry
            if (key.expiresAt != null && now.isAfter(key.expiresAt)) {
                usageRepo.save(new ApiKeyUsage(0, key.id, endpoint, method, 401, now));
                throw new ApiKeyException(401, "api_key_expired", "Key expired");
            }
            // Check scope
            if (!scopeAllows(key.scopes, method, endpoint)) {
                usageRepo.save(new ApiKeyUsage(0, key.id, endpoint, method, 403, now));
                throw new ApiKeyException(403, "insufficient_scope", "Insufficient scope");
            }
            // Atomic rate-limit check and usage logging per key, on a lock object of this key's own: a lock on an interned
            // String can be taken by unrelated code anywhere in the process (code scanning, 2026-11-08, session f3daac6e, from review).
            synchronized (keyLocks.computeIfAbsent(key.id, id -> new Object())) {
                if (!rateLimiter.allow(String.valueOf(key.id), key.rateLimit, now)) {
                    // Rejected calls are counted per key, second and endpoint, not stored one by one: a flood of them
                    // would otherwise fill memory while being refused (2026-11-08, session f3daac6e, from review).
                    // Counted by the usage repository, so every service sharing it sees the same numbers.
                    usageRepo.countRejected(key.id, now, method + " " + endpoint);
                    throw new ApiKeyException(429, "rate_limited", "Rate limit exceeded");
                }
                // Log usage
                ApiKeyUsage usage = new ApiKeyUsage(0, key.id, endpoint, method, status, now);
                usageRepo.save(usage);
                key.lastUsedAt = now;
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

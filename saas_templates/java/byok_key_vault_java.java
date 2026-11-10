import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.IntFunction;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * BYOK key vault (spec docs/specs/byok_key_vault.md): a user stores their own API key for a provider. The key is
 * checked once with the provider, encrypted at rest under a per-key data key (envelope encryption, AES-256-GCM), shown
 * again only as a 4-character hint, opened only for the user who saved it, and every save, use, delete and rewrap is
 * audited. Master keys rotate with rewrap().
 *
 * In: the verified caller's user id, a provider id, a key or a purpose. Out: result maps with "status" (refusals
 * carry "error"); never an unhandled exception for a caller's input. Construction fails closed (ConfigException).
 * Why: Phase D wave 1, owner request 2026-11-10 (VAULT-01 to VAULT-14). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the injected Store (database; memory in tests) and the injected provider client (network in production,
 * a fake in tests). No money. The plain key appears only in save_key's input and use_key's result: never in a log,
 * an audit row, a refusal or an exception message.
 */
public final class ByokKeyVault {
    public static final int SAVES_PER_HOUR = 10;
    private static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9_-]{1,32}");
    private static final Pattern PROVIDER_ID = Pattern.compile("[a-z0-9_]{1,32}");
    private static final Pattern PURPOSE = Pattern.compile("[A-Za-z0-9_.:-]{1,100}");

    /** Construction failure: "invalid_master_key" or "invalid_provider_config". Its message is the code only. */
    public static final class ConfigException extends RuntimeException {
        public final String code;

        /** In: the code. Out: the exception. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        public ConfigException(String code) {
            super(code);
            this.code = code;
        }
    }

    /** A provider's key shape: the prefix and the length range of the key. */
    public record ProviderConfig(String prefix, int minLength, int maxLength) {}

    /**
     * The provider check: "ok", "rejected" or "unreachable" (anything else, or a raised error, is unreachable).
     * The real client makes one read-only call; tests pass a fake. Touches: network (real client only).
     */
    public interface ProviderClient {
        /** In: provider id, the trimmed key. Out: "ok" | "rejected" | "unreachable"; may raise. Touches: network (real client). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        String check(String provider, String key) throws Exception;
    }

    /** A provider_keys row. lastUsedAt is null until use_key. */
    public record KeyRow(String userId, String provider, String keyId, String wrappedDek, String ciphertext,
                         String hint, long createdAt, Long lastUsedAt) {}

    /** A provider_key_audit row (id ascending). purpose is null except for key_used. */
    public record AuditRow(long id, String userId, String provider, String action, String purpose, String keyId, long at) {}

    /**
     * Storage. Each method is one transaction or one conditional write; a failed transaction changes nothing and
     * throws. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (memory in tests).
     */
    public interface Store {
        /** The row for (user_id, provider), or null. Touches: reads the database. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        KeyRow get(String userId, String provider);

        /** The user's rows, sorted by provider (ordinal). */
        List<KeyRow> listForUser(String userId);

        /** Every row, sorted by (user_id, provider) (ordinal). */
        List<KeyRow> listAll();

        /** Replaces the user's row for the provider and appends the audit row, in one transaction. */
        void saveWithAudit(KeyRow row, String action, long at);

        /** Sets last_used_at and appends the key_used audit row, in one transaction. */
        void markUsedWithAudit(String userId, String provider, long now, String purpose, String keyId);

        /** Deletes the row and appends key_deleted, in one transaction. False (nothing written) when there was no row. */
        boolean deleteWithAudit(String userId, String provider, long now);

        /** UPDATE ... SET key_id, wrapped_dek WHERE user, provider AND wrapped_dek = read; plus key_rewrapped. */
        boolean rewrap(String userId, String provider, String newKeyId, String newWrapped, String wrappedRead, long now);

        /** The window write: insert (u, w, 1) or add 1 while count < 10. False when no row changed. */
        boolean bumpWindow(String userId, long windowStart);

        /** The user's audit rows, oldest first. */
        List<AuditRow> audit(String userId);
    }

    /**
     * In-memory Store, synchronized (each method atomic). failWrites makes the next transactions fail (and change
     * nothing), to test storage_failed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    public static final class InMemoryStore implements Store {
        private final TreeMap<String, KeyRow> rows = new TreeMap<>();
        private final List<AuditRow> audit = new ArrayList<>();
        private final Map<String, Integer> windows = new LinkedHashMap<>();
        private long nextAudit = 1;
        public volatile boolean failWrites = false;

        /** The row key. In: user id, provider. Out: a map key that cannot collide. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        private static String k(String u, String p) {
            return u + "\u0000" + p;
        }

        /** Test hook: writes a row as it is (to move or damage it). */
        public synchronized void put(KeyRow r) {
            rows.put(k(r.userId(), r.provider()), r);
        }

        /** Test hook: removes a row without an audit row. */
        public synchronized void remove(String u, String p) {
            rows.remove(k(u, p));
        }

        /** Every audit row, oldest first. */
        public synchronized List<AuditRow> allAudit() {
            return new ArrayList<>(audit);
        }

        @Override
        public synchronized KeyRow get(String userId, String provider) {
            return rows.get(k(userId, provider));
        }

        @Override
        public synchronized List<KeyRow> listForUser(String userId) {
            List<KeyRow> out = new ArrayList<>();
            for (KeyRow r : rows.values()) if (r.userId().equals(userId)) out.add(r);
            out.sort((a, b) -> a.provider().compareTo(b.provider()));
            return out;
        }

        @Override
        public synchronized List<KeyRow> listAll() {
            List<KeyRow> out = new ArrayList<>(rows.values());
            out.sort((a, b) -> a.userId().equals(b.userId()) ? a.provider().compareTo(b.provider()) : a.userId().compareTo(b.userId()));
            return out;
        }

        /** Throws when failWrites is set, before any change (a failed transaction writes nothing). Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        private void fail() {
            if (failWrites) throw new IllegalStateException("storage unavailable");
        }

        @Override
        public synchronized void saveWithAudit(KeyRow row, String action, long at) {
            fail();
            rows.put(k(row.userId(), row.provider()), row);
            audit.add(new AuditRow(nextAudit++, row.userId(), row.provider(), action, null, row.keyId(), at));
        }

        @Override
        public synchronized void markUsedWithAudit(String userId, String provider, long now, String purpose, String keyId) {
            fail();
            KeyRow r = rows.get(k(userId, provider));
            if (r == null) throw new IllegalStateException("row gone");
            rows.put(k(userId, provider), new KeyRow(r.userId(), r.provider(), r.keyId(), r.wrappedDek(), r.ciphertext(), r.hint(), r.createdAt(), now));
            audit.add(new AuditRow(nextAudit++, userId, provider, "key_used", purpose, keyId, now));
        }

        @Override
        public synchronized boolean deleteWithAudit(String userId, String provider, long now) {
            fail();
            KeyRow r = rows.remove(k(userId, provider));
            if (r == null) return false;
            audit.add(new AuditRow(nextAudit++, userId, provider, "key_deleted", null, r.keyId(), now));
            return true;
        }

        @Override
        public synchronized boolean rewrap(String userId, String provider, String newKeyId, String newWrapped, String wrappedRead, long now) {
            fail();
            KeyRow r = rows.get(k(userId, provider));
            if (r == null || !r.wrappedDek().equals(wrappedRead)) return false;
            rows.put(k(userId, provider), new KeyRow(userId, provider, newKeyId, newWrapped, r.ciphertext(), r.hint(), r.createdAt(), r.lastUsedAt()));
            audit.add(new AuditRow(nextAudit++, userId, provider, "key_rewrapped", null, newKeyId, now));
            return true;
        }

        @Override
        public synchronized boolean bumpWindow(String userId, long windowStart) {
            String key = userId + "\u0000" + windowStart;
            int c = windows.getOrDefault(key, 0);
            if (c >= SAVES_PER_HOUR) return false;
            windows.put(key, c + 1);
            return true;
        }

        @Override
        public synchronized List<AuditRow> audit(String userId) {
            List<AuditRow> out = new ArrayList<>();
            for (AuditRow a : audit) if (a.userId().equals(userId)) out.add(a);
            return out;
        }
    }

    private final Store store;
    private final Map<String, byte[]> masterKeys;
    private final String activeKeyId;
    private final Map<String, ProviderConfig> providers;
    private final ProviderClient client;
    private final LongSupplier clock;
    private final IntFunction<byte[]> randomBytes;

    /**
     * In: store, master_keys {key_id: 32 bytes}, active_key_id, providers, provider client, clock (Unix seconds),
     * random_bytes (null = SecureRandom). Out: the vault. Throws ConfigException: invalid_master_key (a key that is not
     * 32 bytes, a malformed key_id, an active id not in the keyring) or invalid_provider_config (VAULT-11).
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only (copies the keys).
     */
    public ByokKeyVault(Store store, Map<String, byte[]> masterKeys, String activeKeyId, Map<String, ProviderConfig> providers,
                        ProviderClient client, LongSupplier clock, IntFunction<byte[]> randomBytes) {
        if (masterKeys == null || activeKeyId == null || !masterKeys.containsKey(activeKeyId)) {
            throw new ConfigException("invalid_master_key");
        }
        Map<String, byte[]> mk = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> e : masterKeys.entrySet()) {
            if (e.getKey() == null || !KEY_ID.matcher(e.getKey()).matches() || e.getValue() == null || e.getValue().length != 32) {
                throw new ConfigException("invalid_master_key");
            }
            mk.put(e.getKey(), e.getValue().clone());
        }
        if (providers == null) throw new ConfigException("invalid_provider_config");
        for (Map.Entry<String, ProviderConfig> e : providers.entrySet()) {
            ProviderConfig c = e.getValue();
            if (e.getKey() == null || !PROVIDER_ID.matcher(e.getKey()).matches() || c == null || c.prefix() == null
                    || c.minLength() < 20 || c.minLength() > c.maxLength() || c.maxLength() > 4096
                    || c.minLength() < c.prefix().length() + 16) {
                throw new ConfigException("invalid_provider_config");
            }
        }
        this.store = store;
        this.masterKeys = mk;
        this.activeKeyId = activeKeyId;
        this.providers = new LinkedHashMap<>(providers);
        this.client = client;
        this.clock = clock;
        if (randomBytes == null) {
            SecureRandom rng = new SecureRandom();
            this.randomBytes = n -> {
                byte[] b = new byte[n];
                rng.nextBytes(b);
                return b;
            };
        } else {
            this.randomBytes = randomBytes;
        }
    }

    // ------------------------------------------------------------------------------------------------ crypto
    /** GCM(key, nonce, plaintext, aad): ciphertext followed by the 16-byte tag. Touches: nothing. */
    private static byte[] gcmSeal(byte[] key, byte[] nonce, byte[] plaintext, String aad) {
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            c.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
            return c.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("aes-gcm unavailable");
        }
    }

    /** base64(nonce + GCM(...)). */
    private static String envelope(byte[] key, byte[] nonce, byte[] plaintext, String aad) {
        byte[] ct = gcmSeal(key, nonce, plaintext, aad);
        byte[] all = new byte[nonce.length + ct.length];
        System.arraycopy(nonce, 0, all, 0, nonce.length);
        System.arraycopy(ct, 0, all, nonce.length, ct.length);
        return Base64.getEncoder().encodeToString(all);
    }

    /**
     * Opens base64(nonce + ciphertext + tag). Out: the plaintext, or null for bad base64, fewer than 28 bytes or a tag
     * that fails. Never throws. Touches: nothing.
     */
    private static byte[] openEnvelope(byte[] key, String stored, String aad) {
        byte[] all;
        try {
            all = Base64.getDecoder().decode(stored);
        } catch (IllegalArgumentException | NullPointerException e) {
            return null;
        }
        if (all.length < 28) return null;
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, all, 0, 12));
            c.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
            return c.doFinal(all, 12, all.length - 12);
        } catch (GeneralSecurityException e) {
            return null;
        }
    }

    /** The DEK's aad. In: key id, provider, user. Out: "byok:dek:" + key_id + ":" + provider + ":" + user_id. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static String dekAad(String keyId, String provider, String userId) {
        return "byok:dek:" + keyId + ":" + provider + ":" + userId;
    }

    /** The key's aad. In: provider, user. Out: "byok:data:" + provider + ":" + user_id. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static String dataAad(String provider, String userId) {
        return "byok:data:" + provider + ":" + userId;
    }

    /** A refusal. In: HTTP status, error code. Out: {status, error}. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static Map<String, Object> refuse(int status, String error) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", status);
        m.put("error", error);
        return m;
    }

    /** In: a character. Out: true for space, tab, CR, LF (the only characters trimmed). Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean isTrimChar(char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    }

    // ------------------------------------------------------------------------------------------------ functions
    /**
     * save_key(user_id, provider, key) -> {status 200, provider, hint, key_id, created_at}. Checks in order: 404
     * unknown_provider, 400 invalid_key_format, the hourly window (429 rate_limited, counted before the provider
     * call), the provider (400 key_rejected, 502 provider_unreachable), then the row + key_saved audit in one
     * transaction (500 storage_failed). VAULT-01..04, 09, 12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the store, the provider client (network in production).
     */
    public Map<String, Object> saveKey(String userId, String provider, String key) {
        ProviderConfig cfg = provider == null ? null : providers.get(provider);
        if (cfg == null) return refuse(404, "unknown_provider");
        if (key == null) return refuse(400, "invalid_key_format");
        int a = 0, b = key.length();
        while (a < b && isTrimChar(key.charAt(a))) a++;
        while (b > a && isTrimChar(key.charAt(b - 1))) b--;
        String k = key.substring(a, b);
        boolean ok = k.startsWith(cfg.prefix()) && k.length() >= cfg.minLength() && k.length() <= cfg.maxLength();
        for (int i = 0; ok && i < k.length(); i++) {
            char c = k.charAt(i);
            if (c < 0x21 || c > 0x7e) ok = false;
        }
        if (!ok) return refuse(400, "invalid_key_format");
        long now = clock.getAsLong();
        long w = now - Math.floorMod(now, 3600L);
        if (!store.bumpWindow(userId, w)) {
            Map<String, Object> m = refuse(429, "rate_limited");
            m.put("retry_after", w + 3600 - now);
            return m;
        }
        String v;
        try {
            v = client.check(provider, k);
        } catch (Exception e) {
            return refuse(502, "provider_unreachable");
        }
        if ("rejected".equals(v)) return refuse(400, "key_rejected");
        if (!"ok".equals(v)) return refuse(502, "provider_unreachable");
        byte[] dek = randomBytes.apply(32);
        byte[] dataNonce = randomBytes.apply(12);
        byte[] wrapNonce = randomBytes.apply(12);
        String ciphertext = envelope(dek, dataNonce, k.getBytes(StandardCharsets.UTF_8), dataAad(provider, userId));
        String wrapped = envelope(masterKeys.get(activeKeyId), wrapNonce, dek, dekAad(activeKeyId, provider, userId));
        java.util.Arrays.fill(dek, (byte) 0);
        String hint = k.substring(k.length() - 4);
        try {
            store.saveWithAudit(new KeyRow(userId, provider, activeKeyId, wrapped, ciphertext, hint, now, null), "key_saved", now);
        } catch (RuntimeException e) {
            return refuse(500, "storage_failed");
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", 200);
        m.put("provider", provider);
        m.put("hint", hint);
        m.put("key_id", activeKeyId);
        m.put("created_at", now);
        return m;
    }

    /**
     * list_keys(user_id) -> [{provider, hint, key_id, created_at, last_used_at}], sorted by provider. Never the key,
     * the ciphertext or the wrapped DEK. VAULT-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the store.
     */
    public List<Map<String, Object>> listKeys(String userId) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (KeyRow r : store.listForUser(userId)) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("provider", r.provider());
            m.put("hint", r.hint());
            m.put("key_id", r.keyId());
            m.put("created_at", r.createdAt());
            m.put("last_used_at", r.lastUsedAt());
            out.add(m);
        }
        return out;
    }

    /**
     * use_key(user_id, provider, purpose) -> {status 200, key}. SERVER-SIDE ONLY. Checks in order: 400 invalid_purpose,
     * 404 key_not_found, 503 key_unavailable (key id not in the keyring), 500 key_unreadable (unwrap or decrypt fails,
     * never an exception), then last_used_at + key_used audit in one transaction (500 storage_failed, no key).
     * VAULT-06..08, 11, 13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
     */
    public Map<String, Object> useKey(String userId, String provider, String purpose) {
        if (purpose == null || !PURPOSE.matcher(purpose).matches()) return refuse(400, "invalid_purpose");
        KeyRow r = store.get(userId, provider);
        if (r == null) return refuse(404, "key_not_found");
        byte[] mk = masterKeys.get(r.keyId());
        if (mk == null) return refuse(503, "key_unavailable");
        byte[] dek = openEnvelope(mk, r.wrappedDek(), dekAad(r.keyId(), provider, userId));
        if (dek == null || dek.length != 32) return refuse(500, "key_unreadable");
        byte[] plain = openEnvelope(dek, r.ciphertext(), dataAad(provider, userId));
        java.util.Arrays.fill(dek, (byte) 0);
        if (plain == null) return refuse(500, "key_unreadable");
        long now = clock.getAsLong();
        try {
            store.markUsedWithAudit(userId, provider, now, purpose, r.keyId());
        } catch (RuntimeException e) {
            return refuse(500, "storage_failed");
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", 200);
        m.put("key", new String(plain, StandardCharsets.UTF_8));
        return m;
    }

    /**
     * delete_key(user_id, provider) -> {status 200, deleted: true} with a key_deleted audit row, or {deleted: false}
     * and no audit row when there was none. VAULT-07, VAULT-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the store.
     */
    public Map<String, Object> deleteKey(String userId, String provider) {
        Map<String, Object> m = new LinkedHashMap<>();
        try {
            m.put("status", 200);
            m.put("deleted", store.deleteWithAudit(userId, provider, clock.getAsLong()));
        } catch (RuntimeException e) {
            return refuse(500, "storage_failed");
        }
        return m;
    }

    /**
     * rewrap() -> {rewrapped, failed}. OPERATOR ONLY. Re-wraps each row's DEK whose key_id is not the active one, in
     * (user_id, provider) order, with one conditional write per row (a row changed meanwhile is counted in neither
     * number). The ciphertext is never touched. VAULT-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the store.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (the gap of review findings 4525344188 and 4525344204,
     * found in Java by the previous fix pass): a row whose nonce (random_bytes not 12 bytes), seal or store write
     * fails is counted in failed and the next row is still rewrapped; such an error used to end rewrap() with an
     * exception and no {rewrapped, failed} count. A short nonce used to be sealed and stored as an envelope that
     * cannot be opened; it is now refused before the seal. Nothing of the error is echoed.
     */
    public Map<String, Object> rewrap() {
        int rewrapped = 0, failed = 0;
        long now = clock.getAsLong();
        for (KeyRow r : store.listAll()) {
            if (r.keyId().equals(activeKeyId)) continue;
            byte[] mk = masterKeys.get(r.keyId());
            byte[] dek = mk == null ? null : openEnvelope(mk, r.wrappedDek(), dekAad(r.keyId(), r.provider(), r.userId()));
            if (dek == null || dek.length != 32) {
                failed++;
                continue;
            }
            try {
                byte[] wrapNonce = randomBytes.apply(12);
                if (wrapNonce == null || wrapNonce.length != 12) throw new IllegalStateException("random_bytes_short");
                String nw = envelope(masterKeys.get(activeKeyId), wrapNonce, dek, dekAad(activeKeyId, r.provider(), r.userId()));
                if (store.rewrap(r.userId(), r.provider(), activeKeyId, nw, r.wrappedDek(), now)) rewrapped++;
            } catch (RuntimeException e) {
                // Count the row, go on with the next one, echo nothing (review findings 4525344188 / 4525344204).
                failed++;
            } finally {
                java.util.Arrays.fill(dek, (byte) 0);
            }
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("rewrapped", rewrapped);
        m.put("failed", failed);
        return m;
    }

    /**
     * list_audit(user_id) -> [{at, action, provider, purpose, key_id}], oldest first. Holds no key.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the store.
     */
    public List<Map<String, Object>> listAudit(String userId) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (AuditRow a : store.audit(userId)) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("at", a.at());
            m.put("action", a.action());
            m.put("provider", a.provider());
            m.put("purpose", a.purpose());
            m.put("key_id", a.keyId());
            out.add(m);
        }
        return out;
    }
}

// BYOK key vault template (docs/specs/byok_key_vault.md): users store their own API key for a third-party provider.
// Envelope encryption: one random 32-byte data key (DEK) per stored key, AES-256-GCM with aad binding the row to its
// user, provider and master key id; the master key only wraps DEKs. Shown again only as a 4-character hint, opened
// only for the user who saved it, every use audited, at most 10 provider checks per user per clock hour, and an
// operator-only rewrap() for master-key rotation.
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1, owner request 2026-11-10).
// Touches: provider_keys, provider_key_audit and provider_key_save_windows behind IVaultStore (process memory in
// InMemoryVaultStore); the injected provider client (the network, in production: ONE read-only call per save).
// Never logs or returns a key, a DEK or a master key outside use_key's result.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AOI.ByokKeyVault
{
    /// <summary>
    /// Construction refused (fail closed): Code is "invalid_master_key" or "invalid_provider_config". Why: VAULT-11.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
    /// </summary>
    public sealed class VaultConfigException : Exception
    {
        /// <summary>The spec's error code. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public string Code { get; }

        /// <summary>Creates the exception; the message never holds a key. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public VaultConfigException(string code) : base(code) { Code = code; }
    }

    /// <summary>A provider's key rules: prefix, min_length, max_length. Pure data. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public sealed class ProviderConfig
    {
        public string Prefix { get; set; }
        public int MinLength { get; set; }
        public int MaxLength { get; set; }
    }

    /// <summary>
    /// The provider check: "ok" | "rejected" | "unreachable" (the real one makes one read-only call; tests pass a fake).
    /// May throw. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the network in production.
    /// </summary>
    public interface IProviderClient
    {
        /// <summary>Checks one key with its provider. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        string Check(string provider, string key);
    }

    /// <summary>One row of provider_keys. Pure data. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public sealed class ProviderKeyRow
    {
        public string UserId { get; set; }
        public string Provider { get; set; }
        public string KeyId { get; set; }
        public string WrappedDek { get; set; }
        public string Ciphertext { get; set; }
        public string Hint { get; set; }
        public long CreatedAt { get; set; }
        public long? LastUsedAt { get; set; }

        /// <summary>A copy. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public ProviderKeyRow Copy() => (ProviderKeyRow)MemberwiseClone();
    }

    /// <summary>One row of provider_key_audit. Pure data. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public sealed class VaultAuditRow
    {
        public long Id { get; set; }
        public string UserId { get; set; }
        public string Provider { get; set; }
        public string Action { get; set; }
        public string Purpose { get; set; }
        public string KeyId { get; set; }
        public long At { get; set; }
    }

    /// <summary>
    /// A vault answer: Status (HTTP; 200 on success), Error on a refusal, and the fields the function names. A refusal
    /// never carries the key. Pure data. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    public sealed class VaultResult
    {
        public int Status { get; set; } = 200;
        public string Error { get; set; }
        public bool Ok => Error == null;
        public long? RetryAfter { get; set; }
        public string Provider { get; set; }
        public string Hint { get; set; }
        public string KeyId { get; set; }
        public long? CreatedAt { get; set; }
        public string Key { get; set; }
        public bool? Deleted { get; set; }

        /// <summary>A refusal. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public static VaultResult Fail(int status, string error, long? retryAfter = null) =>
            new VaultResult { Status = status, Error = error, RetryAfter = retryAfter };
    }

    /// <summary>One entry of list_keys: never the key, the ciphertext or the wrapped DEK. Pure data. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public sealed class KeyListing
    {
        public string Provider { get; set; }
        public string Hint { get; set; }
        public string KeyId { get; set; }
        public long CreatedAt { get; set; }
        public long? LastUsedAt { get; set; }
    }

    /// <summary>
    /// Where the three tables live. Each method is one atomic step; the two-write steps are one transaction (all or
    /// nothing; a failure throws and writes nothing). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
    /// </summary>
    public interface IVaultStore
    {
        /// <summary>The (user, provider) row (a copy), or null. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        ProviderKeyRow GetRow(string userId, string provider);

        /// <summary>The user's rows (copies), sorted by provider (ordinal). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        List<ProviderKeyRow> ListRows(string userId);

        /// <summary>Every row whose key_id is not <paramref name="activeKeyId"/>, in (user_id, provider) ordinal order. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        List<ProviderKeyRow> RowsNotUnder(string activeKeyId);

        /// <summary>One transaction: replace the user's row for the provider and add the audit row key_saved. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        void SaveWithAudit(ProviderKeyRow row, long now);

        /// <summary>One transaction: last_used_at = now and the audit row key_used with the purpose. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        void RecordUse(string userId, string provider, string purpose, string keyId, long now);

        /// <summary>One transaction: delete the row and add key_deleted. Out: false (and no audit row) when there was none. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        bool DeleteWithAudit(string userId, string provider, long now);

        /// <summary>The save-window upsert: insert count 1 or add 1 while the count is under 10. Out: whether a row changed. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        bool BumpSaveWindow(string userId, long windowStart);

        /// <summary>UPDATE SET key_id, wrapped_dek WHERE user, provider AND wrapped_dek = :read, plus key_rewrapped. Out: whether a row changed. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        bool Rewrap(string userId, string provider, string newKeyId, string newWrapped, string wrappedRead, long now);

        /// <summary>The user's audit rows, oldest first. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        List<VaultAuditRow> ListAudit(string userId);
    }

    /// <summary>
    /// IVaultStore in process memory behind one lock. FailAuditWrites makes every transaction that adds an audit row
    /// throw before it changes anything (the VAULT-06 storage failure). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: process memory.
    /// </summary>
    public sealed class InMemoryVaultStore : IVaultStore
    {
        private readonly object _lock = new object();
        private readonly Dictionary<(string, string), ProviderKeyRow> _rows = new Dictionary<(string, string), ProviderKeyRow>();
        private readonly List<VaultAuditRow> _audit = new List<VaultAuditRow>();
        private readonly Dictionary<(string, long), int> _windows = new Dictionary<(string, long), int>();
        private long _nextAudit = 1;

        /// <summary>Test hook: every write with an audit row throws (nothing written). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public bool FailAuditWrites { get; set; }

        /// <summary>Test hook: puts a row as it is (a moved or edited row). Touches: process memory. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public void PutRow(ProviderKeyRow row)
        {
            lock (_lock) _rows[(row.UserId, row.Provider)] = row.Copy();
        }

        /// <summary>Test hook: every audit row of every user, oldest first. Touches: process memory (read). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public List<VaultAuditRow> AllAudit()
        {
            lock (_lock) return _audit.ToList();
        }

        /// <summary>Test hook: every row. Touches: process memory (read). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public List<ProviderKeyRow> AllRows()
        {
            lock (_lock) return _rows.Values.Select(r => r.Copy()).ToList();
        }

        /// <summary>Appends one audit row with the next ascending id (caller holds the lock). Touches: process memory. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private void Audit(string userId, string provider, string action, string purpose, string keyId, long at) =>
            _audit.Add(new VaultAuditRow { Id = _nextAudit++, UserId = userId, Provider = provider, Action = action, Purpose = purpose, KeyId = keyId, At = at });

        /// <summary>Throws when FailAuditWrites is set, before anything is changed (the VAULT-06 storage failure). Touches nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private void FailIfAsked()
        {
            if (FailAuditWrites) throw new InvalidOperationException("audit write failed");
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public ProviderKeyRow GetRow(string userId, string provider)
        {
            lock (_lock) return _rows.TryGetValue((userId, provider), out var r) ? r.Copy() : null;
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public List<ProviderKeyRow> ListRows(string userId)
        {
            lock (_lock) return _rows.Values.Where(r => r.UserId == userId).OrderBy(r => r.Provider, StringComparer.Ordinal).Select(r => r.Copy()).ToList();
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public List<ProviderKeyRow> RowsNotUnder(string activeKeyId)
        {
            lock (_lock)
                return _rows.Values.Where(r => r.KeyId != activeKeyId)
                    .OrderBy(r => r.UserId, StringComparer.Ordinal).ThenBy(r => r.Provider, StringComparer.Ordinal)
                    .Select(r => r.Copy()).ToList();
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public void SaveWithAudit(ProviderKeyRow row, long now)
        {
            lock (_lock)
            {
                FailIfAsked();
                _rows[(row.UserId, row.Provider)] = row.Copy();
                Audit(row.UserId, row.Provider, "key_saved", null, row.KeyId, now);
            }
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public void RecordUse(string userId, string provider, string purpose, string keyId, long now)
        {
            lock (_lock)
            {
                FailIfAsked();
                if (!_rows.TryGetValue((userId, provider), out var r)) throw new InvalidOperationException("row gone");
                r.LastUsedAt = now;
                Audit(userId, provider, "key_used", purpose, keyId, now);
            }
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public bool DeleteWithAudit(string userId, string provider, long now)
        {
            lock (_lock)
            {
                if (!_rows.TryGetValue((userId, provider), out var r)) return false;
                FailIfAsked();
                _rows.Remove((userId, provider));
                Audit(userId, provider, "key_deleted", null, r.KeyId, now);
                return true;
            }
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public bool BumpSaveWindow(string userId, long windowStart)
        {
            lock (_lock)
            {
                _windows.TryGetValue((userId, windowStart), out var count);
                if (count >= ByokKeyVault.SavesPerHour) return false;
                _windows[(userId, windowStart)] = count + 1;
                return true;
            }
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public bool Rewrap(string userId, string provider, string newKeyId, string newWrapped, string wrappedRead, long now)
        {
            lock (_lock)
            {
                if (!_rows.TryGetValue((userId, provider), out var r) || r.WrappedDek != wrappedRead) return false;
                FailIfAsked();
                r.KeyId = newKeyId;
                r.WrappedDek = newWrapped;
                Audit(userId, provider, "key_rewrapped", null, newKeyId, now);
                return true;
            }
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public List<VaultAuditRow> ListAudit(string userId)
        {
            lock (_lock) return _audit.Where(a => a.UserId == userId).OrderBy(a => a.Id).ToList();
        }
    }

    /// <summary>
    /// The vault: save_key, list_keys, use_key, delete_key, rewrap() and list_audit. Written 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1, owner request 2026-11-10). Touches: the store, the provider client.
    /// </summary>
    public sealed class ByokKeyVault
    {
        public const int SavesPerHour = 10;
        private static readonly Regex KeyIdShape = new Regex("^[A-Za-z0-9_-]{1,32}$", RegexOptions.CultureInvariant);
        private static readonly Regex ProviderShape = new Regex("^[a-z0-9_]{1,32}$", RegexOptions.CultureInvariant);

        private readonly IVaultStore _store;
        private readonly Dictionary<string, byte[]> _masterKeys;
        private readonly string _activeKeyId;
        private readonly Dictionary<string, ProviderConfig> _providers;
        private readonly IProviderClient _client;
        private readonly Func<long> _clock;
        private readonly Func<int, byte[]> _randomBytes;

        /// <summary>
        /// Builds the vault. In: the store, master_keys {key_id: 32 bytes}, active_key_id, providers, the provider client,
        /// the clock (Unix seconds) and random_bytes (default: the CSPRNG). Throws VaultConfigException
        /// "invalid_master_key" (a key that is not 32 bytes, a malformed key id, an active id not in the keyring) or
        /// "invalid_provider_config" (bad provider id or lengths). Why: VAULT-11. 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
        /// </summary>
        public ByokKeyVault(IVaultStore store, IDictionary<string, byte[]> masterKeys, string activeKeyId,
            IDictionary<string, ProviderConfig> providers, IProviderClient client, Func<long> clock = null, Func<int, byte[]> randomBytes = null)
        {
            if (masterKeys == null || masterKeys.Count == 0) throw new VaultConfigException("invalid_master_key");
            foreach (var kv in masterKeys)
                if (kv.Key == null || !KeyIdShape.IsMatch(kv.Key) || kv.Value == null || kv.Value.Length != 32)
                    throw new VaultConfigException("invalid_master_key");
            if (activeKeyId == null || !masterKeys.ContainsKey(activeKeyId)) throw new VaultConfigException("invalid_master_key");
            foreach (var kv in providers ?? new Dictionary<string, ProviderConfig>())
            {
                var p = kv.Value;
                if (kv.Key == null || !ProviderShape.IsMatch(kv.Key) || p == null || p.Prefix == null || p.MinLength < 20 ||
                    p.MinLength > p.MaxLength || p.MaxLength > 4096 || p.MinLength < p.Prefix.Length + 16)
                    throw new VaultConfigException("invalid_provider_config");
            }
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _masterKeys = masterKeys.ToDictionary(kv => kv.Key, kv => (byte[])kv.Value.Clone(), StringComparer.Ordinal);
            _activeKeyId = activeKeyId;
            _providers = (providers ?? new Dictionary<string, ProviderConfig>()).ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);
            _client = client ?? throw new ArgumentNullException(nameof(client));
            _clock = clock ?? (() => DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            _randomBytes = randomBytes ?? RandomNumberGenerator.GetBytes;
        }

        /// <summary>
        /// save_key: unknown_provider (404); invalid_key_format (400; only space, tab, CR, LF trimmed; prefix, length,
        /// U+0021-U+007E only); the hourly check window, counted first (429 rate_limited); the provider check (400
        /// key_rejected, 502 provider_unreachable); then the envelope, written with its audit row in one transaction (500
        /// storage_failed). In: the verified user, the provider, the key (null is "not text"). Out: {provider, hint,
        /// key_id, created_at}. Why: VAULT-01..04, 09, 12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the
        /// store, the provider client.
        /// </summary>
        public VaultResult SaveKey(string userId, string provider, string key)
        {
            if (provider == null || !_providers.TryGetValue(provider, out var cfg)) return VaultResult.Fail(404, "unknown_provider");
            if (key == null) return VaultResult.Fail(400, "invalid_key_format");
            var k = TrimAsciiSpace(key);
            if (!k.StartsWith(cfg.Prefix, StringComparison.Ordinal) || k.Length < cfg.MinLength || k.Length > cfg.MaxLength ||
                k.Any(c => c < '!' || c > '~'))
                return VaultResult.Fail(400, "invalid_key_format");
            var now = _clock();
            var w = now - Mod(now, 3600);
            if (!_store.BumpSaveWindow(userId, w)) return VaultResult.Fail(429, "rate_limited", w + 3600 - now);
            string verdict;
            try { verdict = _client.Check(provider, k); }
            catch (Exception) { verdict = null; }
            if (verdict == "rejected") return VaultResult.Fail(400, "key_rejected");
            if (verdict != "ok") return VaultResult.Fail(502, "provider_unreachable");

            var dek = _randomBytes(32);
            var dataNonce = _randomBytes(12);
            var wrapNonce = _randomBytes(12);
            try
            {
                var row = new ProviderKeyRow
                {
                    UserId = userId, Provider = provider, KeyId = _activeKeyId,
                    Ciphertext = Convert.ToBase64String(Gcm(dek, dataNonce, Encoding.UTF8.GetBytes(k), DataAad(provider, userId))),
                    WrappedDek = Convert.ToBase64String(Gcm(_masterKeys[_activeKeyId], wrapNonce, dek, DekAad(_activeKeyId, provider, userId))),
                    Hint = k.Substring(k.Length - 4), CreatedAt = now, LastUsedAt = null,
                };
                _store.SaveWithAudit(row, now);
                return new VaultResult { Provider = provider, Hint = row.Hint, KeyId = row.KeyId, CreatedAt = now };
            }
            catch (Exception)
            {
                return VaultResult.Fail(500, "storage_failed");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(dek);
            }
        }

        /// <summary>list_keys: provider, hint, key_id, created_at, last_used_at, sorted by provider. Touches: the store (read). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public List<KeyListing> ListKeys(string userId) =>
            _store.ListRows(userId).Select(r => new KeyListing
            {
                Provider = r.Provider, Hint = r.Hint, KeyId = r.KeyId, CreatedAt = r.CreatedAt, LastUsedAt = r.LastUsedAt
            }).ToList();

        /// <summary>
        /// use_key (server side only): invalid_purpose (400), key_not_found (404), key_unavailable (503: the row's master
        /// key is not in the keyring), key_unreadable (500: unwrap or decrypt fails, bad base64, short value, a DEK that
        /// is not 32 bytes; never an exception), then last_used_at and the key_used audit row in one transaction
        /// (500 storage_failed and NO key on failure). In: the verified user, the provider, the purpose. Out: {key}.
        /// Why: VAULT-06..08, 11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
        /// </summary>
        public VaultResult UseKey(string userId, string provider, string purpose)
        {
            if (purpose == null || purpose.Length < 1 || purpose.Length > 100 || !purpose.All(IsPurposeChar))
                return VaultResult.Fail(400, "invalid_purpose");
            var row = _store.GetRow(userId, provider);
            if (row == null) return VaultResult.Fail(404, "key_not_found");
            if (!_masterKeys.TryGetValue(row.KeyId ?? "", out var master)) return VaultResult.Fail(503, "key_unavailable");
            var dek = Ungcm(master, row.WrappedDek, DekAad(row.KeyId, provider, userId));
            if (dek == null || dek.Length != 32) return VaultResult.Fail(500, "key_unreadable");
            byte[] plain;
            try { plain = Ungcm(dek, row.Ciphertext, DataAad(provider, userId)); }
            finally { CryptographicOperations.ZeroMemory(dek); }
            if (plain == null) return VaultResult.Fail(500, "key_unreadable");
            string key;
            try { key = new UTF8Encoding(false, true).GetString(plain); }
            catch (Exception) { return VaultResult.Fail(500, "key_unreadable"); }
            try { _store.RecordUse(userId, provider, purpose, row.KeyId, _clock()); }
            catch (Exception) { return VaultResult.Fail(500, "storage_failed"); }
            return new VaultResult { Key = key };
        }

        /// <summary>delete_key: {deleted: true} with key_deleted, or {deleted: false} with no audit row. Why: VAULT-07/13. Touches: the store. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public VaultResult DeleteKey(string userId, string provider)
        {
            try { return new VaultResult { Deleted = _store.DeleteWithAudit(userId, provider, _clock()) }; }
            catch (Exception) { return VaultResult.Fail(500, "storage_failed"); }
        }

        /// <summary>
        /// rewrap() (OPERATOR ONLY): re-wraps every DEK whose key_id is not the active one under the active key, with one
        /// conditional write per row (no change when the row's wrapped_dek moved on), never touching ciphertext. In:
        /// nothing. Out: (rewrapped, failed). Why: VAULT-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
        /// </summary>
        public (int Rewrapped, int Failed) Rewrap()
        {
            int rewrapped = 0, failed = 0;
            foreach (var row in _store.RowsNotUnder(_activeKeyId))
            {
                byte[] dek = null;
                if (row.KeyId != null && _masterKeys.TryGetValue(row.KeyId, out var old))
                    dek = Ungcm(old, row.WrappedDek, DekAad(row.KeyId, row.Provider, row.UserId));
                if (dek == null || dek.Length != 32) { failed++; continue; }
                try
                {
                    var nonce = _randomBytes(12);
                    var wrapped = Convert.ToBase64String(Gcm(_masterKeys[_activeKeyId], nonce, dek, DekAad(_activeKeyId, row.Provider, row.UserId)));
                    if (_store.Rewrap(row.UserId, row.Provider, _activeKeyId, wrapped, row.WrappedDek, _clock())) rewrapped++;
                }
                catch (Exception) { failed++; }
                finally { CryptographicOperations.ZeroMemory(dek); }
            }
            return (rewrapped, failed);
        }

        /// <summary>list_audit: the user's audit rows, oldest first. Touches: the store (read). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public List<VaultAuditRow> ListAudit(string userId) => _store.ListAudit(userId);

        // ------------------------------------------------------------------ helpers

        /// <summary>The data aad "byok:data:" + provider + ":" + user_id. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static string DataAad(string provider, string userId) => "byok:data:" + provider + ":" + userId;
        /// <summary>The DEK aad "byok:dek:" + key_id + ":" + provider + ":" + user_id. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static string DekAad(string keyId, string provider, string userId) => "byok:dek:" + keyId + ":" + provider + ":" + userId;
        /// <summary>A purpose character: [A-Za-z0-9_.:-]. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static bool IsPurposeChar(char c) =>
            (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == ':' || c == '-';
        /// <summary>a mod m, never negative. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static long Mod(long a, long m) => ((a % m) + m) % m;

        /// <summary>Removes leading and trailing space, tab, CR and LF only. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static string TrimAsciiSpace(string s)
        {
            int a = 0, b = s.Length;
            static bool Ws(char c) => c == ' ' || c == '\t' || c == '\r' || c == '\n';
            while (a < b && Ws(s[a])) a++;
            while (b > a && Ws(s[b - 1])) b--;
            return s.Substring(a, b - a);
        }

        /// <summary>nonce + AES-256-GCM(key, nonce, plaintext, aad) + 16-byte tag. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static byte[] Gcm(byte[] key, byte[] nonce, byte[] plaintext, string aad)
        {
            var ct = new byte[plaintext.Length];
            var tag = new byte[16];
            using (var g = new AesGcm(key, 16)) g.Encrypt(nonce, plaintext, ct, tag, Encoding.UTF8.GetBytes(aad));
            return nonce.Concat(ct).Concat(tag).ToArray();
        }

        /// <summary>Opens base64(nonce + ciphertext + tag). Out: the plaintext, or null on bad base64, under 28 bytes or a failed tag. Never throws. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static byte[] Ungcm(byte[] key, string stored, string aad)
        {
            try
            {
                var raw = Convert.FromBase64String(stored ?? "");
                if (raw.Length < 28) return null;
                var pt = new byte[raw.Length - 28];
                using (var g = new AesGcm(key, 16))
                    g.Decrypt(raw.AsSpan(0, 12), raw.AsSpan(12, raw.Length - 28), raw.AsSpan(raw.Length - 16, 16), pt, Encoding.UTF8.GetBytes(aad));
                return pt;
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}

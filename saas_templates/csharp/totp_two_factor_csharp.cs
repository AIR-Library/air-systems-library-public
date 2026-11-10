// TOTP two-factor template (docs/specs/totp_two_factor.md): authenticator-app codes (RFC 4226 HOTP, RFC 6238 TOTP,
// RFC 4648 base32, otpauth:// URI), one step of clock drift each way, a replay guard (last_used_step), a lock after
// 5 failures in 900 seconds counted BEFORE any code is looked at, a hard lock after 100 failures with no success, and
// 8 one-time recovery codes stored only as HMAC-SHA256 under their own key. The TOTP secret is sealed with
// AES-256-GCM (aad "totp:" + user_id).
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1, owner request 2026-11-10).
// Touches: the totp_enrollments, totp_recovery_codes and totp_failures tables behind ITotpStore (process memory in
// InMemoryTotpStore). No network, no money. Never logs a secret, a code, a recovery code or a key.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AOI.TotpTwoFactor
{
    /// <summary>
    /// Construction refused (fail closed): an encryption_key that is not 32 bytes or a recovery_hash_key under 32 bytes
    /// (Code "invalid_key"). In: the code. Why: TOTP-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
    /// </summary>
    public sealed class TotpConfigException : Exception
    {
        /// <summary>The spec's error code, "invalid_key". Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public string Code { get; }

        /// <summary>Creates the exception; the message never holds a key. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public TotpConfigException(string code) : base(code) { Code = code; }
    }

    /// <summary>
    /// The answer of every flow: Status is the HTTP status (200 on success), Error the spec's code on a refusal, plus the
    /// fields the flow names. A refusal is returned, never thrown. Pure data. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    public sealed class TotpResult
    {
        public int Status { get; set; } = 200;
        public string Error { get; set; }
        public bool Ok => Error == null;
        public long? RetryAfter { get; set; }
        public string Method { get; set; }
        public int RecoveryCodesLeft { get; set; }
        public string Secret { get; set; }
        public string OtpauthUri { get; set; }
        public List<string> RecoveryCodes { get; set; }
        public bool Disabled { get; set; }

        /// <summary>A refusal {error, status}. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public static TotpResult Fail(int status, string error, long? retryAfter = null) =>
            new TotpResult { Status = status, Error = error, RetryAfter = retryAfter };
    }

    /// <summary>The answer of status(user_id). Pure data. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public sealed class TotpStatus
    {
        public bool Enrolled { get; set; }
        public long? LockedUntil { get; set; }
        public bool RecoveryRequired { get; set; }
        public int RecoveryCodesLeft { get; set; }
    }

    /// <summary>One row of totp_enrollments. Pure data. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public sealed class TotpEnrollment
    {
        public string UserId { get; set; }
        public string SecretEnc { get; set; }
        public long? ConfirmedAt { get; set; }
        public long LastUsedStep { get; set; }
        public int FailedSinceSuccess { get; set; }
        public long CreatedAt { get; set; }

        /// <summary>A copy, so a caller never edits the stored row. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public TotpEnrollment Copy() => (TotpEnrollment)MemberwiseClone();
    }

    /// <summary>One row of totp_recovery_codes. Pure data. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public sealed class TotpRecoveryCode
    {
        public long Id { get; set; }
        public string UserId { get; set; }
        public string CodeHash { get; set; }
        public long CreatedAt { get; set; }
        public long? UsedAt { get; set; }
    }

    /// <summary>
    /// Where the three tables live. Every method is ONE atomic step (the spec's single statements). Written 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1). Touches: the store.
    /// </summary>
    public interface ITotpStore
    {
        /// <summary>The user's enrollment row (a copy), or null. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        TotpEnrollment GetEnrollment(string userId);

        /// <summary>Writes a fresh unconfirmed row, replacing an unconfirmed one. Out: false (nothing written) when a confirmed row exists. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        bool ReplaceUnconfirmed(string userId, string secretEnc, long now);

        /// <summary>UPDATE ... SET confirmed_at, last_used_step, failed_since_success = 0 WHERE confirmed_at IS NULL AND secret_enc = :read. Out: whether a row changed. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        bool Confirm(string userId, long now, long step, string secretEncRead);

        /// <summary>CLAIM: UPDATE ... SET last_used_step = :step, failed_since_success = 0 WHERE confirmed AND last_used_step &lt; :step. Out: whether a row changed. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        bool Claim(string userId, long step);

        /// <summary>TRY: inserts a failure row when fewer than 5 rows have at &gt; now - 900. Out: the new row's id (the slot), or null (locked). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        long? TrySlot(string userId, long now);

        /// <summary>Deletes one failure row (this call's slot). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        void DeleteSlot(long slotId);

        /// <summary>FAILURE's second statement: failed_since_success + 1. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        void AddFailure(string userId);

        /// <summary>Sets failed_since_success = 0 (a recovery-code success). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        void ResetFailures(string userId);

        /// <summary>The `at` of the user's failure rows, newest first. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        List<long> FailureTimes(string userId);

        /// <summary>Stores the recovery-code hashes of a new set. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        void AddRecoveryCodes(string userId, IEnumerable<string> hashes, long now);

        /// <summary>UPDATE totp_recovery_codes SET used_at = :now WHERE user_id AND code_hash AND used_at IS NULL. Out: whether a row changed. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        bool UseRecoveryCode(string userId, string codeHash, long now);

        /// <summary>The user's recovery-code rows (copies), in insertion order. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        List<TotpRecoveryCode> RecoveryCodes(string userId);

        /// <summary>Deletes the user's enrollment, recovery codes and failures. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        void DeleteAll(string userId);
    }

    /// <summary>
    /// ITotpStore in process memory behind one lock, so each method is atomic (the spec's "a store that cannot make this
    /// one statement atomic runs it while holding a lock"). Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: process memory.
    /// </summary>
    public sealed class InMemoryTotpStore : ITotpStore
    {
        private readonly object _lock = new object();
        private readonly Dictionary<string, TotpEnrollment> _enrollments = new Dictionary<string, TotpEnrollment>(StringComparer.Ordinal);
        private readonly List<TotpRecoveryCode> _codes = new List<TotpRecoveryCode>();
        private readonly List<(long Id, string UserId, long At)> _failures = new List<(long, string, long)>();
        private long _nextId = 1;

        /// <summary>Test hook: overwrites the stored secret_enc (a damaged or re-keyed row). Touches: process memory. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public void SetSecretEnc(string userId, string secretEnc)
        {
            lock (_lock) if (_enrollments.TryGetValue(userId, out var r)) r.SecretEnc = secretEnc;
        }

        /// <summary>Test hook: the number of failure rows the user has. Touches: process memory (read). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public int FailureCount(string userId)
        {
            lock (_lock) return _failures.Count(f => f.UserId == userId);
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public TotpEnrollment GetEnrollment(string userId)
        {
            lock (_lock) return _enrollments.TryGetValue(userId, out var r) ? r.Copy() : null;
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public bool ReplaceUnconfirmed(string userId, string secretEnc, long now)
        {
            lock (_lock)
            {
                if (_enrollments.TryGetValue(userId, out var r) && r.ConfirmedAt != null) return false;
                _enrollments[userId] = new TotpEnrollment
                {
                    UserId = userId, SecretEnc = secretEnc, ConfirmedAt = null, LastUsedStep = 0, FailedSinceSuccess = 0, CreatedAt = now
                };
                return true;
            }
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public bool Confirm(string userId, long now, long step, string secretEncRead)
        {
            lock (_lock)
            {
                if (!_enrollments.TryGetValue(userId, out var r) || r.ConfirmedAt != null || r.SecretEnc != secretEncRead) return false;
                r.ConfirmedAt = now;
                r.LastUsedStep = step;
                r.FailedSinceSuccess = 0;
                return true;
            }
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public bool Claim(string userId, long step)
        {
            lock (_lock)
            {
                if (!_enrollments.TryGetValue(userId, out var r) || r.ConfirmedAt == null || r.LastUsedStep >= step) return false;
                r.LastUsedStep = step;
                r.FailedSinceSuccess = 0;
                return true;
            }
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public long? TrySlot(string userId, long now)
        {
            lock (_lock)
            {
                if (_failures.Count(f => f.UserId == userId && f.At > now - TotpTwoFactor.LockSeconds) >= TotpTwoFactor.LockFailures) return null;
                var id = _nextId++;
                _failures.Add((id, userId, now));
                return id;
            }
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public void DeleteSlot(long slotId)
        {
            lock (_lock) _failures.RemoveAll(f => f.Id == slotId);
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public void AddFailure(string userId)
        {
            lock (_lock) if (_enrollments.TryGetValue(userId, out var r)) r.FailedSinceSuccess++;
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public void ResetFailures(string userId)
        {
            lock (_lock) if (_enrollments.TryGetValue(userId, out var r)) r.FailedSinceSuccess = 0;
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public List<long> FailureTimes(string userId)
        {
            lock (_lock) return _failures.Where(f => f.UserId == userId).OrderByDescending(f => f.At).ThenByDescending(f => f.Id).Select(f => f.At).ToList();
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public void AddRecoveryCodes(string userId, IEnumerable<string> hashes, long now)
        {
            lock (_lock)
                foreach (var h in hashes)
                    _codes.Add(new TotpRecoveryCode { Id = _nextId++, UserId = userId, CodeHash = h, CreatedAt = now });
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public bool UseRecoveryCode(string userId, string codeHash, long now)
        {
            lock (_lock)
            {
                var row = _codes.FirstOrDefault(c => c.UserId == userId && c.UsedAt == null &&
                    CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(c.CodeHash), Encoding.ASCII.GetBytes(codeHash)));
                if (row == null) return false;
                row.UsedAt = now;
                return true;
            }
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public List<TotpRecoveryCode> RecoveryCodes(string userId)
        {
            lock (_lock)
                return _codes.Where(c => c.UserId == userId)
                    .Select(c => new TotpRecoveryCode { Id = c.Id, UserId = c.UserId, CodeHash = c.CodeHash, CreatedAt = c.CreatedAt, UsedAt = c.UsedAt })
                    .ToList();
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public void DeleteAll(string userId)
        {
            lock (_lock)
            {
                _enrollments.Remove(userId);
                _codes.RemoveAll(c => c.UserId == userId);
                _failures.RemoveAll(f => f.UserId == userId);
            }
        }
    }

    /// <summary>
    /// The TOTP two-factor system: pure functions (base32, hotp, totp_at, otpauth_uri, seal, open) and the flows
    /// enroll_start, enroll_confirm, verify, disable and status. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
    /// (Phase D wave 1, owner request 2026-11-10). Touches: the injected store; no network.
    /// </summary>
    public sealed class TotpTwoFactor
    {
        public const int Step = 30, Digits = 6, Window = 1, LockFailures = 5, LockSeconds = 900, HardLockFailures = 100, RecoveryCodeCount = 8;
        public const string RecoveryAlphabet = "23456789abcdefghjkmnpqrstvwxyz";
        private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        private readonly ITotpStore _store;
        private readonly byte[] _encryptionKey;
        private readonly byte[] _recoveryHashKey;
        private readonly string _issuer;
        private readonly Func<long> _clock;
        private readonly Func<int, byte[]> _randomBytes;

        /// <summary>
        /// Builds the system. In: the store, encryption_key (exactly 32 bytes), recovery_hash_key (at least 32 bytes), the
        /// issuer, the clock (Unix seconds) and random_bytes(n) (default: the system CSPRNG). Throws TotpConfigException
        /// ("invalid_key") on a key of the wrong size (TOTP-11, fail closed). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// Touches nothing.
        /// </summary>
        public TotpTwoFactor(ITotpStore store, byte[] encryptionKey, byte[] recoveryHashKey, string issuer,
            Func<long> clock = null, Func<int, byte[]> randomBytes = null)
        {
            if (encryptionKey == null || encryptionKey.Length != 32) throw new TotpConfigException("invalid_key");
            if (recoveryHashKey == null || recoveryHashKey.Length < 32) throw new TotpConfigException("invalid_key");
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _encryptionKey = (byte[])encryptionKey.Clone();
            _recoveryHashKey = (byte[])recoveryHashKey.Clone();
            _issuer = issuer ?? "";
            _clock = clock ?? (() => DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            _randomBytes = randomBytes ?? RandomNumberGenerator.GetBytes;
        }

        // ------------------------------------------------------------------ pure functions

        /// <summary>RFC 4648 base32, upper case, no "=" padding. In: bytes. Out: text. Why: TOTP-02. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public static string Base32Encode(byte[] data)
        {
            var sb = new StringBuilder();
            int buffer = 0, bits = 0;
            foreach (var b in data)
            {
                buffer = (buffer << 8) | b;
                bits += 8;
                while (bits >= 5)
                {
                    sb.Append(Base32Alphabet[(buffer >> (bits - 5)) & 31]);
                    bits -= 5;
                }
            }
            if (bits > 0) sb.Append(Base32Alphabet[(buffer << (5 - bits)) & 31]);
            return sb.ToString();
        }

        /// <summary>
        /// Base32 decode: removes ASCII spaces, "-" and "=", maps a-z to A-Z; every remaining character must be in the
        /// alphabet, at least one must remain, and a length of 1, 3 or 6 modulo 8 is refused. Leftover bits are dropped.
        /// In: text. Out: the bytes, or null (invalid_base32). Why: TOTP-02. Pure.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        public static byte[] Base32Decode(string text)
        {
            if (text == null) return null;
            var clean = new StringBuilder();
            foreach (var ch in text)
            {
                if (ch == ' ' || ch == '-' || ch == '=') continue;
                var c = ch >= 'a' && ch <= 'z' ? (char)(ch - 32) : ch;
                if (Base32Alphabet.IndexOf(c) < 0) return null;
                clean.Append(c);
            }
            var n = clean.Length;
            if (n == 0 || n % 8 == 1 || n % 8 == 3 || n % 8 == 6) return null;
            var output = new List<byte>();
            int buffer = 0, bits = 0;
            for (var i = 0; i < n; i++)
            {
                buffer = ((buffer << 5) | Base32Alphabet.IndexOf(clean[i])) & 0xFFFF;
                bits += 5;
                if (bits >= 8)
                {
                    output.Add((byte)((buffer >> (bits - 8)) & 0xFF));
                    bits -= 8;
                }
            }
            return output.ToArray();
        }

        /// <summary>
        /// RFC 4226 HOTP: HMAC-SHA1 over the 8-byte big-endian counter, dynamic truncation, mod 10^digits, zero-padded.
        /// In: key bytes, a 64-bit counter, digits. Out: the code text. Why: TOTP-01 (a counter above 32 bits). Pure.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        public static string Hotp(byte[] key, long counter, int digits = Digits)
        {
            var msg = new byte[8];
            for (var i = 7; i >= 0; i--) { msg[i] = (byte)(counter & 0xFF); counter >>= 8; }
            var mac = HMACSHA1.HashData(key, msg);
            var o = mac[19] & 0x0F;
            long v = ((mac[o] & 0x7F) << 24) | (mac[o + 1] << 16) | (mac[o + 2] << 8) | mac[o + 3];
            long mod = 1;
            for (var i = 0; i < digits; i++) mod *= 10;
            return (v % mod).ToString().PadLeft(digits, '0');
        }

        /// <summary>RFC 6238 TOTP: hotp(base32_decode(secret), floor(unix_time / 30), digits). In: the secret, the time, digits. Out: the code, or null for a bad secret. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public static string TotpAt(string secretBase32, long unixTime, int digits = Digits)
        {
            var key = Base32Decode(secretBase32);
            return key == null ? null : Hotp(key, FloorDiv(unixTime, Step), digits);
        }

        /// <summary>
        /// The otpauth:// URI authenticator apps read. In: the secret, issuer and account label. Out: the URI, with pct()
        /// encoding every UTF-8 byte outside [A-Za-z0-9._~-] as %XX upper-case. Why: TOTP-03. Pure.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        public static string OtpauthUri(string secret, string issuer, string accountLabel) =>
            "otpauth://totp/" + Pct(issuer + ":" + accountLabel) + "?secret=" + secret + "&issuer=" + Pct(issuer)
            + "&algorithm=SHA1&digits=6&period=30";

        /// <summary>Percent-encodes every UTF-8 byte that is not in [A-Za-z0-9._~-]. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static string Pct(string s)
        {
            var sb = new StringBuilder();
            foreach (var b in Encoding.UTF8.GetBytes(s))
            {
                var c = (char)b;
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '~' || c == '-')
                    sb.Append(c);
                else
                    sb.Append('%').Append(b.ToString("X2"));
            }
            return sb.ToString();
        }

        /// <summary>
        /// AES-256-GCM seal: "v1." + base64(nonce12 + ciphertext + 16-byte tag), aad = UTF-8 of the aad text. In: the
        /// 32-byte key, the 12-byte nonce, the plaintext and the aad. Out: the sealed text. Why: TOTP-03/11. Pure.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        public static string Seal(byte[] key32, byte[] nonce12, string plaintext, string aad)
        {
            var pt = Encoding.UTF8.GetBytes(plaintext);
            var ct = new byte[pt.Length];
            var tag = new byte[16];
            using (var gcm = new AesGcm(key32, 16)) gcm.Encrypt(nonce12, pt, ct, tag, Encoding.UTF8.GetBytes(aad));
            return "v1." + Convert.ToBase64String(nonce12.Concat(ct).Concat(tag).ToArray());
        }

        /// <summary>
        /// Opens a sealed text. Out: the plaintext, or null for a missing "v1." prefix, bad base64, fewer than 28 bytes,
        /// or a tag that does not verify (wrong key, wrong aad, any changed byte). Never throws. Why: TOTP-10/11. Pure.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        public static string Open(byte[] key32, string sealedText, string aad)
        {
            try
            {
                if (key32 == null || key32.Length != 32 || sealedText == null || !sealedText.StartsWith("v1.", StringComparison.Ordinal)) return null;
                var raw = Convert.FromBase64String(sealedText.Substring(3));
                if (raw.Length < 28) return null;
                var nonce = raw.AsSpan(0, 12);
                var tag = raw.AsSpan(raw.Length - 16, 16);
                var ct = raw.AsSpan(12, raw.Length - 28);
                var pt = new byte[ct.Length];
                using (var gcm = new AesGcm(key32, 16)) gcm.Decrypt(nonce, ct, tag, pt, Encoding.UTF8.GetBytes(aad));
                return new UTF8Encoding(false, true).GetString(pt);
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>base32_encode(random_bytes(20)): 32 characters. Touches: the injected random source. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public string GenerateSecret() => Base32Encode(_randomBytes(20));

        /// <summary>
        /// Lower-case hex HMAC-SHA256(recovery_hash_key, "recovery:" + user_id + ":" + the RECOVERY INPUT form). In: the
        /// user and the normalised code. Out: the stored hash. Why: TOTP-08. Pure.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        public string RecoveryCodeHash(string userId, string recoveryInput) =>
            Convert.ToHexString(HMACSHA256.HashData(_recoveryHashKey, Encoding.UTF8.GetBytes("recovery:" + userId + ":" + recoveryInput))).ToLowerInvariant();

        // ------------------------------------------------------------------ flows

        /// <summary>
        /// enroll_start: 409 already_enrolled when a confirmed enrollment exists; otherwise draws the secret (20 bytes) and
        /// the nonce (12 bytes), stores only the sealed secret (replacing an unconfirmed row) and returns the secret and
        /// the otpauth URI. In: the verified user and the account label. Why: TOTP-03/04. 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: totp_enrollments.
        /// </summary>
        public TotpResult EnrollStart(string userId, string accountLabel)
        {
            var row = _store.GetEnrollment(userId);
            if (row?.ConfirmedAt != null) return TotpResult.Fail(409, "already_enrolled");
            var secret = GenerateSecret();
            var nonce = _randomBytes(12);
            var sealedSecret = Seal(_encryptionKey, nonce, secret, "totp:" + userId);
            if (!_store.ReplaceUnconfirmed(userId, sealedSecret, _clock())) return TotpResult.Fail(409, "already_enrolled");
            return new TotpResult { Secret = secret, OtpauthUri = OtpauthUri(secret, _issuer, accountLabel ?? "") };
        }

        /// <summary>
        /// enroll_confirm: the checks of the spec in order (enrollment_not_started, already_enrolled, TRY, TOTP INPUT,
        /// secret_unreadable, MATCH, the conditional confirm), then 8 recovery codes whose keyed hashes are stored. In: the
        /// user and the code. Out: {recovery_codes} or a refusal. Why: TOTP-04. 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: all three tables.
        /// </summary>
        public TotpResult EnrollConfirm(string userId, string code)
        {
            var row = _store.GetEnrollment(userId);
            if (row == null) return TotpResult.Fail(409, "enrollment_not_started");
            if (row.ConfirmedAt != null) return TotpResult.Fail(409, "already_enrolled");
            var now = _clock();
            var slot = _store.TrySlot(userId, now);
            if (slot == null) return Locked(userId, now);
            var input = TotpInput(code);
            if (input == null) return Failure(userId);
            var secret = Open(_encryptionKey, row.SecretEnc, "totp:" + userId);
            var key = secret == null ? null : Base32Decode(secret);
            if (key == null) return NotAFailure(slot.Value, TotpResult.Fail(503, "secret_unreadable"));
            var step = Match(key, input, now);
            if (step == null) return Failure(userId);
            if (!_store.Confirm(userId, now, step.Value, row.SecretEnc))
            {
                if (_store.GetEnrollment(userId)?.ConfirmedAt != null) return NotAFailure(slot.Value, TotpResult.Fail(409, "already_enrolled"));
                return Failure(userId);
            }
            var codes = MakeRecoveryCodes();
            _store.AddRecoveryCodes(userId, codes.Select(c => RecoveryCodeHash(userId, RecoveryInput(c))), now);
            return NotAFailure(slot.Value, new TotpResult { RecoveryCodes = codes });
        }

        /// <summary>
        /// verify: not_enrolled, TRY (429 locked, no failure added), then a TOTP INPUT (recovery_required at 100
        /// failures, secret_unreadable, MATCH above last_used_step, CLAIM) or a RECOVERY INPUT (one conditional use), else
        /// invalid_code. In: the verified user and the code (null is "missing"). Out: {ok, method, recovery_codes_left} or
        /// a refusal. Why: TOTP-05..10, 13, 14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: all three tables.
        /// </summary>
        public TotpResult Verify(string userId, string code)
        {
            var (result, _) = Check(userId, code);
            return result;
        }

        /// <summary>
        /// disable: steps 1 to 5 of verify with the same answers; on ok deletes the user's enrollment, recovery codes and
        /// failures. In: the user and a code. Out: {disabled: true} or the refusal. Why: TOTP-12. 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: all three tables.
        /// </summary>
        public TotpResult Disable(string userId, string code)
        {
            var (result, ok) = Check(userId, code);
            if (!ok) return result;
            _store.DeleteAll(userId);
            return new TotpResult { Disabled = true };
        }

        /// <summary>
        /// status: enrolled (a confirmed row), locked_until (the 5th most recent failure in the window + 900), whether a
        /// recovery code is required (100 failures) and the unused recovery codes. Reads only. Why: auth_system's
        /// mfa_enabled_check. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store (read).
        /// </summary>
        public TotpStatus Status(string userId)
        {
            var row = _store.GetEnrollment(userId);
            var now = _clock();
            var times = _store.FailureTimes(userId).Where(t => t > now - LockSeconds).ToList();
            return new TotpStatus
            {
                Enrolled = row?.ConfirmedAt != null,
                LockedUntil = times.Count >= LockFailures ? times[LockFailures - 1] + LockSeconds : (long?)null,
                RecoveryRequired = row?.ConfirmedAt != null && row.FailedSinceSuccess >= HardLockFailures,
                RecoveryCodesLeft = _store.RecoveryCodes(userId).Count(c => c.UsedAt == null),
            };
        }

        // ------------------------------------------------------------------ helpers

        /// <summary>Steps 1 to 5 of verify. Out: the answer and whether it is ok. Touches: all three tables. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private (TotpResult, bool) Check(string userId, string code)
        {
            var row = _store.GetEnrollment(userId);
            if (row == null || row.ConfirmedAt == null) return (TotpResult.Fail(409, "not_enrolled"), false);
            var now = _clock();
            var slot = _store.TrySlot(userId, now);
            if (slot == null) return (Locked(userId, now), false);

            var totp = TotpInput(code);
            if (totp != null)
            {
                if (row.FailedSinceSuccess >= HardLockFailures) return (NotAFailure(slot.Value, TotpResult.Fail(429, "recovery_required")), false);
                var secret = Open(_encryptionKey, row.SecretEnc, "totp:" + userId);
                var key = secret == null ? null : Base32Decode(secret);
                if (key == null) return (NotAFailure(slot.Value, TotpResult.Fail(503, "secret_unreadable")), false);
                var step = Match(key, totp, now);
                if (step == null || step.Value <= row.LastUsedStep) return (Failure(userId), false);
                if (!_store.Claim(userId, step.Value)) return (Failure(userId), false);
                return (NotAFailure(slot.Value, Success(userId, "totp")), true);
            }
            var recovery = RecoveryInput(code);
            if (recovery != null)
            {
                if (!_store.UseRecoveryCode(userId, RecoveryCodeHash(userId, recovery), now)) return (Failure(userId), false);
                _store.ResetFailures(userId);
                return (NotAFailure(slot.Value, Success(userId, "recovery_code")), true);
            }
            return (Failure(userId), false);
        }

        /// <summary>An ok answer with the unused recovery codes counted after this call. Touches: the store (read). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private TotpResult Success(string userId, string method) =>
            new TotpResult { Method = method, RecoveryCodesLeft = _store.RecoveryCodes(userId).Count(c => c.UsedAt == null) };

        /// <summary>FAILURE: the slot row stays (it is the failure) and failed_since_success + 1. Out: 401 invalid_code. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private TotpResult Failure(string userId)
        {
            _store.AddFailure(userId);
            return TotpResult.Fail(401, "invalid_code");
        }

        /// <summary>Every answer that is not a FAILURE deletes this call's slot row, and only it. Out: the answer. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private TotpResult NotAFailure(long slotId, TotpResult answer)
        {
            _store.DeleteSlot(slotId);
            return answer;
        }

        /// <summary>429 locked with retry_after = (the 5th most recent failure in the window) + 900 - now. Touches: the store (read). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private TotpResult Locked(string userId, long now)
        {
            var times = _store.FailureTimes(userId).Where(t => t > now - LockSeconds).ToList();
            var at = times.Count >= LockFailures ? times[LockFailures - 1] : now;
            return TotpResult.Fail(429, "locked", at + LockSeconds - now);
        }

        /// <summary>TOTP INPUT: at most 64 characters; without ASCII spaces and "-" exactly 6 characters 0-9. Out: the digits, or null. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static string TotpInput(string code)
        {
            if (code == null || code.Length > 64) return null;
            var s = new string(code.Where(c => c != ' ' && c != '-').ToArray());
            return s.Length == 6 && s.All(c => c >= '0' && c <= '9') ? s : null;
        }

        /// <summary>RECOVERY INPUT: at most 64 characters; A-Z to a-z, no ASCII spaces or "-", exactly 12 symbols of the alphabet. Out: the form, or null. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static string RecoveryInput(string code)
        {
            if (code == null || code.Length > 64) return null;
            var sb = new StringBuilder();
            foreach (var ch in code)
            {
                if (ch == ' ' || ch == '-') continue;
                sb.Append(ch >= 'A' && ch <= 'Z' ? (char)(ch + 32) : ch);
            }
            var s = sb.ToString();
            return s.Length == 12 && s.All(c => RecoveryAlphabet.IndexOf(c) >= 0) ? s : null;
        }

        /// <summary>
        /// MATCH: compares hotp(key, s + d) for d = -1, 0, +1 (s + d &gt;= 0) with the input in constant time, ALL of
        /// them, and returns the LARGEST step that was equal, or null. Pure.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        private static long? Match(byte[] key, string input, long now)
        {
            var s = FloorDiv(now, Step);
            long? found = null;
            var given = Encoding.ASCII.GetBytes(input);
            for (var d = -Window; d <= Window; d++)
            {
                var step = s + d;
                if (step < 0) continue;
                if (CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Hotp(key, step)), given)) found = step;
            }
            return found;
        }

        /// <summary>
        /// 8 recovery codes, each 12 symbols drawn one byte at a time (random_bytes(1); b &gt;= 240 drawn again; symbol =
        /// alphabet[b mod 30]); a repeat of an earlier code of the set is dropped. Out: codes as xxxx-xxxx-xxxx.
        /// Touches: the injected random source.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        private List<string> MakeRecoveryCodes()
        {
            var codes = new List<string>();
            while (codes.Count < RecoveryCodeCount)
            {
                var sb = new StringBuilder();
                while (sb.Length < 12)
                {
                    var b = _randomBytes(1)[0];
                    if (b >= 240) continue;
                    sb.Append(RecoveryAlphabet[b % 30]);
                }
                var s = sb.ToString();
                var code = s.Substring(0, 4) + "-" + s.Substring(4, 4) + "-" + s.Substring(8, 4);
                if (!codes.Contains(code)) codes.Add(code);
            }
            return codes;
        }

        /// <summary>floor(a / b) for a 64-bit a and positive b. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static long FloorDiv(long a, long b) => a >= 0 ? a / b : -((-a + b - 1) / b);
    }
}

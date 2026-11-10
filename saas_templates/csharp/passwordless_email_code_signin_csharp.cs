// Passwordless email-code sign-in template (docs/specs/passwordless_email_code_signin.md): sign in, and sign up, with
// a 6-digit code sent by email. One code per address at a time, valid 600 seconds, usable once, 5 tries counted
// before the compare, limits per IP and per address in clock hours and days, the same answer whether or not the
// address has an account. The code, the address and the IP are stored only as HMAC-SHA256 under the server's secret.
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1, owner request 2026-11-10).
// Touches: accounts, email_codes and rate_windows behind IEmailCodeStore (process memory in InMemoryEmailCodeStore);
// the injected sender (email, the network, in production). Never logs the code, the address or the secret.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AOI.PasswordlessEmailCode
{
    /// <summary>
    /// Construction refused (fail closed): a secret under 32 bytes or no sender (Code "not_configured"). Why:
    /// EMAILCODE-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
    /// </summary>
    public sealed class EmailCodeConfigException : Exception
    {
        /// <summary>The spec's error code, "not_configured". Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public string Code { get; }

        /// <summary>Creates the exception; the message never holds the secret. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public EmailCodeConfigException(string code) : base(code) { Code = code; }
    }

    /// <summary>
    /// Sends the code: true when the mail was accepted, false (or an exception) otherwise. Tests pass a fake that records
    /// its calls. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: email (network) in production.
    /// </summary>
    public interface ICodeSender
    {
        /// <summary>Sends <paramref name="code"/> to <paramref name="to"/>; must not log the code. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        bool SendCode(string to, string code, int expiresInSeconds);
    }

    /// <summary>One row of accounts. Status is 'active', 'suspended' or 'closed'. Pure data. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public sealed class Account
    {
        public string Id { get; set; }
        public string Email { get; set; }
        public long? EmailVerifiedAt { get; set; }
        public string Status { get; set; } = "active";
        public long CreatedAt { get; set; }

        /// <summary>A copy. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public Account Copy() => (Account)MemberwiseClone();
    }

    /// <summary>One row of email_codes. Pure data. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public sealed class EmailCodeRow
    {
        public string EmailHash { get; set; }
        public string CodeHash { get; set; }
        public long ExpiresAt { get; set; }
        public int Attempts { get; set; }
        public long CreatedAt { get; set; }

        /// <summary>A copy. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public EmailCodeRow Copy() => (EmailCodeRow)MemberwiseClone();
    }

    /// <summary>
    /// A start or verify answer: Status (HTTP), Error on a refusal, and the fields the endpoint names. Pure data.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    public sealed class EmailCodeResult
    {
        public int Status { get; set; }
        public string Error { get; set; }
        public bool Sent { get; set; }
        public int? ExpiresIn { get; set; }
        public string AccountId { get; set; }
        public string Email { get; set; }
        public bool? NewAccount { get; set; }

        /// <summary>A refusal. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public static EmailCodeResult Fail(int status, string error) => new EmailCodeResult { Status = status, Error = error };
    }

    /// <summary>
    /// The three tables. Each method is ONE atomic step (the spec's single statements). The account methods are the
    /// small interface onto auth_system's users table. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
    /// </summary>
    public interface IEmailCodeStore
    {
        /// <summary>BUMP: inserts (key, window_start, 1) or adds 1. Out: the count after it. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        int Bump(string key, long windowStart);

        /// <summary>Writes the address's code row, replacing an earlier one. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        void PutCode(EmailCodeRow row);

        /// <summary>DELETE FROM email_codes WHERE email_hash = :h AND code_hash = :c. Out: rows deleted. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        int DeleteCode(string emailHash, string codeHash);

        /// <summary>
        /// UPDATE email_codes SET attempts = attempts + 1 WHERE email_hash = :h AND attempts &lt; 5 AND expires_at &gt; :now,
        /// returning the stored code_hash and the new attempts, or null when no row changed.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        (string CodeHash, int Attempts)? CountTry(string emailHash, long now);

        /// <summary>Deletes the address's row when it is expired (expires_at &lt;= now) or used up (attempts &gt;= 5). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        void DeleteIfDead(string emailHash, long now);

        /// <summary>Deletes the address's row (the 5th wrong try). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        void DeleteRow(string emailHash);

        /// <summary>The account with this email, or null. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        Account FindAccount(string email);

        /// <summary>Inserts the account unless a row with that email exists. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        void InsertAccountIfAbsent(Account account);

        /// <summary>Sets email_verified_at = now. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        void MarkVerified(string accountId, long now);
    }

    /// <summary>
    /// IEmailCodeStore in process memory behind one lock. AccountReads counts reads of accounts (EMAILCODE-07: start
    /// never reads them). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    public sealed class InMemoryEmailCodeStore : IEmailCodeStore
    {
        private readonly object _lock = new object();
        private readonly Dictionary<string, EmailCodeRow> _codes = new Dictionary<string, EmailCodeRow>(StringComparer.Ordinal);
        private readonly Dictionary<(string, long), int> _windows = new Dictionary<(string, long), int>();
        private readonly List<Account> _accounts = new List<Account>();

        /// <summary>How many times accounts were read. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public int AccountReads;

        /// <summary>Test hook: the code row of an email hash (a copy), or null. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public EmailCodeRow GetCode(string emailHash)
        {
            lock (_lock) return _codes.TryGetValue(emailHash, out var r) ? r.Copy() : null;
        }

        /// <summary>Test hook: every code row. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public List<EmailCodeRow> AllCodes()
        {
            lock (_lock) return _codes.Values.Select(r => r.Copy()).ToList();
        }

        /// <summary>Test hook: every rate window as (key, window_start, count). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public List<(string Key, long WindowStart, int Count)> AllWindows()
        {
            lock (_lock) return _windows.Select(kv => (kv.Key.Item1, kv.Key.Item2, kv.Value)).ToList();
        }

        /// <summary>Test hook: adds an account as it is (an invitation, a suspended account). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public void PutAccount(Account a)
        {
            lock (_lock) _accounts.Add(a.Copy());
        }

        /// <summary>Test hook: every account (copies), without counting a read. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public List<Account> AllAccounts()
        {
            lock (_lock) return _accounts.Select(a => a.Copy()).ToList();
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public int Bump(string key, long windowStart)
        {
            lock (_lock)
            {
                _windows.TryGetValue((key, windowStart), out var c);
                _windows[(key, windowStart)] = c + 1;
                return c + 1;
            }
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public void PutCode(EmailCodeRow row)
        {
            lock (_lock) _codes[row.EmailHash] = row.Copy();
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public int DeleteCode(string emailHash, string codeHash)
        {
            lock (_lock)
            {
                if (_codes.TryGetValue(emailHash, out var r) && r.CodeHash == codeHash) { _codes.Remove(emailHash); return 1; }
                return 0;
            }
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public (string CodeHash, int Attempts)? CountTry(string emailHash, long now)
        {
            lock (_lock)
            {
                if (!_codes.TryGetValue(emailHash, out var r) || r.Attempts >= PasswordlessEmailCode.CodeAttempts || r.ExpiresAt <= now) return null;
                r.Attempts++;
                return (r.CodeHash, r.Attempts);
            }
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public void DeleteIfDead(string emailHash, long now)
        {
            lock (_lock)
                if (_codes.TryGetValue(emailHash, out var r) && (r.ExpiresAt <= now || r.Attempts >= PasswordlessEmailCode.CodeAttempts))
                    _codes.Remove(emailHash);
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public void DeleteRow(string emailHash)
        {
            lock (_lock) _codes.Remove(emailHash);
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public Account FindAccount(string email)
        {
            lock (_lock)
            {
                AccountReads++;
                return _accounts.FirstOrDefault(a => a.Email == email)?.Copy();
            }
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public void InsertAccountIfAbsent(Account account)
        {
            lock (_lock)
                if (!_accounts.Any(a => a.Email == account.Email)) _accounts.Add(account.Copy());
        }

        /// <inheritdoc/> <!-- Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. -->
        public void MarkVerified(string accountId, long now)
        {
            lock (_lock)
            {
                var a = _accounts.FirstOrDefault(x => x.Id == accountId);
                if (a != null) a.EmailVerifiedAt = now;
            }
        }
    }

    /// <summary>
    /// The sign-in system: start and verify, with the helpers the spec names. Written 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1, owner request 2026-11-10). Touches: the store and the sender.
    /// </summary>
    public sealed class PasswordlessEmailCode
    {
        public const int CodeTtl = 600, CodeAttempts = 5, StartPerEmailHour = 5, StartPerEmailDay = 10, StartPerIpHour = 20,
            VerifyPerIpHour = 30, VerifyPerEmailHour = 10;

        private readonly IEmailCodeStore _store;
        private readonly byte[] _secret;
        private readonly ICodeSender _sender;
        private readonly Action<string> _revokeUnproven;
        private readonly Func<long> _clock;
        private readonly Func<int, byte[]> _randomBytes;
        private readonly Func<string> _generateCode;

        /// <summary>
        /// Builds the system. In: the store, the secret (at least 32 bytes), the sender, revoke_unproven(account_id)
        /// (default: does nothing), the clock (Unix seconds), random_bytes (default: the CSPRNG) and generate_code
        /// (default: CODE). Throws EmailCodeConfigException("not_configured") on a short secret or no sender
        /// (EMAILCODE-12). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
        /// </summary>
        public PasswordlessEmailCode(IEmailCodeStore store, byte[] secret, ICodeSender sender, Action<string> revokeUnproven = null,
            Func<long> clock = null, Func<int, byte[]> randomBytes = null, Func<string> generateCode = null)
        {
            if (secret == null || secret.Length < 32 || sender == null) throw new EmailCodeConfigException("not_configured");
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _secret = (byte[])secret.Clone();
            _sender = sender;
            _revokeUnproven = revokeUnproven ?? (_ => { });
            _clock = clock ?? (() => DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            _randomBytes = randomBytes ?? RandomNumberGenerator.GetBytes;
            _generateCode = generateCode ?? GenerateCode;
        }

        // ------------------------------------------------------------------ helpers the spec names

        /// <summary>
        /// normalize_email: trims only space, tab, CR, LF; maps only A-Z to a-z; 3 to 254 characters matching the whole of
        /// [a-z0-9][a-z0-9._%+=-]*@[a-z0-9-]+(\.[a-z0-9-]+)+ (checked by hand, no regex). Out: the address or null. Pure.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        public static string NormalizeEmail(string raw)
        {
            if (raw == null) return null;
            int a = 0, b = raw.Length;
            static bool Ws(char c) => c == ' ' || c == '\t' || c == '\r' || c == '\n';
            while (a < b && Ws(raw[a])) a++;
            while (b > a && Ws(raw[b - 1])) b--;
            var sb = new StringBuilder();
            for (var i = a; i < b; i++) sb.Append(raw[i] >= 'A' && raw[i] <= 'Z' ? (char)(raw[i] + 32) : raw[i]);
            var e = sb.ToString();
            if (e.Length < 3 || e.Length > 254) return null;
            static bool Alnum(char c) => (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
            var at = e.IndexOf('@');
            if (at < 1) return null;
            var local = e.Substring(0, at);
            var domain = e.Substring(at + 1);
            if (!Alnum(local[0])) return null;
            if (!local.All(c => Alnum(c) || "._%+=-".IndexOf(c) >= 0)) return null;
            var labels = domain.Split('.');
            if (labels.Length < 2) return null;
            foreach (var l in labels)
                if (l.Length == 0 || !l.All(c => Alnum(c) || c == '-')) return null;
            return e;
        }

        /// <summary>Lower-case hex HMAC-SHA256(secret, UTF-8 of text). Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public string HmacHex(string text) => Convert.ToHexString(HMACSHA256.HashData(_secret, Encoding.UTF8.GetBytes(text))).ToLowerInvariant();

        /// <summary>email_hash = hmac_hex("email:" + email). Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public string EmailHash(string email) => HmacHex("email:" + email);

        /// <summary>code_hash = hmac_hex("code:" + email_hash(email) + ":" + code). Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public string CodeHash(string email, string code) => HmacHex("code:" + EmailHash(email) + ":" + code);

        /// <summary>ip_hash = the first 32 characters of hmac_hex("ip:" + ip). Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public string IpHash(string ip) => HmacHex("ip:" + ip).Substring(0, 32);

        /// <summary>EK = the first 32 characters of email_hash(email). Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public string Ek(string email) => EmailHash(email).Substring(0, 32);

        /// <summary>
        /// CODE: an unsigned big-endian 32-bit n from random_bytes(4); n &gt;= 4294000000 is drawn again; the code is n mod
        /// 1000000 with 6 digits, leading zeros kept. Why: EMAILCODE-14. Touches: the injected random source.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        public string GenerateCode()
        {
            while (true)
            {
                var b = _randomBytes(4);
                var n = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
                if (n >= 4294000000u) continue;
                return (n % 1000000u).ToString("D6");
            }
        }

        /// <summary>BUMP(key, span) at the clock's window. Touches: rate_windows. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private int Bump(string key, long span, long now) => _store.Bump(key, now - (now % span));

        // ------------------------------------------------------------------ endpoints

        /// <summary>
        /// start: invalid_email (422); the per-IP hour (429); the per-address hour and day, both always bumped (429); then
        /// a fresh code REPLACES the address's earlier one, and the sender gets it (503 send_failed, and only this code
        /// removed, when it returns false or raises). Never reads accounts. In: the email and the client IP ("unknown"
        /// when missing). Out: 202 {sent, expires_in: 600}. Why: EMAILCODE-01, 06..09, 12. 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: email_codes, rate_windows, the sender.
        /// </summary>
        public EmailCodeResult Start(string email, string ip)
        {
            var e = NormalizeEmail(email);
            if (e == null) return EmailCodeResult.Fail(422, "invalid_email");
            ip ??= "unknown";
            var now = _clock();
            if (Bump("start-ip#" + IpHash(ip), 3600, now) > StartPerIpHour) return EmailCodeResult.Fail(429, "too_many_requests");
            var ek = Ek(e);
            var h = Bump("start-email#" + ek, 3600, now);
            var d = Bump("start-email-day#" + ek, 86400, now);
            if (h > StartPerEmailHour || d > StartPerEmailDay) return EmailCodeResult.Fail(429, "too_many_requests");
            var code = _generateCode();
            var emailHash = EmailHash(e);
            var codeHash = CodeHash(e, code);
            _store.PutCode(new EmailCodeRow { EmailHash = emailHash, CodeHash = codeHash, ExpiresAt = now + CodeTtl, Attempts = 0, CreatedAt = now });
            bool sent;
            try { sent = _sender.SendCode(e, code, CodeTtl); }
            catch (Exception) { sent = false; }
            if (!sent)
            {
                _store.DeleteCode(emailHash, codeHash);
                return EmailCodeResult.Fail(503, "send_failed");
            }
            return new EmailCodeResult { Status = 202, Sent = true, ExpiresIn = CodeTtl };
        }

        /// <summary>
        /// verify: the per-IP hour (429); a malformed address or code is invalid_code (400, no try spent); the per-address
        /// hour (429); the try counted first by one conditional write; a wrong code (the 5th deletes the row); the code
        /// used up by one conditional delete; the account found or made (revoke_unproven before an unverified row is
        /// verified; 500 processing_failed when it raises); 403 account_unavailable for a suspended or closed account.
        /// One 400 body for every bad code. In: email, code, client IP. Out: 200 {account_id, email, new_account}. Why:
        /// EMAILCODE-01..05, 07, 10, 11, 13, 14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: all three tables.
        /// </summary>
        public EmailCodeResult Verify(string email, string code, string ip)
        {
            ip ??= "unknown";
            var now = _clock();
            if (Bump("verify-ip#" + IpHash(ip), 3600, now) > VerifyPerIpHour) return EmailCodeResult.Fail(429, "too_many_requests");
            var e = NormalizeEmail(email);
            var c = code == null ? null : new string(code.Where(ch => ch != ' ' && ch != '-').ToArray());
            if (e == null || c == null || c.Length != 6 || !c.All(ch => ch >= '0' && ch <= '9')) return InvalidCode();
            if (Bump("verify-email#" + Ek(e), 3600, now) > VerifyPerEmailHour) return EmailCodeResult.Fail(429, "too_many_requests");
            var h = EmailHash(e);
            var given = Encoding.ASCII.GetBytes(CodeHash(e, c));
            var counted = _store.CountTry(h, now);
            if (counted == null)
            {
                _store.DeleteIfDead(h, now);
                CryptographicOperations.FixedTimeEquals(given, Encoding.ASCII.GetBytes(new string('0', 64)));
                return InvalidCode();
            }
            var (stored, attempts) = counted.Value;
            if (!CryptographicOperations.FixedTimeEquals(given, Encoding.ASCII.GetBytes(stored)))
            {
                if (attempts >= CodeAttempts) _store.DeleteRow(h);
                return InvalidCode();
            }
            if (_store.DeleteCode(h, stored) != 1) return InvalidCode();

            var id = Convert.ToHexString(_randomBytes(16)).ToLowerInvariant();
            _store.InsertAccountIfAbsent(new Account { Id = id, Email = e, EmailVerifiedAt = now, Status = "active", CreatedAt = now });
            var account = _store.FindAccount(e);
            if (account == null) return EmailCodeResult.Fail(500, "processing_failed");
            var isNew = account.Id == id;
            if (!isNew && account.EmailVerifiedAt == null)
            {
                try { _revokeUnproven(account.Id); }
                catch (Exception) { return EmailCodeResult.Fail(500, "processing_failed"); }
                _store.MarkVerified(account.Id, now);
            }
            if (account.Status != "active") return EmailCodeResult.Fail(403, "account_unavailable");
            return new EmailCodeResult { Status = 200, AccountId = account.Id, Email = e, NewAccount = isNew };
        }

        /// <summary>The one 400 answer for every bad, expired, used, exhausted or never-requested code. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static EmailCodeResult InvalidCode() => EmailCodeResult.Fail(400, "invalid_code");
    }
}

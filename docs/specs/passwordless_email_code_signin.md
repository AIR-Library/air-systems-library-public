# Passwordless Email Code Sign-in

Reference contract for `saas_templates/<lang>/passwordless_email_code_signin_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# EMAILCODE-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `EMAILCODE-01` | start answers 202 {sent: true, expires_in: 600} and the sender gets one 6-digit code; verify with it answers 200 with new_account true and the account exists with email_verified_at set; a second sign-in for the address gives the same account_id with new_account false; for a row that exists with email_verified_at null the right code calls revoke_unproven once with its id and then sets email_verified_at, and an account made by verify never calls it |
| `EMAILCODE-02` | storage: with the spec's secret, address and code the stored code_hash is the spec's value; email_codes and rate_windows hold neither the address, the IP nor the code, and no plain SHA-256 of the code |
| `EMAILCODE-03` | single use: the right code a second time is 400 invalid_code |
| `EMAILCODE-04` | expiry: the code is accepted 599 seconds after start and is 400 invalid_code at 600 seconds |
| `EMAILCODE-05` | five tries per code: after 5 wrong codes the right one is 400 invalid_code; after 4 wrong codes the right one, the 5th try, is accepted |
| `EMAILCODE-06` | a new start replaces the code: the earlier code is 400 invalid_code, the new one is accepted, and the count of tries starts again at 0 |
| `EMAILCODE-07` | no enumeration: start gives the same answer, and the sender the same kind of call, for an address with an account and for one without, and never reads accounts; verify gives the same 400 body for a wrong code, an expired code, a used code and an address that never asked for one |
| `EMAILCODE-08` | sends per address: the 6th start for one address in a clock hour is 429 too_many_requests and sends nothing; in the next hour it works; the 11th in a clock day is 429 (a refused start still counts toward the day) |
| `EMAILCODE-09` | sends per IP: the 21st start from one IP in a clock hour, each for another address, is 429 too_many_requests; another IP is not affected |
| `EMAILCODE-10` | tries per IP and per address: the 31st verify from one IP in a clock hour is 429 too_many_requests, with the right code too; the 11th verify for one address in a clock hour is 429 whatever IP it comes from and however many new codes were sent |
| `EMAILCODE-11` | input: " A@X.com " signs in a@x.com; a malformed address is 422 invalid_email at start and 400 invalid_code at verify; only space, tab, CR and LF are trimmed and only A-Z is lower-cased, so an address followed by U+00A0, U+000B or U+0000, or one that starts with U+212A, is refused; "123 456" and "123-456" are accepted as the code (each with its own fresh code); 5 digits, 7 digits, letters and six non-ASCII digits are 400 invalid_code and spend no try of the code |
| `EMAILCODE-12` | a sender that returns false or raises makes start answer 503 send_failed and leaves no code for the address; a secret under 32 bytes, or no sender, fails construction with not_configured |
| `EMAILCODE-13` | a suspended or closed account: the right code is 403 account_unavailable, and the code is used up |
| `EMAILCODE-14` | a code sent to one address is 400 invalid_code for another address; an injected code "000042" keeps its leading zeros and signs in; the default generator gives 6 digits 0-9 and, with the spec's injected random bytes, the spec's codes |

## Contract

```text
Source: OWASP Authentication Cheat Sheet and Forgot Password Cheat Sheet (rules applied, text not reproduced);
NIST SP 800-63B (limits on verification attempts). The flow and its limits come from a production sign-in
service and its tests.

PURPOSE:
  Sign in, and sign up, with a 6-digit code sent by email: no password to store or leak. One code per address
  at a time, valid 10 minutes, usable once, 5 tries. The same answer whether or not the address has an account.

SCHEMA:
  accounts     (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, email_verified_at INT NULL,
                status TEXT NOT NULL DEFAULT 'active', created_at INT NOT NULL)
                status: 'active' | 'suspended' | 'closed'
  email_codes  (email_hash TEXT PRIMARY KEY, code_hash TEXT NOT NULL, expires_at INT NOT NULL,
                attempts INT NOT NULL DEFAULT 0, created_at INT NOT NULL)
  rate_windows (key TEXT, window_start INT, count INT NOT NULL, PRIMARY KEY (key, window_start))

CONVENTIONS:
  - Names are snake_case here; each language spells them its own way (normalizeEmail, NormalizeEmail).
  - A refusal is a RETURNED value {error, status}, never an unhandled exception. `status` is the HTTP status a
    route serves it with.
  - now = the injected clock, whole seconds since the Unix epoch.
  - ip is the client address as the HTTP layer saw it (the connection, or the header of a proxy you run), never
    a field of the request body. A missing one is the text "unknown". For an IPv6 address the caller passes
    its first four groups (the /64: one client owns all of it), and every address in one canonical text form.
  - "Missing" is the language's own absent value where the parameter can carry one (None, null, undefined, nil
    pointer, Option::None); otherwise the empty text. "Not text" is tested only where the language lets a caller
    pass another type; do not widen a parameter to an untyped value for it. The injected sender "raises" by
    the language's error path: an exception, a Go error, a Rust Err.

CONFIGURATION (injected):
  secret            the server's HMAC key, at least 32 bytes
  sender            send_code(to, code, expires_in_seconds) -> true | false. Tests pass a fake that records
                    its calls: no network.
                    A secret shorter than 32 bytes, or no sender -> construction fails with not_configured
                    (fail closed), as in auth_system, totp_two_factor and byok_key_vault. start and verify
                    have no step for it.
  revoke_unproven(account_id)   called once, when a row that already existed unverified is verified by a code.
                    The application removes every credential the row carries: password hash, OAuth links,
                    sessions, API keys, TOTP enrollment. Default: does nothing (this system's own rows carry
                    no other credential). Tests pass a fake that records its calls.
  clock, random_bytes(n), generate_code()      random_bytes defaults to the system CSPRNG; the default
                    generator is CODE below
  CODE_TTL = 600 seconds | CODE_ATTEMPTS = 5 | START_PER_EMAIL_HOUR = 5 | START_PER_EMAIL_DAY = 10 |
  START_PER_IP_HOUR = 20 | VERIFY_PER_IP_HOUR = 30 | VERIFY_PER_EMAIL_HOUR = 10

HELPERS:
  normalize_email(raw) -> the address, or nothing
      raw is text. Remove leading and trailing space, tab, CR, LF; map A-Z to a-z. The result has 3 to 254
      characters and the WHOLE of it matches  [a-z0-9][a-z0-9._%+=-]*@[a-z0-9-]+(\.[a-z0-9-]+)+
  hmac_hex(text)          = lower-case hex of HMAC-SHA256(key = secret, message = the UTF-8 of text)
  email_hash(email)       = hmac_hex("email:" + email)
  code_hash(email, code)  = hmac_hex("code:" + email_hash(email) + ":" + code)
  ip_hash(ip)             = the first 32 characters of hmac_hex("ip:" + ip)
  EK(email)               = the first 32 characters of email_hash(email)
  BUMP(key, span) -> count: window_start = now - (now mod span), span = 3600 or 86400. ONE atomic write that
      inserts (key, window_start, 1) or adds 1 to its count; the result is the count after it.
  CODE: n = random_bytes(4) read as an UNSIGNED big-endian 32-bit number; n >= 4294000000 -> draw again;
      the code is n mod 1000000 written with 6 digits (leading zeros kept). Every code is equally likely.

ENDPOINTS / FUNCTIONS (the checks run in the order written; the first that fails answers):
  start(email, ip) -> {status: 202, sent: true, expires_in: 600}
      1. e = normalize_email(email) is nothing                       -> 422 {error: "invalid_email"}
      2. BUMP("start-ip#" + ip_hash(ip), 3600) is over 20            -> 429 {error: "too_many_requests"}
      3. h = BUMP("start-email#" + EK(e), 3600) and d = BUMP("start-email-day#" + EK(e), 86400), both always;
         h is over 5 or d is over 10                                 -> 429 {error: "too_many_requests"}
      4. code = generate_code(). Write the row for email_hash(e), REPLACING an earlier one: code_hash(e, code),
         expires_at = now + 600, attempts = 0, created_at = now.
      5. sender.send_code(e, code, 600) returns false or raises: remove the code just written, and only it
         (a parallel start may have replaced it already):
           DELETE FROM email_codes WHERE email_hash = :h AND code_hash = :new_hash
                                                                     -> 503 {error: "send_failed"}
      6. -> {status: 202, sent: true, expires_in: 600}
      start NEVER reads accounts: a known and an unknown address get the same answer and the same email.
  verify(email, code, ip) -> {status: 200, account_id, email, new_account}
      1. BUMP("verify-ip#" + ip_hash(ip), 3600) is over 30           -> 429 {error: "too_many_requests"}
      2. e = normalize_email(email); c = code without ASCII spaces and "-". e is nothing, or c is not exactly
         6 digits 0-9 (ASCII only)                                   -> 400 {error: "invalid_code"}
      3. BUMP("verify-email#" + EK(e), 3600) is over 10              -> 429 {error: "too_many_requests"}
      4. COUNT THE TRY FIRST, in one conditional write that returns the stored code_hash and the new attempts:
           UPDATE email_codes SET attempts = attempts + 1
             WHERE email_hash = :h AND attempts < 5 AND expires_at > :now
         No row changed: delete the address's row when it is expired or used up, compare code_hash(e, c) with
         64 zeros in constant time (the same work as a real compare)  -> 400 {error: "invalid_code"}
      5. code_hash(e, c) differs from the stored code_hash (constant time): when attempts is now 5, delete
         the row                                                     -> 400 {error: "invalid_code"}
      6. USE IT UP: DELETE FROM email_codes WHERE email_hash = :h AND code_hash = :stored. Not exactly one row
         deleted (another request won)                               -> 400 {error: "invalid_code"}
      7. ACCOUNT: id = random_bytes(16) as 32 hex characters. Insert (id, e, email_verified_at = now, 'active',
         created_at = now) unless a row with that email exists; read the row by email. new_account = the row's
         id is the id just made.
         A found row with email_verified_at null was made by someone who never proved the mailbox (an
         invitation, or a password or OAuth sign-up in auth_system). Before it gets email_verified_at = now,
         call revoke_unproven(account_id). If it raises: leave the row unverified
                                                                     -> 500 {error: "processing_failed"}
         Without this, whoever typed the address first keeps a way in to the account its owner has just
         verified.
      8. the account's status is not 'active'                        -> 403 {error: "account_unavailable"}
      9. -> {status: 200, account_id, email: e, new_account}

IMPLEMENTATION -- RULES:
  - A 6-digit code has 1,000,000 values: its plain SHA-256 is reversed by trying them all. So the code, and the
    address and IP used as keys, are stored only as HMAC-SHA256 under the server's secret. accounts.email
    is the one place an address is kept in clear (it is needed to send mail).
  - The code's hash includes the address's hash: a code sent to one address proves nothing for another.
  - One 400 answer for a wrong, expired, used, exhausted or never-requested code. The 403 comes only after a
    right code, so only someone who reads the mailbox learns the account's state.
  - A try is counted before the compare and by a conditional write, so parallel guesses cannot share a try, and
    the DELETE of verify's step 6 lets exactly one request sign in.
  - The limits bound guessing: 10 codes a day times 5 tries is 50 guesses in 1,000,000 per address per day,
    and every code is an email its owner sees.
  - Anyone who knows an address can use up its sends (5 requests stop new codes for the rest of the clock
    hour, 10 for the rest of the clock DAY) and its tries (5 wrong verifies kill the live code, 10 block
    verify for the rest of the hour), without ever seeing the mailbox. With no password to fall back on, the
    owner cannot sign in until the window ends. That is the price of limits per address. (A token that start
    returns only to its caller, and that verify requires, would close the "tries" half; it changes the
    interface and is not part of this spec.)
  - Never log the code, the address or the secret; the sender must not log the code either.
  - This system proves the mailbox and returns the account. Opening the session is auth_system's job
    ("create session + token"), and totp_two_factor runs after it for an enrolled account.
  - Relation to auth_system: `accounts` here is that spec's `users` table, reached through a small store
    interface (find by email, insert verified, mark verified). 'active' is any status auth_system lets sign
    in; 'suspended' and 'closed' are its 'suspended' and 'banned'. Do not keep two tables of people.
  - A product that must NOT create accounts by email still answers 202 from start for an unknown address;
    that variant is outside this spec.
  - SQL is parameterized; BUMP and verify's steps 4 and 6 are single statements, or one transaction that
    locks the row (UPDATE ... RETURNING does not exist everywhere), never a read followed by a write.

PRIMITIVES (standard library unless a package is named):
  HMAC-SHA256      Python hmac + hashlib | JavaScript, TypeScript node:crypto createHmac | Java javax.crypto.Mac
                   "HmacSHA256" | C# System.Security.Cryptography.HMACSHA256 | PHP hash_hmac | Go crypto/hmac +
                   crypto/sha256 | Rust hmac + sha2 crates (on the runner's list)
  constant time    Python hmac.compare_digest | Node crypto.timingSafeEqual | Java MessageDigest.isEqual | C#
                   CryptographicOperations.FixedTimeEquals | PHP hash_equals | Go subtle.ConstantTimeCompare |
                   Rust: an XOR fold over the two 64-character strings
  CSPRNG           Python secrets | Node crypto.randomBytes | Java SecureRandom | C# RandomNumberGenerator |
                   PHP random_bytes | Go crypto/rand | Rust rand crate (OsRng; on the runner's list)

TEST VECTORS (every language asserts these):
  secret = the 32 ASCII bytes "0123456789abcdef0123456789abcdef"
  email_hash("user@example.com")          = 587522269e243312a5d6f20bcdc78dc97a3e644e2ad702cdb94ac9550c03b346
  code_hash("user@example.com", "123456") = 761f222c89dc1744c480d21e141277cc9af815ee0e2a1d7489c9282594728b5b
  ip_hash("203.0.113.7")                  = e01c4eeb03c058165d49564dcaf561cf
  With generate_code giving "123456", start("user@example.com", "203.0.113.7") stores exactly that code_hash
  under that email_hash, and the rate_windows keys are "start-ip#e01c4eeb03c058165d49564dcaf561cf",
  "start-email#587522269e243312a5d6f20bcdc78dc9" and "start-email-day#587522269e243312a5d6f20bcdc78dc9".
  normalize_email: " A@X.com " -> "a@x.com"; "a@b" , "a b@x.com", "a@x..com", ".a@x.com", "a@x.com,b@y.com"
  and "<a@x.com>" -> nothing. "a@x.com\u00a0", "a@x.com\u000b", "a@x.com\u0000" and "\u212a@x.com" -> nothing
  (the default trim and lower-case functions of most languages get these wrong).
  CODE, with random_bytes serving these bytes in order: ff ff ff ff is drawn again, then 80 00 00 00 gives
  "483648"; ff f1 3d 7f gives "999999"; ff f1 3d 80 is drawn again, then 00 00 00 2a gives "000042". (A signed
  32-bit read fails the first one.)
  Window tests start at now = 1699920000 (00:00:00 UTC: the first second of a clock hour and of a clock day).
  The next hour starts at 1699923600 and the next day at 1700006400. A refused start still counts toward
  the day: 6 starts in the first hour (the 6th refused) and 4 in the second make the 11th the one refused.
  Six non-ASCII digits for EMAILCODE-11: "\u0661\u0662\u0663\u0664\u0665\u0666".

TESTS:
  - **EMAILCODE-01** start answers 202 {sent: true, expires_in: 600} and the sender gets one 6-digit code; verify with it answers 200 with new_account true and the account exists with email_verified_at set; a second sign-in for the address gives the same account_id with new_account false; for a row that exists with email_verified_at null the right code calls revoke_unproven once with its id and then sets email_verified_at, and an account made by verify never calls it
  - **EMAILCODE-02** storage: with the spec's secret, address and code the stored code_hash is the spec's value; email_codes and rate_windows hold neither the address, the IP nor the code, and no plain SHA-256 of the code
  - **EMAILCODE-03** single use: the right code a second time is 400 invalid_code
  - **EMAILCODE-04** expiry: the code is accepted 599 seconds after start and is 400 invalid_code at 600 seconds
  - **EMAILCODE-05** five tries per code: after 5 wrong codes the right one is 400 invalid_code; after 4 wrong codes the right one, the 5th try, is accepted
  - **EMAILCODE-06** a new start replaces the code: the earlier code is 400 invalid_code, the new one is accepted, and the count of tries starts again at 0
  - **EMAILCODE-07** no enumeration: start gives the same answer, and the sender the same kind of call, for an address with an account and for one without, and never reads accounts; verify gives the same 400 body for a wrong code, an expired code, a used code and an address that never asked for one
  - **EMAILCODE-08** sends per address: the 6th start for one address in a clock hour is 429 too_many_requests and sends nothing; in the next hour it works; the 11th in a clock day is 429 (a refused start still counts toward the day)
  - **EMAILCODE-09** sends per IP: the 21st start from one IP in a clock hour, each for another address, is 429 too_many_requests; another IP is not affected
  - **EMAILCODE-10** tries per IP and per address: the 31st verify from one IP in a clock hour is 429 too_many_requests, with the right code too; the 11th verify for one address in a clock hour is 429 whatever IP it comes from and however many new codes were sent
  - **EMAILCODE-11** input: " A@X.com " signs in a@x.com; a malformed address is 422 invalid_email at start and 400 invalid_code at verify; only space, tab, CR and LF are trimmed and only A-Z is lower-cased, so an address followed by U+00A0, U+000B or U+0000, or one that starts with U+212A, is refused; "123 456" and "123-456" are accepted as the code (each with its own fresh code); 5 digits, 7 digits, letters and six non-ASCII digits are 400 invalid_code and spend no try of the code
  - **EMAILCODE-12** a sender that returns false or raises makes start answer 503 send_failed and leaves no code for the address; a secret under 32 bytes, or no sender, fails construction with not_configured
  - **EMAILCODE-13** a suspended or closed account: the right code is 403 account_unavailable, and the code is used up
  - **EMAILCODE-14** a code sent to one address is 400 invalid_code for another address; an injected code "000042" keeps its leading zeros and signs in; the default generator gives 6 digits 0-9 and, with the spec's injected random bytes, the spec's codes
```

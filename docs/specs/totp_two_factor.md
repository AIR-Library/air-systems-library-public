# TOTP Two-Factor (Authenticator Codes + Recovery Codes)

Reference contract for `saas_templates/<lang>/totp_two_factor_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# TOTP-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `TOTP-01` | hotp gives the RFC 4226 values for counters 0 to 9, and totp_at gives the RFC 6238 SHA-1 values in 8 and in 6 digits, T = 20000000000 included; a counter above 32 bits (4294967296) gives the spec's value, not the value for 0 |
| `TOTP-02` | base32: the RFC 4648 vectors encode without padding and decode back; decode ignores spaces, dashes, "=" and case; any other character, and a length of 1, 3 or 6 modulo 8, is invalid_base32; generate_secret is 32 characters that decode to 20 bytes |
| `TOTP-03` | enroll_start returns the secret and the exact otpauth URI; the store holds only the sealed secret (with the injected random bytes: the spec's string), never the base32 text; a second enroll_start before confirming replaces the secret |
| `TOTP-04` | enroll_confirm with the current code returns 8 recovery codes shaped xxxx-xxxx-xxxx and stores only their keyed hashes; the code that confirmed is then refused by verify; a second confirm is 409 already_enrolled, a confirm with nothing started is 409 enrollment_not_started, enroll_start after confirming is 409 already_enrolled; with the spec's byte stream the 8 codes are the spec's 8 codes |
| `TOTP-05` | verify accepts the code of the previous, the current and the next 30-second step, and refuses the codes two steps back and two steps ahead with 401 invalid_code (the window vector) |
| `TOTP-06` | replay: an accepted code is 401 the second time; once a step is accepted the code of an earlier step is 401 and the code of a later step is accepted; the store's claim succeeds once per step |
| `TOTP-07` | input: "081 804" and "081-804" are accepted like "081804" (each spelling on its own fresh enrollment); 5 digits, 7 digits, letters, an empty string, a missing code, a code over 64 characters and non-ASCII digits are 401 invalid_code, never an exception, and each adds one failure (each tried on its own user, so the lock does not answer first) |
| `TOTP-08` | a recovery code signs in once (method "recovery_code", recovery_codes_left 7), typed in upper case and without dashes too (each spelling with its own unused code); used again it is 401; user A's code is 401 for user B; its stored hash is the spec's keyed hash, not a plain SHA-256 |
| `TOTP-09` | lock: after 5 failures inside 900 seconds the next verify is 429 locked with retry_after, with a correct code too, and adds no failure; 899 seconds after the oldest of the 5 it is still locked, at 900 seconds a correct code is accepted; the store's try write succeeds 5 times inside one window and not a 6th |
| `TOTP-10` | a sealed secret that cannot be opened (another encryption_key, or one changed character) makes verify answer 503 secret_unreadable for a 6-digit code, never not_enrolled or invalid_code, and adds no failure; a recovery code still signs in |
| `TOTP-11` | seal with the spec's key, nonce and aad gives the spec's string and open returns the secret; open with another user's aad, another key or one changed character returns nothing; an encryption_key that is not 32 bytes, or a recovery_hash_key under 32 bytes, is refused at construction |
| `TOTP-12` | disable with a valid code deletes the enrollment, its recovery codes and its failures, and verify is then 409 not_enrolled; disable with a wrong code is 401 and deletes nothing |
| `TOTP-13` | verify and disable before enroll_confirm are 409 not_enrolled, with the right code too; two users with different secrets never accept each other's codes |
| `TOTP-14` | long-run guessing: after 100 failures with no success between them a correct 6-digit code is 429 recovery_required, however far the clock moves, and adds no failure; a recovery code then signs in, and after it a correct 6-digit code is accepted again; a success before the 100th failure starts the count again |

## Contract

```text
Source: RFC 4226 (HOTP), RFC 6238 (TOTP), RFC 4648 (base32), the Key URI Format that authenticator apps read
(otpauth://), NIST SP 800-38D (AES-GCM). The flow and its limits come from two production implementations and
their tests.

PURPOSE:
  A second sign-in factor from an authenticator app: enroll, verify a 6-digit code with one step of clock drift
  each way, never accept a code twice, lock after repeated wrong codes, and give one-time recovery codes for a
  lost phone.

SCHEMA:
  totp_enrollments    (user_id TEXT PRIMARY KEY, secret_enc TEXT NOT NULL, confirmed_at INT NULL,
                       last_used_step INT NOT NULL DEFAULT 0, failed_since_success INT NOT NULL DEFAULT 0,
                       created_at INT NOT NULL)
  totp_recovery_codes (id, user_id TEXT NOT NULL, code_hash TEXT NOT NULL, created_at INT NOT NULL,
                       used_at INT NULL, UNIQUE (user_id, code_hash))
  totp_failures       (id, user_id TEXT NOT NULL, at INT NOT NULL)

CONVENTIONS:
  - Names are snake_case here; each language spells them its own way (enrollStart, EnrollStart).
  - A refusal is a RETURNED value {error, status} (plus the fields its line names), never an unhandled
    exception. `status` is the HTTP status a route serves it with.
  - now = the injected clock, whole seconds since the Unix epoch, as a 64-bit integer.
  - user_id is the VERIFIED caller: the account that has just passed the first factor. Never request input.
  - "Missing" is the language's own absent value where the parameter can carry one (None, null, undefined, nil
    pointer, Option::None); otherwise the empty text. "Not text" is tested only where the language lets a caller
    pass another type; do not widen a parameter to an untyped value for it.

CONFIGURATION (injected):
  encryption_key      exactly 32 bytes: seals the TOTP secrets
  recovery_hash_key   at least 32 bytes: the HMAC key for recovery codes. A key of its own: when a lost or
                      leaked encryption_key is replaced, every sealed secret stops opening, and recovery codes
                      are then the way back in (sign in with one, disable, enroll again).
                      A key of the wrong size -> construction fails with invalid_key (fail closed).
  issuer              the name the authenticator app shows
  clock, random_bytes(n)      random_bytes defaults to the system CSPRNG
  STEP = 30 seconds, DIGITS = 6, WINDOW = 1 step each way, LOCK_FAILURES = 5, LOCK_SECONDS = 900,
  HARD_LOCK_FAILURES = 100, RECOVERY_CODES = 8

PURE FUNCTIONS:
  base32_encode(bytes) -> text       RFC 4648 alphabet A-Z 2-7, upper case, NO "=" padding
  base32_decode(text) -> bytes, or the error invalid_base32
      Remove ASCII spaces, "-" and "="; map a-z to A-Z; every remaining character must be in the alphabet and at
      least one must remain; a remaining length of 1, 3 or 6 modulo 8 is invalid_base32 (no bytes encode to
      it). 5 bits per character, most significant first; leftover bits that do not fill a byte are dropped.
      Check the characters and the length yourself before calling a library: on these lengths Python raises
      and Go returns fewer bytes with no error.
  hotp(key_bytes, counter, digits = 6) -> text
      mac = HMAC-SHA1(key_bytes, counter as 8 bytes big-endian). o = the low 4 bits of mac[19]. v = the 4 bytes
      mac[o..o+3] as a big-endian number with its top bit cleared. Result = v mod 10^digits, left-padded with "0".
  totp_at(secret_base32, unix_time, digits = 6) = hotp(base32_decode(secret_base32), floor(unix_time / 30), digits)
  generate_secret() -> base32_encode(random_bytes(20))                     (32 characters)
  otpauth_uri(secret, issuer, account_label) ->
      "otpauth://totp/" + pct(issuer + ":" + account_label) + "?secret=" + secret + "&issuer=" + pct(issuer)
      + "&algorithm=SHA1&digits=6&period=30"
      pct(s): every byte of the UTF-8 of s that is not in [A-Za-z0-9._~-] becomes "%" + two upper-case hex digits.
  seal(key32, nonce12, plaintext, aad) -> "v1." + base64(nonce12 + ciphertext + tag)
      AES-256-GCM, 12-byte nonce, 16-byte tag, aad = the UTF-8 of the aad text. base64 is RFC 4648 section 4,
      with padding.
  open(key32, sealed, aad) -> plaintext, or nothing for a missing "v1." prefix, bad base64, fewer than 28 bytes,
      or a tag that does not verify (wrong key, wrong aad, any changed byte)

FLOWS (the checks run in the order written; the first that fails answers):
  enroll_start(user_id, account_label) -> {secret, otpauth_uri}
      1. a CONFIRMED enrollment exists                       -> 409 {error: "already_enrolled"}
      2. secret = generate_secret(); nonce = random_bytes(12). Write the row (an unconfirmed row is replaced):
         secret_enc = seal(encryption_key, nonce, secret, "totp:" + user_id), confirmed_at = null,
         last_used_step = 0, failed_since_success = 0, created_at = now.
      3. -> {secret, otpauth_uri: otpauth_uri(secret, issuer, account_label)}. The secret leaves the server
         only in this answer.
  enroll_confirm(user_id, code) -> {recovery_codes: [8 texts]}
      1. no row                                             -> 409 {error: "enrollment_not_started"}
      2. the row is confirmed                               -> 409 {error: "already_enrolled"}
      3. TRY(user_id) gets no slot                          -> 429 {error: "locked", retry_after}
      4. the code is not a TOTP INPUT                       -> FAILURE, 401 {error: "invalid_code"}
      5. open(encryption_key, secret_enc, "totp:" + user_id) gives nothing
                                                            -> 503 {error: "secret_unreadable"}
      6. MATCH finds no step                                -> FAILURE, 401 {error: "invalid_code"}
      7. UPDATE totp_enrollments SET confirmed_at = :now, last_used_step = :step, failed_since_success = 0
           WHERE user_id = :u AND confirmed_at IS NULL AND secret_enc = :secret_enc_read
         changes no row: the row is confirmed by now        -> 409 {error: "already_enrolled"}
                         otherwise (a second enroll_start replaced the secret that step 5 opened)
                                                            -> FAILURE, 401 {error: "invalid_code"}
      8. make 8 RECOVERY CODES, store their hashes -> {recovery_codes}. They are shown only in this answer.
  verify(user_id, code) -> {ok: true, method: "totp" | "recovery_code", recovery_codes_left}
      1. no row, or the row is not confirmed                -> 409 {error: "not_enrolled"}
      2. TRY(user_id) gets no slot                          -> 429 {error: "locked", retry_after}
         (no code is checked and no failure is added, so a lock always ends)
      3. the code is a TOTP INPUT:
           the row's failed_since_success is 100 or more    -> 429 {error: "recovery_required"}   (no failure)
           open(...) gives nothing                          -> 503 {error: "secret_unreadable"}   (no failure)
           step = MATCH; none, or step <= last_used_step    -> FAILURE, 401 {error: "invalid_code"}
           CLAIM(step) changes no row                       -> FAILURE, 401 {error: "invalid_code"}
           otherwise                                        -> ok, method "totp"
      4. else the code is a RECOVERY INPUT:
           UPDATE totp_recovery_codes SET used_at = :now
             WHERE user_id = :u AND code_hash = :h AND used_at IS NULL
           one row changed -> ok, method "recovery_code"; otherwise -> FAILURE, 401 {error: "invalid_code"}
      5. else (anything else, a missing code included)      -> FAILURE, 401 {error: "invalid_code"}
      An ok answer sets failed_since_success = 0 (for method "totp" in the CLAIM statement itself).
      recovery_codes_left = the user's rows with used_at IS NULL, counted after this call.
  disable(user_id, code) -> {disabled: true}
      Steps 1 to 5 of verify, with the same answers. On ok: delete the user's enrollment, recovery codes and
      failures. The user can then enroll_start again.
  status(user_id) -> {enrolled: true | false, locked_until: time | null, recovery_required: true | false,
                      recovery_codes_left}
      enrolled = a confirmed row exists. recovery_required = its failed_since_success is 100 or more.
      Reading it changes nothing.

  TOTP INPUT: remove every ASCII space and "-" from the code; what is left is exactly 6 characters, each 0-9.
  RECOVERY INPUT: map A-Z to a-z and remove every ASCII space and "-"; what is left is exactly 12 characters,
      each in the RECOVERY ALPHABET.
      A code longer than 64 characters is neither (test the length first).
  MATCH: s = floor(now / 30). For d = -1, 0, +1 (skipping s + d < 0) compare hotp(key, s + d) with the input
      in constant time. ALL candidates are computed and compared, with no early exit. The result is the
      LARGEST s + d that was equal: recording the largest is what stops the same 6 digits being accepted again
      inside their window.
  CLAIM(step): UPDATE totp_enrollments SET last_used_step = :step, failed_since_success = 0
      WHERE user_id = :u AND confirmed_at IS NOT NULL AND last_used_step < :step
      One conditional write: of two requests with the same code, exactly one changes a row.
  TRY(user_id): COUNT THE TRY FIRST, before any code is looked at, in one atomic conditional write:
        INSERT INTO totp_failures (user_id, at) SELECT :u, :now
          WHERE (SELECT COUNT(*) FROM totp_failures WHERE user_id = :u AND at > :now - 900) < 5
      A row was inserted: this call holds a slot, and that row is the slot. No row: the user is LOCKED.
      A store that cannot make this one statement atomic runs it while holding a lock on the user's
      totp_enrollments row. Of N parallel calls for one user, at most (5 - the rows in the window) get a slot,
      so a burst of guesses cannot pass the lock before the first failure is written.
  FAILURE: the slot row stays. It is the failure, at = now. Also, in one statement:
        UPDATE totp_enrollments SET failed_since_success = failed_since_success + 1 WHERE user_id = :u
  Every answer that is not a FAILURE (ok, 503 secret_unreadable, 409 already_enrolled, 429 recovery_required)
      deletes the slot row of this call, and only that row. A success does not delete earlier failures.
  LOCKED(user_id): the user has at least 5 rows with at > now - 900. retry_after = (the `at` of the 5th most
      recent row) + 900 - now, and status.locked_until = that `at` + 900.
  HARD LOCK: 5 tries every 15 minutes is 480 a day for as long as someone holds the password. So after 100
      FAILUREs with no ok answer between them a TOTP INPUT is no longer checked at all (429 recovery_required,
      with no retry_after: waiting does not end it). A recovery code still signs in, and that success sets
      the count to 0. (NIST SP 800-63B: at most 100 consecutive failed attempts on one account.)
  RECOVERY CODES: RECOVERY ALPHABET = "23456789abcdefghjkmnpqrstvwxyz" (30 symbols: no 0 1 i l o u). A code is
      12 symbols shown as xxxx-xxxx-xxxx. Symbols are drawn ONE BYTE AT A TIME, in order, each with its own
      random_bytes(1) call: b >= 240 is drawn again, otherwise the symbol is alphabet[b mod 30]. A code equal
      to an earlier one of the same set is dropped and a new one is drawn.
      Tests inject random_bytes as a queue of bytes served in order, whatever n is asked. A fake that returns
      the same bytes on every call would make these two rules loop forever.
      code_hash = lower-case hex of HMAC-SHA256(recovery_hash_key, "recovery:" + user_id + ":" + the RECOVERY
      INPUT form of the code)

IMPLEMENTATION -- RULES:
  - Never log or return a secret, a code, a recovery code or a key, and never put one in an error.
  - 503 secret_unreadable is never turned into not_enrolled: that would let a stolen session enroll its own
    authenticator. A recovery code needs no secret, so it still works when a secret cannot be opened.
    Unlike byok_key_vault, where a tag that fails is 500 key_unreadable, it is 503 here: the sealed text
    carries no key id, so a wrong or replaced encryption_key cannot be told from a damaged row, and the first
    is a configuration fault the operator must fix.
  - Relation to auth_system: this system IS that spec's MFA step. Its "mfa_enabled_check" is
    status(user_id).enrolled, and the "code_correct" gate of mfa_challenge is verify(user_id, code) here: 401
    invalid_code is the same answer, and 429 locked, 429 recovery_required and 503 secret_unreadable pass
    through. Where this system is installed, users.mfa_secret and users.mfa_enabled are not used: one place
    holds the secret, sealed, and one place says whether MFA is on. A TOTP package may compute a code. It
    never decides whether a code is accepted.
  - A wrong code, a replayed code and a code outside the window get the same answer.
  - Do not use a TOTP package's own verify(): packages differ in window and none keeps a replay guard. The
    vectors below decide what a code is.
  - The counter is 8 bytes: use 64-bit integers for the time and the step (T = 20000000000 is a test).
  - 6-digit codes are compared in constant time. Recovery codes are low-entropy for an offline attacker
    (about 59 bits), so only their HMAC under recovery_hash_key is stored: a copy of the table alone tests
    nothing.
  - The caller offers enroll_start only right after a fresh first-factor sign-in, and writes the audit entries
    (audit_logging): totp_enroll_started, totp_enrolled, totp_verified with the method, totp_failed,
    totp_locked, totp_disabled.

PRIMITIVES (standard library unless a package is named):
  HMAC-SHA1 / -SHA256   Python hmac + hashlib | JavaScript, TypeScript node:crypto createHmac | Java
                        javax.crypto.Mac "HmacSHA1", "HmacSHA256" | C# HMACSHA1, HMACSHA256 | PHP hash_hmac
                        (raw output) | Go crypto/hmac + crypto/sha1, crypto/sha256 | Rust hmac + sha2 (on the
                        runner's list) + sha1 crate (to add)
  AES-256-GCM           Python `cryptography` AESGCM (name it in the runner's list) | JavaScript, TypeScript
                        node:crypto createCipheriv("aes-256-gcm") with setAAD and getAuthTag | Java
                        javax.crypto.Cipher "AES/GCM/NoPadding" + GCMParameterSpec(128, nonce) | C#
                        System.Security.Cryptography.AesGcm | PHP openssl_encrypt("aes-256-gcm",
                        OPENSSL_RAW_DATA, tag length 16) | Go crypto/aes + cipher.NewGCM | Rust aes-gcm crate
                        (to add). Where the library returns the tag apart, append it to the ciphertext.
                        The tag is always exactly the last 16 bytes; check the length (at least 28 bytes in
                        all) before slicing. Node: createDecipheriv(..., {authTagLength: 16}). PHP: pass a
                        16-byte tag, the function does not check its length.
  base32                Python base64.b32encode / b32decode | Go encoding/base32 (no padding) | the others:
                        about 15 lines in the file
  constant time         Python hmac.compare_digest | Node crypto.timingSafeEqual | Java MessageDigest.isEqual
                        | C# CryptographicOperations.FixedTimeEquals | PHP hash_equals | Go
                        subtle.ConstantTimeCompare | Rust: an XOR fold over equal-length bytes

TEST VECTORS (every language asserts these):
  K = the 20 ASCII bytes "12345678901234567890";  base32_encode(K) = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
  hotp(K, c) for c = 0..9:  755224 287082 359152 969429 338314 254676 287922 162583 399871 520489
  hotp(K, 4294967296) = 999456   (a counter cut to 32 bits gives 755224, the value for 0)
  totp_at(base32_encode(K), T, 8) and (same, 6):
                T       step  8 digits  6 digits
               59          1  94287082  287082
       1111111109   37037036  07081804  081804
       1111111111   37037037  14050471  050471
       1234567890   41152263  89005924  005924
       2000000000   66666666  69279037  279037
      20000000000  666666666  65353130  353130
  Window (TOTP-05), secret base32_encode(K): enroll and confirm with now = 1111111000 or earlier, then set
      now = 1111111109. Accepted, in this order: 731029 (previous step), 081804 (current), 050471 (next).
      Refused: 150727 (two steps back) and 266759 (two steps ahead). Check the two refusals FIRST: after the
      three acceptances a code two steps back is also refused by the replay guard, which proves nothing
      about the window.
  base32_encode: "" -> "", "f" -> "MY", "fo" -> "MZXQ", "foo" -> "MZXW6", "foob" -> "MZXW6YQ",
      "fooba" -> "MZXW6YTB", "foobar" -> "MZXW6YTBOI".  base32_decode("mzxw 6ytb-oi==") = "foobar".
      base32_decode("MZXW6YT1") and base32_decode("") are invalid_base32. base32_decode("M"),
      base32_decode("MZX") and base32_decode("MZXW6Y") are invalid_base32. base32_decode("MZ") = "f".
  encryption_key = the 32 bytes 00 01 ... 1f; recovery_hash_key = the 32 bytes 40 41 ... 5f
  seal(encryption_key, the 12 bytes a0 a1 ... ab, base32_encode(K), "totp:user_1") =
      "v1.oKGio6SlpqeoqaqroV0maQKFQOklPLSHVjWKjzfpA1TV+QA621cV0i7kP1B5d8k2owRGDhH/FzF0f662"
      With random_bytes serving, in order, the 20 bytes of K and then a0 ... ab, enroll_start("user_1", any
      label) stores exactly that string.
  code_hash for user_1 and "K7MQ-2XPT-9HCW" (RECOVERY INPUT form "k7mq2xpt9hcw") =
      5a93360f78c7f03de7336a625adf93bf238749d8da4aaf734271b327c52347a3
  Recovery codes: with random_bytes(1) serving enroll_confirm the bytes (7 x k) mod 256 for k = 0, 1, 2, ...
      (00 07 0e 15 ...; in the queue they come after the 32 bytes enroll_start drew) the 8 codes are, in order:
      29gq-y7en-w5ck t3ah-rz8f-px6d mv4b-js29-gqy5 ckt3-ahrz-8fpx
      6dmv-4bjs-29gq y7en-w5ck-t8fp x6dm-v4bj-s29g qy7e-nw5c-kt3a
      101 bytes are drawn; 5 of them are 240 or more and are drawn again. The stored code_hash of the first,
      for user_1, is d9199ecad0b35d9e2f18857343d7fe79dd5f8425f1c460c88fe18f5c4b4a2645
  Hard lock (TOTP-14): 100 failures need 20 lock windows: 5 wrong codes, move the clock 900 seconds, repeat.
  otpauth_uri(base32_encode(K), "Example App", "alice@example.com") =
      otpauth://totp/Example%20App%3Aalice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example%20App&algorithm=SHA1&digits=6&period=30

TESTS:
  - **TOTP-01** hotp gives the RFC 4226 values for counters 0 to 9, and totp_at gives the RFC 6238 SHA-1 values in 8 and in 6 digits, T = 20000000000 included; a counter above 32 bits (4294967296) gives the spec's value, not the value for 0
  - **TOTP-02** base32: the RFC 4648 vectors encode without padding and decode back; decode ignores spaces, dashes, "=" and case; any other character, and a length of 1, 3 or 6 modulo 8, is invalid_base32; generate_secret is 32 characters that decode to 20 bytes
  - **TOTP-03** enroll_start returns the secret and the exact otpauth URI; the store holds only the sealed secret (with the injected random bytes: the spec's string), never the base32 text; a second enroll_start before confirming replaces the secret
  - **TOTP-04** enroll_confirm with the current code returns 8 recovery codes shaped xxxx-xxxx-xxxx and stores only their keyed hashes; the code that confirmed is then refused by verify; a second confirm is 409 already_enrolled, a confirm with nothing started is 409 enrollment_not_started, enroll_start after confirming is 409 already_enrolled; with the spec's byte stream the 8 codes are the spec's 8 codes
  - **TOTP-05** verify accepts the code of the previous, the current and the next 30-second step, and refuses the codes two steps back and two steps ahead with 401 invalid_code (the window vector)
  - **TOTP-06** replay: an accepted code is 401 the second time; once a step is accepted the code of an earlier step is 401 and the code of a later step is accepted; the store's claim succeeds once per step
  - **TOTP-07** input: "081 804" and "081-804" are accepted like "081804" (each spelling on its own fresh enrollment); 5 digits, 7 digits, letters, an empty string, a missing code, a code over 64 characters and non-ASCII digits are 401 invalid_code, never an exception, and each adds one failure (each tried on its own user, so the lock does not answer first)
  - **TOTP-08** a recovery code signs in once (method "recovery_code", recovery_codes_left 7), typed in upper case and without dashes too (each spelling with its own unused code); used again it is 401; user A's code is 401 for user B; its stored hash is the spec's keyed hash, not a plain SHA-256
  - **TOTP-09** lock: after 5 failures inside 900 seconds the next verify is 429 locked with retry_after, with a correct code too, and adds no failure; 899 seconds after the oldest of the 5 it is still locked, at 900 seconds a correct code is accepted; the store's try write succeeds 5 times inside one window and not a 6th
  - **TOTP-10** a sealed secret that cannot be opened (another encryption_key, or one changed character) makes verify answer 503 secret_unreadable for a 6-digit code, never not_enrolled or invalid_code, and adds no failure; a recovery code still signs in
  - **TOTP-11** seal with the spec's key, nonce and aad gives the spec's string and open returns the secret; open with another user's aad, another key or one changed character returns nothing; an encryption_key that is not 32 bytes, or a recovery_hash_key under 32 bytes, is refused at construction
  - **TOTP-12** disable with a valid code deletes the enrollment, its recovery codes and its failures, and verify is then 409 not_enrolled; disable with a wrong code is 401 and deletes nothing
  - **TOTP-13** verify and disable before enroll_confirm are 409 not_enrolled, with the right code too; two users with different secrets never accept each other's codes
  - **TOTP-14** long-run guessing: after 100 failures with no success between them a correct 6-digit code is 429 recovery_required, however far the clock moves, and adds no failure; a recovery code then signs in, and after it a correct 6-digit code is accepted again; a success before the 100th failure starts the count again
```

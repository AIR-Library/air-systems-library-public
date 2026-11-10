# BYOK Key Vault (Users' Own Provider Keys, Encrypted)

Reference contract for `saas_templates/<lang>/byok_key_vault_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# VAULT-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `VAULT-01` | save_key happy path: the provider check is called once with the key; the row holds key_id, wrapped_dek, ciphertext and the hint "WXYZ" and nowhere the key; the answer is {provider, hint, key_id, created_at}; an audit row key_saved exists |
| `VAULT-02` | known answer: with master key k1, the injected random bytes and the key of the spec, the stored ciphertext and wrapped_dek are exactly the spec's two strings, and use_key returns the key |
| `VAULT-03` | an unknown provider is 404 unknown_provider; a key with the wrong prefix, too short, too long, with a space or a line break inside, or that is not text is 400 invalid_key_format; only leading and trailing space, tab, CR and LF are trimmed first, so a key followed by U+00A0, U+000B or U+0000 is 400 invalid_key_format too; in each refusal the provider client is not called and nothing is stored |
| `VAULT-04` | the provider answers "rejected" -> 400 key_rejected; "unreachable", any other answer or a raised error -> 502 provider_unreachable; no provider_keys row and no audit row is written (the check is still counted) |
| `VAULT-05` | list_keys returns provider, hint, key_id, created_at and last_used_at, sorted by provider, and its serialized form holds neither the key nor ciphertext nor wrapped_dek |
| `VAULT-06` | use_key returns the key, sets last_used_at to the clock's time and writes an audit row key_used with the purpose; an empty purpose, or one with a character outside [A-Za-z0-9_.:-], is 400 invalid_purpose; when the audit write fails the answer is 500 storage_failed with no key; no audit row and no refusal ever holds the key |
| `VAULT-07` | isolation: user B's list is empty, use_key for a provider only user A saved is 404 key_not_found and delete_key is {deleted: false}; A's key is untouched |
| `VAULT-08` | a row moved to another user, a row moved to another provider, one changed byte of the DECODED ciphertext and one of the decoded wrapped_dek (decode, XOR 01 into byte 20, encode again), and a stored value that is not base64 or is too short each make use_key answer 500 key_unreadable, never an exception |
| `VAULT-09` | saving again for the same provider replaces the key: one row, a new DEK and new nonces, the new hint, and use_key returns the new key |
| `VAULT-10` | rotation: with k2 added and active a new save is wrapped under k2; rewrap() re-wraps the older rows under k2, changes no ciphertext, returns {rewrapped: 1, failed: 0} and, with the injected nonce, stores the spec's string; with k1 then removed from the keyring every key still opens; the store's rewrap write changes no row when the row's wrapped_dek is no longer the one that was read |
| `VAULT-11` | a row whose key_id is not in the keyring is 503 key_unavailable; a master key that is not 32 bytes, or an active_key_id that is not in the keyring, fails construction; a provider whose min_length is under its prefix's length + 16 fails construction with invalid_provider_config |
| `VAULT-12` | at most 10 provider checks per user per clock hour: the 11th save_key is 429 rate_limited with retry_after and calls no provider; another user is not affected; in the next hour it works again; a malformed key does not count; the store's window write succeeds 10 times in one hour and not an 11th |
| `VAULT-13` | delete_key removes the row and writes key_deleted; a second delete is {deleted: false} with no audit row; use_key is then 404 key_not_found |
| `VAULT-14` | with real randomness, the same key saved for two users gives different ciphertext, different wrapped_dek and different nonces |

## Contract

```text
Source: NIST SP 800-38D (AES-GCM); OWASP Cryptographic Storage Cheat Sheet and Key Management Cheat Sheet
(envelope encryption, rotation; rules applied, text not reproduced). The flow comes from a production key vault
and its tests.

PURPOSE:
  Let a user store their own API key for a third-party provider ("bring your own key"). The key is encrypted at
  rest, shown again only as a 4-character hint, opened only for the user who saved it, and every use is recorded.

SCHEMA:
  provider_keys             (user_id TEXT, provider TEXT, key_id TEXT NOT NULL, wrapped_dek TEXT NOT NULL,
                             ciphertext TEXT NOT NULL, hint TEXT NOT NULL, created_at INT NOT NULL,
                             last_used_at INT NULL, PRIMARY KEY (user_id, provider))
  provider_key_audit        (id INTEGER PRIMARY KEY, ascending; user_id, provider, action, purpose NULL, key_id, at)
                             action: 'key_saved' | 'key_used' | 'key_deleted' | 'key_rewrapped'
  provider_key_save_windows (user_id TEXT, window_start INT, count INT, PRIMARY KEY (user_id, window_start))

CONVENTIONS:
  - Names are snake_case here; each language spells them its own way (saveKey, SaveKey).
  - A refusal is a RETURNED value {error, status} (plus the fields its line names), never an unhandled
    exception. `status` is the HTTP status a route serves it with.
  - now = the injected clock, whole seconds since the Unix epoch.
  - user_id is the VERIFIED caller (the signed-in account). Never request input.
  - Texts are ordered and compared byte by byte (ordinal), never by locale: C# StringComparer.Ordinal, SQL
    COLLATE "C" or BINARY.
  - "Missing" is the language's own absent value where the parameter can carry one (None, null, undefined, nil
    pointer, Option::None); otherwise the empty text. "Not text" is tested only where the language lets a caller
    pass another type; do not widen a parameter to an untyped value for it. The injected provider client
    "raises" by the language's error path: an exception, a Go error, a Rust Err.

CONFIGURATION (injected):
  master_keys      {key_id: 32 bytes}; a key_id matches [A-Za-z0-9_-]{1,32}
  active_key_id    the master key that new saves and rewrap() use
                   A master key that is not 32 bytes, a malformed key_id, or an active_key_id that is not in
                   master_keys -> construction fails with invalid_master_key (fail closed).
  providers        {provider: {prefix, min_length, max_length}}; a provider id matches [a-z0-9_]{1,32};
                   20 <= min_length <= max_length <= 4096, and min_length >= the prefix's length + 16 (so the
                   4 characters of the hint are at most a quarter of the secret part). A provider that breaks
                   these rules -> construction fails with invalid_provider_config.
  provider_client  check(provider, key) -> "ok" | "rejected" | "unreachable". The real one makes ONE read-only
                   call that only a valid key passes (HTTP 2xx or 429 = ok; 400, 401, 403 = rejected; anything
                   else, a timeout or a network error = unreachable). 429 means the provider refused to look:
                   such a key is stored without ever having been checked. Tests pass a fake: no network.
  clock, random_bytes(n)       random_bytes defaults to the system CSPRNG
  SAVES_PER_HOUR = 10

ENVELOPE (one data key per stored key; the master key only wraps data keys):
  save_key draws, in this order: dek = random_bytes(32), data_nonce = random_bytes(12), wrap_nonce = random_bytes(12).
  ciphertext  = base64(data_nonce + GCM(key = dek, nonce = data_nonce, plaintext = the UTF-8 of the key,
                       aad = "byok:data:" + provider + ":" + user_id))
  wrapped_dek = base64(wrap_nonce + GCM(key = master_keys[key_id], nonce = wrap_nonce, plaintext = dek,
                       aad = "byok:dek:" + key_id + ":" + provider + ":" + user_id))
  GCM(...) = AES-256-GCM with a 12-byte nonce: the ciphertext followed by its 16-byte tag. aad = the UTF-8 of the
  text. base64 = RFC 4648 section 4, with padding. hint = the last 4 characters of the key.
  The aad binds a row to its user, provider and master key id: moved or edited, it no longer opens.

ENDPOINTS / FUNCTIONS (the checks run in the order written; the first that fails answers):
  save_key(user_id, provider, key) -> {provider, hint, key_id, created_at}
      1. provider is not in providers                       -> 404 {error: "unknown_provider"}
      2. key is not text                                    -> 400 {error: "invalid_key_format"}
         k = key without leading and trailing space, tab, CR, LF. k must start with the provider's prefix,
         have min_length to max_length characters, and hold only characters U+0021 to U+007E
                                                    otherwise -> 400 {error: "invalid_key_format"}
      3. w = now - (now mod 3600). COUNT THE CHECK FIRST, in one conditional write:
           INSERT INTO provider_key_save_windows (user_id, window_start, count) VALUES (:u, :w, 1)
             ON CONFLICT (user_id, window_start) DO UPDATE
               SET count = provider_key_save_windows.count + 1 WHERE provider_key_save_windows.count < 10
         No row changed (the count is already 10)           -> 429 {error: "rate_limited", retry_after: w + 3600 - now}
         Never "read the count, then add 1": two requests would both read 9. The check is counted whatever
         the provider then answers.
      4. v = provider_client.check(provider, k):  "rejected" -> 400 {error: "key_rejected"}
         "unreachable", any value other than "ok", or a raised error -> 502 {error: "provider_unreachable"}
      5. Build the ENVELOPE under active_key_id and write the row, replacing the user's earlier row for this
         provider: created_at = now, last_used_at = null. Add the audit row key_saved. The row and the audit
         row are ONE transaction; if it fails             -> 500 {error: "storage_failed"}, nothing written
      6. -> {provider, hint, key_id, created_at}
  list_keys(user_id) -> [{provider, hint, key_id, created_at, last_used_at}], sorted by provider
  use_key(user_id, provider, purpose) -> {key}          SERVER-SIDE ONLY: to call the provider for this user
      1. purpose is not text of 1 to 100 characters, each one of [A-Za-z0-9_.:-]
                                                            -> 400 {error: "invalid_purpose"}
      2. no row for (user_id, provider)                     -> 404 {error: "key_not_found"}
      3. the row's key_id is not in master_keys             -> 503 {error: "key_unavailable"}
      4. unwrapping the DEK or decrypting the key fails     -> 500 {error: "key_unreadable"}
         A stored value that is not base64, that decodes to fewer than 28 bytes, or a DEK that is not 32
         bytes, is 500 key_unreadable too: never an exception (check lengths before slicing).
      5. last_used_at = now; add the audit row key_used with the purpose. The two writes are ONE transaction;
         if it fails -> 500 {error: "storage_failed"} and NO key is returned: every use is recorded, or it
         did not happen.                                    -> {key}
  delete_key(user_id, provider) -> {deleted: true} and the audit row key_deleted, or {deleted: false} when
      there was no row (no audit row)
  rewrap() -> {rewrapped, failed}                       OPERATOR ONLY, never reachable from a request
      For each row whose key_id is not active_key_id, in (user_id, provider) order: unwrap the DEK with the row's
      master key (missing key or failed tag -> failed + 1, row unchanged); wrap_nonce = random_bytes(12); then
      write ONLY IF the row still holds the wrapped_dek that was read:
        UPDATE provider_keys SET key_id = :active, wrapped_dek = :new_wrapped
          WHERE user_id = :u AND provider = :p AND wrapped_dek = :wrapped_dek_read
      One row changed -> rewrapped + 1, add the audit row key_rewrapped. No row changed (the user saved a new
      key or deleted it meanwhile) -> leave it, count it in neither number, no audit row. ciphertext is never
      touched. An old master key may leave master_keys only after a rewrap() that returned failed: 0, and when
      no row names it.
  list_audit(user_id) -> [{at, action, provider, purpose, key_id}], oldest first

IMPLEMENTATION -- RULES:
  - The key appears in full only in save_key's input and use_key's result. Never in another result, a
    refusal, a log, an audit row or an exception message. list_keys shows the hint only.
  - The plain key and the DEK live in memory for the one call. Nothing derived from the key is stored except
    ciphertext and hint.
  - A key leaves the server only towards its own provider. The caller of use_key must not return or log it.
  - save_key is for a signed-in account with a confirmed email address (the caller checks that), and the hourly
    limit is on provider checks, so the vault is no oracle for testing stolen keys.
  - Fail closed: an unknown master key id is 503, never a try with another key; a failed tag is 500, never a
    partial or empty key. Unlike totp_two_factor, where a secret that does not open is 503, a failed tag is
    500 here: the key id already proved that the right master key is present (its absence is the 503), so
    what is left is a damaged or moved row.
  - Every nonce is 12 fresh random bytes. A DEK encrypts one key once, so a nonce never repeats under a key.
  - SQL is parameterized. A SQL store updates the save window with one conditional statement (insert, or add
    1 while the count is under 10), never a read followed by a write.

PRIMITIVES (standard library unless a package is named):
  AES-256-GCM      Python `cryptography` AESGCM (name it in the runner's list) | JavaScript, TypeScript
                   node:crypto createCipheriv("aes-256-gcm") with setAAD and getAuthTag | Java
                   javax.crypto.Cipher "AES/GCM/NoPadding" + GCMParameterSpec(128, nonce) | C#
                   System.Security.Cryptography.AesGcm | PHP openssl_encrypt / openssl_decrypt("aes-256-gcm",
                   OPENSSL_RAW_DATA, tag length 16) | Go crypto/aes + cipher.NewGCM | Rust aes-gcm crate (to
                   add). Where the library returns the tag apart, append it to the ciphertext.
                   The tag is always exactly the last 16 bytes; check the length (at least 28 bytes in all)
                   before slicing. Node: createDecipheriv(..., {authTagLength: 16}). PHP: pass a 16-byte tag,
                   the function does not check its length.
  base64, CSPRNG   every standard library (Rust: base64 and rand crates, on the runner's list)

TEST VECTORS (every language asserts these):
  Window tests (VAULT-12) start at now = 1699920000 (00:00:00 UTC: the first second of a clock hour). The
  next hour starts at 1699923600.
  providers = {"acme": {prefix: "acme_", min_length: 24, max_length: 200}}, user_id = "user_1"
  ({prefix: "acme_", min_length: 20, max_length: 200} fails construction: 20 is under 5 + 16)
  key = "acme_" + "k3y0123456789abcdefghWXYZ"            (30 characters, hint "WXYZ")
  master_keys = {"k1": the 32 bytes 00 01 ... 1f}, active_key_id = "k1"
  random_bytes gives: 32 bytes 20 21 ... 3f (the DEK), then 12 bytes 60 61 ... 6b, then 12 bytes 70 71 ... 7b
  save_key stores:
      ciphertext  = "YGFiY2RlZmdoaWprg/fAzqy7SCzJdVWPIX9FTko++mAiaT2vbM/uMNaLHZjhWoVBGl1vBtJurMStRQ=="
      wrapped_dek = "cHFyc3R1dnd4eXp7N6aYBJfsuhNsAxz5/W2f+J0G974wrnqNnbcDf3iKKAEOSVqlT/aJkU58qxAv2nPf"
  Rotation (VAULT-10): add "k2" = the 32 bytes 40 41 ... 5f, make it active, random_bytes gives 80 81 ... 8b:
      rewrap() stores key_id "k2", the same ciphertext, and
      wrapped_dek = "gIGCg4SFhoeIiYqLDX+c5AZRDKRAQ7oDXo+7DcjN++F5UtAjxrdC7+0oX0MOT3cH13mFkfvVnrrN/V6R"

TESTS:
  - **VAULT-01** save_key happy path: the provider check is called once with the key; the row holds key_id, wrapped_dek, ciphertext and the hint "WXYZ" and nowhere the key; the answer is {provider, hint, key_id, created_at}; an audit row key_saved exists
  - **VAULT-02** known answer: with master key k1, the injected random bytes and the key of the spec, the stored ciphertext and wrapped_dek are exactly the spec's two strings, and use_key returns the key
  - **VAULT-03** an unknown provider is 404 unknown_provider; a key with the wrong prefix, too short, too long, with a space or a line break inside, or that is not text is 400 invalid_key_format; only leading and trailing space, tab, CR and LF are trimmed first, so a key followed by U+00A0, U+000B or U+0000 is 400 invalid_key_format too; in each refusal the provider client is not called and nothing is stored
  - **VAULT-04** the provider answers "rejected" -> 400 key_rejected; "unreachable", any other answer or a raised error -> 502 provider_unreachable; no provider_keys row and no audit row is written (the check is still counted)
  - **VAULT-05** list_keys returns provider, hint, key_id, created_at and last_used_at, sorted by provider, and its serialized form holds neither the key nor ciphertext nor wrapped_dek
  - **VAULT-06** use_key returns the key, sets last_used_at to the clock's time and writes an audit row key_used with the purpose; an empty purpose, or one with a character outside [A-Za-z0-9_.:-], is 400 invalid_purpose; when the audit write fails the answer is 500 storage_failed with no key; no audit row and no refusal ever holds the key
  - **VAULT-07** isolation: user B's list is empty, use_key for a provider only user A saved is 404 key_not_found and delete_key is {deleted: false}; A's key is untouched
  - **VAULT-08** a row moved to another user, a row moved to another provider, one changed byte of the DECODED ciphertext and one of the decoded wrapped_dek (decode, XOR 01 into byte 20, encode again), and a stored value that is not base64 or is too short each make use_key answer 500 key_unreadable, never an exception
  - **VAULT-09** saving again for the same provider replaces the key: one row, a new DEK and new nonces, the new hint, and use_key returns the new key
  - **VAULT-10** rotation: with k2 added and active a new save is wrapped under k2; rewrap() re-wraps the older rows under k2, changes no ciphertext, returns {rewrapped: 1, failed: 0} and, with the injected nonce, stores the spec's string; with k1 then removed from the keyring every key still opens; the store's rewrap write changes no row when the row's wrapped_dek is no longer the one that was read
  - **VAULT-11** a row whose key_id is not in the keyring is 503 key_unavailable; a master key that is not 32 bytes, or an active_key_id that is not in the keyring, fails construction; a provider whose min_length is under its prefix's length + 16 fails construction with invalid_provider_config
  - **VAULT-12** at most 10 provider checks per user per clock hour: the 11th save_key is 429 rate_limited with retry_after and calls no provider; another user is not affected; in the next hour it works again; a malformed key does not count; the store's window write succeeds 10 times in one hour and not an 11th
  - **VAULT-13** delete_key removes the row and writes key_deleted; a second delete is {deleted: false} with no audit row; use_key is then 404 key_not_found
  - **VAULT-14** with real randomness, the same key saved for two users gives different ciphertext, different wrapped_dek and different nonces
```

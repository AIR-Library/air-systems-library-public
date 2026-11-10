# Idempotency Keys (Safe Retries)

Reference contract for `saas_templates/<lang>/idempotency_keys_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# IDEM-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `IDEM-01` | first call runs the operation once |
| `IDEM-02` | a second identical call returns the stored response and the operation count stays at 1 |
| `IDEM-03` | same key, different body -> 422 |
| `IDEM-04` | same key while the first is in progress -> 409 |
| `IDEM-05` | required operation with no key -> 400 |
| `IDEM-06` | the same key under two different scopes runs twice (independent) |
| `IDEM-07` | an expired completed key runs the operation again; an in_progress key past expires_at gets 409 outcome_unknown and does not run |
| `IDEM-08` | an operation that raises OperationFailed frees the key: a retry with the same key runs the operation |
| `IDEM-09` | error responses carry content_type "application/problem+json" and a body with type, title, detail |
| `IDEM-10` | an operation that raises any other error leaves the key 'uncertain': a retry gets 409 outcome_unknown and the operation count stays at 1; after release() a retry runs it |
| `IDEM-11` | resolve() on an 'uncertain' key stores the given response; a retry returns it without running the operation; a second resolve() or release() on it returns false |

## Contract

```text
Source: IETF draft-ietf-httpapi-idempotency-key-header-07 (Internet-Draft; IETF Trust provisions).

PURPOSE:
  Make POST/PATCH safe to retry: the same request with the same key runs ONCE (no double charges).

SCHEMA:
  idempotency_records (scope, idem_key, request_fingerprint, status 'in_progress'|'completed'|'uncertain',
                       response_status INT NULL, response_body TEXT NULL, created_at, expires_at,
                       PRIMARY KEY (scope, idem_key))

ENDPOINTS / FUNCTIONS:
  handle(scope, idempotency_key, method, path, body, operation) -> {status, content_type, body}
      scope = the authenticated client/user id. operation = the real work, called at most once;
      it returns {status, body} and its responses are served as "application/json".
      Every error (400/409/422) is served as "application/problem+json".
      Check order: missing key -> 400; different fingerprint -> 422 (even while the first request is still
      in progress); same fingerprint still in progress -> 409; same fingerprint whose outcome is uncertain ->
      409 with problem type "outcome_unknown"; completed -> the stored response.
  release(scope, idempotency_key) -> bool
      Frees an 'uncertain' key once reconciliation shows the first attempt did nothing, so a retry runs the
      operation. Returns false (and changes nothing) for a key that is not 'uncertain'.
  resolve(scope, idempotency_key, status, body) -> bool
      Stores the outcome that reconciliation found for an 'uncertain' key as 'completed', with
      expires_at = now + 24h, so a retry gets that stored response. Returns false (and changes nothing) for a
      key that is not 'uncertain'.
  list_uncertain(limit) -> [{scope, idem_key, created_at}], oldest first: the reconciliation work list.
      release(), resolve() and list_uncertain() are operator / reconciliation functions: never exposed to API
      clients, and scope is the stored record's scope, never taken from request input. release() and
      resolve() are each ONE conditional write (... WHERE scope = ? AND idem_key = ? AND status is uncertain),
      so of two concurrent calls exactly one returns true.
  is_required(method, path) -> bool (configurable; POST and PATCH by default)
  purge_expired()

IMPLEMENTATION -- RULES (quoted, section 2.7 "Error Handling"):
  - Header "Idempotency-Key"; value a unique string (UUID recommended).
  - fingerprint = SHA-256 of (method + " " + path + "\n" + body).
  - "If the Idempotency-Key request header is missing for a documented idempotent operation requiring
    this header, the resource SHOULD reply with an HTTP 400 status code".
  - "If the request is retried, while the original request is still being processed, the resource
    SHOULD reply with an HTTP 409 status code".
  - "If there is an attempt to reuse an idempotency key with a different request payload, the resource
    SHOULD reply with a HTTP 422 status code".
  - Same key + same fingerprint after completion: return the STORED status and body. Do NOT run the
    operation again.
  - Error bodies are application/problem+json (RFC 7807): {type, title, detail}.
  - Keys are scoped per client (two clients may use the same key independently) and expire after 24h.
  - Claim the key atomically (insert-if-absent) so two concurrent requests cannot both run.
  - Only a 'completed' record expires. An expired completed record counts as absent: the claim replaces it
    and the operation runs again. (The last TypeScript build kept the stale record and served its old
    response forever.)
  - An 'in_progress' record past expires_at (a killed process, a panic, any exit the handler could not catch)
    is UNCERTAIN: handle(), release(), resolve(), list_uncertain() and purge_expired() all treat it as
    'uncertain', and a claim never replaces it. Treating it as absent would charge twice after a crash.
  - An operation reports a DEFINITE failure (it did nothing, e.g. a validation error or a provider decline)
    by raising OperationFailed: `OperationFailed` (Python, JavaScript, TypeScript), `OperationFailedException`
    (Java, C#, PHP), an error wrapping `ErrOperationFailed` (Go, checked with errors.Is), or
    `OpError::Failed` (Rust). Then DELETE the in_progress record and re-raise, so a retry runs again
    (IDEM-08). (The last JavaScript build tried this and crashed with a ReferenceError in its catch block.)
  - ANY OTHER error (a timeout, a dropped connection, a crash after the provider was called) means the
    outcome is unknown: the charge may have happened. Set the record to 'uncertain' and re-raise. A retry
    with the same key gets 409 outcome_unknown and the operation does NOT run (IDEM-10), until release()
    or resolve() settles it (IDEM-10, IDEM-11). Deleting the key here would let a retry charge twice.
  - An 'uncertain' record never expires and purge_expired() keeps it: only release() or resolve() clears it.
    Amended again the same day after an independent security review (expiry of in_progress records,
    caller rule for release and resolve).
    Amended 2026-11-10 after review on PR 19.

TESTS:
  - **IDEM-01** first call runs the operation once
  - **IDEM-02** a second identical call returns the stored response and the operation count stays at 1
  - **IDEM-03** same key, different body -> 422
  - **IDEM-04** same key while the first is in progress -> 409
  - **IDEM-05** required operation with no key -> 400
  - **IDEM-06** the same key under two different scopes runs twice (independent)
  - **IDEM-07** an expired completed key runs the operation again; an in_progress key past expires_at gets 409 outcome_unknown and does not run
  - **IDEM-08** an operation that raises OperationFailed frees the key: a retry with the same key runs the operation
  - **IDEM-09** error responses carry content_type "application/problem+json" and a body with type, title, detail
  - **IDEM-10** an operation that raises any other error leaves the key 'uncertain': a retry gets 409 outcome_unknown and the operation count stays at 1; after release() a retry runs it
  - **IDEM-11** resolve() on an 'uncertain' key stores the given response; a retry returns it without running the operation; a second resolve() or release() on it returns false
```

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
| `IDEM-07` | an expired key runs the operation again |
| `IDEM-08` | an operation that raises frees the key: a retry with the same key runs the operation |
| `IDEM-09` | error responses carry content_type "application/problem+json" and a body with type, title, detail |

## Contract

```text
Source: IETF draft-ietf-httpapi-idempotency-key-header-07 (Internet-Draft; IETF Trust provisions).

PURPOSE:
  Make POST/PATCH safe to retry: the same request with the same key runs ONCE (no double charges).

SCHEMA:
  idempotency_records (scope, idem_key, request_fingerprint, status 'in_progress'|'completed',
                       response_status INT NULL, response_body TEXT NULL, created_at, expires_at,
                       PRIMARY KEY (scope, idem_key))

ENDPOINTS / FUNCTIONS:
  handle(scope, idempotency_key, method, path, body, operation) -> {status, content_type, body}
      scope = the authenticated client/user id. operation = the real work, called at most once;
      it returns {status, body} and its responses are served as "application/json".
      Every error (400/409/422) is served as "application/problem+json".
      Check order: missing key -> 400; different fingerprint -> 422 (even while the first request is still
      in progress); same fingerprint still in progress -> 409; completed -> the stored response.
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
  - An EXPIRED record counts as absent: the claim replaces it and the operation runs again. (The last
    TypeScript build kept the stale record and served its old response forever.)
  - If the operation raises/throws, DELETE the in_progress record, then re-raise -- otherwise the key is
    stuck "in progress" (409) until it expires. (The last JavaScript build tried this and crashed with a
    ReferenceError inside its own catch block.)

TESTS:
  - **IDEM-01** first call runs the operation once
  - **IDEM-02** a second identical call returns the stored response and the operation count stays at 1
  - **IDEM-03** same key, different body -> 422
  - **IDEM-04** same key while the first is in progress -> 409
  - **IDEM-05** required operation with no key -> 400
  - **IDEM-06** the same key under two different scopes runs twice (independent)
  - **IDEM-07** an expired key runs the operation again
  - **IDEM-08** an operation that raises frees the key: a retry with the same key runs the operation
  - **IDEM-09** error responses carry content_type "application/problem+json" and a body with type, title, detail
```

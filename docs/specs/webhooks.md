# Webhooks (Signed Outbound Delivery)

Reference contract for `saas_templates/<lang>/webhooks_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# HOOK-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `HOOK-01` | sign then verify round-trips |
| `HOOK-02` | a changed body fails verify; a changed timestamp fails verify |
| `HOOK-03` | a timestamp older than the tolerance is rejected |
| `HOOK-04` | verify accepts when one of two space-separated signatures matches |
| `HOOK-05` | a 200-299 response marks success; 301, 400 and 500 schedule a retry |
| `HOOK-06` | an event sent for org A creates no delivery for org B's endpoint subscribed to the same event type |
| `HOOK-07` | the webhook-id is identical across retries of one message |
| `HOOK-08` | a generated secret starts with "whsec_" and decodes to 24-64 bytes |

## Contract

```text
Source: Standard Webhooks specification (Apache-2.0).

PURPOSE:
  Deliver events to subscribers' URLs, signed so the receiver can prove they came from us, with
  retries and a delivery log. Also provide the receiver-side verify() so both ends are covered.

SCHEMA:
  webhook_endpoints (id, org_id, url, secret, event_types JSON, active BOOL, failure_count INT, created_at)
  webhook_messages  (id TEXT "msg_" + unique random, org_id, event_type, payload JSON, created_at)
  webhook_deliveries(id, message_id, endpoint_id, attempt INT, status_code INT NULL, success BOOL,
                     error TEXT NULL, next_attempt_at NULL, delivered_at NULL)

ENDPOINTS / FUNCTIONS:
  create_endpoint(org_id, url, event_types) -> {id, secret}
      secret = "whsec_" + base64(32 random bytes). URL must be https:// (http://localhost allowed for dev).
  send_event(org_id, event_type, payload) -> message_id
      Create ONE message for that org; create a pending delivery for every active endpoint OF THAT ORG
      subscribed to event_type. An org's events never reach another org's endpoints. (Amended 2026-09-26:
      the first version had no org_id, so every event fanned out to every tenant's endpoints.)
  sign(secret, msg_id, timestamp, body) -> "v1,<base64 signature>"
  deliver(delivery) -> POST body with headers webhook-id, webhook-timestamp, webhook-signature,
      Content-Type: application/json. Record status_code; on failure schedule the next attempt.
  verify(secret, headers, raw_body, tolerance_seconds=300) -> true | error   (receiver side)
  rotate_secret(endpoint_id) -> new secret

IMPLEMENTATION -- RULES (quoted):
  - Headers "webhook-id", "webhook-timestamp" ("integer unix timestamp (seconds since epoch)"),
    "webhook-signature".
  - Content signed is exactly "msg_id.timestamp.payload" (the RAW body bytes, never re-serialised).
  - Scheme "HMAC-SHA256". Key = base64-decode of the secret with its "whsec_" prefix removed.
    Secret "Random. Between 24 bytes (192 bits) and 64 bytes (512 bits)".
  - "a symmetric signature will be v1, followed by a comma (,), followed by the base64 encoded
    signature". The header may hold several space-separated signatures (secret rotation); verify
    accepts if ANY matches.
  - "use a constant time comparison function to compare the calculated with the expected signature".
  - Reject a timestamp outside the tolerance "to prevent replay attacks".
  - "delivery is considered successful if it was responded to with a 2xx status code (status codes
    200-299), and it is considered a failure in any other scenario".
  - The webhook-id stays THE SAME on every retry of a message (receivers use it as an idempotency key).
  - deliver() sends through the injectable sender (see BUILD & TEST CONTRACT); a sender that raises or
    times out counts as a failed attempt, never an unhandled error.
  - Retry with exponential backoff: after 5s, 5m, 30m, 2h, 5h, 10h, 10h. Disable an endpoint after 5
    consecutive fully-failed messages.

TESTS:
  - **HOOK-01** sign then verify round-trips
  - **HOOK-02** a changed body fails verify; a changed timestamp fails verify
  - **HOOK-03** a timestamp older than the tolerance is rejected
  - **HOOK-04** verify accepts when one of two space-separated signatures matches
  - **HOOK-05** a 200-299 response marks success; 301, 400 and 500 schedule a retry
  - **HOOK-06** an event sent for org A creates no delivery for org B's endpoint subscribed to the same event type
  - **HOOK-07** the webhook-id is identical across retries of one message
  - **HOOK-08** a generated secret starts with "whsec_" and decodes to 24-64 bytes
```

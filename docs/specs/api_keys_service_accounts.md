# Api Keys & Service Accounts

Reference contract for `saas_templates/<lang>/api_keys_service_accounts_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# KEYS-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `KEYS-01` | Create key with scopes |
| `KEYS-02` | Use key: request succeeds with Authorization header |
| `KEYS-03` | Revoke key: subsequent requests return 401 |
| `KEYS-04` | Rate limit: 1001st request in hour returns 429 |
| `KEYS-05` | Scope check: key with 'read:deployments' can't write deployments (403) |
| `KEYS-06` | Rotate: new key works, old key stops after grace period |
| `KEYS-07` | Expired key: after expires_at, request returns 401 |
| `KEYS-08` | Usage stats: requests counted per endpoint |
| `KEYS-09` | Admin audit: all keys visible to admin |

## Contract

```text
PURPOSE:
Customers need to integrate (API access, webhooks).
Scoped tokens: read_only, write_deployments, etc.
Rate limits: per key, per user.
Rotation: auto-expire, generate new.
Audit: every API call logged with key used.

SCHEMA:
api_keys (id, user_id, name, key_secret_hash [bcrypt], scopes [JSON], rate_limit, expires_at, created_at, last_used_at, is_active)
api_key_usage (id, api_key_id, endpoint, method, status: 200|400|401|etc, timestamp)

SCOPES (examples):
- read:users (GET /users)
- write:users (POST/PUT /users)
- read:deployments (GET /deployments)
- write:deployments (POST/PUT /deployments)
- read:invoices (GET /invoices)
- write:billing (POST /subscriptions, PUT /billing)
- webhook:manage (POST /webhooks, DELETE /webhooks)
- * (all actions, dangerous)

ENDPOINTS:

1. Create API key
   POST /api-keys
   {
     name: 'My Integration',
     scopes: ['read:deployments', 'write:webhooks'],
     expires_at: '2026-12-31',  // Optional
     rate_limit: 1000  // requests/hour
   }
   Response: {
     api_key_id: '...',
     key: 'sk_live_xxxxxxxxxxxxxxxxxxxx',  // Only shown once!
     created_at,
     expires_at,
     rate_limit: 1000
   }

2. List API keys (masked)
   GET /api-keys
   Response: {
     keys: [
       { api_key_id, name, scopes, created_at, last_used_at, rate_limit, is_active }
     ]
   }
   Note: 'key' field is NEVER returned in list (for security)

3. Revoke API key
   DELETE /api-keys/:api_key_id
   Response: { success: true, revoked_at }

4. Rotate API key (generate new, disable old)
   POST /api-keys/:api_key_id/rotate
   Response: {
     new_key: 'sk_live_yyyyyyyyyyyyyyyyyy',
     old_key_revoked_at: '2026-09-24T...',
     grace_period_ends_at: '2026-09-25T...'  // Old key still works for 24h
   }

5. Use API key (in request headers)
   GET /api/deployments
   Authorization: Bearer sk_live_xxxxxxxxxxxxxxxxxxxx

   Behind scenes:
   - Decode key (bcrypt verify against key_secret_hash)
   - Check scopes: does key have 'read:deployments'?
   - Check rate limit: have we exceeded 1000 req/hour?
   - Check is_active: is key revoked?
   - Log usage: record endpoint, method, status to api_key_usage
   - Response: data (if all checks pass) or 401 (invalid/revoked) or 429 (rate limited)

6. Get API key usage stats
   GET /api-keys/:api_key_id/usage?from=2026-09-01&to=2026-09-24
   Response: {
     api_key_id,
     total_requests: 50000,
     requests_by_endpoint: { 'GET /deployments': 40000, 'POST /webhooks': 10000 },
     rate_limit_hits: 2,  // Times we hit the rate limit
     errors: { '401': 0, '404': 100, '500': 5 }
   }

7. Admin: list all API keys for audit
   GET /admin/api-keys?user_id=123&status=active
   Response: { keys: [...], total: 5 }

IMPLEMENTATION:
- Key format: sk_live_<random> or sk_test_<random>
- Storage: bcrypt hash of secret (never store plaintext)
- Scoping: check scopes[action] before allowing request
- Rate limiting: Redis counter (key_id:2026-09-24T10:00:00) = 450
- Expiry: cron job checks expires_at, marks as_active=false
- Rotation grace period: 24h where old key still works (smooth transition)
- Audit: Every API call logged to api_key_usage (for rate limit investigation)

TESTS:
- **KEYS-01** Create key with scopes
- **KEYS-02** Use key: request succeeds with Authorization header
- **KEYS-03** Revoke key: subsequent requests return 401
- **KEYS-04** Rate limit: 1001st request in hour returns 429
- **KEYS-05** Scope check: key with 'read:deployments' can't write deployments (403)
- **KEYS-06** Rotate: new key works, old key stops after grace period
- **KEYS-07** Expired key: after expires_at, request returns 401
- **KEYS-08** Usage stats: requests counted per endpoint
- **KEYS-09** Admin audit: all keys visible to admin
```

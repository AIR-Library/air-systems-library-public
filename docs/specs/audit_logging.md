# Audit Logging (Immutable Event Log With Replay)

Reference contract for `saas_templates/<lang>/audit_logging_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# AUDIT-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `AUDIT-01` | Happy path: log mutation, query it back |
| `AUDIT-02` | Replay: divergence detection (state changed since log) |
| `AUDIT-03` | Filtering: actor_id + action + resource_type work together |
| `AUDIT-04` | Pagination: limit/offset work |
| `AUDIT-05` | Performance: 1M+ logs, queries return <100ms |
| `AUDIT-06` | Immutability: UPDATE on log returns error |
| `AUDIT-07` | Wildcard: action='user_*' matches user_created, user_suspended, etc. |

## Contract

```text
PURPOSE:
Every mutation gets logged immutably. Given log entry, replay with frozen state.
Used by: GDPR compliance, SOC2, debugging, fraud detection, governance approval

SCHEMA:
audit_log (id, timestamp, actor_id, actor_type, action, resource_type, resource_id, old_value [JSON], new_value [JSON], why_chain_id, metadata)
- timestamp: UTC, ISO 8601
- actor_id: user ID (or null if system)
- actor_type: 'user' | 'service' | 'api_key'
- action: 'user_created' | 'user_suspended' | 'billing_changed' | etc (pattern: resource_action)
- resource_type: 'user' | 'subscription' | 'deployment' | etc
- resource_id: UUID or numeric ID
- old_value: snapshot before mutation
- new_value: snapshot after mutation
- why_chain_id: link to why_chains table (optional, from earlier layer)
- metadata: extra context {ip, user_agent, request_id, feature_flag, custom_fields}

ENDPOINTS:

1. Log mutation (called BEFORE commit)
   POST /audit/log
   {
     actor_id: 123,
     actor_type: 'user',
     action: 'subscription_changed',
     resource_type: 'subscription',
     resource_id: 456,
     old_value: { tier: 'team', billing_date: '2026-10-15' },
     new_value: { tier: 'enterprise', billing_date: '2026-10-15' },
     why_chain_id: 'wc_789'
   }
   Response: { success: true, log_id: '...' }

2. Query logs (filter + paginate)
   GET /audit/logs?actor_id=123&action=user_*&resource_type=user&limit=100&offset=0&date_from=2026-01-01&date_to=2026-12-31
   Response: { logs: [...], total: 1204, has_more: true }

   Each log: { id, timestamp, actor_id, action, resource_type, resource_id, old_value, new_value, why_chain_id }

3. Replay (given log_id, what was state at that moment?)
   GET /audit/replay/:log_id
   Response: {
     log_id,
     timestamp,
     resource_state_at_time: {...old_value},
     has_diverged: false  // Did state change since this log?
   }

4. Search (full-text over actions and resources)
   GET /audit/search?q=user_email&resource_type=user&limit=50
   Response: { results: [...] }

IMPLEMENTATION:
- Database: Store ALL mutations, never delete (archival tier optional)
- Indexing: Index on (actor_id, action, resource_type, timestamp) for fast queries
- Immutability: Once inserted, no updates (append-only log)
- Retention: Keep indefinitely (GDPR requires 7+ years for some industries)
- Integration: Every mutation in Auth, Billing, Admin, Permissions calls audit.log()

TESTS:
- **AUDIT-01** Happy path: log mutation, query it back
- **AUDIT-02** Replay: divergence detection (state changed since log)
- **AUDIT-03** Filtering: actor_id + action + resource_type work together
- **AUDIT-04** Pagination: limit/offset work
- **AUDIT-05** Performance: 1M+ logs, queries return <100ms
- **AUDIT-06** Immutability: UPDATE on log returns error
- **AUDIT-07** Wildcard: action='user_*' matches user_created, user_suspended, etc.
```

# Quotas & Rate Limiting

Reference contract for `saas_templates/<lang>/quotas_rate_limiting_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# QUOTA-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `QUOTA-01` | api_quota PASS → call succeeds, usage incremented |
| `QUOTA-02` | api_quota FAIL → call rejected 429 |
| `QUOTA-03` | storage_quota PASS → file stored |
| `QUOTA-04` | storage_quota FAIL → upload rejected 413 |
| `QUOTA-05` | rate_limit_per_user PASS → < 100/min allowed |
| `QUOTA-06` | rate_limit_per_user FAIL → 100+/min rejected 429 |
| `QUOTA-07` | rate_limit_per_ip PASS → < 10/sec allowed |
| `QUOTA-08` | rate_limit_per_ip FAIL → 10+/sec rejected 429 |
| `QUOTA-09` | feature_gate PASS → feature available in tier |
| `QUOTA-10` | feature_gate FAIL → feature unavailable, 403 with upgrade hint |
| `QUOTA-11` | month rollover → usage_metrics reset for new month |
| `QUOTA-12` | tier upgrade → limits updated immediately |
| `QUOTA-13` | a limit of -1 is unlimited → enterprise storage upload of any size stored, and enterprise API calls past every other tier's limit never get 429 from the quota |

## Contract

```text
QUOTA CHECKS (on every API request):

  1. api_call_quota
     Query: SELECT SUM(call_count) FROM usage_metrics WHERE user_id = ? AND month = CURRENT_MONTH
     Limit: {solo: 1000, team: 10000, enterprise: unlimited}
     Decision: PASS if (current_usage + 1) <= limit
              REJECT if exceeds limit
     Log: why_chain(gate="api_quota_check", user_id, tier, current_usage, limit)
     Action: if REJECT: return 429 {error: "quota_exceeded", usage, limit, reset_date}
             else: increment usage counter

  2. storage_quota
     Query: SELECT SUM(bytes) FROM user_files WHERE user_id = ?
     Limit: {solo: 1e9, team: 100e9, enterprise: -1}
     Decision: PASS if limit == -1 (unlimited), else PASS if (current_storage + incoming_file_size) <= limit
     Log: why_chain(gate="storage_quota_check", user_id, tier, current_usage, limit)
     Action: if REJECT: return 413 {error: "storage_quota_exceeded", usage, limit}

  3. rate_limit_per_user
     Query: SELECT COUNT(*) FROM api_calls WHERE user_id = ? AND timestamp > NOW() - INTERVAL 1 MINUTE
     Limit: 100 requests per minute (all tiers)
     Decision: PASS if count < 100
     Action: if REJECT: return 429 {error: "rate_limit_exceeded", reset_seconds: 60}

  4. rate_limit_per_ip
     Query: SELECT COUNT(*) FROM api_calls WHERE ip = ? AND timestamp > NOW() - INTERVAL 1 SECOND
     Limit: 10 requests per second (all IPs)
     Decision: PASS if count < 10
     Action: if REJECT: return 429 {error: "ip_rate_limit_exceeded", reset_seconds: 1}

  5. feature_gate_by_tier
     features = {
       feature_a: ["team", "enterprise"],  # solo cannot use
       feature_b: ["enterprise"],          # only enterprise
       feature_c: ["solo", "team", "enterprise"]  # all can use
     }
     Decision: PASS if user.tier in allowed_tiers for feature
     Log: why_chain(gate="feature_gate", user_id, feature, tier, allowed_tiers)
     Action: if REJECT: return 403 {error: "feature_not_available_in_tier", upgrade_url}

IMPLEMENTATION REQUIREMENTS:
  - usage_metrics table: (user_id, month, call_count, storage_bytes, updated_at)
  - api_calls table: (id, user_id, ip, endpoint, timestamp, status_code, response_time_ms)
  - Rate limiting: use in-memory counter (Redis if distributed) or DB query
  - Return on quota exceeded: {error: "quota_exceeded", current: X, limit: Y, reset_date: "..."}
  - Return on feature unavailable: {error: "feature_not_available", tier: "solo", minimum_tier: "team"}

TESTS REQUIRED:
  - **QUOTA-01** api_quota PASS → call succeeds, usage incremented
  - **QUOTA-02** api_quota FAIL → call rejected 429
  - **QUOTA-03** storage_quota PASS → file stored
  - **QUOTA-04** storage_quota FAIL → upload rejected 413
  - **QUOTA-05** rate_limit_per_user PASS → < 100/min allowed
  - **QUOTA-06** rate_limit_per_user FAIL → 100+/min rejected 429
  - **QUOTA-07** rate_limit_per_ip PASS → < 10/sec allowed
  - **QUOTA-08** rate_limit_per_ip FAIL → 10+/sec rejected 429
  - **QUOTA-09** feature_gate PASS → feature available in tier
  - **QUOTA-10** feature_gate FAIL → feature unavailable, 403 with upgrade hint
  - **QUOTA-11** month rollover → usage_metrics reset for new month
  - **QUOTA-12** tier upgrade → limits updated immediately
  - **QUOTA-13** a limit of -1 is unlimited → enterprise storage upload of any size stored, and enterprise API calls past every other tier's limit never get 429 from the quota
```

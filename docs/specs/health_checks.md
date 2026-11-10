# Health Checks (Liveness + Readiness)

Reference contract for `saas_templates/<lang>/health_checks_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# HEALTH-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `HEALTH-01` | all checks pass -> 200, status "pass", Content-Type application/health+json |
| `HEALTH-02` | a critical check fails -> 503, status "fail" |
| `HEALTH-03` | only a non-critical check fails -> 200, status "warn" |
| `HEALTH-04` | a slow check past its timeout -> that check "fail" |
| `HEALTH-05` | liveness stays "pass" even when a dependency check would fail |
| `HEALTH-06` | the output contains no connection string |

## Contract

```text
Source: IETF draft-inadarei-api-health-check-06 (Internet-Draft; IETF Trust provisions).

PURPOSE:
  Tell load balancers and monitors whether the service is alive and ready, in a standard format.

SCHEMA:
  none -- an in-memory registry of checks.

ENDPOINTS / FUNCTIONS:
  register_check(component_id, component_type, check_fn, critical BOOL, timeout_ms)
  liveness() -> {http_status, content_type, body}   -- the process is up; runs NO dependency checks
  readiness() -> {http_status, content_type, body}  -- runs every registered check, each with its own
                                                        timeout; content_type "application/health+json"

IMPLEMENTATION -- RULES (quoted):
  - Content-Type "application/health+json".
  - Body field "status" is one of "pass", "fail", "warn".
  - "For "pass" status, HTTP response code in the 2xx-3xx range MUST be used. For "fail" status, HTTP
    response code in the 4xx-5xx range MUST be used. In case of the "warn" status, endpoints MUST return
    HTTP status in the 2xx-3xx range". Use 200 for pass/warn and 503 for fail.
  - Optional fields: version, releaseId, serviceId, description, and
    checks: { "<componentName>:<measurementName>": [ {componentId, componentType, observedValue,
    observedUnit, status, time} ] }.
  - Any CRITICAL check failing -> overall "fail". Only non-critical checks failing -> overall "warn".
  - A check that exceeds its timeout counts as "fail" for that check.
  - Never put secrets, connection strings or stack traces in the output.

TESTS:
  - **HEALTH-01** all checks pass -> 200, status "pass", Content-Type application/health+json
  - **HEALTH-02** a critical check fails -> 503, status "fail"
  - **HEALTH-03** only a non-critical check fails -> 200, status "warn"
  - **HEALTH-04** a slow check past its timeout -> that check "fail"
  - **HEALTH-05** liveness stays "pass" even when a dependency check would fail
  - **HEALTH-06** the output contains no connection string
```

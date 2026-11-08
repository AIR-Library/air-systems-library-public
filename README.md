# AOI Systems Library

Reference implementations of common SaaS building blocks (authentication, billing, webhooks, RBAC,
rate limiting, ...), each written to a shared contract in **eight languages**: C#, Go, Java,
JavaScript, PHP, Python, Rust and TypeScript.

The code was machine-generated and is **unfinished**: many suites do not pass
yet. This repository is where that gets fixed in the open. Treat everything here as a starting point,
not production code.

## Layout

    saas_templates/<lang>/<system>_<lang>.<ext>          implementation
    saas_templates/<lang>/<system>_<lang>_tests.<ext>    its tests
    docs/                                                reference spec for the auth / admin / trial-abuse systems
    tools/run_suites.py                                  one test runner for every language
    ci/baseline.json                                     suites known to fail today

18 systems x 8 languages = 144 suites.

## Status

Last checked 2026-11-05 by CI with `tools/run_suites.py`. Legend: ✅ passes, ❌ fails.
Suites that fail today are listed in `ci/baseline.json`. A missing file or a file that does not parse fails
CI even for a suite on that list.

| system | csharp | go | java | javascript | php | python | rust | typescript |
|---|---|---|---|---|---|---|---|---|
| admin_system | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ |
| api_keys_service_accounts | ❌ | ❌ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| audit_logging | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ❌ |
| auth_system | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| background_jobs_task_queue | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| billing_subscriptions | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ |
| data_export_compliance | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ |
| feature_flags | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ |
| file_uploads | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| full_text_search_indexing | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| health_checks | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| idempotency_keys | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| notifications | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| organizations_teams | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| permissions_rbac | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| quotas_rate_limiting | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ❌ |
| trial_abuse_prevention | ❌ | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| webhooks | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| **passing** | **7/18** | **12/18** | **10/18** | **11/18** | **13/18** | **13/18** | **3/18** | **10/18** |

CI's per-suite table (in each job's summary) is the live version of this; this table is refreshed by
hand and can lag. Some failures depend on the toolchain version: the Python suites were written
against Python 3.14, where annotations are evaluated lazily, and fail with a `NameError` on 3.11/3.12.

## Running tests

    python tools/run_suites.py --lang go                       # every system in one language
    python tools/run_suites.py --lang rust --systems webhooks  # one suite

The runner installs each language's packages into `.deps/` on first use. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the toolchain you need per language.

## How to help

Every ❌ above is a good first issue:

1. Pick one system in one language, run its suite, read the failure.
2. Fix the implementation (or the test, if the test is wrong; say why in the PR). Never weaken a test
   just to get green.
3. Open one pull request per system and language, with `git commit -s` sign-off.
4. If the suite now passes, delete its line from `ci/baseline.json`.

CI fails on **regressions** (a suite that is not in `ci/baseline.json` and does not pass), so
`main` stays green while the known failures are worked down. New systems and new languages are welcome:
open a "New system or feature" issue first so the contract is agreed across languages.

## License

[Apache-2.0](LICENSE). Contributions are accepted under the same license with a DCO sign-off, see
[CONTRIBUTING.md](CONTRIBUTING.md). Please follow the [Code of Conduct](CODE_OF_CONDUCT.md); report
security problems as described in [SECURITY.md](SECURITY.md).

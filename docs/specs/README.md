# System specs

One file per system. Each file is the contract that all eight implementations of that system follow:
Python, JavaScript, TypeScript, Java, C#, PHP, Go and Rust. Code lives in
`saas_templates/<lang>/<system>_<lang>.<ext>`, and its tests live in `<system>_<lang>_tests.<ext>`.

| system | spec | required tests |
|---|---|---|
| admin_system | [admin_system.md](admin_system.md) | 18 |
| api_keys_service_accounts | [api_keys_service_accounts.md](api_keys_service_accounts.md) | 9 |
| audit_logging | [audit_logging.md](audit_logging.md) | 9 |
| auth_system | [auth_system.md](auth_system.md) | 15 |
| background_jobs_task_queue | [background_jobs_task_queue.md](background_jobs_task_queue.md) | 9 |
| billing_subscriptions | [billing_subscriptions.md](billing_subscriptions.md) | 10 |
| data_export_compliance | [data_export_compliance.md](data_export_compliance.md) | 12 |
| feature_flags | [feature_flags.md](feature_flags.md) | 8 |
| file_uploads | [file_uploads.md](file_uploads.md) | 7 |
| full_text_search_indexing | [full_text_search_indexing.md](full_text_search_indexing.md) | 9 |
| health_checks | [health_checks.md](health_checks.md) | 6 |
| idempotency_keys | [idempotency_keys.md](idempotency_keys.md) | 11 |
| notifications | [notifications.md](notifications.md) | 12 |
| organizations_teams | [organizations_teams.md](organizations_teams.md) | 6 |
| permissions_rbac | [permissions_rbac.md](permissions_rbac.md) | 10 |
| quotas_rate_limiting | [quotas_rate_limiting.md](quotas_rate_limiting.md) | 13 |
| trial_abuse_prevention | [trial_abuse_prevention.md](trial_abuse_prevention.md) | 15 |
| webhooks | [webhooks.md](webhooks.md) | 8 |

[../SPEC_auth_admin_trial_abuse.md](../SPEC_auth_admin_trial_abuse.md) is an overview of how auth, admin and
trial abuse fit together. The files here are the detailed contract.

## Rules for every system

- **Same answer in every language.** The functions, error codes and return shapes in a system's spec are
  the same in all eight languages. Two languages that answer the same input differently means one of them
  has a bug.
- **Storage behind an interface.** Each system keeps its data behind a small store interface. The tests
  use an in-memory store or in-memory SQLite. A SQL store follows the schema in the spec.
  - Every function and thread must share the same store. SQLite `:memory:` opened per connection is a new,
    empty database each time.
- **No network in tests.** Stripe, email, SMS, S3, Redis and HTTP callbacks are reached through an
  injectable sender or client. The tests pass a fake.
- **Deterministic.**
  - No test may depend on the time of day, a race between threads, or random ordering.
  - Ties are broken by insertion order.
  - Time comes from an injectable clock where the spec involves time.
- **Secure by default.**
  - Secrets, tokens and signatures are compared in constant time.
  - SQL is parameterized.
  - No secret is hard-coded or written to a log.
  - Identity comes from the verified caller, never from client-controlled input.
- **Tests carry the spec's ids.** Every id in a spec's "Required tests" table has at least one test in every
  language. The id is written exactly as in the spec, hyphen included, in a comment on the line above the
  test or in the test's display name, for example `# HOOK-01` or `// AUTH-03`. A missing id is a missing
  test: `tools/run_suites.py` reports the suite INCOMPLETE and CI fails. Only a test that proves what the
  row says may carry its id.
- **Never weaken a test to get green.** If a test is wrong, fix it and say why in the pull request. A
  threshold such as the 200 ms search budget is part of the contract.

## Running

    python tools/run_suites.py --lang <lang> --systems <system>

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for the toolchain each language needs.

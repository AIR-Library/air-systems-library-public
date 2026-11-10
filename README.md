# AOI Systems Library

Reference implementations of common SaaS building blocks (authentication, billing, webhooks, RBAC,
rate limiting, ...), each written to a shared contract in **eight languages**: C#, Go, Java,
JavaScript, PHP, Python, Rust and TypeScript.

The code was first machine-generated, then repaired and reviewed suite by suite: every suite in every language
now passes its tests in CI. It is reference code to learn from and adapt. Review it before you use it in
production, and wire in your own authentication, secrets and providers where the templates use fakes or
interfaces.

## Layout

    saas_templates/<lang>/<system>_<lang>.<ext>          implementation
    saas_templates/<lang>/<system>_<lang>_tests.<ext>    its tests
    docs/specs/<system>.md                               each system's contract and its required tests
    tools/run_suites.py                                  one test runner for every language
    tools/readme_status.py                               writes the status table below from ci/baseline.json
    ci/baseline.json                                     suites known to fail today (empty when all pass)

24 systems x 8 languages = 192 suites. Six of them (secret and PII screening, TOTP two-factor, a bring-your-own-key
vault, Stripe webhook entitlements, safe archive ingest and passwordless email-code sign-in) were added on 2026-11-10,
built from code already tested in the maintainers' own apps.

## Status

Legend: ✅ passes, ❌ fails. The table is generated from `ci/baseline.json` by `tools/readme_status.py`, and CI
fails when it is out of date. CI fails any suite that does not pass unless it is listed in `ci/baseline.json`; a
missing file or a file that does not parse fails CI even for a suite on that list.

<!-- status:start -->
192 of 192 suites pass.

| system | csharp | go | java | javascript | php | python | rust | typescript |
|---|---|---|---|---|---|---|---|---|
| admin_system | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| api_keys_service_accounts | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| audit_logging | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| auth_system | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| background_jobs_task_queue | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| billing_subscriptions | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| byok_key_vault | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| data_export_compliance | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| feature_flags | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| file_uploads | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| full_text_search_indexing | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| health_checks | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| idempotency_keys | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| notifications | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| organizations_teams | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| passwordless_email_code_signin | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| permissions_rbac | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| quotas_rate_limiting | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| safe_archive_ingest | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| secret_pii_screening | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| stripe_webhook_entitlements | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| totp_two_factor | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| trial_abuse_prevention | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| webhooks | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **passing** | **24/24** | **24/24** | **24/24** | **24/24** | **24/24** | **24/24** | **24/24** | **24/24** |
<!-- status:end -->

Each CI job's summary also shows its language's per-suite table with test counts. CI runs Python 3.12, Node 22,
JDK 21, PHP 8.3, .NET 8 and stable Go and Rust. Each system's contract and the tests it requires are in
[docs/specs/](docs/specs/README.md).

## Running tests

    python tools/run_suites.py --lang go                       # every system in one language
    python tools/run_suites.py --lang rust --systems webhooks  # one suite

The runner installs each language's packages into `.deps/` on first use. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the toolchain you need per language.

## How to help

Every suite passes today, so help now means making the templates better:

1. Read a system's spec in [docs/specs/](docs/specs/README.md) and compare a language's behaviour with it. All
   eight languages must give the same answer for the same input; a difference is a bug.
2. Fix it with a test that fails before your change. Never weaken a test to get green; if a test is wrong,
   say why in the PR.
3. Open one pull request per system and language, with `git commit -s` sign-off.

CI fails when any suite does not pass (a suite listed in `ci/baseline.json` is excused, and the list is empty), when
a file is missing or does not parse, or when this README's table is out of date. New systems and new languages are
welcome: open a "New system or feature" issue first so the contract is agreed across languages.

## License

[Apache-2.0](LICENSE). Contributions are accepted under the same license with a DCO sign-off, see
[CONTRIBUTING.md](CONTRIBUTING.md). Please follow the [Code of Conduct](CODE_OF_CONDUCT.md); report
security problems as described in [SECURITY.md](SECURITY.md).

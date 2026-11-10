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
| `AUDIT-08` | erase_subject(user): no retained row in audit_log, audit_personal or audit_subjects holds the user's id, email or IP; the entry count and every audit_log row are unchanged; queries show the entry with personal_erased true, and an actor_id filter for the user finds nothing |
| `AUDIT-09` | apply_retention: personal data of entries older than the retention period is erased; newer entries keep theirs; no audit_log row is removed |

## Contract

```text
PURPOSE:
Every mutation gets logged immutably. Given log entry, replay with frozen state.
Used by: GDPR compliance, SOC2, debugging, fraud detection, governance approval

SCHEMA:
The log keeps events; personal data lives beside it so it can be erased without rewriting an event.
Amended 2026-11-10 after review on PR 19 (personal data must be erasable while the log stays append-only).

audit_log (id, timestamp, actor_type, action, resource_type, resource_id NULL, old_value [JSON] NULL,
           new_value [JSON] NULL, why_chain_id, personal_roles, metadata)      -- append-only, never updated
- timestamp: UTC, ISO 8601
- actor_type: 'user' | 'service' | 'api_key'
- action: 'user_created' | 'user_suspended' | 'billing_changed' | etc (pattern: resource_action)
- resource_type: 'user' | 'subscription' | 'deployment' | etc
- resource_id: UUID or numeric ID; NULL here when the resource is the data subject (it is kept in audit_personal)
- old_value / new_value: snapshots before and after; NULL here when the entry has a data subject (kept in
  audit_personal)
- why_chain_id: link to why_chains table (optional, from earlier layer)
- personal_roles: which audit_personal rows the entry was written with: '', 'actor', 'subject' or 'actor,subject'
- metadata: non-personal context only {request_id, feature_flag}

audit_personal (log_id, subject_ref, role 'actor'|'subject', data [JSON], PRIMARY KEY (log_id, role))
- role 'actor': data = {actor_id, ip, user_agent} for an entry whose actor_type is 'user'
- role 'subject': data = {resource_id (when the resource is the subject), old_value, new_value}
- rows are inserted with their entry and never updated; they are deleted only by erase_subject() and
  apply_retention()

audit_subjects (subject_ref, user_id UNIQUE, created_at)
- subject_ref is a random 128-bit value made the first time a user appears. It is NEVER derived from the user
  id (a hash of a small id space can be reversed), so once this row is deleted nothing links the log to the user.

Which user is an entry's data subject: the subject_user_id given to log(); when none is given, the resource_id of
a resource_type 'user' entry; otherwise the entry has no subject and its snapshots stay in audit_log.

ENDPOINTS:

1. Log mutation (called BEFORE commit)
   POST /audit/log
   {
     actor_id: 123,
     actor_type: 'user',
     subject_user_id: 789,     // optional: the user whose personal data the snapshots hold
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

5. Erase a data subject (statutory erasure, or account deletion in data_export_compliance)
   erase_subject(user_id) -> {erased_rows}
   Deletes every audit_personal row with the user's subject_ref, then the user's audit_subjects row. No
   audit_log row is updated or deleted. Then logs action 'audit_subject_erased' with no personal data
   (metadata {erased_rows} only).

6. Apply retention
   apply_retention(now) -> {erased_rows}
   Deletes the audit_personal rows of entries older than the configured retention period, and any
   audit_subjects row left with no audit_personal rows. audit_log rows stay.

Reads after erasure: query and search return the entry with its personal fields null and personal_erased: true
(its personal_roles say data was written, and those rows are gone). A filter on actor_id cannot match an erased
actor. Replay of an entry whose subject rows are gone returns {log_id, timestamp, erased: true,
resource_state_at_time: null, has_diverged: null}.

IMPLEMENTATION:
- Database: Store ALL mutations, never delete an event (archival tier optional)
- Indexing: Index on (action, resource_type, timestamp) in audit_log, and on (subject_ref, role) in
  audit_personal, so filters on actor_id resolve through audit_subjects and audit_personal quickly
- Immutability: audit_log is append-only: UPDATE and DELETE are refused. audit_personal rows are never updated.
- Retention: a configured retention period (days), set by purpose and the legal obligations that apply (some
  industries require several years; GDPR itself sets no fixed period and limits storage to what is necessary).
  apply_retention() erases the personal data of older entries; the events stay, so the chain is intact.
- Erasure: erase_subject() runs for a statutory erasure request and for account deletion. Afterwards no retained
  row in audit_log, audit_personal or audit_subjects may contain the user's id, email or IP (AUDIT-08). Backups
  and exports made before erasure are outside this template; a deployment must expire them on its own schedule.
- Integration: Every mutation in Auth, Billing, Admin, Permissions calls audit.log()
- Amended 2026-11-10 after review on PR 19. Before, the spec said to pseudonymize entries in place, which both
  rewrites an append-only log and can leave the person identifiable.

TESTS:
- **AUDIT-01** Happy path: log mutation, query it back
- **AUDIT-02** Replay: divergence detection (state changed since log)
- **AUDIT-03** Filtering: actor_id + action + resource_type work together
- **AUDIT-04** Pagination: limit/offset work
- **AUDIT-05** Performance: 1M+ logs, queries return <100ms
- **AUDIT-06** Immutability: UPDATE on log returns error
- **AUDIT-07** Wildcard: action='user_*' matches user_created, user_suspended, etc.
- **AUDIT-08** erase_subject(user): no retained row in audit_log, audit_personal or audit_subjects holds the user's id, email or IP; the entry count and every audit_log row are unchanged; queries show the entry with personal_erased true, and an actor_id filter for the user finds nothing
- **AUDIT-09** apply_retention: personal data of entries older than the retention period is erased; newer entries keep theirs; no audit_log row is removed
```

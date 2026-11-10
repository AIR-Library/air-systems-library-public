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
| `AUDIT-08` | erase_subject(user): no retained row in audit_log, audit_personal or audit_subjects holds the user's id, email or IP; every earlier audit_log row is unchanged and exactly one row is added ('audit_subject_erased', personal_roles '', metadata {erased_rows}); queries show the user's entries with personal_erased true, and an actor_id filter for the user finds nothing |
| `AUDIT-09` | apply_retention: personal data of entries older than the retention period is erased; newer entries keep theirs; no audit_log row is removed |
| `AUDIT-10` | log() refuses a non-'user' entry without subject_user_id (400 subject_required), a metadata key other than feature_flag/erased_rows (400 metadata_key_not_allowed), and an api_key entry without actor_user_id (400 actor_user_required); reads by a non-admin caller get 403 |

## Contract

```text
PURPOSE:
Every mutation gets logged immutably. Given log entry, replay with frozen state.
Used by: GDPR compliance, SOC2, debugging, fraud detection, governance approval

SCHEMA:
The log keeps events; personal data lives beside it so it can be erased without rewriting an event.
Amended 2026-11-10 after review on PR 19 (personal data must be erasable while the log stays append-only), and
again the same day after an independent security review (nothing that leads back to a person stays in audit_log).

audit_log (id, timestamp, actor_type, actor_service NULL, action, resource_type, resource_id NULL,
           old_value [JSON] NULL, new_value [JSON] NULL, why_chain_id NULL, personal_roles, metadata)
           -- append-only: UPDATE and DELETE are refused
- timestamp: UTC, ISO 8601
- actor_type: 'user' | 'service' | 'api_key'
- actor_service: the service's name when actor_type is 'service'; NULL otherwise
- action: 'user_created' | 'user_suspended' | 'billing_changed' | etc (pattern: resource_action)
- resource_type: 'user' | 'subscription' | 'deployment' | etc
- resource_id, old_value, new_value, why_chain_id: kept here ONLY for an entry with no data subject
  (subject 'none'); for an entry with a subject all four are NULL here and live in its 'subject' row
- personal_roles: which audit_personal rows the entry was written with: '', 'actor', 'subject' or 'actor,subject'
- metadata: only the keys feature_flag and erased_rows; log() refuses any other key with 400
  metadata_key_not_allowed (an ip, email or request id in metadata would outlive erasure)

audit_personal (log_id, subject_ref REFERENCES audit_subjects, role 'actor'|'subject', data [JSON],
                PRIMARY KEY (log_id, role))
- role 'actor': data = {actor_id, ip, user_agent, request_id}. Written when actor_type is 'user' (subject_ref of
  actor_id), and when actor_type is 'api_key' (subject_ref of actor_user_id, the key's owner, which log()
  then requires: 400 actor_user_required)
- role 'subject': data = {resource_id, old_value, new_value, why_chain_id}
- rows are inserted with their entry and never updated; they are deleted only by erase_subject() and
  apply_retention()

audit_subjects (subject_ref, user_id UNIQUE, created_at)
- subject_ref is a random 128-bit value made the first time a user appears. It is NEVER derived from the user
  id (a hash of a small id space can be reversed), so once this row is deleted nothing links the log to the user.
- log() finds or creates the subject (insert-if-absent on user_id) and inserts the entry and its audit_personal
  rows in ONE transaction, so a concurrent erase_subject() or apply_retention() leaves no orphan row. With that,
  the two may run in either order.

Refusals by log(), each 400 with this error code: actor_type not 'user', 'service' or 'api_key' ->
invalid_actor_type; actor_type 'user' without actor_id -> actor_required; actor_type 'service' without
actor_service -> actor_service_required; and the codes below. erase_subject() and apply_retention() return
erased_rows = the number of audit_personal rows they deleted. Amended 2026-11-10 (Phase B.2: one answer in every language).

Which user is an entry's data subject:
- resource_type 'user': the resource_id. A different subject_user_id is refused: 400 subject_mismatch.
- every other resource_type: log() REQUIRES subject_user_id, either a user id or the literal 'none' for a
  resource that belongs to no person. Missing: 400 subject_required. (Leaving it optional let a caller keep a
  session's IP in the permanent log by forgetting it.)
- An admin acting on a user writes two rows: 'actor' under the admin, 'subject' under the user.

ENDPOINTS:

1. Log mutation (called BEFORE commit)
   POST /audit/log
   {
     actor_id: 123,
     actor_type: 'user',
     subject_user_id: 789,     // required unless resource_type is 'user': the user the snapshots are about, or 'none'
     action: 'subscription_changed',
     resource_type: 'subscription',
     resource_id: 456,
     old_value: { tier: 'team', billing_date: '2026-10-15' },
     new_value: { tier: 'enterprise', billing_date: '2026-10-15' },
     why_chain_id: 'wc_789'
   }
   Response: { success: true, log_id: '...' }
   log() is an internal call made by the system that changes the data. Over HTTP it is service-authenticated
   only (401 for any other caller), and actor_id is the authenticated caller's, never taken from the body
   when an end user is the actor.

   Reads (query, replay, search) are for admins only: any other caller gets 403 (AUDIT-10).

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
   Deletes every audit_personal row with the user's subject_ref, then the user's audit_subjects row, in one
   transaction. No audit_log row is updated or deleted. Then adds exactly one entry: action
   'audit_subject_erased', actor_type 'service', resource_type 'user', subject 'none', resource_id NULL,
   personal_roles '', metadata {erased_rows}. Nothing may log this user after the erasure.

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
- **AUDIT-08** erase_subject(user): no retained row in audit_log, audit_personal or audit_subjects holds the user's id, email or IP; every earlier audit_log row is unchanged and exactly one row is added ('audit_subject_erased', personal_roles '', metadata {erased_rows}); queries show the user's entries with personal_erased true, and an actor_id filter for the user finds nothing
- **AUDIT-09** apply_retention: personal data of entries older than the retention period is erased; newer entries keep theirs; no audit_log row is removed
- **AUDIT-10** log() refuses a non-'user' entry without subject_user_id (400 subject_required), a metadata key other than feature_flag/erased_rows (400 metadata_key_not_allowed), and an api_key entry without actor_user_id (400 actor_user_required); reads by a non-admin caller get 403
```

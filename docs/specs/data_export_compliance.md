# Data Export & Compliance (Gdpr/Ccpa)

Reference contract for `saas_templates/<lang>/data_export_compliance_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# EXPORT-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `EXPORT-01` | Export: JSON and CSV formats both work |
| `EXPORT-02` | Export: All data categories included (profile, activity, files, etc) |
| `EXPORT-03` | Export: Email sent with download link |
| `EXPORT-04` | Export: Signed URL works, expires after 7 days |
| `EXPORT-05` | Deletion: 30-day grace period enforced for user_requested (will_delete_at = requested_at + 30 days) |
| `EXPORT-06` | Deletion: User can cancel within grace period |
| `EXPORT-07` | Deletion: Cascade delete works (sessions, api_keys, etc deleted) |
| `EXPORT-08` | Deletion: Audit log preserved (not deleted with user) |
| `EXPORT-09` | Deletion: User confirmed via email token |
| `EXPORT-10` | Admin: Can see all export/deletion requests |
| `EXPORT-11` | Audit: All requests logged with why_chain support |
| `EXPORT-12` | Deletion: a gdpr_request or gdpr_right_to_be_forgotten request is not held for 30 days (will_delete_at = requested_at) |
| `EXPORT-13` | Deletion cascade order: the user's rows are deleted, 'user_deleted_cascade' is logged, then the audit eraser's erase_subject(user_id) is called last, and nothing is logged for the user after it; deletion_requests.user_id is NULL once completed |
| `EXPORT-14` | Deletion confirmation: nothing is deleted before confirm; a wrong, reused or expired (over 24h) token is refused; another user's deletion request is 404 for confirm and cancel |
| `EXPORT-15` | confirm with a wrong, reused or expired token → the same 400 invalid_confirmation_token; confirm or cancel of a cancelled or completed request → 409 deletion_not_pending |

## Contract

```text
PURPOSE:
Export user data (profile, activity, files, preferences) as JSON/CSV.
Delete user account with cascade (sessions, activity, files, preferences).
Audit all requests and actions (legal requirement).

SCHEMA:
export_requests (id, user_id, requested_at, status: 'pending'|'completed'|'failed', format: 'json'|'csv', file_url, completed_at, expires_at)
deletion_requests (id, user_id, requested_at, status: 'pending'|'approved'|'completed', reason, deleted_at)

EXPORT DATA INCLUDES:
- User profile (id, email, name, created_at, tier, status)
- Sessions (list of all sessions, IPs, device info)
- Activity (all actions user performed: logins, purchases, deployments, etc)
- Files (list of files owned by user with sizes, not file contents)
- Preferences (notification settings, theme, language, etc)
- Transactions (all invoices, payments, refunds)
- Audit trail (all mutations involving this user)

ENDPOINTS:

1. Request data export
   POST /compliance/export
   { format: 'json'|'csv' }
   Response: { success: true, export_id: '...', status: 'pending', will_email_at: '2026-09-25T09:00:00Z' }

   Behind scenes:
   - Generate export file (JSON or CSV)
   - Upload to S3
   - Create signed URL (expires in 7 days)
   - Send email with download link
   - Log in audit_log: action='data_export_requested'

2. Check export status
   GET /compliance/exports/:export_id
   Response: { export_id, status: 'pending'|'completed'|'failed', file_url: '...', expires_at, requested_at }

3. Request account deletion
   POST /compliance/delete
   { reason: 'user_requested'|'gdpr_request'|'gdpr_right_to_be_forgotten'|'other' }
   Response: { success: true, deletion_id: '...', status: 'pending', will_delete_at: '2026-10-02T00:00:00Z' }

   Behind scenes:
   - 30-day grace period so the user can cancel an account deletion they asked for (reason user_requested
     or other): will_delete_at = requested_at + 30 days. This is a product choice, not a GDPR requirement.
   - A statutory erasure request (reason gdpr_request or gdpr_right_to_be_forgotten) must be completed
     without undue delay and within one month, so it gets no grace period: will_delete_at = requested_at,
     and the cascade runs as soon as the request is confirmed (step 4). Clarified 2026-11-10 from review on
     PR 19; amended the same day so every language does the same.
   - Nothing is deleted until the request is confirmed (step 4). The confirmation token is 32 random bytes,
     stored only as its SHA-256, single-use, valid 24 hours, bound to its deletion_id, and compared in
     constant time. Confirm and cancel act only on the caller's own request; anyone else's is 404
     {error: "not_found"}. A wrong, reused or expired token gets one answer, 400
     {error: "invalid_confirmation_token"}, so the reply never says which. A request that is no longer
     pending (cancelled or completed) gets 409 {error: "deletion_not_pending"}. Amended 2026-11-10 (Phase B.2: one answer in every language).
   - Schedule cascade delete: sessions, api_keys, preferences, export files and their request rows, etc.
     The audit log is kept (EXPORT-08). Corrected 2026-11-10 from review on PR 19: this line listed audit_logs.
   - Log in audit_log: action='deletion_requested', reason

4. Approve/confirm deletion (user must confirm in email link)
   POST /compliance/delete/:deletion_id/confirm
   { confirmation_token: '...' }
   Response: { success: true, deletion_scheduled_for: '2026-10-02T00:00:00Z' }
   For a statutory reason, confirm() runs the cascade before it returns: status 'completed' and
   deleted_at = deletion_scheduled_for = now.

5. Cancel deletion (within grace period)
   DELETE /compliance/delete/:deletion_id
   Response: { success: true, status: 'cancelled' }

6. List export requests (admin only)
   GET /admin/compliance/exports?user_id=123&status=completed
   Response: { exports: [...], total: 5 }

7. List deletion requests (admin only)
   GET /admin/compliance/deletions?status=pending
   Response: { deletions: [...], total: 2 }

IMPLEMENTATION:
- Export generation: Background job (async), not blocking request
- Storage: S3, encrypted at rest
- Signed URLs: 7-day expiry, download-only (no upload)
- Grace period: 30 days for user_requested / other (the user can cancel); none for a statutory reason
- Cascade delete: delete from all tables where user_id = X, except the audit tables (audit_log,
  audit_personal, audit_subjects), which only the audit system's erase_subject() touches. It is reached
  through an injected audit eraser, like the audit logger, so tests pass a fake. One transaction, in order:
  (1) delete the user's rows; (2) log 'user_deleted_cascade' with the user as subject; (3) call
  erase_subject(user_id) LAST. Nothing logs this user afterwards. deletion_requests.user_id is set NULL when
  the deletion completes, so the request row cannot re-identify erased audit entries by its timestamp.
  Amended 2026-11-10 after an independent security review: nothing erased the user's audit personal data.
- Audit trail: Every export and deletion request logged
- Email confirmation: User must confirm deletion via email link (phishing protection)
- GDPR: Support right_to_be_forgotten, right_to_access, right_to_data_portability
- CCPA: Support consumer opt-out, data access, deletion requests

TESTS:
- **EXPORT-01** Export: JSON and CSV formats both work
- **EXPORT-02** Export: All data categories included (profile, activity, files, etc)
- **EXPORT-03** Export: Email sent with download link
- **EXPORT-04** Export: Signed URL works, expires after 7 days
- **EXPORT-05** Deletion: 30-day grace period enforced for user_requested (will_delete_at = requested_at + 30 days)
- **EXPORT-06** Deletion: User can cancel within grace period
- **EXPORT-07** Deletion: Cascade delete works (sessions, api_keys, etc deleted)
- **EXPORT-08** Deletion: Audit log preserved (not deleted with user)
- **EXPORT-09** Deletion: User confirmed via email token
- **EXPORT-10** Admin: Can see all export/deletion requests
- **EXPORT-11** Audit: All requests logged with why_chain support
- **EXPORT-12** Deletion: a gdpr_request or gdpr_right_to_be_forgotten request is not held for 30 days (will_delete_at = requested_at)
- **EXPORT-13** Deletion cascade order: the user's rows are deleted, 'user_deleted_cascade' is logged, then the audit eraser's erase_subject(user_id) is called last, and nothing is logged for the user after it; deletion_requests.user_id is NULL once completed
- **EXPORT-14** Deletion confirmation: nothing is deleted before confirm; a wrong, reused or expired (over 24h) token is refused; another user's deletion request is 404 for confirm and cancel
- **EXPORT-15** confirm with a wrong, reused or expired token → the same 400 invalid_confirmation_token; confirm or cancel of a cancelled or completed request → 409 deletion_not_pending
```

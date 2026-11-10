# Permissions & Rbac

Reference contract for `saas_templates/<lang>/permissions_rbac_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# RBAC-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `RBAC-01` | require_owner on non-owner → 403 |
| `RBAC-02` | require_admin on member → 403 |
| `RBAC-03` | require_authenticated on public → 401 |
| `RBAC-04` | cascade_delete user → all related records deleted in transaction |
| `RBAC-05` | cascade_delete deployment → all related records deleted |
| `RBAC-06` | cascade_delete org → by an owner of that org only (another org's owner gets 404); its deployments, org API keys, invitations and memberships deleted; every member's user account and personal API keys kept, including a member who also belongs to another org (that membership untouched) |
| `RBAC-07` | cascade on error → rollback (no partial deletes) |
| `RBAC-08` | permission audit logged → queries show who accessed what |
| `RBAC-09` | tier hierarchy → member cannot do admin actions, admin cannot do owner actions |
| `RBAC-10` | permission check response time < 10ms → no performance impact |

## Contract

```text
PERMISSION CHECKS (on every action):

  1. permission_check middleware
     function require_owner(current_user):
       if current_user.tier != "owner": return 403 {error: "owner_only"}

     function require_admin(current_user):
       if current_user.tier not in ["admin", "owner"]: return 403 {error: "admin_only"}

     function require_authenticated(current_user):
       if current_user is None: return 401 {error: "authentication_required"}

     Usage: on every endpoint
       @require_owner
       def admin_create_user(...):
         ...

       @require_admin
       def admin_list_customers(...):
         ...

  2. cascade_delete rules
     if delete_user(user_id):
       → cascade: delete_all_sessions, delete_all_api_keys, delete_all_files, clear_preferences
       → Log: audit_log(action="user_deleted_cascade", user_id, deleted_items={sessions: N, keys: M, files: K})

     if delete_deployment(deployment_id):
       → cascade: delete_all_dns_records, delete_all_theme_configs, delete_all_deployment_logs, archive to S3
       → Log: audit_log(action="deployment_deleted_cascade", deployment_id, deleted_items={dns: N, ...})

     if delete_organization(org_id):
       → Gate: the caller's membership row for org_id has role 'owner'; otherwise 404 (a global admin tier
         is not enough: any owner of any org could delete every org).
       → cascade: its deployments (each with the deployment cascade above), API keys whose org_id is this org
         (a key without an org_id belongs to its user and is kept), ALL its invitations and its membership
         rows. Memberships are rows (org_id, user_id, role) as in organizations_teams.md.
       → NEVER delete a user account or its sessions: a user may belong to several organizations
         (organizations_teams.md). Deleting an account is delete_user, a separate operation.
       → Log: audit_log(action="org_deleted_cascade", org_id,
                        deleted_items={deployments: N, api_keys: M, invitations: I, memberships: K})
       Amended 2026-11-10 after review on PR 19.

  3. permission audit_log
     Every permission check → log to audit_log
       Log: audit_log(action="permission_check", user_id, endpoint, required_tier, user_tier, decision="PASS"|"FAIL")

     This allows forensics: "who tried to access what they couldn't"

IMPLEMENTATION REQUIREMENTS:
  - Middleware: check user.tier before action execution
  - Cascades: execute in transaction, rollback on error
  - Audit: log permission checks (even passes, for forensics)
  - Error response: {error: "permission_denied"|"owner_only"|"admin_only", code: 403}
  - Tier hierarchy: public < member < admin < owner (each level includes lower)

TESTS REQUIRED:
  - **RBAC-01** require_owner on non-owner → 403
  - **RBAC-02** require_admin on member → 403
  - **RBAC-03** require_authenticated on public → 401
  - **RBAC-04** cascade_delete user → all related records deleted in transaction
  - **RBAC-05** cascade_delete deployment → all related records deleted
  - **RBAC-06** cascade_delete org → by an owner of that org only (another org's owner gets 404); its deployments, org API keys, invitations and memberships deleted; every member's user account and personal API keys kept, including a member who also belongs to another org (that membership untouched)
  - **RBAC-07** cascade on error → rollback (no partial deletes)
  - **RBAC-08** permission audit logged → queries show who accessed what
  - **RBAC-09** tier hierarchy → member cannot do admin actions, admin cannot do owner actions
  - **RBAC-10** permission check response time < 10ms → no performance impact
```

# Admin System

Reference contract for `saas_templates/<lang>/admin_system_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# ADMIN-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `ADMIN-01` | create user happy path → user created + invite sent |
| `ADMIN-02` | create user duplicate email → 409 {error: "email_exists"} |
| `ADMIN-03` | create user non-owner → 403 {error: "owner_only"} |
| `ADMIN-04` | reset_password happy path → email sent |
| `ADMIN-05` | reset_password own account → 400 {error: "cannot_reset_own_password"} |
| `ADMIN-06` | change_role happy path → role changed + audit logged |
| `ADMIN-07` | change_role last_owner → 400 {error: "cannot_demote_last_owner"} |
| `ADMIN-08` | suspend_user happy path → status changed |
| `ADMIN-09` | suspend_own_account → 400 {error: "cannot_suspend_yourself"} |
| `ADMIN-10` | customers list → pagination works, all fields present |
| `ADMIN-11` | customers detail → all fields present |
| `ADMIN-12` | change_plan → stripe.subscriptions.update called with the existing item id and the new price (no second item), audit logged |
| `ADMIN-13` | queue_refund → refund record created with status='queued' |
| `ADMIN-14` | create_deployment → deployment created + config initialized |
| `ADMIN-15` | publish_deployment → double-gate checked, status changed to 'live' |
| `ADMIN-16` | governance approve → action executed + status changed |
| `ADMIN-17` | governance reject → action rejected + reason logged |
| `ADMIN-18` | audit_log search → correct filters applied, pagination works |
| `ADMIN-19` | a suspended owner calling any admin action → 403 {error: "account_suspended"}, nothing changed |

## Contract

```text
EVERY ACTION: the caller is the verified session user. A caller whose account status is 'suspended' is refused
  before any gate: 403 {error: "account_suspended"} (ADMIN-19). Amended 2026-11-10 (Phase B.2: one answer in every language).

TIERS: two different things share the word.
  - users.tier is the STAFF ROLE: 'owner' | 'admin' | 'user' (create, change_role, last-owner rules).
  - a customer's or deployment's tier is the PLAN: 'solo' | 'team' | 'enterprise' (change_plan,
    create_deployment, prices). A plan value given where a role is expected, or the reverse, is 400
    {error: "invalid_tier"}. deployments carry domain_verified (BOOLEAN, default false); publish needs it.
  Amended 2026-11-10 (Phase B.2).

DOMAINS:

  USERS DOMAIN:
    POST /admin/users/action
      action=create → require(email, name, tier, notify)
        Gate: owner_only
        Check: email_unique, valid_tier
        Action: create user, send invite email (or show one-time password)
        Log: audit_log(action="user_created", actor_id, user_id, email, tier)
        Return: {success: true, user_id, email, tier, created_at}

      action=reset_password → require(user_id)
        Gate: owner_only, user_id != current_user_id, user exists
        Check: user != last_active_owner
        Action: generate reset token, email user link
        Log: audit_log(action="password_reset_initiated", actor_id, user_id)
        Return: {success: true, status: "reset_email_sent"}

      action=change_role → require(user_id, new_tier)
        Gate: owner_only, user_id != current_user_id
        Check: new_tier in valid_tiers, user != last_active_owner
        Action: update users.tier, audit_log
        Log: audit_log(action="role_changed", actor_id, user_id, old_tier, new_tier)
        Return: {success: true, user_id, old_tier, new_tier}

      action=suspend → require(user_id, reason)
        Gate: owner_only, user_id != current_user_id
        Check: user != last_active_owner
        Action: users.status = 'suspended', audit_log
        Log: audit_log(action="user_suspended", actor_id, user_id, reason)
        Return: {success: true, user_id, suspended: true}

  CUSTOMERS DOMAIN:
    GET /admin/customers → list all (paginated)
      Gate: admin_or_owner (read-only)
      Return: [{customer_id, email, name, tier, signup_date, invoice_count, status}, ...]

    GET /admin/customers/{customer_id} → detail
      Gate: admin_or_owner
      Return: {customer_id, email, name, tier, subscription_status, payment_method, address, notes}

    POST /admin/customers/{customer_id}/action
      action=change_plan → require(new_tier)
        Gate: owner_only
        Action: billing change_plan (billing_subscriptions.md, flow 2): update with {id: current_item_id, price};
                never a bare {price}, which adds a second item and bills both plans. Amended 2026-11-10.
        Log: audit_log(action="plan_changed", actor_id, customer_id, old_tier, new_tier)
        Return: {success: true, customer_id, old_tier, new_tier, effective_date}

      action=queue_refund → require(invoice_id, amount, reason)
        Gate: owner_only
        Check: invoice exists, status='succeeded'
        Action: insert into refunds (status='queued', amount, reason, created_by, created_at)
        Log: audit_log(action="refund_queued", actor_id, invoice_id, amount, reason)
        Return: {success: true, refund_id, status: "queued", amount}

  DEPLOYMENTS DOMAIN:
    GET /admin/deployments → list
      Gate: admin_or_owner
      Return: [{deployment_id, customer_id, domain, tier, status, theme, published_at}, ...]

    POST /admin/deployments/action
      action=create → require(customer_id, domain, tier, theme_id)
        Gate: owner_only
        Check: customer exists, domain not registered, theme exists
        Action: create deployment record, init config
        Log: audit_log(action="deployment_created", actor_id, deployment_id, customer_id)
        Return: {success: true, deployment_id, domain, tier}

      action=publish → require(deployment_id)
        Gate: owner_only + SafetyFlags.can_publish (double-gate)
        Check: status='draft', domain_verified, theme_set
        Action: deployments.status='live', published_at=NOW()
        Log: audit_log(action="deployment_published", actor_id, deployment_id)
        Return: {success: true, deployment_id, status: "live", public_url}

      action=suspend → require(deployment_id, reason)
        Gate: owner_only
        Action: status='suspended', suspend_reason
        Log: audit_log(action="deployment_suspended", actor_id, deployment_id, reason)
        Return: {success: true, deployment_id, status: "suspended"}

      action=retire → require(deployment_id)
        Gate: owner_only
        Action: status='archived', archived_at=NOW()
        Log: audit_log(action="deployment_archived", actor_id, deployment_id)
        Return: {success: true, deployment_id, status: "archived"}

  GOVERNANCE DOMAIN:
    GET /admin/governance/actions → pending approvals (paginated)
      Gate: owner_or_admin
      Return: [{action_id, action_type, actor, target_resource_id, reason, submitted_at, status}, ...]

    POST /admin/governance/actions/{action_id}/decide
      decide=approve
        Gate: owner_only
        Action: execute the original action, actions.status='approved', approved_by, approved_at
        Log: audit_log(action="action_approved", actor_id, action_id, execution_result)
        Return: {success: true, action_id, status: "approved"}

      decide=reject → require(reason)
        Gate: owner_only
        Action: actions.status='rejected', rejection_reason
        Log: audit_log(action="action_rejected", actor_id, action_id, reason)
        Return: {success: true, action_id, status: "rejected"}

    GET /admin/governance/audit-log → search all mutations
      Gate: owner_or_admin
      Params: action_type, resource_id, date_range, limit (default 100), offset
      Return: [{timestamp, actor_id, action, resource_type, resource_id, old_value, new_value, reason}, ...]

IMPLEMENTATION REQUIREMENTS:
  - Every POST: verify_csrf() first
  - Every mutation: require_owner() gate (except reads: require_admin_or_owner())
  - Every mutation: audit_log write before commit
  - Validation: email format, name length, role in allowed_roles
  - Safety: prevent self-suspension, prevent last-owner demotion
  - Response: {success: true, ...} or {error: "code", message: "..."}
  - Stripe calls: use live key (STRIPE_SECRET_KEY env var)

TESTS REQUIRED:
  - **ADMIN-01** create user happy path → user created + invite sent
  - **ADMIN-02** create user duplicate email → 409 {error: "email_exists"}
  - **ADMIN-03** create user non-owner → 403 {error: "owner_only"}
  - **ADMIN-04** reset_password happy path → email sent
  - **ADMIN-05** reset_password own account → 400 {error: "cannot_reset_own_password"}
  - **ADMIN-06** change_role happy path → role changed + audit logged
  - **ADMIN-07** change_role last_owner → 400 {error: "cannot_demote_last_owner"}
  - **ADMIN-08** suspend_user happy path → status changed
  - **ADMIN-09** suspend_own_account → 400 {error: "cannot_suspend_yourself"}
  - **ADMIN-10** customers list → pagination works, all fields present
  - **ADMIN-11** customers detail → all fields present
  - **ADMIN-12** change_plan → stripe.subscriptions.update called with the existing item id and the new price (no second item), audit logged
  - **ADMIN-13** queue_refund → refund record created with status='queued'
  - **ADMIN-14** create_deployment → deployment created + config initialized
  - **ADMIN-15** publish_deployment → double-gate checked, status changed to 'live'
  - **ADMIN-16** governance approve → action executed + status changed
  - **ADMIN-17** governance reject → action rejected + reason logged
  - **ADMIN-18** audit_log search → correct filters applied, pagination works
  - **ADMIN-19** a suspended owner calling any admin action → 403 {error: "account_suspended"}, nothing changed
```

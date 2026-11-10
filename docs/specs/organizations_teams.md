# Organizations & Teams (Multi-Tenant Membership + Invitations)

Reference contract for `saas_templates/<lang>/organizations_teams_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# ORG-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `ORG-01` | a non-member cannot read members of another org (IDOR attempt by id) |
| `ORG-02` | a member cannot invite; an admin can |
| `ORG-03` | an admin cannot remove the owner; the last owner cannot leave |
| `ORG-04` | an invitation works once; the second use fails |
| `ORG-05` | an expired invitation fails; accepting with a different email fails |
| `ORG-06` | the raw token is not stored anywhere in the database |

## Contract

```text
Source: OWASP Authorization Cheat Sheet (CC BY-SA 4.0 -- rules applied, text not reproduced).

PURPOSE:
  Organizations with members and roles, invitations by email, and hard isolation between orgs.

SCHEMA:
  organizations (id, name, slug UNIQUE, created_at)
  memberships   (org_id, user_id, role 'owner'|'admin'|'member', created_at, UNIQUE(org_id, user_id))
  invitations   (id, org_id, email, role, token_hash, expires_at, accepted_at NULL, invited_by, created_at)

ENDPOINTS / FUNCTIONS:
  create_org(user, name) -> org   (creator becomes owner)
  invite(actor, org_id, email, role) -> raw token (returned once, only its hash stored)
  accept_invitation(user, raw_token) -> membership
  change_role(actor, org_id, user_id, role) / remove_member(actor, org_id, user_id)
  leave_org(user, org_id) / list_members(actor, org_id) / get_org(actor, org_id)

IMPLEMENTATION -- RULES (from the cheat sheet):
  - "Deny by Default": every function checks the caller's membership and role explicitly; no check =
    no access.
  - Validate permissions "on every request" -- never trust an earlier check or client-supplied role.
  - Prevent IDOR: every org-scoped read/write filters by org_id AND confirms the caller is a member.
    Never load a record by id alone.
  - Least privilege: member cannot invite, change roles or remove anyone; admin can invite and manage
    members but cannot remove, demote or change the owner; an org must always keep at least 1 owner,
    so the last owner cannot leave or be demoted. Only an OWNER may grant the owner role (invite with role
    owner, or change_role to owner), so an org can have several owners and one of them can then leave.
    (Amended 2026-09-26: the first version never said who may create a second owner.)
  - Invitation tokens: 32 random bytes, stored as a SHA-256 hash, single-use, expire after 7 days, and
    only the user whose email matches may accept.
  - A non-member asking for an org gets "not found" (do not reveal the org exists).
  - change_role / remove_member act on EXISTING members only; for a user who is not a member they fail
    with "not found". The ONLY ways into an org are create_org (owner) and accept_invitation.

TESTS:
  - **ORG-01** a non-member cannot read members of another org (IDOR attempt by id)
  - **ORG-02** a member cannot invite; an admin can
  - **ORG-03** an admin cannot remove the owner; the last owner cannot leave
  - **ORG-04** an invitation works once; the second use fails
  - **ORG-05** an expired invitation fails; accepting with a different email fails
  - **ORG-06** the raw token is not stored anywhere in the database
```

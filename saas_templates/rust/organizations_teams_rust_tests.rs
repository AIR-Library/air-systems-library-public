//! Organizations and teams tests (TIER 3 spec, system 4). The spec's TESTS list (IDOR, member cannot
//! invite, admin cannot remove the owner, single-use and expiring invitations, email match, raw token
//! never stored) was missing; those tests were added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP,
//! and run on both stores. Touches: memory and in-memory SQLite only.
use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_org() {
        let mut system = OrganizationsTeams::new(false);
        let user = "test@example.com";
        let org_name = "Test Org";
        let result = system.create_org(user, org_name);
        assert!(result.is_ok());
        let (org_id, slug, created_at) = result.unwrap();
        assert_eq!(slug, "test-org");
    }

    #[test]
    fn test_invite() {
        let mut system = OrganizationsTeams::new(false);
        let user = "test@example.com";
        let org_name = "Test Org";
        let result = system.create_org(user, org_name);
        assert!(result.is_ok());
        let (org_id, _, _) = result.unwrap();

        let actor = "test@example.com";
        let email = "invite@example.com";
        let role = "member";
        let result = system.invite(actor, &org_id, email, role);
        assert!(result.is_ok());
        let (token, expires_at, created_at) = result.unwrap();
        assert_eq!(token.len(), 32 * 4 / 3 + 2); // Base64 encoded length
    }

    #[test]
    fn test_accept_invitation() {
        let mut system = OrganizationsTeams::new(false);
        let user = "test@example.com";
        let org_name = "Test Org";
        let result = system.create_org(user, org_name);
        assert!(result.is_ok());
        let (org_id, _, _) = result.unwrap();

        let actor = "test@example.com";
        let email = "invite@example.com";
        let role = "member";
        let result = system.invite(actor, &org_id, email, role);
        assert!(result.is_ok());
        let (token, _, _) = result.unwrap();

        let user_email = "invite@example.com";
        let result = system.accept_invitation(user_email, &token);
        assert!(result.is_ok());
        let (org_id, role, created_at) = result.unwrap();
        assert_eq!(role, "member");
    }

    #[test]
    fn test_change_role() {
        let mut system = OrganizationsTeams::new(false);
        let user = "test@example.com";
        let org_name = "Test Org";
        let result = system.create_org(user, org_name);
        assert!(result.is_ok());
        let (org_id, _, _) = result.unwrap();

        let actor = "test@example.com";
        let email = "invite@example.com";
        let role = "member";
        let result = system.invite(actor, &org_id, email, role);
        assert!(result.is_ok());
        let (token, _, _) = result.unwrap();

        let user_email = "invite@example.com";
        let result = system.accept_invitation(user_email, &token);
        assert!(result.is_ok());

        let new_role = "admin";
        let result = system.change_role(actor, &org_id, "invite@example.com", new_role);
        assert!(result.is_ok());
    }

    #[test]
    fn test_remove_member() {
        let mut system = OrganizationsTeams::new(false);
        let user = "test@example.com";
        let org_name = "Test Org";
        let result = system.create_org(user, org_name);
        assert!(result.is_ok());
        let (org_id, _, _) = result.unwrap();

        let actor = "test@example.com";
        let email = "invite@example.com";
        let role = "member";
        let result = system.invite(actor, &org_id, email, role);
        assert!(result.is_ok());
        let (token, _, _) = result.unwrap();

        let user_email = "invite@example.com";
        let result = system.accept_invitation(user_email, &token);
        assert!(result.is_ok());

        let result = system.remove_member(actor, &org_id, "invite@example.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_leave_org() {
        let mut system = OrganizationsTeams::new(false);
        let user = "test@example.com";
        let org_name = "Test Org";
        let result = system.create_org(user, org_name);
        assert!(result.is_ok());
        let (org_id, _, _) = result.unwrap();

        // Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the creator is the org's only
        // owner, and the spec says "the last owner cannot leave", so this call must fail. Leaving
        // itself is still tested below with a member who joined by invitation.
        let result = system.leave_org(user, &org_id);
        assert!(result.is_err());

        let (token, _, _) = system.invite(user, &org_id, "leaver@example.com", "member").unwrap();
        system.accept_invitation("leaver@example.com", &token).unwrap();
        let result = system.leave_org("leaver@example.com", &org_id);
        assert!(result.is_ok());
        assert_eq!(system.list_members(user, &org_id).unwrap().len(), 1);
    }

    #[test]
    fn test_list_members() {
        let mut system = OrganizationsTeams::new(false);
        let user = "test@example.com";
        let org_name = "Test Org";
        let result = system.create_org(user, org_name);
        assert!(result.is_ok());
        let (org_id, _, _) = result.unwrap();

        let actor = "test@example.com";
        let email = "invite@example.com";
        let role = "member";
        let result = system.invite(actor, &org_id, email, role);
        assert!(result.is_ok());
        let (token, _, _) = result.unwrap();

        let user_email = "invite@example.com";
        let result = system.accept_invitation(user_email, &token);
        assert!(result.is_ok());

        let result = system.list_members(actor, &org_id);
        assert!(result.is_ok());
        let members = result.unwrap();
        assert_eq!(members.len(), 2); // owner and member
    }

    #[test]
    fn test_get_org() {
        let mut system = OrganizationsTeams::new(false);
        let user = "test@example.com";
        let org_name = "Test Org";
        let result = system.create_org(user, org_name);
        assert!(result.is_ok());
        let (org_id, _, _) = result.unwrap();

        let actor = "test@example.com";
        let result = system.get_org(actor, &org_id);
        assert!(result.is_ok());
        let (name, slug, created_at) = result.unwrap();
        assert_eq!(name, org_name);
        assert_eq!(slug, "test-org");
    }

    /// Spec: a non-member cannot read another org's members (IDOR by id); they get "not found".
    #[test]
    fn test_non_member_cannot_read_members_of_another_org() {
        for use_sql in [false, true] {
            let mut system = OrganizationsTeams::new(use_sql);
            let (alpha, _, _) = system.create_org("owner@example.com", "Alpha").unwrap();
            let (beta, _, _) = system.create_org("out@example.com", "Beta").unwrap();
            assert_eq!(system.list_members("out@example.com", &alpha), Err(OrgError::NotFound));
            assert_eq!(system.get_org("out@example.com", &alpha), Err(OrgError::NotFound));
            assert_eq!(system.invite("out@example.com", &alpha, "x@example.com", "member").map(|_| ()), Err(OrgError::NotFound));
            assert_eq!(system.change_role("out@example.com", &alpha, "owner@example.com", "admin"), Err(OrgError::NotFound));
            assert_eq!(system.remove_member("out@example.com", &alpha, "owner@example.com"), Err(OrgError::NotFound));
            assert_eq!(system.leave_org("out@example.com", &alpha), Err(OrgError::NotFound));
            assert_eq!(system.get_org("out@example.com", &"f".repeat(32)), Err(OrgError::NotFound));
            assert!(system.get_org("out@example.com", &beta).is_ok());
            assert_eq!(system.list_members("", &alpha), Err(OrgError::Unauthenticated));
        }
    }

    /// Spec: a member cannot invite; an admin can (but cannot invite an owner).
    #[test]
    fn test_member_cannot_invite_admin_can() {
        for use_sql in [false, true] {
            let mut s = OrganizationsTeams::new(use_sql);
            let (org, _, _) = s.create_org("owner@example.com", "TestOrg").unwrap();
            let (t, _, _) = s.invite("owner@example.com", &org, "member@example.com", "member").unwrap();
            s.accept_invitation("member@example.com", &t).unwrap();
            let (t, _, _) = s.invite("owner@example.com", &org, "admin@example.com", "admin").unwrap();
            s.accept_invitation("admin@example.com", &t).unwrap();
            assert_eq!(s.invite("member@example.com", &org, "new@example.com", "member").map(|_| ()), Err(OrgError::Forbidden));
            let (t, _, _) = s.invite("admin@example.com", &org, "new@example.com", "member").unwrap();
            assert_eq!(s.accept_invitation("new@example.com", &t).unwrap().1, "member");
            assert_eq!(s.invite("admin@example.com", &org, "another@example.com", "owner").map(|_| ()), Err(OrgError::Forbidden));
        }
    }

    /// Spec: an admin cannot remove or demote the owner; the last owner cannot leave or be demoted;
    /// change_role on a non-member is "not found".
    #[test]
    fn test_admin_cannot_remove_owner_and_last_owner_cannot_leave() {
        for use_sql in [false, true] {
            let mut s = OrganizationsTeams::new(use_sql);
            let (org, _, _) = s.create_org("owner@example.com", "TestOrg").unwrap();
            let (t, _, _) = s.invite("owner@example.com", &org, "admin@example.com", "admin").unwrap();
            s.accept_invitation("admin@example.com", &t).unwrap();
            let (t, _, _) = s.invite("owner@example.com", &org, "member@example.com", "member").unwrap();
            s.accept_invitation("member@example.com", &t).unwrap();
            assert_eq!(s.remove_member("admin@example.com", &org, "owner@example.com"), Err(OrgError::Forbidden));
            assert_eq!(s.change_role("admin@example.com", &org, "owner@example.com", "member"), Err(OrgError::Forbidden));
            assert_eq!(s.change_role("admin@example.com", &org, "member@example.com", "owner"), Err(OrgError::Forbidden));
            assert_eq!(s.change_role("owner@example.com", &org, "stranger@example.com", "admin"), Err(OrgError::MemberNotFound));
            s.remove_member("admin@example.com", &org, "member@example.com").unwrap();
            assert_eq!(s.list_members("owner@example.com", &org).unwrap().len(), 2);
            assert_eq!(s.leave_org("owner@example.com", &org), Err(OrgError::LastOwner));
            assert_eq!(s.change_role("owner@example.com", &org, "owner@example.com", "admin"), Err(OrgError::LastOwner));
            assert_eq!(s.remove_member("owner@example.com", &org, "owner@example.com"), Err(OrgError::LastOwner));
            // a second owner, granted by an owner, lets the first one leave
            s.change_role("owner@example.com", &org, "admin@example.com", "owner").unwrap();
            assert!(s.leave_org("owner@example.com", &org).is_ok());
        }
    }

    /// Spec: an invitation works once; the second use fails.
    #[test]
    fn test_invitation_works_once_second_use_fails() {
        for use_sql in [false, true] {
            let mut s = OrganizationsTeams::new(use_sql);
            let (org, _, _) = s.create_org("owner@example.com", "TestOrg").unwrap();
            let (t, _, _) = s.invite("owner@example.com", &org, "x@example.com", "member").unwrap();
            let (joined, role, _) = s.accept_invitation("x@example.com", &t).unwrap();
            assert_eq!((joined.as_str(), role.as_str()), (org.as_str(), "member"));
            assert_eq!(s.accept_invitation("x@example.com", &t), Err(OrgError::InvitationUsed));
            let (t2, _, _) = s.invite("owner@example.com", &org, "x@example.com", "member").unwrap();
            assert_eq!(s.accept_invitation("x@example.com", &t2), Err(OrgError::AlreadyMember));
        }
    }

    /// Spec: an expired invitation fails; accepting with a different email fails.
    #[test]
    fn test_expired_invitation_and_different_email_fail() {
        for use_sql in [false, true] {
            let clock = ManualClock::new(1_700_000_000);
            let mut s = OrganizationsTeams::new(use_sql).with_clock(clock.clone());
            let (org, _, _) = s.create_org("owner@example.com", "TestOrg").unwrap();
            let (t, _, _) = s.invite("owner@example.com", &org, "  X@Example.COM ", "member").unwrap();
            assert_eq!(s.accept_invitation("z@example.com", &t), Err(OrgError::EmailMismatch));
            let (t2, _, _) = s.invite("owner@example.com", &org, "y@example.com", "member").unwrap();
            clock.advance(INVITATION_TTL_SECS);
            assert_eq!(s.accept_invitation("y@example.com", &t2), Err(OrgError::InvitationExpired));
            assert_eq!(s.accept_invitation("x@example.com", &t), Err(OrgError::InvitationExpired));
            assert_eq!(s.list_members("owner@example.com", &org).unwrap().len(), 1);
        }
    }

    /// Spec: the raw token is not stored anywhere in the database; its SHA-256 is.
    #[test]
    fn test_raw_token_not_stored_in_database() {
        for use_sql in [false, true] {
            let mut s = OrganizationsTeams::new(use_sql);
            let (org, _, _) = s.create_org("owner@example.com", "TestOrg").unwrap();
            let (token, _, _) = s.invite("owner@example.com", &org, "x@example.com", "member").unwrap();
            let dump = s.debug_dump();
            assert!(!dump.contains(&token));
            assert!(dump.contains(&hash_token(&token)));
            s.accept_invitation("x@example.com", &token).unwrap();
            assert_eq!(s.list_members("owner@example.com", &org).unwrap().len(), 2);
        }
    }
}

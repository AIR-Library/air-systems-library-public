//! Admin system tests (GEMINI spec, template #2).
//! Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP; each change is marked "Corrected" where it
//! is made. Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP, Phase B.2 TIERS rule): users.tier is now the
//! staff role (owner / admin / user) and a customer's or deployment's tier the plan (solo / team / enterprise);
//! the tests used the old mixed tiers (enterprise = owner, premium = admin, basic = user, and basic / premium
//! as plans), so each value is replaced by its role or plan; no assertion was dropped. Touches: in-memory SQLite only.
use super::*;
use rusqlite::Connection;
use std::cell::RefCell;
use std::rc::Rc;

/// What: fake payment client that records each update (the "stripe.subscriptions.update called" check)
/// and serves each subscription's items from `items` (one item "si_<sub>" unless a test sets others).
/// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-12): it now answers retrieve and records
/// the item id sent with the price. Touches: memory.
struct MockStripe {
    calls: Rc<RefCell<Vec<(String, String)>>>,
    items: Rc<RefCell<std::collections::HashMap<String, Vec<SubscriptionItem>>>>,
}
/// What: `StripeClient` for the fake. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
impl StripeClient for MockStripe {
    /// What: the stored items, or one default item. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn retrieve_subscription(&self, stripe_id: &str) -> AdminResult<Vec<SubscriptionItem>> {
        Ok(self.items.borrow().get(stripe_id).cloned().unwrap_or_else(|| vec![SubscriptionItem { id: format!("si_{}", stripe_id), price: "price_solo".into() }]))
    }
    /// What: record (subscription, "item=price proration") per update. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn update_subscription(&self, stripe_id: &str, update: &SubscriptionUpdate) -> AdminResult<()> {
        let items: Vec<String> = update.items.iter().map(|i| format!("{}={}", i.id, i.price)).collect();
        self.calls.borrow_mut().push((stripe_id.to_string(), format!("{} {}", items.join(","), update.proration_behavior)));
        Ok(())
    }
}

/// Fake domain verifier: every domain is verified (no DNS in tests).
struct AllDomainsVerified;
impl DomainVerifier for AllDomainsVerified {
    fn is_verified(&self, _domain: &str) -> bool {
        true
    }
}

thread_local! {
    static STRIPE_CALLS: Rc<RefCell<Vec<(String, String)>>> = Rc::new(RefCell::new(Vec::new()));
    static STRIPE_ITEMS: Rc<RefCell<std::collections::HashMap<String, Vec<SubscriptionItem>>>> = Rc::new(RefCell::new(Default::default()));
}

/// Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the system gets a domain verifier (publishing
/// needs a verified domain per the spec; the default verifies nothing) and the fake payment client
/// records its calls. The unused `std::env` import was removed.
fn setup() -> AdminSystem {
    let conn = Connection::open_in_memory().unwrap();
    let calls = STRIPE_CALLS.with(|c| { c.borrow_mut().clear(); c.clone() });
    let items = STRIPE_ITEMS.with(|c| { c.borrow_mut().clear(); c.clone() });
    let system = AdminSystem::new(conn, Box::new(MockStripe { calls, items })).with_domain_verifier(Box::new(AllDomainsVerified));
    system.init_schema().unwrap();
    // Create an owner user
    let now = Utc::now().to_rfc3339();
    system
        .conn
        .execute(
            "INSERT INTO users (email,name,tier,status,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6)",
            params!["owner@example.com", "Owner", "owner", "active", now, now], // role, Phase B.2 (was "enterprise")
        )
        .unwrap();
    system
}

/// What: ADMIN-01: an owner creates a user, who is stored and sent an invite. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP:
/// the "invite sent" assertion was added. Touches: in-memory SQLite.
// ADMIN-01
#[test]
fn test_create_user_happy_path() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    let resp = system.create_user(&owner, "new@example.com", "New User", "user", true);
    match resp {
        Response::Success { data, .. } => {
            let uid: i64 = serde_json::from_value(data.get("user_id").unwrap().clone()).unwrap();
            assert!(uid > 0);
            let user = system.get_user_by_id(uid).unwrap();
            assert_eq!(user.email, "new@example.com");
        }
        _ => panic!("Expected success"),
    }
    // ADMIN-01 "invite sent" (assertion added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
    assert!(system.sent_emails().iter().any(|m| m.to == "new@example.com"));
}

// ADMIN-02
#[test]
fn test_create_user_duplicate_email() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    system
        .create_user(&owner, "dup@example.com", "Dup", "user", true)
        .unwrap();
    let resp = system.create_user(&owner, "dup@example.com", "Dup2", "user", true);
    // Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the spec's code is "email_exists"
    // ("create user duplicate email -> 409 {error: "email_exists"}"), not "conflict".
    match resp {
        Response::Error { error, .. } => assert_eq!(error, "email_exists"),
        _ => panic!("Expected conflict"),
    }
}

// ADMIN-03
#[test]
fn test_create_user_non_owner() {
    let system = setup();
    let user = system
        .create_user(&system.get_user_by_email("owner@example.com").unwrap().unwrap(), "user@example.com", "User", "user", true)
        .unwrap();
    let uid: i64 = serde_json::from_value(user.data.get("user_id").unwrap().clone()).unwrap();
    let normal = system.get_user_by_id(uid).unwrap();
    let resp = system.create_user(&normal, "another@example.com", "Another", "user", true);
    match resp {
        Response::Error { error, .. } => assert_eq!(error, "owner_only"),
        _ => panic!("Expected owner_only"),
    }
}

/// What: ADMIN-04/05: an owner cannot reset their own password; resetting another user emails a reset link.
/// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the "email sent" assertion was added. Touches: in-memory SQLite.
// ADMIN-04
// ADMIN-05
#[test]
fn test_reset_password_happy_path() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    let resp = system.reset_password(&owner, owner.id);
    match resp {
        Response::Error { error, .. } => assert_eq!(error, "cannot_reset_own_password"),
        _ => panic!("Expected own reset error"),
    }
    let new_user = system
        .create_user(&owner, "reset@example.com", "Reset", "user", true)
        .unwrap();
    let uid: i64 = serde_json::from_value(new_user.data.get("user_id").unwrap().clone()).unwrap();
    let resp = system.reset_password(&owner, uid);
    match resp {
        Response::Success { .. } => {}
        _ => panic!("Expected success"),
    }
    // ADMIN-04 "email sent" (assertion added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
    assert!(system.sent_emails().iter().any(|m| m.to == "reset@example.com" && m.body.contains("/reset?token=")));
}

/// What: ADMIN-06: an owner changes a user's role; the role is stored and audited. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP:
/// the stored-role and audit assertions were added. Touches: in-memory SQLite.
// ADMIN-06
#[test]
fn test_change_role_happy_path() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    let new_user = system
        .create_user(&owner, "role@example.com", "Role", "user", true)
        .unwrap();
    let uid: i64 = serde_json::from_value(new_user.data.get("user_id").unwrap().clone()).unwrap();
    let resp = system.change_role(&owner, uid, "admin"); // role, Phase B.2 (was "premium")
    match resp {
        Response::Success { .. } => {}
        _ => panic!("Expected success"),
    }
    // ADMIN-06 "role changed + audit logged" (assertions added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
    assert_eq!(system.get_user_by_id(uid).unwrap().tier, Role::Admin);
    let audited: i64 = system.conn.query_row("SELECT COUNT(*) FROM audit_logs WHERE action = 'role_changed' AND resource_id = ?1", params![uid], |r| r.get(0)).unwrap();
    assert_eq!(audited, 1);
}

/// What: ADMIN-07: demoting the last active owner is 400 cannot_demote_last_owner. Changed 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.3 ruling and the spec's change_role "Order"): an owner demoting
/// themselves now meets the own-account gate first (cannot_change_own_role, asserted below), so the last-owner
/// refusal is proven where the spec says it is reachable: the remaining active owner approving a governance
/// change_role that demotes them. The approval fails with 400, the role is unchanged and the action stays
/// pending. In: none. Out: panics on a wrong answer. Touches: in-memory SQLite.
/// Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (review finding 4525101321; spec LAST OWNER, approver
/// rule): the last step asserted that owner2, approving an action that targets owner2, demoted itself to Admin. The
/// spec refuses that with 400 cannot_change_own_role (PHP and JavaScript agree), so the step now asserts that
/// refusal with the action still pending, and owner3 (another active owner) approves it to prove the execution.
// ADMIN-07
#[test]
fn test_change_role_last_owner() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    let resp = system.change_role(&owner, owner.id, "user"); // role, Phase B.2 (was "basic")
    match resp {
        Response::Error { error, .. } => assert_eq!(error, "cannot_change_own_role"),
        _ => panic!("Expected error"),
    }
    let second = system.create_user(&owner, "owner2@example.com", "Owner Two", "owner", false).unwrap();
    let owner2_id = second.data["user_id"].as_i64().unwrap();
    let now = Utc::now().to_rfc3339();
    system
        .conn
        .execute(
            "INSERT INTO governance_actions (action_type,actor_id,target_resource_id,reason,submitted_at,status,params) VALUES ('change_role',?1,?2,'reorg',?3,'pending',?4)",
            params![owner.id, owner2_id, now, r#"{"new_tier":"admin"}"#],
        )
        .unwrap();
    let action = system.conn.last_insert_rowid();
    // the first owner is suspended, so owner2 is the last active owner
    let owner2 = system.get_user_by_id(owner2_id).unwrap();
    system.suspend_user(&owner2, owner.id, "policy").unwrap();
    let resp = system.decide_governance_action(&owner2, action, "approve", None);
    match &resp {
        Response::Error { error, .. } => assert_eq!(error, "cannot_demote_last_owner"),
        _ => panic!("Expected error"),
    }
    assert_eq!(resp.status(), 400);
    assert_eq!(system.get_user_by_id(owner2_id).unwrap().tier, Role::Owner);
    let status: String = system.conn.query_row("SELECT status FROM governance_actions WHERE id = ?1", params![action], |r| r.get(0)).unwrap();
    assert_eq!(status, "pending");
    // with another active owner the last-owner check passes, but owner2 is the target and the approver:
    // 400 cannot_change_own_role, still pending (review finding 4525101321, 2026-11-10,
    // session_012zDydZCZ4AChqhEZ4oVtaP; this step asserted that owner2 demoted itself)
    let third = system.create_user(&owner2, "owner3@example.com", "Owner Three", "owner", false).unwrap();
    let owner3 = system.get_user_by_id(third.data["user_id"].as_i64().unwrap()).unwrap();
    let resp = system.decide_governance_action(&owner2, action, "approve", None);
    match &resp {
        Response::Error { error, .. } => assert_eq!(error, "cannot_change_own_role"),
        _ => panic!("Expected error"),
    }
    assert_eq!(resp.status(), 400);
    assert_eq!(system.get_user_by_id(owner2_id).unwrap().tier, Role::Owner);
    let status: String = system.conn.query_row("SELECT status FROM governance_actions WHERE id = ?1", params![action], |r| r.get(0)).unwrap();
    assert_eq!(status, "pending");
    // another owner approving it executes it
    system.decide_governance_action(&owner3, action, "approve", None).unwrap();
    assert_eq!(system.get_user_by_id(owner2_id).unwrap().tier, Role::Admin);
}

/// What: ADMIN-07, approver rule: with two active owners, a governance change_role that targets the approving
/// owner is 400 cannot_change_own_role, the approver keeps the owner role, no role_changed row is written and the
/// action stays pending. In: none. Out: panics on a wrong answer.
/// Why: spec LAST OWNER (approver rule); review finding 4525101339. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: in-memory SQLite.
// ADMIN-07
#[test]
fn test_governance_change_role_target_is_approver() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    let second = system.create_user(&owner, "owner2@example.com", "Owner Two", "owner", false).unwrap();
    let owner2 = system.get_user_by_id(second.data["user_id"].as_i64().unwrap()).unwrap();
    let now = Utc::now().to_rfc3339();
    system
        .conn
        .execute(
            "INSERT INTO governance_actions (action_type,actor_id,target_resource_id,reason,submitted_at,status,params) VALUES ('change_role',?1,?2,'self',?3,'pending',?4)",
            params![owner2.id, owner.id, now, r#"{"new_tier":"user"}"#],
        )
        .unwrap();
    let action = system.conn.last_insert_rowid();
    let resp = system.decide_governance_action(&owner, action, "approve", None);
    match &resp {
        Response::Error { error, .. } => assert_eq!(error, "cannot_change_own_role"),
        _ => panic!("Expected error"),
    }
    assert_eq!(resp.status(), 400);
    assert_eq!(system.get_user_by_id(owner.id).unwrap().tier, Role::Owner);
    let status: String = system.conn.query_row("SELECT status FROM governance_actions WHERE id = ?1", params![action], |r| r.get(0)).unwrap();
    assert_eq!(status, "pending");
    let audited: i64 = system.conn.query_row("SELECT COUNT(*) FROM audit_logs WHERE action = 'role_changed' AND resource_id = ?1", params![owner.id], |r| r.get(0)).unwrap();
    assert_eq!(audited, 0);
}

/// What: ADMIN-08: suspending a user changes their status. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the status assertion
/// was added. Touches: in-memory SQLite.
// ADMIN-08
#[test]
fn test_suspend_user_happy_path() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    let new_user = system
        .create_user(&owner, "suspend@example.com", "Suspend", "user", true)
        .unwrap();
    let uid: i64 = serde_json::from_value(new_user.data.get("user_id").unwrap().clone()).unwrap();
    let resp = system.suspend_user(&owner, uid, "violation");
    match resp {
        Response::Success { .. } => {}
        _ => panic!("Expected success"),
    }
    // ADMIN-08 "status changed" (assertion added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
    assert_eq!(system.get_user_by_id(uid).unwrap().status, "suspended");
}

// ADMIN-09
#[test]
fn test_suspend_own_account() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    let resp = system.suspend_user(&owner, owner.id, "self");
    match resp {
        Response::Error { error, .. } => assert_eq!(error, "cannot_suspend_yourself"),
        _ => panic!("Expected error"),
    }
}

/// What: ADMIN-10: the customer list pages correctly and every field is present. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP:
/// pagination and field assertions were added. Touches: in-memory SQLite.
// ADMIN-10
#[test]
fn test_customers_list() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    // Insert customers
    let now = Utc::now().to_rfc3339();
    for i in 0..5 {
        system
            .conn
            .execute(
                "INSERT INTO customers (email,name,tier,signup_date,invoice_count,status) VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    format!("cust{}@example.com", i),
                    format!("Customer {}", i),
                    "solo", // plan, Phase B.2 (was "basic")
                    now,
                    0,
                    "active"
                ],
            )
            .unwrap();
    }
    let resp = system.list_customers(&owner, 1, 10);
    match resp {
        Response::Success { data, .. } => {
            let arr = data.as_array().unwrap();
            assert_eq!(arr.len(), 5);
        }
        _ => panic!("Expected success"),
    }
    // ADMIN-10 "pagination works, all fields present" (assertions added 2026-11-10,
    // session_012zDydZCZ4AChqhEZ4oVtaP): 2 per page, page 3 holds the 5th customer
    let page = |p: i64| system.list_customers(&owner, p, 2).unwrap().data.as_array().unwrap().clone();
    assert_eq!(page(1).len(), 2);
    assert_eq!(page(3).len(), 1);
    assert_eq!(page(3)[0]["email"], "cust4@example.com");
    for field in ["customer_id", "email", "name", "tier", "signup_date", "invoice_count", "status"] {
        assert!(page(1)[0].get(field).is_some(), "missing {}", field);
    }
}

/// What: ADMIN-11: a customer's detail has every field. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: field assertions added.
/// Touches: in-memory SQLite.
// ADMIN-11
#[test]
fn test_customers_detail() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    let now = Utc::now().to_rfc3339();
    system
        .conn
        .execute(
            "INSERT INTO customers (email,name,tier,signup_date,invoice_count,status) VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                "cust@example.com",
                "Customer",
                "solo", // plan, Phase B.2 (was "basic")
                now,
                0,
                "active"
            ],
        )
        .unwrap();
    let cid = system.conn.last_insert_rowid();
    let resp = system.get_customer(&owner, cid);
    match resp {
        Response::Success { data, .. } => {
            assert_eq!(data.get("customer_id").unwrap(), &serde_json::json!(cid));
            // ADMIN-11 "all fields present" (added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
            for field in ["email", "name", "tier", "subscription_status", "payment_method", "address", "notes", "status"] {
                assert!(data.get(field).is_some(), "missing {}", field);
            }
        }
        _ => panic!("Expected success"),
    }
}

/// What: ADMIN-12: change_plan retrieves the subscription and updates its one item (item id + new price,
/// create_prorations), stores the tier and audits; two items or an unknown tier are refused before any
/// update. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP for the ADMIN-12 amendment. Touches: in-memory SQLite, the fake payment client.
// ADMIN-12
#[test]
fn test_change_plan() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    let now = Utc::now().to_rfc3339();
    system
        .conn
        .execute(
            "INSERT INTO customers (email,name,tier,signup_date,invoice_count,status,stripe_subscription_id) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                "cust@example.com",
                "Customer",
                "solo", // plan, Phase B.2 (was "basic")
                now,
                0,
                "active",
                "sub_1"
            ],
        )
        .unwrap();
    let cid = system.conn.last_insert_rowid();
    // Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the customer now has a subscription id,
    // because the spec's change_plan updates the subscription at the payment provider (a customer
    // with none cannot change plan); the provider call is asserted.
    let resp = system.change_plan(&owner, cid, "team"); // plan, Phase B.2 (was "premium")
    match resp {
        Response::Success { .. } => {}
        _ => panic!("Expected success"),
    }
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-12 amendment): the update carries the existing
    // item id with the new price and create_prorations (no second item)
    STRIPE_CALLS.with(|c| assert_eq!(c.borrow().as_slice(), [("sub_1".to_string(), "si_sub_1=price_team create_prorations".to_string())]));
    let audited: i64 = system
        .conn
        .query_row("SELECT COUNT(*) FROM audit_logs WHERE action = 'plan_changed' AND resource_id = ?1 AND actor_id = ?2", params![cid, owner.id], |r| r.get(0))
        .unwrap();
    assert_eq!(audited, 1);
    let tier: String = system.conn.query_row("SELECT tier FROM customers WHERE id = ?1", params![cid], |r| r.get(0)).unwrap();
    assert_eq!(tier, "team");

    // two items (or an unknown tier) are refused before any update, and nothing changes
    STRIPE_ITEMS.with(|i| {
        i.borrow_mut().insert("sub_1".into(), vec![
            SubscriptionItem { id: "si_a".into(), price: "price_team".into() },
            SubscriptionItem { id: "si_b".into(), price: "price_solo".into() },
        ])
    });
    match system.change_plan(&owner, cid, "enterprise") {
        Response::Error { error, .. } => assert_eq!(error, "subscription_item_ambiguous"),
        _ => panic!("Expected subscription_item_ambiguous"),
    }
    match system.change_plan(&owner, cid, "platinum") {
        Response::Error { error, .. } => assert_eq!(error, "invalid_tier"),
        _ => panic!("Expected invalid_tier"),
    }
    STRIPE_CALLS.with(|c| assert_eq!(c.borrow().len(), 1));
}

/// What: ADMIN-13: a queued refund row exists with status queued. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: row assertion added.
/// Touches: in-memory SQLite.
// ADMIN-13
#[test]
fn test_queue_refund() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    // Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): invoice 1 is created first; the spec
    // requires "invoice exists, status='succeeded'" before a refund is queued.
    system.conn.execute("INSERT INTO invoices (id, amount, status) VALUES (1, 10000, 'succeeded')", []).unwrap();
    let resp = system.queue_refund(&owner, 1, 5000, "refund reason");
    match resp {
        Response::Success { data, .. } => {
            assert_eq!(data.get("status").unwrap(), &serde_json::json!("queued"));
        }
        _ => panic!("Expected success"),
    }
    // ADMIN-13 "refund record created" (assertion added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
    let rows: i64 = system.conn.query_row("SELECT COUNT(*) FROM refunds WHERE invoice_id = 1 AND amount = 5000 AND status = 'queued'", [], |r| r.get(0)).unwrap();
    assert_eq!(rows, 1);
}

/// What: ADMIN-14: a deployment is created as a draft with its config initialized. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP:
/// row and config assertions added. Touches: in-memory SQLite.
// ADMIN-14
#[test]
fn test_create_deployment() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    let now = Utc::now().to_rfc3339();
    system
        .conn
        .execute(
            "INSERT INTO customers (email,name,tier,signup_date,invoice_count,status) VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                "cust@example.com",
                "Customer",
                "solo", // plan, Phase B.2 (was "basic")
                now,
                0,
                "active"
            ],
        )
        .unwrap();
    let cid = system.conn.last_insert_rowid();
    let resp = system.create_deployment(&owner, cid, "example.com", "solo", "theme1"); // plan, Phase B.2 (was "basic")
    let dep_id = match resp {
        Response::Success { data, .. } => data["deployment_id"].as_i64().unwrap(),
        _ => panic!("Expected success"),
    };
    // ADMIN-14 "config initialized" (assertion added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
    let (status, config): (String, String) = system.conn.query_row("SELECT status, config FROM deployments WHERE id = ?1", params![dep_id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!(status, "draft");
    let config: serde_json::Value = serde_json::from_str(&config).unwrap();
    assert_eq!((config["theme"].as_str(), config["tier"].as_str()), (Some("theme1"), Some("solo")));
}

/// What: ADMIN-15: publishing needs the owner AND the safety flag; then the status is live. Changed
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the safety-flag gate and live-status assertions were added.
/// Changed 2026-11-10 (Phase B.2): a new deployment has domain_verified false and publish is refused
/// (domain_not_verified) until `verify_domain` sets it. Touches: in-memory SQLite.
// ADMIN-15
#[test]
fn test_publish_deployment() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    let now = Utc::now().to_rfc3339();
    system
        .conn
        .execute(
            "INSERT INTO customers (email,name,tier,signup_date,invoice_count,status) VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                "cust@example.com",
                "Customer",
                "solo", // plan, Phase B.2 (was "basic")
                now,
                0,
                "active"
            ],
        )
        .unwrap();
    let cid = system.conn.last_insert_rowid();
    let dep_resp = system.create_deployment(&owner, cid, "example.com", "solo", "theme1"); // plan, Phase B.2 (was "basic")
    // Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): `Response` is an enum, so its data is
    // reached through `unwrap()` as in the other tests (`dep_resp.data` could not compile).
    let dep_id: i64 = serde_json::from_value(dep_resp.unwrap().data.get("deployment_id").unwrap().clone()).unwrap();
    // ADMIN-15 double gate (added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): with the safety flag
    // off an owner still cannot publish
    // Phase B.2 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): domain_verified starts false and publish needs it
    let verified: bool = system.conn.query_row("SELECT domain_verified FROM deployments WHERE id = ?1", params![dep_id], |r| r.get(0)).unwrap();
    assert!(!verified);
    let refused = system.publish_deployment(&owner, dep_id);
    assert_eq!((refused.status(), refused.clone()), (400, Response::Error { error: "domain_not_verified".into(), message: "domain not verified".into() }));
    assert!(system.verify_domain(&owner, dep_id).is_success());
    let verified: bool = system.conn.query_row("SELECT domain_verified FROM deployments WHERE id = ?1", params![dep_id], |r| r.get(0)).unwrap();
    assert!(verified);
    let mut system = system;
    system.safety.can_publish = false;
    match system.publish_deployment(&owner, dep_id) {
        Response::Error { error, .. } => assert_eq!(error, "publishing_disabled"),
        _ => panic!("Expected publishing_disabled"),
    }
    system.safety.can_publish = true;
    let resp = system.publish_deployment(&owner, dep_id);
    match resp {
        Response::Success { .. } => {}
        _ => panic!("Expected success"),
    }
    let status: String = system.conn.query_row("SELECT status FROM deployments WHERE id = ?1", params![dep_id], |r| r.get(0)).unwrap();
    assert_eq!(status, "live");
}

/// What: ADMIN-16: approving executes the action and marks it approved. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the
/// status assertion was added. Touches: in-memory SQLite.
// ADMIN-16
#[test]
fn test_governance_approve() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    // Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the action targeted user 1, which is the
    // approving owner himself; approving executes the action, and deleting the last active owner is
    // refused by the spec's safety rules. It now targets a separate user, whose deletion is asserted.
    let target = system.create_user(&owner, "target@example.com", "Target", "user", false).unwrap();
    let target_id: i64 = serde_json::from_value(target.data.get("user_id").unwrap().clone()).unwrap();
    // Insert pending action
    let now = Utc::now().to_rfc3339();
    system
        .conn
        .execute(
            "INSERT INTO governance_actions (action_type,actor_id,target_resource_id,reason,submitted_at,status) VALUES (?1,?2,?3,?4,?5,?6)",
            params!["delete_user", owner.id, target_id, "test", now, "pending"],
        )
        .unwrap();
    let action_id = system.conn.last_insert_rowid();
    let resp = system.decide_governance_action(&owner, action_id, "approve", None);
    match resp {
        Response::Success { .. } => {}
        _ => panic!("Expected success"),
    }
    assert_eq!(system.get_user_by_id(target_id).unwrap().status, "deleted");
    // ADMIN-16 "status changed" (assertion added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
    let status: String = system.conn.query_row("SELECT status FROM governance_actions WHERE id = ?1", params![action_id], |r| r.get(0)).unwrap();
    assert_eq!(status, "approved");
}

/// What: ADMIN-17: rejecting stores the status and the reason, and audits it. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP:
/// assertions added. Touches: in-memory SQLite.
// ADMIN-17
#[test]
fn test_governance_reject() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    let now = Utc::now().to_rfc3339();
    system
        .conn
        .execute(
            "INSERT INTO governance_actions (action_type,actor_id,target_resource_id,reason,submitted_at,status) VALUES (?1,?2,?3,?4,?5,?6)",
            params!["delete_user", owner.id, 1, "test", now, "pending"],
        )
        .unwrap();
    let action_id = system.conn.last_insert_rowid();
    let resp = system.decide_governance_action(&owner, action_id, "reject", Some("not needed"));
    match resp {
        Response::Success { .. } => {}
        _ => panic!("Expected success"),
    }
    // ADMIN-17 "rejected + reason logged" (assertions added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
    let (status, reason): (String, Option<String>) =
        system.conn.query_row("SELECT status, rejection_reason FROM governance_actions WHERE id = ?1", params![action_id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!((status.as_str(), reason.as_deref()), ("rejected", Some("not needed")));
    let logged: i64 = system.conn.query_row("SELECT COUNT(*) FROM audit_logs WHERE action = 'action_rejected' AND reason = 'not needed'", [], |r| r.get(0)).unwrap();
    assert_eq!(logged, 1);
}

/// What: ADMIN-18: audit search filters by action, resource and date and pages correctly. Changed
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: filter and pagination assertions were added. Touches: in-memory SQLite.
// ADMIN-18
#[test]
fn test_audit_log_search() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    // Create a user to generate audit log
    system.create_user(&owner, "audit@example.com", "Audit", "user", true).unwrap();
    let now = Utc::now();
    let resp = system.search_audit_log(&owner, None, None, None, 10, 0);
    match resp {
        Response::Success { data, .. } => {
            let arr = data.as_array().unwrap();
            assert!(arr.len() > 0);
        }
        _ => panic!("Expected success"),
    }
    // ADMIN-18 "filters applied, pagination works" (assertions added 2026-11-10,
    // session_012zDydZCZ4AChqhEZ4oVtaP): three users created -> three user_created rows, newest first
    let second = system.create_user(&owner, "audit2@example.com", "Audit Two", "user", false).unwrap();
    let second_id = second.data["user_id"].as_i64().unwrap();
    system.create_user(&owner, "audit3@example.com", "Audit Three", "user", false).unwrap();
    let uid = system.get_user_by_email("audit@example.com").unwrap().unwrap().id;
    system.suspend_user(&owner, uid, "test").unwrap();
    let search = |action: Option<&str>, rid: Option<i64>, range: Option<(&str, &str)>, limit: i64, offset: i64| {
        system.search_audit_log(&owner, action, rid, range, limit, offset).unwrap().data.as_array().unwrap().clone()
    };
    let created = search(Some("user_created"), None, None, 10, 0);
    assert_eq!(created.len(), 3);
    assert!(created.iter().all(|r| r["action"] == "user_created"));
    assert_eq!(search(Some("user_created"), Some(second_id), None, 10, 0).len(), 1);
    let page1 = search(Some("user_created"), None, None, 2, 0);
    let page2 = search(Some("user_created"), None, None, 2, 2);
    assert_eq!((page1.len(), page2.len()), (2, 1));
    assert_ne!(page1[1]["resource_id"], page2[0]["resource_id"]);
    let future = (now + chrono::Duration::days(1)).to_rfc3339();
    let far = (now + chrono::Duration::days(2)).to_rfc3339();
    assert!(search(None, None, Some((&future, &far)), 10, 0).is_empty());
}
/// What: ADMIN-19: a suspended owner calling any admin action gets 403 account_suspended before any gate
/// (even where another check would also refuse, e.g. a blank reason or their own id), and nothing changes:
/// no user, customer, deployment, refund, governance or audit row is written. In: none. Out: panics on a
/// wrong answer. Why: ADMIN-19 (Phase B.2, 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: in-memory SQLite.
// ADMIN-19
#[test]
fn test_suspended_owner_is_refused_everywhere() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    let other = system.create_user(&owner, "second@example.com", "Second Owner", "owner", false).unwrap();
    let other_id = other.data["user_id"].as_i64().unwrap();
    let now = Utc::now().to_rfc3339();
    system.conn.execute("INSERT INTO customers (email,name,tier,signup_date,invoice_count,status,stripe_subscription_id) VALUES ('c@example.com','C','solo',?1,0,'active','sub_9')", params![now]).unwrap();
    let cid = system.conn.last_insert_rowid();
    let dep = system.create_deployment(&owner, cid, "suspended.example.com", "team", "theme1").unwrap().data["deployment_id"].as_i64().unwrap();
    system.verify_domain(&owner, dep).unwrap();
    system.conn.execute("INSERT INTO invoices (id, amount, status) VALUES (7, 1000, 'succeeded')", []).unwrap();
    system.conn.execute("INSERT INTO governance_actions (action_type,actor_id,target_resource_id,reason,submitted_at,status) VALUES ('suspend_user',?1,?2,'x',?3,'pending')", params![owner.id, other_id, now]).unwrap();
    let action = system.conn.last_insert_rowid();
    // the second owner suspends the first
    let second = system.get_user_by_id(other_id).unwrap();
    system.suspend_user(&second, owner.id, "policy").unwrap();
    let snapshot = || -> Vec<i64> {
        ["users", "customers", "deployments", "refunds", "governance_actions", "audit_logs", "password_resets"]
            .iter()
            .map(|t| system.conn.query_row(&format!("SELECT COUNT(*) FROM {}", t), [], |r| r.get(0)).unwrap())
            .collect()
    };
    let state = |sql: &str| -> String { system.conn.query_row(sql, [], |r| r.get(0)).unwrap() };
    let before = (snapshot(), state("SELECT group_concat(tier || status, ',') FROM users"), state("SELECT group_concat(tier || status, ',') FROM deployments"), state("SELECT tier FROM customers"));
    let calls = [
        system.create_user(&owner, "x@example.com", "X Person", "user", true),
        system.reset_password(&owner, other_id),
        system.change_role(&owner, other_id, "user"),
        system.suspend_user(&owner, other_id, "x"),
        system.suspend_user(&owner, owner.id, ""),
        system.list_customers(&owner, 1, 10),
        system.get_customer(&owner, cid),
        system.change_plan(&owner, cid, "team"),
        system.queue_refund(&owner, 7, 100, "x"),
        system.create_deployment(&owner, cid, "other.example.com", "solo", "theme1"),
        system.verify_domain(&owner, dep),
        system.publish_deployment(&owner, dep),
        system.suspend_deployment(&owner, dep, " "),
        system.retire_deployment(&owner, dep),
        system.list_governance_actions(&owner, 1, 10),
        system.decide_governance_action(&owner, action, "approve", None),
        system.decide_governance_action(&owner, action, "reject", Some("no")),
        system.search_audit_log(&owner, None, None, None, 10, 0),
    ];
    for (i, resp) in calls.iter().enumerate() {
        match resp {
            Response::Error { error, .. } => assert_eq!(error, "account_suspended", "call {}", i),
            _ => panic!("call {} succeeded for a suspended owner", i),
        }
        assert_eq!(resp.status(), 403, "call {}", i);
    }
    let after = (snapshot(), state("SELECT group_concat(tier || status, ',') FROM users"), state("SELECT group_concat(tier || status, ',') FROM deployments"), state("SELECT tier FROM customers"));
    assert_eq!(after, before, "nothing changed");
    STRIPE_CALLS.with(|c| assert!(c.borrow().is_empty(), "no provider call"));
}

/// What: ADMIN-19 and the Phase B.3 ruling: the request check refuses a suspended caller with 403
/// account_suspended BEFORE the CSRF check, so a suspended owner with a wrong CSRF token still gets
/// account_suspended; an active owner with a wrong token gets 403 csrf_invalid, and the right token passes.
/// In: none. Out: panics on a wrong answer. Why: spec EVERY ACTION ("the CSRF check included").
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
// ADMIN-19
#[test]
fn test_suspended_caller_refused_before_csrf() {
    let system = setup().with_csrf_token("session-csrf-token-1");
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    assert_eq!(system.verify_request(&owner, "session-csrf-token-1").unwrap().id, owner.id);
    let wrong = system.verify_request(&owner, "forged").unwrap_err();
    assert!(matches!(&wrong, AdminError::Forbidden(c) if c == "csrf_invalid"));
    assert_eq!(status_for("csrf_invalid"), 403);
    let second = system.create_user(&owner, "second@example.com", "Second Owner", "owner", false).unwrap();
    let second = system.get_user_by_id(second.data["user_id"].as_i64().unwrap()).unwrap();
    system.suspend_user(&second, owner.id, "policy").unwrap();
    for token in ["forged", "", "session-csrf-token-1"] {
        let r = system.verify_request(&owner, token).unwrap_err();
        assert!(matches!(&r, AdminError::Forbidden(c) if c == "account_suspended"), "{:?}", r);
    }
}

/// What: the TIERS rule (Phase B.2), part of ADMIN-06/12/14: users.tier is the staff role and a customer's
/// or deployment's tier the plan; a plan value where a role is expected (create_user, change_role) or a role
/// value where a plan is expected (change_plan, create_deployment) is 400 invalid_tier and nothing changes;
/// an "enterprise" customer plan does not make anyone an owner. In: none. Out: panics on a wrong answer.
/// Why: the old `Tier` read the enterprise plan as the owner role. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: in-memory SQLite.
// ADMIN-06
// ADMIN-12
// ADMIN-14
#[test]
fn test_roles_and_plans_are_not_mixed() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    let user = system.create_user(&owner, "staff@example.com", "Staff", "user", false).unwrap().data["user_id"].as_i64().unwrap();
    let now = Utc::now().to_rfc3339();
    system.conn.execute("INSERT INTO customers (email,name,tier,signup_date,invoice_count,status,stripe_subscription_id) VALUES ('c@example.com','C','solo',?1,0,'active','sub_5')", params![now]).unwrap();
    let cid = system.conn.last_insert_rowid();
    let code = |r: Response| -> (u16, String) {
        let status = r.status();
        match r {
            Response::Error { error, .. } => (status, error),
            _ => (status, "success".into()),
        }
    };
    for plan in ["solo", "team", "enterprise"] {
        assert_eq!(code(system.create_user(&owner, &format!("{}@example.com", plan), "Some One", plan, false)), (400, "invalid_tier".into()));
        assert_eq!(code(system.change_role(&owner, user, plan)), (400, "invalid_tier".into()));
    }
    for role in ["owner", "admin", "user"] {
        assert_eq!(code(system.change_plan(&owner, cid, role)), (400, "invalid_tier".into()));
        assert_eq!(code(system.create_deployment(&owner, cid, &format!("{}.example.com", role), role, "theme1")), (400, "invalid_tier".into()));
    }
    assert_eq!(system.get_user_by_id(user).unwrap().tier, Role::User);
    let deployments: i64 = system.conn.query_row("SELECT COUNT(*) FROM deployments", [], |r| r.get(0)).unwrap();
    assert_eq!(deployments, 0);
    STRIPE_CALLS.with(|c| assert!(c.borrow().is_empty()));
    // a valid plan and a valid role still work, and the enterprise plan is not the owner role
    assert!(system.change_plan(&owner, cid, "enterprise").is_success());
    assert!(system.change_role(&owner, user, "admin").is_success());
    let staff = system.get_user_by_id(user).unwrap();
    assert!(staff.is_admin_or_owner() && !staff.is_owner());
    assert_eq!(code(system.create_user(&staff, "y@example.com", "Y Person", "user", false)), (403, "owner_only".into()));
}

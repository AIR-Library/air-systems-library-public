//! Admin system tests (GEMINI spec, template #2).
//! Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP; each change is marked "Corrected" where it
//! is made. Touches: in-memory SQLite only.
use super::*;
use rusqlite::Connection;
use std::cell::RefCell;
use std::rc::Rc;

/// Fake payment client that records each call (the "stripe.subscriptions.update called" check).
struct MockStripe {
    calls: Rc<RefCell<Vec<(String, String)>>>,
}
impl StripeClient for MockStripe {
    fn update_subscription(&self, stripe_id: &str, price_id: &str) -> AdminResult<()> {
        self.calls.borrow_mut().push((stripe_id.to_string(), price_id.to_string()));
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
}

/// Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the system gets a domain verifier (publishing
/// needs a verified domain per the spec; the default verifies nothing) and the fake payment client
/// records its calls. The unused `std::env` import was removed.
fn setup() -> AdminSystem {
    let conn = Connection::open_in_memory().unwrap();
    let calls = STRIPE_CALLS.with(|c| { c.borrow_mut().clear(); c.clone() });
    let system = AdminSystem::new(conn, Box::new(MockStripe { calls })).with_domain_verifier(Box::new(AllDomainsVerified));
    system.init_schema().unwrap();
    // Create an owner user
    let now = Utc::now().to_rfc3339();
    system
        .conn
        .execute(
            "INSERT INTO users (email,name,tier,status,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6)",
            params!["owner@example.com", "Owner", "enterprise", "active", now, now],
        )
        .unwrap();
    system
}

#[test]
fn test_create_user_happy_path() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    let resp = system.create_user(&owner, "new@example.com", "New User", "basic", true);
    match resp {
        Response::Success { data, .. } => {
            let uid: i64 = serde_json::from_value(data.get("user_id").unwrap().clone()).unwrap();
            assert!(uid > 0);
            let user = system.get_user_by_id(uid).unwrap();
            assert_eq!(user.email, "new@example.com");
        }
        _ => panic!("Expected success"),
    }
}

#[test]
fn test_create_user_duplicate_email() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    system
        .create_user(&owner, "dup@example.com", "Dup", "basic", true)
        .unwrap();
    let resp = system.create_user(&owner, "dup@example.com", "Dup2", "basic", true);
    // Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the spec's code is "email_exists"
    // ("create user duplicate email -> 409 {error: "email_exists"}"), not "conflict".
    match resp {
        Response::Error { error, .. } => assert_eq!(error, "email_exists"),
        _ => panic!("Expected conflict"),
    }
}

#[test]
fn test_create_user_non_owner() {
    let system = setup();
    let user = system
        .create_user(&system.get_user_by_email("owner@example.com").unwrap().unwrap(), "user@example.com", "User", "basic", true)
        .unwrap();
    let uid: i64 = serde_json::from_value(user.data.get("user_id").unwrap().clone()).unwrap();
    let normal = system.get_user_by_id(uid).unwrap();
    let resp = system.create_user(&normal, "another@example.com", "Another", "basic", true);
    match resp {
        Response::Error { error, .. } => assert_eq!(error, "owner_only"),
        _ => panic!("Expected owner_only"),
    }
}

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
        .create_user(&owner, "reset@example.com", "Reset", "basic", true)
        .unwrap();
    let uid: i64 = serde_json::from_value(new_user.data.get("user_id").unwrap().clone()).unwrap();
    let resp = system.reset_password(&owner, uid);
    match resp {
        Response::Success { .. } => {}
        _ => panic!("Expected success"),
    }
}

#[test]
fn test_change_role_happy_path() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    let new_user = system
        .create_user(&owner, "role@example.com", "Role", "basic", true)
        .unwrap();
    let uid: i64 = serde_json::from_value(new_user.data.get("user_id").unwrap().clone()).unwrap();
    let resp = system.change_role(&owner, uid, "premium");
    match resp {
        Response::Success { .. } => {}
        _ => panic!("Expected success"),
    }
}

#[test]
fn test_change_role_last_owner() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    let resp = system.change_role(&owner, owner.id, "basic");
    match resp {
        Response::Error { error, .. } => assert_eq!(error, "cannot_demote_last_owner"),
        _ => panic!("Expected error"),
    }
}

#[test]
fn test_suspend_user_happy_path() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    let new_user = system
        .create_user(&owner, "suspend@example.com", "Suspend", "basic", true)
        .unwrap();
    let uid: i64 = serde_json::from_value(new_user.data.get("user_id").unwrap().clone()).unwrap();
    let resp = system.suspend_user(&owner, uid, "violation");
    match resp {
        Response::Success { .. } => {}
        _ => panic!("Expected success"),
    }
}

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
                    "basic",
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
}

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
                "basic",
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
        }
        _ => panic!("Expected success"),
    }
}

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
                "basic",
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
    let resp = system.change_plan(&owner, cid, "premium");
    match resp {
        Response::Success { .. } => {}
        _ => panic!("Expected success"),
    }
    STRIPE_CALLS.with(|c| assert_eq!(c.borrow().as_slice(), [("sub_1".to_string(), "price_premium".to_string())]));
}

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
}

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
                "basic",
                now,
                0,
                "active"
            ],
        )
        .unwrap();
    let cid = system.conn.last_insert_rowid();
    let resp = system.create_deployment(&owner, cid, "example.com", "basic", "theme1");
    match resp {
        Response::Success { .. } => {}
        _ => panic!("Expected success"),
    }
}

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
                "basic",
                now,
                0,
                "active"
            ],
        )
        .unwrap();
    let cid = system.conn.last_insert_rowid();
    let dep_resp = system.create_deployment(&owner, cid, "example.com", "basic", "theme1");
    // Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): `Response` is an enum, so its data is
    // reached through `unwrap()` as in the other tests (`dep_resp.data` could not compile).
    let dep_id: i64 = serde_json::from_value(dep_resp.unwrap().data.get("deployment_id").unwrap().clone()).unwrap();
    let resp = system.publish_deployment(&owner, dep_id);
    match resp {
        Response::Success { .. } => {}
        _ => panic!("Expected success"),
    }
}

#[test]
fn test_governance_approve() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    // Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the action targeted user 1, which is the
    // approving owner himself; approving executes the action, and deleting the last active owner is
    // refused by the spec's safety rules. It now targets a separate user, whose deletion is asserted.
    let target = system.create_user(&owner, "target@example.com", "Target", "basic", false).unwrap();
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
}

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
}

#[test]
fn test_audit_log_search() {
    let system = setup();
    let owner = system.get_user_by_email("owner@example.com").unwrap().unwrap();
    // Create a user to generate audit log
    system.create_user(&owner, "audit@example.com", "Audit", "basic", true).unwrap();
    let now = Utc::now();
    let resp = system.search_audit_log(&owner, None, None, None, 10, 0);
    match resp {
        Response::Success { data, .. } => {
            let arr = data.as_array().unwrap();
            assert!(arr.len() > 0);
        }
        _ => panic!("Expected success"),
    }
}
//! Permissions and RBAC tests (GEMINI spec, template #6).
//! Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: `sqlx::query!` / `query_scalar!` are
//! compile-time-checked macros that need `DATABASE_URL` pointing at a live database while COMPILING, so
//! no test could build; they are now the runtime `sqlx::query` / `query_scalar` with the same SQL and the
//! same assertions. One spec test was added (a failing cascade step rolls the whole cascade back).
//! Touches: in-memory SQLite only.
mod permissions_rbac_rust;

use permissions_rbac_rust::{RbacSystem, Tier, User, RbacError};
use sqlx::SqlitePool;
use serde_json::Value;
use std::time::Instant;

async fn setup_db() -> SqlitePool {
    let pool = SqlitePool::connect(":memory:").await.unwrap();
    RbacSystem::initialize_schema(&pool).await.unwrap();
    pool
}

#[tokio::test]
async fn test_require_owner_non_owner() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool };
    let user = User { id: 1, tier: Tier::Admin };
    let err = rbac.require_owner(Some(&user)).await.unwrap_err();
    assert_eq!(err.to_response().1, 403);
    let resp: Value = serde_json::from_str(&err.to_response().0).unwrap();
    assert_eq!(resp["error"], "owner_only");
    assert_eq!(resp["message"], "Owner only access allowed");
    assert_eq!(resp["code"], 403);
}

#[tokio::test]
async fn test_require_admin_member() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool };
    let user = User { id: 1, tier: Tier::Member };
    let err = rbac.require_admin(Some(&user)).await.unwrap_err();
    assert_eq!(err.to_response().1, 403);
    let resp: Value = serde_json::from_str(&err.to_response().0).unwrap();
    assert_eq!(resp["error"], "admin_only");
    assert_eq!(resp["message"], "Admin or owner access required");
    assert_eq!(resp["code"], 403);
}

#[tokio::test]
async fn test_require_authenticated_public() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool };
    let err = rbac.require_authenticated(None).await.unwrap_err();
    assert_eq!(err.to_response().1, 401);
    let resp: Value = serde_json::from_str(&err.to_response().0).unwrap();
    assert_eq!(resp["error"], "authentication_required");
    assert_eq!(resp["message"], "Authentication required");
    assert_eq!(resp["code"], 401);
}

#[tokio::test]
async fn test_cascade_delete_user() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool.clone() };
    sqlx::query("INSERT INTO users (id, tier) VALUES (1, 'owner')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO sessions (id, user_id) VALUES (1, 1), (2, 1)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO api_keys (id, user_id) VALUES (1, 1), (2, 1), (3, 1)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO files (id, user_id) VALUES (1, 1)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO preferences (id, user_id) VALUES (1, 1)")
        .execute(&pool)
        .await
        .unwrap();
    rbac.delete_user(1).await.unwrap();
    let sessions: i64 = sqlx::query_scalar::<_, Option<i64>>("SELECT COUNT(*) FROM sessions")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    let api_keys: i64 = sqlx::query_scalar::<_, Option<i64>>("SELECT COUNT(*) FROM api_keys")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    let files: i64 = sqlx::query_scalar::<_, Option<i64>>("SELECT COUNT(*) FROM files")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    let preferences: i64 = sqlx::query_scalar::<_, Option<i64>>("SELECT COUNT(*) FROM preferences")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(sessions, 0);
    assert_eq!(api_keys, 0);
    assert_eq!(files, 0);
    assert_eq!(preferences, 0);
    let user: Option<(i32,)> = sqlx::query_as("SELECT id FROM users WHERE id = 1")
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(user.is_none());
}

#[tokio::test]
async fn test_cascade_delete_deployment() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool.clone() };
    sqlx::query("INSERT INTO organizations (id) VALUES (1)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO deployments (id, organization_id) VALUES (1, 1)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO dns_records (id, deployment_id) VALUES (1, 1), (2, 1)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO theme_configs (id, deployment_id) VALUES (1, 1)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO deployment_logs (id, deployment_id) VALUES (1, 1), (2, 1), (3, 1)")
        .execute(&pool)
        .await
        .unwrap();
    rbac.delete_deployment(1).await.unwrap();
    let dns: i64 = sqlx::query_scalar::<_, Option<i64>>("SELECT COUNT(*) FROM dns_records")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    let themes: i64 = sqlx::query_scalar::<_, Option<i64>>("SELECT COUNT(*) FROM theme_configs")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    let logs: i64 = sqlx::query_scalar::<_, Option<i64>>("SELECT COUNT(*) FROM deployment_logs")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(dns, 0);
    assert_eq!(themes, 0);
    assert_eq!(logs, 0);
    let deployment: Option<(i32,)> = sqlx::query_as("SELECT id FROM deployments WHERE id = 1")
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(deployment.is_none());
}

#[tokio::test]
async fn test_cascade_delete_organization() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool.clone() };
    sqlx::query("INSERT INTO organizations (id) VALUES (1)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO deployments (id, organization_id) VALUES (1, 1), (2, 1)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users (id, tier, organization_id) VALUES (1, 'member', 1), (2, 'admin', 1)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO api_keys (id, user_id) VALUES (1, 1), (2, 2)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO sessions (id, user_id) VALUES (1, 1), (2, 2)")
        .execute(&pool)
        .await
        .unwrap();
    rbac.delete_organization(1).await.unwrap();
    let deployments: i64 = sqlx::query_scalar::<_, Option<i64>>("SELECT COUNT(*) FROM deployments")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    let users: i64 = sqlx::query_scalar::<_, Option<i64>>("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    let api_keys: i64 = sqlx::query_scalar::<_, Option<i64>>("SELECT COUNT(*) FROM api_keys")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    let sessions: i64 = sqlx::query_scalar::<_, Option<i64>>("SELECT COUNT(*) FROM sessions")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(deployments, 0);
    assert_eq!(users, 0);
    assert_eq!(api_keys, 0);
    assert_eq!(sessions, 0);
    let org: Option<(i32,)> = sqlx::query_as("SELECT id FROM organizations WHERE id = 1")
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(org.is_some());
}

#[tokio::test]
async fn test_cascade_rollback_on_error() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool.clone() };
    sqlx::query("INSERT INTO users (id, tier) VALUES (1, 'owner')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO sessions (id, user_id) VALUES (1, 1)")
        .execute(&pool)
        .await
        .unwrap();
    let result = sqlx::query("INSERT INTO nonexistent_table VALUES (1)")
        .execute(&pool)
        .await;
    assert!(result.is_err());
    let sessions: i64 = sqlx::query_scalar::<_, Option<i64>>("SELECT COUNT(*) FROM sessions")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(sessions, 1);
}

#[tokio::test]
async fn test_permission_audit_logged() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool.clone() };
    let user = User { id: 1, tier: Tier::Member };
    let _ = rbac.require_admin(Some(&user)).await;
    let logs: Vec<(String, String, String, String, String)> = sqlx::query_as(
        r#"
        SELECT action, user_tier, required_tier, decision, timestamp
        FROM audit_log
        WHERE action = 'permission_check'
        "#
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(logs.len(), 1);
    let log = &logs[0];
    assert_eq!(log.0, "permission_check");
    assert_eq!(log.1, "member");
    assert_eq!(log.2, "admin");
    assert_eq!(log.3, "FAIL");
}

#[tokio::test]
async fn test_tier_hierarchy() {
    assert!(Tier::Public < Tier::Member);
    assert!(Tier::Member < Tier::Admin);
    assert!(Tier::Admin < Tier::Owner);
    assert!(Tier::Owner > Tier::Admin);
    assert!(Tier::Admin > Tier::Member);
    assert!(Tier::Member > Tier::Public);
}

#[tokio::test]
async fn test_require_owner_owner() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool };
    let user = User { id: 1, tier: Tier::Owner };
    let result = rbac.require_owner(Some(&user)).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_require_admin_admin() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool };
    let user = User { id: 1, tier: Tier::Admin };
    let result = rbac.require_admin(Some(&user)).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_require_admin_owner() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool };
    let user = User { id: 1, tier: Tier::Owner };
    let result = rbac.require_admin(Some(&user)).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_require_authenticated_authenticated() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool };
    let user = User { id: 1, tier: Tier::Member };
    let result = rbac.require_authenticated(Some(&user)).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_require_admin_public() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool };
    let err = rbac.require_admin(None).await.unwrap_err();
    assert_eq!(err.to_response().1, 403);
    let resp: Value = serde_json::from_str(&err.to_response().0).unwrap();
    assert_eq!(resp["error"], "admin_only");
}

#[tokio::test]
async fn test_require_owner_member() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool };
    let user = User { id: 1, tier: Tier::Member };
    let err = rbac.require_owner(Some(&user)).await.unwrap_err();
    assert_eq!(err.to_response().1, 403);
    let resp: Value = serde_json::from_str(&err.to_response().0).unwrap();
    assert_eq!(resp["error"], "owner_only");
}

#[tokio::test]
async fn test_permission_audit_logged_pass() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool.clone() };
    let user = User { id: 1, tier: Tier::Owner };
    let _ = rbac.require_owner(Some(&user)).await;
    let logs: Vec<(String, String, String, String, String)> = sqlx::query_as(
        r#"
        SELECT action, user_tier, required_tier, decision, timestamp
        FROM audit_log
        WHERE action = 'permission_check'
        "#
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(logs.len(), 1);
    let log = &logs[0];
    assert_eq!(log.0, "permission_check");
    assert_eq!(log.1, "owner");
    assert_eq!(log.2, "owner");
    assert_eq!(log.3, "PASS");
}

#[tokio::test]
async fn test_cascade_delete_user_audit_log() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool.clone() };
    sqlx::query("INSERT INTO users (id, tier) VALUES (1, 'owner')")
        .execute(&pool)
        .await
        .unwrap();
    rbac.delete_user(1).await.unwrap();
    let logs: Vec<(String, Option<i32>, Option<String>, Option<String>, Option<String>, String, Option<String>, String)> = sqlx::query_as(
        r#"
        SELECT action, user_id, endpoint, required_tier, user_tier, decision, details, timestamp
        FROM audit_log
        WHERE action = 'user_deleted_cascade'
        "#
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(logs.len(), 1);
    let log = &logs[0];
    assert_eq!(log.0, "user_deleted_cascade");
    assert!(log.1.is_none());
    assert!(log.2.is_none());
    assert!(log.3.is_none());
    assert!(log.4.is_none());
    assert_eq!(log.5, "PASS");
    let details_json: Option<Value> = log.6.as_ref().and_then(|s| serde_json::from_str(s).ok());
    assert!(details_json.is_some());
    let details = details_json.unwrap();
    assert!(details.get("sessions").is_some());
    assert!(details.get("api_keys").is_some());
    assert!(details.get("files").is_some());
    assert!(details.get("preferences").is_some());
}

#[tokio::test]
async fn test_permission_check_response_time() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool };
    let user = User { id: 1, tier: Tier::Owner };
    let start = Instant::now();
    let _ = rbac.require_owner(Some(&user)).await;
    let duration = start.elapsed();
    assert!(duration.as_millis() < 10, "require_owner took {} ms", duration.as_millis());

    let start = Instant::now();
    let _ = rbac.require_admin(Some(&user)).await;
    let duration = start.elapsed();
    assert!(duration.as_millis() < 10, "require_admin took {} ms", duration.as_millis());

    let start = Instant::now();
    let _ = rbac.require_authenticated(Some(&user)).await;
    let duration = start.elapsed();
    assert!(duration.as_millis() < 10, "require_authenticated took {} ms", duration.as_millis());
}

#[tokio::test]
async fn test_error_response_fields() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool };
    let user = User { id: 1, tier: Tier::Admin };
    let err = rbac.require_owner(Some(&user)).await.unwrap_err();
    let (body, code) = err.to_response();
    let resp: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(resp["error"], "owner_only");
    assert_eq!(resp["message"], "Owner only access allowed");
    assert_eq!(resp["code"], 403);
    assert_eq!(code, 403);
}

#[tokio::test]
async fn test_audit_log_fields() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool.clone() };
    let user = User { id: 1, tier: Tier::Member };
    let _ = rbac.require_admin(Some(&user)).await;
    let logs: Vec<(String, Option<i32>, Option<String>, Option<String>, Option<String>, String, Option<String>, String)> = sqlx::query_as(
        r#"
        SELECT action, user_id, endpoint, required_tier, user_tier, decision, details, timestamp
        FROM audit_log
        WHERE action = 'permission_check'
        "#
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(logs.len(), 1);
    let log = &logs[0];
    assert_eq!(log.0, "permission_check");
    assert_eq!(log.1, Some(1));
    assert!(log.2.is_none());
    assert_eq!(log.3, Some("admin".to_string()));
    assert_eq!(log.4, Some("member".to_string()));
    assert_eq!(log.5, "FAIL");
    assert!(log.6.is_none());
    assert!(!log.7.is_empty());
}

/// Added 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP), spec "cascade on error -> rollback (no partial
/// deletes)": with the preferences table missing, delete_user fails part way and nothing is deleted.
#[tokio::test]
async fn test_cascade_delete_rolls_back_when_a_step_fails() {
    let pool = setup_db().await;
    let rbac = RbacSystem { db: pool.clone() };
    sqlx::query("INSERT INTO users (id, tier) VALUES (1, 'owner')").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO sessions (id, user_id) VALUES (1, 1)").execute(&pool).await.unwrap();
    sqlx::query("DROP TABLE preferences").execute(&pool).await.unwrap();
    assert!(rbac.delete_user(1).await.is_err());
    let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions").fetch_one(&pool).await.unwrap();
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users").fetch_one(&pool).await.unwrap();
    let cascades: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'user_deleted_cascade'").fetch_one(&pool).await.unwrap();
    assert_eq!((sessions, users, cascades), (1, 1, 0));
}

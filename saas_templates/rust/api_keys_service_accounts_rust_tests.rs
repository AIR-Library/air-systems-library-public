//! API keys tests (TIER 2 spec, system 5).
//! Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: every test connected to a Postgres server
//! and a Redis server (`DATABASE_URL`, `REDIS_URL`), so none could run without them; each now uses
//! `Database::new_in_memory()` (SQLite in memory) and the unused Postgres/Redis client imports are gone.
//! `get_usage_stats` takes the owning user (a key's usage is never read by id alone). Assertions are
//! unchanged; one spec test was added (old key stops after the rotation grace period).
//! Touches: memory only.
use super::*;
use uuid::Uuid;

#[tokio::test]
async fn test_create_key_with_scopes() {
    let db = Database::new_in_memory().await.unwrap();
    
    let user_id = Uuid::new_v4();
    
    let create_req = CreateApiKeyRequest {
        name: "Test Integration".to_string(),
        scopes: vec!["read:deployments".to_string(), "write:webhooks".to_string()],
        expires_at: Some("2026-12-31T23:59:59Z".to_string()),
        rate_limit: 1000,
    };
    
    let response = db.create_api_key(user_id, create_req).await.unwrap();
    
    assert!(!response.api_key_id.is_empty());
    assert!(response.key.starts_with("sk_live_"));
    assert_eq!(response.rate_limit, 1000);
    assert!(response.expires_at.is_some());
}

#[tokio::test]
async fn test_use_key_with_authorization_header() {
    let db = Database::new_in_memory().await.unwrap();
    
    let user_id = Uuid::new_v4();
    
    let create_req = CreateApiKeyRequest {
        name: "Test Integration".to_string(),
        scopes: vec!["read:deployments".to_string()],
        expires_at: None,
        rate_limit: 1000,
    };
    
    let create_response = db.create_api_key(user_id, create_req).await.unwrap();
    
    let result = db.use_api_key(&create_response.key, "/api/deployments", "GET").await;
    
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_revoke_key() {
    let db = Database::new_in_memory().await.unwrap();
    
    let user_id = Uuid::new_v4();
    
    let create_req = CreateApiKeyRequest {
        name: "Test Integration".to_string(),
        scopes: vec!["read:deployments".to_string()],
        expires_at: None,
        rate_limit: 1000,
    };
    
    let create_response = db.create_api_key(user_id, create_req).await.unwrap();
    let api_key_id = Uuid::parse_str(&create_response.api_key_id).unwrap();
    
    let revoke_response = db.revoke_api_key(api_key_id, user_id).await.unwrap();
    
    assert!(revoke_response.success);
    
    let result = db.use_api_key(&create_response.key, "/api/deployments", "GET").await;
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("API key is not active"));
}

#[tokio::test]
async fn test_rate_limit() {
    let db = Database::new_in_memory().await.unwrap();
    
    let user_id = Uuid::new_v4();
    
    let create_req = CreateApiKeyRequest {
        name: "Test Integration".to_string(),
        scopes: vec!["read:deployments".to_string()],
        expires_at: None,
        rate_limit: 2,
    };
    
    let create_response = db.create_api_key(user_id, create_req).await.unwrap();
    
    let result1 = db.use_api_key(&create_response.key, "/api/deployments", "GET").await;
    assert!(result1.is_ok());
    
    let result2 = db.use_api_key(&create_response.key, "/api/deployments", "GET").await;
    assert!(result2.is_ok());
    
    let result3 = db.use_api_key(&create_response.key, "/api/deployments", "GET").await;
    assert!(result3.is_err());
    assert!(result3.unwrap_err().to_string().contains("Rate limit exceeded"));
}

#[tokio::test]
async fn test_scope_check() {
    let db = Database::new_in_memory().await.unwrap();
    
    let user_id = Uuid::new_v4();
    
    let create_req = CreateApiKeyRequest {
        name: "Test Integration".to_string(),
        scopes: vec!["read:deployments".to_string()],
        expires_at: None,
        rate_limit: 1000,
    };
    
    let create_response = db.create_api_key(user_id, create_req).await.unwrap();
    
    let result = db.use_api_key(&create_response.key, "/api/deployments", "POST").await;
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("API key does not have permission"));
}

#[tokio::test]
async fn test_rotate_key() {
    let db = Database::new_in_memory().await.unwrap();
    
    let user_id = Uuid::new_v4();
    
    let create_req = CreateApiKeyRequest {
        name: "Test Integration".to_string(),
        scopes: vec!["read:deployments".to_string()],
        expires_at: None,
        rate_limit: 1000,
    };
    
    let create_response = db.create_api_key(user_id, create_req).await.unwrap();
    let api_key_id = Uuid::parse_str(&create_response.api_key_id).unwrap();
    
    let rotate_response = db.rotate_api_key(api_key_id, user_id).await.unwrap();
    
    assert!(!rotate_response.new_key.is_empty());
    assert!(rotate_response.new_key.starts_with("sk_live_"));
    assert!(!rotate_response.old_key_revoked_at.is_empty());
    assert!(!rotate_response.grace_period_ends_at.is_empty());
    
    let result = db.use_api_key(&rotate_response.new_key, "/api/deployments", "GET").await;
    
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_expired_key() {
    let db = Database::new_in_memory().await.unwrap();
    
    let user_id = Uuid::new_v4();
    
    let create_req = CreateApiKeyRequest {
        name: "Test Integration".to_string(),
        scopes: vec!["read:deployments".to_string()],
        expires_at: Some("2020-01-01T00:00:00Z".to_string()),
        rate_limit: 1000,
    };
    
    let create_response = db.create_api_key(user_id, create_req).await.unwrap();
    
    let result = db.use_api_key(&create_response.key, "/api/deployments", "GET").await;
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("API key is not active"));
}

#[tokio::test]
async fn test_usage_stats() {
    let db = Database::new_in_memory().await.unwrap();
    
    let user_id = Uuid::new_v4();
    
    let create_req = CreateApiKeyRequest {
        name: "Test Integration".to_string(),
        scopes: vec!["read:deployments".to_string(), "write:webhooks".to_string()],
        expires_at: None,
        rate_limit: 1000,
    };
    
    let create_response = db.create_api_key(user_id, create_req).await.unwrap();
    let api_key_id = Uuid::parse_str(&create_response.api_key_id).unwrap();
    
    db.use_api_key(&create_response.key, "/api/deployments", "GET").await.unwrap();
    db.use_api_key(&create_response.key, "/api/deployments", "GET").await.unwrap();
    db.use_api_key(&create_response.key, "/api/webhooks", "POST").await.unwrap();
    
    let stats = db.get_usage_stats(api_key_id, user_id, "2020-01-01T00:00:00Z", "2030-01-01T00:00:00Z").await.unwrap();
    
    assert_eq!(stats.api_key_id, api_key_id.to_string());
    assert_eq!(stats.total_requests, 3);
    assert!(stats.requests_by_endpoint.contains_key("GET /api/deployments"));
    assert_eq!(stats.requests_by_endpoint["GET /api/deployments"], 2);
    assert!(stats.requests_by_endpoint.contains_key("POST /api/webhooks"));
    assert_eq!(stats.requests_by_endpoint["POST /api/webhooks"], 1);
}

#[tokio::test]
async fn test_admin_audit() {
    let db = Database::new_in_memory().await.unwrap();
    
    let user_id = Uuid::new_v4();
    
    let create_req = CreateApiKeyRequest {
        name: "Test Integration".to_string(),
        scopes: vec!["read:deployments".to_string()],
        expires_at: None,
        rate_limit: 1000,
    };
    
    let create_response = db.create_api_key(user_id, create_req).await.unwrap();
    
    let admin_response = db.admin_list_api_keys(Some(user_id), Some("active".to_string())).await.unwrap();
    
    assert_eq!(admin_response.total, 1);
    assert_eq!(admin_response.keys[0].id.to_string(), create_response.api_key_id);
}

/// Added 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP), spec "Rotate: new key works, old key stops after
/// grace period": the old key still works 23 hours after rotation and is refused after 24 hours.
#[tokio::test]
async fn test_rotated_key_stops_after_grace_period() {
    let now = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(1_767_225_600));
    let clock = now.clone();
    let db = Database::new_in_memory()
        .await
        .unwrap()
        .with_clock(Box::new(move || chrono::DateTime::from_timestamp(clock.load(std::sync::atomic::Ordering::SeqCst), 0).unwrap()));
    let user_id = Uuid::new_v4();
    let create_req = CreateApiKeyRequest { name: "Rotating".to_string(), scopes: vec!["read:deployments".to_string()], expires_at: None, rate_limit: 1000 };
    let created = db.create_api_key(user_id, create_req).await.unwrap();
    let api_key_id = Uuid::parse_str(&created.api_key_id).unwrap();
    let rotated = db.rotate_api_key(api_key_id, user_id).await.unwrap();
    now.fetch_add(23 * 3600, std::sync::atomic::Ordering::SeqCst);
    assert!(db.use_api_key(&created.key, "/api/deployments", "GET").await.is_ok());
    now.fetch_add(3600, std::sync::atomic::Ordering::SeqCst);
    let err = db.use_api_key(&created.key, "/api/deployments", "GET").await.unwrap_err();
    assert!(err.to_string().contains("API key is not active"));
    assert!(db.use_api_key(&rotated.new_key, "/api/deployments", "GET").await.is_ok());
    // another user cannot revoke or read the key
    assert_eq!(db.revoke_api_key(api_key_id, Uuid::new_v4()).await.unwrap_err(), ApiKeyError::NotFound);
}

/// Added 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP), CodeRabbit review on PR 19: a key already in its
/// rotation grace period cannot be rotated again (409 `rotation_in_progress`), so the old key still
/// stops 24 hours after the FIRST rotation even if someone keeps asking to rotate it. The new key can
/// itself be rotated. Touches: memory only.
#[tokio::test]
async fn test_rotate_refuses_key_already_in_grace_period() {
    let now = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(1_767_225_600));
    let clock = now.clone();
    let db = Database::new_in_memory()
        .await
        .unwrap()
        .with_clock(Box::new(move || chrono::DateTime::from_timestamp(clock.load(std::sync::atomic::Ordering::SeqCst), 0).unwrap()));
    let user_id = Uuid::new_v4();
    let create_req = CreateApiKeyRequest { name: "Rotating".to_string(), scopes: vec!["read:deployments".to_string()], expires_at: None, rate_limit: 1000 };
    let created = db.create_api_key(user_id, create_req).await.unwrap();
    let api_key_id = Uuid::parse_str(&created.api_key_id).unwrap();
    let first = db.rotate_api_key(api_key_id, user_id).await.unwrap();

    // 12 hours later the old key is still in its grace period: a second rotation is refused.
    now.fetch_add(12 * 3600, std::sync::atomic::Ordering::SeqCst);
    let err = db.rotate_api_key(api_key_id, user_id).await.unwrap_err();
    assert_eq!(err, ApiKeyError::RotationInProgress);
    assert_eq!(err.status(), 409);
    assert!(err.to_string().contains("rotation_in_progress"));
    let keys = db.list_api_keys(user_id).await.unwrap().keys;
    assert_eq!(keys.len(), 2, "the refused rotation made no new key");

    // The grace period still ends 24 hours after the first rotation.
    now.fetch_add(12 * 3600, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(db.use_api_key(&created.key, "/api/deployments", "GET").await.unwrap_err(), ApiKeyError::NotActive);
    assert!(db.use_api_key(&first.new_key, "/api/deployments", "GET").await.is_ok());

    // The new key can be rotated in its turn.
    let new_id = Uuid::parse_str(&first.new_api_key_id).unwrap();
    assert!(db.rotate_api_key(new_id, user_id).await.is_ok());
}

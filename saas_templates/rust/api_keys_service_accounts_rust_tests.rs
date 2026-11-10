//! API keys tests (TIER 2 spec, system 5).
//! Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: every test connected to a Postgres server
//! and a Redis server (`DATABASE_URL`, `REDIS_URL`), so none could run without them; each now uses
//! `Database::new_in_memory()` (SQLite in memory) and the unused Postgres/Redis client imports are gone.
//! `get_usage_stats` takes the owning user (a key's usage is never read by id alone). Assertions are
//! unchanged; one spec test was added (old key stops after the rotation grace period).
//! Touches: memory only.
use super::*;
use uuid::Uuid;

// KEYS-01
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

// KEYS-02
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

/// What: see the spec id above; the status (401) is asserted. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory only.
// KEYS-03
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
    let err = result.unwrap_err();
    assert!(err.to_string().contains("API key is not active"));
    assert_eq!(err.status(), 401); // "return 401" (assertion added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
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

/// What: see the spec id above; the status (403) is asserted. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory only.
// KEYS-05
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
    let err = result.unwrap_err();
    assert!(err.to_string().contains("API key does not have permission"));
    assert_eq!(err.status(), 403); // "(403)" (assertion added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
}

// KEYS-06
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

/// What: see the spec id above; the status (401) is asserted. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory only.
// KEYS-07
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
    let err = result.unwrap_err();
    assert!(err.to_string().contains("API key is not active"));
    assert_eq!(err.status(), 401); // "returns 401" (assertion added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
}

// KEYS-08
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

/// What: see the spec id above; the status (403 for a non-admin) is asserted. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (the admin list takes the verified caller).
/// Touches: memory only.
// KEYS-09
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
    
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the admin list takes the verified caller; a
    // non-admin is refused 403, and an admin sees every user's keys
    let admin = Caller { user_id: Uuid::new_v4(), is_admin: true };
    let admin_response = db.admin_list_api_keys(&admin, Some(user_id), Some("active".to_string())).await.unwrap();
    
    assert_eq!(admin_response.total, 1);
    assert_eq!(admin_response.keys[0].id.to_string(), create_response.api_key_id);

    let other_user = Uuid::new_v4();
    let other_req = CreateApiKeyRequest { name: "Other".to_string(), scopes: vec!["read:deployments".to_string()], expires_at: None, rate_limit: 1000 };
    db.create_api_key(other_user, other_req).await.unwrap();
    assert_eq!(db.admin_list_api_keys(&admin, None, None).await.unwrap().total, 2);
    let not_admin = Caller { user_id, is_admin: false };
    assert_eq!(db.admin_list_api_keys(&not_admin, None, None).await.unwrap_err().status(), 403);
}

/// Added 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP), spec "Rotate: new key works, old key stops after
/// grace period": the old key still works 23 hours after rotation and is refused after 24 hours.
// KEYS-06
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

/// What: KEYS-04: with the default limit of 1,000 requests per hour, the 1,001st request in the hour is
/// refused with 429 (and is not counted as served); an hour after the first request the key works
/// again. In: none. Out: panics on a wrong answer. Why: the old rate-limit test used a limit of 2, not
/// the spec's 1,001st request. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
// KEYS-04
#[tokio::test]
async fn test_rate_limit_1001st_request_in_hour() {
    let now = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(1_767_225_600));
    let clock = now.clone();
    let db = Database::new_in_memory()
        .await
        .unwrap()
        .with_clock(Box::new(move || chrono::DateTime::from_timestamp(clock.load(std::sync::atomic::Ordering::SeqCst), 0).unwrap()));
    let user_id = Uuid::new_v4();
    let create_req = CreateApiKeyRequest { name: "Busy".to_string(), scopes: vec!["read:deployments".to_string()], expires_at: None, rate_limit: 1000 };
    let created = db.create_api_key(user_id, create_req).await.unwrap();
    for _ in 0..1000 {
        db.use_api_key(&created.key, "/api/deployments", "GET").await.unwrap();
    }
    now.fetch_add(3599, std::sync::atomic::Ordering::SeqCst);
    let err = db.use_api_key(&created.key, "/api/deployments", "GET").await.unwrap_err();
    assert_eq!(err, ApiKeyError::RateLimited);
    assert_eq!(err.status(), 429);
    now.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    assert!(db.use_api_key(&created.key, "/api/deployments", "GET").await.is_ok());
}

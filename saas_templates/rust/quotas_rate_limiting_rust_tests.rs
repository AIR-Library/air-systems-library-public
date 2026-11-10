//! Quotas and rate limiting tests (GEMINI spec, template #5).
//! Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: imports the `Row` trait and the month
//! helpers the tests call (they did not compile without them); the rate-limit, month-rollover and
//! tier-upgrade tests run at a fixed instant through the `_at` functions instead of the wall clock
//! (the 10-per-second IP test failed if 11 calls took over a second, and "now minus 30 days" is the
//! same month on the 31st). Unused imports (`sleep`, `StdDuration`) removed. Touches: in-memory SQLite.
use chrono::{TimeZone, Utc};
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};
use quotas_rate_limiting_rust::{
    check_api_quota, check_api_quota_at, check_feature_gate, check_rate_limit_per_ip_at,
    check_rate_limit_per_user_at, check_storage_quota, init_db, month_of, QuotaError, Tier, User,
};

/// What: a fixed instant (2026-03-31 12:00:00 UTC) for time-based tests. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn t0() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, 31, 12, 0, 0).unwrap()
}

async fn setup_pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(":memory:")
        .await
        .unwrap();
    init_db(&pool).await.unwrap();
    pool
}

#[tokio::test]
async fn api_quota_pass() {
    let pool = setup_pool().await;
    let user = User { id: 1, tier: Tier::Solo };
    // Ensure no prior usage
    check_api_quota(&pool, &user).await.unwrap();
    // Second call should also pass
    check_api_quota(&pool, &user).await.unwrap();
}

#[tokio::test]
async fn api_quota_fail() {
    let pool = setup_pool().await;
    let user = User { id: 2, tier: Tier::Solo };
    // Fill quota
    for _ in 0..1_000 {
        check_api_quota(&pool, &user).await.unwrap();
    }
    // Next call should fail
    let err = check_api_quota(&pool, &user).await.unwrap_err();
    match err {
        QuotaError::QuotaExceeded { current, limit, .. } => {
            assert_eq!(current, 1_000);
            assert_eq!(limit, 1_000);
        }
        _ => panic!("Unexpected error"),
    }
}

#[tokio::test]
async fn storage_quota_pass() {
    let pool = setup_pool().await;
    let user = User { id: 3, tier: Tier::Team };
    // Upload 50 GB
    check_storage_quota(&pool, &user, 50_000_000_000).await.unwrap();
    // Upload another 50 GB
    check_storage_quota(&pool, &user, 50_000_000_000).await.unwrap();
}

#[tokio::test]
async fn storage_quota_fail() {
    let pool = setup_pool().await;
    let user = User { id: 4, tier: Tier::Solo };
    // Upload 900 MB
    check_storage_quota(&pool, &user, 900_000_000).await.unwrap();
    // Upload 200 MB should fail
    let err = check_storage_quota(&pool, &user, 200_000_000).await.unwrap_err();
    match err {
        QuotaError::StorageQuotaExceeded { usage, limit } => {
            assert_eq!(usage, 900_000_000);
            assert_eq!(limit, 1_000_000_000);
        }
        _ => panic!("Unexpected error"),
    }
}

#[tokio::test]
async fn rate_limit_per_user_pass() {
    let pool = setup_pool().await;
    let user = User { id: 5, tier: Tier::Team };
    for _ in 0..99 {
        check_rate_limit_per_user_at(&pool, &user, t0()).await.unwrap();
    }
}

#[tokio::test]
async fn rate_limit_per_user_fail() {
    let pool = setup_pool().await;
    let user = User { id: 6, tier: Tier::Team };
    for _ in 0..100 {
        check_rate_limit_per_user_at(&pool, &user, t0()).await.unwrap();
    }
    let err = check_rate_limit_per_user_at(&pool, &user, t0()).await.unwrap_err();
    match err {
        QuotaError::RateLimitExceeded { reset_seconds } => {
            assert_eq!(reset_seconds, 60);
        }
        _ => panic!("Unexpected error"),
    }
}

#[tokio::test]
async fn rate_limit_per_ip_pass() {
    let pool = setup_pool().await;
    let ip = "192.168.1.1";
    for _ in 0..9 {
        check_rate_limit_per_ip_at(&pool, ip, t0()).await.unwrap();
    }
}

#[tokio::test]
async fn rate_limit_per_ip_fail() {
    let pool = setup_pool().await;
    let ip = "10.0.0.1";
    for _ in 0..10 {
        check_rate_limit_per_ip_at(&pool, ip, t0()).await.unwrap();
    }
    let err = check_rate_limit_per_ip_at(&pool, ip, t0()).await.unwrap_err();
    match err {
        QuotaError::IpRateLimitExceeded { reset_seconds } => {
            assert_eq!(reset_seconds, 1);
        }
        _ => panic!("Unexpected error"),
    }
}

#[tokio::test]
async fn feature_gate_pass() {
    let user = User { id: 7, tier: Tier::Team };
    check_feature_gate(&user, "feature_a").await.unwrap();
    check_feature_gate(&user, "feature_c").await.unwrap();
}

#[tokio::test]
async fn feature_gate_fail() {
    let user = User { id: 8, tier: Tier::Solo };
    let err = check_feature_gate(&user, "feature_a").await.unwrap_err();
    match err {
        QuotaError::FeatureNotAvailable { tier, minimum_tier, .. } => {
            assert_eq!(tier, Tier::Solo);
            assert_eq!(minimum_tier, Tier::Team);
        }
        _ => panic!("Unexpected error"),
    }
}

#[tokio::test]
async fn month_rollover() {
    let pool = setup_pool().await;
    let user = User { id: 9, tier: Tier::Solo };
    // Simulate usage in previous month
    let prev_month = "2026-02".to_string(); // the month before t0()
    sqlx::query(
        r#"
        INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
        VALUES (?, ?, 500, 0, ?)
        "#,
    )
    .bind(user.id)
    .bind(&prev_month)
    .bind(t0().to_rfc3339())
    .execute(&pool)
    .await
    .unwrap();

    // Current month usage should start at 0
    check_api_quota_at(&pool, &user, t0()).await.unwrap();
    let row = sqlx::query(
        r#"
        SELECT call_count FROM usage_metrics
        WHERE user_id = ? AND month = ?
        "#,
    )
    .bind(user.id)
    .bind(&month_of(t0()))
    .fetch_one(&pool)
    .await
    .unwrap();
    let count: i64 = row.get("call_count");
    assert_eq!(count, 1);
}

#[tokio::test]
async fn tier_upgrade() {
    let pool = setup_pool().await;
    let mut user = User { id: 10, tier: Tier::Solo };
    // Use up solo quota
    for _ in 0..1_000 {
        check_api_quota_at(&pool, &user, t0()).await.unwrap();
    }
    // Upgrade tier
    user.tier = Tier::Team;
    // Should now be able to exceed solo limit
    check_api_quota_at(&pool, &user, t0()).await.unwrap();
    // Verify usage count > 1_000
    let row = sqlx::query(
        r#"
        SELECT call_count FROM usage_metrics
        WHERE user_id = ? AND month = ?
        "#,
    )
    .bind(user.id)
    .bind(&month_of(t0()))
    .fetch_one(&pool)
    .await
    .unwrap();
    let count: i64 = row.get("call_count");
    assert!(count > 1_000);
}
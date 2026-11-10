//! Quotas and rate limiting by tier (GEMINI dispatch spec, template #5).
//!
//! What: monthly API-call quotas (Solo 1,000 / Team 10,000 / Enterprise unlimited), storage quotas
//! (1 GB / 100 GB / unlimited), a per-user limit of 100 requests per minute, a per-IP limit of 10 per
//! second, and feature gates by tier. Every check that admits a request also records it in the same
//! SQL statement, so two concurrent requests cannot both take the last unit.
//! Why: the old file did not compile against its tests (`current_month` was private, `Row` not in
//! scope), its rate-limit checks never recorded a request so they could never reject one, it turned
//! database errors into "quota exceeded 0/0", and quota checks were read-then-write races.
//! Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: the SQLite pool it is given (tables `usage_metrics`, `api_calls`, `rate_limit_hits`);
//! no network, no money.

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use sqlx::{Row, SqlitePool};
use std::fmt;

/// Per-user limit: requests per window (spec: 100 per minute, all tiers).
pub const USER_RATE_LIMIT: i64 = 100;
/// Per-user window in seconds.
pub const USER_RATE_WINDOW_SECS: u64 = 60;
/// Per-IP limit: requests per window (spec: 10 per second, all IPs).
pub const IP_RATE_LIMIT: i64 = 10;
/// Per-IP window in seconds.
pub const IP_RATE_WINDOW_SECS: u64 = 1;
/// The longest rate-limit window: any hit older than this can no longer count against any bucket, so
/// every limiter call deletes such hits, whatever their bucket (CodeRabbit review on PR 19,
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: one-time IPs used to leave their rows forever).
pub const LONGEST_RATE_WINDOW_SECS: u64 = if USER_RATE_WINDOW_SECS > IP_RATE_WINDOW_SECS { USER_RATE_WINDOW_SECS } else { IP_RATE_WINDOW_SECS };

/// The spec's "unlimited" limit value (QUOTA-13).
pub const UNLIMITED: i64 = -1;

/// What: a subscription tier. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    Solo,
    Team,
    Enterprise,
}

/// What: methods of `Tier`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl Tier {
    /// What: the tier's lowercase name. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Solo => "solo",
            Tier::Team => "team",
            Tier::Enterprise => "enterprise",
        }
    }

    /// What: (monthly API calls, storage bytes); -1 is unlimited, in every quota. Why: spec tier table,
    /// amended 2026-11-10 (QUOTA-13: "-1 means unlimited, in every quota"). Changed from `Option` (None =
    /// unlimited) to the spec's -1 the same day, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn limits(&self) -> (i64, i64) {
        match self {
            Tier::Solo => (1_000, 1_000_000_000),
            Tier::Team => (10_000, 100_000_000_000),
            Tier::Enterprise => (UNLIMITED, UNLIMITED),
        }
    }
}

/// What: the caller, as the server's own session resolved it (never taken from the request body).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub tier: Tier,
}

/// What: why a request was refused, with the spec's response fields; `Database` when the check itself
/// could not run (the request should then fail closed with a 500, not be reported as over quota).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug)]
pub enum QuotaError {
    QuotaExceeded { current: u64, limit: u64, reset_date: String },
    StorageQuotaExceeded { usage: u64, limit: u64 },
    RateLimitExceeded { reset_seconds: u64 },
    IpRateLimitExceeded { reset_seconds: u64 },
    FeatureNotAvailable { tier: Tier, minimum_tier: Tier, upgrade_url: String },
    Database(String),
}

/// What: methods of `QuotaError`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl QuotaError {
    /// What: the HTTP status for the error (429, 413, 403 or 500). Why: spec actions.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn http_status(&self) -> u16 {
        match self {
            QuotaError::QuotaExceeded { .. } | QuotaError::RateLimitExceeded { .. } | QuotaError::IpRateLimitExceeded { .. } => 429,
            QuotaError::StorageQuotaExceeded { .. } => 413,
            QuotaError::FeatureNotAvailable { .. } => 403,
            QuotaError::Database(_) => 500,
        }
    }
}

/// What: `fmt::Display` for `QuotaError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl fmt::Display for QuotaError {
    /// What: the spec's JSON error body. Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP, Phase B.2):
    /// the feature-gate refusal's code is feature_not_available_in_tier (was feature_not_available), the one
    /// name the quotas spec now gives in every language. Touches: nothing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuotaError::QuotaExceeded { current, limit, reset_date } => write!(
                f,
                "{{\"error\":\"quota_exceeded\",\"current\":{},\"limit\":{},\"reset_date\":\"{}\"}}",
                current, limit, reset_date
            ),
            QuotaError::StorageQuotaExceeded { usage, limit } => {
                write!(f, "{{\"error\":\"storage_quota_exceeded\",\"usage\":{},\"limit\":{}}}", usage, limit)
            }
            QuotaError::RateLimitExceeded { reset_seconds } => {
                write!(f, "{{\"error\":\"rate_limit_exceeded\",\"reset_seconds\":{}}}", reset_seconds)
            }
            QuotaError::IpRateLimitExceeded { reset_seconds } => {
                write!(f, "{{\"error\":\"ip_rate_limit_exceeded\",\"reset_seconds\":{}}}", reset_seconds)
            }
            QuotaError::FeatureNotAvailable { tier, minimum_tier, upgrade_url } => write!(
                f,
                "{{\"error\":\"feature_not_available_in_tier\",\"tier\":\"{}\",\"minimum_tier\":\"{}\",\"upgrade_url\":\"{}\"}}",
                tier.as_str(),
                minimum_tier.as_str(),
                upgrade_url
            ),
            QuotaError::Database(_) => write!(f, "{{\"error\":\"internal_error\"}}"),
        }
    }
}

/// What: `std::error::Error` for `QuotaError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl std::error::Error for QuotaError {}

/// What: a database error as `QuotaError::Database`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn db(e: sqlx::Error) -> QuotaError {
    QuotaError::Database(e.to_string())
}

/// What: create the tables. In: pool. Out: `()` or an error. Why: executable schema (spec tables plus
/// `rate_limit_hits` for the sliding windows; the `at_ms` index serves the all-bucket prune added for
/// the CodeRabbit review on PR 19). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: database (DDL).
pub async fn init_db(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    for ddl in [
        "CREATE TABLE IF NOT EXISTS usage_metrics (user_id INTEGER NOT NULL, month TEXT NOT NULL,
            call_count INTEGER NOT NULL DEFAULT 0, storage_bytes INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL, PRIMARY KEY (user_id, month))",
        "CREATE TABLE IF NOT EXISTS api_calls (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            ip TEXT NOT NULL, endpoint TEXT NOT NULL, timestamp TEXT NOT NULL, status_code INTEGER NOT NULL,
            response_time_ms INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS rate_limit_hits (id INTEGER PRIMARY KEY AUTOINCREMENT, bucket TEXT NOT NULL,
            at_ms INTEGER NOT NULL)",
        "CREATE INDEX IF NOT EXISTS rate_limit_hits_bucket ON rate_limit_hits (bucket, at_ms)",
        "CREATE INDEX IF NOT EXISTS rate_limit_hits_at ON rate_limit_hits (at_ms)",
    ] {
        sqlx::query(ddl).execute(pool).await?;
    }
    Ok(())
}

/// What: "YYYY-MM" of a time. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn month_of(now: DateTime<Utc>) -> String {
    format!("{}-{:02}", now.year(), now.month())
}

/// What: "YYYY-MM" of the current UTC month. Why: public so callers and tests name the same month
/// the checks use. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the clock.
pub fn current_month() -> String {
    month_of(Utc::now())
}

/// What: the first day of the next month, when monthly usage resets ("YYYY-MM-DD").
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn reset_date(now: DateTime<Utc>) -> String {
    let (y, m) = if now.month() == 12 { (now.year() + 1, 1) } else { (now.year(), now.month() + 1) };
    NaiveDate::from_ymd_opt(y, m, 1).map(|d| d.to_string()).unwrap_or_default()
}

/// What: admit one API call against the monthly quota at the current time. In: pool, user.
/// Out: `()` (usage incremented) or `QuotaExceeded`. Why: spec check 1.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, clock.
pub async fn check_api_quota(pool: &SqlitePool, user: &User) -> Result<(), QuotaError> {
    check_api_quota_at(pool, user, Utc::now()).await
}

/// What: admit one API call at `now`: one UPSERT increments this month's count only while it is below
/// the tier's limit (limits apply immediately after a tier change; a new month starts at 0). A limit of
/// -1 is unlimited: the call always passes and is still counted.
/// In: pool, user, time. Out: `()` or `QuotaExceeded { current, limit, reset_date }`.
/// Why: spec "PASS if limit == -1, else PASS if (current_usage + 1) <= limit", without a read-then-write
/// race; -1 handling amended 2026-11-10 (QUOTA-13). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: database (usage_metrics).
pub async fn check_api_quota_at(pool: &SqlitePool, user: &User, now: DateTime<Utc>) -> Result<(), QuotaError> {
    let month = month_of(now);
    let limit = user.tier.limits().0;
    if limit == UNLIMITED {
        sqlx::query(
            "INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at) VALUES (?1, ?2, 1, 0, ?3)
             ON CONFLICT (user_id, month) DO UPDATE SET call_count = MIN(call_count, 9223372036854775806) + 1, updated_at = excluded.updated_at",
        )
        .bind(user.id)
        .bind(&month)
        .bind(now.to_rfc3339())
        .execute(pool)
        .await
        .map_err(db)?;
        return Ok(());
    }
    let done = sqlx::query(
        "INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
         SELECT ?1, ?2, 1, 0, ?3 WHERE ?4 >= 1
         ON CONFLICT (user_id, month) DO UPDATE SET call_count = call_count + 1, updated_at = excluded.updated_at
         WHERE usage_metrics.call_count < ?4",
    )
    .bind(user.id)
    .bind(&month)
    .bind(now.to_rfc3339())
    .bind(limit)
    .execute(pool)
    .await
    .map_err(db)?;
    if done.rows_affected() == 1 {
        return Ok(());
    }
    let current: i64 = sqlx::query("SELECT call_count FROM usage_metrics WHERE user_id = ?1 AND month = ?2")
        .bind(user.id)
        .bind(&month)
        .fetch_optional(pool)
        .await
        .map_err(db)?
        .map(|r| r.get::<i64, _>("call_count"))
        .unwrap_or(0);
    Err(QuotaError::QuotaExceeded { current: current as u64, limit: limit as u64, reset_date: reset_date(now) })
}

/// What: reserve `incoming_size` bytes of storage at the current time. Why: spec check 2.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, clock.
pub async fn check_storage_quota(pool: &SqlitePool, user: &User, incoming_size: u64) -> Result<(), QuotaError> {
    check_storage_quota_at(pool, user, incoming_size, Utc::now()).await
}

/// What: reserve bytes only if the user's total stored bytes plus the new file stay within the tier
/// limit (one conditional UPSERT). A limit of -1 is unlimited: a file of any size is admitted and its
/// bytes recorded (saturating at the largest integer SQLite stores).
/// In: pool, user, size, time. Out: `()` or `StorageQuotaExceeded` with the usage before this file.
/// Why: spec "PASS if (current_storage + incoming_file_size) <= limit"; -1 handling amended 2026-11-10
/// (QUOTA-13). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (usage_metrics).
pub async fn check_storage_quota_at(pool: &SqlitePool, user: &User, incoming_size: u64, now: DateTime<Utc>) -> Result<(), QuotaError> {
    let limit = user.tier.limits().1;
    if limit == UNLIMITED {
        let size = i64::try_from(incoming_size).unwrap_or(i64::MAX);
        sqlx::query(
            "INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at) VALUES (?1, ?2, 0, ?3, ?4)
             ON CONFLICT (user_id, month) DO UPDATE SET storage_bytes = MIN(storage_bytes, 9223372036854775807 - ?3) + ?3,
                updated_at = excluded.updated_at",
        )
        .bind(user.id)
        .bind(month_of(now))
        .bind(size)
        .bind(now.to_rfc3339())
        .execute(pool)
        .await
        .map_err(db)?;
        return Ok(());
    }
    let size = i64::try_from(incoming_size).map_err(|_| QuotaError::StorageQuotaExceeded { usage: 0, limit: limit as u64 })?;
    let done = sqlx::query(
        "INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at)
         SELECT ?1, ?2, 0, ?3, ?4
         WHERE (SELECT COALESCE(SUM(storage_bytes), 0) FROM usage_metrics WHERE user_id = ?1) <= ?5 - ?3
         ON CONFLICT (user_id, month) DO UPDATE SET storage_bytes = storage_bytes + ?3, updated_at = excluded.updated_at",
    )
    .bind(user.id)
    .bind(month_of(now))
    .bind(size)
    .bind(now.to_rfc3339())
    .bind(limit)
    .execute(pool)
    .await
    .map_err(db)?;
    if done.rows_affected() == 1 {
        return Ok(());
    }
    let usage = storage_usage(pool, user).await?;
    Err(QuotaError::StorageQuotaExceeded { usage, limit: limit as u64 })
}

/// What: the user's total stored bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: database (read).
pub async fn storage_usage(pool: &SqlitePool, user: &User) -> Result<u64, QuotaError> {
    let row = sqlx::query("SELECT COALESCE(SUM(storage_bytes), 0) AS total FROM usage_metrics WHERE user_id = ?1")
        .bind(user.id)
        .fetch_one(pool)
        .await
        .map_err(db)?;
    Ok(row.get::<i64, _>("total").max(0) as u64)
}

/// What: give back bytes when a file is deleted. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: database (usage_metrics).
pub async fn release_storage(pool: &SqlitePool, user: &User, bytes: u64, now: DateTime<Utc>) -> Result<(), QuotaError> {
    let size = i64::try_from(bytes).unwrap_or(i64::MAX);
    sqlx::query(
        "INSERT INTO usage_metrics (user_id, month, call_count, storage_bytes, updated_at) VALUES (?1, ?2, 0, -?3, ?4)
         ON CONFLICT (user_id, month) DO UPDATE SET storage_bytes = storage_bytes - ?3, updated_at = excluded.updated_at",
    )
    .bind(user.id)
    .bind(month_of(now))
    .bind(size)
    .bind(now.to_rfc3339())
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(())
}

/// What: a sliding-window limiter: record a hit for `bucket` only if fewer than `limit` hits fall in
/// the last `window_secs`, in one statement. Before that it prunes: the bucket's own hits older than
/// its window, and every bucket's hits older than the longest window (`LONGEST_RATE_WINDOW_SECS`, or
/// this call's window if longer), so a hit is never deleted while it can still count and the per-bucket
/// count stays exact. In: pool, bucket, limit, window, time. Out: whether the hit was admitted.
/// Why: spec checks 3 and 4; the all-bucket prune was added for the CodeRabbit review on PR 19 (rows
/// of IPs seen once were never removed, so the table grew without bound).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (rate_limit_hits).
async fn admit(pool: &SqlitePool, bucket: &str, limit: i64, window_secs: u64, now: DateTime<Utc>) -> Result<bool, QuotaError> {
    let now_ms = now.timestamp_millis();
    let since = now_ms - (window_secs as i64) * 1000;
    let stale = now_ms - (window_secs.max(LONGEST_RATE_WINDOW_SECS) as i64) * 1000;
    sqlx::query("DELETE FROM rate_limit_hits WHERE at_ms <= ?1")
        .bind(stale)
        .execute(pool)
        .await
        .map_err(db)?;
    sqlx::query("DELETE FROM rate_limit_hits WHERE bucket = ?1 AND at_ms <= ?2")
        .bind(bucket)
        .bind(since)
        .execute(pool)
        .await
        .map_err(db)?;
    let done = sqlx::query(
        "INSERT INTO rate_limit_hits (bucket, at_ms) SELECT ?1, ?2
         WHERE (SELECT COUNT(*) FROM rate_limit_hits WHERE bucket = ?1 AND at_ms > ?3) < ?4",
    )
    .bind(bucket)
    .bind(now_ms)
    .bind(since)
    .bind(limit)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(done.rows_affected() == 1)
}

/// What: admit one request for the user (100 per minute). Why: spec check 3.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, clock.
pub async fn check_rate_limit_per_user(pool: &SqlitePool, user: &User) -> Result<(), QuotaError> {
    check_rate_limit_per_user_at(pool, user, Utc::now()).await
}

/// What: as `check_rate_limit_per_user`, at a given time. Out: `()` or `RateLimitExceeded
/// { reset_seconds: 60 }`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
pub async fn check_rate_limit_per_user_at(pool: &SqlitePool, user: &User, now: DateTime<Utc>) -> Result<(), QuotaError> {
    if admit(pool, &format!("user:{}", user.id), USER_RATE_LIMIT, USER_RATE_WINDOW_SECS, now).await? {
        Ok(())
    } else {
        Err(QuotaError::RateLimitExceeded { reset_seconds: USER_RATE_WINDOW_SECS })
    }
}

/// What: admit one request from the IP (10 per second). Why: spec check 4.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, clock.
pub async fn check_rate_limit_per_ip(pool: &SqlitePool, ip: &str) -> Result<(), QuotaError> {
    check_rate_limit_per_ip_at(pool, ip, Utc::now()).await
}

/// What: as `check_rate_limit_per_ip`, at a given time. Out: `()` or `IpRateLimitExceeded
/// { reset_seconds: 1 }`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
pub async fn check_rate_limit_per_ip_at(pool: &SqlitePool, ip: &str, now: DateTime<Utc>) -> Result<(), QuotaError> {
    if admit(pool, &format!("ip:{}", ip.trim()), IP_RATE_LIMIT, IP_RATE_WINDOW_SECS, now).await? {
        Ok(())
    } else {
        Err(QuotaError::IpRateLimitExceeded { reset_seconds: IP_RATE_WINDOW_SECS })
    }
}

/// What: the tiers allowed to use a feature, cheapest first; unknown features have none.
/// Why: spec feature table. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn allowed_tiers(feature: &str) -> &'static [Tier] {
    match feature {
        "feature_a" => &[Tier::Team, Tier::Enterprise],
        "feature_b" => &[Tier::Enterprise],
        "feature_c" => &[Tier::Solo, Tier::Team, Tier::Enterprise],
        _ => &[],
    }
}

/// What: may this user's tier use the feature? Unknown features are denied. In: user, feature.
/// Out: `()` or `FeatureNotAvailable` with the cheapest tier that has it and an upgrade hint.
/// Why: spec check 5. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub async fn check_feature_gate(user: &User, feature: &str) -> Result<(), QuotaError> {
    let tiers = allowed_tiers(feature);
    if tiers.contains(&user.tier) {
        return Ok(());
    }
    Err(QuotaError::FeatureNotAvailable {
        tier: user.tier,
        minimum_tier: tiers.first().copied().unwrap_or(Tier::Enterprise),
        upgrade_url: "/billing/upgrade".to_string(),
    })
}

/// What: log one finished API call (spec table `api_calls`). In: pool, user, IP, endpoint, status,
/// duration. Out: `()` or an error. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: database (api_calls), clock.
pub async fn record_api_call(
    pool: &SqlitePool,
    user: &User,
    ip: &str,
    endpoint: &str,
    status_code: u16,
    response_time_ms: u64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO api_calls (user_id, ip, endpoint, timestamp, status_code, response_time_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(user.id)
    .bind(ip)
    .bind(endpoint)
    .bind(Utc::now().to_rfc3339())
    .bind(status_code as i64)
    .bind(response_time_ms as i64)
    .execute(pool)
    .await
    .map(|_| ())
}

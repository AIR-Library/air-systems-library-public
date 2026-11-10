//! Permissions and RBAC: tier checks, cascading deletes and a permission audit log (GEMINI dispatch
//! spec, template #6).
//!
//! What: `RbacSystem` checks the tier hierarchy public < member < admin < owner (`require_owner`,
//! `require_admin`, `require_authenticated`), writes every check, pass or fail, to `audit_log`, and runs
//! the user, deployment and organization cascades inside one transaction each (the cascade's own audit
//! row included), so an error rolls the whole cascade back. The organization cascade (amended
//! 2026-11-10, RBAC-06, session_012zDydZCZ4AChqhEZ4oVtaP) is allowed only to an owner of that org (else
//! 404) and never deletes a user account, a session or a personal API key.
//! Why: the old file did not compile without a database at build time (`sqlx::query!` macros check SQL
//! against `DATABASE_URL` while compiling), `initialize_schema` was private although callers need it,
//! the users table had no `organization_id`, and the organization cascade deleted the users before
//! looking up their sessions and API keys through them, so those were never deleted.
//! Repaired 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: the SQLite pool it is given; the clock. No network, no money.

use sqlx::{Pool, Sqlite, SqlitePool, Transaction};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// What: the `Tier` enum. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub enum Tier {
    Public = 0,
    Member = 1,
    Admin = 2,
    Owner = 3,
}

/// What: methods of `Tier`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl Tier {
    /// What: `from_str` of `Tier`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "public" => Some(Tier::Public),
            "member" => Some(Tier::Member),
            "admin" => Some(Tier::Admin),
            "owner" => Some(Tier::Owner),
            _ => None,
        }
    }

    /// What: `to_str` of `Tier`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    pub fn to_str(&self) -> &'static str {
        match self {
            Tier::Public => "public",
            Tier::Member => "member",
            Tier::Admin => "admin",
            Tier::Owner => "owner",
        }
    }
}

#[derive(Debug, Clone)]
/// What: the `User` struct. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub struct User {
    pub id: i32,
    pub tier: Tier,
}

#[derive(Debug, Serialize, Deserialize)]
/// What: the `AuditLogEntry` struct. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub struct AuditLogEntry {
    pub action: String,
    pub user_id: Option<i32>,
    pub endpoint: Option<String>,
    pub required_tier: Option<String>,
    pub user_tier: Option<String>,
    pub decision: String,
    pub details: Option<serde_json::Value>,
    pub timestamp: String,
}

#[derive(Debug)]
/// What: the `RbacSystem` struct. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub struct RbacSystem {
    pub db: Pool<Sqlite>,
}

/// What: methods of `RbacSystem`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl RbacSystem {
    /// What: `new` of `RbacSystem`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    pub async fn new(db_url: &str) -> Result<Self, sqlx::Error> {
        let pool = SqlitePool::connect(db_url).await?;
        Self::initialize_schema(&pool).await?;
        Ok(RbacSystem { db: pool })
    }

    /// What: create the tables (users, their sessions/keys/files/preferences, organizations, their
    /// memberships (org_id, user_id, role) and invitations, deployments and their DNS/theme/log rows,
    /// audit_log). API keys carry a nullable org_id: NULL is a personal key. Changed 2026-11-10 (RBAC-06
    /// amendment): users no longer carry one organization_id, because a user may belong to several orgs. Public so callers sharing a pool can set it
    /// up. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (DDL).
    pub async fn initialize_schema(pool: &SqlitePool) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                tier TEXT NOT NULL CHECK (tier IN ('public', 'member', 'admin', 'owner'))
            );
            CREATE TABLE IF NOT EXISTS memberships (
                org_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
                PRIMARY KEY (org_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS invitations (
                id INTEGER PRIMARY KEY,
                org_id INTEGER NOT NULL,
                email TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                org_id INTEGER NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS preferences (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS deployments (
                id INTEGER PRIMARY KEY,
                organization_id INTEGER NOT NULL,
                FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS dns_records (
                id INTEGER PRIMARY KEY,
                deployment_id INTEGER NOT NULL,
                FOREIGN KEY (deployment_id) REFERENCES deployments(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS theme_configs (
                id INTEGER PRIMARY KEY,
                deployment_id INTEGER NOT NULL,
                FOREIGN KEY (deployment_id) REFERENCES deployments(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS deployment_logs (
                id INTEGER PRIMARY KEY,
                deployment_id INTEGER NOT NULL,
                FOREIGN KEY (deployment_id) REFERENCES deployments(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                user_id INTEGER,
                endpoint TEXT,
                required_tier TEXT,
                user_tier TEXT,
                decision TEXT NOT NULL,
                details TEXT,
                timestamp TEXT NOT NULL
            );
            "#,
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    /// What: allow only owners; logs the check. In: the caller (from the server's session, `None`
    /// when anonymous). Out: `()` or `OwnerOnly` (403). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (audit_log).
    pub async fn require_owner(&self, user: Option<&User>) -> Result<(), RbacError> {
        self.require_tier(user, Tier::Owner, RbacError::OwnerOnly).await
    }

    /// What: allow admins and owners; logs the check. Out: `()` or `AdminOnly` (403; anonymous callers
    /// get the same answer). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub async fn require_admin(&self, user: Option<&User>) -> Result<(), RbacError> {
        self.require_tier(user, Tier::Admin, RbacError::AdminOnly).await
    }

    /// What: compare the caller's tier with the required one, log PASS/FAIL, and deny on failure. If the
    /// audit row cannot be written the request is denied (fail closed). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (audit_log).
    async fn require_tier(&self, user: Option<&User>, required: Tier, denied: RbacError) -> Result<(), RbacError> {
        let user_tier = user.map(|u| u.tier).unwrap_or(Tier::Public);
        let pass = user_tier >= required;
        let decision = if pass { "PASS" } else { "FAIL" };
        self.log_audit(&self.db, "permission_check", user.map(|u| u.id), None, Some(required.to_str()), Some(user_tier.to_str()), decision, None)
            .await
            .map_err(|_| RbacError::Internal)?;
        if pass { Ok(()) } else { Err(denied) }
    }

    /// What: allow any signed-in caller; logs the check. Out: `()` or `AuthenticationRequired` (401).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (audit_log).
    pub async fn require_authenticated(&self, user: Option<&User>) -> Result<(), RbacError> {
        let decision = if user.is_some() { "PASS" } else { "FAIL" };
        self.log_audit(&self.db, "permission_check", user.map(|u| u.id), None, Some("member"), user.map(|u| u.tier.to_str()), decision, None)
            .await
            .map_err(|_| RbacError::Internal)?;
        if user.is_some() { Ok(()) } else { Err(RbacError::AuthenticationRequired) }
    }

    /// What: run one DELETE inside the transaction and return the rows removed.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    async fn delete(tx: &mut Transaction<'_, Sqlite>, sql: &str, id: i32) -> Result<u64, sqlx::Error> {
        Ok(sqlx::query(sql).bind(id).execute(&mut **tx).await?.rows_affected())
    }

    /// What: delete a user with their sessions, API keys, files and preferences, plus the
    /// `user_deleted_cascade` audit row, all in one transaction (rolled back on any error).
    /// In: user id. Out: `()`. Why: spec cascade rule. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database.
    pub async fn delete_user(&self, user_id: i32) -> Result<(), sqlx::Error> {
        let mut tx = self.db.begin().await?;
        let sessions = Self::delete(&mut tx, "DELETE FROM sessions WHERE user_id = ?", user_id).await?;
        let api_keys = Self::delete(&mut tx, "DELETE FROM api_keys WHERE user_id = ?", user_id).await?;
        let files = Self::delete(&mut tx, "DELETE FROM files WHERE user_id = ?", user_id).await?;
        let preferences = Self::delete(&mut tx, "DELETE FROM preferences WHERE user_id = ?", user_id).await?;
        let users = Self::delete(&mut tx, "DELETE FROM users WHERE id = ?", user_id).await?;
        let details = json!({ "user_id": user_id, "users": users, "sessions": sessions, "api_keys": api_keys, "files": files, "preferences": preferences });
        self.log_audit(&mut *tx, "user_deleted_cascade", None, None, None, None, "PASS", Some(details)).await?;
        tx.commit().await
    }

    /// What: delete a deployment with its DNS records, theme configs and logs, plus the
    /// `deployment_deleted_cascade` audit row, in one transaction. (Archiving to object storage is the
    /// caller's job before calling this.) 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub async fn delete_deployment(&self, deployment_id: i32) -> Result<(), sqlx::Error> {
        let mut tx = self.db.begin().await?;
        let dns = Self::delete(&mut tx, "DELETE FROM dns_records WHERE deployment_id = ?", deployment_id).await?;
        let themes = Self::delete(&mut tx, "DELETE FROM theme_configs WHERE deployment_id = ?", deployment_id).await?;
        let logs = Self::delete(&mut tx, "DELETE FROM deployment_logs WHERE deployment_id = ?", deployment_id).await?;
        let deployments = Self::delete(&mut tx, "DELETE FROM deployments WHERE id = ?", deployment_id).await?;
        let details = json!({ "deployment_id": deployment_id, "deployments": deployments, "dns_records": dns, "theme_configs": themes, "deployment_logs": logs });
        self.log_audit(&mut *tx, "deployment_deleted_cascade", None, None, None, None, "PASS", Some(details)).await?;
        tx.commit().await
    }

    /// What: delete an organization (RBAC-06, amended 2026-11-10). Gate: the caller's membership row for
    /// `org_id` has role 'owner'; otherwise `NotFound` (404), so a global admin or the owner of another org
    /// can neither delete it nor learn that it exists. Cascade, in one transaction with the audit row: its
    /// deployments with their DNS records, theme configs and logs; API keys whose org_id is this org; all
    /// its invitations; its membership rows; the organization row. NEVER a user account, a session or a
    /// personal API key (org_id NULL): a user may belong to several orgs, and deleting an account is
    /// `delete_user`. In: the verified caller (from the server's session, never from request input) and the
    /// org id. Out: deleted_items {deployments, api_keys, invitations, memberships, ...}, or `NotFound` /
    /// `Internal` (rolled back). Why: review on PR 19: the old cascade deleted every member's account
    /// and anyone could call it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub async fn delete_organization(&self, caller: &User, org_id: i32) -> Result<serde_json::Value, RbacError> {
        self.delete_organization_tx(caller, org_id).await.map_err(|e| match e {
            OrgDeleteError::NotFound => RbacError::NotFound,
            OrgDeleteError::Db(_) => RbacError::Internal,
        })
    }

    /// What: the transaction behind `delete_organization`; any error drops the transaction, which rolls
    /// it back. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    async fn delete_organization_tx(&self, caller: &User, org_id: i32) -> Result<serde_json::Value, OrgDeleteError> {
        let mut tx = self.db.begin().await?;
        let role: Option<String> = sqlx::query_scalar("SELECT role FROM memberships WHERE org_id = ? AND user_id = ?")
            .bind(org_id)
            .bind(caller.id)
            .fetch_optional(&mut *tx)
            .await?;
        if role.as_deref() != Some("owner") {
            return Err(OrgDeleteError::NotFound);
        }
        let of_deployments = "IN (SELECT id FROM deployments WHERE organization_id = ?)";
        let dns = Self::delete(&mut tx, &format!("DELETE FROM dns_records WHERE deployment_id {}", of_deployments), org_id).await?;
        let themes = Self::delete(&mut tx, &format!("DELETE FROM theme_configs WHERE deployment_id {}", of_deployments), org_id).await?;
        let logs = Self::delete(&mut tx, &format!("DELETE FROM deployment_logs WHERE deployment_id {}", of_deployments), org_id).await?;
        let deployments = Self::delete(&mut tx, "DELETE FROM deployments WHERE organization_id = ?", org_id).await?;
        let api_keys = Self::delete(&mut tx, "DELETE FROM api_keys WHERE org_id = ?", org_id).await?;
        let invitations = Self::delete(&mut tx, "DELETE FROM invitations WHERE org_id = ?", org_id).await?;
        let memberships = Self::delete(&mut tx, "DELETE FROM memberships WHERE org_id = ?", org_id).await?;
        let organizations = Self::delete(&mut tx, "DELETE FROM organizations WHERE id = ?", org_id).await?;
        let details = json!({ "org_id": org_id, "deployments": deployments, "api_keys": api_keys, "invitations": invitations,
            "memberships": memberships, "organizations": organizations, "dns_records": dns, "theme_configs": themes, "deployment_logs": logs });
        self.log_audit(&mut *tx, "org_deleted_cascade", Some(caller.id), None, None, None, "PASS", Some(details.clone())).await?;
        tx.commit().await?;
        Ok(details)
    }

    /// What: append one audit row through any executor (the pool, or a cascade's transaction).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (audit_log), clock.
    #[allow(clippy::too_many_arguments)]
    async fn log_audit<'e, E>(
        &self,
        executor: E,
        action: &str,
        user_id: Option<i32>,
        endpoint: Option<String>,
        required_tier: Option<&str>,
        user_tier: Option<&str>,
        decision: &str,
        details: Option<serde_json::Value>,
    ) -> Result<(), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = Sqlite>,
    {
        sqlx::query(
            "INSERT INTO audit_log (action, user_id, endpoint, required_tier, user_tier, decision, details, timestamp)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(action)
        .bind(user_id)
        .bind(endpoint)
        .bind(required_tier)
        .bind(user_tier)
        .bind(decision)
        .bind(details.map(|d| d.to_string()))
        .bind(Utc::now().to_rfc3339())
        .execute(executor)
        .await?;
        Ok(())
    }
}

/// What: why the organization cascade stopped (internal to `delete_organization`).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug)]
enum OrgDeleteError {
    NotFound,
    Db(sqlx::Error),
}

/// What: `From<sqlx::Error>` for `OrgDeleteError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
impl From<sqlx::Error> for OrgDeleteError {
    /// What: wrap a database error. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn from(e: sqlx::Error) -> Self {
        OrgDeleteError::Db(e)
    }
}

/// What: why access was refused; `Internal` when the audit row could not be written (fail closed) or a
/// cascade failed and was rolled back; `NotFound` (added 2026-11-10, RBAC-06) when the caller is not an
/// owner of the organization. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RbacError {
    OwnerOnly,
    AdminOnly,
    AuthenticationRequired,
    NotFound,
    Internal,
}

/// What: methods of `RbacError`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl RbacError {
    /// What: the spec's error body and HTTP status. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn to_response(&self) -> (String, u16) {
        match self {
            RbacError::OwnerOnly => (
                json!({
                    "error": "owner_only",
                    "message": "Owner only access allowed",
                    "code": 403
                })
                .to_string(),
                403,
            ),
            RbacError::AdminOnly => (
                json!({
                    "error": "admin_only",
                    "message": "Admin or owner access required",
                    "code": 403
                })
                .to_string(),
                403,
            ),
            RbacError::AuthenticationRequired => (
                json!({
                    "error": "authentication_required",
                    "message": "Authentication required",
                    "code": 401
                })
                .to_string(),
                401,
            ),
            RbacError::NotFound => (
                json!({
                    "error": "not_found",
                    "message": "Not found",
                    "code": 404
                })
                .to_string(),
                404,
            ),
            RbacError::Internal => (
                json!({
                    "error": "internal_error",
                    "message": "Permission check could not be recorded",
                    "code": 500
                })
                .to_string(),
                500,
            ),
        }
    }
}

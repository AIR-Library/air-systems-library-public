//! Admin system: owner-gated user, customer, deployment and governance actions with an audit log
//! (GEMINI dispatch spec, template #2; docs/SPEC_auth_admin_trial_abuse.md part 2).
//!
//! What: `AdminSystem` runs the spec's admin actions on SQLite. Mutations require an active owner,
//! reads an active admin or owner (the admin tier is the user's `tier`: enterprise = owner,
//! premium = admin, basic = user, as in the spec's "change_role(user_id, new_tier)"). Safety rules:
//! nobody can suspend, reset or change themselves, the last active owner can never be demoted,
//! suspended, reset or deleted, refunds are only queued, plan changes go through the payment provider,
//! publishing needs a verified domain and the publish safety flag, and governance approvals execute
//! the approved action. Every mutation writes its audit row in the same transaction.
//! Why: the old file did not compile (`NO_PARAMS` is gone from the SQLite crate, private helpers the
//! tests call, an enum used as a struct), its "CSRF check" always passed, and it decided ownership from
//! a billing tier without saying so. Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: the SQLite database it owns; money through `StripeClient` (plan changes; refunds are
//! only queued); email through `Mailer`; domain checks through `DomainVerifier`; OS randomness.
//! CSRF tokens are checked by the HTTP layer before these methods are called.

use chrono::Utc;
use rand::RngCore;
pub use rusqlite::params;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;

/// What: the user tiers; for admin purposes enterprise is owner, premium admin, basic user.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Basic,
    Premium,
    Enterprise,
}

/// What: methods of `Tier`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl Tier {
    /// What: the stored name. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Basic => "basic",
            Tier::Premium => "premium",
            Tier::Enterprise => "enterprise",
        }
    }
    /// What: parse a tier name, or `Validation("invalid_tier")`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn parse(s: &str) -> AdminResult<Tier> {
        match s {
            "basic" => Ok(Tier::Basic),
            "premium" => Ok(Tier::Premium),
            "enterprise" => Ok(Tier::Enterprise),
            _ => Err(AdminError::Validation("invalid_tier".into())),
        }
    }
}

/// What: an admin-side user. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub name: String,
    pub tier: Tier,
    pub status: String,
    pub created_at: String,
}

/// What: methods of `User`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl User {
    /// What: may this user run owner-only actions? Active and enterprise tier. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn is_owner(&self) -> bool {
        self.status == "active" && self.tier == Tier::Enterprise
    }
    /// What: may this user run read-only admin actions? Active and premium or enterprise.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn is_admin_or_owner(&self) -> bool {
        self.status == "active" && self.tier >= Tier::Premium
    }
}

/// What: admin errors. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminError {
    Forbidden(String),
    NotFound(String),
    Validation(String),
    Conflict(String),
    Internal(String),
}

/// What: `std::fmt::Display` for `AdminError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl std::fmt::Display for AdminError {
    /// What: human-readable text of `std::fmt::Display for AdminError` (never secrets). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminError::Forbidden(m) => write!(f, "forbidden: {}", m),
            AdminError::NotFound(m) => write!(f, "not found: {}", m),
            AdminError::Validation(m) => write!(f, "invalid: {}", m),
            AdminError::Conflict(m) => write!(f, "conflict: {}", m),
            AdminError::Internal(_) => write!(f, "internal error"),
        }
    }
}

/// What: `std::error::Error` for `AdminError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl std::error::Error for AdminError {}

/// What: `From<rusqlite::Error>` for `AdminError`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl From<rusqlite::Error> for AdminError {
    /// What: convert the error of `From<rusqlite::Error> for AdminError`, keeping its message for logs. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn from(e: rusqlite::Error) -> Self {
        AdminError::Internal(e.to_string())
    }
}

/// Result type of the admin system.
pub type AdminResult<T> = Result<T, AdminError>;

/// What: the success part of a response. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SuccessBody {
    pub success: bool,
    pub data: Value,
}

/// What: the spec's `{success: true, ...}` or `{error, message}` response. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(untagged)]
pub enum Response {
    Success { success: bool, data: Value },
    Error { error: String, message: String },
}

/// What: methods of `Response`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl Response {
    /// What: a success. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn success(data: Value) -> Self {
        Response::Success { success: true, data }
    }
    /// What: an error with a code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn error(code: &str, message: &str) -> Self {
        Response::Error { error: code.to_string(), message: message.to_string() }
    }
    /// What: map an `AdminError` to a response code (`owner_only`, `not_found`, ...). Internal
    /// details are never shown. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn from_error(e: AdminError) -> Self {
        match e {
            AdminError::Forbidden(code) | AdminError::Validation(code) | AdminError::Conflict(code) => Response::error(&code, &code.replace('_', " ")),
            AdminError::NotFound(what) => Response::error("not_found", &format!("{} not found", what)),
            AdminError::Internal(_) => Response::error("internal_error", "internal error"),
        }
    }
    /// What: the success body, panicking with the error otherwise (for tests and scripts).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn unwrap(self) -> SuccessBody {
        match self {
            Response::Success { success, data } => SuccessBody { success, data },
            Response::Error { error, message } => panic!("admin action failed: {} ({})", error, message),
        }
    }
    /// What: is this a success? 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn is_success(&self) -> bool {
        matches!(self, Response::Success { .. })
    }
}

/// What: the payment provider client for plan changes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: money and the network in a real implementation (key from STRIPE_SECRET_KEY).
pub trait StripeClient {
    /// What: `update_subscription` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn update_subscription(&self, stripe_id: &str, price_id: &str) -> AdminResult<()>;
}

/// What: checks that a deployment's domain points at us (DNS TXT record, HTTP token, ...).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: network in a real implementation.
pub trait DomainVerifier {
    /// What: `is_verified` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn is_verified(&self, domain: &str) -> bool;
}

/// What: the default verifier: verifies nothing, so nothing publishes until a real one is set.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
pub struct NoDomainVerifier;

/// What: `DomainVerifier` for `NoDomainVerifier`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl DomainVerifier for NoDomainVerifier {
    /// What: `is_verified` of `DomainVerifier for NoDomainVerifier`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn is_verified(&self, _domain: &str) -> bool {
        false
    }
}

/// What: global safety switches (the spec's "SafetyFlags.can_publish" double gate).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafetyFlags {
    pub can_publish: bool,
}

/// What: one email the system sent (invites, reset links). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// Tier name -> the provider's price id (placeholders; set real ids from configuration).
pub fn default_price_ids() -> HashMap<String, String> {
    [("basic", "price_basic"), ("premium", "price_premium"), ("enterprise", "price_enterprise")].iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
}

/// What: the admin system. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: see module doc.
pub struct AdminSystem {
    conn: Connection,
    stripe: Box<dyn StripeClient>,
    domains: Box<dyn DomainVerifier>,
    price_ids: HashMap<String, String>,
    pub safety: SafetyFlags,
    outbox: RefCell<Vec<Email>>,
    base_url: String,
}

/// What: `n` random bytes as hex. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: OS randomness.
fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// What: now, RFC 3339 UTC. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn now() -> String {
    Utc::now().to_rfc3339()
}

/// What: basic email shape check (one @, a dot in the domain, no spaces, <= 254).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else { return false };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.') && !email.contains(char::is_whitespace) && !domain.contains('@') && email.len() <= 254
}

/// What: a lowercase DNS name with at least one dot. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn valid_domain(d: &str) -> bool {
    d.len() <= 253 && d.contains('.') && d.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
}

/// What: methods of `AdminSystem`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl AdminSystem {
    /// What: an admin system on a connection with a payment client; no domain is verified and
    /// publishing is allowed by the safety flag until changed. Call `init_schema` next.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing yet.
    pub fn new(conn: Connection, stripe: Box<dyn StripeClient>) -> Self {
        Self {
            conn,
            stripe,
            domains: Box::new(NoDomainVerifier),
            price_ids: default_price_ids(),
            safety: SafetyFlags { can_publish: true },
            outbox: RefCell::new(Vec::new()),
            base_url: "https://app.example.com".into(),
        }
    }

    /// What: set the domain verifier. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn with_domain_verifier(mut self, v: Box<dyn DomainVerifier>) -> Self {
        self.domains = v;
        self
    }

    /// What: emails sent so far (a mailer in production reads this queue). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn sent_emails(&self) -> Vec<Email> {
        self.outbox.borrow().clone()
    }

    /// What: create the tables. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (DDL).
    pub fn init_schema(&self) -> AdminResult<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
                tier TEXT NOT NULL CHECK (tier IN ('basic','premium','enterprise')), status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS password_resets (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at TEXT NOT NULL, used_at TEXT NULL);
             CREATE TABLE IF NOT EXISTS customers (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, name TEXT NOT NULL, tier TEXT NOT NULL,
                signup_date TEXT NOT NULL, invoice_count INTEGER NOT NULL, status TEXT NOT NULL, stripe_subscription_id TEXT NULL,
                subscription_status TEXT NULL, payment_method TEXT NULL, address TEXT NULL, notes TEXT NULL);
             CREATE TABLE IF NOT EXISTS invoices (id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id INTEGER NULL, amount INTEGER NOT NULL, status TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS deployments (id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id INTEGER NOT NULL REFERENCES customers(id), domain TEXT NOT NULL,
                tier TEXT NOT NULL, status TEXT NOT NULL, theme TEXT NOT NULL, config TEXT NOT NULL, domain_verified INTEGER NOT NULL DEFAULT 0,
                published_at TEXT NULL, suspend_reason TEXT NULL, archived_at TEXT NULL);
             CREATE TABLE IF NOT EXISTS governance_actions (id INTEGER PRIMARY KEY AUTOINCREMENT, action_type TEXT NOT NULL, actor_id INTEGER NOT NULL,
                target_resource_id INTEGER NOT NULL, reason TEXT, submitted_at TEXT NOT NULL, status TEXT NOT NULL, approved_by INTEGER,
                approved_at TEXT, rejection_reason TEXT, execution_result TEXT);
             CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, actor_id INTEGER NOT NULL,
                resource_type TEXT NOT NULL, resource_id INTEGER NOT NULL, old_value TEXT, new_value TEXT, reason TEXT, timestamp TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS refunds (id INTEGER PRIMARY KEY AUTOINCREMENT, invoice_id INTEGER NOT NULL, amount INTEGER NOT NULL,
                reason TEXT NOT NULL, created_by INTEGER NOT NULL, created_at TEXT NOT NULL, status TEXT NOT NULL);",
        )?;
        Ok(())
    }

    /// What: re-read the caller and require an active owner (never trust the passed-in struct's tier).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
    fn require_owner(&self, current: &User) -> AdminResult<User> {
        let me = self.get_user_by_id(current.id).map_err(|_| AdminError::Forbidden("owner_only".into()))?;
        if me.is_owner() { Ok(me) } else { Err(AdminError::Forbidden("owner_only".into())) }
    }

    /// What: re-read the caller and require an active admin or owner. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
    fn require_admin_or_owner(&self, current: &User) -> AdminResult<User> {
        let me = self.get_user_by_id(current.id).map_err(|_| AdminError::Forbidden("admin_only".into()))?;
        if me.is_admin_or_owner() { Ok(me) } else { Err(AdminError::Forbidden("admin_only".into())) }
    }

    /// What: write one audit row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    #[allow(clippy::too_many_arguments)]
    fn audit(conn: &Connection, action: &str, actor: i64, resource_type: &str, resource_id: i64, old: Option<Value>, new: Option<Value>, reason: Option<&str>) -> AdminResult<()> {
        conn.execute(
            "INSERT INTO audit_logs (action, actor_id, resource_type, resource_id, old_value, new_value, reason, timestamp) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![action, actor, resource_type, resource_id, old.map(|v| v.to_string()), new.map(|v| v.to_string()), reason, now()],
        )?;
        Ok(())
    }

    /// What: map a user row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn user_row(r: &rusqlite::Row) -> rusqlite::Result<User> {
        let tier: String = r.get(3)?;
        Ok(User { id: r.get(0)?, email: r.get(1)?, name: r.get(2)?, tier: Tier::parse(&tier).unwrap_or(Tier::Basic), status: r.get(4)?, created_at: r.get(5)? })
    }

    /// What: a user by id, or `NotFound`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub fn get_user_by_id(&self, id: i64) -> AdminResult<User> {
        self.conn
            .query_row("SELECT id, email, name, tier, status, created_at FROM users WHERE id = ?1", params![id], Self::user_row)
            .optional()?
            .ok_or_else(|| AdminError::NotFound("user".into()))
    }

    /// What: a user by email (case-insensitive). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database.
    pub fn get_user_by_email(&self, email: &str) -> AdminResult<Option<User>> {
        Ok(self
            .conn
            .query_row("SELECT id, email, name, tier, status, created_at FROM users WHERE email = ?1", params![email.trim().to_lowercase()], Self::user_row)
            .optional()?)
    }

    /// What: number of active owners. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn active_owner_count(&self) -> AdminResult<i64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM users WHERE tier = 'enterprise' AND status = 'active'", [], |r| r.get(0))?)
    }

    /// What: is this user the last active owner? 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn is_last_active_owner(&self, u: &User) -> AdminResult<bool> {
        Ok(u.is_owner() && self.active_owner_count()? <= 1)
    }

    /// What: users action=create. Gates: owner, valid email/name/tier, unique email. Creates an
    /// active user and (if `notify`) queues an invite email. Out: `{user_id, email, tier, created_at}`
    /// or `email_exists`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, email.
    pub fn create_user(&self, current: &User, email: &str, name: &str, tier: &str, notify: bool) -> Response {
        let run = || -> AdminResult<Value> {
            let me = self.require_owner(current)?;
            let email = email.trim().to_lowercase();
            if !valid_email(&email) {
                return Err(AdminError::Validation("invalid_email".into()));
            }
            let name = name.trim();
            if name.chars().count() < 2 || name.chars().count() > 100 {
                return Err(AdminError::Validation("invalid_name".into()));
            }
            let tier = Tier::parse(tier)?;
            if self.get_user_by_email(&email)?.is_some() {
                return Err(AdminError::Conflict("email_exists".into()));
            }
            let ts = now();
            let tx = self.conn.unchecked_transaction()?;
            tx.execute("INSERT INTO users (email, name, tier, status, created_at, updated_at) VALUES (?1, ?2, ?3, 'active', ?4, ?4)", params![email, name, tier.as_str(), ts])?;
            let id = tx.last_insert_rowid();
            Self::audit(&tx, "user_created", me.id, "user", id, None, Some(json!({ "email": email, "tier": tier.as_str() })), None)?;
            tx.commit()?;
            if notify {
                self.outbox.borrow_mut().push(Email { to: email.clone(), subject: "You have been invited".into(), body: format!("Sign in at {}/login", self.base_url) });
            }
            Ok(json!({ "user_id": id, "email": email, "tier": tier.as_str(), "created_at": ts }))
        };
        run().map(Response::success).unwrap_or_else(Response::from_error)
    }

    /// What: users action=reset_password. Gates: owner, not yourself, target exists, not the last
    /// active owner. Stores the SHA-256 of a random token (1 hour) and emails the link; the password
    /// itself is never seen. Out: `{status: "reset_email_sent"}`. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, email.
    pub fn reset_password(&self, current: &User, user_id: i64) -> Response {
        let run = || -> AdminResult<Value> {
            let me = self.require_owner(current)?;
            if user_id == me.id {
                return Err(AdminError::Validation("cannot_reset_own_password".into()));
            }
            let target = self.get_user_by_id(user_id)?;
            if self.is_last_active_owner(&target)? {
                return Err(AdminError::Validation("cannot_reset_last_owner".into()));
            }
            let token = random_hex(32);
            let hash: String = Sha256::digest(token.as_bytes()).iter().map(|b| format!("{:02x}", b)).collect();
            let tx = self.conn.unchecked_transaction()?;
            tx.execute(
                "INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES (?1, ?2, ?3)",
                params![hash, user_id, (Utc::now() + chrono::Duration::hours(1)).to_rfc3339()],
            )?;
            Self::audit(&tx, "password_reset_initiated", me.id, "user", user_id, None, None, None)?;
            tx.commit()?;
            self.outbox.borrow_mut().push(Email { to: target.email, subject: "Reset your password".into(), body: format!("{}/reset?token={}", self.base_url, token) });
            Ok(json!({ "status": "reset_email_sent" }))
        };
        run().map(Response::success).unwrap_or_else(Response::from_error)
    }

    /// What: users action=change_role (tier). Gates: owner, valid tier, the last active owner cannot be
    /// demoted, nobody changes their own role. Out: `{user_id, old_tier, new_tier}`. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub fn change_role(&self, current: &User, user_id: i64, new_tier: &str) -> Response {
        let run = || -> AdminResult<Value> {
            let me = self.require_owner(current)?;
            let new_tier = Tier::parse(new_tier)?;
            let target = self.get_user_by_id(user_id)?;
            if self.is_last_active_owner(&target)? && new_tier != Tier::Enterprise {
                return Err(AdminError::Validation("cannot_demote_last_owner".into()));
            }
            if user_id == me.id {
                return Err(AdminError::Validation("cannot_change_own_role".into()));
            }
            let tx = self.conn.unchecked_transaction()?;
            tx.execute("UPDATE users SET tier = ?1, updated_at = ?2 WHERE id = ?3", params![new_tier.as_str(), now(), user_id])?;
            Self::audit(&tx, "role_changed", me.id, "user", user_id, Some(json!({ "tier": target.tier.as_str() })), Some(json!({ "tier": new_tier.as_str() })), None)?;
            tx.commit()?;
            Ok(json!({ "user_id": user_id, "old_tier": target.tier.as_str(), "new_tier": new_tier.as_str() }))
        };
        run().map(Response::success).unwrap_or_else(Response::from_error)
    }

    /// What: users action=suspend. Gates: owner, not yourself, not the last active owner, a reason.
    /// Out: `{user_id, suspended: true}`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub fn suspend_user(&self, current: &User, user_id: i64, reason: &str) -> Response {
        let run = || -> AdminResult<Value> {
            let me = self.require_owner(current)?;
            if user_id == me.id {
                return Err(AdminError::Validation("cannot_suspend_yourself".into()));
            }
            if reason.trim().is_empty() {
                return Err(AdminError::Validation("reason_required".into()));
            }
            let target = self.get_user_by_id(user_id)?;
            if self.is_last_active_owner(&target)? {
                return Err(AdminError::Validation("cannot_suspend_last_owner".into()));
            }
            let tx = self.conn.unchecked_transaction()?;
            tx.execute("UPDATE users SET status = 'suspended', updated_at = ?1 WHERE id = ?2", params![now(), user_id])?;
            Self::audit(&tx, "user_suspended", me.id, "user", user_id, Some(json!({ "status": target.status })), Some(json!({ "status": "suspended" })), Some(reason))?;
            tx.commit()?;
            Ok(json!({ "user_id": user_id, "suspended": true }))
        };
        run().map(Response::success).unwrap_or_else(Response::from_error)
    }

    /// What: customers list, page from 1, 1-100 per page, oldest first. Gate: admin or owner.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
    pub fn list_customers(&self, current: &User, page: i64, per_page: i64) -> Response {
        let run = || -> AdminResult<Value> {
            self.require_admin_or_owner(current)?;
            let per = per_page.clamp(1, 100);
            let offset = (page.max(1) - 1) * per;
            let mut stmt = self.conn.prepare(
                "SELECT id, email, name, tier, signup_date, invoice_count, status FROM customers ORDER BY id LIMIT ?1 OFFSET ?2",
            )?;
            let rows = stmt
                .query_map(params![per, offset], |r| {
                    Ok(json!({ "customer_id": r.get::<_, i64>(0)?, "email": r.get::<_, String>(1)?, "name": r.get::<_, String>(2)?,
                        "tier": r.get::<_, String>(3)?, "signup_date": r.get::<_, String>(4)?, "invoice_count": r.get::<_, i64>(5)?, "status": r.get::<_, String>(6)? }))
                })?
                .collect::<rusqlite::Result<Vec<Value>>>()?;
            Ok(Value::Array(rows))
        };
        run().map(Response::success).unwrap_or_else(Response::from_error)
    }

    /// What: one customer with every detail field. Gate: admin or owner. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
    pub fn get_customer(&self, current: &User, customer_id: i64) -> Response {
        let run = || -> AdminResult<Value> {
            self.require_admin_or_owner(current)?;
            self.conn
                .query_row(
                    "SELECT id, email, name, tier, subscription_status, payment_method, address, notes, status FROM customers WHERE id = ?1",
                    params![customer_id],
                    |r| {
                        Ok(json!({ "customer_id": r.get::<_, i64>(0)?, "email": r.get::<_, String>(1)?, "name": r.get::<_, String>(2)?,
                            "tier": r.get::<_, String>(3)?, "subscription_status": r.get::<_, Option<String>>(4)?, "payment_method": r.get::<_, Option<String>>(5)?,
                            "address": r.get::<_, Option<String>>(6)?, "notes": r.get::<_, Option<String>>(7)?, "status": r.get::<_, String>(8)? }))
                    },
                )
                .optional()?
                .ok_or_else(|| AdminError::NotFound("customer".into()))
        };
        run().map(Response::success).unwrap_or_else(Response::from_error)
    }

    /// What: customers action=change_plan. Gate: owner. The customer's subscription is updated at the
    /// payment provider first; only then is the tier stored and audited. A customer without a
    /// subscription cannot change plan here. Out: `{customer_id, old_tier, new_tier, effective_date}`.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: money (provider), database.
    pub fn change_plan(&self, current: &User, customer_id: i64, new_tier: &str) -> Response {
        let run = || -> AdminResult<Value> {
            let me = self.require_owner(current)?;
            let tier = Tier::parse(new_tier)?;
            let (old_tier, sub): (String, Option<String>) = self
                .conn
                .query_row("SELECT tier, stripe_subscription_id FROM customers WHERE id = ?1", params![customer_id], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?
                .ok_or_else(|| AdminError::NotFound("customer".into()))?;
            let sub = sub.ok_or_else(|| AdminError::Validation("no_subscription".into()))?;
            let price = self.price_ids.get(tier.as_str()).ok_or_else(|| AdminError::Validation("invalid_tier".into()))?;
            self.stripe.update_subscription(&sub, price)?;
            let ts = now();
            let tx = self.conn.unchecked_transaction()?;
            tx.execute("UPDATE customers SET tier = ?1 WHERE id = ?2", params![tier.as_str(), customer_id])?;
            Self::audit(&tx, "plan_changed", me.id, "customer", customer_id, Some(json!({ "tier": old_tier })), Some(json!({ "tier": tier.as_str() })), None)?;
            tx.commit()?;
            Ok(json!({ "customer_id": customer_id, "old_tier": old_tier, "new_tier": tier.as_str(), "effective_date": ts }))
        };
        run().map(Response::success).unwrap_or_else(Response::from_error)
    }

    /// What: customers action=queue_refund. Gate: owner. The invoice must exist and have succeeded;
    /// the amount must be positive and within what is not already queued. Never moves money.
    /// Out: `{refund_id, status: "queued", amount}`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database.
    pub fn queue_refund(&self, current: &User, invoice_id: i64, amount: i64, reason: &str) -> Response {
        let run = || -> AdminResult<Value> {
            let me = self.require_owner(current)?;
            if amount <= 0 {
                return Err(AdminError::Validation("invalid_amount".into()));
            }
            if reason.trim().is_empty() {
                return Err(AdminError::Validation("reason_required".into()));
            }
            let (total, status): (i64, String) = self
                .conn
                .query_row("SELECT amount, status FROM invoices WHERE id = ?1", params![invoice_id], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?
                .ok_or_else(|| AdminError::NotFound("invoice".into()))?;
            if status != "succeeded" {
                return Err(AdminError::Validation("invoice_not_succeeded".into()));
            }
            let queued: i64 = self.conn.query_row("SELECT COALESCE(SUM(amount), 0) FROM refunds WHERE invoice_id = ?1", params![invoice_id], |r| r.get(0))?;
            if amount > total - queued {
                return Err(AdminError::Validation("refund_exceeds_invoice".into()));
            }
            let tx = self.conn.unchecked_transaction()?;
            tx.execute(
                "INSERT INTO refunds (invoice_id, amount, reason, created_by, created_at, status) VALUES (?1, ?2, ?3, ?4, ?5, 'queued')",
                params![invoice_id, amount, reason, me.id, now()],
            )?;
            let id = tx.last_insert_rowid();
            Self::audit(&tx, "refund_queued", me.id, "invoice", invoice_id, None, Some(json!({ "refund_id": id, "amount": amount })), Some(reason))?;
            tx.commit()?;
            Ok(json!({ "refund_id": id, "status": "queued", "amount": amount }))
        };
        run().map(Response::success).unwrap_or_else(Response::from_error)
    }

    /// What: deployments action=create. Gate: owner. Customer exists, domain valid and not used by a
    /// live or draft deployment, theme id given. Creates a draft with an initial config.
    /// Out: `{deployment_id, domain, tier}`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database.
    pub fn create_deployment(&self, current: &User, customer_id: i64, domain: &str, tier: &str, theme_id: &str) -> Response {
        let run = || -> AdminResult<Value> {
            let me = self.require_owner(current)?;
            let tier = Tier::parse(tier)?;
            let domain = domain.trim().to_lowercase();
            if !valid_domain(&domain) {
                return Err(AdminError::Validation("invalid_domain".into()));
            }
            if theme_id.is_empty() || !theme_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Err(AdminError::Validation("invalid_theme".into()));
            }
            let customer: i64 = self.conn.query_row("SELECT COUNT(*) FROM customers WHERE id = ?1", params![customer_id], |r| r.get(0))?;
            if customer == 0 {
                return Err(AdminError::NotFound("customer".into()));
            }
            let taken: i64 = self.conn.query_row("SELECT COUNT(*) FROM deployments WHERE domain = ?1 AND status != 'archived'", params![domain], |r| r.get(0))?;
            if taken > 0 {
                return Err(AdminError::Conflict("domain_taken".into()));
            }
            let config = json!({ "theme": theme_id, "tier": tier.as_str() });
            let tx = self.conn.unchecked_transaction()?;
            tx.execute(
                "INSERT INTO deployments (customer_id, domain, tier, status, theme, config) VALUES (?1, ?2, ?3, 'draft', ?4, ?5)",
                params![customer_id, domain, tier.as_str(), theme_id, config.to_string()],
            )?;
            let id = tx.last_insert_rowid();
            Self::audit(&tx, "deployment_created", me.id, "deployment", id, None, Some(json!({ "customer_id": customer_id, "domain": domain })), None)?;
            tx.commit()?;
            Ok(json!({ "deployment_id": id, "domain": domain, "tier": tier.as_str() }))
        };
        run().map(Response::success).unwrap_or_else(Response::from_error)
    }

    /// What: deployments action=publish. Gates: owner AND the `can_publish` safety flag; the deployment
    /// is a draft with a theme and its domain is verified now by the `DomainVerifier`.
    /// Out: `{deployment_id, status: "live", public_url}`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database, domain verification.
    pub fn publish_deployment(&self, current: &User, deployment_id: i64) -> Response {
        let run = || -> AdminResult<Value> {
            let me = self.require_owner(current)?;
            if !self.safety.can_publish {
                return Err(AdminError::Forbidden("publishing_disabled".into()));
            }
            let (status, domain, theme): (String, String, String) = self
                .conn
                .query_row("SELECT status, domain, theme FROM deployments WHERE id = ?1", params![deployment_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .optional()?
                .ok_or_else(|| AdminError::NotFound("deployment".into()))?;
            if status != "draft" {
                return Err(AdminError::Validation("not_a_draft".into()));
            }
            if theme.is_empty() {
                return Err(AdminError::Validation("theme_not_set".into()));
            }
            if !self.domains.is_verified(&domain) {
                return Err(AdminError::Validation("domain_not_verified".into()));
            }
            let tx = self.conn.unchecked_transaction()?;
            tx.execute("UPDATE deployments SET status = 'live', domain_verified = 1, published_at = ?1 WHERE id = ?2", params![now(), deployment_id])?;
            Self::audit(&tx, "deployment_published", me.id, "deployment", deployment_id, Some(json!({ "status": status })), Some(json!({ "status": "live" })), None)?;
            tx.commit()?;
            Ok(json!({ "deployment_id": deployment_id, "status": "live", "public_url": format!("https://{}", domain) }))
        };
        run().map(Response::success).unwrap_or_else(Response::from_error)
    }

    /// What: set a deployment's status with an audit row (suspend or retire). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    fn set_deployment_status(&self, current: &User, deployment_id: i64, status: &str, action: &str, reason: Option<&str>) -> AdminResult<Value> {
        let me = self.require_owner(current)?;
        let old: String = self
            .conn
            .query_row("SELECT status FROM deployments WHERE id = ?1", params![deployment_id], |r| r.get(0))
            .optional()?
            .ok_or_else(|| AdminError::NotFound("deployment".into()))?;
        if old == "archived" {
            return Err(AdminError::Validation("deployment_archived".into()));
        }
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE deployments SET status = ?1, suspend_reason = COALESCE(?2, suspend_reason), archived_at = CASE WHEN ?1 = 'archived' THEN ?3 ELSE archived_at END WHERE id = ?4",
            params![status, reason, now(), deployment_id],
        )?;
        Self::audit(&tx, action, me.id, "deployment", deployment_id, Some(json!({ "status": old })), Some(json!({ "status": status })), reason)?;
        tx.commit()?;
        Ok(json!({ "deployment_id": deployment_id, "status": status }))
    }

    /// What: deployments action=suspend (reason required). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database.
    pub fn suspend_deployment(&self, current: &User, deployment_id: i64, reason: &str) -> Response {
        if reason.trim().is_empty() {
            return Response::error("reason_required", "reason required");
        }
        self.set_deployment_status(current, deployment_id, "suspended", "deployment_suspended", Some(reason)).map(Response::success).unwrap_or_else(Response::from_error)
    }

    /// What: deployments action=retire (archive). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database.
    pub fn retire_deployment(&self, current: &User, deployment_id: i64) -> Response {
        self.set_deployment_status(current, deployment_id, "archived", "deployment_archived", None).map(Response::success).unwrap_or_else(Response::from_error)
    }

    /// What: pending governance actions, oldest first. Gate: admin or owner. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
    pub fn list_governance_actions(&self, current: &User, page: i64, per_page: i64) -> Response {
        let run = || -> AdminResult<Value> {
            self.require_admin_or_owner(current)?;
            let per = per_page.clamp(1, 100);
            let mut stmt = self.conn.prepare(
                "SELECT id, action_type, actor_id, target_resource_id, reason, submitted_at, status FROM governance_actions WHERE status = 'pending' ORDER BY id LIMIT ?1 OFFSET ?2",
            )?;
            let rows = stmt
                .query_map(params![per, (page.max(1) - 1) * per], |r| {
                    Ok(json!({ "action_id": r.get::<_, i64>(0)?, "action_type": r.get::<_, String>(1)?, "actor": r.get::<_, i64>(2)?,
                        "target_resource_id": r.get::<_, i64>(3)?, "reason": r.get::<_, Option<String>>(4)?, "submitted_at": r.get::<_, String>(5)?, "status": r.get::<_, String>(6)? }))
                })?
                .collect::<rusqlite::Result<Vec<Value>>>()?;
            Ok(Value::Array(rows))
        };
        run().map(Response::success).unwrap_or_else(Response::from_error)
    }

    /// What: governance decide. Gate: owner. "approve" executes the action (supported:
    /// `suspend_user`, `delete_user` (soft delete), `retire_deployment`), under the same safety rules,
    /// and marks it approved with its result; "reject" needs a reason. Only pending actions can be
    /// decided. Out: `{action_id, status}`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database.
    pub fn decide_governance_action(&self, current: &User, action_id: i64, decision: &str, reason: Option<&str>) -> Response {
        let run = || -> AdminResult<Value> {
            let me = self.require_owner(current)?;
            let (action_type, target, status): (String, i64, String) = self
                .conn
                .query_row("SELECT action_type, target_resource_id, status FROM governance_actions WHERE id = ?1", params![action_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .optional()?
                .ok_or_else(|| AdminError::NotFound("governance action".into()))?;
            if status != "pending" {
                return Err(AdminError::Conflict("already_decided".into()));
            }
            match decision {
                "approve" => {
                    // the action and its approval commit together, or not at all
                    let tx = self.conn.unchecked_transaction()?;
                    let result = match action_type.as_str() {
                        "suspend_user" | "delete_user" => {
                            if target == me.id {
                                return Err(AdminError::Validation("cannot_act_on_yourself".into()));
                            }
                            let user = self.get_user_by_id(target)?;
                            if self.is_last_active_owner(&user)? {
                                return Err(AdminError::Validation("cannot_remove_last_owner".into()));
                            }
                            let new_status = if action_type == "delete_user" { "deleted" } else { "suspended" };
                            tx.execute("UPDATE users SET status = ?1, updated_at = ?2 WHERE id = ?3", params![new_status, now(), target])?;
                            json!({ "user_id": target, "status": new_status })
                        }
                        "retire_deployment" => {
                            let n = tx.execute("UPDATE deployments SET status = 'archived', archived_at = ?1 WHERE id = ?2", params![now(), target])?;
                            if n == 0 {
                                return Err(AdminError::NotFound("deployment".into()));
                            }
                            json!({ "deployment_id": target, "status": "archived" })
                        }
                        other => return Err(AdminError::Validation(format!("unsupported_action_{}", other))),
                    };
                    tx.execute(
                        "UPDATE governance_actions SET status = 'approved', approved_by = ?1, approved_at = ?2, execution_result = ?3 WHERE id = ?4",
                        params![me.id, now(), result.to_string(), action_id],
                    )?;
                    Self::audit(&tx, "action_approved", me.id, "approval", action_id, None, Some(result), None)?;
                    tx.commit()?;
                    Ok(json!({ "action_id": action_id, "status": "approved" }))
                }
                "reject" => {
                    let reason = reason.map(str::trim).filter(|r| !r.is_empty()).ok_or_else(|| AdminError::Validation("reason_required".into()))?;
                    let tx = self.conn.unchecked_transaction()?;
                    tx.execute("UPDATE governance_actions SET status = 'rejected', rejection_reason = ?1 WHERE id = ?2", params![reason, action_id])?;
                    Self::audit(&tx, "action_rejected", me.id, "approval", action_id, None, None, Some(reason))?;
                    tx.commit()?;
                    Ok(json!({ "action_id": action_id, "status": "rejected" }))
                }
                _ => Err(AdminError::Validation("invalid_decision".into())),
            }
        };
        run().map(Response::success).unwrap_or_else(Response::from_error)
    }

    /// What: search the audit log, newest first. Gate: admin or owner. Filters: action, resource id,
    /// (from, to) RFC 3339 range; limit 1-1000 (default 100 when 0), offset. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
    pub fn search_audit_log(&self, current: &User, action_type: Option<&str>, resource_id: Option<i64>, date_range: Option<(&str, &str)>, limit: i64, offset: i64) -> Response {
        let run = || -> AdminResult<Value> {
            self.require_admin_or_owner(current)?;
            let limit = if limit <= 0 { 100 } else { limit.min(1000) };
            let (from, to) = date_range.map(|(a, b)| (Some(a.to_string()), Some(b.to_string()))).unwrap_or((None, None));
            let mut stmt = self.conn.prepare(
                "SELECT timestamp, actor_id, action, resource_type, resource_id, old_value, new_value, reason FROM audit_logs
                 WHERE (?1 IS NULL OR action = ?1) AND (?2 IS NULL OR resource_id = ?2) AND (?3 IS NULL OR timestamp >= ?3) AND (?4 IS NULL OR timestamp <= ?4)
                 ORDER BY id DESC LIMIT ?5 OFFSET ?6",
            )?;
            let rows = stmt
                .query_map(params![action_type, resource_id, from, to, limit, offset.max(0)], |r| {
                    Ok(json!({ "timestamp": r.get::<_, String>(0)?, "actor_id": r.get::<_, i64>(1)?, "action": r.get::<_, String>(2)?,
                        "resource_type": r.get::<_, String>(3)?, "resource_id": r.get::<_, i64>(4)?, "old_value": r.get::<_, Option<String>>(5)?,
                        "new_value": r.get::<_, Option<String>>(6)?, "reason": r.get::<_, Option<String>>(7)? }))
                })?
                .collect::<rusqlite::Result<Vec<Value>>>()?;
            Ok(Value::Array(rows))
        };
        run().map(Response::success).unwrap_or_else(Response::from_error)
    }
}

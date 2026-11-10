//! Organizations and teams: multi-tenant membership and email invitations (TIER 3 spec, system 4,
//! from the OWASP Authorization Cheat Sheet).
//!
//! What: `OrganizationsTeams` creates orgs (the creator is owner), invites by email with a 32-byte
//! random token stored only as its SHA-256 hash (single use, 7-day expiry, email must match), and
//! changes roles, removes members, lets members leave, lists members and reads an org, checking the
//! caller's membership and role on every call. A non-member gets "not found", never a hint the org
//! exists, and an org always keeps at least one owner.
//! Why: the old file did not compile (private items, a `main` inside a library, a SQL store of stubs),
//! hashed the token hash a second time, let the last owner leave, and stored the "accepted" time in the
//! wrong tuple slot. Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: memory, or SQLite through `SqliteStorage`; the OS random source; no network, no money.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Invitation lifetime: 7 days, in seconds (spec).
pub const INVITATION_TTL_SECS: u64 = 7 * 24 * 60 * 60;
/// The three roles, most powerful first.
pub const ROLES: [&str; 3] = ["owner", "admin", "member"];

/// What: every way an org call can fail. Why: typed errors instead of the old `(u32, String, String)`.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgError {
    /// No caller identity given.
    Unauthenticated,
    /// The org does not exist, or the caller is not a member of it (indistinguishable on purpose).
    NotFound,
    /// The target user is not a member of the org.
    MemberNotFound,
    /// The caller's role does not allow this.
    Forbidden,
    /// The change would leave the org without an owner.
    LastOwner,
    /// No invitation matches this token.
    InvitationNotFound,
    /// The invitation was already accepted.
    InvitationUsed,
    /// The invitation's 7 days are over.
    InvitationExpired,
    /// The accepting user's email is not the invited email.
    EmailMismatch,
    /// The invited user is already a member.
    AlreadyMember,
    /// A bad name, email or role.
    InvalidInput(String),
    /// The store failed.
    Storage(String),
}

/// What: one organization (spec table `organizations`). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq)]
pub struct Org {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub created_at: u64,
}

/// What: one membership (spec table `memberships`). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq)]
pub struct Membership {
    pub org_id: String,
    pub user_id: String,
    pub role: String,
    pub created_at: u64,
}

/// What: one invitation (spec table `invitations`); only the token's SHA-256 hex is kept.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq)]
pub struct Invitation {
    pub id: String,
    pub org_id: String,
    pub email: String,
    pub role: String,
    pub token_hash: String,
    pub expires_at: u64,
    pub accepted_at: Option<u64>,
    pub invited_by: String,
    pub created_at: u64,
}

/// What: the reads and writes the org system needs. Memberships list in insertion order.
/// Why: the spec's storage contract. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: whatever the implementation stores to.
pub trait Storage: Send {
    /// What: `insert_org` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn insert_org(&mut self, org: &Org) -> Result<(), OrgError>;
    /// What: `get_org` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn get_org(&self, org_id: &str) -> Option<Org>;
    /// What: `slug_taken` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn slug_taken(&self, slug: &str) -> bool;
    /// Fails with `AlreadyMember` when (org, user) exists (UNIQUE(org_id, user_id)).
    fn insert_membership(&mut self, m: &Membership) -> Result<(), OrgError>;
    /// What: `get_membership` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn get_membership(&self, org_id: &str, user_id: &str) -> Option<Membership>;
    /// What: `set_role` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn set_role(&mut self, org_id: &str, user_id: &str, role: &str) -> Result<(), OrgError>;
    /// What: `delete_membership` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn delete_membership(&mut self, org_id: &str, user_id: &str) -> Result<(), OrgError>;
    /// What: `list_memberships` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn list_memberships(&self, org_id: &str) -> Vec<Membership>;
    /// What: `insert_invitation` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn insert_invitation(&mut self, inv: &Invitation) -> Result<(), OrgError>;
    /// What: `find_invitation` (see the implementations). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn find_invitation(&self, token_hash: &str) -> Option<Invitation>;
    /// Sets `accepted_at` only if it is still empty; returns whether this call did it (single use).
    fn mark_accepted(&mut self, invitation_id: &str, at: u64) -> Result<bool, OrgError>;
    /// Every stored row as text, for audits such as "the raw token is stored nowhere".
    fn debug_dump(&self) -> String;
}

/// What: the in-memory store. Why: tests and examples. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory only.
#[derive(Default)]
pub struct InMemoryStorage {
    orgs: Vec<Org>,
    memberships: Vec<Membership>,
    invitations: Vec<Invitation>,
}

/// What: `Storage` for `InMemoryStorage`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl Storage for InMemoryStorage {
    /// What: `insert_org` of `Storage for InMemoryStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn insert_org(&mut self, org: &Org) -> Result<(), OrgError> {
        self.orgs.push(org.clone());
        Ok(())
    }
    /// What: `get_org` of `Storage for InMemoryStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn get_org(&self, org_id: &str) -> Option<Org> {
        self.orgs.iter().find(|o| o.id == org_id).cloned()
    }
    /// What: `slug_taken` of `Storage for InMemoryStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn slug_taken(&self, slug: &str) -> bool {
        self.orgs.iter().any(|o| o.slug == slug)
    }
    /// What: `insert_membership` of `Storage for InMemoryStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn insert_membership(&mut self, m: &Membership) -> Result<(), OrgError> {
        if self.get_membership(&m.org_id, &m.user_id).is_some() {
            return Err(OrgError::AlreadyMember);
        }
        self.memberships.push(m.clone());
        Ok(())
    }
    /// What: `get_membership` of `Storage for InMemoryStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn get_membership(&self, org_id: &str, user_id: &str) -> Option<Membership> {
        self.memberships.iter().find(|m| m.org_id == org_id && m.user_id == user_id).cloned()
    }
    /// What: `set_role` of `Storage for InMemoryStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn set_role(&mut self, org_id: &str, user_id: &str, role: &str) -> Result<(), OrgError> {
        let m = self
            .memberships
            .iter_mut()
            .find(|m| m.org_id == org_id && m.user_id == user_id)
            .ok_or(OrgError::MemberNotFound)?;
        m.role = role.to_string();
        Ok(())
    }
    /// What: `delete_membership` of `Storage for InMemoryStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn delete_membership(&mut self, org_id: &str, user_id: &str) -> Result<(), OrgError> {
        let before = self.memberships.len();
        self.memberships.retain(|m| !(m.org_id == org_id && m.user_id == user_id));
        if self.memberships.len() == before { Err(OrgError::MemberNotFound) } else { Ok(()) }
    }
    /// What: `list_memberships` of `Storage for InMemoryStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn list_memberships(&self, org_id: &str) -> Vec<Membership> {
        self.memberships.iter().filter(|m| m.org_id == org_id).cloned().collect()
    }
    /// What: `insert_invitation` of `Storage for InMemoryStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn insert_invitation(&mut self, inv: &Invitation) -> Result<(), OrgError> {
        self.invitations.push(inv.clone());
        Ok(())
    }
    /// What: `find_invitation` of `Storage for InMemoryStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn find_invitation(&self, token_hash: &str) -> Option<Invitation> {
        self.invitations.iter().find(|i| i.token_hash == token_hash).cloned()
    }
    /// What: `mark_accepted` of `Storage for InMemoryStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn mark_accepted(&mut self, invitation_id: &str, at: u64) -> Result<bool, OrgError> {
        match self.invitations.iter_mut().find(|i| i.id == invitation_id) {
            Some(i) if i.accepted_at.is_none() => {
                i.accepted_at = Some(at);
                Ok(true)
            }
            Some(_) => Ok(false),
            None => Err(OrgError::InvitationNotFound),
        }
    }
    /// What: `debug_dump` of `Storage for InMemoryStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn debug_dump(&self) -> String {
        format!("{:?}\n{:?}\n{:?}", self.orgs, self.memberships, self.invitations)
    }
}

/// What: the production store on SQLite, the spec's three tables as DDL, every query parameterised.
/// Why: the old SQL store was a set of stubs. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: the SQLite database it is given.
pub struct SqliteStorage {
    conn: rusqlite::Connection,
}

/// What: a SQLite error as a storage error. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn sql_err(e: rusqlite::Error) -> OrgError {
    OrgError::Storage(e.to_string())
}

/// What: methods of `SqliteStorage`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl SqliteStorage {
    /// What: wrap a connection and create the tables. In: connection. Out: store or error.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (DDL).
    pub fn new(conn: rusqlite::Connection) -> Result<Self, OrgError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS organizations (id TEXT PRIMARY KEY, name TEXT NOT NULL,
                slug TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS memberships (seq INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT NOT NULL,
                user_id TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('owner','admin','member')),
                created_at INTEGER NOT NULL, UNIQUE(org_id, user_id));
             CREATE TABLE IF NOT EXISTS invitations (id TEXT PRIMARY KEY, org_id TEXT NOT NULL, email TEXT NOT NULL,
                role TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL,
                accepted_at INTEGER NULL, invited_by TEXT NOT NULL, created_at INTEGER NOT NULL);",
        )
        .map_err(sql_err)?;
        Ok(Self { conn })
    }

    /// What: read one invitation row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn invitation_row(r: &rusqlite::Row) -> rusqlite::Result<Invitation> {
        Ok(Invitation {
            id: r.get(0)?,
            org_id: r.get(1)?,
            email: r.get(2)?,
            role: r.get(3)?,
            token_hash: r.get(4)?,
            expires_at: r.get::<_, i64>(5)? as u64,
            accepted_at: r.get::<_, Option<i64>>(6)?.map(|t| t as u64),
            invited_by: r.get(7)?,
            created_at: r.get::<_, i64>(8)? as u64,
        })
    }
}

/// What: read one membership row. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn membership_row(r: &rusqlite::Row) -> rusqlite::Result<Membership> {
    Ok(Membership { org_id: r.get(0)?, user_id: r.get(1)?, role: r.get(2)?, created_at: r.get::<_, i64>(3)? as u64 })
}

/// What: `Storage` for `SqliteStorage`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing beyond what each method says.
impl Storage for SqliteStorage {
    /// What: `insert_org` of `Storage for SqliteStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn insert_org(&mut self, o: &Org) -> Result<(), OrgError> {
        self.conn
            .execute("INSERT INTO organizations (id, name, slug, created_at) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![o.id, o.name, o.slug, o.created_at as i64])
            .map_err(sql_err)?;
        Ok(())
    }
    /// What: `get_org` of `Storage for SqliteStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn get_org(&self, org_id: &str) -> Option<Org> {
        self.conn
            .query_row("SELECT id, name, slug, created_at FROM organizations WHERE id = ?1", rusqlite::params![org_id],
                |r| Ok(Org { id: r.get(0)?, name: r.get(1)?, slug: r.get(2)?, created_at: r.get::<_, i64>(3)? as u64 }))
            .ok()
    }
    /// What: `slug_taken` of `Storage for SqliteStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn slug_taken(&self, slug: &str) -> bool {
        self.conn
            .query_row("SELECT COUNT(*) FROM organizations WHERE slug = ?1", rusqlite::params![slug], |r| r.get::<_, i64>(0))
            .map(|n| n > 0)
            .unwrap_or(true)
    }
    /// What: `insert_membership` of `Storage for SqliteStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn insert_membership(&mut self, m: &Membership) -> Result<(), OrgError> {
        if self.get_membership(&m.org_id, &m.user_id).is_some() {
            return Err(OrgError::AlreadyMember);
        }
        self.conn
            .execute("INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![m.org_id, m.user_id, m.role, m.created_at as i64])
            .map_err(sql_err)?;
        Ok(())
    }
    /// What: `get_membership` of `Storage for SqliteStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn get_membership(&self, org_id: &str, user_id: &str) -> Option<Membership> {
        self.conn
            .query_row("SELECT org_id, user_id, role, created_at FROM memberships WHERE org_id = ?1 AND user_id = ?2",
                rusqlite::params![org_id, user_id], membership_row)
            .ok()
    }
    /// What: `set_role` of `Storage for SqliteStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn set_role(&mut self, org_id: &str, user_id: &str, role: &str) -> Result<(), OrgError> {
        let n = self
            .conn
            .execute("UPDATE memberships SET role = ?3 WHERE org_id = ?1 AND user_id = ?2", rusqlite::params![org_id, user_id, role])
            .map_err(sql_err)?;
        if n == 0 { Err(OrgError::MemberNotFound) } else { Ok(()) }
    }
    /// What: `delete_membership` of `Storage for SqliteStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn delete_membership(&mut self, org_id: &str, user_id: &str) -> Result<(), OrgError> {
        let n = self
            .conn
            .execute("DELETE FROM memberships WHERE org_id = ?1 AND user_id = ?2", rusqlite::params![org_id, user_id])
            .map_err(sql_err)?;
        if n == 0 { Err(OrgError::MemberNotFound) } else { Ok(()) }
    }
    /// What: `list_memberships` of `Storage for SqliteStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn list_memberships(&self, org_id: &str) -> Vec<Membership> {
        let Ok(mut stmt) = self
            .conn
            .prepare("SELECT org_id, user_id, role, created_at FROM memberships WHERE org_id = ?1 ORDER BY seq")
        else {
            return Vec::new();
        };
        let rows = stmt.query_map(rusqlite::params![org_id], membership_row);
        rows.map(|r| r.filter_map(Result::ok).collect()).unwrap_or_default()
    }
    /// What: `insert_invitation` of `Storage for SqliteStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn insert_invitation(&mut self, i: &Invitation) -> Result<(), OrgError> {
        self.conn
            .execute(
                "INSERT INTO invitations (id, org_id, email, role, token_hash, expires_at, accepted_at, invited_by, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![i.id, i.org_id, i.email, i.role, i.token_hash, i.expires_at as i64,
                    i.accepted_at.map(|t| t as i64), i.invited_by, i.created_at as i64],
            )
            .map_err(sql_err)?;
        Ok(())
    }
    /// What: `find_invitation` of `Storage for SqliteStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn find_invitation(&self, token_hash: &str) -> Option<Invitation> {
        self.conn
            .query_row(
                "SELECT id, org_id, email, role, token_hash, expires_at, accepted_at, invited_by, created_at
                 FROM invitations WHERE token_hash = ?1",
                rusqlite::params![token_hash],
                Self::invitation_row,
            )
            .ok()
    }
    /// What: `mark_accepted` of `Storage for SqliteStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn mark_accepted(&mut self, invitation_id: &str, at: u64) -> Result<bool, OrgError> {
        let n = self
            .conn
            .execute("UPDATE invitations SET accepted_at = ?2 WHERE id = ?1 AND accepted_at IS NULL",
                rusqlite::params![invitation_id, at as i64])
            .map_err(sql_err)?;
        Ok(n == 1)
    }
    /// What: `debug_dump` of `Storage for SqliteStorage`; behaviour as the trait or type documents it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: as described for its type.
    fn debug_dump(&self) -> String {
        let mut out = String::new();
        for table in ["organizations", "memberships", "invitations"] {
            if let Ok(mut stmt) = self.conn.prepare(&format!("SELECT * FROM {}", table)) {
                let cols = stmt.column_count();
                if let Ok(mut rows) = stmt.query([]) {
                    while let Ok(Some(row)) = rows.next() {
                        for c in 0..cols {
                            let v: rusqlite::types::Value = row.get(c).unwrap_or(rusqlite::types::Value::Null);
                            out.push_str(&format!("{:?}|", v));
                        }
                        out.push('\n');
                    }
                }
            }
        }
        out
    }
}

/// What: the org service. In: a store and a clock. Why: the spec's functions with deny-by-default
/// checks. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, the clock, OS randomness.
pub struct OrganizationsTeams {
    store: Box<dyn Storage>,
    clock: Box<dyn Fn() -> u64 + Send>,
}

/// What: a shared settable clock for tests. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Clone)]
pub struct ManualClock(pub Arc<AtomicU64>);

/// What: methods of `ManualClock`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl ManualClock {
    /// What: a clock reading `t`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    pub fn new(t: u64) -> Self {
        ManualClock(Arc::new(AtomicU64::new(t)))
    }
    /// What: move forward by `secs`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

/// What: SHA-256 of the raw token as lowercase hex. In: token. Out: hex. Why: only the hash is stored.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn hash_token(raw_token: &str) -> String {
    Sha256::digest(raw_token.as_bytes()).iter().map(|b| format!("{:02x}", b)).collect()
}

/// What: `n` OS-random bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: OS randomness.
fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

/// What: a URL slug: lowercase ASCII letters and digits, other runs become one `-`. In: name.
/// Out: slug (`org` when nothing is left). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
pub fn slugify(name: &str) -> String {
    let mut slug = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
        } else if !slug.ends_with('-') && !slug.is_empty() {
            slug.push('-');
        }
    }
    let slug = slug.trim_end_matches('-').to_string();
    if slug.is_empty() { "org".to_string() } else { slug }
}

/// What: trimmed lowercase email, or `InvalidInput`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn normalize_email(email: &str) -> Result<String, OrgError> {
    let e = email.trim().to_lowercase();
    match e.split_once('@') {
        Some((local, domain)) if !local.is_empty() && !domain.is_empty() && !domain.contains('@') => Ok(e),
        _ => Err(OrgError::InvalidInput("email".into())),
    }
}

/// What: rank of a role, higher is stronger; `InvalidInput` for an unknown role.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn role_rank(role: &str) -> Result<u8, OrgError> {
    match role {
        "owner" => Ok(3),
        "admin" => Ok(2),
        "member" => Ok(1),
        _ => Err(OrgError::InvalidInput("role".into())),
    }
}

/// What: methods of `OrganizationsTeams`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl OrganizationsTeams {
    /// What: a service on the in-memory store (`use_sql = false`) or on an in-memory SQLite database
    /// (`use_sql = true`), using the system clock. Why: the tests' constructor; both stores behave
    /// the same. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory or SQLite.
    pub fn new(use_sql: bool) -> Self {
        let store: Box<dyn Storage> = if use_sql {
            let conn = rusqlite::Connection::open_in_memory().expect("open in-memory SQLite");
            Box::new(SqliteStorage::new(conn).expect("create org tables"))
        } else {
            Box::new(InMemoryStorage::default())
        };
        Self::with_store(store)
    }

    /// What: a service on any store with the system clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn with_store(store: Box<dyn Storage>) -> Self {
        Self {
            store,
            clock: Box::new(|| SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)),
        }
    }

    /// What: replace the clock. Why: deterministic expiry tests. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn with_clock(mut self, clock: ManualClock) -> Self {
        self.clock = Box::new(move || clock.0.load(Ordering::SeqCst));
        self
    }

    /// What: the store's audit dump. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
    pub fn debug_dump(&self) -> String {
        self.store.debug_dump()
    }

    /// What: the caller's membership, or `Unauthenticated` / `NotFound` (non-members never learn the
    /// org exists). Why: "Deny by Default", checked on every request. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the store.
    fn require_member(&self, user: &str, org_id: &str) -> Result<Membership, OrgError> {
        if user.trim().is_empty() {
            return Err(OrgError::Unauthenticated);
        }
        self.store.get_membership(org_id, user).ok_or(OrgError::NotFound)
    }

    /// What: number of owners in an org. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    fn owner_count(&self, org_id: &str) -> usize {
        self.store.list_memberships(org_id).iter().filter(|m| m.role == "owner").count()
    }

    /// What: create an org; the creator becomes its owner. In: user, name. Out: (org id, unique slug,
    /// created_at). Why: spec `create_org`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: writes the store; OS randomness for the id.
    pub fn create_org(&mut self, user: &str, name: &str) -> Result<(String, String, u64), OrgError> {
        if user.trim().is_empty() {
            return Err(OrgError::Unauthenticated);
        }
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 200 {
            return Err(OrgError::InvalidInput("name".into()));
        }
        let base = slugify(name);
        let mut slug = base.clone();
        let mut n = 2;
        while self.store.slug_taken(&slug) {
            slug = format!("{}-{}", base, n);
            n += 1;
        }
        let now = (self.clock)();
        let id: String = random_bytes(16).iter().map(|b| format!("{:02x}", b)).collect();
        self.store.insert_org(&Org { id: id.clone(), name: name.to_string(), slug: slug.clone(), created_at: now })?;
        self.store.insert_membership(&Membership { org_id: id.clone(), user_id: user.to_string(), role: "owner".into(), created_at: now })?;
        Ok((id, slug, now))
    }

    /// What: invite an email to an org with a role. Members cannot invite; admins can invite admins and
    /// members; only an owner can invite an owner. In: actor, org, email, role. Out: (raw token — base64
    /// of 32 random bytes, returned once, only its hash stored; expires_at; created_at).
    /// Why: spec `invite`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: writes the store.
    pub fn invite(&mut self, actor: &str, org_id: &str, email: &str, role: &str) -> Result<(String, u64, u64), OrgError> {
        let me = self.require_member(actor, org_id)?;
        let wanted = role_rank(role)?;
        let mine = role_rank(&me.role)?;
        if mine < 2 || (wanted == 3 && mine < 3) {
            return Err(OrgError::Forbidden);
        }
        let email = normalize_email(email)?;
        let token = URL_SAFE.encode(random_bytes(32));
        let now = (self.clock)();
        let expires_at = now + INVITATION_TTL_SECS;
        let id: String = random_bytes(16).iter().map(|b| format!("{:02x}", b)).collect();
        self.store.insert_invitation(&Invitation {
            id,
            org_id: org_id.to_string(),
            email,
            role: role.to_string(),
            token_hash: hash_token(&token),
            expires_at,
            accepted_at: None,
            invited_by: actor.to_string(),
            created_at: now,
        })?;
        Ok((token, expires_at, now))
    }

    /// What: join an org with an invitation. `user` is the accepting user's identity, which is their
    /// email. In: user, raw token. Out: (org id, role, membership created_at), or
    /// `InvitationNotFound`, `InvitationUsed`, `InvitationExpired`, `EmailMismatch`, `AlreadyMember`.
    /// Why: spec "single-use, expire after 7 days, only the user whose email matches may accept".
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: writes the store.
    pub fn accept_invitation(&mut self, user: &str, raw_token: &str) -> Result<(String, String, u64), OrgError> {
        if user.trim().is_empty() {
            return Err(OrgError::Unauthenticated);
        }
        let inv = self.store.find_invitation(&hash_token(raw_token)).ok_or(OrgError::InvitationNotFound)?;
        if inv.accepted_at.is_some() {
            return Err(OrgError::InvitationUsed);
        }
        let now = (self.clock)();
        if now >= inv.expires_at {
            return Err(OrgError::InvitationExpired);
        }
        if normalize_email(user).ok().as_deref() != Some(inv.email.as_str()) {
            return Err(OrgError::EmailMismatch);
        }
        if self.store.get_membership(&inv.org_id, user).is_some() {
            return Err(OrgError::AlreadyMember);
        }
        if !self.store.mark_accepted(&inv.id, now)? {
            return Err(OrgError::InvitationUsed);
        }
        self.store.insert_membership(&Membership { org_id: inv.org_id.clone(), user_id: user.to_string(), role: inv.role.clone(), created_at: now })?;
        Ok((inv.org_id, inv.role, now))
    }

    /// What: change an existing member's role. Members cannot; admins cannot touch an owner or grant
    /// owner; only owners grant owner; the last owner cannot be demoted. In: actor, org, user, role.
    /// Out: `()` or an error. Why: spec least privilege. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: writes the store.
    pub fn change_role(&mut self, actor: &str, org_id: &str, user_id: &str, role: &str) -> Result<(), OrgError> {
        let me = self.require_member(actor, org_id)?;
        let wanted = role_rank(role)?;
        let mine = role_rank(&me.role)?;
        if mine < 2 {
            return Err(OrgError::Forbidden);
        }
        let target = self.store.get_membership(org_id, user_id).ok_or(OrgError::MemberNotFound)?;
        if (target.role == "owner" || wanted == 3) && mine < 3 {
            return Err(OrgError::Forbidden);
        }
        if target.role == "owner" && wanted != 3 && self.owner_count(org_id) <= 1 {
            return Err(OrgError::LastOwner);
        }
        self.store.set_role(org_id, user_id, role)
    }

    /// What: remove an existing member. Members cannot; admins cannot remove an owner; the last owner
    /// cannot be removed. In: actor, org, user. Out: `()` or an error. Why: spec least privilege.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: writes the store.
    pub fn remove_member(&mut self, actor: &str, org_id: &str, user_id: &str) -> Result<(), OrgError> {
        let me = self.require_member(actor, org_id)?;
        let mine = role_rank(&me.role)?;
        if mine < 2 {
            return Err(OrgError::Forbidden);
        }
        let target = self.store.get_membership(org_id, user_id).ok_or(OrgError::MemberNotFound)?;
        if target.role == "owner" {
            if mine < 3 {
                return Err(OrgError::Forbidden);
            }
            if self.owner_count(org_id) <= 1 {
                return Err(OrgError::LastOwner);
            }
        }
        self.store.delete_membership(org_id, user_id)
    }

    /// What: leave an org; the last owner cannot. In: user, org. Out: `()` or an error.
    /// Why: spec "an org must always keep at least 1 owner". 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: writes the store.
    pub fn leave_org(&mut self, user: &str, org_id: &str) -> Result<(), OrgError> {
        let me = self.require_member(user, org_id)?;
        if me.role == "owner" && self.owner_count(org_id) <= 1 {
            return Err(OrgError::LastOwner);
        }
        self.store.delete_membership(org_id, user)
    }

    /// What: the org's members as (user id, role, created_at) in join order; members only.
    /// Why: spec `list_members`, IDOR-safe. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: reads the store.
    pub fn list_members(&self, actor: &str, org_id: &str) -> Result<Vec<(String, String, u64)>, OrgError> {
        self.require_member(actor, org_id)?;
        Ok(self.store.list_memberships(org_id).into_iter().map(|m| (m.user_id, m.role, m.created_at)).collect())
    }

    /// What: the org's (name, slug, created_at); members only. Why: spec `get_org`.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the store.
    pub fn get_org(&self, actor: &str, org_id: &str) -> Result<(String, String, u64), OrgError> {
        self.require_member(actor, org_id)?;
        let org = self.store.get_org(org_id).ok_or(OrgError::NotFound)?;
        Ok((org.name, org.slug, org.created_at))
    }
}

/// What: a thread-safe handle for servers that share one service. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
pub type SharedOrganizationsTeams = Arc<Mutex<OrganizationsTeams>>;

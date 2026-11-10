//! Trial abuse prevention: six gates checked at signup and at payment (GEMINI dispatch spec,
//! template #3, and docs/SPEC_auth_admin_trial_abuse.md part 3).
//!
//! What: `Database` holds the trial abuse ledger, signups, device fingerprints, billing events and
//! refunds in SQLite, and answers each gate with PASS, CHALLENGE or FAIL, writing every decision with
//! its inputs to `gate_decisions` (the why-chain).
//! Why: the old file did not compile (`NO_PARAMS` is gone from the SQLite crate, `Deserialize` on a
//! `&'static str`), read a `stripe_customer_id` column its schema never created so chargebacks from the
//! payment provider were never counted, hashed device fields without separators ("ab"+"c" equals
//! "a"+"bc"), used "more than 5" where the spec says FAIL at 5 devices, and returned FAIL without a
//! logged decision when a user had no ledger row. Repaired 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: the SQLite database it owns (in memory for tests); no network, no money.

use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension, Result as SqlResult};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// What: a gate's verdict. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Decision {
    Pass,
    Challenge,
    Fail,
}

/// What: methods of `Decision`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl Decision {
    /// What: the spec's upper-case name. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Pass => "PASS",
            Decision::Challenge => "CHALLENGE",
            Decision::Fail => "FAIL",
        }
    }
}

/// What: one gate's verdict with the inputs it used (also stored in `gate_decisions`).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, Serialize)]
pub struct GateResult {
    pub gate_name: &'static str,
    pub decision: Decision,
    pub rule_inputs: Value,
    pub rule_outputs: Value,
}

/// What: the spec's FAIL response body. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub code: u16,
}

/// What: the spec's CHALLENGE response body. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize)]
pub struct ChallengeResponse {
    pub success: bool,
    pub challenge: String,
}

/// What: the browser traits hashed into a device fingerprint (spec gate 4).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceInfo {
    pub user_agent: String,
    pub screen_resolution: String,
    pub timezone: String,
    pub browser_language: String,
}

/// What: the FAIL response a caller returns for a gate (error code and HTTP status from the spec).
/// In: the gate result. Out: `Some(ErrorResponse)` on FAIL, `None` otherwise.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn fail_response(result: &GateResult) -> Option<ErrorResponse> {
    if result.decision != Decision::Fail {
        return None;
    }
    let (error, code) = match result.gate_name {
        "email_trial_history" => ("email_has_trial_history", 409),
        "payment_method_history" => ("payment_method_used_for_multiple_trials", 403),
        "ip_signup_rate_limit" => ("too_many_signups_from_ip", 429),
        "device_fingerprint" => ("device_suspected_fraud", 403),
        "trial_payment_timing" => ("trial_ended_no_payment_cannot_retry", 403),
        _ => ("chargeback_history_requires_prepayment", 403),
    };
    Some(ErrorResponse { error: error.into(), message: format!("{} failed", result.gate_name), code })
}

/// What: the gate store and checker. Why: one place for the six gates and their audit trail.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
pub struct Database {
    conn: Connection,
    clock: Box<dyn Fn() -> DateTime<Utc>>,
}

/// What: methods of `Database`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl Database {
    /// What: an in-memory database with the schema and the system clock. Out: the database.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    pub fn new_in_memory() -> SqlResult<Self> {
        Self::open(Connection::open_in_memory()?)
    }

    /// What: use an existing connection, creating the tables if missing. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (DDL).
    pub fn open(conn: Connection) -> SqlResult<Self> {
        Self::migrate(&conn)?;
        Ok(Self { conn, clock: Box::new(Utc::now) })
    }

    /// What: replace the clock (for tests of the time-based gates). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> DateTime<Utc>>) -> Self {
        self.clock = clock;
        self
    }

    /// What: the spec's tables (ledger gains `stripe_customer_id`, the link from a user to the payment
    /// provider's customer id that gate 6 needs). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database (DDL).
    fn migrate(conn: &Connection) -> SqlResult<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS trial_abuse_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, email TEXT, stripe_payment_method_id TEXT,
                stripe_customer_id TEXT, ip TEXT, device_fingerprint TEXT, signup_date TEXT, trial_started_at TEXT,
                payment_added_date TEXT, subscription_status TEXT, chargeback_count INTEGER NOT NULL DEFAULT 0,
                refund_count INTEGER NOT NULL DEFAULT 0, gate_flags TEXT NOT NULL DEFAULT '{}', alert_reason TEXT,
                created_at TEXT NOT NULL);
             CREATE INDEX IF NOT EXISTS ledger_email ON trial_abuse_ledger (email);
             CREATE INDEX IF NOT EXISTS ledger_pm ON trial_abuse_ledger (stripe_payment_method_id);
             CREATE TABLE IF NOT EXISTS device_fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, device_hash TEXT NOT NULL,
                user_agent TEXT, screen_resolution TEXT, timezone TEXT, created_at TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS gate_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, gate_name TEXT NOT NULL, decision TEXT NOT NULL,
                rule_inputs TEXT NOT NULL, rule_outputs TEXT NOT NULL, created_at TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS signups (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, created_at TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS stripe_events (id INTEGER PRIMARY KEY AUTOINCREMENT, customer TEXT NOT NULL, type TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS refunds (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, status TEXT NOT NULL);",
        )
    }

    /// What: write the why-chain row and build the result. In: user, gate, decision, inputs.
    /// Out: `GateResult`. Why: spec "Log: why_chain(...)" for every gate.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (gate_decisions).
    fn decide(&self, user_id: Option<i64>, gate_name: &'static str, decision: Decision, rule_inputs: Value) -> SqlResult<GateResult> {
        let rule_outputs = json!({ "decision": decision.as_str() });
        self.conn.execute(
            "INSERT INTO gate_decisions (user_id, gate_name, decision, rule_inputs, rule_outputs, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![user_id, gate_name, decision.as_str(), rule_inputs.to_string(), rule_outputs.to_string(), (self.clock)().to_rfc3339()],
        )?;
        Ok(GateResult { gate_name, decision, rule_inputs, rule_outputs })
    }

    /// What: gate 1. Prior completed or chargebacked trials for the email (case-insensitive):
    /// 0 PASS, 1 CHALLENGE, 2+ FAIL. In: email. Out: `GateResult`.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub fn check_email_trial_history(&self, email: &str) -> SqlResult<GateResult> {
        let email = email.trim().to_lowercase();
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM trial_abuse_ledger
             WHERE lower(email) = ?1 AND subscription_status IN ('completed', 'chargebacked')",
            params![email],
            |r| r.get(0),
        )?;
        let decision = match count {
            0 => Decision::Pass,
            1 => Decision::Challenge,
            _ => Decision::Fail,
        };
        self.decide(None, "email_trial_history", decision, json!({ "email": email, "prior_count": count }))
    }

    /// What: gate 2. Prior trials with the payment method: under 2 PASS, 2 CHALLENGE, 3+ FAIL.
    /// In: the provider's payment method id. Out: `GateResult`. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub fn check_payment_method_history(&self, payment_method_id: &str) -> SqlResult<GateResult> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM trial_abuse_ledger
             WHERE stripe_payment_method_id = ?1 AND subscription_status IN ('completed', 'chargebacked')",
            params![payment_method_id],
            |r| r.get(0),
        )?;
        let decision = if count < 2 {
            Decision::Pass
        } else if count == 2 {
            Decision::Challenge
        } else {
            Decision::Fail
        };
        self.decide(None, "payment_method_history", decision, json!({ "payment_method_id": payment_method_id, "prior_count": count }))
    }

    /// What: gate 3. Signups from the IP in the last 24 hours: under 5 PASS, 5-9 CHALLENGE, 10+ FAIL.
    /// In: IP. Out: `GateResult`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, clock.
    pub fn check_ip_signup_rate_limit(&self, ip: &str) -> SqlResult<GateResult> {
        let since = ((self.clock)() - Duration::hours(24)).to_rfc3339();
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM signups WHERE ip = ?1 AND created_at > ?2",
            params![ip.trim(), since],
            |r| r.get(0),
        )?;
        let decision = if count < 5 {
            Decision::Pass
        } else if count < 10 {
            Decision::Challenge
        } else {
            Decision::Fail
        };
        self.decide(None, "ip_signup_rate_limit", decision, json!({ "ip": ip.trim(), "count": count, "limit": 10 }))
    }

    /// What: SHA-256 of the four device traits as a JSON array (unambiguous field boundaries).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn device_hash(device: &DeviceInfo) -> String {
        let canonical = json!([device.user_agent, device.screen_resolution, device.timezone, device.browser_language]).to_string();
        Sha256::digest(canonical.as_bytes()).iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// What: gate 4. Distinct OTHER users seen on this device: PASS under 2 (or when the device is
    /// already one of this user's known devices), CHALLENGE 2-4, FAIL 5+ (spec "FAIL if count >= 5").
    /// In: device, the user (if known). Out: `GateResult`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database.
    pub fn check_device_fingerprint(&self, device: &DeviceInfo, user_id: Option<i64>) -> SqlResult<GateResult> {
        let hash = Self::device_hash(device);
        let others: i64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT user_id) FROM device_fingerprints WHERE device_hash = ?1 AND (?2 IS NULL OR user_id != ?2)",
            params![hash, user_id],
            |r| r.get(0),
        )?;
        let known: i64 = match user_id {
            Some(u) => self.conn.query_row(
                "SELECT COUNT(*) FROM device_fingerprints WHERE device_hash = ?1 AND user_id = ?2",
                params![hash, u],
                |r| r.get(0),
            )?,
            None => 0,
        };
        let decision = if others < 2 || known > 0 {
            Decision::Pass
        } else if others < 5 {
            Decision::Challenge
        } else {
            Decision::Fail
        };
        self.decide(user_id, "device_fingerprint", decision, json!({ "device_hash": hash, "matching_users": others, "known_device": known > 0 }))
    }

    /// What: gate 5. From the user's latest ledger row: payment added after the trial started and
    /// within trial_days + 5 days -> PASS; more than trial_days + 30 days in and payment added after the
    /// trial ended -> CHALLENGE (late payment entry); trial over, no payment ever, more than 90 days
    /// since it started -> FAIL; anything else PASS. No ledger row -> PASS (no trial to abuse).
    /// In: user, trial length in days. Out: `GateResult`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: database, clock.
    pub fn check_trial_payment_timing(&self, user_id: i64, trial_days: i64) -> SqlResult<GateResult> {
        let row: Option<(Option<String>, Option<String>)> = self
            .conn
            .query_row(
                "SELECT trial_started_at, payment_added_date FROM trial_abuse_ledger
                 WHERE user_id = ?1 AND trial_started_at IS NOT NULL ORDER BY trial_started_at DESC, id DESC LIMIT 1",
                params![user_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let parse = |s: &Option<String>| s.as_deref().and_then(|t| DateTime::parse_from_rfc3339(t).ok()).map(|d| d.with_timezone(&Utc));
        let Some((Some(start), payment)) = row.as_ref().map(|(s, p)| (parse(s), parse(p))) else {
            return self.decide(Some(user_id), "trial_payment_timing", Decision::Pass, json!({ "reason": "no_trial_record" }));
        };
        let now = (self.clock)();
        let days_elapsed = (now - start).num_days();
        let decision = match payment {
            Some(paid) if paid > start => {
                if days_elapsed < trial_days + 5 {
                    Decision::Pass
                } else if days_elapsed > trial_days + 30 && paid > start + Duration::days(trial_days) {
                    Decision::Challenge
                } else {
                    Decision::Pass
                }
            }
            _ => {
                if days_elapsed >= trial_days && days_elapsed > 90 {
                    Decision::Fail
                } else {
                    Decision::Pass
                }
            }
        };
        self.decide(
            Some(user_id),
            "trial_payment_timing",
            decision,
            json!({ "trial_days": trial_days, "days_elapsed": days_elapsed, "payment_added": payment.map(|p| p.to_rfc3339()) }),
        )
    }

    /// What: gate 6. Chargeback events of the user's linked payment-provider customer plus refunds
    /// marked chargebacked: 0 PASS, 1 CHALLENGE, 2+ FAIL. In: user. Out: `GateResult`.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub fn check_chargeback_history(&self, user_id: i64) -> SqlResult<GateResult> {
        let provider_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM stripe_events WHERE type LIKE '%chargeback%' AND customer IN
                (SELECT stripe_customer_id FROM trial_abuse_ledger WHERE user_id = ?1 AND stripe_customer_id IS NOT NULL)",
            params![user_id],
            |r| r.get(0),
        )?;
        let refund_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM refunds WHERE user_id = ?1 AND status = 'chargebacked'",
            params![user_id],
            |r| r.get(0),
        )?;
        let total = provider_count + refund_count;
        let decision = match total {
            0 => Decision::Pass,
            1 => Decision::Challenge,
            _ => Decision::Fail,
        };
        self.decide(Some(user_id), "chargeback_history", decision,
            json!({ "provider_chargebacks": provider_count, "refund_chargebacks": refund_count, "total": total }))
    }

    /// What: record one signup attempt from an IP (input to gate 3). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, clock.
    pub fn insert_signup(&self, ip: &str) -> SqlResult<()> {
        self.conn.execute("INSERT INTO signups (ip, created_at) VALUES (?1, ?2)", params![ip.trim(), (self.clock)().to_rfc3339()])?;
        Ok(())
    }

    /// What: add a ledger row (signup or trial outcome). In: the spec's ledger fields; email is stored
    /// lower-cased. Out: `()`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_trial_abuse_ledger(
        &self,
        user_id: Option<i64>,
        email: Option<&str>,
        stripe_payment_method_id: Option<&str>,
        ip: Option<&str>,
        device_fingerprint: Option<&str>,
        signup_date: Option<&str>,
        trial_started_at: Option<&str>,
        payment_added_date: Option<&str>,
        subscription_status: Option<&str>,
    ) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO trial_abuse_ledger (user_id, email, stripe_payment_method_id, ip, device_fingerprint, signup_date,
                trial_started_at, payment_added_date, subscription_status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![user_id, email.map(|e| e.trim().to_lowercase()), stripe_payment_method_id, ip, device_fingerprint,
                signup_date, trial_started_at, payment_added_date, subscription_status, (self.clock)().to_rfc3339()],
        )?;
        Ok(())
    }

    /// What: link a user to their payment-provider customer id, so gate 6 counts that customer's
    /// chargeback events. Updates the user's ledger rows, or adds one. In: user, customer id.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub fn link_billing_customer(&self, user_id: i64, customer_id: &str) -> SqlResult<()> {
        let n = self.conn.execute(
            "UPDATE trial_abuse_ledger SET stripe_customer_id = ?2 WHERE user_id = ?1",
            params![user_id, customer_id],
        )?;
        if n == 0 {
            self.conn.execute(
                "INSERT INTO trial_abuse_ledger (user_id, stripe_customer_id, created_at) VALUES (?1, ?2, ?3)",
                params![user_id, customer_id, (self.clock)().to_rfc3339()],
            )?;
        }
        Ok(())
    }

    /// What: remember that a user used a device (input to gate 4). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, clock.
    pub fn insert_device_fingerprint(&self, user_id: i64, device: &DeviceInfo) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO device_fingerprints (user_id, device_hash, user_agent, screen_resolution, timezone, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![user_id, Self::device_hash(device), device.user_agent, device.screen_resolution, device.timezone, (self.clock)().to_rfc3339()],
        )?;
        Ok(())
    }

    /// What: record a payment-provider webhook event for a customer (input to gate 6).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub fn insert_stripe_event(&self, customer: &str, event_type: &str) -> SqlResult<()> {
        self.conn.execute("INSERT INTO stripe_events (customer, type) VALUES (?1, ?2)", params![customer, event_type])?;
        Ok(())
    }

    /// What: record a refund and its status (input to gate 6). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
    pub fn insert_refund(&self, user_id: i64, status: &str) -> SqlResult<()> {
        self.conn.execute("INSERT INTO refunds (user_id, status) VALUES (?1, ?2)", params![user_id, status])?;
        Ok(())
    }

    /// What: how many gate decisions were logged (the why-chain), for audits. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
    pub fn gate_decision_count(&self) -> SqlResult<i64> {
        self.conn.query_row("SELECT COUNT(*) FROM gate_decisions", [], |r| r.get(0))
    }
}

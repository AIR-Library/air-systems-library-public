//! Audit logging tests (TIER 2 spec, system: audit_logging).
//! Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, for the AUDIT-08/09/10 amendment: requests now
//! name the data subject (`subject_user_id`, required unless resource_type is 'user'), the actor's IP and
//! user agent are request fields stored as personal data (the old happy-path test put them in metadata,
//! which log() now refuses with 400 metadata_key_not_allowed), reads take an admin `Caller`, and the clock is
//! fixed. AUDIT-01..07 keep their old assertions; AUDIT-05 now loads 1,000,000 entries (the spec's "1M+";
//! the old test loaded 10,000) and keeps the 100 ms budget. Touches: in-memory SQLite only.
use audit_logging_rust::{AuditError, AuditLogger, Caller, LogMutationRequest, QueryLogsParams};
use chrono::{DateTime, Duration, TimeZone, Utc};
use rusqlite::{params, Connection};
use serde_json::json;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// What: a logger on in-memory SQLite whose clock reads `now` (Unix ms); returns both.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
fn setup_clocked() -> (AuditLogger, Arc<AtomicI64>) {
    let now = Arc::new(AtomicI64::new(Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap().timestamp_millis()));
    let clock = now.clone();
    let logger = AuditLogger::new(Connection::open_in_memory().unwrap())
        .with_clock(Box::new(move || DateTime::from_timestamp_millis(clock.load(Ordering::SeqCst)).unwrap()));
    logger.init_db().unwrap();
    (logger, now)
}

/// What: a logger with a fixed clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
fn setup_logger() -> AuditLogger {
    setup_clocked().0
}

/// What: the admin caller used for reads. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn admin() -> Caller {
    Caller::admin("admin_1")
}

/// What: a user-actor request (subject "none" unless set). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn req(actor: &str, action: &str, resource_type: &str, resource_id: &str) -> LogMutationRequest {
    LogMutationRequest {
        actor_id: Some(actor.to_string()),
        actor_type: "user".to_string(),
        subject_user_id: if resource_type == "user" { None } else { Some("none".to_string()) },
        action: action.to_string(),
        resource_type: resource_type.to_string(),
        resource_id: resource_id.to_string(),
        old_value: json!({}),
        new_value: json!({}),
        ..Default::default()
    }
}

/// What: AUDIT-01: log a mutation and query it back, with its snapshots, why-chain id and the actor's
/// IP and user agent. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: ip and user_agent moved from
/// metadata (now refused) to request fields; the entry names its subject; reads take an admin caller.
/// Touches: memory only.
// AUDIT-01
#[test]
fn test_happy_path() {
    let logger = setup_logger();

    let res = logger
        .log_mutation(LogMutationRequest {
            actor_id: Some("123".to_string()),
            actor_type: "user".to_string(),
            subject_user_id: Some("123".to_string()),
            action: "subscription_changed".to_string(),
            resource_type: "subscription".to_string(),
            resource_id: "456".to_string(),
            old_value: json!({ "tier": "team", "billing_date": "2026-10-15" }),
            new_value: json!({ "tier": "enterprise", "billing_date": "2026-10-15" }),
            why_chain_id: Some("wc_789".to_string()),
            ip: Some("127.0.0.1".to_string()),
            user_agent: Some("Mozilla".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert!(res.success);
    assert!(!res.log_id.is_empty());

    // Query it back
    let query_res = logger.query_logs(&admin(), QueryLogsParams { actor_id: Some("123".to_string()), ..Default::default() }).unwrap();

    assert_eq!(query_res.total, 1);
    assert_eq!(query_res.logs.len(), 1);
    let log = &query_res.logs[0];
    assert_eq!(log.id, res.log_id);
    assert_eq!(log.action, "subscription_changed");
    assert_eq!(log.old_value["tier"], "team");
    assert_eq!(log.new_value["tier"], "enterprise");
    assert_eq!(log.resource_id.as_deref(), Some("456"));
    assert_eq!(log.why_chain_id.as_deref(), Some("wc_789"));
    assert_eq!((log.actor_id.as_deref(), log.ip.as_deref(), log.user_agent.as_deref()), (Some("123"), Some("127.0.0.1"), Some("Mozilla")));
    assert!(!log.personal_erased);
}

/// What: AUDIT-02: replay returns the state at the time (old_value) and detects divergence once a newer
/// entry changed the same resource, for an entry about a user (snapshots in its subject row) and for one
/// with no subject. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: subject named, admin caller.
/// Touches: memory only.
// AUDIT-02
#[test]
fn test_replay_and_divergence() {
    for subject in ["123", "none"] {
        let logger = setup_logger();
        let change = |old: serde_json::Value, new: serde_json::Value| LogMutationRequest {
            subject_user_id: Some(subject.to_string()),
            old_value: old,
            new_value: new,
            ..req("123", "subscription_changed", "subscription", "456")
        };
        let res1 = logger.log_mutation(change(json!({ "tier": "free" }), json!({ "tier": "team" }))).unwrap();

        // Replay immediately (no divergence yet)
        let replay1 = logger.replay(&admin(), &res1.log_id).unwrap();
        assert_eq!(replay1.resource_state_at_time["tier"], "free");
        assert_eq!(replay1.has_diverged, Some(false));

        // Log subsequent state change
        let res2 = logger.log_mutation(change(json!({ "tier": "team" }), json!({ "tier": "enterprise" }))).unwrap();

        // Replay first log again (should now be diverged)
        assert_eq!(logger.replay(&admin(), &res1.log_id).unwrap().has_diverged, Some(true));
        // Replay second log (should not be diverged as it is the latest)
        assert_eq!(logger.replay(&admin(), &res2.log_id).unwrap().has_diverged, Some(false));
    }
}

/// What: AUDIT-03: actor_id + action + resource_type filters work together. Changed 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP: requests built with the helper (subject named), admin caller.
/// Touches: memory only.
// AUDIT-03
#[test]
fn test_filtering() {
    let logger = setup_logger();
    logger.log_mutation(LogMutationRequest { new_value: json!({"name": "Alice"}), ..req("user_a", "user_created", "user", "1") }).unwrap();
    logger.log_mutation(req("user_b", "user_suspended", "user", "2")).unwrap();
    logger.log_mutation(req("user_a", "billing_changed", "billing", "3")).unwrap();
    logger.log_mutation(req("user_a", "user_suspended", "user", "4")).unwrap();

    // Filter by actor_id + action + resource_type
    let query_res = logger
        .query_logs(&admin(), QueryLogsParams {
            actor_id: Some("user_a".to_string()),
            action: Some("user_created".to_string()),
            resource_type: Some("user".to_string()),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(query_res.total, 1);
    assert_eq!(query_res.logs[0].actor_id, Some("user_a".to_string()));
    assert_eq!(query_res.logs[0].action, "user_created");
}

/// What: AUDIT-04: limit/offset pagination with total and has_more. Changed 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP: helper requests, admin caller. Touches: memory only.
// AUDIT-04
#[test]
fn test_pagination() {
    let logger = setup_logger();
    for i in 0..5 {
        logger.log_mutation(req("user_pagination", &format!("action_{}", i), "item", &i.to_string())).unwrap();
    }

    // Page 1
    let page1 = logger
        .query_logs(&admin(), QueryLogsParams { actor_id: Some("user_pagination".to_string()), limit: Some(2), offset: Some(0), ..Default::default() })
        .unwrap();
    assert_eq!(page1.total, 5);
    assert_eq!(page1.logs.len(), 2);
    assert!(page1.has_more);

    // Page 3 (last page)
    let page3 = logger
        .query_logs(&admin(), QueryLogsParams { actor_id: Some("user_pagination".to_string()), limit: Some(2), offset: Some(4), ..Default::default() })
        .unwrap();
    assert_eq!(page3.total, 5);
    assert_eq!(page3.logs.len(), 1);
    assert!(!page3.has_more);
    // newest first, ties by insertion: the last page holds the first entry
    assert_eq!(page3.logs[0].action, "action_0");
}

/// What: AUDIT-06: UPDATE and DELETE on audit_log are refused; an audit_personal row cannot be updated
/// either. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the audit_personal check was added.
/// Touches: memory only.
// AUDIT-06
#[test]
fn test_immutability() {
    let logger = setup_logger();
    let res = logger.log_mutation(req("123", "user_created", "user", "456")).unwrap();

    let conn = logger.conn.lock().unwrap();

    // Attempt UPDATE
    let update_res = conn.execute("UPDATE audit_log SET action = 'hacked' WHERE id = ?1", params![res.log_id]);
    assert!(update_res.is_err());
    assert!(update_res.unwrap_err().to_string().contains("Audit logs are immutable"));

    // Attempt DELETE
    let delete_res = conn.execute("DELETE FROM audit_log WHERE id = ?1", params![res.log_id]);
    assert!(delete_res.is_err());
    assert!(delete_res.unwrap_err().to_string().contains("Audit logs are immutable"));

    // personal rows are never updated
    let personal = conn.execute("UPDATE audit_personal SET data = '{}' WHERE log_id = ?1", params![res.log_id]);
    assert!(personal.is_err());
}

/// What: AUDIT-07: action='user_*' matches user_created and user_suspended, not billing_changed, and the
/// `_` in the filter is literal (it does not match "userXdeleted"). Changed 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP: helper requests, admin caller, literal-underscore check added.
/// Touches: memory only.
// AUDIT-07
#[test]
fn test_wildcard() {
    let logger = setup_logger();
    logger.log_mutation(req("123", "user_created", "user", "1")).unwrap();
    logger.log_mutation(req("123", "user_suspended", "user", "2")).unwrap();
    logger.log_mutation(req("123", "billing_changed", "billing", "3")).unwrap();
    logger.log_mutation(req("123", "userXdeleted", "item", "4")).unwrap();

    let query_res = logger.query_logs(&admin(), QueryLogsParams { action: Some("user_*".to_string()), ..Default::default() }).unwrap();

    assert_eq!(query_res.total, 2);
    assert!(query_res.logs.iter().any(|l| l.action == "user_created"));
    assert!(query_res.logs.iter().any(|l| l.action == "user_suspended"));
    assert!(!query_res.logs.iter().any(|l| l.action == "billing_changed"));
    assert!(!query_res.logs.iter().any(|l| l.action == "userXdeleted"));
}

/// What: AUDIT-05: with 1,000,000 entries (1,000 actors), a query on actor + action + resource_type returns
/// its 500 matches in under 100 ms. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the old test
/// loaded 10,000 rows into a one-table schema; it now loads the spec's 1M+ into the three-table schema
/// (event row plus the actor's personal row). The budget is unchanged. Touches: memory only.
// AUDIT-05
#[test]
fn test_performance() {
    let logger = setup_logger();
    {
        let mut conn = logger.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        {
            let mut subject = tx.prepare("INSERT INTO audit_subjects (subject_ref, user_id, created_at) VALUES (?1, ?2, '2026-01-01T00:00:00.000Z')").unwrap();
            for a in 0..1000 {
                subject.execute(params![format!("ref_{:04}", a), format!("actor_{}", a)]).unwrap();
            }
            let mut log = tx
                .prepare(
                    "INSERT INTO audit_log (id, timestamp, actor_type, action, resource_type, resource_id, old_value, new_value, personal_roles, metadata)
                     VALUES (?1, '2026-10-15T14:30:00.000Z', 'user', ?2, 'item', ?3, '{}', '{}', 'actor', '{}')",
                )
                .unwrap();
            let mut personal = tx.prepare("INSERT INTO audit_personal (log_id, subject_ref, role, data) VALUES (?1, ?2, 'actor', ?3)").unwrap();
            for i in 0..1_000_000 {
                let id = format!("perf_{}", i);
                let actor = i % 1000;
                // 500 user_created entries per actor: (1,000,000 / 1,000) / 2
                let action = if (i / 1000) % 2 == 0 { "user_created" } else { "billing_changed" };
                log.execute(params![id, action, i.to_string()]).unwrap();
                personal.execute(params![id, format!("ref_{:04}", actor), format!("{{\"actor_id\":\"actor_{}\"}}", actor)]).unwrap();
            }
        }
        tx.commit().unwrap();
    }

    // Measure query performance
    let start = Instant::now();
    let query_res = logger
        .query_logs(&admin(), QueryLogsParams {
            actor_id: Some("actor_5".to_string()),
            action: Some("user_created".to_string()),
            resource_type: Some("item".to_string()),
            limit: Some(100),
            ..Default::default()
        })
        .unwrap();
    let duration = start.elapsed();

    assert_eq!(query_res.total, 500);
    assert_eq!(query_res.logs.len(), 100);
    assert!(duration.as_millis() < 100, "Query took too long: {}ms", duration.as_millis());
}

/// What: every column of every row of a table, as text, for leak checks. 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
fn dump(logger: &AuditLogger, table: &str) -> Vec<String> {
    let conn = logger.conn.lock().unwrap();
    let mut stmt = conn.prepare(&format!("SELECT * FROM {} ORDER BY rowid", table)).unwrap();
    let n = stmt.column_count();
    let rows = stmt
        .query_map([], |r| {
            let mut cols = Vec::new();
            for i in 0..n {
                cols.push(match r.get::<_, rusqlite::types::Value>(i)? {
                    rusqlite::types::Value::Null => "NULL".to_string(),
                    rusqlite::types::Value::Integer(v) => v.to_string(),
                    rusqlite::types::Value::Real(v) => v.to_string(),
                    rusqlite::types::Value::Text(t) => t,
                    rusqlite::types::Value::Blob(b) => format!("{:?}", b),
                });
            }
            Ok(cols.join("|"))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    rows
}

/// What: AUDIT-08: after erase_subject(987654321) no retained row of audit_log, audit_personal or
/// audit_subjects holds the user's id, email (erase.me@example.test) or IP (203.0.113.77); every earlier
/// audit_log row is unchanged and exactly one row is added ('audit_subject_erased', personal_roles '',
/// metadata {erased_rows}); queries show the user's entries with personal_erased true (another user's
/// data in a shared entry is kept); an actor_id filter for the user finds nothing; replay of an erased
/// subject entry says erased. In: none. Out: panics on a leak. Why: 2026-11-10 amendment (AUDIT-08).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
// AUDIT-08
#[test]
fn test_erase_subject_leaves_nothing_identifying() {
    let logger = setup_logger();
    let (uid, email, ip) = ("987654321", "erase.me@example.test", "203.0.113.77");
    // the user signs up (actor and subject), changes a subscription about themself, uses an API key,
    // and an admin suspends them; another user's entry stays as it is
    let signup = logger
        .log_mutation(LogMutationRequest {
            new_value: json!({ "email": email, "signup_ip": ip }),
            ip: Some(ip.into()),
            user_agent: Some("Mozilla".into()),
            request_id: Some("req-1".into()),
            ..req(uid, "user_created", "user", uid)
        })
        .unwrap();
    let sub = logger
        .log_mutation(LogMutationRequest {
            subject_user_id: Some(uid.into()),
            old_value: json!({ "billing_email": email }),
            new_value: json!({ "billing_email": email, "tier": "team" }),
            why_chain_id: Some(format!("wc_{}", uid)),
            ip: Some(ip.into()),
            ..req(uid, "subscription_changed", "subscription", "sub_1")
        })
        .unwrap();
    logger
        .log_mutation(LogMutationRequest {
            actor_type: "api_key".into(),
            actor_id: Some("key_42".into()),
            actor_user_id: Some(uid.into()),
            ip: Some(ip.into()),
            ..req("key_42", "deployment_published", "deployment", "dep_1")
        })
        .unwrap();
    let suspend = logger
        .log_mutation(LogMutationRequest { old_value: json!({ "email": email }), ip: Some("198.51.100.1".into()), ..req("admin_7", "user_suspended", "user", uid) })
        .unwrap();
    logger
        .log_mutation(LogMutationRequest { new_value: json!({ "email": "keep@example.test" }), ip: Some("198.51.100.2".into()), ..req("555", "user_created", "user", "555") })
        .unwrap();

    let before = dump(&logger, "audit_log");
    let erased = logger.erase_subject(uid).unwrap();
    assert_eq!(erased.erased_rows, 6); // actor x3 + subject x3

    let after = dump(&logger, "audit_log");
    assert_eq!(after.len(), before.len() + 1, "exactly one row added");
    assert_eq!(&after[..before.len()], &before[..], "earlier rows unchanged");
    let added = logger.query_logs(&admin(), QueryLogsParams { action: Some("audit_subject_erased".into()), ..Default::default() }).unwrap();
    assert_eq!(added.total, 1);
    assert_eq!((added.logs[0].personal_roles.as_str(), added.logs[0].actor_type.as_str()), ("", "service"));
    assert_eq!(added.logs[0].metadata, json!({ "erased_rows": 6 }));
    assert_eq!(added.logs[0].resource_id, None);

    for table in ["audit_log", "audit_personal", "audit_subjects"] {
        for row in dump(&logger, table) {
            for secret in [uid, email, ip] {
                assert!(!row.contains(secret), "{} still holds {:?}: {}", table, secret, row);
            }
        }
    }

    let all = logger.query_logs(&admin(), QueryLogsParams::default()).unwrap();
    let by_id = |id: &str| all.logs.iter().find(|l| l.id == id).unwrap().clone();
    assert!(by_id(&signup.log_id).personal_erased);
    assert_eq!(by_id(&signup.log_id).ip, None);
    assert!(by_id(&sub.log_id).personal_erased);
    assert_eq!(by_id(&sub.log_id).new_value, serde_json::Value::Null);
    let s = by_id(&suspend.log_id);
    assert!(s.personal_erased);
    assert_eq!(s.actor_id.as_deref(), Some("admin_7"), "the admin's own actor row is not the user's to erase");
    assert_eq!(logger.query_logs(&admin(), QueryLogsParams { actor_id: Some(uid.into()), ..Default::default() }).unwrap().total, 0);
    let replay = logger.replay(&admin(), &sub.log_id).unwrap();
    assert_eq!((replay.erased, replay.resource_state_at_time.clone(), replay.has_diverged), (true, serde_json::Value::Null, None));
    assert!(logger.search(&admin(), email, None, None).unwrap().results.is_empty());
}

/// What: AUDIT-09: apply_retention erases the personal data of entries older than the retention period
/// (and subjects left with none); newer entries keep theirs; no audit_log row is removed.
/// In: none. Out: panics on a wrong answer. Why: 2026-11-10 amendment (AUDIT-09).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
// AUDIT-09
#[test]
fn test_apply_retention_erases_old_personal_data_only() {
    let (logger, now) = setup_clocked();
    let logger = logger.with_retention_days(30);
    let old = logger.log_mutation(LogMutationRequest { ip: Some("192.0.2.10".into()), ..req("old_user", "user_created", "user", "old_user") }).unwrap();
    now.fetch_add(Duration::days(20).num_milliseconds(), Ordering::SeqCst);
    let new = logger.log_mutation(LogMutationRequest { ip: Some("192.0.2.11".into()), ..req("new_user", "user_created", "user", "new_user") }).unwrap();
    let rows_before = dump(&logger, "audit_log");

    let at = DateTime::from_timestamp_millis(now.load(Ordering::SeqCst)).unwrap() + Duration::days(15);
    let res = logger.apply_retention(at).unwrap();
    assert_eq!(res.erased_rows, 2); // the old entry's actor and subject rows

    assert_eq!(dump(&logger, "audit_log"), rows_before, "no audit_log row removed or changed");
    let all = logger.query_logs(&admin(), QueryLogsParams::default()).unwrap();
    let old_e = all.logs.iter().find(|l| l.id == old.log_id).unwrap();
    let new_e = all.logs.iter().find(|l| l.id == new.log_id).unwrap();
    assert!(old_e.personal_erased);
    assert_eq!(old_e.ip, None);
    assert!(!new_e.personal_erased);
    assert_eq!(new_e.ip.as_deref(), Some("192.0.2.11"));
    let subjects = dump(&logger, "audit_subjects");
    assert_eq!(subjects.len(), 1);
    assert!(subjects[0].contains("new_user"));
}

/// What: AUDIT-10: log() refuses a non-'user' entry without subject_user_id (400 subject_required), a
/// metadata key other than feature_flag / erased_rows (400 metadata_key_not_allowed), an api_key entry
/// without actor_user_id (400 actor_user_required) and a 'user' entry whose subject_user_id is not its
/// resource id (400 subject_mismatch); nothing is written for a refused entry; reads (query, replay,
/// search) by a non-admin caller get 403. In: none. Out: panics on a wrong answer.
/// Why: 2026-11-10 amendment (AUDIT-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
// AUDIT-10
#[test]
fn test_log_validation_and_admin_only_reads() {
    let logger = setup_logger();
    let refused = |r: LogMutationRequest| logger.log_mutation(r).unwrap_err();
    let e = refused(LogMutationRequest { subject_user_id: None, ..req("1", "plan_changed", "subscription", "s1") });
    assert_eq!((e.code(), e.status()), ("subject_required", 400));
    let e = refused(LogMutationRequest { metadata: Some(json!({ "ip": "192.0.2.1" })), ..req("1", "plan_changed", "subscription", "s1") });
    assert_eq!((e.code(), e.status()), ("metadata_key_not_allowed", 400));
    let e = refused(LogMutationRequest { actor_type: "api_key".into(), actor_id: Some("key_1".into()), ..req("key_1", "plan_changed", "subscription", "s1") });
    assert_eq!((e.code(), e.status()), ("actor_user_required", 400));
    let e = refused(LogMutationRequest { subject_user_id: Some("2".into()), ..req("1", "user_suspended", "user", "3") });
    assert_eq!((e.code(), e.status()), ("subject_mismatch", 400));
    assert!(dump(&logger, "audit_log").is_empty());
    assert!(dump(&logger, "audit_personal").is_empty());
    // allowed metadata keys pass
    let ok = logger.log_mutation(LogMutationRequest { metadata: Some(json!({ "feature_flag": "new_billing" })), ..req("1", "plan_changed", "subscription", "s1") }).unwrap();

    let user = Caller::user("1");
    assert_eq!(logger.query_logs(&user, QueryLogsParams::default()).unwrap_err(), AuditError::Forbidden);
    assert_eq!(logger.replay(&user, &ok.log_id).unwrap_err().status(), 403);
    assert_eq!(logger.search(&user, "plan", None, None).unwrap_err().to_response().1, 403);
    assert_eq!(logger.query_logs(&admin(), QueryLogsParams::default()).unwrap().total, 1);
}

use audit_logging_rust::{AuditLogger, LogMutationRequest, QueryLogsParams};
use rusqlite::{params, Connection};
use serde_json::json;
use std::time::Instant;

fn setup_logger() -> AuditLogger {
    let conn = Connection::open_in_memory().unwrap();
    let logger = AuditLogger::new(conn);
    logger.init_db().unwrap();
    logger
}

#[test]
fn test_happy_path() {
    let logger = setup_logger();

    let req = LogMutationRequest {
        actor_id: Some("123".to_string()),
        actor_type: "user".to_string(),
        action: "subscription_changed".to_string(),
        resource_type: "subscription".to_string(),
        resource_id: "456".to_string(),
        old_value: json!({ "tier": "team", "billing_date": "2026-10-15" }),
        new_value: json!({ "tier": "enterprise", "billing_date": "2026-10-15" }),
        why_chain_id: Some("wc_789".to_string()),
        metadata: Some(json!({ "ip": "127.0.0.1", "user_agent": "Mozilla" })),
    };

    let res = logger.log_mutation(req).unwrap();
    assert!(res.success);
    assert!(!res.log_id.is_empty());

    // Query it back
    let query_res = logger.query_logs(QueryLogsParams {
        actor_id: Some("123".to_string()),
        ..Default::default()
    }).unwrap();

    assert_eq!(query_res.total, 1);
    assert_eq!(query_res.logs.len(), 1);
    assert_eq!(query_res.logs[0].id, res.log_id);
    assert_eq!(query_res.logs[0].action, "subscription_changed");
    assert_eq!(query_res.logs[0].old_value["tier"], "team");
    assert_eq!(query_res.logs[0].new_value["tier"], "enterprise");
}

#[test]
fn test_replay_and_divergence() {
    let logger = setup_logger();

    // Log initial state
    let res1 = logger.log_mutation(LogMutationRequest {
        actor_id: Some("123".to_string()),
        actor_type: "user".to_string(),
        action: "subscription_changed".to_string(),
        resource_type: "subscription".to_string(),
        resource_id: "456".to_string(),
        old_value: json!({ "tier": "free" }),
        new_value: json!({ "tier": "team" }),
        why_chain_id: None,
        metadata: None,
    }).unwrap();

    // Replay immediately (no divergence yet)
    let replay1 = logger.replay(&res1.log_id).unwrap();
    assert_eq!(replay1.resource_state_at_time["tier"], "free");
    assert!(!replay1.has_diverged);

    // Log subsequent state change
    let res2 = logger.log_mutation(LogMutationRequest {
        actor_id: Some("123".to_string()),
        actor_type: "user".to_string(),
        action: "subscription_changed".to_string(),
        resource_type: "subscription".to_string(),
        resource_id: "456".to_string(),
        old_value: json!({ "tier": "team" }),
        new_value: json!({ "tier": "enterprise" }),
        why_chain_id: None,
        metadata: None,
    }).unwrap();

    // Replay first log again (should now be diverged)
    let replay1_after = logger.replay(&res1.log_id).unwrap();
    assert!(replay1_after.has_diverged);

    // Replay second log (should not be diverged as it is the latest)
    let replay2 = logger.replay(&res2.log_id).unwrap();
    assert!(!replay2.has_diverged);
}

#[test]
fn test_filtering() {
    let logger = setup_logger();

    // Log 1
    logger.log_mutation(LogMutationRequest {
        actor_id: Some("user_a".to_string()),
        actor_type: "user".to_string(),
        action: "user_created".to_string(),
        resource_type: "user".to_string(),
        resource_id: "1".to_string(),
        old_value: json!({}),
        new_value: json!({"name": "Alice"}),
        why_chain_id: None,
        metadata: None,
    }).unwrap();

    // Log 2
    logger.log_mutation(LogMutationRequest {
        actor_id: Some("user_b".to_string()),
        actor_type: "user".to_string(),
        action: "user_suspended".to_string(),
        resource_type: "user".to_string(),
        resource_id: "2".to_string(),
        old_value: json!({"status": "active"}),
        new_value: json!({"status": "suspended"}),
        why_chain_id: None,
        metadata: None,
    }).unwrap();

    // Log 3
    logger.log_mutation(LogMutationRequest {
        actor_id: Some("user_a".to_string()),
        actor_type: "user".to_string(),
        action: "billing_changed".to_string(),
        resource_type: "billing".to_string(),
        resource_id: "3".to_string(),
        old_value: json!({}),
        new_value: json!({}),
        why_chain_id: None,
        metadata: None,
    }).unwrap();

    // Filter by actor_id + action + resource_type
    let query_res = logger.query_logs(QueryLogsParams {
        actor_id: Some("user_a".to_string()),
        action: Some("user_created".to_string()),
        resource_type: Some("user".to_string()),
        ..Default::default()
    }).unwrap();

    assert_eq!(query_res.total, 1);
    assert_eq!(query_res.logs[0].actor_id, Some("user_a".to_string()));
    assert_eq!(query_res.logs[0].action, "user_created");
}

#[test]
fn test_pagination() {
    let logger = setup_logger();

    for i in 0..5 {
        logger.log_mutation(LogMutationRequest {
            actor_id: Some("user_pagination".to_string()),
            actor_type: "user".to_string(),
            action: format!("action_{}", i),
            resource_type: "item".to_string(),
            resource_id: i.to_string(),
            old_value: json!({}),
            new_value: json!({}),
            why_chain_id: None,
            metadata: None,
        }).unwrap();
    }

    // Page 1
    let page1 = logger.query_logs(QueryLogsParams {
        actor_id: Some("user_pagination".to_string()),
        limit: Some(2),
        offset: Some(0),
        ..Default::default()
    }).unwrap();

    assert_eq!(page1.total, 5);
    assert_eq!(page1.logs.len(), 2);
    assert!(page1.has_more);

    // Page 3 (last page)
    let page3 = logger.query_logs(QueryLogsParams {
        actor_id: Some("user_pagination".to_string()),
        limit: Some(2),
        offset: Some(4),
        ..Default::default()
    }).unwrap();

    assert_eq!(page3.total, 5);
    assert_eq!(page3.logs.len(), 1);
    assert!(!page3.has_more);
}

#[test]
fn test_immutability() {
    let logger = setup_logger();

    let res = logger.log_mutation(LogMutationRequest {
        actor_id: Some("123".to_string()),
        actor_type: "user".to_string(),
        action: "user_created".to_string(),
        resource_type: "user".to_string(),
        resource_id: "456".to_string(),
        old_value: json!({}),
        new_value: json!({}),
        why_chain_id: None,
        metadata: None,
    }).unwrap();

    let conn = logger.conn.lock().unwrap();

    // Attempt UPDATE
    let update_res = conn.execute(
        "UPDATE audit_log SET action = 'hacked' WHERE id = ?1",
        params![res.log_id],
    );
    assert!(update_res.is_err());
    assert!(update_res.unwrap_err().to_string().contains("Audit logs are immutable"));

    // Attempt DELETE
    let delete_res = conn.execute(
        "DELETE FROM audit_log WHERE id = ?1",
        params![res.log_id],
    );
    assert!(delete_res.is_err());
    assert!(delete_res.unwrap_err().to_string().contains("Audit logs are immutable"));
}

#[test]
fn test_wildcard() {
    let logger = setup_logger();

    logger.log_mutation(LogMutationRequest {
        actor_id: Some("123".to_string()),
        actor_type: "user".to_string(),
        action: "user_created".to_string(),
        resource_type: "user".to_string(),
        resource_id: "1".to_string(),
        old_value: json!({}),
        new_value: json!({}),
        why_chain_id: None,
        metadata: None,
    }).unwrap();

    logger.log_mutation(LogMutationRequest {
        actor_id: Some("123".to_string()),
        actor_type: "user".to_string(),
        action: "user_suspended".to_string(),
        resource_type: "user".to_string(),
        resource_id: "2".to_string(),
        old_value: json!({}),
        new_value: json!({}),
        why_chain_id: None,
        metadata: None,
    }).unwrap();

    logger.log_mutation(LogMutationRequest {
        actor_id: Some("123".to_string()),
        actor_type: "user".to_string(),
        action: "billing_changed".to_string(),
        resource_type: "billing".to_string(),
        resource_id: "3".to_string(),
        old_value: json!({}),
        new_value: json!({}),
        why_chain_id: None,
        metadata: None,
    }).unwrap();

    let query_res = logger.query_logs(QueryLogsParams {
        action: Some("user_*".to_string()),
        ..Default::default()
    }).unwrap();

    assert_eq!(query_res.total, 2);
    assert!(query_res.logs.iter().any(|l| l.action == "user_created"));
    assert!(query_res.logs.iter().any(|l| l.action == "user_suspended"));
    assert!(!query_res.logs.iter().any(|l| l.action == "billing_changed"));
}

#[test]
fn test_performance() {
    let logger = setup_logger();
    let mut conn = logger.conn.lock().unwrap();

    // Insert 10,000 logs inside a transaction for speed
    let tx = conn.transaction().unwrap();
    {
        let mut stmt = tx.prepare(
            "INSERT INTO audit_log (id, timestamp, actor_id, actor_type, action, resource_type, resource_id, old_value, new_value, why_chain_id, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
        ).unwrap();

        for i in 0..10000 {
            let id = format!("perf_{}", i);
            let timestamp = "2026-10-15T14:30:00.000Z".to_string();
            let actor_id = Some(format!("actor_{}", i % 10));
            let actor_type = "user".to_string();
            // Use (i / 10) % 2 so action is independent of actor_id modulo,
            // giving ~500 user_created entries per actor (10000 / 10 / 2 = 500).
            let action = if (i / 10) % 2 == 0 { "user_created" } else { "billing_changed" };
            let resource_type = "user".to_string();
            let resource_id = format!("res_{}", i);
            let old_value = "{}";
            let new_value = "{}";
            let why_chain_id = None::<String>;
            let metadata = "{}";

            stmt.execute(params![
                id,
                timestamp,
                actor_id,
                actor_type,
                action,
                resource_type,
                resource_id,
                old_value,
                new_value,
                why_chain_id,
                metadata
            ]).unwrap();
        }
    }
    tx.commit().unwrap();
    drop(conn); // Release lock for query_logs

    // Measure query performance
    let start = Instant::now();
    let query_res = logger.query_logs(QueryLogsParams {
        actor_id: Some("actor_5".to_string()),
        action: Some("user_created".to_string()),
        resource_type: Some("user".to_string()),
        limit: Some(100),
        ..Default::default()
    }).unwrap();

    let duration = start.elapsed();

    assert_eq!(query_res.total, 500); // 10000 / 10 actors / 2 actions = 500
    assert!(duration.as_millis() < 100, "Query took too long: {}ms", duration.as_millis());
}

use chrono::Utc;
use rusqlite::{params, Connection, Result as RusqliteResult, Row};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub timestamp: String,
    pub actor_id: Option<String>,
    pub actor_type: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub old_value: Value,
    pub new_value: Value,
    pub why_chain_id: Option<String>,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogMutationRequest {
    pub actor_id: Option<String>,
    pub actor_type: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub old_value: Value,
    pub new_value: Value,
    pub why_chain_id: Option<String>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogMutationResponse {
    pub success: bool,
    pub log_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct QueryLogsParams {
    pub actor_id: Option<String>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub date_from: Option<String>,
    pub date_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLogsResponse {
    pub logs: Vec<AuditLogEntry>,
    pub total: usize,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResponse {
    pub log_id: String,
    pub timestamp: String,
    pub resource_state_at_time: Value,
    pub has_diverged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResponse {
    pub results: Vec<AuditLogEntry>,
}

pub struct AuditLogger {
    pub conn: Mutex<Connection>,
}

impl AuditLogger {
    pub fn new(conn: Connection) -> Self {
        Self {
            conn: Mutex::new(conn),
        }
    }

    pub fn init_db(&self) -> RusqliteResult<()> {
        let conn = self.conn.lock().unwrap();

        // Create table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                actor_id TEXT,
                actor_type TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                old_value TEXT NOT NULL,
                new_value TEXT NOT NULL,
                why_chain_id TEXT,
                metadata TEXT NOT NULL
            );",
            [],
        )?;

        // Create indexes for fast queries
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_log_query
             ON audit_log(actor_id, action, resource_type, timestamp);",
            [],
        )?;

        // Create triggers to enforce immutability
        conn.execute(
            "CREATE TRIGGER IF NOT EXISTS audit_log_prevent_update
             BEFORE UPDATE ON audit_log
             BEGIN
                 SELECT RAISE(FAIL, 'Audit logs are immutable and cannot be updated');
             END;",
            [],
        )?;

        conn.execute(
            "CREATE TRIGGER IF NOT EXISTS audit_log_prevent_delete
             BEFORE DELETE ON audit_log
             BEGIN
                 SELECT RAISE(FAIL, 'Audit logs are immutable and cannot be deleted');
             END;",
            [],
        )?;

        Ok(())
    }

    pub fn log_mutation(&self, req: LogMutationRequest) -> RusqliteResult<LogMutationResponse> {
        let conn = self.conn.lock().unwrap();
        let log_id = Uuid::new_v4().to_string();
        let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        let old_value_str = serde_json::to_string(&req.old_value).unwrap_or_else(|_| "{}".to_string());
        let new_value_str = serde_json::to_string(&req.new_value).unwrap_or_else(|_| "{}".to_string());
        let metadata_str = serde_json::to_string(&req.metadata.unwrap_or_else(|| serde_json::json!({}))).unwrap_or_else(|_| "{}".to_string());

        conn.execute(
            "INSERT INTO audit_log (id, timestamp, actor_id, actor_type, action, resource_type, resource_id, old_value, new_value, why_chain_id, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                log_id,
                timestamp,
                req.actor_id,
                req.actor_type,
                req.action,
                req.resource_type,
                req.resource_id,
                old_value_str,
                new_value_str,
                req.why_chain_id,
                metadata_str
            ],
        )?;

        Ok(LogMutationResponse {
            success: true,
            log_id,
        })
    }

    pub fn query_logs(&self, params_filter: QueryLogsParams) -> RusqliteResult<QueryLogsResponse> {
        let conn = self.conn.lock().unwrap();

        let mut conditions = Vec::new();
        let mut sql_params: Vec<rusqlite::types::Value> = Vec::new();

        if let Some(ref actor_id) = params_filter.actor_id {
            conditions.push("actor_id = ?".to_string());
            sql_params.push(rusqlite::types::Value::Text(actor_id.clone()));
        }

        if let Some(ref action) = params_filter.action {
            if action.contains('*') {
                conditions.push("action LIKE ?".to_string());
                sql_params.push(rusqlite::types::Value::Text(action.replace('*', "%")));
            } else {
                conditions.push("action = ?".to_string());
                sql_params.push(rusqlite::types::Value::Text(action.clone()));
            }
        }

        if let Some(ref resource_type) = params_filter.resource_type {
            conditions.push("resource_type = ?".to_string());
            sql_params.push(rusqlite::types::Value::Text(resource_type.clone()));
        }

        if let Some(ref date_from) = params_filter.date_from {
            conditions.push("timestamp >= ?".to_string());
            sql_params.push(rusqlite::types::Value::Text(date_from.clone()));
        }

        if let Some(ref date_to) = params_filter.date_to {
            conditions.push("timestamp <= ?".to_string());
            sql_params.push(rusqlite::types::Value::Text(date_to.clone()));
        }

        let where_clause = if conditions.is_empty() {
            "".to_string()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        // Count total matching
        let count_sql = format!("SELECT COUNT(*) FROM audit_log {}", where_clause);
        let mut count_stmt = conn.prepare(&count_sql)?;
        let total: usize = count_stmt.query_row(rusqlite::params_from_iter(sql_params.iter()), |row| row.get(0))?;

        // Fetch paginated logs
        let limit = params_filter.limit.unwrap_or(100);
        let offset = params_filter.offset.unwrap_or(0);

        let query_sql = format!(
            "SELECT id, timestamp, actor_id, actor_type, action, resource_type, resource_id, old_value, new_value, why_chain_id, metadata
             FROM audit_log {}
             ORDER BY timestamp DESC, id DESC
             LIMIT ? OFFSET ?",
            where_clause
        );

        let mut select_params = sql_params;
        select_params.push(rusqlite::types::Value::Integer(limit as i64));
        select_params.push(rusqlite::types::Value::Integer(offset as i64));

        let mut stmt = conn.prepare(&query_sql)?;
        let log_rows = stmt.query_map(rusqlite::params_from_iter(select_params.iter()), |row| {
            Self::map_row_to_entry(row)
        })?;

        let mut logs = Vec::new();
        for log_res in log_rows {
            logs.push(log_res?);
        }

        let has_more = offset + logs.len() < total;

        Ok(QueryLogsResponse {
            logs,
            total,
            has_more,
        })
    }

    pub fn replay(&self, log_id: &str) -> RusqliteResult<ReplayResponse> {
        let conn = self.conn.lock().unwrap();

        // Fetch target log
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, actor_id, actor_type, action, resource_type, resource_id, old_value, new_value, why_chain_id, metadata
             FROM audit_log WHERE id = ?1"
        )?;

        let target_log = stmt.query_row([log_id], |row| Self::map_row_to_entry(row))?;

        // Check if state has diverged since this log. Two writes can share a millisecond and ids are random,
        // so rowid, the insertion order, breaks the tie. Found by CI on 2026-11-05, session f3daac6e.
        // Divergence is defined as: is there any newer log for this resource that has a different state?
        let mut latest_stmt = conn.prepare(
            "SELECT id, timestamp, new_value
             FROM audit_log
             WHERE resource_type = ?1 AND resource_id = ?2
             ORDER BY timestamp DESC, rowid DESC LIMIT 1"
        )?;

        let latest_log = latest_stmt.query_row(
            params![target_log.resource_type, target_log.resource_id],
            |row| {
                let id: String = row.get(0)?;
                let timestamp: String = row.get(1)?;
                let new_value_str: String = row.get(2)?;
                let new_value: Value = serde_json::from_str(&new_value_str).unwrap_or(Value::Null);
                Ok((id, timestamp, new_value))
            }
        )?;

        let has_diverged = latest_log.0 != target_log.id && latest_log.2 != target_log.new_value;

        Ok(ReplayResponse {
            log_id: target_log.id,
            timestamp: target_log.timestamp,
            resource_state_at_time: target_log.old_value,
            has_diverged,
        })
    }

    pub fn search(&self, q: &str, resource_type: Option<&str>, limit: Option<usize>) -> RusqliteResult<SearchResponse> {
        let conn = self.conn.lock().unwrap();
        let limit_val = limit.unwrap_or(50);
        let search_pattern = format!("%{}%", q);

        let mut query_sql = "SELECT id, timestamp, actor_id, actor_type, action, resource_type, resource_id, old_value, new_value, why_chain_id, metadata
                             FROM audit_log
                             WHERE (action LIKE ?1 OR resource_id LIKE ?1 OR old_value LIKE ?1 OR new_value LIKE ?1 OR metadata LIKE ?1)".to_string();

        let mut sql_params: Vec<rusqlite::types::Value> = vec![rusqlite::types::Value::Text(search_pattern)];

        if let Some(rt) = resource_type {
            query_sql.push_str(" AND resource_type = ?2");
            sql_params.push(rusqlite::types::Value::Text(rt.to_string()));
            sql_params.push(rusqlite::types::Value::Integer(limit_val as i64));
            query_sql.push_str(" ORDER BY timestamp DESC LIMIT ?3");
        } else {
            sql_params.push(rusqlite::types::Value::Integer(limit_val as i64));
            query_sql.push_str(" ORDER BY timestamp DESC LIMIT ?2");
        }

        let mut stmt = conn.prepare(&query_sql)?;
        let log_rows = stmt.query_map(rusqlite::params_from_iter(sql_params.iter()), |row| {
            Self::map_row_to_entry(row)
        })?;

        let mut results = Vec::new();
        for log_res in log_rows {
            results.push(log_res?);
        }

        Ok(SearchResponse { results })
    }

    fn map_row_to_entry(row: &Row) -> RusqliteResult<AuditLogEntry> {
        let old_value_str: String = row.get(7)?;
        let new_value_str: String = row.get(8)?;
        let metadata_str: String = row.get(10)?;

        let old_value: Value = serde_json::from_str(&old_value_str).unwrap_or(Value::Null);
        let new_value: Value = serde_json::from_str(&new_value_str).unwrap_or(Value::Null);
        let metadata: Value = serde_json::from_str(&metadata_str).unwrap_or(Value::Null);

        Ok(AuditLogEntry {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            actor_id: row.get(2)?,
            actor_type: row.get(3)?,
            action: row.get(4)?,
            resource_type: row.get(5)?,
            resource_id: row.get(6)?,
            old_value,
            new_value,
            why_chain_id: row.get(9)?,
            metadata,
        })
    }
}

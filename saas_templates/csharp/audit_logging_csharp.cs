using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;

namespace AuditLogging
{
    public enum ActorType
    {
        User,
        Service,
        ApiKey
    }

    public class AuditLogEntry
    {
        public string Id { get; set; }
        public DateTime Timestamp { get; set; }
        public long? ActorId { get; set; }
        public ActorType? ActorType { get; set; }
        public string Action { get; set; }
        public string ResourceType { get; set; }
        public string ResourceId { get; set; }
        public JsonElement? OldValue { get; set; }
        public JsonElement? NewValue { get; set; }
        public string WhyChainId { get; set; }
        public JsonElement? Metadata { get; set; }
    }

    public class ReplayResult
    {
        public string LogId { get; set; }
        public DateTime Timestamp { get; set; }
        public JsonElement? ResourceStateAtTime { get; set; }
        public bool HasDiverged { get; set; }
    }

    public class AuditLogRepository : IDisposable
    {
        private readonly DbConnection _connection;
        private bool _disposed;

        public AuditLogRepository(DbConnection connection)
        {
            _connection = connection ?? throw new ArgumentNullException(nameof(connection));
            if (_connection.State != ConnectionState.Open)
            {
                _connection.Open();
            }
            CreateSchema();
        }

        private void CreateSchema()
        {
            var sql = @"
                CREATE TABLE IF NOT EXISTS audit_log (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    actor_id INTEGER,
                    actor_type TEXT,
                    action TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    old_value TEXT,
                    new_value TEXT,
                    why_chain_id TEXT,
                    metadata TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_audit_log_actor_action_resource_timestamp
                    ON audit_log(actor_id, action, resource_type, timestamp);
                CREATE TRIGGER IF NOT EXISTS prevent_audit_log_update
                    BEFORE UPDATE ON audit_log
                    BEGIN
                        SELECT RAISE(ABORT, 'cannot update immutable audit log');
                    END;
                CREATE TRIGGER IF NOT EXISTS prevent_audit_log_delete
                    BEFORE DELETE ON audit_log
                    BEGIN
                        SELECT RAISE(ABORT, 'cannot delete from immutable audit log');
                    END;
            ";
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = sql;
            cmd.ExecuteNonQuery();
        }

        public async Task<string> LogMutationAsync(AuditLogEntry entry)
        {
            entry.Id = Guid.NewGuid().ToString();
            entry.Timestamp = DateTime.UtcNow;
            var sql = @"
                INSERT INTO audit_log
                (id, timestamp, actor_id, actor_type, action, resource_type, resource_id,
                 old_value, new_value, why_chain_id, metadata)
                VALUES
                (@id, @timestamp, @actor_id, @actor_type, @action, @resource_type, @resource_id,
                 @old_value, @new_value, @why_chain_id, @metadata);
            ";
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = sql;
            cmd.Parameters.Add(new SqliteParameter("@id", entry.Id));
            cmd.Parameters.Add(new SqliteParameter("@timestamp", entry.Timestamp.ToString("o")));
            cmd.Parameters.Add(new SqliteParameter("@actor_id", (object)entry.ActorId ?? DBNull.Value));
            cmd.Parameters.Add(new SqliteParameter("@actor_type", (object)entry.ActorType?.ToString() ?? DBNull.Value));
            cmd.Parameters.Add(new SqliteParameter("@action", entry.Action));
            cmd.Parameters.Add(new SqliteParameter("@resource_type", entry.ResourceType));
            cmd.Parameters.Add(new SqliteParameter("@resource_id", entry.ResourceId));
            cmd.Parameters.Add(new SqliteParameter("@old_value", entry.OldValue.HasValue ? entry.OldValue.Value.GetRawText() : (object)DBNull.Value));
            cmd.Parameters.Add(new SqliteParameter("@new_value", entry.NewValue.HasValue ? entry.NewValue.Value.GetRawText() : (object)DBNull.Value));
            cmd.Parameters.Add(new SqliteParameter("@why_chain_id", (object)entry.WhyChainId ?? DBNull.Value));
            cmd.Parameters.Add(new SqliteParameter("@metadata", entry.Metadata.HasValue ? entry.Metadata.Value.GetRawText() : (object)DBNull.Value));
            await cmd.ExecuteNonQueryAsync();
            return entry.Id;
        }

        public async Task<(IEnumerable<AuditLogEntry> Logs, int Total, bool HasMore)> QueryLogsAsync(
            long? actorId = null,
            string action = null,
            string resourceType = null,
            int limit = 100,
            int offset = 0,
            DateTime? dateFrom = null,
            DateTime? dateTo = null)
        {
            var whereClauses = new List<string>();

            if (actorId.HasValue)
            {
                whereClauses.Add("actor_id = @actor_id");
            }

            if (!string.IsNullOrEmpty(action))
            {
                whereClauses.Add("action LIKE @action");
            }

            if (!string.IsNullOrEmpty(resourceType))
            {
                whereClauses.Add("resource_type = @resource_type");
            }

            if (dateFrom.HasValue)
            {
                whereClauses.Add("timestamp >= @date_from");
            }

            if (dateTo.HasValue)
            {
                whereClauses.Add("timestamp <= @date_to");
            }

            var where = whereClauses.Count > 0 ? "WHERE " + string.Join(" AND ", whereClauses) : "";

            var countSql = $"SELECT COUNT(*) FROM audit_log {where};";
            int total;
            using (var countCmd = _connection.CreateCommand())
            {
                countCmd.CommandText = countSql;
                AddParameters(countCmd, actorId, action, resourceType, dateFrom, dateTo);
                var result = await countCmd.ExecuteScalarAsync();
                total = Convert.ToInt32(result);
            }

            var dataSql = $@"
                SELECT * FROM audit_log
                {where}
                ORDER BY timestamp DESC
                LIMIT @limit OFFSET @offset;
            ";
            using var dataCmd = _connection.CreateCommand();
            dataCmd.CommandText = dataSql;
            AddParameters(dataCmd, actorId, action, resourceType, dateFrom, dateTo);
            dataCmd.Parameters.Add(new SqliteParameter("@limit", limit));
            dataCmd.Parameters.Add(new SqliteParameter("@offset", offset));

            var logs = new List<AuditLogEntry>();
            using var reader = await dataCmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                logs.Add(ReadEntry(reader));
            }

            var hasMore = offset + limit < total;
            return (logs, total, hasMore);
        }

        private void AddParameters(DbCommand cmd, long? actorId, string action, string resourceType, DateTime? dateFrom, DateTime? dateTo)
        {
            if (actorId.HasValue)
            {
                cmd.Parameters.Add(new SqliteParameter("@actor_id", actorId.Value));
            }
            if (!string.IsNullOrEmpty(action))
            {
                cmd.Parameters.Add(new SqliteParameter("@action", action.Replace("*", "%")));
            }
            if (!string.IsNullOrEmpty(resourceType))
            {
                cmd.Parameters.Add(new SqliteParameter("@resource_type", resourceType));
            }
            if (dateFrom.HasValue)
            {
                cmd.Parameters.Add(new SqliteParameter("@date_from", dateFrom.Value.ToString("o")));
            }
            if (dateTo.HasValue)
            {
                cmd.Parameters.Add(new SqliteParameter("@date_to", dateTo.Value.ToString("o")));
            }
        }

        public async Task<ReplayResult> ReplayAsync(string logId)
        {
            var sql = "SELECT * FROM audit_log WHERE id = @id;";
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = sql;
            cmd.Parameters.Add(new SqliteParameter("@id", logId));
            AuditLogEntry entry = null;
            using var reader = await cmd.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                entry = ReadEntry(reader);
            }
            else
            {
                throw new KeyNotFoundException($"Log with id {logId} not found.");
            }

            var divergeSql = @"
                SELECT 1 FROM audit_log
                WHERE resource_type = @resource_type
                  AND resource_id = @resource_id
                  AND timestamp > @timestamp
                LIMIT 1;
            ";
            using var divergeCmd = _connection.CreateCommand();
            divergeCmd.CommandText = divergeSql;
            divergeCmd.Parameters.Add(new SqliteParameter("@resource_type", entry.ResourceType));
            divergeCmd.Parameters.Add(new SqliteParameter("@resource_id", entry.ResourceId));
            divergeCmd.Parameters.Add(new SqliteParameter("@timestamp", entry.Timestamp.ToString("o")));
            var diverge = await divergeCmd.ExecuteScalarAsync();
            bool hasDiverged = diverge != null;

            return new ReplayResult
            {
                LogId = entry.Id,
                Timestamp = entry.Timestamp,
                ResourceStateAtTime = entry.OldValue,
                HasDiverged = hasDiverged
            };
        }

        public async Task<IEnumerable<AuditLogEntry>> SearchAsync(string query, string resourceType = null, int limit = 50)
        {
            var sql = @"
                SELECT * FROM audit_log
                WHERE (action LIKE @q OR resource_type LIKE @q)
            ";
            if (!string.IsNullOrEmpty(resourceType))
            {
                sql += " AND resource_type = @resource_type";
            }
            sql += " ORDER BY timestamp DESC LIMIT @limit;";

            using var cmd = _connection.CreateCommand();
            cmd.CommandText = sql;
            cmd.Parameters.Add(new SqliteParameter("@q", $"%{query}%"));
            if (!string.IsNullOrEmpty(resourceType))
            {
                cmd.Parameters.Add(new SqliteParameter("@resource_type", resourceType));
            }
            cmd.Parameters.Add(new SqliteParameter("@limit", limit));

            var results = new List<AuditLogEntry>();
            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                results.Add(ReadEntry(reader));
            }
            return results;
        }

        private AuditLogEntry ReadEntry(DbDataReader reader)
        {
            int idOrdinal = reader.GetOrdinal("id");
            int timestampOrdinal = reader.GetOrdinal("timestamp");
            int actorIdOrdinal = reader.GetOrdinal("actor_id");
            int actorTypeOrdinal = reader.GetOrdinal("actor_type");
            int actionOrdinal = reader.GetOrdinal("action");
            int resourceTypeOrdinal = reader.GetOrdinal("resource_type");
            int resourceIdOrdinal = reader.GetOrdinal("resource_id");
            int oldValueOrdinal = reader.GetOrdinal("old_value");
            int newValueOrdinal = reader.GetOrdinal("new_value");
            int whyChainIdOrdinal = reader.GetOrdinal("why_chain_id");
            int metadataOrdinal = reader.GetOrdinal("metadata");

            var entry = new AuditLogEntry
            {
                Id = reader.GetString(idOrdinal),
                Timestamp = DateTime.Parse(reader.GetString(timestampOrdinal), null, System.Globalization.DateTimeStyles.RoundtripKind),
                ActorId = reader.IsDBNull(actorIdOrdinal) ? (long?)null : reader.GetInt64(actorIdOrdinal),
                ActorType = reader.IsDBNull(actorTypeOrdinal) ? (ActorType?)null : Enum.Parse<ActorType>(reader.GetString(actorTypeOrdinal)),
                Action = reader.GetString(actionOrdinal),
                ResourceType = reader.GetString(resourceTypeOrdinal),
                ResourceId = reader.GetString(resourceIdOrdinal),
                OldValue = reader.IsDBNull(oldValueOrdinal) ? (JsonElement?)null : JsonSerializer.Deserialize<JsonElement>(reader.GetString(oldValueOrdinal)),
                NewValue = reader.IsDBNull(newValueOrdinal) ? (JsonElement?)null : JsonSerializer.Deserialize<JsonElement>(reader.GetString(newValueOrdinal)),
                WhyChainId = reader.IsDBNull(whyChainIdOrdinal) ? null : reader.GetString(whyChainIdOrdinal),
                Metadata = reader.IsDBNull(metadataOrdinal) ? (JsonElement?)null : JsonSerializer.Deserialize<JsonElement>(reader.GetString(metadataOrdinal))
            };
            return entry;
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _disposed = true;
                // Do not dispose the connection - it is owned by the caller
            }
        }
    }
}

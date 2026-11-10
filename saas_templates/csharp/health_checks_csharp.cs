using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HealthChecks
{
    public class HealthCheckResult
    {
        public string ComponentId { get; set; }
        public string ComponentType { get; set; }
        public object ObservedValue { get; set; }
        public string ObservedUnit { get; set; }
        public string Status { get; set; }
        public DateTime Time { get; set; }
    }

    public class CheckMetadata
    {
        public string ComponentId { get; set; }
        public string ComponentType { get; set; }
        public bool Critical { get; set; }
        public int TimeoutMs { get; set; }
    }

    public interface IHealthCheckStore
    {
        void AddCheck(string componentId, string componentType, bool critical, int timeoutMs);
        void RemoveCheck(string componentId);
        IEnumerable<CheckMetadata> GetAllChecks();
    }

    public class InMemoryHealthCheckStore : IHealthCheckStore
    {
        private readonly List<CheckMetadata> _checks = new List<CheckMetadata>();
        private readonly object _lock = new object();

        public void AddCheck(string componentId, string componentType, bool critical, int timeoutMs)
        {
            lock (_lock)
            {
                var existing = _checks.Find(c => c.ComponentId == componentId);
                if (existing != null)
                    _checks.Remove(existing);
                _checks.Add(new CheckMetadata
                {
                    ComponentId = componentId,
                    ComponentType = componentType,
                    Critical = critical,
                    TimeoutMs = timeoutMs
                });
            }
        }

        public void RemoveCheck(string componentId)
        {
            lock (_lock)
            {
                var existing = _checks.Find(c => c.ComponentId == componentId);
                if (existing != null)
                    _checks.Remove(existing);
            }
        }

        public IEnumerable<CheckMetadata> GetAllChecks()
        {
            lock (_lock)
            {
                return new List<CheckMetadata>(_checks);
            }
        }
    }

    public class SqlHealthCheckStore : IHealthCheckStore
    {
        private readonly DbConnection _connection;

        public SqlHealthCheckStore(DbConnection connection)
        {
            _connection = connection ?? throw new ArgumentNullException(nameof(connection));
            EnsureSchema();
        }

        private void EnsureSchema()
        {
            using (var cmd = _connection.CreateCommand())
            {
                cmd.CommandText = @"
                    CREATE TABLE IF NOT EXISTS health_checks (
                        component_id TEXT PRIMARY KEY,
                        component_type TEXT NOT NULL,
                        critical INTEGER NOT NULL,
                        timeout_ms INTEGER NOT NULL
                    );";
                cmd.ExecuteNonQuery();
            }
        }

        public void AddCheck(string componentId, string componentType, bool critical, int timeoutMs)
        {
            using (var cmd = _connection.CreateCommand())
            {
                cmd.CommandText = @"
                    INSERT OR REPLACE INTO health_checks (component_id, component_type, critical, timeout_ms)
                    VALUES (@componentId, @componentType, @critical, @timeoutMs);";

                var p1 = cmd.CreateParameter();
                p1.ParameterName = "@componentId";
                p1.Value = componentId;
                cmd.Parameters.Add(p1);

                var p2 = cmd.CreateParameter();
                p2.ParameterName = "@componentType";
                p2.Value = componentType;
                cmd.Parameters.Add(p2);

                var p3 = cmd.CreateParameter();
                p3.ParameterName = "@critical";
                p3.Value = critical ? 1 : 0;
                cmd.Parameters.Add(p3);

                var p4 = cmd.CreateParameter();
                p4.ParameterName = "@timeoutMs";
                p4.Value = timeoutMs;
                cmd.Parameters.Add(p4);

                cmd.ExecuteNonQuery();
            }
        }

        public void RemoveCheck(string componentId)
        {
            using (var cmd = _connection.CreateCommand())
            {
                cmd.CommandText = "DELETE FROM health_checks WHERE component_id = @componentId;";

                var p = cmd.CreateParameter();
                p.ParameterName = "@componentId";
                p.Value = componentId;
                cmd.Parameters.Add(p);

                cmd.ExecuteNonQuery();
            }
        }

        public IEnumerable<CheckMetadata> GetAllChecks()
        {
            var checks = new List<CheckMetadata>();
            using (var cmd = _connection.CreateCommand())
            {
                cmd.CommandText = "SELECT component_id, component_type, critical, timeout_ms FROM health_checks;";
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        checks.Add(new CheckMetadata
                        {
                            ComponentId = reader.GetString(0),
                            ComponentType = reader.GetString(1),
                            Critical = reader.GetInt32(2) != 0,
                            TimeoutMs = reader.GetInt32(3)
                        });
                    }
                }
            }
            return checks;
        }
    }

    public class HealthCheckResponse
    {
        public int HttpStatus { get; set; }
        public string ContentType { get; set; }
        public string Body { get; set; }
    }

    public static class HealthCheckService
    {
        private class CheckExecutionResult
        {
            public CheckMetadata Metadata { get; set; }
            public HealthCheckResult Result { get; set; }
        }

        private static IHealthCheckStore _store = new InMemoryHealthCheckStore();
        private static readonly Dictionary<string, CheckFunction> _functions = new Dictionary<string, CheckFunction>();
        private static readonly object _lock = new object();

        public delegate HealthCheckResult CheckFunction();

        public static void RegisterCheck(string componentId, string componentType, CheckFunction checkFn, bool critical, int timeoutMs)
        {
            lock (_lock)
            {
                _store.AddCheck(componentId, componentType, critical, timeoutMs);
                _functions[componentId] = checkFn;
            }
        }

        public static void UnregisterCheck(string componentId)
        {
            lock (_lock)
            {
                _store.RemoveCheck(componentId);
                _functions.Remove(componentId);
            }
        }

        public static void Reset()
        {
            lock (_lock)
            {
                _store = new InMemoryHealthCheckStore();
                _functions.Clear();
            }
        }

        public static HealthCheckResponse Liveness()
        {
            return new HealthCheckResponse
            {
                HttpStatus = 200,
                ContentType = "application/health+json",
                Body = "{\"status\":\"pass\"}"
            };
        }

        public static HealthCheckResponse Readiness()
        {
            var executionResults = new List<CheckExecutionResult>();

            List<CheckMetadata> metadataList;
            Dictionary<string, CheckFunction> functionsSnapshot;

            lock (_lock)
            {
                metadataList = new List<CheckMetadata>(_store.GetAllChecks());
                functionsSnapshot = new Dictionary<string, CheckFunction>(_functions);
            }

            foreach (var metadata in metadataList)
            {
                if (functionsSnapshot.TryGetValue(metadata.ComponentId, out var checkFn))
                {
                    var result = RunCheck(checkFn, metadata);

                    executionResults.Add(new CheckExecutionResult { Metadata = metadata, Result = result });
                }
                else
                {
                    executionResults.Add(new CheckExecutionResult
                    {
                        Metadata = metadata,
                        Result = CreateFailedHealthCheckResult(metadata)
                    });
                }
            }

            bool anyCriticalFail = false;
            bool anyNonCriticalFail = false;
            foreach (var exec in executionResults)
            {
                if (exec.Result.Status == "fail")
                {
                    if (exec.Metadata.Critical)
                        anyCriticalFail = true;
                    else
                        anyNonCriticalFail = true;
                }
            }

            string overallStatus;
            if (anyCriticalFail)
                overallStatus = "fail";
            else if (anyNonCriticalFail)
                overallStatus = "warn";
            else
                overallStatus = "pass";

            int httpStatus = overallStatus == "fail" ? 503 : 200;

            var bodyBuilder = new StringBuilder();
            bodyBuilder.Append("{");
            bodyBuilder.Append("\"status\":\"").Append(EscapeJson(overallStatus)).Append("\"");

            bodyBuilder.Append(",\"checks\":{");
            bool first = true;
            foreach (var exec in executionResults)
            {
                if (!first)
                    bodyBuilder.Append(",");
                first = false;

                var key = exec.Metadata.ComponentId + ":" + exec.Metadata.ComponentType;
                bodyBuilder.Append("\"").Append(EscapeJson(key)).Append("\":[{");
                bodyBuilder.Append("\"componentId\":\"").Append(EscapeJson(exec.Metadata.ComponentId)).Append("\",");
                bodyBuilder.Append("\"componentType\":\"").Append(EscapeJson(exec.Metadata.ComponentType)).Append("\",");
                bodyBuilder.Append("\"observedValue\":").Append(FormatJsonValue(exec.Result.ObservedValue)).Append(",");
                bodyBuilder.Append("\"observedUnit\":\"").Append(EscapeJson(exec.Result.ObservedUnit ?? string.Empty)).Append("\",");
                bodyBuilder.Append("\"status\":\"").Append(EscapeJson(exec.Result.Status)).Append("\",");
                bodyBuilder.Append("\"time\":\"").Append(exec.Result.Time.ToString("o")).Append("\"");
                bodyBuilder.Append("}]");
            }
            bodyBuilder.Append("}");
            bodyBuilder.Append("}");

            return new HealthCheckResponse
            {
                HttpStatus = httpStatus,
                ContentType = "application/health+json",
                Body = bodyBuilder.ToString()
            };
        }

        /// <summary>
        /// Runs one check with its own timeout.
        /// In: the check function and its metadata (timeout_ms). Out: the check's result, or a "fail" result with
        /// no observed value when the check times out, throws, or returns null.
        /// Why: HEALTH-04 (a check past its timeout fails) and HEALTH-06 (never put secrets, connection strings or
        /// stack traces in the output). Before 2026-11-10 a check that threw made Task.Wait raise an
        /// AggregateException out of readiness(), carrying the exception's message (often a connection string);
        /// now the exception is caught and nothing from it reaches the body.
        /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: whatever the check function touches; a thread-pool task.
        /// </summary>
        private static HealthCheckResult RunCheck(CheckFunction checkFn, CheckMetadata metadata)
        {
            using var cts = new CancellationTokenSource();
            var task = Task.Run(() => checkFn(), cts.Token);
            try
            {
                if (!task.Wait(TimeSpan.FromMilliseconds(metadata.TimeoutMs)))
                {
                    cts.Cancel();
                    // observe a later fault so it never surfaces as an unobserved task exception
                    task.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
                    return CreateFailedHealthCheckResult(metadata);
                }
                return task.Result ?? CreateFailedHealthCheckResult(metadata);
            }
            catch (AggregateException)
            {
                return CreateFailedHealthCheckResult(metadata);
            }
        }

        private static HealthCheckResult CreateFailedHealthCheckResult(CheckMetadata metadata)
        {
            return new HealthCheckResult
            {
                ComponentId = metadata.ComponentId,
                ComponentType = metadata.ComponentType,
                ObservedValue = null,
                ObservedUnit = null,
                Status = "fail",
                Time = DateTime.UtcNow
            };
        }

        private static string EscapeJson(string s)
        {
            if (s == null) return string.Empty;
            var sb = new StringBuilder();
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (char.IsControl(c))
                        {
                            sb.Append("\\u").Append(((int)c).ToString("x4"));
                        }
                        else
                        {
                            sb.Append(c);
                        }
                        break;
                }
            }
            return sb.ToString();
        }

        private static string FormatJsonValue(object value)
        {
            if (value == null) return "null";
            if (value is string str) return "\"" + EscapeJson(str) + "\"";
            if (value is bool b) return b ? "true" : "false";
            if (value is byte || value is sbyte || value is short || value is ushort || value is int || value is uint || value is long || value is ulong ||
                value is float || value is double || value is decimal)
                return value.ToString();
            return "\"" + EscapeJson(value.ToString()) + "\"";
        }
    }
}
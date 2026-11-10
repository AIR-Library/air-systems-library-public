// Idempotency keys template (IETF draft-ietf-httpapi-idempotency-key-header-07): the same request with the same key
// runs ONCE. Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, for the spec amendment of that day
// (IDEM-07/08/10/11): status 'uncertain'; OperationFailedException frees a key, any other error leaves it uncertain;
// only 'completed' records expire and an expired 'in_progress' record counts as uncertain; release(), resolve() and
// list_uncertain() for reconciliation, each release/resolve ONE conditional write; an injectable clock.
// Touches: the idempotency_records table (SqlStore) or process memory (InMemoryStore); the operation passed in may
// touch anything (money, network).
using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AOI.IdempotencyKeys
{
    /// <summary>
    /// Thrown by an operation to report a DEFINITE failure: it did nothing (a validation error, a provider decline).
    /// The key is freed so a retry runs again (IDEM-08). Any other exception leaves the key 'uncertain' (IDEM-10).
    /// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (the spec's name for C#). Touches nothing.
    /// </summary>
    public class OperationFailedException : Exception
    {
        /// <summary>Creates the exception with a message and an optional cause.</summary>
        public OperationFailedException(string message, Exception inner = null) : base(message, inner) { }
    }

    /// <summary>One row of idempotency_records. Status is 'in_progress', 'completed' or 'uncertain'. Pure data.</summary>
    public sealed class IdempotencyRecord
    {
        public string Scope { get; set; }
        public string IdemKey { get; set; }
        public string Fingerprint { get; set; }
        public string Status { get; set; }
        public int? ResponseStatus { get; set; }
        public string ResponseBody { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }

        /// <summary>
        /// The status as the spec reads it at <paramref name="now"/>: an 'in_progress' record past expires_at is
        /// 'uncertain' (its process died without a known outcome). Pure.
        /// </summary>
        public string EffectiveStatus(DateTime now) =>
            Status == "in_progress" && ExpiresAt <= now ? "uncertain" : Status;

        /// <summary>True for a 'completed' record past expires_at: it counts as absent. Pure.</summary>
        public bool IsExpiredCompleted(DateTime now) => Status == "completed" && ExpiresAt <= now;
    }

    /// <summary>An entry of the reconciliation work list. Pure data.</summary>
    public sealed class UncertainEntry
    {
        public string Scope { get; set; }
        public string IdemKey { get; set; }
        public DateTime CreatedAt { get; set; }
    }

    /// <summary>
    /// Where idempotency records live. Every method is one atomic step. Rewritten 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP (uncertain status, release, resolve, list_uncertain).
    /// </summary>
    public interface IIdempotencyStore
    {
        /// <summary>The record for (scope, key), or null.</summary>
        IdempotencyRecord Get(string scope, string idemKey);

        /// <summary>
        /// Inserts an 'in_progress' record if none exists, replacing only a 'completed' record whose expires_at has
        /// passed. Never replaces an in_progress or uncertain record. Out: true when this call claimed the key.
        /// </summary>
        bool TryClaim(string scope, string idemKey, string fingerprint, DateTime now, DateTime expiresAt);

        /// <summary>Stores the response of a claimed key: in_progress -> completed (same fingerprint only).</summary>
        void Complete(string scope, string idemKey, string fingerprint, int status, string body);

        /// <summary>Deletes the record when it is still in_progress (a definite failure frees the key).</summary>
        void DeleteInProgress(string scope, string idemKey);

        /// <summary>in_progress -> uncertain (the outcome is unknown).</summary>
        void MarkUncertain(string scope, string idemKey);

        /// <summary>One conditional delete of an uncertain record (or an in_progress one past expires_at). Out: whether it did.</summary>
        bool Release(string scope, string idemKey, DateTime now);

        /// <summary>One conditional update of an uncertain record to completed with this response and expires_at. Out: whether it did.</summary>
        bool Resolve(string scope, string idemKey, int status, string body, DateTime now, DateTime expiresAt);

        /// <summary>Uncertain records (including in_progress past expires_at), oldest first, at most <paramref name="limit"/>.</summary>
        List<UncertainEntry> ListUncertain(int limit, DateTime now);

        /// <summary>Deletes 'completed' records past expires_at. Out: how many.</summary>
        int PurgeExpired(DateTime now);
    }

    /// <summary>
    /// The store in process memory, behind one lock (every method is atomic). Rewritten 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
    /// </summary>
    public sealed class InMemoryStore : IIdempotencyStore
    {
        private readonly Dictionary<string, IdempotencyRecord> _records = new();
        private readonly List<string> _order = new(); // insertion order, for oldest-first ties
        private readonly object _lock = new();

        private static string Key(string scope, string idemKey) => scope + "\0" + idemKey;

        private static IdempotencyRecord Copy(IdempotencyRecord r) => r == null ? null : new IdempotencyRecord
        {
            Scope = r.Scope, IdemKey = r.IdemKey, Fingerprint = r.Fingerprint, Status = r.Status,
            ResponseStatus = r.ResponseStatus, ResponseBody = r.ResponseBody, CreatedAt = r.CreatedAt, ExpiresAt = r.ExpiresAt
        };

        private static bool IsUncertain(IdempotencyRecord r, DateTime now) => r.EffectiveStatus(now) == "uncertain";

        /// <inheritdoc/>
        public IdempotencyRecord Get(string scope, string idemKey)
        {
            lock (_lock) return Copy(_records.TryGetValue(Key(scope, idemKey), out var r) ? r : null);
        }

        /// <inheritdoc/>
        public bool TryClaim(string scope, string idemKey, string fingerprint, DateTime now, DateTime expiresAt)
        {
            lock (_lock)
            {
                var key = Key(scope, idemKey);
                if (_records.TryGetValue(key, out var existing))
                {
                    if (!existing.IsExpiredCompleted(now)) return false;
                    _records.Remove(key);
                    _order.Remove(key);
                }
                _records[key] = new IdempotencyRecord
                {
                    Scope = scope, IdemKey = idemKey, Fingerprint = fingerprint, Status = "in_progress",
                    CreatedAt = now, ExpiresAt = expiresAt
                };
                _order.Add(key);
                return true;
            }
        }

        /// <inheritdoc/>
        public void Complete(string scope, string idemKey, string fingerprint, int status, string body)
        {
            lock (_lock)
            {
                if (_records.TryGetValue(Key(scope, idemKey), out var r) && r.Status == "in_progress" && r.Fingerprint == fingerprint)
                {
                    r.Status = "completed";
                    r.ResponseStatus = status;
                    r.ResponseBody = body;
                }
            }
        }

        /// <inheritdoc/>
        public void DeleteInProgress(string scope, string idemKey)
        {
            lock (_lock)
            {
                var key = Key(scope, idemKey);
                if (_records.TryGetValue(key, out var r) && r.Status == "in_progress")
                {
                    _records.Remove(key);
                    _order.Remove(key);
                }
            }
        }

        /// <inheritdoc/>
        public void MarkUncertain(string scope, string idemKey)
        {
            lock (_lock)
            {
                if (_records.TryGetValue(Key(scope, idemKey), out var r) && r.Status == "in_progress")
                    r.Status = "uncertain";
            }
        }

        /// <inheritdoc/>
        public bool Release(string scope, string idemKey, DateTime now)
        {
            lock (_lock)
            {
                var key = Key(scope, idemKey);
                if (!_records.TryGetValue(key, out var r) || !IsUncertain(r, now)) return false;
                _records.Remove(key);
                _order.Remove(key);
                return true;
            }
        }

        /// <inheritdoc/>
        public bool Resolve(string scope, string idemKey, int status, string body, DateTime now, DateTime expiresAt)
        {
            lock (_lock)
            {
                if (!_records.TryGetValue(Key(scope, idemKey), out var r) || !IsUncertain(r, now)) return false;
                r.Status = "completed";
                r.ResponseStatus = status;
                r.ResponseBody = body;
                r.ExpiresAt = expiresAt;
                return true;
            }
        }

        /// <inheritdoc/>
        public List<UncertainEntry> ListUncertain(int limit, DateTime now)
        {
            lock (_lock)
            {
                return _order.Select(k => _records[k])
                    .Where(r => IsUncertain(r, now))
                    .OrderBy(r => r.CreatedAt) // stable: insertion order breaks ties
                    .Take(Math.Max(0, limit))
                    .Select(r => new UncertainEntry { Scope = r.Scope, IdemKey = r.IdemKey, CreatedAt = r.CreatedAt })
                    .ToList();
            }
        }

        /// <inheritdoc/>
        public int PurgeExpired(DateTime now)
        {
            lock (_lock)
            {
                var expired = _records.Where(kv => kv.Value.IsExpiredCompleted(now)).Select(kv => kv.Key).ToList();
                foreach (var key in expired)
                {
                    _records.Remove(key);
                    _order.Remove(key);
                }
                return expired.Count;
            }
        }
    }

    /// <summary>
    /// The store in a SQL database (SQLite and Postgres syntax): idempotency_records with PRIMARY KEY (scope, idem_key).
    /// Every statement is parameterized; a claim is one transaction (delete an expired completed row, then
    /// INSERT ... ON CONFLICT DO NOTHING); release and resolve are each ONE conditional statement. Times are stored as
    /// fixed-width UTC ISO 8601 text, so they compare as text. Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: the database behind the connection.
    /// </summary>
    public sealed class SqlStore : IIdempotencyStore
    {
        private readonly DbConnection _connection;
        private readonly object _gate = new();
        private bool _initialized;

        /// <summary>Uses <paramref name="connection"/> (opened on demand). Touches nothing until first use.</summary>
        public SqlStore(DbConnection connection)
        {
            _connection = connection ?? throw new ArgumentNullException(nameof(connection));
        }

        /// <summary>The table, as created on first use.</summary>
        public const string Ddl = @"
            CREATE TABLE IF NOT EXISTS idempotency_records (
                scope TEXT NOT NULL,
                idem_key TEXT NOT NULL,
                request_fingerprint TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('in_progress','completed','uncertain')),
                response_status INTEGER NULL,
                response_body TEXT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY (scope, idem_key)
            )";

        private const string UncertainCondition =
            "(status = 'uncertain' OR (status = 'in_progress' AND expires_at <= @now))";

        private static string ToIso(DateTime dt) =>
            DateTime.SpecifyKind(dt.Kind == DateTimeKind.Local ? dt.ToUniversalTime() : dt, DateTimeKind.Utc)
                .ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", System.Globalization.CultureInfo.InvariantCulture);

        private static DateTime FromIso(string s) =>
            DateTime.Parse(s, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal);

        /// <summary>Runs <paramref name="work"/> on the open connection (creating the table once). Serialized per store.</summary>
        private T With<T>(Func<T> work)
        {
            lock (_gate)
            {
                var wasClosed = _connection.State == System.Data.ConnectionState.Closed;
                if (wasClosed) _connection.Open();
                try
                {
                    if (!_initialized)
                    {
                        using var cmd = _connection.CreateCommand();
                        cmd.CommandText = Ddl;
                        cmd.ExecuteNonQuery();
                        _initialized = true;
                    }
                    return work();
                }
                finally
                {
                    if (wasClosed) _connection.Close();
                }
            }
        }

        private DbCommand Command(string sql, DbTransaction tx = null, params (string Name, object Value)[] args)
        {
            var cmd = _connection.CreateCommand();
            cmd.CommandText = sql;
            cmd.Transaction = tx;
            foreach (var (name, value) in args)
            {
                var p = cmd.CreateParameter();
                p.ParameterName = name;
                p.Value = value ?? DBNull.Value;
                cmd.Parameters.Add(p);
            }
            return cmd;
        }

        /// <inheritdoc/>
        public IdempotencyRecord Get(string scope, string idemKey) => With(() =>
        {
            using var cmd = Command(@"SELECT request_fingerprint, status, response_status, response_body, created_at, expires_at
                                      FROM idempotency_records WHERE scope = @scope AND idem_key = @key", null,
                ("@scope", scope), ("@key", idemKey));
            using var r = cmd.ExecuteReader();
            if (!r.Read()) return null;
            return new IdempotencyRecord
            {
                Scope = scope, IdemKey = idemKey, Fingerprint = r.GetString(0), Status = r.GetString(1),
                ResponseStatus = r.IsDBNull(2) ? null : r.GetInt32(2), ResponseBody = r.IsDBNull(3) ? null : r.GetString(3),
                CreatedAt = FromIso(r.GetString(4)), ExpiresAt = FromIso(r.GetString(5))
            };
        });

        /// <inheritdoc/>
        public bool TryClaim(string scope, string idemKey, string fingerprint, DateTime now, DateTime expiresAt) => With(() =>
        {
            using var tx = _connection.BeginTransaction();
            using (var del = Command(@"DELETE FROM idempotency_records WHERE scope = @scope AND idem_key = @key
                                         AND status = 'completed' AND expires_at <= @now", tx,
                       ("@scope", scope), ("@key", idemKey), ("@now", ToIso(now))))
                del.ExecuteNonQuery();
            int rows;
            using (var ins = Command(@"INSERT INTO idempotency_records (scope, idem_key, request_fingerprint, status, created_at, expires_at)
                                       VALUES (@scope, @key, @fp, 'in_progress', @now, @exp)
                                       ON CONFLICT (scope, idem_key) DO NOTHING", tx,
                       ("@scope", scope), ("@key", idemKey), ("@fp", fingerprint), ("@now", ToIso(now)), ("@exp", ToIso(expiresAt))))
                rows = ins.ExecuteNonQuery();
            tx.Commit();
            return rows == 1;
        });

        /// <inheritdoc/>
        public void Complete(string scope, string idemKey, string fingerprint, int status, string body) => With(() =>
        {
            using var cmd = Command(@"UPDATE idempotency_records SET status = 'completed', response_status = @status, response_body = @body
                                      WHERE scope = @scope AND idem_key = @key AND status = 'in_progress' AND request_fingerprint = @fp", null,
                ("@status", status), ("@body", body), ("@scope", scope), ("@key", idemKey), ("@fp", fingerprint));
            return cmd.ExecuteNonQuery();
        });

        /// <inheritdoc/>
        public void DeleteInProgress(string scope, string idemKey) => With(() =>
        {
            using var cmd = Command("DELETE FROM idempotency_records WHERE scope = @scope AND idem_key = @key AND status = 'in_progress'", null,
                ("@scope", scope), ("@key", idemKey));
            return cmd.ExecuteNonQuery();
        });

        /// <inheritdoc/>
        public void MarkUncertain(string scope, string idemKey) => With(() =>
        {
            using var cmd = Command("UPDATE idempotency_records SET status = 'uncertain' WHERE scope = @scope AND idem_key = @key AND status = 'in_progress'", null,
                ("@scope", scope), ("@key", idemKey));
            return cmd.ExecuteNonQuery();
        });

        /// <inheritdoc/>
        public bool Release(string scope, string idemKey, DateTime now) => With(() =>
        {
            using var cmd = Command($"DELETE FROM idempotency_records WHERE scope = @scope AND idem_key = @key AND {UncertainCondition}", null,
                ("@scope", scope), ("@key", idemKey), ("@now", ToIso(now)));
            return cmd.ExecuteNonQuery() == 1;
        });

        /// <inheritdoc/>
        public bool Resolve(string scope, string idemKey, int status, string body, DateTime now, DateTime expiresAt) => With(() =>
        {
            using var cmd = Command($@"UPDATE idempotency_records
                                       SET status = 'completed', response_status = @status, response_body = @body, expires_at = @exp
                                       WHERE scope = @scope AND idem_key = @key AND {UncertainCondition}", null,
                ("@status", status), ("@body", body), ("@exp", ToIso(expiresAt)), ("@scope", scope), ("@key", idemKey), ("@now", ToIso(now)));
            return cmd.ExecuteNonQuery() == 1;
        });

        /// <inheritdoc/>
        public List<UncertainEntry> ListUncertain(int limit, DateTime now) => With(() =>
        {
            using var cmd = Command($@"SELECT scope, idem_key, created_at FROM idempotency_records WHERE {UncertainCondition}
                                       ORDER BY created_at, scope, idem_key LIMIT @limit", null,
                ("@now", ToIso(now)), ("@limit", Math.Max(0, limit)));
            using var r = cmd.ExecuteReader();
            var list = new List<UncertainEntry>();
            while (r.Read())
                list.Add(new UncertainEntry { Scope = r.GetString(0), IdemKey = r.GetString(1), CreatedAt = FromIso(r.GetString(2)) });
            return list;
        });

        /// <inheritdoc/>
        public int PurgeExpired(DateTime now) => With(() =>
        {
            using var cmd = Command("DELETE FROM idempotency_records WHERE status = 'completed' AND expires_at <= @now", null,
                ("@now", ToIso(now)));
            return cmd.ExecuteNonQuery();
        });
    }

    /// <summary>
    /// handle(), release(), resolve(), list_uncertain(), is_required() and purge_expired() of the spec.
    /// release(), resolve() and list_uncertain() are operator / reconciliation functions: never map them to an API route,
    /// and pass the stored record's scope, never one from request input. Rewritten 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store; the operation passed to Handle.
    /// </summary>
    public sealed class IdempotencyKeys
    {
        private readonly IIdempotencyStore _store;
        private readonly HashSet<string> _requiredMethods;
        private readonly TimeSpan _ttl;
        private readonly Func<DateTime> _clock;

        /// <summary>Problem type of every error except outcome_unknown.</summary>
        public const string ProblemType = "https://developer.example.com/idempotency";

        /// <summary>Problem type of a 409 for a key whose first outcome is unknown (IDEM-07, IDEM-10).</summary>
        public const string OutcomeUnknownType = "https://developer.example.com/problems/outcome_unknown";

        /// <summary>
        /// In: the store, the methods that require a key (POST and PATCH by default), the lifetime of a completed key
        /// (24 h by default), and an optional clock returning UTC now (default DateTime.UtcNow; tests move it).
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the clock. Touches nothing.
        /// </summary>
        public IdempotencyKeys(IIdempotencyStore store, IEnumerable<string> requiredMethods = null, TimeSpan? ttl = null,
            Func<DateTime> clock = null)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _requiredMethods = new HashSet<string>(requiredMethods ?? new[] { "POST", "PATCH" }, StringComparer.OrdinalIgnoreCase);
            _ttl = ttl ?? TimeSpan.FromHours(24);
            _clock = clock ?? (() => DateTime.UtcNow);
        }

        /// <summary>is_required(method, path): true for the configured methods. Pure.</summary>
        public bool IsRequired(string method, string path)
        {
            return _requiredMethods.Contains(method?.ToUpperInvariant());
        }

        /// <summary>
        /// handle(scope, key, method, path, body, operation) -&gt; (status, content_type, body).
        /// Check order: missing key on a required operation -&gt; 400; a different fingerprint -&gt; 422 (even while the
        /// first is in progress); same fingerprint in progress -&gt; 409; uncertain (or in_progress past expires_at) -&gt;
        /// 409 outcome_unknown; completed -&gt; the stored response. Otherwise the key is claimed atomically (an expired
        /// completed record is replaced) and the operation runs once: its result is stored and served as
        /// application/json; OperationFailedException deletes the claim and is re-raised (IDEM-08); any other
        /// exception marks the key 'uncertain' and is re-raised (IDEM-10). Errors are application/problem+json.
        /// In: scope = the authenticated client id. Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// Touches: the store; whatever the operation touches.
        /// </summary>
        public (int status, string contentType, string body) Handle(
            string scope,
            string idempotencyKey,
            string method,
            string path,
            string body,
            Func<(int status, string body)> operation)
        {
            if (string.IsNullOrEmpty(scope))
                throw new ArgumentException("scope required", nameof(scope));
            if (string.IsNullOrEmpty(method))
                throw new ArgumentException("method required", nameof(method));
            if (string.IsNullOrEmpty(path))
                throw new ArgumentException("path required", nameof(path));
            if (operation == null)
                throw new ArgumentNullException(nameof(operation));

            if (string.IsNullOrEmpty(idempotencyKey))
            {
                if (IsRequired(method, path))
                    return Problem(400, ProblemType, "Missing Idempotency-Key", "Idempotency-Key header is required for this operation");
                var plain = operation();
                return (plain.status, "application/json", plain.body);
            }

            var fingerprint = ComputeFingerprint(method, path, body ?? "");
            // Two passes at most: a claim lost to a concurrent request re-reads the winner's record.
            for (var attempt = 0; attempt < 2; attempt++)
            {
                var now = _clock();
                var existing = _store.Get(scope, idempotencyKey);
                if (existing != null && !existing.IsExpiredCompleted(now))
                    return Answer(existing, fingerprint, now);

                if (_store.TryClaim(scope, idempotencyKey, fingerprint, now, now.Add(_ttl)))
                    return Run(scope, idempotencyKey, fingerprint, operation);
            }
            return Problem(409, ProblemType, "Conflict", "Request with this Idempotency-Key is already in progress");
        }

        /// <summary>The answer for an existing, unexpired record (see Handle's check order). Pure.</summary>
        private static (int status, string contentType, string body) Answer(IdempotencyRecord record, string fingerprint, DateTime now)
        {
            if (record.Fingerprint != fingerprint)
                return Problem(422, ProblemType, "Unprocessable Content", "Idempotency-Key reused with different request payload");
            switch (record.EffectiveStatus(now))
            {
                case "in_progress":
                    return Problem(409, ProblemType, "Conflict", "Request with this Idempotency-Key is already in progress");
                case "uncertain":
                    return Problem(409, OutcomeUnknownType, "Outcome unknown",
                        "The first request with this Idempotency-Key ended without a known outcome; it will not be run again until it is reconciled.");
                default:
                    return (record.ResponseStatus ?? 200, "application/json", record.ResponseBody);
            }
        }

        /// <summary>Runs the operation for a claimed key and records the outcome (see Handle). Touches: the store, the operation.</summary>
        private (int status, string contentType, string body) Run(string scope, string idempotencyKey, string fingerprint,
            Func<(int status, string body)> operation)
        {
            (int status, string body) result;
            try
            {
                result = operation();
            }
            catch (OperationFailedException)
            {
                _store.DeleteInProgress(scope, idempotencyKey);
                throw;
            }
            catch (Exception)
            {
                // Outcome unknown (timeout, dropped connection, crash after the provider was called): never free the
                // key here, or a retry could charge twice. Re-raised, not swallowed.
                _store.MarkUncertain(scope, idempotencyKey);
                throw;
            }
            _store.Complete(scope, idempotencyKey, fingerprint, result.status, result.body);
            return (result.status, "application/json", result.body);
        }

        /// <summary>
        /// release(scope, key): frees an 'uncertain' key (or an in_progress one past expires_at) once reconciliation shows
        /// the first attempt did nothing, so a retry runs. One conditional write: of two concurrent calls exactly one
        /// returns true. Out: false (nothing changed) for any other key. Operator function: never an API route; scope is
        /// the stored record's. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
        /// </summary>
        public bool Release(string scope, string idempotencyKey) => _store.Release(scope, idempotencyKey, _clock());

        /// <summary>
        /// resolve(scope, key, status, body): stores the outcome reconciliation found for an 'uncertain' key as
        /// 'completed' with expires_at = now + 24 h, so a retry gets that response. One conditional write. Out: false
        /// (nothing changed) for a key that is not uncertain. Operator function: never an API route.
        /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
        /// </summary>
        public bool Resolve(string scope, string idempotencyKey, int status, string body)
        {
            var now = _clock();
            return _store.Resolve(scope, idempotencyKey, status, body, now, now.AddHours(24));
        }

        /// <summary>
        /// list_uncertain(limit): the reconciliation work list [{scope, idem_key, created_at}], oldest first. Operator
        /// function. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store (read).
        /// </summary>
        public List<UncertainEntry> ListUncertain(int limit = 100) => _store.ListUncertain(limit, _clock());

        /// <summary>purge_expired(): deletes completed records past expires_at; uncertain ones are kept. Out: how many. Touches: the store.</summary>
        public int PurgeExpired() => _store.PurgeExpired(_clock());

        /// <summary>
        /// The request fingerprint: SHA-256 (lower-case hex) of METHOD + " " + path + "\n" + body. Public so an operator
        /// tool (or a test) can match a stored record to a request. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Pure.
        /// </summary>
        public static string Fingerprint(string method, string path, string body) => ComputeFingerprint(method, path, body ?? "");

        /// <summary>SHA-256 (lower-case hex) of method + " " + path + "\n" + body. Pure.</summary>
        private static string ComputeFingerprint(string method, string path, string body)
        {
            var input = Encoding.UTF8.GetBytes(method.ToUpperInvariant() + " " + path + "\n" + body);
            return Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();
        }

        /// <summary>An RFC 7807 problem response {type, title, detail, status} as application/problem+json. Pure.</summary>
        private static (int status, string contentType, string body) Problem(int status, string type, string title, string detail)
        {
            var json = JsonSerializer.Serialize(new { type, title, detail, status });
            return (status, "application/problem+json", json);
        }
    }
}

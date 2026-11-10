// Audit logging template: an append-only event log with the personal data kept beside it, so a person can be erased
// without rewriting an event.
// Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, for the spec amendment of that day (AUDIT-08/09/10, after
// review on PR 19 and an independent security review): audit_log keeps events only; an entry's personal data lives in
// audit_personal rows ('actor': actor id, ip, user agent, request id; 'subject': resource id, old/new value, why chain
// id) under a random subject_ref in audit_subjects; log() requires subject_user_id (a user id or 'none') for every
// resource_type except 'user' and allows only the metadata keys feature_flag and erased_rows; erase_subject() and
// apply_retention() delete personal and subject rows only, never audit_log rows; reads are admin-only and show
// personal_erased after erasure. Touches: the SQLite database behind the connection (audit_log, audit_personal,
// audit_subjects); nothing else.
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
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

    /// <summary>
    /// A refused call: the HTTP status and the error code of the spec (400 subject_required, 400 subject_mismatch, 400
    /// metadata_key_not_allowed, 400 actor_user_required, 400 invalid_actor_type, 400 actor_required, 400
    /// actor_service_required, 400 invalid_entry, 403 admin_only, 404 not_found).
    /// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (AUDIT-10; the three actor codes added the same day, Phase B.2).
    /// Touches nothing.
    /// </summary>
    public class AuditException : Exception
    {
        public int Status { get; }
        public string Code { get; }

        /// <summary>Creates the error with its status and code.</summary>
        public AuditException(int status, string code, string message = null) : base(message ?? code)
        {
            Status = status;
            Code = code;
        }
    }

    /// <summary>
    /// The verified caller of a read (query, replay, search): reads are for admins only (AUDIT-10). The application's
    /// authentication layer builds it; never from request input. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    public sealed record AuditCaller(string Id, bool IsAdmin)
    {
        /// <summary>An admin caller.</summary>
        public static AuditCaller Admin(string id = "admin") => new(id, true);

        /// <summary>A caller who is not an admin.</summary>
        public static AuditCaller User(string id) => new(id, false);
    }

    /// <summary>
    /// One audit entry: what log() is given, and what reads return. On write: ActorType; ActorId (the authenticated
    /// actor: required for 'user', the key id for 'api_key'); ActorUserId (the key's owner, required for 'api_key');
    /// ActorService (for 'service'); SubjectUserId (required unless ResourceType is 'user': a user id or "none"); Ip,
    /// UserAgent, RequestId (actor personal data); Metadata (only feature_flag and erased_rows). On read: the fields
    /// joined back from audit_personal, null when erased, with PersonalErased true and PersonalRoles as written.
    /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: ids are strings; personal fields added. Pure data.
    /// </summary>
    public class AuditLogEntry
    {
        public string Id { get; set; }
        public DateTime Timestamp { get; set; }
        public string ActorId { get; set; }
        public ActorType? ActorType { get; set; }
        public string ActorService { get; set; }
        public string ActorUserId { get; set; }
        public string SubjectUserId { get; set; }
        public string Action { get; set; }
        public string ResourceType { get; set; }
        public string ResourceId { get; set; }
        public JsonElement? OldValue { get; set; }
        public JsonElement? NewValue { get; set; }
        public string WhyChainId { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        public string Ip { get; set; }
        public string UserAgent { get; set; }
        public string RequestId { get; set; }
        public string PersonalRoles { get; set; } = "";
        public bool PersonalErased { get; set; }
    }

    /// <summary>
    /// Answer of replay(log_id). For an entry whose subject rows were erased: Erased true, ResourceStateAtTime and
    /// HasDiverged null. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Pure data.
    /// </summary>
    public class ReplayResult
    {
        public string LogId { get; set; }
        public DateTime Timestamp { get; set; }
        public JsonElement? ResourceStateAtTime { get; set; }
        public bool? HasDiverged { get; set; }
        public bool Erased { get; set; }
    }

    /// <summary>
    /// The audit log over SQLite. Every statement is parameterized. log() writes the subject, the entry and its personal
    /// rows in one transaction; audit_log refuses UPDATE and DELETE and audit_personal refuses UPDATE (triggers).
    /// Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (see the file header). Touches: the database.
    /// </summary>
    public class AuditLogRepository : IDisposable
    {
        /// <summary>The only metadata keys log() accepts.</summary>
        public static readonly string[] AllowedMetadataKeys = { "feature_flag", "erased_rows" };

        private readonly DbConnection _connection;
        private readonly Func<DateTime> _clock;
        private readonly TimeSpan _retention;
        private bool _disposed;

        /// <summary>
        /// In: an SQLite connection (opened if closed; owned by the caller), the retention period of personal data
        /// (default 365 days; set it by purpose and the legal obligations that apply) and an optional clock returning UTC
        /// now (default DateTime.UtcNow). Creates the schema. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// Touches: the database (DDL).
        /// </summary>
        public AuditLogRepository(DbConnection connection, TimeSpan? retention = null, Func<DateTime> clock = null)
        {
            _connection = connection ?? throw new ArgumentNullException(nameof(connection));
            _retention = retention ?? TimeSpan.FromDays(365);
            _clock = clock ?? (() => DateTime.UtcNow);
            if (_connection.State != ConnectionState.Open)
                _connection.Open();
            CreateSchema();
        }

        /// <summary>The schema: the three tables, their indexes and the immutability triggers.</summary>
        public const string Ddl = @"
            CREATE TABLE IF NOT EXISTS audit_log (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                id TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                actor_type TEXT NOT NULL CHECK (actor_type IN ('user','service','api_key')),
                actor_service TEXT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NULL,
                old_value TEXT NULL,
                new_value TEXT NULL,
                why_chain_id TEXT NULL,
                personal_roles TEXT NOT NULL,
                metadata TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_log_action_type_ts ON audit_log(action, resource_type, timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(timestamp, action, resource_type);
            CREATE TABLE IF NOT EXISTS audit_subjects (
                subject_ref TEXT PRIMARY KEY,
                user_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_personal (
                log_id TEXT NOT NULL,
                subject_ref TEXT NOT NULL REFERENCES audit_subjects(subject_ref),
                role TEXT NOT NULL CHECK (role IN ('actor','subject')),
                data TEXT NOT NULL,
                PRIMARY KEY (log_id, role)
            );
            CREATE INDEX IF NOT EXISTS idx_audit_personal_subject_role ON audit_personal(subject_ref, role);
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
            CREATE TRIGGER IF NOT EXISTS prevent_audit_personal_update
                BEFORE UPDATE ON audit_personal
                BEGIN
                    SELECT RAISE(ABORT, 'cannot update audit personal data');
                END;";

        /// <summary>Creates the schema if missing. Touches: the database.</summary>
        private void CreateSchema()
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = Ddl;
            cmd.ExecuteNonQuery();
        }

        private static string Iso(DateTime dt) =>
            DateTime.SpecifyKind(dt.Kind == DateTimeKind.Local ? dt.ToUniversalTime() : dt, DateTimeKind.Utc)
                .ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);

        private static DateTime ParseIso(string s) =>
            DateTime.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal);

        private static string ActorTypeText(ActorType t) => t switch
        {
            AuditLogging.ActorType.User => "user",
            AuditLogging.ActorType.Service => "service",
            _ => "api_key"
        };

        private static ActorType ParseActorType(string s) => s switch
        {
            "user" => AuditLogging.ActorType.User,
            "service" => AuditLogging.ActorType.Service,
            _ => AuditLogging.ActorType.ApiKey
        };

        private DbCommand Command(string sql, DbTransaction tx = null, params (string Name, object Value)[] args)
        {
            var cmd = _connection.CreateCommand();
            cmd.CommandText = sql;
            cmd.Transaction = tx;
            foreach (var (name, value) in args)
                cmd.Parameters.Add(new SqliteParameter(name, value ?? DBNull.Value));
            return cmd;
        }

        /// <summary>
        /// log(): appends one entry (AUDIT-01, AUDIT-10). Checks, in order: action and resource_type present (400
        /// invalid_entry); actor_type one of user, service, api_key (missing or any other value: 400 invalid_actor_type);
        /// a 'user' actor has an actor id (400 actor_required); a 'service' actor has actor_service (400
        /// actor_service_required); an 'api_key' entry has actor_user_id
        /// (400 actor_user_required); metadata keys only feature_flag / erased_rows (400 metadata_key_not_allowed); the
        /// data subject: for resource_type 'user' the resource_id (a different subject_user_id is 400 subject_mismatch),
        /// otherwise subject_user_id is required (400 subject_required), a user id or "none".
        /// Writes, in ONE transaction: the subject(s) (found or created with a random 128-bit subject_ref), the
        /// audit_log row (resource_id, old/new value and why_chain_id only when the subject is "none"), the 'actor' row
        /// {actor_id, ip, user_agent, request_id} for a user or api_key actor, and the 'subject' row {resource_id,
        /// old_value, new_value, why_chain_id}. Out: the new entry's id (random). Rewritten 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP. Changed the same day (Phase B.2, audit spec "Refusals by log()"): the codes
        /// invalid_actor_type, actor_required and actor_service_required; a service entry no longer falls back to
        /// actor_id or "service" for its name. Touches: audit_log, audit_personal, audit_subjects.
        /// </summary>
        public Task<string> LogMutationAsync(AuditLogEntry entry)
        {
            if (entry == null) throw new ArgumentNullException(nameof(entry));
            if (string.IsNullOrWhiteSpace(entry.Action) || string.IsNullOrWhiteSpace(entry.ResourceType))
                throw new AuditException(400, "invalid_entry", "action and resource_type are required");
            if (entry.ActorType == null || !Enum.IsDefined(typeof(AuditLogging.ActorType), entry.ActorType.Value))
                throw new AuditException(400, "invalid_actor_type", "actor_type must be 'user', 'service' or 'api_key'");
            var actorType = entry.ActorType.Value;
            if (actorType == AuditLogging.ActorType.User && string.IsNullOrWhiteSpace(entry.ActorId))
                throw new AuditException(400, "actor_required", "a user actor needs actor_id");
            if (actorType == AuditLogging.ActorType.Service && string.IsNullOrWhiteSpace(entry.ActorService))
                throw new AuditException(400, "actor_service_required", "a service actor needs actor_service");
            if (actorType == AuditLogging.ActorType.ApiKey && string.IsNullOrWhiteSpace(entry.ActorUserId))
                throw new AuditException(400, "actor_user_required", "an api_key entry needs actor_user_id (the key's owner)");
            if (entry.Metadata != null && entry.Metadata.Keys.Any(k => !AllowedMetadataKeys.Contains(k)))
                throw new AuditException(400, "metadata_key_not_allowed", "metadata may only hold feature_flag and erased_rows");

            string subjectUser;
            if (entry.ResourceType == "user")
            {
                if (string.IsNullOrWhiteSpace(entry.ResourceId))
                    throw new AuditException(400, "subject_required", "a 'user' entry needs its resource_id");
                if (!string.IsNullOrEmpty(entry.SubjectUserId) && entry.SubjectUserId != entry.ResourceId)
                    throw new AuditException(400, "subject_mismatch", "subject_user_id must be the user resource_id");
                subjectUser = entry.ResourceId;
            }
            else
            {
                if (string.IsNullOrWhiteSpace(entry.SubjectUserId))
                    throw new AuditException(400, "subject_required", "subject_user_id is required (a user id or 'none')");
                subjectUser = entry.SubjectUserId == "none" ? null : entry.SubjectUserId;
            }

            string actorUser = actorType switch
            {
                AuditLogging.ActorType.User => entry.ActorId,
                AuditLogging.ActorType.ApiKey => entry.ActorUserId,
                _ => null
            };

            var roles = new List<string>();
            if (actorUser != null) roles.Add("actor");
            if (subjectUser != null) roles.Add("subject");

            var id = Guid.NewGuid().ToString();
            var now = _clock();
            using var tx = _connection.BeginTransaction();
            using (var cmd = Command(@"INSERT INTO audit_log (id, timestamp, actor_type, actor_service, action, resource_type, resource_id,
                                           old_value, new_value, why_chain_id, personal_roles, metadata)
                                       VALUES (@id, @ts, @at, @svc, @action, @rt, @rid, @old, @new, @why, @roles, @meta)", tx,
                       ("@id", id), ("@ts", Iso(now)), ("@at", ActorTypeText(actorType)),
                       ("@svc", actorType == AuditLogging.ActorType.Service ? entry.ActorService : null),
                       ("@action", entry.Action), ("@rt", entry.ResourceType),
                       ("@rid", subjectUser == null ? entry.ResourceId : null),
                       ("@old", subjectUser == null ? entry.OldValue?.GetRawText() : null),
                       ("@new", subjectUser == null ? entry.NewValue?.GetRawText() : null),
                       ("@why", subjectUser == null ? entry.WhyChainId : null),
                       ("@roles", string.Join(",", roles)),
                       ("@meta", entry.Metadata == null || entry.Metadata.Count == 0 ? null : JsonSerializer.Serialize(entry.Metadata))))
                cmd.ExecuteNonQuery();

            if (actorUser != null)
                InsertPersonal(tx, id, SubjectRef(tx, actorUser, now), "actor", new
                {
                    actor_id = entry.ActorId,
                    ip = entry.Ip,
                    user_agent = entry.UserAgent,
                    request_id = entry.RequestId
                });
            if (subjectUser != null)
                InsertPersonal(tx, id, SubjectRef(tx, subjectUser, now), "subject", new
                {
                    resource_id = entry.ResourceId,
                    old_value = entry.OldValue,
                    new_value = entry.NewValue,
                    why_chain_id = entry.WhyChainId
                });
            tx.Commit();

            entry.Id = id;
            entry.Timestamp = now;
            entry.PersonalRoles = string.Join(",", roles);
            return Task.FromResult(id);
        }

        /// <summary>
        /// The user's subject_ref, created on first use as a random 128-bit value (never derived from the user id),
        /// insert-if-absent on user_id. Inside the caller's transaction. Touches: audit_subjects.
        /// </summary>
        private string SubjectRef(DbTransaction tx, string userId, DateTime now)
        {
            var fresh = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
            using (var ins = Command("INSERT INTO audit_subjects (subject_ref, user_id, created_at) VALUES (@ref, @uid, @now) ON CONFLICT (user_id) DO NOTHING", tx,
                       ("@ref", fresh), ("@uid", userId), ("@now", Iso(now))))
                ins.ExecuteNonQuery();
            using var sel = Command("SELECT subject_ref FROM audit_subjects WHERE user_id = @uid", tx, ("@uid", userId));
            return (string)sel.ExecuteScalar();
        }

        /// <summary>Inserts one audit_personal row. Inside the caller's transaction. Touches: audit_personal.</summary>
        private void InsertPersonal(DbTransaction tx, string logId, string subjectRef, string role, object data)
        {
            using var cmd = Command("INSERT INTO audit_personal (log_id, subject_ref, role, data) VALUES (@log, @ref, @role, @data)", tx,
                ("@log", logId), ("@ref", subjectRef), ("@role", role), ("@data", JsonSerializer.Serialize(data)));
            cmd.ExecuteNonQuery();
        }

        /// <summary>Refuses a caller who is not an admin with 403 admin_only (AUDIT-10). Pure.</summary>
        private static void RequireAdmin(AuditCaller caller)
        {
            if (caller == null || !caller.IsAdmin)
                throw new AuditException(403, "admin_only", "audit reads are for admins only");
        }

        /// <summary>The columns every read selects: the entry and its two personal rows.</summary>
        private const string SelectEntry = @"
            SELECT l.seq, l.id, l.timestamp, l.actor_type, l.actor_service, l.action, l.resource_type, l.resource_id,
                   l.old_value, l.new_value, l.why_chain_id, l.personal_roles, l.metadata, pa.data AS actor_data, ps.data AS subject_data
            FROM audit_log l
            LEFT JOIN audit_personal pa ON pa.log_id = l.id AND pa.role = 'actor'
            LEFT JOIN audit_personal ps ON ps.log_id = l.id AND ps.role = 'subject'";

        /// <summary>
        /// Escapes a filter for GLOB, where only * is a wildcard: ? and [ are matched literally. Changed 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP (GLOB instead of LIKE ... ESCAPE, so a prefix uses the action index). Pure.
        /// </summary>
        private static string GlobPattern(string s) => s.Replace("[", "[[]").Replace("?", "[?]");

        /// <summary>
        /// query (admin only, AUDIT-01/03/04/07/08): filters by actor (a user id, matched through the actor's
        /// audit_personal rows, so an erased actor matches nothing), action (* is the only wildcard: 'user_*'), resource
        /// type and a time window; newest first, ties newest inserted first. Out: the page, the total and has_more.
        /// Entries come back with their personal fields joined, or null with PersonalErased true after erasure.
        /// Indexes: (action, resource_type, timestamp) for action filters, (timestamp, action, resource_type) for time
        /// windows and the newest-first order, (subject_ref, role) for the actor filter; AUDIT-05 checks 1M entries in
        /// under 100 ms. Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the database.
        /// </summary>
        public async Task<(IEnumerable<AuditLogEntry> Logs, int Total, bool HasMore)> QueryLogsAsync(
            AuditCaller caller,
            string actorId = null,
            string action = null,
            string resourceType = null,
            int limit = 100,
            int offset = 0,
            DateTime? dateFrom = null,
            DateTime? dateTo = null)
        {
            RequireAdmin(caller);
            var where = new List<string>();
            var args = new List<(string, object)>();
            if (actorId != null)
            {
                using var refCmd = Command("SELECT subject_ref FROM audit_subjects WHERE user_id = @uid", null, ("@uid", actorId));
                var subjectRef = (string)await refCmd.ExecuteScalarAsync();
                if (subjectRef == null)
                    return (new List<AuditLogEntry>(), 0, false);
                where.Add("l.id IN (SELECT log_id FROM audit_personal WHERE subject_ref = @aref AND role = 'actor')");
                args.Add(("@aref", subjectRef));
            }
            // With a time window the timestamp index (covering action and resource_type) drives the query: the unary +
            // keeps SQLite from choosing the action index, which made a one-day window scan every matching action.
            var window = dateFrom.HasValue || dateTo.HasValue ? "+" : "";
            if (!string.IsNullOrEmpty(action))
            {
                where.Add(window + "l.action GLOB @action");
                args.Add(("@action", GlobPattern(action)));
            }
            if (!string.IsNullOrEmpty(resourceType))
            {
                where.Add(window + "l.resource_type = @rt");
                args.Add(("@rt", resourceType));
            }
            if (dateFrom.HasValue)
            {
                where.Add("l.timestamp >= @from");
                args.Add(("@from", Iso(dateFrom.Value)));
            }
            if (dateTo.HasValue)
            {
                where.Add("l.timestamp <= @to");
                args.Add(("@to", Iso(dateTo.Value)));
            }
            var whereSql = where.Count > 0 ? " WHERE " + string.Join(" AND ", where) : "";

            int total;
            using (var count = Command("SELECT COUNT(*) FROM audit_log l" + whereSql, null, args.ToArray()))
                total = Convert.ToInt32(await count.ExecuteScalarAsync());

            // The page is chosen first, then only its rows are joined to their personal data.
            var pageArgs = args.Concat(new (string, object)[] { ("@limit", Math.Max(0, limit)), ("@offset", Math.Max(0, offset)) }).ToArray();
            var pageSql = SelectEntry.Replace("FROM audit_log l",
                "FROM (SELECT l.* FROM audit_log l" + whereSql + " ORDER BY l.timestamp DESC, l.seq DESC LIMIT @limit OFFSET @offset) l");
            using var data = Command(pageSql + " ORDER BY l.timestamp DESC, l.seq DESC", null, pageArgs);
            var logs = new List<AuditLogEntry>();
            using (var reader = await data.ExecuteReaderAsync())
                while (await reader.ReadAsync())
                    logs.Add(ReadEntry(reader));
            return (logs, total, offset + logs.Count < total);
        }

        /// <summary>
        /// replay (admin only, AUDIT-02): the state an entry recorded (its old_value) and whether a later entry changed
        /// the same resource. For an entry whose subject data was erased: {erased: true, state null, has_diverged null}.
        /// erased reflects the entry's own 'subject' row only: true when the entry was written with one and it is gone;
        /// an entry whose actor alone was erased, or one with no subject, replays with erased false.
        /// Throws AuditException 404 for an unknown id. Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// Changed the same day (Phase B.2, "replay erased reflects the entry's subject row"): the subject row is checked
        /// directly instead of inferred from PersonalErased and a null resource_id. Touches: reads the database.
        /// </summary>
        public async Task<ReplayResult> ReplayAsync(AuditCaller caller, string logId)
        {
            RequireAdmin(caller);
            AuditLogEntry entry;
            long seq;
            using (var cmd = Command(SelectEntry + " WHERE l.id = @id", null, ("@id", logId)))
            using (var reader = await cmd.ExecuteReaderAsync())
            {
                if (!await reader.ReadAsync())
                    throw new AuditException(404, "not_found", $"Log with id {logId} not found.");
                seq = reader.GetInt64(0);
                entry = ReadEntry(reader);
            }

            bool subjectErased = false;
            if (entry.PersonalRoles.Split(',').Contains("subject"))
            {
                using var subjectRow = Command("SELECT 1 FROM audit_personal WHERE log_id = @id AND role = 'subject'", null, ("@id", entry.Id));
                subjectErased = await subjectRow.ExecuteScalarAsync() == null;
            }
            if (subjectErased)
                return new ReplayResult { LogId = entry.Id, Timestamp = entry.Timestamp, Erased = true, ResourceStateAtTime = null, HasDiverged = null };

            using var diverge = Command(@"
                SELECT 1 FROM audit_log l
                LEFT JOIN audit_personal ps ON ps.log_id = l.id AND ps.role = 'subject'
                WHERE l.resource_type = @rt
                  AND COALESCE(l.resource_id, json_extract(ps.data, '$.resource_id')) = @rid
                  AND (l.timestamp > @ts OR (l.timestamp = @ts AND l.seq > @seq))
                LIMIT 1", null,
                ("@rt", entry.ResourceType), ("@rid", entry.ResourceId), ("@ts", Iso(entry.Timestamp)), ("@seq", seq));
            var hasDiverged = await diverge.ExecuteScalarAsync() != null;
            return new ReplayResult { LogId = entry.Id, Timestamp = entry.Timestamp, ResourceStateAtTime = entry.OldValue, HasDiverged = hasDiverged };
        }

        /// <summary>Escapes LIKE's own wildcards and its escape character, for use with ESCAPE '\'. A literal
        /// %, _ or \ in a search then matches only itself (CodeRabbit, PR 18, 2026-11-09).</summary>
        private static string EscapeLike(string s) => s.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");

        /// <summary>
        /// search (admin only): substring search over action and resource type (%, _ and \ match themselves), newest
        /// first. Out: up to <paramref name="limit"/> entries, personal fields as in query. Changed 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP: admin-only, personal rows joined. Touches: reads the database.
        /// </summary>
        public async Task<IEnumerable<AuditLogEntry>> SearchAsync(AuditCaller caller, string query, string resourceType = null, int limit = 50)
        {
            RequireAdmin(caller);
            var sql = SelectEntry + " WHERE (l.action LIKE @q ESCAPE '\\' OR l.resource_type LIKE @q ESCAPE '\\')";
            var args = new List<(string, object)> { ("@q", $"%{EscapeLike(query ?? "")}%"), ("@limit", Math.Max(0, limit)) };
            if (!string.IsNullOrEmpty(resourceType))
            {
                sql += " AND l.resource_type = @rt";
                args.Add(("@rt", resourceType));
            }
            using var cmd = Command(sql + " ORDER BY l.timestamp DESC, l.seq DESC LIMIT @limit", null, args.ToArray());
            var results = new List<AuditLogEntry>();
            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
                results.Add(ReadEntry(reader));
            return results;
        }

        /// <summary>
        /// erase_subject(user_id) (AUDIT-08): deletes every audit_personal row with the user's subject_ref, then the
        /// user's audit_subjects row, in one transaction; no audit_log row is updated or deleted. Then adds exactly one
        /// entry: 'audit_subject_erased', actor_type 'service', resource_type 'user', no subject, resource_id NULL,
        /// personal_roles '', metadata {erased_rows}. Out: erased_rows (the personal rows deleted; 0 for an unknown user).
        /// Nothing may log this user afterwards. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: audit_personal,
        /// audit_subjects, one audit_log insert.
        /// </summary>
        public Task<int> EraseSubjectAsync(string userId)
        {
            int erased;
            using (var tx = _connection.BeginTransaction())
            {
                using (var del = Command("DELETE FROM audit_personal WHERE subject_ref IN (SELECT subject_ref FROM audit_subjects WHERE user_id = @uid)", tx, ("@uid", userId)))
                    erased = del.ExecuteNonQuery();
                using (var delSubject = Command("DELETE FROM audit_subjects WHERE user_id = @uid", tx, ("@uid", userId)))
                    delSubject.ExecuteNonQuery();
                tx.Commit();
            }
            AppendServiceEntry("audit_subject_erased", erased);
            return Task.FromResult(erased);
        }

        /// <summary>
        /// apply_retention(now) (AUDIT-09): deletes the audit_personal rows of entries older than the retention period,
        /// then every audit_subjects row left with no audit_personal row, in one transaction. audit_log rows stay.
        /// Out: erased_rows (the personal rows deleted). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// Touches: audit_personal, audit_subjects.
        /// </summary>
        public Task<int> ApplyRetentionAsync(DateTime now)
        {
            int erased;
            using var tx = _connection.BeginTransaction();
            using (var del = Command(@"DELETE FROM audit_personal WHERE log_id IN
                                         (SELECT id FROM audit_log WHERE timestamp < @cutoff)", tx, ("@cutoff", Iso(now - _retention))))
                erased = del.ExecuteNonQuery();
            using (var orphans = Command(@"DELETE FROM audit_subjects WHERE NOT EXISTS
                                             (SELECT 1 FROM audit_personal p WHERE p.subject_ref = audit_subjects.subject_ref)", tx))
                orphans.ExecuteNonQuery();
            tx.Commit();
            return Task.FromResult(erased);
        }

        /// <summary>Appends an entry by the audit service itself, with no personal data. Touches: one audit_log insert.</summary>
        private void AppendServiceEntry(string action, int erasedRows)
        {
            using var cmd = Command(@"INSERT INTO audit_log (id, timestamp, actor_type, actor_service, action, resource_type, resource_id,
                                          old_value, new_value, why_chain_id, personal_roles, metadata)
                                      VALUES (@id, @ts, 'service', 'audit', @action, 'user', NULL, NULL, NULL, NULL, '', @meta)", null,
                ("@id", Guid.NewGuid().ToString()), ("@ts", Iso(_clock())), ("@action", action),
                ("@meta", JsonSerializer.Serialize(new Dictionary<string, object> { ["erased_rows"] = erasedRows })));
            cmd.ExecuteNonQuery();
        }

        /// <summary>
        /// Builds an entry from a row of <see cref="SelectEntry"/>: the event, then its actor and subject data when their
        /// rows still exist; PersonalErased when personal_roles names a row that is gone. Pure (reads the row).
        /// </summary>
        private static AuditLogEntry ReadEntry(DbDataReader r)
        {
            string Str(string name) { var o = r.GetOrdinal(name); return r.IsDBNull(o) ? null : r.GetString(o); }
            JsonElement? Json(string text) => text == null ? null : JsonSerializer.Deserialize<JsonElement>(text);

            var entry = new AuditLogEntry
            {
                Id = Str("id"),
                Timestamp = ParseIso(Str("timestamp")),
                ActorType = ParseActorType(Str("actor_type")),
                ActorService = Str("actor_service"),
                Action = Str("action"),
                ResourceType = Str("resource_type"),
                ResourceId = Str("resource_id"),
                OldValue = Json(Str("old_value")),
                NewValue = Json(Str("new_value")),
                WhyChainId = Str("why_chain_id"),
                PersonalRoles = Str("personal_roles") ?? ""
            };
            var meta = Str("metadata");
            if (meta != null)
                entry.Metadata = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(meta).ToDictionary(kv => kv.Key, kv => (object)kv.Value);

            var roles = entry.PersonalRoles.Split(',', StringSplitOptions.RemoveEmptyEntries);
            var actor = Str("actor_data");
            var subject = Str("subject_data");
            if (actor != null)
            {
                using var doc = JsonDocument.Parse(actor);
                entry.ActorId = Prop(doc.RootElement, "actor_id");
                entry.Ip = Prop(doc.RootElement, "ip");
                entry.UserAgent = Prop(doc.RootElement, "user_agent");
                entry.RequestId = Prop(doc.RootElement, "request_id");
            }
            if (subject != null)
            {
                using var doc = JsonDocument.Parse(subject);
                var root = doc.RootElement;
                entry.ResourceId = Prop(root, "resource_id");
                entry.OldValue = root.TryGetProperty("old_value", out var o) && o.ValueKind != JsonValueKind.Null ? o.Clone() : null;
                entry.NewValue = root.TryGetProperty("new_value", out var n) && n.ValueKind != JsonValueKind.Null ? n.Clone() : null;
                entry.WhyChainId = Prop(root, "why_chain_id");
            }
            entry.PersonalErased = (roles.Contains("actor") && actor == null) || (roles.Contains("subject") && subject == null);
            return entry;
        }

        /// <summary>A string property of a JSON object, or null. Pure.</summary>
        private static string Prop(JsonElement e, string name) =>
            e.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Null ? (v.ValueKind == JsonValueKind.String ? v.GetString() : v.GetRawText()) : null;

        /// <summary>
        /// Marks the repository disposed. The connection belongs to the caller and is not closed here. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
        /// </summary>
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

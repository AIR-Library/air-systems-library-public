// Tests for the audit logging template. Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, for the spec amendment
// of that day: log() now needs subject_user_id for non-'user' entries, ids are strings, reads take the verified caller
// (admins only), and erase_subject / apply_retention are covered (AUDIT-08/09/10). The earlier tests keep their names
// and assertions; the performance test (AUDIT-05) is new. Touches: private in-memory SQLite databases only.
using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AuditLogging;
using Microsoft.Data.Sqlite;
using Xunit;

public class AuditLoggingTests : IDisposable
{
    private readonly AuditLogRepository _repo;
    private readonly DbConnection _connection;
    private static readonly AuditCaller Admin = AuditCaller.Admin();
    private DateTime _now = new DateTime(2026, 11, 10, 12, 0, 0, DateTimeKind.Utc);

    /// <summary>A fresh in-memory database with a 90-day retention and a clock that advances 1 ms per entry. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public AuditLoggingTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
        _repo = new AuditLogRepository(_connection, TimeSpan.FromDays(90), () => _now = _now.AddMilliseconds(1));
    }

    public void Dispose()
    {
        _repo.Dispose();
        _connection.Dispose();
    }

    private static JsonElement J(string json) => JsonSerializer.Deserialize<JsonElement>(json);

    /// <summary>
    /// Logs a user actor's mutation. The subject is the resource for a 'user' entry, else <paramref name="subject"/>.
    /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: string ids and the required subject.
    /// </summary>
    private async Task<string> LogSampleAsync(string actorId = "123", string action = "user_created", string resourceType = "user",
        string resourceId = "456", string subject = "none", string ip = "198.51.100.1")
    {
        var entry = new AuditLogEntry
        {
            ActorId = actorId,
            ActorType = ActorType.User,
            Action = action,
            ResourceType = resourceType,
            ResourceId = resourceId,
            SubjectUserId = resourceType == "user" ? null : subject,
            OldValue = J("{\"tier\":\"team\"}"),
            NewValue = J("{\"tier\":\"enterprise\"}"),
            WhyChainId = "wc_789",
            Ip = ip
        };
        return await _repo.LogMutationAsync(entry);
    }

    // AUDIT-01
    [Fact]
    public async Task HappyPath_LogAndQuery()
    {
        var logId = await LogSampleAsync();
        var result = await _repo.QueryLogsAsync(Admin, actorId: "123", action: "user_*", resourceType: "user");
        Assert.Single(result.Logs);
        var log = result.Logs.First();
        Assert.Equal(logId, log.Id);
        Assert.Equal("user_created", log.Action);
        Assert.Equal("user", log.ResourceType);
        Assert.Equal("456", log.ResourceId);
        Assert.Equal("123", log.ActorId);
        Assert.Equal("{\"tier\":\"enterprise\"}", log.NewValue!.Value.GetRawText());
        Assert.Equal("wc_789", log.WhyChainId);
        Assert.Equal("actor,subject", log.PersonalRoles);
        Assert.False(log.PersonalErased);
    }

    // AUDIT-02
    [Fact]
    public async Task Replay_DivergenceDetection()
    {
        var firstLogId = await LogSampleAsync();
        var unrelated = await LogSampleAsync(resourceId: "999");
        // mutate same resource again
        await LogSampleAsync(action: "user_suspended");
        var replay = await _repo.ReplayAsync(Admin, firstLogId);
        Assert.Equal(firstLogId, replay.LogId);
        Assert.True(replay.HasDiverged);
        Assert.NotNull(replay.ResourceStateAtTime);
        Assert.Equal("{\"tier\":\"team\"}", replay.ResourceStateAtTime!.Value.GetRawText());
        Assert.False((await _repo.ReplayAsync(Admin, unrelated)).HasDiverged); // nothing changed resource 999 since
    }

    // AUDIT-03
    [Fact]
    public async Task Filtering_ActorActionResource()
    {
        await LogSampleAsync(action: "user_created");
        await LogSampleAsync(action: "user_suspended");
        await LogSampleAsync(action: "billing_changed", resourceType: "subscription");
        await LogSampleAsync(actorId: "77", action: "user_created");
        var result = await _repo.QueryLogsAsync(Admin, actorId: "123", action: "user_*", resourceType: "user");
        Assert.Equal(2, result.Total);
        Assert.All(result.Logs, l => Assert.StartsWith("user_", l.Action));
        Assert.All(result.Logs, l => Assert.Equal("123", l.ActorId));
    }

    // AUDIT-04
    [Fact]
    public async Task Pagination_LimitOffset()
    {
        for (int i = 0; i < 150; i++)
        {
            await LogSampleAsync(action: $"action_{i}", resourceType: "deployment", resourceId: "d" + i);
        }
        var firstPage = await _repo.QueryLogsAsync(Admin, limit: 100, offset: 0);
        var secondPage = await _repo.QueryLogsAsync(Admin, limit: 100, offset: 100);
        Assert.Equal(100, firstPage.Logs.Count());
        Assert.Equal(50, secondPage.Logs.Count());
        Assert.True(firstPage.HasMore);
        Assert.False(secondPage.HasMore);
        Assert.Equal("action_149", firstPage.Logs.First().Action); // newest first
        Assert.Equal("action_0", secondPage.Logs.Last().Action);
    }

    // AUDIT-06
    [Fact]
    public async Task Immutability_UpdateFails()
    {
        var logId = await LogSampleAsync();
        var ex = await Assert.ThrowsAsync<SqliteException>(async () =>
        {
            var cmd = _connection.CreateCommand();
            cmd.CommandText = "UPDATE audit_log SET action = 'hacked' WHERE id = @id;";
            cmd.Parameters.Add(new SqliteParameter("@id", logId));
            await cmd.ExecuteNonQueryAsync();
        });
        Assert.Contains("cannot", ex.Message, StringComparison.OrdinalIgnoreCase);

        // DELETE is refused too, and personal rows are never updated (added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
        foreach (var sql in new[] { "DELETE FROM audit_log WHERE id = @id;", "UPDATE audit_personal SET data = '{}' WHERE log_id = @id;" })
        {
            var refused = await Assert.ThrowsAsync<SqliteException>(async () =>
            {
                var cmd = _connection.CreateCommand();
                cmd.CommandText = sql;
                cmd.Parameters.Add(new SqliteParameter("@id", logId));
                await cmd.ExecuteNonQueryAsync();
            });
            Assert.Contains("cannot", refused.Message, StringComparison.OrdinalIgnoreCase);
        }
    }

    // AUDIT-07
    [Fact]
    public async Task Wildcard_ActionMatches()
    {
        await LogSampleAsync(action: "user_created");
        await LogSampleAsync(action: "user_suspended");
        await LogSampleAsync(action: "billing_changed");
        var result = await _repo.QueryLogsAsync(Admin, action: "user_*");
        Assert.Equal(2, result.Total);
    }

    [Fact]
    public async Task Search_FullText()
    {
        await LogSampleAsync(action: "subscription_changed", resourceType: "subscription", subject: "456");
        await LogSampleAsync(action: "user_created");
        var results = await _repo.SearchAsync(Admin, "subscription");
        Assert.Single(results);
        Assert.Equal("subscription_changed", results.First().Action);
    }

    [Fact]
    public async Task Wildcard_Underscore_IsLiteral_InQueryAndSearch()
    {
        // "user_*" must not match "userXcreated"; Search for "r_c" must not match "userXcreated" (CodeRabbit, PR 18).
        await LogSampleAsync(action: "user_created");
        await LogSampleAsync(action: "userXcreated");
        var result = await _repo.QueryLogsAsync(Admin, actorId: "123", action: "user_*", resourceType: "user");
        Assert.Equal(1, result.Total);
        var found = await _repo.SearchAsync(Admin, "r_c");
        Assert.Single(found);
        Assert.Equal("user_created", found.First().Action);
    }

    /// <summary>All text of every row of the three audit tables, for leak checks. Touches: reads the database.</summary>
    private async Task<List<string>> AllRowsText()
    {
        var rows = new List<string>();
        foreach (var table in new[] { "audit_log", "audit_personal", "audit_subjects" })
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = $"SELECT * FROM {table}";
            using var r = await cmd.ExecuteReaderAsync();
            while (await r.ReadAsync())
                rows.Add(table + ":" + string.Join("|", Enumerable.Range(0, r.FieldCount).Select(i => r.IsDBNull(i) ? "" : Convert.ToString(r.GetValue(i), System.Globalization.CultureInfo.InvariantCulture))));
        }
        return rows;
    }

    /// <summary>
    /// AUDIT-08: erase_subject on a user who signed up, acted with an IP, and was acted on by an admin leaves no row in
    /// audit_log, audit_personal or audit_subjects holding their id, email or IP; every earlier audit_log row is
    /// unchanged and exactly one row is added ('audit_subject_erased', personal_roles '', metadata {erased_rows});
    /// queries show their entries with personal_erased true, and an actor_id filter for them finds nothing; replay of
    /// an erased entry says erased. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    // AUDIT-08
    [Fact]
    public async Task EraseSubject_LeavesNoPersonalData_AndKeepsEveryEvent()
    {
        const string user = "987654321", email = "erase.me@example.test", ip = "203.0.113.77";
        var created = await _repo.LogMutationAsync(new AuditLogEntry
        {
            ActorType = ActorType.User, ActorId = user, Action = "user_created", ResourceType = "user", ResourceId = user,
            NewValue = J($"{{\"email\":\"{email}\"}}"), Ip = ip, UserAgent = "Firefox", RequestId = "req-1"
        });
        await _repo.LogMutationAsync(new AuditLogEntry
        {
            ActorType = ActorType.User, ActorId = user, Action = "deployment_created", ResourceType = "deployment",
            ResourceId = "dep-1", SubjectUserId = user, NewValue = J("{\"domain\":\"x.example\"}"), Ip = ip
        });
        await _repo.LogMutationAsync(new AuditLogEntry
        {
            ActorType = ActorType.User, ActorId = "1", Action = "user_suspended", ResourceType = "user", ResourceId = user,
            OldValue = J($"{{\"email\":\"{email}\",\"status\":\"active\"}}"), Ip = "198.51.100.9"
        });
        await _repo.LogMutationAsync(new AuditLogEntry
        {
            ActorType = ActorType.Service, ActorService = "billing", Action = "invoice_created", ResourceType = "invoice",
            ResourceId = "inv-1", SubjectUserId = "none", Metadata = new Dictionary<string, object> { ["feature_flag"] = "new_invoices" }
        });
        Assert.Contains(await AllRowsText(), r => r.Contains(email)); // present before
        var logBefore = (await AllRowsText()).Where(r => r.StartsWith("audit_log:")).ToList();

        var erased = await _repo.EraseSubjectAsync(user);
        Assert.Equal(5, erased); // the user's two actor rows and three subject rows

        var after = await AllRowsText();
        Assert.DoesNotContain(after, r => r.Contains(user) || r.Contains(email) || r.Contains(ip));
        var logAfter = after.Where(r => r.StartsWith("audit_log:")).ToList();
        Assert.Equal(logBefore.Count + 1, logAfter.Count);
        Assert.Equal(logBefore, logAfter.Take(logBefore.Count)); // earlier rows unchanged

        var all = await _repo.QueryLogsAsync(Admin, limit: 10);
        var marker = all.Logs.First();
        Assert.Equal("audit_subject_erased", marker.Action);
        Assert.Equal("", marker.PersonalRoles);
        Assert.Equal(ActorType.Service, marker.ActorType);
        Assert.Null(marker.ResourceId);
        Assert.Equal(5, ((JsonElement)marker.Metadata["erased_rows"]).GetInt32());

        var mine = all.Logs.Where(l => l.Action is "user_created" or "deployment_created").ToList();
        Assert.Equal(2, mine.Count);
        Assert.All(mine, l => Assert.True(l.PersonalErased));
        Assert.All(mine, l => Assert.Null(l.ActorId));
        Assert.Null(mine.Single(l => l.Action == "user_created").NewValue);
        var suspended = all.Logs.Single(l => l.Action == "user_suspended");
        Assert.True(suspended.PersonalErased);   // its subject row is gone
        Assert.Equal("1", suspended.ActorId);    // the admin's actor row stays
        Assert.Equal(0, (await _repo.QueryLogsAsync(Admin, actorId: user)).Total);

        var replay = await _repo.ReplayAsync(Admin, created);
        Assert.True(replay.Erased);
        Assert.Null(replay.ResourceStateAtTime);
        Assert.Null(replay.HasDiverged);
    }

    /// <summary>
    /// AUDIT-09: apply_retention erases the personal data of entries older than the retention period (90 days here);
    /// newer entries keep theirs; no audit_log row is removed. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    // AUDIT-09
    [Fact]
    public async Task ApplyRetention_ErasesOldPersonalData_KeepsEvents()
    {
        var old = await LogSampleAsync(actorId: "500", resourceId: "500", ip: "192.0.2.50");
        _now = _now.AddDays(80);
        var recent = await LogSampleAsync(actorId: "501", resourceId: "501", ip: "192.0.2.51");
        _now = _now.AddDays(15); // old is 95 days old, recent 15

        var erased = await _repo.ApplyRetentionAsync(_now);
        Assert.Equal(2, erased); // the old entry's actor and subject rows

        var logs = (await _repo.QueryLogsAsync(Admin)).Logs.ToList();
        Assert.Equal(2, logs.Count); // no event removed
        var oldEntry = logs.Single(l => l.Id == old);
        Assert.True(oldEntry.PersonalErased);
        Assert.Null(oldEntry.Ip);
        Assert.Null(oldEntry.ResourceId);
        var recentEntry = logs.Single(l => l.Id == recent);
        Assert.False(recentEntry.PersonalErased);
        Assert.Equal("192.0.2.51", recentEntry.Ip);
        Assert.Equal("501", recentEntry.ResourceId);
        Assert.DoesNotContain(await AllRowsText(), r => r.StartsWith("audit_subjects:") && r.Contains("|500|"));
    }

    /// <summary>
    /// AUDIT-10: log() refuses a non-'user' entry without subject_user_id (400 subject_required), a metadata key other
    /// than feature_flag / erased_rows (400 metadata_key_not_allowed), an api_key entry without actor_user_id (400
    /// actor_user_required) and a 'user' entry with another subject (400 subject_mismatch); nothing is written. Reads
    /// by a non-admin caller get 403. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    // AUDIT-10
    [Fact]
    public async Task Log_RefusesMissingSubjectBadMetadataKeyAndApiKeyWithoutOwner_ReadsAreAdminOnly()
    {
        async Task Refused(AuditLogEntry e, string code)
        {
            var ex = await Assert.ThrowsAsync<AuditException>(() => _repo.LogMutationAsync(e));
            Assert.Equal(400, ex.Status);
            Assert.Equal(code, ex.Code);
        }
        await Refused(new AuditLogEntry { ActorType = ActorType.User, ActorId = "1", Action = "session_created", ResourceType = "session", ResourceId = "s1", Ip = "192.0.2.1" }, "subject_required");
        await Refused(new AuditLogEntry { ActorType = ActorType.Service, ActorService = "x", Action = "a_b", ResourceType = "deployment", SubjectUserId = "none", Metadata = new Dictionary<string, object> { ["ip"] = "192.0.2.1" } }, "metadata_key_not_allowed");
        await Refused(new AuditLogEntry { ActorType = ActorType.ApiKey, ActorId = "key_1", Action = "deployment_created", ResourceType = "deployment", SubjectUserId = "none" }, "actor_user_required");
        await Refused(new AuditLogEntry { ActorType = ActorType.User, ActorId = "1", Action = "user_created", ResourceType = "user", ResourceId = "2", SubjectUserId = "3" }, "subject_mismatch");
        Assert.Empty(await AllRowsText());

        // an api_key entry with its owner: the actor row is under the owner, with the key id
        await _repo.LogMutationAsync(new AuditLogEntry { ActorType = ActorType.ApiKey, ActorId = "key_1", ActorUserId = "42", Action = "deployment_created", ResourceType = "deployment", ResourceId = "d1", SubjectUserId = "none" });
        var byOwner = await _repo.QueryLogsAsync(Admin, actorId: "42");
        Assert.Equal("key_1", Assert.Single(byOwner.Logs).ActorId);

        var stranger = AuditCaller.User("42");
        Assert.Equal(403, (await Assert.ThrowsAsync<AuditException>(() => _repo.QueryLogsAsync(stranger))).Status);
        Assert.Equal(403, (await Assert.ThrowsAsync<AuditException>(() => _repo.SearchAsync(stranger, "deployment"))).Status);
        Assert.Equal(403, (await Assert.ThrowsAsync<AuditException>(() => _repo.ReplayAsync(stranger, byOwner.Logs.First().Id))).Status);
        Assert.Equal(403, (await Assert.ThrowsAsync<AuditException>(() => _repo.QueryLogsAsync(null))).Status);
    }

    /// <summary>
    /// AUDIT-10 (Phase B.2 amendment, "Refusals by log()"): a missing actor_type or one outside user / service /
    /// api_key is 400 invalid_actor_type; a 'user' actor without actor_id is 400 actor_required; a 'service' actor
    /// without actor_service is 400 actor_service_required; nothing is written. In: nothing. Out: asserts. Added
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test's in-memory SQLite database.
    /// </summary>
    // AUDIT-10
    [Fact]
    public async Task Log_RefusesBadActorTypeMissingActorAndMissingServiceName()
    {
        async Task Refused(AuditLogEntry e, string code)
        {
            var ex = await Assert.ThrowsAsync<AuditException>(() => _repo.LogMutationAsync(e));
            Assert.Equal(400, ex.Status);
            Assert.Equal(code, ex.Code);
        }
        await Refused(new AuditLogEntry { ActorType = null, ActorId = "1", Action = "user_created", ResourceType = "user", ResourceId = "2" }, "invalid_actor_type");
        await Refused(new AuditLogEntry { ActorType = (ActorType)99, ActorId = "1", Action = "user_created", ResourceType = "user", ResourceId = "2" }, "invalid_actor_type");
        await Refused(new AuditLogEntry { ActorType = ActorType.User, Action = "user_created", ResourceType = "user", ResourceId = "2" }, "actor_required");
        await Refused(new AuditLogEntry { ActorType = ActorType.User, ActorId = " ", Action = "user_created", ResourceType = "user", ResourceId = "2" }, "actor_required");
        await Refused(new AuditLogEntry { ActorType = ActorType.Service, ActorId = "billing", Action = "invoice_created", ResourceType = "invoice", ResourceId = "i1", SubjectUserId = "none" }, "actor_service_required");
        Assert.Empty(await AllRowsText());

        await _repo.LogMutationAsync(new AuditLogEntry { ActorType = ActorType.Service, ActorService = "billing", Action = "invoice_created", ResourceType = "invoice", ResourceId = "i1", SubjectUserId = "none" });
        Assert.Equal("billing", Assert.Single((await _repo.QueryLogsAsync(Admin)).Logs).ActorService);
    }

    /// <summary>
    /// AUDIT-08 (Phase B.2 amendment): replay's erased reflects the entry's own subject row. An admin's entry about a
    /// user replays with erased false after only the admin is erased (its subject row stays) and erased true once the
    /// user is erased; an entry with subject 'none' replays with erased false after its actor is erased. erased_rows
    /// counts the audit_personal rows deleted. In: nothing. Out: asserts. Added 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test's in-memory SQLite database.
    /// </summary>
    // AUDIT-08
    [Fact]
    public async Task Replay_ErasedFollowsTheEntrysSubjectRow()
    {
        var aboutUser = await LogSampleAsync(actorId: "1", action: "user_suspended", resourceType: "user", resourceId: "77");
        var noSubject = await LogSampleAsync(actorId: "1", action: "deployment_created", resourceType: "deployment", resourceId: "dep-9", subject: "none");

        Assert.Equal(2, await _repo.EraseSubjectAsync("1")); // the admin's two actor rows
        var afterAdmin = await _repo.ReplayAsync(Admin, aboutUser);
        Assert.False(afterAdmin.Erased);
        // The subject's snapshot is still there (only the admin's actor rows were erased). Asserted before use:
        // code-quality review on PR 21, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Assert.NotNull(afterAdmin.ResourceStateAtTime);
        Assert.Equal("team", afterAdmin.ResourceStateAtTime.Value.GetProperty("tier").GetString());
        var noSubjectReplay = await _repo.ReplayAsync(Admin, noSubject);
        Assert.False(noSubjectReplay.Erased);
        Assert.NotNull(noSubjectReplay.ResourceStateAtTime);

        Assert.Equal(1, await _repo.EraseSubjectAsync("77")); // the user's one subject row
        var afterUser = await _repo.ReplayAsync(Admin, aboutUser);
        Assert.True(afterUser.Erased);
        Assert.Null(afterUser.ResourceStateAtTime);
        Assert.Null(afterUser.HasDiverged);
    }

    /// <summary>
    /// AUDIT-05: with 1,000,000 entries (seeded directly in one transaction; 1% by user actors with personal rows) an
    /// unfiltered page, a filtered page (actor + action wildcard + resource type) and a time-window page each return in
    /// under 100 ms, with their totals. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (the suite had no AUDIT-05
    /// test). Touches: a private in-memory SQLite database.
    /// </summary>
    // AUDIT-05
    [Fact]
    public async Task Performance_OneMillionLogs_QueriesUnder100ms()
    {
        const int n = 1_000_000;
        var start = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        static SqliteParameter Param(DbCommand cmd, string name)
        {
            var p = new SqliteParameter(name, "");
            cmd.Parameters.Add(p);
            return p;
        }
        using (var tx = _connection.BeginTransaction())
        {
            using var log = _connection.CreateCommand();
            log.Transaction = tx;
            log.CommandText = @"INSERT INTO audit_log (id, timestamp, actor_type, actor_service, action, resource_type, resource_id, personal_roles)
                                VALUES (@id, @ts, @at, @svc, @action, @rt, @rid, @roles)";
            var pId = Param(log, "@id");
            var pTs = Param(log, "@ts");
            var pAt = Param(log, "@at");
            var pSvc = Param(log, "@svc");
            var pAction = Param(log, "@action");
            var pRt = Param(log, "@rt");
            var pRid = Param(log, "@rid");
            var pRoles = Param(log, "@roles");
            using var personal = _connection.CreateCommand();
            personal.Transaction = tx;
            personal.CommandText = "INSERT INTO audit_personal (log_id, subject_ref, role, data) VALUES (@log, @ref, 'actor', @data)";
            var qLog = Param(personal, "@log");
            var qRef = Param(personal, "@ref");
            var qData = Param(personal, "@data");
            using (var subjects = _connection.CreateCommand())
            {
                subjects.Transaction = tx;
                subjects.CommandText = "INSERT INTO audit_subjects (subject_ref, user_id, created_at) VALUES ('ref_123', '123', '2026-01-01'), ('ref_77', '77', '2026-01-01')";
                subjects.ExecuteNonQuery();
            }
            string[] actions = { "deployment_created", "deployment_updated", "billing_changed", "invoice_created", "user_created", "user_suspended" };
            for (var i = 0; i < n; i++)
            {
                var id = "log-" + i.ToString("D7");
                var byUser = i % 100 == 0;
                pId.Value = id;
                pTs.Value = start.AddSeconds(i).ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'");
                pAt.Value = byUser ? "user" : "service";
                pSvc.Value = byUser ? DBNull.Value : "worker";
                pAction.Value = actions[i % actions.Length];
                pRt.Value = actions[i % actions.Length].StartsWith("user") ? "user_settings" : "deployment";
                pRid.Value = "r" + (i % 5000);
                pRoles.Value = byUser ? "actor" : "";
                log.ExecuteNonQuery();
                if (byUser)
                {
                    qLog.Value = id;
                    qRef.Value = i % 200 == 0 ? "ref_123" : "ref_77";
                    qData.Value = "{\"actor_id\":\"" + (i % 200 == 0 ? "123" : "77") + "\",\"ip\":\"192.0.2.1\"}";
                    personal.ExecuteNonQuery();
                }
            }
            tx.Commit();
        }

        async Task<(long Ms, int Total, int Count)> Timed(Func<Task<(IEnumerable<AuditLogEntry> Logs, int Total, bool HasMore)>> q)
        {
            var sw = Stopwatch.StartNew();
            var r = await q();
            sw.Stop();
            return (sw.ElapsedMilliseconds, r.Total, r.Logs.Count());
        }

        await _repo.QueryLogsAsync(Admin, limit: 1); // warm-up (statement preparation)
        var page = await Timed(() => _repo.QueryLogsAsync(Admin, limit: 100));
        var filtered = await Timed(() => _repo.QueryLogsAsync(Admin, actorId: "123", action: "deployment_*", resourceType: "deployment", limit: 100));
        var window = await Timed(() => _repo.QueryLogsAsync(Admin, action: "user_*", dateFrom: start.AddDays(5), dateTo: start.AddDays(6), limit: 100));

        Assert.Equal((n, 100), (page.Total, page.Count));
        Assert.True(filtered.Total > 0 && filtered.Count > 0);
        Assert.True(window.Total > 0 && window.Count == 100);
        Assert.True(page.Ms < 100, $"unfiltered page took {page.Ms} ms");
        Assert.True(filtered.Ms < 100, $"filtered page took {filtered.Ms} ms");
        Assert.True(window.Ms < 100, $"time-window page took {window.Ms} ms");
    }
}

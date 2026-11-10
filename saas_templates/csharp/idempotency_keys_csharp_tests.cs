using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Linq;
using System.Threading;
using AOI.IdempotencyKeys;
using Microsoft.Data.Sqlite;

public static class IdempotencyKeysTests
{
    private static int _failures = 0;
    private static int _testsRun = 0;

    public static int Main()
    {
        TestFirstCallRunsOperationOnce();
        TestSecondIdenticalCallReturnsStoredResponse();
        TestSameKeyDifferentBodyReturns422();
        TestSameKeyWhileInProgressReturns409();
        TestRequiredOperationNoKeyReturns400();
        TestSameKeyDifferentScopesIndependent();
        TestExpiredKeyRunsOperationAgain();
        TestOperationExceptionFreesKey();
        TestErrorResponsesHaveProblemJsonContentType();
        foreach (var (name, factory) in Stores())
        {
            TestInProgressPastExpiryIsUncertain(name, factory);
            TestOtherErrorLeavesKeyUncertainUntilRelease(name, factory);
            TestResolveStoresResponseOnce(name, factory);
            TestConcurrentReleaseExactlyOneWins(name, factory);
            TestExpiredCompletedRunsAgainOnStore(name, factory);
        }

        Console.WriteLine($"\n=== Results: {_testsRun} tests run, {_failures} failures ===");
        return _failures > 0 ? 1 : 0;
    }

    private static void Assert(bool condition, string message)
    {
        _testsRun++;
        if (!condition)
        {
            _failures++;
            Console.WriteLine($"FAIL: {message}");
        }
        else
        {
            Console.WriteLine($"PASS: {message}");
        }
    }

    private static void AssertEqual<T>(T expected, T actual, string message)
    {
        _testsRun++;
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            _failures++;
            Console.WriteLine($"FAIL: {message} -- expected {expected}, got {actual}");
        }
        else
        {
            Console.WriteLine($"PASS: {message}");
        }
    }

    private static IIdempotencyStore NewStore() => new InMemoryStore();

    /// <summary>
    /// Both stores the template ships: in memory, and SQL over an open in-memory SQLite connection (it must stay open:
    /// an in-memory SQLite database lives only as long as its connection). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: process memory.
    /// </summary>
    private static IEnumerable<(string Name, Func<IIdempotencyStore> Factory)> Stores()
    {
        yield return ("memory", () => new InMemoryStore());
        yield return ("sqlite", () =>
        {
            var conn = new SqliteConnection("Data Source=:memory:");
            conn.Open();
            return new SqlStore(conn);
        });
    }

    /// <summary>A movable test clock (UTC). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private sealed class TestClock
    {
        public DateTime Now = new DateTime(2026, 11, 10, 12, 0, 0, DateTimeKind.Utc);
    }

    /// <summary>An operation that counts its calls and then times out (an unknown outcome). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static (int status, string body) TimeoutOp()
    {
        _opCount++;
        throw new TimeoutException("provider did not answer");
    }

    /// <summary>The type of a problem response's body. Pure.</summary>
    private static string ProblemTypeOf((int status, string contentType, string body) r)
    {
        using var doc = JsonDocument.Parse(r.body);
        return doc.RootElement.GetProperty("type").GetString();
    }

    private static IdempotencyKeys NewKeys(IIdempotencyStore store = null) => new IdempotencyKeys(store ?? NewStore());

    private static int _opCount;

    private static (int status, string body) CountingOp()
    {
        _opCount++;
        return (200, "{\"ok\":true}");
    }

    private static (int status, string body) FailingOp()
    {
        _opCount++;
        throw new InvalidOperationException("operation failed");
    }

    // IDEM-01
    private static void TestFirstCallRunsOperationOnce()
    {
        _opCount = 0;
        var keys = NewKeys();
        var result = keys.Handle("client1", "key-1", "POST", "/charge", "{\"amount\":100}", CountingOp);
        AssertEqual(200, result.status, "First call returns 200");
        AssertEqual("application/json", result.contentType, "First call content-type is application/json");
        AssertEqual("{\"ok\":true}", result.body, "First call returns operation body");
        AssertEqual(1, _opCount, "Operation called exactly once");
    }

    // IDEM-02
    private static void TestSecondIdenticalCallReturnsStoredResponse()
    {
        _opCount = 0;
        var keys = NewKeys();
        var result1 = keys.Handle("client1", "key-2", "POST", "/charge", "{\"amount\":100}", CountingOp);
        var result2 = keys.Handle("client1", "key-2", "POST", "/charge", "{\"amount\":100}", CountingOp);
        AssertEqual(200, result2.status, "Second call returns 200");
        AssertEqual("application/json", result2.contentType, "Second call content-type is application/json");
        AssertEqual(result1.body, result2.body, "Second call returns same body as first");
        AssertEqual(1, _opCount, "Operation called only once for two identical calls");
    }

    // IDEM-03
    private static void TestSameKeyDifferentBodyReturns422()
    {
        _opCount = 0;
        var keys = NewKeys();
        var result1 = keys.Handle("client1", "key-3", "POST", "/charge", "{\"amount\":100}", CountingOp);
        var result2 = keys.Handle("client1", "key-3", "POST", "/charge", "{\"amount\":200}", CountingOp);
        AssertEqual(422, result2.status, "Different body returns 422");
        AssertEqual("application/problem+json", result2.contentType, "422 response has problem+json content-type");
        AssertEqual(1, _opCount, "Operation not called for mismatched payload");
    }

    // IDEM-04
    private static void TestSameKeyWhileInProgressReturns409()
    {
        _opCount = 0;
        var store = NewStore();
        var keys = new IdempotencyKeys(store);
        var gate = new ManualResetEventSlim(false);
        var firstDone = new ManualResetEventSlim(false);
        Exception firstError = null;

        var thread = new Thread(() =>
        {
            try
            {
                keys.Handle("client1", "key-4", "POST", "/charge", "{\"amount\":100}", () =>
                {
                    gate.Set();
                    firstDone.Wait();
                    return (200, "{\"ok\":true}");
                });
            }
            catch (Exception ex)
            {
                firstError = ex;
            }
        });
        thread.Start();

        gate.Wait();
        var result2 = keys.Handle("client1", "key-4", "POST", "/charge", "{\"amount\":100}", CountingOp);
        firstDone.Set();
        thread.Join();

        AssertEqual(409, result2.status, "Concurrent call returns 409");
        AssertEqual("application/problem+json", result2.contentType, "409 response has problem+json content-type");
        AssertEqual(0, _opCount, "Second operation not started while first in progress");
        AssertNull(firstError, "First operation completed without error");
    }

    // IDEM-05
    private static void TestRequiredOperationNoKeyReturns400()
    {
        _opCount = 0;
        var keys = NewKeys();
        var result = keys.Handle("client1", null, "POST", "/charge", "{\"amount\":100}", CountingOp);
        AssertEqual(400, result.status, "Missing key on required operation returns 400");
        AssertEqual("application/problem+json", result.contentType, "400 response has problem+json content-type");
        AssertEqual(0, _opCount, "Operation not called when key missing");
    }

    // IDEM-06
    private static void TestSameKeyDifferentScopesIndependent()
    {
        _opCount = 0;
        var keys = NewKeys();
        var result1 = keys.Handle("clientA", "shared-key", "POST", "/charge", "{\"amount\":100}", CountingOp);
        var result2 = keys.Handle("clientB", "shared-key", "POST", "/charge", "{\"amount\":100}", CountingOp);
        AssertEqual(200, result1.status, "Client A gets 200");
        AssertEqual(200, result2.status, "Client B gets 200");
        AssertEqual(2, _opCount, "Operation called twice for different scopes");
    }

    /// <summary>
    /// IDEM-07, first half: a completed key past its expiry runs the operation again.
    /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the clock is moved instead of a 100 ms sleep (deterministic).
    /// </summary>
    // IDEM-07
    private static void TestExpiredKeyRunsOperationAgain()
    {
        _opCount = 0;
        var store = new InMemoryStore();
        var clock = new TestClock();
        var keys = new IdempotencyKeys(store, ttl: TimeSpan.FromMilliseconds(50), clock: () => clock.Now);
        var result1 = keys.Handle("client1", "key-expired", "POST", "/charge", "{\"amount\":100}", CountingOp);
        AssertEqual(1, _opCount, "First call runs operation");

        clock.Now = clock.Now.AddMilliseconds(49);
        keys.Handle("client1", "key-expired", "POST", "/charge", "{\"amount\":100}", CountingOp);
        AssertEqual(1, _opCount, "Before expiry the stored response is served");

        clock.Now = clock.Now.AddMilliseconds(1);
        var result2 = keys.Handle("client1", "key-expired", "POST", "/charge", "{\"amount\":100}", CountingOp);
        AssertEqual(2, _opCount, "Operation runs again after key expires");
        AssertEqual(200, result2.status, "Second call returns 200");
        AssertEqual("application/json", result2.contentType, "Second call content-type is application/json");
    }

    /// <summary>
    /// IDEM-08: an operation that raises OperationFailedException frees the key; a retry runs it.
    /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec amendment): it threw InvalidOperationException, which now
    /// means "outcome unknown" and leaves the key uncertain (IDEM-10); a definite failure is OperationFailedException.
    /// </summary>
    // IDEM-08
    private static void TestOperationExceptionFreesKey()
    {
        _opCount = 0;
        var keys = NewKeys();
        try
        {
            keys.Handle("client1", "key-fail", "POST", "/charge", "{\"amount\":100}", () =>
            {
                _opCount++;
                throw new OperationFailedException("card declined");
            });
            Assert(false, "Expected exception from failing operation");
        }
        catch (OperationFailedException)
        {
            Assert(true, "OperationFailedException is re-raised");
        }
        AssertEqual(1, _opCount, "Operation called once before failing");

        var result2 = keys.Handle("client1", "key-fail", "POST", "/charge", "{\"amount\":100}", CountingOp);
        AssertEqual(200, result2.status, "Retry after failure succeeds");
        AssertEqual(2, _opCount, "Operation called again on retry");
    }

    /// <summary>
    /// IDEM-07, second half: an in_progress key past expires_at (a killed process) gets 409 outcome_unknown and does not
    /// run, is listed for reconciliation, survives purge_expired, and is freed only by release(). Added 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
    /// </summary>
    // IDEM-07
    private static void TestInProgressPastExpiryIsUncertain(string name, Func<IIdempotencyStore> factory)
    {
        _opCount = 0;
        var store = factory();
        var clock = new TestClock();
        var t0 = clock.Now;
        var keys = new IdempotencyKeys(store, clock: () => clock.Now);
        const string body = "{\"amount\":100}";
        // a request claimed the key and its process was killed: the record stays in_progress
        AssertEqual(true, store.TryClaim("client-a", "key-1", IdempotencyKeys.Fingerprint("POST", "/charges", body), t0, t0.AddHours(24)),
            $"[{name}] a claim that never finishes");

        clock.Now = t0.AddHours(23);
        var during = keys.Handle("client-a", "key-1", "POST", "/charges", body, CountingOp);
        AssertEqual(409, during.status, $"[{name}] before expires_at it is plain in progress");
        AssertEqual(IdempotencyKeys.ProblemType, ProblemTypeOf(during), $"[{name}] in-progress problem type");
        AssertEqual(422, keys.Handle("client-a", "key-1", "POST", "/charges", "{\"amount\":5}", CountingOp).status,
            $"[{name}] a different payload is 422 even while in progress");

        clock.Now = t0.AddHours(24);
        var after = keys.Handle("client-a", "key-1", "POST", "/charges", body, CountingOp);
        AssertEqual(409, after.status, $"[{name}] in_progress past expires_at -> 409");
        AssertEqual(IdempotencyKeys.OutcomeUnknownType, ProblemTypeOf(after), $"[{name}] ... outcome_unknown");
        AssertEqual(0, _opCount, $"[{name}] the operation did not run");
        AssertEqual(0, keys.PurgeExpired(), $"[{name}] purge keeps it");
        var listed = keys.ListUncertain();
        AssertEqual(1, listed.Count, $"[{name}] listed for reconciliation");
        AssertEqual(("client-a", "key-1", t0), (listed[0].Scope, listed[0].IdemKey, listed[0].CreatedAt), $"[{name}] ... with scope, key, created_at");
        AssertEqual(true, keys.Release("client-a", "key-1"), $"[{name}] release frees it");
        var retry = keys.Handle("client-a", "key-1", "POST", "/charges", body, CountingOp);
        AssertEqual(200, retry.status, $"[{name}] after release the retry runs");
        AssertEqual(1, _opCount, $"[{name}] ... exactly once");
    }

    /// <summary>
    /// IDEM-10: any other error leaves the key 'uncertain': the error is re-raised, a retry gets 409 outcome_unknown and
    /// the count stays 1, purge keeps it; after release() a retry runs. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    // IDEM-10
    private static void TestOtherErrorLeavesKeyUncertainUntilRelease(string name, Func<IIdempotencyStore> factory)
    {
        _opCount = 0;
        var clock = new TestClock();
        var keys = new IdempotencyKeys(factory(), clock: () => clock.Now);
        var raised = false;
        try { keys.Handle("client-a", "key-u", "POST", "/charges", "{\"amount\":100}", TimeoutOp); }
        catch (TimeoutException) { raised = true; }
        Assert(raised, $"[{name}] the timeout is re-raised");

        var retry = keys.Handle("client-a", "key-u", "POST", "/charges", "{\"amount\":100}", CountingOp);
        AssertEqual(409, retry.status, $"[{name}] retry of an uncertain key -> 409");
        AssertEqual("application/problem+json", retry.contentType, $"[{name}] problem+json");
        AssertEqual(IdempotencyKeys.OutcomeUnknownType, ProblemTypeOf(retry), $"[{name}] outcome_unknown");
        AssertEqual(1, _opCount, $"[{name}] the operation count stays at 1");

        clock.Now = clock.Now.AddDays(30);
        AssertEqual(0, keys.PurgeExpired(), $"[{name}] an uncertain key never expires");
        AssertEqual(409, keys.Handle("client-a", "key-u", "POST", "/charges", "{\"amount\":100}", CountingOp).status, $"[{name}] still 409 a month later");
        AssertEqual(false, keys.Release("client-a", "no-such-key"), $"[{name}] release of an unknown key is false");
        AssertEqual(true, keys.Release("client-a", "key-u"), $"[{name}] release frees the key");
        var after = keys.Handle("client-a", "key-u", "POST", "/charges", "{\"amount\":100}", CountingOp);
        AssertEqual(200, after.status, $"[{name}] after release the retry runs");
        AssertEqual(2, _opCount, $"[{name}] ... once more");
        AssertEqual(false, keys.Release("client-a", "key-u"), $"[{name}] release of a completed key is false");
    }

    /// <summary>
    /// IDEM-11: resolve() on an uncertain key stores the response (expires 24 h later); a retry returns it without
    /// running; a second resolve() or release() returns false and changes nothing. Added 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    // IDEM-11
    private static void TestResolveStoresResponseOnce(string name, Func<IIdempotencyStore> factory)
    {
        _opCount = 0;
        var clock = new TestClock();
        var store = factory();
        var keys = new IdempotencyKeys(store, clock: () => clock.Now);
        try { keys.Handle("client-a", "key-r", "POST", "/charges", "{\"amount\":100}", TimeoutOp); }
        catch (TimeoutException) { Assert(true, $"[{name}] timeout re-raised"); }

        AssertEqual(true, keys.Resolve("client-a", "key-r", 201, "{\"id\":\"ch_found\"}"), $"[{name}] resolve stores the found outcome");
        AssertEqual(clock.Now.AddHours(24), store.Get("client-a", "key-r").ExpiresAt, $"[{name}] expires_at = now + 24h");
        var retry = keys.Handle("client-a", "key-r", "POST", "/charges", "{\"amount\":100}", CountingOp);
        AssertEqual(201, retry.status, $"[{name}] the retry gets the resolved status");
        AssertEqual("{\"id\":\"ch_found\"}", retry.body, $"[{name}] ... and body");
        AssertEqual(1, _opCount, $"[{name}] the operation did not run again");
        AssertEqual(false, keys.Resolve("client-a", "key-r", 500, "{}"), $"[{name}] a second resolve is false");
        AssertEqual(false, keys.Release("client-a", "key-r"), $"[{name}] release after resolve is false");
        AssertEqual("{\"id\":\"ch_found\"}", keys.Handle("client-a", "key-r", "POST", "/charges", "{\"amount\":100}", CountingOp).body, $"[{name}] unchanged");
        AssertEqual(0, keys.ListUncertain().Count, $"[{name}] nothing left to reconcile");
    }

    /// <summary>
    /// release() is one conditional write: of two concurrent calls exactly one returns true (repeated 50 times).
    /// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, two threads.
    /// </summary>
    private static void TestConcurrentReleaseExactlyOneWins(string name, Func<IIdempotencyStore> factory)
    {
        var store = factory();
        var clock = new TestClock();
        var keys = new IdempotencyKeys(store, clock: () => clock.Now);
        var allExactlyOne = true;
        for (var i = 0; i < 50; i++)
        {
            var key = "race-" + i;
            try { keys.Handle("client-a", key, "POST", "/charges", "{}", TimeoutOp); }
            catch (TimeoutException) { }
            var wins = 0;
            using var start = new ManualResetEventSlim(false);
            var threads = Enumerable.Range(0, 2).Select(_ => new Thread(() =>
            {
                start.Wait();
                if (i % 2 == 0 ? keys.Release("client-a", key) : keys.Resolve("client-a", key, 200, "{}"))
                    Interlocked.Increment(ref wins);
            })).ToList();
            threads.ForEach(t => t.Start());
            start.Set();
            threads.ForEach(t => t.Join());
            if (wins != 1) allExactlyOne = false;
        }
        Assert(allExactlyOne, $"[{name}] of two concurrent release/resolve calls exactly one returns true");
    }

    /// <summary>IDEM-07 on both stores: a completed key past expires_at is replaced by the claim and runs again. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static void TestExpiredCompletedRunsAgainOnStore(string name, Func<IIdempotencyStore> factory)
    {
        _opCount = 0;
        var clock = new TestClock();
        var keys = new IdempotencyKeys(factory(), clock: () => clock.Now);
        keys.Handle("client-a", "key-e", "POST", "/charges", "{}", CountingOp);
        keys.Handle("client-a", "key-e", "POST", "/charges", "{}", CountingOp);
        AssertEqual(1, _opCount, $"[{name}] served from the store within 24 h");
        clock.Now = clock.Now.AddHours(24);
        AssertEqual(200, keys.Handle("client-a", "key-e", "POST", "/charges", "{}", CountingOp).status, $"[{name}] after 24 h");
        AssertEqual(2, _opCount, $"[{name}] the operation ran again");
        AssertEqual(0, keys.PurgeExpired(), $"[{name}] the fresh record is not purged");
    }

    // IDEM-09
    private static void TestErrorResponsesHaveProblemJsonContentType()
    {
        var keys = NewKeys();

        var r400 = keys.Handle("client1", null, "POST", "/charge", "{}", CountingOp);
        AssertEqual("application/problem+json", r400.contentType, "400 has problem+json content-type");
        AssertProblemBody(r400.body, "400 body has type, title, detail");

        var r422 = keys.Handle("client1", "key-err", "POST", "/charge", "{\"a\":1}", CountingOp);
        r422 = keys.Handle("client1", "key-err", "POST", "/charge", "{\"a\":2}", CountingOp);
        AssertEqual("application/problem+json", r422.contentType, "422 has problem+json content-type");
        AssertProblemBody(r422.body, "422 body has type, title, detail");

        var store = NewStore();
        var keys2 = new IdempotencyKeys(store);
        var gate = new ManualResetEventSlim(false);
        var firstDone = new ManualResetEventSlim(false);
        var thread = new Thread(() =>
        {
            keys2.Handle("client1", "key-409", "POST", "/charge", "{}", () =>
            {
                gate.Set();
                firstDone.Wait();
                return (200, "{}");
            });
        });
        thread.Start();
        gate.Wait();
        var r409 = keys2.Handle("client1", "key-409", "POST", "/charge", "{}", CountingOp);
        firstDone.Set();
        thread.Join();
        AssertEqual("application/problem+json", r409.contentType, "409 has problem+json content-type");
        AssertProblemBody(r409.body, "409 body has type, title, detail");
    }

    private static void AssertProblemBody(string json, string message)
    {
        _testsRun++;
        try
        {
            using (var doc = JsonDocument.Parse(json))
            {
                var root = doc.RootElement;
                var hasType = root.TryGetProperty("type", out var type) && type.GetString() == "https://developer.example.com/idempotency";
                var hasTitle = root.TryGetProperty("title", out var title) && !string.IsNullOrEmpty(title.GetString());
                var hasDetail = root.TryGetProperty("detail", out var detail) && !string.IsNullOrEmpty(detail.GetString());
                var hasStatus = root.TryGetProperty("status", out var status) && status.ValueKind == JsonValueKind.Number;
                if (!(hasType && hasTitle && hasDetail && hasStatus))
                {
                    _failures++;
                    Console.WriteLine($"FAIL: {message} -- missing required fields in {json}");
                }
                else
                {
                    Console.WriteLine($"PASS: {message}");
                }
            }
        }
        catch (Exception ex)
        {
            _failures++;
            Console.WriteLine($"FAIL: {message} -- invalid JSON: {ex.Message}");
        }
    }

    private static void AssertNull(object obj, string message)
    {
        _testsRun++;
        if (obj != null)
        {
            _failures++;
            Console.WriteLine($"FAIL: {message} -- expected null, got {obj}");
        }
        else
        {
            Console.WriteLine($"PASS: {message}");
        }
    }
}
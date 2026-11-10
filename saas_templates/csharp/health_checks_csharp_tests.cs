using System;
using System.Threading;
using HealthChecks;

public static class HealthChecksTests
{
    private static int _failed = 0;

    public static int Main()
    {
        try
        {
            TestAllChecksPass();
            TestCriticalCheckFails();
            TestOnlyNonCriticalCheckFails();
            TestSlowCheckTimesOut();
            TestLivenessUnaffectedByDependencyFailure();
            TestOutputContainsNoConnectionString();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Unhandled exception: " + ex);
            _failed++;
        }

        return _failed > 0 ? 1 : 0;
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            Console.Error.WriteLine("FAIL: " + message);
            _failed++;
        }
    }

    // HEALTH-01
    public static void TestAllChecksPass()
    {
        HealthCheckService.Reset();
        HealthCheckService.RegisterCheck("comp1", "type1", () => new HealthCheckResult
        {
            ComponentId = "comp1",
            ComponentType = "type1",
            ObservedValue = "ok",
            ObservedUnit = "",
            Status = "pass",
            Time = DateTime.UtcNow
        }, false, 1000);
        HealthCheckService.RegisterCheck("comp2", "type2", () => new HealthCheckResult
        {
            ComponentId = "comp2",
            ComponentType = "type2",
            ObservedValue = 42,
            ObservedUnit = "count",
            Status = "pass",
            Time = DateTime.UtcNow
        }, true, 1000);

        var response = HealthCheckService.Readiness();
        Assert(response.HttpStatus == 200, "Expected HTTP 200 for all checks pass");
        Assert(response.ContentType == "application/health+json", "Expected content type application/health+json");
        Assert(response.Body.Contains("\"status\":\"pass\""), "Expected status pass in body");
    }

    // HEALTH-02
    public static void TestCriticalCheckFails()
    {
        HealthCheckService.Reset();
        HealthCheckService.RegisterCheck("comp1", "type1", () => new HealthCheckResult
        {
            ComponentId = "comp1",
            ComponentType = "type1",
            ObservedValue = null,
            ObservedUnit = "",
            Status = "fail",
            Time = DateTime.UtcNow
        }, true, 1000);

        var response = HealthCheckService.Readiness();
        Assert(response.HttpStatus == 503, "Expected HTTP 503 for critical check fail");
        Assert(response.ContentType == "application/health+json", "Expected content type application/health+json");
        Assert(response.Body.Contains("\"status\":\"fail\""), "Expected status fail in body");
    }

    // HEALTH-03
    public static void TestOnlyNonCriticalCheckFails()
    {
        HealthCheckService.Reset();
        HealthCheckService.RegisterCheck("comp1", "type1", () => new HealthCheckResult
        {
            ComponentId = "comp1",
            ComponentType = "type1",
            ObservedValue = null,
            ObservedUnit = "",
            Status = "fail",
            Time = DateTime.UtcNow
        }, false, 1000);
        HealthCheckService.RegisterCheck("comp2", "type2", () => new HealthCheckResult
        {
            ComponentId = "comp2",
            ComponentType = "type2",
            ObservedValue = "ok",
            ObservedUnit = "",
            Status = "pass",
            Time = DateTime.UtcNow
        }, true, 1000);

        var response = HealthCheckService.Readiness();
        Assert(response.HttpStatus == 200, "Expected HTTP 200 for only non-critical check fail");
        Assert(response.ContentType == "application/health+json", "Expected content type application/health+json");
        Assert(response.Body.Contains("\"status\":\"warn\""), "Expected status warn in body");
    }

    // HEALTH-04
    public static void TestSlowCheckTimesOut()
    {
        HealthCheckService.Reset();
        var resetEvent = new ManualResetEventSlim(false);
        HealthCheckService.RegisterCheck("slow", "type", () =>
        {
            resetEvent.Wait();
            return new HealthCheckResult
            {
                ComponentId = "slow",
                ComponentType = "type",
                ObservedValue = null,
                ObservedUnit = "",
                Status = "pass",
                Time = DateTime.UtcNow
            };
        }, false, 100);

        var response = HealthCheckService.Readiness();
        Assert(response.HttpStatus == 200, "Expected HTTP 200 (since non-critical check fails -> warn)");
        Assert(response.ContentType == "application/health+json", "Expected content type application/health+json");
        Assert(response.Body.Contains("\"status\":\"warn\""), "Expected status warn in body");
        Assert(response.Body.Contains("\"status\":\"fail\""), "Expected the slow check to be marked as fail in the checks section");

        resetEvent.Set();
    }

    // HEALTH-05
    public static void TestLivenessUnaffectedByDependencyFailure()
    {
        HealthCheckService.Reset();
        HealthCheckService.RegisterCheck("comp1", "type1", () => new HealthCheckResult
        {
            ComponentId = "comp1",
            ComponentType = "type1",
            ObservedValue = null,
            ObservedUnit = "",
            Status = "fail",
            Time = DateTime.UtcNow
        }, true, 1000);

        var livenessResponse = HealthCheckService.Liveness();
        Assert(livenessResponse.HttpStatus == 200, "Liveness should return HTTP 200");
        Assert(livenessResponse.ContentType == "application/health+json", "Liveness content type should be application/health+json");
        Assert(livenessResponse.Body.Contains("\"status\":\"pass\""), "Liveness status should be pass");

        var readinessResponse = HealthCheckService.Readiness();
        Assert(readinessResponse.HttpStatus == 503, "Readiness should return HTTP 503 due to critical check failure");
    }

    // HEALTH-06
    public static void TestOutputContainsNoConnectionString()
    {
        HealthCheckService.Reset();
        HealthCheckService.RegisterCheck("comp1", "type1", () => new HealthCheckResult
        {
            ComponentId = "comp1",
            ComponentType = "type1",
            ObservedValue = "safe",
            ObservedUnit = "",
            Status = "pass",
            Time = DateTime.UtcNow
        }, false, 1000);

        // Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: a failing check whose exception carries a connection
        // string, so the test proves the string is kept out of the output (before, nothing could have leaked it).
        HealthCheckService.RegisterCheck("db", "datastore", () =>
            throw new InvalidOperationException("cannot open Server=db.internal;User Id=app;Password=hunter2;Database=prod"),
            false, 1000);

        var response = HealthCheckService.Readiness();
        Assert(response.Body.Contains("\"status\":\"fail\""), "The throwing check should be reported as fail");
        Assert(!response.Body.Contains("hunter2") && !response.Body.Contains("db.internal"), "Output should not contain the exception's connection string");
        Assert(!response.Body.Contains("Server="), "Output should not contain a connection string (Server=)");
        Assert(!response.Body.Contains("Password="), "Output should not contain a connection string (Password=)");
        Assert(!response.Body.Contains("User Id="), "Output should not contain a connection string (User Id=)");
        Assert(!response.Body.Contains("Database="), "Output should not contain a connection string (Database=)");
    }
}
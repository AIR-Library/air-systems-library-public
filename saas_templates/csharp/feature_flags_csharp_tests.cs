using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Linq;
using System.Text.Json;
using AOI.FeatureFlags;

namespace AOI.FeatureFlags.Tests
{
    public static class FeatureFlagTests
    {
        private static int _passed = 0;
        private static int _failed = 0;

        public static int Main()
        {
            TestUnknownFlagReturnsDefault();
            TestTypeMismatchReturnsDefault();
            TestDisabledFlagReturnsDefault();
            TestMatchingRuleReturnsValue();
            TestRolloutDeterministicAndDistribution();
            TestUserOutsideRolloutFallsThrough();
            TestCorruptRulesReturnsParseError();
            TestSetFlagWritesAuditRow();

            Console.WriteLine($"\n=== Results: {_passed} passed, {_failed} failed ===");
            return _failed > 0 ? 1 : 0;
        }

        private static void Assert(bool condition, string message)
        {
            if (condition)
            {
                _passed++;
                Console.WriteLine($"  PASS: {message}");
            }
            else
            {
                _failed++;
                Console.WriteLine($"  FAIL: {message}");
            }
        }

        private static void AssertEqual<T>(T expected, T actual, string message)
        {
            if (EqualityComparer<T>.Default.Equals(expected, actual))
            {
                _passed++;
                Console.WriteLine($"  PASS: {message}");
            }
            else
            {
                _failed++;
                Console.WriteLine($"  FAIL: {message} (expected: {expected}, actual: {actual})");
            }
        }

        private static IFeatureFlagStore CreateStore()
        {
            return new InMemoryFeatureFlagStore();
        }

        private static FeatureFlagClient CreateClient(IFeatureFlagStore store = null)
        {
            return new FeatureFlagClient(store ?? CreateStore());
        }

        private static EvaluationContext CreateContext(string targetingKey = "user1", string email = null, string orgId = null, string tier = null, Dictionary<string, JsonElement> attrs = null)
        {
            var attributes = new Dictionary<string, JsonElement>();
            if (targetingKey != null)
                attributes["targeting_key"] = JsonSerializer.SerializeToElement(targetingKey);
            if (email != null)
                attributes["email"] = JsonSerializer.SerializeToElement(email);
            if (orgId != null)
                attributes["org_id"] = JsonSerializer.SerializeToElement(orgId);
            if (tier != null)
                attributes["tier"] = JsonSerializer.SerializeToElement(tier);
            if (attrs != null)
            {
                foreach (var kv in attrs)
                    attributes[kv.Key] = kv.Value;
            }
            return new EvaluationContext { Attributes = attributes };
        }

        private static JsonElement ToJsonElement(object value)
        {
            return JsonDocument.Parse(JsonSerializer.Serialize(value)).RootElement;
        }

        // FLAG-01
        static void TestUnknownFlagReturnsDefault()
        {
            Console.WriteLine("TestUnknownFlagReturnsDefault");
            var client = CreateClient();
            var ctx = CreateContext("user1");

            var result = client.GetBooleanDetails("unknown_flag", false, ctx);

            AssertEqual(false, result.Value, "Returns default value");
            AssertEqual("ERROR", result.Reason, "Reason is ERROR");
            AssertEqual("FLAG_NOT_FOUND", result.ErrorCode, "Error code is FLAG_NOT_FOUND");
            Assert(result.ErrorMessage.Contains("not found"), "Error message mentions not found");
        }

        // FLAG-02
        static void TestTypeMismatchReturnsDefault()
        {
            Console.WriteLine("TestTypeMismatchReturnsDefault");
            var store = CreateStore();
            var client = CreateClient(store);

            store.SetFlag(new FeatureFlag
            {
                Key = "bool_flag",
                Type = "boolean",
                DefaultValue = ToJsonElement(false),
                Enabled = true,
                RulesJson = "[]",
                UpdatedAt = DateTime.UtcNow,
                UpdatedBy = "test"
            });

            var ctx = CreateContext("user1");
            var result = client.GetStringDetails("bool_flag", "default", ctx);

            AssertEqual("default", result.Value, "Returns default value");
            AssertEqual("ERROR", result.Reason, "Reason is ERROR");
            AssertEqual("TYPE_MISMATCH", result.ErrorCode, "Error code is TYPE_MISMATCH");
        }

        // FLAG-03
        static void TestDisabledFlagReturnsDefault()
        {
            Console.WriteLine("TestDisabledFlagReturnsDefault");
            var store = CreateStore();
            var client = CreateClient(store);

            store.SetFlag(new FeatureFlag
            {
                Key = "disabled_flag",
                Type = "boolean",
                DefaultValue = ToJsonElement(true),
                Enabled = false,
                RulesJson = "[]",
                UpdatedAt = DateTime.UtcNow,
                UpdatedBy = "test"
            });

            var ctx = CreateContext("user1");
            var result = client.GetBooleanDetails("disabled_flag", false, ctx);

            AssertEqual(false, result.Value, "Returns caller default (not flag default)");
            AssertEqual("DISABLED", result.Reason, "Reason is DISABLED");
            AssertEqual(null, result.ErrorCode, "No error code");
        }

        // FLAG-04
        static void TestMatchingRuleReturnsValue()
        {
            Console.WriteLine("TestMatchingRuleReturnsValue");
            var store = CreateStore();
            var client = CreateClient(store);

            var rulesJson = @"[
                { ""conditions"": [{ ""attribute"": ""email"", ""operator"": ""ends_with"", ""value"": ""@acme.com"" }], ""variant"": ""on"", ""value"": true, ""rollout"": null },
                { ""conditions"": [], ""variant"": ""beta"", ""value"": true, ""rollout"": { ""percentage"": 30 } }
            ]";

            store.SetFlag(new FeatureFlag
            {
                Key = "match_flag",
                Type = "boolean",
                DefaultValue = ToJsonElement(false),
                Enabled = true,
                RulesJson = rulesJson,
                UpdatedAt = DateTime.UtcNow,
                UpdatedBy = "test"
            });

            var ctxMatch = CreateContext("user1", "alice@acme.com");
            var resultMatch = client.GetBooleanDetails("match_flag", false, ctxMatch);
            AssertEqual(true, resultMatch.Value, "Matching rule returns rule value");
            AssertEqual("on", resultMatch.Variant, "Variant is 'on'");
            AssertEqual("TARGETING_MATCH", resultMatch.Reason, "Reason is TARGETING_MATCH");

            var ctxNoMatch = CreateContext("user2", "bob@other.com");
            var resultNoMatch = client.GetBooleanDetails("match_flag", false, ctxNoMatch);
            AssertEqual(false, resultNoMatch.Value, "Non-matching falls to next rule (rollout)");
            Assert(resultNoMatch.Variant != "on", "Non-matching rule's variant is not returned");
        }

        // FLAG-05
        static void TestRolloutDeterministicAndDistribution()
        {
            Console.WriteLine("TestRolloutDeterministicAndDistribution");
            var store = CreateStore();
            var client = CreateClient(store);

            var rulesJson = @"[
                { ""conditions"": [], ""variant"": ""rollout_on"", ""value"": true, ""rollout"": { ""percentage"": 30 } }
            ]";

            store.SetFlag(new FeatureFlag
            {
                Key = "rollout_flag",
                Type = "boolean",
                DefaultValue = ToJsonElement(false),
                Enabled = true,
                RulesJson = rulesJson,
                UpdatedAt = DateTime.UtcNow,
                UpdatedBy = "test"
            });

            var ctx = CreateContext("consistent_user");
            var first = client.GetBooleanDetails("rollout_flag", false, ctx);
            var second = client.GetBooleanDetails("rollout_flag", false, ctx);
            AssertEqual(first.Value, second.Value, "Same targeting_key gives same answer every call");

            int trueCount = 0;
            const int sampleSize = 10000;
            for (int i = 0; i < sampleSize; i++)
            {
                var c = CreateContext($"user_{i}");
                var r = client.GetBooleanDetails("rollout_flag", false, c);
                if (r.Value) trueCount++;
            }
            double pct = (double)trueCount / sampleSize * 100;
            Assert(pct >= 25 && pct <= 35, $"30% rollout yields {pct:F1}% true (expected 25-35%)");
        }

        // FLAG-06
        static void TestUserOutsideRolloutFallsThrough()
        {
            Console.WriteLine("TestUserOutsideRolloutFallsThrough");
            var store = CreateStore();
            var client = CreateClient(store);

            var rulesJson = @"[
                { ""conditions"": [], ""variant"": ""rollout_30"", ""value"": true, ""rollout"": { ""percentage"": 30 } },
                { ""conditions"": [], ""variant"": ""fallback_on"", ""value"": true, ""rollout"": null }
            ]";

            store.SetFlag(new FeatureFlag
            {
                Key = "fallback_flag",
                Type = "boolean",
                DefaultValue = ToJsonElement(false),
                Enabled = true,
                RulesJson = rulesJson,
                UpdatedAt = DateTime.UtcNow,
                UpdatedBy = "test"
            });

            int fallbackCount = 0, strayCount = 0;
            const int sampleSize = 10000;
            for (int i = 0; i < sampleSize; i++)
            {
                var c = CreateContext($"user_{i}");
                var r = client.GetBooleanDetails("fallback_flag", false, c);
                if (r.Reason == "TARGETING_MATCH" && r.Variant == "fallback_on")
                    fallbackCount++;
                else if (r.Variant != "rollout_30")
                    strayCount++;
            }
            // every user is either in the rollout or reaches the next rule (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
            AssertEqual(0, strayCount, "No user gets anything but the rollout variant or the next rule");
            double pct = (double)fallbackCount / sampleSize * 100;
            Assert(pct >= 65 && pct <= 75, $"~70% fall through to next rule, got {pct:F1}%");
        }

        // FLAG-07
        static void TestCorruptRulesReturnsParseError()
        {
            Console.WriteLine("TestCorruptRulesReturnsParseError");
            var store = CreateStore();
            var client = CreateClient(store);

            client.SetFlag("actor1", "corrupt_flag", "boolean", ToJsonElement(false), true, "{ invalid json }");

            var ctx = CreateContext("user1");
            var result = client.GetBooleanDetails("corrupt_flag", false, ctx);
            AssertEqual(false, result.Value, "Returns default");
            AssertEqual("ERROR", result.Reason, "Reason is ERROR");
            AssertEqual("PARSE_ERROR", result.ErrorCode, "Error code is PARSE_ERROR");
        }

        // FLAG-08
        static void TestSetFlagWritesAuditRow()
        {
            Console.WriteLine("TestSetFlagWritesAuditRow");
            var store = CreateStore();
            var client = CreateClient(store);

            client.SetFlag("actor1", "audit_flag", "boolean", ToJsonElement(false), true, "[]");
            var audit = store.GetAudit("audit_flag");
            AssertEqual(1, audit.Count, "Audit row count is 1");
            AssertEqual("CREATE", audit[0].Action, "Action is CREATE");
            AssertEqual("actor1", audit[0].ActorId, "ActorId is actor1");

            // Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: FLAG-08 names old AND new values, so change the
            // flag and check the second audit row carries both.
            client.SetFlag("actor2", "audit_flag", "boolean", ToJsonElement(true), false, "[]");
            audit = store.GetAudit("audit_flag");
            AssertEqual(2, audit.Count, "Audit row count is 2 after an update");
            AssertEqual("actor2", audit[1].ActorId, "ActorId is actor2");
            AssertEqual(true, audit[1].OldValue.GetProperty("Enabled").GetBoolean(), "Old value holds the old enabled state");
            AssertEqual(false, audit[1].OldValue.GetProperty("DefaultValue").GetBoolean(), "Old value holds the old default");
            AssertEqual(false, audit[1].NewValue.GetProperty("Enabled").GetBoolean(), "New value holds the new enabled state");
            AssertEqual(true, audit[1].NewValue.GetProperty("DefaultValue").GetBoolean(), "New value holds the new default");
        }
    }
}
# Tests updated with the fix 2026-11-03: an in-memory logger keeps one connection, so every call sees the same database (each call
#   used to open a new, empty one).
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: SQLite only.
import unittest
import sqlite3
import time
from audit_logging_python import AuditLogger

class TestAuditLogger(unittest.TestCase):
    def setUp(self):
        # Use an in-memory database for clean, isolated tests
        self.logger = AuditLogger(":memory:")

    def test_happy_path_log_and_query(self):
        # 1. Log mutation
        log_res = self.logger.log_mutation(
            actor_id=123,
            actor_type="user",
            action="subscription_changed",
            resource_type="subscription",
            resource_id=456,
            old_value={"tier": "team", "billing_date": "2026-10-15"},
            new_value={"tier": "enterprise", "billing_date": "2026-10-15"},
            why_chain_id="wc_789",
            metadata={"ip": "192.168.1.1", "user_agent": "Mozilla"}
        )
        self.assertTrue(log_res["success"])
        self.assertIsNotNone(log_res["log_id"])

        # 2. Query it back
        query_res = self.logger.query_logs(actor_id=123, resource_type="subscription")
        self.assertEqual(query_res["total"], 1)
        self.assertFalse(query_res["has_more"])
        
        log_entry = query_res["logs"][0]
        self.assertEqual(log_entry["id"], log_res["log_id"])
        self.assertEqual(log_entry["actor_id"], "123")
        self.assertEqual(log_entry["action"], "subscription_changed")
        self.assertEqual(log_entry["old_value"]["tier"], "team")
        self.assertEqual(log_entry["new_value"]["tier"], "enterprise")
        self.assertEqual(log_entry["why_chain_id"], "wc_789")
        self.assertEqual(log_entry["metadata"]["ip"], "192.168.1.1")

    def test_replay_and_divergence(self):
        # Log initial mutation
        res1 = self.logger.log_mutation(
            actor_id=123,
            actor_type="user",
            action="user_created",
            resource_type="user",
            resource_id=999,
            old_value={},
            new_value={"status": "active", "role": "member"}
        )
        log_id_1 = res1["log_id"]

        # Replay immediately (no divergence)
        replay_1 = self.logger.replay(log_id_1)
        self.assertEqual(replay_1["log_id"], log_id_1)
        self.assertEqual(replay_1["resource_state_at_time"], {})
        self.assertFalse(replay_1["has_diverged"])

        # Log subsequent mutation (state changes)
        res2 = self.logger.log_mutation(
            actor_id=123,
            actor_type="user",
            action="user_suspended",
            resource_type="user",
            resource_id=999,
            old_value={"status": "active", "role": "member"},
            new_value={"status": "suspended", "role": "member"}
        )
        log_id_2 = res2["log_id"]

        # Replay first log again (should now detect divergence because current state is suspended)
        replay_1_after = self.logger.replay(log_id_1)
        self.assertTrue(replay_1_after["has_diverged"])

        # Replay second log (should not be diverged as it represents the latest state)
        replay_2 = self.logger.replay(log_id_2)
        self.assertFalse(replay_2["has_diverged"])

    def test_filtering_combinations(self):
        # Insert multiple logs
        self.logger.log_mutation(1, "user", "user_created", "user", 101, {}, {"name": "Alice"})
        self.logger.log_mutation(1, "user", "user_suspended", "user", 101, {"name": "Alice"}, {"name": "Alice", "suspended": True})
        self.logger.log_mutation(2, "user", "user_created", "user", 102, {}, {"name": "Bob"})
        self.logger.log_mutation(3, "service", "billing_changed", "billing", 501, {}, {"amount": 100})

        # Filter by actor_id + action + resource_type
        res = self.logger.query_logs(actor_id=1, action="user_suspended", resource_type="user")
        self.assertEqual(res["total"], 1)
        self.assertEqual(res["logs"][0]["resource_id"], "101")

        # Filter by date range
        res_date = self.logger.query_logs(date_from="2020-01-01T00:00:00Z", date_to="2030-12-31T23:59:59Z")
        self.assertEqual(res_date["total"], 4)

    def test_pagination(self):
        # Insert 5 logs
        for i in range(5):
            self.logger.log_mutation(1, "user", "item_added", "cart", 200, {}, {"item": i})

        # Page 1 (limit 2, offset 0)
        page1 = self.logger.query_logs(limit=2, offset=0)
        self.assertEqual(len(page1["logs"]), 2)
        self.assertEqual(page1["total"], 5)
        self.assertTrue(page1["has_more"])

        # Page 2 (limit 2, offset 2)
        page2 = self.logger.query_logs(limit=2, offset=2)
        self.assertEqual(len(page2["logs"]), 2)
        self.assertTrue(page2["has_more"])

        # Page 3 (limit 2, offset 4)
        page3 = self.logger.query_logs(limit=2, offset=4)
        self.assertEqual(len(page3["logs"]), 1)
        self.assertFalse(page3["has_more"])

    def test_immutability(self):
        res = self.logger.log_mutation(1, "user", "test_action", "test_resource", 99, {}, {"val": 1})
        log_id = res["log_id"]

        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            with self.logger._get_connection() as conn:
                conn.execute("UPDATE audit_log SET action = 'hacked' WHERE id = ?", (log_id,))
                conn.commit()
        self.assertIn("immutable", str(ctx.exception))

        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            with self.logger._get_connection() as conn:
                conn.execute("DELETE FROM audit_log WHERE id = ?", (log_id,))
                conn.commit()
        self.assertIn("immutable", str(ctx.exception))

    def test_wildcard_matching(self):
        self.logger.log_mutation(1, "user", "user_created", "user", 101, {}, {})
        self.logger.log_mutation(1, "user", "user_suspended", "user", 101, {}, {})
        self.logger.log_mutation(1, "user", "billing_changed", "billing", 101, {}, {})

        # Wildcard search for user_*
        res = self.logger.query_logs(action="user_*")
        self.assertEqual(res["total"], 2)
        actions = {log["action"] for log in res["logs"]}
        self.assertEqual(actions, {"user_created", "user_suspended"})

    def test_search(self):
        self.logger.log_mutation(
            actor_id=1,
            actor_type="user",
            action="profile_updated",
            resource_type="user",
            resource_id=101,
            old_value={"email": "old@example.com"},
            new_value={"email": "new@example.com"},
            metadata={"reason": "user requested change"}
        )

        # Search by email in old/new values
        res = self.logger.search("example.com")
        self.assertEqual(len(res["results"]), 1)

        # Search by metadata content
        res_meta = self.logger.search("requested change")
        self.assertEqual(len(res_meta["results"]), 1)

        # Search with resource_type filter
        res_filtered = self.logger.search("example.com", resource_type="user")
        self.assertEqual(len(res_filtered["results"]), 1)

        res_none = self.logger.search("example.com", resource_type="billing")
        self.assertEqual(len(res_none["results"]), 0)

    def test_performance_large_dataset(self):
        # Bulk insert 10,000 logs to simulate a large dataset and verify fast query performance (<100ms)
        # Using a transaction and optimized SQLite settings for fast setup
        with self.logger._get_connection() as conn:
            conn.execute("PRAGMA synchronous = OFF;")
            conn.execute("PRAGMA journal_mode = MEMORY;")
            
            logs_to_insert = []
            for i in range(10000):
                logs_to_insert.append((
                    f"id_{i}",
                    f"2026-01-01T00:00:{i%60:02d}Z",
                    "perf_actor",
                    "user",
                    "perf_action",
                    "perf_resource",
                    f"res_{i}",
                    "{}",
                    "{}",
                    None,
                    "{}"
                ))
            
            conn.executemany(
                """
                INSERT INTO audit_log (
                    id, timestamp, actor_id, actor_type, action, 
                    resource_type, resource_id, old_value, new_value, 
                    why_chain_id, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                logs_to_insert
            )
            conn.commit()

        # Measure query execution time
        start_time = time.perf_counter()
        res = self.logger.query_logs(actor_id="perf_actor", action="perf_action", limit=100)
        end_time = time.perf_counter()

        duration_ms = (end_time - start_time) * 1000
        self.assertEqual(res["total"], 10000)
        self.assertLess(duration_ms, 100.0, f"Query took too long: {duration_ms:.2f}ms")

if __name__ == "__main__":
    unittest.main()

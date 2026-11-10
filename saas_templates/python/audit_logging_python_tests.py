# Tests updated with the fix 2026-11-03: an in-memory logger keeps one connection, so every call sees the same database (each call
#   used to open a new, empty one).
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: SQLite only.
# [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Updated for the amended spec (AUDIT-08/09/10): every non-'user' entry now
#   names its subject (subject_user_id, or 'none'); metadata may only hold feature_flag / erased_rows, so the old
#   tests' ip / user_agent / reason metadata moved to the ip and user_agent fields or a feature_flag; reads pass an
#   admin caller; the logger runs on an injected clock. AUDIT-05 now seeds 1,000,000 entries (the row says "1M+";
#   it seeded 10,000). AUDIT-08/09/10 are new.
import datetime
import json
import sqlite3
import time
import unittest

from audit_logging_python import AuditLogger, AuditError

ADMIN = {"id": "admin-1", "is_admin": True}
T0 = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)


class TestAuditLogger(unittest.TestCase):
    def setUp(self):
        # Use an in-memory database for clean, isolated tests; the clock moves 1 s per call so order is fixed
        """A fresh in-memory logger on a clock that moves 1 s per call, retention 30 days. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.now = [T0]

        def clock():
            self.now[0] += datetime.timedelta(seconds=1)
            return self.now[0]

        self.logger = AuditLogger(":memory:", clock=clock, retention_days=30)

    def _all_rows_text(self):
        """Every retained row of the three audit tables as text. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        conn = self.logger.conn
        text = []
        for table in ("audit_log", "audit_personal", "audit_subjects"):
            for row in conn.execute(f"SELECT * FROM {table}"):
                text.append(json.dumps([str(v) for v in tuple(row)]))
        return "\n".join(text)

    # AUDIT-01
    def test_happy_path_log_and_query(self):
        # 1. Log mutation
        """Log a mutation and query it back by actor and resource type; the event row keeps no personal data.
        In: the test fixtures. Out: assertions. Why: AUDIT-01. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: subject_user_id, ip/user_agent fields instead of metadata, admin caller.
        Touches: in-memory SQLite only."""
        log_res = self.logger.log_mutation(
            actor_id=123,
            actor_type="user",
            action="subscription_changed",
            resource_type="subscription",
            resource_id=456,
            old_value={"tier": "team", "billing_date": "2026-10-15"},
            new_value={"tier": "enterprise", "billing_date": "2026-10-15"},
            why_chain_id="wc_789",
            subject_user_id=789,
            ip="192.168.1.1",
            user_agent="Mozilla",
        )
        self.assertTrue(log_res["success"])
        self.assertIsNotNone(log_res["log_id"])

        # 2. Query it back
        query_res = self.logger.query_logs(actor_id=123, resource_type="subscription", caller=ADMIN)
        self.assertEqual(query_res["total"], 1)
        self.assertFalse(query_res["has_more"])

        log_entry = query_res["logs"][0]
        self.assertEqual(log_entry["id"], log_res["log_id"])
        self.assertEqual(log_entry["actor_id"], "123")
        self.assertEqual(log_entry["action"], "subscription_changed")
        self.assertEqual(log_entry["resource_id"], "456")
        self.assertEqual(log_entry["old_value"]["tier"], "team")
        self.assertEqual(log_entry["new_value"]["tier"], "enterprise")
        self.assertEqual(log_entry["why_chain_id"], "wc_789")
        self.assertEqual(log_entry["ip"], "192.168.1.1")
        self.assertFalse(log_entry["personal_erased"])
        # the event row itself holds no resource id, values or IP: they are in audit_personal
        raw = self.logger.conn.execute("SELECT * FROM audit_log WHERE id = ?", (log_res["log_id"],)).fetchone()
        self.assertEqual((raw["resource_id"], raw["old_value"], raw["why_chain_id"]), (None, None, None))
        self.assertEqual(raw["personal_roles"], "actor,subject")

    # AUDIT-02
    def test_replay_and_divergence(self):
        # Log initial mutation
        """Replay shows the state at the time and detects a later change.
        In: the test fixtures. Out: assertions. Why: AUDIT-02. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: admin caller.
        Touches: in-memory SQLite only."""
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
        replay_1 = self.logger.replay(log_id_1, caller=ADMIN)
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
        replay_1_after = self.logger.replay(log_id_1, caller=ADMIN)
        self.assertTrue(replay_1_after["has_diverged"])

        # Replay second log (should not be diverged as it represents the latest state)
        replay_2 = self.logger.replay(log_id_2, caller=ADMIN)
        self.assertFalse(replay_2["has_diverged"])

    # AUDIT-03
    def test_filtering_combinations(self):
        # Insert multiple logs
        """actor_id + action + resource_type filter together; date range; a service actor by name.
        In: the test fixtures. Out: assertions. Why: AUDIT-03. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: subject 'none' for the billing entry, admin caller.
        Touches: in-memory SQLite only."""
        self.logger.log_mutation(1, "user", "user_created", "user", 101, {}, {"name": "Alice"})
        self.logger.log_mutation(1, "user", "user_suspended", "user", 101, {"name": "Alice"}, {"name": "Alice", "suspended": True})
        self.logger.log_mutation(2, "user", "user_created", "user", 102, {}, {"name": "Bob"})
        self.logger.log_mutation(3, "service", "billing_changed", "billing", 501, {}, {"amount": 100}, subject_user_id="none")

        # Filter by actor_id + action + resource_type
        res = self.logger.query_logs(actor_id=1, action="user_suspended", resource_type="user", caller=ADMIN)
        self.assertEqual(res["total"], 1)
        self.assertEqual(res["logs"][0]["resource_id"], "101")

        # Filter by date range
        res_date = self.logger.query_logs(date_from="2020-01-01T00:00:00Z", date_to="2030-12-31T23:59:59Z", caller=ADMIN)
        self.assertEqual(res_date["total"], 4)
        self.assertEqual(self.logger.query_logs(actor_id="3", caller=ADMIN)["total"], 1)  # a service by name

    # AUDIT-04
    def test_pagination(self):
        # Insert 5 logs
        """limit/offset pages, newest first.
        In: the test fixtures. Out: assertions. Why: AUDIT-04. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: subject_user_id, admin caller, page order checked.
        Touches: in-memory SQLite only."""
        for i in range(5):
            self.logger.log_mutation(1, "user", "item_added", "cart", 200, {}, {"item": i}, subject_user_id=1)

        # Page 1 (limit 2, offset 0)
        page1 = self.logger.query_logs(limit=2, offset=0, caller=ADMIN)
        self.assertEqual(len(page1["logs"]), 2)
        self.assertEqual(page1["total"], 5)
        self.assertTrue(page1["has_more"])
        self.assertEqual([log["new_value"]["item"] for log in page1["logs"]], [4, 3])

        # Page 2 (limit 2, offset 2)
        page2 = self.logger.query_logs(limit=2, offset=2, caller=ADMIN)
        self.assertEqual(len(page2["logs"]), 2)
        self.assertTrue(page2["has_more"])

        # Page 3 (limit 2, offset 4)
        page3 = self.logger.query_logs(limit=2, offset=4, caller=ADMIN)
        self.assertEqual(len(page3["logs"]), 1)
        self.assertFalse(page3["has_more"])

    # AUDIT-06
    def test_immutability(self):
        """UPDATE and DELETE on audit_log, and UPDATE on audit_personal, raise.
        In: the test fixtures. Out: assertions. Why: AUDIT-06. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: audit_personal checked too.
        Touches: in-memory SQLite only."""
        res = self.logger.log_mutation(1, "user", "test_action", "test_resource", 99, {}, {"val": 1}, subject_user_id=1)
        log_id = res["log_id"]

        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            self.logger._get_connection().execute("UPDATE audit_log SET action = 'hacked' WHERE id = ?", (log_id,))
        self.assertIn("immutable", str(ctx.exception))

        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            self.logger._get_connection().execute("DELETE FROM audit_log WHERE id = ?", (log_id,))
        self.assertIn("immutable", str(ctx.exception))

        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            self.logger._get_connection().execute("UPDATE audit_personal SET data = '{}' WHERE log_id = ?", (log_id,))
        self.assertIn("immutable", str(ctx.exception))

    # AUDIT-07
    def test_wildcard_matching(self):
        """action='user_*' matches user_created and user_suspended only ('_' is literal).
        In: the test fixtures. Out: assertions. Why: AUDIT-07. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: subject for the billing entry, a 'userX' entry proves '_' is literal.
        Touches: in-memory SQLite only."""
        self.logger.log_mutation(1, "user", "user_created", "user", 101, {}, {})
        self.logger.log_mutation(1, "user", "user_suspended", "user", 101, {}, {})
        self.logger.log_mutation(1, "user", "billing_changed", "billing", 101, {}, {}, subject_user_id=1)
        self.logger.log_mutation(1, "user", "userXcreated", "user", 101, {}, {})  # '_' is literal

        # Wildcard search for user_*
        res = self.logger.query_logs(action="user_*", caller=ADMIN)
        self.assertEqual(res["total"], 2)
        actions = {log["action"] for log in res["logs"]}
        self.assertEqual(actions, {"user_created", "user_suspended"})

    def test_search(self):
        """Search finds values and metadata, honours resource_type, and treats '%' literally.
        In: the test fixtures. Out: assertions. Why: spec endpoint 4. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: metadata uses feature_flag (other keys are refused), admin caller.
        Touches: in-memory SQLite only."""
        self.logger.log_mutation(
            actor_id=1,
            actor_type="user",
            action="profile_updated",
            resource_type="user",
            resource_id=101,
            old_value={"email": "old@example.com"},
            new_value={"email": "new@example.com"},
            metadata={"feature_flag": "requested_change_flow"}
        )

        # Search by email in old/new values
        res = self.logger.search("example.com", caller=ADMIN)
        self.assertEqual(len(res["results"]), 1)

        # Search by metadata content
        res_meta = self.logger.search("requested_change", caller=ADMIN)
        self.assertEqual(len(res_meta["results"]), 1)

        # Search with resource_type filter
        res_filtered = self.logger.search("example.com", resource_type="user", caller=ADMIN)
        self.assertEqual(len(res_filtered["results"]), 1)

        res_none = self.logger.search("example.com", resource_type="billing", caller=ADMIN)
        self.assertEqual(len(res_none["results"]), 0)
        self.assertEqual(len(self.logger.search("%", caller=ADMIN)["results"]), 0)  # wildcards are literal

    # AUDIT-05
    def test_performance_large_dataset(self):
        # Bulk insert 1,000,000 entries by 100 actors (10,000 each) straight into the tables, then a filtered query
        # must return in under 100 ms. The budget is contract.
        """1,000,000 entries by 100 actors: an actor_id + action query returns 10,000 total in under 100 ms.
        In: the test fixtures. Out: assertions. Why: AUDIT-05. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: seeds 1M rows in the new schema (was 10,000).
        Touches: in-memory SQLite only."""
        conn = self.logger._get_connection()
        conn.execute("PRAGMA synchronous = OFF;")
        conn.execute("PRAGMA journal_mode = MEMORY;")
        n, actors = 1_000_000, 100
        conn.execute("BEGIN")
        conn.executemany("INSERT INTO audit_subjects (subject_ref, user_id, created_at) VALUES (?, ?, '2026-01-01')",
                         ((f"ref_{a:03d}", f"perf_actor_{a}") for a in range(actors)))
        conn.executemany(
            "INSERT INTO audit_log (id, timestamp, actor_type, action, resource_type, resource_id, personal_roles, metadata) "
            "VALUES (?, ?, 'user', 'perf_action', 'perf_resource', ?, 'actor', '{}')",
            ((f"id_{i:07d}", f"2026-01-01T{(i // 3600) % 24:02d}:{(i // 60) % 60:02d}:{i % 60:02d}.{i:06d}Z", f"res_{i}")
             for i in range(n)))
        conn.executemany(
            "INSERT INTO audit_personal (log_id, subject_ref, role, data) VALUES (?, ?, 'actor', ?)",
            ((f"id_{i:07d}", f"ref_{i % actors:03d}", '{"actor_id": "perf_actor_%d", "ip": null, "user_agent": null, '
              '"request_id": null}' % (i % actors)) for i in range(n)))
        conn.execute("COMMIT")

        # Measure query execution time
        start_time = time.perf_counter()
        res = self.logger.query_logs(actor_id="perf_actor_7", action="perf_action", limit=100, caller=ADMIN)
        end_time = time.perf_counter()

        duration_ms = (end_time - start_time) * 1000
        self.assertEqual(res["total"], 10000)
        self.assertEqual(len(res["logs"]), 100)
        self.assertLess(duration_ms, 100.0, f"Query took too long: {duration_ms:.2f}ms")

    # AUDIT-08
    def test_erase_subject_leaves_nothing_that_identifies_the_user(self):
        """erase_subject(user): no retained row of the three tables holds the user's id, email or IP; earlier
        audit_log rows are unchanged and exactly one 'audit_subject_erased' row is added; reads show the user's
        entries with personal_erased true, an actor_id filter for the user finds nothing, replay says erased.
        Why: AUDIT-08 (amended 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test db."""
        uid, email, ip = 987654321, "erase.me@example.test", "203.0.113.77"
        own = self.logger.log_mutation(uid, "user", "user_profile_updated", "user", uid, {"email": "a@x.test"},
                                       {"email": email}, why_chain_id="wc_1", ip=ip, user_agent="UA", request_id="r1")
        by_admin = self.logger.log_mutation(5, "user", "subscription_changed", "subscription", "sub_1",
                                            {"tier": "solo", "email": email}, {"tier": "team"},
                                            subject_user_id=uid, ip="198.51.100.5")
        via_key = self.logger.log_mutation("key_1", "api_key", "deployment_created", "deployment", "dep_1", None,
                                           {"name": "site"}, subject_user_id="none", actor_user_id=uid, ip=ip)
        other = self.logger.log_mutation(6, "user", "user_created", "user", 6, {}, {"email": "keep@x.test"}, ip="192.0.2.6")
        self.assertIn(email, self._all_rows_text())
        before = [tuple(r) for r in self.logger.conn.execute("SELECT * FROM audit_log ORDER BY rowid")]

        result = self.logger.erase_subject(uid)
        self.assertEqual(result, {"erased_rows": 4})  # own: actor+subject, by_admin: subject, via_key: actor

        text = self._all_rows_text()
        for needle in (str(uid), email, ip):
            self.assertNotIn(needle, text)
        after = [tuple(r) for r in self.logger.conn.execute("SELECT * FROM audit_log ORDER BY rowid")]
        self.assertEqual(after[:len(before)], before)
        self.assertEqual(len(after), len(before) + 1)
        added = self.logger.conn.execute("SELECT * FROM audit_log ORDER BY rowid DESC LIMIT 1").fetchone()
        self.assertEqual((added["action"], added["actor_type"], added["resource_type"], added["resource_id"],
                          added["personal_roles"], json.loads(added["metadata"])),
                         ("audit_subject_erased", "service", "user", None, "", {"erased_rows": 4}))

        logs = {log["id"]: log for log in self.logger.query_logs(limit=10, caller=ADMIN)["logs"]}
        for log_id in (own["log_id"], by_admin["log_id"], via_key["log_id"]):
            self.assertTrue(logs[log_id]["personal_erased"])
        self.assertIsNone(logs[own["log_id"]]["new_value"])
        self.assertEqual(logs[by_admin["log_id"]]["actor_id"], "5")  # the admin's own actor row stays
        self.assertFalse(logs[other["log_id"]]["personal_erased"])
        self.assertEqual(self.logger.query_logs(actor_id=uid, caller=ADMIN)["total"], 0)
        self.assertEqual(self.logger.search(email, caller=ADMIN)["results"], [])
        self.assertEqual(self.logger.replay(own["log_id"], caller=ADMIN),
                         {"log_id": own["log_id"], "timestamp": logs[own["log_id"]]["timestamp"], "erased": True,
                          "resource_state_at_time": None, "has_diverged": None})

    # AUDIT-09
    def test_apply_retention_erases_only_old_personal_data(self):
        """Entries older than retention_days (30 here) lose their personal rows; newer ones keep them; no audit_log
        row is removed; a subject left with no rows is removed. Why: AUDIT-09 (amended 2026-11-10).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test db."""
        old = self.logger.log_mutation(11, "user", "user_created", "user", 11, {}, {"email": "old@x.test"}, ip="192.0.2.11")
        self.now[0] = T0 + datetime.timedelta(days=40)
        new = self.logger.log_mutation(12, "user", "user_created", "user", 12, {}, {"email": "new@x.test"}, ip="192.0.2.12")
        count_before = self.logger.conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        result = self.logger.apply_retention(T0 + datetime.timedelta(days=41))
        self.assertEqual(result, {"erased_rows": 2})
        self.assertEqual(self.logger.conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0], count_before)
        text = self._all_rows_text()
        self.assertNotIn("192.0.2.11", text)
        self.assertNotIn("old@x.test", text)
        self.assertIn("192.0.2.12", text)
        logs = {log["id"]: log for log in self.logger.query_logs(caller=ADMIN)["logs"]}
        self.assertTrue(logs[old["log_id"]]["personal_erased"])
        self.assertEqual(logs[new["log_id"]]["new_value"], {"email": "new@x.test"})
        users = [r[0] for r in self.logger.conn.execute("SELECT user_id FROM audit_subjects")]
        self.assertEqual(users, ["12"])

    # AUDIT-10
    def test_log_and_read_refusals(self):
        """log() refuses a non-'user' entry without subject_user_id (subject_required), a metadata key other than
        feature_flag / erased_rows (metadata_key_not_allowed), an api_key entry without actor_user_id
        (actor_user_required) and a 'user' entry whose subject differs (subject_mismatch), all 400 and writing
        nothing; reads by a non-admin caller get 403. Why: AUDIT-10 (amended 2026-11-10).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test db."""
        cases = [
            (dict(resource_type="subscription", resource_id=1), "subject_required"),
            (dict(resource_type="subscription", resource_id=1, subject_user_id="none", metadata={"ip": "1.2.3.4"}),
             "metadata_key_not_allowed"),
            (dict(resource_type="deployment", resource_id=1, subject_user_id="none", actor_type="api_key"),
             "actor_user_required"),
            (dict(resource_type="user", resource_id=1, subject_user_id=2), "subject_mismatch"),
        ]
        for kwargs, code in cases:
            args = dict(actor_id=1, actor_type="user", action="x_changed", old_value={}, new_value={})
            args.update(kwargs)
            with self.assertRaises(AuditError) as cm:
                self.logger.log_mutation(**args)
            self.assertEqual((cm.exception.status, cm.exception.code), (400, code))
        self.assertEqual(self.logger.conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0], 0)
        self.assertEqual(self.logger.conn.execute("SELECT COUNT(*) FROM audit_subjects").fetchone()[0], 0)
        ok = self.logger.log_mutation(1, "user", "flag_toggled", "flag", "f1", {}, {}, subject_user_id="none",
                                      metadata={"feature_flag": "beta"})
        for caller in (None, {"id": 1, "is_admin": False}, {"id": 1, "is_admin": "yes"}):
            for read in (lambda: self.logger.query_logs(caller=caller),
                         lambda: self.logger.replay(ok["log_id"], caller=caller),
                         lambda: self.logger.search("flag", caller=caller)):
                with self.assertRaises(AuditError) as cm:
                    read()
                self.assertEqual((cm.exception.status, cm.exception.code), (403, "admin_only"))


if __name__ == "__main__":
    unittest.main()

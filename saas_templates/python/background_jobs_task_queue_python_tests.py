import unittest
import tempfile
import os
import time
import json
import threading
from datetime import datetime, timedelta, timezone
from background_jobs_task_queue_python import BackgroundJobSystem

class TestBackgroundJobSystem(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp()
        self.system = BackgroundJobSystem(db_path=self.db_path)
        self.system.start_worker()
        
    def tearDown(self):
        self.system.stop_worker()
        os.close(self.db_fd)
        os.unlink(self.db_path)

    # JOBS-01
    def test_enqueue_job_initial_status(self):
        # [2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP] Stop the worker first: with it polling, it
        # could claim the job between enqueue and the status read (a timing race), so "enqueued" was luck.
        self.system.stop_worker()
        result = self.system.enqueue_job("send_bulk_email", {"template_key": "test"})
        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "enqueued")
        job_id = result["job_id"]
        
        status = self.system.get_job_status(job_id)
        self.assertEqual(status["job_id"], job_id)
        self.assertEqual(status["task_type"], "send_bulk_email")
        self.assertEqual(status["status"], "enqueued")
        self.assertIsNone(status["started_at"])
        self.assertIsNone(status["completed_at"])
        self.assertIsNone(status["result"])
        self.assertIsNone(status["next_retry_at"])

    # JOBS-02
    def test_job_completes_and_results_available(self):
        def success_handler(params, progress_callback):
            progress_callback(5, 10)
            progress_callback(10, 10)
            return {"sent": 10, "failed": 0}
        
        self.system.register_handler("test_success", success_handler)
        result = self.system.enqueue_job("test_success", {})
        job_id = result["job_id"]
        
        # Wait for job to complete
        timeout = time.time() + 5
        while time.time() < timeout:
            status = self.system.get_job_status(job_id)
            if status["status"] == "completed":
                break
            time.sleep(0.1)
        else:
            self.fail("Job did not complete within timeout")
        
        self.assertEqual(status["status"], "completed")
        self.assertEqual(status["progress"], "10/10")
        self.assertIsNotNone(status["result"])
        self.assertEqual(status["result"]["sent"], 10)
        self.assertEqual(status["result"]["failed"], 0)
        
        # Test results endpoint
        results = self.system.get_job_results(job_id)
        self.assertEqual(results["status"], "completed")
        self.assertEqual(results["result"]["sent"], 10)
        self.assertEqual(results["completed_at"], status["completed_at"])

    # JOBS-03
    def test_job_fails_and_retries_with_exponential_backoff(self):
        attempt_count = 0
        def failing_handler(params, progress_callback):
            nonlocal attempt_count
            attempt_count += 1
            raise Exception(f"Attempt {attempt_count} failed")
        
        self.system.register_handler("test_failure", failing_handler)
        result = self.system.enqueue_job("test_failure", {}, max_retries=2)
        job_id = result["job_id"]
        
        # First failure -> enqueued for retry
        timeout = time.time() + 5
        while time.time() < timeout:
            status = self.system.get_job_status(job_id)
            if status["status"] == "enqueued" and status["retry_count"] == 1:
                break
            time.sleep(0.1)
        else:
            self.fail("Job did not retry after first failure")
        
        # Check backoff timing: the spec's backoff is 1s, 2s, 4s, ... so the first retry waits 2^0 = 1 second.
        # [2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP] was 2.0, which contradicts TIER_2 spec system 4
        # ("Exponential backoff (1s, 2s, 4s, 8s, ... up to max_retries)") and the passing Java suite.
        first_retry_time = datetime.fromisoformat(status["next_retry_at"].replace('Z', '+00:00'))
        enqueue_time = datetime.fromisoformat(status["created_at"].replace('Z', '+00:00'))
        backoff = (first_retry_time - enqueue_time).total_seconds()
        self.assertAlmostEqual(backoff, 1.0, delta=0.5)
        
        # Second and third attempts fail (retries 1 and 2) -> retries exhausted -> failed.
        # [2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP] max_retries=2 allows two retries after the
        # first attempt (spec: "up to max_retries"; Java: retry_count 2 after three attempts), so the
        # final error is from attempt 3; the old "Attempt 2 failed" meant only one retry was ever made.
        timeout = time.time() + 5
        while time.time() < timeout:
            status = self.system.get_job_status(job_id)
            if status["status"] == "failed":
                break
            time.sleep(0.1)
        else:
            self.fail("Job did not fail after max retries")
        
        self.assertEqual(status["retry_count"], 2)
        self.assertEqual(status["max_retries"], 2)
        self.assertIsNotNone(status["error"])
        self.assertIn("Attempt 3 failed", status["error"])
        self.assertEqual(attempt_count, 3)

    # JOBS-04
    def test_job_exceeds_max_retries_becomes_failed(self):
        def failing_handler(params, progress_callback):
            raise Exception("Permanent failure")
        
        self.system.register_handler("test_perm_fail", failing_handler)
        result = self.system.enqueue_job("test_perm_fail", {}, max_retries=0)
        job_id = result["job_id"]
        
        timeout = time.time() + 5
        while time.time() < timeout:
            status = self.system.get_job_status(job_id)
            if status["status"] == "failed":
                break
            time.sleep(0.1)
        else:
            self.fail("Job did not become failed")
        
        self.assertEqual(status["status"], "failed")
        self.assertEqual(status["retry_count"], 0)
        self.assertEqual(status["max_retries"], 0)
        self.assertIsNotNone(status["error"])

    def _clocked_system(self):
        """A second system on its own database with an injected clock and no worker thread.

        Out: (system, now) where now[0] is the clock's current time; jobs run only through run_pending().
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (deterministic JOBS-03/04). Touches a temp SQLite file."""
        fd, path = tempfile.mkstemp()
        os.close(fd)
        self.addCleanup(os.unlink, path)
        now = [datetime(2026, 11, 10, 12, 0, 0, tzinfo=timezone.utc)]
        return BackgroundJobSystem(db_path=path, clock=lambda: now[0]), now

    # JOBS-03
    def test_retry_waits_1s_then_2s_and_counts_retries(self):
        """Retry n waits 2^(n-1) s: next_retry_at = failed_at + 1 s, then + 2 s; while waiting the job is
        'enqueued' with retry_count = n and is skipped until next_retry_at.
        In: a clocked system and a handler that always fails. Out: assertions. Why: JOBS-03 as amended
        2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches a temp SQLite file."""
        system, now = self._clocked_system()
        runs = []

        def failing(params, progress):
            runs.append(now[0])
            raise Exception(f"attempt {len(runs)} failed")

        system.register_handler("flaky", failing)
        job_id = system.enqueue_job("flaky", {}, max_retries=3)["job_id"]
        t0 = now[0]
        self.assertEqual(system.run_pending(), 1)
        status = system.get_job_status(job_id)
        self.assertEqual((status["status"], status["retry_count"]), ("enqueued", 1))
        self.assertEqual(datetime.fromisoformat(status["next_retry_at"]), t0 + timedelta(seconds=1))

        now[0] = t0 + timedelta(milliseconds=999)
        self.assertEqual(system.run_pending(), 0)  # skipped until next_retry_at
        now[0] = t0 + timedelta(seconds=1)
        self.assertEqual(system.run_pending(), 1)
        status = system.get_job_status(job_id)
        self.assertEqual((status["status"], status["retry_count"]), ("enqueued", 2))
        self.assertEqual(datetime.fromisoformat(status["next_retry_at"]), now[0] + timedelta(seconds=2))
        now[0] += timedelta(seconds=1)
        self.assertEqual(system.run_pending(), 0)
        self.assertEqual(len(runs), 2)

    # JOBS-04
    def test_max_retries_3_runs_4_times_then_failed_with_retry_count_3(self):
        """With max_retries = 3 the job runs 4 times (waits 1, 2, 4 s), then is 'failed' with retry_count 3
        and no next_retry_at. In: a clocked system. Out: assertions. Why: JOBS-04 as amended 2026-11-10.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches a temp SQLite file."""
        system, now = self._clocked_system()
        runs = []

        def failing(params, progress):
            runs.append(now[0])
            raise Exception(f"attempt {len(runs)} failed")

        system.register_handler("always_fails", failing)
        job_id = system.enqueue_job("always_fails", {}, max_retries=3)["job_id"]
        t0 = now[0]
        for wait in (0, 1, 2, 4):
            now[0] += timedelta(seconds=wait)
            self.assertEqual(system.run_pending(), 1)
        now[0] += timedelta(seconds=60)
        self.assertEqual(system.run_pending(), 0)
        self.assertEqual(runs, [t0, t0 + timedelta(seconds=1), t0 + timedelta(seconds=3), t0 + timedelta(seconds=7)])
        status = system.get_job_status(job_id)
        self.assertEqual(status["status"], "failed")
        self.assertEqual(status["retry_count"], 3)
        self.assertIsNone(status["next_retry_at"])
        self.assertIn("attempt 4 failed", status["error"])

    # JOBS-05
    def test_user_can_cancel_enqueued_job(self):
        # [2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP] Stop the worker so the job is certainly not
        # started when we cancel; with it polling, the cancel raced the worker's claim.
        self.system.stop_worker()
        result = self.system.enqueue_job("send_bulk_email", {})
        job_id = result["job_id"]
        
        cancel_result = self.system.cancel_job(job_id)
        self.assertTrue(cancel_result["success"])
        self.assertEqual(cancel_result["status"], "cancelled")
        
        status = self.system.get_job_status(job_id)
        self.assertEqual(status["status"], "cancelled")
        self.assertIsNone(status["started_at"])

    # JOBS-01
    def test_cannot_cancel_job_that_has_started(self):
        # [2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP] The handler holds the job in "running" until
        # the test releases it, instead of sleeping 0.5 s and hoping the poll lands inside that window.
        release = threading.Event()
        def slow_handler(params, progress_callback):
            release.wait(5)  # Simulate work that lasts until released
            return {"done": True}
        
        self.system.register_handler("test_slow", slow_handler)
        result = self.system.enqueue_job("test_slow", {})
        job_id = result["job_id"]
        
        # Wait for job to start running
        timeout = time.time() + 2
        while time.time() < timeout:
            status = self.system.get_job_status(job_id)
            if status["status"] == "running":
                break
            time.sleep(0.05)
        else:
            self.fail("Job did not start running")
        
        # Attempt to cancel running job
        with self.assertRaises(ValueError) as cm:
            self.system.cancel_job(job_id)
        self.assertIn("Cannot cancel job that has already started", str(cm.exception))
        
        # Verify job still running/completed
        status = self.system.get_job_status(job_id)
        self.assertIn(status["status"], ["running", "completed"])
        release.set()

    # JOBS-06
    def test_progress_tracking_updates_in_real_time(self):
        progress_updates = []
        # [2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP] Each step waits until the test has read it
        # from the store (observed.set()), instead of sleeping 10 ms while the test polls every 50 ms, which
        # skipped most steps (it saw ['30/100', '70/100'] and failed on '50/100'). Same assertions.
        observed = threading.Event()
        def progress_handler(params, progress_callback):
            for i in range(0, 101, 10):
                progress_callback(i, 100)
                if not observed.wait(5):  # wait until the test has seen this step
                    raise RuntimeError("test did not observe progress")
                observed.clear()
            return {"completed": 100}
        
        self.system.register_handler("test_progress", progress_handler)
        result = self.system.enqueue_job("test_progress", {})
        job_id = result["job_id"]
        
        # Monitor progress updates
        last_progress = None
        timeout = time.time() + 3
        while time.time() < timeout:
            status = self.system.get_job_status(job_id)
            if status["status"] == "completed":
                break
            if status["progress"] and status["progress"] != last_progress:
                last_progress = status["progress"]
                progress_updates.append(status["progress"])
                observed.set()
            time.sleep(0.01)
        else:
            self.fail("Job did not complete")
        
        # Verify we saw incremental progress
        self.assertGreater(len(progress_updates), 0)
        self.assertIn("50/100", progress_updates)
        self.assertIn("90/100", progress_updates)
        final_status = self.system.get_job_status(job_id)
        self.assertEqual(final_status["progress"], "100/100")

    # JOBS-07
    def test_scheduled_job_only_runs_after_scheduled_time(self):
        future_time = datetime.now(timezone.utc) + timedelta(seconds=2)
        scheduled_at = future_time.isoformat()
        
        def quick_handler(params, progress_callback):
            progress_callback(1, 1)
            return {"ran": True}
        
        self.system.register_handler("test_scheduled", quick_handler)
        result = self.system.enqueue_job("test_scheduled", {}, scheduled_at=scheduled_at)
        job_id = result["job_id"]
        
        # Immediately check - should still be enqueued
        status = self.system.get_job_status(job_id)
        self.assertEqual(status["status"], "enqueued")
        self.assertIsNone(status["started_at"])
        
        # Wait until after scheduled time
        time.sleep(2.5)
        
        # Should now be processing/completed
        timeout = time.time() + 3
        while time.time() < timeout:
            status = self.system.get_job_status(job_id)
            if status["status"] in ["running", "completed"]:
                break
            time.sleep(0.1)
        else:
            self.fail("Job did not run after scheduled time")
        
        self.assertIn(status["status"], ["running", "completed"])
        if status["status"] == "completed":
            self.assertEqual(status["result"]["ran"], True)

    def test_bulk_job_processed_without_blocking_request(self):
        # [2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP] Stop the worker so the stored job is still
        # "enqueued" when we read it back (the worker could otherwise claim it first: a timing race).
        self.system.stop_worker()
        # Test that enqueue returns quickly even with large params
        large_params = {"items": list(range(1000))}  # Simulate large payload
        
        start_time = time.time()
        result = self.system.enqueue_job("send_bulk_email", large_params)
        enqueue_time = time.time() - start_time
        
        # Enqueue should be fast (<100ms) regardless of payload size
        self.assertLess(enqueue_time, 0.1)
        self.assertTrue(result["success"])
        job_id = result["job_id"]
        
        # Verify job was stored correctly
        status = self.system.get_job_status(job_id)
        self.assertEqual(status["status"], "enqueued")
        params = json.loads(status["params"]) if status["params"] else {}
        self.assertEqual(len(params.get("items", [])), 1000)

    # JOBS-07
    def test_scheduled_job_waits_for_scheduled_at_on_injected_clock(self):
        """A job scheduled an hour ahead is not claimed before then and runs once it is due (no sleeps).
        In: a clocked system. Out: assertions. Why: JOBS-07 without wall-clock waits (docs/specs/README.md).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches a temp SQLite file."""
        system, now = self._clocked_system()
        system.register_handler("later", lambda params, progress: {"ran": True})
        due = now[0] + timedelta(hours=1)
        job_id = system.enqueue_job("later", {}, scheduled_at=due.isoformat())["job_id"]
        now[0] = due - timedelta(microseconds=1)
        self.assertEqual(system.run_pending(), 0)
        self.assertEqual(system.get_job_status(job_id)["status"], "enqueued")
        now[0] = due
        self.assertEqual(system.run_pending(), 1)
        self.assertEqual(system.get_job_status(job_id)["result"], {"ran": True})

    # JOBS-08
    def test_bulk_job_of_10000_items_is_queued_then_processed_by_the_worker(self):
        """enqueue_job returns at once with 10,000 recipients and sends nothing in the request; the worker then
        sends all 10,000 and reports progress 10000/10000.
        In: a clocked system (no thread) with the in-memory email sender. Out: assertions.
        Why: JOBS-08; the older test only enqueued 1,000 items and never processed them.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches a temp SQLite file and the fake email sender."""
        system, now = self._clocked_system()
        recipients = [f"user{i}@example.com" for i in range(10000)]
        result = system.enqueue_job("send_bulk_email", {"template_key": "digest", "recipients": recipients})
        self.assertEqual(result["status"], "enqueued")
        self.assertEqual(len(system.email_sender.sent), 0)  # nothing sent inside the request
        self.assertEqual(system.run_pending(), 1)
        status = system.get_job_status(result["job_id"])
        self.assertEqual(status["status"], "completed")
        self.assertEqual(status["progress"], "10000/10000")
        self.assertEqual(status["result"]["sent"], 10000)
        self.assertEqual(len(system.email_sender.sent), 10000)

    # JOBS-09
    def test_results_available_after_job_completion(self):
        def result_handler(params, progress_callback):
            progress_callback(3, 5)
            progress_callback(5, 5)
            return {"processed": 5, "errors": [{"id": 1, "msg": "test"}]}
        
        self.system.register_handler("test_result", result_handler)
        result = self.system.enqueue_job("test_result", {})
        job_id = result["job_id"]
        
        # Wait for completion
        timeout = time.time() + 3
        while time.time() < timeout:
            status = self.system.get_job_status(job_id)
            if status["status"] == "completed":
                break
            time.sleep(0.1)
        else:
            self.fail("Job did not complete")
        
        # Check results endpoint
        results = self.system.get_job_results(job_id)
        self.assertEqual(results["job_id"], job_id)
        self.assertEqual(results["status"], "completed")
        self.assertEqual(results["result"]["processed"], 5)
        self.assertEqual(len(results["result"]["errors"]), 1)
        self.assertEqual(results["result"]["errors"][0]["msg"], "test")
        self.assertIsNotNone(results["completed_at"])

    def test_get_nonexistent_job_raises_error(self):
        with self.assertRaises(ValueError) as cm:
            self.system.get_job_status("nonexistent-id")
        self.assertIn("Job nonexistent-id not found", str(cm.exception))

    def test_cancel_nonexistent_job_raises_error(self):
        with self.assertRaises(ValueError) as cm:
            self.system.cancel_job("nonexistent-id")
        self.assertIn("Job nonexistent-id not found", str(cm.exception))

    def test_retry_nonexistent_job_raises_error(self):
        with self.assertRaises(ValueError) as cm:
            self.system.retry_job("nonexistent-id")
        self.assertIn("Job nonexistent-id not found", str(cm.exception))

    def test_get_results_for_nonexistent_job_raises_error(self):
        with self.assertRaises(ValueError) as cm:
            self.system.get_job_results("nonexistent-id")
        self.assertIn("Job nonexistent-id not found", str(cm.exception))

    def test_cannot_retry_non_failed_job(self):
        def success_handler(params, progress_callback):
            return {"ok": True}
        
        self.system.register_handler("test_success2", success_handler)
        result = self.system.enqueue_job("test_success2", {})
        job_id = result["job_id"]
        
        # Wait for completion
        timeout = time.time() + 2
        while time.time() < timeout:
            status = self.system.get_job_status(job_id)
            if status["status"] == "completed":
                break
            time.sleep(0.1)
        else:
            self.fail("Job did not complete")
        
        # Attempt to retry completed job: the spec retries failed jobs only.
        # [2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP] removed stale comments that said the
        # implementation allows retrying any job; it now refuses, as the spec and Java do.
        with self.assertRaises(ValueError) as cm:
            self.system.retry_job(job_id)
        self.assertIn("only failed jobs can be retried", str(cm.exception))

if __name__ == '__main__':
    unittest.main()
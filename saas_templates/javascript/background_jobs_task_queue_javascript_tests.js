const request = require('supertest');
const { createJobService } = require('./background_jobs_task_queue_javascript');
jest.setTimeout(30000); // allow long-running jobs

// Deterministic time (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). These tests used to sleep against a worker
// polling on a real 1 s timer, so whether a retry had happened by the time of each check depended on where the timer
// stood when the test began. The queue now runs on this clock, and advanceClock() lets the worker poll once per
// POLL_MS of clock time, exactly as its timer would, so every check sees the same state on every run.
const POLL_MS = 1000;
let clock = Date.parse('2026-01-01T00:00:00.000Z');
const { app, db, jobManager } = createJobService({ now: () => clock, pollIntervalMs: POLL_MS });

async function advanceClock(ms) {
    let left = ms;
    while (left > 0) {
        const step = Math.min(POLL_MS, left);
        clock += step;
        left -= step;
        await jobManager.tick();
    }
}

describe('Background Jobs & Task Queue API', () => {
    beforeAll(() => {
        // Ensure DB is clean
        db.exec('DELETE FROM job_runs');
        db.exec('DELETE FROM jobs');
    });

    afterAll(async () => {
        await jobManager.stop();
        db.close();
    });

    // JOBS-01
    test('Enqueue job, worker picks it up, status becomes running', async () => {
        const res = await request(app)
            .post('/jobs/enqueue')
            .send({ task_type: 'send_bulk_email', params: { total: 20 } });
        expect(res.body.success).toBe(true);
        const jobId = res.body.job_id;

        // Wait a moment for worker to claim
        await advanceClock(1500);
        const statusRes = await request(app).get(`/jobs/${jobId}`);
        expect(['running', 'completed']).toContain(statusRes.body.status);
    });

    // JOBS-02
    test('Job completes, status becomes completed, results available', async () => {
        const res = await request(app)
            .post('/jobs/enqueue')
            .send({ task_type: 'export_generate', params: { items: 30 } });
        const jobId = res.body.job_id;

        // Wait enough time for completion
        await advanceClock(4000);
        const statusRes = await request(app).get(`/jobs/${jobId}`);
        expect(statusRes.body.status).toBe('completed');
        const resultsRes = await request(app).get(`/jobs/${jobId}/results`);
        expect(resultsRes.body.status).toBe('completed');
        expect(resultsRes.body.result).toHaveProperty('exported', 30);
    });

    // JOBS-03
    test('Job fails, auto-retries with exponential backoff', async () => {
        // Create a task that throws error to trigger retry
        jobManager.db.prepare(`
            INSERT INTO jobs (id, task_type, params, status, created_at, max_retries, retry_count)
            VALUES ('fail-job', 'nonexistent_task', '{}', 'enqueued', ?, 2, 0)
        `).run(now());

        // Wait for first attempt (should fail and schedule retry)
        await advanceClock(1500);
        let job = jobManager.get('fail-job');
        expect(job.status).toBe('enqueued');
        expect(job.retry_count).toBe(1);
        expect(job.next_retry_at).not.toBeNull();

        // Wait for the second backoff (spec: 1 s, then 2 s)
        await advanceClock(2500);
        job = jobManager.get('fail-job');
        expect(job.retry_count).toBe(2);
        expect(job.status).toBe('enqueued');

        // Wait for the final retry
        await advanceClock(4500);
        job = jobManager.get('fail-job');
        expect(job.status).toBe('failed');
        expect(job.retry_count).toBe(2);
    });

    // JOBS-04
    test('Job exceeds max_retries, status becomes failed', async () => {
        // Insert job with max_retries = 1
        const id = 'max-retry-job';
        jobManager.db.prepare(`
            INSERT INTO jobs (id, task_type, params, status, created_at, max_retries, retry_count)
            VALUES (?, 'nonexistent_task', '{}', 'enqueued', ?, 1, 0)
        `).run(id, now());

        await advanceClock(2000);
        const job = jobManager.get(id);
        expect(job.status).toBe('failed');
        expect(job.retry_count).toBe(1);
    });

    /**
     * JOBS-03: exact backoff. Retry n waits 2^(n-1) s from the failed attempt: retry 1 runs 1 s after the first
     * failure (not at 999 ms), retry 2 runs 2 s after the second; while it waits the job is 'enqueued' with
     * retry_count = n and the worker skips it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec amended).
     * Touches: the test's in-memory database only.
     */
    // JOBS-03
    test('Retry n waits 2^(n-1) s and the worker skips the job until next_retry_at', async () => {
        const id = 'backoff-exact';
        jobManager.db.prepare(`
            INSERT INTO jobs (id, task_type, params, status, created_at, max_retries, retry_count)
            VALUES (?, 'nonexistent_task', '{}', 'enqueued', ?, 3, 0)
        `).run(id, now());
        const runs = () => jobManager.db.prepare('SELECT COUNT(*) AS n FROM job_runs WHERE job_id = ?').get(id).n;

        await jobManager.tick();
        const failedAt = clock;
        let job = jobManager.get(id);
        expect(runs()).toBe(1);
        expect(job.status).toBe('enqueued');
        expect(job.retry_count).toBe(1);
        expect(Date.parse(job.next_retry_at)).toBe(failedAt + 1000);

        await advanceClock(999);
        expect(runs()).toBe(1);
        await advanceClock(1);
        job = jobManager.get(id);
        expect(runs()).toBe(2);
        expect(job.retry_count).toBe(2);
        expect(Date.parse(job.next_retry_at)).toBe(failedAt + 1000 + 2000);

        await advanceClock(1999);
        expect(runs()).toBe(2);
        await advanceClock(1);
        expect(runs()).toBe(3);
        expect(jobManager.get(id).retry_count).toBe(3);
    });

    /**
     * JOBS-04: max_retries counts retries after the first attempt, so max_retries = 3 runs the job 4 times; after the
     * 4th failure the status is 'failed' with retry_count = 3 and it never runs again.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec amended). Touches: the test's in-memory database only.
     */
    // JOBS-04
    test('max_retries = 3 runs the job 4 times, then failed with retry_count = 3', async () => {
        const id = 'four-runs';
        jobManager.db.prepare(`
            INSERT INTO jobs (id, task_type, params, status, created_at, max_retries, retry_count)
            VALUES (?, 'nonexistent_task', '{}', 'enqueued', ?, 3, 0)
        `).run(id, now());
        const runs = () => jobManager.db.prepare('SELECT COUNT(*) AS n FROM job_runs WHERE job_id = ?').get(id).n;
        await jobManager.tick();
        await advanceClock(1000 + 2000 + 4000);
        let job = jobManager.get(id);
        expect(runs()).toBe(4);
        expect(job.status).toBe('failed');
        expect(job.retry_count).toBe(3);
        await advanceClock(20000);
        job = jobManager.get(id);
        expect(runs()).toBe(4);
        expect(job.status).toBe('failed');
        expect(job.retry_count).toBe(3);
    });

    // JOBS-05
    test('User cancels before job starts, status becomes cancelled', async () => {
        const res = await request(app)
            .post('/jobs/enqueue')
            .send({ task_type: 'cleanup_old_sessions', params: { total: 10 }, scheduled_at: new Date(clock + 60000).toISOString() });
        const jobId = res.body.job_id;

        const cancelRes = await request(app).delete(`/jobs/${jobId}`);
        expect(cancelRes.body.success).toBe(true);
        expect(cancelRes.body.status).toBe('cancelled');

        const statusRes = await request(app).get(`/jobs/${jobId}`);
        expect(statusRes.body.status).toBe('cancelled');
    });

    // JOBS-06
    test('Progress tracking updates in real-time', async () => {
        const res = await request(app)
            .post('/jobs/enqueue')
            .send({ task_type: 'send_bulk_email', params: { total: 15 } });
        const jobId = res.body.job_id;
        const updates = [];
        const onProgress = (e) => { if (e.job_id === jobId) updates.push(e.progress); };
        jobManager.on('progress', onProgress);

        // Poll progress a few times
        let progressSeen = false;
        for (let i = 0; i < 5; i++) {
            await advanceClock(800);
            const statusRes = await request(app).get(`/jobs/${jobId}`);
            if (statusRes.body.progress && statusRes.body.progress !== '0/0') {
                progressSeen = true;
                break;
            }
        }
        expect(progressSeen).toBe(true);
        // Progress was published item by item while the job ran, not only at the end.
        jobManager.off('progress', onProgress);
        expect(updates[0]).toBe('1/15');
        expect(updates).toHaveLength(15);
        expect(updates[14]).toBe('15/15');
    });

    // JOBS-07
    test('Scheduled jobs only run after scheduled_at time', async () => {
        const future = new Date(clock + 5000).toISOString();
        const res = await request(app)
            .post('/jobs/enqueue')
            .send({ task_type: 'daily_report', params: {}, scheduled_at: future });
        const jobId = res.body.job_id;

        // Immediately check status (should be enqueued)
        let statusRes = await request(app).get(`/jobs/${jobId}`);
        expect(statusRes.body.status).toBe('enqueued');

        // Wait past scheduled time
        await advanceClock(6000);
        statusRes = await request(app).get(`/jobs/${jobId}`);
        expect(['running', 'completed']).toContain(statusRes.body.status);
    });

    // JOBS-08
    test('Bulk job processes many items without blocking request', async () => {
        const res = await request(app)
            .post('/jobs/enqueue')
            // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: JOBS-08 names 10,000 items; this used 1,000.
            .send({ task_type: 'send_bulk_email', params: { total: 10000 } });
        const jobId = res.body.job_id;

        // Immediately after enqueue, request should have returned
        expect(res.body.success).toBe(true);
        const pending = await request(app).get(`/jobs/${jobId}`);
        expect(pending.body.status).toBe('enqueued');

        // Wait for completion
        await advanceClock(8000);
        const statusRes = await request(app).get(`/jobs/${jobId}`);
        expect(statusRes.body.status).toBe('completed');
        expect(statusRes.body.progress).toBe('10000/10000');
    });

    // JOBS-09
    test('Results available after completion', async () => {
        const res = await request(app)
            .post('/jobs/enqueue')
            .send({ task_type: 'send_bulk_email', params: { total: 10 } });
        const jobId = res.body.job_id;

        await advanceClock(3000);
        const resultsRes = await request(app).get(`/jobs/${jobId}/results`);
        expect(resultsRes.body.status).toBe('completed');
        expect(resultsRes.body.result).toHaveProperty('sent');
        expect(resultsRes.body.result).toHaveProperty('failed');
    });
});

function now() {
    return new Date(clock).toISOString();
}
import { JobStatus } from './background_jobs_task_queue_typescript';

/**
 * Tests for the background job manager, with the database and Redis replaced by shared fakes.
 *
 * Why the fakes are built this way: the implementation opens its connections when the module loads, and these tests
 * reload the module before each test. A plain jest.mock('pg') gives every reload a new mock class, so the fakes set up
 * in beforeEach were never the ones in use. Here each mock is a factory that always hands back the same object.
 * 2026-11-05, session f3daac6e (AIR record finding:2026-11-05:3a00300d16: this suite had been pasted onto the end of the
 * implementation file, and this file stopped in its first test). Touches: memory only.
 */
jest.mock('pg', () => {
  const g = globalThis as any;
  g.__mockDb = g.__mockDb ?? { query: jest.fn(), connect: jest.fn() };
  return { Pool: jest.fn(() => g.__mockDb) };
});
jest.mock('ioredis', () => {
  const g = globalThis as any;
  g.__mockRedis = g.__mockRedis ?? {
    setex: jest.fn(), set: jest.fn(), lpush: jest.fn(), lrange: jest.fn(), lrem: jest.fn(), keys: jest.fn(),
    del: jest.fn(), pipeline: jest.fn(), get: jest.fn(),
  };
  return { __esModule: true, default: jest.fn(() => g.__mockRedis) };
});
jest.mock('uuid', () => ({ v4: jest.fn(() => 'test-uuid-123') }));

const mockDb = (globalThis as any).__mockDb;
const mockRedis = (globalThis as any).__mockRedis;

describe('Background Job Manager', () => {
  let jobManager: any;
  // Each test reloads the module, and each load defines its own error class: compare against this load's (from review).
  let BackgroundJobError: any;
  
  beforeEach(() => {
    for (const fake of [...Object.values(mockDb), ...Object.values(mockRedis)]) {
      (fake as jest.Mock).mockReset();
    }

    const loaded = require('./background_jobs_task_queue_typescript');
    BackgroundJobError = loaded.BackgroundJobError;
    jobManager = loaded.JobManager.getInstance();
    jobManager.workerRunning = false;
  });

  afterEach(() => {
    // Stop a worker a test started before the module is reloaded, or its loop keeps the test run open (from review).
    jobManager.workerRunning = false;
    jest.resetModules();
  });
  
  describe('initialize', () => {
    it('should setup database and start worker', async () => {
      mockDb.query.mockResolvedValue({ rows: [] });
      
      await jobManager.initialize();
      
      expect(mockDb.query).toHaveBeenCalledWith(
        expect.stringContaining('CREATE TABLE IF NOT EXISTS jobs')
      );
      expect(mockDb.query).toHaveBeenCalledWith(
        expect.stringContaining('CREATE TABLE IF NOT EXISTS job_runs')
      );
    });
  });
  
  describe('enqueueJob', () => {
    it('should enqueue a job successfully', async () => {
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'send_bulk_email',
        params: { template_key: 'trial_ending_soon' },
        status: JobStatus.ENQUEUED,
        created_at: new Date(),
        scheduled_at: null,
        max_retries: 3,
        retry_count: 0,
        next_retry_at: null
      };
      
      mockDb.query.mockResolvedValue({ rows: [mockJob] });
      
      const result = await jobManager.enqueueJob('send_bulk_email', { template_key: 'trial_ending_soon' });
      
      expect(result).toEqual({
        success: true,
        job_id: 'test-uuid-123',
        status: JobStatus.ENQUEUED
      });
      expect(mockDb.query).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO jobs'),
        expect.any(Array)
      );
    });
    
    // JOBS-07
    it('should schedule a job for future execution', async () => {
      const scheduledAt = new Date(Date.now() + 3600000);
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'send_bulk_email',
        params: { template_key: 'trial_ending_soon' },
        status: JobStatus.ENQUEUED,
        created_at: new Date(),
        scheduled_at: scheduledAt,
        max_retries: 3,
        retry_count: 0,
        next_retry_at: null
      };
      
      mockDb.query.mockResolvedValue({ rows: [mockJob] });
      mockRedis.set.mockResolvedValue('OK');
      
      await jobManager.enqueueJob('send_bulk_email', { template_key: 'trial_ending_soon' }, scheduledAt);
      
      // Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the worker reads this key as the run time in epoch
      // milliseconds, so that is what must be stored (no TTL). The old assertion expected setex(key, seconds, jobId),
      // which the worker parses as a time that is never due, so the scheduled job never ran.
      expect(mockRedis.set).toHaveBeenCalledWith(
        'job:scheduled:test-uuid-123',
        String(scheduledAt.getTime())
      );
      expect(mockRedis.lpush).not.toHaveBeenCalledWith('job:queue', 'test-uuid-123');
    });
  });
  
  describe('getJobStatus', () => {
    it('should return job status', async () => {
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'send_bulk_email',
        params: { template_key: 'trial_ending_soon' },
        status: JobStatus.RUNNING,
        created_at: new Date(),
        started_at: new Date(),
        completed_at: null,
        progress: '50/100',
        result: null,
        error: null,
        retry_count: 0,
        max_retries: 3,
        next_retry_at: null,
        scheduled_at: null
      };
      
      mockDb.query.mockResolvedValue({ rows: [mockJob] });
      
      const result = await jobManager.getJobStatus('test-uuid-123');
      
      expect(result).toEqual({
        job_id: 'test-uuid-123',
        task_type: 'send_bulk_email',
        status: JobStatus.RUNNING,
        progress: '50/100',
        created_at: mockJob.created_at,
        started_at: mockJob.started_at,
        result: null,
        next_retry_at: null
      });
    });
    
    it('should throw error if job not found', async () => {
      mockDb.query.mockResolvedValue({ rows: [] });
      
      await expect(jobManager.getJobStatus('non-existent')).rejects.toThrow(BackgroundJobError);
      await expect(jobManager.getJobStatus('non-existent')).rejects.toThrow('Job not found');
    });
  });
  
  describe('listJobs', () => {
    it('should list jobs with filters', async () => {
      const mockJobs = [
        {
          id: 'test-uuid-1',
          task_type: 'send_bulk_email',
          params: {},
          status: JobStatus.COMPLETED,
          created_at: new Date(),
          started_at: new Date(),
          completed_at: new Date(),
          progress: '100/100',
          result: { sent: 100 },
          error: null,
          retry_count: 0,
          max_retries: 3,
          next_retry_at: null,
          scheduled_at: null
        },
        {
          id: 'test-uuid-2',
          task_type: 'send_bulk_email',
          params: {},
          status: JobStatus.RUNNING,
          created_at: new Date(),
          started_at: new Date(),
          completed_at: null,
          progress: '50/100',
          result: null,
          error: null,
          retry_count: 0,
          max_retries: 3,
          next_retry_at: null,
          scheduled_at: null
        }
      ];
      
      const mockCount = { rows: [{ count: '2' }] };
      
      mockDb.query
        .mockResolvedValueOnce({ rows: mockJobs })
        .mockResolvedValueOnce(mockCount);
      
      const result = await jobManager.listJobs(JobStatus.RUNNING, 'send_bulk_email', 10);
      
      expect(result.jobs).toHaveLength(2);
      expect(result.total).toBe(2);
      expect(mockDb.query).toHaveBeenCalledTimes(2);
    });
  });
  
  describe('cancelJob', () => {
    // JOBS-05
    it('should cancel a pending job', async () => {
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'send_bulk_email',
        params: {},
        status: JobStatus.ENQUEUED,
        created_at: new Date(),
        started_at: null,
        completed_at: null,
        progress: null,
        result: null,
        error: null,
        retry_count: 0,
        max_retries: 3,
        next_retry_at: null,
        scheduled_at: null
      };
      
      mockDb.query.mockResolvedValue({ rows: [mockJob] });
      
      const result = await jobManager.cancelJob('test-uuid-123');
      
      expect(result).toEqual({
        success: true,
        status: JobStatus.CANCELLED
      });
      expect(mockRedis.lrem).toHaveBeenCalledWith('job:queue', 0, 'test-uuid-123');
    });
    
    it('should not cancel a running job', async () => {
      
      mockDb.query.mockResolvedValue({ rows: [] });
      
      await expect(jobManager.cancelJob('test-uuid-123')).rejects.toThrow(BackgroundJobError);
      await expect(jobManager.cancelJob('test-uuid-123')).rejects.toThrow('Cannot cancel job');
    });
  });
  
  describe('retryJob', () => {
    it('should retry a failed job', async () => {
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'send_bulk_email',
        params: { template_key: 'trial_ending_soon' },
        status: JobStatus.FAILED,
        created_at: new Date(),
        started_at: new Date(),
        completed_at: new Date(),
        progress: null,
        result: null,
        error: 'Something went wrong',
        retry_count: 3,
        max_retries: 5,
        next_retry_at: null,
        scheduled_at: null
      };
      
      const mockNewJob = {
        ...mockJob,
        id: 'test-uuid-456',
        status: JobStatus.ENQUEUED,
        retry_count: 0,
        next_retry_at: null
      };
      
      mockDb.query
        .mockResolvedValueOnce({ rows: [mockJob] })
        .mockResolvedValueOnce({ rows: [mockNewJob] });
      
      // The replacement job gets its own id; it must never reuse the failed job's (from review).
      require('uuid').v4.mockReturnValueOnce('test-uuid-456');
      const result = await jobManager.retryJob('test-uuid-123');
      
      expect(result).toEqual({
        success: true,
        new_job_id: 'test-uuid-456',
        status: JobStatus.ENQUEUED
      });
      expect(mockRedis.lpush).toHaveBeenCalledWith('job:queue', 'test-uuid-456');
    });
    
    it('should not retry a non-failed job', async () => {
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'send_bulk_email',
        params: {},
        status: JobStatus.COMPLETED,
        created_at: new Date(),
        started_at: new Date(),
        completed_at: new Date(),
        progress: '100/100',
        result: { sent: 100 },
        error: null,
        retry_count: 0,
        max_retries: 3,
        next_retry_at: null,
        scheduled_at: null
      };
      
      mockDb.query.mockResolvedValue({ rows: [mockJob] });
      
      await expect(jobManager.retryJob('test-uuid-123')).rejects.toThrow(BackgroundJobError);
      await expect(jobManager.retryJob('test-uuid-123')).rejects.toThrow('Can only retry failed jobs');
    });
  });
  
  describe('getJobResults', () => {
    // JOBS-09
    it('should return results for completed job', async () => {
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'send_bulk_email',
        params: {},
        status: JobStatus.COMPLETED,
        created_at: new Date(),
        started_at: new Date(),
        completed_at: new Date(),
        progress: '100/100',
        result: { sent: 100, failed: 0 },
        error: null,
        retry_count: 0,
        max_retries: 3,
        next_retry_at: null,
        scheduled_at: null
      };
      
      mockDb.query.mockResolvedValue({ rows: [mockJob] });
      
      const result = await jobManager.getJobResults('test-uuid-123');
      
      expect(result).toEqual({
        job_id: 'test-uuid-123',
        status: JobStatus.COMPLETED,
        result: { sent: 100, failed: 0 },
        completed_at: mockJob.completed_at
      });
    });
    
    it('should not return results for non-completed job', async () => {
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'send_bulk_email',
        params: {},
        status: JobStatus.RUNNING,
        created_at: new Date(),
        started_at: new Date(),
        completed_at: null,
        progress: '50/100',
        result: null,
        error: null,
        retry_count: 0,
        max_retries: 3,
        next_retry_at: null,
        scheduled_at: null
      };
      
      mockDb.query.mockResolvedValue({ rows: [mockJob] });
      
      await expect(jobManager.getJobResults('test-uuid-123')).rejects.toThrow(BackgroundJobError);
      await expect(jobManager.getJobResults('test-uuid-123')).rejects.toThrow('Results only available for completed jobs');
    });
  });
  
  describe('processJob', () => {
    // JOBS-01
    // JOBS-02
    it('should process a job successfully', async () => {
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'send_bulk_email',
        params: { template_key: 'trial_ending_soon' },
        status: JobStatus.ENQUEUED,
        created_at: new Date(),
        started_at: null,
        completed_at: null,
        progress: null,
        result: null,
        error: null,
        retry_count: 0,
        max_retries: 3,
        next_retry_at: null,
        scheduled_at: null
      };
      
      const mockJobRun = {
        id: 'test-uuid-123',
        job_id: 'test-uuid-123',
        status: 'running',
        started_at: new Date(),
        completed_at: null,
        result: null
      };
      
      const mockCount = { rows: [{ count: '100' }] };
      const mockBatch = { rows: [{ id: 'user-1' }, { id: 'user-2' }] };
      
      const mockClient = {
        query: jest.fn()
          .mockResolvedValueOnce({ rows: [] })   // BEGIN
          .mockResolvedValueOnce({ rows: [mockJob] })
          .mockResolvedValueOnce({ rows: [] })
          .mockResolvedValueOnce({ rows: [mockJobRun] })
          .mockResolvedValueOnce({ rows: [] })
          .mockResolvedValueOnce({ rows: [] })
          .mockResolvedValueOnce({ rows: [] })
          .mockResolvedValueOnce({ rows: [] }),
        release: jest.fn(),
      };
      
      mockDb.connect.mockResolvedValue(mockClient as any);
      // The task itself reads through db.query, not the transaction's client (from review).
      mockDb.query.mockResolvedValueOnce(mockCount).mockResolvedValueOnce(mockBatch).mockResolvedValue({ rows: [] });
      
      await jobManager.processJob('test-uuid-123');
      
      expect(mockClient.query).toHaveBeenCalledWith(
        'BEGIN'
      );
      expect(mockClient.query).toHaveBeenCalledWith(
        'SELECT * FROM jobs WHERE id = $1 FOR UPDATE',
        ['test-uuid-123']
      );
      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: added checks so this test proves JOBS-01 and JOBS-02: the worker
      // moved the job to running, then to completed with its result stored.
      const calls = mockClient.query.mock.calls;
      const running = calls.find((c: any[]) => String(c[0]).startsWith('UPDATE jobs SET status = $1, started_at'));
      expect(running[1][0]).toBe(JobStatus.RUNNING);
      const done = calls.find((c: any[]) => String(c[0]).startsWith('UPDATE jobs SET status = $1, completed_at = $2, result'));
      expect(done[1][0]).toBe(JobStatus.COMPLETED);
      expect(JSON.parse(done[1][2])).toEqual({ sent: 2, failed: 0, template_key: 'trial_ending_soon' });
    });

    /**
     * A job that is gone or no longer 'enqueued' must end its transaction (ROLLBACK) before the client goes back to
     * the pool, and must not be run. In: a fake client. Out: assertions only.
     * Why 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): CodeRabbit review on PR 19 (early returns left the
     * row-locking transaction open). Touches: memory only.
     */
    it.each([
      ['the job does not exist', []],
      ['the job is no longer enqueued', [{ id: 'test-uuid-123', task_type: 'send_bulk_email', params: {},
        status: JobStatus.RUNNING, retry_count: 0, max_retries: 3, next_retry_at: null, scheduled_at: null }]],
    ])('should roll back and release when %s', async (_label: string, rows: any[]) => {
      const mockClient = {
        query: jest.fn()
          .mockResolvedValueOnce({ rows: [] })   // BEGIN
          .mockResolvedValueOnce({ rows })       // SELECT ... FOR UPDATE
          .mockResolvedValue({ rows: [] }),
        release: jest.fn(),
      };
      mockDb.connect.mockResolvedValue(mockClient as any);

      await jobManager.processJob('test-uuid-123');

      const statements = mockClient.query.mock.calls.map((call: any[]) => call[0]);
      expect(statements).toEqual(['BEGIN', 'SELECT * FROM jobs WHERE id = $1 FOR UPDATE', 'ROLLBACK']);
      expect(mockClient.release).toHaveBeenCalledTimes(1);
      expect(mockDb.query).not.toHaveBeenCalled();
    });

    /**
     * A retry whose next_retry_at is still in the future is not run: the transaction is rolled back, no job_run is
     * written, the task does not execute, and the job is put back on the delayed path for its next_retry_at.
     * In: a fake client. Out: assertions only.
     * Why 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): CodeRabbit review on PR 19 (retries ignored the
     * backoff). Touches: memory only.
     */
    it('should not execute a job whose next_retry_at is in the future', async () => {
      const nextRetryAt = new Date(Date.now() + 60000);
      const mockJob = {
        id: 'test-uuid-123', task_type: 'send_bulk_email', params: { template_key: 'trial_ending_soon' },
        status: JobStatus.ENQUEUED, created_at: new Date(), started_at: null, completed_at: null, progress: null,
        result: null, error: 'boom', retry_count: 1, max_retries: 3, next_retry_at: nextRetryAt, scheduled_at: null
      };
      const mockClient = {
        query: jest.fn()
          .mockResolvedValueOnce({ rows: [] })        // BEGIN
          .mockResolvedValueOnce({ rows: [mockJob] }) // SELECT ... FOR UPDATE
          .mockResolvedValue({ rows: [] }),
        release: jest.fn(),
      };
      mockDb.connect.mockResolvedValue(mockClient as any);

      await jobManager.processJob('test-uuid-123');

      const statements = mockClient.query.mock.calls.map((call: any[]) => call[0]);
      expect(statements).toEqual(['BEGIN', 'SELECT * FROM jobs WHERE id = $1 FOR UPDATE', 'ROLLBACK']);
      expect(statements.some((sql: string) => sql.includes('INSERT INTO job_runs'))).toBe(false);
      expect(mockDb.query).not.toHaveBeenCalled();
      expect(mockRedis.lpush).not.toHaveBeenCalled();
      expect(mockRedis.set).toHaveBeenCalledWith('job:scheduled:test-uuid-123', String(nextRetryAt.getTime()));
      expect(mockClient.release).toHaveBeenCalledTimes(1);
    });
  });
  
  describe('handleJobError', () => {
    it('should handle job error and retry', async () => {
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'send_bulk_email',
        params: {},
        status: JobStatus.ENQUEUED,
        created_at: new Date(),
        started_at: null,
        completed_at: null,
        progress: null,
        result: null,
        error: null,
        retry_count: 0,
        max_retries: 3,
        next_retry_at: null,
        scheduled_at: null
      };
      
      const mockClient = {
        query: jest.fn()
          .mockResolvedValueOnce({ rows: [] })   // BEGIN
          .mockResolvedValueOnce({ rows: [mockJob] })
          .mockResolvedValueOnce({ rows: [] })
          .mockResolvedValueOnce({ rows: [] }),
        release: jest.fn(),
      };
      
      mockDb.connect.mockResolvedValue(mockClient as any);
      
      await jobManager.handleJobError('test-uuid-123', new Error('Test error'));
      
      expect(mockClient.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE jobs SET'),
        expect.any(Array)
      );
    });

    /**
     * A retry goes through the delayed path at its backoff time (1 s for the first retry), not straight onto
     * job:queue. In: a fake client. Out: assertions only.
     * Why 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): CodeRabbit review on PR 19 (the documented 1 s, 2 s,
     * 4 s backoff never happened). Touches: memory only.
     */
    // JOBS-03
    it('should schedule the retry after its backoff instead of queueing it now', async () => {
      const mockJob = {
        id: 'test-uuid-123', task_type: 'send_bulk_email', params: {}, status: JobStatus.RUNNING,
        retry_count: 0, max_retries: 3, next_retry_at: null, scheduled_at: null
      };
      const mockClient = {
        query: jest.fn()
          .mockResolvedValueOnce({ rows: [] })        // BEGIN
          .mockResolvedValueOnce({ rows: [mockJob] }) // SELECT ... FOR UPDATE
          .mockResolvedValue({ rows: [] }),
        release: jest.fn(),
      };
      mockDb.connect.mockResolvedValue(mockClient as any);
      const before = Date.now();

      await jobManager.handleJobError('test-uuid-123', new Error('Test error'));

      expect(mockRedis.lpush).not.toHaveBeenCalled();
      expect(mockRedis.set).toHaveBeenCalledTimes(1);
      const [key, runAt] = mockRedis.set.mock.calls[0];
      expect(key).toBe('job:scheduled:test-uuid-123');
      expect(Number(runAt)).toBeGreaterThanOrEqual(before + 1000);
      const update = mockClient.query.mock.calls.find((call: any[]) => String(call[0]).startsWith('UPDATE jobs SET'));
      expect((update[1][3] as Date).getTime()).toBe(Number(runAt));
    });
    
    // JOBS-04
    it('should mark job as failed after max retries exceeded', async () => {
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'send_bulk_email',
        params: {},
        status: JobStatus.ENQUEUED,
        created_at: new Date(),
        started_at: null,
        completed_at: null,
        progress: null,
        result: null,
        error: null,
        retry_count: 5,
        max_retries: 3,
        next_retry_at: null,
        scheduled_at: null
      };
      
      const mockClient = {
        query: jest.fn()
          .mockResolvedValueOnce({ rows: [] })   // BEGIN
          .mockResolvedValueOnce({ rows: [mockJob] })
          .mockResolvedValueOnce({ rows: [] })
          .mockResolvedValueOnce({ rows: [] }),
        release: jest.fn(),
      };
      
      mockDb.connect.mockResolvedValue(mockClient as any);
      
      await jobManager.handleJobError('test-uuid-123', new Error('Test error'));
      
      expect(mockClient.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE jobs SET status = $1'),
        expect.any(Array)
      );
      expect(mockClient.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE job_runs SET status = $1'),
        expect.any(Array)
      );
    });
  });
  
  /**
   * JOBS-03 / JOBS-04 on an injected clock: a job with max_retries = 3 fails every time. Each failure is fed back
   * through handleJobError with the row as the previous step left it. Retry n waits 2^(n-1) s from the failure
   * (1 s, 2 s, 4 s) with status 'enqueued' and retry_count = n; the 4th failure (the 4th run) makes it 'failed'
   * with retry_count = 3. In: fake database client and Redis. Out: assertions only.
   * Why: JOBS-03/04 amendment 2026-11-10 (the job used to end with retry_count = 4). 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
   */
  describe('retry schedule (JOBS-03, JOBS-04)', () => {
    // JOBS-03
    // JOBS-04
    it('max_retries = 3: retries after 1 s, 2 s, 4 s, then failed with retry_count 3 after 4 runs', async () => {
      const t0 = Date.parse('2026-06-15T10:00:00Z');
      let nowMs = t0;
      jobManager.setClock(() => new Date(nowMs));
      const row: any = { id: 'job-r', task_type: 'send_bulk_email', params: {}, status: JobStatus.RUNNING,
        retry_count: 0, max_retries: 3, next_retry_at: null, scheduled_at: null };
      let runs = 0;
      const waits: number[] = [];
      for (;;) {
        runs++;                                    // an attempt runs and fails
        const client = {
          query: jest.fn().mockImplementation((sql: string, params: any[]) => {
            if (sql.startsWith('SELECT * FROM jobs')) return Promise.resolve({ rows: [{ ...row }] });
            if (sql.startsWith('UPDATE jobs SET status = $1, error = $2, retry_count = $3, next_retry_at = $4')) {
              Object.assign(row, { status: params[0], retry_count: params[2], next_retry_at: params[3] });
            } else if (sql.startsWith('UPDATE jobs SET status = $1, error = $2, completed_at = $3, retry_count = $4')) {
              Object.assign(row, { status: params[0], retry_count: params[3] });
            }
            return Promise.resolve({ rows: [] });
          }),
          release: jest.fn(),
        };
        mockDb.connect.mockResolvedValue(client as any);
        await jobManager.handleJobError('job-r', new Error('boom'));
        if (row.status === JobStatus.FAILED) break;
        expect(row.status).toBe(JobStatus.ENQUEUED);
        expect(row.retry_count).toBe(waits.length + 1);
        waits.push(row.next_retry_at.getTime() - nowMs);
        nowMs = row.next_retry_at.getTime();       // the worker picks it up once next_retry_at has passed
        row.status = JobStatus.RUNNING;
        if (runs > 10) throw new Error('never failed');
      }
      expect(waits).toEqual([1000, 2000, 4000]);
      expect(runs).toBe(4);
      expect(row.status).toBe(JobStatus.FAILED);
      expect(row.retry_count).toBe(3);
      expect(mockRedis.set.mock.calls.map((c: any[]) => Number(c[1]))).toEqual([t0 + 1000, t0 + 3000, t0 + 7000]);
    });

    it('retry n waits 2^(n-1) seconds with no cap', () => {
      const { JobManager } = require('./background_jobs_task_queue_typescript');
      expect([1, 2, 3, 4, 10].map((n: number) => JobManager.retryDelayMs(n))).toEqual([1000, 2000, 4000, 8000, 512000]);
    });
  });

  /**
   * JOBS-06 / JOBS-08: a bulk e-mail to 10,000 users runs through the worker's task code, paging 100 at a time and
   * writing progress after every user (so "45/100"-style progress is visible while it runs), and enqueueing it
   * only queues it: the request returns before any e-mail is sent. In: a fake database answering by SQL text.
   * Out: assertions only. Why: JOBS-06 and JOBS-08 had no test. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: memory only.
   */
  describe('bulk work (JOBS-06, JOBS-08)', () => {
    function fakeUsers(total: number) {
      const progress: string[] = [];
      let sent = 0;
      mockDb.query.mockImplementation((sql: string, params: any[] = []) => {
        if (sql.startsWith('SELECT COUNT(*) FROM users')) return Promise.resolve({ rows: [{ count: String(total) }] });
        if (sql.startsWith('SELECT id FROM users')) {
          const [, limit, offset] = params;
          const n = Math.max(0, Math.min(limit, total - offset));
          return Promise.resolve({ rows: Array.from({ length: n }, (_, i) => ({ id: `user-${offset + i}` })) });
        }
        if (sql.startsWith('INSERT INTO notifications')) sent++;
        if (sql.startsWith('UPDATE jobs SET progress')) progress.push(params[0]);
        if (sql.includes('INSERT INTO jobs')) return Promise.resolve({ rows: [{ status: JobStatus.ENQUEUED }] });
        return Promise.resolve({ rows: [] });
      });
      return { progress, sentCount: () => sent };
    }

    // JOBS-06
    it('progress is written as the job runs (45/100 along the way)', async () => {
      const fake = fakeUsers(100);
      const result = await jobManager.executeJob({ id: 'job-p', task_type: 'send_bulk_email', params: { template_key: 't' } });
      expect(fake.progress).toContain('45/100');
      expect(fake.progress.indexOf('45/100')).toBeLessThan(fake.progress.indexOf('100/100'));
      expect(fake.progress[fake.progress.length - 1]).toBe('100/100');
      expect(result.sent).toBe(100);
    });

    // JOBS-08
    it('10,000 items: enqueue returns at once, and the worker task processes all of them', async () => {
      const fake = fakeUsers(10000);
      const queued = await jobManager.enqueueJob('send_bulk_email', { template_key: 't' });
      expect(queued).toEqual({ success: true, job_id: 'test-uuid-123', status: JobStatus.ENQUEUED });
      expect(mockRedis.lpush).toHaveBeenCalledWith('job:queue', 'test-uuid-123');
      expect(fake.sentCount()).toBe(0);           // the request did not do the work

      const result = await jobManager.executeJob({ id: 'test-uuid-123', task_type: 'send_bulk_email', params: { template_key: 't' } });
      expect(result.sent).toBe(10000);
      expect(fake.sentCount()).toBe(10000);
      expect(fake.progress[fake.progress.length - 1]).toBe('10000/10000');
    });
  });

  /**
   * JOBS-07: the worker moves a scheduled job onto the queue only once its run time has passed on the injected
   * clock. In: two scheduled keys, one due and one in the future. Out: assertions only. Why: JOBS-07 needs the
   * worker side as well as the enqueue side. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
   */
  // JOBS-07
  it('the worker queues a scheduled job only after its scheduled time', async () => {
    const now = Date.parse('2026-06-15T10:00:00Z');
    jobManager.setClock(() => new Date(now));
    mockRedis.lrange.mockResolvedValue([]);
    const pipeline: any = { exec: jest.fn().mockResolvedValue([]) };
    pipeline.lrem = jest.fn().mockReturnValue(pipeline);
    mockRedis.pipeline.mockReturnValue(pipeline);
    mockRedis.keys.mockResolvedValue(['job:scheduled:due', 'job:scheduled:later']);
    mockRedis.get.mockImplementation((key: string) =>
      Promise.resolve(key === 'job:scheduled:due' ? String(now - 1) : String(now + 60000)));

    await jobManager.processJobs();

    expect(mockRedis.lpush).toHaveBeenCalledTimes(1);
    expect(mockRedis.lpush).toHaveBeenCalledWith('job:queue', 'due');
    expect(mockRedis.del).toHaveBeenCalledWith('job:scheduled:due');
    expect(mockRedis.del).not.toHaveBeenCalledWith('job:scheduled:later');
  });

  describe('executeJob', () => {
    it('should execute send_bulk_email task', async () => {
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'send_bulk_email',
        params: { template_key: 'trial_ending_soon' },
        status: JobStatus.ENQUEUED,
        created_at: new Date(),
        started_at: null,
        completed_at: null,
        progress: null,
        result: null,
        error: null,
        retry_count: 0,
        max_retries: 3,
        next_retry_at: null,
        scheduled_at: null
      };
      
      const mockCount = { rows: [{ count: '100' }] };
      const mockBatch = { rows: [{ id: 'user-1' }, { id: 'user-2' }] };
      
      mockDb.query
        .mockResolvedValueOnce(mockCount)
        .mockResolvedValueOnce(mockBatch)
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [] });
      
      const result = await jobManager.executeJob(mockJob);
      
      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the fake database returns two users, so two e-mails are sent;
      // `sent` used to echo COUNT(*) (100) whatever was actually sent.
      expect(result).toEqual({
        sent: 2,
        failed: 0,
        template_key: 'trial_ending_soon'
      });
    });
    
    it('should execute webhook_retry task', async () => {
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'webhook_retry',
        params: { webhook_id: 'webhook-123' },
        status: JobStatus.ENQUEUED,
        created_at: new Date(),
        started_at: null,
        completed_at: null,
        progress: null,
        result: null,
        error: null,
        retry_count: 0,
        max_retries: 3,
        next_retry_at: null,
        scheduled_at: null
      };
      
      const mockWebhook = {
        id: 'webhook-123',
        max_retries: 3
      };
      
      const mockAttempt = {
        id: 'attempt-123',
        retry_count: 1
      };
      
      mockDb.query
        .mockResolvedValueOnce({ rows: [mockWebhook] })
        .mockResolvedValueOnce({ rows: [mockAttempt] })
        .mockResolvedValueOnce({ rows: [] });
      
      const result = await jobManager.executeJob(mockJob);
      
      expect(result).toHaveProperty('webhook_id', 'webhook-123');
      expect(result).toHaveProperty('status', 'queued');
    });
    
    it('should execute export_generate task', async () => {
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'export_generate',
        params: { export_type: 'users' },
        status: JobStatus.ENQUEUED,
        created_at: new Date(),
        started_at: null,
        completed_at: null,
        progress: null,
        result: null,
        error: null,
        retry_count: 0,
        max_retries: 3,
        next_retry_at: null,
        scheduled_at: null
      };
      
      const mockCount = { rows: [{ count: '50' }] };
      const mockBatch = { rows: [{ id: 'user-1' }, { id: 'user-2' }] };
      const mockExport = {
        id: 'test-uuid-123',
        type: 'users',
        status: 'processing',
        created_at: new Date(),
        filters: {},
        user_id: 'user-123'
      };
      
      // exportGenerate stores the export row before it counts the records (from review).
      mockDb.query
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce(mockCount)
        .mockResolvedValueOnce(mockBatch)
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [mockExport] });
      
      const result = await jobManager.executeJob(mockJob);
      
      expect(result).toHaveProperty('export_id', 'test-uuid-123');
      expect(result).toHaveProperty('type', 'users');
      expect(result).toHaveProperty('total_records', 50);
    });
    
    it('should execute daily_report task', async () => {
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'daily_report',
        params: { report_date: '2026-09-25' },
        status: JobStatus.ENQUEUED,
        created_at: new Date(),
        started_at: null,
        completed_at: null,
        progress: null,
        result: null,
        error: null,
        retry_count: 0,
        max_retries: 3,
        next_retry_at: null,
        scheduled_at: null
      };
      
      const mockMetrics = {
        total_users: 100,
        active_users: 75,
        total_revenue: 5000.00,
        new_signups: 10
      };
      
      const mockReport = {
        id: 'report-123',
        date: new Date('2026-09-25'),
        total_users: 100,
        active_users: 75,
        total_revenue: 5000.00,
        new_signups: 10,
        status: 'completed',
        data: JSON.stringify(mockMetrics)
      };
      
      // calculateDailyMetrics runs four queries before the report is stored (from review).
      mockDb.query
        .mockResolvedValueOnce({ rows: [{ count: '100' }] })
        .mockResolvedValueOnce({ rows: [{ coalesce: '5000' }] })
        .mockResolvedValueOnce({ rows: [{ count: '10' }] })
        .mockResolvedValueOnce({ rows: [{ count: '75' }] })
        .mockResolvedValueOnce({ rows: [mockReport] });
      
      const result = await jobManager.executeJob(mockJob);
      
      expect(result).toHaveProperty('report_date', '2026-09-25');
      expect(result.metrics).toEqual(mockMetrics);
    });
    
    it('should execute cleanup_old_sessions task', async () => {
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'cleanup_old_sessions',
        params: { days_old: 30 },
        status: JobStatus.ENQUEUED,
        created_at: new Date(),
        started_at: null,
        completed_at: null,
        progress: null,
        result: null,
        error: null,
        retry_count: 0,
        max_retries: 3,
        next_retry_at: null,
        scheduled_at: null
      };
      
      const mockSessions = [
        { user_id: 'user-1' },
        { user_id: 'user-2' }
      ];
      
      mockDb.query
        .mockResolvedValueOnce({ rows: mockSessions })
        .mockResolvedValueOnce({ rows: [] });
      
      const result = await jobManager.executeJob(mockJob);
      
      expect(result).toHaveProperty('sessions_cleaned', 2);
      expect(result).toHaveProperty('cutoff_date');
    });
    
    it('should execute delete_user_cascade task', async () => {
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'delete_user_cascade',
        params: { user_id: 'user-123' },
        status: JobStatus.ENQUEUED,
        created_at: new Date(),
        started_at: null,
        completed_at: null,
        progress: null,
        result: null,
        error: null,
        retry_count: 0,
        max_retries: 3,
        next_retry_at: null,
        scheduled_at: null
      };
      
      const mockClient = {
        query: jest.fn()
          .mockResolvedValueOnce({ rows: [] })
          .mockResolvedValueOnce({ rows: [] })
          .mockResolvedValueOnce({ rows: [] })
          .mockResolvedValueOnce({ rows: [] })
          .mockResolvedValueOnce({ rows: [] })
          .mockResolvedValueOnce({ rows: [] })
          .mockResolvedValueOnce({ rows: [] }),
        release: jest.fn(),
      };
      
      mockDb.connect.mockResolvedValue(mockClient as any);
      
      const result = await jobManager.executeJob(mockJob);
      
      expect(result).toHaveProperty('user_id', 'user-123');
      expect(result).toHaveProperty('deleted_at');
      expect(result).toHaveProperty('items_deleted', 4);
    });
    
    it('should execute sync_stripe_invoices task', async () => {
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'sync_stripe_invoices',
        params: { days_back: 7 },
        status: JobStatus.ENQUEUED,
        created_at: new Date(),
        started_at: null,
        completed_at: null,
        progress: null,
        result: null,
        error: null,
        retry_count: 0,
        max_retries: 3,
        next_retry_at: null,
        scheduled_at: null
      };
      
      const mockInvoices = [
        { id: 'invoice-1' },
        { id: 'invoice-2' }
      ];
      
      mockDb.query
        .mockResolvedValueOnce({ rows: mockInvoices })
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [] });
      // Syncing means asking Stripe for each invoice; Stripe is faked here so the test makes no network call
      // (2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the task used to re-read its own table instead).
      const retrieveInvoice = jest.fn(async (id: string) => ({ id, status: 'paid', amount_paid: 1000, amount_due: 0 }));
      jobManager.setStripeInvoiceGateway({ retrieveInvoice });
      
      const result = await jobManager.executeJob(mockJob);
      
      expect(result).toHaveProperty('invoices_processed', 2);
      expect(result).toHaveProperty('total_invoices', 2);
      expect(retrieveInvoice).toHaveBeenCalledWith('invoice-1');
      expect(retrieveInvoice).toHaveBeenCalledWith('invoice-2');
    });
    
    it('should execute generate_deployment_archive task', async () => {
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'generate_deployment_archive',
        params: { environment: 'production', services: ['web', 'api'] },
        status: JobStatus.ENQUEUED,
        created_at: new Date(),
        started_at: null,
        completed_at: null,
        progress: null,
        result: null,
        error: null,
        retry_count: 0,
        max_retries: 3,
        next_retry_at: null,
        scheduled_at: null
      };
      
      const mockDeployments = [
        { id: 'deploy-1', environment: 'production', service_name: 'web' },
        { id: 'deploy-2', environment: 'production', service_name: 'api' }
      ];
      
      const mockArchive = {
        id: 'test-uuid-123',
        environment: 'production',
        services: JSON.stringify(['web', 'api']),
        status: 'creating',
        created_at: new Date(),
        user_id: 'user-123'
      };
      
      mockDb.query
        .mockResolvedValueOnce({ rows: mockDeployments })
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [mockArchive] });
      
      const result = await jobManager.executeJob(mockJob);
      
      expect(result).toHaveProperty('archive_id', 'test-uuid-123');
      expect(result).toHaveProperty('environment', 'production');
      expect(result).toHaveProperty('services', ['web', 'api']);
      expect(result).toHaveProperty('deployments_count', 2);
    });
    
    it('should throw error for unknown task type', async () => {
      const mockJob = {
        id: 'test-uuid-123',
        task_type: 'unknown_task',
        params: {},
        status: JobStatus.ENQUEUED,
        created_at: new Date(),
        started_at: null,
        completed_at: null,
        progress: null,
        result: null,
        error: null,
        retry_count: 0,
        max_retries: 3,
        next_retry_at: null,
        scheduled_at: null
      };
      
      await expect(jobManager.executeJob(mockJob)).rejects.toThrow(BackgroundJobError);
      await expect(jobManager.executeJob(mockJob)).rejects.toThrow('Unknown task type: unknown_task');
    });
  });
  
  describe('worker process', () => {
    it('should process jobs from queue', async () => {
      mockRedis.lrange.mockResolvedValue(['job-1', 'job-2']);
      mockRedis.keys.mockResolvedValue([]);
      // processJobs removes the jobs through a pipeline, then processes each with a database client (from review).
      const pipeline: any = { exec: jest.fn().mockResolvedValue([]) };
      pipeline.lrem = jest.fn().mockReturnValue(pipeline);
      mockRedis.pipeline.mockReturnValue(pipeline);
      mockDb.connect.mockResolvedValue({ query: jest.fn().mockResolvedValue({ rows: [] }), release: jest.fn() });

      await jobManager.processJobs();

      expect(mockRedis.lrange).toHaveBeenCalledWith('job:queue', 0, 9);
      expect(pipeline.lrem).toHaveBeenCalledTimes(2);
    });
  });
  
  describe('API functions', () => {
    it('should export API functions', async () => {
      const { enqueueJob, getJobStatus, listJobs, cancelJob, retryJob, getJobResults, initializeJobManager } = 
        require('./background_jobs_task_queue_typescript');
      
      expect(typeof enqueueJob).toBe('function');
      expect(typeof getJobStatus).toBe('function');
      expect(typeof listJobs).toBe('function');
      expect(typeof cancelJob).toBe('function');
      expect(typeof retryJob).toBe('function');
      expect(typeof getJobResults).toBe('function');
      expect(typeof initializeJobManager).toBe('function');
    });
  });
});

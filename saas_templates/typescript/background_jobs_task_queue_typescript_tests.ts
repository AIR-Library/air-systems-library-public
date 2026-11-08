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
    setex: jest.fn(), lpush: jest.fn(), lrange: jest.fn(), lrem: jest.fn(), keys: jest.fn(), del: jest.fn(),
    pipeline: jest.fn(),
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
      mockRedis.setex.mockResolvedValue('OK');
      
      await jobManager.enqueueJob('send_bulk_email', { template_key: 'trial_ending_soon' }, scheduledAt);
      
      expect(mockRedis.setex).toHaveBeenCalledWith(
        'job:scheduled:test-uuid-123',
        expect.any(Number),
        'test-uuid-123'
      );
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
      
      expect(result).toEqual({
        sent: 100,
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
      
      const result = await jobManager.executeJob(mockJob);
      
      expect(result).toHaveProperty('invoices_processed', 2);
      expect(result).toHaveProperty('total_invoices', 2);
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

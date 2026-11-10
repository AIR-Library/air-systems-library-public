import { Pool } from 'pg';
import Redis from 'ioredis';
import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import { format } from 'date-fns';
import { z } from 'zod';
import Stripe from 'stripe';

const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const JobStatus = {
  ENQUEUED: 'enqueued',
  RUNNING: 'running',
  COMPLETED: 'completed',
  FAILED: 'failed',
  CANCELLED: 'cancelled',
} as const;

type JobStatusType = typeof JobStatus[keyof typeof JobStatus];

const JobSchema = z.object({
  id: z.string().uuid(),
  task_type: z.string(),
  params: z.record(z.any()),
  status: z.enum(['enqueued', 'running', 'completed', 'failed', 'cancelled']),
  created_at: z.date(),
  started_at: z.date().nullable(),
  completed_at: z.date().nullable(),
  progress: z.string().nullable(),
  result: z.record(z.any()).nullable(),
  error: z.string().nullable(),
  retry_count: z.number().int().min(0),
  max_retries: z.number().int().min(0),
  next_retry_at: z.date().nullable(),
  scheduled_at: z.date().nullable(),
});

const JobRunSchema = z.object({
  id: z.string().uuid(),
  job_id: z.string().uuid(),
  status: z.string(),
  started_at: z.date(),
  completed_at: z.date().nullable(),
  result: z.record(z.any()).nullable(),
});

interface Job extends z.infer<typeof JobSchema> {}
interface JobRun extends z.infer<typeof JobRunSchema> {}

class BackgroundJobError extends Error {
  constructor(
    message: string,
    public jobId: string,
    public code: string
  ) {
    super(message);
    this.name = 'BackgroundJobError';
  }
}

/**
 * What the sync_stripe_invoices task needs from Stripe: the current state of one invoice.
 * In: a Stripe invoice id. Out: its id, status, amount paid and amount due (cents).
 * Why: the task "synced" invoices by re-reading its own table and stamping them synced without ever asking Stripe,
 * and its test re-read each row a second time; Stripe now sits behind this interface so tests use a fake and no test
 * touches the network (repair of the failing sync_stripe_invoices test, 2026-11-10, session
 * session_012zDydZCZ4AChqhEZ4oVtaP). Touches: Stripe over the network (the default implementation).
 */
export interface StripeInvoiceGateway {
  retrieveInvoice(invoiceId: string): Promise<{ id: string; status: string | null; amount_paid: number; amount_due: number }>;
}

/**
 * The default {@link StripeInvoiceGateway}: Stripe's API with the key in STRIPE_SECRET_KEY, created on first use.
 * In/out: as the interface. Throws when STRIPE_SECRET_KEY is not set. Added 2026-11-10, session
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: Stripe (network); reads the environment.
 */
class StripeApiInvoiceGateway implements StripeInvoiceGateway {
  private client: Stripe | null = null;

  async retrieveInvoice(invoiceId: string) {
    if (!this.client) {
      const key = process.env.STRIPE_SECRET_KEY;
      if (!key) throw new Error('stripe_not_configured: set STRIPE_SECRET_KEY or install a gateway');
      this.client = new Stripe(key);
    }
    const invoice = await this.client.invoices.retrieve(invoiceId);
    return { id: invoice.id, status: invoice.status, amount_paid: invoice.amount_paid, amount_due: invoice.amount_due };
  }
}

class JobManager {
  private static instance: JobManager;
  private stripeInvoices: StripeInvoiceGateway = new StripeApiInvoiceGateway();
  private workerRunning = false;
  private readonly BATCH_SIZE = 10;
  private readonly RETRY_DELAYS = [1000, 2000, 4000, 8000, 16000, 32000, 64000, 128000];

  private constructor() {}

  /**
   * Replaces how the sync_stripe_invoices task reads invoices from Stripe (tests install a fake).
   * In: the gateway. Out: nothing. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: this object.
   */
  public setStripeInvoiceGateway(gateway: StripeInvoiceGateway): void {
    this.stripeInvoices = gateway;
  }

  public static getInstance(): JobManager {
    if (!JobManager.instance) {
      JobManager.instance = new JobManager();
    }
    return JobManager.instance;
  }

  public async initialize(): Promise<void> {
    await this.setupDatabase();
    await this.startWorker();
  }

  private async setupDatabase(): Promise<void> {
    await db.query(`
      CREATE TABLE IF NOT EXISTS jobs (
        id VARCHAR(255) PRIMARY KEY,
        task_type VARCHAR(255) NOT NULL,
        params JSONB NOT NULL,
        status VARCHAR(50) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        started_at TIMESTAMP WITH TIME ZONE,
        completed_at TIMESTAMP WITH TIME ZONE,
        progress VARCHAR(50),
        result JSONB,
        error TEXT,
        retry_count INTEGER NOT NULL DEFAULT 0,
        max_retries INTEGER NOT NULL DEFAULT 3,
        next_retry_at TIMESTAMP WITH TIME ZONE,
        scheduled_at TIMESTAMP WITH TIME ZONE
      );

      CREATE TABLE IF NOT EXISTS job_runs (
        id VARCHAR(255) PRIMARY KEY,
        job_id VARCHAR(255) NOT NULL REFERENCES jobs(id),
        status VARCHAR(50) NOT NULL,
        started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        completed_at TIMESTAMP WITH TIME ZONE,
        result JSONB,
        FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
      CREATE INDEX IF NOT EXISTS idx_jobs_scheduled_at ON jobs(scheduled_at);
      CREATE INDEX IF NOT EXISTS idx_jobs_next_retry_at ON jobs(next_retry_at);
      CREATE INDEX IF NOT EXISTS idx_job_runs_job_id ON job_runs(job_id);
    `);
  }

  public async enqueueJob(
    task_type: string,
    params: Record<string, any>,
    scheduled_at?: Date,
    max_retries?: number
  ): Promise<{ success: boolean; job_id: string; status: string }> {
    const jobId = uuidv4();
    const now = new Date();
    
    const query = `
      INSERT INTO jobs (
        id, task_type, params, status, created_at, 
        scheduled_at, max_retries, retry_count, next_retry_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
    `;
    
    const values = [
      jobId,
      task_type,
      JSON.stringify(params),
      JobStatus.ENQUEUED,
      now,
      scheduled_at || null,
      max_retries || 3,
      0,
      scheduled_at && scheduled_at > now ? scheduled_at : null
    ];
    
    const result = await db.query(query, values);
    const job = result.rows[0];
    
    if (scheduled_at && scheduled_at > now) {
      // The worker (processJobs) reads job:scheduled:<id> as the run time in epoch milliseconds and queues the job once
      // it has passed. This used to store the job id with a TTL of the delay: the reader parsed the id as a time (never
      // due), and the key could expire before the worker saw it, so a scheduled job never ran. Fixed 2026-11-10,
      // session_012zDydZCZ4AChqhEZ4oVtaP (found while fixing CodeRabbit's backoff finding on PR 19). Touches: Redis.
      await redis.set(`job:scheduled:${jobId}`, String(scheduled_at.getTime()));
    } else {
      await redis.lpush('job:queue', jobId);
    }
    
    return { success: true, job_id: jobId, status: job.status };
  }

  public async getJobStatus(jobId: string): Promise<any> {
    const query = 'SELECT * FROM jobs WHERE id = $1';
    const result = await db.query(query, [jobId]);
    
    if (result.rows.length === 0) {
      throw new BackgroundJobError('Job not found', jobId, 'JOB_NOT_FOUND');
    }
    
    const job = result.rows[0];
    return {
      job_id: job.id,
      task_type: job.task_type,
      status: job.status,
      progress: job.progress,
      created_at: job.created_at,
      started_at: job.started_at,
      result: job.result,
      next_retry_at: job.next_retry_at
    };
  }

  public async listJobs(
    status?: string,
    task_type?: string,
    limit: number = 10
  ): Promise<{ jobs: any[]; total: number }> {
    let query = 'SELECT * FROM jobs WHERE 1=1';
    const params: any[] = [];
    let paramIndex = 1;
    
    if (status) {
      query += ` AND status = $${paramIndex++}`;
      params.push(status);
    }
    
    if (task_type) {
      query += ` AND task_type = $${paramIndex++}`;
      params.push(task_type);
    }
    
    query += ` ORDER BY created_at DESC LIMIT $${paramIndex++}`;
    params.push(limit);
    
    let countQuery = 'SELECT COUNT(*) FROM jobs WHERE 1=1';
    const countParams: any[] = [];
    let countParamIndex = 1;
    
    if (status) {
      countQuery += ` AND status = $${countParamIndex++}`;
      countParams.push(status);
    }
    
    if (task_type) {
      countQuery += ` AND task_type = $${countParamIndex++}`;
      countParams.push(task_type);
    }
    
    const [jobsResult, countResult] = await Promise.all([
      db.query(query, params),
      db.query(countQuery, countParams)
    ]);
    
    return {
      jobs: jobsResult.rows.map(this.formatJobResponse),
      total: parseInt(countResult.rows[0].count)
    };
  }

  public async cancelJob(jobId: string): Promise<{ success: boolean; status: string }> {
    const query = `
      UPDATE jobs 
      SET status = $1, error = $2, completed_at = $3
      WHERE id = $4 AND status = $5
      RETURNING *
    `;
    
    const values = [
      JobStatus.CANCELLED,
      'Job cancelled by user',
      new Date(),
      jobId,
      JobStatus.ENQUEUED
    ];
    
    const result = await db.query(query, values);
    
    if (result.rows.length === 0) {
      throw new BackgroundJobError('Cannot cancel job', jobId, 'JOB_ALREADY_STARTED');
    }
    
    await redis.del(`job:scheduled:${jobId}`);
    await redis.lrem('job:queue', 0, jobId);
    
    return { success: true, status: JobStatus.CANCELLED };
  }

  public async retryJob(jobId: string): Promise<{ success: boolean; new_job_id: string; status: string }> {
    const query = 'SELECT * FROM jobs WHERE id = $1';
    const result = await db.query(query, [jobId]);
    
    if (result.rows.length === 0) {
      throw new BackgroundJobError('Job not found', jobId, 'JOB_NOT_FOUND');
    }
    
    const job = result.rows[0];
    
    if (job.status !== JobStatus.FAILED) {
      throw new BackgroundJobError('Can only retry failed jobs', jobId, 'INVALID_JOB_STATUS');
    }
    
    const newJobId = uuidv4();
    const now = new Date();
    
    const insertQuery = `
      INSERT INTO jobs (
        id, task_type, params, status, created_at, 
        scheduled_at, max_retries, retry_count, next_retry_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
    `;
    
    const insertValues = [
      newJobId,
      job.task_type,
      job.params,
      JobStatus.ENQUEUED,
      now,
      job.scheduled_at,
      job.max_retries,
      0,
      null
    ];
    
    const insertResult = await db.query(insertQuery, insertValues);
    await redis.lpush('job:queue', newJobId);
    
    return { success: true, new_job_id: newJobId, status: JobStatus.ENQUEUED };
  }

  public async getJobResults(jobId: string): Promise<any> {
    const query = 'SELECT * FROM jobs WHERE id = $1';
    const result = await db.query(query, [jobId]);
    
    if (result.rows.length === 0) {
      throw new BackgroundJobError('Job not found', jobId, 'JOB_NOT_FOUND');
    }
    
    const job = result.rows[0];
    
    if (job.status !== JobStatus.COMPLETED) {
      throw new BackgroundJobError('Results only available for completed jobs', jobId, 'JOB_NOT_COMPLETED');
    }
    
    return {
      job_id: job.id,
      status: job.status,
      result: job.result,
      completed_at: job.completed_at
    };
  }

  private formatJobResponse(job: any): any {
    return {
      job_id: job.id,
      task_type: job.task_type,
      status: job.status,
      progress: job.progress,
      created_at: job.created_at,
      started_at: job.started_at,
      result: job.result,
      next_retry_at: job.next_retry_at
    };
  }

  private async startWorker(): Promise<void> {
    if (this.workerRunning) return;
    this.workerRunning = true;
    
    const processWorker = async () => {
      while (this.workerRunning) {
        try {
          await this.processJobs();
          await new Promise(resolve => setTimeout(resolve, 1000));
        } catch (error) {
          console.error('Worker error:', error);
          await new Promise(resolve => setTimeout(resolve, 5000));
        }
      }
    };
    
    processWorker();
  }

  private async processJobs(): Promise<void> {
    const pipeline = redis.pipeline();
    
    const queueJobs = await redis.lrange('job:queue', 0, this.BATCH_SIZE - 1);
    const scheduledJobs = await redis.keys('job:scheduled:*');
    
    for (const jobId of queueJobs) {
      pipeline.lrem('job:queue', 0, jobId);
    }
    
    await pipeline.exec();
    
    for (const jobId of queueJobs) {
      await this.processJob(jobId);
    }
    
    for (const key of scheduledJobs) {
      const scheduledJobId = key.split(':')[2];
      const scheduledTime = await redis.get(key);
      const now = new Date();
      
      if (scheduledTime && new Date(parseInt(scheduledTime)) <= now) {
        await redis.del(key);
        await redis.lpush('job:queue', scheduledJobId);
      }
    }
  }

  /**
   * Runs one queued job: locks its row, records a job_run, marks it 'running', executes the task, then marks it
   * 'completed'; a task error goes to handleJobError.
   * In: the job id. Out: nothing (state is written to Postgres).
   * Every path that does not run the job ends its transaction before returning: a missing job, a job that is no longer
   * 'enqueued', and a retry whose next_retry_at is still in the future all issue ROLLBACK, so the pooled client is
   * never released inside an open transaction still holding the row lock. A retry that is not yet due is not run; it
   * is put back on the delayed path (scheduleRetry) for its next_retry_at, so the backoff in handleJobError holds.
   * Why changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): CodeRabbit review on PR 19 (early returns left
   * the transaction open; next_retry_at was never checked, so every retry ran within seconds).
   * Touches: Postgres jobs and job_runs (row lock), Redis job:scheduled:<id> (via scheduleRetry), the task's own I/O.
   */
  private async processJob(jobId: string): Promise<void> {
    const client = await db.connect();

    try {
      await client.query('BEGIN');

      const query = 'SELECT * FROM jobs WHERE id = $1 FOR UPDATE';
      const result = await client.query(query, [jobId]);

      if (result.rows.length === 0) {
        await client.query('ROLLBACK');
        return;
      }

      const job = result.rows[0];

      if (job.status !== JobStatus.ENQUEUED) {
        await client.query('ROLLBACK');
        return;
      }

      if (job.next_retry_at && new Date(job.next_retry_at) > new Date()) {
        await client.query('ROLLBACK');
        await this.scheduleRetry(jobId, new Date(job.next_retry_at));
        return;
      }

      if (job.scheduled_at && job.scheduled_at > new Date()) {
        await client.query('COMMIT');
        return;
      }
      
      const jobRunId = uuidv4();
      const startedAt = new Date();
      
      await client.query(
        'INSERT INTO job_runs (id, job_id, status, started_at) VALUES ($1, $2, $3, $4)',
        [jobRunId, jobId, 'running', startedAt]
      );
      
      await client.query(
        'UPDATE jobs SET status = $1, started_at = $2 WHERE id = $3',
        [JobStatus.RUNNING, startedAt, jobId]
      );
      
      await client.query('COMMIT');
      
      const resultData = await this.executeJob(job);
      
      await client.query('BEGIN');
      
      await client.query(
        'UPDATE job_runs SET status = $1, completed_at = $2, result = $3 WHERE id = $4',
        [JobStatus.COMPLETED, new Date(), JSON.stringify(resultData), jobRunId]
      );
      
      await client.query(
        'UPDATE jobs SET status = $1, completed_at = $2, result = $3, progress = $4 WHERE id = $5',
        [JobStatus.COMPLETED, new Date(), JSON.stringify(resultData), '100/100', jobId]
      );
      
      await client.query('COMMIT');
      
    } catch (error) {
      await client.query('ROLLBACK');
      
      if (error instanceof BackgroundJobError) {
        throw error;
      }
      
      await this.handleJobError(jobId, error as Error);
    } finally {
      client.release();
    }
  }

  private async executeJob(job: Job): Promise<any> {
    switch (job.task_type) {
      case 'send_bulk_email':
        return await this.sendBulkEmail(job);
      case 'webhook_retry':
        return await this.webhookRetry(job);
      case 'export_generate':
        return await this.exportGenerate(job);
      case 'daily_report':
        return await this.dailyReport(job);
      case 'cleanup_old_sessions':
        return await this.cleanupOldSessions(job);
      case 'delete_user_cascade':
        return await this.deleteUserCascade(job);
      case 'sync_stripe_invoices':
        return await this.syncStripeInvoices(job);
      case 'generate_deployment_archive':
        return await this.generateDeploymentArchive(job);
      default:
        throw new BackgroundJobError(`Unknown task type: ${job.task_type}`, job.id, 'UNKNOWN_TASK_TYPE');
    }
  }

  private async sendBulkEmail(job: Job): Promise<any> {
    const params = job.params;
    const filter = params.filter || {};
    
    const { rows } = await db.query(
      'SELECT COUNT(*) FROM users WHERE trial_days_left <= $1',
      [filter.trial_days_left?.$lte || 7]
    );
    
    const total = parseInt(rows[0].count);
    const batchSize = 100;
    let processed = 0;
    
    for (let i = 0; i < total; i += batchSize) {
      const batch = await db.query(
        'SELECT id FROM users WHERE trial_days_left <= $1 LIMIT $2 OFFSET $3',
        [filter.trial_days_left?.$lte || 7, batchSize, i]
      );
      
      for (const user of batch.rows) {
        await this.sendEmailToUser(user.id, params.template_key);
        processed++;
        
        const progress = `${processed}/${total}`;
        await db.query(
          'UPDATE jobs SET progress = $1 WHERE id = $2',
          [progress, job.id]
        );
      }
    }
    
    return {
      sent: total,
      failed: 0,
      template_key: params.template_key
    };
  }

  private async sendEmailToUser(userId: string, templateKey: string): Promise<void> {
    await db.query(
      'INSERT INTO notifications (user_id, type, template_key, status) VALUES ($1, $2, $3, $4)',
      [userId, 'email', templateKey, 'sent']
    );
  }

  private async webhookRetry(job: Job): Promise<any> {
    const params = job.params;
    const webhookId = params.webhook_id;
    
    const { rows } = await db.query(
      'SELECT * FROM webhooks WHERE id = $1',
      [webhookId]
    );
    
    if (rows.length === 0) {
      throw new BackgroundJobError(`Webhook not found: ${webhookId}`, job.id, 'WEBHOOK_NOT_FOUND');
    }
    
    const webhook = rows[0];
    
    const { rows: attempts } = await db.query(
      'SELECT * FROM webhook_attempts WHERE webhook_id = $1 ORDER BY created_at DESC LIMIT 1',
      [webhookId]
    );
    
    const lastAttempt = attempts[0];
    const maxRetries = webhook.max_retries || 3;
    const retryCount = lastAttempt ? lastAttempt.retry_count + 1 : 1;
    
    if (retryCount > maxRetries) {
      return {
        webhook_id: webhookId,
        status: 'failed',
        attempts: retryCount,
        error: 'Max retries exceeded'
      };
    }
    
    const backoffDelay = Math.min(1000 * Math.pow(2, retryCount - 1), 300000);
    
    await db.query(
      `INSERT INTO webhook_attempts (
        webhook_id, status, retry_count, next_retry_at, error
      ) VALUES ($1, $2, $3, $4, $5)`,
      [
        webhookId,
        'pending',
        retryCount,
        new Date(Date.now() + backoffDelay),
        null
      ]
    );
    
    return {
      webhook_id: webhookId,
      status: 'queued',
      attempts: retryCount,
      next_retry_at: new Date(Date.now() + backoffDelay)
    };
  }

  /**
   * export_generate task: records a data_exports row, then copies every matching record into export_records page by
   * page (ordered by id so pages neither repeat nor skip), updating the job's progress after each page.
   * In: the job (params export_type, filters, user_id). Out: { export_id, type, total_records, processed }.
   * Why changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): it kept asking for pages until the processed
   * count reached the initial count, so a short last page (rows deleted meanwhile, or fewer than counted) looped for
   * ever; the failing test hit a page past the end. Touches: Postgres data_exports, export_records, jobs.
   */
  private async exportGenerate(job: Job): Promise<any> {
    const params = job.params;
    const exportType = params.export_type;
    const filters = params.filters || {};
    
    const exportId = uuidv4();
    const createdAt = new Date();
    
    await db.query(
      `INSERT INTO data_exports (
        id, type, status, created_at, filters, user_id
      ) VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        exportId,
        exportType,
        'processing',
        createdAt,
        JSON.stringify(filters),
        params.user_id
      ]
    );
    
    const totalRecords = await this.getExportRecordCount(exportType, filters);
    const pageSize = 1000;
    let processed = 0;
    
    // Page through the records until a short page says there are no more. Comparing against the count alone looped
    // for ever when rows were deleted after counting, and asked for pages past the end (2026-11-10).
    for (;;) {
      const batch = await this.getExportBatch(exportType, filters, processed, pageSize);
      for (const record of batch) {
        await this.processExportRecord(exportId, record, exportType);
        processed++;
      }
      if (batch.length > 0) {
        await db.query(
          'UPDATE jobs SET progress = $1 WHERE id = $2',
          [`${processed}/${totalRecords}`, job.id]
        );
      }
      if (batch.length < pageSize) break;
    }
    
    await db.query(
      'UPDATE data_exports SET status = $1, completed_at = $2 WHERE id = $3',
      ['completed', new Date(), exportId]
    );
    
    return {
      export_id: exportId,
      type: exportType,
      total_records: totalRecords,
      processed
    };
  }

  private async getExportRecordCount(exportType: string, filters: any): Promise<number> {
    switch (exportType) {
      case 'users':
        return parseInt((await db.query(
          'SELECT COUNT(*) FROM users WHERE created_at >= $1',
          [filters.created_after || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)]
        )).rows[0].count);
      case 'orders':
        return parseInt((await db.query(
          'SELECT COUNT(*) FROM orders WHERE created_at >= $1',
          [filters.created_after || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)]
        )).rows[0].count);
      default:
        return 0;
    }
  }

  /**
   * One page of export records, ordered by id so consecutive pages neither repeat nor skip rows.
   * In: export type, filters, offset, limit. Out: the rows. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (ORDER BY id). Touches: Postgres.
   */
  private async getExportBatch(exportType: string, filters: any, offset: number, limit: number): Promise<any[]> {
    switch (exportType) {
      case 'users':
        return (await db.query(
          'SELECT * FROM users WHERE created_at >= $1 ORDER BY id LIMIT $2 OFFSET $3',
          [
            filters.created_after || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
            limit,
            offset
          ]
        )).rows;
      case 'orders':
        return (await db.query(
          'SELECT * FROM orders WHERE created_at >= $1 ORDER BY id LIMIT $2 OFFSET $3',
          [
            filters.created_after || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
            limit,
            offset
          ]
        )).rows;
      default:
        return [];
    }
  }

  private async processExportRecord(exportId: string, record: any, exportType: string): Promise<void> {
    await db.query(
      `INSERT INTO export_records (
        export_id, record_type, record_id, data, status
      ) VALUES ($1, $2, $3, $4, $5)`,
      [
        exportId,
        exportType,
        record.id,
        JSON.stringify(record),
        'processed'
      ]
    );
  }

  /**
   * daily_report task: computes one UTC day's metrics and stores them in daily_reports.
   * In: the job (params report_date "YYYY-MM-DD", default today in UTC). Out: { report_date: "YYYY-MM-DD", metrics }.
   * Why changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): it returned a full timestamp
   * ("2026-09-25T00:00:00.000Z") as the date of a daily report (failing test), and accepted any text as a date.
   * Touches: Postgres users, orders, user_sessions, daily_reports.
   */
  private async dailyReport(job: Job): Promise<any> {
    const params = job.params;
    const reportDate = params.report_date ? new Date(params.report_date) : new Date();
    if (Number.isNaN(reportDate.getTime())) {
      throw new BackgroundJobError(`Invalid report_date: ${params.report_date}`, job.id, 'INVALID_PARAMS');
    }
    const reportDay = reportDate.toISOString().slice(0, 10);
    
    const metrics = await this.calculateDailyMetrics(reportDate);
    
    await db.query(
      `INSERT INTO daily_reports (
        date, total_users, active_users, total_revenue, 
        new_signups, status, data
      ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        reportDay,
        metrics.total_users,
        metrics.active_users,
        metrics.total_revenue,
        metrics.new_signups,
        'completed',
        JSON.stringify(metrics)
      ]
    );
    
    return {
      report_date: reportDay,
      metrics
    };
  }

  /**
   * One UTC day's metrics: total users by the end of the day, revenue of completed orders, sign-ups and active
   * users that day. In: a date. Out: { total_users, active_users, total_revenue, new_signups }.
   * Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: total_users counted the day's sign-ups. Touches: Postgres users, orders, user_sessions.
   */
  private async calculateDailyMetrics(date: Date): Promise<any> {
    // Copies, in UTC: setHours changed the caller's date and used the server's own time zone (2026-11-08, session f3daac6e, from review).
    const startOfDay = new Date(date);
    startOfDay.setUTCHours(0, 0, 0, 0);
    const endOfDay = new Date(date);
    endOfDay.setUTCHours(23, 59, 59, 999);
    
    const [usersResult, ordersResult, signupsResult] = await Promise.all([
      // Every user who existed by the end of the day; the day's sign-ups are counted separately below. This was the
      // same query as the sign-ups, so total_users always equalled new_signups (2026-11-10, session
      // session_012zDydZCZ4AChqhEZ4oVtaP).
      db.query(
        'SELECT COUNT(*) FROM users WHERE created_at <= $1',
        [endOfDay]
      ),
      db.query(
        'SELECT COALESCE(SUM(amount), 0) FROM orders WHERE created_at BETWEEN $1 AND $2 AND status = $3',
        [startOfDay, endOfDay, 'completed']
      ),
      db.query(
        'SELECT COUNT(*) FROM users WHERE created_at BETWEEN $1 AND $2',
        [startOfDay, endOfDay]
      )
    ]);
    
    const activeUsers = parseInt((await db.query(
      'SELECT COUNT(DISTINCT user_id) FROM user_sessions WHERE last_active BETWEEN $1 AND $2',
      [startOfDay, endOfDay]
    )).rows[0].count);
    
    return {
      total_users: parseInt(usersResult.rows[0].count),
      active_users: activeUsers,
      total_revenue: parseFloat(ordersResult.rows[0].coalesce),
      new_signups: parseInt(signupsResult.rows[0].count)
    };
  }

  private async cleanupOldSessions(job: Job): Promise<any> {
    const params = job.params;
    const daysOld = params.days_old || 30;
    const cutoffDate = new Date(Date.now() - daysOld * 24 * 60 * 60 * 1000);
    
    const { rows } = await db.query(
      'DELETE FROM user_sessions WHERE last_active < $1 RETURNING user_id',
      [cutoffDate]
    );
    
    const userIds = rows.map(row => row.user_id);
    
    if (userIds.length > 0) {
      await db.query(
        'UPDATE users SET last_session_cleanup = $1 WHERE id = ANY($2)',
        [new Date(), userIds]
      );
    }
    
    return {
      sessions_cleaned: rows.length,
      cutoff_date: cutoffDate.toISOString()
    };
  }

  private async deleteUserCascade(job: Job): Promise<any> {
    const params = job.params;
    const userId = params.user_id;
    
    await db.query('BEGIN');
    
    try {
      await db.query('DELETE FROM user_sessions WHERE user_id = $1', [userId]);
      await db.query('DELETE FROM notifications WHERE user_id = $1', [userId]);
      await db.query('DELETE FROM user_preferences WHERE user_id = $1', [userId]);
      await db.query('DELETE FROM user_activity WHERE user_id = $1', [userId]);
      
      await db.query(
        'UPDATE users SET status = $1, deleted_at = $2 WHERE id = $3',
        ['deleted', new Date(), userId]
      );
      
      await db.query('COMMIT');
      
      return {
        user_id: userId,
        deleted_at: new Date().toISOString(),
        items_deleted: 4
      };
    } catch (error) {
      await db.query('ROLLBACK');
      throw error;
    }
  }

  /**
   * sync_stripe_invoices task: for every open invoice created in the last days_back days (default 7), reads its
   * current state from Stripe and stores status, amount paid and amount due, updating the job's progress as it goes.
   * One invoice failing is recorded and the rest continue.
   * In: the job (params days_back). Out: { invoices_processed, total_invoices, failed: [{ invoice_id, error }],
   * cutoff_date }.
   * Why changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): it never asked Stripe (it re-read each row it
   * had just read and stamped it "synced"), and the re-read made the failing test count 0 of 2.
   * Touches: Stripe (network, through the gateway), Postgres stripe_invoices and jobs.
   */
  private async syncStripeInvoices(job: Job): Promise<any> {
    const params = job.params;
    const daysBack = params.days_back || 7;
    const cutoffDate = new Date(Date.now() - daysBack * 24 * 60 * 60 * 1000);
    
    const { rows: invoices } = await db.query(
      'SELECT * FROM stripe_invoices WHERE status = $1 AND created_at >= $2 ORDER BY created_at, id',
      ['open', cutoffDate]
    );
    
    let processed = 0;
    const failed: { invoice_id: string; error: string }[] = [];
    
    for (const invoice of invoices) {
      try {
        const remote = await this.stripeInvoices.retrieveInvoice(invoice.id);
        await db.query(
          'UPDATE stripe_invoices SET status = $1, amount_paid = $2, amount_due = $3, last_synced = $4, sync_status = $5 WHERE id = $6',
          [remote.status, remote.amount_paid, remote.amount_due, new Date(), 'synced', invoice.id]
        );
        processed++;
      } catch (error) {
        // Only the invoice id and the error text: invoice contents may hold customer data.
        failed.push({ invoice_id: String(invoice.id), error: (error as Error).message });
      }
      await db.query(
        'UPDATE jobs SET progress = $1 WHERE id = $2',
        [`${processed + failed.length}/${invoices.length}`, job.id]
      );
    }
    
    return {
      invoices_processed: processed,
      total_invoices: invoices.length,
      failed,
      cutoff_date: cutoffDate.toISOString()
    };
  }

  /**
   * generate_deployment_archive task: selects the environment's deployments (optionally only some services), then
   * records an archive with one entry per deployment and marks it completed, updating progress per entry.
   * In: the job (params environment, services, user_id). Out: { archive_id, environment, services,
   * deployments_count, processed }.
   * Why changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): the deployments are now read before the
   * archive row is written, so the archive is built from one read; the failing test counted 0 of 2 because its
   * deployment rows were consumed by the earlier insert. Touches: Postgres deployments, deployment_archives,
   * archive_entries, jobs.
   */
  private async generateDeploymentArchive(job: Job): Promise<any> {
    const params = job.params;
    const environment = params.environment;
    const services = params.services || [];
    
    const deployments = await this.getDeploymentsForArchive(environment, services);
    
    const archiveId = uuidv4();
    const createdAt = new Date();
    
    await db.query(
      `INSERT INTO deployment_archives (
        id, environment, services, status, created_at, user_id
      ) VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        archiveId,
        environment,
        JSON.stringify(services),
        'creating',
        createdAt,
        params.user_id
      ]
    );
    
    let processed = 0;
    
    for (const deployment of deployments) {
      await this.createArchiveEntry(archiveId, deployment);
      processed++;
      
      const progress = `${processed}/${deployments.length}`;
      await db.query(
        'UPDATE jobs SET progress = $1 WHERE id = $2',
        [progress, job.id]
      );
    }
    
    await db.query(
      'UPDATE deployment_archives SET status = $1, completed_at = $2 WHERE id = $3',
      ['completed', new Date(), archiveId]
    );
    
    return {
      archive_id: archiveId,
      environment,
      services,
      deployments_count: deployments.length,
      processed: deployments.length
    };
  }

  /**
   * The deployments to archive: one environment, optionally only some services, newest first, ties by id.
   * In: environment, services. Out: the rows. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (tie-break by id). Touches: Postgres deployments.
   */
  private async getDeploymentsForArchive(environment: string, services: string[]): Promise<any[]> {
    let query = 'SELECT * FROM deployments WHERE environment = $1';
    const params: any[] = [environment];
    
    if (services.length > 0) {
      query += ' AND service_name = ANY($2)';
      params.push(services);
    }
    
    query += ' ORDER BY created_at DESC, id';
    
    const { rows } = await db.query(query, params);
    return rows;
  }

  private async createArchiveEntry(archiveId: string, deployment: any): Promise<void> {
    await db.query(
      `INSERT INTO archive_entries (
        archive_id, deployment_id, deployment_data, status
      ) VALUES ($1, $2, $3, $4)`,
      [
        archiveId,
        deployment.id,
        JSON.stringify(deployment),
        'included'
      ]
    );
  }

  /**
   * Puts a job on the delayed path so the worker queues it once `runAt` has passed: writes job:scheduled:<id> with
   * runAt in epoch milliseconds, the value processJobs reads and compares with the clock. No TTL, so the key cannot
   * expire before the worker has moved the job to job:queue.
   * In: the job id and when it may run. Out: nothing.
   * Why 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): CodeRabbit review on PR 19; retries were pushed
   * straight onto job:queue and ran within seconds, ignoring the backoff.
   * Touches: Redis job:scheduled:<id>.
   */
  private async scheduleRetry(jobId: string, runAt: Date): Promise<void> {
    await redis.set(`job:scheduled:${jobId}`, String(runAt.getTime()));
  }

  /**
   * Records a failed run: with retries left, the job goes back to 'enqueued' with retry_count + 1 and next_retry_at
   * after an exponential backoff (1 s, 2 s, 4 s, ...) and, after the commit, is put on the delayed path
   * (scheduleRetry) for next_retry_at, not onto job:queue, so it is not picked up before its backoff has passed
   * (processJob also refuses to run it early). With none left it becomes 'failed' and its running job_run is closed
   * as failed. Both in one transaction on the locked job row.
   * In: the job id and the error. Out: nothing.
   * Why changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): the status updates are written as single-line
   * statements ("UPDATE jobs SET status = $1, ..."), which is what the failing test looks for; a missing job left its
   * transaction open on a client returned to the pool, and a failed ROLLBACK hid the original error. Later the same
   * day, CodeRabbit review on PR 19: the retry was lpush'ed straight back onto job:queue, so the documented backoff
   * never happened; it now goes through the delayed path.
   * Touches: Postgres jobs and job_runs, Redis job:scheduled:<id>.
   */
  private async handleJobError(jobId: string, error: Error): Promise<void> {
    const client = await db.connect();
    
    try {
      await client.query('BEGIN');
      
      const query = 'SELECT * FROM jobs WHERE id = $1 FOR UPDATE';
      const result = await client.query(query, [jobId]);
      
      if (result.rows.length === 0) {
        await client.query('ROLLBACK');
        return;
      }
      
      const job = result.rows[0];
      
      const retryCount = job.retry_count + 1;
      const maxRetries = job.max_retries;
      
      if (retryCount > maxRetries) {
        await client.query(
          'UPDATE jobs SET status = $1, error = $2, completed_at = $3, retry_count = $4 WHERE id = $5',
          [
            JobStatus.FAILED,
            error.message,
            new Date(),
            retryCount,
            jobId
          ]
        );
        
        await client.query(
          'UPDATE job_runs SET status = $1, completed_at = $2 WHERE job_id = $3 AND status = $4',
          [JobStatus.FAILED, new Date(), jobId, 'running']
        );
        
        await client.query('COMMIT');
        return;
      }
      
      const backoffDelay = this.RETRY_DELAYS[Math.min(retryCount - 1, this.RETRY_DELAYS.length - 1)];
      const nextRetryAt = new Date(Date.now() + backoffDelay);
      
      await client.query(
        'UPDATE jobs SET status = $1, error = $2, retry_count = $3, next_retry_at = $4 WHERE id = $5',
        [
          JobStatus.ENQUEUED,
          error.message,
          retryCount,
          nextRetryAt,
          jobId
        ]
      );
      
      await client.query('COMMIT');

      await this.scheduleRetry(jobId, nextRetryAt);

    } catch (error) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // The connection is broken; the original error is the one to report.
      }
      throw error;
    } finally {
      client.release();
    }
  }
}

const jobManager = JobManager.getInstance();

export const enqueueJob = async (task_type: string, params: Record<string, any>, scheduled_at?: Date, max_retries?: number) => {
  return await jobManager.enqueueJob(task_type, params, scheduled_at, max_retries);
};

export const getJobStatus = async (jobId: string) => {
  return await jobManager.getJobStatus(jobId);
};

export const listJobs = async (status?: string, task_type?: string, limit?: number) => {
  return await jobManager.listJobs(status, task_type, limit);
};

export const cancelJob = async (jobId: string) => {
  return await jobManager.cancelJob(jobId);
};

export const retryJob = async (jobId: string) => {
  return await jobManager.retryJob(jobId);
};

export const getJobResults = async (jobId: string) => {
  return await jobManager.getJobResults(jobId);
};

export const initializeJobManager = async () => {
  await jobManager.initialize();
};

export { JobManager, JobStatus, BackgroundJobError };

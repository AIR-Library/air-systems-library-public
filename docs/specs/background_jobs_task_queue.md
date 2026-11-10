# Background Jobs & Task Queue

Reference contract for `saas_templates/<lang>/background_jobs_task_queue_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# JOBS-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `JOBS-01` | Enqueue job, worker picks it up, status becomes running |
| `JOBS-02` | Job completes, status becomes completed, results available |
| `JOBS-03` | Job fails, auto-retries with exponential backoff |
| `JOBS-04` | Job exceeds max_retries, status becomes failed |
| `JOBS-05` | User cancels before job starts, status becomes cancelled |
| `JOBS-06` | Progress tracking (45/100 updates in real-time) |
| `JOBS-07` | Scheduled jobs: only run after scheduled_at time |
| `JOBS-08` | Bulk job: 10,000 items processed without blocking request |
| `JOBS-09` | Results available after completion |

## Contract

```text
PURPOSE:
Long-running tasks queued and processed in background.
Examples: bulk email, webhook retries, daily reports, data processing.
Retry failed tasks with exponential backoff.
Track progress and results.

SCHEMA:
jobs (id, task_type, params [JSON], status: 'enqueued'|'running'|'completed'|'failed'|'cancelled', created_at, started_at, completed_at, progress: 'X/Y', result [JSON], error, retry_count, max_retries, next_retry_at, scheduled_at)
job_runs (id, job_id, status, started_at, completed_at, result)

TASK TYPES (examples):
- send_bulk_email
- webhook_retry
- daily_report_generate
- export_generate
- delete_user_cascade
- cleanup_old_sessions
- sync_stripe_invoices
- generate_deployment_archive

ENDPOINTS:

1. Enqueue job
   POST /jobs/enqueue
   {
     task_type: 'send_bulk_email',
     params: {
       template_key: 'trial_ending_soon',
       filter: { trial_days_left: { $lte: 7 } }
     },
     scheduled_at: '2026-09-25T09:00:00Z',  // Run at specific time
     max_retries: 3
   }
   Response: { success: true, job_id: '...', status: 'enqueued' }

2. Get job status
   GET /jobs/:job_id
   Response: {
     job_id,
     task_type: 'send_bulk_email',
     status: 'running',
     progress: '345/500',  // 345 of 500 emails sent
     created_at,
     started_at,
     result: { sent: 0, failed: 0 },  // Updated in real-time
     next_retry_at: null
   }

3. List jobs (filter by status)
   GET /jobs?status=running&task_type=send_bulk_email&limit=10
   Response: { jobs: [...], total: 5 }

4. Cancel job (only if not started)
   DELETE /jobs/:job_id
   Response: { success: true, status: 'cancelled' }

5. Retry failed job
   POST /jobs/:job_id/retry
   Response: { success: true, new_job_id: '...', status: 'enqueued' }

6. Get results (when completed)
   GET /jobs/:job_id/results
   Response: {
     job_id,
     status: 'completed',
     result: {
       task_type: 'send_bulk_email',
       sent: 450,
       failed: 2,
       skipped: 48,
       errors: [
         { user_id: 123, error: 'email_bounced' },
         { user_id: 456, error: 'opted_out' }
       ]
     },
     completed_at
   }

IMPLEMENTATION:
- Queue: Redis or database-backed queue (simple polling)
- Worker: Background process picks up enqueued jobs, runs, updates status
- Retry: Exponential backoff (1s, 2s, 4s, 8s, ... up to max_retries)
- Progress: Update job.progress as task completes (45/100 emails sent)
- Atomic updates: Status changes are atomic (no race conditions)
- Scheduled jobs: Check scheduled_at before moving to running
- Webhook retries: Built-in task_type for webhook retries (500+ failures auto-retry)

TASKS TO BUILD:
- send_bulk_email (use Notifications system)
- webhook_retry (use Webhooks system)
- export_generate (use Data Export system)
- daily_report (aggregate metrics)
- cleanup_old_sessions (delete sessions > 30 days old)
- delete_user_cascade (use Data Export deletion)

TESTS:
- **JOBS-01** Enqueue job, worker picks it up, status becomes running
- **JOBS-02** Job completes, status becomes completed, results available
- **JOBS-03** Job fails, auto-retries with exponential backoff
- **JOBS-04** Job exceeds max_retries, status becomes failed
- **JOBS-05** User cancels before job starts, status becomes cancelled
- **JOBS-06** Progress tracking (45/100 updates in real-time)
- **JOBS-07** Scheduled jobs: only run after scheduled_at time
- **JOBS-08** Bulk job: 10,000 items processed without blocking request
- **JOBS-09** Results available after completion
```

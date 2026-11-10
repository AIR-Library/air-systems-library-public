// Command background_jobs_task_queue is the AOI Systems Library background-jobs template: a
// database-backed job queue (SQLite) with an HTTP API (gin), a polling worker, per-task handlers,
// progress reporting, scheduled jobs, exponential-backoff retries and run history.
//
// Repair 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): the suite did not compile (the tests
// used context/sql/redis without imports; nextRetryAt.Time was assigned to *time.Time), its tests
// needed a live PostgreSQL and Redis on localhost, the worker test never started a worker and relied
// on a 100 ms sleep, retry answered job_id instead of new_job_id, every task handler returned
// invented numbers (e.g. "deleted_sessions": 1500) without doing any work, and cancel could race the
// worker. This version follows TIER_2_MASTER_SPEC_6SYSTEMS.txt system 4 ("Queue: Redis or
// database-backed queue (simple polling)") and the passing Java template: the jobs table is the
// queue, every status change is a compare-and-swap UPDATE, the worker step is a callable function,
// and a task type only runs if the host registered a real handler for it (otherwise the job fails
// with a clear error instead of reporting fake success).
// Touches: SQLite database (jobs, job_runs); network only when main() serves HTTP.
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite"
)

// JobStatus is a job's lifecycle state. It is an alias of string (changed 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP) so Job.Status compares equal to plain strings such as "running".
type JobStatus = string

// Job states (spec: 'enqueued'|'running'|'completed'|'failed'|'cancelled').
const (
	JobStatusEnqueued  JobStatus = "enqueued"
	JobStatusRunning   JobStatus = "running"
	JobStatusCompleted JobStatus = "completed"
	JobStatusFailed    JobStatus = "failed"
	JobStatusCancelled JobStatus = "cancelled"
)

// JobsSchema is the SQLite schema: jobs is the queue, job_runs keeps one row per attempt.
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (was PostgreSQL DDL inside initDB and
// duplicated in the tests). Touches: database.
const JobsSchema = `
CREATE TABLE IF NOT EXISTS jobs (
	id TEXT PRIMARY KEY,
	task_type TEXT NOT NULL,
	params TEXT,
	status TEXT NOT NULL,
	created_at DATETIME NOT NULL,
	started_at DATETIME,
	completed_at DATETIME,
	progress TEXT,
	result TEXT,
	error TEXT,
	retry_count INTEGER NOT NULL DEFAULT 0,
	max_retries INTEGER NOT NULL DEFAULT 3,
	next_retry_at DATETIME,
	scheduled_at DATETIME
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE TABLE IF NOT EXISTS job_runs (
	id TEXT PRIMARY KEY,
	job_id TEXT NOT NULL REFERENCES jobs(id),
	status TEXT NOT NULL,
	started_at DATETIME NOT NULL,
	completed_at DATETIME,
	result TEXT,
	error TEXT
);
CREATE INDEX IF NOT EXISTS idx_job_runs_job_id ON job_runs(job_id);
`

// KnownTaskTypes are the task types the API accepts (spec "TASK TYPES"). A job of a known type
// still needs a registered handler to run.
var KnownTaskTypes = map[string]bool{
	"send_bulk_email": true, "webhook_retry": true, "daily_report_generate": true, "daily_report": true,
	"export_generate": true, "delete_user_cascade": true, "cleanup_old_sessions": true,
	"sync_stripe_invoices": true, "generate_deployment_archive": true,
}

// OpenDB opens (and migrates) a SQLite database. Input: a file path or ":memory:". Output: the
// handle. Times are written in SQLite's own format so they read back as time.Time; ":memory:" gets
// one connection because each new connection would be a separate empty database.
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (file or memory).
func OpenDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_time_format=sqlite&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if path == ":memory:" {
		db.SetMaxOpenConns(1)
	}
	if _, err := db.Exec(JobsSchema); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// Job is one row of the jobs table.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: Error is a plain string (sql.NullString
// serialised as an object) and the times are pointers filled from sql.NullTime.
type Job struct {
	ID          string          `json:"job_id"`
	TaskType    string          `json:"task_type"`
	Params      json.RawMessage `json:"params,omitempty"`
	Status      JobStatus       `json:"status"`
	CreatedAt   time.Time       `json:"created_at"`
	StartedAt   *time.Time      `json:"started_at"`
	CompletedAt *time.Time      `json:"completed_at"`
	Progress    string          `json:"progress"`
	Result      json.RawMessage `json:"result"`
	Error       string          `json:"error,omitempty"`
	RetryCount  int             `json:"retry_count"`
	MaxRetries  int             `json:"max_retries"`
	NextRetryAt *time.Time      `json:"next_retry_at"`
	ScheduledAt *time.Time      `json:"scheduled_at"`
}

// TaskHandler runs one job. Inputs: context, the job, and report(done, total) for progress
// ("45/100"). Output: a JSON-serialisable result, or an error (the job is then retried with backoff
// until max_retries, then failed).
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: whatever the handler does.
type TaskHandler func(ctx context.Context, job *Job, report func(done, total int)) (map[string]interface{}, error)

// JobService is the queue, its HTTP handlers and its worker. The zero value plus db is usable.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the Redis client is gone (the jobs
// table is the queue); a clock and a handler registry were added.
type JobService struct {
	db       *sql.DB
	now      func() time.Time
	mu       sync.RWMutex
	handlers map[string]TaskHandler
}

// NewJobService returns a service on db using the wall clock. Added 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing until used.
func NewJobService(db *sql.DB) *JobService { return &JobService{db: db} }

// clock returns the current UTC time from the injected clock or the wall clock.
func (js *JobService) clock() time.Time {
	if js.now != nil {
		return js.now().UTC()
	}
	return time.Now().UTC()
}

// RegisterTask installs the handler for a task type. Added 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory only.
func (js *JobService) RegisterTask(taskType string, h TaskHandler) {
	js.mu.Lock()
	defer js.mu.Unlock()
	if js.handlers == nil {
		js.handlers = map[string]TaskHandler{}
	}
	js.handlers[taskType] = h
}

func (js *JobService) handler(taskType string) TaskHandler {
	js.mu.RLock()
	defer js.mu.RUnlock()
	return js.handlers[taskType]
}

// newUUID returns a random RFC 4122 version-4 UUID. Added 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP (replaces github.com/google/uuid). Touches: OS random source.
func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("background_jobs: crypto/rand failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// EnqueueRequest is the body of POST /jobs/enqueue.
type EnqueueRequest struct {
	TaskType    string          `json:"task_type"`
	Params      json.RawMessage `json:"params"`
	ScheduledAt string          `json:"scheduled_at,omitempty"` // RFC3339; the job will not start before it
	MaxRetries  *int            `json:"max_retries,omitempty"`  // default 3, 0..25
}

const jobColumns = `id, task_type, params, status, created_at, started_at, completed_at, progress, result, error,
	retry_count, max_retries, next_retry_at, scheduled_at`

// scanJob reads one row selected with jobColumns. Added 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP (one scanner for getJob and ListJobs). Touches: database row.
func scanJob(sc interface{ Scan(...interface{}) error }) (*Job, error) {
	j := &Job{}
	var params, progress, result, errStr sql.NullString
	var started, completed, nextRetry, scheduled sql.NullTime
	if err := sc.Scan(&j.ID, &j.TaskType, &params, &j.Status, &j.CreatedAt, &started, &completed, &progress, &result,
		&errStr, &j.RetryCount, &j.MaxRetries, &nextRetry, &scheduled); err != nil {
		return nil, err
	}
	if params.Valid && params.String != "" {
		j.Params = json.RawMessage(params.String)
	}
	if result.Valid && result.String != "" {
		j.Result = json.RawMessage(result.String)
	}
	j.Progress, j.Error = progress.String, errStr.String
	for _, p := range []struct {
		src sql.NullTime
		dst **time.Time
	}{{started, &j.StartedAt}, {completed, &j.CompletedAt}, {nextRetry, &j.NextRetryAt}, {scheduled, &j.ScheduledAt}} {
		if p.src.Valid {
			t := p.src.Time.UTC()
			*p.dst = &t
		}
	}
	j.CreatedAt = j.CreatedAt.UTC()
	return j, nil
}

// getJob loads a job by id. Output: the job, or sql.ErrNoRows. Changed 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
func (js *JobService) getJob(jobID string) (*Job, error) {
	return scanJob(js.db.QueryRow(`SELECT `+jobColumns+` FROM jobs WHERE id = ?`, jobID))
}

// jsonError answers {"error": msg} with status. Added 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP: database errors are logged, never sent to the client.
func jsonError(c *gin.Context, status int, msg string, err error) {
	if err != nil {
		log.Printf("background_jobs: %s: %v", msg, err)
	}
	c.JSON(status, gin.H{"error": msg})
}

// EnqueueJob handles POST /jobs/enqueue. Input: EnqueueRequest. Output: {success, job_id,
// status:"enqueued"}; 400 for an unknown task type, bad params, scheduled_at or max_retries.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
func (js *JobService) EnqueueJob(c *gin.Context) {
	var req EnqueueRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonError(c, http.StatusBadRequest, "invalid JSON body", nil)
		return
	}
	if !KnownTaskTypes[req.TaskType] {
		jsonError(c, http.StatusBadRequest, "unknown task_type", nil)
		return
	}
	if len(req.Params) > 0 && !json.Valid(req.Params) {
		jsonError(c, http.StatusBadRequest, "params must be JSON", nil)
		return
	}
	maxRetries := 3
	if req.MaxRetries != nil {
		if *req.MaxRetries < 0 || *req.MaxRetries > 25 {
			jsonError(c, http.StatusBadRequest, "max_retries must be between 0 and 25", nil)
			return
		}
		maxRetries = *req.MaxRetries
	}
	var scheduledAt interface{}
	if req.ScheduledAt != "" {
		t, err := time.Parse(time.RFC3339, req.ScheduledAt)
		if err != nil {
			jsonError(c, http.StatusBadRequest, "scheduled_at must be RFC3339", nil)
			return
		}
		scheduledAt = t.UTC()
	}
	var params interface{}
	if len(req.Params) > 0 {
		params = string(req.Params)
	}
	jobID := newUUID()
	if _, err := js.db.Exec(`INSERT INTO jobs (id, task_type, params, status, created_at, scheduled_at, max_retries)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, jobID, req.TaskType, params, JobStatusEnqueued, js.clock(), scheduledAt, maxRetries); err != nil {
		jsonError(c, http.StatusInternalServerError, "could not enqueue job", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "job_id": jobID, "status": JobStatusEnqueued})
}

// GetJobStatus handles GET /jobs/:job_id. Output: job_id, task_type, status, progress, created_at,
// started_at, result, next_retry_at, retry_count; 404 if unknown. Changed 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
func (js *JobService) GetJobStatus(c *gin.Context) {
	job, err := js.getJob(c.Param("job_id"))
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(c, http.StatusNotFound, "Job not found", nil)
		return
	} else if err != nil {
		jsonError(c, http.StatusInternalServerError, "could not load job", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"job_id": job.ID, "task_type": job.TaskType, "status": job.Status, "progress": job.Progress,
		"created_at": job.CreatedAt, "started_at": job.StartedAt, "result": job.Result,
		"next_retry_at": job.NextRetryAt, "retry_count": job.RetryCount, "error": job.Error,
	})
}

// ListJobs handles GET /jobs?status=&task_type=&limit=&offset=. Output: {jobs, total}, newest
// first (ties by insertion order); limit defaults to 50, max 100. Changed 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP (an empty limit used to be bound into LIMIT). Touches: database.
func (js *JobService) ListJobs(c *gin.Context) {
	where, args := " WHERE 1=1", []interface{}{}
	if s := c.Query("status"); s != "" {
		where += " AND status = ?"
		args = append(args, s)
	}
	if t := c.Query("task_type"); t != "" {
		where += " AND task_type = ?"
		args = append(args, t)
	}
	limit, offset := 50, 0
	if v, err := strconv.Atoi(c.Query("limit")); err == nil && v > 0 {
		limit = v
	}
	if limit > 100 {
		limit = 100
	}
	if v, err := strconv.Atoi(c.Query("offset")); err == nil && v >= 0 {
		offset = v
	}
	var total int
	if err := js.db.QueryRow(`SELECT COUNT(*) FROM jobs`+where, args...).Scan(&total); err != nil {
		jsonError(c, http.StatusInternalServerError, "could not list jobs", err)
		return
	}
	rows, err := js.db.Query(`SELECT `+jobColumns+` FROM jobs`+where+` ORDER BY rowid DESC LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		jsonError(c, http.StatusInternalServerError, "could not list jobs", err)
		return
	}
	defer rows.Close()
	jobs := []*Job{}
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			jsonError(c, http.StatusInternalServerError, "could not list jobs", err)
			return
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		jsonError(c, http.StatusInternalServerError, "could not list jobs", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"jobs": jobs, "total": total})
}

// CancelJob handles DELETE /jobs/:job_id: only a job that has not started can be cancelled. The
// status change is one compare-and-swap UPDATE, so it cannot race a worker claiming the job.
// Output: {success, status:"cancelled"}; 404 unknown; 409 already started or finished.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
func (js *JobService) CancelJob(c *gin.Context) {
	jobID := c.Param("job_id")
	res, err := js.db.Exec(`UPDATE jobs SET status = ?, completed_at = ? WHERE id = ? AND status = ?`,
		JobStatusCancelled, js.clock(), jobID, JobStatusEnqueued)
	if err != nil {
		jsonError(c, http.StatusInternalServerError, "could not cancel job", err)
		return
	}
	if n, _ := res.RowsAffected(); n == 1 {
		c.JSON(http.StatusOK, gin.H{"success": true, "job_id": jobID, "status": JobStatusCancelled})
		return
	}
	if _, err := js.getJob(jobID); errors.Is(err, sql.ErrNoRows) {
		jsonError(c, http.StatusNotFound, "Job not found", nil)
		return
	}
	jsonError(c, http.StatusConflict, "Cannot cancel job that has started or completed", nil)
}

// RetryJob handles POST /jobs/:job_id/retry: a failed job is copied into a new enqueued job.
// Output: {success, new_job_id, status:"enqueued"}; 404 unknown; 409 if the job is not failed.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (answered job_id, not new_job_id).
// Touches: database.
func (js *JobService) RetryJob(c *gin.Context) {
	job, err := js.getJob(c.Param("job_id"))
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(c, http.StatusNotFound, "Job not found", nil)
		return
	} else if err != nil {
		jsonError(c, http.StatusInternalServerError, "could not load job", err)
		return
	}
	if job.Status != JobStatusFailed {
		jsonError(c, http.StatusConflict, "Only failed jobs can be retried", nil)
		return
	}
	var params interface{}
	if len(job.Params) > 0 {
		params = string(job.Params)
	}
	newID := newUUID()
	if _, err := js.db.Exec(`INSERT INTO jobs (id, task_type, params, status, created_at, max_retries) VALUES (?, ?, ?, ?, ?, ?)`,
		newID, job.TaskType, params, JobStatusEnqueued, js.clock(), job.MaxRetries); err != nil {
		jsonError(c, http.StatusInternalServerError, "could not retry job", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "new_job_id": newID, "status": JobStatusEnqueued})
}

// GetJobResults handles GET /jobs/:job_id/results. Output: {job_id, status, result, completed_at}
// for a completed job; 400 otherwise; 404 unknown. Changed 2026-11-10, session
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
func (js *JobService) GetJobResults(c *gin.Context) {
	job, err := js.getJob(c.Param("job_id"))
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(c, http.StatusNotFound, "Job not found", nil)
		return
	} else if err != nil {
		jsonError(c, http.StatusInternalServerError, "could not load job", err)
		return
	}
	if job.Status != JobStatusCompleted {
		jsonError(c, http.StatusBadRequest, "Results only available for completed jobs", nil)
		return
	}
	c.JSON(http.StatusOK, gin.H{"job_id": job.ID, "status": job.Status, "result": job.Result, "completed_at": job.CompletedAt})
}

// ClaimNextJob is the worker's pick-up step: the oldest enqueued job whose scheduled_at and
// next_retry_at have passed moves to running (compare-and-swap, so two workers never claim the same
// job) and gets a job_runs row. Output: the claimed job and its run id, or (nil, "", nil) when
// nothing is ready. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database.
func (js *JobService) ClaimNextJob(ctx context.Context) (*Job, string, error) {
	now := js.clock()
	rows, err := js.db.QueryContext(ctx, `SELECT id, scheduled_at, next_retry_at FROM jobs WHERE status = ? ORDER BY rowid`, JobStatusEnqueued)
	if err != nil {
		return nil, "", err
	}
	var ready []string
	for rows.Next() {
		var id string
		var sched, retry sql.NullTime
		if err := rows.Scan(&id, &sched, &retry); err != nil {
			rows.Close()
			return nil, "", err
		}
		if (!sched.Valid || !sched.Time.After(now)) && (!retry.Valid || !retry.Time.After(now)) {
			ready = append(ready, id)
		}
	}
	if err := rows.Close(); err != nil {
		return nil, "", err
	}
	for _, id := range ready {
		res, err := js.db.ExecContext(ctx, `UPDATE jobs SET status = ?, started_at = ?, next_retry_at = NULL WHERE id = ? AND status = ?`,
			JobStatusRunning, now, id, JobStatusEnqueued)
		if err != nil {
			return nil, "", err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			continue // another worker took it, or it was cancelled
		}
		runID := newUUID()
		if _, err := js.db.ExecContext(ctx, `INSERT INTO job_runs (id, job_id, status, started_at) VALUES (?, ?, ?, ?)`,
			runID, id, JobStatusRunning, now); err != nil {
			return nil, "", err
		}
		job, err := js.getJob(id)
		return job, runID, err
	}
	return nil, "", nil
}

// RunJob executes a claimed job with its registered handler and records the outcome: completed
// with its result, or failed-and-retried with exponential backoff (1s, 2s, 4s, ...) until
// max_retries, then failed. A missing handler or a panic counts as a failure.
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, the handler's effects.
func (js *JobService) RunJob(ctx context.Context, job *Job, runID string) error {
	h := js.handler(job.TaskType)
	var result map[string]interface{}
	var runErr error
	if h == nil {
		runErr = fmt.Errorf("no handler registered for task type %q", job.TaskType)
	} else {
		func() {
			defer func() {
				if r := recover(); r != nil {
					runErr = fmt.Errorf("task panicked: %v", r)
				}
			}()
			result, runErr = h(ctx, job, func(done, total int) {
				if _, err := js.db.ExecContext(ctx, `UPDATE jobs SET progress = ? WHERE id = ?`, fmt.Sprintf("%d/%d", done, total), job.ID); err != nil {
					log.Printf("background_jobs: progress update for %s: %v", job.ID, err)
				}
			})
		}()
	}
	now := js.clock()
	if runErr == nil {
		b, err := json.Marshal(result)
		if err != nil {
			runErr = fmt.Errorf("result is not JSON: %w", err)
		} else {
			if _, err := js.db.ExecContext(ctx, `UPDATE jobs SET status = ?, completed_at = ?, result = ?, error = NULL WHERE id = ? AND status = ?`,
				JobStatusCompleted, now, string(b), job.ID, JobStatusRunning); err != nil {
				return err
			}
			_, err = js.db.ExecContext(ctx, `UPDATE job_runs SET status = ?, completed_at = ?, result = ? WHERE id = ?`,
				JobStatusCompleted, now, string(b), runID)
			return err
		}
	}
	if _, err := js.db.ExecContext(ctx, `UPDATE job_runs SET status = ?, completed_at = ?, error = ? WHERE id = ?`,
		JobStatusFailed, now, runErr.Error(), runID); err != nil {
		return err
	}
	retries := job.RetryCount + 1
	if retries <= job.MaxRetries {
		next := now.Add(time.Second << uint(retries-1))
		_, err := js.db.ExecContext(ctx, `UPDATE jobs SET status = ?, retry_count = ?, next_retry_at = ?, error = ? WHERE id = ? AND status = ?`,
			JobStatusEnqueued, retries, next, runErr.Error(), job.ID, JobStatusRunning)
		return err
	}
	_, err := js.db.ExecContext(ctx, `UPDATE jobs SET status = ?, completed_at = ?, error = ? WHERE id = ? AND status = ?`,
		JobStatusFailed, now, runErr.Error(), job.ID, JobStatusRunning)
	return err
}

// ProcessNext claims and runs one ready job. Output: whether a job ran, and any storage error.
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, handler effects.
func (js *JobService) ProcessNext(ctx context.Context) (bool, error) {
	job, runID, err := js.ClaimNextJob(ctx)
	if err != nil || job == nil {
		return false, err
	}
	return true, js.RunJob(ctx, job, runID)
}

// RunWorker polls for ready jobs until ctx is cancelled, so enqueue requests never block on work.
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, handler effects.
func (js *JobService) RunWorker(ctx context.Context, poll time.Duration) {
	for {
		ran, err := js.ProcessNext(ctx)
		if err != nil {
			log.Printf("background_jobs: worker: %v", err)
		}
		if ran {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(poll):
		}
	}
}

// Routes registers the HTTP API on router. The host app must put its admin authentication in
// front of these routes. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
func (js *JobService) Routes(router gin.IRoutes) {
	router.POST("/jobs/enqueue", js.EnqueueJob)
	router.GET("/jobs/:job_id", js.GetJobStatus)
	router.GET("/jobs", js.ListJobs)
	router.DELETE("/jobs/:job_id", js.CancelJob)
	router.POST("/jobs/:job_id/retry", js.RetryJob)
	router.GET("/jobs/:job_id/results", js.GetJobResults)
}

// main serves the API on :8080 with one worker, using the SQLite file in JOBS_DB (default jobs.db).
// Task handlers are registered with RegisterTask before the worker starts.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database file, network (HTTP).
func main() {
	path := os.Getenv("JOBS_DB")
	if path == "" {
		path = "jobs.db"
	}
	db, err := OpenDB(path)
	if err != nil {
		log.Fatal(err)
	}
	js := NewJobService(db)
	router := gin.Default()
	js.Routes(router)
	go js.RunWorker(context.Background(), time.Second)
	log.Fatal(router.Run(":8080"))
}

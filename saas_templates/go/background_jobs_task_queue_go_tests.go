package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnqueueJob(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	
	js := &JobService{
		db: setupTestDB(t),
	}
	router.POST("/jobs/enqueue", js.EnqueueJob)

	reqBody := map[string]interface{}{
		"task_type": "send_bulk_email",
		"params": map[string]interface{}{
			"template_key": "trial_ending_soon",
			"filter": map[string]interface{}{
				"trial_days_left": map[string]interface{}{
					"$lte": 7,
				},
			},
		},
		"max_retries": 3,
	}

	req, _ := json.Marshal(reqBody)
	reqRecorder := httptest.NewRecorder()
	reqTest := httptest.NewRequest("POST", "/jobs/enqueue", bytes.NewBuffer(req))
	router.ServeHTTP(reqRecorder, reqTest)

	assert.Equal(t, http.StatusOK, reqRecorder.Code)
	
	var response map[string]interface{}
	json.Unmarshal(reqRecorder.Body.Bytes(), &response)
	assert.True(t, response["success"].(bool))
	assert.NotEmpty(t, response["job_id"])
	assert.Equal(t, "enqueued", response["status"])
}

func TestGetJobStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	
	js := &JobService{
		db: setupTestDB(t),
	}
	router.GET("/jobs/:job_id", js.GetJobStatus)

	jobID := createTestJob(t, js.db, "send_bulk_email")
	
	reqRecorder := httptest.NewRecorder()
	reqTest := httptest.NewRequest("GET", fmt.Sprintf("/jobs/%s", jobID), nil)
	router.ServeHTTP(reqRecorder, reqTest)

	assert.Equal(t, http.StatusOK, reqRecorder.Code)
	
	var response map[string]interface{}
	json.Unmarshal(reqRecorder.Body.Bytes(), &response)
	assert.Equal(t, jobID, response["job_id"])
	assert.Equal(t, "send_bulk_email", response["task_type"])
	assert.Equal(t, "enqueued", response["status"])
}

func TestListJobs(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	
	js := &JobService{
		db: setupTestDB(t),
	}
	router.GET("/jobs", js.ListJobs)

	createTestJob(t, js.db, "send_bulk_email")
	createTestJob(t, js.db, "webhook_retry")
	
	reqRecorder := httptest.NewRecorder()
	reqTest := httptest.NewRequest("GET", "/jobs?limit=10", nil)
	router.ServeHTTP(reqRecorder, reqTest)

	assert.Equal(t, http.StatusOK, reqRecorder.Code)
	
	var response map[string]interface{}
	json.Unmarshal(reqRecorder.Body.Bytes(), &response)
	jobs := response["jobs"].([]interface{})
	assert.GreaterOrEqual(t, len(jobs), 2)
}

// JOBS-05
func TestCancelJob(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	
	js := &JobService{
		db: setupTestDB(t),
	}
	router.DELETE("/jobs/:job_id", js.CancelJob)

	jobID := createTestJob(t, js.db, "send_bulk_email")
	
	reqRecorder := httptest.NewRecorder()
	reqTest := httptest.NewRequest("DELETE", fmt.Sprintf("/jobs/%s", jobID), nil)
	router.ServeHTTP(reqRecorder, reqTest)

	assert.Equal(t, http.StatusOK, reqRecorder.Code)
	
	var response map[string]interface{}
	json.Unmarshal(reqRecorder.Body.Bytes(), &response)
	assert.True(t, response["success"].(bool))
	assert.Equal(t, "cancelled", response["status"])
}

func TestRetryJob(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	
	js := &JobService{
		db: setupTestDB(t),
	}
	router.POST("/jobs/:job_id/retry", js.RetryJob)

	jobID := createTestJob(t, js.db, "send_bulk_email")
	// Only a failed job can be retried (spec: "Retry failed job"; the Java reference answers 409 otherwise).
	_, err := js.db.Exec("UPDATE jobs SET status = ? WHERE id = ?", "failed", jobID)
	require.NoError(t, err)
	
	reqRecorder := httptest.NewRecorder()
	reqTest := httptest.NewRequest("POST", fmt.Sprintf("/jobs/%s/retry", jobID), nil)
	router.ServeHTTP(reqRecorder, reqTest)

	assert.Equal(t, http.StatusOK, reqRecorder.Code)
	
	var response map[string]interface{}
	json.Unmarshal(reqRecorder.Body.Bytes(), &response)
	assert.True(t, response["success"].(bool))
	assert.NotEmpty(t, response["new_job_id"])
	assert.Equal(t, "enqueued", response["status"])
}

func TestGetJobResults(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	
	js := &JobService{
		db: setupTestDB(t),
	}
	router.GET("/jobs/:job_id/results", js.GetJobResults)

	jobID := createTestJob(t, js.db, "send_bulk_email")
	
	reqRecorder := httptest.NewRecorder()
	reqTest := httptest.NewRequest("GET", fmt.Sprintf("/jobs/%s/results", jobID), nil)
	router.ServeHTTP(reqRecorder, reqTest)

	assert.Equal(t, http.StatusBadRequest, reqRecorder.Code)
	
	var response map[string]interface{}
	json.Unmarshal(reqRecorder.Body.Bytes(), &response)
	assert.Contains(t, response["error"], "Results only available for completed jobs")
}

// JOBS-01
func TestWorkerProcessesJob(t *testing.T) {
	js := &JobService{
		db: setupTestDB(t),
	}

	jobID := createTestJob(t, js.db, "send_bulk_email")
	// One worker step, run synchronously: the worker picks the enqueued job up and marks it running.
	claimed, _, err := js.ClaimNextJob(context.Background())
	require.NoError(t, err)
	require.NotNil(t, claimed)
	assert.Equal(t, jobID, claimed.ID)
	
	job, err := js.getJob(jobID)
	require.NoError(t, err)
	assert.Equal(t, "running", job.Status)
}

// setupTestDB returns a fresh in-memory SQLite database with the template's schema.
// Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: it needed a live PostgreSQL on
// localhost (and a live Redis via setupTestRedis, now removed: the jobs table is the queue).
func setupTestDB(t *testing.T) *sql.DB {
	db, err := OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func createTestJob(t *testing.T, db *sql.DB, taskType string) string {
	jobID := newUUID()
	params, _ := json.Marshal(map[string]interface{}{
		"template_key": "test",
	})
	
	_, err := db.Exec(
		"INSERT INTO jobs (id, task_type, params, status, created_at) VALUES (?, ?, ?, ?, ?)",
		jobID, taskType, string(params), "enqueued", time.Now().UTC(),
	)
	require.NoError(t, err)
	
	return jobID
}
// fixedClockService returns a JobService on a fresh database whose clock reads *now.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (deterministic retry and schedule tests).
func fixedClockService(t *testing.T, now *time.Time) *JobService {
	js := NewJobService(setupTestDB(t))
	js.now = func() time.Time { return *now }
	return js
}

// enqueue inserts an enqueued job with maxRetries and an optional scheduled time; returns its id.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
func enqueue(t *testing.T, js *JobService, taskType string, maxRetries int, scheduledAt *time.Time) string {
	id := newUUID()
	var sched interface{}
	if scheduledAt != nil {
		sched = scheduledAt.UTC()
	}
	_, err := js.db.Exec(`INSERT INTO jobs (id, task_type, params, status, created_at, max_retries, scheduled_at) VALUES (?, ?, '{}', ?, ?, ?, ?)`,
		id, taskType, JobStatusEnqueued, js.clock(), maxRetries, sched)
	require.NoError(t, err)
	return id
}

// TestJobCompletesWithResults proves a job's handler result is stored, the status becomes completed and
// GET /jobs/:id/results serves the result, with one completed job_runs row.
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (the Go suite had no completion test).
// JOBS-02, JOBS-09
func TestJobCompletesWithResults(t *testing.T) {
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	js := fixedClockService(t, &now)
	js.RegisterTask("send_bulk_email", func(ctx context.Context, job *Job, report func(int, int)) (map[string]interface{}, error) {
		return map[string]interface{}{"sent": 450, "failed": 2, "skipped": 48}, nil
	})
	id := enqueue(t, js, "send_bulk_email", 3, nil)
	ran, err := js.ProcessNext(context.Background())
	require.NoError(t, err)
	require.True(t, ran)

	job, err := js.getJob(id)
	require.NoError(t, err)
	assert.Equal(t, "completed", job.Status)
	require.NotNil(t, job.CompletedAt)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/jobs/:job_id/results", js.GetJobResults)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest("GET", "/jobs/"+id+"/results", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Status string         `json:"status"`
		Result map[string]int `json:"result"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "completed", body.Status)
	assert.Equal(t, map[string]int{"sent": 450, "failed": 2, "skipped": 48}, body.Result)

	var runs int
	require.NoError(t, js.db.QueryRow(`SELECT COUNT(*) FROM job_runs WHERE job_id = ? AND status = 'completed'`, id).Scan(&runs))
	assert.Equal(t, 1, runs)
}

// TestJobRetriesWithExponentialBackoff proves retry n waits 2^(n-1) s: after the first failure the job is
// 'enqueued' with retry_count 1 and next_retry_at = failed_at + 1 s, the worker skips it until then; after
// the second failure retry_count 2 and + 2 s. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// JOBS-03
func TestJobRetriesWithExponentialBackoff(t *testing.T) {
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	js := fixedClockService(t, &now)
	attempts := 0
	js.RegisterTask("webhook_retry", func(ctx context.Context, job *Job, report func(int, int)) (map[string]interface{}, error) {
		attempts++
		return nil, fmt.Errorf("endpoint answered 500")
	})
	id := enqueue(t, js, "webhook_retry", 3, nil)
	ctx := context.Background()

	for n := 1; n <= 2; n++ {
		ran, err := js.ProcessNext(ctx)
		require.NoError(t, err)
		require.True(t, ran)
		job, _ := js.getJob(id)
		delay := time.Second << uint(n-1)
		assert.Equal(t, "enqueued", job.Status, "retry %d", n)
		assert.Equal(t, n, job.RetryCount)
		require.NotNil(t, job.NextRetryAt)
		assert.True(t, job.NextRetryAt.Equal(now.Add(delay)), "retry %d at %v, want %v", n, job.NextRetryAt, now.Add(delay))
		assert.Equal(t, "endpoint answered 500", job.Error)

		now = now.Add(delay - time.Millisecond)
		ran, err = js.ProcessNext(ctx)
		require.NoError(t, err)
		assert.False(t, ran, "the worker must skip the job until next_retry_at")
		now = now.Add(time.Millisecond)
	}
	assert.Equal(t, 2, attempts)
}

// TestJobExceedsMaxRetries proves max_retries = 3 runs the job 4 times, then status 'failed' with
// retry_count 3 and the last error kept. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// JOBS-04
func TestJobExceedsMaxRetries(t *testing.T) {
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	js := fixedClockService(t, &now)
	attempts := 0
	js.RegisterTask("webhook_retry", func(ctx context.Context, job *Job, report func(int, int)) (map[string]interface{}, error) {
		attempts++
		return nil, fmt.Errorf("attempt %d failed", attempts)
	})
	id := enqueue(t, js, "webhook_retry", 3, nil)
	for i := 0; i < 10; i++ {
		ran, err := js.ProcessNext(context.Background())
		require.NoError(t, err)
		if !ran {
			now = now.Add(time.Minute)
		}
	}
	job, _ := js.getJob(id)
	assert.Equal(t, 4, attempts)
	assert.Equal(t, "failed", job.Status)
	assert.Equal(t, 3, job.RetryCount)
	assert.Equal(t, "attempt 4 failed", job.Error)
	var runs int
	require.NoError(t, js.db.QueryRow(`SELECT COUNT(*) FROM job_runs WHERE job_id = ?`, id).Scan(&runs))
	assert.Equal(t, 4, runs)
}

// TestJobProgressTracking proves progress "45/100" is visible through GET /jobs/:id while the job is
// still running. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// JOBS-06
func TestJobProgressTracking(t *testing.T) {
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	js := fixedClockService(t, &now)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/jobs/:job_id", js.GetJobStatus)
	var seen map[string]interface{}
	js.RegisterTask("send_bulk_email", func(ctx context.Context, job *Job, report func(int, int)) (map[string]interface{}, error) {
		report(45, 100)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest("GET", "/jobs/"+job.ID, nil))
		_ = json.Unmarshal(rec.Body.Bytes(), &seen)
		report(100, 100)
		return map[string]interface{}{"sent": 100}, nil
	})
	id := enqueue(t, js, "send_bulk_email", 3, nil)
	_, err := js.ProcessNext(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "45/100", seen["progress"])
	assert.Equal(t, "running", seen["status"])
	job, _ := js.getJob(id)
	assert.Equal(t, "100/100", job.Progress)
}

// TestScheduledJobWaits proves a job with scheduled_at in the future is not picked up before that time,
// and is picked up from it on. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// JOBS-07
func TestScheduledJobWaits(t *testing.T) {
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	js := fixedClockService(t, &now)
	at := now.Add(time.Hour)
	id := enqueue(t, js, "daily_report", 0, &at)
	claimed, _, err := js.ClaimNextJob(context.Background())
	require.NoError(t, err)
	assert.Nil(t, claimed, "a job must not run before scheduled_at")
	now = at
	claimed, _, err = js.ClaimNextJob(context.Background())
	require.NoError(t, err)
	require.NotNil(t, claimed)
	assert.Equal(t, id, claimed.ID)
	assert.Equal(t, "running", claimed.Status)
}

// TestBulkJobTenThousandItems proves enqueueing a 10,000-item job answers at once without doing the work
// (the request does not block), and the worker then processes all 10,000 items with progress.
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// JOBS-08
func TestBulkJobTenThousandItems(t *testing.T) {
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	js := fixedClockService(t, &now)
	processed := 0
	js.RegisterTask("send_bulk_email", func(ctx context.Context, job *Job, report func(int, int)) (map[string]interface{}, error) {
		for i := 1; i <= 10000; i++ {
			processed++
			if i%1000 == 0 {
				report(i, 10000)
			}
		}
		return map[string]interface{}{"processed": processed}, nil
	})
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/jobs/enqueue", js.EnqueueJob)
	body, _ := json.Marshal(map[string]interface{}{"task_type": "send_bulk_email", "params": map[string]int{"items": 10000}})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest("POST", "/jobs/enqueue", bytes.NewBuffer(body)))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 0, processed, "the enqueue request must not run the work")
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "enqueued", resp["status"])

	ran, err := js.ProcessNext(context.Background())
	require.NoError(t, err)
	require.True(t, ran)
	job, _ := js.getJob(resp["job_id"].(string))
	assert.Equal(t, "completed", job.Status)
	assert.Equal(t, "10000/10000", job.Progress)
	assert.JSONEq(t, `{"processed":10000}`, string(job.Result))
}

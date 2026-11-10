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
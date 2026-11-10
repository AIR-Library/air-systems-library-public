package health

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// HEALTH-01
func TestAllChecksPass(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterCheck("db", "database", func() (string, string, string) {
		return "pass", "connected", ""
	}, true, 1000)

	result := registry.Readiness()
	if result["http_status"] != 200 {
		t.Errorf("expected http_status 200, got %v", result["http_status"])
	}

	body, ok := result["body"].(HealthResponse)
	if !ok {
		t.Fatalf("expected HealthResponse body, got %T", result["body"])
	}
	if body.Status != "pass" {
		t.Errorf("expected status 'pass', got '%s'", body.Status)
	}
	if result["content_type"] != "application/health+json" {
		t.Errorf("expected content_type 'application/health+json', got '%v'", result["content_type"])
	}
}

// HEALTH-02
func TestCriticalCheckFails(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterCheck("db", "database", func() (string, string, string) {
		return "fail", "connection refused", ""
	}, true, 1000)

	result := registry.Readiness()
	if result["http_status"] != 503 {
		t.Errorf("expected http_status 503, got %v", result["http_status"])
	}

	body := result["body"].(HealthResponse)
	if body.Status != "fail" {
		t.Errorf("expected status 'fail', got '%s'", body.Status)
	}
}

// HEALTH-03
func TestNonCriticalCheckFails(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterCheck("cache", "redis", func() (string, string, string) {
		return "fail", "timeout", ""
	}, false, 1000)

	result := registry.Readiness()
	if result["http_status"] != 200 {
		t.Errorf("expected http_status 200, got %v", result["http_status"])
	}

	body := result["body"].(HealthResponse)
	if body.Status != "warn" {
		t.Errorf("expected status 'warn', got '%s'", body.Status)
	}
}

// HEALTH-04
func TestSlowCheckTimesOut(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterCheck("slow", "service", func() (string, string, string) {
		time.Sleep(200 * time.Millisecond)
		return "pass", "", ""
	}, true, 50) // 50ms timeout

	result := registry.Readiness()
	body := result["body"].(HealthResponse)

	checks := body.Checks["slow:service"]
	if len(checks) == 0 {
		t.Fatal("expected check result for slow:service")
	}
	if checks[0].Status != "fail" {
		t.Errorf("expected slow check status 'fail' due to timeout, got '%s'", checks[0].Status)
	}
}

// HEALTH-05
func TestLivenessStaysPass(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterCheck("db", "database", func() (string, string, string) {
		return "fail", "connection refused", ""
	}, true, 1000)

	result := registry.Liveness()
	if result["http_status"] != 200 {
		t.Errorf("expected http_status 200, got %v", result["http_status"])
	}

	body := result["body"].(HealthResponse)
	if body.Status != "pass" {
		t.Errorf("expected liveness status 'pass', got '%s'", body.Status)
	}
}

// HEALTH-06
func TestNoConnectionStringInOutput(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterCheck("db", "database", func() (string, string, string) {
		return "fail", "connection to postgres://user:pass@host:5432/db failed", ""
	}, true, 1000)

	result := registry.Readiness()
	body := result["body"].(HealthResponse)

	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("failed to marshal body: %v", err)
	}

	output := string(data)
	if strings.Contains(output, "postgres://") || strings.Contains(output, "user:pass@") {
		t.Errorf("output contains connection string: %s", output)
	}
}
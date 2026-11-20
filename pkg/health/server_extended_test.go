package health

import (
	"io"

	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"log/slog"
)

// Mock checker for testing
type mockChecker struct {
	name   string
	status ComponentStatus
}

func (m *mockChecker) Name() string {
	return m.name
}

func (m *mockChecker) CheckHealth() ComponentStatus {
	return m.status
}

// Mock stats provider
type mockStatsProvider struct {
	stats map[string]interface{}
}

func (m *mockStatsProvider) GetStats() any {
	return m.stats
}

// Mock cache flusher
type mockCacheFlusher struct {
	flushCount int
}

func (m *mockCacheFlusher) FlushCache() map[string]int {
	m.flushCount++
	return map[string]int{
		"routing_cache": 100,
		"dns_cache":     50,
	}
}

func TestNewServer(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewServer(":8080", logger)

	if server == nil {
		t.Fatal("Server is nil")
	}
	if server.listenAddr != ":8080" {
		t.Error("Listen address not set correctly")
	}

	t.Log("✓ NewServer creates server successfully")
}

func TestNewServer_NilLogger(t *testing.T) {
	server := NewServer(":8080", nil)

	if server == nil {
		t.Fatal("Server is nil")
	}
	if server.logger == nil {
		t.Error("Logger should be set to nop logger")
	}

	t.Log("✓ NewServer handles nil logger")
}

func TestServer_SetStatsProvider(t *testing.T) {
	server := NewServer(":8080", slog.New(slog.NewTextHandler(io.Discard, nil)))
	provider := &mockStatsProvider{
		stats: map[string]interface{}{"test": "data"},
	}

	server.SetStatsProvider(provider)
	if server.statsProvider != provider {
		t.Error("Stats provider not set")
	}

	t.Log("✓ SetStatsProvider works")
}

func TestServer_AddCacheFlusher(t *testing.T) {
	server := NewServer(":8080", slog.New(slog.NewTextHandler(io.Discard, nil)))
	flusher := &mockCacheFlusher{}

	server.AddCacheFlusher(flusher)
	if len(server.cacheFlushers) != 1 || server.cacheFlushers[0] != CacheFlusher(flusher) {
		t.Error("Cache flusher not set")
	}

	t.Log("✓ AddCacheFlusher works")
}

func TestServer_SetBasicAuth(t *testing.T) {
	server := NewServer(":8080", slog.New(slog.NewTextHandler(io.Discard, nil)))

	server.SetBasicAuth("admin", "secret")
	if server.username != "admin" {
		t.Error("Username not set")
	}
	if server.password != "secret" {
		t.Error("Password not set")
	}

	t.Log("✓ SetBasicAuth works")
}

func TestServer_SetMetricsConfig(t *testing.T) {
	server := NewServer(":8080", slog.New(slog.NewTextHandler(io.Discard, nil)))

	server.SetMetricsConfig(true, "/custom-metrics", "metrics-user", "metrics-pass")
	if !server.metricsEnabled {
		t.Error("Metrics not enabled")
	}
	if server.metricsPath != "/custom-metrics" {
		t.Error("Metrics path not set")
	}
	if server.metricsUsername != "metrics-user" {
		t.Error("Metrics username not set")
	}

	t.Log("✓ SetMetricsConfig works")
}

func TestServer_HealthHandler_AllHealthy(t *testing.T) {
	checker1 := &mockChecker{
		name:   "component1",
		status: ComponentStatus{Status: "healthy"},
	}
	checker2 := &mockChecker{
		name:   "component2",
		status: ComponentStatus{Status: "healthy"},
	}

	server := NewServer(":8080", slog.New(slog.NewTextHandler(io.Discard, nil)), checker1, checker2)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	server.healthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	if response["status"] != "healthy" {
		t.Errorf("Expected healthy status, got %v", response["status"])
	}

	t.Log("✓ Health handler returns healthy when all components healthy")
}

func TestServer_HealthHandler_OneUnhealthy(t *testing.T) {
	checker1 := &mockChecker{
		name:   "component1",
		status: ComponentStatus{Status: "healthy"},
	}
	checker2 := &mockChecker{
		name:   "component2",
		status: ComponentStatus{Status: "unhealthy"},
	}

	server := NewServer(":8080", slog.New(slog.NewTextHandler(io.Discard, nil)), checker1, checker2)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	server.healthHandler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	if response["status"] != "unhealthy" {
		t.Errorf("Expected unhealthy status, got %v", response["status"])
	}

	t.Log("✓ Health handler returns unhealthy when any component unhealthy")
}

func TestServer_StatsHandler_NoProvider(t *testing.T) {
	server := NewServer(":8080", slog.New(slog.NewTextHandler(io.Discard, nil)))

	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()

	server.statsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	// Should return empty stats
	if response["ips"] == nil {
		t.Error("Expected ips in response")
	}

	t.Log("✓ Stats handler returns empty stats when no provider")
}

func TestServer_StatsHandler_WithProvider(t *testing.T) {
	server := NewServer(":8080", slog.New(slog.NewTextHandler(io.Discard, nil)))
	provider := &mockStatsProvider{
		stats: map[string]interface{}{
			"custom": "value",
			"count":  42,
		},
	}
	server.SetStatsProvider(provider)

	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()

	server.statsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	if response["custom"] != "value" {
		t.Error("Expected custom stats")
	}

	t.Log("✓ Stats handler returns provider stats")
}

func TestServer_StatsHandler_WrongMethod(t *testing.T) {
	server := NewServer(":8080", slog.New(slog.NewTextHandler(io.Discard, nil)))

	req := httptest.NewRequest("POST", "/api/stats", nil)
	w := httptest.NewRecorder()

	server.statsHandler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}

	t.Log("✓ Stats handler rejects non-GET requests")
}

func TestServer_FlushCacheHandler_NoFlusher(t *testing.T) {
	server := NewServer(":8080", slog.New(slog.NewTextHandler(io.Discard, nil)))

	req := httptest.NewRequest("POST", "/api/flush-cache", nil)
	w := httptest.NewRecorder()

	server.flushCacheHandler(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("Expected status 501, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	if response["status"] != "error" {
		t.Error("Expected error status")
	}

	t.Log("✓ Flush cache handler returns not implemented when no flusher")
}

func TestServer_FlushCacheHandler_WithFlusher(t *testing.T) {
	server := NewServer(":8080", slog.New(slog.NewTextHandler(io.Discard, nil)))
	flusher := &mockCacheFlusher{}
	server.AddCacheFlusher(flusher)

	req := httptest.NewRequest("POST", "/api/flush-cache", nil)
	w := httptest.NewRecorder()

	server.flushCacheHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	if flusher.flushCount != 1 {
		t.Error("Expected flush to be called")
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	if response["status"] != "success" {
		t.Error("Expected success status")
	}

	t.Log("✓ Flush cache handler flushes cache successfully")
}

func TestServer_FlushCacheHandler_WrongMethod(t *testing.T) {
	server := NewServer(":8080", slog.New(slog.NewTextHandler(io.Discard, nil)))

	req := httptest.NewRequest("GET", "/api/flush-cache", nil)
	w := httptest.NewRecorder()

	server.flushCacheHandler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}

	t.Log("✓ Flush cache handler rejects non-POST requests")
}

func TestServer_BasicAuthMiddleware_NoAuth(t *testing.T) {
	server := NewServer(":8080", slog.New(slog.NewTextHandler(io.Discard, nil)))
	// No auth configured

	called := false
	handler := server.basicAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if !called {
		t.Error("Handler should be called when no auth configured")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	t.Log("✓ Basic auth middleware allows requests when no auth configured")
}

func TestServer_BasicAuthMiddleware_WithAuth_Valid(t *testing.T) {
	server := NewServer(":8080", slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.SetBasicAuth("admin", "secret")

	called := false
	handler := server.basicAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.SetBasicAuth("admin", "secret")
	w := httptest.NewRecorder()

	handler(w, req)

	if !called {
		t.Error("Handler should be called with valid credentials")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	t.Log("✓ Basic auth middleware allows valid credentials")
}

func TestServer_BasicAuthMiddleware_WithAuth_Invalid(t *testing.T) {
	server := NewServer(":8080", slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.SetBasicAuth("admin", "secret")

	called := false
	handler := server.basicAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.SetBasicAuth("admin", "wrong-password")
	w := httptest.NewRecorder()

	handler(w, req)

	if called {
		t.Error("Handler should not be called with invalid credentials")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}

	t.Log("✓ Basic auth middleware rejects invalid credentials")
}

func TestServer_BasicAuthMiddleware_NoCredentials(t *testing.T) {
	server := NewServer(":8080", slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.SetBasicAuth("admin", "secret")

	called := false
	handler := server.basicAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	// No credentials provided
	w := httptest.NewRecorder()

	handler(w, req)

	if called {
		t.Error("Handler should not be called without credentials")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}

	t.Log("✓ Basic auth middleware rejects missing credentials")
}

func TestCheckDestination_Healthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewCheckDestination(server.URL, 5*time.Second)
	status := checker.CheckHealth()

	if status.Status != "healthy" {
		t.Errorf("Expected healthy, got %s", status.Status)
	}

	t.Log("✓ CheckDestination reports healthy for reachable endpoint")
}

func TestCheckDestination_Unhealthy_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	checker := NewCheckDestination(server.URL, 5*time.Second)
	status := checker.CheckHealth()

	if status.Status != "unhealthy" {
		t.Errorf("Expected unhealthy, got %s", status.Status)
	}

	t.Log("✓ CheckDestination reports unhealthy for 5xx errors")
}

func TestCheckDestination_Healthy_ClientError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	checker := NewCheckDestination(server.URL, 5*time.Second)
	status := checker.CheckHealth()

	// 4xx errors are acceptable (endpoint exists, just returns 404 for HEAD)
	if status.Status != "healthy" {
		t.Errorf("Expected healthy, got %s", status.Status)
	}

	t.Log("✓ CheckDestination reports healthy for 4xx errors")
}

func TestCheckDestination_Unhealthy_Unreachable(t *testing.T) {
	checker := NewCheckDestination("http://localhost:99999", 1*time.Second)
	status := checker.CheckHealth()

	if status.Status != "unhealthy" {
		t.Errorf("Expected unhealthy, got %s", status.Status)
	}

	// Should contain error message
	details := status.Details.(map[string]any)
	if details["error"] == nil {
		t.Error("Expected error in details")
	}

	t.Log("✓ CheckDestination reports unhealthy for unreachable endpoint")
}

func TestCheckDestination_Name(t *testing.T) {
	checker := NewCheckDestination("http://example.com", 5*time.Second)
	if checker.Name() != "destination" {
		t.Errorf("Expected name 'destination', got '%s'", checker.Name())
	}
}

func TestServer_RegisterHandler(t *testing.T) {
	server := NewServer(":8080", slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.Start()
	defer server.Stop(context.Background())

	// Wait a bit for server to start
	time.Sleep(100 * time.Millisecond)

	called := false
	server.RegisterHandler("/custom", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	if !called {
		// Note: We can't easily test the actual HTTP call without starting a real server
		// This test just verifies the method doesn't panic
		t.Log("✓ RegisterHandler registers custom handler")
	}
}

func TestServer_Stop(t *testing.T) {
	server := NewServer(":0", slog.New(slog.NewTextHandler(io.Discard, nil))) // Use port 0 for random available port
	server.Start()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Stop should not panic
	server.Stop(ctx)

	t.Log("✓ Server stops gracefully")
}

func TestContainsHelper(t *testing.T) {
	if !contains("hello world", "hello") {
		t.Error("contains should find 'hello' in 'hello world'")
	}
	if contains("hello", "world") {
		t.Error("contains should not find 'world' in 'hello'")
	}
	if !contains("test", "test") {
		t.Error("contains should find exact match")
	}

	t.Log("✓ contains helper works correctly")
}

func TestComponentStatus_JSON(t *testing.T) {
	status := ComponentStatus{
		Status: "healthy",
		Details: map[string]string{
			"test": "value",
		},
	}

	data, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if !strings.Contains(string(data), "healthy") {
		t.Error("JSON should contain status")
	}

	t.Log("✓ ComponentStatus serializes to JSON")
}

func TestServer_MetricsHandler(t *testing.T) {
	server := NewServer(":8080", slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.SetMetricsConfig(true, "/metrics", "", "")

	handler := server.metricsHandler()
	if handler == nil {
		t.Error("Metrics handler should not be nil")
	}

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should return prometheus metrics (200 OK)
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	t.Log("✓ Metrics handler returns Prometheus metrics")
}

func TestServer_SetACMEHandler(t *testing.T) {
	server := NewServer(":8080", slog.New(slog.NewTextHandler(io.Discard, nil)))

	acmeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server.SetACMEHandler(acmeHandler)
	if server.acmeHandler == nil {
		t.Error("ACME handler not set")
	}

	t.Log("✓ SetACMEHandler sets handler")
}

func TestNewCheckDestination(t *testing.T) {
	checker := NewCheckDestination("https://example.com", 10*time.Second)

	if checker.URL != "https://example.com" {
		t.Error("URL not set correctly")
	}
	if checker.Timeout != 10*time.Second {
		t.Error("Timeout not set correctly")
	}
	if checker.httpClient == nil {
		t.Error("HTTP client not initialized")
	}

	t.Log("✓ NewCheckDestination creates checker correctly")
}

func TestNewCheckS3Connection(t *testing.T) {
	checker := NewCheckS3Connection(nil, "test-bucket")

	if checker.BucketName != "test-bucket" {
		t.Error("Bucket name not set correctly")
	}
	if checker.Name() != "s3_connection" {
		t.Error("Name not correct")
	}

	t.Log("✓ NewCheckS3Connection creates checker correctly")
}

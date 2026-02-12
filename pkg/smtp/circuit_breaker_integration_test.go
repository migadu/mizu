package smtp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/poster"
	"migadu/mizu/pkg/stats"

	"github.com/emersion/go-smtp"
)

// TestCircuitBreakerIntegration_OpenReturns451 verifies that when the circuit breaker
// is open, SMTP sessions return 451 (temporary failure) to incoming messages.
func TestCircuitBreakerIntegration_OpenReturns451(t *testing.T) {
	var requestCount atomic.Int32

	// Create a backend server that fails consistently
	failingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable) // 503 error
		w.Write([]byte("Backend unavailable"))
	}))
	defer failingServer.Close()

	// Configure circuit breaker with low thresholds for testing
	cbConfig := poster.CircuitBreakerConfig{
		FailureThreshold: 3, // Open after 3 failures
		SuccessThreshold: 2,
		Timeout:          2 * time.Second, // Stay open for 2s before half-open
		HalfOpenMaxCalls: 1,
	}
	cb := poster.NewCircuitBreaker(cbConfig, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	// Create HTTP client for delivery
	httpClient := &http.Client{Timeout: 5 * time.Second}

	cfg := testConfig()
	// Add a server config since DefaultConfig has empty Servers slice
	if len(cfg.Servers) == 0 {
		cfg.Servers = append(cfg.Servers, config.ServerConfig{
			ListenAddr: ":25",
		})
	}
	cfg.Servers[0].Delivery = config.DeliveryConfig{
		URL:                failingServer.URL,
		AuthToken:          "test-token",
		MaxRetryAttempts:   1, // Don't retry within the request
		HTTPTimeoutSeconds: 5,
	}

	statsManager := stats.NewManager(false, 0, "test", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer statsManager.Stop()

	// Step 1: Make 3 failed delivery attempts to open the circuit
	t.Log("Step 1: Triggering circuit breaker by causing failures...")
	for i := 0; i < 3; i++ {
		session := &Session{
			ctx:            context.Background(),
			helo:           "test.example.com",
			from:           "sender@example.com",
			to:             []string{"recipient@example.com"},
			serverConfig:   &cfg.Servers[0],
			globalConfig:   cfg,
			statsManager:   statsManager,
			circuitBreaker: cb,
			httpClient:     httpClient,
			Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
			remoteAddr:     "192.0.2.1:12345",
			traceID:        fmt.Sprintf("trace-%d", i),
		}

		err := session.deliverSynchronous("Subject: Test\r\n\r\nTest email")
		if err == nil {
			t.Fatal("Expected delivery to fail, but it succeeded")
		}

		// Should get temporary failure (451) because 503 is retryable
		smtpErr, ok := err.(*smtp.SMTPError)
		if !ok {
			t.Fatalf("Expected *smtp.SMTPError, got %T: %v", err, err)
		}
		if smtpErr.Code != 451 {
			t.Errorf("Expected SMTP code 451 for retryable error, got %d", smtpErr.Code)
		}

		t.Logf("  Attempt %d: Got expected 451 error: %s", i+1, smtpErr.Message)
	}

	// Verify circuit is now open
	if cb.GetState() != poster.StateOpen {
		t.Fatalf("Expected circuit to be Open after %d failures, got %v", 3, cb.GetState())
	}
	t.Log("✓ Circuit breaker is now OPEN")

	// Step 2: New SMTP request should get 451 without hitting the backend
	t.Log("Step 2: Testing new SMTP request with circuit breaker OPEN...")
	beforeCount := requestCount.Load()

	session := &Session{
		ctx:            context.Background(),
		helo:           "test.example.com",
		from:           "sender@example.com",
		to:             []string{"recipient@example.com"},
		serverConfig:   &cfg.Servers[0],
		globalConfig:   cfg,
		statsManager:   statsManager,
		circuitBreaker: cb,
		httpClient:     httpClient,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteAddr:     "192.0.2.2:12345",
		traceID:        "trace-open",
	}

	err := session.deliverSynchronous("Subject: Test during open circuit\r\n\r\nTest email")
	if err == nil {
		t.Fatal("Expected delivery to fail when circuit is open")
	}

	// Should get temporary failure (451) because ErrCircuitOpen is retryable
	smtpErr, ok := err.(*smtp.SMTPError)
	if !ok {
		t.Fatalf("Expected *smtp.SMTPError, got %T: %v", err, err)
	}
	if smtpErr.Code != 451 {
		t.Errorf("Expected SMTP code 451 for circuit open, got %d", smtpErr.Code)
	}
	if smtpErr.EnhancedCode != (smtp.EnhancedCode{4, 4, 0}) {
		t.Errorf("Expected enhanced code 4.4.0, got %v", smtpErr.EnhancedCode)
	}
	if smtpErr.Message != "Temporary failure, please try again later" {
		t.Errorf("Expected specific error message, got: %s", smtpErr.Message)
	}

	afterCount := requestCount.Load()
	if afterCount != beforeCount {
		t.Errorf("Expected circuit breaker to block request (no backend calls), but backend was called %d times", afterCount-beforeCount)
	}

	t.Logf("✓ Circuit breaker blocked request and returned 451: %s", smtpErr.Message)
	t.Log("✓ Backend was NOT called (fail-fast behavior)")

	// Step 3: Wait for circuit to transition to half-open, then test recovery
	t.Log("Step 3: Waiting for circuit to transition to HALF-OPEN...")
	time.Sleep(2100 * time.Millisecond) // Timeout is 2s

	// Circuit should transition to half-open on next call
	// We need to make the backend succeed now
	successServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Success"))
	}))
	defer successServer.Close()

	// Update config to use successful backend
	cfg.Servers[0].Delivery.URL = successServer.URL

	session = &Session{
		ctx:            context.Background(),
		helo:           "test.example.com",
		from:           "sender@example.com",
		to:             []string{"recipient@example.com"},
		serverConfig:   &cfg.Servers[0],
		globalConfig:   cfg,
		statsManager:   statsManager,
		circuitBreaker: cb,
		httpClient:     httpClient,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteAddr:     "192.0.2.3:12345",
		traceID:        "trace-recovery-1",
	}

	err = session.deliverSynchronous("Subject: Recovery test\r\n\r\nTest email")
	if err != nil {
		t.Fatalf("Expected delivery to succeed in half-open state, got error: %v", err)
	}

	t.Log("✓ First request in HALF-OPEN state succeeded")

	// Need one more success to close the circuit (success_threshold = 2)
	session.traceID = "trace-recovery-2"
	err = session.deliverSynchronous("Subject: Recovery test 2\r\n\r\nTest email")
	if err != nil {
		t.Fatalf("Expected delivery to succeed, got error: %v", err)
	}

	// Circuit should now be closed
	if cb.GetState() != poster.StateClosed {
		t.Errorf("Expected circuit to be Closed after %d successes, got %v", 2, cb.GetState())
	}

	t.Log("✓ Circuit breaker recovered to CLOSED state after successful deliveries")
	t.Log("✓ Integration test complete: Circuit breaker properly protects SMTP with 451 errors")
}

// TestCircuitBreakerIntegration_PermanentFailureReturns550 verifies that
// permanent failures (like 4xx errors) return 550, not 451.
func TestCircuitBreakerIntegration_PermanentFailureReturns550(t *testing.T) {
	// Create a backend server that returns 400 Bad Request
	badRequestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest) // 400 - permanent failure
		w.Write([]byte("Bad request"))
	}))
	defer badRequestServer.Close()

	cbConfig := poster.CircuitBreakerConfig{
		FailureThreshold: 5,
		SuccessThreshold: 2,
		Timeout:          30 * time.Second,
	}
	cb := poster.NewCircuitBreaker(cbConfig, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	httpClient := &http.Client{Timeout: 5 * time.Second}

	cfg := testConfig()
	// Add a server config since DefaultConfig has empty Servers slice
	if len(cfg.Servers) == 0 {
		cfg.Servers = append(cfg.Servers, config.ServerConfig{
			ListenAddr: ":25",
		})
	}
	cfg.Servers[0].Delivery = config.DeliveryConfig{
		URL:                badRequestServer.URL,
		AuthToken:          "test-token",
		MaxRetryAttempts:   1,
		HTTPTimeoutSeconds: 5,
	}

	statsManager := stats.NewManager(false, 0, "test", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer statsManager.Stop()

	session := &Session{
		ctx:            context.Background(),
		helo:           "test.example.com",
		from:           "sender@example.com",
		to:             []string{"recipient@example.com"},
		serverConfig:   &cfg.Servers[0],
		globalConfig:   cfg,
		statsManager:   statsManager,
		circuitBreaker: cb,
		httpClient:     httpClient,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteAddr:     "192.0.2.1:12345",
		traceID:        "trace-permanent",
	}

	err := session.deliverSynchronous("Subject: Test\r\n\r\nTest email")
	if err == nil {
		t.Fatal("Expected delivery to fail with 400 error")
	}

	// Should get permanent failure (550) because 400 is not retryable
	smtpErr, ok := err.(*smtp.SMTPError)
	if !ok {
		t.Fatalf("Expected *smtp.SMTPError, got %T: %v", err, err)
	}
	if smtpErr.Code != 550 {
		t.Errorf("Expected SMTP code 550 for permanent error, got %d", smtpErr.Code)
	}
	if smtpErr.EnhancedCode != (smtp.EnhancedCode{5, 4, 0}) {
		t.Errorf("Expected enhanced code 5.4.0, got %v", smtpErr.EnhancedCode)
	}

	// Circuit should still be closed (4xx errors don't trigger circuit breaker)
	if cb.GetState() != poster.StateClosed {
		t.Errorf("Expected circuit to remain Closed for non-retryable errors, got %v", cb.GetState())
	}

	t.Logf("✓ Permanent failure (400) correctly returned 550: %s", smtpErr.Message)
	t.Log("✓ Circuit breaker remained CLOSED (4xx errors don't count as failures)")
}

// TestCircuitBreakerIntegration_4xxErrorsDoNotTriggerCircuit verifies that
// 4xx errors (client errors) don't trigger the circuit breaker and return 550.
func TestCircuitBreakerIntegration_4xxErrorsDoNotTriggerCircuit(t *testing.T) {
	var requestCount atomic.Int32

	// Create a backend server that returns 404 Not Found
	notFoundServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusNotFound) // 404
		w.Write([]byte("Recipient not found"))
	}))
	defer notFoundServer.Close()

	cbConfig := poster.CircuitBreakerConfig{
		FailureThreshold: 5,
		SuccessThreshold: 2,
		Timeout:          30 * time.Second,
	}
	cb := poster.NewCircuitBreaker(cbConfig, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	httpClient := &http.Client{Timeout: 5 * time.Second}

	cfg := testConfig()
	// Add a server config since DefaultConfig has empty Servers slice
	if len(cfg.Servers) == 0 {
		cfg.Servers = append(cfg.Servers, config.ServerConfig{
			ListenAddr: ":25",
		})
	}
	cfg.Servers[0].Delivery = config.DeliveryConfig{
		URL:                notFoundServer.URL,
		AuthToken:          "test-token",
		MaxRetryAttempts:   1,
		HTTPTimeoutSeconds: 5,
	}

	statsManager := stats.NewManager(false, 0, "test", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer statsManager.Stop()

	session := &Session{
		ctx:            context.Background(),
		helo:           "test.example.com",
		from:           "sender@example.com",
		to:             []string{"unknown@example.com"},
		serverConfig:   &cfg.Servers[0],
		globalConfig:   cfg,
		statsManager:   statsManager,
		circuitBreaker: cb,
		httpClient:     httpClient,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteAddr:     "192.0.2.1:12345",
		traceID:        "trace-404",
		distTracker:    nil, // No distributed tracker (404 falls through to generic error)
	}

	err := session.deliverSynchronous("Subject: Test\r\n\r\nTest email")
	if err == nil {
		t.Fatal("Expected delivery to fail with 404 error")
	}

	// Without distTracker, 404 returns generic permanent failure (550 5.4.0)
	smtpErr, ok := err.(*smtp.SMTPError)
	if !ok {
		t.Fatalf("Expected *smtp.SMTPError, got %T: %v", err, err)
	}
	if smtpErr.Code != 550 {
		t.Errorf("Expected SMTP code 550 for 4xx error, got %d", smtpErr.Code)
	}
	if smtpErr.EnhancedCode != (smtp.EnhancedCode{5, 4, 0}) {
		t.Errorf("Expected enhanced code 5.4.0 (permanent failure), got %v", smtpErr.EnhancedCode)
	}
	if smtpErr.Message != "Message delivery failed" {
		t.Errorf("Expected 'Message delivery failed' message, got: %s", smtpErr.Message)
	}

	// Verify backend was called
	if requestCount.Load() != 1 {
		t.Errorf("Expected backend to be called once, got %d calls", requestCount.Load())
	}

	// Circuit should remain closed (4xx errors are permanent, not circuit breaker triggers)
	if cb.GetState() != poster.StateClosed {
		t.Errorf("Expected circuit to remain Closed for 4xx errors, got %v", cb.GetState())
	}

	t.Logf("✓ 404 error correctly returned 550 5.4.0: %s", smtpErr.Message)
	t.Log("✓ Circuit breaker remained CLOSED (4xx errors don't trigger circuit breaker)")
}

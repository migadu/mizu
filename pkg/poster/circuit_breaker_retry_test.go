package poster

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestCircuitBreaker_RetriesContinueWhenOpen verifies that retries continue
// even when the circuit breaker opens during the retry sequence.
// This is critical for preventing message loss.
func TestCircuitBreaker_RetriesContinueWhenOpen(t *testing.T) {
	var attemptCount atomic.Int32

	// Backend that fails twice (opens circuit) then succeeds
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := attemptCount.Add(1)
		if count <= 2 {
			// First 2 attempts fail to trigger circuit breaker
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("Backend unavailable"))
		} else {
			// Third attempt succeeds (even though circuit is open)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}
	}))
	defer backend.Close()

	// Circuit breaker with low threshold (opens after 2 failures)
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 1,
		Timeout:          1 * time.Second,
		HalfOpenMaxCalls: 1,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	httpClient := &http.Client{Timeout: 5 * time.Second}

	// Try to post email with 3 retry attempts
	err := PostEmailToDestinationWithContext(
		context.Background(),
		"Subject: Test\r\n\r\nTest email",
		backend.URL,
		"test-key",
		3, // 3 retry attempts
		false,
		"sender@example.com",
		"recipient@example.com",
		"test-trace",
		"",
		cb,
		httpClient,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
	)

	// Should succeed even though circuit opened during retries
	if err != nil {
		t.Fatalf("Expected delivery to succeed after retries, got error: %v", err)
	}

	// Verify all 3 attempts were made
	if attemptCount.Load() != 3 {
		t.Errorf("Expected 3 attempts, got %d", attemptCount.Load())
	}

	// Verify circuit is now closed (recovered)
	if cb.GetState() != StateClosed {
		t.Errorf("Expected circuit to be Closed after success, got %v", cb.GetState())
	}

	t.Log("✓ Retries continued even after circuit opened, message delivered successfully")
}

// TestCircuitBreaker_AllRetriesFailWithCircuitOpen verifies that when all
// retries fail (including when circuit is open), a retryable error is returned
// so the sender can retry.
func TestCircuitBreaker_AllRetriesFailWithCircuitOpen(t *testing.T) {
	var attemptCount atomic.Int32

	// Backend that always fails
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Backend down"))
	}))
	defer backend.Close()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 1,
		Timeout:          1 * time.Second,
		HalfOpenMaxCalls: 1,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	httpClient := &http.Client{Timeout: 5 * time.Second}

	err := PostEmailToDestinationWithContext(
		context.Background(),
		"Subject: Test\r\n\r\nTest email",
		backend.URL,
		"test-key",
		3,
		false,
		"sender@example.com",
		"recipient@example.com",
		"test-trace",
		"",
		cb,
		httpClient,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
	)

	// Should fail after all retries exhausted
	if err == nil {
		t.Fatal("Expected delivery to fail after all retries, got success")
	}

	// Should be a retryable error
	if !IsRetryableError(err) {
		t.Errorf("Expected retryable error, got: %v", err)
	}

	// Verify all 3 attempts were made (circuit breaker didn't prevent retries)
	if attemptCount.Load() != 3 {
		t.Errorf("Expected 3 attempts even with circuit open, got %d", attemptCount.Load())
	}

	t.Log("✓ All retries attempted even with circuit open, returned retryable error for sender to retry")
}

// TestCircuitBreaker_OpensButRecoversInRetryWindow verifies that if the
// circuit opens but transitions to half-open during the retry window, the
// message can still be delivered.
func TestCircuitBreaker_OpensButRecoversInRetryWindow(t *testing.T) {
	var attemptCount atomic.Int32

	// Backend that fails twice then succeeds
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := attemptCount.Add(1)
		if count <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer backend.Close()

	// Circuit with very short timeout (100ms) so it recovers quickly
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 1,
		Timeout:          100 * time.Millisecond, // Short timeout for test
		HalfOpenMaxCalls: 1,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	httpClient := &http.Client{Timeout: 5 * time.Second}

	start := time.Now()
	err := PostEmailToDestinationWithContext(
		context.Background(),
		"Subject: Test\r\n\r\nTest email",
		backend.URL,
		"test-key",
		5, // More retries to allow circuit to recover
		false,
		"sender@example.com",
		"recipient@example.com",
		"test-trace",
		"",
		cb,
		httpClient,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
	)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Expected delivery to succeed after circuit recovery, got error: %v", err)
	}

	// Should have taken long enough for circuit to open then recover
	if elapsed < 100*time.Millisecond {
		t.Errorf("Expected retry delay for circuit recovery, took only %v", elapsed)
	}

	t.Logf("✓ Circuit opened after 2 failures, recovered during retry window, message delivered (took %v)", elapsed)
}

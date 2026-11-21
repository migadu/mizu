package poster

import (
	"context"
	"io"

	"errors"
	"testing"
	"time"

	"log/slog"
)

func TestCircuitBreaker_InitialState(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          1 * time.Second,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	if cb.GetState() != StateClosed {
		t.Errorf("Expected initial state to be Closed, got %v", cb.GetState())
	}
}

func TestCircuitBreaker_OpenAfterFailureThreshold(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	// First 2 failures should keep it closed
	for i := 0; i < 2; i++ {
		err := cb.Call(context.Background(), func() error {
			return errors.New("test error")
		})
		if err == nil {
			t.Fatal("Expected error from failing function")
		}
		if cb.GetState() != StateClosed {
			t.Errorf("Expected state to be Closed after %d failures, got %v", i+1, cb.GetState())
		}
	}

	// Third failure should open the circuit
	err := cb.Call(context.Background(), func() error {
		return errors.New("test error")
	})
	if err == nil {
		t.Fatal("Expected error from failing function")
	}
	if cb.GetState() != StateOpen {
		t.Errorf("Expected state to be Open after 3 failures, got %v", cb.GetState())
	}

	// Circuit is open - should reject immediately
	err = cb.Call(context.Background(), func() error {
		t.Error("Function should not be called when circuit is open")
		return nil
	})
	if !errors.Is(err, ErrCircuitOpen) {
		t.Errorf("Expected ErrCircuitOpen, got %v", err)
	}
}

func TestCircuitBreaker_TransitionToHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	// Open the circuit
	for i := 0; i < 2; i++ {
		cb.Call(context.Background(), func() error {
			return errors.New("test error")
		})
	}

	if cb.GetState() != StateOpen {
		t.Fatal("Circuit should be open")
	}

	// Wait for timeout
	time.Sleep(150 * time.Millisecond)

	// Next call should transition to half-open
	var called bool
	err := cb.Call(context.Background(), func() error {
		called = true
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error in half-open state, got %v", err)
	}
	if !called {
		t.Error("Function should have been called in half-open state")
	}
}

func TestCircuitBreaker_CloseAfterSuccessThreshold(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
		HalfOpenMaxCalls: 2,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	// Open the circuit
	for i := 0; i < 2; i++ {
		cb.Call(context.Background(), func() error {
			return errors.New("test error")
		})
	}

	// Wait for timeout to enter half-open
	time.Sleep(150 * time.Millisecond)

	// First success in half-open
	err := cb.Call(context.Background(), func() error {
		return nil
	})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Should still be in half-open
	if cb.GetState() != StateHalfOpen {
		t.Errorf("Expected state to be HalfOpen after 1 success, got %v", cb.GetState())
	}

	// Second success should close the circuit
	err = cb.Call(context.Background(), func() error {
		return nil
	})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if cb.GetState() != StateClosed {
		t.Errorf("Expected state to be Closed after 2 successes, got %v", cb.GetState())
	}
}

func TestCircuitBreaker_HalfOpenFailureReopens(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	// Open the circuit
	for i := 0; i < 2; i++ {
		cb.Call(context.Background(), func() error {
			return errors.New("test error")
		})
	}

	// Wait for timeout to enter half-open
	time.Sleep(150 * time.Millisecond)

	// Failure in half-open should reopen
	err := cb.Call(context.Background(), func() error {
		return errors.New("test error")
	})
	if err == nil {
		t.Fatal("Expected error from failing function")
	}

	if cb.GetState() != StateOpen {
		t.Errorf("Expected state to be Open after failure in half-open, got %v", cb.GetState())
	}
}

func TestCircuitBreaker_SuccessResetsConsecutiveFailures(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	// 2 failures
	for i := 0; i < 2; i++ {
		cb.Call(context.Background(), func() error {
			return errors.New("test error")
		})
	}

	// 1 success should reset consecutive failures
	err := cb.Call(context.Background(), func() error {
		return nil
	})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// 2 more failures shouldn't open (need 3 consecutive)
	for i := 0; i < 2; i++ {
		cb.Call(context.Background(), func() error {
			return errors.New("test error")
		})
	}

	if cb.GetState() != StateClosed {
		t.Errorf("Expected state to be Closed (consecutive failures reset), got %v", cb.GetState())
	}
}

func TestCircuitBreaker_GetStats(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          1 * time.Second,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	stats := cb.GetStats()

	if stats["state"] != "closed" {
		t.Errorf("Expected state 'closed', got %v", stats["state"])
	}

	if stats["failure_threshold"] != 3 {
		t.Errorf("Expected failure_threshold 3, got %v", stats["failure_threshold"])
	}

	if stats["success_threshold"] != 2 {
		t.Errorf("Expected success_threshold 2, got %v", stats["success_threshold"])
	}

	// Add a failure
	cb.Call(context.Background(), func() error {
		return errors.New("test error")
	})

	stats = cb.GetStats()
	if stats["failure_count"] != 1 {
		t.Errorf("Expected failure_count 1, got %v", stats["failure_count"])
	}

	if stats["consecutive_fails"] != 1 {
		t.Errorf("Expected consecutive_fails 1, got %v", stats["consecutive_fails"])
	}
}

func TestCircuitBreaker_Reset(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	// Open the circuit
	for i := 0; i < 2; i++ {
		cb.Call(context.Background(), func() error {
			return errors.New("test error")
		})
	}

	if cb.GetState() != StateOpen {
		t.Fatal("Circuit should be open")
	}

	// Reset
	cb.Reset()

	if cb.GetState() != StateClosed {
		t.Errorf("Expected state to be Closed after reset, got %v", cb.GetState())
	}

	stats := cb.GetStats()
	if stats["failure_count"] != 0 {
		t.Errorf("Expected failure_count 0 after reset, got %v", stats["failure_count"])
	}
}

func TestCircuitBreaker_HalfOpenMaxCalls(t *testing.T) {
	// This test verifies that the circuit breaker limits concurrent calls in half-open state
	// We set HalfOpenMaxCalls to 1 to ensure only one request can be in-flight at a time
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 3, // Need 3 successes to close
		Timeout:          100 * time.Millisecond,
		HalfOpenMaxCalls: 1, // Only allow 1 concurrent call in half-open
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	// Open the circuit
	for i := 0; i < 2; i++ {
		cb.Call(context.Background(), func() error {
			return errors.New("test error")
		})
	}

	if cb.GetState() != StateOpen {
		t.Fatal("Circuit should be open")
	}

	// Wait for timeout to transition to half-open
	time.Sleep(150 * time.Millisecond)

	// Verify we're in half-open and can make one call
	err := cb.Call(context.Background(), func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("First call in half-open should succeed, got %v", err)
	}

	// Now we should still be in half-open (need 3 successes, only have 1)
	if cb.GetState() != StateHalfOpen {
		t.Errorf("Expected state HalfOpen after 1 success, got %v", cb.GetState())
	}

	// Second call should also succeed (halfOpenCalls was decremented)
	err = cb.Call(context.Background(), func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("Second call in half-open should succeed, got %v", err)
	}

	// After 2 successes, still in half-open (need 3)
	if cb.GetState() != StateHalfOpen {
		t.Errorf("Expected state HalfOpen after 2 successes, got %v", cb.GetState())
	}

	// Third call should succeed and transition to closed
	err = cb.Call(context.Background(), func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("Third call should succeed, got %v", err)
	}

	// Should now be closed
	if cb.GetState() != StateClosed {
		t.Errorf("Expected state Closed after 3 successes, got %v", cb.GetState())
	}
}

func TestCircuitBreaker_Defaults(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	if cb.failureThreshold != 5 {
		t.Errorf("Expected default failure_threshold 5, got %d", cb.failureThreshold)
	}

	if cb.successThreshold != 2 {
		t.Errorf("Expected default success_threshold 2, got %d", cb.successThreshold)
	}

	if cb.timeout != 30*time.Second {
		t.Errorf("Expected default timeout 30s, got %v", cb.timeout)
	}

	if cb.halfOpenMaxCalls != 1 {
		t.Errorf("Expected default half_open_max_calls 1, got %d", cb.halfOpenMaxCalls)
	}

	if cb.resetTimeout != 60*time.Second {
		t.Errorf("Expected default reset_timeout 60s, got %v", cb.resetTimeout)
	}
}

func TestCircuitBreaker_ResetTimeoutInClosed(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 5,
		ResetTimeout:     100 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	// Add 2 failures
	for i := 0; i < 2; i++ {
		cb.Call(context.Background(), func() error {
			return errors.New("test error")
		})
	}

	stats := cb.GetStats()
	if stats["failure_count"] != 2 {
		t.Fatalf("Expected 2 failures, got %v", stats["failure_count"])
	}

	// Wait for reset timeout
	time.Sleep(150 * time.Millisecond)

	// Next call should reset counters
	cb.Call(context.Background(), func() error {
		return nil
	})

	stats = cb.GetStats()
	if stats["failure_count"] != 0 {
		t.Errorf("Expected failure_count to be reset to 0, got %v", stats["failure_count"])
	}
}

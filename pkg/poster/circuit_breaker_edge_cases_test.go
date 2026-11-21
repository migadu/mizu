package poster

import (
	"context"
	"io"

	"errors"
	"sync"
	"testing"
	"time"

	"log/slog"
)

// TestCircuitBreaker_HalfOpenCallsNeverNegative ensures halfOpenCalls counter never goes negative
func TestCircuitBreaker_HalfOpenCallsNeverNegative(t *testing.T) {
	config := CircuitBreakerConfig{
		Enabled:          true,
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
		HalfOpenMaxCalls: 1,
		ResetTimeout:     1 * time.Second,
	}

	cb := NewCircuitBreaker(config, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	// Force circuit to Open state by triggering failures
	for i := 0; i < 3; i++ {
		cb.Call(context.Background(), func() error {
			return errors.New("failure")
		})
	}

	// Verify circuit is Open
	cb.mu.RLock()
	if cb.state != StateOpen {
		t.Fatalf("Expected Open state, got %s", cb.state)
	}
	cb.mu.RUnlock()

	// Wait for transition to Half-Open
	time.Sleep(150 * time.Millisecond)

	// First call in Half-Open - should increment halfOpenCalls to 1
	err := cb.Call(context.Background(), func() error {
		return nil // Success
	})
	if err != nil {
		t.Errorf("First Half-Open call failed: %v", err)
	}

	// Check halfOpenCalls is 0 (decremented from 1)
	cb.mu.RLock()
	if cb.halfOpenCalls < 0 {
		t.Errorf("halfOpenCalls went negative: %d", cb.halfOpenCalls)
	}
	cb.mu.RUnlock()

	// Second successful call (should close circuit if successThreshold=2)
	err = cb.Call(context.Background(), func() error {
		return nil
	})
	if err != nil {
		t.Errorf("Second call failed: %v", err)
	}

	// Verify circuit transitioned to Closed and halfOpenCalls is not negative
	cb.mu.RLock()
	finalState := cb.state
	finalHalfOpenCalls := cb.halfOpenCalls
	cb.mu.RUnlock()

	if finalState != StateClosed {
		t.Errorf("Expected Closed state after successes, got %s", finalState)
	}

	if finalHalfOpenCalls < 0 {
		t.Errorf("CRITICAL: halfOpenCalls is negative: %d", finalHalfOpenCalls)
	}

	t.Logf("✅ halfOpenCalls never went negative (final value: %d)", finalHalfOpenCalls)
}

// TestCircuitBreaker_ConcurrentHalfOpenCalls tests race conditions in half-open state
func TestCircuitBreaker_ConcurrentHalfOpenCalls(t *testing.T) {
	config := CircuitBreakerConfig{
		Enabled:          true,
		FailureThreshold: 2,
		SuccessThreshold: 1,
		Timeout:          100 * time.Millisecond,
		HalfOpenMaxCalls: 1, // Only 1 concurrent call allowed
		ResetTimeout:     1 * time.Second,
	}

	cb := NewCircuitBreaker(config, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	// Force to Open state
	cb.Call(context.Background(), func() error { return errors.New("fail") })
	cb.Call(context.Background(), func() error { return errors.New("fail") })

	// Wait for Half-Open
	time.Sleep(150 * time.Millisecond)

	// Launch 10 concurrent requests in Half-Open state
	var wg sync.WaitGroup
	successCount := 0
	rejectedCount := 0
	var mu sync.Mutex

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := cb.Call(context.Background(), func() error {
				time.Sleep(10 * time.Millisecond) // Simulate work
				return nil
			})

			mu.Lock()
			if err == ErrCircuitOpen {
				rejectedCount++
			} else {
				successCount++
			}
			mu.Unlock()
		}()
	}

	wg.Wait()

	// With SuccessThreshold=1, after first success circuit closes, allowing more through
	// So we expect 1-2 successes (race between state transition and concurrent calls)
	if successCount < 1 || successCount > 3 {
		t.Errorf("Expected 1-3 successes (due to state transition), got %d", successCount)
	}

	if successCount+rejectedCount != 10 {
		t.Errorf("Total calls should be 10, got %d", successCount+rejectedCount)
	}

	// Check halfOpenCalls is never negative
	cb.mu.RLock()
	finalHalfOpenCalls := cb.halfOpenCalls
	cb.mu.RUnlock()

	if finalHalfOpenCalls < 0 {
		t.Errorf("CRITICAL: halfOpenCalls went negative under concurrency: %d", finalHalfOpenCalls)
	}

	t.Logf("✅ Concurrent access safe: %d succeeded, %d rejected, halfOpenCalls=%d",
		successCount, rejectedCount, finalHalfOpenCalls)
}

// TestCircuitBreaker_HalfOpenFailureResetsCounter ensures failure in half-open properly resets counter
func TestCircuitBreaker_HalfOpenFailureResetsCounter(t *testing.T) {
	config := CircuitBreakerConfig{
		Enabled:          true,
		FailureThreshold: 2,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
		HalfOpenMaxCalls: 2,
		ResetTimeout:     1 * time.Second,
	}

	cb := NewCircuitBreaker(config, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	// Force to Open
	cb.Call(context.Background(), func() error { return errors.New("fail") })
	cb.Call(context.Background(), func() error { return errors.New("fail") })

	// Wait for Half-Open
	time.Sleep(150 * time.Millisecond)

	// First call succeeds - increments and decrements
	cb.Call(context.Background(), func() error { return nil })

	// Check state is still Half-Open (needs 2 successes)
	cb.mu.RLock()
	state1 := cb.state
	calls1 := cb.halfOpenCalls
	cb.mu.RUnlock()

	if state1 != StateHalfOpen {
		t.Errorf("Expected Half-Open after 1 success, got %s", state1)
	}

	// Second call fails - should reset to Open and reset halfOpenCalls to 0
	cb.Call(context.Background(), func() error { return errors.New("fail") })

	cb.mu.RLock()
	state2 := cb.state
	calls2 := cb.halfOpenCalls
	cb.mu.RUnlock()

	if state2 != StateOpen {
		t.Errorf("Expected Open after failure in Half-Open, got %s", state2)
	}

	if calls2 != 0 {
		t.Errorf("Expected halfOpenCalls=0 after reset, got %d", calls2)
	}

	if calls1 < 0 || calls2 < 0 {
		t.Errorf("CRITICAL: halfOpenCalls went negative: calls1=%d, calls2=%d", calls1, calls2)
	}

	t.Logf("✅ Failure in Half-Open properly resets counter: before=%d, after=%d", calls1, calls2)
}

// TestCircuitBreaker_StateTransitions validates all state transitions maintain invariants
func TestCircuitBreaker_StateTransitions(t *testing.T) {
	config := CircuitBreakerConfig{
		Enabled:          true,
		FailureThreshold: 2,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
		HalfOpenMaxCalls: 1,
		ResetTimeout:     1 * time.Second,
	}

	cb := NewCircuitBreaker(config, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	checkInvariants := func(stage string) {
		cb.mu.RLock()
		defer cb.mu.RUnlock()

		if cb.halfOpenCalls < 0 {
			t.Errorf("[%s] CRITICAL: halfOpenCalls is negative: %d", stage, cb.halfOpenCalls)
		}

		if cb.failureCount < 0 {
			t.Errorf("[%s] CRITICAL: failureCount is negative: %d", stage, cb.failureCount)
		}

		if cb.successCount < 0 {
			t.Errorf("[%s] CRITICAL: successCount is negative: %d", stage, cb.successCount)
		}

		if cb.consecutiveFails < 0 {
			t.Errorf("[%s] CRITICAL: consecutiveFails is negative: %d", stage, cb.consecutiveFails)
		}

		// In Half-Open, halfOpenCalls should never exceed halfOpenMaxCalls
		if cb.state == StateHalfOpen && cb.halfOpenCalls > cb.halfOpenMaxCalls {
			t.Errorf("[%s] CRITICAL: halfOpenCalls (%d) exceeds max (%d)",
				stage, cb.halfOpenCalls, cb.halfOpenMaxCalls)
		}
	}

	// Test sequence: Closed → Open → Half-Open → Closed
	checkInvariants("Initial")

	// Closed → Open (2 failures)
	cb.Call(context.Background(), func() error { return errors.New("fail1") })
	checkInvariants("After 1 failure")

	cb.Call(context.Background(), func() error { return errors.New("fail2") })
	checkInvariants("After 2 failures (should be Open)")

	// Open → Half-Open (wait timeout)
	time.Sleep(150 * time.Millisecond)
	checkInvariants("After timeout (before Half-Open call)")

	// Half-Open → Closed (2 successes)
	cb.Call(context.Background(), func() error { return nil })
	checkInvariants("After 1 success in Half-Open")

	cb.Call(context.Background(), func() error { return nil })
	checkInvariants("After 2 successes (should be Closed)")

	cb.mu.RLock()
	finalState := cb.state
	cb.mu.RUnlock()

	if finalState != StateClosed {
		t.Errorf("Expected final state Closed, got %s", finalState)
	}

	t.Log("✅ All invariants maintained through state transitions")
}

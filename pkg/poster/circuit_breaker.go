package poster

import (
	"context"
	"io"

	"errors"
	"sync"
	"time"

	"migadu/mizu/pkg/health"
	"migadu/mizu/pkg/metrics"

	"log/slog"
)

var (
	// ErrCircuitOpen is returned when the circuit breaker is open (too many failures)
	ErrCircuitOpen = errors.New("circuit breaker is open - too many recent failures")
)

// CircuitState represents the state of the circuit breaker
type CircuitState string

const (
	StateClosed   CircuitState = "closed"    // Normal operation, requests allowed
	StateOpen     CircuitState = "open"      // Too many failures, requests blocked
	StateHalfOpen CircuitState = "half_open" // Testing if service recovered
)

// CircuitBreaker implements the circuit breaker pattern to prevent cascading failures.
// It tracks success/failure rates and "opens" to fail fast when the destination is unhealthy.
type CircuitBreaker struct {
	mu sync.RWMutex

	// Configuration
	failureThreshold int           // Number of failures before opening
	successThreshold int           // Number of successes in half-open to close
	timeout          time.Duration // How long to stay open before trying half-open
	halfOpenMaxCalls int           // Max concurrent requests in half-open state
	resetTimeout     time.Duration // How long to wait before resetting counters

	// State
	state            CircuitState
	failureCount     int
	successCount     int
	consecutiveFails int
	lastFailureTime  time.Time
	lastStateChange  time.Time
	halfOpenCalls    int

	// Logging and metrics
	logger  *slog.Logger
	metrics *metrics.Metrics
}

// CircuitBreakerConfig holds configuration for the circuit breaker
type CircuitBreakerConfig struct {
	Enabled          bool          `toml:"enabled"`
	FailureThreshold int           `toml:"failure_threshold"`   // failures before opening (default: 5)
	SuccessThreshold int           `toml:"success_threshold"`   // successes in half-open to close (default: 2)
	Timeout          time.Duration `toml:"timeout"`             // time to wait before half-open (default: 30s)
	HalfOpenMaxCalls int           `toml:"half_open_max_calls"` // max concurrent calls in half-open (default: 1)
	ResetTimeout     time.Duration `toml:"reset_timeout"`       // time before resetting counters (default: 60s)
}

// NewCircuitBreaker creates a new circuit breaker with the given configuration
func NewCircuitBreaker(config CircuitBreakerConfig, logger *slog.Logger, metrics *metrics.Metrics) *CircuitBreaker {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// Set defaults if not provided
	if config.FailureThreshold == 0 {
		config.FailureThreshold = 5
	}
	if config.SuccessThreshold == 0 {
		config.SuccessThreshold = 2
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.HalfOpenMaxCalls == 0 {
		config.HalfOpenMaxCalls = 1
	}
	if config.ResetTimeout == 0 {
		config.ResetTimeout = 60 * time.Second
	}

	cb := &CircuitBreaker{
		failureThreshold: config.FailureThreshold,
		successThreshold: config.SuccessThreshold,
		timeout:          config.Timeout,
		halfOpenMaxCalls: config.HalfOpenMaxCalls,
		resetTimeout:     config.ResetTimeout,
		state:            StateClosed,
		lastStateChange:  time.Now(),
		logger:           logger,
		metrics:          metrics,
	}

	// Initialize metrics state
	cb.updateMetricsState()

	return cb
}

// Call executes the given function through the circuit breaker.
// Returns ErrCircuitOpen if the circuit is open.
func (cb *CircuitBreaker) Call(ctx context.Context, fn func() error) error {
	// Check if we can proceed with the call
	allowed, probe := cb.canProceed()
	if !allowed {
		// Record rejection in metrics
		if cb.metrics != nil {
			cb.metrics.CircuitBreakerRejects.Inc()
		}
		return ErrCircuitOpen
	}

	// Execute the function and record the result
	err := fn()

	// The caller's own context ending (client disconnect, session deadline,
	// graceful shutdown) is not a backend-health signal: recording it could
	// trip the breaker against a perfectly healthy backend. That is judged by
	// ctx itself, never by the error's type - an http.Client timeout also
	// reports context.DeadlineExceeded, and a backend that hangs is exactly
	// what the breaker exists for.
	//
	// It still has to give its half-open probe slot back: returning without
	// doing so left the breaker in half-open with every slot taken, refusing
	// all traffic until restart.
	//
	// Only a call that took a probe slot gives one back: a call admitted while
	// the breaker was still closed, finishing after it went half-open, would
	// otherwise free a slot it never held and admit an extra probe.
	if err != nil && ctx.Err() != nil {
		if probe {
			cb.releaseProbe()
		}
		return err
	}

	// A per-message verdict (see isMessageVerdict) is the backend working: it
	// examined the message and refused it. That says nothing bad about backend
	// health - and counting it let any sender open the breaker for everyone
	// with a few messages to rejected recipients. Record it as a success for
	// the breaker; the caller still gets the error.
	var httpErr *HTTPStatusError
	if errors.As(err, &httpErr) && isMessageVerdict(httpErr.StatusCode) {
		cb.recordResult(nil)
		return err
	}

	cb.recordResult(err)

	return err
}

// isMessageVerdict reports whether an HTTP status is the backend's answer about
// one particular message - bad request, delivery not authorized, unknown
// recipient, too large, unprocessable - as opposed to a sign that the backend
// is refusing everything. The list is deliberately closed: a 401 (our delivery
// token is wrong), a redirect, or any status not named here counts as a
// failure, so a backend that answers every probe that way stays open.
func isMessageVerdict(status int) bool {
	switch status {
	case 400, 403, 404, 413, 422:
		return true
	}
	return false
}

// releaseProbe returns a half-open probe slot without recording an outcome,
// for a call that ended without telling us anything about the backend.
func (cb *CircuitBreaker) releaseProbe() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.state == StateHalfOpen && cb.halfOpenCalls > 0 {
		cb.halfOpenCalls--
	}
}

// canProceed determines if a request should be allowed based on circuit state.
// probe reports whether the call was admitted as a half-open probe and so holds
// one of the halfOpenCalls slots.
func (cb *CircuitBreaker) canProceed() (allowed, probe bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	switch cb.state {
	case StateClosed:
		// Check if we should reset counters (no failures for resetTimeout)
		if cb.failureCount > 0 && now.Sub(cb.lastFailureTime) > cb.resetTimeout {
			cb.failureCount = 0
			cb.consecutiveFails = 0
		}
		return true, false

	case StateOpen:
		// Check if timeout has elapsed, transition to half-open
		if now.Sub(cb.lastStateChange) >= cb.timeout {
			cb.logger.Info("Circuit breaker transitioning from Open to Half-Open")
			cb.state = StateHalfOpen
			cb.lastStateChange = now
			// Count this caller as the first probe. Starting at 0 would let a
			// concurrent goroutine also pass the halfOpenCalls < max check,
			// admitting halfOpenMaxCalls+1 probes to a recovering backend.
			cb.halfOpenCalls = 1
			cb.successCount = 0
			cb.updateMetricsState()
			return true, true
		}
		return false, false

	case StateHalfOpen:
		// Limit concurrent requests in half-open state
		if cb.halfOpenCalls < cb.halfOpenMaxCalls {
			cb.halfOpenCalls++
			return true, true
		}
		return false, false
	}

	return false, false
}

// recordResult records the success or failure of a request
func (cb *CircuitBreaker) recordResult(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	if err != nil {
		// Failure
		cb.failureCount++
		cb.consecutiveFails++
		cb.lastFailureTime = now

		// Record failure in metrics
		if cb.metrics != nil {
			cb.metrics.CircuitBreakerFailures.Inc()
		}

		switch cb.state {
		case StateClosed:
			// Check if we should open the circuit
			if cb.consecutiveFails >= cb.failureThreshold {
				cb.logger.Warn("Circuit breaker transitioning from Closed to Open", "failures", cb.consecutiveFails)
				cb.state = StateOpen
				cb.lastStateChange = now
				cb.updateMetricsState()
			}

		case StateHalfOpen:
			// Any failure in half-open goes back to open
			cb.logger.Warn("Circuit breaker transitioning from Half-Open to Open due to failure")
			cb.state = StateOpen
			cb.lastStateChange = now
			cb.halfOpenCalls = 0
			cb.successCount = 0
			cb.updateMetricsState()
		}
	} else {
		// Success
		cb.successCount++
		cb.consecutiveFails = 0 // Reset consecutive failure counter

		// Record success in metrics
		if cb.metrics != nil {
			cb.metrics.CircuitBreakerSuccesses.Inc()
		}

		switch cb.state {
		case StateHalfOpen:
			// Decrement half-open call counter (with defensive guard against negative)
			if cb.halfOpenCalls > 0 {
				cb.halfOpenCalls--
			}
			// Check if we have enough successes to close the circuit
			if cb.successCount >= cb.successThreshold {
				cb.logger.Info("Circuit breaker transitioning from Half-Open to Closed", "successes", cb.successCount)
				cb.state = StateClosed
				cb.lastStateChange = now
				cb.failureCount = 0
				cb.successCount = 0
				cb.updateMetricsState()
			}

		case StateClosed:
			// Reset failure count on success if we've been healthy for a while
			if now.Sub(cb.lastFailureTime) > cb.resetTimeout {
				cb.failureCount = 0
			}
		}
	}
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// GetStats returns current statistics about the circuit breaker
func (cb *CircuitBreaker) GetStats() map[string]interface{} {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	stats := map[string]interface{}{
		"state":             string(cb.state),
		"failure_count":     cb.failureCount,
		"success_count":     cb.successCount,
		"consecutive_fails": cb.consecutiveFails,
		"failure_threshold": cb.failureThreshold,
		"success_threshold": cb.successThreshold,
	}

	if cb.state == StateOpen {
		timeUntilHalfOpen := cb.timeout - time.Since(cb.lastStateChange)
		if timeUntilHalfOpen > 0 {
			stats["time_until_half_open"] = timeUntilHalfOpen.String()
		} else {
			stats["time_until_half_open"] = "transitioning..."
		}
	}

	return stats
}

// Reset manually resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = StateClosed
	cb.failureCount = 0
	cb.successCount = 0
	cb.consecutiveFails = 0
	cb.halfOpenCalls = 0
	cb.lastStateChange = time.Now()
}

// Name returns the component name for health checks
func (cb *CircuitBreaker) Name() string {
	return "circuit_breaker"
}

// CheckHealth returns the health status of the circuit breaker
// Status is "healthy" when closed, "degraded" when half-open, "unhealthy" when open
func (cb *CircuitBreaker) CheckHealth() health.ComponentStatus {
	stats := cb.GetStats()
	state := cb.GetState()

	var status string
	switch state {
	case StateClosed:
		status = "healthy"
	case StateHalfOpen:
		status = "degraded"
	case StateOpen:
		status = "unhealthy"
	default:
		status = "unknown"
	}

	return health.ComponentStatus{
		Status:  status,
		Details: stats,
	}
}

// updateMetricsState updates Prometheus metrics to reflect current circuit breaker state
// Must be called while holding cb.mu lock
func (cb *CircuitBreaker) updateMetricsState() {
	if cb.metrics == nil {
		return
	}

	// Reset all state gauges to 0
	cb.metrics.CircuitBreakerState.WithLabelValues("closed").Set(0)
	cb.metrics.CircuitBreakerState.WithLabelValues("open").Set(0)
	cb.metrics.CircuitBreakerState.WithLabelValues("half_open").Set(0)

	// Set current state to 1
	switch cb.state {
	case StateClosed:
		cb.metrics.CircuitBreakerState.WithLabelValues("closed").Set(1)
	case StateOpen:
		cb.metrics.CircuitBreakerState.WithLabelValues("open").Set(1)
	case StateHalfOpen:
		cb.metrics.CircuitBreakerState.WithLabelValues("half_open").Set(1)
	}
}

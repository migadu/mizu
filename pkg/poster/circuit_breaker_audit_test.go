package poster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Audit B6 (docs/security-audit-todo.md): a half-open probe that ended in a
// context error returned before recordResult, so its probe slot was never
// released. The breaker then sat in half-open with every slot taken and
// refused all deliveries until restart - exactly when the backend was slow
// enough to have opened it in the first place.
func TestAudit_HalfOpenProbeTimeoutDoesNotWedgeBreaker(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 1,
		Timeout:          20 * time.Millisecond,
		HalfOpenMaxCalls: 1,
	}, nil, nil)

	boom := errors.New("backend down")
	for i := 0; i < 2; i++ {
		_ = cb.Call(context.Background(), func() error { return boom })
	}
	if cb.GetState() != StateOpen {
		t.Fatalf("state = %v, want open", cb.GetState())
	}
	time.Sleep(30 * time.Millisecond)

	// The single half-open probe is abandoned by its caller (session deadline,
	// then client disconnect). A backend timeout is a different case: it
	// counts as a failed probe (TestAudit_BackendTimeoutOpensBreaker).
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctxErr := range []error{context.DeadlineExceeded, context.Canceled} {
		err := cb.Call(gone, func() error { return fmt.Errorf("post: %w", ctxErr) })
		if !errors.Is(err, ctxErr) {
			t.Fatalf("probe error = %v, want %v", err, ctxErr)
		}
	}

	// The backend is healthy again: the next call must be let through.
	called := false
	if err := cb.Call(context.Background(), func() error { called = true; return nil }); err != nil {
		t.Fatalf("call after a timed-out probe = %v, want it admitted", err)
	}
	if !called {
		t.Fatal("breaker is wedged: the call was never executed")
	}
	if cb.GetState() != StateClosed {
		t.Fatalf("state = %v, want closed after a successful probe", cb.GetState())
	}
}

// Audit B7: a 4xx from the backend is the backend working - it looked at the
// message and said no. Counting those as failures let any sender open the
// breaker for everyone with a handful of messages to rejected recipients.
func TestAudit_ClientErrorsDoNotOpenBreaker(t *testing.T) {
	for _, status := range []int{400, 403, 404, 413} {
		cb := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 3}, nil, nil)
		for i := 0; i < 20; i++ {
			_ = cb.Call(context.Background(), func() error { return NewHTTPStatusError(status, "no") })
		}
		if cb.GetState() != StateClosed {
			t.Errorf("status %d: state = %v after 20 responses, want closed", status, cb.GetState())
		}
	}
}

// Server-side failures still open it.
func TestAudit_ServerErrorsStillOpenBreaker(t *testing.T) {
	for _, status := range []int{429, 500, 502, 503} {
		cb := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 3}, nil, nil)
		for i := 0; i < 3; i++ {
			_ = cb.Call(context.Background(), func() error { return NewHTTPStatusError(status, "down") })
		}
		if cb.GetState() != StateOpen {
			t.Errorf("status %d: state = %v after 3 responses, want open", status, cb.GetState())
		}
	}
}

// A 4xx is a real answer from a live backend, so it counts as a successful
// probe when the breaker is half-open.
func TestAudit_ClientErrorCountsAsBackendAlive(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 1,
		Timeout:          20 * time.Millisecond,
	}, nil, nil)
	for i := 0; i < 2; i++ {
		_ = cb.Call(context.Background(), func() error { return NewHTTPStatusError(503, "down") })
	}
	time.Sleep(30 * time.Millisecond)
	// Half-open probe answered with a 404: the backend is back.
	_ = cb.Call(context.Background(), func() error { return NewHTTPStatusError(404, "unknown recipient") })
	if cb.GetState() != StateClosed {
		t.Fatalf("state = %v, want closed: a 404 proves the backend is answering", cb.GetState())
	}
}

// Review follow-up: only statuses that are a verdict on one message count as
// "backend alive". A 401 (wrong delivery token) or a redirect is the backend
// refusing everything - probes answered that way must not close the breaker.
func TestAudit_NonVerdictStatusesAreBackendFailures(t *testing.T) {
	for _, status := range []int{301, 302, 401, 407, 418} {
		cb := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 3}, nil, nil)
		for i := 0; i < 3; i++ {
			_ = cb.Call(context.Background(), func() error { return NewHTTPStatusError(status, "no") })
		}
		if cb.GetState() != StateOpen {
			t.Errorf("status %d: state = %v after 3 responses, want open", status, cb.GetState())
		}
	}
}

// C14: an http.Client timeout satisfies errors.Is(err, context.DeadlineExceeded),
// and every context error was treated as "the caller went away, says nothing
// about the backend". A backend that hangs therefore never opened the breaker:
// every delivery waited out the full HTTP timeout. Only the caller's own
// context ending is not a health signal.
func TestAudit_BackendTimeoutOpensBreaker(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 3, Timeout: time.Minute}, nil, nil)
	timeout := fmt.Errorf("Post \"https://backend/ingest\": %w", context.DeadlineExceeded)

	for i := 0; i < 3; i++ {
		_ = cb.Call(context.Background(), func() error { return timeout })
	}
	if cb.GetState() != StateOpen {
		t.Fatalf("state = %v after 3 backend timeouts at threshold 3, want open", cb.GetState())
	}
}

func TestAudit_CallerCancellationDoesNotOpenBreaker(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 3, Timeout: time.Minute}, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for i := 0; i < 10; i++ {
		_ = cb.Call(ctx, func() error { return fmt.Errorf("post: %w", ctx.Err()) })
	}
	if cb.GetState() != StateClosed {
		t.Fatalf("state = %v after the caller's own context ended, want closed", cb.GetState())
	}
}

// B7: a backend timeout was treated like the caller hanging up - not
// retryable - so a slow backend got exactly one attempt however many were
// configured. Retrying is safe: the receiver drops a repeat carrying the same
// trace ID, and it is what the receiver's own retry window assumes.
func TestAudit_BackendTimeoutIsRetried(t *testing.T) {
	var hits atomic.Int32
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-release
	}))
	defer backend.Close()
	defer close(release)

	client := &http.Client{Timeout: 100 * time.Millisecond}
	err := PostEmailToDestinationWithContext(context.Background(), "Subject: x\r\n\r\nbody\r\n",
		backend.URL, "", 2, false, "a@b.test", "c@d.test", "trace", "", nil, client, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err == nil {
		t.Fatal("delivery to a hung backend succeeded")
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("backend saw %d attempts, want 2", got)
	}
}

// The caller's own context ending is still final: the SMTP client is gone or
// the session deadline has passed, and nobody is waiting for the answer.
func TestAudit_CallerCancellationIsNotRetried(t *testing.T) {
	var hits atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		cancel()
		w.WriteHeader(http.StatusServiceUnavailable) // retryable, were anyone still waiting
	}))
	defer backend.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	err := PostEmailToDestinationWithContext(ctx, "Subject: x\r\n\r\nbody\r\n",
		backend.URL, "", 3, false, "a@b.test", "c@d.test", "trace", "", nil, client, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err == nil {
		t.Fatal("delivery succeeded after the caller cancelled")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("backend saw %d attempts, want 1", got)
	}
}

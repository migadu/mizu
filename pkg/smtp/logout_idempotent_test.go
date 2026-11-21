package smtp

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"migadu/mizu/pkg/config"
)

// TestLogout_Idempotent verifies that calling Logout multiple times is safe.
// This is critical because NewSession calls prev.Logout() when a client
// re-issues EHLO, and go-smtp may also call Logout when the connection closes.
// Without idempotency the second call would double-release the tracker slot
// (leaking negative counts) and call sessionsWg.Done() twice (WaitGroup panic).
func TestLogout_Idempotent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tracker := NewConnectionTracker(100, 10, 0, nil)
	var wg sync.WaitGroup
	var sessionCount atomic.Int64

	remoteAddr := "192.168.1.1"

	// Acquire a connection slot (like NewSession does)
	lease1, err := tracker.Acquire(remoteAddr)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	wg.Add(1)
	sessionCount.Add(1)

	session := &Session{
		remoteAddr:   remoteAddr,
		connTracker:  tracker,
		connLease:    lease1,
		sessionsWg:   &wg,
		sessionCount: &sessionCount,
		Logger:       logger,
		serverConfig: &config.ServerConfig{Name: "test", Type: "relay"},
		globalConfig: &config.Config{Local: true},
		ctx:          context.Background(),
		cancel:       func() {},
	}

	// First Logout should release everything
	if err := session.Logout(); err != nil {
		t.Fatalf("First Logout returned error: %v", err)
	}

	// Verify counters after first Logout
	total, _, _ := tracker.GetStats()
	if total != 0 {
		t.Errorf("After first Logout: expected 0 tracker connections, got %d", total)
	}
	if count := sessionCount.Load(); count != 0 {
		t.Errorf("After first Logout: expected sessionCount=0, got %d", count)
	}

	// Second Logout should be a no-op (no panic, no double-release)
	if err := session.Logout(); err != nil {
		t.Fatalf("Second Logout returned error: %v", err)
	}

	// Counters should still be 0, NOT -1
	total, _, _ = tracker.GetStats()
	if total != 0 {
		t.Errorf("After second Logout: expected 0 tracker connections, got %d", total)
	}
	if count := sessionCount.Load(); count != 0 {
		t.Errorf("After second Logout: expected sessionCount=0, got %d", count)
	}

	// Third Logout for good measure
	if err := session.Logout(); err != nil {
		t.Fatalf("Third Logout returned error: %v", err)
	}

	// WaitGroup should not hang
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		t.Log("✓ WaitGroup correctly cleaned up after multiple Logout calls")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("❌ WaitGroup hung - Done() was not called or was called more than once")
	}
}

// TestLogout_Idempotent_WithDistributedTracker verifies idempotency with the distributed tracker path.
func TestLogout_Idempotent_WithDistributedTracker(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	localTracker := NewConnectionTracker(100, 10, 0, nil)
	distTracker := NewDistributedTracker(localTracker, nil, "", "", DistributedConfig{
		Hostname:       "test-node",
		GossipInterval: 5 * time.Second,
		S3SyncInterval: 30 * time.Second,
	}, logger)

	var wg sync.WaitGroup
	var sessionCount atomic.Int64

	remoteAddr := "10.0.0.1"

	// Acquire via distributed tracker
	lease2, err := distTracker.Acquire(remoteAddr)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	wg.Add(1)
	sessionCount.Add(1)

	session := &Session{
		remoteAddr:   remoteAddr,
		distTracker:  distTracker,
		connLease:    lease2,
		sessionsWg:   &wg,
		sessionCount: &sessionCount,
		Logger:       logger,
		serverConfig: &config.ServerConfig{Name: "test", Type: "relay"},
		globalConfig: &config.Config{Local: true},
		ctx:          context.Background(),
		cancel:       func() {},
	}

	// First Logout releases the slot
	session.Logout()

	total, _, _ := distTracker.GetStats()
	if total != 0 {
		t.Errorf("After first Logout: expected 0, got %d", total)
	}

	// Second Logout is a no-op
	session.Logout()

	total, _, _ = distTracker.GetStats()
	if total != 0 {
		t.Errorf("After second Logout: expected 0, got %d (double-release!)", total)
	}
	if count := sessionCount.Load(); count != 0 {
		t.Errorf("After second Logout: expected sessionCount=0, got %d", count)
	}

	// WaitGroup must not hang
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		t.Log("✓ Distributed tracker: idempotent Logout works correctly")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("❌ WaitGroup hung with distributed tracker")
	}
}

// TestLogout_SimulateReEHLO simulates the exact scenario that caused the
// connection leak: a client sends EHLO twice on the same connection (e.g.
// after STARTTLS). NewSession calls prev.Logout() on the old session and
// creates a new session. When the connection closes, Logout is called on
// the new session. The old session's Logout must not run twice.
func TestLogout_SimulateReEHLO(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tracker := NewConnectionTracker(100, 10, 0, nil)
	var wg sync.WaitGroup
	var sessionCount atomic.Int64

	remoteAddr := "172.16.0.1"

	// --- First EHLO: create session A ---
	lease3, err := tracker.Acquire(remoteAddr)
	if err != nil {
		t.Fatalf("Acquire for session A failed: %v", err)
	}
	wg.Add(1)
	sessionCount.Add(1)

	sessionA := &Session{
		remoteAddr:   remoteAddr,
		connTracker:  tracker,
		connLease:    lease3,
		sessionsWg:   &wg,
		sessionCount: &sessionCount,
		Logger:       logger,
		serverConfig: &config.ServerConfig{Name: "test", Type: "relay"},
		globalConfig: &config.Config{Local: true},
		ctx:          context.Background(),
		cancel:       func() {},
	}

	// Verify: 1 connection tracked
	total, _, _ := tracker.GetStats()
	if total != 1 {
		t.Fatalf("Expected 1 connection after session A, got %d", total)
	}

	// --- Second EHLO: NewSession calls prev.Logout() then creates session B ---
	// This is what NewSession does: prev.Logout()
	sessionA.Logout()

	// Verify: session A released its slot
	total, _, _ = tracker.GetStats()
	if total != 0 {
		t.Fatalf("Expected 0 connections after session A logout, got %d", total)
	}

	// NewSession acquires a new slot for session B
	lease4, err := tracker.Acquire(remoteAddr)
	if err != nil {
		t.Fatalf("Acquire for session B failed: %v", err)
	}
	wg.Add(1)
	sessionCount.Add(1)

	sessionB := &Session{
		remoteAddr:   remoteAddr,
		connTracker:  tracker,
		connLease:    lease4,
		sessionsWg:   &wg,
		sessionCount: &sessionCount,
		Logger:       logger,
		serverConfig: &config.ServerConfig{Name: "test", Type: "relay"},
		globalConfig: &config.Config{Local: true},
		ctx:          context.Background(),
		cancel:       func() {},
	}

	// Verify: 1 connection tracked (session B)
	total, _, _ = tracker.GetStats()
	if total != 1 {
		t.Fatalf("Expected 1 connection after session B created, got %d", total)
	}
	if count := sessionCount.Load(); count != 1 {
		t.Fatalf("Expected sessionCount=1, got %d", count)
	}

	// --- Connection closes: go-smtp calls Logout on session B ---
	sessionB.Logout()

	total, _, _ = tracker.GetStats()
	if total != 0 {
		t.Errorf("Expected 0 after session B logout, got %d", total)
	}
	if count := sessionCount.Load(); count != 0 {
		t.Errorf("Expected sessionCount=0 after session B logout, got %d", count)
	}

	// --- Edge case: go-smtp might also call Logout on session A again ---
	// With sync.Once this is a safe no-op
	sessionA.Logout()

	total, _, _ = tracker.GetStats()
	if total != 0 {
		t.Errorf("Expected 0 after redundant session A logout, got %d (double-release!)", total)
	}
	if count := sessionCount.Load(); count != 0 {
		t.Errorf("Expected sessionCount=0, got %d (double-decrement!)", count)
	}

	// WaitGroup must not hang
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		t.Log("✓ Re-EHLO scenario: no connection leak, no double-release, no WaitGroup panic")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("❌ WaitGroup hung in re-EHLO scenario")
	}
}

// TestLogout_ConcurrentCalls verifies that concurrent Logout calls are safe.
func TestLogout_ConcurrentCalls(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tracker := NewConnectionTracker(100, 10, 0, nil)
	var wg sync.WaitGroup
	var sessionCount atomic.Int64

	remoteAddr := "10.0.0.5"

	lease5, err := tracker.Acquire(remoteAddr)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	wg.Add(1)
	sessionCount.Add(1)

	session := &Session{
		remoteAddr:   remoteAddr,
		connTracker:  tracker,
		connLease:    lease5,
		sessionsWg:   &wg,
		sessionCount: &sessionCount,
		Logger:       logger,
		serverConfig: &config.ServerConfig{Name: "test", Type: "relay"},
		globalConfig: &config.Config{Local: true},
		ctx:          context.Background(),
		cancel:       func() {},
	}

	// Call Logout concurrently from 10 goroutines
	var race sync.WaitGroup
	for i := 0; i < 10; i++ {
		race.Add(1)
		go func() {
			defer race.Done()
			session.Logout()
		}()
	}
	race.Wait()

	// Verify exactly one release happened
	total, _, _ := tracker.GetStats()
	if total != 0 {
		t.Errorf("Expected 0 connections, got %d", total)
	}
	if count := sessionCount.Load(); count != 0 {
		t.Errorf("Expected sessionCount=0, got %d", count)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		t.Log("✓ Concurrent Logout calls: safe and correct")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("❌ WaitGroup hung after concurrent Logout calls")
	}
}

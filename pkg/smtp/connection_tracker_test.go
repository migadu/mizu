package smtp

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"
)

func TestConnectionTracker_GlobalLimit(t *testing.T) {
	tracker := NewConnectionTracker(3, 0, 0, nil) // Max 3 total, unlimited per IP

	// Acquire 3 connections from different IPs
	first, err := tracker.Acquire("192.168.1.1:1234")
	if err != nil {
		t.Errorf("Expected to acquire connection 1, got error: %v", err)
	}
	if _, err := tracker.Acquire("192.168.1.2:1234"); err != nil {
		t.Errorf("Expected to acquire connection 2, got error: %v", err)
	}
	if _, err := tracker.Acquire("192.168.1.3:1234"); err != nil {
		t.Errorf("Expected to acquire connection 3, got error: %v", err)
	}

	// 4th connection should fail
	if _, err := tracker.Acquire("192.168.1.4:1234"); err == nil {
		t.Error("Expected error when exceeding global limit, got nil")
	}

	// Release one connection
	first.Release()

	// Now should be able to acquire again
	if _, err := tracker.Acquire("192.168.1.4:1234"); err != nil {
		t.Errorf("Expected to acquire connection after release, got error: %v", err)
	}

	// Check stats
	total, uniqueIPs, _ := tracker.GetStats()
	if total != 3 {
		t.Errorf("Expected 3 total connections, got %d", total)
	}
	if uniqueIPs != 3 {
		t.Errorf("Expected 3 unique IPs, got %d", uniqueIPs)
	}
}

func TestConnectionTracker_PerIPLimit(t *testing.T) {
	tracker := NewConnectionTracker(0, 2, 0, nil) // Unlimited total, max 2 per IP

	// Acquire 2 connections from same IP
	first, err := tracker.Acquire("192.168.1.1:1234")
	if err != nil {
		t.Errorf("Expected to acquire connection 1, got error: %v", err)
	}
	if _, err := tracker.Acquire("192.168.1.1:5678"); err != nil {
		t.Errorf("Expected to acquire connection 2, got error: %v", err)
	}

	// 3rd connection from same IP should fail
	if _, err := tracker.Acquire("192.168.1.1:9999"); err == nil {
		t.Error("Expected error when exceeding per-IP limit, got nil")
	}

	// Different IP should work
	if _, err := tracker.Acquire("192.168.1.2:1234"); err != nil {
		t.Errorf("Expected to acquire connection from different IP, got error: %v", err)
	}

	// Release one connection from first IP
	first.Release()

	// Now should be able to acquire from that IP again
	if _, err := tracker.Acquire("192.168.1.1:9999"); err != nil {
		t.Errorf("Expected to acquire connection after release, got error: %v", err)
	}

	// Check stats
	total, uniqueIPs, perIP := tracker.GetStats()
	if total != 3 {
		t.Errorf("Expected 3 total connections, got %d", total)
	}
	if uniqueIPs != 2 {
		t.Errorf("Expected 2 unique IPs, got %d", uniqueIPs)
	}
	if perIP["192.168.1.1"] != 2 {
		t.Errorf("Expected 2 connections from 192.168.1.1, got %d", perIP["192.168.1.1"])
	}
}

func TestConnectionTracker_BothLimits(t *testing.T) {
	tracker := NewConnectionTracker(5, 2, 0, nil) // Max 5 total, max 2 per IP

	// Acquire 2 connections from IP1
	tracker.Acquire("192.168.1.1:1234")
	tracker.Acquire("192.168.1.1:5678")

	// 3rd from IP1 should fail (per-IP limit)
	if _, err := tracker.Acquire("192.168.1.1:9999"); err == nil {
		t.Error("Expected error for per-IP limit, got nil")
	}

	// Acquire 2 from IP2
	tracker.Acquire("192.168.1.2:1234")
	tracker.Acquire("192.168.1.2:5678")

	// Acquire 1 from IP3 (total = 5)
	tracker.Acquire("192.168.1.3:1234")

	// Next connection should fail (global limit)
	if _, err := tracker.Acquire("192.168.1.4:1234"); err == nil {
		t.Error("Expected error for global limit, got nil")
	}
}

func TestConnectionTracker_UnlimitedMode(t *testing.T) {
	tracker := NewConnectionTracker(0, 0, 0, nil) // Unlimited

	// Should accept many connections
	for i := 0; i < 1000; i++ {
		addr := fmt.Sprintf("192.168.1.1:%d", 1000+i)
		if _, err := tracker.Acquire(addr); err != nil {
			t.Errorf("Expected unlimited mode to accept connection, got error: %v", err)
		}
	}

	total, _, _ := tracker.GetStats()
	if total != 1000 {
		t.Errorf("Expected 1000 connections, got %d", total)
	}
}

func TestConnectionTracker_IPv6(t *testing.T) {
	tracker := NewConnectionTracker(0, 2, 0, nil) // Max 2 per IP

	// Test with IPv6 addresses
	if _, err := tracker.Acquire("[2001:db8::1]:1234"); err != nil {
		t.Errorf("Expected to acquire IPv6 connection 1, got error: %v", err)
	}
	if _, err := tracker.Acquire("[2001:db8::1]:5678"); err != nil {
		t.Errorf("Expected to acquire IPv6 connection 2, got error: %v", err)
	}

	// 3rd connection from same IPv6 should fail
	if _, err := tracker.Acquire("[2001:db8::1]:9999"); err == nil {
		t.Error("Expected error when exceeding per-IP limit for IPv6, got nil")
	}
}

func TestConnectionTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewConnectionTracker(100, 10, 0, nil)
	var wg sync.WaitGroup

	// Simulate concurrent connections and releases
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			addr := fmt.Sprintf("192.168.1.%d:1234", id%10) // 10 different IPs
			lease, err := tracker.Acquire(addr)
			if err != nil {
				// Expected if limit reached
				return
			}
			// Simulate some work
			lease.Release()
		}(i)
	}

	wg.Wait()

	// After all releases, should have 0 connections
	total, uniqueIPs, _ := tracker.GetStats()
	if total != 0 {
		t.Errorf("Expected 0 connections after all releases, got %d", total)
	}
	if uniqueIPs != 0 {
		t.Errorf("Expected 0 unique IPs after cleanup, got %d", uniqueIPs)
	}
}

func TestConnectionTracker_ReleaseNonExistent(t *testing.T) {
	tracker := NewConnectionTracker(10, 5, 0, nil)

	// Releasing a slot that was never acquired (a nil lease, as held by a
	// connection whose Acquire failed) should not panic or cause issues
	var none *ConnLease
	none.Release()

	total, uniqueIPs, _ := tracker.GetStats()
	if total != 0 {
		t.Errorf("Expected 0 connections, got %d", total)
	}
	if uniqueIPs != 0 {
		t.Errorf("Expected 0 unique IPs, got %d", uniqueIPs)
	}

	// Releasing a slot that is already gone must not underflow the counters
	// or take the slot of another connection from the same IP.
	gone, err := tracker.Acquire("192.168.1.1:1234")
	if err != nil {
		t.Fatalf("Expected to acquire connection, got error: %v", err)
	}
	if _, err := tracker.Acquire("192.168.1.1:5678"); err != nil {
		t.Fatalf("Expected to acquire second connection, got error: %v", err)
	}
	gone.Release()
	gone.Release()

	total, uniqueIPs, perIP := tracker.GetStats()
	if total != 1 {
		t.Errorf("Expected 1 connection after double release, got %d", total)
	}
	if uniqueIPs != 1 {
		t.Errorf("Expected 1 unique IP after double release, got %d", uniqueIPs)
	}
	if perIP["192.168.1.1"] != 1 {
		t.Errorf("Expected 1 connection from 192.168.1.1, got %d", perIP["192.168.1.1"])
	}
}

func TestConnectionTracker_GetLimits(t *testing.T) {
	tracker := NewConnectionTracker(50, 5, 0, nil)

	maxTotal, maxPerIP := tracker.GetLimits()
	if maxTotal != 50 {
		t.Errorf("Expected max total 50, got %d", maxTotal)
	}
	if maxPerIP != 5 {
		t.Errorf("Expected max per IP 5, got %d", maxPerIP)
	}
}

func TestConnectionTracker_MemoryLeak(t *testing.T) {
	tracker := NewConnectionTracker(1000, 10, 0, nil)

	// Acquire and release many connections
	for i := 0; i < 100; i++ {
		addr := fmt.Sprintf("192.168.1.%d:1234", i)
		lease, err := tracker.Acquire(addr)
		if err != nil {
			t.Fatalf("Expected to acquire connection for %s, got error: %v", addr, err)
		}
		lease.Release()
	}

	// Map should be empty after all releases
	_, uniqueIPs, _ := tracker.GetStats()
	if uniqueIPs != 0 {
		t.Errorf("Memory leak detected: expected 0 IPs in map, got %d", uniqueIPs)
	}
}

// TestConnectionTracker_ReaperForceRelease verifies that the reaper
// automatically force-releases connections that exceed MaxConnectionDuration.
// This prevents connection leaks from panics, half-open TCP connections,
// or go-smtp edge cases (like re-EHLO without Logout).
func TestConnectionTracker_ReaperForceRelease(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Create tracker with 2-second max duration
	maxDuration := 2 * time.Second
	tracker := NewConnectionTracker(100, 10, maxDuration, logger)
	tracker.Start()
	defer tracker.Stop()

	// Acquire connections from 3 different IPs
	ips := []string{
		"192.168.1.1:1234",
		"192.168.1.2:5678",
		"192.168.1.3:9999",
	}

	for _, ip := range ips {
		if _, err := tracker.Acquire(ip); err != nil {
			t.Fatalf("Failed to acquire connection for %s: %v", ip, err)
		}
	}

	// Verify connections are tracked
	total, uniqueIPs, perIP := tracker.GetStats()
	if total != 3 {
		t.Errorf("Expected 3 total connections, got %d", total)
	}
	if uniqueIPs != 3 {
		t.Errorf("Expected 3 unique IPs, got %d", uniqueIPs)
	}
	for _, ip := range ips {
		host := ip[:len(ip)-5] // Strip port
		if perIP[host] != 1 {
			t.Errorf("Expected 1 connection from %s, got %d", host, perIP[host])
		}
	}

	// Wait for reaper to run (maxDuration + grace period)
	// Reaper interval is maxDuration/2 = 1s, so it should run within 3s
	time.Sleep(3 * time.Second)

	// Verify all connections were force-released
	total, uniqueIPs, perIP = tracker.GetStats()
	if total != 0 {
		t.Errorf("Expected 0 connections after reaper, got %d (perIP: %v)", total, perIP)
	}
	if uniqueIPs != 0 {
		t.Errorf("Expected 0 unique IPs after reaper, got %d", uniqueIPs)
	}

	// Verify reaper stats
	health := tracker.CheckHealth()
	details, ok := health.Details.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected Details to be map[string]interface{}, got %T", health.Details)
	}
	if reaped, ok := details["total_reaped"].(uint64); !ok || reaped != 3 {
		t.Errorf("Expected 3 reaped connections in health stats, got %v", details["total_reaped"])
	}
}

// TestConnectionTracker_ReaperPartialRelease verifies that the reaper
// only releases expired connections, not all connections.
func TestConnectionTracker_ReaperPartialRelease(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelWarn, // Reduce noise
	}))

	maxDuration := 3 * time.Second
	tracker := NewConnectionTracker(100, 10, maxDuration, logger)
	tracker.Start()
	defer tracker.Stop()

	// Acquire 2 connections initially
	tracker.Acquire("192.168.1.1:1111")
	tracker.Acquire("192.168.1.2:2222")

	// Wait 2 seconds
	time.Sleep(2 * time.Second)

	// Acquire 2 more connections (these are newer)
	tracker.Acquire("192.168.1.3:3333")
	tracker.Acquire("192.168.1.4:4444")

	// Verify 4 total connections
	total, _, _ := tracker.GetStats()
	if total != 4 {
		t.Errorf("Expected 4 connections before reaper, got %d", total)
	}

	// Wait for reaper to run (first 2 connections should be expired by now)
	// maxDuration=3s, we waited 2s, so first 2 are at 2s age, need to wait 1.5s more
	time.Sleep(2 * time.Second)

	// Only the first 2 connections should be reaped (they're >3s old)
	total, uniqueIPs, _ := tracker.GetStats()
	if total != 2 {
		t.Errorf("Expected 2 connections remaining after partial reap, got %d", total)
	}
	if uniqueIPs != 2 {
		t.Errorf("Expected 2 unique IPs remaining, got %d", uniqueIPs)
	}

	// Verify reaper stats show 2 reaped
	health := tracker.CheckHealth()
	details, ok := health.Details.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected Details to be map[string]interface{}, got %T", health.Details)
	}
	if reaped, ok := details["total_reaped"].(uint64); !ok || reaped != 2 {
		t.Errorf("Expected 2 reaped connections, got %v", details["total_reaped"])
	}
}

// TestConnectionTracker_ReaperWithManualRelease verifies that manually
// released connections are not double-counted by the reaper.
func TestConnectionTracker_ReaperWithManualRelease(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	}))

	maxDuration := 2 * time.Second
	tracker := NewConnectionTracker(100, 10, maxDuration, logger)
	tracker.Start()
	defer tracker.Stop()

	// Acquire 3 connections
	tracker.Acquire("192.168.1.1:1111")
	second, err := tracker.Acquire("192.168.1.2:2222")
	if err != nil {
		t.Fatalf("Failed to acquire connection: %v", err)
	}
	tracker.Acquire("192.168.1.3:3333")

	// Manually release one connection
	second.Release()

	// Wait for reaper to run
	time.Sleep(3 * time.Second)

	// All connections should be gone (1 manual + 2 reaped)
	total, _, _ := tracker.GetStats()
	if total != 0 {
		t.Errorf("Expected 0 connections after manual release + reaper, got %d", total)
	}

	// Verify only 2 were reaped (not 3, since one was manually released)
	health := tracker.CheckHealth()
	details, ok := health.Details.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected Details to be map[string]interface{}, got %T", health.Details)
	}
	if reaped, ok := details["total_reaped"].(uint64); !ok || reaped != 2 {
		t.Errorf("Expected 2 reaped connections (not counting manual release), got %v", details["total_reaped"])
	}
}

// TestConnectionTracker_ReaperDisabled verifies that no reaping occurs
// when MaxConnectionDuration is 0 (disabled).
func TestConnectionTracker_ReaperDisabled(t *testing.T) {
	tracker := NewConnectionTracker(100, 10, 0, nil) // Reaper disabled
	tracker.Start()                                  // Should be no-op
	defer tracker.Stop()                             // Should be no-op

	// Acquire connections
	tracker.Acquire("192.168.1.1:1111")
	tracker.Acquire("192.168.1.2:2222")

	// Wait (reaper should not run)
	time.Sleep(1 * time.Second)

	// Connections should still be tracked (not reaped)
	total, _, _ := tracker.GetStats()
	if total != 2 {
		t.Errorf("Expected 2 connections (reaper disabled), got %d", total)
	}

	// Verify no reaping occurred
	health := tracker.CheckHealth()
	details, ok := health.Details.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected Details to be map[string]interface{}, got %T", health.Details)
	}
	if reaped, ok := details["total_reaped"].(uint64); !ok || reaped != 0 {
		t.Errorf("Expected 0 reaped connections when disabled, got %v", details["total_reaped"])
	}
}

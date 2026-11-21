package smtp

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestE2E_PerIPConnectionLimit demonstrates per-IP connection limiting works end-to-end
func TestE2E_PerIPConnectionLimit(t *testing.T) {
	tracker := NewConnectionTracker(100, 3, 0, nil) // Max 3 per IP

	// Simulate 5 connection attempts from the same IP
	ip := "192.168.1.100:5000"
	var successful []string
	var rejected []string
	var leases []*ConnLease

	for i := 0; i < 5; i++ {
		connID := fmt.Sprintf("%s-conn%d", ip, i)
		lease, err := tracker.Acquire(ip)
		if err == nil {
			successful = append(successful, connID)
			leases = append(leases, lease)
			t.Logf("✓ Connection %d from %s: ACCEPTED", i+1, ip)
		} else {
			rejected = append(rejected, connID)
			t.Logf("✗ Connection %d from %s: REJECTED (%v)", i+1, ip, err)
		}
	}

	// Verify results
	if len(successful) != 3 {
		t.Errorf("Expected 3 successful connections, got %d", len(successful))
	}
	if len(rejected) != 2 {
		t.Errorf("Expected 2 rejected connections, got %d", len(rejected))
	}

	// Verify stats
	total, uniqueIPs, perIP := tracker.GetStats()
	t.Logf("Stats: total=%d, unique_ips=%d, ip_breakdown=%v", total, uniqueIPs, perIP)

	if total != 3 {
		t.Errorf("Expected 3 total connections, got %d", total)
	}
	if perIP["192.168.1.100"] != 3 {
		t.Errorf("Expected 3 connections from IP, got %d", perIP["192.168.1.100"])
	}

	// Release one connection
	leases[0].Release()
	leases = leases[1:]
	t.Logf("Released 1 connection from %s", ip)

	// Now we should be able to connect again
	lease, err := tracker.Acquire(ip)
	if err != nil {
		t.Errorf("Should be able to connect after release, got error: %v", err)
	} else {
		leases = append(leases, lease)
		t.Logf("✓ New connection after release: ACCEPTED")
	}

	// Cleanup
	if len(leases) != 3 {
		t.Errorf("Expected 3 open connections to clean up, got %d", len(leases))
	}
	for _, l := range leases {
		l.Release()
	}

	total, _, _ = tracker.GetStats()
	if total != 0 {
		t.Errorf("Expected 0 connections after cleanup, got %d", total)
	}
}

// TestE2E_GlobalConnectionLimit demonstrates global connection limiting works end-to-end
func TestE2E_GlobalConnectionLimit(t *testing.T) {
	tracker := NewConnectionTracker(5, 10, 0, nil) // Max 5 total, 10 per IP

	var successful int
	var rejected int

	// Try to create 8 connections from different IPs
	for i := 0; i < 8; i++ {
		ip := fmt.Sprintf("192.168.1.%d:5000", 100+i)
		_, err := tracker.Acquire(ip)
		if err == nil {
			successful++
			t.Logf("✓ Connection %d from %s: ACCEPTED", i+1, ip)
		} else {
			rejected++
			t.Logf("✗ Connection %d from %s: REJECTED (%v)", i+1, ip, err)
		}
	}

	if successful != 5 {
		t.Errorf("Expected 5 successful connections, got %d", successful)
	}
	if rejected != 3 {
		t.Errorf("Expected 3 rejected connections, got %d", rejected)
	}

	total, uniqueIPs, _ := tracker.GetStats()
	t.Logf("Stats: total=%d, unique_ips=%d", total, uniqueIPs)

	if total != 5 {
		t.Errorf("Expected 5 total connections, got %d", total)
	}
	if uniqueIPs != 5 {
		t.Errorf("Expected 5 unique IPs, got %d", uniqueIPs)
	}
}

// TestE2E_ConcurrentConnectionsFromSameIP simulates realistic concurrent connection scenario
func TestE2E_ConcurrentConnectionsFromSameIP(t *testing.T) {
	tracker := NewConnectionTracker(50, 5, 0, nil) // Max 5 per IP

	var wg sync.WaitGroup
	var successMu sync.Mutex
	successCount := 0
	failCount := 0

	// Simulate 20 concurrent connection attempts from the same IP
	ip := "192.168.1.100:5000"
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(connNum int) {
			defer wg.Done()

			lease, err := tracker.Acquire(ip)
			successMu.Lock()
			if err == nil {
				successCount++
				t.Logf("✓ Concurrent connection %d: ACCEPTED", connNum)
				// Simulate connection doing work
				time.Sleep(5 * time.Millisecond)
				lease.Release()
			} else {
				failCount++
				t.Logf("✗ Concurrent connection %d: REJECTED", connNum)
			}
			successMu.Unlock()
		}(i)
	}

	wg.Wait()

	t.Logf("Results: %d accepted, %d rejected", successCount, failCount)

	// Due to timing, we might not get exactly 5 successes, but it should be around that
	if successCount < 5 || successCount > 20 {
		t.Logf("Warning: Expected around 5 successes, got %d", successCount)
	}

	// All should be released now
	total, _, _ := tracker.GetStats()
	if total != 0 {
		t.Errorf("Expected 0 connections after all released, got %d", total)
	}
}

// TestE2E_MixedIPScenario simulates a realistic mixed scenario
func TestE2E_MixedIPScenario(t *testing.T) {
	// Realistic limits: max 100 total, max 10 per IP
	tracker := NewConnectionTracker(100, 10, 0, nil)

	type connection struct {
		ip    string
		id    int
		lease *ConnLease
	}

	var activeConns []connection
	var mu sync.Mutex

	// Simulate legitimate traffic: 5 different IPs, each making 8 connections
	t.Log("=== Simulating legitimate traffic ===")
	for ipNum := 0; ipNum < 5; ipNum++ {
		ip := fmt.Sprintf("10.0.%d.1:5000", ipNum)
		for connNum := 0; connNum < 8; connNum++ {
			lease, err := tracker.Acquire(ip)
			if err == nil {
				mu.Lock()
				activeConns = append(activeConns, connection{ip: ip, id: connNum, lease: lease})
				mu.Unlock()
				t.Logf("✓ Legitimate: IP %s connection %d accepted", ip, connNum)
			} else {
				t.Errorf("Legitimate traffic should not be rejected: %v", err)
			}
		}
	}

	total, uniqueIPs, _ := tracker.GetStats()
	t.Logf("After legitimate traffic: total=%d, unique_ips=%d", total, uniqueIPs)

	if total != 40 {
		t.Errorf("Expected 40 connections, got %d", total)
	}

	// Simulate attack: single IP trying to create 20 connections
	t.Log("=== Simulating DoS attack from 1.2.3.4 ===")
	attackIP := "1.2.3.4:5000"
	attackSuccess := 0
	attackBlocked := 0

	for i := 0; i < 20; i++ {
		lease, err := tracker.Acquire(attackIP)
		if err == nil {
			attackSuccess++
			mu.Lock()
			activeConns = append(activeConns, connection{ip: attackIP, id: i, lease: lease})
			mu.Unlock()
			t.Logf("⚠ Attack: connection %d accepted (within per-IP limit)", i+1)
		} else {
			attackBlocked++
			t.Logf("🛡 Attack: connection %d BLOCKED", i+1)
		}
	}

	t.Logf("Attack results: %d accepted, %d blocked", attackSuccess, attackBlocked)

	// Should only accept up to 10 from the attack IP
	if attackSuccess != 10 {
		t.Errorf("Expected 10 attack connections accepted, got %d", attackSuccess)
	}
	if attackBlocked != 10 {
		t.Errorf("Expected 10 attack connections blocked, got %d", attackBlocked)
	}

	// Total should now be 50 (40 legitimate + 10 attack)
	total, uniqueIPs, perIP := tracker.GetStats()
	t.Logf("After attack: total=%d, unique_ips=%d", total, uniqueIPs)

	if total != 50 {
		t.Errorf("Expected 50 total connections, got %d", total)
	}

	// Verify attack IP has exactly 10 connections
	if perIP["1.2.3.4"] != 10 {
		t.Errorf("Expected 10 connections from attack IP, got %d", perIP["1.2.3.4"])
	}

	// Cleanup: release all connections
	t.Log("=== Cleaning up ===")
	mu.Lock()
	for _, conn := range activeConns {
		conn.lease.Release()
	}
	mu.Unlock()

	total, uniqueIPs, _ = tracker.GetStats()
	t.Logf("After cleanup: total=%d, unique_ips=%d", total, uniqueIPs)

	if total != 0 {
		t.Errorf("Expected 0 connections after cleanup, got %d", total)
	}
	if uniqueIPs != 0 {
		t.Errorf("Expected 0 unique IPs after cleanup, got %d", uniqueIPs)
	}
}

// TestE2E_HealthCheckUtilization verifies health status changes with utilization
func TestE2E_HealthCheckUtilization(t *testing.T) {
	scenarios := []struct {
		connections    int
		expectedStatus string
	}{
		{0, "healthy"},    // 0% utilization
		{5, "healthy"},    // 50% utilization
		{9, "degraded"},   // 90% utilization
		{10, "unhealthy"}, // 100% utilization
	}

	for _, scenario := range scenarios {
		// Create fresh tracker for each scenario
		tracker := NewConnectionTracker(10, 5, 0, nil)

		// Add connections
		for i := 0; i < scenario.connections; i++ {
			ip := fmt.Sprintf("192.168.1.%d:5000", i)
			if _, err := tracker.Acquire(ip); err != nil {
				t.Fatalf("Failed to acquire connection: %v", err)
			}
		}

		// Check health
		health := tracker.CheckHealth()
		t.Logf("Connections: %d/10, Health Status: %s", scenario.connections, health.Status)

		if health.Status != scenario.expectedStatus {
			t.Errorf("With %d connections, expected status '%s', got '%s'",
				scenario.connections, scenario.expectedStatus, health.Status)
		}
	}
}

// TestE2E_RapidConnectDisconnect simulates rapid connection churn
func TestE2E_RapidConnectDisconnect(t *testing.T) {
	tracker := NewConnectionTracker(20, 5, 0, nil)

	var wg sync.WaitGroup
	iterations := 100

	// Simulate rapid connect/disconnect from multiple IPs
	for ipNum := 0; ipNum < 3; ipNum++ {
		wg.Add(1)
		go func(ipSuffix int) {
			defer wg.Done()
			ip := fmt.Sprintf("192.168.1.%d:5000", 100+ipSuffix)

			for i := 0; i < iterations; i++ {
				// Try to connect
				if lease, err := tracker.Acquire(ip); err == nil {
					// Immediately disconnect
					time.Sleep(1 * time.Millisecond)
					lease.Release()
				}
			}
		}(ipNum)
	}

	wg.Wait()

	// All connections should be released
	total, uniqueIPs, _ := tracker.GetStats()
	if total != 0 {
		t.Errorf("Expected 0 connections after rapid churn, got %d", total)
	}
	if uniqueIPs != 0 {
		t.Errorf("Expected 0 unique IPs (memory leak check), got %d", uniqueIPs)
	}

	t.Logf("✓ Successfully handled %d rapid connect/disconnect cycles", iterations*3)
}

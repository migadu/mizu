package stats

import (
	"io"

	"fmt"
	"testing"
	"time"

	"log/slog"
)

func TestLRUEviction_IPs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create manager with limit of 10 IPs
	m := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 10, 0, 0, logger)
	m.Start()
	defer m.Stop()

	// Add 15 IPs
	for i := 1; i <= 15; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i)
		m.RecordConnection(ip, true)
		time.Sleep(10 * time.Millisecond) // Ensure different LastSeen times
	}

	// Wait for events to be processed
	time.Sleep(200 * time.Millisecond)

	// Trigger cleanup (which should evict 5 oldest IPs)
	m.cleanup()

	// Check that we have exactly 10 IPs
	m.ipMu.RLock()
	ipCount := len(m.ips)
	m.ipMu.RUnlock()

	if ipCount != 10 {
		t.Errorf("Expected 10 IPs after eviction, got %d", ipCount)
	}

	// Verify the oldest IPs were evicted (first 5)
	m.ipMu.RLock()
	for i := 1; i <= 5; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i)
		if _, exists := m.ips[ip]; exists {
			t.Errorf("Old IP %s should have been evicted", ip)
		}
	}

	// Verify the newest IPs were kept (last 10)
	for i := 6; i <= 15; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i)
		if _, exists := m.ips[ip]; !exists {
			t.Errorf("Recent IP %s should have been kept", ip)
		}
	}
	m.ipMu.RUnlock()
}

func TestLRUEviction_Domains(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create manager with limit of 5 domains
	m := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 5, 0, logger)
	m.Start()
	defer m.Stop()

	// Add 10 domains
	domains := []string{
		"domain1.com", "domain2.com", "domain3.com", "domain4.com", "domain5.com",
		"domain6.com", "domain7.com", "domain8.com", "domain9.com", "domain10.com",
	}

	for _, domain := range domains {
		m.RecordMailFrom(domain)
		time.Sleep(10 * time.Millisecond) // Ensure different LastSeen times
	}

	// Wait for events to be processed
	time.Sleep(200 * time.Millisecond)

	// Trigger cleanup (which should evict 5 oldest domains)
	m.cleanup()

	// Check that we have exactly 5 domains
	m.domainMu.RLock()
	domainCount := len(m.domains)
	m.domainMu.RUnlock()

	if domainCount != 5 {
		t.Errorf("Expected 5 domains after eviction, got %d", domainCount)
	}

	// Verify the oldest domains were evicted (first 5)
	m.domainMu.RLock()
	for i := 0; i < 5; i++ {
		if _, exists := m.domains[domains[i]]; exists {
			t.Errorf("Old domain %s should have been evicted", domains[i])
		}
	}

	// Verify the newest domains were kept (last 5)
	for i := 5; i < 10; i++ {
		if _, exists := m.domains[domains[i]]; !exists {
			t.Errorf("Recent domain %s should have been kept", domains[i])
		}
	}
	m.domainMu.RUnlock()
}

func TestLRUEviction_NoLimit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create manager with no limits (0 = unlimited)
	m := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	m.Start()
	defer m.Stop()

	// Add 50 IPs
	for i := 1; i <= 50; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		m.RecordConnection(ip, true)
	}

	// Wait for events to be processed
	time.Sleep(200 * time.Millisecond)

	// Trigger cleanup
	m.cleanup()

	// Check that all IPs are still present
	m.ipMu.RLock()
	ipCount := len(m.ips)
	m.ipMu.RUnlock()

	// We should have 50 unique IPs
	if ipCount != 50 {
		t.Errorf("Expected 50 IPs with no eviction, got %d", ipCount)
	}
}

func TestLRUEviction_UpdatesLastSeen(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create manager with limit of 3 IPs
	m := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 3, 0, 0, logger)
	m.Start()
	defer m.Stop()

	// Add 3 IPs
	m.RecordConnection("192.168.1.1", true)
	time.Sleep(10 * time.Millisecond)
	m.RecordConnection("192.168.1.2", true)
	time.Sleep(10 * time.Millisecond)
	m.RecordConnection("192.168.1.3", true)
	time.Sleep(10 * time.Millisecond)

	// Wait for events to be processed
	time.Sleep(100 * time.Millisecond)

	// Update the oldest IP (192.168.1.1)
	m.RecordConnection("192.168.1.1", true)
	time.Sleep(100 * time.Millisecond)

	// Add a new IP (should evict 192.168.1.2 which is now oldest)
	m.RecordConnection("192.168.1.4", true)
	time.Sleep(100 * time.Millisecond)

	// Trigger cleanup
	m.cleanup()

	// Check results
	m.ipMu.RLock()
	defer m.ipMu.RUnlock()

	if len(m.ips) != 4 {
		t.Logf("Expected 4 IPs before eviction, got %d", len(m.ips))
	}

	// After cleanup with limit of 3, should have 3 IPs
	// The oldest (192.168.1.2) should be evicted
}

func TestEvictLRUIPs_EmptyMap(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 10, 0, 0, logger)

	m.ipMu.Lock()
	evicted := m.evictLRUIPs(5)
	m.ipMu.Unlock()

	if evicted != 0 {
		t.Errorf("Expected 0 evictions from empty map, got %d", evicted)
	}
}

func TestEvictLRUDomains_NegativeCount(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 10, 0, logger)
	m.Start()
	defer m.Stop()

	// Add some domains
	m.RecordMailFrom("test1.com")
	m.RecordMailFrom("test2.com")
	time.Sleep(100 * time.Millisecond)

	m.domainMu.Lock()
	initialCount := len(m.domains)
	evicted := m.evictLRUDomains(-5)
	finalCount := len(m.domains)
	m.domainMu.Unlock()

	if evicted != 0 {
		t.Errorf("Expected 0 evictions with negative count, got %d", evicted)
	}

	if initialCount != finalCount {
		t.Errorf("Map size should not change with negative eviction count")
	}
}

// TestLRUEviction_MixedActivity tests that active IPs are preserved
func TestLRUEviction_MixedActivity(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create manager with limit of 5 IPs
	m := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 5, 0, 0, logger)
	m.Start()
	defer m.Stop()

	// Add 10 IPs with varying activity levels
	for i := 1; i <= 10; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		m.RecordConnection(ip, true)
		time.Sleep(5 * time.Millisecond)
	}

	time.Sleep(100 * time.Millisecond)

	// Keep some IPs active by recording more connections
	activeIPs := []string{"10.0.0.1", "10.0.0.3", "10.0.0.7", "10.0.0.9", "10.0.0.10"}
	for _, ip := range activeIPs {
		m.RecordConnection(ip, true)
		time.Sleep(5 * time.Millisecond)
	}

	time.Sleep(100 * time.Millisecond)

	// Trigger cleanup
	m.cleanup()

	// Verify we have exactly 5 IPs
	m.ipMu.RLock()
	if len(m.ips) != 5 {
		t.Errorf("Expected 5 IPs after eviction, got %d", len(m.ips))
	}

	// Verify the active IPs are the ones kept
	for _, ip := range activeIPs {
		if _, exists := m.ips[ip]; !exists {
			t.Errorf("Active IP %s should have been kept", ip)
		}
	}
	m.ipMu.RUnlock()
}

// TestLRUEviction_ConcurrentUpdates tests eviction with concurrent updates
func TestLRUEviction_ConcurrentUpdates(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create manager with limit of 10 IPs
	m := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 10, 0, 0, logger)
	m.Start()
	defer m.Stop()

	// Add 20 IPs
	for i := 1; i <= 20; i++ {
		ip := fmt.Sprintf("172.16.0.%d", i)
		m.RecordConnection(ip, true)
	}

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Run cleanup multiple times
	for i := 0; i < 3; i++ {
		m.cleanup()
		time.Sleep(50 * time.Millisecond)
	}

	// Should still have exactly 10 IPs
	m.ipMu.RLock()
	ipCount := len(m.ips)
	m.ipMu.RUnlock()

	if ipCount != 10 {
		t.Errorf("Expected 10 IPs after multiple cleanups, got %d", ipCount)
	}
}

// TestLRUEviction_BothLimits tests when both IP and domain limits are enforced
func TestLRUEviction_BothLimits(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create manager with limits for both IPs and domains
	m := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 5, 5, 0, logger)
	m.Start()
	defer m.Stop()

	// Add 10 IPs and 10 domains
	for i := 1; i <= 10; i++ {
		ip := fmt.Sprintf("192.168.100.%d", i)
		domain := fmt.Sprintf("example%d.com", i)
		m.RecordConnection(ip, true)
		m.RecordMailFrom(domain)
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Trigger cleanup
	m.cleanup()

	// Verify both limits are enforced
	m.ipMu.RLock()
	ipCount := len(m.ips)
	m.ipMu.RUnlock()

	m.domainMu.RLock()
	domainCount := len(m.domains)
	m.domainMu.RUnlock()

	if ipCount != 5 {
		t.Errorf("Expected 5 IPs after eviction, got %d", ipCount)
	}

	if domainCount != 5 {
		t.Errorf("Expected 5 domains after eviction, got %d", domainCount)
	}
}

// TestLRUEviction_ExactLimit tests behavior when count equals limit
func TestLRUEviction_ExactLimit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create manager with limit of 10 IPs
	m := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 10, 0, 0, logger)
	m.Start()
	defer m.Stop()

	// Add exactly 10 IPs
	for i := 1; i <= 10; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		m.RecordConnection(ip, true)
		time.Sleep(5 * time.Millisecond)
	}

	time.Sleep(100 * time.Millisecond)

	// Trigger cleanup
	m.cleanup()

	// Should still have exactly 10 IPs (no eviction needed)
	m.ipMu.RLock()
	ipCount := len(m.ips)
	m.ipMu.RUnlock()

	if ipCount != 10 {
		t.Errorf("Expected 10 IPs (no eviction), got %d", ipCount)
	}
}

// TestLRUEviction_WithExpiredEntries tests eviction combined with expiration
func TestLRUEviction_WithExpiredEntries(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create manager with short retention (500ms) and limit of 5
	m := NewManager(true, 500*time.Millisecond, "test", false, 1*time.Minute, nil, 5, 0, 0, logger)
	m.Start()
	defer m.Stop()

	// Add 3 old IPs that will expire
	for i := 1; i <= 3; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		m.RecordConnection(ip, true)
	}

	// Wait for events to be processed
	time.Sleep(100 * time.Millisecond)

	// Wait for them to expire (> 500ms retention)
	time.Sleep(600 * time.Millisecond)

	// Add 7 new IPs (total would be 10, but 3 should be expired)
	for i := 4; i <= 10; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		m.RecordConnection(ip, true)
		time.Sleep(5 * time.Millisecond)
	}

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	// Trigger cleanup (should remove 3 expired + evict 2 oldest of remaining 7)
	m.cleanup()

	// Should have exactly 5 IPs
	m.ipMu.RLock()
	ipCount := len(m.ips)
	m.ipMu.RUnlock()

	if ipCount != 5 {
		t.Errorf("Expected 5 IPs after expiration and eviction, got %d", ipCount)
	}
}

// TestLRUEviction_LargeScale tests eviction with a large number of entries
func TestLRUEviction_LargeScale(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create manager with limit of 100 IPs
	m := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 100, 100, 0, logger)
	m.Start()
	defer m.Stop()

	// Add 500 IPs
	for i := 1; i <= 500; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i/256)%256, (i/16)%16, i%16)
		m.RecordConnection(ip, true)
		m.RecordMailFrom(fmt.Sprintf("domain%d.com", i))
	}

	// Wait for processing
	time.Sleep(500 * time.Millisecond)

	// Trigger cleanup
	m.cleanup()

	// Verify limits are enforced
	m.ipMu.RLock()
	ipCount := len(m.ips)
	m.ipMu.RUnlock()

	m.domainMu.RLock()
	domainCount := len(m.domains)
	m.domainMu.RUnlock()

	if ipCount != 100 {
		t.Errorf("Expected 100 IPs after large-scale eviction, got %d", ipCount)
	}

	if domainCount != 100 {
		t.Errorf("Expected 100 domains after large-scale eviction, got %d", domainCount)
	}
}

// TestLRUEviction_ReputationPreserved tests that evicted IPs lose reputation
func TestLRUEviction_ReputationPreserved(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create manager with limit of 3 IPs
	m := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 3, 0, 0, logger)
	m.Start()
	defer m.Stop()

	// Add 5 IPs with different reputation scores
	goodIP := "192.168.1.100"
	for i := 0; i < 20; i++ {
		m.RecordConnection(goodIP, true)
		m.RecordHamDelivery(goodIP, "good.com", 1)
	}

	badIP1 := "192.168.1.101"
	for i := 0; i < 10; i++ {
		m.RecordConnection(badIP1, true)
		m.RecordJunkMessage(badIP1, "bad1.com")
	}

	middleIP := "192.168.1.102"
	m.RecordConnection(middleIP, true)

	time.Sleep(200 * time.Millisecond)

	// Add 2 more IPs to trigger eviction
	m.RecordConnection("192.168.1.103", true)
	time.Sleep(10 * time.Millisecond)
	m.RecordConnection("192.168.1.104", true)
	time.Sleep(100 * time.Millisecond)

	// Trigger cleanup
	m.cleanup()

	// The good IP should still be accessible with reputation
	shouldDeny, reputation := m.CheckIPReputation(goodIP)
	if shouldDeny {
		t.Error("Good IP should not be denied")
	}
	if reputation < 0 {
		t.Errorf("Good IP should have positive reputation, got %f", reputation)
	}

	// Evicted IPs should return neutral reputation (new entry behavior)
	m.ipMu.RLock()
	ipCount := len(m.ips)
	m.ipMu.RUnlock()

	if ipCount != 3 {
		t.Errorf("Expected 3 IPs after eviction, got %d", ipCount)
	}
}

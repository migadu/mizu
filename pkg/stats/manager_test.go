package stats

import (
	"io"

	"fmt"
	"testing"
	"time"

	"log/slog"
)

func TestNewManager(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	enabled := true
	retention := 24 * time.Hour
	hostname := "test-host"
	syncEnabled := true
	syncInterval := 1 * time.Minute
	syncServers := []string{"server1", "server2"}

	manager := NewManager(enabled, retention, hostname, syncEnabled, syncInterval, syncServers, 0, 0, 0, logger)

	if manager == nil {
		t.Fatal("NewManager returned nil")
	}

	if !manager.enabled {
		t.Error("manager should be enabled")
	}

	if manager.retentionDuration != retention {
		t.Errorf("retentionDuration = %v; want %v", manager.retentionDuration, retention)
	}

	if manager.hostname != hostname {
		t.Errorf("hostname = %s; want %s", manager.hostname, hostname)
	}

	if manager.ips == nil {
		t.Error("ips map is nil")
	}

}

func TestManagerRecordConnection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	ip := "192.168.1.1"

	// Record connection with rDNS
	manager.RecordConnection(ip, true)

	var entry *IPEntry
	err := waitFor(1*time.Second, func() bool {
		manager.ipMu.RLock()
		defer manager.ipMu.RUnlock()
		entry = manager.ips[ip]
		return entry != nil
	})

	if err != nil {
		t.Fatal("IP entry not created after timeout")
	}
	if entry == nil {
		t.Fatal("IP entry not created")
	}

	if entry.GetConnections() != 1 {
		t.Errorf("Connections = %d; want 1", entry.GetConnections())
	}

	if entry.GetIsDenied() {
		t.Error("IsDenied should be false when hasRDNS is true")
	}

	// Record another connection without rDNS, then explicitly deny it
	ip2 := "192.168.1.2"
	manager.RecordConnection(ip2, false)
	manager.RecordDeniedConnection(ip2)

	var entry2 *IPEntry
	err = waitFor(1*time.Second, func() bool {
		manager.ipMu.RLock()
		defer manager.ipMu.RUnlock()
		entry2 = manager.ips[ip2]
		return entry2 != nil && entry2.GetIsDenied()
	})
	if err != nil {
		t.Fatal("IP entry 2 not created or not denied after timeout")
	}

	if !entry2.GetIsDenied() {
		t.Error("IsDenied should be true after RecordDeniedConnection")
	}
}

func TestManagerRecordMailFrom(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	// RecordMailFrom takes a domain for observability (message counting),
	// but domain reputation is NOT used for scoring (domain is unverified/forged).
	manager.RecordMailFrom("example.com")
	manager.RecordMailFrom("example.com")

	// Give event loop time to process
	time.Sleep(200 * time.Millisecond)

	// Verify per-server domain counter incremented
	manager.srvCountersMu.RLock()
	sc := manager.srvCounters["_default"]
	manager.srvCountersMu.RUnlock()
	if sc == nil {
		t.Fatal("Per-server counters not created")
	}
	dc := sc.domains["example.com"]
	if dc == nil || dc.messages != 2 {
		t.Errorf("Per-server domain messages = %v; want 2", dc)
	}

}

func TestManagerRecordInvalidRecipient(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	ip := "192.168.1.1"

	manager.RecordInvalidRecipient(ip)

	var ipEntry *IPEntry
	_ = waitFor(1*time.Second, func() bool {
		manager.ipMu.RLock()
		defer manager.ipMu.RUnlock()
		ipEntry = manager.ips[ip]
		return ipEntry != nil && ipEntry.GetNegative() == WeightInvalidRecipient
	})

	if ipEntry == nil {
		t.Fatal("IP entry not created")
	}
	if ipEntry.GetNegative() != WeightInvalidRecipient {
		t.Errorf("IP Negative = %d; want %d", ipEntry.GetNegative(), WeightInvalidRecipient)
	}

}

func TestManagerRecordSpoofingAttempt(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	ip := "192.168.1.1"

	manager.RecordSpoofingAttempt(ip)

	var ipEntry *IPEntry
	_ = waitFor(1*time.Second, func() bool {
		manager.ipMu.RLock()
		defer manager.ipMu.RUnlock()
		ipEntry = manager.ips[ip]
		return ipEntry != nil && ipEntry.GetNegative() == WeightSpoofingAttempt
	})

	if ipEntry == nil {
		t.Fatal("IP entry not created")
	}
	if ipEntry.GetNegative() != WeightSpoofingAttempt {
		t.Errorf("IP Negative = %d; want %d", ipEntry.GetNegative(), WeightSpoofingAttempt)
	}
}

func TestManagerRecordDMARCFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	ip := "192.168.1.1"

	manager.RecordDMARCFailure(ip)

	var ipEntry *IPEntry
	_ = waitFor(1*time.Second, func() bool {
		manager.ipMu.RLock()
		defer manager.ipMu.RUnlock()
		ipEntry = manager.ips[ip]
		return ipEntry != nil && ipEntry.GetNegative() == WeightDMARCFailure
	})

	if ipEntry == nil {
		t.Fatal("IP entry not created")
	}
	if ipEntry.GetNegative() != WeightDMARCFailure {
		t.Errorf("IP Negative = %d; want %d", ipEntry.GetNegative(), WeightDMARCFailure)
	}
}

func TestManagerRecordSPFFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	ip := "192.168.1.1"

	manager.RecordSPFFailure(ip)

	// Verify IP gets negative weight
	var ipEntry *IPEntry
	_ = waitFor(1*time.Second, func() bool {
		manager.ipMu.RLock()
		defer manager.ipMu.RUnlock()
		ipEntry = manager.ips[ip]
		return ipEntry != nil && ipEntry.GetNegative() == WeightSPFFailure
	})

	if ipEntry == nil {
		t.Fatal("IP entry not created")
	}

	if ipEntry.GetNegative() != WeightSPFFailure {
		t.Errorf("IP Negative = %d; want %d", ipEntry.GetNegative(), WeightSPFFailure)
	}

}

// TestManagerSPFFailureAccumulatesForRotatingIPs verifies that multiple SPF failures
// from the same IP accumulate negative reputation, helping catch rotating spammers.
func TestManagerSPFFailureAccumulatesForRotatingIPs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	ip := "10.0.0.1"

	// Simulate 5 SPF failures from same IP (e.g., spammer forging different domains)
	for i := 0; i < 5; i++ {
		manager.RecordSPFFailure(ip)
	}

	expectedNegative := int64(WeightSPFFailure * 5) // 3 * 5 = 15

	var ipEntry *IPEntry
	_ = waitFor(1*time.Second, func() bool {
		manager.ipMu.RLock()
		defer manager.ipMu.RUnlock()
		ipEntry = manager.ips[ip]
		return ipEntry != nil && ipEntry.GetNegative() == expectedNegative
	})

	if ipEntry == nil {
		t.Fatal("IP entry not created")
	}

	if ipEntry.GetNegative() != expectedNegative {
		t.Errorf("IP Negative = %d; want %d (5 SPF failures × weight %d)",
			ipEntry.GetNegative(), expectedNegative, WeightSPFFailure)
	}
}

func TestManagerRecordJunkMessage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	ip := "192.168.1.1"

	manager.RecordJunkMessage(ip)

	var ipEntry *IPEntry
	_ = waitFor(1*time.Second, func() bool {
		manager.ipMu.RLock()
		defer manager.ipMu.RUnlock()
		ipEntry = manager.ips[ip]
		return ipEntry != nil && ipEntry.GetNegative() == WeightJunkMessage
	})

	if ipEntry == nil {
		t.Fatal("IP entry not created")
	}
	if ipEntry.GetNegative() != WeightJunkMessage {
		t.Errorf("IP Negative = %d; want %d", ipEntry.GetNegative(), WeightJunkMessage)
	}
}

func TestManagerRecordHamDelivery(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	ip := "192.168.1.1"

	manager.RecordHamDelivery(ip, 1)

	var ipEntry *IPEntry
	_ = waitFor(1*time.Second, func() bool {
		manager.ipMu.RLock()
		defer manager.ipMu.RUnlock()
		ipEntry = manager.ips[ip]
		return ipEntry != nil && ipEntry.GetPositive() == WeightHamDelivery
	})

	if ipEntry == nil {
		t.Fatal("IP entry not created")
	}
	if ipEntry.GetPositive() != WeightHamDelivery {
		t.Errorf("IP Positive = %d; want %d", ipEntry.GetPositive(), WeightHamDelivery)
	}
}

func TestManagerRecordHamDelivery_MultipleRecipients(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	ip := "192.168.1.1"

	// Simulate a mailing list sending to 100 recipients
	manager.RecordHamDelivery(ip, 100)

	expectedPositive := WeightHamDelivery * int64(100)
	var ipEntry *IPEntry
	_ = waitFor(1*time.Second, func() bool {
		manager.ipMu.RLock()
		defer manager.ipMu.RUnlock()
		ipEntry = manager.ips[ip]
		return ipEntry != nil && ipEntry.GetPositive() == expectedPositive
	})

	if ipEntry == nil {
		t.Fatal("IP entry not created")
	}
	if ipEntry.GetPositive() != expectedPositive {
		t.Errorf("IP Positive = %d; want %d (100 recipients × weight %d)", ipEntry.GetPositive(), expectedPositive, WeightHamDelivery)
	}
}

// TestManagerMailingListScenario verifies that a mailing list sending to 100 recipients
// with 1 invalid recipient gets a net positive reputation, not net negative.
// This was the original bug: per-message scoring gave +1 -2 = -1 instead of +100 -2 = +98.
func TestManagerMailingListScenario(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	ip := "10.0.0.1"
	_ = "googlegroups.com"

	// Simulate: mailing list sends to 100 recipients, 1 is invalid
	// The invalid recipient is caught during RCPT TO (before DATA)
	manager.RecordInvalidRecipient(ip)

	// Wait for invalid recipient event to be processed
	_ = waitFor(1*time.Second, func() bool {
		manager.ipMu.RLock()
		defer manager.ipMu.RUnlock()
		ipEntry := manager.ips[ip]
		return ipEntry != nil && ipEntry.GetNegative() == WeightInvalidRecipient
	})

	// The remaining 99 are delivered successfully
	manager.RecordHamDelivery(ip, 99)

	// Wait for ham delivery event to be processed
	_ = waitFor(1*time.Second, func() bool {
		manager.ipMu.RLock()
		defer manager.ipMu.RUnlock()
		ipEntry := manager.ips[ip]
		return ipEntry != nil && ipEntry.GetPositive() == WeightHamDelivery*99
	})

	manager.ipMu.RLock()
	ipEntry := manager.ips[ip]
	manager.ipMu.RUnlock()

	if ipEntry == nil {
		t.Fatal("IP entry not created")
	}

	// Counters accumulate independently (no cross-penalty).
	// After InvalidRecipient: Positive=0, Negative=2
	// After HamDelivery(99):  Positive=99, Negative=2
	expectedPositive := WeightHamDelivery * int64(99) // 99
	expectedNegative := int64(WeightInvalidRecipient) // 2 — unchanged by AddPositive

	if ipEntry.GetPositive() != expectedPositive {
		t.Errorf("IP Positive = %d; want %d", ipEntry.GetPositive(), expectedPositive)
	}
	if ipEntry.GetNegative() != expectedNegative {
		t.Errorf("IP Negative = %d; want %d", ipEntry.GetNegative(), expectedNegative)
	}

	// Net score should be clearly positive for a legitimate mailing list
	netScore := ipEntry.GetPositive() - ipEntry.GetNegative()
	if netScore <= 0 {
		t.Errorf("Net score = %d; should be positive for a legitimate mailing list", netScore)
	}
	t.Logf("Mailing list scenario: positive=%d, negative=%d, net=%d ✓",
		ipEntry.GetPositive(), ipEntry.GetNegative(), netScore)
}

func TestManagerCheckIPReputation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	ip := "192.168.1.1"

	// No data - should not deny
	shouldDeny, reputation := manager.CheckIPReputation(ip)
	if shouldDeny {
		t.Error("should not deny IP with no data")
	}
	if reputation != 0 {
		t.Errorf("reputation = %f; want 0", reputation)
	}

	// Build up bad reputation
	entry := manager.getOrCreateIP(ip)
	entry.Connections = 20
	entry.Negative = 15
	entry.LastNegativeAt = time.Now()
	entry.Positive = 5

	shouldDeny, reputation = manager.CheckIPReputation(ip)
	if !shouldDeny {
		t.Error("should deny IP with bad reputation")
	}
	if reputation >= ReputationDenyThreshold {
		t.Errorf("reputation = %f; should be below %f", reputation, ReputationDenyThreshold)
	}
}

func TestManagerDisabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(false, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	ip := "192.168.1.1"
	_ = "example.com"

	// Operations should be no-ops when disabled
	manager.RecordConnection(ip, true)
	manager.RecordMailFrom("example.com")
	manager.RecordInvalidRecipient(ip)
	manager.RecordHamDelivery(ip, 1)

	// Give a moment for any potential (unwanted) processing
	time.Sleep(50 * time.Millisecond)

	manager.ipMu.RLock()
	if len(manager.ips) != 0 {
		t.Error("ips map should be empty when disabled")
	}
	manager.ipMu.RUnlock()

	shouldDeny, _ := manager.CheckIPReputation(ip)
	if shouldDeny {
		t.Error("should not deny when disabled")
	}
}

func TestGetIPFromRemoteAddr(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		expected   string
	}{
		{
			name:       "IP with port",
			remoteAddr: "192.168.1.1:12345",
			expected:   "192.168.1.1",
		},
		{
			name:       "IPv6 with port",
			remoteAddr: "[2001:db8::1]:12345",
			expected:   "2001:db8::1",
		},
		{
			name:       "IP only",
			remoteAddr: "192.168.1.1",
			expected:   "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetIPFromRemoteAddr(tt.remoteAddr)
			if result != tt.expected {
				t.Errorf("GetIPFromRemoteAddr(%s) = %s; want %s", tt.remoteAddr, result, tt.expected)
			}
		})
	}
}

func TestExtractDomainFromEmail(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected string
	}{
		{
			name:     "simple email",
			email:    "user@example.com",
			expected: "example.com",
		},
		{
			name:     "email with brackets",
			email:    "<user@example.com>",
			expected: "example.com",
		},
		{
			name:     "uppercase domain",
			email:    "user@EXAMPLE.COM",
			expected: "example.com",
		},
		{
			name:     "email with spaces",
			email:    "  user@example.com  ",
			expected: "example.com",
		},
		{
			name:     "no @ sign",
			email:    "invalid-email",
			expected: "",
		},
		{
			name:     "empty email",
			email:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractDomainFromEmail(tt.email)
			if result != tt.expected {
				t.Errorf("ExtractDomainFromEmail(%s) = %s; want %s", tt.email, result, tt.expected)
			}
		})
	}
}

func TestManagerCleanup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 1*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	// Add some IP entries
	oldIP := "192.168.1.1"
	recentIP := "192.168.1.2"

	manager.ipMu.Lock()
	manager.ips[oldIP] = &IPEntry{
		FirstSeen: time.Now().Add(-2 * time.Hour),
		LastSeen:  time.Now().Add(-2 * time.Hour),
	}
	manager.ips[recentIP] = &IPEntry{
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
	manager.ipMu.Unlock()

	// Run cleanup
	manager.cleanup()

	manager.ipMu.RLock()
	if _, exists := manager.ips[oldIP]; exists {
		t.Error("old IP entry should be removed")
	}
	if _, exists := manager.ips[recentIP]; !exists {
		t.Error("recent IP entry should remain")
	}
	manager.ipMu.RUnlock()
}

func TestRemoveIP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewManager(true, time.Hour, "test", false, 0, nil, 1000, 100, 1000, logger)
	m.Start()
	defer m.Stop()

	// Insert an IP directly
	entry := m.getOrCreateIP("1.2.3.4")
	entry.AddNegative(100)

	// RemoveIP should find and remove it
	if !m.RemoveIP("1.2.3.4") {
		t.Error("RemoveIP returned false for existing IP")
	}

	// Second call should return false
	if m.RemoveIP("1.2.3.4") {
		t.Error("RemoveIP returned true for already-removed IP")
	}

	// Reputation should be neutral after removal
	denied, rep := m.CheckIPReputation("1.2.3.4")
	if denied {
		t.Error("IP should not be denied after removal")
	}
	if rep != 0 {
		t.Errorf("reputation should be 0 after removal, got %f", rep)
	}
}

func TestRemoveIP_IPv6Normalization(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewManager(true, time.Hour, "test", false, 0, nil, 1000, 100, 1000, logger)

	// Insert with compressed form
	m.getOrCreateIP("2001:db8::1")

	// Remove with expanded representation — should still work because
	// NormalizeIP canonicalizes both forms to the same string
	if !m.RemoveIP("2001:0db8:0000:0000:0000:0000:0000:0001") {
		t.Error("RemoveIP should find IPv6 address regardless of representation")
	}
}

func TestRemoveIP_InvalidIP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewManager(true, time.Hour, "test", false, 0, nil, 1000, 100, 1000, logger)

	if m.RemoveIP("not-an-ip") {
		t.Error("RemoveIP should return false for invalid IP")
	}
}

// waitFor polls a condition until it's true or a timeout is reached.
func waitFor(timeout time.Duration, condition func() bool) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("condition not met after %v", timeout)
}

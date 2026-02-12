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

	if manager.domains == nil {
		t.Error("domains map is nil")
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

	// Record another connection without rDNS
	ip2 := "192.168.1.2"
	manager.RecordConnection(ip2, false)

	var entry2 *IPEntry
	err = waitFor(1*time.Second, func() bool {
		manager.ipMu.RLock()
		defer manager.ipMu.RUnlock()
		entry2 = manager.ips[ip2]
		return entry2 != nil
	})
	if err != nil {
		t.Fatal("IP entry 2 not created after timeout")
	}
	if entry2 == nil {
		t.Fatal("IP entry not created")
	}

	if !entry2.GetIsDenied() {
		t.Error("IsDenied should be true when hasRDNS is false")
	}
}

func TestManagerRecordMailFrom(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	domain := "example.com"

	manager.RecordMailFrom(domain)

	var entry *DomainEntry
	err := waitFor(1*time.Second, func() bool {
		manager.domainMu.RLock()
		defer manager.domainMu.RUnlock()
		entry = manager.domains[domain]
		return entry != nil && entry.GetMessages() == 1
	})
	if err != nil {
		t.Fatal("Domain entry not created or message count incorrect after timeout")
	}
	if entry == nil {
		t.Fatal("Domain entry not created")
	}

	if entry.GetMessages() != 1 {
		t.Errorf("Messages = %d; want 1", entry.GetMessages())
	}

	// Record another
	manager.RecordMailFrom(domain)
	err = waitFor(1*time.Second, func() bool {
		return entry.GetMessages() == 2
	})
	if err != nil {
		t.Fatal("Message count did not increment to 2 after timeout")
	}
	if entry.GetMessages() != 2 {
		t.Errorf("Messages = %d; want 2", entry.GetMessages())
	}
}

func TestManagerRecordInvalidRecipient(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	ip := "192.168.1.1"
	domain := "example.com"

	manager.RecordInvalidRecipient(ip, domain)

	var ipEntry *IPEntry
	err := waitFor(1*time.Second, func() bool {
		manager.ipMu.RLock()
		defer manager.ipMu.RUnlock()
		ipEntry = manager.ips[ip]
		return ipEntry != nil
	})
	if err != nil {
		t.Fatal("IP entry not created after timeout")
	}

	waitFor(1*time.Second, func() bool {
		return ipEntry.GetNegative() == WeightInvalidRecipient
	})

	if ipEntry == nil {
		t.Fatal("IP entry not created")
	}

	if ipEntry.GetNegative() != WeightInvalidRecipient {
		t.Errorf("IP Negative = %d; want %d", ipEntry.GetNegative(), WeightInvalidRecipient)
	}

	var domainEntry *DomainEntry
	err = waitFor(1*time.Second, func() bool {
		manager.domainMu.RLock()
		defer manager.domainMu.RUnlock()
		domainEntry = manager.domains[domain]
		return domainEntry != nil
	})
	if err != nil {
		t.Fatal("Domain entry not created after timeout")
	}

	if domainEntry == nil {
		t.Fatal("Domain entry not created")
	}

	if domainEntry.GetNegative() != WeightInvalidRecipient {
		t.Errorf("Domain Negative = %d; want %d", domainEntry.GetNegative(), WeightInvalidRecipient)
	}
}

func TestManagerRecordSpoofingAttempt(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	ip := "192.168.1.1"
	domain := "example.com"

	manager.RecordSpoofingAttempt(ip, domain)

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

	var domainEntry *DomainEntry
	_ = waitFor(1*time.Second, func() bool {
		manager.domainMu.RLock()
		defer manager.domainMu.RUnlock()
		domainEntry = manager.domains[domain]
		return domainEntry != nil && domainEntry.GetNegative() == WeightSpoofingAttempt
	})

	if domainEntry == nil {
		t.Fatal("Domain entry not created")
	}

	if domainEntry.GetNegative() != WeightSpoofingAttempt {
		t.Errorf("Domain Negative = %d; want %d", domainEntry.GetNegative(), WeightSpoofingAttempt)
	}
}

func TestManagerRecordDMARCFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	ip := "192.168.1.1"
	domain := "example.com"

	manager.RecordDMARCFailure(ip, domain)

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

	var domainEntry *DomainEntry
	_ = waitFor(1*time.Second, func() bool {
		manager.domainMu.RLock()
		defer manager.domainMu.RUnlock()
		domainEntry = manager.domains[domain]
		return domainEntry != nil && domainEntry.GetNegative() == WeightDMARCFailure
	})

	if domainEntry == nil {
		t.Fatal("Domain entry not created")
	}

	if domainEntry.GetNegative() != WeightDMARCFailure {
		t.Errorf("Domain Negative = %d; want %d", domainEntry.GetNegative(), WeightDMARCFailure)
	}
}

func TestManagerRecordJunkMessage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	ip := "192.168.1.1"
	domain := "example.com"

	manager.RecordJunkMessage(ip, domain)

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

	var domainEntry *DomainEntry
	_ = waitFor(1*time.Second, func() bool {
		manager.domainMu.RLock()
		defer manager.domainMu.RUnlock()
		domainEntry = manager.domains[domain]
		return domainEntry != nil && domainEntry.GetNegative() == WeightJunkMessage
	})

	if domainEntry == nil {
		t.Fatal("Domain entry not created")
	}

	if domainEntry.GetNegative() != WeightJunkMessage {
		t.Errorf("Domain Negative = %d; want %d", domainEntry.GetNegative(), WeightJunkMessage)
	}
}

func TestManagerRecordHamDelivery(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	ip := "192.168.1.1"
	domain := "example.com"

	manager.RecordHamDelivery(ip, domain)

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

	var domainEntry *DomainEntry
	_ = waitFor(1*time.Second, func() bool {
		manager.domainMu.RLock()
		defer manager.domainMu.RUnlock()
		domainEntry = manager.domains[domain]
		return domainEntry != nil && domainEntry.GetPositive() == WeightHamDelivery
	})

	if domainEntry == nil {
		t.Fatal("Domain entry not created")
	}

	if domainEntry.GetPositive() != WeightHamDelivery {
		t.Errorf("Domain Positive = %d; want %d", domainEntry.GetPositive(), WeightHamDelivery)
	}
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
	entry.Positive = 5

	shouldDeny, reputation = manager.CheckIPReputation(ip)
	if !shouldDeny {
		t.Error("should deny IP with bad reputation")
	}
	if reputation >= ReputationDenyThreshold {
		t.Errorf("reputation = %f; should be below %f", reputation, ReputationDenyThreshold)
	}
}

func TestManagerCheckDomainReputation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(true, 24*time.Hour, "test", false, 1*time.Minute, nil, 0, 0, 0, logger)
	manager.Start()
	defer manager.Stop()

	domain := "example.com"

	// No data - should not deny
	shouldDeny, reputation := manager.CheckDomainReputation(domain)
	if shouldDeny {
		t.Error("should not deny domain with no data")
	}
	if reputation != 0 {
		t.Errorf("reputation = %f; want 0", reputation)
	}

	// Build up bad reputation
	entry := manager.getOrCreateDomain(domain)
	entry.Messages = 20
	entry.Negative = 15
	entry.Positive = 5

	shouldDeny, reputation = manager.CheckDomainReputation(domain)
	if !shouldDeny {
		t.Error("should deny domain with bad reputation")
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
	domain := "example.com"

	// Operations should be no-ops when disabled
	manager.RecordConnection(ip, true)
	manager.RecordMailFrom(domain)
	manager.RecordInvalidRecipient(ip, domain)
	manager.RecordHamDelivery(ip, domain)

	// Give a moment for any potential (unwanted) processing
	time.Sleep(50 * time.Millisecond)

	manager.ipMu.RLock()
	if len(manager.ips) != 0 {
		t.Error("ips map should be empty when disabled")
	}
	manager.ipMu.RUnlock()

	manager.domainMu.RLock()
	if len(manager.domains) != 0 {
		t.Error("domains map should be empty when disabled")
	}
	manager.domainMu.RUnlock()

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

	// Add some entries
	oldIP := "192.168.1.1"
	recentIP := "192.168.1.2"
	oldDomain := "old.example.com"
	recentDomain := "recent.example.com"

	manager.ipMu.Lock()
	// Old entries
	manager.ips[oldIP] = &IPEntry{
		FirstSeen: time.Now().Add(-2 * time.Hour),
		LastSeen:  time.Now().Add(-2 * time.Hour),
	}
	// Recent entries
	manager.ips[recentIP] = &IPEntry{
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
	manager.ipMu.Unlock()

	manager.domainMu.Lock()
	manager.domains[oldDomain] = &DomainEntry{
		FirstSeen: time.Now().Add(-2 * time.Hour),
		LastSeen:  time.Now().Add(-2 * time.Hour),
	}
	manager.domains[recentDomain] = &DomainEntry{
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
	manager.domainMu.Unlock()

	// Run cleanup
	manager.cleanup()

	manager.ipMu.RLock()
	// Old entries should be removed
	if _, exists := manager.ips[oldIP]; exists {
		t.Error("old IP entry should be removed")
	}
	// Recent entries should remain
	if _, exists := manager.ips[recentIP]; !exists {
		t.Error("recent IP entry should remain")
	}
	manager.ipMu.RUnlock()

	manager.domainMu.RLock()
	if _, exists := manager.domains[oldDomain]; exists {
		t.Error("old domain entry should be removed")
	}
	if _, exists := manager.domains[recentDomain]; !exists {
		t.Error("recent domain entry should remain")
	}
	manager.domainMu.RUnlock()
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

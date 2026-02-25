//go:build integration
// +build integration

package tests

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/stats"

	"log/slog"
)

// TestStatsIntegration tests the stats system integration
func TestStatsIntegration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	statsMgr := stats.NewManager(
		true,
		1*time.Hour,
		"test-host",
		false,
		1*time.Minute,
		nil,
		0, // maxIPEntries (unlimited for test)
		0, // maxDomainEntries (unlimited for test)
		0, // bufferSize (use default)
		logger,
	)
	statsMgr.Start()
	defer statsMgr.Stop()

	t.Run("GoodIPBehavior", func(t *testing.T) {
		// Test IP reputation tracking with good behavior
		goodIP := "192.168.1.100"
		for i := 0; i < 15; i++ {
			statsMgr.RecordConnection(goodIP, true)
			statsMgr.RecordMailFrom("good.com")
			statsMgr.RecordHamDelivery(goodIP, "good.com", 1)
		}

		shouldDeny, reputation := statsMgr.CheckIPReputation(goodIP)
		t.Logf("Good IP: shouldDeny=%v, reputation=%f", shouldDeny, reputation)

		// Good IP should not be denied
		if shouldDeny {
			t.Errorf("good IP should not be denied (reputation: %f)", reputation)
		}
	})

	t.Run("MixedIPBehavior", func(t *testing.T) {
		// Test that stats manager tracks various events without errors
		testIP := "192.168.1.1"
		testDomain := "test.com"

		// Record various events
		statsMgr.RecordConnection(testIP, true)
		statsMgr.RecordConnection(testIP, false) // No rDNS
		statsMgr.RecordMailFrom(testDomain)
		statsMgr.RecordInvalidRecipient(testIP, testDomain)
		statsMgr.RecordSpoofingAttempt(testIP, testDomain)
		statsMgr.RecordDMARCFailure(testIP, testDomain)
		statsMgr.RecordJunkMessage(testIP, testDomain)
		statsMgr.RecordHamDelivery(testIP, testDomain, 1)

		// Check that reputation can be queried (may be 0 due to insufficient data, that's okay)
		_, ipRep := statsMgr.CheckIPReputation(testIP)
		_, domainRep := statsMgr.CheckDomainReputation(testDomain)

		t.Logf("Test IP reputation: %f, Test domain reputation: %f", ipRep, domainRep)
	})

	// Final verification that the manager is not nil
	if statsMgr == nil {
		t.Error("stats manager should not be nil")
	}

	t.Log("Stats integration test completed successfully")
}

// TestConfigIntegration tests configuration loading and validation
func TestConfigIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.toml")

	configContent := `
local = true

[smtp]
listen_addr = ":2525"
domain = "mail.test.com"
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := config.LoadConfig([]string{"--config", configPath})
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.SMTP.ListenAddr != ":2525" {
		t.Errorf("SMTP.ListenAddr = %s; want :2525", cfg.SMTP.ListenAddr)
	}

	if cfg.SMTP.Domain != "mail.test.com" {
		t.Errorf("SMTP.Domain = %s; want mail.test.com", cfg.SMTP.Domain)
	}

	if !cfg.Local {
		t.Error("Local should be true")
	}

	t.Log("Config integration test completed successfully")
}

// TestComponentsIntegration tests that all major components can be initialized together
func TestComponentsIntegration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create config
	cfg := config.DefaultConfig()
	cfg.Local = true
	cfg.Stats.Enabled = true
	cfg.Stats.RetentionSeconds = 3600 // 1 hour

	// Initialize stats manager
	statsMgr := stats.NewManager(
		cfg.Stats.Enabled,
		time.Duration(cfg.Stats.RetentionSeconds)*time.Second,
		"test-host",
		false,
		1*time.Minute,
		nil,
		0, // maxIPEntries (unlimited for test)
		0, // maxDomainEntries (unlimited for test)
		0, // bufferSize (use default)
		logger,
	)
	statsMgr.Start()
	defer statsMgr.Stop()

	// Verify components work together
	// Record some activity
	testIP := "192.168.1.1"
	testDomain := "test.com"

	statsMgr.RecordConnection(testIP, true)
	statsMgr.RecordMailFrom(testDomain)
	statsMgr.RecordHamDelivery(testIP, testDomain, 1)

	shouldDeny, _ := statsMgr.CheckIPReputation(testIP)
	if shouldDeny {
		t.Error("IP should not be denied after single good delivery")
	}

	t.Log("All components initialized and working together successfully")
}

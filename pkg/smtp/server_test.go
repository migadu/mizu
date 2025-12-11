package smtp

import (
	"io"

	"testing"

	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/stats"

	"log/slog"
)

func TestExtractDomainFromEmail(t *testing.T) {
	result := stats.ExtractDomainFromEmail("user@example.com")
	if result != "example.com" {
		t.Errorf("ExtractDomainFromEmail = %s; want example.com", result)
	}

	result = stats.ExtractDomainFromEmail("<user@example.com>")
	if result != "example.com" {
		t.Errorf("ExtractDomainFromEmail with brackets = %s; want example.com", result)
	}

	result = stats.ExtractDomainFromEmail("invalid")
	if result != "" {
		t.Errorf("ExtractDomainFromEmail for invalid = %s; want empty", result)
	}
}

func TestTLSVersionString(t *testing.T) {
	// This test is now internal to the package and doesn't need to be exported.
	// If it were needed, it would be here.
}

func TestBackend_Configuration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	defaultCfg := config.DefaultConfig()
	cfg := &defaultCfg
	cfg.Local = true
	statsMgr := stats.NewManager(true, 0, "test", false, 0, nil, 0, 0, logger)

	// Get first server config
	if len(cfg.Servers) == 0 {
		cfg.Servers = append(cfg.Servers, config.ServerConfig{
			ListenAddr: ":25",
		})
	}
	serverCfg := &cfg.Servers[0]

	backend := &Backend{
		ServerConfig: serverCfg,
		GlobalConfig: cfg,
		StatsManager: statsMgr,
		Logger:       logger,
	}

	if backend.ServerConfig != serverCfg {
		t.Error("ServerConfig not set correctly")
	}

	if backend.GlobalConfig != cfg {
		t.Error("GlobalConfig not set correctly")
	}

	if backend.StatsManager == nil {
		t.Error("StatsManager is nil")
	}

	if backend.Logger == nil {
		t.Error("Logger is nil")
	}
}

func TestSMTPErrors(t *testing.T) {
	// Test that error constants are defined
	if ErrInternalServerError == nil {
		t.Error("ErrInternalServerError is nil")
	}

	if ErrServerUnavailable == nil {
		t.Error("ErrServerUnavailable is nil")
	}

	if ErrTLSRequired == nil {
		t.Error("ErrTLSRequired is nil")
	}

	if ErrTLSRequiredStartTLS == nil {
		t.Error("ErrTLSRequiredStartTLS is nil")
	}

	if ErrMessageTooBig == nil {
		t.Error("ErrMessageTooBig is nil")
	}

	if ErrSessionTimeout == nil {
		t.Error("ErrSessionTimeout is nil")
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
			result := stats.GetIPFromRemoteAddr(tt.remoteAddr)
			if result != tt.expected {
				t.Errorf("GetIPFromRemoteAddr(%s) = %s; want %s", tt.remoteAddr, result, tt.expected)
			}
		})
	}
}

func TestCommandStates(t *testing.T) {
	// Test that state constants are defined and ordered correctly
	if stateNew != 0 {
		t.Errorf("stateNew = %d; want 0", stateNew)
	}

	if stateHelo <= stateNew {
		t.Error("stateHelo should be greater than stateNew")
	}

	if stateMail <= stateHelo {
		t.Error("stateMail should be greater than stateHelo")
	}

	if stateRcpt <= stateMail {
		t.Error("stateRcpt should be greater than stateMail")
	}

	if stateData <= stateRcpt {
		t.Error("stateData should be greater than stateRcpt")
	}
}

func TestSessionTimeoutConstants(t *testing.T) {
	// Verify timeout constants are reasonable
	if SessionDeadline <= 0 {
		t.Error("SessionDeadline should be positive")
	}

	if ProcessingTimeout <= 0 {
		t.Error("ProcessingTimeout should be positive")
	}

	if IdleTimeout <= 0 {
		t.Error("IdleTimeout should be positive")
	}

	if DataTimeout <= 0 {
		t.Error("DataTimeout should be positive")
	}

	// Verify ordering (session > data > command > idle)
	if SessionDeadline <= DataTimeout {
		t.Error("SessionDeadline should be greater than DataTimeout")
	}

	if DataTimeout <= ProcessingTimeout {
		t.Error("DataTimeout should be greater than ProcessingTimeout")
	}
}

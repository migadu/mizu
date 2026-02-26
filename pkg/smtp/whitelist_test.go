package smtp

import (
	"io"
	"log/slog"
	"testing"

	"migadu/mizu/pkg/config"
)

func TestMatchIPWhitelist(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := &Backend{
		ServerConfig: &config.ServerConfig{Name: "test"},
		Logger:       logger,
	}

	tests := []struct {
		name           string
		ip             string
		whitelistEntry string
		expected       bool
	}{
		// Exact IP matches
		{
			name:           "exact IPv4 match",
			ip:             "1.2.3.4",
			whitelistEntry: "1.2.3.4",
			expected:       true,
		},
		{
			name:           "exact IPv4 no match",
			ip:             "1.2.3.4",
			whitelistEntry: "1.2.3.5",
			expected:       false,
		},
		{
			name:           "exact IPv6 match",
			ip:             "2001:db8::1",
			whitelistEntry: "2001:db8::1",
			expected:       true,
		},

		// CIDR matches
		{
			name:           "IPv4 CIDR match /24",
			ip:             "10.0.1.50",
			whitelistEntry: "10.0.1.0/24",
			expected:       true,
		},
		{
			name:           "IPv4 CIDR no match /24",
			ip:             "10.0.2.50",
			whitelistEntry: "10.0.1.0/24",
			expected:       false,
		},
		{
			name:           "IPv4 CIDR match /8",
			ip:             "10.50.100.200",
			whitelistEntry: "10.0.0.0/8",
			expected:       true,
		},
		{
			name:           "IPv6 CIDR match",
			ip:             "2001:db8::1234",
			whitelistEntry: "2001:db8::/32",
			expected:       true,
		},

		// Edge cases
		{
			name:           "invalid IP",
			ip:             "not-an-ip",
			whitelistEntry: "1.2.3.4",
			expected:       false,
		},
		{
			name:           "invalid CIDR",
			ip:             "1.2.3.4",
			whitelistEntry: "1.2.3.4/99",
			expected:       false,
		},
		{
			name:           "invalid whitelist IP",
			ip:             "1.2.3.4",
			whitelistEntry: "not-an-ip",
			expected:       false,
		},

		// Real-world monitoring service examples
		{
			name:           "Hetrix Tools IP",
			ip:             "189.1.173.35",
			whitelistEntry: "189.1.173.35",
			expected:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := backend.matchIPWhitelist(tt.ip, tt.whitelistEntry)
			if result != tt.expected {
				t.Errorf("matchIPWhitelist(%q, %q) = %v, want %v", tt.ip, tt.whitelistEntry, result, tt.expected)
			}
		})
	}
}

func TestMatchHostWhitelist(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := &Backend{
		ServerConfig: &config.ServerConfig{Name: "test"},
		Logger:       logger,
	}

	tests := []struct {
		name          string
		ptrHost       string
		whitelistHost string
		expected      bool
	}{
		// Exact matches
		{
			name:          "exact match",
			ptrHost:       "hetrixtools.com",
			whitelistHost: "hetrixtools.com",
			expected:      true,
		},
		{
			name:          "exact match with trailing dot",
			ptrHost:       "hetrixtools.com.",
			whitelistHost: "hetrixtools.com",
			expected:      true,
		},

		// Suffix matches
		{
			name:          "subdomain suffix match",
			ptrHost:       "wk9-4.hetrixtools.com",
			whitelistHost: "hetrixtools.com",
			expected:      true,
		},
		{
			name:          "subdomain suffix match with trailing dot",
			ptrHost:       "wk9-4.hetrixtools.com.",
			whitelistHost: "hetrixtools.com",
			expected:      true,
		},
		{
			name:          "multi-level subdomain suffix match",
			ptrHost:       "server.monitoring.hetrixtools.com",
			whitelistHost: "hetrixtools.com",
			expected:      true,
		},
		{
			name:          "no match different domain",
			ptrHost:       "mail.example.com",
			whitelistHost: "hetrixtools.com",
			expected:      false,
		},
		{
			name:          "no match partial suffix",
			ptrHost:       "fakehetrixtools.com",
			whitelistHost: "hetrixtools.com",
			expected:      false,
		},

		// Case insensitivity
		{
			name:          "case insensitive match",
			ptrHost:       "WK9-4.HetrixTools.COM",
			whitelistHost: "hetrixtools.com",
			expected:      true,
		},

		// Real-world examples
		{
			name:          "Hetrix Tools actual hostname",
			ptrHost:       "wk9-4.hetrixtools.com.",
			whitelistHost: "hetrixtools.com",
			expected:      true,
		},
		{
			name:          "Pingdom hostname",
			ptrHost:       "probe-123.pingdom.com",
			whitelistHost: "pingdom.com",
			expected:      true,
		},
		{
			name:          "UptimeRobot hostname",
			ptrHost:       "static.456.78.90.clients.your-server.de",
			whitelistHost: "your-server.de",
			expected:      true,
		},

		// Edge cases
		{
			name:          "empty PTR",
			ptrHost:       "",
			whitelistHost: "hetrixtools.com",
			expected:      false,
		},
		{
			name:          "empty whitelist",
			ptrHost:       "wk9-4.hetrixtools.com",
			whitelistHost: "",
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := backend.matchHostWhitelist(tt.ptrHost, tt.whitelistHost)
			if result != tt.expected {
				t.Errorf("matchHostWhitelist(%q, %q) = %v, want %v", tt.ptrHost, tt.whitelistHost, result, tt.expected)
			}
		})
	}
}

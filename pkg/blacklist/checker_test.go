package blacklist

import (
	"io"

	"net"
	"testing"
	"time"

	"log/slog"
)

func TestReverseIPAddress(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{
			name:     "standard IPv4",
			ip:       "192.168.1.1",
			expected: "1.1.168.192",
		},
		{
			name:     "localhost",
			ip:       "127.0.0.1",
			expected: "1.0.0.127",
		},
		{
			name:     "IPv6 standard",
			ip:       "2001:0db8::1",
			expected: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
		},
		{
			name:     "IPv6 with hex digits",
			ip:       "2001:41d0:203:199d::f",
			expected: "f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.9.9.1.3.0.2.0.0.d.1.4.1.0.0.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}
			result := reverseIP(ip)
			if result != tt.expected {
				t.Errorf("reverseIP(%s) = %s; want %s", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestGetSpamhausReason(t *testing.T) {
	tests := []struct {
		code     byte
		expected string
	}{
		{2, "SBL - Spam source"},
		{3, "CSS - Snowshoe spam"},
		{4, "XBL - Exploited/compromised"},
		{5, "XBL - Exploited/compromised"},
		{6, "XBL - Exploited/compromised"},
		{7, "XBL - Exploited/compromised"},
		{9, "DROP - Hijacked netblocks"},
		{10, "PBL - Policy block list"},
		{11, "PBL - Policy block list"},
		{99, "Code 99"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := getSpamhausReason(tt.code)
			if result != tt.expected {
				t.Errorf("getSpamhausReason(%d) = %s; want %s", tt.code, result, tt.expected)
			}
		})
	}
}

func TestCheckHELOResolves(t *testing.T) {
	tests := []struct {
		name          string
		hostname      string
		shouldResolve bool
		expectError   bool
		expectReason  string
	}{
		{
			name:          "IP in brackets",
			hostname:      "[192.168.1.1]",
			shouldResolve: true,
			expectError:   false,
			expectReason:  "IP address literal",
		},
		{
			name:          "valid hostname",
			hostname:      "localhost",
			shouldResolve: true,
			expectError:   false,
			expectReason:  "Valid hostname",
		},
		{
			name:          "invalid hostname",
			hostname:      "this-hostname-definitely-does-not-exist-12345.invalid",
			shouldResolve: false,
			expectError:   false, // A non-resolving host is a valid check, not an error
			expectReason:  "Hostname does not resolve",
		},
		{
			name:          "empty hostname",
			hostname:      "",
			shouldResolve: false,
			expectError:   false, // Should not resolve, but not error
			expectReason:  "Empty hostname",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolves, reason, err := CheckHELOResolves(tt.hostname, 2*time.Second)

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if !tt.expectError && resolves != tt.shouldResolve {
				t.Errorf("CheckHELOResolves(%s) = %v; want %v", tt.hostname, resolves, tt.shouldResolve)
			}

			if !tt.expectError && reason != tt.expectReason {
				t.Errorf("CheckHELOResolves(%s) reason = %q; want %q", tt.hostname, reason, tt.expectReason)
			}
		})
	}
}

func TestNewChecker(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	lists := []string{"zen.spamhaus.org", "bl.spamcop.net"}
	timeout := 3 * time.Second

	checker := NewChecker(lists, timeout, logger)

	if checker == nil {
		t.Fatal("NewChecker returned nil")
	}

	if len(checker.lists) != len(lists) {
		t.Errorf("checker has %d lists; want %d", len(checker.lists), len(lists))
	}

	if checker.timeout != timeout {
		t.Errorf("checker timeout = %v; want %v", checker.timeout, timeout)
	}

	if checker.resolver == nil {
		t.Error("checker resolver is nil")
	}
}

func TestCheckerCheckIP_ValidIP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Use a non-existent blacklist to ensure we get a clean non-listed result
	checker := NewChecker([]string{"invalid-blacklist-that-does-not-exist.example"}, 1*time.Second, logger)

	ip := net.ParseIP("8.8.8.8")
	if ip == nil {
		t.Fatal("failed to parse IP")
	}

	isListed, reason, err := checker.CheckIP(ip)

	// We expect no error and not listed since the blacklist doesn't exist
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if isListed {
		t.Errorf("IP should not be listed, but got: %s", reason)
	}
}

func TestCheckerCheckIP_IPv6(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Use a non-existent IPv6 blacklist
	checker := NewChecker([]string{"invalid-ipv6-blacklist.example"}, 1*time.Second, logger)

	// Test with IPv6 (now supported)
	ip := net.ParseIP("2001:0db8::1")
	if ip == nil {
		t.Fatal("failed to parse IP")
	}

	isListed, _, err := checker.CheckIP(ip)

	// Should not return error (IPv6 is supported)
	if err != nil {
		t.Errorf("unexpected error for IPv6: %v", err)
	}

	// Should not be listed (blacklist doesn't exist)
	if isListed {
		t.Error("IPv6 should not be listed on non-existent blacklist")
	}
}

func TestCheckerCheckIP_Timeout(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Use very short timeout to test timeout behavior
	checker := NewChecker([]string{"zen.spamhaus.org"}, 1*time.Nanosecond, logger)

	ip := net.ParseIP("8.8.8.8")
	if ip == nil {
		t.Fatal("failed to parse IP")
	}

	// With such a short timeout, the lookup should fail but not return listed
	isListed, _, _ := checker.CheckIP(ip)

	// Even with timeout, we should fail open (not block)
	if isListed {
		t.Error("IP should not be listed when timeout occurs (fail open)")
	}
}

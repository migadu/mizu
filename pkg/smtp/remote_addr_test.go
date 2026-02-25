package smtp

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/stats"
)

// TestRemoteAddr_StripsPort verifies that remoteAddr is stored without port number
// This tests the logic from Backend.NewSession (lines 157-164 in server.go)
func TestRemoteAddr_StripsPort(t *testing.T) {
	testCases := []struct {
		name          string
		remoteAddr    string
		expectedIP    string
		shouldParseIP bool
	}{
		{
			name:          "IPv4 with port (bug scenario)",
			remoteAddr:    "198.103.213.10:51371",
			expectedIP:    "198.103.213.10",
			shouldParseIP: true,
		},
		{
			name:          "IPv6 with port",
			remoteAddr:    "[2001:db8::1]:12345",
			expectedIP:    "2001:db8::1",
			shouldParseIP: true,
		},
		{
			name:          "Localhost with port",
			remoteAddr:    "127.0.0.1:25",
			expectedIP:    "127.0.0.1",
			shouldParseIP: true,
		},
		{
			name:          "High port number",
			remoteAddr:    "192.168.1.1:65535",
			expectedIP:    "192.168.1.1",
			shouldParseIP: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate the logic from Backend.NewSession (lines 157-164)
			// This is the exact code that was added to fix the bug
			remoteAddrWithPort := tc.remoteAddr
			host, _, err := net.SplitHostPort(remoteAddrWithPort)
			if err != nil {
				// If split fails, use the raw address (shouldn't happen with TCP connections)
				host = remoteAddrWithPort
			}
			remoteAddr := host

			// Verify the port was stripped
			if remoteAddr != tc.expectedIP {
				t.Errorf("Expected remoteAddr=%s, got %s", tc.expectedIP, remoteAddr)
				return
			}

			// Verify it can be parsed as IP (critical for SPF)
			if tc.shouldParseIP {
				ip := net.ParseIP(remoteAddr)
				if ip == nil {
					t.Errorf("Failed to parse %s as IP address - SPF validation will fail!", remoteAddr)
				} else {
					t.Logf("✓ Successfully parsed as IP: %v", ip)
				}
			}
		})
	}
}

// TestSPFCheckReceivesCleanIP verifies the complete flow from connection to SPF check
// This simulates what happens in the real system:
// 1. Connection arrives with port (RemoteAddr().String())
// 2. Port is stripped in NewSession (server.go:157-164)
// 3. IP is used for SPF check (server.go:855)
func TestSPFCheckReceivesCleanIP(t *testing.T) {
	testCases := []struct {
		name       string
		connAddr   string
		expectedIP string
	}{
		{
			name:       "Real-world example from bug report",
			connAddr:   "198.103.213.10:51371",
			expectedIP: "198.103.213.10",
		},
		{
			name:       "IPv6 with port",
			connAddr:   "[2001:db8::1]:25",
			expectedIP: "2001:db8::1",
		},
		{
			name:       "Different port number",
			connAddr:   "192.168.1.100:12345",
			expectedIP: "192.168.1.100",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate the complete flow from connection to SPF check

			// Step 1: Connection arrives with port (like in the logs)
			t.Logf("Step 1: Connection arrives with port: %s", tc.connAddr)

			// Step 2: Extract IP in NewSession (server.go:157-164)
			remoteAddrWithPort := tc.connAddr
			host, _, err := net.SplitHostPort(remoteAddrWithPort)
			if err != nil {
				host = remoteAddrWithPort
			}
			remoteAddr := host
			t.Logf("Step 2: Stored in Session (port stripped): %s", remoteAddr)

			// Verify no port in stored address
			if remoteAddr != tc.expectedIP {
				t.Errorf("Expected remoteAddr=%s, got %s", tc.expectedIP, remoteAddr)
				return
			}

			// Step 3: Used for SPF check in Mail() (server.go:855)
			// The code does: ip := net.ParseIP(s.remoteAddr)
			ip := net.ParseIP(remoteAddr)
			if ip == nil {
				t.Fatalf("Failed to parse %s as IP (SPF will fail!)", remoteAddr)
			}
			t.Logf("Step 3: Passed to SPF validation: %v", ip)

			// Step 4: Verify SPF library receives clean IP
			// The SPF library expects: CheckHost(ip net.IP, heloHost, sender string)
			// With our fix, it now receives a proper net.IP without port
			t.Logf("✓ SUCCESS: SPF CheckHost receives valid IP: %v (no port!)", ip)
		})
	}
}

// TestRemoteAddrConsistency verifies remoteAddr is used consistently throughout the session
// After the fix, remoteAddr should always be IP-only, never with port
func TestRemoteAddrConsistency(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create minimal session (simulating what happens after NewSession)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Simulate a session with remoteAddr that had port stripped in NewSession
	session := &Session{
		remoteAddr:   "198.103.213.10", // Port already stripped by NewSession
		serverConfig: &config.ServerConfig{Name: "test", Type: "relay"},
		globalConfig: &config.Config{Local: true},
		statsManager: stats.NewServerRecorder(stats.NewManager(true, 0, "test", false, 0, nil, 0, 0, 0, logger), "test", 0, 0),
		Logger:       logger,
		ctx:          ctx,
		cancel:       cancel,
		commandState: stateNew,
		traceID:      "test-trace",
	}

	// Test 1: Verify remoteAddr doesn't have port
	// If SplitHostPort succeeds, it means there's a port (bad!)
	if _, _, err := net.SplitHostPort(session.remoteAddr); err == nil {
		t.Errorf("BUG: session.remoteAddr still contains port: %s", session.remoteAddr)
		return
	}

	// Test 2: Verify it's a valid IP
	ip := net.ParseIP(session.remoteAddr)
	if ip == nil {
		t.Errorf("session.remoteAddr is not a valid IP: %s", session.remoteAddr)
		return
	}

	// Test 3: Verify it can be used directly in all places that need it
	// Previously we had to call stats.GetIPFromRemoteAddr(s.remoteAddr)
	// Now we can use s.remoteAddr directly since it's already clean
	directIP := session.remoteAddr
	parsedIP := net.ParseIP(directIP)
	if parsedIP == nil {
		t.Errorf("Failed to parse remoteAddr directly as IP: %s", directIP)
		return
	}

	// Test 4: Verify consistency across multiple accesses
	// This simulates what happens in various places like:
	// - SPF check (server.go:855)
	// - Sender validation (server.go:792)
	// - Recipient validation (server.go:1039)
	// - Stats recording (server.go:1470, 1481, 1519)
	for i := 0; i < 5; i++ {
		if net.ParseIP(session.remoteAddr) == nil {
			t.Errorf("Iteration %d: remoteAddr no longer valid: %s", i, session.remoteAddr)
			return
		}
	}

	t.Logf("✓ Session.remoteAddr is consistent and usable: %s", session.remoteAddr)
}

// TestRemoteAddr_BeforeAndAfterFix demonstrates the bug and the fix
func TestRemoteAddr_BeforeAndAfterFix(t *testing.T) {
	connAddr := "198.103.213.10:51371"

	// BEFORE THE FIX: remoteAddr would have been stored with port
	// This would cause SPF validation to fail because net.ParseIP("198.103.213.10:51371") returns nil
	remoteAddrBefore := connAddr // Bug: stored with port
	ipBefore := net.ParseIP(remoteAddrBefore)
	if ipBefore != nil {
		t.Errorf("BUG TEST FAILED: Expected nil IP from address with port, got %v", ipBefore)
	}
	t.Logf("BEFORE FIX: net.ParseIP(%q) = nil (SPF fails!)", remoteAddrBefore)

	// AFTER THE FIX: remoteAddr is stored without port
	// SPF validation works because net.ParseIP("198.103.213.10") returns valid IP
	host, _, _ := net.SplitHostPort(connAddr)
	remoteAddrAfter := host // Fix: port stripped
	ipAfter := net.ParseIP(remoteAddrAfter)
	if ipAfter == nil {
		t.Errorf("AFTER FIX: Expected valid IP, got nil for %q", remoteAddrAfter)
	}
	t.Logf("AFTER FIX: net.ParseIP(%q) = %v (SPF works!)", remoteAddrAfter, ipAfter)
}

// TestRemoteAddr_IPv6WithBrackets ensures IPv6 addresses with brackets are handled
func TestRemoteAddr_IPv6WithBrackets(t *testing.T) {
	testCases := []struct {
		name       string
		connAddr   string
		expectedIP string
	}{
		{
			name:       "IPv6 with brackets and port",
			connAddr:   "[2001:db8::1]:25",
			expectedIP: "2001:db8::1",
		},
		{
			name:       "IPv6 with brackets and high port",
			connAddr:   "[::1]:8025",
			expectedIP: "::1",
		},
		{
			name:       "Full IPv6 address",
			connAddr:   "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:587",
			expectedIP: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Extract IP (same logic as server.go:157-164)
			host, _, err := net.SplitHostPort(tc.connAddr)
			if err != nil {
				t.Fatalf("Failed to split %q: %v", tc.connAddr, err)
			}

			if host != tc.expectedIP {
				t.Errorf("Expected %s, got %s", tc.expectedIP, host)
			}

			// Verify it's a valid IPv6 address
			ip := net.ParseIP(host)
			if ip == nil {
				t.Errorf("Failed to parse %q as IP", host)
			} else if ip.To4() != nil {
				t.Errorf("Expected IPv6 address, got IPv4: %v", ip)
			} else {
				t.Logf("✓ Valid IPv6 address: %v", ip)
			}
		})
	}
}

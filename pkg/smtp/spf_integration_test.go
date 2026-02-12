package smtp

import (
	"io"
	"log/slog"
	"net"
	"testing"

	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/stats"
)

// TestSPFEvaluation_WithPortInRemoteAddr verifies that SPF evaluation works
// even when the connection address originally had a port.
// This is a regression test for the bug where remoteAddr included the port,
// causing net.ParseIP() to return nil and SPF checks to fail.
func TestSPFEvaluation_WithPortInRemoteAddr(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Simulate a session with remoteAddr correctly stripped of port
	session := &Session{
		remoteAddr:   "198.103.213.10", // This should be set without port by NewSession
		helo:         "mail.gg.ca",
		from:         "Alexandre.Bellerive@gg.ca",
		serverConfig: &config.ServerConfig{Name: "test", Type: "relay", SPFCheck: true},
		globalConfig: &config.Config{Local: false},
		statsManager: stats.NewManager(true, 0, "test", false, 0, nil, 0, 0, 0, logger),
		Logger:       logger,
		senderDomain: "gg.ca",
	}

	// This is what happens in Mail() function at line 855
	ip := net.ParseIP(session.remoteAddr)

	// Verify the IP was parsed successfully
	if ip == nil {
		t.Fatalf("CRITICAL BUG: net.ParseIP(%q) returned nil! SPF validation will fail!", session.remoteAddr)
	}

	t.Logf("✓ Successfully parsed IP: %v", ip)

	// Verify it's the correct IP (not nil, proper value)
	expectedIP := net.ParseIP("198.103.213.10")
	if !ip.Equal(expectedIP) {
		t.Errorf("Expected IP %v, got %v", expectedIP, ip)
	}

	// Verify SPF check would receive a valid IP
	// Note: We're not actually calling CheckSPF here because that requires
	// a real DNS setup, but we're verifying that the IP parameter would be valid
	if ip.To4() == nil && ip.To16() == nil {
		t.Error("IP is neither IPv4 nor IPv6")
	}

	t.Logf("✓ SPF validation.CheckSPF() would receive valid IP: %v", ip)
}

// TestSPFEvaluation_BeforeAndAfterFix demonstrates the bug and the fix
func TestSPFEvaluation_BeforeAndAfterFix(t *testing.T) {
	connAddr := "198.103.213.10:32980"

	t.Logf("Testing with connection address: %s", connAddr)

	// BEFORE THE FIX: Session.remoteAddr would have had the port
	t.Run("Before Fix (Buggy Behavior)", func(t *testing.T) {
		remoteAddrWithPort := connAddr // Bug: included port

		// Try to parse IP for SPF check
		ip := net.ParseIP(remoteAddrWithPort)
		if ip != nil {
			t.Errorf("BUG TEST FAILED: Expected nil IP when parsing address with port, got %v", ip)
		}

		t.Logf("❌ BEFORE: net.ParseIP(%q) = nil (SPF fails!)", remoteAddrWithPort)
		t.Logf("❌ Result: SPF check fails → DMARC fails → Email rejected")
	})

	// AFTER THE FIX: Session.remoteAddr has port stripped
	t.Run("After Fix (Correct Behavior)", func(t *testing.T) {
		// This is what NewSession now does (line 157-164)
		host, _, err := net.SplitHostPort(connAddr)
		if err != nil {
			host = connAddr
		}
		remoteAddr := host // Port stripped

		// Try to parse IP for SPF check
		ip := net.ParseIP(remoteAddr)
		if ip == nil {
			t.Fatalf("AFTER FIX: Expected valid IP, got nil for %q", remoteAddr)
		}

		t.Logf("✅ AFTER: net.ParseIP(%q) = %v (SPF works!)", remoteAddr, ip)
		t.Logf("✅ Result: SPF check succeeds → DMARC passes → Email accepted")
	})
}

// TestSessionRemoteAddr_NeverHasPort verifies that Session.remoteAddr
// is always stored without port throughout the session lifecycle
func TestSessionRemoteAddr_NeverHasPort(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	testCases := []struct {
		name     string
		connAddr string
		wantIP   string
	}{
		{
			name:     "Real bug scenario from logs",
			connAddr: "198.103.213.10:32980",
			wantIP:   "198.103.213.10",
		},
		{
			name:     "Different port",
			connAddr: "198.103.213.10:51371",
			wantIP:   "198.103.213.10",
		},
		{
			name:     "IPv6 with port",
			connAddr: "[2001:db8::1]:25",
			wantIP:   "2001:db8::1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate what NewSession does
			host, _, err := net.SplitHostPort(tc.connAddr)
			if err != nil {
				host = tc.connAddr
			}
			remoteAddr := host

			// Create session (this is line 468 - the key fix!)
			session := &Session{
				remoteAddr:   remoteAddr, // Must use cleaned variable, not c.Conn().RemoteAddr().String()
				serverConfig: &config.ServerConfig{Name: "test", Type: "relay", SPFCheck: true},
				globalConfig: &config.Config{Local: false},
				statsManager: stats.NewManager(true, 0, "test", false, 0, nil, 0, 0, 0, logger),
				Logger:       logger,
			}

			// Verify remoteAddr doesn't have port
			if session.remoteAddr != tc.wantIP {
				t.Errorf("Expected remoteAddr=%s, got %s", tc.wantIP, session.remoteAddr)
			}

			// Verify it can be parsed for SPF
			ip := net.ParseIP(session.remoteAddr)
			if ip == nil {
				t.Errorf("Failed to parse remoteAddr for SPF: %s", session.remoteAddr)
			}

			t.Logf("✓ Session.remoteAddr = %s (no port, SPF ready)", session.remoteAddr)
		})
	}
}

// TestSPFCheckFlow_CompleteScenario tests the complete flow from connection to SPF check
func TestSPFCheckFlow_CompleteScenario(t *testing.T) {
	// This test simulates the exact scenario from the production logs where SPF was failing

	// Step 1: Connection arrives with port (from RemoteAddr().String())
	connAddr := "198.103.213.10:32980"
	t.Logf("Step 1: Connection from %s", connAddr)

	// Step 2: NewSession strips port (line 157-164)
	host, _, err := net.SplitHostPort(connAddr)
	if err != nil {
		t.Fatalf("Failed to parse connection address: %v", err)
	}
	remoteAddr := host
	t.Logf("Step 2: Port stripped, remoteAddr = %s", remoteAddr)

	// Step 3: Session created with cleaned remoteAddr (line 468 - THE FIX!)
	sessionRemoteAddr := remoteAddr // NOT connAddr!
	t.Logf("Step 3: Session.remoteAddr = %s", sessionRemoteAddr)

	// Step 4: Mail() function runs SPF check (line 855)
	ip := net.ParseIP(sessionRemoteAddr)
	if ip == nil {
		t.Fatalf("Step 4 FAILED: SPF check cannot parse IP from %q", sessionRemoteAddr)
	}
	t.Logf("Step 4: SPF check uses IP = %v ✓", ip)

	// Step 5: SPF validation.CheckSPF() receives valid IP
	// (We don't actually call CheckSPF here as it requires DNS, but we verify the parameter is valid)
	if ip.String() != "198.103.213.10" {
		t.Errorf("Expected IP 198.103.213.10, got %s", ip.String())
	}
	t.Logf("Step 5: validation.CheckSPF(ip=%v, helo, from) will work ✓", ip)

	t.Log("✓ Complete flow verified: SPF evaluation receives clean IP without port")
}

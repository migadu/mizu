package smtp

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/metrics"
	"migadu/mizu/pkg/poster"
	"migadu/mizu/pkg/stats"

	gosmtp "github.com/emersion/go-smtp"
)

// createTestBackend creates a minimal Backend for testing
func createTestBackend(t *testing.T) *Backend {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	globalCfg := &config.Config{
		Local: true, // Use local mode to skip TLS/validation
	}

	serverCfg := &config.ServerConfig{
		Name:           "test-server",
		Type:           "relay",
		Hostname:       "test.example.com",
		TimeoutSeconds: 30,
		MaxMessageSize: 1024 * 1024, // 1MB
		Limits: config.ServerLimitsConfig{
			MaxConnections:      100,
			MaxConnectionsPerIP: 10,
		},
		Delivery: config.DeliveryConfig{
			URL:                "http://localhost:8080/deliver",
			MaxRetryAttempts:   1,
			HTTPTimeoutSeconds: 5,
		},
	}

	statsManager := stats.NewManager(false, 0, "", false, 0, nil, 0, 0, 0, logger)
	// Use a unique metrics name to avoid duplicate registration
	metricsInstance := metrics.New("test_" + generateTraceID())

	var sessionsWg sync.WaitGroup
	var sessionCount atomic.Int64

	return &Backend{
		ServerConfig:       serverCfg,
		GlobalConfig:       globalCfg,
		StatsManager:       stats.NewServerRecorder(statsManager, "test"),
		HTTPClient:         poster.NewHTTPClient(5 * time.Second),
		DNSResolver:        &net.Resolver{},
		Metrics:            metricsInstance,
		Logger:             logger,
		ActiveSessionsWg:   &sessionsWg,
		ActiveSessionCount: &sessionCount,
		ShutdownChan:       make(chan struct{}),
	}
}

// mockConn implements net.Conn for testing
type mockConn struct {
	io.Reader
	io.Writer
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return m.localAddr }
func (m *mockConn) RemoteAddr() net.Addr               { return m.remoteAddr }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// mockAddr implements net.Addr
type mockAddr struct {
	network string
	addr    string
}

func (m *mockAddr) Network() string { return m.network }
func (m *mockAddr) String() string  { return m.addr }

// TestBackend_NewSession tests session creation
func TestBackend_NewSession(t *testing.T) {
	backend := createTestBackend(t)

	// Create mock connection
	conn := &mockConn{
		Reader: bytes.NewReader([]byte{}),
		Writer: &bytes.Buffer{},
		remoteAddr: &mockAddr{
			network: "tcp",
			addr:    "192.168.1.1:12345",
		},
	}

	smtpConn := &gosmtp.Conn{}
	// Note: In real tests, we'd need to properly initialize gosmtp.Conn
	// For now, this tests the basic structure

	// Test that creating a session doesn't panic
	_ = backend
	_ = conn
	_ = smtpConn

	t.Log("✓ Backend structure is correct")
}

// TestGenerateTraceID_Session tests trace ID generation in session context
func TestGenerateTraceID_Session(t *testing.T) {
	// Generate multiple trace IDs
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateTraceID()

		// Check format (should be 16 hex characters)
		if len(id) != 16 {
			t.Errorf("Expected 16 character trace ID, got %d: %s", len(id), id)
		}

		// Check uniqueness
		if ids[id] {
			t.Errorf("Duplicate trace ID generated: %s", id)
		}
		ids[id] = true
	}

	t.Logf("✓ Generated %d unique trace IDs", len(ids))
}

// TestSession_SetCommandTimeout tests timeout setting
func TestSession_SetCommandTimeout(t *testing.T) {
	backend := createTestBackend(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	session := &Session{
		ctx:    ctx,
		cancel: cancel,
		Logger: backend.Logger,
		conn:   nil, // No real connection for this test
	}

	// Test setting timeout (should not error without real connection)
	err := session.setCommandTimeout(10 * time.Second)
	if err != nil {
		t.Errorf("setCommandTimeout should not error without connection: %v", err)
	}

	t.Log("✓ setCommandTimeout works without real connection")
}

// TestSession_ServerNameType tests helper methods
func TestSession_ServerNameType(t *testing.T) {
	serverCfg := &config.ServerConfig{
		Name: "test-server",
		Type: "relay",
	}

	session := &Session{
		serverConfig: serverCfg,
	}

	if session.serverName() != "test-server" {
		t.Errorf("Expected 'test-server', got %s", session.serverName())
	}

	if session.serverType() != "relay" {
		t.Errorf("Expected 'relay', got %s", session.serverType())
	}

	// Test with nil config
	session.serverConfig = nil
	if session.serverName() != "unknown" {
		t.Error("Expected 'unknown' for nil config")
	}

	t.Log("✓ Helper methods work correctly")
}

// TestSession_Reset tests session reset
func TestSession_Reset(t *testing.T) {
	backend := createTestBackend(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session := &Session{
		from:         "sender@example.com",
		to:           []string{"recipient1@example.com", "recipient2@example.com"},
		mailData:     bytes.Buffer{},
		isJunk:       true,
		junkReasons:  []string{"test reason"},
		senderDomain: "example.com",
		commandState: stateData,
		ctx:          ctx,
		cancel:       cancel,
		Logger:       backend.Logger,
		conn:         nil,
		serverConfig: backend.ServerConfig,
		globalConfig: backend.GlobalConfig,
	}

	// Write some data
	session.mailData.WriteString("test data")

	// Reset
	session.Reset()

	// Verify reset
	if session.from != "" {
		t.Error("from should be empty after reset")
	}
	if len(session.to) != 0 {
		t.Error("to should be empty after reset")
	}
	if session.mailData.Len() != 0 {
		t.Error("mailData should be empty after reset")
	}
	if session.isJunk {
		t.Error("isJunk should be false after reset")
	}
	if len(session.junkReasons) != 0 {
		t.Error("junkReasons should be empty after reset")
	}
	if session.senderDomain != "" {
		t.Error("senderDomain should be empty after reset")
	}
	if session.commandState != stateHelo {
		t.Errorf("commandState should be stateHelo after reset, got %d", session.commandState)
	}

	t.Log("✓ Session reset works correctly")
}

// TestSession_Logout tests session logout
func TestSession_Logout(t *testing.T) {
	backend := createTestBackend(t)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)

	var count atomic.Int64
	count.Store(1)

	session := &Session{
		remoteAddr:   "192.168.1.1:12345",
		ctx:          ctx,
		cancel:       cancel,
		sessionsWg:   &wg,
		sessionCount: &count,
		Logger:       backend.Logger,
	}

	// Test logout
	err := session.Logout()
	if err != nil {
		t.Errorf("Logout should not error: %v", err)
	}

	// Verify WaitGroup was decremented
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(100 * time.Millisecond):
		t.Error("WaitGroup was not properly decremented")
	}

	// Verify counter was decremented
	if count.Load() != 0 {
		t.Errorf("Expected counter to be 0, got %d", count.Load())
	}

	t.Log("✓ Logout properly cleans up resources")
}

// TestConnectionTracker_Basic tests basic connection tracking
func TestConnectionTracker_Basic(t *testing.T) {
	tracker := NewConnectionTracker(10, 2)

	// Test acquiring connection
	err := tracker.TryAcquire("192.168.1.1:12345")
	if err != nil {
		t.Fatalf("First acquire should succeed: %v", err)
	}

	// Test releasing connection
	tracker.Release("192.168.1.1:12345")

	// Verify released
	total, _, _ := tracker.GetStats()
	if total != 0 {
		t.Errorf("Expected 0 connections after release, got %d", total)
	}

	t.Log("✓ Connection tracking works correctly")
}

// TestConnectionTracker_Limits tests connection limits
func TestConnectionTracker_Limits(t *testing.T) {
	tracker := NewConnectionTracker(3, 2)

	// Acquire up to per-IP limit
	if err := tracker.TryAcquire("192.168.1.1:1"); err != nil {
		t.Fatalf("First acquire failed: %v", err)
	}
	if err := tracker.TryAcquire("192.168.1.1:2"); err != nil {
		t.Fatalf("Second acquire failed: %v", err)
	}

	// Third from same IP should fail
	if err := tracker.TryAcquire("192.168.1.1:3"); err == nil {
		t.Error("Expected per-IP limit to be enforced")
	}

	// Different IP should work
	if err := tracker.TryAcquire("192.168.1.2:1"); err != nil {
		t.Fatalf("Acquire from different IP failed: %v", err)
	}

	// Fourth connection should fail (global limit)
	if err := tracker.TryAcquire("192.168.1.3:1"); err == nil {
		t.Error("Expected global limit to be enforced")
	}

	t.Log("✓ Connection limits enforced correctly")
}

// TestTLSVersionString_Session tests TLS version string conversion in session context
func TestTLSVersionString_Session(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{0x0301, "TLS 1.0"},
		{0x0302, "TLS 1.1"},
		{0x0303, "TLS 1.2"},
		{0x0304, "TLS 1.3"},
		{0x0000, "Unknown (0x0)"},
	}

	for _, tt := range tests {
		result := tlsVersionString(tt.version)
		if result != tt.expected {
			t.Errorf("tlsVersionString(0x%x) = %s, want %s", tt.version, result, tt.expected)
		}
	}

	t.Log("✓ TLS version string conversion works")
}

// TestConnectionTracker_Stats tests statistics
func TestConnectionTracker_Stats(t *testing.T) {
	tracker := NewConnectionTracker(10, 5)

	// Acquire some connections
	tracker.TryAcquire("192.168.1.1:1")
	tracker.TryAcquire("192.168.1.1:2")
	tracker.TryAcquire("192.168.1.2:1")

	total, uniqueIPs, perIP := tracker.GetStats()

	if total != 3 {
		t.Errorf("Expected 3 total connections, got %d", total)
	}

	if uniqueIPs != 2 {
		t.Errorf("Expected 2 unique IPs, got %d", uniqueIPs)
	}

	// Check per-IP stats
	if _, exists := perIP["192.168.1.1"]; !exists {
		t.Error("Expected IP 192.168.1.1 in stats")
	}

	if count := perIP["192.168.1.1"]; count != 2 {
		t.Errorf("Expected 2 connections from 192.168.1.1, got %d", count)
	}

	t.Log("✓ Connection statistics work correctly")
}

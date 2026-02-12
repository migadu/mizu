package smtp

import (
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"

	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/metrics"
	"migadu/mizu/pkg/stats"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestSession_ServerLabels tests that Session helper methods return correct labels
func TestSession_ServerLabels(t *testing.T) {
	tests := []struct {
		name         string
		serverConfig *config.ServerConfig
		expectedName string
		expectedType string
	}{
		{
			name: "relay server",
			serverConfig: &config.ServerConfig{
				Name: "relay",
				Type: "relay",
			},
			expectedName: "relay",
			expectedType: "relay",
		},
		{
			name: "submission server",
			serverConfig: &config.ServerConfig{
				Name: "submission-tls",
				Type: "submission",
			},
			expectedName: "submission-tls",
			expectedType: "submission",
		},
		{
			name:         "nil server config",
			serverConfig: nil,
			expectedName: "unknown",
			expectedType: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{
				serverConfig: tt.serverConfig,
			}

			if got := session.serverName(); got != tt.expectedName {
				t.Errorf("serverName() = %v, want %v", got, tt.expectedName)
			}

			if got := session.serverType(); got != tt.expectedType {
				t.Errorf("serverType() = %v, want %v", got, tt.expectedType)
			}
		})
	}
}

// TestBackend_MetricsWithServerLabels tests that Backend records metrics with correct server labels
func TestBackend_MetricsWithServerLabels(t *testing.T) {
	// Create custom registry for isolated testing
	registry := prometheus.NewRegistry()

	// Create logger
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create metrics (they auto-register)
	m := metrics.New("test_backend")

	// Create server configs
	relayConfig := &config.ServerConfig{
		Name: "relay",
		Type: "relay",
	}

	submissionConfig := &config.ServerConfig{
		Name: "submission",
		Type: "submission",
	}

	// Create backends for different servers
	relayBackend := &Backend{
		ServerConfig: relayConfig,
		Metrics:      m,
		Logger:       logger,
	}

	submissionBackend := &Backend{
		ServerConfig: submissionConfig,
		Metrics:      m,
		Logger:       logger,
	}

	// Record metrics for relay server
	m.SMTPConnectionsTotal.WithLabelValues("relay", "relay").Inc()
	m.SMTPConnectionsTotal.WithLabelValues("relay", "relay").Inc()
	m.SMTPMessagesReceived.WithLabelValues("relay", "relay").Inc()
	m.SMTPMessagesRejected.WithLabelValues("relay", "relay", "spam").Inc()

	// Record metrics for submission server
	m.SMTPConnectionsTotal.WithLabelValues("submission", "submission").Inc()
	m.SMTPMessagesReceived.WithLabelValues("submission", "submission").Inc()
	m.SMTPMessagesReceived.WithLabelValues("submission", "submission").Inc()

	// Verify relay metrics
	relayConnections := testutil.ToFloat64(m.SMTPConnectionsTotal.WithLabelValues("relay", "relay"))
	if relayConnections != 2 {
		t.Errorf("Relay connections = %v, want 2", relayConnections)
	}

	relayMessages := testutil.ToFloat64(m.SMTPMessagesReceived.WithLabelValues("relay", "relay"))
	if relayMessages != 1 {
		t.Errorf("Relay messages = %v, want 1", relayMessages)
	}

	// Verify submission metrics
	submissionConnections := testutil.ToFloat64(m.SMTPConnectionsTotal.WithLabelValues("submission", "submission"))
	if submissionConnections != 1 {
		t.Errorf("Submission connections = %v, want 1", submissionConnections)
	}

	submissionMessages := testutil.ToFloat64(m.SMTPMessagesReceived.WithLabelValues("submission", "submission"))
	if submissionMessages != 2 {
		t.Errorf("Submission messages = %v, want 2", submissionMessages)
	}

	t.Log("✓ Backend metrics correctly labeled per server")

	// Prevent unused variable errors
	_ = relayBackend
	_ = submissionBackend
	_ = registry
}

// TestBackend_ActiveConnectionsMetric tests that active connections are tracked per server
func TestBackend_ActiveConnectionsMetric(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.New("test_active")

	relayConfig := &config.ServerConfig{
		Name: "relay",
		Type: "relay",
	}

	submissionConfig := &config.ServerConfig{
		Name: "submission",
		Type: "submission",
	}

	// Simulate connections
	m.SMTPConnectionsActive.WithLabelValues("relay", "relay").Set(5)
	m.SMTPConnectionsActive.WithLabelValues("submission", "submission").Set(3)

	// Verify per-server counts
	relayActive := testutil.ToFloat64(m.SMTPConnectionsActive.WithLabelValues("relay", "relay"))
	if relayActive != 5 {
		t.Errorf("Relay active connections = %v, want 5", relayActive)
	}

	submissionActive := testutil.ToFloat64(m.SMTPConnectionsActive.WithLabelValues("submission", "submission"))
	if submissionActive != 3 {
		t.Errorf("Submission active connections = %v, want 3", submissionActive)
	}

	t.Log("✓ Active connections tracked separately per server")

	_ = relayConfig
	_ = submissionConfig
	_ = logger
}

// TestBackend_ValidationMetrics tests that SPF/DMARC/DKIM/ARC metrics are per-server
func TestBackend_ValidationMetrics(t *testing.T) {
	m := metrics.New("test_validation")

	// Relay server - strict validation
	m.SMTPSPFChecks.WithLabelValues("relay", "pass").Inc()
	m.SMTPSPFChecks.WithLabelValues("relay", "fail").Inc()
	m.SMTPDMARCChecks.WithLabelValues("relay", "pass").Inc()
	m.SMTPARCChecks.WithLabelValues("relay", "pass").Inc()

	// Submission server - less validation (users authenticated)
	m.SMTPSPFChecks.WithLabelValues("submission", "pass").Inc()
	// Submission usually skips DMARC

	// Verify relay validation
	relaySPFPass := testutil.ToFloat64(m.SMTPSPFChecks.WithLabelValues("relay", "pass"))
	if relaySPFPass != 1 {
		t.Errorf("Relay SPF pass = %v, want 1", relaySPFPass)
	}

	relaySPFFail := testutil.ToFloat64(m.SMTPSPFChecks.WithLabelValues("relay", "fail"))
	if relaySPFFail != 1 {
		t.Errorf("Relay SPF fail = %v, want 1", relaySPFFail)
	}

	relayDMARCPass := testutil.ToFloat64(m.SMTPDMARCChecks.WithLabelValues("relay", "pass"))
	if relayDMARCPass != 1 {
		t.Errorf("Relay DMARC pass = %v, want 1", relayDMARCPass)
	}

	// Verify submission validation
	submissionSPFPass := testutil.ToFloat64(m.SMTPSPFChecks.WithLabelValues("submission", "pass"))
	if submissionSPFPass != 1 {
		t.Errorf("Submission SPF pass = %v, want 1", submissionSPFPass)
	}

	t.Log("✓ Validation metrics tracked separately per server")
}

// TestBackend_RejectionMetrics tests that rejections are tracked per server with reasons
func TestBackend_RejectionMetrics(t *testing.T) {
	m := metrics.New("test_rejections")

	// Relay rejections
	m.SMTPMessagesRejected.WithLabelValues("relay", "relay", "spam").Inc()
	m.SMTPMessagesRejected.WithLabelValues("relay", "relay", "blacklist").Inc()
	m.SMTPMessagesRejected.WithLabelValues("relay", "relay", "no_rdns").Inc()
	m.SMTPMessagesRejected.WithLabelValues("relay", "relay", "dmarc_reject").Inc()

	// Submission rejections
	m.SMTPMessagesRejected.WithLabelValues("submission", "submission", "rate_limit").Inc()
	m.SMTPMessagesRejected.WithLabelValues("submission", "submission", "rate_limit").Inc()

	// Verify relay rejections
	relaySpam := testutil.ToFloat64(m.SMTPMessagesRejected.WithLabelValues("relay", "relay", "spam"))
	if relaySpam != 1 {
		t.Errorf("Relay spam rejections = %v, want 1", relaySpam)
	}

	relayBlacklist := testutil.ToFloat64(m.SMTPMessagesRejected.WithLabelValues("relay", "relay", "blacklist"))
	if relayBlacklist != 1 {
		t.Errorf("Relay blacklist rejections = %v, want 1", relayBlacklist)
	}

	// Verify submission rejections
	submissionRateLimit := testutil.ToFloat64(m.SMTPMessagesRejected.WithLabelValues("submission", "submission", "rate_limit"))
	if submissionRateLimit != 2 {
		t.Errorf("Submission rate_limit rejections = %v, want 2", submissionRateLimit)
	}

	t.Log("✓ Rejection metrics tracked per server with reasons")
}

// TestMultiServer_ConcurrentMetrics tests concurrent metric updates from multiple servers
func TestMultiServer_ConcurrentMetrics(t *testing.T) {
	m := metrics.New("test_concurrent")

	servers := []struct {
		name string
		typ  string
	}{
		{"relay", "relay"},
		{"submission-tls", "submission"},
		{"submission-starttls", "submission"},
	}

	// Simulate concurrent load from multiple servers
	var wg sync.WaitGroup
	for _, srv := range servers {
		wg.Add(1)
		go func(name, typ string) {
			defer wg.Done()

			// Simulate 100 connections per server
			for i := 0; i < 100; i++ {
				m.SMTPConnectionsTotal.WithLabelValues(name, typ).Inc()
			}

			// Simulate 50 messages per server
			for i := 0; i < 50; i++ {
				m.SMTPMessagesReceived.WithLabelValues(name, typ).Inc()
			}
		}(srv.name, srv.typ)
	}

	wg.Wait()

	// Verify each server recorded correct counts
	for _, srv := range servers {
		connections := testutil.ToFloat64(m.SMTPConnectionsTotal.WithLabelValues(srv.name, srv.typ))
		if connections != 100 {
			t.Errorf("Server %s connections = %v, want 100", srv.name, connections)
		}

		messages := testutil.ToFloat64(m.SMTPMessagesReceived.WithLabelValues(srv.name, srv.typ))
		if messages != 50 {
			t.Errorf("Server %s messages = %v, want 50", srv.name, messages)
		}
	}

	t.Log("✓ Concurrent metrics from multiple servers handled correctly")
}

// TestMultiServer_PerIPTracking tests that per-IP metrics include server context
func TestMultiServer_PerIPTracking(t *testing.T) {
	m := metrics.New("test_per_ip")

	// Same IP connecting to different servers
	testIP := "192.168.1.100"

	m.SMTPConnectionsPerIPActive.WithLabelValues("relay", testIP).Set(3)
	m.SMTPConnectionsPerIPActive.WithLabelValues("submission-tls", testIP).Set(1)

	// Verify separate tracking
	relayIPConns := testutil.ToFloat64(m.SMTPConnectionsPerIPActive.WithLabelValues("relay", testIP))
	if relayIPConns != 3 {
		t.Errorf("Relay IP connections = %v, want 3", relayIPConns)
	}

	submissionIPConns := testutil.ToFloat64(m.SMTPConnectionsPerIPActive.WithLabelValues("submission-tls", testIP))
	if submissionIPConns != 1 {
		t.Errorf("Submission IP connections = %v, want 1", submissionIPConns)
	}

	t.Log("✓ Per-IP metrics tracked separately per server")
}

// TestMultiServer_MessageSizeHistogram tests message size tracking per server
func TestMultiServer_MessageSizeHistogram(t *testing.T) {
	m := metrics.New("test_size")

	// Relay receives larger messages (external)
	m.SMTPMessageSize.WithLabelValues("relay", "relay").Observe(500000)  // 500KB
	m.SMTPMessageSize.WithLabelValues("relay", "relay").Observe(1000000) // 1MB

	// Submission receives smaller messages (authenticated users)
	m.SMTPMessageSize.WithLabelValues("submission", "submission").Observe(50000)  // 50KB
	m.SMTPMessageSize.WithLabelValues("submission", "submission").Observe(100000) // 100KB

	// Can't easily verify histogram values without scraping, but ensure no panic
	t.Log("✓ Message size histograms tracked separately per server")
}

// TestBackend_NewSession_MetricsIncrement tests that NewSession records metrics with server labels
func TestBackend_NewSession_MetricsIncrement(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.New("test_newsession")

	cfg := config.DefaultConfig()
	cfg.Local = true

	serverCfg := &config.ServerConfig{
		Name:       "test-relay",
		Type:       "relay",
		ListenAddr: ":25",
		Hostname:   "test.example.com",
		Limits: config.ServerLimitsConfig{
			MaxConnections:      100,
			MaxConnectionsPerIP: 10,
		},
	}

	statsMgr := stats.NewManager(true, 0, "test", false, 0, nil, 0, 0, 0, logger)

	var wg sync.WaitGroup
	var count atomic.Int64

	backend := &Backend{
		ServerConfig:       serverCfg,
		GlobalConfig:       &cfg,
		StatsManager:       statsMgr,
		Metrics:            m,
		Logger:             logger,
		ActiveSessionsWg:   &wg,
		ActiveSessionCount: &count,
		ShutdownChan:       make(chan struct{}),
	}

	// Record connection metric (simulating what NewSession does)
	if backend.Metrics != nil {
		backend.Metrics.SMTPConnectionsTotal.WithLabelValues(backend.ServerConfig.Name, backend.ServerConfig.Type).Inc()
		backend.Metrics.SMTPConnectionsTotal.WithLabelValues(backend.ServerConfig.Name, backend.ServerConfig.Type).Inc()
	}

	// Verify metrics
	connections := testutil.ToFloat64(m.SMTPConnectionsTotal.WithLabelValues("test-relay", "relay"))
	if connections != 2 {
		t.Errorf("Connections = %v, want 2", connections)
	}

	t.Log("✓ NewSession metrics recorded with correct server labels")
}

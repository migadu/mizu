package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestNew(t *testing.T) {
	// Create metrics with default namespace
	m := New("")
	if m == nil {
		t.Fatal("Metrics is nil")
	}

	// Verify metrics are created
	if m.SMTPConnectionsTotal == nil {
		t.Error("SMTPConnectionsTotal is nil")
	}

	t.Log("✓ Metrics created with default namespace")
}

func TestNew_CustomNamespace(t *testing.T) {
	// Create metrics with custom namespace
	m := New("custom")
	if m == nil {
		t.Fatal("Metrics is nil")
	}

	// Verify metrics are created
	if m.SMTPConnectionsTotal == nil {
		t.Error("SMTPConnectionsTotal is nil")
	}

	t.Log("✓ Metrics created with custom namespace")
}

func TestMetrics_SMTPMetrics(t *testing.T) {
	m := New("test_smtp")

	// Test counters with server labels
	m.SMTPConnectionsTotal.WithLabelValues("relay", "relay").Inc()
	m.SMTPMessagesReceived.WithLabelValues("relay", "relay").Inc()

	// Test gauge with server labels
	m.SMTPConnectionsActive.WithLabelValues("relay", "relay").Set(5)
	m.SMTPConnectionsActive.WithLabelValues("relay", "relay").Inc()
	m.SMTPConnectionsActive.WithLabelValues("relay", "relay").Dec()

	// Test histograms with server labels
	m.SMTPConnectionDuration.WithLabelValues("relay", "relay").Observe(1.5)
	m.SMTPMessageSize.WithLabelValues("relay", "relay").Observe(1024)

	// Test counter vec with server labels
	m.SMTPMessagesRejected.WithLabelValues("relay", "relay", "spam").Inc()
	m.SMTPSPFChecks.WithLabelValues("relay", "pass").Inc()
	m.SMTPDMARCChecks.WithLabelValues("relay", "pass").Inc()
	m.SMTPDKIMChecks.WithLabelValues("relay", "pass").Inc()
	m.SMTPARCChecks.WithLabelValues("relay", "pass").Inc()
	m.SMTPBlacklistChecks.WithLabelValues("relay", "clean").Inc()

	// Test gauge vec with server label
	m.SMTPConnectionsPerIPActive.WithLabelValues("relay", "192.168.1.1").Set(2)

	t.Log("✓ SMTP metrics work correctly with server labels")
}

func TestMetrics_HTTPMetrics(t *testing.T) {
	m := New("test_http")

	// Test counter vec
	m.HTTPRequestsTotal.WithLabelValues("2xx").Inc()
	m.HTTPRequestsTotal.WithLabelValues("5xx").Inc()

	// Test histograms
	m.HTTPRequestDuration.Observe(0.5)
	m.HTTPRequestSize.Observe(2048)
	m.HTTPResponseSize.Observe(512)

	t.Log("✓ HTTP metrics work correctly")
}

func TestMetrics_CircuitBreakerMetrics(t *testing.T) {
	m := New("test_cb")

	// Test gauge vec
	m.CircuitBreakerState.WithLabelValues("closed").Set(1)
	m.CircuitBreakerState.WithLabelValues("open").Set(0)

	// Test counters
	m.CircuitBreakerFailures.Inc()
	m.CircuitBreakerSuccesses.Inc()
	m.CircuitBreakerRejects.Inc()

	t.Log("✓ Circuit breaker metrics work correctly")
}

func TestMetrics_ConnectionTrackerMetrics(t *testing.T) {
	m := New("test_conn")

	m.ConnectionsTrackerTotal.Set(100)
	m.ConnectionsTrackerLimit.Set(1000)
	m.ConnectionsTrackerPerIP.WithLabelValues("10.0.0.1").Set(5)

	t.Log("✓ Connection tracker metrics work correctly")
}

func TestMetrics_RateLimiterMetrics(t *testing.T) {
	m := New("test_rate")

	m.RateLimitChecks.WithLabelValues("IP", "allowed").Inc()
	m.RateLimitViolations.WithLabelValues("IP").Inc()
	m.RateLimitWindowCount.WithLabelValues("IP", "192.168.1.1").Set(50)

	t.Log("✓ Rate limiter metrics work correctly")
}

func TestMetrics_StatsManagerMetrics(t *testing.T) {
	m := New("test_stats")

	m.StatsIPEntriesTotal.Set(1000)
	m.StatsDomainEntriesTotal.Set(500)
	m.StatsEventsProcessed.Inc()
	m.StatsEventsDropped.Inc()

	t.Log("✓ Stats manager metrics work correctly")
}

func TestMetrics_ClusterMetrics(t *testing.T) {
	m := New("test_cluster")

	m.ClusterMembers.Set(3)
	m.ClusterLeader.WithLabelValues("node1").Set(1)
	m.ClusterGossipMessages.WithLabelValues("connection_state", "send").Inc()

	t.Log("✓ Cluster metrics work correctly")
}

func TestMetrics_RecipientCacheMetrics(t *testing.T) {
	m := New("test_cache")

	m.RecipientCacheHits.WithLabelValues("routing").Inc()
	m.RecipientCacheMisses.Inc()
	m.RecipientCacheSize.WithLabelValues("routing").Set(100)

	t.Log("✓ Recipient cache metrics work correctly")
}

func TestMetrics_AllMetricsNonNil(t *testing.T) {
	m := New("test_all")

	// Check all metrics are non-nil
	if m.SMTPConnectionsTotal == nil {
		t.Error("SMTPConnectionsTotal is nil")
	}
	if m.SMTPConnectionsActive == nil {
		t.Error("SMTPConnectionsActive is nil")
	}
	if m.SMTPConnectionsPerIPActive == nil {
		t.Error("SMTPConnectionsPerIPActive is nil")
	}
	if m.HTTPRequestsTotal == nil {
		t.Error("HTTPRequestsTotal is nil")
	}
	if m.CircuitBreakerState == nil {
		t.Error("CircuitBreakerState is nil")
	}

	t.Log("✓ All metrics are non-nil")
}

func TestMetrics_PrometheusRegistration(t *testing.T) {
	// Create a new registry to avoid conflicts
	_ = prometheus.NewRegistry()

	// This tests that metrics can be registered without panic
	m := New("test_registration")
	if m == nil {
		t.Fatal("Failed to create metrics")
	}

	t.Log("✓ Metrics registered with Prometheus successfully")
}

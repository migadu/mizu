package metrics

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestNew(t *testing.T) {
	// Create metrics with default namespace
	m := NewWithRegisterer("", prometheus.NewRegistry())
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
	m := NewWithRegisterer("custom", prometheus.NewRegistry())
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
	m := NewWithRegisterer("test_smtp", prometheus.NewRegistry())

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
	m := NewWithRegisterer("test_http", prometheus.NewRegistry())

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
	m := NewWithRegisterer("test_cb", prometheus.NewRegistry())

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
	m := NewWithRegisterer("test_conn", prometheus.NewRegistry())

	m.ConnectionsTrackerTotal.Set(100)
	m.ConnectionsTrackerLimit.Set(1000)
	m.ConnectionsTrackerPerIP.WithLabelValues("10.0.0.1").Set(5)

	t.Log("✓ Connection tracker metrics work correctly")
}

func TestMetrics_RateLimiterMetrics(t *testing.T) {
	m := NewWithRegisterer("test_rate", prometheus.NewRegistry())

	m.RateLimitChecks.WithLabelValues("IP", "allowed").Inc()
	m.RateLimitViolations.WithLabelValues("IP").Inc()
	m.RateLimitWindowCount.WithLabelValues("IP", "192.168.1.1").Set(50)

	t.Log("✓ Rate limiter metrics work correctly")
}

func TestMetrics_StatsManagerMetrics(t *testing.T) {
	m := NewWithRegisterer("test_stats", prometheus.NewRegistry())

	m.StatsIPEntriesTotal.Set(1000)
	m.StatsDomainEntriesTotal.Set(500)
	m.StatsEventsProcessed.Inc()
	m.StatsEventsDropped.Inc()

	t.Log("✓ Stats manager metrics work correctly")
}

func TestMetrics_ClusterMetrics(t *testing.T) {
	m := NewWithRegisterer("test_cluster", prometheus.NewRegistry())

	m.ClusterMembers.Set(3)
	m.ClusterLeader.WithLabelValues("node1").Set(1)
	m.ClusterGossipMessages.WithLabelValues("connection_state", "send").Inc()

	t.Log("✓ Cluster metrics work correctly")
}

func TestMetrics_RecipientCacheMetrics(t *testing.T) {
	m := NewWithRegisterer("test_cache", prometheus.NewRegistry())

	m.RecipientCacheHits.WithLabelValues("routing").Inc()
	m.RecipientCacheMisses.Inc()
	m.RecipientCacheSize.WithLabelValues("routing").Set(100)

	t.Log("✓ Recipient cache metrics work correctly")
}

func TestMetrics_AllMetricsNonNil(t *testing.T) {
	m := NewWithRegisterer("test_all", prometheus.NewRegistry())

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
	m := NewWithRegisterer("test_registration", prometheus.NewRegistry())
	if m == nil {
		t.Fatal("Failed to create metrics")
	}

	t.Log("✓ Metrics registered with Prometheus successfully")
}

// TestNewRegistersInTheDefaultRegistry is the counterweight to the registry
// split. Every other test here builds against a PRIVATE registry, so nothing
// would notice if New itself stopped using the default one — and /metrics is
// served from the default gatherer, so that mistake would silently empty every
// mizu_* series in production while the suite stayed green.
//
// The namespace is unique per run so this test does not reintroduce the
// duplicate-registration panic: the default registry outlives the test.
func TestNewRegistersInTheDefaultRegistry(t *testing.T) {
	namespace := fmt.Sprintf("test_default_reg_%d", defaultRegSeq.Add(1))

	if m := New(namespace); m == nil {
		t.Fatal("Failed to create metrics")
	}

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if strings.HasPrefix(f.GetName(), namespace+"_") {
			return
		}
	}
	t.Errorf("New(%q) registered nothing in the DEFAULT registry; /metrics would serve no mizu_* series", namespace)
}

// defaultRegSeq keeps the namespace above unique across -count=N runs.
var defaultRegSeq atomic.Int64

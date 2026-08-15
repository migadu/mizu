package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metrics for the SMTP relay
type Metrics struct {
	// SMTP connection metrics (per-server)
	SMTPConnectionsTotal       *prometheus.CounterVec   // Labels: server_name, server_type
	SMTPConnectionsActive      *prometheus.GaugeVec     // Labels: server_name, server_type
	SMTPConnectionsPerIPActive *prometheus.GaugeVec     // Labels: server_name, ip
	SMTPConnectionDuration     *prometheus.HistogramVec // Labels: server_name, server_type
	SMTPMessagesReceived       *prometheus.CounterVec   // Labels: server_name, server_type
	SMTPMessagesRejected       *prometheus.CounterVec   // Labels: server_name, server_type, reason
	SMTPMessageSize            *prometheus.HistogramVec // Labels: server_name, server_type

	// SMTP validation metrics (per-server)
	SMTPSPFChecks       *prometheus.CounterVec // Labels: server_name, result
	SMTPDMARCChecks     *prometheus.CounterVec // Labels: server_name, result
	SMTPDKIMChecks      *prometheus.CounterVec // Labels: server_name, result
	SMTPARCChecks       *prometheus.CounterVec // Labels: server_name, result
	SMTPBlacklistChecks *prometheus.CounterVec // Labels: server_name, result

	// HTTP destination metrics
	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration prometheus.Histogram
	HTTPRequestSize     prometheus.Histogram
	HTTPResponseSize    prometheus.Histogram

	// Circuit breaker metrics
	CircuitBreakerState     *prometheus.GaugeVec
	CircuitBreakerFailures  prometheus.Counter
	CircuitBreakerSuccesses prometheus.Counter
	CircuitBreakerRejects   prometheus.Counter

	// Connection tracker metrics
	ConnectionsTrackerTotal prometheus.Gauge
	ConnectionsTrackerPerIP *prometheus.GaugeVec
	ConnectionsTrackerLimit prometheus.Gauge

	// Rate limiter metrics
	RateLimitChecks      *prometheus.CounterVec
	RateLimitViolations  *prometheus.CounterVec
	RateLimitWindowCount *prometheus.GaugeVec

	// Stats manager metrics
	StatsIPEntriesTotal     prometheus.Gauge
	StatsDomainEntriesTotal prometheus.Gauge
	StatsEventsProcessed    prometheus.Counter
	StatsEventsDropped      prometheus.Counter

	// Cluster metrics
	ClusterMembers        prometheus.Gauge
	ClusterLeader         *prometheus.GaugeVec
	ClusterGossipMessages *prometheus.CounterVec

	// Recipient cache metrics
	RecipientCacheHits   *prometheus.CounterVec
	RecipientCacheMisses prometheus.Counter
	RecipientCacheSize   *prometheus.GaugeVec

	// Auth rate limiter metrics
	AuthRateLimitIPBlocks         *prometheus.CounterVec   // Labels: ip
	AuthRateLimitIPUsernameBlocks *prometheus.CounterVec   // Labels: ip, username
	AuthRateLimitDelays           *prometheus.HistogramVec // Labels: type (ip, ip_username)
	AuthRateLimitEvictions        *prometheus.CounterVec   // Labels: type (ip, ip_username, username, blocked_ips)
	AuthRateLimitCacheSize        *prometheus.GaugeVec     // Labels: type

	// Spam check metrics
	SpamCheckUp prometheus.Gauge // 1 = rspamd reachable, 0 = unreachable

	// DNS cache metrics
	DNSCacheHits      *prometheus.CounterVec // Labels: record_type
	DNSCacheMisses    *prometheus.CounterVec // Labels: record_type
	DNSCacheSize      *prometheus.GaugeVec   // Labels: record_type
	DNSQueryDuration  *prometheus.HistogramVec
	DNSResolverErrors *prometheus.CounterVec // Labels: resolver, error_type
}

// New creates and registers all Prometheus metrics in the DEFAULT registry.
// This is what the server uses, so /metrics keeps working unchanged.
func New(namespace string) *Metrics {
	return NewWithRegisterer(namespace, prometheus.DefaultRegisterer)
}

// NewWithRegisterer is New against a caller-supplied registry.
//
// It exists because registering into a process-global registry makes a Metrics
// UNCONSTRUCTABLE TWICE for one namespace: promauto panics on a duplicate
// collector. That is invisible in production (one instance per process) and
// fatal in tests — "go test -count=2" re-runs every test in the SAME process,
// so any test building a Metrics with a fixed namespace panics on the second
// pass and the package cannot be run repeatedly to check for flakes.
//
// Tests should pass prometheus.NewRegistry(): a private registry is discarded
// with the test, which is both repeatable and free of cross-test interference.
// testutil.ToFloat64 reads a Collector directly, not a registry, so assertions
// are unaffected.
func NewWithRegisterer(namespace string, reg prometheus.Registerer) *Metrics {
	if namespace == "" {
		namespace = "mizu"
	}
	factory := promauto.With(reg)

	return &Metrics{
		// SMTP connection metrics (per-server)
		SMTPConnectionsTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "connections_total",
			Help:      "Total number of SMTP connections accepted per server",
		}, []string{"server_name", "server_type"}),
		SMTPConnectionsActive: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "connections_active",
			Help:      "Current number of active SMTP connections per server",
		}, []string{"server_name", "server_type"}),
		SMTPConnectionsPerIPActive: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "connections_per_ip_active",
			Help:      "Current number of active connections per IP address and server",
		}, []string{"server_name", "ip"}),
		SMTPConnectionDuration: factory.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "connection_duration_seconds",
			Help:      "Duration of SMTP connections in seconds per server",
			Buckets:   prometheus.DefBuckets,
		}, []string{"server_name", "server_type"}),
		SMTPMessagesReceived: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "messages_received_total",
			Help:      "Total number of messages received via SMTP per server",
		}, []string{"server_name", "server_type"}),
		SMTPMessagesRejected: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "messages_rejected_total",
			Help:      "Total number of messages rejected per server",
		}, []string{"server_name", "server_type", "reason"}),
		SMTPMessageSize: factory.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "message_size_bytes",
			Help:      "Size of received messages in bytes per server",
			Buckets:   prometheus.ExponentialBuckets(1024, 2, 15), // 1KB to 16MB
		}, []string{"server_name", "server_type"}),

		// SMTP validation metrics (per-server)
		SMTPSPFChecks: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "spf_checks_total",
			Help:      "Total number of SPF checks performed per server",
		}, []string{"server_name", "result"}),
		SMTPDMARCChecks: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "dmarc_checks_total",
			Help:      "Total number of DMARC checks performed per server",
		}, []string{"server_name", "result"}),
		SMTPDKIMChecks: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "dkim_checks_total",
			Help:      "Total number of DKIM checks performed per server",
		}, []string{"server_name", "result"}),
		SMTPARCChecks: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "arc_checks_total",
			Help:      "Total number of ARC (Authenticated Received Chain) checks performed per server",
		}, []string{"server_name", "result"}),
		SMTPBlacklistChecks: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "blacklist_checks_total",
			Help:      "Total number of blacklist checks performed per server",
		}, []string{"server_name", "result"}),

		// HTTP destination metrics
		HTTPRequestsTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total number of HTTP requests to destination",
		}, []string{"status_code"}),
		HTTPRequestDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "Duration of HTTP requests to destination in seconds",
			Buckets:   prometheus.DefBuckets,
		}),
		HTTPRequestSize: factory.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "http",
			Name:      "request_size_bytes",
			Help:      "Size of HTTP request bodies in bytes",
			Buckets:   prometheus.ExponentialBuckets(1024, 2, 15), // 1KB to 16MB
		}),
		HTTPResponseSize: factory.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "http",
			Name:      "response_size_bytes",
			Help:      "Size of HTTP response bodies in bytes",
			Buckets:   prometheus.ExponentialBuckets(128, 2, 10), // 128B to 64KB
		}),

		// Circuit breaker metrics
		CircuitBreakerState: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "circuit_breaker",
			Name:      "state",
			Help:      "Current state of circuit breaker (0=closed, 1=open, 2=half_open)",
		}, []string{"state"}),
		CircuitBreakerFailures: factory.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "circuit_breaker",
			Name:      "failures_total",
			Help:      "Total number of circuit breaker failures",
		}),
		CircuitBreakerSuccesses: factory.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "circuit_breaker",
			Name:      "successes_total",
			Help:      "Total number of circuit breaker successes",
		}),
		CircuitBreakerRejects: factory.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "circuit_breaker",
			Name:      "rejects_total",
			Help:      "Total number of requests rejected due to open circuit",
		}),

		// Connection tracker metrics
		ConnectionsTrackerTotal: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "connections",
			Name:      "tracker_total",
			Help:      "Total number of tracked connections",
		}),
		ConnectionsTrackerPerIP: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "connections",
			Name:      "tracker_per_ip",
			Help:      "Number of connections tracked per IP",
		}, []string{"ip"}),
		ConnectionsTrackerLimit: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "connections",
			Name:      "tracker_limit",
			Help:      "Maximum allowed connections",
		}),

		// Rate limiter metrics
		RateLimitChecks: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "rate_limit",
			Name:      "checks_total",
			Help:      "Total number of rate limit checks",
		}, []string{"dimension", "result"}),
		RateLimitViolations: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "rate_limit",
			Name:      "violations_total",
			Help:      "Total number of rate limit violations",
		}, []string{"dimension"}),
		RateLimitWindowCount: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "rate_limit",
			Name:      "window_count",
			Help:      "Current count in rate limit window",
		}, []string{"dimension", "key"}),

		// Stats manager metrics
		StatsIPEntriesTotal: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "stats",
			Name:      "ip_entries_total",
			Help:      "Total number of IP entries in stats manager",
		}),
		StatsDomainEntriesTotal: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "stats",
			Name:      "domain_entries_total",
			Help:      "Total number of domain entries in stats manager",
		}),
		StatsEventsProcessed: factory.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "stats",
			Name:      "events_processed_total",
			Help:      "Total number of stats events processed",
		}),
		StatsEventsDropped: factory.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "stats",
			Name:      "events_dropped_total",
			Help:      "Total number of stats events dropped due to full channel",
		}),

		// Cluster metrics
		ClusterMembers: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "cluster",
			Name:      "members_total",
			Help:      "Total number of cluster members",
		}),
		ClusterLeader: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "cluster",
			Name:      "leader",
			Help:      "Whether this node is the cluster leader (1=leader, 0=not leader)",
		}, []string{"node"}),
		ClusterGossipMessages: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "cluster",
			Name:      "gossip_messages_total",
			Help:      "Total number of gossip messages sent/received",
		}, []string{"type", "direction"}),

		// Recipient cache metrics
		RecipientCacheHits: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "recipient_cache",
			Name:      "hits_total",
			Help:      "Total number of recipient cache hits",
		}, []string{"type"}),
		RecipientCacheMisses: factory.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "recipient_cache",
			Name:      "misses_total",
			Help:      "Total number of recipient cache misses",
		}),
		RecipientCacheSize: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "recipient_cache",
			Name:      "size",
			Help:      "Current size of recipient cache",
		}, []string{"type"}),

		// Auth rate limiter metrics
		AuthRateLimitIPBlocks: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "auth_rate_limit",
			Name:      "ip_blocks_total",
			Help:      "Total number of IPs blocked due to authentication failures",
		}, []string{"ip"}),
		AuthRateLimitIPUsernameBlocks: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "auth_rate_limit",
			Name:      "ip_username_blocks_total",
			Help:      "Total number of IP+username combinations blocked",
		}, []string{"ip", "username"}),
		AuthRateLimitDelays: factory.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "auth_rate_limit",
			Name:      "delay_seconds",
			Help:      "Authentication delay durations in seconds",
			Buckets:   prometheus.ExponentialBuckets(0.1, 2, 10), // 0.1s to 51.2s
		}, []string{"type"}),
		AuthRateLimitEvictions: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "auth_rate_limit",
			Name:      "evictions_total",
			Help:      "Total number of LRU evictions by cache type",
		}, []string{"type"}),
		AuthRateLimitCacheSize: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "auth_rate_limit",
			Name:      "cache_size",
			Help:      "Current size of auth rate limit caches",
		}, []string{"type"}),

		// Spam check metrics
		SpamCheckUp: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "spam_check",
			Name:      "up",
			Help:      "Whether the spam check server (rspamd) is reachable (1 = up, 0 = down)",
		}),

		// DNS cache metrics
		DNSCacheHits: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "dns_cache",
			Name:      "hits_total",
			Help:      "Total number of DNS cache hits",
		}, []string{"record_type"}),
		DNSCacheMisses: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "dns_cache",
			Name:      "misses_total",
			Help:      "Total number of DNS cache misses",
		}, []string{"record_type"}),
		DNSCacheSize: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "dns_cache",
			Name:      "size",
			Help:      "Current size of DNS cache by record type",
		}, []string{"record_type"}),
		DNSQueryDuration: factory.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "dns",
			Name:      "query_duration_seconds",
			Help:      "DNS query duration in seconds",
			Buckets:   prometheus.DefBuckets,
		}, []string{"record_type"}),
		DNSResolverErrors: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "dns",
			Name:      "resolver_errors_total",
			Help:      "Total number of DNS resolver errors",
		}, []string{"resolver", "error_type"}),
	}
}

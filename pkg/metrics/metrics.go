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

// New creates and registers all Prometheus metrics
func New(namespace string) *Metrics {
	if namespace == "" {
		namespace = "mizu"
	}

	return &Metrics{
		// SMTP connection metrics (per-server)
		SMTPConnectionsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "connections_total",
			Help:      "Total number of SMTP connections accepted per server",
		}, []string{"server_name", "server_type"}),
		SMTPConnectionsActive: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "connections_active",
			Help:      "Current number of active SMTP connections per server",
		}, []string{"server_name", "server_type"}),
		SMTPConnectionsPerIPActive: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "connections_per_ip_active",
			Help:      "Current number of active connections per IP address and server",
		}, []string{"server_name", "ip"}),
		SMTPConnectionDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "connection_duration_seconds",
			Help:      "Duration of SMTP connections in seconds per server",
			Buckets:   prometheus.DefBuckets,
		}, []string{"server_name", "server_type"}),
		SMTPMessagesReceived: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "messages_received_total",
			Help:      "Total number of messages received via SMTP per server",
		}, []string{"server_name", "server_type"}),
		SMTPMessagesRejected: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "messages_rejected_total",
			Help:      "Total number of messages rejected per server",
		}, []string{"server_name", "server_type", "reason"}),
		SMTPMessageSize: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "message_size_bytes",
			Help:      "Size of received messages in bytes per server",
			Buckets:   prometheus.ExponentialBuckets(1024, 2, 15), // 1KB to 16MB
		}, []string{"server_name", "server_type"}),

		// SMTP validation metrics (per-server)
		SMTPSPFChecks: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "spf_checks_total",
			Help:      "Total number of SPF checks performed per server",
		}, []string{"server_name", "result"}),
		SMTPDMARCChecks: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "dmarc_checks_total",
			Help:      "Total number of DMARC checks performed per server",
		}, []string{"server_name", "result"}),
		SMTPDKIMChecks: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "dkim_checks_total",
			Help:      "Total number of DKIM checks performed per server",
		}, []string{"server_name", "result"}),
		SMTPARCChecks: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "arc_checks_total",
			Help:      "Total number of ARC (Authenticated Received Chain) checks performed per server",
		}, []string{"server_name", "result"}),
		SMTPBlacklistChecks: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "blacklist_checks_total",
			Help:      "Total number of blacklist checks performed per server",
		}, []string{"server_name", "result"}),

		// HTTP destination metrics
		HTTPRequestsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total number of HTTP requests to destination",
		}, []string{"status_code"}),
		HTTPRequestDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "Duration of HTTP requests to destination in seconds",
			Buckets:   prometheus.DefBuckets,
		}),
		HTTPRequestSize: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "http",
			Name:      "request_size_bytes",
			Help:      "Size of HTTP request bodies in bytes",
			Buckets:   prometheus.ExponentialBuckets(1024, 2, 15), // 1KB to 16MB
		}),
		HTTPResponseSize: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "http",
			Name:      "response_size_bytes",
			Help:      "Size of HTTP response bodies in bytes",
			Buckets:   prometheus.ExponentialBuckets(128, 2, 10), // 128B to 64KB
		}),

		// Circuit breaker metrics
		CircuitBreakerState: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "circuit_breaker",
			Name:      "state",
			Help:      "Current state of circuit breaker (0=closed, 1=open, 2=half_open)",
		}, []string{"state"}),
		CircuitBreakerFailures: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "circuit_breaker",
			Name:      "failures_total",
			Help:      "Total number of circuit breaker failures",
		}),
		CircuitBreakerSuccesses: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "circuit_breaker",
			Name:      "successes_total",
			Help:      "Total number of circuit breaker successes",
		}),
		CircuitBreakerRejects: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "circuit_breaker",
			Name:      "rejects_total",
			Help:      "Total number of requests rejected due to open circuit",
		}),

		// Connection tracker metrics
		ConnectionsTrackerTotal: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "connections",
			Name:      "tracker_total",
			Help:      "Total number of tracked connections",
		}),
		ConnectionsTrackerPerIP: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "connections",
			Name:      "tracker_per_ip",
			Help:      "Number of connections tracked per IP",
		}, []string{"ip"}),
		ConnectionsTrackerLimit: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "connections",
			Name:      "tracker_limit",
			Help:      "Maximum allowed connections",
		}),

		// Rate limiter metrics
		RateLimitChecks: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "rate_limit",
			Name:      "checks_total",
			Help:      "Total number of rate limit checks",
		}, []string{"dimension", "result"}),
		RateLimitViolations: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "rate_limit",
			Name:      "violations_total",
			Help:      "Total number of rate limit violations",
		}, []string{"dimension"}),
		RateLimitWindowCount: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "rate_limit",
			Name:      "window_count",
			Help:      "Current count in rate limit window",
		}, []string{"dimension", "key"}),

		// Stats manager metrics
		StatsIPEntriesTotal: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "stats",
			Name:      "ip_entries_total",
			Help:      "Total number of IP entries in stats manager",
		}),
		StatsDomainEntriesTotal: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "stats",
			Name:      "domain_entries_total",
			Help:      "Total number of domain entries in stats manager",
		}),
		StatsEventsProcessed: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "stats",
			Name:      "events_processed_total",
			Help:      "Total number of stats events processed",
		}),
		StatsEventsDropped: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "stats",
			Name:      "events_dropped_total",
			Help:      "Total number of stats events dropped due to full channel",
		}),

		// Cluster metrics
		ClusterMembers: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "cluster",
			Name:      "members_total",
			Help:      "Total number of cluster members",
		}),
		ClusterLeader: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "cluster",
			Name:      "leader",
			Help:      "Whether this node is the cluster leader (1=leader, 0=not leader)",
		}, []string{"node"}),
		ClusterGossipMessages: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "cluster",
			Name:      "gossip_messages_total",
			Help:      "Total number of gossip messages sent/received",
		}, []string{"type", "direction"}),

		// Recipient cache metrics
		RecipientCacheHits: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "recipient_cache",
			Name:      "hits_total",
			Help:      "Total number of recipient cache hits",
		}, []string{"type"}),
		RecipientCacheMisses: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "recipient_cache",
			Name:      "misses_total",
			Help:      "Total number of recipient cache misses",
		}),
		RecipientCacheSize: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "recipient_cache",
			Name:      "size",
			Help:      "Current size of recipient cache",
		}, []string{"type"}),

		// Auth rate limiter metrics
		AuthRateLimitIPBlocks: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "auth_rate_limit",
			Name:      "ip_blocks_total",
			Help:      "Total number of IPs blocked due to authentication failures",
		}, []string{"ip"}),
		AuthRateLimitIPUsernameBlocks: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "auth_rate_limit",
			Name:      "ip_username_blocks_total",
			Help:      "Total number of IP+username combinations blocked",
		}, []string{"ip", "username"}),
		AuthRateLimitDelays: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "auth_rate_limit",
			Name:      "delay_seconds",
			Help:      "Authentication delay durations in seconds",
			Buckets:   prometheus.ExponentialBuckets(0.1, 2, 10), // 0.1s to 51.2s
		}, []string{"type"}),
		AuthRateLimitEvictions: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "auth_rate_limit",
			Name:      "evictions_total",
			Help:      "Total number of LRU evictions by cache type",
		}, []string{"type"}),
		AuthRateLimitCacheSize: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "auth_rate_limit",
			Name:      "cache_size",
			Help:      "Current size of auth rate limit caches",
		}, []string{"type"}),

		// Spam check metrics
		SpamCheckUp: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "spam_check",
			Name:      "up",
			Help:      "Whether the spam check server (rspamd) is reachable (1 = up, 0 = down)",
		}),

		// DNS cache metrics
		DNSCacheHits: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "dns_cache",
			Name:      "hits_total",
			Help:      "Total number of DNS cache hits",
		}, []string{"record_type"}),
		DNSCacheMisses: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "dns_cache",
			Name:      "misses_total",
			Help:      "Total number of DNS cache misses",
		}, []string{"record_type"}),
		DNSCacheSize: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "dns_cache",
			Name:      "size",
			Help:      "Current size of DNS cache by record type",
		}, []string{"record_type"}),
		DNSQueryDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "dns",
			Name:      "query_duration_seconds",
			Help:      "DNS query duration in seconds",
			Buckets:   prometheus.DefBuckets,
		}, []string{"record_type"}),
		DNSResolverErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "dns",
			Name:      "resolver_errors_total",
			Help:      "Total number of DNS resolver errors",
		}, []string{"resolver", "error_type"}),
	}
}

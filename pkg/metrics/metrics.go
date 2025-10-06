package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metrics for the SMTP relay
type Metrics struct {
	// SMTP connection metrics
	SMTPConnectionsTotal       prometheus.Counter
	SMTPConnectionsActive      prometheus.Gauge
	SMTPConnectionsPerIPActive *prometheus.GaugeVec
	SMTPConnectionDuration     prometheus.Histogram
	SMTPMessagesReceived       prometheus.Counter
	SMTPMessagesRejected       *prometheus.CounterVec
	SMTPMessageSize            prometheus.Histogram

	// SMTP validation metrics
	SMTPSPFChecks       *prometheus.CounterVec
	SMTPDMARCChecks     *prometheus.CounterVec
	SMTPDKIMChecks      *prometheus.CounterVec
	SMTPBlacklistChecks *prometheus.CounterVec

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
}

// New creates and registers all Prometheus metrics
func New(namespace string) *Metrics {
	if namespace == "" {
		namespace = "mizu"
	}

	return &Metrics{
		// SMTP connection metrics
		SMTPConnectionsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "connections_total",
			Help:      "Total number of SMTP connections accepted",
		}),
		SMTPConnectionsActive: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "connections_active",
			Help:      "Current number of active SMTP connections",
		}),
		SMTPConnectionsPerIPActive: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "connections_per_ip_active",
			Help:      "Current number of active connections per IP address",
		}, []string{"ip"}),
		SMTPConnectionDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "connection_duration_seconds",
			Help:      "Duration of SMTP connections in seconds",
			Buckets:   prometheus.DefBuckets,
		}),
		SMTPMessagesReceived: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "messages_received_total",
			Help:      "Total number of messages received via SMTP",
		}),
		SMTPMessagesRejected: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "messages_rejected_total",
			Help:      "Total number of messages rejected",
		}, []string{"reason"}),
		SMTPMessageSize: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "message_size_bytes",
			Help:      "Size of received messages in bytes",
			Buckets:   prometheus.ExponentialBuckets(1024, 2, 15), // 1KB to 16MB
		}),

		// SMTP validation metrics
		SMTPSPFChecks: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "spf_checks_total",
			Help:      "Total number of SPF checks performed",
		}, []string{"result"}),
		SMTPDMARCChecks: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "dmarc_checks_total",
			Help:      "Total number of DMARC checks performed",
		}, []string{"result"}),
		SMTPDKIMChecks: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "dkim_checks_total",
			Help:      "Total number of DKIM checks performed",
		}, []string{"result"}),
		SMTPBlacklistChecks: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "smtp",
			Name:      "blacklist_checks_total",
			Help:      "Total number of blacklist checks performed",
		}, []string{"result"}),

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
	}
}

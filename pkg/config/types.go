package config

import "time"

// Config holds all configuration for the SMTP relay server
type Config struct {
	SMTP        SMTPConfig        `toml:"smtp"`
	DNS         DNSConfig         `toml:"dns"`
	S3          S3Config          `toml:"s3"`
	Destination DestinationConfig `toml:"destination"`
	TLS         TLSConfig         `toml:"tls"`
	Blacklists  BlacklistsConfig  `toml:"blacklists"`
	Health      HealthConfig      `toml:"health"`
	Stats       StatsConfig       `toml:"stats"`
	Cluster     ClusterConfig     `toml:"cluster"`    // Global cluster/peering configuration
	LogFormat   string            `toml:"log_format"` // "json" or "text"
	Local       bool              `toml:"local"`      // Local development mode
}

// SMTPConfig holds SMTP server configuration
type SMTPConfig struct {
	ListenAddr            string                  `toml:"listen_addr"`
	Domain                string                  `toml:"domain"`
	MaxMessageSize        int                     `toml:"max_message_size"`
	TimeoutDuration       time.Duration           `toml:"timeout_duration"`
	MinTLSVersion         string                  `toml:"min_tls_version"`          // Minimum TLS version: "1.2" or "1.3" (TLS 1.0/1.1 not supported)
	CheckXSpamFlag        bool                    `toml:"check_x_spam_flag"`        // Enable check for X-Spam-Flag header
	DMARCQuarantineAsJunk bool                    `toml:"dmarc_quarantine_as_junk"` // Treat DMARC quarantine policy as junk
	RequireSenderMX       bool                    `toml:"require_sender_mx"`        // Require sender domain to have MX records (default: true)
	ShutdownTimeout       time.Duration           `toml:"shutdown_timeout"`         // Maximum time to wait for graceful shutdown (default: 60s)
	MaxConnections        int                     `toml:"max_connections"`          // Maximum total concurrent connections (0 = unlimited, default: 100)
	MaxConnectionsPerIP   int                     `toml:"max_connections_per_ip"`   // Maximum concurrent connections per IP (0 = unlimited, default: 10)
	RateLimit             RateLimitConfig         `toml:"rate_limit"`               // Rate limiting configuration
	Distributed           DistributedLimitsConfig `toml:"distributed"`              // Distributed connection tracking
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled        bool                 `toml:"enabled"`         // Enable rate limiting (default: true)
	GossipEnabled  bool                 `toml:"gossip_enabled"`  // Share rate limit state across cluster via gossip (default: false)
	GossipInterval time.Duration        `toml:"gossip_interval"` // How often to gossip rate limit data (default: 5s)
	Dimensions     []RateLimitDimension `toml:"dimensions"`      // Rate limit dimensions (e.g., IP, FROM, FROM_DOMAIN, etc.)
}

// RateLimitDimension defines a single rate limit dimension with configurable key combination
type RateLimitDimension struct {
	Name   string        `toml:"name"`   // Human-readable name for this dimension
	Keys   []string      `toml:"keys"`   // Dimension keys to combine (IP, FROM, FROM_DOMAIN, TO, TO_DOMAIN)
	Limit  int           `toml:"limit"`  // Max connections/emails per window (0 = unlimited)
	Window time.Duration `toml:"window"` // Time window for rate limiting (default: 1m)
}

// DNSConfig holds DNS resolver configuration (global for all DNS operations)
type DNSConfig struct {
	Servers []string      `toml:"servers"` // Custom DNS servers (e.g., ["1.1.1.1:53", "1.0.0.1:53"]), empty = use system default
	Timeout time.Duration `toml:"timeout"` // DNS query timeout (default: 5s)
}

// ClusterConfig holds global cluster/peering configuration
type ClusterConfig struct {
	Enabled  bool     `toml:"enabled"`   // Enable cluster mode
	Hostname string   `toml:"hostname"`  // This server's hostname (auto-detected if empty)
	PeerPort string   `toml:"peer_port"` // Port for peer-to-peer communication (default: same as health.listen_addr)
	Peers    []string `toml:"peers"`     // List of peer hostnames (e.g., ["smtp2.example.com", "smtp3.example.com"])
}

// DistributedLimitsConfig holds configuration for distributed connection tracking
// Note: Peer configuration is now in ClusterConfig (cluster.peers + cluster.peer_port)
type DistributedLimitsConfig struct {
	Enabled           bool          `toml:"enabled"`             // Enable distributed tracking (requires cluster.enabled=true)
	GlobalMaxPerIP    int           `toml:"global_max_per_ip"`   // Global max connections per IP across cluster (0 = use local limit only)
	GossipInterval    time.Duration `toml:"gossip_interval"`     // How often to broadcast (default: 5s)
	S3SyncInterval    time.Duration `toml:"s3_sync_interval"`    // How often to sync with S3 (default: 30s)
	RecipientCacheTTL time.Duration `toml:"recipient_cache_ttl"` // How long to cache recipient validation results (default: 15m)
}

// S3Config holds S3 configuration for certificate storage
type S3Config struct {
	Endpoint        string `toml:"endpoint"`
	Bucket          string `toml:"bucket"`
	Prefix          string `toml:"prefix"`
	AccessKeyID     string `toml:"access_key_id"`
	SecretAccessKey string `toml:"secret_access_key"`
	Region          string `toml:"region"`
}

// DestinationConfig holds configuration for the HTTP destination endpoint
type DestinationConfig struct {
	URL              string               `toml:"url"`
	APIKey           string               `toml:"api_key"`
	MaxRetryAttempts int                  `toml:"max_retry_attempts"`
	HTTPTimeout      time.Duration        `toml:"http_timeout"` // HTTP client timeout (default: 30s)
	CircuitBreaker   CircuitBreakerConfig `toml:"circuit_breaker"`
}

// CircuitBreakerConfig holds configuration for the circuit breaker
type CircuitBreakerConfig struct {
	Enabled          bool          `toml:"enabled"`
	FailureThreshold int           `toml:"failure_threshold"`   // failures before opening (default: 5)
	SuccessThreshold int           `toml:"success_threshold"`   // successes in half-open to close (default: 2)
	Timeout          time.Duration `toml:"timeout"`             // time to wait before half-open (default: 30s)
	HalfOpenMaxCalls int           `toml:"half_open_max_calls"` // max concurrent calls in half-open (default: 1)
	ResetTimeout     time.Duration `toml:"reset_timeout"`       // time before resetting counters (default: 60s)
}

// HealthConfig holds configuration for the health check endpoint.
type HealthConfig struct {
	Enabled    bool   `toml:"enabled"`
	ListenAddr string `toml:"listen_addr"`
	Username   string `toml:"username"` // HTTP Basic Auth username (empty = no auth)
	Password   string `toml:"password"` // HTTP Basic Auth password
}

// BlacklistsConfig holds configuration for DNS blacklists
type BlacklistsConfig struct {
	Enabled           bool          `toml:"enabled"`             // Whether to enable blacklist checking
	Lists             []string      `toml:"lists"`               // DNS blacklist servers to check
	Timeout           time.Duration `toml:"timeout"`             // Timeout for blacklist queries
	CheckHELOResolves bool          `toml:"check_helo_resolves"` // Whether to check if HELO hostname resolves
}

// TLSConfig holds TLS/certificate configuration
type TLSConfig struct {
	Email            string `toml:"email"`             // Email for Let's Encrypt
	UseProduction    bool   `toml:"use_production"`    // Use Let's Encrypt production (vs staging)
	UseLocalCA       bool   `toml:"use_local_ca"`      // Use local CA for testing
	CertMagicVerbose bool   `toml:"certmagic_verbose"` // Enable verbose certmagic logging
}

// StatsConfig holds configuration for IP and domain reputation tracking
// Note: Peer and hostname configuration is now in ClusterConfig (cluster.peers + cluster.hostname)
type StatsConfig struct {
	Enabled           bool          `toml:"enabled"`            // Enable stats tracking
	RetentionDuration time.Duration `toml:"retention_duration"` // How long to keep stats
	SyncEnabled       bool          `toml:"sync_enabled"`       // Enable distributed stats sync (uses cluster.peers)
	SyncInterval      time.Duration `toml:"sync_interval"`      // How often to sync/export stats
	MaxIPEntries      int           `toml:"max_ip_entries"`     // Maximum number of IP entries to track (0 = unlimited, default: 100000)
	MaxDomainEntries  int           `toml:"max_domain_entries"` // Maximum number of domain entries to track (0 = unlimited, default: 50000)
}

// DefaultConfig returns a Config with default values
func DefaultConfig() *Config {
	return &Config{
		SMTP: SMTPConfig{
			ListenAddr:            ":25",
			Domain:                "mail.yourdomain.com",
			MaxMessageSize:        10 << 20, // 10 MB
			TimeoutDuration:       10 * time.Second,
			MinTLSVersion:         "1.2",            // Default to TLS 1.2
			CheckXSpamFlag:        true,             // Default to enabled
			DMARCQuarantineAsJunk: true,             // Default to treating quarantine as junk
			RequireSenderMX:       true,             // Default to requiring MX records
			ShutdownTimeout:       60 * time.Second, // Default 60s graceful shutdown
			MaxConnections:        100,              // Default max 100 concurrent connections
			MaxConnectionsPerIP:   10,               // Default max 10 connections per IP
			RateLimit: RateLimitConfig{
				Enabled:        true,            // Enabled by default
				GossipEnabled:  false,           // Disabled by default (requires cluster mode)
				GossipInterval: 5 * time.Second, // Gossip every 5 seconds
				Dimensions: []RateLimitDimension{
					{
						Name:   "per_ip",
						Keys:   []string{"IP"},
						Limit:  60,
						Window: 1 * time.Minute,
					},
				},
			},
			Distributed: DistributedLimitsConfig{
				Enabled:           false,            // Disabled by default
				GlobalMaxPerIP:    0,                // 0 = use local limit only
				GossipInterval:    5 * time.Second,  // Broadcast every 5 seconds
				S3SyncInterval:    30 * time.Second, // Sync with S3 every 30 seconds
				RecipientCacheTTL: 15 * time.Minute, // Cache recipient results for 15 minutes
			},
		},
		DNS: DNSConfig{
			Servers: []string{},      // Empty = use system DNS
			Timeout: 5 * time.Second, // Default 5s DNS timeout
		},
		S3: S3Config{
			Endpoint: "s3.amazonaws.com",
			Bucket:   "email-mx-certs",
			Prefix:   "certs/",
			Region:   "us-east-1",
		},
		Destination: DestinationConfig{
			MaxRetryAttempts: 3,                // Default to 3 retry attempts
			HTTPTimeout:      30 * time.Second, // Default 30s HTTP client timeout
			CircuitBreaker: CircuitBreakerConfig{
				Enabled:          true,             // Enabled by default
				FailureThreshold: 5,                // Open after 5 consecutive failures
				SuccessThreshold: 2,                // Close after 2 successes in half-open
				Timeout:          30 * time.Second, // Wait 30s before trying half-open
				HalfOpenMaxCalls: 1,                // Only 1 request in half-open state
				ResetTimeout:     60 * time.Second, // Reset counters after 60s of no failures
			},
		},
		TLS: TLSConfig{
			UseProduction:    true,
			CertMagicVerbose: false,
		},
		Health: HealthConfig{
			Enabled:    true,
			ListenAddr: ":8080",
		},
		Blacklists: BlacklistsConfig{
			Enabled:           true,
			Lists:             []string{"zen.spamhaus.org"},
			Timeout:           3 * time.Second,
			CheckHELOResolves: false,
		},
		Stats: StatsConfig{
			Enabled:           true,
			RetentionDuration: 24 * time.Hour,
			SyncEnabled:       false,
			SyncInterval:      1 * time.Minute,
			MaxIPEntries:      100000, // 100k IP entries
			MaxDomainEntries:  50000,  // 50k domain entries
		},
		Cluster: ClusterConfig{
			Enabled:  false,
			Hostname: "",         // Auto-detected if empty
			PeerPort: ":8080",    // Default to health check port
			Peers:    []string{}, // No peers by default
		},
		LogFormat: "text",
		Local:     false,
	}
}

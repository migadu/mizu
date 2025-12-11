// Package config handles configuration loading and validation for Mizu.
//
// # Overview
//
// The config package provides TOML-based configuration with environment variable
// support for sensitive values. It defines all configuration structures and
// provides validation and default values.
//
// # Configuration File Format
//
// Configuration uses TOML format with nested sections:
//
//	[defaults]
//	domain = "mail.example.com"
//	max_message_size = 10485760  # 10MB
//
//	[[server]]
//	name = "mx-primary"
//	type = "relay"
//	listen_addr = ":25"
//
//	[server.dkim]
//	enabled = true  # Validate DKIM signatures
//
//	[server.arc]
//	enabled = true
//	mode = "check"  # or "sign" for forwarding
//
//	[server.delivery]
//	url = "https://backend.example.com/email"
//	auth_token = "${DELIVERY_AUTH_TOKEN}"  # From environment
//	max_retry_attempts = 3
//
//	[server.delivery.circuit_breaker]
//	enabled = true
//	failure_threshold = 5
//
//	[storage]
//	backend = "s3"  # or "filesystem"
//	bucket = "mizu-storage"
//
//	[cluster]
//	enabled = true
//	peers = ["node1.example.com:7946", "node2.example.com:7946"]
//
// # Environment Variables
//
// Sensitive values can be provided via environment variables:
//
//	DELIVERY_AUTH_TOKEN: Authentication token for HTTP backend
//	S3_ACCESS_KEY: AWS access key
//	S3_SECRET_KEY: AWS secret access key
//	HEALTH_PASSWORD: Password for health endpoint
//	CLUSTER_SECRET_KEY: 32-byte base64-encoded encryption key for cluster
//
// Environment variables override values in the configuration file.
//
// # Loading Configuration
//
//	cfg, err := config.Load("config.toml")
//	if err != nil {
//	    log.Fatal("Failed to load config:", err)
//	}
//
// # Validation
//
// The Load function automatically validates the configuration:
//
//   - Required fields are present
//   - Numeric values are within valid ranges
//   - Domain names are valid
//   - Port numbers are valid
//   - File paths exist (when applicable)
//   - Distributed features have required dependencies
//
// # Default Values
//
// The package provides sensible defaults via DefaultConfig():
//
//	SMTP listen address: :25
//	Max message size: 10MB
//	Connection timeout: 10s
//	Max connections: 100
//	Max connections per IP: 10
//	Rate limit: 60 emails/minute per IP
//	DNS timeout: 5s
//	HTTP timeout: 30s
//	Circuit breaker: enabled with threshold of 5 failures
//
// # Storage Backend
//
// Two storage backends are supported:
//
//  1. S3 (default) - For production clusters
//     Used for TLS certificates and reputation stats sync
//
//  2. Filesystem - For single-node deployments
//     Stores data in local directory
//
// # Distributed Features
//
// Some features require cluster mode (cluster.enabled=true):
//
//	Distributed connection tracking (server.distributed.enabled)
//	Rate limit gossip (server.rate_limit.gossip_enabled)
//	TLS certificate management with leader election
//	Reputation stats sync across cluster
//
// # Example: Generate Configuration
//
//	// Generate example config file
//	if err := config.SaveExample("config.toml.example"); err != nil {
//	    log.Fatal(err)
//	}
//
// # Configuration Sections
//
// The Config struct has the following main sections:
//
//	Defaults: Default values inherited by all servers
//	Servers: Array of SMTP server instances (relay/submission)
//	DNS: DNS resolver configuration
//	Storage: S3 or filesystem backend settings
//	TLS: Let's Encrypt and certificate management
//	Health: Health check endpoint settings
//	Metrics: Prometheus metrics endpoint settings
//	Stats: Reputation tracking configuration
//	Cluster: Distributed coordination settings
//
// Each server has its own configuration:
//
//	Limits: Connection and rate limits
//	TLS: TLS mode and requirements
//	DNS Checks: rDNS, sender MX validation
//	Junk: Spam detection settings
//	SPF/DKIM/DMARC/ARC: Email authentication
//	DNSBL: DNS blacklist checking
//	Header Analysis: Advanced spam detection
//	Rate Limiting: Multi-dimensional rate limits
//	Distributed: Cluster-wide connection tracking
//	Recipient Validation: HTTP-based validation
//	Delivery: HTTP backend configuration with circuit breaker
//
// # Thread Safety
//
// Config instances are immutable after loading and can be safely
// shared across goroutines.
package config

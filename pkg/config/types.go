package config

import (
	"net"
	"strconv"
	"strings"
)

// Config holds all configuration for the SMTP server(s)
type Config struct {
	Servers  []ServerConfig `toml:"server"`   // Multiple SMTP server instances
	Defaults DefaultsConfig `toml:"defaults"` // Default values for all servers
	Logging  LoggingConfig  `toml:"logging"`  // Logging configuration
	DNS      DNSConfig      `toml:"dns"`
	Storage  StorageConfig  `toml:"storage"`
	TLS      TLSConfig      `toml:"tls"`
	Health   HealthConfig   `toml:"health"`
	Metrics  MetricsConfig  `toml:"metrics"`
	Stats    StatsConfig    `toml:"stats"`
	Cluster  ClusterConfig  `toml:"cluster"` // Global cluster/peering configuration
	Local    bool           `toml:"local"`   // Local development mode (disables TLS and validation)
}

// DefaultsConfig provides default values that can be overridden per-server
type DefaultsConfig struct {
	Hostname               string `toml:"hostname"`                 // Default hostname (FQDN) for all servers
	MaxMessageSize         int    `toml:"max_message_size"`         // Default max message size in bytes
	TimeoutSeconds         int    `toml:"timeout_seconds"`          // Default SMTP command timeout (see ServerConfig.TimeoutSeconds)
	ShutdownTimeoutSeconds int    `toml:"shutdown_timeout_seconds"` // Default graceful shutdown timeout
	MaxConnections         int    `toml:"max_connections"`          // Default max total connections per server
}

// MaxMessageSizeLimit is the hard ceiling on a server's max_message_size.
// Messages are fully buffered in memory (once per session during DATA, and
// again per recipient during delivery), so a limit beyond this is a
// memory-exhaustion risk regardless of what the operator asked for.
const MaxMessageSizeLimit = 100 * 1024 * 1024 // 100 MiB

// ServerConfig defines a single SMTP server instance
type ServerConfig struct {
	// === Identity ===
	Name string `toml:"name"` // Human-readable name (e.g., "mx-primary", "submission-tls")
	Type string `toml:"type"` // "relay" (MX server) or "submission" (MSA server). Also sets the default for strip_client_identity (stripped on submission, kept on relay).

	// === Network ===
	ListenAddr           string       `toml:"listen_addr"`            // Address to bind (e.g., ":25", ":465", ":587", "127.0.0.1:2525")
	Hostname             string       `toml:"hostname"`               // Server hostname/FQDN (overrides defaults.hostname if set)
	ProxyProtocol        bool         `toml:"proxy_protocol"`         // Enable HAProxy PROXY protocol v1/v2 (real client IP from PROXY header)
	ProxyProtocolTrusted []string     `toml:"proxy_protocol_trusted"` // CIDRs/IPs allowed to send PROXY headers (required when proxy_protocol=true)
	proxyTrustedNets     []*net.IPNet // ProxyProtocolTrusted parsed by Validate

	// === Message Processing ===
	MaxMessageSize          int `toml:"max_message_size"`           // Maximum message size in bytes (overrides default)
	MaxRecipientsPerMessage int `toml:"max_recipients_per_message"` // Maximum recipients per message (default: 100)

	// === Connection Limits ===
	Limits ServerLimitsConfig `toml:"limits"` // Connection limits

	// === TLS Configuration ===
	TLS ServerTLSConfig `toml:"tls"` // TLS configuration (if section present, TLS is enabled)

	// === Timeouts ===
	// TimeoutSeconds is how long the server waits for the next command from
	// the client (and for a response write to drain). RFC 5321 §4.5.3.2.7
	// sets the floor at 5 minutes, which is also Postfix's smtpd_timeout
	// default; anything shorter disconnects legitimate clients that pause
	// between commands — a desktop MUA doing a slow reverse-DNS lookup of its
	// own LAN address before EHLO, a laggy mobile uplink, an on-access virus
	// scanner. Such a client sees the connection drop right after the banner
	// or mid-conversation and cannot distinguish it from a network fault.
	//
	// A short value buys almost no DoS protection: an attacker holding a slot
	// only has to trickle one command per interval to stay under it, and total
	// connection lifetime is bounded independently by smtp.SessionDeadline.
	// Cap concurrency with limits.max_connections / max_connections_per_ip
	// instead.
	TimeoutSeconds         int `toml:"timeout_seconds"`          // SMTP command timeout (overrides default)
	ShutdownTimeoutSeconds int `toml:"shutdown_timeout_seconds"` // Graceful shutdown timeout (overrides default)

	// === Client Compatibility ===
	// LegacyAuthCap advertises the obsolete "AUTH=<mechanisms>" EHLO line in
	// addition to the standard "AUTH <mechanisms>" capability on submission
	// servers. Microsoft Outlook lineages look for the legacy form and refuse
	// to attempt authentication when it is absent (the August 2026 "new
	// Outlook cannot connect" incident); Postfix ships the same workaround as
	// broken_sasl_auth_clients. Default: true.
	LegacyAuthCap *bool `toml:"legacy_auth_cap"`
	// AdvertiseLimits re-enables the "LIMITS RCPTMAX=..." (RFC 9422) EHLO
	// capability, advertised when max_recipients_per_message is set. Off by
	// default: the extension is young and can confuse client capability
	// parsers. Default: false.
	AdvertiseLimits bool `toml:"advertise_limits"`

	// === Debugging ===
	Debug bool `toml:"debug"` // Enable SMTP protocol debug logging (shows all SMTP commands and responses)

	// === Injected Header Toggles ===
	// Per-header toggles for the X-Mizu-* headers injected before delivery.
	// nil defaults to true (header emitted); explicit false suppresses the
	// individual header. The Received header is always added regardless.
	EnableTraceIDHeader     *bool `toml:"enable_trace_id_header"`     // X-Mizu-Trace-ID (default: true)
	EnableAuthResultsHeader *bool `toml:"enable_auth_results_header"` // X-Mizu-Authentication-Results (default: true)
	EnableJunkHeader        *bool `toml:"enable_junk_header"`         // X-Mizu-Junk (default: true). Governs only this header: junk.apply_action adds its own junk marker (e.g. X-Spam) independently

	// === Privacy ===
	// StripClientIdentity omits the "from <HELO> (<client IP>)" clause from the
	// Received header this server stamps, so the submitting client's machine name
	// and network are not published to recipients. The rest of the hop (server
	// hostname, protocol, trace ID, timestamp) is preserved, so the message stays
	// correlatable with our own logs. This deliberately deviates from RFC 5321 §4.4,
	// which recommends recording the source in the Received line.
	// Defaults to true on submission servers (the client is an end user whose home
	// or mobile address should not reach recipients) and false on relay servers,
	// where downstream receivers rely on the full trace for SPF/DMARC forensics and
	// loop detection. Set explicitly to override either default.
	StripClientIdentity *bool `toml:"strip_client_identity"`

	// === Email Validation ===
	HELOValidation        *bool  `toml:"helo_validation"`         // Validate HELO/EHLO hostname (default: true on relay, false on submission — Windows MUAs send bare machine names; explicit setting wins)
	SPFCheck              bool   `toml:"spf_check"`               // Enable SPF validation
	DKIMCheck             bool   `toml:"dkim_check"`              // Enable DKIM validation
	ARCCheck              bool   `toml:"arc_check"`               // Enable ARC validation
	DMARCCheck            bool   `toml:"dmarc_check"`             // Enable DMARC validation
	DMARCRejectAction     string `toml:"dmarc_reject_action"`     // Action for policy=reject: "none", "reject", "junk" (default: "reject")
	DMARCQuarantineAction string `toml:"dmarc_quarantine_action"` // Action for policy=quarantine: "none", "reject", "junk" (default: "junk")

	// === Nested Configuration Sections ===
	Validation ServerValidationConfig `toml:"validation"` // Message validation settings (applies to both relay and submission)
	Reputation ServerReputationConfig `toml:"reputation"` // Reputation checking configuration
	Auth       ServerAuthConfig       `toml:"auth"`       // Authentication configuration (use auth.required=true to require auth)
	DNSChecks  ServerDNSChecksConfig  `toml:"dns_checks"` // DNS validation checks (rDNS, MX)
	Junk       ServerJunkConfig       `toml:"junk"`       // Junk/spam detection configuration
	SpamCheck  ServerSpamCheckConfig  `toml:"spam_check"` // External spam checking (rspamd) configuration

	// === Rate Limiting (per-server) ===
	RateLimit   RateLimitConfig         `toml:"rate_limit"`  // Rate limiting configuration
	Distributed DistributedLimitsConfig `toml:"distributed"` // Distributed connection tracking

	// === Sender Validation Configuration (per-server) ===
	SenderValidation SenderValidationConfig `toml:"sender_validation"` // HTTP endpoint for sender validation during MAIL FROM

	// === Recipient Validation Configuration (per-server) ===
	RecipientValidation RecipientValidationConfig `toml:"recipient_validation"` // HTTP endpoint for recipient validation during RCPT TO

	// === Delivery Configuration (per-server) ===
	Delivery DeliveryConfig `toml:"delivery"` // HTTP endpoint for email delivery
}

// HeaderToggles selects which X-Mizu-* headers are injected before delivery.
type HeaderToggles struct {
	TraceID     bool // X-Mizu-Trace-ID
	AuthResults bool // X-Mizu-Authentication-Results
	Junk        bool // X-Mizu-Junk
}

// HeaderToggles resolves the per-header enable flags (nil = true).
func (s *ServerConfig) HeaderToggles() HeaderToggles {
	return HeaderToggles{
		TraceID:     s.EnableTraceIDHeader == nil || *s.EnableTraceIDHeader,
		AuthResults: s.EnableAuthResultsHeader == nil || *s.EnableAuthResultsHeader,
		Junk:        s.EnableJunkHeader == nil || *s.EnableJunkHeader,
	}
}

// ServerLimitsConfig holds connection limits
type ServerLimitsConfig struct {
	MaxConnections               int `toml:"max_connections"`                 // Total connections for this server
	MaxConnectionsPerIP          int `toml:"max_connections_per_ip"`          // Per-IP connection limit (for DoS protection)
	MaxConnectionsPerUser        int `toml:"max_connections_per_user"`        // Per-user connection limit (for submission servers)
	MaxConnectionDurationSeconds int `toml:"max_connection_duration_seconds"` // Maximum connection duration in seconds before force-release (default: 300 = 5m, 0 = disabled)
}

// ServerValidationConfig holds message validation settings (applies to both relay and submission)
type ServerValidationConfig struct {
	MissingHeadersAction string `toml:"missing_headers_action"` // Action for missing Message-ID/Date headers: "reject", "fix", "none" (default: "reject" for submission, "fix" for relay)
	LoopDetection        *bool  `toml:"loop_detection"`         // Enable mail loop detection by checking Received headers (default: true, set to false to disable)
	MaxHops              int    `toml:"max_hops"`               // Maximum number of hops (Received headers) before rejecting (default: 30, RFC 5321 recommends 100)
}

// ServerReputationConfig holds reputation checking configuration
type ServerReputationConfig struct {
	Enabled        bool                        `toml:"enabled"`          // Enable reputation checking (default: true for relay, false for submission)
	MinIPScore     float64                     `toml:"min_ip_score"`     // Minimum IP reputation score (default: -0.2, range: -1.0 to 1.0)
	MinDomainScore float64                     `toml:"min_domain_score"` // Minimum domain reputation score (default: -0.2, range: -1.0 to 1.0)
	RejectCode     int                         `toml:"reject_code"`      // SMTP code for reputation rejection (default: 421, common: 421, 450, 451, 550)
	RejectMessage  string                      `toml:"reject_message"`   // Message for reputation rejection (default: "poor reputation, please try again later")
	WhitelistIPs   []string                    `toml:"whitelist_ips"`    // IP addresses/CIDRs to whitelist (e.g., ["1.2.3.4", "10.0.0.0/8"])
	WhitelistHosts []string                    `toml:"whitelist_hosts"`  // PTR hostnames to whitelist (suffix match, e.g., ["hetrixtools.com", "pingdom.com"])
	DNSBL          ServerReputationDNSBLConfig `toml:"dnsbl"`            // DNS blacklist checking that feeds into reputation scoring
	whitelistNets  []*net.IPNet                // WhitelistIPs parsed by ServerConfig.Validate
}

// WhitelistNets returns the parsed whitelist_ips networks. Populated by
// ServerConfig.Validate.
func (c *ServerReputationConfig) WhitelistNets() []*net.IPNet {
	return c.whitelistNets
}

// ServerReputationDNSBLConfig holds DNSBL checking configuration for reputation
type ServerReputationDNSBLConfig struct {
	Enabled        bool     `toml:"enabled"`         // Enable DNSBL checking (default: false)
	IPv4Lists      []string `toml:"ipv4_lists"`      // DNS blacklist servers for IPv4 (e.g., ["zen.spamhaus.org", "bl.spamcop.net"])
	IPv6Lists      []string `toml:"ipv6_lists"`      // DNS blacklist servers for IPv6 (e.g., ["zen.spamhaus.org"])
	TimeoutSeconds int      `toml:"timeout_seconds"` // Timeout for DNSBL queries in seconds (default: 3)
	Weight         int64    `toml:"weight"`          // Negative reputation weight for DNSBL hits (default: 5)
}

// ServerAuthConfig holds authentication configuration for submission servers
// Authentication is performed via HTTPS POST to the configured URL
type ServerAuthConfig struct {
	Enabled   bool                      `toml:"enabled"`    // Enable SMTP AUTH (advertise AUTH in EHLO, default: false)
	Required  bool                      `toml:"required"`   // Require authentication before MAIL FROM (default: false, implies enabled=true)
	URL       string                    `toml:"url"`        // HTTPS URL for authentication (must use https://)
	AuthToken string                    `toml:"auth_token"` // Authentication token (sent as Bearer token, can use env var: ${AUTH_TOKEN})
	Cache     ServerAuthCacheConfig     `toml:"cache"`      // Authentication caching configuration
	RateLimit ServerAuthRateLimitConfig `toml:"rate_limit"` // Authentication rate limiting configuration
}

// ServerAuthRateLimitConfig holds authentication rate limiting configuration
// Implements two-tier blocking system to protect against brute-force attacks
type ServerAuthRateLimitConfig struct {
	Enabled bool `toml:"enabled"` // Enable authentication rate limiting (default: true when auth is enabled)

	// TIER 1: Fast IP+Username Blocking
	// Protects shared IPs (corporate gateways) by blocking specific user+IP combinations
	MaxAttemptsPerIPUsername int    `toml:"max_attempts_per_ip_username"` // Failures before blocking (default: 5)
	IPUsernameBlockDuration  string `toml:"ip_username_block_duration"`   // Block duration (default: "15m")
	IPUsernameWindowDuration string `toml:"ip_username_window_duration"`  // Sliding window for counting failures (default: "10m")

	// TIER 2: Slow IP-Only Blocking
	// Catches distributed attacks trying many usernames from same IP
	MaxAttemptsPerIP int    `toml:"max_attempts_per_ip"` // Failures before blocking entire IP (default: 50)
	IPBlockDuration  string `toml:"ip_block_duration"`   // Block duration (default: "30m")
	IPWindowDuration string `toml:"ip_window_duration"`  // Sliding window for counting failures (default: "30m")

	// TIER 3: Subnet Blocking
	// Catches attackers rotating through sibling IPs (one failure per address,
	// so tiers 1-2 never accumulate). Triggers on BREADTH — distinct failing
	// IPs inside one subnet — not raw failure volume, so a shared NAT where a
	// few users mistype passwords never qualifies. IPv4 groups by /24; IPv6
	// counts distinct /64s inside a /48 (a /64 is one subscriber, so
	// per-address counting would hand v6 attackers 2^64 free identities).
	SubnetMaxDistinctIPs  int      `toml:"subnet_max_distinct_ips"` // Distinct failing IPv4 addresses / IPv6 64s before the subnet blocks (default: 8, negative = tier disabled)
	SubnetMinFailures     int      `toml:"subnet_min_failures"`     // Minimum total failures in the window before the subnet blocks (default: 15)
	SubnetWindowDuration  string   `toml:"subnet_window_duration"`  // Sliding window for the distinct-IP set (default: "30m")
	SubnetBlockDuration   string   `toml:"subnet_block_duration"`   // Block duration (default: "30m")
	SubnetIPv4Prefix      int      `toml:"subnet_ipv4_prefix"`      // IPv4 grouping prefix length (default: 24)
	SubnetIPv6Prefix      int      `toml:"subnet_ipv6_prefix"`      // IPv6 grouping prefix length (default: 48)
	SubnetExempt          []string `toml:"subnet_exempt"`           // CIDRs never subnet-blocked (own infra, known customers); private/loopback are always exempt
	SuccessExemptDuration string   `toml:"success_exempt_duration"` // How long a successful login exempts its IP from subnet blocks (default: "24h")

	// USERNAME TRACKING (Statistics Only - No Blocking)
	// Synchronized across cluster for detecting compromised accounts
	MaxAttemptsPerUsername int    `toml:"max_attempts_per_username"` // Tracking threshold (default: 100, no blocking)
	UsernameWindowDuration string `toml:"username_window_duration"`  // Tracking window (default: "1h")

	// PROGRESSIVE DELAYS
	// Adds delays before full IP blocking to slow attackers
	DelayStartThreshold int     `toml:"delay_start_threshold"` // Failures before delays start (default: 3)
	InitialDelay        string  `toml:"initial_delay"`         // First delay (default: "1s")
	MaxDelay            string  `toml:"max_delay"`             // Maximum delay (default: "30s")
	DelayMultiplier     float64 `toml:"delay_multiplier"`      // Delay growth factor (default: 2.0)

	// MAINTENANCE
	CacheCleanupInterval string `toml:"cache_cleanup_interval"` // In-memory cleanup interval (default: "5m")

	// MEMORY SAFETY LIMITS
	// Prevents unbounded memory growth during massive attacks
	MaxIPUsernameEntries int `toml:"max_ip_username_entries"` // Max IP+username tracking entries (default: 100000, 0 = unlimited)
	MaxIPEntries         int `toml:"max_ip_entries"`          // Max IP tracking entries (default: 50000, 0 = unlimited)
	MaxUsernameEntries   int `toml:"max_username_entries"`    // Max username tracking entries (default: 50000, 0 = unlimited)
	MaxSubnetEntries     int `toml:"max_subnet_entries"`      // Max subnet tracking entries (default: 10000, 0 = unlimited)

	// CLUSTER SYNCHRONIZATION
	// Syncs auth failures and blocks across cluster via gossip
	ClusterSyncEnabled bool `toml:"cluster_sync_enabled"` // Enable cluster-wide sync (default: true when cluster enabled)
	SyncBlocks         bool `toml:"sync_blocks"`          // Sync IP blocks across cluster (default: true)
	SyncFailureCounts  bool `toml:"sync_failure_counts"`  // Sync progressive delay counts across cluster (default: true)
}

// ServerAuthCacheConfig holds authentication caching configuration
// Reduces load on authentication backend and protects against DoS attacks
type ServerAuthCacheConfig struct {
	Enabled bool `toml:"enabled"` // Enable authentication caching (default: true when auth is enabled)

	// CACHE TTL SETTINGS
	PositiveTTL string `toml:"positive_ttl"` // Cache duration for successful auth (default: "5m")
	NegativeTTL string `toml:"negative_ttl"` // Cache duration for failed auth (default: "1m")

	// MEMORY SAFETY
	MaxSize int `toml:"max_size"` // Maximum cache entries (default: 50000)

	// MAINTENANCE
	CleanupInterval string `toml:"cleanup_interval"` // Cleanup interval (default: "5m")

	// PASSWORD CHANGE DETECTION
	// Allows detecting password changes while maintaining cache benefits
	PositiveRevalidationWindow string `toml:"positive_revalidation_window"` // Revalidate successful auth after this duration (default: "30s")
}

// Removed: ServerSPFConfig, ServerDKIMConfig, ServerDMARCConfig, ServerARCConfig
// ServerDNSChecksConfig holds DNS validation checks
type ServerDNSChecksConfig struct {
	RequireRDNS           bool `toml:"require_rdns"`            // Require reverse DNS for sender IP
	RequireSenderMX       bool `toml:"require_sender_mx"`       // Require sender domain to have MX records
	RequireResolvableHELO bool `toml:"require_resolvable_helo"` // Require HELO hostname to have DNS records (default: false)

	// RDNSWhitelistIPs lists IP addresses/CIDRs exempt from require_rdns
	// (e.g., ["1.2.3.4", "10.0.0.0/8"]). The exemption covers only the rDNS
	// requirement; reputation checks still apply (use reputation.whitelist_ips
	// to bypass those). Sessions admitted without a PTR record interpolate
	// $ptr as an empty string in sender/recipient validation URLs.
	RDNSWhitelistIPs  []string     `toml:"rdns_whitelist_ips"`
	rdnsWhitelistNets []*net.IPNet // RDNSWhitelistIPs parsed by ServerConfig.Validate
}

// RDNSWhitelistNets returns the parsed rdns_whitelist_ips networks. Populated
// by ServerConfig.Validate.
func (c *ServerDNSChecksConfig) RDNSWhitelistNets() []*net.IPNet {
	return c.rdnsWhitelistNets
}

// ServerJunkConfig holds junk/spam detection configuration
type ServerJunkConfig struct {
	RejectNullSender bool     `toml:"reject_null_sender"` // Reject bounce messages (<>)
	CheckHeaders     []string `toml:"check_headers"`      // Headers that mark email as junk
	ApplyAction      string   `toml:"apply_action"`       // Action when junk detected: "header", "reject", "warn", "subject"
	SubjectPattern   string   `toml:"subject_pattern"`    // Subject pattern for "subject" action (e.g., "[spam] %s")
	Header           string   `toml:"header"`             // Header to add for "header" action (e.g., "X-Spam")
}

// ServerSpamCheckConfig holds external spam checking configuration (rspamd)
type ServerSpamCheckConfig struct {
	Enabled            bool   `toml:"enabled"`              // Enable external spam checking (default: false)
	URL                string `toml:"url"`                  // Rspamd HTTP endpoint (e.g., "http://rspamd:11333/checkv2")
	Password           string `toml:"password"`             // HTTPCrypt password for rspamd authentication (optional)
	HTTPTimeoutSeconds int    `toml:"http_timeout_seconds"` // HTTP client timeout in seconds (default: 15)
	SpamHeader         string `toml:"spam_header"`          // Header name to add when spam detected (default: "X-Junk")
	SpamHeaderValue    string `toml:"spam_header_value"`    // Header value for spam (default: "yes")
	HamHeaderValue     string `toml:"ham_header_value"`     // Header value for ham/not spam (default: "", empty = don't add header for ham)
	RejectOnAction     string `toml:"reject_on_action"`     // Reject message if rspamd action matches this (e.g., "reject", empty = never reject)
}

// ServerTLSConfig holds TLS configuration for a server
type ServerTLSConfig struct {
	Enabled       bool   `toml:"enabled"`         // Enable TLS for this server
	Mode          string `toml:"mode"`            // TLS mode: "starttls" or "implicit"
	Required      bool   `toml:"required"`        // Enforce TLS (reject unencrypted connections)
	MinTLSVersion string `toml:"min_tls_version"` // Minimum TLS version: "1.2" or "1.3"
	MaxTLSVersion string `toml:"max_tls_version"` // Maximum TLS version: "1.2" or "1.3" (empty = no cap). Set to "1.2" for Exchange Online interop.
}

// ProxyTrustedNets returns the parsed proxy_protocol_trusted networks.
// Populated by ServerConfig.Validate.
func (s *ServerConfig) ProxyTrustedNets() []*net.IPNet {
	return s.proxyTrustedNets
}

// IsRelay returns true if this is a relay (MX) server
func (s *ServerConfig) IsRelay() bool {
	return s.Type == "relay"
}

// IsSubmission returns true if this is a submission (MSA) server
func (s *ServerConfig) IsSubmission() bool {
	return s.Type == "submission"
}

// StripsClientIdentity reports whether the Received header stamped by this server
// should omit the client's HELO name and IP. Unset means the per-type default:
// stripped on submission, kept on relay.
func (s *ServerConfig) StripsClientIdentity() bool {
	if s.StripClientIdentity == nil {
		return s.IsSubmission()
	}
	return *s.StripClientIdentity
}

// LegacyAuthCapEnabled reports whether the obsolete "AUTH=" EHLO line should
// be advertised alongside the standard AUTH capability (default: true; see
// the LegacyAuthCap field comment for the Outlook background).
func (s *ServerConfig) LegacyAuthCapEnabled() bool {
	return s.LegacyAuthCap == nil || *s.LegacyAuthCap
}

// IsTLSEnabled returns true if TLS is explicitly enabled
func (s *ServerConfig) IsTLSEnabled() bool {
	return s.TLS.Enabled
}

// UsesSTARTTLS returns true if TLS mode is "starttls"
func (s *ServerConfig) UsesSTARTTLS() bool {
	return s.TLS.Mode == "starttls"
}

// UsesImplicitTLS returns true if TLS mode is "implicit"
func (s *ServerConfig) UsesImplicitTLS() bool {
	return s.TLS.Mode == "implicit"
}

// NeedsReverseDNS reports whether this server must perform a reverse-DNS (PTR)
// lookup on connecting clients. The lookup is uncached and runs inside
// NewSession (again after STARTTLS re-EHLO), so on a slow or absent PTR it
// stalls every EHLO. It is only worth that latency when something actually
// consumes the PTR result:
//   - require_rdns rejects connections that lack a PTR record;
//   - a reputation PTR-hostname whitelist (whitelist_hosts) matches against it;
//   - a sender or recipient validation URL interpolates the $ptr placeholder.
//
// Submission servers with none of these (the common case) skip the lookup
// entirely.
func (s *ServerConfig) NeedsReverseDNS() bool {
	if s.DNSChecks.RequireRDNS {
		return true
	}
	if s.Reputation.Enabled && len(s.Reputation.WhitelistHosts) > 0 {
		return true
	}
	if s.SenderValidation.Enabled && strings.Contains(s.SenderValidation.URL, "$ptr") {
		return true
	}
	if s.RecipientValidation.Enabled && strings.Contains(s.RecipientValidation.URL, "$ptr") {
		return true
	}
	return false
}

// ApplyDefaults fills in missing values from defaults
func (s *ServerConfig) ApplyDefaults(defaults DefaultsConfig) {
	if s.Hostname == "" {
		s.Hostname = defaults.Hostname
	}
	if s.MaxMessageSize == 0 {
		s.MaxMessageSize = defaults.MaxMessageSize
	}
	if s.TimeoutSeconds == 0 {
		s.TimeoutSeconds = defaults.TimeoutSeconds
	}
	if s.ShutdownTimeoutSeconds == 0 {
		s.ShutdownTimeoutSeconds = defaults.ShutdownTimeoutSeconds
	}
	if s.Limits.MaxConnections == 0 {
		s.Limits.MaxConnections = defaults.MaxConnections
	}
	if s.MaxRecipientsPerMessage == 0 {
		s.MaxRecipientsPerMessage = 100
	}

	// LegacyAuthCap defaults to true for Microsoft client compatibility
	// (uses pointer to detect unset); see the field comment.
	if s.LegacyAuthCap == nil {
		trueVal := true
		s.LegacyAuthCap = &trueVal
	}

	// X-Mizu-* header toggles default to true (pointers detect unset)
	for _, p := range []**bool{&s.EnableTraceIDHeader, &s.EnableAuthResultsHeader, &s.EnableJunkHeader} {
		if *p == nil {
			trueVal := true
			*p = &trueVal
		}
	}

	// Apply validation defaults
	// LoopDetection defaults to true for safety (uses pointer to detect unset)
	if s.Validation.LoopDetection == nil {
		trueVal := true
		s.Validation.LoopDetection = &trueVal
	}

	// HELOValidation defaults by server type (uses pointer to detect unset):
	// true on relay (MX) servers, where it screens spam bots, and false on
	// submission servers — authenticated desktop clients (notably Windows
	// Outlook) send their bare machine name as the EHLO argument, and
	// rejecting it locks every such client out (the August 2026 Outlook
	// incident). Postfix likewise never enforces HELO checks on submission.
	// An explicit helo_validation setting wins for either type.
	if s.HELOValidation == nil {
		v := !s.IsSubmission()
		s.HELOValidation = &v
	}

	// StripClientIdentity defaults to true on submission servers, where the client
	// is an end user whose network should not be disclosed to recipients, and false
	// on relay servers, where the full trace is operationally useful downstream.
	if s.StripClientIdentity == nil {
		v := s.IsSubmission()
		s.StripClientIdentity = &v
	}
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled               bool `toml:"enabled"`                 // Enable rate limiting (default: true)
	GossipEnabled         bool `toml:"gossip_enabled"`          // Share rate limit state across cluster via gossip (default: false)
	GossipIntervalSeconds int  `toml:"gossip_interval_seconds"` // How often to gossip rate limit data in seconds (default: 5)
	// Whitelisted IPs are exempt from ALL rate limit dimensions. Whitelisted
	// sender domains/addresses are exempt from all dimensions on an
	// authenticated session, and only from the FROM / FROM_DOMAIN dimensions
	// otherwise (an unauthenticated MAIL FROM is unverified). Each
	// kind accepts an inline array and/or an external file (one entry per line,
	// blank lines and '#' comments ignored); the effective set is the union of
	// both. Files are re-read automatically when they change on disk.
	WhitelistedIPs                 []string             `toml:"whitelisted_ips"`                   // IPs/CIDRs exempt from all rate limits (e.g., ["1.2.3.4", "10.0.0.0/8"])
	WhitelistedDomains             []string             `toml:"whitelisted_domains"`               // Sender domains exempt from all rate limits (e.g., ["example.com", "trusted.org"])
	WhitelistedSenders             []string             `toml:"whitelisted_senders"`               // Sender addresses exempt from all rate limits (e.g., ["admin@example.com"])
	WhitelistedIPsFile             string               `toml:"whitelisted_ips_file"`              // Optional file of IPs/CIDRs, merged with whitelisted_ips and hot-reloaded
	WhitelistedDomainsFile         string               `toml:"whitelisted_domains_file"`          // Optional file of sender domains, merged with whitelisted_domains and hot-reloaded
	WhitelistedSendersFile         string               `toml:"whitelisted_senders_file"`          // Optional file of sender addresses, merged with whitelisted_senders and hot-reloaded
	WhitelistReloadIntervalSeconds int                  `toml:"whitelist_reload_interval_seconds"` // How often to check whitelist files for changes, in seconds (default: 10)
	Dimensions                     []RateLimitDimension `toml:"dimensions"`                        // Rate limit dimensions (e.g., IP, FROM, FROM_DOMAIN, etc.)
}

// RateLimitDimension defines a single rate limit dimension with configurable key combination
type RateLimitDimension struct {
	Name          string   `toml:"name"`           // Human-readable name for this dimension
	Keys          []string `toml:"keys"`           // Dimension keys to combine (IP, FROM, FROM_DOMAIN, TO, TO_DOMAIN)
	Limit         int      `toml:"limit"`          // Max connections/emails per window (0 = unlimited)
	WindowSeconds int      `toml:"window_seconds"` // Time window for rate limiting in seconds (default: 60)
}

// DNSConfig holds DNS resolver configuration (global for all DNS operations)
type DNSConfig struct {
	Resolvers        []string `toml:"resolvers"`          // Custom DNS resolvers (e.g., ["1.1.1.1:53", "1.0.0.1:53"]), empty = use system default
	TimeoutSeconds   int      `toml:"timeout_seconds"`    // DNS query timeout in seconds (default: 5)
	CacheTTLSeconds  int      `toml:"cache_ttl_seconds"`  // DNS cache TTL in seconds for successful lookups (default: 300 = 5m)
	CacheNegativeTTL int      `toml:"cache_negative_ttl"` // DNS cache TTL in seconds for failed lookups (default: 60 = 1m)
}

// ClusterConfig holds global cluster/peering configuration (using memberlist)
type ClusterConfig struct {
	Enabled   bool     `toml:"enabled"`    // Enable cluster mode (memberlist)
	Addr      string   `toml:"addr"`       // Gossip listen address (can be "IP:port" or just "IP", must be specific IP, NOT 0.0.0.0 or localhost)
	Port      int      `toml:"port"`       // Gossip port (used if not specified in addr, default: 7946)
	NodeName  string   `toml:"node_name"`  // This node's name (defaults to hostname, also used as NodeID)
	Peers     []string `toml:"peers"`      // Other cluster nodes to connect to (e.g., ["10.0.1.10:7946", "10.0.1.11:7946"])
	SecretKey string   `toml:"secret_key"` // 32-byte base64-encoded encryption key (use CLUSTER_SECRET_KEY env var)
}

// GetBindAddr returns the bind address by parsing the addr field
func (c *ClusterConfig) GetBindAddr() string {
	if c.Addr == "" {
		return ""
	}
	// If addr contains port, split it
	if host, _, err := net.SplitHostPort(c.Addr); err == nil {
		return host
	}
	// Otherwise, return as-is (it's just an IP)
	return c.Addr
}

// GetBindPort returns the bind port from either addr or port field
func (c *ClusterConfig) GetBindPort() int {
	if c.Addr != "" {
		// If addr contains port, extract it
		if _, portStr, err := net.SplitHostPort(c.Addr); err == nil {
			if port, err := strconv.Atoi(portStr); err == nil {
				return port
			}
		}
	}
	// Fall back to port field
	if c.Port > 0 {
		return c.Port
	}
	// Default port
	return 7946
}

// DistributedLimitsConfig holds configuration for distributed connection tracking
type DistributedLimitsConfig struct {
	Enabled                  bool `toml:"enabled"`                     // Enable distributed tracking (requires cluster.enabled=true)
	GlobalMaxPerIP           int  `toml:"global_max_per_ip"`           // Global max connections per IP across cluster (0 = use local limit only)
	GossipIntervalSeconds    int  `toml:"gossip_interval_seconds"`     // How often to broadcast in seconds (default: 5)
	S3SyncIntervalSeconds    int  `toml:"s3_sync_interval_seconds"`    // How often to sync with S3 in seconds (default: 30)
	RecipientCacheTTLSeconds int  `toml:"recipient_cache_ttl_seconds"` // How long to cache recipient validation results in seconds (default: 900 = 15m)
}

// StorageConfig holds configuration for object storage (S3 or filesystem)
type StorageConfig struct {
	Backend        string `toml:"backend"`         // Storage backend: "s3" or "filesystem" (default: "s3")
	FilesystemPath string `toml:"filesystem_path"` // Path for filesystem backend (e.g., "/var/lib/mizu/storage")
	S3Endpoint     string `toml:"s3_endpoint"`     // S3 endpoint
	S3Bucket       string `toml:"s3_bucket"`       // S3 bucket name
	S3Prefix       string `toml:"s3_prefix"`       // S3 key prefix
	S3AccessKey    string `toml:"s3_access_key"`   // S3 access key
	S3SecretKey    string `toml:"s3_secret_key"`   // S3 secret key
	S3Region       string `toml:"s3_region"`       // S3 region
}

// SenderValidationConfig holds configuration for sender validation during MAIL FROM
type SenderValidationConfig struct {
	Enabled            bool   `toml:"enabled"`              // Enable sender validation (default: false)
	URL                string `toml:"url"`                  // HTTP endpoint for sender validation
	AuthToken          string `toml:"auth_token"`           // Authentication token (sent as Bearer token)
	HTTPTimeoutSeconds int    `toml:"http_timeout_seconds"` // HTTP client timeout in seconds (default: 5)
	CacheTTLSeconds    int    `toml:"cache_ttl_seconds"`    // Cache TTL for successful validations (default: 300 = 5min)
}

// RecipientValidationConfig holds configuration for recipient validation during RCPT TO
type RecipientValidationConfig struct {
	Enabled            bool   `toml:"enabled"`              // Enable recipient validation (default: false)
	URL                string `toml:"url"`                  // HTTP endpoint for recipient validation
	AuthToken          string `toml:"auth_token"`           // Authentication token (sent as Bearer token)
	HTTPTimeoutSeconds int    `toml:"http_timeout_seconds"` // HTTP client timeout in seconds (default: 5)
	CacheTTLSeconds    int    `toml:"cache_ttl_seconds"`    // Cache TTL for successful validations (default: 300 = 5min)
}

// DeliveryConfig holds configuration for the HTTP delivery endpoint
type DeliveryConfig struct {
	URL                    string               `toml:"url"`
	AuthToken              string               `toml:"auth_token"`
	MaxRetryAttempts       int                  `toml:"max_retry_attempts"`
	HTTPTimeoutSeconds     int                  `toml:"http_timeout_seconds"`      // HTTP client timeout in seconds (default: 30)
	MaxIdleConnsPerHost    int                  `toml:"max_idle_conns_per_host"`   // Max idle connections per backend host (default: 100, Go default is only 2)
	MaxConnsPerHost        int                  `toml:"max_conns_per_host"`        // Max total connections per backend host (default: 0 = unlimited)
	IdleConnTimeoutSeconds int                  `toml:"idle_conn_timeout_seconds"` // How long idle connections stay in pool before closing (default: 90)
	CircuitBreaker         CircuitBreakerConfig `toml:"circuit_breaker"`
}

// CircuitBreakerConfig holds configuration for the circuit breaker
type CircuitBreakerConfig struct {
	Enabled             bool `toml:"enabled"`
	FailureThreshold    int  `toml:"failure_threshold"`     // failures before opening (default: 5)
	SuccessThreshold    int  `toml:"success_threshold"`     // successes in half-open to close (default: 2)
	TimeoutSeconds      int  `toml:"timeout_seconds"`       // time to wait before half-open in seconds (default: 30)
	HalfOpenMaxCalls    int  `toml:"half_open_max_calls"`   // max concurrent calls in half-open (default: 1)
	ResetTimeoutSeconds int  `toml:"reset_timeout_seconds"` // time before resetting counters in seconds (default: 60)
}

// HealthConfig holds configuration for the health check endpoint.
type HealthConfig struct {
	Enabled    bool   `toml:"enabled"`
	ListenAddr string `toml:"listen_addr"`
	Username   string `toml:"username"` // HTTP Basic Auth username (empty = no auth)
	Password   string `toml:"password"` // HTTP Basic Auth password
}

// MetricsConfig holds configuration for Prometheus metrics endpoint
type MetricsConfig struct {
	Enabled  bool   `toml:"enabled"`  // Enable Prometheus metrics endpoint
	Bind     string `toml:"bind"`     // Bind address for metrics server (default: ":9091")
	Path     string `toml:"path"`     // Metrics endpoint path (default: "/metrics")
	Username string `toml:"username"` // HTTP Basic Auth username (optional, empty = no auth)
	Password string `toml:"password"` // HTTP Basic Auth password
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level  string `toml:"level"`  // Log level: debug, info, warn, error (default: info)
	Format string `toml:"format"` // Output format: console (human-readable) or json (structured) (default: console)
	Output string `toml:"output"` // Output destination: stderr, stdout, syslog, or /path/to/file.log (default: syslog)
}

// TLSConfig holds TLS/certificate configuration
type TLSConfig struct {
	Enabled     bool                 `toml:"enabled"`     // Enable TLS certificate management
	Provider    string               `toml:"provider"`    // "file" or "letsencrypt" (default: "file")
	File        TLSFileConfig        `toml:"file"`        // File-based certificate configuration
	LetsEncrypt TLSLetsEncryptConfig `toml:"letsencrypt"` // Let's Encrypt configuration
}

// TLSFileConfig holds configuration for file-based TLS certificates
type TLSFileConfig struct {
	CertFile string `toml:"cert_file"` // Path to certificate file (PEM)
	KeyFile  string `toml:"key_file"`  // Path to private key file (PEM)
}

// TLSLetsEncryptConfig holds Let's Encrypt automatic certificate configuration
type TLSLetsEncryptConfig struct {
	Email               string      `toml:"email"`                 // Email for Let's Encrypt notifications
	Domains             []string    `toml:"domains"`               // Domains to obtain certificates for
	DefaultDomain       string      `toml:"default_domain"`        // Default domain for SNI-less connections (defaults to first domain)
	StorageProvider     string      `toml:"storage_provider"`      // "s3" or "file" (default: "s3")
	CacheDir            string      `toml:"cache_dir"`             // Local cache dir (file mode) or fallback dir (s3 mode)
	SyncIntervalMinutes int         `toml:"sync_interval_minutes"` // Local→S3 sync interval (default: 5 minutes; only applies when storage_provider="s3")
	Staging             bool        `toml:"staging"`               // Use Let's Encrypt staging environment for testing (issued certs are untrusted)
	RenewBeforeDays     int         `toml:"renew_before_days"`     // Days before expiry to renew (default: 30)
	S3                  TLSS3Config `toml:"s3"`                    // S3 credentials and bucket for certificate storage
}

// TLSS3Config holds S3 credentials for Let's Encrypt certificate storage.
type TLSS3Config struct {
	Bucket    string `toml:"bucket"`
	Region    string `toml:"region"`
	Endpoint  string `toml:"endpoint"` // Custom S3 endpoint (e.g., Backblaze B2, MinIO); empty = AWS default
	Prefix    string `toml:"prefix"`
	AccessKey string `toml:"access_key"`
	SecretKey string `toml:"secret_key"`
}

// StatsConfig holds configuration for IP and domain reputation tracking
// Note: Peer and hostname configuration is now in ClusterConfig (cluster.peers + cluster.hostname)
type StatsConfig struct {
	Enabled             bool `toml:"enabled"`               // Enable stats tracking
	RetentionSeconds    int  `toml:"retention_seconds"`     // How long to keep stats in seconds (default: 86400 = 24h)
	SyncEnabled         bool `toml:"sync_enabled"`          // Enable distributed stats sync (uses cluster.peers)
	SyncIntervalSeconds int  `toml:"sync_interval_seconds"` // How often to sync/export stats in seconds (default: 60)
	MaxIPEntries        int  `toml:"max_ip_entries"`        // Maximum number of IP entries to track (0 = unlimited, default: 100000)
	MaxDomainEntries    int  `toml:"max_domain_entries"`    // Maximum number of domain entries to track (0 = unlimited, default: 50000)
	BufferSize          int  `toml:"buffer_size"`           // Event channel buffer size (default: 100000)
}

// DefaultConfig returns a Config with sensible default values
func DefaultConfig() Config {
	return Config{
		Defaults: DefaultsConfig{
			Hostname:               "mail.example.com",
			MaxMessageSize:         25 * 1024 * 1024, // 25MB
			TimeoutSeconds:         300,              // RFC 5321 §4.5.3.2.7 server minimum
			ShutdownTimeoutSeconds: 60,
			MaxConnections:         100,
		},
		Servers: []ServerConfig{},
		DNS: DNSConfig{
			Resolvers:        []string{}, // Empty = use system DNS
			TimeoutSeconds:   5,          // Default 5s DNS timeout
			CacheTTLSeconds:  300,        // Default 5m (300s) DNS cache TTL
			CacheNegativeTTL: 60,         // Default 1m (60s) negative cache TTL
		},
		Storage: StorageConfig{
			Backend:        "s3",                    // Default to S3
			FilesystemPath: "/var/lib/mizu/storage", // Default filesystem path
			S3Endpoint:     "s3.amazonaws.com",
			S3Bucket:       "email-mx-certs",
			S3Prefix:       "", // Base prefix for all S3 keys. Subdirectories are appended automatically: certs/, stats/, connections/. Do NOT set this to "certs/" or similar — that would cause doubled paths like certs/certs/.
			S3Region:       "us-east-1",
		},
		TLS: TLSConfig{
			Enabled:  false,
			Provider: "file",
			LetsEncrypt: TLSLetsEncryptConfig{
				Email:               "admin@example.com",
				Domains:             []string{},
				StorageProvider:     "s3",
				CacheDir:            "",
				SyncIntervalMinutes: 5,
				Staging:             false,
				RenewBeforeDays:     30,
			},
		},
		Health: HealthConfig{
			Enabled:    true,
			ListenAddr: ":8080",
			Username:   "",
			Password:   "",
		},
		Metrics: MetricsConfig{
			Enabled:  true,
			Bind:     ":9091",
			Path:     "/metrics",
			Username: "",
			Password: "",
		},
		Stats: StatsConfig{
			Enabled:             true,
			RetentionSeconds:    86400,  // Default 24h (86400s) retention
			SyncEnabled:         false,  // Disabled by default
			SyncIntervalSeconds: 60,     // Default 1m (60s) sync interval
			MaxIPEntries:        100000, // 100k IP entries
			MaxDomainEntries:    50000,  // 50k domain entries
			BufferSize:          100000, // 100k event buffer
		},
		Cluster: ClusterConfig{
			Enabled:  false,
			Addr:     "",         // Must be set to specific IP when enabled
			Port:     7946,       // Standard memberlist port
			NodeName: "",         // Auto-detected if empty
			Peers:    []string{}, // No peers by default
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "console",
			Output: "syslog",
		},
		Local: false,
	}
}

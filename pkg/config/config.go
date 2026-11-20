package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// requireHTTPSURL enforces that a token-bearing endpoint uses https:// so that
// bearer tokens (and, for delivery, the full message) are never sent in
// cleartext. Loopback URLs are exempt to allow local development.
func requireHTTPSURL(fieldName, rawURL string) error {
	if !strings.HasPrefix(rawURL, "https://") && !isLocalhostURL(rawURL) {
		return fmt.Errorf("%s must use https:// (bearer token and message data are sent in cleartext over http, except for localhost)", fieldName)
	}
	return nil
}

// isLocalhostURL reports whether the given URL points to a loopback address,
// allowing http:// for local development/testing of authentication endpoints.
func isLocalhostURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// ParseIPList parses IP whitelist entries into networks. Each entry is either
// an exact IP ("1.2.3.4", "2001:db8::1") or a CIDR ("10.0.0.0/8"); exact IPs
// become single-address networks.
func ParseIPList(entries []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		if strings.Contains(entry, "/") {
			_, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q", entry)
			}
			nets = append(nets, ipNet)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address %q", entry)
		}
		mask := net.CIDRMask(128, 128)
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
			mask = net.CIDRMask(32, 32)
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: mask})
	}
	return nets, nil
}

// Validate checks the configuration for required fields and placeholder values.
func (c *Config) Validate() error {
	// Check that at least one server is configured
	if len(c.Servers) == 0 {
		return errors.New("no [[server]] sections defined - at least one server is required")
	}

	// Before the local-mode return below: these hold in every mode.
	if err := c.validateNonNegative(); err != nil {
		return err
	}

	// Handle duplicate server names (warn and de-duplicate)
	seenNames := make(map[string]int)
	for i := range c.Servers {
		name := c.Servers[i].Name
		if name == "" {
			// Assign default name
			c.Servers[i].Name = fmt.Sprintf("server-%d", i+1)
			name = c.Servers[i].Name
		}

		if count, exists := seenNames[name]; exists {
			// Duplicate name found - append suffix
			count++
			seenNames[name] = count
			newName := fmt.Sprintf("%s-%d", name, count)
			// Note: Using fmt.Fprintf to stderr since logger not available yet
			fmt.Fprintf(os.Stderr, "WARNING: Duplicate server name '%s' renamed to '%s'\n", name, newName)
			c.Servers[i].Name = newName
		} else {
			seenNames[name] = 1
		}
	}

	// Apply defaults and validate each server
	for i := range c.Servers {
		c.Servers[i].ApplyDefaults(c.Defaults)
		if err := c.Servers[i].Validate(); err != nil {
			return fmt.Errorf("server '%s': %w", c.Servers[i].Name, err)
		}

		// Validate the effective max message size (defaults already applied, so
		// this covers a per-server override and an inherited defaults value
		// alike). A zero ("unlimited") limit is a memory-DoS foot-gun — the whole
		// message is buffered in RAM per session and again per recipient during
		// delivery — so it is rejected outright, and a ceiling caps the blast
		// radius of a misconfigured large limit.
		if size := c.Servers[i].MaxMessageSize; size <= 0 {
			return fmt.Errorf("server '%s': max_message_size must be a positive byte limit - messages are buffered in memory, \"unlimited\" (0) is not supported", c.Servers[i].Name)
		} else if size > MaxMessageSizeLimit {
			return fmt.Errorf("server '%s': max_message_size must be <= %d MiB (got %d bytes)", c.Servers[i].Name, MaxMessageSizeLimit/(1024*1024), size)
		}
	}

	// Check for port conflicts
	usedPorts := make(map[string]string)
	for _, srv := range c.Servers {
		if existingServer, exists := usedPorts[srv.ListenAddr]; exists {
			return fmt.Errorf("port conflict: servers '%s' and '%s' both use %s",
				existingServer, srv.Name, srv.ListenAddr)
		}
		usedPorts[srv.ListenAddr] = srv.Name
	}

	// Validate per-server delivery configuration
	for i := range c.Servers {
		srv := &c.Servers[i]
		if srv.Delivery.MaxRetryAttempts > 5 {
			return fmt.Errorf("server[%s].delivery.max_retry_attempts must be <= 5 (got %d) to prevent excessive delays", srv.Name, srv.Delivery.MaxRetryAttempts)
		}
		if srv.Delivery.MaxRetryAttempts < 1 {
			return fmt.Errorf("server[%s].delivery.max_retry_attempts must be >= 1 (got %d)", srv.Name, srv.Delivery.MaxRetryAttempts)
		}

		// Validate HTTP timeout
		if srv.Delivery.HTTPTimeoutSeconds < 1 {
			return fmt.Errorf("server[%s].delivery.http_timeout_seconds must be >= 1 (got %d)", srv.Name, srv.Delivery.HTTPTimeoutSeconds)
		}
		if srv.Delivery.HTTPTimeoutSeconds > 300 {
			return fmt.Errorf("server[%s].delivery.http_timeout_seconds must be <= 300 (5m) (got %d) to prevent blocking SMTP sessions", srv.Name, srv.Delivery.HTTPTimeoutSeconds)
		}

		// Production mode validations (skip in local mode)
		if !c.Local {
			if srv.Delivery.URL == "" {
				return fmt.Errorf("server[%s].delivery.url must be set", srv.Name)
			}
			if srv.Delivery.AuthToken == "" || srv.Delivery.AuthToken == "your-auth-token-here" {
				return fmt.Errorf("server[%s].delivery.auth_token must be set", srv.Name)
			}
			if err := requireHTTPSURL(fmt.Sprintf("server[%s].delivery.url", srv.Name), srv.Delivery.URL); err != nil {
				return err
			}
			// Other token-bearing endpoints must also use HTTPS in production so
			// bearer tokens are not sent in cleartext (loopback exempt).
			if srv.SenderValidation.Enabled {
				if err := requireHTTPSURL(fmt.Sprintf("server[%s].sender_validation.url", srv.Name), srv.SenderValidation.URL); err != nil {
					return err
				}
			}
			if srv.RecipientValidation.Enabled {
				if err := requireHTTPSURL(fmt.Sprintf("server[%s].recipient_validation.url", srv.Name), srv.RecipientValidation.URL); err != nil {
					return err
				}
			}
		}
	}

	// The gossip key is required in every mode. Local mode relaxes TLS and
	// storage requirements, but the server still starts the cluster when
	// cluster.enabled is set, and an unkeyed cluster accepts block, unblock and
	// rate-limit state from anyone who can reach the gossip port.
	if c.Cluster.Enabled {
		if err := c.validateClusterSecretKey(); err != nil {
			return err
		}
	}

	// Production mode validations (skip in local mode)
	if c.Local {
		return nil
	}

	// Validate storage configuration based on backend
	if c.Storage.Backend == "" {
		c.Storage.Backend = "s3" // Default to S3
	}

	switch c.Storage.Backend {
	case "s3":
		if c.Storage.S3AccessKey == "" || c.Storage.S3AccessKey == "your-s3-access-key" {
			return errors.New("storage.s3_access_key must be set when using S3 backend")
		}
		if c.Storage.S3SecretKey == "" || c.Storage.S3SecretKey == "your-s3-secret-key" {
			return errors.New("storage.s3_secret_key must be set when using S3 backend")
		}
		if c.Storage.S3Bucket == "" {
			return errors.New("storage.s3_bucket must be set when using S3 backend")
		}
	case "filesystem":
		if c.Storage.FilesystemPath == "" {
			return errors.New("storage.filesystem_path must be set when using filesystem backend")
		}
	default:
		return fmt.Errorf("invalid storage backend: %s (must be 's3' or 'filesystem')", c.Storage.Backend)
	}

	// Validate TLS configuration
	if c.TLS.Enabled {
		switch c.TLS.Provider {
		case "file":
			if c.TLS.File.CertFile == "" || c.TLS.File.KeyFile == "" {
				return errors.New("tls.file.cert_file and tls.file.key_file must be set when tls.provider=file")
			}
		case "letsencrypt":
			if c.TLS.LetsEncrypt.Email == "" || c.TLS.LetsEncrypt.Email == "admin@example.com" {
				return errors.New("tls.letsencrypt.email must be set for Let's Encrypt certificate management")
			}
			if len(c.TLS.LetsEncrypt.Domains) == 0 {
				return errors.New("tls.letsencrypt.domains must be set for automatic certificate management")
			}
			switch c.TLS.LetsEncrypt.StorageProvider {
			case "s3":
				if c.TLS.LetsEncrypt.S3.Bucket == "" {
					return errors.New("tls.letsencrypt.s3.bucket must be set when storage_provider=s3")
				}
			case "file":
				if c.TLS.LetsEncrypt.CacheDir == "" {
					return errors.New("tls.letsencrypt.cache_dir must be set when storage_provider=file")
				}
			case "":
				return errors.New("tls.letsencrypt.storage_provider must be set (must be 's3' or 'file')")
			default:
				return fmt.Errorf("invalid tls.letsencrypt.storage_provider: %s (must be 's3' or 'file')", c.TLS.LetsEncrypt.StorageProvider)
			}
		case "":
			return errors.New("tls.provider must be set when tls.enabled=true (must be 'file' or 'letsencrypt')")
		default:
			return fmt.Errorf("invalid tls.provider: %s (must be 'file' or 'letsencrypt')", c.TLS.Provider)
		}
	}

	// Validate cluster configuration
	if c.Cluster.Enabled {
		bindAddr := c.Cluster.GetBindAddr()
		if bindAddr == "" {
			return errors.New("cluster.addr must be set when cluster.enabled=true")
		}
		// Prevent binding to 0.0.0.0 or localhost in production cluster mode
		if bindAddr == "0.0.0.0" || bindAddr == "::" {
			return errors.New("cluster.addr cannot be 0.0.0.0 or :: - must be a specific IP address for gossip protocol")
		}
		if bindAddr == "localhost" || bindAddr == "127.0.0.1" || bindAddr == "::1" {
			return errors.New("cluster.addr cannot be localhost/127.0.0.1/::1 - must be a routable IP address for gossip protocol")
		}

		bindPort := c.Cluster.GetBindPort()
		if bindPort < 1 || bindPort > 65535 {
			return fmt.Errorf("cluster bind port must be between 1 and 65535, got %d", bindPort)
		}
	}

	return nil
}

// Validate validates a single server configuration
// validateNonNegative rejects negative values for settings where 0 means
// "use the default". A negative number is not caught by those "== 0" default
// checks and then misbehaves at runtime: half_open_max_calls = -1 wedges the
// delivery circuit breaker in half-open, and a negative DNS timeout makes
// every lookup time out (which the sender-domain check treats as a pass).
func (c *Config) validateNonNegative() error {
	if c.DNS.TimeoutSeconds < 0 {
		return fmt.Errorf("dns.timeout_seconds must not be negative, got %d", c.DNS.TimeoutSeconds)
	}
	for i := range c.Servers {
		cb := c.Servers[i].Delivery.CircuitBreaker
		for name, v := range map[string]int{
			"failure_threshold":     cb.FailureThreshold,
			"success_threshold":     cb.SuccessThreshold,
			"timeout_seconds":       cb.TimeoutSeconds,
			"half_open_max_calls":   cb.HalfOpenMaxCalls,
			"reset_timeout_seconds": cb.ResetTimeoutSeconds,
		} {
			if v < 0 {
				return fmt.Errorf("server %q: delivery.circuit_breaker.%s must not be negative, got %d",
					c.Servers[i].Name, name, v)
			}
		}
	}
	return nil
}

func (s *ServerConfig) Validate() error {
	// Required fields
	if s.Name == "" {
		return errors.New("name is required")
	}
	if s.ListenAddr == "" {
		return errors.New("listen_addr is required")
	}

	// Validate server type
	if s.Type != "relay" && s.Type != "submission" {
		return fmt.Errorf("type must be 'relay' or 'submission', got '%s'", s.Type)
	}

	// Validate TLS mode
	if s.IsTLSEnabled() {
		if s.TLS.Mode != "starttls" && s.TLS.Mode != "implicit" {
			return fmt.Errorf("tls.mode must be 'starttls' or 'implicit', got '%s'", s.TLS.Mode)
		}
		if s.TLS.MinTLSVersion != "" && s.TLS.MinTLSVersion != "1.2" && s.TLS.MinTLSVersion != "1.3" {
			return fmt.Errorf("tls.min_tls_version must be '1.2' or '1.3', got '%s'", s.TLS.MinTLSVersion)
		}
		if s.TLS.MaxTLSVersion != "" && s.TLS.MaxTLSVersion != "1.2" && s.TLS.MaxTLSVersion != "1.3" {
			return fmt.Errorf("tls.max_tls_version must be '1.2' or '1.3', got '%s'", s.TLS.MaxTLSVersion)
		}
		if s.TLS.MinTLSVersion == "1.3" && s.TLS.MaxTLSVersion == "1.2" {
			return errors.New("tls.max_tls_version (1.2) cannot be lower than tls.min_tls_version (1.3)")
		}
	}

	// Submission servers must require auth
	if s.IsSubmission() && !s.Auth.Required {
		return errors.New("submission servers must have auth.required=true")
	}

	// Submission servers should use TLS
	if s.IsSubmission() && !s.IsTLSEnabled() {
		return errors.New("submission servers must use TLS - add [server.tls] section")
	}

	// Validate auth for submission servers
	if s.IsSubmission() && s.Auth.Required {
		if s.Auth.URL == "" {
			return errors.New("auth.url is required when auth.required=true")
		}
		// Enforce HTTPS for authentication endpoint (localhost may use http:// for development)
		if !strings.HasPrefix(s.Auth.URL, "https://") && !isLocalhostURL(s.Auth.URL) {
			return errors.New("auth.url must use https:// (HTTPS required for authentication, except for localhost)")
		}
	}

	// Validate Validation config
	if s.Validation.MissingHeadersAction != "" {
		if s.Validation.MissingHeadersAction != "reject" && s.Validation.MissingHeadersAction != "fix" && s.Validation.MissingHeadersAction != "none" {
			return fmt.Errorf("validation.missing_headers_action must be 'reject', 'fix', or 'none', got '%s'", s.Validation.MissingHeadersAction)
		}
	}

	// Parse IP whitelists once; the server backend reads the parsed networks
	// via the accessors, so a typo in any list fails startup instead of
	// silently never matching.
	var err error
	if s.DNSChecks.rdnsWhitelistNets, err = ParseIPList(s.DNSChecks.RDNSWhitelistIPs); err != nil {
		return fmt.Errorf("dns_checks.rdns_whitelist_ips: %w", err)
	}
	if s.Reputation.whitelistNets, err = ParseIPList(s.Reputation.WhitelistIPs); err != nil {
		return fmt.Errorf("reputation.whitelist_ips: %w", err)
	}

	// Validate Junk config
	if s.Junk.ApplyAction != "" {
		if s.Junk.ApplyAction != "header" && s.Junk.ApplyAction != "reject" && s.Junk.ApplyAction != "warn" && s.Junk.ApplyAction != "subject" {
			return fmt.Errorf("junk.apply_action must be 'header', 'reject', 'warn', or 'subject', got '%s'", s.Junk.ApplyAction)
		}
	}

	// Validate DMARC config
	if s.DMARCCheck {
		if s.DMARCRejectAction != "" && s.DMARCRejectAction != "none" && s.DMARCRejectAction != "reject" && s.DMARCRejectAction != "junk" {
			return fmt.Errorf("dmarc_reject_action must be 'none', 'reject', or 'junk', got '%s'", s.DMARCRejectAction)
		}
		if s.DMARCQuarantineAction != "" && s.DMARCQuarantineAction != "none" && s.DMARCQuarantineAction != "reject" && s.DMARCQuarantineAction != "junk" {
			return fmt.Errorf("dmarc_quarantine_action must be 'none', 'reject', or 'junk', got '%s'", s.DMARCQuarantineAction)
		}
	}

	// Port-specific validations
	if strings.HasSuffix(s.ListenAddr, ":465") && !s.UsesImplicitTLS() {
		return errors.New("port 465 should use tls.mode='implicit'")
	}
	if strings.HasSuffix(s.ListenAddr, ":587") && !s.UsesSTARTTLS() {
		return errors.New("port 587 should use tls.mode='starttls'")
	}
	if strings.HasSuffix(s.ListenAddr, ":25") && s.IsSubmission() {
		return errors.New("port 25 is typically for relay servers, not submission (use 465 or 587)")
	}

	// Validate PROXY protocol config
	if s.ProxyProtocol && len(s.ProxyProtocolTrusted) == 0 {
		return errors.New("proxy_protocol_trusted is required when proxy_protocol=true (specify trusted proxy CIDRs/IPs)")
	}
	if !s.ProxyProtocol && len(s.ProxyProtocolTrusted) > 0 {
		return errors.New("proxy_protocol_trusted is set but proxy_protocol is not enabled")
	}
	if s.proxyTrustedNets, err = ParseIPList(s.ProxyProtocolTrusted); err != nil {
		return fmt.Errorf("proxy_protocol_trusted: %w", err)
	}

	// Validate distributed tracking
	if s.Distributed.Enabled && s.Distributed.RecipientCacheTTLSeconds < 60 {
		return fmt.Errorf("distributed.recipient_cache_ttl_seconds must be >= 60 (1m), got %d", s.Distributed.RecipientCacheTTLSeconds)
	}

	// Validate sender validation config (HTTPS scheme is enforced in production
	// mode by Config.Validate, alongside delivery.url).
	if s.SenderValidation.Enabled {
		if s.SenderValidation.URL == "" {
			return errors.New("sender_validation.url is required when sender_validation.enabled=true")
		}
	}

	// Validate rate limiting config: an enabled limiter with no usable dimension
	// silently enforces nothing, which reads as "protected" but isn't.
	if s.RateLimit.Enabled {
		usable := 0
		for i, dim := range s.RateLimit.Dimensions {
			if len(dim.Keys) == 0 {
				return fmt.Errorf("rate_limit.dimensions[%d] (%q) must specify at least one key", i, dim.Name)
			}
			if dim.Limit > 0 {
				usable++
			}
		}
		if usable == 0 {
			return errors.New("rate_limit.enabled=true but no dimension has a positive limit - rate limiting would enforce nothing (set at least one dimension with limit > 0, or disable rate limiting)")
		}
	}

	// Validate inline rate-limit IP whitelist entries so typos fail fast at
	// startup. File-sourced entries are validated leniently at load/reload time
	// (bad lines are skipped and logged) so a running server survives a bad edit.
	if _, err := ParseIPList(s.RateLimit.WhitelistedIPs); err != nil {
		return fmt.Errorf("rate_limit.whitelisted_ips: %w", err)
	}

	// Validate recipient validation config (HTTPS scheme is enforced in
	// production mode by Config.Validate, alongside delivery.url).
	if s.RecipientValidation.Enabled {
		if s.RecipientValidation.URL == "" {
			return errors.New("recipient_validation.url is required when recipient_validation.enabled=true")
		}
		// Set defaults for optional fields
		if s.RecipientValidation.HTTPTimeoutSeconds == 0 {
			s.RecipientValidation.HTTPTimeoutSeconds = 5
		}
		if s.RecipientValidation.CacheTTLSeconds == 0 {
			s.RecipientValidation.CacheTTLSeconds = 300
		}
	}

	return nil
}

// validateClusterSecretKey checks that the gossip key is present and well
// formed. A secret key is mandatory: without it gossip runs unauthenticated and
// unencrypted, so any host that reaches the gossip port can join the cluster
// and inject rate-limit / connection-state / auth-block messages.
// (CLUSTER_SECRET_KEY env var is copied into SecretKey during load.)
func (c *Config) validateClusterSecretKey() error {
	if c.Cluster.SecretKey == "" {
		return errors.New("cluster.secret_key (or CLUSTER_SECRET_KEY env var) must be set when cluster.enabled=true - gossip must be authenticated and encrypted")
	}
	decoded, err := base64.StdEncoding.DecodeString(c.Cluster.SecretKey)
	if err != nil {
		return fmt.Errorf("cluster.secret_key must be base64-encoded: %w", err)
	}
	if len(decoded) != 32 {
		return fmt.Errorf("cluster.secret_key must decode to exactly 32 bytes (got %d) - generate with: openssl rand -base64 32", len(decoded))
	}
	return nil
}

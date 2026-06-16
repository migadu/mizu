package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

// Validate checks the configuration for required fields and placeholder values.
func (c *Config) Validate() error {
	// Check that at least one server is configured
	if len(c.Servers) == 0 {
		return errors.New("no [[server]] sections defined - at least one server is required")
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
		// Enforce HTTPS for authentication endpoint
		if !strings.HasPrefix(s.Auth.URL, "https://") {
			return errors.New("auth.url must use https:// (HTTPS required for authentication)")
		}
	}

	// Validate Validation config
	if s.Validation.MissingHeadersAction != "" {
		if s.Validation.MissingHeadersAction != "reject" && s.Validation.MissingHeadersAction != "fix" && s.Validation.MissingHeadersAction != "none" {
			return fmt.Errorf("validation.missing_headers_action must be 'reject', 'fix', or 'none', got '%s'", s.Validation.MissingHeadersAction)
		}
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
	for _, cidr := range s.ProxyProtocolTrusted {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			// Try as plain IP
			if net.ParseIP(cidr) == nil {
				return fmt.Errorf("proxy_protocol_trusted: invalid CIDR or IP %q", cidr)
			}
		}
	}

	// Validate distributed tracking
	if s.Distributed.Enabled && s.Distributed.RecipientCacheTTLSeconds < 60 {
		return fmt.Errorf("distributed.recipient_cache_ttl_seconds must be >= 60 (1m), got %d", s.Distributed.RecipientCacheTTLSeconds)
	}

	// Validate recipient validation config
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

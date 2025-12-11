package config

import (
	"errors"
	"fmt"
	"strings"
)

// Validate checks the configuration for required fields and placeholder values.
func (c *Config) Validate() error {
	// Check that at least one server is configured
	if len(c.Servers) == 0 {
		return errors.New("no [[server]] sections defined - at least one server is required")
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
		if c.Storage.AccessKeyID == "" || c.Storage.AccessKeyID == "your-s3-access-key-id" {
			return errors.New("storage.access_key_id must be set when using S3 backend")
		}
		if c.Storage.SecretAccessKey == "" || c.Storage.SecretAccessKey == "your-s3-secret-access-key" {
			return errors.New("storage.secret_access_key must be set when using S3 backend")
		}
		if c.Storage.Bucket == "" {
			return errors.New("storage.bucket must be set when using S3 backend")
		}
	case "filesystem":
		if c.Storage.FilesystemPath == "" {
			return errors.New("storage.filesystem_path must be set when using filesystem backend")
		}
	default:
		return fmt.Errorf("invalid storage backend: %s (must be 's3' or 'filesystem')", c.Storage.Backend)
	}

	if c.TLS.Email == "" || c.TLS.Email == "admin@example.com" {
		return errors.New("tls.email must be set for Let's Encrypt certificate management")
	}

	// Validate TLS domains
	if len(c.TLS.Domains) == 0 {
		return errors.New("tls.domains must be set for automatic certificate management")
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
	if s.DMARC.Enabled {
		if s.DMARC.RejectPolicyAction != "" && s.DMARC.RejectPolicyAction != "none" && s.DMARC.RejectPolicyAction != "reject" && s.DMARC.RejectPolicyAction != "junk" {
			return fmt.Errorf("dmarc.reject_policy_action must be 'none', 'reject', or 'junk', got '%s'", s.DMARC.RejectPolicyAction)
		}
		if s.DMARC.QuarantinePolicyAction != "" && s.DMARC.QuarantinePolicyAction != "none" && s.DMARC.QuarantinePolicyAction != "reject" && s.DMARC.QuarantinePolicyAction != "junk" {
			return fmt.Errorf("dmarc.quarantine_policy_action must be 'none', 'reject', or 'junk', got '%s'", s.DMARC.QuarantinePolicyAction)
		}
	}

	// DKIM validation is always enabled if DKIM.Enabled is true
	// No additional configuration validation needed

	// Validate ARC config
	if s.ARC.Enabled {
		if s.ARC.Mode != "" && s.ARC.Mode != "check" && s.ARC.Mode != "sign" {
			return fmt.Errorf("arc.mode must be 'check' or 'sign', got '%s'", s.ARC.Mode)
		}
		// If mode is sign, require signing parameters
		if s.ARC.Mode == "sign" {
			if s.ARC.Domain == "" {
				return errors.New("arc.domain is required when arc.mode='sign'")
			}
			if s.ARC.Selector == "" {
				return errors.New("arc.selector is required when arc.mode='sign'")
			}
			if s.ARC.PrivateKeyPath == "" {
				return errors.New("arc.private_key_path is required when arc.mode='sign'")
			}
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

package config

import (
	"errors"
	"fmt"
)

// Validate checks the configuration for required fields and placeholder values.
func (c *Config) Validate() error {
	// Validate retry attempts (prevent infinite loops and excessive delays)
	if c.Destination.MaxRetryAttempts > 5 {
		return fmt.Errorf("destination.max_retry_attempts must be <= 5 (got %d) to prevent excessive delays", c.Destination.MaxRetryAttempts)
	}
	if c.Destination.MaxRetryAttempts < 1 {
		return fmt.Errorf("destination.max_retry_attempts must be >= 1 (got %d)", c.Destination.MaxRetryAttempts)
	}

	// Validate HTTP timeout
	if c.Destination.HTTPTimeoutSeconds < 1 {
		return fmt.Errorf("destination.http_timeout_seconds must be >= 1 (got %d)", c.Destination.HTTPTimeoutSeconds)
	}
	if c.Destination.HTTPTimeoutSeconds > 300 {
		return fmt.Errorf("destination.http_timeout_seconds must be <= 300 (5m) (got %d) to prevent blocking SMTP sessions", c.Destination.HTTPTimeoutSeconds)
	}

	// Validate distributed tracking settings
	if c.SMTP.Distributed.Enabled {
		if !c.Cluster.Enabled {
			return errors.New("smtp.distributed.enabled requires cluster.enabled=true")
		}
		if c.SMTP.Distributed.RecipientCacheTTLSeconds < 60 {
			return fmt.Errorf("smtp.distributed.recipient_cache_ttl_seconds must be >= 60 (1m) (got %d)", c.SMTP.Distributed.RecipientCacheTTLSeconds)
		}
	}

	// Production mode validations
	if c.Local {
		return nil // In local mode, remaining checks are skipped.
	}

	if c.SMTP.Domain == "" || c.SMTP.Domain == "mail.example.com" {
		return errors.New("smtp.domain must be set")
	}
	if c.Destination.URL == "" {
		return errors.New("destination.url must be set")
	}
	if c.Destination.APIKey == "" || c.Destination.APIKey == "your-api-key-here" {
		return errors.New("destination.api_key must be set")
	}
	if c.S3.AccessKeyID == "" || c.S3.AccessKeyID == "your-s3-access-key-id" {
		return errors.New("s3.access_key_id must be set")
	}
	if c.S3.SecretAccessKey == "" || c.S3.SecretAccessKey == "your-s3-secret-access-key" {
		return errors.New("s3.secret_access_key must be set")
	}
	if c.TLS.Email == "" || c.TLS.Email == "admin@example.com" {
		return errors.New("tls.email must be set for Let's Encrypt certificate management")
	}

	// Validate autocert settings
	if c.TLS.EnableAutocert {
		if len(c.TLS.Domains) == 0 {
			return errors.New("tls.domains must be set when tls.enable_autocert=true")
		}
		if !c.Cluster.Enabled {
			return errors.New("tls.enable_autocert requires cluster.enabled=true for leader election")
		}
	}

	return nil
}

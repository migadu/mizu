package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Audit B12 (docs/security-audit-todo.md): Validate returned early in local
// mode, before the cluster block, while the server still started the cluster
// when cluster.enabled was set. A node run with --local therefore accepted
// unauthenticated, unencrypted gossip - block, unblock and rate-limit state
// from anyone who could reach the gossip port.
func TestAudit_LocalModeStillRequiresClusterSecretKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Local = true
	cfg.Servers = []ServerConfig{auditTestServer()}
	cfg.Cluster.Enabled = true
	cfg.Cluster.Addr = "192.0.2.10:7946"

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "secret_key") {
		t.Fatalf("local mode with cluster enabled and no secret key: Validate() = %v, want a secret_key error", err)
	}

	cfg.Cluster.SecretKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := cfg.Validate(); err != nil {
		t.Fatalf("local mode with a valid cluster key must validate: %v", err)
	}
}

// Local mode without clustering is the normal development setup and must keep
// working with no further configuration.
func TestAudit_LocalModeWithoutClusterNeedsNothing(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Local = true
	cfg.Servers = []ServerConfig{auditTestServer()}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("plain local mode must validate: %v", err)
	}
}

func auditTestServer() ServerConfig {
	return ServerConfig{
		Name:       "test-server",
		Type:       "relay",
		ListenAddr: ":2525",
		Hostname:   "test.example.com",
		Delivery: DeliveryConfig{
			URL:                "https://test.example.com",
			AuthToken:          "test-token",
			MaxRetryAttempts:   3,
			HTTPTimeoutSeconds: 30,
		},
	}
}

// C19: negative values were accepted where only "0 = default" and positive
// numbers make sense. half_open_max_calls = -1 slipped past the "== 0 means
// default" check and wedged the breaker in half-open for good (0 < -1 is never
// true); a negative dns.timeout_seconds made every MX lookup time out, which
// the sender-domain check treats as a pass.
func TestAudit_NegativeTimeoutsAndThresholdsAreRejected(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"half_open_max_calls":   func(c *Config) { c.Servers[0].Delivery.CircuitBreaker.HalfOpenMaxCalls = -1 },
		"failure_threshold":     func(c *Config) { c.Servers[0].Delivery.CircuitBreaker.FailureThreshold = -1 },
		"success_threshold":     func(c *Config) { c.Servers[0].Delivery.CircuitBreaker.SuccessThreshold = -1 },
		"breaker timeout":       func(c *Config) { c.Servers[0].Delivery.CircuitBreaker.TimeoutSeconds = -1 },
		"reset_timeout_seconds": func(c *Config) { c.Servers[0].Delivery.CircuitBreaker.ResetTimeoutSeconds = -1 },
		"dns.timeout_seconds":   func(c *Config) { c.DNS.TimeoutSeconds = -1 },
	} {
		cfg := DefaultConfig()
		cfg.Local = true
		cfg.Servers = []ServerConfig{auditTestServer()}
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s = -1 was accepted", name)
		}
	}
}

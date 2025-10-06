package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig_Defaults(t *testing.T) {
	// Test loading with no config file in local mode (to skip validation)
	cfg, err := LoadConfig([]string{"--local"})
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg == nil {
		t.Fatal("LoadConfig returned nil config")
	}

	// Verify some defaults
	if cfg.SMTP.ListenAddr != ":25" {
		t.Errorf("SMTP.ListenAddr = %s; want :25", cfg.SMTP.ListenAddr)
	}

	if cfg.SMTP.MaxMessageSize != 10<<20 {
		t.Errorf("SMTP.MaxMessageSize = %d; want %d", cfg.SMTP.MaxMessageSize, 10<<20)
	}

	if cfg.LogFormat != "text" {
		t.Errorf("LogFormat = %s; want text", cfg.LogFormat)
	}
}

func TestLoadConfig_LocalMode(t *testing.T) {
	cfg, err := LoadConfig([]string{"--local"})
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if !cfg.Local {
		t.Error("Local should be true")
	}

	// In local mode, validation should be relaxed
	if cfg.SMTP.Domain != "localhost" && cfg.SMTP.Domain != "mail.example.com" {
		t.Errorf("SMTP.Domain = %s; expected localhost or default in local mode", cfg.SMTP.Domain)
	}
}

func TestLoadConfig_Flags(t *testing.T) {
	cfg, err := LoadConfig([]string{
		"--smtp.listen", ":2525",
		"--smtp.domain", "test.example.com",
		"--smtp.max-message-size", "5242880",
		"--log-format", "json",
		"--local",
	})
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.SMTP.ListenAddr != ":2525" {
		t.Errorf("SMTP.ListenAddr = %s; want :2525", cfg.SMTP.ListenAddr)
	}

	if cfg.SMTP.Domain != "test.example.com" {
		t.Errorf("SMTP.Domain = %s; want test.example.com", cfg.SMTP.Domain)
	}

	if cfg.SMTP.MaxMessageSize != 5242880 {
		t.Errorf("SMTP.MaxMessageSize = %d; want 5242880", cfg.SMTP.MaxMessageSize)
	}

	if cfg.LogFormat != "json" {
		t.Errorf("LogFormat = %s; want json", cfg.LogFormat)
	}

	if !cfg.Local {
		t.Error("Local should be true")
	}
}

func TestLoadConfig_ConfigFile(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.toml")

	configContent := `
[smtp]
listen_addr = ":2525"
domain = "mail.test.com"
max_message_size = 5242880

[s3]
endpoint = "s3.amazonaws.com"
bucket = "test-bucket"
region = "us-west-2"

[destination]
url = "https://destination.example.com/email"
api_key = "test-api-key"

log_format = "json"
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := LoadConfig([]string{"--config", configPath, "--local"})
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.SMTP.ListenAddr != ":2525" {
		t.Errorf("SMTP.ListenAddr = %s; want :2525", cfg.SMTP.ListenAddr)
	}

	if cfg.SMTP.Domain != "mail.test.com" {
		t.Errorf("SMTP.Domain = %s; want mail.test.com", cfg.SMTP.Domain)
	}

	if cfg.S3.Bucket != "test-bucket" {
		t.Errorf("S3.Bucket = %s; want test-bucket", cfg.S3.Bucket)
	}

	if cfg.Destination.URL != "https://destination.example.com/email" {
		t.Errorf("Destination.URL = %s; want https://destination.example.com/email", cfg.Destination.URL)
	}

	// LogFormat from config file
	if cfg.LogFormat != "text" {
		t.Errorf("LogFormat = %s; want text", cfg.LogFormat)
	}
}

func TestLoadConfig_FlagOverridesFile(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.toml")

	configContent := `
[smtp]
listen_addr = ":2525"
domain = "mail.test.com"
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Flag should override config file
	cfg, err := LoadConfig([]string{
		"--config", configPath,
		"--smtp.listen", ":3535",
		"--local",
	})
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.SMTP.ListenAddr != ":3535" {
		t.Errorf("SMTP.ListenAddr = %s; want :3535 (flag should override file)", cfg.SMTP.ListenAddr)
	}

	if cfg.SMTP.Domain != "mail.test.com" {
		t.Errorf("SMTP.Domain = %s; want mail.test.com (from file)", cfg.SMTP.Domain)
	}
}

func TestLoadEnvVars(t *testing.T) {
	// Set environment variables
	os.Setenv("S3_ACCESS_KEY_ID", "test-access-key")
	os.Setenv("S3_SECRET_ACCESS_KEY", "test-secret-key")
	os.Setenv("S3_ENDPOINT", "test-endpoint")
	os.Setenv("DESTINATION_URL", "https://test-destination.com")
	os.Setenv("DESTINATION_API_KEY", "test-dest-key")

	defer func() {
		os.Unsetenv("S3_ACCESS_KEY_ID")
		os.Unsetenv("S3_SECRET_ACCESS_KEY")
		os.Unsetenv("S3_ENDPOINT")
		os.Unsetenv("DESTINATION_URL")
		os.Unsetenv("DESTINATION_API_KEY")
	}()

	defaultCfg := DefaultConfig()
	cfg := &defaultCfg
	loadEnvVars(cfg)

	if cfg.S3.AccessKeyID != "test-access-key" {
		t.Errorf("S3.AccessKeyID = %s; want test-access-key", cfg.S3.AccessKeyID)
	}

	if cfg.S3.SecretAccessKey != "test-secret-key" {
		t.Errorf("S3.SecretAccessKey = %s; want test-secret-key", cfg.S3.SecretAccessKey)
	}

	if cfg.S3.Endpoint != "test-endpoint" {
		t.Errorf("S3.Endpoint = %s; want test-endpoint", cfg.S3.Endpoint)
	}

	if cfg.Destination.URL != "https://test-destination.com" {
		t.Errorf("Destination.URL = %s; want https://test-destination.com", cfg.Destination.URL)
	}

	if cfg.Destination.APIKey != "test-dest-key" {
		t.Errorf("Destination.APIKey = %s; want test-dest-key", cfg.Destination.APIKey)
	}
}

func TestValidateConfig_LocalMode(t *testing.T) {
	defaultCfg := DefaultConfig()
	cfg := &defaultCfg
	cfg.Local = true

	err := validateConfig(cfg)
	if err != nil {
		t.Errorf("validateConfig should not fail in local mode: %v", err)
	}
}

func TestValidateConfig_ProductionMode(t *testing.T) {
	tests := []struct {
		name        string
		modifyFunc  func(*Config)
		expectError bool
		errorMsg    string
	}{
		{
			name: "missing SMTP domain",
			modifyFunc: func(c *Config) {
				c.SMTP.Domain = ""
			},
			expectError: true,
			errorMsg:    "SMTP domain must be configured",
		},
		{
			name: "missing S3 bucket",
			modifyFunc: func(c *Config) {
				c.SMTP.Domain = "mail.example.com"
				c.S3.Bucket = ""
			},
			expectError: true,
			errorMsg:    "S3 bucket must be configured",
		},
		{
			name: "missing S3 access key",
			modifyFunc: func(c *Config) {
				c.SMTP.Domain = "mail.example.com"
				c.S3.Bucket = "test-bucket"
				c.S3.AccessKeyID = ""
			},
			expectError: true,
			errorMsg:    "S3 access key ID must be configured",
		},
		{
			name: "missing S3 secret key",
			modifyFunc: func(c *Config) {
				c.SMTP.Domain = "mail.example.com"
				c.S3.Bucket = "test-bucket"
				c.S3.AccessKeyID = "test-key"
				c.S3.SecretAccessKey = ""
			},
			expectError: true,
			errorMsg:    "S3 secret access key must be configured",
		},
		{
			name: "missing destination URL",
			modifyFunc: func(c *Config) {
				c.SMTP.Domain = "mail.example.com"
				c.S3.Bucket = "test-bucket"
				c.S3.AccessKeyID = "test-key"
				c.S3.SecretAccessKey = "test-secret"
				c.Destination.URL = ""
			},
			expectError: true,
			errorMsg:    "destination URL must be configured",
		},
		{
			name: "missing destination API key",
			modifyFunc: func(c *Config) {
				c.SMTP.Domain = "mail.example.com"
				c.S3.Bucket = "test-bucket"
				c.S3.AccessKeyID = "test-key"
				c.S3.SecretAccessKey = "test-secret"
				c.Destination.URL = "https://test.com"
				c.Destination.APIKey = ""
			},
			expectError: true,
			errorMsg:    "destination API key must be configured",
		},
		{
			name: "valid production config",
			modifyFunc: func(c *Config) {
				c.SMTP.Domain = "mail.example.com"
				c.S3.Bucket = "test-bucket"
				c.S3.AccessKeyID = "test-key"
				c.S3.SecretAccessKey = "test-secret"
				c.Destination.URL = "https://test.com"
				c.Destination.APIKey = "test-api-key"
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defaultCfg := DefaultConfig()
			cfg := &defaultCfg
			cfg.Local = false
			tt.modifyFunc(cfg)

			err := validateConfig(cfg)

			if tt.expectError && err == nil {
				t.Errorf("expected error containing %q, got nil", tt.errorMsg)
			}

			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if tt.expectError && err != nil && tt.errorMsg != "" {
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("error = %q; want to contain %q", err.Error(), tt.errorMsg)
				}
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	defaultCfg := DefaultConfig()
	cfg := &defaultCfg

	// Verify defaults
	if cfg.SMTP.ListenAddr != ":25" {
		t.Errorf("SMTP.ListenAddr = %s; want :25", cfg.SMTP.ListenAddr)
	}

	if cfg.SMTP.Domain != "mail.example.com" {
		t.Errorf("SMTP.Domain = %s; want mail.example.com", cfg.SMTP.Domain)
	}

	if cfg.SMTP.MaxMessageSize != 10<<20 {
		t.Errorf("SMTP.MaxMessageSize = %d; want %d", cfg.SMTP.MaxMessageSize, 10<<20)
	}

	if cfg.SMTP.TimeoutSeconds != 10 {
		t.Errorf("SMTP.TimeoutSeconds = %v; want 10s", cfg.SMTP.TimeoutSeconds)
	}

	if cfg.SMTP.MinTLSVersion != "1.2" {
		t.Errorf("SMTP.MinTLSVersion = %s; want 1.2", cfg.SMTP.MinTLSVersion)
	}

	if cfg.S3.Endpoint != "s3.amazonaws.com" {
		t.Errorf("S3.Endpoint = %s; want s3.amazonaws.com", cfg.S3.Endpoint)
	}

	if cfg.S3.Region != "us-east-1" {
		t.Errorf("S3.Region = %s; want us-east-1", cfg.S3.Region)
	}

	if cfg.Destination.MaxRetryAttempts != 3 {
		t.Errorf("Destination.MaxRetryAttempts = %d; want 3", cfg.Destination.MaxRetryAttempts)
	}

	if !cfg.Blacklists.Enabled {
		t.Error("Blacklists.Enabled should be true by default")
	}

	if len(cfg.Blacklists.Lists) != 1 || cfg.Blacklists.Lists[0] != "zen.spamhaus.org" {
		t.Errorf("Blacklists.Lists = %v; want [zen.spamhaus.org]", cfg.Blacklists.Lists)
	}

	if cfg.Blacklists.TimeoutSeconds != 3 {
		t.Errorf("Blacklists.TimeoutSeconds = %v; want 3s", cfg.Blacklists.TimeoutSeconds)
	}

	if !cfg.Stats.Enabled {
		t.Error("Stats.Enabled should be true by default")
	}

	if cfg.Stats.RetentionSeconds != 86400 {
		t.Errorf("Stats.RetentionSeconds = %v; want 24h", cfg.Stats.RetentionSeconds)
	}

	if cfg.LogFormat != "text" {
		t.Errorf("LogFormat = %s; want text", cfg.LogFormat)
	}

	if cfg.Local {
		t.Error("Local should be false by default")
	}
}

func TestSaveExample(t *testing.T) {
	tmpDir := t.TempDir()
	examplePath := filepath.Join(tmpDir, "config.toml.example")

	err := SaveExample(examplePath)
	if err != nil {
		t.Fatalf("SaveExample failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(examplePath); os.IsNotExist(err) {
		t.Error("example config file was not created")
	}

	// Verify file can be loaded
	data, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatalf("failed to read example file: %v", err)
	}

	if len(data) == 0 {
		t.Error("example file is empty")
	}

	// Verify it contains expected sections
	content := string(data)
	expectedSections := []string{"[smtp]", "[s3]", "[destination]", "[tls]", "[blacklists]", "[stats]"}
	for _, section := range expectedSections {
		if !contains(content, section) {
			t.Errorf("example file missing section: %s", section)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || contains(s[1:], substr)))
}

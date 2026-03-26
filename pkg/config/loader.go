package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/spf13/pflag"
)

func defaultConfigPath() string {
	for _, p := range []string{
		"/etc/mizu/config.toml",
		"/usr/local/etc/mizu/config.toml",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "config.toml"
}

// LoadConfig loads configuration from file and command line flags
func LoadConfig(args []string) (*Config, error) {
	// Start with default configuration
	defaultCfg := DefaultConfig()
	cfg := &defaultCfg

	// Define command line flags
	fs := pflag.NewFlagSet("mizu-server", pflag.ContinueOnError)

	// Config file flag
	configFile := fs.StringP("config", "c", defaultConfigPath(), "Path to configuration file")

	// Local development mode flag
	fs.BoolVar(&cfg.Local, "local", false, "Run in local development mode (no TLS, dump emails to terminal)")

	// Log format flag
	fs.StringVar(&cfg.Logging.Format, "log-format", "console", "Log format: console or json")

	// Parse command line flags
	if err := fs.Parse(args); err != nil {
		return nil, fmt.Errorf("failed to parse flags: %w", err)
	}

	// Load configuration from file if it exists
	if *configFile != "" {
		if _, err := os.Stat(*configFile); err == nil {
			if _, err := toml.DecodeFile(*configFile, cfg); err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to stat config file: %w", err)
		}
		// If file doesn't exist, just use defaults (no error)
	}

	// Override with environment variables
	applyEnvironmentVariables(cfg)

	return cfg, nil
}

// applyEnvironmentVariables overrides configuration with environment variables
func applyEnvironmentVariables(cfg *Config) {
	// Storage credentials
	if val := os.Getenv("S3_ACCESS_KEY"); val != "" {
		cfg.Storage.S3AccessKey = val
	}
	if val := os.Getenv("S3_SECRET_KEY"); val != "" {
		cfg.Storage.S3SecretKey = val
	}

	// Delivery credentials (apply to all servers)
	if val := os.Getenv("DESTINATION_AUTH_TOKEN"); val != "" {
		for i := range cfg.Servers {
			if cfg.Servers[i].Delivery.AuthToken == "" || cfg.Servers[i].Delivery.AuthToken == "your-auth-token-here" {
				cfg.Servers[i].Delivery.AuthToken = val
			}
		}
	}
	if val := os.Getenv("DELIVERY_AUTH_TOKEN"); val != "" {
		for i := range cfg.Servers {
			if cfg.Servers[i].Delivery.AuthToken == "" || cfg.Servers[i].Delivery.AuthToken == "your-auth-token-here" {
				cfg.Servers[i].Delivery.AuthToken = val
			}
		}
	}

	// Health check credentials
	if val := os.Getenv("HEALTH_PASSWORD"); val != "" {
		cfg.Health.Password = val
	}

	// Cluster encryption key
	if val := os.Getenv("CLUSTER_SECRET_KEY"); val != "" {
		cfg.Cluster.SecretKey = val
	}

	// Apply auth token to all submission servers
	if val := os.Getenv("AUTH_TOKEN"); val != "" {
		for i := range cfg.Servers {
			if cfg.Servers[i].IsSubmission() && cfg.Servers[i].Auth.AuthToken == "" {
				cfg.Servers[i].Auth.AuthToken = val
			}
		}
	}
}

// SaveExample saves an example configuration file
func SaveExample(filename string) error {
	exampleConfig := DefaultConfig()

	// Create example config with comments
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := toml.NewEncoder(f)
	encoder.Indent = ""

	// Write example configuration
	if err := encoder.Encode(exampleConfig); err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}

	return nil
}

// LoadFromFile loads configuration from a specific file path
func LoadFromFile(filename string) (*Config, error) {
	cfg := DefaultConfig()

	if _, err := toml.DecodeFile(filename, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file '%s': %w", filename, err)
	}

	// Apply environment variable overrides
	applyEnvironmentVariables(&cfg)

	return &cfg, nil
}

// GetConfigPath returns the configuration file path, checking common locations
func GetConfigPath() (string, error) {
	// Check in order: /usr/local/etc/mizu, current directory, /etc/mizu, ~/.config/mizu
	locations := []string{
		"/usr/local/etc/mizu/config.toml",
		"config.toml",
		"/etc/mizu/config.toml",
		filepath.Join(os.Getenv("HOME"), ".config", "mizu", "config.toml"),
	}

	for _, path := range locations {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("config file not found in standard locations")
}

package tls

import (
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"migadu/mizu/pkg/storage"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Manager handles automatic TLS certificate management using Let's Encrypt
type Manager struct {
	autocertManager *autocert.Manager
	logger          *slog.Logger
	stopCertSync    chan struct{} // Signal to stop certificate sync worker
	tlsConfig       *tls.Config   // Cached TLS config with wrapped GetCertificate
	isLeaderF       func() bool   // Cluster leader check function
}

// Config holds configuration for TLS manager
type Config struct {
	Enabled        bool
	Email          string
	Domains        []string
	DefaultDomain  string          // Default domain for SNI-less connections
	StorageBackend storage.Backend // Storage backend for certificates (S3 or filesystem)
	StoragePrefix  string          // Prefix for certificate storage
	IsLeaderF      func() bool     // Cluster leader function
	Staging        bool            // Use Let's Encrypt staging environment
	RenewBefore    time.Duration   // How long before expiry to renew (0 = default 30 days)
	FallbackDir    string          // Local fallback directory for certificates (empty = no fallback)
	SyncInterval   time.Duration   // How often to sync certificates (0 = no sync)
}

// NewManager creates a new TLS manager with autocert and storage backend
// Returns nil if TLS is not enabled or cluster/leader function is not available
func NewManager(cfg Config, logger *slog.Logger) (*Manager, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// Require cluster leader function for distributed coordination
	if cfg.IsLeaderF == nil {
		logger.Warn("TLS manager disabled: no cluster leader function provided")
		return nil, nil
	}

	// Require at least one domain
	if len(cfg.Domains) == 0 {
		logger.Warn("TLS manager disabled: no domains configured")
		return nil, nil
	}

	// Require storage backend
	if cfg.StorageBackend == nil {
		return nil, fmt.Errorf("storage backend is required for TLS manager")
	}

	// Create storage-backed cache
	storageCache, err := NewStorageCache(cfg.StorageBackend, cfg.StoragePrefix, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage cache: %w", err)
	}

	// Wrap storage cache with cluster-aware wrapper
	var cache autocert.Cache = NewClusterAwareCache(storageCache, cfg.IsLeaderF, logger)
	logger.Info("Cluster-aware certificate cache enabled - only leader can request certificates")

	// Optionally wrap with fallback cache if directory is provided
	if cfg.FallbackDir != "" {
		var err error
		cache, err = NewFallbackCache(cache, cfg.FallbackDir, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize fallback cache: %w", err)
		}
	} else {
		logger.Info("Certificate fallback cache disabled - using S3 only")
	}

	// Determine default domain for SNI-less connections
	defaultDomain := cfg.DefaultDomain
	if defaultDomain == "" && len(cfg.Domains) > 0 {
		// If not specified, use the first configured domain
		defaultDomain = cfg.Domains[0]
	}

	// Create autocert manager
	autocertMgr := &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		Email:       cfg.Email,
		HostPolicy:  autocert.HostWhitelist(cfg.Domains...),
		Cache:       cache,
		RenewBefore: cfg.RenewBefore, // 0 = default 30 days
		Client: &acme.Client{
			DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
		},
	}

	// Use staging environment for testing
	if cfg.Staging {
		autocertMgr.Client = &acme.Client{
			DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		}
		logger.Info("TLS manager using Let's Encrypt staging environment")
	}

	// Force HTTP-01 only by calling HTTPHandler, which sets tryHTTP01=true
	// on the autocert manager. We do NOT use autocertMgr.TLSConfig() because
	// that registers TLS-ALPN-01 support, which requires port 443 — Mizu
	// listens on port 465 (SMTP), so ALPN challenges can't be fulfilled.
	autocertMgr.HTTPHandler(nil)

	m := &Manager{
		autocertManager: autocertMgr,
		logger:          logger,
		stopCertSync:    make(chan struct{}),
		tlsConfig:       nil, // Will be set below after wrapping GetCertificate
		isLeaderF:       cfg.IsLeaderF,
	}

	// Build TLS config manually (not via autocertMgr.TLSConfig which adds ALPN)
	originalGetCert := autocertMgr.GetCertificate
	wrappedGetCert := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		serverName := hello.ServerName

		// Handle missing SNI by using default domain
		if serverName == "" {
			if defaultDomain != "" {
				logger.Debug("TLS: Missing SNI - using default domain", "domain", defaultDomain)
				serverName = defaultDomain
			} else {
				logger.Debug("TLS: Rejected certificate request - missing SNI and no default domain")
				return nil, ErrMissingServerName
			}
		}

		// Normalize server name to lowercase for case-insensitive comparison
		// RFC 4343: DNS names are case-insensitive
		serverName = strings.ToLower(serverName)

		// Check if the server name matches our configured domains using the HostPolicy
		if err := autocertMgr.HostPolicy(nil, serverName); err != nil {
			logger.Debug("TLS: Rejected certificate request for unconfigured domain", "domain", serverName, "error", err)
			return nil, fmt.Errorf("%w: %s", ErrHostNotAllowed, serverName)
		}

		// Log ClientHello details for TLS handshake diagnostics
		logger.Info("TLS: Certificate request during handshake",
			"domain", serverName,
			"has_sni", hello.ServerName != "",
			"tls_versions", formatSupportedVersions(hello.SupportedVersions),
			"alpn_protocols", hello.SupportedProtos,
			"cipher_suites_count", len(hello.CipherSuites),
			"server_name_raw", hello.ServerName)

		// Create a modified ClientHelloInfo with the resolved server name
		modifiedHello := *hello
		modifiedHello.ServerName = serverName

		cert, err := originalGetCert(&modifiedHello)
		if err != nil {
			// Certificate retrieval failures are often transient (S3 down, ACME rate limits, network issues)
			// Wrap as ErrCertificateUnavailable so the server logs but doesn't crash
			// This allows the server to continue serving cached certificates for other domains
			logger.Error("TLS: Failed to get certificate",
				"server_name", serverName,
				"error", err,
				"error_type", fmt.Sprintf("%T", err))
			return nil, fmt.Errorf("%w for %s: %v", ErrCertificateUnavailable, serverName, err)
		}

		// Log certificate chain details for diagnostics
		if cert != nil {
			chainLen := len(cert.Certificate)
			keyType := fmt.Sprintf("%T", cert.PrivateKey) // e.g. *ecdsa.PrivateKey, *rsa.PrivateKey
			leafSize := 0
			if chainLen > 0 {
				leafSize = len(cert.Certificate[0])
			}
			logger.Info("TLS: Certificate provided successfully",
				"domain", serverName,
				"chain_length", chainLen,
				"has_leaf", chainLen > 0,
				"has_intermediates", chainLen > 1,
				"key_type", keyType,
				"leaf_der_bytes", leafSize)
			if chainLen <= 1 {
				logger.Warn("TLS: Certificate chain may be incomplete - no intermediate certificates",
					"domain", serverName,
					"chain_length", chainLen,
					"hint", "Outlook/Exchange Online requires full chain (leaf + intermediate)")
			}
		} else {
			logger.Info("TLS: Certificate provided successfully", "domain", serverName)
		}
		return cert, nil
	}

	logger.Info("TLS manager initialized with autocert",
		"domains", cfg.Domains,
		"email", cfg.Email,
		"staging", cfg.Staging)

	if defaultDomain != "" {
		logger.Info("Default domain for SNI-less connections", "domain", defaultDomain)
	}

	logger.Info("Certificates will be stored using storage backend", "prefix", cfg.StoragePrefix)

	// Store the manually-built TLS config (HTTP-01 only, no ALPN)
	m.tlsConfig = &tls.Config{
		GetCertificate: wrappedGetCert,
		MinVersion:     tls.VersionTLS12,
	}

	// Start certificate sync worker if configured
	if cfg.SyncInterval > 0 {
		m.startCertificateSyncWorker(cfg.SyncInterval)
	}

	return m, nil
}

// TLSConfig returns the TLS configuration for use with HTTP/SMTP servers
// Returns the cached config with our wrapped GetCertificate function
func (m *Manager) TLSConfig() *tls.Config {
	if m == nil {
		return nil
	}
	if m.tlsConfig != nil {
		m.logger.Debug("TLSConfig retrieved (using cached wrapped config)",
			"has_get_certificate", m.tlsConfig.GetCertificate != nil)
	}
	return m.tlsConfig
}

// HTTPHandler returns the HTTP handler for ACME HTTP-01 challenges
// This should be registered at /.well-known/acme-challenge/
//
// In cluster mode, all nodes run this handler on port 80. Here's how it works:
// 1. Leader node requests certificate from Let's Encrypt
// 2. autocert stores challenge token in cache (S3)
// 3. Let's Encrypt makes HTTP request to domain (may hit any node via load balancer)
// 4. Any node can respond because challenge token is in shared S3 cache
// 5. autocert.HTTPHandler reads token from cache and responds correctly
func (m *Manager) HTTPHandler() http.Handler {
	if m == nil || m.autocertManager == nil {
		return nil
	}
	return m.autocertManager.HTTPHandler(nil)
}

// GetCertificate can be used directly in tls.Config.GetCertificate
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m == nil || m.autocertManager == nil {
		return nil, nil
	}
	return m.autocertManager.GetCertificate(hello)
}

// GetAutocertManager returns the underlying autocert.Manager
func (m *Manager) GetAutocertManager() *autocert.Manager {
	return m.autocertManager
}

package tls

import (
	"crypto/tls"
	"net/http"

	"github.com/minio/minio-go/v7"
	"go.uber.org/zap"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"migadu/mizu/pkg/storage"
)

// Manager handles automatic TLS certificate management using Let's Encrypt
type Manager struct {
	autocertManager *autocert.Manager
	logger          *zap.Logger
}

// Config holds configuration for TLS manager
type Config struct {
	Enabled   bool
	Email     string
	Domains   []string
	S3Client  *minio.Client
	S3Bucket  string
	S3Prefix  string
	IsLeaderF func() bool
	Staging   bool // Use Let's Encrypt staging environment
}

// NewManager creates a new TLS manager with autocert and S3 storage
// Returns nil if TLS is not enabled or cluster/leader function is not available
func NewManager(cfg Config, logger *zap.Logger) (*Manager, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	if logger == nil {
		logger = zap.NewNop()
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

	// Create S3 cache with leader-only writes
	s3Cache := storage.NewAutocertS3Cache(cfg.S3Client, cfg.S3Bucket, cfg.S3Prefix, cfg.IsLeaderF, logger)

	// Configure autocert with S3 cache
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.Domains...),
		Cache:      s3Cache,
		Email:      cfg.Email,
	}

	// Use staging environment for testing
	if cfg.Staging {
		m.Client = &acme.Client{
			DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		}
		logger.Info("TLS manager using Let's Encrypt staging environment")
	}

	logger.Info("TLS manager initialized with autocert",
		zap.Strings("domains", cfg.Domains),
		zap.String("email", cfg.Email),
		zap.Bool("staging", cfg.Staging))

	return &Manager{
		autocertManager: m,
		logger:          logger,
	}, nil
}

// TLSConfig returns the TLS configuration for use with HTTP/SMTP servers
func (m *Manager) TLSConfig() *tls.Config {
	if m == nil || m.autocertManager == nil {
		return nil
	}
	return m.autocertManager.TLSConfig()
}

// HTTPHandler returns the HTTP handler for ACME HTTP-01 challenges
// This should be registered at /.well-known/acme-challenge/
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

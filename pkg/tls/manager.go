package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"golang.org/x/crypto/acme/autocert"
)

// Config configures the TLS certificate manager.
type Config struct {
	Enabled     bool
	Provider    string // must be "letsencrypt" — anything else returns (nil, nil)
	LetsEncrypt LetsEncryptConfig
}

// LetsEncryptConfig configures Let's Encrypt certificate provisioning.
type LetsEncryptConfig struct {
	Email               string
	Domains             []string
	DefaultDomain       string
	StorageProvider     string // "s3" or "file"
	CacheDir            string // local cache dir (file mode) or fallback dir (s3 mode)
	SyncIntervalMinutes int    // periodic local→S3 sync interval (default 5)
	S3                  S3Config
}

// S3Config holds the S3 credentials and bucket info for certificate storage.
type S3Config struct {
	Bucket    string
	Region    string
	Endpoint  string // custom endpoint (Backblaze B2, MinIO, etc.); empty = AWS default
	Prefix    string
	AccessKey string
	SecretKey string
}

// Manager orchestrates TLS certificate management using Let's Encrypt.
type Manager struct {
	autocertManager *autocert.Manager
	logger          *slog.Logger
	domains         []string
	defaultDomain   string
	syncWorker      *CertSyncWorker
	tlsConfig       *tls.Config
	isLeaderF       func() bool
}

// NewManager creates a new TLS manager.
// If isLeaderF is provided and non-nil, only the cluster leader is allowed to
// request new certificates from Let's Encrypt.
func NewManager(ctx context.Context, cfg *Config, logger *slog.Logger, isLeaderF ...func() bool) (*Manager, error) {
	if !cfg.Enabled || cfg.Provider != "letsencrypt" {
		return nil, nil
	}

	var cache autocert.Cache
	var syncWorker *CertSyncWorker

	switch cfg.LetsEncrypt.StorageProvider {
	case "s3":
		s3Cache, err := createS3Cache(ctx, cfg.LetsEncrypt, logger)
		if err != nil {
			return nil, err
		}

		cacheDir := cfg.LetsEncrypt.CacheDir
		if cacheDir == "" {
			cacheDir = "cert-cache"
		}
		fallbackCache := NewFallbackCache(cacheDir, s3Cache, logger)
		cache = fallbackCache

		syncInterval := time.Duration(cfg.LetsEncrypt.SyncIntervalMinutes) * time.Minute
		if syncInterval == 0 {
			syncInterval = 5 * time.Minute
		}
		syncWorker = NewCertSyncWorker(fallbackCache, syncInterval, logger)
		syncWorker.Start()

		prefixInfo := cfg.LetsEncrypt.S3.Prefix
		if prefixInfo == "" {
			prefixInfo = "(none - bucket root)"
		}
		logger.Info("using hybrid file+S3 certificate cache with periodic sync",
			"local_cache_dir", cacheDir,
			"s3_bucket", cfg.LetsEncrypt.S3.Bucket,
			"s3_prefix", prefixInfo,
			"sync_interval", syncInterval)

	case "file":
		cache = autocert.DirCache(cfg.LetsEncrypt.CacheDir)
		logger.Info("using file-based certificate cache",
			"cache_dir", cfg.LetsEncrypt.CacheDir)

	default:
		return nil, fmt.Errorf("unsupported storage provider: %s", cfg.LetsEncrypt.StorageProvider)
	}

	var leaderFunc func() bool
	if len(isLeaderF) > 0 && isLeaderF[0] != nil {
		leaderFunc = isLeaderF[0]
		cache = NewClusterAwareCache(cache, leaderFunc, logger)
		logger.Info("TLS certificate cache wrapped with cluster-aware leader gating")
	} else {
		logger.Info("TLS running in single-instance mode (no cluster leader election)")
	}

	autocertMgr := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.LetsEncrypt.Domains...),
		Cache:      cache,
		Email:      cfg.LetsEncrypt.Email,
	}

	defaultDomain := cfg.LetsEncrypt.DefaultDomain
	if defaultDomain == "" && len(cfg.LetsEncrypt.Domains) > 0 {
		defaultDomain = cfg.LetsEncrypt.Domains[0]
	}

	baseTLSConfig := autocertMgr.TLSConfig()

	m := &Manager{
		autocertManager: autocertMgr,
		logger:          logger,
		domains:         cfg.LetsEncrypt.Domains,
		defaultDomain:   defaultDomain,
		syncWorker:      syncWorker,
		tlsConfig:       nil,
		isLeaderF:       leaderFunc,
	}

	originalGetCert := baseTLSConfig.GetCertificate
	baseTLSConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		serverName := hello.ServerName

		if serverName == "" {
			if defaultDomain != "" {
				logger.Debug("TLS: missing SNI - using default domain", "domain", defaultDomain)
				serverName = defaultDomain
			} else {
				logger.Debug("TLS: rejected certificate request - missing SNI and no default domain")
				return nil, ErrMissingServerName
			}
		}

		// RFC 4343: DNS names are case-insensitive.
		serverName = strings.ToLower(serverName)

		// Let's Encrypt doesn't issue certificates for IP addresses.
		if isIPAddress(serverName) {
			logger.Debug("TLS: rejected certificate request for IP address (Let's Encrypt requires domain names)",
				"ip", serverName,
				"remote_addr", hello.Conn.RemoteAddr().String())
			return nil, fmt.Errorf("%w: IP addresses not supported (use domain name)", ErrHostNotAllowed)
		}

		if err := autocertMgr.HostPolicy(nil, serverName); err != nil {
			logger.Debug("TLS: rejected certificate request for unconfigured domain",
				"domain", serverName,
				"remote_addr", hello.Conn.RemoteAddr().String(),
				"error", err)
			return nil, fmt.Errorf("%w: %s", ErrHostNotAllowed, serverName)
		}

		logger.Debug("TLS: certificate request during handshake", "domain", serverName, "has_sni", hello.ServerName != "")

		modifiedHello := *hello
		modifiedHello.ServerName = serverName

		cert, err := originalGetCert(&modifiedHello)
		if err != nil {
			logger.Error("TLS: failed to get certificate",
				"server_name", serverName,
				"error", err,
				"error_type", fmt.Sprintf("%T", err))
			return nil, fmt.Errorf("%w for %s: %v", ErrCertificateUnavailable, serverName, err)
		}
		logger.Debug("TLS: certificate provided successfully", "domain", serverName)
		return cert, nil
	}

	m.tlsConfig = baseTLSConfig

	logger.Info("TLS manager initialized",
		"domains", cfg.LetsEncrypt.Domains,
		"email", cfg.LetsEncrypt.Email,
		"storage", cfg.LetsEncrypt.StorageProvider,
		"default_domain", defaultDomain)

	return m, nil
}

// TLSConfig returns the TLS configuration for use with HTTP/SMTP servers.
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

// HTTPHandler returns an HTTP handler for ACME HTTP-01 challenges. Register at
// /.well-known/acme-challenge/ on the server's port 80 endpoint.
func (m *Manager) HTTPHandler() http.Handler {
	if m == nil || m.autocertManager == nil {
		return nil
	}
	return m.autocertManager.HTTPHandler(nil)
}

// CertificateInfo contains information about a TLS certificate.
type CertificateInfo struct {
	Domain          string
	NotBefore       time.Time
	NotAfter        time.Time
	DaysUntilExpiry int
	IsExpired       bool
	Error           error
}

// GetCertificateInfo retrieves certificate information for a domain.
func (m *Manager) GetCertificateInfo(domain string) CertificateInfo {
	info := CertificateInfo{
		Domain: domain,
	}

	if m == nil || m.autocertManager == nil {
		info.Error = fmt.Errorf("TLS manager not initialized")
		return info
	}

	hello := &tls.ClientHelloInfo{
		ServerName: domain,
	}

	cert, err := m.autocertManager.GetCertificate(hello)
	if err != nil {
		info.Error = fmt.Errorf("failed to get certificate: %w", err)
		return info
	}

	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			info.Error = fmt.Errorf("failed to parse certificate: %w", err)
			return info
		}
		cert.Leaf = leaf
	}

	if cert.Leaf != nil {
		info.NotBefore = cert.Leaf.NotBefore
		info.NotAfter = cert.Leaf.NotAfter
		info.DaysUntilExpiry = int(time.Until(cert.Leaf.NotAfter).Hours() / 24)
		info.IsExpired = time.Now().After(cert.Leaf.NotAfter)
	}

	return info
}

// CheckCertificates checks all configured domains and logs their status.
func (m *Manager) CheckCertificates() {
	if m == nil || m.autocertManager == nil {
		return
	}

	m.logger.Info("checking certificate status for all domains")

	for _, domain := range m.domains {
		info := m.GetCertificateInfo(domain)

		if info.Error != nil {
			m.logger.Warn("certificate check failed",
				"domain", domain,
				"error", info.Error)
			continue
		}

		if info.IsExpired {
			m.logger.Error("certificate EXPIRED",
				"domain", domain,
				"expired_at", info.NotAfter)
		} else if info.DaysUntilExpiry <= 30 {
			m.logger.Info("certificate expiring soon",
				"domain", domain,
				"days_remaining", info.DaysUntilExpiry)
		}
	}
}

// RenewCertificate deletes the cached certificate for a domain so the next
// TLS handshake triggers a fresh ACME request. Must run on the cluster leader.
func (m *Manager) RenewCertificate(domain string) ([]string, error) {
	if m == nil || m.autocertManager == nil {
		return nil, fmt.Errorf("TLS manager not initialized")
	}

	if m.isLeaderF != nil && !m.isLeaderF() {
		return nil, fmt.Errorf("certificate renewal must be performed on the cluster leader node")
	}

	cache := m.autocertManager.Cache
	if cache == nil {
		return nil, fmt.Errorf("no certificate cache configured")
	}

	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	ctx := context.Background()
	if err := m.autocertManager.HostPolicy(ctx, domain); err != nil {
		return nil, fmt.Errorf("domain %q not in allowed list: %w", domain, err)
	}

	m.logger.Info("deleting cached certificate", "domain", domain)
	if err := cache.Delete(ctx, domain); err != nil {
		m.logger.Warn("failed to delete cached certificate (may not exist yet)", "domain", domain, "error", err)
	}
	_ = cache.Delete(ctx, domain+"+rsa")
	_ = cache.Delete(ctx, domain+"+ecdsa")

	m.logger.Info("certificate cache cleared — next TLS handshake will trigger fresh ACME request", "domain", domain)
	return []string{domain}, nil
}

// Stop gracefully shuts down the TLS manager and its sync worker.
func (m *Manager) Stop() {
	if m == nil {
		return
	}

	if m.syncWorker != nil {
		m.logger.Info("stopping certificate sync worker")
		m.syncWorker.Stop(10 * time.Second)
	}
}

func createS3Cache(ctx context.Context, cfg LetsEncryptConfig, logger *slog.Logger) (*S3Cache, error) {
	initCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	awsCfg, err := awsconfig.LoadDefaultConfig(initCtx,
		awsconfig.WithRetryer(func() aws.Retryer {
			return retry.NewStandard(func(o *retry.StandardOptions) {
				o.MaxAttempts = 3
				o.MaxBackoff = 5 * time.Second
			})
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	if cfg.S3.Region != "" {
		awsCfg.Region = cfg.S3.Region
	}

	if cfg.S3.AccessKey != "" && cfg.S3.SecretKey != "" {
		awsCfg.Credentials = credentials.NewStaticCredentialsProvider(
			cfg.S3.AccessKey,
			cfg.S3.SecretKey,
			"",
		)
	}

	var s3Client *s3.Client
	if cfg.S3.Endpoint != "" {
		s3Client = s3.NewFromConfig(awsCfg, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.S3.Endpoint)
			o.UsePathStyle = true
		})
		logger.Info("using custom S3 endpoint", "endpoint", cfg.S3.Endpoint)
	} else {
		s3Client = s3.NewFromConfig(awsCfg)
	}

	logger.Info("validating S3 bucket access", "bucket", cfg.S3.Bucket)

	// Retry S3 HeadBucket with exponential backoff to handle DNS startup race conditions.
	maxRetries := 5

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second // 1s, 2s, 4s, 8s
			logger.Info("retrying S3 bucket validation after backoff",
				"attempt", attempt+1,
				"max_retries", maxRetries,
				"backoff", backoff)

			select {
			case <-time.After(backoff):
			case <-initCtx.Done():
				return nil, fmt.Errorf("S3 bucket validation cancelled during retry backoff: %w", initCtx.Err())
			}
		}

		_, err = s3Client.HeadBucket(initCtx, &s3.HeadBucketInput{
			Bucket: &cfg.S3.Bucket,
		})
		if err == nil {
			break
		}

		logger.Warn("S3 bucket validation failed",
			"attempt", attempt+1,
			"max_retries", maxRetries,
			"error", err)
	}

	if err != nil {
		return nil, fmt.Errorf("S3 bucket validation failed after %d attempts: %w", maxRetries, err)
	}

	logger.Info("S3 bucket validated successfully", "bucket", cfg.S3.Bucket)

	s3Cache := &S3Cache{
		S3Client: s3Client,
		Bucket:   cfg.S3.Bucket,
		Prefix:   cfg.S3.Prefix,
		Logger:   logger,
	}

	if cfg.S3.Prefix == "" {
		logger.Warn("S3Cache created WITHOUT prefix - certificates will be stored in bucket root!", "bucket", cfg.S3.Bucket)
	} else {
		logger.Info("S3Cache created with prefix", "bucket", cfg.S3.Bucket, "prefix", cfg.S3.Prefix)
	}

	return s3Cache, nil
}

// isIPAddress checks whether a string parses as an IPv4 or IPv6 address.
func isIPAddress(host string) bool {
	return net.ParseIP(host) != nil
}

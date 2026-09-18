package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"migadu/mizu/pkg/concurrency"
	"migadu/mizu/pkg/metrics"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"golang.org/x/crypto/acme"
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
	Staging             bool   // use Let's Encrypt staging environment (issued certs untrusted)
	RenewBeforeDays     int    // days before expiry to renew (0 = autocert default, 30)
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

const (
	// certMaintenanceDelay puts the first maintenance run after the cluster has
	// settled who the leader is: a node that cannot reach its peers claims no
	// leader for cluster.Config.LeaderGracePeriod (1 minute by default).
	certMaintenanceDelay = 2 * time.Minute

	certMaintenanceInterval = time.Hour

	// Used instead when a pass left a domain without a certificate: until the
	// next one the node exports an expiry of 0 for it, and the gap usually
	// clears in seconds (the leader issuing a newly configured domain, a node
	// catching up after a restart).
	certMaintenanceRetryInterval = 5 * time.Minute

	// defaultRenewBefore mirrors autocert's cap on the renewal window.
	defaultRenewBefore = 30 * 24 * time.Hour
)

// Manager orchestrates TLS certificate management using Let's Encrypt.
type Manager struct {
	current  atomic.Pointer[autocertInstance] // replaced by reload
	renewMu  sync.Mutex                       // one RenewCertificate at a time
	reloadMu sync.Mutex                       // one reload at a time
	stopOnce sync.Once                        // Stop is idempotent
	served   sync.Map                         // cache key -> certRecord; see recordServed

	// What every autocert instance is built from (see newAutocert).
	cache          autocert.Cache
	hostPolicy     autocert.HostPolicy
	email          string
	directoryURL   string
	renewBeforeCfg time.Duration // autocert's RenewBefore; 0 = its default
	acmeBase       http.RoundTripper

	metrics       atomic.Pointer[metrics.Metrics] // nil until SetMetrics
	logger        *slog.Logger
	domains       []string
	defaultDomain string
	syncWorker    *CertSyncWorker
	tlsConfig     *tls.Config
	isLeaderF     func() bool
	renewBefore   time.Duration
	stopCh        chan struct{}
}

// NewManager creates a new TLS manager.
// If isLeaderF is provided and non-nil, only the cluster leader talks to Let's
// Encrypt: it keeps every configured domain issued and renewed, and the other
// nodes take their certificates from the shared cache.
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

	m := &Manager{
		cache:        cache,
		hostPolicy:   autocert.HostWhitelist(cfg.LetsEncrypt.Domains...),
		email:        cfg.LetsEncrypt.Email,
		directoryURL: autocert.DefaultACMEDirectory,
		acmeBase:     http.DefaultTransport,
		logger:       logger,
		domains:      cfg.LetsEncrypt.Domains,
		syncWorker:   syncWorker,
		isLeaderF:    leaderFunc,
		renewBefore:  defaultRenewBefore,
		stopCh:       make(chan struct{}),
	}

	// Override autocert's 30-day default renewal window when configured.
	if cfg.LetsEncrypt.RenewBeforeDays > 0 {
		m.renewBeforeCfg = time.Duration(cfg.LetsEncrypt.RenewBeforeDays) * 24 * time.Hour
		m.renewBefore = min(m.renewBeforeCfg, defaultRenewBefore)
	}

	// Point at Let's Encrypt staging for testing. Staging certs are signed by an
	// untrusted root, so clients won't validate them — use only to exercise the
	// issuance flow without consuming production rate limits.
	if cfg.LetsEncrypt.Staging {
		m.directoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
		logger.Warn("TLS: using Let's Encrypt STAGING environment — issued certificates are NOT trusted by clients")
	}

	defaultDomain := cfg.LetsEncrypt.DefaultDomain
	if defaultDomain == "" && len(cfg.LetsEncrypt.Domains) > 0 {
		defaultDomain = cfg.LetsEncrypt.Domains[0]
	}
	m.defaultDomain = defaultDomain

	m.current.Store(m.newAutocert(cache))

	// autocert's config supplies the ALPN protocols (including "acme-tls/1");
	// GetCertificate is replaced below and always asks the current instance.
	baseTLSConfig := m.current.Load().mgr.TLSConfig()

	baseTLSConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// RFC 4343: DNS names are case-insensitive.
		serverName := strings.ToLower(hello.ServerName)

		// A sender that omits SNI, or puts an IP literal in it (RFC 6066 forbids IP
		// SNI, but some MTAs send it anyway), hasn't named a certificate we can serve.
		// Fall back to the default domain's cert instead of hard-failing the
		// handshake — failing breaks opportunistic inbound TLS and surfaces on the
		// sender as "Failed to init TLS". The default domain is substituted before
		// autocert sees the name, so a bogus SNI can never trigger ACME issuance.
		if serverName == "" || isIPAddress(serverName) {
			if defaultDomain == "" {
				logger.Debug("TLS: no usable SNI and no default domain configured", "sni", hello.ServerName)
				return nil, ErrMissingServerName
			}
			logger.Debug("TLS: missing or IP-literal SNI - using default domain",
				"sni", hello.ServerName, "default_domain", defaultDomain)
			serverName = strings.ToLower(defaultDomain)
		}

		if err := m.hostPolicy(context.Background(), serverName); err != nil {
			logger.Debug("TLS: rejected certificate request for unconfigured domain",
				"domain", serverName,
				"remote_addr", hello.Conn.RemoteAddr().String(),
				"error", err)
			return nil, fmt.Errorf("%w: %s", ErrHostNotAllowed, serverName)
		}

		logger.Debug("TLS: certificate request during handshake", "domain", serverName, "has_sni", hello.ServerName != "")

		modifiedHello := *hello
		modifiedHello.ServerName = serverName

		cert, err := m.current.Load().mgr.GetCertificate(&modifiedHello)
		if errors.Is(err, ErrNotLeader) {
			logger.Warn("TLS: no usable certificate in the shared cache yet - waiting for the cluster leader to provide it",
				"server_name", serverName)
			return nil, fmt.Errorf("%w for %s: %v", ErrCertificateUnavailable, serverName, err)
		}
		if err != nil {
			logger.Error("TLS: failed to get certificate",
				"server_name", serverName,
				"error", err,
				"error_type", fmt.Sprintf("%T", err))
			return nil, fmt.Errorf("%w for %s: %v", ErrCertificateUnavailable, serverName, err)
		}
		// A leaf-only chain (no intermediates) makes strict clients — notably
		// Outlook / Exchange Online — abort the handshake. Skip TLS-ALPN-01 token
		// certs, which are intentionally single self-signed certs.
		isALPNChallenge := len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == acme.ALPNProto
		if !isALPNChallenge && cert != nil && len(cert.Certificate) <= 1 {
			logger.Warn("TLS: certificate chain may be incomplete (no intermediates) — Outlook/Exchange Online require the full chain",
				"domain", serverName,
				"chain_length", len(cert.Certificate))
		}
		if !isALPNChallenge && cert.Leaf != nil {
			m.recordServed(serverName, keyTypeOf(cert.Leaf), cert.Leaf)
		}

		logger.Debug("TLS: certificate provided successfully", "domain", serverName)
		return cert, nil
	}

	m.tlsConfig = baseTLSConfig

	// Runs in single-instance mode too: there every node is its own leader, and
	// certificates should be ready before the first message arrives rather than
	// issued during a handshake.
	m.startMaintenance()

	logger.Info("TLS manager initialized",
		"domains", cfg.LetsEncrypt.Domains,
		"email", cfg.LetsEncrypt.Email,
		"storage", cfg.LetsEncrypt.StorageProvider,
		"default_domain", defaultDomain)

	return m, nil
}

// TLSConfig returns the TLS configuration for use with HTTP/SMTP servers.
func (m *Manager) TLSConfig() *tls.Config {
	if m == nil || m.tlsConfig == nil {
		return nil
	}
	// Return a clone so callers can safely mutate fields (NextProtos, MinVersion,
	// SessionTicketsDisabled, …) for their own use — e.g. SMTP servers strip
	// autocert's ALPN protos — without corrupting the shared config that other
	// consumers rely on, notably the :443 TLS-ALPN-01 challenge server which needs
	// autocert's "acme-tls/1" ALPN proto left intact.
	return m.tlsConfig.Clone()
}

// HTTPHandler returns an HTTP handler for ACME HTTP-01 challenges. Register at
// /.well-known/acme-challenge/ on the server's port 80 endpoint.
func (m *Manager) HTTPHandler() http.Handler {
	if m == nil || m.current.Load() == nil {
		return nil
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.current.Load().httpHandler.ServeHTTP(w, r)
	})
}

// startMaintenance runs maintainCertificates shortly after startup and then
// periodically, so a node that becomes leader later takes the duty over.
//
// Nothing runs before certMaintenanceDelay, so mizu_tls_cert_expiry_seconds
// appears a couple of minutes after boot.
func (m *Manager) startMaintenance() {
	concurrency.SafeGo(m.logger, "tls-cert-maintenance", func() {
		timer := time.NewTimer(certMaintenanceDelay)
		defer timer.Stop()

		for {
			select {
			case <-timer.C:
				next := certMaintenanceInterval
				if !m.maintainCertificates() {
					next = certMaintenanceRetryInterval
				}
				timer.Reset(next)
			case <-m.stopCh:
				return
			}
		}
	})
}

// maintainCertificates walks every configured domain, for both key types, and
// records what this node would actually serve — the expiry each node reports in
// mizu_tls_cert_expiry_seconds is therefore the certificate a client would get
// from it, not a fact about the cluster.
//
// On the leader the same walk issues and renews. autocert only manages names it
// has been asked for in a handshake, and a renewal timer runs only on a node
// that has loaded the certificate, so a name whose traffic never reaches the
// leader (a sibling node's own hostname) would otherwise never be issued or
// renewed. On every other node the ACME transport refuses the order, leaving the
// walk a read of the shared cache.
//
// Reports whether every configured certificate is in service.
func (m *Manager) maintainCertificates() bool {
	inst := m.current.Load()
	isLeader := m.isLeaderF == nil || m.isLeaderF()
	complete := true

	for _, domain := range m.domains {
		for _, keyType := range certKeyTypes {
			leaf, err := m.currentLeaf(inst, isLeader, domain, keyType)
			if err != nil {
				// Report "nothing to serve" rather than leaving the last good
				// value in place, where it would read as a healthy certificate.
				m.forgetServed(domain, keyType)
				complete = false
				if isLeader {
					m.logger.Error("TLS: certificate unavailable",
						"domain", domain, "key_type", keyType, "error", err)
				} else {
					m.logger.Warn("TLS: no usable certificate - waiting for the cluster leader to supply one",
						"domain", domain, "key_type", keyType, "error", err)
				}
				continue
			}

			m.recordServed(domain, keyType, leaf)
			m.logCertificateStatus(domain, keyType, leaf)
		}
	}

	m.adoptNewerFromCache()
	return complete
}

// certRecord is the certificate this node is currently handing out for one
// domain and key type.
type certRecord struct {
	domain  string
	keyType string
	leaf    *x509.Certificate
}

// recordServed notes a certificate this node has just handed out or loaded, and
// exports its expiry.
//
// This record is what reload and adoptNewerFromCache read to learn what is in
// service. They must not ask autocert: its GetCertificate orders a certificate
// when it does not have one, so on the leader a question becomes an ACME order.
// Repeating the last observation is free, which keeps this cheap enough for the
// handshake path — where it also keeps the exported expiry live between the
// hourly maintenance passes.
func (m *Manager) recordServed(domain, keyType string, leaf *x509.Certificate) {
	key := certCacheKey(domain, keyType)
	if prev, ok := m.served.Load(key); ok && prev.(certRecord).leaf == leaf {
		return
	}

	m.served.Store(key, certRecord{domain: domain, keyType: keyType, leaf: leaf})
	m.observeCertificate(domain, keyType, leaf)
}

// forgetServed records that this node has nothing to serve for a domain.
func (m *Manager) forgetServed(domain, keyType string) {
	m.served.Delete(certCacheKey(domain, keyType))
	m.observeCertificate(domain, keyType, nil)
}

// servedRecords returns what this node is handing out, across all domains.
func (m *Manager) servedRecords() []certRecord {
	var records []certRecord
	m.served.Range(func(_, value any) bool {
		records = append(records, value.(certRecord))
		return true
	})
	return records
}

// keyTypeOf names the certificate key type autocert files a leaf under.
func keyTypeOf(leaf *x509.Certificate) string {
	if leaf.PublicKeyAlgorithm == x509.RSA {
		return "rsa"
	}
	return "ecdsa"
}

// SetMetrics attaches the metrics instance so certificate expiry is exported.
// Optional: without it the manager simply records nothing.
func (m *Manager) SetMetrics(mx *metrics.Metrics) {
	if m == nil {
		return
	}
	m.metrics.Store(mx)
}

// observeCertificate records when the certificate this node would serve for a
// domain expires. A nil leaf means there is none, recorded as 0 — far enough in
// the past that the usual "expires within N days" alert fires on it.
func (m *Manager) observeCertificate(domain, keyType string, leaf *x509.Certificate) {
	mx := m.metrics.Load()
	if mx == nil || mx.TLSCertExpiry == nil {
		return
	}

	var expiry float64
	if leaf != nil {
		expiry = float64(leaf.NotAfter.Unix())
	}
	mx.TLSCertExpiry.WithLabelValues(domain, keyType).Set(expiry)
}

// currentLeaf returns the certificate this node would serve for a domain.
//
// Only the leader asks autocert, whose GetCertificate orders what it does not
// have — which is the point of the walk there. Elsewhere that order is refused,
// and the refusal is not free: autocert keeps the failed attempt for a minute
// and answers every handshake for that name from it without reading the cache,
// so a certificate the leader publishes in the meantime is ignored and the next
// pass poisons it again. It also costs an RSA keygen per domain per pass. A
// non-leader has nothing to order, so it reads the cache instead.
func (m *Manager) currentLeaf(inst *autocertInstance, isLeader bool, domain, keyType string) (*x509.Certificate, error) {
	if isLeader {
		return servedLeaf(inst, domain, keyType)
	}
	return m.cachedLeaf(context.Background(), domain, keyType)
}

// servedLeaf returns the leaf of the certificate inst would hand out for a
// domain and key type.
func servedLeaf(inst *autocertInstance, domain, keyType string) (*x509.Certificate, error) {
	cert, err := inst.mgr.GetCertificate(certHello(domain, keyType))
	if err != nil {
		return nil, err
	}
	if cert.Leaf != nil {
		return cert.Leaf, nil
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("certificate for %s (%s) carries no chain", domain, keyType)
	}
	return x509.ParseCertificate(cert.Certificate[0])
}

// logCertificateStatus reports a certificate that autocert should have renewed
// by now. autocert retries failed renewals without logging, so this — together
// with acmeTransport's error logging — is what makes a stuck renewal visible.
func (m *Manager) logCertificateStatus(domain, keyType string, leaf *x509.Certificate) {
	remaining := time.Until(leaf.NotAfter)
	switch {
	case remaining <= 0:
		m.logger.Error("TLS: certificate EXPIRED - renewal is failing",
			"domain", domain, "key_type", keyType, "expired_at", leaf.NotAfter)
	case remaining < m.renewBefore/2:
		m.logger.Warn("TLS: certificate renewal is overdue",
			"domain", domain, "key_type", keyType,
			"days_remaining", int(remaining.Hours()/24),
			"renew_before_days", int(m.renewBefore.Hours()/24))
	default:
		m.logger.Debug("TLS: certificate ok",
			"domain", domain, "key_type", keyType, "days_remaining", int(remaining.Hours()/24))
	}
}

// Stop gracefully shuts down the TLS manager and its sync worker.
func (m *Manager) Stop() {
	if m == nil {
		return
	}

	m.stopOnce.Do(func() {
		close(m.stopCh)

		if m.syncWorker != nil {
			m.logger.Info("stopping certificate sync worker")
			m.syncWorker.Stop(10 * time.Second)
		}
	})
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

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/health"
	"migadu/mizu/pkg/logging"
	"migadu/mizu/pkg/poster"
	"migadu/mizu/pkg/smtp"
	"migadu/mizu/pkg/stats"
	"migadu/mizu/pkg/storage"

	"github.com/caddyserver/certmagic"
	gosmtp "github.com/emersion/go-smtp"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.uber.org/zap"
)

func main() {
	// Handle special command-line arguments like 'generate-config'
	handleCLIArgs()

	// Load configuration
	cfg, err := config.LoadConfig(os.Args[1:])
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Configuration validation failed: %v", err)
	}

	// Setup logging
	logger, err := logging.Setup(cfg.LogFormat, cfg.TLS.CertMagicVerbose)
	if err != nil {
		log.Fatalf("Failed to setup logging: %v", err)
	}
	defer logger.Sync()

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Sugar().Info("Received shutdown signal")
		cancel()
	}()

	// Initialize core components
	statsManager := initStatsManager(cfg, logger)

	var tlsConfig *tls.Config
	var s3Client *minio.Client
	if cfg.Local {
		logger.Sugar().Info("Running in LOCAL mode - TLS disabled, messages will be dumped to terminal")
	} else {
		tlsConfig, s3Client, err = initTLS(cfg, logger)
		if err != nil {
			logger.Sugar().Fatalf("Failed to initialize TLS: %v", err)
		}
	}
	circuitBreaker := initCircuitBreaker(cfg, logger)

	// Create HTTP client with configured timeout for posting emails to destination
	httpClient := poster.NewHTTPClient(cfg.Destination.HTTPTimeout)

	// Create connection tracker for DoS protection (global and per-IP limits)
	connTracker := smtp.NewConnectionTracker(cfg.SMTP.MaxConnections, cfg.SMTP.MaxConnectionsPerIP)
	logger.Sugar().Infof("Connection limits: max_total=%d, max_per_ip=%d", cfg.SMTP.MaxConnections, cfg.SMTP.MaxConnectionsPerIP)

	// Create distributed tracker if enabled (requires cluster configuration)
	var distTracker *smtp.DistributedTracker
	if cfg.SMTP.Distributed.Enabled {
		if !cfg.Cluster.Enabled {
			logger.Sugar().Fatal("Distributed connection tracking requires cluster.enabled=true")
		}

		// Build peer URLs using cluster configuration (hostname + peer_port)
		// Note: Path will be added by DistributedTracker.sendToPeer()
		peerURLs := make([]string, len(cfg.Cluster.Peers))
		for i, hostname := range cfg.Cluster.Peers {
			peerURLs[i] = fmt.Sprintf("http://%s%s", hostname, cfg.Cluster.PeerPort)
		}

		distTracker = smtp.NewDistributedTracker(
			connTracker,
			s3Client,
			cfg.S3.Bucket,
			cfg.S3.Prefix,
			smtp.DistributedConfig{
				Hostname:          cfg.Cluster.Hostname,
				Peers:             peerURLs,
				GossipInterval:    cfg.SMTP.Distributed.GossipInterval,
				S3SyncInterval:    cfg.SMTP.Distributed.S3SyncInterval,
				GlobalMaxPerIP:    cfg.SMTP.Distributed.GlobalMaxPerIP,
				RecipientCacheTTL: cfg.SMTP.Distributed.RecipientCacheTTL,
			},
			logger,
		)
		distTracker.Start()
		logger.Sugar().Infof("Distributed connection tracking enabled: global_max_per_ip=%d, peers=%d",
			cfg.SMTP.Distributed.GlobalMaxPerIP, len(cfg.Cluster.Peers))
	}

	// Initialize and start health check server
	healthServer := startHealthServer(cfg, logger, statsManager, circuitBreaker, connTracker, distTracker, s3Client)

	// Register distributed connection sync endpoint if enabled
	if distTracker != nil && healthServer != nil {
		healthServer.RegisterHandler("/api/connections/sync", distTracker.HTTPHandler())
		logger.Info("Registered distributed connection sync endpoint at /api/connections/sync")
	}

	// Note: Rate limiter gossip endpoint will be registered after rate limiter is created

	// Start stats manager and sync/export loops
	statsManager.Start()
	startStatsLoops(ctx, statsManager, s3Client, cfg)

	// --- SMTP Server Setup ---

	// Create DNS resolver (custom or system default)
	dnsResolver := smtp.NewDNSResolver(cfg.DNS.Servers, cfg.DNS.Timeout)
	if len(cfg.DNS.Servers) > 0 {
		logger.Info("Using custom DNS servers: " + strings.Join(cfg.DNS.Servers, ", ") + " (timeout: " + cfg.DNS.Timeout.String() + ")")
	} else {
		logger.Info("Using system default DNS resolver (timeout: " + cfg.DNS.Timeout.String() + ")")
	}

	// Create rate limiter
	var rateLimiter *smtp.RateLimiter
	if cfg.SMTP.RateLimit.Enabled {
		// Build peer URLs for gossip if cluster mode and gossip enabled
		var peerURLs []string
		if cfg.SMTP.RateLimit.GossipEnabled && cfg.Cluster.Enabled && len(cfg.Cluster.Peers) > 0 {
			peerURLs = make([]string, len(cfg.Cluster.Peers))
			for i, peer := range cfg.Cluster.Peers {
				peerURLs[i] = "http://" + peer + cfg.Cluster.PeerPort
			}
		}

		rateLimiter = smtp.NewRateLimiter(cfg.SMTP.RateLimit, peerURLs, logger)

		// Log configured dimensions
		logger.Info("Rate limiting enabled",
			zap.Int("dimensions", len(cfg.SMTP.RateLimit.Dimensions)),
			zap.Bool("gossip_enabled", cfg.SMTP.RateLimit.GossipEnabled))
		for _, dim := range cfg.SMTP.RateLimit.Dimensions {
			logger.Info("Rate limit dimension configured",
				zap.String("name", dim.Name),
				zap.Strings("keys", dim.Keys),
				zap.Int("limit", dim.Limit),
				zap.Duration("window", dim.Window))
		}

		// Register rate limit gossip endpoint with health server
		if cfg.SMTP.RateLimit.GossipEnabled && healthServer != nil {
			healthServer.RegisterHandler("/api/rate-limit-gossip", rateLimiter.HandleGossip)
			logger.Info("Registered rate limit gossip endpoint at /api/rate-limit-gossip")
		}
	}

	// Create the backend that handles SMTP protocol logic with connection tracking
	var activeSessionsWg sync.WaitGroup
	var activeSessionCount atomic.Int64
	shutdownChan := make(chan struct{})

	be := &smtp.Backend{
		Config:             cfg,
		StatsManager:       statsManager,
		CircuitBreaker:     circuitBreaker,
		HTTPClient:         httpClient,
		DNSResolver:        dnsResolver,
		ConnTracker:        connTracker,
		DistTracker:        distTracker,
		RateLimiter:        rateLimiter,
		Logger:             logger,
		ActiveSessionsWg:   &activeSessionsWg,
		ActiveSessionCount: &activeSessionCount,
		ShutdownChan:       shutdownChan,
	}

	// Run the SMTP server and wait for it to complete
	runSMTPServer(ctx, cfg, be, tlsConfig, healthServer, logger)
}

// handleCLIArgs checks for special command-line arguments, like 'generate-config'.
func handleCLIArgs() {
	if len(os.Args) > 1 && os.Args[1] == "generate-config" {
		if err := config.SaveExample("config.toml.example"); err != nil {
			log.Fatalf("Failed to generate example config: %v", err)
		}
		fmt.Println("Generated example configuration file: config.toml.example")
		os.Exit(0)
	}
}

// initStatsManager initializes the statistics manager based on the configuration.
func initStatsManager(cfg *config.Config, logger *zap.Logger) *stats.Manager {
	if !cfg.Stats.Enabled {
		logger.Sugar().Info("Stats tracking disabled")
		return stats.NewManager(false, 0, "", false, 0, nil, 0, 0, logger)
	}

	// Use cluster peers for stats sync (build full URLs with peer port)
	var syncServers []string
	if cfg.Stats.SyncEnabled && cfg.Cluster.Enabled {
		syncServers = make([]string, len(cfg.Cluster.Peers))
		for i, hostname := range cfg.Cluster.Peers {
			syncServers[i] = fmt.Sprintf("http://%s%s", hostname, cfg.Cluster.PeerPort)
		}
	}

	// Use cluster hostname for stats identification
	hostname := cfg.Cluster.Hostname
	if hostname == "" {
		// Auto-detect hostname if not configured
		if h, err := os.Hostname(); err == nil {
			hostname = h
		}
	}

	statsManager := stats.NewManager(true, cfg.Stats.RetentionDuration, hostname,
		cfg.Stats.SyncEnabled, cfg.Stats.SyncInterval, syncServers,
		cfg.Stats.MaxIPEntries, cfg.Stats.MaxDomainEntries, logger)
	logger.Sugar().Infof("Stats tracking enabled with %v retention, max entries: IPs=%d, Domains=%d",
		cfg.Stats.RetentionDuration, cfg.Stats.MaxIPEntries, cfg.Stats.MaxDomainEntries)

	if cfg.Stats.SyncEnabled {
		logger.Sugar().Infof("Stats sync enabled with %v interval, syncing with %d servers",
			cfg.Stats.SyncInterval, len(syncServers))
	}
	return statsManager
}

// initTLS sets up the S3 client and CertMagic for automatic TLS certificate management.
func initTLS(cfg *config.Config, logger *zap.Logger) (*tls.Config, *minio.Client, error) {
	// Configure certmagic logging for debugging TLS certificate issues
	if cfg.TLS.CertMagicVerbose {
		certmagic.Default.Logger = logger
	}

	// Initialize S3 client for MinIO (S3-compatible)
	s3Client, err := minio.New(cfg.S3.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.S3.AccessKeyID, cfg.S3.SecretAccessKey, ""),
		Region: cfg.S3.Region,
		Secure: true, // Use HTTPS
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init S3 client: %w", err)
	}

	// Validate S3 credentials early by checking bucket access
	// This fails fast on startup rather than during certificate operations
	logger.Sugar().Infof("Validating S3 access to bucket '%s'...", cfg.S3.Bucket)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	exists, err := s3Client.BucketExists(ctx, cfg.S3.Bucket)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate S3 credentials/access: %w (check S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY)", err)
	}
	if !exists {
		// Bucket doesn't exist - try to create it
		logger.Sugar().Infof("Bucket '%s' does not exist, attempting to create it...", cfg.S3.Bucket)
		err = s3Client.MakeBucket(ctx, cfg.S3.Bucket, minio.MakeBucketOptions{
			Region: cfg.S3.Region,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("S3 bucket '%s' does not exist and could not be created: %w (ensure credentials have s3:CreateBucket permission)", cfg.S3.Bucket, err)
		}
		logger.Sugar().Infof("Successfully created S3 bucket '%s'", cfg.S3.Bucket)
	} else {
		logger.Sugar().Infof("Successfully validated S3 access to bucket '%s'", cfg.S3.Bucket)
	}

	// Set up Certmagic storage to use S3
	certmagic.Default.Storage = storage.NewS3CertStorage(s3Client, cfg.S3.Bucket, cfg.S3.Prefix, logger)

	// Configure Certmagic for ACME (Let's Encrypt)
	if cfg.TLS.Email != "" {
		certmagic.DefaultACME.Email = cfg.TLS.Email
	}

	if !cfg.TLS.UseProduction || cfg.TLS.UseLocalCA {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
		logger.Sugar().Info("Using Let's Encrypt staging CA")
	} else {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
		logger.Sugar().Info("Using Let's Encrypt production CA")
	}

	certmagic.Default.OnDemand = &certmagic.OnDemandConfig{} // Enable on-demand certs

	// Load or issue initial certificate
	logger.Sugar().Infof("Attempting to get TLS certificate for %s...", cfg.SMTP.Domain)
	tlsConfig, err := certmagic.TLS([]string{cfg.SMTP.Domain})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get initial TLS certificate: %w", err)
	}

	// Configure minimum TLS version
	tlsConfig.MinVersion = getTLSVersion(cfg.SMTP.MinTLSVersion)
	logger.Sugar().Infof("Minimum TLS version set to: %s", cfg.SMTP.MinTLSVersion)
	if cfg.SMTP.MinTLSVersion != "" && cfg.SMTP.MinTLSVersion != "1.2" && cfg.SMTP.MinTLSVersion != "1.3" {
		logger.Sugar().Warnf("Unsupported TLS version '%s' requested - using default TLS 1.2.", cfg.SMTP.MinTLSVersion)
	}

	logger.Sugar().Infof("Successfully configured TLS certificate for %s", cfg.SMTP.Domain)
	return tlsConfig, s3Client, nil
}

// initCircuitBreaker initializes the circuit breaker for the destination endpoint.
func initCircuitBreaker(cfg *config.Config, logger *zap.Logger) *poster.CircuitBreaker {
	if cfg.Local || !cfg.Destination.CircuitBreaker.Enabled {
		return nil
	}

	cb := poster.NewCircuitBreaker(poster.CircuitBreakerConfig{
		Enabled:          cfg.Destination.CircuitBreaker.Enabled,
		FailureThreshold: cfg.Destination.CircuitBreaker.FailureThreshold,
		SuccessThreshold: cfg.Destination.CircuitBreaker.SuccessThreshold,
		Timeout:          cfg.Destination.CircuitBreaker.Timeout,
		HalfOpenMaxCalls: cfg.Destination.CircuitBreaker.HalfOpenMaxCalls,
		ResetTimeout:     cfg.Destination.CircuitBreaker.ResetTimeout,
	}, logger)
	logger.Sugar().Infof("Circuit breaker enabled: failure_threshold=%d, timeout=%v",
		cfg.Destination.CircuitBreaker.FailureThreshold,
		cfg.Destination.CircuitBreaker.Timeout)
	return cb
}

// startHealthServer initializes and starts the health check server.
func startHealthServer(cfg *config.Config, logger *zap.Logger, statsManager *stats.Manager, cb *poster.CircuitBreaker, connTracker *smtp.ConnectionTracker, distTracker *smtp.DistributedTracker, s3Client *minio.Client) *health.Server {
	if !cfg.Health.Enabled {
		return nil
	}

	var checkers []health.Checker
	if statsManager != nil {
		checkers = append(checkers, statsManager)
	}
	if cb != nil {
		checkers = append(checkers, cb)
	}
	if distTracker != nil {
		checkers = append(checkers, distTracker)
	} else if connTracker != nil {
		checkers = append(checkers, connTracker)
	}
	if s3Client != nil {
		checkers = append(checkers, health.NewCheckS3Connection(s3Client, cfg.S3.Bucket))
	}
	if !cfg.Local && cfg.Destination.URL != "" {
		checkers = append(checkers, health.NewCheckDestination(cfg.Destination.URL, 5*time.Second))
	}
	if !cfg.Local && cfg.SMTP.Domain != "" && cfg.SMTP.Domain != "mail.yourdomain.com" {
		// Extract port from listen address
		_, portStr, err := net.SplitHostPort(cfg.SMTP.ListenAddr)
		if err != nil {
			logger.Sugar().Warnf("Could not parse SMTP listen address for health check: %v", err)
		} else {
			port, _ := net.LookupPort("tcp", portStr)
			if port > 0 {
				checkers = append(checkers, health.NewCheckTLSCertificate(cfg.SMTP.Domain, port, 14*24*time.Hour))
			}
		}
	}

	healthServer := health.NewServer(cfg.Health.ListenAddr, logger, checkers...)

	// Configure HTTP Basic Auth for health endpoint
	if cfg.Health.Username != "" {
		healthServer.SetBasicAuth(cfg.Health.Username, cfg.Health.Password)
	}

	// Set stats provider
	healthServer.SetStatsProvider(statsManager)

	// Set cache flusher (if distributed tracker exists)
	if distTracker != nil {
		healthServer.SetCacheFlusher(distTracker)
	}

	healthServer.Start()
	return healthServer
}

// startStatsLoops starts the background loops for exporting and syncing stats data.
func startStatsLoops(ctx context.Context, statsMgr *stats.Manager, s3Client *minio.Client, cfg *config.Config) {
	if !cfg.Stats.Enabled || !cfg.Stats.SyncEnabled || s3Client == nil {
		return
	}

	// Use cluster hostname for stats identification
	hostname := cfg.Cluster.Hostname
	if hostname == "" {
		// Auto-detect hostname if not configured
		if h, err := os.Hostname(); err == nil {
			hostname = h
		}
	}

	// Start export loop
	go func() {
		statsMgr.StartExportLoop(ctx, s3Client, cfg.S3.Bucket, cfg.S3.Prefix,
			hostname, cfg.Stats.SyncInterval)
	}()

	// Start sync loop
	go func() {
		statsMgr.StartSyncLoop(ctx, s3Client, cfg.S3.Bucket, cfg.S3.Prefix,
			cfg.Stats.SyncInterval)
	}()
}

// runSMTPServer configures and runs the main SMTP server, handling graceful shutdown.
func runSMTPServer(ctx context.Context, cfg *config.Config, be *smtp.Backend, tlsConfig *tls.Config, healthServer *health.Server, logger *zap.Logger) {
	server := gosmtp.NewServer(be)
	// Configure SMTP server parameters
	server.Addr = cfg.SMTP.ListenAddr                       // e.g., ":25" for standard SMTP port
	server.Domain = cfg.SMTP.Domain                         // Server's hostname for HELO/EHLO responses
	server.ReadTimeout = cfg.SMTP.TimeoutDuration           // Timeout for reading client commands
	server.WriteTimeout = cfg.SMTP.TimeoutDuration          // Timeout for writing responses
	server.MaxMessageBytes = int64(cfg.SMTP.MaxMessageSize) // Limit email size to prevent abuse
	server.AllowInsecureAuth = false                        // Require TLS for authentication
	server.EnableSMTPUTF8 = true                            // Support international characters in addresses
	// Use the TLS config from certmagic which handles certificate management
	server.TLSConfig = tlsConfig

	// Create a listener that we can close for graceful shutdown
	listener, err := net.Listen("tcp", cfg.SMTP.ListenAddr)
	if err != nil {
		logger.Sugar().Fatalf("Failed to create listener: %v", err)
	}

	// Start server in a goroutine with panic recovery
	serverErrors := make(chan error, 1)
	go func() {
		logger.Sugar().Infof("Starting SMTP server on %s for domain %s", cfg.SMTP.ListenAddr, cfg.SMTP.Domain)
		serverErrors <- server.Serve(listener)
	}()

	// Start session monitoring goroutine
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if be.ActiveSessionCount != nil {
					count := be.ActiveSessionCount.Load()
					if count > 0 {
						logger.Info("Active SMTP sessions", zap.Int64("count", count))
					}
				}
			}
		}
	}()
	defer func() {
		<-monitorDone // Wait for monitoring goroutine to finish
	}()

	// Wait for shutdown signal or server error
	select {
	case <-ctx.Done():
		logger.Sugar().Info("Initiating graceful shutdown...")

		// Phase 1: Stop accepting new connections
		close(be.ShutdownChan)
		listener.Close()
		logger.Sugar().Info("Stopped accepting new connections")

		// Phase 2: Wait for active sessions to complete (with timeout)
		logger.Sugar().Infof("Waiting up to %v for active SMTP sessions to complete...", cfg.SMTP.ShutdownTimeout)

		waitDone := make(chan struct{})
		go func() {
			be.ActiveSessionsWg.Wait()
			close(waitDone)
		}()

		select {
		case <-waitDone:
			logger.Sugar().Info("All SMTP sessions completed gracefully")
		case <-time.After(cfg.SMTP.ShutdownTimeout):
			logger.Sugar().Warn("Shutdown timeout reached, forcing termination of remaining sessions")
		}

		// Phase 3: Stop stats manager (ensures events are flushed)
		logger.Sugar().Info("Stopping stats manager...")
		if be.StatsManager != nil {
			be.StatsManager.Stop()
		}

		// Phase 4: Stop health server
		if healthServer != nil {
			logger.Sugar().Info("Stopping health server...")
			healthServer.Stop(context.Background())
		}

		logger.Sugar().Info("Graceful shutdown complete")
	case err := <-serverErrors:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			logger.Sugar().Fatalf("SMTP server error: %v", err)
		}
	}
}

// getTLSVersion converts a string TLS version to the corresponding tls constant
// Only TLS 1.2 and 1.3 are supported for security reasons
func getTLSVersion(version string) uint16 {
	switch version {
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	default:
		// Default to TLS 1.2 for security - TLS 1.0 and 1.1 are deprecated
		return tls.VersionTLS12
	}
}

package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"migadu/mizu/pkg/cluster"
	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/health"
	"migadu/mizu/pkg/logging"
	"migadu/mizu/pkg/metrics"
	"migadu/mizu/pkg/poster"
	"migadu/mizu/pkg/recipient"
	"migadu/mizu/pkg/smtp"
	"migadu/mizu/pkg/stats"
	"migadu/mizu/pkg/storage"
	tlsmgr "migadu/mizu/pkg/tls"

	gosmtp "github.com/emersion/go-smtp"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Version information, injected at build time
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// Handle special command-line arguments like 'generate-config' and '-version'
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
	logFormat := cfg.Logging.Format
	if logFormat == "" {
		logFormat = "console" // Default to console format
	}
	verbose := cfg.Logging.Level == "debug"
	logger, err := logging.Setup(logFormat, verbose)
	if err != nil {
		log.Fatalf("Failed to setup logging: %v", err)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	logging.SafeGo(logger, "signal-handler", func() {
		<-sigChan
		logger.Info("Received shutdown signal")
		cancel()
	})

	// Initialize memberlist cluster first (required for TLS leader election)
	var clusterMgr *cluster.Cluster
	if cfg.Cluster.Enabled {
		clusterMgr, err = initCluster(cfg, logger)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to initialize cluster: %v", err))
			os.Exit(1)
		}
		defer clusterMgr.Shutdown()
	}

	// Initialize core components
	statsManager := initStatsManager(cfg, logger)

	// Initialize Prometheus metrics
	metricsInstance := metrics.New("mizu")
	logger.Info("Prometheus metrics initialized")

	var tlsConfig *tls.Config
	var s3Client *minio.Client
	var tlsMgr *tlsmgr.Manager
	if cfg.Local {
		logger.Info("Running in LOCAL mode - TLS disabled, messages will be dumped to terminal")
	} else {
		tlsConfig, s3Client, tlsMgr, err = initTLS(cfg, clusterMgr, logger)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to initialize TLS: %v", err))
			os.Exit(1)
		}

		// Start ACME challenge servers
		if tlsMgr != nil {
			logger.Info("TLS manager initialized successfully - starting ACME challenge servers")
			// Start HTTPS server on port 443 for TLS-ALPN-01 challenges (primary method)
			logging.SafeGo(logger, "acme-tls-alpn-server", func() {
				logger.Info("Starting HTTPS server for ACME TLS-ALPN-01 challenges on :443")
				server := &http.Server{
					Addr:      ":443",
					TLSConfig: tlsMgr.TLSConfig(),
				}
				// Empty cert/key files - TLSConfig.GetCertificate handles everything
				if err := server.ListenAndServeTLS("", ""); err != nil {
					logger.Error("TLS-ALPN-01 challenge server failed", "error", err)
				}
			})

			// Start HTTP server on port 80 for HTTP-01 challenges (fallback)
			logging.SafeGo(logger, "acme-http-server", func() {
				logger.Info("Starting HTTP server for ACME HTTP-01 challenges on :80")
				if err := http.ListenAndServe(":80", tlsMgr.HTTPHandler()); err != nil {
					logger.Error("HTTP-01 challenge server failed", "error", err)
				}
			})
		} else {
			logger.Warn("TLS manager is nil - ACME challenge servers will NOT start",
				"tls_domains", cfg.TLS.Domains,
				"cluster_enabled", cfg.Cluster.Enabled)
		}
	}

	// Initialize and start health check server (before starting SMTP servers)
	healthServer := startHealthServer(cfg, logger, statsManager, nil, nil, s3Client)

	// Set ACME handler on health server if autocert is enabled
	if healthServer != nil && tlsMgr != nil {
		healthServer.SetACMEHandler(tlsMgr.HTTPHandler())
	}

	// Start stats manager and sync/export loops
	statsManager.Start()
	startStatsLoops(ctx, statsManager, s3Client, cfg, logger)

	// --- SMTP Server Setup ---

	// Create shared DNS resolver with caching (used by all servers)
	dnsTimeout := time.Duration(cfg.DNS.TimeoutSeconds) * time.Second
	dnsCacheTTL := time.Duration(cfg.DNS.CacheTTLSeconds) * time.Second
	dnsResolver, dnsCache := smtp.NewDNSResolver(cfg.DNS.Resolvers, dnsTimeout, dnsCacheTTL)
	if len(cfg.DNS.Resolvers) > 0 {
		logger.Info("Using custom DNS resolvers: " + strings.Join(cfg.DNS.Resolvers, ", "))
	} else {
		logger.Info("Using system default DNS resolver")
	}

	// Set metrics on DNS cache for monitoring
	if dnsCache != nil {
		dnsCache.SetMetrics(metricsInstance)
		logger.Info("DNS cache metrics enabled")
	}

	// Track all server instances for coordinated shutdown
	var serverWg sync.WaitGroup
	type serverInstance struct {
		backend      *smtp.Backend
		cancelFunc   context.CancelFunc
		shutdownChan chan struct{}
	}
	servers := make([]serverInstance, 0)

	// Start each configured SMTP server instance
	for i := range cfg.Servers {
		serverCfg := &cfg.Servers[i]

		logger.Info("Initializing SMTP server",
			"name", serverCfg.Name,
			"type", serverCfg.Type,
			"listen_addr", serverCfg.ListenAddr,
			"tls", serverCfg.TLS.Mode)

		// Initialize recipient validator if enabled for this server
		var recipientValidator smtp.RecipientValidator
		if serverCfg.RecipientValidation.Enabled {
			recipientValidator = initRecipientValidator(serverCfg, logger)
		}

		// Create server-specific backend
		backend := createServerBackend(
			serverCfg,
			cfg,
			statsManager,
			dnsResolver,
			metricsInstance,
			recipientValidator,
			clusterMgr,
			s3Client,
			logger,
		)

		// Create server-specific context
		serverCtx, serverCancel := context.WithCancel(ctx)

		// Store for shutdown coordination
		servers = append(servers, serverInstance{
			backend:      backend,
			cancelFunc:   serverCancel,
			shutdownChan: backend.ShutdownChan,
		})

		// Start server in background with panic recovery
		serverWg.Add(1)
		// Capture variables for closure
		srvCfg := serverCfg
		srvCtx := serverCtx
		be := backend
		logging.SafeGoWithWg(logger, fmt.Sprintf("smtp-server-%s", srvCfg.Name), &serverWg, func() {
			runSMTPServerInstance(srvCtx, srvCfg, be, tlsConfig, logger)
		})
	}

	if len(servers) == 0 {
		logger.Error("No SMTP servers enabled")
		os.Exit(1)
	}

	logger.Info(fmt.Sprintf("Started %d SMTP server(s)", len(servers)))

	// Wait for shutdown signal
	<-ctx.Done()
	logger.Info("Initiating graceful shutdown of all servers...")

	// Phase 1: Stop accepting new connections on all servers
	for _, srv := range servers {
		close(srv.shutdownChan)
		srv.cancelFunc()
	}

	// Phase 2: Wait for all servers to shut down
	shutdownDone := make(chan struct{})
	logging.SafeGo(logger, "shutdown-wait", func() {
		serverWg.Wait()
		close(shutdownDone)
	})

	shutdownTimeout := time.Duration(cfg.Defaults.ShutdownTimeoutSeconds) * time.Second
	select {
	case <-shutdownDone:
		logger.Info("All servers shut down gracefully")
	case <-time.After(shutdownTimeout):
		logger.Warn("Shutdown timeout reached, forcing exit")
	}

	// Phase 3: Stop stats manager
	if statsManager != nil {
		logger.Info("Stopping stats manager...")
		statsManager.Stop()
	}

	// Phase 4: Stop health server
	if healthServer != nil {
		logger.Info("Stopping health server...")
		healthServer.Stop(context.Background())
	}

	logger.Info("Graceful shutdown complete")
}

// handleCLIArgs checks for special command-line arguments, like 'generate-config' and '-version'.
func handleCLIArgs() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "generate-config":
			if err := config.SaveExample("config.toml.example"); err != nil {
				log.Fatalf("Failed to generate example config: %v", err)
			}
			fmt.Println("Generated example configuration file: config.toml.example")
			os.Exit(0)
		case "-version", "--version", "version":
			fmt.Printf("mizu-server %s\n", version)
			fmt.Printf("  commit: %s\n", commit)
			fmt.Printf("  built:  %s\n", date)
			os.Exit(0)
		}
	}
}

// initStatsManager initializes the statistics manager based on the configuration.
func initStatsManager(cfg *config.Config, logger *slog.Logger) *stats.Manager {
	if !cfg.Stats.Enabled {
		logger.Info("Stats tracking disabled")
		return stats.NewManager(false, 0, "", false, 0, nil, 0, 0, logger)
	}

	// Stats sync still uses HTTP (not migrated to memberlist yet)
	// Build peer URLs from seed nodes for stats HTTP sync
	var syncServers []string
	if cfg.Stats.SyncEnabled && cfg.Cluster.Enabled {
		// Convert peers to HTTP URLs (assuming health server port 8080)
		syncServers = make([]string, len(cfg.Cluster.Peers))
		for i, peer := range cfg.Cluster.Peers {
			// Extract hostname from "hostname:port" format
			host, _, _ := net.SplitHostPort(peer)
			if host == "" {
				host = peer // No port specified
			}
			syncServers[i] = fmt.Sprintf("http://%s:8080", host)
		}
	}

	// Use node name for stats identification
	hostname := cfg.Cluster.NodeName
	if hostname == "" {
		// Auto-detect hostname if not configured
		if h, err := os.Hostname(); err == nil {
			hostname = h
		}
	}

	statsManager := stats.NewManager(true, time.Duration(cfg.Stats.RetentionSeconds)*time.Second, hostname,
		cfg.Stats.SyncEnabled, time.Duration(cfg.Stats.SyncIntervalSeconds)*time.Second, syncServers,
		cfg.Stats.MaxIPEntries, cfg.Stats.MaxDomainEntries, logger)
	logger.Info(fmt.Sprintf("Stats tracking enabled with %v retention, max entries: IPs=%d, Domains=%d",
		time.Duration(cfg.Stats.RetentionSeconds)*time.Second, cfg.Stats.MaxIPEntries, cfg.Stats.MaxDomainEntries))

	if cfg.Stats.SyncEnabled {
		logger.Info(fmt.Sprintf("Stats sync enabled with %v interval, syncing with %d servers",
			time.Duration(cfg.Stats.SyncIntervalSeconds)*time.Second, len(syncServers)))
	}
	return statsManager
}

// initStorageBackend initializes the storage backend based on configuration (S3 or filesystem)
func initStorageBackend(cfg *config.Config, logger *slog.Logger) (storage.Backend, *minio.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var backend storage.Backend
	var s3Client *minio.Client

	switch cfg.Storage.Backend {
	case "filesystem":
		logger.Info("Using filesystem storage backend", "path", cfg.Storage.FilesystemPath)
		fsBackend, err := storage.NewFilesystemBackend(cfg.Storage.FilesystemPath, logger)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to init filesystem backend: %w", err)
		}

		// Ensure storage directory exists
		exists, err := fsBackend.BucketExists(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to check storage directory: %w", err)
		}
		if !exists {
			logger.Info("Creating storage directory", "path", cfg.Storage.FilesystemPath)
			if err := fsBackend.MakeBucket(ctx); err != nil {
				return nil, nil, fmt.Errorf("failed to create storage directory: %w", err)
			}
		}

		backend = fsBackend

	case "s3":
		logger.Info("Using S3 storage backend", "bucket", cfg.Storage.Bucket)
		// Initialize S3 client for MinIO (S3-compatible)
		var err error
		s3Client, err = minio.New(cfg.Storage.Endpoint, &minio.Options{
			Creds:  credentials.NewStaticV4(cfg.Storage.AccessKeyID, cfg.Storage.SecretAccessKey, ""),
			Region: cfg.Storage.Region,
			Secure: true, // Use HTTPS
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to init S3 client: %w", err)
		}

		s3Backend := storage.NewS3Backend(s3Client, cfg.Storage.Bucket, logger)

		// Validate S3 credentials early by checking bucket access
		logger.Info(fmt.Sprintf("Validating S3 access to bucket '%s'...", cfg.Storage.Bucket))
		exists, err := s3Backend.BucketExists(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to validate S3 credentials/access: %w (check S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY)", err)
		}
		if !exists {
			// Bucket doesn't exist - try to create it
			logger.Info(fmt.Sprintf("Bucket '%s' does not exist, attempting to create it...", cfg.Storage.Bucket))
			if err := s3Backend.MakeBucket(ctx); err != nil {
				return nil, nil, fmt.Errorf("S3 bucket '%s' does not exist and could not be created: %w (ensure credentials have s3:CreateBucket permission)", cfg.Storage.Bucket, err)
			}
			logger.Info(fmt.Sprintf("Successfully created S3 bucket '%s'", cfg.Storage.Bucket))
		} else {
			logger.Info(fmt.Sprintf("Successfully validated S3 access to bucket '%s'", cfg.Storage.Bucket))
		}

		backend = s3Backend

	default:
		return nil, nil, fmt.Errorf("invalid storage backend: %s", cfg.Storage.Backend)
	}

	return backend, s3Client, nil
}

// initTLS sets up the storage backend and TLS certificate management using autocert.
func initTLS(cfg *config.Config, clusterMgr *cluster.Cluster, logger *slog.Logger) (*tls.Config, *minio.Client, *tlsmgr.Manager, error) {
	storageBackend, s3Client, err := initStorageBackend(cfg, logger)
	if err != nil {
		return nil, nil, nil, err
	}

	var tlsConfig *tls.Config
	var tlsMgr *tlsmgr.Manager

	// Get leader function from cluster
	var isLeaderF func() bool
	if clusterMgr != nil {
		isLeaderF = clusterMgr.IsLeader
	} else {
		// Fallback: always return true if no cluster (single-node mode)
		isLeaderF = func() bool { return true }
		logger.Warn("No cluster configured - autocert running in single-node mode")
	}

	// Calculate renewal window
	var renewBefore time.Duration
	if cfg.TLS.RenewBeforeDays > 0 {
		renewBefore = time.Duration(cfg.TLS.RenewBeforeDays) * 24 * time.Hour
	}

	// Calculate sync interval
	var syncInterval time.Duration
	if cfg.TLS.SyncIntervalMinutes > 0 {
		syncInterval = time.Duration(cfg.TLS.SyncIntervalMinutes) * time.Minute
	} else if cfg.TLS.SyncIntervalMinutes == 0 && cfg.TLS.FallbackCacheDir != "" {
		// Default to 5 minutes if fallback cache is enabled but interval not specified
		syncInterval = 5 * time.Minute
	}

	// Create TLS manager with autocert using storage backend abstraction
	tlsMgr, err = tlsmgr.NewManager(tlsmgr.Config{
		Enabled:        true,
		Email:          cfg.TLS.Email,
		Domains:        cfg.TLS.Domains,
		DefaultDomain:  cfg.TLS.DefaultDomain,
		StorageBackend: storageBackend,
		StoragePrefix:  cfg.Storage.Prefix,
		IsLeaderF:      isLeaderF,
		Staging:        !cfg.TLS.UseProduction,
		RenewBefore:    renewBefore,
		FallbackDir:    cfg.TLS.FallbackCacheDir,
		SyncInterval:   syncInterval,
	}, logger)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create TLS manager: %w", err)
	}

	tlsConfig = tlsMgr.TLSConfig()
	if tlsConfig == nil {
		return nil, nil, nil, fmt.Errorf("TLS manager returned nil config")
	}

	logger.Info(fmt.Sprintf("Autocert initialized for domains: %v", cfg.TLS.Domains))

	// Set default minimum TLS version (can be overridden per-server)
	tlsConfig.MinVersion = tls.VersionTLS12
	logger.Info("Default TLS configuration ready (per-server min version can be set in [server.tls])")

	return tlsConfig, s3Client, tlsMgr, nil
}

// initCluster initializes the memberlist cluster for distributed operations
func initCluster(cfg *config.Config, logger *slog.Logger) (*cluster.Cluster, error) {
	// Determine node name
	nodeName := cfg.Cluster.NodeName
	if nodeName == "" {
		// Auto-detect from OS hostname
		if h, err := os.Hostname(); err == nil {
			nodeName = h
		} else {
			return nil, fmt.Errorf("failed to auto-detect hostname: %w", err)
		}
	}

	// Read secret key from environment variable (preferred) or config file
	var secretKey []byte
	secretKeyStr := os.Getenv("CLUSTER_SECRET_KEY")
	if secretKeyStr != "" {
		decoded, err := base64.StdEncoding.DecodeString(secretKeyStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode CLUSTER_SECRET_KEY: %w", err)
		}
		if len(decoded) != 32 {
			return nil, fmt.Errorf("CLUSTER_SECRET_KEY must be 32 bytes when decoded, got %d", len(decoded))
		}
		secretKey = decoded
		logger.Info("Using cluster secret key from CLUSTER_SECRET_KEY environment variable")
	} else if cfg.Cluster.SecretKey != "" {
		// Fallback to config file (not recommended for production)
		decoded, err := base64.StdEncoding.DecodeString(cfg.Cluster.SecretKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode cluster.secret_key from config: %w", err)
		}
		if len(decoded) != 32 {
			return nil, fmt.Errorf("cluster.secret_key must be 32 bytes when decoded, got %d", len(decoded))
		}
		secretKey = decoded
		logger.Warn("Using cluster secret key from config file - use CLUSTER_SECRET_KEY env var instead")
	}

	clusterCfg := cluster.Config{
		NodeName:  nodeName,
		BindAddr:  cfg.Cluster.GetBindAddr(),
		BindPort:  cfg.Cluster.GetBindPort(),
		Peers:     cfg.Cluster.Peers,
		SecretKey: secretKey,
		Logger:    logger,
	}

	logger.Info("Initializing memberlist cluster",
		"node_name", nodeName,
		"bind_addr", cfg.Cluster.GetBindAddr(),
		"bind_port", cfg.Cluster.GetBindPort(),
		"peers", len(cfg.Cluster.Peers))

	return cluster.NewCluster(clusterCfg)
}

// startHealthServer initializes and starts the health check server.
func startHealthServer(cfg *config.Config, logger *slog.Logger, statsManager *stats.Manager, connTracker *smtp.ConnectionTracker, distTracker *smtp.DistributedTracker, s3Client *minio.Client) *health.Server {
	if !cfg.Health.Enabled {
		return nil
	}

	var checkers []health.Checker
	if statsManager != nil {
		checkers = append(checkers, statsManager)
	}
	if distTracker != nil {
		checkers = append(checkers, distTracker)
	} else if connTracker != nil {
		checkers = append(checkers, connTracker)
	}
	if s3Client != nil {
		checkers = append(checkers, health.NewCheckS3Connection(s3Client, cfg.Storage.Bucket))
	}
	// Check delivery URLs for each server
	if !cfg.Local {
		deliveryURLsChecked := make(map[string]bool) // Track URLs to avoid duplicates
		for _, srv := range cfg.Servers {
			if srv.Delivery.URL != "" && !deliveryURLsChecked[srv.Delivery.URL] {
				checkers = append(checkers, health.NewCheckDestination(srv.Delivery.URL, 5*time.Second))
				deliveryURLsChecked[srv.Delivery.URL] = true
			}
		}
	}
	// Check TLS certificates for all enabled servers
	if !cfg.Local {
		for _, srv := range cfg.Servers {
			if srv.Domain != "" && srv.Domain != "mail.yourdomain.com" {
				_, portStr, err := net.SplitHostPort(srv.ListenAddr)
				if err != nil {
					logger.Warn("Could not parse listen address for health check",
						"server", srv.Name,
						"error", err)
					continue
				}
				port, _ := net.LookupPort("tcp", portStr)
				if port > 0 {
					checkers = append(checkers, health.NewCheckTLSCertificate(srv.Domain, port, 14*24*time.Hour))
				}
			}
		}
	}

	// Only start health server if at least one feature is enabled
	if !cfg.Health.Enabled && !cfg.Metrics.Enabled {
		logger.Info("Health and metrics endpoints disabled")
		return nil
	}

	healthServer := health.NewServer(cfg.Health.ListenAddr, logger, checkers...)

	// Configure health endpoint (only if enabled)
	healthServer.SetHealthEnabled(cfg.Health.Enabled)
	if cfg.Health.Enabled {
		// Configure HTTP Basic Auth for health endpoint
		if cfg.Health.Username != "" {
			healthServer.SetBasicAuth(cfg.Health.Username, cfg.Health.Password)
		}
		logger.Info("Health endpoint enabled", "listen_addr", cfg.Health.ListenAddr, "auth_enabled", cfg.Health.Username != "")
	}

	// Configure Prometheus metrics endpoint (only if enabled)
	if cfg.Metrics.Enabled {
		healthServer.SetMetricsConfig(
			cfg.Metrics.Enabled,
			cfg.Metrics.Path,
			cfg.Metrics.Username,
			cfg.Metrics.Password,
		)
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
func startStatsLoops(ctx context.Context, statsMgr *stats.Manager, s3Client *minio.Client, cfg *config.Config, logger *slog.Logger) {
	if !cfg.Stats.Enabled || !cfg.Stats.SyncEnabled || s3Client == nil {
		return
	}

	// Use node name for stats identification
	hostname := cfg.Cluster.NodeName
	if hostname == "" {
		// Auto-detect hostname if not configured
		if h, err := os.Hostname(); err == nil {
			hostname = h
		}
	}

	// Start export loop
	logging.SafeGo(logger, "stats-export-loop", func() {
		statsMgr.StartExportLoop(ctx, s3Client, cfg.Storage.Bucket, cfg.Storage.Prefix,
			hostname, time.Duration(cfg.Stats.SyncIntervalSeconds)*time.Second)
	})

	// Start sync loop
	logging.SafeGo(logger, "stats-sync-loop", func() {
		statsMgr.StartSyncLoop(ctx, s3Client, cfg.Storage.Bucket, cfg.Storage.Prefix,
			time.Duration(cfg.Stats.SyncIntervalSeconds)*time.Second)
	})
}

// createServerBackend creates a Backend instance for a specific server
func createServerBackend(
	serverCfg *config.ServerConfig,
	globalCfg *config.Config,
	statsManager *stats.Manager,
	dnsResolver *net.Resolver,
	metricsInstance *metrics.Metrics,
	recipientValidator smtp.RecipientValidator,
	clusterMgr *cluster.Cluster,
	s3Client *minio.Client,
	logger *slog.Logger,
) *smtp.Backend {
	// Create server-specific logger
	serverLogger := logger.With(
		"server_name", serverCfg.Name,
		"server_type", serverCfg.Type,
	)

	// Create per-server connection tracker
	connTracker := smtp.NewConnectionTracker(serverCfg.Limits.MaxConnections, serverCfg.Limits.MaxConnectionsPerIP)

	// Create distributed tracker if enabled for this server
	var distTracker *smtp.DistributedTracker
	if serverCfg.Distributed.Enabled {
		if !globalCfg.Cluster.Enabled || clusterMgr == nil {
			serverLogger.Error("Distributed tracking requires cluster.enabled=true")
			os.Exit(1)
		}

		nodeName := globalCfg.Cluster.NodeName
		if nodeName == "" {
			if h, err := os.Hostname(); err == nil {
				nodeName = h
			}
		}

		distTracker = smtp.NewDistributedTracker(
			connTracker,
			s3Client,
			globalCfg.Storage.Bucket,
			globalCfg.Storage.Prefix,
			smtp.DistributedConfig{
				Hostname:          nodeName,
				Cluster:           clusterMgr,
				GossipInterval:    time.Duration(serverCfg.Distributed.GossipIntervalSeconds) * time.Second,
				S3SyncInterval:    time.Duration(serverCfg.Distributed.S3SyncIntervalSeconds) * time.Second,
				GlobalMaxPerIP:    serverCfg.Distributed.GlobalMaxPerIP,
				RecipientCacheTTL: time.Duration(serverCfg.Distributed.RecipientCacheTTLSeconds) * time.Second,
			},
			serverLogger,
		)
		distTracker.Start()
		serverLogger.Info("Distributed tracking enabled", "global_max_per_ip", serverCfg.Distributed.GlobalMaxPerIP)
	}

	// Create per-server rate limiter if configured
	var rateLimiter *smtp.RateLimiter
	if serverCfg.RateLimit.Enabled {
		if serverCfg.RateLimit.GossipEnabled && (!globalCfg.Cluster.Enabled || clusterMgr == nil) {
			serverLogger.Error("Rate limit gossip requires cluster.enabled=true")
			os.Exit(1)
		}

		rateLimiter = smtp.NewRateLimiter(serverCfg.RateLimit, clusterMgr, serverLogger)
		serverLogger.Info("Rate limiting enabled",
			"dimensions", len(serverCfg.RateLimit.Dimensions),
			"gossip_enabled", serverCfg.RateLimit.GossipEnabled)
	}

	// ARC signer removed - Mizu is SMTP-to-HTTP relay, never forwards messages
	// ARC validation (checking incoming ARC headers) is handled in session.Data()

	// Initialize authenticator if auth is enabled or required
	var authenticator smtp.Authenticator
	var authRateLimiter *smtp.AuthRateLimiter
	if serverCfg.Auth.Enabled || serverCfg.Auth.Required {
		authenticator = initAuthenticator(serverCfg, serverLogger)

		// Initialize auth rate limiter with default values if not configured
		cfg := serverCfg.Auth.RateLimit
		if cfg.MaxAttemptsPerIPUsername == 0 {
			cfg.MaxAttemptsPerIPUsername = 5
		}
		if cfg.MaxAttemptsPerIP == 0 {
			cfg.MaxAttemptsPerIP = 50
		}
		if cfg.MaxAttemptsPerUsername == 0 {
			cfg.MaxAttemptsPerUsername = 100
		}
		if cfg.DelayStartThreshold == 0 {
			cfg.DelayStartThreshold = 3
		}
		if cfg.DelayMultiplier == 0 {
			cfg.DelayMultiplier = 2.0
		}
		if cfg.MaxIPUsernameEntries == 0 {
			cfg.MaxIPUsernameEntries = 100000
		}
		if cfg.MaxIPEntries == 0 {
			cfg.MaxIPEntries = 50000
		}
		if cfg.MaxUsernameEntries == 0 {
			cfg.MaxUsernameEntries = 50000
		}

		// Enable auth rate limiting by default when auth is required
		if !cfg.Enabled && serverCfg.Auth.Required {
			cfg.Enabled = true
		}

		if cfg.Enabled {
			limiter, err := smtp.NewAuthRateLimiter(cfg, serverLogger, metricsInstance)
			if err != nil {
				serverLogger.Error("Failed to create auth rate limiter", "error", err)
				os.Exit(1)
			}
			authRateLimiter = limiter

			// Set up cluster sync if cluster is enabled and sync is configured
			if clusterMgr != nil && cfg.ClusterSyncEnabled {
				clusterLimiter := smtp.NewClusterAuthRateLimiter(limiter, clusterMgr, serverLogger)
				limiter.SetClusterLimiter(clusterLimiter)

				// Register handler with cluster
				clusterMgr.RegisterAuthRateLimitHandler(clusterLimiter.HandleClusterEvent)

				serverLogger.Info("Auth rate limiter cluster sync enabled")
			}

			serverLogger.Info("Auth rate limiter enabled",
				"max_ip_username", cfg.MaxAttemptsPerIPUsername,
				"max_ip", cfg.MaxAttemptsPerIP,
				"max_username", cfg.MaxAttemptsPerUsername,
				"cluster_sync", cfg.ClusterSyncEnabled)
		}
	}

	// Create per-server circuit breaker and HTTP client for delivery
	var serverCircuitBreaker *poster.CircuitBreaker
	if !globalCfg.Local && serverCfg.Delivery.CircuitBreaker.Enabled {
		serverCircuitBreaker = poster.NewCircuitBreaker(poster.CircuitBreakerConfig{
			Enabled:          serverCfg.Delivery.CircuitBreaker.Enabled,
			FailureThreshold: serverCfg.Delivery.CircuitBreaker.FailureThreshold,
			SuccessThreshold: serverCfg.Delivery.CircuitBreaker.SuccessThreshold,
			Timeout:          time.Duration(serverCfg.Delivery.CircuitBreaker.TimeoutSeconds) * time.Second,
			HalfOpenMaxCalls: serverCfg.Delivery.CircuitBreaker.HalfOpenMaxCalls,
			ResetTimeout:     time.Duration(serverCfg.Delivery.CircuitBreaker.ResetTimeoutSeconds) * time.Second,
		}, serverLogger, metricsInstance)
		serverLogger.Info("Circuit breaker enabled",
			"failure_threshold", serverCfg.Delivery.CircuitBreaker.FailureThreshold,
			"timeout_seconds", serverCfg.Delivery.CircuitBreaker.TimeoutSeconds)
	}

	serverHTTPClient := poster.NewHTTPClient(time.Duration(serverCfg.Delivery.HTTPTimeoutSeconds) * time.Second)
	serverLogger.Info("HTTP client created", "timeout_seconds", serverCfg.Delivery.HTTPTimeoutSeconds)

	// Create Backend
	var activeSessionsWg sync.WaitGroup
	var activeSessionCount atomic.Int64
	shutdownChan := make(chan struct{})

	return &smtp.Backend{
		ServerConfig:       serverCfg,
		GlobalConfig:       globalCfg,
		StatsManager:       statsManager,
		CircuitBreaker:     serverCircuitBreaker,
		HTTPClient:         serverHTTPClient,
		DNSResolver:        dnsResolver,
		Metrics:            metricsInstance,
		Logger:             serverLogger,
		ActiveSessionsWg:   &activeSessionsWg,
		ActiveSessionCount: &activeSessionCount,
		ShutdownChan:       shutdownChan,
		ConnTracker:        connTracker,
		DistTracker:        distTracker,
		RateLimiter:        rateLimiter,
		Authenticator:      authenticator,
		AuthRateLimiter:    authRateLimiter,
		RecipientValidator: recipientValidator,
	}
}

// initAuthenticator initializes an HTTP authenticator for submission servers
func initAuthenticator(serverCfg *config.ServerConfig, logger *slog.Logger) smtp.Authenticator {
	if serverCfg.Auth.URL == "" {
		logger.Error("Authentication requires auth.url")
		os.Exit(1)
	}

	// Initialize auth cache if enabled
	var authCache *smtp.AuthCache
	cacheCfg := serverCfg.Auth.Cache
	if cacheCfg.Enabled {
		// Set defaults
		if cacheCfg.PositiveTTL == "" {
			cacheCfg.PositiveTTL = "5m"
		}
		if cacheCfg.NegativeTTL == "" {
			cacheCfg.NegativeTTL = "1m"
		}
		if cacheCfg.MaxSize == 0 {
			cacheCfg.MaxSize = 50000
		}
		if cacheCfg.CleanupInterval == "" {
			cacheCfg.CleanupInterval = "5m"
		}
		if cacheCfg.PositiveRevalidationWindow == "" {
			cacheCfg.PositiveRevalidationWindow = "30s"
		}

		// Parse durations
		positiveTTL, err := time.ParseDuration(cacheCfg.PositiveTTL)
		if err != nil {
			logger.Error("Invalid auth cache positive_ttl", "value", cacheCfg.PositiveTTL, "error", err)
			os.Exit(1)
		}
		negativeTTL, err := time.ParseDuration(cacheCfg.NegativeTTL)
		if err != nil {
			logger.Error("Invalid auth cache negative_ttl", "value", cacheCfg.NegativeTTL, "error", err)
			os.Exit(1)
		}
		cleanupInterval, err := time.ParseDuration(cacheCfg.CleanupInterval)
		if err != nil {
			logger.Error("Invalid auth cache cleanup_interval", "value", cacheCfg.CleanupInterval, "error", err)
			os.Exit(1)
		}
		revalidationWindow, err := time.ParseDuration(cacheCfg.PositiveRevalidationWindow)
		if err != nil {
			logger.Error("Invalid auth cache positive_revalidation_window", "value", cacheCfg.PositiveRevalidationWindow, "error", err)
			os.Exit(1)
		}

		authCache = smtp.NewAuthCache(
			positiveTTL,
			negativeTTL,
			cacheCfg.MaxSize,
			cleanupInterval,
			revalidationWindow,
			logger.With("component", "auth_cache"),
		)

		logger.Info("Auth cache initialized",
			"positive_ttl", cacheCfg.PositiveTTL,
			"negative_ttl", cacheCfg.NegativeTTL,
			"max_size", cacheCfg.MaxSize,
			"revalidation_window", cacheCfg.PositiveRevalidationWindow)
	}

	logger.Info("Using HTTP authenticator", "url", serverCfg.Auth.URL, "cache_enabled", cacheCfg.Enabled)
	return smtp.NewHTTPAuthenticator(serverCfg.Auth.URL, serverCfg.Auth.AuthToken, logger, authCache)
}

// initRecipientValidator initializes a recipient validator for a server
func initRecipientValidator(serverCfg *config.ServerConfig, logger *slog.Logger) smtp.RecipientValidator {
	if serverCfg.RecipientValidation.URL == "" {
		logger.Error("Recipient validation requires recipient_validation.url")
		os.Exit(1)
	}

	validator, err := recipient.NewValidator(recipient.ValidatorConfig{
		URL:                serverCfg.RecipientValidation.URL,
		AuthToken:          serverCfg.RecipientValidation.AuthToken,
		HTTPTimeoutSeconds: serverCfg.RecipientValidation.HTTPTimeoutSeconds,
		CacheTTLSeconds:    serverCfg.RecipientValidation.CacheTTLSeconds,
		Logger:             logger,
	})
	if err != nil {
		logger.Error("Failed to initialize recipient validator",
			"url", serverCfg.RecipientValidation.URL,
			"error", err)
		os.Exit(1)
	}

	// Wrap in adapter to match smtp.RecipientValidator interface
	adapter := recipient.NewSMTPAdapter(validator)

	logger.Info("Recipient validator initialized",
		"url", serverCfg.RecipientValidation.URL,
		"timeout_seconds", serverCfg.RecipientValidation.HTTPTimeoutSeconds,
		"cache_ttl_seconds", serverCfg.RecipientValidation.CacheTTLSeconds)

	return adapter
}

// runSMTPServerInstance runs a single SMTP server instance
func runSMTPServerInstance(ctx context.Context, serverCfg *config.ServerConfig, be *smtp.Backend, tlsConfig *tls.Config, logger *slog.Logger) {
	server := gosmtp.NewServer(be)
	server.Addr = serverCfg.ListenAddr
	server.Domain = serverCfg.Domain
	server.ReadTimeout = time.Duration(serverCfg.TimeoutSeconds) * time.Second
	server.WriteTimeout = time.Duration(serverCfg.TimeoutSeconds) * time.Second
	server.MaxMessageBytes = int64(serverCfg.MaxMessageSize)
	server.EnableSMTPUTF8 = true

	// Configure authentication for submission servers
	// Note: Authentication is handled in the Backend.Auth() method
	if serverCfg.IsSubmission() {
		server.AllowInsecureAuth = false // Always require TLS for AUTH
	}

	// Configure TLS mode
	// Note: STARTTLS is always available if TLSConfig is set in go-smtp
	if serverCfg.IsTLSEnabled() {
		// Clone TLS config for per-server settings
		serverTLSConfig := tlsConfig.Clone()

		// Apply per-server min TLS version if specified
		if serverCfg.TLS.MinTLSVersion != "" {
			serverTLSConfig.MinVersion = getTLSVersion(serverCfg.TLS.MinTLSVersion)
			logger.Info("Server-specific minimum TLS version",
				"server", serverCfg.Name,
				"min_tls_version", serverCfg.TLS.MinTLSVersion)
		}

		server.TLSConfig = serverTLSConfig
	} else {
		// No TLS (only for testing/internal use)
		server.TLSConfig = nil
	}

	// Create listener
	listener, err := net.Listen("tcp", serverCfg.ListenAddr)
	if err != nil {
		logger.Error("Failed to create listener",
			"server", serverCfg.Name,
			"addr", serverCfg.ListenAddr,
			"error", err)
		return
	}
	defer listener.Close()

	// Start server in background
	serverErrors := make(chan error, 1)
	logging.SafeGo(logger, "smtp-server", func() {
		logger.Info("SMTP server listening",
			"server", serverCfg.Name,
			"type", serverCfg.Type,
			"addr", serverCfg.ListenAddr,
			"tls", serverCfg.TLS.Mode,
			"deferred_handshake", serverCfg.TLS.DeferredHandshake)

		// For implicit TLS (port 465), wrap listener with TLS
		if serverCfg.UsesImplicitTLS() && tlsConfig != nil {
			// Use deferred TLS handshake if enabled to prevent head-of-line blocking
			if serverCfg.TLS.DeferredHandshake {
				// Determine handshake timeout
				handshakeTimeout := time.Duration(serverCfg.TLS.HandshakeTimeoutSecs) * time.Second
				if handshakeTimeout == 0 {
					handshakeTimeout = 10 * time.Second // Default 10 seconds
				}

				tlsListener := tlsmgr.NewDeferredTLSListener(listener, tlsConfig, handshakeTimeout, logger)
				logger.Info("Using deferred TLS handshake for implicit TLS",
					"server", serverCfg.Name,
					"handshake_timeout", handshakeTimeout)
				serverErrors <- server.Serve(tlsListener)
			} else {
				// Traditional synchronous TLS handshake in Accept()
				tlsListener := tls.NewListener(listener, tlsConfig)
				serverErrors <- server.Serve(tlsListener)
			}
		} else {
			serverErrors <- server.Serve(listener)
		}
	})

	// Wait for shutdown or error
	select {
	case <-ctx.Done():
		logger.Info("Shutting down server", "server", serverCfg.Name)

		// Graceful shutdown
		close(be.ShutdownChan)
		listener.Close()

		// Wait for active sessions
		waitDone := make(chan struct{})
		logging.SafeGo(logger, "shutdown-wait", func() {
			be.ActiveSessionsWg.Wait()
			close(waitDone)
		})

		select {
		case <-waitDone:
			logger.Info("Server shut down gracefully", "server", serverCfg.Name)
		case <-time.After(time.Duration(serverCfg.ShutdownTimeoutSeconds) * time.Second):
			logger.Warn("Server shutdown timeout", "server", serverCfg.Name)
		}

		// Shutdown rate limiters and cleanup background goroutines
		if be.AuthRateLimiter != nil {
			be.AuthRateLimiter.Shutdown()
		}
		if be.RateLimiter != nil {
			be.RateLimiter.Shutdown()
		}

	case err := <-serverErrors:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			logger.Error("Server error",
				"server", serverCfg.Name,
				"error", err)
		}
	}
}

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

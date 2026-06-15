package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
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
	"migadu/mizu/pkg/concurrency"
	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/health"
	"migadu/mizu/pkg/logging"
	"migadu/mizu/pkg/metrics"
	"migadu/mizu/pkg/poster"
	"migadu/mizu/pkg/recipient"
	"migadu/mizu/pkg/sender"
	"migadu/mizu/pkg/smtp"
	"migadu/mizu/pkg/stats"
	"migadu/mizu/pkg/storage"
	tlsmgr "migadu/mizu/pkg/tls"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	gosmtp "github.com/emersion/go-smtp"
	proxyproto "github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

	// Setup logging
	logger, logWriter, err := logging.NewLogger(cfg.Logging)
	if err != nil {
		log.Fatalf("Failed to setup logging: %v", err)
	}
	defer logWriter.Close()

	logger.Info("███╗   ███╗██╗███████╗██╗   ██╗")
	logger.Info("████╗ ████║██║╚══███╔╝██║   ██║")
	logger.Info("██╔████╔██║██║  ███╔╝ ██║   ██║")
	logger.Info("██║╚██╔╝██║██║ ███╔╝  ██║   ██║")
	logger.Info("██║ ╚═╝ ██║██║███████╗╚██████╔╝")
	logger.Info("╚═╝     ╚═╝╚═╝╚══════╝ ╚═════╝ ")
	logger.Info("mizu smtp2http server starting", "version", version, "commit", commit, "built", date)
	logger.Info("Logging configuration", "format", cfg.Logging.Format, "level", cfg.Logging.Level)

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Configuration validation failed: %v", err)
	}

	// Normalize S3 prefix: strip leading "/" and ensure trailing "/" if non-empty.
	// Leading "/" creates objects under an empty-named directory in S3.
	// Missing trailing "/" causes "inbound" + "connections/" = "inboundconnections/".
	if cfg.Storage.S3Prefix != "" {
		cfg.Storage.S3Prefix = strings.TrimLeft(cfg.Storage.S3Prefix, "/")
		if cfg.Storage.S3Prefix != "" && !strings.HasSuffix(cfg.Storage.S3Prefix, "/") {
			cfg.Storage.S3Prefix += "/"
		}
		logger.Info("S3 prefix configured", "s3_prefix", cfg.Storage.S3Prefix)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	concurrency.SafeGo(logger, "signal-handler", func() {
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
	var s3Client *s3.Client
	var tlsMgr *tlsmgr.Manager
	var fileCertProvider *tlsmgr.FileCertProvider
	if cfg.Local {
		logger.Info("Running in LOCAL mode - TLS disabled, messages will be dumped to terminal")
	} else {
		logger.Info("Initializing TLS subsystem", "enabled", cfg.TLS.Enabled, "provider", cfg.TLS.Provider)
		tlsConfig, s3Client, tlsMgr, fileCertProvider, err = initTLS(cfg, clusterMgr, logger)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to initialize TLS: %v", err))
			os.Exit(1)
		}
		logger.Info("initTLS completed", "tlsMgr_nil", tlsMgr == nil, "tlsConfig_nil", tlsConfig == nil)

		// Start ACME challenge servers (only for Let's Encrypt)
		if tlsMgr != nil {
			logger.Info("TLS manager initialized successfully - starting ACME challenge servers")
			// Start HTTPS server on port 443 for TLS-ALPN-01 challenges (primary method)
			concurrency.SafeGo(logger, "acme-tls-alpn-server", func() {
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
			concurrency.SafeGo(logger, "acme-http-server", func() {
				logger.Info("Starting HTTP server for ACME HTTP-01 challenges on :80")
				if err := http.ListenAndServe(":80", tlsMgr.HTTPHandler()); err != nil {
					logger.Error("HTTP-01 challenge server failed", "error", err)
				}
			})
		} else {
			logger.Info("TLS manager is nil - ACME challenge servers will NOT start",
				"tls_enabled", cfg.TLS.Enabled,
				"tls_provider", cfg.TLS.Provider,
				"cluster_enabled", cfg.Cluster.Enabled)
		}
	}

	// Handle SIGHUP: reopen log file for newsyslog rotation + reload TLS certificates (file-based).
	hupChan := make(chan os.Signal, 1)
	signal.Notify(hupChan, syscall.SIGHUP)
	concurrency.SafeGo(logger, "sighup-handler", func() {
		defer signal.Stop(hupChan)
		for {
			select {
			case <-hupChan:
				logger.Info("received SIGHUP, reopening log file")
				if err := logWriter.Reopen(); err != nil {
					logger.Error("failed to reopen log file", "error", err)
				}
				if fileCertProvider != nil {
					logger.Info("reloading TLS certificates")
					if err := fileCertProvider.Reload(); err != nil {
						logger.Error("TLS certificate reload failed, keeping previous certificate", "error", err)
					} else {
						logger.Info("TLS certificates reloaded successfully")
					}
				}
			case <-ctx.Done():
				return
			}
		}
	})

	// Initialize and start health check server (before starting SMTP servers)
	// Note: Connection trackers are registered later via AddChecker after server backends are created
	healthServer := startHealthServer(cfg, logger, statsManager, nil, nil, s3Client)

	// Start separate metrics server
	metricsServer := startMetricsServer(cfg, logger)

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
	var successfullyStarted atomic.Int32

	// Start each configured SMTP server instance
	for i := range cfg.Servers {
		serverCfg := &cfg.Servers[i]

		logger.Info("Initializing SMTP server",
			"name", serverCfg.Name,
			"type", serverCfg.Type,
			"listen_addr", serverCfg.ListenAddr,
			"tls", serverCfg.TLS.Mode)

		// Initialize sender validator if enabled for this server
		var senderValidator smtp.SenderValidator
		if serverCfg.SenderValidation.Enabled {
			senderValidator = initSenderValidator(serverCfg, logger)
		}

		// Initialize recipient validator if enabled for this server
		var recipientValidator smtp.RecipientValidator
		if serverCfg.RecipientValidation.Enabled {
			recipientValidator = initRecipientValidator(serverCfg, logger)
		}

		// Create per-server stats recorder (tags events with server name)
		var serverRecorder *stats.ServerRecorder
		if statsManager != nil {
			serverRecorder = stats.NewServerRecorder(
				statsManager,
				serverCfg.Name,
				serverCfg.Reputation.MinIPScore,
				serverCfg.Reputation.MinDomainScore,
			)
		}

		// Create server-specific backend
		backend := createServerBackend(
			serverCfg,
			cfg,
			serverRecorder,
			dnsResolver,
			metricsInstance,
			senderValidator,
			recipientValidator,
			clusterMgr,
			s3Client,
			logger,
		)

		// Register connection tracker as health checker (trackers are created per-server,
		// after the health server, so we use AddChecker to register them lazily)
		if healthServer != nil {
			if backend.DistTracker != nil {
				backend.DistTracker.SetName("distributed_connections:" + serverCfg.Name)
				healthServer.AddChecker(backend.DistTracker)
			} else if backend.ConnTracker != nil {
				backend.ConnTracker.SetName("connection_tracker:" + serverCfg.Name)
				healthServer.AddChecker(backend.ConnTracker)
			}

			// Register auth rate limiter as health checker
			if backend.AuthRateLimiter != nil {
				backend.AuthRateLimiter.SetName("auth_rate_limiter:" + serverCfg.Name)
				healthServer.AddChecker(backend.AuthRateLimiter)
			}
		}

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
		started := &successfullyStarted
		concurrency.SafeGoWithWg(logger, fmt.Sprintf("smtp-server-%s", srvCfg.Name), &serverWg, func() {
			runSMTPServerInstance(srvCtx, srvCfg, be, tlsConfig, logger, started)
		})
	}

	// Wait briefly for servers to start listening
	time.Sleep(100 * time.Millisecond)

	startedCount := successfullyStarted.Load()
	if startedCount == 0 {
		logger.Error("No SMTP servers successfully started")
		os.Exit(1)
	}

	logger.Info(fmt.Sprintf("Started %d SMTP server(s)", startedCount))

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
	concurrency.SafeGo(logger, "shutdown-wait", func() {
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

	// Phase 4: Stop metrics server
	if metricsServer != nil {
		logger.Info("Stopping metrics server...")
		if err := metricsServer.Shutdown(context.Background()); err != nil {
			logger.Error("metrics server shutdown error", "error", err)
		}
	}

	// Phase 5: Stop health server
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
		return stats.NewManager(false, 0, "", false, 0, nil, 0, 0, 0, logger)
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
		cfg.Stats.MaxIPEntries, cfg.Stats.MaxDomainEntries, cfg.Stats.BufferSize, logger)
	logger.Info(fmt.Sprintf("Stats tracking enabled with %v retention, max entries: IPs=%d, Domains=%d, Buffer=%d",
		time.Duration(cfg.Stats.RetentionSeconds)*time.Second, cfg.Stats.MaxIPEntries, cfg.Stats.MaxDomainEntries, cfg.Stats.BufferSize))

	if cfg.Stats.SyncEnabled {
		logger.Info(fmt.Sprintf("Stats sync enabled with %v interval, syncing with %d servers",
			time.Duration(cfg.Stats.SyncIntervalSeconds)*time.Second, len(syncServers)))
	}
	return statsManager
}

// initStorageBackend initializes the storage backend based on configuration (S3 or filesystem)
func initStorageBackend(cfg *config.Config, logger *slog.Logger) (storage.Backend, *s3.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var backend storage.Backend
	var s3Client *s3.Client

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
		logger.Info("Using S3 storage backend", "bucket", cfg.Storage.S3Bucket)
		// Initialize S3 client using AWS SDK v2
		var err error

		awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(cfg.Storage.S3Region),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				cfg.Storage.S3AccessKey,
				cfg.Storage.S3SecretKey,
				"",
			)),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load AWS config: %w", err)
		}

		s3Client = s3.NewFromConfig(awsCfg, func(o *s3.Options) {
			// Custom endpoint resolver for non-AWS S3 services
			if cfg.Storage.S3Endpoint != "" {
				o.BaseEndpoint = aws.String(cfg.Storage.S3Endpoint)
				o.UsePathStyle = true
			}
		})

		s3Backend := storage.NewS3Backend(s3Client, cfg.Storage.S3Bucket, logger)

		// Validate S3 credentials early by checking bucket access
		logger.Info(fmt.Sprintf("Validating S3 access to bucket '%s'...", cfg.Storage.S3Bucket))
		exists, err := s3Backend.BucketExists(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to validate S3 credentials/access: %w (check S3_ACCESS_KEY and S3_SECRET_KEY)", err)
		}
		if !exists {
			// Bucket doesn't exist - try to create it
			logger.Info(fmt.Sprintf("Bucket '%s' does not exist, attempting to create it...", cfg.Storage.S3Bucket))
			if err := s3Backend.MakeBucket(ctx); err != nil {
				return nil, nil, fmt.Errorf("S3 bucket '%s' does not exist and could not be created: %w (ensure credentials have s3:CreateBucket permission)", cfg.Storage.S3Bucket, err)
			}
			logger.Info(fmt.Sprintf("Successfully created S3 bucket '%s'", cfg.Storage.S3Bucket))
		} else {
			logger.Info(fmt.Sprintf("Successfully validated S3 access to bucket '%s'", cfg.Storage.S3Bucket))
		}

		backend = s3Backend

	default:
		return nil, nil, fmt.Errorf("invalid storage backend: %s", cfg.Storage.Backend)
	}

	return backend, s3Client, nil
}

// initTLS sets up the storage backend and TLS certificate management using autocert.
func initTLS(cfg *config.Config, clusterMgr *cluster.Cluster, logger *slog.Logger) (*tls.Config, *s3.Client, *tlsmgr.Manager, *tlsmgr.FileCertProvider, error) {
	// Check if TLS is enabled
	if !cfg.TLS.Enabled {
		logger.Info("TLS management disabled in configuration")
		return nil, nil, nil, nil, nil
	}

	storageBackend, s3Client, err := initStorageBackend(cfg, logger)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	var tlsConfig *tls.Config
	var tlsMgr *tlsmgr.Manager

	// Handle different TLS providers
	switch cfg.TLS.Provider {
	case "file":
		// Load certificates from files via FileCertProvider (supports SIGHUP reload)
		if cfg.TLS.File.CertFile == "" || cfg.TLS.File.KeyFile == "" {
			return nil, nil, nil, nil, fmt.Errorf("tls.file.cert_file and tls.file.key_file are required when provider=file")
		}
		fileCertProvider, err := tlsmgr.NewFileCertProvider(cfg.TLS.File.CertFile, cfg.TLS.File.KeyFile, logger)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		tlsConfig = &tls.Config{
			GetCertificate: fileCertProvider.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		}
		return tlsConfig, s3Client, nil, fileCertProvider, nil

	case "letsencrypt":
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
		if cfg.TLS.LetsEncrypt.RenewBeforeDays > 0 {
			renewBefore = time.Duration(cfg.TLS.LetsEncrypt.RenewBeforeDays) * 24 * time.Hour
		}

		// Calculate sync interval
		var syncInterval time.Duration
		if cfg.TLS.LetsEncrypt.SyncIntervalMinutes > 0 {
			syncInterval = time.Duration(cfg.TLS.LetsEncrypt.SyncIntervalMinutes) * time.Minute
		} else if cfg.TLS.LetsEncrypt.SyncIntervalMinutes == 0 && cfg.TLS.LetsEncrypt.FallbackCacheDir != "" {
			// Default to 5 minutes if fallback cache is enabled but interval not specified
			syncInterval = 5 * time.Minute
		}

		// Build storage prefix for certificates (append "certs/" to base prefix).
		// Guard against duplication if s3_prefix already ends with "certs/".
		certStoragePrefix := cfg.Storage.S3Prefix + "certs/"
		if strings.HasSuffix(cfg.Storage.S3Prefix, "certs/") {
			certStoragePrefix = cfg.Storage.S3Prefix
		}

		// Create TLS manager with autocert using storage backend abstraction
		tlsMgr, err = tlsmgr.NewManager(tlsmgr.Config{
			Enabled:        true,
			Email:          cfg.TLS.LetsEncrypt.Email,
			Domains:        cfg.TLS.LetsEncrypt.Domains,
			DefaultDomain:  cfg.TLS.LetsEncrypt.DefaultDomain,
			StorageBackend: storageBackend,
			StoragePrefix:  certStoragePrefix,
			IsLeaderF:      isLeaderF,
			Staging:        cfg.TLS.LetsEncrypt.Staging,
			RenewBefore:    renewBefore,
			FallbackDir:    cfg.TLS.LetsEncrypt.FallbackCacheDir,
			SyncInterval:   syncInterval,
		}, logger)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to create TLS manager: %w", err)
		}

		tlsConfig = tlsMgr.TLSConfig()
		if tlsConfig == nil {
			return nil, nil, nil, nil, fmt.Errorf("TLS manager returned nil config")
		}

		logger.Info(fmt.Sprintf("Autocert initialized for domains: %v", cfg.TLS.LetsEncrypt.Domains))

		// Set default minimum TLS version (can be overridden per-server)
		tlsConfig.MinVersion = tls.VersionTLS12

		// Clear HTTP-specific ALPN protocols set by autocert.TLSConfig().
		// autocert sets NextProtos to ["h2", "http/1.1", "acme-tls/1"] which are
		// appropriate for HTTPS but incorrect for SMTP. Advertising HTTP ALPN on
		// an SMTP connection can cause strict clients (e.g. Exchange Online) to
		// abort the TLS handshake. The ACME TLS-ALPN-01 challenges are handled
		// by the dedicated HTTPS server on port 443, not the SMTP servers.
		tlsConfig.NextProtos = nil

		// Disable TLS session tickets for SMTP.
		// Go's TLS 1.3 implementation sends NewSessionTicket messages after the
		// handshake completes. Some SMTP clients (notably Exchange Online/Outlook)
		// don't expect post-handshake data and interpret it as a protocol error,
		// closing the connection with EOF. Session ticket resumption provides
		// minimal benefit for SMTP (connections are typically short-lived) and
		// disabling it fixes compatibility with these clients.
		tlsConfig.SessionTicketsDisabled = true

		logger.Info("Default TLS configuration ready (per-server min version can be set in [server.tls])")

		return tlsConfig, s3Client, tlsMgr, nil, nil

	default:
		return nil, nil, nil, nil, fmt.Errorf("unknown TLS provider: %s (must be 'file' or 'letsencrypt')", cfg.TLS.Provider)
	}
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
func startHealthServer(cfg *config.Config, logger *slog.Logger, statsManager *stats.Manager, connTracker *smtp.ConnectionTracker, distTracker *smtp.DistributedTracker, s3Client *s3.Client) *health.Server {
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
		checkers = append(checkers, health.NewCheckS3Connection(s3Client, cfg.Storage.S3Bucket))
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
	// Check TLS certificates only for servers with implicit TLS (e.g. port 465).
	// STARTTLS ports (25, 587) cannot be checked with tls.Dial - they require
	// a plaintext SMTP greeting followed by STARTTLS upgrade.
	if !cfg.Local {
		for _, srv := range cfg.Servers {
			if srv.Hostname != "" && srv.Hostname != "mail.yourdomain.com" && srv.UsesImplicitTLS() {
				_, portStr, err := net.SplitHostPort(srv.ListenAddr)
				if err != nil {
					logger.Warn("Could not parse listen address for health check",
						"server", srv.Name,
						"error", err)
					continue
				}
				port, _ := net.LookupPort("tcp", portStr)
				if port > 0 {
					checkers = append(checkers, health.NewCheckTLSCertificate(srv.Hostname, port, 14*24*time.Hour))
				}
			}
		}
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

	// Set stats provider
	healthServer.SetStatsProvider(statsManager)

	// Set cache flusher (if distributed tracker exists)
	if distTracker != nil {
		healthServer.SetCacheFlusher(distTracker)
	}

	healthServer.Start()
	return healthServer
}

// basicAuthMiddlewareHandler wraps an http.Handler with HTTP Basic Auth.
func basicAuthMiddlewareHandler(next http.Handler, username, password, realm string, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqUser, reqPass, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(reqUser), []byte(username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(reqPass), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			if ok {
				logger.Warn("metrics auth failed", "remote_addr", r.RemoteAddr)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

// startMetricsServer creates a separate HTTP server for Prometheus metrics.
func startMetricsServer(cfg *config.Config, logger *slog.Logger) *http.Server {
	if !cfg.Metrics.Enabled {
		return nil
	}

	mux := http.NewServeMux()

	var metricsHandler http.Handler = promhttp.Handler()

	// Optional basic auth for metrics
	if cfg.Metrics.Username != "" {
		metricsHandler = basicAuthMiddlewareHandler(metricsHandler, cfg.Metrics.Username, cfg.Metrics.Password, "Metrics", logger)
	}

	metricsPath := cfg.Metrics.Path
	if metricsPath == "" {
		metricsPath = "/metrics"
	}
	mux.Handle(metricsPath, metricsHandler)

	bind := cfg.Metrics.Bind
	if bind == "" {
		bind = ":9091"
	}

	server := &http.Server{
		Addr:         bind,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	concurrency.SafeGo(logger, "metrics-server", func() {
		logger.Info("metrics server starting", "addr", bind, "path", metricsPath, "auth_enabled", cfg.Metrics.Username != "")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server failed", "error", err)
		}
	})

	return server
}

// startStatsLoops starts the background loops for exporting and syncing stats data.
func startStatsLoops(ctx context.Context, statsMgr *stats.Manager, s3Client *s3.Client, cfg *config.Config, logger *slog.Logger) {
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

	// Start export loop (use stats/ subdirectory).
	// Guard against duplication if s3_prefix already ends with "stats/".
	statsPrefix := cfg.Storage.S3Prefix + "stats/"
	if strings.HasSuffix(cfg.Storage.S3Prefix, "stats/") {
		statsPrefix = cfg.Storage.S3Prefix
	}
	concurrency.SafeGo(logger, "stats-export-loop", func() {
		statsMgr.StartExportLoop(ctx, s3Client, cfg.Storage.S3Bucket, statsPrefix,
			hostname, time.Duration(cfg.Stats.SyncIntervalSeconds)*time.Second)
	})

	// Start sync loop
	concurrency.SafeGo(logger, "stats-sync-loop", func() {
		statsMgr.StartSyncLoop(ctx, s3Client, cfg.Storage.S3Bucket, statsPrefix,
			time.Duration(cfg.Stats.SyncIntervalSeconds)*time.Second)
	})
}

// createServerBackend creates a Backend instance for a specific server
func createServerBackend(
	serverCfg *config.ServerConfig,
	globalCfg *config.Config,
	statsRecorder *stats.ServerRecorder,
	dnsResolver *net.Resolver,
	metricsInstance *metrics.Metrics,
	senderValidator smtp.SenderValidator,
	recipientValidator smtp.RecipientValidator,
	clusterMgr *cluster.Cluster,
	s3Client *s3.Client,
	logger *slog.Logger,
) *smtp.Backend {
	// Create server-specific logger
	serverLogger := logger.With(
		"server_name", serverCfg.Name,
		"server_type", serverCfg.Type,
	)

	// Create per-server connection tracker with max connection duration for leak protection.
	// Default to 300s (5 minutes) if not configured (0).
	maxConnDuration := time.Duration(serverCfg.Limits.MaxConnectionDurationSeconds) * time.Second
	if serverCfg.Limits.MaxConnectionDurationSeconds == 0 {
		maxConnDuration = 5 * time.Minute // Default: 5 minutes
	}
	connTracker := smtp.NewConnectionTracker(serverCfg.Limits.MaxConnections, serverCfg.Limits.MaxConnectionsPerIP, maxConnDuration, serverLogger)
	connTracker.SetServerName(serverCfg.Name)
	connTracker.Start()

	// Register connection tracker with stats manager for active connection monitoring
	if statsRecorder != nil {
		statsRecorder.Manager().RegisterConnectionTracker(connTracker)
	}

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

		// Use connections/ subdirectory for distributed tracking.
		// Guard against duplication if s3_prefix already ends with "connections/".
		connectionsPrefix := globalCfg.Storage.S3Prefix + "connections/"
		if strings.HasSuffix(globalCfg.Storage.S3Prefix, "connections/") {
			connectionsPrefix = globalCfg.Storage.S3Prefix
		}
		distTracker = smtp.NewDistributedTracker(
			connTracker,
			s3Client,
			globalCfg.Storage.S3Bucket,
			connectionsPrefix,
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
		distTracker.SetServerName(serverCfg.Name)
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

	serverHTTPClient := poster.NewHTTPClient(
		time.Duration(serverCfg.Delivery.HTTPTimeoutSeconds)*time.Second,
		serverCfg.Delivery.MaxIdleConnsPerHost,
		serverCfg.Delivery.MaxConnsPerHost,
		time.Duration(serverCfg.Delivery.IdleConnTimeoutSeconds)*time.Second,
	)
	serverLogger.Info("HTTP client created",
		"timeout_seconds", serverCfg.Delivery.HTTPTimeoutSeconds,
		"max_idle_conns_per_host", serverCfg.Delivery.MaxIdleConnsPerHost,
		"max_conns_per_host", serverCfg.Delivery.MaxConnsPerHost)

	// Create Backend
	var activeSessionsWg sync.WaitGroup
	var activeSessionCount atomic.Int64
	shutdownChan := make(chan struct{})

	return &smtp.Backend{
		ServerConfig:       serverCfg,
		GlobalConfig:       globalCfg,
		StatsManager:       statsRecorder,
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
		SenderValidator:    senderValidator,
		RecipientValidator: recipientValidator,
	}
}

// initAuthenticator initializes an HTTP authenticator for submission servers
func initAuthenticator(serverCfg *config.ServerConfig, logger *slog.Logger) smtp.Authenticator {
	if serverCfg.Auth.URL == "" {
		logger.Error("Authentication requires auth.url")
		os.Exit(1)
	}

	// Initialize auth cache
	var authCache *smtp.AuthCache
	cacheCfg := serverCfg.Auth.Cache

	// Enable auth cache by default for security (brute force protection)
	// If no cache config is specified, enable it with defaults
	// If user explicitly sets enabled=false, respect that (but warn them)
	cacheConfigSpecified := cacheCfg.PositiveTTL != "" || cacheCfg.NegativeTTL != "" ||
		cacheCfg.MaxSize > 0 || cacheCfg.CleanupInterval != "" ||
		cacheCfg.PositiveRevalidationWindow != ""

	if !cacheCfg.Enabled && !cacheConfigSpecified {
		// No cache config at all - enable by default
		cacheCfg.Enabled = true
		logger.Info("Auth cache enabled by default for brute force protection")
	}

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
	} else {
		logger.Warn("Auth cache is DISABLED - no brute force protection",
			"warning", "Every failed authentication attempt will hit the backend API",
			"recommendation", "Enable auth cache for production deployments to prevent password guessing attacks",
			"config", "Set [server.auth.cache] enabled = true")
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

// initSenderValidator initializes a sender validator for a server
func initSenderValidator(serverCfg *config.ServerConfig, logger *slog.Logger) smtp.SenderValidator {
	if serverCfg.SenderValidation.URL == "" {
		logger.Error("Sender validation requires sender_validation.url")
		os.Exit(1)
	}

	validator, err := sender.NewValidator(sender.ValidatorConfig{
		URL:                serverCfg.SenderValidation.URL,
		AuthToken:          serverCfg.SenderValidation.AuthToken,
		HTTPTimeoutSeconds: serverCfg.SenderValidation.HTTPTimeoutSeconds,
		CacheTTLSeconds:    serverCfg.SenderValidation.CacheTTLSeconds,
		Logger:             logger,
	})
	if err != nil {
		logger.Error("Failed to initialize sender validator",
			"url", serverCfg.SenderValidation.URL,
			"error", err)
		os.Exit(1)
	}

	// Wrap in adapter to match smtp.SenderValidator interface
	adapter := sender.NewSMTPAdapter(validator)

	logger.Info("Sender validator initialized",
		"url", serverCfg.SenderValidation.URL,
		"timeout_seconds", serverCfg.SenderValidation.HTTPTimeoutSeconds,
		"cache_ttl_seconds", serverCfg.SenderValidation.CacheTTLSeconds)

	return adapter
}

// runSMTPServerInstance runs a single SMTP server instance
func runSMTPServerInstance(ctx context.Context, serverCfg *config.ServerConfig, be *smtp.Backend, tlsConfig *tls.Config, logger *slog.Logger, successCounter *atomic.Int32) {
	server := gosmtp.NewServer(be)
	server.Addr = serverCfg.ListenAddr
	server.Domain = serverCfg.Hostname
	server.ReadTimeout = time.Duration(serverCfg.TimeoutSeconds) * time.Second
	server.WriteTimeout = time.Duration(serverCfg.TimeoutSeconds) * time.Second
	server.MaxMessageBytes = int64(serverCfg.MaxMessageSize)
	server.EnableSMTPUTF8 = true

	// Enable debug logging if configured
	if serverCfg.Debug {
		server.Debug = &smtpDebugWriter{logger: logger, serverName: serverCfg.Name}
		logger.Info("SMTP protocol debug logging enabled", "server", serverCfg.Name)
	}
	// Always enable error logging
	server.ErrorLog = &smtpErrorLogger{logger: logger, serverName: serverCfg.Name}

	// Configure authentication for submission servers
	// Note: Authentication is handled in the Backend.Auth() method
	if serverCfg.IsSubmission() {
		server.AllowInsecureAuth = false // Always require TLS for AUTH
	}

	// Configure TLS mode
	// Note: STARTTLS is always available if TLSConfig is set in go-smtp
	if serverCfg.IsTLSEnabled() {
		// Check if global TLS config is available
		if tlsConfig == nil {
			logger.Error("Server has TLS enabled but global TLS is not configured",
				"server", serverCfg.Name,
				"hint", "Set tls.enabled=true and configure tls.provider in config")
			return
		}

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
		logger.Info("TLS configured for SMTP server",
			"server", serverCfg.Name,
			"mode", serverCfg.TLS.Mode,
			"required", serverCfg.TLS.Required,
			"starttls_enabled", serverCfg.UsesSTARTTLS(),
			"implicit_tls", serverCfg.UsesImplicitTLS())
	} else {
		// No TLS (only for testing/internal use)
		server.TLSConfig = nil
		logger.Warn("TLS disabled for SMTP server (not recommended for production)",
			"server", serverCfg.Name)
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

	// Wrap with PROXY protocol listener if enabled
	if serverCfg.ProxyProtocol {
		// Build trusted subnet list for policy enforcement
		var trustedNets []*net.IPNet
		for _, entry := range serverCfg.ProxyProtocolTrusted {
			if _, cidr, err := net.ParseCIDR(entry); err == nil {
				trustedNets = append(trustedNets, cidr)
			} else if ip := net.ParseIP(entry); ip != nil {
				// Convert single IP to /32 or /128
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				trustedNets = append(trustedNets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			}
		}

		listener = &proxyproto.Listener{
			Listener: listener,
			Policy: func(upstream net.Addr) (proxyproto.Policy, error) {
				tcpAddr, ok := upstream.(*net.TCPAddr)
				if !ok {
					return proxyproto.REJECT, nil
				}
				for _, n := range trustedNets {
					if n.Contains(tcpAddr.IP) {
						return proxyproto.REQUIRE, nil
					}
				}
				return proxyproto.REJECT, nil
			},
		}
		logger.Info("PROXY protocol enabled",
			"server", serverCfg.Name,
			"addr", serverCfg.ListenAddr,
			"trusted", serverCfg.ProxyProtocolTrusted)
	}

	// Mark server as successfully started
	successCounter.Add(1)

	// Start server in background
	serverErrors := make(chan error, 1)
	concurrency.SafeGo(logger, "smtp-server", func() {
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

		// Graceful shutdown - ShutdownChan is closed by main shutdown coordinator
		listener.Close()

		// Wait for active sessions
		waitDone := make(chan struct{})
		concurrency.SafeGo(logger, "shutdown-wait", func() {
			be.ActiveSessionsWg.Wait()
			close(waitDone)
		})

		select {
		case <-waitDone:
			logger.Info("Server shut down gracefully", "server", serverCfg.Name)
		case <-time.After(time.Duration(serverCfg.ShutdownTimeoutSeconds) * time.Second):
			logger.Warn("Server shutdown timeout", "server", serverCfg.Name)
		}

		// Shutdown rate limiters, connection tracker reaper, and cleanup background goroutines
		if be.AuthRateLimiter != nil {
			be.AuthRateLimiter.Shutdown()
		}
		if be.RateLimiter != nil {
			be.RateLimiter.Shutdown()
		}
		if be.DistTracker != nil {
			be.DistTracker.Stop()
		}
		if be.ConnTracker != nil {
			be.ConnTracker.Stop()
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

// smtpDebugWriter wraps slog.Logger for go-smtp Debug output
type smtpDebugWriter struct {
	logger     *slog.Logger
	serverName string
}

func (w *smtpDebugWriter) Write(p []byte) (n int, err error) {
	msg := string(p)
	// Remove trailing newline if present
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}
	w.logger.Info("SMTP protocol", "server", w.serverName, "message", msg)
	return len(p), nil
}

// smtpErrorLogger wraps slog.Logger for go-smtp ErrorLog.
// It classifies errors: benign connection lifecycle events (EOF, reset, timeout)
// are logged at DEBUG level to avoid log noise, while genuine errors use ERROR.
type smtpErrorLogger struct {
	logger     *slog.Logger
	serverName string
}

// containsBenignError inspects the variadic arguments passed by go-smtp's
// ErrorLog for well-known benign error types. This uses errors.Is / type
// assertions on the actual error values rather than fragile string matching.
//
// Benign errors are normal connection lifecycle events:
//   - io.EOF: client disconnected (port scanners, health probes, normal close)
//   - syscall.ECONNRESET: client forcefully closed the connection
//   - syscall.EPIPE: writing to a connection the client already closed
//   - os.ErrDeadlineExceeded: idle/session timeout expired (expected)
//   - net.ErrClosed: connection used after close (race during shutdown)
func containsBenignError(args []interface{}) bool {
	for _, arg := range args {
		err, ok := arg.(error)
		if !ok {
			continue
		}
		if errors.Is(err, io.EOF) ||
			errors.Is(err, syscall.ECONNRESET) ||
			errors.Is(err, syscall.EPIPE) ||
			errors.Is(err, os.ErrDeadlineExceeded) ||
			errors.Is(err, net.ErrClosed) {
			return true
		}
	}
	return false
}

func (l *smtpErrorLogger) Printf(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	if containsBenignError(v) {
		l.logger.Debug("SMTP connection closed", "server", l.serverName, "message", msg)
		return
	}
	// STARTTLS success/failure are informational, not errors
	if strings.HasPrefix(msg, "STARTTLS ") {
		l.logger.Info(msg, "server", l.serverName)
		return
	}
	l.logger.Error("SMTP error", "server", l.serverName, "message", msg)
}

func (l *smtpErrorLogger) Println(v ...interface{}) {
	if containsBenignError(v) {
		l.logger.Debug("SMTP connection closed", "server", l.serverName, "message", fmt.Sprint(v...))
		return
	}
	l.logger.Error("SMTP error", "server", l.serverName, "message", fmt.Sprint(v...))
}

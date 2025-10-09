package health

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"migadu/mizu/pkg/logging"
	"net/http"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Checker defines an interface for components that can report their health status.
type Checker interface {
	Name() string
	CheckHealth() ComponentStatus
}

// ComponentStatus represents the health of a single component.
type ComponentStatus struct {
	Status  string `json:"status"`
	Details any    `json:"details,omitempty"`
}

// StatsProvider defines an interface for components that can provide statistics
type StatsProvider interface {
	GetStats() any
}

// CacheFlusher defines an interface for components that can flush their caches
type CacheFlusher interface {
	FlushCache() map[string]int
}

// DLQProvider defines an interface for accessing the dead letter queue
type DLQProvider interface {
	GetDLQEntries(limit int) (any, error)
	GetDLQEntry(jobID string) (any, error)
	ReprocessDLQJob(jobID string) error
	DeleteDLQEntry(jobID string) error
}

// Server represents the health check HTTP server.
type Server struct {
	listenAddr      string
	logger          *zap.Logger
	checkers        []Checker
	statsProvider   StatsProvider
	cacheFlusher    CacheFlusher
	dlqProvider     DLQProvider
	httpServer      *http.Server
	mux             *http.ServeMux
	username        string // HTTP Basic Auth username (empty = no auth)
	password        string // HTTP Basic Auth password
	acmeHandler     http.Handler
	metricsEnabled  bool   // Enable Prometheus metrics endpoint
	metricsPath     string // Metrics endpoint path
	metricsUsername string // Metrics HTTP Basic Auth username (empty = no auth)
	metricsPassword string // Metrics HTTP Basic Auth password
}

// NewServer creates a new health check server.
func NewServer(listenAddr string, logger *zap.Logger, checkers ...Checker) *Server {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Server{
		listenAddr: listenAddr,
		logger:     logger,
		checkers:   checkers,
	}
}

// SetStatsProvider registers a stats provider for the /api/stats endpoint
func (s *Server) SetStatsProvider(provider StatsProvider) {
	s.statsProvider = provider
}

// SetCacheFlusher registers a cache flusher for the /api/flush-cache endpoint
func (s *Server) SetCacheFlusher(flusher CacheFlusher) {
	s.cacheFlusher = flusher
}

// SetDLQProvider registers a DLQ provider for the /api/dlq/* endpoints
func (s *Server) SetDLQProvider(provider DLQProvider) {
	s.dlqProvider = provider
}

// SetACMEHandler registers an HTTP handler for the ACME challenge
func (s *Server) SetACMEHandler(handler http.Handler) {
	s.acmeHandler = handler
}

// SetBasicAuth configures HTTP Basic Authentication for the health endpoint
func (s *Server) SetBasicAuth(username, password string) {
	s.username = username
	s.password = password
	if username != "" {
		s.logger.Info("HTTP Basic Auth enabled for health endpoint")
	}
}

// SetMetricsConfig configures Prometheus metrics endpoint
func (s *Server) SetMetricsConfig(enabled bool, path, username, password string) {
	s.metricsEnabled = enabled
	s.metricsPath = path
	s.metricsUsername = username
	s.metricsPassword = password
	if enabled {
		s.logger.Info("Prometheus metrics endpoint enabled",
			zap.String("path", path),
			zap.Bool("auth_enabled", username != ""))
	}
}

// basicAuthMiddleware wraps a handler with HTTP Basic Auth
func (s *Server) basicAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return s.basicAuthMiddlewareWithCreds(next, s.username, s.password, "Health Check")
}

// metricsAuthMiddleware wraps a handler with HTTP Basic Auth for metrics endpoint
func (s *Server) metricsAuthMiddleware(next http.Handler) http.Handler {
	return s.basicAuthMiddlewareWithCredsHandler(next, s.metricsUsername, s.metricsPassword, "Metrics")
}

// basicAuthMiddlewareWithCreds creates auth middleware with custom credentials
func (s *Server) basicAuthMiddlewareWithCreds(next http.HandlerFunc, username, password, realm string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip auth if no username configured
		if username == "" {
			next(w, r)
			return
		}

		// Get credentials from request
		reqUsername, reqPassword, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			s.logger.Warn("Access denied - no credentials provided",
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("path", r.URL.Path),
				zap.String("realm", realm))
			return
		}

		// Use constant-time comparison to prevent timing attacks
		usernameMatch := subtle.ConstantTimeCompare([]byte(reqUsername), []byte(username)) == 1
		passwordMatch := subtle.ConstantTimeCompare([]byte(reqPassword), []byte(password)) == 1

		if !usernameMatch || !passwordMatch {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			s.logger.Warn("Access denied - invalid credentials",
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("username", reqUsername),
				zap.String("path", r.URL.Path),
				zap.String("realm", realm))
			return
		}

		// Credentials valid, proceed
		next(w, r)
	}
}

// basicAuthMiddlewareWithCredsHandler creates auth middleware for http.Handler
func (s *Server) basicAuthMiddlewareWithCredsHandler(next http.Handler, username, password, realm string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth if no username configured
		if username == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Get credentials from request
		reqUsername, reqPassword, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			s.logger.Warn("Access denied - no credentials provided",
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("path", r.URL.Path),
				zap.String("realm", realm))
			return
		}

		// Use constant-time comparison to prevent timing attacks
		usernameMatch := subtle.ConstantTimeCompare([]byte(reqUsername), []byte(username)) == 1
		passwordMatch := subtle.ConstantTimeCompare([]byte(reqPassword), []byte(password)) == 1

		if !usernameMatch || !passwordMatch {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			s.logger.Warn("Access denied - invalid credentials",
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("username", reqUsername),
				zap.String("path", r.URL.Path),
				zap.String("realm", realm))
			return
		}

		// Credentials valid, proceed
		next.ServeHTTP(w, r)
	})
}

// RegisterHandler registers an additional HTTP handler
func (s *Server) RegisterHandler(pattern string, handler http.HandlerFunc) {
	if s.mux != nil {
		s.mux.HandleFunc(pattern, handler)
	}
}

// Start runs the HTTP server in a new goroutine.
func (s *Server) Start() {
	s.mux = http.NewServeMux()

	// Register ACME handler if provided
	if s.acmeHandler != nil {
		s.mux.Handle("/.well-known/acme-challenge/", s.acmeHandler)
		s.logger.Info("ACME HTTP-01 challenge handler registered")
	}

	// Wrap all handlers with Basic Auth middleware
	s.mux.HandleFunc("/health", s.basicAuthMiddleware(s.healthHandler))
	s.mux.HandleFunc("/api/stats", s.basicAuthMiddleware(s.statsHandler))
	s.mux.HandleFunc("/api/flush-cache", s.basicAuthMiddleware(s.flushCacheHandler))
	s.mux.HandleFunc("/api/dlq", s.basicAuthMiddleware(s.dlqHandler))
	s.mux.HandleFunc("/api/dlq/", s.basicAuthMiddleware(s.dlqHandler))

	// Prometheus metrics endpoint (optional auth based on config)
	if s.metricsEnabled {
		metricsPath := s.metricsPath
		if metricsPath == "" {
			metricsPath = "/metrics"
		}
		s.mux.Handle(metricsPath, s.metricsAuthMiddleware(s.metricsHandler()))
		s.logger.Info("Metrics endpoint registered", zap.String("path", metricsPath))
	}

	s.httpServer = &http.Server{
		Addr:    s.listenAddr,
		Handler: s.mux,
	}

	s.logger.Sugar().Infof("Starting health check server on %s", s.listenAddr)
	logging.SafeGo(s.logger, "health-server", func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("Health check server error", zap.Error(err))
		}
	})
}

// Stop gracefully shuts down the HTTP server.
func (s *Server) Stop(ctx context.Context) {
	if s.httpServer != nil {
		s.logger.Info("Stopping health check server")
		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.logger.Error("Health check server shutdown error", zap.Error(err))
		}
	}
}

// healthHandler is the HTTP handler for the /health endpoint.
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	overallStatus := "healthy"
	httpStatusCode := http.StatusOK

	componentStatus := make(map[string]ComponentStatus)

	// Create a channel to collect results from concurrent checks.
	// The buffer size is equal to the number of checkers to prevent goroutines from blocking.
	resultsChan := make(chan struct {
		Name   string
		Status ComponentStatus
	}, len(s.checkers))

	for _, checker := range s.checkers {
		c := checker // Capture loop variable
		logging.SafeGo(s.logger, "health-checker-"+c.Name(), func() {
			status := c.CheckHealth()
			resultsChan <- struct {
				Name   string
				Status ComponentStatus
			}{c.Name(), status}
		})
	}

	// Collect results from all checkers and determine the overall status.
	for i := 0; i < len(s.checkers); i++ {
		res := <-resultsChan
		componentStatus[res.Name] = res.Status
		if res.Status.Status == "unhealthy" {
			overallStatus = "unhealthy" // If any component is unhealthy, the overall status is unhealthy.
		}
	}

	if overallStatus != "healthy" {
		httpStatusCode = http.StatusServiceUnavailable
	}

	response := map[string]any{
		"status":     overallStatus,
		"components": componentStatus,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatusCode)
	json.NewEncoder(w).Encode(response)
}

// CheckDestination checks if the HTTP destination endpoint is reachable.
type CheckDestination struct {
	URL        string
	Timeout    time.Duration
	httpClient *http.Client
}

// NewCheckDestination creates a new destination health checker.
func NewCheckDestination(url string, timeout time.Duration) *CheckDestination {
	return &CheckDestination{
		URL:     url,
		Timeout: timeout,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// CheckS3Connection checks if the S3 bucket is accessible.
type CheckS3Connection struct {
	S3Client   *minio.Client
	BucketName string
}

// NewCheckS3Connection creates a new S3 connection health checker.
func NewCheckS3Connection(s3Client *minio.Client, bucketName string) *CheckS3Connection {
	return &CheckS3Connection{
		S3Client:   s3Client,
		BucketName: bucketName,
	}
}

func (c *CheckS3Connection) Name() string { return "s3_connection" }

func (c *CheckS3Connection) CheckHealth() ComponentStatus {
	if c.S3Client == nil {
		return ComponentStatus{
			Status:  "disabled",
			Details: "S3 client not initialized (local mode?)",
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	exists, err := c.S3Client.BucketExists(ctx, c.BucketName)
	latency := time.Since(start)

	if err != nil {
		return ComponentStatus{
			Status: "unhealthy",
			Details: map[string]any{
				"error":   "failed to check S3 bucket: " + err.Error(),
				"latency": latency.String(),
			},
		}
	}

	if !exists {
		return ComponentStatus{
			Status: "unhealthy",
			Details: map[string]any{
				"error":   fmt.Sprintf("S3 bucket '%s' does not exist", c.BucketName),
				"latency": latency.String(),
			},
		}
	}

	return ComponentStatus{
		Status: "healthy",
		Details: map[string]any{
			"bucket":  c.BucketName,
			"latency": latency.String(),
		},
	}
}

func (c *CheckDestination) Name() string { return "destination" }

func (c *CheckDestination) CheckHealth() ComponentStatus {
	// Perform HEAD request to check if endpoint is reachable
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "HEAD", c.URL, nil)
	if err != nil {
		return ComponentStatus{
			Status:  "unhealthy",
			Details: map[string]string{"error": "failed to create request: " + err.Error()},
		}
	}

	start := time.Now()
	resp, err := c.httpClient.Do(req)
	latency := time.Since(start)

	if err != nil {
		return ComponentStatus{
			Status: "unhealthy",
			Details: map[string]any{
				"error":   "destination unreachable: " + err.Error(),
				"latency": latency.String(),
			},
		}
	}
	defer resp.Body.Close()

	// Accept any non-5xx status code (destination might return 404/405 for HEAD, that's ok)
	if resp.StatusCode >= 500 {
		return ComponentStatus{
			Status: "unhealthy",
			Details: map[string]any{
				"error":       fmt.Sprintf("destination returned %d", resp.StatusCode),
				"status_code": resp.StatusCode,
				"latency":     latency.String(),
			},
		}
	}

	// Warn if latency is high
	status := "healthy"
	if latency > 2*time.Second {
		status = "degraded"
	}

	return ComponentStatus{
		Status: status,
		Details: map[string]any{
			"status_code": resp.StatusCode,
			"latency":     latency.String(),
		},
	}
}

// CheckTLSCertificate checks if TLS certificate is valid and not expiring soon.
type CheckTLSCertificate struct {
	Domain        string
	Port          int
	WarnThreshold time.Duration // Warn if cert expires within this duration
}

// NewCheckTLSCertificate creates a new TLS certificate health checker.
func NewCheckTLSCertificate(domain string, port int, warnThreshold time.Duration) *CheckTLSCertificate {
	return &CheckTLSCertificate{
		Domain:        domain,
		Port:          port,
		WarnThreshold: warnThreshold,
	}
}

func (c *CheckTLSCertificate) Name() string { return "tls_certificate" }

func (c *CheckTLSCertificate) CheckHealth() ComponentStatus {
	addr := fmt.Sprintf("%s:%d", c.Domain, c.Port)
	// Connect to the domain to get certificate
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName: c.Domain,
	})
	if err != nil {
		return ComponentStatus{
			Status: "unhealthy",
			Details: map[string]string{
				"error": "failed to connect for certificate check: " + err.Error(),
			},
		}
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return ComponentStatus{
			Status:  "unhealthy",
			Details: map[string]string{"error": "no certificates found"},
		}
	}

	// Check the first certificate (leaf certificate)
	cert := certs[0]
	now := time.Now()

	// Check if certificate is expired
	if now.After(cert.NotAfter) {
		return ComponentStatus{
			Status: "unhealthy",
			Details: map[string]any{
				"error":      "certificate expired",
				"expired_at": cert.NotAfter.Format(time.RFC3339),
				"days_ago":   int(now.Sub(cert.NotAfter).Hours() / 24),
			},
		}
	}

	// Check if certificate is not yet valid
	if now.Before(cert.NotBefore) {
		return ComponentStatus{
			Status: "unhealthy",
			Details: map[string]any{
				"error":      "certificate not yet valid",
				"valid_from": cert.NotBefore.Format(time.RFC3339),
			},
		}
	}

	timeUntilExpiry := cert.NotAfter.Sub(now)
	daysUntilExpiry := int(timeUntilExpiry.Hours() / 24)

	// Warn if expiring soon
	status := "healthy"
	if timeUntilExpiry < c.WarnThreshold {
		status = "degraded"
	}

	return ComponentStatus{
		Status: status,
		Details: map[string]any{
			"subject":           cert.Subject.CommonName,
			"issuer":            cert.Issuer.CommonName,
			"valid_from":        cert.NotBefore.Format(time.RFC3339),
			"valid_until":       cert.NotAfter.Format(time.RFC3339),
			"days_until_expiry": daysUntilExpiry,
		},
	}
}

// statsHandler handles /api/stats requests
func (s *Server) statsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.statsProvider == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"ips":     map[string]any{},
			"domains": map[string]any{},
			"summary": map[string]any{
				"total_ips":         0,
				"total_domains":     0,
				"blocked_ips":       0,
				"total_connections": 0,
				"total_messages":    0,
				"accepted_messages": 0,
				"rejected_messages": 0,
			},
		})
		return
	}

	stats := s.statsProvider.GetStats()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}

// flushCacheHandler handles /api/flush-cache requests
func (s *Server) flushCacheHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.cacheFlusher == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"error":   "Cache flushing not configured",
			"message": "Server does not have cache flushing capability enabled",
		})
		return
	}

	flushed := s.cacheFlusher.FlushCache()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "success",
		"message": "Caches flushed successfully",
		"flushed": flushed,
	})
}

// metricsHandler returns the Prometheus metrics handler
func (s *Server) metricsHandler() http.Handler {
	return promhttp.Handler()
}

// CheckDLQ checks the health of the dead letter queue
type CheckDLQ struct {
	DLQProvider    DLQProvider
	WarnThreshold  int           // Warn if DLQ has this many entries
	ErrorThreshold int           // Error if DLQ has this many entries
	AgeThreshold   time.Duration // Warn if oldest entry is older than this
}

// NewCheckDLQ creates a new DLQ health checker
func NewCheckDLQ(provider DLQProvider, warnThreshold, errorThreshold int, ageThreshold time.Duration) *CheckDLQ {
	return &CheckDLQ{
		DLQProvider:    provider,
		WarnThreshold:  warnThreshold,
		ErrorThreshold: errorThreshold,
		AgeThreshold:   ageThreshold,
	}
}

func (c *CheckDLQ) Name() string { return "dead_letter_queue" }

func (c *CheckDLQ) CheckHealth() ComponentStatus {
	if c.DLQProvider == nil {
		return ComponentStatus{
			Status:  "disabled",
			Details: "DLQ not configured (in-memory queue or no persistent queue)",
		}
	}

	// Get DLQ entries
	entriesAny, err := c.DLQProvider.GetDLQEntries(c.ErrorThreshold + 1)
	if err != nil {
		return ComponentStatus{
			Status: "unhealthy",
			Details: map[string]any{
				"error": "failed to get DLQ entries: " + err.Error(),
			},
		}
	}

	// Type assert to slice
	var dlqCount int
	var oldestAge time.Duration

	if entries, ok := entriesAny.([]*any); ok {
		dlqCount = len(entries)

		// Find oldest entry
		if dlqCount > 0 {
			// Try to get timestamp from first entry
			if entryMap, ok := (*entries[0]).(map[string]any); ok {
				if movedAtStr, ok := entryMap["moved_at"].(string); ok {
					if movedAt, err := time.Parse(time.RFC3339, movedAtStr); err == nil {
						oldestAge = time.Since(movedAt)
					}
				}
			}
		}
	}

	// Determine status based on thresholds
	status := "healthy"
	details := map[string]any{
		"entries": dlqCount,
	}

	if oldestAge > 0 {
		details["oldest_age_seconds"] = oldestAge.Seconds()
		details["oldest_age_hours"] = oldestAge.Hours()
	}

	// Check entry count thresholds
	if c.ErrorThreshold > 0 && dlqCount >= c.ErrorThreshold {
		status = "unhealthy"
		details["message"] = fmt.Sprintf("DLQ has %d entries (threshold: %d)", dlqCount, c.ErrorThreshold)
	} else if c.WarnThreshold > 0 && dlqCount >= c.WarnThreshold {
		status = "degraded"
		details["message"] = fmt.Sprintf("DLQ has %d entries (warning threshold: %d)", dlqCount, c.WarnThreshold)
	}

	// Check age threshold
	if c.AgeThreshold > 0 && oldestAge > c.AgeThreshold {
		if status == "healthy" {
			status = "degraded"
		}
		details["age_warning"] = fmt.Sprintf("Oldest entry is %.0f hours old (threshold: %.0f hours)",
			oldestAge.Hours(), c.AgeThreshold.Hours())
	}

	if status == "healthy" && dlqCount == 0 {
		details["message"] = "DLQ is empty"
	}

	return ComponentStatus{
		Status:  status,
		Details: details,
	}
}

// dlqHandler handles /api/dlq/* requests for dead letter queue management
func (s *Server) dlqHandler(w http.ResponseWriter, r *http.Request) {
	if s.dlqProvider == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"error":   "DLQ not configured",
			"message": "Server does not have DLQ capability enabled (persistent queue required)",
		})
		return
	}

	// Parse path to determine action
	// /api/dlq - list entries (GET)
	// /api/dlq/{job_id} - get entry (GET), reprocess (POST), delete (DELETE)
	path := r.URL.Path

	if path == "/api/dlq" {
		// List DLQ entries
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get limit from query parameter (default: 100)
		limit := 100
		if limitParam := r.URL.Query().Get("limit"); limitParam != "" {
			fmt.Sscanf(limitParam, "%d", &limit)
		}

		entries, err := s.dlqProvider.GetDLQEntries(limit)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  err.Error(),
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "success",
			"entries": entries,
		})
		return
	}

	// Extract job ID from path: /api/dlq/{job_id}
	if len(path) > len("/api/dlq/") {
		jobID := path[len("/api/dlq/"):]

		switch r.Method {
		case http.MethodGet:
			// Get specific DLQ entry
			entry, err := s.dlqProvider.GetDLQEntry(jobID)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]any{
					"status": "error",
					"error":  err.Error(),
				})
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"status": "success",
				"entry":  entry,
			})
			return

		case http.MethodPost:
			// Reprocess DLQ entry
			err := s.dlqProvider.ReprocessDLQJob(jobID)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]any{
					"status": "error",
					"error":  err.Error(),
				})
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"status":  "success",
				"message": fmt.Sprintf("Job %s moved back to active queue for reprocessing", jobID),
			})
			return

		case http.MethodDelete:
			// Delete DLQ entry
			err := s.dlqProvider.DeleteDLQEntry(jobID)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]any{
					"status": "error",
					"error":  err.Error(),
				})
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"status":  "success",
				"message": fmt.Sprintf("DLQ entry %s deleted successfully", jobID),
			})
			return

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	http.Error(w, "Bad request", http.StatusBadRequest)
}

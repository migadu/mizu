package health

import (
	"io"

	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"migadu/mizu/pkg/concurrency"
	"net"
	"net/http"
	"time"

	"log/slog"

	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

// CertRenewer defines an interface for components that can renew TLS certificates
type CertRenewer interface {
	RenewCertificate(domain string) ([]string, error)
}

// IPUnblocker defines an interface for components that can remove IPs from reputation tracking
type IPUnblocker interface {
	RemoveIP(ip string) bool
}

// Server represents the health check HTTP server.
type Server struct {
	listenAddr      string
	logger          *slog.Logger
	checkers        []Checker
	statsProvider   StatsProvider
	cacheFlusher    CacheFlusher
	certRenewer     CertRenewer
	ipUnblocker     IPUnblocker
	httpServer      *http.Server
	mux             *http.ServeMux
	healthEnabled   bool   // Enable health endpoints (/health, /api/stats, /api/flush-cache)
	username        string // HTTP Basic Auth username (empty = no auth)
	password        string // HTTP Basic Auth password
	acmeHandler     http.Handler
	metricsEnabled  bool   // Enable Prometheus metrics endpoint
	metricsPath     string // Metrics endpoint path
	metricsUsername string // Metrics HTTP Basic Auth username (empty = no auth)
	metricsPassword string // Metrics HTTP Basic Auth password
}

// NewServer creates a new health check server.
func NewServer(listenAddr string, logger *slog.Logger, checkers ...Checker) *Server {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
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

// SetCertRenewer registers a certificate renewer for the /api/renew-cert endpoint
func (s *Server) SetCertRenewer(renewer CertRenewer) {
	s.certRenewer = renewer
}

// SetIPUnblocker registers an IP unblocker for the /api/unblock-ip endpoint
func (s *Server) SetIPUnblocker(unblocker IPUnblocker) {
	s.ipUnblocker = unblocker
}

// SetACMEHandler registers an HTTP handler for the ACME challenge
func (s *Server) SetACMEHandler(handler http.Handler) {
	s.acmeHandler = handler
}

// SetHealthEnabled configures whether health endpoints should be registered
func (s *Server) SetHealthEnabled(enabled bool) {
	s.healthEnabled = enabled
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
			"path", path,
			"auth_enabled", username != "")
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
				"remote_addr", r.RemoteAddr,
				"path", r.URL.Path,
				"realm", realm)
			return
		}

		// Use constant-time comparison to prevent timing attacks
		usernameMatch := subtle.ConstantTimeCompare([]byte(reqUsername), []byte(username)) == 1
		passwordMatch := subtle.ConstantTimeCompare([]byte(reqPassword), []byte(password)) == 1

		if !usernameMatch || !passwordMatch {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			s.logger.Warn("Access denied - invalid credentials",
				"remote_addr", r.RemoteAddr,
				"username", reqUsername,
				"path", r.URL.Path,
				"realm", realm)
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
				"remote_addr", r.RemoteAddr,
				"path", r.URL.Path,
				"realm", realm)
			return
		}

		// Use constant-time comparison to prevent timing attacks
		usernameMatch := subtle.ConstantTimeCompare([]byte(reqUsername), []byte(username)) == 1
		passwordMatch := subtle.ConstantTimeCompare([]byte(reqPassword), []byte(password)) == 1

		if !usernameMatch || !passwordMatch {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			s.logger.Warn("Access denied - invalid credentials",
				"remote_addr", r.RemoteAddr,
				"username", reqUsername,
				"path", r.URL.Path,
				"realm", realm)
			return
		}

		// Credentials valid, proceed
		next.ServeHTTP(w, r)
	})
}

// AddChecker registers an additional health checker after the server is created.
// This is useful when components (like per-server connection trackers) are created
// after the health server has been initialized.
func (s *Server) AddChecker(checker Checker) {
	s.checkers = append(s.checkers, checker)
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

	// Register health endpoints only if enabled
	if s.healthEnabled {
		s.mux.HandleFunc("/health", s.basicAuthMiddleware(s.healthHandler))
		s.mux.HandleFunc("/api/stats", s.basicAuthMiddleware(s.statsHandler))
		s.mux.HandleFunc("/api/flush-cache", s.basicAuthMiddleware(s.flushCacheHandler))
		s.mux.HandleFunc("/api/renew-cert", s.basicAuthMiddleware(s.renewCertHandler))
		s.mux.HandleFunc("/api/unblock-ip", s.basicAuthMiddleware(s.unblockIPHandler))
		s.logger.Info("Health endpoints registered", "auth_enabled", s.username != "")
	}

	// Prometheus metrics endpoint (optional, separate from health)
	if s.metricsEnabled {
		metricsPath := s.metricsPath
		if metricsPath == "" {
			metricsPath = "/metrics"
		}
		s.mux.Handle(metricsPath, s.metricsAuthMiddleware(s.metricsHandler()))
		s.logger.Info("Metrics endpoint registered", "path", metricsPath, "auth_enabled", s.metricsUsername != "")
	}

	s.httpServer = &http.Server{
		Addr:    s.listenAddr,
		Handler: s.mux,
	}

	s.logger.Info(fmt.Sprintf("Starting health/metrics server on %s", s.listenAddr))
	concurrency.SafeGo(s.logger, "health-server", func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("Health/metrics server error", "error", err)
		}
	})
}

// Stop gracefully shuts down the HTTP server.
func (s *Server) Stop(ctx context.Context) {
	if s.httpServer != nil {
		s.logger.Info("Stopping health check server")
		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.logger.Error("Health check server shutdown error", "error", err)
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
		concurrency.SafeGo(s.logger, "health-checker-"+c.Name(), func() {
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
	S3Client   *s3.Client
	BucketName string
}

// NewCheckS3Connection creates a new S3 connection health checker.
func NewCheckS3Connection(s3Client *s3.Client, bucketName string) *CheckS3Connection {
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
	_, err := c.S3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(c.BucketName),
	})
	latency := time.Since(start)

	if err != nil {
		// Check if bucket doesn't exist
		var nsk *types.NoSuchBucket
		var ae smithy.APIError
		if errors.As(err, &nsk) || (errors.As(err, &ae) && (ae.ErrorCode() == "NotFound" || strings.Contains(err.Error(), "StatusCode: 404"))) {
			return ComponentStatus{
				Status: "unhealthy",
				Details: map[string]any{
					"error":   fmt.Sprintf("S3 bucket '%s' does not exist", c.BucketName),
					"latency": latency.String(),
				},
			}
		}

		// Other errors
		return ComponentStatus{
			Status: "unhealthy",
			Details: map[string]any{
				"error":   "failed to check S3 bucket: " + err.Error(),
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

// renewCertHandler handles /api/renew-cert requests
func (s *Server) renewCertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.certRenewer == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		json.NewEncoder(w).Encode(map[string]any{
			"status": "error",
			"error":  "Certificate renewal not configured (TLS manager not available)",
		})
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		// Try reading from JSON body
		var body struct {
			Domain string `json:"domain"`
		}
		if r.Body != nil {
			json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&body)
			domain = body.Domain
		}
	}
	if domain == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"status": "error",
			"error":  "domain parameter is required",
		})
		return
	}

	s.logger.Info("Certificate renewal requested", "domain", domain)
	renewed, err := s.certRenewer.RenewCertificate(domain)
	if err != nil {
		s.logger.Error("Certificate renewal failed", "domain", domain, "error", err)
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
		"message": fmt.Sprintf("Certificate cache cleared for %s — next TLS handshake will trigger fresh ACME request", domain),
		"renewed": renewed,
	})
}

// unblockIPHandler handles /api/unblock-ip requests
func (s *Server) unblockIPHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.ipUnblocker == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		json.NewEncoder(w).Encode(map[string]any{
			"status": "error",
			"error":  "IP unblocking not configured",
		})
		return
	}

	// Parse IP from query param (precedence) or JSON body
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		var body struct {
			IP string `json:"ip"`
		}
		if r.Body != nil {
			if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&body); err != nil && err != io.EOF {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]any{
					"status": "error",
					"error":  "malformed request body",
				})
				return
			}
			ip = body.IP
		}
	}
	if ip == "" || net.ParseIP(ip) == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"status": "error",
			"error":  "valid ip parameter is required",
		})
		return
	}

	removed := s.ipUnblocker.RemoveIP(ip)

	// Log the admin action
	s.logger.Info("IP unblock requested",
		"ip", ip,
		"removed", removed,
		"remote_addr", r.RemoteAddr,
	)

	w.Header().Set("Content-Type", "application/json")
	msg := fmt.Sprintf("IP %s removed from reputation tracker", ip)
	if !removed {
		msg = fmt.Sprintf("IP %s was not tracked", ip)
	}
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "success",
		"removed": removed,
		"message": msg,
	})
}

// metricsHandler returns the Prometheus metrics handler
func (s *Server) metricsHandler() http.Handler {
	return promhttp.Handler()
}

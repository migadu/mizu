package smtp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	net_http "net/http"
	"net/mail"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"migadu/mizu/pkg/blacklist"
	"migadu/mizu/pkg/concurrency"
	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/dns"
	"migadu/mizu/pkg/metrics"
	"migadu/mizu/pkg/poster"
	"migadu/mizu/pkg/stats"
	"migadu/mizu/pkg/validation"

	"github.com/emersion/go-msgauth/authres"
	"github.com/emersion/go-smtp"
)

const (
	// Session timeouts for security and resource management
	SessionDeadline   = 5 * time.Minute  // Hard limit for entire SMTP session to prevent hanging connections
	ProcessingTimeout = 30 * time.Second // Timeout for processing a command after it's received
	IdleTimeout       = 1 * time.Minute  // Maximum idle time between commands before disconnect
	DataTimeout       = 2 * time.Minute  // Timeout for receiving email body after DATA command
)

// generateTraceID creates a unique trace ID for correlating logs and tracking emails through the system.
// Format: 16 character hex string (8 random bytes)
func generateTraceID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID if random fails
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// NewDNSResolver creates a DNS resolver based on configuration.
// If custom DNS servers are configured, uses them with round-robin, failover, and caching;
// otherwise uses system default resolver.
// Returns both the resolver and a caching wrapper for cache-aware operations.
func NewDNSResolver(dnsServers []string, timeout time.Duration, cacheTTL time.Duration) (*net.Resolver, *dns.CachingWrapper) {
	// Use the resilient resolver which implements round-robin, failover, and caching
	resolver, rr := dns.NewResilientResolver(dnsServers, timeout, cacheTTL)

	// Wrap with caching layer
	wrapper := dns.WrapWithCache(resolver, rr)

	return resolver, wrapper
}

// SenderValidator defines the interface for sender validation during MAIL FROM
type SenderValidator interface {
	Validate(ctx context.Context, clientIP, from string) (*SenderValidationResponse, error)
	ValidateWithContext(ctx context.Context, clientIP, ptr, helo, from, authenticatedUser string) (*SenderValidationResponse, error)
	FlushCache()
	GetStats() map[string]interface{}
}

// SenderValidationResponse represents the result of sender validation
type SenderValidationResponse struct {
	Accepted bool
	Message  string
}

// RecipientValidator defines the interface for recipient validation during RCPT TO
type RecipientValidator interface {
	Validate(ctx context.Context, clientIP, from, to string) (*RecipientValidationResponse, error)
	ValidateWithContext(ctx context.Context, clientIP, ptr, helo, from, to string) (*RecipientValidationResponse, error)
	FlushCache()
	GetStats() map[string]interface{}
}

// RecipientValidationResponse represents the result of recipient validation
type RecipientValidationResponse struct {
	Accepted  bool
	Message   string
	Temporary bool // If true, rejection is temporary (4xx), otherwise permanent (5xx)
}

// Backend implements smtp.Backend interface for our custom SMTP server.
// It manages the overall server configuration and creates new sessions for incoming connections.
type Backend struct {
	ServerConfig   *config.ServerConfig   // Server-specific configuration (this server instance)
	GlobalConfig   *config.Config         // Global configuration (shared across servers)
	StatsManager   *stats.Manager         // IP and domain reputation tracking
	CircuitBreaker *poster.CircuitBreaker // Circuit breaker for destination HTTP calls
	HTTPClient     *net_http.Client       // HTTP client for posting emails to destination
	Logger         *slog.Logger           // Structured logger for debugging and monitoring
	DNSResolver    *net.Resolver          // Custom DNS resolver (uses config.DNS.Servers or system default)
	Metrics        *metrics.Metrics       // Prometheus metrics for observability

	// Connection tracking for graceful shutdown and DoS protection
	ActiveSessionsWg   *sync.WaitGroup     // Tracks active SMTP sessions
	ActiveSessionCount *atomic.Int64       // Current number of active sessions (for observability)
	ShutdownChan       chan struct{}       // Signals shutdown to new connections
	ConnTracker        *ConnectionTracker  // Tracks connections to enforce limits
	DistTracker        *DistributedTracker // Optional: Distributed connection tracking
	RateLimiter        *RateLimiter        // Rate limiter to prevent rapid connection attempts

	// Authentication (for submission servers)
	Authenticator   Authenticator    // Optional: Authenticates users (submission servers)
	AuthRateLimiter *AuthRateLimiter // Optional: Auth rate limiter for brute-force protection

	// Sender validation
	SenderValidator SenderValidator // Optional: Sender validator (validates during MAIL FROM)

	// Recipient validation
	RecipientValidator RecipientValidator // Optional: Recipient validator (validates during RCPT TO)
}

// Authenticator interface for SMTP AUTH
type Authenticator interface {
	Authenticate(username, password string) (bool, error)
	CanSendAs(authenticatedUser, fromAddress string) bool
}

// EHLO/HELO is called for the HELO/EHLO command.
// This implements the optional smtp.EHLOBackend interface
func (be *Backend) EHLO(hostname string) error {
	// This is called by go-smtp when EHLO is received
	// We don't do validation here as it's done in the session
	return nil
}

// NewSession is called when a new SMTP session is started.
// It performs initial validation (blacklists, reverse DNS) before creating a session.
func (be *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	// Check if server is shutting down
	select {
	case <-be.ShutdownChan:
		be.Logger.Info("Server shutting down - rejecting new connection")
		return nil, &smtp.SMTPError{
			Code:         421,
			EnhancedCode: smtp.EnhancedCode{4, 3, 2},
			Message:      "server is shutting down, please try again later",
		}
	default:
		// Continue with session creation
	}

	// Extract IP without port for all subsequent operations
	remoteAddrWithPort := c.Conn().RemoteAddr().String()
	host, _, err := net.SplitHostPort(remoteAddrWithPort)
	if err != nil {
		// If split fails, use the raw address (shouldn't happen with TCP connections)
		host = remoteAddrWithPort
	}
	remoteAddr := host

	// Record connection attempt in metrics
	if be.Metrics != nil {
		be.Metrics.SMTPConnectionsTotal.WithLabelValues(be.ServerConfig.Name, be.ServerConfig.Type).Inc()
	}

	// Track whether session was successfully created for connection cleanup
	sessionCreated := false

	// Check rate limit (prevent rapid connection attempts)
	// At this point, we only have IP information, so only IP-based dimensions will be checked
	if be.RateLimiter != nil {
		sessionCtx := SessionContext{
			RemoteAddr: remoteAddr,
		}
		if err := be.RateLimiter.CheckRateLimit(sessionCtx); err != nil {
			be.Logger.Info("Rejecting connection - rate limit exceeded",
				"server", be.ServerConfig.Name,
				"remote_addr", remoteAddr,
				"error", err)

			// Record rejection in metrics
			if be.Metrics != nil {
				be.Metrics.SMTPMessagesRejected.WithLabelValues(be.ServerConfig.Name, be.ServerConfig.Type, "rate_limit").Inc()
			}

			return nil, &smtp.SMTPError{
				Code:         421,
				EnhancedCode: smtp.EnhancedCode{4, 3, 2},
				Message:      "rate limit exceeded, please slow down",
			}
		}
	}

	// Check connection limits (DoS protection)
	// Use distributed tracker if available, otherwise fall back to local tracker
	tracker := be.ConnTracker
	if be.DistTracker != nil {
		// Distributed tracker wraps local tracker
		if err := be.DistTracker.TryAcquire(remoteAddr); err != nil {
			be.Logger.Info("Rejecting connection - distributed connection limit exceeded",
				"server", be.ServerConfig.Name,
				"remote_addr", remoteAddr,
				"error", err)
			return nil, &smtp.SMTPError{
				Code:         421,
				EnhancedCode: smtp.EnhancedCode{4, 3, 2},
				Message:      "too many connections, please try again later",
			}
		}
		// Ensure connection is released if we fail to create session
		defer func() {
			if !sessionCreated {
				be.DistTracker.Release(remoteAddr)
			}
		}()
	} else if tracker != nil {
		if err := tracker.TryAcquire(remoteAddr); err != nil {
			be.Logger.Info("Rejecting connection - connection limit exceeded",
				"server", be.ServerConfig.Name,
				"remote_addr", remoteAddr,
				"error", err)
			return nil, &smtp.SMTPError{
				Code:         421,
				EnhancedCode: smtp.EnhancedCode{4, 3, 2},
				Message:      "too many connections, please try again later",
			}
		}
		// Ensure connection is released if we fail to create session
		defer func() {
			if !sessionCreated {
				tracker.Release(remoteAddr)
			}
		}()
	}

	// Track this session for graceful shutdown with panic recovery
	if be.ActiveSessionsWg != nil {
		be.ActiveSessionsWg.Add(1)

		// Increment active session counter for observability
		if be.ActiveSessionCount != nil {
			count := be.ActiveSessionCount.Add(1)
			be.Logger.Debug("Session count incremented",
				"active_sessions", count,
				"remote_addr", remoteAddr)

			// Update Prometheus gauge for active connections
			if be.Metrics != nil {
				be.Metrics.SMTPConnectionsActive.WithLabelValues(be.ServerConfig.Name, be.ServerConfig.Type).Set(float64(count))
			}
		}

		// Ensure we clean up on early returns or panics
		defer func() {
			if r := recover(); r != nil {
				// Panic recovery: ensure we call Done() if session creation panics
				be.Logger.Error("Panic in NewSession - recovering",
					"remote_addr", remoteAddr,
					"panic", r,
					"stack", "")

				// Decrement counter and call Done() since we won't reach Logout()
				if be.ActiveSessionCount != nil {
					be.ActiveSessionCount.Add(-1)
				}
				be.ActiveSessionsWg.Done()

				// Re-panic to let go-smtp library handle it
				panic(r)
			} else if !sessionCreated {
				// Early return: clean up WaitGroup and counter
				if be.ActiveSessionCount != nil {
					count := be.ActiveSessionCount.Add(-1)
					be.Logger.Debug("Session count decremented on early return",
						"active_sessions", count,
						"remote_addr", remoteAddr)

					// Update Prometheus gauge
					if be.Metrics != nil {
						be.Metrics.SMTPConnectionsActive.WithLabelValues(be.ServerConfig.Name, be.ServerConfig.Type).Set(float64(count))
					}
				}
				be.ActiveSessionsWg.Done()
			}
		}()
	}

	// Log client connection immediately with detailed info
	// Get current connection count for monitoring
	var activeConns int
	var connectionsFromIP int
	if be.DistTracker != nil {
		total, _, perIP := be.DistTracker.GetStats()
		activeConns = total
		connectionsFromIP = perIP[remoteAddr]
	} else if tracker != nil {
		total, _, perIP := tracker.GetStats()
		activeConns = total
		connectionsFromIP = perIP[remoteAddr]
	}

	be.Logger.Info("Client connected",
		"server", be.ServerConfig.Name,
		"remote_addr", remoteAddr,
		"active_connections", activeConns,
		"connections_from_ip", connectionsFromIP,
		"tls_enabled", be.ServerConfig.IsTLSEnabled(),
		"tls_mode", be.ServerConfig.TLS.Mode,
		"tls_required", be.ServerConfig.TLS.Required)

	ipStr := remoteAddr // Already stripped of port at line 164
	hasRDNS := true
	var ptrRecord string // Store PTR (reverse DNS) record for use in validation

	// Perform security checks in production mode (skip for submission servers with relaxed validation)
	// Relay servers should validate, submission servers with skip_rdns/skip_dnsbl will skip
	if !be.GlobalConfig.Local {
		// Parse IP address (already stripped of port)
		ip := net.ParseIP(remoteAddr)
		if ip == nil {
			be.Logger.Error("Failed to parse IP address", "remote_addr", remoteAddr)
			return nil, ErrInternalServerError
		}

		// Check DNS blacklists (RBLs) to prevent spam
		if be.ServerConfig.DNSBL.Enabled {
			// Determine which DNSBL lists to use based on IP version
			var lists []string
			if ip.To4() != nil {
				// IPv4 address
				lists = be.ServerConfig.DNSBL.IPv4Lists
			} else {
				// IPv6 address
				lists = be.ServerConfig.DNSBL.IPv6Lists
			}

			if len(lists) > 0 {
				timeoutSecs := be.ServerConfig.DNSBL.TimeoutSeconds
				if timeoutSecs == 0 {
					timeoutSecs = 3 // Default timeout
				}
				checker := blacklist.NewChecker(lists, time.Duration(timeoutSecs)*time.Second, be.Logger)
				isListed, reason, err := checker.CheckIP(ip)
				if err != nil {
					be.Logger.Error("Blacklist check error", "error", err, "ip", host)
					// Don't reject on blacklist check errors - fail open for availability
				} else if isListed {
					// Determine action based on configuration
					action := be.ServerConfig.DNSBL.Action
					if action == "" {
						action = "reject" // Default to reject
					}

					// Record blacklist detection in metrics
					if be.Metrics != nil {
						be.Metrics.SMTPBlacklistChecks.WithLabelValues(be.ServerConfig.Name, "blocked").Inc()
					}

					switch action {
					case "reject":
						// Reject the connection
						be.Logger.Info("Rejecting connection - IP blacklisted",
							"server", be.ServerConfig.Name,
							"remote_addr", remoteAddr,
							"reason", reason)
						if be.Metrics != nil {
							be.Metrics.SMTPMessagesRejected.WithLabelValues(be.ServerConfig.Name, be.ServerConfig.Type, "blacklist").Inc()
						}
						return nil, &smtp.SMTPError{
							Code:         550,
							EnhancedCode: smtp.EnhancedCode{5, 7, 1},
							Message:      fmt.Sprintf("your IP address is blacklisted: %s", reason),
						}
					case "junk":
						// Mark for junk but allow connection
						be.Logger.Info("Allowing blacklisted IP but marking as junk", "ip", host, "reason", reason)
						// Note: The session will be created and marked as junk
					case "none":
						// Just log but take no action
						be.Logger.Info("Blacklisted IP detected but no action configured", "ip", host, "reason", reason)
					}
				} else if be.Metrics != nil {
					// Record successful blacklist check
					be.Metrics.SMTPBlacklistChecks.WithLabelValues(be.ServerConfig.Name, "pass").Inc()
				}
			}
		}

		// Check reverse DNS (PTR record) - helps prevent spam from compromised hosts
		// Use context with timeout to prevent hanging on unresponsive DNS servers
		rdnsCtx, rdnsCancel := context.WithTimeout(context.Background(), time.Duration(be.GlobalConfig.DNS.TimeoutSeconds)*time.Second)
		names, err := be.DNSResolver.LookupAddr(rdnsCtx, remoteAddr)
		rdnsCancel()
		if err != nil || len(names) == 0 {
			hasRDNS = false
			// Record this in stats
			if be.StatsManager != nil {
				be.StatsManager.RecordConnection(ipStr, false)
			}

			// Reject if rDNS is required
			if be.ServerConfig.DNSChecks.RequireRDNS {
				// Record rejection in metrics
				if be.Metrics != nil {
					be.Metrics.SMTPMessagesRejected.WithLabelValues(be.ServerConfig.Name, be.ServerConfig.Type, "no_rdns").Inc()
				}

				be.Logger.Info("Rejecting connection - no reverse DNS",
					"server", be.ServerConfig.Name,
					"remote_addr", remoteAddr)
				return nil, &smtp.SMTPError{
					Code:         550,
					EnhancedCode: smtp.EnhancedCode{5, 7, 25},
					Message:      "no reverse DNS record for IP address",
				}
			}
			// Allow connection even without rDNS when not required
			be.Logger.Info("Connection allowed without reverse DNS (not required)",
				"server", be.ServerConfig.Name,
				"remote_addr", remoteAddr)
		}
		// Store first PTR record for use in recipient validation
		if len(names) > 0 {
			ptrRecord = names[0]
		}
		be.Logger.Info("Reverse DNS resolved",
			"server", be.ServerConfig.Name,
			"remote_addr", remoteAddr,
			"remote_host", ptrRecord)

		// Record connection in stats
		if be.StatsManager != nil {
			be.StatsManager.RecordConnection(ipStr, hasRDNS)

			// Check IP reputation if enabled for this server
			if be.ServerConfig.ReputationCheck {
				if shouldDeny, reputation := be.StatsManager.CheckIPReputation(ipStr); shouldDeny {
					be.Logger.Info("Rejecting connection - poor IP reputation",
						"server", be.ServerConfig.Name,
						"remote_addr", remoteAddr,
						"remote_host", ptrRecord,
						"score", reputation)
					return nil, &smtp.SMTPError{
						Code:         421,
						EnhancedCode: smtp.EnhancedCode{4, 7, 1},
						Message:      "please try again later",
					}
				}
			}
		}
	}

	// Store connection state for TLS checking
	state, ok := c.TLSConnectionState()
	var tlsState *tls.ConnectionState
	if ok {
		tlsState = &state
	}

	// Create session context with deadline
	ctx, cancel := context.WithTimeout(context.Background(), SessionDeadline)

	// Set initial idle timeout
	if err := c.Conn().SetDeadline(time.Now().Add(IdleTimeout)); err != nil {
		cancel()
		be.Logger.Error("Failed to set deadline", "error", err)
		return nil, ErrInternalServerError
	}

	// Generate unique trace ID for this session
	traceID := generateTraceID()

	session := &Session{
		conn:               c,
		helo:               "",
		ptr:                ptrRecord,
		from:               "",
		to:                 make([]string, 0),
		remoteAddr:         remoteAddr, // Use the cleaned IP (without port) from line 164
		serverConfig:       be.ServerConfig,
		globalConfig:       be.GlobalConfig,
		tlsState:           tlsState,
		statsManager:       be.StatsManager,
		circuitBreaker:     be.CircuitBreaker,
		httpClient:         be.HTTPClient,
		dnsResolver:        be.DNSResolver,
		connTracker:        be.ConnTracker,
		distTracker:        be.DistTracker,
		rateLimiter:        be.RateLimiter,
		metrics:            be.Metrics,
		ctx:                ctx,
		Logger:             be.Logger.With("trace_id", traceID, "remote_addr", remoteAddr, "remote_host", ptrRecord),
		cancel:             cancel,
		sessionsWg:         be.ActiveSessionsWg,
		sessionCount:       be.ActiveSessionCount,
		commandState:       stateNew, // Explicitly initialize command state
		traceID:            traceID,
		isAuthenticated:    false,                 // Not authenticated initially
		authenticatedUser:  "",                    // No user yet
		authenticator:      be.Authenticator,      // Authenticator (nil if not submission)
		authRateLimiter:    be.AuthRateLimiter,    // Auth rate limiter (nil if disabled)
		senderValidator:    be.SenderValidator,    // Sender validator (nil if disabled)
		recipientValidator: be.RecipientValidator, // Recipient validator (nil if disabled)
	}

	sessionCreated = true

	be.Logger.Info("Session created successfully",
		"server", be.ServerConfig.Name,
		"remote_addr", remoteAddr,
		"remote_host", ptrRecord,
		"trace_id", traceID,
		"initial_tls_state", tlsState != nil)

	return session, nil
}

// Session represents an active SMTP session for an incoming email.
// It tracks the SMTP conversation state and enforces protocol requirements.
type Session struct {
	conn           *smtp.Conn             // The underlying SMTP connection
	helo           string                 // HELO/EHLO domain from the client
	ptr            string                 // Reverse DNS (PTR) record for client IP
	from           string                 // Sender's email address (MAIL FROM)
	to             []string               // Recipient email addresses (RCPT TO)
	remoteAddr     string                 // Remote IP:port of the client
	mailData       bytes.Buffer           // Buffer to store the raw email body
	serverConfig   *config.ServerConfig   // Server-specific configuration (this server instance)
	globalConfig   *config.Config         // Global configuration (shared across servers)
	tlsState       *tls.ConnectionState   // TLS connection state (nil if not using TLS)
	statsManager   *stats.Manager         // IP and domain reputation tracking
	circuitBreaker *poster.CircuitBreaker // Circuit breaker for HTTP destination
	httpClient     *net_http.Client       // HTTP client for posting emails to destination
	dnsResolver    *net.Resolver          // DNS resolver (custom or system default)
	connTracker    *ConnectionTracker     // Connection tracker for DoS protection
	distTracker    *DistributedTracker    // Distributed connection tracker (optional, for cluster-wide limits)
	rateLimiter    *RateLimiter           // Multi-dimensional rate limiter
	metrics        *metrics.Metrics       // Prometheus metrics for observability
	ctx            context.Context        // Session context with deadline for timeout
	Logger         *slog.Logger           // Structured logger for this session
	cancel         context.CancelFunc     // Cancel function to clean up resources
	sessionsWg     *sync.WaitGroup        // WaitGroup to track active sessions for graceful shutdown
	sessionCount   *atomic.Int64          // Pointer to active session counter for observability

	// Authentication (for submission servers)
	isAuthenticated   bool             // Whether user has authenticated via SMTP AUTH
	authenticatedUser string           // Username from successful authentication
	authenticator     Authenticator    // Authenticator for this session
	authRateLimiter   *AuthRateLimiter // Auth rate limiter for brute-force protection

	// Anti-spam tracking
	isJunk       bool     // Whether this message is considered junk/spam
	junkReasons  []string // Specific reasons why message is marked as junk
	commandState int      // Track SMTP command sequence state for protocol enforcement
	traceID      string   // Unique trace ID for correlating logs and tracking email through system

	// Stats tracking
	senderDomain string // Domain from MAIL FROM for stats
	spfResult    *validation.SPFResult
	dmarcResult  *validation.DMARCResult
	arcResult    *validation.ARCResult

	// Sender validation
	senderValidator SenderValidator // Sender validator for validating during MAIL FROM (nil if disabled)

	// Recipient validation
	recipientValidator RecipientValidator // Recipient validator for validating during RCPT TO (nil if disabled)
}

// SMTP command states for sequence validation
// Ensures commands are issued in the correct order per RFC 5321
const (
	stateNew  = iota // Initial state before HELO/EHLO
	stateHelo        // After HELO/EHLO received
	stateMail        // After MAIL FROM received
	stateRcpt        // After at least one RCPT TO received
	stateData        // After DATA command (currently receiving message)
)

// serverName returns the server name for metric labeling
func (s *Session) serverName() string {
	if s.serverConfig != nil {
		return s.serverConfig.Name
	}
	return "unknown"
}

// serverType returns the server type for metric labeling
func (s *Session) serverType() string {
	if s.serverConfig != nil {
		return s.serverConfig.Type
	}
	return "unknown"
}

// Helo is called for the HELO/EHLO command.
// RFC 5321 requires this to be the first command in an SMTP session.
func (s *Session) Helo(hostname string) error {
	// Set timeout for this command
	if err := s.setCommandTimeout(ProcessingTimeout); err != nil {
		return err
	}

	// Enforce command sequence - HELO/EHLO must be first
	if s.commandState != stateNew {
		s.Logger.Warn("Rejecting HELO/EHLO - already received", "state", int(s.commandState))
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "bad sequence of commands",
		}
	}

	// Validate HELO hostname for security (skip in local development mode)
	if !s.globalConfig.Local {
		// Reject if HELO claims to be our own hostname or a subdomain (spoofing attempt)
		// Case-insensitive check for robustness.
		if strings.HasSuffix(strings.ToLower(hostname), "."+strings.ToLower(s.serverConfig.Hostname)) || strings.EqualFold(hostname, s.serverConfig.Hostname) {
			s.Logger.Warn("Rejecting HELO/EHLO - client using our hostname", "hostname", hostname, "our_hostname", s.serverConfig.Hostname)
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 7, 8},
				Message:      "invalid HELO hostname",
			}
		}

		// Reject localhost or single-label hostnames
		if hostname == "localhost" || !strings.Contains(hostname, ".") {
			s.Logger.Warn("Rejecting HELO/EHLO - invalid hostname", "hostname", hostname)
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 7, 1},
				Message:      "HELO requires fully-qualified hostname",
			}
		}

		// Reject bare IP addresses. Per RFC 5321, IP literals must be in brackets.
		isIPLiteral := strings.HasPrefix(hostname, "[") && strings.HasSuffix(hostname, "]")
		if !isIPLiteral && net.ParseIP(hostname) != nil {
			s.Logger.Warn("Rejecting HELO/EHLO - bare IP", "ip", hostname)
			return &smtp.SMTPError{
				Code:    550,
				Message: "HELO with bare IP must use [IP] format",
			}
		}

		// Check for invalid characters
		if strings.ContainsAny(hostname, " \t\r\n") {
			s.Logger.Warn("Rejecting HELO/EHLO - invalid characters")
			return &smtp.SMTPError{
				Code:    550,
				Message: "invalid characters in HELO hostname",
			}
		}

		// Optional: Verify HELO hostname has valid DNS records
		if s.globalConfig.Blacklists.CheckHELOResolves {
			resolves, reason, err := blacklist.CheckHELOResolves(hostname, time.Duration(s.globalConfig.Blacklists.TimeoutSeconds)*time.Second)
			if err != nil || !resolves {
				s.Logger.Warn("Rejecting HELO/EHLO - hostname check failed", "hostname", hostname, "reason", reason)
				return &smtp.SMTPError{
					Code:         550,
					EnhancedCode: smtp.EnhancedCode{5, 7, 27},
					Message:      fmt.Sprintf("HELO hostname check failed: %s", reason),
				}
			}
		}
	}

	s.helo = hostname
	s.commandState = stateHelo
	s.Logger.Info("HELO/EHLO received", "hostname", hostname)

	// Reset to idle timeout to wait for the next command
	if err := s.setCommandTimeout(IdleTimeout); err != nil {
		return err
	}

	return nil
}

// updateTLSState updates the TLS state from the connection
func (s *Session) updateTLSState() {
	if s.conn == nil {
		s.Logger.Warn("updateTLSState: conn is nil")
		return
	}
	state, ok := s.conn.TLSConnectionState()
	if ok {
		s.tlsState = &state
		s.Logger.Info("TLS state updated", "tls_version", tlsVersionString(state.Version),
			"cipher_suite", fmt.Sprintf("0x%04x", state.CipherSuite),
			"server_name", state.ServerName,
			"handshake_complete", state.HandshakeComplete)
	} else {
		s.Logger.Warn("TLS state check returned ok=false", "had_previous_tls", s.tlsState != nil)
		if s.tlsState != nil {
			s.Logger.Warn("TLS state cleared (was previously set)")
		}
		s.tlsState = nil
	}
}

// setCommandTimeout sets the deadline for the current command
func (s *Session) setCommandTimeout(timeout time.Duration) error {
	// Skip timeout if no connection (e.g., in tests)
	if s.conn == nil {
		return nil
	}

	// Check if session deadline has been exceeded
	select {
	case <-s.ctx.Done():
		s.Logger.Warn("Session deadline exceeded")
		return ErrSessionTimeout
	default:
		// Set the command timeout
		deadline := time.Now().Add(timeout)
		if err := s.conn.Conn().SetDeadline(deadline); err != nil {
			s.Logger.Error("Failed to set deadline", "error", err)
			return ErrInternalServerError
		}
		return nil
	}
}

// Mail is called for the MAIL FROM command.
// This sets the envelope sender for the SMTP transaction.
func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	// Reject null sender <> (bounce messages) to prevent backscatter
	// Check this FIRST before any other processing for security
	if s.serverConfig.Junk.RejectNullSender && (from == "" || from == "<>") {
		s.Logger.Warn("Rejecting null sender")
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "null sender not accepted",
		}
	}

	// Handle case where go-smtp library processed EHLO internally
	if s.conn != nil {
		heloHostname := s.conn.Hostname()
		if heloHostname != "" && s.helo == "" {
			// EHLO was handled by go-smtp internally, update our state
			s.helo = heloHostname
			s.commandState = stateHelo
			s.Logger.Debug("HELO/EHLO set via conn.Hostname", "hostname", heloHostname)
		}
	}

	// Set timeout for this command
	if err := s.setCommandTimeout(ProcessingTimeout); err != nil {
		return err
	}

	// Check if HELO/EHLO has been received
	if s.helo == "" {
		s.Logger.Warn("Rejecting MAIL FROM - no HELO/EHLO")
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "bad sequence of commands - HELO/EHLO first",
		}
	}

	// Update and check TLS state (skip in local mode)
	s.updateTLSState()
	if !s.globalConfig.Local && s.serverConfig.TLS.Required && s.tlsState == nil {
		s.Logger.Warn("Rejecting MAIL FROM - TLS required", "from", from)
		return ErrTLSRequiredStartTLS
	}

	// Check authentication requirement (for submission servers)
	if s.serverConfig.Auth.Required && !s.isAuthenticated {
		s.Logger.Warn("Rejecting MAIL FROM - authentication required", "from", from)
		return &smtp.SMTPError{
			Code:         530,
			EnhancedCode: smtp.EnhancedCode{5, 7, 0},
			Message:      "authentication required",
		}
	}

	// Verify authenticated user can send as this FROM address
	if s.isAuthenticated && s.authenticator != nil {
		if !s.authenticator.CanSendAs(s.authenticatedUser, from) {
			s.Logger.Warn("User not allowed to send from address",
				"user", s.authenticatedUser,
				"from", from)
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 7, 1},
				Message:      "sender address rejected: not allowed",
			}
		}
	}

	// Perform sender validation if enabled (skip for authenticated sessions - already validated via allowed_from)
	if !s.isAuthenticated && s.senderValidator != nil && s.serverConfig.SenderValidation.Enabled {
		result, err := s.senderValidator.ValidateWithContext(s.ctx, s.remoteAddr, s.ptr, s.helo, from, s.authenticatedUser)
		if err != nil {
			s.Logger.Warn("Sender validation failed", "from", from, "authenticated_user", s.authenticatedUser, "error", err)
			// Treat validation errors as temporary failures
			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 4, 0},
				Message:      "temporary failure, please try again later",
			}
		}

		// Check if sender is accepted
		if !result.Accepted {
			s.Logger.Info("Sender rejected by validation endpoint",
				"from", from,
				"client_ip", s.remoteAddr,
				"authenticated_user", s.authenticatedUser,
				"message", result.Message)

			message := result.Message
			if message == "" {
				message = "sender address rejected"
			}

			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 7, 1},
				Message:      message,
			}
		}

		s.Logger.Info("Sender validation passed", "from", from, "authenticated_user", s.authenticatedUser)
	}

	// Extract domain from sender
	senderDomain := stats.ExtractDomainFromEmail(from)
	s.senderDomain = senderDomain

	// Record MAIL FROM in stats
	if s.statsManager != nil && senderDomain != "" {
		s.statsManager.RecordMailFrom(senderDomain)

		// Check domain reputation
		if shouldDeny, reputation := s.statsManager.CheckDomainReputation(senderDomain); shouldDeny {
			s.Logger.Warn("Rejecting MAIL FROM - poor domain reputation", "from", from, "score", reputation)
			return &smtp.SMTPError{
				Code:         421,
				EnhancedCode: smtp.EnhancedCode{4, 7, 1},
				Message:      "please try again later",
			}
		}
	}

	// Note: Mailbox/domain validation is now handled by the destination HTTP endpoint
	// The worker can reject messages for unknown users by returning 404
	// This allows dynamic user management without syncing mailbox lists

	// Perform SPF and MX checks in parallel (skip in local mode)
	if !s.globalConfig.Local {
		var wg sync.WaitGroup
		var spfMu sync.Mutex // Protect SPF result writes

		// SPF check in parallel
		ip := net.ParseIP(s.remoteAddr)
		if ip == nil {
			s.Logger.Warn("SPF check skipped - failed to parse IP", "from", from)
		} else if !s.serverConfig.SPFCheck {
			s.Logger.Debug("SPF check disabled in config", "from", from)
		}

		if ip != nil && s.serverConfig.SPFCheck {
			wg.Add(1)
			concurrency.SafeGo(s.Logger, "spf-check", func() {
				defer wg.Done()
				// Extract domain from email address for SPF lookup
				// SPF library needs the domain to look up SPF records, not the HELO hostname
				domain := from
				if idx := strings.Index(from, "@"); idx != -1 {
					domain = from[idx+1:]
				}
				// If no domain could be extracted (e.g., null sender <>), use HELO as fallback
				if domain == "" || domain == from {
					domain = s.helo
				}
				res, err := validation.CheckSPF(context.Background(), ip, domain, from, s.dnsResolver)
				if err != nil {
					s.Logger.Info("SPF check error", "from", from, "domain", domain, "error", err)
					if s.metrics != nil {
						s.metrics.SMTPSPFChecks.WithLabelValues(s.serverName(), "error").Inc()
					}
				} else if res != nil {
					resultStr := string(*res)
					s.Logger.Info("SPF result", "from", from, "domain", domain, "result", resultStr)

					// Record SPF check result in metrics
					if s.metrics != nil {
						s.metrics.SMTPSPFChecks.WithLabelValues(s.serverName(), resultStr).Inc()
					}

					spfMu.Lock()
					s.spfResult = &validation.SPFResult{
						Domain: s.senderDomain,
						Result: authres.SPFResult{
							Value: validation.ConvertSPFResult(*res),
						},
					}
					spfMu.Unlock()
				}
			})
		}

		// MX check in parallel
		var mxErr error
		var hasMX bool
		if s.serverConfig.DNSChecks.RequireSenderMX && senderDomain != "" {
			wg.Add(1)
			concurrency.SafeGo(s.Logger, "mx-check", func() {
				defer wg.Done()
				var err error
				hasMX, err = validation.CheckMXRecord(context.Background(), senderDomain, s.dnsResolver, time.Duration(s.globalConfig.DNS.TimeoutSeconds)*time.Second)
				if err != nil {
					s.Logger.Warn("MX lookup error for sender domain", "from", from, "domain", senderDomain, "error", err)
					mxErr = err
					// Continue despite lookup error - don't fail on temporary DNS issues
				} else if !hasMX {
					s.Logger.Info("Sender domain has no MX records or is invalid/test domain",
						"from", from,
						"domain", senderDomain)
				} else {
					s.Logger.Info("Sender domain has valid MX records", "from", from, "domain", senderDomain)
				}
			})
		}

		// Wait for both DNS queries to complete
		wg.Wait()

		// Check MX result after parallel execution
		if s.serverConfig.DNSChecks.RequireSenderMX && senderDomain != "" {
			s.Logger.Debug("MX check result",
				"from", from,
				"domain", senderDomain,
				"has_mx", hasMX,
				"mx_error", mxErr,
				"will_reject", mxErr == nil && !hasMX)

			if mxErr == nil && !hasMX {
				s.Logger.Warn("Rejecting MAIL FROM - sender domain has no MX records",
					"from", from,
					"domain", senderDomain)
				return &smtp.SMTPError{
					Code:         550,
					EnhancedCode: smtp.EnhancedCode{5, 7, 1},
					Message:      "sender domain has no mail servers (no MX records)",
				}
			}
		}
	}

	s.from = from
	s.commandState = stateMail

	// Check rate limits now that we have FROM information
	// This allows FROM, FROM_DOMAIN, AUTHENTICATED_USER, and IP+FROM combination checks
	if s.rateLimiter != nil {
		sessionCtx := SessionContext{
			RemoteAddr:        s.remoteAddr,
			From:              from,
			To:                s.to, // May be empty at this point
			AuthenticatedUser: s.authenticatedUser,
		}
		if err := s.rateLimiter.CheckRateLimit(sessionCtx); err != nil {
			s.Logger.Warn("Rate limit exceeded for sender", "from", from, "error", err)
			return &smtp.SMTPError{
				Code:         421,
				EnhancedCode: smtp.EnhancedCode{4, 3, 2},
				Message:      "rate limit exceeded, please slow down",
			}
		}
	}

	if s.tlsState != nil {
		s.Logger.Info("MAIL FROM", "from", from, "tls", tlsVersionString(s.tlsState.Version))
	} else {
		s.Logger.Info("MAIL FROM", "from", from, "tls", "none")
	}

	// Reset to idle timeout to wait for the next command
	if err := s.setCommandTimeout(IdleTimeout); err != nil {
		return err
	}

	return nil
}

// Rcpt is called for the RCPT TO command.
// This validates and adds recipients to the envelope.
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	// Set timeout for this command
	if err := s.setCommandTimeout(ProcessingTimeout); err != nil {
		return err
	}

	// Enforce command sequence - must have MAIL FROM before RCPT TO
	if s.commandState != stateMail && s.commandState != stateRcpt {
		s.Logger.Warn("Rejecting RCPT TO - bad sequence")
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "bad sequence of commands - MAIL FROM first",
		}
	}

	// Update and check TLS state (skip in local mode)
	s.updateTLSState()
	if !s.globalConfig.Local && s.serverConfig.TLS.Required && s.tlsState == nil {
		s.Logger.Warn("Rejecting RCPT TO - TLS required", "to", to)
		return ErrTLSRequired
	}

	s.Logger.Info("RCPT TO", "to", to)

	// Check max recipients limit
	maxRecipients := s.serverConfig.MaxRecipientsPerMessage
	if maxRecipients == 0 {
		maxRecipients = 100 // Default if not set
	}
	if len(s.to) >= maxRecipients {
		s.Logger.Warn("Rejecting RCPT TO - max recipients exceeded",
			"to", to,
			"current_count", len(s.to),
			"max_recipients", maxRecipients)
		return &smtp.SMTPError{
			Code:         452,
			EnhancedCode: smtp.EnhancedCode{4, 5, 3},
			Message:      fmt.Sprintf("Too many recipients (maximum: %d)", maxRecipients),
		}
	}

	s.to = append(s.to, to)
	s.commandState = stateRcpt

	// Check rate limits now that we have TO information
	// This allows TO, TO_DOMAIN, FROM+TO, AUTHENTICATED_USER, and other recipient-based combination checks
	if s.rateLimiter != nil {
		sessionCtx := SessionContext{
			RemoteAddr:        s.remoteAddr,
			From:              s.from,
			To:                s.to,
			AuthenticatedUser: s.authenticatedUser,
		}
		if err := s.rateLimiter.CheckRateLimit(sessionCtx); err != nil {
			s.Logger.Warn("Rate limit exceeded for recipient", "to", to, "error", err)
			return &smtp.SMTPError{
				Code:         421,
				EnhancedCode: smtp.EnhancedCode{4, 3, 2},
				Message:      "rate limit exceeded, please slow down",
			}
		}
	}

	// Perform recipient validation if enabled
	if s.recipientValidator != nil && s.serverConfig.RecipientValidation.Enabled {
		result, err := s.recipientValidator.ValidateWithContext(s.ctx, s.remoteAddr, s.ptr, s.helo, s.from, to)
		if err != nil {
			s.Logger.Warn("Recipient validation failed", "to", to, "error", err)
			// Treat validation errors as temporary failures
			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 4, 0},
				Message:      "temporary failure, please try again later",
			}
		}

		// Check if recipient is accepted
		if !result.Accepted {
			// Use custom message if provided, otherwise use default
			message := result.Message
			if message == "" {
				if result.Temporary {
					message = "temporary failure, please try again later"
				} else {
					message = "mailbox unavailable"
				}
			}

			if result.Temporary {
				s.Logger.Info("Recipient temporarily rejected by validation",
					"to", to,
					"message", message)
				return &smtp.SMTPError{
					Code:         450,
					EnhancedCode: smtp.EnhancedCode{4, 2, 1},
					Message:      message,
				}
			}

			s.Logger.Info("Recipient rejected by validation",
				"to", to,
				"message", message)
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 1, 1},
				Message:      message,
			}
		}

		s.Logger.Info("Recipient validation passed", "to", to)
	}

	// Reset to idle timeout to wait for the next command
	if err := s.setCommandTimeout(IdleTimeout); err != nil {
		return err
	}

	return nil
}

// Data is called when the email body is received.
// This is where we process the message headers and body, perform validation, and forward the email.
func (s *Session) Data(r io.Reader) (err error) {
	// 1. Perform initial checks and read the message data from the client.
	rawEmail, err := s.readMessageData(r)
	if err != nil {
		return err
	}
	defer s.mailData.Reset() // Ensure buffer is cleared after processing.

	// 2. Handle local mode separately for development and testing.
	if s.globalConfig.Local {
		return s.handleLocalMode(rawEmail)
	}

	// 3. Perform pre-delivery validation (headers, DMARC, etc.).
	// This may mark the message as junk or return a hard rejection error.
	if err := s.performPreDeliveryChecks(rawEmail); err != nil {
		return err
	}

	// 4. Attempt to deliver the message to the final destination.
	if err := s.deliverMessage(rawEmail); err != nil {
		return err
	}

	// 5. Finalize the session by recording stats for the successful delivery.
	s.finalizeSuccessfulDelivery()

	return nil
}

// readMessageData handles the initial checks and reads the email content from the client.
func (s *Session) readMessageData(r io.Reader) (string, error) {
	// Set extended timeout for receiving potentially large email data.
	if err := s.setCommandTimeout(DataTimeout); err != nil {
		return "", err
	}

	// Enforce command sequence - must have at least one recipient.
	if s.commandState != stateRcpt {
		s.Logger.Warn("Rejecting DATA - bad sequence")
		return "", &smtp.SMTPError{Code: 503, EnhancedCode: smtp.EnhancedCode{5, 5, 1}, Message: "bad sequence of commands - RCPT TO first"}
	}

	// Final update and check of TLS state.
	s.updateTLSState()
	if !s.globalConfig.Local && s.serverConfig.TLS.Required && s.tlsState == nil {
		s.Logger.Warn("Rejecting DATA - TLS required")
		return "", ErrTLSRequired
	}

	s.Logger.Info("Receiving DATA", "from", s.from, "to", s.to)

	// Read the entire email into a buffer, respecting the size limit.
	if _, err := io.Copy(&s.mailData, io.LimitReader(r, int64(s.serverConfig.MaxMessageSize))); err != nil {
		s.Logger.Error("Failed to read message data", "error", err)
		return "", err
	}

	rawEmail := s.mailData.String()

	// Record message received and size in metrics
	if s.metrics != nil {
		s.metrics.SMTPMessagesReceived.WithLabelValues(s.serverName(), s.serverType()).Inc()
		s.metrics.SMTPMessageSize.WithLabelValues(s.serverName(), s.serverType()).Observe(float64(len(rawEmail)))
	}

	// Check for empty message.
	if strings.TrimSpace(rawEmail) == "" {
		s.Logger.Warn("Rejecting empty message", "from", s.from)
		return "", &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "empty message not accepted"}
	}

	return rawEmail, nil
}

// handleLocalMode dumps the email content to the console for development/testing.
func (s *Session) handleLocalMode(rawEmail string) error {
	s.Logger.Info("=== LOCAL MODE: EMAIL CONTENT START ===")
	fmt.Println(rawEmail)
	s.Logger.Info("=== LOCAL MODE: EMAIL CONTENT END ===")
	s.Logger.Info("Local mode - received email", "from", s.from, "to", s.to)
	return nil
}

// performPreDeliveryChecks runs all content validation checks (headers, DMARC).
// It may mark the message as junk or return an SMTPError for a hard rejection.
func (s *Session) performPreDeliveryChecks(rawEmail string) error {
	// Mail loop detection (check before other validations to prevent wasting resources)
	loopDetectionEnabled := s.serverConfig.Validation.LoopDetection
	if loopDetectionEnabled {
		maxHops := s.serverConfig.Validation.MaxHops
		if maxHops <= 0 {
			maxHops = 30 // Default
		}

		loopResult := detectMailLoop(rawEmail, s.serverConfig.Hostname, maxHops)
		if loopResult.IsLoop {
			if loopResult.LoopHostname != "" {
				s.Logger.Warn("Mail loop detected - hostname appears in Received headers",
					"hostname", loopResult.LoopHostname,
					"hop_count", loopResult.HopCount,
					"from", s.from)
				if s.metrics != nil {
					s.metrics.SMTPMessagesRejected.WithLabelValues(s.serverName(), s.serverType(), "mail_loop").Inc()
				}
				return &smtp.SMTPError{
					Code:         554,
					EnhancedCode: smtp.EnhancedCode{5, 4, 6},
					Message:      "mail loop detected - message has already been processed by this server",
				}
			} else {
				s.Logger.Warn("Too many hops detected",
					"hop_count", loopResult.HopCount,
					"max_hops", maxHops,
					"from", s.from)
				if s.metrics != nil {
					s.metrics.SMTPMessagesRejected.WithLabelValues(s.serverName(), s.serverType(), "too_many_hops").Inc()
				}
				return &smtp.SMTPError{
					Code:         554,
					EnhancedCode: smtp.EnhancedCode{5, 4, 6},
					Message:      fmt.Sprintf("too many hops (%d) - possible mail loop", loopResult.HopCount),
				}
			}
		}

		// Log hop count for monitoring
		if loopResult.HopCount > 0 {
			s.Logger.Debug("Mail hop count", "hops", loopResult.HopCount, "max_hops", maxHops)
		}
	}

	// Basic header validation (required headers, format)
	if err := s.validateHeaders(rawEmail); err != nil {
		return err
	}

	// DMARC validation
	var dmarcResult *validation.DMARCResult
	var err error
	var quarantineAction string
	if s.serverConfig.DMARCCheck {
		quarantineAction = s.serverConfig.DMARCQuarantineAction
		if quarantineAction == "" {
			quarantineAction = "junk" // Default to junk for quarantine
		}
		dmarcResult, err = validation.CheckDMARC(context.Background(), rawEmail, s.spfResult, quarantineAction, s.Logger)
	}
	s.dmarcResult = dmarcResult
	if err != nil {
		s.Logger.Warn("DMARC validation error", "error", err)
		if s.metrics != nil {
			s.metrics.SMTPDMARCChecks.WithLabelValues(s.serverName(), "error").Inc()
		}
	} else if dmarcResult != nil {
		// Record DMARC check result in metrics
		if s.metrics != nil {
			if dmarcResult.Pass {
				s.metrics.SMTPDMARCChecks.WithLabelValues(s.serverName(), "pass").Inc()
			} else {
				s.metrics.SMTPDMARCChecks.WithLabelValues(s.serverName(), "fail").Inc()
			}
		}

		// Handle DMARC policy=reject failures based on configured action
		if !dmarcResult.Pass && dmarcResult.Policy == "reject" {
			rejectAction := s.serverConfig.DMARCRejectAction
			if rejectAction == "" {
				rejectAction = "reject" // Default to reject for reject policy
			}

			switch rejectAction {
			case "reject":
				s.recordDMARCFailure()
				s.Logger.Warn("Rejecting email - DMARC reject policy", "from", s.from, "reasons", dmarcResult.FailureReasons)
				if s.metrics != nil {
					s.metrics.SMTPMessagesRejected.WithLabelValues(s.serverName(), s.serverType(), "dmarc_reject").Inc()
				}
				return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "message rejected due to DMARC policy"}
			case "junk":
				s.isJunk = true
				s.Logger.Info("Marking message as junk - DMARC reject policy", "from", s.from)
			case "none":
				s.Logger.Debug("DMARC reject policy - no action configured", "from", s.from)
			}
		}

		// Handle DMARC policy=quarantine failures
		if !dmarcResult.Pass && dmarcResult.Policy == "quarantine" {
			switch quarantineAction {
			case "reject":
				s.recordDMARCFailure()
				s.Logger.Warn("Rejecting email - DMARC quarantine policy with reject action", "from", s.from, "reasons", dmarcResult.FailureReasons)
				if s.metrics != nil {
					s.metrics.SMTPMessagesRejected.WithLabelValues(s.serverName(), s.serverType(), "dmarc_quarantine").Inc()
				}
				return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "message rejected due to DMARC quarantine policy"}
			case "junk":
				// Already handled by CheckDMARC via ShouldBeJunk
			case "none":
				s.Logger.Debug("DMARC quarantine policy - no action configured", "from", s.from)
			}
		}

		// Mark as junk if DMARC suggests it.
		if dmarcResult.ShouldBeJunk {
			s.isJunk = true
			s.junkReasons = append(s.junkReasons, "DMARC check failed or missing with unaligned auth")
			s.Logger.Info("Marking as junk - DMARC", "reasons", dmarcResult.FailureReasons)
		}
	}

	// ARC (Authenticated Received Chain) validation
	// ARC preserves email authentication results through forwarding intermediaries
	if s.serverConfig.ARCCheck {
		// Create DNS lookup function using session's resolver
		lookupTXT := func(domain string) ([]string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), validation.DNSLookupTimeout)
			defer cancel()
			return s.dnsResolver.LookupTXT(ctx, domain)
		}

		arcResult, err := validation.CheckARC(context.Background(), rawEmail, lookupTXT, s.Logger)
		s.arcResult = arcResult
		if err != nil {
			s.Logger.Warn("ARC validation error", "error", err)
			if s.metrics != nil {
				s.metrics.SMTPARCChecks.WithLabelValues(s.serverName(), "error").Inc()
			}
		} else if arcResult != nil {
			// Record ARC check result in metrics
			if s.metrics != nil {
				if arcResult.Pass {
					s.metrics.SMTPARCChecks.WithLabelValues(s.serverName(), "pass").Inc()
				} else {
					s.metrics.SMTPARCChecks.WithLabelValues(s.serverName(), "fail").Inc()
				}
			}

			// Log ARC validation result
			s.Logger.Info("ARC validation result",
				"pass", arcResult.Pass,
				"chain_valid", arcResult.ChainValid,
				"instance", arcResult.Instance,
				"failure_reasons", arcResult.FailureReasons)

			// If ARC chain is broken (invalid), mark as suspicious but don't reject
			// ARC failure doesn't mean the message is spam, just that the chain is broken
			if !arcResult.Pass && arcResult.Instance > 0 {
				s.Logger.Info("ARC chain validation failed",
					"instance", arcResult.Instance,
					"reasons", arcResult.FailureReasons)
				// Note: We don't mark as junk solely based on ARC failure
				// ARC is informational and helps with forwarded emails
			}

			// If ARC validates successfully and shows the message passed authentication
			// at an earlier hop, this can override DMARC failures for forwarded emails
			if arcResult.Pass && arcResult.Instance > 0 && s.isJunk {
				s.Logger.Info("ARC chain valid - message likely forwarded, reconsidering junk status",
					"arc_instance", arcResult.Instance)
				// Note: In a full implementation, we'd parse ARC-Authentication-Results
				// to see if earlier hops validated successfully
			}
		}
	}

	if s.isJunk {
		s.Logger.Info("Message marked as junk", "from", s.from, "reasons", s.junkReasons)
	}

	return nil
}

// deliverMessage attempts to post the email to the destination endpoint.
// It translates delivery errors into appropriate SMTP temporary or permanent failure codes.
// It also checks the recipient cache before attempting delivery and caches 404/403 responses.
func (s *Session) deliverMessage(rawEmail string) error {
	// Step 1: Inject Received and X-Mizu-* headers
	// This must happen BEFORE ARC signing so the signature covers these headers
	tlsVersionStr := "none"
	if s.tlsState != nil {
		tlsVersionStr = tlsVersionString(s.tlsState.Version)
	}

	emailWithHeaders := InjectMizuHeaders(
		rawEmail,
		s.serverConfig.Hostname,
		s.remoteAddr,
		s.helo,
		s.traceID,
		tlsVersionStr,
		s.spfResult,
		s.dmarcResult,
		s.arcResult,
		s.isJunk,
		s.serverConfig.DisableMizuHeaders,
	)

	if s.serverConfig.DisableMizuHeaders {
		s.Logger.Info("Injected Received header (X-Mizu-* headers disabled)")
	} else {
		s.Logger.Info("Injected Received and X-Mizu-* headers")
	}

	// Apply junk modifications if message is marked as junk
	if s.isJunk {
		action := s.serverConfig.Junk.ApplyAction
		if action == "" {
			action = "header" // Default action
		}

		switch action {
		case "header":
			// Add custom junk header
			headerName := s.serverConfig.Junk.Header
			if headerName == "" {
				headerName = "X-Spam" // Default header
			}
			emailWithHeaders = addJunkHeader(emailWithHeaders, headerName)
			s.Logger.Info("Added junk header", "header", headerName)

		case "subject":
			// Modify subject with pattern
			pattern := s.serverConfig.Junk.SubjectPattern
			if pattern == "" {
				pattern = "[spam] %s" // Default pattern
			}
			emailWithHeaders = modifySubject(emailWithHeaders, pattern)
			s.Logger.Info("Modified subject for junk", "pattern", pattern)
		}
	}

	// Fix missing headers if configured to do so
	missingHeadersAction := s.serverConfig.Validation.MissingHeadersAction
	if missingHeadersAction == "" {
		// Default: reject for submission, fix for relay
		if s.serverConfig.IsSubmission() {
			missingHeadersAction = "reject"
		} else {
			missingHeadersAction = "fix"
		}
	}
	if missingHeadersAction == "fix" {
		var addedHeaders []string
		emailWithHeaders, addedHeaders = fixMissingHeaders(emailWithHeaders, s.serverConfig.Hostname)
		if len(addedHeaders) > 0 {
			s.Logger.Info("Fixed missing headers", "added", addedHeaders, "from", s.from)
		}
	}

	// ARC signing removed - Mizu is SMTP-to-HTTP relay, never forwards messages
	// Deliver message synchronously (no ARC signing needed)
	return s.deliverSynchronous(emailWithHeaders)
}

// deliverSynchronous handles synchronous delivery
func (s *Session) deliverSynchronous(signedEmail string) error {
	// Check recipient cache first (if distributed tracking is enabled)
	if s.distTracker != nil && len(s.to) > 0 {
		// Check cache for all recipients
		for _, recipient := range s.to {
			if found, isBlocked, reason := s.distTracker.IsRecipientCached(recipient); found {
				s.Logger.Info(fmt.Sprintf("Recipient %s found in cache: %s", recipient, reason))
				if isBlocked {
					// Recipient is blocked (403)
					return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Recipient blocked by destination"}
				}
				// Recipient not found (404)
				return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "Recipient not found"}
			}
		}
	}

	err := poster.PostEmailToDestinationWithContext(
		s.ctx,
		signedEmail,
		s.serverConfig.Delivery.URL,
		s.serverConfig.Delivery.AuthToken,
		s.serverConfig.Delivery.MaxRetryAttempts,
		s.isJunk,
		s.from,
		s.to,
		s.traceID,
		s.authenticatedUser,
		s.circuitBreaker,
		s.httpClient,
		s.Logger,
	)

	if err != nil {
		s.Logger.Error(fmt.Sprintf("Failed to deliver message to destination: %v", err))

		// Check if this is a recipient-specific error that should be cached
		var httpErr *poster.HTTPStatusError
		if errors.As(err, &httpErr) {
			// Cache 404 responses (recipient not found)
			if httpErr.IsRecipientNotFound() && s.distTracker != nil && s.distTracker.recipientCacheTTL > 0 && len(s.to) > 0 {
				for _, recipient := range s.to {
					s.distTracker.CacheRecipientNotFound(recipient)
				}
				return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "Recipient not found"}
			}

			// Cache 403 responses (recipient blocked)
			if httpErr.IsRecipientBlocked() && s.distTracker != nil && s.distTracker.recipientCacheTTL > 0 && len(s.to) > 0 {
				for _, recipient := range s.to {
					s.distTracker.CacheRecipientBlocked(recipient)
				}
				return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Recipient blocked by destination"}
			}
		}

		if poster.IsRetryableError(err) {
			// Temporary failure (e.g., network error, 5xx, circuit open).
			return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 0}, Message: "Temporary failure, please try again later"}
		}
		// Permanent failure (e.g., 4xx error, context cancelled, bad request).
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 4, 0}, Message: "Message delivery failed"}
	}

	s.Logger.Info("Successfully delivered message to destination")
	return nil
}

// finalizeSuccessfulDelivery records statistics for a successfully delivered message.
func (s *Session) finalizeSuccessfulDelivery() {
	if s.statsManager != nil {
		if s.isJunk {
			s.statsManager.RecordJunkMessage(s.remoteAddr, s.senderDomain)
		} else {
			s.statsManager.RecordHamDelivery(s.remoteAddr, s.senderDomain)
		}
	}
	s.Logger.Info("Email delivered successfully", "from", s.from, "to", s.to)
}

// recordDMARCFailure is a helper to record DMARC failure stats.
func (s *Session) recordDMARCFailure() {
	if s.statsManager != nil {
		s.statsManager.RecordDMARCFailure(s.remoteAddr, s.senderDomain)
	}
}

// validateHeaders parses and validates the email headers.
// It checks for required headers, spam flags, and common formatting issues.
// It returns an SMTPError for hard rejections or nil if validation passes (or only marks as junk).
func (s *Session) validateHeaders(rawEmail string) error {
	// Use net/mail to parse headers robustly.
	msg, err := mail.ReadMessage(strings.NewReader(rawEmail))
	if err != nil {
		s.Logger.Warn("Rejecting message - failed to parse headers", "from", s.from, "error", err)
		return &smtp.SMTPError{
			Code:    550,
			Message: "invalid header format",
		}
	}

	if msg == nil {
		return nil // Should not happen if ReadMessage doesn't error, but good practice.
	}

	headers := msg.Header

	// Check for junk headers if configured
	if len(s.serverConfig.Junk.CheckHeaders) > 0 {
		for _, headerName := range s.serverConfig.Junk.CheckHeaders {
			if headerValue := headers.Get(headerName); headerValue != "" {
				// Header detected - apply configured action
				action := s.serverConfig.Junk.ApplyAction
				if action == "" {
					action = "reject" // Default action
				}

				s.Logger.Info("Junk header detected", "from", s.from, "header", headerName, "value", headerValue, "action", action)

				// Record this as a junk message for stats
				if s.statsManager != nil {
					s.statsManager.RecordJunkMessage(s.remoteAddr, s.senderDomain)
				}

				switch action {
				case "reject":
					s.Logger.Warn("Rejecting message - junk header present", "from", s.from, "header", headerName)
					return &smtp.SMTPError{
						Code:         550,
						EnhancedCode: smtp.EnhancedCode{5, 7, 1},
						Message:      "Message identified as junk",
					}
				case "header":
					// Mark message as junk (will add header in Data method)
					s.isJunk = true
					s.Logger.Info("Marking message as junk - will add header", "from", s.from)
				case "subject":
					// Mark message as junk (will modify subject in Data method)
					s.isJunk = true
					s.Logger.Info("Marking message as junk - will modify subject", "from", s.from)
				case "warn":
					// Just log, don't modify or reject
					s.Logger.Warn("Junk header detected but no action taken", "from", s.from, "header", headerName)
				}
				break // Only process first matching header
			}
		}
	}

	// Check required headers
	if _, hasFrom := headers["From"]; !hasFrom {
		s.Logger.Warn("Rejecting message - missing From header", "from", s.from)
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "missing required From header"}
	}

	// Handle missing Date and Message-ID headers based on config
	_, hasDate := headers["Date"]
	_, hasMessageID := headers["Message-Id"]

	missingHeadersAction := s.serverConfig.Validation.MissingHeadersAction
	if missingHeadersAction == "" {
		// Default: reject for submission, fix for relay
		if s.serverConfig.IsSubmission() {
			missingHeadersAction = "reject"
		} else {
			missingHeadersAction = "fix"
		}
	}

	switch missingHeadersAction {
	case "reject":
		if !hasDate {
			s.Logger.Warn("Rejecting message - missing Date header", "from", s.from)
			return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "missing required Date header"}
		}
		if !hasMessageID {
			s.Logger.Warn("Rejecting message - missing Message-ID header", "from", s.from)
			return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "missing required Message-ID header"}
		}
	case "fix":
		// Headers will be added later before delivery (handled in fixMissingHeaders function)
		if !hasDate {
			s.Logger.Info("Will add missing Date header", "from", s.from)
		}
		if !hasMessageID {
			s.Logger.Info("Will add missing Message-ID header", "from", s.from)
		}
	case "none":
		// Allow missing headers without modification
		if !hasDate || !hasMessageID {
			s.Logger.Debug("Allowing message with missing headers", "from", s.from, "missing_date", !hasDate, "missing_message_id", !hasMessageID)
		}
	}

	// Check for duplicate headers that should be unique
	for headerKey, values := range headers {
		if len(values) > 1 {
			switch strings.ToLower(headerKey) {
			case "from", "date", "message-id", "subject", "to":
				s.isJunk = true
				s.junkReasons = append(s.junkReasons, fmt.Sprintf("duplicate %s header", headerKey))
				s.Logger.Info("Marking as junk - duplicate header", "from", s.from, "header", headerKey)
			}
		}
	}

	// Validate Date header format
	if dateHeaders, hasDate := headers["Date"]; hasDate && len(dateHeaders) > 0 {
		// Try to parse the date
		if _, err := mail.ParseDate(dateHeaders[0]); err != nil {
			s.isJunk = true
			s.junkReasons = append(s.junkReasons, "invalid Date header format")
			s.Logger.Info("Marking as junk - invalid Date format", "from", s.from, "error", err)
		}
	}

	return nil
}

// Reset is called to reset the session after a message.
func (s *Session) Reset() {
	s.Logger.Debug("Session reset")
	s.from = ""
	s.to = make([]string, 0)
	s.mailData.Reset()
	s.commandState = stateHelo // After reset, we're back to post-HELO state
	s.isJunk = false
	s.junkReasons = nil
	s.senderDomain = ""
	s.spfResult = nil

	// Reset idle timeout after successful message
	if err := s.setCommandTimeout(IdleTimeout); err != nil {
		s.Logger.Error("Failed to reset idle timeout", "error", err)
	}
}

// Logout is called when the session ends.
func (s *Session) Logout() error {
	// Ensure connection is always released even if something panics
	defer func() {
		if r := recover(); r != nil {
			s.Logger.Error("Panic in Logout - recovering but connection was released", "panic", r)
		}
	}()

	s.Logger.Debug("Session logout")
	if s.cancel != nil {
		s.cancel()
	}
	// Release connection slot for DoS protection
	// Prefer distributed tracker for cluster-wide coordination
	if s.distTracker != nil {
		s.distTracker.Release(s.remoteAddr)
	} else if s.connTracker != nil {
		s.connTracker.Release(s.remoteAddr)
	}
	// Signal that this session has completed (for graceful shutdown)
	if s.sessionsWg != nil {
		// Decrement active session counter for observability
		if s.sessionCount != nil {
			count := s.sessionCount.Add(-1)
			s.Logger.Debug("Session count decremented",
				"active_sessions", count)

			// Update Prometheus gauge
			if s.metrics != nil {
				s.metrics.SMTPConnectionsActive.WithLabelValues(s.serverConfig.Name, s.serverConfig.Type).Set(float64(count))
			}
		}

		s.sessionsWg.Done()
	}
	return nil
}

// tlsVersionString returns a human-readable TLS version string
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%x)", version)
	}
}

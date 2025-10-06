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

	"net"
	net_http "net/http"
	"net/mail"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"migadu/mizu/pkg/blacklist"
	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/dns"
	"migadu/mizu/pkg/poster"
	"migadu/mizu/pkg/stats"
	"migadu/mizu/pkg/validation"

	"github.com/emersion/go-msgauth/authres"
	"github.com/emersion/go-smtp"
	"go.uber.org/zap"
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

// Backend implements smtp.Backend interface for our custom SMTP server.
// It manages the overall server configuration and creates new sessions for incoming connections.
type Backend struct {
	Config         *config.Config         // Server configuration (ports, TLS, domains, etc.)
	StatsManager   *stats.Manager         // IP and domain reputation tracking
	CircuitBreaker *poster.CircuitBreaker // Circuit breaker for destination HTTP calls
	HTTPClient     *net_http.Client       // HTTP client for posting emails to destination
	Logger         *zap.Logger            // Structured logger for debugging and monitoring
	DNSResolver    *net.Resolver          // Custom DNS resolver (uses config.DNS.Servers or system default)

	// Connection tracking for graceful shutdown and DoS protection
	ActiveSessionsWg   *sync.WaitGroup     // Tracks active SMTP sessions
	ActiveSessionCount *atomic.Int64       // Current number of active sessions (for observability)
	ShutdownChan       chan struct{}       // Signals shutdown to new connections
	ConnTracker        *ConnectionTracker  // Tracks connections to enforce limits
	DistTracker        *DistributedTracker // Optional: Distributed connection tracking
	RateLimiter        *RateLimiter        // Rate limiter to prevent rapid connection attempts
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

	remoteAddr := c.Conn().RemoteAddr().String()

	// Track whether session was successfully created for connection cleanup
	sessionCreated := false

	// Check rate limit (prevent rapid connection attempts)
	// At this point, we only have IP information, so only IP-based dimensions will be checked
	if be.RateLimiter != nil {
		sessionCtx := SessionContext{
			RemoteAddr: remoteAddr,
		}
		if err := be.RateLimiter.CheckRateLimit(sessionCtx); err != nil {
			be.Logger.Warn("Rate limit exceeded", zap.String("remote_addr", remoteAddr), zap.Error(err))
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
			be.Logger.Warn("Distributed connection limit exceeded", zap.String("remote_addr", remoteAddr), zap.Error(err))
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
			be.Logger.Warn("Connection limit exceeded", zap.String("remote_addr", remoteAddr), zap.Error(err))
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
				zap.Int64("active_sessions", count),
				zap.String("remote_addr", remoteAddr))
		}

		// Panic recovery: ensure we call Done() if session creation panics
		defer func() {
			if r := recover(); r != nil {
				be.Logger.Error("Panic in NewSession - recovering",
					zap.String("remote_addr", remoteAddr),
					zap.Any("panic", r),
					zap.Stack("stack"))

				// Decrement counter and call Done() since we won't reach Logout()
				if be.ActiveSessionCount != nil {
					be.ActiveSessionCount.Add(-1)
				}
				be.ActiveSessionsWg.Done()

				// Re-panic to let go-smtp library handle it
				panic(r)
			}
		}()
	}

	be.Logger.Info("New session", zap.String("remote_addr", remoteAddr))

	ipStr := stats.GetIPFromRemoteAddr(remoteAddr)
	hasRDNS := true

	// Perform security checks in production mode
	if !be.Config.Local {
		// Extract IP from address
		host, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			be.Logger.Error("Failed to parse remote address", zap.String("remote_addr", remoteAddr), zap.Error(err))
			return nil, ErrInternalServerError
		}

		// Parse IP address
		ip := net.ParseIP(host)
		if ip == nil {
			be.Logger.Error("Failed to parse IP address", zap.String("host", host))
			return nil, ErrInternalServerError
		}

		// Check DNS blacklists (RBLs) to prevent spam
		if be.Config.Blacklists.Enabled && len(be.Config.Blacklists.Lists) > 0 {
			checker := blacklist.NewChecker(be.Config.Blacklists.Lists, time.Duration(be.Config.Blacklists.TimeoutSeconds)*time.Second, be.Logger)
			isListed, reason, err := checker.CheckIP(ip)
			if err != nil {
				be.Logger.Error("Blacklist check error", zap.Error(err), zap.String("ip", host))
				// Don't reject on blacklist check errors - fail open for availability
			} else if isListed {
				be.Logger.Warn("Rejecting session - blacklisted", zap.String("remote_addr", remoteAddr), zap.String("reason", reason))
				return nil, &smtp.SMTPError{
					Code:         550,
					EnhancedCode: smtp.EnhancedCode{5, 7, 1},
					Message:      fmt.Sprintf("your IP address is blacklisted: %s", reason),
				}
			}
		}

		// Require valid reverse DNS (PTR record) - helps prevent spam from compromised hosts
		// Use context with timeout to prevent hanging on unresponsive DNS servers
		rdnsCtx, rdnsCancel := context.WithTimeout(context.Background(), time.Duration(be.Config.DNS.TimeoutSeconds)*time.Second)
		names, err := be.DNSResolver.LookupAddr(rdnsCtx, host)
		rdnsCancel()
		if err != nil || len(names) == 0 {
			hasRDNS = false
			// Record this in stats
			if be.StatsManager != nil {
				be.StatsManager.RecordConnection(ipStr, false)
			}
			be.Logger.Warn("Rejecting session - no reverse DNS", zap.String("remote_addr", remoteAddr))
			return nil, &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 7, 25},
				Message:      "no reverse DNS record for IP address",
			}
		}
		be.Logger.Debug("Reverse DNS lookup", zap.String("host", host), zap.Any("names", names))

		// Record connection in stats
		if be.StatsManager != nil {
			be.StatsManager.RecordConnection(ipStr, hasRDNS)

			// Check IP reputation
			if shouldDeny, reputation := be.StatsManager.CheckIPReputation(ipStr); shouldDeny {
				be.Logger.Warn("Rejecting session - poor reputation", zap.String("remote_addr", remoteAddr), zap.Float64("score", reputation))
				return nil, &smtp.SMTPError{
					Code:         421,
					EnhancedCode: smtp.EnhancedCode{4, 7, 1},
					Message:      "please try again later",
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
		be.Logger.Error("Failed to set deadline", zap.Error(err))
		return nil, ErrInternalServerError
	}

	// Generate unique trace ID for this session
	traceID := generateTraceID()

	session := &Session{
		conn:           c,
		helo:           "",
		from:           "",
		to:             make([]string, 0),
		remoteAddr:     c.Conn().RemoteAddr().String(),
		config:         be.Config,
		tlsState:       tlsState,
		statsManager:   be.StatsManager,
		circuitBreaker: be.CircuitBreaker,
		httpClient:     be.HTTPClient,
		dnsResolver:    be.DNSResolver,
		connTracker:    be.ConnTracker,
		distTracker:    be.DistTracker,
		rateLimiter:    be.RateLimiter,
		ctx:            ctx,
		Logger:         be.Logger.With(zap.String("trace_id", traceID)),
		cancel:         cancel,
		sessionsWg:     be.ActiveSessionsWg,
		sessionCount:   be.ActiveSessionCount,
		commandState:   stateNew, // Explicitly initialize command state
		traceID:        traceID,
	}

	sessionCreated = true
	return session, nil
}

// Session represents an active SMTP session for an incoming email.
// It tracks the SMTP conversation state and enforces protocol requirements.
type Session struct {
	conn           *smtp.Conn             // The underlying SMTP connection
	helo           string                 // HELO/EHLO domain from the client
	from           string                 // Sender's email address (MAIL FROM)
	to             []string               // Recipient email addresses (RCPT TO)
	remoteAddr     string                 // Remote IP:port of the client
	mailData       bytes.Buffer           // Buffer to store the raw email body
	config         *config.Config         // Server configuration
	tlsState       *tls.ConnectionState   // TLS connection state (nil if not using TLS)
	statsManager   *stats.Manager         // IP and domain reputation tracking
	circuitBreaker *poster.CircuitBreaker // Circuit breaker for HTTP destination
	httpClient     *net_http.Client       // HTTP client for posting emails to destination
	dnsResolver    *net.Resolver          // DNS resolver (custom or system default)
	connTracker    *ConnectionTracker     // Connection tracker for DoS protection
	distTracker    *DistributedTracker    // Distributed connection tracker (optional, for cluster-wide limits)
	rateLimiter    *RateLimiter           // Multi-dimensional rate limiter
	ctx            context.Context        // Session context with deadline for timeout
	Logger         *zap.Logger            // Structured logger for this session
	cancel         context.CancelFunc     // Cancel function to clean up resources
	sessionsWg     *sync.WaitGroup        // WaitGroup to track active sessions for graceful shutdown
	sessionCount   *atomic.Int64          // Pointer to active session counter for observability

	// Anti-spam tracking
	isJunk       bool     // Whether this message is considered junk/spam
	junkReasons  []string // Specific reasons why message is marked as junk
	commandState int      // Track SMTP command sequence state for protocol enforcement
	traceID      string   // Unique trace ID for correlating logs and tracking email through system

	// Stats tracking
	senderDomain string // Domain from MAIL FROM for stats
	spfResult    *validation.SPFResult
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

// Helo is called for the HELO/EHLO command.
// RFC 5321 requires this to be the first command in an SMTP session.
func (s *Session) Helo(hostname string) error {
	// Set timeout for this command
	if err := s.setCommandTimeout(ProcessingTimeout); err != nil {
		return err
	}

	// Enforce command sequence - HELO/EHLO must be first
	if s.commandState != stateNew {
		s.Logger.Warn("Rejecting HELO/EHLO - already received", zap.String("remote_addr", s.remoteAddr), zap.Int("state", int(s.commandState)))
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "bad sequence of commands",
		}
	}

	// Validate HELO hostname for security (skip in local development mode)
	if !s.config.Local {
		// Reject if HELO claims to be our own domain or a subdomain (spoofing attempt)
		// Case-insensitive check for robustness.
		if strings.HasSuffix(strings.ToLower(hostname), "."+strings.ToLower(s.config.SMTP.Domain)) || strings.EqualFold(hostname, s.config.SMTP.Domain) {
			s.Logger.Warn("Rejecting HELO/EHLO - client using our domain", zap.String("remote_addr", s.remoteAddr), zap.String("hostname", hostname), zap.String("our_domain", s.config.SMTP.Domain))
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 7, 8},
				Message:      "invalid HELO hostname",
			}
		}

		// Reject localhost or single-label hostnames
		if hostname == "localhost" || !strings.Contains(hostname, ".") {
			s.Logger.Warn("Rejecting HELO/EHLO - invalid hostname", zap.String("remote_addr", s.remoteAddr), zap.String("hostname", hostname))
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 7, 1},
				Message:      "HELO requires fully-qualified hostname",
			}
		}

		// Reject bare IP addresses. Per RFC 5321, IP literals must be in brackets.
		isIPLiteral := strings.HasPrefix(hostname, "[") && strings.HasSuffix(hostname, "]")
		if !isIPLiteral && net.ParseIP(hostname) != nil {
			s.Logger.Warn("Rejecting HELO/EHLO - bare IP", zap.String("remote_addr", s.remoteAddr), zap.String("ip", hostname))
			return &smtp.SMTPError{
				Code:    550,
				Message: "HELO with bare IP must use [IP] format",
			}
		}

		// Check for invalid characters
		if strings.ContainsAny(hostname, " \t\r\n") {
			s.Logger.Warn("Rejecting HELO/EHLO - invalid characters", zap.String("remote_addr", s.remoteAddr))
			return &smtp.SMTPError{
				Code:    550,
				Message: "invalid characters in HELO hostname",
			}
		}

		// Optional: Verify HELO hostname has valid DNS records
		if s.config.Blacklists.CheckHELOResolves {
			resolves, err := blacklist.CheckHELOResolves(hostname, time.Duration(s.config.Blacklists.TimeoutSeconds)*time.Second)
			if err != nil || !resolves {
				s.Logger.Warn("Rejecting HELO/EHLO - hostname mismatch", zap.String("remote_addr", s.remoteAddr), zap.String("hostname", hostname))
				return &smtp.SMTPError{
					Code:         550,
					EnhancedCode: smtp.EnhancedCode{5, 7, 27},
					Message:      "HELO hostname does not resolve",
				}
			}
		}
	}

	s.helo = hostname
	s.commandState = stateHelo
	s.Logger.Info("HELO/EHLO received", zap.String("remote_addr", s.remoteAddr), zap.String("hostname", hostname))

	// Reset to idle timeout to wait for the next command
	if err := s.setCommandTimeout(IdleTimeout); err != nil {
		return err
	}

	return nil
}

// updateTLSState updates the TLS state from the connection
func (s *Session) updateTLSState() {
	state, ok := s.conn.TLSConnectionState()
	if ok {
		s.tlsState = &state
	} else {
		s.tlsState = nil
	}
}

// setCommandTimeout sets the deadline for the current command
func (s *Session) setCommandTimeout(timeout time.Duration) error {
	// Check if session deadline has been exceeded
	select {
	case <-s.ctx.Done():
		s.Logger.Warn("Session deadline exceeded", zap.String("remote_addr", s.remoteAddr))
		return ErrSessionTimeout
	default:
		// Set the command timeout
		deadline := time.Now().Add(timeout)
		if err := s.conn.Conn().SetDeadline(deadline); err != nil {
			s.Logger.Error("Failed to set deadline", zap.Error(err))
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
	if from == "" || from == "<>" {
		s.Logger.Warn("Rejecting null sender", zap.String("remote_addr", s.remoteAddr))
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "null sender not accepted",
		}
	}

	// Handle case where go-smtp library processed EHLO internally
	heloHostname := s.conn.Hostname()
	if heloHostname != "" && s.helo == "" {
		// EHLO was handled by go-smtp internally, update our state
		s.helo = heloHostname
		s.commandState = stateHelo
		s.Logger.Debug("HELO/EHLO set via conn.Hostname", zap.String("remote_addr", s.remoteAddr), zap.String("hostname", heloHostname))
	}

	// Set timeout for this command
	if err := s.setCommandTimeout(ProcessingTimeout); err != nil {
		return err
	}

	// Check if HELO/EHLO has been received
	if s.helo == "" {
		s.Logger.Warn("Rejecting MAIL FROM - no HELO/EHLO", zap.String("remote_addr", s.remoteAddr))
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "bad sequence of commands - HELO/EHLO first",
		}
	}

	// Update and check TLS state (skip in local mode)
	s.updateTLSState()
	if !s.config.Local && s.tlsState == nil {
		s.Logger.Warn("Rejecting MAIL FROM - TLS required", zap.String("from", from))
		return ErrTLSRequiredStartTLS
	}

	// Extract domain from sender
	senderDomain := stats.ExtractDomainFromEmail(from)
	s.senderDomain = senderDomain

	// Record MAIL FROM in stats
	if s.statsManager != nil && senderDomain != "" {
		s.statsManager.RecordMailFrom(senderDomain)

		// Check domain reputation
		if shouldDeny, reputation := s.statsManager.CheckDomainReputation(senderDomain); shouldDeny {
			s.Logger.Warn("Rejecting MAIL FROM - poor domain reputation", zap.String("from", from), zap.Float64("score", reputation))
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
	if !s.config.Local {
		var wg sync.WaitGroup
		var spfMu sync.Mutex // Protect SPF result writes

		// SPF check in parallel
		ipStr := stats.GetIPFromRemoteAddr(s.remoteAddr)
		ip := net.ParseIP(ipStr)
		if ip != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := validation.CheckSPF(context.Background(), ip, s.helo, from)
				if err != nil {
					s.Logger.Debug("SPF check error", zap.String("from", from), zap.Error(err))
				} else if res != nil {
					s.Logger.Debug("SPF result", zap.String("from", from), zap.String("result", string(*res)))
					spfMu.Lock()
					s.spfResult = &validation.SPFResult{
						Domain: s.senderDomain,
						Result: authres.SPFResult{
							Value: validation.ConvertSPFResult(*res),
						},
					}
					spfMu.Unlock()
				}
			}()
		}

		// MX check in parallel
		var mxErr error
		var hasMX bool
		if s.config.SMTP.RequireSenderMX && senderDomain != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var err error
				hasMX, err = validation.CheckMXRecord(context.Background(), senderDomain, s.dnsResolver, time.Duration(s.config.DNS.TimeoutSeconds)*time.Second)
				if err != nil {
					s.Logger.Warn("MX lookup error for sender domain", zap.String("from", from), zap.String("domain", senderDomain), zap.Error(err))
					mxErr = err
					// Continue despite lookup error - don't fail on temporary DNS issues
				} else if !hasMX {
					s.Logger.Warn("Sender domain has no MX records", zap.String("from", from), zap.String("domain", senderDomain))
				} else {
					s.Logger.Debug("Sender domain has valid MX records", zap.String("from", from), zap.String("domain", senderDomain))
				}
			}()
		}

		// Wait for both DNS queries to complete
		wg.Wait()

		// Check MX result after parallel execution
		if s.config.SMTP.RequireSenderMX && senderDomain != "" && mxErr == nil && !hasMX {
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 7, 1},
				Message:      "sender domain has no mail servers (no MX records)",
			}
		}
	}

	s.from = from
	s.commandState = stateMail

	// Check rate limits now that we have FROM information
	// This allows FROM, FROM_DOMAIN, and IP+FROM combination checks
	if s.rateLimiter != nil {
		sessionCtx := SessionContext{
			RemoteAddr: s.remoteAddr,
			From:       from,
			To:         s.to, // May be empty at this point
		}
		if err := s.rateLimiter.CheckRateLimit(sessionCtx); err != nil {
			s.Logger.Warn("Rate limit exceeded for sender", zap.String("from", from), zap.Error(err))
			return &smtp.SMTPError{
				Code:         421,
				EnhancedCode: smtp.EnhancedCode{4, 3, 2},
				Message:      "rate limit exceeded, please slow down",
			}
		}
	}

	if s.tlsState != nil {
		s.Logger.Info("MAIL FROM", zap.String("from", from), zap.String("remote_addr", s.remoteAddr), zap.String("tls", tlsVersionString(s.tlsState.Version)))
	} else {
		s.Logger.Info("MAIL FROM", zap.String("from", from), zap.String("remote_addr", s.remoteAddr), zap.String("tls", "none"))
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
		s.Logger.Warn("Rejecting RCPT TO - bad sequence", zap.String("remote_addr", s.remoteAddr))
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "bad sequence of commands - MAIL FROM first",
		}
	}

	// Update and check TLS state (skip in local mode)
	s.updateTLSState()
	if !s.config.Local && s.tlsState == nil {
		s.Logger.Warn("Rejecting RCPT TO - TLS required", zap.String("to", to))
		return ErrTLSRequired
	}

	s.Logger.Info("RCPT TO", zap.String("to", to), zap.String("remote_addr", s.remoteAddr))

	// Enforce single recipient per transaction
	// This ensures per-recipient validation at the destination and proper retry behavior
	if len(s.to) >= 1 {
		s.Logger.Warn("Rejecting RCPT TO - multiple recipients", zap.String("to", to))
		return &smtp.SMTPError{
			Code:         452,
			EnhancedCode: smtp.EnhancedCode{4, 5, 3},
			Message:      "Too many recipients (only one allowed per transaction)",
		}
	}

	s.to = append(s.to, to)
	s.commandState = stateRcpt

	// Check rate limits now that we have TO information
	// This allows TO, TO_DOMAIN, FROM+TO, and other recipient-based combination checks
	if s.rateLimiter != nil {
		sessionCtx := SessionContext{
			RemoteAddr: s.remoteAddr,
			From:       s.from,
			To:         s.to,
		}
		if err := s.rateLimiter.CheckRateLimit(sessionCtx); err != nil {
			s.Logger.Warn("Rate limit exceeded for recipient", zap.String("to", to), zap.Error(err))
			return &smtp.SMTPError{
				Code:         421,
				EnhancedCode: smtp.EnhancedCode{4, 3, 2},
				Message:      "rate limit exceeded, please slow down",
			}
		}
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
	if s.config.Local {
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
		s.Logger.Warn("Rejecting DATA - bad sequence", zap.String("remote_addr", s.remoteAddr))
		return "", &smtp.SMTPError{Code: 503, EnhancedCode: smtp.EnhancedCode{5, 5, 1}, Message: "bad sequence of commands - RCPT TO first"}
	}

	// Final update and check of TLS state.
	s.updateTLSState()
	if !s.config.Local && s.tlsState == nil {
		s.Logger.Warn("Rejecting DATA - TLS required")
		return "", ErrTLSRequired
	}

	s.Logger.Info("Receiving DATA", zap.String("from", s.from), zap.Strings("to", s.to))

	// Read the entire email into a buffer, respecting the size limit.
	if _, err := io.Copy(&s.mailData, io.LimitReader(r, int64(s.config.SMTP.MaxMessageSize))); err != nil {
		s.Logger.Error("Failed to read message data", zap.Error(err))
		return "", err
	}

	rawEmail := s.mailData.String()

	// Check for empty message.
	if strings.TrimSpace(rawEmail) == "" {
		s.Logger.Warn("Rejecting empty message", zap.String("from", s.from))
		return "", &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "empty message not accepted"}
	}

	return rawEmail, nil
}

// handleLocalMode dumps the email content to the console for development/testing.
func (s *Session) handleLocalMode(rawEmail string) error {
	s.Logger.Info("=== LOCAL MODE: EMAIL CONTENT START ===")
	fmt.Println(rawEmail)
	s.Logger.Info("=== LOCAL MODE: EMAIL CONTENT END ===")
	s.Logger.Info("Local mode - received email", zap.String("from", s.from), zap.Strings("to", s.to))
	return nil
}

// performPreDeliveryChecks runs all content validation checks (headers, DMARC).
// It may mark the message as junk or return an SMTPError for a hard rejection.
func (s *Session) performPreDeliveryChecks(rawEmail string) error {
	// Header validation
	if err := s.validateHeaders(rawEmail); err != nil {
		return err
	}

	// DMARC validation
	dmarcResult, err := validation.CheckDMARC(context.Background(), rawEmail, s.spfResult, s.config.SMTP.DMARCQuarantineAsJunk, s.Logger)
	if err != nil {
		s.Logger.Warn("DMARC validation error", zap.Error(err))
	} else if dmarcResult != nil {
		// If DMARC policy is 'reject' and validation failed, reject the message.
		if !dmarcResult.Pass && dmarcResult.Policy == "reject" {
			s.recordDMARCFailure()
			s.Logger.Warn("Rejecting email - DMARC reject policy", zap.String("from", s.from), zap.Strings("reasons", dmarcResult.FailureReasons))
			return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "message rejected due to DMARC policy"}
		}

		// Mark as junk if DMARC suggests it.
		if dmarcResult.ShouldBeJunk {
			s.isJunk = true
			s.junkReasons = append(s.junkReasons, "DMARC check failed or missing with unaligned auth")
			s.Logger.Info("Marking as junk - DMARC", zap.Strings("reasons", dmarcResult.FailureReasons))
		}
	}

	if s.isJunk {
		s.Logger.Info("Message marked as junk", zap.String("from", s.from), zap.Strings("reasons", s.junkReasons))
	}

	return nil
}

// deliverMessage attempts to post the email to the destination endpoint.
// It translates delivery errors into appropriate SMTP temporary or permanent failure codes.
// It also checks the recipient cache before attempting delivery and caches 404/403 responses.
func (s *Session) deliverMessage(rawEmail string) error {
	// Check recipient cache first (if distributed tracking is enabled)
	if s.distTracker != nil && len(s.to) > 0 {
		// Check cache for all recipients
		for _, recipient := range s.to {
			if found, isBlocked, reason := s.distTracker.IsRecipientCached(recipient); found {
				s.Logger.Sugar().Infof("Recipient %s found in cache: %s", recipient, reason)
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
		rawEmail,
		s.config.Destination.URL,
		s.config.Destination.APIKey,
		s.config.Destination.MaxRetryAttempts,
		s.isJunk,
		s.from,
		s.to,
		s.traceID,
		s.circuitBreaker,
		s.httpClient,
		s.Logger,
	)

	if err != nil {
		s.Logger.Sugar().Errorf("Failed to deliver message to destination: %v", err)

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
		ipStr := stats.GetIPFromRemoteAddr(s.remoteAddr)
		if s.isJunk {
			s.statsManager.RecordJunkMessage(ipStr, s.senderDomain)
		} else {
			s.statsManager.RecordHamDelivery(ipStr, s.senderDomain)
		}
	}
	s.Logger.Info("Email delivered successfully", zap.String("from", s.from), zap.Strings("to", s.to))
}

// recordDMARCFailure is a helper to record DMARC failure stats.
func (s *Session) recordDMARCFailure() {
	if s.statsManager != nil {
		ipStr := stats.GetIPFromRemoteAddr(s.remoteAddr)
		s.statsManager.RecordDMARCFailure(ipStr, s.senderDomain)
	}
}

// validateHeaders parses and validates the email headers.
// It checks for required headers, spam flags, and common formatting issues.
// It returns an SMTPError for hard rejections or nil if validation passes (or only marks as junk).
func (s *Session) validateHeaders(rawEmail string) error {
	// Use net/mail to parse headers robustly.
	msg, err := mail.ReadMessage(strings.NewReader(rawEmail))
	if err != nil {
		s.Logger.Warn("Rejecting message - failed to parse headers", zap.String("from", s.from), zap.Error(err))
		return &smtp.SMTPError{
			Code:    550,
			Message: "invalid header format",
		}
	}

	if msg == nil {
		return nil // Should not happen if ReadMessage doesn't error, but good practice.
	}

	headers := msg.Header

	// Check for external spam flags if enabled
	if s.config.SMTP.CheckXSpamFlag {
		if spamFlag := headers.Get("X-Spam-Flag"); strings.EqualFold(spamFlag, "YES") {
			s.Logger.Warn("Rejecting message - X-Spam-Flag YES", zap.String("from", s.from))
			// Record this as a junk message for stats
			if s.statsManager != nil {
				ipStr := stats.GetIPFromRemoteAddr(s.remoteAddr)
				s.statsManager.RecordJunkMessage(ipStr, s.senderDomain)
			}
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 7, 1},
				Message:      "Message identified as spam",
			}
		}
	}

	// Check required headers
	if _, hasFrom := headers["From"]; !hasFrom {
		s.Logger.Warn("Rejecting message - missing From header", zap.String("from", s.from))
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "missing required From header"}
	}
	if _, hasDate := headers["Date"]; !hasDate {
		s.Logger.Warn("Rejecting message - missing Date header", zap.String("from", s.from))
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "missing required Date header"}
	}

	// Check for junk indicators
	if _, hasMessageID := headers["Message-Id"]; !hasMessageID {
		s.isJunk = true
		s.junkReasons = append(s.junkReasons, "missing Message-ID header")
		s.Logger.Info("Marking as junk - missing Message-ID", zap.String("from", s.from))
	}

	// Check for duplicate headers that should be unique
	for headerKey, values := range headers {
		if len(values) > 1 {
			switch strings.ToLower(headerKey) {
			case "from", "date", "message-id", "subject", "to":
				s.isJunk = true
				s.junkReasons = append(s.junkReasons, fmt.Sprintf("duplicate %s header", headerKey))
				s.Logger.Info("Marking as junk - duplicate header", zap.String("from", s.from), zap.String("header", headerKey))
			}
		}
	}

	// Validate Date header format
	if dateHeaders, hasDate := headers["Date"]; hasDate && len(dateHeaders) > 0 {
		// Try to parse the date
		if _, err := mail.ParseDate(dateHeaders[0]); err != nil {
			s.isJunk = true
			s.junkReasons = append(s.junkReasons, "invalid Date header format")
			s.Logger.Info("Marking as junk - invalid Date format", zap.String("from", s.from), zap.Error(err))
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
		s.Logger.Error("Failed to reset idle timeout", zap.Error(err))
	}
}

// Logout is called when the session ends.
func (s *Session) Logout() error {
	s.Logger.Debug("Session logout", zap.String("remote_addr", s.remoteAddr))
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
				zap.Int64("active_sessions", count),
				zap.String("remote_addr", s.remoteAddr))
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

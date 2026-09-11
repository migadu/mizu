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
	"slices"
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

// Session timeouts, in the order they bind.
//
// The wait for the next command belongs to go-smtp, not to this package:
// Server.ReadTimeout (config timeout_seconds, RFC 5321 §4.5.3.2.7 requires at
// least 5 minutes) is re-armed before every command read and therefore
// overrides whatever deadline a session callback left on the socket. The
// deadlines below are what remains ours: the DATA body, which go-smtp hands to
// Session.Data without touching the deadline, and a backstop for deployments
// that disable go-smtp's timeouts by setting timeout_seconds to 0.
const (
	// SessionDeadline caps time spent without completing a transaction, and is
	// restarted by extendSessionDeadline whenever one completes — a sender
	// working through a queue on one connection is judged on progress, not on
	// total connection age. It bounds a client that drips valid commands
	// forever; a client that simply goes quiet is cut off far sooner by the
	// per-phase budgets below.
	SessionDeadline = 30 * time.Minute

	// DataPhaseBudget is what ensureSessionBudget reserves when DATA starts, so
	// receiving the body and delivering it synchronously is never handed
	// whatever scrap of the session budget happens to remain. RFC 5321
	// §4.5.3.2.6 allows 10 minutes for the reply to the end of a DATA transfer
	// precisely so this work can finish before the sender gives up. It is also
	// the ceiling on the body read: the rolling deadline below may not push
	// past the session deadline, or a client dripping one byte at a time could
	// hold the phase open forever.
	DataPhaseBudget = 10 * time.Minute

	// DataBlockTimeout bounds how long the client may stall *within* the
	// message body. It is re-armed on every chunk that arrives (see
	// rollingDeadlineReader), per RFC 5321 §4.5.3.2.6, which specifies a
	// per-block rather than a whole-transfer budget. A single deadline over
	// the entire body would silently turn max_message_size into a minimum
	// bandwidth requirement (25MB in 2 minutes ≈ 1.7 Mbit/s) and cut off
	// mobile and other slow uplinks mid-message.
	DataBlockTimeout = 3 * time.Minute

	// ProcessingTimeout is the socket deadline held while a command handler
	// runs, and IdleTimeout the one left behind for the wait that follows.
	// Both are normally superseded by go-smtp's own deadlines; they matter
	// when those are disabled. Setting either is also where a session's
	// remaining SessionDeadline budget is checked (see setCommandTimeout).
	ProcessingTimeout = 30 * time.Second
	IdleTimeout       = 1 * time.Minute
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

// SpamChecker defines the interface for external spam checking (rspamd).
// authenticatedUser is the SMTP AUTH username (empty for unauthenticated
// relay/inbound mail); it is passed to rspamd as the "User" header so rspamd
// can recognize authenticated submission as outgoing mail and apply its
// outbound settings (e.g. skip inbound filtering, sign with DKIM/ARC).
type SpamChecker interface {
	Check(ctx context.Context, traceID, message, clientIP, from string, rcpt []string, helo, authenticatedUser string) (SpamCheckResult, error)
}

// SpamCheckResult represents the result of spam checking
type SpamCheckResult struct {
	IsSpam       bool                // True if message should be treated as spam
	Action       string              // Rspamd action (e.g., "add header", "reject")
	Score        float64             // Spam score
	AddHeaders   map[string][]string // Headers to add (from rspamd milter); each key may map to multiple values when rspamd asks for the same header more than once (e.g. Authentication-Results)
	ShouldReject bool                // True if message should be permanently rejected (5xx) based on action
	ShouldDefer  bool                // True if message should be temporarily deferred (4xx), e.g. rspamd "soft reject"
	SMTPMessage  string              // Custom SMTP reply text from rspamd (messages.smtp_message); used on reject/defer when non-empty, else a generic message
}

// Backend implements smtp.Backend interface for our custom SMTP server.
// It manages the overall server configuration and creates new sessions for incoming connections.
type Backend struct {
	ServerConfig   *config.ServerConfig   // Server-specific configuration (this server instance)
	GlobalConfig   *config.Config         // Global configuration (shared across servers)
	StatsManager   *stats.ServerRecorder  // IP and domain reputation tracking (per-server)
	CircuitBreaker *poster.CircuitBreaker // Circuit breaker for destination HTTP calls
	HTTPClient     *net_http.Client       // HTTP client for posting emails to destination
	Logger         *slog.Logger           // Structured logger for debugging and monitoring
	DNSResolver    *net.Resolver          // Custom DNS resolver (uses config.DNS.Servers or system default)
	DNSCache       *dns.CachingWrapper    // Caching wrapper around DNSResolver; preferred for TXT/MX lookups
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

	// Spam checking
	SpamChecker SpamChecker // Optional: External spam checker (rspamd)
}

// Authenticator interface for SMTP AUTH.
//
// Authenticate's return pair is a three-way verdict, and the session layer maps
// it straight onto SMTP reply codes - implementations must respect it exactly:
//
//	(true, nil)   authenticated
//	(false, nil)  the backend has no such account. PERMANENT: a 535 5.7.8,
//	              because no retry can make a missing account appear.
//	(_, err)      the account may well exist, but this attempt could not be
//	              authenticated - wrong password, an unusable stored hash, an
//	              account denied submission, or a backend failure. TEMPORARY:
//	              a 454 4.7.0, so a client keeps a stored password that may
//	              still be valid instead of discarding it.
//
// The dividing line is whether the ACCOUNT exists, not whether the credential
// was correct: everything except a missing account can change without the
// client doing anything, so only a missing account earns a permanent reply.
//
// The asymmetry is deliberate: err is checked first, so an implementation that
// signals a rejection with an error can only ever be too lenient (a 4xx), never
// too harsh. Only return (false, nil) when the account itself is absent.
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

	// If the client sends EHLO/HELO multiple times on the same connection (e.g. after
	// STARTTLS fails or due to a misbehaving client), the go-smtp library calls NewSession
	// again without calling Logout on the previous session first. Release the old session's
	// connection slot now to prevent the counter from leaking.
	if prev := c.Session(); prev != nil {
		// We must cast to *Session to access our custom Logout method if needed,
		// but since Session interface has Logout, we can just call it.
		// However, we need to be careful about what Logout does.
		// Our Logout releases the connection slot.
		if err := prev.Logout(); err != nil {
			be.Logger.Error("Failed to logout previous session", "error", err)
		}
		// Explicitly set the session to nil on the connection to prevent double-logout
		// or other issues if go-smtp tries to use it later (though it shouldn't).
		// Note: go-smtp doesn't expose a SetSession method on Conn interface,
		// but we are in NewSession which is called by go-smtp, and it will overwrite
		// the session on the connection after this function returns successfully.
	}

	// Extract IP without port for all subsequent operations
	remoteAddrWithPort := c.Conn().RemoteAddr().String()
	host, _, err := net.SplitHostPort(remoteAddrWithPort)
	if err != nil {
		// If split fails, use the raw address (shouldn't happen with TCP connections)
		host = remoteAddrWithPort
	}
	var remoteAddr string
	if normalized, ok := stats.NormalizeIP(host); ok {
		remoteAddr = normalized
	} else {
		remoteAddr = host
	}

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
	// Note: We use lock-free atomic operations to avoid RWMutex contention under high load.
	// GetTotalCount() is lock-free (atomic read), GetCountForIP() uses RLock for single IP only.
	var activeConnections int
	var connectionsFromIP int
	if be.DistTracker != nil {
		activeConnections = be.DistTracker.GetTotalCount()
		connectionsFromIP = be.DistTracker.GetCountForIP(remoteAddr)
	} else if tracker != nil {
		activeConnections = tracker.GetTotalCount()
		connectionsFromIP = tracker.GetCountForIP(remoteAddr)
	}

	be.Logger.Info("Client connected",
		"server", be.ServerConfig.Name,
		"remote_addr", remoteAddr,
		"active_connections", activeConnections,
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

		// Check DNS blacklists (DNSBL) for reputation scoring
		if be.ServerConfig.Reputation.Enabled && be.ServerConfig.Reputation.DNSBL.Enabled {
			// Determine which DNSBL lists to use based on IP version
			var lists []string
			if ip.To4() != nil {
				// IPv4 address
				lists = be.ServerConfig.Reputation.DNSBL.IPv4Lists
			} else {
				// IPv6 address
				lists = be.ServerConfig.Reputation.DNSBL.IPv6Lists
			}

			if len(lists) > 0 {
				timeoutSecs := be.ServerConfig.Reputation.DNSBL.TimeoutSeconds
				if timeoutSecs == 0 {
					timeoutSecs = 3 // Default timeout
				}
				checker := blacklist.NewChecker(lists, time.Duration(timeoutSecs)*time.Second, be.Logger)
				isListed, reason, err := checker.CheckIP(ip)
				if err != nil {
					be.Logger.Error("DNSBL check error", "error", err, "ip", host)
					// Don't penalize on DNSBL check errors - fail open for availability
				} else if isListed {
					// Record DNSBL hit in reputation system
					weight := be.ServerConfig.Reputation.DNSBL.Weight
					if weight == 0 {
						weight = 5 // Default weight
					}

					be.Logger.Info("DNSBL hit - recording negative reputation",
						"server", be.ServerConfig.Name,
						"remote_addr", remoteAddr,
						"reason", reason,
						"weight", weight)

					if be.StatsManager != nil {
						be.StatsManager.RecordDNSBLHit(ipStr, weight)
					}

					// Record blacklist detection in metrics
					if be.Metrics != nil {
						be.Metrics.SMTPBlacklistChecks.WithLabelValues(be.ServerConfig.Name, "blocked").Inc()
					}
				} else if be.Metrics != nil {
					// Record successful blacklist check
					be.Metrics.SMTPBlacklistChecks.WithLabelValues(be.ServerConfig.Name, "pass").Inc()
				}
			}
		}

		// Reverse DNS (PTR) lookup. LookupAddr is uncached and blocks the EHLO
		// response (NewSession runs again after STARTTLS re-EHLO, so it can fire
		// twice per message), so only pay for it when something consumes the PTR:
		// require_rdns, a reputation PTR-hostname whitelist, or a $ptr placeholder
		// in a sender/recipient validation URL. Submission servers with none of
		// these skip it — a slow or absent PTR no longer stalls every send.
		// When skipped, ptrRecord stays "" and hasRDNS stays true (we don't
		// penalize an IP for a check we chose not to run).
		if be.ServerConfig.NeedsReverseDNS() {
			// Use context with timeout to prevent hanging on unresponsive DNS servers
			rdnsCtx, rdnsCancel := context.WithTimeout(context.Background(), time.Duration(be.GlobalConfig.DNS.TimeoutSeconds)*time.Second)
			names, err := be.DNSResolver.LookupAddr(rdnsCtx, remoteAddr)
			rdnsCancel()

			// Distinguish "no PTR record exists" (NXDOMAIN / empty answer) from
			// transient lookup failures (timeout, SERVFAIL, network blip). Treating
			// transient errors as "no PTR" rejects legitimate senders whose PTR is
			// fine — `dig -x` from another resolver succeeds while Mizu's recursor
			// happens to fail or time out.
			//
			// Stats: every code path below falls through to the shared
			// RecordConnection call at the end of this rDNS block EXCEPT the
			// reject path, which returns early and records inline. The hasRDNS
			// argument reflects best-known state:
			//   - success → true
			//   - confirmed no PTR → false
			//   - transient DNS error → true (optimistic; don't penalize the IP
			//     for our recursor's problem, matching the fail-open policy)
			switch classifyRDNSResult(names, err) {
			case rdnsTransient:
				be.Logger.Warn("Reverse DNS lookup failed transiently - allowing connection",
					"server", be.ServerConfig.Name,
					"remote_addr", remoteAddr,
					"error", err)

			case rdnsMissing:
				hasRDNS = false

				// Reject if rDNS is required, unless the IP is whitelisted
				rdnsAllowReason := "not_required"
				if be.ServerConfig.DNSChecks.RequireRDNS {
					if !ipInNets(ip, be.ServerConfig.DNSChecks.RDNSWhitelistNets()) {
						if be.StatsManager != nil {
							// Reject returns early; record inline so this connection
							// still counts toward the IP's connection total.
							be.StatsManager.RecordConnection(ipStr, false)
							be.StatsManager.RecordDeniedConnection(ipStr)
						}
						if be.Metrics != nil {
							be.Metrics.SMTPMessagesRejected.WithLabelValues(be.ServerConfig.Name, be.ServerConfig.Type, "no_rdns").Inc()
						}

						be.Logger.Info("Rejecting connection - no reverse DNS",
							"server", be.ServerConfig.Name,
							"remote_addr", remoteAddr)
						return nil, &smtp.SMTPError{
							Code:         450,
							EnhancedCode: smtp.EnhancedCode{4, 7, 25},
							Message:      fmt.Sprintf("no reverse DNS record for IP address %s", ipStr),
						}
					}
					rdnsAllowReason = "ip_whitelisted"
				}
				be.Logger.Info("Connection allowed without reverse DNS",
					"server", be.ServerConfig.Name,
					"remote_addr", remoteAddr,
					"reason", rdnsAllowReason)

			case rdnsSuccess:
				ptrRecord = names[0]
				be.Logger.Info("Reverse DNS resolved",
					"server", be.ServerConfig.Name,
					"remote_addr", remoteAddr,
					"remote_host", ptrRecord)

			default:
				// Compile-time exhaustiveness isn't enforced; trip loudly if a new
				// rdnsResult variant gets added without a corresponding arm here.
				panic(fmt.Sprintf("unhandled rdnsResult: %d", classifyRDNSResult(names, err)))
			}
		}

		// Record connection in stats
		if be.StatsManager != nil {
			be.StatsManager.RecordConnection(ipStr, hasRDNS)

			// Check IP reputation if enabled for this server
			if be.ServerConfig.Reputation.Enabled {
				// Check whitelist first - skip reputation check if whitelisted
				isWhitelisted := false

				// Check IP whitelist
				if ipInNets(ip, be.ServerConfig.Reputation.WhitelistNets()) {
					be.Logger.Info("IP is whitelisted - skipping reputation check",
						"server", be.ServerConfig.Name,
						"remote_addr", remoteAddr)
					isWhitelisted = true
				}

				// Check hostname whitelist (PTR suffix match)
				if !isWhitelisted && ptrRecord != "" {
					for _, whitelistHost := range be.ServerConfig.Reputation.WhitelistHosts {
						if be.matchHostWhitelist(ptrRecord, whitelistHost) {
							be.Logger.Info("Hostname is whitelisted - skipping reputation check",
								"server", be.ServerConfig.Name,
								"remote_addr", remoteAddr,
								"remote_host", ptrRecord,
								"whitelist_host", whitelistHost)
							isWhitelisted = true
							break
						}
					}
				}

				// Only check reputation if not whitelisted
				if !isWhitelisted {
					if shouldDeny, reputation := be.StatsManager.CheckIPReputation(ipStr); shouldDeny {
						be.Logger.Info("Rejecting connection - poor IP reputation",
							"server", be.ServerConfig.Name,
							"remote_addr", remoteAddr,
							"remote_host", ptrRecord,
							"score", reputation)

						// Use configured rejection code and message
						rejectCode := be.ServerConfig.Reputation.RejectCode
						if rejectCode == 0 {
							rejectCode = 421 // Default temporary failure
						}
						rejectMessage := be.ServerConfig.Reputation.RejectMessage
						if rejectMessage == "" {
							rejectMessage = "poor reputation, please try again later"
						}

						return nil, &smtp.SMTPError{
							Code:         rejectCode,
							EnhancedCode: smtp.EnhancedCode{4, 7, 1},
							Message:      rejectMessage,
						}
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

	// The session context is cancelled on Logout; the session's time budget is
	// tracked separately by sessionDeadline, which — unlike a context deadline —
	// can be restarted as the session makes progress.
	ctx, cancel := context.WithCancel(context.Background())

	// Capture the raw connection once, here, where no go-smtp lock is held.
	// Session callbacks use it for deadlines instead of smtp.Conn.Conn().
	netConn := c.Conn()

	// Set initial idle timeout
	if err := netConn.SetDeadline(time.Now().Add(IdleTimeout)); err != nil {
		cancel()
		be.Logger.Error("Failed to set deadline", "error", err)
		return nil, ErrInternalServerError
	}

	// Generate unique trace ID for this session
	traceID := generateTraceID()

	session := &Session{
		conn:               c,
		netConn:            netConn,
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
		dnsCache:           be.DNSCache,
		connTracker:        be.ConnTracker,
		distTracker:        be.DistTracker,
		rateLimiter:        be.RateLimiter,
		metrics:            be.Metrics,
		ctx:                ctx,
		baseLogger:         be.Logger,
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
		spamChecker:        be.SpamChecker,        // Spam checker (nil if disabled)
	}
	session.sessionDeadline.Store(time.Now().Add(SessionDeadline).UnixNano())

	be.Logger.Info("Session created successfully",
		"server", be.ServerConfig.Name,
		"remote_addr", remoteAddr,
		"remote_host", ptrRecord,
		"trace_id", traceID,
		"initial_tls_state", tlsState != nil)

	sessionCreated = true
	return session, nil
}

// ipInNets reports whether ip falls within any of the given networks
func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// rdnsResult classifies the outcome of a reverse-DNS (PTR) lookup. The three
// states are mutually exclusive by construction — callers can switch
// exhaustively without worrying about overlap.
type rdnsResult int

const (
	rdnsSuccess   rdnsResult = iota // At least one PTR record returned.
	rdnsMissing                     // Authoritative "no PTR" (NXDOMAIN / empty answer).
	rdnsTransient                   // Lookup failed transiently (timeout, SERVFAIL, network); PTR may well exist.
)

// classifyRDNSResult inspects a (names, err) tuple from net.Resolver.LookupAddr
// and classifies it. Transient failures must be distinguished from "no PTR"
// so the caller can fail-open: a `dig -x` from a different recursor may
// succeed while ours just timed out.
func classifyRDNSResult(names []string, err error) rdnsResult {
	if err == nil {
		// Empty answer with no error is equivalent to "record does not exist".
		if len(names) == 0 {
			return rdnsMissing
		}
		return rdnsSuccess
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return rdnsMissing
	}
	return rdnsTransient
}

// matchHostWhitelist checks if a PTR hostname matches a whitelist entry (suffix match)
// Example: "wk9-4.hetrixtools.com." matches "hetrixtools.com"
func (be *Backend) matchHostWhitelist(ptrHost string, whitelistHost string) bool {
	// Normalize: remove trailing dots and convert to lowercase
	ptrHost = strings.TrimSuffix(strings.ToLower(ptrHost), ".")
	whitelistHost = strings.TrimSuffix(strings.ToLower(whitelistHost), ".")

	// Exact match
	if ptrHost == whitelistHost {
		return true
	}

	// Suffix match: "wk9-4.hetrixtools.com" ends with ".hetrixtools.com"
	return strings.HasSuffix(ptrHost, "."+whitelistHost)
}

// Session represents an active SMTP session for an incoming email.
// It tracks the SMTP conversation state and enforces protocol requirements.
type Session struct {
	conn           *smtp.Conn             // The underlying SMTP connection
	netConn        net.Conn               // Raw connection captured at session creation, for deadlines (see setCommandTimeout)
	helo           string                 // HELO/EHLO domain from the client
	ptr            string                 // Reverse DNS (PTR) record for client IP; "" when NewSession skipped the lookup. If you add a new consumer of this field, update ServerConfig.NeedsReverseDNS so the lookup still runs.
	from           string                 // Sender's email address (MAIL FROM)
	to             []string               // Recipient email addresses (RCPT TO)
	remoteAddr     string                 // Remote IP:port of the client
	mailData       bytes.Buffer           // Buffer to store the raw email body
	serverConfig   *config.ServerConfig   // Server-specific configuration (this server instance)
	globalConfig   *config.Config         // Global configuration (shared across servers)
	tlsState       *tls.ConnectionState   // TLS connection state (nil if not using TLS)
	statsManager   *stats.ServerRecorder  // IP and domain reputation tracking (per-server)
	circuitBreaker *poster.CircuitBreaker // Circuit breaker for HTTP destination
	httpClient     *net_http.Client       // HTTP client for posting emails to destination
	dnsResolver    *net.Resolver          // DNS resolver (custom or system default)
	dnsCache       *dns.CachingWrapper    // Caching wrapper around dnsResolver (preferred for TXT/MX lookups)
	connTracker    *ConnectionTracker     // Connection tracker for DoS protection
	distTracker    *DistributedTracker    // Distributed connection tracker (optional, for cluster-wide limits)
	rateLimiter    *RateLimiter           // Multi-dimensional rate limiter
	metrics        *metrics.Metrics       // Prometheus metrics for observability
	ctx            context.Context        // Session context, cancelled on Logout
	baseLogger     *slog.Logger           // Logger without session attrs, to rebuild Logger when the trace ID rotates
	Logger         *slog.Logger           // Structured logger for this session
	cancel         context.CancelFunc     // Cancel function to clean up resources

	// sessionDeadline caps time spent without completing a transaction, as
	// Unix nanoseconds (zero when unset, as in bare test sessions). Unlike a
	// context deadline it moves: extendSessionDeadline restarts it on progress
	// and ensureSessionBudget guarantees room for work about to start. Held
	// atomically because BDAT runs Session.Data on its own goroutine while the
	// connection goroutine keeps handling commands.
	sessionDeadline atomic.Int64
	sessionsWg      *sync.WaitGroup // WaitGroup to track active sessions for graceful shutdown
	sessionCount    *atomic.Int64   // Pointer to active session counter for observability
	logoutOnce      sync.Once       // Ensures Logout cleanup runs exactly once

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

	// Spam checking
	spamChecker SpamChecker      // Spam checker for external spam scanning (nil if disabled)
	spamResult  *SpamCheckResult // Result from spam check (nil if not checked)
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

// junkAction returns the effective junk apply_action for this server,
// defaulting to "header" when unset.
func (s *Session) junkAction() string {
	if s.serverConfig.Junk.ApplyAction != "" {
		return s.serverConfig.Junk.ApplyAction
	}
	return "header"
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

	// Validate HELO hostname for security (skip in local development mode
	// or when HELO validation is explicitly disabled via helo_validation = false)
	if !s.globalConfig.Local && s.heloValidationEnabled() {
		if err := s.validateHeloHostname(hostname); err != nil {
			return err
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

// heloValidationEnabled reports whether HELO/EHLO hostname validation is
// enabled for this server. An explicit helo_validation setting always wins.
// When unset (nil — config.ApplyDefaults normally materializes it), the
// default is type-aware: enabled on relay (MX) servers where it screens spam
// bots, disabled on submission servers — authenticated desktop clients
// (notably Windows Outlook) send their bare machine name as the EHLO
// argument, and rejecting it locks every such client out (the August 2026
// Outlook incident).
func (s *Session) heloValidationEnabled() bool {
	if s.serverConfig.HELOValidation != nil {
		return *s.serverConfig.HELOValidation
	}
	return !s.serverConfig.IsSubmission()
}

// validateHeloHostname checks a HELO/EHLO hostname for security issues.
// This is called both from the explicit Helo() handler and from the Mail()
// fallback path when go-smtp handles EHLO internally.
func (s *Session) validateHeloHostname(hostname string) error {
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

	// Check for invalid characters (including null bytes)
	if strings.ContainsAny(hostname, " \t\r\n\x00") {
		s.Logger.Warn("Rejecting HELO/EHLO - invalid characters")
		return &smtp.SMTPError{
			Code:    550,
			Message: "invalid characters in HELO hostname",
		}
	}

	// Optional: Verify HELO hostname has valid DNS records
	if s.serverConfig.DNSChecks.RequireResolvableHELO {
		timeoutSecs := s.globalConfig.DNS.TimeoutSeconds
		if timeoutSecs == 0 {
			timeoutSecs = 5 // Default DNS timeout
		}
		resolves, reason, err := blacklist.CheckHELOResolves(hostname, time.Duration(timeoutSecs)*time.Second)
		if err != nil || !resolves {
			s.Logger.Warn("Rejecting HELO/EHLO - hostname check failed", "hostname", hostname, "reason", reason)
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 7, 27},
				Message:      fmt.Sprintf("HELO hostname check failed: %s", reason),
			}
		}
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

// setCommandTimeout sets the deadline for the current command.
//
// The deadline is set on s.netConn, captured once at session creation, rather
// than through smtp.Conn.Conn(). That accessor takes go-smtp's per-connection
// lock, and go-smtp calls Session.Reset (which calls this) from Conn.reset;
// re-entering the lock from a session callback deadlocks the connection
// goroutine for good. go-smtp no longer holds the lock across Reset, but not
// depending on that keeps every session callback safe to call any accessor.
// The captured value stays current because go-smtp builds a fresh session
// after STARTTLS swaps the underlying connection.
func (s *Session) setCommandTimeout(timeout time.Duration) error {
	// Skip timeout if no connection (e.g., in tests)
	if s.netConn == nil {
		return nil
	}

	// Check if session deadline has been exceeded
	if deadline := s.sessionDeadlineTime(); !deadline.IsZero() && time.Now().After(deadline) {
		s.Logger.Warn("Session deadline exceeded")
		return ErrSessionTimeout
	}

	// Set the command timeout
	if err := s.netConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		s.Logger.Error("Failed to set deadline", "error", err)
		return ErrInternalServerError
	}
	return nil
}

// sessionDeadlineTime returns the current session deadline, or the zero time
// when the session has no budget (bare test sessions).
func (s *Session) sessionDeadlineTime() time.Time {
	nanos := s.sessionDeadline.Load()
	if nanos == 0 {
		return time.Time{}
	}
	return time.Unix(0, nanos)
}

// extendSessionDeadline restarts the session's progress budget. Called when a
// transaction completes, so a sender delivering a queue of messages over one
// connection is judged on progress rather than on total connection age.
func (s *Session) extendSessionDeadline() {
	if s.sessionDeadline.Load() == 0 {
		return
	}
	s.sessionDeadline.Store(time.Now().Add(SessionDeadline).UnixNano())
}

// ensureSessionBudget guarantees at least d remains before the session
// deadline. Without it, a transaction starting near the end of the budget would
// be handed a truncated deadline — and a message rejected with 451 after the
// backend had already accepted it is a duplicate on the next delivery attempt,
// not a clean failure.
func (s *Session) ensureSessionBudget(d time.Duration) {
	for {
		current := s.sessionDeadline.Load()
		if current == 0 {
			return
		}
		minimum := time.Now().Add(d).UnixNano()
		if current >= minimum {
			return
		}
		if s.sessionDeadline.CompareAndSwap(current, minimum) {
			return
		}
	}
}

// commandContext derives the context for a command's outbound work from the
// per-command context go-smtp supplies, bounded by the session deadline.
// go-smtp cancels its context when the transaction ends or the server shuts
// down; the session deadline stops work that outlives the session's budget.
// Callers must call the returned cancel.
func (s *Session) commandContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if deadline := s.sessionDeadlineTime(); !deadline.IsZero() {
		return context.WithDeadline(ctx, deadline)
	}
	return context.WithCancel(ctx)
}

// Mail is called for the MAIL FROM command.
// This sets the envelope sender for the SMTP transaction.
func (s *Session) Mail(ctx context.Context, from string, opts *smtp.MailOptions) error {
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
			// EHLO was handled by go-smtp internally — run the same
			// validation that the explicit Helo() path uses.
			if !s.globalConfig.Local && s.heloValidationEnabled() {
				if err := s.validateHeloHostname(heloHostname); err != nil {
					return err
				}
			}
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
		cmdCtx, cancel := s.commandContext(ctx)
		result, err := s.senderValidator.ValidateWithContext(cmdCtx, s.remoteAddr, s.ptr, s.helo, from, s.authenticatedUser)
		cancel()
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
				"backend_message", result.Message)

			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 7, 1},
				Message:      "sender address rejected",
			}
		}

		s.Logger.Info("Sender validation passed", "from", from, "authenticated_user", s.authenticatedUser)
	}

	// Extract domain from sender
	senderDomain := stats.ExtractDomainFromEmail(from)
	s.senderDomain = senderDomain

	// Record MAIL FROM in stats (for observability only).
	// NOTE: We do NOT check domain reputation here for rejection because the
	// MAIL FROM domain is unverified at this point — any sender can forge it.
	// Rejecting based on a forged domain's reputation would punish innocent
	// domains that spammers impersonate. IP reputation (checked at connection
	// time) is the correct signal since TCP source IPs cannot be forged.
	// Record MAIL FROM for per-server message counting.
	// Domain is not passed because it is unverified (trivially forged).
	if s.statsManager != nil {
		s.statsManager.RecordMailFrom(s.senderDomain)
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

					converted := validation.ConvertSPFResult(*res)
					spfMu.Lock()
					s.spfResult = &validation.SPFResult{
						Domain: s.senderDomain,
						Result: authres.SPFResult{
							Value: converted,
						},
					}
					spfMu.Unlock()

					// Record hard SPF failure against the sender's IP for reputation.
					// Only IP is penalized (not domain) because the MAIL FROM domain
					// is unverified and trivially forged by spammers.
					if converted == authres.ResultFail && s.statsManager != nil {
						s.statsManager.RecordSPFFailure(s.remoteAddr)
					}
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
func (s *Session) Rcpt(ctx context.Context, to string, opts *smtp.RcptOptions) error {
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

	s.commandState = stateRcpt

	// Check rate limits now that we have TO information
	// This allows TO, TO_DOMAIN, FROM+TO, AUTHENTICATED_USER, and other recipient-based combination checks
	if s.rateLimiter != nil {
		// Include the candidate recipient for rate limit evaluation.
		// Use slices.Concat to avoid mutating s.to's underlying array.
		sessionCtx := SessionContext{
			RemoteAddr:        s.remoteAddr,
			From:              s.from,
			To:                slices.Concat(s.to, []string{to}),
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
		cmdCtx, cancel := s.commandContext(ctx)
		result, err := s.recipientValidator.ValidateWithContext(cmdCtx, s.remoteAddr, s.ptr, s.helo, s.from, to)
		cancel()
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
			if result.Temporary {
				s.Logger.Info("Recipient temporarily rejected by validation",
					"to", to,
					"backend_message", result.Message)
				return &smtp.SMTPError{
					Code:         450,
					EnhancedCode: smtp.EnhancedCode{4, 2, 1},
					Message:      "temporary failure, please try again later",
				}
			}

			s.Logger.Info("Recipient rejected by validation",
				"to", to,
				"backend_message", result.Message)
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 1, 1},
				Message:      "mailbox unavailable",
			}
		}

		s.Logger.Info("Recipient validation passed", "to", to)

		// Clear any stale delivery cache entry for this recipient.
		// The delivery recipient cache (distTracker) caches 404/403 responses from
		// the delivery endpoint. If the recipient validation endpoint just confirmed
		// the recipient exists, any cached 404/403 is stale and must be removed to
		// prevent deliverSynchronous() from rejecting the message based on outdated data.
		if s.distTracker != nil {
			s.distTracker.ClearRecipientCache(to)
		}
	}

	// Add recipient only after all checks pass
	s.to = append(s.to, to)

	// Reset to idle timeout to wait for the next command
	if err := s.setCommandTimeout(IdleTimeout); err != nil {
		return err
	}

	return nil
}

// Data is called when the email body is received.
// This is where we process the message headers and body, perform validation, and forward the email.
func (s *Session) Data(ctx context.Context, r io.Reader) (err error) {
	// Guarantee the full data budget before anything derives a context from the
	// session deadline: reading the body and delivering it synchronously must
	// not be cut short by however much of the session budget happens to remain.
	s.ensureSessionBudget(DataPhaseBudget)

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

	cmdCtx, cancel := s.commandContext(ctx)
	defer cancel()

	// 3. Perform pre-delivery validation (headers, DMARC, etc.).
	// This may mark the message as junk or return a hard rejection error.
	if err := s.performPreDeliveryChecks(cmdCtx, rawEmail); err != nil {
		return err
	}

	// 4. Attempt to deliver the message to the final destination.
	if err := s.deliverMessage(cmdCtx, rawEmail); err != nil {
		return err
	}

	// 5. Finalize the session by recording stats for the successful delivery.
	s.finalizeSuccessfulDelivery()

	return nil
}

// readMessageData handles the initial checks and reads the email content from the client.
func (s *Session) readMessageData(r io.Reader) (string, error) {
	// Arm the first block's deadline (and check the session budget); the
	// rolling reader below re-arms it as the body arrives.
	if err := s.setCommandTimeout(DataBlockTimeout); err != nil {
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

	// Read the entire email into a buffer, enforcing the configured size limit.
	// We read one byte past the limit so that an oversize message is detected
	// and rejected with 552 rather than being silently truncated and accepted
	// with 250 OK (which would violate the zero-message-loss guarantee). The
	// underlying go-smtp reader also enforces MaxMessageBytes and returns its
	// own 552; either path yields a rejection. go-smtp discards any remaining
	// DATA after this returns.
	maxSize := int64(s.serverConfig.MaxMessageSize)
	// Bound how long the client may stall mid-message rather than how long the
	// whole body may take: every chunk that arrives pushes the deadline out by
	// DataBlockTimeout, so a slow uplink can keep sending while a client that
	// goes silent is still dropped. The session deadline, guaranteed a full
	// DataPhaseBudget by Data, is the ceiling the extensions cannot push past.
	reader := newRollingDeadlineReader(r, s.netConn, DataBlockTimeout, s.sessionDeadlineTime())
	// A non-positive limit means unlimited; only wrap with a bounded reader when
	// a real limit is configured (otherwise LimitReader(r, 1) would truncate).
	if maxSize > 0 {
		reader = io.LimitReader(reader, maxSize+1)
	}
	n, err := io.Copy(&s.mailData, reader)
	if err != nil {
		// A 552 (message exceeds MaxMessageBytes) from the underlying reader is
		// returned as-is so the client receives the correct SMTP status.
		s.Logger.Error("Failed to read message data", "error", err)
		return "", err
	}
	if maxSize > 0 && n > maxSize {
		s.Logger.Warn("Rejecting message - exceeds maximum size",
			"from", s.from, "max_size_bytes", maxSize)
		return "", &smtp.SMTPError{
			Code:         552,
			EnhancedCode: smtp.EnhancedCode{5, 3, 4},
			Message:      "message exceeds maximum allowed size",
		}
	}

	// Canonicalize line endings to CRLF once, up front. Header-processing
	// functions split on "\r\n" while validateHeaders uses net/mail (which
	// tolerates bare "\n"); that parsing differential would otherwise let a
	// message using lone-LF line endings smuggle a forged header (e.g.
	// X-Envelope-To) past stripHeader and bypass mail-loop counting. A
	// compliant client already sends CRLF, so this is a no-op for them.
	rawEmail := normalizeToCRLF(s.mailData.String())

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
func (s *Session) performPreDeliveryChecks(ctx context.Context, rawEmail string) error {
	// Mail loop detection (check before other validations to prevent wasting resources)
	loopDetectionEnabled := s.serverConfig.Validation.LoopDetection != nil && *s.serverConfig.Validation.LoopDetection
	if loopDetectionEnabled {
		maxHops := s.serverConfig.Validation.MaxHops
		if maxHops <= 0 {
			maxHops = 30 // Default
		}

		loopResult := detectMailLoop(rawEmail, s.serverConfig.Hostname, maxHops)
		if loopResult.IsLoop {
			if loopResult.LoopHostname != "" {
				s.Logger.Warn("Mail loop detected - hostname appears multiple times in Received headers",
					"hostname", loopResult.LoopHostname,
					"hostname_count", loopResult.HostnameCount,
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
		// Prefer the cache wrapper so DKIM key + DMARC TXT lookups are cached.
		// Fall back to the raw resolver if no cache is wired.
		var txtResolver validation.TXTResolver
		if s.dnsCache != nil {
			txtResolver = s.dnsCache
		} else if s.dnsResolver != nil {
			txtResolver = s.dnsResolver
		}
		lookupTimeout := time.Duration(s.globalConfig.DNS.TimeoutSeconds) * time.Second
		dmarcResult, err = validation.CheckDMARC(ctx, rawEmail, s.spfResult, quarantineAction, txtResolver, lookupTimeout, s.Logger)
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

	// External spam checking (rspamd)
	if s.spamChecker != nil {
		result, err := s.spamChecker.Check(ctx, s.traceID, rawEmail, s.remoteAddr, s.from, s.to, s.helo, s.authenticatedUser)
		if err != nil {
			s.Logger.Warn("Spam check failed", "error", err)
			if s.metrics != nil {
				s.metrics.SMTPMessagesRejected.WithLabelValues(s.serverName(), s.serverType(), "spam_check_error").Inc()
			}
			// Don't reject on spam check errors - fail open for availability
		} else {
			s.spamResult = &result

			s.Logger.Info("Spam check completed",
				"is_spam", result.IsSpam,
				"action", result.Action,
				"score", result.Score)

			// Check if we should defer based on rspamd action ("soft reject").
			// This is a temporary failure: the sending MTA retries later.
			if result.ShouldDefer {
				s.Logger.Warn("Deferring message - spam check action", "action", result.Action, "score", result.Score)
				if s.metrics != nil {
					s.metrics.SMTPMessagesRejected.WithLabelValues(s.serverName(), s.serverType(), "spam_soft_reject").Inc()
				}
				// Prefer rspamd's own reply text (e.g. "Reached account
				// incoming limits ... Try again later.") when it set one,
				// falling back to a generic notice.
				message := result.SMTPMessage
				if message == "" {
					message = "message deferred, please try again later"
				}
				return &smtp.SMTPError{
					Code:         451,
					EnhancedCode: smtp.EnhancedCode{4, 7, 1},
					Message:      message,
				}
			}

			// Check if we should reject based on rspamd action
			if result.ShouldReject {
				s.Logger.Warn("Rejecting message - spam check action", "action", result.Action, "score", result.Score)
				if s.metrics != nil {
					s.metrics.SMTPMessagesRejected.WithLabelValues(s.serverName(), s.serverType(), "spam_reject").Inc()
				}
				// Prefer rspamd's own reply text (e.g. "Reached account
				// outgoing limits for account #123") when it set one, falling
				// back to a generic notice.
				message := result.SMTPMessage
				if message == "" {
					message = "message rejected - spam detected"
				}
				return &smtp.SMTPError{
					Code:         550,
					EnhancedCode: smtp.EnhancedCode{5, 7, 1},
					Message:      message,
				}
			}

			// Mark as junk if spam detected (even if not rejecting)
			if result.IsSpam {
				s.isJunk = true
				s.junkReasons = append(s.junkReasons, fmt.Sprintf("spam check (score: %.2f)", result.Score))
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
func (s *Session) deliverMessage(ctx context.Context, rawEmail string) error {
	// Step 1: Inject Received and X-Mizu-* headers
	// This must happen BEFORE ARC signing so the signature covers these headers
	tlsVersionStr := "none"
	if s.tlsState != nil {
		tlsVersionStr = tlsVersionString(s.tlsState.Version)
	}

	// Collect spam check headers
	var spamHeaders map[string][]string
	if s.spamResult != nil && len(s.spamResult.AddHeaders) > 0 {
		spamHeaders = s.spamResult.AddHeaders
	}

	mizuHeaderToggles := s.serverConfig.HeaderToggles()
	stripClientIdentity := s.serverConfig.StripsClientIdentity()

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
		mizuHeaderToggles,
		stripClientIdentity,
		spamHeaders,
	)

	s.Logger.Info("Injected Received and X-Mizu-* headers",
		"trace_id_header", mizuHeaderToggles.TraceID,
		"auth_results_header", mizuHeaderToggles.AuthResults,
		"junk_header", mizuHeaderToggles.Junk,
		"strip_client_identity", stripClientIdentity)

	// Apply junk modifications if message is marked as junk
	if s.isJunk {
		action := s.junkAction()

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
	return s.deliverSynchronous(ctx, emailWithHeaders)
}

// deliverSynchronous handles synchronous delivery
func (s *Session) deliverSynchronous(ctx context.Context, signedEmail string) error {
	// Per-recipient POST to Mailqueuer. Each request is atomic: one recipient,
	// one queue message, one S3 object. On first failure, stop and return the
	// error — the sending MTA will retry all recipients.
	for _, recipient := range s.to {
		if err := s.deliverToRecipient(ctx, signedEmail, recipient); err != nil {
			return err
		}
	}

	s.Logger.Info("Successfully delivered message to destination", "recipients", len(s.to))
	return nil
}

func (s *Session) deliverToRecipient(ctx context.Context, signedEmail string, recipient string) error {
	// Check recipient cache first (if distributed tracking is enabled)
	if s.distTracker != nil {
		if found, isBlocked, reason := s.distTracker.IsRecipientCached(recipient); found {
			s.Logger.Info(fmt.Sprintf("Recipient %s found in cache: %s", recipient, reason))
			if isBlocked {
				return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Recipient blocked by destination"}
			}
			return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "Recipient not found"}
		}
	}

	// Add the X-Envelope-To header for this specific recipient. Delivery is
	// per-recipient, so each delivered copy carries exactly the envelope
	// recipient it was sent for.
	emailForRecipient := addEnvelopeToHeader(signedEmail, recipient)

	delivery := poster.Delivery{
		RawEmail:          emailForRecipient,
		URL:               s.serverConfig.Delivery.URL,
		AuthToken:         s.serverConfig.Delivery.AuthToken,
		MaxRetryAttempts:  s.serverConfig.Delivery.MaxRetryAttempts,
		MailFrom:          s.from,
		MailTo:            recipient,
		TraceID:           s.traceID,
		AuthenticatedUser: s.authenticatedUser,
		Origin:            s.serverConfig.Type,
		ClientIP:          s.remoteAddr,
		IsJunk:            s.isJunk,
	}
	if s.isJunk {
		delivery.JunkAction = s.junkAction()
	}
	if s.spamResult != nil {
		delivery.Spam = &poster.SpamVerdict{Score: s.spamResult.Score, Action: s.spamResult.Action}
	}

	err := poster.PostEmailToDestinationWithContext(ctx, delivery, s.circuitBreaker, s.httpClient, s.Logger, s.metrics)

	if err != nil {
		s.Logger.Error(fmt.Sprintf("Failed to deliver message for recipient %s: %v", recipient, err))

		var httpErr *poster.HTTPStatusError
		if errors.As(err, &httpErr) {
			if httpErr.IsPayloadTooLarge() {
				return &smtp.SMTPError{
					Code:         552,
					EnhancedCode: smtp.EnhancedCode{5, 3, 4},
					Message:      "Message size not accepted",
				}
			}

			if httpErr.IsRecipientNotFound() && s.distTracker != nil && s.distTracker.recipientCacheTTL > 0 {
				s.distTracker.CacheRecipientNotFound(recipient)
				return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "Recipient not found"}
			}

			if httpErr.IsRecipientBlocked() && s.distTracker != nil && s.distTracker.recipientCacheTTL > 0 {
				s.distTracker.CacheRecipientBlocked(recipient)
				return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Recipient blocked by destination"}
			}
		}

		// Any other delivery failure is treated as temporary so the sender's MTA
		// retries rather than bouncing the message (zero message loss). Deliberate
		// backend rejections (404/403/413) are handled above and remain permanent.
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 0}, Message: "Temporary failure, please try again later"}
	}

	return nil
}

// finalizeSuccessfulDelivery records statistics for a successfully delivered message.
func (s *Session) finalizeSuccessfulDelivery() {
	if s.statsManager != nil {
		if s.isJunk {
			s.statsManager.RecordJunkMessage(s.remoteAddr)
			// Track recipient domains for observability (junk delivery)
			s.statsManager.RecordDeliveryRecipients(s.to, false)
		} else {
			// Award reputation per successful recipient, not per message.
			// This ensures mailing lists and bulk senders get proportional
			// positive reputation (e.g., 100 recipients = +100, not +1).
			s.statsManager.RecordHamDelivery(s.remoteAddr, len(s.to))
			// Track recipient domains for observability (ham delivery)
			s.statsManager.RecordDeliveryRecipients(s.to, true)
		}
	}
	// A completed transaction is the progress the session budget measures:
	// restart it so a sender working through a queue on this connection is not
	// disconnected mid-stream, which would force redelivery of every message it
	// had not yet been told we accepted.
	s.extendSessionDeadline()

	s.Logger.Info("Email delivered successfully",
		"from", s.from,
		"to", s.to,
		"recipient_count", len(s.to))
}

// recordDMARCFailure is a helper to record DMARC failure stats.
func (s *Session) recordDMARCFailure() {
	if s.statsManager != nil {
		s.statsManager.RecordDMARCFailure(s.remoteAddr)
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
	// A later message on the same connection is a different email — rotate the
	// trace ID so one trace ID always means one message. This also keeps
	// mailqueuer's (trace_id, recipient) ingest dedup from ever suppressing a
	// second, distinct message to the same recipient on this connection.
	previousTraceID := s.traceID
	s.traceID = generateTraceID()
	if s.baseLogger != nil { // bare test sessions have no baseLogger
		s.Logger = s.baseLogger.With("trace_id", s.traceID, "remote_addr", s.remoteAddr, "remote_host", s.ptr)
	}
	// Reset also fires on RSET and repeated EHLO, so connection/auth-time log
	// lines carry an earlier trace ID than the message eventually delivered on
	// this session. This line chains the IDs so a grep for either finds the
	// rotation and can follow the session history.
	s.Logger.Info("Trace ID rotated", "previous_trace_id", previousTraceID)
	s.from = ""
	s.to = make([]string, 0)
	s.mailData.Reset()
	s.commandState = stateHelo // After reset, we're back to post-HELO state
	s.isJunk = false
	s.junkReasons = nil
	s.senderDomain = ""
	s.spfResult = nil
	// Clear all per-message authentication/scan results so a later message on
	// the same connection can never inherit an earlier message's verdict or
	// headers (e.g. a stale spam result when a subsequent check fails open).
	s.dmarcResult = nil
	s.arcResult = nil
	s.spamResult = nil

	// Reset idle timeout after successful message
	if err := s.setCommandTimeout(IdleTimeout); err != nil {
		s.Logger.Error("Failed to reset idle timeout", "error", err)
	}
}

// Logout is called when the session ends.
// It is idempotent: calling it more than once is safe and only the first call
// performs cleanup. This is important because NewSession may call prev.Logout()
// when a client re-issues EHLO, and go-smtp may also call Logout when the
// connection closes. Without idempotency the second call would double-release
// the connection tracker slot (leaking negative counts) and call
// sessionsWg.Done() twice (causing a panic).
func (s *Session) Logout() error {
	s.logoutOnce.Do(func() {
		// Ensure connection is always released even if something panics.
		// All cleanup logic lives in this defer so a panic anywhere in
		// Logout cannot leak counters.
		defer func() {
			if r := recover(); r != nil {
				s.Logger.Error("Panic in Logout - recovering", "panic", r)
			}

			// Release connection slot for DoS protection.
			// Prefer distributed tracker for cluster-wide coordination.
			if s.distTracker != nil {
				s.distTracker.Release(s.remoteAddr)
			} else if s.connTracker != nil {
				s.connTracker.Release(s.remoteAddr)
			}

			// Signal that this session has completed (for graceful shutdown).
			if s.sessionsWg != nil {
				// Decrement active session counter for observability.
				if s.sessionCount != nil {
					count := s.sessionCount.Add(-1)
					s.Logger.Debug("Session count decremented",
						"active_sessions", count)

					// Update Prometheus gauge.
					if s.metrics != nil {
						s.metrics.SMTPConnectionsActive.WithLabelValues(s.serverConfig.Name, s.serverConfig.Type).Set(float64(count))
					}
				}

				s.sessionsWg.Done()
			}
		}()

		s.Logger.Debug("Session logout")
		if s.cancel != nil {
			s.cancel()
		}
	})
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

package stats

import (
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"migadu/mizu/pkg/concurrency"
	"migadu/mizu/pkg/health"

	"log/slog"
)

const (
	// stalePeerTimeout is the duration after which a peer is considered stale if its stats file is missing.
	stalePeerTimeout = 24 * time.Hour
)

// eventType defines the type of statistical event
type eventType int

const (
	eventConnection eventType = iota
	eventDeniedConnection
	eventMailFrom
	eventInvalidRecipient
	eventSpoofingAttempt
	eventDMARCFailure
	eventDNSBLHit
	eventJunkMessage
	eventHamDelivery
	eventSPFFailure
)

// Manager handles IP and domain reputation tracking
type Manager struct {
	enabled           bool
	retentionDuration time.Duration
	logger            *slog.Logger

	// Sync configuration
	syncEnabled  bool
	syncInterval time.Duration
	syncServers  []string
	hostname     string

	// LRU eviction limits
	maxIPEntries        int
	maxSrvDomainEntries int // Max sender/recipient domains tracked per server

	// Maps for tracking IPs
	ips map[string]*IPEntry

	// Mutex for map access
	ipMu sync.RWMutex

	// Track sync times per server
	lastSync        map[string]time.Time // Tracks LastModified time of successfully synced objects
	lastSyncAttempt map[string]time.Time // Tracks the time of the last sync attempt for a peer
	lastSyncMu      sync.RWMutex

	// Context for cleanup goroutine
	ctx    context.Context
	cancel context.CancelFunc

	// Channel for processing events concurrently
	eventChan chan event

	// Metrics for monitoring event processing
	eventsProcessed uint64 // Total events successfully processed
	eventsDropped   uint64 // Total events dropped due to full channel
	metricsMu       sync.RWMutex

	// S3 export change detection to avoid writing unchanged data
	lastExportHash string

	// Per-config-server message counters (e.g., "mx-primary", "mx-submission")
	srvCounters   map[string]*srvCounters
	srvCountersMu sync.RWMutex

	// Per-server summaries collected during sync
	peerSummaries   map[string]*ServerSummary
	peerSummariesMu sync.RWMutex

	// Connection trackers for active connection count
	connTrackers   []ConnectionTracker
	connTrackersMu sync.RWMutex
}

// srvDomainCounters tracks per-domain message counts within a single server
type srvDomainCounters struct {
	messages int64
	accepted int64
	rejected int64
	junk     int64
}

// srvCounters tracks message counters for a single config server name
// Note: total is computed from (accepted + rejected + junk) to handle multi-recipient messages
type srvCounters struct {
	accepted    uint64
	rejected    uint64
	junk        uint64
	domains     map[string]*srvDomainCounters // Sender (FROM) domains
	rcptDomains map[string]*srvDomainCounters // Recipient (TO) domains
}

// ConnectionTracker interface for getting active connection stats
type ConnectionTracker interface {
	GetTotalCount() int    // Returns total active connections (lock-free optimization)
	GetServerName() string // Returns the config server name (e.g., "mx-primary")
}

// event represents a statistical event to be processed
type event struct {
	Type       eventType
	IP         string
	Domain     string
	ServerName string // Config server name (e.g., "mx-primary", "mx-submission")
	Count      int    // Multiplier for weighted events (e.g., recipient count for ham delivery)
}

// ServerRecorder wraps a Manager with a server name for per-config-server tracking.
// It has the same method signatures as Manager for Record* and Check* methods,
// allowing it to be used as a drop-in replacement in the SMTP Backend/Session.
type ServerRecorder struct {
	manager        *Manager
	serverName     string
	minIPScore     float64 // Minimum IP reputation threshold (default: -0.2)
	minDomainScore float64 // Minimum domain reputation threshold (default: -0.2)
}

// NewServerRecorder creates a recorder that tags all events with the given server name.
// It eagerly registers the server name so it appears in stats even with zero traffic.
// minIPScore and minDomainScore default to ReputationDenyThreshold (-0.2) if set to 0.
func NewServerRecorder(manager *Manager, serverName string, minIPScore, minDomainScore float64) *ServerRecorder {
	// Apply defaults if thresholds are not set
	if minIPScore == 0 {
		minIPScore = ReputationDenyThreshold
	}
	if minDomainScore == 0 {
		minDomainScore = ReputationDenyThreshold
	}

	if manager != nil {
		manager.srvCountersMu.Lock()
		manager.getOrCreateSrvCounters(serverName)
		manager.srvCountersMu.Unlock()
	}
	return &ServerRecorder{
		manager:        manager,
		serverName:     serverName,
		minIPScore:     minIPScore,
		minDomainScore: minDomainScore,
	}
}

// Manager returns the underlying stats manager (for registration, health checks, etc.)
func (r *ServerRecorder) Manager() *Manager {
	return r.manager
}

func (r *ServerRecorder) RecordConnection(ip string, hasRDNS bool) {
	if r.manager == nil || !r.manager.enabled {
		return
	}
	rdnsStatus := "yes"
	if !hasRDNS {
		rdnsStatus = "no"
	}
	r.manager.sendEvent(event{Type: eventConnection, IP: ip, Domain: rdnsStatus, ServerName: r.serverName})
}

// RecordDeniedConnection marks an IP as denied (e.g., no rDNS on a server that requires it).
// Only call this when the server policy actually denies the connection.
func (r *ServerRecorder) RecordDeniedConnection(ip string) {
	if r.manager == nil || !r.manager.enabled {
		return
	}
	r.manager.sendEvent(event{Type: eventDeniedConnection, IP: ip, ServerName: r.serverName})
}

func (r *ServerRecorder) RecordMailFrom(domain string) {
	if r.manager == nil || !r.manager.enabled {
		return
	}
	r.manager.sendEvent(event{Type: eventMailFrom, Domain: domain, ServerName: r.serverName})
}

func (r *ServerRecorder) RecordInvalidRecipient(ip string) {
	if r.manager == nil || !r.manager.enabled {
		return
	}
	r.manager.sendEvent(event{Type: eventInvalidRecipient, IP: ip, ServerName: r.serverName})
}

func (r *ServerRecorder) RecordSpoofingAttempt(ip string) {
	if r.manager == nil || !r.manager.enabled {
		return
	}
	r.manager.sendEvent(event{Type: eventSpoofingAttempt, IP: ip, ServerName: r.serverName})
}

func (r *ServerRecorder) RecordDMARCFailure(ip string) {
	if r.manager == nil || !r.manager.enabled {
		return
	}
	r.manager.sendEvent(event{Type: eventDMARCFailure, IP: ip, ServerName: r.serverName})
}

// RecordSPFFailure records a hard SPF fail against the sender's IP.
// Only applied to IP reputation (not domain) because the MAIL FROM domain
// is unverified and trivially forged — penalizing the domain would harm
// innocent domains that spammers impersonate.
func (r *ServerRecorder) RecordSPFFailure(ip string) {
	if r.manager == nil || !r.manager.enabled {
		return
	}
	r.manager.sendEvent(event{Type: eventSPFFailure, IP: ip, ServerName: r.serverName})
}

func (r *ServerRecorder) RecordDNSBLHit(ip string, weight int64) {
	if r.manager == nil || !r.manager.enabled {
		return
	}
	// Store weight in Domain field as string (bit of a hack but avoids changing event struct)
	r.manager.sendEvent(event{Type: eventDNSBLHit, IP: ip, Domain: fmt.Sprintf("%d", weight), ServerName: r.serverName})
}

func (r *ServerRecorder) RecordJunkMessage(ip string) {
	if r.manager == nil || !r.manager.enabled {
		return
	}
	r.manager.sendEvent(event{Type: eventJunkMessage, IP: ip, ServerName: r.serverName})
}

func (r *ServerRecorder) RecordHamDelivery(ip string, recipientCount int) {
	if r.manager == nil || !r.manager.enabled {
		return
	}
	if recipientCount <= 0 {
		recipientCount = 1
	}
	r.manager.sendEvent(event{Type: eventHamDelivery, IP: ip, ServerName: r.serverName, Count: recipientCount})
}

// RecordDeliveryRecipients tracks recipient (TO) domains for observability.
// This is called after successful delivery to record which recipient domains
// were involved. For incoming servers these are our hosted domains; for
// submission servers these are external destination domains.
// accepted=true for ham deliveries, accepted=false for junk deliveries.
func (r *ServerRecorder) RecordDeliveryRecipients(recipients []string, accepted bool) {
	if r.manager == nil || !r.manager.enabled {
		return
	}
	// Extract unique recipient domains
	rcptDomains := make(map[string]int) // domain → count
	for _, rcpt := range recipients {
		domain := ExtractDomainFromEmail(rcpt)
		if domain != "" {
			rcptDomains[domain]++
		}
	}
	// Update per-server recipient domain counters directly (observability only)
	r.manager.srvCountersMu.Lock()
	sc := r.manager.getOrCreateSrvCounters(r.serverName)
	for domain, count := range rcptDomains {
		rd := sc.getOrCreateRcptDomain(domain, r.manager.maxSrvDomainEntries)
		rd.messages += int64(count)
		if accepted {
			rd.accepted += int64(count)
		} else {
			rd.junk += int64(count)
		}
	}
	r.manager.srvCountersMu.Unlock()
}

func (r *ServerRecorder) CheckIPReputation(ip string) (shouldDeny bool, reputation float64) {
	if r.manager == nil {
		return false, 0
	}
	// Get reputation from manager, but apply server-specific threshold
	_, reputation = r.manager.CheckIPReputation(ip)
	shouldDeny = reputation < r.minIPScore
	return shouldDeny, reputation
}

// NewManager creates a new stats manager
func NewManager(enabled bool, retentionDuration time.Duration, hostname string, syncEnabled bool, syncInterval time.Duration, syncServers []string, maxIPEntries, maxSrvDomainEntries, bufferSize int, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// Default buffer size if not specified
	if bufferSize <= 0 {
		bufferSize = 100000
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Manager{
		enabled:             enabled,
		retentionDuration:   retentionDuration,
		hostname:            hostname,
		syncEnabled:         syncEnabled,
		syncInterval:        syncInterval,
		syncServers:         syncServers,
		maxIPEntries:        maxIPEntries,
		maxSrvDomainEntries: maxSrvDomainEntries,
		logger:              logger,
		ips:                 make(map[string]*IPEntry),
		lastSync:            make(map[string]time.Time),
		lastSyncAttempt:     make(map[string]time.Time),
		ctx:                 ctx,
		cancel:              cancel,
		eventChan:           make(chan event, bufferSize),
		connTrackers:        make([]ConnectionTracker, 0),
		srvCounters:         make(map[string]*srvCounters),
		peerSummaries:       make(map[string]*ServerSummary),
	}
}

// getOrCreateSrvCounters returns the counters for a server name, creating if needed.
// Caller must hold srvCountersMu write lock.
func (m *Manager) getOrCreateSrvCounters(name string) *srvCounters {
	if name == "" {
		name = "_default"
	}
	c, ok := m.srvCounters[name]
	if !ok {
		c = &srvCounters{
			domains:     make(map[string]*srvDomainCounters),
			rcptDomains: make(map[string]*srvDomainCounters),
		}
		m.srvCounters[name] = c
	}
	return c
}

// getOrCreateDomain returns the per-sender-domain counters for a server, creating if needed.
// Returns nil if the domain map is at capacity and this is a new domain (prevents unbounded growth).
// Caller must hold srvCountersMu write lock.
func (c *srvCounters) getOrCreateDomain(domain string, maxEntries int) *srvDomainCounters {
	if domain == "" {
		return nil
	}
	d, ok := c.domains[domain]
	if !ok {
		if maxEntries > 0 && len(c.domains) >= maxEntries {
			return nil // At capacity, don't track new domains
		}
		d = &srvDomainCounters{}
		c.domains[domain] = d
	}
	return d
}

// getOrCreateRcptDomain returns the per-recipient-domain counters for a server, creating if needed.
// Returns nil if the domain map is at capacity and this is a new domain (prevents unbounded growth).
// Caller must hold srvCountersMu write lock.
func (c *srvCounters) getOrCreateRcptDomain(domain string, maxEntries int) *srvDomainCounters {
	if domain == "" {
		return nil
	}
	d, ok := c.rcptDomains[domain]
	if !ok {
		if maxEntries > 0 && len(c.rcptDomains) >= maxEntries {
			return nil // At capacity, don't track new domains
		}
		d = &srvDomainCounters{}
		c.rcptDomains[domain] = d
	}
	return d
}

// RegisterConnectionTracker adds a connection tracker to monitor active connections
func (m *Manager) RegisterConnectionTracker(tracker ConnectionTracker) {
	m.connTrackersMu.Lock()
	defer m.connTrackersMu.Unlock()
	m.connTrackers = append(m.connTrackers, tracker)
}

// Start begins the cleanup goroutine
func (m *Manager) Start() {
	if !m.enabled {
		m.logger.Info("Stats tracking disabled")
		return
	}

	m.logger.Info(fmt.Sprintf("Starting stats manager with %v retention", m.retentionDuration))

	// Start cleanup goroutine
	concurrency.SafeGo(m.logger, "stats-manager-cleanup", m.cleanupLoop)

	// Start event processing goroutine
	concurrency.SafeGo(m.logger, "stats-manager-events", m.processEventsLoop)
}

// Stop stops the cleanup goroutine
func (m *Manager) Stop() {
	if m.cancel != nil {
		m.cancel()
		close(m.eventChan)
	}
}

// cleanupLoop periodically removes expired entries
func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute) // Run cleanup every 5 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.cleanup()
		case <-m.ctx.Done():
			m.logger.Info("Stats cleanup loop stopped")
			return
		}
	}
}

// processEventsLoop is the central goroutine for processing statistical events.
// This serializes all write access to the stats maps, reducing lock contention.
func (m *Manager) processEventsLoop() {
	defer func() {
		if r := recover(); r != nil {
			m.logger.Error("panic in stats event processing loop",
				"panic", r,
				"stack", "",
			)
			// Critical: restart the loop if it panics
			m.logger.Warn("Restarting stats event processing loop after panic")
			concurrency.SafeGo(m.logger, "stats-manager-events-restart", m.processEventsLoop)
		}
	}()

	m.logger.Info("Starting stats event processing loop")
	for {
		select {
		case e, ok := <-m.eventChan:
			if !ok {
				m.logger.Info("Stats event channel closed, stopping loop")
				return
			}
			m.handleEvent(e)
		case <-m.ctx.Done():
			// On shutdown, drain any remaining events in the channel
			m.logger.Info("Context cancelled, draining remaining stats events...")
			for {
				select {
				case e, ok := <-m.eventChan:
					if !ok {
						m.logger.Info("Finished draining stats event channel.")
						return
					}
					m.handleEvent(e)
				default:
					m.logger.Info("Finished draining stats event channel.")
					return
				}
			}
		}
	}
}

// handleEvent processes a single statistical event.
func (m *Manager) handleEvent(e event) {
	// Increment processed counter
	m.metricsMu.Lock()
	m.eventsProcessed++
	m.metricsMu.Unlock()

	switch e.Type {
	case eventConnection:
		entry := m.getOrCreateIP(e.IP)
		entry.IncrementConnections()
		// Track which server(s) saw this IP
		if e.ServerName != "" {
			entry.mu.Lock()
			if entry.Servers == nil {
				entry.Servers = make(map[string]struct{})
			}
			entry.Servers[e.ServerName] = struct{}{}
			entry.mu.Unlock()
		}
	case eventDeniedConnection:
		entry := m.getOrCreateIP(e.IP)
		entry.mu.Lock()
		entry.IsDenied = true
		entry.mu.Unlock()
	case eventMailFrom:
		// Track per-server sender domain message counts
		// Note: We don't increment total here because it's computed from outcomes
		// (accepted + rejected + junk) to handle multi-recipient messages correctly
		m.srvCountersMu.Lock()
		c := m.getOrCreateSrvCounters(e.ServerName)
		if e.Domain != "" {
			if d := c.getOrCreateDomain(e.Domain, m.maxSrvDomainEntries); d != nil {
				d.messages++
			}
		}
		m.srvCountersMu.Unlock()
	case eventInvalidRecipient:
		m.applyNegativeWeight(e.IP, e.Domain, WeightInvalidRecipient)
		// Track per-server rejected count + per-server domain rejected
		m.srvCountersMu.Lock()
		sc := m.getOrCreateSrvCounters(e.ServerName)
		sc.rejected++
		if d := sc.getOrCreateDomain(e.Domain, m.maxSrvDomainEntries); d != nil {
			d.rejected++
		}
		m.srvCountersMu.Unlock()
	case eventSpoofingAttempt:
		m.applyNegativeWeight(e.IP, e.Domain, WeightSpoofingAttempt)
		// Track per-server rejected count + per-server domain rejected
		m.srvCountersMu.Lock()
		sc := m.getOrCreateSrvCounters(e.ServerName)
		sc.rejected++
		if d := sc.getOrCreateDomain(e.Domain, m.maxSrvDomainEntries); d != nil {
			d.rejected++
		}
		m.srvCountersMu.Unlock()
	case eventDMARCFailure:
		m.applyNegativeWeight(e.IP, e.Domain, WeightDMARCFailure)
		// Track per-server rejected count + per-server domain rejected
		m.srvCountersMu.Lock()
		sc := m.getOrCreateSrvCounters(e.ServerName)
		sc.rejected++
		if d := sc.getOrCreateDomain(e.Domain, m.maxSrvDomainEntries); d != nil {
			d.rejected++
		}
		m.srvCountersMu.Unlock()
	case eventDNSBLHit:
		// Weight is stored in Domain field as string
		weight := int64(WeightDNSBLHit) // Default weight
		if e.Domain != "" {
			var w int64
			if n, err := fmt.Sscanf(e.Domain, "%d", &w); err == nil && n == 1 {
				weight = w // Successfully parsed custom weight
			}
		}
		// Apply negative weight to IP only (DNSBL is IP-based)
		if e.IP != "" {
			ipEntry := m.getOrCreateIP(e.IP)
			ipEntry.AddNegative(weight)
		}
	case eventJunkMessage:
		m.applyNegativeWeight(e.IP, e.Domain, WeightJunkMessage)
		// Track per-server junk count + per-server domain junk
		m.srvCountersMu.Lock()
		sc := m.getOrCreateSrvCounters(e.ServerName)
		sc.junk++
		if d := sc.getOrCreateDomain(e.Domain, m.maxSrvDomainEntries); d != nil {
			d.junk++
		}
		m.srvCountersMu.Unlock()
	case eventHamDelivery:
		// Apply positive weight multiplied by recipient count.
		// This ensures mailing lists get proportional positive reputation.
		count := e.Count
		if count <= 0 {
			count = 1
		}
		weight := WeightHamDelivery * int64(count)
		m.applyPositiveWeight(e.IP, e.Domain, weight)
		// Track per-server accepted count + per-server domain accepted
		m.srvCountersMu.Lock()
		sc := m.getOrCreateSrvCounters(e.ServerName)
		sc.accepted += uint64(count)
		if d := sc.getOrCreateDomain(e.Domain, m.maxSrvDomainEntries); d != nil {
			d.accepted += int64(count)
		}
		m.srvCountersMu.Unlock()
	case eventSPFFailure:
		// Apply negative weight to IP only (not domain).
		// The MAIL FROM domain is unverified and trivially forged by spammers.
		// Penalizing the domain would harm innocent domains being impersonated.
		if e.IP != "" {
			ipEntry := m.getOrCreateIP(e.IP)
			ipEntry.AddNegative(WeightSPFFailure)
		}
	}
}

// cleanup removes expired entries and enforces LRU limits
func (m *Manager) cleanup() {
	// Clean IPs
	m.ipMu.Lock()
	expiredIPs := 0
	for ip, entry := range m.ips {
		if entry.IsExpired(m.retentionDuration) {
			delete(m.ips, ip)
			expiredIPs++
		}
	}

	// Enforce LRU eviction if over limit
	evictedIPs := 0
	if m.maxIPEntries > 0 && len(m.ips) > m.maxIPEntries {
		evictedIPs = m.evictLRUIPs(len(m.ips) - m.maxIPEntries)
	}
	m.ipMu.Unlock()

	if expiredIPs > 0 || evictedIPs > 0 {
		m.logger.Debug("Cleaned expired stats entries",
			"expired_ips", expiredIPs,
			"evicted_ips", evictedIPs,
			"remaining_ips", len(m.ips))
	}
}

// evictLRUIPs evicts the oldest n IP entries based on LastSeen time
// Caller must hold ipMu.Lock()
func (m *Manager) evictLRUIPs(n int) int {
	if n <= 0 {
		return 0
	}

	// Build a list of candidates for eviction
	type candidate struct {
		ip       string
		lastSeen time.Time
	}
	candidates := make([]candidate, 0, len(m.ips))

	for ip, entry := range m.ips {
		entry.mu.RLock()
		candidates = append(candidates, candidate{ip: ip, lastSeen: entry.LastSeen})
		entry.mu.RUnlock()
	}

	// Sort by LastSeen (oldest first) using O(n log n) sort
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].lastSeen.Before(candidates[j].lastSeen)
	})

	// Evict the oldest n entries
	evicted := 0
	for i := 0; i < n && i < len(candidates); i++ {
		delete(m.ips, candidates[i].ip)
		evicted++
	}

	return evicted
}

// getOrCreateIP gets or creates an IP entry. This uses locks as it can be called
// from the event loop or from reputation checks.
func (m *Manager) getOrCreateIP(ip string) *IPEntry {
	m.ipMu.RLock()
	entry, exists := m.ips[ip]
	m.ipMu.RUnlock()

	if exists && entry != nil {
		return entry
	}

	// Create new entry
	m.ipMu.Lock()
	defer m.ipMu.Unlock()

	// Double-check after acquiring write lock
	if entry, exists := m.ips[ip]; exists && entry != nil {
		return entry
	}

	now := time.Now()
	entry = &IPEntry{
		FirstSeen: now,
		Servers:   make(map[string]struct{}),
		LastSeen:  now,
	}
	m.ips[ip] = entry
	return entry
}

// RecordDeniedConnection marks an IP as denied.
func (m *Manager) RecordDeniedConnection(ip string) {
	if !m.enabled {
		return
	}
	m.sendEvent(event{Type: eventDeniedConnection, IP: ip})
}

// RecordConnection records a new connection from an IP by sending an event.
func (m *Manager) RecordConnection(ip string, hasRDNS bool) {
	if !m.enabled {
		return
	}

	// Use the Domain field to pass the hasRDNS status.
	rdnsStatus := "yes"
	if !hasRDNS {
		rdnsStatus = "no"
	}

	m.sendEvent(event{Type: eventConnection, IP: ip, Domain: rdnsStatus})
}

// RecordMailFrom records a MAIL FROM command for per-server message counting
// and domain observability. The domain is used for stats/monitoring only,
// NOT for reputation scoring (since MAIL FROM is trivially forged).
func (m *Manager) RecordMailFrom(domain string) {
	if !m.enabled {
		return
	}
	m.sendEvent(event{Type: eventMailFrom, Domain: domain})
}

// RecordInvalidRecipient records an attempt to send to a non-existent address.
// Only IP reputation is affected (domain is unverified and trivially forged).
func (m *Manager) RecordInvalidRecipient(ip string) {
	if !m.enabled {
		return
	}
	m.sendEvent(event{Type: eventInvalidRecipient, IP: ip})
}

// RecordSpoofingAttempt records a spoofing attempt.
// Only IP reputation is affected (domain is unverified and trivially forged).
func (m *Manager) RecordSpoofingAttempt(ip string) {
	if !m.enabled {
		return
	}
	m.sendEvent(event{Type: eventSpoofingAttempt, IP: ip})
}

// RecordDMARCFailure records a DMARC policy failure.
// Only IP reputation is affected (domain is unverified and trivially forged).
func (m *Manager) RecordDMARCFailure(ip string) {
	if !m.enabled {
		return
	}
	m.sendEvent(event{Type: eventDMARCFailure, IP: ip})
}

// RecordSPFFailure records a hard SPF failure against the sender's IP.
// Only applied to IP reputation (not domain) because the MAIL FROM domain
// is unverified and trivially forged.
func (m *Manager) RecordSPFFailure(ip string) {
	if !m.enabled {
		return
	}
	m.sendEvent(event{Type: eventSPFFailure, IP: ip})
}

// RecordJunkMessage records a junk/spam message.
// Only IP reputation is affected (domain is unverified and trivially forged).
func (m *Manager) RecordJunkMessage(ip string) {
	if !m.enabled {
		return
	}
	m.sendEvent(event{Type: eventJunkMessage, IP: ip})
}

// RecordHamDelivery records a successful ham (non-spam) delivery.
// recipientCount indicates the number of recipients successfully delivered to.
// This ensures reputation scoring is proportional to the number of recipients,
// fixing incorrect scoring for mailing lists and bulk senders.
// Only IP reputation is affected (domain is unverified and trivially forged).
func (m *Manager) RecordHamDelivery(ip string, recipientCount int) {
	if !m.enabled {
		return
	}
	if recipientCount <= 0 {
		recipientCount = 1
	}
	m.sendEvent(event{Type: eventHamDelivery, IP: ip, Count: recipientCount})
}

// sendEvent is a non-blocking send to the event channel.
// If the channel is full, it logs a warning and drops the event.
func (m *Manager) sendEvent(e event) {
	select {
	case m.eventChan <- e:
		// Event sent successfully
	default:
		// Channel is full - increment dropped counter
		m.metricsMu.Lock()
		m.eventsDropped++
		droppedCount := m.eventsDropped
		m.metricsMu.Unlock()

		m.logger.Warn("Stats event channel is full, dropping event",
			"event_type", e.Type,
			"total_dropped", droppedCount)
	}
}

// applyNegativeWeight applies a negative weight to IP and domain entries.
// This is called by the event processing loop.
func (m *Manager) applyNegativeWeight(ip, domain string, weight int64) {
	if ip != "" {
		ipEntry := m.getOrCreateIP(ip)
		ipEntry.AddNegative(weight)
	}
}

// applyPositiveWeight applies a positive weight to IP and domain entries.
// This is called by the event processing loop.
func (m *Manager) applyPositiveWeight(ip, domain string, weight int64) {
	if ip != "" {
		ipEntry := m.getOrCreateIP(ip)
		ipEntry.AddPositive(weight)
	}
}

// CheckIPReputation checks if an IP should be denied based on reputation
func (m *Manager) CheckIPReputation(ip string) (shouldDeny bool, reputation float64) {
	if !m.enabled {
		return false, 0
	}

	m.ipMu.RLock()
	entry, exists := m.ips[ip]
	m.ipMu.RUnlock()

	if !exists {
		return false, 0 // No data, allow
	}

	return entry.ShouldDeny(), entry.GetReputation()
}

// GetIPFromRemoteAddr extracts IP from remote address string
func GetIPFromRemoteAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// If split fails, try using the whole string as IP
		return remoteAddr
	}
	return host
}

// ExtractDomainFromEmail extracts domain from email address
func ExtractDomainFromEmail(email string) string {
	email = strings.TrimSpace(email)
	// Remove angle brackets if present
	email = strings.Trim(email, "<>")

	if idx := strings.LastIndex(email, "@"); idx != -1 {
		return strings.ToLower(email[idx+1:])
	}
	return ""
}

// RemoveIP removes an IP entry from the reputation tracker, effectively unblocking it.
// Returns true if the IP was found and removed, false if it was not tracked.
// Note: buffered events already in the channel may recreate the entry with a clean
// slate shortly after removal. This is harmless as the new entry starts with neutral
// reputation.
func (m *Manager) RemoveIP(ip string) bool {
	key, ok := NormalizeIP(ip)
	if !ok {
		return false
	}

	m.ipMu.Lock()
	defer m.ipMu.Unlock()
	_, exists := m.ips[key]
	if exists {
		delete(m.ips, key)
	}
	return exists
}

// GetIPForTest is a helper function for integration tests to access an IP entry.
// This should only be used in tests.
func (m *Manager) GetIPForTest(ip string) *IPEntry {
	m.ipMu.RLock()
	defer m.ipMu.RUnlock()
	if entry, exists := m.ips[ip]; exists {
		return entry
	}
	return nil
}

// Name returns the component name for health checks.
// GetStats returns a snapshot of current statistics (satisfies health.StatsProvider interface)
func (m *Manager) GetStats() any {
	return m.GetStatsSnapshot()
}

// GetStatsSnapshot returns a snapshot of current statistics
func (m *Manager) GetStatsSnapshot() *StatsSnapshot {
	if !m.enabled {
		return &StatsSnapshot{
			IPs:     make(map[string]*IPExport),
			Summary: StatsSummary{},
		}
	}

	m.ipMu.RLock()
	ips := make(map[string]*IPExport, len(m.ips))
	var blockedCount int
	for ip, entry := range m.ips {
		ips[ip] = entry.ToExport()
		if entry.ShouldDeny() {
			blockedCount++
		}
	}
	m.ipMu.RUnlock()

	m.metricsMu.RLock()
	eventsProcessed := m.eventsProcessed
	eventsDropped := m.eventsDropped
	m.metricsMu.RUnlock()

	// Get active connections from all registered connection trackers
	m.connTrackersMu.RLock()
	var activeConnections int
	for _, tracker := range m.connTrackers {
		activeConnections += tracker.GetTotalCount()
	}
	m.connTrackersMu.RUnlock()

	// Build per-server breakdown
	servers := m.buildServerSummaries()

	return &StatsSnapshot{
		IPs: ips,
		Summary: StatsSummary{
			TotalIPs:          len(ips),
			BlockedIPs:        blockedCount,
			ActiveConnections: int64(activeConnections),
			EventsProcessed:   int64(eventsProcessed),
			EventsDropped:     int64(eventsDropped),
		},
		Servers: servers,
	}
}

// buildServerSummaries returns per-config-server message statistics
func (m *Manager) buildServerSummaries() map[string]*ServerSummary {
	servers := make(map[string]*ServerSummary)

	// Collect active connections per server from connection trackers
	serverConnections := make(map[string]int)
	m.connTrackersMu.RLock()
	for _, tracker := range m.connTrackers {
		serverName := tracker.GetServerName()
		serverConnections[serverName] += tracker.GetTotalCount()
	}
	m.connTrackersMu.RUnlock()

	// Add per-config-server summaries from local counters
	m.srvCountersMu.RLock()
	for name, c := range m.srvCounters {
		// Total is computed from outcomes to handle multi-recipient messages correctly
		total := int64(c.accepted + c.rejected + c.junk)
		summary := &ServerSummary{
			Hostname:          name,
			TotalMessages:     total,
			AcceptedMessages:  int64(c.accepted),
			RejectedMessages:  int64(c.rejected),
			JunkMessages:      int64(c.junk),
			ActiveConnections: int64(serverConnections[name]),
			LastUpdated:       time.Now(),
		}
		// Include per-server domain breakdown
		if len(c.domains) > 0 {
			summary.SenderDomains = make(map[string]*ServerDomainStats, len(c.domains))
			for domain, dc := range c.domains {
				summary.SenderDomains[domain] = &ServerDomainStats{
					Messages: dc.messages,
					Accepted: dc.accepted,
					Rejected: dc.rejected,
					Junk:     dc.junk,
				}
			}
		}
		// Include per-server recipient domain breakdown
		if len(c.rcptDomains) > 0 {
			summary.RecipientDomains = make(map[string]*ServerDomainStats, len(c.rcptDomains))
			for domain, dc := range c.rcptDomains {
				summary.RecipientDomains[domain] = &ServerDomainStats{
					Messages: dc.messages,
					Accepted: dc.accepted,
					Rejected: dc.rejected,
					Junk:     dc.junk,
				}
			}
		}
		servers[name] = summary
	}
	m.srvCountersMu.RUnlock()

	// Add peer summaries collected during sync
	m.peerSummariesMu.RLock()
	for name, summary := range m.peerSummaries {
		servers[name] = summary
	}
	m.peerSummariesMu.RUnlock()

	return servers
}

func (m *Manager) Name() string {
	return "stats"
}

// CheckHealth checks the health of the stats manager.
func (m *Manager) CheckHealth() health.ComponentStatus {
	if !m.enabled {
		return health.ComponentStatus{
			Status:  "disabled",
			Details: map[string]any{"enabled": false},
		}
	}

	m.ipMu.RLock()
	ipCount := len(m.ips)
	m.ipMu.RUnlock()

	// Get event metrics
	m.metricsMu.RLock()
	eventsProcessed := m.eventsProcessed
	eventsDropped := m.eventsDropped
	m.metricsMu.RUnlock()

	// Calculate channel utilization
	chanLen := len(m.eventChan)
	chanCap := cap(m.eventChan)
	chanUtilization := float64(chanLen) / float64(chanCap) * 100.0

	details := map[string]any{
		"enabled":          true,
		"tracked_ips":      ipCount,
		"events_processed": eventsProcessed,
		"events_dropped":   eventsDropped,
		"channel_length":   chanLen,
		"channel_capacity": chanCap,
		"channel_util_pct": chanUtilization,
	}

	// If sync is enabled, check last sync status
	if m.syncEnabled {
		m.lastSyncMu.RLock()
		lastSyncTimes := make(map[string]string)
		for server, t := range m.lastSyncAttempt {
			lastSyncTimes[server] = time.Since(t).String()
		}
		m.lastSyncMu.RUnlock()

		details["sync_enabled"] = true
		details["sync_servers"] = len(m.syncServers)
		details["last_sync_attempts"] = lastSyncTimes

		// Check if any sync is very stale (> 2x sync interval)
		staleSyncFound := false
		m.lastSyncMu.RLock()
		for _, lastAttempt := range m.lastSyncAttempt {
			if time.Since(lastAttempt) > 2*m.syncInterval {
				staleSyncFound = true
				break
			}
		}
		m.lastSyncMu.RUnlock()

		if staleSyncFound {
			return health.ComponentStatus{Status: "degraded", Details: details}
		}
	}

	// Check if we're dropping events
	if eventsDropped > 0 {
		// Calculate drop rate
		totalEvents := eventsProcessed + eventsDropped
		dropRate := float64(eventsDropped) / float64(totalEvents) * 100.0
		details["drop_rate_pct"] = dropRate

		// Degraded if dropping any events
		if dropRate > 1.0 {
			// More than 1% drop rate is concerning
			return health.ComponentStatus{Status: "unhealthy", Details: details}
		} else {
			return health.ComponentStatus{Status: "degraded", Details: details}
		}
	}

	// Check channel utilization - warn if >80% full
	if chanUtilization > 80.0 {
		return health.ComponentStatus{Status: "degraded", Details: details}
	}

	return health.ComponentStatus{Status: "healthy", Details: details}
}

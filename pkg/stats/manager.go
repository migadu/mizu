package stats

import (
	"context"
	"fmt"
	"io"
	"net"
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
	eventMailFrom
	eventInvalidRecipient
	eventSpoofingAttempt
	eventDMARCFailure
	eventJunkMessage
	eventHamDelivery
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
	maxIPEntries     int
	maxDomainEntries int

	// Maps for tracking IPs and domains
	ips     map[string]*IPEntry
	domains map[string]*DomainEntry

	// Mutex for map access
	ipMu     sync.RWMutex
	domainMu sync.RWMutex

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

// srvCounters tracks message counters for a single config server name
type srvCounters struct {
	total    uint64
	accepted uint64
	rejected uint64
	junk     uint64
}

// ConnectionTracker interface for getting active connection stats
type ConnectionTracker interface {
	GetStats() (total int, uniqueIPs int, perIP map[string]int)
}

// event represents a statistical event to be processed
type event struct {
	Type       eventType
	IP         string
	Domain     string
	ServerName string // Config server name (e.g., "mx-primary", "mx-submission")
}

// ServerRecorder wraps a Manager with a server name for per-config-server tracking.
// It has the same method signatures as Manager for Record* and Check* methods,
// allowing it to be used as a drop-in replacement in the SMTP Backend/Session.
type ServerRecorder struct {
	manager    *Manager
	serverName string
}

// NewServerRecorder creates a recorder that tags all events with the given server name.
func NewServerRecorder(manager *Manager, serverName string) *ServerRecorder {
	return &ServerRecorder{manager: manager, serverName: serverName}
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

func (r *ServerRecorder) RecordMailFrom(domain string) {
	if r.manager == nil || !r.manager.enabled || domain == "" {
		return
	}
	r.manager.sendEvent(event{Type: eventMailFrom, Domain: domain, ServerName: r.serverName})
}

func (r *ServerRecorder) RecordInvalidRecipient(ip, domain string) {
	if r.manager == nil || !r.manager.enabled {
		return
	}
	r.manager.sendEvent(event{Type: eventInvalidRecipient, IP: ip, Domain: domain, ServerName: r.serverName})
}

func (r *ServerRecorder) RecordSpoofingAttempt(ip, domain string) {
	if r.manager == nil || !r.manager.enabled {
		return
	}
	r.manager.sendEvent(event{Type: eventSpoofingAttempt, IP: ip, Domain: domain, ServerName: r.serverName})
}

func (r *ServerRecorder) RecordDMARCFailure(ip, domain string) {
	if r.manager == nil || !r.manager.enabled {
		return
	}
	r.manager.sendEvent(event{Type: eventDMARCFailure, IP: ip, Domain: domain, ServerName: r.serverName})
}

func (r *ServerRecorder) RecordJunkMessage(ip, domain string) {
	if r.manager == nil || !r.manager.enabled {
		return
	}
	r.manager.sendEvent(event{Type: eventJunkMessage, IP: ip, Domain: domain, ServerName: r.serverName})
}

func (r *ServerRecorder) RecordHamDelivery(ip, domain string) {
	if r.manager == nil || !r.manager.enabled {
		return
	}
	r.manager.sendEvent(event{Type: eventHamDelivery, IP: ip, Domain: domain, ServerName: r.serverName})
}

func (r *ServerRecorder) CheckIPReputation(ip string) (shouldDeny bool, reputation float64) {
	if r.manager == nil {
		return false, 0
	}
	return r.manager.CheckIPReputation(ip)
}

func (r *ServerRecorder) CheckDomainReputation(domain string) (shouldDeny bool, reputation float64) {
	if r.manager == nil {
		return false, 0
	}
	return r.manager.CheckDomainReputation(domain)
}

// NewManager creates a new stats manager
func NewManager(enabled bool, retentionDuration time.Duration, hostname string, syncEnabled bool, syncInterval time.Duration, syncServers []string, maxIPEntries, maxDomainEntries, bufferSize int, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// Default buffer size if not specified
	if bufferSize <= 0 {
		bufferSize = 100000
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Manager{
		enabled:           enabled,
		retentionDuration: retentionDuration,
		hostname:          hostname,
		syncEnabled:       syncEnabled,
		syncInterval:      syncInterval,
		syncServers:       syncServers,
		maxIPEntries:      maxIPEntries,
		maxDomainEntries:  maxDomainEntries,
		logger:            logger,
		ips:               make(map[string]*IPEntry),
		domains:           make(map[string]*DomainEntry),
		lastSync:          make(map[string]time.Time),
		lastSyncAttempt:   make(map[string]time.Time),
		ctx:               ctx,
		cancel:            cancel,
		eventChan:         make(chan event, bufferSize),
		connTrackers:      make([]ConnectionTracker, 0),
		srvCounters:       make(map[string]*srvCounters),
		peerSummaries:     make(map[string]*ServerSummary),
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
		c = &srvCounters{}
		m.srvCounters[name] = c
	}
	return c
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
		// hasRDNS is passed via the Domain field for this event type
		if e.Domain == "no" {
			entry.mu.Lock()
			entry.IsDenied = true
			entry.mu.Unlock()
		}
	case eventMailFrom:
		if e.Domain != "" {
			entry := m.getOrCreateDomain(e.Domain)
			entry.IncrementMessages()

			// Track per-server message count
			m.srvCountersMu.Lock()
			c := m.getOrCreateSrvCounters(e.ServerName)
			c.total++
			m.srvCountersMu.Unlock()
		}
	case eventInvalidRecipient:
		m.applyNegativeWeight(e.IP, e.Domain, WeightInvalidRecipient)
		// Track unweighted rejected count on domain
		if e.Domain != "" {
			domainEntry := m.getOrCreateDomain(e.Domain)
			domainEntry.mu.Lock()
			domainEntry.Rejected++
			domainEntry.mu.Unlock()
		}
		// Track per-server rejected count
		m.srvCountersMu.Lock()
		m.getOrCreateSrvCounters(e.ServerName).rejected++
		m.srvCountersMu.Unlock()
	case eventSpoofingAttempt:
		m.applyNegativeWeight(e.IP, e.Domain, WeightSpoofingAttempt)
		// Track unweighted rejected count on domain
		if e.Domain != "" {
			domainEntry := m.getOrCreateDomain(e.Domain)
			domainEntry.mu.Lock()
			domainEntry.Rejected++
			domainEntry.mu.Unlock()
		}
		// Track per-server rejected count
		m.srvCountersMu.Lock()
		m.getOrCreateSrvCounters(e.ServerName).rejected++
		m.srvCountersMu.Unlock()
	case eventDMARCFailure:
		m.applyNegativeWeight(e.IP, e.Domain, WeightDMARCFailure)
		// Track unweighted rejected count on domain
		if e.Domain != "" {
			domainEntry := m.getOrCreateDomain(e.Domain)
			domainEntry.mu.Lock()
			domainEntry.Rejected++
			domainEntry.mu.Unlock()
		}
		// Track per-server rejected count
		m.srvCountersMu.Lock()
		m.getOrCreateSrvCounters(e.ServerName).rejected++
		m.srvCountersMu.Unlock()
	case eventJunkMessage:
		m.applyNegativeWeight(e.IP, e.Domain, WeightJunkMessage)
		// Track unweighted junk count on domain
		if e.Domain != "" {
			domainEntry := m.getOrCreateDomain(e.Domain)
			domainEntry.mu.Lock()
			domainEntry.Junk++
			domainEntry.mu.Unlock()
		}
		// Track per-server junk count
		m.srvCountersMu.Lock()
		m.getOrCreateSrvCounters(e.ServerName).junk++
		m.srvCountersMu.Unlock()
	case eventHamDelivery:
		m.applyPositiveWeight(e.IP, e.Domain, WeightHamDelivery)
		// Track per-server accepted count
		m.srvCountersMu.Lock()
		m.getOrCreateSrvCounters(e.ServerName).accepted++
		m.srvCountersMu.Unlock()
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

	// Clean domains
	m.domainMu.Lock()
	expiredDomains := 0
	for domain, entry := range m.domains {
		if entry.IsExpired(m.retentionDuration) {
			delete(m.domains, domain)
			expiredDomains++
		}
	}

	// Enforce LRU eviction if over limit
	evictedDomains := 0
	if m.maxDomainEntries > 0 && len(m.domains) > m.maxDomainEntries {
		evictedDomains = m.evictLRUDomains(len(m.domains) - m.maxDomainEntries)
	}
	m.domainMu.Unlock()

	if expiredIPs > 0 || expiredDomains > 0 || evictedIPs > 0 || evictedDomains > 0 {
		m.logger.Debug("Cleaned expired stats entries",
			"expired_ips", expiredIPs,
			"expired_domains", expiredDomains,
			"evicted_ips", evictedIPs,
			"evicted_domains", evictedDomains,
			"remaining_ips", len(m.ips),
			"remaining_domains", len(m.domains))
	}
}

// evictLRUIPs evicts the oldest n IP entries based on LastSeen time
// Caller must hold ipMu.Lock()
func (m *Manager) evictLRUIPs(n int) int {
	if n <= 0 {
		return 0
	}

	// Build a list of candidates for eviction (sorted by LastSeen)
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

	// Sort by LastSeen (oldest first)
	for i := 0; i < len(candidates)-1; i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[i].lastSeen.After(candidates[j].lastSeen) {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}

	// Evict the oldest n entries
	evicted := 0
	for i := 0; i < n && i < len(candidates); i++ {
		delete(m.ips, candidates[i].ip)
		evicted++
	}

	return evicted
}

// evictLRUDomains evicts the oldest n domain entries based on LastSeen time
// Caller must hold domainMu.Lock()
func (m *Manager) evictLRUDomains(n int) int {
	if n <= 0 {
		return 0
	}

	// Build a list of candidates for eviction (sorted by LastSeen)
	type candidate struct {
		domain   string
		lastSeen time.Time
	}
	candidates := make([]candidate, 0, len(m.domains))

	for domain, entry := range m.domains {
		entry.mu.RLock()
		candidates = append(candidates, candidate{domain: domain, lastSeen: entry.LastSeen})
		entry.mu.RUnlock()
	}

	// Sort by LastSeen (oldest first)
	for i := 0; i < len(candidates)-1; i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[i].lastSeen.After(candidates[j].lastSeen) {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}

	// Evict the oldest n entries
	evicted := 0
	for i := 0; i < n && i < len(candidates); i++ {
		delete(m.domains, candidates[i].domain)
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
		LastSeen:  now,
	}
	m.ips[ip] = entry
	return entry
}

// getOrCreateDomain gets or creates a domain entry.
func (m *Manager) getOrCreateDomain(domain string) *DomainEntry {
	// Normalize domain
	domain = strings.ToLower(strings.TrimSpace(domain))

	m.domainMu.RLock()
	entry, exists := m.domains[domain]
	m.domainMu.RUnlock()

	if exists && entry != nil {
		return entry
	}

	// Create new entry
	m.domainMu.Lock()
	defer m.domainMu.Unlock()

	// Double-check after acquiring write lock
	if entry, exists := m.domains[domain]; exists && entry != nil {
		return entry
	}

	now := time.Now()
	entry = &DomainEntry{
		FirstSeen: now,
		LastSeen:  now,
	}
	m.domains[domain] = entry
	return entry
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

// RecordMailFrom records a MAIL FROM command by sending an event.
func (m *Manager) RecordMailFrom(domain string) {
	if !m.enabled || domain == "" {
		return
	}
	m.sendEvent(event{Type: eventMailFrom, Domain: domain})
}

// RecordInvalidRecipient records an attempt to send to a non-existent address.
func (m *Manager) RecordInvalidRecipient(ip, domain string) {
	if !m.enabled {
		return
	}
	m.sendEvent(event{Type: eventInvalidRecipient, IP: ip, Domain: domain})
}

// RecordSpoofingAttempt records a spoofing attempt.
func (m *Manager) RecordSpoofingAttempt(ip, domain string) {
	if !m.enabled {
		return
	}
	m.sendEvent(event{Type: eventSpoofingAttempt, IP: ip, Domain: domain})
}

// RecordDMARCFailure records a DMARC policy failure.
func (m *Manager) RecordDMARCFailure(ip, domain string) {
	if !m.enabled {
		return
	}
	m.sendEvent(event{Type: eventDMARCFailure, IP: ip, Domain: domain})
}

// RecordJunkMessage records a junk/spam message.
func (m *Manager) RecordJunkMessage(ip, domain string) {
	if !m.enabled {
		return
	}
	m.sendEvent(event{Type: eventJunkMessage, IP: ip, Domain: domain})
}

// RecordHamDelivery records a successful ham (non-spam) delivery.
func (m *Manager) RecordHamDelivery(ip, domain string) {
	if !m.enabled {
		return
	}
	m.sendEvent(event{Type: eventHamDelivery, IP: ip, Domain: domain})
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
	if domain != "" {
		domainEntry := m.getOrCreateDomain(domain)
		domainEntry.AddNegative(weight)
	}
}

// applyPositiveWeight applies a positive weight to IP and domain entries.
// This is called by the event processing loop.
func (m *Manager) applyPositiveWeight(ip, domain string, weight int64) {
	if ip != "" {
		ipEntry := m.getOrCreateIP(ip)
		ipEntry.AddPositive(weight)
	}
	if domain != "" {
		domainEntry := m.getOrCreateDomain(domain)
		domainEntry.AddPositive(weight)
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

// CheckDomainReputation checks if a domain should be denied based on reputation
func (m *Manager) CheckDomainReputation(domain string) (shouldDeny bool, reputation float64) {
	if !m.enabled {
		return false, 0
	}

	// Normalize domain
	domain = strings.ToLower(strings.TrimSpace(domain))

	m.domainMu.RLock()
	entry, exists := m.domains[domain]
	m.domainMu.RUnlock()

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
			Domains: make(map[string]*DomainExport),
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

	m.domainMu.RLock()
	domains := make(map[string]*DomainExport, len(m.domains))
	var totalMessages, acceptedMessages, rejectedMessages, junkMessages int64
	for domain, entry := range m.domains {
		domains[domain] = entry.ToExport()
		entry.mu.RLock()
		totalMessages += entry.Messages
		acceptedMessages += entry.Positive // Positive tracks ham deliveries (weight=1)
		rejectedMessages += entry.Rejected // Unweighted rejected count
		junkMessages += entry.Junk         // Unweighted junk count
		entry.mu.RUnlock()
	}
	m.domainMu.RUnlock()

	m.metricsMu.RLock()
	eventsProcessed := m.eventsProcessed
	eventsDropped := m.eventsDropped
	m.metricsMu.RUnlock()

	// Get active connections from all registered connection trackers
	m.connTrackersMu.RLock()
	var activeConnections int
	for _, tracker := range m.connTrackers {
		total, _, _ := tracker.GetStats()
		activeConnections += total
	}
	m.connTrackersMu.RUnlock()

	// Build per-server breakdown
	servers := m.buildServerSummaries()

	return &StatsSnapshot{
		IPs:     ips,
		Domains: domains,
		Summary: StatsSummary{
			TotalIPs:          len(ips),
			TotalDomains:      len(domains),
			BlockedIPs:        blockedCount,
			ActiveConnections: int64(activeConnections),
			TotalMessages:     totalMessages,
			AcceptedMessages:  acceptedMessages,
			RejectedMessages:  rejectedMessages,
			JunkMessages:      junkMessages,
			EventsProcessed:   int64(eventsProcessed),
			EventsDropped:     int64(eventsDropped),
		},
		Servers: servers,
	}
}

// buildServerSummaries returns per-config-server message statistics
func (m *Manager) buildServerSummaries() map[string]*ServerSummary {
	servers := make(map[string]*ServerSummary)

	// Add per-config-server summaries from local counters
	m.srvCountersMu.RLock()
	for name, c := range m.srvCounters {
		servers[name] = &ServerSummary{
			Hostname:         name,
			TotalMessages:    int64(c.total),
			AcceptedMessages: int64(c.accepted),
			RejectedMessages: int64(c.rejected),
			JunkMessages:     int64(c.junk),
			LastUpdated:      time.Now(),
		}
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

	m.domainMu.RLock()
	domainCount := len(m.domains)
	m.domainMu.RUnlock()

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
		"tracked_domains":  domainCount,
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

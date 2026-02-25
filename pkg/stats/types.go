package stats

import (
	"sync"
	"time"
)

// Event weight constants
const (
	// Positive events
	WeightHamDelivery = 1

	// Negative events
	WeightJunkMessage      = 1
	WeightInvalidRecipient = 2
	WeightSPFFailure       = 3
	WeightDNSBLHit         = 5
	WeightSpoofingAttempt  = 10
	WeightDMARCFailure     = 10

	// Minimum data threshold
	MinDataThreshold = 10

	// Reputation threshold for denial
	ReputationDenyThreshold = -0.2
)

// IPEntry tracks reputation for an IP address
type IPEntry struct {
	FirstSeen   time.Time
	LastSeen    time.Time
	Connections int64               // Total connections from this IP
	Positive    int64               // Ham messages delivered
	Negative    int64               // Junk + failed recipients + spoofing + DMARC failures
	IsDenied    bool                // Set true if no rDNS
	Servers     map[string]struct{} // Config server names that saw this IP
	mu          sync.RWMutex
}

// DomainEntry tracks reputation for a domain
type DomainEntry struct {
	FirstSeen time.Time
	LastSeen  time.Time
	Messages  int64 // Total messages from this domain
	Positive  int64 // Ham messages (weighted, used for reputation)
	Negative  int64 // Junk + invalid recipients + DMARC failures (weighted, used for reputation)
	Junk      int64 // Actual junk message count (unweighted)
	Rejected  int64 // Actual rejected message count (unweighted)
	mu        sync.RWMutex
}

// AddPositive adds a positive score with redemption logic
func (e *IPEntry) AddPositive(weight int64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.Positive += weight
	// Redemption: reduce negative score, but not below 0
	if e.Negative > 0 {
		e.Negative -= weight
		if e.Negative < 0 {
			e.Negative = 0
		}
	}
	e.LastSeen = time.Now()
}

// AddNegative adds a negative score with penalty logic
func (e *IPEntry) AddNegative(weight int64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.Negative += weight
	// Penalty: reduce positive score, but not below 0
	if e.Positive > 0 {
		e.Positive -= weight
		if e.Positive < 0 {
			e.Positive = 0
		}
	}
	e.LastSeen = time.Now()
}

// IncrementConnections increments the connection count
func (e *IPEntry) IncrementConnections() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Connections++
	e.LastSeen = time.Now()
}

// GetReputation returns the reputation score from -1 (worst) to +1 (best)
func (e *IPEntry) GetReputation() float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.getReputationLocked()
}

// getReputationLocked computes the reputation score without acquiring locks.
// Caller must hold e.mu.RLock() or e.mu.Lock().
func (e *IPEntry) getReputationLocked() float64 {
	if e.Connections < MinDataThreshold {
		return 0 // Neutral - not enough data
	}

	// Apply time decay to the negative score.
	// This allows reputation to self-heal over time if no new negative events occur.
	// The decay is linear, reaching zero after 24 hours of inactivity.
	hoursSinceLastSeen := time.Since(e.LastSeen).Hours()
	decayFactor := 1.0 - (hoursSinceLastSeen / 24.0)
	if decayFactor < 0 {
		decayFactor = 0
	}
	decayedNegative := float64(e.Negative) * decayFactor

	total := float64(e.Positive) + decayedNegative
	if total == 0 {
		return 0
	}

	// Return reputation score: -1 (worst) to +1 (best)
	return (float64(e.Positive) - decayedNegative) / total
}

// ShouldDeny returns true if the IP should be denied based on reputation
func (e *IPEntry) ShouldDeny() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.IsDenied { // No rDNS
		return true
	}

	if e.Connections < MinDataThreshold {
		return false // Not enough data
	}

	// Deny if reputation < -0.2
	// Use lock-free internal method to avoid recursive RLock deadlock
	return e.getReputationLocked() < ReputationDenyThreshold
}

// IsExpired checks if the entry is older than the retention duration
func (e *IPEntry) IsExpired(retention time.Duration) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return time.Since(e.LastSeen) > retention
}

// GetConnections returns the connection count (thread-safe)
func (e *IPEntry) GetConnections() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.Connections
}

// GetPositive returns the positive score (thread-safe)
func (e *IPEntry) GetPositive() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.Positive
}

// GetNegative returns the negative score (thread-safe)
func (e *IPEntry) GetNegative() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.Negative
}

// GetIsDenied returns whether the IP is denied (thread-safe)
func (e *IPEntry) GetIsDenied() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.IsDenied
}

// DomainEntry methods

// AddPositive adds a positive score with redemption logic
func (e *DomainEntry) AddPositive(weight int64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.Positive += weight
	// Redemption: reduce negative score, but not below 0
	if e.Negative > 0 {
		e.Negative -= weight
		if e.Negative < 0 {
			e.Negative = 0
		}
	}
	e.LastSeen = time.Now()
}

// AddNegative adds a negative score with penalty logic
func (e *DomainEntry) AddNegative(weight int64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.Negative += weight
	// Penalty: reduce positive score, but not below 0
	if e.Positive > 0 {
		e.Positive -= weight
		if e.Positive < 0 {
			e.Positive = 0
		}
	}
	e.LastSeen = time.Now()
}

// IncrementMessages increments the message count
func (e *DomainEntry) IncrementMessages() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Messages++
	e.LastSeen = time.Now()
}

// GetReputation returns the reputation score from -1 (worst) to +1 (best)
func (e *DomainEntry) GetReputation() float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.getReputationLocked()
}

// getReputationLocked computes the reputation score without acquiring locks.
// Caller must hold e.mu.RLock() or e.mu.Lock().
func (e *DomainEntry) getReputationLocked() float64 {
	if e.Messages < MinDataThreshold {
		return 0 // Neutral - not enough data
	}

	// Apply time decay to the negative score.
	hoursSinceLastSeen := time.Since(e.LastSeen).Hours()
	decayFactor := 1.0 - (hoursSinceLastSeen / 24.0)
	if decayFactor < 0 {
		decayFactor = 0
	}
	decayedNegative := float64(e.Negative) * decayFactor

	total := float64(e.Positive) + decayedNegative
	if total == 0 {
		return 0
	}

	// Return reputation score: -1 (worst) to +1 (best)
	return (float64(e.Positive) - decayedNegative) / total
}

// ShouldDeny returns true if the domain should be denied based on reputation
func (e *DomainEntry) ShouldDeny() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.Messages < MinDataThreshold {
		return false // Not enough data
	}

	// Deny if reputation < -0.2
	// Use lock-free internal method to avoid recursive RLock deadlock
	return e.getReputationLocked() < ReputationDenyThreshold
}

// IsExpired checks if the entry is older than the retention duration
func (e *DomainEntry) IsExpired(retention time.Duration) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return time.Since(e.LastSeen) > retention
}

// GetMessages returns the message count (thread-safe)
func (e *DomainEntry) GetMessages() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.Messages
}

// GetPositive returns the positive score (thread-safe)
func (e *DomainEntry) GetPositive() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.Positive
}

// GetNegative returns the negative score (thread-safe)
func (e *DomainEntry) GetNegative() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.Negative
}

// Export types for JSON serialization

// IPExport is the JSON-serializable version of IPEntry
type IPExport struct {
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Connections int64     `json:"connections"`
	Positive    int64     `json:"positive"`
	Negative    int64     `json:"negative"`
	IsDenied    bool      `json:"is_denied"`
	Servers     []string  `json:"servers,omitempty"`
}

// DomainExport is the JSON-serializable version of DomainEntry
type DomainExport struct {
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Messages  int64     `json:"messages"`
	Positive  int64     `json:"positive"`
	Negative  int64     `json:"negative"`
	Junk      int64     `json:"junk,omitempty"`     // Actual junk message count (unweighted)
	Rejected  int64     `json:"rejected,omitempty"` // Actual rejected message count (unweighted)
}

// ExportSummary provides per-server message counts in exports
type ExportSummary struct {
	TotalMessages    int64 `json:"total_messages"`
	AcceptedMessages int64 `json:"accepted_messages"`
	RejectedMessages int64 `json:"rejected_messages"`
	JunkMessages     int64 `json:"junk_messages"`
}

// StatsExport is the complete stats export structure
type StatsExport struct {
	Version   string                   `json:"version"`
	Hostname  string                   `json:"hostname"`
	Timestamp time.Time                `json:"timestamp"`
	IPs       map[string]*IPExport     `json:"ips"`
	Domains   map[string]*DomainExport `json:"domains"`
	Summary   *ExportSummary           `json:"summary,omitempty"` // Per-server message counts
}

// ToExport converts IPEntry to IPExport
func (e *IPEntry) ToExport() *IPExport {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var servers []string
	for s := range e.Servers {
		servers = append(servers, s)
	}

	return &IPExport{
		FirstSeen:   e.FirstSeen,
		LastSeen:    e.LastSeen,
		Connections: e.Connections,
		Positive:    e.Positive,
		Negative:    e.Negative,
		IsDenied:    e.IsDenied,
		Servers:     servers,
	}
}

// ToExport converts DomainEntry to DomainExport
func (e *DomainEntry) ToExport() *DomainExport {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return &DomainExport{
		FirstSeen: e.FirstSeen,
		LastSeen:  e.LastSeen,
		Messages:  e.Messages,
		Positive:  e.Positive,
		Negative:  e.Negative,
		Junk:      e.Junk,
		Rejected:  e.Rejected,
	}
}

// FromExport updates IPEntry from IPExport (used in merging)
func (e *IPEntry) FromExport(export *IPExport) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.FirstSeen = export.FirstSeen
	e.LastSeen = export.LastSeen
	e.Connections = export.Connections
	e.Positive = export.Positive
	e.Negative = export.Negative
	e.IsDenied = export.IsDenied
	if len(export.Servers) > 0 {
		e.Servers = make(map[string]struct{}, len(export.Servers))
		for _, s := range export.Servers {
			e.Servers[s] = struct{}{}
		}
	}
}

// FromExport updates DomainEntry from DomainExport (used in merging)
func (e *DomainEntry) FromExport(export *DomainExport) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.FirstSeen = export.FirstSeen
	e.LastSeen = export.LastSeen
	e.Messages = export.Messages
	e.Positive = export.Positive
	e.Negative = export.Negative
	e.Junk = export.Junk
	e.Rejected = export.Rejected
}

// ServerDomainStats tracks per-domain message counts within a single server
type ServerDomainStats struct {
	Messages   int64   `json:"messages"`
	Accepted   int64   `json:"accepted"`
	Rejected   int64   `json:"rejected"`
	Junk       int64   `json:"junk"`
	Reputation float64 `json:"reputation"` // Global reputation (from shared DomainEntry)
}

// ServerSummary provides per-server message statistics
type ServerSummary struct {
	Hostname          string                        `json:"hostname"`
	TotalMessages     int64                         `json:"total_messages"`
	AcceptedMessages  int64                         `json:"accepted_messages"`
	RejectedMessages  int64                         `json:"rejected_messages"`
	JunkMessages      int64                         `json:"junk_messages"`
	ActiveConnections int64                         `json:"active_connections"` // Active SMTP connections for this server
	LastUpdated       time.Time                     `json:"last_updated"`
	Domains           map[string]*ServerDomainStats `json:"domains,omitempty"`           // Sender (FROM) domains
	RecipientDomains  map[string]*ServerDomainStats `json:"recipient_domains,omitempty"` // Recipient (TO) domains
}

// StatsSnapshot is a complete snapshot of stats for API responses
type StatsSnapshot struct {
	IPs     map[string]*IPExport      `json:"ips"`
	Domains map[string]*DomainExport  `json:"domains"`
	Summary StatsSummary              `json:"summary"`
	Servers map[string]*ServerSummary `json:"servers,omitempty"` // Per-server breakdown
}

// StatsSummary provides aggregated statistics
type StatsSummary struct {
	TotalIPs          int   `json:"total_ips"`
	TotalDomains      int   `json:"total_domains"`
	BlockedIPs        int   `json:"blocked_ips"`
	ActiveConnections int64 `json:"active_connections"` // Current active SMTP connections across all servers
	TotalMessages     int64 `json:"total_messages"`
	AcceptedMessages  int64 `json:"accepted_messages"`
	RejectedMessages  int64 `json:"rejected_messages"`
	JunkMessages      int64 `json:"junk_messages"`
	EventsProcessed   int64 `json:"events_processed"`
	EventsDropped     int64 `json:"events_dropped"`
}

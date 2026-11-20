package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"migadu/mizu/pkg/concurrency"
	"migadu/mizu/pkg/health"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const shardCount = 32

type connectionShard struct {
	mu            sync.RWMutex
	ipConnections map[string]int
	leases        map[string][]*ConnLease // per IP, oldest first; len == ipConnections[ip]
}

// ConnLease is one connection slot handed out by ConnectionTracker.Acquire.
//
// A slot has an identity so that it can be given back exactly once. The reaper
// force-releases slots older than MaxConnectionDuration; when the connection
// that owned such a slot finally closes, its Release must be a no-op. With
// address-keyed counters alone that second release took the slot of some
// other, still-open connection, and the counters drifted below reality.
type ConnLease struct {
	ct         *ConnectionTracker
	host       string
	acquiredAt time.Time
	released   bool // guarded by the shard mutex of host
}

// Release gives the slot back. It is idempotent, and a no-op for a lease the
// reaper has already taken. Safe to call on a nil lease.
func (l *ConnLease) Release() {
	if l == nil {
		return
	}
	shard := l.ct.getShard(l.host)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	l.ct.releaseLocked(shard, l)
}

// releaseLocked removes one lease and its counts. The shard mutex must be held.
func (ct *ConnectionTracker) releaseLocked(shard *connectionShard, l *ConnLease) {
	if l.released {
		return
	}
	l.released = true

	leases := shard.leases[l.host]
	for i, candidate := range leases {
		if candidate == l {
			leases = append(leases[:i:i], leases[i+1:]...)
			break
		}
	}

	ct.totalConnections.Add(-1)
	ct.generation.Add(1)

	if len(leases) == 0 {
		// Clean up map entries to prevent memory leak
		delete(shard.leases, l.host)
		delete(shard.ipConnections, l.host)
		return
	}
	shard.leases[l.host] = leases
	shard.ipConnections[l.host] = len(leases)
}

// ConnectionTracker tracks active connections globally and per-IP to enforce limits.
// It provides thread-safe operations for tracking and releasing connections.
//
// It uses sharding (32 shards) to minimize lock contention, especially during
// high-concurrency scenarios or when GetStats() is called frequently (e.g. by gossip).
//
// When MaxConnectionDuration is set (> 0), a background reaper goroutine
// periodically scans for connections that have exceeded the maximum duration
// and force-releases them. This prevents connection count leaks.
type ConnectionTracker struct {
	name                  string        // Health checker name (empty = default "connection_tracker")
	serverName            string        // Config server name (e.g., "mx-primary", "mx-submission")
	maxConnections        int           // Maximum total concurrent connections (0 = unlimited)
	maxConnectionsPerIP   int           // Maximum concurrent connections per IP (0 = unlimited)
	maxConnectionDuration time.Duration // Maximum duration before a connection is force-released (0 = disabled)
	totalConnections      atomic.Int32  // Current total number of connections (atomic for lock-free reads)

	// Sharded storage for connections to reduce lock contention
	shards [shardCount]*connectionShard

	// Reaper stats (how many connections were force-released)
	totalReaped atomic.Uint64

	// Generation counter for change detection (to optimize gossip)
	generation atomic.Uint64

	// Lifecycle
	logger *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewConnectionTracker creates a new connection tracker with the specified limits.
// Set maxConnections to 0 for unlimited total connections.
// Set maxConnectionsPerIP to 0 for unlimited connections per IP.
// Set maxConnectionDuration to 0 to disable the reaper (not recommended in production).
func NewConnectionTracker(maxConnections, maxConnectionsPerIP int, maxConnectionDuration time.Duration, logger *slog.Logger) *ConnectionTracker {
	ctx, cancel := context.WithCancel(context.Background())
	ct := &ConnectionTracker{
		maxConnections:        maxConnections,
		maxConnectionsPerIP:   maxConnectionsPerIP,
		maxConnectionDuration: maxConnectionDuration,
		logger:                logger,
		ctx:                   ctx,
		cancel:                cancel,
	}

	// Initialize shards
	for i := 0; i < shardCount; i++ {
		ct.shards[i] = &connectionShard{
			ipConnections: make(map[string]int),
			leases:        make(map[string][]*ConnLease),
		}
	}

	return ct
}

// getShard returns the shard for a given IP address
func (ct *ConnectionTracker) getShard(ip string) *connectionShard {
	var h uint32 = 5381
	for i := 0; i < len(ip); i++ {
		h = ((h << 5) + h) + uint32(ip[i])
	}
	return ct.shards[h%shardCount]
}

// Start begins the background reaper goroutine (if MaxConnectionDuration > 0).
// Must be called after NewConnectionTracker. Safe to call even if reaping is disabled.
func (ct *ConnectionTracker) Start() {
	if ct.maxConnectionDuration <= 0 {
		return
	}

	// Reap interval: half the max duration, capped at 30s for faster leak detection
	interval := ct.maxConnectionDuration / 2
	if interval < 1*time.Millisecond {
		interval = 1 * time.Millisecond
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}

	ct.wg.Add(1)
	concurrency.SafeGoWithWg(ct.logger, "connection-tracker-reaper", &ct.wg, func() {
		ct.reaperLoop(interval)
	})

	if ct.logger != nil {
		ct.logger.Info("Connection reaper started",
			"max_connection_duration", ct.maxConnectionDuration,
			"reap_interval", interval)
	}
}

// Stop gracefully shuts down the reaper goroutine.
func (ct *ConnectionTracker) Stop() {
	ct.cancel()
	ct.wg.Wait()
}

// reaperLoop periodically checks for and force-releases stale connections.
func (ct *ConnectionTracker) reaperLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ct.ctx.Done():
			return
		case <-ticker.C:
			reaped := ct.reapExpired()
			if reaped > 0 && ct.logger != nil {
				ct.logger.Warn("Reaped stale connections",
					"reaped", reaped,
					"max_duration", ct.maxConnectionDuration,
					"total_connections", ct.getTotalConnections())
			}
		}
	}
}

// reapExpired scans all tracked connections and force-releases any that exceed
// MaxConnectionDuration. Returns the number of connections reaped.
func (ct *ConnectionTracker) reapExpired() int {
	if ct.maxConnectionDuration <= 0 {
		return 0
	}

	now := time.Now()
	cutoff := now.Add(-ct.maxConnectionDuration)
	reaped := 0

	// Iterate over all shards
	for i := 0; i < shardCount; i++ {
		shard := ct.shards[i]
		shard.mu.Lock()

		for ip, leases := range shard.leases {
			// Leases are ordered oldest-first, so the expired ones are a prefix.
			var expired []*ConnLease
			for _, l := range leases {
				if !l.acquiredAt.Before(cutoff) {
					break // All subsequent are newer
				}
				expired = append(expired, l)
			}
			if len(expired) == 0 {
				continue
			}

			if ct.logger != nil {
				ct.logger.Warn("Force-releasing stale connections for IP",
					"ip", ip,
					"expired", len(expired),
					"remaining", len(leases)-len(expired),
					"oldest", expired[0].acquiredAt.Format(time.RFC3339))
			}

			// Marking each lease released is what makes the owner's eventual
			// Release a no-op instead of a second decrement.
			for _, l := range expired {
				ct.releaseLocked(shard, l)
			}
			reaped += len(expired)
		}
		shard.mu.Unlock()
	}

	ct.totalReaped.Add(uint64(reaped))
	return reaped
}

// getTotalConnections returns total connections (for logging, lock-free).
func (ct *ConnectionTracker) getTotalConnections() int {
	return int(ct.totalConnections.Load())
}

// Acquire attempts to acquire a connection slot for the given remote address
// and returns the lease that owns it. Release the lease when the connection
// ends.
func (ct *ConnectionTracker) Acquire(remoteAddr string) (*ConnLease, error) {
	// Extract IP from address (format: "IP:port" or "[IPv6]:port")
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// If no port, assume it's just an IP
		host = remoteAddr
	}
	// Per-IP limits key IPv6 on the /64: one allocation is 2^64 addresses,
	// each of which would otherwise get its own budget.
	host = bucketIP(host)

	// Check global connection limit (lock-free check first)
	if ct.maxConnections > 0 && int(ct.totalConnections.Load()) >= ct.maxConnections {
		return nil, fmt.Errorf("maximum total connections reached (%d)", ct.maxConnections)
	}

	shard := ct.getShard(host)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	// The global limit is not re-checked under the shard lock: totalConnections
	// is atomic, so concurrent acquires on different shards can overshoot it
	// slightly. Strict enforcement would need a global lock, defeating sharding.

	// Check per-IP connection limit
	if ct.maxConnectionsPerIP > 0 {
		currentIPConns := shard.ipConnections[host]
		if currentIPConns >= ct.maxConnectionsPerIP {
			return nil, fmt.Errorf("maximum connections per IP reached (%d)", ct.maxConnectionsPerIP)
		}
	}

	// Acquire connection slot
	lease := &ConnLease{ct: ct, host: host, acquiredAt: time.Now()}
	ct.totalConnections.Add(1)
	ct.generation.Add(1)
	shard.leases[host] = append(shard.leases[host], lease)
	shard.ipConnections[host] = len(shard.leases[host])

	return lease, nil
}

// GetStats returns current connection statistics.
// Returns total connections, number of unique IPs, and per-IP breakdown.
// Note: This iterates over all shards, so it's more expensive than GetCountForIP.
func (ct *ConnectionTracker) GetStats() (total int, uniqueIPs int, perIP map[string]int) {
	// Estimate size to avoid reallocations
	estimatedSize := int(ct.totalConnections.Load())
	if estimatedSize < 0 {
		estimatedSize = 0
	}
	perIP = make(map[string]int, estimatedSize)

	// Iterate over all shards
	for i := 0; i < shardCount; i++ {
		shard := ct.shards[i]
		shard.mu.RLock()
		for ip, count := range shard.ipConnections {
			if count > 0 {
				perIP[ip] = count
			}
		}
		shard.mu.RUnlock()
	}

	return int(ct.totalConnections.Load()), len(perIP), perIP
}

// GetTotalCount returns the current total connection count (lock-free).
// This is safe to call from hot paths without causing RWMutex contention.
func (ct *ConnectionTracker) GetTotalCount() int {
	return int(ct.totalConnections.Load())
}

// GetCountForIP returns the current connection count for a specific IP.
// This is more efficient than GetStats() when you only need one IP's count.
func (ct *ConnectionTracker) GetCountForIP(ip string) int {
	ip = bucketIP(ip)
	shard := ct.getShard(ip)
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	return shard.ipConnections[ip]
}

// GetLimits returns the configured connection limits.
func (ct *ConnectionTracker) GetLimits() (maxTotal, maxPerIP int) {
	// These are immutable after creation, so no lock needed
	return ct.maxConnections, ct.maxConnectionsPerIP
}

// GetGeneration returns the current generation counter.
// This changes whenever a connection is added or removed.
func (ct *ConnectionTracker) GetGeneration() uint64 {
	return ct.generation.Load()
}

// SetName sets a custom health checker name (e.g. "connection_tracker:mx-primary").
func (ct *ConnectionTracker) SetName(name string) {
	ct.name = name
}

// Name returns the component name for health checks.
func (ct *ConnectionTracker) Name() string {
	if ct.name != "" {
		return ct.name
	}
	return "connection_tracker"
}

// SetServerName sets the config server name for this connection tracker.
// This is used for per-server statistics tracking. Safe to call after creation.
func (ct *ConnectionTracker) SetServerName(serverName string) {
	ct.serverName = serverName
}

// GetServerName returns the config server name (implements stats.ConnectionTracker interface).
// This is lock-free and safe for concurrent use.
func (ct *ConnectionTracker) GetServerName() string {
	return ct.serverName
}

// CheckHealth returns the health status of the connection tracker.
func (ct *ConnectionTracker) CheckHealth() health.ComponentStatus {
	total, uniqueIPs, perIP := ct.GetStats()
	maxTotal, maxPerIP := ct.GetLimits()

	// Calculate utilization percentages
	var totalUtilization float64
	if maxTotal > 0 {
		totalUtilization = float64(total) / float64(maxTotal) * 100
	}

	// Find the IP with the highest connection count
	var maxIPConns int
	var maxIPAddr string
	for ip, count := range perIP {
		if count > maxIPConns {
			maxIPConns = count
			maxIPAddr = ip
		}
	}

	var perIPUtilization float64
	if maxPerIP > 0 && maxIPConns > 0 {
		perIPUtilization = float64(maxIPConns) / float64(maxPerIP) * 100
	}

	status := "healthy"
	if maxTotal > 0 && totalUtilization >= 90 {
		status = "degraded"
	}
	if maxTotal > 0 && totalUtilization >= 100 {
		status = "unhealthy"
	}

	details := map[string]interface{}{
		"total_connections":          total,
		"unique_ips":                 uniqueIPs,
		"max_total_connections":      maxTotal,
		"max_connections_per_ip":     maxPerIP,
		"max_connection_duration":    ct.maxConnectionDuration.String(),
		"total_utilization_pct":      fmt.Sprintf("%.1f", totalUtilization),
		"highest_ip_connections":     maxIPConns,
		"highest_ip_address":         maxIPAddr,
		"highest_ip_utilization_pct": fmt.Sprintf("%.1f", perIPUtilization),
		"total_reaped":               ct.totalReaped.Load(),
	}

	return health.ComponentStatus{
		Status:  status,
		Details: details,
	}
}

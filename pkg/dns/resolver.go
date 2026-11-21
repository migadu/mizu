package dns

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"migadu/mizu/pkg/concurrency"
	"migadu/mizu/pkg/metrics"
)

// Bounds on the response cache. Keys and values are both chosen by whoever
// sends us mail (DKIM selectors, SPF includes, HELO names, and the contents of
// their zones), so the cache needs a hard ceiling.
const (
	// maxCacheEntries caps the number of cached responses.
	maxCacheEntries = 50000
	// maxCachedAnswerBytes caps the size of one cached response. Larger answers
	// are still returned to the caller, just not retained.
	maxCachedAnswerBytes = 16 * 1024
)

// cacheEntry represents a cached DNS response
type cacheEntry struct {
	addrs     []string
	expiresAt time.Time
}

// ResilientResolver provides DNS resolution with round-robin load balancing,
// automatic failover across multiple DNS servers, and application-level caching.
type ResilientResolver struct {
	servers  []string               // List of DNS servers
	timeout  time.Duration          // Timeout for each DNS query
	index    atomic.Uint32          // Current server index for round-robin
	mu       sync.RWMutex           // Protects servers list
	cache    map[string]*cacheEntry // DNS response cache
	cacheMu  sync.RWMutex           // Protects cache
	cacheTTL time.Duration          // How long to cache responses
	metrics  *metrics.Metrics       // Prometheus metrics (optional)
	logger   *slog.Logger           // Logger for SafeGo
}

// NewResilientResolver creates a new resilient DNS resolver with caching.
// If servers is empty or nil, returns the system default resolver.
// Returns both the net.Resolver and the ResilientResolver for cache access.
func NewResilientResolver(servers []string, timeout time.Duration, cacheTTL time.Duration) (*net.Resolver, *ResilientResolver) {
	if len(servers) == 0 {
		return net.DefaultResolver, nil
	}

	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute // Default cache TTL
	}

	// Create a logger for the resolver
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	rr := &ResilientResolver{
		servers:  servers,
		timeout:  timeout,
		cache:    make(map[string]*cacheEntry),
		cacheTTL: cacheTTL,
		metrics:  nil, // Will be set via SetMetrics()
		logger:   logger,
	}

	// Start cache cleanup goroutine
	concurrency.SafeGo(logger, "dns-resolver-cache-cleanup", rr.cleanupExpiredCache)

	resolver := &net.Resolver{
		PreferGo: true,
		Dial:     rr.dial,
	}

	return resolver, rr
}

// dial implements the Dial function for net.Resolver with round-robin and failover.
// It tries each DNS server in round-robin order until one succeeds or all fail.
// Supports both UDP and TCP protocols with automatic TCP fallback for truncated responses.
func (r *ResilientResolver) dial(ctx context.Context, network, address string) (net.Conn, error) {
	r.mu.RLock()
	serverCount := len(r.servers)
	servers := make([]string, serverCount)
	copy(servers, r.servers)
	r.mu.RUnlock()

	if serverCount == 0 {
		return nil, fmt.Errorf("no DNS servers configured")
	}

	// Get starting index for round-robin (atomic increment)
	startIdx := int(r.index.Add(1) % uint32(serverCount))

	var lastErr error

	// Try each server once in round-robin order
	for i := 0; i < serverCount; i++ {
		// Calculate current server index with wraparound
		idx := (startIdx + i) % serverCount
		server := servers[idx]

		// Create dialer with timeout
		d := net.Dialer{
			Timeout: r.timeout,
		}

		// Determine protocol - respect caller's preference (UDP or TCP)
		// Go's DNS resolver will retry with TCP if UDP response is truncated
		protocol := network
		if protocol == "" {
			protocol = "udp" // Default to UDP
		}

		// Attempt connection
		conn, err := d.DialContext(ctx, protocol, server)
		if err == nil {
			return conn, nil
		}

		lastErr = err
	}

	// All servers failed
	return nil, fmt.Errorf("all DNS servers failed, last error: %w", lastErr)
}

// GetServers returns a copy of the current server list.
func (r *ResilientResolver) GetServers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	servers := make([]string, len(r.servers))
	copy(servers, r.servers)
	return servers
}

// UpdateServers updates the list of DNS servers.
// This can be used for dynamic DNS server configuration.
func (r *ResilientResolver) UpdateServers(servers []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.servers = make([]string, len(servers))
	copy(r.servers, servers)
}

// SetMetrics sets the metrics instance for DNS cache monitoring
func (r *ResilientResolver) SetMetrics(m *metrics.Metrics) {
	r.metrics = m
}

// getCached retrieves a cached DNS response if it exists and hasn't expired
func (r *ResilientResolver) getCached(key string) ([]string, bool) {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()

	entry, exists := r.cache[key]
	if !exists {
		return nil, false
	}

	// Check if entry has expired
	if time.Now().After(entry.expiresAt) {
		return nil, false
	}

	// Return copy to prevent external modification
	addrs := make([]string, len(entry.addrs))
	copy(addrs, entry.addrs)
	return addrs, true
}

// putCache stores a DNS response in the cache
func (r *ResilientResolver) putCache(key string, addrs []string) {
	size := 0
	for _, a := range addrs {
		size += len(a)
	}
	if size > maxCachedAnswerBytes {
		return // Too large to retain; the caller already has the answer
	}

	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	if _, exists := r.cache[key]; !exists && len(r.cache) >= maxCacheEntries {
		r.evictLocked()
	}

	// Store copy to prevent external modification
	cachedAddrs := make([]string, len(addrs))
	copy(cachedAddrs, addrs)

	r.cache[key] = &cacheEntry{
		addrs:     cachedAddrs,
		expiresAt: time.Now().Add(r.cacheTTL),
	}
}

// evictLocked makes room in a full cache: expired entries go first, and if that
// frees nothing, a tenth of the cache is dropped. Go's map iteration order is
// randomized, so this is random eviction - good enough for a cache whose
// entries are cheap to refetch, and it cannot be steered by the sender.
// cacheMu must be held.
func (r *ResilientResolver) evictLocked() {
	now := time.Now()
	for key, entry := range r.cache {
		if now.After(entry.expiresAt) {
			delete(r.cache, key)
		}
	}
	if len(r.cache) < maxCacheEntries {
		return
	}
	drop := maxCacheEntries / 10
	for key := range r.cache {
		if drop == 0 {
			break
		}
		delete(r.cache, key)
		drop--
	}
}

// cleanupExpiredCache periodically removes expired entries from the cache
func (r *ResilientResolver) cleanupExpiredCache() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		r.cacheMu.Lock()
		now := time.Now()
		for key, entry := range r.cache {
			if now.After(entry.expiresAt) {
				delete(r.cache, key)
			}
		}
		r.cacheMu.Unlock()
	}
}

// GetCacheStats returns cache statistics for monitoring
func (r *ResilientResolver) GetCacheStats() (size int, ttl time.Duration) {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()
	return len(r.cache), r.cacheTTL
}

// FlushCache clears all cached DNS responses
func (r *ResilientResolver) FlushCache() {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	r.cache = make(map[string]*cacheEntry)
}

package smtp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"migadu/mizu/pkg/config"
)

// RateLimiterCluster interface allows for testing and abstraction
type RateLimiterCluster interface {
	BroadcastRateLimit(data []byte) error
	RegisterRateLimitHandler(handler func(data []byte))
}

// RateLimiter implements a multi-dimensional sliding window rate limiter with memberlist gossip sync.
// It tracks connection attempts across multiple configurable dimensions (e.g., IP, FROM, TO, combinations).
type RateLimiter struct {
	mu             sync.RWMutex
	enabled        bool
	dimensions     []dimensionTracker           // Configured rate limit dimensions
	windows        map[string]*connectionWindow // composite key -> connection window with local/peer counts
	gossipEnabled  bool
	gossipInterval time.Duration
	logger         *zap.Logger
	cluster        RateLimiterCluster // Memberlist cluster for gossip
	ctx            context.Context
	cancel         context.CancelFunc
}

// dimensionTracker tracks a single rate limit dimension
type dimensionTracker struct {
	name   string        // Human-readable name (e.g., "per_ip", "per_sender")
	keys   []string      // Dimension keys to combine (e.g., ["IP"], ["FROM"], ["IP", "FROM"])
	limit  int           // Max connections per window
	window time.Duration // Time window for rate limiting
}

// connectionWindow tracks connection attempts for a single composite key using a sliding window
// Uses counter-based approach to avoid timestamp accumulation bugs from gossip
type connectionWindow struct {
	localCount  int       // Connections from this node
	peerCount   int       // Estimated connections from peers (from gossip)
	windowStart time.Time // Start of current window
	lastUpdate  time.Time // Last time this window was updated
	lastCleanup time.Time // Last time old windows were cleaned up
}

// RateLimitData represents rate limit data that can be gossiped across the cluster
type RateLimitData struct {
	CompositeKey string    `json:"composite_key"` // e.g., "IP:1.2.3.4" or "FROM:user@example.com,TO:recipient@example.com"
	Count        int       `json:"count"`         // Connection count in current window
	WindowStart  time.Time `json:"window_start"`  // Start of this node's window
	ReportedAt   time.Time `json:"reported_at"`   // When this data was reported
}

// SessionContext holds all the information needed for rate limiting checks
type SessionContext struct {
	RemoteAddr string   // Remote address (IP:port)
	From       string   // MAIL FROM address
	To         []string // RCPT TO addresses
}

// NewRateLimiter creates a new multi-dimensional rate limiter with memberlist gossip
func NewRateLimiter(rlConfig config.RateLimitConfig, cluster RateLimiterCluster, logger *zap.Logger) *RateLimiter {
	if logger == nil {
		logger = zap.NewNop()
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Convert config dimensions to internal trackers
	dimensions := make([]dimensionTracker, 0, len(rlConfig.Dimensions))
	for _, d := range rlConfig.Dimensions {
		if d.Limit > 0 && len(d.Keys) > 0 {
			dimensions = append(dimensions, dimensionTracker{
				name:   d.Name,
				keys:   d.Keys,
				limit:  d.Limit,
				window: time.Duration(d.WindowSeconds) * time.Second,
			})
		}
	}

	rl := &RateLimiter{
		enabled:        rlConfig.Enabled,
		dimensions:     dimensions,
		windows:        make(map[string]*connectionWindow),
		gossipEnabled:  rlConfig.GossipEnabled,
		gossipInterval: time.Duration(rlConfig.GossipIntervalSeconds) * time.Second,
		logger:         logger,
		cluster:        cluster,
		ctx:            ctx,
		cancel:         cancel,
	}

	// Register handler for rate limit gossip from peers
	if rlConfig.GossipEnabled && cluster != nil {
		cluster.RegisterRateLimitHandler(rl.handleGossipMessage)
		go rl.gossipLoop()
	}

	// Start cleanup loop
	go rl.cleanupLoop()

	return rl
}

// CheckRateLimit checks if a session has exceeded any configured rate limits
// Returns nil if allowed, error with dimension name if rate limit exceeded
func (rl *RateLimiter) CheckRateLimit(sessionCtx SessionContext) error {
	if !rl.enabled || len(rl.dimensions) == 0 {
		return nil // Rate limiting disabled
	}

	now := time.Now()

	// Check each dimension independently - any violation rejects the connection
	for _, dim := range rl.dimensions {
		compositeKey := rl.buildCompositeKey(dim.keys, sessionCtx)
		if compositeKey == "" {
			// Skip this dimension if we can't build a key (e.g., FROM dimension but no MAIL FROM yet)
			continue
		}

		rl.mu.Lock()

		// Get or create window for this composite key
		window, exists := rl.windows[compositeKey]
		if !exists {
			window = &connectionWindow{
				localCount:  0,
				peerCount:   0,
				windowStart: now,
				lastUpdate:  now,
				lastCleanup: now,
			}
			rl.windows[compositeKey] = window
		}

		// Reset window if it has expired
		if now.Sub(window.windowStart) > dim.window {
			window.localCount = 0
			window.peerCount = 0
			window.windowStart = now
			window.lastUpdate = now
		}

		// Check if adding this connection would exceed the limit (local + peer counts)
		totalCount := window.localCount + window.peerCount
		if totalCount >= dim.limit {
			rl.mu.Unlock()
			rl.logger.Warn("Rate limit exceeded",
				zap.String("dimension", dim.name),
				zap.String("composite_key", compositeKey),
				zap.Int("local_count", window.localCount),
				zap.Int("peer_count", window.peerCount),
				zap.Int("total", totalCount),
				zap.Int("limit", dim.limit),
				zap.Duration("window", dim.window))
			return fmt.Errorf("rate limit exceeded for %s: %d/%d connections in %v", dim.name, totalCount, dim.limit, dim.window)
		}

		// Increment local count for this connection
		window.localCount++
		window.lastUpdate = now
		rl.mu.Unlock()
	}

	return nil
}

// buildCompositeKey builds a composite key from the specified dimension keys and session context
// Returns empty string if any required key is not available
func (rl *RateLimiter) buildCompositeKey(keys []string, sessionCtx SessionContext) string {
	parts := make([]string, 0, len(keys))

	for _, key := range keys {
		switch strings.ToUpper(key) {
		case "IP":
			ip := extractIP(sessionCtx.RemoteAddr)
			if ip == "" {
				return "" // Can't build key without IP
			}
			parts = append(parts, fmt.Sprintf("IP:%s", ip))

		case "FROM":
			if sessionCtx.From == "" {
				return "" // Can't build key without FROM
			}
			parts = append(parts, fmt.Sprintf("FROM:%s", strings.ToLower(sessionCtx.From)))

		case "FROM_DOMAIN":
			domain := extractDomain(sessionCtx.From)
			if domain == "" {
				return "" // Can't build key without FROM domain
			}
			parts = append(parts, fmt.Sprintf("FROM_DOMAIN:%s", strings.ToLower(domain)))

		case "TO":
			if len(sessionCtx.To) == 0 {
				return "" // Can't build key without TO
			}
			// For multiple recipients, use the first one (or could iterate per-recipient)
			parts = append(parts, fmt.Sprintf("TO:%s", strings.ToLower(sessionCtx.To[0])))

		case "TO_DOMAIN":
			if len(sessionCtx.To) == 0 {
				return "" // Can't build key without TO
			}
			domain := extractDomain(sessionCtx.To[0])
			if domain == "" {
				return "" // Can't build key without TO domain
			}
			parts = append(parts, fmt.Sprintf("TO_DOMAIN:%s", strings.ToLower(domain)))

		default:
			rl.logger.Warn("Unknown rate limit dimension key", zap.String("key", key))
			return "" // Unknown key type
		}
	}

	if len(parts) == 0 {
		return ""
	}

	// Sort parts to ensure consistent key regardless of order in config
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// extractIP extracts the IP address from a remote address string (removes port)
func extractIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr // Already just an IP
	}
	return host
}

// extractDomain extracts the domain part from an email address
func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// gossipLoop periodically sends rate limit data to cluster peers
func (rl *RateLimiter) gossipLoop() {
	ticker := time.NewTicker(rl.gossipInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.ctx.Done():
			return
		case <-ticker.C:
			rl.sendGossip()
		}
	}
}

// sendGossip broadcasts current rate limit state via memberlist
func (rl *RateLimiter) sendGossip() {
	rl.mu.RLock()

	// Collect data for all composite keys (only send non-zero local counts)
	now := time.Now()
	data := make([]RateLimitData, 0, len(rl.windows))

	for compositeKey, window := range rl.windows {
		if window.localCount > 0 {
			data = append(data, RateLimitData{
				CompositeKey: compositeKey,
				Count:        window.localCount,
				WindowStart:  window.windowStart,
				ReportedAt:   now,
			})
		}
	}

	rl.mu.RUnlock()

	if len(data) == 0 {
		return // Nothing to gossip
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		rl.logger.Error("Failed to marshal rate limit data", zap.Error(err))
		return
	}

	if err := rl.cluster.BroadcastRateLimit(jsonData); err != nil {
		rl.logger.Debug("Failed to broadcast rate limit data", zap.Error(err))
	}
}

// handleGossipMessage processes rate limit gossip messages from memberlist
func (rl *RateLimiter) handleGossipMessage(data []byte) {
	var rateLimitData []RateLimitData
	if err := json.Unmarshal(data, &rateLimitData); err != nil {
		rl.logger.Warn("Failed to unmarshal rate limit gossip data", zap.Error(err))
		return
	}

	rl.MergeGossipData(rateLimitData)
}

// MergeGossipData merges received gossip data into local state
// Uses sum of peer counts to estimate cluster-wide rate limit consumption
func (rl *RateLimiter) MergeGossipData(data []RateLimitData) {
	if !rl.gossipEnabled {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	maxWindow := rl.getMaxWindow()

	// First, reset all peer counts (we'll rebuild from gossip)
	for _, window := range rl.windows {
		window.peerCount = 0
	}

	// Aggregate peer counts from gossip
	for _, item := range data {
		// Skip stale data (older than any configured window)
		if now.Sub(item.ReportedAt) > maxWindow {
			continue
		}

		// Get or create window for this composite key
		window, exists := rl.windows[item.CompositeKey]
		if !exists {
			window = &connectionWindow{
				localCount:  0,
				peerCount:   0,
				windowStart: item.WindowStart,
				lastUpdate:  now,
				lastCleanup: now,
			}
			rl.windows[item.CompositeKey] = window
		}

		// Add peer's count to our peer count (sum across all peers)
		window.peerCount += item.Count
	}
}

// getMaxWindow returns the maximum window duration across all dimensions
func (rl *RateLimiter) getMaxWindow() time.Duration {
	maxWindow := time.Minute
	for _, dim := range rl.dimensions {
		if dim.window > maxWindow {
			maxWindow = dim.window
		}
	}
	return maxWindow
}

// cleanupLoop periodically removes old entries to prevent memory leaks
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-rl.ctx.Done():
			return
		case <-ticker.C:
			rl.cleanup()
		}
	}
}

// cleanup removes old windows that are no longer active
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	maxWindow := rl.getMaxWindow()
	staleThreshold := maxWindow * 2 // Keep windows for 2x max window

	for compositeKey, window := range rl.windows {
		// Remove windows that haven't been updated recently and have no counts
		if window.localCount == 0 && window.peerCount == 0 && now.Sub(window.lastUpdate) > staleThreshold {
			delete(rl.windows, compositeKey)
		}
	}
}

// Shutdown stops the rate limiter's background goroutines
func (rl *RateLimiter) Shutdown() {
	if rl.cancel != nil {
		rl.cancel()
	}
}

// GetStats returns current rate limiter statistics for monitoring
func (rl *RateLimiter) GetStats() map[string]any {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	stats := map[string]any{
		"enabled":         rl.enabled,
		"total_windows":   len(rl.windows),
		"gossip_enabled":  rl.gossipEnabled,
		"dimension_count": len(rl.dimensions),
	}

	// Add per-dimension stats
	dimensions := make([]map[string]any, 0, len(rl.dimensions))
	for _, dim := range rl.dimensions {
		dimensions = append(dimensions, map[string]any{
			"name":   dim.name,
			"keys":   dim.keys,
			"limit":  dim.limit,
			"window": dim.window.String(),
		})
	}
	stats["dimensions"] = dimensions

	return stats
}

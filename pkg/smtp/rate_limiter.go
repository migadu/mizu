package smtp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"migadu/mizu/pkg/config"
)

// RateLimiter implements a multi-dimensional sliding window rate limiter with optional distributed gossip sync.
// It tracks connection attempts across multiple configurable dimensions (e.g., IP, FROM, TO, combinations).
type RateLimiter struct {
	mu             sync.RWMutex
	enabled        bool
	dimensions     []dimensionTracker           // Configured rate limit dimensions
	windows        map[string]*connectionWindow // composite key -> sliding window of connection timestamps
	gossipEnabled  bool
	gossipInterval time.Duration
	logger         *zap.Logger
	peerURLs       []string // Cluster peer URLs for gossip
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
type connectionWindow struct {
	timestamps  []time.Time
	lastCleanup time.Time
}

// RateLimitData represents rate limit data that can be gossiped across the cluster
type RateLimitData struct {
	CompositeKey string    `json:"composite_key"` // e.g., "IP:1.2.3.4" or "FROM:user@example.com,TO:recipient@example.com"
	Connections  int       `json:"connections"`
	WindowStart  time.Time `json:"window_start"`
	ReportedAt   time.Time `json:"reported_at"`
}

// SessionContext holds all the information needed for rate limiting checks
type SessionContext struct {
	RemoteAddr string   // Remote address (IP:port)
	From       string   // MAIL FROM address
	To         []string // RCPT TO addresses
}

// NewRateLimiter creates a new multi-dimensional rate limiter with the specified configuration
func NewRateLimiter(rlConfig config.RateLimitConfig, peerURLs []string, logger *zap.Logger) *RateLimiter {
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
				window: d.Window,
			})
		}
	}

	rl := &RateLimiter{
		enabled:        rlConfig.Enabled,
		dimensions:     dimensions,
		windows:        make(map[string]*connectionWindow),
		gossipEnabled:  rlConfig.GossipEnabled,
		gossipInterval: rlConfig.GossipInterval,
		logger:         logger,
		peerURLs:       peerURLs,
		ctx:            ctx,
		cancel:         cancel,
	}

	// Start gossip loop if enabled
	if rlConfig.GossipEnabled && len(peerURLs) > 0 {
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
				timestamps:  make([]time.Time, 0),
				lastCleanup: now,
			}
			rl.windows[compositeKey] = window
		}

		// Remove timestamps outside the window
		cutoff := now.Add(-dim.window)
		validTimestamps := make([]time.Time, 0, len(window.timestamps))
		for _, ts := range window.timestamps {
			if ts.After(cutoff) {
				validTimestamps = append(validTimestamps, ts)
			}
		}
		window.timestamps = validTimestamps
		window.lastCleanup = now

		// Check if adding this connection would exceed the limit
		currentCount := len(window.timestamps)
		if currentCount >= dim.limit {
			rl.mu.Unlock()
			rl.logger.Warn("Rate limit exceeded",
				zap.String("dimension", dim.name),
				zap.String("composite_key", compositeKey),
				zap.Int("current", currentCount),
				zap.Int("limit", dim.limit),
				zap.Duration("window", dim.window))
			return fmt.Errorf("rate limit exceeded for %s: %d/%d connections in %v", dim.name, currentCount, dim.limit, dim.window)
		}

		// Add this connection to the window
		window.timestamps = append(window.timestamps, now)
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

// sendGossip broadcasts current rate limit state to all peers
func (rl *RateLimiter) sendGossip() {
	rl.mu.RLock()

	// Collect data for all composite keys
	now := time.Now()
	data := make([]RateLimitData, 0, len(rl.windows))

	for compositeKey, window := range rl.windows {
		if len(window.timestamps) > 0 {
			// Find oldest timestamp still in any window
			oldestTimestamp := window.timestamps[0]
			for _, ts := range window.timestamps {
				if ts.Before(oldestTimestamp) {
					oldestTimestamp = ts
				}
			}

			data = append(data, RateLimitData{
				CompositeKey: compositeKey,
				Connections:  len(window.timestamps),
				WindowStart:  oldestTimestamp,
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
		rl.logger.Error("Failed to marshal gossip data", zap.Error(err))
		return
	}

	// Send to all peers in parallel
	for _, peerURL := range rl.peerURLs {
		go rl.sendToPeer(peerURL, jsonData)
	}
}

// sendToPeer sends gossip data to a single peer
func (rl *RateLimiter) sendToPeer(peerURL string, jsonData []byte) {
	url := peerURL + "/api/rate-limit-gossip"

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(jsonData))
	if err != nil {
		rl.logger.Debug("Failed to send rate limit gossip to peer", zap.String("peer", peerURL), zap.Error(err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		rl.logger.Debug("Peer returned non-OK status for rate limit gossip", zap.String("peer", peerURL), zap.Int("status", resp.StatusCode))
	}
}

// HandleGossip processes incoming gossip data from a peer (HTTP handler)
func (rl *RateLimiter) HandleGossip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data []RateLimitData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		rl.logger.Warn("Failed to decode rate limit gossip data", zap.Error(err))
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	rl.MergeGossipData(data)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status": "success",
		"merged": len(data),
	})
}

// MergeGossipData merges received gossip data into local state
func (rl *RateLimiter) MergeGossipData(data []RateLimitData) {
	if !rl.gossipEnabled {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	for _, item := range data {
		// Skip stale data (older than any configured window)
		maxWindow := rl.getMaxWindow()
		if now.Sub(item.ReportedAt) > maxWindow {
			continue
		}

		// Get or create window for this composite key
		window, exists := rl.windows[item.CompositeKey]
		if !exists {
			window = &connectionWindow{
				timestamps:  make([]time.Time, 0, item.Connections),
				lastCleanup: now,
			}
			rl.windows[item.CompositeKey] = window
		}

		// Add timestamps from peer (approximate distribution across window)
		// This is a simplified merge - real timestamps not available from peers
		for i := 0; i < item.Connections; i++ {
			// Distribute timestamps evenly across the window
			offset := time.Duration(i) * (now.Sub(item.WindowStart)) / time.Duration(item.Connections)
			ts := item.WindowStart.Add(offset)

			// Only add if not too old for any dimension
			if now.Sub(ts) <= maxWindow {
				window.timestamps = append(window.timestamps, ts)
			}
		}
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

// cleanup removes old timestamps and empty windows
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	maxWindow := rl.getMaxWindow()
	cutoff := now.Add(-maxWindow * 2) // Keep 2x max window for safety

	for compositeKey, window := range rl.windows {
		// Remove old timestamps
		validTimestamps := make([]time.Time, 0, len(window.timestamps))
		for _, ts := range window.timestamps {
			if ts.After(cutoff) {
				validTimestamps = append(validTimestamps, ts)
			}
		}
		window.timestamps = validTimestamps

		// Remove empty windows
		if len(window.timestamps) == 0 && now.Sub(window.lastCleanup) > maxWindow {
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

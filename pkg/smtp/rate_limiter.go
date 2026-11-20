package smtp

import (
	"io"

	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"log/slog"
	"migadu/mizu/pkg/concurrency"
	"migadu/mizu/pkg/config"
)

// RateLimiterCluster interface allows for testing and abstraction
type RateLimiterCluster interface {
	BroadcastRateLimit(data []byte) error
	RegisterRateLimitHandler(handler func(data []byte))
	// LocalNodeName returns this node's stable name, used to attribute gossiped
	// counts to their source peer so contributions can be summed (not overwritten).
	LocalNodeName() string
}

// maxGossipCount bounds a single peer's reported count for a key. Gossip is
// untrusted; without a cap a malicious/buggy peer could report an enormous
// count to deny a victim key, or overflow the running sum. Any legitimate count
// far exceeds every configured dimension limit well below this ceiling.
const maxGossipCount = 1_000_000

// RateLimiter implements a multi-dimensional sliding window rate limiter with memberlist gossip sync.
// It tracks connection attempts across multiple configurable dimensions (e.g., IP, FROM, TO, combinations).
type RateLimiter struct {
	mu             sync.RWMutex
	enabled        bool
	dimensions     []dimensionTracker           // Configured rate limit dimensions
	windows        map[string]*connectionWindow // composite key -> connection window with local/peer counts
	gossipEnabled  bool
	gossipInterval time.Duration
	// whitelist holds the current exemption set (IPs, domains, senders). It is
	// swapped atomically by the reload loop so CheckRateLimit reads it lock-free.
	whitelist               atomic.Pointer[whitelistSnapshot]
	whitelistSource         *whitelistSource
	whitelistReloadInterval time.Duration
	whitelistFileFP         map[string]string // path -> last-seen fingerprint (reload loop only)
	logger                  *slog.Logger
	cluster                 RateLimiterCluster // Memberlist cluster for gossip
	nodeID                  string             // This node's name (attached to outgoing gossip)
	ctx                     context.Context
	cancel                  context.CancelFunc
}

// dimensionTracker tracks a single rate limit dimension
type dimensionTracker struct {
	name   string         // Human-readable name (e.g., "per_ip", "per_sender")
	keys   []string       // Dimension keys to combine (e.g., ["IP"], ["FROM"], ["IP", "FROM"])
	limit  int            // Max connections per window
	window time.Duration  // Time window for rate limiting
	stage  RateLimitStage // The one stage this dimension is checked and charged at
}

// connectionWindow tracks connection attempts for a single composite key using a sliding window
// Uses counter-based approach to avoid timestamp accumulation bugs from gossip
type connectionWindow struct {
	localCount  int                         // Connections from this node
	peerCount   int                         // Cached sum of peerCounts (cluster-wide estimate)
	peerCounts  map[string]peerContribution // nodeID -> that peer's last reported count
	windowStart time.Time                   // Start of current window
	duration    time.Duration               // Length of the window (its dimension's), zero for a window created from gossip only
	lastUpdate  time.Time                   // Last time this window was updated
	lastCleanup time.Time                   // Last time old windows were cleaned up
}

// peerContribution is a single peer's reported count for a window, retained so
// that per-peer contributions can be summed and aged out independently.
type peerContribution struct {
	count      int
	reportedAt time.Time
}

// RateLimitData represents rate limit data that can be gossiped across the cluster
type RateLimitData struct {
	NodeID       string    `json:"node_id"`       // Source node name (for per-peer attribution)
	CompositeKey string    `json:"composite_key"` // e.g., "per_ip|IP:1.2.3.4"
	Count        int       `json:"count"`         // Connection count in current window
	WindowStart  time.Time `json:"window_start"`  // Start of this node's window
	ReportedAt   time.Time `json:"reported_at"`   // When this data was reported
}

// SessionContext holds all the information needed for rate limiting checks
type SessionContext struct {
	RemoteAddr        string         // Remote address (IP:port)
	From              string         // MAIL FROM address
	To                []string       // The recipient under evaluation, as a single element (TO/TO_DOMAIN key on To[0]); empty before RCPT
	AuthenticatedUser string         // Authenticated username (empty if not authenticated)
	Stage             RateLimitStage // Which SMTP stage is asking; selects the dimensions charged
}

// RateLimitStage is the point in the SMTP dialogue a rate-limit check is made
// at. Each dimension belongs to exactly one stage - the one where the last of
// its keys becomes known - and is checked and charged only there, so the unit
// of a limit follows from its keys:
//
//	IP alone                               -> connections  (StageConnect)
//	FROM / FROM_DOMAIN / AUTHENTICATED_USER -> messages     (StageMail)
//	TO / TO_DOMAIN                         -> recipients   (StageRcpt)
type RateLimitStage int

const (
	StageConnect RateLimitStage = iota // EHLO/HELO: only the peer address is known
	StageMail                          // MAIL FROM accepted: sender and login are known
	StageRcpt                          // RCPT TO: one recipient under evaluation
)

// stageForKeys returns the stage a dimension with these keys is charged at.
func stageForKeys(keys []string) RateLimitStage {
	stage := StageConnect
	for _, key := range keys {
		switch strings.ToUpper(key) {
		case "TO", "TO_DOMAIN":
			return StageRcpt
		case "FROM", "FROM_DOMAIN", "AUTHENTICATED_USER":
			stage = StageMail
		}
	}
	return stage
}

// NewRateLimiter creates a new multi-dimensional rate limiter with memberlist gossip
func NewRateLimiter(rlConfig config.RateLimitConfig, cluster RateLimiterCluster, logger *slog.Logger) *RateLimiter {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
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
				stage:  stageForKeys(d.Keys),
			})
		}
	}

	reloadInterval := time.Duration(rlConfig.WhitelistReloadIntervalSeconds) * time.Second
	if reloadInterval <= 0 {
		reloadInterval = 10 * time.Second
	}

	rl := &RateLimiter{
		enabled:                 rlConfig.Enabled,
		dimensions:              dimensions,
		windows:                 make(map[string]*connectionWindow),
		gossipEnabled:           rlConfig.GossipEnabled,
		gossipInterval:          time.Duration(rlConfig.GossipIntervalSeconds) * time.Second,
		whitelistSource:         newWhitelistSource(rlConfig, logger),
		whitelistReloadInterval: reloadInterval,
		whitelistFileFP:         make(map[string]string),
		logger:                  logger,
		cluster:                 cluster,
		ctx:                     ctx,
		cancel:                  cancel,
	}

	// Build the initial whitelist snapshot and prime file fingerprints so the
	// reload loop only rebuilds on an actual change.
	rl.whitelist.Store(rl.whitelistSource.build())
	for _, path := range rl.whitelistSource.filePaths() {
		rl.whitelistFileFP[path] = fileFingerprint(path)
	}

	// Register handler for rate limit gossip from peers
	if rlConfig.GossipEnabled && cluster != nil {
		rl.nodeID = cluster.LocalNodeName()
		cluster.RegisterRateLimitHandler(rl.handleGossipMessage)
		concurrency.SafeGo(logger, "rate-limiter-gossip", rl.gossipLoop)
	}

	// Start cleanup loop
	concurrency.SafeGo(logger, "rate-limiter-cleanup", rl.cleanupLoop)

	// Watch whitelist files for changes and hot-reload them. Only started when
	// at least one file is configured.
	if len(rl.whitelistSource.filePaths()) > 0 {
		concurrency.SafeGo(logger, "rate-limiter-whitelist-reload", rl.whitelistReloadLoop)
	}

	return rl
}

// whitelistReloadLoop periodically checks the configured whitelist files and
// rebuilds the whitelist snapshot when any of them changes on disk.
func (rl *RateLimiter) whitelistReloadLoop() {
	ticker := time.NewTicker(rl.whitelistReloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.ctx.Done():
			return
		case <-ticker.C:
			if rl.whitelistFilesChanged() {
				rl.whitelist.Store(rl.whitelistSource.build())
				rl.logger.Info("reloaded rate-limit whitelist files")
			}
		}
	}
}

// whitelistFilesChanged reports whether any watched file's fingerprint changed
// since the last check, updating the stored fingerprints. Only the reload loop
// goroutine touches whitelistFileFP, so no locking is needed.
func (rl *RateLimiter) whitelistFilesChanged() bool {
	changed := false
	for _, path := range rl.whitelistSource.filePaths() {
		if fp := fileFingerprint(path); rl.whitelistFileFP[path] != fp {
			rl.whitelistFileFP[path] = fp
			changed = true
		}
	}
	return changed
}

// CheckRateLimit checks if a session has exceeded any configured rate limits
// Returns nil if allowed, error with dimension name if rate limit exceeded
func (rl *RateLimiter) CheckRateLimit(sessionCtx SessionContext) error {
	if !rl.enabled || len(rl.dimensions) == 0 {
		return nil // Rate limiting disabled
	}

	// Skip rate limiting entirely for whitelisted connections (by IP, or by
	// sender email/domain). A match exempts all dimensions.
	snapshot := rl.whitelist.Load()
	if snapshot.matchesIP(extractIP(sessionCtx.RemoteAddr)) {
		return nil // Whitelisted IP
	}
	// A whitelisted sender is only as trustworthy as the MAIL FROM it was
	// matched against. On an authenticated session that address has passed
	// allowed_from, so the exemption covers every dimension. Unauthenticated,
	// MAIL FROM is whatever the client typed: it lifts only the dimensions
	// keyed on the sender (below), never IP or recipient limits - otherwise
	// claiming a whitelisted address is a free pass through all rate limiting.
	senderWhitelisted := snapshot.matchesSender(sessionCtx.From)
	if senderWhitelisted && sessionCtx.AuthenticatedUser != "" {
		return nil // Whitelisted, verified sender
	}

	now := time.Now()

	// Two passes under one lock: first check every dimension that belongs to
	// this stage, then charge them - and only if none refused. Charging as we
	// went meant a client refused by a later dimension had still spent the
	// earlier ones, so an already-blocked client could burn a victim's
	// recipient budget.
	rl.mu.Lock()
	defer rl.mu.Unlock()

	var charged []*connectionWindow
	for _, dim := range rl.dimensions {
		if dim.stage != sessionCtx.Stage {
			continue
		}
		if senderWhitelisted && dimensionKeyedOnSender(dim.keys) {
			continue
		}
		compositeKey := rl.buildCompositeKey(dim.keys, sessionCtx)
		if compositeKey == "" {
			// A key this dimension needs is absent (null sender, no login).
			continue
		}
		// Namespace the window by dimension name so two dimensions that share the
		// same keys (e.g. per-IP-per-minute and per-IP-per-hour) get independent
		// windows instead of colliding and corrupting each other's counts.
		windowKey := dim.name + "|" + compositeKey

		window, exists := rl.windows[windowKey]
		if exists && now.Sub(window.windowStart) > dim.window {
			// Expired: start a fresh window.
			window.localCount = 0
			window.peerCount = 0
			window.peerCounts = nil
			window.windowStart = now
			window.lastUpdate = now
		}

		if exists {
			if totalCount := window.localCount + window.peerCount; totalCount >= dim.limit {
				rl.logger.Warn("Rate limit exceeded",
					"dimension", dim.name,
					"composite_key", compositeKey,
					"local_count", window.localCount,
					"peer_count", window.peerCount,
					"total", totalCount,
					"limit", dim.limit,
					"window", dim.window)
				return fmt.Errorf("rate limit exceeded for %s: %d/%d in %v", dim.name, totalCount, dim.limit, dim.window)
			}
		} else {
			// Created only once the request is known to pass every dimension
			// would be tidier, but an empty window is harmless and cleanup
			// removes it; creating it here keeps a single map lookup.
			window = &connectionWindow{windowStart: now, lastUpdate: now, lastCleanup: now}
			rl.windows[windowKey] = window
		}
		window.duration = dim.window
		charged = append(charged, window)
	}

	for _, window := range charged {
		window.localCount++
		window.lastUpdate = now
	}

	return nil
}

// dimensionKeyedOnSender reports whether a dimension's key includes the
// envelope sender (FROM or FROM_DOMAIN).
func dimensionKeyedOnSender(keys []string) bool {
	for _, key := range keys {
		switch strings.ToUpper(key) {
		case "FROM", "FROM_DOMAIN":
			return true
		}
	}
	return false
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
			// IPv6 is keyed on the /64 (see bucketIP): per-address keys give
			// one host 2^64 budgets.
			parts = append(parts, fmt.Sprintf("IP:%s", bucketIP(ip)))

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
			// Callers pass exactly the recipient being evaluated (see Session.Rcpt).
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

		case "AUTHENTICATED_USER":
			if sessionCtx.AuthenticatedUser == "" {
				return "" // Can't build key without authenticated user
			}
			parts = append(parts, fmt.Sprintf("USER:%s", strings.ToLower(sessionCtx.AuthenticatedUser)))

		default:
			rl.logger.Warn("Unknown rate limit dimension key", "key", key)
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
//
// The domain is whatever follows the LAST "@" - the part mail is routed on -
// minus a trailing dot. Requiring exactly one "@" returned "" for
// `"a@b"@spam.test`, and a dimension with an empty key is skipped: the
// address had no domain limit at all.
func extractDomain(email string) string {
	at := strings.LastIndex(email, "@")
	if at == -1 {
		return ""
	}
	return strings.TrimSuffix(email[at+1:], ".")
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
		// Windows are reset lazily on the next hit, so a key that is not used
		// again keeps its last count indefinitely. Never report such a count:
		// it carries ReportedAt = now, so peers would charge it against the
		// key in every later window.
		if window.duration > 0 && now.Sub(window.windowStart) > window.duration {
			continue
		}
		if window.localCount > 0 {
			data = append(data, RateLimitData{
				NodeID:       rl.nodeID,
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
		rl.logger.Error("Failed to marshal rate limit data", "error", err)
		return
	}

	if err := rl.cluster.BroadcastRateLimit(jsonData); err != nil {
		rl.logger.Debug("Failed to broadcast rate limit data", "error", err)
	}
}

// handleGossipMessage processes rate limit gossip messages from memberlist
func (rl *RateLimiter) handleGossipMessage(data []byte) {
	var rateLimitData []RateLimitData
	if err := json.Unmarshal(data, &rateLimitData); err != nil {
		rl.logger.Warn("Failed to unmarshal rate limit gossip data", "error", err)
		return
	}

	rl.MergeGossipData(rateLimitData)
}

// MergeGossipData merges received gossip data into local state.
//
// Each gossip batch carries one peer's own counts. Contributions are tracked
// per source node (window.peerCounts[nodeID]) and summed, so a batch from peer B
// does not overwrite peer A's contribution — the previous implementation zeroed
// all peer counts and rebuilt from a single batch, collapsing the cluster-wide
// estimate to whichever peer gossiped last. A key that is absent from a peer's
// batch means that peer's count for it is now zero, so the peer's prior entries
// are cleared before the batch is applied.
//
// Gossip is untrusted, so counts are validated: negative counts (which could
// disable limiting) and absurdly large counts (which could deny a victim key or
// overflow the sum) are rejected, and unattributed batches are ignored.
func (rl *RateLimiter) MergeGossipData(data []RateLimitData) {
	if !rl.gossipEnabled {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	maxWindow := rl.getMaxWindow()

	// Identify the peer(s) reporting in this batch so we can replace only their
	// contribution across all windows.
	reportingNodes := make(map[string]bool)
	for _, item := range data {
		if item.NodeID != "" && item.NodeID != rl.nodeID {
			reportingNodes[item.NodeID] = true
		}
	}
	for _, window := range rl.windows {
		for nodeID := range reportingNodes {
			delete(window.peerCounts, nodeID)
		}
	}

	// Apply the reported (and validated) counts, attributed to their source node.
	for _, item := range data {
		if now.Sub(item.ReportedAt) > maxWindow {
			continue // Stale
		}
		if item.NodeID == "" || item.NodeID == rl.nodeID {
			continue // Unattributable, or our own count echoed back
		}
		if item.Count < 0 || item.Count > maxGossipCount {
			rl.logger.Warn("Rejecting out-of-range rate-limit gossip count",
				"composite_key", item.CompositeKey, "count", item.Count, "node", item.NodeID)
			continue
		}

		window, exists := rl.windows[item.CompositeKey]
		if !exists {
			window = &connectionWindow{
				windowStart: item.WindowStart,
				lastUpdate:  now,
				lastCleanup: now,
			}
			rl.windows[item.CompositeKey] = window
		}
		if window.peerCounts == nil {
			window.peerCounts = make(map[string]peerContribution)
		}
		window.peerCounts[item.NodeID] = peerContribution{count: item.Count, reportedAt: item.ReportedAt}
	}

	// Recompute cached peer sums, pruning contributions from peers we haven't
	// heard from within the window.
	for _, window := range rl.windows {
		sum := 0
		for nodeID, pc := range window.peerCounts {
			if now.Sub(pc.reportedAt) > maxWindow {
				delete(window.peerCounts, nodeID)
				continue
			}
			sum += pc.count
		}
		window.peerCount = sum
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

	removed := 0
	for compositeKey, window := range rl.windows {
		// Remove windows that haven't been updated recently and whose counts
		// no longer matter: either zero, or belonging to a window that has
		// run out (counts are only reset lazily, on the next hit - which for
		// a key nobody uses again never comes).
		empty := window.localCount == 0 && window.peerCount == 0
		expired := window.duration > 0 && now.Sub(window.windowStart) > window.duration
		if (empty || expired) && now.Sub(window.lastUpdate) > staleThreshold {
			delete(rl.windows, compositeKey)
			removed++
		}
	}

	// Proactive memory management: if still above threshold, remove oldest windows
	const maxWindows = 100000 // Maximum number of windows to keep in memory
	if len(rl.windows) > maxWindows {
		rl.proactiveEvictWindows(maxWindows)
	}

	if removed > 0 {
		rl.logger.Debug("cleaned up stale rate limit windows",
			"removed", removed,
			"remaining", len(rl.windows))
	}
}

// proactiveEvictWindows evicts oldest windows when memory limit is exceeded
// This prevents unbounded memory growth under attack scenarios
func (rl *RateLimiter) proactiveEvictWindows(targetSize int) {
	// Already holding lock from cleanup()

	toEvict := len(rl.windows) - targetSize + (targetSize / 10) // Evict extra 10% for headroom
	if toEvict <= 0 {
		return
	}

	// Sort windows by last update time (oldest first)
	type windowEntry struct {
		key        string
		lastUpdate time.Time
	}

	entries := make([]windowEntry, 0, len(rl.windows))
	for key, window := range rl.windows {
		entries = append(entries, windowEntry{
			key:        key,
			lastUpdate: window.lastUpdate,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].lastUpdate.Before(entries[j].lastUpdate)
	})

	// Evict oldest entries
	evicted := 0
	for i := 0; i < toEvict && i < len(entries); i++ {
		delete(rl.windows, entries[i].key)
		evicted++
	}

	rl.logger.Warn("proactively evicted rate limit windows to prevent memory exhaustion",
		"evicted", evicted,
		"remaining", len(rl.windows),
		"target", targetSize)
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

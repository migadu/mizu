package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"migadu/mizu/pkg/concurrency"
	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/health"
	"migadu/mizu/pkg/metrics"
)

// AuthRateLimiter implements two-tier authentication rate limiting
// to protect against brute-force attacks
type AuthRateLimiter struct {
	name    string // for health checker identification
	config  config.ServerAuthRateLimitConfig
	logger  *slog.Logger
	metrics *metrics.Metrics

	// Tier 1: IP+username blocking
	blockedIPUsernames map[string]*BlockedIPUsernameInfo
	ipUsernameMu       sync.RWMutex

	// Tier 2: IP-only blocking
	blockedIPs      map[string]*BlockedIPInfo
	ipFailureCounts map[string]*IPFailureInfo
	ipMu            sync.RWMutex

	// Tier 3: subnet blocking (auth_subnet.go)
	subnets      map[string]*SubnetInfo
	subnetMu     sync.RWMutex
	subnetExempt []netip.Prefix

	// Recent successful logins, exempted from subnet blocks
	goodIPs map[string]time.Time
	goodMu  sync.RWMutex

	// Username tracking (statistics only)
	usernameFailureCounts map[string]*UsernameFailureInfo
	usernameMu            sync.RWMutex

	// Cluster integration
	clusterLimiter *ClusterAuthRateLimiter

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc

	// Parsed durations (from string config)
	ipUsernameBlockDuration  time.Duration
	ipUsernameWindowDuration time.Duration
	ipBlockDuration          time.Duration
	ipWindowDuration         time.Duration
	subnetBlockDuration      time.Duration
	subnetWindowDuration     time.Duration
	successExemptDuration    time.Duration
	usernameWindowDuration   time.Duration
	initialDelay             time.Duration
	maxDelay                 time.Duration
	cacheCleanupInterval     time.Duration
}

// BlockedIPUsernameInfo tracks a blocked IP+username combination
type BlockedIPUsernameInfo struct {
	IP           string
	Username     string
	BlockedUntil time.Time
	FailureCount int
	FirstFailure time.Time
}

// BlockedIPInfo tracks a blocked IP
type BlockedIPInfo struct {
	IP           string
	BlockedUntil time.Time
	FailureCount int
	FirstFailure time.Time
}

// IPFailureInfo tracks progressive delay information for an IP
type IPFailureInfo struct {
	IP           string
	FailureCount int
	FirstFailure time.Time
	LastDelay    time.Duration

	// perUser counts this window's failures by username, so that a success
	// can forgive that user's own failures and nothing else. Bounded by
	// maxTrackedUsersPerIP; failures beyond it are counted but never forgiven.
	perUser map[string]int
}

// maxTrackedUsersPerIP bounds IPFailureInfo.perUser.
const maxTrackedUsersPerIP = 64

// UsernameFailureInfo tracks authentication failures per username
type UsernameFailureInfo struct {
	Username     string
	FailureCount int
	SuccessCount int
	FirstFailure time.Time
}

// NewAuthRateLimiter creates a new authentication rate limiter
func NewAuthRateLimiter(cfg config.ServerAuthRateLimitConfig, logger *slog.Logger, m *metrics.Metrics) (*AuthRateLimiter, error) {
	// Parse durations
	ipUsernameBlockDuration, err := parseDuration(cfg.IPUsernameBlockDuration, 15*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("invalid ip_username_block_duration: %w", err)
	}

	ipUsernameWindowDuration, err := parseDuration(cfg.IPUsernameWindowDuration, 10*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("invalid ip_username_window_duration: %w", err)
	}

	ipBlockDuration, err := parseDuration(cfg.IPBlockDuration, 30*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("invalid ip_block_duration: %w", err)
	}

	ipWindowDuration, err := parseDuration(cfg.IPWindowDuration, 30*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("invalid ip_window_duration: %w", err)
	}

	subnetBlockDuration, err := parseDuration(cfg.SubnetBlockDuration, 30*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet_block_duration: %w", err)
	}

	subnetWindowDuration, err := parseDuration(cfg.SubnetWindowDuration, 30*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet_window_duration: %w", err)
	}

	successExemptDuration, err := parseDuration(cfg.SuccessExemptDuration, 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("invalid success_exempt_duration: %w", err)
	}

	subnetExempt := make([]netip.Prefix, 0, len(cfg.SubnetExempt))
	for _, cidr := range cfg.SubnetExempt {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid subnet_exempt entry %q: %w", cidr, err)
		}
		subnetExempt = append(subnetExempt, prefix.Masked())
	}

	usernameWindowDuration, err := parseDuration(cfg.UsernameWindowDuration, 1*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("invalid username_window_duration: %w", err)
	}

	initialDelay, err := parseDuration(cfg.InitialDelay, 1*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid initial_delay: %w", err)
	}

	maxDelay, err := parseDuration(cfg.MaxDelay, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid max_delay: %w", err)
	}

	cacheCleanupInterval, err := parseDuration(cfg.CacheCleanupInterval, 5*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("invalid cache_cleanup_interval: %w", err)
	}

	// Create context for lifecycle management
	ctx, cancel := context.WithCancel(context.Background())

	limiter := &AuthRateLimiter{
		config:                   cfg,
		logger:                   logger,
		metrics:                  m,
		blockedIPUsernames:       make(map[string]*BlockedIPUsernameInfo),
		blockedIPs:               make(map[string]*BlockedIPInfo),
		ipFailureCounts:          make(map[string]*IPFailureInfo),
		subnets:                  make(map[string]*SubnetInfo),
		subnetExempt:             subnetExempt,
		goodIPs:                  make(map[string]time.Time),
		usernameFailureCounts:    make(map[string]*UsernameFailureInfo),
		ipUsernameBlockDuration:  ipUsernameBlockDuration,
		ipUsernameWindowDuration: ipUsernameWindowDuration,
		ipBlockDuration:          ipBlockDuration,
		ipWindowDuration:         ipWindowDuration,
		subnetBlockDuration:      subnetBlockDuration,
		subnetWindowDuration:     subnetWindowDuration,
		successExemptDuration:    successExemptDuration,
		usernameWindowDuration:   usernameWindowDuration,
		initialDelay:             initialDelay,
		maxDelay:                 maxDelay,
		cacheCleanupInterval:     cacheCleanupInterval,
		ctx:                      ctx,
		cancel:                   cancel,
	}

	// Start cleanup goroutine with panic recovery
	concurrency.SafeGo(logger, "auth-rate-limiter-cleanup", limiter.cleanupLoop)

	return limiter, nil
}

// MaxBlockDuration returns the longest block this node would apply locally. It
// is used to clamp block expiries received via untrusted cluster gossip.
func (a *AuthRateLimiter) MaxBlockDuration() time.Duration {
	max := a.ipBlockDuration
	if a.ipUsernameBlockDuration > max {
		max = a.ipUsernameBlockDuration
	}
	if a.subnetBlockDuration > max {
		max = a.subnetBlockDuration
	}
	return max
}

// parseDuration parses a duration string or returns default
func parseDuration(s string, defaultDuration time.Duration) (time.Duration, error) {
	if s == "" {
		return defaultDuration, nil
	}
	return time.ParseDuration(s)
}

// SetClusterLimiter sets the cluster rate limiter for distributed sync
func (a *AuthRateLimiter) SetClusterLimiter(cluster *ClusterAuthRateLimiter) {
	a.clusterLimiter = cluster
}

// CanAttemptAuth checks if an authentication attempt is allowed
// Returns error if rate limited
func (a *AuthRateLimiter) CanAttemptAuth(ctx context.Context, ip, username string) error {
	if !a.config.Enabled {
		return nil
	}

	username = normalizeAuthUsername(username)

	// Every tier keys on the bucketed identity (IPv6 → its /64), or a v6
	// attacker rotates addresses inside one allocation for free.
	ip = bucketIP(ip)

	// Check Tier 1: IP+username blocking (only if enabled)
	if a.config.MaxAttemptsPerIPUsername > 0 && username != "" {
		key := makeIPUsernameKey(ip, username)
		a.ipUsernameMu.RLock()
		if info, exists := a.blockedIPUsernames[key]; exists {
			if time.Now().Before(info.BlockedUntil) {
				a.ipUsernameMu.RUnlock()
				a.logger.Warn("authentication blocked (IP+username)",
					"ip", ip,
					"username", username,
					"blocked_until", info.BlockedUntil,
					"failure_count", info.FailureCount)
				return fmt.Errorf("rate limit exceeded for user from this IP")
			}
		}
		a.ipUsernameMu.RUnlock()
	}

	// Check Tier 2: IP-only blocking
	a.ipMu.RLock()
	if info, exists := a.blockedIPs[ip]; exists {
		if time.Now().Before(info.BlockedUntil) {
			a.ipMu.RUnlock()
			a.logger.Warn("authentication blocked (IP)",
				"ip", ip,
				"blocked_until", info.BlockedUntil,
				"failure_count", info.FailureCount)
			return fmt.Errorf("rate limit exceeded for this IP")
		}
	}
	a.ipMu.RUnlock()

	// Check Tier 3: subnet blocking (recently-successful IPs pass through)
	if blockedUntil, blocked := a.subnetBlocked(ip, time.Now()); blocked {
		a.logger.Warn("authentication blocked (subnet)",
			"ip", ip,
			"blocked_until", blockedUntil)
		return fmt.Errorf("rate limit exceeded for this network")
	}

	return nil
}

// GetAuthenticationDelay returns the progressive delay for an IP
func (a *AuthRateLimiter) GetAuthenticationDelay(ip string) time.Duration {
	if !a.config.Enabled {
		return 0
	}

	ip = bucketIP(ip)

	a.ipMu.RLock()
	defer a.ipMu.RUnlock()

	info, exists := a.ipFailureCounts[ip]
	if !exists {
		return 0
	}

	// Check if within window
	if time.Since(info.FirstFailure) > a.ipWindowDuration {
		return 0
	}

	// Check if threshold reached
	if info.FailureCount < a.config.DelayStartThreshold {
		return 0
	}

	return info.LastDelay
}

// RecordAuthAttempt records the result of an authentication attempt
func (a *AuthRateLimiter) RecordAuthAttempt(ctx context.Context, ip, username string, success bool) {
	if !a.config.Enabled {
		return
	}

	username = normalizeAuthUsername(username)

	ip = bucketIP(ip)

	if success {
		a.recordSuccess(ip, username)
	} else {
		a.recordFailure(ip, username)
	}
}

// recordSuccess handles successful authentication
func (a *AuthRateLimiter) recordSuccess(ip, username string) {
	// Clear IP+username failure
	key := makeIPUsernameKey(ip, username)
	a.ipUsernameMu.Lock()
	delete(a.blockedIPUsernames, key)
	a.ipUsernameMu.Unlock()

	// Forgive this user's own failures from this IP - and only those. Deleting
	// the whole count let one valid account launder unlimited guesses at
	// other accounts.
	a.forgiveIPFailures(ip, username)

	// Stamp the subnet-block bypass and stop counting this address toward
	// its subnet's fate (the subnet's BLOCK state, if any, stays — one
	// cracked credential must not lift it)
	a.recordGoodIP(ip, time.Now())
	a.clearSubnetMember(ip)

	// Clear username failure (but track success)
	a.usernameMu.Lock()
	if info, exists := a.usernameFailureCounts[username]; exists {
		info.SuccessCount++
		info.FailureCount = 0
	}
	a.usernameMu.Unlock()

	// Broadcast username success to cluster
	if a.clusterLimiter != nil && a.config.ClusterSyncEnabled {
		a.clusterLimiter.BroadcastUsernameSuccess(username)
	}

	a.logger.Debug("authentication success recorded",
		"ip", ip,
		"username", username)
}

// recordFailure handles failed authentication
func (a *AuthRateLimiter) recordFailure(ip, username string) {
	now := time.Now()

	// Update Tier 1: IP+username (only if enabled)
	if a.config.MaxAttemptsPerIPUsername > 0 && username != "" {
		a.updateIPUsernameFailure(ip, username, now)
	}

	// Update Tier 2: IP-only
	a.updateIPFailure(ip, username, now)

	// Update Tier 3: subnet
	a.noteSubnetFailure(ip, 0, now)

	// Update username tracking (only if enabled)
	if a.config.MaxAttemptsPerUsername > 0 && username != "" {
		a.updateUsernameFailure(username, now)
	}
}

// updateIPUsernameFailure updates IP+username failure count and blocks if threshold reached
func (a *AuthRateLimiter) updateIPUsernameFailure(ip, username string, now time.Time) {
	key := makeIPUsernameKey(ip, username)

	a.ipUsernameMu.Lock()
	defer a.ipUsernameMu.Unlock()

	info, exists := a.blockedIPUsernames[key]
	if !exists {
		// Proactively enforce limits BEFORE adding new entry
		if a.config.MaxIPUsernameEntries > 0 && len(a.blockedIPUsernames) >= a.config.MaxIPUsernameEntries {
			a.proactiveEvictIPUsername()
		}

		info = &BlockedIPUsernameInfo{
			IP:           ip,
			Username:     username,
			FirstFailure: now,
			FailureCount: 0,
		}
		a.blockedIPUsernames[key] = info
	}

	// Reset if outside window
	if now.Sub(info.FirstFailure) > a.ipUsernameWindowDuration {
		info.FirstFailure = now
		info.FailureCount = 0
	}

	info.FailureCount++

	// Check if should block
	if info.FailureCount >= a.config.MaxAttemptsPerIPUsername {
		info.BlockedUntil = now.Add(a.ipUsernameBlockDuration)

		a.logger.Warn("blocking IP+username combination",
			"ip", ip,
			"username", username,
			"failure_count", info.FailureCount,
			"blocked_until", info.BlockedUntil)

		// Record metrics
		if a.metrics != nil {
			a.metrics.AuthRateLimitIPUsernameBlocks.WithLabelValues(ip, username).Inc()
		}
	}
}

// forgiveIPFailures subtracts username's own failures from ip's count after a
// successful login.
func (a *AuthRateLimiter) forgiveIPFailures(ip, username string) {
	a.ipMu.Lock()
	defer a.ipMu.Unlock()

	info, exists := a.ipFailureCounts[ip]
	if !exists {
		return
	}
	info.FailureCount -= info.perUser[username]
	delete(info.perUser, username)
	if info.FailureCount <= 0 {
		delete(a.ipFailureCounts, ip)
		return
	}
	if info.FailureCount >= a.config.DelayStartThreshold {
		info.LastDelay = a.calculateDelay(info.FailureCount - a.config.DelayStartThreshold)
	} else {
		info.LastDelay = 0
	}
}

// updateIPFailure updates IP failure count and progressive delays
func (a *AuthRateLimiter) updateIPFailure(ip, username string, now time.Time) {
	a.ipMu.Lock()
	defer a.ipMu.Unlock()

	info, exists := a.ipFailureCounts[ip]
	if !exists {
		// Proactively enforce limits BEFORE adding new entry
		if a.config.MaxIPEntries > 0 && len(a.ipFailureCounts) >= a.config.MaxIPEntries {
			a.proactiveEvictIPFailures()
		}

		info = &IPFailureInfo{
			IP:           ip,
			FirstFailure: now,
			FailureCount: 0,
		}
		a.ipFailureCounts[ip] = info
	}

	// Reset if outside window
	if now.Sub(info.FirstFailure) > a.ipWindowDuration {
		info.FirstFailure = now
		info.FailureCount = 0
		info.perUser = nil
	}

	info.FailureCount++
	if _, tracked := info.perUser[username]; tracked || len(info.perUser) < maxTrackedUsersPerIP {
		if info.perUser == nil {
			info.perUser = make(map[string]int)
		}
		info.perUser[username]++
	}

	// Calculate progressive delay
	if info.FailureCount >= a.config.DelayStartThreshold {
		delay := a.calculateDelay(info.FailureCount - a.config.DelayStartThreshold)
		info.LastDelay = delay

		// Record delay metric
		if a.metrics != nil {
			a.metrics.AuthRateLimitDelays.WithLabelValues("ip").Observe(delay.Seconds())
		}
	}

	// Check if should block entire IP
	if info.FailureCount >= a.config.MaxAttemptsPerIP {
		blockedUntil := now.Add(a.ipBlockDuration)

		// Proactively enforce limits BEFORE adding new blocked IP entry
		if _, alreadyBlocked := a.blockedIPs[ip]; !alreadyBlocked {
			if a.config.MaxIPEntries > 0 && len(a.blockedIPs) >= a.config.MaxIPEntries {
				a.proactiveEvictBlockedIPs()
			}
		}

		a.blockedIPs[ip] = &BlockedIPInfo{
			IP:           ip,
			BlockedUntil: blockedUntil,
			FailureCount: info.FailureCount,
			FirstFailure: info.FirstFailure,
		}

		a.logger.Warn("blocking IP",
			"ip", ip,
			"failure_count", info.FailureCount,
			"blocked_until", blockedUntil)

		// Record metrics
		if a.metrics != nil {
			a.metrics.AuthRateLimitIPBlocks.WithLabelValues(ip).Inc()
		}

		// Broadcast block to cluster
		if a.clusterLimiter != nil && a.config.ClusterSyncEnabled && a.config.SyncBlocks {
			a.clusterLimiter.BroadcastBlockIP(ip, blockedUntil, info.FailureCount, info.FirstFailure)
		}
	} else if a.clusterLimiter != nil && a.config.ClusterSyncEnabled && a.config.SyncFailureCounts {
		// Broadcast failure count update
		a.clusterLimiter.BroadcastFailureCount(ip, info.FailureCount, info.LastDelay, info.FirstFailure)
	}
}

// updateUsernameFailure updates username failure tracking
func (a *AuthRateLimiter) updateUsernameFailure(username string, now time.Time) {
	a.usernameMu.Lock()
	defer a.usernameMu.Unlock()

	info, exists := a.usernameFailureCounts[username]
	if !exists {
		// Proactively enforce limits BEFORE adding new entry
		if a.config.MaxUsernameEntries > 0 && len(a.usernameFailureCounts) >= a.config.MaxUsernameEntries {
			a.proactiveEvictUsernames()
		}

		info = &UsernameFailureInfo{
			Username:     username,
			FirstFailure: now,
			FailureCount: 0,
		}
		a.usernameFailureCounts[username] = info
	}

	// Reset if outside window
	if now.Sub(info.FirstFailure) > a.usernameWindowDuration {
		info.FirstFailure = now
		info.FailureCount = 0
	}

	info.FailureCount++

	// Log if threshold exceeded (no blocking, just tracking)
	if info.FailureCount >= a.config.MaxAttemptsPerUsername {
		a.logger.Warn("high username failure rate",
			"username", username,
			"failure_count", info.FailureCount,
			"window", a.usernameWindowDuration)
	}

	// Broadcast to cluster for statistics
	if a.clusterLimiter != nil && a.config.ClusterSyncEnabled {
		a.clusterLimiter.BroadcastUsernameFailure(username, info.FailureCount, info.FirstFailure)
	}
}

// calculateDelay calculates exponential backoff delay
func (a *AuthRateLimiter) calculateDelay(failuresSinceThreshold int) time.Duration {
	if failuresSinceThreshold < 0 {
		return 0
	}

	// Start with initial delay
	delay := a.initialDelay

	// Apply multiplier for each failure after the first
	for i := 0; i < failuresSinceThreshold; i++ {
		delay = time.Duration(float64(delay) * a.config.DelayMultiplier)
		if delay > a.maxDelay {
			return a.maxDelay
		}
	}

	return delay
}

// normalizeAuthUsername canonicalizes the client-supplied AUTH username into
// the identity the limiter keys on. Lowercased because the backend resolves
// logins case-insensitively - otherwise each case variant of one account gets
// a fresh tier-1 budget. Invalid UTF-8 is replaced because the value is also
// used as a Prometheus label, and client_golang panics on an invalid one.
func normalizeAuthUsername(username string) string {
	return strings.ToValidUTF8(strings.ToLower(strings.TrimSpace(username)), "\uFFFD")
}

// makeIPUsernameKey creates a key for IP+username combination
func makeIPUsernameKey(ip, username string) string {
	return ip + "|" + username
}

// proactiveEvictIPUsername proactively evicts oldest entries when at capacity
// This prevents memory spikes by evicting BEFORE adding new entries
func (a *AuthRateLimiter) proactiveEvictIPUsername() {
	// Evict 20% to create headroom (more aggressive than reactive 10%)
	toEvict := a.config.MaxIPUsernameEntries / 5
	if toEvict < 1 {
		toEvict = 1
	}

	type kv struct {
		key  string
		time time.Time
	}
	entries := make([]kv, 0, len(a.blockedIPUsernames))
	for k, v := range a.blockedIPUsernames {
		entries = append(entries, kv{k, v.FirstFailure})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].time.Before(entries[j].time)
	})

	evicted := 0
	for i := 0; i < toEvict && i < len(entries); i++ {
		delete(a.blockedIPUsernames, entries[i].key)
		evicted++
	}

	a.logger.Info("proactively evicted IP+username entries to prevent memory spike",
		"evicted", evicted,
		"remaining", len(a.blockedIPUsernames),
		"capacity", a.config.MaxIPUsernameEntries)

	// Record metrics
	if a.metrics != nil {
		a.metrics.AuthRateLimitEvictions.WithLabelValues("ip_username").Add(float64(evicted))
		a.metrics.AuthRateLimitCacheSize.WithLabelValues("ip_username").Set(float64(len(a.blockedIPUsernames)))
	}
}

// proactiveEvictBlockedIPs proactively evicts oldest blocked IPs
func (a *AuthRateLimiter) proactiveEvictBlockedIPs() {
	toEvict := a.config.MaxIPEntries / 5
	if toEvict < 1 {
		toEvict = 1
	}

	type kv struct {
		key  string
		time time.Time
	}
	entries := make([]kv, 0, len(a.blockedIPs))
	for k, v := range a.blockedIPs {
		entries = append(entries, kv{k, v.FirstFailure})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].time.Before(entries[j].time)
	})

	evicted := 0
	for i := 0; i < toEvict && i < len(entries); i++ {
		delete(a.blockedIPs, entries[i].key)
		evicted++
	}

	a.logger.Debug("proactively evicted blocked IPs",
		"evicted", evicted,
		"remaining", len(a.blockedIPs))

	// Record metrics
	if a.metrics != nil {
		a.metrics.AuthRateLimitEvictions.WithLabelValues("blocked_ips").Add(float64(evicted))
		a.metrics.AuthRateLimitCacheSize.WithLabelValues("blocked_ips").Set(float64(len(a.blockedIPs)))
	}
}

// proactiveEvictIPFailures proactively evicts oldest IP failure counts
func (a *AuthRateLimiter) proactiveEvictIPFailures() {
	toEvict := a.config.MaxIPEntries / 5
	if toEvict < 1 {
		toEvict = 1
	}

	type kv struct {
		key  string
		time time.Time
	}
	entries := make([]kv, 0, len(a.ipFailureCounts))
	for k, v := range a.ipFailureCounts {
		entries = append(entries, kv{k, v.FirstFailure})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].time.Before(entries[j].time)
	})

	evicted := 0
	for i := 0; i < toEvict && i < len(entries); i++ {
		delete(a.ipFailureCounts, entries[i].key)
		evicted++
	}

	a.logger.Debug("proactively evicted IP failure counts",
		"evicted", evicted,
		"remaining", len(a.ipFailureCounts))

	// Record metrics
	if a.metrics != nil {
		a.metrics.AuthRateLimitEvictions.WithLabelValues("ip").Add(float64(evicted))
		a.metrics.AuthRateLimitCacheSize.WithLabelValues("ip").Set(float64(len(a.ipFailureCounts)))
	}
}

// proactiveEvictUsernames proactively evicts oldest username failure tracking
func (a *AuthRateLimiter) proactiveEvictUsernames() {
	toEvict := a.config.MaxUsernameEntries / 5
	if toEvict < 1 {
		toEvict = 1
	}

	type kv struct {
		key  string
		time time.Time
	}
	entries := make([]kv, 0, len(a.usernameFailureCounts))
	for k, v := range a.usernameFailureCounts {
		entries = append(entries, kv{k, v.FirstFailure})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].time.Before(entries[j].time)
	})

	evicted := 0
	for i := 0; i < toEvict && i < len(entries); i++ {
		delete(a.usernameFailureCounts, entries[i].key)
		evicted++
	}

	a.logger.Debug("proactively evicted username failure counts",
		"evicted", evicted,
		"remaining", len(a.usernameFailureCounts))

	// Record metrics
	if a.metrics != nil {
		a.metrics.AuthRateLimitEvictions.WithLabelValues("username").Add(float64(evicted))
		a.metrics.AuthRateLimitCacheSize.WithLabelValues("username").Set(float64(len(a.usernameFailureCounts)))
	}
}

// cleanupLoop periodically removes expired entries
// Respects context cancellation for graceful shutdown
func (a *AuthRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(a.cacheCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			a.logger.Info("auth rate limiter cleanup loop shutting down")
			return
		case <-ticker.C:
			a.cleanup()
		}
	}
}

// cleanup removes expired entries from all maps
func (a *AuthRateLimiter) cleanup() {
	now := time.Now()

	// Cleanup IP+username blocks
	a.ipUsernameMu.Lock()
	for key, info := range a.blockedIPUsernames {
		if now.After(info.BlockedUntil) && now.Sub(info.FirstFailure) > a.ipUsernameWindowDuration {
			delete(a.blockedIPUsernames, key)
		}
	}
	a.ipUsernameMu.Unlock()

	// Cleanup IP blocks
	a.ipMu.Lock()
	for ip, info := range a.blockedIPs {
		if now.After(info.BlockedUntil) {
			delete(a.blockedIPs, ip)
		}
	}
	// Cleanup IP failure counts
	for ip, info := range a.ipFailureCounts {
		if now.Sub(info.FirstFailure) > a.ipWindowDuration {
			delete(a.ipFailureCounts, ip)
		}
	}
	a.ipMu.Unlock()

	// Cleanup subnet tracking: drop members that fell out of the window,
	// then subnets with neither members nor a live block
	a.subnetMu.Lock()
	for subnet, info := range a.subnets {
		pruneSubnetMembers(info, now, a.subnetWindowDuration)
		if len(info.Members) == 0 && now.After(info.BlockedUntil) {
			delete(a.subnets, subnet)
		}
	}
	a.subnetMu.Unlock()

	// Cleanup expired success stamps
	a.goodMu.Lock()
	for ip, seen := range a.goodIPs {
		if now.Sub(seen) > a.successExemptDuration {
			delete(a.goodIPs, ip)
		}
	}
	a.goodMu.Unlock()

	// Cleanup username tracking
	a.usernameMu.Lock()
	for username, info := range a.usernameFailureCounts {
		if now.Sub(info.FirstFailure) > a.usernameWindowDuration {
			delete(a.usernameFailureCounts, username)
		}
	}
	a.usernameMu.Unlock()
}

// RemoveIP removes an IP — or, given CIDR notation, a blocked subnet — from
// tracking, and broadcasts to the cluster. Implements health.IPUnblocker.
func (a *AuthRateLimiter) RemoveIP(ip string) bool {
	if strings.Contains(ip, "/") {
		// Canonicalize BEFORE broadcasting: peers' gossip sanitizer refuses a
		// non-masked prefix, so an operator's "203.0.113.5/24" must leave
		// this node as "203.0.113.0/24" or the unblock stays local-only.
		prefix, err := netip.ParsePrefix(ip)
		if err != nil {
			return false
		}
		subnet := prefix.Masked().String()
		removed := a.ApplyUnblockSubnet(subnet)
		if removed && a.clusterLimiter != nil {
			a.clusterLimiter.BroadcastUnblockSubnet(subnet)
		}
		return removed
	}

	removed := a.ApplyUnblockIP(ip)

	// Broadcast to cluster if available
	if removed && a.clusterLimiter != nil {
		a.clusterLimiter.BroadcastUnblockIP(bucketIP(ip))
	}

	return removed
}

// ApplyUnblockIP removes an IP from the blocked list and failure tracking (local only, no broadcast).
// Used by cluster event handler to apply unblocks from other nodes.
func (a *AuthRateLimiter) ApplyUnblockIP(ip string) bool {
	ip = bucketIP(ip)

	a.ipMu.Lock()

	_, blockedExists := a.blockedIPs[ip]
	_, failureExists := a.ipFailureCounts[ip]
	removed := blockedExists || failureExists

	delete(a.blockedIPs, ip)
	delete(a.ipFailureCounts, ip)

	if removed {
		a.logger.Info("IP unblocked",
			"ip", ip,
			"was_blocked", blockedExists,
			"had_failures", failureExists)
	}
	a.ipMu.Unlock()

	// The IP+username blocks from this address go too: the operator unblocked
	// the address, not "the address except for the account that was mistyped".
	// A scan of the whole map is fine for an operator action.
	a.ipUsernameMu.Lock()
	for key, info := range a.blockedIPUsernames {
		if info.IP == ip {
			delete(a.blockedIPUsernames, key)
			removed = true
		}
	}
	a.ipUsernameMu.Unlock()

	// An operator vouching for an address also stops it counting toward its
	// subnet's distinct-failure set (the subnet's own block, if already
	// standing, is lifted separately via CIDR).
	a.clearSubnetMember(ip)

	return removed
}

// ApplyBlockIP applies a block from cluster sync
func (a *AuthRateLimiter) ApplyBlockIP(ip string, blockedUntil time.Time, failureCount int, firstFailure time.Time) {
	ip = bucketIP(ip)

	a.ipMu.Lock()
	// Only apply if newer or not exists
	existing, exists := a.blockedIPs[ip]
	if !exists || blockedUntil.After(existing.BlockedUntil) {
		a.blockedIPs[ip] = &BlockedIPInfo{
			IP:           ip,
			BlockedUntil: blockedUntil,
			FailureCount: failureCount,
			FirstFailure: firstFailure,
		}

		a.logger.Info("applied IP block from cluster",
			"ip", ip,
			"blocked_until", blockedUntil,
			"failure_count", failureCount)
	}
	a.ipMu.Unlock()

	// A peer blocking this IP is prime evidence of a failing subnet member;
	// without this, a deployment syncing blocks but not failure counts would
	// leave the subnet tier blind to cluster-observed rotation.
	a.noteSubnetFailure(ip, failureCount, time.Now())
}

// ApplyFailureCount applies failure count from cluster sync
func (a *AuthRateLimiter) ApplyFailureCount(ip string, failureCount int, lastDelay time.Duration, firstFailure time.Time) {
	ip = bucketIP(ip)

	a.ipMu.Lock()
	// Only apply if higher count or not exists
	existing, exists := a.ipFailureCounts[ip]
	if !exists || failureCount > existing.FailureCount {
		info := &IPFailureInfo{
			IP:           ip,
			FailureCount: failureCount,
			LastDelay:    lastDelay,
			FirstFailure: firstFailure,
		}
		// Keep the per-user attribution of the failures this node saw itself.
		// Dropping it with the old entry meant a later successful login had
		// nothing to forgive, and the user kept the delays for their own typos.
		if exists {
			info.perUser = existing.perUser
		}
		a.ipFailureCounts[ip] = info

		a.logger.Debug("applied failure count from cluster",
			"ip", ip,
			"failure_count", failureCount,
			"last_delay", lastDelay)
	}
	a.ipMu.Unlock()

	// Feed the subnet tracker: FAILURE_COUNT events carry the failing IP, so
	// a rotation spread across cluster nodes still converges on one subnet
	// verdict. Distinct-set semantics make this merge idempotent — the same
	// IP reported twice is still one member.
	a.noteSubnetFailure(ip, failureCount, time.Now())
}

// ApplyUsernameFailure applies username failure from cluster sync
func (a *AuthRateLimiter) ApplyUsernameFailure(username string, failureCount int, firstFailure time.Time) {
	a.usernameMu.Lock()
	defer a.usernameMu.Unlock()

	// Increment or create
	info, exists := a.usernameFailureCounts[username]
	if !exists {
		a.usernameFailureCounts[username] = &UsernameFailureInfo{
			Username:     username,
			FailureCount: failureCount,
			FirstFailure: firstFailure,
		}
	} else if failureCount > info.FailureCount {
		info.FailureCount = failureCount
		if firstFailure.Before(info.FirstFailure) {
			info.FirstFailure = firstFailure
		}
	}
}

// ClearUsernameFailure clears username failure tracking (from success)
func (a *AuthRateLimiter) ClearUsernameFailure(username string) {
	a.usernameMu.Lock()
	defer a.usernameMu.Unlock()

	if info, exists := a.usernameFailureCounts[username]; exists {
		info.FailureCount = 0
		info.SuccessCount++
	}
}

// GetStats returns rate limiter statistics
func (a *AuthRateLimiter) GetStats() map[string]interface{} {
	a.ipUsernameMu.RLock()
	blockedIPUsernameCount := len(a.blockedIPUsernames)
	a.ipUsernameMu.RUnlock()

	a.ipMu.RLock()
	blockedIPCount := len(a.blockedIPs)
	ipFailureCount := len(a.ipFailureCounts)
	a.ipMu.RUnlock()

	a.usernameMu.RLock()
	usernameFailureCount := len(a.usernameFailureCounts)
	a.usernameMu.RUnlock()

	now := time.Now()
	a.subnetMu.RLock()
	subnetCount := len(a.subnets)
	blockedSubnetCount := 0
	for _, info := range a.subnets {
		if now.Before(info.BlockedUntil) {
			blockedSubnetCount++
		}
	}
	a.subnetMu.RUnlock()

	a.goodMu.RLock()
	goodIPCount := len(a.goodIPs)
	a.goodMu.RUnlock()

	return map[string]interface{}{
		"enabled":                   a.config.Enabled,
		"blocked_ip_username":       blockedIPUsernameCount,
		"blocked_ips":               blockedIPCount,
		"ip_failure_tracking":       ipFailureCount,
		"blocked_subnets":           blockedSubnetCount,
		"subnet_tracking":           subnetCount,
		"good_ips":                  goodIPCount,
		"username_failure_tracking": usernameFailureCount,
	}
}

// SetName sets the health checker name for this rate limiter.
func (a *AuthRateLimiter) SetName(name string) {
	a.name = name
}

// Name returns the health checker name. Implements health.Checker.
func (a *AuthRateLimiter) Name() string {
	return a.name
}

// CheckHealth reports auth rate limiter status. Implements health.Checker.
func (a *AuthRateLimiter) CheckHealth() health.ComponentStatus {
	stats := a.GetStats()
	stats["cluster_sync"] = a.clusterLimiter != nil

	return health.ComponentStatus{
		Status:  "healthy",
		Details: stats,
	}
}

// Shutdown gracefully stops the auth rate limiter cleanup goroutine
// This should be called when the rate limiter is no longer needed to prevent goroutine leaks
func (a *AuthRateLimiter) Shutdown() {
	if a.cancel != nil {
		a.logger.Info("shutting down auth rate limiter")
		a.cancel()
	}
}

package smtp

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"migadu/mizu/pkg/cluster"
	"migadu/mizu/pkg/concurrency"
	"migadu/mizu/pkg/health"
	"net"
	"path"
	"strings"
	"sync"
	"time"

	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/hashicorp/memberlist"
)

// ClusterManager interface allows for testing and abstraction
type ClusterManager interface {
	BroadcastConnectionState(data []byte) error
	RegisterConnectionStateHandler(handler func(data []byte))
	NumMembers() int
	SetStateDelegate(delegate cluster.StateDelegate)
	SetEventDelegate(delegate cluster.EventDelegate)
}

// DistributedTracker wraps ConnectionTracker with memberlist gossip and S3 sync capabilities
type DistributedTracker struct {
	local      *ConnectionTracker // Local connection tracking (fast path)
	name       string             // Health checker name (empty = default)
	serverName string             // Config server name (e.g., "mx-primary", "mx-submission")
	hostname   string             // This server's hostname
	logger     *slog.Logger

	// Vector clock for conflict resolution
	vectorClock *cluster.VectorClock
	clockMu     sync.RWMutex

	// Memberlist cluster for peer discovery and gossip
	cluster        ClusterManager
	gossipInterval time.Duration // How often to broadcast (default: 5s)

	// Peer state from memberlist gossip
	peerConnections map[string]*PeerConnectionState
	peerMu          sync.RWMutex

	// S3 sync configuration (for cold start and backup)
	s3Client       *s3.Client
	s3Bucket       string
	s3Prefix       string
	s3SyncInterval time.Duration // How often to sync with S3 (default: 30s)

	// Global limits (enforced across cluster)
	globalMaxPerIP int

	// Recipient cache (distributed via gossip)
	recipientNotFound map[string]time.Time // email -> expiry (404 responses)
	recipientBlocked  map[string]time.Time // email -> expiry (403 responses)
	recipientMu       sync.RWMutex
	recipientCacheTTL time.Duration // How long to cache recipient results

	// Snapshot caching to avoid expensive GetStats() calls
	snapshotMu         sync.Mutex
	lastConnGeneration uint64
	lastConnMap        map[string]int

	// S3 export change detection to avoid writing unchanged data
	lastExportHash string

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// PeerConnectionState holds connection counts from a peer server
type PeerConnectionState struct {
	Hostname    string               `json:"hostname"`
	Timestamp   time.Time            `json:"timestamp"`
	Connections map[string]int       `json:"connections"` // IP -> count
	TotalCount  int                  `json:"total_count"`
	VectorClock *cluster.VectorClock `json:"vector_clock"`
	UpdatedAt   time.Time            `json:"-"` // When we received this update
}

// ConnectionSnapshot represents the state to sync
type ConnectionSnapshot struct {
	Hostname       string                  `json:"hostname"`
	Timestamp      time.Time               `json:"timestamp"`
	Connections    map[string]int          `json:"connections"`
	TotalCount     int                     `json:"total_count"`
	VectorClock    *cluster.VectorClock    `json:"vector_clock"`
	RecipientCache *RecipientCacheSnapshot `json:"recipient_cache,omitempty"`
}

// RecipientCacheSnapshot holds cached recipient validation results
type RecipientCacheSnapshot struct {
	NotFound map[string]time.Time `json:"not_found,omitempty"` // email -> expiry (404 responses)
	Blocked  map[string]time.Time `json:"blocked,omitempty"`   // email -> expiry (403 responses)
}

// DistributedConfig holds configuration for distributed tracking
type DistributedConfig struct {
	Hostname          string
	Cluster           ClusterManager // Memberlist cluster instance
	GossipInterval    time.Duration  // How often to broadcast (default: 5s)
	S3SyncInterval    time.Duration  // S3 sync interval (default: 30s)
	GlobalMaxPerIP    int            // Global per-IP limit across cluster
	RecipientCacheTTL time.Duration  // How long to cache recipient validation results
}

// NewDistributedTracker creates a new distributed connection tracker using memberlist
func NewDistributedTracker(
	local *ConnectionTracker,
	s3Client *s3.Client,
	s3Bucket, s3Prefix string,
	config DistributedConfig,
	logger *slog.Logger,
) *DistributedTracker {
	ctx, cancel := context.WithCancel(context.Background())

	dt := &DistributedTracker{
		local:             local,
		hostname:          config.Hostname,
		vectorClock:       cluster.NewVectorClock(config.Hostname),
		cluster:           config.Cluster,
		gossipInterval:    config.GossipInterval,
		s3Client:          s3Client,
		s3Bucket:          s3Bucket,
		s3Prefix:          s3Prefix,
		s3SyncInterval:    config.S3SyncInterval,
		globalMaxPerIP:    config.GlobalMaxPerIP,
		recipientNotFound: make(map[string]time.Time),
		recipientBlocked:  make(map[string]time.Time),
		recipientCacheTTL: config.RecipientCacheTTL,
		peerConnections:   make(map[string]*PeerConnectionState),
		logger:            logger,
		ctx:               ctx,
		cancel:            cancel,
	}

	// Register handlers, state delegate, and event delegate with the cluster
	if config.Cluster != nil {
		config.Cluster.RegisterConnectionStateHandler(dt.handleGossipMessage)
		config.Cluster.SetStateDelegate(dt)
		config.Cluster.SetEventDelegate(dt)
	}

	return dt
}

// GetState returns the current state of the tracker as a byte slice.
// This is used for state synchronization when a new node joins the cluster.
func (dt *DistributedTracker) GetState() []byte {
	// Increment vector clock for state synchronization event
	dt.clockMu.Lock()
	dt.vectorClock.Increment()
	dt.clockMu.Unlock()

	snapshot := dt.createSnapshot()
	data, err := json.Marshal(snapshot)
	if err != nil {
		dt.logger.Error("Failed to marshal state snapshot", "error", err)
		return nil
	}
	return data
}

// MergeState merges the remote state into the local state.
// This is used for state synchronization when a new node joins the cluster.
func (dt *DistributedTracker) MergeState(data []byte) {
	var snapshot ConnectionSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		dt.logger.Error("Failed to unmarshal remote state snapshot", "error", err)
		return
	}

	// Update local vector clock with remote clock
	if snapshot.VectorClock != nil {
		dt.clockMu.Lock()
		dt.vectorClock.Update(snapshot.VectorClock)
		dt.clockMu.Unlock()
	}

	// We can just use the same handler as for gossip messages
	dt.handleGossipMessage(data)

	clockStr := "nil"
	if snapshot.VectorClock != nil {
		clockStr = snapshot.VectorClock.String()
	}
	dt.logger.Info("Merged remote state from peer",
		"peer", snapshot.Hostname,
		"total_connections", snapshot.TotalCount,
		"unique_ips", len(snapshot.Connections),
		"vector_clock", clockStr)
}

// Start begins the gossip and sync loops
func (dt *DistributedTracker) Start() {
	clusterMembers := 0
	if dt.cluster != nil {
		clusterMembers = dt.cluster.NumMembers()
	}

	dt.logger.Info("Starting distributed connection tracker",
		"hostname", dt.hostname,
		"cluster_members", clusterMembers,
		"gossip_interval", dt.gossipInterval,
		"s3_sync_interval", dt.s3SyncInterval,
		"global_max_per_ip", dt.globalMaxPerIP,
		"recipient_cache_ttl", dt.recipientCacheTTL)

	// Start memberlist gossip loop
	if dt.cluster != nil {
		dt.wg.Add(1)
		concurrency.SafeGoWithWg(dt.logger, "distributed-tracker-gossip", &dt.wg, dt.gossipLoopInner)
	}

	// Start S3 sync loop (if configured - for cold start and backup)
	if dt.s3Client != nil && dt.s3Bucket != "" {
		dt.wg.Add(1)
		concurrency.SafeGoWithWg(dt.logger, "distributed-tracker-s3-sync", &dt.wg, dt.s3SyncLoopInner)
	}

	// Start recipient cache cleanup loop
	dt.wg.Add(1)
	concurrency.SafeGoWithWg(dt.logger, "distributed-tracker-recipient-cleanup", &dt.wg, dt.recipientCacheCleanupLoopInner)

	// Start stale peer cleanup loop
	dt.wg.Add(1)
	concurrency.SafeGoWithWg(dt.logger, "distributed-tracker-peer-cleanup", &dt.wg, dt.stalePeerCleanupLoopInner)
}

// recipientCacheCleanupLoopInner is the inner function for recipient cache cleanup
func (dt *DistributedTracker) recipientCacheCleanupLoopInner() {
	ticker := time.NewTicker(1 * time.Minute) // Cleanup every minute
	defer ticker.Stop()

	for {
		select {
		case <-dt.ctx.Done():
			return
		case <-ticker.C:
			dt.cleanupExpiredRecipients()
		}
	}
}

// cleanupExpiredRecipients removes expired entries from recipient cache
func (dt *DistributedTracker) cleanupExpiredRecipients() {
	dt.recipientMu.Lock()
	defer dt.recipientMu.Unlock()

	now := time.Now()
	removed := 0

	for email, expiry := range dt.recipientNotFound {
		if now.After(expiry) {
			delete(dt.recipientNotFound, email)
			removed++
		}
	}

	for email, expiry := range dt.recipientBlocked {
		if now.After(expiry) {
			delete(dt.recipientBlocked, email)
			removed++
		}
	}

	if removed > 0 {
		dt.logger.Debug("Cleaned up expired recipient cache entries",
			"removed", removed,
			"not_found_remaining", len(dt.recipientNotFound),
			"blocked_remaining", len(dt.recipientBlocked))
	}
}

// stalePeerCleanupLoopInner is the inner function for stale peer cleanup
func (dt *DistributedTracker) stalePeerCleanupLoopInner() {
	ticker := time.NewTicker(5 * time.Minute) // Cleanup every 5 minutes
	defer ticker.Stop()

	for {
		select {
		case <-dt.ctx.Done():
			return
		case <-ticker.C:
			dt.cleanupStalePeers()
		}
	}
}

// cleanupStalePeers removes peer connections that haven't been updated in 5 minutes
func (dt *DistributedTracker) cleanupStalePeers() {
	dt.peerMu.Lock()
	defer dt.peerMu.Unlock()

	now := time.Now()
	removed := 0
	staleThreshold := 5 * time.Minute

	for hostname, peer := range dt.peerConnections {
		if now.Sub(peer.UpdatedAt) > staleThreshold {
			delete(dt.peerConnections, hostname)
			removed++
		}
	}

	if removed > 0 {
		dt.logger.Debug("Cleaned up stale peer connections",
			"removed", removed,
			"remaining_peers", len(dt.peerConnections))
	}
}

// CacheRecipientNotFound adds a recipient to the "not found" cache (404 responses)
func (dt *DistributedTracker) CacheRecipientNotFound(email string) {
	dt.recipientMu.Lock()
	defer dt.recipientMu.Unlock()

	expiry := time.Now().Add(dt.recipientCacheTTL)
	dt.recipientNotFound[email] = expiry

	dt.logger.Debug("Cached recipient as not found",
		"email", email,
		"expiry", expiry)
}

// CacheRecipientBlocked adds a recipient to the "blocked" cache (403 responses)
func (dt *DistributedTracker) CacheRecipientBlocked(email string) {
	dt.recipientMu.Lock()
	defer dt.recipientMu.Unlock()

	expiry := time.Now().Add(dt.recipientCacheTTL)
	dt.recipientBlocked[email] = expiry

	dt.logger.Debug("Cached recipient as blocked",
		"email", email,
		"expiry", expiry)
}

// IsRecipientCached checks if a recipient is in the cache and returns the status
// Returns (found, isBlocked, reason)
func (dt *DistributedTracker) IsRecipientCached(email string) (bool, bool, string) {
	dt.recipientMu.RLock()
	defer dt.recipientMu.RUnlock()

	now := time.Now()

	// Check if recipient is in "not found" cache
	if expiry, exists := dt.recipientNotFound[email]; exists {
		if now.Before(expiry) {
			return true, false, "recipient not found (cached)"
		}
	}

	// Check if recipient is in "blocked" cache
	if expiry, exists := dt.recipientBlocked[email]; exists {
		if now.Before(expiry) {
			return true, true, "recipient blocked by destination (cached)"
		}
	}

	return false, false, ""
}

// Stop gracefully shuts down the distributed tracker
func (dt *DistributedTracker) Stop() {
	dt.logger.Info("Stopping distributed connection tracker")
	dt.cancel()
	dt.wg.Wait()
}

// TryAcquire attempts to acquire a connection slot with cluster-wide limit checking
func (dt *DistributedTracker) TryAcquire(remoteAddr string) error {
	host, _, _ := parseAddr(remoteAddr)

	// Step 1: Check local limit (fast path)
	if err := dt.local.TryAcquire(remoteAddr); err != nil {
		return err
	}

	// Step 2: Check estimated global limit (if configured)
	// We get the local count using the optimized method to avoid lock contention
	if dt.globalMaxPerIP > 0 {
		localCount := dt.local.GetCountForIP(host)

		// Add peer counts
		dt.peerMu.RLock()
		peerTotal := 0
		for _, peerState := range dt.peerConnections {
			// Ignore stale peer data (older than 30 seconds)
			if time.Since(peerState.UpdatedAt) > 30*time.Second {
				continue
			}
			if peerState.Connections != nil {
				peerTotal += peerState.Connections[host]
			}
		}
		dt.peerMu.RUnlock()

		globalCount := localCount + peerTotal

		if globalCount > dt.globalMaxPerIP {
			// Rollback local acquisition
			dt.local.Release(remoteAddr)
			return fmt.Errorf("estimated global connections per IP limit reached (%d)", dt.globalMaxPerIP)
		}
	}

	return nil
}

// Release releases a connection slot
func (dt *DistributedTracker) Release(remoteAddr string) {
	dt.local.Release(remoteAddr)
}

// GetStats returns current connection statistics from the local tracker
func (dt *DistributedTracker) GetStats() (total int, uniqueIPs int, perIP map[string]int) {
	return dt.local.GetStats()
}

// GetTotalCount returns the current total connection count (lock-free).
// This delegates to the local tracker and is safe to call from hot paths.
func (dt *DistributedTracker) GetTotalCount() int {
	return dt.local.GetTotalCount()
}

// GetCountForIP returns the current connection count for a specific IP.
// This delegates to the local tracker for efficiency.
func (dt *DistributedTracker) GetCountForIP(ip string) int {
	return dt.local.GetCountForIP(ip)
}

// gossipLoopInner is the inner function for gossip loop
func (dt *DistributedTracker) gossipLoopInner() {
	ticker := time.NewTicker(dt.gossipInterval)
	defer ticker.Stop()

	for {
		select {
		case <-dt.ctx.Done():
			return
		case <-ticker.C:
			dt.broadcastToCluster()
		}
	}
}

// broadcastToCluster broadcasts current connection state via memberlist
func (dt *DistributedTracker) broadcastToCluster() {
	// Increment vector clock for each broadcast
	dt.clockMu.Lock()
	dt.vectorClock.Increment()
	dt.clockMu.Unlock()

	snapshot := dt.createSnapshot()

	// Log local state being broadcast
	dt.logger.Debug("Broadcasting connection state to cluster",
		"total_connections", snapshot.TotalCount,
		"unique_ips", len(snapshot.Connections))

	data, err := json.Marshal(snapshot)
	if err != nil {
		dt.logger.Error("Failed to marshal connection snapshot", "error", err)
		return
	}

	if err := dt.cluster.BroadcastConnectionState(data); err != nil {
		dt.logger.Debug("Failed to broadcast connection state", "error", err)
	}
}

// createSnapshot creates a snapshot of current connection state
func (dt *DistributedTracker) createSnapshot() *ConnectionSnapshot {
	// Optimize: Check if connections changed since last snapshot
	currentGen := dt.local.GetGeneration()

	var perIP map[string]int
	var total int

	dt.snapshotMu.Lock()
	if currentGen == dt.lastConnGeneration && dt.lastConnMap != nil {
		// No changes, reuse cached map
		perIP = dt.lastConnMap
		total = dt.local.GetTotalCount()
	} else {
		dt.snapshotMu.Unlock()
		// Release lock while calling GetStats to avoid holding it during expensive op
		total, _, perIP = dt.local.GetStats()

		dt.snapshotMu.Lock()
		dt.lastConnGeneration = currentGen
		dt.lastConnMap = perIP
	}
	dt.snapshotMu.Unlock()

	// Copy recipient cache
	dt.recipientMu.RLock()
	notFoundCopy := make(map[string]time.Time, len(dt.recipientNotFound))
	for k, v := range dt.recipientNotFound {
		notFoundCopy[k] = v
	}
	blockedCopy := make(map[string]time.Time, len(dt.recipientBlocked))
	for k, v := range dt.recipientBlocked {
		blockedCopy[k] = v
	}
	dt.recipientMu.RUnlock()

	var recipientCache *RecipientCacheSnapshot
	if len(notFoundCopy) > 0 || len(blockedCopy) > 0 {
		recipientCache = &RecipientCacheSnapshot{
			NotFound: notFoundCopy,
			Blocked:  blockedCopy,
		}
	}

	// Copy vector clock
	dt.clockMu.RLock()
	clockCopy := dt.vectorClock.Copy()
	dt.clockMu.RUnlock()

	return &ConnectionSnapshot{
		Hostname:       dt.hostname,
		Timestamp:      time.Now(),
		Connections:    perIP,
		TotalCount:     total,
		VectorClock:    clockCopy,
		RecipientCache: recipientCache,
	}
}

// handleGossipMessage processes connection state gossip messages from memberlist
func (dt *DistributedTracker) handleGossipMessage(data []byte) {
	var snapshot ConnectionSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		dt.logger.Warn("Failed to unmarshal connection snapshot from gossip", "error", err)
		return
	}

	// Perform conflict resolution using vector clocks
	shouldMerge := true
	conflictType := "new"

	dt.peerMu.Lock()
	if existingPeer, exists := dt.peerConnections[snapshot.Hostname]; exists && existingPeer.VectorClock != nil && snapshot.VectorClock != nil {
		comparison := snapshot.VectorClock.Compare(existingPeer.VectorClock)
		switch comparison {
		case 1:
			// New snapshot happened after existing one - accept
			conflictType = "newer"
			shouldMerge = true
		case -1:
			// New snapshot happened before existing one - reject (stale)
			conflictType = "stale"
			shouldMerge = false
			dt.logger.Debug("Rejecting stale snapshot",
				"peer", snapshot.Hostname,
				"local_clock", existingPeer.VectorClock.String(),
				"remote_clock", snapshot.VectorClock.String())
		case 0:
			// Concurrent updates - use timestamp as tiebreaker
			conflictType = "concurrent"
			shouldMerge = snapshot.Timestamp.After(existingPeer.Timestamp)
			dt.logger.Debug("Concurrent snapshot detected, using timestamp tiebreaker",
				"peer", snapshot.Hostname,
				"accepting", shouldMerge,
				"local_time", existingPeer.Timestamp,
				"remote_time", snapshot.Timestamp)
		}
	}

	if shouldMerge {
		// Convert to PeerConnectionState
		peerState := &PeerConnectionState{
			Hostname:    snapshot.Hostname,
			Timestamp:   snapshot.Timestamp,
			Connections: snapshot.Connections,
			TotalCount:  snapshot.TotalCount,
			VectorClock: snapshot.VectorClock,
			UpdatedAt:   time.Now(),
		}

		// Update peer state
		dt.peerConnections[snapshot.Hostname] = peerState
		dt.peerMu.Unlock()

		// Update our vector clock with the remote clock
		if snapshot.VectorClock != nil {
			dt.clockMu.Lock()
			dt.vectorClock.Update(snapshot.VectorClock)
			dt.clockMu.Unlock()
		}

		// Merge recipient cache from peer
		if snapshot.RecipientCache != nil {
			dt.mergeRecipientCache(snapshot.RecipientCache)
		}

		clockStr := "nil"
		if snapshot.VectorClock != nil {
			clockStr = snapshot.VectorClock.String()
		}
		dt.logger.Debug("Received connection state from peer via memberlist",
			"peer", snapshot.Hostname,
			"total_connections", snapshot.TotalCount,
			"unique_ips", len(snapshot.Connections),
			"conflict_type", conflictType,
			"vector_clock", clockStr)
	} else {
		dt.peerMu.Unlock()
	}
}

// mergeRecipientCache merges recipient cache from a peer snapshot
func (dt *DistributedTracker) mergeRecipientCache(peerCache *RecipientCacheSnapshot) {
	dt.recipientMu.Lock()
	defer dt.recipientMu.Unlock()

	now := time.Now()
	merged := 0

	// Merge "not found" entries
	for email, expiry := range peerCache.NotFound {
		// Only merge if not expired and (not exists locally OR peer's expiry is later)
		if now.Before(expiry) {
			if localExpiry, exists := dt.recipientNotFound[email]; !exists || expiry.After(localExpiry) {
				dt.recipientNotFound[email] = expiry
				merged++
			}
		}
	}

	// Merge "blocked" entries
	for email, expiry := range peerCache.Blocked {
		// Only merge if not expired and (not exists locally OR peer's expiry is later)
		if now.Before(expiry) {
			if localExpiry, exists := dt.recipientBlocked[email]; !exists || expiry.After(localExpiry) {
				dt.recipientBlocked[email] = expiry
				merged++
			}
		}
	}

	if merged > 0 {
		dt.logger.Debug("Merged recipient cache from peer",
			"entries_merged", merged,
			"total_not_found", len(dt.recipientNotFound),
			"total_blocked", len(dt.recipientBlocked))
	}
}

// s3SyncLoopInner is the inner function for S3 sync loop
func (dt *DistributedTracker) s3SyncLoopInner() {
	ticker := time.NewTicker(dt.s3SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-dt.ctx.Done():
			return
		case <-ticker.C:
			dt.syncWithS3()
		}
	}
}

// syncWithS3 exports local state and imports peer states from S3
func (dt *DistributedTracker) syncWithS3() {
	// Check if S3 client is available
	if dt.s3Client == nil {
		dt.logger.Debug("S3 client not initialized, skipping S3 sync")
		return
	}

	// Export our state
	if err := dt.exportToS3(); err != nil {
		dt.logger.Error("Failed to export to S3", "error", err)
	}

	// Import peer states
	if err := dt.importFromS3(); err != nil {
		dt.logger.Error("Failed to import from S3", "error", err)
	}
}

// exportToS3 exports current connection state to S3.
// Uses hash-based change detection to avoid writing unchanged data,
// which prevents accumulating S3 object versions when state hasn't changed.
func (dt *DistributedTracker) exportToS3() error {
	if dt.s3Client == nil {
		return fmt.Errorf("S3 client not initialized")
	}

	snapshot := dt.createSnapshot()

	// Marshal to JSON (deterministic - same data produces same JSON since maps are sorted by encoding/json)
	data, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("failed to marshal snapshot: %w", err)
	}

	// Hash the JSON data (pre-compression) to detect changes.
	// We hash the uncompressed JSON because gzip output can vary
	// even for identical input (timestamps in gzip header).
	h := sha256.Sum256(data)
	currentHash := hex.EncodeToString(h[:])

	// Skip upload if data hasn't changed since last export
	if currentHash == dt.lastExportHash {
		dt.logger.Debug("Skipping S3 export - connection state unchanged")
		return nil
	}

	// Compress
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	if _, err := gzWriter.Write(data); err != nil {
		return fmt.Errorf("failed to compress: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		return fmt.Errorf("failed to close gzip: %w", err)
	}

	// Upload to S3 (s3Prefix already includes the "connections/" subdirectory)
	objectName := path.Join(dt.s3Prefix, fmt.Sprintf("%s.json.gz", dt.hostname))
	_, err = dt.s3Client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket:      aws.String(dt.s3Bucket),
		Key:         aws.String(objectName),
		Body:        bytes.NewReader(buf.Bytes()),
		ContentType: aws.String("application/gzip"),
	})
	if err != nil {
		return fmt.Errorf("failed to upload to S3: %w", err)
	}

	// Update last export hash on successful upload
	dt.lastExportHash = currentHash

	dt.logger.Debug("Exported connection state to S3",
		"object", objectName,
		"size", buf.Len())

	return nil
}

// importFromS3 imports peer connection states from S3
func (dt *DistributedTracker) importFromS3() error {
	if dt.s3Client == nil {
		return fmt.Errorf("S3 client not initialized")
	}

	// s3Prefix already includes the "connections/" subdirectory
	prefix := dt.s3Prefix
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	// List all connection files
	paginator := s3.NewListObjectsV2Paginator(dt.s3Client, &s3.ListObjectsV2Input{
		Bucket:    aws.String(dt.s3Bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			dt.logger.Error("Error listing S3 objects", "error", err)
			break
		}

		for _, object := range page.Contents {
			// Skip our own file
			expectedName := fmt.Sprintf("%s.json.gz", dt.hostname)
			if path.Base(*object.Key) == expectedName {
				continue
			}

			// Download and process peer state
			if err := dt.downloadPeerState(*object.Key); err != nil {
				dt.logger.Debug("Failed to download peer state",
					"key", *object.Key,
					"error", err)
			}
		}
	}

	return nil
}

// downloadPeerState downloads and processes a peer's connection state from S3
func (dt *DistributedTracker) downloadPeerState(objectKey string) error {
	if dt.s3Client == nil {
		return fmt.Errorf("S3 client not initialized")
	}

	result, err := dt.s3Client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(dt.s3Bucket),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return fmt.Errorf("failed to get object: %w", err)
	}
	defer result.Body.Close()

	// Decompress
	gzReader, err := gzip.NewReader(result.Body)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Read and unmarshal
	data, err := io.ReadAll(gzReader)
	if err != nil {
		return fmt.Errorf("failed to read: %w", err)
	}

	var snapshot ConnectionSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return fmt.Errorf("failed to unmarshal: %w", err)
	}

	// Process the update (same as memberlist gossip)
	dt.handleGossipMessage(data)

	return nil
}

// GetGlobalStats returns connection statistics across the cluster
func (dt *DistributedTracker) GetGlobalStats() (localTotal, estimatedGlobalTotal, uniqueIPs int, topIPs map[string]int) {
	localTotal, _, localPerIP := dt.local.GetStats()

	dt.peerMu.RLock()
	defer dt.peerMu.RUnlock()

	// Aggregate all IPs across cluster
	globalPerIP := make(map[string]int)
	for ip, count := range localPerIP {
		globalPerIP[ip] = count
	}

	peerTotal := 0
	for _, peerState := range dt.peerConnections {
		// Skip stale peers
		if time.Since(peerState.UpdatedAt) > 30*time.Second {
			continue
		}

		peerTotal += peerState.TotalCount
		for ip, count := range peerState.Connections {
			globalPerIP[ip] += count
		}
	}

	return localTotal, localTotal + peerTotal, len(globalPerIP), globalPerIP
}

// parseAddr extracts IP from "IP:port" format
func parseAddr(addr string) (string, string, error) {
	// Try to parse as IP:port
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// If no port, assume it's just an IP
		return addr, "", nil
	}
	return host, port, nil
}

// --- EventDelegate Interface Implementation ---

// NotifyJoin is called when a node joins the cluster
func (dt *DistributedTracker) NotifyJoin(node *memberlist.Node) {
	dt.logger.Info("Peer joined - expecting state sync",
		"peer", node.Name,
		"addr", node.Address())
}

// NotifyLeave is called when a node leaves the cluster gracefully
func (dt *DistributedTracker) NotifyLeave(node *memberlist.Node) {
	nodeName := node.Name

	dt.peerMu.Lock()
	if _, exists := dt.peerConnections[nodeName]; exists {
		delete(dt.peerConnections, nodeName)
		dt.logger.Info("Proactively removed peer state on leave event",
			"peer", nodeName,
			"addr", node.Address())
	}
	dt.peerMu.Unlock()
}

// NotifyUpdate is called when a node's metadata is updated
func (dt *DistributedTracker) NotifyUpdate(node *memberlist.Node) {
	dt.logger.Debug("Peer updated",
		"peer", node.Name,
		"addr", node.Address())
}

// SetName sets a custom health checker name (e.g. "distributed_connections:mx-primary").
func (dt *DistributedTracker) SetName(name string) {
	dt.name = name
}

// Name returns the name of this health checker
func (dt *DistributedTracker) Name() string {
	if dt.name != "" {
		return dt.name
	}
	return "distributed_connections"
}

// SetServerName sets the config server name for this distributed tracker.
// This is used for per-server statistics tracking. Safe to call after creation.
func (dt *DistributedTracker) SetServerName(serverName string) {
	dt.serverName = serverName
	if dt.local != nil {
		dt.local.SetServerName(serverName)
	}
}

// GetServerName returns the config server name (implements stats.ConnectionTracker interface).
// This is lock-free and safe for concurrent use.
func (dt *DistributedTracker) GetServerName() string {
	return dt.serverName
}

// CheckHealth reports the health status of the distributed connection tracker
func (dt *DistributedTracker) CheckHealth() health.ComponentStatus {
	localTotal, globalTotal, uniqueIPs, _ := dt.GetGlobalStats()

	// Count active peers
	dt.peerMu.RLock()
	activePeers := 0
	stalePeers := 0
	for _, peerState := range dt.peerConnections {
		if time.Since(peerState.UpdatedAt) > 30*time.Second {
			stalePeers++
		} else {
			activePeers++
		}
	}
	dt.peerMu.RUnlock()

	// Get cluster members count
	clusterMembers := 0
	if dt.cluster != nil {
		clusterMembers = dt.cluster.NumMembers()
	}

	// Determine status
	status := "healthy"
	if clusterMembers > 1 && activePeers == 0 {
		// We have cluster members but none are sending gossip
		status = "degraded"
	}

	return health.ComponentStatus{
		Status: status,
		Details: map[string]any{
			"local_connections":  localTotal,
			"global_connections": globalTotal,
			"unique_ips":         uniqueIPs,
			"cluster_members":    clusterMembers,
			"active_peers":       activePeers,
			"stale_peers":        stalePeers,
			"global_max_per_ip":  dt.globalMaxPerIP,
		},
	}
}

// FlushCache clears the recipient cache and returns the number of flushed entries.
// This method implements the health.CacheFlusher interface.
func (dt *DistributedTracker) FlushCache() map[string]int {
	dt.recipientMu.Lock()
	defer dt.recipientMu.Unlock()

	flushedCounts := make(map[string]int)

	flushedCounts["recipient_not_found"] = len(dt.recipientNotFound)
	flushedCounts["recipient_blocked"] = len(dt.recipientBlocked)

	// Re-initialize the maps to clear them
	dt.recipientNotFound = make(map[string]time.Time)
	dt.recipientBlocked = make(map[string]time.Time)

	dt.logger.Info("Recipient cache flushed via API",
		"not_found_flushed", flushedCounts["recipient_not_found"],
		"blocked_flushed", flushedCounts["recipient_blocked"])

	return flushedCounts
}

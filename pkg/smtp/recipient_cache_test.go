package smtp

import (
	"io"

	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"log/slog"
)

// TestRecipientCache_NotFoundCaching tests that 404 responses are cached
func TestRecipientCache_NotFoundCaching(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	local := NewConnectionTracker(100, 10, 0, nil)
	dt := NewDistributedTracker(
		local,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:          "server1",
			Cluster:           newMockCluster(),
			GossipInterval:    1 * time.Hour, // Don't gossip during test
			S3SyncInterval:    1 * time.Hour,
			GlobalMaxPerIP:    20,
			RecipientCacheTTL: 5 * time.Minute,
		},
		logger,
	)

	// Initially, recipient should not be cached
	found, _, _ := dt.IsRecipientCached("user@example.com")
	if found {
		t.Fatal("Expected recipient to not be cached initially")
	}

	// Cache the recipient as not found
	dt.CacheRecipientNotFound("user@example.com")

	// Now it should be cached
	found, isBlocked, reason := dt.IsRecipientCached("user@example.com")
	if !found {
		t.Fatal("Expected recipient to be cached")
	}
	if isBlocked {
		t.Fatal("Expected recipient to be marked as 'not found', not 'blocked'")
	}
	if reason != "recipient not found (cached)" {
		t.Fatalf("Expected reason 'recipient not found (cached)', got: %s", reason)
	}
}

// TestRecipientCache_BlockedCaching tests that 403 responses are cached
func TestRecipientCache_BlockedCaching(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	local := NewConnectionTracker(100, 10, 0, nil)
	dt := NewDistributedTracker(
		local,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:          "server1",
			Cluster:           newMockCluster(),
			GossipInterval:    1 * time.Hour,
			S3SyncInterval:    1 * time.Hour,
			GlobalMaxPerIP:    20,
			RecipientCacheTTL: 5 * time.Minute,
		},
		logger,
	)

	// Cache the recipient as blocked
	dt.CacheRecipientBlocked("blocked@example.com")

	// Should be cached and marked as blocked
	found, isBlocked, reason := dt.IsRecipientCached("blocked@example.com")
	if !found {
		t.Fatal("Expected recipient to be cached")
	}
	if !isBlocked {
		t.Fatal("Expected recipient to be marked as 'blocked'")
	}
	if reason != "recipient blocked by destination (cached)" {
		t.Fatalf("Expected reason 'recipient blocked by destination (cached)', got: %s", reason)
	}
}

// TestRecipientCache_Expiry tests that cached entries expire
func TestRecipientCache_Expiry(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	local := NewConnectionTracker(100, 10, 0, nil)
	dt := NewDistributedTracker(
		local,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:          "server1",
			Cluster:           newMockCluster(),
			GossipInterval:    1 * time.Hour,
			S3SyncInterval:    1 * time.Hour,
			GlobalMaxPerIP:    20,
			RecipientCacheTTL: 100 * time.Millisecond, // Very short TTL for testing
		},
		logger,
	)

	// Cache a recipient
	dt.CacheRecipientNotFound("temp@example.com")

	// Should be cached immediately
	found, _, _ := dt.IsRecipientCached("temp@example.com")
	if !found {
		t.Fatal("Expected recipient to be cached")
	}

	// Wait for expiry
	time.Sleep(150 * time.Millisecond)

	// Should no longer be cached
	found, _, _ = dt.IsRecipientCached("temp@example.com")
	if found {
		t.Fatal("Expected recipient cache to expire")
	}
}

// TestRecipientCache_GossipPropagation tests that cache entries are gossiped between servers
func TestRecipientCache_GossipPropagation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create server 1
	local1 := NewConnectionTracker(100, 10, 0, nil)
	dt1 := NewDistributedTracker(
		local1,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:          "server1",
			Cluster:           newMockCluster(),
			GossipInterval:    1 * time.Hour,
			S3SyncInterval:    1 * time.Hour,
			GlobalMaxPerIP:    20,
			RecipientCacheTTL: 5 * time.Minute,
		},
		logger,
	)

	// Create server 2
	local2 := NewConnectionTracker(100, 10, 0, nil)
	dt2 := NewDistributedTracker(
		local2,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:          "server2",
			Cluster:           newMockCluster(),
			GossipInterval:    1 * time.Hour,
			S3SyncInterval:    1 * time.Hour,
			GlobalMaxPerIP:    20,
			RecipientCacheTTL: 5 * time.Minute,
		},
		logger,
	)

	// Server 1 caches a recipient
	dt1.CacheRecipientNotFound("user@example.com")
	dt1.CacheRecipientBlocked("blocked@example.com")

	// Server 2 should not have it yet
	found, _, _ := dt2.IsRecipientCached("user@example.com")
	if found {
		t.Fatal("Server 2 should not have cached recipient yet")
	}

	// Create snapshot from server 1 (simulating gossip)
	snapshot := dt1.createSnapshot()

	// Server 2 processes the update (simulating receiving gossip)
	snapshotJSON, _ := json.Marshal(snapshot)
	dt2.handleGossipMessage(snapshotJSON)

	// Now server 2 should have the cached entries
	found, isBlocked, reason := dt2.IsRecipientCached("user@example.com")
	if !found {
		t.Fatal("Server 2 should have received cached recipient via gossip")
	}
	if isBlocked {
		t.Fatal("Expected recipient to be marked as 'not found', not 'blocked'")
	}
	if reason != "recipient not found (cached)" {
		t.Fatalf("Expected reason 'recipient not found (cached)', got: %s", reason)
	}

	// Check blocked recipient
	found, isBlocked, reason = dt2.IsRecipientCached("blocked@example.com")
	if !found {
		t.Fatal("Server 2 should have received blocked recipient via gossip")
	}
	if !isBlocked {
		t.Fatal("Expected recipient to be marked as 'blocked'")
	}
	if reason != "recipient blocked by destination (cached)" {
		t.Fatalf("Expected reason 'recipient blocked by destination (cached)', got: %s", reason)
	}
}

// TestRecipientCache_MergeStrategy tests that the merge keeps the latest expiry
func TestRecipientCache_MergeStrategy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	local := NewConnectionTracker(100, 10, 0, nil)
	dt := NewDistributedTracker(
		local,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:          "server1",
			Cluster:           newMockCluster(),
			GossipInterval:    1 * time.Hour,
			S3SyncInterval:    1 * time.Hour,
			GlobalMaxPerIP:    20,
			RecipientCacheTTL: 5 * time.Minute,
		},
		logger,
	)

	// Cache a recipient with current expiry
	dt.CacheRecipientNotFound("user@example.com")

	// Get the current expiry
	dt.recipientMu.RLock()
	originalExpiry := dt.recipientNotFound["user@example.com"]
	dt.recipientMu.RUnlock()

	// Create a peer snapshot with a later expiry (10 minutes from now)
	futureExpiry := time.Now().Add(10 * time.Minute)
	peerCache := &RecipientCacheSnapshot{
		NotFound: map[string]time.Time{
			"user@example.com": futureExpiry,
		},
	}

	// Merge the peer cache
	dt.mergeRecipientCache(peerCache)

	// Should have the later expiry
	dt.recipientMu.RLock()
	newExpiry := dt.recipientNotFound["user@example.com"]
	dt.recipientMu.RUnlock()

	if !newExpiry.After(originalExpiry) {
		t.Fatal("Expected merge to keep the later expiry time")
	}

	if newExpiry != futureExpiry {
		t.Fatalf("Expected expiry to be %v, got %v", futureExpiry, newExpiry)
	}
}

// TestRecipientCache_HTTPEndToEnd tests the complete HTTP handler flow
func TestRecipientCache_HTTPEndToEnd(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create server 1 with HTTP handler
	local1 := NewConnectionTracker(100, 10, 0, nil)
	dt1 := NewDistributedTracker(
		local1,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:          "server1",
			Cluster:           newMockCluster(),
			GossipInterval:    1 * time.Hour,
			S3SyncInterval:    1 * time.Hour,
			GlobalMaxPerIP:    20,
			RecipientCacheTTL: 5 * time.Minute,
		},
		logger,
	)

	// Cache some recipients on server 1
	dt1.CacheRecipientNotFound("user1@example.com")
	dt1.CacheRecipientBlocked("user2@example.com")

	// Create server 2
	local2 := NewConnectionTracker(100, 10, 0, nil)
	mockCluster2 := newMockCluster()
	dt2 := NewDistributedTracker(
		local2,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:          "server2",
			Cluster:           mockCluster2,
			GossipInterval:    1 * time.Hour,
			S3SyncInterval:    1 * time.Hour,
			GlobalMaxPerIP:    20,
			RecipientCacheTTL: 5 * time.Minute,
		},
		logger,
	)

	// Server 1 sends its snapshot to server 2 (via memberlist gossip)
	snapshot := dt1.createSnapshot()
	snapshotJSON, _ := json.Marshal(snapshot)
	mockCluster2.simulateIncomingGossip(snapshotJSON)

	// Verify server 2 received the cache from server 1
	found, _, _ := dt2.IsRecipientCached("user1@example.com")
	if !found {
		t.Error("Expected server 2 to have user1@example.com in cache")
	}

	found, isBlocked, _ := dt2.IsRecipientCached("user2@example.com")
	if !found || !isBlocked {
		t.Error("Expected server 2 to have user2@example.com as blocked in cache")
	}
}

// TestRecipientCache_TwoServerIntegration is a comprehensive integration test
// that simulates two SMTP servers gossiping recipient cache entries via memberlist
func TestRecipientCache_TwoServerIntegration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create two servers with mock clusters
	servers := make([]*DistributedTracker, 2)
	mockClusters := make([]*mockCluster, 2)

	for i := 0; i < 2; i++ {
		local := NewConnectionTracker(100, 10, 0, nil)
		mockCluster := newMockCluster()
		mockClusters[i] = mockCluster

		dt := NewDistributedTracker(
			local,
			nil,
			"",
			"",
			DistributedConfig{
				Hostname:          fmt.Sprintf("server%d", i+1),
				Cluster:           mockCluster,
				GossipInterval:    100 * time.Millisecond, // Fast gossip for testing
				S3SyncInterval:    1 * time.Hour,
				GlobalMaxPerIP:    20,
				RecipientCacheTTL: 5 * time.Minute,
			},
			logger,
		)
		servers[i] = dt
	}
	defer func() {
		for _, dt := range servers {
			dt.Stop()
		}
	}()

	t.Log("✓ Created two test servers")

	// Server 1 caches a 404 recipient
	servers[0].CacheRecipientNotFound("notfound@example.com")
	t.Log("✓ Server 1 cached notfound@example.com as 404")

	// Server 2 caches a 403 recipient
	servers[1].CacheRecipientBlocked("blocked@example.com")
	t.Log("✓ Server 2 cached blocked@example.com as 403")

	// Verify initial state - each server only has its own cache
	if found, _, _ := servers[0].IsRecipientCached("blocked@example.com"); found {
		t.Fatal("Server 1 should not have blocked@example.com yet")
	}
	if found, _, _ := servers[1].IsRecipientCached("notfound@example.com"); found {
		t.Fatal("Server 2 should not have notfound@example.com yet")
	}
	t.Log("✓ Verified initial cache isolation")

	// Simulate gossip exchange: server 1 broadcasts to server 2
	snapshot1 := servers[0].createSnapshot()
	snapshot1JSON, _ := json.Marshal(snapshot1)
	mockClusters[1].simulateIncomingGossip(snapshot1JSON)
	t.Log("✓ Server 1 broadcasted to Server 2")

	// Simulate gossip exchange: server 2 broadcasts to server 1
	snapshot2 := servers[1].createSnapshot()
	snapshot2JSON, _ := json.Marshal(snapshot2)
	mockClusters[0].simulateIncomingGossip(snapshot2JSON)
	t.Log("✓ Server 2 broadcasted to Server 1")

	// Verify that cache entries have propagated
	// Server 1 should now have Server 2's blocked recipient
	found, isBlocked, reason := servers[0].IsRecipientCached("blocked@example.com")
	if !found {
		t.Fatal("Server 1 should have received blocked@example.com from Server 2")
	}
	if !isBlocked {
		t.Fatal("Server 1 should have received blocked@example.com as 'blocked'")
	}
	if reason != "recipient blocked by destination (cached)" {
		t.Fatalf("Server 1: Expected reason 'recipient blocked by destination (cached)', got: %s", reason)
	}
	t.Log("✓ Server 1 received blocked@example.com from Server 2")

	// Server 2 should now have Server 1's not found recipient
	found, isBlocked, reason = servers[1].IsRecipientCached("notfound@example.com")
	if !found {
		t.Fatal("Server 2 should have received notfound@example.com from Server 1")
	}
	if isBlocked {
		t.Fatal("Server 2 should have received notfound@example.com as 'not found'")
	}
	if reason != "recipient not found (cached)" {
		t.Fatalf("Server 2: Expected reason 'recipient not found (cached)', got: %s", reason)
	}
	t.Log("✓ Server 2 received notfound@example.com from Server 1")

	// Add a new recipient to Server 2
	servers[1].CacheRecipientNotFound("newuser@example.com")
	t.Log("✓ Server 2 cached newuser@example.com")

	// Simulate another gossip round from server 2 to server 1
	snapshot2Again := servers[1].createSnapshot()
	snapshot2AgainJSON, _ := json.Marshal(snapshot2Again)
	mockClusters[0].simulateIncomingGossip(snapshot2AgainJSON)
	t.Log("✓ Server 2 broadcasted again to Server 1")

	// Server 1 should receive it
	found, _, _ = servers[0].IsRecipientCached("newuser@example.com")
	if !found {
		t.Fatal("Server 1 should have received newuser@example.com from Server 2")
	}
	t.Log("✓ Server 1 received newuser@example.com from Server 2")

	t.Log("✅ Integration test passed: Two servers successfully gossip recipient cache entries")
}

// TestRecipientCache_CleanupExpiredEntries tests the automatic cleanup
func TestRecipientCache_CleanupExpiredEntries(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	local := NewConnectionTracker(100, 10, 0, nil)
	dt := NewDistributedTracker(
		local,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:          "server1",
			Cluster:           newMockCluster(),
			GossipInterval:    1 * time.Hour,
			S3SyncInterval:    1 * time.Hour,
			GlobalMaxPerIP:    20,
			RecipientCacheTTL: 50 * time.Millisecond, // Very short for testing
		},
		logger,
	)

	// Cache multiple recipients
	dt.CacheRecipientNotFound("user1@example.com")
	dt.CacheRecipientNotFound("user2@example.com")
	dt.CacheRecipientBlocked("user3@example.com")

	// Verify they're cached
	dt.recipientMu.RLock()
	notFoundCount := len(dt.recipientNotFound)
	blockedCount := len(dt.recipientBlocked)
	dt.recipientMu.RUnlock()

	if notFoundCount != 2 {
		t.Fatalf("Expected 2 not-found entries, got %d", notFoundCount)
	}
	if blockedCount != 1 {
		t.Fatalf("Expected 1 blocked entry, got %d", blockedCount)
	}

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	// Run cleanup
	dt.cleanupExpiredRecipients()

	// All entries should be removed
	dt.recipientMu.RLock()
	notFoundCount = len(dt.recipientNotFound)
	blockedCount = len(dt.recipientBlocked)
	dt.recipientMu.RUnlock()

	if notFoundCount != 0 {
		t.Fatalf("Expected 0 not-found entries after cleanup, got %d", notFoundCount)
	}
	if blockedCount != 0 {
		t.Fatalf("Expected 0 blocked entries after cleanup, got %d", blockedCount)
	}

	t.Log("✓ Cleanup successfully removed expired entries")
}

// TestRecipientCache_ClearAfterValidation tests that ClearRecipientCache removes stale entries
// This prevents the bug where a recipient passes RCPT TO validation but is then
// rejected during DATA by a stale cached 404/403 from a previous delivery attempt.
func TestRecipientCache_ClearAfterValidation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	local := NewConnectionTracker(100, 10, 0, nil)
	dt := NewDistributedTracker(
		local,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:          "server1",
			Cluster:           newMockCluster(),
			GossipInterval:    1 * time.Hour,
			S3SyncInterval:    1 * time.Hour,
			GlobalMaxPerIP:    20,
			RecipientCacheTTL: 5 * time.Minute,
		},
		logger,
	)

	// Simulate a previous delivery returning 404 — recipient gets cached as "not found"
	dt.CacheRecipientNotFound("user@example.com")

	// Verify it's cached
	found, _, _ := dt.IsRecipientCached("user@example.com")
	if !found {
		t.Fatal("Expected recipient to be cached as not found")
	}

	// Now simulate recipient validation passing (recipient exists again)
	// This should clear the stale cache entry
	dt.ClearRecipientCache("user@example.com")

	// The cache entry should be gone
	found, _, _ = dt.IsRecipientCached("user@example.com")
	if found {
		t.Fatal("Expected recipient cache to be cleared after successful validation")
	}
}

// TestRecipientCache_ClearBlockedAfterValidation tests clearing a blocked entry
func TestRecipientCache_ClearBlockedAfterValidation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	local := NewConnectionTracker(100, 10, 0, nil)
	dt := NewDistributedTracker(
		local,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:          "server1",
			Cluster:           newMockCluster(),
			GossipInterval:    1 * time.Hour,
			S3SyncInterval:    1 * time.Hour,
			GlobalMaxPerIP:    20,
			RecipientCacheTTL: 5 * time.Minute,
		},
		logger,
	)

	// Simulate a previous delivery returning 403 — recipient gets cached as "blocked"
	dt.CacheRecipientBlocked("user@example.com")

	found, isBlocked, _ := dt.IsRecipientCached("user@example.com")
	if !found || !isBlocked {
		t.Fatal("Expected recipient to be cached as blocked")
	}

	// Clear after validation passes
	dt.ClearRecipientCache("user@example.com")

	found, _, _ = dt.IsRecipientCached("user@example.com")
	if found {
		t.Fatal("Expected blocked cache to be cleared after successful validation")
	}
}

// TestRecipientCache_ClearNonExistent tests that clearing a non-cached recipient is a no-op
func TestRecipientCache_ClearNonExistent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	local := NewConnectionTracker(100, 10, 0, nil)
	dt := NewDistributedTracker(
		local,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:          "server1",
			Cluster:           newMockCluster(),
			GossipInterval:    1 * time.Hour,
			S3SyncInterval:    1 * time.Hour,
			GlobalMaxPerIP:    20,
			RecipientCacheTTL: 5 * time.Minute,
		},
		logger,
	)

	// Clearing a non-existent entry should not panic or error
	dt.ClearRecipientCache("nonexistent@example.com")

	// Other entries should be unaffected
	dt.CacheRecipientNotFound("other@example.com")
	found, _, _ := dt.IsRecipientCached("other@example.com")
	if !found {
		t.Fatal("Expected other recipient to still be cached")
	}
}

// TestRecipientCache_ClearDoesNotAffectOtherEntries tests selective clearing
func TestRecipientCache_ClearDoesNotAffectOtherEntries(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	local := NewConnectionTracker(100, 10, 0, nil)
	dt := NewDistributedTracker(
		local,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:          "server1",
			Cluster:           newMockCluster(),
			GossipInterval:    1 * time.Hour,
			S3SyncInterval:    1 * time.Hour,
			GlobalMaxPerIP:    20,
			RecipientCacheTTL: 5 * time.Minute,
		},
		logger,
	)

	// Cache multiple recipients
	dt.CacheRecipientNotFound("user1@example.com")
	dt.CacheRecipientNotFound("user2@example.com")
	dt.CacheRecipientBlocked("user3@example.com")

	// Clear only user1
	dt.ClearRecipientCache("user1@example.com")

	// user1 should be gone
	found, _, _ := dt.IsRecipientCached("user1@example.com")
	if found {
		t.Fatal("Expected user1 to be cleared")
	}

	// user2 and user3 should still be cached
	found, _, _ = dt.IsRecipientCached("user2@example.com")
	if !found {
		t.Fatal("Expected user2 to still be cached")
	}
	found, isBlocked, _ := dt.IsRecipientCached("user3@example.com")
	if !found || !isBlocked {
		t.Fatal("Expected user3 to still be cached as blocked")
	}
}

// TestRecipientCache_ConcurrentAccess tests thread safety
func TestRecipientCache_ConcurrentAccess(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	local := NewConnectionTracker(100, 10, 0, nil)
	dt := NewDistributedTracker(
		local,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:          "server1",
			Cluster:           newMockCluster(),
			GossipInterval:    1 * time.Hour,
			S3SyncInterval:    1 * time.Hour,
			GlobalMaxPerIP:    20,
			RecipientCacheTTL: 5 * time.Minute,
		},
		logger,
	)

	var wg sync.WaitGroup
	concurrency := 100

	// Concurrent writes
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			email := fmt.Sprintf("user%d@example.com", idx)
			if idx%2 == 0 {
				dt.CacheRecipientNotFound(email)
			} else {
				dt.CacheRecipientBlocked(email)
			}
		}(i)
	}

	// Concurrent reads
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			email := fmt.Sprintf("user%d@example.com", idx)
			dt.IsRecipientCached(email)
		}(i)
	}

	wg.Wait()

	// Verify all entries were added
	dt.recipientMu.RLock()
	totalEntries := len(dt.recipientNotFound) + len(dt.recipientBlocked)
	dt.recipientMu.RUnlock()

	if totalEntries != concurrency {
		t.Fatalf("Expected %d total entries, got %d", concurrency, totalEntries)
	}

	t.Log("✓ Concurrent access test passed")
}

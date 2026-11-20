package smtp

import (
	"io"

	"encoding/json"
	"migadu/mizu/pkg/cluster"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"log/slog"
)

// mockCluster is a test implementation of ClusterManager
type mockCluster struct {
	broadcasts [][]byte
	handler    func(data []byte)
	mu         sync.Mutex
}

func newMockCluster() *mockCluster {
	return &mockCluster{
		broadcasts: make([][]byte, 0),
	}
}

func (m *mockCluster) BroadcastConnectionState(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.broadcasts = append(m.broadcasts, data)
	return nil
}

func (m *mockCluster) RegisterConnectionStateHandler(handler func(data []byte)) {
	m.handler = handler
}

func (m *mockCluster) NumMembers() int {
	return 1
}

func (m *mockCluster) SetStateDelegate(delegate cluster.StateDelegate) {
	// Mock implementation - does nothing
}

func (m *mockCluster) SetEventDelegate(delegate cluster.EventDelegate) {
	// Mock implementation - does nothing
}

func (m *mockCluster) simulateIncomingGossip(data []byte) {
	if m.handler != nil {
		m.handler(data)
	}
}

// TestDistributedTracker_LocalAndGlobalLimits tests that both local and global limits are enforced
func TestDistributedTracker_LocalAndGlobalLimits(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Local tracker: max 5 per IP, max 10 total
	local := NewConnectionTracker(10, 5, 0, nil)

	// Distributed tracker: global max 8 per IP across cluster
	mockCluster := newMockCluster()
	dt := NewDistributedTracker(
		local,
		nil, // No S3
		"",
		"",
		DistributedConfig{
			Hostname:       "server1",
			Cluster:        mockCluster,
			GossipInterval: 1 * time.Hour, // Don't gossip during test
			S3SyncInterval: 1 * time.Hour,
			GlobalMaxPerIP: 8,
		},
		logger,
	)

	// Acquire 5 connections locally (local limit)
	for i := 0; i < 5; i++ {
		if _, err := dt.Acquire("192.168.1.100:5000"); err != nil {
			t.Fatalf("Expected to acquire connection %d, got error: %v", i+1, err)
		}
	}

	// 6th connection should fail (local limit reached)
	if _, err := dt.Acquire("192.168.1.100:5000"); err == nil {
		t.Fatal("Expected error when exceeding local per-IP limit, got nil")
	}

	// Simulate peer having 4 connections from same IP
	dt.peerMu.Lock()
	dt.peerConnections["server2"] = &PeerConnectionState{
		Hostname:  "server2",
		Timestamp: time.Now(),
		Connections: map[string]int{
			"192.168.1.100": 4,
		},
		TotalCount: 4,
		UpdatedAt:  time.Now(),
	}
	dt.peerMu.Unlock()

	// Now we have 5 local + 4 peer = 9 total for this IP
	// Global limit is 8, so new connection should fail even though local has room
	if _, err := dt.Acquire("192.168.1.100:5001"); err == nil {
		t.Fatal("Expected error when exceeding global per-IP limit, got nil")
	}

	// Different IP should still work
	if _, err := dt.Acquire("192.168.1.200:5000"); err != nil {
		t.Fatalf("Expected to acquire connection from different IP, got error: %v", err)
	}
}

// TestDistributedTracker_StalePerrsIgnored tests that stale peer data is ignored
func TestDistributedTracker_StalePeersIgnored(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	local := NewConnectionTracker(100, 10, 0, nil)
	mockCluster := newMockCluster()
	dt := NewDistributedTracker(
		local,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:       "server1",
			Cluster:        mockCluster,
			GossipInterval: 1 * time.Hour,
			S3SyncInterval: 1 * time.Hour,
			GlobalMaxPerIP: 15,
		},
		logger,
	)

	// Acquire 5 connections locally
	for i := 0; i < 5; i++ {
		if _, err := dt.Acquire("192.168.1.100:5000"); err != nil {
			t.Fatalf("Failed to acquire connection %d: %v", i+1, err)
		}
	}

	// Add stale peer data (31 seconds old)
	dt.peerMu.Lock()
	dt.peerConnections["server2"] = &PeerConnectionState{
		Hostname:  "server2",
		Timestamp: time.Now().Add(-31 * time.Second),
		Connections: map[string]int{
			"192.168.1.100": 100, // This should be ignored
		},
		TotalCount: 100,
		UpdatedAt:  time.Now().Add(-31 * time.Second),
	}
	dt.peerMu.Unlock()

	// Should succeed because stale peer data is ignored
	// Local: 5, Stale peer: 100 (ignored), Global limit: 15
	if _, err := dt.Acquire("192.168.1.100:5001"); err != nil {
		t.Fatalf("Expected to acquire connection (stale peer should be ignored), got error: %v", err)
	}
}

// TestDistributedTracker_GossipHandler tests memberlist gossip handling
func TestDistributedTracker_GossipHandler(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	local := NewConnectionTracker(100, 10, 0, nil)
	mockCluster := newMockCluster()
	dt := NewDistributedTracker(
		local,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:       "server1",
			Cluster:        mockCluster,
			GossipInterval: 1 * time.Hour,
			S3SyncInterval: 1 * time.Hour,
			GlobalMaxPerIP: 20,
		},
		logger,
	)

	// Acquire some connections
	dt.Acquire("192.168.1.100:5000")
	dt.Acquire("192.168.1.100:5001")
	dt.Acquire("192.168.1.101:5000")

	// Create a peer snapshot to send via gossip
	peerSnapshot := ConnectionSnapshot{
		Hostname:  "server2",
		Timestamp: time.Now(),
		Connections: map[string]int{
			"192.168.1.200": 5,
		},
		TotalCount: 5,
	}

	// Simulate receiving gossip from peer
	peerJSON, _ := json.Marshal(peerSnapshot)
	mockCluster.simulateIncomingGossip(peerJSON)

	// Verify peer data was stored
	dt.peerMu.RLock()
	stored, ok := dt.peerConnections["server2"]
	dt.peerMu.RUnlock()

	if !ok {
		t.Fatal("Expected peer 'server2' to be stored")
	}

	if stored.Connections["192.168.1.200"] != 5 {
		t.Errorf("Expected peer to have 5 connections from 192.168.1.200, got %d",
			stored.Connections["192.168.1.200"])
	}
}

// TestDistributedTracker_GetGlobalStats tests global statistics aggregation
func TestDistributedTracker_GetGlobalStats(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	local := NewConnectionTracker(100, 10, 0, nil)
	mockCluster := newMockCluster()
	dt := NewDistributedTracker(
		local,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:       "server1",
			Cluster:        mockCluster,
			GossipInterval: 1 * time.Hour,
			S3SyncInterval: 1 * time.Hour,
			GlobalMaxPerIP: 20,
		},
		logger,
	)

	// Acquire 5 connections from 2 IPs locally
	for i := 0; i < 3; i++ {
		dt.Acquire("192.168.1.100:5000")
	}
	for i := 0; i < 2; i++ {
		dt.Acquire("192.168.1.101:5000")
	}

	// Add peer data
	dt.peerMu.Lock()
	dt.peerConnections["server2"] = &PeerConnectionState{
		Hostname:  "server2",
		Timestamp: time.Now(),
		Connections: map[string]int{
			"192.168.1.100": 2, // Same IP as local
			"192.168.1.102": 4, // Different IP
		},
		TotalCount: 6,
		UpdatedAt:  time.Now(),
	}
	dt.peerMu.Unlock()

	localTotal, globalTotal, uniqueIPs, topIPs := dt.GetGlobalStats()

	// Local should have 5 connections
	if localTotal != 5 {
		t.Errorf("Expected local total 5, got %d", localTotal)
	}

	// Global should be 5 (local) + 6 (peer) = 11
	if globalTotal != 11 {
		t.Errorf("Expected global total 11, got %d", globalTotal)
	}

	// Unique IPs: 192.168.1.100, 192.168.1.101, 192.168.1.102 = 3
	if uniqueIPs != 3 {
		t.Errorf("Expected 3 unique IPs, got %d", uniqueIPs)
	}

	// Check aggregated counts per IP
	if topIPs["192.168.1.100"] != 5 { // 3 local + 2 peer
		t.Errorf("Expected 192.168.1.100 to have 5 connections, got %d", topIPs["192.168.1.100"])
	}
	if topIPs["192.168.1.101"] != 2 {
		t.Errorf("Expected 192.168.1.101 to have 2 connections, got %d", topIPs["192.168.1.101"])
	}
	if topIPs["192.168.1.102"] != 4 {
		t.Errorf("Expected 192.168.1.102 to have 4 connections, got %d", topIPs["192.168.1.102"])
	}
}

// TestDistributedTracker_ConcurrentAccess tests thread safety
func TestDistributedTracker_ConcurrentAccess(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	local := NewConnectionTracker(1000, 50, 0, nil)
	mockCluster := newMockCluster()
	dt := NewDistributedTracker(
		local,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:       "server1",
			Cluster:        mockCluster,
			GossipInterval: 1 * time.Hour,
			S3SyncInterval: 1 * time.Hour,
			GlobalMaxPerIP: 100,
		},
		logger,
	)

	var wg sync.WaitGroup
	concurrency := 50
	operationsPerGoroutine := 100

	// Concurrent acquire/release
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			addr := "192.168.1.100:5000"
			for j := 0; j < operationsPerGoroutine; j++ {
				if lease, err := dt.Acquire(addr); err == nil {
					lease.Release()
				}
			}
		}(i)
	}

	// Concurrent peer updates
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				dt.peerMu.Lock()
				dt.peerConnections["peer"+string(rune(id))] = &PeerConnectionState{
					Hostname:    "peer" + string(rune(id)),
					Timestamp:   time.Now(),
					Connections: map[string]int{"192.168.1.200": j},
					TotalCount:  j,
					UpdatedAt:   time.Now(),
				}
				dt.peerMu.Unlock()
			}
		}(i)
	}

	// Concurrent stats reads
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				dt.GetGlobalStats()
			}
		}()
	}

	wg.Wait()

	// Should have no connections left (all released)
	localTotal, _, _, _ := dt.GetGlobalStats()
	if localTotal != 0 {
		t.Errorf("Expected 0 local connections after cleanup, got %d", localTotal)
	}
}

// TestDistributedTracker_ReleaseRollback tests rollback on global limit failure
func TestDistributedTracker_ReleaseRollback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	local := NewConnectionTracker(100, 10, 0, nil)
	mockCluster := newMockCluster()
	dt := NewDistributedTracker(
		local,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:       "server1",
			Cluster:        mockCluster,
			GossipInterval: 1 * time.Hour,
			S3SyncInterval: 1 * time.Hour,
			GlobalMaxPerIP: 8,
		},
		logger,
	)

	// Acquire 5 locally
	for i := 0; i < 5; i++ {
		if _, err := dt.Acquire("192.168.1.100:5000"); err != nil {
			t.Fatalf("Failed to acquire connection %d: %v", i+1, err)
		}
	}

	// Simulate peer with 5 connections (total = 10, exceeds global limit of 8)
	dt.peerMu.Lock()
	dt.peerConnections["server2"] = &PeerConnectionState{
		Hostname:  "server2",
		Timestamp: time.Now(),
		Connections: map[string]int{
			"192.168.1.100": 5,
		},
		TotalCount: 5,
		UpdatedAt:  time.Now(),
	}
	dt.peerMu.Unlock()

	// Try to acquire 6th connection - should fail global limit
	if _, err := dt.Acquire("192.168.1.100:5001"); err == nil {
		t.Fatal("Expected error due to global limit, got nil")
	}

	// Verify local count is still 5 (rollback worked)
	localTotal, _, _, topIPs := dt.GetGlobalStats()
	if localTotal != 5 {
		t.Errorf("Expected local total to remain 5 after rollback, got %d", localTotal)
	}

	if topIPs["192.168.1.100"] != 10 { // 5 local + 5 peer
		t.Errorf("Expected 192.168.1.100 to have 10 total connections, got %d", topIPs["192.168.1.100"])
	}
}

// TestDistributedTracker_HealthCheck tests the health checker interface
func TestDistributedTracker_HealthCheck(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	local := NewConnectionTracker(100, 10, 0, nil)
	mockCluster := newMockCluster()
	dt := NewDistributedTracker(
		local,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:       "server1",
			Cluster:        mockCluster,
			GossipInterval: 5 * time.Second,
			S3SyncInterval: 30 * time.Second,
			GlobalMaxPerIP: 20,
		},
		logger,
	)

	// Initially no peers active - should be healthy (mockCluster always reports 1 member)
	status := dt.CheckHealth()
	if status.Status != "healthy" {
		t.Errorf("Expected status 'healthy', got '%s'", status.Status)
	}

	// Add active peer
	dt.peerMu.Lock()
	dt.peerConnections["server2"] = &PeerConnectionState{
		Hostname:   "server2",
		Timestamp:  time.Now(),
		TotalCount: 10,
		UpdatedAt:  time.Now(),
	}
	dt.peerMu.Unlock()

	status = dt.CheckHealth()
	if status.Status != "healthy" {
		t.Errorf("Expected status 'healthy' with active peer, got '%s'", status.Status)
	}

	details, ok := status.Details.(map[string]any)
	if !ok {
		t.Fatal("Expected details to be map[string]any")
	}
	if details["cluster_members"] != 1 {
		t.Errorf("Expected 1 cluster member (from mockCluster), got %v", details["cluster_members"])
	}
	if details["active_peers"] != 1 {
		t.Errorf("Expected 1 active peer (that we manually added), got %v", details["active_peers"])
	}
}

// TestDistributedTracker_NoGlobalLimit tests behavior when global limit is 0 (disabled)
func TestDistributedTracker_NoGlobalLimit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	local := NewConnectionTracker(100, 5, 0, nil)
	mockCluster := newMockCluster()
	dt := NewDistributedTracker(
		local,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:       "server1",
			Cluster:        mockCluster,
			GossipInterval: 1 * time.Hour,
			S3SyncInterval: 1 * time.Hour,
			GlobalMaxPerIP: 0, // Disabled
		},
		logger,
	)

	// Acquire 5 connections (local limit)
	for i := 0; i < 5; i++ {
		if _, err := dt.Acquire("192.168.1.100:5000"); err != nil {
			t.Fatalf("Failed to acquire connection %d: %v", i+1, err)
		}
	}

	// Add peer with huge number of connections
	dt.peerMu.Lock()
	dt.peerConnections["server2"] = &PeerConnectionState{
		Hostname:  "server2",
		Timestamp: time.Now(),
		Connections: map[string]int{
			"192.168.1.100": 1000,
		},
		TotalCount: 1000,
		UpdatedAt:  time.Now(),
	}
	dt.peerMu.Unlock()

	// 6th connection should fail due to LOCAL limit only (global is disabled)
	if _, err := dt.Acquire("192.168.1.100:5001"); err == nil {
		t.Fatal("Expected error due to local limit, got nil")
	} else if !strings.Contains(err.Error(), "maximum connections per IP") {
		t.Errorf("Expected local limit error, got: %v", err)
	}
}

// TestDistributedTracker_ProactivePeerCleanup tests that peers are removed on leave events
func TestDistributedTracker_ProactivePeerCleanup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockCluster := newMockCluster()

	local := NewConnectionTracker(100, 10, 0, nil)

	dt := NewDistributedTracker(
		local,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:       "server1",
			Cluster:        mockCluster,
			GossipInterval: 1 * time.Hour,
			S3SyncInterval: 1 * time.Hour,
			GlobalMaxPerIP: 10,
		},
		logger,
	)

	// Simulate receiving gossip from a peer (adds peer to peerConnections)
	peerSnapshot := ConnectionSnapshot{
		Hostname:  "server2",
		Timestamp: time.Now(),
		Connections: map[string]int{
			"192.168.1.200": 5,
		},
		TotalCount:  5,
		VectorClock: cluster.NewVectorClock("server2"),
	}
	peerJSON, _ := json.Marshal(peerSnapshot)
	mockCluster.simulateIncomingGossip(peerJSON)

	// Verify peer was added
	dt.peerMu.RLock()
	if _, exists := dt.peerConnections["server2"]; !exists {
		t.Fatal("Peer should exist after gossip")
	}
	dt.peerMu.RUnlock()

	// Simulate node leave event using real memberlist.Node
	node := &memberlist.Node{
		Name: "server2",
		Addr: net.ParseIP("192.168.1.200"),
		Port: 7946,
	}
	dt.NotifyLeave(node)

	// Verify peer was removed proactively
	dt.peerMu.RLock()
	if _, exists := dt.peerConnections["server2"]; exists {
		t.Fatal("Peer should be removed after leave event")
	}
	dt.peerMu.RUnlock()
}

// TestDistributedTracker_EventNotifications tests event notification handlers
func TestDistributedTracker_EventNotifications(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockCluster := newMockCluster()

	local := NewConnectionTracker(100, 10, 0, nil)

	dt := NewDistributedTracker(
		local,
		nil,
		"",
		"",
		DistributedConfig{
			Hostname:       "server1",
			Cluster:        mockCluster,
			GossipInterval: 1 * time.Hour,
			S3SyncInterval: 1 * time.Hour,
			GlobalMaxPerIP: 10,
		},
		logger,
	)

	node := &memberlist.Node{
		Name: "server3",
		Addr: net.ParseIP("192.168.1.3"),
		Port: 7946,
	}

	// Test NotifyJoin - should not panic
	dt.NotifyJoin(node)

	// Test NotifyUpdate - should not panic
	dt.NotifyUpdate(node)

	// Test NotifyLeave on non-existent peer - should not panic
	dt.NotifyLeave(node)
}

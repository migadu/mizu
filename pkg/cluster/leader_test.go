package cluster

import (
	"io"

	"testing"
	"time"

	"log/slog"
)

func TestLeaderElection_SingleNode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create single node cluster
	c1, err := NewCluster(Config{
		NodeName: "node1",
		BindAddr: "127.0.0.1",
		BindPort: 17946,
		Peers:    []string{},
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("Failed to create cluster: %v", err)
	}
	defer c1.Shutdown()

	// Single node should be leader
	if !c1.IsLeader() {
		t.Errorf("Single node should be leader")
	}

	if c1.GetLeader() != "node1" {
		t.Errorf("Expected leader to be 'node1', got '%s'", c1.GetLeader())
	}
}

func TestLeaderElection_MultiNode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create first node
	c1, err := NewCluster(Config{
		NodeName: "node1",
		BindAddr: "127.0.0.1",
		BindPort: 17947,
		Peers:    []string{},
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("Failed to create node1: %v", err)
	}
	defer c1.Shutdown()

	// Create second node and join first
	c2, err := NewCluster(Config{
		NodeName: "node2",
		BindAddr: "127.0.0.1",
		BindPort: 17948,
		Peers:    []string{"127.0.0.1:17947"},
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("Failed to create node2: %v", err)
	}
	defer c2.Shutdown()

	// Wait for cluster to converge and leader election
	time.Sleep(1 * time.Second)

	// Verify both nodes see 2 members
	if c1.NumMembers() != 2 {
		t.Errorf("Node1 expected 2 members, got %d", c1.NumMembers())
	}
	if c2.NumMembers() != 2 {
		t.Errorf("Node2 expected 2 members, got %d", c2.NumMembers())
	}

	// Verify leader is lexicographically smallest (node1)
	if c1.GetLeader() != "node1" {
		t.Errorf("Expected leader to be 'node1', got '%s'", c1.GetLeader())
	}
	if c2.GetLeader() != "node1" {
		t.Errorf("Expected leader to be 'node1', got '%s'", c2.GetLeader())
	}

	// Verify only node1 is leader
	if !c1.IsLeader() {
		t.Errorf("Node1 should be leader")
	}
	if c2.IsLeader() {
		t.Errorf("Node2 should not be leader")
	}
}

func TestLeaderElection_ThreeNodes(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create three nodes with different names
	c1, err := NewCluster(Config{
		NodeName: "alpha",
		BindAddr: "127.0.0.1",
		BindPort: 17949,
		Peers:    []string{},
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("Failed to create alpha: %v", err)
	}
	defer c1.Shutdown()

	c2, err := NewCluster(Config{
		NodeName: "beta",
		BindAddr: "127.0.0.1",
		BindPort: 17950,
		Peers:    []string{"127.0.0.1:17949"},
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("Failed to create beta: %v", err)
	}
	defer c2.Shutdown()

	c3, err := NewCluster(Config{
		NodeName: "gamma",
		BindAddr: "127.0.0.1",
		BindPort: 17951,
		Peers:    []string{"127.0.0.1:17949"},
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("Failed to create gamma: %v", err)
	}
	defer c3.Shutdown()

	// Wait for cluster to converge and leader election
	time.Sleep(1 * time.Second)

	// Verify all nodes see 3 members
	if c1.NumMembers() != 3 {
		t.Errorf("Alpha expected 3 members, got %d", c1.NumMembers())
	}
	if c2.NumMembers() != 3 {
		t.Errorf("Beta expected 3 members, got %d", c2.NumMembers())
	}
	if c3.NumMembers() != 3 {
		t.Errorf("Gamma expected 3 members, got %d", c3.NumMembers())
	}

	// Verify leader is lexicographically smallest (alpha)
	expectedLeader := "alpha"
	if c1.GetLeader() != expectedLeader {
		t.Errorf("Alpha expected leader '%s', got '%s'", expectedLeader, c1.GetLeader())
	}
	if c2.GetLeader() != expectedLeader {
		t.Errorf("Beta expected leader '%s', got '%s'", expectedLeader, c2.GetLeader())
	}
	if c3.GetLeader() != expectedLeader {
		t.Errorf("Gamma expected leader '%s', got '%s'", expectedLeader, c3.GetLeader())
	}

	// Verify only alpha is leader
	if !c1.IsLeader() {
		t.Errorf("Alpha should be leader")
	}
	if c2.IsLeader() {
		t.Errorf("Beta should not be leader")
	}
	if c3.IsLeader() {
		t.Errorf("Gamma should not be leader")
	}
}

func TestLeaderElection_LeaderFailover(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create cluster with 3 nodes
	c1, err := NewCluster(Config{
		NodeName: "node-a",
		BindAddr: "127.0.0.1",
		BindPort: 17952,
		Peers:    []string{},
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("Failed to create node-a: %v", err)
	}
	defer c1.Shutdown()

	c2, err := NewCluster(Config{
		NodeName: "node-b",
		BindAddr: "127.0.0.1",
		BindPort: 17953,
		Peers:    []string{"127.0.0.1:17952"},
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("Failed to create node-b: %v", err)
	}
	defer c2.Shutdown()

	c3, err := NewCluster(Config{
		NodeName: "node-c",
		BindAddr: "127.0.0.1",
		BindPort: 17954,
		Peers:    []string{"127.0.0.1:17952"},
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("Failed to create node-c: %v", err)
	}
	defer c3.Shutdown()

	// Wait for cluster to converge and leader election to complete
	time.Sleep(1 * time.Second)

	// Verify node-a is initial leader (lexicographically smallest)
	if !c1.IsLeader() {
		t.Errorf("node-a should be initial leader")
	}
	if c2.IsLeader() {
		t.Errorf("node-b should not be leader")
	}
	if c3.IsLeader() {
		t.Errorf("node-c should not be leader")
	}

	// Shutdown the leader (node-a)
	c1.Shutdown()

	// Wait for memberlist to detect failure and leader to re-elect
	// Memberlist uses probe intervals, so this can take several seconds
	// Poll until we see the leader change or timeout
	maxWait := 10 * time.Second
	checkInterval := 100 * time.Millisecond
	deadline := time.Now().Add(maxWait)

	leaderChanged := false
	for time.Now().Before(deadline) {
		if c2.GetLeader() == "node-b" && c2.IsLeader() {
			leaderChanged = true
			break
		}
		time.Sleep(checkInterval)
	}

	if !leaderChanged {
		t.Fatalf("Leader did not change within %v. Current: c2.leader=%s, c2.IsLeader=%v, c2.members=%d, c3.leader=%s",
			maxWait, c2.GetLeader(), c2.IsLeader(), c2.NumMembers(), c3.GetLeader())
	}

	// Verify node-b is now leader (next lexicographically smallest)
	if !c2.IsLeader() {
		t.Errorf("node-b should be new leader after node-a fails (current leader: %s)", c2.GetLeader())
	}
	if c3.IsLeader() {
		t.Errorf("node-c should not be leader (current leader: %s)", c3.GetLeader())
	}

	if c2.GetLeader() != "node-b" {
		t.Errorf("Expected new leader to be 'node-b', got '%s'", c2.GetLeader())
	}
}

// waitFor polls cond until it holds or the timeout passes.
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

// A node that cannot reach its configured peers is the only member it knows of.
// It must not elect itself on that view until the grace period has passed.
func TestLeaderElection_UnreachablePeersDelayLeadership(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	c, err := NewCluster(Config{
		NodeName:          "node-a",
		BindAddr:          "127.0.0.1",
		BindPort:          17960,
		Peers:             []string{"127.0.0.1:17961"}, // nothing listens here
		Logger:            logger,
		LeaderGracePeriod: 1500 * time.Millisecond,
		RejoinInterval:    time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create cluster: %v", err)
	}
	defer c.Shutdown()

	if c.IsLeader() || c.GetLeader() != "" {
		t.Errorf("lone node claimed a leader before confirming membership: leader=%q", c.GetLeader())
	}

	// Its peers really are down: it has to be able to act alone eventually.
	if !waitFor(5*time.Second, c.IsLeader) {
		t.Errorf("lone node never became leader after the grace period")
	}
}

// Regression: memberlist never retries a join, so nodes started at the same
// moment could miss each other and each remain a single-node cluster - each one
// leader - until restarted.
func TestLeaderElection_RejoinsAfterMissedJoin(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// node-b starts first; its only peer is not up yet, so the initial join fails.
	c2, err := NewCluster(Config{
		NodeName:          "node-b",
		BindAddr:          "127.0.0.1",
		BindPort:          17963,
		Peers:             []string{"127.0.0.1:17962"},
		Logger:            logger,
		LeaderGracePeriod: time.Hour,
		RejoinInterval:    200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Failed to create cluster 2: %v", err)
	}
	defer c2.Shutdown()

	if c2.IsLeader() {
		t.Fatalf("node-b elected itself while alone")
	}

	// node-a comes up without knowing node-b: only node-b's retry can connect them.
	c1, err := NewCluster(Config{
		NodeName: "node-a",
		BindAddr: "127.0.0.1",
		BindPort: 17962,
		Peers:    []string{},
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("Failed to create cluster 1: %v", err)
	}
	defer c1.Shutdown()

	if !waitFor(5*time.Second, func() bool { return c2.GetLeader() == "node-a" }) {
		t.Fatalf("node-b never rejoined: members=%d leader=%q", c2.NumMembers(), c2.GetLeader())
	}
	if c2.IsLeader() {
		t.Errorf("node-b is leader, want node-a")
	}
	if !c1.IsLeader() {
		t.Errorf("node-a is not leader")
	}
}

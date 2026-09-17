package cluster

import (
	"io"

	"encoding/json"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"log/slog"

	"github.com/hashicorp/memberlist"

	"migadu/mizu/pkg/concurrency"
	"migadu/mizu/pkg/metrics"
)

// MessageType identifies the type of gossip message
type MessageType byte

const (
	MessageTypeConnectionState MessageType = iota
	MessageTypeRateLimit
	MessageTypeAuthRateLimit
)

// GossipMessage is the envelope for all gossip messages
type GossipMessage struct {
	Type    MessageType     `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// StateDelegate defines the interface for state synchronization
type StateDelegate interface {
	GetState() []byte
	MergeState(data []byte)
}

// EventDelegate defines the interface for cluster membership events
type EventDelegate interface {
	NotifyJoin(node *memberlist.Node)
	NotifyLeave(node *memberlist.Node)
	NotifyUpdate(node *memberlist.Node)
}

// Cluster manages memberlist-based cluster membership and gossip
type Cluster struct {
	ml                     *memberlist.Memberlist
	broadcasts             *memberlist.TransmitLimitedQueue
	logger                 *slog.Logger
	connectionStateHandler func(data []byte)
	rateLimitHandler       func(data []byte)
	authRateLimitHandler   func(data []byte)
	stateDelegate          StateDelegate
	eventDelegate          EventDelegate

	// Leader election
	leader    string
	leaderMtx sync.RWMutex
	metrics   *metrics.Metrics // optional; publishes the cluster leader gauge

	// Membership confirmation (see membershipConfirmed)
	peers             []string
	startedAt         time.Time
	leaderGracePeriod time.Duration
	rejoinInterval    time.Duration
	confirmed         bool // guarded by leaderMtx; never reset once true

	// Lifecycle
	done         chan struct{} // Closed on Shutdown to stop background goroutines
	shutdownOnce sync.Once     // Ensures Shutdown runs exactly once
}

// Config holds configuration for creating a cluster
type Config struct {
	NodeName      string   // This node's name (defaults to hostname)
	BindAddr      string   // Address to bind to (e.g., "0.0.0.0")
	BindPort      int      // Port to bind to for memberlist (default: 7946)
	Peers         []string // Other cluster nodes to connect to (e.g., ["node1:7946", "node2:7946"])
	SecretKey     []byte   // 32-byte encryption key for gossip protocol (AES-256)
	Logger        *slog.Logger
	StateDelegate StateDelegate
	EventDelegate EventDelegate

	// LeaderGracePeriod is how long a node that has peers configured but has not
	// reached any of them waits before it may act as leader (default 1 minute).
	LeaderGracePeriod time.Duration
	// RejoinInterval is how often a node that is alone retries joining its
	// configured peers (default 15 seconds).
	RejoinInterval time.Duration
}

const (
	defaultLeaderGracePeriod = time.Minute
	defaultRejoinInterval    = 15 * time.Second
)

// NewCluster creates a new cluster instance with memberlist
func NewCluster(cfg Config) (*Cluster, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	cluster := &Cluster{
		logger:            cfg.Logger,
		stateDelegate:     cfg.StateDelegate,
		eventDelegate:     cfg.EventDelegate,
		done:              make(chan struct{}),
		peers:             cfg.Peers,
		startedAt:         time.Now(),
		leaderGracePeriod: cfg.LeaderGracePeriod,
		rejoinInterval:    cfg.RejoinInterval,
	}
	if cluster.leaderGracePeriod <= 0 {
		cluster.leaderGracePeriod = defaultLeaderGracePeriod
	}
	if cluster.rejoinInterval <= 0 {
		cluster.rejoinInterval = defaultRejoinInterval
	}

	// Create memberlist configuration
	mlConfig := memberlist.DefaultLANConfig()

	// Set event delegate for cluster membership events
	mlConfig.Events = cluster

	// Set node name
	if cfg.NodeName != "" {
		mlConfig.Name = cfg.NodeName
	}

	// Set bind address and port
	if cfg.BindAddr != "" {
		mlConfig.BindAddr = cfg.BindAddr
	}
	if cfg.BindPort > 0 {
		mlConfig.BindPort = cfg.BindPort
	}

	// Enable gossip encryption and authentication if secret key is provided
	if len(cfg.SecretKey) > 0 {
		if len(cfg.SecretKey) != 32 {
			return nil, fmt.Errorf("secret key must be exactly 32 bytes, got %d", len(cfg.SecretKey))
		}
		mlConfig.SecretKey = cfg.SecretKey
		mlConfig.GossipVerifyIncoming = true // Verify all incoming gossip messages
		mlConfig.GossipVerifyOutgoing = true // Sign all outgoing gossip messages
		cfg.Logger.Info("Gossip encryption and authentication enabled (AES-256)")
	} else {
		cfg.Logger.Warn("Gossip encryption DISABLED - cluster communication is INSECURE")
	}

	// Set delegate for custom gossip messages
	mlConfig.Delegate = cluster

	// Disable memberlist's built-in logging
	mlConfig.LogOutput = &logWriter{logger: cfg.Logger}

	// Create broadcast queue for efficient message distribution
	// Initialize this BEFORE creating memberlist to avoid races
	cluster.broadcasts = &memberlist.TransmitLimitedQueue{
		NumNodes: func() int {
			if cluster.ml == nil {
				return 0
			}
			return cluster.ml.NumMembers()
		},
		RetransmitMult: 3, // Retransmit to 3x nodes for reliability
	}

	// Create memberlist - this can immediately trigger callbacks like NotifyJoin
	// so all cluster fields must be initialized before this point
	ml, err := memberlist.Create(mlConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create memberlist: %w", err)
	}

	// Assign ml - use lock to ensure updateLeader() sees this write
	cluster.leaderMtx.Lock()
	cluster.ml = ml
	cluster.leaderMtx.Unlock()

	// Join peers if provided
	if len(cfg.Peers) > 0 {
		_, err := ml.Join(cfg.Peers)
		if err != nil {
			cfg.Logger.Warn("Failed to join some peers", "error", err)
			// Don't fail completely - we might be the first node
		}

		// memberlist never retries a join. Without this, nodes restarted at the
		// same moment can each miss the other's listener and stay one-member
		// clusters - every one of them leader - until the next restart.
		concurrency.SafeGo(cfg.Logger, "cluster-rejoin", cluster.rejoinLoop)
	}

	// Initialize leader election
	cluster.updateLeader()

	// Start periodic leader check to handle failures (every second)
	concurrency.SafeGo(cfg.Logger, "cluster-leader-ticker", func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-cluster.done:
				return
			case <-ticker.C:
				cluster.updateLeader()
			}
		}
	})

	cfg.Logger.Info("Cluster started",
		"node_name", ml.LocalNode().Name,
		"bind_addr", mlConfig.BindAddr,
		"bind_port", mlConfig.BindPort,
		"members", ml.NumMembers(),
		"leader", cluster.GetLeader(),
		"is_leader", cluster.IsLeader())

	return cluster, nil
}

// SetStateDelegate sets the state delegate for the cluster
func (c *Cluster) SetStateDelegate(delegate StateDelegate) {
	c.stateDelegate = delegate
}

// SetEventDelegate sets the event delegate for the cluster
func (c *Cluster) SetEventDelegate(delegate EventDelegate) {
	c.eventDelegate = delegate
}

// RegisterConnectionStateHandler registers a handler for connection state gossip
func (c *Cluster) RegisterConnectionStateHandler(handler func(data []byte)) {
	c.connectionStateHandler = handler
}

// RegisterRateLimitHandler registers a handler for rate limit gossip
func (c *Cluster) RegisterRateLimitHandler(handler func(data []byte)) {
	c.rateLimitHandler = handler
}

// RegisterAuthRateLimitHandler registers a handler for auth rate limit gossip
func (c *Cluster) RegisterAuthRateLimitHandler(handler func(data []byte)) {
	c.authRateLimitHandler = handler
}

// BroadcastConnectionState broadcasts connection state to the cluster
func (c *Cluster) BroadcastConnectionState(data []byte) error {
	msg := GossipMessage{
		Type:    MessageTypeConnectionState,
		Payload: json.RawMessage(data),
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	c.broadcasts.QueueBroadcast(&broadcast{
		msg:    msgBytes,
		notify: nil,
	})

	return nil
}

// BroadcastRateLimit broadcasts rate limit data to the cluster
func (c *Cluster) BroadcastRateLimit(data []byte) error {
	msg := GossipMessage{
		Type:    MessageTypeRateLimit,
		Payload: json.RawMessage(data),
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	c.broadcasts.QueueBroadcast(&broadcast{
		msg:    msgBytes,
		notify: nil,
	})

	return nil
}

// BroadcastAuthRateLimit broadcasts auth rate limit data to the cluster
func (c *Cluster) BroadcastAuthRateLimit(data []byte) error {
	msg := GossipMessage{
		Type:    MessageTypeAuthRateLimit,
		Payload: json.RawMessage(data),
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	c.broadcasts.QueueBroadcast(&broadcast{
		msg:    msgBytes,
		notify: nil,
	})

	return nil
}

// Members returns the list of cluster members
func (c *Cluster) Members() []*memberlist.Node {
	return c.ml.Members()
}

// NumMembers returns the number of cluster members
func (c *Cluster) NumMembers() int {
	return c.ml.NumMembers()
}

// LocalNode returns the local node
func (c *Cluster) LocalNode() *memberlist.Node {
	return c.ml.LocalNode()
}

// LocalNodeName returns this node's stable name, used to attribute gossiped
// state (e.g. rate-limit counts) to their source peer.
func (c *Cluster) LocalNodeName() string {
	return c.ml.LocalNode().Name
}

// Shutdown gracefully shuts down the cluster.
// It first stops background goroutines, then gracefully leaves the cluster
// (notifying peers), and finally shuts down the memberlist transport.
// This method is idempotent — calling it multiple times is safe.
func (c *Cluster) Shutdown() error {
	var err error
	c.shutdownOnce.Do(func() {
		// Stop background goroutines (leader ticker)
		close(c.done)

		if c.ml != nil {
			// Gracefully leave the cluster so peers get a departure notification
			// instead of detecting this node as failed via failure detection.
			// Use a 5-second timeout to avoid blocking shutdown indefinitely.
			if leaveErr := c.ml.Leave(5 * time.Second); leaveErr != nil {
				c.logger.Warn("Failed to gracefully leave cluster", "error", leaveErr)
			}
			err = c.ml.Shutdown()
		}
	})
	return err
}

// --- Leader Election ---

// IsLeader returns true if this node is the cluster leader
// Leader is determined by lexicographic ordering of node names (deterministic).
// No node is leader while its membership is unconfirmed (see membershipConfirmed).
func (c *Cluster) IsLeader() bool {
	c.leaderMtx.RLock()
	defer c.leaderMtx.RUnlock()
	if c.ml == nil {
		return false
	}
	return c.leader == c.ml.LocalNode().Name
}

// GetLeader returns the current leader node name
func (c *Cluster) GetLeader() string {
	c.leaderMtx.RLock()
	defer c.leaderMtx.RUnlock()
	return c.leader
}

// updateLeader determines cluster leader based on member list
// Leader = node with lexicographically smallest node name (deterministic)
func (c *Cluster) updateLeader() {
	c.leaderMtx.Lock()

	if c.ml == nil {
		c.leaderMtx.Unlock()
		return
	}

	members := c.ml.Members()
	if len(members) == 0 {
		c.leaderMtx.Unlock()
		return
	}

	if !c.membershipConfirmed(len(members)) {
		c.leaderMtx.Unlock()
		return
	}

	// Sort members by node name lexicographically
	sort.Slice(members, func(i, j int) bool {
		return members[i].Name < members[j].Name
	})

	newLeader := members[0].Name
	localName := c.ml.LocalNode().Name
	oldLeader := c.leader
	changed := oldLeader != newLeader
	c.leader = newLeader
	m := c.metrics
	c.leaderMtx.Unlock()

	if changed {
		c.logger.Info("cluster leader changed",
			"old_leader", oldLeader,
			"new_leader", newLeader,
			"is_leader", newLeader == localName)
	}

	// Reflect leadership in the Prometheus gauge (1 = this node is leader).
	if m != nil && m.ClusterLeader != nil {
		v := 0.0
		if newLeader == localName {
			v = 1.0
		}
		m.ClusterLeader.WithLabelValues(localName).Set(v)
	}
}

// membershipConfirmed reports whether this node's view of the cluster can be
// trusted for leader election. Must be called with leaderMtx held.
//
// A node that has not reached its peers yet is the only member it knows of, and
// the smallest name in a list of one is its own: it would elect itself. Until
// it has seen another member it therefore claims no leader at all. The grace
// period bounds that: a node whose peers really are down must still be able to
// act alone (renew certificates), so after it the lone view is accepted.
func (c *Cluster) membershipConfirmed(numMembers int) bool {
	if c.confirmed {
		return true
	}

	switch {
	case len(c.peers) == 0:
		// Nothing to wait for.
	case numMembers > 1:
		c.logger.Info("cluster membership confirmed", "members", numMembers)
	case time.Since(c.startedAt) >= c.leaderGracePeriod:
		c.logger.Warn("no configured peer reachable - proceeding as a single-node cluster",
			"peers", c.peers,
			"waited", c.leaderGracePeriod)
	default:
		return false
	}

	c.confirmed = true
	return true
}

// rejoinLoop retries joining the configured peers for as long as this node is
// alone. Once it knows any other member, gossip keeps the rest in sync.
func (c *Cluster) rejoinLoop() {
	ticker := time.NewTicker(c.rejoinInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			if c.ml.NumMembers() > 1 {
				continue
			}
			if n, err := c.ml.Join(c.peers); err != nil {
				c.logger.Debug("cluster rejoin failed", "peers", c.peers, "error", err)
			} else {
				c.logger.Info("rejoined cluster", "contacted_peers", n)
				c.updateLeader()
			}
		}
	}
}

// SetMetrics attaches the metrics instance so the cluster can publish the
// leader gauge, and immediately reflects the current leadership state.
func (c *Cluster) SetMetrics(m *metrics.Metrics) {
	c.leaderMtx.Lock()
	c.metrics = m
	c.leaderMtx.Unlock()
	c.updateLeader()
}

// --- Memberlist Delegate Interface Implementation ---

// NodeMeta is used to retrieve meta-data about the current node
func (c *Cluster) NodeMeta(limit int) []byte {
	// Could include node metadata here (e.g., version, capabilities)
	return []byte{}
}

// NotifyMsg is called when a user-data message is received
func (c *Cluster) NotifyMsg(data []byte) {
	var msg GossipMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		c.logger.Warn("Failed to unmarshal gossip message", "error", err)
		return
	}

	switch msg.Type {
	case MessageTypeConnectionState:
		if c.connectionStateHandler != nil {
			c.connectionStateHandler(msg.Payload)
		}
	case MessageTypeRateLimit:
		if c.rateLimitHandler != nil {
			c.rateLimitHandler(msg.Payload)
		}
	case MessageTypeAuthRateLimit:
		if c.authRateLimitHandler != nil {
			c.authRateLimitHandler(msg.Payload)
		}
	default:
		c.logger.Warn("Unknown gossip message type", "type", uint8(msg.Type))
	}
}

// GetBroadcasts is called when user data messages can be broadcast
func (c *Cluster) GetBroadcasts(overhead, limit int) [][]byte {
	return c.broadcasts.GetBroadcasts(overhead, limit)
}

// LocalState is used for state synchronization on node join
func (c *Cluster) LocalState(join bool) []byte {
	if c.stateDelegate != nil {
		return c.stateDelegate.GetState()
	}
	return []byte{}
}

// MergeRemoteState is called to merge state from a remote node
func (c *Cluster) MergeRemoteState(buf []byte, join bool) {
	if c.stateDelegate != nil {
		c.stateDelegate.MergeState(buf)
	}
}

// --- EventDelegate Interface Implementation ---

// NotifyJoin is called when a node joins the cluster
func (c *Cluster) NotifyJoin(node *memberlist.Node) {
	c.logger.Info("Node joined cluster",
		"node", node.Name,
		"addr", node.Address())

	// Re-evaluate leader asynchronously to avoid deadlock
	// (memberlist holds a read lock when calling this)
	concurrency.SafeGo(c.logger, "cluster-update-leader-join", c.updateLeader)

	if c.eventDelegate != nil {
		c.eventDelegate.NotifyJoin(node)
	}
}

// NotifyLeave is called when a node leaves the cluster gracefully
func (c *Cluster) NotifyLeave(node *memberlist.Node) {
	c.logger.Info("Node left cluster",
		"node", node.Name,
		"addr", node.Address())

	// Re-evaluate leader asynchronously to avoid deadlock
	// (memberlist holds a read lock when calling this)
	concurrency.SafeGo(c.logger, "cluster-update-leader-leave", c.updateLeader)

	if c.eventDelegate != nil {
		c.eventDelegate.NotifyLeave(node)
	}
}

// NotifyUpdate is called when a node's metadata is updated
func (c *Cluster) NotifyUpdate(node *memberlist.Node) {
	c.logger.Debug("Node updated",
		"node", node.Name,
		"addr", node.Address())

	if c.eventDelegate != nil {
		c.eventDelegate.NotifyUpdate(node)
	}
}

// --- Helper Types ---

// broadcast implements memberlist.Broadcast
type broadcast struct {
	msg    []byte
	notify chan<- struct{}
}

func (b *broadcast) Invalidates(other memberlist.Broadcast) bool {
	return false // Don't invalidate other broadcasts
}

func (b *broadcast) Message() []byte {
	return b.msg
}

func (b *broadcast) Finished() {
	if b.notify != nil {
		close(b.notify)
	}
}

type logWriter struct {
	logger *slog.Logger
}

func (w *logWriter) Write(p []byte) (n int, err error) {
	// Strip trailing newline from memberlist logs to prevent escaped newlines
	msg := string(p)
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}
	w.logger.Debug(msg)
	return len(p), nil
}

// HealthStatus returns cluster health information
func (c *Cluster) HealthStatus() map[string]interface{} {
	members := c.Members()
	alive := 0
	suspect := 0
	dead := 0

	for _, member := range members {
		switch member.State {
		case memberlist.StateAlive:
			alive++
		case memberlist.StateSuspect:
			suspect++
		case memberlist.StateDead:
			dead++
		}
	}

	return map[string]interface{}{
		"node_name":       c.LocalNode().Name,
		"total_members":   len(members),
		"alive_members":   alive,
		"suspect_members": suspect,
		"dead_members":    dead,
		"bind_addr":       net.JoinHostPort(c.ml.LocalNode().Addr.String(), fmt.Sprintf("%d", c.ml.LocalNode().Port)),
	}
}

// WaitForMembers waits until at least minMembers are in the cluster or timeout is reached
func (c *Cluster) WaitForMembers(minMembers int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c.NumMembers() >= minMembers {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %d members (current: %d)", minMembers, c.NumMembers())
}

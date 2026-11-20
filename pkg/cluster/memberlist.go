package cluster

import (
	"io"

	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
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
	Type MessageType `json:"type"`
	// Scope names the [[server]] the message belongs to, so that a node
	// running several servers routes it to the matching one. Empty for a
	// process-wide (unscoped) sender.
	Scope   string          `json:"scope,omitempty"`
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
	ml               *memberlist.Memberlist
	broadcasts       *memberlist.TransmitLimitedQueue
	reliableInFlight sync.Map // handlerKey -> *atomic.Bool: a large direct send is in progress
	logger           *slog.Logger
	handlersMu       sync.RWMutex
	handlers         map[handlerKey]func(data []byte) // per message type and server scope
	stateDelegates   map[string]StateDelegate         // per server scope, guarded by handlersMu
	eventDelegates   map[string]EventDelegate         // per server scope, guarded by handlersMu

	// Leader election
	leader    string
	leaderMtx sync.RWMutex
	metrics   *metrics.Metrics // optional; publishes the cluster leader gauge

	// rejoinInterval: how often to re-join configured peers that are not
	// members (see maintainMembership)
	rejoinInterval time.Duration

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
	// RejoinInterval: how often to re-join configured peers that are not
	// members (0 = 30s)
	RejoinInterval time.Duration
}

// defaultRejoinInterval is how often a node re-joins missing peers.
const defaultRejoinInterval = 30 * time.Second

// NewCluster creates a new cluster instance with memberlist
func NewCluster(cfg Config) (*Cluster, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	cluster := &Cluster{
		logger: cfg.Logger,
		done:   make(chan struct{}),
	}
	if cfg.StateDelegate != nil {
		cluster.setStateDelegate("", cfg.StateDelegate)
	}
	if cfg.EventDelegate != nil {
		cluster.setEventDelegate("", cfg.EventDelegate)
	}
	cluster.rejoinInterval = cfg.RejoinInterval
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
		// Keep re-joining peers that are missing: memberlist never contacts
		// a node again once it has declared it dead, so without this a
		// partition splits the cluster until a restart.
		peers := cfg.Peers
		concurrency.SafeGo(cfg.Logger, "cluster-rejoin", func() { cluster.maintainMembership(peers) })
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

// maintainMembership re-joins every configured peer that is not currently a
// member. Peers are checked by address, not by counting members: with a
// partial peer list, one side of a partition can hold enough members to look
// complete while its configured seed is on the other side.
func (c *Cluster) maintainMembership(peers []string) {
	ticker := time.NewTicker(c.rejoinInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
		}
		missing := c.missingPeers(peers)
		if len(missing) == 0 {
			continue
		}
		before := c.ml.NumMembers()
		n, err := c.ml.Join(missing)
		if after := c.ml.NumMembers(); after > before {
			c.logger.Info("Rejoined cluster", "peers_reached", n, "members", after)
		} else if err != nil {
			c.logger.Debug("Cluster rejoin found no new peers", "missing", missing, "error", err, "members", after)
		}
	}
}

// missingPeers returns the configured peers whose address is not that of a
// current member (this node included). A peer whose name doesn't resolve
// counts as missing; Join reports the error.
func (c *Cluster) missingPeers(peers []string) []string {
	present := make(map[string]bool)
	for _, m := range c.ml.Members() {
		present[net.JoinHostPort(m.Addr.String(), strconv.Itoa(int(m.Port)))] = true
	}
	var missing []string
	for _, p := range peers {
		addr, err := net.ResolveTCPAddr("tcp", p)
		if err != nil || !present[net.JoinHostPort(addr.IP.String(), strconv.Itoa(addr.Port))] {
			missing = append(missing, p)
		}
	}
	return missing
}

// SetStateDelegate sets the unscoped state delegate for the cluster. A process
// with several servers must use Scoped instead.
func (c *Cluster) SetStateDelegate(delegate StateDelegate) {
	c.setStateDelegate("", delegate)
}

// SetEventDelegate sets the unscoped event delegate for the cluster. A process
// with several servers must use Scoped instead.
func (c *Cluster) SetEventDelegate(delegate EventDelegate) {
	c.setEventDelegate("", delegate)
}

func (c *Cluster) setStateDelegate(scope string, delegate StateDelegate) {
	c.handlersMu.Lock()
	defer c.handlersMu.Unlock()
	if c.stateDelegates == nil {
		c.stateDelegates = make(map[string]StateDelegate)
	}
	c.stateDelegates[scope] = delegate
}

func (c *Cluster) setEventDelegate(scope string, delegate EventDelegate) {
	c.handlersMu.Lock()
	defer c.handlersMu.Unlock()
	if c.eventDelegates == nil {
		c.eventDelegates = make(map[string]EventDelegate)
	}
	c.eventDelegates[scope] = delegate
}

// stateDelegatesSnapshot copies the registered state delegates so they can be
// called without holding handlersMu.
func (c *Cluster) stateDelegatesSnapshot() map[string]StateDelegate {
	c.handlersMu.RLock()
	defer c.handlersMu.RUnlock()
	out := make(map[string]StateDelegate, len(c.stateDelegates))
	for scope, d := range c.stateDelegates {
		out[scope] = d
	}
	return out
}

// eventDelegatesSnapshot copies the registered event delegates so they can be
// called without holding handlersMu.
func (c *Cluster) eventDelegatesSnapshot() []EventDelegate {
	c.handlersMu.RLock()
	defer c.handlersMu.RUnlock()
	out := make([]EventDelegate, 0, len(c.eventDelegates))
	for _, d := range c.eventDelegates {
		out = append(out, d)
	}
	return out
}

// handlerKey identifies who a gossip message is for: its type, and the
// [[server]] scope it was sent under.
type handlerKey struct {
	kind  MessageType
	scope string
}

func (c *Cluster) registerHandler(kind MessageType, scope string, handler func(data []byte)) {
	c.handlersMu.Lock()
	defer c.handlersMu.Unlock()
	if c.handlers == nil {
		c.handlers = make(map[handlerKey]func(data []byte))
	}
	c.handlers[handlerKey{kind, scope}] = handler
}

func (c *Cluster) handlerFor(kind MessageType, scope string) func(data []byte) {
	c.handlersMu.RLock()
	defer c.handlersMu.RUnlock()
	return c.handlers[handlerKey{kind, scope}]
}

// RegisterConnectionStateHandler registers the unscoped handler for connection
// state gossip. A process with several servers must use Scoped instead.
func (c *Cluster) RegisterConnectionStateHandler(handler func(data []byte)) {
	c.registerHandler(MessageTypeConnectionState, "", handler)
}

// RegisterRateLimitHandler registers the unscoped handler for rate limit gossip
func (c *Cluster) RegisterRateLimitHandler(handler func(data []byte)) {
	c.registerHandler(MessageTypeRateLimit, "", handler)
}

// RegisterAuthRateLimitHandler registers the unscoped handler for auth rate limit gossip
func (c *Cluster) RegisterAuthRateLimitHandler(handler func(data []byte)) {
	c.registerHandler(MessageTypeAuthRateLimit, "", handler)
}

// BroadcastConnectionState broadcasts a connection state snapshot to the cluster
func (c *Cluster) BroadcastConnectionState(data []byte) error {
	return c.send(MessageTypeConnectionState, "", data, true)
}

// BroadcastRateLimit broadcasts a rate limit snapshot to the cluster
func (c *Cluster) BroadcastRateLimit(data []byte) error {
	return c.send(MessageTypeRateLimit, "", data, true)
}

// BroadcastAuthRateLimit broadcasts one auth rate limit event to the cluster
func (c *Cluster) BroadcastAuthRateLimit(data []byte) error {
	return c.send(MessageTypeAuthRateLimit, "", data, false)
}

// Scoped returns a view of the cluster for one [[server]]. Messages broadcast
// through it are tagged with the scope and delivered only to handlers
// registered under the same scope on the receiving node.
//
// There used to be a single handler slot per message type for the whole
// process: with two servers on a node, the last to register received both
// servers' gossip (mixing their connection counts, rate-limit windows and auth
// blocks) and the other received none.
func (c *Cluster) Scoped(scope string) *ScopedCluster {
	return &ScopedCluster{c: c, scope: scope}
}

// ScopedCluster is a per-server view of a Cluster. See Cluster.Scoped.
type ScopedCluster struct {
	c     *Cluster
	scope string
}

func (s *ScopedCluster) RegisterConnectionStateHandler(handler func(data []byte)) {
	s.c.registerHandler(MessageTypeConnectionState, s.scope, handler)
}

func (s *ScopedCluster) RegisterRateLimitHandler(handler func(data []byte)) {
	s.c.registerHandler(MessageTypeRateLimit, s.scope, handler)
}

func (s *ScopedCluster) RegisterAuthRateLimitHandler(handler func(data []byte)) {
	s.c.registerHandler(MessageTypeAuthRateLimit, s.scope, handler)
}

func (s *ScopedCluster) BroadcastConnectionState(data []byte) error {
	return s.c.send(MessageTypeConnectionState, s.scope, data, true)
}

func (s *ScopedCluster) BroadcastRateLimit(data []byte) error {
	return s.c.send(MessageTypeRateLimit, s.scope, data, true)
}

func (s *ScopedCluster) BroadcastAuthRateLimit(data []byte) error {
	return s.c.send(MessageTypeAuthRateLimit, s.scope, data, false)
}

// SetStateDelegate registers this server's push/pull state delegate. State is
// exchanged per scope, so each server syncs with its counterpart on the peer.
func (s *ScopedCluster) SetStateDelegate(delegate StateDelegate) {
	s.c.setStateDelegate(s.scope, delegate)
}

// SetEventDelegate registers this server's membership event delegate. Every
// registered delegate is notified of every membership event.
func (s *ScopedCluster) SetEventDelegate(delegate EventDelegate) {
	s.c.setEventDelegate(s.scope, delegate)
}

// NumMembers and LocalNodeName are not per-server; they pass through to the
// cluster.
func (s *ScopedCluster) NumMembers() int       { return s.c.NumMembers() }
func (s *ScopedCluster) LocalNodeName() string { return s.c.LocalNodeName() }

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
// Leader is determined by lexicographic ordering of node names (deterministic)
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
	case MessageTypeConnectionState, MessageTypeRateLimit, MessageTypeAuthRateLimit:
		// Delivered only to the handler registered under the sender's scope: a
		// message from a server this node does not run is dropped.
		if handler := c.handlerFor(msg.Type, msg.Scope); handler != nil {
			handler(msg.Payload)
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
//
// The state is a JSON object of server scope -> that server's state, so a node
// running several servers syncs each with its counterpart on the peer.
func (c *Cluster) LocalState(join bool) []byte {
	delegates := c.stateDelegatesSnapshot()
	if len(delegates) == 0 {
		return []byte{}
	}
	states := make(map[string][]byte, len(delegates))
	for scope, d := range delegates {
		states[scope] = d.GetState()
	}
	buf, err := json.Marshal(states)
	if err != nil {
		c.logger.Warn("Failed to marshal local cluster state", "error", err)
		return []byte{}
	}
	return buf
}

// MergeRemoteState is called to merge state from a remote node
// State for a scope this node does not run is dropped.
func (c *Cluster) MergeRemoteState(buf []byte, join bool) {
	if len(buf) == 0 {
		return
	}
	var states map[string][]byte
	if err := json.Unmarshal(buf, &states); err != nil {
		c.logger.Warn("Failed to unmarshal remote cluster state", "error", err)
		return
	}
	delegates := c.stateDelegatesSnapshot()
	for scope, state := range states {
		if d := delegates[scope]; d != nil {
			d.MergeState(state)
		}
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

	for _, d := range c.eventDelegatesSnapshot() {
		d.NotifyJoin(node)
	}
}

// NotifyLeave is called when a node leaves the cluster gracefully
func (c *Cluster) NotifyLeave(node *memberlist.Node) {
	c.logger.Warn("Node left cluster",
		"node", node.Name,
		"addr", node.Address())

	// Re-evaluate leader asynchronously to avoid deadlock
	// (memberlist holds a read lock when calling this)
	concurrency.SafeGo(c.logger, "cluster-update-leader-leave", c.updateLeader)

	for _, d := range c.eventDelegatesSnapshot() {
		d.NotifyLeave(node)
	}
}

// NotifyUpdate is called when a node's metadata is updated
func (c *Cluster) NotifyUpdate(node *memberlist.Node) {
	c.logger.Debug("Node updated",
		"node", node.Name,
		"addr", node.Address())

	for _, d := range c.eventDelegatesSnapshot() {
		d.NotifyUpdate(node)
	}
}

// maxGossipMessageSize is the largest message handed to the UDP gossip queue.
// memberlist only ever transmits queued broadcasts that fit what is left of one
// UDP packet (UDPBufferSize 1400, minus its own framing, the compound-message
// header and encryption overhead) and never drops the ones that do not, so
// anything larger would sit in the queue forever. Kept comfortably below that.
const maxGossipMessageSize = 1024

// send distributes one message to the cluster.
//
// Small messages ride on gossip. A snapshot (full state, where only the latest
// matters) replaces an older queued snapshot of the same type instead of
// queueing behind it; events do not invalidate one another.
//
// Messages too large for a UDP packet are sent directly to every member over
// memberlist's reliable (TCP) channel. If the previous large snapshot of the
// same type and scope is still being sent, a new snapshot is skipped: they are
// periodic, so the next tick carries fresher state, and a slow peer must not
// make sends pile up. Events are never skipped.
func (c *Cluster) send(msgType MessageType, scope string, data []byte, snapshot bool) error {
	msgBytes, err := json.Marshal(GossipMessage{Type: msgType, Scope: scope, Payload: json.RawMessage(data)})
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	if len(msgBytes) <= maxGossipMessageSize {
		c.broadcasts.QueueBroadcast(&broadcast{msg: msgBytes, kind: msgType, scope: scope, snapshot: snapshot})
		return nil
	}

	// Only snapshots may be skipped while an earlier one is in flight. An event
	// is sent once and never repeated, so skipping it would lose it; events are
	// small in number (the callers bound their queues) and each gets its send.
	release := func() {}
	if snapshot {
		flag, _ := c.reliableInFlight.LoadOrStore(handlerKey{msgType, scope}, new(atomic.Bool))
		inFlight := flag.(*atomic.Bool)
		if !inFlight.CompareAndSwap(false, true) {
			c.logger.Debug("Skipping large cluster snapshot - previous send still in progress",
				"type", uint8(msgType), "bytes", len(msgBytes))
			return nil
		}
		release = func() { inFlight.Store(false) }
	}

	concurrency.SafeGo(c.logger, "cluster-send-reliable", func() {
		defer release()

		c.leaderMtx.RLock()
		ml := c.ml
		c.leaderMtx.RUnlock()
		if ml == nil {
			return
		}
		local := ml.LocalNode().Name
		for _, node := range ml.Members() {
			if node.Name == local {
				continue
			}
			if err := ml.SendReliable(node, msgBytes); err != nil {
				c.logger.Debug("Failed to send cluster message to peer",
					"peer", node.Name, "type", uint8(msgType), "bytes", len(msgBytes), "error", err)
			}
		}
	})
	return nil
}

// --- Helper Types ---

// broadcast implements memberlist.Broadcast
type broadcast struct {
	msg      []byte
	kind     MessageType
	scope    string
	snapshot bool // full-state message: a newer one of the same kind supersedes it
	notify   chan<- struct{}
}

// Invalidates reports whether b makes an older queued broadcast pointless. A
// snapshot supersedes any queued snapshot of the same kind and server scope,
// which keeps the queue at one entry per kind and scope however fast snapshots
// are produced.
func (b *broadcast) Invalidates(other memberlist.Broadcast) bool {
	o, ok := other.(*broadcast)
	return ok && b.snapshot && o.snapshot && o.kind == b.kind && o.scope == b.scope
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

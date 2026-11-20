package smtp

import (
	"encoding/json"
	"log/slog"
	"migadu/mizu/pkg/concurrency"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Bounds applied to untrusted auth-rate-limit gossip. Without them a peer could
// block any IP effectively forever or report an absurd failure count.
const (
	maxAuthGossipFailureCount = 10_000           // Sane ceiling for a failure counter
	maxAuthGossipUsernameLen  = 320              // RFC 5321 max email/localpart-ish bound
	authGossipBlockSkewMargin = 10 * time.Minute // Allowance for clock skew + event age
)

// AuthRateLimitEventType identifies the type of auth rate limit event
type AuthRateLimitEventType string

const (
	AuthRateLimitEventBlockIP         AuthRateLimitEventType = "BLOCK_IP"
	AuthRateLimitEventUnblockIP       AuthRateLimitEventType = "UNBLOCK_IP"
	AuthRateLimitEventFailureCount    AuthRateLimitEventType = "FAILURE_COUNT"
	AuthRateLimitEventBlockSubnet     AuthRateLimitEventType = "BLOCK_SUBNET"
	AuthRateLimitEventUnblockSubnet   AuthRateLimitEventType = "UNBLOCK_SUBNET"
	AuthRateLimitEventUsernameFailure AuthRateLimitEventType = "USERNAME_FAILURE"
	AuthRateLimitEventUsernameSuccess AuthRateLimitEventType = "USERNAME_SUCCESS"
)

// AuthRateLimitEvent represents a rate limit event to broadcast
type AuthRateLimitEvent struct {
	Type      AuthRateLimitEventType
	IP        string
	Timestamp time.Time
	NodeID    string // Originating node

	// For BLOCK_IP events
	BlockedUntil time.Time
	FailureCount int
	FirstFailure time.Time

	// For FAILURE_COUNT events
	LastDelay time.Duration

	// For USERNAME_* events
	Username string

	// For *_SUBNET events
	Subnet string
}

// AuthRateLimitCluster is what the auth rate limiter needs from the cluster.
// Pass a per-server view (cluster.Cluster.Scoped) so that a node running
// several submission servers keeps their blocks apart.
type AuthRateLimitCluster interface {
	BroadcastAuthRateLimit(data []byte) error
	RegisterAuthRateLimitHandler(handler func(data []byte))
	LocalNodeName() string
}

// ClusterAuthRateLimiter handles cluster synchronization for auth rate limiting
type ClusterAuthRateLimiter struct {
	limiter        *AuthRateLimiter
	cluster        AuthRateLimitCluster
	logger         *slog.Logger
	broadcastQueue []AuthRateLimitEvent
	queueMu        sync.Mutex
	nodeID         string
	maxQueueSize   int
}

// NewClusterAuthRateLimiter creates a new cluster auth rate limiter
func NewClusterAuthRateLimiter(limiter *AuthRateLimiter, clusterMgr AuthRateLimitCluster, logger *slog.Logger) *ClusterAuthRateLimiter {
	nodeID := clusterMgr.LocalNodeName()

	cl := &ClusterAuthRateLimiter{
		limiter:        limiter,
		cluster:        clusterMgr,
		logger:         logger,
		broadcastQueue: make([]AuthRateLimitEvent, 0),
		nodeID:         nodeID,
		maxQueueSize:   10000, // Same as Sora
	}

	// Start broadcast routine
	concurrency.SafeGo(logger, "auth-rate-limiter-cluster-broadcast", cl.broadcastRoutine)

	return cl
}

// BroadcastBlockIP broadcasts an IP block event
func (c *ClusterAuthRateLimiter) BroadcastBlockIP(ip string, blockedUntil time.Time, failureCount int, firstFailure time.Time) {
	event := AuthRateLimitEvent{
		Type:         AuthRateLimitEventBlockIP,
		IP:           ip,
		BlockedUntil: blockedUntil,
		FailureCount: failureCount,
		FirstFailure: firstFailure,
		Timestamp:    time.Now(),
		NodeID:       c.nodeID,
	}

	c.queueEvent(event)
}

// BroadcastUnblockIP broadcasts an IP unblock event
func (c *ClusterAuthRateLimiter) BroadcastUnblockIP(ip string) {
	event := AuthRateLimitEvent{
		Type:      AuthRateLimitEventUnblockIP,
		IP:        ip,
		Timestamp: time.Now(),
		NodeID:    c.nodeID,
	}

	c.queueEvent(event)
}

// BroadcastFailureCount broadcasts a failure count update
func (c *ClusterAuthRateLimiter) BroadcastFailureCount(ip string, failureCount int, lastDelay time.Duration, firstFailure time.Time) {
	event := AuthRateLimitEvent{
		Type:         AuthRateLimitEventFailureCount,
		IP:           ip,
		FailureCount: failureCount,
		LastDelay:    lastDelay,
		FirstFailure: firstFailure,
		Timestamp:    time.Now(),
		NodeID:       c.nodeID,
	}

	c.queueEvent(event)
}

// BroadcastBlockSubnet broadcasts a subnet block event
func (c *ClusterAuthRateLimiter) BroadcastBlockSubnet(subnet string, blockedUntil time.Time, failureCount int, firstFailure time.Time) {
	event := AuthRateLimitEvent{
		Type:         AuthRateLimitEventBlockSubnet,
		Subnet:       subnet,
		BlockedUntil: blockedUntil,
		FailureCount: failureCount,
		FirstFailure: firstFailure,
		Timestamp:    time.Now(),
		NodeID:       c.nodeID,
	}

	c.queueEvent(event)
}

// BroadcastUnblockSubnet broadcasts a subnet unblock event
func (c *ClusterAuthRateLimiter) BroadcastUnblockSubnet(subnet string) {
	event := AuthRateLimitEvent{
		Type:      AuthRateLimitEventUnblockSubnet,
		Subnet:    subnet,
		Timestamp: time.Now(),
		NodeID:    c.nodeID,
	}

	c.queueEvent(event)
}

// BroadcastUsernameFailure broadcasts a username failure event
func (c *ClusterAuthRateLimiter) BroadcastUsernameFailure(username string, failureCount int, firstFailure time.Time) {
	event := AuthRateLimitEvent{
		Type:         AuthRateLimitEventUsernameFailure,
		Username:     username,
		FailureCount: failureCount,
		FirstFailure: firstFailure,
		Timestamp:    time.Now(),
		NodeID:       c.nodeID,
	}

	c.queueEvent(event)
}

// BroadcastUsernameSuccess broadcasts a username success event
func (c *ClusterAuthRateLimiter) BroadcastUsernameSuccess(username string) {
	event := AuthRateLimitEvent{
		Type:      AuthRateLimitEventUsernameSuccess,
		Username:  username,
		Timestamp: time.Now(),
		NodeID:    c.nodeID,
	}

	c.queueEvent(event)
}

// queueEvent adds an event to the broadcast queue
func (c *ClusterAuthRateLimiter) queueEvent(event AuthRateLimitEvent) {
	c.queueMu.Lock()
	defer c.queueMu.Unlock()

	// Check queue size limit
	if len(c.broadcastQueue) >= c.maxQueueSize {
		// Drop oldest 10% (1000 events)
		dropCount := c.maxQueueSize / 10
		c.broadcastQueue = c.broadcastQueue[dropCount:]
		c.logger.Warn("auth rate limit broadcast queue overflow, dropped oldest events",
			"dropped", dropCount,
			"remaining", len(c.broadcastQueue))
	}

	c.broadcastQueue = append(c.broadcastQueue, event)
}

// HandleClusterEvent handles incoming cluster events
func (c *ClusterAuthRateLimiter) HandleClusterEvent(data []byte) {
	var event AuthRateLimitEvent
	if err := decodeEvent(data, &event); err != nil {
		c.logger.Warn("failed to decode auth rate limit event", "error", err)
		return
	}

	// Ignore our own events
	if event.NodeID == c.nodeID {
		return
	}

	// Ignore stale events (older than 5 minutes)
	if time.Since(event.Timestamp) > 5*time.Minute {
		c.logger.Debug("ignoring stale auth rate limit event",
			"type", event.Type,
			"age", time.Since(event.Timestamp))
		return
	}

	// Gossip is untrusted: validate/clamp fields before applying so a malicious
	// or buggy peer cannot lock out an arbitrary IP forever or inject an absurd
	// failure counter. Events referencing an unparseable IP or username are dropped.
	if !c.sanitizeEvent(&event) {
		return
	}

	// Handle event based on type
	switch event.Type {
	case AuthRateLimitEventBlockIP:
		c.limiter.ApplyBlockIP(event.IP, event.BlockedUntil, event.FailureCount, event.FirstFailure)

	case AuthRateLimitEventUnblockIP:
		c.limiter.ApplyUnblockIP(event.IP)

	case AuthRateLimitEventFailureCount:
		c.limiter.ApplyFailureCount(event.IP, event.FailureCount, event.LastDelay, event.FirstFailure)

	case AuthRateLimitEventBlockSubnet:
		c.limiter.ApplyBlockSubnet(event.Subnet, event.BlockedUntil, event.FailureCount, event.FirstFailure)

	case AuthRateLimitEventUnblockSubnet:
		c.limiter.ApplyUnblockSubnet(event.Subnet)

	case AuthRateLimitEventUsernameFailure:
		c.limiter.ApplyUsernameFailure(event.Username, event.FailureCount, event.FirstFailure)

	case AuthRateLimitEventUsernameSuccess:
		c.limiter.ClearUsernameFailure(event.Username)

	default:
		c.logger.Warn("unknown auth rate limit event type", "type", event.Type)
	}
}

// sanitizeEvent validates and clamps an incoming gossip event in place. It
// returns false if the event should be dropped entirely.
func (c *ClusterAuthRateLimiter) sanitizeEvent(event *AuthRateLimitEvent) bool {
	switch event.Type {
	case AuthRateLimitEventBlockIP, AuthRateLimitEventUnblockIP, AuthRateLimitEventFailureCount:
		if net.ParseIP(event.IP) == nil {
			c.logger.Warn("dropping auth rate limit event with invalid IP", "type", event.Type, "ip", event.IP)
			return false
		}
	case AuthRateLimitEventBlockSubnet, AuthRateLimitEventUnblockSubnet:
		if !validGossipSubnet(event.Subnet) {
			c.logger.Warn("dropping auth rate limit event with invalid subnet", "type", event.Type, "subnet", event.Subnet)
			return false
		}
	case AuthRateLimitEventUsernameFailure, AuthRateLimitEventUsernameSuccess:
		if event.Username == "" || len(event.Username) > maxAuthGossipUsernameLen {
			c.logger.Warn("dropping auth rate limit event with invalid username", "type", event.Type)
			return false
		}
	}

	// Clamp failure counts to a sane ceiling (also guards against negatives).
	if event.FailureCount < 0 {
		event.FailureCount = 0
	} else if event.FailureCount > maxAuthGossipFailureCount {
		event.FailureCount = maxAuthGossipFailureCount
	}

	// Clamp the block expiry: a peer must not be able to block an IP for longer
	// than this node's own maximum block duration (plus a skew/age margin).
	if !event.BlockedUntil.IsZero() {
		maxUntil := time.Now().Add(c.limiter.MaxBlockDuration() + authGossipBlockSkewMargin)
		if event.BlockedUntil.After(maxUntil) {
			event.BlockedUntil = maxUntil
		}
	}

	return true
}

// validGossipSubnet bounds the blast radius a peer can claim: the prefix must
// parse, be in canonical (masked) form, and be no broader than a /16 (v4) or
// /32 (v6) — gossip must never be able to block half the internet — and no
// narrower than a single member identity, where per-IP events are the honest
// vocabulary. Deliberately NOT an equality check against this node's own
// configured prefix length: nodes may briefly disagree during a config
// rollout, and a /23 from a peer is still a legitimate, bounded block.
func validGossipSubnet(subnet string) bool {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return false
	}
	if prefix.Masked() != prefix {
		return false
	}
	bits := prefix.Bits()
	if prefix.Addr().Is4() {
		return bits >= 16 && bits < 32
	}
	return bits >= 32 && bits <= ipv6MemberBits
}

// broadcastRoutine periodically broadcasts queued events
func (c *ClusterAuthRateLimiter) broadcastRoutine() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		c.queueMu.Lock()
		if len(c.broadcastQueue) == 0 {
			c.queueMu.Unlock()
			continue
		}

		// Get events to broadcast
		events := make([]AuthRateLimitEvent, len(c.broadcastQueue))
		copy(events, c.broadcastQueue)
		c.broadcastQueue = c.broadcastQueue[:0]
		c.queueMu.Unlock()

		// Broadcast each event
		for _, event := range events {
			data, err := encodeEvent(event)
			if err != nil {
				c.logger.Warn("failed to encode auth rate limit event", "error", err)
				continue
			}

			// Use existing cluster broadcast mechanism
			// We'll need to add a new message type to cluster package
			if err := c.cluster.BroadcastAuthRateLimit(data); err != nil {
				c.logger.Warn("failed to broadcast auth rate limit event", "error", err)
			}
		}
	}
}

// encodeEvent encodes an event as JSON. The gossip envelope
// (cluster.GossipMessage) carries its payload as json.RawMessage, so the
// payload must itself be JSON: the previous gob encoding made every envelope
// fail to marshal and no auth rate-limit event was ever broadcast.
func encodeEvent(event AuthRateLimitEvent) ([]byte, error) {
	return json.Marshal(event)
}

// decodeEvent decodes an event produced by encodeEvent.
func decodeEvent(data []byte, event *AuthRateLimitEvent) error {
	return json.Unmarshal(data, event)
}

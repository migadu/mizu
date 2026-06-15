package smtp

import (
	"bytes"
	"encoding/gob"
	"log/slog"
	"migadu/mizu/pkg/cluster"
	"migadu/mizu/pkg/concurrency"
	"sync"
	"time"
)

// AuthRateLimitEventType identifies the type of auth rate limit event
type AuthRateLimitEventType string

const (
	AuthRateLimitEventBlockIP         AuthRateLimitEventType = "BLOCK_IP"
	AuthRateLimitEventUnblockIP       AuthRateLimitEventType = "UNBLOCK_IP"
	AuthRateLimitEventFailureCount    AuthRateLimitEventType = "FAILURE_COUNT"
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
}

// ClusterAuthRateLimiter handles cluster synchronization for auth rate limiting
type ClusterAuthRateLimiter struct {
	limiter        *AuthRateLimiter
	cluster        *cluster.Cluster
	logger         *slog.Logger
	broadcastQueue []AuthRateLimitEvent
	queueMu        sync.Mutex
	nodeID         string
	maxQueueSize   int
}

// NewClusterAuthRateLimiter creates a new cluster auth rate limiter
func NewClusterAuthRateLimiter(limiter *AuthRateLimiter, clusterMgr *cluster.Cluster, logger *slog.Logger) *ClusterAuthRateLimiter {
	nodeID := clusterMgr.LocalNode().Name

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

	// Handle event based on type
	switch event.Type {
	case AuthRateLimitEventBlockIP:
		c.limiter.ApplyBlockIP(event.IP, event.BlockedUntil, event.FailureCount, event.FirstFailure)

	case AuthRateLimitEventUnblockIP:
		c.limiter.ApplyUnblockIP(event.IP)

	case AuthRateLimitEventFailureCount:
		c.limiter.ApplyFailureCount(event.IP, event.FailureCount, event.LastDelay, event.FirstFailure)

	case AuthRateLimitEventUsernameFailure:
		c.limiter.ApplyUsernameFailure(event.Username, event.FailureCount, event.FirstFailure)

	case AuthRateLimitEventUsernameSuccess:
		c.limiter.ClearUsernameFailure(event.Username)

	default:
		c.logger.Warn("unknown auth rate limit event type", "type", event.Type)
	}
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

// encodeEvent encodes an event using gob
func encodeEvent(event AuthRateLimitEvent) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(event); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeEvent decodes an event using gob
func decodeEvent(data []byte, event *AuthRateLimitEvent) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(event)
}

package smtp

import (
	"encoding/json"
	"testing"
	"time"

	"migadu/mizu/pkg/cluster"
)

// Audit B8 (docs/security-audit-todo.md): auth rate-limit events were
// gob-encoded and then placed in the gossip envelope as json.RawMessage.
// Gob output is not JSON, so marshalling the envelope failed for every event
// and nothing was ever broadcast: with cluster_sync_enabled, blocks and
// `mizu-admin unblock-ip` silently stayed node-local.
//
// This builds the envelope exactly as Cluster.BroadcastAuthRateLimit does and
// takes it apart exactly as the receive path does.
func TestAudit_AuthRateLimitEventSurvivesGossipEnvelope(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	events := []AuthRateLimitEvent{
		{Type: AuthRateLimitEventBlockIP, IP: "203.0.113.7", Timestamp: now, NodeID: "n1", BlockedUntil: now.Add(30 * time.Minute), FailureCount: 50, FirstFailure: now.Add(-time.Minute)},
		{Type: AuthRateLimitEventUnblockIP, IP: "203.0.113.7", Timestamp: now, NodeID: "n1"},
		{Type: AuthRateLimitEventFailureCount, IP: "2001:db8:1:2::", Timestamp: now, NodeID: "n1", FailureCount: 3, LastDelay: 4 * time.Second},
		{Type: AuthRateLimitEventBlockSubnet, Subnet: "203.0.113.0/24", Timestamp: now, NodeID: "n1", BlockedUntil: now.Add(time.Hour)},
		{Type: AuthRateLimitEventUsernameFailure, Username: "user@example.com", Timestamp: now, NodeID: "n1", FailureCount: 2},
	}

	for _, want := range events {
		data, err := encodeEvent(want)
		if err != nil {
			t.Fatalf("%s: encodeEvent: %v", want.Type, err)
		}

		wire, err := json.Marshal(cluster.GossipMessage{
			Type:    cluster.MessageTypeAuthRateLimit,
			Payload: json.RawMessage(data),
		})
		if err != nil {
			t.Fatalf("%s: the gossip envelope cannot carry the event: %v", want.Type, err)
		}

		var msg cluster.GossipMessage
		if err := json.Unmarshal(wire, &msg); err != nil {
			t.Fatalf("%s: envelope unmarshal: %v", want.Type, err)
		}
		var got AuthRateLimitEvent
		if err := decodeEvent(msg.Payload, &got); err != nil {
			t.Fatalf("%s: decodeEvent: %v", want.Type, err)
		}
		if got.Type != want.Type || got.IP != want.IP || got.Subnet != want.Subnet ||
			got.Username != want.Username || got.NodeID != want.NodeID ||
			got.FailureCount != want.FailureCount || got.LastDelay != want.LastDelay ||
			!got.Timestamp.Equal(want.Timestamp) || !got.BlockedUntil.Equal(want.BlockedUntil) ||
			!got.FirstFailure.Equal(want.FirstFailure) {
			t.Errorf("%s: round trip changed the event:\n got  %+v\n want %+v", want.Type, got, want)
		}
	}
}

package cluster

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// Audit B9 (docs/security-audit-todo.md): state snapshots were queued on
// memberlist's UDP gossip queue whatever their size. That queue only ever
// picks messages that fit one UDP packet (about 1.3 KB), never drops the ones
// that do not, and nothing invalidated older snapshots. As soon as a snapshot
// outgrew a packet - a few dozen cached recipients or rate-limit keys, which
// an SMTP client can cause - it was never delivered, cluster-wide limits
// silently stopped, and one more copy piled up in memory every gossip tick.

func newTestPair(t *testing.T, port1, port2 int) (*Cluster, *Cluster) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c1, err := NewCluster(Config{NodeName: "node1", BindAddr: "127.0.0.1", BindPort: port1, Logger: logger})
	if err != nil {
		t.Fatalf("node1: %v", err)
	}
	t.Cleanup(func() { c1.Shutdown() })
	c2, err := NewCluster(Config{NodeName: "node2", BindAddr: "127.0.0.1", BindPort: port2,
		Peers: []string{"127.0.0.1:" + itoa(port1)}, Logger: logger})
	if err != nil {
		t.Fatalf("node2: %v", err)
	}
	t.Cleanup(func() { c2.Shutdown() })

	deadline := time.Now().Add(5 * time.Second)
	for c1.NumMembers() != 2 || c2.NumMembers() != 2 {
		if time.Now().After(deadline) {
			t.Fatal("cluster did not converge")
		}
		time.Sleep(50 * time.Millisecond)
	}
	return c1, c2
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func bigJSONPayload(t *testing.T, size int) []byte {
	t.Helper()
	p, err := json.Marshal(map[string]string{"blob": string(bytes.Repeat([]byte("x"), size))})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAudit_OversizedGossipIsDeliveredAndNotQueued(t *testing.T) {
	c1, c2 := newTestPair(t, 17961, 17962)

	var mu sync.Mutex
	got := map[string][]byte{}
	c2.RegisterConnectionStateHandler(func(data []byte) {
		mu.Lock()
		got["conn"] = append([]byte(nil), data...)
		mu.Unlock()
	})
	c2.RegisterRateLimitHandler(func(data []byte) {
		mu.Lock()
		got["rate"] = append([]byte(nil), data...)
		mu.Unlock()
	})

	connPayload := bigJSONPayload(t, 60_000) // far beyond one UDP packet
	ratePayload := bigJSONPayload(t, 40_000)
	if err := c1.BroadcastConnectionState(connPayload); err != nil {
		t.Fatalf("BroadcastConnectionState: %v", err)
	}
	if err := c1.BroadcastRateLimit(ratePayload); err != nil {
		t.Fatalf("BroadcastRateLimit: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		okConn := bytes.Equal(got["conn"], connPayload)
		okRate := bytes.Equal(got["rate"], ratePayload)
		mu.Unlock()
		if okConn && okRate {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("oversized snapshots were not delivered to the peer (conn=%v rate=%v)", okConn, okRate)
		}
		time.Sleep(50 * time.Millisecond)
	}

	if n := c1.broadcasts.NumQueued(); n != 0 {
		t.Fatalf("%d oversized messages left on the UDP gossip queue, want 0", n)
	}
}

// Snapshots that do fit a packet still use gossip, but a newer snapshot
// replaces an older queued one instead of piling up behind it.
func TestAudit_NewerSnapshotReplacesQueuedOne(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := NewCluster(Config{NodeName: "solo", BindAddr: "127.0.0.1", BindPort: 17963, Logger: logger})
	if err != nil {
		t.Fatalf("cluster: %v", err)
	}
	defer c.Shutdown()

	for i := 0; i < 50; i++ {
		if err := c.BroadcastConnectionState([]byte(`{"n":` + itoa(i) + `}`)); err != nil {
			t.Fatal(err)
		}
		if err := c.BroadcastRateLimit([]byte(`[{"n":` + itoa(i) + `}]`)); err != nil {
			t.Fatal(err)
		}
	}
	if n := c.broadcasts.NumQueued(); n > 2 {
		t.Fatalf("%d snapshots queued after 50 rounds of two kinds, want at most 2", n)
	}

	// Auth rate-limit messages are events, not snapshots: each one matters.
	for i := 0; i < 5; i++ {
		if err := c.BroadcastAuthRateLimit([]byte(`{"n":` + itoa(i) + `}`)); err != nil {
			t.Fatal(err)
		}
	}
	if n := c.broadcasts.NumQueued(); n < 5 {
		t.Fatalf("only %d messages queued; auth events must not invalidate one another", n)
	}
}

// Audit B11: there was one handler slot per message type for the whole
// process, and payloads carried no server name. On a node running several
// [[server]] blocks (465 and 587, say) the last one to register received every
// server's gossip and the others received nothing.
func TestAudit_GossipIsRoutedPerServerScope(t *testing.T) {
	c1, c2 := newTestPair(t, 17964, 17965)

	var mu sync.Mutex
	got := map[string][]string{}
	record := func(key string) func([]byte) {
		return func(data []byte) {
			mu.Lock()
			got[key] = append(got[key], string(data))
			mu.Unlock()
		}
	}
	for _, scope := range []string{"smtps", "submission"} {
		s := c2.Scoped(scope)
		s.RegisterConnectionStateHandler(record(scope + "/conn"))
		s.RegisterRateLimitHandler(record(scope + "/rate"))
		s.RegisterAuthRateLimitHandler(record(scope + "/auth"))
	}

	if err := c1.Scoped("smtps").BroadcastRateLimit([]byte(`{"from":"smtps"}`)); err != nil {
		t.Fatal(err)
	}
	if err := c1.Scoped("submission").BroadcastRateLimit([]byte(`{"from":"submission"}`)); err != nil {
		t.Fatal(err)
	}
	if err := c1.Scoped("submission").BroadcastAuthRateLimit([]byte(`{"auth":"submission"}`)); err != nil {
		t.Fatal(err)
	}
	if err := c1.Scoped("smtps").BroadcastConnectionState(bigJSONPayload(t, 20_000)); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		done := len(got["smtps/rate"]) > 0 && len(got["submission/rate"]) > 0 &&
			len(got["submission/auth"]) > 0 && len(got["smtps/conn"]) > 0
		mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			mu.Lock()
			defer mu.Unlock()
			t.Fatalf("not every scope received its own gossip: %v", keysOf(got))
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // let any misrouted retransmits arrive

	mu.Lock()
	defer mu.Unlock()
	for _, m := range got["smtps/rate"] {
		if m != `{"from":"smtps"}` {
			t.Errorf("smtps received another server's rate-limit gossip: %s", m)
		}
	}
	for _, m := range got["submission/rate"] {
		if m != `{"from":"submission"}` {
			t.Errorf("submission received another server's rate-limit gossip: %s", m)
		}
	}
	if len(got["smtps/auth"]) != 0 {
		t.Errorf("smtps received submission's auth events: %v", got["smtps/auth"])
	}
	if len(got["submission/conn"]) != 0 {
		t.Error("submission received smtps's connection state")
	}
}

func keysOf(m map[string][]string) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// Two servers' snapshots of the same type must not supersede each other on
// the gossip queue.
func TestAudit_SnapshotsOfDifferentScopesDoNotInvalidateEachOther(t *testing.T) {
	a := &broadcast{kind: MessageTypeRateLimit, scope: "smtps", snapshot: true}
	b := &broadcast{kind: MessageTypeRateLimit, scope: "submission", snapshot: true}
	a2 := &broadcast{kind: MessageTypeRateLimit, scope: "smtps", snapshot: true}
	if a.Invalidates(b) || b.Invalidates(a) {
		t.Fatal("snapshots from different server scopes must both be delivered")
	}
	if !a2.Invalidates(a) {
		t.Fatal("a newer snapshot must still replace the older one of the same scope")
	}
}

// Review follow-up: the "skip while the previous large send is in flight" rule
// is only sound for snapshots, where the next tick carries fresher state. An
// event is sent once; skipping it loses it.
func TestAudit_LargeEventsAreNotSkippedWhileAnotherIsInFlight(t *testing.T) {
	c1, c2 := newTestPair(t, 17966, 17967)

	var mu sync.Mutex
	seen := map[string]bool{}
	c2.RegisterAuthRateLimitHandler(func(data []byte) {
		var m map[string]string
		if json.Unmarshal(data, &m) == nil {
			mu.Lock()
			seen[m["id"]] = true
			mu.Unlock()
		}
	})

	const n = 20
	for i := 0; i < n; i++ {
		payload, _ := json.Marshal(map[string]string{"id": itoa(i), "pad": string(bytes.Repeat([]byte("u"), 2000))})
		if err := c1.BroadcastAuthRateLimit(payload); err != nil {
			t.Fatal(err)
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		got := len(seen)
		mu.Unlock()
		if got == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d large events delivered; events must never be skipped", got, n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

package smtp

import (
	"io"
	"net"
	"testing"
	"time"
)

// Audit A8 (docs/security-audit-todo.md): connection limits were only applied
// in Backend.NewSession, which go-smtp calls on EHLO. A client that connected
// and never greeted (or sent NOOP now and then) was not counted by anything,
// so one address could hold sockets up to the fd limit. The accept limiter
// counts sockets where they are created.

func startLimitedListener(t *testing.T, maxTotal, maxPerIP int, exempt []*net.IPNet) (*AcceptLimiter, chan net.Conn) {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	l := NewAcceptLimiter(raw, maxTotal, maxPerIP, exempt, nil)
	accepted := make(chan net.Conn, 64)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c
		}
	}()
	t.Cleanup(func() { l.Close() })
	return l, accepted
}

// dialAndProbe connects and reports whether the server kept the socket open.
func dialAndProbe(t *testing.T, addr net.Addr) (net.Conn, bool) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// A refused socket is closed by the server: the read ends at once with
	// EOF/reset. A kept one stays silent until the deadline.
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, err = c.Read(make([]byte, 1))
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		_ = c.SetReadDeadline(time.Time{})
		return c, true
	}
	if err != io.EOF && err == nil {
		t.Fatalf("unexpected data from a silent server")
	}
	c.Close()
	return nil, false
}

func waitAccepted(t *testing.T, ch chan net.Conn) net.Conn {
	t.Helper()
	select {
	case c := <-ch:
		return c
	case <-time.After(2 * time.Second):
		t.Fatal("expected a connection to be accepted")
		return nil
	}
}

func TestAudit_AcceptLimiterCapsSocketsPerIPBeforeAnyGreeting(t *testing.T) {
	l, accepted := startLimitedListener(t, 100, 2, nil)

	// Two silent connections - no EHLO, nothing - take both slots.
	c1, ok1 := dialAndProbe(t, l.Addr())
	c2, ok2 := dialAndProbe(t, l.Addr())
	if !ok1 || !ok2 {
		t.Fatal("the first two connections must be accepted")
	}
	s1 := waitAccepted(t, accepted)
	waitAccepted(t, accepted)

	// A third from the same address is refused at accept.
	if _, ok := dialAndProbe(t, l.Addr()); ok {
		t.Fatal("a third socket from one IP at a per-IP limit of 2 must be refused")
	}
	if total, _ := l.Counts(); total != 2 {
		t.Fatalf("total = %d, want 2", total)
	}

	// Closing one (server side, as go-smtp does) frees exactly one slot.
	s1.Close()
	s1.Close() // double close must not free a second slot
	c1.Close()
	if total, _ := l.Counts(); total != 1 {
		t.Fatalf("total after one close = %d, want 1", total)
	}
	c3, ok := dialAndProbe(t, l.Addr())
	if !ok {
		t.Fatal("a slot freed by close must be usable again")
	}
	waitAccepted(t, accepted)
	if _, ok := dialAndProbe(t, l.Addr()); ok {
		t.Fatal("the limit must hold again after the freed slot is reused")
	}
	c2.Close()
	c3.Close()
}

func TestAudit_AcceptLimiterCapsTotalSockets(t *testing.T) {
	l, accepted := startLimitedListener(t, 3, 0, nil)
	var conns []net.Conn
	for i := 0; i < 3; i++ {
		c, ok := dialAndProbe(t, l.Addr())
		if !ok {
			t.Fatalf("connection %d must be accepted", i+1)
		}
		conns = append(conns, c)
		waitAccepted(t, accepted)
	}
	if _, ok := dialAndProbe(t, l.Addr()); ok {
		t.Fatal("a fourth socket at a total limit of 3 must be refused")
	}
	for _, c := range conns {
		c.Close()
	}
}

// With PROXY protocol the TCP peer is the load balancer, not the client, so
// trusted proxies are exempt from the per-IP count (the total still applies).
func TestAudit_AcceptLimiterExemptsTrustedProxiesFromPerIP(t *testing.T) {
	_, loopback, _ := net.ParseCIDR("127.0.0.0/8")
	l, accepted := startLimitedListener(t, 4, 1, []*net.IPNet{loopback})
	var conns []net.Conn
	for i := 0; i < 4; i++ {
		c, ok := dialAndProbe(t, l.Addr())
		if !ok {
			t.Fatalf("connection %d from an exempt peer must be accepted", i+1)
		}
		conns = append(conns, c)
		waitAccepted(t, accepted)
	}
	if _, ok := dialAndProbe(t, l.Addr()); ok {
		t.Fatal("the total limit still applies to exempt peers")
	}
	for _, c := range conns {
		c.Close()
	}
}

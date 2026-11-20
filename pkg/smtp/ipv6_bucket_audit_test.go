package smtp

import (
	"fmt"
	"io"
	"log/slog"
	"testing"

	"migadu/mizu/pkg/config"
)

// A11: connection and rate limits keyed IPv6 peers on the full address. One
// customer allocation is a /64 - 2^64 addresses - so a single host had a
// fresh per-IP budget for every connection and was bounded only by the global
// cap, which it could fill to lock everyone else out. Every per-IP limit now
// keys IPv6 on the /64, as the auth limiter already did (bucketIP).

func TestAudit_ConnectionTrackerKeysIPv6ByPrefix(t *testing.T) {
	ct := NewConnectionTracker(100, 2, 0, nil)
	var refused int
	for i := 0; i < 10; i++ {
		if _, err := ct.Acquire(fmt.Sprintf("[2001:db8:1:2::%x]:5000", i+1)); err != nil {
			refused++
		}
	}
	if refused != 8 {
		t.Fatalf("10 connections from one /64 at a per-IP limit of 2: %d refused, want 8", refused)
	}
	// A different /64 has its own budget, and so do distinct IPv4 addresses.
	if _, err := ct.Acquire("[2001:db8:1:3::1]:5000"); err != nil {
		t.Fatalf("other /64: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := ct.Acquire(fmt.Sprintf("192.0.2.%d:5000", i+1)); err != nil {
			t.Fatalf("distinct IPv4 address %d: %v", i, err)
		}
	}
	if got := ct.GetCountForIP("2001:db8:1:2::ffff"); got != 2 {
		t.Fatalf("GetCountForIP for another address of the /64 = %d, want 2", got)
	}
}

func TestAudit_RateLimiterKeysIPv6ByPrefix(t *testing.T) {
	rl := NewRateLimiter(config.RateLimitConfig{Enabled: true, Dimensions: []config.RateLimitDimension{
		{Name: "per_ip", Keys: []string{"IP"}, Limit: 2, WindowSeconds: 60},
	}}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer rl.Shutdown()

	var refused int
	for i := 0; i < 10; i++ {
		if rl.CheckRateLimit(SessionContext{RemoteAddr: fmt.Sprintf("2001:db8:1:2::%x", i+1)}) != nil {
			refused++
		}
	}
	if refused != 8 {
		t.Fatalf("10 connections from one /64 at a limit of 2: %d refused, want 8", refused)
	}
}

func TestAudit_AcceptLimiterKeysIPv6ByPrefix(t *testing.T) {
	if a, b := acceptKey("2001:db8:1:2::1"), acceptKey("2001:db8:1:2:ffff::9"); a != b {
		t.Fatalf("two addresses of one /64 have different keys: %q and %q", a, b)
	}
	if a, b := acceptKey("2001:db8:1:2::1"), acceptKey("2001:db8:1:3::1"); a == b {
		t.Fatal("two different /64s share a key")
	}
	if a, b := acceptKey("192.0.2.1"), acceptKey("192.0.2.2"); a == b {
		t.Fatal("two IPv4 addresses share a key")
	}
}

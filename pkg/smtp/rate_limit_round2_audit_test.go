package smtp

import (
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"migadu/mizu/pkg/config"
)

func newRound2Limiter(t *testing.T, dims ...config.RateLimitDimension) *RateLimiter {
	t.Helper()
	rl := NewRateLimiter(config.RateLimitConfig{Enabled: true, Dimensions: dims},
		nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(rl.Shutdown)
	return rl
}

// C6: every dimension was charged at EHLO, at MAIL and again at each RCPT, so
// one message to 50 recipients cost a per-IP limit 52 and a per-sender limit
// 51. Each dimension is charged once, at the stage where its last key becomes
// known: IP alone = connections, sender-keyed = messages, recipient-keyed =
// recipients.
func TestAudit_DimensionIsChargedOnceAtItsOwnStage(t *testing.T) {
	rl := newRound2Limiter(t,
		config.RateLimitDimension{Name: "per_ip", Keys: []string{"IP"}, Limit: 3, WindowSeconds: 60},
		config.RateLimitDimension{Name: "per_from", Keys: []string{"FROM"}, Limit: 3, WindowSeconds: 60},
		config.RateLimitDimension{Name: "per_ip_user", Keys: []string{"IP", "AUTHENTICATED_USER"}, Limit: 3, WindowSeconds: 60},
		config.RateLimitDimension{Name: "per_to", Keys: []string{"TO"}, Limit: 100, WindowSeconds: 60},
	)

	// Two connections, each sending one message to 50 recipients: well inside
	// "3 connections per IP" and "3 messages per sender".
	for conn := 0; conn < 2; conn++ {
		base := SessionContext{RemoteAddr: "192.0.2.1"}
		if err := rl.CheckRateLimit(base); err != nil {
			t.Fatalf("connection %d: %v", conn, err)
		}
		base.From, base.AuthenticatedUser = "sender@example.org", "sender@example.org"
		base.Stage = StageMail
		if err := rl.CheckRateLimit(base); err != nil {
			t.Fatalf("connection %d MAIL: %v", conn, err)
		}
		base.Stage = StageRcpt
		for i := 0; i < 50; i++ {
			base.To = []string{fmt.Sprintf("rcpt%d@example.net", i)}
			if err := rl.CheckRateLimit(base); err != nil {
				t.Fatalf("connection %d RCPT %d: %v", conn, i, err)
			}
		}
	}

	// The limits still bite at their own stage.
	if err := rl.CheckRateLimit(SessionContext{RemoteAddr: "192.0.2.1"}); err != nil {
		t.Fatalf("third connection: %v", err)
	}
	if err := rl.CheckRateLimit(SessionContext{RemoteAddr: "192.0.2.1"}); err == nil {
		t.Fatal("fourth connection within the window must be refused by per_ip")
	}
	mail := SessionContext{RemoteAddr: "192.0.2.9", From: "sender@example.org", Stage: StageMail}
	if err := rl.CheckRateLimit(mail); err != nil {
		t.Fatalf("third message: %v", err)
	}
	if err := rl.CheckRateLimit(mail); err == nil {
		t.Fatal("fourth message from the sender must be refused by per_from")
	}
}

// C5: dimensions were charged one by one as they passed, with no rollback. A
// client refused by a later dimension had still spent the earlier ones, so an
// already-blocked client could burn a victim recipient's budget.
func TestAudit_RefusedRequestChargesNothing(t *testing.T) {
	rl := newRound2Limiter(t,
		config.RateLimitDimension{Name: "per_to", Keys: []string{"TO"}, Limit: 5, WindowSeconds: 60},
		config.RateLimitDimension{Name: "per_ip_to_domain", Keys: []string{"IP", "TO_DOMAIN"}, Limit: 2, WindowSeconds: 60},
	)

	attacker := SessionContext{RemoteAddr: "198.51.100.7", From: "x@evil.test",
		To: []string{"victim@victim.example"}, Stage: StageRcpt}
	refused := 0
	for i := 0; i < 20; i++ {
		if rl.CheckRateLimit(attacker) != nil {
			refused++
		}
	}
	if refused != 18 {
		t.Fatalf("attacker refused %d of 20, want 18", refused)
	}

	// The attacker got 2 through; the victim's budget of 5 must have 3 left.
	for i := 0; i < 3; i++ {
		honest := SessionContext{RemoteAddr: fmt.Sprintf("203.0.113.%d", i+1), From: "friend@example.org",
			To: []string{"victim@victim.example"}, Stage: StageRcpt}
		if err := rl.CheckRateLimit(honest); err != nil {
			t.Fatalf("honest sender %d refused - the attacker's refused attempts were charged to the victim: %v", i, err)
		}
	}
}

// C7: extractDomain returned "" for anything but exactly one "@", and a
// dimension with an empty key is skipped. `MAIL FROM:<"a@b"@spam.test>` (which
// go-smtp unquotes to a@b@spam.test) therefore had no FROM_DOMAIN limit at
// all, and a trailing dot bought a second budget.
func TestAudit_DomainDimensionsCannotBeSidestepped(t *testing.T) {
	rl := newRound2Limiter(t,
		config.RateLimitDimension{Name: "per_from_domain", Keys: []string{"FROM_DOMAIN"}, Limit: 1, WindowSeconds: 60},
		config.RateLimitDimension{Name: "per_to_domain", Keys: []string{"TO_DOMAIN"}, Limit: 1, WindowSeconds: 60},
	)

	if err := rl.CheckRateLimit(SessionContext{RemoteAddr: "192.0.2.1", From: "a@spam.test", Stage: StageMail}); err != nil {
		t.Fatal(err)
	}
	for _, from := range []string{"a@b@spam.test", "a@spam.test.", "a@SPAM.test"} {
		if rl.CheckRateLimit(SessionContext{RemoteAddr: "192.0.2.1", From: from, Stage: StageMail}) == nil {
			t.Errorf("MAIL FROM %q got a fresh FROM_DOMAIN budget", from)
		}
	}

	rcpt := func(to string) error {
		return rl.CheckRateLimit(SessionContext{RemoteAddr: "192.0.2.1", From: "z@other.test", To: []string{to}, Stage: StageRcpt})
	}
	if err := rcpt("v@victim.test"); err != nil {
		t.Fatal(err)
	}
	for _, to := range []string{"x@y@victim.test", "v@victim.test."} {
		if rcpt(to) == nil {
			t.Errorf("RCPT TO %q got a fresh TO_DOMAIN budget", to)
		}
	}
}

// C8: cleanup only removed windows whose counts were zero, but counts are
// reset lazily on the next hit - a window that was ever hit and then went
// idle stayed forever. Any client varying MAIL FROM could grow the map.
func TestAudit_ExpiredWindowsAreCleanedUp(t *testing.T) {
	rl := newRound2Limiter(t,
		config.RateLimitDimension{Name: "per_from", Keys: []string{"FROM"}, Limit: 10, WindowSeconds: 60},
	)
	for i := 0; i < 500; i++ {
		_ = rl.CheckRateLimit(SessionContext{RemoteAddr: "192.0.2.1", From: fmt.Sprintf("u%d@example.org", i), Stage: StageMail})
	}

	// Age every window far past its duration.
	old := time.Now().Add(-48 * time.Hour)
	rl.mu.Lock()
	for _, w := range rl.windows {
		w.windowStart, w.lastUpdate = old, old
	}
	rl.mu.Unlock()

	rl.cleanup()

	rl.mu.RLock()
	left := len(rl.windows)
	rl.mu.RUnlock()
	if left != 0 {
		t.Fatalf("%d of 500 long-expired windows survived cleanup", left)
	}
}

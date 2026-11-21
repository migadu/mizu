package smtp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"migadu/mizu/pkg/config"
)

// Audit A9 (docs/security-audit-todo.md): the TO / TO_DOMAIN rate-limit key was
// built from the FIRST recipient of the transaction, while the recipient being
// added is the last. A sender who put any throwaway address first never
// incremented the victim's key, so a per-recipient limit did not limit.
func TestAudit_ToRateLimitCountsTheRecipientBeingAdded(t *testing.T) {
	for _, key := range []string{"TO", "TO_DOMAIN"} {
		t.Run(key, func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			rl := NewRateLimiter(config.RateLimitConfig{
				Enabled: true,
				Dimensions: []config.RateLimitDimension{
					{Keys: []string{key}, Limit: 3, WindowSeconds: 60},
				},
			}, nil, logger)
			defer rl.Shutdown()

			cfg := config.DefaultConfig()
			cfg.Local = true
			sc := config.ServerConfig{Name: "t", Type: "relay", Hostname: "mx.example.com", MaxRecipientsPerMessage: 100}

			blocked := 0
			for i := 0; i < 10; i++ {
				s := &Session{
					serverConfig: &sc,
					globalConfig: &cfg,
					Logger:       logger,
					remoteAddr:   "192.0.2.1",
					ctx:          context.Background(),
					commandState: stateMail,
					from:         "sender@example.org",
					rateLimiter:  rl,
				}
				// A different throwaway first recipient each time, then the victim.
				if err := s.Rcpt(context.Background(), fmt.Sprintf("decoy%d@decoy%d.example", i, i), nil); err != nil {
					t.Fatalf("decoy RCPT %d: %v", i, err)
				}
				if err := s.Rcpt(context.Background(), "victim@victim.example", nil); err != nil {
					blocked++
				}
			}
			if blocked != 7 {
				t.Fatalf("victim addressed 10 times at a limit of 3: %d refused, want 7", blocked)
			}
		})
	}
}

type captureCluster struct {
	sent [][]byte
}

func (c *captureCluster) BroadcastRateLimit(data []byte) error {
	c.sent = append(c.sent, append([]byte(nil), data...))
	return nil
}
func (c *captureCluster) RegisterRateLimitHandler(func([]byte)) {}
func (c *captureCluster) LocalNodeName() string                 { return "node-a" }

// Audit B10: windows are reset lazily, on the next hit for the same key. A key
// that is never used again on this node kept its last count forever, and
// sendGossip reported every non-zero count with ReportedAt = now. Peers took
// that as fresh and kept charging it against the key in each new window: one
// burst on one node throttled that sender or recipient cluster-wide until the
// key happened to be used on the originating node again.
func TestAudit_ExpiredRateLimitWindowsAreNotGossiped(t *testing.T) {
	cc := &captureCluster{}
	rl := NewRateLimiter(config.RateLimitConfig{
		Enabled:               true,
		GossipEnabled:         true,
		GossipIntervalSeconds: 3600, // the test drives sendGossip itself
		Dimensions: []config.RateLimitDimension{
			{Name: "per-sender", Keys: []string{"FROM"}, Limit: 3, WindowSeconds: 1},
		},
	}, cc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer rl.Shutdown()

	for i := 0; i < 3; i++ {
		if err := rl.CheckRateLimit(SessionContext{RemoteAddr: "192.0.2.1", From: "x@victim.example", Stage: StageMail}); err != nil {
			t.Fatalf("hit %d: %v", i, err)
		}
	}

	rl.sendGossip()
	if len(cc.sent) != 1 {
		t.Fatalf("live window: %d broadcasts, want 1", len(cc.sent))
	}

	time.Sleep(1100 * time.Millisecond) // the 1s window is over
	cc.sent = nil
	rl.sendGossip()
	for _, payload := range cc.sent {
		var items []RateLimitData
		if err := json.Unmarshal(payload, &items); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		for _, item := range items {
			if item.Count > 0 {
				t.Errorf("expired window still gossiped: key=%q count=%d", item.CompositeKey, item.Count)
			}
		}
	}
}

// Audit A10: a whitelisted sender or sender domain exempted the session from
// EVERY dimension, including IP - and it was matched against the bare MAIL
// FROM, which on port 25 anyone can set. Claiming a whitelisted address was a
// free pass through all rate limiting.
//
// An unauthenticated MAIL FROM now only lifts the dimensions keyed on the
// sender. That keeps the point of the whitelist (a trusted sender is not
// throttled for its own volume) and gives a forger nothing: sender-keyed
// limits can be dodged with any made-up address anyway.
func TestAudit_ForgedWhitelistedSenderDoesNotBypassIPLimit(t *testing.T) {
	newLimiter := func() *RateLimiter {
		return NewRateLimiter(config.RateLimitConfig{
			Enabled:            true,
			WhitelistedDomains: []string{"trusted.example"},
			Dimensions: []config.RateLimitDimension{
				{Name: "per-to", Keys: []string{"TO"}, Limit: 3, WindowSeconds: 60},
				{Name: "per-sender-domain", Keys: []string{"FROM_DOMAIN"}, Limit: 2, WindowSeconds: 60},
			},
		}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}

	// (A pure IP dimension is charged at connect, before any MAIL FROM exists,
	// so it cannot be lifted by one; the recipient limit is the one a forged
	// sender could still have reached.)
	t.Run("unauthenticated: recipient limit still applies", func(t *testing.T) {
		rl := newLimiter()
		defer rl.Shutdown()
		blocked := 0
		for i := 0; i < 10; i++ {
			if err := rl.CheckRateLimit(SessionContext{RemoteAddr: "203.0.113.9", From: "ceo@trusted.example",
				To: []string{"victim@example.net"}, Stage: StageRcpt}); err != nil {
				blocked++
			}
		}
		if blocked != 7 {
			t.Fatalf("10 hits at a recipient limit of 3 with a forged whitelisted sender: %d refused, want 7", blocked)
		}
	})

	t.Run("unauthenticated: sender-keyed limit is lifted", func(t *testing.T) {
		rl := newLimiter()
		defer rl.Shutdown()
		// Different IPs so only the FROM_DOMAIN dimension (limit 2) could bite.
		for i := 0; i < 10; i++ {
			ctx := SessionContext{RemoteAddr: fmt.Sprintf("203.0.113.%d", i+1), From: "news@trusted.example", Stage: StageMail}
			if err := rl.CheckRateLimit(ctx); err != nil {
				t.Fatalf("hit %d: a whitelisted sender domain must not be limited by FROM_DOMAIN: %v", i+1, err)
			}
		}
	})

	t.Run("authenticated: sender is verified, all dimensions lifted", func(t *testing.T) {
		rl := newLimiter()
		defer rl.Shutdown()
		for i := 0; i < 10; i++ {
			ctx := SessionContext{RemoteAddr: "203.0.113.9", From: "ceo@trusted.example", AuthenticatedUser: "ceo@trusted.example",
				To: []string{"victim@example.net"}, Stage: StageRcpt}
			if err := rl.CheckRateLimit(ctx); err != nil {
				t.Fatalf("hit %d: an authenticated whitelisted sender must be exempt: %v", i+1, err)
			}
		}
	})
}

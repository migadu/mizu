package smtp

import (
	"io"

	"testing"
	"time"

	"log/slog"
	"migadu/mizu/pkg/config"
)

// TestRateLimiter_IPDimension tests IP-based rate limiting
func TestRateLimiter_IPDimension(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:               true,
		GossipEnabled:         false,
		GossipIntervalSeconds: 5,
		Dimensions: []config.RateLimitDimension{
			{
				Name:          "per_ip",
				Keys:          []string{"IP"},
				Limit:         3,
				WindowSeconds: 60,
			},
		},
	}

	rl := NewRateLimiter(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer rl.Shutdown()

	ctx := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
	}

	// Should allow first 3 connections
	for i := 0; i < 3; i++ {
		if err := rl.CheckRateLimit(ctx); err != nil {
			t.Fatalf("Connection %d should be allowed, got error: %v", i+1, err)
		}
	}

	// 4th connection should be blocked
	if err := rl.CheckRateLimit(ctx); err == nil {
		t.Fatal("4th connection should be rate limited")
	}

	// Different IP should be allowed
	ctx2 := SessionContext{
		RemoteAddr: "192.168.1.101:12345",
	}
	if err := rl.CheckRateLimit(ctx2); err != nil {
		t.Fatalf("Different IP should be allowed, got error: %v", err)
	}
}

// TestRateLimiter_FromDimension tests sender-based rate limiting
func TestRateLimiter_FromDimension(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:               true,
		GossipEnabled:         false,
		GossipIntervalSeconds: 5,
		Dimensions: []config.RateLimitDimension{
			{
				Name:          "per_sender",
				Keys:          []string{"FROM"},
				Limit:         5,
				WindowSeconds: 60,
			},
		},
	}

	rl := NewRateLimiter(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer rl.Shutdown()

	// Same sender from different IPs
	for i := 0; i < 5; i++ {
		ctx := SessionContext{
			RemoteAddr: "192.168.1.100:12345",
			From:       "spammer@example.com",
			Stage:      StageMail,
		}
		if err := rl.CheckRateLimit(ctx); err != nil {
			t.Fatalf("Email %d should be allowed, got error: %v", i+1, err)
		}
	}

	// 6th email from same sender should be blocked
	ctx := SessionContext{
		RemoteAddr: "192.168.1.200:12345", // Different IP
		From:       "spammer@example.com",
		Stage:      StageMail,
	}
	if err := rl.CheckRateLimit(ctx); err == nil {
		t.Fatal("6th email from same sender should be rate limited")
	}

	// Different sender should be allowed
	ctx2 := SessionContext{
		RemoteAddr: "192.168.1.200:12345",
		From:       "legitimate@example.com",
		Stage:      StageMail,
	}
	if err := rl.CheckRateLimit(ctx2); err != nil {
		t.Fatalf("Different sender should be allowed, got error: %v", err)
	}
}

// TestRateLimiter_FromDomainDimension tests sender domain-based rate limiting
func TestRateLimiter_FromDomainDimension(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:               true,
		GossipEnabled:         false,
		GossipIntervalSeconds: 5,
		Dimensions: []config.RateLimitDimension{
			{
				Name:          "per_sender_domain",
				Keys:          []string{"FROM_DOMAIN"},
				Limit:         10,
				WindowSeconds: 60,
			},
		},
	}

	rl := NewRateLimiter(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer rl.Shutdown()

	// Different senders from same domain
	for i := 0; i < 10; i++ {
		ctx := SessionContext{
			RemoteAddr: "192.168.1.100:12345",
			From:       "user" + string(rune('a'+i)) + "@spam-domain.com",
			Stage:      StageMail,
		}
		if err := rl.CheckRateLimit(ctx); err != nil {
			t.Fatalf("Email %d should be allowed, got error: %v", i+1, err)
		}
	}

	// 11th email from same domain should be blocked
	ctx := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "another@spam-domain.com",
		Stage:      StageMail,
	}
	if err := rl.CheckRateLimit(ctx); err == nil {
		t.Fatal("11th email from same domain should be rate limited")
	}

	// Different domain should be allowed
	ctx2 := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "user@different-domain.com",
		Stage:      StageMail,
	}
	if err := rl.CheckRateLimit(ctx2); err != nil {
		t.Fatalf("Different domain should be allowed, got error: %v", err)
	}
}

// TestRateLimiter_ToDimension tests recipient-based rate limiting
func TestRateLimiter_ToDimension(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:               true,
		GossipEnabled:         false,
		GossipIntervalSeconds: 5,
		Dimensions: []config.RateLimitDimension{
			{
				Name:          "per_recipient",
				Keys:          []string{"TO"},
				Limit:         3,
				WindowSeconds: 60,
			},
		},
	}

	rl := NewRateLimiter(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer rl.Shutdown()

	// Different senders to same recipient
	for i := 0; i < 3; i++ {
		ctx := SessionContext{
			RemoteAddr: "192.168.1.100:12345",
			From:       "sender" + string(rune('a'+i)) + "@example.com",
			To:         []string{"victim@example.com"},
			Stage:      StageRcpt,
		}
		if err := rl.CheckRateLimit(ctx); err != nil {
			t.Fatalf("Email %d should be allowed, got error: %v", i+1, err)
		}
	}

	// 4th email to same recipient should be blocked
	ctx := SessionContext{
		RemoteAddr: "192.168.1.200:12345",
		From:       "another@example.com",
		To:         []string{"victim@example.com"},
		Stage:      StageRcpt,
	}
	if err := rl.CheckRateLimit(ctx); err == nil {
		t.Fatal("4th email to same recipient should be rate limited")
	}

	// Different recipient should be allowed
	ctx2 := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "sender@example.com",
		To:         []string{"other@example.com"},
		Stage:      StageRcpt,
	}
	if err := rl.CheckRateLimit(ctx2); err != nil {
		t.Fatalf("Different recipient should be allowed, got error: %v", err)
	}
}

// TestRateLimiter_CompositeKeys tests composite key rate limiting (FROM+TO)
func TestRateLimiter_CompositeKeys(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:               true,
		GossipEnabled:         false,
		GossipIntervalSeconds: 5,
		Dimensions: []config.RateLimitDimension{
			{
				Name:          "per_sender_recipient_pair",
				Keys:          []string{"FROM", "TO"},
				Limit:         2,
				WindowSeconds: 60,
			},
		},
	}

	rl := NewRateLimiter(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer rl.Shutdown()

	ctx := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "stalker@example.com",
		To:         []string{"victim@example.com"},
		Stage:      StageRcpt,
	}

	// First 2 emails from same sender to same recipient
	for i := 0; i < 2; i++ {
		if err := rl.CheckRateLimit(ctx); err != nil {
			t.Fatalf("Email %d should be allowed, got error: %v", i+1, err)
		}
	}

	// 3rd email should be blocked
	if err := rl.CheckRateLimit(ctx); err == nil {
		t.Fatal("3rd email from same sender to same recipient should be rate limited")
	}

	// Same sender to different recipient should be allowed
	ctx2 := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "stalker@example.com",
		To:         []string{"other@example.com"},
		Stage:      StageRcpt,
	}
	if err := rl.CheckRateLimit(ctx2); err != nil {
		t.Fatalf("Same sender to different recipient should be allowed, got error: %v", err)
	}

	// Different sender to same victim should be allowed
	ctx3 := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "different@example.com",
		To:         []string{"victim@example.com"},
		Stage:      StageRcpt,
	}
	if err := rl.CheckRateLimit(ctx3); err != nil {
		t.Fatalf("Different sender to same recipient should be allowed, got error: %v", err)
	}
}

// TestRateLimiter_MultipleDimensions tests multiple dimensions enforced simultaneously
func TestRateLimiter_MultipleDimensions(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:               true,
		GossipEnabled:         false,
		GossipIntervalSeconds: 5,
		Dimensions: []config.RateLimitDimension{
			{
				Name:          "per_ip",
				Keys:          []string{"IP"},
				Limit:         10,
				WindowSeconds: 60,
			},
			{
				Name:          "per_sender",
				Keys:          []string{"FROM"},
				Limit:         5,
				WindowSeconds: 60,
			},
		},
	}

	rl := NewRateLimiter(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer rl.Shutdown()

	// First 5 emails - should pass both limits
	for i := 0; i < 5; i++ {
		ctx := SessionContext{
			RemoteAddr: "192.168.1.100:12345",
			From:       "sender@example.com",
			Stage:      StageMail,
		}
		if err := rl.CheckRateLimit(ctx); err != nil {
			t.Fatalf("Email %d should be allowed, got error: %v", i+1, err)
		}
	}

	// 6th email - should be blocked by FROM limit (5), not IP limit (10)
	ctx := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "sender@example.com",
		Stage:      StageMail,
	}
	if err := rl.CheckRateLimit(ctx); err == nil {
		t.Fatal("6th email should be blocked by sender limit")
	}

	// A different sender has its own budget.
	other := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "different@example.com",
		Stage:      StageMail,
	}
	for i := 0; i < 5; i++ {
		if err := rl.CheckRateLimit(other); err != nil {
			t.Fatalf("Email %d from different sender should be allowed, got error: %v", i+1, err)
		}
	}
	if err := rl.CheckRateLimit(other); err == nil {
		t.Fatal("6th email from different@example.com should be blocked by sender limit (5)")
	}

	// The IP dimension is charged per connection, independently of messages:
	// the 11 messages above cost it nothing.
	conn := SessionContext{RemoteAddr: "192.168.1.100:12345"}
	for i := 0; i < 10; i++ {
		if err := rl.CheckRateLimit(conn); err != nil {
			t.Fatalf("Connection %d should be allowed, got error: %v", i+1, err)
		}
	}
	if err := rl.CheckRateLimit(conn); err == nil {
		t.Fatal("11th connection should be blocked by IP limit (10)")
	}
}

// TestRateLimiter_SlidingWindow tests that rate limits respect sliding windows
func TestRateLimiter_SlidingWindow(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:               true,
		GossipEnabled:         false,
		GossipIntervalSeconds: 5,
		Dimensions: []config.RateLimitDimension{
			{
				Name:          "per_ip",
				Keys:          []string{"IP"},
				Limit:         2,
				WindowSeconds: 1, // Very short window for testing (1 second)
			},
		},
	}

	rl := NewRateLimiter(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer rl.Shutdown()

	ctx := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
	}

	// Use up the limit
	for i := 0; i < 2; i++ {
		if err := rl.CheckRateLimit(ctx); err != nil {
			t.Fatalf("Email %d should be allowed, got error: %v", i+1, err)
		}
	}

	// Should be blocked
	if err := rl.CheckRateLimit(ctx); err == nil {
		t.Fatal("3rd email should be rate limited")
	}

	// Wait for window to expire
	time.Sleep(1100 * time.Millisecond) // Slightly more than 1 second

	// Should be allowed again
	if err := rl.CheckRateLimit(ctx); err != nil {
		t.Fatalf("After window expiry, email should be allowed, got error: %v", err)
	}
}

// TestRateLimiter_GetStats tests the stats endpoint
func TestRateLimiter_GetStats(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:               true,
		GossipEnabled:         false,
		GossipIntervalSeconds: 5,
		Dimensions: []config.RateLimitDimension{
			{
				Name:          "per_ip",
				Keys:          []string{"IP"},
				Limit:         10,
				WindowSeconds: 60,
			},
			{
				Name:          "per_sender",
				Keys:          []string{"FROM"},
				Limit:         5,
				WindowSeconds: 60,
			},
		},
	}

	rl := NewRateLimiter(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer rl.Shutdown()

	stats := rl.GetStats()

	if enabled, ok := stats["enabled"].(bool); !ok || !enabled {
		t.Errorf("Expected enabled=true, got %v", stats["enabled"])
	}

	if dimCount, ok := stats["dimension_count"].(int); !ok || dimCount != 2 {
		t.Errorf("Expected 2 dimensions, got %v", stats["dimension_count"])
	}

	dimensions, ok := stats["dimensions"].([]map[string]any)
	if !ok {
		t.Fatal("Expected dimensions to be array of maps")
	}

	if len(dimensions) != 2 {
		t.Fatalf("Expected 2 dimension configs, got %d", len(dimensions))
	}

	// Check first dimension
	if dimensions[0]["name"] != "per_ip" {
		t.Errorf("Expected first dimension name 'per_ip', got %v", dimensions[0]["name"])
	}
}

// TestRateLimiter_WhitelistedDomain tests that whitelisted domains bypass rate limits
func TestRateLimiter_WhitelistedDomain(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:               true,
		GossipEnabled:         false,
		GossipIntervalSeconds: 5,
		WhitelistedDomains:    []string{"trusted.com", "example.org"},
		Dimensions: []config.RateLimitDimension{
			{
				Name:          "per_sender",
				Keys:          []string{"FROM"},
				Limit:         2,
				WindowSeconds: 60,
			},
		},
	}

	rl := NewRateLimiter(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer rl.Shutdown()

	// Non-whitelisted sender should be rate limited after 2 emails
	ctx := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "user@nonwhitelisted.com",
		Stage:      StageMail,
	}
	for i := 0; i < 2; i++ {
		if err := rl.CheckRateLimit(ctx); err != nil {
			t.Fatalf("Email %d should be allowed, got error: %v", i+1, err)
		}
	}
	if err := rl.CheckRateLimit(ctx); err == nil {
		t.Fatal("3rd email from non-whitelisted domain should be rate limited")
	}

	// Whitelisted domain should bypass rate limit entirely
	ctxWhitelisted := SessionContext{
		RemoteAddr: "192.168.1.200:12345",
		From:       "admin@trusted.com",
		Stage:      StageMail,
	}
	for i := 0; i < 100; i++ {
		if err := rl.CheckRateLimit(ctxWhitelisted); err != nil {
			t.Fatalf("Whitelisted domain should bypass rate limit at email %d, got error: %v", i+1, err)
		}
	}

	// Second whitelisted domain should also bypass
	ctxWhitelisted2 := SessionContext{
		RemoteAddr: "192.168.1.200:12345",
		From:       "user@example.org",
		Stage:      StageMail,
	}
	for i := 0; i < 100; i++ {
		if err := rl.CheckRateLimit(ctxWhitelisted2); err != nil {
			t.Fatalf("Second whitelisted domain should bypass rate limit at email %d, got error: %v", i+1, err)
		}
	}
}

// TestRateLimiter_WhitelistedSender tests that whitelisted senders bypass rate limits
func TestRateLimiter_WhitelistedSender(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:               true,
		GossipEnabled:         false,
		GossipIntervalSeconds: 5,
		WhitelistedSenders:    []string{"admin@example.com", "noreply@service.com"},
		Dimensions: []config.RateLimitDimension{
			{
				Name:          "per_sender",
				Keys:          []string{"FROM"},
				Limit:         2,
				WindowSeconds: 60,
			},
		},
	}

	rl := NewRateLimiter(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer rl.Shutdown()

	// Non-whitelisted sender from same domain should be rate limited
	ctx := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "user@example.com",
		Stage:      StageMail,
	}
	for i := 0; i < 2; i++ {
		if err := rl.CheckRateLimit(ctx); err != nil {
			t.Fatalf("Email %d should be allowed, got error: %v", i+1, err)
		}
	}
	if err := rl.CheckRateLimit(ctx); err == nil {
		t.Fatal("3rd email from non-whitelisted sender should be rate limited")
	}

	// Whitelisted sender should bypass rate limit
	ctxWhitelisted := SessionContext{
		RemoteAddr: "192.168.1.200:12345",
		From:       "admin@example.com",
		Stage:      StageMail,
	}
	for i := 0; i < 100; i++ {
		if err := rl.CheckRateLimit(ctxWhitelisted); err != nil {
			t.Fatalf("Whitelisted sender should bypass rate limit at email %d, got error: %v", i+1, err)
		}
	}

	// Second whitelisted sender
	ctxWhitelisted2 := SessionContext{
		RemoteAddr: "192.168.1.200:12345",
		From:       "noreply@service.com",
		Stage:      StageMail,
	}
	for i := 0; i < 100; i++ {
		if err := rl.CheckRateLimit(ctxWhitelisted2); err != nil {
			t.Fatalf("Second whitelisted sender should bypass rate limit at email %d, got error: %v", i+1, err)
		}
	}
}

// TestRateLimiter_WhitelistCaseInsensitive tests that whitelist matching is case-insensitive
func TestRateLimiter_WhitelistCaseInsensitive(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:               true,
		GossipEnabled:         false,
		GossipIntervalSeconds: 5,
		WhitelistedDomains:    []string{"TrustedDomain.com"},
		WhitelistedSenders:    []string{"Admin@Example.COM"},
		Dimensions: []config.RateLimitDimension{
			{
				Name:          "per_sender",
				Keys:          []string{"FROM"},
				Limit:         2,
				WindowSeconds: 60,
			},
		},
	}

	rl := NewRateLimiter(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer rl.Shutdown()

	// Lowercase domain should match
	ctx1 := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "user@trusteddomain.com",
		Stage:      StageMail,
	}
	for i := 0; i < 10; i++ {
		if err := rl.CheckRateLimit(ctx1); err != nil {
			t.Fatalf("Lowercase domain should be whitelisted, got error at email %d: %v", i+1, err)
		}
	}

	// Uppercase domain should match
	ctx2 := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "USER@TRUSTEDDOMAIN.COM",
		Stage:      StageMail,
	}
	for i := 0; i < 10; i++ {
		if err := rl.CheckRateLimit(ctx2); err != nil {
			t.Fatalf("Uppercase domain should be whitelisted, got error at email %d: %v", i+1, err)
		}
	}

	// Mixed case sender should match
	ctx3 := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "aDmIn@eXaMpLe.CoM",
		Stage:      StageMail,
	}
	for i := 0; i < 10; i++ {
		if err := rl.CheckRateLimit(ctx3); err != nil {
			t.Fatalf("Mixed case sender should be whitelisted, got error at email %d: %v", i+1, err)
		}
	}
}

// TestRateLimiter_WhitelistWithMultipleDimensions tests whitelist with IP and FROM dimensions
func TestRateLimiter_WhitelistWithMultipleDimensions(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:               true,
		GossipEnabled:         false,
		GossipIntervalSeconds: 5,
		WhitelistedDomains:    []string{"trusted.com"},
		Dimensions: []config.RateLimitDimension{
			{
				Name:          "per_ip",
				Keys:          []string{"IP"},
				Limit:         3,
				WindowSeconds: 60,
			},
			{
				Name:          "per_sender",
				Keys:          []string{"FROM"},
				Limit:         2,
				WindowSeconds: 60,
			},
		},
	}

	rl := NewRateLimiter(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer rl.Shutdown()

	// A whitelisted sender on an authenticated session (MAIL FROM verified
	// against allowed_from) bypasses both IP and FROM rate limits. The
	// unauthenticated case, where only sender-keyed dimensions are lifted, is
	// covered by TestAudit_ForgedWhitelistedSenderDoesNotBypassIPLimit.
	ctx := SessionContext{
		RemoteAddr:        "192.168.1.100:12345",
		From:              "admin@trusted.com",
		AuthenticatedUser: "admin@trusted.com",
		Stage:             StageMail,
	}
	for i := 0; i < 100; i++ {
		if err := rl.CheckRateLimit(ctx); err != nil {
			t.Fatalf("Whitelisted sender should bypass all rate limits at email %d, got error: %v", i+1, err)
		}
	}

	// Non-whitelisted sender from same IP should still be subject to limits
	ctxNonWhitelisted := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "user@other.com",
		Stage:      StageMail,
	}
	for i := 0; i < 2; i++ {
		if err := rl.CheckRateLimit(ctxNonWhitelisted); err != nil {
			t.Fatalf("Non-whitelisted sender email %d should be allowed, got error: %v", i+1, err)
		}
	}
	// Should be blocked by FROM limit (2)
	if err := rl.CheckRateLimit(ctxNonWhitelisted); err == nil {
		t.Fatal("Non-whitelisted sender should be blocked by FROM limit")
	}
}

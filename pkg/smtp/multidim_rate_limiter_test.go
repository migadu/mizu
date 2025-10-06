package smtp

import (
	"testing"
	"time"

	"go.uber.org/zap"
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

	rl := NewRateLimiter(cfg, nil, zap.NewNop())
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

	rl := NewRateLimiter(cfg, nil, zap.NewNop())
	defer rl.Shutdown()

	// Same sender from different IPs
	for i := 0; i < 5; i++ {
		ctx := SessionContext{
			RemoteAddr: "192.168.1.100:12345",
			From:       "spammer@example.com",
		}
		if err := rl.CheckRateLimit(ctx); err != nil {
			t.Fatalf("Email %d should be allowed, got error: %v", i+1, err)
		}
	}

	// 6th email from same sender should be blocked
	ctx := SessionContext{
		RemoteAddr: "192.168.1.200:12345", // Different IP
		From:       "spammer@example.com",
	}
	if err := rl.CheckRateLimit(ctx); err == nil {
		t.Fatal("6th email from same sender should be rate limited")
	}

	// Different sender should be allowed
	ctx2 := SessionContext{
		RemoteAddr: "192.168.1.200:12345",
		From:       "legitimate@example.com",
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

	rl := NewRateLimiter(cfg, nil, zap.NewNop())
	defer rl.Shutdown()

	// Different senders from same domain
	for i := 0; i < 10; i++ {
		ctx := SessionContext{
			RemoteAddr: "192.168.1.100:12345",
			From:       "user" + string(rune('a'+i)) + "@spam-domain.com",
		}
		if err := rl.CheckRateLimit(ctx); err != nil {
			t.Fatalf("Email %d should be allowed, got error: %v", i+1, err)
		}
	}

	// 11th email from same domain should be blocked
	ctx := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "another@spam-domain.com",
	}
	if err := rl.CheckRateLimit(ctx); err == nil {
		t.Fatal("11th email from same domain should be rate limited")
	}

	// Different domain should be allowed
	ctx2 := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "user@different-domain.com",
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

	rl := NewRateLimiter(cfg, nil, zap.NewNop())
	defer rl.Shutdown()

	// Different senders to same recipient
	for i := 0; i < 3; i++ {
		ctx := SessionContext{
			RemoteAddr: "192.168.1.100:12345",
			From:       "sender" + string(rune('a'+i)) + "@example.com",
			To:         []string{"victim@example.com"},
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
	}
	if err := rl.CheckRateLimit(ctx); err == nil {
		t.Fatal("4th email to same recipient should be rate limited")
	}

	// Different recipient should be allowed
	ctx2 := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "sender@example.com",
		To:         []string{"other@example.com"},
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

	rl := NewRateLimiter(cfg, nil, zap.NewNop())
	defer rl.Shutdown()

	ctx := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "stalker@example.com",
		To:         []string{"victim@example.com"},
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
	}
	if err := rl.CheckRateLimit(ctx2); err != nil {
		t.Fatalf("Same sender to different recipient should be allowed, got error: %v", err)
	}

	// Different sender to same victim should be allowed
	ctx3 := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "different@example.com",
		To:         []string{"victim@example.com"},
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

	rl := NewRateLimiter(cfg, nil, zap.NewNop())
	defer rl.Shutdown()

	// First 5 emails - should pass both limits
	for i := 0; i < 5; i++ {
		ctx := SessionContext{
			RemoteAddr: "192.168.1.100:12345",
			From:       "sender@example.com",
		}
		if err := rl.CheckRateLimit(ctx); err != nil {
			t.Fatalf("Email %d should be allowed, got error: %v", i+1, err)
		}
	}

	// 6th email - should be blocked by FROM limit (5), not IP limit (10)
	ctx := SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "sender@example.com",
	}
	if err := rl.CheckRateLimit(ctx); err == nil {
		t.Fatal("6th email should be blocked by sender limit")
	}

	// Different sender, same IP - should be allowed up to IP limit
	// We already have 5 emails, limit is 10, so 4 more are allowed (total 9)
	for i := 0; i < 4; i++ {
		ctx := SessionContext{
			RemoteAddr: "192.168.1.100:12345",
			From:       "different@example.com",
		}
		if err := rl.CheckRateLimit(ctx); err != nil {
			t.Fatalf("Email %d from different sender should be allowed, got error: %v", i+6, err)
		}
	}

	// 10th email should be blocked by IP limit (5 from first sender + 4 from second = 9, limit is 10 but check is >=)
	ctx = SessionContext{
		RemoteAddr: "192.168.1.100:12345",
		From:       "different@example.com",
	}
	if err := rl.CheckRateLimit(ctx); err == nil {
		t.Fatal("10th email from different@example.com should be blocked by sender limit (5)")
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

	rl := NewRateLimiter(cfg, nil, zap.NewNop())
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

	rl := NewRateLimiter(cfg, nil, zap.NewNop())
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

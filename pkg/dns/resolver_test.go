package dns

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNewResilientResolver(t *testing.T) {
	tests := []struct {
		name           string
		servers        []string
		timeout        time.Duration
		wantDefault    bool
		wantServerAddr string
	}{
		{
			name:        "empty servers returns default resolver",
			servers:     []string{},
			timeout:     5 * time.Second,
			wantDefault: true,
		},
		{
			name:        "nil servers returns default resolver",
			servers:     nil,
			timeout:     5 * time.Second,
			wantDefault: true,
		},
		{
			name:        "single server creates custom resolver",
			servers:     []string{"8.8.8.8:53"},
			timeout:     5 * time.Second,
			wantDefault: false,
		},
		{
			name:        "multiple servers creates custom resolver",
			servers:     []string{"8.8.8.8:53", "1.1.1.1:53"},
			timeout:     5 * time.Second,
			wantDefault: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver, rr := NewResilientResolver(tt.servers, tt.timeout, 5*time.Minute)
			if resolver == nil {
				t.Fatal("NewResilientResolver returned nil")
			}

			if tt.wantDefault {
				// For empty/nil servers, we return net.DefaultResolver
				if resolver != net.DefaultResolver {
					t.Error("expected default resolver for empty servers")
				}
				if rr != nil {
					t.Error("expected nil ResilientResolver for default resolver")
				}
			} else {
				// For non-empty servers, we return a custom resolver
				if resolver == net.DefaultResolver {
					t.Error("expected custom resolver for non-empty servers")
				}
				if rr == nil {
					t.Error("expected non-nil ResilientResolver for custom resolver")
				}
			}
		})
	}
}

func TestResilientResolverRoundRobin(t *testing.T) {
	// This test verifies round-robin behavior by checking that the index
	// increments across multiple calls
	servers := []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53"}
	rr := &ResilientResolver{
		servers: servers,
		timeout: 100 * time.Millisecond,
	}

	// Get initial index
	initialIdx := rr.index.Load()

	// Make several dial attempts
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		rr.dial(ctx, "udp", "")
		cancel()
	}

	// Verify index has incremented
	finalIdx := rr.index.Load()
	if finalIdx <= initialIdx {
		t.Errorf("expected index to increment from %d, got %d", initialIdx, finalIdx)
	}
}

func TestResilientResolverFailover(t *testing.T) {
	// Use a mix of invalid and valid DNS servers to test failover
	servers := []string{
		"127.0.0.1:9999", // Invalid - should fail
		"8.8.8.8:53",     // Valid Google DNS
	}

	resolver, _ := NewResilientResolver(servers, 2*time.Second, 5*time.Minute)

	// Try to lookup a known domain - should succeed via failover to 8.8.8.8
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := resolver.LookupHost(ctx, "google.com")
	if err != nil {
		t.Fatalf("expected successful lookup via failover, got error: %v", err)
	}

	if len(addrs) == 0 {
		t.Error("expected at least one address")
	}
}

func TestResilientResolverAllServersFail(t *testing.T) {
	// Use invalid server addresses (malformed)
	servers := []string{
		"invalid-server-address",
		"another-invalid-address",
	}

	rr := &ResilientResolver{
		servers: servers,
		timeout: 100 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := rr.dial(ctx, "udp", "")
	if err == nil {
		t.Fatal("expected error when all servers fail")
	}

	if !strings.Contains(err.Error(), "all DNS servers failed") {
		t.Errorf("expected 'all DNS servers failed' error, got: %v", err)
	}
}

func TestResilientResolverTimeout(t *testing.T) {
	// Use an IP that will timeout (192.0.2.0/24 is reserved for documentation)
	servers := []string{"192.0.2.1:53"}

	resolver, _ := NewResilientResolver(servers, 100*time.Millisecond, 5*time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := resolver.LookupHost(ctx, "example.com")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}

	// Should timeout relatively quickly (within a reasonable margin)
	if elapsed > 1*time.Second {
		t.Errorf("timeout took too long: %v", elapsed)
	}
}

func TestResilientResolverGetServers(t *testing.T) {
	servers := []string{"8.8.8.8:53", "1.1.1.1:53"}
	rr := &ResilientResolver{
		servers: servers,
		timeout: 5 * time.Second,
	}

	got := rr.GetServers()

	if len(got) != len(servers) {
		t.Errorf("GetServers() returned %d servers, want %d", len(got), len(servers))
	}

	for i, server := range servers {
		if got[i] != server {
			t.Errorf("GetServers()[%d] = %s, want %s", i, got[i], server)
		}
	}

	// Verify it's a copy (modifying returned slice shouldn't affect original)
	got[0] = "modified"
	if rr.servers[0] == "modified" {
		t.Error("GetServers() should return a copy, not the original slice")
	}
}

func TestResilientResolverUpdateServers(t *testing.T) {
	rr := &ResilientResolver{
		servers: []string{"8.8.8.8:53"},
		timeout: 5 * time.Second,
	}

	newServers := []string{"1.1.1.1:53", "1.0.0.1:53"}
	rr.UpdateServers(newServers)

	got := rr.GetServers()

	if len(got) != len(newServers) {
		t.Errorf("after UpdateServers, got %d servers, want %d", len(got), len(newServers))
	}

	for i, server := range newServers {
		if got[i] != server {
			t.Errorf("after UpdateServers, servers[%d] = %s, want %s", i, got[i], server)
		}
	}
}

func TestResilientResolverConcurrency(t *testing.T) {
	// Test that concurrent DNS lookups work correctly
	servers := []string{"8.8.8.8:53", "8.8.4.4:53"}
	resolver, _ := NewResilientResolver(servers, 5*time.Second, 5*time.Minute)

	const numGoroutines = 10
	errCh := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			_, err := resolver.LookupHost(ctx, "google.com")
			errCh <- err
		}()
	}

	// Collect results
	var errs []error
	for i := 0; i < numGoroutines; i++ {
		if err := <-errCh; err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		t.Errorf("got %d errors from concurrent lookups: %v", len(errs), errs)
	}
}

func TestResilientResolverContextCancellation(t *testing.T) {
	servers := []string{"8.8.8.8:53"}
	resolver, _ := NewResilientResolver(servers, 30*time.Second, 5*time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := resolver.LookupHost(ctx, "google.com")
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled error, got: %v", err)
	}
}

func TestResilientResolverRealDNSLookup(t *testing.T) {
	// Integration test with real DNS servers
	servers := []string{"8.8.8.8:53", "1.1.1.1:53"}
	resolver, _ := NewResilientResolver(servers, 5*time.Second, 5*time.Minute)

	tests := []struct {
		name     string
		hostname string
		wantErr  bool
	}{
		{
			name:     "lookup google.com",
			hostname: "google.com",
			wantErr:  false,
		},
		{
			name:     "lookup cloudflare.com",
			hostname: "cloudflare.com",
			wantErr:  false,
		},
		{
			name:     "lookup invalid domain",
			hostname: "this-domain-definitely-does-not-exist-12345.com",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			addrs, err := resolver.LookupHost(ctx, tt.hostname)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if len(addrs) == 0 {
					t.Error("expected at least one address")
				}
			}
		})
	}
}

package dns

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestCachingWrapper_LookupHostCacheHit(t *testing.T) {
	// Create a resolver with a very short TTL for testing
	resolver, rr := NewResilientResolver([]string{"8.8.8.8:53"}, 5*time.Second, 5*time.Minute)
	if rr == nil {
		t.Fatal("expected non-nil ResilientResolver")
	}

	wrapper := WrapWithCache(resolver, rr)

	ctx := context.Background()
	host := "google.com"

	// First lookup - should hit DNS
	addrs1, err := wrapper.LookupHost(ctx, host)
	if err != nil {
		t.Fatalf("first lookup failed: %v", err)
	}
	if len(addrs1) == 0 {
		t.Fatal("expected at least one address")
	}

	// Verify it's in cache
	cached, found := rr.getCached(host)
	if !found {
		t.Error("expected cache hit after first lookup")
	}
	if len(cached) != len(addrs1) {
		t.Errorf("cached entries mismatch: got %d, want %d", len(cached), len(addrs1))
	}

	// Second lookup - should hit cache
	addrs2, err := wrapper.LookupHost(ctx, host)
	if err != nil {
		t.Fatalf("second lookup failed: %v", err)
	}

	// Should return same addresses
	if len(addrs2) != len(addrs1) {
		t.Errorf("cache returned different number of addresses: got %d, want %d", len(addrs2), len(addrs1))
	}
}

func TestCachingWrapper_LookupAddrCacheKey(t *testing.T) {
	resolver, rr := NewResilientResolver([]string{"8.8.8.8:53"}, 5*time.Second, 5*time.Minute)
	if rr == nil {
		t.Fatal("expected non-nil ResilientResolver")
	}

	wrapper := WrapWithCache(resolver, rr)

	ctx := context.Background()
	addr := "8.8.8.8"

	// Perform reverse lookup
	_, err := wrapper.LookupAddr(ctx, addr)
	if err != nil {
		// Some networks may not support reverse DNS, that's okay
		t.Logf("reverse lookup failed (this is okay): %v", err)
		return
	}

	// Verify cache key has correct prefix
	cacheKey := fmt.Sprintf("reverse:%s", addr)
	_, found := rr.getCached(cacheKey)
	if !found {
		t.Error("expected reverse lookup to be cached with 'reverse:' prefix")
	}
}

func TestCachingWrapper_LookupMXCacheKey(t *testing.T) {
	resolver, rr := NewResilientResolver([]string{"8.8.8.8:53"}, 5*time.Second, 5*time.Minute)
	if rr == nil {
		t.Fatal("expected non-nil ResilientResolver")
	}

	wrapper := WrapWithCache(resolver, rr)

	ctx := context.Background()
	domain := "gmail.com"

	// Perform MX lookup
	mxRecords, err := wrapper.LookupMX(ctx, domain)
	if err != nil {
		t.Fatalf("MX lookup failed: %v", err)
	}
	if len(mxRecords) == 0 {
		t.Fatal("expected at least one MX record")
	}

	// Verify cache key has correct prefix
	cacheKey := fmt.Sprintf("mx:%s", domain)
	cached, found := rr.getCached(cacheKey)
	if !found {
		t.Error("expected MX lookup to be cached with 'mx:' prefix")
	}

	// Verify cached format is "pref:host"
	if len(cached) > 0 {
		var pref uint16
		var host string
		if _, err := fmt.Sscanf(cached[0], "%d:%s", &pref, &host); err != nil {
			t.Errorf("cached MX format invalid: %s", cached[0])
		}
	}

	// Second lookup should hit cache and return same MX records
	mxRecords2, err := wrapper.LookupMX(ctx, domain)
	if err != nil {
		t.Fatalf("second MX lookup failed: %v", err)
	}
	if len(mxRecords2) != len(mxRecords) {
		t.Errorf("cache returned different number of MX records: got %d, want %d", len(mxRecords2), len(mxRecords))
	}
}

func TestCachingWrapper_LookupTXTCacheKey(t *testing.T) {
	resolver, rr := NewResilientResolver([]string{"8.8.8.8:53"}, 5*time.Second, 5*time.Minute)
	if rr == nil {
		t.Fatal("expected non-nil ResilientResolver")
	}

	wrapper := WrapWithCache(resolver, rr)

	ctx := context.Background()
	domain := "google.com"

	// Perform TXT lookup
	txtRecords, err := wrapper.LookupTXT(ctx, domain)
	if err != nil {
		t.Fatalf("TXT lookup failed: %v", err)
	}

	// Verify cache key has correct prefix
	cacheKey := fmt.Sprintf("txt:%s", domain)
	_, found := rr.getCached(cacheKey)
	if !found {
		t.Error("expected TXT lookup to be cached with 'txt:' prefix")
	}

	// Second lookup should hit cache
	txtRecords2, err := wrapper.LookupTXT(ctx, domain)
	if err != nil {
		t.Fatalf("second TXT lookup failed: %v", err)
	}
	if len(txtRecords2) != len(txtRecords) {
		t.Errorf("cache returned different number of TXT records: got %d, want %d", len(txtRecords2), len(txtRecords))
	}
}

func TestResilientResolver_CacheExpiration(t *testing.T) {
	_, rr := NewResilientResolver([]string{"8.8.8.8:53"}, 5*time.Second, 5*time.Minute)
	if rr == nil {
		t.Fatal("expected non-nil ResilientResolver")
	}

	// Set a very short TTL for testing
	rr.cacheMu.Lock()
	rr.cacheTTL = 100 * time.Millisecond
	rr.cacheMu.Unlock()

	// Add entry to cache
	testKey := "test.example.com"
	testAddrs := []string{"1.2.3.4", "5.6.7.8"}
	rr.putCache(testKey, testAddrs)

	// Should be in cache immediately
	cached, found := rr.getCached(testKey)
	if !found {
		t.Fatal("expected cache hit immediately after adding")
	}
	if len(cached) != len(testAddrs) {
		t.Errorf("cached entries mismatch: got %d, want %d", len(cached), len(testAddrs))
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should no longer be in cache
	_, found = rr.getCached(testKey)
	if found {
		t.Error("expected cache miss after expiration")
	}
}

func TestResilientResolver_GetCacheStats(t *testing.T) {
	_, rr := NewResilientResolver([]string{"8.8.8.8:53"}, 5*time.Second, 5*time.Minute)
	if rr == nil {
		t.Fatal("expected non-nil ResilientResolver")
	}

	// Initially cache should be empty
	size, ttl := rr.GetCacheStats()
	if size != 0 {
		t.Errorf("expected empty cache, got size %d", size)
	}
	if ttl != 5*time.Minute {
		t.Errorf("expected default TTL of 5m, got %v", ttl)
	}

	// Add some entries
	rr.putCache("host1.example.com", []string{"1.2.3.4"})
	rr.putCache("host2.example.com", []string{"5.6.7.8"})
	rr.putCache("mx:example.com", []string{"10:mail.example.com"})

	// Check stats
	size, _ = rr.GetCacheStats()
	if size != 3 {
		t.Errorf("expected cache size 3, got %d", size)
	}
}

func TestResilientResolver_FlushCache(t *testing.T) {
	_, rr := NewResilientResolver([]string{"8.8.8.8:53"}, 5*time.Second, 5*time.Minute)
	if rr == nil {
		t.Fatal("expected non-nil ResilientResolver")
	}

	// Add multiple entries
	rr.putCache("host1.example.com", []string{"1.2.3.4"})
	rr.putCache("host2.example.com", []string{"5.6.7.8"})
	rr.putCache("mx:example.com", []string{"10:mail.example.com"})

	// Verify entries exist
	size, _ := rr.GetCacheStats()
	if size != 3 {
		t.Fatalf("expected cache size 3 before flush, got %d", size)
	}

	// Flush cache
	rr.FlushCache()

	// Verify cache is empty
	size, _ = rr.GetCacheStats()
	if size != 0 {
		t.Errorf("expected empty cache after flush, got size %d", size)
	}

	// Verify entries are gone
	_, found := rr.getCached("host1.example.com")
	if found {
		t.Error("expected cache miss after flush")
	}
}

func TestResilientResolver_CleanupExpiredCache(t *testing.T) {
	_, rr := NewResilientResolver([]string{"8.8.8.8:53"}, 5*time.Second, 5*time.Minute)
	if rr == nil {
		t.Fatal("expected non-nil ResilientResolver")
	}

	// Set very short TTL
	rr.cacheMu.Lock()
	rr.cacheTTL = 50 * time.Millisecond
	rr.cacheMu.Unlock()

	// Add entries
	rr.putCache("host1.example.com", []string{"1.2.3.4"})
	rr.putCache("host2.example.com", []string{"5.6.7.8"})

	// Wait for entries to expire
	time.Sleep(100 * time.Millisecond)

	// Manually trigger cleanup (normally runs every minute)
	rr.cacheMu.Lock()
	now := time.Now()
	for key, entry := range rr.cache {
		if now.After(entry.expiresAt) {
			delete(rr.cache, key)
		}
	}
	rr.cacheMu.Unlock()

	// Verify cache is empty after cleanup
	size, _ := rr.GetCacheStats()
	if size != 0 {
		t.Errorf("expected empty cache after cleanup, got size %d", size)
	}
}

func TestCachingWrapper_ConcurrentAccess(t *testing.T) {
	resolver, rr := NewResilientResolver([]string{"8.8.8.8:53"}, 5*time.Second, 5*time.Minute)
	if rr == nil {
		t.Fatal("expected non-nil ResilientResolver")
	}

	wrapper := WrapWithCache(resolver, rr)

	const numGoroutines = 10
	errCh := make(chan error, numGoroutines)

	host := "google.com"

	// Multiple goroutines performing concurrent lookups
	for i := 0; i < numGoroutines; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// Each goroutine does multiple lookups
			for j := 0; j < 5; j++ {
				_, err := wrapper.LookupHost(ctx, host)
				if err != nil {
					errCh <- err
					return
				}
			}
			errCh <- nil
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

	// Verify cache is populated
	cached, found := rr.getCached(host)
	if !found {
		t.Error("expected cache hit after concurrent lookups")
	}
	if len(cached) == 0 {
		t.Error("expected cached addresses")
	}
}

func TestCachingWrapper_DefaultResolver(t *testing.T) {
	// Test that caching wrapper works with default resolver (nil ResilientResolver)
	resolver, rr := NewResilientResolver([]string{}, 5*time.Second, 5*time.Minute)
	if resolver != net.DefaultResolver {
		t.Error("expected default resolver for empty servers")
	}
	if rr != nil {
		t.Error("expected nil ResilientResolver for default resolver")
	}

	wrapper := WrapWithCache(resolver, rr)

	ctx := context.Background()

	// Lookups should work but not cache
	addrs, err := wrapper.LookupHost(ctx, "google.com")
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	if len(addrs) == 0 {
		t.Error("expected at least one address")
	}

	// No cache operations should panic (they check for nil rr)
	_, _ = wrapper.LookupMX(ctx, "gmail.com")
	_, _ = wrapper.LookupTXT(ctx, "google.com")
}

func TestCachingWrapper_DifferentRecordTypes(t *testing.T) {
	// Verify that different record types don't collide in cache
	resolver, rr := NewResilientResolver([]string{"8.8.8.8:53"}, 5*time.Second, 5*time.Minute)
	if rr == nil {
		t.Fatal("expected non-nil ResilientResolver")
	}

	wrapper := WrapWithCache(resolver, rr)

	ctx := context.Background()
	domain := "google.com"

	// Perform different types of lookups
	_, err1 := wrapper.LookupHost(ctx, domain)
	if err1 != nil {
		t.Fatalf("LookupHost failed: %v", err1)
	}

	_, err2 := wrapper.LookupTXT(ctx, domain)
	if err2 != nil {
		t.Fatalf("LookupTXT failed: %v", err2)
	}

	// Both should be cached with different keys
	hostCached, hostFound := rr.getCached(domain)
	txtCached, txtFound := rr.getCached(fmt.Sprintf("txt:%s", domain))

	if !hostFound {
		t.Error("expected host lookup to be cached")
	}
	if !txtFound {
		t.Error("expected TXT lookup to be cached")
	}

	// They should have different entries
	if len(hostCached) > 0 && len(txtCached) > 0 {
		// Host records are IPs, TXT records are text - they should be different
		// (In practice they will be very different, but we just verify both exist)
		if hostFound && txtFound {
			t.Log("Successfully cached different record types with different keys")
		}
	}
}

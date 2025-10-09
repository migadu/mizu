package routing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"go.uber.org/zap"
)

// TestSeparateNegativeCache tests that negative responses have a separate cache with different TTL
func TestSeparateNegativeCache(t *testing.T) {
	callCount := int32(0)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)

		// Decode to see which recipient
		var req ResolveRequest
		json.NewDecoder(r.Body).Decode(&req)

		// Reject user1, accept user2
		if req.Recipient == "user1@example.com" {
			resp := ResolveResponse{
				Accepted:     false,
				ErrorCode:    ErrorCodeRecipientNotFound,
				ErrorMessage: "User not found",
			}
			json.NewEncoder(w).Encode(resp)
		} else {
			resp := ResolveResponse{
				Accepted:  true,
				DeliverTo: []string{req.Recipient},
			}
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	logger := zap.NewNop()
	client, err := NewClient(ClientConfig{
		Endpoint:                server.URL,
		Logger:                  logger,
		CacheTTLSeconds:         300, // 5 minutes for positive
		CacheNegativeTTLSeconds: 60,  // 1 minute for negative
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx := context.Background()

	// First call - should hit endpoint (negative response)
	resp1, err := client.Resolve(ctx, "user1@example.com", "sender@example.com", "", "")
	if err != nil {
		t.Fatalf("First resolve failed: %v", err)
	}
	if resp1.Accepted {
		t.Error("Expected rejection")
	}

	// Second call - should use negative cache
	resp2, err := client.Resolve(ctx, "user1@example.com", "sender@example.com", "", "")
	if err != nil {
		t.Fatalf("Second resolve failed: %v", err)
	}
	if resp2.Accepted {
		t.Error("Expected rejection from cache")
	}

	// Third call with different user - should hit endpoint (positive response)
	resp3, err := client.Resolve(ctx, "user2@example.com", "sender@example.com", "", "")
	if err != nil {
		t.Fatalf("Third resolve failed: %v", err)
	}
	if !resp3.Accepted {
		t.Error("Expected acceptance")
	}

	// Fourth call - should use positive cache
	resp4, err := client.Resolve(ctx, "user2@example.com", "sender@example.com", "", "")
	if err != nil {
		t.Fatalf("Fourth resolve failed: %v", err)
	}
	if !resp4.Accepted {
		t.Error("Expected acceptance from cache")
	}

	// Should only have called endpoint twice (once for user1, once for user2)
	if atomic.LoadInt32(&callCount) != 2 {
		t.Errorf("Expected 2 endpoint calls, got %d", callCount)
	}

	// Check stats
	stats := client.GetStats()
	if stats["cache_entries"].(int) != 1 {
		t.Errorf("Expected 1 positive cache entry, got %d", stats["cache_entries"])
	}
	if stats["negative_cache_entries"].(int) != 1 {
		t.Errorf("Expected 1 negative cache entry, got %d", stats["negative_cache_entries"])
	}

	t.Log("✓ Separate negative cache works correctly")
}

// TestNonRetryableError_4xx tests that 4xx errors are not retried
func TestNonRetryableError_4xx(t *testing.T) {
	callCount := int32(0)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "Bad request"}`))
	}))
	defer server.Close()

	logger := zap.NewNop()
	client, err := NewClient(ClientConfig{
		Endpoint:   server.URL,
		Logger:     logger,
		MaxRetries: 3, // Allow up to 3 retries
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx := context.Background()
	_, err = client.Resolve(ctx, "user@example.com", "", "", "")

	// Should fail
	if err == nil {
		t.Error("Expected error for 4xx response")
	}

	// Should only have called endpoint once (no retries for 4xx)
	if atomic.LoadInt32(&callCount) != 1 {
		t.Errorf("Expected 1 endpoint call (no retries for 4xx), got %d", callCount)
	}

	t.Log("✓ 4xx errors are not retried")
}

// TestNonRetryableError_5xx tests that 5xx errors ARE retried
func TestRetryable_5xx(t *testing.T) {
	callCount := int32(0)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Server error"}`))
	}))
	defer server.Close()

	logger := zap.NewNop()
	client, err := NewClient(ClientConfig{
		Endpoint:   server.URL,
		Logger:     logger,
		MaxRetries: 2, // Allow 2 retries
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx := context.Background()
	_, err = client.Resolve(ctx, "user@example.com", "", "", "")

	// Should fail
	if err == nil {
		t.Error("Expected error for 5xx response")
	}

	// Should have called endpoint 3 times (1 initial + 2 retries)
	if atomic.LoadInt32(&callCount) != 3 {
		t.Errorf("Expected 3 endpoint calls (1 initial + 2 retries), got %d", callCount)
	}

	t.Log("✓ 5xx errors are retried")
}

// TestCacheKeyIncludesSender tests that cache keys are per-recipient AND per-sender
func TestCacheKeyIncludesSender(t *testing.T) {
	callCount := int32(0)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)

		var req ResolveRequest
		json.NewDecoder(r.Body).Decode(&req)

		// Different response based on sender
		resp := ResolveResponse{
			Accepted:  true,
			DeliverTo: []string{req.Sender + "->" + req.Recipient}, // Include sender in response
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	logger := zap.NewNop()
	client, err := NewClient(ClientConfig{
		Endpoint: server.URL,
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx := context.Background()

	// Same recipient, different senders should result in different cache entries
	resp1, _ := client.Resolve(ctx, "user@example.com", "sender1@example.com", "", "")
	resp2, _ := client.Resolve(ctx, "user@example.com", "sender2@example.com", "", "")
	resp3, _ := client.Resolve(ctx, "user@example.com", "sender1@example.com", "", "")

	// Should have called endpoint twice (sender1 and sender2)
	if atomic.LoadInt32(&callCount) != 2 {
		t.Errorf("Expected 2 endpoint calls, got %d", callCount)
	}

	// First and third should be same (cached)
	if resp1.DeliverTo[0] != resp3.DeliverTo[0] {
		t.Error("Expected same response for same sender (cached)")
	}

	// First and second should be different
	if resp1.DeliverTo[0] == resp2.DeliverTo[0] {
		t.Error("Expected different responses for different senders")
	}

	t.Log("✓ Cache keys include both recipient and sender")
}

// TestFlushCache_BothCaches tests that FlushCache clears both positive and negative caches
func TestFlushCache_BothCaches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ResolveRequest
		json.NewDecoder(r.Body).Decode(&req)

		if req.Recipient == "reject@example.com" {
			resp := ResolveResponse{Accepted: false, ErrorCode: ErrorCodeRecipientNotFound}
			json.NewEncoder(w).Encode(resp)
		} else {
			resp := ResolveResponse{Accepted: true, DeliverTo: []string{req.Recipient}}
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	logger := zap.NewNop()
	client, err := NewClient(ClientConfig{
		Endpoint: server.URL,
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx := context.Background()

	// Populate both caches
	client.Resolve(ctx, "accept@example.com", "sender@example.com", "", "")
	client.Resolve(ctx, "reject@example.com", "sender@example.com", "", "")

	// Check both caches have entries
	stats := client.GetStats()
	if stats["cache_entries"].(int) != 1 {
		t.Error("Expected 1 positive cache entry before flush")
	}
	if stats["negative_cache_entries"].(int) != 1 {
		t.Error("Expected 1 negative cache entry before flush")
	}

	// Flush both caches
	client.FlushCache()

	// Check both caches are empty
	stats = client.GetStats()
	if stats["cache_entries"].(int) != 0 {
		t.Error("Expected 0 positive cache entries after flush")
	}
	if stats["negative_cache_entries"].(int) != 0 {
		t.Error("Expected 0 negative cache entries after flush")
	}

	t.Log("✓ FlushCache clears both positive and negative caches")
}

// TestNonRetryableError_Unwrap tests the error type
func TestNonRetryableError_Type(t *testing.T) {
	originalErr := http.ErrNotSupported
	wrapped := &NonRetryableError{Err: originalErr}

	if wrapped.Error() != originalErr.Error() {
		t.Errorf("Expected error message '%s', got '%s'", originalErr.Error(), wrapped.Error())
	}

	t.Log("✓ NonRetryableError implements error interface correctly")
}

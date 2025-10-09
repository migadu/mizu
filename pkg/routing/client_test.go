package routing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestNewClient(t *testing.T) {
	logger := zap.NewNop()

	client, err := NewClient(ClientConfig{
		Endpoint: "https://routing.example.com",
		Logger:   logger,
	})

	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	if client == nil {
		t.Fatal("Client is nil")
	}

	t.Log("✓ Client created successfully")
}

func TestNewClient_MissingEndpoint(t *testing.T) {
	logger := zap.NewNop()

	_, err := NewClient(ClientConfig{
		Logger: logger,
	})

	if err == nil {
		t.Error("Expected error for missing endpoint")
	}
}

func TestNewClient_MissingLogger(t *testing.T) {
	_, err := NewClient(ClientConfig{
		Endpoint: "https://routing.example.com",
	})

	if err == nil {
		t.Error("Expected error for missing logger")
	}
}

func TestNewClient_Defaults(t *testing.T) {
	logger := zap.NewNop()

	client, err := NewClient(ClientConfig{
		Endpoint: "https://routing.example.com",
		Logger:   logger,
	})

	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// Check defaults
	if client.maxRetries != 2 {
		t.Errorf("Expected maxRetries=2, got %d", client.maxRetries)
	}
	if client.cacheTTL != 300*time.Second {
		t.Errorf("Expected cacheTTL=300s, got %v", client.cacheTTL)
	}
	if client.fallbackOnError != "tempfail" {
		t.Errorf("Expected fallbackOnError=tempfail, got %s", client.fallbackOnError)
	}
}

func TestResolve_AcceptedRecipient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("Expected Content-Type: application/json")
		}

		// Decode request
		var req ResolveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request: %v", err)
		}

		// Send response
		resp := ResolveResponse{
			Accepted:  true,
			DeliverTo: []string{"user@example.com"},
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
	resp, err := client.Resolve(ctx, "user@example.com", "sender@example.com", "192.168.1.1", "Test")

	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if !resp.Accepted {
		t.Error("Expected recipient to be accepted")
	}
	if len(resp.DeliverTo) != 1 {
		t.Error("Expected 1 delivery recipient")
	}

	t.Log("✓ Accepted recipient resolution works")
}

func TestResolve_RejectedRecipient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ResolveResponse{
			Accepted:     false,
			ErrorCode:    ErrorCodeRecipientNotFound,
			ErrorMessage: "User not found",
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
	resp, err := client.Resolve(ctx, "unknown@example.com", "", "", "")

	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if resp.Accepted {
		t.Error("Expected recipient to be rejected")
	}
	if resp.ErrorCode != ErrorCodeRecipientNotFound {
		t.Error("Expected ErrorCodeRecipientNotFound")
	}

	t.Log("✓ Rejected recipient resolution works")
}

func TestResolve_Caching(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		resp := ResolveResponse{
			Accepted:  true,
			DeliverTo: []string{"user@example.com"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	logger := zap.NewNop()
	client, err := NewClient(ClientConfig{
		Endpoint:        server.URL,
		Logger:          logger,
		CacheTTLSeconds: 60,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx := context.Background()

	// First call - should hit endpoint
	_, err = client.Resolve(ctx, "user@example.com", "sender@example.com", "", "")
	if err != nil {
		t.Fatalf("First resolve failed: %v", err)
	}

	// Second call - should use cache
	_, err = client.Resolve(ctx, "user@example.com", "sender@example.com", "", "")
	if err != nil {
		t.Fatalf("Second resolve failed: %v", err)
	}

	// Should only have called endpoint once
	if callCount != 1 {
		t.Errorf("Expected 1 endpoint call, got %d", callCount)
	}

	t.Log("✓ Caching works correctly")
}

func TestResolve_WithAPIKey(t *testing.T) {
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		resp := ResolveResponse{Accepted: true}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	logger := zap.NewNop()
	client, err := NewClient(ClientConfig{
		Endpoint: server.URL,
		APIKey:   "test-api-key",
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx := context.Background()
	_, err = client.Resolve(ctx, "user@example.com", "", "", "")

	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if receivedAuth != "Bearer test-api-key" {
		t.Errorf("Expected Authorization header 'Bearer test-api-key', got '%s'", receivedAuth)
	}

	t.Log("✓ API key authentication works")
}

func TestFlushCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ResolveResponse{Accepted: true}
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

	// Add something to cache
	ctx := context.Background()
	client.Resolve(ctx, "user@example.com", "", "", "")

	// Check cache has entries
	stats := client.GetStats()
	if stats["cache_entries"].(int) == 0 {
		t.Error("Expected cache to have entries")
	}

	// Flush cache
	client.FlushCache()

	// Check cache is empty
	stats = client.GetStats()
	if stats["cache_entries"].(int) != 0 {
		t.Error("Expected cache to be empty after flush")
	}

	t.Log("✓ Cache flush works")
}

func TestGetStats(t *testing.T) {
	logger := zap.NewNop()
	client, err := NewClient(ClientConfig{
		Endpoint: "https://routing.example.com",
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	stats := client.GetStats()
	if stats == nil {
		t.Fatal("Stats is nil")
	}

	if endpoint, ok := stats["endpoint"].(string); !ok || endpoint == "" {
		t.Error("Expected endpoint in stats")
	}
	if _, ok := stats["cache_entries"].(int); !ok {
		t.Error("Expected cache_entries in stats")
	}

	t.Log("✓ GetStats works")
}

func TestResolve_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal server error"))
	}))
	defer server.Close()

	logger := zap.NewNop()
	client, err := NewClient(ClientConfig{
		Endpoint:   server.URL,
		Logger:     logger,
		MaxRetries: 1, // Reduce retries for faster test
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx := context.Background()
	_, err = client.Resolve(ctx, "user@example.com", "", "", "")

	if err == nil {
		t.Error("Expected error for server error")
	}

	t.Log("✓ Server error handling works")
}

func TestResolve_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond) // Longer than timeout
		resp := ResolveResponse{Accepted: true}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	logger := zap.NewNop()
	client, err := NewClient(ClientConfig{
		Endpoint:   server.URL,
		Logger:     logger,
		TimeoutMS:  50, // Short timeout
		MaxRetries: 0,  // No retries
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx := context.Background()
	_, err = client.Resolve(ctx, "user@example.com", "", "", "")

	if err == nil {
		t.Error("Expected timeout error")
	}

	t.Log("✓ Timeout handling works")
}

func TestBuildCacheKey(t *testing.T) {
	logger := zap.NewNop()
	client, err := NewClient(ClientConfig{
		Endpoint: "https://routing.example.com",
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	key1 := client.buildCacheKey("user@example.com", "sender1@example.com")
	key2 := client.buildCacheKey("user@example.com", "sender2@example.com")
	key3 := client.buildCacheKey("user@example.com", "sender1@example.com")

	// Implementation now uses recipient:sender
	expected1 := "user@example.com:sender1@example.com"
	if key1 != expected1 {
		t.Errorf("Expected cache key '%s', got '%s'", expected1, key1)
	}

	// Keys should be different for different senders
	if key1 == key2 {
		t.Error("Cache keys should be different for different senders")
	}

	// Keys should be same for same recipient+sender
	if key1 != key3 {
		t.Error("Cache keys should be same for same recipient and sender")
	}
}

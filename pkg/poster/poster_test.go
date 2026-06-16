package poster

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"log/slog"
)

func TestPostEmailToDestinationWithContext_SuccessFirstAttempt(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewHTTPClient(30*time.Second, 0, 0, 0)
	err := PostEmailToDestinationWithContext(context.Background(), "test email", server.URL, "api-key", 3, false, "sender@example.com", "recipient@example.com", "", "", nil, client, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("Expected 1 request, but got: %d", requestCount)
	}
}

func TestPostEmailToDestinationWithContext_SuccessAfterRetries(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if count < 3 {
			w.WriteHeader(http.StatusServiceUnavailable) // 503 error
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	// Use a custom HTTP client with a very short timeout to speed up the test
	client := NewHTTPClient(100*time.Millisecond, 0, 0, 0)

	err := PostEmailToDestinationWithContext(context.Background(), "test email", server.URL, "api-key", 4, false, "sender@example.com", "recipient@example.com", "", "", nil, client, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	if atomic.LoadInt32(&requestCount) != 3 {
		t.Errorf("Expected 3 requests, but got: %d", requestCount)
	}
}

func TestPostEmailToDestinationWithContext_FailureAllRetries(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusInternalServerError) // 500 error
	}))
	defer server.Close()

	// Use a custom HTTP client with a very short timeout to speed up the test
	client := NewHTTPClient(100*time.Millisecond, 0, 0, 0)

	maxRetries := 3
	err := PostEmailToDestinationWithContext(context.Background(), "test email", server.URL, "api-key", maxRetries, false, "", "", "", "", nil, client, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	if err == nil {
		t.Error("Expected an error, but got nil")
	}

	var httpErr *HTTPStatusError
	if !errors.As(err, &httpErr) {
		t.Errorf("Expected HTTPStatusError, but got: %T", err)
	}

	if atomic.LoadInt32(&requestCount) != int32(maxRetries) {
		t.Errorf("Expected %d requests, but got: %d", maxRetries, requestCount)
	}
}

func TestPostEmailToDestinationWithContext_NonRetryableError(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusBadRequest) // 400 error
		io.WriteString(w, "bad request body")
	}))
	defer server.Close()

	client := NewHTTPClient(30*time.Second, 0, 0, 0)
	err := PostEmailToDestinationWithContext(context.Background(), "test email", server.URL, "api-key", 3, false, "", "", "", "", nil, client, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	if err == nil {
		t.Error("Expected an error, but got nil")
	}

	var httpErr *HTTPStatusError
	if errors.As(err, &httpErr) {
		if httpErr.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status code 400, but got: %d", httpErr.StatusCode)
		}
	} else {
		t.Errorf("Expected HTTPStatusError, but got: %T", err)
	}

	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("Expected 1 request (no retries), but got: %d", requestCount)
	}
}

func TestPostEmailToDestinationWithContext_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This handler will always cause a retry, giving us time to cancel.
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	// Use a custom HTTP client with a very short timeout to speed up the test
	client := NewHTTPClient(100*time.Millisecond, 0, 0, 0)

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel the context after a short delay, during the first backoff period.
	// The first backoff is 1 second, so 500ms is safe.
	time.AfterFunc(500*time.Millisecond, cancel)

	err := PostEmailToDestinationWithContext(ctx, "test email", server.URL, "api-key", 5, false, "", "", "", "", nil, client, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	if err == nil {
		t.Fatal("Expected an error, but got nil")
	}

	// Check if the error is a context cancellation error
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Expected context.Canceled error, but got: %v", err)
	}
}

func TestPostEmailToDestinationWithContext_NetworkError(t *testing.T) {
	// Create a server just to get a URL, then immediately close it.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL
	server.Close() // This ensures requests will fail with a network error.

	// Use a custom HTTP client with a very short timeout to speed up the test
	client := NewHTTPClient(100*time.Millisecond, 0, 0, 0)

	maxRetries := 3
	err := PostEmailToDestinationWithContext(context.Background(), "test email", url, "api-key", maxRetries, false, "", "", "", "", nil, client, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	if err == nil {
		t.Fatal("Expected an error, but got nil")
	}

	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("Expected a connection error, but got: %v", err)
	}

	// Check that the final error message indicates it failed after all attempts.
	if !strings.Contains(err.Error(), "failed after 3 attempts") {
		t.Errorf("Expected error message to indicate final failure, but got: %v", err)
	}
}

func TestPostEmailToDestinationWithContext_JunkHeader(t *testing.T) {
	var junkHeaderPresent bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Junk") == "yes" {
			junkHeaderPresent = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewHTTPClient(30*time.Second, 0, 0, 0)
	err := PostEmailToDestinationWithContext(context.Background(), "test email", server.URL, "api-key", 1, true, "", "", "", "", nil, client, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}

	if !junkHeaderPresent {
		t.Error("Expected X-Junk header to be present, but it was not")
	}
}

func TestPostEmailToDestinationWithContext_EnvelopeHeaders(t *testing.T) {
	var mailFromHeader, mailToHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mailFromHeader = r.Header.Get("X-Mail-From")
		mailToHeader = r.Header.Get("X-Mail-To")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewHTTPClient(30*time.Second, 0, 0, 0)
	err := PostEmailToDestinationWithContext(context.Background(), "test email", server.URL, "api-key", 1, false, "sender@example.com", "recipient@example.com", "", "", nil, client, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}

	if mailFromHeader != "sender@example.com" {
		t.Errorf("Expected X-Mail-From header to be 'sender@example.com', but got: %s", mailFromHeader)
	}

	if mailToHeader != "recipient@example.com" {
		t.Errorf("Expected X-Mail-To header to be 'recipient@example.com', but got: %s", mailToHeader)
	}
}

func TestPostEmailToDestinationWithContext_TraceIDHeader(t *testing.T) {
	var traceIDHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceIDHeader = r.Header.Get("X-Trace-ID")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewHTTPClient(30*time.Second, 0, 0, 0)
	testTraceID := "abc123def456"
	err := PostEmailToDestinationWithContext(context.Background(), "test email", server.URL, "api-key", 1, false, "", "", testTraceID, "", nil, client, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}

	if traceIDHeader != testTraceID {
		t.Errorf("Expected X-Trace-ID header to be '%s', but got: %s", testTraceID, traceIDHeader)
	}
}

// TestPostEmailToDestinationWithContext_NoAPIKeyForCustomEndpoint verifies that when apiKey is empty,
// no X-API-Key header is sent (for custom endpoints that use URL-based auth)
func TestPostEmailToDestinationWithContext_NoAPIKeyForCustomEndpoint(t *testing.T) {
	// Track received headers
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		io.ReadAll(r.Body) // Drain body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := server.Client()

	// Test 1: With API key
	err := PostEmailToDestinationWithContext(
		context.Background(),
		"Subject: Test\r\n\r\nBody",
		server.URL,
		"test-api-key",
		0,
		false,
		"from@example.com",
		"to@example.com",
		"trace-123",
		"",
		nil,
		client,
		logger,
		nil,
	)

	if err != nil {
		t.Fatalf("Failed with API key: %v", err)
	}

	if receivedHeaders.Get("Authorization") != "Bearer test-api-key" {
		t.Errorf("Expected Authorization header with value 'Bearer test-api-key', got: %s", receivedHeaders.Get("Authorization"))
	}

	// Test 2: Without API key (custom endpoint)
	receivedHeaders = nil
	err = PostEmailToDestinationWithContext(
		context.Background(),
		"Subject: Test\r\n\r\nBody",
		server.URL,
		"", // Empty API key for custom endpoint
		0,
		false,
		"from@example.com",
		"to@example.com",
		"trace-123",
		"",
		nil,
		client,
		logger,
		nil,
	)

	if err != nil {
		t.Fatalf("Failed without API key: %v", err)
	}

	if receivedHeaders.Get("Authorization") != "" {
		t.Errorf("Expected no Authorization header for custom endpoint, but got: %s", receivedHeaders.Get("Authorization"))
	}

	// Verify other headers are still present
	if receivedHeaders.Get("Content-Type") != "message/rfc822" {
		t.Errorf("Expected Content-Type header")
	}

	if receivedHeaders.Get("X-Trace-ID") != "trace-123" {
		t.Errorf("Expected X-Trace-ID header")
	}
}

func TestPostEmailToDestinationWithContext_PayloadTooLarge(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusRequestEntityTooLarge) // 413
		io.WriteString(w, `{"error": "Message too large - 41.23MB exceeds 25MB limit", "size": 43234234, "limit": 26214400}`)
	}))
	defer server.Close()

	client := NewHTTPClient(30*time.Second, 0, 0, 0)
	err := PostEmailToDestinationWithContext(context.Background(), "test email", server.URL, "api-key", 3, false, "", "", "", "", nil, client, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	if err == nil {
		t.Fatal("Expected an error, but got nil")
	}

	var httpErr *HTTPStatusError
	if !errors.As(err, &httpErr) {
		t.Fatalf("Expected HTTPStatusError, but got: %T", err)
	}

	if httpErr.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected status code 413, but got: %d", httpErr.StatusCode)
	}

	if !strings.Contains(httpErr.Body, "Message too large") {
		t.Errorf("Expected error body to contain 'Message too large', but got: %s", httpErr.Body)
	}

	// 413 should NOT be retried (it's a permanent client error)
	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("Expected 1 request (no retries), but got: %d", requestCount)
	}

	// Verify it's not marked as retryable
	if httpErr.IsRetryable() {
		t.Error("Expected HTTP 413 to be non-retryable, but IsRetryable() returned true")
	}
}

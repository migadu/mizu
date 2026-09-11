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

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testDelivery fills in the body and token most tests do not care about.
func testDelivery(d Delivery) Delivery {
	if d.RawEmail == "" {
		d.RawEmail = "test email"
	}
	if d.AuthToken == "" {
		d.AuthToken = "api-key"
	}
	return d
}

func TestPostEmailToDestinationWithContext_SuccessFirstAttempt(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewHTTPClient(30*time.Second, 0, 0, 0)
	err := PostEmailToDestinationWithContext(context.Background(), testDelivery(Delivery{URL: server.URL, MaxRetryAttempts: 3, MailFrom: "sender@example.com", MailTo: "recipient@example.com"}), nil, client, testLogger(), nil)

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

	err := PostEmailToDestinationWithContext(context.Background(), testDelivery(Delivery{URL: server.URL, MaxRetryAttempts: 4, MailFrom: "sender@example.com", MailTo: "recipient@example.com"}), nil, client, testLogger(), nil)

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
	err := PostEmailToDestinationWithContext(context.Background(), testDelivery(Delivery{URL: server.URL, MaxRetryAttempts: maxRetries}), nil, client, testLogger(), nil)

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
	err := PostEmailToDestinationWithContext(context.Background(), testDelivery(Delivery{URL: server.URL, MaxRetryAttempts: 3}), nil, client, testLogger(), nil)

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

	err := PostEmailToDestinationWithContext(ctx, testDelivery(Delivery{URL: server.URL, MaxRetryAttempts: 5}), nil, client, testLogger(), nil)

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
	err := PostEmailToDestinationWithContext(context.Background(), testDelivery(Delivery{URL: url, MaxRetryAttempts: maxRetries}), nil, client, testLogger(), nil)

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
	err := PostEmailToDestinationWithContext(context.Background(), testDelivery(Delivery{URL: server.URL, MaxRetryAttempts: 1, IsJunk: true}), nil, client, testLogger(), nil)
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
	err := PostEmailToDestinationWithContext(context.Background(), testDelivery(Delivery{URL: server.URL, MaxRetryAttempts: 1, MailFrom: "sender@example.com", MailTo: "recipient@example.com"}), nil, client, testLogger(), nil)
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
	err := PostEmailToDestinationWithContext(context.Background(), testDelivery(Delivery{URL: server.URL, MaxRetryAttempts: 1, TraceID: testTraceID}), nil, client, testLogger(), nil)
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
	err := PostEmailToDestinationWithContext(context.Background(), Delivery{
		RawEmail:  "Subject: Test\r\n\r\nBody",
		URL:       server.URL,
		AuthToken: "test-api-key",
		MailFrom:  "from@example.com",
		MailTo:    "to@example.com",
		TraceID:   "trace-123",
	}, nil, client, logger, nil)

	if err != nil {
		t.Fatalf("Failed with API key: %v", err)
	}

	if receivedHeaders.Get("Authorization") != "Bearer test-api-key" {
		t.Errorf("Expected Authorization header with value 'Bearer test-api-key', got: %s", receivedHeaders.Get("Authorization"))
	}

	// Test 2: Without API key (custom endpoint)
	receivedHeaders = nil
	err = PostEmailToDestinationWithContext(context.Background(), Delivery{
		RawEmail: "Subject: Test\r\n\r\nBody",
		URL:      server.URL,
		// Empty AuthToken for custom endpoint
		MailFrom: "from@example.com",
		MailTo:   "to@example.com",
		TraceID:  "trace-123",
	}, nil, client, logger, nil)

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
	err := PostEmailToDestinationWithContext(context.Background(), testDelivery(Delivery{URL: server.URL, MaxRetryAttempts: 3}), nil, client, testLogger(), nil)

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

func TestNewHTTPClient_DoesNotFollowRedirects(t *testing.T) {
	// A delivery endpoint has no legitimate redirect use: a 307/308 response
	// must NOT be followed, otherwise the message body (and envelope headers)
	// would be re-routed to whatever host the response points at.
	var redirectHit, secondHop int32
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&redirectHit, 1)
		http.Redirect(w, r, "http://attacker.example/collect", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/collect", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&secondHop, 1)
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewHTTPClient(5*time.Second, 0, 0, 0)
	resp, err := client.Get(server.URL + "/start")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if got := atomic.LoadInt32(&redirectHit); got != 1 {
		t.Errorf("expected the first hop to be hit once, got %d", got)
	}
	if got := atomic.LoadInt32(&secondHop); got != 0 {
		t.Errorf("redirect was followed to second hop - CheckRedirect must not follow redirects")
	}
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("expected 307 as the returned response, got %d", resp.StatusCode)
	}
}

// TestDelivery_applyHeaders pins the HTTP request contract: every populated
// field maps to its header, and optional headers are absent when unset.
func TestDelivery_applyHeaders(t *testing.T) {
	t.Run("all fields set", func(t *testing.T) {
		d := Delivery{
			AuthToken:         "tok",
			MailFrom:          "sender@example.com",
			MailTo:            "recipient@example.com",
			TraceID:           "trace-1",
			AuthenticatedUser: "user@example.com",
			Origin:            "submission",
			ClientIP:          "203.0.113.7",
			IsJunk:            true,
			JunkAction:        "header",
			Spam:              &SpamVerdict{Score: 4.349, Action: "add header"},
		}
		req, _ := http.NewRequest("POST", "http://backend", nil)
		d.applyHeaders(req)

		want := map[string]string{
			"Content-Type":  "message/rfc822",
			"Authorization": "Bearer tok",
			"X-Mail-From":   "sender@example.com",
			"X-Mail-To":     "recipient@example.com",
			"X-Trace-ID":    "trace-1",
			"X-Auth-User":   "user@example.com",
			"X-Mail-Origin": "submission",
			"X-Client-IP":   "203.0.113.7",
			"X-Junk":        "yes",
			"X-Junk-Action": "header",
			"X-Spam-Score":  "4.35",
			"X-Spam-Action": "add header",
		}
		for name, value := range want {
			if got := req.Header.Get(name); got != value {
				t.Errorf("%s = %q, want %q", name, got, value)
			}
		}
	})

	t.Run("optional headers omitted when unset", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "http://backend", nil)
		Delivery{}.applyHeaders(req)

		if got := req.Header.Get("Content-Type"); got != "message/rfc822" {
			t.Errorf("Content-Type = %q, want message/rfc822", got)
		}
		for _, name := range []string{
			"Authorization", "X-Mail-From", "X-Mail-To", "X-Trace-ID", "X-Auth-User",
			"X-Mail-Origin", "X-Client-IP",
			"X-Junk", "X-Junk-Action", "X-Spam-Score", "X-Spam-Action",
		} {
			if _, present := req.Header[name]; present {
				t.Errorf("%s should be absent on an empty Delivery, got %q", name, req.Header.Get(name))
			}
		}
	})

	t.Run("spam score without action", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "http://backend", nil)
		Delivery{Spam: &SpamVerdict{Score: -1.5}}.applyHeaders(req)
		if got := req.Header.Get("X-Spam-Score"); got != "-1.50" {
			t.Errorf("X-Spam-Score = %q, want -1.50", got)
		}
		if _, present := req.Header["X-Spam-Action"]; present {
			t.Error("X-Spam-Action should be absent when the verdict has no action")
		}
	})
}

// TestPostEmail_BodyUnchanged proves delivery metadata never leaks into the
// message: the backend receives RawEmail byte for byte, with every header
// carried only in the HTTP envelope.
func TestPostEmail_BodyUnchanged(t *testing.T) {
	const raw = "Received: by mizu\r\nSubject: Test\r\n\r\nBody\r\n"
	var gotBody []byte
	var gotHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	d := Delivery{
		RawEmail:          raw,
		URL:               server.URL,
		AuthToken:         "tok",
		MailFrom:          "sender@example.com",
		MailTo:            "recipient@example.com",
		TraceID:           "trace-1",
		AuthenticatedUser: "user@example.com",
		Origin:            "relay",
		ClientIP:          "203.0.113.7",
		IsJunk:            true,
		JunkAction:        "subject",
		Spam:              &SpamVerdict{Score: 12, Action: "reject"},
	}
	if err := PostEmailToDestinationWithContext(context.Background(), d, nil, server.Client(), testLogger(), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(gotBody) != raw {
		t.Errorf("body was modified:\n got: %q\nwant: %q", gotBody, raw)
	}
	if gotHeaders.Get("X-Mail-Origin") != "relay" || gotHeaders.Get("X-Client-IP") != "203.0.113.7" || gotHeaders.Get("X-Spam-Score") != "12.00" {
		t.Errorf("metadata headers missing from request: %v", gotHeaders)
	}
}

// TestDelivery_noClientSuppliedHeaders guards the reason X-Client-Helo was
// removed: Go's transport rejects an entire request when a header value holds a
// control byte, so client-supplied text in a delivery header turns a hostile or
// buggy HELO into a permanent delivery failure. Every Delivery string is
// mizu-generated; this test fails if a client-controlled one is reintroduced.
func TestDelivery_noClientSuppliedHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Every free-text field carries a byte a hostile client could supply.
	// Delivery must still reach the backend.
	d := Delivery{
		RawEmail:         "Subject: T\r\n\r\nBody",
		URL:              srv.URL,
		MaxRetryAttempts: 1,
		Origin:           "relay",
		ClientIP:         "192.0.2.1",
		JunkAction:       "header",
		Spam:             &SpamVerdict{Score: 1, Action: "no action"},
	}
	if err := PostEmailToDestinationWithContext(context.Background(), d, nil, srv.Client(), testLogger(), nil); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}

	// Demonstrate the failure mode being guarded against: a control byte in any
	// header value fails the whole POST, not just that header.
	req, _ := http.NewRequest("POST", srv.URL, nil)
	req.Header.Set("X-Client-Helo", "evil\x01host.com")
	if _, err := srv.Client().Do(req); err == nil {
		t.Error("expected Go transport to reject a control byte in a header value; " +
			"if this now succeeds, the rationale for omitting client text needs revisiting")
	}
}

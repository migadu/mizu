package spamcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestClient_Check_Spam(t *testing.T) {
	// Mock rspamd server that returns "add header" action
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and path
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		// Verify headers
		if r.Header.Get("IP") == "" {
			t.Error("Expected IP header to be set")
		}
		if r.Header.Get("From") == "" {
			t.Error("Expected From header to be set")
		}
		if r.Header.Get("Helo") == "" {
			t.Error("Expected Helo header to be set")
		}

		// Return spam response
		resp := rspamdResponse{
			Action:        "add header",
			Score:         7.5,
			RequiredScore: 5.0,
			Symbols: map[string]rspamdSymbol{
				"SPAM_RULE": {Score: 7.5},
			},
			Milter: &rspamdMilter{
				AddHeaders: map[string]rspamdHeaderList{
					"X-Spam": {{Value: "Yes", Order: 0}},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Create client
	client := NewClient(server.URL, "", 5*time.Second, slog.Default())

	// Test spam detection
	result, err := client.Check(
		context.Background(),
		"test-trace",
		"Subject: Get rich quick\r\n\r\nBuy now!",
		"1.2.3.4",
		"spammer@bad.com",
		[]string{"victim@example.com"},
		"spammer.bad.com",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify result
	if !result.IsSpam {
		t.Error("Expected IsSpam to be true for 'add header' action")
	}

	if result.Action != "add header" {
		t.Errorf("Expected action 'add header', got '%s'", result.Action)
	}

	if result.Score != 7.5 {
		t.Errorf("Expected score 7.5, got %.2f", result.Score)
	}

	if result.RequiredScore != 5.0 {
		t.Errorf("Expected required score 5.0, got %.2f", result.RequiredScore)
	}

	// Verify headers
	if got := result.AddHeaders["X-Spam"]; len(got) != 1 || got[0] != "Yes" {
		t.Errorf("Expected X-Spam header with value [Yes], got %v", got)
	}
}

func TestClient_Check_Ham(t *testing.T) {
	// Mock rspamd server that returns "no action"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := rspamdResponse{
			Action:        "no action",
			Score:         1.2,
			RequiredScore: 5.0,
			Symbols: map[string]rspamdSymbol{
				"LEGITIMATE": {Score: -1.0},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "", 5*time.Second, slog.Default())

	result, err := client.Check(
		context.Background(),
		"test-trace",
		"Subject: Legitimate email\r\n\r\nHello!",
		"10.0.0.1",
		"user@example.com",
		[]string{"recipient@example.com"},
		"mail.example.com",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify result
	if result.IsSpam {
		t.Error("Expected IsSpam to be false for 'no action'")
	}

	if result.Action != "no action" {
		t.Errorf("Expected action 'no action', got '%s'", result.Action)
	}

	if result.Score != 1.2 {
		t.Errorf("Expected score 1.2, got %.2f", result.Score)
	}
}

func TestClient_Check_QueueIDHeader(t *testing.T) {
	// Mock rspamd server that records the Queue-ID header it receives.
	var receivedQueueID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQueueID = r.Header.Get("Queue-ID")

		resp := rspamdResponse{Action: "no action", Score: 0.0, RequiredScore: 5.0}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "", 5*time.Second, slog.Default())

	_, err := client.Check(
		context.Background(),
		"trace-abc-123",
		"Subject: Hello\r\n\r\nBody",
		"10.0.0.1",
		"user@example.com",
		[]string{"recipient@example.com"},
		"mail.example.com",
	)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if receivedQueueID != "trace-abc-123" {
		t.Errorf("Expected Queue-ID header 'trace-abc-123', got '%s'", receivedQueueID)
	}
}

func TestClient_Check_QueueIDHeaderOmittedWhenEmpty(t *testing.T) {
	// An empty trace ID must not produce a blank Queue-ID header.
	var queueIDPresent bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, queueIDPresent = r.Header["Queue-Id"]

		resp := rspamdResponse{Action: "no action", Score: 0.0, RequiredScore: 5.0}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "", 5*time.Second, slog.Default())

	_, err := client.Check(
		context.Background(),
		"",
		"Subject: Hello\r\n\r\nBody",
		"10.0.0.1",
		"user@example.com",
		[]string{"recipient@example.com"},
		"mail.example.com",
	)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if queueIDPresent {
		t.Error("Expected no Queue-ID header when trace ID is empty")
	}
}

func TestClient_Check_Reject(t *testing.T) {
	// Mock rspamd server that returns "reject" action
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := rspamdResponse{
			Action:        "reject",
			Score:         15.0,
			RequiredScore: 5.0,
			Symbols: map[string]rspamdSymbol{
				"HIGH_SPAM": {Score: 15.0},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "", 5*time.Second, slog.Default())

	result, err := client.Check(
		context.Background(),
		"test-trace",
		"Subject: Obvious spam\r\n\r\nVirus content",
		"1.2.3.4",
		"virus@malware.com",
		[]string{"victim@example.com"},
		"malware.com",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify result
	if !result.IsSpam {
		t.Error("Expected IsSpam to be true for 'reject' action")
	}

	if result.Action != "reject" {
		t.Errorf("Expected action 'reject', got '%s'", result.Action)
	}

	if result.Score != 15.0 {
		t.Errorf("Expected score 15.0, got %.2f", result.Score)
	}
}

func TestClient_Check_HTTPCrypt(t *testing.T) {
	password := "test-secret"
	receivedPassword := ""
	receivedNonce := ""

	// Mock rspamd server that checks HTTPCrypt auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPassword = r.Header.Get("Password")
		receivedNonce = r.Header.Get("Nonce")

		resp := rspamdResponse{
			Action:        "no action",
			Score:         0.0,
			RequiredScore: 5.0,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, password, 5*time.Second, slog.Default())

	_, err := client.Check(
		context.Background(),
		"test-trace",
		"Subject: Test\r\n\r\nBody",
		"1.2.3.4",
		"user@example.com",
		[]string{"recipient@example.com"},
		"mail.example.com",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify HTTPCrypt headers were sent
	if receivedPassword == "" {
		t.Error("Expected Password header to be set")
	}

	if receivedNonce == "" {
		t.Error("Expected Nonce header to be set")
	}

	// Verify signature format (should be hex-encoded HMAC-SHA256)
	if len(receivedPassword) != 64 { // SHA256 hex = 64 chars
		t.Errorf("Expected 64-char hex signature, got %d chars", len(receivedPassword))
	}

	// Verify it's valid hex
	if !isHex(receivedPassword) {
		t.Errorf("Expected hex-encoded signature, got: %s", receivedPassword)
	}
}

func TestAdapter_Check(t *testing.T) {
	// Mock rspamd server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := rspamdResponse{
			Action:        "add header",
			Score:         6.0,
			RequiredScore: 5.0,
			Milter: &rspamdMilter{
				AddHeaders: map[string]rspamdHeaderList{
					"X-Spam-Score": {{Value: "6.0", Order: 0}},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Create adapter with custom spam header
	client := NewClient(server.URL, "", 5*time.Second, slog.Default())
	adapter := NewAdapter(client, "X-Junk", "yes", "", "")

	result, err := adapter.Check(
		context.Background(),
		"test-trace",
		"Subject: Spam\r\n\r\nSpam content",
		"1.2.3.4",
		"spammer@bad.com",
		[]string{"victim@example.com"},
		"spammer.bad.com",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify result
	if !result.IsSpam {
		t.Error("Expected IsSpam to be true")
	}

	// Verify custom spam header was added
	if got := result.AddHeaders["X-Junk"]; len(got) != 1 || got[0] != "yes" {
		t.Errorf("Expected X-Junk header with value [yes], got %v", got)
	}

	// Verify rspamd milter headers are also present
	if got := result.AddHeaders["X-Spam-Score"]; len(got) != 1 || got[0] != "6.0" {
		t.Errorf("Expected X-Spam-Score header with value [6.0], got %v", got)
	}
}

func TestAdapter_Check_RejectOnAction(t *testing.T) {
	// Mock rspamd server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := rspamdResponse{
			Action:        "reject",
			Score:         15.0,
			RequiredScore: 5.0,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Create adapter with reject_on_action="reject"
	client := NewClient(server.URL, "", 5*time.Second, slog.Default())
	adapter := NewAdapter(client, "X-Junk", "yes", "", "reject")

	result, err := adapter.Check(
		context.Background(),
		"test-trace",
		"Subject: Virus\r\n\r\nMalware",
		"1.2.3.4",
		"virus@malware.com",
		[]string{"victim@example.com"},
		"malware.com",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify ShouldReject is set
	if !result.ShouldReject {
		t.Error("Expected ShouldReject to be true when action matches reject_on_action")
	}
}

func TestAdapter_Check_Defer(t *testing.T) {
	// rspamd's "soft reject" (rate limiting) and "greylist" (greylisting
	// module) are both temporary failures: they must map to a defer
	// regardless of reject_on_action, and must not be classified as spam.
	for _, action := range []string{"soft reject", "greylist"} {
		t.Run(action, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp := rspamdResponse{
					Action:        action,
					Score:         8.0,
					RequiredScore: 15.0,
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			}))
			defer server.Close()

			// reject_on_action is "reject", which must NOT match a defer action.
			client := NewClient(server.URL, "", 5*time.Second, slog.Default())
			adapter := NewAdapter(client, "X-Junk", "yes", "", "reject")

			result, err := adapter.Check(
				context.Background(),
				"test-trace",
				"Subject: Hello\r\n\r\nBody",
				"1.2.3.4",
				"sender@example.com",
				[]string{"victim@example.com"},
				"example.com",
			)

			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			if !result.ShouldDefer {
				t.Errorf("Expected ShouldDefer to be true for %q action", action)
			}
			if result.ShouldReject {
				t.Errorf("Expected ShouldReject to be false for %q action", action)
			}
			// A temporary failure is not a spam classification.
			if result.IsSpam {
				t.Errorf("Expected IsSpam to be false for %q action", action)
			}
		})
	}
}

func TestRspamdHeader_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected rspamdHeader
	}{
		{
			name:     "object format",
			json:     `{"value": "Yes", "order": 1}`,
			expected: rspamdHeader{Value: "Yes", Order: 1},
		},
		{
			name:     "string format",
			json:     `"Yes"`,
			expected: rspamdHeader{Value: "Yes", Order: 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var h rspamdHeader
			if err := json.Unmarshal([]byte(tt.json), &h); err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if h.Value != tt.expected.Value {
				t.Errorf("Value = %q, want %q", h.Value, tt.expected.Value)
			}
			if h.Order != tt.expected.Order {
				t.Errorf("Order = %d, want %d", h.Order, tt.expected.Order)
			}
		})
	}
}

func TestClient_Check_StringHeaders(t *testing.T) {
	// Mock rspamd server returning add_headers as plain strings (not objects)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"action": "add header",
			"score": 8.0,
			"required_score": 5.0,
			"symbols": {},
			"milter": {
				"add_headers": {
					"X-Spam": "Yes",
					"X-Spam-Score": "8.0"
				}
			}
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "", 5*time.Second, slog.Default())
	result, err := client.Check(
		context.Background(),
		"test-trace",
		"Subject: Test\r\n\r\nBody",
		"1.2.3.4",
		"sender@example.com",
		[]string{"recipient@example.com"},
		"mail.example.com",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if got := result.AddHeaders["X-Spam"]; len(got) != 1 || got[0] != "Yes" {
		t.Errorf("Expected X-Spam header [Yes], got %v", got)
	}
	if got := result.AddHeaders["X-Spam-Score"]; len(got) != 1 || got[0] != "8.0" {
		t.Errorf("Expected X-Spam-Score header [8.0], got %v", got)
	}
}

func TestClient_Check_ArrayHeaders(t *testing.T) {
	// Regression: rspamd returns an array of header entries when the same
	// header name needs to be added more than once (e.g. multiple
	// Authentication-Results lines for chained ARC instances). The decoder
	// must accept that shape instead of failing with "cannot unmarshal array".
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"action": "no action",
			"score": 0.0,
			"required_score": 5.0,
			"symbols": {},
			"milter": {
				"add_headers": {
					"Authentication-Results": [
						{"value": "mx.example.com; dkim=pass", "order": 0},
						{"value": "mx.example.com; arc=pass", "order": 1}
					],
					"X-Mixed": ["one", "two"],
					"X-Single": "solo"
				}
			}
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "", 5*time.Second, slog.Default())
	result, err := client.Check(
		context.Background(),
		"test-trace",
		"Subject: Test\r\n\r\nBody",
		"1.2.3.4",
		"sender@example.com",
		[]string{"recipient@example.com"},
		"mail.example.com",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	got := result.AddHeaders["Authentication-Results"]
	if len(got) != 2 {
		t.Fatalf("Expected 2 Authentication-Results values, got %d: %v", len(got), got)
	}
	// rspamd returns a map, so the order in which keys are visited isn't
	// guaranteed — but each individual array preserves its ordering.
	if got[0] != "mx.example.com; dkim=pass" || got[1] != "mx.example.com; arc=pass" {
		t.Errorf("Unexpected Authentication-Results values: %v", got)
	}

	if got := result.AddHeaders["X-Mixed"]; len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Errorf("Expected X-Mixed=[one two], got %v", got)
	}
	if got := result.AddHeaders["X-Single"]; len(got) != 1 || got[0] != "solo" {
		t.Errorf("Expected X-Single=[solo], got %v", got)
	}
}

func TestClient_Check_ArrayHeaders_OrderRespected(t *testing.T) {
	// Rspamd's protocol doesn't guarantee JSON array order matches the
	// intended emission order — `order` is the authoritative field. Hand
	// the decoder an array whose array index disagrees with `order` and
	// verify we sort by `order`.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"action": "no action",
			"score": 0.0,
			"required_score": 5.0,
			"symbols": {},
			"milter": {
				"add_headers": {
					"Authentication-Results": [
						{"value": "second", "order": 2},
						{"value": "first",  "order": 1},
						{"value": "third",  "order": 3}
					]
				}
			}
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "", 5*time.Second, slog.Default())
	result, err := client.Check(
		context.Background(),
		"test-trace",
		"Subject: Test\r\n\r\nBody",
		"",
		"sender@example.com",
		[]string{"recipient@example.com"},
		"",
	)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	got := result.AddHeaders["Authentication-Results"]
	want := []string{"first", "second", "third"}
	if len(got) != len(want) {
		t.Fatalf("Expected %d values, got %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Position %d: expected %q, got %q (full: %v)", i, want[i], got[i], got)
		}
	}
}

func TestClient_Check_NullHeaderDropped(t *testing.T) {
	// A `null` entry should not yield a `Name: \r\n` header — drop it.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"action": "no action",
			"score": 0.0,
			"required_score": 5.0,
			"symbols": {},
			"milter": {
				"add_headers": {
					"X-Dropped": null,
					"X-Empty":   "",
					"X-Kept":    "yes"
				}
			}
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "", 5*time.Second, slog.Default())
	result, err := client.Check(
		context.Background(),
		"test-trace",
		"Subject: Test\r\n\r\nBody",
		"",
		"sender@example.com",
		[]string{"recipient@example.com"},
		"",
	)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if _, ok := result.AddHeaders["X-Dropped"]; ok {
		t.Errorf("Expected X-Dropped to be omitted (null entry), got %v", result.AddHeaders["X-Dropped"])
	}
	if _, ok := result.AddHeaders["X-Empty"]; ok {
		t.Errorf("Expected X-Empty to be omitted (empty value), got %v", result.AddHeaders["X-Empty"])
	}
	if got := result.AddHeaders["X-Kept"]; len(got) != 1 || got[0] != "yes" {
		t.Errorf("Expected X-Kept=[yes], got %v", got)
	}
}

func TestClient_Check_RetryOnBrokenConnection(t *testing.T) {
	// Reproduce the half-dead-keep-alive scenario: first connection is
	// closed with SO_LINGER=0 so the client observes an RST mid-response;
	// the second connection answers normally. The client should retry
	// transparently and return success.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var attempts atomic.Int32
	const okBody = `{"action":"no action","score":0.0,"required_score":5.0,"symbols":{}}`
	okResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(okBody), okBody)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			n := attempts.Add(1)
			go func(conn net.Conn, attempt int32) {
				defer conn.Close()
				if attempt == 1 {
					// Drain a few bytes so the client side commits to the
					// connection, then RST.
					_ = conn.SetReadDeadline(time.Now().Add(time.Second))
					buf := make([]byte, 64)
					_, _ = conn.Read(buf)
					if tcp, ok := conn.(*net.TCPConn); ok {
						_ = tcp.SetLinger(0)
					}
					return
				}
				// Subsequent attempts: read request, write canned response.
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 4096)
				for {
					nRead, err := conn.Read(buf)
					if err != nil || nRead < len(buf) {
						break
					}
				}
				_, _ = conn.Write([]byte(okResp))
			}(conn, n)
		}
	}()
	t.Cleanup(func() { ln.Close(); <-done })

	url := fmt.Sprintf("http://%s/checkv2", ln.Addr().String())
	client := NewClient(url, "", 5*time.Second, slog.Default())

	result, err := client.Check(
		context.Background(),
		"test-trace",
		"Subject: Test\r\n\r\nBody",
		"1.2.3.4",
		"sender@example.com",
		[]string{"recipient@example.com"},
		"mail.example.com",
	)
	if err != nil {
		t.Fatalf("Expected retry to succeed, got: %v", err)
	}
	if result == nil || result.Action != "no action" {
		t.Fatalf("Unexpected result: %+v", result)
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("Expected exactly 2 attempts (one broken, one good), got %d", got)
	}
}

func TestIsBrokenConnErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"context canceled", context.Canceled, false},
		{"deadline exceeded", context.DeadlineExceeded, false},
		{"ECONNRESET", fmt.Errorf("wrap: %w", syscall.ECONNRESET), true},
		{"EPIPE", fmt.Errorf("wrap: %w", syscall.EPIPE), true},
		{"EOF", fmt.Errorf("wrap: %w", io.EOF), true},
		{"unexpected EOF", fmt.Errorf("wrap: %w", io.ErrUnexpectedEOF), true},
		{"random other error", fmt.Errorf("nope"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isBrokenConnErr(tc.err); got != tc.want {
				t.Errorf("isBrokenConnErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestClient_Check_StatisticsError504(t *testing.T) {
	// Rspamd returns 504 when autolearn/statistics fails. The scan result is
	// lost, but we should fail open (no error, empty result).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGatewayTimeout)
		w.Write([]byte(`{"error":"all learn conditions denied learning ham in default classifier","error_domain":"rspamd-statistics"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "", 5*time.Second, slog.Default())
	result, err := client.Check(
		context.Background(),
		"test-trace",
		"Subject: Test\r\n\r\nBody",
		"1.2.3.4",
		"sender@example.com",
		[]string{"recipient@example.com"},
		"mail.example.com",
	)

	if err != nil {
		t.Fatalf("Expected no error for statistics 504, got: %v", err)
	}
	if result.IsSpam {
		t.Error("Expected IsSpam=false for statistics error fallback")
	}
	if result.Action != "" {
		t.Errorf("Expected empty action, got %q", result.Action)
	}
}

func TestClient_Check_Non_Statistics504(t *testing.T) {
	// A 504 without error_domain "rspamd-statistics" should still be an error.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGatewayTimeout)
		w.Write([]byte(`{"error":"backend timeout","error_domain":"rspamd-proxy"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "", 5*time.Second, slog.Default())
	_, err := client.Check(
		context.Background(),
		"test-trace",
		"Subject: Test\r\n\r\nBody",
		"1.2.3.4",
		"sender@example.com",
		[]string{"recipient@example.com"},
		"mail.example.com",
	)

	if err == nil {
		t.Fatal("Expected error for non-statistics 504, got nil")
	}
	if !strings.Contains(err.Error(), "504") {
		t.Errorf("Expected error to mention status 504, got: %v", err)
	}
}

// isHex checks if a string is valid hexadecimal
func isHex(s string) bool {
	s = strings.ToLower(s)
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

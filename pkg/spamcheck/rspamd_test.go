package spamcheck

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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
				AddHeaders: map[string]rspamdHeader{
					"X-Spam": {Value: "Yes", Order: 0},
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
	if result.AddHeaders["X-Spam"] != "Yes" {
		t.Errorf("Expected X-Spam header with value 'Yes', got '%s'", result.AddHeaders["X-Spam"])
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
				AddHeaders: map[string]rspamdHeader{
					"X-Spam-Score": {Value: "6.0", Order: 0},
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
	if result.AddHeaders["X-Junk"] != "yes" {
		t.Errorf("Expected X-Junk header with value 'yes', got '%s'", result.AddHeaders["X-Junk"])
	}

	// Verify rspamd milter headers are also present
	if result.AddHeaders["X-Spam-Score"] != "6.0" {
		t.Errorf("Expected X-Spam-Score header with value '6.0', got '%s'", result.AddHeaders["X-Spam-Score"])
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
		"Subject: Test\r\n\r\nBody",
		"1.2.3.4",
		"sender@example.com",
		[]string{"recipient@example.com"},
		"mail.example.com",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if result.AddHeaders["X-Spam"] != "Yes" {
		t.Errorf("Expected X-Spam header 'Yes', got %q", result.AddHeaders["X-Spam"])
	}
	if result.AddHeaders["X-Spam-Score"] != "8.0" {
		t.Errorf("Expected X-Spam-Score header '8.0', got %q", result.AddHeaders["X-Spam-Score"])
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

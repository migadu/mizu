package smtp

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/stats"

	"github.com/emersion/go-smtp"
)

// TestMultipleRecipients_DeliveryToBackend verifies that SMTP sessions can accept
// multiple RCPT TO commands and deliver them all in a single HTTP POST request
func TestMultipleRecipients_DeliveryToBackend(t *testing.T) {
	var receivedRecipients string
	var receivedFrom string
	var receivedBody string

	// Create a backend server that captures the delivered email
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture headers
		receivedFrom = r.Header.Get("X-Mail-From")
		receivedRecipients = r.Header.Get("X-Mail-To")

		// Capture body
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backendServer.Close()

	// Configure SMTP server
	cfg := testConfig()
	// Add a server config since DefaultConfig has empty Servers slice
	if len(cfg.Servers) == 0 {
		cfg.Servers = append(cfg.Servers, config.ServerConfig{
			ListenAddr: ":25",
		})
	}
	cfg.Servers[0].Delivery = config.DeliveryConfig{
		URL:                backendServer.URL,
		AuthToken:          "test-token",
		MaxRetryAttempts:   1,
		HTTPTimeoutSeconds: 5,
	}

	statsManager := stats.NewManager(false, 0, "test", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer statsManager.Stop()

	httpClient := &http.Client{}

	// Create session with multiple recipients
	session := &Session{
		ctx:            context.Background(),
		helo:           "sender.example.com",
		from:           "alice@sender.com",
		to:             []string{"bob@example.com", "charlie@example.com", "dave@example.com"},
		serverConfig:   &cfg.Servers[0],
		globalConfig:   cfg,
		statsManager:   statsManager,
		circuitBreaker: nil,
		httpClient:     httpClient,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteAddr:     "192.0.2.1:12345",
		traceID:        "test-trace-123",
	}

	// Deliver email
	emailContent := "Subject: Test Email\r\n\r\nThis is a test email for multiple recipients."
	err := session.deliverSynchronous(emailContent)
	if err != nil {
		t.Fatalf("Expected delivery to succeed, got error: %v", err)
	}

	// Verify backend received correct envelope sender
	if receivedFrom != "alice@sender.com" {
		t.Errorf("Expected X-Mail-From 'alice@sender.com', got '%s'", receivedFrom)
	}

	// Verify backend received all recipients as comma-separated list
	expectedRecipients := "bob@example.com, charlie@example.com, dave@example.com"
	if receivedRecipients != expectedRecipients {
		t.Errorf("Expected X-Mail-To '%s', got '%s'", expectedRecipients, receivedRecipients)
	}

	// Verify email content was delivered
	if !strings.Contains(receivedBody, "This is a test email") {
		t.Errorf("Expected email body to contain test message, got: %s", receivedBody)
	}
}

// TestMultipleRecipients_SingleRecipientStillWorks verifies backward compatibility
// with single recipient delivery
func TestMultipleRecipients_SingleRecipientStillWorks(t *testing.T) {
	var receivedRecipients string

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedRecipients = r.Header.Get("X-Mail-To")
		w.WriteHeader(http.StatusOK)
	}))
	defer backendServer.Close()

	cfg := testConfig()
	// Add a server config since DefaultConfig has empty Servers slice
	if len(cfg.Servers) == 0 {
		cfg.Servers = append(cfg.Servers, config.ServerConfig{
			ListenAddr: ":25",
		})
	}
	cfg.Servers[0].Delivery = config.DeliveryConfig{
		URL:                backendServer.URL,
		AuthToken:          "test-token",
		MaxRetryAttempts:   1,
		HTTPTimeoutSeconds: 5,
	}

	statsManager := stats.NewManager(false, 0, "test", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer statsManager.Stop()

	httpClient := &http.Client{}

	// Create session with single recipient
	session := &Session{
		ctx:            context.Background(),
		helo:           "sender.example.com",
		from:           "alice@sender.com",
		to:             []string{"bob@example.com"}, // Single recipient
		serverConfig:   &cfg.Servers[0],
		globalConfig:   cfg,
		statsManager:   statsManager,
		circuitBreaker: nil,
		httpClient:     httpClient,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteAddr:     "192.0.2.1:12345",
		traceID:        "test-trace-single",
	}

	emailContent := "Subject: Single Recipient Test\r\n\r\nTest"
	err := session.deliverSynchronous(emailContent)
	if err != nil {
		t.Fatalf("Expected delivery to succeed, got error: %v", err)
	}

	// Single recipient should NOT have trailing comma
	expectedRecipients := "bob@example.com"
	if receivedRecipients != expectedRecipients {
		t.Errorf("Expected X-Mail-To '%s', got '%s'", expectedRecipients, receivedRecipients)
	}
}

// TestMultipleRecipients_BackendFailureRejectsAll verifies that if the backend
// rejects the delivery, all recipients are rejected (no partial success)
func TestMultipleRecipients_BackendFailureRejectsAll(t *testing.T) {
	// Backend that returns 550 (permanent failure)
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // 404
		w.Write([]byte("Recipient not found"))
	}))
	defer backendServer.Close()

	cfg := testConfig()
	// Add a server config since DefaultConfig has empty Servers slice
	if len(cfg.Servers) == 0 {
		cfg.Servers = append(cfg.Servers, config.ServerConfig{
			ListenAddr: ":25",
		})
	}
	cfg.Servers[0].Delivery = config.DeliveryConfig{
		URL:                backendServer.URL,
		AuthToken:          "test-token",
		MaxRetryAttempts:   1,
		HTTPTimeoutSeconds: 5,
	}

	statsManager := stats.NewManager(false, 0, "test", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer statsManager.Stop()

	httpClient := &http.Client{}

	session := &Session{
		ctx:            context.Background(),
		helo:           "sender.example.com",
		from:           "alice@sender.com",
		to:             []string{"bob@example.com", "charlie@example.com"},
		serverConfig:   &cfg.Servers[0],
		globalConfig:   cfg,
		statsManager:   statsManager,
		circuitBreaker: nil,
		httpClient:     httpClient,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteAddr:     "192.0.2.1:12345",
		traceID:        "test-trace-fail",
	}

	emailContent := "Subject: Test\r\n\r\nTest"
	err := session.deliverSynchronous(emailContent)

	// Should fail for ALL recipients
	if err == nil {
		t.Fatal("Expected delivery to fail when backend returns 404")
	}

	// Should return 550 SMTP error
	smtpErr, ok := err.(*smtp.SMTPError)
	if !ok {
		t.Fatalf("Expected *smtp.SMTPError, got %T", err)
	}

	if smtpErr.Code != 550 {
		t.Errorf("Expected SMTP code 550 for recipient not found, got %d", smtpErr.Code)
	}
}

// testConfig returns a minimal config for testing
func testConfig() *config.Config {
	cfg := config.DefaultConfig()
	cfg.Local = true // Disable TLS and other production features
	return &cfg
}

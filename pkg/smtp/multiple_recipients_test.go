package smtp

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/stats"

	"github.com/emersion/go-smtp"
)

// testConfig returns a minimal config for testing
func testConfig() *config.Config {
	cfg := config.DefaultConfig()
	cfg.Local = true
	return &cfg
}

// TestMultipleRecipients_DeliveryToBackend verifies that SMTP sessions with
// multiple recipients deliver one HTTP POST per recipient.
func TestMultipleRecipients_DeliveryToBackend(t *testing.T) {
	var mu sync.Mutex
	var posts []struct{ from, to, body string }

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		posts = append(posts, struct{ from, to, body string }{
			from: r.Header.Get("X-Mail-From"),
			to:   r.Header.Get("X-Mail-To"),
			body: string(body),
		})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer backendServer.Close()

	cfg := testConfig()
	if len(cfg.Servers) == 0 {
		cfg.Servers = append(cfg.Servers, config.ServerConfig{ListenAddr: ":25"})
	}
	cfg.Servers[0].Delivery = config.DeliveryConfig{
		URL:                backendServer.URL,
		AuthToken:          "test-token",
		MaxRetryAttempts:   1,
		HTTPTimeoutSeconds: 5,
	}

	statsManager := stats.NewManager(false, 0, "test", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer statsManager.Stop()

	session := &Session{
		ctx:            context.Background(),
		helo:           "sender.example.com",
		from:           "alice@sender.com",
		to:             []string{"bob@example.com", "charlie@example.com", "dave@example.com"},
		serverConfig:   &cfg.Servers[0],
		globalConfig:   cfg,
		statsManager:   stats.NewServerRecorder(statsManager, "test", 0, 0),
		httpClient:     &http.Client{},
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteAddr:     "192.0.2.1:12345",
		traceID:        "test-trace-123",
	}

	emailContent := "Subject: Test Email\r\n\r\nThis is a test email for multiple recipients."
	err := session.deliverSynchronous(emailContent)
	if err != nil {
		t.Fatalf("Expected delivery to succeed, got error: %v", err)
	}

	if len(posts) != 3 {
		t.Fatalf("Expected 3 HTTP POSTs (one per recipient), got %d", len(posts))
	}

	expectedRecipients := []string{"bob@example.com", "charlie@example.com", "dave@example.com"}
	for i, p := range posts {
		if p.from != "alice@sender.com" {
			t.Errorf("POST %d: expected X-Mail-From 'alice@sender.com', got '%s'", i, p.from)
		}
		if p.to != expectedRecipients[i] {
			t.Errorf("POST %d: expected X-Mail-To '%s', got '%s'", i, expectedRecipients[i], p.to)
		}
		if !strings.Contains(p.body, "This is a test email") {
			t.Errorf("POST %d: expected email body to contain test message", i)
		}
	}
}

// TestMultipleRecipients_SingleRecipientStillWorks verifies backward compatibility
func TestMultipleRecipients_SingleRecipientStillWorks(t *testing.T) {
	var receivedRecipient string

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedRecipient = r.Header.Get("X-Mail-To")
		w.WriteHeader(http.StatusOK)
	}))
	defer backendServer.Close()

	cfg := testConfig()
	if len(cfg.Servers) == 0 {
		cfg.Servers = append(cfg.Servers, config.ServerConfig{ListenAddr: ":25"})
	}
	cfg.Servers[0].Delivery = config.DeliveryConfig{
		URL:                backendServer.URL,
		AuthToken:          "test-token",
		MaxRetryAttempts:   1,
		HTTPTimeoutSeconds: 5,
	}

	statsManager := stats.NewManager(false, 0, "test", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer statsManager.Stop()

	session := &Session{
		ctx:            context.Background(),
		helo:           "sender.example.com",
		from:           "alice@sender.com",
		to:             []string{"bob@example.com"},
		serverConfig:   &cfg.Servers[0],
		globalConfig:   cfg,
		statsManager:   stats.NewServerRecorder(statsManager, "test", 0, 0),
		httpClient:     &http.Client{},
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteAddr:     "192.0.2.1:12345",
		traceID:        "test-trace-single",
	}

	err := session.deliverSynchronous("Subject: Test\r\n\r\nTest")
	if err != nil {
		t.Fatalf("Expected delivery to succeed, got error: %v", err)
	}

	if receivedRecipient != "bob@example.com" {
		t.Errorf("Expected X-Mail-To 'bob@example.com', got '%s'", receivedRecipient)
	}
}

// TestMultipleRecipients_SecondRecipientFails verifies stop-on-first-failure
func TestMultipleRecipients_SecondRecipientFails(t *testing.T) {
	var mu sync.Mutex
	var postCount int

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		postCount++
		n := postCount
		mu.Unlock()

		if n == 2 {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Recipient not found"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backendServer.Close()

	cfg := testConfig()
	if len(cfg.Servers) == 0 {
		cfg.Servers = append(cfg.Servers, config.ServerConfig{ListenAddr: ":25"})
	}
	cfg.Servers[0].Delivery = config.DeliveryConfig{
		URL:                backendServer.URL,
		AuthToken:          "test-token",
		MaxRetryAttempts:   1,
		HTTPTimeoutSeconds: 5,
	}

	statsManager := stats.NewManager(false, 0, "test", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer statsManager.Stop()

	session := &Session{
		ctx:            context.Background(),
		helo:           "sender.example.com",
		from:           "alice@sender.com",
		to:             []string{"bob@example.com", "charlie@example.com", "dave@example.com"},
		serverConfig:   &cfg.Servers[0],
		globalConfig:   cfg,
		statsManager:   stats.NewServerRecorder(statsManager, "test", 0, 0),
		httpClient:     &http.Client{},
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteAddr:     "192.0.2.1:12345",
		traceID:        "test-trace-fail",
	}

	err := session.deliverSynchronous("Subject: Test\r\n\r\nTest")
	if err == nil {
		t.Fatal("Expected delivery to fail when second recipient returns 404")
	}

	// Without a distTracker, a 404 falls through to a generic temporary failure (451);
	// the key guarantee is that the whole transaction fails (no partial success).
	smtpErr, ok := err.(*smtp.SMTPError)
	if !ok {
		t.Fatalf("Expected *smtp.SMTPError, got %T", err)
	}

	if smtpErr.Code != 451 {
		t.Errorf("Expected SMTP code 451 for generic delivery failure, got %d", smtpErr.Code)
	}

	// Should have stopped after 2 POSTs (bob succeeded, charlie failed, dave skipped)
	mu.Lock()
	finalCount := postCount
	mu.Unlock()
	if finalCount != 2 {
		t.Errorf("Expected 2 HTTP POSTs (stopped on failure), got %d", finalCount)
	}
}

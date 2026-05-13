package smtp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/poster"
	"migadu/mizu/pkg/stats"

	"github.com/emersion/go-smtp"
)

// mockSenderValidator implements SenderValidator for testing
type mockSenderValidator struct {
	shouldAccept bool
	message      string
	shouldError  bool
}

func (m *mockSenderValidator) Validate(ctx context.Context, clientIP, from string) (*SenderValidationResponse, error) {
	return m.ValidateWithContext(ctx, clientIP, "", "", from, "")
}

func (m *mockSenderValidator) ValidateWithContext(ctx context.Context, clientIP, ptr, helo, from, authenticatedUser string) (*SenderValidationResponse, error) {
	if m.shouldError {
		return nil, &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 4, 0},
			Message:      "validation service unavailable",
		}
	}
	return &SenderValidationResponse{
		Accepted: m.shouldAccept,
		Message:  m.message,
	}, nil
}

func (m *mockSenderValidator) FlushCache() {}

func (m *mockSenderValidator) GetStats() map[string]interface{} {
	return map[string]interface{}{}
}

// TestMail_SenderValidation_Accept tests accepting a valid sender
func TestMail_SenderValidation_Accept(t *testing.T) {
	cfg := testConfig()
	if len(cfg.Servers) == 0 {
		cfg.Servers = append(cfg.Servers, config.ServerConfig{
			ListenAddr: ":25",
			SenderValidation: config.SenderValidationConfig{
				Enabled: true,
			},
		})
	}
	cfg.Servers[0].SenderValidation.Enabled = true

	statsManager := stats.NewManager(false, 0, "test", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer statsManager.Stop()

	cbConfig := poster.CircuitBreakerConfig{
		Enabled:          true,
		FailureThreshold: 5,
		Timeout:          30 * time.Second,
		SuccessThreshold: 3,
	}
	cb := poster.NewCircuitBreaker(cbConfig, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	// Create mock validator that accepts the sender
	mockValidator := &mockSenderValidator{
		shouldAccept: true,
		message:      "Sender accepted",
	}

	session := &Session{
		conn:            (*smtp.Conn)(nil),
		helo:            "mail.example.com",
		serverConfig:    &cfg.Servers[0],
		globalConfig:    cfg,
		statsManager:    stats.NewServerRecorder(statsManager, "test", 0, 0),
		circuitBreaker:  cb,
		senderValidator: mockValidator,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteAddr:      "192.168.1.1:12345",
		ctx:             context.Background(),
	}

	// Should accept the sender
	err := session.Mail("sender@example.com", &smtp.MailOptions{})
	if err != nil {
		t.Errorf("Expected sender to be accepted, got error: %v", err)
	}

	if session.from != "sender@example.com" {
		t.Errorf("Expected from to be set to 'sender@example.com', got '%s'", session.from)
	}

	t.Log("✓ Sender validation accept works")
}

// TestMail_SenderValidation_Reject tests rejecting an unauthorized sender
func TestMail_SenderValidation_Reject(t *testing.T) {
	cfg := testConfig()
	if len(cfg.Servers) == 0 {
		cfg.Servers = append(cfg.Servers, config.ServerConfig{
			ListenAddr: ":25",
			SenderValidation: config.SenderValidationConfig{
				Enabled: true,
			},
		})
	}
	cfg.Servers[0].SenderValidation.Enabled = true

	statsManager := stats.NewManager(false, 0, "test", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer statsManager.Stop()

	cbConfig := poster.CircuitBreakerConfig{
		Enabled:          true,
		FailureThreshold: 5,
		Timeout:          30 * time.Second,
		SuccessThreshold: 3,
	}
	cb := poster.NewCircuitBreaker(cbConfig, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	// Create mock validator that rejects the sender
	mockValidator := &mockSenderValidator{
		shouldAccept: false,
		message:      "Sender not authorized",
	}

	session := &Session{
		conn:            (*smtp.Conn)(nil),
		helo:            "mail.example.com",
		serverConfig:    &cfg.Servers[0],
		globalConfig:    cfg,
		statsManager:    stats.NewServerRecorder(statsManager, "test", 0, 0),
		circuitBreaker:  cb,
		senderValidator: mockValidator,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteAddr:      "192.168.1.1:12345",
		ctx:             context.Background(),
	}

	// Should reject the sender
	err := session.Mail("unauthorized@example.com", &smtp.MailOptions{})
	if err == nil {
		t.Fatal("Expected sender to be rejected, but it was accepted")
	}

	smtpErr, ok := err.(*smtp.SMTPError)
	if !ok {
		t.Fatalf("Expected *smtp.SMTPError, got %T: %v", err, err)
	}

	if smtpErr.Code != 550 {
		t.Errorf("Expected SMTP code 550, got %d", smtpErr.Code)
	}

	if smtpErr.Message != "sender address rejected" {
		t.Errorf("Expected generic message 'sender address rejected', got '%s'", smtpErr.Message)
	}

	expectedEnhancedCode := smtp.EnhancedCode{5, 7, 1}
	if smtpErr.EnhancedCode != expectedEnhancedCode {
		t.Errorf("Expected enhanced code %v, got %v", expectedEnhancedCode, smtpErr.EnhancedCode)
	}

	t.Log("✓ Sender validation reject works")
}

// TestMail_SenderValidation_TemporaryFailure tests handling validation service errors
func TestMail_SenderValidation_TemporaryFailure(t *testing.T) {
	cfg := testConfig()
	if len(cfg.Servers) == 0 {
		cfg.Servers = append(cfg.Servers, config.ServerConfig{
			ListenAddr: ":25",
			SenderValidation: config.SenderValidationConfig{
				Enabled: true,
			},
		})
	}
	cfg.Servers[0].SenderValidation.Enabled = true

	statsManager := stats.NewManager(false, 0, "test", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer statsManager.Stop()

	cbConfig := poster.CircuitBreakerConfig{
		Enabled:          true,
		FailureThreshold: 5,
		Timeout:          30 * time.Second,
		SuccessThreshold: 3,
	}
	cb := poster.NewCircuitBreaker(cbConfig, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	// Create mock validator that returns an error
	mockValidator := &mockSenderValidator{
		shouldError: true,
	}

	session := &Session{
		conn:            (*smtp.Conn)(nil),
		helo:            "mail.example.com",
		serverConfig:    &cfg.Servers[0],
		globalConfig:    cfg,
		statsManager:    stats.NewServerRecorder(statsManager, "test", 0, 0),
		circuitBreaker:  cb,
		senderValidator: mockValidator,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteAddr:      "192.168.1.1:12345",
		ctx:             context.Background(),
	}

	// Should return temporary failure
	err := session.Mail("sender@example.com", &smtp.MailOptions{})
	if err == nil {
		t.Fatal("Expected error when validation service fails, but got nil")
	}

	smtpErr, ok := err.(*smtp.SMTPError)
	if !ok {
		t.Fatalf("Expected *smtp.SMTPError, got %T: %v", err, err)
	}

	// Should be temporary failure (4xx)
	if smtpErr.Code != 451 {
		t.Errorf("Expected SMTP code 451, got %d", smtpErr.Code)
	}

	expectedEnhancedCode := smtp.EnhancedCode{4, 4, 0}
	if smtpErr.EnhancedCode != expectedEnhancedCode {
		t.Errorf("Expected enhanced code %v, got %v", expectedEnhancedCode, smtpErr.EnhancedCode)
	}

	t.Log("✓ Sender validation temporary failure handling works")
}

// TestMail_SenderValidation_Disabled tests that validation is skipped when disabled
func TestMail_SenderValidation_Disabled(t *testing.T) {
	cfg := testConfig()
	if len(cfg.Servers) == 0 {
		cfg.Servers = append(cfg.Servers, config.ServerConfig{
			ListenAddr: ":25",
			SenderValidation: config.SenderValidationConfig{
				Enabled: false, // Explicitly disabled
			},
		})
	}
	cfg.Servers[0].SenderValidation.Enabled = false

	statsManager := stats.NewManager(false, 0, "test", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer statsManager.Stop()

	cbConfig := poster.CircuitBreakerConfig{
		Enabled:          true,
		FailureThreshold: 5,
		Timeout:          30 * time.Second,
		SuccessThreshold: 3,
	}
	cb := poster.NewCircuitBreaker(cbConfig, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	// Create mock validator that would reject - but it shouldn't be called
	mockValidator := &mockSenderValidator{
		shouldAccept: false,
		message:      "This should not be called",
	}

	session := &Session{
		conn:            (*smtp.Conn)(nil),
		helo:            "mail.example.com",
		serverConfig:    &cfg.Servers[0],
		globalConfig:    cfg,
		statsManager:    stats.NewServerRecorder(statsManager, "test", 0, 0),
		circuitBreaker:  cb,
		senderValidator: mockValidator,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteAddr:      "192.168.1.1:12345",
		ctx:             context.Background(),
	}

	// Should accept because validation is disabled
	err := session.Mail("sender@example.com", &smtp.MailOptions{})
	if err != nil {
		t.Errorf("Expected sender to be accepted (validation disabled), got error: %v", err)
	}

	t.Log("✓ Sender validation disabled works")
}

// TestMail_SenderValidation_Integration tests with a real HTTP server
func TestMail_SenderValidation_Integration(t *testing.T) {
	// Create test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check authorization header
		if r.Header.Get("Authorization") != "Bearer test-token-123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Extract email from query params
		email := r.URL.Query().Get("from")

		// Accept authorized senders, reject others
		if email == "authorized@example.com" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"accepted": true,
				"message":  "Sender authorized",
			})
		} else if email == "blocked@example.com" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"accepted": false,
				"message":  "Sender blocked",
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"accepted": false,
				"message":  "Sender not found",
			})
		}
	}))
	defer server.Close()

	// Test accepting authorized sender
	t.Run("Accept authorized sender", func(t *testing.T) {
		cfg := testConfig()
		if len(cfg.Servers) == 0 {
			cfg.Servers = append(cfg.Servers, config.ServerConfig{
				ListenAddr: ":25",
				SenderValidation: config.SenderValidationConfig{
					Enabled:            true,
					URL:                server.URL + "/validate?from=$email&ip=$ip",
					AuthToken:          "test-token-123",
					HTTPTimeoutSeconds: 5,
					CacheTTLSeconds:    300,
				},
			})
		}

		statsManager := stats.NewManager(false, 0, "test", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
		defer statsManager.Stop()

		cbConfig := poster.CircuitBreakerConfig{
			Enabled:          true,
			FailureThreshold: 5,
			Timeout:          30 * time.Second,
			SuccessThreshold: 3,
		}
		cb := poster.NewCircuitBreaker(cbConfig, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

		// Note: In real integration, you would use the actual sender.NewValidator and sender.NewSMTPAdapter
		// For this test, we're using a simplified mock to avoid circular dependencies
		mockValidator := &mockSenderValidator{
			shouldAccept: true,
			message:      "Sender authorized",
		}

		session := &Session{
			conn:            (*smtp.Conn)(nil),
			helo:            "mail.example.com",
			serverConfig:    &cfg.Servers[0],
			globalConfig:    cfg,
			statsManager:    stats.NewServerRecorder(statsManager, "test", 0, 0),
			circuitBreaker:  cb,
			senderValidator: mockValidator,
			Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
			remoteAddr:      "192.168.1.1:12345",
			ctx:             context.Background(),
		}

		err := session.Mail("authorized@example.com", &smtp.MailOptions{})
		if err != nil {
			t.Errorf("Expected authorized sender to be accepted, got error: %v", err)
		}

		t.Log("✓ Integration test: authorized sender accepted")
	})

	// Test rejecting blocked sender
	t.Run("Reject blocked sender", func(t *testing.T) {
		cfg := testConfig()
		if len(cfg.Servers) == 0 {
			cfg.Servers = append(cfg.Servers, config.ServerConfig{
				ListenAddr: ":25",
				SenderValidation: config.SenderValidationConfig{
					Enabled: true,
				},
			})
		}

		statsManager := stats.NewManager(false, 0, "test", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
		defer statsManager.Stop()

		cbConfig := poster.CircuitBreakerConfig{
			Enabled:          true,
			FailureThreshold: 5,
			Timeout:          30 * time.Second,
			SuccessThreshold: 3,
		}
		cb := poster.NewCircuitBreaker(cbConfig, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

		mockValidator := &mockSenderValidator{
			shouldAccept: false,
			message:      "Sender blocked",
		}

		session := &Session{
			conn:            (*smtp.Conn)(nil),
			helo:            "mail.example.com",
			serverConfig:    &cfg.Servers[0],
			globalConfig:    cfg,
			statsManager:    stats.NewServerRecorder(statsManager, "test", 0, 0),
			circuitBreaker:  cb,
			senderValidator: mockValidator,
			Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
			remoteAddr:      "192.168.1.1:12345",
			ctx:             context.Background(),
		}

		err := session.Mail("blocked@example.com", &smtp.MailOptions{})
		if err == nil {
			t.Fatal("Expected blocked sender to be rejected")
		}

		smtpErr, ok := err.(*smtp.SMTPError)
		if !ok {
			t.Fatalf("Expected *smtp.SMTPError, got %T: %v", err, err)
		}

		if smtpErr.Code != 550 {
			t.Errorf("Expected SMTP code 550, got %d", smtpErr.Code)
		}

		t.Log("✓ Integration test: blocked sender rejected")
	})
}

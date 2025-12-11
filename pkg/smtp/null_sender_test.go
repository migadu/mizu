package smtp

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/poster"
	"migadu/mizu/pkg/stats"

	"github.com/emersion/go-smtp"
)

func TestMail_NullSenderRejection(t *testing.T) {
	tests := []struct {
		name     string
		from     string
		errorMsg string
	}{
		{
			name:     "Empty sender string",
			from:     "",
			errorMsg: "null sender not accepted",
		},
		{
			name:     "Null sender with angle brackets",
			from:     "<>",
			errorMsg: "null sender not accepted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test session with mock connection
			cfg := testConfig()
			// Add a server config since DefaultConfig has empty Servers slice
			if len(cfg.Servers) == 0 {
				cfg.Servers = append(cfg.Servers, config.ServerConfig{
					ListenAddr: ":25",
					Junk: config.ServerJunkConfig{
						RejectNullSender: true,
					},
				})
			}
			statsManager := stats.NewManager(false, 0, "test", false, 0, nil, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
			cbConfig := poster.CircuitBreakerConfig{
				Enabled:          true,
				FailureThreshold: 5,
				Timeout:          30 * time.Second,
				SuccessThreshold: 3,
			}
			cb := poster.NewCircuitBreaker(cbConfig, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

			session := &Session{
				conn:           (*smtp.Conn)(nil),  // Set to nil, we'll bypass by setting helo directly
				helo:           "test.example.com", // Set HELO to pass that check
				serverConfig:   &cfg.Servers[0],
				globalConfig:   cfg,
				statsManager:   statsManager,
				circuitBreaker: cb,
				Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
				remoteAddr:     "192.0.2.1:12345",
			}

			// Call Mail with the test sender
			err := session.Mail(tt.from, &smtp.MailOptions{})

			if err == nil {
				t.Errorf("Expected error for sender '%s', but got nil", tt.from)
				return
			}

			// Check if it's an SMTP error with correct message
			smtpErr, ok := err.(*smtp.SMTPError)
			if !ok {
				t.Errorf("Expected *smtp.SMTPError, got %T: %v", err, err)
				return
			}

			if smtpErr.Code != 550 {
				t.Errorf("Expected SMTP code 550, got %d", smtpErr.Code)
			}

			if smtpErr.Message != tt.errorMsg {
				t.Errorf("Expected error message '%s', got '%s'", tt.errorMsg, smtpErr.Message)
			}

			expectedEnhancedCode := smtp.EnhancedCode{5, 7, 1}
			if smtpErr.EnhancedCode != expectedEnhancedCode {
				t.Errorf("Expected enhanced code %v, got %v", expectedEnhancedCode, smtpErr.EnhancedCode)
			}

			// Clean up
			statsManager.Stop()
		})
	}
}

func TestMail_NullSenderPreventsBackscatter(t *testing.T) {
	// This test verifies that we properly reject null senders to prevent backscatter spam
	// Backscatter occurs when a server accepts mail with forged sender, then tries to
	// send bounce messages to innocent parties.

	cfg := testConfig()
	// Add a server config since DefaultConfig has empty Servers slice
	if len(cfg.Servers) == 0 {
		cfg.Servers = append(cfg.Servers, config.ServerConfig{
			ListenAddr: ":25",
			Junk: config.ServerJunkConfig{
				RejectNullSender: true,
			},
		})
	}
	statsManager := stats.NewManager(false, 0, "test", false, 0, nil, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer statsManager.Stop()
	cbConfig := poster.CircuitBreakerConfig{
		Enabled:          true,
		FailureThreshold: 5,
		Timeout:          30 * time.Second,
		SuccessThreshold: 3,
	}
	cb := poster.NewCircuitBreaker(cbConfig, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	session := &Session{
		conn:           (*smtp.Conn)(nil), // Set to nil, we'll bypass by setting helo directly
		helo:           "attacker.example.com",
		serverConfig:   &cfg.Servers[0],
		globalConfig:   cfg,
		statsManager:   statsManager,
		circuitBreaker: cb,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteAddr:     "198.51.100.1:54321",
	}

	// Attempt to send with null sender (typical bounce message format)
	err := session.Mail("", &smtp.MailOptions{})

	if err == nil {
		t.Fatal("Expected null sender to be rejected to prevent backscatter, but it was accepted")
	}

	smtpErr, ok := err.(*smtp.SMTPError)
	if !ok {
		t.Fatalf("Expected *smtp.SMTPError, got %T: %v", err, err)
	}

	// Should be a permanent failure (5xx)
	if smtpErr.Code < 500 || smtpErr.Code >= 600 {
		t.Errorf("Expected permanent failure (5xx), got code %d", smtpErr.Code)
	}

	t.Logf("✓ Null sender properly rejected with: %d %s", smtpErr.Code, smtpErr.Message)
}

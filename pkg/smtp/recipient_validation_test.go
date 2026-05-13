package smtp

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"migadu/mizu/pkg/config"

	"github.com/emersion/go-smtp"
)

// mockRecipientValidator implements RecipientValidator for testing
type mockRecipientValidator struct {
	response *RecipientValidationResponse
	err      error
}

func (m *mockRecipientValidator) Validate(ctx context.Context, clientIP, from, to string) (*RecipientValidationResponse, error) {
	return m.response, m.err
}

func (m *mockRecipientValidator) ValidateWithContext(ctx context.Context, clientIP, ptr, helo, from, to string) (*RecipientValidationResponse, error) {
	return m.response, m.err
}

func (m *mockRecipientValidator) FlushCache() {}

func (m *mockRecipientValidator) GetStats() map[string]interface{} {
	return map[string]interface{}{}
}

// TestRecipientValidation_TemporaryFailure tests SMTP 450 response for temporary failures
func TestRecipientValidation_TemporaryFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create mock validator that returns temporary failure
	mockValidator := &mockRecipientValidator{
		response: &RecipientValidationResponse{
			Accepted:  false,
			Message:   "Mailbox temporarily unavailable",
			Temporary: true,
		},
		err: nil,
	}

	cfg := &config.Config{
		Local: true,
	}

	serverCfg := &config.ServerConfig{
		Name: "test-server",
		Type: "relay",
		RecipientValidation: config.RecipientValidationConfig{
			Enabled: true,
		},
	}

	// Create session directly
	session := &Session{
		serverConfig:       serverCfg,
		globalConfig:       cfg,
		recipientValidator: mockValidator,
		Logger:             logger,
		remoteAddr:         "192.168.1.1:12345",
		ctx:                context.Background(),
		commandState:       stateMail,
		from:               "sender@example.com",
		to:                 []string{},
	}

	// Try RCPT TO - should get temporary failure (450)
	err := session.Rcpt("recipient@example.com", nil)
	if err == nil {
		t.Fatal("Expected RCPT TO to fail with temporary error")
	}

	smtpErr, ok := err.(*smtp.SMTPError)
	if !ok {
		t.Fatalf("Expected *smtp.SMTPError, got %T: %v", err, err)
	}

	if smtpErr.Code != 450 {
		t.Errorf("Expected SMTP code 450, got %d", smtpErr.Code)
	}

	if smtpErr.EnhancedCode[0] != 4 {
		t.Errorf("Expected enhanced code 4.x.x, got %v", smtpErr.EnhancedCode)
	}

	if smtpErr.Message != "temporary failure, please try again later" {
		t.Errorf("Expected generic temporary message, got: %s", smtpErr.Message)
	}

	t.Log("✓ Temporary rejection returns SMTP 450 with generic message")
}

// TestRecipientValidation_PermanentFailure tests SMTP 550 response for permanent failures
func TestRecipientValidation_PermanentFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create mock validator that returns permanent failure
	mockValidator := &mockRecipientValidator{
		response: &RecipientValidationResponse{
			Accepted:  false,
			Message:   "User unknown",
			Temporary: false,
		},
		err: nil,
	}

	cfg := &config.Config{
		Local: true,
	}

	serverCfg := &config.ServerConfig{
		Name: "test-server",
		Type: "relay",
		RecipientValidation: config.RecipientValidationConfig{
			Enabled: true,
		},
	}

	// Create session directly
	session := &Session{
		serverConfig:       serverCfg,
		globalConfig:       cfg,
		recipientValidator: mockValidator,
		Logger:             logger,
		remoteAddr:         "192.168.1.1:12345",
		ctx:                context.Background(),
		commandState:       stateMail,
		from:               "sender@example.com",
		to:                 []string{},
	}

	// Try RCPT TO - should get permanent failure (550)
	err := session.Rcpt("nonexistent@example.com", nil)
	if err == nil {
		t.Fatal("Expected RCPT TO to fail with permanent error")
	}

	smtpErr, ok := err.(*smtp.SMTPError)
	if !ok {
		t.Fatalf("Expected *smtp.SMTPError, got %T: %v", err, err)
	}

	if smtpErr.Code != 550 {
		t.Errorf("Expected SMTP code 550, got %d", smtpErr.Code)
	}

	if smtpErr.EnhancedCode[0] != 5 {
		t.Errorf("Expected enhanced code 5.x.x, got %v", smtpErr.EnhancedCode)
	}

	if smtpErr.Message != "mailbox unavailable" {
		t.Errorf("Expected generic permanent message, got: %s", smtpErr.Message)
	}

	t.Log("✓ Permanent rejection returns SMTP 550 with generic message")
}

// TestRecipientValidation_Accepted tests successful recipient validation
func TestRecipientValidation_Accepted(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create mock validator that accepts the recipient
	mockValidator := &mockRecipientValidator{
		response: &RecipientValidationResponse{
			Accepted:  true,
			Message:   "Recipient accepted",
			Temporary: false,
		},
		err: nil,
	}

	cfg := &config.Config{
		Local: true,
	}

	serverCfg := &config.ServerConfig{
		Name: "test-server",
		Type: "relay",
		RecipientValidation: config.RecipientValidationConfig{
			Enabled: true,
		},
	}

	// Create session directly
	session := &Session{
		serverConfig:       serverCfg,
		globalConfig:       cfg,
		recipientValidator: mockValidator,
		Logger:             logger,
		remoteAddr:         "192.168.1.1:12345",
		ctx:                context.Background(),
		commandState:       stateMail,
		from:               "sender@example.com",
		to:                 []string{},
	}

	// Try RCPT TO - should succeed
	err := session.Rcpt("recipient@example.com", nil)
	if err != nil {
		t.Fatalf("Expected RCPT TO to succeed, got error: %v", err)
	}

	t.Log("✓ Recipient validation accepts valid recipients")
}

// TestRecipientValidation_TemporaryWithPlainText tests temporary rejection with plain text message
func TestRecipientValidation_TemporaryWithPlainText(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create mock validator with plain text message
	mockValidator := &mockRecipientValidator{
		response: &RecipientValidationResponse{
			Accepted:  false,
			Message:   "Mailbox is being migrated",
			Temporary: true,
		},
		err: nil,
	}

	cfg := &config.Config{
		Local: true,
	}

	serverCfg := &config.ServerConfig{
		Name: "test-server",
		Type: "relay",
		RecipientValidation: config.RecipientValidationConfig{
			Enabled: true,
		},
	}

	// Create session directly
	session := &Session{
		serverConfig:       serverCfg,
		globalConfig:       cfg,
		recipientValidator: mockValidator,
		Logger:             logger,
		remoteAddr:         "192.168.1.1:12345",
		ctx:                context.Background(),
		commandState:       stateMail,
		from:               "sender@example.com",
		to:                 []string{},
	}

	// Try RCPT TO - should get temporary failure with plain text message
	err := session.Rcpt("recipient@example.com", nil)
	if err == nil {
		t.Fatal("Expected RCPT TO to fail with temporary error")
	}

	smtpErr, ok := err.(*smtp.SMTPError)
	if !ok {
		t.Fatalf("Expected *smtp.SMTPError, got %T: %v", err, err)
	}

	if smtpErr.Code != 450 {
		t.Errorf("Expected SMTP code 450, got %d", smtpErr.Code)
	}

	if smtpErr.Message != "temporary failure, please try again later" {
		t.Errorf("Expected generic temporary message, got: %s", smtpErr.Message)
	}

	t.Log("✓ Temporary rejection with plain text returns generic message")
}

// TestRecipientValidation_TemporaryDefault tests temporary rejection with empty message (default)
func TestRecipientValidation_TemporaryDefault(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create mock validator with empty message (will use default)
	mockValidator := &mockRecipientValidator{
		response: &RecipientValidationResponse{
			Accepted:  false,
			Message:   "", // Empty message - should use default
			Temporary: true,
		},
		err: nil,
	}

	cfg := &config.Config{
		Local: true,
	}

	serverCfg := &config.ServerConfig{
		Name: "test-server",
		Type: "relay",
		RecipientValidation: config.RecipientValidationConfig{
			Enabled: true,
		},
	}

	// Create session directly
	session := &Session{
		serverConfig:       serverCfg,
		globalConfig:       cfg,
		recipientValidator: mockValidator,
		Logger:             logger,
		remoteAddr:         "192.168.1.1:12345",
		ctx:                context.Background(),
		commandState:       stateMail,
		from:               "sender@example.com",
		to:                 []string{},
	}

	// Try RCPT TO - should get temporary failure with default message
	err := session.Rcpt("recipient@example.com", nil)
	if err == nil {
		t.Fatal("Expected RCPT TO to fail with temporary error")
	}

	smtpErr, ok := err.(*smtp.SMTPError)
	if !ok {
		t.Fatalf("Expected *smtp.SMTPError, got %T: %v", err, err)
	}

	if smtpErr.Code != 450 {
		t.Errorf("Expected SMTP code 450, got %d", smtpErr.Code)
	}

	if smtpErr.Message != "temporary failure, please try again later" {
		t.Errorf("Expected default message, got: %s", smtpErr.Message)
	}

	t.Log("✓ Temporary rejection with empty message uses default")
}

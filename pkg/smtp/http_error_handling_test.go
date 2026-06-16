package smtp

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/emersion/go-smtp"
)

// TestHTTP413PayloadTooLarge tests that HTTP 413 errors are properly converted to SMTP 552 errors
func TestHTTP413PayloadTooLarge(t *testing.T) {
	// Create a test HTTP server that returns 413
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		io.WriteString(w, `{"error": "Message too large - 41.23MB exceeds 25MB limit", "size": 43234234, "limit": 26214400}`)
	}))
	defer server.Close()

	// Create a test SMTP session
	backend, client := createTestSMTPServer(t, server.URL)
	defer backend.Close()

	// Simulate SMTP conversation
	if err := client.Hello("test.local"); err != nil {
		t.Fatalf("EHLO failed: %v", err)
	}

	if err := client.Mail("sender@example.com", nil); err != nil {
		t.Fatalf("MAIL FROM failed: %v", err)
	}

	if err := client.Rcpt("recipient@example.com", nil); err != nil {
		t.Fatalf("RCPT TO failed: %v", err)
	}

	// Send DATA - this should fail with SMTP 552 (message too large)
	wc, err := client.Data()
	if err != nil {
		t.Fatalf("DATA command failed: %v", err)
	}

	// Send a proper RFC822 message with all required headers
	message := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Date: Mon, 23 Jun 2015 11:40:36 -0400\r\n" +
		"Message-ID: <test@example.com>\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"Test body\r\n"

	_, err = io.WriteString(wc, message)
	if err != nil {
		t.Fatalf("Writing message failed: %v", err)
	}

	err = wc.Close()
	if err == nil {
		t.Fatal("Expected DATA to fail with 552, but got success")
	}

	// Verify we got SMTP 552 error
	smtpErr, ok := err.(*smtp.SMTPError)
	if !ok {
		t.Fatalf("Expected SMTPError, got: %T: %v", err, err)
	}

	if smtpErr.Code != 552 {
		t.Errorf("Expected SMTP code 552, got: %d", smtpErr.Code)
	}

	// Verify enhanced code is 5.3.4 (message too big for system)
	expectedEnhancedCode := smtp.EnhancedCode{5, 3, 4}
	if smtpErr.EnhancedCode != expectedEnhancedCode {
		t.Errorf("Expected enhanced code %v, got: %v", expectedEnhancedCode, smtpErr.EnhancedCode)
	}

	// Verify message is the standard size rejection message
	expectedMessage := "Message size not accepted"
	if smtpErr.Message != expectedMessage {
		t.Errorf("Expected error message '%s', got: %s", expectedMessage, smtpErr.Message)
	}
}

// TestHTTP400BadRequest tests that a generic HTTP 400 delivery failure is
// returned as a temporary SMTP 451 so the sender's MTA retries (zero message loss).
func TestHTTP400BadRequest(t *testing.T) {
	// Create a test HTTP server that returns 400
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "bad request")
	}))
	defer server.Close()

	// Create a test SMTP session
	backend, client := createTestSMTPServer(t, server.URL)
	defer backend.Close()

	// Simulate SMTP conversation
	if err := client.Hello("test.local"); err != nil {
		t.Fatalf("EHLO failed: %v", err)
	}

	if err := client.Mail("sender@example.com", nil); err != nil {
		t.Fatalf("MAIL FROM failed: %v", err)
	}

	if err := client.Rcpt("recipient@example.com", nil); err != nil {
		t.Fatalf("RCPT TO failed: %v", err)
	}

	// Send DATA - this should fail with SMTP 451 (temporary failure)
	wc, err := client.Data()
	if err != nil {
		t.Fatalf("DATA command failed: %v", err)
	}

	// Send a proper RFC822 message with all required headers
	message := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Date: Mon, 23 Jun 2015 11:40:36 -0400\r\n" +
		"Message-ID: <test@example.com>\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"Test body\r\n"

	_, err = io.WriteString(wc, message)
	if err != nil {
		t.Fatalf("Writing message failed: %v", err)
	}

	err = wc.Close()
	if err == nil {
		t.Fatal("Expected DATA to fail with 451, but got success")
	}

	// Verify we got SMTP 451 error
	smtpErr, ok := err.(*smtp.SMTPError)
	if !ok {
		t.Fatalf("Expected SMTPError, got: %T: %v", err, err)
	}

	if smtpErr.Code != 451 {
		t.Errorf("Expected SMTP code 451, got: %d", smtpErr.Code)
	}
}

// createTestSMTPServer creates a test SMTP server and client for testing
func createTestSMTPServer(t *testing.T, deliveryURL string) (*smtp.Server, *smtp.Client) {
	t.Helper()

	backend := createTestBackendWithURL(t, deliveryURL)

	// Start SMTP server
	server := smtp.NewServer(backend)
	server.Domain = "test.example.com"
	server.AllowInsecureAuth = true

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	go server.Serve(ln)

	// Create SMTP client
	client, err := smtp.Dial(ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatalf("Failed to connect to SMTP server: %v", err)
	}

	return server, client
}

// createTestBackendWithURL creates a Backend with a custom delivery URL
func createTestBackendWithURL(t *testing.T, deliveryURL string) *Backend {
	t.Helper()

	backend := createTestBackend(t)
	backend.ServerConfig.Delivery.URL = deliveryURL
	// Disable local mode so that HTTP delivery actually happens
	backend.GlobalConfig.Local = false
	return backend
}

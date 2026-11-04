package smtp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"migadu/mizu/pkg/config"

	"github.com/emersion/go-smtp"
)

// A recipient mailqueuer's ingest would refuse is refused at RCPT TO with
// 553 5.1.3. Before this, `RCPT TO:<user@gmail>` (2026-10-24) was accepted and
// failed only at delivery, where mailqueuer's 422 became a 451 the client
// retried. The rule is emailutil.IsValidEmail plus no comma (ingest splits
// X-Mail-To on commas) and no address literal (553 5.1.2).

func assertRefused(t *testing.T, err error, want *smtp.SMTPError) {
	t.Helper()
	var smtpErr *smtp.SMTPError
	if !errors.As(err, &smtpErr) {
		t.Fatalf("want *smtp.SMTPError, got %T: %v", err, err)
	}
	if smtpErr.Code != want.Code || smtpErr.EnhancedCode != want.EnhancedCode || smtpErr.Message != want.Message {
		t.Fatalf("want %d %v %q, got %d %v %q", want.Code, want.EnhancedCode, want.Message,
			smtpErr.Code, smtpErr.EnhancedCode, smtpErr.Message)
	}
}

// countingRecipientValidator accepts every recipient and counts the calls.
type countingRecipientValidator struct {
	mockRecipientValidator
	calls int
}

func (c *countingRecipientValidator) ValidateWithContext(ctx context.Context, clientIP, ptr, helo, from, to string) (*RecipientValidationResponse, error) {
	c.calls++
	return &RecipientValidationResponse{Accepted: true}, nil
}

// rcptSession is a non-local session in MAIL state with recipient validation
// enabled, so a recipient that gets past the address check reaches the API.
func rcptSession(validator RecipientValidator) *Session {
	s := nonASCIISession()
	s.globalConfig = &config.Config{}
	s.serverConfig.RecipientValidation.Enabled = true
	s.recipientValidator = validator
	s.commandState = stateMail
	s.from = "sender@example.com"
	return s
}

func TestRcpt_InvalidRecipientRefused(t *testing.T) {
	for _, tc := range []struct {
		to   string
		want *smtp.SMTPError
	}{
		{"user@gmail", ErrInvalidRecipient},
		{"user@example", ErrInvalidRecipient},
		{"user@.com", ErrInvalidRecipient},
		{"user@example.com.", ErrInvalidRecipient},
		{"user@example..com", ErrInvalidRecipient},
		{"a@b@example.com", ErrInvalidRecipient},      // "a@b"@example.com
		{"john doe@example.com", ErrInvalidRecipient}, // "john doe"@example.com
		{"user@a.com,b.com", ErrInvalidRecipient},
		{"a,b@example.com", ErrInvalidRecipient},
		{",bob@example.com", ErrInvalidRecipient},
		{"x@[y@example.com", ErrInvalidRecipient}, // "x@[y"@example.com: not a literal
		{"user@[192.0.2.1]", ErrRecipientAddressLiteral},
		{"user@[IPv6:2001:db8::1]", ErrRecipientAddressLiteral},
	} {
		t.Run(tc.to, func(t *testing.T) {
			v := &countingRecipientValidator{}
			s := rcptSession(v)
			err := s.Rcpt(context.Background(), tc.to, nil)
			assertRefused(t, err, tc.want)
			if len(s.to) != 0 {
				t.Fatalf("refused recipient must not be recorded, got %v", s.to)
			}
			if s.commandState != stateMail {
				t.Fatalf("refused recipient must not advance the state, got %v", s.commandState)
			}
			if v.calls != 0 {
				t.Fatalf("refused recipient must not reach the validation API, got %d calls", v.calls)
			}
		})
	}
}

func TestRcpt_ValidRecipientAccepted(t *testing.T) {
	for _, to := range []string{
		"user@example.com",
		"user@sub.example.com",
		"first.last+tag@example.co.uk",
	} {
		t.Run(to, func(t *testing.T) {
			v := &countingRecipientValidator{}
			s := rcptSession(v)
			if err := s.Rcpt(context.Background(), to, nil); err != nil {
				t.Fatalf("valid recipient refused: %v", err)
			}
			if len(s.to) != 1 || s.to[0] != to {
				t.Fatalf("accepted recipient must be recorded, got %v", s.to)
			}
			if v.calls != 1 {
				t.Fatalf("accepted recipient must reach the validation API once, got %d calls", v.calls)
			}
		})
	}
}

// Local mode delivers nowhere, so a development address is not refused.
func TestRcpt_LocalModeSkipsAddressCheck(t *testing.T) {
	s := nonASCIISession()
	s.commandState = stateMail
	s.from = "sender@example.com"
	if err := s.Rcpt(context.Background(), "me@localhost", nil); err != nil {
		t.Fatalf("local mode refused me@localhost: %v", err)
	}
}

// Through the go-smtp parser, which strips the quotes from a quoted local
// part (the only place `"a@b"@example.com` turns into a second `@`) and
// passes an address literal through verbatim.
func TestRcpt_InvalidRecipientRefused_Wire(t *testing.T) {
	// Never reached: the test stops at RCPT TO.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	for _, tc := range []struct {
		to   string
		want *smtp.SMTPError
	}{
		{`"a@b"@example.com`, ErrInvalidRecipient},
		{`"john doe"@example.com`, ErrInvalidRecipient},
		{`"a,b"@example.com`, ErrInvalidRecipient},
		{`"x@[y"@example.com`, ErrInvalidRecipient},
		{`user@gmail`, ErrInvalidRecipient},
		{`user@[192.0.2.1]`, ErrRecipientAddressLiteral},
		{`user@[IPv6:2001:db8::1]`, ErrRecipientAddressLiteral},
	} {
		t.Run(tc.to, func(t *testing.T) {
			backend, client := createTestSMTPServer(t, server.URL)
			defer backend.Close()
			defer client.Close()

			if err := client.Hello("test.local"); err != nil {
				t.Fatalf("EHLO failed: %v", err)
			}
			if err := client.Mail("sender@example.com", nil); err != nil {
				t.Fatalf("MAIL FROM failed: %v", err)
			}
			assertRefused(t, client.Rcpt(tc.to, nil), tc.want)
		})
	}
}

// Ingest's 422 is permanent: an ingest rule the RCPT check does not mirror
// must not leave the client retrying for days.
func TestHTTP422InvalidRecipient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Invalid recipient address: "+r.Header.Get("X-Mail-To"), http.StatusUnprocessableEntity)
	}))
	defer server.Close()

	backend, client := createTestSMTPServer(t, server.URL)
	defer backend.Close()
	defer client.Close()

	if err := client.Hello("test.local"); err != nil {
		t.Fatalf("EHLO failed: %v", err)
	}
	if err := client.Mail("sender@example.com", nil); err != nil {
		t.Fatalf("MAIL FROM failed: %v", err)
	}
	if err := client.Rcpt("recipient@example.com", nil); err != nil {
		t.Fatalf("RCPT TO failed: %v", err)
	}
	wc, err := client.Data()
	if err != nil {
		t.Fatalf("DATA command failed: %v", err)
	}
	message := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Date: Mon, 23 Jun 2015 11:40:36 -0400\r\n" +
		"Message-ID: <test@example.com>\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"Test body\r\n"
	if _, err := io.WriteString(wc, message); err != nil {
		t.Fatalf("Writing message failed: %v", err)
	}
	assertRefused(t, wc.Close(), ErrInvalidRecipient)
}

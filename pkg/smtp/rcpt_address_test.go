package smtp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/emersion/go-smtp"
)

// The cases of emailutil's TestIsValidEmail plus the shapes go-smtp hands to
// Rcpt after unquoting a quoted local part.
func TestIsDeliverableAddress(t *testing.T) {
	for addr, want := range map[string]bool{
		"user@example.com":         true,
		"user+tag@sub.example.com": true,
		"üser@exämple.com":         true,
		"":                         false,
		"postmaster":               false, // no domain
		"@example.com":             false,
		"user@":                    false,
		"user@localhost":           false, // no dot
		"user@.example.com":        false,
		"user@example.com.":        false,
		"user@example..com":        false,
		"a@b@example.com":          false, // "a@b"@example.com unquoted
		"john doe@example.com":     false, // "john doe"@example.com unquoted
		"user@example.com\r\n":     false,
	} {
		if got := isDeliverableAddress(addr); got != want {
			t.Errorf("isDeliverableAddress(%q) = %v, want %v", addr, got, want)
		}
	}
}

// Such an address is refused at RCPT, for that recipient alone, before the
// command-sequence check or anything else looks at it.
func TestRcpt_RefusesAddressTheBackendWouldRefuse(t *testing.T) {
	s := &Session{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, to := range []string{"a@b@example.com", "john doe@example.com", "user@localhost", "postmaster"} {
		err := s.Rcpt(context.Background(), to, nil)
		var se *smtp.SMTPError
		if !errors.As(err, &se) || se.Code != 553 {
			t.Errorf("Rcpt(%q) = %v, want a 553", to, err)
		}
	}
	if len(s.to) != 0 {
		t.Errorf("refused recipients were added to the envelope: %v", s.to)
	}
}

package smtp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"migadu/mizu/pkg/config"

	"github.com/emersion/go-smtp"
)

// Every case of emailutil's TestIsValidEmail (services/emailutil/validate_test.go:
// a case added there belongs here too), plus the shapes go-smtp hands to Rcpt
// after unquoting a quoted local part.
func TestIsDeliverableAddress(t *testing.T) {
	for addr, want := range map[string]bool{
		// emailutil: valid
		"user+tag@example.com":   true,
		"first.last@example.com": true,
		"user@mail.example.com":  true,
		"user@example.co.uk":     true,
		"123@example.com":        true,
		"user@my-domain.com":     true,
		// emailutil: invalid
		"user":                 false,
		"user@.com":            false,
		"user@com":             false,
		"user@ example.com":    false,
		"user@example\t.com":   false,
		"user@example\n.com":   false,
		"user@@example.com":    false,
		"user@exam\x00ple.com": false,
		// the rest
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
	cfg := config.DefaultConfig()
	s := &Session{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), globalConfig: &cfg}
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

// Local mode delivers nowhere, so the backend's rule does not apply: the
// address gets past this check (and is then refused for the missing MAIL
// FROM, like any other).
func TestRcpt_LocalModeAcceptsAnyAddressShape(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Local = true
	s := &Session{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), globalConfig: &cfg, serverConfig: &config.ServerConfig{}}
	err := s.Rcpt(context.Background(), "user@localhost", nil)
	var se *smtp.SMTPError
	if errors.As(err, &se) && se.Code == 553 {
		t.Errorf("Rcpt in local mode refused the address shape: %v", err)
	}
}

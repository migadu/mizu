package smtp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/emersion/go-smtp"

	"migadu/mizu/pkg/config"
)

// C13: go-smtp's address parser accepts any byte, and the envelope is copied
// into HTTP headers on delivery (X-Mail-From / X-Rcpt-To). net/http refuses to
// send a header value holding a control byte, so the message could never be
// delivered: 451 on every retry, each one counted by the circuit breaker as a
// backend failure - five such messages opened it for every sender. No valid
// address contains these bytes; refuse them where they arrive.
func TestAudit_ControlBytesInEnvelopeAreRefused(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.DefaultConfig()
	cfg.Local = true
	sc := config.ServerConfig{Name: "t", Type: "relay", Hostname: "mx.example.com", MaxRecipientsPerMessage: 100}

	newSession := func(state int) *Session {
		return &Session{
			serverConfig: &sc, globalConfig: &cfg, Logger: logger,
			remoteAddr: "192.0.2.1", ctx: context.Background(),
			helo: "client.example.org", commandState: state, from: "sender@example.org",
		}
	}
	requireRefused := func(t *testing.T, err error) {
		t.Helper()
		var se *smtp.SMTPError
		if !errors.As(err, &se) || se.Code != 553 {
			t.Fatalf("got %v, want a 553 refusal", err)
		}
	}

	for _, addr := range []string{"a\x01b@x.test", "a@x.test\r", "a\nb@x.test", "a\x7f@x.test", "a\x00@x.test"} {
		t.Run("MAIL", func(t *testing.T) {
			s := newSession(stateHelo)
			requireRefused(t, s.Mail(context.Background(), addr, nil))
			if s.from == addr {
				t.Fatal("the address was stored on the session")
			}
		})
		t.Run("RCPT", func(t *testing.T) {
			s := newSession(stateMail)
			requireRefused(t, s.Rcpt(context.Background(), addr, nil))
			if len(s.to) != 0 {
				t.Fatal("the address was added to the envelope")
			}
		})
	}

	// Non-ASCII (SMTPUTF8) local parts are not control bytes.
	s := newSession(stateMail)
	if err := s.Rcpt(context.Background(), "jos\xc3\xa9@example.net", nil); err != nil {
		var se *smtp.SMTPError
		if errors.As(err, &se) && se.Code == 553 {
			t.Fatalf("UTF-8 address refused as a control byte: %v", err)
		}
	}
}

// Mailqueuer splits X-Mail-To on commas, and its address check does not refuse
// one. A single `RCPT TO:<a@x.test,b@y.test>` therefore counted as one
// recipient here - one RCPT rate-limit charge, one slot of
// max_recipients_per_message, one validation lookup - and was delivered to
// two mailboxes there. A comma is not valid in an unquoted address, and no
// address worth supporting has a quoted one.
func TestAudit_CommaInRecipientIsRefused(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.DefaultConfig()
	cfg.Local = true
	sc := config.ServerConfig{Name: "t", Type: "relay", Hostname: "mx.example.com", MaxRecipientsPerMessage: 100}

	for _, to := range []string{"a@x.test,b@y.test", "a,b@x.test", "a@x.test,"} {
		s := &Session{
			serverConfig: &sc, globalConfig: &cfg, Logger: logger,
			remoteAddr: "192.0.2.1", ctx: context.Background(),
			helo: "client.example.org", commandState: stateMail, from: "sender@example.org",
		}
		err := s.Rcpt(context.Background(), to, nil)
		var se *smtp.SMTPError
		if !errors.As(err, &se) || se.Code != 553 {
			t.Errorf("RCPT TO:<%s>: got %v, want a 553 refusal", to, err)
		}
		if len(s.to) != 0 {
			t.Errorf("RCPT TO:<%s>: added to the envelope", to)
		}
	}
}

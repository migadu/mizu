package smtp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"migadu/mizu/pkg/config"

	"github.com/emersion/go-smtp"
)

// A 422 is the backend refusing a request it can never accept (mailqueuer: a
// recipient address it considers malformed, an empty message). It was
// answered 451, so the sending MTA retried until its queue expired - and with
// one request for all recipients, every recipient of the message waited that
// long for nothing.
func TestAudit_Delivery422IsPermanent(t *testing.T) {
	requests := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "Invalid recipient address: a@b@example.com", http.StatusUnprocessableEntity)
	}))
	defer backend.Close()

	off := false
	cfg := config.DefaultConfig()
	sc := config.ServerConfig{Name: "t", Type: "relay", Hostname: "mx.example.com", EnableEnvelopeToHeader: &off}
	sc.Delivery.URL = backend.URL
	sc.Delivery.MaxRetryAttempts = 3
	s := &Session{
		ctx: context.Background(), serverConfig: &sc, globalConfig: &cfg,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteAddr: "192.0.2.1", from: "x@sender.example",
		to:         []string{"good@example.com", "a@b@example.com"},
		httpClient: backend.Client(),
	}

	err := s.deliverSynchronous(context.Background(), "Subject: x\r\n\r\nbody\r\n")
	var se *smtp.SMTPError
	if !errors.As(err, &se) || se.Code != 554 {
		t.Fatalf("got %v, want a permanent 554", err)
	}
	if requests != 1 {
		t.Errorf("a 422 must not be retried: %d requests", requests)
	}
}

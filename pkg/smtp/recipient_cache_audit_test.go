package smtp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"migadu/mizu/pkg/config"

	"github.com/emersion/go-smtp"
)

// Audit B15 (docs/security-audit-todo.md): a delivery 403 means "this
// delivery is not authorized" - in this system, a recipient blocking a sender.
// It used to be cached under the recipient alone and gossiped, so one blocked
// sender made every other sender's mail to that recipient bounce with a
// permanent 550 for the cache TTL, cluster-wide. A recipient who blocks one
// sender expects everyone else's mail to keep arriving.
func TestAudit_Delivery403DoesNotBlockOtherSenders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Mail-From") == "blocked@sender.example" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dt := NewDistributedTracker(NewConnectionTracker(100, 10, 0, nil), nil, "", "",
		DistributedConfig{
			Hostname:          "server1",
			Cluster:           newMockCluster(),
			GossipInterval:    time.Hour,
			S3SyncInterval:    time.Hour,
			GlobalMaxPerIP:    20,
			RecipientCacheTTL: 5 * time.Minute,
		}, logger)
	defer dt.Stop()

	cfg := config.DefaultConfig()
	sc := config.ServerConfig{Name: "t", Type: "relay", Hostname: "mx.example.com"}
	sc.Delivery.URL = backend.URL
	sc.Delivery.MaxRetryAttempts = 1

	newSession := func(from string) *Session {
		return &Session{
			ctx:          context.Background(),
			serverConfig: &sc,
			globalConfig: &cfg,
			Logger:       logger,
			remoteAddr:   "192.0.2.1",
			from:         from,
			distTracker:  dt,
			httpClient:   backend.Client(),
		}
	}
	const msg = "From: x@sender.example\r\nSubject: x\r\n\r\nbody\r\n"
	const rcpt = "victim@example.com"

	err := newSession("blocked@sender.example").deliverToRecipient(context.Background(), msg, rcpt)
	se, ok := err.(*smtp.SMTPError)
	if !ok || se.Code != 550 {
		t.Fatalf("blocked sender: got %v, want a 550", err)
	}

	if err := newSession("friend@other.example").deliverToRecipient(context.Background(), msg, rcpt); err != nil {
		t.Fatalf("another sender to the same recipient must still be delivered, got: %v", err)
	}

	// And nothing about the 403 may be gossiped to peers.
	if snap := dt.createSnapshot(); snap.RecipientCache != nil {
		t.Fatalf("a delivery 403 must not enter the gossiped recipient cache: %+v", snap.RecipientCache)
	}
}

// A delivery 403 (the recipient refuses this sender) used to be permanent only
// on servers with the recipient cache enabled - a leftover from when the 403
// was cached. Elsewhere it was a 451, so the sending MTA retried for days
// something that cannot succeed. The verdict does not depend on a cache.
func TestAudit_Delivery403IsPermanentWithoutRecipientCache(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer backend.Close()

	cfg := config.DefaultConfig()
	sc := config.ServerConfig{Name: "t", Type: "relay", Hostname: "mx.example.com"}
	sc.Delivery.URL = backend.URL
	sc.Delivery.MaxRetryAttempts = 1
	s := &Session{
		ctx: context.Background(), serverConfig: &sc, globalConfig: &cfg,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteAddr: "192.0.2.1", from: "blocked@sender.example",
		httpClient: backend.Client(), // no distTracker
	}

	err := s.deliverToRecipient(context.Background(), "Subject: x\r\n\r\nbody\r\n", "rcpt@example.com")
	var se *smtp.SMTPError
	if !errors.As(err, &se) || se.Code != 550 {
		t.Fatalf("got %v, want a permanent 550", err)
	}
}

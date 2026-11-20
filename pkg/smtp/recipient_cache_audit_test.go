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

	err := deliverTo(newSession("blocked@sender.example"), msg, rcpt)
	se, ok := err.(*smtp.SMTPError)
	if !ok || se.Code != 550 {
		t.Fatalf("blocked sender: got %v, want a 550", err)
	}

	if err := deliverTo(newSession("friend@other.example"), msg, rcpt); err != nil {
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

	err := deliverTo(s, "Subject: x\r\n\r\nbody\r\n", "rcpt@example.com")
	var se *smtp.SMTPError
	if !errors.As(err, &se) || se.Code != 550 {
		t.Fatalf("got %v, want a permanent 550", err)
	}
}

// deliverTo delivers msg to a single recipient through the session.
func deliverTo(s *Session, msg, rcpt string) error {
	s.to = []string{rcpt}
	return s.deliverSynchronous(context.Background(), msg)
}

// With one request for all recipients, a 404 is a verdict on the request. It
// may be cached against a recipient only when there was exactly one: caching
// it against every recipient of a multi-recipient message would refuse mail
// to mailboxes that exist.
func TestAudit_Delivery404IsCachedOnlyForASingleRecipient(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer backend.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dt := NewDistributedTracker(NewConnectionTracker(100, 10, 0, nil), nil, "", "",
		DistributedConfig{
			Hostname: "server1", Cluster: newMockCluster(),
			GossipInterval: time.Hour, S3SyncInterval: time.Hour,
			GlobalMaxPerIP: 20, RecipientCacheTTL: 5 * time.Minute,
		}, logger)
	defer dt.Stop()

	cfg := config.DefaultConfig()
	sc := config.ServerConfig{Name: "t", Type: "relay", Hostname: "mx.example.com"}
	sc.Delivery.URL = backend.URL
	sc.Delivery.MaxRetryAttempts = 1
	off := false
	sc.EnableEnvelopeToHeader = &off // one request for all recipients
	newSession := func(to ...string) *Session {
		return &Session{
			ctx: context.Background(), serverConfig: &sc, globalConfig: &cfg, Logger: logger,
			remoteAddr: "192.0.2.1", from: "a@sender.example", to: to,
			distTracker: dt, httpClient: backend.Client(),
		}
	}
	const msg = "Subject: x\r\n\r\nbody\r\n"

	err := newSession("a@example.com", "b@example.com").deliverSynchronous(context.Background(), msg)
	var se *smtp.SMTPError
	if !errors.As(err, &se) || se.Code != 550 {
		t.Fatalf("multi-recipient 404: got %v, want 550", err)
	}
	if dt.IsRecipientCached("a@example.com") || dt.IsRecipientCached("b@example.com") {
		t.Fatal("a 404 for a multi-recipient request was cached against a recipient")
	}

	if err := newSession("gone@example.com").deliverSynchronous(context.Background(), msg); err == nil {
		t.Fatal("single-recipient 404 must fail")
	}
	if !dt.IsRecipientCached("gone@example.com") {
		t.Fatal("a 404 for a single recipient should be cached")
	}
}

package smtp

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"migadu/mizu/pkg/config"
)

// enable_envelope_to_header decides whether the delivered copy carries Mizu's
// X-Envelope-To. A sender-supplied one never reaches the backend either way:
// with the toggle off the backend adds the header unless one is present, so a
// forged one left in place would stand as the envelope recipient.
func TestDeliver_EnvelopeToToggle(t *testing.T) {
	const msg = "X-Envelope-To: forged@evil.example\r\nFrom: x@sender.example\r\nSubject: x\r\n\r\nbody\r\n"
	const rcpt = "rcpt@example.com"
	off := false

	tests := []struct {
		name   string
		toggle *bool
		want   string
	}{
		{"default adds it", nil, "X-Envelope-To: rcpt@example.com\r\nFrom: x@sender.example\r\nSubject: x\r\n\r\nbody\r\n"},
		{"off strips and adds none", &off, "From: x@sender.example\r\nSubject: x\r\n\r\nbody\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				got = string(b)
				w.WriteHeader(http.StatusOK)
			}))
			defer backend.Close()

			cfg := config.DefaultConfig()
			sc := config.ServerConfig{Name: "t", Type: "relay", Hostname: "mx.example.com"}
			sc.Delivery.URL = backend.URL
			sc.Delivery.MaxRetryAttempts = 1
			sc.EnableEnvelopeToHeader = tt.toggle

			s := &Session{
				ctx:          context.Background(),
				serverConfig: &sc,
				globalConfig: &cfg,
				Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
				remoteAddr:   "192.0.2.1",
				from:         "x@sender.example",
				httpClient:   backend.Client(),
			}
			if err := deliverTo(s, msg, rcpt); err != nil {
				t.Fatalf("deliver: %v", err)
			}
			if got != tt.want {
				t.Errorf("delivered message:\n got %q\nwant %q", got, tt.want)
			}
			if n := strings.Count(got, "forged@evil.example"); n != 0 {
				t.Errorf("sender-supplied X-Envelope-To reached the backend")
			}
		})
	}
}

// With enable_envelope_to_header off, a message with several recipients is
// handed over in ONE request carrying all of them.
//
// With a request per recipient (the default, needed for Mizu to stamp the
// header), SMTP's single reply to DATA means a failure on the third recipient
// makes the sender retry all three - a duplicate for the first two - or
// bounces a message two recipients already have. One request is
// all-or-nothing as far as the sender can tell.
func TestDeliver_SingleRequestForAllRecipients(t *testing.T) {
	type post struct{ to, body string }
	var posts []post
	status := http.StatusOK
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		posts = append(posts, post{r.Header.Get("X-Mail-To"), string(b)})
		w.WriteHeader(status)
	}))
	defer backend.Close()

	cfg := config.DefaultConfig()
	off := false
	sc := config.ServerConfig{Name: "t", Type: "relay", Hostname: "mx.example.com", EnableEnvelopeToHeader: &off}
	sc.Delivery.URL = backend.URL
	sc.Delivery.MaxRetryAttempts = 1
	newSession := func() *Session {
		return &Session{
			ctx: context.Background(), serverConfig: &sc, globalConfig: &cfg,
			Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
			remoteAddr: "192.0.2.1", from: "x@sender.example", httpClient: backend.Client(),
			to: []string{"bob@example.com", "charlie@example.com", "dave@example.com"},
		}
	}
	const msg = "X-Envelope-To: forged@evil.example\r\nFrom: x@sender.example\r\nSubject: x\r\n\r\nbody\r\n"

	if err := newSession().deliverSynchronous(context.Background(), msg); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if len(posts) != 1 {
		t.Fatalf("got %d requests, want 1", len(posts))
	}
	if want := "bob@example.com,charlie@example.com,dave@example.com"; posts[0].to != want {
		t.Errorf("X-Mail-To = %q, want %q", posts[0].to, want)
	}
	// The body is shared, so it carries no per-recipient header - and not
	// the sender's forged one either.
	if want := "From: x@sender.example\r\nSubject: x\r\n\r\nbody\r\n"; posts[0].body != want {
		t.Errorf("body = %q, want %q", posts[0].body, want)
	}

	// A refused hand-off is one failed request: nobody is delivered on their own.
	posts, status = nil, http.StatusServiceUnavailable
	if err := newSession().deliverSynchronous(context.Background(), msg); err == nil {
		t.Fatal("delivery succeeded although the backend answered 503")
	}
	if len(posts) != 1 {
		t.Fatalf("got %d requests on failure, want 1", len(posts))
	}
}

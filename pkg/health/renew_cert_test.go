package health

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeRenewer struct {
	delay   time.Duration
	renewed []string
	err     error

	mu        sync.Mutex
	keyTypes  []string // what the handler asked for
	cancelled bool     // the handler passed a context that was cancelled
}

func (f *fakeRenewer) askedFor() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.keyTypes
}

func (f *fakeRenewer) gaveUp() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cancelled
}

func (f *fakeRenewer) RenewCertificate(ctx context.Context, _ string, keyTypes ...string) ([]string, error) {
	f.mu.Lock()
	f.keyTypes = keyTypes
	f.mu.Unlock()

	select {
	case <-time.After(f.delay):
	case <-ctx.Done():
		f.mu.Lock()
		f.cancelled = true
		f.mu.Unlock()
		return nil, ctx.Err()
	}
	return f.renewed, f.err
}

func renewCertServer(t *testing.T, renewer CertRenewer, writeTimeout time.Duration) *httptest.Server {
	t.Helper()
	return renewCertServerWithTimeouts(t, renewer, writeTimeout, time.Minute)
}

func renewCertServerWithTimeouts(t *testing.T, renewer CertRenewer, writeTimeout, readTimeout time.Duration) *httptest.Server {
	t.Helper()
	s := NewServer("127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetCertRenewer(renewer)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(s.renewCertHandler))
	srv.Config.WriteTimeout = writeTimeout
	srv.Config.ReadTimeout = readTimeout
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func postRenew(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(`{"domain":"mx.example.com"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp.StatusCode, body
}

// The renewal is answered only once the CA has, which takes longer than the
// server's WriteTimeout. Without the extended deadline the reply is cut off.
func TestRenewCertHandlerOutlastsWriteTimeout(t *testing.T) {
	renewer := &fakeRenewer{delay: 600 * time.Millisecond, renewed: []string{"mx.example.com (ecdsa)"}}
	srv := renewCertServer(t, renewer, 100*time.Millisecond)

	status, body := postRenew(t, srv.URL)
	if status != http.StatusOK || body["status"] != "success" {
		t.Errorf("status = %d, body = %v; want 200 success", status, body)
	}
}

func TestRenewCertHandlerReportsPartialAndFailedRenewals(t *testing.T) {
	partial := &fakeRenewer{renewed: []string{"mx.example.com (ecdsa)"}, err: errors.New("rsa: rate limited")}
	status, body := postRenew(t, renewCertServer(t, partial, time.Second).URL)
	if status != http.StatusOK || body["status"] != "partial" || body["error"] != "rsa: rate limited" {
		t.Errorf("partial renewal: status = %d, body = %v", status, body)
	}

	failed := &fakeRenewer{err: errors.New("rate limited")}
	status, body = postRenew(t, renewCertServer(t, failed, time.Second).URL)
	if status != http.StatusInternalServerError || body["status"] != "error" {
		t.Errorf("failed renewal: status = %d, body = %v", status, body)
	}
}

// F8: the operator has to be able to retry the key type that failed without
// re-ordering the one that succeeded, so the endpoint carries the selection.
func TestRenewCertHandlerPassesKeyTypeThrough(t *testing.T) {
	renewer := &fakeRenewer{renewed: []string{"mx.example.com (rsa)"}}
	srv := renewCertServer(t, renewer, time.Second)

	resp, err := http.Post(srv.URL, "application/json",
		strings.NewReader(`{"domain":"mx.example.com","key_type":"rsa"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()

	if asked := renewer.askedFor(); len(asked) != 1 || asked[0] != "rsa" {
		t.Errorf("renewer asked for %v, want [rsa]", asked)
	}
}

// With no selection it stays "both", which is what an unqualified renewal means.
func TestRenewCertHandlerDefaultsToEveryKeyType(t *testing.T) {
	renewer := &fakeRenewer{renewed: []string{"mx.example.com (ecdsa)", "mx.example.com (rsa)"}}
	srv := renewCertServer(t, renewer, time.Second)

	if _, body := postRenew(t, srv.URL); body["status"] != "success" {
		t.Fatalf("renewal failed: %v", body)
	}
	if asked := renewer.askedFor(); len(asked) != 0 {
		t.Errorf("renewer asked for %v, want every key type", asked)
	}
}

// A client that hangs up must stop the work it asked for: renew-cert blocks for
// as long as the CA takes, and an operator who gives up and re-runs it would
// otherwise have two orders running for the same certificates.
func TestRenewCertHandlerStopsWhenTheClientHangsUp(t *testing.T) {
	renewer := &fakeRenewer{delay: 30 * time.Second, renewed: []string{"mx.example.com (ecdsa)"}}
	srv := renewCertServer(t, renewer, time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL,
		strings.NewReader(`{"domain":"mx.example.com"}`))
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !renewer.gaveUp() {
		time.Sleep(20 * time.Millisecond)
	}
	if !renewer.gaveUp() {
		t.Error("the renewal carried on after the client hung up")
	}
}

// Finding 2: the health server sets ReadTimeout, which net/http applies to the
// whole request. For a POST with no body - the documented query-string form -
// it starts a background read that trips at the deadline and cancels the
// request context. The renewal would then abandon itself part-way and report a
// certificate the CA had already issued as a failure. Extending the write
// deadline alone is not enough.
func TestRenewCertHandlerOutlastsReadTimeout(t *testing.T) {
	renewer := &fakeRenewer{delay: 900 * time.Millisecond, renewed: []string{"mx.example.com (ecdsa)"}}
	srv := renewCertServerWithTimeouts(t, renewer, time.Minute, 250*time.Millisecond)

	resp, err := http.Post(srv.URL+"/api/renew-cert?domain=mx.example.com", "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "success" {
		t.Errorf("status = %v, want success (the read deadline cut the renewal short)", body)
	}
	if renewer.gaveUp() {
		t.Error("the renewal was cancelled by the server's own read timeout")
	}
}

// Finding 9: key_type is read from the query and then from the body. Taking both
// asks for the same key type twice, which is two orders for one certificate.
func TestRenewCertHandlerDoesNotDoubleUpKeyType(t *testing.T) {
	renewer := &fakeRenewer{renewed: []string{"mx.example.com (rsa)"}}
	srv := renewCertServer(t, renewer, time.Minute)

	resp, err := http.Post(srv.URL+"?key_type=rsa", "application/json",
		strings.NewReader(`{"domain":"mx.example.com","key_type":"rsa"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()

	if asked := renewer.askedFor(); len(asked) != 1 {
		t.Errorf("renewer asked for %v, want one key type", asked)
	}
}

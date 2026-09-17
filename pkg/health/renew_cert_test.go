package health

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeRenewer struct {
	delay   time.Duration
	renewed []string
	err     error
}

func (f *fakeRenewer) RenewCertificate(string) ([]string, error) {
	time.Sleep(f.delay)
	return f.renewed, f.err
}

func renewCertServer(t *testing.T, renewer CertRenewer, writeTimeout time.Duration) *httptest.Server {
	t.Helper()
	s := NewServer("127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetCertRenewer(renewer)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(s.renewCertHandler))
	srv.Config.WriteTimeout = writeTimeout
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

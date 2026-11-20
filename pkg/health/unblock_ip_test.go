package health

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"log/slog"
)

type mockUnblocker struct {
	removed bool
	lastIP  string
}

func (m *mockUnblocker) RemoveIP(ip string) bool {
	m.lastIP = ip
	return m.removed
}

func TestUnblockIPHandler_Success(t *testing.T) {
	s := NewServer(":0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetHealthEnabled(true)
	ub := &mockUnblocker{removed: true}
	s.AddIPUnblocker(ub)

	body := strings.NewReader(`{"ip": "1.2.3.4"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/unblock-ip", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.unblockIPHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ub.lastIP != "1.2.3.4" {
		t.Errorf("expected IP 1.2.3.4, got %s", ub.lastIP)
	}
	if !strings.Contains(w.Body.String(), `"removed":true`) {
		t.Errorf("expected removed:true in response, got %s", w.Body.String())
	}
}

func TestUnblockIPHandler_NotTracked(t *testing.T) {
	s := NewServer(":0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetHealthEnabled(true)
	ub := &mockUnblocker{removed: false}
	s.AddIPUnblocker(ub)

	body := strings.NewReader(`{"ip": "5.6.7.8"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/unblock-ip", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.unblockIPHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"removed":false`) {
		t.Errorf("expected removed:false in response, got %s", w.Body.String())
	}
}

func TestUnblockIPHandler_InvalidIP(t *testing.T) {
	s := NewServer(":0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetHealthEnabled(true)
	s.AddIPUnblocker(&mockUnblocker{})

	body := strings.NewReader(`{"ip": "not-an-ip"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/unblock-ip", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.unblockIPHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestUnblockIPHandler_MalformedBody(t *testing.T) {
	s := NewServer(":0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetHealthEnabled(true)
	s.AddIPUnblocker(&mockUnblocker{})

	body := strings.NewReader(`{not json}`)
	req := httptest.NewRequest(http.MethodPost, "/api/unblock-ip", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.unblockIPHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "malformed") {
		t.Errorf("expected malformed error message, got %s", w.Body.String())
	}
}

func TestUnblockIPHandler_EmptyBody(t *testing.T) {
	s := NewServer(":0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetHealthEnabled(true)
	s.AddIPUnblocker(&mockUnblocker{})

	req := httptest.NewRequest(http.MethodPost, "/api/unblock-ip", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.unblockIPHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "valid ip or CIDR parameter is required") {
		t.Errorf("expected 'valid ip or CIDR parameter is required', got %s", w.Body.String())
	}
}

// TestUnblockIPHandler_CIDR: CIDR notation is accepted and passed through to
// the unblocker (which lifts a subnet block in the auth rate limiter).
func TestUnblockIPHandler_CIDR(t *testing.T) {
	s := NewServer(":0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetHealthEnabled(true)
	ub := &mockUnblocker{removed: true}
	s.AddIPUnblocker(ub)

	req := httptest.NewRequest(http.MethodPost, "/api/unblock-ip?ip=203.0.113.0/24", nil)
	w := httptest.NewRecorder()

	s.unblockIPHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if ub.lastIP != "203.0.113.0/24" {
		t.Errorf("expected CIDR passed through to unblocker, got %q", ub.lastIP)
	}
}

// TestUnblockIPHandler_BadCIDR: garbage with a slash is still refused.
func TestUnblockIPHandler_BadCIDR(t *testing.T) {
	s := NewServer(":0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetHealthEnabled(true)
	s.AddIPUnblocker(&mockUnblocker{})

	req := httptest.NewRequest(http.MethodPost, "/api/unblock-ip?ip=garbage/24", nil)
	w := httptest.NewRecorder()

	s.unblockIPHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestUnblockIPHandler_QueryParam(t *testing.T) {
	s := NewServer(":0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetHealthEnabled(true)
	ub := &mockUnblocker{removed: true}
	s.AddIPUnblocker(ub)

	req := httptest.NewRequest(http.MethodPost, "/api/unblock-ip?ip=10.0.0.1", nil)
	w := httptest.NewRecorder()

	s.unblockIPHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ub.lastIP != "10.0.0.1" {
		t.Errorf("expected IP 10.0.0.1, got %s", ub.lastIP)
	}
}

func TestUnblockIPHandler_MethodNotAllowed(t *testing.T) {
	s := NewServer(":0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetHealthEnabled(true)
	s.AddIPUnblocker(&mockUnblocker{})

	req := httptest.NewRequest(http.MethodGet, "/api/unblock-ip?ip=1.2.3.4", nil)
	w := httptest.NewRecorder()

	s.unblockIPHandler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestUnblockIPHandler_NilUnblocker(t *testing.T) {
	s := NewServer(":0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetHealthEnabled(true)
	// Don't set unblocker

	body := strings.NewReader(`{"ip": "1.2.3.4"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/unblock-ip", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.unblockIPHandler(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", w.Code)
	}
}

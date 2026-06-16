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
	s.SetIPUnblocker(ub)

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
	s.SetIPUnblocker(ub)

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
	s.SetIPUnblocker(&mockUnblocker{})

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
	s.SetIPUnblocker(&mockUnblocker{})

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
	s.SetIPUnblocker(&mockUnblocker{})

	req := httptest.NewRequest(http.MethodPost, "/api/unblock-ip", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.unblockIPHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "valid ip parameter is required") {
		t.Errorf("expected 'valid ip parameter is required', got %s", w.Body.String())
	}
}

func TestUnblockIPHandler_QueryParam(t *testing.T) {
	s := NewServer(":0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetHealthEnabled(true)
	ub := &mockUnblocker{removed: true}
	s.SetIPUnblocker(ub)

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
	s.SetIPUnblocker(&mockUnblocker{})

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

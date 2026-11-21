package health

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type auditChecker struct{ name string }

func (c auditChecker) Name() string                 { return c.name }
func (c auditChecker) CheckHealth() ComponentStatus { return ComponentStatus{Status: "healthy"} }

type auditFlusher struct {
	name  string
	calls *int
}

func (f auditFlusher) FlushCache() map[string]int {
	*f.calls++
	return map[string]int{f.name: 1}
}

type auditUnblocker struct{}

func (auditUnblocker) RemoveIP(string) bool { return false }

// C18: the server is started first and components are registered afterwards
// (per-server trackers and limiters exist only later), with no
// synchronisation: a /health poll during startup read the checker slice while
// it was being appended to. Run with -race.
func TestAudit_RegistrationAfterStartIsSafe(t *testing.T) {
	s := NewServer("127.0.0.1:0", nil)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			s.AddChecker(auditChecker{name: fmt.Sprintf("c%d", i)})
			s.AddIPUnblocker(auditUnblocker{})
			s.AddCacheFlusher(auditFlusher{name: "f", calls: new(int)})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			s.healthHandler(httptest.NewRecorder(), httptest.NewRequest("GET", "/health", nil))
			s.unblockIPHandler(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/unblock-ip?ip=192.0.2.1", nil))
		}
	}()
	wg.Wait()
}

// C17: /api/flush-cache answered 501 on every deployment, because the only
// SetCacheFlusher call ran with a nil tracker before any server existed.
// Flushers are now added per server, and a flush reaches all of them.
func TestAudit_FlushCacheReachesEveryRegisteredFlusher(t *testing.T) {
	s := NewServer("127.0.0.1:0", nil)
	var a, b int
	s.AddCacheFlusher(auditFlusher{name: "in", calls: &a})
	s.AddCacheFlusher(auditFlusher{name: "out", calls: &b})

	w := httptest.NewRecorder()
	s.flushCacheHandler(w, httptest.NewRequest("POST", "/api/flush-cache", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body.String())
	}
	if a != 1 || b != 1 {
		t.Fatalf("flushers called %d and %d times, want once each", a, b)
	}
}

// The ACME route was only registered if the handler was set before Start, and
// main sets it after: the call was dead.
func TestAudit_ACMEHandlerSetAfterStartIsServed(t *testing.T) {
	s := NewServer("127.0.0.1:0", nil)
	s.Start()
	defer s.Stop(context.Background())

	s.SetACMEHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest("GET", "/.well-known/acme-challenge/token", nil))
	if w.Code != http.StatusTeapot {
		t.Fatalf("status %d, want the ACME handler's reply", w.Code)
	}
}

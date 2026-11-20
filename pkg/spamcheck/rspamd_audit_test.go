package spamcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Audit A1 (docs/security-audit-todo.md): envelope values are copied into
// rspamd request headers. net/http refuses to send a request whose header
// value holds a control byte, the scan then errors, and the session fails
// open - so one \x7f in EHLO used to deliver a message with no scan at all.
// The client must never let an envelope value abort the request.
func TestClient_Check_ControlBytesInEnvelopeDoNotAbortScan(t *testing.T) {
	cases := map[string]struct{ helo, from, rcpt, user string }{
		"helo DEL":  {helo: "mail.evil.test\x7f", from: "a@b.test", rcpt: "c@d.test"},
		"helo SOH":  {helo: "mail.evil.test\x01", from: "a@b.test", rcpt: "c@d.test"},
		"from ctl":  {helo: "mail.evil.test", from: "a\x02@b.test", rcpt: "c@d.test"},
		"rcpt ctl":  {helo: "mail.evil.test", from: "a@b.test", rcpt: "c\x1f@d.test"},
		"user ctl":  {helo: "mail.evil.test", from: "a@b.test", rcpt: "c@d.test", user: "u\x03@b.test"},
		"helo CRLF": {helo: "mail.evil.test\r\nX-Injected: 1", from: "a@b.test", rcpt: "c@d.test"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			var hits int
			var got http.Header
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				hits++
				got = r.Header.Clone()
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"action":"reject","score":20,"required_score":15,"symbols":{}}`))
			}))
			defer server.Close()

			client := NewClient(server.URL, "", 5*time.Second, nil)
			result, err := client.Check(context.Background(), "trace", "Subject: x\r\n\r\nbody\r\n",
				"192.0.2.1", tc.from, []string{tc.rcpt}, tc.helo, tc.user)
			if err != nil {
				t.Fatalf("scan must not be aborted by the envelope: %v", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if hits != 1 {
				t.Fatalf("rspamd received %d requests, want 1", hits)
			}
			if result.Action != "reject" {
				t.Fatalf("action = %q, want the server's verdict %q", result.Action, "reject")
			}
			if got.Get("X-Injected") != "" {
				t.Fatal("a CRLF in an envelope value must not create a request header")
			}
			if got.Get("Helo") == "" {
				t.Fatal("Helo header must still be sent, minus the illegal bytes")
			}
		})
	}
}

package spamcheck

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// C4: the reply was read through a 1 MiB LimitReader. A longer reply - rspamd
// echoes every URL and address it found - was cut off silently, failed to
// parse, and the session failed open: a message stuffed with URLs was
// delivered without its "reject" verdict.
func TestAudit_LargeRspamdReplyKeepsItsVerdict(t *testing.T) {
	var urls strings.Builder
	for i := 0; i < 12000; i++ {
		fmt.Fprintf(&urls, `"http://host-%06d.%s.example/",`, i, strings.Repeat("a", 180))
	}
	reply := `{"urls":[` + strings.TrimSuffix(urls.String(), ",") +
		`],"action":"reject","score":20,"required_score":15,"symbols":{}}`
	if len(reply) < 2<<20 {
		t.Fatalf("test reply is only %d bytes", len(reply))
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(reply))
	}))
	defer server.Close()

	client := NewClient(server.URL, "", 5*time.Second, nil)
	result, err := client.Check(context.Background(), "trace", "Subject: x\r\n\r\nbody\r\n",
		"192.0.2.1", "a@b.test", []string{"c@d.test"}, "mail.b.test", "")
	if err != nil {
		t.Fatalf("a %d byte reply must still be parsed: %v", len(reply), err)
	}
	if result.Action != "reject" {
		t.Fatalf("action = %q, want %q", result.Action, "reject")
	}
}

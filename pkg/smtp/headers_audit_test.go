package smtp

import (
	"strings"
	"testing"
)

// Audit B13 (docs/security-audit-todo.md): modifySubject scanned the whole
// message, not just the header block. A junk message with no Subject header
// and a body line starting "Subject:" got the tag written into its body and
// reached the recipient with no tagged Subject at all.
func TestAudit_ModifySubjectNeverTouchesTheBody(t *testing.T) {
	raw := "From: a@example.com\r\nTo: b@example.com\r\n\r\nhello\r\nSubject: in body\r\nbye\r\n"
	got := modifySubject(raw, "[spam] %s")

	head, body, ok := strings.Cut(got, "\r\n\r\n")
	if !ok {
		t.Fatalf("header/body separator lost: %q", got)
	}
	if body != "hello\r\nSubject: in body\r\nbye\r\n" {
		t.Errorf("body was modified: %q", body)
	}
	if !strings.Contains(head, "Subject: [spam]") {
		t.Errorf("a message without a Subject header must get a tagged one; headers: %q", head)
	}
}

func TestAudit_ModifySubjectStillTagsHeader(t *testing.T) {
	raw := "From: a@example.com\r\nSubject: Hello\r\n there\r\nTo: b@example.com\r\n\r\nSubject: in body\r\n"
	got := modifySubject(raw, "[spam] %s")
	want := "From: a@example.com\r\nSubject: [spam] Hello there\r\nTo: b@example.com\r\n\r\nSubject: in body\r\n"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

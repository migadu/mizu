package smtp

import (
	"runtime"
	"strings"
	"testing"
)

// C2: the header helpers split the whole message - body included - into lines.
// A body of bare newlines (2 bytes per line after CRLF normalisation, 16 bytes
// per slice element) made each helper allocate many times the message size.
func TestAudit_HeaderHelpersDoNotSplitTheBody(t *testing.T) {
	const bodySize = 4 << 20
	body := strings.Repeat("\r\n", bodySize/2)
	raw := "Received: from a by b\r\nFrom: Support <user@example.com@TOKEN>\r\nSubject: hi\r\n\r\n" + body

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	loop := detectMailLoop(raw, "mx.example.net", 30)
	fixed, added := fixMissingHeaders(raw, "example.net")
	subj := modifySubject(raw, "[SPAM] %s")
	rewritten, ok := rewriteFromHeader(raw, "user@example.com@TOKEN", "user@example.com")

	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc

	// Three of the four return a new copy of the message; allow a generous 2x
	// each. Splitting the body costs 8x per helper on top.
	if limit := uint64(6 * bodySize); allocated > limit {
		t.Errorf("header helpers allocated %d MiB for a %d MiB message (limit %d MiB)",
			allocated>>20, bodySize>>20, limit>>20)
	}

	// Behaviour is unchanged.
	if loop.HopCount != 1 || loop.IsLoop {
		t.Errorf("detectMailLoop = %+v, want one hop and no loop", loop)
	}
	if len(added) != 2 || !strings.HasSuffix(fixed, "\r\n\r\n"+body) ||
		!strings.Contains(fixed[:len(fixed)-len(body)], "\r\nMessage-ID: <") {
		t.Errorf("fixMissingHeaders added %v or damaged the body", added)
	}
	if !strings.HasPrefix(subj, "Received: from a by b\r\nFrom: Support <user@example.com@TOKEN>\r\nSubject: [SPAM] hi\r\n\r\n") ||
		len(subj) != len(raw)+len("[SPAM] ") {
		t.Errorf("modifySubject damaged the message (len %d, want %d)", len(subj), len(raw)+7)
	}
	if !ok || !strings.HasPrefix(rewritten, "Received: from a by b\r\nFrom: Support <user@example.com>\r\nSubject: hi\r\n\r\n\r\n") ||
		len(rewritten) != len(raw)-len("@TOKEN") {
		t.Errorf("rewriteFromHeader ok=%v, damaged the message", ok)
	}
}

func TestAudit_HeaderHelpersEdgeShapes(t *testing.T) {
	// Message that starts with the blank line (no headers at all).
	fixed, added := fixMissingHeaders("\r\nbody\r\n\r\nmore", "example.net")
	if len(added) != 2 || !strings.HasSuffix(fixed, "\r\n\r\nbody\r\n\r\nmore") || strings.HasPrefix(fixed, "\r\n") {
		t.Errorf("no-header message: added=%v fixed=%q", added, fixed)
	}
	// A body line that looks like a header must stay untouched.
	in := "From: a@b.test\r\n\r\nSubject: not a header\r\n\r\nDate: nor this"
	out := modifySubject(in, "[X] %s")
	if out != "From: a@b.test\r\nSubject: [X] (no subject)\r\n\r\nSubject: not a header\r\n\r\nDate: nor this" {
		t.Errorf("modifySubject = %q", out)
	}
	// No blank line at all: unchanged behaviour (headers appended, separator added).
	fixed, _ = fixMissingHeaders("From: a@b.test", "example.net")
	if !strings.HasPrefix(fixed, "From: a@b.test\r\nDate: ") || !strings.HasSuffix(fixed, "\r\n") {
		t.Errorf("no-terminator message: %q", fixed)
	}
}

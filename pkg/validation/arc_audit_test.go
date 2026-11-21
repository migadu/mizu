package validation

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Audit B1 (docs/security-audit-todo.md): the ARC instance number was taken
// from the header with a bare Atoi and then used as a loop bound, with a log
// line per missing instance. One header with i=9223372036854775807 pinned a
// core and flooded the log for as long as the process lived. RFC 8617 §4.2.1
// caps the instance at 50.
func TestAudit_ARCHugeInstanceIsBoundedAndFails(t *testing.T) {
	for _, instance := range []string{"51", "1000000000", "9223372036854775807"} {
		msg := "ARC-Seal: i=" + instance + "; a=rsa-sha256; cv=none; d=evil.test; s=s; b=AAAA\r\n" +
			"From: a@evil.test\r\nSubject: x\r\n\r\nbody\r\n"

		type outcome struct {
			res *ARCResult
			err error
		}
		done := make(chan outcome, 1)
		go func() {
			res, err := CheckARC(context.Background(), msg, func(string) ([]string, error) {
				return nil, errors.New("no dns in test")
			}, nil)
			done <- outcome{res, err}
		}()

		select {
		case o := <-done:
			if o.err != nil {
				continue // refusing the message outright is fine too
			}
			if o.res.Pass || o.res.ChainValid {
				t.Errorf("i=%s: an out-of-range ARC instance must not validate: %+v", instance, o.res)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("i=%s: CheckARC did not return within 3s (unbounded instance loop)", instance)
		}
	}
}

func TestAudit_ExtractInstanceRange(t *testing.T) {
	for header, want := range map[string]int{
		"i=1; a=rsa-sha256":  1,
		"i=50; a=rsa-sha256": 50,
		"i=0; a=rsa-sha256":  0,
		"i=-3; a=rsa-sha256": 0,
		"a=rsa-sha256":       0,
	} {
		if got := extractInstance(header); got != want {
			t.Errorf("extractInstance(%q) = %d, want %d", header, got, want)
		}
	}
	for _, header := range []string{"i=51", "i=1000000", "i=9223372036854775807"} {
		if got := extractInstance(header); got != maxARCInstance+1 {
			t.Errorf("extractInstance(%q) = %d, want the out-of-range marker %d", header, got, maxARCInstance+1)
		}
	}
}

func TestAudit_ExtractInstanceOverflowIsOutOfRange(t *testing.T) {
	if got := extractInstance("i=99999999999999999999999"); got != maxARCInstance+1 {
		t.Errorf("an instance too large for an int = %d, want the out-of-range marker", got)
	}
}

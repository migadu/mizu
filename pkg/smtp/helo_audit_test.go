package smtp

import (
	"errors"
	"testing"

	"github.com/emersion/go-smtp"
)

// Audit A1 (docs/security-audit-todo.md): a control byte in the EHLO argument
// is never legitimate, and it is dangerous wherever the name is later used
// (it used to abort the rspamd request, which fails open). It must be refused
// on every server type, including submission where the hostname *shape*
// checks are off by default.
func TestAudit_HeloControlBytesRejectedEvenWhenValidationIsOff(t *testing.T) {
	for _, serverType := range []string{"submission", "relay"} {
		for _, helo := range []string{
			"mail.evil.test\x7f",
			"mail.evil.test\x01",
			"mail\x00.evil.test",
			"mail.evil.test\x1b[31m",
			"ChiaraThinkpad\x02",
		} {
			s := newHeloGateSession(t, serverType, nil)
			err := s.Helo(helo)
			var se *smtp.SMTPError
			if !errors.As(err, &se) || se.Code < 500 {
				t.Errorf("%s: Helo(%q) = %v, want a permanent rejection", serverType, helo, err)
			}
			if s.helo != "" {
				t.Errorf("%s: Helo(%q) must not be recorded on the session", serverType, helo)
			}
		}
	}
}

// The unconditional check must not reintroduce the August 2026 Outlook
// incident: bare machine names, including non-ASCII ones, stay accepted on
// submission.
func TestAudit_HeloBareAndNonASCIINamesStillAcceptedOnSubmission(t *testing.T) {
	for _, helo := range []string{"ChiaraThinkpad", "DESKTOP-4F2K1", "Jürgens-PC", "[192.0.2.7]"} {
		s := newHeloGateSession(t, "submission", nil)
		if err := s.Helo(helo); err != nil {
			t.Errorf("Helo(%q) on submission = %v, want accepted", helo, err)
		}
	}
}

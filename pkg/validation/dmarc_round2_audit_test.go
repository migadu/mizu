package validation

import (
	"context"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/authres"
)

// D2: DMARC was evaluated on the first From address only. A message with two
// From headers, or two addresses in one, passed on the attacker's own domain
// while mail clients may display the other - a p=reject domain. RFC 5322
// allows exactly one From header, and RFC 7489 section 6.6.1 says a message
// with several From domains cannot be evaluated: it is treated like an
// unparseable From and marked as junk.
func TestAudit_DMARCMultipleFromIsJunk(t *testing.T) {
	spf := &SPFResult{Domain: "attacker.test", Result: authres.SPFResult{Value: authres.ResultPass}}
	for name, headers := range map[string]string{
		"two From headers":        "From: x@attacker.test\r\nFrom: CEO <ceo@victim.test>\r\n",
		"two headers, mixed case": "From: x@attacker.test\r\nfrom: CEO <ceo@victim.test>\r\n",
		"two addresses":           "From: x@attacker.test, CEO <ceo@victim.test>\r\n",
	} {
		raw := headers + "To: r@example.com\r\nSubject: x\r\n\r\nbody\r\n"
		res, err := CheckDMARC(context.Background(), raw, spf, "junk", nil, 0, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.Pass || !res.ShouldBeJunk {
			t.Errorf("%s: pass=%v junk=%v, want a junk verdict", name, res.Pass, res.ShouldBeJunk)
		}
	}
}

// D4: a signature whose t= was even one second ahead of this host's clock was
// discarded. Clocks differ by a second or two all the time; with no SPF
// alignment (forwarded mail) that turned valid mail into a p=reject failure.
func TestAudit_DKIMTimestampAllowsClockSkew(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name   string
		signed time.Time
		usable bool
	}{
		{"2s ahead", now.Add(2 * time.Second), true},
		{"4 min ahead", now.Add(4 * time.Minute), true},
		{"1h ahead", now.Add(time.Hour), false},
		{"1h old", now.Add(-time.Hour), true},
		{"8 days old", now.Add(-8 * 24 * time.Hour), false},
		{"no timestamp", time.Time{}, true},
	} {
		if problem := dkimTimestampProblem(tc.signed, now); (problem == "") != tc.usable {
			t.Errorf("%s: problem=%q, want usable=%v", tc.name, problem, tc.usable)
		}
	}
}

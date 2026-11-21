package validation

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/authres"
	"github.com/emersion/go-msgauth/dmarc"
)

// Audit B2 (docs/security-audit-todo.md): a From header that net/mail cannot
// parse used to return before any DMARC lookup with Policy "none" and
// ShouldBeJunk false, so none of the reject / quarantine / junk branches in the
// session fired. A spoofer only had to break the syntax slightly - lenient
// MUAs still display the victim's address - to get past a p=reject domain as
// clean mail. With no parseable domain there is no policy to look up, so the
// message is marked as junk.
func TestAudit_DMARCUnparseableFromIsJunk(t *testing.T) {
	for _, from := range []string{
		"CEO <ceo@dmarc.io>>",
		"CEO <ceo@dmarc.io",
		"<ceo@dmarc.io> CEO",
		"ceo@dmarc.io;",
		"CEO [x] <ceo@dmarc.io>",
		"ceo@dmarc.io.",
		`CEO <"ceo@"@dmarc.io>`,
		`"ceo@dmarc.io"@dmarc.io`,
	} {
		raw := "From: " + from + "\r\nTo: r@example.com\r\nSubject: x\r\n\r\nbody\r\n"
		spf := &SPFResult{Domain: "evil.test", Result: authres.SPFResult{Value: authres.ResultFail}}
		res, err := CheckDMARC(context.Background(), raw, spf, "junk", nil, 0, nil)
		if err != nil {
			continue // refusing to evaluate is handled by the caller; not a pass
		}
		if res.Pass {
			t.Errorf("From %q: must not pass DMARC", from)
		}
		if !res.ShouldBeJunk && res.Policy != "reject" {
			t.Errorf("From %q: delivered clean (policy=%q junk=%v); want junk or reject", from, res.Policy, res.ShouldBeJunk)
		}
	}
}

// Audit B3: relaxed alignment compared organizational domains, and the helper
// returned "" for any name the public suffix list cannot split - a name that
// is itself a public suffix (gov.in, gov.uk, github.io ...) or one with a
// trailing dot. Two failures compared equal, so SPF for "attacker.com." was
// "aligned" with a From at gov.in.
func TestAudit_RelaxedAlignmentNeverMatchesOnEmptyOrgDomain(t *testing.T) {
	for _, tc := range []struct {
		from, auth string
		want       bool
	}{
		{"gov.in", "attacker.com.", false},
		{"gov.uk", "attacker.com.", false},
		{"github.io", "attacker.com.", false},
		{"gov.in", "co.uk", false},
		{"gov.in", "com", false},
		{"gov.in", "", false},
		{"", "", false},
		// Legitimate cases keep working.
		{"gov.in", "gov.in", true},
		{"example.com", "mail.example.com", true},
		{"mail.example.com", "example.com", true},
		{"example.com", "example.com.", true},
		{"example.co.uk", "other.co.uk", false},
	} {
		if got := isAligned(tc.from, tc.auth, false); got != tc.want {
			t.Errorf("isAligned(%q, %q, relaxed) = %v, want %v", tc.from, tc.auth, got, tc.want)
		}
	}
}

func TestAudit_DMARCPublicSuffixFromNotAlignedWithTrailingDotSPF(t *testing.T) {
	dmarcRecords["gov.in"] = &dmarc.Record{Policy: dmarc.PolicyReject}
	t.Cleanup(func() { delete(dmarcRecords, "gov.in") })

	raw := "From: minister@gov.in\r\nTo: r@example.com\r\nSubject: x\r\n\r\nbody\r\n"
	spf := &SPFResult{Domain: "attacker.com.", Result: authres.SPFResult{Value: authres.ResultPass}}
	res, err := CheckDMARC(context.Background(), raw, spf, "junk", nil, 0, nil)
	if err != nil {
		t.Fatalf("CheckDMARC: %v", err)
	}
	if res.Pass || res.SPFAligned {
		t.Fatalf("SPF for attacker.com. must not align with gov.in: %+v", res)
	}
	if res.Policy != "reject" {
		t.Fatalf("policy = %q, want reject", res.Policy)
	}
}

type countingTXT struct {
	mu    chan struct{}
	count int
}

func (c *countingTXT) LookupTXT(ctx context.Context, name string) ([]string, error) {
	c.mu <- struct{}{}
	c.count++
	<-c.mu
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// Audit B5: DKIM verification had no cap on the number of signatures. Each one
// costs a goroutine, a DNS TXT lookup and a pass over the body, so a message
// made of signature headers was a cheap amplifier.
func TestAudit_DKIMSignatureCountIsCapped(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&b, "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=evil.test; s=s%d;\r\n\th=from; bh=AAAA; b=AAAA\r\n", i)
	}
	b.WriteString("From: a@dmarc.io\r\nTo: r@example.com\r\nSubject: x\r\n\r\nbody\r\n")

	resolver := &countingTXT{mu: make(chan struct{}, 1)}
	if _, err := CheckDMARC(context.Background(), b.String(), nil, "junk", resolver, 0, nil); err != nil {
		t.Fatalf("CheckDMARC: %v", err)
	}
	if resolver.count > maxDKIMVerifications {
		t.Fatalf("%d DNS lookups for 200 signatures, want at most %d", resolver.count, maxDKIMVerifications)
	}
	if resolver.count == 0 {
		t.Fatal("expected the first signatures to be verified")
	}
}

// Audit B4: only _dmarc.<exact From domain> was queried. RFC 7489 §6.6.3 says
// to fall back to the organizational domain and apply its sp= (or p=) policy;
// without that, From: ceo@anything.victim.test walked past victim.test's
// p=reject as "no DMARC record".
func TestAudit_DMARCFallsBackToOrganizationalDomain(t *testing.T) {
	for name, tc := range map[string]struct {
		record     *dmarc.Record
		wantPolicy string
	}{
		"p applies to subdomains when sp is absent": {&dmarc.Record{Policy: dmarc.PolicyReject}, "reject"},
		"sp overrides p for subdomains":             {&dmarc.Record{Policy: dmarc.PolicyNone, SubdomainPolicy: dmarc.PolicyReject}, "reject"},
		"sp can also relax":                         {&dmarc.Record{Policy: dmarc.PolicyReject, SubdomainPolicy: dmarc.PolicyQuarantine}, "quarantine"},
	} {
		t.Run(name, func(t *testing.T) {
			dmarcRecords["victim.test"] = tc.record
			t.Cleanup(func() { delete(dmarcRecords, "victim.test") })

			raw := "From: ceo@anything.victim.test\r\nTo: r@example.com\r\nSubject: x\r\n\r\nbody\r\n"
			spf := &SPFResult{Domain: "evil.test", Result: authres.SPFResult{Value: authres.ResultPass}}
			resolver := &countingTXT{mu: make(chan struct{}, 1)}
			res, err := CheckDMARC(context.Background(), raw, spf, "junk", resolver, 0, nil)
			if err != nil {
				t.Fatalf("CheckDMARC: %v", err)
			}
			if res.NoDMARCRecord {
				t.Fatal("the organizational domain publishes a record; NoDMARCRecord must be false")
			}
			if res.Policy != tc.wantPolicy {
				t.Fatalf("policy = %q, want %q", res.Policy, tc.wantPolicy)
			}
			if res.Pass {
				t.Fatal("unaligned mail must not pass")
			}
		})
	}
}

// The exact domain's own record still wins over the organizational one.
func TestAudit_DMARCExactDomainRecordWinsOverOrganizational(t *testing.T) {
	dmarcRecords["victim.test"] = &dmarc.Record{Policy: dmarc.PolicyReject}
	dmarcRecords["sub.victim.test"] = &dmarc.Record{Policy: dmarc.PolicyNone}
	t.Cleanup(func() { delete(dmarcRecords, "victim.test"); delete(dmarcRecords, "sub.victim.test") })

	raw := "From: a@sub.victim.test\r\nTo: r@example.com\r\nSubject: x\r\n\r\nbody\r\n"
	res, err := CheckDMARC(context.Background(), raw, nil, "junk", &countingTXT{mu: make(chan struct{}, 1)}, 0, nil)
	if err != nil {
		t.Fatalf("CheckDMARC: %v", err)
	}
	if res.Policy != "none" {
		t.Fatalf("policy = %q, want the subdomain's own %q", res.Policy, "none")
	}
}

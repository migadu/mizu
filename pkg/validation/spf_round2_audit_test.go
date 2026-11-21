package validation

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/migadu/spf"
)

// fakeSPFDNS answers like net.Resolver does: a name that does not exist is an
// error (*net.DNSError with IsNotFound), not an empty answer.
type fakeSPFDNS struct {
	txt     map[string][]string
	failing map[string]bool // names whose lookups fail with a server error
}

func (f fakeSPFDNS) miss(name string) error {
	if f.failing[name] {
		return &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f fakeSPFDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f.txt[name]; ok {
		return v, nil
	}
	return nil, f.miss(name)
}
func (f fakeSPFDNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return nil, f.miss(name)
}
func (f fakeSPFDNS) LookupHost(_ context.Context, name string) ([]string, error) {
	return nil, f.miss(name)
}
func (f fakeSPFDNS) LookupAddr(_ context.Context, addr string) ([]string, error) {
	return nil, f.miss(addr)
}

// D3: the adapter passed net.Resolver's "no such host" error straight to the
// SPF library, which treats any resolver error as a DNS failure: TempError,
// reported as spf=none. A record with an exists: macro or a dangling a:/mx:
// name - where "does not exist" is the normal non-matching answer - therefore
// never produced pass or fail: authorised senders lost SPF, spoofers were
// never failed.
func TestAudit_SPFNotFoundIsAnEmptyAnswerNotAnError(t *testing.T) {
	for _, record := range []string{
		"v=spf1 exists:%{i}._spf.sender.test ip4:192.0.2.1 -all",
		"v=spf1 a:gone.sender.test ip4:192.0.2.1 -all",
		"v=spf1 mx:gone.sender.test ip4:192.0.2.1 -all",
	} {
		dns := fakeSPFDNS{txt: map[string][]string{"sender.test": {record}}}
		check := func(ip string) spf.Result {
			return spf.CheckHostWithResolver(context.Background(), net.ParseIP(ip),
				"sender.test", "a@sender.test", "mail.sender.test", &spfResolver{r: dns})
		}
		if got := check("192.0.2.1"); got != spf.Pass {
			t.Errorf("%q: authorised IP got %v, want pass", record, got)
		}
		if got := check("198.51.100.9"); got != spf.Fail {
			t.Errorf("%q: unauthorised IP got %v, want fail", record, got)
		}
	}
}

// A real DNS failure must stay an error: turning it into "no record" would
// make an unreachable resolver look like a domain without SPF.
func TestAudit_SPFServerFailureStaysAnError(t *testing.T) {
	dns := fakeSPFDNS{failing: map[string]bool{"sender.test": true}}
	r := &spfResolver{r: dns}
	if _, err := r.LookupTXT(context.Background(), "sender.test"); err == nil {
		t.Fatal("a temporary DNS failure was reported as an empty answer")
	}
	var dnsErr *net.DNSError
	if _, err := r.LookupA(context.Background(), "sender.test"); !errors.As(err, &dnsErr) {
		t.Fatalf("LookupA error = %v, want the DNS error", err)
	}
}

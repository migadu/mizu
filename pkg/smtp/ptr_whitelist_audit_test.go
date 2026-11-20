package smtp

import (
	"context"
	"errors"
	"net"
	"testing"
)

// Audit A12 (docs/security-audit-todo.md): reputation.whitelist_hosts was
// matched against the PTR name alone. Whoever controls the reverse zone of
// their own IP can make the PTR say anything, e.g.
// "x.monitoring.trusted.example", and skip the reputation check. A PTR name is
// only evidence once the name resolves back to the same address (FCrDNS).
func TestAudit_PTRWhitelistRequiresForwardConfirmation(t *testing.T) {
	be := &Backend{}
	hosts := []string{"trusted.example"}
	clientIP := net.ParseIP("203.0.113.50")

	forward := map[string][]string{
		"probe1.trusted.example": {"203.0.113.50"},                 // genuine
		"spoof.trusted.example":  {"198.51.100.1"},                 // PTR claims it, forward disagrees
		"multi.trusted.example":  {"198.51.100.2", "203.0.113.50"}, // one of several A records
	}
	lookup := func(_ context.Context, name string) ([]string, error) {
		if addrs, ok := forward[name]; ok {
			return addrs, nil
		}
		return nil, errors.New("no such host")
	}

	for ptr, want := range map[string]bool{
		"probe1.trusted.example.":  true,
		"multi.trusted.example":    true,
		"spoof.trusted.example":    false, // forward lookup points elsewhere
		"missing.trusted.example":  false, // forward lookup fails: not confirmed
		"probe1.untrusted.example": false, // not in the whitelist at all
	} {
		_, got := be.ptrWhitelisted(context.Background(), ptr, clientIP, hosts, lookup)
		if got != want {
			t.Errorf("ptrWhitelisted(%q) = %v, want %v", ptr, got, want)
		}
	}
}

func TestAudit_PTRWhitelistForwardConfirmationHandlesIPv6(t *testing.T) {
	be := &Backend{}
	lookup := func(_ context.Context, name string) ([]string, error) {
		return []string{"2001:0db8:0000:0000:0000:0000:0000:0001"}, nil // non-canonical spelling
	}
	if _, ok := be.ptrWhitelisted(context.Background(), "mx.trusted.example", net.ParseIP("2001:db8::1"), []string{"trusted.example"}, lookup); !ok {
		t.Fatal("the same IPv6 address in a different spelling must confirm")
	}
}

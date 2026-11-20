package validation

import (
	"context"
	"errors"
	"net"

	"github.com/emersion/go-msgauth/authres"
	"github.com/migadu/spf"
)

// spfLookups is the part of *net.Resolver the SPF adapter uses.
type spfLookups interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// spfResolver adapts a *net.Resolver to the spf.Resolver interface.
type spfResolver struct {
	r spfLookups
}

// notFoundIsEmpty turns "this name does not exist / has no such record" into
// a nil error, leaving the answer empty. net.Resolver reports that case as an
// error, but for SPF it is an ordinary answer - the normal non-match of an
// exists: or a: mechanism, and the void lookups the library counts and limits.
// Passed through as an error it made the library return TempError. Real
// failures (timeout, SERVFAIL) are returned unchanged.
func notFoundIsEmpty(err error) error {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return nil
	}
	return err
}

func (s *spfResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	txts, err := s.r.LookupTXT(ctx, domain)
	if err = notFoundIsEmpty(err); err != nil {
		return nil, err
	}
	return txts, nil
}

func (s *spfResolver) LookupMX(ctx context.Context, domain string) ([]string, error) {
	mxs, err := s.r.LookupMX(ctx, domain)
	if err = notFoundIsEmpty(err); err != nil {
		return nil, err
	}
	hosts := make([]string, len(mxs))
	for i, mx := range mxs {
		hosts[i] = mx.Host
	}
	return hosts, nil
}

func (s *spfResolver) LookupA(ctx context.Context, domain string) ([]net.IP, error) {
	addrs, err := s.r.LookupHost(ctx, domain)
	if err = notFoundIsEmpty(err); err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			if ip.To4() != nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips, nil
}

func (s *spfResolver) LookupAAAA(ctx context.Context, domain string) ([]net.IP, error) {
	addrs, err := s.r.LookupHost(ctx, domain)
	if err = notFoundIsEmpty(err); err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			if ip.To4() == nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips, nil
}

func (s *spfResolver) LookupPTR(ctx context.Context, ip net.IP) ([]string, error) {
	names, err := s.r.LookupAddr(ctx, ip.String())
	if err = notFoundIsEmpty(err); err != nil {
		return nil, err
	}
	return names, nil
}

// CheckSPF performs an SPF check using the provided DNS resolver.
// domain is the name whose SPF record is evaluated (the MAIL FROM domain).
func CheckSPF(ctx context.Context, ip net.IP, domain, sender string, resolver *net.Resolver) (*spf.Result, error) {
	res := spf.CheckHostWithResolver(ctx, ip, domain, sender, "", &spfResolver{r: resolver})
	return &res, nil
}

// ConvertSPFResult converts a result from the migadu/spf library to the
// standard authres.SPFResultValue used by the go-msgauth library.
func ConvertSPFResult(res spf.Result) authres.ResultValue {
	switch res {
	case spf.Pass:
		return authres.ResultPass
	case spf.Fail:
		return authres.ResultFail
	case spf.Softfail:
		return authres.ResultSoftFail
	case spf.Neutral:
		return authres.ResultNeutral
	default:
		return authres.ResultNone // Includes None, TempError, PermError
	}
}

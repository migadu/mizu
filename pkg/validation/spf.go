package validation

import (
	"context"
	"net"

	"github.com/emersion/go-msgauth/authres"
	"github.com/migadu/spf"
)

// spfResolver adapts a *net.Resolver to the spf.Resolver interface.
type spfResolver struct {
	r *net.Resolver
}

func (s *spfResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	return s.r.LookupTXT(ctx, domain)
}

func (s *spfResolver) LookupMX(ctx context.Context, domain string) ([]string, error) {
	mxs, err := s.r.LookupMX(ctx, domain)
	if err != nil {
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
	if err != nil {
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
	if err != nil {
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
	return s.r.LookupAddr(ctx, ip.String())
}

// CheckSPF performs an SPF check using the provided DNS resolver.
func CheckSPF(ctx context.Context, ip net.IP, heloHost, sender string, resolver *net.Resolver) (*spf.Result, error) {
	res := spf.CheckHostWithResolver(ctx, ip, heloHost, sender, "", &spfResolver{r: resolver})
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

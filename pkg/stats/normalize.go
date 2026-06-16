package stats

import "net"

// NormalizeIP returns the canonical string form of an IP address and true,
// or ("", false) if the input is not a valid IP.
// For IPv6 this compresses zeros and lowercases hex digits.
func NormalizeIP(ip string) (string, bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", false
	}
	return parsed.String(), true
}

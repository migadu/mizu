package smtp

import "strings"

// isDeliverableAddress reports whether the delivery backend accepts addr as a
// recipient. It is mailqueuer's rule (IsValidEmail in the emailutil module,
// applied to every X-Mail-To entry at ingest), kept identical here: exactly
// one "@" with something before it, no space or control character, and a
// domain that has a dot, neither starts nor ends with one, and has no empty
// label. An address this accepts and mailqueuer refuses bounces the whole
// message at DATA (a 422), so a change there needs the same change here.
func isDeliverableAddress(addr string) bool {
	for _, c := range addr {
		if c <= 0x1f || c == 0x7f || c == ' ' {
			return false
		}
	}
	at := strings.LastIndex(addr, "@")
	if at < 1 || at == len(addr)-1 || strings.Count(addr, "@") != 1 {
		return false
	}
	domain := addr[at+1:]
	return strings.Contains(domain, ".") &&
		!strings.HasPrefix(domain, ".") && !strings.HasSuffix(domain, ".") &&
		!strings.Contains(domain, "..")
}

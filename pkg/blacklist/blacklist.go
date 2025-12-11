package blacklist

import (
	"io"

	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"log/slog"

	"migadu/mizu/pkg/logging"
)

// resolver defines an interface for DNS lookups, allowing for mocking in tests.
type resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Checker is responsible for checking an IP against a set of DNS blacklists.
type Checker struct {
	lists    []string
	timeout  time.Duration
	logger   *slog.Logger
	resolver resolver // Use interface for testability
}

// NewChecker creates a new blacklist checker.
func NewChecker(lists []string, timeout time.Duration, logger *slog.Logger) *Checker {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	return &Checker{
		lists:    lists,
		timeout:  timeout,
		logger:   logger,
		resolver: &net.Resolver{}, // Use the default net.Resolver
	}
}

// CheckIP checks if the given IP address is on any of the configured blacklists.
func (c *Checker) CheckIP(ip net.IP) (bool, string, error) {
	if ip == nil {
		return false, "", fmt.Errorf("invalid IP address")
	}

	// Skip if no blacklists configured
	if len(c.lists) == 0 {
		return false, "", nil
	}

	// Reverse the IP address for DNSBL lookup.
	reversedIP := reverseIP(ip)
	if reversedIP == "" {
		return false, "", fmt.Errorf("invalid IP format")
	}

	// Create a context with timeout for all lookups.
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	// Use channels to perform lookups concurrently.
	type result struct {
		list   string
		reason string
	}
	resultChan := make(chan result, len(c.lists))
	var wg sync.WaitGroup

	for _, list := range c.lists {
		wg.Add(1)
		logging.SafeGoWithWg(c.logger, fmt.Sprintf("blacklist-lookup-%s", list), &wg, func(l string) func() {
			return func() {
				query := fmt.Sprintf("%s.%s", reversedIP, l)
				addrs, err := c.resolver.LookupIPAddr(ctx, query)
				if err != nil {
					// Not listed or error - either way, skip
					c.logger.Debug("blacklist lookup", "query", query, "error", err)
					return
				}
				if len(addrs) > 0 {
					// IP is listed. Check if it's Spamhaus to get detailed reason
					reason := l
					if strings.Contains(l, "spamhaus") && len(addrs) > 0 {
						// Extract last octet from response (e.g., 127.0.0.2 -> 2)
						responseIP := addrs[0].IP.To4()
						if responseIP != nil && len(responseIP) == 4 {
							code := responseIP[3]
							spamhausReason := getSpamhausReason(code)
							reason = fmt.Sprintf("%s (%s)", l, spamhausReason)
						}
					}
					resultChan <- result{list: l, reason: reason}
				}
			}
		}(list))
	}

	// Wait for all lookups to complete in a separate goroutine to not block the timeout.
	logging.SafeGo(c.logger, "blacklist-closer", func() {
		wg.Wait()
		close(resultChan)
	})

	select {
	case res, ok := <-resultChan:
		if !ok {
			// Channel closed, no results found
			return false, "", nil
		}
		// As soon as we get one result, we can return.
		return true, res.reason, nil
	case <-ctx.Done():
		// Timeout occurred
		return false, "", nil
	}
}

// CheckHELOResolves verifies that a given HELO hostname resolves to an IP address.
func CheckHELOResolves(hostname string, timeout time.Duration) (bool, string, error) {
	// Handle IP address literals in brackets [192.168.1.1]
	if strings.HasPrefix(hostname, "[") && strings.HasSuffix(hostname, "]") {
		ipStr := strings.Trim(hostname, "[]")
		ip := net.ParseIP(ipStr)
		if ip != nil {
			return true, "IP address literal", nil
		}
		return false, "Invalid IP address literal", nil
	}

	// Empty hostname doesn't resolve
	if hostname == "" {
		return false, "Empty hostname", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	addrs, err := (&net.Resolver{}).LookupHost(ctx, hostname)
	if err != nil {
		// Check if it's a "no such host" error, which is a valid check result.
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return false, "Hostname does not resolve", nil
		}
		// For other errors (e.g., timeout), return the error.
		return false, "", err
	}

	if len(addrs) > 0 {
		return true, "Valid hostname", nil
	}
	return false, "No addresses found", nil
}

// reverseIP reverses an IP address for DNSBL lookups.
// For IPv4: reverses octets (1.2.3.4 -> 4.3.2.1)
// For IPv6: reverses nibbles in expanded format
func reverseIP(ip net.IP) string {
	// Try IPv4 first
	ipv4 := ip.To4()
	if ipv4 != nil {
		parts := strings.Split(ipv4.String(), ".")
		if len(parts) != 4 {
			return ""
		}
		return fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])
	}

	// Handle IPv6
	ipv6 := ip.To16()
	if ipv6 == nil {
		return "" // Not a valid IP
	}

	// Convert to nibble format (each hex digit separated by dots, reversed)
	// Example: 2001:db8::1 -> 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2
	var nibbles []string
	for i := len(ipv6) - 1; i >= 0; i-- {
		nibbles = append(nibbles, fmt.Sprintf("%x", ipv6[i]&0x0f))
		nibbles = append(nibbles, fmt.Sprintf("%x", ipv6[i]>>4))
	}
	return strings.Join(nibbles, ".")
}

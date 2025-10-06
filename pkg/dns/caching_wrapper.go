package dns

import (
	"context"
	"fmt"
	"net"
)

// CachingWrapper wraps a net.Resolver and adds application-level caching
type CachingWrapper struct {
	resolver *net.Resolver
	rr       *ResilientResolver // For cache access
}

// WrapWithCache wraps a net.Resolver with caching capabilities
func WrapWithCache(resolver *net.Resolver, rr *ResilientResolver) *CachingWrapper {
	return &CachingWrapper{
		resolver: resolver,
		rr:       rr,
	}
}

// LookupHost performs a cached DNS lookup for a hostname
func (c *CachingWrapper) LookupHost(ctx context.Context, host string) ([]string, error) {
	if c.rr != nil {
		// Check cache first
		if addrs, found := c.rr.getCached(host); found {
			return addrs, nil
		}
	}

	// Perform actual lookup
	addrs, err := c.resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if c.rr != nil {
		c.rr.putCache(host, addrs)
	}

	return addrs, nil
}

// LookupAddr performs a cached reverse DNS lookup
func (c *CachingWrapper) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	cacheKey := fmt.Sprintf("reverse:%s", addr)

	if c.rr != nil {
		// Check cache first
		if names, found := c.rr.getCached(cacheKey); found {
			return names, nil
		}
	}

	// Perform actual lookup
	names, err := c.resolver.LookupAddr(ctx, addr)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if c.rr != nil {
		c.rr.putCache(cacheKey, names)
	}

	return names, nil
}

// LookupMX performs a cached MX record lookup
func (c *CachingWrapper) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	cacheKey := fmt.Sprintf("mx:%s", name)

	if c.rr != nil {
		// Check cache first
		if cached, found := c.rr.getCached(cacheKey); found {
			// Reconstruct MX records from cache (format: "pref:host")
			mxRecords := make([]*net.MX, 0, len(cached))
			for _, entry := range cached {
				var pref uint16
				var host string
				if _, err := fmt.Sscanf(entry, "%d:%s", &pref, &host); err == nil {
					mxRecords = append(mxRecords, &net.MX{Host: host, Pref: pref})
				}
			}
			if len(mxRecords) > 0 {
				return mxRecords, nil
			}
		}
	}

	// Perform actual lookup
	mxRecords, err := c.resolver.LookupMX(ctx, name)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if c.rr != nil {
		cached := make([]string, len(mxRecords))
		for i, mx := range mxRecords {
			cached[i] = fmt.Sprintf("%d:%s", mx.Pref, mx.Host)
		}
		c.rr.putCache(cacheKey, cached)
	}

	return mxRecords, nil
}

// LookupTXT performs a cached TXT record lookup
func (c *CachingWrapper) LookupTXT(ctx context.Context, name string) ([]string, error) {
	cacheKey := fmt.Sprintf("txt:%s", name)

	if c.rr != nil {
		// Check cache first
		if txts, found := c.rr.getCached(cacheKey); found {
			return txts, nil
		}
	}

	// Perform actual lookup
	txts, err := c.resolver.LookupTXT(ctx, name)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if c.rr != nil {
		c.rr.putCache(cacheKey, txts)
	}

	return txts, nil
}

// GetResolver returns the underlying net.Resolver for methods that don't need caching
func (c *CachingWrapper) GetResolver() *net.Resolver {
	return c.resolver
}

// GetCacheStats returns cache statistics
func (c *CachingWrapper) GetCacheStats() (size int, ttl string) {
	if c.rr != nil {
		s, t := c.rr.GetCacheStats()
		return s, t.String()
	}
	return 0, "0s"
}

// FlushCache clears all cached DNS responses
func (c *CachingWrapper) FlushCache() {
	if c.rr != nil {
		c.rr.FlushCache()
	}
}

package recipient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"log/slog"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// Validator handles recipient validation with caching
type Validator struct {
	urlTemplate string // URL template with $ip, $ptr, $helo, $email placeholders
	apiKey      string
	httpClient  *http.Client
	logger      *slog.Logger

	// Caching
	cache    *expirable.LRU[string, *ValidateResponse]
	cacheTTL time.Duration

	mu sync.RWMutex
}

// ValidatorConfig holds configuration for the recipient validator
type ValidatorConfig struct {
	URL                string
	AuthToken          string
	HTTPTimeoutSeconds int
	CacheTTLSeconds    int
	Logger             *slog.Logger
}

// NewValidator creates a new recipient validator
func NewValidator(cfg ValidatorConfig) (*Validator, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("recipient validation URL is required")
	}

	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	// Set defaults
	if cfg.HTTPTimeoutSeconds == 0 {
		cfg.HTTPTimeoutSeconds = 5
	}
	if cfg.CacheTTLSeconds == 0 {
		cfg.CacheTTLSeconds = 300 // 5 minutes
	}

	httpClient := &http.Client{
		Timeout: time.Duration(cfg.HTTPTimeoutSeconds) * time.Second,
	}

	// Create LRU cache
	cache := expirable.NewLRU[string, *ValidateResponse](
		10000, // Max 10k cached entries
		nil,   // no eviction callback
		time.Duration(cfg.CacheTTLSeconds)*time.Second,
	)

	return &Validator{
		urlTemplate: cfg.URL,
		apiKey:      cfg.AuthToken,
		httpClient:  httpClient,
		logger:      cfg.Logger,
		cache:       cache,
		cacheTTL:    time.Duration(cfg.CacheTTLSeconds) * time.Second,
	}, nil
}

// Validate checks if a recipient should be accepted during RCPT TO
// Parameters can include PTR (reverse DNS) and HELO hostname if available
func (v *Validator) Validate(ctx context.Context, clientIP, from, to string) (*ValidateResponse, error) {
	return v.ValidateWithContext(ctx, clientIP, "", "", from, to)
}

// ValidateWithContext checks recipient with additional context (PTR, HELO)
func (v *Validator) ValidateWithContext(ctx context.Context, clientIP, ptr, helo, from, to string) (*ValidateResponse, error) {
	cacheKey := v.buildCacheKey(clientIP, ptr, helo, from, to)

	// Check cache first
	if cached, ok := v.cache.Get(cacheKey); ok {
		v.logger.Debug("Recipient validation cache hit",
			"to", to,
			"from", from,
			"client_ip", clientIP)
		return cached, nil
	}

	// Cache miss - query the endpoint
	v.logger.Debug("Recipient validation cache miss - querying endpoint",
		"to", to,
		"url_template", v.urlTemplate)

	resp, err := v.queryEndpoint(ctx, clientIP, ptr, helo, from, to)
	if err != nil {
		return nil, err
	}

	// Cache the result (only cache accepted recipients to avoid caching temporary failures)
	if resp.Accepted {
		v.cache.Add(cacheKey, resp)
		v.logger.Debug("Cached recipient validation result",
			"key", cacheKey,
			"accepted", resp.Accepted)
	}

	return resp, nil
}

// buildURL builds the request URL with interpolated parameters
func (v *Validator) buildURL(clientIP, ptr, helo, from, to string) string {
	result := v.urlTemplate
	result = strings.ReplaceAll(result, "$ip", url.QueryEscape(clientIP))
	result = strings.ReplaceAll(result, "$ptr", url.QueryEscape(ptr))
	result = strings.ReplaceAll(result, "$helo", url.QueryEscape(helo))
	// Normalize email addresses to lowercase before URL encoding.
	// Email local parts are case-insensitive per RFC 5321, and uppercase
	// percent-encoded characters (e.g. MARINA%40MAROUN.COM) can trigger
	// Cloudflare WAF rules or URL-normalization redirects that cause timeouts.
	result = strings.ReplaceAll(result, "$from", url.QueryEscape(strings.ToLower(from)))
	result = strings.ReplaceAll(result, "$email", url.QueryEscape(strings.ToLower(to)))
	return result
}

// queryEndpoint makes the HTTP GET request to the validation endpoint
func (v *Validator) queryEndpoint(ctx context.Context, clientIP, ptr, helo, from, to string) (*ValidateResponse, error) {
	// Build URL with interpolation
	requestURL := v.buildURL(clientIP, ptr, helo, from, to)

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	if v.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+v.apiKey)
	}

	// Execute request
	httpResp, err := v.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer httpResp.Body.Close()

	// Read response body (limit to 64KB to prevent memory exhaustion)
	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Handle different HTTP status codes
	switch httpResp.StatusCode {
	case http.StatusOK:
		// 200 OK - recipient accepted
		var resp ValidateResponse
		if len(respBody) > 0 {
			if err := json.Unmarshal(respBody, &resp); err != nil {
				// If body is not JSON, use it as plain message
				resp.Message = string(respBody)
			}
		}
		resp.Accepted = true
		return &resp, nil

	case http.StatusNotFound:
		// 404 Not Found - recipient does not exist
		var resp ValidateResponse
		if len(respBody) > 0 {
			if err := json.Unmarshal(respBody, &resp); err != nil {
				// If body is not JSON, use it as plain message or default
				if len(respBody) > 0 {
					resp.Message = string(respBody)
				} else {
					resp.Message = "User unknown"
				}
			}
		} else {
			resp.Message = "User unknown"
		}
		resp.Accepted = false
		return &resp, nil

	case http.StatusForbidden:
		// 403 Forbidden - sender blocked by recipient
		var resp ValidateResponse
		if len(respBody) > 0 {
			if err := json.Unmarshal(respBody, &resp); err != nil {
				// If body is not JSON, use it as plain message or default
				if len(respBody) > 0 {
					resp.Message = string(respBody)
				} else {
					resp.Message = "Delivery not authorized"
				}
			}
		} else {
			resp.Message = "Delivery not authorized"
		}
		resp.Accepted = false
		return &resp, nil

	case 450:
		// 450 - temporary failure with custom message
		var resp ValidateResponse
		if len(respBody) > 0 {
			if err := json.Unmarshal(respBody, &resp); err != nil {
				// If body is not JSON, use it as plain message
				if len(respBody) > 0 {
					resp.Message = string(respBody)
				} else {
					resp.Message = "Requested action not taken: mailbox unavailable"
				}
			}
		} else {
			resp.Message = "Requested action not taken: mailbox unavailable"
		}
		resp.Accepted = false
		resp.Temporary = true
		return &resp, nil

	case http.StatusTooManyRequests:
		// 429 Too Many Requests - rate limit exceeded
		return nil, fmt.Errorf("rate limit exceeded (HTTP 429)")

	case http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusBadGateway:
		// 503, 504, 502 - temporary failures
		return nil, fmt.Errorf("temporary failure (HTTP %d)", httpResp.StatusCode)

	default:
		// All other status codes are treated as errors
		msg := string(respBody)
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", httpResp.StatusCode)
		}
		return nil, fmt.Errorf("validation endpoint error: %s", msg)
	}
}

// buildCacheKey creates a cache key from request parameters
func (v *Validator) buildCacheKey(clientIP, ptr, helo, from, to string) string {
	// Normalize email addresses to lowercase for consistent cache hits.
	return fmt.Sprintf("%s:%s:%s:%s:%s", clientIP, ptr, helo, strings.ToLower(from), strings.ToLower(to))
}

// GetStats returns cache statistics
func (v *Validator) GetStats() map[string]interface{} {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return map[string]interface{}{
		"cache_entries": v.cache.Len(),
		"url_template":  v.urlTemplate,
	}
}

// FlushCache clears all cached entries
func (v *Validator) FlushCache() {
	v.cache.Purge()
	v.logger.Info("Recipient validation cache flushed")
}

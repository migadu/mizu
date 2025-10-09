package routing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"migadu/mizu/pkg/poster"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"go.uber.org/zap"
)

// NonRetryableError is an error that should not be retried.
type NonRetryableError struct {
	Err error
}

func (e *NonRetryableError) Error() string {
	return e.Err.Error()
}

// Client handles routing lookups with caching and retries
type Client struct {
	endpoint       string
	apiKey         string
	httpClient     *http.Client
	circuitBreaker *poster.CircuitBreaker
	logger         *zap.Logger

	// Caching
	cache            *expirable.LRU[string, *ResolveResponse]
	negativeCache    *expirable.LRU[string, *ResolveResponse]
	cacheTTL         time.Duration
	cacheNegativeTTL time.Duration

	// Retry configuration
	maxRetries int
	retryDelay time.Duration

	// Fallback behavior
	fallbackOnError string // "tempfail" or "reject"

	mu sync.RWMutex
}

// ClientConfig holds configuration for the routing client
type ClientConfig struct {
	Endpoint                string
	APIKey                  string
	TimeoutMS               int
	MaxRetries              int
	CacheTTLSeconds         int
	CacheNegativeTTLSeconds int
	CacheMaxEntries         int
	FallbackOnError         string // "tempfail" or "reject"
	CircuitBreaker          *poster.CircuitBreaker
	Logger                  *zap.Logger
}

// NewClient creates a new routing client
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("routing endpoint is required")
	}

	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	// Set defaults
	if cfg.TimeoutMS == 0 {
		cfg.TimeoutMS = 100
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 2
	}
	if cfg.CacheTTLSeconds == 0 {
		cfg.CacheTTLSeconds = 300 // 5 minutes
	}
	if cfg.CacheNegativeTTLSeconds == 0 {
		cfg.CacheNegativeTTLSeconds = 60 // 1 minute
	}
	if cfg.CacheMaxEntries == 0 {
		cfg.CacheMaxEntries = 50000
	}
	if cfg.FallbackOnError == "" {
		cfg.FallbackOnError = "tempfail"
	}

	httpClient := &http.Client{
		Timeout: time.Duration(cfg.TimeoutMS) * time.Millisecond,
	}

	// Create LRU cache for positive responses
	cache := expirable.NewLRU[string, *ResolveResponse](
		cfg.CacheMaxEntries,
		nil, // no eviction callback
		time.Duration(cfg.CacheTTLSeconds)*time.Second,
	)

	// Create a separate LRU cache for negative responses
	negativeCache := expirable.NewLRU[string, *ResolveResponse](
		cfg.CacheMaxEntries, // Use the same max entries for now
		nil,
		time.Duration(cfg.CacheNegativeTTLSeconds)*time.Second,
	)

	return &Client{
		endpoint:         cfg.Endpoint,
		apiKey:           cfg.APIKey,
		httpClient:       httpClient,
		circuitBreaker:   cfg.CircuitBreaker,
		logger:           cfg.Logger,
		cache:            cache,
		negativeCache:    negativeCache,
		cacheTTL:         time.Duration(cfg.CacheTTLSeconds) * time.Second,
		cacheNegativeTTL: time.Duration(cfg.CacheNegativeTTLSeconds) * time.Second,
		maxRetries:       cfg.MaxRetries,
		retryDelay:       50 * time.Millisecond,
		fallbackOnError:  cfg.FallbackOnError,
	}, nil
}

// Resolve looks up routing information for a recipient
func (c *Client) Resolve(ctx context.Context, recipient, sender, clientIP, subject string) (*ResolveResponse, error) {
	cacheKey := c.buildCacheKey(recipient, sender)

	// Check positive cache first
	if cached, ok := c.cache.Get(cacheKey); ok {
		c.logger.Debug("Routing cache hit (positive)",
			zap.String("recipient", recipient),
			zap.String("cache_key", cacheKey))
		return cached, nil
	}

	// Check negative cache
	if cached, ok := c.negativeCache.Get(cacheKey); ok {
		c.logger.Debug("Routing cache hit (negative)",
			zap.String("recipient", recipient),
			zap.String("cache_key", cacheKey))
		return cached, nil
	}

	// Cache miss - query the endpoint
	c.logger.Debug("Routing cache miss - querying endpoint",
		zap.String("recipient", recipient),
		zap.String("endpoint", c.endpoint))

	req := ResolveRequest{
		Recipient: recipient,
		Sender:    sender,
		ClientIP:  clientIP,
		Subject:   subject,
	}

	resp, err := c.queryEndpoint(ctx, req)
	if err != nil {
		c.logger.Warn("Routing lookup failed",
			zap.String("recipient", recipient),
			zap.Error(err))
		return nil, err
	}

	// Cache the result
	c.cacheResult(cacheKey, resp)

	return resp, nil
}

// queryEndpoint makes the HTTP request to the routing endpoint with retries
func (c *Client) queryEndpoint(ctx context.Context, req ResolveRequest) (*ResolveResponse, error) {
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			backoff := c.retryDelay * time.Duration(1<<uint(attempt-1))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		resp, err := c.makeHTTPRequest(ctx, req)
		if err == nil {
			return resp, nil
		}

		// Don't retry on non-retryable errors (e.g., 4xx)
		var nonRetryable *NonRetryableError
		if errors.As(err, &nonRetryable) {
			return nil, nonRetryable.Err
		}

		lastErr = err
		c.logger.Debug("Routing query attempt failed",
			zap.Int("attempt", attempt+1),
			zap.Int("max_retries", c.maxRetries+1),
			zap.Error(err))
	}

	return nil, fmt.Errorf("routing lookup failed after %d attempts: %w", c.maxRetries+1, lastErr)
}

// makeHTTPRequest performs the actual HTTP call with circuit breaker protection
func (c *Client) makeHTTPRequest(ctx context.Context, req ResolveRequest) (*ResolveResponse, error) {
	var result *ResolveResponse

	// This function is wrapped by the circuit breaker
	executeRequest := func() error {
		// Marshal request
		body, err := json.Marshal(req)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}

		// Create HTTP request
		httpReq, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("failed to create HTTP request: %w", err)
		}

		httpReq.Header.Set("Content-Type", "application/json")
		if c.apiKey != "" {
			httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
		}

		// Execute request
		httpResp, err := c.httpClient.Do(httpReq)
		if err != nil {
			return fmt.Errorf("HTTP request failed: %w", err)
		}
		defer httpResp.Body.Close()

		// Read response
		respBody, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}

		// Check status code
		if httpResp.StatusCode != http.StatusOK {
			err := fmt.Errorf("routing endpoint returned status %d: %s", httpResp.StatusCode, string(respBody))
			// 5xx errors are returned as retryable errors (circuit breaker will count them)
			if httpResp.StatusCode >= 500 {
				return err
			}
			// 4xx errors are wrapped in NonRetryableError
			return &NonRetryableError{Err: err}
		}

		// Parse response
		var resp ResolveResponse
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		result = &resp
		return nil
	}

	// Execute with circuit breaker
	if c.circuitBreaker != nil {
		if err := c.circuitBreaker.Call(executeRequest); err != nil {
			return nil, err
		}
	} else {
		if err := executeRequest(); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// cacheResult stores the result in the appropriate cache with appropriate TTL
func (c *Client) cacheResult(key string, resp *ResolveResponse) {
	if !resp.Accepted {
		// Cache negative responses in the negative cache
		c.negativeCache.Add(key, resp)
		c.logger.Debug("Cached routing result (negative)",
			zap.String("key", key),
			zap.Bool("accepted", resp.Accepted),
			zap.Duration("ttl", c.cacheNegativeTTL))
	} else {
		// Cache positive responses in the main cache
		c.cache.Add(key, resp)
		c.logger.Debug("Cached routing result (positive)",
			zap.String("key", key),
			zap.Bool("accepted", resp.Accepted),
			zap.Duration("ttl", c.cacheTTL))
	}
}

// buildCacheKey creates a cache key from request parameters
func (c *Client) buildCacheKey(recipient, sender string) string {
	// Use a combination of recipient and sender for more granular caching
	return fmt.Sprintf("%s:%s", recipient, sender)
}

// GetStats returns cache statistics
func (c *Client) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"cache_entries":          c.cache.Len(),
		"negative_cache_entries": c.negativeCache.Len(),
		"endpoint":               c.endpoint,
	}
}

// FlushCache clears all cached entries
func (c *Client) FlushCache() {
	c.cache.Purge()
	c.negativeCache.Purge()
	c.logger.Info("Routing caches flushed")
}

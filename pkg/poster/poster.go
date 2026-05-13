package poster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"log/slog"
)

// NewHTTPClient creates a new HTTP client with the specified timeout and connection pool settings.
// The timeout controls the maximum time for the entire request/response cycle.
// maxIdleConnsPerHost controls how many idle connections to keep per backend host (0 = use default 100).
// maxConnsPerHost limits total connections per host (0 = unlimited).
// idleConnTimeout controls how long idle connections stay in the pool (0 = use default 90s).
// These settings are critical for high-throughput relay scenarios — Go's default of 2 idle
// connections per host is insufficient when posting many emails to a single backend.
func NewHTTPClient(timeout time.Duration, maxIdleConnsPerHost, maxConnsPerHost int, idleConnTimeout time.Duration) *http.Client {
	// Apply sensible defaults if not configured
	if maxIdleConnsPerHost <= 0 {
		maxIdleConnsPerHost = 100
	}
	if idleConnTimeout <= 0 {
		idleConnTimeout = 90 * time.Second
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = maxIdleConnsPerHost * 2 // Total idle connections across all hosts
	transport.MaxIdleConnsPerHost = maxIdleConnsPerHost
	transport.MaxConnsPerHost = maxConnsPerHost // 0 = unlimited
	transport.IdleConnTimeout = idleConnTimeout

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

// PostEmailToDestinationWithContext sends the raw email content to the destination with retry logic and context support.
// It implements exponential backoff between retries and respects context cancellation.
// The isJunk parameter adds an X-Junk header to help the destination system handle spam appropriately.
// The mailFrom and mailTo parameters are added as X-Mail-From and X-Mail-To headers with envelope addresses.
// The traceID parameter is added as X-Trace-ID header for distributed tracing and log correlation.
// The authenticatedUser parameter is added as X-Auth-User header when the message was sent via authenticated submission.
// The circuitBreaker parameter is optional - if provided, each retry attempt will be protected by the circuit breaker.
// The httpClient parameter specifies the HTTP client to use for requests (with configured timeout).
func PostEmailToDestinationWithContext(ctx context.Context, rawEmail string, destinationURL, apiKey string, maxRetryAttempts int, isJunk bool, mailFrom string, mailTo []string, traceID string, authenticatedUser string, circuitBreaker *CircuitBreaker, httpClient *http.Client, logger *slog.Logger) error {
	return postEmailWithRetries(ctx, rawEmail, destinationURL, apiKey, maxRetryAttempts, isJunk, mailFrom, mailTo, traceID, authenticatedUser, circuitBreaker, httpClient, logger)
}

// postEmailWithRetries contains the actual retry logic with circuit breaker protection per attempt
func postEmailWithRetries(ctx context.Context, rawEmail string, destinationURL, apiKey string, maxRetryAttempts int, isJunk bool, mailFrom string, mailTo []string, traceID string, authenticatedUser string, circuitBreaker *CircuitBreaker, httpClient *http.Client, logger *slog.Logger) error {
	var lastErr error

	// Ensure at least one attempt even if configured incorrectly
	if maxRetryAttempts < 1 {
		maxRetryAttempts = 1
	}

	// Retry loop with exponential backoff
	for attempt := 0; attempt < maxRetryAttempts; attempt++ {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled: %w", ctx.Err())
		default:
		}

		// Implement exponential backoff between retries to avoid overwhelming the destination
		// Backoff sequence: 0s (first attempt), 1s, 2s, 4s, 8s, etc.
		if attempt > 0 {
			backoff := time.Duration(1<<(attempt-1)) * time.Second
			logger.Info(fmt.Sprintf("Retrying HTTP post to URL (attempt %d/%d) after %v delay", attempt+1, maxRetryAttempts, backoff))

			// Sleep with context awareness - allows early cancellation
			select {
			case <-time.After(backoff):
				// Continue after backoff
			case <-ctx.Done():
				return fmt.Errorf("context cancelled during backoff: %w", ctx.Err())
			}
		}

		// Execute this attempt with circuit breaker protection
		var err error
		if circuitBreaker != nil {
			// Circuit breaker protects each individual attempt
			err = circuitBreaker.Call(func() error {
				return postEmailAttemptWithContext(ctx, rawEmail, destinationURL, apiKey, isJunk, mailFrom, mailTo, traceID, authenticatedUser, httpClient, logger)
			})
		} else {
			// No circuit breaker - call directly
			err = postEmailAttemptWithContext(ctx, rawEmail, destinationURL, apiKey, isJunk, mailFrom, mailTo, traceID, authenticatedUser, httpClient, logger)
		}

		if err == nil {
			// Success
			return nil
		}

		lastErr = err

		// Determine if the error warrants a retry
		// Non-retryable errors (like 4xx HTTP codes) fail immediately
		if !IsRetryableError(err) {
			logger.Warn(fmt.Sprintf("Non-retryable error posting to URL: %v", err))
			return err
		}

		if attempt < maxRetryAttempts-1 {
			logger.Warn(fmt.Sprintf("Retryable error posting to URL (attempt %d/%d): %v", attempt+1, maxRetryAttempts, err))
		}
	}

	// All retries exhausted
	logger.Error(fmt.Sprintf("All retry attempts exhausted (%d/%d) posting to URL: %v", maxRetryAttempts, maxRetryAttempts, lastErr))
	return fmt.Errorf("failed after %d attempts: %w", maxRetryAttempts, lastErr)
}

// postEmailAttemptWithContext performs a single attempt to post the email with context support.
// It sends the raw email as message/rfc822 content type with API key authentication.
func postEmailAttemptWithContext(ctx context.Context, rawEmail string, destinationURL, apiKey string, isJunk bool, mailFrom string, mailTo []string, traceID string, authenticatedUser string, httpClient *http.Client, logger *slog.Logger) error {
	if httpClient == nil {
		return fmt.Errorf("httpClient cannot be nil")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", destinationURL, strings.NewReader(rawEmail))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set standard headers for email relay
	req.Header.Set("Content-Type", "message/rfc822") // RFC 2822 compliant email format

	// Only set API key if provided (custom endpoints may use URL-based auth)
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey) // Bearer token authentication
	}

	// Add envelope addresses as headers
	if mailFrom != "" {
		req.Header.Set("X-Mail-From", mailFrom)
	}
	if len(mailTo) > 0 {
		req.Header.Set("X-Mail-To", strings.Join(mailTo, ", "))
	}

	// Add trace ID for distributed tracing and log correlation
	if traceID != "" {
		req.Header.Set("X-Trace-ID", traceID)
	}

	// Add authenticated user if message was sent via authenticated submission
	if authenticatedUser != "" {
		req.Header.Set("X-Auth-User", authenticatedUser)
	}

	// Signal to destination that this message was classified as junk/spam
	if isJunk {
		req.Header.Set("X-Junk", "yes")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request to URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return NewHTTPStatusError(resp.StatusCode, string(bodyBytes))
	}

	logger.Info(fmt.Sprintf("Successfully sent email to destination URL, status: %d", resp.StatusCode))
	return nil
}

// IsRetryableError determines if an error should trigger a retry.
// Returns false for permanent failures (4xx HTTP codes, context cancellation).
// Returns true for temporary failures (5xx codes, network errors, timeouts).
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Circuit breaker being open is a temporary, retryable state.
	if errors.Is(err, ErrCircuitOpen) {
		return true
	}

	// Check if it's an HTTP status error with specific retry logic
	var httpErr *HTTPStatusError
	if errors.As(err, &httpErr) {
		return httpErr.IsRetryable() // 5xx errors are retryable, 4xx are not
	}

	// Context errors indicate intentional cancellation - don't retry
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Check for specific network errors that are generally retryable.
	var netErr net.Error
	if errors.As(err, &netErr) {
		// Timeouts are always retryable
		if netErr.Timeout() {
			return true
		}

		// DNS lookup errors can be temporary
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			return true
		}

		// Connection refused is retryable (server may come back up)
		if strings.Contains(err.Error(), "connection refused") {
			return true
		}

		// Connection reset / broken pipe are retryable
		if strings.Contains(err.Error(), "connection reset") || strings.Contains(err.Error(), "broken pipe") {
			return true
		}

		return false
	}

	// Default to non-retryable for unknown errors to avoid infinite retry loops on unexpected issues.
	return false
}

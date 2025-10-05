package poster

import (
	"errors"
	"fmt"
)

// Error types for HTTP posting
var (
	// Network errors (retryable)
	ErrConnectionRefused = errors.New("connection refused")
	ErrConnectionReset   = errors.New("connection reset")
	ErrTimeout           = errors.New("timeout")
	ErrNoSuchHost        = errors.New("no such host")
	ErrTemporaryFailure  = errors.New("temporary failure")

	// Context errors (non-retryable)
	ErrContextCancelled = errors.New("context cancelled")
	ErrContextTimeout   = errors.New("context deadline exceeded")
)

// HTTPStatusError represents an HTTP response error with status code
type HTTPStatusError struct {
	StatusCode int
	Body       string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("URL returned non-success status: %d, body: %s", e.StatusCode, e.Body)
}

// IsRetryable returns true if the status code indicates a retryable error
func (e *HTTPStatusError) IsRetryable() bool {
	// 5xx server errors are retryable
	if e.StatusCode >= 500 && e.StatusCode < 600 {
		return true
	}
	// 429 Too Many Requests is retryable (rate limiting)
	if e.StatusCode == 429 {
		return true
	}
	return false
}

// IsRecipientNotFound returns true if the status code indicates recipient not found (404)
func (e *HTTPStatusError) IsRecipientNotFound() bool {
	return e.StatusCode == 404
}

// IsRecipientBlocked returns true if the status code indicates recipient is blocked (403)
func (e *HTTPStatusError) IsRecipientBlocked() bool {
	return e.StatusCode == 403
}

// NewHTTPStatusError creates a new HTTPStatusError
func NewHTTPStatusError(statusCode int, body string) *HTTPStatusError {
	return &HTTPStatusError{
		StatusCode: statusCode,
		Body:       body,
	}
}

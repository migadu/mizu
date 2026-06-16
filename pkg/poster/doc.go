// Package poster handles HTTP delivery of emails to the destination backend.
//
// # Overview
//
// The poster package provides functions to POST emails to an HTTP endpoint
// with retry logic and circuit breaker protection. It ensures reliable
// delivery while protecting the backend from being overwhelmed.
//
// # Synchronous Delivery
//
// Mizu's core principle is "zero message loss" through synchronous delivery:
//
//  1. Receive email via SMTP
//  2. POST to HTTP backend
//  3. Wait for 200/202 response
//  4. Send SMTP 250 OK only after successful HTTP response
//
// There is NO internal queue - delivery happens during the SMTP session.
// If the backend is unavailable, SMTP returns 4xx (temporary failure) and
// the sending server will retry later.
//
// # Circuit Breaker and Retry Interaction
//
// The circuit breaker protects each individual retry attempt (NOT the entire retry loop):
//
//	States:
//	  - Closed: Normal operation, requests pass through
//	  - Open: Too many failures, fail fast but still allow retries
//	  - HalfOpen: Testing if backend has recovered
//
//	Transitions:
//	  Closed → Open: After N consecutive failures (default: 5)
//	  Open → HalfOpen: After timeout (default: 30s)
//	  HalfOpen → Closed: After M successes (default: 2)
//	  HalfOpen → Open: On any failure
//
// IMPORTANT: When the circuit is open, individual attempts fail fast with ErrCircuitOpen,
// but this error is marked as retryable. This means:
//
//  1. Circuit breaker protects backend from being overwhelmed
//  2. Retry logic continues attempting delivery (with exponential backoff)
//  3. If backend recovers during retry window, message is delivered
//  4. If all retries fail, SMTP returns 451 (temporary failure)
//
// This design prevents message loss while still protecting the backend.
//
// # Retry Logic
//
// Failed deliveries are retried with exponential backoff:
//
//	Attempt 1: Immediate
//	Attempt 2: 1s delay
//	Attempt 3: 2s delay
//	Maximum attempts: Configurable (default: 3)
//
// Only temporary failures are retried:
//
//	Network errors: Connection refused, timeout, DNS failure
//	HTTP 5xx errors: 500, 502, 503, 504
//
// Permanent failures are NOT retried:
//
//	HTTP 4xx errors: 400, 404, 403 (except 429)
//	HTTP 429: Rate limit (returned as SMTP 451)
//
// # HTTP Request Format
//
// Emails are posted as message/rfc822 with envelope information in headers:
//
//	POST /email HTTP/1.1
//	Host: backend.example.com
//	Content-Type: message/rfc822
//	Authorization: Bearer secret-key
//	X-Trace-ID: unique-trace-id
//	X-Mail-From: sender@example.com
//	X-Mail-To: recipient@example.com
//	X-Junk: yes  # Only present if spam detected
//
//	[Raw RFC 822 email content]
//
// The backend should respond with:
//
//	200 OK: Message accepted and processed
//	202 Accepted: Message queued for processing
//	404 Not Found: Recipient doesn't exist (permanent failure)
//	403 Forbidden: Recipient blocked (permanent failure)
//	429 Too Many Requests: Rate limited (temporary failure)
//	5xx Server Error: Backend error (temporary failure)
//
// # Recipient Caching
//
// 404 (not found) and 403 (blocked) responses can be cached to avoid
// repeated backend calls for invalid recipients. The cache is cluster-wide
// when distributed mode is enabled.
//
// # Error Types
//
// The package defines custom error types for different failure scenarios:
//
//	HTTPStatusError: HTTP response with non-2xx status code
//	NetworkError: Connection or DNS failure
//	TimeoutError: Request timed out
//
// These allow the SMTP layer to return appropriate SMTP error codes.
//
// # Metrics
//
// All HTTP requests are instrumented with Prometheus metrics:
//
//	mizu_http_requests_total{status_code}: Total requests by status code
//	mizu_http_request_duration_seconds: Request latency histogram
//	mizu_http_request_size_bytes: Request body size
//	mizu_http_response_size_bytes: Response body size
//	mizu_circuit_breaker_state: Current circuit breaker state
//	mizu_circuit_breaker_failures_total: Total failures
//	mizu_circuit_breaker_rejects_total: Requests rejected due to open circuit
//
// # Example Usage
//
//	err := poster.PostEmailToDestinationWithContext(
//	    ctx,
//	    rawEmail,
//	    "https://backend.example.com/email",
//	    "api-key-secret",
//	    3,  // max retry attempts
//	    false,  // is_junk
//	    "sender@example.com",
//	    "recipient@example.com",
//	    "trace-id-123",
//	    circuitBreaker,
//	    httpClient,
//	    logger,
//	)
//	if err != nil {
//	    var httpErr *poster.HTTPStatusError
//	    if errors.As(err, &httpErr) {
//	        // Handle HTTP error
//	        if httpErr.IsRecipientNotFound() {
//	            // Return SMTP 550
//	        }
//	    }
//	}
//
// # Thread Safety
//
// All functions are thread-safe. The circuit breaker uses atomic operations
// and mutexes for state management.
package poster

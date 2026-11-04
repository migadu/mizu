package poster

import (
	"errors"
	"testing"
)

func TestHTTPStatusError_Error(t *testing.T) {
	err := NewHTTPStatusError(500, "Internal Server Error")

	expected := "URL returned non-success status: 500, body: Internal Server Error"
	if err.Error() != expected {
		t.Errorf("Error() = %q; want %q", err.Error(), expected)
	}
}

func TestHTTPStatusError_IsRetryable(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		expected   bool
	}{
		{
			name:       "500 Internal Server Error",
			statusCode: 500,
			expected:   true,
		},
		{
			name:       "502 Bad Gateway",
			statusCode: 502,
			expected:   true,
		},
		{
			name:       "503 Service Unavailable",
			statusCode: 503,
			expected:   true,
		},
		{
			name:       "504 Gateway Timeout",
			statusCode: 504,
			expected:   true,
		},
		{
			name:       "400 Bad Request",
			statusCode: 400,
			expected:   false,
		},
		{
			name:       "401 Unauthorized",
			statusCode: 401,
			expected:   false,
		},
		{
			name:       "404 Not Found",
			statusCode: 404,
			expected:   false,
		},
		{
			name:       "200 OK",
			statusCode: 200,
			expected:   false,
		},
		{
			name:       "300 Multiple Choices",
			statusCode: 300,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewHTTPStatusError(tt.statusCode, "test body")
			result := err.IsRetryable()

			if result != tt.expected {
				t.Errorf("IsRetryable() = %v; want %v for status %d", result, tt.expected, tt.statusCode)
			}
		})
	}
}

// A 422 is mailqueuer's verdict on the address: permanent, and not retried.
func TestHTTPStatusError_IsInvalidRecipient(t *testing.T) {
	for _, tt := range []struct {
		statusCode int
		expected   bool
	}{
		{422, true},
		{400, false},
		{404, false},
		{500, false},
	} {
		err := NewHTTPStatusError(tt.statusCode, "test body")
		if got := err.IsInvalidRecipient(); got != tt.expected {
			t.Errorf("IsInvalidRecipient() = %v; want %v for status %d", got, tt.expected, tt.statusCode)
		}
	}
	if NewHTTPStatusError(422, "test body").IsRetryable() {
		t.Error("IsRetryable() = true for 422; want false")
	}
}

func TestNewHTTPStatusError(t *testing.T) {
	statusCode := 404
	body := "Not Found"

	err := NewHTTPStatusError(statusCode, body)

	if err == nil {
		t.Fatal("NewHTTPStatusError returned nil")
	}

	if err.StatusCode != statusCode {
		t.Errorf("StatusCode = %d; want %d", err.StatusCode, statusCode)
	}

	if err.Body != body {
		t.Errorf("Body = %q; want %q", err.Body, body)
	}
}

func TestAsHTTPStatusError(t *testing.T) {
	// Create an HTTPStatusError
	httpErr := NewHTTPStatusError(500, "Internal Server Error")

	// Wrap it in another error
	wrappedErr := errors.New("wrapped: " + httpErr.Error())

	// Test with direct HTTPStatusError
	var extractedErr *HTTPStatusError
	if !errors.As(httpErr, &extractedErr) {
		t.Error("errors.As should work with HTTPStatusError")
	}

	if extractedErr.StatusCode != 500 {
		t.Errorf("extracted StatusCode = %d; want 500", extractedErr.StatusCode)
	}

	// Test with non-HTTPStatusError
	var extractedErr2 *HTTPStatusError
	if errors.As(wrappedErr, &extractedErr2) {
		t.Error("errors.As should not match wrapped error without proper wrapping")
	}
}

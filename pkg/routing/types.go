package routing

import "time"

// ResolveRequest represents a request to resolve a recipient address
type ResolveRequest struct {
	Recipient string `json:"recipient"`           // The recipient email address to validate
	Sender    string `json:"sender,omitempty"`    // Optional: sender email for policy checks
	ClientIP  string `json:"client_ip,omitempty"` // Optional: client IP for policy checks
	Subject   string `json:"subject,omitempty"`   // Optional: email subject for policy checks
}

// ResolveResponse represents the routing decision from the endpoint
type ResolveResponse struct {
	Accepted  bool     `json:"accepted"`             // Whether to accept mail for this recipient
	DeliverTo []string `json:"deliver_to,omitempty"` // Final recipients for local delivery (internal)
	ForwardTo []string `json:"forward_to,omitempty"` // External addresses to forward to (relay)

	// Separate endpoints for delivery vs forwarding
	DeliveryEndpoint string `json:"delivery_endpoint,omitempty"` // HTTP endpoint for local delivery (DeliverTo)
	ForwardEndpoint  string `json:"forward_endpoint,omitempty"`  // SMTP/HTTP endpoint for forwarding (ForwardTo)

	IsCatchall bool `json:"is_catchall,omitempty"` // Whether this matched a catchall rule

	// Priority for queueing
	Priority int `json:"priority,omitempty"` // Job priority for queueing

	// Error information if not accepted
	ErrorCode    string `json:"error_code,omitempty"`    // Machine-readable error code
	ErrorMessage string `json:"error_message,omitempty"` // Human-readable error message
}

// CachedResult represents a cached routing lookup result
type CachedResult struct {
	Response *ResolveResponse
	CachedAt time.Time
	TTL      time.Duration
}

// IsExpired checks if the cached result has expired
func (c *CachedResult) IsExpired() bool {
	return time.Since(c.CachedAt) > c.TTL
}

// Error codes returned by routing endpoint
const (
	ErrorCodeDomainNotFound    = "domain_not_found"
	ErrorCodeRecipientNotFound = "recipient_not_found"
	ErrorCodeRecipientBlocked  = "recipient_blocked"
	ErrorCodePolicyRejection   = "policy_rejection"
	ErrorCodeQuotaExceeded     = "quota_exceeded"
)

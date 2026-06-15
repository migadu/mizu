// Package spamcheck provides external spam checking integration for Mizu SMTP server.
//
// This package implements rspamd HTTP protocol v2 for spam detection and classification.
// It supports HTTPCrypt authentication, configurable spam headers, and action-based rejection.
//
// # Basic Usage
//
// Create a client and adapter:
//
//	client := spamcheck.NewClient(
//	    "http://rspamd:11333/checkv2",
//	    "secret-password",  // HTTPCrypt password (optional)
//	    5*time.Second,      // HTTP timeout
//	    logger,
//	)
//
//	adapter := spamcheck.NewAdapter(
//	    client,
//	    "X-Junk",     // spam header name
//	    "yes",        // spam header value
//	    "",           // ham header value (empty = don't add for ham)
//	    "reject",     // reject if rspamd action matches this
//	)
//
// Use in SMTP session:
//
//	result, err := adapter.Check(ctx, message, clientIP, from, recipients, helo)
//	if err != nil {
//	    // Handle error (fail open for availability)
//	}
//
//	if result.ShouldReject {
//	    return smtp.ErrSpamRejected
//	}
//
//	if result.IsSpam {
//	    // Add spam headers from result.AddHeaders
//	}
//
// # Rspamd Protocol
//
// This implementation supports rspamd HTTP protocol v2:
//
//   - Endpoint: POST /checkv2
//   - Request headers: IP, From, Rcpt, Helo
//   - Request body: Raw email message
//   - Response: JSON with action, score, symbols, milter headers
//
// Supported actions:
//   - "no action": Message is not spam
//   - "greylist": Temporary rejection (not implemented)
//   - "add header": Add spam header to message
//   - "rewrite subject": Modify subject line (header provided in milter)
//   - "reject": Reject message as spam
//
// # HTTPCrypt Authentication
//
// If a password is configured, the client will use HTTPCrypt authentication:
//
//	signature = HMAC-SHA256(nonce, password)
//	Headers:
//	  Password: <hex-encoded signature>
//	  Nonce: <unix timestamp>
//
// # Configuration
//
// Configuration in TOML:
//
//	[server.spam_check]
//	enabled = true
//	url = "http://rspamd:11333/checkv2"
//	password = "secret"
//	http_timeout_seconds = 15
//	spam_header = "X-Junk"
//	spam_header_value = "yes"
//	ham_header_value = ""
//	reject_on_action = "reject"
//
// # Error Handling
//
// The spam checker fails open by design:
//   - Network errors: Don't reject message, log warning
//   - Timeout errors: Don't reject message, log warning
//   - Parse errors: Don't reject message, log error
//
// This ensures email delivery is not disrupted by spam checker unavailability.
package spamcheck

package spamcheck

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Client is an HTTP client for checking messages against rspamd
type Client struct {
	URL        string       // Rspamd URL (e.g., "http://rspamd:11333/checkv2")
	HTTPClient *http.Client // Reusable HTTP client
	Password   string       // HTTPCrypt password (optional)
	Logger     *slog.Logger // Logger for debugging
}

// CheckResult contains the spam check result from rspamd
type CheckResult struct {
	Action        string             // Rspamd action: "reject", "add header", "rewrite subject", etc.
	Score         float64            // Spam score
	RequiredScore float64            // Threshold score for spam classification
	IsSpam        bool               // True if action is "add header", "rewrite subject", or "reject"
	AddHeaders    map[string]string  // Headers to add (from milter.add_headers)
	Symbols       map[string]float64 // Triggered spam rules and their scores
}

// rspamdResponse represents the JSON response from rspamd HTTP protocol v2
type rspamdResponse struct {
	Action        string                  `json:"action"`
	Score         float64                 `json:"score"`
	RequiredScore float64                 `json:"required_score"`
	Symbols       map[string]rspamdSymbol `json:"symbols"`
	Milter        *rspamdMilter           `json:"milter,omitempty"`
}

// rspamdSymbol represents a triggered spam rule
type rspamdSymbol struct {
	Score       float64  `json:"score"`
	Description string   `json:"description,omitempty"`
	Options     []string `json:"options,omitempty"`
}

// rspamdMilter contains headers and actions for modifying the message
type rspamdMilter struct {
	AddHeaders    map[string]rspamdHeader `json:"add_headers,omitempty"`
	RemoveHeaders map[string]int          `json:"remove_headers,omitempty"`
}

// rspamdHeader represents a header to add (with order)
type rspamdHeader struct {
	Value string `json:"value"`
	Order int    `json:"order"`
}

// NewClient creates a new rspamd spam check client
func NewClient(url, password string, timeout time.Duration, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}

	return &Client{
		URL:      url,
		Password: password,
		HTTPClient: &http.Client{
			Timeout: timeout,
		},
		Logger: logger,
	}
}

// Check sends a message to rspamd for spam checking
// Parameters:
//   - ctx: Context for request cancellation
//   - message: Raw email message (headers + body)
//   - clientIP: IP address of the SMTP client
//   - from: MAIL FROM address
//   - rcpt: RCPT TO addresses
//   - helo: HELO/EHLO hostname
func (c *Client) Check(ctx context.Context, message, clientIP, from string, rcpt []string, helo string) (*CheckResult, error) {
	// Prepare request
	req, err := http.NewRequestWithContext(ctx, "POST", c.URL, bytes.NewReader([]byte(message)))
	if err != nil {
		return nil, fmt.Errorf("failed to create rspamd request: %w", err)
	}

	// Set rspamd protocol v2 headers
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("User-Agent", "Mizu-SMTP/1.0")

	// Add message metadata headers
	if clientIP != "" {
		req.Header.Set("IP", clientIP)
	}
	if from != "" {
		req.Header.Set("From", from)
	}
	if len(rcpt) > 0 {
		// Rspamd expects multiple Rcpt headers for multiple recipients
		for _, r := range rcpt {
			req.Header.Add("Rcpt", r)
		}
	}
	if helo != "" {
		req.Header.Set("Helo", helo)
	}

	// Add HTTPCrypt authentication if password is configured
	if c.Password != "" {
		nonce := fmt.Sprintf("%d", time.Now().Unix())
		signature := c.generateHTTPCryptSignature(nonce)
		req.Header.Set("Password", signature)
		req.Header.Set("Nonce", nonce)
	}

	// Send request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rspamd request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("rspamd returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse JSON response
	var rspamdResp rspamdResponse
	if err := json.NewDecoder(resp.Body).Decode(&rspamdResp); err != nil {
		return nil, fmt.Errorf("failed to parse rspamd response: %w", err)
	}

	// Build result
	result := &CheckResult{
		Action:        rspamdResp.Action,
		Score:         rspamdResp.Score,
		RequiredScore: rspamdResp.RequiredScore,
		AddHeaders:    make(map[string]string),
		Symbols:       make(map[string]float64),
	}

	// Determine if message is spam based on action
	action := strings.ToLower(rspamdResp.Action)
	result.IsSpam = action == "add header" || action == "rewrite subject" || action == "reject"

	// Extract headers to add from milter section
	if rspamdResp.Milter != nil && rspamdResp.Milter.AddHeaders != nil {
		for name, header := range rspamdResp.Milter.AddHeaders {
			result.AddHeaders[name] = header.Value
		}
	}

	// Extract symbol scores for debugging
	for name, symbol := range rspamdResp.Symbols {
		result.Symbols[name] = symbol.Score
	}

	c.Logger.Debug("Rspamd check completed",
		"action", result.Action,
		"score", result.Score,
		"required_score", result.RequiredScore,
		"is_spam", result.IsSpam,
		"symbols_count", len(result.Symbols))

	return result, nil
}

// generateHTTPCryptSignature creates HMAC-SHA256 signature for rspamd authentication
// Format: HMAC-SHA256(nonce, password)
func (c *Client) generateHTTPCryptSignature(nonce string) string {
	h := hmac.New(sha256.New, []byte(c.Password))
	h.Write([]byte(nonce))
	return hex.EncodeToString(h.Sum(nil))
}

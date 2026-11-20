package spamcheck

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
)

// Rspamd actions as returned in the checkv2 response "action" field.
// See https://rspamd.com/doc/architecture/protocol.html#rspamd-actions
const (
	ActionNoAction       = "no action"       // Message is clean (ham)
	ActionGreylist       = "greylist"        // Greylist: ask sender to retry later
	ActionAddHeader      = "add header"      // Mark as spam via header
	ActionRewriteSubject = "rewrite subject" // Mark as spam by rewriting subject
	ActionSoftReject     = "soft reject"     // Temporary rejection (defer, SMTP 4xx)
	ActionReject         = "reject"          // Permanent rejection (SMTP 5xx)
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
	Action        string              // Rspamd action: "reject", "add header", "rewrite subject", etc.
	Score         float64             // Spam score
	RequiredScore float64             // Threshold score for spam classification
	IsSpam        bool                // True if action is "add header", "rewrite subject", or "reject"
	AddHeaders    map[string][]string // Headers to add (from milter.add_headers); a key may have multiple values when rspamd asks for the same header to be added more than once (e.g. Authentication-Results)
	Symbols       map[string]float64  // Triggered spam rules and their scores
	SMTPMessage   string              // Custom SMTP reply text from rspamd's messages.smtp_message (set via set_pre_result), sanitized to a single line; empty if rspamd sent none
}

// rspamdResponse represents the JSON response from rspamd HTTP protocol v2
type rspamdResponse struct {
	Action        string                  `json:"action"`
	Score         float64                 `json:"score"`
	RequiredScore float64                 `json:"required_score"`
	Symbols       map[string]rspamdSymbol `json:"symbols"`
	Milter        *rspamdMilter           `json:"milter,omitempty"`
	// Messages carries rspamd's out-of-band notices. The SMTP reply text a
	// module sets via task:set_pre_result(action, message, ...) arrives here
	// under the "smtp_message" key. Kept as RawMessage because rspamd's
	// protocol has historically encoded this field as both an object and an
	// array; a tolerant extractor (extractSMTPMessage) avoids failing the
	// whole decode on the shape we don't expect.
	Messages json.RawMessage `json:"messages,omitempty"`
}

// maxResponseBytes bounds how much of an rspamd reply is read.
const maxResponseBytes = 64 << 20

// bodyExcerpt is the start of a reply, for logs and error text: the whole
// reply can be tens of megabytes.
func bodyExcerpt(body []byte) string {
	const max = 2048
	if len(body) > max {
		return string(body[:max]) + "...(truncated)"
	}
	return string(body)
}

// rspamdSymbol represents a triggered spam rule
type rspamdSymbol struct {
	Score       float64  `json:"score"`
	Description string   `json:"description,omitempty"`
	Options     []string `json:"options,omitempty"`
}

// rspamdMilter contains headers and actions for modifying the message
type rspamdMilter struct {
	AddHeaders map[string]rspamdHeaderList `json:"add_headers,omitempty"`
}

// rspamdHeader represents a single header entry to add. Rspamd may return
// either a string value or an object {"value": "...", "order": 0}.
type rspamdHeader struct {
	Value string `json:"value"`
	Order int    `json:"order"`
}

func (h *rspamdHeader) UnmarshalJSON(data []byte) error {
	// Try string first
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		h.Value = s
		return nil
	}
	// Fall back to object
	type alias rspamdHeader
	var obj alias
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	*h = rspamdHeader(obj)
	return nil
}

// rspamdHeaderList holds one or more header entries for a single header
// name. Rspamd returns a string or object for a single value, or an array
// of strings/objects when the same header should be added multiple times
// (commonly seen with Authentication-Results when several ARC instances
// or chained results are present).
type rspamdHeaderList []rspamdHeader

func (l *rspamdHeaderList) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var arr []rspamdHeader
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*l = arr
		return nil
	}
	var single rspamdHeader
	if err := json.Unmarshal(data, &single); err != nil {
		return err
	}
	// Treat `null` (or any payload that yields no value) as an empty list so
	// callers don't emit a bodyless `Name: \r\n` header line.
	if single.Value == "" {
		*l = nil
		return nil
	}
	*l = rspamdHeaderList{single}
	return nil
}

// NewClient creates a new rspamd spam check client
//
// TODO: give the rspamd client its own *http.Transport with an
// IdleConnTimeout shorter than rspamd's default keepalive (65s — so
// ~30s here). Today we share http.DefaultTransport, whose 90s
// IdleConnTimeout guarantees the 65–90s stale window where pooled
// sockets RST on next use; the retry in Check papers over that.
// Optionally, once the transport is dedicated, CloseIdleConnections()
// could be called before the retry to flush sibling stale sockets
// from the same pool — safe to do only on a dedicated transport,
// since the global pool is shared with the rest of the process.
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
//   - authenticatedUser: SMTP AUTH username (empty for unauthenticated mail);
//     sent as rspamd's "User" header so rspamd treats it as authenticated
//     outbound submission
func (c *Client) Check(ctx context.Context, traceID, message, clientIP, from string, rcpt []string, helo, authenticatedUser string) (*CheckResult, error) {
	msgBytes := []byte(message)

	// rspamd /checkv2 is effectively idempotent, but POSTs are not retried
	// by the Go http.Client. A stale pooled connection (rspamd closes idle
	// workers faster than our IdleConnTimeout) surfaces here as RST or EOF
	// mid-response. Retry once on those transport-level glitches before
	// surfacing the error.
	bodyBytes, status, err := c.doCheckOnce(ctx, traceID, msgBytes, clientIP, from, rcpt, helo, authenticatedUser)
	if err != nil && isBrokenConnErr(err) {
		c.Logger.Debug("Retrying rspamd request after broken connection", "error", err)
		bodyBytes, status, err = c.doCheckOnce(ctx, traceID, msgBytes, clientIP, from, rcpt, helo, authenticatedUser)
	}
	if err != nil {
		return nil, err
	}

	// Log full rspamd response for debugging empty-action results. Logged
	// BEFORE the status check so we capture 504/statistics-error fail-open
	// bodies too. Debug level — set logger to debug to see it.
	c.Logger.Debug("Rspamd raw response",
		"trace_id", traceID,
		"status", status,
		"body", bodyExcerpt(bodyBytes))

	// Rspamd may return 504 when autolearn/statistics fails even though the
	// scan itself succeeded. The body contains a JSON error (not a scan result),
	// so we log and return a nil result rather than an error — fail open.
	if status != http.StatusOK {
		if status == http.StatusGatewayTimeout && isStatisticsError(bodyBytes) {
			c.Logger.Debug("Ignoring rspamd statistics error (autolearn failure)", "body", bodyExcerpt(bodyBytes))
			return &CheckResult{AddHeaders: map[string][]string{}, Symbols: map[string]float64{}}, nil
		}
		return nil, fmt.Errorf("rspamd returned status %d: %s", status, bodyExcerpt(bodyBytes))
	}

	// Parse JSON response
	var rspamdResp rspamdResponse
	if err := json.Unmarshal(bodyBytes, &rspamdResp); err != nil {
		return nil, fmt.Errorf("failed to parse rspamd response: %w", err)
	}

	// Build result
	result := &CheckResult{
		Action:        rspamdResp.Action,
		Score:         rspamdResp.Score,
		RequiredScore: rspamdResp.RequiredScore,
		AddHeaders:    make(map[string][]string),
		Symbols:       make(map[string]float64),
	}

	// Determine if message is spam based on action
	action := strings.ToLower(rspamdResp.Action)
	result.IsSpam = action == ActionAddHeader || action == ActionRewriteSubject || action == ActionReject

	// Custom SMTP reply text a module attached to the verdict (e.g. the
	// migadu_counters plugin's "Reached account outgoing limits ..."). Passed
	// through to the SMTP client on reject/defer; sanitized so it can't inject
	// extra reply lines.
	result.SMTPMessage = sanitizeSMTPMessage(extractSMTPMessage(rspamdResp.Messages))

	// Extract headers to add from milter section. Rspamd uses `order` to
	// disambiguate entries that share a header name (e.g. multiple
	// Authentication-Results lines for chained ARC instances). JSON array
	// order usually matches but isn't guaranteed by the protocol, so we
	// sort explicitly. Empty values are skipped so we never emit a
	// bodyless header line.
	if rspamdResp.Milter != nil && rspamdResp.Milter.AddHeaders != nil {
		for name, headers := range rspamdResp.Milter.AddHeaders {
			ordered := append(rspamdHeaderList(nil), headers...)
			sort.SliceStable(ordered, func(i, j int) bool {
				return ordered[i].Order < ordered[j].Order
			})
			values := make([]string, 0, len(ordered))
			for _, h := range ordered {
				if h.Value == "" {
					continue
				}
				values = append(values, h.Value)
			}
			if len(values) > 0 {
				result.AddHeaders[name] = values
			}
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

// headerValue drops the bytes net/http rejects in a header field value (ASCII
// control characters and DEL), so a client-supplied envelope value can never
// make the transport refuse the whole request.
func headerValue(v string) string {
	clean := true
	for i := 0; i < len(v); i++ {
		if c := v[i]; c < 0x20 || c == 0x7f {
			clean = false
			break
		}
	}
	if clean {
		return v
	}
	b := make([]byte, 0, len(v))
	for i := 0; i < len(v); i++ {
		if c := v[i]; c >= 0x20 && c != 0x7f {
			b = append(b, c)
		}
	}
	return string(b)
}

// doCheckOnce performs a single rspamd /checkv2 round trip, returning the
// response body and status code. Transport-level failures are returned
// wrapped with the existing "rspamd request failed" / "failed to read
// rspamd response" prefixes so the caller can decide whether to retry.
func (c *Client) doCheckOnce(ctx context.Context, traceID string, msgBytes []byte, clientIP, from string, rcpt []string, helo, authenticatedUser string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.URL, bytes.NewReader(msgBytes))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create rspamd request: %w", err)
	}

	// Set rspamd protocol v2 headers
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("User-Agent", "Mizu-SMTP/1.0")

	// Pass our trace ID as the rspamd Queue-ID so rspamd records it in its
	// own logs, letting us correlate a Mizu trace with the matching scan.
	if traceID != "" {
		req.Header.Set("Queue-ID", headerValue(traceID))
	}

	// Add message metadata headers. Every value below originates from the
	// SMTP client, so each goes through headerValue: net/http refuses to send
	// a request whose header value holds a control byte, and a refused scan
	// fails open in the session - one such byte must never skip the scan.
	if clientIP != "" {
		req.Header.Set("IP", headerValue(clientIP))
	}
	if from != "" {
		req.Header.Set("From", headerValue(from))
	}
	if len(rcpt) > 0 {
		// Rspamd expects multiple Rcpt headers for multiple recipients
		for _, r := range rcpt {
			req.Header.Add("Rcpt", headerValue(r))
		}
	}
	if helo != "" {
		req.Header.Set("Helo", headerValue(helo))
	}

	// Pass the SMTP AUTH username as rspamd's "User" header. Rspamd uses this
	// to identify authenticated senders and apply its authenticated/outbound
	// settings (skip inbound-only checks, sign outgoing mail with DKIM/ARC).
	// Empty for unauthenticated relay/inbound mail, in which case the header
	// is omitted so rspamd scans the message as ordinary inbound traffic.
	if authenticatedUser != "" {
		req.Header.Set("User", headerValue(authenticatedUser))
	}

	// Add HTTPCrypt authentication if password is configured.
	// UnixNano gives distinct nonces for back-to-back retries in the same
	// second; rspamd treats the nonce as opaque HMAC input so the format
	// doesn't matter, only that consecutive calls don't collide.
	if c.Password != "" {
		nonce := fmt.Sprintf("%d", time.Now().UnixNano())
		signature := c.generateHTTPCryptSignature(nonce)
		req.Header.Set("Password", signature)
		req.Header.Set("Nonce", nonce)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("rspamd request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read full response body once for both status-check and decode paths.
	// The cap only guards against a runaway peer. It has to sit well above
	// anything a real scan produces: rspamd echoes every URL and address it
	// found, so the reply grows with the message, and a reply cut short does
	// not parse - the scan would fail open for exactly the messages built to
	// be large.
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read rspamd response: %w", err)
	}
	if len(bodyBytes) > maxResponseBytes {
		return nil, resp.StatusCode, fmt.Errorf("rspamd response exceeds %d bytes", maxResponseBytes)
	}
	return bodyBytes, resp.StatusCode, nil
}

// isBrokenConnErr reports whether err looks like a transport-level glitch
// from a half-dead TCP connection (commonly a pooled keep-alive socket
// that the server already closed). Context cancellation and deadline
// exceeded are explicitly excluded so we don't retry past the caller's
// deadline.
func isBrokenConnErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	return false
}

// isStatisticsError returns true when the body is an rspamd JSON error whose
// error_domain is "rspamd-statistics" — i.e., autolearn failed but the scan
// itself completed successfully.
func isStatisticsError(body []byte) bool {
	var errResp struct {
		ErrorDomain string `json:"error_domain"`
	}
	return json.Unmarshal(body, &errResp) == nil && errResp.ErrorDomain == "rspamd-statistics"
}

// extractSMTPMessage pulls the "smtp_message" string out of rspamd's
// "messages" field. Rspamd normally encodes messages as an object
// ({"smtp_message": "..."}), but older/other builds have used an array of
// strings; anything that isn't the object form we understand yields "" rather
// than an error, so an unexpected shape never fails the surrounding decode.
func extractSMTPMessage(raw json.RawMessage) string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	var obj struct {
		SMTPMessage string `json:"smtp_message"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}
	return obj.SMTPMessage
}

// sanitizeSMTPMessage makes an rspamd-supplied string safe to use as an SMTP
// reply message. It collapses any control characters (notably CR/LF, which the
// SMTP transport would otherwise turn into additional reply lines) to spaces,
// trims surrounding whitespace, and caps the length so a single reply line
// stays within the RFC 5321 512-octet limit once the status code and CRLF are
// added. Truncation happens on a rune boundary so the reply never ends in a
// partial UTF-8 sequence.
func sanitizeSMTPMessage(s string) string {
	if s == "" {
		return ""
	}
	const maxLen = 480 // leave headroom for "NNN X.Y.Z " prefix and CRLF
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		// Replace C0 controls (incl. CR/LF), DEL, and C1 controls with a
		// space; keep everything else, including non-ASCII that SMTPUTF8
		// clients accept.
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			r = ' '
		}
		if b.Len()+utf8.RuneLen(r) > maxLen {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// Ping checks if the rspamd server is reachable by sending a HEAD request.
// Returns nil if the server responds, or an error if it is unreachable.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "HEAD", c.URL, nil)
	if err != nil {
		return fmt.Errorf("failed to create ping request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("rspamd unreachable: %w", err)
	}
	resp.Body.Close()
	return nil
}

// StartHealthCheck periodically pings rspamd and updates the provided gauge metric.
// It runs until the context is cancelled. The gauge is set to 1 when rspamd is reachable,
// and 0 when it is not.
func (c *Client) StartHealthCheck(ctx context.Context, gauge prometheus.Gauge, interval time.Duration) {
	// Check immediately on start
	c.updateHealthMetric(ctx, gauge)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.updateHealthMetric(ctx, gauge)
		}
	}
}

func (c *Client) updateHealthMetric(ctx context.Context, gauge prometheus.Gauge) {
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := c.Ping(pingCtx); err != nil {
		gauge.Set(0)
		c.Logger.Warn("Spam check server unreachable", "error", err)
	} else {
		gauge.Set(1)
	}
}

// generateHTTPCryptSignature creates HMAC-SHA256 signature for rspamd authentication
// Format: HMAC-SHA256(nonce, password)
func (c *Client) generateHTTPCryptSignature(nonce string) string {
	h := hmac.New(sha256.New, []byte(c.Password))
	h.Write([]byte(nonce))
	return hex.EncodeToString(h.Sum(nil))
}

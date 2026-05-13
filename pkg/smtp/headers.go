package smtp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"migadu/mizu/pkg/validation"
)

// InjectMizuHeaders adds Received and X-Mizu-* headers to the email
// These headers provide email tracing, authentication results, and debugging information
// If disableMizuHeaders is true, only the Received header is added (X-Mizu-* headers are skipped)
// spamHeaders contains additional headers from spam checking (e.g., X-Junk: yes)
func InjectMizuHeaders(rawEmail, domain, remoteAddr, heloHostname, traceID string, tlsVersion string, spfResult *validation.SPFResult, dmarcResult *validation.DMARCResult, arcResult *validation.ARCResult, isJunk bool, disableMizuHeaders bool, spamHeaders map[string]string) string {
	// Build the Received header (always added)
	receivedHeader := buildReceivedHeader(domain, remoteAddr, heloHostname, traceID, tlsVersion)

	// Build X-Mizu-* headers (only if not disabled)
	var mizuHeaders string
	if !disableMizuHeaders {
		mizuHeaders = buildMizuHeaders(traceID, spfResult, dmarcResult, arcResult, isJunk)
	}

	// Build spam check headers (from rspamd or other spam checkers)
	var spamHeaderStr string
	if len(spamHeaders) > 0 {
		var sb strings.Builder
		for name, value := range spamHeaders {
			sb.WriteString(name)
			sb.WriteString(": ")
			sb.WriteString(value)
			sb.WriteString("\r\n")
		}
		spamHeaderStr = sb.String()
	}

	// Prepend headers to the email
	// RFC 5322: Headers come before the body, separated by CRLF
	allHeaders := receivedHeader + mizuHeaders + spamHeaderStr
	return allHeaders + rawEmail
}

// buildReceivedHeader creates a standard Received header for email tracing
// Format follows RFC 5321 section 4.4 (Trace Information)
func buildReceivedHeader(domain, remoteAddr, heloHostname, traceID, tlsVersion string) string {
	// Sanitize heloHostname: strip any control characters to prevent header injection
	heloHostname = sanitizeHeaderValue(heloHostname)

	// Extract IP and port from remoteAddr
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr // Fallback if parsing fails
	}

	// Determine protocol (SMTP, ESMTP, ESMTPS, ESMTPSA)
	protocol := "ESMTP"
	if tlsVersion != "none" && tlsVersion != "" {
		protocol = "ESMTPS" // S suffix indicates TLS
	}

	// RFC 5322 date format: "Mon, 02 Jan 2006 15:04:05 -0700"
	timestamp := time.Now().Format(time.RFC1123Z)

	// Build Received header
	// Format: Received: from <client> by <server> with <protocol> id <id>; <timestamp>
	var sb strings.Builder
	sb.WriteString("Received: from ")
	sb.WriteString(heloHostname)
	sb.WriteString(" (")
	sb.WriteString(host)
	sb.WriteString(")\r\n")
	sb.WriteString("\tby ")
	sb.WriteString(domain)
	sb.WriteString(" with ")
	sb.WriteString(protocol)
	sb.WriteString(" id ")
	sb.WriteString(traceID)
	sb.WriteString(";\r\n")
	sb.WriteString("\t")
	sb.WriteString(timestamp)
	sb.WriteString("\r\n")

	return sb.String()
}

// sanitizeHeaderValue removes control characters (CR, LF, NUL) from a string
// to prevent header injection when interpolating untrusted values into email headers.
func sanitizeHeaderValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return -1 // drop control chars except tab (valid in header folding)
		}
		return r
	}, s)
}

// buildMizuHeaders creates custom X-Mizu-* headers for debugging and analysis
func buildMizuHeaders(traceID string, spfResult *validation.SPFResult, dmarcResult *validation.DMARCResult, arcResult *validation.ARCResult, isJunk bool) string {
	var sb strings.Builder

	// X-Mizu-Trace-ID: Unique identifier for this email transaction
	sb.WriteString("X-Mizu-Trace-ID: ")
	sb.WriteString(traceID)
	sb.WriteString("\r\n")

	// X-Mizu-Authentication-Results: Summary of authentication results
	sb.WriteString("X-Mizu-Authentication-Results: ")
	sb.WriteString(buildAuthenticationSummary(spfResult, dmarcResult, arcResult))
	sb.WriteString("\r\n")

	// X-Mizu-Junk: Spam classification
	if isJunk {
		sb.WriteString("X-Mizu-Junk: YES\r\n")
	} else {
		sb.WriteString("X-Mizu-Junk: NO\r\n")
	}

	return sb.String()
}

// buildAuthenticationSummary creates a summary string of authentication results
// Format: "spf=pass dkim=pass dmarc=pass arc=pass"
func buildAuthenticationSummary(spfResult *validation.SPFResult, dmarcResult *validation.DMARCResult, arcResult *validation.ARCResult) string {
	var parts []string

	// SPF result
	if spfResult != nil {
		parts = append(parts, fmt.Sprintf("spf=%s", spfResult.Result.Value))
	} else {
		parts = append(parts, "spf=none")
	}

	// DKIM result (from DMARC alignment check)
	if dmarcResult != nil {
		if dmarcResult.DKIMAligned {
			parts = append(parts, "dkim=pass")
		} else {
			parts = append(parts, "dkim=fail")
		}
	} else {
		parts = append(parts, "dkim=none")
	}

	// DMARC result
	if dmarcResult != nil {
		if dmarcResult.Pass {
			parts = append(parts, "dmarc=pass")
		} else {
			parts = append(parts, "dmarc=fail")
		}
	} else {
		parts = append(parts, "dmarc=none")
	}

	// ARC result
	if arcResult != nil && arcResult.Instance > 0 {
		if arcResult.Pass {
			parts = append(parts, "arc=pass")
		} else {
			parts = append(parts, "arc=fail")
		}
	} else {
		parts = append(parts, "arc=none")
	}

	return strings.Join(parts, " ")
}

// addJunkHeader adds a custom header to mark the message as junk/spam
func addJunkHeader(rawEmail, headerName string) string {
	header := fmt.Sprintf("%s: YES\r\n", headerName)
	return header + rawEmail
}

// modifySubject modifies the Subject header according to the provided pattern
// The pattern should contain %s which will be replaced with the original subject
func modifySubject(rawEmail, pattern string) string {
	lines := strings.Split(rawEmail, "\r\n")
	var result []string
	subjectModified := false

	// Use index-based loop so we can properly advance past folded continuation lines.
	// A range loop would revisit continuation lines even after incrementing i.
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		// Look for Subject header (case-insensitive)
		if !subjectModified && len(line) >= 8 && strings.EqualFold(line[:8], "Subject:") {
			// Extract original subject (everything after "Subject: ")
			originalSubject := strings.TrimSpace(line[8:])

			// Handle multi-line subjects (RFC 5322 folding)
			// Check if next lines are continuations (start with whitespace)
			for i+1 < len(lines) && len(lines[i+1]) > 0 && (lines[i+1][0] == ' ' || lines[i+1][0] == '\t') {
				i++
				originalSubject += " " + strings.TrimSpace(lines[i])
			}

			// Apply pattern
			newSubject := fmt.Sprintf(pattern, originalSubject)
			result = append(result, "Subject: "+newSubject)
			subjectModified = true
		} else {
			result = append(result, line)
		}
	}

	// If no subject was found, add one
	if !subjectModified {
		// Find the end of headers (empty line)
		for i, line := range result {
			if line == "" {
				// Insert subject before the empty line
				newSubject := fmt.Sprintf(pattern, "(no subject)")
				result = append(result[:i], append([]string{"Subject: " + newSubject}, result[i:]...)...)
				break
			}
		}
	}

	return strings.Join(result, "\r\n")
}

// fixMissingHeaders adds missing Message-ID and Date headers if they don't exist
// This is typically used for relay servers that accept mail from other systems
// Returns the modified email and a list of headers that were added
func fixMissingHeaders(rawEmail, domain string) (string, []string) {
	lines := strings.Split(rawEmail, "\r\n")
	hasMessageID := false
	hasDate := false
	headerEndIndex := -1

	// Scan headers to check what's missing and find where headers end
	for i, line := range lines {
		// Empty line marks end of headers
		if line == "" {
			headerEndIndex = i
			break
		}

		// Check for Message-ID header (case-insensitive)
		if len(line) >= 11 && strings.EqualFold(line[:11], "Message-ID:") {
			hasMessageID = true
		}

		// Check for Date header (case-insensitive)
		if len(line) >= 5 && strings.EqualFold(line[:5], "Date:") {
			hasDate = true
		}
	}

	// If both headers exist, return unchanged
	if hasMessageID && hasDate {
		return rawEmail, nil
	}

	// Build list of headers to add
	var headersToAdd []string
	var addedHeaders []string // Track what we added for logging

	if !hasDate {
		// RFC 5322 date format: "Mon, 02 Jan 2006 15:04:05 -0700"
		timestamp := time.Now().Format(time.RFC1123Z)
		headersToAdd = append(headersToAdd, "Date: "+timestamp)
		addedHeaders = append(addedHeaders, "Date")
	}

	if !hasMessageID {
		// Generate Message-ID: <random>@domain
		// Format: <uniqueID.timestamp@domain>
		messageID := generateMessageID(domain)
		headersToAdd = append(headersToAdd, "Message-ID: "+messageID)
		addedHeaders = append(addedHeaders, "Message-ID")
	}

	// Insert headers before the empty line (or at the end if no empty line found)
	var result []string
	if headerEndIndex == -1 {
		// No empty line found - malformed email, append headers at the end
		result = append(result, lines...)
		result = append(result, headersToAdd...)
		result = append(result, "") // Add empty line separator
	} else {
		// Insert headers before the empty line that separates headers from body
		result = append(result, lines[:headerEndIndex]...)
		result = append(result, headersToAdd...)
		result = append(result, lines[headerEndIndex:]...)
	}

	return strings.Join(result, "\r\n"), addedHeaders
}

// generateMessageID creates a unique Message-ID header value
// Format: <16-char-hex.timestamp@domain>
func generateMessageID(domain string) string {
	// Generate 8 random bytes (16 hex characters)
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID if random fails
		return fmt.Sprintf("<%d@%s>", time.Now().UnixNano(), domain)
	}
	randomPart := hex.EncodeToString(b)
	timestamp := time.Now().Unix()
	return fmt.Sprintf("<%s.%d@%s>", randomPart, timestamp, domain)
}

// LoopDetectionResult contains the result of mail loop detection
type LoopDetectionResult struct {
	IsLoop        bool   // True if a loop was detected
	HopCount      int    // Total number of Received headers (hops)
	HostnameCount int    // Number of times our hostname appears in Received "by" clauses
	LoopHostname  string // The hostname that appears multiple times (if IsLoop=true)
}

// detectMailLoop checks for mail loops by examining Received headers
// A loop is detected if:
// 1. The server's own hostname appears 2+ times in existing Received "by" clauses, OR
// 2. The number of Received headers (hops) exceeds maxHops
//
// A single occurrence of the hostname is expected in legitimate scenarios such as
// mailing lists (e.g., Google Groups) or forwarding, where a message is first
// processed by this server, forwarded externally, and then delivered back.
// Only when the hostname appears two or more times is a real loop indicated.
//
// RFC 5321 section 6.3 recommends a hop count limit (typically 100, but we use 30 as default for safety)
func detectMailLoop(rawEmail, serverHostname string, maxHops int) LoopDetectionResult {
	result := LoopDetectionResult{}

	// Default maxHops if not set
	if maxHops <= 0 {
		maxHops = 30
	}

	lines := strings.Split(rawEmail, "\r\n")
	hostnameCount := 0
	currentReceivedHeader := ""

	// processHeader checks a complete Received header for our hostname in the "by" clause
	processHeader := func(header string) {
		if checkReceivedHeaderForLoop(header, serverHostname) {
			hostnameCount++
		}
	}

	// Parse all Received headers
	// Format: "Received: from <client> by <server> ..."
	// Received headers can be multi-line (RFC 5322 folding - continuation lines start with whitespace)
	for _, line := range lines {
		// Stop at end of headers (empty line)
		if line == "" {
			// Process the last accumulated Received header
			if currentReceivedHeader != "" {
				processHeader(currentReceivedHeader)
			}
			break
		}

		// Check if this is a new Received header (case-insensitive)
		if len(line) >= 9 && strings.EqualFold(line[:9], "Received:") {
			// Process previous Received header if any
			if currentReceivedHeader != "" {
				processHeader(currentReceivedHeader)
			}

			// Start new Received header
			result.HopCount++
			currentReceivedHeader = line
		} else if currentReceivedHeader != "" && len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			// Continuation of current Received header (RFC 5322 folding)
			currentReceivedHeader += " " + strings.TrimSpace(line)
		} else {
			// This is a different header, process accumulated Received header if any
			if currentReceivedHeader != "" {
				processHeader(currentReceivedHeader)
				currentReceivedHeader = ""
			}
		}
	}

	result.HostnameCount = hostnameCount

	// A loop is detected when our hostname appears in 2+ Received "by" clauses.
	// A single occurrence is normal for mailing lists/forwarding scenarios.
	if hostnameCount >= 2 {
		result.IsLoop = true
		result.LoopHostname = serverHostname
		return result
	}

	// Check if hop count exceeds limit (strictly greater than)
	if result.HopCount > maxHops {
		result.IsLoop = true
		return result
	}

	return result
}

// checkReceivedHeaderForLoop checks if a Received header contains our server hostname in the "by" clause
func checkReceivedHeaderForLoop(receivedHeader, serverHostname string) bool {
	// Check the "by" clause to see if this server has already processed this message
	// Format: "Received: from <client> by <server> ..."
	lowerHeader := strings.ToLower(receivedHeader)
	lowerHostname := strings.ToLower(serverHostname)

	// Look for "by <hostname>" pattern
	if strings.Contains(lowerHeader, "by "+lowerHostname) {
		return true
	}

	return false
}

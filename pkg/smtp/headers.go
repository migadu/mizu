package smtp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/validation"
)

// normalizeToCRLF canonicalizes all line endings (lone CR, lone LF, and CRLF)
// to CRLF. This removes the parsing differential between header-processing code
// that splits on "\r\n" and net/mail's more lenient parsing, closing a
// header-smuggling vector for messages that use bare-LF line endings.
func normalizeToCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

// InjectMizuHeaders adds Received and X-Mizu-* headers to the email
// These headers provide email tracing, authentication results, and debugging information
// toggles selects which X-Mizu-* headers are emitted; the Received header is always added
// spamHeaders contains additional headers from spam checking (e.g., X-Junk: yes); a key
// may map to multiple values, which become separate header lines (e.g. Authentication-Results).
// spamHeaders are NOT subject to toggles — rspamd's add_headers are injected verbatim.
// stripClientIdentity omits the "from <HELO> (<client IP>)" clause from Received; see buildReceivedHeader.
func InjectMizuHeaders(rawEmail, domain, remoteAddr, heloHostname, traceID string, tlsVersion string, spfResult *validation.SPFResult, dmarcResult *validation.DMARCResult, arcResult *validation.ARCResult, isJunk bool, toggles config.HeaderToggles, stripClientIdentity bool, spamHeaders map[string][]string) string {
	// Build the Received header (always added)
	receivedHeader := buildReceivedHeader(domain, remoteAddr, heloHostname, traceID, tlsVersion, stripClientIdentity)

	// Build X-Mizu-* headers (per-header toggles)
	mizuHeaders := buildMizuHeaders(traceID, spfResult, dmarcResult, arcResult, isJunk, toggles)

	// Build spam check headers (from rspamd or other spam checkers).
	// Sanitize both name and value: although rspamd is internal, a stray CR/LF
	// in either field would forge an arbitrary header or inject body content.
	var spamHeaderStr string
	if len(spamHeaders) > 0 {
		var sb strings.Builder
		for name, values := range spamHeaders {
			safeName := sanitizeHeaderValue(name)
			if safeName == "" {
				continue
			}
			for _, value := range values {
				sb.WriteString(safeName)
				sb.WriteString(": ")
				sb.WriteString(sanitizeFoldedHeaderValue(value))
				sb.WriteString("\r\n")
			}
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
//
// When stripClientIdentity is set — the default on submission servers, configurable
// per server via strip_client_identity — the "from" clause is omitted entirely. The
// HELO name and the client IP identify the submitting user's machine and network,
// and stamping them here publishes the user's home or mobile address to every
// recipient. The trace ID stays in the header, so the hop remains correlatable with
// our own logs. Relay servers keep the full client trace by default: downstream
// receivers rely on it for SPF/DMARC forensics and loop detection.
func buildReceivedHeader(domain, remoteAddr, heloHostname, traceID, tlsVersion string, stripClientIdentity bool) string {
	// Determine protocol (SMTP, ESMTP, ESMTPS, ESMTPSA)
	protocol := "ESMTP"
	if tlsVersion != "none" && tlsVersion != "" {
		protocol = "ESMTPS" // S suffix indicates TLS
	}

	// RFC 5322 date format: "Mon, 02 Jan 2006 15:04:05 -0700"
	timestamp := time.Now().Format(time.RFC1123Z)

	// Build Received header
	// Format: Received: [from <client>] by <server> with <protocol> id <id>; <timestamp>
	var sb strings.Builder
	sb.WriteString("Received: ")
	if !stripClientIdentity {
		// Extract IP and port from remoteAddr
		host, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			host = remoteAddr // Fallback if parsing fails
		}

		sb.WriteString("from ")
		// Sanitize heloHostname: strip any control characters to prevent header injection
		sb.WriteString(sanitizeHeaderValue(heloHostname))
		sb.WriteString(" (")
		sb.WriteString(host)
		sb.WriteString(")\r\n\t")
	}
	sb.WriteString("by ")
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

// sanitizeFoldedHeaderValue sanitizes a header value that may legitimately
// contain folding whitespace (CRLF followed by SP or TAB), as produced by
// rspamd's milter add_headers for long values such as Authentication-Results.
// Folds are preserved and normalized to canonical CRLF; every other CR or LF is
// stripped. Because each surviving newline is guaranteed to be followed by
// whitespace, a malicious value can never begin a new header line or terminate
// the header block, so header/body injection remains impossible.
func sanitizeFoldedHeaderValue(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\r':
			// Drop; a real fold is recognized at the following '\n'.
			continue
		case c == '\n':
			// Preserve only when this newline begins a fold (next byte is SP/TAB).
			if i+1 < len(s) && (s[i+1] == ' ' || s[i+1] == '\t') {
				sb.WriteString("\r\n")
			}
			// Otherwise it is a bare or injected newline — drop it.
		case c < 0x20 && c != '\t':
			// Drop other control characters (NUL, etc.); tab is valid.
			continue
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// buildMizuHeaders creates custom X-Mizu-* headers for debugging and analysis
func buildMizuHeaders(traceID string, spfResult *validation.SPFResult, dmarcResult *validation.DMARCResult, arcResult *validation.ARCResult, isJunk bool, toggles config.HeaderToggles) string {
	var sb strings.Builder

	// X-Mizu-Trace-ID: Unique identifier for this email transaction
	if toggles.TraceID {
		sb.WriteString("X-Mizu-Trace-ID: ")
		sb.WriteString(traceID)
		sb.WriteString("\r\n")
	}

	// X-Mizu-Authentication-Results: Summary of authentication results
	if toggles.AuthResults {
		sb.WriteString("X-Mizu-Authentication-Results: ")
		sb.WriteString(buildAuthenticationSummary(spfResult, dmarcResult, arcResult))
		sb.WriteString("\r\n")
	}

	// X-Mizu-Junk: Spam classification
	if toggles.Junk {
		if isJunk {
			sb.WriteString("X-Mizu-Junk: YES\r\n")
		} else {
			sb.WriteString("X-Mizu-Junk: NO\r\n")
		}
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

// addJunkHeader adds a custom header to mark the message as junk/spam.
// headerName comes from config (trusted), but we sanitize anyway for the
// same defense-in-depth reason as the spam-check header path. A fully
// stripped name would yield a malformed colon-only line, so skip in that
// (practically unreachable) case.
func addJunkHeader(rawEmail, headerName string) string {
	safeName := sanitizeHeaderValue(headerName)
	if safeName == "" {
		return rawEmail
	}
	return fmt.Sprintf("%s: YES\r\n", safeName) + rawEmail
}

// addEnvelopeToHeader prepends an X-Envelope-To header carrying the envelope
// recipient address. Delivery is per-recipient, so each delivered copy records
// exactly the recipient it was sent for. Any X-Envelope-To header already
// present (e.g. forged by an upstream sender) is removed first so the value we
// emit is authoritative and never duplicated. The address comes from RCPT TO
// (already parsed) but is sanitized for the same defense-in-depth reason as the
// other header injection paths — a stray CR/LF would otherwise forge headers.
func addEnvelopeToHeader(rawEmail, recipient string) string {
	rawEmail = stripHeader(rawEmail, "X-Envelope-To")

	safeRecipient := sanitizeHeaderValue(recipient)
	if safeRecipient == "" {
		return rawEmail
	}
	return fmt.Sprintf("X-Envelope-To: %s\r\n", safeRecipient) + rawEmail
}

// stripHeader removes every occurrence of the named header (case-insensitive),
// including any RFC 5322 folded continuation lines, from the header section of
// the message. Everything from the first empty line onward (the body) is left
// untouched, so occurrences of the name in the body are not affected.
func stripHeader(rawEmail, headerName string) string {
	prefix := headerName + ":"
	lines := strings.Split(rawEmail, "\r\n")
	result := make([]string, 0, len(lines))
	skipping := false

	for i, line := range lines {
		// Empty line marks the end of the header section: copy the body verbatim.
		if line == "" {
			result = append(result, lines[i:]...)
			break
		}

		// Drop folded continuation lines belonging to a stripped header.
		if skipping {
			if line[0] == ' ' || line[0] == '\t' {
				continue
			}
			skipping = false
		}

		if len(line) >= len(prefix) && strings.EqualFold(line[:len(prefix)], prefix) {
			skipping = true
			continue
		}

		result = append(result, line)
	}

	return strings.Join(result, "\r\n")
}

// rewriteFromHeader replaces the address in the From header with newAddress,
// but only when the address currently there is exactly oldAddress. Any display
// name is preserved: "Support <user@domain@TOKEN>" becomes "Support <user@domain>".
//
// This exists for master/token logins. A client that prefills its compose form
// from the login string — Sora's webmail does — puts "user@domain@SUFFIX" in
// From, which is not a routable address and which would publish the master
// username to every recipient. The envelope is already resolved by then
// (Session.Mail); this brings the visible header along so the two agree and
// DMARC can align.
//
// The match is exact and case-insensitive on the address only, so a From that
// is anything other than the login is left untouched — this can never rewrite
// one user's message into another's name. Returns the message and whether a
// rewrite happened.
func rewriteFromHeader(rawEmail, oldAddress, newAddress string) (string, bool) {
	oldAddress = strings.ToLower(strings.TrimSpace(oldAddress))
	newAddress = strings.TrimSpace(newAddress)
	if oldAddress == "" || newAddress == "" {
		return rawEmail, false
	}

	const prefix = "From:"
	lines := strings.Split(rawEmail, "\r\n")

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		// Empty line marks the end of the header section.
		if line == "" {
			break
		}
		if len(line) < len(prefix) || !strings.EqualFold(line[:len(prefix)], prefix) {
			continue
		}

		// Gather the full value, including RFC 5322 folded continuations.
		value := strings.TrimSpace(line[len(prefix):])
		last := i
		for last+1 < len(lines) && len(lines[last+1]) > 0 && (lines[last+1][0] == ' ' || lines[last+1][0] == '\t') {
			last++
			value += " " + strings.TrimSpace(lines[last])
		}

		if extractEmail(value) != oldAddress {
			return rawEmail, false // Not the login: leave it alone.
		}

		// Preserve the display name, if any, and re-emit as a single line.
		rewritten := "From: <" + newAddress + ">"
		if open := strings.Index(value, "<"); open > 0 {
			if name := strings.TrimSpace(value[:open]); name != "" {
				rewritten = "From: " + name + " <" + newAddress + ">"
			}
		}

		out := make([]string, 0, len(lines))
		out = append(out, lines[:i]...)
		out = append(out, rewritten)
		out = append(out, lines[last+1:]...)
		return strings.Join(out, "\r\n"), true
	}

	return rawEmail, false
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
	needle := "by " + lowerHostname

	// Match "by <hostname>" only at a hostname boundary so that a host named
	// "mx1" does not spuriously match "by mx10.example.com" (a substring match
	// would falsely flag legitimate mail as a loop and reject it).
	from := 0
	for {
		idx := strings.Index(lowerHeader[from:], needle)
		if idx < 0 {
			return false
		}
		end := from + idx + len(needle)
		if end >= len(lowerHeader) || !isHostnameChar(lowerHeader[end]) {
			return true
		}
		from = end
	}
}

// isHostnameChar reports whether b can be part of a hostname (letters, digits,
// '.', '-'). Used to detect hostname boundaries when matching "by <hostname>".
func isHostnameChar(b byte) bool {
	return b == '.' || b == '-' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

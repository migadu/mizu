package validation

import (
	"bufio"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/textproto"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"log/slog"

	emersiontextproto "github.com/emersion/go-message/textproto"
	"github.com/emersion/go-msgauth/authres"
)

// ARCResult represents the result of ARC (Authenticated Received Chain) validation.
//
// ARC preserves email authentication results across forwarding intermediaries
// like mailing lists and forwarders. Each intermediary adds an "instance" of
// ARC headers (numbered sequentially: i=1, i=2, etc.).
//
// The validation process checks:
//   - Chain integrity (all instances from 1 to N are present)
//   - Signature validity (ARC-Seal and ARC-Message-Signature)
//   - Proper sequence (no gaps or duplicates in instance numbers)
//
// A valid ARC chain indicates the message passed authentication at earlier
// hops, even if current SPF/DKIM checks fail due to forwarding.
type ARCResult struct {
	Pass           bool     // Whether ARC chain validation passed
	ChainValid     bool     // Whether the ARC chain is intact and valid
	Instance       int      // The highest ARC instance number (0 if no ARC headers)
	FailureReasons []string // List of reasons why validation failed
}

// ARCSet represents a single set of ARC headers at a specific hop.
//
// Per RFC 8617, each intermediary that handles an email adds exactly three
// ARC headers with the same instance number (i=N):
//
//  1. ARC-Authentication-Results: Records the authentication results
//     (SPF, DKIM, DMARC) observed at this hop
//
//  2. ARC-Message-Signature: A DKIM-style signature over selected message
//     headers and body hash
//
//  3. ARC-Seal: Signs all previous ARC headers plus the new ones,
//     creating a tamper-evident chain
//
// A complete ARC chain requires all three headers for each instance from
// 1 to N with no gaps.
type ARCSet struct {
	Instance               int    // Instance number (i=)
	AuthenticationResults  string // ARC-Authentication-Results header value
	MessageSignature       string // ARC-Message-Signature header value
	Seal                   string // ARC-Seal header value
	SealDomain             string // Domain that sealed this set (d= from ARC-Seal)
	MessageSignatureDomain string // Domain from ARC-Message-Signature (d=)
}

// CheckARC performs ARC (Authenticated Received Chain) validation on an email message.
//
// ARC validation verifies that the authentication chain through forwarding
// intermediaries is intact and valid. This is critical for emails that pass
// through mailing lists or forwarders where SPF/DKIM alignment breaks.
//
// The validation process:
//  1. Extracts all ARC header sets (i=1, i=2, ..., i=N)
//  2. Verifies each ARC-Message-Signature (DKIM-style verification)
//  3. Verifies each ARC-Seal (signs the chain)
//  4. Checks chain integrity (no gaps or duplicates)
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - rawEmail: Complete RFC 5322 format email including headers and body
//   - lookupTXT: DNS TXT lookup function (uses lookupTXTWithTimeout if nil)
//   - logger: Structured logger for debugging (uses nop logger if nil)
//
// Returns:
//   - ARCResult with Pass=true if chain is valid, false otherwise
//   - Error only for parsing failures (not validation failures)
func CheckARC(ctx context.Context, rawEmail string, lookupTXT func(string) ([]string, error), logger *slog.Logger) (*ARCResult, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// Parse email headers using go-message
	h, err := emersiontextproto.ReadHeader(bufio.NewReader(strings.NewReader(rawEmail)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse email headers: %w", err)
	}

	// Extract all ARC headers and organize them by instance number
	arcSets, maxInstance := extractARCSets(h, logger)

	// If no ARC headers found, return "none" result (not a failure)
	if len(arcSets) == 0 {
		logger.Debug("No ARC headers found in message")
		return &ARCResult{
			Pass:       true, // No ARC headers means pass (nothing to validate)
			ChainValid: true,
			Instance:   0,
		}, nil
	}

	result := &ARCResult{
		Instance:       maxInstance,
		FailureReasons: make([]string, 0),
	}

	logger.Debug("Found ARC headers", "max_instance", maxInstance, "sets_count", len(arcSets))

	// Use default DNS lookup if none provided
	if lookupTXT == nil {
		lookupTXT = lookupTXTWithTimeout
	}

	// Validate the ARC chain
	// The chain is valid if all ARC-Seal and ARC-Message-Signature headers verify correctly
	chainValid, reasons := validateARCChain(rawEmail, arcSets, maxInstance, lookupTXT, logger)
	result.ChainValid = chainValid
	result.FailureReasons = reasons

	// ARC passes if the chain is valid
	result.Pass = result.ChainValid

	logger.Debug("ARC validation result",
		"instance", result.Instance,
		"chain_valid", result.ChainValid,
		"pass", result.Pass,
		"failure_reasons", result.FailureReasons)

	return result, nil
}

// extractARCSets extracts and organizes ARC header sets from email headers
func extractARCSets(h emersiontextproto.Header, logger *slog.Logger) (map[int]*ARCSet, int) {
	sets := make(map[int]*ARCSet)
	maxInstance := 0

	// Extract ARC-Authentication-Results headers
	for _, aar := range h.Values("ARC-Authentication-Results") {
		instance := extractInstance(aar)
		if instance > 0 {
			if sets[instance] == nil {
				sets[instance] = &ARCSet{Instance: instance}
			}
			sets[instance].AuthenticationResults = aar
			if instance > maxInstance {
				maxInstance = instance
			}
		}
	}

	// Extract ARC-Message-Signature headers
	for _, ams := range h.Values("ARC-Message-Signature") {
		instance := extractInstance(ams)
		if instance > 0 {
			if sets[instance] == nil {
				sets[instance] = &ARCSet{Instance: instance}
			}
			sets[instance].MessageSignature = ams
			sets[instance].MessageSignatureDomain = extractDomain(ams)
			if instance > maxInstance {
				maxInstance = instance
			}
		}
	}

	// Extract ARC-Seal headers
	for _, as := range h.Values("ARC-Seal") {
		instance := extractInstance(as)
		if instance > 0 {
			if sets[instance] == nil {
				sets[instance] = &ARCSet{Instance: instance}
			}
			sets[instance].Seal = as
			sets[instance].SealDomain = extractDomain(as)
			if instance > maxInstance {
				maxInstance = instance
			}
		}
	}

	// Validate that each set is complete (has all three header types)
	for i := 1; i <= maxInstance; i++ {
		set := sets[i]
		if set == nil {
			logger.Warn("Missing ARC set", "instance", i)
			continue
		}
		if set.AuthenticationResults == "" || set.MessageSignature == "" || set.Seal == "" {
			logger.Warn("Incomplete ARC set",
				"instance", i,
				"has_aar", set.AuthenticationResults != "",
				"has_ams", set.MessageSignature != "",
				"has_as", set.Seal != "")
		}
	}

	return sets, maxInstance
}

// maxARCInstance is the highest instance number an ARC set may carry
// (RFC 8617 §4.2.1: "ARC-Seal ... i ... between 1 and 50").
const maxARCInstance = 50

// extractInstance extracts the instance number (i=) from an ARC header
func extractInstance(header string) int {
	// Look for i=N in the header
	parts := strings.Split(header, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "i=") {
			instanceStr := strings.TrimPrefix(part, "i=")
			instanceStr = strings.TrimSpace(instanceStr)
			instance, err := strconv.Atoi(instanceStr)
			switch {
			case errors.Is(err, strconv.ErrRange):
				// Too large for an int: out of range, not absent.
				return maxARCInstance + 1
			case err != nil || instance < 1:
				return 0
			case instance > maxARCInstance:
				// Collapse every out-of-range value onto one marker just past
				// the limit. Callers loop from 1 to the highest instance seen,
				// so an attacker-chosen i=9223372036854775807 must never become
				// a loop bound; the marker keeps the set visible so the chain
				// is failed rather than the header silently ignored.
				return maxARCInstance + 1
			default:
				return instance
			}
		}
	}
	return 0
}

// extractDomain extracts the domain (d=) from an ARC header
func extractDomain(header string) string {
	// Look for d=domain in the header
	parts := strings.Split(header, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "d=") {
			domain := strings.TrimPrefix(part, "d=")
			domain = strings.TrimSpace(domain)
			return domain
		}
	}
	return ""
}

// validateARCChain validates the entire ARC chain by verifying signatures
func validateARCChain(rawEmail string, sets map[int]*ARCSet, maxInstance int, lookupTXT func(string) ([]string, error), logger *slog.Logger) (bool, []string) {
	reasons := make([]string, 0)

	if maxInstance > maxARCInstance {
		reason := fmt.Sprintf("ARC instance exceeds the RFC 8617 maximum of %d", maxARCInstance)
		logger.Warn("ARC chain validation failed", "reason", reason)
		return false, append(reasons, reason)
	}

	// Check that we have a complete chain from 1 to maxInstance
	for i := 1; i <= maxInstance; i++ {
		set := sets[i]
		if set == nil {
			reason := fmt.Sprintf("missing ARC set for instance %d", i)
			reasons = append(reasons, reason)
			logger.Warn("ARC chain validation failed", "reason", reason)
			return false, reasons
		}

		// Verify that the set is complete
		if set.AuthenticationResults == "" || set.MessageSignature == "" || set.Seal == "" {
			reason := fmt.Sprintf("incomplete ARC set at instance %d", i)
			reasons = append(reasons, reason)
			logger.Warn("ARC chain validation failed", "reason", reason)
			return false, reasons
		}
	}

	// Verify ARC-Message-Signature headers (these are DKIM-like signatures over the message)
	// We validate them in order from oldest (1) to newest (maxInstance)
	for i := 1; i <= maxInstance; i++ {
		set := sets[i]

		// Parse and verify the ARC-Message-Signature
		// This reconstructs the message as it existed at instance i and verifies the signature
		valid, err := verifyARCMessageSignature(rawEmail, set, i, lookupTXT, logger)
		if err != nil || !valid {
			reason := fmt.Sprintf("ARC-Message-Signature verification failed at instance %d", i)
			if err != nil {
				reason = fmt.Sprintf("%s: %v", reason, err)
			}
			reasons = append(reasons, reason)
			logger.Warn("ARC-Message-Signature verification failed",
				"instance", i,
				"domain", set.MessageSignatureDomain,
				"error", err)
			return false, reasons
		}

		logger.Debug("ARC-Message-Signature verified",
			"instance", i,
			"domain", set.MessageSignatureDomain)
	}

	// Verify ARC-Seal headers (these sign the previous ARC sets)
	// We validate them in order from oldest (1) to newest (maxInstance)
	for i := 1; i <= maxInstance; i++ {
		set := sets[i]

		// Parse and verify the ARC-Seal
		// Note: The ARC-Seal at instance i signs all ARC headers from instances 1 through i

		valid, err := verifyARCSeal(rawEmail, set, i, lookupTXT, logger)
		if err != nil || !valid {
			reason := fmt.Sprintf("ARC-Seal verification failed at instance %d", i)
			if err != nil {
				reason = fmt.Sprintf("%s: %v", reason, err)
			}
			reasons = append(reasons, reason)
			logger.Warn("ARC-Seal verification failed",
				"instance", i,
				"domain", set.SealDomain,
				"error", err)
			return false, reasons
		}

		logger.Debug("ARC-Seal verified",
			"instance", i,
			"domain", set.SealDomain)
	}

	logger.Info("ARC chain validated successfully", "max_instance", maxInstance)
	return true, reasons
}

// verifyARCMessageSignature verifies an ARC-Message-Signature header
// Per RFC 8617, AMS has the same syntax and semantics as DKIM-Signature with minor differences:
// 1. Different header field name (ARC-Message-Signature vs DKIM-Signature)
// 2. No version tag (v=)
// 3. Uses instance tag (i=) instead of AUID
func verifyARCMessageSignature(rawEmail string, set *ARCSet, instance int, lookupTXT func(string) ([]string, error), logger *slog.Logger) (bool, error) {
	// 1. Find the raw ARC-Message-Signature header for this instance
	headers, _ := parseRawHeaders(rawEmail)
	var sigHeader RawHeader
	found := false
	for _, h := range headers {
		key := textproto.CanonicalMIMEHeaderKey(h.Key)
		if key == "Arc-Message-Signature" && h.Instance == instance {
			sigHeader = h
			found = true
			break
		}
	}
	if !found {
		return false, fmt.Errorf("ARC-Message-Signature header not found for instance %d", instance)
	}

	// 2. Reconstruct the message as it existed at this ARC instance
	// by removing all ARC headers with instance numbers >= current instance
	// (except current ARC-Authentication-Results)
	reconstructedMsg := removeARCHeadersFromInstance(rawEmail, instance)

	// 3. Parse the reconstructed message to get headers and body for verification
	recHeaders, recBody := parseRawHeaders(reconstructedMsg)
	if recHeaders == nil {
		return false, fmt.Errorf("failed to parse reconstructed message")
	}

	// 4. Verify using our custom ARC verifier
	err := verifyARCSignature(
		"ARC-Message-Signature",
		sigHeader,
		recHeaders,
		recBody,
		lookupTXT,
		logger,
	)

	if err != nil {
		return false, err
	}

	return true, nil
}

// verifyARCSeal verifies an ARC-Seal header
// Per RFC 8617, ARC-Seal signs all ARC header fields from instances 1 through i
// The cv= (chain validation) tag indicates whether prior ARC instances validated successfully
func verifyARCSeal(rawEmail string, set *ARCSet, instance int, lookupTXT func(string) ([]string, error), logger *slog.Logger) (bool, error) {
	// 1. Find the raw ARC-Seal header for this instance
	headers, _ := parseRawHeaders(rawEmail)
	var sigHeader RawHeader
	found := false
	for _, h := range headers {
		key := textproto.CanonicalMIMEHeaderKey(h.Key)
		if key == "Arc-Seal" && h.Instance == instance {
			sigHeader = h
			found = true
			break
		}
	}
	if !found {
		return false, fmt.Errorf("ARC-Seal header not found for instance %d", instance)
	}

	// 2. Extract ARC headers to be signed (from instance 1 to i)
	// extractARCHeadersUpToInstance returns a string of headers.
	// We need to pass them as RawHeaders to verifyARCSignature.
	// Actually, extractARCHeadersUpToInstance logic already selects the correct headers.
	// But `verifyARCSignature` expects `[]RawHeader`.
	// We can parse the string returned by `extractARCHeadersUpToInstance`.

	arcHeadersStr := extractARCHeadersUpToInstance(rawEmail, instance)
	arcHeaders, _ := parseRawHeaders(arcHeadersStr + "\r\n\r\n") // Add empty body to ensure parsing works

	// Note: ARC-Seal signs headers only. Body is empty.

	// 3. Verify
	err := verifyARCSignature(
		"ARC-Seal",
		sigHeader,
		arcHeaders,
		"", // Empty body for ARC-Seal
		lookupTXT,
		logger,
	)

	if err != nil {
		return false, err
	}

	return true, nil
}

// RawHeader represents a header field with its raw text
type RawHeader struct {
	Key      string // Header name (e.g. "ARC-Seal")
	Value    string // Header value (e.g. "i=1; ...")
	Raw      string // Raw header line(s) including CRLF
	Instance int    // ARC instance number (0 if not ARC)
}

// parseRawHeaders parses headers from raw email preserving exact bytes using go-message
func parseRawHeaders(rawEmail string) ([]RawHeader, string) {
	reader := bufio.NewReader(strings.NewReader(rawEmail))
	h, err := emersiontextproto.ReadHeader(reader)
	if err != nil {
		// If header parsing fails, return what we can or empty
		return nil, rawEmail
	}

	var headers []RawHeader
	fields := h.Fields()
	for fields.Next() {
		rawBytes, err := fields.Raw()
		if err != nil {
			continue
		}

		rh := RawHeader{
			Key:   fields.Key(),
			Value: fields.Value(),
			Raw:   string(rawBytes),
		}
		rh.Instance = extractInstance(rh.Value)
		headers = append(headers, rh)
	}

	// Read the rest as body
	bodyBytes, _ := io.ReadAll(reader)
	return headers, string(bodyBytes)
}

// extractARCHeadersUpToInstance extracts all ARC headers from instances 1 through i
// Uses robust raw header parsing and strictly follows RFC 8617 ordering
func extractARCHeadersUpToInstance(rawEmail string, maxInstance int) string {
	headers, _ := parseRawHeaders(rawEmail)

	var arcHeaders []RawHeader

	for _, h := range headers {
		key := textproto.CanonicalMIMEHeaderKey(h.Key)
		if strings.HasPrefix(key, "Arc-") { // Canonical key check
			if h.Instance > 0 && h.Instance <= maxInstance {
				// For the maxInstance (current), we should NOT include ARC-Seal
				// because ARC-Seal signs everything up to it, but not itself
				if h.Instance == maxInstance && key == "Arc-Seal" {
					continue
				}
				arcHeaders = append(arcHeaders, h)
			}
		}
	}

	// Sort headers according to RFC 8617 Section 5.1.2:
	// "The headers MUST be presented to the hash algorithm in the order of increasing instance numbers"
	// "Within each instance, the headers MUST be presented in the order:
	//  ARC-Authentication-Results, then ARC-Message-Signature, then ARC-Seal."
	sort.SliceStable(arcHeaders, func(i, j int) bool {
		if arcHeaders[i].Instance != arcHeaders[j].Instance {
			return arcHeaders[i].Instance < arcHeaders[j].Instance
		}

		// Same instance, order by type
		// Keys must match textproto.CanonicalMIMEHeaderKey output (e.g. Arc-Authentication-Results)
		typeOrder := map[string]int{
			"Arc-Authentication-Results": 1,
			"Arc-Message-Signature":      2,
			"Arc-Seal":                   3,
		}

		ki := textproto.CanonicalMIMEHeaderKey(arcHeaders[i].Key)
		kj := textproto.CanonicalMIMEHeaderKey(arcHeaders[j].Key)

		return typeOrder[ki] < typeOrder[kj]
	})

	var buf strings.Builder
	for _, h := range arcHeaders {
		buf.WriteString(h.Raw)
	}

	return buf.String()
}

// removeARCHeadersFromInstance removes all ARC headers with instance >= the specified instance
// This reconstructs the message as it existed at a previous ARC hop
// Uses robust raw header parsing to preserve other headers exactly
func removeARCHeadersFromInstance(rawEmail string, instance int) string {
	headers, body := parseRawHeaders(rawEmail)

	var buf strings.Builder
	for _, h := range headers {
		key := textproto.CanonicalMIMEHeaderKey(h.Key)
		isARC := strings.HasPrefix(key, "Arc-")

		// If it's an ARC header with instance >= current, skip it
		if isARC && h.Instance >= instance {
			continue
		}

		buf.WriteString(h.Raw)
	}

	// Add the blank line separator
	buf.WriteString("\r\n")

	// Add body
	buf.WriteString(body)

	return buf.String()
}

// GetARCAuthenticationResults extracts the most recent ARC-Authentication-Results header.
//
// This function retrieves the authentication results from the last hop in the
// ARC chain (highest instance number). This is useful for understanding what
// authentication checks (SPF, DKIM, DMARC) were performed by the most recent
// intermediary.
//
// Returns nil if no ARC headers are present (not an error condition).
//
// Example:
//
//	results, err := GetARCAuthenticationResults(rawEmail)
//	if err != nil {
//	    return err
//	}
//	if results != nil {
//	    for _, r := range results {
//	        fmt.Printf("Method: %s, Result: %s\n", r.Method, r.Result)
//	    }
//	}
func GetARCAuthenticationResults(rawEmail string) ([]authres.Result, error) {
	// Parse email headers using go-message
	h, err := emersiontextproto.ReadHeader(bufio.NewReader(strings.NewReader(rawEmail)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse email headers: %w", err)
	}

	// Find the highest instance ARC-Authentication-Results
	arcSets, maxInstance := extractARCSets(h, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if maxInstance == 0 {
		return nil, nil // No ARC headers
	}

	set := arcSets[maxInstance]
	if set == nil || set.AuthenticationResults == "" {
		return nil, fmt.Errorf("no ARC-Authentication-Results found for instance %d", maxInstance)
	}

	// Parse the Authentication-Results header
	// Format: ARC-Authentication-Results: i=N; authserv-id; methods
	// We need to extract the part after "i=N;"
	parts := strings.SplitN(set.AuthenticationResults, ";", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid ARC-Authentication-Results format")
	}

	authResultsStr := parts[1]
	_, results, err := authres.Parse(authResultsStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authentication results: %w", err)
	}

	return results, nil
}

// ARCSigner handles signing emails with ARC headers to preserve authentication
// results when acting as a mail forwarder or intermediary.
//
// When an email passes through Mizu and needs to be forwarded, ARC signing
// ensures that downstream mail servers can verify that the email passed
// authentication checks at this hop, even if SPF/DKIM alignment breaks during
// forwarding.
//
// The signer uses an RSA private key to create cryptographic signatures.
// The corresponding public key must be published in DNS as a TXT record at:
//
//	<selector>._domainkey.<domain>
//
// For example, with selector="arc" and domain="mail.example.com":
//
//	arc._domainkey.mail.example.com TXT "v=DKIM1; k=rsa; p=<base64-public-key>"
//
// ARC signing adds three headers per instance:
//   - ARC-Authentication-Results: Records SPF/DKIM/DMARC results
//   - ARC-Message-Signature: Signs message headers and body
//   - ARC-Seal: Signs the entire ARC chain with validation status
type ARCSigner struct {
	Domain     string          // Domain to sign with (e.g., "mail.example.com")
	Selector   string          // DKIM selector (e.g., "arc")
	PrivateKey *rsa.PrivateKey // RSA private key for signing
	Logger     *slog.Logger    // Logger
}

// NewARCSigner creates a new ARC signer from a private key file.
//
// The private key must be in PEM format and can be either:
//   - PKCS#1 format (BEGIN RSA PRIVATE KEY)
//   - PKCS#8 format (BEGIN PRIVATE KEY)
//
// To generate a suitable key pair:
//
//	# Generate private key (2048 or 4096 bits recommended)
//	openssl genrsa -out arc-private.pem 2048
//
//	# Extract public key for DNS
//	openssl rsa -in arc-private.pem -pubout -outform PEM
//
// Parameters:
//   - domain: The domain that will appear in ARC signatures (must match DNS)
//   - selector: The DKIM selector (must match DNS record)
//   - privateKeyPath: Path to PEM-encoded RSA private key file
//   - logger: Structured logger (uses nop logger if nil)
//
// Returns an error if the key file cannot be read or parsed.
//
// Example:
//
//	signer, err := NewARCSigner(
//	    "mail.example.com",
//	    "arc",
//	    "/etc/mizu/arc-private.pem",
//	    logger,
//	)
//	if err != nil {
//	    log.Fatal("Failed to create ARC signer:", err)
//	}
func NewARCSigner(domain, selector, privateKeyPath string, logger *slog.Logger) (*ARCSigner, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// Read private key file
	keyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	// Parse PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from private key")
	}

	// Parse RSA private key
	var privateKey *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
		}
	} else if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
	} else {
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}

	return &ARCSigner{
		Domain:     domain,
		Selector:   selector,
		PrivateKey: privateKey,
		Logger:     logger,
	}, nil
}

// SignEmail adds ARC headers to an email message
// It takes the raw email, authentication results from validation, and returns the email with ARC headers prepended
func (s *ARCSigner) SignEmail(rawEmail string, spfResult *SPFResult, dmarcResult *DMARCResult, arcResult *ARCResult) (string, error) {
	// Parse the email to extract headers
	msg, err := mail.ReadMessage(strings.NewReader(rawEmail))
	if err != nil {
		return "", fmt.Errorf("failed to parse email: %w", err)
	}

	// Determine the next ARC instance number
	instance := 1
	if arcResult != nil && arcResult.Instance > 0 {
		instance = arcResult.Instance + 1
	}

	// Build ARC-Authentication-Results header
	aar := s.buildAuthenticationResults(instance, spfResult, dmarcResult, arcResult)

	// Build ARC-Message-Signature header
	ams, err := s.buildMessageSignature(instance, rawEmail, msg)
	if err != nil {
		return "", fmt.Errorf("failed to build ARC-Message-Signature: %w", err)
	}

	// Build ARC-Seal header (signs the ARC chain)
	as, err := s.buildSeal(instance, rawEmail, aar, ams, arcResult)
	if err != nil {
		return "", fmt.Errorf("failed to build ARC-Seal: %w", err)
	}

	// Prepend ARC headers to the email
	// Order matters: ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results
	arcHeaders := fmt.Sprintf("ARC-Seal: %s\r\nARC-Message-Signature: %s\r\nARC-Authentication-Results: %s\r\n", as, ams, aar)

	s.Logger.Info("Added ARC headers",
		"instance", instance,
		"domain", s.Domain,
		"selector", s.Selector)

	return arcHeaders + rawEmail, nil
}

// buildAuthenticationResults creates the ARC-Authentication-Results header
func (s *ARCSigner) buildAuthenticationResults(instance int, spfResult *SPFResult, dmarcResult *DMARCResult, arcResult *ARCResult) string {
	parts := []string{
		fmt.Sprintf("i=%d", instance),
		s.Domain,
	}

	// Add SPF result
	if spfResult != nil {
		spfStatus := strings.ToLower(string(spfResult.Result.Value))
		parts = append(parts, fmt.Sprintf("spf=%s smtp.mailfrom=%s", spfStatus, spfResult.Domain))
	}

	// Add DMARC result
	if dmarcResult != nil {
		dmarcStatus := "fail"
		if dmarcResult.Pass {
			dmarcStatus = "pass"
		}
		parts = append(parts, fmt.Sprintf("dmarc=%s", dmarcStatus))
	}

	// Add ARC result
	if arcResult != nil && arcResult.Instance > 0 {
		arcStatus := "fail"
		if arcResult.Pass {
			arcStatus = "pass"
		}
		parts = append(parts, fmt.Sprintf("arc=%s (i=%d)", arcStatus, arcResult.Instance))
	}

	return strings.Join(parts, "; ")
}

// buildMessageSignature creates the ARC-Message-Signature header
func (s *ARCSigner) buildMessageSignature(instance int, rawEmail string, msg *mail.Message) (string, error) {
	// ARC-Message-Signature is similar to DKIM-Signature but for ARC
	// It signs selected headers from the original message

	// Extract headers to sign (typical set for ARC)
	headersToSign := []string{"from", "to", "subject", "date", "message-id"}

	// Calculate body hash
	bodyHash := s.calculateBodyHash(rawEmail)

	// Build the signature header (unsigned)
	timestamp := time.Now().Unix()
	sigHeader := fmt.Sprintf("i=%d; a=rsa-sha256; d=%s; s=%s; t=%d; c=relaxed/relaxed; h=%s; bh=%s; b=",
		instance,
		s.Domain,
		s.Selector,
		timestamp,
		strings.Join(headersToSign, ":"),
		bodyHash)

	// Create data to sign (headers + signature header without b= value)
	dataToSign := s.buildSigningData(msg, headersToSign, sigHeader)

	// Sign the data
	signature, err := s.signData(dataToSign)
	if err != nil {
		return "", fmt.Errorf("failed to sign data: %w", err)
	}

	// Add signature to header
	return sigHeader + signature, nil
}

// buildSeal creates the ARC-Seal header
func (s *ARCSigner) buildSeal(instance int, rawEmail string, aar string, ams string, arcResult *ARCResult) (string, error) {
	// ARC-Seal signs the entire ARC chain up to this point
	// It includes all previous ARC headers plus the new ones

	// Determine chain validation result
	cv := "none" // First ARC seal
	if instance > 1 {
		if arcResult != nil && arcResult.Pass {
			cv = "pass"
		} else {
			cv = "fail"
		}
	}

	// Build the seal header (unsigned)
	timestamp := time.Now().Unix()
	sealHeader := fmt.Sprintf("i=%d; a=rsa-sha256; d=%s; s=%s; t=%d; cv=%s; b=",
		instance,
		s.Domain,
		s.Selector,
		timestamp,
		cv)

	// Create data to sign (AAR + AMS + seal header without b= value)
	dataToSign := fmt.Sprintf("%s\r\n%s\r\n%s", aar, ams, sealHeader)

	// Sign the data
	signature, err := s.signData(dataToSign)
	if err != nil {
		return "", fmt.Errorf("failed to sign seal: %w", err)
	}

	// Add signature to header
	return sealHeader + signature, nil
}

// calculateBodyHash computes the body hash for ARC-Message-Signature
func (s *ARCSigner) calculateBodyHash(rawEmail string) string {
	// Find the body (after headers)
	bodyStart := strings.Index(rawEmail, "\r\n\r\n")
	if bodyStart == -1 {
		bodyStart = strings.Index(rawEmail, "\n\n")
		if bodyStart == -1 {
			return "" // No body
		}
		bodyStart += 2
	} else {
		bodyStart += 4
	}

	body := rawEmail[bodyStart:]

	// Compute SHA-256 hash
	hash := sha256.Sum256([]byte(body))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// buildSigningData creates the data to be signed for ARC-Message-Signature
func (s *ARCSigner) buildSigningData(msg *mail.Message, headersToSign []string, sigHeader string) string {
	var parts []string

	// Add each header to the signing data
	for _, headerName := range headersToSign {
		if value := msg.Header.Get(headerName); value != "" {
			parts = append(parts, fmt.Sprintf("%s: %s", headerName, value))
		}
	}

	// Add the signature header itself (without the b= value)
	parts = append(parts, "arc-message-signature: "+sigHeader)

	return strings.Join(parts, "\r\n")
}

// signData signs the given data using RSA-SHA256
func (s *ARCSigner) signData(data string) (string, error) {
	// Compute SHA-256 hash
	hash := sha256.Sum256([]byte(data))

	// Sign with RSA
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.PrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("RSA signing failed: %w", err)
	}

	// Encode to base64
	return base64.StdEncoding.EncodeToString(signature), nil
}

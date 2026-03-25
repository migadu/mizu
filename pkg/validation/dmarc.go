package validation

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/mail"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/authres"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"golang.org/x/net/publicsuffix"
	"log/slog"
)

// dmarcLookup is a function variable that can be replaced in tests for mocking.
var dmarcLookup = dmarc.Lookup

// DMARCResult represents the result of DMARC validation
// DMARC (Domain-based Message Authentication, Reporting & Conformance) helps prevent email spoofing
type DMARCResult struct {
	Pass           bool     // Whether DMARC validation passed (SPF or DKIM aligned)
	Policy         string   // Domain's DMARC policy: none, quarantine, or reject
	SPFAligned     bool     // Whether SPF passed AND domain aligned with From header
	DKIMAligned    bool     // Whether DKIM passed AND domain aligned with From header
	FailureReasons []string // List of reasons why validation failed
	NoDMARCRecord  bool     // Whether domain has no DMARC record
	ShouldBeJunk   bool     // Whether message should be marked as junk (no DMARC + SPF/DKIM failure)
}

// SPFResult holds the result of an SPF check from the SMTP session.
type SPFResult struct {
	Domain string
	Result authres.SPFResult
}

// DNS lookup timeout for DKIM and DMARC queries
const DNSLookupTimeout = 5 * time.Second

// Maximum age for DKIM signatures (reject signatures older than this)
// RFC 6376 recommends rejecting signatures older than a few days to prevent replay attacks
const MaxDKIMSignatureAge = 7 * 24 * time.Hour // 7 days

// lookupTXTWithTimeout is a function variable for DNS TXT lookups with timeout (can be mocked in tests)
var lookupTXTWithTimeout = defaultLookupTXTWithTimeout

// defaultLookupTXTWithTimeout performs a DNS TXT lookup with a timeout.
// Uses net.Resolver with context for proper timeout propagation to the
// underlying DNS query, preventing goroutine leaks on timeout.
func defaultLookupTXTWithTimeout(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DNSLookupTimeout)
	defer cancel()

	resolver := &net.Resolver{}
	records, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil, err
	}
	return records, nil
}

// CheckDMARC performs DMARC validation on an email
// It validates DKIM signatures and checks DMARC policy compliance
func CheckDMARC(ctx context.Context, rawEmail string, spfResult *SPFResult, quarantinePolicyAction string, logger *slog.Logger) (*DMARCResult, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	// Parse the email message to extract headers
	msg, err := mail.ReadMessage(strings.NewReader(rawEmail))
	if err != nil {
		return nil, fmt.Errorf("failed to parse email: %w", err)
	}

	// Extract the From header - this is what recipients see as the sender
	fromHeader := msg.Header.Get("From")
	if fromHeader == "" {
		return &DMARCResult{
			Pass:           false,
			Policy:         "none",
			FailureReasons: []string{"missing From header"},
		}, nil
	}

	// Parse From address to get domain
	fromAddrs, err := mail.ParseAddressList(fromHeader)
	if err != nil || len(fromAddrs) == 0 {
		return &DMARCResult{
			Pass:           false,
			Policy:         "none",
			FailureReasons: []string{"invalid From header format"},
		}, nil
	}

	fromAddr := fromAddrs[0].Address
	parts := strings.Split(fromAddr, "@")
	if len(parts) != 2 {
		return &DMARCResult{
			Pass:           false,
			Policy:         "none",
			FailureReasons: []string{"invalid From address format"},
		}, nil
	}
	fromDomain := parts[1]

	// Create result structure
	result := &DMARCResult{
		FailureReasons: make([]string, 0),
		Policy:         "none",
	}

	// Look up DMARC policy via DNS TXT record (_dmarc.domain.com)
	record, err := dmarcLookup(fromDomain)
	noDMARCRecord := false
	if err != nil {
		logger.Debug("DMARC lookup failed", "domain", fromDomain, "error", err)
		// No DMARC record - continue processing to check SPF/DKIM
		noDMARCRecord = true
		result.NoDMARCRecord = true
		// Don't return early - we need to check SPF/DKIM to determine if it should be junk
	} else {
		// Set the DMARC policy
		result.Policy = string(record.Policy)
	}

	// Verify DKIM signatures with DNS timeout
	reader := strings.NewReader(rawEmail)
	verifyOpts := &dkim.VerifyOptions{
		LookupTXT: lookupTXTWithTimeout,
	}
	verifications, err := dkim.VerifyWithOptions(reader, verifyOpts)
	if err != nil && err != io.EOF {
		logger.Warn("DKIM verification error", "error", err, "from_domain", fromDomain)
		result.FailureReasons = append(result.FailureReasons, fmt.Sprintf("DKIM verification error: %v", err))
	}

	// Log summary of DKIM signatures found
	if len(verifications) > 0 {
		logger.Debug("DKIM signatures found",
			"from_domain", fromDomain,
			"signature_count", len(verifications))
	}

	// Check DKIM results and alignment
	for idx, v := range verifications {
		if v.Err == nil {
			// Log detailed signature information for debugging
			if !v.Expiration.IsZero() {
				logger.Debug("Processing DKIM signature",
					"signature_index", idx,
					"signing_domain", v.Domain,
					"identifier", v.Identifier,
					"signature_time", v.Time,
					"signed_headers", v.HeaderKeys,
					"expiration", v.Expiration)
			} else {
				logger.Debug("Processing DKIM signature",
					"signature_index", idx,
					"signing_domain", v.Domain,
					"identifier", v.Identifier,
					"signature_time", v.Time,
					"signed_headers", v.HeaderKeys)
			}

			// Check signature age to prevent replay attacks
			if !v.Time.IsZero() {
				signatureAge := time.Since(v.Time)
				if signatureAge > MaxDKIMSignatureAge {
					logger.Warn("DKIM signature too old",
						"domain", v.Domain,
						"identifier", v.Identifier,
						"age", signatureAge,
						"max_age", MaxDKIMSignatureAge,
						"signature_time", v.Time)
					result.FailureReasons = append(result.FailureReasons,
						fmt.Sprintf("DKIM signature too old: %v (max: %v)", signatureAge.Round(time.Hour), MaxDKIMSignatureAge))
					continue // Skip this signature, try others
				}
				if signatureAge < 0 {
					// Signature timestamp is in the future
					logger.Warn("DKIM signature timestamp in future",
						"domain", v.Domain,
						"identifier", v.Identifier,
						"signature_time", v.Time,
						"time_offset", -signatureAge)
					result.FailureReasons = append(result.FailureReasons,
						"DKIM signature timestamp is in the future")
					continue
				}
			}

			// Check signature expiration
			if !v.Expiration.IsZero() && time.Now().After(v.Expiration) {
				logger.Warn("DKIM signature expired",
					"domain", v.Domain,
					"identifier", v.Identifier,
					"expiration", v.Expiration,
					"expired_since", time.Since(v.Expiration))
				result.FailureReasons = append(result.FailureReasons,
					fmt.Sprintf("DKIM signature expired at %v", v.Expiration.Format(time.RFC3339)))
				continue
			}

			// DKIM signature is valid and not expired, check domain alignment
			signingDomain := v.Domain

			// Check DKIM alignment based on DMARC alignment mode
			alignmentMode := "relaxed"
			aligned := false
			if !noDMARCRecord && record.DKIMAlignment == dmarc.AlignmentStrict {
				// Strict alignment: exact domain match
				alignmentMode = "strict"
				aligned = strings.EqualFold(signingDomain, fromDomain)
			} else {
				// Relaxed alignment (default): organizational domain match
				aligned = isAligned(fromDomain, signingDomain, false)
			}

			if aligned {
				result.DKIMAligned = true
				logger.Info("DKIM signature passed and aligned",
					"from_domain", fromDomain,
					"signing_domain", signingDomain,
					"identifier", v.Identifier,
					"alignment_mode", alignmentMode,
					"signature_time", v.Time,
					"signature_age", time.Since(v.Time),
					"signed_headers", v.HeaderKeys)
				break
			} else {
				logger.Debug("DKIM signature valid but not aligned",
					"from_domain", fromDomain,
					"signing_domain", signingDomain,
					"identifier", v.Identifier,
					"alignment_mode", alignmentMode,
					"reason", "domain mismatch")
			}
		} else {
			// DKIM verification failed
			logger.Warn("DKIM signature verification failed",
				"signing_domain", v.Domain,
				"identifier", v.Identifier,
				"error", v.Err,
				"signed_headers", v.HeaderKeys)
			result.FailureReasons = append(result.FailureReasons, fmt.Sprintf("DKIM failed: %v", v.Err))
		}
	}

	if len(verifications) == 0 {
		logger.Debug("No DKIM signatures found", "domain", fromDomain)
		result.FailureReasons = append(result.FailureReasons, "no DKIM signatures found")
	}

	// Check SPF alignment using the result from the SMTP session
	if spfResult != nil && spfResult.Result.Value == authres.ResultPass {
		spfDomain := spfResult.Domain
		if spfDomain != "" {
			// Check SPF alignment based on DMARC alignment mode
			isStrict := !noDMARCRecord && record.SPFAlignment == dmarc.AlignmentStrict
			if isAligned(fromDomain, spfDomain, isStrict) {
				result.SPFAligned = true
				logger.Debug("SPF passed and aligned", "domain", fromDomain, "envelope_domain", spfDomain)
			} else {
				logger.Debug("SPF passed but not aligned", "domain", fromDomain, "envelope_domain", spfDomain)
			}
		} else {
			result.FailureReasons = append(result.FailureReasons, "SPF passed but domain was empty")
		}
	}

	// DMARC passes if EITHER SPF or DKIM is aligned (not both required)
	result.Pass = result.SPFAligned || result.DKIMAligned

	// Special handling for no DMARC record case
	if noDMARCRecord {
		// If no DMARC record exists:
		// - If SPF or DKIM is aligned, message passes (result.Pass is already set correctly)
		// - If neither SPF nor DKIM is aligned, mark as junk
		if !result.SPFAligned && !result.DKIMAligned {
			result.ShouldBeJunk = true
			result.FailureReasons = append(result.FailureReasons,
				"No DMARC record and neither SPF nor DKIM aligned - marking as junk")
			logger.Debug("Marking as junk - no DMARC record", "domain", fromDomain)
		} else {
			// Even with no DMARC, if SPF or DKIM passes, we let it through
			result.Pass = true
		}
	} else {
		// Handle policies for domains with DMARC records
		if !result.Pass {
			switch result.Policy {
			case "reject":
				result.FailureReasons = append(result.FailureReasons,
					"DMARC policy is 'reject' and neither SPF nor DKIM aligned")
			case "quarantine":
				// Apply quarantine policy action
				if quarantinePolicyAction == "junk" {
					result.ShouldBeJunk = true
					result.FailureReasons = append(result.FailureReasons,
						"DMARC policy is 'quarantine' and authentication failed - marking as junk")
				}
				// "none" or "reject" actions are handled by the caller
			}
		}
	}

	logger.Debug("DMARC validation result",
		"domain", fromDomain,
		"policy", result.Policy,
		"spf_aligned", result.SPFAligned,
		"dkim_aligned", result.DKIMAligned,
		"pass", result.Pass,
		"no_dmarc", result.NoDMARCRecord,
		"should_be_junk", result.ShouldBeJunk)

	return result, nil
}

// isAligned checks if two domains are aligned according to DMARC rules
// Alignment ensures the authenticated domain matches the visible From domain
func isAligned(fromDomain, authDomain string, strict bool) bool {
	// Normalize domains for comparison
	fromDomain = strings.ToLower(strings.TrimSpace(fromDomain))
	authDomain = strings.ToLower(strings.TrimSpace(authDomain))

	if strict {
		// Strict alignment requires exact domain match
		return fromDomain == authDomain
	}

	// Relaxed alignment allows subdomains to align with parent domain
	// e.g., mail.example.com aligns with example.com
	fromOrg := getOrganizationalDomain(fromDomain)
	authOrg := getOrganizationalDomain(authDomain)
	return fromOrg == authOrg
}

// getOrganizationalDomain returns the organizational domain using the Public Suffix List.
// This correctly handles multi-level TLDs like .co.uk.
func getOrganizationalDomain(domain string) string {
	eTLD, _ := publicsuffix.EffectiveTLDPlusOne(domain)
	// On error (e.g., for "localhost"), it returns the original domain, which is fine.
	return eTLD
}

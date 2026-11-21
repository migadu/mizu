package validation

import (
	"context"
	"errors"
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
// The lookupTXT argument is used to perform the underlying DNS TXT query so the
// caller's configured DNS resolver is honored.
var dmarcLookup = func(domain string, lookupTXT func(string) ([]string, error)) (*dmarc.Record, error) {
	return dmarc.LookupWithOptions(domain, &dmarc.LookupOptions{LookupTXT: lookupTXT})
}

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

// DNSLookupTimeout is the default per-TXT-lookup deadline used when callers
// pass a zero timeout. Production callers should pass globalConfig.DNS.TimeoutSeconds
// so DKIM/DMARC honor the same configurable timeout as MX/SPF.
const DNSLookupTimeout = 5 * time.Second

// Maximum age for DKIM signatures (reject signatures older than this)
// RFC 6376 recommends rejecting signatures older than a few days to prevent replay attacks
const MaxDKIMSignatureAge = 7 * 24 * time.Hour // 7 days

// MaxDKIMClockSkew is how far ahead of this host's clock a signature's t= may
// be. Signer and verifier clocks routinely differ by seconds; with no
// allowance a valid signature made "one second from now" was thrown away.
const MaxDKIMClockSkew = 5 * time.Minute

// maxDKIMVerifications caps how many DKIM signatures of one message are
// verified. Each costs a goroutine, a DNS TXT lookup and a hash over the body,
// and the count is otherwise sender-controlled. Signatures beyond the cap are
// ignored (go-msgauth verifies the first N); real mail carries a handful.
const maxDKIMVerifications = 10

// TXTResolver is the minimal interface CheckDMARC needs to perform TXT lookups
// for both the DMARC policy record and DKIM key records.
//
// Both *net.Resolver and *dns.CachingWrapper satisfy this — production callers
// should pass the caching wrapper so DKIM key lookups benefit from caching.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// lookupTXTWithTimeout is a test-only fallback for when CheckDMARC is invoked
// without a TXTResolver. It uses the system resolver and is mockable in tests.
// Production code must pass a non-nil TXTResolver to CheckDMARC.
var lookupTXTWithTimeout = defaultLookupTXTWithTimeout

// defaultLookupTXTWithTimeout performs a DNS TXT lookup with a timeout using the system resolver.
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

// CheckDMARC performs DMARC validation on an email.
// It validates DKIM signatures and checks DMARC policy compliance.
//
// txtResolver is used for both the DMARC policy TXT lookup and DKIM key TXT lookups,
// so the caller's configured DNS resolver (and any caching layer) is honored. Pass
// the cluster's *dns.CachingWrapper to get cached TXT lookups. Pass nil only in tests
// — production callers must supply a resolver.
//
// lookupTimeout bounds each TXT query. A zero value falls back to DNSLookupTimeout.
//
// The parent ctx propagates into each lookup, so cancellation of the SMTP session
// cancels in-flight DNS queries.
func CheckDMARC(ctx context.Context, rawEmail string, spfResult *SPFResult, quarantinePolicyAction string, txtResolver TXTResolver, lookupTimeout time.Duration, logger *slog.Logger) (*DMARCResult, error) {
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

	// Exactly one From header (RFC 5322 section 3.6). With several, which one
	// a mail client shows is up to the client; evaluating the first let a
	// message pass on the attacker's domain while displaying another.
	if len(msg.Header["From"]) > 1 {
		return unparseableFromResult("multiple From headers"), nil
	}

	// Parse From address to get domain
	fromAddrs, err := mail.ParseAddressList(fromHeader)
	if err != nil || len(fromAddrs) == 0 {
		return unparseableFromResult("invalid From header format"), nil
	}
	// One author address. RFC 7489 section 6.6.1: a From with several
	// addresses has no single domain to evaluate; same hole as above.
	if len(fromAddrs) > 1 {
		return unparseableFromResult("multiple addresses in From header"), nil
	}

	fromAddr := fromAddrs[0].Address
	parts := strings.Split(fromAddr, "@")
	if len(parts) != 2 || parts[1] == "" {
		return unparseableFromResult("invalid From address format"), nil
	}
	fromDomain := parts[1]

	// Create result structure
	result := &DMARCResult{
		FailureReasons: make([]string, 0),
		Policy:         "none",
	}

	if lookupTimeout <= 0 {
		lookupTimeout = DNSLookupTimeout
	}

	// Build a TXT lookup closure that propagates the parent ctx and applies the
	// per-lookup timeout. dkim.VerifyOptions and dmarc.LookupWithOptions both
	// expect a func(string)([]string, error) signature without a ctx parameter,
	// so the closure bridges the two.
	var lookupTXT func(string) ([]string, error)
	if txtResolver != nil {
		lookupTXT = func(name string) ([]string, error) {
			lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
			defer cancel()
			txts, err := txtResolver.LookupTXT(lookupCtx, name)
			// Strip the misleading Server field from net.DNSError. With a custom
			// Dial, Go reports the resolv.conf nameserver here, not the upstream
			// our Dial actually connected to.
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.Server != "" {
				cleaned := *dnsErr
				cleaned.Server = ""
				return txts, &cleaned
			}
			return txts, err
		}
	} else {
		// Test-only fallback: re-read the package-level mockable variable on
		// each invocation so swaps mid-lookup are observed.
		lookupTXT = func(name string) ([]string, error) {
			return lookupTXTWithTimeout(name)
		}
	}

	// Look up DMARC policy via DNS TXT record (_dmarc.domain.com)
	record, err := dmarcLookup(fromDomain, lookupTXT)

	// RFC 7489 §6.6.3: with no record at the From domain itself, the policy of
	// its organizational domain applies - and for a subdomain that is the sp=
	// tag when present, p= otherwise. Without this fallback any made-up
	// subdomain of a p=reject domain counted as "no DMARC record".
	//
	// A temporary DNS failure is not "no record": the From domain may publish
	// its own (possibly more lenient) policy, so the organizational domain's
	// must not be applied in its place.
	fromOrgRecord := false
	if err != nil && !dmarc.IsTempFail(err) {
		if orgDomain := getOrganizationalDomain(fromDomain); orgDomain != "" && orgDomain != normalizeDomain(fromDomain) {
			if orgRecord, orgErr := dmarcLookup(orgDomain, lookupTXT); orgErr == nil {
				logger.Debug("Using organizational domain DMARC record", "domain", fromDomain, "org_domain", orgDomain)
				record, err, fromOrgRecord = orgRecord, nil, true
			}
		}
	}

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
		if fromOrgRecord && record.SubdomainPolicy != "" {
			result.Policy = string(record.SubdomainPolicy)
		}
	}

	// Verify DKIM signatures using the same resolver-aware TXT lookup
	reader := strings.NewReader(rawEmail)
	verifyOpts := &dkim.VerifyOptions{
		LookupTXT:        lookupTXT,
		MaxVerifications: maxDKIMVerifications,
	}
	verifications, err := dkim.VerifyWithOptions(reader, verifyOpts)
	if errors.Is(err, dkim.ErrTooManySignatures) {
		// Not a verification failure: the first maxDKIMVerifications
		// signatures were verified and are judged below as usual.
		logger.Debug("DKIM signatures beyond the verification cap ignored", "cap", maxDKIMVerifications, "from_domain", fromDomain)
	} else if err != nil && err != io.EOF {
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
			if problem := dkimTimestampProblem(v.Time, time.Now()); problem != "" {
				logger.Warn("DKIM signature timestamp not acceptable",
					"domain", v.Domain,
					"identifier", v.Identifier,
					"signature_time", v.Time,
					"problem", problem)
				result.FailureReasons = append(result.FailureReasons, problem)
				continue // Skip this signature, try others
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

// dkimTimestampProblem returns why a signature's t= timestamp makes it
// unusable, or "" if it is fine. A missing timestamp is fine.
func dkimTimestampProblem(signed, now time.Time) string {
	if signed.IsZero() {
		return ""
	}
	age := now.Sub(signed)
	if age > MaxDKIMSignatureAge {
		return fmt.Sprintf("DKIM signature too old: %v (max: %v)", age.Round(time.Hour), MaxDKIMSignatureAge)
	}
	if age < -MaxDKIMClockSkew {
		return "DKIM signature timestamp is in the future"
	}
	return ""
}

// unparseableFromResult is the verdict for a From header no domain can be
// extracted from. There is no domain, so there is no policy to look up - but
// that must not read as "nothing to enforce": returning a bare Policy "none"
// let a spoofer skip a p=reject domain's policy by breaking the header syntax
// slightly (lenient MUAs still show the address). The message is marked as
// junk, the same treatment as an unauthenticated message from a domain with no
// DMARC record.
func unparseableFromResult(reason string) *DMARCResult {
	return &DMARCResult{
		Pass:           false,
		Policy:         "none",
		ShouldBeJunk:   true,
		FailureReasons: []string{reason, "From header has no single parseable domain - marking as junk"},
	}
}

// normalizeDomain lowercases a domain and drops the root label's trailing dot,
// so "Example.COM." and "example.com" compare equal.
func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// isAligned checks if two domains are aligned according to DMARC rules
// Alignment ensures the authenticated domain matches the visible From domain
func isAligned(fromDomain, authDomain string, strict bool) bool {
	// Normalize domains for comparison
	fromDomain = normalizeDomain(fromDomain)
	authDomain = normalizeDomain(authDomain)

	// An absent domain aligns with nothing - in particular not with another
	// absent domain.
	if fromDomain == "" || authDomain == "" {
		return false
	}

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
	domain = normalizeDomain(domain)
	org, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil || org == "" {
		// EffectiveTLDPlusOne fails - and returns "" - for a name that is
		// itself a public suffix ("gov.in", "github.io") and for malformed
		// names. Such a domain is its own organizational domain. Returning ""
		// here made every such pair compare equal under relaxed alignment.
		return domain
	}
	return org
}

package validation

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/authres"
)

// Note: These tests rely on the public DNS records of dmarc.io, which are
// specifically set up for testing DMARC implementations.

func TestCheckDMARC_Pass(t *testing.T) {
	// This email has a valid DKIM signature for the domain dmarc.io.
	// The domain dmarc.io has a DMARC policy. We will simulate a passing
	// and aligned SPF check to ensure DMARC passes.
	rawEmail := `From: Test User <test@dmarc.io>
To: Recipient <recipient@example.com>
Subject: DMARC Pass Test
Date: Fri, 1 Jan 2021 00:00:00 +0000
Message-ID: <pass@dmarc.io>

This is a test email that should pass DMARC via SPF alignment.
`

	// Simulate a passing and aligned SPF result.
	spfResult := &SPFResult{
		Domain: "dmarc.io",
		Result: authres.SPFResult{Value: authres.ResultPass},
	}

	result, err := CheckDMARC(context.Background(), rawEmail, spfResult, "junk", nil, 0, nil)
	if err != nil {
		t.Fatalf("CheckDMARC failed: %v", err)
	}

	if !result.Pass {
		t.Errorf("Expected DMARC to pass, but it failed. Reasons: %v", result.FailureReasons)
	}
	if !result.SPFAligned {
		t.Error("Expected SPF to be aligned, but it was not.")
	}
	if result.ShouldBeJunk {
		t.Error("Message should not be marked as junk.")
	}
}

func TestCheckDMARC_Reject(t *testing.T) {
	// This email has no valid DKIM signature and we simulate a failing SPF.
	// The domain st.dmarc.io has a strict DMARC policy of p=reject.
	rawEmail := `From: Test User <test@st.dmarc.io>
To: Recipient <recipient@example.com>
Subject: DMARC Reject Test
Date: Fri, 1 Jan 2021 00:00:00 +0000
Message-ID: <reject@st.dmarc.io>

This is a test email that should be rejected by DMARC.
`

	// Simulate a failing SPF result.
	spfResult := &SPFResult{
		Domain: "st.dmarc.io",
		Result: authres.SPFResult{Value: authres.ResultFail},
	}

	result, err := CheckDMARC(context.Background(), rawEmail, spfResult, "junk", nil, 0, nil)
	if err != nil {
		t.Fatalf("CheckDMARC failed: %v", err)
	}

	if result.Pass {
		t.Error("Expected DMARC to fail, but it passed.")
	}
	if result.Policy != "reject" {
		t.Errorf("Expected policy to be 'reject', but got '%s'", result.Policy)
	}
	if result.ShouldBeJunk {
		t.Error("Message should not be marked as junk (it should be rejected outright).")
	}
}

func TestCheckDMARC_Quarantine(t *testing.T) {
	// The domain qt.dmarc.io has a DMARC policy of p=quarantine.
	rawEmail := `From: Test User <test@qt.dmarc.io>
To: Recipient <recipient@example.com>
Subject: DMARC Quarantine Test
Date: Fri, 1 Jan 2021 00:00:00 +0000
Message-ID: <quarantine@qt.dmarc.io>

This is a test email that should be quarantined by DMARC.
`
	spfResult := &SPFResult{
		Domain: "qt.dmarc.io",
		Result: authres.SPFResult{Value: authres.ResultFail},
	}

	// Test case 1: Quarantine is treated as junk
	t.Run("QuarantineAsJunk", func(t *testing.T) {
		result, err := CheckDMARC(context.Background(), rawEmail, spfResult, "junk", nil, 0, nil)
		if err != nil {
			t.Fatalf("CheckDMARC failed: %v", err)
		}

		if result.Pass {
			t.Error("Expected DMARC to fail, but it passed.")
		}
		if result.Policy != "quarantine" {
			t.Errorf("Expected policy to be 'quarantine', but got '%s'", result.Policy)
		}
		if !result.ShouldBeJunk {
			t.Error("Message should be marked as junk when quarantineAsJunk is true.")
		}
	})

	// Test case 2: Quarantine is not treated as junk
	t.Run("QuarantineNotAsJunk", func(t *testing.T) {
		result, err := CheckDMARC(context.Background(), rawEmail, spfResult, "none", nil, 0, nil)
		if err != nil {
			t.Fatalf("CheckDMARC failed: %v", err)
		}

		if result.Pass {
			t.Error("Expected DMARC to fail, but it passed.")
		}
		if result.Policy != "quarantine" {
			t.Errorf("Expected policy to be 'quarantine', but got '%s'", result.Policy)
		}
		if result.ShouldBeJunk {
			t.Error("Message should not be marked as junk when quarantineAsJunk is false.")
		}
	})
}

func TestCheckDMARC_NoDMARCRecord(t *testing.T) {
	// Use a domain that is unlikely to have a DMARC record.
	domain := fmt.Sprintf("no-dmarc-record-%d.example.com", time.Now().UnixNano())
	rawEmail := fmt.Sprintf(`From: Test User <test@%s>
To: Recipient <recipient@example.com>
Subject: No DMARC Record Test

This is a test email from a domain with no DMARC record.
`, domain)

	spfResult := &SPFResult{
		Domain: domain,
		Result: authres.SPFResult{Value: authres.ResultFail},
	}

	result, err := CheckDMARC(context.Background(), rawEmail, spfResult, "junk", nil, 0, nil)
	if err != nil {
		t.Fatalf("CheckDMARC failed: %v", err)
	}

	if !result.NoDMARCRecord {
		t.Error("Expected NoDMARCRecord to be true.")
	}
	if result.Pass {
		t.Error("Expected DMARC to fail when no record and no auth, but it passed.")
	}
	if !result.ShouldBeJunk {
		t.Error("Message should be marked as junk when no DMARC and auth fails.")
	}
}

func TestCheckDMARC_MalformedHeaders(t *testing.T) {
	// Test with no From header
	rawEmail := `To: Recipient <recipient@example.com>
Subject: No From Header

Test.
`
	result, err := CheckDMARC(context.Background(), rawEmail, nil, "junk", nil, 0, nil)
	if err != nil {
		t.Fatalf("CheckDMARC failed: %v", err)
	}
	if result.Pass || len(result.FailureReasons) == 0 || result.FailureReasons[0] != "missing From header" {
		t.Errorf("Expected 'missing From header' failure, got: %v", result.FailureReasons)
	}
}

func TestDKIMDNSTimeout(t *testing.T) {
	// Test that DKIM verification handles DNS timeouts gracefully
	rawEmail := `From: Test User <test@example.com>
To: Recipient <recipient@example.com>
Subject: DNS Timeout Test
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1;
 h=from:to:subject; bh=test; b=invalid
Date: Fri, 1 Jan 2021 00:00:00 +0000

Test email with invalid DKIM signature that will trigger DNS lookup.
`

	// Replace the DNS lookup function with one that times out
	originalLookup := lookupTXTWithTimeout
	defer func() {
		// Restore after test
		lookupTXTWithTimeout = originalLookup
	}()

	// Mock a slow DNS lookup that simulates hanging DNS server
	// The actual timeout logic will cancel this via context
	lookupTXTWithTimeout = func(domain string) ([]string, error) {
		// Simulate a slow DNS server
		ctx, cancel := context.WithTimeout(context.Background(), DNSLookupTimeout)
		defer cancel()

		select {
		case <-time.After(10 * time.Second):
			return nil, fmt.Errorf("DNS lookup took too long")
		case <-ctx.Done():
			return nil, fmt.Errorf("DNS lookup timeout: %w", ctx.Err())
		}
	}

	// This should complete within reasonable time despite DNS timeout
	start := time.Now()
	result, err := CheckDMARC(context.Background(), rawEmail, nil, "junk", nil, 0, nil)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("CheckDMARC failed: %v", err)
	}

	// DMARC TXT and DKIM key lookups both go through the same resolver-aware
	// LookupTXT, so each hits the 5s timeout sequentially. Allow up to ~2x
	// DNSLookupTimeout plus headroom.
	if duration > 2*DNSLookupTimeout+3*time.Second {
		t.Errorf("CheckDMARC took too long: %v (expected ~%v)", duration, 2*DNSLookupTimeout)
	}

	// Should not pass due to DKIM failure
	if result.Pass {
		t.Error("Expected DMARC to fail due to DNS timeout, but it passed")
	}

	t.Logf("CheckDMARC completed in %v with result: %+v", duration, result)
}

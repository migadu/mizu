package smtp

import (
	"strings"
	"testing"

	"migadu/mizu/pkg/validation"

	"github.com/emersion/go-msgauth/authres"
)

func TestInjectMizuHeaders(t *testing.T) {
	// Original email without headers
	originalEmail := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Test Email\r\n" +
		"\r\n" +
		"This is the email body.\r\n"

	// Test parameters
	domain := "mail.example.com"
	remoteAddr := "1.2.3.4:12345"
	heloHostname := "client.example.com"
	traceID := "abc123def456"
	tlsVersion := "TLS 1.3"

	// Mock validation results
	spfResult := &validation.SPFResult{
		Domain: "example.com",
		Result: authres.SPFResult{
			Value: authres.ResultPass,
		},
	}

	dmarcResult := &validation.DMARCResult{
		Pass:        true,
		DKIMAligned: true,
		SPFAligned:  true,
	}

	arcResult := &validation.ARCResult{
		Pass: true,
	}

	// Inject headers
	modifiedEmail := InjectMizuHeaders(
		originalEmail,
		domain,
		remoteAddr,
		heloHostname,
		traceID,
		tlsVersion,
		spfResult,
		dmarcResult,
		arcResult,
		false, // not junk
		false, // don't disable mizu headers
	)

	// Verify the modified email contains expected headers
	tests := []struct {
		name     string
		contains string
	}{
		{"Received header exists", "Received: from"},
		{"Received contains HELO hostname", heloHostname},
		{"Received contains client IP", "1.2.3.4"},
		{"Received contains server domain", domain},
		{"Received contains protocol", "ESMTPS"},
		{"Received contains trace ID", traceID},
		{"X-Mizu-Trace-ID header", "X-Mizu-Trace-ID: " + traceID},
		{"X-Mizu-Authentication-Results header", "X-Mizu-Authentication-Results:"},
		{"SPF pass in authentication", "spf=pass"},
		{"DKIM pass in authentication", "dkim=pass"},
		{"DMARC pass in authentication", "dmarc=pass"},
		{"ARC pass in authentication", "arc=pass"},
		{"X-Mizu-Junk header", "X-Mizu-Junk: NO"},
		{"Original email preserved", "This is the email body."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(modifiedEmail, tt.contains) {
				t.Errorf("Modified email does not contain expected string: %q\nEmail:\n%s", tt.contains, modifiedEmail)
			}
		})
	}

	// Verify headers come before original email
	if !strings.HasPrefix(modifiedEmail, "Received:") {
		t.Error("Modified email should start with Received header")
	}

	// Verify original email is intact at the end
	if !strings.HasSuffix(modifiedEmail, originalEmail) {
		t.Error("Modified email should end with original email content")
	}
}

func TestInjectMizuHeaders_Junk(t *testing.T) {
	originalEmail := "From: spammer@bad.com\r\nSubject: Spam\r\n\r\nSpam content\r\n"

	modifiedEmail := InjectMizuHeaders(
		originalEmail,
		"mail.example.com",
		"5.6.7.8:9999",
		"spammer.bad.com",
		"trace123",
		"TLS 1.2",
		nil,   // no SPF
		nil,   // no DMARC
		nil,   // no ARC
		true,  // IS JUNK
		false, // don't disable mizu headers
	)

	// Should mark as junk
	if !strings.Contains(modifiedEmail, "X-Mizu-Junk: YES") {
		t.Error("Expected X-Mizu-Junk: YES for junk email")
	}

	// Should show missing authentication
	if !strings.Contains(modifiedEmail, "spf=none") {
		t.Error("Expected spf=none when no SPF result")
	}
	if !strings.Contains(modifiedEmail, "dmarc=none") {
		t.Error("Expected dmarc=none when no DMARC result")
	}
}

func TestInjectMizuHeaders_NoTLS(t *testing.T) {
	originalEmail := "From: sender@example.com\r\nSubject: Test\r\n\r\nBody\r\n"

	modifiedEmail := InjectMizuHeaders(
		originalEmail,
		"mail.example.com",
		"1.2.3.4:5678",
		"client.example.com",
		"trace456",
		"none", // No TLS
		nil,
		nil,
		nil,
		false,
		false, // don't disable mizu headers
	)

	// Should use ESMTP (not ESMTPS) when no TLS
	if !strings.Contains(modifiedEmail, "with ESMTP id") {
		t.Error("Expected 'with ESMTP' when TLS is not used")
	}
	if strings.Contains(modifiedEmail, "ESMTPS") {
		t.Error("Should not contain ESMTPS when TLS is not used")
	}
}

func TestBuildReceivedHeader(t *testing.T) {
	header := buildReceivedHeader(
		"mail.example.com",
		"192.0.2.1:54321",
		"sender.example.org",
		"xyz789",
		"TLS 1.3",
	)

	// Verify structure
	if !strings.HasPrefix(header, "Received: from sender.example.org") {
		t.Error("Received header should start with 'Received: from <hostname>'")
	}

	// Should contain IP
	if !strings.Contains(header, "192.0.2.1") {
		t.Error("Received header should contain client IP")
	}

	// Should contain server domain
	if !strings.Contains(header, "by mail.example.com") {
		t.Error("Received header should contain server domain")
	}

	// Should contain trace ID
	if !strings.Contains(header, "id xyz789") {
		t.Error("Received header should contain trace ID")
	}

	// Should end with CRLF
	if !strings.HasSuffix(header, "\r\n") {
		t.Error("Received header should end with CRLF")
	}
}

func TestBuildAuthenticationSummary(t *testing.T) {
	tests := []struct {
		name        string
		spf         *validation.SPFResult
		dmarc       *validation.DMARCResult
		arc         *validation.ARCResult
		expectedStr string
	}{
		{
			name: "All pass",
			spf: &validation.SPFResult{
				Result: authres.SPFResult{Value: authres.ResultPass},
			},
			dmarc: &validation.DMARCResult{
				Pass:        true,
				DKIMAligned: true,
			},
			arc: &validation.ARCResult{
				Pass:     true,
				Instance: 1, // Must have Instance > 0 for ARC to be evaluated
			},
			expectedStr: "spf=pass dkim=pass dmarc=pass arc=pass",
		},
		{
			name: "All fail",
			spf: &validation.SPFResult{
				Result: authres.SPFResult{Value: authres.ResultFail},
			},
			dmarc: &validation.DMARCResult{
				Pass:        false,
				DKIMAligned: false,
			},
			arc: &validation.ARCResult{
				Pass:     false,
				Instance: 1, // Must have Instance > 0 for ARC to be evaluated
			},
			expectedStr: "spf=fail dkim=fail dmarc=fail arc=fail",
		},
		{
			name:        "All none",
			spf:         nil,
			dmarc:       nil,
			arc:         nil,
			expectedStr: "spf=none dkim=none dmarc=none arc=none",
		},
		{
			name: "Mixed results",
			spf: &validation.SPFResult{
				Result: authres.SPFResult{Value: authres.ResultPass},
			},
			dmarc: &validation.DMARCResult{
				Pass:        false,
				DKIMAligned: true,
			},
			arc:         nil,
			expectedStr: "spf=pass dkim=pass dmarc=fail arc=none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildAuthenticationSummary(tt.spf, tt.dmarc, tt.arc)
			if result != tt.expectedStr {
				t.Errorf("Expected %q, got %q", tt.expectedStr, result)
			}
		})
	}
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func TestFixMissingHeaders_BothMissing(t *testing.T) {
	// Email missing both Date and Message-ID
	email := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"Body content\r\n"

	fixed, added := fixMissingHeaders(email, "mail.example.com")

	// Should report both headers were added
	if len(added) != 2 {
		t.Errorf("Expected 2 headers added, got %d: %v", len(added), added)
	}
	if !contains(added, "Date") {
		t.Error("Expected 'Date' in added headers list")
	}
	if !contains(added, "Message-ID") {
		t.Error("Expected 'Message-ID' in added headers list")
	}

	// Should add Date header
	if !strings.Contains(fixed, "Date:") {
		t.Error("Expected Date header to be added")
	}

	// Should add Message-ID header
	if !strings.Contains(fixed, "Message-ID:") {
		t.Error("Expected Message-ID header to be added")
	}

	// Should contain domain in Message-ID
	if !strings.Contains(fixed, "@mail.example.com>") {
		t.Error("Expected Message-ID to contain domain")
	}

	// Original content should be preserved
	if !strings.Contains(fixed, "Body content") {
		t.Error("Original body content should be preserved")
	}
}

func TestFixMissingHeaders_OnlyDateMissing(t *testing.T) {
	// Email with Message-ID but no Date
	email := "From: sender@example.com\r\n" +
		"Message-ID: <existing123@example.com>\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"Body\r\n"

	fixed, added := fixMissingHeaders(email, "mail.example.com")

	// Should report only Date was added
	if len(added) != 1 || added[0] != "Date" {
		t.Errorf("Expected [Date], got %v", added)
	}

	// Should add Date
	if !strings.Contains(fixed, "Date:") {
		t.Error("Expected Date header to be added")
	}

	// Should NOT add another Message-ID
	messageIDCount := strings.Count(fixed, "Message-ID:")
	if messageIDCount != 1 {
		t.Errorf("Expected exactly 1 Message-ID header, found %d", messageIDCount)
	}

	// Original Message-ID should be preserved
	if !strings.Contains(fixed, "<existing123@example.com>") {
		t.Error("Original Message-ID should be preserved")
	}
}

func TestFixMissingHeaders_OnlyMessageIDMissing(t *testing.T) {
	// Email with Date but no Message-ID
	email := "From: sender@example.com\r\n" +
		"Date: Mon, 02 Jan 2006 15:04:05 -0700\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"Body\r\n"

	fixed, added := fixMissingHeaders(email, "mail.example.com")

	// Should report only Message-ID was added
	if len(added) != 1 || added[0] != "Message-ID" {
		t.Errorf("Expected [Message-ID], got %v", added)
	}

	// Should add Message-ID
	if !strings.Contains(fixed, "Message-ID:") {
		t.Error("Expected Message-ID header to be added")
	}

	// Should NOT add another Date
	dateCount := strings.Count(fixed, "Date:")
	if dateCount != 1 {
		t.Errorf("Expected exactly 1 Date header, found %d", dateCount)
	}

	// Original Date should be preserved
	if !strings.Contains(fixed, "Mon, 02 Jan 2006 15:04:05 -0700") {
		t.Error("Original Date should be preserved")
	}
}

func TestFixMissingHeaders_NothingMissing(t *testing.T) {
	// Email with both Date and Message-ID
	email := "From: sender@example.com\r\n" +
		"Date: Mon, 02 Jan 2006 15:04:05 -0700\r\n" +
		"Message-ID: <abc123@example.com>\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"Body\r\n"

	fixed, added := fixMissingHeaders(email, "mail.example.com")

	// Should report nothing was added
	if len(added) != 0 {
		t.Errorf("Expected no headers added, got %v", added)
	}

	// Should be unchanged
	if fixed != email {
		t.Error("Email with both headers should remain unchanged")
	}
}

func TestFixMissingHeaders_CaseInsensitive(t *testing.T) {
	// Test case-insensitive header detection
	email := "From: sender@example.com\r\n" +
		"date: Mon, 02 Jan 2006 15:04:05 -0700\r\n" +
		"message-id: <abc123@example.com>\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"Body\r\n"

	fixed, added := fixMissingHeaders(email, "mail.example.com")

	// Should detect lowercase headers and not add duplicates
	if len(added) != 0 {
		t.Errorf("Expected no headers added (case-insensitive detection), got %v", added)
	}

	// Should be unchanged (lowercase headers should be detected)
	if fixed != email {
		t.Error("Lowercase header names should be recognized")
	}
}

func TestGenerateMessageID(t *testing.T) {
	domain := "mail.example.com"
	messageID1 := generateMessageID(domain)
	messageID2 := generateMessageID(domain)

	// Should be different (contains random component)
	if messageID1 == messageID2 {
		t.Error("Generated Message-IDs should be unique")
	}

	// Should contain domain
	if !strings.Contains(messageID1, domain) {
		t.Errorf("Message-ID should contain domain: %s", messageID1)
	}

	// Should be in angle brackets
	if !strings.HasPrefix(messageID1, "<") || !strings.HasSuffix(messageID1, ">") {
		t.Errorf("Message-ID should be in angle brackets: %s", messageID1)
	}

	// Should contain @ symbol
	if !strings.Contains(messageID1, "@") {
		t.Errorf("Message-ID should contain @ symbol: %s", messageID1)
	}
}

package smtp

import (
	"strings"
	"testing"

	"migadu/mizu/pkg/config"
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
		config.HeaderToggles{TraceID: true, AuthResults: true, Junk: true},
		false, // keep client identity (relay behavior)
		nil,   // no spam headers
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
		nil,  // no SPF
		nil,  // no DMARC
		nil,  // no ARC
		true, // IS JUNK
		config.HeaderToggles{TraceID: true, AuthResults: true, Junk: true},
		false, // keep client identity
		nil,   // no spam headers
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
		config.HeaderToggles{TraceID: true, AuthResults: true, Junk: true},
		false, // keep client identity
		nil,   // no spam headers
	)

	// Should use ESMTP (not ESMTPS) when no TLS
	if !strings.Contains(modifiedEmail, "with ESMTP id") {
		t.Error("Expected 'with ESMTP' when TLS is not used")
	}
	if strings.Contains(modifiedEmail, "ESMTPS") {
		t.Error("Should not contain ESMTPS when TLS is not used")
	}
}

func TestInjectMizuHeaders_ToggleSuppression(t *testing.T) {
	originalEmail := "From: sender@example.com\r\nSubject: Test\r\n\r\nBody\r\n"

	// Each case disables exactly one header; the other two must survive so a
	// toggle routed to the wrong header block is caught, not just an
	// all-on/all-off regression.
	cases := []struct {
		name    string
		toggles config.HeaderToggles
		absent  string
		present []string
	}{
		{
			name:    "trace ID off",
			toggles: config.HeaderToggles{AuthResults: true, Junk: true},
			absent:  "X-Mizu-Trace-ID:",
			present: []string{"X-Mizu-Authentication-Results:", "X-Mizu-Junk:"},
		},
		{
			name:    "auth results off",
			toggles: config.HeaderToggles{TraceID: true, Junk: true},
			absent:  "X-Mizu-Authentication-Results:",
			present: []string{"X-Mizu-Trace-ID:", "X-Mizu-Junk:"},
		},
		{
			name:    "junk off",
			toggles: config.HeaderToggles{TraceID: true, AuthResults: true},
			absent:  "X-Mizu-Junk:",
			present: []string{"X-Mizu-Trace-ID:", "X-Mizu-Authentication-Results:"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			modifiedEmail := InjectMizuHeaders(
				originalEmail,
				"mail.example.com",
				"1.2.3.4:5678",
				"client.example.com",
				"trace123",
				"TLS 1.3",
				nil, nil, nil,
				false,
				tc.toggles,
				false, // keep client identity
				nil,
			)

			if strings.Contains(modifiedEmail, tc.absent) {
				t.Errorf("Expected %q suppressed, got:\n%s", tc.absent, modifiedEmail)
			}
			for _, want := range tc.present {
				if !strings.Contains(modifiedEmail, want) {
					t.Errorf("Expected %q present, got:\n%s", want, modifiedEmail)
				}
			}
			// The Received header (with the trace ID as its id token) is
			// emitted regardless of the toggles.
			if !strings.Contains(modifiedEmail, "Received: from") || !strings.Contains(modifiedEmail, "id trace123") {
				t.Errorf("Received header must be present regardless of toggles, got:\n%s", modifiedEmail)
			}
		})
	}
}

func TestInjectMizuHeaders_SpamHeaderSanitization(t *testing.T) {
	originalEmail := "From: sender@example.com\r\nSubject: Test\r\n\r\nBody\r\n"

	// Both the header name and value carry CR/LF — a successful injection
	// would either forge an arbitrary header or splice content into the
	// body. Sanitization should strip the control characters and keep the
	// remaining payload on a single header line.
	spamHeaders := map[string][]string{
		"X-Spam\r\nInjected-Name": {"value\r\nInjected-Value: yes"},
	}

	modifiedEmail := InjectMizuHeaders(
		originalEmail,
		"mail.example.com",
		"1.2.3.4:5678",
		"client.example.com",
		"trace789",
		"TLS 1.3",
		nil, nil, nil,
		false,
		config.HeaderToggles{}, // no X-Mizu-* headers — focus the assertion on the spam path
		false,                  // keep client identity
		spamHeaders,
	)

	// "Injected-Name"/"Injected-Value" must only appear as inline fragments
	// of the surviving single header line — never as the start of a line.
	for _, line := range strings.Split(modifiedEmail, "\r\n") {
		if strings.HasPrefix(line, "Injected-Name") {
			t.Errorf("Header name was injected as its own line: %q", line)
		}
		if strings.HasPrefix(line, "Injected-Value") {
			t.Errorf("Header value was injected as its own line: %q", line)
		}
	}
	// sanitizeHeaderValue *strips* control characters rather than replacing
	// them with a separator, so the substrings concatenate directly.
	if !strings.Contains(modifiedEmail, "X-SpamInjected-Name: valueInjected-Value: yes\r\n") {
		t.Errorf("Expected sanitized single-line header, got:\n%s", modifiedEmail)
	}
}

func TestInjectMizuHeaders_FoldedSpamHeaderPreserved(t *testing.T) {
	originalEmail := "From: sender@example.com\r\nSubject: Test\r\n\r\nBody\r\n"

	// rspamd emits long values (e.g. Authentication-Results) pre-folded with
	// CRLF + whitespace. Those folds must survive sanitization so the header
	// stays valid RFC 5322 instead of collapsing onto one long line.
	folded := "mx13.migadu.com;\r\n\tdkim=pass header.d=wise.com;\r\n\tdmarc=pass (policy=reject) header.from=wise.com"
	spamHeaders := map[string][]string{
		"Authentication-Results": {folded},
	}

	modifiedEmail := InjectMizuHeaders(
		originalEmail,
		"mail.example.com",
		"1.2.3.4:5678",
		"client.example.com",
		"trace789",
		"TLS 1.3",
		nil, nil, nil,
		false,
		config.HeaderToggles{}, // no X-Mizu-* headers — focus on the spam path
		false,                  // keep client identity
		spamHeaders,
	)

	// The fold must be preserved verbatim: continuation lines begin with WSP.
	want := "Authentication-Results: mx13.migadu.com;\r\n\tdkim=pass header.d=wise.com;\r\n\tdmarc=pass (policy=reject) header.from=wise.com\r\n"
	if !strings.Contains(modifiedEmail, want) {
		t.Errorf("Folded header was not preserved.\nwant substring:\n%q\ngot:\n%q", want, modifiedEmail)
	}

	// Every continuation line of the header must start with whitespace; none
	// may look like a new header or a blank (body-separator) line.
	lines := strings.Split(modifiedEmail, "\r\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "dkim=pass") || strings.HasPrefix(line, "dmarc=pass") {
			t.Errorf("Continuation line %d lost its folding whitespace: %q", i, line)
		}
	}
}

func TestSanitizeFoldedHeaderValue_InjectionStillBlocked(t *testing.T) {
	// A newline NOT followed by whitespace is an injection attempt and must be
	// stripped, exactly like the strict sanitizer.
	cases := map[string]string{
		"value\r\nInjected-Header: yes": "valueInjected-Header: yes",
		"a\r\n\r\nbody injection":       "abody injection", // blank line collapses
		"keep\r\n\tfold":                "keep\r\n\tfold",  // real fold survives
		"bare\nnewline":                 "barenewline",
		"nul\x00byte":                   "nulbyte",
	}
	for in, want := range cases {
		if got := sanitizeFoldedHeaderValue(in); got != want {
			t.Errorf("sanitizeFoldedHeaderValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildReceivedHeader(t *testing.T) {
	header := buildReceivedHeader(
		"mail.example.com",
		"192.0.2.1:54321",
		"sender.example.org",
		"xyz789",
		"TLS 1.3",
		false, // keep the client trace
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

// With strip_client_identity on — the default for submission servers — the
// submitting user's machine name and network address must not reach recipients, so
// the "from" clause is dropped entirely. Everything else about the hop — server
// domain, protocol, trace ID, timestamp — is preserved.
func TestBuildReceivedHeader_StripsClientIdentity(t *testing.T) {
	header := buildReceivedHeader(
		"smtp.example.com",
		"192.0.2.1:54321",
		"laptop.home.arpa",
		"xyz789",
		"TLS 1.3",
		true, // strip the client identity
	)

	if !strings.HasPrefix(header, "Received: by smtp.example.com with ESMTPS id xyz789;") {
		t.Errorf("Submission Received header should omit the from clause, got:\n%s", header)
	}

	for _, leaked := range []string{"laptop.home.arpa", "192.0.2.1", "from "} {
		if strings.Contains(header, leaked) {
			t.Errorf("Submission Received header must not contain %q, got:\n%s", leaked, header)
		}
	}

	if !strings.HasSuffix(header, "\r\n") {
		t.Error("Received header should end with CRLF")
	}
}

// The point of strip_client_identity is that a server's config decides what reaches
// the recipient, so cover the wiring from ServerConfig.StripsClientIdentity() through
// InjectMizuHeaders to the stamped bytes, not just the flag in isolation.
func TestInjectMizuHeaders_StripsClientIdentity(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }

	tests := []struct {
		name          string
		cfg           config.ServerConfig
		wantClientHop bool
	}{
		{name: "submission strips by default", cfg: config.ServerConfig{Type: "submission"}, wantClientHop: false},
		{name: "relay keeps by default", cfg: config.ServerConfig{Type: "relay"}, wantClientHop: true},
		{
			name:          "submission can opt out",
			cfg:           config.ServerConfig{Type: "submission", StripClientIdentity: boolPtr(false)},
			wantClientHop: true,
		},
		{
			name:          "relay can opt in",
			cfg:           config.ServerConfig{Type: "relay", StripClientIdentity: boolPtr(true)},
			wantClientHop: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			out := InjectMizuHeaders(
				"Subject: Test\r\n\r\nBody\r\n",
				"mail.example.com",
				"1.2.3.4:5678",
				"client.example.com",
				"trace-wiring",
				"TLS 1.3",
				nil, nil, nil,
				false,
				cfg.HeaderToggles(),
				cfg.StripsClientIdentity(),
				nil,
			)

			gotClientHop := strings.Contains(out, "client.example.com") || strings.Contains(out, "1.2.3.4")
			if gotClientHop != tt.wantClientHop {
				t.Errorf("client identity present = %v, want %v; headers:\n%s", gotClientHop, tt.wantClientHop, out)
			}

			// Either way the hop itself is stamped, with its trace ID intact.
			if !strings.Contains(out, "by mail.example.com with ESMTPS id trace-wiring;") {
				t.Errorf("Received hop missing or malformed:\n%s", out)
			}
		})
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

func TestAddEnvelopeToHeader(t *testing.T) {
	originalEmail := "From: sender@example.com\r\nSubject: Test\r\n\r\nBody\r\n"

	modifiedEmail := addEnvelopeToHeader(originalEmail, "recipient@example.com")

	// The header must be prepended as the first line, carry the recipient,
	// and leave the original message intact.
	if !strings.HasPrefix(modifiedEmail, "X-Envelope-To: recipient@example.com\r\n") {
		t.Errorf("Expected X-Envelope-To prepended, got:\n%s", modifiedEmail)
	}
	if !strings.HasSuffix(modifiedEmail, originalEmail) {
		t.Errorf("Original email should remain unchanged after the header, got:\n%s", modifiedEmail)
	}
}

func TestAddEnvelopeToHeader_Sanitization(t *testing.T) {
	originalEmail := "From: sender@example.com\r\nSubject: Test\r\n\r\nBody\r\n"

	// A CR/LF in the recipient must not forge an additional header line.
	modifiedEmail := addEnvelopeToHeader(originalEmail, "recipient@example.com\r\nInjected-Header: yes")

	for _, line := range strings.Split(modifiedEmail, "\r\n") {
		if strings.HasPrefix(line, "Injected-Header") {
			t.Errorf("Recipient injected as its own header line: %q", line)
		}
	}
	if !strings.HasPrefix(modifiedEmail, "X-Envelope-To: recipient@example.comInjected-Header: yes\r\n") {
		t.Errorf("Expected sanitized single-line header, got:\n%s", modifiedEmail)
	}
}

func TestAddEnvelopeToHeader_ReplacesExisting(t *testing.T) {
	// An upstream sender forged an X-Envelope-To; it must be replaced, not
	// duplicated, so the value we emit is authoritative.
	originalEmail := "From: sender@example.com\r\n" +
		"X-Envelope-To: forged@evil.com\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"Body\r\n"

	modifiedEmail := addEnvelopeToHeader(originalEmail, "recipient@example.com")

	if strings.Contains(modifiedEmail, "forged@evil.com") {
		t.Errorf("Existing X-Envelope-To should be removed, got:\n%s", modifiedEmail)
	}
	if n := strings.Count(modifiedEmail, "X-Envelope-To:"); n != 1 {
		t.Errorf("Expected exactly one X-Envelope-To header, got %d:\n%s", n, modifiedEmail)
	}
	if !strings.HasPrefix(modifiedEmail, "X-Envelope-To: recipient@example.com\r\n") {
		t.Errorf("Expected our X-Envelope-To prepended, got:\n%s", modifiedEmail)
	}
}

func TestAddEnvelopeToHeader_ReplacesFoldedExisting(t *testing.T) {
	// A folded (multi-line) X-Envelope-To and its continuation must both be
	// removed, while a header in the body is left untouched.
	originalEmail := "From: sender@example.com\r\n" +
		"x-envelope-to: forged@evil.com,\r\n" +
		"\tsecond@evil.com\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"X-Envelope-To: not-a-header-in-body\r\n"

	modifiedEmail := addEnvelopeToHeader(originalEmail, "recipient@example.com")

	if strings.Contains(modifiedEmail, "evil.com") {
		t.Errorf("Folded X-Envelope-To and continuation should be removed, got:\n%s", modifiedEmail)
	}
	// The body line that happens to look like a header must survive.
	if !strings.Contains(modifiedEmail, "X-Envelope-To: not-a-header-in-body\r\n") {
		t.Errorf("Body content should be untouched, got:\n%s", modifiedEmail)
	}
	if !strings.HasPrefix(modifiedEmail, "X-Envelope-To: recipient@example.com\r\n") {
		t.Errorf("Expected our X-Envelope-To prepended, got:\n%s", modifiedEmail)
	}
}

func TestAddEnvelopeToHeader_EmptyRecipient(t *testing.T) {
	originalEmail := "From: sender@example.com\r\nSubject: Test\r\n\r\nBody\r\n"

	// A recipient that fully sanitizes away would yield a malformed colon-only
	// line, so the email is returned unchanged.
	if got := addEnvelopeToHeader(originalEmail, "\r\n"); got != originalEmail {
		t.Errorf("Expected email unchanged for empty recipient, got:\n%s", got)
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

// === rewriteFromHeader (master/token login senders) ===

func TestRewriteFromHeader(t *testing.T) {
	const login = "user@example.com@MASTER"
	const identity = "user@example.com"

	tests := []struct {
		name     string
		raw      string
		wantFrom string // expected From line, "" when no rewrite is expected
		wantOK   bool
	}{
		{
			name:     "bare address rewritten",
			raw:      "From: <" + login + ">\r\nTo: x@y.com\r\n\r\nbody\r\n",
			wantFrom: "From: <" + identity + ">",
			wantOK:   true,
		},
		{
			name:     "address without angle brackets",
			raw:      "From: " + login + "\r\nTo: x@y.com\r\n\r\nbody\r\n",
			wantFrom: "From: <" + identity + ">",
			wantOK:   true,
		},
		{
			name:     "display name preserved",
			raw:      "From: Support Team <" + login + ">\r\nTo: x@y.com\r\n\r\nbody\r\n",
			wantFrom: "From: Support Team <" + identity + ">",
			wantOK:   true,
		},
		{
			name:     "case-insensitive header name and address",
			raw:      "FROM: <User@Example.COM@MASTER>\r\nTo: x@y.com\r\n\r\nbody\r\n",
			wantFrom: "From: <" + identity + ">",
			wantOK:   true,
		},
		{
			name:     "folded value collapsed to one line",
			raw:      "From: Support\r\n <" + login + ">\r\nTo: x@y.com\r\n\r\nbody\r\n",
			wantFrom: "From: Support <" + identity + ">",
			wantOK:   true,
		},
		{
			// The whole point of matching exactly: a From that is not this
			// session's login is somebody else's and must not be touched.
			name:   "different address untouched",
			raw:    "From: <someone@example.com>\r\nTo: x@y.com\r\n\r\nbody\r\n",
			wantOK: false,
		},
		{
			name:   "no From header",
			raw:    "To: x@y.com\r\nSubject: hi\r\n\r\nbody\r\n",
			wantOK: false,
		},
		{
			// A From-looking line in the body is not a header.
			name:   "From in body ignored",
			raw:    "To: x@y.com\r\n\r\nFrom: <" + login + ">\r\n",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := rewriteFromHeader(tt.raw, login, identity)
			if ok != tt.wantOK {
				t.Fatalf("rewriteFromHeader ok = %v, want %v (got %q)", ok, tt.wantOK, got)
			}
			if !tt.wantOK {
				if got != tt.raw {
					t.Errorf("message must be unchanged when no rewrite happens:\n got %q\nwant %q", got, tt.raw)
				}
				return
			}
			if !strings.Contains(got, tt.wantFrom+"\r\n") {
				t.Errorf("expected From line %q in:\n%q", tt.wantFrom, got)
			}
			if strings.Contains(got, "MASTER") {
				t.Errorf("master suffix survived the rewrite:\n%q", got)
			}
			// Everything after the headers must be untouched.
			if !strings.HasSuffix(got, "\r\n\r\nbody\r\n") {
				t.Errorf("body or CRLF framing damaged:\n%q", got)
			}
		})
	}
}

// An empty old or new address is a no-op rather than a way to blank the header.
func TestRewriteFromHeader_EmptyArgs(t *testing.T) {
	raw := "From: <user@example.com>\r\n\r\nbody\r\n"
	if got, ok := rewriteFromHeader(raw, "", "new@example.com"); ok || got != raw {
		t.Error("empty old address must be a no-op")
	}
	if got, ok := rewriteFromHeader(raw, "user@example.com", ""); ok || got != raw {
		t.Error("empty new address must be a no-op")
	}
}

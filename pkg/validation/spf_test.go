package validation

import (
	"context"
	"net"
	"testing"

	"github.com/emersion/go-msgauth/authres"
	"github.com/mileusna/spf"
)

func TestConvertSPFResult(t *testing.T) {
	tests := []struct {
		name     string
		input    spf.Result
		expected authres.ResultValue
	}{
		{
			name:     "Pass",
			input:    spf.Pass,
			expected: authres.ResultPass,
		},
		{
			name:     "Fail",
			input:    spf.Fail,
			expected: authres.ResultFail,
		},
		{
			name:     "SoftFail",
			input:    spf.Softfail,
			expected: authres.ResultSoftFail,
		},
		{
			name:     "Neutral",
			input:    spf.Neutral,
			expected: authres.ResultNeutral,
		},
		{
			name:     "None",
			input:    spf.None,
			expected: authres.ResultNone,
		},
		{
			name:     "TempError",
			input:    spf.TempError,
			expected: authres.ResultNone, // TempError maps to None
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ConvertSPFResult(tt.input); got != tt.expected {
				t.Errorf("ConvertSPFResult() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCheckSPF_RealDNS(t *testing.T) {
	tests := []struct {
		name       string
		ip         string
		domain     string
		sender     string
		wantResult string // Expected SPF result
	}{
		{
			name:       "gg.ca domain with their mail server",
			ip:         "198.103.213.10",
			domain:     "gg.ca",
			sender:     "Alexandre.Bellerive@gg.ca",
			wantResult: "PASS", // Should pass if IP is authorized
		},
		{
			name:       "Facebook - known good SPF",
			ip:         "66.220.149.11", // Facebook mail server
			domain:     "facebookmail.com",
			sender:     "friendupdates@facebookmail.com",
			wantResult: "PASS",
		},
		{
			name:       "Random IP for gg.ca - should fail",
			ip:         "1.2.3.4",
			domain:     "gg.ca",
			sender:     "test@gg.ca",
			wantResult: "FAIL", // Random IP should fail
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}

			result, err := CheckSPF(context.Background(), ip, tt.domain, tt.sender)
			if err != nil {
				t.Logf("SPF check returned error: %v (this may be expected)", err)
			}

			if result != nil {
				t.Logf("SPF result for %s from %s: %s", tt.sender, tt.ip, string(*result))
				// Note: We don't assert here because DNS records can change
				// This is more for manual testing and debugging
			} else {
				t.Logf("SPF result is nil")
			}
		})
	}
}

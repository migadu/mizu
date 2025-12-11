package validation

import (
	"context"
	"testing"
)

func TestCheckMXRecord(t *testing.T) {
	tests := []struct {
		name          string
		domain        string
		expectValid   bool
		expectError   bool
		errorContains string
	}{
		{
			name:        "Valid domain with MX - gmail.com",
			domain:      "gmail.com",
			expectValid: true,
			expectError: false,
		},
		{
			name:        "Valid domain with MX - google.com",
			domain:      "google.com",
			expectValid: true,
			expectError: false,
		},
		{
			name:          "Empty domain",
			domain:        "",
			expectValid:   false,
			expectError:   true,
			errorContains: "empty domain",
		},
		{
			name:        "Domain with angle brackets",
			domain:      "<gmail.com>",
			expectValid: true, // Should strip brackets and check
			expectError: false,
		},
		{
			name:        "Domain with whitespace",
			domain:      "  gmail.com  ",
			expectValid: true,
			expectError: false,
		},
		{
			name:        "Non-existent domain",
			domain:      "this-domain-definitely-does-not-exist-12345.com",
			expectValid: false,
			expectError: false, // Not an error, just no MX records
		},
		{
			name:        "Invalid TLD",
			domain:      "example.invalid",
			expectValid: false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			valid, err := CheckMXRecord(ctx, tt.domain, nil, 0) // nil resolver = use default, 0 timeout = use default

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for domain '%s', but got nil", tt.domain)
					return
				}
				if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', but got: %v", tt.errorContains, err)
				}
				return
			}

			if err != nil {
				// For real DNS lookups, we might get temporary errors
				// Log but don't fail the test
				t.Logf("Got error for domain '%s': %v (this might be expected for some domains)", tt.domain, err)
				return
			}

			if valid != tt.expectValid {
				t.Errorf("For domain '%s': expected valid=%v, got valid=%v", tt.domain, tt.expectValid, valid)
			}

			if valid {
				t.Logf("✓ Domain '%s' has valid MX records", tt.domain)
			} else {
				t.Logf("✗ Domain '%s' has no MX records", tt.domain)
			}
		})
	}
}

func TestCheckMXRecord_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := CheckMXRecord(ctx, "gmail.com", nil, 0)
	if err == nil {
		t.Error("Expected error when context is cancelled, but got nil")
	}
	t.Logf("✓ Properly handles cancelled context: %v", err)
}

func TestCheckMXRecord_RealWorldDomains(t *testing.T) {
	// Test some well-known domains that should have MX records
	domains := []string{
		"gmail.com",
		"yahoo.com",
		"outlook.com",
		"protonmail.com",
	}

	ctx := context.Background()
	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			valid, err := CheckMXRecord(ctx, domain, nil, 0)
			if err != nil {
				t.Logf("Warning: Got error for %s: %v (might be temporary DNS issue)", domain, err)
				return
			}

			if !valid {
				t.Errorf("Expected %s to have MX records, but got valid=false", domain)
			} else {
				t.Logf("✓ %s has valid MX records", domain)
			}
		})
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

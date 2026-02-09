package smtp

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestHTTPAuthenticator_Authenticate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Generate bcrypt hash for "testpass"
	bcryptHash, _ := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.DefaultCost)

	// Test successful authentication
	t.Run("successful authentication", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request
			if r.Method != "GET" {
				t.Errorf("expected GET, got %s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer test-auth-token" {
				t.Errorf("expected Bearer token, got %s", r.Header.Get("Authorization"))
			}

			// Return password hashes (can support multiple passwords)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(AuthResponse{
				PasswordHashes: []string{string(bcryptHash)},
				AllowedFrom:    []string{"testuser@example.com", "alias@example.com"},
			})
		}))
		defer server.Close()

		auth := NewHTTPAuthenticator(server.URL+"?email=$email&ip=$ip", "test-auth-token", logger, nil)

		// Test authentication with correct password
		authenticated, err := auth.Authenticate("testuser@example.com", "testpass")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !authenticated {
			t.Error("expected authentication to succeed")
		}

		// Test CanSendAs
		if !auth.CanSendAs("testuser@example.com", "testuser@example.com") {
			t.Error("expected user to be able to send from testuser@example.com")
		}
		if !auth.CanSendAs("testuser@example.com", "alias@example.com") {
			t.Error("expected user to be able to send from alias@example.com")
		}
		if auth.CanSendAs("testuser@example.com", "other@example.com") {
			t.Error("expected user NOT to be able to send from other@example.com")
		}
	})

	// Test failed authentication (wrong password)
	t.Run("failed authentication", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(AuthResponse{
				PasswordHashes: []string{string(bcryptHash)},
				AllowedFrom:    []string{"testuser@example.com"},
			})
		}))
		defer server.Close()

		auth := NewHTTPAuthenticator(server.URL, "test-auth-token", logger, nil)

		authenticated, err := auth.Authenticate("testuser@example.com", "wrongpass")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if authenticated {
			t.Error("expected authentication to fail")
		}
	})

	// Test user not found (404)
	t.Run("user not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		auth := NewHTTPAuthenticator(server.URL, "test-auth-token", logger, nil)

		authenticated, err := auth.Authenticate("nonexistent@example.com", "testpass")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if authenticated {
			t.Error("expected authentication to fail for non-existent user")
		}
	})

	// Test authentication service error
	t.Run("service error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		auth := NewHTTPAuthenticator(server.URL, "test-auth-token", logger, nil)

		authenticated, err := auth.Authenticate("testuser@example.com", "testpass")
		if err == nil {
			t.Error("expected error on service failure")
		}
		if authenticated {
			t.Error("expected authentication to fail on service error")
		}
	})

	// Test caching
	t.Run("authentication caching", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(AuthResponse{
				PasswordHashes: []string{string(bcryptHash)},
				AllowedFrom:    []string{"testuser@example.com"},
			})
		}))
		defer server.Close()

		auth := NewHTTPAuthenticator(server.URL, "test-auth-token", logger, nil)
		auth.credCacheTTL = 1 * time.Second

		// First authentication should hit the server
		auth.Authenticate("testuser@example.com", "testpass")
		if callCount != 1 {
			t.Errorf("expected 1 call, got %d", callCount)
		}

		// Second authentication should use cache (credentials cached)
		auth.Authenticate("testuser@example.com", "testpass")
		if callCount != 1 {
			t.Errorf("expected 1 call (cached), got %d", callCount)
		}

		// Wait for credentials cache to expire
		time.Sleep(1100 * time.Millisecond)

		// Third authentication should hit the server again (credentials expired)
		auth.Authenticate("testuser@example.com", "testpass")
		if callCount != 2 {
			t.Errorf("expected 2 calls (credentials cache expired), got %d", callCount)
		}
	})

	// Test URL interpolation
	t.Run("URL interpolation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify URL contains interpolated values
			if !strings.Contains(r.URL.String(), "testuser%40example.com") {
				t.Errorf("expected URL to contain encoded email, got %s", r.URL.String())
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(AuthResponse{
				PasswordHashes: []string{string(bcryptHash)},
				AllowedFrom:    []string{"testuser@example.com"},
			})
		}))
		defer server.Close()

		auth := NewHTTPAuthenticator(server.URL+"?email=$email", "test-auth-token", logger, nil)
		auth.Authenticate("testuser@example.com", "testpass")
	})

	// Test multiple password hashes
	t.Run("multiple password hashes", func(t *testing.T) {
		// Generate multiple password hashes
		hash1, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.DefaultCost)
		hash2, _ := bcrypt.GenerateFromPassword([]byte("password2"), bcrypt.DefaultCost)
		hash3, _ := bcrypt.GenerateFromPassword([]byte("password3"), bcrypt.DefaultCost)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(AuthResponse{
				PasswordHashes: []string{string(hash1), string(hash2), string(hash3)},
				AllowedFrom:    []string{"testuser@example.com"},
			})
		}))
		defer server.Close()

		auth := NewHTTPAuthenticator(server.URL, "test-auth-token", logger, nil)

		// All three passwords should work
		authenticated, err := auth.Authenticate("testuser@example.com", "password1")
		if err != nil || !authenticated {
			t.Error("expected password1 to authenticate")
		}

		// Clear cache to test fresh fetch
		auth.clearCredCacheEntry("testuser@example.com")

		authenticated, err = auth.Authenticate("testuser@example.com", "password2")
		if err != nil || !authenticated {
			t.Error("expected password2 to authenticate")
		}

		auth.clearCredCacheEntry("testuser@example.com")

		authenticated, err = auth.Authenticate("testuser@example.com", "password3")
		if err != nil || !authenticated {
			t.Error("expected password3 to authenticate")
		}

		// Wrong password should fail
		auth.clearCredCacheEntry("testuser@example.com")
		authenticated, err = auth.Authenticate("testuser@example.com", "wrongpassword")
		if err != nil || authenticated {
			t.Error("expected wrong password to fail")
		}
	})
}

func TestExtractEmail(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"user@example.com", "user@example.com"},
		{"User Name <user@example.com>", "user@example.com"},
		{"  user@example.com  ", "user@example.com"},
		{"<user@example.com>", "user@example.com"},
		{"User@Example.COM", "user@example.com"},
		{"User Name <User@Example.COM>", "user@example.com"},
	}

	for _, tt := range tests {
		result := extractEmail(tt.input)
		if result != tt.expected {
			t.Errorf("extractEmail(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestMatchEmailPattern(t *testing.T) {
	tests := []struct {
		pattern  string
		email    string
		expected bool
		desc     string
	}{
		// Exact matches
		{"user@example.com", "user@example.com", true, "exact match"},
		{"user@example.com", "User@Example.COM", true, "case insensitive exact match"},
		{"user@example.com", "other@example.com", false, "different user"},
		{"user@example.com", "user@other.com", false, "different domain"},

		// Wildcard matches - domain level
		{"*@example.com", "user@example.com", true, "wildcard matches user"},
		{"*@example.com", "anyone@example.com", true, "wildcard matches any user"},
		{"*@example.com", "User@Example.COM", true, "wildcard case insensitive"},
		{"*@example.com", "user@other.com", false, "wildcard different domain"},
		{"*@example.com", "user@sub.example.com", false, "wildcard does not match subdomain"},

		// Subdomain wildcards
		{"*@sub.example.com", "user@sub.example.com", true, "wildcard matches subdomain"},
		{"*@sub.example.com", "user@example.com", false, "wildcard subdomain not parent domain"},
		{"*@humans.gomailify.com", "h@humans.gomailify.com", true, "wildcard matches subdomain user"},
		{"*@h.gomailify.com", "anything@h.gomailify.com", true, "wildcard matches subdomain user"},

		// Edge cases
		{"  *@example.com  ", "  user@example.com  ", true, "whitespace handling"},
		{"*@", "user@example.com", false, "invalid pattern - no domain"},
		{"@example.com", "user@example.com", false, "invalid pattern - no local part"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			result := matchEmailPattern(tt.pattern, tt.email)
			if result != tt.expected {
				t.Errorf("matchEmailPattern(%q, %q) = %v, want %v",
					tt.pattern, tt.email, result, tt.expected)
			}
		})
	}
}

func TestCanSendAs_Wildcards(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	bcryptHash, _ := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.DefaultCost)

	tests := []struct {
		name        string
		allowedFrom []string
		testAddress string
		shouldAllow bool
	}{
		{
			name:        "exact match",
			allowedFrom: []string{"humans@gomailify.com"},
			testAddress: "humans@gomailify.com",
			shouldAllow: true,
		},
		{
			name:        "wildcard subdomain match",
			allowedFrom: []string{"*@humans.gomailify.com"},
			testAddress: "anything@humans.gomailify.com",
			shouldAllow: true,
		},
		{
			name:        "wildcard subdomain no match parent",
			allowedFrom: []string{"*@humans.gomailify.com"},
			testAddress: "user@gomailify.com",
			shouldAllow: false,
		},
		{
			name:        "multiple patterns with wildcard",
			allowedFrom: []string{"humans@gomailify.com", "*@humans.gomailify.com", "h@gomailify.com", "*@h.gomailify.com"},
			testAddress: "test@humans.gomailify.com",
			shouldAllow: true,
		},
		{
			name:        "multiple patterns exact match",
			allowedFrom: []string{"humans@gomailify.com", "*@humans.gomailify.com", "h@gomailify.com", "*@h.gomailify.com"},
			testAddress: "h@gomailify.com",
			shouldAllow: true,
		},
		{
			name:        "multiple patterns wildcard second domain",
			allowedFrom: []string{"humans@gomailify.com", "*@humans.gomailify.com", "h@gomailify.com", "*@h.gomailify.com"},
			testAddress: "anyone@h.gomailify.com",
			shouldAllow: true,
		},
		{
			name:        "multiple patterns no match",
			allowedFrom: []string{"humans@gomailify.com", "*@humans.gomailify.com", "h@gomailify.com", "*@h.gomailify.com"},
			testAddress: "other@example.com",
			shouldAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(AuthResponse{
					PasswordHashes: []string{string(bcryptHash)},
					AllowedFrom:    tt.allowedFrom,
				})
			}))
			defer server.Close()

			auth := NewHTTPAuthenticator(server.URL, "test-auth-token", logger, nil)

			// Authenticate first to populate cache
			authenticated, err := auth.Authenticate("testuser@example.com", "testpass")
			if err != nil || !authenticated {
				t.Fatalf("authentication failed: %v", err)
			}

			// Test CanSendAs
			result := auth.CanSendAs("testuser@example.com", tt.testAddress)
			if result != tt.shouldAllow {
				t.Errorf("CanSendAs(%q) = %v, want %v", tt.testAddress, result, tt.shouldAllow)
			}
		})
	}
}

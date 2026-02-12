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

func TestHTTPAuthenticator_BackendErrorReturnsTemporaryFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Server returns 500 error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	auth := NewHTTPAuthenticator(server.URL, "test-auth-token", logger, nil)

	// Authentication should return error (not false)
	authenticated, err := auth.Authenticate("testuser@example.com", "testpass")
	if err == nil {
		t.Error("expected error when backend returns 500")
	}
	if authenticated {
		t.Error("should not authenticate when backend errors")
	}

	// The error should be returned (not just false), allowing the SMTP layer
	// to convert it to a 454 temporary failure instead of 535 permanent failure
	if err == nil {
		t.Fatal("backend error should return err, not just false")
	}
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

func TestHTTPAuthenticator_PasswordChange(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Initial password
	oldPasswordHash, _ := bcrypt.GenerateFromPassword([]byte("oldpass"), bcrypt.DefaultCost)
	// New password after change
	newPasswordHash, _ := bcrypt.GenerateFromPassword([]byte("newpass"), bcrypt.DefaultCost)

	passwordChanged := false
	callCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)

		var hash []byte
		if passwordChanged {
			hash = newPasswordHash
		} else {
			hash = oldPasswordHash
		}

		json.NewEncoder(w).Encode(AuthResponse{
			PasswordHashes: []string{string(hash)},
			AllowedFrom:    []string{"testuser@example.com"},
		})
	}))
	defer server.Close()

	auth := NewHTTPAuthenticator(server.URL, "test-auth-token", logger, nil)
	auth.credCacheTTL = 5 * time.Second

	// First authentication with old password - should succeed and cache
	authenticated, err := auth.Authenticate("testuser@example.com", "oldpass")
	if err != nil || !authenticated {
		t.Fatal("first authentication with old password should succeed")
	}
	if callCount != 1 {
		t.Errorf("expected 1 backend call, got %d", callCount)
	}

	// Second authentication with old password - should use cache (no backend call)
	authenticated, err = auth.Authenticate("testuser@example.com", "oldpass")
	if err != nil || !authenticated {
		t.Fatal("second authentication with old password should succeed from cache")
	}
	if callCount != 1 {
		t.Errorf("expected still 1 backend call (cached), got %d", callCount)
	}

	// Simulate password change on backend
	passwordChanged = true

	// Try new password - should fail on cache (has old password cached),
	// trigger refetch, verify against new password, succeed
	authenticated, err = auth.Authenticate("testuser@example.com", "newpass")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !authenticated {
		t.Error("new password should succeed after refetch")
	}
	if callCount != 2 {
		t.Errorf("expected 2 backend calls (cache miss triggered refetch), got %d", callCount)
	}

	// Try old password - should refetch (credentials mismatch), fail
	authenticated, err = auth.Authenticate("testuser@example.com", "oldpass")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if authenticated {
		t.Error("old password should fail")
	}
	if callCount != 3 {
		t.Errorf("expected 3 backend calls (refetch to verify old password is wrong), got %d", callCount)
	}

	// Try old password again - without auth cache, will refetch again (no brute force protection)
	authenticated, err = auth.Authenticate("testuser@example.com", "oldpass")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if authenticated {
		t.Error("old password should still fail")
	}
	if callCount != 4 {
		t.Errorf("expected 4 backend calls (no negative caching without auth cache), got %d", callCount)
	}

	// Try new password again - should use cached credentials (no backend call)
	authenticated, err = auth.Authenticate("testuser@example.com", "newpass")
	if err != nil || !authenticated {
		t.Error("new password should succeed from cache")
	}
	if callCount != 4 {
		t.Errorf("expected still 4 backend calls (using cached creds), got %d", callCount)
	}
}

func TestCanSendAs_AllowedFromChanges(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	bcryptHash, _ := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.DefaultCost)

	// Track allowed addresses - will change during test
	allowedAddresses := []string{"user@example.com", "alias@example.com"}
	callCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AuthResponse{
			PasswordHashes: []string{string(bcryptHash)},
			AllowedFrom:    allowedAddresses,
		})
	}))
	defer server.Close()

	auth := NewHTTPAuthenticator(server.URL, "test-auth-token", logger, nil)

	// Authenticate user
	authenticated, err := auth.Authenticate("user@example.com", "testpass")
	if err != nil || !authenticated {
		t.Fatalf("authentication failed: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 backend call, got %d", callCount)
	}

	// User should be able to send from both addresses
	if !auth.CanSendAs("user@example.com", "user@example.com") {
		t.Error("user should be able to send from user@example.com")
	}
	if callCount != 1 {
		t.Errorf("expected still 1 backend call (cached), got %d", callCount)
	}

	if !auth.CanSendAs("user@example.com", "alias@example.com") {
		t.Error("user should be able to send from alias@example.com")
	}
	if callCount != 1 {
		t.Errorf("expected still 1 backend call (cached), got %d", callCount)
	}

	// Admin removes alias from allowed_from on backend
	allowedAddresses = []string{"user@example.com"}

	// User tries to send from alias - STILL ALLOWED because cached allowed_from has it
	// This is expected behavior: cache is valid for up to 5 minutes (credCacheTTL)
	// To detect removal immediately, user needs to re-authenticate or cache needs to expire
	if !auth.CanSendAs("user@example.com", "alias@example.com") {
		t.Error("alias should still be in cache (not yet expired)")
	}
	if callCount != 1 {
		t.Errorf("expected still 1 backend call (using cached allowed_from), got %d", callCount)
	}

	// User tries an address not in cache - triggers refetch, gets fresh allowed_from
	if auth.CanSendAs("user@example.com", "notincache@example.com") {
		t.Error("address not in list should be denied")
	}
	if callCount != 2 {
		t.Errorf("expected 2 backend calls (refetch on unknown address), got %d", callCount)
	}

	// Now cache has fresh data (without alias) - verify alias is denied
	if auth.CanSendAs("user@example.com", "alias@example.com") {
		t.Error("alias should now be denied (fresh cache without it)")
	}
	if callCount != 3 {
		t.Errorf("expected 3 backend calls (refetch again since alias not in fresh cache), got %d", callCount)
	}

	// User can still send from primary address
	if !auth.CanSendAs("user@example.com", "user@example.com") {
		t.Error("user should still be able to send from user@example.com")
	}
	if callCount != 3 {
		t.Errorf("expected still 3 backend calls (cached), got %d", callCount)
	}

	// Admin adds new alias
	allowedAddresses = []string{"user@example.com", "newalias@example.com"}

	// User tries new alias - should be denied from cache, then refetch and allow
	if !auth.CanSendAs("user@example.com", "newalias@example.com") {
		t.Error("user should be able to send from newalias@example.com after it was added")
	}
	if callCount != 4 {
		t.Errorf("expected 4 backend calls (refetch on CanSendAs failure), got %d", callCount)
	}

	// Verify new alias works from cache now
	if !auth.CanSendAs("user@example.com", "newalias@example.com") {
		t.Error("new alias should work from cache")
	}
	if callCount != 4 {
		t.Errorf("expected still 4 backend calls (cached), got %d", callCount)
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

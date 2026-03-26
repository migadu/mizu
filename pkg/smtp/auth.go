package smtp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"migadu/mizu/pkg/concurrency"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// HTTPAuthenticator authenticates users via HTTPS GET API with local password verification
type HTTPAuthenticator struct {
	urlTemplate string // URL template with $email and $ip placeholders
	apiKey      string
	httpClient  *http.Client
	logger      *slog.Logger

	// Auth result cache (password-aware, separate positive/negative TTL)
	// When enabled, handles both positive and negative caching
	// When disabled (nil), credentials cache is used without brute force protection
	authCache *AuthCache

	// Credentials cache (stores password hashes and allowed_from for successful auth)
	credCache      map[string]*credCacheEntry
	credCacheMu    sync.RWMutex
	credCacheTTL   time.Duration
	credCacheClean time.Duration
}

type credCacheEntry struct {
	passwordHashes       []string // Password hashes from backend
	allowedFromAddresses []string // Email addresses user can send as
	expiresAt            time.Time
}

// NewHTTPAuthenticator creates a new HTTPS-based authenticator with GET requests
func NewHTTPAuthenticator(urlTemplate, apiKey string, logger *slog.Logger, authCache *AuthCache) *HTTPAuthenticator {
	auth := &HTTPAuthenticator{
		urlTemplate: urlTemplate,
		apiKey:      apiKey,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		logger:         logger,
		authCache:      authCache,
		credCache:      make(map[string]*credCacheEntry),
		credCacheTTL:   5 * time.Minute,  // Cache credentials for 5 minutes
		credCacheClean: 10 * time.Minute, // Cleanup every 10 minutes
	}

	// Start credentials cache cleanup goroutine
	concurrency.SafeGo(logger, "auth-credentials-cache-cleanup", auth.cleanupCredCache)

	return auth
}

// AuthResponse represents the authentication response from the backend
type AuthResponse struct {
	PasswordHashes []string `json:"password_hashes"` // List of hashed passwords (bcrypt, SSHA512, etc.)
	AllowedFrom    []string `json:"allowed_from"`    // Email addresses user can send as
}

// Authenticate verifies username and password by fetching hash from backend and verifying locally
// The remoteIP parameter is used for URL interpolation ($ip placeholder)
func (a *HTTPAuthenticator) Authenticate(username, password string) (bool, error) {
	return a.AuthenticateWithIP(username, password, "")
}

// AuthenticateWithIP verifies username and password with client IP for URL interpolation
func (a *HTTPAuthenticator) AuthenticateWithIP(username, password, remoteIP string) (bool, error) {
	// Check auth cache first (if enabled)
	if a.authCache != nil {
		isAuthenticated, found, err := a.authCache.CheckAuth(username, password)
		if err != nil {
			// Cached failure - don't check backend
			return false, nil
		}
		if found && isAuthenticated {
			// Cache hit - authentication successful
			// Still need to check credentials cache for CanSendAs
			if entry := a.getCredCached(username); entry == nil {
				// Creds not in cache - fetch them for CanSendAs later
				creds, fetchErr := a.fetchCredentials(username, remoteIP)
				if fetchErr == nil && len(creds.PasswordHashes) > 0 {
					a.cacheCredentials(username, creds.PasswordHashes, creds.AllowedFrom)
				}
			}
			return true, nil
		}
		// Cache miss or needs revalidation - continue to backend check
	} else {
		// Auth cache disabled - only use credentials cache (no brute force protection)
		// Check credentials cache
		if entry := a.getCredCached(username); entry != nil {
			a.logger.Debug("credentials cache hit", "username", username)
			// Verify password against cached hashes (try all until one matches)
			if a.verifyAgainstHashes(entry.passwordHashes, password) {
				return true, nil
			}

			// Password doesn't match cached hash - might be password change
			// Refetch from backend to verify
			a.logger.Debug("cached password verification failed, refetching credentials", "username", username)
			a.clearCredCacheEntry(username)

			// Fetch fresh credentials from backend
			creds, err := a.fetchCredentials(username, remoteIP)
			if err != nil {
				// Backend error - return error without caching
				return false, err
			}

			// No password hashes means user not found
			if len(creds.PasswordHashes) == 0 {
				return false, fmt.Errorf("no such user")
			}

			// Verify password against fresh credentials
			if a.verifyAgainstHashes(creds.PasswordHashes, password) {
				// Success with fresh credentials (password was changed)
				a.cacheCredentials(username, creds.PasswordHashes, creds.AllowedFrom)
				a.logger.Info("authentication successful with fresh credentials", "username", username)
				return true, nil
			}

			// Password still doesn't match - cache fresh credentials
			a.cacheCredentials(username, creds.PasswordHashes, creds.AllowedFrom)
			return false, fmt.Errorf("password verification failed")
		}
	}

	// Fetch credentials from backend (cache miss)
	creds, err := a.fetchCredentials(username, remoteIP)
	if err != nil {
		// Cache negative result if auth cache enabled
		if a.authCache != nil {
			a.authCache.SetFailure(username, password, AuthFailed)
		}
		return false, err
	}

	// No password hashes means user not found
	if len(creds.PasswordHashes) == 0 {
		if a.authCache != nil {
			a.authCache.SetFailure(username, password, AuthUserNotFound)
		}
		return false, fmt.Errorf("no such user")
	}

	// Verify password against fetched hashes (try all until one matches)
	if !a.verifyAgainstHashes(creds.PasswordHashes, password) {
		if a.authCache != nil {
			a.authCache.SetFailure(username, password, AuthInvalidPassword)
		}
		// Cache credentials anyway so future attempts can use them
		a.cacheCredentials(username, creds.PasswordHashes, creds.AllowedFrom)
		return false, fmt.Errorf("password verification failed")
	}

	// Cache successful authentication
	a.cacheCredentials(username, creds.PasswordHashes, creds.AllowedFrom)
	if a.authCache != nil {
		a.authCache.SetSuccess(username, password)
	}
	a.logger.Info("Authentication successful", "username", username)
	return true, nil
}

// verifyAgainstHashes tries to verify the password against a list of hashes
// Returns true if any hash matches
func (a *HTTPAuthenticator) verifyAgainstHashes(hashes []string, password string) bool {
	for _, hash := range hashes {
		if err := VerifyPassword(hash, password); err == nil {
			return true
		}
	}
	return false
}

// fetchCredentials fetches user credentials from the backend via GET request
func (a *HTTPAuthenticator) fetchCredentials(username, remoteIP string) (*AuthResponse, error) {
	// Build URL with interpolation
	requestURL := a.buildURL(username, remoteIP)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
	if err != nil {
		a.logger.Error("failed to create auth request", "error", err)
		return nil, fmt.Errorf("internal error")
	}

	// Add API key if configured
	if a.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.apiKey)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.logger.Error("auth request failed", "url", requestURL, "error", err)
		return nil, fmt.Errorf("authentication service unavailable")
	}
	defer resp.Body.Close()

	// 404 means user not found - this is not an error, just auth failure
	if resp.StatusCode == http.StatusNotFound {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			a.logger.Warn("failed to read auth 404 response body", "username", username, "error", err)
		}
		a.logger.Debug("auth request: user not found",
			"username", username,
			"url", requestURL,
			"status", resp.StatusCode,
			"response", string(body))
		return &AuthResponse{}, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			a.logger.Warn("failed to read auth error response body", "username", username, "error", err)
		}
		a.logger.Warn("auth request failed",
			"username", username,
			"url", requestURL,
			"status", resp.StatusCode,
			"response", string(body))
		return nil, fmt.Errorf("authentication service error: %d", resp.StatusCode)
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		a.logger.Error("failed to parse auth response", "error", err)
		return nil, fmt.Errorf("internal error")
	}

	return &authResp, nil
}

// buildURL builds the request URL by interpolating $email and $ip placeholders
func (a *HTTPAuthenticator) buildURL(email, ip string) string {
	result := a.urlTemplate

	// URL-encode the values
	result = strings.ReplaceAll(result, "$email", url.QueryEscape(email))
	result = strings.ReplaceAll(result, "$ip", url.QueryEscape(ip))

	return result
}

// CanSendAs checks if authenticated user can send as a specific FROM address
// Supports wildcards in allowed_from patterns (e.g., "*@example.com")
// If the FROM address is not in the cached allowed list, refetches from backend to detect changes
func (a *HTTPAuthenticator) CanSendAs(authenticatedUser, fromAddress string) bool {
	// Get cached credentials entry to check allowed FROM addresses
	entry := a.getCredCached(authenticatedUser)
	if entry == nil {
		// Not in cache - shouldn't happen if Authenticate was called first
		a.logger.Warn("CanSendAs called but user credentials not in cache", "user", authenticatedUser)
		return false
	}

	// Normalize addresses for comparison
	authUser := strings.ToLower(strings.TrimSpace(authenticatedUser))
	fromAddr := extractEmail(fromAddress)

	// Check against cached allowed_from list
	if a.checkAllowedFrom(entry.allowedFromAddresses, authUser, fromAddr) {
		return true
	}

	// FROM address not in cached list - refetch credentials to check for updates
	// (admin might have added/removed aliases)
	a.logger.Debug("FROM address not in cached allowed_from, refetching credentials",
		"user", authenticatedUser,
		"from", fromAddr,
		"cached_allowed", entry.allowedFromAddresses)

	a.clearCredCacheEntry(authenticatedUser)
	creds, err := a.fetchCredentials(authenticatedUser, "")
	if err != nil {
		a.logger.Error("failed to refetch credentials for CanSendAs check", "user", authenticatedUser, "error", err)
		return false
	}

	if len(creds.PasswordHashes) == 0 {
		a.logger.Warn("user not found during CanSendAs refetch", "user", authenticatedUser)
		return false
	}

	// Cache fresh credentials
	a.cacheCredentials(authenticatedUser, creds.PasswordHashes, creds.AllowedFrom)

	// Check again with fresh allowed_from list
	if a.checkAllowedFrom(creds.AllowedFrom, authUser, fromAddr) {
		a.logger.Info("FROM address allowed after refetch (allowed_from was updated)",
			"user", authenticatedUser,
			"from", fromAddr)
		return true
	}

	a.logger.Warn("FROM address not in allowed list (verified with fresh data)",
		"authenticated", authUser,
		"from", fromAddr,
		"allowed", creds.AllowedFrom)
	return false
}

// checkAllowedFrom checks if fromAddr matches the allowed_from list
func (a *HTTPAuthenticator) checkAllowedFrom(allowedFromAddresses []string, authUser, fromAddr string) bool {
	// If no specific allowed addresses configured, default to username match
	if len(allowedFromAddresses) == 0 {
		return authUser == fromAddr
	}

	// Check if from address matches any allowed pattern (exact or wildcard)
	for _, allowed := range allowedFromAddresses {
		allowedEmail := extractEmail(allowed)
		if matchEmailPattern(allowedEmail, fromAddr) {
			return true
		}
	}

	return false
}

// matchEmailPattern checks if an email matches a pattern (supports wildcards)
// Pattern examples: "user@example.com" (exact), "*@example.com" (domain wildcard)
func matchEmailPattern(pattern, email string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	email = strings.ToLower(strings.TrimSpace(email))

	// Exact match
	if pattern == email {
		return true
	}

	// Wildcard matching: *@domain.com
	if strings.HasPrefix(pattern, "*@") {
		domain := pattern[2:] // Remove "*@"
		if strings.HasSuffix(email, "@"+domain) {
			return true
		}
	}

	return false
}

// extractEmail extracts the email address from "Name <email>" or just "email" format
func extractEmail(address string) string {
	addr := strings.TrimSpace(address)

	// Extract email address from "Name <email>" format
	if strings.Contains(addr, "<") && strings.Contains(addr, ">") {
		start := strings.Index(addr, "<")
		end := strings.Index(addr, ">")
		if start < end {
			addr = addr[start+1 : end]
		}
	}

	return strings.ToLower(strings.TrimSpace(addr))
}

// getCredCached retrieves cached credentials entry
func (a *HTTPAuthenticator) getCredCached(username string) *credCacheEntry {
	a.credCacheMu.RLock()
	defer a.credCacheMu.RUnlock()

	entry, ok := a.credCache[username]
	if !ok {
		return nil
	}

	// Check if expired
	if time.Now().After(entry.expiresAt) {
		return nil
	}

	return entry
}

// cacheCredentials stores credentials in cache
func (a *HTTPAuthenticator) cacheCredentials(username string, passwordHashes []string, allowedFromAddresses []string) {
	a.credCacheMu.Lock()
	defer a.credCacheMu.Unlock()

	a.credCache[username] = &credCacheEntry{
		passwordHashes:       passwordHashes,
		allowedFromAddresses: allowedFromAddresses,
		expiresAt:            time.Now().Add(a.credCacheTTL),
	}
}

// clearCredCacheEntry removes a specific entry from the credentials cache
func (a *HTTPAuthenticator) clearCredCacheEntry(username string) {
	a.credCacheMu.Lock()
	defer a.credCacheMu.Unlock()
	delete(a.credCache, username)
}

// cleanupCredCache periodically removes expired credentials entries
func (a *HTTPAuthenticator) cleanupCredCache() {
	ticker := time.NewTicker(a.credCacheClean)
	defer ticker.Stop()

	for range ticker.C {
		a.credCacheMu.Lock()
		now := time.Now()
		for username, entry := range a.credCache {
			if now.After(entry.expiresAt) {
				delete(a.credCache, username)
			}
		}
		a.credCacheMu.Unlock()
	}
}

// FlushCache clears both authentication and credentials caches
func (a *HTTPAuthenticator) FlushCache() {
	a.credCacheMu.Lock()
	a.credCache = make(map[string]*credCacheEntry)
	a.credCacheMu.Unlock()

	if a.authCache != nil {
		a.authCache.Clear()
	}

	a.logger.Info("authentication caches flushed")
}

// LoginServer implements the LOGIN SASL mechanism server
// LOGIN is non-standard but widely used for SMTP authentication
type LoginServer struct {
	authenticator func(username, password string) error
	username      string
	step          int
}

// Next processes the LOGIN authentication handshake
func (l *LoginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch l.step {
	case 0:
		// First step: request username
		l.step = 1
		return []byte("Username:"), false, nil
	case 1:
		// Second step: got username, request password
		l.username = string(response)
		l.step = 2
		return []byte("Password:"), false, nil
	case 2:
		// Third step: got password, authenticate
		password := string(response)
		err = l.authenticator(l.username, password)
		return nil, true, err
	default:
		return nil, true, fmt.Errorf("unexpected step in LOGIN authentication")
	}
}

// NewLoginServer creates a new LOGIN SASL server
func NewLoginServer(authenticator func(username, password string) error) *LoginServer {
	return &LoginServer{
		authenticator: authenticator,
		step:          0,
	}
}

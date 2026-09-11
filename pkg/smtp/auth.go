package smtp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"migadu/mizu/pkg/concurrency"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/migadu/passwd"
)

// HTTPAuthenticator authenticates users via HTTPS GET API with local password verification
type HTTPAuthenticator struct {
	urlTemplate string // URL template with $email and $ip placeholders
	apiKey      string
	httpClient  *http.Client
	logger      *slog.Logger

	// Auth result cache (password-aware, separate positive/negative TTL).
	// A hit only short-circuits successful re-authentication of the same
	// username+password within the positive TTL; negative entries are kept for
	// observability only and never block a retry (brute-force protection is
	// the auth rate limiter's job).
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
	identity             string   // Address the login acts as (see AuthResponse.Identity)
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

	// Identity is the address the AUTH username acts as. For an ordinary login
	// it equals the username; for a master/token login ("user@domain@SUFFIX",
	// Sora's support access) it is the base address, because the suffix names
	// the credential and not the sender. The backend is the only authority for
	// this: an empty value means "no rewrite", so a backend that does not serve
	// the field behaves exactly as before.
	Identity string `json:"identity"`
}

// Authenticate verifies username and password by fetching hash from backend and verifying locally
// The remoteIP parameter is used for URL interpolation ($ip placeholder)
func (a *HTTPAuthenticator) Authenticate(username, password string) (bool, error) {
	return a.AuthenticateWithIP(username, password, "")
}

// AuthenticateWithIP verifies username and password with client IP for URL interpolation
func (a *HTTPAuthenticator) AuthenticateWithIP(username, password, remoteIP string) (bool, error) {
	// Check auth cache first (if enabled). A hit only ever short-circuits a
	// successful re-authentication of the same username+password; misses,
	// expiries, and negative entries all fall through to the backend. Brute-force
	// protection is the auth rate limiter's job, never the cache's.
	if a.authCache != nil {
		authenticated, found := a.authCache.CheckAuth(username, password)
		if found && authenticated {
			// Cache hit - authentication successful
			// Still need to check credentials cache for CanSendAs
			if entry := a.getCredCached(username); entry == nil {
				// Creds not in cache - fetch them for CanSendAs later
				creds, fetchErr := a.fetchCredentials(username, remoteIP)
				if fetchErr == nil && len(creds.PasswordHashes) > 0 {
					a.cacheCredentials(username, creds.PasswordHashes, creds.AllowedFrom, creds.Identity)
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
				// The account is gone from the backend: definitive, so (false,
				// nil) for a permanent 535. See the contract on Authenticator in
				// server.go.
				if errors.Is(err, errUserUnknown) {
					return false, nil
				}
				// Backend error - return error without caching
				return false, err
			}

			// Account exists but serves no usable hash. Nothing to verify
			// against, yet the account is real, so this stays temporary.
			if len(creds.PasswordHashes) == 0 {
				return false, fmt.Errorf("no password hashes for user")
			}

			// Verify password against fresh credentials
			if a.verifyAgainstHashes(creds.PasswordHashes, password) {
				// Success with fresh credentials (password was changed)
				a.cacheCredentials(username, creds.PasswordHashes, creds.AllowedFrom, creds.Identity)
				a.logger.Info("authentication successful with fresh credentials", "username", username)
				return true, nil
			}

			// Password still doesn't match - cache fresh credentials
			a.cacheCredentials(username, creds.PasswordHashes, creds.AllowedFrom, creds.Identity)
			return false, fmt.Errorf("password verification failed")
		}
	}

	// Fetch credentials from backend (cache miss)
	creds, err := a.fetchCredentials(username, remoteIP)
	if err != nil {
		// The backend has no row for this address. That is the ONE definitive
		// rejection: no retry can conjure the account into existence, so it is
		// the only thing that returns (false, nil) and becomes a permanent 535.
		// See the contract on Authenticator in server.go.
		if errors.Is(err, errUserUnknown) {
			if a.authCache != nil {
				a.authCache.SetFailure(username, password, AuthUserNotFound)
			}
			return false, nil
		}
		// Everything else - a denied account, a backend 5xx, a timeout - leaves
		// the credential unjudged. Cache negative result if auth cache enabled.
		if a.authCache != nil {
			a.authCache.SetFailure(username, password, AuthFailed)
		}
		return false, err
	}

	// The account exists but serves no usable hash (200 with an empty list).
	// There is nothing to verify against, but the account is real and an
	// operator can fix its credential, so this stays temporary.
	if len(creds.PasswordHashes) == 0 {
		if a.authCache != nil {
			a.authCache.SetFailure(username, password, AuthInvalidPassword)
		}
		return false, fmt.Errorf("no password hashes for user")
	}

	// Verify password against fetched hashes (try all until one matches)
	if !a.verifyAgainstHashes(creds.PasswordHashes, password) {
		if a.authCache != nil {
			a.authCache.SetFailure(username, password, AuthInvalidPassword)
		}
		// Cache credentials anyway so future attempts can use them
		a.cacheCredentials(username, creds.PasswordHashes, creds.AllowedFrom, creds.Identity)
		return false, fmt.Errorf("password verification failed")
	}

	// Cache successful authentication
	a.cacheCredentials(username, creds.PasswordHashes, creds.AllowedFrom, creds.Identity)
	if a.authCache != nil {
		a.authCache.SetSuccess(username, password)
	}
	a.logger.Info("Authentication successful", "username", username)
	return true, nil
}

// verifyAgainstHashes tries to verify the password against a list of hashes.
// Returns true if any hash matches. passwd.VerifyAny always iterates all
// hashes, so which position matched cannot leak via a timing side-channel.
func (a *HTTPAuthenticator) verifyAgainstHashes(hashes []string, password string) bool {
	return passwd.VerifyAny(hashes, password).Matched
}

// errUserUnknown reports that the auth backend has no row for this address
// (HTTP 404) - the account does not exist, as opposed to existing but failing
// to authenticate. It is the ONLY condition that earns a permanent 535; every
// other failure, including a denied account or one with no usable hash, is
// temporary. Callers must test it with errors.Is before any generic error
// handling, since it travels in the error return.
var errUserUnknown = errors.New("user not found in auth backend")

// fetchCredentials fetches user credentials from the backend via GET request.
// Returns errUserUnknown when the backend has no such account (404); any other
// non-nil error means the lookup itself did not produce a usable answer.
func (a *HTTPAuthenticator) fetchCredentials(username, remoteIP string) (*AuthResponse, error) {
	requestURL := BuildAuthURL(a.urlTemplate, username, remoteIP)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	status, authResp, body, err := FetchAuthCredentials(ctx, a.httpClient, requestURL, a.apiKey)
	if err != nil {
		a.logger.Error("auth request failed", "url", requestURL, "status", status, "error", err)
		if status == http.StatusOK {
			// Got a 200 but the body was unreadable or not valid JSON
			return nil, fmt.Errorf("internal error")
		}
		return nil, fmt.Errorf("authentication service unavailable")
	}

	switch status {
	case http.StatusOK:
		return authResp, nil
	case http.StatusNotFound:
		// 404 is the one definitive "no such account" answer, and the only path
		// to a permanent 535. Everything else that fails stays temporary.
		a.logger.Debug("auth request: user not found",
			"username", username,
			"url", requestURL,
			"status", status,
			"response", string(body))
		return nil, errUserUnknown
	case http.StatusForbidden:
		// 403 means the user is denied submission (deny_smtp). The account EXISTS
		// - it is just not permitted to submit right now, and a deny can be
		// lifted - so this must not read as "your credentials are permanently
		// invalid". A permanent reply would have clients discard a stored
		// password that starts working again the moment the deny is removed, so
		// a deny is temporary. Logged distinctly so operators can tell a deny
		// apart from an unknown user.
		a.logger.Info("auth request: user denied submission",
			"username", username,
			"url", requestURL,
			"status", status)
		return nil, fmt.Errorf("user denied submission")
	default:
		a.logger.Warn("auth request failed",
			"username", username,
			"url", requestURL,
			"status", status,
			"response", string(body))
		return nil, fmt.Errorf("authentication service error: %d", status)
	}
}

// FetchAuthCredentials performs the GET request Mizu sends to the auth backend:
// bearer-token authorization, 404 treated as "user unknown" (empty response, no
// error), JSON decode on 200. It returns the HTTP status code, the decoded
// response, and the raw body for diagnostics; err is set only for transport,
// read, or decode failures. Shared with mizu-admin so the CLI queries the
// backend exactly as the server does.
//
// The response is non-nil on 200, 404, and 403 (empty for the latter two).
// Note this is the raw transport helper: it reports the status and lets the
// caller decide. The server's own policy lives in fetchCredentials, which keys
// the permanent-vs-temporary verdict off the STATUS - only a 404 is permanent -
// and never off len(PasswordHashes), since an empty hash list also arrives with
// a 403 and with a 200 for an account that simply has no credential set.
func FetchAuthCredentials(ctx context.Context, client *http.Client, requestURL, token string) (int, *AuthResponse, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var authResp AuthResponse
		if err := json.Unmarshal(body, &authResp); err != nil {
			return resp.StatusCode, nil, body, err
		}
		return resp.StatusCode, &authResp, body, nil
	case http.StatusNotFound:
		return resp.StatusCode, &AuthResponse{}, body, nil
	case http.StatusForbidden:
		// The backend denied submission for this user (rcptd deny_smtp). This is
		// a definitive auth failure, not a transport error: hand back an empty
		// (no-hashes) response so the caller rejects the AUTH the same way it
		// does for an unknown user, rather than raising a backend error.
		return resp.StatusCode, &AuthResponse{}, body, nil
	default:
		return resp.StatusCode, nil, body, nil
	}
}

// BuildAuthURL builds an auth request URL by interpolating the $email and $ip
// placeholders (URL-encoded) in the endpoint URL template.
func BuildAuthURL(template, email, ip string) string {
	result := strings.ReplaceAll(template, "$email", url.QueryEscape(email))
	return strings.ReplaceAll(result, "$ip", url.QueryEscape(ip))
}

// CanSendAs reports whether the authenticated user may send as a FROM address.
// It is ResolveSender without the resolved address, kept for callers that only
// need the verdict.
func (a *HTTPAuthenticator) CanSendAs(authenticatedUser, fromAddress string) bool {
	_, ok := a.ResolveSender(authenticatedUser, fromAddress)
	return ok
}

// ResolveSender authorizes a FROM address for an authenticated user and returns
// the address the session should actually send as.
//
// The two differ only for a master/token login ("user@domain@SUFFIX"), where a
// client — Sora's webmail prefills its compose form from the login string —
// may present the suffixed login as the sender. That string is not a routable
// address, and it carries the master username, which must not reach a
// recipient. When the FROM address is exactly the login, it is resolved to the
// identity the backend reported at AUTH and authorized as that. Every other
// FROM address is authorized as sent, so this cannot be used to send as a third
// party: the resolved address still has to pass allowed_from.
//
// The backend is the sole authority for the rewrite. With no identity served
// (an older rcptd, or another backend) the login is its own identity and
// nothing is rewritten.
//
// Supports wildcards in allowed_from patterns (e.g., "*@example.com"). If the
// FROM address is not in the cached allowed list, refetches from the backend to
// detect changes.
func (a *HTTPAuthenticator) ResolveSender(authenticatedUser, fromAddress string) (string, bool) {
	// Get cached credentials entry to check allowed FROM addresses
	entry := a.getCredCached(authenticatedUser)
	if entry == nil {
		// Not in cache - shouldn't happen if Authenticate was called first
		a.logger.Warn("CanSendAs called but user credentials not in cache", "user", authenticatedUser)
		return "", false
	}

	// Normalize addresses for comparison
	authUser := strings.ToLower(strings.TrimSpace(authenticatedUser))
	identity := resolveIdentity(authUser, entry.identity)
	fromAddr := resolveFrom(extractEmail(fromAddress), authUser, identity)

	// Check against cached allowed_from list
	if a.checkAllowedFrom(entry.allowedFromAddresses, identity, fromAddr) {
		return fromAddr, true
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
		if errors.Is(err, errUserUnknown) {
			// The account was removed mid-session; not a backend failure.
			a.logger.Warn("user no longer exists during CanSendAs refetch", "user", authenticatedUser)
		} else {
			a.logger.Error("failed to refetch credentials for CanSendAs check", "user", authenticatedUser, "error", err)
		}
		return "", false
	}

	if len(creds.PasswordHashes) == 0 {
		a.logger.Warn("user serves no password hashes during CanSendAs refetch", "user", authenticatedUser)
		return "", false
	}

	// Cache fresh credentials
	a.cacheCredentials(authenticatedUser, creds.PasswordHashes, creds.AllowedFrom, creds.Identity)

	// The identity may have moved with the refetch, so redo the resolution
	// against the fresh answer rather than the one the cache held.
	identity = resolveIdentity(authUser, creds.Identity)
	fromAddr = resolveFrom(extractEmail(fromAddress), authUser, identity)

	// Check again with fresh allowed_from list
	if a.checkAllowedFrom(creds.AllowedFrom, identity, fromAddr) {
		a.logger.Info("FROM address allowed after refetch (allowed_from was updated)",
			"user", authenticatedUser,
			"from", fromAddr)
		return fromAddr, true
	}

	a.logger.Warn("FROM address not in allowed list (verified with fresh data)",
		"authenticated", authUser,
		"from", fromAddr,
		"allowed", creds.AllowedFrom)
	return "", false
}

// SenderIdentity returns the address this login acts as when that differs from
// the login itself — i.e. a master/token login — and "" otherwise, including
// when nothing is cached for the user.
//
// It reads the cache only and never refetches: it answers "is this session
// acting as someone else", which must not cost a backend round trip on every
// message, and a miss simply means no rewrite.
func (a *HTTPAuthenticator) SenderIdentity(authenticatedUser string) string {
	entry := a.getCredCached(authenticatedUser)
	if entry == nil {
		return ""
	}
	authUser := strings.ToLower(strings.TrimSpace(authenticatedUser))
	if identity := resolveIdentity(authUser, entry.identity); identity != authUser {
		return identity
	}
	return ""
}

// resolveIdentity returns the address a login acts as: what the backend served,
// or the login itself when it served nothing.
func resolveIdentity(authUser, served string) string {
	if served = strings.ToLower(strings.TrimSpace(served)); served != "" {
		return served
	}
	return authUser
}

// resolveFrom maps a FROM address that is really the login string onto the
// identity it stands for. Everything else passes through untouched.
func resolveFrom(fromAddr, authUser, identity string) string {
	if fromAddr == authUser && identity != authUser {
		return identity
	}
	return fromAddr
}

// checkAllowedFrom checks if fromAddr matches the allowed_from list. identity is
// the address the session acts as — for a plain login that is the AUTH username
// itself, for a master login the address it stands in for. It must never be the
// raw login string: a suffixed login is not an address, so falling back to it
// here would demand an unroutable envelope sender.
func (a *HTTPAuthenticator) checkAllowedFrom(allowedFromAddresses []string, identity, fromAddr string) bool {
	// If no specific allowed addresses configured, default to identity match
	if len(allowedFromAddresses) == 0 {
		return identity == fromAddr
	}

	// Check if from address matches any allowed pattern (exact, wildcard, or regex)
	for _, allowed := range allowedFromAddresses {
		pattern := strings.TrimSpace(allowed)
		if isRegexPattern(pattern) {
			// rcptd compile-checks patterns before serving them, but Go's RE2
			// rejects PCRE-only constructs (lookaheads, backreferences); log
			// those instead of silently never matching.
			if _, err := regexCache.get(pattern[1 : len(pattern)-1]); err != nil {
				a.logger.Warn("Ignoring allowed_from regex that does not compile",
					"pattern", pattern, "error", err)
				continue
			}
		} else {
			// extractEmail would mangle a regex (it strips "Name <email>"
			// forms and lowercases); only apply it to address patterns.
			pattern = extractEmail(pattern)
		}
		if matchEmailPattern(pattern, fromAddr) {
			return true
		}
	}

	return false
}

// matchEmailPattern checks if an email matches a pattern (supports wildcards)
// Pattern examples: "user@example.com" (exact), "*@example.com" (domain
// wildcard), "/^user\+.*@example\.com/" (regex from rcptd's regex_sender_login
// pass-through, matched with Postfix pcre substring semantics).
func matchEmailPattern(pattern, email string) bool {
	pattern = strings.TrimSpace(pattern)
	email = strings.ToLower(strings.TrimSpace(email))

	// Regex pattern: "/.../" — a compile failure is no match (checkAllowedFrom
	// logs uncompilable patterns before calling here).
	if isRegexPattern(pattern) {
		re, err := regexCache.get(pattern[1 : len(pattern)-1])
		if err != nil {
			return false
		}
		return re.MatchString(email)
	}

	pattern = strings.ToLower(pattern)

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

// isRegexPattern reports whether an allowed_from entry is a "/.../" regex
// (rcptd's regex_sender_login pass-through) rather than an address pattern.
// The trailing "/" check matters: an entry like "/dev/null <alias@example.com>"
// starts with a slash but is a display-name address, not a regex.
func isRegexPattern(pattern string) bool {
	return len(pattern) > 2 && strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/")
}

// regexCache caches compiled allowed_from regex patterns. Entries come from
// the trusted rcptd backend and the set is small and stable, so the cache is
// unbounded and never evicted.
var regexCache = &compiledRegexCache{patterns: make(map[string]compiledRegex)}

type compiledRegex struct {
	re  *regexp.Regexp
	err error
}

type compiledRegexCache struct {
	mu       sync.RWMutex
	patterns map[string]compiledRegex
}

func (c *compiledRegexCache) get(pattern string) (*regexp.Regexp, error) {
	c.mu.RLock()
	entry, ok := c.patterns[pattern]
	c.mu.RUnlock()
	if !ok {
		// Case-insensitive: SMTP addresses are compared lowercased, and the
		// patterns are written for lowercase addresses.
		re, err := regexp.Compile("(?i)" + pattern)
		entry = compiledRegex{re: re, err: err}
		c.mu.Lock()
		c.patterns[pattern] = entry
		c.mu.Unlock()
	}
	return entry.re, entry.err
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

// maxCredCacheEntries bounds the credential cache. The keyspace is
// attacker-controlled (arbitrary usernames from unauthenticated clients trigger
// backend fetches), so without a cap a username flood could exhaust memory
// within the TTL window.
const maxCredCacheEntries = 10000

// cacheCredentials stores credentials in cache. identity is the address the
// login acts as (AuthResponse.Identity); an empty value means the login is its
// own identity.
func (a *HTTPAuthenticator) cacheCredentials(username string, passwordHashes []string, allowedFromAddresses []string, identity string) {
	a.credCacheMu.Lock()
	defer a.credCacheMu.Unlock()

	if _, exists := a.credCache[username]; !exists && len(a.credCache) >= maxCredCacheEntries {
		// At capacity: opportunistically drop expired entries before giving up.
		now := time.Now()
		for k, e := range a.credCache {
			if now.After(e.expiresAt) {
				delete(a.credCache, k)
			}
		}
		if len(a.credCache) >= maxCredCacheEntries {
			return // Still full; refuse to grow to bound memory against username floods.
		}
	}

	a.credCache[username] = &credCacheEntry{
		passwordHashes:       passwordHashes,
		allowedFromAddresses: allowedFromAddresses,
		identity:             identity,
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

// Next processes the LOGIN authentication handshake.
//
// The exchange has two shapes and BOTH must work. Without an initial response
// it is the three-step form (`AUTH LOGIN`, "Username:", "Password:"). With one,
// the client sent its username on the AUTH command itself (RFC 4954 §4 initial
// response) and waits to be asked only for the password — this is what Outlook
// and every go-sasl LOGIN client do. go-smtp passes that initial response here;
// DISCARDING it desynchronizes the exchange: the client answers our "Username:"
// prompt with its PASSWORD, which we then try as a username, and auth can never
// succeed.
func (l *LoginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch l.step {
	case 0:
		// Initial response present (non-nil, including the "=" zero-length
		// form) => it is the username; skip straight to asking for the password.
		if response != nil {
			l.username = string(response)
			l.step = 2
			return []byte("Password:"), false, nil
		}
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

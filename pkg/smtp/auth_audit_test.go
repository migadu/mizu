package smtp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"migadu/mizu/pkg/config"

	"golang.org/x/crypto/bcrypt"
)

// Regression tests for the 2026-11 security audit (docs/security-audit-todo.md),
// AUTH section.

func newAuditLimiter(t *testing.T, cfg config.ServerAuthRateLimitConfig) *AuthRateLimiter {
	t.Helper()
	cfg.Enabled = true
	limiter, err := NewAuthRateLimiter(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("NewAuthRateLimiter: %v", err)
	}
	return limiter
}

// A2: a wrong password on an existing account is reported by the authenticator
// as an error (so the client gets a temporary 454), and the limiter gate used
// to skip every error. That left password guessing against real accounts - the
// only accounts worth guessing against - completely unlimited.
func TestAudit_WrongPasswordFeedsAuthRateLimiter(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-horse"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(AuthResponse{
			PasswordHashes: []string{string(hash)},
			AllowedFrom:    []string{"user@example.com"},
		})
	}))
	defer backend.Close()

	limiter := newAuditLimiter(t, config.ServerAuthRateLimitConfig{
		MaxAttemptsPerIPUsername: 3,
		MaxAttemptsPerIP:         100, // keep tier 2 out of the way
		IPUsernameBlockDuration:  "15m",
		IPUsernameWindowDuration: "10m",
	})

	s := newAuthReplySession(t, backend.URL)
	s.authRateLimiter = limiter

	for i := 0; i < 3; i++ {
		if err := authOnce(t, s, "user@example.com", "wrong"); err == nil {
			t.Fatalf("guess %d: wrong password must not authenticate", i+1)
		}
	}

	if err := limiter.CanAttemptAuth(context.Background(), s.remoteAddr, "user@example.com"); err == nil {
		t.Fatal("3 wrong passwords at a limit of 3 must block the IP+username pair")
	}
	// The block must hold even for the right password: that is what makes
	// guessing pointless.
	if err := authOnce(t, s, "user@example.com", "correct-horse"); err == nil {
		t.Fatal("a blocked pair must not authenticate, even with the right password")
	}
	if s.isAuthenticated {
		t.Fatal("session must not be authenticated while blocked")
	}
}

// A backend outage is not a guess, and must keep being ignored by the limiter:
// counting it would spend a legitimate user's budget on our own failure.
func TestAudit_BackendErrorDoesNotFeedAuthRateLimiter(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer backend.Close()

	limiter := newAuditLimiter(t, config.ServerAuthRateLimitConfig{
		MaxAttemptsPerIPUsername: 3,
		MaxAttemptsPerIP:         100, // keep tier 2 out of the way
		IPUsernameBlockDuration:  "15m",
		IPUsernameWindowDuration: "10m",
	})
	s := newAuthReplySession(t, backend.URL)
	s.authRateLimiter = limiter

	for i := 0; i < 10; i++ {
		_ = authOnce(t, s, "user@example.com", "whatever")
	}
	if err := limiter.CanAttemptAuth(context.Background(), s.remoteAddr, "user@example.com"); err != nil {
		t.Fatalf("backend errors must not count as failed guesses: %v", err)
	}
}

// A5: Session.remoteAddr is a bare IP (NewSession strips the port). The AUTH
// path used to strip "the port" again by cutting at the last colon, which for
// IPv6 removed the final hextet: the limiter got an unparseable key (no /64
// bucketing, no subnet tier) and the auth backend got a mangled $ip.
func TestAudit_IPv6RemoteAddrIsNotTruncatedForAuth(t *testing.T) {
	var mu sync.Mutex
	var seenIPs []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenIPs = append(seenIPs, r.URL.Query().Get("ip"))
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}))
	defer backend.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auth := NewHTTPAuthenticator(backend.URL+"/?email=$email&ip=$ip", "tok", logger, nil)

	limiter := newAuditLimiter(t, config.ServerAuthRateLimitConfig{
		MaxAttemptsPerIP: 4,
		IPBlockDuration:  "30m",
		IPWindowDuration: "15m",
	})

	// Four failures, each from a different address inside one /64.
	addrs := []string{
		"2001:db8:1:2:aaaa:bbbb:cccc:1",
		"2001:db8:1:2:aaaa:bbbb:dddd:2",
		"2001:db8:1:2:1111:2222:3333:3",
		"2001:db8:1:2::4",
	}
	for _, addr := range addrs {
		s := newAuthReplySessionWith(t, auth)
		s.remoteAddr = addr
		s.authRateLimiter = limiter
		_ = authOnce(t, s, "nobody@example.com", "x")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seenIPs) != len(addrs) {
		t.Fatalf("backend saw %d requests, want %d", len(seenIPs), len(addrs))
	}
	for i, addr := range addrs {
		if seenIPs[i] != addr {
			t.Errorf("backend $ip = %q, want the full address %q", seenIPs[i], addr)
		}
	}

	// All four share a /64, so they share one tier-2 bucket and a fifth
	// sibling must now be refused.
	if err := limiter.CanAttemptAuth(context.Background(), "2001:db8:1:2:ffff:ffff:ffff:5", "nobody@example.com"); err == nil {
		t.Fatal("4 failures from one IPv6 /64 at a limit of 4 must block the /64")
	}
}

// A4: go-smtp unquotes a quoted local part, so
// MAIL FROM:<"<me@mine.example>"@victim.example> reaches the session as
// `<me@mine.example>@victim.example`. ResolveSender used to run a display-name
// parser over that envelope path, authorize the text between the angle
// brackets (the attacker's own address), and leave the envelope - and with it
// the sender domain used by stats, rate limits, rspamd and mailqueuer - as
// victim.example.
func TestAudit_ResolveSenderAuthorizesTheWholeEnvelopeAddress(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	for name, allowed := range map[string][]string{
		"exact":    {"me@mine.example"},
		"wildcard": {"*@mine.example"},
		"regex":    {`/^me(\+.*)?@mine\.example$/`},
		"default":  nil, // empty allowed_from: identity only
	} {
		t.Run(name, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(AuthResponse{PasswordHashes: []string{string(hash)}, AllowedFrom: allowed})
			}))
			defer backend.Close()

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			auth := NewHTTPAuthenticator(backend.URL, "tok", logger, nil)
			if ok, err := auth.Authenticate("me@mine.example", "pw"); !ok || err != nil {
				t.Fatalf("Authenticate = (%v, %v)", ok, err)
			}

			if got, ok := auth.ResolveSender("me@mine.example", "Me@Mine.Example"); !ok || got != "me@mine.example" {
				t.Fatalf("own address: ResolveSender = (%q, %v), want (me@mine.example, true)", got, ok)
			}

			for _, from := range []string{
				"<me@mine.example>@victim.example",
				"x<me@mine.example>y@victim.example",
				"me@mine.example>@victim.example",
				"<me@mine.example",
				"me@mine.example@victim.example",
				"Me <me@mine.example>",
			} {
				if got, ok := auth.ResolveSender("me@mine.example", from); ok {
					t.Errorf("ResolveSender(%q) = (%q, true); an envelope that is not the plain authorized address must be refused", from, got)
				}
			}
		})
	}
}

// A6: the credentials cache was keyed on the raw AUTH username, so case
// variants of one address (which the backend treats as the same account) each
// took a slot, and ResolveSender answered a cache miss with a permanent
// rejection. An unauthenticated client could fill the capped cache with
// variants and every legitimate sender then got 550 at MAIL FROM; so did any
// session still sending after the 5-minute entry TTL.
func TestAudit_CredCacheKeyIsCaseInsensitive(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(AuthResponse{PasswordHashes: []string{string(hash)}, AllowedFrom: []string{"user@example.com"}})
	}))
	defer backend.Close()

	auth := NewHTTPAuthenticator(backend.URL, "tok", slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	for _, variant := range []string{"user@example.com", "User@example.com", "USER@EXAMPLE.COM", "uSeR@eXaMpLe.CoM"} {
		_, _ = auth.Authenticate(variant, "wrong")
	}
	auth.credCacheMu.RLock()
	n := len(auth.credCache)
	auth.credCacheMu.RUnlock()
	if n != 1 {
		t.Fatalf("4 case variants of one account occupy %d cache slots, want 1", n)
	}
}

func TestAudit_ResolveSenderRefetchesOnCredCacheMiss(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(AuthResponse{PasswordHashes: []string{string(hash)}, AllowedFrom: []string{"user@example.com", "alias@example.com"}})
	}))
	defer backend.Close()

	auth := NewHTTPAuthenticator(backend.URL, "tok", slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if ok, err := auth.Authenticate("user@example.com", "pw"); !ok || err != nil {
		t.Fatalf("Authenticate = (%v, %v)", ok, err)
	}

	// The entry is gone: expired mid-session, or never stored because the
	// cache was full when this user authenticated.
	auth.credCacheMu.Lock()
	auth.credCache = make(map[string]*credCacheEntry)
	auth.credCacheMu.Unlock()

	if got, ok := auth.ResolveSender("user@example.com", "alias@example.com"); !ok || got != "alias@example.com" {
		t.Fatalf("ResolveSender after a cache miss = (%q, %v), want (alias@example.com, true)", got, ok)
	}
	if _, ok := auth.ResolveSender("user@example.com", "stranger@example.com"); ok {
		t.Fatal("a cache miss must not authorize an address outside allowed_from")
	}
}

// A13: the backend treats the login case-insensitively, so the limiter must
// too - otherwise each case variant gets its own tier-1 budget.
func TestAudit_AuthRateLimiterUsernameIsCaseInsensitive(t *testing.T) {
	limiter := newAuditLimiter(t, config.ServerAuthRateLimitConfig{
		MaxAttemptsPerIPUsername: 3,
		MaxAttemptsPerIP:         100, // keep tier 2 out of the way
		IPUsernameBlockDuration:  "15m",
		IPUsernameWindowDuration: "10m",
	})
	ctx := context.Background()
	for _, variant := range []string{"user@example.com", "User@example.com", "USER@example.com"} {
		limiter.RecordAuthAttempt(ctx, "192.0.2.10", variant, false)
	}
	if err := limiter.CanAttemptAuth(ctx, "192.0.2.10", "uSeR@example.com"); err == nil {
		t.Fatal("3 failures across case variants of one username at a limit of 3 must block the pair")
	}
}

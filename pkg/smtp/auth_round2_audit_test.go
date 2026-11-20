package smtp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/emersion/go-smtp"
	"golang.org/x/crypto/bcrypt"

	"migadu/mizu/pkg/config"
)

// C1: a successful login used to delete the whole per-IP failure count. Anyone
// holding one valid account could guess a few passwords against other
// accounts, log in as themselves, and repeat: tier 2 never fired.
func TestAudit_SuccessDoesNotForgiveGuessesAtOtherAccounts(t *testing.T) {
	limiter := newAuditLimiter(t, config.ServerAuthRateLimitConfig{
		MaxAttemptsPerIP: 10,
		IPBlockDuration:  "15m",
		IPWindowDuration: "10m",
	})
	ctx := context.Background()
	const ip = "203.0.113.50"

	blocked := false
	for round := 0; round < 5 && !blocked; round++ {
		for i := 0; i < 4; i++ {
			victim := fmt.Sprintf("victim%d-%d@example.com", round, i)
			if err := limiter.CanAttemptAuth(ctx, ip, victim); err != nil {
				blocked = true
				break
			}
			limiter.RecordAuthAttempt(ctx, ip, victim, false)
		}
		if blocked {
			break
		}
		if err := limiter.CanAttemptAuth(ctx, ip, "attacker@example.com"); err != nil {
			blocked = true
			break
		}
		limiter.RecordAuthAttempt(ctx, ip, "attacker@example.com", true)
	}
	if !blocked {
		t.Fatal("20 wrong guesses at other accounts were never blocked: the attacker's own logins reset the per-IP count")
	}
}

// The other half of the expectation: a user's own typos are forgiven once they
// get the password right, so an office behind one address is not blocked by
// mistakes that were corrected.
func TestAudit_SuccessForgivesTheUsersOwnFailures(t *testing.T) {
	limiter := newAuditLimiter(t, config.ServerAuthRateLimitConfig{
		MaxAttemptsPerIP: 10,
		IPBlockDuration:  "15m",
		IPWindowDuration: "10m",
	})
	ctx := context.Background()
	const ip = "203.0.113.51"

	for round := 0; round < 10; round++ {
		user := fmt.Sprintf("colleague%d@example.com", round)
		for i := 0; i < 3; i++ {
			if err := limiter.CanAttemptAuth(ctx, ip, user); err != nil {
				t.Fatalf("round %d: blocked although every earlier typo was followed by a success: %v", round, err)
			}
			limiter.RecordAuthAttempt(ctx, ip, user, false)
		}
		limiter.RecordAuthAttempt(ctx, ip, user, true)
	}
	if d := limiter.GetAuthenticationDelay(ip); d != 0 {
		t.Fatalf("delay %v remains after all failures were forgiven", d)
	}
}

// D1: AUTH was accepted in the middle of a mail transaction. ResolveSender -
// the allowed_from check - only runs inside Mail, so
//
//	MAIL FROM:<ceo@victim.test>   (unauthenticated)
//	AUTH PLAIN <own account>
//	RCPT TO / DATA
//
// ended as an authenticated session sending as an address the account was
// never authorised for. RFC 4954 section 4: AUTH is not permitted during a
// mail transaction.
func TestAudit_AuthIsRefusedDuringMailTransaction(t *testing.T) {
	for _, state := range []int{stateMail, stateRcpt} {
		s := newAuthReplySession(t, "https://unused.invalid")
		s.commandState = state
		s.from = "ceo@victim.test"

		_, err := s.Auth("PLAIN")
		requireSMTPCode(t, err, 503, smtp.EnhancedCode{5, 5, 1}, "AUTH after MAIL FROM")
	}

	// Before MAIL it is still accepted.
	s := newAuthReplySession(t, "https://unused.invalid")
	s.commandState = stateHelo
	if _, err := s.Auth("PLAIN"); err != nil {
		t.Fatalf("AUTH before MAIL FROM: %v", err)
	}
}

// D14: `mizu-admin unblock-ip` cleared the per-IP block and count but left the
// IP+username blocks standing, so the user the operator had just unblocked was
// still refused for the account they had mistyped.
func TestAudit_UnblockIPAlsoLiftsItsUsernameBlocks(t *testing.T) {
	limiter := newAuditLimiter(t, config.ServerAuthRateLimitConfig{
		MaxAttemptsPerIPUsername: 3,
		MaxAttemptsPerIP:         100,
		IPUsernameBlockDuration:  "15m",
		IPUsernameWindowDuration: "10m",
	})
	ctx := context.Background()
	const ip, other = "203.0.113.60", "203.0.113.61"

	for i := 0; i < 3; i++ {
		limiter.RecordAuthAttempt(ctx, ip, "user@example.com", false)
		limiter.RecordAuthAttempt(ctx, other, "user@example.com", false)
	}
	if limiter.CanAttemptAuth(ctx, ip, "user@example.com") == nil {
		t.Fatal("setup: the IP+username pair should be blocked")
	}

	if !limiter.RemoveIP(ip) {
		t.Fatal("RemoveIP reported nothing removed")
	}
	if err := limiter.CanAttemptAuth(ctx, ip, "user@example.com"); err != nil {
		t.Fatalf("still refused after the operator unblocked the address: %v", err)
	}
	// Another address's block on the same username is untouched.
	if limiter.CanAttemptAuth(ctx, other, "user@example.com") == nil {
		t.Fatal("unblocking one address lifted another address's block")
	}
}

// C16: `validation.allow_null_sender` was read nowhere and has been removed.
// What actually keeps the null sender off a submission server is this: an
// authenticated MAIL FROM:<> has to pass allowed_from like any other sender,
// and no address list contains the empty address. Pinned here so removing the
// setting cannot silently open it.
func TestAudit_AuthenticatedNullSenderIsRefused(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	for name, allowed := range map[string][]string{
		"exact":    {"me@mine.example"},
		"wildcard": {"*@mine.example"},
		"regex":    {`/@mine\.example$/`},
		"default":  nil,
	} {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(AuthResponse{PasswordHashes: []string{string(hash)}, AllowedFrom: allowed})
		}))
		auth := NewHTTPAuthenticator(backend.URL, "tok", slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
		if ok, err := auth.Authenticate("me@mine.example", "pw"); !ok || err != nil {
			t.Fatalf("%s: Authenticate = (%v, %v)", name, ok, err)
		}
		for _, from := range []string{"", "<>"} {
			if got, ok := auth.ResolveSender("me@mine.example", from); ok {
				t.Errorf("%s: ResolveSender(%q) = (%q, true), want the null sender refused", name, from, got)
			}
		}
		backend.Close()
	}
}

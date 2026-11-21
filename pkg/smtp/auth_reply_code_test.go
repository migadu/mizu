package smtp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"migadu/mizu/pkg/config"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"golang.org/x/crypto/bcrypt"
)

// The reply code an AUTH failure carries is the whole user-visible contract,
// and until now nothing asserted it: auth_test.go only ever checked that
// Authenticate returned *an* error, which stayed true whether the session layer
// then produced a 535 or a 454. That gap let every failure - including an
// address that does not exist - answer 454 "try again later", so clients
// retried a hopeless address forever instead of reporting it.
//
// These tests drive the real Session.Auth exchange against a stub backend and
// assert the code on the wire.

func newAuthReplySession(t *testing.T, backendURL string) *Session {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return newAuthReplySessionWith(t, NewHTTPAuthenticator(backendURL, "test-auth-token", logger, nil))
}

// newAuthReplySessionWith builds a session over an existing authenticator, so a
// test can run two AUTH exchanges against the same credentials cache.
func newAuthReplySessionWith(t *testing.T, auth Authenticator) *Session {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Local = true // skip the TLS-before-AUTH gate; irrelevant to code mapping
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sc := config.ServerConfig{Hostname: "mx.example.com", Type: "submission"}
	sc.Auth.Enabled = true

	return &Session{
		ctx:           context.Background(),
		serverConfig:  &sc,
		globalConfig:  &cfg,
		Logger:        logger,
		remoteAddr:    "192.0.2.10", // bare IP, as NewSession stores it
		authenticator: auth,
	}
}

// authOnce runs one AUTH PLAIN exchange and returns the error the client sees.
func authOnce(t *testing.T, s *Session, username, password string) error {
	t.Helper()
	server, err := s.Auth(sasl.Plain)
	if err != nil {
		t.Fatalf("Session.Auth(PLAIN) setup failed: %v", err)
	}
	// PLAIN initial response: authzid \0 authcid \0 passwd (RFC 4616).
	ir := append([]byte{0}, append([]byte(username), append([]byte{0}, []byte(password)...)...)...)
	_, done, err := server.Next(ir)
	if !done {
		t.Fatal("PLAIN exchange should complete in one step")
	}
	return err
}

func requireSMTPCode(t *testing.T, err error, code int, enhanced smtp.EnhancedCode, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected a failure, got success", what)
	}
	var se *smtp.SMTPError
	if !errors.As(err, &se) {
		t.Fatalf("%s: expected *smtp.SMTPError, got %T: %v", what, err, err)
	}
	if se.Code != code || se.EnhancedCode != enhanced {
		t.Fatalf("%s: got %d %v, want %d %v", what, se.Code, se.EnhancedCode, code, enhanced)
	}
}

// An address the backend does not know is PERMANENT: no retry can make it
// appear, and a 4xx would have the client hammering a typo indefinitely.
func TestAuthReplyCode_UnknownUserIsPermanent(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer backend.Close()

	s := newAuthReplySession(t, backend.URL)
	err := authOnce(t, s, "nobody@example.com", "whatever")
	requireSMTPCode(t, err, 535, smtp.EnhancedCode{5, 7, 8}, "unknown user (backend 404)")
	if s.isAuthenticated {
		t.Fatal("session must not be marked authenticated")
	}
}

// A backend 403 (rcptd deny_smtp) is NOT the same as a 404: the account exists,
// it is only barred from submitting, and a deny can be lifted. A permanent
// reply would make clients discard a password that starts working again the
// moment the deny is removed - so a deny is temporary.
func TestAuthReplyCode_DeniedUserIsTemporary(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer backend.Close()

	s := newAuthReplySession(t, backend.URL)
	err := authOnce(t, s, "denied@example.com", "whatever")
	requireSMTPCode(t, err, 454, smtp.EnhancedCode{4, 7, 0}, "denied user (backend 403)")
}

// An account that exists but serves no hashes (200 with an empty list) is also
// temporary: it is in the table, so it is not the "no such account" case, and
// an operator can set a credential on it. This is the case most easily confused
// with a 404, since both arrive with zero hashes.
func TestAuthReplyCode_ExistingUserWithNoHashesIsTemporary(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(AuthResponse{
			PasswordHashes: []string{},
			AllowedFrom:    []string{"user@example.com"},
		})
	}))
	defer backend.Close()

	s := newAuthReplySession(t, backend.URL)
	err := authOnce(t, s, "user@example.com", "whatever")
	requireSMTPCode(t, err, 454, smtp.EnhancedCode{4, 7, 0}, "existing user, no hashes (200 empty)")
}

// A wrong password on an account that DOES exist stays temporary: the stored
// credential may still be valid (it could have just been rotated), so a 5xx
// would make clients discard a working password.
func TestAuthReplyCode_WrongPasswordIsTemporary(t *testing.T) {
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

	s := newAuthReplySession(t, backend.URL)
	authErr := authOnce(t, s, "user@example.com", "wrong")
	requireSMTPCode(t, authErr, 454, smtp.EnhancedCode{4, 7, 0}, "wrong password")
}

// A stored hash mizu cannot evaluate is an operator-side data problem, not a
// verdict on the credential - so it must not read as "your password is wrong".
func TestAuthReplyCode_UnusableHashIsTemporary(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(AuthResponse{
			PasswordHashes: []string{"{NOSUCHSCHEME}garbage"},
			AllowedFrom:    []string{"user@example.com"},
		})
	}))
	defer backend.Close()

	s := newAuthReplySession(t, backend.URL)
	err := authOnce(t, s, "user@example.com", "anything")
	requireSMTPCode(t, err, 454, smtp.EnhancedCode{4, 7, 0}, "unsupported hash scheme")
}

// Our own outage must never be reported as a credential problem.
func TestAuthReplyCode_BackendErrorIsTemporary(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer backend.Close()

	s := newAuthReplySession(t, backend.URL)
	err := authOnce(t, s, "user@example.com", "anything")
	requireSMTPCode(t, err, 454, smtp.EnhancedCode{4, 7, 0}, "backend 500")
}

// The happy path, so the tests above are not all passing for the wrong reason.
func TestAuthReplyCode_ValidCredentialsSucceed(t *testing.T) {
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

	s := newAuthReplySession(t, backend.URL)
	if authErr := authOnce(t, s, "user@example.com", "correct-horse"); authErr != nil {
		t.Fatalf("valid credentials should authenticate, got: %v", authErr)
	}
	if !s.isAuthenticated || s.authenticatedUser != "user@example.com" {
		t.Fatalf("session state not set: authenticated=%v user=%q", s.isAuthenticated, s.authenticatedUser)
	}
}

// The credentials-cache refetch branch: reached only when the auth cache is
// explicitly disabled (auth.cache.enabled=false - it is on by default), a user
// already has cached hashes, and the presented password stops matching them.
// AuthenticateWithIP refetches, and if the account has since disappeared that
// second verdict must be permanent too. This branch has its own copy of the
// empty-hashes check, so it needs its own test - it is easy to change one site
// and miss the other.
func TestAuthReplyCode_CachedCredsThenAccountRemovedIsPermanent(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-horse"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	var removed atomic.Bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if removed.Load() {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(AuthResponse{
			PasswordHashes: []string{string(hash)},
			AllowedFrom:    []string{"user@example.com"},
		})
	}))
	defer backend.Close()

	// nil auth cache => the credentials-cache branch is the live path.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auth := NewHTTPAuthenticator(backend.URL, "test-auth-token", logger, nil)

	// Populate the credentials cache with a real success.
	if err := authOnce(t, newAuthReplySessionWith(t, auth), "user@example.com", "correct-horse"); err != nil {
		t.Fatalf("setup: first auth should succeed, got: %v", err)
	}

	// Account removed. A password that no longer matches the cached hash forces
	// the refetch, which now comes back empty.
	removed.Store(true)
	err = authOnce(t, newAuthReplySessionWith(t, auth), "user@example.com", "some-other-pass")
	requireSMTPCode(t, err, 535, smtp.EnhancedCode{5, 7, 8}, "cached creds, account since removed")
}

// Same branch, but the refetch still finds the account: a wrong password must
// stay temporary here exactly as it does on the uncached path.
func TestAuthReplyCode_CachedCredsWrongPasswordStaysTemporary(t *testing.T) {
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

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auth := NewHTTPAuthenticator(backend.URL, "test-auth-token", logger, nil)

	if err := authOnce(t, newAuthReplySessionWith(t, auth), "user@example.com", "correct-horse"); err != nil {
		t.Fatalf("setup: first auth should succeed, got: %v", err)
	}
	err = authOnce(t, newAuthReplySessionWith(t, auth), "user@example.com", "wrong")
	requireSMTPCode(t, err, 454, smtp.EnhancedCode{4, 7, 0}, "cached creds, wrong password")
}

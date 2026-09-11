package smtp

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	"migadu/mizu/pkg/config"
)

// masterAuthenticator stands in for an rcptd that serves a master/token login:
// the login authenticates, but the address it acts as is the base address.
type masterAuthenticator struct {
	login    string
	identity string
	allowed  []string
}

func (m *masterAuthenticator) Authenticate(username, password string) (bool, error) {
	return username == m.login, nil
}

func (m *masterAuthenticator) CanSendAs(authenticatedUser, fromAddress string) bool {
	_, ok := m.ResolveSender(authenticatedUser, fromAddress)
	return ok
}

func (m *masterAuthenticator) SenderIdentity(authenticatedUser string) string {
	if strings.ToLower(m.login) != m.identity {
		return m.identity
	}
	return ""
}

func (m *masterAuthenticator) ResolveSender(authenticatedUser, fromAddress string) (string, bool) {
	from := extractEmail(fromAddress)
	if from == strings.ToLower(m.login) {
		from = m.identity
	}
	for _, a := range m.allowed {
		if a == from {
			return from, true
		}
	}
	return "", false
}

func masterSession(t *testing.T, auth Authenticator, login string) *Session {
	t.Helper()
	return &Session{
		serverConfig: &config.ServerConfig{
			Name: "test-submission",
			Type: "submission",
			Auth: config.ServerAuthConfig{Required: true},
		},
		// Local mode keeps MAIL FROM off SPF/MX lookups; the sender resolution
		// under test runs before either.
		globalConfig:      &config.Config{Local: true},
		Logger:            slog.New(slog.NewTextHandler(os.Stdout, nil)),
		remoteAddr:        "192.0.2.1:12345",
		ctx:               context.Background(),
		helo:              "client.example.com",
		commandState:      stateHelo,
		authenticator:     auth,
		isAuthenticated:   true,
		authenticatedUser: login,
		to:                []string{},
	}
}

// The end-to-end shape of master access: the client sends its own login string
// as the sender, and the envelope ends up carrying the base address.
func TestMail_MasterLoginRewritesEnvelopeSender(t *testing.T) {
	const login = "user@example.com@MASTER"
	const identity = "user@example.com"

	auth := &masterAuthenticator{login: login, identity: identity, allowed: []string{identity}}
	s := masterSession(t, auth, login)

	if err := s.Mail(context.Background(), login, nil); err != nil {
		t.Fatalf("MAIL FROM with a master login was rejected: %v", err)
	}
	if s.from != identity {
		t.Errorf("envelope sender = %q, want %q", s.from, identity)
	}
	if s.senderIdentity != identity {
		t.Errorf("senderIdentity = %q, want %q", s.senderIdentity, identity)
	}
	if s.senderDomain != "example.com" {
		// Without the rewrite this would be the master username, not a domain.
		t.Errorf("senderDomain = %q, want example.com", s.senderDomain)
	}

	// The From header rewrite that Data() performs, on the values the session
	// now holds.
	raw := "From: Support <" + login + ">\r\nTo: x@y.com\r\n\r\nbody\r\n"
	rewritten, ok := rewriteFromHeader(raw, s.authenticatedUser, s.senderIdentity)
	if !ok {
		t.Fatal("From header was not rewritten")
	}
	if !strings.Contains(rewritten, "From: Support <"+identity+">\r\n") {
		t.Errorf("unexpected From header:\n%q", rewritten)
	}
	if strings.Contains(rewritten, "MASTER") {
		t.Errorf("master suffix reached the message:\n%q", rewritten)
	}
}

// Sending as the base address directly needs no rewrite, and must leave the
// session marked as un-rewritten so Data() does not touch the headers.
func TestMail_MasterLoginSendingAsIdentityIsNotRewritten(t *testing.T) {
	const login = "user@example.com@MASTER"
	const identity = "user@example.com"

	auth := &masterAuthenticator{login: login, identity: identity, allowed: []string{identity}}
	s := masterSession(t, auth, login)

	if err := s.Mail(context.Background(), identity, nil); err != nil {
		t.Fatalf("MAIL FROM with the identity was rejected: %v", err)
	}
	if s.from != identity {
		t.Errorf("envelope sender = %q, want %q", s.from, identity)
	}
	// The identity is a property of the login, so it is recorded even though
	// this envelope needed no rewrite — a From header still carrying the login
	// string must be rewritten either way.
	if s.senderIdentity != identity {
		t.Errorf("senderIdentity = %q, want %q", s.senderIdentity, identity)
	}
}

// A master credential is not a licence to send as anyone.
func TestMail_MasterLoginCannotSendAsThirdParty(t *testing.T) {
	const login = "user@example.com@MASTER"

	auth := &masterAuthenticator{login: login, identity: "user@example.com", allowed: []string{"user@example.com"}}
	s := masterSession(t, auth, login)

	if err := s.Mail(context.Background(), "victim@example.com", nil); err == nil {
		t.Fatal("expected MAIL FROM as a third party to be rejected")
	}
	if s.from != "" {
		t.Errorf("rejected sender must not be recorded, got %q", s.from)
	}
}

// A plain login is untouched: no identity, no rewrite, same envelope as before.
func TestMail_PlainLoginUnchanged(t *testing.T) {
	const login = "user@example.com"

	auth := &masterAuthenticator{login: login, identity: login, allowed: []string{login}}
	s := masterSession(t, auth, login)

	if err := s.Mail(context.Background(), login, nil); err != nil {
		t.Fatalf("MAIL FROM was rejected: %v", err)
	}
	if s.from != login {
		t.Errorf("envelope sender = %q, want %q", s.from, login)
	}
	if s.senderIdentity != "" {
		t.Errorf("senderIdentity = %q, want empty for a plain login", s.senderIdentity)
	}
}

// Reset must clear the rewrite state, or a second message on the same
// connection could inherit an earlier message's identity.
func TestReset_ClearsSenderIdentity(t *testing.T) {
	const login = "user@example.com@MASTER"
	const identity = "user@example.com"

	auth := &masterAuthenticator{login: login, identity: identity, allowed: []string{identity}}
	s := masterSession(t, auth, login)
	if err := s.Mail(context.Background(), login, nil); err != nil {
		t.Fatalf("MAIL FROM was rejected: %v", err)
	}

	s.Reset()
	if s.senderIdentity != "" {
		t.Errorf("senderIdentity = %q after Reset, want empty", s.senderIdentity)
	}
}

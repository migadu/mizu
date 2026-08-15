package smtp

// The permanent/temporary split on AUTH and on the envelope-sender gate.
//
// The rule these tests encode is one rule in two places: a refusal may be
// PERMANENT only when the credential (or the sender) was actually judged. When
// the backend could not be reached nothing was judged, and a 5xx answer there
// tells a mail client its stored password is wrong.
//
// They assert on the SMTP error VALUE rather than on the (bool, error) contract
// deliberately. go-smtp renders any error that is not a *smtp.SMTPError with its
// own AUTH default of 454 4.7.0 (writeError type-asserts, it does not use
// errors.As), so a classification can be perfectly correct in Go and still reach
// the wire as the wrong reply class — which is exactly what happened here.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"migadu/mizu/pkg/config"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// authSessionFor builds the smallest Session that can serve AUTH: local mode
// skips the TLS precondition, and conn/netConn stay nil.
func authSessionFor(a Authenticator) *Session {
	return &Session{
		serverConfig: &config.ServerConfig{
			Name: "submission-test",
			Type: "submission",
			Auth: config.ServerAuthConfig{Enabled: true, Required: true},
		},
		globalConfig:  &config.Config{Local: true},
		authenticator: a,
		ctx:           context.Background(),
		remoteAddr:    "203.0.113.7:51234",
		Logger:        quietLogger(),
	}
}

// stubAuth returns a fixed verdict. (false, nil) and (false, definitive error)
// are judged rejections; an error wrapping ErrAuthUnavailable is "no verdict".
type stubAuth struct {
	ok  bool
	err error
}

func (s stubAuth) Authenticate(username, password string) (bool, error) { return s.ok, s.err }
func (s stubAuth) CanSendAs(user, from string) bool                     { return true }

// driveAuth replays go-smtp's handleAuth loop: feed the initial response, then
// answer each challenge, stopping at the first error or at done.
func driveAuth(t *testing.T, srv sasl.Server, ir []byte, responses ...[]byte) error {
	t.Helper()
	resp := ir
	for i := 0; ; i++ {
		_, done, err := srv.Next(resp)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if i >= len(responses) {
			t.Fatalf("SASL server issued more challenges than the test had responses (%d)", len(responses))
		}
		resp = responses[i]
	}
}

func wantSMTPCode(t *testing.T, err error, code int, enhanced smtp.EnhancedCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a refusal with %d %v, got success", code, enhanced)
	}
	smtpErr, ok := err.(*smtp.SMTPError)
	if !ok {
		t.Fatalf("want *smtp.SMTPError (any other error is rendered as 454 4.7.0), got %T: %v", err, err)
	}
	if smtpErr.Code != code {
		t.Errorf("code = %d, want %d (message %q)", smtpErr.Code, code, smtpErr.Message)
	}
	if smtpErr.EnhancedCode != enhanced {
		t.Errorf("enhanced code = %v, want %v", smtpErr.EnhancedCode, enhanced)
	}
}

// TestAuthReplyPermanence is the regression test for the reported defect: a
// rejected credential answered 454 (temporary), so clients retried a password
// that could never work.
func TestAuthReplyPermanence(t *testing.T) {
	cases := []struct {
		name     string
		stub     stubAuth
		code     int
		enhanced smtp.EnhancedCode
	}{
		{
			// HTTPAuthenticator's shape for a bad password and for an unknown
			// user: (false, a descriptive but definitive error).
			name:     "wrong password is permanent",
			stub:     stubAuth{ok: false, err: errors.New("password verification failed")},
			code:     535,
			enhanced: smtp.EnhancedCode{5, 7, 8},
		},
		{
			name:     "unknown user is permanent",
			stub:     stubAuth{ok: false, err: errors.New("no such user")},
			code:     535,
			enhanced: smtp.EnhancedCode{5, 7, 8},
		},
		{
			// A 403 from the backend is a deliberate deny (deny_smtp): the
			// backend answered, so it is a verdict and stays permanent.
			name:     "denied submission is permanent",
			stub:     stubAuth{ok: false, err: nil},
			code:     535,
			enhanced: smtp.EnhancedCode{5, 7, 8},
		},
		{
			name:     "unreachable backend is temporary",
			stub:     stubAuth{ok: false, err: fmt.Errorf("authentication service unavailable: %w", ErrAuthUnavailable)},
			code:     454,
			enhanced: smtp.EnhancedCode{4, 7, 0},
		},
		{
			name:     "unexpected backend status is temporary",
			stub:     stubAuth{ok: false, err: fmt.Errorf("authentication service error: 502: %w", ErrAuthUnavailable)},
			code:     454,
			enhanced: smtp.EnhancedCode{4, 7, 0},
		},
	}

	for _, tc := range cases {
		for _, mech := range []string{sasl.Plain, sasl.Login} {
			t.Run(tc.name+"/"+mech, func(t *testing.T) {
				sess := authSessionFor(tc.stub)
				srv, err := sess.Auth(mech)
				if err != nil {
					t.Fatalf("Auth(%s): %v", mech, err)
				}

				if mech == sasl.Plain {
					err = driveAuth(t, srv, []byte("\x00user@example.com\x00pw"))
				} else {
					err = driveAuth(t, srv, nil, []byte("user@example.com"), []byte("pw"))
				}
				wantSMTPCode(t, err, tc.code, tc.enhanced)

				if sess.isAuthenticated {
					t.Error("session marked authenticated despite a refusal")
				}
			})
		}
	}
}

// TestAuthSuccessStillSucceeds keeps the happy path honest — every case above
// asserts a refusal, so a change that refused everything would pass them all.
func TestAuthSuccessStillSucceeds(t *testing.T) {
	sess := authSessionFor(stubAuth{ok: true, err: nil})
	srv, err := sess.Auth(sasl.Plain)
	if err != nil {
		t.Fatalf("Auth: %v", err)
	}
	if err := driveAuth(t, srv, []byte("\x00alice@example.com\x00pw")); err != nil {
		t.Fatalf("valid credentials refused: %v", err)
	}
	if !sess.isAuthenticated || sess.authenticatedUser != "alice@example.com" {
		t.Errorf("session not authenticated as alice@example.com (auth=%v user=%q)",
			sess.isAuthenticated, sess.authenticatedUser)
	}
}

// TestBackendOutageDoesNotSpendAttemptBudget: an outage is not evidence of
// guessing. Counting it would spend a legitimate user's budget and keep blocking
// them for the whole block duration after the backend recovered.
func TestBackendOutageDoesNotSpendAttemptBudget(t *testing.T) {
	newLimiter := func() *AuthRateLimiter {
		rl, err := NewAuthRateLimiter(config.ServerAuthRateLimitConfig{
			Enabled:                  true,
			MaxAttemptsPerIPUsername: 2,
			IPUsernameBlockDuration:  "15m",
			IPUsernameWindowDuration: "10m",
			MaxAttemptsPerIP:         1000,
			IPWindowDuration:         "30m",
		}, quietLogger(), nil)
		if err != nil {
			t.Fatalf("NewAuthRateLimiter: %v", err)
		}
		t.Cleanup(func() { rl.Shutdown() })
		return rl
	}

	attempt := func(t *testing.T, rl *AuthRateLimiter, stub stubAuth) {
		t.Helper()
		sess := authSessionFor(stub)
		sess.authRateLimiter = rl
		srv, err := sess.Auth(sasl.Plain)
		if err != nil {
			t.Fatalf("Auth: %v", err)
		}
		if err := driveAuth(t, srv, []byte("\x00user@example.com\x00pw")); err == nil {
			t.Fatal("expected a refusal")
		}
	}

	t.Run("outage does not block", func(t *testing.T) {
		rl := newLimiter()
		outage := stubAuth{ok: false, err: fmt.Errorf("unavailable: %w", ErrAuthUnavailable)}
		for i := 0; i < 5; i++ {
			attempt(t, rl, outage)
		}
		if err := rl.CanAttemptAuth(context.Background(), "203.0.113.7", "user@example.com"); err != nil {
			t.Errorf("blocked after 5 attempts that never reached a verdict: %v", err)
		}
	})

	t.Run("real rejections still block", func(t *testing.T) {
		rl := newLimiter()
		rejected := stubAuth{ok: false, err: errors.New("password verification failed")}
		for i := 0; i < 2; i++ {
			attempt(t, rl, rejected)
		}
		if err := rl.CanAttemptAuth(context.Background(), "203.0.113.7", "user@example.com"); err == nil {
			t.Error("not blocked after 2 judged rejections; the damper stopped damping")
		}
	})
}

// TestAuthRateLimitedIsTemporary is the counterweight to the 535: a block
// expires, so it must stay 4xx. A user sharing a NATed egress with a guesser
// must not be told their password is permanently wrong.
func TestAuthRateLimitedIsTemporary(t *testing.T) {
	rl, err := NewAuthRateLimiter(config.ServerAuthRateLimitConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 1,
		IPUsernameBlockDuration:  "15m",
		IPUsernameWindowDuration: "10m",
		MaxAttemptsPerIP:         1000,
		IPWindowDuration:         "30m",
	}, quietLogger(), nil)
	if err != nil {
		t.Fatalf("NewAuthRateLimiter: %v", err)
	}
	defer rl.Shutdown()

	rl.RecordAuthAttempt(context.Background(), "203.0.113.7", "victim@example.com", false)
	if err := rl.CanAttemptAuth(context.Background(), "203.0.113.7", "victim@example.com"); err == nil {
		t.Fatal("precondition failed: limiter should be blocking")
	}

	sess := authSessionFor(stubAuth{ok: true, err: nil}) // would SUCCEED if consulted
	sess.authRateLimiter = rl
	srv, err := sess.Auth(sasl.Plain)
	if err != nil {
		t.Fatalf("Auth: %v", err)
	}
	wantSMTPCode(t, driveAuth(t, srv, []byte("\x00victim@example.com\x00pw")),
		454, smtp.EnhancedCode{4, 7, 0})
}

// ---------------------------------------------------------------------------
// LOGIN initial response
// ---------------------------------------------------------------------------

// TestLoginServerInitialResponse pins RFC 4954 §4's initial response for LOGIN.
// go-sasl's LOGIN client always sends the username that way, and it rejects any
// challenge that is not literally "Password:", so discarding the initial
// response made AUTH LOGIN unusable for such clients.
func TestLoginServerInitialResponse(t *testing.T) {
	cases := []struct {
		name         string
		ir           []byte
		responses    [][]byte
		wantPrompts  []string
		wantUsername string
		wantPassword string
	}{
		{
			name:         "no initial response uses the three-step exchange",
			ir:           nil,
			responses:    [][]byte{[]byte("alice@example.com"), []byte("s3cret")},
			wantPrompts:  []string{"Username:", "Password:"},
			wantUsername: "alice@example.com",
			wantPassword: "s3cret",
		},
		{
			name:         "initial response is taken as the username",
			ir:           []byte("alice@example.com"),
			responses:    [][]byte{[]byte("s3cret")},
			wantPrompts:  []string{"Password:"},
			wantUsername: "alice@example.com",
			wantPassword: "s3cret",
		},
		{
			// go-smtp decodes the RFC 4954 "=" form to a non-nil empty slice;
			// nil means the argument was absent. Conflating them would send a
			// client that asked for the two-step exchange down the three-step one.
			name:         "empty initial response is honoured, not treated as absent",
			ir:           []byte{},
			responses:    [][]byte{[]byte("s3cret")},
			wantPrompts:  []string{"Password:"},
			wantUsername: "",
			wantPassword: "s3cret",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotUser, gotPass string
			var called int
			srv := NewLoginServer(func(username, password string) error {
				called++
				gotUser, gotPass = username, password
				return nil
			})

			var prompts []string
			resp := tc.ir
			for i := 0; ; i++ {
				challenge, done, err := srv.Next(resp)
				if err != nil {
					t.Fatalf("Next: %v", err)
				}
				if done {
					break
				}
				prompts = append(prompts, string(challenge))
				if i >= len(tc.responses) {
					t.Fatalf("server issued challenge %q with no response left", challenge)
				}
				resp = tc.responses[i]
			}

			if len(prompts) != len(tc.wantPrompts) {
				t.Fatalf("prompts = %v, want %v", prompts, tc.wantPrompts)
			}
			for i := range prompts {
				if prompts[i] != tc.wantPrompts[i] {
					t.Errorf("prompt %d = %q, want %q", i, prompts[i], tc.wantPrompts[i])
				}
			}
			if called != 1 {
				t.Errorf("authenticator called %d times, want 1", called)
			}
			if gotUser != tc.wantUsername || gotPass != tc.wantPassword {
				t.Errorf("authenticated (%q, %q), want (%q, %q)",
					gotUser, gotPass, tc.wantUsername, tc.wantPassword)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The envelope-sender gate
// ---------------------------------------------------------------------------

// TestExtractEmailIsAnchored pins that an authorization entry can never be
// reduced to an interior substring of itself.
//
// allowed_from is served whole by the backend and derives from operator- and
// customer-supplied strings, so an entry that merely CONTAINS a bracketed
// address must authorize itself and nothing else. A genuine display form — the
// shape rcptd really serves, pinned by TestCheckAllowedFrom — still unwraps.
func TestExtractEmailIsAnchored(t *testing.T) {
	cases := []struct {
		name  string
		entry string
		want  string
	}{
		{"bare address unchanged", "alice@example.com", "alice@example.com"},
		{"display form unwraps", "Support <help@example.com>", "help@example.com"},
		{"display form with odd name unwraps", "/dev/null alias <alias@aaaa.tech>", "alias@aaaa.tech"},
		{"case and space normalised", "  Alice <Alice@Example.COM>  ", "alice@example.com"},
		{
			// The one that matters: a bracketed address in the MIDDLE of an entry
			// is not the entry's address. Unanchored, this returned
			// "other@elsewhere.example" and granted send rights for a domain the
			// entry's owner does not control.
			name:  "interior bracketed address is not extracted",
			entry: "someone+<other@elsewhere.example>@theirdomain.example",
			want:  "someone+<other@elsewhere.example>@theirdomain.example",
		},
		{
			name:  "trailing bracket wins over an earlier one",
			entry: "<first@a.example> Name <real@b.example>",
			want:  "real@b.example",
		},
		{"unterminated bracket is left alone", "weird<addr@example.com", "weird<addr@example.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractEmail(tc.entry); got != tc.want {
				t.Errorf("extractEmail(%q) = %q, want %q", tc.entry, got, tc.want)
			}
		})
	}
}

// TestCanSendAsJudgesTheForwardedAddress: the gate must decide on the exact
// envelope sender the session will forward. Unwrapping the query side made it
// judge a substring while MAIL FROM, the sender-domain accounting and the
// X-Mail-From header all used the whole string.
func TestCanSendAsJudgesTheForwardedAddress(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(AuthResponse{
			PasswordHashes: []string{"$2a$10$notused"},
			AllowedFrom:    []string{"alice@attacker.example"},
		})
	}))
	defer server.Close()

	auth := NewHTTPAuthenticator(server.URL+"?email=$email", "tok", quietLogger(), nil)
	auth.cacheCredentials("alice@attacker.example", []string{"$2a$10$notused"}, []string{"alice@attacker.example"})

	if !auth.CanSendAs("alice@attacker.example", "alice@attacker.example") {
		t.Error("the permitted sender was refused")
	}

	// A reverse-path whose quoted local part carries an address for another
	// domain must not be authorized by the address it contains: the string
	// forwarded downstream is the whole thing, whose domain is not ours to use.
	//
	// The last case is the one that pins the query side specifically. MAIL FROM
	// carries an addr-spec, never a display form, so an envelope sender that
	// looks like one must be compared whole — unwrapping it here would authorize
	// the inner address while the sender-domain accounting and the X-Mail-From
	// header we forward continue to use the entire string.
	for _, from := range []string{
		"<alice@attacker.example>@victim.example",
		"\"alice@attacker.example\"@victim.example",
		"Display Name <alice@attacker.example>",
	} {
		if auth.CanSendAs("alice@attacker.example", from) {
			t.Errorf("MAIL FROM %q was authorized by an address extracted out of it; "+
				"the gate must judge the string it forwards", from)
		}
	}
}

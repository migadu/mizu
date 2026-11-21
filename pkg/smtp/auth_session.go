package smtp

import (
	"errors"
	"fmt"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// AuthMechanisms returns the list of supported SMTP AUTH mechanisms
// Implements smtp.AuthSession interface
func (s *Session) AuthMechanisms() []string {
	// Only offer AUTH if enabled (or required, which implies enabled)
	if !s.serverConfig.Auth.Enabled && !s.serverConfig.Auth.Required {
		return nil
	}

	// Only offer AUTH if authenticator is configured
	if s.authenticator == nil {
		return nil
	}

	// Support PLAIN and LOGIN mechanisms
	mechanisms := []string{sasl.Plain, sasl.Login}

	// Don't offer AUTH over unencrypted connection (unless in local mode)
	if !s.globalConfig.Local && s.tlsState == nil {
		s.Logger.Debug("Not offering AUTH - TLS not active")
		return nil
	}

	return mechanisms
}

// Auth handles SMTP AUTH command
// Implements smtp.AuthSession interface
func (s *Session) Auth(mech string) (sasl.Server, error) {
	// Verify authenticator is configured
	if s.authenticator == nil {
		s.Logger.Warn("AUTH attempted but no authenticator configured")
		return nil, &smtp.SMTPError{
			Code:         502,
			EnhancedCode: smtp.EnhancedCode{5, 7, 0},
			Message:      "authentication not supported",
		}
	}

	// Update and check TLS state (skip in local mode)
	s.updateTLSState()
	if !s.globalConfig.Local && s.tlsState == nil {
		s.Logger.Warn("AUTH attempted without TLS", "remote_addr", s.remoteAddr, "remote_host", s.ptr)
		return nil, &smtp.SMTPError{
			Code:         538,
			EnhancedCode: smtp.EnhancedCode{5, 7, 11},
			Message:      "encryption required for authentication",
		}
	}

	// AUTH is not permitted during a mail transaction (RFC 4954 section 4).
	// The sender is authorised against allowed_from inside Mail; a login
	// arriving after MAIL FROM would attach an identity to an envelope sender
	// it was never checked against.
	if s.commandState >= stateMail {
		s.Logger.Warn("AUTH attempted during mail transaction", "remote_addr", s.remoteAddr)
		return nil, &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "AUTH not permitted during a mail transaction",
		}
	}

	// Check if already authenticated
	if s.isAuthenticated {
		s.Logger.Warn("Already authenticated", "user", s.authenticatedUser)
		return nil, &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "already authenticated",
		}
	}

	// Create authenticator function that captures session state
	authenticatorFunc := func(identity, username, password string) error {
		// For PLAIN, username is in the 'username' parameter
		// For LOGIN, username comes from the handshake
		user := username
		if user == "" {
			user = identity
		}

		s.Logger.Debug("Authentication attempt", "username", user, "mechanism", mech)

		// s.remoteAddr is already a bare IP: NewSession strips the port. Do not
		// cut at a colon here - on IPv6 that removes the last hextet, which
		// leaves the limiter an unparseable key (no /64 bucketing, no subnet
		// tier) and hands the auth backend a mangled $ip.
		remoteIP := s.remoteAddr

		// Rate-limiter work is bounded by the session budget: s.ctx carries only
		// cancellation now that the deadline lives in sessionDeadline.
		authCtx, cancelAuthCtx := s.commandContext(s.ctx)
		defer cancelAuthCtx()

		// Check auth rate limit before attempting authentication
		if s.authRateLimiter != nil {
			if err := s.authRateLimiter.CanAttemptAuth(authCtx, remoteIP, user); err != nil {
				s.Logger.Warn("Authentication blocked by rate limiter",
					"username", user,
					"ip", remoteIP,
					"error", err)
				return fmt.Errorf("authentication rate limit exceeded")
			}

			// Apply progressive delay if configured
			delay := s.authRateLimiter.GetAuthenticationDelay(remoteIP)
			if delay > 0 {
				s.Logger.Debug("Applying progressive authentication delay",
					"username", user,
					"ip", remoteIP,
					"delay", delay)
				select {
				case <-authCtx.Done():
					return fmt.Errorf("authentication cancelled")
				case <-time.After(delay):
					// Delay complete, continue
				}
			}
		}

		// Try to use AuthenticateWithIP if available, otherwise fallback to Authenticate
		var authenticated bool
		var err error
		if httpAuth, ok := s.authenticator.(*HTTPAuthenticator); ok {
			authenticated, err = httpAuth.AuthenticateWithIP(user, password, remoteIP)
		} else {
			authenticated, err = s.authenticator.Authenticate(user, password)
		}

		// Only a genuine verdict feeds the brute-force damper. A transient
		// backend error is neither a success nor a failed guess; counting it
		// would spend a legitimate user's attempt budget on OUR outage.
		//
		// A wrong password IS a verdict, though it arrives as an error (so the
		// reply stays a temporary 454): it carries ErrCredentialRejected.
		// Without this branch, guessing against an existing account - the only
		// kind worth guessing against - was never counted at all.
		if s.authRateLimiter != nil {
			switch {
			case err == nil:
				s.authRateLimiter.RecordAuthAttempt(authCtx, remoteIP, user, authenticated)
			case errors.Is(err, ErrCredentialRejected):
				s.authRateLimiter.RecordAuthAttempt(authCtx, remoteIP, user, false)
			}
		}

		// ERROR IS CHECKED FIRST, and the order is the safety property. Per the
		// Authenticator contract (see server.go), (false, nil) means the account
		// is absent and every other rejection carries an error; judging
		// `authenticated` first would turn a backend blip into a PERMANENT 535
		// that makes the client discard a valid stored password. Any error =>
		// temporary 454. That covers a wrong password, an unusable stored hash,
		// and an account denied submission: none of them prove the account is
		// gone, and all can start working again with no change by the client.
		if err != nil {
			s.Logger.Error("Authentication error", "username", user, "error", err)
			return ErrAuthTemporaryFailure
		}

		if !authenticated {
			// Permanent: the backend has no such account. RFC 4954 §6's
			// 535 5.7.8 — a 4xx here tells the client to retry an address that
			// can never work, and Outlook's setup wizard reads 454 as "server
			// unavailable" and aborts account creation instead of telling the
			// user their address is wrong.
			s.Logger.Warn("Authentication failed: no such account", "username", user)
			return ErrAuthCredentialsInvalid
		}

		// Mark session as authenticated
		s.isAuthenticated = true
		s.authenticatedUser = user
		s.Logger.Info("User authenticated successfully", "username", user, "mechanism", mech)

		return nil
	}

	// Return appropriate SASL server based on mechanism
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(authenticatorFunc), nil
	case sasl.Login:
		// Create a wrapper for LOGIN that matches the expected signature
		loginAuth := func(username, password string) error {
			return authenticatorFunc("", username, password)
		}
		return NewLoginServer(loginAuth), nil
	default:
		s.Logger.Warn("Unsupported AUTH mechanism", "mechanism", mech)
		return nil, &smtp.SMTPError{
			Code:         504,
			EnhancedCode: smtp.EnhancedCode{5, 5, 4},
			Message:      fmt.Sprintf("unsupported authentication mechanism: %s", mech),
		}
	}
}

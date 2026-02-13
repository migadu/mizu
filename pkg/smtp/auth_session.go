package smtp

import (
	"fmt"
	"strings"
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

		// Extract IP from remoteAddr (format: "ip:port")
		remoteIP := s.remoteAddr
		if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
			remoteIP = remoteIP[:idx]
		}

		// Check auth rate limit before attempting authentication
		if s.authRateLimiter != nil {
			if err := s.authRateLimiter.CanAttemptAuth(s.ctx, remoteIP, user); err != nil {
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
				case <-s.ctx.Done():
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

		// Record auth attempt result in rate limiter
		if s.authRateLimiter != nil {
			s.authRateLimiter.RecordAuthAttempt(s.ctx, remoteIP, user, authenticated && err == nil)
		}

		if err != nil {
			s.Logger.Error("Authentication error", "username", user, "error", err)
			// Return a temporary failure error that SASL can understand
			// The SASL library will convert this to appropriate SMTP response
			return &smtp.SMTPError{
				Code:         454,
				EnhancedCode: smtp.EnhancedCode{4, 7, 0},
				Message:      "temporary authentication failure: please try again later",
			}
		}

		if !authenticated {
			s.Logger.Warn("Authentication failed", "username", user)
			return fmt.Errorf("invalid credentials")
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

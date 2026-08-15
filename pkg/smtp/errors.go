package smtp

import (
	"errors"

	"github.com/emersion/go-smtp"
)

// Common SMTP server errors
var (
	// Session errors
	ErrSessionTimeout      = errors.New("session timeout")
	ErrInternalServerError = errors.New("internal server error")
	ErrServerUnavailable   = errors.New("server temporarily unavailable")
	ErrNoReverseDNS        = errors.New("no reverse DNS record")

	// TLS errors. These are structured SMTPErrors so clients receive the
	// RFC 3207 §4 mandated "530 5.7.0 Must issue a STARTTLS command first"
	// response rather than go-smtp's generic default reply.
	ErrTLSRequired = &smtp.SMTPError{
		Code:         530,
		EnhancedCode: smtp.EnhancedCode{5, 7, 0},
		Message:      "Must issue a STARTTLS command first",
	}
	ErrTLSRequiredStartTLS = &smtp.SMTPError{
		Code:         530,
		EnhancedCode: smtp.EnhancedCode{5, 7, 0},
		Message:      "Must issue a STARTTLS command first",
	}

	// ErrAuthUnavailable marks an authentication outcome as NO VERDICT: the
	// backend could not be reached, answered a status we cannot interpret, or
	// returned a body we could not read, so the credential was never checked.
	//
	// It exists because (false, err) alone cannot say which happened. A wrong
	// password and an unreachable backend both return it, and only one of them
	// may be reported to the client as permanent. Wrap this into the transient
	// returns and test with errors.Is; a 404 (unknown user) and a 403 (denied
	// submission) are verdicts and must NOT carry it.
	ErrAuthUnavailable = errors.New("authentication backend unavailable")

	// AUTH replies. These are structured SMTPErrors for the same reason the TLS
	// ones are, and for a sharper one: go-smtp answers ANY error returned by a
	// SASL server with its own AUTH default of 454 4.7.0, so an unstructured
	// error does not merely lose its wording — it silently becomes TEMPORARY,
	// and the client retries a password that can never work until the server
	// closes the connection. Return them UNWRAPPED (go-smtp type-asserts rather
	// than using errors.As) and spell the enhanced code out (an unset one is
	// rewritten to X.0.0, so 535 alone emits "535 5.0.0").

	// ErrAuthCredentialsInvalid is the one PERMANENT auth refusal: the
	// credential was checked and rejected. RFC 4954 §6's 535 5.7.8. It says
	// nothing about which half was wrong — an unknown user, a denied mailbox and
	// a bad password are deliberately indistinguishable.
	ErrAuthCredentialsInvalid = &smtp.SMTPError{
		Code:         535,
		EnhancedCode: smtp.EnhancedCode{5, 7, 8},
		Message:      "Authentication credentials invalid",
	}
	// ErrAuthTemporaryFailure is the backend's fault, not the caller's: nothing
	// was judged, so a stored password must survive our outage.
	ErrAuthTemporaryFailure = &smtp.SMTPError{
		Code:         454,
		EnhancedCode: smtp.EnhancedCode{4, 7, 0},
		Message:      "temporary authentication failure: please try again later",
	}
	// ErrAuthRateLimited is the brute-force damper refusing to spend an attempt.
	// Temporary by construction — the block expires — and it must stay 4xx: a
	// legitimate user sharing a NATed egress with a guesser must not be told
	// their password is permanently wrong.
	ErrAuthRateLimited = &smtp.SMTPError{
		Code:         454,
		EnhancedCode: smtp.EnhancedCode{4, 7, 0},
		Message:      "too many authentication attempts, try again later",
	}
	// ErrAuthCancelled is the session going away mid-attempt. Nothing judged.
	ErrAuthCancelled = &smtp.SMTPError{
		Code:         454,
		EnhancedCode: smtp.EnhancedCode{4, 7, 0},
		Message:      "authentication cancelled",
	}

	// Message errors
	ErrMessageTooBig = errors.New("message too big")

	// Context errors
	ErrContextCancelled = errors.New("context cancelled")
	ErrContextTimeout   = errors.New("context deadline exceeded")
)

// Common error messages for logging (not returned to clients)
const (
	LogMsgFailedSetDeadline       = "Failed to set connection deadline"
	LogMsgDomainListNotReady      = "domain list not ready"
	LogMsgSessionDeadlineExceeded = "Session deadline exceeded"
)

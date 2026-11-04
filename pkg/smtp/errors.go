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

	// ErrNonASCIIAddress: an envelope address with a byte outside ASCII.
	// SMTPUTF8 is not advertised (applyEhloCompat in cmd/mizu-server) and
	// nothing downstream can deliver an internationalised address, but the
	// go-smtp parser accepts raw UTF-8 with or without the parameter, so the
	// session has to refuse it. 553 5.6.7 is the reply RFC 6531 §3.7.1
	// prescribes for an address that needs SMTPUTF8 when it is not in use.
	ErrNonASCIIAddress = &smtp.SMTPError{
		Code:         553,
		EnhancedCode: smtp.EnhancedCode{5, 6, 7},
		Message:      "non-ASCII addresses not permitted: SMTPUTF8 not supported",
	}

	// ErrInvalidRecipient: a recipient mailqueuer's ingest would refuse
	// (`user@gmail`, 2026-10-24). The go-smtp parser is grammar-only and
	// strips the quotes from a quoted local part, so `"a@b"@example.com` and
	// `"john doe"@example.com` reach the session as unquoted strings. Before
	// this they were accepted and failed at delivery, where mailqueuer's 422
	// became a 451 the client retried for days. Returned at RCPT TO
	// (validRecipient) and, as a backstop, for a 422 at delivery. 553 5.1.3 is
	// RFC 3463's "bad destination mailbox address syntax".
	ErrInvalidRecipient = &smtp.SMTPError{
		Code:         553,
		EnhancedCode: smtp.EnhancedCode{5, 1, 3},
		Message:      "invalid recipient address",
	}

	// ErrRecipientAddressLiteral: a recipient whose domain is an address
	// literal (`user@[192.0.2.1]`, `user@[IPv6:2001:db8::1]`). A literal never
	// names a hosted domain, so both families are refused alike. The syntax
	// is valid, so this is RFC 3463's 5.1.2 "bad destination system address",
	// not the 5.1.3 syntax code.
	ErrRecipientAddressLiteral = &smtp.SMTPError{
		Code:         553,
		EnhancedCode: smtp.EnhancedCode{5, 1, 2},
		Message:      "address literals not accepted",
	}

	// Authentication errors. Structured SMTPErrors so the auth-failure code is
	// correct per RFC 4954 §6, which Outlook's setup wizard relies on: a
	// permanent 535 is a password prompt, a temporary 454 is read as "server
	// down" and aborts account creation.
	//
	// ErrAuthCredentialsInvalid: the auth backend has no such account (404) —
	// PERMANENT, because no retry makes an absent account appear. This is the
	// ONLY permanent auth failure. An account that exists but cannot be
	// authenticated right now — wrong password, no usable hash, denied
	// submission — gets the 454 below instead, since all of those can change
	// without the client altering anything.
	//
	// Note this is distinguishable from the 454 below, which an existing
	// account gets when its password is wrong, so the pair is a mailbox
	// enumeration oracle: one AUTH per address reveals which ones exist. That
	// is an accepted trade-off — a client that cannot tell "no such address"
	// from "server down" retries a hopeless address forever. The auth rate
	// limiter is what bounds the probing, since these attempts are now recorded
	// (see the RecordAuthAttempt gate in auth_session.go).
	ErrAuthCredentialsInvalid = &smtp.SMTPError{
		Code:         535,
		EnhancedCode: smtp.EnhancedCode{5, 7, 8},
		Message:      "Authentication credentials invalid",
	}
	// ErrAuthTemporaryFailure: everything that is not a missing account — a
	// wrong password, an unusable stored hash, an account denied submission, or
	// a backend that was unreachable/5xx/misconfigured. TEMPORARY, so a stored
	// password survives our outage (or a lifted deny) instead of being discarded
	// by the client.
	ErrAuthTemporaryFailure = &smtp.SMTPError{
		Code:         454,
		EnhancedCode: smtp.EnhancedCode{4, 7, 0},
		Message:      "temporary authentication failure: please try again later",
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

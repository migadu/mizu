package tls

import "errors"

var (
	// ErrMissingServerName is returned when a TLS handshake is attempted without SNI
	// and no default domain is configured.
	ErrMissingServerName = errors.New("tls: missing server name (SNI) and no default domain configured")

	// ErrHostNotAllowed is returned when a certificate is requested for a domain
	// that is not in the configured whitelist.
	ErrHostNotAllowed = errors.New("tls: host not allowed")

	// ErrCertificateUnavailable is returned when a certificate cannot be retrieved
	// due to transient errors (S3 down, ACME rate limits, network issues).
	// This allows the server to continue serving cached certificates for other domains.
	ErrCertificateUnavailable = errors.New("tls: certificate unavailable")
)

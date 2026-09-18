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

	// ErrNotLeader is returned for any ACME request attempted on a node that is
	// not the cluster leader. Such a node waits for the leader's certificate to
	// appear in the shared cache instead of ordering its own.
	ErrNotLeader = errors.New("tls: not cluster leader - ACME requests are made by the leader only")

	// ErrStorageUnavailable is returned when the certificate store could not be
	// consulted at all. It must never be reported as autocert.ErrCacheMiss:
	// autocert reads a miss as proof that no certificate exists and orders a new
	// one, so a miss during an S3 outage spends the duplicate-certificate limit
	// on certificates that are sitting in the bucket.
	ErrStorageUnavailable = errors.New("tls: certificate storage unavailable")

	// errInstanceRetired is returned for any ACME request from an autocert
	// instance that has been replaced (see autocertInstance).
	errInstanceRetired = errors.New("tls: autocert instance retired")
)

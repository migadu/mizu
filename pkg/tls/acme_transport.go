package tls

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
)

// maxACMEErrorBody bounds how much of an ACME error response is logged. Problem
// documents (RFC 7807) are a few hundred bytes.
const maxACMEErrorBody = 4096

// acmeTransport is the HTTP transport handed to autocert's ACME client.
//
// It is the cluster's leader gate. autocert has no hook to stop it ordering a
// certificate: a renewal runs the whole ACME order first and only then writes
// the result to the cache, so gating cache writes alone lets a non-leader obtain
// a certificate, fail to store it, and retry every 30-60 minutes — which burns
// Let's Encrypt's duplicate-certificate limit for every node, leader included.
// Refusing the requests themselves means a non-leader cannot reach the CA.
//
// It also logs every ACME error response. autocert retries failed renewals
// silently, so without this a rate limit or failed validation stays invisible
// until the certificate expires.
type acmeTransport struct {
	base      http.RoundTripper
	isLeaderF func() bool // nil in single-instance mode: never gated
	logger    *slog.Logger
	retired   atomic.Bool // set once the owning autocert instance has been replaced
}

func (t *acmeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.retired.Load() {
		return nil, errInstanceRetired
	}
	if t.isLeaderF != nil && !t.isLeaderF() {
		return nil, ErrNotLeader
	}

	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxACMEErrorBody))
		// Hand the bytes back: the ACME client parses the problem document itself.
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(body), resp.Body), resp.Body}

		// A stale nonce is routine and retried transparently by the ACME client.
		level := slog.LevelWarn
		if bytes.Contains(body, []byte("badNonce")) {
			level = slog.LevelDebug
		}
		t.logger.Log(req.Context(), level, "TLS: ACME server returned an error",
			"status", resp.StatusCode,
			"url", req.URL.String(),
			"retry_after", resp.Header.Get("Retry-After"),
			"body", string(body))
	}

	return resp, nil
}

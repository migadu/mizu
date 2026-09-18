package tls

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// maxACMEErrorBody bounds how much of an ACME error response is logged. Problem
// documents (RFC 7807) are a few hundred bytes.
const maxACMEErrorBody = 4096

// maxACMERequestBody bounds how much of a request is read to classify it. The
// largest is a finalize carrying a CSR, a couple of kilobytes.
const maxACMERequestBody = 64 * 1024

// acmeTransport is the HTTP transport handed to autocert's ACME client.
//
// It is the cluster's leader gate. autocert has no hook to stop it ordering a
// certificate: a renewal runs the whole ACME order first and only then writes
// the result to the cache, so gating cache writes alone lets a non-leader obtain
// a certificate, fail to store it, and retry every 30-60 minutes — which burns
// Let's Encrypt's duplicate-certificate limit for every node, leader included.
// Refusing the requests themselves means a non-leader cannot reach the CA.
//
// It also logs what the ACME server refuses. autocert retries failed renewals
// silently, so without this a rate limit or a failed validation stays invisible
// until the certificate expires. A failed validation is not an HTTP error - the
// CA answers 200 with an authorization whose status is "invalid" - so successful
// JSON replies are inspected too.
type acmeTransport struct {
	base         http.RoundTripper
	isLeaderF    func() bool // nil in single-instance mode: never gated
	logger       *slog.Logger
	retired      atomic.Bool  // set once the owning autocert instance has been replaced
	lastAsLeader atomic.Int64 // unix nano of the last request made while leader
}

// acmeOrderGrace is how long after losing leadership a node may still collect
// the result of an order it started. autocert allows an order ten minutes.
const acmeOrderGrace = 10 * time.Minute

func (t *acmeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.retired.Load() {
		return nil, errInstanceRetired
	}

	if t.isLeaderF == nil || t.isLeaderF() {
		t.lastAsLeader.Store(time.Now().UnixNano())
	} else {
		// Leadership can move while an order is in flight — a rolling restart
		// demotes a node a second after the smaller name rejoins. Refusing
		// everything then strands a certificate the CA has already issued and
		// charged against the weekly limit: issuance happens at finalize, and
		// the download that follows is a read. autocert ignores the error rather
		// than retrying, so the certificate is simply lost.
		//
		// So a node that was leader moments ago may still read, which cannot
		// cause an issuance, but never write. A node that has not been leader
		// within the grace does not reach the CA at all.
		if !t.recentlyLeader() {
			return nil, ErrNotLeader
		}

		isRead, err := isACMERead(req)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNotLeader, err)
		}
		if !isRead {
			return nil, ErrNotLeader
		}
		t.logger.Warn("TLS: collecting an ACME response after losing leadership - an order was in flight",
			"url", req.URL.String())
	}

	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	switch {
	case resp.StatusCode >= 400:
		body := t.peekBody(resp)

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

	case isACMEJSON(resp):
		if body := t.peekBody(resp); bytes.Contains(body, []byte(`"status":"invalid"`)) ||
			bytes.Contains(body, []byte(`"status": "invalid"`)) {
			t.logger.Warn("TLS: ACME validation failed - the CA could not verify this domain",
				"url", req.URL.String(),
				"body", string(body))
		}
	}

	return resp, nil
}

// peekBody reads the start of a response and hands the bytes back, so the ACME
// client still parses the document itself.
func (t *acmeTransport) peekBody(resp *http.Response) []byte {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxACMEErrorBody))
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(body), resp.Body), resp.Body}
	return body
}

// recentlyLeader reports whether this transport was still acting as leader
// recently enough that an order it started could be in flight.
func (t *acmeTransport) recentlyLeader() bool {
	last := t.lastAsLeader.Load()
	return last != 0 && time.Since(time.Unix(0, last)) < acmeOrderGrace
}

// isACMERead reports whether a request is a POST-as-GET (RFC 8555 §6.3): a JWS
// whose payload is a zero-length string. Everything else carries a payload and
// can change something at the CA.
//
// The body is restored for the real request either way.
func isACMERead(req *http.Request) (bool, error) {
	if req.Body == nil {
		// The nonce request (HEAD/GET) carries nothing and changes nothing.
		return true, nil
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, maxACMERequestBody))
	req.Body.Close()
	if err != nil {
		return false, fmt.Errorf("cannot read the ACME request body: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	var jws struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(body, &jws); err != nil {
		// Not a JWS we understand: treat it as a write.
		return false, nil
	}
	return jws.Payload == "", nil
}

// isACMEJSON reports whether a reply is one of the CA's JSON documents, as
// opposed to an issued certificate chain, which must not be read here.
func isACMEJSON(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	return strings.HasPrefix(contentType, "application/json") ||
		strings.HasPrefix(contentType, "application/problem+json")
}

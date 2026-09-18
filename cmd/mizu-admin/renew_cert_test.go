package main

import (
	"errors"
	"strings"
	"testing"
)

// F11: a failed renewal comes back as HTTP 500, so the CLI only ever saw an
// error string. Matching "404" anywhere in it meant the CA's own text decided
// the message: an ACME authorization URL contains a numeric id, and one
// containing 404 turned a rate limit into "endpoint not available", hiding the
// verdict the operator needs. The failure branch was never reached at all.
func TestRenewCertResult(t *testing.T) {
	const authzError = `{"status":"error","error":"ecdsa: acme/autocert: unable to satisfy ` +
		`\"https://acme-v02.api.letsencrypt.org/acme/authz/2217385910/561874049155\" for domain ` +
		`\"mx.example.com\": too many certificates already issued"}`

	for _, tc := range []struct {
		name     string
		body     []byte
		err      error
		wantExit int
		want     string
		notWant  string
	}{
		{
			name:     "rate limit reported verbatim",
			err:      &httpStatusError{StatusCode: 500, Body: []byte(authzError)},
			wantExit: 1,
			want:     "too many certificates already issued",
			notWant:  "endpoint not available",
		},
		{
			name:     "unchanged certificate is spelled out",
			err:      &httpStatusError{StatusCode: 500, Body: []byte(authzError)},
			wantExit: 1,
			want:     "unchanged",
		},
		{
			name:     "a real 404 still reports a missing endpoint",
			err:      &httpStatusError{StatusCode: 404, Body: []byte("not found")},
			wantExit: 1,
			want:     "endpoint not available",
		},
		{
			name:     "not the leader",
			err:      &httpStatusError{StatusCode: 500, Body: []byte(`{"status":"error","error":"certificate renewal must be performed on the cluster leader node"}`)},
			wantExit: 1,
			want:     "cluster leader",
			notWant:  "endpoint not available",
		},
		{
			name:     "success",
			body:     []byte(`{"status":"success","renewed":["mx.example.com (ecdsa, expires 2026-12-05T06:14:40Z)"]}`),
			wantExit: 0,
			want:     "expires 2026-12-05T06:14:40Z",
		},
		{
			name:     "partial",
			body:     []byte(`{"status":"partial","renewed":["mx.example.com (ecdsa)"],"error":"rsa: rate limited"}`),
			wantExit: 1,
			want:     "rsa: rate limited",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, exit := renewCertResult(tc.body, tc.err)
			text := strings.Join(out, "\n")

			if exit != tc.wantExit {
				t.Errorf("exit = %d, want %d (output: %s)", exit, tc.wantExit, text)
			}
			if !strings.Contains(text, tc.want) {
				t.Errorf("output %q does not mention %q", text, tc.want)
			}
			if tc.notWant != "" && strings.Contains(text, tc.notWant) {
				t.Errorf("output %q should not mention %q", text, tc.notWant)
			}
		})
	}
}

// A network failure is not an HTTP status, and must not be mistaken for one.
func TestRenewCertResultNetworkFailure(t *testing.T) {
	out, exit := renewCertResult(nil, errors.New("dial tcp 127.0.0.1:8080: connect: connection refused"))
	text := strings.Join(out, "\n")

	if exit != 1 {
		t.Errorf("exit = %d, want 1", exit)
	}
	if !strings.Contains(text, "connection refused") {
		t.Errorf("output %q does not carry the underlying error", text)
	}
}
